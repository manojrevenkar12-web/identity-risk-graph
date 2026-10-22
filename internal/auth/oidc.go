// Package auth verifies who is calling: API keys (hashed, tenant-bound) for machines and AI
// agents, and OIDC ID/access tokens (RS256 or ES256, JWKS-discovered) for people signing in
// through the customer's IdP. Standard library only: no JWT dependency to audit or patch.
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience any    `json:"aud"` // string or []string
	Expiry   int64  `json:"exp"`
	NotBefor int64  `json:"nbf"`
	IssuedAt int64  `json:"iat"`
	Email    string `json:"email"`
	Tenant   string `json:"irg_tenant"` // tenant UUID, set by an IdP claim mapping
	Role     string `json:"irg_role"`   // viewer | analyst | admin
}

type Verifier struct {
	Issuer   string
	Audience string
	JWKSURL  string
	Leeway   time.Duration
	HTTP     *http.Client

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	now       func() time.Time
}

func NewVerifier(issuer, audience, jwksURL string) *Verifier {
	return &Verifier{Issuer: issuer, Audience: audience, JWKSURL: jwksURL, Leeway: time.Minute, HTTP: &http.Client{Timeout: 5 * time.Second}, now: time.Now}
}

// Verify checks signature, algorithm, issuer, audience and time claims.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, ErrInvalidToken
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &h) != nil {
		return nil, ErrInvalidToken
	}
	if h.Alg != "RS256" && h.Alg != "ES256" { // never "none", never HS256 with a public key
		return nil, fmt.Errorf("%w: algorithm %q not accepted", ErrInvalidToken, h.Alg)
	}
	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, fmt.Errorf("%w: bad signature", ErrInvalidToken)
		}
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 {
			return nil, fmt.Errorf("%w: bad signature", ErrInvalidToken)
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, digest[:], r, s) {
			return nil, fmt.Errorf("%w: bad signature", ErrInvalidToken)
		}
	default:
		return nil, ErrInvalidToken
	}
	var c Claims
	if json.Unmarshal(pb, &c) != nil {
		return nil, ErrInvalidToken
	}
	now := v.now()
	switch {
	case c.Issuer != v.Issuer:
		return nil, fmt.Errorf("%w: issuer", ErrInvalidToken)
	case !audienceOK(c.Audience, v.Audience):
		return nil, fmt.Errorf("%w: audience", ErrInvalidToken)
	case c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(v.Leeway)):
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	case c.NotBefor != 0 && now.Add(v.Leeway).Before(time.Unix(c.NotBefor, 0)):
		return nil, fmt.Errorf("%w: not yet valid", ErrInvalidToken)
	case c.Subject == "" || c.Tenant == "":
		return nil, fmt.Errorf("%w: missing subject or tenant claim", ErrInvalidToken)
	}
	return &c, nil
}

func audienceOK(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}

// key returns the signing key for kid, refreshing the JWKS at most once a minute for an unknown
// kid (key rotation) and every 10 minutes otherwise.
func (v *Verifier) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok && v.now().Sub(v.fetchedAt) < 10*time.Minute {
		return k, nil
	}
	if v.keys != nil && v.now().Sub(v.fetchedAt) < time.Minute {
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("%w: unknown key id", ErrInvalidToken)
	}
	keys, err := v.fetch(ctx)
	if err != nil {
		if k, ok := v.keys[kid]; ok {
			return k, nil // IdP briefly unavailable: keep using the key we have
		}
		return nil, err
	}
	v.keys, v.fetchedAt = keys, v.now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown key id", ErrInvalidToken)
}

func (v *Verifier) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			if pub.N.BitLen() < 2048 {
				continue // refuse weak keys
			}
			out[k.Kid] = pub
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pub.IsOnCurve(pub.X, pub.Y) { //nolint:staticcheck // deprecated for general use, but it is exactly the on-curve check a JWK's raw x/y needs
				continue
			}
			out[k.Kid] = pub
		}
	}
	return out, nil
}

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

type idp struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
	srv *httptest.Server
}

func newIdP(t *testing.T) *idp {
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &idp{rsa: r, ec: e}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{ //nolint:errcheck
			{"kty": "RSA", "kid": "r1", "use": "sig", "n": b64.EncodeToString(r.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(r.E)).Bytes())},
			{"kty": "EC", "kid": "e1", "crv": "P-256", "x": b64.EncodeToString(e.X.FillBytes(make([]byte, 32))), "y": b64.EncodeToString(e.Y.FillBytes(make([]byte, 32)))},
		}})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) token(t *testing.T, alg, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	d := sha256.Sum256([]byte(signing))
	var sig []byte
	switch alg {
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, p.rsa, crypto.SHA256, d[:])
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, p.ec, d[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	return signing + "." + b64.EncodeToString(sig)
}

func claims(mod map[string]any) map[string]any {
	c := map[string]any{"iss": "https://idp.example", "aud": "irg", "sub": "alice", "exp": time.Now().Add(time.Hour).Unix(), "irg_tenant": "t-1", "irg_role": "analyst"}
	for k, v := range mod {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func TestVerify(t *testing.T) {
	p := newIdP(t)
	v := NewVerifier("https://idp.example", "irg", p.srv.URL)
	ctx := context.Background()
	for _, alg := range []struct{ alg, kid string }{{"RS256", "r1"}, {"ES256", "e1"}} {
		c, err := v.Verify(ctx, p.token(t, alg.alg, alg.kid, claims(nil)))
		if err != nil || c.Subject != "alice" || c.Tenant != "t-1" || c.Role != "analyst" {
			t.Fatalf("%s: %+v %v", alg.alg, c, err)
		}
	}
	bad := map[string]string{
		"expired":        p.token(t, "RS256", "r1", claims(map[string]any{"exp": time.Now().Add(-2 * time.Minute).Unix()})),
		"wrong issuer":   p.token(t, "RS256", "r1", claims(map[string]any{"iss": "https://evil.example"})),
		"wrong audience": p.token(t, "RS256", "r1", claims(map[string]any{"aud": []string{"other"}})),
		"no tenant":      p.token(t, "RS256", "r1", claims(map[string]any{"irg_tenant": nil})),
		"unknown kid":    p.token(t, "RS256", "nope", claims(nil)),
		"kid/alg swap":   p.token(t, "RS256", "e1", claims(nil)),
		"not yet valid":  p.token(t, "RS256", "r1", claims(map[string]any{"nbf": time.Now().Add(time.Hour).Unix()})),
	}
	for name, tok := range bad {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// alg=none and a forged payload with a valid signature from another token
	good := p.token(t, "RS256", "r1", claims(nil))
	parts := strings.Split(good, ".")
	none := b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
	forged := parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"https://idp.example","aud":"irg","sub":"mallory","exp":9999999999,"irg_tenant":"t-1","irg_role":"admin"}`)) + "." + parts[2]
	for name, tok := range map[string]string{"alg none": none, "forged payload": forged, "garbage": "a.b.c"} {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

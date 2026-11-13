package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/trace"
)

// Sink delivers a batch. It returns nil only when the SIEM acknowledged every event in it.
type Sink interface {
	Name() string
	Send(ctx context.Context, batch []Event) error
}

// RetryAfter is a temporary failure; Wait is the server's hint (0 when it gave none).
type RetryAfter struct {
	Wait time.Duration
	Err  error
}

func (r *RetryAfter) Error() string { return r.Err.Error() }
func (r *RetryAfter) Unwrap() error { return r.Err }

func classify(resp *http.Response, body []byte) error {
	msg := fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		wait := time.Duration(0)
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			wait = time.Duration(s) * time.Second
		}
		return &RetryAfter{wait, msg}
	}
	return fmt.Errorf("%w: %w", ErrPermanent, msg)
}

func post(ctx context.Context, c *http.Client, name, url string, body []byte, header http.Header) error {
	ctx, span := trace.Start(ctx, "POST siem "+name, trace.Client, trace.String("irg.siem.sink", name),
		trace.Int("http.request.body.size", len(body)))
	defer span.End()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	trace.Inject(ctx, req.Header)
	resp, err := c.Do(req)
	if err != nil {
		span.Fail(err.Error())
		return &RetryAfter{0, err} // network error or timeout: the batch may or may not have landed
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	span.SetAttributes(trace.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode >= 300 {
		span.Fail(resp.Status)
		return classify(resp, b)
	}
	return nil
}

// ------------------------------------------------------------------------------------- Splunk HEC
// SplunkHEC sends to Splunk's HTTP Event Collector, one JSON envelope per event, many per request.
type SplunkHEC struct {
	URL        string // https://splunk.example.com:8088
	Token      string
	Index      string
	SourceType string // default "irg:ecs"
	Client     *http.Client
}

func (s *SplunkHEC) Name() string { return "splunk" }

func (s *SplunkHEC) Send(ctx context.Context, batch []Event) error {
	var buf bytes.Buffer
	st := s.SourceType
	if st == "" {
		st = "irg:ecs"
	}
	for _, e := range batch {
		env := map[string]any{"time": float64(e.At.UnixNano()) / 1e9, "host": "identity-risk-graph",
			"source": "irg:" + e.Stream, "sourcetype": st, "event": e.ECS(),
			"fields": map[string]string{"event_id": e.ID(), "tenant": e.Tenant}}
		if s.Index != "" {
			env["index"] = s.Index
		}
		b, _ := json.Marshal(env)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	h := http.Header{}
	h.Set("Authorization", "Splunk "+s.Token)
	h.Set("Content-Type", "application/json")
	return post(ctx, client(s.Client), s.Name(), strings.TrimRight(s.URL, "/")+"/services/collector/event", buf.Bytes(), h)
}

// ------------------------------------------------------------------------------------- Microsoft Sentinel
// Sentinel sends to a Log Analytics custom table through the Logs Ingestion API (a data collection
// endpoint and rule). Requests are split to stay under the API's 1 MB limit.
type Sentinel struct {
	Endpoint string // data collection endpoint, https://<dce>.ingest.monitor.azure.com
	RuleID   string // the data collection rule's immutable id, dcr-...
	Stream   string // Custom-IrgSecurityEvents_CL
	Token    *AzureToken
	Client   *http.Client
	MaxBytes int // default 1,000,000
}

func (s *Sentinel) Name() string { return "sentinel" }

func (s *Sentinel) Send(ctx context.Context, batch []Event) error {
	max := s.MaxBytes
	if max <= 0 {
		max = 1_000_000
	}
	tok, err := s.Token.Get(ctx, client(s.Client))
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01", strings.TrimRight(s.Endpoint, "/"),
		url.PathEscape(s.RuleID), url.PathEscape(s.Stream))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	h.Set("Content-Type", "application/json")
	var chunk []json.RawMessage
	size := 2
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		b, _ := json.Marshal(chunk)
		chunk, size = chunk[:0], 2
		return post(ctx, client(s.Client), s.Name(), u, b, h)
	}
	for _, e := range batch {
		ecs, _ := json.Marshal(e.ECS())
		row, _ := json.Marshal(map[string]any{
			"TimeGenerated": e.At.UTC().Format(time.RFC3339Nano), "EventId": e.ID(), "TenantId": e.Tenant,
			"Stream": e.Stream, "Action": e.Action, "Outcome": e.Outcome, "Actor": e.Actor, "Target": e.Target,
			"Decision": e.Decision, "Reason": e.Reason, "Message": e.message(), "Ecs": string(ecs)})
		if size+len(row)+1 > max {
			if err := flush(); err != nil {
				return err
			}
		}
		chunk = append(chunk, row)
		size += len(row) + 1
	}
	return flush()
}

// AzureToken gets and caches a Microsoft Entra ID token with the client-credentials flow.
type AzureToken struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Authority    string // default https://login.microsoftonline.com
	mu           sync.Mutex
	token        string
	expires      time.Time
}

func (a *AzureToken) Get(ctx context.Context, c *http.Client) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Until(a.expires) > time.Minute {
		return a.token, nil
	}
	auth := a.Authority
	if auth == "" {
		auth = "https://login.microsoftonline.com"
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {a.ClientID},
		"client_secret": {a.ClientSecret}, "scope": {"https://monitor.azure.com//.default"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(auth, "/")+"/"+url.PathEscape(a.TenantID)+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return "", &RetryAfter{0, err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return "", classify(resp, b)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", fmt.Errorf("%w: token response without access_token", ErrPermanent)
	}
	a.token, a.expires = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second)
	return a.token, nil
}

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 15 * time.Second}
}

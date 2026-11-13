package app_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/app"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/testdb"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/trace"
)

type spanSink struct {
	mu    sync.Mutex
	spans []map[string]any
}

func (s *spanSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []map[string]any `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &req)
	s.mu.Lock()
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			s.spans = append(s.spans, ss.Spans...)
		}
	}
	s.mu.Unlock()
}

// One trace follows a sync from the HTTP request through the job queue, the connector's calls to the
// estate and the analysis job it schedules; an agent's decision is a span under its request.
func TestATraceFollowsTheRequestThroughTheQueue(t *testing.T) {
	ctx := context.Background()
	d := testdb.New(t)
	src, _ := synth.Generate(synth.Config{Humans: 200, Seed: 7, Now: time.Now().UTC()})
	es := httptest.NewServer(estate.New(src, "estate-token").Handler())
	defer es.Close()
	tenant, adminKey, err := store.CreateTenant(ctx, d, "trace", "Trace", synth.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTenantSetting(ctx, d, tenant, "estate_url", es.URL); err != nil {
		t.Fatal(err)
	}
	sink := &spanSink{}
	col := httptest.NewServer(sink)
	defer col.Close()
	prev := trace.Default
	trace.Default = trace.New(trace.Config{Service: "irg-test", Endpoint: col.URL, Ratio: 1, Interval: time.Hour})
	defer func() { trace.Default = prev }()

	cfg := app.ConfigFromEnv()
	cfg.EstateToken, cfg.PDPRate, cfg.PDPBurst = "estate-token", 1000, 1000
	a := app.New(d, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Close()
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	const caller = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	req, _ := http.NewRequest("POST", srv.URL+"/v1/sync", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("traceparent", caller)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("sync: %v %v", err, resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("traceparent"), "00-0af7651916cd43dd8448eb211c80319c-") {
		t.Fatalf("response traceparent %q", resp.Header.Get("traceparent"))
	}
	_ = resp.Body.Close()
	drain(t, a)
	admin := client{t, srv.URL, adminKey}
	admin.do("POST", "/v1/agents/decide", map[string]string{"agent_id": "agent-x", "action": "s3:GetObject", "resource": "arn:aws:s3:::x"}, 200)
	if err := trace.Default.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	byTrace := map[string][]string{}
	for _, s := range sink.spans {
		byTrace[s["traceId"].(string)] = append(byTrace[s["traceId"].(string)], s["name"].(string))
	}
	names := strings.Join(byTrace["0af7651916cd43dd8448eb211c80319c"], ",")
	for _, want := range []string{"POST /v1/sync", "job sync", "GET estate", "job analyze"} {
		if !strings.Contains(names, want) {
			t.Fatalf("caller's trace lacks %q: %s", want, names)
		}
	}
	found := false
	for _, ns := range byTrace {
		if strings.Contains(strings.Join(ns, ","), "pdp.decide") {
			found = true
		}
	}
	if !found {
		t.Fatal("no pdp.decide span")
	}
}

package trace

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type collector struct {
	mu    sync.Mutex
	spans []map[string]any
	res   []map[string]any
	fail  atomic.Int32 // respond 503 this many times first
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if c.fail.Add(-1) >= 0 {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		ResourceSpans []struct {
			Resource struct {
				Attributes []map[string]any `json:"attributes"`
			} `json:"resource"`
			ScopeSpans []struct {
				Spans []map[string]any `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	b, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(b, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	for _, rs := range req.ResourceSpans {
		c.res = append(c.res, rs.Resource.Attributes...)
		for _, ss := range rs.ScopeSpans {
			c.spans = append(c.spans, ss.Spans...)
		}
	}
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func TestTraceparentRoundTrip(t *testing.T) {
	sc, ok := ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok || !sc.Sampled {
		t.Fatal("valid header rejected")
	}
	if got := FormatTraceparent(sc); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatal(got)
	}
	for _, bad := range []string{"", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01", "00-4bf9-00f0-01"} {
		if _, ok := ParseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSpansReachTheCollectorAsOTLP(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c)
	defer srv.Close()
	tr := New(Config{Service: "irg-api", Version: "test", Endpoint: srv.URL, Ratio: 1, Interval: time.Hour})

	h := http.Header{}
	h.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx := Extract(context.Background(), h)
	ctx, server := tr.Start(ctx, "POST /v1/agents/decide", Server, String("http.route", "/v1/agents/decide"))
	_, child := tr.Start(ctx, "pdp.decide", Internal, Int("pdp.latency_us", 3))
	child.SetAttributes(String("pdp.decision", "deny"), Bool("pdp.crown_jewel", true), Float("x", 0.5))
	child.Fail("denied")
	child.End()
	server.End()
	server.End() // idempotent
	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.spans) != 2 {
		t.Fatalf("collector got %d spans", len(c.spans))
	}
	byName := map[string]map[string]any{}
	for _, s := range c.spans {
		byName[s["name"].(string)] = s
	}
	srvSpan, pdpSpan := byName["POST /v1/agents/decide"], byName["pdp.decide"]
	if srvSpan["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" || srvSpan["parentSpanId"] != "00f067aa0ba902b7" {
		t.Fatalf("server span did not continue the caller's trace: %v", srvSpan)
	}
	if pdpSpan["parentSpanId"] != srvSpan["spanId"] || pdpSpan["traceId"] != srvSpan["traceId"] {
		t.Fatal("child span is not under the server span")
	}
	if srvSpan["kind"].(float64) != 2 || pdpSpan["status"].(map[string]any)["code"].(float64) != 2 {
		t.Fatal("kind or status wrong")
	}
	if _, ok := srvSpan["startTimeUnixNano"].(string); !ok {
		t.Fatal("timestamps must be strings in OTLP JSON")
	}
	found := false
	for _, a := range c.res {
		if a["key"] == "service.name" && a["value"].(map[string]any)["stringValue"] == "irg-api" {
			found = true
		}
	}
	if !found {
		t.Fatal("service.name missing from the resource")
	}
}

func TestRetriesWhileTheCollectorIsUnavailable(t *testing.T) {
	c := &collector{}
	c.fail.Store(2)
	srv := httptest.NewServer(c)
	defer srv.Close()
	tr := New(Config{Service: "irg", Endpoint: srv.URL, Ratio: 1, Interval: time.Hour})
	_, s := tr.Start(context.Background(), "job sync", Internal)
	s.End()
	_ = tr.Flush(context.Background())
	exported, dropped, failed := tr.Stats()
	if exported != 1 || dropped != 0 || failed != 0 {
		t.Fatalf("exported %d dropped %d failed %d", exported, dropped, failed)
	}
}

func TestUnsampledTracesAreNotExportedButStillPropagate(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c)
	defer srv.Close()
	tr := New(Config{Service: "irg", Endpoint: srv.URL, Ratio: 0, Interval: time.Hour})
	ctx, s := tr.Start(context.Background(), "root", Server)
	h := http.Header{}
	Inject(ctx, h)
	if h.Get("traceparent") == "" || h.Get("traceparent")[53:] != "00" {
		t.Fatalf("traceparent %q should carry the not-sampled flag", h.Get("traceparent"))
	}
	s.End()
	_ = tr.Flush(context.Background())
	if len(c.spans) != 0 {
		t.Fatal("unsampled span exported")
	}
}

func TestAFullQueueDropsInsteadOfBlocking(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	defer func() { close(block); srv.Close() }()
	tr := New(Config{Service: "irg", Endpoint: srv.URL, Ratio: 1, Queue: 4, Batch: 1, Interval: time.Hour})
	t0 := time.Now()
	for i := 0; i < 200; i++ {
		_, s := tr.Start(context.Background(), "x", Internal)
		s.End()
	}
	if time.Since(t0) > time.Second {
		t.Fatal("ending spans blocked on a stuck collector")
	}
	if _, dropped, _ := tr.Stats(); dropped == 0 {
		t.Fatal("expected drops")
	}
}

func TestDisabledTracerIsANoop(t *testing.T) {
	var tr *Tracer
	ctx, s := tr.Start(context.Background(), "x", Internal)
	s.SetAttributes(String("a", "b"))
	s.Fail("x")
	s.End()
	if s.TraceID() != "" || ctx.Value(ctxKey{}) != nil {
		t.Fatal("disabled tracer recorded something")
	}
}

func BenchmarkSpan(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	tr := New(Config{Service: "irg", Endpoint: srv.URL, Ratio: 1, Queue: 1 << 20})
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c, s := tr.Start(ctx, "POST /v1/agents/decide", Server, String("http.route", "/v1/agents/decide"))
		_, d := tr.Start(c, "pdp.decide", Internal)
		d.SetAttributes(String("pdp.decision", "allow"))
		d.End()
		s.End()
	}
}

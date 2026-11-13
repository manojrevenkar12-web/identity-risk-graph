// Package trace records OpenTelemetry spans and exports them over OTLP/HTTP (JSON encoding) to any
// OpenTelemetry Collector, Grafana Tempo, Jaeger or vendor endpoint that speaks OTLP. W3C Trace
// Context (traceparent) carries a trace across services.
//
// It is written on the standard library, like internal/metrics: a security product should not pull
// a dependency tree for its telemetry. CI sends its spans to a real OpenTelemetry Collector and checks
// that the collector accepted every one (see .github/workflows/ci.yml, job otel).
package trace

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/metrics"
)

var mSpans = metrics.Default.Counter("irg_trace_spans_total", "Spans handed to the OTLP exporter", "outcome")

// Kind follows the OTLP SpanKind enum.
type Kind int

const (
	Internal Kind = 1
	Server   Kind = 2
	Client   Kind = 3
)

// Attr is one span attribute. Values are string, bool, int, int64 or float64.
type Attr struct {
	Key   string
	Value any
}

func String(k, v string) Attr        { return Attr{k, v} }
func Int(k string, v int) Attr       { return Attr{k, int64(v)} }
func Bool(k string, v bool) Attr     { return Attr{k, v} }
func Float(k string, v float64) Attr { return Attr{k, v} }

// SpanContext identifies a span across process boundaries.
type SpanContext struct {
	TraceID [16]byte
	SpanID  [8]byte
	Sampled bool
}

func (s SpanContext) Valid() bool { return s.TraceID != [16]byte{} && s.SpanID != [8]byte{} }

// Span is one timed operation. A nil *Span is valid and records nothing.
type Span struct {
	tracer *Tracer
	sc     SpanContext
	parent [8]byte
	name   string
	kind   Kind
	start  time.Time
	end    time.Time
	mu     sync.Mutex
	attrs  []Attr
	errMsg string
	failed bool
	ended  atomic.Bool
}

func (s *Span) SetAttributes(a ...Attr) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.attrs = append(s.attrs, a...)
	s.mu.Unlock()
}

// Fail marks the span's status as an error.
func (s *Span) Fail(msg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.failed, s.errMsg = true, msg
	s.mu.Unlock()
}

// End records the end time and hands a sampled span to the exporter. Calling it twice is harmless.
func (s *Span) End() {
	if s == nil || s.ended.Swap(true) {
		return
	}
	s.end = time.Now()
	if s.sc.Sampled && s.tracer.exp != nil {
		s.tracer.exp.enqueue(s)
	}
}

func (s *Span) Context() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return s.sc
}

// TraceID is the hex trace id, for log correlation ("" when not tracing).
func (s *Span) TraceID() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.sc.TraceID[:])
}

// ------------------------------------------------------------------------------------- tracer
type Config struct {
	Service  string  // service.name
	Version  string  // service.version
	Endpoint string  // OTLP/HTTP base URL, e.g. http://otel-collector:4318 ("" disables export)
	Ratio    float64 // root-span sampling ratio, 0..1; children follow their parent
	Headers  map[string]string
	Batch    int           // spans per request (default 512)
	Interval time.Duration // flush interval (default 2 s)
	Queue    int           // spans held before dropping (default 8192)
}

type Tracer struct {
	cfg   Config
	exp   *exporter
	ratio uint64 // threshold on the trace id's low 8 bytes
}

type ctxKey struct{}

// Default is the process tracer; it records nothing until Init is called with an endpoint.
var Default = &Tracer{}

// FromEnv reads the standard OpenTelemetry variables: OTEL_EXPORTER_OTLP_ENDPOINT,
// OTEL_EXPORTER_OTLP_HEADERS (k=v,k=v), OTEL_SERVICE_NAME, OTEL_TRACES_SAMPLER_ARG.
func FromEnv(service, version string) Config {
	c := Config{Service: service, Version: version, Endpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), Ratio: 1}
	if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
		c.Service = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("OTEL_TRACES_SAMPLER_ARG"), 64); err == nil {
		c.Ratio = v
	}
	if h := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"); h != "" {
		c.Headers = map[string]string{}
		for _, kv := range strings.Split(h, ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				c.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return c
}

func New(cfg Config) *Tracer {
	if cfg.Batch <= 0 {
		cfg.Batch = 512
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 8192
	}
	r := math.Max(0, math.Min(1, cfg.Ratio))
	t := &Tracer{cfg: cfg, ratio: uint64(r * float64(math.MaxUint64))}
	if r == 1 {
		t.ratio = math.MaxUint64
	}
	if cfg.Endpoint != "" {
		t.exp = newExporter(t)
	}
	return t
}

// Enabled reports whether spans are being exported.
func (t *Tracer) Enabled() bool { return t != nil && t.exp != nil }

// Start begins a span as a child of the span in ctx (or of a remote parent put there by Extract).
func (t *Tracer) Start(ctx context.Context, name string, kind Kind, attrs ...Attr) (context.Context, *Span) {
	if !t.Enabled() {
		return ctx, nil
	}
	s := &Span{tracer: t, name: name, kind: kind, start: time.Now(), attrs: attrs}
	parent, _ := ctx.Value(ctxKey{}).(SpanContext)
	if parent.Valid() {
		s.sc.TraceID, s.parent, s.sc.Sampled = parent.TraceID, parent.SpanID, parent.Sampled
	} else {
		_, _ = rand.Read(s.sc.TraceID[:])
		s.sc.Sampled = binary.BigEndian.Uint64(s.sc.TraceID[8:]) <= t.ratio
	}
	_, _ = rand.Read(s.sc.SpanID[:])
	return context.WithValue(ctx, ctxKey{}, s.sc), s
}

// Start uses the Default tracer.
func Start(ctx context.Context, name string, kind Kind, attrs ...Attr) (context.Context, *Span) {
	return Default.Start(ctx, name, kind, attrs...)
}

// Shutdown flushes what is queued, waiting at most until ctx ends.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if !t.Enabled() {
		return nil
	}
	return t.exp.shutdown(ctx)
}

// Stats reports exported, dropped and failed span counts.
func (t *Tracer) Stats() (exported, dropped, failed uint64) {
	if !t.Enabled() {
		return 0, 0, 0
	}
	return t.exp.exported.Load(), t.exp.dropped.Load(), t.exp.failed.Load()
}

// ------------------------------------------------------------------------------------- W3C propagation
// Extract reads a traceparent header into ctx, so the next Start continues the caller's trace.
func Extract(ctx context.Context, h http.Header) context.Context {
	sc, ok := ParseTraceparent(h.Get("traceparent"))
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, sc)
}

// Inject writes the span in ctx as a traceparent header.
func Inject(ctx context.Context, h http.Header) {
	sc, _ := ctx.Value(ctxKey{}).(SpanContext)
	if sc.Valid() {
		h.Set("traceparent", FormatTraceparent(sc))
	}
}

func FormatTraceparent(sc SpanContext) string {
	flags := "00"
	if sc.Sampled {
		flags = "01"
	}
	return "00-" + hex.EncodeToString(sc.TraceID[:]) + "-" + hex.EncodeToString(sc.SpanID[:]) + "-" + flags
}

// ParseTraceparent accepts version 00 headers and rejects all-zero ids, as the spec requires.
func ParseTraceparent(v string) (SpanContext, bool) {
	var sc SpanContext
	p := strings.Split(strings.TrimSpace(v), "-")
	if len(p) != 4 || p[0] != "00" || len(p[1]) != 32 || len(p[2]) != 16 || len(p[3]) != 2 {
		return sc, false
	}
	if _, err := hex.Decode(sc.TraceID[:], []byte(p[1])); err != nil {
		return sc, false
	}
	if _, err := hex.Decode(sc.SpanID[:], []byte(p[2])); err != nil {
		return sc, false
	}
	f, err := strconv.ParseUint(p[3], 16, 8)
	if err != nil || !sc.Valid() {
		return SpanContext{}, false
	}
	sc.Sampled = f&1 == 1
	return sc, true
}

// ------------------------------------------------------------------------------------- OTLP/JSON
type kv struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

func encodeAttrs(as []Attr) []kv {
	out := make([]kv, 0, len(as))
	for _, a := range as {
		var v map[string]any
		switch x := a.Value.(type) {
		case string:
			v = map[string]any{"stringValue": x}
		case bool:
			v = map[string]any{"boolValue": x}
		case int:
			v = map[string]any{"intValue": strconv.FormatInt(int64(x), 10)}
		case int64:
			v = map[string]any{"intValue": strconv.FormatInt(x, 10)}
		case float64:
			v = map[string]any{"doubleValue": x}
		default:
			v = map[string]any{"stringValue": fmt.Sprint(x)}
		}
		out = append(out, kv{a.Key, v})
	}
	return out
}

// Encode renders spans as one OTLP ExportTraceServiceRequest in the protobuf JSON mapping.
func (t *Tracer) Encode(spans []*Span) ([]byte, error) {
	type status struct {
		Code    int    `json:"code"`
		Message string `json:"message,omitempty"`
	}
	type span struct {
		TraceID      string `json:"traceId"`
		SpanID       string `json:"spanId"`
		ParentSpanID string `json:"parentSpanId,omitempty"`
		Name         string `json:"name"`
		Kind         int    `json:"kind"`
		Start        string `json:"startTimeUnixNano"`
		End          string `json:"endTimeUnixNano"`
		Attributes   []kv   `json:"attributes,omitempty"`
		Status       status `json:"status"`
	}
	out := make([]span, 0, len(spans))
	for _, s := range spans {
		s.mu.Lock()
		st := status{Code: 1}
		if s.failed {
			st = status{Code: 2, Message: s.errMsg}
		}
		e := span{TraceID: hex.EncodeToString(s.sc.TraceID[:]), SpanID: hex.EncodeToString(s.sc.SpanID[:]),
			Name: s.name, Kind: int(s.kind), Start: strconv.FormatInt(s.start.UnixNano(), 10),
			End: strconv.FormatInt(s.end.UnixNano(), 10), Attributes: encodeAttrs(s.attrs), Status: st}
		if s.parent != [8]byte{} {
			e.ParentSpanID = hex.EncodeToString(s.parent[:])
		}
		s.mu.Unlock()
		out = append(out, e)
	}
	res := []Attr{String("service.name", t.cfg.Service), String("service.version", t.cfg.Version),
		String("telemetry.sdk.name", "irg-trace"), String("telemetry.sdk.language", "go")}
	req := map[string]any{"resourceSpans": []any{map[string]any{
		"resource": map[string]any{"attributes": encodeAttrs(res)},
		"scopeSpans": []any{map[string]any{
			"scope": map[string]any{"name": "github.com/manojrevenkar12-web/identity-risk-graph", "version": t.cfg.Version},
			"spans": out,
		}},
	}}}
	return json.Marshal(req)
}

// ------------------------------------------------------------------------------------- exporter
type exporter struct {
	t        *Tracer
	q        chan *Span
	flush    chan chan struct{}
	done     chan struct{}
	client   *http.Client
	exported atomic.Uint64
	dropped  atomic.Uint64
	failed   atomic.Uint64
}

func newExporter(t *Tracer) *exporter {
	e := &exporter{t: t, q: make(chan *Span, t.cfg.Queue), flush: make(chan chan struct{}), done: make(chan struct{}),
		client: &http.Client{Timeout: 10 * time.Second}}
	go e.loop()
	return e
}

// enqueue never blocks the request path: when the queue is full the span is dropped and counted.
func (e *exporter) enqueue(s *Span) {
	select {
	case e.q <- s:
	default:
		e.dropped.Add(1)
		mSpans.Inc("dropped")
	}
}

func (e *exporter) loop() {
	defer close(e.done)
	batch := make([]*Span, 0, e.t.cfg.Batch)
	tick := time.NewTicker(e.t.cfg.Interval)
	defer tick.Stop()
	send := func() {
		if len(batch) > 0 {
			e.post(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case s, ok := <-e.q:
			if !ok {
				send()
				return
			}
			batch = append(batch, s)
			if len(batch) >= e.t.cfg.Batch {
				send()
			}
		case <-tick.C:
			send()
		case ack := <-e.flush:
			for n := len(e.q); n > 0; n-- {
				batch = append(batch, <-e.q)
				if len(batch) >= e.t.cfg.Batch {
					send()
				}
			}
			send()
			close(ack)
		}
	}
}

// post sends one batch, retrying twice on 429/5xx and network errors (the collector may be restarting).
func (e *exporter) post(batch []*Span) {
	body, err := e.t.Encode(batch)
	if err != nil {
		e.failed.Add(uint64(len(batch)))
		return
	}
	url := strings.TrimRight(e.t.cfg.Endpoint, "/") + "/v1/traces"
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range e.t.cfg.Headers {
			req.Header.Set(k, v)
		}
		resp, err := e.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 300 {
				e.exported.Add(uint64(len(batch)))
				mSpans.Add(float64(len(batch)), "exported")
				return
			}
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				break // a 4xx other than 429 will not get better
			}
		}
		time.Sleep(time.Duration(200*(attempt+1)) * time.Millisecond)
	}
	e.failed.Add(uint64(len(batch)))
	mSpans.Add(float64(len(batch)), "failed")
}

// Flush exports everything queued so far.
func (t *Tracer) Flush(ctx context.Context) error {
	if !t.Enabled() {
		return nil
	}
	ack := make(chan struct{})
	select {
	case t.exp.flush <- ack:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *exporter) shutdown(ctx context.Context) error {
	if err := e.t.Flush(ctx); err != nil {
		return err
	}
	return nil
}

package siem

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/testdb"
)

var sample = []Event{
	{Seq: 41, Stream: "decisions", Tenant: "6f1c2a7e-0000-4000-8000-000000000001", At: time.Unix(1_800_000_000, 0),
		Actor: "agent-billing", Action: "agent.decide", Target: "arn:aws:s3:::payroll/2026.csv", Outcome: "failure",
		Decision: "deny", Reason: "crown jewel, destructive action", Detail: json.RawMessage(`{"requested_action":"s3:DeleteObject"}`)},
	{Seq: 7, Stream: "audit", Tenant: "6f1c2a7e-0000-4000-8000-000000000001", At: time.Unix(1_800_000_100, 0),
		Actor: "bob", Action: "plan.apply", Target: "plan-9", Outcome: "success", Detail: json.RawMessage(`{"actions":3}`)},
}

func TestECSShape(t *testing.T) {
	d := sample[0].ECS()
	ev := d["event"].(map[string]any)
	if ev["id"] != "irg-6f1c2a7e-decisions-41" || ev["outcome"] != "failure" || ev["severity"] != 5 {
		t.Fatalf("event %v", ev)
	}
	if d["user"].(map[string]any)["name"] != "agent-billing" || !strings.Contains(d["message"].(string), "s3:DeleteObject") {
		t.Fatalf("doc %v", d)
	}
	if _, err := json.Marshal(sample[1].ECS()); err != nil {
		t.Fatal(err)
	}
}

func TestSplunkHECEnvelope(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk hec-token" {
			http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
			return
		}
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			m := map[string]any{}
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				http.Error(w, `{"text":"Invalid data format","code":6}`, http.StatusBadRequest)
				return
			}
			got = append(got, m)
		}
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()
	s := &SplunkHEC{URL: srv.URL, Token: "hec-token", Index: "security"}
	if err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["index"] != "security" || got[0]["sourcetype"] != "irg:ecs" || got[0]["time"].(float64) != 1.8e9 {
		t.Fatalf("envelopes %v", got)
	}
	bad := &SplunkHEC{URL: srv.URL, Token: "wrong"}
	if err := bad.Send(context.Background(), sample); !errors.Is(err, ErrPermanent) {
		t.Fatalf("a rejected token must be permanent, got %v", err)
	}
}

func TestSentinelTokenAndChunks(t *testing.T) {
	var tokens, posts atomic.Int32
	var rows int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "https://monitor.azure.com//.default" {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			tokens.Add(1)
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case strings.HasPrefix(r.URL.Path, "/dataCollectionRules/dcr-123/streams/Custom-IrgSecurityEvents_CL"):
			if r.URL.Query().Get("api-version") != "2023-01-01" || r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			b, _ := io.ReadAll(r.Body)
			if len(b) > 2000 {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			var arr []map[string]any
			if err := json.Unmarshal(b, &arr); err != nil || arr[0]["TimeGenerated"] == nil {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			posts.Add(1)
			rows += len(arr)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	s := &Sentinel{Endpoint: srv.URL, RuleID: "dcr-123", Stream: "Custom-IrgSecurityEvents_CL", MaxBytes: 2000,
		Token: &AzureToken{TenantID: "t", ClientID: "c", ClientSecret: "s", Authority: srv.URL}}
	for i := 0; i < 2; i++ {
		if err := s.Send(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
	}
	if tokens.Load() != 1 || posts.Load() != 4 || rows != 4 {
		t.Fatalf("tokens %d posts %d rows %d", tokens.Load(), posts.Load(), rows)
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Retry-After", "7")
		http.Error(w, `{"text":"Server is busy","code":9}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	err := (&SplunkHEC{URL: srv.URL, Token: "x"}).Send(context.Background(), sample)
	var ra *RetryAfter
	if !errors.As(err, &ra) || ra.Wait != 7*time.Second {
		t.Fatalf("got %v", err)
	}
}

// Every event reaches the SIEM at least once through busy replies and lost acknowledgements; plain
// allows and the other tenant's events never leave.
func TestDrillDeliversEverythingAtLeastOnce(t *testing.T) {
	d := testdb.New(t)
	res, err := Drill(context.Background(), d, 300, 2000, 0.2, 0.05, 3)
	if err != nil {
		t.Fatal(err)
	}
	if res.Missing != 0 || res.Leaked != 0 || res.AllowsExported != 0 {
		t.Fatalf("%+v", res)
	}
	if res.LostAcks > 0 && res.Duplicates == 0 || res.LostAcks == 0 && res.Duplicates != 0 {
		t.Fatalf("duplicates should come only from lost acknowledgements: %+v", res)
	}
	if res.BusyReplies == 0 {
		t.Fatal("the drill injected nothing")
	}
}

type recordSink struct {
	name string
	err  error
	got  int
}

func (r *recordSink) Name() string { return r.name }
func (r *recordSink) Send(_ context.Context, b []Event) error {
	if r.err != nil {
		return r.err
	}
	r.got += len(b)
	return nil
}

func TestARejectingSinkDoesNotStopTheOthersOrMoveItsCursor(t *testing.T) {
	ctx := context.Background()
	d := testdb.New(t)
	tenant, _, err := store.CreateTenant(ctx, d, "rej", "Rej", "rej.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := withTenant(ctx, d, tenant, 5); err != nil {
		t.Fatal(err)
	}
	bad := &recordSink{name: "splunk", err: errors.Join(ErrPermanent, errors.New("HTTP 403: invalid token"))}
	good := &recordSink{name: "sentinel"}
	x := &Exporter{DB: d, Sinks: []Sink{bad, good}, Sleep: func(context.Context, time.Duration) error { return nil }}
	if _, err := x.Drain(ctx, tenant); !errors.Is(err, ErrPermanent) {
		t.Fatalf("got %v", err)
	}
	if good.got != 5 {
		t.Fatalf("the healthy sink got %d of 5", good.got)
	}
	var last int64
	_ = d.QueryRowContext(ctx, "SELECT coalesce(max(last_seq), 0) FROM siem_cursors WHERE sink = 'splunk'").Scan(&last)
	if last != 0 {
		t.Fatal("the rejecting sink's cursor moved")
	}
}

func withTenant(ctx context.Context, d *sql.DB, tenant string, n int) error {
	return db.WithTenant(ctx, d, tenant, func(tx *sql.Tx) error {
		for i := 0; i < n; i++ {
			if err := store.Audit(ctx, tx, tenant, "bob", "risk.accept", "finding-x", map[string]int{"i": i}); err != nil {
				return err
			}
		}
		return nil
	})
}

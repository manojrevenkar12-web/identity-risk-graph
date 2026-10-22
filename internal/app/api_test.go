package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/app"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/testdb"
)

type client struct {
	t   *testing.T
	url string
	key string
}

func (c client) do(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.url+path, r)
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, resp.StatusCode, want, raw)
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func drain(t *testing.T, a *app.App) {
	t.Helper()
	for i := 0; i < 50; i++ {
		did, err := a.WorkOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			return
		}
	}
	t.Fatal("queue did not drain")
}

func idsOf(list any, rule string) []string {
	var out []string
	for _, f := range list.([]any) {
		m := f.(map[string]any)
		if rule == "" || m["rule"] == rule {
			out = append(out, m["id"].(string))
		}
	}
	return out
}

// The whole product through its API: sync → analysis → findings → plan → four-eyes approval →
// apply against the estate → verified resolved → rollback → AI-agent decisions and JIT grants →
// audit chain intact → tenants isolated.
func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	d := testdb.New(t)
	src, truth := synth.Generate(synth.Config{Humans: 600, Seed: 31, Now: time.Now().UTC()})
	es := httptest.NewServer(estate.New(src, "estate-token").Handler())
	defer es.Close()

	tenant, adminKey, err := store.CreateTenant(ctx, d, "acme", "Acme", synth.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTenantSetting(ctx, d, tenant, "estate_url", es.URL); err != nil {
		t.Fatal(err)
	}
	cfg := app.ConfigFromEnv()
	cfg.EstateToken, cfg.MaxActions, cfg.PDPRate, cfg.PDPBurst = "estate-token", 100, 1000, 1000
	a := app.New(d, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Close()
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	admin := client{t, srv.URL, adminKey}

	// sync and analyse
	admin.do("POST", "/v1/sync", nil, 202)
	drain(t, a)
	post := admin.do("GET", "/v1/posture", nil, 200)["current"].(map[string]any)
	planted := 0
	for _, ids := range truth {
		planted += len(ids)
	}
	open := post["open_by_severity"].(map[string]any)
	got := 0
	for _, v := range open {
		got += int(v.(float64))
	}
	if got != planted {
		t.Fatalf("open findings %d, planted %d", got, planted)
	}

	// people: an analyst proposes, a second admin approves (the analyst cannot)
	analyst := client{t, srv.URL, admin.do("POST", "/v1/keys", map[string]string{"name": "ana", "role": "analyst"}, 201)["key"].(string)}
	admin2 := client{t, srv.URL, admin.do("POST", "/v1/keys", map[string]string{"name": "bob", "role": "admin"}, 201)["key"].(string)}
	viewer := client{t, srv.URL, admin.do("POST", "/v1/keys", map[string]string{"name": "vic", "role": "viewer"}, 201)["key"].(string)}
	fs := analyst.do("GET", "/v1/findings?limit=500", nil, 200)["findings"]
	sel := append(idsOf(fs, risk.RuleOffboard), idsOf(fs, risk.RuleToxic)...)
	plan := analyst.do("POST", "/v1/plans", map[string]any{"finding_ids": sel}, 201)
	pid := plan["id"].(string)
	if len(plan["impact"].(map[string]any)["resolves"].([]any)) != len(sel) {
		t.Fatalf("dry run should resolve all %d: %v", len(sel), plan["impact"])
	}
	analyst.do("POST", "/v1/plans/"+pid+"/approve", nil, 403)
	viewer.do("POST", "/v1/plans", map[string]any{"finding_ids": sel}, 403)
	admin.do("POST", "/v1/plans/"+pid+"/apply", nil, 409) // not approved yet
	admin.do("POST", "/v1/plans/"+pid+"/approve", nil, 200)
	admin.do("POST", "/v1/plans/"+pid+"/apply", nil, 200)
	drain(t, a) // apply → sync → analyze
	if st := admin.do("GET", "/v1/plans/"+pid, nil, 200)["status"]; st != "applied" {
		t.Fatalf("plan status %v", st)
	}
	resolved := idsOf(admin.do("GET", "/v1/findings?status=resolved&limit=500", nil, 200)["findings"], "")
	also := plan["impact"].(map[string]any)["also_resolves"].([]any)
	if len(resolved) != len(sel)+len(also) {
		t.Fatalf("resolved %d, dry run promised %d selected + %d collateral", len(resolved), len(sel), len(also))
	}
	// four eyes: an admin cannot approve their own plan
	own := admin2.do("POST", "/v1/plans", map[string]any{"finding_ids": idsOf(fs, risk.RuleOAuth)[:1]}, 201)
	admin2.do("POST", "/v1/plans/"+own["id"].(string)+"/approve", nil, 403)
	// rollback restores the access, and the findings reopen
	admin.do("POST", "/v1/plans/"+pid+"/rollback", nil, 200)
	drain(t, a)
	if n := len(idsOf(admin.do("GET", "/v1/findings?status=resolved&limit=500", nil, 200)["findings"], "")); n != 0 {
		t.Fatalf("%d findings still resolved after rollback", n)
	}

	// AI agents: each agent key may only ask about itself
	var agentID string
	for id := range truth[risk.RuleAgent] {
		_ = id
	}
	for _, n := range src.Nodes {
		if n.Kind == "ai_agent" && !truth[risk.RuleAgent][n.ID] {
			agentID = n.ID
			break
		}
	}
	agent := client{t, srv.URL, admin.do("POST", "/v1/keys", map[string]string{"name": agentID, "role": "agent"}, 201)["key"].(string)}
	read := map[string]string{"agent_id": agentID, "action": "s3:GetObject", "resource": "arn:aws:s3:::analytics-raw/x.parquet"}
	if dec := agent.do("POST", "/v1/agents/decide", read, 200); dec["decision"] != "allow" {
		t.Fatalf("decide: %v", dec)
	}
	write := map[string]string{"agent_id": agentID, "action": "s3:PutObject", "resource": "arn:aws:s3:::analytics-raw/backfill/x"}
	if dec := agent.do("POST", "/v1/agents/decide", write, 200); dec["decision"] != "deny" {
		t.Fatalf("write without a grant: %v", dec)
	}
	agent.do("POST", "/v1/agents/decide", map[string]string{"agent_id": "agt-other", "action": "s3:GetObject", "resource": "x"}, 403)
	agent.do("GET", "/v1/findings", nil, 403)
	viewer.do("POST", "/v1/agents/decide", read, 403)
	// JIT: the analyst asks, the analyst cannot approve, an admin does, the write is allowed
	g := analyst.do("POST", "/v1/agents/"+agentID+"/grants", map[string]any{"action": "s3:PutObject", "resource": "arn:aws:s3:::analytics-raw/backfill/*", "ttl_minutes": 30, "justification": "INC-77 backfill"}, 201)
	admin.do("POST", "/v1/grants/"+g["id"].(string)+"/approve", nil, 200)
	if dec := agent.do("POST", "/v1/agents/decide", write, 200); dec["decision"] != "allow" || dec["grant_id"] != g["id"] {
		t.Fatalf("with grant: %v", dec)
	}

	// identity view, explanation, audit
	var subject string
	for id := range truth[risk.RuleToxic] {
		subject = id
		break
	}
	idv := viewer.do("GET", "/v1/identities/"+subject, nil, 200)
	if idv["blast_radius"].(float64) < 1 || idv["risk_score"].(float64) <= 0 {
		t.Fatalf("identity view: %v", idv)
	}
	exp := viewer.do("GET", "/v1/findings/"+sel[0]+"/explain", nil, 200)
	if exp["source"] != "template" || !strings.Contains(exp["explanation"].(string), "Controls:") {
		t.Fatalf("explain: %v", exp)
	}
	if v := viewer.do("GET", "/v1/audit/verify", nil, 200); v["intact"] != true || v["entries"].(float64) < 10 {
		t.Fatalf("audit: %v", v)
	}

	// a second tenant sees nothing of the first
	_, otherKey, _ := store.CreateTenant(ctx, d, "globex", "Globex", "globex.example")
	other := client{t, srv.URL, otherKey}
	other.do("GET", "/v1/findings/"+sel[0], nil, 404)
	if n := len(other.do("GET", "/v1/findings", nil, 200)["findings"].([]any)); n != 0 {
		t.Fatalf("other tenant sees %d findings", n)
	}
	other.do("GET", "/v1/plans/"+pid, nil, 404)

	// errors and ops
	client{t, srv.URL, "irg_wrong"}.do("GET", "/v1/findings", nil, 401)
	client{t, srv.URL, ""}.do("GET", "/v1/findings", nil, 401)
	resp, _ := http.Get(srv.URL + "/metrics")
	m, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"irg_agent_decisions_total", "irg_jobs_total", "irg_open_findings"} {
		if !strings.Contains(string(m), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

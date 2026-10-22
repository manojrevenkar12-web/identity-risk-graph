package connector_test

import (
	"context"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/connector"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
)

func findingSet(s *model.Snapshot) []string {
	var out []string
	for _, f := range risk.Analyze(graph.Build(s)) {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

// Reading the estate over HTTP (with paging) yields exactly the analysis of the source data.
func TestFetchRoundTripsTheEstate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	src, _ := synth.Generate(synth.Config{Humans: 1200, Seed: 4, Now: now})
	want := findingSet(src)
	srv := httptest.NewServer(estate.New(src, "secret").Handler())
	defer srv.Close()
	got, err := connector.New(srv.URL, "secret").Fetch(context.Background(), "acme", synth.Domain, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != len(src.Nodes) {
		t.Fatalf("nodes: %d vs %d", len(got.Nodes), len(src.Nodes))
	}
	g := findingSet(got)
	if len(g) != len(want) {
		t.Fatalf("findings through the API: %d, from the source: %d", len(g), len(want))
	}
	for i := range g {
		if g[i] != want[i] {
			t.Fatalf("finding %d differs: %s vs %s", i, g[i], want[i])
		}
	}
	if _, err := connector.New(srv.URL, "wrong").Fetch(context.Background(), "acme", synth.Domain, now); err == nil {
		t.Fatal("a bad token must fail")
	}
}

func TestApplyIsIdempotentAndReversible(t *testing.T) {
	src, _ := synth.Generate(synth.Config{Humans: 300, Seed: 5, Now: time.Now()})
	es := estate.New(src, "secret")
	srv := httptest.NewServer(es.Handler())
	defer srv.Close()
	c := connector.New(srv.URL, "secret")
	ctx := context.Background()
	var app string
	for _, n := range src.Nodes {
		if n.Kind == model.OAuthApp {
			app = n.ID
			break
		}
	}
	var user string
	for _, e := range src.Edges {
		if e.Kind == model.Granted && e.To == app {
			user = e.From
			break
		}
	}
	act := model.Action{Type: "revoke_grant", Target: user, From: app}
	undo, err := c.Apply(ctx, act, "plan-1:0")
	if err != nil || undo == nil || undo.Type != "restore_grant" || undo.Data["scopes"] == "" {
		t.Fatalf("undo %+v err %v", undo, err)
	}
	// the same idempotency key is a replay, not a second write
	if _, err := c.Apply(ctx, act, "plan-1:0"); err != nil {
		t.Fatal(err)
	}
	if n := es.Calls["DELETE /workspace/v1/grants/{user}/{app}"]; n != 1 {
		t.Fatalf("grant deleted %d times", n)
	}
	if _, err := c.Apply(ctx, *undo, "plan-1:undo:0"); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"suspend_user", "require_mfa"} {
		if _, err := c.Apply(ctx, model.Action{Type: typ, Target: "usr-00001"}, ""); err != nil {
			t.Fatal(typ, err)
		}
	}
	if _, err := c.Apply(ctx, model.Action{Type: "suspend_user", Target: "usr-99999"}, ""); err == nil {
		t.Fatal("unknown user must fail without retries")
	}
}

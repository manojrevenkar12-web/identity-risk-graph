package enforce_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/connector"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/enforce"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
)

func ids(fs []model.Finding, rules ...string) []string {
	want := map[string]bool{}
	for _, r := range rules {
		want[r] = true
	}
	var out []string
	for _, f := range fs {
		if want[f.Rule] {
			out = append(out, f.ID)
		}
	}
	return out
}

// The full loop against the HTTP estate: plan → dry run → execute → re-sync → findings gone →
// rollback → re-sync → findings back.
func TestPlanExecuteVerifyRollback(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	src, _ := synth.Generate(synth.Config{Humans: 800, Seed: 11, Now: now})
	srv := httptest.NewServer(estate.New(src, "t").Handler())
	defer srv.Close()
	conn := connector.New(srv.URL, "t")
	snap, err := conn.Fetch(ctx, "acme", synth.Domain, now)
	if err != nil {
		t.Fatal(err)
	}
	fs := risk.Analyze(graph.Build(snap))
	sel := ids(fs, risk.RuleOffboard, risk.RuleToxic, risk.RuleOAuth, risk.RuleAgent, risk.RuleStaleCred)
	steps, imp, err := enforce.Plan(snap, fs, sel, enforce.Guardrails{MaxActions: 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.NewFindings) > 0 || len(imp.StillOpen) > 0 || len(imp.Resolves) != len(sel) {
		t.Fatalf("dry run: resolves %d of %d, still open %v, new %v", len(imp.Resolves), len(sel), imp.StillOpen, imp.NewFindings)
	}
	if len(imp.AccessRemoved) == 0 {
		t.Fatal("dry run should list the crown-jewel access removed")
	}
	var saves int
	save := func([]enforce.Step) error { saves++; return nil }
	if err := enforce.Execute(ctx, conn, "p1", steps, save); err != nil {
		t.Fatal(err)
	}
	if saves != len(steps) {
		t.Fatalf("progress saved %d times for %d steps", saves, len(steps))
	}
	after, _ := conn.Fetch(ctx, "acme", synth.Domain, now)
	open := map[string]bool{}
	for _, f := range risk.Analyze(graph.Build(after)) {
		open[f.ID] = true
	}
	for _, id := range sel {
		if open[id] {
			t.Fatalf("finding %s still open after the plan ran", id)
		}
	}
	if err := enforce.Rollback(ctx, conn, "p1", steps, save); err != nil {
		t.Fatal(err)
	}
	back, _ := conn.Fetch(ctx, "acme", synth.Domain, now)
	reopened := map[string]bool{}
	for _, f := range risk.Analyze(graph.Build(back)) {
		reopened[f.ID] = true
	}
	for _, id := range sel {
		if !reopened[id] {
			t.Fatalf("rollback did not restore %s", id)
		}
	}
}

func TestGuardrails(t *testing.T) {
	src, _ := synth.Generate(synth.Config{Humans: 600, Seed: 12})
	fs := risk.Analyze(graph.Build(src))
	all := ids(fs, risk.RuleOffboard, risk.RuleDormant, risk.RuleToxic, risk.RuleOAuth)
	if _, _, err := enforce.Plan(src, fs, all, enforce.Guardrails{MaxActions: 3}); !errors.Is(err, enforce.ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	off := ids(fs, risk.RuleOffboard)
	steps, imp, err := enforce.Plan(src, fs, off[:1], enforce.Guardrails{Protected: map[string]bool{fs[0].Subject: true}})
	if err != nil {
		t.Fatal(err)
	}
	var target string
	for _, f := range fs {
		if f.ID == off[0] {
			target = f.Subject
		}
	}
	_, imp2, _ := enforce.Plan(src, fs, off[:1], enforce.Guardrails{Protected: map[string]bool{target: true}})
	if len(imp2.Blocked) != 1 {
		t.Fatalf("protected target must be blocked: %+v", imp2)
	}
	_ = steps
	_ = imp
	if _, _, err := enforce.Plan(src, fs, []string{"f_nope"}, enforce.Guardrails{}); err == nil {
		t.Fatal("unknown finding must fail")
	}
}

type flaky struct {
	inner enforce.Applier
	fail  int
	n     int
}

func (f *flaky) Apply(ctx context.Context, a model.Action, k string) (*model.Action, error) {
	f.n++
	if f.n == f.fail {
		return nil, errors.New("connection reset")
	}
	return f.inner.Apply(ctx, a, k)
}

// A failure mid-plan stops, records the failed step, and a rerun completes without repeating
// the steps already done.
func TestResumeAfterFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	src, _ := synth.Generate(synth.Config{Humans: 600, Seed: 13, Now: now})
	es := estate.New(src, "t")
	srv := httptest.NewServer(es.Handler())
	defer srv.Close()
	conn := connector.New(srv.URL, "t")
	snap, _ := conn.Fetch(ctx, "acme", synth.Domain, now)
	fs := risk.Analyze(graph.Build(snap))
	steps, _, err := enforce.Plan(snap, fs, ids(fs, risk.RuleOffboard), enforce.Guardrails{})
	if err != nil || len(steps) < 3 {
		t.Fatalf("%d steps, %v", len(steps), err)
	}
	f := &flaky{inner: conn, fail: 2}
	if err := enforce.Execute(ctx, f, "p2", steps, func([]enforce.Step) error { return nil }); err == nil {
		t.Fatal("expected the injected failure")
	}
	if steps[0].State != "done" || steps[1].State != "failed" {
		t.Fatalf("states %s %s", steps[0].State, steps[1].State)
	}
	if err := enforce.Execute(ctx, conn, "p2", steps, func([]enforce.Step) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n := es.Calls["POST /idp/v1/users/{id}/lifecycle/{op}"]; n != len(steps) {
		t.Fatalf("estate saw %d suspensions for %d steps (a step was repeated or lost)", n, len(steps))
	}
}

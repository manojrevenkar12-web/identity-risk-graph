package pdp_test

import (
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/pdp"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
)

const customerData = "arn:aws:s3:::prod-customer-data/exports/2026-10.csv"

func agents(s *model.Snapshot) (readonly, ops, unowned string) {
	owned := map[string]bool{}
	role := map[string]string{}
	for _, e := range s.Edges {
		if e.Kind == model.Owns {
			owned[e.To] = true
		}
		if e.Kind == model.Assigned {
			role[e.From] = e.To
		}
	}
	for _, n := range s.Nodes {
		if n.Kind != model.Agent {
			continue
		}
		switch {
		case !owned[n.ID] && unowned == "":
			unowned = n.ID
		case owned[n.ID] && role[n.ID] == "role:AgentOps" && ops == "":
			ops = n.ID
		case owned[n.ID] && role[n.ID] == "role:AgentReadOnly" && readonly == "":
			readonly = n.ID
		}
	}
	return
}

func TestDecisions(t *testing.T) {
	s, _ := synth.Generate(synth.Config{Humans: 600, Seed: 21})
	e := pdp.New(1000, 1000)
	e.LoadGraph(s)
	ro, ops, unowned := agents(s)
	cases := []struct {
		name string
		req  pdp.Request
		want string
	}{
		{"read-only agent reads analytics", pdp.Request{Agent: ro, Action: "s3:GetObject", Resource: "arn:aws:s3:::analytics-raw/day=1/part-0.parquet"}, "allow"},
		{"read-only agent cannot write", pdp.Request{Agent: ro, Action: "s3:PutObject", Resource: "arn:aws:s3:::analytics-raw/x"}, "deny"},
		{"read-only agent cannot read customer data", pdp.Request{Agent: ro, Action: "s3:GetObject", Resource: customerData}, "deny"},
		{"ops agent reads customer data", pdp.Request{Agent: ops, Action: "s3:GetObject", Resource: customerData}, "allow"},
		{"ops agent deleting customer data needs a human", pdp.Request{Agent: ops, Action: "s3:DeleteObject", Resource: customerData}, "require_approval"},
		{"unowned agent is denied even for reads", pdp.Request{Agent: unowned, Action: "s3:GetObject", Resource: "arn:aws:s3:::analytics-raw/x"}, "deny"},
		{"unknown agent", pdp.Request{Agent: "agt-nope", Action: "s3:GetObject", Resource: "*"}, "deny"},
		{"a human is not an agent", pdp.Request{Agent: "usr-00001", Action: "s3:GetObject", Resource: "*"}, "deny"},
	}
	for _, c := range cases {
		if d := e.Decide(c.req); d.Decision != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, d.Decision, d.Reason, c.want)
		}
	}
	// a just-in-time grant opens exactly what it names, until it expires
	e.LoadGrants([]store.Grant{{ID: "g1", Agent: ro, Action: "s3:PutObject", Resource: "arn:aws:s3:::analytics-raw/backfill/*", Justification: "INC-42 backfill", ExpiresAt: time.Now().Add(time.Hour)}})
	if d := e.Decide(pdp.Request{Agent: ro, Action: "s3:PutObject", Resource: "arn:aws:s3:::analytics-raw/backfill/a"}); d.Decision != "allow" || d.Grant != "g1" {
		t.Errorf("JIT grant: %+v", d)
	}
	if d := e.Decide(pdp.Request{Agent: ro, Action: "s3:PutObject", Resource: "arn:aws:s3:::analytics-raw/other"}); d.Decision != "deny" {
		t.Errorf("JIT grant must not widen beyond its resource: %+v", d)
	}
	e.LoadGrants([]store.Grant{{ID: "g2", Agent: ro, Action: "s3:PutObject", Resource: "*", ExpiresAt: time.Now().Add(-time.Second)}})
	if d := e.Decide(pdp.Request{Agent: ro, Action: "s3:PutObject", Resource: "arn:aws:s3:::analytics-raw/backfill/a"}); d.Decision != "deny" {
		t.Errorf("expired grant: %+v", d)
	}
}

func TestRateLimitStopsARunawayAgent(t *testing.T) {
	s, _ := synth.Generate(synth.Config{Humans: 300, Seed: 22})
	e := pdp.New(5, 10) // 5/s, bursts of 10
	e.LoadGraph(s)
	ro, _, _ := agents(s)
	allowed := 0
	for i := 0; i < 100; i++ {
		if e.Decide(pdp.Request{Agent: ro, Action: "s3:GetObject", Resource: "arn:aws:s3:::analytics-raw/x"}).Decision == "allow" {
			allowed++
		}
	}
	if allowed < 10 || allowed > 12 {
		t.Fatalf("allowed %d of 100 instant requests with a burst of 10", allowed)
	}
}

func BenchmarkDecide(b *testing.B) {
	s, _ := synth.Generate(synth.Config{Humans: 5000, Seed: 23})
	e := pdp.New(1e9, 1e9)
	e.LoadGraph(s)
	ro, _, _ := agents(s)
	go func() {
		for range e.Log {
		}
	}()
	req := pdp.Request{Agent: ro, Action: "s3:GetObject", Resource: "arn:aws:s3:::analytics-raw/day=1/part-0.parquet"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Decide(req)
		}
	})
}

// Package bench produces the numbers in reports/: detection quality against ground truth (and
// against a naive configuration scanner), whole-organisation analysis time and memory as the
// company grows, and AI-agent decision latency.
package bench

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/pdp"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
)

func Run(out string, maxHumans int, log *slog.Logger) error {
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	det := Detection([]uint64{1, 2, 3, 4, 5}, 2000)
	log.Info("detection", "engine", det["summary"].(map[string]any)["graph_engine"], "naive", det["summary"].(map[string]any)["naive_scanner"])
	if err := write(out, "detection.json", det); err != nil {
		return err
	}
	var sizes []int
	for _, n := range []int{2000, 10000, 50000, 100000} {
		if n <= maxHumans {
			sizes = append(sizes, n)
		}
	}
	sc := Scale(sizes)
	log.Info("scale", "rows", sc)
	if err := write(out, "scale.json", sc); err != nil {
		return err
	}
	dec := Decisions(5000, 200_000)
	log.Info("decisions", "result", dec)
	return write(out, "decisions.json", dec)
}

func write(dir, name string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	return os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o600)
}

// ------------------------------------------------------------------------------------- detection
type counts struct{ TP, FP, FN int }

func (c counts) precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}
func (c counts) recall() float64 {
	if c.TP+c.FN == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

func Detection(seeds []uint64, humans int) map[string]any {
	engine, naive := map[string]*counts{}, map[string]*counts{}
	for r := range risk.Rules {
		engine[r], naive[r] = &counts{}, &counts{}
	}
	actors := 0
	for _, seed := range seeds {
		snap, truth := synth.Generate(synth.Config{Humans: humans, Seed: seed})
		g := graph.Build(snap)
		for _, n := range snap.Nodes {
			if n.Kind.Actor() {
				actors++
			}
		}
		score := func(flagged map[string]map[string]bool, into map[string]*counts) {
			for rule := range risk.Rules {
				for id := range flagged[rule] {
					if truth[rule][id] {
						into[rule].TP++
					} else {
						into[rule].FP++
					}
				}
				for id := range truth[rule] {
					if !flagged[rule][id] {
						into[rule].FN++
					}
				}
			}
		}
		got := map[string]map[string]bool{}
		for _, f := range risk.Analyze(g) {
			if got[f.Rule] == nil {
				got[f.Rule] = map[string]bool{}
			}
			got[f.Rule][f.Subject] = true
		}
		score(got, engine)
		score(Naive(snap), naive)
	}
	rows := map[string]any{}
	tot := func(m map[string]*counts) counts {
		var c counts
		for _, x := range m {
			c.TP += x.TP
			c.FP += x.FP
			c.FN += x.FN
		}
		return c
	}
	for r := range risk.Rules {
		e, n := engine[r], naive[r]
		rows[r] = map[string]any{"planted": e.TP + e.FN,
			"graph_engine":  map[string]any{"precision": round(e.precision()), "recall": round(e.recall()), "false_positives": e.FP},
			"naive_scanner": map[string]any{"precision": round(n.precision()), "recall": round(n.recall()), "false_positives": n.FP, "rule": naiveRule[r]}}
	}
	te, tn := tot(engine), tot(naive)
	return map[string]any{
		"setup": fmt.Sprintf("%d synthetic companies (seeds %v), %d people each, %d identities in total; planted risks plus deliberate near-misses", len(seeds), seeds, humans, actors),
		"summary": map[string]any{
			"graph_engine":  map[string]any{"precision": round(te.precision()), "recall": round(te.recall()), "false_positives": te.FP, "true_positives": te.TP},
			"naive_scanner": map[string]any{"precision": round(tn.precision()), "recall": round(tn.recall()), "false_positives": tn.FP, "true_positives": tn.TP},
		},
		"by_rule": rows,
		"caveat":  "Ground truth is planted by the generator, so this measures whether the logic is right on known cases, not recall on a real estate.",
	}
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }

var naiveRule = map[string]string{
	risk.RuleOffboard:  "HR says terminated (ignores whether the account is already deprovisioned)",
	risk.RuleDormant:   "no sign-in for 90 days (ignores what the identity can reach)",
	risk.RuleNoMFA:     "no MFA and member of an admin group or holder of a role named *Admin* (ignores MFA conditions in policies)",
	risk.RuleEscalate:  "reaches a policy whose text mentions iam: or Action * (ignores NotAction, scoping and conditions)",
	risk.RuleToxic:     "reaches a policy mentioning cloudtrail or Action * (ignores Deny statements)",
	risk.RuleStaleCred: "key older than 90 days (ignores what the key can do)",
	risk.RuleAgent:     "agent without owner, or with any role other than read-only by name",
	risk.RuleOAuth:     "any high-risk scope (ignores verified publishers)",
	risk.RuleExternal:  "external email domain (ignores access)",
}

// Naive is what a configuration scanner without effective-permission evaluation reports.
func Naive(s *model.Snapshot) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(r, id string) {
		if out[r] == nil {
			out[r] = map[string]bool{}
		}
		out[r][id] = true
	}
	nodes := map[string]*model.Node{}
	for i := range s.Nodes {
		nodes[s.Nodes[i].ID] = &s.Nodes[i]
	}
	roles := map[string][]string{} // actor → role names reachable by name (groups and assignments, one hop of assume)
	groupsOf := map[string][]string{}
	for _, e := range s.Edges {
		if e.Kind == model.MemberOf {
			groupsOf[e.From] = append(groupsOf[e.From], e.To)
		}
	}
	assigned := map[string][]string{}
	assume := map[string][]string{}
	for _, e := range s.Edges {
		switch e.Kind {
		case model.Assigned:
			assigned[e.From] = append(assigned[e.From], e.To)
		case model.CanAssume:
			assume[e.From] = append(assume[e.From], e.To)
		}
	}
	reach := func(actor string) []string {
		var rs []string
		for _, g := range append([]string{actor}, groupsOf[actor]...) {
			for _, r := range assigned[g] {
				rs = append(rs, r)
				rs = append(rs, assume[r]...)
			}
		}
		return rs
	}
	policyText := func(role string) string {
		b, _ := json.Marshal(s.Policies[role])
		return string(b)
	}
	now := s.TakenAt
	owned := map[string]bool{}
	grants := map[string]int{}
	for _, e := range s.Edges {
		if e.Kind == model.Owns {
			owned[e.To] = true
		}
		if e.Kind == model.Granted {
			grants[e.To]++
		}
	}
	for _, n := range s.Nodes {
		a := n.Attrs
		if a[model.AttrBreakGlass] == "true" {
			continue
		}
		rs := reach(n.ID)
		roles[n.ID] = rs
		texts := ""
		for _, r := range rs {
			texts += policyText(r)
		}
		switch n.Kind {
		case model.Human:
			if a[model.AttrHRStatus] == "terminated" {
				add(risk.RuleOffboard, n.ID)
			}
			if a[model.AttrEmailDomain] != s.Domain {
				add(risk.RuleExternal, n.ID)
			}
			admin := false
			for _, g := range groupsOf[n.ID] {
				if nodes[g] != nil && nodes[g].Attrs["privileged"] == "true" {
					admin = true
				}
			}
			for _, r := range rs {
				if strings.Contains(strings.ToLower(nodes[r].Name), "admin") {
					admin = true
				}
			}
			if a[model.AttrMFA] != "true" && admin {
				add(risk.RuleNoMFA, n.ID)
			}
		case model.Service, model.Agent:
			if t, err := time.Parse(time.RFC3339, a[model.AttrKeyCreated]); err == nil && now.Sub(t) > risk.KeyMaxAge {
				add(risk.RuleStaleCred, n.ID)
			}
			if n.Kind == model.Agent {
				ro := true
				for _, r := range rs {
					if !strings.Contains(nodes[r].Name, "ReadOnly") {
						ro = false
					}
				}
				if !owned[n.ID] || !ro {
					add(risk.RuleAgent, n.ID)
				}
			}
		case model.OAuthApp:
			for _, sc := range strings.Fields(a["scopes"]) {
				if risk.HighRiskScopes[sc] && grants[n.ID] > 0 {
					add(risk.RuleOAuth, n.ID)
					break
				}
			}
			continue
		default:
			continue
		}
		if a[model.AttrStatus] != "active" && n.Kind == model.Human {
			continue
		}
		if t, err := time.Parse(time.RFC3339, a[model.AttrLastSeen]); err == nil && now.Sub(t) > risk.DormantAfter && n.Kind == model.Human {
			add(risk.RuleDormant, n.ID)
		}
		if strings.Contains(texts, `"iam:`) || strings.Contains(texts, `"Action":["*"]`) || strings.Contains(texts, `"Action":"*"`) {
			add(risk.RuleEscalate, n.ID)
		}
		if strings.Contains(texts, "cloudtrail") || strings.Contains(texts, `"Action":["*"]`) {
			add(risk.RuleToxic, n.ID)
		}
	}
	return out
}

// ------------------------------------------------------------------------------------- scale
func Scale(sizes []int) []map[string]any {
	var rows []map[string]any
	for _, n := range sizes {
		snap, _ := synth.Generate(synth.Config{Humans: n, Seed: 7})
		raw, _ := json.Marshal(snap)
		runtime.GC()
		var m0 runtime.MemStats
		runtime.ReadMemStats(&m0)
		peak := uint64(0)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			var m runtime.MemStats
			for {
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak {
					peak = m.HeapInuse
				}
				select {
				case <-stop:
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
		}()
		t0 := time.Now()
		g := graph.Build(snap)
		fs := risk.Analyze(g)
		took := time.Since(t0)
		close(stop)
		wg.Wait()
		actors := 0
		for _, x := range snap.Nodes {
			if x.Kind.Actor() {
				actors++
			}
		}
		rows = append(rows, map[string]any{"people": n, "identities": actors, "nodes": len(snap.Nodes), "edges": len(snap.Edges), "snapshot_mb": round(float64(len(raw)) / 1e6),
			"analysis_seconds": round(took.Seconds()), "findings": len(fs), "peak_heap_mb": round(float64(peak-min(peak, m0.HeapInuse)) / 1e6), "cpus": runtime.NumCPU()})
	}
	return rows
}

// ------------------------------------------------------------------------------------- decisions
func Decisions(humans, n int) map[string]any {
	snap, _ := synth.Generate(synth.Config{Humans: humans, Seed: 8})
	e := pdp.New(1e9, 1e9)
	e.LoadGraph(snap)
	go func() {
		for range e.Log {
		}
	}()
	var agents []string
	for _, x := range snap.Nodes {
		if x.Kind == model.Agent {
			agents = append(agents, x.ID)
		}
	}
	reqs := []pdp.Request{}
	for i, a := range agents {
		reqs = append(reqs,
			pdp.Request{Agent: a, Action: "s3:GetObject", Resource: fmt.Sprintf("arn:aws:s3:::analytics-raw/day=%d/part-0.parquet", i)},
			pdp.Request{Agent: a, Action: "s3:DeleteObject", Resource: "arn:aws:s3:::prod-customer-data/export.csv"},
			pdp.Request{Agent: a, Action: "rds-db:connect", Resource: "arn:aws:rds-db:eu-central-1:" + synth.Account + ":dbuser:staging-core/app"})
	}
	lat := make([]float64, 0, n)
	outcome := map[string]int{}
	t0 := time.Now()
	for i := 0; i < n; i++ {
		s := time.Now()
		d := e.Decide(reqs[i%len(reqs)])
		lat = append(lat, float64(time.Since(s).Nanoseconds())/1e3)
		outcome[d.Decision]++
	}
	single := time.Since(t0)
	sort.Float64s(lat)
	pct := func(p float64) float64 { return round(lat[int(p*float64(len(lat)-1))]) }
	// throughput with every core busy
	var wg sync.WaitGroup
	workers := runtime.NumCPU() * 2
	per := n / workers
	t1 := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				e.Decide(reqs[(w*per+i)%len(reqs)])
			}
		}(w)
	}
	wg.Wait()
	par := time.Since(t1)
	return map[string]any{"setup": fmt.Sprintf("%d people, %d agents, %d decisions, in-process (no HTTP)", humans, len(agents), n),
		"latency_us":             map[string]float64{"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "max": round(lat[len(lat)-1])},
		"single_core_per_second": int(float64(n) / single.Seconds()), "all_cores_per_second": int(float64(per*workers) / par.Seconds()), "cpus": runtime.NumCPU(),
		"outcomes": outcome}
}

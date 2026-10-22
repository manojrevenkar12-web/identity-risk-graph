package risk_test

import (
	"sort"
	"testing"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
)

// Every planted risk is found, and nothing else is flagged, across several generated companies.
func TestDetectionMatchesGroundTruth(t *testing.T) {
	for _, seed := range []uint64{1, 2, 3} {
		snap, truth := synth.Generate(synth.Config{Humans: 1500, Seed: seed})
		fs := risk.Analyze(graph.Build(snap))
		got := map[string]map[string]bool{}
		for _, f := range fs {
			if got[f.Rule] == nil {
				got[f.Rule] = map[string]bool{}
			}
			got[f.Rule][f.Subject] = true
		}
		for rule := range risk.Rules {
			var missed, extra []string
			for id := range truth[rule] {
				if !got[rule][id] {
					missed = append(missed, id)
				}
			}
			for id := range got[rule] {
				if !truth[rule][id] {
					extra = append(extra, id)
				}
			}
			sort.Strings(missed)
			sort.Strings(extra)
			if len(missed) > 0 || len(extra) > 0 {
				t.Errorf("seed %d %s: planted %d, missed %v, false positives %v", seed, rule, len(truth[rule]), head(missed), head(extra))
			}
		}
	}
}

func head(s []string) []string {
	if len(s) > 5 {
		return append(s[:5:5], "…")
	}
	return s
}

func TestFindingsAreStableAndExplained(t *testing.T) {
	snap, _ := synth.Generate(synth.Config{Humans: 400, Seed: 9})
	a := risk.Analyze(graph.Build(snap))
	b := risk.Analyze(graph.Build(snap))
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("got %d and %d findings", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatal("finding IDs and order must be deterministic")
		}
		f := a[i]
		if len(f.Evidence) == 0 || len(f.Controls) == 0 || f.Score <= 0 || f.Score > 100 {
			t.Fatalf("finding without evidence, controls or a sane score: %+v", f)
		}
		if f.Rule != risk.RuleNoMFA && len(f.Remediation) == 0 {
			t.Fatalf("finding without remediation: %+v", f)
		}
	}
}

func TestIdentityScoreCombines(t *testing.T) {
	if s := risk.IdentityScore(nil); s != 0 {
		t.Fatal(s)
	}
}

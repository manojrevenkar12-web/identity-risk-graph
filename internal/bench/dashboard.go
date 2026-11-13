package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
)

// Dashboard writes the data the CISO dashboard (web/) shows: one synthetic company analysed by the
// engine, plus the committed measurements from reports/. Nothing in it is typed by hand.
func Dashboard(reports, out string, humans int, seed uint64) error {
	snap, _ := synth.Generate(synth.Config{Humans: humans, Seed: seed})
	g := graph.Build(snap)
	fs := risk.Analyze(g)

	kinds := map[model.Kind]int{}
	for _, n := range snap.Nodes {
		if n.Kind.Actor() {
			kinds[n.Kind]++
		}
	}
	bySev := map[model.Severity]int{}
	type ruleRow struct {
		Rule     string   `json:"rule"`
		Title    string   `json:"title"`
		Open     int      `json:"open"`
		Critical int      `json:"critical"`
		Controls []string `json:"controls"`
	}
	rules := map[string]*ruleRow{}
	for _, f := range fs {
		bySev[f.Severity]++
		r := rules[f.Rule]
		if r == nil {
			r = &ruleRow{Rule: f.Rule, Title: risk.Rules[f.Rule].Title, Controls: risk.Rules[f.Rule].Controls}
			rules[f.Rule] = r
		}
		r.Open++
		if f.Severity == model.Critical {
			r.Critical++
		}
	}
	rows := make([]*ruleRow, 0, len(rules))
	for _, r := range rules {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Critical != rows[j].Critical {
			return rows[i].Critical > rows[j].Critical
		}
		return rows[i].Open > rows[j].Open || rows[i].Open == rows[j].Open && rows[i].Rule < rows[j].Rule
	})
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Score != fs[j].Score {
			return fs[i].Score > fs[j].Score
		}
		return fs[i].ID < fs[j].ID
	})
	type top struct {
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Severity    string   `json:"severity"`
		Score       float64  `json:"score"`
		Subject     string   `json:"subject"`
		Kind        string   `json:"kind"`
		BlastRadius int      `json:"blast_radius"`
		Evidence    []string `json:"evidence"`
		Controls    []string `json:"controls"`
		Fix         []string `json:"fix"`
	}
	var tops []top
	for _, f := range fs[:min(12, len(fs))] {
		name := f.Subject
		if n := g.Nodes[f.Subject]; n != nil && n.Name != "" {
			name = n.Name
		}
		ev := f.Evidence
		if len(ev) > 4 {
			ev = ev[:4]
		}
		var fix []string
		for _, a := range f.Remediation {
			fix = append(fix, a.Type)
		}
		tops = append(tops, top{f.ID, f.Title, string(f.Severity), f.Score, name, string(f.SubjectKind), f.BlastRadius, ev, f.Controls, fix})
	}
	read := func(name string) any {
		var v any
		b, err := os.ReadFile(filepath.Join(reports, name)) //nolint:gosec // the report directory is the operator's own argument
		if err == nil {
			_ = json.Unmarshal(b, &v)
		}
		return v
	}
	data := map[string]any{
		"company":   map[string]any{"humans": humans, "seed": seed, "identities": kinds, "edges": len(snap.Edges)},
		"open":      bySev,
		"rules":     rows,
		"top":       tops,
		"detection": read("detection.json"),
		"decisions": read("decisions.json"),
		"siem":      read("siem.json"),
		"generated": "irg dashboard (synthetic company, seed " + itoa(seed) + ")",
	}
	if d, ok := data["detection"].(map[string]any); ok {
		data["detection"] = d["summary"] // the per-rule table stays in reports/
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(data, "", " ")
	return os.WriteFile(out, append(b, '\n'), 0o600)
}

func itoa(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

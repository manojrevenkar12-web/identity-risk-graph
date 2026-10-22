// Package enforce turns findings into remediation plans and carries them out safely.
//
// Safety, in order:
//  1. Guardrails at planning time: protected identities (break-glass, an explicit list) are
//     never touched, and a plan larger than MaxActions is refused: big changes are split.
//  2. A dry run on a copy of the graph: which findings the plan resolves, which access each
//     identity loses, and proof it introduces no new finding.
//  3. Four-eyes approval (enforced by the API: approver ≠ author).
//  4. Execution step by step, each step persisted with its undo, each write idempotent, so a
//     crashed worker resumes without repeating a step.
//  5. Rollback replays the recorded undos in reverse order.
package enforce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
)

type Guardrails struct {
	MaxActions int
	Protected  map[string]bool
}

var ErrTooLarge = errors.New("plan exceeds the action limit; split it")

type Step struct {
	model.Action
	State string        `json:"state"` // pending | done | failed | undone
	Undo  *model.Action `json:"undo,omitempty"`
	Error string        `json:"error,omitempty"`
	At    *time.Time    `json:"at,omitempty"`
}

type Blocked struct {
	Action model.Action `json:"action"`
	Reason string       `json:"reason"`
}

type Impact struct {
	Resolves      []string  `json:"resolves"`       // selected findings the plan resolves
	StillOpen     []string  `json:"still_open"`     // selected findings it does not (e.g. MFA enrolment pending)
	AlsoResolves  []string  `json:"also_resolves"`  // other open findings the same actions fix
	NewFindings   []string  `json:"new_findings"`   // must be empty for approval
	AccessRemoved []string  `json:"access_removed"` // crown-jewel access lost, per identity
	Blocked       []Blocked `json:"blocked"`        // actions refused by guardrails
}

// Applier performs one action against the real estate (connector.Client implements it).
type Applier interface {
	Apply(ctx context.Context, a model.Action, idempotencyKey string) (*model.Action, error)
}

// Plan builds the steps and the dry-run impact for the selected findings.
func Plan(s *model.Snapshot, findings []model.Finding, selected []string, gr Guardrails) ([]Step, Impact, error) {
	if gr.MaxActions <= 0 {
		gr.MaxActions = 25
	}
	byID := map[string]model.Finding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	nodes := map[string]*model.Node{}
	for i := range s.Nodes {
		nodes[s.Nodes[i].ID] = &s.Nodes[i]
	}
	var imp Impact
	var steps []Step
	seen := map[string]bool{}
	for _, id := range selected {
		f, ok := byID[id]
		if !ok {
			return nil, imp, fmt.Errorf("finding %s is not open", id)
		}
		for _, a := range f.Remediation {
			k := a.Type + "|" + a.Target + "|" + a.From
			if seen[k] {
				continue
			}
			seen[k] = true
			if n := nodes[a.Target]; gr.Protected[a.Target] || (n != nil && n.Attrs[model.AttrBreakGlass] == "true") {
				imp.Blocked = append(imp.Blocked, Blocked{Action: a, Reason: "protected identity"})
				continue
			}
			steps = append(steps, Step{Action: a, State: "pending"})
		}
	}
	if len(steps) > gr.MaxActions {
		return nil, imp, fmt.Errorf("%w: %d actions, limit %d", ErrTooLarge, len(steps), gr.MaxActions)
	}
	// dry run
	before := graph.Build(s)
	after := Simulate(s, steps)
	ga := graph.Build(after)
	still := map[string]bool{}
	for _, f := range risk.Analyze(ga) {
		still[f.ID] = true
		if _, existed := byID[f.ID]; !existed {
			imp.NewFindings = append(imp.NewFindings, f.ID)
		}
	}
	chosen := map[string]bool{}
	for _, id := range selected {
		chosen[id] = true
		if still[id] {
			imp.StillOpen = append(imp.StillOpen, id)
		} else {
			imp.Resolves = append(imp.Resolves, id)
		}
	}
	for _, f := range findings {
		if !chosen[f.ID] && !still[f.ID] {
			imp.AlsoResolves = append(imp.AlsoResolves, f.ID)
		}
	}
	sort.Strings(imp.AlsoResolves)
	targets := map[string]bool{}
	for _, st := range steps {
		targets[st.Target] = true
	}
	for t := range targets {
		lost := diffCrown(before, ga, t)
		for _, l := range lost {
			imp.AccessRemoved = append(imp.AccessRemoved, t+": "+l)
		}
	}
	sort.Strings(imp.AccessRemoved)
	return steps, imp, nil
}

func diffCrown(before, after *graph.Graph, actor string) []string {
	usable := func(g *graph.Graph) map[string]bool {
		out := map[string]bool{}
		if n := g.Nodes[actor]; n == nil || n.Attrs[model.AttrStatus] != "active" {
			return out
		}
		for r, a := range g.CrownJewels(g.AccessOf(actor)) {
			out[strings.TrimPrefix(r, "res:")+" ("+string(a.Level)+")"] = true
		}
		return out
	}
	b, a := usable(before), usable(after)
	var lost []string
	for k := range b {
		if !a[k] {
			lost = append(lost, k)
		}
	}
	sort.Strings(lost)
	return lost
}

// Simulate applies steps to a copy of the snapshot, mirroring what each connector action does.
func Simulate(s *model.Snapshot, steps []Step) *model.Snapshot {
	c := *s
	c.Nodes = make([]model.Node, len(s.Nodes))
	idx := map[string]int{}
	for i, n := range s.Nodes {
		attrs := make(map[string]string, len(n.Attrs))
		for k, v := range n.Attrs {
			attrs[k] = v
		}
		n.Attrs = attrs
		c.Nodes[i] = n
		idx[n.ID] = i
	}
	drop := map[string]bool{}
	for _, st := range steps {
		n := func() *model.Node {
			if i, ok := idx[st.Target]; ok {
				return &c.Nodes[i]
			}
			return nil
		}()
		switch st.Type {
		case "suspend_user":
			if n != nil {
				n.Attrs[model.AttrStatus] = "suspended"
			}
		case "require_mfa":
			if n != nil {
				n.Attrs["mfa_required"] = "true"
			}
		case "deactivate_key":
			if n != nil {
				n.Attrs[model.AttrStatus], n.Attrs["key_status"] = "inactive", "inactive"
			}
		case "quarantine_agent":
			if n != nil {
				n.Attrs[model.AttrStatus], n.Attrs[model.AttrQuarantined] = "quarantined", "true"
			}
		case "remove_membership":
			drop[string(model.MemberOf)+"|"+st.Target+"|"+st.From] = true
		case "unassign_role":
			drop[string(model.Assigned)+"|"+st.Target+"|"+st.From] = true
		case "revoke_grant":
			drop[string(model.Granted)+"|"+st.Target+"|"+st.From] = true
		}
	}
	c.Edges = make([]model.Edge, 0, len(s.Edges))
	for _, e := range s.Edges {
		if !drop[string(e.Kind)+"|"+e.From+"|"+e.To] {
			c.Edges = append(c.Edges, e)
		}
	}
	return &c
}

// Execute runs pending steps in order. save is called after every step so progress survives a
// crash; a rerun skips done steps and replays nothing (idempotency keys are plan:index).
func Execute(ctx context.Context, conn Applier, planID string, steps []Step, save func([]Step) error) error {
	for i := range steps {
		if steps[i].State == "done" {
			continue
		}
		undo, err := conn.Apply(ctx, steps[i].Action, fmt.Sprintf("%s:%d", planID, i))
		now := time.Now().UTC()
		steps[i].At = &now
		if err != nil {
			steps[i].State, steps[i].Error = "failed", err.Error()
			if serr := save(steps); serr != nil {
				return errors.Join(err, serr)
			}
			return fmt.Errorf("step %d (%s %s): %w", i, steps[i].Type, steps[i].Target, err)
		}
		steps[i].State, steps[i].Undo, steps[i].Error = "done", undo, ""
		if err := save(steps); err != nil {
			return err
		}
	}
	return nil
}

// Rollback undoes every done step, last first.
func Rollback(ctx context.Context, conn Applier, planID string, steps []Step, save func([]Step) error) error {
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].State != "done" {
			continue
		}
		if steps[i].Undo != nil {
			if _, err := conn.Apply(ctx, *steps[i].Undo, fmt.Sprintf("%s:undo:%d", planID, i)); err != nil {
				steps[i].Error = "rollback: " + err.Error()
				_ = save(steps)
				return fmt.Errorf("rollback step %d: %w", i, err)
			}
		}
		steps[i].State = "undone"
		if err := save(steps); err != nil {
			return err
		}
	}
	return nil
}

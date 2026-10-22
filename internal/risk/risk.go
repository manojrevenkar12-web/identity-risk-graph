// Package risk turns the identity graph into findings a CISO can act on.
//
// Each rule is a precise, testable statement about effective access, not a keyword match:
// "this person left the company and can still sign in", "this identity can change production
// and erase the audit trail", "this AI agent has no accountable owner". Every finding carries
// the evidence path, the blast radius (crown-jewel resources exposed), the SOC 2 and
// ISO/IEC 27001:2022 controls it breaks, and a remediation an enforcement plan can execute and
// roll back.
package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

const (
	DormantAfter  = 90 * 24 * time.Hour
	KeyMaxAge     = 90 * 24 * time.Hour
	RuleOffboard  = "offboarding_gap"
	RuleDormant   = "dormant_privileged"
	RuleNoMFA     = "privileged_without_mfa"
	RuleEscalate  = "privilege_escalation"
	RuleToxic     = "toxic_combination"
	RuleStaleCred = "stale_credential" //nolint:gosec // a rule name, not a credential
	RuleAgent     = "ai_agent_risk"
	RuleOAuth     = "risky_oauth_app"
	RuleExternal  = "external_privileged"
)

// Rules lists every rule with its controls, for docs and the API.
var Rules = map[string]struct {
	Title    string
	Controls []string
}{
	RuleOffboard:  {"Left the company, account still active", []string{"SOC2 CC6.2", "SOC2 CC6.3", "ISO27001 A.5.16", "ISO27001 A.5.18"}},
	RuleDormant:   {"Dormant identity with production access", []string{"SOC2 CC6.2", "SOC2 CC6.3", "ISO27001 A.5.18", "ISO27001 A.8.2"}},
	RuleNoMFA:     {"Production access without MFA", []string{"SOC2 CC6.1", "ISO27001 A.8.5"}},
	RuleEscalate:  {"Can grant itself more privileges", []string{"SOC2 CC6.3", "ISO27001 A.8.2"}},
	RuleToxic:     {"Can change production and erase the audit trail", []string{"SOC2 CC6.3", "SOC2 CC7.2", "ISO27001 A.5.3", "ISO27001 A.8.15"}},
	RuleStaleCred: {"Long-lived credential older than 90 days with write access", []string{"SOC2 CC6.1", "ISO27001 A.5.17"}},
	RuleAgent:     {"AI agent without owner or with destructive standing access", []string{"SOC2 CC6.3", "ISO27001 A.5.15", "ISO27001 A.8.2"}},
	RuleOAuth:     {"Unverified third-party app with broad data access", []string{"SOC2 CC6.6", "SOC2 CC9.2", "ISO27001 A.5.19", "ISO27001 A.5.23"}},
	RuleExternal:  {"External identity with production access", []string{"SOC2 CC6.6", "ISO27001 A.5.19", "ISO27001 A.8.2"}},
}

var HighRiskScopes = map[string]bool{"https://mail.google.com/": true, "drive": true, "admin.directory.user": true, "gmail.modify": true}

// Analyze runs every rule over every actor. Parallel across actors; deterministic output order.
func Analyze(g *graph.Graph) []model.Finding {
	g.Precompute()
	privileged := privilegedMembers(g)
	var actors []*model.Node
	for _, n := range g.Nodes {
		if n.Kind.Actor() {
			actors = append(actors, n)
		}
	}
	var mu sync.Mutex
	var out []model.Finding
	work := make(chan *model.Node)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range work {
				fs := analyzeActor(g, n, privileged)
				if len(fs) > 0 {
					mu.Lock()
					out = append(out, fs...)
					mu.Unlock()
				}
			}
		}()
	}
	for _, n := range actors {
		work <- n
	}
	close(work)
	wg.Wait()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func privilegedMembers(g *graph.Graph) map[string]bool {
	out := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind == model.Group && n.Attrs["privileged"] == "true" {
			for _, e := range g.In[n.ID] {
				if e.Kind == model.MemberOf {
					out[e.From] = true
				}
			}
		}
	}
	return out
}

func analyzeActor(g *graph.Graph, n *model.Node, privileged map[string]bool) []model.Finding {
	a := n.Attrs
	if a[model.AttrBreakGlass] == "true" || a[model.AttrQuarantined] == "true" {
		return nil // break-glass is monitored by alerting, not remediated by rules; quarantined is already contained
	}
	now := g.Snap.TakenAt
	if n.Kind == model.OAuthApp {
		return oauthFindings(g, n)
	}
	if a[model.AttrStatus] != "active" {
		return nil // cannot authenticate
	}
	access := g.AccessOf(n.ID)
	crown := g.CrownJewels(access)
	blast := len(crown)
	var out []model.Finding
	add := func(rule string, sev model.Severity, title string, evidence []string, rem []model.Action) {
		out = append(out, finding(g, n, rule, sev, title, evidence, blast, rem))
	}
	crownEvidence := describeCrown(g, crown)

	if n.Kind == model.Human && a[model.AttrHRStatus] == "terminated" {
		sev := model.High
		if blast > 0 {
			sev = model.Critical
		}
		add(RuleOffboard, sev, fmt.Sprintf("%s left the company but can still sign in", n.Name),
			append([]string{"HR status: terminated; IdP status: active"}, crownEvidence...), []model.Action{{Type: "suspend_user", Target: n.ID}})
	}
	if blast > 0 {
		if last, err := time.Parse(time.RFC3339, a[model.AttrLastSeen]); err == nil && now.Sub(last) > DormantAfter {
			add(RuleDormant, model.High, fmt.Sprintf("%s has not signed in for %d days and can still reach %d crown jewels", n.Name, int(now.Sub(last).Hours()/24), blast),
				crownEvidence, removeAccessTo(g, crown))
		}
	}
	if n.Kind == model.Human && a[model.AttrMFA] != "true" {
		esc, escPath := g.Escalation(n.ID)
		if blast > 0 || esc != "" {
			ev := crownEvidence
			if esc != "" {
				ev = append(ev, "can call "+esc+" via "+pathString(g, escPath))
			}
			add(RuleNoMFA, model.High, fmt.Sprintf("%s has production access without MFA", n.Name), ev, []model.Action{{Type: "require_mfa", Target: n.ID}})
		}
	}
	if esc, path := g.Escalation(n.ID); esc != "" && !privileged[n.ID] {
		add(RuleEscalate, model.Critical, fmt.Sprintf("%s can grant itself more privileges (%s)", n.Name, esc),
			[]string{"via " + pathString(g, path) + " → " + esc}, cutPath(g, path))
	}
	if tamper, write := toxic(g, access); tamper != nil && write != nil {
		add(RuleToxic, model.Critical, fmt.Sprintf("%s can change production data and erase the audit trail", n.Name),
			[]string{describe(g, *write), describe(g, *tamper)}, cutPath(g, tamper.Path))
	}
	if n.Kind == model.Service || n.Kind == model.Agent {
		if created, err := time.Parse(time.RFC3339, a[model.AttrKeyCreated]); err == nil && now.Sub(created) > KeyMaxAge && (blast > 0 || canChange(access)) {
			add(RuleStaleCred, model.High, fmt.Sprintf("%s uses a %d-day-old key with write access", n.Name, int(now.Sub(created).Hours()/24)),
				append([]string{"key created " + a[model.AttrKeyCreated]}, writes(g, access)...), []model.Action{{Type: "deactivate_key", Target: n.ID}})
		}
	}
	if n.Kind == model.Agent {
		owned := false
		for _, e := range g.In[n.ID] {
			if e.Kind == model.Owns {
				owned = true
			}
		}
		destructive := destructiveCrown(crown)
		if !owned || len(destructive) > 0 {
			sev, why := model.High, []string{}
			if !owned {
				why = append(why, "no accountable owner")
			}
			if len(destructive) > 0 {
				sev = model.Critical
				why = append(why, destructive...)
			}
			add(RuleAgent, sev, fmt.Sprintf("AI agent %s: %s", n.Name, strings.Join(why, "; ")), why, []model.Action{{Type: "quarantine_agent", Target: n.ID}})
		}
	}
	if n.Kind == model.Human && blast > 0 && a[model.AttrEmailDomain] != "" && a[model.AttrEmailDomain] != g.Snap.Domain {
		add(RuleExternal, model.High, fmt.Sprintf("external identity %s can reach %d crown jewels", n.Name, blast), crownEvidence, removeAccessTo(g, crown))
	}
	return out
}

func oauthFindings(g *graph.Graph, n *model.Node) []model.Finding {
	if n.Attrs[model.AttrVerified] == "true" {
		return nil
	}
	var risky []string
	for _, s := range strings.Fields(n.Attrs["scopes"]) {
		if HighRiskScopes[s] {
			risky = append(risky, s)
		}
	}
	if len(risky) == 0 {
		return nil
	}
	var grants []model.Action
	for _, e := range g.In[n.ID] {
		if e.Kind == model.Granted {
			grants = append(grants, model.Action{Type: "revoke_grant", Target: e.From, From: n.ID})
		}
	}
	if len(grants) == 0 {
		return nil // nobody has consented: the app holds no data
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Target < grants[j].Target })
	return []model.Finding{finding(g, n, RuleOAuth, model.High, fmt.Sprintf("unverified app %s holds %s for %d people", n.Name, strings.Join(risky, ", "), len(grants)),
		[]string{"publisher not verified", "scopes: " + n.Attrs["scopes"], fmt.Sprintf("%d user grants", len(grants))}, 0, grants)}
}

// ------------------------------------------------------------------------------------- helpers
func finding(g *graph.Graph, n *model.Node, rule string, sev model.Severity, title string, ev []string, blast int, rem []model.Action) model.Finding {
	h := sha256.Sum256([]byte(rule + "|" + n.ID))
	return model.Finding{ID: "f_" + hex.EncodeToString(h[:8]), Rule: rule, Severity: sev, Score: score(sev, blast), Subject: n.ID, SubjectKind: n.Kind,
		Title: title, Evidence: ev, BlastRadius: blast, Controls: Rules[rule].Controls, Remediation: rem}
}

func score(s model.Severity, blast int) float64 {
	base := map[model.Severity]float64{model.Critical: 90, model.High: 70, model.Medium: 45, model.Low: 20}[s]
	return math.Min(100, base+math.Min(10, 2*float64(blast)))
}

// IdentityScore combines an identity's findings: 100 × (1 − Π(1 − score/100)).
func IdentityScore(fs []model.Finding) float64 {
	p := 1.0
	for _, f := range fs {
		p *= 1 - f.Score/100
	}
	return math.Round((1-p)*1000) / 10
}

func toxic(g *graph.Graph, access []graph.Access) (tamper, write *graph.Access) {
	for i := range access {
		a := &access[i]
		r := g.Nodes[a.Resource]
		if r.Attrs[model.AttrCrownJewel] != "true" {
			continue
		}
		switch {
		case a.Level == graph.Tamper && r.Attrs[model.AttrResType] == "trail":
			tamper = a
		case (a.Level == graph.Write || a.Level == graph.Delete) && write == nil:
			write = a
		}
	}
	return tamper, write
}

func canChange(access []graph.Access) bool {
	for _, a := range access {
		if a.Level != graph.Read {
			return true
		}
	}
	return false
}

func destructiveCrown(crown map[string]graph.Access) []string {
	var out []string
	for _, a := range crown {
		if a.Level == graph.Delete || a.Level == graph.Tamper || a.Level == graph.Write {
			out = append(out, fmt.Sprintf("can %s %s", a.Level, strings.TrimPrefix(a.Resource, "res:")))
		}
	}
	sort.Strings(out)
	return out
}

func writes(g *graph.Graph, access []graph.Access) []string {
	var out []string
	for _, a := range access {
		if a.Level != graph.Read {
			out = append(out, describe(g, a))
		}
	}
	return out
}

func describeCrown(g *graph.Graph, crown map[string]graph.Access) []string {
	var out []string
	for _, a := range crown {
		out = append(out, describe(g, a))
	}
	sort.Strings(out)
	return out
}

func describe(g *graph.Graph, a graph.Access) string {
	return fmt.Sprintf("%s → %s %s (%s)", pathString(g, a.Path), a.Level, strings.TrimPrefix(a.Resource, "res:"), a.Reason)
}

func pathString(g *graph.Graph, p []string) string {
	names := make([]string, len(p))
	for i, id := range p {
		if n := g.Nodes[id]; n != nil {
			names[i] = n.Name
			if n.Kind == model.Group || n.Kind == model.Role {
				names[i] = string(n.Kind) + ":" + n.Name
			}
		} else {
			names[i] = id
		}
	}
	return strings.Join(names, " → ")
}

// cutPath removes the first hop of a path: leave the group, or unassign the role.
func cutPath(g *graph.Graph, p []string) []model.Action {
	if len(p) < 2 {
		return nil
	}
	next := g.Nodes[p[1]]
	if next != nil && next.Kind == model.Group {
		return []model.Action{{Type: "remove_membership", Target: p[0], From: p[1]}}
	}
	return []model.Action{{Type: "unassign_role", Target: p[0], From: p[1]}}
}

// removeAccessTo cuts every first hop that leads to the given crown-jewel grants.
func removeAccessTo(g *graph.Graph, crown map[string]graph.Access) []model.Action {
	seen := map[string]bool{}
	var out []model.Action
	for _, a := range crown {
		for _, act := range cutPath(g, a.Path) {
			k := act.Type + act.Target + act.From
			if !seen[k] {
				seen[k] = true
				out = append(out, act)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out
}

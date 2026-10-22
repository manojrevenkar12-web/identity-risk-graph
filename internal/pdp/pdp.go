// Package pdp is the policy decision point for AI agents: before an agent acts, it asks
// "may I do <action> on <resource>?" and gets allow, deny or require_approval in well under a
// millisecond, with the reason and the access path.
//
// Order of checks (first match wins):
//  1. unknown, inactive or quarantined agent          → deny
//  2. no accountable human owner                       → deny
//  3. over its rate limit (token bucket per agent)     → deny  (a runaway loop stops here)
//  4. an approved, unexpired just-in-time grant matches → allow (time-boxed elevation)
//  5. no standing access in the identity graph         → deny  (request a JIT grant instead)
//  6. destructive action on a crown-jewel resource     → require_approval, even with access
//  7. otherwise                                        → allow, with the path that grants it
//
// The graph and grants are swapped in atomically when a new analysis or grant lands, so
// decisions never wait on the database. Every decision is logged asynchronously in batches.
package pdp

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/awsiam"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
)

// Destructive action patterns: changes that are hard or impossible to undo.
var Destructive = []string{"*:Delete*", "*:Terminate*", "*:Destroy*", "*:Remove*", "iam:*", "cloudtrail:StopLogging", "kms:ScheduleKeyDeletion",
	"*:Put*Policy", "s3:PutBucketAcl", "rds:ModifyDBInstance", "secretsmanager:PutSecretValue"}

type Request struct {
	Agent    string            `json:"agent_id"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Context  map[string]string `json:"context,omitempty"`
}

type Decision struct {
	ID       string   `json:"decision_id"`
	Decision string   `json:"decision"` // allow | deny | require_approval
	Reason   string   `json:"reason"`
	Path     []string `json:"path,omitempty"`
	Grant    string   `json:"grant_id,omitempty"`
}

type state struct {
	g      *graph.Graph
	owners map[string]bool
	crown  []string // crown-jewel ARNs (and their object prefix for S3)
	grants map[string][]store.Grant
}

type Engine struct {
	st      atomic.Pointer[state]
	rate    float64 // tokens per second per agent
	burst   float64
	mu      sync.Mutex
	buckets map[string]*bucket
	Log     chan store.Decision // drained by the API's batch writer; full channel drops (and counts)
	Dropped atomic.Int64
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(ratePerSec, burst float64) *Engine {
	e := &Engine{rate: ratePerSec, burst: burst, buckets: map[string]*bucket{}, Log: make(chan store.Decision, 65536), now: time.Now}
	e.st.Store(&state{grants: map[string][]store.Grant{}})
	return e
}

// LoadGraph swaps in a new identity graph (after each analysis).
func (e *Engine) LoadGraph(s *model.Snapshot) {
	g := graph.Build(s)
	g.Precompute()
	owners := map[string]bool{}
	for _, edge := range s.Edges {
		if edge.Kind == model.Owns {
			if o := g.Nodes[edge.From]; o != nil && o.Attrs[model.AttrStatus] == "active" {
				owners[edge.To] = true // an owner who left does not count
			}
		}
	}
	var crown []string
	for _, n := range s.Nodes {
		if n.Kind == model.Resource && n.Attrs[model.AttrCrownJewel] == "true" {
			crown = append(crown, n.Attrs[model.AttrARN])
		}
	}
	old := e.st.Load()
	e.st.Store(&state{g: g, owners: owners, crown: crown, grants: old.grants})
}

// LoadGrants swaps in the live JIT grants.
func (e *Engine) LoadGrants(gs []store.Grant) {
	by := map[string][]store.Grant{}
	for _, g := range gs {
		by[g.Agent] = append(by[g.Agent], g)
	}
	old := e.st.Load()
	e.st.Store(&state{g: old.g, owners: old.owners, crown: old.crown, grants: by})
}

func (e *Engine) Ready() bool { return e.st.Load().g != nil }

// Graph is the identity graph decisions are currently made against.
func (e *Engine) Graph() *graph.Graph { return e.st.Load().g }

func (e *Engine) Decide(r Request) Decision {
	t0 := e.now()
	d := e.decide(r, t0)
	d.ID = newID()
	select {
	case e.Log <- store.Decision{At: t0.UTC(), Agent: r.Agent, Action: r.Action, Resource: r.Resource, Decision: d.Decision, Reason: d.Reason,
		LatencyUS: int(e.now().Sub(t0).Microseconds())}:
	default:
		e.Dropped.Add(1)
	}
	return d
}

func (e *Engine) decide(r Request, now time.Time) Decision {
	st := e.st.Load()
	if st.g == nil {
		return Decision{Decision: "deny", Reason: "no identity graph loaded yet"}
	}
	n := st.g.Nodes[r.Agent]
	if n == nil || n.Kind != model.Agent {
		return Decision{Decision: "deny", Reason: "unknown agent"}
	}
	if n.Attrs[model.AttrQuarantined] == "true" {
		return Decision{Decision: "deny", Reason: "agent is quarantined"}
	}
	if n.Attrs[model.AttrStatus] != "active" {
		return Decision{Decision: "deny", Reason: "agent credential is not active"}
	}
	if !st.owners[r.Agent] {
		return Decision{Decision: "deny", Reason: "agent has no active accountable owner"}
	}
	if !e.allowRate(r.Agent, now) {
		return Decision{Decision: "deny", Reason: "rate limit exceeded"}
	}
	for _, g := range st.grants[r.Agent] {
		if now.Before(g.ExpiresAt) && awsiam.Wildcard(strings.ToLower(g.Action), strings.ToLower(r.Action)) && awsiam.Wildcard(g.Resource, r.Resource) {
			return Decision{Decision: "allow", Reason: "just-in-time grant until " + g.ExpiresAt.UTC().Format(time.RFC3339) + ": " + g.Justification, Grant: g.ID}
		}
	}
	ok, path, why := st.g.Can(r.Agent, r.Action, r.Resource, r.Context)
	if !ok {
		return Decision{Decision: "deny", Reason: "no standing access (" + why + "); request a just-in-time grant"}
	}
	if isDestructive(r.Action) && isCrown(st.crown, r.Resource) {
		return Decision{Decision: "require_approval", Reason: "destructive action on a crown-jewel resource needs a human approval", Path: path}
	}
	return Decision{Decision: "allow", Reason: why, Path: path}
}

func isDestructive(action string) bool {
	a := strings.ToLower(action)
	for _, p := range Destructive {
		if awsiam.Wildcard(strings.ToLower(p), a) {
			return true
		}
	}
	return false
}

func isCrown(crown []string, arn string) bool {
	for _, c := range crown {
		if arn == c || strings.HasPrefix(arn, c+"/") {
			return true
		}
	}
	return false
}

func (e *Engine) allowRate(agent string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := e.buckets[agent]
	if b == nil {
		b = &bucket{tokens: e.burst, last: now}
		e.buckets[agent] = b
	}
	b.tokens = min(e.burst, b.tokens+now.Sub(b.last).Seconds()*e.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "d_" + hex.EncodeToString(b)
}

// Package graph answers "who can do what to which resource, and how?" over one snapshot.
//
// Access flows actor → group → role → (assume) role → resource. The last hop is decided by
// evaluating each role's IAM policies (package awsiam) for the actor's authentication context:
// a human who signed in with MFA, one who did not, or a machine with a long-lived key. So a
// policy that only allows admin actions with MFA gives a non-MFA human nothing, as AWS would.
//
// Role access is computed once per (role, context) and shared by every actor that reaches the
// role, which keeps whole-organisation analysis close to linear in the number of actors.
package graph

import (
	"runtime"
	"sort"
	"sync"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/awsiam"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

// Level of access to a resource.
type Level string

const (
	Read   Level = "read"
	Write  Level = "write"
	Delete Level = "delete" // destroy data or the resource
	Tamper Level = "tamper" // disable the audit trail or schedule key deletion
)

// Probe actions per resource type: the questions asked of each role's policies.
var probes = map[string]map[Level][]string{
	"s3":     {Read: {"s3:GetObject"}, Write: {"s3:PutObject"}, Delete: {"s3:DeleteObject", "s3:DeleteBucket"}},
	"rds":    {Read: {"rds-db:connect"}, Delete: {"rds:DeleteDBInstance"}},
	"secret": {Read: {"secretsmanager:GetSecretValue"}, Write: {"secretsmanager:PutSecretValue"}, Delete: {"secretsmanager:DeleteSecret"}},
	"trail":  {Tamper: {"cloudtrail:StopLogging", "cloudtrail:DeleteTrail"}},
	"kms":    {Read: {"kms:Decrypt"}, Tamper: {"kms:ScheduleKeyDeletion"}},
}

// EscalationActions on "*" let an identity grant itself more than it has.
var EscalationActions = []string{"iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy", "iam:PassRole"}

// AuthContext is how an actor authenticates, which changes what IAM conditions see.
type AuthContext int

const (
	HumanMFA AuthContext = iota
	HumanNoMFA
	Machine
)

func (c AuthContext) iam() map[string]string {
	switch c {
	case HumanMFA:
		return map[string]string{"aws:MultiFactorAuthPresent": "true", "aws:PrincipalType": "AssumedRole"}
	case HumanNoMFA:
		return map[string]string{"aws:MultiFactorAuthPresent": "false", "aws:PrincipalType": "AssumedRole"}
	default:
		return map[string]string{"aws:PrincipalType": "User"} // long-term key: the MFA key is absent
	}
}

type Grant struct {
	Resource string // node ID
	Level    Level
	Action   string
	Reason   string // which policy statement allowed it
}

type Access struct {
	Grant
	Role string   // the role that carries the grant
	Path []string // actor … role, node IDs
}

type Graph struct {
	Snap  *model.Snapshot
	Nodes map[string]*model.Node
	Out   map[string][]model.Edge
	In    map[string][]model.Edge

	resources []*model.Node
	mu        sync.Mutex
	roleGrant map[roleCtx][]Grant
	escalate  map[roleCtx]string // role → the escalation action it allows, if any
}

type roleCtx struct {
	role string
	ctx  AuthContext
}

func Build(s *model.Snapshot) *Graph {
	g := &Graph{Snap: s, Nodes: make(map[string]*model.Node, len(s.Nodes)), Out: map[string][]model.Edge{}, In: map[string][]model.Edge{},
		roleGrant: map[roleCtx][]Grant{}, escalate: map[roleCtx]string{}}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		g.Nodes[n.ID] = n
		if n.Kind == model.Resource {
			g.resources = append(g.resources, n)
		}
	}
	for _, e := range s.Edges {
		g.Out[e.From] = append(g.Out[e.From], e)
		g.In[e.To] = append(g.In[e.To], e)
	}
	return g
}

// Precompute evaluates every role in every context in parallel. Optional: queries compute lazily.
func (g *Graph) Precompute() {
	var roles []string
	for id, n := range g.Nodes {
		if n.Kind == model.Role {
			roles = append(roles, id)
		}
	}
	work := make(chan roleCtx)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rc := range work {
				g.grants(rc.role, rc.ctx)
			}
		}()
	}
	for _, r := range roles {
		for _, c := range []AuthContext{HumanMFA, HumanNoMFA, Machine} {
			work <- roleCtx{r, c}
		}
	}
	close(work)
	wg.Wait()
}

// grants: what one role allows on every resource, in one context. Cached.
func (g *Graph) grants(role string, ctx AuthContext) []Grant {
	key := roleCtx{role, ctx}
	g.mu.Lock()
	if v, ok := g.roleGrant[key]; ok {
		g.mu.Unlock()
		return v
	}
	g.mu.Unlock()
	pols := g.Snap.Policies[role]
	cond := ctx.iam()
	var out []Grant
	for _, r := range g.resources {
		arn := r.Attrs[model.AttrARN]
		target := arn
		if r.Attrs[model.AttrResType] == "s3" {
			target = arn + "/*" // object-level actions: any object in the bucket
		}
		for lvl, actions := range probes[r.Attrs[model.AttrResType]] {
			for _, a := range actions {
				res := target
				if a == "s3:DeleteBucket" {
					res = arn
				}
				if d := awsiam.Evaluate(pols, awsiam.Request{Action: a, Resource: res, Context: cond}); d.Allowed {
					out = append(out, Grant{Resource: r.ID, Level: lvl, Action: a, Reason: d.Reason})
					break
				}
			}
		}
	}
	esc := ""
	for _, a := range EscalationActions {
		if awsiam.Evaluate(pols, awsiam.Request{Action: a, Resource: "*", Context: cond}).Allowed {
			esc = a
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Resource+string(out[i].Level) < out[j].Resource+string(out[j].Level)
	})
	g.mu.Lock()
	g.roleGrant[key], g.escalate[key] = out, esc
	g.mu.Unlock()
	return out
}

// ContextOf returns how an actor authenticates.
func (g *Graph) ContextOf(actor string) AuthContext {
	n := g.Nodes[actor]
	if n == nil || n.Kind != model.Human {
		return Machine
	}
	if n.Attrs[model.AttrMFA] == "true" {
		return HumanMFA
	}
	return HumanNoMFA
}

// Roles returns every role an actor can reach and the shortest path to each (BFS over
// member_of, assigned and can_assume edges).
func (g *Graph) Roles(actor string) map[string][]string {
	paths := map[string][]string{actor: {actor}}
	queue := []string{actor}
	out := map[string][]string{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.Out[cur] {
			if e.Kind != model.MemberOf && e.Kind != model.Assigned && e.Kind != model.CanAssume {
				continue
			}
			if _, seen := paths[e.To]; seen {
				continue
			}
			p := append(append([]string{}, paths[cur]...), e.To)
			paths[e.To] = p
			if n := g.Nodes[e.To]; n != nil && n.Kind == model.Role {
				out[e.To] = p
			}
			queue = append(queue, e.To)
		}
	}
	return out
}

// AccessOf lists everything the actor can do, with the shortest path for each grant.
func (g *Graph) AccessOf(actor string) []Access {
	ctx := g.ContextOf(actor)
	best := map[string]Access{} // resource|level → shortest
	for role, path := range g.Roles(actor) {
		for _, gr := range g.grants(role, ctx) {
			k := gr.Resource + "|" + string(gr.Level)
			if cur, ok := best[k]; !ok || len(path) < len(cur.Path) {
				best[k] = Access{Grant: gr, Role: role, Path: path}
			}
		}
	}
	out := make([]Access, 0, len(best))
	for _, a := range best {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Resource+string(out[i].Level) < out[j].Resource+string(out[j].Level)
	})
	return out
}

// Escalation reports whether the actor can reach a role able to grant itself more access.
func (g *Graph) Escalation(actor string) (action string, path []string) {
	ctx := g.ContextOf(actor)
	for role, p := range g.Roles(actor) {
		g.grants(role, ctx)
		g.mu.Lock()
		a := g.escalate[roleCtx{role, ctx}]
		g.mu.Unlock()
		if a != "" && (path == nil || len(p) < len(path)) {
			action, path = a, p
		}
	}
	return action, path
}

// CrownJewels returns the crown-jewel resources the actor can write, delete or tamper with
// (or read, for secrets), i.e. its blast radius.
func (g *Graph) CrownJewels(access []Access) map[string]Access {
	out := map[string]Access{}
	for _, a := range access {
		r := g.Nodes[a.Resource]
		if r == nil || r.Attrs[model.AttrCrownJewel] != "true" {
			continue
		}
		if a.Level == Read && r.Attrs[model.AttrResType] != "secret" && r.Attrs[model.AttrResType] != "s3" && r.Attrs[model.AttrResType] != "rds" {
			continue
		}
		if _, ok := out[a.Resource]; !ok || rank(a.Level) > rank(out[a.Resource].Level) {
			out[a.Resource] = a
		}
	}
	return out
}

func rank(l Level) int {
	switch l {
	case Tamper:
		return 4
	case Delete:
		return 3
	case Write:
		return 2
	default:
		return 1
	}
}

// Can answers one concrete question, for the AI-agent decision point: may this actor perform
// this action on this ARN right now? Returns the path and statement that allow it.
func (g *Graph) Can(actor, action, arn string, extra map[string]string) (bool, []string, string) {
	ctx := g.ContextOf(actor)
	cond := ctx.iam()
	for k, v := range extra {
		cond[k] = v
	}
	var bestPath []string
	reason := "no reachable role allows it"
	for role, p := range g.Roles(actor) {
		d := awsiam.Evaluate(g.Snap.Policies[role], awsiam.Request{Action: action, Resource: arn, Context: cond})
		if d.Allowed && (bestPath == nil || len(p) < len(bestPath)) {
			bestPath, reason = p, d.Reason
		}
	}
	return bestPath != nil, bestPath, reason
}

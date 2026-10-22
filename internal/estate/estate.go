// Package estate is a stand-in for a customer's SaaS estate: an identity provider, an HR system,
// AWS IAM, a Google-Workspace-style app inventory and an AI-agent registry, each behind its own
// HTTP API with paging, bearer auth and idempotency keys on writes. Connectors read it and
// enforcement writes to it exactly as they would to the real services, so the end-to-end tests
// exercise the network path, not a mock function call.
//
// Run it with `irg estate` (seeded from package synth).
package estate

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/awsiam"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

type Server struct {
	mu    sync.Mutex
	s     *model.Snapshot
	token string
	idem  map[string][]byte // idempotency key → response body
	Calls map[string]int    // writes received, by route (tests read it)
}

func New(s *model.Snapshot, token string) *Server {
	return &Server{s: s, token: token, idem: map[string][]byte{}, Calls: map[string]int{}}
}

// ------------------------------------------------------------------------------------- wire types
type User struct {
	ID          string `json:"id"`
	Status      string `json:"status"` // ACTIVE | SUSPENDED | DEPROVISIONED (Okta-style)
	Email       string `json:"email"`
	Department  string `json:"department,omitempty"`
	MFAEnrolled bool   `json:"mfa_enrolled"`
	MFARequired bool   `json:"mfa_required"`
	LastLogin   string `json:"last_login,omitempty"`
	BreakGlass  bool   `json:"break_glass,omitempty"`
}
type GroupW struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Privileged bool   `json:"privileged"`
}
type Membership struct {
	User  string `json:"user"`
	Group string `json:"group"`
}
type Employee struct {
	ID     string `json:"id"`
	Status string `json:"status"` // employed | terminated
}
type RoleW struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	ARN         string          `json:"arn"`
	Policies    []PolicyW       `json:"policies"`
	CanAssume   []string        `json:"can_assume"`
	Assignments json.RawMessage `json:"-"`
}
type PolicyW struct {
	Name     string        `json:"name"`
	Document awsiam.Policy `json:"document"`
}
type Assignment struct {
	Principal string `json:"principal"`
	Role      string `json:"role"`
}
type Principal struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"` // service_account | ai_agent
	Owner       string `json:"owner,omitempty"`
	KeyCreated  string `json:"key_created,omitempty"`
	KeyLastUsed string `json:"key_last_used,omitempty"`
	KeyStatus   string `json:"key_status"` // Active | Inactive (AWS-style)
	LastSeen    string `json:"last_seen,omitempty"`
	Purpose     string `json:"purpose,omitempty"`
}
type ResourceW struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	ARN   string `json:"arn"`
	Type  string `json:"type"`
	Env   string `json:"env"`
	Crown bool   `json:"crown_jewel"`
}
type App struct {
	ID       string `json:"id"`
	Verified bool   `json:"publisher_verified"`
	Scopes   string `json:"scopes"`
}
type GrantW struct {
	User   string `json:"user"`
	App    string `json:"app"`
	Scopes string `json:"scopes"`
}
type AgentW struct {
	ID          string `json:"id"`
	Framework   string `json:"framework,omitempty"`
	Quarantined bool   `json:"quarantined"`
}

// ------------------------------------------------------------------------------------- routing
func (sv *Server) Handler() http.Handler {
	m := http.NewServeMux()
	get := map[string]func() []any{
		"/idp/v1/users": sv.users, "/idp/v1/groups": sv.groups, "/idp/v1/memberships": sv.memberships, "/hr/v1/employees": sv.employees,
		"/aws/v1/roles": sv.roles, "/aws/v1/assignments": sv.assignments, "/aws/v1/principals": sv.principals, "/aws/v1/resources": sv.resources,
		"/workspace/v1/apps": sv.apps, "/workspace/v1/grants": sv.grants, "/agents/v1/agents": sv.agents,
	}
	for path, fn := range get {
		m.HandleFunc("GET "+path, sv.auth(func(w http.ResponseWriter, r *http.Request) { sv.page(w, r, fn) }))
	}
	m.HandleFunc("POST /idp/v1/users/{id}/lifecycle/{op}", sv.write(sv.lifecycle))
	m.HandleFunc("POST /idp/v1/users/{id}/factors/require", sv.write(sv.requireMFA))
	m.HandleFunc("PUT /idp/v1/groups/{group}/members/{user}", sv.write(sv.membership(true)))
	m.HandleFunc("DELETE /idp/v1/groups/{group}/members/{user}", sv.write(sv.membership(false)))
	m.HandleFunc("PUT /aws/v1/assignments/{principal}/{role}", sv.write(sv.assignment(true)))
	m.HandleFunc("DELETE /aws/v1/assignments/{principal}/{role}", sv.write(sv.assignment(false)))
	m.HandleFunc("POST /aws/v1/principals/{id}/keys/{op}", sv.write(sv.key))
	m.HandleFunc("PUT /workspace/v1/grants/{user}/{app}", sv.write(sv.grant(true)))
	m.HandleFunc("DELETE /workspace/v1/grants/{user}/{app}", sv.write(sv.grant(false)))
	m.HandleFunc("POST /agents/v1/agents/{id}/{op}", sv.write(sv.quarantine))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return m
}

func (sv *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sv.token != "" && r.Header.Get("Authorization") != "Bearer "+sv.token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// write wraps a mutation: auth, a lock, and idempotency (same key → same response, no re-apply).
func (sv *Server) write(fn func(r *http.Request) (any, int)) http.HandlerFunc {
	return sv.auth(func(w http.ResponseWriter, r *http.Request) {
		sv.mu.Lock()
		defer sv.mu.Unlock()
		key := r.Header.Get("Idempotency-Key")
		if b, ok := sv.idem[key]; ok && key != "" {
			w.Header().Set("Idempotent-Replay", "true")
			_, _ = w.Write(b)
			return
		}
		body, code := fn(r)
		b, _ := json.Marshal(body)
		if code >= 300 {
			w.WriteHeader(code)
			_, _ = w.Write(b)
			return
		}
		sv.Calls[r.Pattern]++
		if key != "" {
			sv.idem[key] = b
		}
		_, _ = w.Write(b)
	})
}

// page serves ?after=<id>&limit=<n> over items sorted by id, with next=<id> while more remain.
func (sv *Server) page(w http.ResponseWriter, r *http.Request, fn func() []any) {
	sv.mu.Lock()
	items := fn()
	sv.mu.Unlock()
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	after := r.URL.Query().Get("after")
	start := 0
	if after != "" {
		start = len(items)
		for i, it := range items {
			if idOf(it) > after {
				start = i
				break
			}
		}
	}
	end := min(len(items), start+limit)
	out := map[string]any{"data": items[start:end]}
	if end < len(items) {
		out["next"] = idOf(items[end-1])
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func idOf(v any) string {
	switch x := v.(type) {
	case User:
		return x.ID
	case GroupW:
		return x.ID
	case Membership:
		return x.User + "|" + x.Group
	case Employee:
		return x.ID
	case RoleW:
		return x.ID
	case Assignment:
		return x.Principal + "|" + x.Role
	case Principal:
		return x.ID
	case ResourceW:
		return x.ID
	case App:
		return x.ID
	case GrantW:
		return x.User + "|" + x.App
	case AgentW:
		return x.ID
	}
	return ""
}

func sorted[T any](xs []T) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	slices.SortFunc(out, func(a, b any) int { return strings.Compare(idOf(a), idOf(b)) })
	return out
}

// ------------------------------------------------------------------------------------- reads
func (sv *Server) nodes(k model.Kind) []*model.Node {
	var out []*model.Node
	for i := range sv.s.Nodes {
		if sv.s.Nodes[i].Kind == k {
			out = append(out, &sv.s.Nodes[i])
		}
	}
	return out
}

func (sv *Server) node(id string) *model.Node {
	for i := range sv.s.Nodes {
		if sv.s.Nodes[i].ID == id {
			return &sv.s.Nodes[i]
		}
	}
	return nil
}

func (sv *Server) users() []any {
	var out []User
	for _, n := range sv.nodes(model.Human) {
		a := n.Attrs
		st := map[string]string{"active": "ACTIVE", "suspended": "SUSPENDED", "deprovisioned": "DEPROVISIONED"}[a[model.AttrStatus]]
		out = append(out, User{ID: n.ID, Status: st, Email: n.Name, Department: a["department"], MFAEnrolled: a[model.AttrMFA] == "true",
			MFARequired: a["mfa_required"] == "true", LastLogin: a[model.AttrLastSeen], BreakGlass: a[model.AttrBreakGlass] == "true"})
	}
	return sorted(out)
}

func (sv *Server) groups() []any {
	var out []GroupW
	for _, n := range sv.nodes(model.Group) {
		out = append(out, GroupW{ID: n.ID, Name: n.Name, Privileged: n.Attrs["privileged"] == "true"})
	}
	return sorted(out)
}

func (sv *Server) memberships() []any {
	var out []Membership
	for _, e := range sv.s.Edges {
		if e.Kind == model.MemberOf {
			out = append(out, Membership{User: e.From, Group: e.To})
		}
	}
	return sorted(out)
}

func (sv *Server) employees() []any {
	var out []Employee
	for _, n := range sv.nodes(model.Human) {
		out = append(out, Employee{ID: n.ID, Status: n.Attrs[model.AttrHRStatus]})
	}
	return sorted(out)
}

func (sv *Server) roles() []any {
	var out []RoleW
	for _, n := range sv.nodes(model.Role) {
		r := RoleW{ID: n.ID, Name: n.Name, ARN: n.Attrs[model.AttrARN]}
		for _, p := range sv.s.Policies[n.ID] {
			r.Policies = append(r.Policies, PolicyW{Name: p.Name, Document: p})
		}
		for _, e := range sv.s.Edges {
			if e.Kind == model.CanAssume && e.From == n.ID {
				r.CanAssume = append(r.CanAssume, e.To)
			}
		}
		out = append(out, r)
	}
	return sorted(out)
}

func (sv *Server) assignments() []any {
	var out []Assignment
	for _, e := range sv.s.Edges {
		if e.Kind == model.Assigned {
			out = append(out, Assignment{Principal: e.From, Role: e.To})
		}
	}
	return sorted(out)
}

func (sv *Server) principals() []any {
	owners := map[string]string{}
	for _, e := range sv.s.Edges {
		if e.Kind == model.Owns {
			owners[e.To] = e.From
		}
	}
	var out []Principal
	for _, k := range []model.Kind{model.Service, model.Agent} {
		for _, n := range sv.nodes(k) {
			a := n.Attrs
			ks := "Active"
			if a["key_status"] == "inactive" {
				ks = "Inactive"
			}
			out = append(out, Principal{ID: n.ID, Kind: string(k), Owner: owners[n.ID], KeyCreated: a[model.AttrKeyCreated], KeyLastUsed: a[model.AttrKeyLastUsed],
				KeyStatus: ks, LastSeen: a[model.AttrLastSeen], Purpose: a["purpose"]})
		}
	}
	return sorted(out)
}

func (sv *Server) resources() []any {
	var out []ResourceW
	for _, n := range sv.nodes(model.Resource) {
		a := n.Attrs
		out = append(out, ResourceW{ID: n.ID, Name: n.Name, ARN: a[model.AttrARN], Type: a[model.AttrResType], Env: a[model.AttrEnv], Crown: a[model.AttrCrownJewel] == "true"})
	}
	return sorted(out)
}

func (sv *Server) apps() []any {
	var out []App
	for _, n := range sv.nodes(model.OAuthApp) {
		out = append(out, App{ID: n.ID, Verified: n.Attrs[model.AttrVerified] == "true", Scopes: n.Attrs["scopes"]})
	}
	return sorted(out)
}

func (sv *Server) grants() []any {
	var out []GrantW
	seen := map[string]bool{}
	for _, e := range sv.s.Edges {
		if e.Kind == model.Granted && !seen[e.From+e.To] {
			seen[e.From+e.To] = true
			out = append(out, GrantW{User: e.From, App: e.To, Scopes: e.Attrs["scopes"]})
		}
	}
	return sorted(out)
}

func (sv *Server) agents() []any {
	var out []AgentW
	for _, n := range sv.nodes(model.Agent) {
		out = append(out, AgentW{ID: n.ID, Framework: n.Attrs["framework"], Quarantined: n.Attrs[model.AttrQuarantined] == "true"})
	}
	return sorted(out)
}

// ------------------------------------------------------------------------------------- writes
func notFound(what string) (any, int) {
	return map[string]string{"error": what + " not found"}, http.StatusNotFound
}

func (sv *Server) lifecycle(r *http.Request) (any, int) {
	n := sv.node(r.PathValue("id"))
	if n == nil || n.Kind != model.Human {
		return notFound("user")
	}
	switch r.PathValue("op") {
	case "suspend":
		n.Attrs[model.AttrStatus] = "suspended"
	case "unsuspend":
		n.Attrs[model.AttrStatus] = "active"
	default:
		return map[string]string{"error": "unknown operation"}, http.StatusBadRequest
	}
	return map[string]string{"id": n.ID, "status": n.Attrs[model.AttrStatus]}, 200
}

func (sv *Server) requireMFA(r *http.Request) (any, int) {
	n := sv.node(r.PathValue("id"))
	if n == nil || n.Kind != model.Human {
		return notFound("user")
	}
	n.Attrs["mfa_required"] = "true"
	return map[string]string{"id": n.ID, "mfa_required": "true"}, 200
}

func (sv *Server) setEdge(from, to string, kind model.EdgeKind, present bool, attrs map[string]string) (removed *model.Edge) {
	out := sv.s.Edges[:0]
	for _, e := range sv.s.Edges {
		if e.From == from && e.To == to && e.Kind == kind {
			c := e
			removed = &c
			continue
		}
		out = append(out, e)
	}
	sv.s.Edges = out
	if present {
		sv.s.Edges = append(sv.s.Edges, model.Edge{From: from, To: to, Kind: kind, Attrs: attrs})
	}
	return removed
}

func (sv *Server) membership(add bool) func(*http.Request) (any, int) {
	return func(r *http.Request) (any, int) {
		u, g := r.PathValue("user"), r.PathValue("group")
		if sv.node(u) == nil || sv.node(g) == nil {
			return notFound("user or group")
		}
		sv.setEdge(u, g, model.MemberOf, add, nil)
		return Membership{User: u, Group: g}, 200
	}
}

func (sv *Server) assignment(add bool) func(*http.Request) (any, int) {
	return func(r *http.Request) (any, int) {
		p, role := r.PathValue("principal"), r.PathValue("role")
		if sv.node(p) == nil || sv.node(role) == nil {
			return notFound("principal or role")
		}
		sv.setEdge(p, role, model.Assigned, add, nil)
		return Assignment{Principal: p, Role: role}, 200
	}
}

func (sv *Server) key(r *http.Request) (any, int) {
	n := sv.node(r.PathValue("id"))
	if n == nil || (n.Kind != model.Service && n.Kind != model.Agent) {
		return notFound("principal")
	}
	switch r.PathValue("op") {
	case "deactivate":
		n.Attrs["key_status"] = "inactive"
	case "activate":
		delete(n.Attrs, "key_status")
	default:
		return map[string]string{"error": "unknown operation"}, http.StatusBadRequest
	}
	return map[string]string{"id": n.ID}, 200
}

func (sv *Server) grant(add bool) func(*http.Request) (any, int) {
	return func(r *http.Request) (any, int) {
		u, app := r.PathValue("user"), r.PathValue("app")
		if sv.node(u) == nil || sv.node(app) == nil {
			return notFound("user or app")
		}
		var body struct {
			Scopes string `json:"scopes"`
		}
		if add {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Scopes == "" {
				return map[string]string{"error": "scopes required"}, http.StatusBadRequest
			}
			sv.setEdge(u, app, model.Granted, true, map[string]string{"scopes": body.Scopes})
			return GrantW{User: u, App: app, Scopes: body.Scopes}, 200
		}
		removed := sv.setEdge(u, app, model.Granted, false, nil)
		if removed == nil {
			return GrantW{User: u, App: app}, 200 // already gone: deleting is idempotent
		}
		return GrantW{User: u, App: app, Scopes: removed.Attrs["scopes"]}, 200
	}
}

func (sv *Server) quarantine(r *http.Request) (any, int) {
	n := sv.node(r.PathValue("id"))
	if n == nil || n.Kind != model.Agent {
		return notFound("agent")
	}
	switch r.PathValue("op") {
	case "quarantine":
		n.Attrs[model.AttrQuarantined] = "true"
	case "release":
		delete(n.Attrs, model.AttrQuarantined)
	default:
		return map[string]string{"error": "unknown operation"}, http.StatusBadRequest
	}
	return AgentW{ID: n.ID, Quarantined: n.Attrs[model.AttrQuarantined] == "true"}, 200
}

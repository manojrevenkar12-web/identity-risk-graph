// Package connector reads a customer's identity estate into one model.Snapshot and carries out
// remediation actions against it. Reads page through every API; writes send an idempotency key
// so a retried action is applied once, and every write returns its exact inverse for rollback.
package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/awsiam"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

func New(base, token string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// ------------------------------------------------------------------------------------- transport
type httpError struct {
	Code int
	Body string
}

func (e *httpError) Error() string { return fmt.Sprintf("estate: HTTP %d: %s", e.Code, e.Body) }

func (c *Client) do(ctx context.Context, method, path string, body any, idem string, out any) error {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 100 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Content-Type", "application/json")
		if idem != "" {
			req.Header.Set("Idempotency-Key", idem)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			last = err
			continue // network error: retry; writes are idempotent by key
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			last = &httpError{resp.StatusCode, string(b)}
			continue
		}
		if resp.StatusCode >= 300 {
			return &httpError{resp.StatusCode, string(b)}
		}
		if out != nil {
			return json.Unmarshal(b, out)
		}
		return nil
	}
	return last
}

func pages[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	after := ""
	for {
		var page struct {
			Data []T     `json:"data"`
			Next *string `json:"next"`
		}
		q := path + "?limit=500"
		if after != "" {
			q += "&after=" + url.QueryEscape(after)
		}
		if err := c.do(ctx, http.MethodGet, q, nil, "", &page); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, page.Data...)
		if page.Next == nil {
			return all, nil
		}
		after = *page.Next
	}
}

// ------------------------------------------------------------------------------------- read
// Fetch reads the whole estate. domain is the customer's own email domain.
func (c *Client) Fetch(ctx context.Context, tenant, domain string, now time.Time) (*model.Snapshot, error) {
	s := &model.Snapshot{Tenant: tenant, TakenAt: now, Domain: domain, Policies: map[string][]awsiam.Policy{}}
	users, err := pages[estate.User](ctx, c, "/idp/v1/users")
	if err != nil {
		return nil, err
	}
	emps, err := pages[estate.Employee](ctx, c, "/hr/v1/employees")
	if err != nil {
		return nil, err
	}
	hr := map[string]string{}
	for _, e := range emps {
		hr[e.ID] = e.Status
	}
	for _, u := range users {
		dom := ""
		if i := strings.LastIndexByte(u.Email, '@'); i >= 0 {
			dom = u.Email[i+1:]
		}
		a := map[string]string{model.AttrStatus: strings.ToLower(u.Status), model.AttrMFA: fmt.Sprint(u.MFAEnrolled), model.AttrLastSeen: u.LastLogin,
			model.AttrEmailDomain: dom, model.AttrHRStatus: hr[u.ID], "department": u.Department}
		if u.BreakGlass {
			a[model.AttrBreakGlass] = "true"
		}
		if u.MFARequired {
			a["mfa_required"] = "true"
		}
		s.Nodes = append(s.Nodes, model.Node{ID: u.ID, Kind: model.Human, Name: u.Email, Source: "idp", Attrs: a})
	}
	groups, err := pages[estate.GroupW](ctx, c, "/idp/v1/groups")
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		a := map[string]string{}
		if g.Privileged {
			a["privileged"] = "true"
		}
		s.Nodes = append(s.Nodes, model.Node{ID: g.ID, Kind: model.Group, Name: g.Name, Source: "idp", Attrs: a})
	}
	mems, err := pages[estate.Membership](ctx, c, "/idp/v1/memberships")
	if err != nil {
		return nil, err
	}
	for _, m := range mems {
		s.Edges = append(s.Edges, model.Edge{From: m.User, To: m.Group, Kind: model.MemberOf})
	}
	roles, err := pages[estate.RoleW](ctx, c, "/aws/v1/roles")
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		s.Nodes = append(s.Nodes, model.Node{ID: r.ID, Kind: model.Role, Name: r.Name, Source: "aws", Attrs: map[string]string{model.AttrARN: r.ARN}})
		for _, p := range r.Policies {
			doc := p.Document
			if err := doc.Validate(); err != nil {
				return nil, fmt.Errorf("role %s policy %s: %w", r.ID, p.Name, err)
			}
			doc.Name = p.Name
			s.Policies[r.ID] = append(s.Policies[r.ID], doc)
		}
		for _, to := range r.CanAssume {
			s.Edges = append(s.Edges, model.Edge{From: r.ID, To: to, Kind: model.CanAssume})
		}
	}
	asg, err := pages[estate.Assignment](ctx, c, "/aws/v1/assignments")
	if err != nil {
		return nil, err
	}
	for _, a := range asg {
		s.Edges = append(s.Edges, model.Edge{From: a.Principal, To: a.Role, Kind: model.Assigned})
	}
	agents, err := pages[estate.AgentW](ctx, c, "/agents/v1/agents")
	if err != nil {
		return nil, err
	}
	agentInfo := map[string]estate.AgentW{}
	for _, a := range agents {
		agentInfo[a.ID] = a
	}
	prins, err := pages[estate.Principal](ctx, c, "/aws/v1/principals")
	if err != nil {
		return nil, err
	}
	for _, p := range prins {
		a := map[string]string{model.AttrStatus: "active", model.AttrKeyCreated: p.KeyCreated, model.AttrKeyLastUsed: p.KeyLastUsed, model.AttrLastSeen: p.LastSeen}
		if p.Purpose != "" {
			a["purpose"] = p.Purpose
		}
		if p.KeyStatus == "Inactive" {
			a[model.AttrStatus] = "inactive" // its only credential is disabled: it cannot authenticate
			a["key_status"] = "inactive"
		}
		kind := model.Service
		if p.Kind == string(model.Agent) {
			kind = model.Agent
			if ai, ok := agentInfo[p.ID]; ok {
				if ai.Framework != "" {
					a["framework"] = ai.Framework
				}
				if ai.Quarantined {
					a[model.AttrQuarantined] = "true"
					a[model.AttrStatus] = "quarantined"
				}
			}
		}
		s.Nodes = append(s.Nodes, model.Node{ID: p.ID, Kind: kind, Name: p.ID, Source: map[model.Kind]string{model.Service: "aws", model.Agent: "agents"}[kind], Attrs: a})
		if p.Owner != "" {
			s.Edges = append(s.Edges, model.Edge{From: p.Owner, To: p.ID, Kind: model.Owns})
		}
	}
	res, err := pages[estate.ResourceW](ctx, c, "/aws/v1/resources")
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		a := map[string]string{model.AttrARN: r.ARN, model.AttrResType: r.Type, model.AttrEnv: r.Env}
		if r.Crown {
			a[model.AttrCrownJewel] = "true"
		}
		s.Nodes = append(s.Nodes, model.Node{ID: r.ID, Kind: model.Resource, Name: r.Name, Source: "aws", Attrs: a})
	}
	apps, err := pages[estate.App](ctx, c, "/workspace/v1/apps")
	if err != nil {
		return nil, err
	}
	for _, a := range apps {
		s.Nodes = append(s.Nodes, model.Node{ID: a.ID, Kind: model.OAuthApp, Name: a.ID, Source: "workspace", Attrs: map[string]string{model.AttrVerified: fmt.Sprint(a.Verified), "scopes": a.Scopes}})
	}
	grants, err := pages[estate.GrantW](ctx, c, "/workspace/v1/grants")
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		s.Edges = append(s.Edges, model.Edge{From: g.User, To: g.App, Kind: model.Granted, Attrs: map[string]string{"scopes": g.Scopes}})
	}
	return s, nil
}

// ------------------------------------------------------------------------------------- write
// Apply performs one action and returns the action that undoes it (nil when there is nothing to
// undo, e.g. requiring MFA enrolment).
func (c *Client) Apply(ctx context.Context, a model.Action, idem string) (*model.Action, error) {
	esc := url.PathEscape
	inverse := func(t string) *model.Action {
		return &model.Action{Type: t, Target: a.Target, From: a.From, Data: a.Data}
	}
	switch a.Type {
	case "suspend_user", "unsuspend_user":
		op := strings.TrimSuffix(a.Type, "_user")
		if err := c.do(ctx, http.MethodPost, "/idp/v1/users/"+esc(a.Target)+"/lifecycle/"+op, nil, idem, nil); err != nil {
			return nil, err
		}
		return inverse(map[string]string{"suspend_user": "unsuspend_user", "unsuspend_user": "suspend_user"}[a.Type]), nil
	case "require_mfa":
		return nil, c.do(ctx, http.MethodPost, "/idp/v1/users/"+esc(a.Target)+"/factors/require", nil, idem, nil)
	case "remove_membership", "add_membership":
		m := map[string]string{"remove_membership": http.MethodDelete, "add_membership": http.MethodPut}[a.Type]
		if err := c.do(ctx, m, "/idp/v1/groups/"+esc(a.From)+"/members/"+esc(a.Target), nil, idem, nil); err != nil {
			return nil, err
		}
		return inverse(map[string]string{"remove_membership": "add_membership", "add_membership": "remove_membership"}[a.Type]), nil
	case "unassign_role", "assign_role":
		m := map[string]string{"unassign_role": http.MethodDelete, "assign_role": http.MethodPut}[a.Type]
		if err := c.do(ctx, m, "/aws/v1/assignments/"+esc(a.Target)+"/"+esc(a.From), nil, idem, nil); err != nil {
			return nil, err
		}
		return inverse(map[string]string{"unassign_role": "assign_role", "assign_role": "unassign_role"}[a.Type]), nil
	case "deactivate_key", "activate_key":
		op := strings.TrimSuffix(a.Type, "_key")
		if err := c.do(ctx, http.MethodPost, "/aws/v1/principals/"+esc(a.Target)+"/keys/"+op, nil, idem, nil); err != nil {
			return nil, err
		}
		return inverse(map[string]string{"deactivate_key": "activate_key", "activate_key": "deactivate_key"}[a.Type]), nil
	case "revoke_grant":
		var removed estate.GrantW
		if err := c.do(ctx, http.MethodDelete, "/workspace/v1/grants/"+esc(a.Target)+"/"+esc(a.From), nil, idem, &removed); err != nil {
			return nil, err
		}
		if removed.Scopes == "" {
			return nil, nil // it was already gone: nothing to restore
		}
		return &model.Action{Type: "restore_grant", Target: a.Target, From: a.From, Data: map[string]string{"scopes": removed.Scopes}}, nil
	case "restore_grant":
		if err := c.do(ctx, http.MethodPut, "/workspace/v1/grants/"+esc(a.Target)+"/"+esc(a.From), map[string]string{"scopes": a.Data["scopes"]}, idem, nil); err != nil {
			return nil, err
		}
		return &model.Action{Type: "revoke_grant", Target: a.Target, From: a.From}, nil
	case "quarantine_agent", "release_agent":
		op := strings.TrimSuffix(a.Type, "_agent")
		if err := c.do(ctx, http.MethodPost, "/agents/v1/agents/"+esc(a.Target)+"/"+op, nil, idem, nil); err != nil {
			return nil, err
		}
		return inverse(map[string]string{"quarantine_agent": "release_agent", "release_agent": "quarantine_agent"}[a.Type]), nil
	}
	return nil, fmt.Errorf("unknown action type %q", a.Type)
}

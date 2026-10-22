package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/enforce"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/metrics"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/pdp"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
)

type ctxKey struct{}

const keyCacheTTL = 30 * time.Second

type cachedKey struct {
	p     store.Principal
	until time.Time
}

func principal(r *http.Request) store.Principal { return r.Context().Value(ctxKey{}).(store.Principal) }

var roleRank = map[string]int{"agent": 0, "viewer": 1, "analyst": 2, "admin": 3}

// OpsHandler serves health and metrics for a worker-only process.
func (a *App) OpsHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.DB.PingContext(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready"))
	})
	m.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		metrics.Default.Write(w)
	})
	return m
}

// Handler returns the full API.
func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	route := func(pattern, minRole string, h func(w http.ResponseWriter, r *http.Request) error) {
		m.Handle(pattern, a.wrap(pattern, minRole, h))
	}
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.DB.PingContext(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready"))
	})
	m.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		metrics.Default.Write(w)
	})

	route("GET /v1/posture", "viewer", a.getPosture)
	route("GET /v1/findings", "viewer", a.listFindings)
	route("GET /v1/findings/{id}", "viewer", a.getFinding)
	route("GET /v1/findings/{id}/explain", "viewer", a.explain)
	route("POST /v1/findings/{id}/accept", "admin", a.acceptRisk)
	route("GET /v1/identities", "viewer", a.listIdentities)
	route("GET /v1/identities/{id}", "viewer", a.getIdentity)
	route("POST /v1/sync", "admin", a.postSync)
	route("GET /v1/jobs/{id}", "viewer", a.getJob)
	route("POST /v1/plans", "analyst", a.createPlan)
	route("GET /v1/plans", "viewer", a.listPlans)
	route("GET /v1/plans/{id}", "viewer", a.getPlan)
	route("POST /v1/plans/{id}/approve", "admin", a.approvePlan)
	route("POST /v1/plans/{id}/reject", "admin", a.rejectPlan)
	route("POST /v1/plans/{id}/apply", "admin", a.applyPlan)
	route("POST /v1/plans/{id}/rollback", "admin", a.rollbackPlan)
	route("POST /v1/agents/decide", "agent", a.decide)
	route("POST /v1/agents/{id}/grants", "analyst", a.requestGrant)
	route("POST /v1/grants/{id}/approve", "admin", a.approveGrant)
	route("GET /v1/audit", "viewer", a.listAudit)
	route("GET /v1/audit/verify", "viewer", a.verifyAudit)
	route("POST /v1/keys", "admin", a.createKey)
	return a.base(m)
}

// ------------------------------------------------------------------------------------- middleware
type apiError struct {
	code   int
	key    string
	detail string
}

func (e *apiError) Error() string { return e.detail }

func errf(code int, key, detail string) error { return &apiError{code, key, detail} }

func (a *App) base(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'")
		rid := r.Header.Get("X-Request-Id")
		if rid == "" || len(rid) > 64 {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			rid = hex.EncodeToString(b)
		}
		h.Set("X-Request-Id", rid)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		defer func() {
			if v := recover(); v != nil {
				a.Log.Error("panic", "err", v, "request_id", rid)
				writeErr(w, errf(500, "internal", "internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func (a *App) wrap(pattern, minRole string, h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		defer func() {
			mHTTP.Inc(pattern, strconv.Itoa(sw.code))
			mHTTPLat.Observe(time.Since(t0).Seconds(), pattern)
		}()
		p, err := a.authenticate(r)
		if err != nil {
			writeErr(sw, err)
			return
		}
		if !a.limiter.allow(p.ID) {
			sw.Header().Set("Retry-After", "1")
			writeErr(sw, errf(429, "rate_limited", "too many requests"))
			return
		}
		if !permitted(p.Role, minRole) {
			writeErr(sw, errf(403, "forbidden", "role "+p.Role+" cannot call this endpoint"))
			return
		}
		if err := h(sw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p))); err != nil {
			writeErr(sw, err)
		}
	})
}

// permitted: agent keys may only call the decision endpoint (admins may too, for testing);
// people need at least minRole.
func permitted(role, minRole string) bool {
	if minRole == "agent" {
		return role == "agent" || role == "admin"
	}
	return role != "agent" && roleRank[role] >= roleRank[minRole]
}

func (a *App) authenticate(r *http.Request) (store.Principal, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return store.Principal{}, errf(401, "unauthenticated", "missing bearer token")
	}
	if strings.HasPrefix(tok, store.KeyPrefix) {
		h := string(store.HashKey(tok))
		if v, ok := a.keyCache.Load(h); ok && time.Now().Before(v.(cachedKey).until) {
			return v.(cachedKey).p, nil
		}
		var p store.Principal
		err := db.AsApp(r.Context(), a.DB, func(tx *sql.Tx) (err error) { p, err = store.ResolveKey(r.Context(), tx, tok); return })
		if errors.Is(err, store.ErrNotFound) {
			return p, errf(401, "unauthenticated", "invalid API key")
		}
		if err == nil {
			a.keyCache.Store(h, cachedKey{p, time.Now().Add(keyCacheTTL)}) // a revoked key stops working within keyCacheTTL
		}
		return p, err
	}
	if a.Verifier == nil {
		return store.Principal{}, errf(401, "unauthenticated", "invalid API key")
	}
	c, err := a.Verifier.Verify(r.Context(), tok)
	if err != nil {
		return store.Principal{}, errf(401, "unauthenticated", "invalid token")
	}
	role := c.Role
	if _, ok := roleRank[role]; !ok || role == "agent" {
		role = "viewer"
	}
	return store.Principal{Tenant: c.Tenant, Role: role, ID: "user:" + c.Subject, Name: c.Email}, nil
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		switch {
		case errors.Is(err, store.ErrNotFound):
			ae = &apiError{404, "not_found", "not found"}
		case errors.Is(err, store.ErrConflict):
			ae = &apiError{409, "conflict", "the resource is not in a state that allows this"}
		default:
			ae = &apiError{500, "internal", "internal error"}
		}
	}
	writeJSON(w, ae.code, map[string]any{"error": map[string]string{"code": ae.key, "message": ae.detail}})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errf(400, "bad_request", "invalid JSON body: "+err.Error())
	}
	return nil
}

func (a *App) tx(r *http.Request, fn func(*sql.Tx) error) error {
	return db.WithTenant(r.Context(), a.DB, principal(r).Tenant, fn)
}

// ------------------------------------------------------------------------------------- read endpoints
func (a *App) getPosture(w http.ResponseWriter, r *http.Request) error {
	var hist []store.Posture
	if err := a.tx(r, func(tx *sql.Tx) (err error) { hist, err = store.PostureHistory(r.Context(), tx, 30); return }); err != nil {
		return err
	}
	if len(hist) == 0 {
		return errf(404, "no_analysis", "no analysis yet: POST /v1/sync")
	}
	writeJSON(w, 200, map[string]any{"current": hist[0], "history": hist})
	return nil
}

func (a *App) listFindings(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	f := store.FindingFilter{Status: q.Get("status"), Severity: q.Get("severity"), Rule: q.Get("rule"), Subject: q.Get("subject"), Limit: limit}
	if f.Status == "" {
		f.Status = "open"
	}
	var rows []store.FindingRow
	if err := a.tx(r, func(tx *sql.Tx) (err error) { rows, err = store.ListFindings(r.Context(), tx, f); return }); err != nil {
		return err
	}
	if rows == nil {
		rows = []store.FindingRow{}
	}
	writeJSON(w, 200, map[string]any{"findings": rows, "count": len(rows)})
	return nil
}

func (a *App) getFinding(w http.ResponseWriter, r *http.Request) error {
	var f store.FindingRow
	if err := a.tx(r, func(tx *sql.Tx) (err error) { f, err = store.GetFinding(r.Context(), tx, r.PathValue("id")); return }); err != nil {
		return err
	}
	writeJSON(w, 200, f)
	return nil
}

func (a *App) explain(w http.ResponseWriter, r *http.Request) error {
	var f store.FindingRow
	if err := a.tx(r, func(tx *sql.Tx) (err error) { f, err = store.GetFinding(r.Context(), tx, r.PathValue("id")); return }); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	text, src, err := a.Explainer.Explain(ctx, f.Finding)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]string{"finding": f.ID, "explanation": text, "source": src})
	return nil
}

func (a *App) acceptRisk(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if len(strings.TrimSpace(body.Reason)) < 10 {
		return errf(400, "reason_required", "a risk acceptance needs a written reason")
	}
	p, id := principal(r), r.PathValue("id")
	if err := a.tx(r, func(tx *sql.Tx) error {
		if err := store.AcceptRisk(r.Context(), tx, id, p.ID, body.Reason); err != nil {
			return err
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, "finding.accepted", id, map[string]string{"reason": body.Reason})
	}); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]string{"id": id, "status": "accepted"})
	return nil
}

func (a *App) getIdentity(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	te, err := a.engine(r.Context(), p.Tenant)
	if err != nil {
		return err
	}
	g := te.e.Graph()
	if g == nil {
		return errf(404, "no_analysis", "no snapshot yet")
	}
	id := r.PathValue("id")
	n := g.Nodes[id]
	if n == nil || !n.Kind.Actor() {
		return store.ErrNotFound
	}
	var fs []store.FindingRow
	if err := a.tx(r, func(tx *sql.Tx) (err error) {
		fs, err = store.ListFindings(r.Context(), tx, store.FindingFilter{Subject: id, Status: "open"})
		return
	}); err != nil {
		return err
	}
	plain := make([]model.Finding, len(fs))
	for i, f := range fs {
		plain[i] = f.Finding
	}
	access := g.AccessOf(id)
	type acc struct {
		Resource string   `json:"resource"`
		Level    string   `json:"level"`
		Via      []string `json:"via"`
		Reason   string   `json:"reason"`
		Crown    bool     `json:"crown_jewel"`
	}
	out := make([]acc, 0, len(access))
	for _, x := range access {
		out = append(out, acc{x.Resource, string(x.Level), x.Path, x.Reason, g.Nodes[x.Resource].Attrs[model.AttrCrownJewel] == "true"})
	}
	writeJSON(w, 200, map[string]any{"identity": n, "risk_score": risk.IdentityScore(plain), "findings": fs, "access": out,
		"blast_radius": len(g.CrownJewels(access))})
	return nil
}

func (a *App) listIdentities(w http.ResponseWriter, r *http.Request) error {
	te, err := a.engine(r.Context(), principal(r).Tenant)
	if err != nil {
		return err
	}
	g := te.e.Graph()
	if g == nil {
		return errf(404, "no_analysis", "no snapshot yet")
	}
	kind := r.URL.Query().Get("kind")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	type item struct {
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Owned  bool   `json:"owned,omitempty"`
	}
	var out []item
	for _, n := range g.Snap.Nodes {
		if !n.Kind.Actor() || (kind != "" && string(n.Kind) != kind) {
			continue
		}
		owned := false
		for _, e := range g.In[n.ID] {
			if e.Kind == model.Owns {
				owned = true
			}
		}
		out = append(out, item{n.ID, string(n.Kind), n.Name, n.Attrs[model.AttrStatus], owned})
		if len(out) == limit {
			break
		}
	}
	writeJSON(w, 200, map[string]any{"identities": out, "count": len(out)})
	return nil
}

func (a *App) getJob(w http.ResponseWriter, r *http.Request) error {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return store.ErrNotFound
	}
	var status string
	var jerr *string
	if err := a.tx(r, func(tx *sql.Tx) (err error) { status, jerr, err = store.JobStatus(r.Context(), tx, id); return }); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": status, "error": jerr})
	return nil
}

func (a *App) listAudit(w http.ResponseWriter, r *http.Request) error {
	var es []store.AuditEntry
	if err := a.tx(r, func(tx *sql.Tx) (err error) { es, err = store.ListAudit(r.Context(), tx, 200); return }); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"entries": es})
	return nil
}

func (a *App) verifyAudit(w http.ResponseWriter, r *http.Request) error {
	var n int
	var broken int64
	p := principal(r)
	if err := a.tx(r, func(tx *sql.Tx) (err error) { n, broken, err = store.VerifyAudit(r.Context(), tx, p.Tenant); return }); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"entries": n, "intact": broken == 0, "first_broken_seq": broken})
	return nil
}

// ------------------------------------------------------------------------------------- write endpoints
func (a *App) postSync(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	var id int64
	if err := a.tx(r, func(tx *sql.Tx) (err error) {
		if id, err = store.Enqueue(r.Context(), tx, p.Tenant, "sync", map[string]string{"by": p.ID}, 0); err != nil {
			return err
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, "sync.requested", strconv.FormatInt(id, 10), nil)
	}); err != nil {
		return err
	}
	writeJSON(w, 202, map[string]any{"job_id": id})
	return nil
}

func (a *App) createPlan(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		FindingIDs []string `json:"finding_ids"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if len(body.FindingIDs) == 0 || len(body.FindingIDs) > 200 {
		return errf(400, "bad_request", "finding_ids must hold 1 to 200 findings")
	}
	p := principal(r)
	var plan store.Plan
	err := a.tx(r, func(tx *sql.Tx) error {
		_, snap, err := store.LatestSnapshot(r.Context(), tx)
		if err != nil {
			return err
		}
		rows, err := store.ListFindings(r.Context(), tx, store.FindingFilter{Status: "open", Limit: 1000})
		if err != nil {
			return err
		}
		open := make([]model.Finding, len(rows))
		for i, f := range rows {
			open[i] = f.Finding
		}
		steps, impact, err := enforce.Plan(snap, open, body.FindingIDs, a.guardrails())
		if errors.Is(err, enforce.ErrTooLarge) {
			return errf(422, "plan_too_large", err.Error())
		}
		if err != nil {
			return errf(422, "invalid_plan", err.Error())
		}
		if len(impact.NewFindings) > 0 {
			return errf(422, "plan_introduces_risk", "the dry run shows this plan would create new findings")
		}
		if len(steps) == 0 {
			return errf(422, "nothing_to_do", "every action was blocked by guardrails")
		}
		if plan, err = store.CreatePlan(r.Context(), tx, p.Tenant, p.ID, body.FindingIDs, steps, impact); err != nil {
			return err
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, "plan.created", plan.ID, map[string]any{"findings": len(body.FindingIDs), "steps": len(steps)})
	})
	if err != nil {
		return err
	}
	writeJSON(w, 201, plan)
	return nil
}

func (a *App) listPlans(w http.ResponseWriter, r *http.Request) error {
	var ps []store.Plan
	if err := a.tx(r, func(tx *sql.Tx) (err error) { ps, err = store.ListPlans(r.Context(), tx, 50); return }); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"plans": ps})
	return nil
}

func (a *App) getPlan(w http.ResponseWriter, r *http.Request) error {
	var plan store.Plan
	if err := a.tx(r, func(tx *sql.Tx) (err error) {
		plan, err = store.GetPlan(r.Context(), tx, r.PathValue("id"), false)
		return
	}); err != nil {
		return err
	}
	writeJSON(w, 200, plan)
	return nil
}

// planTransition: shared shape of approve / reject / apply / rollback.
func (a *App) planTransition(w http.ResponseWriter, r *http.Request, from []string, to, action, job string, fourEyes bool) error {
	p, id := principal(r), r.PathValue("id")
	var jobID int64
	err := a.tx(r, func(tx *sql.Tx) error {
		plan, err := store.GetPlan(r.Context(), tx, id, true)
		if err != nil {
			return err
		}
		if fourEyes && plan.CreatedBy == p.ID {
			return errf(403, "four_eyes", "a plan must be approved by someone other than its author")
		}
		var approver *string
		if fourEyes {
			approver = &p.ID
		}
		if err := store.TransitionPlan(r.Context(), tx, id, from, to, approver); err != nil {
			return err
		}
		if job != "" {
			if jobID, err = store.Enqueue(r.Context(), tx, p.Tenant, job, map[string]string{"plan": id}, 0); err != nil {
				return err
			}
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, action, id, nil)
	})
	if err != nil {
		return err
	}
	out := map[string]any{"id": id, "status": to}
	if jobID != 0 {
		out["job_id"] = jobID
	}
	writeJSON(w, 200, out)
	return nil
}

func (a *App) approvePlan(w http.ResponseWriter, r *http.Request) error {
	return a.planTransition(w, r, []string{"draft"}, "approved", "plan.approved", "", true)
}
func (a *App) rejectPlan(w http.ResponseWriter, r *http.Request) error {
	return a.planTransition(w, r, []string{"draft", "approved"}, "rejected", "plan.rejected", "", false)
}
func (a *App) applyPlan(w http.ResponseWriter, r *http.Request) error {
	return a.planTransition(w, r, []string{"approved", "failed"}, "applying", "plan.apply_requested", "apply", false)
}
func (a *App) rollbackPlan(w http.ResponseWriter, r *http.Request) error {
	return a.planTransition(w, r, []string{"applied", "failed"}, "rolling_back", "plan.rollback_requested", "rollback", false)
}

func (a *App) decide(w http.ResponseWriter, r *http.Request) error {
	var req pdp.Request
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Agent == "" || req.Action == "" || req.Resource == "" {
		return errf(400, "bad_request", "agent_id, action and resource are required")
	}
	p := principal(r)
	if p.Role == "agent" && p.Name != req.Agent {
		return errf(403, "forbidden", "an agent key may only ask about its own agent")
	}
	te, err := a.engine(r.Context(), p.Tenant)
	if err != nil {
		return err
	}
	t0 := time.Now()
	d := te.e.Decide(req)
	mDecLat.Observe(time.Since(t0).Seconds(), d.Decision)
	mDecisions.Inc(d.Decision)
	writeJSON(w, 200, d)
	return nil
}

func (a *App) requestGrant(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Action        string `json:"action"`
		Resource      string `json:"resource"`
		TTLMinutes    int    `json:"ttl_minutes"`
		Justification string `json:"justification"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if body.Action == "" || body.Resource == "" || body.Resource == "*" || strings.TrimSpace(body.Justification) == "" {
		return errf(400, "bad_request", "action, a specific resource and a justification are required")
	}
	if body.TTLMinutes <= 0 || body.TTLMinutes > 480 {
		return errf(400, "bad_request", "ttl_minutes must be between 1 and 480")
	}
	p := principal(r)
	var g store.Grant
	err := a.tx(r, func(tx *sql.Tx) (err error) {
		g, err = store.CreateGrant(r.Context(), tx, p.Tenant, store.Grant{Agent: r.PathValue("id"), Action: body.Action, Resource: body.Resource,
			Justification: body.Justification, RequestedBy: p.ID, ExpiresAt: time.Now().Add(time.Duration(body.TTLMinutes) * time.Minute)})
		if err != nil {
			return err
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, "grant.requested", g.ID, body)
	})
	if err != nil {
		return err
	}
	writeJSON(w, 201, g)
	return nil
}

func (a *App) approveGrant(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	var g store.Grant
	err := a.tx(r, func(tx *sql.Tx) (err error) {
		if g, err = store.ApproveGrant(r.Context(), tx, r.PathValue("id"), p.ID); err != nil {
			return err
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, "grant.approved", g.ID, map[string]string{"agent": g.Agent, "action": g.Action, "resource": g.Resource})
	})
	if errors.Is(err, store.ErrNotFound) {
		return errf(404, "not_found", "no pending grant with that id that you did not request yourself")
	}
	if err != nil {
		return err
	}
	if te, err := a.engine(r.Context(), p.Tenant); err == nil {
		_ = a.refresh(r.Context(), p.Tenant, te) // effective now, not in 5 seconds
	}
	writeJSON(w, 200, g)
	return nil
}

func (a *App) createKey(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if _, ok := roleRank[body.Role]; !ok || body.Name == "" {
		return errf(400, "bad_request", "name and a role of viewer, analyst, admin or agent are required (agent keys are named after the agent id)")
	}
	p := principal(r)
	var key string
	err := a.tx(r, func(tx *sql.Tx) (err error) {
		if key, err = store.CreateKey(r.Context(), tx, p.Tenant, body.Name, body.Role); err != nil {
			return err
		}
		return store.Audit(r.Context(), tx, p.Tenant, p.ID, "key.created", body.Name, map[string]string{"role": body.Role})
	})
	if err != nil {
		return err
	}
	writeJSON(w, 201, map[string]string{"key": key, "name": body.Name, "role": body.Role, "note": "shown once; store it in a secret manager"})
	return nil
}

// ------------------------------------------------------------------------------------- rate limiter
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*[2]float64 // tokens, last unix seconds
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[string]*[2]float64{}}
}

func (l *limiter) allow(id string) bool {
	now := float64(time.Now().UnixNano()) / 1e9
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[id]
	if b == nil {
		b = &[2]float64{l.burst, now}
		l.buckets[id] = b
	}
	b[0] = min(l.burst, b[0]+(now-b[1])*l.rate)
	b[1] = now
	if b[0] < 1 {
		return false
	}
	b[0]--
	return true
}

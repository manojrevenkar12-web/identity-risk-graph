package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/connector"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/enforce"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/graph"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/risk"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
)

const lease = 10 * time.Minute

// RunWorker processes jobs until ctx ends, and schedules a sync per tenant every SyncInterval.
func (a *App) RunWorker(ctx context.Context) {
	go a.schedule(ctx)
	for ctx.Err() == nil {
		did, err := a.WorkOnce(ctx)
		if err != nil {
			a.Log.Error("worker", "err", err)
		}
		if !did {
			select {
			case <-ctx.Done():
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
}

func (a *App) schedule(ctx context.Context) {
	tick := func() {
		var tenants []store.TenantRef
		err := db.AsApp(ctx, a.DB, func(tx *sql.Tx) (err error) { tenants, err = store.Tenants(ctx, tx); return })
		if err != nil {
			a.Log.Warn("scheduler", "err", err)
			return
		}
		for _, t := range tenants {
			_ = db.WithTenant(ctx, a.DB, t.ID, func(tx *sql.Tx) error {
				if busy, err := store.PendingJob(ctx, tx, "sync"); err != nil || busy {
					return err
				}
				_, err := store.Enqueue(ctx, tx, t.ID, "sync", map[string]string{"by": "scheduler"}, 0)
				return err
			})
		}
	}
	tick()
	t := time.NewTicker(a.Cfg.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// WorkOnce claims and runs one job. It returns false when the queue is empty.
func (a *App) WorkOnce(ctx context.Context) (bool, error) {
	var job *store.Job
	if err := db.AsApp(ctx, a.DB, func(tx *sql.Tx) (err error) { job, err = store.ClaimJob(ctx, tx, lease); return }); err != nil || job == nil {
		return false, err
	}
	t0 := time.Now()
	var jobErr error
	switch job.Kind {
	case "sync":
		jobErr = a.sync(ctx, job.Tenant)
	case "analyze":
		jobErr = a.analyze(ctx, job.Tenant)
	case "apply", "rollback":
		var p struct {
			Plan string `json:"plan"`
		}
		_ = json.Unmarshal(job.Payload, &p)
		jobErr = a.runPlan(ctx, job.Tenant, p.Plan, job.Kind == "rollback")
	default:
		jobErr = fmt.Errorf("unknown job kind %q", job.Kind)
	}
	outcome := "ok"
	if jobErr != nil {
		outcome = "error"
		a.Log.Warn("job failed", "id", job.ID, "kind", job.Kind, "tenant", job.Tenant, "attempt", job.Attempts, "err", jobErr)
	}
	mJobs.Inc(job.Kind, outcome)
	mJobSeconds.Observe(time.Since(t0).Seconds(), job.Kind)
	return true, db.WithTenant(ctx, a.DB, job.Tenant, func(tx *sql.Tx) error { return store.FinishJob(ctx, tx, job.ID, jobErr, job.Attempts, job.Max) })
}

func (a *App) connector(settings map[string]string) (*connector.Client, error) {
	url := settings["estate_url"]
	if url == "" {
		url = a.Cfg.EstateURL
	}
	if url == "" {
		return nil, errors.New("tenant has no estate_url and IRG_ESTATE_URL is not set")
	}
	return connector.New(url, a.Cfg.EstateToken), nil
}

func (a *App) sync(ctx context.Context, tenant string) error {
	var domain string
	var settings map[string]string
	if err := db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) (err error) { domain, settings, err = store.TenantSettings(ctx, tx); return }); err != nil {
		return err
	}
	c, err := a.connector(settings)
	if err != nil {
		return err
	}
	snap, err := c.Fetch(ctx, tenant, domain, a.Clock().UTC()) // network I/O outside any transaction
	if err != nil {
		return err
	}
	return db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) error {
		id, err := store.SaveSnapshot(ctx, tx, tenant, snap)
		if err != nil {
			return err
		}
		if _, err := store.Enqueue(ctx, tx, tenant, "analyze", map[string]int64{"snapshot": id}, 0); err != nil {
			return err
		}
		return store.Audit(ctx, tx, tenant, "system:worker", "sync.completed", fmt.Sprint(id), map[string]int{"nodes": len(snap.Nodes), "edges": len(snap.Edges)})
	})
}

func (a *App) analyze(ctx context.Context, tenant string) error {
	var snapID int64
	var snap *model.Snapshot
	if err := db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) (err error) { snapID, snap, err = store.LatestSnapshot(ctx, tx); return }); err != nil {
		return err
	}
	t0 := time.Now()
	g := graph.Build(snap)
	fs := risk.Analyze(g)
	took := time.Since(t0)
	p := posture(g, fs, a.Clock().UTC())
	return db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) error {
		res, err := store.SyncFindings(ctx, tx, tenant, fs, p.At)
		if err != nil {
			return err
		}
		if p.MTTRHours, err = store.MTTR(ctx, tx, p.At.Add(-30*24*time.Hour)); err != nil {
			return err
		}
		var accepted int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM findings WHERE status = 'accepted'").Scan(&accepted); err != nil {
			return err
		}
		p.Accepted = accepted
		if err := store.SavePosture(ctx, tx, tenant, snapID, p); err != nil {
			return err
		}
		for _, sev := range []model.Severity{model.Critical, model.High, model.Medium, model.Low} {
			mOpen.Set(float64(p.Open[string(sev)]), tenant, string(sev))
		}
		return store.Audit(ctx, tx, tenant, "system:worker", "analysis.completed", fmt.Sprint(snapID),
			map[string]any{"opened": res.Opened, "resolved": res.Resolved, "open": len(fs), "analysis_ms": took.Milliseconds()})
	})
}

func posture(g *graph.Graph, fs []model.Finding, at time.Time) store.Posture {
	p := store.Posture{At: at, Open: map[string]int{}, OpenByRule: map[string]int{}}
	bySubject := map[string][]model.Finding{}
	for _, f := range fs {
		p.Open[string(f.Severity)]++
		p.OpenByRule[f.Rule]++
		bySubject[f.Subject] = append(bySubject[f.Subject], f)
	}
	for _, n := range g.Nodes {
		if n.Kind.Actor() {
			p.Actors++
		}
	}
	total := 0.0
	for _, list := range bySubject {
		total += risk.IdentityScore(list)
	}
	p.IdentitiesAtRisk = len(bySubject)
	if p.Actors > 0 {
		p.MeanIdentityRisk = float64(int(total/float64(p.Actors)*100)) / 100
	}
	return p
}

// runPlan executes or rolls back a plan, persisting each step as it completes.
func (a *App) runPlan(ctx context.Context, tenant, planID string, rollback bool) error {
	var plan store.Plan
	var settings map[string]string
	err := db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) (err error) {
		if plan, err = store.GetPlan(ctx, tx, planID, false); err != nil {
			return err
		}
		_, settings, err = store.TenantSettings(ctx, tx)
		return err
	})
	if err != nil {
		return err
	}
	var steps []enforce.Step
	if err := json.Unmarshal(plan.Steps, &steps); err != nil {
		return err
	}
	c, err := a.connector(settings)
	if err != nil {
		return err
	}
	save := func(s []enforce.Step) error {
		return db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) error { return store.SavePlanSteps(ctx, tx, planID, s) })
	}
	var runErr error
	final, action := "applied", "plan.applied"
	if rollback {
		runErr = enforce.Rollback(ctx, c, planID, steps, save)
		final, action = "rolled_back", "plan.rolled_back"
	} else {
		runErr = enforce.Execute(ctx, c, planID, steps, save)
	}
	if runErr != nil {
		final, action = "failed", "plan.failed"
	}
	from := []string{"applying"}
	if rollback {
		from = []string{"rolling_back"}
	}
	err = db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) error {
		if err := store.TransitionPlan(ctx, tx, planID, from, final, nil); err != nil {
			return err
		}
		detail := map[string]any{"steps": len(steps)}
		if runErr != nil {
			detail["error"] = runErr.Error()
		}
		if err := store.Audit(ctx, tx, tenant, "system:worker", action, planID, detail); err != nil {
			return err
		}
		_, err := store.Enqueue(ctx, tx, tenant, "sync", map[string]string{"by": "plan " + planID}, 0) // verify against the estate
		return err
	})
	if err != nil {
		return err
	}
	if runErr != nil {
		a.Log.Warn("plan failed; it can be resumed or rolled back", "plan", planID, "err", runErr)
	}
	return nil // a failed plan is a recorded outcome, not a job to retry blindly
}

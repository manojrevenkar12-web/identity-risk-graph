// Package app wires the platform together: configuration, the job worker and the HTTP API.
package app

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/auth"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/enforce"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/llm"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/metrics"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/pdp"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
)

type Config struct {
	DatabaseURL  string
	Addr         string
	WorkerAddr   string // health and metrics of a worker-only process
	EstateURL    string // default estate for tenants without their own estate_url setting
	EstateToken  string
	SyncInterval time.Duration
	MaxActions   int
	Protected    map[string]bool
	PDPRate      float64
	PDPBurst     float64
	APIRate      float64 // requests per second per API key or user
	APIBurst     float64
	OIDCIssuer   string
	OIDCAudience string
	OIDCJWKS     string
	BedrockModel string
	AWSRegion    string
}

// env reads K, or the file named by K_FILE (secrets mounted as files, not environment
// variables, which leak into /proc and crash dumps).
func env(k, def string) string {
	if f := os.Getenv(k + "_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil { //nolint:gosec // the path comes from the operator's own configuration
			return strings.TrimSpace(string(b))
		}
	}
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func ConfigFromEnv() Config {
	num := func(k string, def float64) float64 {
		f, err := strconv.ParseFloat(env(k, ""), 64)
		if err != nil {
			return def
		}
		return f
	}
	sync, err := time.ParseDuration(env("IRG_SYNC_INTERVAL", "15m"))
	if err != nil {
		sync = 15 * time.Minute
	}
	prot := map[string]bool{}
	for _, p := range strings.Split(env("IRG_PROTECTED_IDENTITIES", ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			prot[p] = true
		}
	}
	return Config{
		WorkerAddr:  env("IRG_WORKER_ADDR", ":9100"),
		DatabaseURL: env("DATABASE_URL", "postgres://postgres@localhost:5432/irg?sslmode=disable"), Addr: env("IRG_ADDR", ":8080"),
		EstateURL: env("IRG_ESTATE_URL", ""), EstateToken: env("IRG_ESTATE_TOKEN", ""), SyncInterval: sync,
		MaxActions: int(num("IRG_MAX_PLAN_ACTIONS", 25)), Protected: prot, PDPRate: num("IRG_AGENT_RATE", 50), PDPBurst: num("IRG_AGENT_BURST", 100),
		APIRate: num("IRG_API_RATE", 100), APIBurst: num("IRG_API_BURST", 200),
		OIDCIssuer: env("IRG_OIDC_ISSUER", ""), OIDCAudience: env("IRG_OIDC_AUDIENCE", "irg"), OIDCJWKS: env("IRG_OIDC_JWKS_URL", ""),
		BedrockModel: env("IRG_BEDROCK_MODEL_ID", ""), AWSRegion: env("AWS_REGION", "eu-central-1"),
	}
}

type App struct {
	DB        *sql.DB
	Cfg       Config
	Log       *slog.Logger
	Verifier  *auth.Verifier
	Explainer llm.Explainer
	Clock     func() time.Time

	mu       sync.Mutex
	engines  map[string]*tenantEngine
	limiter  *limiter
	keyCache sync.Map // sha256(key) → cachedKey
}

func New(d *sql.DB, cfg Config, log *slog.Logger) *App {
	a := &App{DB: d, Cfg: cfg, Log: log, Explainer: llm.Template{}, Clock: time.Now, engines: map[string]*tenantEngine{}, limiter: newLimiter(cfg.APIRate, cfg.APIBurst)}
	if cfg.OIDCIssuer != "" && cfg.OIDCJWKS != "" {
		a.Verifier = auth.NewVerifier(cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCJWKS)
	}
	if cfg.BedrockModel != "" && os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		a.Explainer = &llm.Bedrock{Region: cfg.AWSRegion, ModelID: cfg.BedrockModel, Fallback: llm.Template{},
			Creds: llm.Credentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN")}}
	}
	return a
}

func (a *App) guardrails() enforce.Guardrails {
	return enforce.Guardrails{MaxActions: a.Cfg.MaxActions, Protected: a.Cfg.Protected}
}

// ------------------------------------------------------------------------------------- metrics
var (
	mHTTP       = metrics.Default.Counter("irg_http_requests_total", "HTTP requests", "route", "code")
	mHTTPLat    = metrics.Default.Histogram("irg_http_request_seconds", "HTTP latency", []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5}, "route")
	mDecisions  = metrics.Default.Counter("irg_agent_decisions_total", "AI-agent access decisions", "decision")
	mDecLat     = metrics.Default.Histogram("irg_agent_decision_seconds", "Decision latency inside the engine", []float64{.00001, .000025, .00005, .0001, .00025, .0005, .001, .005}, "decision")
	mJobs       = metrics.Default.Counter("irg_jobs_total", "Jobs finished", "kind", "outcome")
	mJobSeconds = metrics.Default.Histogram("irg_job_seconds", "Job duration", []float64{.1, .5, 1, 5, 15, 60, 300}, "kind")
	mOpen       = metrics.Default.Gauge("irg_open_findings", "Open findings after the last analysis", "tenant", "severity")
	mDropped    = metrics.Default.Counter("irg_decision_log_dropped_total", "Decisions not logged because the buffer was full")
)

// ------------------------------------------------------------------------------------- per-tenant decision engine
type tenantEngine struct {
	e        *pdp.Engine
	snapshot int64
	stop     chan struct{}
	flushed  chan struct{} // closed when the decision log has been written out after stop
}

// engine returns the tenant's decision engine, loading it on first use and keeping it fresh:
// a new snapshot or grant is picked up within 5 seconds, decisions never wait on the database.
func (a *App) engine(ctx context.Context, tenant string) (*tenantEngine, error) {
	a.mu.Lock()
	te, ok := a.engines[tenant]
	a.mu.Unlock()
	if ok {
		return te, nil
	}
	te = &tenantEngine{e: pdp.New(a.Cfg.PDPRate, a.Cfg.PDPBurst), stop: make(chan struct{}), flushed: make(chan struct{})}
	if err := a.refresh(ctx, tenant, te); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if existing, ok := a.engines[tenant]; ok {
		a.mu.Unlock()
		return existing, nil
	}
	a.engines[tenant] = te
	a.mu.Unlock()
	go a.keepFresh(tenant, te)
	go a.logDecisions(tenant, te)
	return te, nil
}

func (a *App) refresh(ctx context.Context, tenant string, te *tenantEngine) error {
	return db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) error {
		var latest sql.NullInt64
		if err := tx.QueryRowContext(ctx, "SELECT max(id) FROM snapshots").Scan(&latest); err != nil {
			return err
		}
		if latest.Valid && latest.Int64 != te.snapshot {
			id, snap, err := store.LatestSnapshot(ctx, tx)
			if err != nil {
				return err
			}
			te.e.LoadGraph(snap)
			te.snapshot = id
		}
		gs, err := store.LiveGrants(ctx, tx)
		if err != nil {
			return err
		}
		te.e.LoadGrants(gs)
		return nil
	})
}

func (a *App) keepFresh(tenant string, te *tenantEngine) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-te.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := a.refresh(ctx, tenant, te); err != nil {
				a.Log.Warn("decision engine refresh failed", "tenant", tenant, "err", err)
			}
			cancel()
		}
	}
}

// logDecisions writes decisions in batches of up to 500 or every second.
func (a *App) logDecisions(tenant string, te *tenantEngine) {
	batch := make([]store.Decision, 0, 500)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := db.WithTenant(ctx, a.DB, tenant, func(tx *sql.Tx) error { return store.SaveDecisions(ctx, tx, tenant, batch) })
		cancel()
		if err != nil {
			a.Log.Warn("decision log write failed", "tenant", tenant, "n", len(batch), "err", err)
		}
		batch = batch[:0]
	}
	var lastDropped int64
	for {
		select {
		case <-te.stop:
			for { // drain what is buffered, then write it
				select {
				case d := <-te.e.Log:
					batch = append(batch, d)
					if len(batch) == cap(batch) {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			close(te.flushed)
			return
		case d := <-te.e.Log:
			batch = append(batch, d)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-t.C:
			flush()
			if n := te.e.Dropped.Load(); n > lastDropped {
				mDropped.Add(float64(n - lastDropped))
				lastDropped = n
			}
		}
	}
}

// Close stops background goroutines and waits (up to 10 s) for decision logs to be written.
func (a *App) Close() {
	a.mu.Lock()
	engines := a.engines
	a.engines = map[string]*tenantEngine{}
	a.mu.Unlock()
	for _, te := range engines {
		close(te.stop)
	}
	deadline := time.After(10 * time.Second)
	for _, te := range engines {
		select {
		case <-te.flushed:
		case <-deadline:
			a.Log.Warn("decision log flush timed out")
			return
		}
	}
}

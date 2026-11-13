// Command irg runs the identity risk platform.
//
//	irg migrate                                  apply database migrations
//	irg tenant create <slug> <name> <domain>     create a tenant; prints its first admin key
//	irg tenant set <tenant-id> <key> <value>     set a tenant setting (estate_url)
//	irg api | irg worker | irg all               serve the API, run the worker, or both
//	irg estate [-humans N] [-seed S]             run the demo SaaS estate (synthetic company)
//	irg bench [-out reports]                     detection, scale and decision benchmarks
//	irg loadtest -keys keys.json [-c 32 -d 20s]  HTTP load test of the agent decision endpoint
//	irg dashboard [-out web/public/data/...]     data for the CISO dashboard (web/)
//	irg siem-drill [-out reports/siem.json]      SIEM delivery under busy replies and lost acknowledgements
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/app"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/bench"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/siem"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/trace"
)

var version = "dev" // set at build time: -ldflags "-X main.version=..."

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("version", version)
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, os.Args[1], os.Args[2:]); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: irg migrate | tenant create <slug> <name> <domain> | tenant set <id> <key> <value> | api | worker | all | estate | bench")
	os.Exit(2)
}

func run(ctx context.Context, log *slog.Logger, cmd string, args []string) error {
	cfg := app.ConfigFromEnv()
	switch cmd {
	case "estate":
		fs := flag.NewFlagSet("estate", flag.ExitOnError)
		humans := fs.Int("humans", 2000, "people in the synthetic company")
		seed := fs.Uint64("seed", 1, "random seed")
		addr := fs.String("addr", envOr("ESTATE_ADDR", ":9090"), "listen address")
		_ = fs.Parse(args)
		snap, truth := synth.Generate(synth.Config{Humans: *humans, Seed: *seed, Now: time.Now().UTC()})
		planted := 0
		for _, ids := range truth {
			planted += len(ids)
		}
		log.Info("estate ready", "addr", *addr, "nodes", len(snap.Nodes), "edges", len(snap.Edges), "planted_risks", planted)
		return serve(ctx, log, *addr, estate.New(snap, os.Getenv("IRG_ESTATE_TOKEN")).Handler())
	case "loadtest":
		fs := flag.NewFlagSet("loadtest", flag.ExitOnError)
		base := fs.String("base", "http://localhost:8080", "API base URL")
		keysFile := fs.String("keys", "", "JSON file: {agent_id: api_key}")
		conc := fs.Int("c", 32, "concurrent clients")
		dur := fs.Duration("d", 20*time.Second, "duration")
		out := fs.String("out", "", "write the report here too")
		_ = fs.Parse(args)
		raw, err := os.ReadFile(*keysFile)
		if err != nil {
			return err
		}
		keys := map[string]string{}
		if err := json.Unmarshal(raw, &keys); err != nil {
			return err
		}
		rep, err := bench.LoadTest(*base, keys, *conc, *dur)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		if *out != "" {
			return os.WriteFile(*out, append(b, '\n'), 0o600)
		}
		return nil
	case "health": // for container HEALTHCHECK on distroless images (no shell, no curl)
		url := envOr("IRG_HEALTH_URL", "http://127.0.0.1:8080/healthz")
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get(url) //nolint:gosec,noctx // a fixed local health URL
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("health: HTTP %d", resp.StatusCode)
		}
		return nil
	case "dashboard": // data for the CISO dashboard in web/
		fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
		out := fs.String("out", "web/public/data/dashboard.json", "output file")
		humans := fs.Int("humans", 2000, "people in the synthetic company")
		_ = fs.Parse(args)
		return bench.Dashboard("reports", *out, *humans, 1)
	case "bench":
		fs := flag.NewFlagSet("bench", flag.ExitOnError)
		out := fs.String("out", "reports", "report directory")
		scale := fs.Int("max-humans", 50000, "largest company size for the scale benchmark")
		_ = fs.Parse(args)
		return bench.Run(*out, *scale, log)
	}

	d, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer d.Close()
	switch cmd {
	case "migrate":
		return db.Migrate(ctx, d)
	case "siem-drill": // delivery to a SIEM that is busy and loses acknowledgements (reports/siem.json)
		fs := flag.NewFlagSet("siem-drill", flag.ExitOnError)
		out := fs.String("out", "reports/siem.json", "report file")
		audits := fs.Int("audit", 2000, "audit-log entries")
		decisions := fs.Int("decisions", 50000, "agent decisions")
		busy := fs.Float64("busy", 0.2, "share of requests answered 503")
		lost := fs.Float64("lost", 0.03, "share of requests stored but never acknowledged")
		_ = fs.Parse(args)
		if err := db.Migrate(ctx, d); err != nil {
			return err
		}
		res, err := siem.Drill(ctx, d, *audits, *decisions, *busy, *lost, 11)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		log.Info("siem drill", "result", res)
		return os.WriteFile(*out, append(b, '\n'), 0o600)
	case "tenant":
		if len(args) == 4 && args[0] == "create" {
			id, key, err := store.CreateTenant(ctx, d, args[1], args[2], args[3])
			if err != nil {
				return err
			}
			fmt.Printf("{\"tenant_id\":%q,\"admin_key\":%q}\n", id, key)
			return nil
		}
		if len(args) == 4 && args[0] == "set" {
			return store.SetTenantSetting(ctx, d, args[1], args[2], args[3])
		}
		usage()
	case "api", "worker", "all":
		// OpenTelemetry traces go to OTEL_EXPORTER_OTLP_ENDPOINT when it is set; nothing is recorded otherwise.
		trace.Default = trace.New(trace.FromEnv("irg-"+cmd, version))
		defer func() {
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = trace.Default.Shutdown(shut)
		}()
		if err := db.Migrate(ctx, d); err != nil {
			return err
		}
		a := app.New(d, cfg, log)
		defer a.Close()
		if cmd != "api" {
			go a.RunWorker(ctx)
			if sinks := siemSinks(); len(sinks) > 0 {
				x := &siem.Exporter{DB: d, Sinks: sinks, Log: log, IncludeAllow: os.Getenv("IRG_SIEM_INCLUDE_ALLOW") == "true"}
				go x.Run(ctx, 15*time.Second)
				log.Info("siem export on", "sinks", len(sinks))
			}
		}
		if cmd == "worker" { // health and metrics only
			return serve(ctx, log, cfg.WorkerAddr, a.OpsHandler())
		}
		return serve(ctx, log, cfg.Addr, a.Handler())
	default:
		usage()
	}
	return nil
}

func serve(ctx context.Context, log *slog.Logger, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", addr)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// siemSinks builds the configured SIEM sinks. Secrets come from files (*_FILE), as Kubernetes mounts them.
func siemSinks() []siem.Sink {
	var out []siem.Sink
	if u := os.Getenv("IRG_SIEM_SPLUNK_URL"); u != "" {
		out = append(out, &siem.SplunkHEC{URL: u, Token: secret("IRG_SIEM_SPLUNK_TOKEN"), Index: os.Getenv("IRG_SIEM_SPLUNK_INDEX")})
	}
	if e := os.Getenv("IRG_SIEM_SENTINEL_ENDPOINT"); e != "" {
		out = append(out, &siem.Sentinel{Endpoint: e, RuleID: os.Getenv("IRG_SIEM_SENTINEL_RULE_ID"),
			Stream: envOr("IRG_SIEM_SENTINEL_STREAM", "Custom-IrgSecurityEvents_CL"),
			Token: &siem.AzureToken{TenantID: os.Getenv("IRG_SIEM_SENTINEL_TENANT_ID"), ClientID: os.Getenv("IRG_SIEM_SENTINEL_CLIENT_ID"),
				ClientSecret: secret("IRG_SIEM_SENTINEL_CLIENT_SECRET")}})
	}
	return out
}

func secret(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // the path is operator configuration
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return os.Getenv(name)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

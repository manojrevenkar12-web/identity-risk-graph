// Command irg runs the identity risk platform.
//
//	irg migrate                                  apply database migrations
//	irg tenant create <slug> <name> <domain>     create a tenant; prints its first admin key
//	irg tenant set <tenant-id> <key> <value>     set a tenant setting (estate_url)
//	irg api | irg worker | irg all               serve the API, run the worker, or both
//	irg estate [-humans N] [-seed S]             run the demo SaaS estate (synthetic company)
//	irg bench [-out reports]                     detection, scale and decision benchmarks
//	irg loadtest -keys keys.json [-c 32 -d 20s]  HTTP load test of the agent decision endpoint
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
	"syscall"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/app"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/bench"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/estate"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/synth"
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
		if err := db.Migrate(ctx, d); err != nil {
			return err
		}
		a := app.New(d, cfg, log)
		defer a.Close()
		if cmd != "api" {
			go a.RunWorker(ctx)
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

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

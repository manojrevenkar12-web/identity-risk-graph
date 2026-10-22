// Package db owns the PostgreSQL connection, migrations and the tenant boundary.
//
// Every tenant-scoped query goes through WithTenant, which opens a transaction, drops to the
// non-owner role irg_app and sets app.tenant_id for that transaction only. Row-level security
// then makes it impossible for a query to read or write another tenant's rows, even a buggy
// query with a missing WHERE clause (tests prove it).
package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrations embed.FS

const migrationLock = 7_301_449

func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	d, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(20)
	d.SetMaxIdleConns(10)
	d.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return d, nil
}

// Migrate applies embedded migrations once, under an advisory lock so replicas can start together.
func Migrate(ctx context.Context, d *sql.DB) error {
	conn, err := d.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLock) }()
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		body, _ := migrations.ReadFile(name)
		sum := fmt.Sprintf("%x", sha256.Sum256(body))
		var have string
		err := conn.QueryRowContext(ctx, "SELECT sha256 FROM schema_migrations WHERE name = $1", name).Scan(&have)
		switch {
		case err == nil && have != sum:
			return fmt.Errorf("migration %s was changed after it was applied", name)
		case err == nil:
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (name, sha256) VALUES ($1, $2)", name, sum); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ErrNoTenant guards against calling WithTenant with an empty tenant.
var ErrNoTenant = errors.New("no tenant in context")

// WithTenant runs fn in a transaction confined to one tenant by row-level security.
func WithTenant(ctx context.Context, d *sql.DB, tenant string, fn func(*sql.Tx) error) error {
	if strings.TrimSpace(tenant) == "" {
		return ErrNoTenant
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE irg_app"); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenant); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// AsApp runs fn as irg_app without a tenant: only the SECURITY DEFINER functions return data.
func AsApp(ctx context.Context, d *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE irg_app"); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

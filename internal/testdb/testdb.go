// Package testdb gives each test package a fresh, migrated PostgreSQL database.
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"testing"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
)

// URL of the server to create databases on (as an owner role): IRG_TEST_DATABASE_URL, default local.
func URL() string {
	if u := os.Getenv("IRG_TEST_DATABASE_URL"); u != "" {
		return u
	}
	return "postgres://postgres@localhost:5432/postgres?sslmode=disable"
}

func New(t testing.TB) *sql.DB {
	t.Helper()
	ctx := context.Background()
	admin, err := sql.Open("postgres", URL())
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("no PostgreSQL at %s: %v", URL(), err)
	}
	name := fmt.Sprintf("irg_test_%d", rand.Int64()) //nolint:gosec // a unique name, not a secret
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(URL())
	u.Path = "/" + name
	d, err := db.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
		if _, err := admin.ExecContext(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop %s: %v", name, err)
		}
		_ = admin.Close()
	})
	return d
}

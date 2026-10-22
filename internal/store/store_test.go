package store_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/testdb"
)

func TestTenantIsolationIsEnforcedByTheDatabase(t *testing.T) {
	ctx := context.Background()
	d := testdb.New(t)
	a, keyA, err := store.CreateTenant(ctx, d, "acme", "Acme", "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := store.CreateTenant(ctx, d, "globex", "Globex", "globex.example")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, tn := range []string{a, b} {
		err := db.WithTenant(ctx, d, tn, func(tx *sql.Tx) error {
			_, err := store.SyncFindings(ctx, tx, tn, []model.Finding{{ID: "f_" + tn[:8], Rule: "r", Severity: model.High, Score: 70, Subject: "u", SubjectKind: model.Human, Title: "t", Evidence: []string{"e"}, Controls: []string{"c"}}}, now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// a query with no tenant filter still sees only its own tenant's rows
	err = db.WithTenant(ctx, d, a, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM findings").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("tenant A sees %d findings, want 1", n)
		}
		// writing into another tenant is refused by WITH CHECK
		if _, err := tx.ExecContext(ctx, "SAVEPOINT cross_tenant"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO findings (tenant_id, id, rule, severity, score, subject, subject_kind, title, evidence, controls, remediation, blast_radius)
			VALUES ($1, 'x', 'r', 'high', 1, 's', 'human', 't', '[]', '{}', '[]', 0)`, b)
		if err == nil {
			t.Error("insert into another tenant must fail")
		}
		_, err = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT cross_tenant")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// no tenant set: nothing at all, not everything
	err = db.AsApp(ctx, d, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM findings").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("without a tenant the app role sees %d rows", n)
		}
		p, err := store.ResolveKey(ctx, tx, keyA)
		if err != nil || p.Tenant != a || p.Role != "admin" {
			t.Errorf("resolve key: %+v %v", p, err)
		}
		if _, err := store.ResolveKey(ctx, tx, "irg_nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown key: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTenant(ctx, d, "", func(*sql.Tx) error { return nil }); !errors.Is(err, db.ErrNoTenant) {
		t.Fatal("empty tenant must be refused")
	}
}

func TestFindingLifecycle(t *testing.T) {
	ctx := context.Background()
	d := testdb.New(t)
	tn, _, _ := store.CreateTenant(ctx, d, "acme", "Acme", "acme.example")
	f := func(id string) model.Finding {
		return model.Finding{ID: id, Rule: "r", Severity: model.High, Score: 70, Subject: id, SubjectKind: model.Human, Title: id, Evidence: []string{"e"}, Controls: []string{"c"}}
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	run := func(at time.Time, fs ...model.Finding) store.SyncResult {
		var r store.SyncResult
		if err := db.WithTenant(ctx, d, tn, func(tx *sql.Tx) (err error) { r, err = store.SyncFindings(ctx, tx, tn, fs, at); return }); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := run(t0, f("a"), f("b")); r.Opened != 2 {
		t.Fatalf("%+v", r)
	}
	if r := run(t0.Add(6*time.Hour), f("a")); r.Resolved != 1 || r.Updated != 1 {
		t.Fatalf("%+v", r)
	}
	err := db.WithTenant(ctx, d, tn, func(tx *sql.Tx) error {
		h, err := store.MTTR(ctx, tx, t0.Add(-time.Hour))
		if err != nil || h == nil || *h != 6 {
			t.Errorf("MTTR %v %v", h, err)
		}
		return store.AcceptRisk(ctx, tx, "a", "user:ciso", "compensating control: VPN only")
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := run(t0.Add(12*time.Hour), f("a"), f("b")); r.Opened != 0 || r.Updated != 2 {
		t.Fatalf("a resolved finding that reappears is reopened, not duplicated: %+v", r)
	}
	db.WithTenant(ctx, d, tn, func(tx *sql.Tx) error { //nolint:errcheck
		rows, _ := store.ListFindings(ctx, tx, store.FindingFilter{})
		st := map[string]string{}
		for _, r := range rows {
			st[r.ID] = r.Status
		}
		if st["a"] != "accepted" || st["b"] != "open" {
			t.Errorf("statuses %v", st)
		}
		return nil
	})
}

func TestAuditChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	d := testdb.New(t)
	tn, _, _ := store.CreateTenant(ctx, d, "acme", "Acme", "acme.example")
	for i := 0; i < 5; i++ {
		if err := db.WithTenant(ctx, d, tn, func(tx *sql.Tx) error {
			return store.Audit(ctx, tx, tn, "user:alice", "plan.approve", "plan-1", map[string]any{"n": i, "zeta": "z", "alpha": []string{"a"}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	verify := func() (int, int64) {
		var n int
		var broken int64
		db.WithTenant(ctx, d, tn, func(tx *sql.Tx) (err error) { n, broken, err = store.VerifyAudit(ctx, tx, tn); return }) //nolint:errcheck
		return n, broken
	}
	if n, broken := verify(); n != 5 || broken != 0 {
		t.Fatalf("intact chain: %d entries, broken at %d", n, broken)
	}
	// an attacker with database access edits one row: verification points at it
	if _, err := d.ExecContext(ctx, "UPDATE audit_log SET actor = 'user:mallory' WHERE seq = (SELECT min(seq) + 2 FROM audit_log)"); err != nil {
		t.Fatal(err)
	}
	if _, broken := verify(); broken == 0 {
		t.Fatal("tampering not detected")
	}
}

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"
)

type Plan struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	CreatedBy  string          `json:"created_by"`
	ApprovedBy *string         `json:"approved_by,omitempty"`
	FindingIDs []string        `json:"finding_ids"`
	Steps      json.RawMessage `json:"steps"`
	Impact     json.RawMessage `json:"impact"`
	CreatedAt  time.Time       `json:"created_at"`
	ApprovedAt *time.Time      `json:"approved_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

func CreatePlan(ctx context.Context, tx *sql.Tx, tenant, by string, findings []string, steps, impact any) (Plan, error) {
	s, _ := json.Marshal(steps)
	i, _ := json.Marshal(impact)
	var p Plan
	err := tx.QueryRowContext(ctx, `INSERT INTO plans (tenant_id, status, created_by, finding_ids, actions, impact) VALUES ($1, 'draft', $2, $3, $4, $5)
		RETURNING id, status, created_by, approved_by, finding_ids, actions, impact, created_at, approved_at, finished_at`,
		tenant, by, pq.Array(findings), s, i).Scan(&p.ID, &p.Status, &p.CreatedBy, &p.ApprovedBy, pq.Array(&p.FindingIDs), &p.Steps, &p.Impact, &p.CreatedAt, &p.ApprovedAt, &p.FinishedAt)
	return p, err
}

func GetPlan(ctx context.Context, tx *sql.Tx, id string, forUpdate bool) (Plan, error) {
	q := `SELECT id, status, created_by, approved_by, finding_ids, actions, impact, created_at, approved_at, finished_at FROM plans WHERE id = $1`
	if forUpdate {
		q += " FOR UPDATE"
	}
	var p Plan
	err := tx.QueryRowContext(ctx, q, id).Scan(&p.ID, &p.Status, &p.CreatedBy, &p.ApprovedBy, pq.Array(&p.FindingIDs), &p.Steps, &p.Impact, &p.CreatedAt, &p.ApprovedAt, &p.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// TransitionPlan moves a plan from one status to another, failing if it is not in `from`.
func TransitionPlan(ctx context.Context, tx *sql.Tx, id string, from []string, to string, approver *string) error {
	q := `UPDATE plans SET status = $2,
		approved_by = COALESCE($4, approved_by), approved_at = CASE WHEN $4::text IS NOT NULL THEN now() ELSE approved_at END,
		finished_at = CASE WHEN $2 IN ('applied', 'failed', 'rolled_back', 'rejected') THEN now() ELSE finished_at END
		WHERE id = $1 AND status = ANY($3)`
	res, err := tx.ExecContext(ctx, q, id, to, pq.Array(from), approver)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

var ErrConflict = errors.New("conflict")

func SavePlanSteps(ctx context.Context, tx *sql.Tx, id string, steps any) error {
	b, _ := json.Marshal(steps)
	_, err := tx.ExecContext(ctx, "UPDATE plans SET actions = $2 WHERE id = $1", id, b)
	return err
}

func ListPlans(ctx context.Context, tx *sql.Tx, limit int) ([]Plan, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, status, created_by, approved_by, finding_ids, actions, impact, created_at, approved_at, finished_at FROM plans ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Status, &p.CreatedBy, &p.ApprovedBy, pq.Array(&p.FindingIDs), &p.Steps, &p.Impact, &p.CreatedAt, &p.ApprovedAt, &p.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TenantSettings returns the tenant's connector settings and domain.
func TenantSettings(ctx context.Context, tx *sql.Tx) (domain string, settings map[string]string, err error) {
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT domain, settings FROM tenants").Scan(&domain, &raw); err != nil {
		return
	}
	settings = map[string]string{}
	_ = json.Unmarshal(raw, &settings)
	return
}

func SetTenantSetting(ctx context.Context, d *sql.DB, tenant, key, value string) error {
	_, err := d.ExecContext(ctx, "UPDATE tenants SET settings = settings || jsonb_build_object($2::text, $3::text) WHERE id = $1", tenant, key, value)
	return err
}

type TenantRef struct {
	ID       string
	Settings map[string]string
}

func Tenants(ctx context.Context, tx *sql.Tx) ([]TenantRef, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, settings FROM irg_tenant_ids()")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantRef
	for rows.Next() {
		var t TenantRef
		var raw []byte
		if err := rows.Scan(&t.ID, &raw); err != nil {
			return nil, err
		}
		t.Settings = map[string]string{}
		_ = json.Unmarshal(raw, &t.Settings)
		out = append(out, t)
	}
	return out, rows.Err()
}

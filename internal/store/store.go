// Package store is the persistence layer. Every method takes a *sql.Tx opened by db.WithTenant,
// so tenant isolation is enforced by the database, not by remembering a WHERE clause.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

var ErrNotFound = errors.New("not found")

const KeyPrefix = "irg_"

// ------------------------------------------------------------------------------------- tenants
// CreateTenant runs as the owner (CLI/bootstrap only) and returns the first admin key.
func CreateTenant(ctx context.Context, d *sql.DB, slug, name, domain string) (tenantID, adminKey string, err error) {
	if err = d.QueryRowContext(ctx, "INSERT INTO tenants (slug, name, domain) VALUES ($1, $2, $3) RETURNING id", slug, name, domain).Scan(&tenantID); err != nil {
		return "", "", err
	}
	adminKey, err = createKey(ctx, d, tenantID, "bootstrap admin", "admin")
	return tenantID, adminKey, err
}

func createKey(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenant, name, role string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := KeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	_, err := q.ExecContext(ctx, "INSERT INTO api_keys (tenant_id, name, role, key_hash) VALUES ($1, $2, $3, $4)", tenant, name, role, HashKey(key))
	return key, err
}

// CreateKey issues a key inside a tenant transaction (admin API).
func CreateKey(ctx context.Context, tx *sql.Tx, tenant, name, role string) (string, error) {
	return createKey(ctx, tx, tenant, name, role)
}

func HashKey(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

type Principal struct {
	Tenant string
	Role   string // viewer | analyst | admin | agent
	ID     string // "key:<uuid>" or "user:<sub>"
	Name   string
}

func ResolveKey(ctx context.Context, tx *sql.Tx, key string) (Principal, error) {
	var p Principal
	var keyID string
	err := tx.QueryRowContext(ctx, "SELECT tenant_id, key_id, role, name FROM irg_resolve_key($1)", HashKey(key)).Scan(&p.Tenant, &keyID, &p.Role, &p.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	p.ID = "key:" + keyID
	return p, err
}

func TenantDomain(ctx context.Context, tx *sql.Tx) (string, error) {
	var d string
	err := tx.QueryRowContext(ctx, "SELECT domain FROM tenants").Scan(&d)
	return d, err
}

// ------------------------------------------------------------------------------------- snapshots
func SaveSnapshot(ctx context.Context, tx *sql.Tx, tenant string, s *model.Snapshot) (int64, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRowContext(ctx, "INSERT INTO snapshots (tenant_id, taken_at, nodes, edges, data) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		tenant, s.TakenAt, len(s.Nodes), len(s.Edges), b).Scan(&id)
	return id, err
}

func LatestSnapshot(ctx context.Context, tx *sql.Tx) (int64, *model.Snapshot, error) {
	var id int64
	var b []byte
	err := tx.QueryRowContext(ctx, "SELECT id, data FROM snapshots ORDER BY id DESC LIMIT 1").Scan(&id, &b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	var s model.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return 0, nil, err
	}
	return id, &s, nil
}

// ------------------------------------------------------------------------------------- findings
type SyncResult struct {
	Opened, Updated, Resolved int
}

// SyncFindings makes the findings table match one analysis: new ones open, existing ones are
// refreshed, open ones no longer produced are resolved (time-to-resolve starts at first_seen).
// Accepted risks stay accepted while they still occur.
func SyncFindings(ctx context.Context, tx *sql.Tx, tenant string, fs []model.Finding, at time.Time) (SyncResult, error) {
	var r SyncResult
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ev, _ := json.Marshal(f.Evidence)
		rem, _ := json.Marshal(f.Remediation)
		var inserted bool
		err := tx.QueryRowContext(ctx, `
			INSERT INTO findings (tenant_id, id, rule, severity, score, subject, subject_kind, title, evidence, controls, remediation, blast_radius, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)
			ON CONFLICT (tenant_id, id) DO UPDATE SET severity = EXCLUDED.severity, score = EXCLUDED.score, title = EXCLUDED.title, evidence = EXCLUDED.evidence,
				remediation = EXCLUDED.remediation, blast_radius = EXCLUDED.blast_radius, last_seen = EXCLUDED.last_seen,
				status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END,
				resolved_at = CASE WHEN findings.status = 'resolved' THEN NULL ELSE findings.resolved_at END,
				first_seen = CASE WHEN findings.status = 'resolved' THEN EXCLUDED.first_seen ELSE findings.first_seen END
			RETURNING (xmax = 0)`,
			tenant, f.ID, f.Rule, f.Severity, f.Score, f.Subject, f.SubjectKind, f.Title, ev, pq.Array(f.Controls), rem, f.BlastRadius, at).Scan(&inserted)
		if err != nil {
			return r, err
		}
		if inserted {
			r.Opened++
		} else {
			r.Updated++
		}
		ids = append(ids, f.ID)
	}
	res, err := tx.ExecContext(ctx, "UPDATE findings SET status = 'resolved', resolved_at = $1 WHERE status <> 'resolved' AND NOT (id = ANY($2))", at, pq.Array(ids))
	if err != nil {
		return r, err
	}
	n, _ := res.RowsAffected()
	r.Resolved = int(n)
	return r, nil
}

type FindingRow struct {
	model.Finding
	Status     string     `json:"status"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

type FindingFilter struct {
	Status, Severity, Rule, Subject string
	Limit                           int
}

func ListFindings(ctx context.Context, tx *sql.Tx, f FindingFilter) ([]FindingRow, error) {
	q := `SELECT id, rule, severity, score, subject, subject_kind, title, evidence, controls, remediation, blast_radius, status, first_seen, last_seen, resolved_at FROM findings WHERE true`
	var args []any
	add := func(col, v string) {
		if v != "" {
			args = append(args, v)
			q += fmt.Sprintf(" AND %s = $%d", col, len(args))
		}
	}
	add("status", f.Status)
	add("severity", f.Severity)
	add("rule", f.Rule)
	add("subject", f.Subject)
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q += fmt.Sprintf(" ORDER BY score DESC, id LIMIT %d", f.Limit)
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		r, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func GetFinding(ctx context.Context, tx *sql.Tx, id string) (FindingRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, rule, severity, score, subject, subject_kind, title, evidence, controls, remediation, blast_radius, status, first_seen, last_seen, resolved_at FROM findings WHERE id = $1`, id)
	if err != nil {
		return FindingRow{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return FindingRow{}, ErrNotFound
	}
	return scanFinding(rows)
}

func scanFinding(rows *sql.Rows) (FindingRow, error) {
	var r FindingRow
	var ev, rem []byte
	var controls []string
	err := rows.Scan(&r.ID, &r.Rule, &r.Severity, &r.Score, &r.Subject, &r.SubjectKind, &r.Title, &ev, pq.Array(&controls), &rem, &r.BlastRadius, &r.Status, &r.FirstSeen, &r.LastSeen, &r.ResolvedAt)
	if err != nil {
		return r, err
	}
	r.Controls = controls
	_ = json.Unmarshal(ev, &r.Evidence)
	_ = json.Unmarshal(rem, &r.Remediation)
	return r, nil
}

// AcceptRisk records a documented risk acceptance (who, why). Accepted findings leave the open
// queue but remain visible and audited.
func AcceptRisk(ctx context.Context, tx *sql.Tx, id, by, reason string) error {
	res, err := tx.ExecContext(ctx, "UPDATE findings SET status = 'accepted', accepted_by = $2, accept_reason = $3 WHERE id = $1 AND status = 'open'", id, by, reason)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type Posture struct {
	At               time.Time      `json:"at"`
	MeanIdentityRisk float64        `json:"mean_identity_risk"`
	Open             map[string]int `json:"open_by_severity"`
	OpenByRule       map[string]int `json:"open_by_rule"`
	IdentitiesAtRisk int            `json:"identities_at_risk"`
	Actors           int            `json:"actors"`
	MTTRHours        *float64       `json:"mttr_hours,omitempty"` // mean time to resolve, last 30 days
	Accepted         int            `json:"accepted"`
}

func SavePosture(ctx context.Context, tx *sql.Tx, tenant string, snapshot int64, p Posture) error {
	b, _ := json.Marshal(p)
	_, err := tx.ExecContext(ctx, "INSERT INTO posture_history (tenant_id, at, snapshot, org_score, counts) VALUES ($1, $2, $3, $4, $5)", tenant, p.At, snapshot, p.MeanIdentityRisk, b)
	return err
}

func PostureHistory(ctx context.Context, tx *sql.Tx, limit int) ([]Posture, error) {
	rows, err := tx.QueryContext(ctx, "SELECT counts FROM posture_history ORDER BY at DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Posture
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var p Posture
		_ = json.Unmarshal(b, &p)
		out = append(out, p)
	}
	return out, rows.Err()
}

func MTTR(ctx context.Context, tx *sql.Tx, since time.Time) (*float64, error) {
	var h sql.NullFloat64
	err := tx.QueryRowContext(ctx, "SELECT avg(extract(epoch FROM resolved_at - first_seen)) / 3600 FROM findings WHERE status = 'resolved' AND resolved_at >= $1", since).Scan(&h)
	if err != nil || !h.Valid {
		return nil, err
	}
	return &h.Float64, nil
}

// ------------------------------------------------------------------------------------- jobs
type Job struct {
	ID       int64
	Tenant   string
	Kind     string
	Payload  json.RawMessage
	Attempts int
	Max      int
}

func Enqueue(ctx context.Context, tx *sql.Tx, tenant, kind string, payload any, after time.Duration) (int64, error) {
	b, _ := json.Marshal(payload)
	var id int64
	err := tx.QueryRowContext(ctx, "INSERT INTO jobs (tenant_id, kind, payload, run_after) VALUES ($1, $2, $3, now() + make_interval(secs => $4)) RETURNING id",
		tenant, kind, b, after.Seconds()).Scan(&id)
	return id, err
}

func ClaimJob(ctx context.Context, tx *sql.Tx, lease time.Duration) (*Job, error) {
	var j Job
	var b []byte
	err := tx.QueryRowContext(ctx, "SELECT id, tenant_id, kind, payload, attempts, max_attempts FROM irg_claim_job($1)", int(lease.Seconds())).Scan(&j.ID, &j.Tenant, &j.Kind, &b, &j.Attempts, &j.Max)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	j.Payload = b
	return &j, err
}

func FinishJob(ctx context.Context, tx *sql.Tx, id int64, jobErr error, attempts, maxAttempts int) error {
	if jobErr == nil {
		_, err := tx.ExecContext(ctx, "UPDATE jobs SET status = 'done', finished_at = now(), locked_until = NULL, error = NULL WHERE id = $1", id)
		return err
	}
	if attempts >= maxAttempts {
		_, err := tx.ExecContext(ctx, "UPDATE jobs SET status = 'failed', finished_at = now(), locked_until = NULL, error = $2 WHERE id = $1", id, jobErr.Error())
		return err
	}
	backoff := time.Duration(1<<min(attempts, 8)) * 5 * time.Second
	_, err := tx.ExecContext(ctx, "UPDATE jobs SET status = 'queued', locked_until = NULL, error = $2, run_after = now() + make_interval(secs => $3) WHERE id = $1", id, jobErr.Error(), backoff.Seconds())
	return err
}

func PendingJob(ctx context.Context, tx *sql.Tx, kind string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE kind = $1 AND status IN ('queued', 'running')", kind).Scan(&n)
	return n > 0, err
}

func JobStatus(ctx context.Context, tx *sql.Tx, id int64) (status string, errText *string, err error) {
	err = tx.QueryRowContext(ctx, "SELECT status, error FROM jobs WHERE id = $1", id).Scan(&status, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

// ------------------------------------------------------------------------------------- audit
// Audit appends to the tenant's hash chain. The advisory lock serialises appends per tenant, so
// the chain has no forks; Verify recomputes it.
func Audit(ctx context.Context, tx *sql.Tx, tenant, actor, action, target string, detail any) error {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 42))", tenant); err != nil {
		return err
	}
	var prev []byte
	err := tx.QueryRowContext(ctx, "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		prev = make([]byte, 32)
	} else if err != nil {
		return err
	}
	raw, _ := json.Marshal(detail)
	d := canonical(raw) // the form Verify can reproduce from jsonb, whatever key order jsonb keeps
	at := time.Now().UTC().Truncate(time.Microsecond)
	h := chainHash(prev, tenant, at, actor, action, target, d)
	_, err = tx.ExecContext(ctx, "INSERT INTO audit_log (tenant_id, at, actor, action, target, detail, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
		tenant, at, actor, action, target, d, prev, h)
	return err
}

func chainHash(prev []byte, tenant string, at time.Time, actor, action, target string, detail []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	for _, s := range []string{tenant, at.Format(time.RFC3339Nano), actor, action, target} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	h.Write(detail)
	return h.Sum(nil)
}

type AuditEntry struct {
	Seq    int64           `json:"seq"`
	At     time.Time       `json:"at"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Target string          `json:"target"`
	Detail json.RawMessage `json:"detail"`
}

// VerifyAudit walks the chain. It returns the first broken sequence number, or 0 if intact.
func VerifyAudit(ctx context.Context, tx *sql.Tx, tenant string) (entries int, brokenAt int64, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT seq, at, actor, action, target, detail, prev_hash, hash FROM audit_log ORDER BY seq")
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	prev := make([]byte, 32)
	for rows.Next() {
		var e AuditEntry
		var p, h []byte
		if err := rows.Scan(&e.Seq, &e.At, &e.Actor, &e.Action, &e.Target, &e.Detail, &p, &h); err != nil {
			return entries, 0, err
		}
		entries++
		// jsonb reorders keys and drops spacing; canonical() maps both sides to one encoding
		if string(p) != string(prev) || string(chainHash(p, tenant, e.At.UTC(), e.Actor, e.Action, e.Target, canonical(e.Detail))) != string(h) {
			return entries, e.Seq, nil
		}
		prev = h
	}
	return entries, 0, rows.Err()
}

func ListAudit(ctx context.Context, tx *sql.Tx, limit int) ([]AuditEntry, error) {
	rows, err := tx.QueryContext(ctx, "SELECT seq, at, actor, action, target, detail FROM audit_log ORDER BY seq DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.At, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// canonical re-encodes JSON the same way Audit encoded it (Go's encoder: sorted map keys).
func canonical(b []byte) []byte {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return b
	}
	out, _ := json.Marshal(v)
	return out
}

// ------------------------------------------------------------------------------------- JIT grants
type Grant struct {
	ID            string     `json:"id"`
	Agent         string     `json:"agent_id"`
	Action        string     `json:"action"`
	Resource      string     `json:"resource"`
	Justification string     `json:"justification"`
	RequestedBy   string     `json:"requested_by"`
	ApprovedBy    *string    `json:"approved_by,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

func CreateGrant(ctx context.Context, tx *sql.Tx, tenant string, g Grant) (Grant, error) {
	err := tx.QueryRowContext(ctx, `INSERT INTO agent_grants (tenant_id, agent_id, action, resource, justification, requested_by, approved_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, tenant, g.Agent, g.Action, g.Resource, g.Justification, g.RequestedBy, g.ApprovedBy, g.ExpiresAt).Scan(&g.ID)
	return g, err
}

func ApproveGrant(ctx context.Context, tx *sql.Tx, id, by string) (Grant, error) {
	var g Grant
	err := tx.QueryRowContext(ctx, `UPDATE agent_grants SET approved_by = $2 WHERE id = $1 AND approved_by IS NULL AND revoked_at IS NULL AND requested_by <> $2
		RETURNING id, agent_id, action, resource, justification, requested_by, approved_by, expires_at`, id, by).
		Scan(&g.ID, &g.Agent, &g.Action, &g.Resource, &g.Justification, &g.RequestedBy, &g.ApprovedBy, &g.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return g, ErrNotFound
	}
	return g, err
}

// LiveGrants returns approved, unexpired grants for every agent (the decision point caches them).
func LiveGrants(ctx context.Context, tx *sql.Tx) ([]Grant, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, agent_id, action, resource, justification, requested_by, approved_by, expires_at FROM agent_grants
		WHERE approved_by IS NOT NULL AND revoked_at IS NULL AND expires_at > now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.Agent, &g.Action, &g.Resource, &g.Justification, &g.RequestedBy, &g.ApprovedBy, &g.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------------------------- decisions
type Decision struct {
	At        time.Time
	Agent     string
	Action    string
	Resource  string
	Decision  string
	Reason    string
	LatencyUS int
}

// SaveDecisions writes a batch in one statement (the decision point buffers them).
func SaveDecisions(ctx context.Context, tx *sql.Tx, tenant string, ds []Decision) error {
	if len(ds) == 0 {
		return nil
	}
	var sb strings.Builder
	args := make([]any, 0, len(ds)*8)
	sb.WriteString("INSERT INTO decisions (tenant_id, at, agent_id, action, resource, decision, reason, latency_us) VALUES ")
	for i, d := range ds {
		if i > 0 {
			sb.WriteString(",")
		}
		n := i * 8
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8)
		args = append(args, tenant, d.At, d.Agent, d.Action, d.Resource, d.Decision, d.Reason, d.LatencyUS)
	}
	_, err := tx.ExecContext(ctx, sb.String(), args...)
	return err
}

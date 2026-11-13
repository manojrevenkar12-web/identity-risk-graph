// Package siem ships the platform's security events to the customer's SIEM: every audit-log entry
// (plans applied and rolled back, risks accepted, grants approved, keys created) and every AI-agent
// decision that was not a plain allow. Events are Elastic Common Schema (ECS) documents, sent to
// Splunk through the HTTP Event Collector and to Microsoft Sentinel through the Azure Monitor Logs
// Ingestion API. A cursor per tenant, sink and stream moves only after the sink acknowledged a batch.
package siem

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Event is one security event, before it is shaped for a sink.
type Event struct {
	Seq      int64
	Stream   string // audit | decisions
	Tenant   string
	At       time.Time
	Actor    string // a person's key name, an agent id, or "scheduler"
	Action   string // plan.apply, risk.accept, agent.decide, ...
	Target   string
	Outcome  string // success | failure | unknown
	Reason   string
	Detail   json.RawMessage
	Decision string // for agent decisions: allow | deny | require_approval
}

// ID is stable across retries, so a SIEM can drop a duplicate delivery.
func (e Event) ID() string {
	return "irg-" + e.Tenant[:8] + "-" + e.Stream + "-" + strconv.FormatInt(e.Seq, 10)
}

// ECS renders the event as an Elastic Common Schema document (field names as Splunk's and
// Sentinel's ECS mappings expect them).
func (e Event) ECS() map[string]any {
	doc := map[string]any{
		"@timestamp":   e.At.UTC().Format(time.RFC3339Nano),
		"ecs":          map[string]any{"version": "8.11.0"},
		"event":        map[string]any{"id": e.ID(), "kind": "event", "action": e.Action, "outcome": e.Outcome, "module": "identity-risk-graph", "dataset": "irg." + e.Stream},
		"organization": map[string]any{"id": e.Tenant},
		"observer":     map[string]any{"vendor": "identity-risk-graph", "product": "identity-risk-graph", "type": "identity"},
		"related":      map[string]any{"user": []string{e.Actor}},
		"labels":       map[string]any{"stream": e.Stream},
		"irg":          map[string]any{"target": e.Target},
		"message":      e.message(),
	}
	if e.Stream == "decisions" {
		doc["event"].(map[string]any)["category"] = []string{"iam"}
		doc["event"].(map[string]any)["type"] = []string{"access"}
		doc["event"].(map[string]any)["severity"] = severityOf(e.Decision)
		doc["user"] = map[string]any{"name": e.Actor, "roles": []string{"ai_agent"}}
		doc["rule"] = map[string]any{"name": e.Reason}
		doc["irg"].(map[string]any)["decision"] = e.Decision
		doc["irg"].(map[string]any)["detail"] = json.RawMessage(e.Detail)
	} else {
		doc["event"].(map[string]any)["category"] = []string{"iam", "configuration"}
		doc["event"].(map[string]any)["type"] = []string{"change"}
		doc["user"] = map[string]any{"name": e.Actor}
		if len(e.Detail) > 0 {
			doc["irg"].(map[string]any)["detail"] = json.RawMessage(e.Detail)
		}
	}
	return doc
}

func (e Event) message() string {
	if e.Stream == "decisions" {
		var d struct {
			A string `json:"requested_action"`
		}
		_ = json.Unmarshal(e.Detail, &d)
		return fmt.Sprintf("AI agent %s: %s on %s → %s (%s)", e.Actor, d.A, e.Target, e.Decision, e.Reason)
	}
	return fmt.Sprintf("%s by %s on %s", e.Action, e.Actor, e.Target)
}

func severityOf(decision string) int {
	switch decision {
	case "deny":
		return 5
	case "require_approval":
		return 3
	}
	return 1
}

// ------------------------------------------------------------------------------------- reading
// Read returns up to limit events after seq, in order, from one tenant's stream. tx must be confined to
// the tenant (db.WithTenant). Allowed decisions are skipped unless includeAllow: an agent allowed to
// read a bucket is not a security event, and at thousands of decisions a second it would drown the SIEM.
//
// Decisions are written by several API replicas in concurrent batches, so a row with a lower id can
// commit after one with a higher id. Reading only rows older than notAfter (now minus a settling
// window) keeps the cursor from stepping over a row that has not committed yet. The audit log needs no
// window: appends are serialised per tenant by an advisory lock held until commit.
func Read(ctx context.Context, tx *sql.Tx, tenant, stream string, after int64, limit int, includeAllow bool, notAfter time.Time) ([]Event, error) {
	var rows *sql.Rows
	var err error
	switch stream {
	case "audit":
		rows, err = tx.QueryContext(ctx, `SELECT seq, at, actor, action, target, detail FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT $2`, after, limit)
	case "decisions":
		rows, err = tx.QueryContext(ctx, `SELECT id, at, agent_id, action, resource, decision, reason FROM decisions
			WHERE id > $1 AND ($3 OR decision <> 'allow') AND at < $4 ORDER BY id LIMIT $2`, after, limit, includeAllow, notAfter)
	default:
		return nil, fmt.Errorf("unknown stream %q", stream)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e := Event{Stream: stream, Tenant: tenant}
		if stream == "audit" {
			var detail []byte
			if err := rows.Scan(&e.Seq, &e.At, &e.Actor, &e.Action, &e.Target, &detail); err != nil {
				return nil, err
			}
			e.Detail, e.Outcome = detail, "success"
		} else {
			var action string
			if err := rows.Scan(&e.Seq, &e.At, &e.Actor, &action, &e.Target, &e.Decision, &e.Reason); err != nil {
				return nil, err
			}
			e.Action = "agent.decide"
			e.Detail, _ = json.Marshal(map[string]string{"requested_action": action})
			e.Outcome = "failure" // the agent did not get to act unchecked
			if e.Decision == "allow" {
				e.Outcome = "success"
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrPermanent wraps a sink error that retrying will not fix (bad token, rejected schema).
var ErrPermanent = errors.New("permanent")

package siem

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
)

// FlakySIEM stands in for a SIEM that is sometimes busy and sometimes loses its answer: it rejects a
// share of requests with 503 (nothing stored), and for another share stores the events but the
// acknowledgement never reaches us (a timeout after the write). It records what it stored.
type FlakySIEM struct {
	Busy, LostAck float64
	rng           *rand.Rand
	mu            sync.Mutex
	stored        map[string]int // event id -> times stored
	requests      int
	busy, lost    int
}

func NewFlakySIEM(busy, lostAck float64, seed uint64) *FlakySIEM {
	//nolint:gosec // a reproducible simulation, not a secret
	return &FlakySIEM{Busy: busy, LostAck: lostAck, rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), stored: map[string]int{}}
}

func (f *FlakySIEM) Name() string { return "drill" }

func (f *FlakySIEM) Send(_ context.Context, batch []Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	r := f.rng.Float64()
	if r < f.Busy {
		f.busy++
		return &RetryAfter{0, errors.New("HTTP 503: server busy")}
	}
	for _, e := range batch {
		f.stored[e.ID()]++
	}
	if r < f.Busy+f.LostAck {
		f.lost++
		return &RetryAfter{0, fmt.Errorf("timeout after the write: %w", http.ErrHandlerTimeout)}
	}
	return nil
}

// DrillResult is what reports/siem.json holds.
type DrillResult struct {
	AuditEvents     int     `json:"audit_events"`
	Decisions       int     `json:"agent_decisions"`
	DecisionsToSend int     `json:"decisions_to_export"`
	BusyShare       float64 `json:"injected_busy_share"`
	LostAckShare    float64 `json:"injected_lost_ack_share"`
	Requests        int     `json:"requests"`
	BusyReplies     int     `json:"busy_replies"`
	LostAcks        int     `json:"lost_acknowledgements"`
	Expected        int     `json:"events_expected"`
	Stored          int     `json:"events_stored_at_least_once"`
	Missing         int     `json:"events_missing"`
	Duplicates      int     `json:"duplicate_deliveries"`
	Leaked          int     `json:"events_from_other_tenants"`
	AllowsExported  int     `json:"plain_allows_exported"`
	Rounds          int     `json:"rounds"`
	Seconds         float64 `json:"seconds"`
	EventsPerSecond float64 `json:"events_per_second"`
}

// Drill writes a tenant's worth of audit entries and agent decisions (plus a second tenant's, which
// must never leave), exports them through a FlakySIEM until the cursors stop moving, and counts.
func Drill(ctx context.Context, d *sql.DB, audits, decisions int, busy, lostAck float64, seed uint64) (DrillResult, error) {
	res := DrillResult{AuditEvents: audits, Decisions: decisions, BusyShare: busy, LostAckShare: lostAck}
	rng := rand.New(rand.NewPCG(seed, 1)) //nolint:gosec // a reproducible simulation, not a secret
	var tenants [2]string
	for i := range tenants {
		t, _, err := store.CreateTenant(ctx, d, fmt.Sprintf("drill%d-%d", i, rng.IntN(1e9)), "Drill", "drill.example")
		if err != nil {
			return res, err
		}
		tenants[i] = t
	}
	past := time.Now().Add(-time.Hour)
	want := map[string]bool{}
	for ti, tenant := range tenants {
		err := db.WithTenant(ctx, d, tenant, func(tx *sql.Tx) error {
			for i := 0; i < audits; i++ {
				if err := store.Audit(ctx, tx, tenant, "ana", "plan.apply", fmt.Sprintf("plan-%d", i), map[string]int{"n": i}); err != nil {
					return err
				}
			}
			ds := make([]store.Decision, 0, 1000)
			for i := 0; i < decisions; i++ {
				dec := []string{"allow", "allow", "allow", "deny", "require_approval"}[rng.IntN(5)]
				ds = append(ds, store.Decision{At: past.Add(time.Duration(i) * time.Millisecond), Agent: "agent-7", Action: "s3:DeleteObject",
					Resource: "arn:aws:s3:::payroll", Decision: dec, Reason: "drill", LatencyUS: 3})
				if len(ds) == cap(ds) || i == decisions-1 {
					if err := store.SaveDecisions(ctx, tx, tenant, ds); err != nil {
						return err
					}
					ds = ds[:0]
				}
			}
			return nil
		})
		if err != nil {
			return res, err
		}
		if ti != 0 {
			continue
		}
		if err := db.WithTenant(ctx, d, tenant, func(tx *sql.Tx) error {
			for _, stream := range Streams {
				evs, err := Read(ctx, tx, tenant, stream, 0, 1<<30, false, time.Now())
				if err != nil {
					return err
				}
				for _, e := range evs {
					want[e.ID()] = true
					if stream == "decisions" {
						res.DecisionsToSend++
					}
				}
			}
			return nil
		}); err != nil {
			return res, err
		}
	}
	sink := NewFlakySIEM(busy, lostAck, seed)
	x := &Exporter{DB: d, Sinks: []Sink{sink}, Batch: 200, MaxAttempts: 4, Backoff: time.Microsecond,
		Sleep: func(context.Context, time.Duration) error { return nil }}
	t0 := time.Now()
	for res.Rounds = 1; res.Rounds <= 50; res.Rounds++ {
		st, _ := x.Drain(ctx, tenants[0])
		if st.Delivered == 0 && st.Failed == 0 {
			break
		}
	}
	res.Seconds = time.Since(t0).Seconds()
	res.Expected = len(want)
	ids := make([]string, 0, len(sink.stored))
	for id := range sink.stored {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	other := "irg-" + tenants[1][:8]
	for _, id := range ids {
		n := sink.stored[id]
		switch {
		case want[id]:
			res.Stored++
			res.Duplicates += n - 1
		case len(id) >= len(other) && id[:len(other)] == other:
			res.Leaked++
		default:
			res.AllowsExported++
		}
	}
	res.Missing = res.Expected - res.Stored
	res.Requests, res.BusyReplies, res.LostAcks = sink.requests, sink.busy, sink.lost
	res.EventsPerSecond = float64(res.Stored) / res.Seconds
	return res, nil
}

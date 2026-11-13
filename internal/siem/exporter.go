package siem

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/db"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/metrics"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/store"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/trace"
)

var (
	mEvents = metrics.Default.Counter("irg_siem_events_total", "Security events handed to a SIEM", "sink", "stream", "outcome")
	mLag    = metrics.Default.Gauge("irg_siem_delivery_lag_seconds", "Age of the newest event at its delivery", "sink", "stream")
	mStuck  = metrics.Default.Gauge("irg_siem_sink_blocked", "1 while a sink rejects events permanently (bad token, bad schema)", "sink")
)

// Streams exported, in this order.
var Streams = []string{"audit", "decisions"}

// Exporter moves each tenant's events to every sink.
type Exporter struct {
	DB           *sql.DB
	Sinks        []Sink
	Batch        int           // events per request (default 500)
	IncludeAllow bool          // also export plain allows
	Settle       time.Duration // decisions younger than this wait (default 10 s)
	MaxAttempts  int           // per batch, before giving up until the next round (default 6)
	Backoff      time.Duration // first retry wait, doubled each time, capped at 30 s (default 500 ms)
	Log          *slog.Logger
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
}

// Stats for one drain.
type Stats struct {
	Delivered int
	Retries   int
	Failed    int // batches that ran out of attempts (they are retried next round)
}

func (x *Exporter) defaults() {
	if x.Batch <= 0 {
		x.Batch = 500
	}
	if x.Settle == 0 {
		x.Settle = 10 * time.Second
	}
	if x.MaxAttempts <= 0 {
		x.MaxAttempts = 6
	}
	if x.Backoff <= 0 {
		x.Backoff = 500 * time.Millisecond
	}
	if x.Now == nil {
		x.Now = time.Now
	}
	if x.Sleep == nil {
		x.Sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
	if x.Log == nil {
		x.Log = slog.Default()
	}
}

// Run drains every tenant each interval until ctx ends.
func (x *Exporter) Run(ctx context.Context, interval time.Duration) {
	x.defaults()
	for {
		var tenants []store.TenantRef
		if err := db.AsApp(ctx, x.DB, func(tx *sql.Tx) (err error) { tenants, err = store.Tenants(ctx, tx); return }); err != nil {
			x.Log.Warn("siem: list tenants", "err", err)
		}
		for _, t := range tenants {
			if _, err := x.Drain(ctx, t.ID); err != nil && ctx.Err() == nil {
				x.Log.Warn("siem: drain", "tenant", t.ID, "err", err)
			}
		}
		if x.Sleep(ctx, interval) != nil {
			return
		}
	}
}

// Drain sends everything a tenant has that its sinks have not acknowledged yet.
func (x *Exporter) Drain(ctx context.Context, tenant string) (Stats, error) {
	x.defaults()
	var st Stats
	var errs []error
	for _, s := range x.Sinks {
		for _, stream := range Streams {
			if err := x.drainOne(ctx, tenant, s, stream, &st); err != nil {
				errs = append(errs, err)
				if errors.Is(err, ErrPermanent) {
					break // this sink rejects us; the other sinks still get their events
				}
			}
		}
	}
	return st, errors.Join(errs...)
}

func (x *Exporter) drainOne(ctx context.Context, tenant string, s Sink, stream string, st *Stats) error {
	// One exporter per tenant, sink and stream at a time, across replicas.
	conn, err := x.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var got bool
	key := tenant + "/" + s.Name() + "/" + stream
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1, 7))", key).Scan(&got); err != nil || !got {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1, 7))", key)
	}()

	for ctx.Err() == nil {
		var cursor int64
		var batch []Event
		err := db.WithTenant(ctx, x.DB, tenant, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO siem_cursors (tenant_id, sink, stream) VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING`, tenant, s.Name(), stream); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, "SELECT last_seq FROM siem_cursors WHERE sink = $1 AND stream = $2",
				s.Name(), stream).Scan(&cursor); err != nil {
				return err
			}
			var err error
			batch, err = Read(ctx, tx, tenant, stream, cursor, x.Batch, x.IncludeAllow, x.Now().Add(-x.Settle))
			return err
		})
		if err != nil || len(batch) == 0 {
			return err
		}
		if err := x.send(ctx, s, stream, batch, st); err != nil {
			return err
		}
		last := batch[len(batch)-1]
		if err := db.WithTenant(ctx, x.DB, tenant, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE siem_cursors SET last_seq = $1, delivered = delivered + $2, updated_at = now()
				WHERE sink = $3 AND stream = $4 AND last_seq = $5`, last.Seq, len(batch), s.Name(), stream, cursor)
			return err
		}); err != nil {
			return err
		}
		st.Delivered += len(batch)
		mEvents.Add(float64(len(batch)), s.Name(), stream, "delivered")
		mLag.Set(x.Now().Sub(last.At).Seconds(), s.Name(), stream)
		mStuck.Set(0, s.Name())
		if len(batch) < x.Batch {
			return nil
		}
	}
	return ctx.Err()
}

func (x *Exporter) send(ctx context.Context, s Sink, stream string, batch []Event, st *Stats) error {
	ctx, span := trace.Start(ctx, "siem.export", trace.Internal, trace.String("irg.siem.sink", s.Name()),
		trace.String("irg.siem.stream", stream), trace.Int("irg.siem.events", len(batch)))
	defer span.End()
	wait := x.Backoff
	for attempt := 1; ; attempt++ {
		err := s.Send(ctx, batch)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrPermanent) {
			mEvents.Add(float64(len(batch)), s.Name(), stream, "rejected")
			mStuck.Set(1, s.Name())
			span.Fail(err.Error())
			x.Log.Error("siem: sink rejects events; fix the sink, nothing is skipped", "sink", s.Name(), "err", err)
			return err
		}
		if attempt >= x.MaxAttempts {
			st.Failed++
			mEvents.Add(float64(len(batch)), s.Name(), stream, "deferred")
			span.Fail(err.Error())
			return err
		}
		st.Retries++
		mEvents.Add(float64(len(batch)), s.Name(), stream, "retried")
		d := wait
		var ra *RetryAfter
		if errors.As(err, &ra) && ra.Wait > d {
			d = ra.Wait
		}
		if err := x.Sleep(ctx, d); err != nil {
			return err
		}
		wait = min(wait*2, 30*time.Second)
	}
}

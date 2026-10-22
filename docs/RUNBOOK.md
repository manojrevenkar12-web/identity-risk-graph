# Runbook

## Service levels

| Objective | Target | Measured by |
|---|---|---|
| API availability (non-5xx) | 99.9% monthly | `irg_http_requests_total{code=~"5.."}` |
| Agent decision latency, server-side | p99 < 50 ms | `irg_http_request_seconds{route="POST /v1/agents/decide"}` (load test: 9.6 ms at 14.7k req/s on 2 vCPUs) |
| Analysis freshness | latest analysis under 30 min old | `posture_history.at` |
| Remediation | zero unreviewed changes; every plan applied or rolled back within 1 h of approval | `plans`, audit log |

## Alerts and what to do

### Agent decision latency or errors high (page)

1. Check `irg_agent_decision_seconds`. If the engine is fast but HTTP is slow, the API pods are
   saturated: check the HPA (`kubectl -n irg get hpa api`).
2. A 401 spike: a key was revoked or the OIDC issuer is unreachable. The JWKS cache keeps the
   last keys working during an IdP outage.
3. A 429 spike: an agent is looping. Find it in `decisions` (`agent_id`, last 5 minutes),
   contact its owner, and quarantine it in the agent registry if needed.

### Job backlog (page if the oldest queued job is more than 15 min old)

1. Check that workers are running: `kubectl -n irg get pods -l app=irg-worker`.
2. Look for a failing job kind in `irg_jobs_total{outcome="error"}`, and for the error in
   `jobs.error`.
3. If a connector is failing for one tenant, pause that tenant's syncs: remove its
   `estate_url`, or fix the credential. Other tenants are unaffected.

### Audit chain broken (page, SEV1)

`GET /v1/audit/verify` returned `intact: false`. Someone with database access changed history.
1. Declare a SEV1 security incident (`docs/engineering/HANDBOOK.md`).
2. Snapshot the database now, before anything else changes.
3. `first_broken_seq` is where to start. Compare it with RDS logs and the CloudTrail entries for
   database access.

### Plan failed mid-way (ticket)

The plan shows `failed`, with the failed step's error, and the completed steps carry their undo.
1. If the error is transient (a timeout, or a 5xx from the customer's API), apply again. Done
   steps are skipped, and idempotency keys prevent repeats.
2. Otherwise, roll back. The recorded undos run in reverse.

### Revoking access quickly

- **API key:** delete the key row. It stops working within 30 s, when the cache expires.
- **AI agent:** quarantine it in the registry. Decisions deny it from the next sync. For an
  instant effect, also remove its grants.
- **JIT grant:** set `revoked_at`. The decision engine drops it within 5 s.

## Deploy and roll back

```bash
kubectl -n irg set image deployment/api api=ghcr.io/…/identity-risk-graph@sha256:<digest>
kubectl -n irg rollout status deployment/api
kubectl -n irg rollout undo deployment/api      # rollback
```

Migrations run at startup under an advisory lock, and only additive migrations ship alongside
code. CI performs a rolling restart under load on every push and fails on any dropped request.

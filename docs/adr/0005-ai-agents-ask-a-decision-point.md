# ADR-0005: AI agents ask a decision point before acting

**Context.** AI agents hold standing credentials and act in loops. Posture findings arrive hours
later. Agents need a guardrail at the moment they act.

**Decision.** `POST /v1/agents/decide` answers *allow / deny / require_approval* from an
in-memory, per-tenant copy of the identity graph. In addition to the agent's standing access, it
enforces:
- an accountable owner;
- quarantine;
- a rate limit;
- time-boxed JIT grants;
- human approval for destructive actions on crown jewels.

Decisions are logged asynchronously.

**Consequences.**
- Measured: p99 19 µs in process and 9.6 ms over HTTP at 14.7k requests/s on 2 vCPUs.
- Graph freshness is bounded by sync frequency (15 min by default), and grants by the 5-second
  refresh. A revoked grant can live up to 5 s. If that is too long, push invalidation through
  PostgreSQL `LISTEN/NOTIFY`.
- Agents must integrate a call before acting. The decision point does not intercept their
  traffic.

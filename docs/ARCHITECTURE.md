# Architecture

```
                 ┌──────────────── customer estate ────────────────┐
                 │ IdP (users, groups, MFA) · HR · AWS IAM (roles,  │
                 │ policies, trust, keys) · Workspace (OAuth apps,  │
                 │ grants) · AI-agent registry                     │
                 └───────▲──────────────────────────────┬──────────┘
          remediation    │ idempotent writes            │ paged reads
          (approved plan)│ with exact undo              │ (connector)
┌────────────────────────┴──────────────────────────────▼──────────────────────┐
│ worker ×N   jobs table, FOR UPDATE SKIP LOCKED, leases, retry with backoff    │
│   sync ──► snapshot (jsonb) ──► analyze: graph + IAM evaluation + 9 rules     │
│   apply / rollback: step by step, each step persisted with its undo          │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ PostgreSQL, row-level security per tenant
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ api ×N (HPA)  /v1 findings · identities · plans (four eyes) · audit · keys    │
│               /v1/agents/decide ← in-memory graph per tenant, refreshed ≤5 s  │
│               auth: hashed API keys, OIDC (RS256/ES256 via JWKS)              │
│               explanations: Bedrock (SigV4) or template; never acts           │
└──────────────────────────────────────────────────────────────────────────────┘
```

One Go binary (`irg`) runs as `api`, `worker` or both. PostgreSQL is the only stateful
dependency.

## The core: effective access, not configuration

A configuration scanner reads names and strings: "this user is in the admins group", "this policy
mentions `iam:`". On the benchmark companies that approach produces **1,645 false positives at 24%
precision** (`reports/detection.json`), because real estates are full of near-misses:
- admin groups whose policy only works with MFA;
- `NotAction: iam:*`;
- `iam:PassRole` scoped to application roles;
- explicit Deny statements that protect the audit trail.

This platform answers a different question: *what can this identity actually do?*

1. **Graph.** Actors (people, service accounts, AI agents, OAuth apps) connect to groups, roles
   and other roles (`sts:AssumeRole` chains). Breadth-first search gives the shortest path to
   every reachable role.
2. **IAM evaluation** (`internal/awsiam`). Each role's policies are evaluated the way AWS
   evaluates them:
   - explicit Deny wins; otherwise any matching Allow wins; otherwise the request is implicitly
     denied;
   - wildcards are matched, with actions case-insensitive and resources case-sensitive;
   - `NotAction`, `NotResource` and 18 condition operators (each with its `IfExists` form) are supported.

   Each role is evaluated **in the actor's authentication context**: MFA, no MFA, or a
   long-lived key. Tests pin this against AWS's documented semantics, and a fuzzer checks the
   matcher.
3. **Shared work.** Role grants are computed once per (role, context) and shared by every actor
   that reaches the role. That keeps a 50,000-person company at **0.96 s** for the whole analysis
   (`reports/scale.json`).
4. **Rules** (`internal/risk`) are statements about effective access. Each finding carries:
   - the evidence path;
   - its blast radius: the crown jewels exposed;
   - the SOC 2 and ISO 27001 controls it breaks;
   - a reversible remediation.

## Multi-tenancy: the database enforces it

Every tenant table has `tenant_id` and a row-level-security policy. The application never queries
as the table owner. Each transaction runs `SET LOCAL ROLE irg_app` and
`set_config('app.tenant_id', …, true)`, so:
- a query with a forgotten `WHERE tenant_id` still sees one tenant;
- a missing tenant sees **nothing**, not everything;
- a write into another tenant fails the policy's `WITH CHECK`.

Two narrow `SECURITY DEFINER` functions are the only cross-tenant paths:
- resolving an API key to its tenant;
- claiming the next job.

`internal/store/store_test.go` proves all of this against real PostgreSQL.

## Enforcement: the safe path from finding to fix

`internal/enforce`:
1. **Plan.** Deduplicates the selected findings' actions and applies guardrails: protected and
   break-glass identities are never touched, and plans over `MaxActions` are refused.
2. **Dry run.** Runs on a copy of the graph and reports:
   - which selected findings resolve;
   - which other findings the same actions fix;
   - which crown-jewel access each identity loses;
   - proof that **no new finding** appears. A plan that introduces risk is refused.
3. **Four eyes.** The approver must differ from the author. The API enforces this, and the audit
   log records it.
4. **Execute.** Runs step by step. Each write carries the idempotency key `plan:index`, each step
   is persisted with its undo, and a crashed worker resumes without repeating a step (tested
   with an injected failure).
5. **Verify.** A sync runs after every plan, so "resolved" means the estate actually changed, not
   that an API call returned 200.
6. **Rollback.** Replays the recorded undos in reverse.

## AI agents: a decision point, not a scanner

`POST /v1/agents/decide` answers *may this agent do X to Y now?* in microseconds, from an
in-memory graph per tenant. The checks, in order:
1. the agent is known, active and not quarantined;
2. it has an active human owner;
3. it is within its rate limit;
4. a just-in-time grant matches, which is time-boxed, four-eyes approved and exact;
5. it has standing access in the graph;
6. destructive actions on crown jewels need a human approval;
7. otherwise, allow with the access path.

Decisions are logged asynchronously in batches. 293,494 of 293,494 were persisted in the load
test, and shutdown waits for the flush.

## LLM: explains, never acts

`GET /v1/findings/{id}/explain` sends the finding's facts to a Bedrock model through the
Converse API, signed with SigV4. The signer is tested against AWS's published example. The model
can only produce text: plans, approvals and enforcement stay with people and the policy engine.
If Bedrock is not configured or fails, a deterministic template answers and says so.

## Build vs buy

| Decision | Choice | Why | Revisit when |
|---|---|---|---|
| Graph store | In-memory graph per analysis, snapshots in PostgreSQL jsonb | Whole-org analysis is 1 s at 50k people; one fewer database to secure, back up and certify for SOC 2 | Interactive graph queries across many snapshots, or >1M identities per tenant: then Neo4j or Neptune |
| Job queue | PostgreSQL `SKIP LOCKED` | Transactional with the data it changes (a plan step and its job commit together); no broker to operate | >1k jobs/s sustained |
| IAM semantics | Own evaluator | Must run offline over snapshots, in every auth context; AWS's policy simulator is per-call and rate-limited | Coverage gaps (resource policies, SCPs as layers) cost more than integrating Cedar or the simulator |
| JWT / OIDC | Standard library | Small, auditable, no dependency CVEs in the auth path | Never, for this scope |
| Metrics | Minimal Prometheus writer | Same reason; standard text format | Need exemplars or OpenTelemetry tracing |
| Explanations | Bedrock (Converse) with a template fallback | Customer data stays in their AWS region; the product works without it | — |

## Scaling notes

- **API pods** are stateless apart from caches: decision graphs refresh within 5 s and API keys
  are cached for 30 s, so a revoked key stops within 30 s. Scale them on CPU.
- **Workers** scale on queue depth.
- **Snapshots** grow with the estate: 62 MB of JSON at 50k people. Old snapshots should move to
  object storage after N days. Only the latest is analysed.
- **Decisions** are the high-volume table. Partition it by month and give it a retention policy
  before the first big customer.

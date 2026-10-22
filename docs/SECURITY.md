# Security model and threat model

A product that holds a map of who can reach every crown jewel, and can change access, is itself a
crown jewel. This document lists what it defends against and where each defence lives.

## Assets

1. **The identity graph.** It is an attacker's map. Snapshots and findings live in PostgreSQL,
   isolated per tenant.
2. **Write access to customer estates.** Connector credentials and the enforcement path.
3. **The decision point.** If it says "allow" when it should not, an AI agent acts beyond its
   mandate.
4. **The audit trail.** It is the evidence for SOC 2 and ISO 27001, and for incident response.

## Threats (STRIDE) and controls

| Threat | Example | Control | Where |
|---|---|---|---|
| **S**poofing | Forged JWT; `alg: none`; key/algorithm confusion | RS256/ES256 only; signature checked against the JWKS key with the token's `kid`; issuer, audience, expiry and nbf checked; RSA keys under 2048 bits refused | `internal/auth`, tests with forged tokens |
| | Stolen API key | Stored as SHA-256 only; shown once; per-key rate limit; revocation effective within 30 s | `store.HashKey`, `api.go` |
| **T**ampering | Editing the audit log in the database | Hash chain per tenant (each row covers the previous hash); `GET /v1/audit/verify` names the first broken row | `store.Audit`, `TestAuditChainDetectsTampering` |
| | Replayed or duplicated enforcement | Idempotency key per plan step; steps persisted before the next one runs | `enforce.Execute`, `TestResumeAfterFailure` |
| **R**epudiation | "I didn't approve that" | Every state change is audited with the actor; approver ≠ author | `planTransition` |
| **I**nformation disclosure | Tenant A reads tenant B | PostgreSQL row-level security; the app runs as a non-owner role; no tenant means no rows | `db.WithTenant`, `TestTenantIsolationIsEnforcedByTheDatabase` |
| | Secrets in env, logs, prompts | Secrets mounted as files (`*_FILE`); the LLM prompt carries finding metadata only; the Bedrock secret key is never on the wire (tested) | `app.env`, `llm` |
| **D**enial of service | A runaway AI agent; a noisy client | Token bucket per agent in the decision point, per key at the API; 1 MB body limit; server timeouts | `pdp.allowRate`, `limiter` |
| **E**levation of privilege | An agent asks about another agent | An agent key may only ask about itself | `decide` |
| | A JIT grant wider than intended | Specific resource required (`*` refused); TTL 1–480 min; four-eyes approval; exact pattern match | `requestGrant`, `TestDecisions` |
| | Enforcement locks out the company | Break-glass and protected identities are never touched; action cap per plan; dry run must show no new findings | `enforce.Plan` |
| | LLM prompt injection via estate data | The model's output is display text only; no tool use, no path from text to action | `llm`, ADR-0006 |

## Supply chain and runtime

- **Dependencies.** One third-party Go module (`lib/pq`). `govulncheck` runs on every CI build.
- **Static analysis.** `golangci-lint` with `gosec`. Each suppression names its reason in the code.
- **Image.** Distroless, static, non-root (UID 65532), no shell.
- **Kubernetes.**
  - The namespace enforces the `restricted` Pod Security Standard.
  - Root filesystems are read-only, all capabilities are dropped, and the seccomp profile is
    `RuntimeDefault`.
  - Ingress is denied by default, and API-server tokens are not mounted (IRSA projects its own).
- **AWS.**
  - KMS keys with rotation cover EKS secrets, RDS, Performance Insights and logs.
  - RDS is Multi-AZ, accepts TLS only, allows IAM authentication, and has deletion protection.
  - Nodes enforce IMDSv2 with a hop limit of 1, so pods cannot take node credentials.
  - EKS control-plane audit logs are kept for 365 days, and VPC flow logs record rejected
    traffic.
  - The app's role can only read its own secret, decrypt with the project key, and invoke the
    named Bedrock models.
- **Scanning.** Checkov runs on Terraform, the rendered production manifests and the Dockerfile
  in CI, with zero unsuppressed findings. Each suppression carries its justification.

## Known gaps, in priority order

1. **Connector credentials** live in one Secrets Manager secret per environment. Per-tenant
   secrets with tenant-scoped KMS grants would contain a compromise to one customer.
2. **IAM coverage.** Resource-based policies, SCPs and permission boundaries are not evaluated
   as separate layers. They can be expressed as Deny statements today, but a real connector
   must model them.
3. **Image provenance.** There are no SBOMs or image signatures yet (Syft and cosign in the
   release pipeline).
4. **Per-pod caches.** The decision cache and rate limiters are per pod. A fleet-wide agent
   limit needs a shared counter (Redis or PostgreSQL).
5. **Decisions table.** It has no partitioning or retention yet.

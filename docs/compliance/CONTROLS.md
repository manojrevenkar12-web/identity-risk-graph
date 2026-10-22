# SOC 2 and ISO/IEC 27001:2022: two sides of the same controls

The platform touches compliance twice:
1. **What it detects** in a customer's estate. Each finding names the controls it breaks.
2. **How it is built and run.** This is the evidence an auditor asks *us* for.

## 1. Product: findings mapped to controls

| Rule | What it means | SOC 2 | ISO 27001:2022 Annex A |
|---|---|---|---|
| `offboarding_gap` | left the company, account still active | CC6.2, CC6.3 | 5.16 identity management, 5.18 access rights |
| `dormant_privileged` | no sign-in for 90 days, can still change production | CC6.2, CC6.3 | 5.18, 8.2 privileged access rights |
| `privileged_without_mfa` | production access without MFA | CC6.1 | 8.5 secure authentication |
| `privilege_escalation` | can grant itself more access | CC6.3 | 8.2 |
| `toxic_combination` | can change production and erase the audit trail | CC6.3, CC7.2 | 5.3 segregation of duties, 8.15 logging |
| `stale_credential` | key older than 90 days with write access | CC6.1 | 5.17 authentication information |
| `ai_agent_risk` | AI agent without owner, or with destructive standing access | CC6.3 | 5.15 access control, 8.2 |
| `risky_oauth_app` | unverified third-party app with broad data access | CC6.6, CC9.2 | 5.19 supplier relationships, 5.23 cloud services |
| `external_privileged` | external identity with production access | CC6.6 | 5.19, 8.2 |

Access reviews (SOC 2 CC6.2–6.3, ISO 5.18) are the expensive part of an audit. Findings, risk
acceptances (with a written reason and approver) and plans with their audit trail are the
evidence for "reviewed, decided, done".

## 2. Platform: our own controls and where the evidence is

| Control area | SOC 2 | ISO | Implementation | Evidence |
|---|---|---|---|---|
| Logical access to the product | CC6.1 | 5.15, 8.5 | OIDC SSO for people; hashed, scoped API keys for machines; roles viewer, analyst, admin and agent | `internal/auth`, `api.go` `permitted()` |
| Tenant segregation | CC6.1 | 8.3 information access restriction | PostgreSQL row-level security; non-owner app role | `TestTenantIsolationIsEnforcedByTheDatabase` |
| Change management | CC8.1 | 8.32 | Pull request review by a second engineer; CI gates (lint, gosec, tests, govulncheck, IaC scan, kind deploy); deploy by digest | `.github/workflows/ci.yml`, branch protection |
| Segregation of duties in operations | CC6.3 | 5.3 | Four-eyes approval of remediation plans and JIT grants (the author cannot approve) | `planTransition`, `ApproveGrant`, `TestEndToEnd` |
| Logging and monitoring | CC7.2 | 8.15, 8.16 | Tamper-evident audit chain; Prometheus metrics; EKS audit logs for 365 days; VPC flow logs | `store.Audit`, `/v1/audit/verify`, `deploy/terraform` |
| Encryption | CC6.7 | 8.24 | TLS-only RDS; KMS at rest with rotation (RDS, EKS secrets, logs, EBS) | `deploy/terraform/kms.tf`, `database.tf` |
| Vulnerability management | CC7.1 | 8.8 | govulncheck and gosec every build; Checkov on infrastructure; distroless image | CI logs |
| Secrets management | CC6.1 | 5.17 | Secrets Manager → External Secrets → files; RDS-managed master password rotation | `deploy/k8s/overlays/production`, `database.tf` |
| Availability | A1.2 | 8.14 redundancy | Multi-AZ RDS; 3-AZ node group; HPA; PDBs; zero-downtime rollouts (tested in CI under load) | `scripts/k8s-smoke.sh` |
| Incident management | CC7.3–7.5 | 5.24–5.27 | Severity matrix, roles, GDPR timeline, blameless postmortems | `docs/engineering/HANDBOOK.md` |
| Backup and recovery | A1.2 | 8.13 | RDS backups kept 14 days; final snapshot on deletion; deletion protection | `database.tf` |

## Gaps to close before an audit window opens

- Branch protection and CODEOWNERS enforced in the GitHub organisation settings. They are
  documented here, but configured outside this repository.
- Evidence collection automated, for example a nightly export of CI runs, access reviews and
  audit-chain verification to an evidence bucket.
- A restore test from backup, run quarterly, with the timing recorded.
- A vendor inventory with risk ratings (AWS, GitHub, the IdP and Bedrock).

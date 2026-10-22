# Engineering handbook

How this team builds, ships and runs a security product. Short on purpose: if a rule here does
not earn its keep, delete it in a pull request.

## Principles

1. **Security engineering is the product.** A finding we get wrong costs a customer an outage or
   a breach. A tenant-isolation bug costs the company. Correctness beats speed here, and only
   here. Everywhere else, ship small and often.
2. **Evidence over opinion.** Claims in docs, sales decks and incident reports cite a test, a
   benchmark or a log line. `reports/` exists for that.
3. **Reversible by default.** Prefer changes we can roll back in minutes: feature flags, plans
   with undo, migrations that expand before they contract.
4. **Write it down once.** Decisions go in ADRs, operations in the runbook, and ownership in
   `CODEOWNERS`.

## Planning

- **Two-week cycles.** A one-page cycle goal agreed with product and the founders. Each piece of
  work has one owner and a written definition of done.
- **RFC for anything that takes more than a week or changes a contract**: an API, the schema, the
  threat model. Two pages at most, a 48-hour comment window, decision by the owning engineer
  and the Head of Engineering. The outcome becomes an ADR.
- **Roadmap trade-offs** are made in the open: a ranked list with the cost of delay written next
  to each item.

## Code review

- **Every change goes through a pull request**, reviewed by someone other than the author (SOC 2
  CC8.1). Small PRs (under 400 lines) get reviewed the same day.
- **What review is for:** correctness, security, operability and tests. Not style: `gofmt` and
  `golangci-lint` settle that in CI.
- **Changes to auth, tenancy, enforcement or the decision point** need a reviewer from the
  security-critical owners list, and a test that would have failed without the change.
- **The author merges after a green CI.** CI runs lint, gosec, race tests, fuzzing, govulncheck,
  IaC scanning, and a deploy to kind with a rollout under load.

## Definition of done

- Tests at the level that would catch the bug: a unit test for logic, a PostgreSQL test for SQL
  and RLS, and an end-to-end test for flows.
- Metrics and logs answer "is it working?" without a debugger.
- The runbook covers the new alert, if there is one.
- Docs and ADRs are updated when behaviour or a decision changed.

## Releases

- `main` is always deployable. Every merge builds one image, tagged with the commit and
  deployed by digest.
- Production rollouts are rolling (`maxUnavailable: 0`), gated on readiness, and watched for 15
  minutes on error rate and p99 latency. Rollback is `kubectl rollout undo`; it is rehearsed,
  not theoretical.
- Schema migrations are additive in the release that introduces them, and destructive only in a
  later one.

## On-call

- **Rotation.** One primary and one secondary, weekly, handing over on Monday at 11:00 Berlin
  time.
- **Load.** Paging is for customer-impacting symptoms only: the API error rate, decision-point
  latency, a job backlog, and the audit chain broken. Everything else is a ticket.
- **Response times.** Acknowledge within 15 minutes, 24/7, for SEV1–2. Business hours for SEV3.
- **Compensation.** On-call is paid, and the week after a heavy shift is lighter.
- **Who is eligible.** Engineers join after their second month, and after shadowing one rotation.

## Incident response

| Severity | Definition | Example |
|---|---|---|
| SEV1 | Customer data exposed, wrong enforcement executed, or the platform down for all | A plan suspended the wrong users |
| SEV2 | A major function degraded for some customers | Decision point p99 above 100 ms; syncs failing for one tenant |
| SEV3 | Minor or internal | One connector retrying |

1. **Declare early.** Whoever notices declares, in `#incident`, with a severity. Downgrading is
   free.
2. **Assign roles.** An *incident commander*, who coordinates and decides; an *operator*, who
   changes systems; and a *communicator*, who updates customers and the founders every 30
   minutes for SEV1.
3. **Stop the bleeding first.** Roll back, pause the worker, or quarantine. Root cause comes
   later.
4. **Security incidents** (SEV1 with possible data exposure) bring in the founders and legal
   within the hour. GDPR Article 33 gives 72 hours to notify the authority, and the timeline
   starts at awareness.
5. **Blameless postmortem** within 5 working days for SEV1–2. It covers the timeline, impact,
   contributing factors, what went well, and action items with owners and dates. Action items
   are tracked like features.

## Security engineering in the lifecycle

- **Threat model** (`docs/SECURITY.md`): updated in the same PR as any change to an asset or a
  trust boundary.
- **Dependencies:** added only with a reason in the PR. govulncheck runs in CI, and Renovate
  handles weekly updates.
- **Secrets:** never in code or environment variables. They are mounted from Secrets Manager.
- **Production access:** time-boxed and approved through the same JIT flow our product offers
  (we use what we sell). Every access is logged.
- **Pen test:** annually and before major launches. Findings are tracked to closure.

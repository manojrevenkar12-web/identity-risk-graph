# ADR-0004: Enforcement is a reviewed, reversible plan

**Context.** Automatic remediation is the product's promise and its biggest risk. One bad bulk
action can lock a company out of production or out of its own IdP.

**Decision.** No finding changes access directly. Changes go through a plan:
1. a guardrailed set of actions, with protected identities and a size cap;
2. a dry run that must show zero new findings and lists the access each identity loses;
3. approval by a second person;
4. execution with an idempotency key per step and the undo of each step persisted;
5. a re-sync that verifies the change against the estate;
6. rollback that replays the recorded undos.

**Consequences.**
- Slower than "auto-fix", deliberately. A customer can loosen this per rule once trust exists,
  for example auto-approving `revoke_grant` for unverified apps. The plan machinery stays the
  same.
- Every change is explainable after the fact, which is what an auditor and an incident
  responder both need.

# ADR-0002: Tenant isolation with PostgreSQL row-level security

**Context.** Cross-tenant leakage is the one bug a security vendor cannot survive. Application-level
`WHERE tenant_id = ?` is one forgotten clause away from it.

**Decision.** Every tenant table has an RLS policy keyed on `current_setting('app.tenant_id')`. The
app never queries as the owner:
- `db.WithTenant` runs `SET LOCAL ROLE irg_app` and sets the tenant for that transaction only;
- an unset tenant matches no rows;
- the two cross-tenant needs (key lookup, job claim) are narrow `SECURITY DEFINER` functions.

**Consequences.**
- Isolation is enforced below the code and proven by tests.
- Every query pays one extra round trip at transaction start, which is negligible.
- The owner role is only for migrations. In production it is a separate credential that
  application pods do not have.
- Shard-per-tenant stays possible later, because no query relies on seeing two tenants.

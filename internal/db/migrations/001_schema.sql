-- Multi-tenant schema. Every tenant table carries tenant_id and is protected by row-level
-- security: queries run as the non-owner role irg_app (SET LOCAL ROLE in each transaction) with
-- app.tenant_id set for that transaction only. Unset tenant → no rows, never all rows.
-- The owner (migrations, the two SECURITY DEFINER functions below) bypasses RLS as owners do;
-- the application never runs a query as the owner.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'irg_app') THEN
    CREATE ROLE irg_app NOLOGIN;
  END IF;
  EXECUTE format('GRANT irg_app TO %I', current_user);
END $$;

CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text UNIQUE NOT NULL CHECK (slug ~ '^[a-z0-9-]{2,40}$'),
    name       text NOT NULL,
    domain     text NOT NULL,
    settings   jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    role       text NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin', 'agent')),
    key_hash   bytea UNIQUE NOT NULL,          -- SHA-256 of the key; the key itself is shown once
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE TABLE snapshots (
    id         bigserial PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    taken_at   timestamptz NOT NULL,
    nodes      int NOT NULL,
    edges      int NOT NULL,
    data       jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX snapshots_latest ON snapshots (tenant_id, id DESC);

CREATE TABLE findings (
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id           text NOT NULL,
    rule         text NOT NULL,
    severity     text NOT NULL,
    score        real NOT NULL,
    subject      text NOT NULL,
    subject_kind text NOT NULL,
    title        text NOT NULL,
    evidence     jsonb NOT NULL,
    controls     text[] NOT NULL,
    remediation  jsonb NOT NULL,
    blast_radius int NOT NULL,
    status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'accepted')),
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz,
    accepted_by  text,
    accept_reason text,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX findings_open ON findings (tenant_id, status, score DESC);
CREATE INDEX findings_subject ON findings (tenant_id, subject);

CREATE TABLE posture_history (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    snapshot   bigint NOT NULL,
    org_score  real NOT NULL,
    counts     jsonb NOT NULL,
    PRIMARY KEY (tenant_id, at)
);

CREATE TABLE plans (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status      text NOT NULL CHECK (status IN ('draft', 'approved', 'applying', 'applied', 'failed', 'rolling_back', 'rolled_back', 'rejected')),
    created_by  text NOT NULL,
    approved_by text,
    finding_ids text[] NOT NULL,
    actions     jsonb NOT NULL,      -- [{type,target,from,state,result,undo}]
    impact      jsonb NOT NULL,      -- dry run: access removed, guardrail checks
    created_at  timestamptz NOT NULL DEFAULT now(),
    approved_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX plans_by_tenant ON plans (tenant_id, created_at DESC);

CREATE TABLE jobs (
    id           bigserial PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('sync', 'analyze', 'apply', 'rollback')),
    payload      jsonb NOT NULL DEFAULT '{}',
    status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    attempts     int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 5,
    run_after    timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);
CREATE INDEX jobs_ready ON jobs (run_after) WHERE status IN ('queued', 'running');

-- Tamper-evident audit log: each row's hash covers the previous row's hash (per tenant).
CREATE TABLE audit_log (
    seq        bigserial PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    actor      text NOT NULL,
    action     text NOT NULL,
    target     text NOT NULL,
    detail     jsonb NOT NULL DEFAULT '{}',
    prev_hash  bytea NOT NULL,
    hash       bytea NOT NULL
);
CREATE INDEX audit_by_tenant ON audit_log (tenant_id, seq);

CREATE TABLE agent_grants (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id      text NOT NULL,
    action        text NOT NULL,     -- IAM-style pattern
    resource      text NOT NULL,     -- ARN pattern
    justification text NOT NULL,
    requested_by  text NOT NULL,
    approved_by   text,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz
);
CREATE INDEX agent_grants_live ON agent_grants (tenant_id, agent_id, expires_at);

CREATE TABLE decisions (
    id        bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    at        timestamptz NOT NULL,
    agent_id  text NOT NULL,
    action    text NOT NULL,
    resource  text NOT NULL,
    decision  text NOT NULL,
    reason    text NOT NULL,
    latency_us int NOT NULL
);
CREATE INDEX decisions_by_agent ON decisions (tenant_id, agent_id, at DESC);

-- Row-level security on every tenant table.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['api_keys','snapshots','findings','posture_history','plans','jobs','audit_log','agent_grants','decisions'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
                   WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO irg_app', t);
  END LOOP;
END $$;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON tenants USING (id = nullif(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT ON tenants TO irg_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO irg_app;

-- The one cross-tenant read the app needs: resolve an API key to its tenant. SECURITY DEFINER,
-- narrow, and it returns nothing for revoked keys.
CREATE FUNCTION irg_resolve_key(h bytea) RETURNS TABLE (tenant_id uuid, key_id uuid, role text, name text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT k.tenant_id, k.id, k.role, k.name FROM api_keys k WHERE k.key_hash = h AND k.revoked_at IS NULL
$$;
REVOKE ALL ON FUNCTION irg_resolve_key(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION irg_resolve_key(bytea) TO irg_app;

-- Workers claim jobs across tenants; this is the only other cross-tenant path, also narrow.
CREATE FUNCTION irg_claim_job(lease_seconds int) RETURNS SETOF jobs
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  UPDATE jobs SET status = 'running', attempts = attempts + 1, locked_until = now() + make_interval(secs => lease_seconds)
  WHERE id = (SELECT id FROM jobs WHERE (status = 'queued' AND run_after <= now()) OR (status = 'running' AND locked_until < now())
              ORDER BY run_after FOR UPDATE SKIP LOCKED LIMIT 1)
  RETURNING *
$$;
REVOKE ALL ON FUNCTION irg_claim_job(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION irg_claim_job(int) TO irg_app;

-- The scheduler needs the list of tenants to sync; nothing else.
CREATE FUNCTION irg_tenant_ids() RETURNS TABLE (id uuid, settings jsonb)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$ SELECT id, settings FROM tenants $$;
REVOKE ALL ON FUNCTION irg_tenant_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION irg_tenant_ids() TO irg_app;

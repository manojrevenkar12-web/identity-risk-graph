-- SIEM export: one cursor per tenant, sink and stream (audit log, agent decisions). The cursor moves
-- only after the sink acknowledged the batch, so delivery is at least once; event ids are stable, so
-- the SIEM can drop the rare duplicate (a batch whose acknowledgement was lost).
CREATE TABLE siem_cursors (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sink       text NOT NULL,
    stream     text NOT NULL CHECK (stream IN ('audit', 'decisions')),
    last_seq   bigint NOT NULL DEFAULT 0,
    delivered  bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sink, stream)
);
ALTER TABLE siem_cursors ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON siem_cursors
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE ON siem_cursors TO irg_app;

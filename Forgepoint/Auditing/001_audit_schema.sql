-- =====================================================================
-- ForgePoint audit trail - Postgres schema
-- Requires PostgreSQL 14+ (BEFORE ROW triggers on partitioned tables
-- landed in PG 13; 14+ is the safe floor).
--
-- Run this as a DBA/owner role, NOT as the application role.
-- The application role must never own these objects, or it can drop
-- the triggers that enforce append-only (NIST 800-171 3.3.8).
-- =====================================================================

CREATE SCHEMA IF NOT EXISTS audit;
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- digest() for the hash chain

-- ---------------------------------------------------------------------
-- Roles
--   forgepoint_app     : INSERT only. Cannot read, update, or delete.
--   forgepoint_auditor : SELECT only. Used by the audit viewer, granted
--                        to a small subset of users (3.3.9).
--   forgepoint_archive : SELECT + partition DETACH for retention jobs.
-- The app connects with two connection strings, one per role.
-- ---------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forgepoint_app') THEN
        CREATE ROLE forgepoint_app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forgepoint_auditor') THEN
        CREATE ROLE forgepoint_auditor LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forgepoint_archive') THEN
        CREATE ROLE forgepoint_archive LOGIN;
    END IF;
END $$;

-- ---------------------------------------------------------------------
-- Sequence (explicit, not IDENTITY - identity columns on partitioned
-- tables are version-sensitive; a plain sequence always works)
-- ---------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS audit.audit_trail_id_seq AS bigint;

-- ---------------------------------------------------------------------
-- Main table. Partitioned monthly by occurred_utc so that retention is
-- a DETACH rather than a DELETE (you cannot DELETE from this table).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.audit_trail
(
    id              bigint      NOT NULL DEFAULT nextval('audit.audit_trail_id_seq'),
    occurred_utc    timestamptz NOT NULL DEFAULT clock_timestamp(),

    -- What happened
    event_type      text        NOT NULL,   -- 'EntityChange' | 'DataAccess' | 'Transfer' | 'Authn' | 'Authz' | 'AuditRead' | ...
    action          text        NOT NULL,   -- 'Insert' | 'Update' | 'Delete' | 'View' | 'Download' | 'Print' | 'DncPush' | 'Login' | 'Denied' | ...
    outcome         text        NOT NULL,   -- 'Success' | 'Failure' | 'Denied'

    -- Who (3.3.2 - unique traceability; all three are NOT NULL by design)
    actor_id        text        NOT NULL,   -- AD/Entra objectId or SID. Never a display name.
    actor_name      text        NOT NULL,   -- UPN at time of action (denormalised on purpose)
    actor_kind      text        NOT NULL,   -- 'User' | 'Service' | 'Machine'

    -- Where from
    client_ip       inet        NULL,
    circuit_id      text        NULL,       -- Blazor circuit, for session correlation
    correlation_id  uuid        NOT NULL,   -- one user action spanning N tables (3.3.5)

    -- What it touched
    entity_type     text        NULL,       -- CLR type / logical object name
    entity_key      text        NULL,       -- PK as text, composite keys joined by '|'

    -- Export control classification (drives ITAR review + retention)
    export_control  text        NOT NULL DEFAULT 'ITAR',  -- 'ITAR' | 'EAR' | 'CUI' | 'None'

    -- Optional operator-supplied justification. Required for changes to
    -- released technical data; enforced in the application, not here.
    reason          text        NULL,

    -- Payload. Redacted before it ever reaches this table.
    detail          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    changes         jsonb       NULL,       -- [{ "column": ..., "old": ..., "new": ... }]
    schema_version  smallint    NOT NULL DEFAULT 1,

    -- Tamper evidence
    prev_hash       bytea       NULL,
    row_hash        bytea       NULL,

    PRIMARY KEY (id, occurred_utc)
) PARTITION BY RANGE (occurred_utc);

-- Chain head. Separate single-row table so the BEFORE INSERT trigger
-- never has to scan partitions to find the previous hash.
CREATE TABLE IF NOT EXISTS audit.chain_state
(
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_id   bigint  NOT NULL DEFAULT 0,
    last_hash bytea   NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
);
INSERT INTO audit.chain_state (singleton) VALUES (true) ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------
-- Hash chain
--
-- Each row's hash covers the previous row's hash, so any silent edit or
-- removal of a historical row breaks verification from that point on.
-- The advisory lock serialises audit inserts. At job-shop volume this
-- is irrelevant; if you ever push five figures of audit rows per second,
-- drop the chain rather than the lock.
--
-- Note: jsonb::text is canonical (keys sorted, whitespace normalised),
-- so the hash is stable across dump/restore.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.fn_hash_chain() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER            -- so forgepoint_app can fire it without
SET search_path = audit, pg_catalog   -- rights on chain_state
AS $$
DECLARE
    prev bytea;
    payload text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit.audit_trail'));

    SELECT last_hash INTO prev FROM audit.chain_state WHERE singleton;

    payload := concat_ws('|',
        NEW.id,
        to_char(NEW.occurred_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        NEW.event_type, NEW.action, NEW.outcome,
        NEW.actor_id, NEW.actor_name, NEW.actor_kind,
        coalesce(host(NEW.client_ip), ''), coalesce(NEW.circuit_id, ''),
        NEW.correlation_id,
        coalesce(NEW.entity_type, ''), coalesce(NEW.entity_key, ''),
        NEW.export_control, coalesce(NEW.reason, ''),
        NEW.detail::text, coalesce(NEW.changes::text, ''),
        NEW.schema_version);

    NEW.prev_hash := prev;
    NEW.row_hash  := digest(prev || convert_to(payload, 'UTF8'), 'sha256');

    UPDATE audit.chain_state
       SET last_id = NEW.id, last_hash = NEW.row_hash
     WHERE singleton;

    RETURN NEW;
END $$;

CREATE TRIGGER trg_audit_hash_chain
    BEFORE INSERT ON audit.audit_trail
    FOR EACH ROW EXECUTE FUNCTION audit.fn_hash_chain();

-- ---------------------------------------------------------------------
-- Append-only enforcement (3.3.8)
--
-- Belt and braces: role grants below stop the app, these triggers stop
-- anyone who connects as the owner. Only a superuser who first disables
-- the trigger can modify history - and that shows up in the Postgres log.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.fn_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit.audit_trail is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE OR DELETE ON audit.audit_trail
    FOR EACH ROW EXECUTE FUNCTION audit.fn_append_only();

CREATE TRIGGER trg_audit_no_truncate
    BEFORE TRUNCATE ON audit.audit_trail
    FOR EACH STATEMENT EXECUTE FUNCTION audit.fn_append_only();

-- ---------------------------------------------------------------------
-- Verification. Recompute the chain and return the first row that fails.
-- Run nightly; alert on any result. Also run before handing an export
-- to an assessor or investigator.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.verify_chain(
    p_from bigint DEFAULT 0,
    p_to   bigint DEFAULT 9223372036854775807)
RETURNS TABLE (first_bad_id bigint, reason text)
LANGUAGE plpgsql AS $$
DECLARE
    r record;
    running bytea;
    expected bytea;
    payload text;
BEGIN
    running := NULL;
    FOR r IN
        SELECT * FROM audit.audit_trail
         WHERE id BETWEEN p_from AND p_to
         ORDER BY id
    LOOP
        IF running IS NOT NULL AND r.prev_hash IS DISTINCT FROM running THEN
            first_bad_id := r.id; reason := 'prev_hash does not match preceding row_hash';
            RETURN NEXT; RETURN;
        END IF;

        payload := concat_ws('|',
            r.id,
            to_char(r.occurred_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            r.event_type, r.action, r.outcome,
            r.actor_id, r.actor_name, r.actor_kind,
            coalesce(host(r.client_ip), ''), coalesce(r.circuit_id, ''),
            r.correlation_id,
            coalesce(r.entity_type, ''), coalesce(r.entity_key, ''),
            r.export_control, coalesce(r.reason, ''),
            r.detail::text, coalesce(r.changes::text, ''),
            r.schema_version);

        expected := digest(r.prev_hash || convert_to(payload, 'UTF8'), 'sha256');
        IF expected IS DISTINCT FROM r.row_hash THEN
            first_bad_id := r.id; reason := 'row contents do not match row_hash';
            RETURN NEXT; RETURN;
        END IF;

        running := r.row_hash;
    END LOOP;
    RETURN;
END $$;

-- ---------------------------------------------------------------------
-- Indexes for audit record reduction and reporting (3.3.6)
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS ix_audit_occurred    ON audit.audit_trail (occurred_utc DESC);
CREATE INDEX IF NOT EXISTS ix_audit_actor       ON audit.audit_trail (actor_id, occurred_utc DESC);
CREATE INDEX IF NOT EXISTS ix_audit_entity      ON audit.audit_trail (entity_type, entity_key, occurred_utc DESC);
CREATE INDEX IF NOT EXISTS ix_audit_correlation ON audit.audit_trail (correlation_id);
CREATE INDEX IF NOT EXISTS ix_audit_type        ON audit.audit_trail (event_type, action, occurred_utc DESC);
CREATE INDEX IF NOT EXISTS ix_audit_detail_gin  ON audit.audit_trail USING gin (detail jsonb_path_ops);

-- ---------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA audit TO forgepoint_app, forgepoint_auditor, forgepoint_archive;

-- App: insert only. No SELECT - the app has no business reading history.
GRANT INSERT   ON audit.audit_trail        TO forgepoint_app;
GRANT USAGE    ON SEQUENCE audit.audit_trail_id_seq TO forgepoint_app;
REVOKE UPDATE, DELETE, TRUNCATE, SELECT ON audit.audit_trail FROM forgepoint_app;
REVOKE ALL     ON audit.chain_state        FROM forgepoint_app;  -- trigger is SECURITY DEFINER

-- Auditor: read only.
GRANT SELECT   ON audit.audit_trail        TO forgepoint_auditor;
GRANT EXECUTE  ON FUNCTION audit.verify_chain(bigint, bigint) TO forgepoint_auditor;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit.audit_trail FROM forgepoint_auditor;

-- Archive: read + detach partitions.
GRANT SELECT   ON audit.audit_trail        TO forgepoint_archive;

-- ---------------------------------------------------------------------
-- Partition management
--
-- ITAR record retention is five years, so nothing is dropped inside
-- that window. Detached partitions go to encrypted offline media and
-- are re-attachable if an investigation needs them.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.ensure_partition(p_month date)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    start_d date := date_trunc('month', p_month)::date;
    end_d   date := (date_trunc('month', p_month) + interval '1 month')::date;
    name    text := format('audit_trail_%s', to_char(start_d, 'YYYY_MM'));
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = name) THEN
        EXECUTE format(
            'CREATE TABLE audit.%I PARTITION OF audit.audit_trail FOR VALUES FROM (%L) TO (%L)',
            name, start_d, end_d);
    END IF;
END $$;

-- Bootstrap: current month plus the next twelve.
DO $$
DECLARE i int;
BEGIN
    FOR i IN 0..12 LOOP
        PERFORM audit.ensure_partition((current_date + (i || ' month')::interval)::date);
    END LOOP;
END $$;

-- Schedule this monthly (pg_cron, or a hosted service in the app):
--   SELECT audit.ensure_partition((current_date + interval '13 month')::date);

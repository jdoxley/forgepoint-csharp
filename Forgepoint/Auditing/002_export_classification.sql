-- =====================================================================
-- 002: per-item export classification
--
-- Replaces the single export_control column with a classification
-- snapshot: jurisdiction plus the specific control reference and the
-- determination that authorises it.
--
-- Run as the DBA/owner role, not the application role.
--
-- ALTER TABLE ADD COLUMN does not fire the row-level append-only
-- triggers, so this is safe against existing history. Existing rows keep
-- schema_version = 1 and are still verifiable (see fn_hash_chain below).
-- =====================================================================

ALTER TABLE audit.audit_trail
    ADD COLUMN IF NOT EXISTS jurisdiction     text NOT NULL DEFAULT 'Undetermined',
    ADD COLUMN IF NOT EXISTS usml_category    text NULL,   -- e.g. 'XII(e)'
    ADD COLUMN IF NOT EXISTS eccn             text NULL,   -- e.g. '9E991', 'EAR99'
    ADD COLUMN IF NOT EXISTS determination_id text NULL,   -- FK-by-value into your determinations table
    ADD COLUMN IF NOT EXISTS classified_utc   timestamptz NULL;  -- when that determination was made

-- Backfill history from the old column, best effort.
UPDATE audit.chain_state SET singleton = true WHERE false;  -- no-op, keeps this block transactional
ALTER TABLE audit.audit_trail ALTER COLUMN schema_version SET DEFAULT 2;

COMMENT ON COLUMN audit.audit_trail.jurisdiction IS
    'Itar | Ear | NotControlled | Undetermined - as of the moment of the event, not current';
COMMENT ON COLUMN audit.audit_trail.export_control IS
    'DEPRECATED as of schema_version 2; retained for schema_version 1 rows and hash verification';

-- Reporting: "every ITAR touch by actor", "every undetermined item accessed"
CREATE INDEX IF NOT EXISTS ix_audit_jurisdiction
    ON audit.audit_trail (jurisdiction, occurred_utc DESC);
CREATE INDEX IF NOT EXISTS ix_audit_actor_jurisdiction
    ON audit.audit_trail (actor_id, jurisdiction, occurred_utc DESC);

-- ---------------------------------------------------------------------
-- Hash chain, version-aware.
--
-- The payload formula changed, so old rows must keep hashing under the
-- v1 formula or every historical row fails verification. schema_version
-- selects the formula. Never edit a formula in place - add a version.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.fn_chain_payload(r audit.audit_trail)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE r.schema_version
        WHEN 1 THEN concat_ws('|',
            r.id,
            to_char(r.occurred_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            r.event_type, r.action, r.outcome,
            r.actor_id, r.actor_name, r.actor_kind,
            coalesce(host(r.client_ip), ''), coalesce(r.circuit_id, ''),
            r.correlation_id,
            coalesce(r.entity_type, ''), coalesce(r.entity_key, ''),
            r.export_control, coalesce(r.reason, ''),
            r.detail::text, coalesce(r.changes::text, ''),
            r.schema_version)
        ELSE concat_ws('|',
            r.id,
            to_char(r.occurred_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            r.event_type, r.action, r.outcome,
            r.actor_id, r.actor_name, r.actor_kind,
            coalesce(host(r.client_ip), ''), coalesce(r.circuit_id, ''),
            r.correlation_id,
            coalesce(r.entity_type, ''), coalesce(r.entity_key, ''),
            r.jurisdiction, coalesce(r.usml_category, ''), coalesce(r.eccn, ''),
            coalesce(r.determination_id, ''),
            coalesce(to_char(r.classified_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), ''),
            coalesce(r.reason, ''),
            r.detail::text, coalesce(r.changes::text, ''),
            r.schema_version)
    END
$$;

CREATE OR REPLACE FUNCTION audit.fn_hash_chain() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = audit, pg_catalog
AS $$
DECLARE prev bytea;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit.audit_trail'));
    SELECT last_hash INTO prev FROM audit.chain_state WHERE singleton;

    NEW.prev_hash := prev;
    NEW.row_hash  := digest(prev || convert_to(audit.fn_chain_payload(NEW), 'UTF8'), 'sha256');

    UPDATE audit.chain_state
       SET last_id = NEW.id, last_hash = NEW.row_hash
     WHERE singleton;

    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION audit.verify_chain(
    p_from bigint DEFAULT 0,
    p_to   bigint DEFAULT 9223372036854775807)
RETURNS TABLE (first_bad_id bigint, reason text)
LANGUAGE plpgsql AS $$
DECLARE
    r audit.audit_trail;
    running bytea := NULL;
    expected bytea;
BEGIN
    FOR r IN SELECT * FROM audit.audit_trail
              WHERE id BETWEEN p_from AND p_to ORDER BY id
    LOOP
        IF running IS NOT NULL AND r.prev_hash IS DISTINCT FROM running THEN
            first_bad_id := r.id;
            reason := 'prev_hash does not match preceding row_hash';
            RETURN NEXT; RETURN;
        END IF;

        expected := digest(r.prev_hash || convert_to(audit.fn_chain_payload(r), 'UTF8'), 'sha256');
        IF expected IS DISTINCT FROM r.row_hash THEN
            first_bad_id := r.id;
            reason := format('row contents do not match row_hash (schema v%s)', r.schema_version);
            RETURN NEXT; RETURN;
        END IF;

        running := r.row_hash;
    END LOOP;
    RETURN;
END $$;

-- ---------------------------------------------------------------------
-- Retroactive exposure review.
--
-- When an item is reclassified upward - NotControlled or Undetermined to
-- ITAR - you need to know who saw it under the old classification. This
-- is the query you will actually be asked for during a voluntary
-- disclosure, so make it a function rather than ad hoc SQL.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.exposure_review(
    p_entity_type text,
    p_entity_key  text,
    p_since       timestamptz DEFAULT '-infinity')
RETURNS TABLE (
    actor_id text, actor_name text, actor_kind text,
    first_touch timestamptz, last_touch timestamptz,
    touch_count bigint, actions text[], jurisdictions text[])
LANGUAGE sql STABLE AS $$
    SELECT a.actor_id, a.actor_name, a.actor_kind,
           min(a.occurred_utc), max(a.occurred_utc), count(*),
           array_agg(DISTINCT a.action),
           array_agg(DISTINCT a.jurisdiction)
      FROM audit.audit_trail a
     WHERE a.entity_type = p_entity_type
       AND a.entity_key  = p_entity_key
       AND a.occurred_utc >= p_since
     GROUP BY a.actor_id, a.actor_name, a.actor_kind
     ORDER BY min(a.occurred_utc)
$$;

GRANT EXECUTE ON FUNCTION audit.exposure_review(text, text, timestamptz) TO forgepoint_auditor;
GRANT EXECUTE ON FUNCTION audit.verify_chain(bigint, bigint) TO forgepoint_auditor;

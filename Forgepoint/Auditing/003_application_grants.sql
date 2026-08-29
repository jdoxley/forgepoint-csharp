-- =====================================================================
-- 003: application grants on the business schema
--
-- The role split is by schema, not by application function:
--
--   forgepoint_app      full CRUD on public, INSERT-only on audit.
--                       Every normal operation - update a part, list work
--                       orders, delete a PO - runs as this role. It has to,
--                       because the audit row is written on the same
--                       connection and in the same transaction.
--
--   forgepoint_auditor  SELECT on audit, nothing at all on public.
--                       Used only by AuditQueryService. The audit rows
--                       denormalise actor_name and entity_key precisely so
--                       the viewer never needs to join to business data.
--
--   forgepoint_migrator owns the schema and holds DDL. The app role must
--                       never own tables, or it can drop the triggers that
--                       enforce append-only.
--
--   forgepoint_archive  SELECT on audit + partition detach for retention.
-- =====================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forgepoint_migrator') THEN
        CREATE ROLE forgepoint_migrator LOGIN;
    END IF;
END $$;

-- Migrator owns everything in public.
ALTER SCHEMA public OWNER TO forgepoint_migrator;
GRANT ALL ON SCHEMA public TO forgepoint_migrator;

-- App: data, not structure.
GRANT USAGE ON SCHEMA public TO forgepoint_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO forgepoint_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO forgepoint_app;

-- Same for tables the migrator creates later.
ALTER DEFAULT PRIVILEGES FOR ROLE forgepoint_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO forgepoint_app;
ALTER DEFAULT PRIVILEGES FOR ROLE forgepoint_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO forgepoint_app;

-- No DDL for the app role. This is what keeps the audit triggers in place.
REVOKE CREATE ON SCHEMA public FROM forgepoint_app;

-- Auditor stays out of business data entirely.
REVOKE ALL ON SCHEMA public FROM forgepoint_auditor;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM forgepoint_auditor;

-- Migrations run under a named principal so their audit rows are attributable
-- (SystemActors.Migration). Give the migrator INSERT on the trail too.
GRANT INSERT ON audit.audit_trail TO forgepoint_migrator;
GRANT USAGE  ON SEQUENCE audit.audit_trail_id_seq TO forgepoint_migrator;
REVOKE UPDATE, DELETE, TRUNCATE ON audit.audit_trail FROM forgepoint_migrator;

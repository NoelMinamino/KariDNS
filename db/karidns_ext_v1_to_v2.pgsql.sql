-- karidns_ext_v1_to_v2.pgsql.sql - converts the KariDNS extension tables of a PostgreSQL database from schema version 1
-- (db/karidns_ext.pgsql.sql of milestone B6a..B9) to version 2 (milestone B10).  PostgreSQL 13 or later (xid8).
--
-- Apply it once, as the owner of the tables, in the schema that holds them (SET search_path TO that_schema first):
--     psql -v ON_ERROR_STOP=1 -f karidns_ext_v1_to_v2.pgsql.sql karidns
-- It can be applied again (every step is IF NOT EXISTS / a no-op on version 2).  Then apply db/karidns_ext.pgsql.sql again
-- if you want the triggers and functions of the current file (it is idempotent); the triggers of version 1 keep working.
--
-- What changes:
--   karidns_changes.xid xid8   the transaction that wrote the row (DEFAULT pg_current_xact_id()).  The loader keeps the xmin
--                              of its snapshot as its position in the log, so a transaction that took a lower seq but
--                              commits later is never skipped (see db/karidns_ext.pgsql.sql).  The rows that exist now get
--                              xid 0: they belong to finished transactions.
--   karidns_zone_tagdefs.id    BIGSERIAL, the order of the definitions of a zone (the first match wins).  The existing rows are
--                              numbered in the order PostgreSQL returns them, which for a table that was only appended to
--                              is the order they were inserted in.  Check it with
--                              SELECT * FROM karidns_zone_tagdefs ORDER BY domain_id, id;
--   karidns_schema_version     2
--   the karidns_* functions       get SET search_path FROM CURRENT (the search_path of the session that runs this script, so SET search_path TO
--                              that_schema first for a non-default schema), as in db/karidns_ext.pgsql.sql
--
-- Until this script has run, the loader serves the database without a change log (the zones are compared by serial) and
-- reads the tag definitions in physical order.

BEGIN;

ALTER TABLE karidns_changes ADD COLUMN IF NOT EXISTS xid xid8 NOT NULL DEFAULT '0'::xid8;
ALTER TABLE karidns_changes ALTER COLUMN xid SET DEFAULT pg_current_xact_id();
CREATE INDEX IF NOT EXISTS karidns_changes_xid_idx ON karidns_changes (xid);

-- ADD COLUMN IF NOT EXISTS would still try to add the primary key a second time
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'karidns_zone_tagdefs'::regclass AND attname = 'id' AND NOT attisdropped) THEN
    ALTER TABLE karidns_zone_tagdefs ADD COLUMN id BIGSERIAL PRIMARY KEY;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS karidns_schema_version (version INTEGER NOT NULL);
INSERT INTO karidns_schema_version (version) SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM karidns_schema_version);
UPDATE karidns_schema_version SET version = 2 WHERE version < 2;

-- The functions of version 1 resolved karidns_log_domains / karidns_changes / records through the writer's search_path.  Pin the
-- search_path of this session (the schema that holds the tables) into every karidns_* function of that schema.
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p WHERE p.pronamespace = current_schema()::regnamespace AND p.proname LIKE 'karidns_%'
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path FROM CURRENT', f);
  END LOOP;
END $$;

COMMIT;

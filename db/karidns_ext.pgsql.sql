-- karidns_ext.pgsql.sql - the KariDNS extension tables and the change-log triggers for a PowerDNS 5.1 gpgsql database
-- (beta design 3.7, 5.1, 6; milestones B6a, B10).  Schema version 3.  PostgreSQL 13 or later (transition tables, xid8).
--
-- Manual: docs/karidns-dbloader.md (the schema and trigger files, the privileges, the drivers) and the database chapter of
-- docs/karidns.md.  The packages karidns-sqlite3, karidns-postgresql and karidns-db install this file in /usr/local/share/karidns/db/.
--
-- Apply it once, as the owner of the PowerDNS tables, after the PowerDNS schema (schema.pgsql.sql), in the schema that
-- holds them (a view with its own schema needs its own copy: SET search_path TO that_schema first):
--     psql -v ON_ERROR_STOP=1 -f karidns_ext.pgsql.sql karidns
-- It can be applied again (IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS); the version row is only inserted once.  Applied to a
-- version 2 database it adds the schema karidns_auth (the end of this file) and moves the version row to 3.
--
-- Schema version 3 (0.6.0 item B) adds the schema karidns_auth: the users, groups, grants and the audit log of the WebAdmin.  The loader and
-- karicheck db read versions 1 to 3 and use nothing of it; the end of this file says what it holds.
--
-- What it gives karidns-dbloader:
--   karidns_changes   a log of "domain D changed" (seq, domain_id, changed_at).  Statement-level AFTER INSERT / UPDATE /
--                     DELETE triggers with transition tables on domains, records, domainmetadata, cryptokeys and the
--                     karidns_* tables below write ONE row per distinct domain per statement (OLD and NEW domain ids), so a
--                     bulk import of a million records into one zone logs one row, and NOTIFY the channel karidns_changes.
--                     There is no foreign key on domain_id: a deleted domain must stay in the log.
--   a prune trigger   keeps the newest 1,000,000 rows (the loader is read-only and cannot prune).  BIGSERIAL values are not
--                     given back by a rolled-back transaction, so the log can have holes; a loader that sees the rows after
--                     its seq start later than seq + 1 compares everything again (never wrong, only slower).
--   the tables of design 3.7 that later milestones read: karidns_domain_views (B6b), karidns_profiles (B7a, with triggers that log the domains naming the profile),
--                     karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs (B8).
--
-- Why karidns_changes.xid (schema version 2): seq is taken when a statement ends, but a row becomes visible when its transaction
-- commits, and transactions commit in another order than their statements ended.  A reader that remembered "seq 6" would
-- never see a seq 5 that commits later.  The loader keeps the xmin of its snapshot instead (every transaction below it has
-- finished) and reads the rows with xid >= that cursor again next time.  Version 1 had no xid; the loader serves such a
-- database without a change log (zones compared by serial); db/karidns_ext_v1_to_v2.pgsql.sql converts a database.
--
-- Every function has SET search_path FROM CURRENT: the search_path of the session that applies this file (SET search_path TO that_schema
-- first for a non-default schema) is pinned into the functions, so a trigger fired by a writer with another search_path still logs into
-- the karidns_changes of the schema the DDL was installed in (tests/run_db_ddl_test.sh).
--
-- Multi-server operation (B11; release plan 4.8, beta design 3.7): karidns_reload_requests and karidns_server_status, at the end of
-- this file.  They are optional: karidns-dbloader looks for them like for the other karidns_* tables, and without them a server
-- simply does not watch for requests or report (applying this file again to a version 2 database adds the two tables, and
-- db/karidns_ext_v1_to_v2.pgsql.sql needs no new step).
--
-- TRUNCATE is not logged (a trigger on TRUNCATE has no transition tables); use DELETE, or `karictl reload` afterwards.
-- The loader role needs SELECT on karidns_changes (and the other tables it reads); it only writes karidns_server_status (B11).
--
-- The retention is the number 1000000 in karidns_changes_prune_fn below; tests/run_db_ddl_test.sh replaces it by 5 to test
-- the pruning on a small scale.

CREATE TABLE IF NOT EXISTS karidns_schema_version (version INTEGER NOT NULL);
-- a fresh database starts as version 2; the last statement of this file (after karidns_auth exists) makes it 3
INSERT INTO karidns_schema_version (version) SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM karidns_schema_version);

CREATE TABLE IF NOT EXISTS karidns_changes (
  seq        BIGSERIAL PRIMARY KEY,
  domain_id  INTEGER NOT NULL,
  changed_at BIGINT NOT NULL,
  xid        xid8 NOT NULL DEFAULT pg_current_xact_id()   -- schema version 2: the transaction that wrote the row
);
CREATE INDEX IF NOT EXISTS karidns_changes_xid_idx ON karidns_changes (xid);

CREATE TABLE IF NOT EXISTS karidns_domain_views (
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  view_name VARCHAR(64) NOT NULL,
  PRIMARY KEY (domain_id, view_name)
);

CREATE TABLE IF NOT EXISTS karidns_profiles (
  name     VARCHAR(64) PRIMARY KEY,
  settings TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS karidns_record_tags (
  record_id    BIGINT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
  location_tag VARCHAR(63),
  ecs_tag      VARCHAR(63)
);

CREATE TABLE IF NOT EXISTS karidns_record_tinydns (
  record_id BIGINT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
  ttd       BIGINT,
  loc       CHAR(2),
  countdown BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS karidns_zone_tagdefs (
  id        BIGSERIAL PRIMARY KEY,          -- schema version 2: the order of the definitions (the first match wins)
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  kind      VARCHAR(8) NOT NULL,          -- 'location' | 'ecs' | 'tinydns'
  tag       VARCHAR(63) NOT NULL,
  cidr      VARCHAR(64) NOT NULL
);
-- the loader reads the definitions of one zone at a time (scan_metadata): without this index every such read scans the
-- table.  Added after version 2; applying this file again creates it (the schema version stays 2).
CREATE INDEX IF NOT EXISTS karidns_zone_tagdefs_domain_idx ON karidns_zone_tagdefs (domain_id);

-- prune: keep the newest 1000000 rows (statement level: one DELETE per INSERT statement)
CREATE OR REPLACE FUNCTION karidns_changes_prune_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  DELETE FROM karidns_changes WHERE seq <= (SELECT max(seq) FROM new_rows) - 1000000;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_changes_prune ON karidns_changes;
CREATE TRIGGER karidns_changes_prune AFTER INSERT ON karidns_changes
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_changes_prune_fn();

-- the one place that writes the log: the distinct domain ids of a statement, then NOTIFY
CREATE OR REPLACE FUNCTION karidns_log_domains(ids INTEGER[]) RETURNS void LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at)
    SELECT DISTINCT d, extract(epoch FROM now())::bigint FROM unnest(ids) AS d WHERE d IS NOT NULL;
  PERFORM pg_notify('karidns_changes', '');
END $$;

-- domains (the key is id)
CREATE OR REPLACE FUNCTION karidns_trg_domains_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domains_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT id FROM old_rows UNION SELECT id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domains_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT id FROM old_rows)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_domains_ins ON domains;
DROP TRIGGER IF EXISTS karidns_trg_domains_upd ON domains;
DROP TRIGGER IF EXISTS karidns_trg_domains_del ON domains;
CREATE TRIGGER karidns_trg_domains_ins AFTER INSERT ON domains REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domains_ins_fn();
CREATE TRIGGER karidns_trg_domains_upd AFTER UPDATE ON domains REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domains_upd_fn();
CREATE TRIGGER karidns_trg_domains_del AFTER DELETE ON domains REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domains_del_fn();

-- records
CREATE OR REPLACE FUNCTION karidns_trg_records_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_records_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_records_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_records_ins ON records;
DROP TRIGGER IF EXISTS karidns_trg_records_upd ON records;
DROP TRIGGER IF EXISTS karidns_trg_records_del ON records;
CREATE TRIGGER karidns_trg_records_ins AFTER INSERT ON records REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_records_ins_fn();
CREATE TRIGGER karidns_trg_records_upd AFTER UPDATE ON records REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_records_upd_fn();
CREATE TRIGGER karidns_trg_records_del AFTER DELETE ON records REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_records_del_fn();

-- domainmetadata
CREATE OR REPLACE FUNCTION karidns_trg_domainmetadata_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domainmetadata_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domainmetadata_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_domainmetadata_ins ON domainmetadata;
DROP TRIGGER IF EXISTS karidns_trg_domainmetadata_upd ON domainmetadata;
DROP TRIGGER IF EXISTS karidns_trg_domainmetadata_del ON domainmetadata;
CREATE TRIGGER karidns_trg_domainmetadata_ins AFTER INSERT ON domainmetadata REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domainmetadata_ins_fn();
CREATE TRIGGER karidns_trg_domainmetadata_upd AFTER UPDATE ON domainmetadata REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domainmetadata_upd_fn();
CREATE TRIGGER karidns_trg_domainmetadata_del AFTER DELETE ON domainmetadata REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domainmetadata_del_fn();

-- cryptokeys: a zone that gets a key without PRESIGNED must fail (design 3.5), so the loader has to look at it again
CREATE OR REPLACE FUNCTION karidns_trg_cryptokeys_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_cryptokeys_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_cryptokeys_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_cryptokeys_ins ON cryptokeys;
DROP TRIGGER IF EXISTS karidns_trg_cryptokeys_upd ON cryptokeys;
DROP TRIGGER IF EXISTS karidns_trg_cryptokeys_del ON cryptokeys;
CREATE TRIGGER karidns_trg_cryptokeys_ins AFTER INSERT ON cryptokeys REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_cryptokeys_ins_fn();
CREATE TRIGGER karidns_trg_cryptokeys_upd AFTER UPDATE ON cryptokeys REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_cryptokeys_upd_fn();
CREATE TRIGGER karidns_trg_cryptokeys_del AFTER DELETE ON cryptokeys REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_cryptokeys_del_fn();

-- karidns_domain_views
CREATE OR REPLACE FUNCTION karidns_trg_domain_views_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domain_views_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domain_views_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_domain_views_ins ON karidns_domain_views;
DROP TRIGGER IF EXISTS karidns_trg_domain_views_upd ON karidns_domain_views;
DROP TRIGGER IF EXISTS karidns_trg_domain_views_del ON karidns_domain_views;
CREATE TRIGGER karidns_trg_domain_views_ins AFTER INSERT ON karidns_domain_views REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domain_views_ins_fn();
CREATE TRIGGER karidns_trg_domain_views_upd AFTER UPDATE ON karidns_domain_views REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domain_views_upd_fn();
CREATE TRIGGER karidns_trg_domain_views_del AFTER DELETE ON karidns_domain_views REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_domain_views_del_fn();

-- karidns_zone_tagdefs
CREATE OR REPLACE FUNCTION karidns_trg_zone_tagdefs_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_zone_tagdefs_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_zone_tagdefs_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_zone_tagdefs_ins ON karidns_zone_tagdefs;
DROP TRIGGER IF EXISTS karidns_trg_zone_tagdefs_upd ON karidns_zone_tagdefs;
DROP TRIGGER IF EXISTS karidns_trg_zone_tagdefs_del ON karidns_zone_tagdefs;
CREATE TRIGGER karidns_trg_zone_tagdefs_ins AFTER INSERT ON karidns_zone_tagdefs REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_zone_tagdefs_ins_fn();
CREATE TRIGGER karidns_trg_zone_tagdefs_upd AFTER UPDATE ON karidns_zone_tagdefs REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_zone_tagdefs_upd_fn();
CREATE TRIGGER karidns_trg_zone_tagdefs_del AFTER DELETE ON karidns_zone_tagdefs REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_zone_tagdefs_del_fn();

-- karidns_record_tags: the domain is found through the record (a record that is gone has logged its own deletion)
CREATE OR REPLACE FUNCTION karidns_trg_record_tags_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tags_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN old_rows o ON o.record_id = r.id
                                        UNION SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id));
RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tags_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN old_rows o ON o.record_id = r.id)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_record_tags_ins ON karidns_record_tags;
DROP TRIGGER IF EXISTS karidns_trg_record_tags_upd ON karidns_record_tags;
DROP TRIGGER IF EXISTS karidns_trg_record_tags_del ON karidns_record_tags;
CREATE TRIGGER karidns_trg_record_tags_ins AFTER INSERT ON karidns_record_tags REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_record_tags_ins_fn();
CREATE TRIGGER karidns_trg_record_tags_upd AFTER UPDATE ON karidns_record_tags REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_record_tags_upd_fn();
CREATE TRIGGER karidns_trg_record_tags_del AFTER DELETE ON karidns_record_tags REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_record_tags_del_fn();

-- karidns_record_tinydns
CREATE OR REPLACE FUNCTION karidns_trg_record_tinydns_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tinydns_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN old_rows o ON o.record_id = r.id
                                        UNION SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id));
RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tinydns_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN old_rows o ON o.record_id = r.id)); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_record_tinydns_ins ON karidns_record_tinydns;
DROP TRIGGER IF EXISTS karidns_trg_record_tinydns_upd ON karidns_record_tinydns;
DROP TRIGGER IF EXISTS karidns_trg_record_tinydns_del ON karidns_record_tinydns;
CREATE TRIGGER karidns_trg_record_tinydns_ins AFTER INSERT ON karidns_record_tinydns REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_record_tinydns_ins_fn();
CREATE TRIGGER karidns_trg_record_tinydns_upd AFTER UPDATE ON karidns_record_tinydns REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_record_tinydns_upd_fn();
CREATE TRIGGER karidns_trg_record_tinydns_del AFTER DELETE ON karidns_record_tinydns REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_record_tinydns_del_fn();

-- karidns_profiles (B7a): the settings of a profile are part of every zone that names it (domainmetadata X-KARIDNS-PROFILE),
-- so editing, adding or deleting a profile logs every domain that uses the old or the new name (one statement = one
-- log row per domain).  The kind is compared case-insensitively and the content without leading / trailing blanks, like
-- the loader does.
CREATE OR REPLACE FUNCTION karidns_trg_profiles_ins_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT m.domain_id FROM domainmetadata m JOIN new_rows n ON btrim(m.content, E' \t') = n.name
                                         WHERE upper(m.kind) = 'X-KARIDNS-PROFILE')); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_profiles_upd_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT m.domain_id FROM domainmetadata m
                                         WHERE upper(m.kind) = 'X-KARIDNS-PROFILE'
                                           AND btrim(m.content, E' \t') IN (SELECT name FROM old_rows UNION SELECT name FROM new_rows))); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_profiles_del_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT m.domain_id FROM domainmetadata m JOIN old_rows o ON btrim(m.content, E' \t') = o.name
                                         WHERE upper(m.kind) = 'X-KARIDNS-PROFILE')); RETURN NULL; END $$;
DROP TRIGGER IF EXISTS karidns_trg_profiles_ins ON karidns_profiles;
DROP TRIGGER IF EXISTS karidns_trg_profiles_upd ON karidns_profiles;
DROP TRIGGER IF EXISTS karidns_trg_profiles_del ON karidns_profiles;
CREATE TRIGGER karidns_trg_profiles_ins AFTER INSERT ON karidns_profiles REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_profiles_ins_fn();
CREATE TRIGGER karidns_trg_profiles_upd AFTER UPDATE ON karidns_profiles REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_profiles_upd_fn();
CREATE TRIGGER karidns_trg_profiles_del AFTER DELETE ON karidns_profiles REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_trg_profiles_del_fn();

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Multi-server operation (B11; release plan 4.8).  Several karidns servers read one database.  A management tool (WebAdmin, a
-- script) that wants every server to reload INSERTs one row into karidns_reload_requests, after the data it wants them to see
-- is committed; every server's karidns-dbloader LISTENs, reads the new rows, reloads, and writes the outcome to its row of
-- karidns_server_status.  "At the same time" means within seconds, with visible per-server status; it is not atomic.
--     INSERT INTO karidns_reload_requests DEFAULT VALUES;                 -- every zone of this schema
--     INSERT INTO karidns_reload_requests (zone) VALUES ('example.test'); -- one zone (name without a trailing dot is fine)
--     INSERT INTO karidns_reload_requests (zone, force) VALUES (NULL, true);   -- compare and send everything, even unchanged zones
--     SELECT server_id, generation, ok, applied_at, failed_zones FROM karidns_server_status ORDER BY server_id;
-- A server that has applied generation G has the data of every transaction that committed before request G (replicas included:
-- the request row reaches a replica after the data, by WAL order).  Several requests that arrive together are one reload: any
-- request for all zones (zone NULL), or a hole in the generations (rows pruned or rolled back), makes it a full diff, else the
-- listed zones are reloaded; force is the OR of the requests.  The tables are per schema (a view with a schema of its own needs
-- its own copy of this file, like the other karidns_* tables).
--
--   karidns_reload_requests   generation: the order of the requests (an IDENTITY column; the loader reads generation > the last it
--                             applied).  The INSERT trigger first takes a transaction-level advisory lock on the table, so that
--                             two concurrent requesters take their generations in the order they commit (otherwise a request with
--                             a lower generation could become visible after a higher one was applied, and be skipped); requesters
--                             wait for each other until commit, so commit soon.  Then AFTER INSERT, pg_notify('karidns_reload',
--                             generation).  Only the newest 1000 requests are kept.
--   karidns_server_status     one row per server-id (the `server-id` of the database block, default the host name): the last
--                             request the server applied, when, whether every zone loaded (ok), and, if not, the zones that
--                             did not ("zone: reason" lines, at most 64 lines and 4 KiB, control characters written as \DDD).
--                             The loader role needs INSERT and UPDATE on this table (db/karidns_loader_role.pgsql.sql).
CREATE TABLE IF NOT EXISTS karidns_reload_requests (
  generation   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  zone         VARCHAR(255) NULL,                 -- NULL = all zones of this schema
  force        BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS karidns_server_status (
  server_id    VARCHAR(64) PRIMARY KEY,
  generation   BIGINT NOT NULL,                   -- the last request applied
  applied_at   TIMESTAMPTZ NOT NULL,
  ok           BOOLEAN NOT NULL,
  failed_zones TEXT NOT NULL DEFAULT ''           -- "zone: reason" lines, capped
);

-- requesters take the lock before the generation is drawn (a statement-level BEFORE trigger runs before any row), and keep it
-- until they commit: generations then become visible in order.  The key is the OID of this table (one lock per schema's copy).
CREATE OR REPLACE FUNCTION karidns_reload_requests_lock_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM pg_advisory_xact_lock('karidns_reload_requests'::regclass::oid::bigint);
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_reload_requests_lock ON karidns_reload_requests;
CREATE TRIGGER karidns_reload_requests_lock BEFORE INSERT ON karidns_reload_requests
  FOR EACH STATEMENT EXECUTE FUNCTION karidns_reload_requests_lock_fn();

CREATE OR REPLACE FUNCTION karidns_reload_requests_notify_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM pg_notify('karidns_reload', (SELECT max(generation)::text FROM new_rows));
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_reload_requests_notify ON karidns_reload_requests;
CREATE TRIGGER karidns_reload_requests_notify AFTER INSERT ON karidns_reload_requests
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_reload_requests_notify_fn();

-- prune: keep the newest 1000 requests
CREATE OR REPLACE FUNCTION karidns_reload_requests_prune_fn() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  DELETE FROM karidns_reload_requests WHERE generation <= (SELECT max(generation) FROM new_rows) - 1000;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_reload_requests_prune ON karidns_reload_requests;
CREATE TRIGGER karidns_reload_requests_prune AFTER INSERT ON karidns_reload_requests
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_reload_requests_prune_fn();

-- ---------------------------------------------------------------------------------------------------------------------------------
-- == karidns_auth (schema version 3) ==    0.6.0 item B, milestone M1.  Everything above is version 2.
--
-- The schema karidns_auth holds the users, groups, grants and the audit log of the WebAdmin / API (docs/karidns-auth.md); it is shared
-- by every data schema of the database: the tables are CREATE ... IF NOT EXISTS and the functions CREATE OR REPLACE, so the
-- copy of this file that runs in a second data schema only adds that schema's trigger.  The owner of the PowerDNS tables applies this file and needs
-- the CREATE privilege on the database (for CREATE SCHEMA karidns_auth).  A version 2 database becomes version 3 when this file is applied
-- again (the version row goes from 2 to 3 at the very end); a version 1 database needs db/karidns_ext_v1_to_v2.pgsql.sql first.
--
-- This file only CREATES things.  It does not enable row level security and it does not attach the audit triggers to the PowerDNS tables:
-- either would hide rows from, or slow down, roles that have nothing to do with the WebAdmin (the loader, karidns-zone, PowerDNS itself).
-- The role scripts of the WebAdmin and the signer (milestone M2) switch them on; a site without them has no audit rows and no RLS.
-- The audit is attached to a schema's tables with
--     SELECT karidns_auth.enable_audit('public');       -- idempotent; karidns_auth.disable_audit('public') takes it off again
-- The audit triggers of the karidns_auth tables themselves are attached below (nothing writes them without the WebAdmin).
--
--   principals          users and groups (kind), a group that is in no group is a tenant
--   credentials         password hash (PHC string: $argon2id$ or $scrypt$, the prefix is checked), TOTP secret, OIDC subject; users only
--   memberships         member -> group; a trigger refuses a cycle, a nesting deeper than 8 and a user as a group
--   principal_closure   (principal, group it is in directly or through groups, shortest depth), plus (p, p, 0); kept by triggers
--   rr_policies         the record types, TTL range and flags a grant allows; no DNSSEC-managed type
--   grants              global_master / domain_master / subdomain_master on (data_schema, zone_name [, name_suffix]); canonical names only
--   audit_log           who changed what: before / after as JSON, secrets replaced by "<redacted>"; append only (the owner alone has rights)
--   schema_version      3
-- Zones are named by (data schema, zone name), not by domains.id.  The trigger karidns_trg_domains_grants on domains removes the grants of
-- a deleted zone and renames those of a renamed zone, so a grant never outlives its zone and never moves to a later zone of the same name.

CREATE SCHEMA IF NOT EXISTS karidns_auth;

CREATE TABLE IF NOT EXISTS karidns_auth.schema_version (version INTEGER NOT NULL);       -- its row is written by the last statements of this file

-- canonical names: lower case, no trailing dot, no empty label, no blank or control character (0x01-0x20, 0x7f), 1 to 253 octets
-- (PowerDNS stores names this way)
CREATE OR REPLACE FUNCTION karidns_auth.is_canonical_name(n text) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
  SELECT n IS NOT NULL AND octet_length(n) BETWEEN 1 AND 253 AND n = lower(n) AND n !~ '(^[.]|[.][.]|[.]$)' AND n !~ '[\x01-\x20\x7f]'
$$;

-- the types of an rr_policy: upper case; none of the types the signer owns (also written TYPE46, TYPE0047, ...: RRSIG 46, NSEC 47, DNSKEY 48,
-- NSEC3 50, NSEC3PARAM 51, CDS 59, CDNSKEY 60) and none of the meta types that are not data (ANY AXFR IXFR OPT TSIG TKEY MAILA MAILB)
CREATE OR REPLACE FUNCTION karidns_auth.rr_types_ok(t text[]) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
  SELECT t IS NOT NULL AND NOT EXISTS (SELECT 1 FROM unnest(t) AS x
                                        WHERE x IS NULL OR x !~ '^[A-Z][A-Z0-9]*$'
                                           OR x IN ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY',
                                                    'ANY', 'AXFR', 'IXFR', 'OPT', 'TSIG', 'TKEY', 'MAILA', 'MAILB')
                                           OR x ~ '^TYPE0*(46|47|48|50|51|59|60)$')
$$;

CREATE TABLE IF NOT EXISTS karidns_auth.principals (
  id           BIGSERIAL PRIMARY KEY,
  kind         VARCHAR(5) NOT NULL CHECK (kind IN ('user', 'group')),
  name         VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(255) NULL,
  email        VARCHAR(255) NULL,
  disabled     BOOLEAN NOT NULL DEFAULT false,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   BIGINT NULL                       -- a principal id; NULL = a database role
);

CREATE UNIQUE INDEX IF NOT EXISTS principals_lname_idx ON karidns_auth.principals (lower(name));       -- Alice and alice are one name

CREATE TABLE IF NOT EXISTS karidns_auth.credentials (
  principal_id        BIGINT PRIMARY KEY REFERENCES karidns_auth.principals (id) ON DELETE CASCADE,   -- users only (trigger)
  password_hash       TEXT NULL CHECK (password_hash IS NULL OR left(password_hash, 10) = '$argon2id$' OR left(password_hash, 8) = '$scrypt$'),
  totp_secret         TEXT NULL,                 -- opaque to the database
  totp_enabled        BOOLEAN NOT NULL DEFAULT false,
  oidc_issuer         TEXT NULL,
  oidc_subject        TEXT NULL,
  failed_logins       INTEGER NOT NULL DEFAULT 0,
  locked_until        TIMESTAMPTZ NULL,
  password_changed_at TIMESTAMPTZ NULL,
  UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE IF NOT EXISTS karidns_auth.memberships (
  member_id BIGINT NOT NULL REFERENCES karidns_auth.principals (id) ON DELETE CASCADE,
  group_id  BIGINT NOT NULL REFERENCES karidns_auth.principals (id) ON DELETE CASCADE,        -- a group (trigger)
  PRIMARY KEY (member_id, group_id),
  CHECK (member_id <> group_id)
);
CREATE INDEX IF NOT EXISTS memberships_group_idx ON karidns_auth.memberships (group_id);

CREATE TABLE IF NOT EXISTS karidns_auth.principal_closure (
  member_id BIGINT NOT NULL REFERENCES karidns_auth.principals (id) ON DELETE CASCADE,
  group_id  BIGINT NOT NULL REFERENCES karidns_auth.principals (id) ON DELETE CASCADE,
  depth     INTEGER NOT NULL,                    -- the shortest chain of memberships; 0 for (p, p)
  PRIMARY KEY (member_id, group_id)
);
CREATE INDEX IF NOT EXISTS principal_closure_group_idx ON karidns_auth.principal_closure (group_id);

CREATE TABLE IF NOT EXISTS karidns_auth.rr_policies (
  id               BIGSERIAL PRIMARY KEY,
  name             VARCHAR(255) NOT NULL UNIQUE,
  allowed_types    TEXT[] NOT NULL CHECK (karidns_auth.rr_types_ok(allowed_types)),   -- no RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY
  allow_wildcard   BOOLEAN NOT NULL DEFAULT false,
  allow_delegation BOOLEAN NOT NULL DEFAULT false,         -- NS below the apex
  allow_dname      BOOLEAN NOT NULL DEFAULT false,
  apex_editable    BOOLEAN NOT NULL DEFAULT false,
  ttl_min          INTEGER NOT NULL DEFAULT 0,
  ttl_max          INTEGER NOT NULL DEFAULT 2147483647,
  max_rr           INTEGER NULL CHECK (max_rr IS NULL OR max_rr >= 0),     -- NULL = no limit; the API enforces it
  created_by       BIGINT NULL,
  CHECK (ttl_min >= 0 AND ttl_min <= ttl_max)
);

CREATE TABLE IF NOT EXISTS karidns_auth.grants (
  id           BIGSERIAL PRIMARY KEY,
  principal_id BIGINT NOT NULL REFERENCES karidns_auth.principals (id) ON DELETE CASCADE,
  role         VARCHAR(16) NOT NULL CHECK (role IN ('global_master', 'domain_master', 'subdomain_master')),
  data_schema  VARCHAR(63) NULL,
  zone_name    VARCHAR(255) NULL,
  name_suffix  VARCHAR(255) NULL,
  rr_policy_id BIGINT NOT NULL REFERENCES karidns_auth.rr_policies (id) ON DELETE RESTRICT,
  granted_by   BIGINT NULL,                      -- a principal id; NULL = a database role
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT grants_scope CHECK (
       (role = 'global_master'    AND data_schema IS NULL     AND zone_name IS NULL     AND name_suffix IS NULL)
    OR (role = 'domain_master'    AND data_schema IS NOT NULL AND zone_name IS NOT NULL AND name_suffix IS NULL)
    OR (role = 'subdomain_master' AND data_schema IS NOT NULL AND zone_name IS NOT NULL AND name_suffix IS NOT NULL)),
  CONSTRAINT grants_zone_canonical CHECK (zone_name IS NULL OR karidns_auth.is_canonical_name(zone_name)),
  CONSTRAINT grants_suffix_canonical CHECK (name_suffix IS NULL OR karidns_auth.is_canonical_name(name_suffix)),
  CONSTRAINT grants_suffix_under_zone CHECK (name_suffix IS NULL OR zone_name IS NULL
    OR name_suffix = zone_name OR right(name_suffix, length(zone_name) + 1) = '.' || zone_name)
);
CREATE INDEX IF NOT EXISTS grants_zone_idx ON karidns_auth.grants (data_schema, zone_name);
CREATE INDEX IF NOT EXISTS grants_principal_idx ON karidns_auth.grants (principal_id);
CREATE INDEX IF NOT EXISTS grants_policy_idx ON karidns_auth.grants (rr_policy_id);

-- ---- credentials: users only; a principal that has credentials stays a user; a principal in a membership keeps its kind
CREATE OR REPLACE FUNCTION karidns_auth.credentials_user_only_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('karidns_auth.memberships'));          -- the same lock as a kind change: no group-with-credentials race
  IF NOT EXISTS (SELECT 1 FROM karidns_auth.principals WHERE id = NEW.principal_id AND kind = 'user') THEN
    RAISE EXCEPTION 'karidns_auth.credentials: principal % is not a user', NEW.principal_id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS karidns_credentials_user_only ON karidns_auth.credentials;
CREATE TRIGGER karidns_credentials_user_only BEFORE INSERT OR UPDATE OF principal_id ON karidns_auth.credentials
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.credentials_user_only_fn();

CREATE OR REPLACE FUNCTION karidns_auth.principals_kind_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
BEGIN
  IF NEW.kind <> OLD.kind THEN
    PERFORM pg_advisory_xact_lock(hashtext('karidns_auth.memberships'));        -- the lock of the membership and credentials triggers
    IF EXISTS (SELECT 1 FROM karidns_auth.memberships WHERE member_id = OLD.id OR group_id = OLD.id) THEN
      RAISE EXCEPTION 'karidns_auth.principals: principal % is in a membership: its kind cannot change', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.kind = 'group' AND EXISTS (SELECT 1 FROM karidns_auth.credentials WHERE principal_id = OLD.id) THEN
      RAISE EXCEPTION 'karidns_auth.principals: principal % has credentials: it stays a user', OLD.id USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS karidns_principals_kind ON karidns_auth.principals;
CREATE TRIGGER karidns_principals_kind BEFORE UPDATE OF kind ON karidns_auth.principals
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.principals_kind_fn();

-- every principal is in its own closure at depth 0
CREATE OR REPLACE FUNCTION karidns_auth.principals_self_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
BEGIN
  INSERT INTO karidns_auth.principal_closure (member_id, group_id, depth) VALUES (NEW.id, NEW.id, 0) ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_principals_self ON karidns_auth.principals;
CREATE TRIGGER karidns_principals_self AFTER INSERT ON karidns_auth.principals
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.principals_self_fn();

-- ---- memberships: the group is a group, no cycle, at most 8 memberships in a chain; the closure follows every insert and delete.
-- Membership changes take one advisory lock for the transaction, so two transactions cannot each add the edge that closes a cycle.
CREATE OR REPLACE FUNCTION karidns_auth.memberships_check_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  k_group text;
  n_up    integer;
  n_down  integer;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'karidns_auth.memberships: a membership cannot be updated; delete it and insert the new one' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'karidns_auth.memberships: memberships change only in a READ COMMITTED transaction (the cycle check needs the lock below and a snapshot taken after it)'
      USING ERRCODE = 'feature_not_supported';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('karidns_auth.memberships'));
  SELECT kind INTO k_group FROM karidns_auth.principals WHERE id = NEW.group_id;
  IF k_group IS DISTINCT FROM 'group' THEN
    RAISE EXCEPTION 'karidns_auth.memberships: principal % is not a group (a user has no members)', NEW.group_id USING ERRCODE = 'check_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM karidns_auth.principal_closure WHERE member_id = NEW.group_id AND group_id = NEW.member_id) THEN
    RAISE EXCEPTION 'karidns_auth.memberships: % in % would make a cycle', NEW.member_id, NEW.group_id USING ERRCODE = 'check_violation';
  END IF;
  WITH RECURSIVE u(id, d) AS (
    SELECT NEW.group_id, 0
    UNION ALL
    SELECT ms.group_id, u.d + 1 FROM u JOIN karidns_auth.memberships ms ON ms.member_id = u.id WHERE u.d < 9)
  SELECT max(d) INTO n_up FROM u;
  WITH RECURSIVE dn(id, d) AS (
    SELECT NEW.member_id, 0
    UNION ALL
    SELECT ms.member_id, dn.d + 1 FROM dn JOIN karidns_auth.memberships ms ON ms.group_id = dn.id WHERE dn.d < 9)
  SELECT max(d) INTO n_down FROM dn;
  IF n_up + 1 + n_down > 8 THEN
    RAISE EXCEPTION 'karidns_auth.memberships: % in % would nest groups % levels deep (at most 8)', NEW.member_id, NEW.group_id, n_up + 1 + n_down
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS karidns_memberships_check ON karidns_auth.memberships;
CREATE TRIGGER karidns_memberships_check BEFORE INSERT OR UPDATE ON karidns_auth.memberships
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.memberships_check_fn();

-- the closure of the member and of everything below it is computed again from the memberships (a group tree is small)
CREATE OR REPLACE FUNCTION karidns_auth.memberships_closure_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  m   bigint;
  ids bigint[];
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'karidns_auth.memberships: memberships change only in a READ COMMITTED transaction (the closure is computed after taking the lock below, from a fresh snapshot)'
      USING ERRCODE = 'feature_not_supported';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('karidns_auth.memberships'));
  m := CASE WHEN TG_OP = 'DELETE' THEN OLD.member_id ELSE NEW.member_id END;
  SELECT array_agg(c.member_id) INTO ids
    FROM karidns_auth.principal_closure c JOIN karidns_auth.principals p ON p.id = c.member_id WHERE c.group_id = m;
  IF ids IS NULL THEN RETURN NULL; END IF;                 -- the member is gone (a principal that is being deleted)
  DELETE FROM karidns_auth.principal_closure WHERE member_id = ANY (ids);
  INSERT INTO karidns_auth.principal_closure (member_id, group_id, depth)
    WITH RECURSIVE up(root, gid, d) AS (
      SELECT x, x, 0 FROM unnest(ids) AS x
      UNION ALL
      SELECT up.root, ms.group_id, up.d + 1 FROM up JOIN karidns_auth.memberships ms ON ms.member_id = up.gid WHERE up.d < 9)
    SELECT up.root, up.gid, min(up.d)
      FROM up JOIN karidns_auth.principals pr ON pr.id = up.root JOIN karidns_auth.principals pg ON pg.id = up.gid
     GROUP BY up.root, up.gid;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_memberships_closure ON karidns_auth.memberships;
CREATE TRIGGER karidns_memberships_closure AFTER INSERT OR DELETE ON karidns_auth.memberships
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.memberships_closure_fn();

-- a deleted principal first loses its memberships (in both directions) here, so that the closure of everything below and above it is computed
-- again while the principal still exists; the foreign key cascades, whose order against the closure triggers is not defined, find nothing left
CREATE OR REPLACE FUNCTION karidns_auth.principals_delete_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
BEGIN
  DELETE FROM karidns_auth.memberships WHERE member_id = OLD.id OR group_id = OLD.id;
  RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS karidns_principals_delete ON karidns_auth.principals;
CREATE TRIGGER karidns_principals_delete BEFORE DELETE ON karidns_auth.principals
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.principals_delete_fn();

-- ---- grants follow their zone: a deleted zone takes its grants with it, a renamed zone keeps them (on every data schema's domains)
CREATE OR REPLACE FUNCTION karidns_auth.domains_grants_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  o text := lower(regexp_replace(OLD.name, '[.]$', ''));
  n text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM karidns_auth.grants WHERE data_schema = TG_TABLE_SCHEMA AND zone_name = o;
    RETURN NULL;
  END IF;
  n := lower(regexp_replace(NEW.name, '[.]$', ''));
  IF n = o THEN RETURN NULL; END IF;
  IF karidns_auth.is_canonical_name(n) THEN
    UPDATE karidns_auth.grants
       SET zone_name = n,
           name_suffix = CASE WHEN name_suffix IS NULL THEN NULL WHEN name_suffix = o THEN n
                              ELSE left(name_suffix, length(name_suffix) - length(o)) || n END
     WHERE data_schema = TG_TABLE_SCHEMA AND zone_name = o;
  ELSE
    DELETE FROM karidns_auth.grants WHERE data_schema = TG_TABLE_SCHEMA AND zone_name = o;      -- a name no grant can hold
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_trg_domains_grants ON domains;
CREATE TRIGGER karidns_trg_domains_grants AFTER DELETE OR UPDATE OF name ON domains
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.domains_grants_fn();

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The audit log (4.5).  Only the owner may write it; the trigger functions are SECURITY DEFINER, so the roles that change the data
-- need no right on it.  Nothing is granted here: no role (the WebAdmin's included) can UPDATE or DELETE a row.  Pruning is the
-- owner's job:  DELETE FROM karidns_auth.audit_log WHERE at < now() - interval '1 year';
-- TRUNCATE of an audited table is not logged (use DELETE; the roles of the WebAdmin are given no TRUNCATE right).
CREATE TABLE IF NOT EXISTS karidns_auth.audit_log (
  id             BIGSERIAL PRIMARY KEY,
  at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  xid            xid8 NOT NULL DEFAULT pg_current_xact_id(),
  db_role        TEXT NOT NULL DEFAULT current_user,
  principal_id   BIGINT NULL,                    -- karidns.principal of the session (SET LOCAL karidns.principal = '42')
  principal_name TEXT NULL,                      -- copied: it survives the deletion of the principal
  change_set     TEXT NULL,                      -- karidns.change_set of the session
  data_schema    TEXT NOT NULL,
  table_name     TEXT NOT NULL,
  op             CHAR(1) NOT NULL CHECK (op IN ('I', 'U', 'D')),
  zone_name      TEXT NULL,
  row_id         BIGINT NULL,
  before         JSONB NULL,
  after          JSONB NULL
);
CREATE INDEX IF NOT EXISTS audit_log_zone_idx ON karidns_auth.audit_log (zone_name, at);
CREATE INDEX IF NOT EXISTS audit_log_principal_idx ON karidns_auth.audit_log (principal_id, at);
CREATE INDEX IF NOT EXISTS audit_log_change_set_idx ON karidns_auth.audit_log (change_set);
REVOKE ALL ON karidns_auth.audit_log FROM PUBLIC;
REVOKE ALL ON SEQUENCE karidns_auth.audit_log_id_seq FROM PUBLIC;

-- the database role of the caller: SET ROLE wins over the login role (inside a SECURITY DEFINER trigger current_user is the owner)
CREATE OR REPLACE FUNCTION karidns_auth.audit_caller() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN current_setting('role') <> 'none' THEN current_setting('role') ELSE session_user::text END
$$;

-- `SET LOCAL karidns.audit = 'summary'` (karidns-zone --audit summary): instead of one audit row per changed row, one row per transaction,
-- table, operation and zone, which counts the statements and the rows (before / after = {"summary": true, "statements": S, "rows": N}).
-- (karidns-zone writes a zone one row per statement, so one row per statement would not shrink the log.)  The WebAdmin's and the signer's
-- roles (karidns_api, karidns_signer, or a member of them) cannot turn the detail off.
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_summary_uq ON karidns_auth.audit_log (xid, data_schema, table_name, op, (coalesce(zone_name, '')))
  WHERE ((coalesce(after, before) ->> 'summary') = 'true');
-- The roles that cannot turn the detail off are the rows of audit_restricted_roles (owner only; the role scripts of the WebAdmin and the signer add
-- the name they were given with -v role=).  Summary is refused when the login role (session_user) or the SET ROLE role is one of them or a
-- member of one, through any chain of memberships: a member of karidns_api cannot SET ROLE to another role to get rid of the restriction.
-- (Inside a SECURITY DEFINER trigger current_user is the owner, so it cannot be looked at.)
CREATE TABLE IF NOT EXISTS karidns_auth.audit_restricted_roles (role_name name PRIMARY KEY);
INSERT INTO karidns_auth.audit_restricted_roles (role_name) VALUES ('karidns_api'), ('karidns_signer') ON CONFLICT DO NOTHING;
REVOKE ALL ON karidns_auth.audit_restricted_roles FROM PUBLIC;
CREATE OR REPLACE FUNCTION karidns_auth.audit_summary() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT coalesce(current_setting('karidns.audit', true), '') = 'summary'
     AND NOT EXISTS (WITH RECURSIVE m(roleid) AS (SELECT oid FROM pg_roles WHERE rolname IN (session_user::text, current_setting('role'))
                                                  UNION
                                                  SELECT am.roleid FROM pg_auth_members am JOIN m ON am.member = m.roleid)
                     SELECT 1 FROM m JOIN pg_roles r ON r.oid = m.roleid JOIN karidns_auth.audit_restricted_roles x ON x.role_name = r.rolname)
$$;

-- keys of a JSON object whose value is not null become "<redacted>"
CREATE OR REPLACE FUNCTION karidns_auth.audit_redact(j jsonb, keys text[]) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE k text;
BEGIN
  IF j IS NULL THEN RETURN NULL; END IF;
  FOREACH k IN ARRAY keys LOOP
    IF j ? k AND jsonb_typeof(j -> k) <> 'null' THEN j := jsonb_set(j, ARRAY[k], '"<redacted>"'::jsonb); END IF;
  END LOOP;
  RETURN j;
END $$;

-- AFTER INSERT / UPDATE / DELETE ... FOR EACH ROW on the tables enable_audit() names
CREATE OR REPLACE FUNCTION karidns_auth.audit_row() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  sch  text := TG_TABLE_SCHEMA;
  tbl  text := TG_TABLE_NAME;
  jo   jsonb;
  jn   jsonb;
  jr   jsonb;
  zone text;
  did  bigint;
  pid  bigint;
  pname text;
BEGIN
  IF sch <> 'karidns_auth' AND karidns_auth.audit_summary() THEN RETURN NULL; END IF;       -- audit_stmt() writes the summary row
  IF TG_OP <> 'INSERT' THEN jo := to_jsonb(OLD); END IF;
  IF TG_OP <> 'DELETE' THEN jn := to_jsonb(NEW); END IF;
  jr := coalesce(jn, jo);
  IF sch = 'karidns_auth' THEN
    IF tbl = 'credentials' THEN
      jo := karidns_auth.audit_redact(jo, ARRAY['password_hash', 'totp_secret']);
      jn := karidns_auth.audit_redact(jn, ARRAY['password_hash', 'totp_secret']);
    END IF;
    IF tbl = 'grants' THEN zone := jr ->> 'zone_name'; END IF;
  ELSE
    IF tbl = 'cryptokeys' THEN
      jo := karidns_auth.audit_redact(jo, ARRAY['content']);
      jn := karidns_auth.audit_redact(jn, ARRAY['content']);
    END IF;
    IF tbl = 'domains' THEN
      zone := lower(jr ->> 'name');
    ELSIF jr ? 'domain_id' THEN
      did := (jr ->> 'domain_id')::bigint;
      EXECUTE format('SELECT lower(name) FROM %I.domains WHERE id = $1', sch) INTO zone USING did;
    ELSIF jr ? 'record_id' THEN
      EXECUTE format('SELECT lower(d.name), d.id FROM %1$I.records r JOIN %1$I.domains d ON d.id = r.domain_id WHERE r.id = $1', sch)
        INTO zone, did USING (jr ->> 'record_id')::bigint;
    END IF;
    IF zone IS NULL AND did IS NOT NULL THEN                -- the zone is being deleted: karidns_audit_zone remembered its name
      zone := current_setting('karidns.zc_' || substr(md5(sch), 1, 8) || '_' || did, true);
    END IF;
  END IF;
  pid := NULLIF(current_setting('karidns.principal', true), '')::bigint;
  IF pid IS NOT NULL THEN SELECT p.name INTO pname FROM karidns_auth.principals p WHERE p.id = pid; END IF;
  INSERT INTO karidns_auth.audit_log (db_role, principal_id, principal_name, change_set, data_schema, table_name, op, zone_name, row_id, before, after)
    VALUES (karidns_auth.audit_caller(), pid, pname, NULLIF(current_setting('karidns.change_set', true), ''), sch, tbl, left(TG_OP, 1),
            NULLIF(zone, ''), coalesce(jr ->> 'id', jr ->> 'record_id')::bigint, jo, jn);
  RETURN NULL;
END $$;

-- AFTER INSERT / UPDATE / DELETE ... FOR EACH STATEMENT with transition tables: in summary mode the statement is added to the summary row
-- of its transaction, table, operation and zone
CREATE OR REPLACE FUNCTION karidns_auth.audit_stmt() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  sch  text := TG_TABLE_SCHEMA;
  tbl  text := TG_TABLE_NAME;
  src  text := CASE WHEN TG_OP = 'DELETE' THEN 'old_rows' ELSE 'new_rows' END;
  q    text;
  n    bigint;
  nz   bigint;
  did  bigint;
  zone text;
  pid  bigint;
  pname text;
  j    jsonb;
BEGIN
  IF NOT karidns_auth.audit_summary() THEN RETURN NULL; END IF;
  IF tbl = 'domains' THEN
    q := format('SELECT count(*), count(DISTINCT lower(t.name)), min(lower(t.name)), NULL::bigint FROM %s t', src);
  ELSIF tbl IN ('karidns_record_tags', 'karidns_record_tinydns') THEN
    -- the records of a zone or a record that is being deleted are gone when their tags go: no zone (the record's own row has it)
    q := format('SELECT count(*), count(DISTINCT d.id), min(lower(d.name)), NULL::bigint FROM %s t LEFT JOIN %I.records r ON r.id = t.record_id '
                'LEFT JOIN %I.domains d ON d.id = r.domain_id', src, sch, sch);
  ELSE
    q := format('SELECT count(*), count(DISTINCT t.domain_id), min(lower(d.name)), min(t.domain_id) FROM %s t LEFT JOIN %I.domains d ON d.id = t.domain_id', src, sch);
  END IF;
  EXECUTE q INTO n, nz, zone, did;
  IF n = 0 THEN RETURN NULL; END IF;                       -- a statement that changed no row is not logged
  IF nz <> 1 THEN zone := NULL; END IF;                    -- several zones (or a zone already gone): the row names none
  IF zone IS NULL AND nz = 1 AND did IS NOT NULL THEN      -- the zone is being deleted: karidns_audit_zone remembered its name
    zone := current_setting('karidns.zc_' || substr(md5(sch), 1, 8) || '_' || did, true);
  END IF;
  j := jsonb_build_object('summary', true, 'statements', 1, 'rows', n);
  pid := NULLIF(current_setting('karidns.principal', true), '')::bigint;
  IF pid IS NOT NULL THEN SELECT p.name INTO pname FROM karidns_auth.principals p WHERE p.id = pid; END IF;
  INSERT INTO karidns_auth.audit_log AS a (db_role, principal_id, principal_name, change_set, data_schema, table_name, op, zone_name, row_id, before, after)
    VALUES (karidns_auth.audit_caller(), pid, pname, NULLIF(current_setting('karidns.change_set', true), ''), sch, tbl, left(TG_OP, 1),
            NULLIF(zone, ''), NULL, CASE WHEN TG_OP <> 'INSERT' THEN j END, CASE WHEN TG_OP <> 'DELETE' THEN j END)
    ON CONFLICT (xid, data_schema, table_name, op, (coalesce(zone_name, ''))) WHERE ((coalesce(after, before) ->> 'summary') = 'true')
    DO UPDATE SET before = CASE WHEN a.before IS NOT NULL THEN jsonb_build_object('summary', true, 'statements', (a.before ->> 'statements')::bigint + 1,
                                                                                      'rows', (a.before ->> 'rows')::bigint + n) END,
                  after  = CASE WHEN a.after IS NOT NULL THEN jsonb_build_object('summary', true, 'statements', (a.after ->> 'statements')::bigint + 1,
                                                                                    'rows', (a.after ->> 'rows')::bigint + n) END;
  RETURN NULL;
END $$;

-- BEFORE DELETE on domains: remember the name for the rows of the zone that the cascade deletes next (the domains row is gone by then).
-- The name is kept in a transaction-local setting karidns.zc_<hash of the schema>_<domain id> (one per deleted zone; it goes away with the
-- transaction).  Rows of karidns_record_tags / karidns_record_tinydns that go with their record (the cascade of a zone delete, or a DELETE of
-- the record) are logged with zone_name NULL: the record is gone by then and the rows only know the record id.  The D row of the record has
-- the zone, and its row_id is the record_id of those rows.
CREATE OR REPLACE FUNCTION karidns_auth.audit_zone_fn() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM set_config('karidns.zc_' || substr(md5(TG_TABLE_SCHEMA), 1, 8) || '_' || OLD.id, lower(OLD.name), true);
  RETURN OLD;
END $$;

-- switch the audit on / off for the PowerDNS and karidns_* tables of a schema (or for karidns_auth itself); the tables that do not exist are
-- skipped.  The owner of the tables runs it.  Returns the number of tables it attached the audit to / took it off.
CREATE OR REPLACE FUNCTION karidns_auth.enable_audit(sch text) RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t   text;
  cnt integer := 0;
BEGIN
  FOREACH t IN ARRAY (CASE WHEN sch = 'karidns_auth' THEN ARRAY['principals', 'credentials', 'memberships', 'rr_policies', 'grants']
                           ELSE ARRAY['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_record_tags', 'karidns_record_tinydns',
                                      'karidns_zone_tagdefs', 'karidns_domain_views'] END) LOOP
    IF to_regclass(format('%I.%I', sch, t)) IS NULL THEN CONTINUE; END IF;
    EXECUTE format('DROP TRIGGER IF EXISTS karidns_audit_row ON %I.%I', sch, t);
    EXECUTE format('CREATE TRIGGER karidns_audit_row AFTER INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION karidns_auth.audit_row()', sch, t);
    IF sch <> 'karidns_auth' THEN
      EXECUTE format('DROP TRIGGER IF EXISTS karidns_audit_ins ON %I.%I', sch, t);
      EXECUTE format('DROP TRIGGER IF EXISTS karidns_audit_upd ON %I.%I', sch, t);
      EXECUTE format('DROP TRIGGER IF EXISTS karidns_audit_del ON %I.%I', sch, t);
      EXECUTE format('CREATE TRIGGER karidns_audit_ins AFTER INSERT ON %I.%I REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_auth.audit_stmt()', sch, t);
      EXECUTE format('CREATE TRIGGER karidns_audit_upd AFTER UPDATE ON %I.%I REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_auth.audit_stmt()', sch, t);
      EXECUTE format('CREATE TRIGGER karidns_audit_del AFTER DELETE ON %I.%I REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_auth.audit_stmt()', sch, t);
    END IF;
    IF t = 'domains' AND sch <> 'karidns_auth' THEN
      EXECUTE format('DROP TRIGGER IF EXISTS karidns_audit_zone ON %I.%I', sch, t);
      EXECUTE format('CREATE TRIGGER karidns_audit_zone BEFORE DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION karidns_auth.audit_zone_fn()', sch, t);
    END IF;
    cnt := cnt + 1;
  END LOOP;
  RETURN cnt;
END $$;

CREATE OR REPLACE FUNCTION karidns_auth.disable_audit(sch text) RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t   text;
  tg  text;
  cnt integer := 0;
BEGIN
  FOREACH t IN ARRAY (CASE WHEN sch = 'karidns_auth' THEN ARRAY['principals', 'credentials', 'memberships', 'rr_policies', 'grants']
                           ELSE ARRAY['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_record_tags', 'karidns_record_tinydns',
                                      'karidns_zone_tagdefs', 'karidns_domain_views'] END) LOOP
    IF to_regclass(format('%I.%I', sch, t)) IS NULL THEN CONTINUE; END IF;
    FOREACH tg IN ARRAY ARRAY['karidns_audit_row', 'karidns_audit_ins', 'karidns_audit_upd', 'karidns_audit_del', 'karidns_audit_zone'] LOOP
      EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I.%I', tg, sch, t);
    END LOOP;
    cnt := cnt + 1;
  END LOOP;
  RETURN cnt;
END $$;

-- the tables of karidns_auth are audited from the start (they only change when the WebAdmin is in use)
DO $$ BEGIN PERFORM karidns_auth.enable_audit('karidns_auth'); END $$;


-- The trigger functions and the audit switches are not for anybody to call or to attach to a table of their own: EXECUTE is for the owner only
-- (a trigger function needs no EXECUTE right of the role whose statement fires the trigger; CREATE TRIGGER does).  is_canonical_name and
-- rr_types_ok stay with PUBLIC: CHECK constraints call them as the role that inserts the row.
REVOKE EXECUTE ON FUNCTION karidns_auth.credentials_user_only_fn(), karidns_auth.principals_kind_fn(), karidns_auth.principals_self_fn(),
  karidns_auth.principals_delete_fn(), karidns_auth.memberships_check_fn(), karidns_auth.memberships_closure_fn(), karidns_auth.domains_grants_fn(),
  karidns_auth.audit_row(), karidns_auth.audit_stmt(), karidns_auth.audit_zone_fn(), karidns_auth.audit_summary(),
  karidns_auth.enable_audit(text), karidns_auth.disable_audit(text) FROM PUBLIC;

-- the versions, last: a fresh install whose karidns_auth part fails stays version 2 (a version 1 database is not touched: it needs
-- db/karidns_ext_v1_to_v2.pgsql.sql first)
INSERT INTO karidns_auth.schema_version (version) SELECT 3 WHERE NOT EXISTS (SELECT 1 FROM karidns_auth.schema_version);
UPDATE karidns_auth.schema_version SET version = 3 WHERE version < 3;
UPDATE karidns_schema_version SET version = 3 WHERE version = 2;

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
-- The role scripts of the WebAdmin and the signer (db/karidns_api_role.pgsql.sql, db/karidns_signer_role.pgsql.sql) switch them on; a site without
-- them has no audit rows and no RLS.  The functions and the policies of the RLS (milestone M2) are created below, inactive until then.
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


-- ---------------------------------------------------------------------------------------------------------------------------------
-- Row level security (0.6.0 item B, milestone M2).  This file creates the functions and the policies; RLS stays OFF on every table until the role
-- script of the WebAdmin API (db/karidns_api_role.pgsql.sql) or of the signer (db/karidns_signer_role.pgsql.sql) calls karidns_auth.enable_rls(schema),
-- so a site without them changes nothing.  How the rules work (docs/karidns-dbloader.md, "Roles and row level security"):
--   * The policies without a TO clause apply to every role that is not a member of karidns_rls_trusted (a NOLOGIN role the role scripts create).
--     A role that must not be bound by them (the loader, karidns-zone, the PowerDNS gpgsql role) is a member of karidns_rls_trusted, whose own
--     policy is USING (true) WITH CHECK (true).  The table owner is not subject to RLS (no FORCE).
--   * The acting user is the setting karidns.principal (SET LOCAL karidns.principal = '42' in every transaction of the API).  It is a custom
--     setting any session can set: the API is trusted to set it to the logged-in user, RLS catches the API's own mistakes (a missing WHERE, a wrong
--     zone id), not a compromised API process.  A missing, empty or non-numeric setting, a principal that does not exist and a disabled
--     principal are all "no principal": no rows, no writes.
--   * The effective grants of a principal are the grants of the principal and of every group it is in, directly or through groups (principal_closure);
--     a grant given to a disabled group does not count (a disabled group in the middle of a chain does not cut the chain).
--   * rr_ok() asks for ONE effective grant that covers a record: two grants that each allow half of a record do not combine.
--   * The signer's own policies are PERMISSIVE like the API's, so they would be OR-ed with them (a signer that sets karidns.principal to a global
--     master would pass the API policies): the signer therefore also gets RESTRICTIVE policies, which every write must pass as well.
-- The functions are SECURITY DEFINER (they read karidns_auth, which the caller may only see through its policies), STABLE, with a pinned search_path,
-- owned by the owner that applies this file; EXECUTE is revoked from PUBLIC and granted by the role scripts.
--
-- Type names.  The special record types are compared through karidns_auth.canon_type(): upper case, trimmed, and the generic forms TYPE2, TYPE06,
-- TYPE0039 ... of NS (2), SOA (6), DNAME (39) and the DNSSEC-managed types (46 RRSIG, 47 NSEC, 48 DNSKEY, 50 NSEC3, 51 NSEC3PARAM, 59 CDS, 60 CDNSKEY)
-- are read as the named type, so an alias gets exactly the rules of the name.  Any other TYPEnn is its own type (a policy may list it, as TYPE65280;
-- an rr_policy may not list the aliases of the special types: rr_types_ok).

-- the roles whose sessions are the WebAdmin API / the signer (a member of one of them, directly or through any chain, counts): the trigger on grants
-- binds the first, the trigger on records (SOA rows) the second
CREATE TABLE IF NOT EXISTS karidns_auth.api_roles (role_name name PRIMARY KEY);
INSERT INTO karidns_auth.api_roles (role_name) VALUES ('karidns_api') ON CONFLICT DO NOTHING;
REVOKE ALL ON karidns_auth.api_roles FROM PUBLIC;
CREATE TABLE IF NOT EXISTS karidns_auth.signer_roles (role_name name PRIMARY KEY);
INSERT INTO karidns_auth.signer_roles (role_name) VALUES ('karidns_signer') ON CONFLICT DO NOTHING;
REVOKE ALL ON karidns_auth.signer_roles FROM PUBLIC;

-- the type, upper case and trimmed, with the generic form of NS, SOA, DNAME and the DNSSEC-managed types read as the name; NULL stays NULL
CREATE OR REPLACE FUNCTION karidns_auth.canon_type(t text) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN u ~ '^TYPE0*[0-9]{1,5}$' THEN
           CASE substring(u from '^TYPE0*([0-9]{1,5})$')::integer
             WHEN 2 THEN 'NS' WHEN 6 THEN 'SOA' WHEN 39 THEN 'DNAME' WHEN 46 THEN 'RRSIG' WHEN 47 THEN 'NSEC' WHEN 48 THEN 'DNSKEY'
             WHEN 50 THEN 'NSEC3' WHEN 51 THEN 'NSEC3PARAM' WHEN 59 THEN 'CDS' WHEN 60 THEN 'CDNSKEY' ELSE u END
         ELSE u END
    FROM (SELECT upper(btrim(t)) AS u) x
$$;

-- a DNSSEC-managed type (the signer's), also as TYPE46, TYPE0047, ...; false for NULL.  (Self-contained: the signer calls it from its policies and has no USAGE on karidns_auth,
-- and a SQL function that names another function of the schema looks it up at run time.  Keep it in step with canon_type.)
CREATE OR REPLACE FUNCTION karidns_auth.is_dnssec_type(t text) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(upper(btrim(t)) IN ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY') OR upper(btrim(t)) ~ '^TYPE0*(46|47|48|50|51|59|60)$', false)
$$;

-- the types of an rr_policy: upper case; none of the types the signer owns and none of the meta types that are not data, and none of the generic forms
-- (TYPE2, TYPE06 ...) of NS, SOA or DNAME or of a DNSSEC-managed type (write the name; the generic form of an ordinary type is a type of its own)
CREATE OR REPLACE FUNCTION karidns_auth.rr_types_ok(t text[]) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
  SELECT t IS NOT NULL AND NOT EXISTS (SELECT 1 FROM unnest(t) AS x
                                        WHERE x IS NULL OR x !~ '^[A-Z][A-Z0-9]*$'
                                           OR x IN ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY',
                                                    'ANY', 'AXFR', 'IXFR', 'OPT', 'TSIG', 'TKEY', 'MAILA', 'MAILB')
                                           OR x ~ '^TYPE0*(2|6|39|46|47|48|50|51|59|60)$')
$$;

-- karidns.principal as a number: NULL for no setting, '' and anything that is not 1 to 18 digits (a non-numeric setting is "no principal", never an error)
CREATE OR REPLACE FUNCTION karidns_auth.setting_principal() RETURNS bigint LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN s ~ '^[0-9]{1,18}$' THEN s::bigint END FROM (SELECT current_setting('karidns.principal', true) AS s) x
$$;

-- the acting principal: NULL unless the setting names an existing principal that is not disabled
CREATE OR REPLACE FUNCTION karidns_auth.current_principal() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT p.id FROM karidns_auth.principals p WHERE p.id = karidns_auth.setting_principal() AND NOT p.disabled
$$;

-- the principal and every group it is in (the ids a grant may be given to for the principal to hold it)
CREATE OR REPLACE FUNCTION karidns_auth.my_groups() RETURNS bigint[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT coalesce(array_agg(c.group_id), '{}'::bigint[]) FROM karidns_auth.principal_closure c WHERE c.member_id = karidns_auth.current_principal()
$$;

-- the strongest effective grant on a zone ('global_master' > 'domain_master' > 'subdomain_master'), NULL when there is none.  A global master has a grant
-- on every zone.  The zone name is compared in lower case, without a trailing dot (as PowerDNS stores it; the policies strip a dot of domains.name).
CREATE OR REPLACE FUNCTION karidns_auth.zone_grant(sch text, zone text) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT g.role
    FROM karidns_auth.principal_closure c
    JOIN karidns_auth.principals gp ON gp.id = c.group_id AND NOT gp.disabled
    JOIN karidns_auth.grants g ON g.principal_id = c.group_id
   WHERE c.member_id = karidns_auth.current_principal()
     AND (g.role = 'global_master' OR (g.data_schema = sch AND g.zone_name = lower(zone)))
   ORDER BY CASE g.role WHEN 'global_master' THEN 0 WHEN 'domain_master' THEN 1 ELSE 2 END
   LIMIT 1
$$;

CREATE OR REPLACE FUNCTION karidns_auth.is_global() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT EXISTS (SELECT 1
                   FROM karidns_auth.principal_closure c
                   JOIN karidns_auth.principals gp ON gp.id = c.group_id AND NOT gp.disabled
                   JOIN karidns_auth.grants g ON g.principal_id = c.group_id
                  WHERE c.member_id = karidns_auth.current_principal() AND g.role = 'global_master')
$$;

-- May the principal WRITE this record?  True when ONE effective grant covers it (4.4 of the design):
--   scope        the name is the zone or ends in '.<zone>' (for every grant); a subdomain master: the name is the suffix or ends in '.<suffix>' (label
--                boundary: evilsub.example.com is not under sub.example.com); a global master: any zone, a domain master: its (schema, zone)
--   rr_policy    the type (canon_type: TYPE2 is NS, TYPE6 is SOA, ...) is allowed and not DNSSEC-managed; the TTL (NULL counts as 0) is in range; a
--                wildcard label (*) needs allow_wildcard; NS below the apex is a delegation (allow_delegation); DNAME needs allow_dname; the apex needs
--                apex_editable and a role other than subdomain master; SOA only for a global master whose policy allows SOA and apex_editable
--                (everybody else: bump_serial())
--   an empty non-terminal (type NULL or '') is a bare name: it needs the scope, never the apex, and the wildcard rule; type and TTL do not matter
-- A NULL or empty zone or name is never writable (the row is not inside any zone).  The name is compared as lower(records.name).
CREATE OR REPLACE FUNCTION karidns_auth.rr_ok(sch text, zone text, nm text, typ text, p_ttl integer) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT CASE WHEN zone IS NULL OR zone = '' OR nm IS NULL OR nm = '' THEN false ELSE EXISTS (
    SELECT 1
      FROM (SELECT lower(nm) AS n, lower(zone) AS z, nullif(karidns_auth.canon_type(typ), '') AS t) x,
           karidns_auth.principal_closure c
      JOIN karidns_auth.principals gp ON gp.id = c.group_id AND NOT gp.disabled
      JOIN karidns_auth.grants g ON g.principal_id = c.group_id
      JOIN karidns_auth.rr_policies p ON p.id = g.rr_policy_id
     WHERE c.member_id = karidns_auth.current_principal()
       AND (x.n = x.z OR right(x.n, length(x.z) + 1) = '.' || x.z)
       AND (g.role = 'global_master'
            OR (g.data_schema = sch AND g.zone_name = x.z
                AND (g.role = 'domain_master' OR x.n = g.name_suffix OR right(x.n, length(g.name_suffix) + 1) = '.' || g.name_suffix)))
       AND (x.n !~ '(^|[.])[*]([.]|$)' OR p.allow_wildcard)
       AND CASE WHEN x.t IS NULL THEN x.n <> x.z
                ELSE x.t = ANY (p.allowed_types)
                     AND NOT karidns_auth.is_dnssec_type(x.t)
                     AND coalesce(p_ttl, 0) BETWEEN p.ttl_min AND p.ttl_max
                     AND (x.t <> 'NS' OR x.n = x.z OR p.allow_delegation)
                     AND (x.t <> 'DNAME' OR p.allow_dname)
                     AND (x.n <> x.z OR (p.apex_editable AND g.role <> 'subdomain_master'))
                     AND (x.t <> 'SOA' OR (x.n = x.z AND g.role = 'global_master' AND p.apex_editable))
           END) END
$$;

-- May the principal READ this record?  The name must be inside the zone for every grant (a row without a name, a row without a zone and a row whose name
-- is outside its zone are invisible to the API, a global master included: the owner repairs them).  Then: a global master sees every such row; a domain
-- master the rows of its (schema, zone); a subdomain master the rows of its suffix; the SOA and the apex NS are visible to every grant on the zone.
-- An empty non-terminal (type NULL) is visible by its name alone.
CREATE OR REPLACE FUNCTION karidns_auth.rr_visible(sch text, zone text, nm text, typ text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT coalesce(zone <> '' AND nm <> '' AND (lower(nm) = lower(zone) OR right(lower(nm), length(zone) + 1) = '.' || lower(zone)), false) AND EXISTS (
    SELECT 1
      FROM karidns_auth.principal_closure c
      JOIN karidns_auth.principals gp ON gp.id = c.group_id AND NOT gp.disabled
      JOIN karidns_auth.grants g ON g.principal_id = c.group_id
     WHERE c.member_id = karidns_auth.current_principal()
       AND (g.role = 'global_master'
            OR (g.data_schema = sch AND g.zone_name = lower(zone)
                AND (g.role = 'domain_master'
                     OR lower(nm) = g.name_suffix OR right(lower(nm), length(g.name_suffix) + 1) = '.' || g.name_suffix
                     OR (lower(nm) = lower(zone) AND karidns_auth.canon_type(typ) IN ('SOA', 'NS')))))
  )
$$;

-- an audit_log row is visible to a global master, and to a domain master of the row's zone (the rows about grants name the data schema in the JSON)
CREATE OR REPLACE FUNCTION karidns_auth.audit_visible(ds text, zone text, tbl text, b jsonb, a jsonb) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT karidns_auth.is_global()
         OR (zone IS NOT NULL
             AND karidns_auth.zone_grant(CASE WHEN ds = 'karidns_auth' AND tbl = 'grants' THEN coalesce(a, b) ->> 'data_schema' ELSE ds END, zone) = 'domain_master')
$$;

-- bump_serial(schema, domain id): add 1 to the serial of the SOA of the zone (RFC 1982: 4294967295 + 1 = 0).  Any effective grant on the zone may do it
-- (the SOA is otherwise not writable by the API); the update is audited as an UPDATE of records by the principal.  Returns the new serial.
CREATE OR REPLACE FUNCTION karidns_auth.bump_serial(sch text, did integer) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  zone text;
  rec  record;
  m    text[];
  ser  bigint;
  nser bigint;
  n    integer := 0;
BEGIN
  IF karidns_auth.current_principal() IS NULL THEN
    RAISE EXCEPTION 'karidns_auth.bump_serial: no valid karidns.principal' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF sch IS NULL OR to_regclass(format('%I.domains', sch)) IS NULL OR to_regclass(format('%I.records', sch)) IS NULL
     OR to_regclass(format('%I.karidns_schema_version', sch)) IS NULL THEN
    RAISE EXCEPTION 'karidns_auth.bump_serial: % is not a KariDNS data schema', sch USING ERRCODE = 'invalid_schema_name';
  END IF;
  EXECUTE format('SELECT lower(regexp_replace(name, ''[.]$'', '''')) FROM %I.domains WHERE id = $1', sch) INTO zone USING did;
  IF zone IS NULL OR karidns_auth.zone_grant(sch, zone) IS NULL THEN
    RAISE EXCEPTION 'karidns_auth.bump_serial: no grant on zone % of schema %', did, sch USING ERRCODE = 'insufficient_privilege';
  END IF;
  FOR rec IN EXECUTE format('SELECT id, content FROM %I.records WHERE domain_id = $1 AND lower(name) = $2 AND karidns_auth.canon_type(type) = ''SOA'' ORDER BY id FOR UPDATE', sch) USING did, zone LOOP
    m := regexp_match(rec.content, '^(\s*\S+\s+\S+\s+)([0-9]{1,10})(\s.*)?$');
    IF m IS NULL OR m[2]::bigint > 4294967295 THEN
      RAISE EXCEPTION 'karidns_auth.bump_serial: the SOA of zone % has no serial that can be incremented', zone USING ERRCODE = 'data_exception';
    END IF;
    ser := m[2]::bigint;
    nser := (ser + 1) % 4294967296;
    EXECUTE format('UPDATE %I.records SET content = $1 WHERE id = $2', sch) USING m[1] || nser::text || coalesce(m[3], ''), rec.id;
    n := n + 1;
  END LOOP;
  IF n = 0 THEN
    RAISE EXCEPTION 'karidns_auth.bump_serial: zone % has no SOA record', zone USING ERRCODE = 'no_data_found';
  END IF;
  RETURN nser;
END $$;

-- ---- no escalation (4.7): a BEFORE trigger on grants for the sessions of the API roles (karidns_auth.api_roles); every other role is the operator
-- Is the session one of the API roles, or a member of one (the login role AND the SET ROLE role are looked at, as audit_summary() does)?
CREATE OR REPLACE FUNCTION karidns_auth.is_api_caller() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT EXISTS (WITH RECURSIVE m(roleid) AS (SELECT oid FROM pg_roles WHERE rolname IN (session_user::text, current_setting('role'))
                                              UNION
                                              SELECT am.roleid FROM pg_auth_members am JOIN m ON am.member = m.roleid)
                 SELECT 1 FROM m JOIN pg_roles r ON r.oid = m.roleid JOIN karidns_auth.api_roles x ON x.role_name = r.rolname)
$$;

-- the same for the signer roles (the trigger on SOA rows)
CREATE OR REPLACE FUNCTION karidns_auth.is_signer_caller() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT EXISTS (WITH RECURSIVE m(roleid) AS (SELECT oid FROM pg_roles WHERE rolname IN (session_user::text, current_setting('role'))
                                              UNION
                                              SELECT am.roleid FROM pg_auth_members am JOIN m ON am.member = m.roleid)
                 SELECT 1 FROM m JOIN pg_roles r ON r.oid = m.roleid JOIN karidns_auth.signer_roles x ON x.role_name = r.rolname)
$$;

-- is policy `sub` no wider than policy `sup`?  (types a subset, each flag not more, ttl_min not lower, ttl_max not higher, max_rr not higher; NULL = no limit)
CREATE OR REPLACE FUNCTION karidns_auth.policy_subset(sub bigint, sup bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT coalesce((SELECT a.allowed_types <@ b.allowed_types
                          AND (NOT a.allow_wildcard OR b.allow_wildcard)
                          AND (NOT a.allow_delegation OR b.allow_delegation)
                          AND (NOT a.allow_dname OR b.allow_dname)
                          AND (NOT a.apex_editable OR b.apex_editable)
                          AND a.ttl_min >= b.ttl_min AND a.ttl_max <= b.ttl_max
                          AND (b.max_rr IS NULL OR (a.max_rr IS NOT NULL AND a.max_rr <= b.max_rr))
                     FROM karidns_auth.rr_policies a, karidns_auth.rr_policies b WHERE a.id = sub AND b.id = sup), false)
$$;

-- may the principal (not a global master) make, change or remove a grant of this shape?  It must be a domain master of the same (schema, zone) with a
-- policy at least as wide, and the grant must be a domain_master or subdomain_master one.  A subdomain master therefore never grants.
CREATE OR REPLACE FUNCTION karidns_auth.may_grant(r text, ds text, zone text, pol bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
  SELECT r IN ('domain_master', 'subdomain_master') AND ds IS NOT NULL AND zone IS NOT NULL
         AND EXISTS (SELECT 1
                       FROM karidns_auth.principal_closure c
                       JOIN karidns_auth.principals gp ON gp.id = c.group_id AND NOT gp.disabled
                       JOIN karidns_auth.grants g ON g.principal_id = c.group_id
                      WHERE c.member_id = karidns_auth.current_principal() AND g.role = 'domain_master' AND g.data_schema = ds AND g.zone_name = zone
                        AND karidns_auth.policy_subset(pol, g.rr_policy_id))
$$;

-- granted_by and granted_at are the trigger's: an INSERT sets them (what the caller sent is replaced); an UPDATE keeps the old values unless the
-- grant changes materially (principal, role or rr_policy; and, for a statement of the session itself, the data schema, zone or suffix: a rename that
-- follows a renamed zone, made by the trigger on domains one level down, is not a new grant)
CREATE OR REPLACE FUNCTION karidns_auth.grants_escalation_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  me bigint;
BEGIN
  IF NOT karidns_auth.is_api_caller() THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;                  -- the operator: anything
  END IF;
  me := karidns_auth.current_principal();
  IF me IS NULL THEN
    RAISE EXCEPTION 'karidns_auth.grants: no valid karidns.principal' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT karidns_auth.is_global() THEN                                         -- a global master may do anything
    IF TG_OP IN ('UPDATE', 'DELETE') AND NOT karidns_auth.may_grant(OLD.role, OLD.data_schema, OLD.zone_name, OLD.rr_policy_id) THEN
      RAISE EXCEPTION 'karidns_auth.grants: grant % is not one that principal % may change or remove (escalation)', OLD.id, me USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') AND NOT karidns_auth.may_grant(NEW.role, NEW.data_schema, NEW.zone_name, NEW.rr_policy_id) THEN
      RAISE EXCEPTION 'karidns_auth.grants: principal % may not make this grant (it needs a domain master grant of the same zone with a wider rr_policy: escalation)', me USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  IF TG_OP = 'INSERT'
     OR (NEW.principal_id, NEW.role, NEW.rr_policy_id) IS DISTINCT FROM (OLD.principal_id, OLD.role, OLD.rr_policy_id)
     OR (pg_trigger_depth() = 1 AND (NEW.data_schema, NEW.zone_name, NEW.name_suffix) IS DISTINCT FROM (OLD.data_schema, OLD.zone_name, OLD.name_suffix)) THEN
    NEW.granted_by := me;
    NEW.granted_at := now();
  ELSE
    NEW.granted_by := OLD.granted_by;
    NEW.granted_at := OLD.granted_at;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS karidns_grants_escalation ON karidns_auth.grants;
CREATE TRIGGER karidns_grants_escalation BEFORE INSERT OR UPDATE OR DELETE ON karidns_auth.grants
  FOR EACH ROW EXECUTE FUNCTION karidns_auth.grants_escalation_fn();

-- ---- the signer and the SOA: for the sessions of the signer roles (karidns_auth.signer_roles), a BEFORE trigger on the records of this schema lets an
-- SOA row change in its serial only: it keeps its type, name and domain_id, the rest of its content is the same, a record cannot become an SOA (nor
-- an SOA another type), and the signer cannot insert or delete an SOA.  (The policies of the signer allow UPDATE of SOA rows; a policy cannot look at
-- columns.)  The trigger fires only for rows that are, or become, an SOA.
CREATE OR REPLACE FUNCTION karidns_auth.signer_soa_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, karidns_auth, pg_temp AS $$
DECLARE
  mo  text[];
  mn  text[];
  pat constant text := '^(\s*\S+\s+\S+\s+)([0-9]{1,10})(\s.*)?$';
BEGIN
  IF NOT karidns_auth.is_signer_caller() THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  IF TG_OP = 'INSERT' THEN
    RAISE EXCEPTION 'karidns_auth.signer: the signer cannot insert an SOA record' USING ERRCODE = 'insufficient_privilege';
  ELSIF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'karidns_auth.signer: the signer cannot delete an SOA record' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF karidns_auth.canon_type(OLD.type) IS DISTINCT FROM 'SOA' THEN
    RAISE EXCEPTION 'karidns_auth.signer: a record cannot become an SOA record' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF karidns_auth.canon_type(NEW.type) IS DISTINCT FROM 'SOA' THEN
    RAISE EXCEPTION 'karidns_auth.signer: an SOA record cannot become another type' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.type IS DISTINCT FROM OLD.type OR NEW.name IS DISTINCT FROM OLD.name OR NEW.domain_id IS DISTINCT FROM OLD.domain_id THEN
    RAISE EXCEPTION 'karidns_auth.signer: an SOA record keeps its type, name and domain_id' USING ERRCODE = 'insufficient_privilege';
  END IF;
  mo := regexp_match(OLD.content, pat);
  mn := regexp_match(NEW.content, pat);
  IF mo IS NULL OR mn IS NULL OR mo[1] <> mn[1] OR coalesce(mo[3], '') <> coalesce(mn[3], '') THEN
    RAISE EXCEPTION 'karidns_auth.signer: the signer may change only the serial of an SOA record' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS karidns_signer_soa_ins ON records;
DROP TRIGGER IF EXISTS karidns_signer_soa_upd ON records;
DROP TRIGGER IF EXISTS karidns_signer_soa_del ON records;
CREATE TRIGGER karidns_signer_soa_ins BEFORE INSERT ON records FOR EACH ROW WHEN (karidns_auth.canon_type(NEW.type) = 'SOA')
  EXECUTE FUNCTION karidns_auth.signer_soa_fn();
CREATE TRIGGER karidns_signer_soa_upd BEFORE UPDATE ON records FOR EACH ROW WHEN (karidns_auth.canon_type(OLD.type) = 'SOA' OR karidns_auth.canon_type(NEW.type) = 'SOA')
  EXECUTE FUNCTION karidns_auth.signer_soa_fn();
CREATE TRIGGER karidns_signer_soa_del BEFORE DELETE ON records FOR EACH ROW WHEN (karidns_auth.canon_type(OLD.type) = 'SOA')
  EXECUTE FUNCTION karidns_auth.signer_soa_fn();

-- ---- the role scripts of the API and the signer call this first: the role must be one that RLS binds.  It is refused when it is a superuser or has
-- BYPASSRLS, when it is (directly or through other roles) a member of karidns_rls_trusted, or when it is, or is a member of, the owner of the tables
CREATE OR REPLACE FUNCTION karidns_auth.assert_service_role(sch text, rol text) RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r   pg_roles%ROWTYPE;
  own oid;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE rolname = rol;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'karidns_auth.assert_service_role: role % does not exist', rol;
  END IF;
  IF r.rolsuper OR r.rolbypassrls THEN
    RAISE EXCEPTION 'karidns_auth.assert_service_role: role % is a superuser or has BYPASSRLS: row level security would not bind it', rol USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT c.relowner INTO own FROM pg_class c WHERE c.oid = to_regclass(format('%I.records', sch));
  IF own IS NULL THEN
    RAISE EXCEPTION 'karidns_auth.assert_service_role: schema % has no records table', sch;
  END IF;
  IF EXISTS (WITH RECURSIVE m(roleid) AS (SELECT r.oid UNION SELECT am.roleid FROM pg_auth_members am JOIN m ON am.member = m.roleid)
             SELECT 1 FROM m JOIN pg_roles t ON t.oid = m.roleid WHERE t.rolname = 'karidns_rls_trusted') THEN
    RAISE EXCEPTION 'karidns_auth.assert_service_role: role % is a member of karidns_rls_trusted (directly or through another role): row level security would not bind it', rol USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF EXISTS (WITH RECURSIVE m(roleid) AS (SELECT r.oid UNION SELECT am.roleid FROM pg_auth_members am JOIN m ON am.member = m.roleid)
             SELECT 1 FROM m WHERE m.roleid = own) THEN
    RAISE EXCEPTION 'karidns_auth.assert_service_role: role % is, or is a member of, the owner of the tables of schema %: the owner is not bound by row level security', rol, sch USING ERRCODE = 'insufficient_privilege';
  END IF;
END $$;

-- ---- policies.  set_policy replaces one policy; create_policies(schema) creates the policies of a data schema (the schema is a literal in them, so no
-- search_path matters when they run) or, for 'karidns_auth', those of the auth tables.  Both are idempotent.
DROP FUNCTION IF EXISTS karidns_auth.set_policy(regclass, text, text, text, text, text);
CREATE OR REPLACE FUNCTION karidns_auth.set_policy(tbl regclass, pname text, cmd text, using_e text, check_e text, to_role text DEFAULT NULL, restrictive boolean DEFAULT false) RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  EXECUTE format('DROP POLICY IF EXISTS %I ON %s', pname, tbl);
  EXECUTE format('CREATE POLICY %I ON %s AS %s FOR %s%s%s%s', pname, tbl, CASE WHEN restrictive THEN 'RESTRICTIVE' ELSE 'PERMISSIVE' END, cmd,
                 CASE WHEN to_role IS NOT NULL THEN format(' TO %I', to_role) ELSE '' END,
                 CASE WHEN using_e IS NOT NULL THEN ' USING (' || using_e || ')' ELSE '' END,
                 CASE WHEN check_e IS NOT NULL THEN ' WITH CHECK (' || check_e || ')' ELSE '' END);
END $$;

CREATE OR REPLACE FUNCTION karidns_auth.create_policies(sch text) RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cnt  integer := 0;
  lit  text := quote_literal(sch);
  rel  regclass;
  zr   text;       -- the zone name of a row with a domain_id column (a trailing dot of domains.name is stripped); %1$s is the table
  zn   text := $q$lower(regexp_replace(%s, '[.]$', ''))$q$;
  w    text;
  nm   text;
BEGIN
  IF sch = 'karidns_auth' THEN
    -- audit_log: append only for the roles (the owner and the SECURITY DEFINER triggers write it); read by scope
    PERFORM karidns_auth.set_policy('karidns_auth.audit_log', 'karidns_rls_select', 'SELECT',
      'karidns_auth.audit_visible(audit_log.data_schema, audit_log.zone_name, audit_log.table_name, audit_log.before, audit_log.after)', NULL);
    -- grants: own and inherited grants, the grants on zones the principal is domain master of, all for a global master; changes by global master or
    -- the domain master of the zone (the trigger karidns_grants_escalation checks the subset rule)
    w := 'karidns_auth.is_global() OR (grants.zone_name IS NOT NULL AND karidns_auth.zone_grant(grants.data_schema, grants.zone_name) = ''domain_master'')';
    PERFORM karidns_auth.set_policy('karidns_auth.grants', 'karidns_rls_select', 'SELECT',
      'grants.principal_id = ANY (karidns_auth.my_groups()) OR karidns_auth.is_global() OR (grants.zone_name IS NOT NULL AND karidns_auth.zone_grant(grants.data_schema, grants.zone_name) IN (''global_master'', ''domain_master''))', NULL);
    PERFORM karidns_auth.set_policy('karidns_auth.grants', 'karidns_rls_insert', 'INSERT', NULL, w);
    PERFORM karidns_auth.set_policy('karidns_auth.grants', 'karidns_rls_update', 'UPDATE', w, w);
    PERFORM karidns_auth.set_policy('karidns_auth.grants', 'karidns_rls_delete', 'DELETE', w, NULL);
    -- principals, memberships, rr_policies: every row is readable (a login looks the user up by name before it has a principal id; the names are
    -- needed to grant); only a global master changes them
    FOREACH nm IN ARRAY ARRAY['principals', 'memberships', 'rr_policies'] LOOP
      rel := format('karidns_auth.%I', nm)::regclass;
      PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', 'true', NULL);
      PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, 'karidns_auth.is_global()');
      PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', 'karidns_auth.is_global()', 'karidns_auth.is_global()');
      PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', 'karidns_auth.is_global()', NULL);
    END LOOP;
    -- credentials: the principal's own row (the API sets the principal of a login before it reads the credentials), a global master all of them
    w := 'credentials.principal_id = karidns_auth.current_principal() OR karidns_auth.is_global()';
    PERFORM karidns_auth.set_policy('karidns_auth.credentials', 'karidns_rls_select', 'SELECT', w, NULL);
    PERFORM karidns_auth.set_policy('karidns_auth.credentials', 'karidns_rls_insert', 'INSERT', NULL, 'karidns_auth.is_global()');
    PERFORM karidns_auth.set_policy('karidns_auth.credentials', 'karidns_rls_update', 'UPDATE', w, w);
    PERFORM karidns_auth.set_policy('karidns_auth.credentials', 'karidns_rls_delete', 'DELETE', 'karidns_auth.is_global()', NULL);
    RETURN 6;
  END IF;

  -- ---- a data schema
  zr := format('(SELECT %s FROM %I.domains d WHERE d.id = %%1$s.domain_id)', format(zn, 'd.name'), sch);
  -- domains
  IF to_regclass(format('%I.domains', sch)) IS NOT NULL THEN
    rel := format('%I.domains', sch)::regclass;
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('karidns_auth.zone_grant(%s, %s) IS NOT NULL', lit, format(zn, 'domains.name')), NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, 'karidns_auth.is_global()');
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', 'karidns_auth.is_global()', 'karidns_auth.is_global()');
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', 'karidns_auth.is_global()', NULL);
    cnt := cnt + 1;
  END IF;
  -- records
  IF to_regclass(format('%I.records', sch)) IS NOT NULL THEN
    rel := format('%I.records', sch)::regclass;
    w := format('karidns_auth.rr_ok(%s, %s, records.name, records.type, records.ttl)', lit, format(zr, 'records'));
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('karidns_auth.rr_visible(%s, %s, records.name, records.type)', lit, format(zr, 'records')), NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', w, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', w, NULL);
    cnt := cnt + 1;
  END IF;
  -- domainmetadata: a grant on the zone reads; a global master writes every kind but the ones the signer owns
  IF to_regclass(format('%I.domainmetadata', sch)) IS NOT NULL THEN
    rel := format('%I.domainmetadata', sch)::regclass;
    w := 'karidns_auth.is_global() AND upper(btrim(domainmetadata.kind)) NOT IN (''PRESIGNED'', ''NSEC3PARAM'', ''X-KARIDNS-SIGNER'')';
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('karidns_auth.zone_grant(%s, %s) IS NOT NULL', lit, format(zr, 'domainmetadata')), NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', w, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', w, NULL);
    cnt := cnt + 1;
  END IF;
  -- the tag tables of a record: readable when the record is (the records policy filters the subquery), writable when the record is
  FOREACH nm IN ARRAY ARRAY['karidns_record_tags', 'karidns_record_tinydns'] LOOP
    IF to_regclass(format('%I.%I', sch, nm)) IS NULL THEN CONTINUE; END IF;
    rel := format('%I.%I', sch, nm)::regclass;
    w := format('EXISTS (SELECT 1 FROM %1$I.records r JOIN %1$I.domains d ON d.id = r.domain_id WHERE r.id = %2$I.record_id AND karidns_auth.rr_ok(%3$s, %4$s, r.name, r.type, r.ttl))', sch, nm, lit, format(zn, 'd.name'));
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('EXISTS (SELECT 1 FROM %I.records r WHERE r.id = %I.record_id)', sch, nm), NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', w, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', w, NULL);
    cnt := cnt + 1;
  END LOOP;
  -- karidns_zone_tagdefs: a domain master (or global) writes
  IF to_regclass(format('%I.karidns_zone_tagdefs', sch)) IS NOT NULL THEN
    rel := format('%I.karidns_zone_tagdefs', sch)::regclass;
    w := format('karidns_auth.zone_grant(%s, %s) IN (''global_master'', ''domain_master'')', lit, format(zr, 'karidns_zone_tagdefs'));
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('karidns_auth.zone_grant(%s, %s) IS NOT NULL', lit, format(zr, 'karidns_zone_tagdefs')), NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', w, w);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', w, NULL);
    cnt := cnt + 1;
  END IF;
  -- karidns_domain_views: a global master writes
  IF to_regclass(format('%I.karidns_domain_views', sch)) IS NOT NULL THEN
    rel := format('%I.karidns_domain_views', sch)::regclass;
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('karidns_auth.zone_grant(%s, %s) IS NOT NULL', lit, format(zr, 'karidns_domain_views')), NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, 'karidns_auth.is_global()');
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_update', 'UPDATE', 'karidns_auth.is_global()', 'karidns_auth.is_global()');
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_delete', 'DELETE', 'karidns_auth.is_global()', NULL);
    cnt := cnt + 1;
  END IF;
  -- karidns_reload_requests: a request for one zone needs a grant on the zone, for all zones (zone NULL) a global master; the same rule says which
  -- requests a principal sees.  No UPDATE, no DELETE: the prune trigger of the table is SECURITY DEFINER.
  IF to_regclass(format('%I.karidns_reload_requests', sch)) IS NOT NULL THEN
    rel := format('%I.karidns_reload_requests', sch)::regclass;
    w := format('CASE WHEN karidns_reload_requests.zone IS NULL THEN karidns_auth.is_global() ELSE karidns_auth.zone_grant(%s, %s) IS NOT NULL END', lit, format(zn, 'karidns_reload_requests.zone'));
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', w, NULL);
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_insert', 'INSERT', NULL, w);
    cnt := cnt + 1;
  END IF;
  -- cryptokeys: the rows of the zones the principal has a grant on; the role has the column privilege SELECT (id, domain_id, flags, active, published) only
  IF to_regclass(format('%I.cryptokeys', sch)) IS NOT NULL THEN
    rel := format('%I.cryptokeys', sch)::regclass;
    PERFORM karidns_auth.set_policy(rel, 'karidns_rls_select', 'SELECT', format('karidns_auth.zone_grant(%s, %s) IS NOT NULL', lit, format(zr, 'cryptokeys')), NULL);
    cnt := cnt + 1;
  END IF;
  RETURN cnt;
END $$;

-- The policies of the signer role (db/karidns_signer_role.pgsql.sql): it reads everything and writes only what it owns: records of DNSSEC-managed types
-- (and UPDATE of SOA rows, whose serial is all the trigger signer_soa_fn lets it change), the domainmetadata kinds PRESIGNED, NSEC3PARAM and
-- X-KARIDNS-SIGNER, reload requests.  It is not bound by grants.  Every write policy exists twice, PERMISSIVE (what it may do) and RESTRICTIVE (what
-- every write must also pass, so the permissive policies of the API, which are OR-ed with these, cannot widen them: karidns.principal changes nothing).
CREATE OR REPLACE FUNCTION karidns_auth.create_signer_policies(sch text, rol text) RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cnt integer := 0;
  nm  text;
  rel regclass;
  sfx text := CASE WHEN length(rol) <= 40 THEN rol ELSE left(md5(rol), 16) END;
  pr  text;
  pm  text;
BEGIN
  FOREACH nm IN ARRAY ARRAY['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_record_tags', 'karidns_record_tinydns', 'karidns_zone_tagdefs',
                            'karidns_domain_views', 'karidns_reload_requests'] LOOP
    IF to_regclass(format('%I.%I', sch, nm)) IS NULL THEN CONTINUE; END IF;
    rel := format('%I.%I', sch, nm)::regclass;
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_select_' || sfx, 'SELECT', 'true', NULL, rol);
    cnt := cnt + 1;
  END LOOP;
  IF to_regclass(format('%I.records', sch)) IS NOT NULL THEN
    rel := format('%I.records', sch)::regclass;
    pr := 'karidns_auth.is_dnssec_type(records.type)';
    pm := 'karidns_auth.is_dnssec_type(records.type) OR karidns_auth.canon_type(records.type) = ''SOA''';
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_insert_' || sfx, 'INSERT', NULL, pr, rol);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_update_' || sfx, 'UPDATE', pm, pm, rol);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_delete_' || sfx, 'DELETE', pr, NULL, rol);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_r_insert_' || sfx, 'INSERT', NULL, pr, rol, true);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_r_update_' || sfx, 'UPDATE', pm, pm, rol, true);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_r_delete_' || sfx, 'DELETE', pr, NULL, rol, true);
  END IF;
  IF to_regclass(format('%I.domainmetadata', sch)) IS NOT NULL THEN
    rel := format('%I.domainmetadata', sch)::regclass;
    pr := 'upper(btrim(domainmetadata.kind)) IN (''PRESIGNED'', ''NSEC3PARAM'', ''X-KARIDNS-SIGNER'')';
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_insert_' || sfx, 'INSERT', NULL, pr, rol);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_update_' || sfx, 'UPDATE', pr, pr, rol);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_delete_' || sfx, 'DELETE', pr, NULL, rol);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_r_insert_' || sfx, 'INSERT', NULL, pr, rol, true);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_r_update_' || sfx, 'UPDATE', pr, pr, rol, true);
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_r_delete_' || sfx, 'DELETE', pr, NULL, rol, true);
  END IF;
  IF to_regclass(format('%I.karidns_reload_requests', sch)) IS NOT NULL THEN       -- INSERT only (the prune trigger is SECURITY DEFINER)
    rel := format('%I.karidns_reload_requests', sch)::regclass;
    PERFORM karidns_auth.set_policy(rel, 'karidns_signer_insert_' || sfx, 'INSERT', NULL, 'true', rol);
  END IF;
  RETURN cnt;
END $$;

-- Switch RLS on / off for the tables of a schema (or of karidns_auth).  enable_rls also gives the role karidns_rls_trusted its policy
-- (USING (true) WITH CHECK (true)); the role must exist (the role scripts create it).  The owner of the tables runs them.  Returns the number of tables.
CREATE OR REPLACE FUNCTION karidns_auth.enable_rls(sch text) RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t   text;
  cnt integer := 0;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'karidns_rls_trusted') THEN
    RAISE EXCEPTION 'karidns_auth.enable_rls: the role karidns_rls_trusted does not exist (the role scripts create it)';
  END IF;
  FOREACH t IN ARRAY (CASE WHEN sch = 'karidns_auth' THEN ARRAY['principals', 'credentials', 'memberships', 'rr_policies', 'grants', 'audit_log']
                           ELSE ARRAY['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_record_tags', 'karidns_record_tinydns',
                                      'karidns_zone_tagdefs', 'karidns_domain_views', 'karidns_reload_requests'] END) LOOP
    IF to_regclass(format('%I.%I', sch, t)) IS NULL THEN CONTINUE; END IF;
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', sch, t);
    EXECUTE format('DROP POLICY IF EXISTS karidns_rls_trusted ON %I.%I', sch, t);
    EXECUTE format('CREATE POLICY karidns_rls_trusted ON %I.%I AS PERMISSIVE FOR ALL TO karidns_rls_trusted USING (true) WITH CHECK (true)', sch, t);
    cnt := cnt + 1;
  END LOOP;
  RETURN cnt;
END $$;

CREATE OR REPLACE FUNCTION karidns_auth.disable_rls(sch text) RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t   text;
  cnt integer := 0;
BEGIN
  FOREACH t IN ARRAY (CASE WHEN sch = 'karidns_auth' THEN ARRAY['principals', 'credentials', 'memberships', 'rr_policies', 'grants', 'audit_log']
                           ELSE ARRAY['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_record_tags', 'karidns_record_tinydns',
                                      'karidns_zone_tagdefs', 'karidns_domain_views', 'karidns_reload_requests'] END) LOOP
    IF to_regclass(format('%I.%I', sch, t)) IS NULL THEN CONTINUE; END IF;
    EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY', sch, t);
    cnt := cnt + 1;
  END LOOP;
  RETURN cnt;
END $$;

-- the policies of the auth tables and of the schema this file is applied in (inactive while RLS is off)
DO $$ BEGIN PERFORM karidns_auth.create_policies('karidns_auth'); PERFORM karidns_auth.create_policies(current_schema()); END $$;

-- The maintenance triggers of the data tables (the change log, its prune, the reload requests: all of the version 2 part of this file) run as the owner,
-- not as the role that writes: the roles of the API and the signer need no right on karidns_changes (and cannot read or forge the log the loader's
-- auto reload depends on) and cannot delete reload requests.  Their search_path is pinned to pg_catalog, this schema, pg_temp (the temporary schema
-- last: a temporary table cannot shadow a table of the log); a SECURITY DEFINER function must not use the writer's path.
DO $$
DECLARE
  f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p
            WHERE p.pronamespace = current_schema()::regnamespace AND p.prokind = 'f'
              AND (p.proname LIKE 'karidns\_trg\_%\_fn' OR p.proname IN ('karidns_log_domains', 'karidns_changes_prune_fn', 'karidns_reload_requests_lock_fn',
                                                                         'karidns_reload_requests_notify_fn', 'karidns_reload_requests_prune_fn'))
  LOOP
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER SET search_path = pg_catalog, %I, pg_temp', f, current_schema());
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
  END LOOP;
END $$;


-- The trigger functions and the audit switches are not for anybody to call or to attach to a table of their own: EXECUTE is for the owner only
-- (a trigger function needs no EXECUTE right of the role whose statement fires the trigger; CREATE TRIGGER does).  is_canonical_name and
-- rr_types_ok stay with PUBLIC: CHECK constraints call them as the role that inserts the row.
REVOKE EXECUTE ON FUNCTION karidns_auth.credentials_user_only_fn(), karidns_auth.principals_kind_fn(), karidns_auth.principals_self_fn(),
  karidns_auth.principals_delete_fn(), karidns_auth.memberships_check_fn(), karidns_auth.memberships_closure_fn(), karidns_auth.domains_grants_fn(),
  karidns_auth.audit_row(), karidns_auth.audit_stmt(), karidns_auth.audit_zone_fn(), karidns_auth.audit_summary(),
  karidns_auth.enable_audit(text), karidns_auth.disable_audit(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION karidns_auth.current_principal(), karidns_auth.my_groups(), karidns_auth.zone_grant(text, text), karidns_auth.is_global(),
  karidns_auth.rr_ok(text, text, text, text, integer), karidns_auth.rr_visible(text, text, text, text), karidns_auth.audit_visible(text, text, text, jsonb, jsonb),
  karidns_auth.bump_serial(text, integer), karidns_auth.is_api_caller(), karidns_auth.is_signer_caller(), karidns_auth.policy_subset(bigint, bigint),
  karidns_auth.may_grant(text, text, text, bigint), karidns_auth.grants_escalation_fn(), karidns_auth.signer_soa_fn(), karidns_auth.assert_service_role(text, text),
  karidns_auth.set_policy(regclass, text, text, text, text, text, boolean), karidns_auth.create_policies(text),
  karidns_auth.create_signer_policies(text, text), karidns_auth.enable_rls(text), karidns_auth.disable_rls(text) FROM PUBLIC;
-- (canon_type, is_dnssec_type and setting_principal stay with PUBLIC: the policies and the trigger conditions of the signer call them as the signer.)
-- The role scripts grant EXECUTE on current_principal, my_groups, zone_grant, is_global, rr_ok, rr_visible and audit_visible (and bump_serial to the API
-- role) to their role and to karidns_rls_trusted: the policies call them as the role that runs the statement.


-- the versions, last: a fresh install whose karidns_auth part fails stays version 2 (a version 1 database is not touched: it needs
-- db/karidns_ext_v1_to_v2.pgsql.sql first)
INSERT INTO karidns_auth.schema_version (version) SELECT 3 WHERE NOT EXISTS (SELECT 1 FROM karidns_auth.schema_version);
UPDATE karidns_auth.schema_version SET version = 3 WHERE version < 3;
UPDATE karidns_schema_version SET version = 3 WHERE version = 2;

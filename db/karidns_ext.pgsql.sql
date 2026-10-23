-- karidns_ext.pgsql.sql - the KariDNS extension tables and the change-log triggers for a PowerDNS 5.1 gpgsql database
-- (beta design 3.7, 5.1, 6; milestone B6a).  Schema version 1.  PostgreSQL 10 or later (transition tables).
--
-- Apply it once, as the owner of the PowerDNS tables, after the PowerDNS schema (schema.pgsql.sql), in the schema that
-- holds them (a view with its own schema needs its own copy: SET search_path TO that_schema first):
--     psql -v ON_ERROR_STOP=1 -f karidns_ext.pgsql.sql karidns
-- It can be applied again (IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS); the version row is only inserted once.
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
-- TRUNCATE is not logged (a trigger on TRUNCATE has no transition tables); use DELETE, or `karictl reload` afterwards.
-- The loader role needs SELECT on karidns_changes (and the other tables it reads); it never writes.
--
-- The retention is the number 1000000 in karidns_changes_prune_fn below; tests/run_db_ddl_test.sh replaces it by 5 to test
-- the pruning on a small scale.

CREATE TABLE IF NOT EXISTS karidns_schema_version (version INTEGER NOT NULL);
INSERT INTO karidns_schema_version (version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM karidns_schema_version);

CREATE TABLE IF NOT EXISTS karidns_changes (
  seq        BIGSERIAL PRIMARY KEY,
  domain_id  INTEGER NOT NULL,
  changed_at BIGINT NOT NULL
);

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
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  kind      VARCHAR(8) NOT NULL,          -- 'location' | 'ecs' | 'tinydns'
  tag       VARCHAR(63) NOT NULL,
  cidr      VARCHAR(64) NOT NULL
);

-- prune: keep the newest 1000000 rows (statement level: one DELETE per INSERT statement)
CREATE OR REPLACE FUNCTION karidns_changes_prune_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM karidns_changes WHERE seq <= (SELECT max(seq) FROM new_rows) - 1000000;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS karidns_changes_prune ON karidns_changes;
CREATE TRIGGER karidns_changes_prune AFTER INSERT ON karidns_changes
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_changes_prune_fn();

-- the one place that writes the log: the distinct domain ids of a statement, then NOTIFY
CREATE OR REPLACE FUNCTION karidns_log_domains(ids INTEGER[]) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at)
    SELECT DISTINCT d, extract(epoch FROM now())::bigint FROM unnest(ids) AS d WHERE d IS NOT NULL;
  PERFORM pg_notify('karidns_changes', '');
END $$;

-- domains (the key is id)
CREATE OR REPLACE FUNCTION karidns_trg_domains_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domains_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT id FROM old_rows UNION SELECT id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domains_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_records_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_records_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_records_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_domainmetadata_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domainmetadata_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domainmetadata_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_cryptokeys_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_cryptokeys_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_cryptokeys_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_domain_views_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domain_views_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_domain_views_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_zone_tagdefs_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_zone_tagdefs_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT domain_id FROM old_rows UNION SELECT domain_id FROM new_rows)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_zone_tagdefs_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_record_tags_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tags_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN old_rows o ON o.record_id = r.id
                                        UNION SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id));
RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tags_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_record_tinydns_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id)); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tinydns_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT r.domain_id FROM records r JOIN old_rows o ON o.record_id = r.id
                                        UNION SELECT r.domain_id FROM records r JOIN new_rows n ON n.record_id = r.id));
RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_record_tinydns_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE OR REPLACE FUNCTION karidns_trg_profiles_ins_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT m.domain_id FROM domainmetadata m JOIN new_rows n ON btrim(m.content, E' \t') = n.name
                                         WHERE upper(m.kind) = 'X-KARIDNS-PROFILE')); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_profiles_upd_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM karidns_log_domains(ARRAY(SELECT m.domain_id FROM domainmetadata m
                                         WHERE upper(m.kind) = 'X-KARIDNS-PROFILE'
                                           AND btrim(m.content, E' \t') IN (SELECT name FROM old_rows UNION SELECT name FROM new_rows))); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION karidns_trg_profiles_del_fn() RETURNS trigger LANGUAGE plpgsql AS $$
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

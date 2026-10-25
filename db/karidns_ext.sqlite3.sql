-- karidns_ext.sqlite3.sql - the KariDNS extension tables and the change-log triggers for a PowerDNS 5.1 gsqlite3 database
-- (beta design 3.7, 5.1, 6; milestones B6a, B10).  Schema version 2.
--
-- Manual: docs/karidns-dbloader.md (the schema and trigger files, the privileges, the drivers) and the database chapter of
-- docs/karidns.md.  The packages karidns-sqlite3, karidns-postgresql and karidns-db install this file in /usr/local/share/karidns/db/.
--
-- Apply it once, as the owner of the database, after the PowerDNS schema (schema.sqlite3.sql):
--     sqlite3 /var/db/karidns/zones.sqlite3 < karidns_ext.sqlite3.sql
-- It can be applied again (CREATE ... IF NOT EXISTS); the version row is only inserted once.
--
-- What it gives karidns-dbloader:
--   karidns_changes   a log of "domain D changed" (seq, domain_id, changed_at), written by AFTER INSERT / UPDATE / DELETE
--                     triggers on domains, records, domainmetadata, cryptokeys and the karidns_* tables below, for the OLD
--                     and the NEW domain id.  The loader reads the rows after the last seq it has applied, so an edit that
--                     does not bump the SOA serial is noticed by `karictl reload` (and by auto-reload, milestone B9).
--                     There is no foreign key on domain_id: a deleted domain must stay in the log.
--   a prune trigger   keeps the newest 1,000,000 rows (the loader is read-only and cannot prune).  A loader that finds the
--                     rows after its seq are gone (the first remaining seq is not seq + 1) compares everything again.
--   the tables of design 3.7 that later milestones read: karidns_domain_views (B6b), karidns_profiles (B7a, with triggers that log the domains naming the profile),
--                     karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs (B8).
--
-- SQLite triggers are row level, so a bulk import writes one log row per changed row; that is harmless (the log is pruned)
-- but a big import makes the loader compare everything once.  DELETE FROM is logged (SQLite has no TRUNCATE).
-- Foreign keys are only enforced when the connection runs PRAGMA foreign_keys=ON (PowerDNS can, the sqlite3 shell does not).
--
-- Version 1 had no karidns_zone_tagdefs.id (the rowid gave the order); db/karidns_ext_v1_to_v2.sqlite3.sql converts a database.
-- The loader reads both versions.
--
-- The retention is the number 1000000 in karidns_changes_prune below; tests/run_db_ddl_test.sh replaces it by 5 to test
-- the pruning on a small scale.

CREATE TABLE IF NOT EXISTS karidns_schema_version (version INTEGER NOT NULL);
INSERT INTO karidns_schema_version (version) SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM karidns_schema_version);

CREATE TABLE IF NOT EXISTS karidns_changes (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id  INTEGER NOT NULL,
  changed_at INTEGER NOT NULL
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
  record_id    INTEGER PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
  location_tag VARCHAR(63),
  ecs_tag      VARCHAR(63)
);

CREATE TABLE IF NOT EXISTS karidns_record_tinydns (
  record_id INTEGER PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
  ttd       BIGINT,
  loc       CHAR(2),
  countdown BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS karidns_zone_tagdefs (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,      -- schema version 2: the order of the definitions (the first match wins)
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  kind      VARCHAR(8) NOT NULL,          -- 'location' | 'ecs' | 'tinydns'
  tag       VARCHAR(63) NOT NULL,
  cidr      VARCHAR(64) NOT NULL
);

-- prune: keep the newest 1000000 rows
CREATE TRIGGER IF NOT EXISTS karidns_changes_prune AFTER INSERT ON karidns_changes
BEGIN
  DELETE FROM karidns_changes WHERE seq <= NEW.seq - 1000000;
END;

-- domains (the key is id)
CREATE TRIGGER IF NOT EXISTS karidns_trg_domains_ins AFTER INSERT ON domains
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (NEW.id, strftime('%s', 'now'));
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_domains_upd AFTER UPDATE ON domains
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (OLD.id, strftime('%s', 'now'));
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.id, strftime('%s', 'now') WHERE NEW.id IS NOT OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_domains_del AFTER DELETE ON domains
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (OLD.id, strftime('%s', 'now'));
END;

-- records
CREATE TRIGGER IF NOT EXISTS karidns_trg_records_ins AFTER INSERT ON records
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now') WHERE NEW.domain_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_records_upd AFTER UPDATE ON records
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT OLD.domain_id, strftime('%s', 'now') WHERE OLD.domain_id IS NOT NULL;
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now')
    WHERE NEW.domain_id IS NOT NULL AND NEW.domain_id IS NOT OLD.domain_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_records_del AFTER DELETE ON records
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT OLD.domain_id, strftime('%s', 'now') WHERE OLD.domain_id IS NOT NULL;
END;

-- domainmetadata
CREATE TRIGGER IF NOT EXISTS karidns_trg_domainmetadata_ins AFTER INSERT ON domainmetadata
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now') WHERE NEW.domain_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_domainmetadata_upd AFTER UPDATE ON domainmetadata
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT OLD.domain_id, strftime('%s', 'now') WHERE OLD.domain_id IS NOT NULL;
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now')
    WHERE NEW.domain_id IS NOT NULL AND NEW.domain_id IS NOT OLD.domain_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_domainmetadata_del AFTER DELETE ON domainmetadata
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT OLD.domain_id, strftime('%s', 'now') WHERE OLD.domain_id IS NOT NULL;
END;

-- cryptokeys: a zone that gets a key without PRESIGNED must fail (design 3.5), so the loader has to look at it again
CREATE TRIGGER IF NOT EXISTS karidns_trg_cryptokeys_ins AFTER INSERT ON cryptokeys
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now') WHERE NEW.domain_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_cryptokeys_upd AFTER UPDATE ON cryptokeys
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT OLD.domain_id, strftime('%s', 'now') WHERE OLD.domain_id IS NOT NULL;
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now')
    WHERE NEW.domain_id IS NOT NULL AND NEW.domain_id IS NOT OLD.domain_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_cryptokeys_del AFTER DELETE ON cryptokeys
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT OLD.domain_id, strftime('%s', 'now') WHERE OLD.domain_id IS NOT NULL;
END;

-- karidns_domain_views
CREATE TRIGGER IF NOT EXISTS karidns_trg_domain_views_ins AFTER INSERT ON karidns_domain_views
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (NEW.domain_id, strftime('%s', 'now'));
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_domain_views_upd AFTER UPDATE ON karidns_domain_views
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (OLD.domain_id, strftime('%s', 'now'));
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now') WHERE NEW.domain_id IS NOT OLD.domain_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_domain_views_del AFTER DELETE ON karidns_domain_views
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (OLD.domain_id, strftime('%s', 'now'));
END;

-- karidns_zone_tagdefs
CREATE TRIGGER IF NOT EXISTS karidns_trg_zone_tagdefs_ins AFTER INSERT ON karidns_zone_tagdefs
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (NEW.domain_id, strftime('%s', 'now'));
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_zone_tagdefs_upd AFTER UPDATE ON karidns_zone_tagdefs
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (OLD.domain_id, strftime('%s', 'now'));
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT NEW.domain_id, strftime('%s', 'now') WHERE NEW.domain_id IS NOT OLD.domain_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_zone_tagdefs_del AFTER DELETE ON karidns_zone_tagdefs
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) VALUES (OLD.domain_id, strftime('%s', 'now'));
END;

-- karidns_record_tags: the domain is found through the record (a record that is gone has logged its own deletion)
CREATE TRIGGER IF NOT EXISTS karidns_trg_record_tags_ins AFTER INSERT ON karidns_record_tags
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records WHERE id = NEW.record_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_record_tags_upd AFTER UPDATE ON karidns_record_tags
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records WHERE id = OLD.record_id;
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records
    WHERE id = NEW.record_id AND NEW.record_id IS NOT OLD.record_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_record_tags_del AFTER DELETE ON karidns_record_tags
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records WHERE id = OLD.record_id;
END;

-- karidns_record_tinydns
CREATE TRIGGER IF NOT EXISTS karidns_trg_record_tinydns_ins AFTER INSERT ON karidns_record_tinydns
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records WHERE id = NEW.record_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_record_tinydns_upd AFTER UPDATE ON karidns_record_tinydns
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records WHERE id = OLD.record_id;
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records
    WHERE id = NEW.record_id AND NEW.record_id IS NOT OLD.record_id;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_record_tinydns_del AFTER DELETE ON karidns_record_tinydns
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at) SELECT domain_id, strftime('%s', 'now') FROM records WHERE id = OLD.record_id;
END;

-- karidns_profiles (B7a): the settings of a profile are part of every zone that names it (domainmetadata X-KARIDNS-PROFILE),
-- so editing, adding or deleting a profile logs every domain that uses the old or the new name.  The kind is compared
-- case-insensitively and the content without leading / trailing blanks, like the loader does.
CREATE TRIGGER IF NOT EXISTS karidns_trg_profiles_ins AFTER INSERT ON karidns_profiles
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at)
    SELECT domain_id, strftime('%s', 'now') FROM domainmetadata
     WHERE domain_id IS NOT NULL AND upper(kind) = 'X-KARIDNS-PROFILE' AND trim(content, ' ' || char(9)) = NEW.name;
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_profiles_upd AFTER UPDATE ON karidns_profiles
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at)
    SELECT domain_id, strftime('%s', 'now') FROM domainmetadata
     WHERE domain_id IS NOT NULL AND upper(kind) = 'X-KARIDNS-PROFILE'
       AND trim(content, ' ' || char(9)) IN (OLD.name, NEW.name);
END;
CREATE TRIGGER IF NOT EXISTS karidns_trg_profiles_del AFTER DELETE ON karidns_profiles
BEGIN
  INSERT INTO karidns_changes (domain_id, changed_at)
    SELECT domain_id, strftime('%s', 'now') FROM domainmetadata
     WHERE domain_id IS NOT NULL AND upper(kind) = 'X-KARIDNS-PROFILE' AND trim(content, ' ' || char(9)) = OLD.name;
END;

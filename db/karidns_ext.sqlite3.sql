-- karidns_ext.sqlite3.sql - the KariDNS extension tables and the change-log triggers for a PowerDNS 5.1 gsqlite3 database
-- (beta design 3.7, 5.1, 6; milestones B6a, B10).  Schema version 3.
--
-- Manual: docs/karidns-dbloader.md (the schema and trigger files, the privileges, the drivers) and the database chapter of
-- docs/karidns.md.  The packages karidns-sqlite3, karidns-postgresql and karidns-db install this file in /usr/local/share/karidns/db/.
--
-- Apply it once, as the owner of the database, after the PowerDNS schema (schema.sqlite3.sql):
--     sqlite3 /var/db/karidns/zones.sqlite3 < karidns_ext.sqlite3.sql
-- It can be applied again (CREATE ... IF NOT EXISTS); the version row is only inserted once.  Applied to a version 2 database it adds
-- the two audit tables (the end of this file) and moves the version row to 3.
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
-- Version 3 (0.6.0 item B) adds the audit tables karidns_audit_log and karidns_audit_actor; item C (the signer) adds karidns_key_requests and
-- karidns_signer_state; items D and E (the API, zone versions) add karidns_zone_state (the zone generation, grown by the trigger karidns_changes_generation),
-- karidns_zone_versions and karidns_zone_version_rrsets (apply this file again to a version 3 file that lacks them).  The loader reads versions 1 to 3 and
-- uses nothing of version 3.
--
-- The retention is the number 1000000 in karidns_changes_prune below; tests/run_db_ddl_test.sh replaces it by 5 to test
-- the pruning on a small scale.

CREATE TABLE IF NOT EXISTS karidns_schema_version (version INTEGER NOT NULL);
-- a fresh database starts as version 2; the last statement of this file (after the audit tables exist) makes it 3
INSERT INTO karidns_schema_version (version) SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM karidns_schema_version);

CREATE TABLE IF NOT EXISTS karidns_changes (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id  INTEGER NOT NULL,
  changed_at INTEGER NOT NULL
);

-- The zone generation (0.6.0 items D and E, schema version 3): one row per zone with a number that grows whenever a row of the zone changes (records,
-- domainmetadata, the karidns_* zone tables: the set that writes karidns_changes; the trigger karidns_changes_generation below follows the log).  The API
-- (karidns-zone apply --expect-generation) validates a change against the generation it read and commits only when nobody changed the zone in between
-- (SQLite3 has one writer at a time, so the check and the commit run cannot overlap; the generation tells that someone wrote between them).  It grows once
-- per changed row (SQLite3 triggers are row level); only equality counts.  Every writer bumps it, the signer too (docs/karidns-dbloader.md).  A zone with no row
-- has generation 0.
CREATE TABLE IF NOT EXISTS karidns_zone_state (
  domain_id  INTEGER PRIMARY KEY REFERENCES domains(id) ON UPDATE CASCADE ON DELETE CASCADE,
  generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
  changed_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO karidns_zone_state (domain_id) SELECT id FROM domains;

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
-- the loader reads the definitions of one zone at a time (scan_metadata): without this index every such read scans the
-- table.  Added after version 2; applying this file again creates it (the schema version stays 2).
CREATE INDEX IF NOT EXISTS karidns_zone_tagdefs_domain_idx ON karidns_zone_tagdefs (domain_id);

-- prune: keep the newest 1000000 rows
CREATE TRIGGER IF NOT EXISTS karidns_changes_prune AFTER INSERT ON karidns_changes
BEGIN
  DELETE FROM karidns_changes WHERE seq <= NEW.seq - 1000000;
END;

-- the generation follows the change log: every row the log gets grows the generation of its zone, if the zone still exists (a zone that is deleted loses its
-- state row and its versions with it: the foreign keys do it when PRAGMA foreign_keys=ON, the second trigger when it is off)
CREATE TRIGGER IF NOT EXISTS karidns_changes_generation AFTER INSERT ON karidns_changes
BEGIN
  INSERT INTO karidns_zone_state (domain_id, generation, changed_at)
    SELECT NEW.domain_id, 1, NEW.changed_at WHERE EXISTS (SELECT 1 FROM domains WHERE id = NEW.domain_id)
    ON CONFLICT (domain_id) DO UPDATE SET generation = generation + 1, changed_at = excluded.changed_at;
END;
CREATE TRIGGER IF NOT EXISTS karidns_zone_state_del AFTER DELETE ON domains
BEGIN
  DELETE FROM karidns_zone_state WHERE domain_id = OLD.id;
  DELETE FROM karidns_zone_version_rrsets WHERE version_id IN (SELECT id FROM karidns_zone_versions WHERE domain_id = OLD.id);
  DELETE FROM karidns_zone_versions WHERE domain_id = OLD.id;
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

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The signer (0.6.0 item C, docs/karidns-signer.md; schema version 3): the work queue and the schedule of karidns-signer.  They are NOT zone data: no
-- trigger writes karidns_changes for them (the signer writes its state after every run, and a signer that followed its own state would never stop).
-- SQLite3 has no roles: the WebAdmin API does the checks of who may file a request.  Times are unix seconds (INTEGER), like karidns_changes.changed_at.
--
--   karidns_key_requests   a request for keys, filed by the WebAdmin or an operator, answered by the signer.  kind: 'enable' = start signing the zone
--                          (generate the first key or keys, set the metadata, sign), 'add' = one more key.  algorithm: 8, 10 (RSA; bits 1024..8192), 13,
--                          14 (ECDSA), 15, 16 (EdDSA); key_type 'csk' (one key signs everything), 'ksk' or 'zsk'; nsec 'nsec3' (the default of the
--                          signer) or 'nsec' for an 'enable' request.  state: 'pending' -> 'done' or 'failed' (message says why); done_at is set with the
--                          state.  requested_by: the principal id of the requester.
--   karidns_signer_state   one row per signed zone: when it was signed, the SOA serial it wrote, the earliest RRSIG expiration of the zone (min_expire),
--                          when the signer wants to look at the zone again (next_due), the failed attempts since the last success and the last error.
-- Both go away with their zone when the connection runs PRAGMA foreign_keys=ON (ON DELETE CASCADE).
CREATE TABLE IF NOT EXISTS karidns_key_requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id    INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  kind         VARCHAR(6) NOT NULL DEFAULT 'enable' CHECK (kind IN ('enable', 'add')),
  algorithm    INTEGER NOT NULL DEFAULT 13 CHECK (algorithm IN (8, 10, 13, 14, 15, 16)),
  bits         INTEGER NULL CHECK (bits IS NULL OR (bits BETWEEN 1024 AND 8192 AND algorithm IN (8, 10))),
  key_type     VARCHAR(3) NOT NULL DEFAULT 'csk' CHECK (key_type IN ('csk', 'ksk', 'zsk')),
  nsec         VARCHAR(5) NULL CHECK (nsec IS NULL OR (nsec IN ('nsec3', 'nsec') AND kind = 'enable')),
  state        VARCHAR(7) NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'done', 'failed')),
  message      TEXT NULL,
  requested_by INTEGER NULL,
  created_at   INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
  done_at      INTEGER NULL,
  CONSTRAINT karidns_key_requests_done_chk CHECK ((state = 'pending') = (done_at IS NULL))
);
CREATE INDEX IF NOT EXISTS karidns_key_requests_domain_idx ON karidns_key_requests (domain_id);
CREATE INDEX IF NOT EXISTS karidns_key_requests_pending_idx ON karidns_key_requests (id) WHERE state = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS karidns_key_requests_one_pending_idx ON karidns_key_requests (domain_id) WHERE state = 'pending';       -- one open request per zone

CREATE TABLE IF NOT EXISTS karidns_signer_state (
  domain_id        INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
  signed_at        INTEGER NULL,
  signed_serial    INTEGER NULL CHECK (signed_serial IS NULL OR signed_serial BETWEEN 0 AND 4294967295),
  min_expire       INTEGER NULL,
  next_due         INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
  attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error       TEXT NULL,
  last_duration_ms INTEGER NULL CHECK (last_duration_ms IS NULL OR last_duration_ms >= 0)
);
CREATE INDEX IF NOT EXISTS karidns_signer_state_due_idx ON karidns_signer_state (next_due);

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Zone versions (0.6.0 item E, docs/karidns-zone.md "Versions"; schema version 3): one row per committed change set of one zone, written by
-- `karidns-zone apply` (and `import`) in the transaction of the change itself.  Version numbers are per zone, from 1.  The same tables as on PostgreSQL
-- (db/karidns_ext.pgsql.sql), with db_role written by the tool ('karidns-zone:<OS user>') and the API's principal in principal_id / principal_name.
--   karidns_zone_versions         who, when, kind ('create' 'edit' 'template' 'import' 'rollback'), the change set id, the comment, the SOA serial and the zone
--                                 generation before and after, rollback_of (the version a rollback restores), delta_complete (0: too big to store).
--   karidns_zone_version_rrsets   the delta: for each RRset the version changed, the RRset before and after as canonical lines "<ttl> <TYPE> <rdata>" joined by
--                                 LF (names absolute), NULL = absent.  DNSSEC types and a change of the SOA serial alone are not versioned.
-- The newest 100 versions of a zone are kept: the number in the trigger karidns_zone_versions_prune (tests/run_db_ddl_test.sh replaces it).
CREATE TABLE IF NOT EXISTS karidns_zone_versions (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id         INTEGER NOT NULL REFERENCES domains(id) ON UPDATE CASCADE ON DELETE CASCADE,
  version           INTEGER NOT NULL CHECK (version >= 1),
  kind              TEXT NOT NULL CHECK (kind IN ('create', 'edit', 'template', 'import', 'rollback')),
  change_set        TEXT NULL CHECK (change_set IS NULL OR length(change_set) <= 64),
  principal_id      INTEGER NULL,
  principal_name    TEXT NULL CHECK (principal_name IS NULL OR length(principal_name) <= 255),
  db_role           TEXT NULL,
  at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  comment           TEXT NULL CHECK (comment IS NULL OR length(CAST(comment AS BLOB)) <= 1024),
  serial_before     INTEGER NULL CHECK (serial_before IS NULL OR serial_before BETWEEN 0 AND 4294967295),
  serial_after      INTEGER NULL CHECK (serial_after IS NULL OR serial_after BETWEEN 0 AND 4294967295),
  generation_before INTEGER NOT NULL,
  generation_after  INTEGER NOT NULL,
  rollback_of       INTEGER NULL CHECK (rollback_of IS NULL OR rollback_of >= 1),
  delta_complete    INTEGER NOT NULL DEFAULT 1 CHECK (delta_complete IN (0, 1)),
  UNIQUE (domain_id, version),
  CONSTRAINT karidns_zone_versions_rollback_chk CHECK ((kind = 'rollback') = (rollback_of IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS karidns_zone_version_rrsets (
  version_id INTEGER NOT NULL REFERENCES karidns_zone_versions(id) ON DELETE CASCADE,
  owner      TEXT NOT NULL CHECK (length(CAST(owner AS BLOB)) BETWEEN 1 AND 253),       -- lower case, no final dot (the form of records.name)
  type       TEXT NOT NULL CHECK (length(type) BETWEEN 1 AND 32),
  before     TEXT NULL,
  after      TEXT NULL,
  PRIMARY KEY (version_id, owner, type),
  CHECK (before IS NOT NULL OR after IS NOT NULL)
);
-- prune: keep the newest 100 versions of the zone (the rows of their RRsets first: the foreign key does not do it unless PRAGMA foreign_keys=ON)
CREATE TRIGGER IF NOT EXISTS karidns_zone_versions_prune AFTER INSERT ON karidns_zone_versions
BEGIN
  DELETE FROM karidns_zone_version_rrsets WHERE version_id IN (SELECT id FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 100);
  DELETE FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 100;
END;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- == audit tables (schema version 3) ==    0.6.0 item B.  Everything above is version 2.
--
-- The audit log of the WebAdmin / API and of karidns-zone.  This file only creates the two tables; the triggers that fill the log are in
-- db/karidns_audit.sqlite3.sql, applied to this file when the WebAdmin (or the signer) is used, so that a site without them logs nothing.
--
--   karidns_audit_log    who changed what: the same columns as karidns_auth.audit_log on PostgreSQL (docs/karidns-auth.md), before / after
--                        as JSON text, cryptokeys.content replaced by "<redacted>"; no xid.
--   karidns_audit_actor  at most one row (id is always 1): who is writing.  A persistent trigger can only read its own database, so
--                        the writer puts the actor here first in its transaction and deletes it last (SQLite has one writer at a
--                        time: BEGIN IMMEDIATE).  karidns-zone writes db_role 'karidns-zone:<OS user>' and no principal.  A writer
--                        that writes no row is logged with all four columns NULL.
CREATE TABLE IF NOT EXISTS karidns_audit_log (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  db_role        TEXT NULL,
  principal_id   INTEGER NULL,
  principal_name TEXT NULL,
  change_set     TEXT NULL,
  data_schema    TEXT NOT NULL DEFAULT 'main',
  table_name     TEXT NOT NULL,
  op             TEXT NOT NULL CHECK (op IN ('I', 'U', 'D')),
  zone_name      TEXT NULL,
  row_id         INTEGER NULL,
  before         TEXT NULL,
  after          TEXT NULL
);
CREATE INDEX IF NOT EXISTS karidns_audit_log_zone_idx ON karidns_audit_log (zone_name, at);
CREATE INDEX IF NOT EXISTS karidns_audit_log_principal_idx ON karidns_audit_log (principal_id, at);
CREATE INDEX IF NOT EXISTS karidns_audit_log_change_set_idx ON karidns_audit_log (change_set);
-- the triggers of db/karidns_audit.sqlite3.sql find the name of a zone that is being deleted in the log row of its domains DELETE; the terms of
-- the WHERE are those of the lookup (table_name = 'domains' AND op = 'D'), which is how SQLite knows it may use the index
CREATE INDEX IF NOT EXISTS karidns_audit_log_zdel_idx ON karidns_audit_log (row_id) WHERE table_name = 'domains' AND op = 'D';

CREATE TABLE IF NOT EXISTS karidns_audit_actor (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  principal_id   INTEGER NULL,
  principal_name TEXT NULL,
  change_set     TEXT NULL,
  db_role        TEXT NULL
);

-- the data schema is at version 3 (a version 1 database is not touched: it needs db/karidns_ext_v1_to_v2.sqlite3.sql first)
UPDATE karidns_schema_version SET version = 3 WHERE version = 2;

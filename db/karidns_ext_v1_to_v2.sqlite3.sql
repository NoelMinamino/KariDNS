-- karidns_ext_v1_to_v2.sqlite3.sql - converts the KariDNS extension tables of a SQLite3 database from schema version 1
-- (db/karidns_ext.sqlite3.sql of milestone B6a..B9) to version 2 (milestone B10).
--
-- Apply it once, as the owner of the database, while nothing else writes to it:
--     sqlite3 /var/db/karidns/zones.sqlite3 < karidns_ext_v1_to_v2.sqlite3.sql
-- Applying it to a version 2 database rebuilds the table once more with the same content and the same order; it changes nothing.
--
-- What changes: karidns_zone_tagdefs gets `id INTEGER PRIMARY KEY AUTOINCREMENT`, the order of the definitions of a zone (the
-- first match wins).  Version 1 had no id and the order was the rowid, so the rows are copied in rowid order and keep their
-- order.  SQLite cannot add a primary key to a table, so the table is rebuilt; its three triggers go with the old table and
-- are created again.  The loader reads both versions (the order is the rowid either way).
-- karidns_schema_version becomes 2.

BEGIN;

CREATE TABLE karidns_zone_tagdefs_v2 (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  kind      VARCHAR(8) NOT NULL,          -- 'location' | 'ecs' | 'tinydns'
  tag       VARCHAR(63) NOT NULL,
  cidr      VARCHAR(64) NOT NULL
);
INSERT INTO karidns_zone_tagdefs_v2 (domain_id, kind, tag, cidr)
  SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs ORDER BY rowid;
DROP TABLE karidns_zone_tagdefs;
ALTER TABLE karidns_zone_tagdefs_v2 RENAME TO karidns_zone_tagdefs;

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

CREATE TABLE IF NOT EXISTS karidns_schema_version (version INTEGER NOT NULL);
INSERT INTO karidns_schema_version (version) SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM karidns_schema_version);
UPDATE karidns_schema_version SET version = 2 WHERE version < 2;

COMMIT;

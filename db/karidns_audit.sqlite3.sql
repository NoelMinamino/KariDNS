-- karidns_audit.sqlite3.sql - the audit triggers for a PowerDNS gsqlite3 database with the KariDNS extension (0.6.0 item B).
--
-- Apply it to the zone file when the WebAdmin / API or the signer is used.  A site without them does not apply it and logs nothing:
--     sqlite3 /var/db/karidns/zones.sqlite3 < karidns_audit.sqlite3.sql
-- It can be applied again: the tables are CREATE ... IF NOT EXISTS, and every trigger is dropped and created again, so that a changed body
-- reaches an existing database.  It creates karidns_audit_log and karidns_audit_actor itself when the database has not got them (a schema
-- version 2 database: without them every write would fail); db/karidns_ext.sqlite3.sql (version 3) creates the same tables.
--
-- What it does: AFTER INSERT / UPDATE / DELETE triggers on domains, records, domainmetadata, cryptokeys, karidns_record_tags,
-- karidns_record_tinydns, karidns_zone_tagdefs, karidns_domain_views, karidns_key_requests and karidns_signer_state write one row per changed row to karidns_audit_log: who (the one
-- row of karidns_audit_actor, if the writer put it there; NULLs if not), when, the table, the operation (I, U, D), the zone, the row id and
-- before / after as JSON.  cryptokeys.content (the private key) is written as "<redacted>".  The log has no summary mode (the
-- triggers are row level, like those of karidns_changes).
--
-- The domains DELETE trigger is a BEFORE trigger: SQLite deletes the rows that an ON DELETE CASCADE foreign key (PRAGMA foreign_keys=ON)
-- removes before the AFTER triggers of the parent run, and those rows find the name of their zone in the log row that was written first (the
-- partial index karidns_audit_log_zdel_idx makes that lookup a seek).  Rows of karidns_record_tags / karidns_record_tinydns that go with
-- their record (the cascade of a zone delete, or a DELETE of the record) are logged with zone_name NULL: the record is gone by then and the
-- rows only know the record id.  The D row of the record has the zone, and its row_id is the record_id of those rows.
--
-- The columns in the JSON are the ones PowerDNS 4.x / 5.x use; a PowerDNS version that adds a column to these tables needs this file
-- changed (add the column to the json_object of the three triggers of the table).  JSON needs the JSON functions of SQLite (3.38 and
-- later have them built in).

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
CREATE INDEX IF NOT EXISTS karidns_audit_log_zdel_idx ON karidns_audit_log (row_id) WHERE table_name = 'domains' AND op = 'D';

CREATE TABLE IF NOT EXISTS karidns_audit_actor (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  principal_id   INTEGER NULL,
  principal_name TEXT NULL,
  change_set     TEXT NULL,
  db_role        TEXT NULL
);

-- domains
DROP TRIGGER IF EXISTS karidns_audit_domains_ins;
CREATE TRIGGER karidns_audit_domains_ins AFTER INSERT ON domains
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'domains', 'I', lower(NEW.name), NEW.id,
          NULL,
          json_object('id', NEW.id, 'name', NEW.name, 'master', NEW.master, 'last_check', NEW.last_check, 'type', NEW.type, 'notified_serial', NEW.notified_serial, 'account', NEW.account, 'catalog', NEW.catalog));
END;
DROP TRIGGER IF EXISTS karidns_audit_domains_upd;
CREATE TRIGGER karidns_audit_domains_upd AFTER UPDATE ON domains
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'domains', 'U', lower(NEW.name), NEW.id,
          json_object('id', OLD.id, 'name', OLD.name, 'master', OLD.master, 'last_check', OLD.last_check, 'type', OLD.type, 'notified_serial', OLD.notified_serial, 'account', OLD.account, 'catalog', OLD.catalog),
          json_object('id', NEW.id, 'name', NEW.name, 'master', NEW.master, 'last_check', NEW.last_check, 'type', NEW.type, 'notified_serial', NEW.notified_serial, 'account', NEW.account, 'catalog', NEW.catalog));
END;
DROP TRIGGER IF EXISTS karidns_audit_domains_del;
CREATE TRIGGER karidns_audit_domains_del BEFORE DELETE ON domains
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'domains', 'D', lower(OLD.name), OLD.id,
          json_object('id', OLD.id, 'name', OLD.name, 'master', OLD.master, 'last_check', OLD.last_check, 'type', OLD.type, 'notified_serial', OLD.notified_serial, 'account', OLD.account, 'catalog', OLD.catalog),
          NULL);
END;

-- records
DROP TRIGGER IF EXISTS karidns_audit_records_ins;
CREATE TRIGGER karidns_audit_records_ins AFTER INSERT ON records
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'records', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          NULL,
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'name', NEW.name, 'type', NEW.type, 'content', NEW.content, 'ttl', NEW.ttl, 'prio', NEW.prio, 'disabled', NEW.disabled, 'ordername', NEW.ordername, 'auth', NEW.auth));
END;
DROP TRIGGER IF EXISTS karidns_audit_records_upd;
CREATE TRIGGER karidns_audit_records_upd AFTER UPDATE ON records
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'records', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'name', OLD.name, 'type', OLD.type, 'content', OLD.content, 'ttl', OLD.ttl, 'prio', OLD.prio, 'disabled', OLD.disabled, 'ordername', OLD.ordername, 'auth', OLD.auth),
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'name', NEW.name, 'type', NEW.type, 'content', NEW.content, 'ttl', NEW.ttl, 'prio', NEW.prio, 'disabled', NEW.disabled, 'ordername', NEW.ordername, 'auth', NEW.auth));
END;
DROP TRIGGER IF EXISTS karidns_audit_records_del;
CREATE TRIGGER karidns_audit_records_del AFTER DELETE ON records
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'records', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), OLD.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'name', OLD.name, 'type', OLD.type, 'content', OLD.content, 'ttl', OLD.ttl, 'prio', OLD.prio, 'disabled', OLD.disabled, 'ordername', OLD.ordername, 'auth', OLD.auth),
          NULL);
END;

-- domainmetadata
DROP TRIGGER IF EXISTS karidns_audit_domainmetadata_ins;
CREATE TRIGGER karidns_audit_domainmetadata_ins AFTER INSERT ON domainmetadata
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'domainmetadata', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          NULL,
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'kind', NEW.kind, 'content', NEW.content));
END;
DROP TRIGGER IF EXISTS karidns_audit_domainmetadata_upd;
CREATE TRIGGER karidns_audit_domainmetadata_upd AFTER UPDATE ON domainmetadata
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'domainmetadata', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'kind', OLD.kind, 'content', OLD.content),
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'kind', NEW.kind, 'content', NEW.content));
END;
DROP TRIGGER IF EXISTS karidns_audit_domainmetadata_del;
CREATE TRIGGER karidns_audit_domainmetadata_del AFTER DELETE ON domainmetadata
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'domainmetadata', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), OLD.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'kind', OLD.kind, 'content', OLD.content),
          NULL);
END;

-- cryptokeys
DROP TRIGGER IF EXISTS karidns_audit_cryptokeys_ins;
CREATE TRIGGER karidns_audit_cryptokeys_ins AFTER INSERT ON cryptokeys
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'cryptokeys', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          NULL,
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'flags', NEW.flags, 'active', NEW.active, 'published', NEW.published, 'content', CASE WHEN NEW.content IS NULL THEN NULL ELSE '<redacted>' END));
END;
DROP TRIGGER IF EXISTS karidns_audit_cryptokeys_upd;
CREATE TRIGGER karidns_audit_cryptokeys_upd AFTER UPDATE ON cryptokeys
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'cryptokeys', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'flags', OLD.flags, 'active', OLD.active, 'published', OLD.published, 'content', CASE WHEN OLD.content IS NULL THEN NULL ELSE '<redacted>' END),
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'flags', NEW.flags, 'active', NEW.active, 'published', NEW.published, 'content', CASE WHEN NEW.content IS NULL THEN NULL ELSE '<redacted>' END));
END;
DROP TRIGGER IF EXISTS karidns_audit_cryptokeys_del;
CREATE TRIGGER karidns_audit_cryptokeys_del AFTER DELETE ON cryptokeys
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'cryptokeys', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), OLD.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'flags', OLD.flags, 'active', OLD.active, 'published', OLD.published, 'content', CASE WHEN OLD.content IS NULL THEN NULL ELSE '<redacted>' END),
          NULL);
END;

-- karidns_record_tags
DROP TRIGGER IF EXISTS karidns_audit_karidns_record_tags_ins;
CREATE TRIGGER karidns_audit_karidns_record_tags_ins AFTER INSERT ON karidns_record_tags
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_record_tags', 'I', (SELECT lower(name) FROM domains WHERE id = (SELECT domain_id FROM records WHERE id = NEW.record_id)), NEW.record_id,
          NULL,
          json_object('record_id', NEW.record_id, 'location_tag', NEW.location_tag, 'ecs_tag', NEW.ecs_tag));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_record_tags_upd;
CREATE TRIGGER karidns_audit_karidns_record_tags_upd AFTER UPDATE ON karidns_record_tags
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_record_tags', 'U', (SELECT lower(name) FROM domains WHERE id = (SELECT domain_id FROM records WHERE id = NEW.record_id)), NEW.record_id,
          json_object('record_id', OLD.record_id, 'location_tag', OLD.location_tag, 'ecs_tag', OLD.ecs_tag),
          json_object('record_id', NEW.record_id, 'location_tag', NEW.location_tag, 'ecs_tag', NEW.ecs_tag));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_record_tags_del;
CREATE TRIGGER karidns_audit_karidns_record_tags_del AFTER DELETE ON karidns_record_tags
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_record_tags', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = (SELECT domain_id FROM records WHERE id = OLD.record_id)), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = (SELECT domain_id FROM records WHERE id = OLD.record_id) ORDER BY id DESC LIMIT 1)), OLD.record_id,
          json_object('record_id', OLD.record_id, 'location_tag', OLD.location_tag, 'ecs_tag', OLD.ecs_tag),
          NULL);
END;

-- karidns_record_tinydns
DROP TRIGGER IF EXISTS karidns_audit_karidns_record_tinydns_ins;
CREATE TRIGGER karidns_audit_karidns_record_tinydns_ins AFTER INSERT ON karidns_record_tinydns
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_record_tinydns', 'I', (SELECT lower(name) FROM domains WHERE id = (SELECT domain_id FROM records WHERE id = NEW.record_id)), NEW.record_id,
          NULL,
          json_object('record_id', NEW.record_id, 'ttd', NEW.ttd, 'loc', NEW.loc, 'countdown', NEW.countdown));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_record_tinydns_upd;
CREATE TRIGGER karidns_audit_karidns_record_tinydns_upd AFTER UPDATE ON karidns_record_tinydns
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_record_tinydns', 'U', (SELECT lower(name) FROM domains WHERE id = (SELECT domain_id FROM records WHERE id = NEW.record_id)), NEW.record_id,
          json_object('record_id', OLD.record_id, 'ttd', OLD.ttd, 'loc', OLD.loc, 'countdown', OLD.countdown),
          json_object('record_id', NEW.record_id, 'ttd', NEW.ttd, 'loc', NEW.loc, 'countdown', NEW.countdown));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_record_tinydns_del;
CREATE TRIGGER karidns_audit_karidns_record_tinydns_del AFTER DELETE ON karidns_record_tinydns
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_record_tinydns', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = (SELECT domain_id FROM records WHERE id = OLD.record_id)), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = (SELECT domain_id FROM records WHERE id = OLD.record_id) ORDER BY id DESC LIMIT 1)), OLD.record_id,
          json_object('record_id', OLD.record_id, 'ttd', OLD.ttd, 'loc', OLD.loc, 'countdown', OLD.countdown),
          NULL);
END;

-- karidns_zone_tagdefs
DROP TRIGGER IF EXISTS karidns_audit_karidns_zone_tagdefs_ins;
CREATE TRIGGER karidns_audit_karidns_zone_tagdefs_ins AFTER INSERT ON karidns_zone_tagdefs
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_zone_tagdefs', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          NULL,
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'kind', NEW.kind, 'tag', NEW.tag, 'cidr', NEW.cidr));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_zone_tagdefs_upd;
CREATE TRIGGER karidns_audit_karidns_zone_tagdefs_upd AFTER UPDATE ON karidns_zone_tagdefs
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_zone_tagdefs', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'kind', OLD.kind, 'tag', OLD.tag, 'cidr', OLD.cidr),
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'kind', NEW.kind, 'tag', NEW.tag, 'cidr', NEW.cidr));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_zone_tagdefs_del;
CREATE TRIGGER karidns_audit_karidns_zone_tagdefs_del AFTER DELETE ON karidns_zone_tagdefs
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_zone_tagdefs', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), OLD.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'kind', OLD.kind, 'tag', OLD.tag, 'cidr', OLD.cidr),
          NULL);
END;

-- karidns_domain_views
DROP TRIGGER IF EXISTS karidns_audit_karidns_domain_views_ins;
CREATE TRIGGER karidns_audit_karidns_domain_views_ins AFTER INSERT ON karidns_domain_views
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_domain_views', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NULL,
          NULL,
          json_object('domain_id', NEW.domain_id, 'view_name', NEW.view_name));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_domain_views_upd;
CREATE TRIGGER karidns_audit_karidns_domain_views_upd AFTER UPDATE ON karidns_domain_views
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_domain_views', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NULL,
          json_object('domain_id', OLD.domain_id, 'view_name', OLD.view_name),
          json_object('domain_id', NEW.domain_id, 'view_name', NEW.view_name));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_domain_views_del;
CREATE TRIGGER karidns_audit_karidns_domain_views_del AFTER DELETE ON karidns_domain_views
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_domain_views', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), NULL,
          json_object('domain_id', OLD.domain_id, 'view_name', OLD.view_name),
          NULL);
END;

-- karidns_key_requests
DROP TRIGGER IF EXISTS karidns_audit_karidns_key_requests_ins;
CREATE TRIGGER karidns_audit_karidns_key_requests_ins AFTER INSERT ON karidns_key_requests
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_key_requests', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          NULL,
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'kind', NEW.kind, 'algorithm', NEW.algorithm, 'bits', NEW.bits, 'key_type', NEW.key_type, 'nsec', NEW.nsec, 'state', NEW.state, 'message', NEW.message, 'requested_by', NEW.requested_by, 'created_at', NEW.created_at, 'done_at', NEW.done_at));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_key_requests_upd;
CREATE TRIGGER karidns_audit_karidns_key_requests_upd AFTER UPDATE ON karidns_key_requests
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_key_requests', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'kind', OLD.kind, 'algorithm', OLD.algorithm, 'bits', OLD.bits, 'key_type', OLD.key_type, 'nsec', OLD.nsec, 'state', OLD.state, 'message', OLD.message, 'requested_by', OLD.requested_by, 'created_at', OLD.created_at, 'done_at', OLD.done_at),
          json_object('id', NEW.id, 'domain_id', NEW.domain_id, 'kind', NEW.kind, 'algorithm', NEW.algorithm, 'bits', NEW.bits, 'key_type', NEW.key_type, 'nsec', NEW.nsec, 'state', NEW.state, 'message', NEW.message, 'requested_by', NEW.requested_by, 'created_at', NEW.created_at, 'done_at', NEW.done_at));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_key_requests_del;
CREATE TRIGGER karidns_audit_karidns_key_requests_del AFTER DELETE ON karidns_key_requests
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_key_requests', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), OLD.id,
          json_object('id', OLD.id, 'domain_id', OLD.domain_id, 'kind', OLD.kind, 'algorithm', OLD.algorithm, 'bits', OLD.bits, 'key_type', OLD.key_type, 'nsec', OLD.nsec, 'state', OLD.state, 'message', OLD.message, 'requested_by', OLD.requested_by, 'created_at', OLD.created_at, 'done_at', OLD.done_at),
          NULL);
END;

-- karidns_signer_state
DROP TRIGGER IF EXISTS karidns_audit_karidns_signer_state_ins;
CREATE TRIGGER karidns_audit_karidns_signer_state_ins AFTER INSERT ON karidns_signer_state
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_signer_state', 'I', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.domain_id,
          NULL,
          json_object('domain_id', NEW.domain_id, 'signed_at', NEW.signed_at, 'signed_serial', NEW.signed_serial, 'min_expire', NEW.min_expire, 'next_due', NEW.next_due, 'attempts', NEW.attempts, 'last_error', NEW.last_error, 'last_duration_ms', NEW.last_duration_ms));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_signer_state_upd;
CREATE TRIGGER karidns_audit_karidns_signer_state_upd AFTER UPDATE ON karidns_signer_state
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_signer_state', 'U', (SELECT lower(name) FROM domains WHERE id = NEW.domain_id), NEW.domain_id,
          json_object('domain_id', OLD.domain_id, 'signed_at', OLD.signed_at, 'signed_serial', OLD.signed_serial, 'min_expire', OLD.min_expire, 'next_due', OLD.next_due, 'attempts', OLD.attempts, 'last_error', OLD.last_error, 'last_duration_ms', OLD.last_duration_ms),
          json_object('domain_id', NEW.domain_id, 'signed_at', NEW.signed_at, 'signed_serial', NEW.signed_serial, 'min_expire', NEW.min_expire, 'next_due', NEW.next_due, 'attempts', NEW.attempts, 'last_error', NEW.last_error, 'last_duration_ms', NEW.last_duration_ms));
END;
DROP TRIGGER IF EXISTS karidns_audit_karidns_signer_state_del;
CREATE TRIGGER karidns_audit_karidns_signer_state_del AFTER DELETE ON karidns_signer_state
BEGIN
  INSERT INTO karidns_audit_log (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_audit_actor), (SELECT principal_id FROM karidns_audit_actor), (SELECT principal_name FROM karidns_audit_actor),
          (SELECT change_set FROM karidns_audit_actor), 'karidns_signer_state', 'D', coalesce((SELECT lower(name) FROM domains WHERE id = OLD.domain_id), (SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = OLD.domain_id ORDER BY id DESC LIMIT 1)), OLD.domain_id,
          json_object('domain_id', OLD.domain_id, 'signed_at', OLD.signed_at, 'signed_serial', OLD.signed_serial, 'min_expire', OLD.min_expire, 'next_due', OLD.next_due, 'attempts', OLD.attempts, 'last_error', OLD.last_error, 'last_duration_ms', OLD.last_duration_ms),
          NULL);
END;

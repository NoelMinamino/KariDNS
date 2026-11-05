-- karidns_auth.sqlite3.sql - the users, groups, grants and the audit of the WebAdmin / API for SQLite3 (0.6.0 item B).  Schema version 3.
--
-- A file of its own, not part of the zone file: the API ATTACHes it (ATTACH DATABASE '/var/db/karidns/auth.sqlite3' AS auth), so the
-- karidns-dbloader, which only opens the zone file, can never read the password hashes in it.  Create it as the user of the API and keep it
-- mode 0600:
--     sqlite3 /var/db/karidns/auth.sqlite3 < karidns_auth.sqlite3.sql
-- It can be applied again (the tables are CREATE ... IF NOT EXISTS; every trigger is dropped and created again, so that a changed body
-- reaches an existing file).  Run PRAGMA foreign_keys=ON on the connection (the cascades of the foreign keys, and the
-- triggers below, expect it; the principals delete trigger does the cascades itself when it is off).
--
-- The same tables as the schema karidns_auth of db/karidns_ext.pgsql.sql, with these differences: there is no row level security
-- (SQLite has no roles: the API checks the grants, and the CHECKs and triggers below hold whatever does not depend on it), rr_policies
-- keeps its record types in rr_policy_types instead of an array, grants.data_schema is NULL (one zone file per API instance), and a grant
-- cannot follow the zone it names (the zones are in another file): the API removes the grants of a zone it deletes or renames.
--
--   principals, credentials, memberships, principal_closure, rr_policies, rr_policy_types, grants, schema_version (3)
--   karidns_auth_audit   who changed what in this file, before / after as JSON; password_hash and totp_secret are written as "<redacted>"
--   karidns_auth_actor   at most one row (id 1): who is writing; the API writes it first in its transaction and deletes it last
--
-- Checks without the API: the CHECK constraints (kind, canonical zone and suffix names, the suffix under the zone, role and scope, no DNSSEC
-- type in a policy, the PHC prefix of a password hash, TTL range), credentials for users only, a membership only into a group, no
-- cycle, at most 8 memberships in a chain, and the closure table (every principal and the groups it is in, directly or not), which
-- triggers keep.  This file only creates objects; it does not enable anything.

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);       -- its row is written by the last statements of this file

CREATE TABLE IF NOT EXISTS principals (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         TEXT NOT NULL CHECK (kind IN ('user', 'group')),
  name         TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 255),
  display_name TEXT NULL,
  email        TEXT NULL,
  disabled     INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  created_by   INTEGER NULL                      -- a principal id; NULL = not a principal (a script)
);

CREATE UNIQUE INDEX IF NOT EXISTS principals_lname_idx ON principals (lower(name));       -- Alice and alice are one name

CREATE TABLE IF NOT EXISTS credentials (
  principal_id        INTEGER PRIMARY KEY REFERENCES principals (id) ON DELETE CASCADE,        -- users only (trigger)
  password_hash       TEXT NULL CHECK (password_hash IS NULL OR substr(password_hash, 1, 10) = '$argon2id$' OR substr(password_hash, 1, 8) = '$scrypt$'),
  totp_secret         TEXT NULL,
  totp_enabled        INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
  oidc_issuer         TEXT NULL,
  oidc_subject        TEXT NULL,
  failed_logins       INTEGER NOT NULL DEFAULT 0,
  locked_until        TEXT NULL,
  password_changed_at TEXT NULL,
  UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE IF NOT EXISTS memberships (
  member_id INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
  group_id  INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,       -- a group (trigger)
  PRIMARY KEY (member_id, group_id),
  CHECK (member_id <> group_id)
);
CREATE INDEX IF NOT EXISTS memberships_group_idx ON memberships (group_id);

-- no foreign keys: the triggers keep it, and a principal that is being deleted must not make them fail
CREATE TABLE IF NOT EXISTS principal_closure (
  member_id INTEGER NOT NULL,
  group_id  INTEGER NOT NULL,
  depth     INTEGER NOT NULL,                    -- the shortest chain of memberships; 0 for (p, p)
  PRIMARY KEY (member_id, group_id)
);
CREATE INDEX IF NOT EXISTS principal_closure_group_idx ON principal_closure (group_id);

CREATE TABLE IF NOT EXISTS rr_policies (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  name             TEXT NOT NULL UNIQUE,
  allow_wildcard   INTEGER NOT NULL DEFAULT 0 CHECK (allow_wildcard IN (0, 1)),
  allow_delegation INTEGER NOT NULL DEFAULT 0 CHECK (allow_delegation IN (0, 1)),      -- NS below the apex
  allow_dname      INTEGER NOT NULL DEFAULT 0 CHECK (allow_dname IN (0, 1)),
  apex_editable    INTEGER NOT NULL DEFAULT 0 CHECK (apex_editable IN (0, 1)),
  ttl_min          INTEGER NOT NULL DEFAULT 0,
  ttl_max          INTEGER NOT NULL DEFAULT 2147483647,
  max_rr           INTEGER NULL CHECK (max_rr IS NULL OR max_rr >= 0),     -- NULL = no limit; the API enforces it
  created_by       INTEGER NULL,
  CHECK (ttl_min >= 0 AND ttl_min <= ttl_max)
);

-- the record types of a policy (PostgreSQL: rr_policies.allowed_types); upper case; none of the types the signer owns (also written TYPE46,
-- TYPE0047, ...: RRSIG 46, NSEC 47, DNSKEY 48, NSEC3 50, NSEC3PARAM 51, CDS 59, CDNSKEY 60) and none of the meta types that are not data
CREATE TABLE IF NOT EXISTS rr_policy_types (
  policy_id INTEGER NOT NULL REFERENCES rr_policies (id) ON DELETE CASCADE,
  type      TEXT NOT NULL CHECK (type GLOB '[A-Z]*' AND type NOT GLOB '*[^A-Z0-9]*'
                                 AND type NOT IN ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY',
                                                  'ANY', 'AXFR', 'IXFR', 'OPT', 'TSIG', 'TKEY', 'MAILA', 'MAILB')
                                 AND NOT (type GLOB 'TYPE[0-9]*' AND type NOT GLOB 'TYPE*[^0-9]*' AND CAST(substr(type, 5) AS INTEGER) IN (46, 47, 48, 50, 51, 59, 60))),
  PRIMARY KEY (policy_id, type)
);

CREATE TABLE IF NOT EXISTS grants (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  principal_id INTEGER NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
  role         TEXT NOT NULL CHECK (role IN ('global_master', 'domain_master', 'subdomain_master')),
  data_schema  TEXT NULL,                        -- NULL: this zone file
  zone_name    TEXT NULL,
  name_suffix  TEXT NULL,
  rr_policy_id INTEGER NOT NULL REFERENCES rr_policies (id) ON DELETE RESTRICT,
  granted_by   INTEGER NULL,                     -- a principal id; NULL = not a principal (a script)
  granted_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  CONSTRAINT grants_scope CHECK (
       (role = 'global_master'    AND data_schema IS NULL AND zone_name IS NULL     AND name_suffix IS NULL)
    OR (role = 'domain_master'    AND zone_name IS NOT NULL AND name_suffix IS NULL)
    OR (role = 'subdomain_master' AND zone_name IS NOT NULL AND name_suffix IS NOT NULL)),
  -- canonical names: lower case, no trailing dot, no empty label, no blank or control character (0x01-0x20, 0x7f) or NUL, 1 to 253 octets
  CONSTRAINT grants_zone_canonical CHECK (zone_name IS NULL OR (zone_name = lower(zone_name) AND length(CAST(zone_name AS BLOB)) BETWEEN 1 AND 253
    AND zone_name NOT LIKE '.%' AND zone_name NOT LIKE '%.' AND zone_name NOT LIKE '%..%'
    AND zone_name NOT GLOB ('*[' || char(1) || '-' || char(32) || char(127) || ']*') AND instr(CAST(zone_name AS BLOB), x'00') = 0)),
  CONSTRAINT grants_suffix_canonical CHECK (name_suffix IS NULL OR (name_suffix = lower(name_suffix) AND length(CAST(name_suffix AS BLOB)) BETWEEN 1 AND 253
    AND name_suffix NOT LIKE '.%' AND name_suffix NOT LIKE '%.' AND name_suffix NOT LIKE '%..%'
    AND name_suffix NOT GLOB ('*[' || char(1) || '-' || char(32) || char(127) || ']*') AND instr(CAST(name_suffix AS BLOB), x'00') = 0)),
  CONSTRAINT grants_suffix_under_zone CHECK (name_suffix IS NULL OR zone_name IS NULL
    OR name_suffix = zone_name OR substr(name_suffix, -(length(zone_name) + 1)) = '.' || zone_name)
);
CREATE INDEX IF NOT EXISTS grants_zone_idx ON grants (data_schema, zone_name);
CREATE INDEX IF NOT EXISTS grants_principal_idx ON grants (principal_id);
CREATE INDEX IF NOT EXISTS grants_policy_idx ON grants (rr_policy_id);

-- ---- credentials: users only; a principal that has credentials stays a user; a principal in a membership keeps its kind
DROP TRIGGER IF EXISTS karidns_credentials_user_only_ins;
CREATE TRIGGER karidns_credentials_user_only_ins BEFORE INSERT ON credentials
WHEN (SELECT kind FROM principals WHERE id = NEW.principal_id) IS NOT 'user'
BEGIN
  SELECT RAISE(ABORT, 'karidns_auth.credentials: the principal is not a user');
END;
DROP TRIGGER IF EXISTS karidns_credentials_user_only_upd;
CREATE TRIGGER karidns_credentials_user_only_upd BEFORE UPDATE OF principal_id ON credentials
WHEN (SELECT kind FROM principals WHERE id = NEW.principal_id) IS NOT 'user'
BEGIN
  SELECT RAISE(ABORT, 'karidns_auth.credentials: the principal is not a user');
END;
DROP TRIGGER IF EXISTS karidns_principals_kind;
CREATE TRIGGER karidns_principals_kind BEFORE UPDATE OF kind ON principals
WHEN NEW.kind <> OLD.kind
BEGIN
  SELECT RAISE(ABORT, 'karidns_auth.principals: the principal is in a membership: its kind cannot change')
   WHERE EXISTS (SELECT 1 FROM memberships WHERE member_id = OLD.id OR group_id = OLD.id);
  SELECT RAISE(ABORT, 'karidns_auth.principals: the principal has credentials: it stays a user')
   WHERE NEW.kind = 'group' AND EXISTS (SELECT 1 FROM credentials WHERE principal_id = OLD.id);
END;

-- every principal is in its own closure at depth 0
DROP TRIGGER IF EXISTS karidns_principals_self;
CREATE TRIGGER karidns_principals_self AFTER INSERT ON principals
BEGIN
  INSERT OR IGNORE INTO principal_closure (member_id, group_id, depth) VALUES (NEW.id, NEW.id, 0);
END;

-- a deleted principal takes its memberships, credentials, grants and closure rows with it (the foreign keys do it when
-- PRAGMA foreign_keys=ON; this makes it so when they are off)
DROP TRIGGER IF EXISTS karidns_principals_delete;
CREATE TRIGGER karidns_principals_delete AFTER DELETE ON principals
BEGIN
  DELETE FROM memberships WHERE member_id = OLD.id OR group_id = OLD.id;
  DELETE FROM credentials WHERE principal_id = OLD.id;
  DELETE FROM grants WHERE principal_id = OLD.id;
  DELETE FROM principal_closure WHERE member_id = OLD.id OR group_id = OLD.id;
END;

-- ---- memberships: the group is a group, no cycle, at most 8 memberships in a chain
DROP TRIGGER IF EXISTS karidns_memberships_no_update;
CREATE TRIGGER karidns_memberships_no_update BEFORE UPDATE ON memberships
BEGIN
  SELECT RAISE(ABORT, 'karidns_auth.memberships: a membership cannot be updated; delete it and insert the new one');
END;
DROP TRIGGER IF EXISTS karidns_memberships_check;
CREATE TRIGGER karidns_memberships_check BEFORE INSERT ON memberships
BEGIN
  SELECT RAISE(ABORT, 'karidns_auth.memberships: the group is not a group (a user has no members)')
   WHERE (SELECT kind FROM principals WHERE id = NEW.group_id) IS NOT 'group';
  SELECT RAISE(ABORT, 'karidns_auth.memberships: this membership would make a cycle')
   WHERE EXISTS (SELECT 1 FROM principal_closure WHERE member_id = NEW.group_id AND group_id = NEW.member_id);
  SELECT RAISE(ABORT, 'karidns_auth.memberships: this membership would nest groups more than 8 levels deep')
   WHERE (WITH RECURSIVE u(id, d) AS (
            SELECT NEW.group_id, 0
            UNION ALL
            SELECT ms.group_id, u.d + 1 FROM u JOIN memberships ms ON ms.member_id = u.id WHERE u.d < 9)
          SELECT max(d) FROM u)
       + 1
       + (WITH RECURSIVE dn(id, d) AS (
            SELECT NEW.member_id, 0
            UNION ALL
            SELECT ms.member_id, dn.d + 1 FROM dn JOIN memberships ms ON ms.group_id = dn.id WHERE dn.d < 9)
          SELECT max(d) FROM dn) > 8;
END;

-- the closure of the member and of everything below it is computed again from the memberships (a group tree is small)
DROP TRIGGER IF EXISTS karidns_memberships_closure_ins;
CREATE TRIGGER karidns_memberships_closure_ins AFTER INSERT ON memberships
BEGIN
  DELETE FROM principal_closure WHERE member_id IN (
    WITH RECURSIVE dn(id, d) AS (
      SELECT NEW.member_id, 0
      UNION ALL
      SELECT ms.member_id, dn.d + 1 FROM dn JOIN memberships ms ON ms.group_id = dn.id WHERE dn.d < 9)
    SELECT id FROM dn);
  INSERT INTO principal_closure (member_id, group_id, depth)
    SELECT root, gid, min(d) FROM (
      WITH RECURSIVE dn(id, d) AS (
        SELECT NEW.member_id, 0
        UNION ALL
        SELECT ms.member_id, dn.d + 1 FROM dn JOIN memberships ms ON ms.group_id = dn.id WHERE dn.d < 9),
      up(root, gid, d) AS (
        SELECT id, id, 0 FROM dn
        UNION ALL
        SELECT up.root, ms.group_id, up.d + 1 FROM up JOIN memberships ms ON ms.member_id = up.gid WHERE up.d < 9)
      SELECT root, gid, d FROM up WHERE root IN (SELECT id FROM principals) AND gid IN (SELECT id FROM principals))
    GROUP BY root, gid;
END;
DROP TRIGGER IF EXISTS karidns_memberships_closure_del;
CREATE TRIGGER karidns_memberships_closure_del AFTER DELETE ON memberships
BEGIN
  DELETE FROM principal_closure WHERE member_id IN (
    WITH RECURSIVE dn(id, d) AS (
      SELECT OLD.member_id, 0
      UNION ALL
      SELECT ms.member_id, dn.d + 1 FROM dn JOIN memberships ms ON ms.group_id = dn.id WHERE dn.d < 9)
    SELECT id FROM dn);
  INSERT INTO principal_closure (member_id, group_id, depth)
    SELECT root, gid, min(d) FROM (
      WITH RECURSIVE dn(id, d) AS (
        SELECT OLD.member_id, 0
        UNION ALL
        SELECT ms.member_id, dn.d + 1 FROM dn JOIN memberships ms ON ms.group_id = dn.id WHERE dn.d < 9),
      up(root, gid, d) AS (
        SELECT id, id, 0 FROM dn
        UNION ALL
        SELECT up.root, ms.group_id, up.d + 1 FROM up JOIN memberships ms ON ms.member_id = up.gid WHERE up.d < 9)
      SELECT root, gid, d FROM up WHERE root IN (SELECT id FROM principals) AND gid IN (SELECT id FROM principals))
    GROUP BY root, gid;
END;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The audit of this file (4.6): the actor, then the log.  A trigger can only read the database it is in, so the actor of this file is
-- a table of this file.  The tables of the zone file are audited by db/karidns_audit.sqlite3.sql.
CREATE TABLE IF NOT EXISTS karidns_auth_audit (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  db_role        TEXT NULL,
  principal_id   INTEGER NULL,
  principal_name TEXT NULL,
  change_set     TEXT NULL,
  data_schema    TEXT NOT NULL DEFAULT 'auth',
  table_name     TEXT NOT NULL,
  op             TEXT NOT NULL CHECK (op IN ('I', 'U', 'D')),
  zone_name      TEXT NULL,
  row_id         INTEGER NULL,
  before         TEXT NULL,
  after          TEXT NULL
);
CREATE INDEX IF NOT EXISTS karidns_auth_audit_zone_idx ON karidns_auth_audit (zone_name, at);
CREATE INDEX IF NOT EXISTS karidns_auth_audit_principal_idx ON karidns_auth_audit (principal_id, at);
CREATE INDEX IF NOT EXISTS karidns_auth_audit_change_set_idx ON karidns_auth_audit (change_set);

CREATE TABLE IF NOT EXISTS karidns_auth_actor (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  principal_id   INTEGER NULL,
  principal_name TEXT NULL,
  change_set     TEXT NULL,
  db_role        TEXT NULL
);

-- the audit triggers: one row of karidns_auth_audit per changed row; password_hash and totp_secret are written as "<redacted>"

-- principals
DROP TRIGGER IF EXISTS karidns_audit_principals_ins;
CREATE TRIGGER karidns_audit_principals_ins AFTER INSERT ON principals
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'principals', 'I', NULL, NEW.id,
          NULL,
          json_object('id', NEW.id, 'kind', NEW.kind, 'name', NEW.name, 'display_name', NEW.display_name, 'email', NEW.email, 'disabled', NEW.disabled, 'created_at', NEW.created_at, 'created_by', NEW.created_by));
END;
DROP TRIGGER IF EXISTS karidns_audit_principals_upd;
CREATE TRIGGER karidns_audit_principals_upd AFTER UPDATE ON principals
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'principals', 'U', NULL, NEW.id,
          json_object('id', OLD.id, 'kind', OLD.kind, 'name', OLD.name, 'display_name', OLD.display_name, 'email', OLD.email, 'disabled', OLD.disabled, 'created_at', OLD.created_at, 'created_by', OLD.created_by),
          json_object('id', NEW.id, 'kind', NEW.kind, 'name', NEW.name, 'display_name', NEW.display_name, 'email', NEW.email, 'disabled', NEW.disabled, 'created_at', NEW.created_at, 'created_by', NEW.created_by));
END;
DROP TRIGGER IF EXISTS karidns_audit_principals_del;
CREATE TRIGGER karidns_audit_principals_del AFTER DELETE ON principals
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'principals', 'D', NULL, OLD.id,
          json_object('id', OLD.id, 'kind', OLD.kind, 'name', OLD.name, 'display_name', OLD.display_name, 'email', OLD.email, 'disabled', OLD.disabled, 'created_at', OLD.created_at, 'created_by', OLD.created_by),
          NULL);
END;

-- credentials
DROP TRIGGER IF EXISTS karidns_audit_credentials_ins;
CREATE TRIGGER karidns_audit_credentials_ins AFTER INSERT ON credentials
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'credentials', 'I', NULL, NEW.principal_id,
          NULL,
          json_object('principal_id', NEW.principal_id, 'password_hash', CASE WHEN NEW.password_hash IS NULL THEN NULL ELSE '<redacted>' END, 'totp_secret', CASE WHEN NEW.totp_secret IS NULL THEN NULL ELSE '<redacted>' END, 'totp_enabled', NEW.totp_enabled, 'oidc_issuer', NEW.oidc_issuer, 'oidc_subject', NEW.oidc_subject, 'failed_logins', NEW.failed_logins, 'locked_until', NEW.locked_until, 'password_changed_at', NEW.password_changed_at));
END;
DROP TRIGGER IF EXISTS karidns_audit_credentials_upd;
CREATE TRIGGER karidns_audit_credentials_upd AFTER UPDATE ON credentials
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'credentials', 'U', NULL, NEW.principal_id,
          json_object('principal_id', OLD.principal_id, 'password_hash', CASE WHEN OLD.password_hash IS NULL THEN NULL ELSE '<redacted>' END, 'totp_secret', CASE WHEN OLD.totp_secret IS NULL THEN NULL ELSE '<redacted>' END, 'totp_enabled', OLD.totp_enabled, 'oidc_issuer', OLD.oidc_issuer, 'oidc_subject', OLD.oidc_subject, 'failed_logins', OLD.failed_logins, 'locked_until', OLD.locked_until, 'password_changed_at', OLD.password_changed_at),
          json_object('principal_id', NEW.principal_id, 'password_hash', CASE WHEN NEW.password_hash IS NULL THEN NULL ELSE '<redacted>' END, 'totp_secret', CASE WHEN NEW.totp_secret IS NULL THEN NULL ELSE '<redacted>' END, 'totp_enabled', NEW.totp_enabled, 'oidc_issuer', NEW.oidc_issuer, 'oidc_subject', NEW.oidc_subject, 'failed_logins', NEW.failed_logins, 'locked_until', NEW.locked_until, 'password_changed_at', NEW.password_changed_at));
END;
DROP TRIGGER IF EXISTS karidns_audit_credentials_del;
CREATE TRIGGER karidns_audit_credentials_del AFTER DELETE ON credentials
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'credentials', 'D', NULL, OLD.principal_id,
          json_object('principal_id', OLD.principal_id, 'password_hash', CASE WHEN OLD.password_hash IS NULL THEN NULL ELSE '<redacted>' END, 'totp_secret', CASE WHEN OLD.totp_secret IS NULL THEN NULL ELSE '<redacted>' END, 'totp_enabled', OLD.totp_enabled, 'oidc_issuer', OLD.oidc_issuer, 'oidc_subject', OLD.oidc_subject, 'failed_logins', OLD.failed_logins, 'locked_until', OLD.locked_until, 'password_changed_at', OLD.password_changed_at),
          NULL);
END;

-- memberships
DROP TRIGGER IF EXISTS karidns_audit_memberships_ins;
CREATE TRIGGER karidns_audit_memberships_ins AFTER INSERT ON memberships
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'memberships', 'I', NULL, NULL,
          NULL,
          json_object('member_id', NEW.member_id, 'group_id', NEW.group_id));
END;
DROP TRIGGER IF EXISTS karidns_audit_memberships_upd;
CREATE TRIGGER karidns_audit_memberships_upd AFTER UPDATE ON memberships
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'memberships', 'U', NULL, NULL,
          json_object('member_id', OLD.member_id, 'group_id', OLD.group_id),
          json_object('member_id', NEW.member_id, 'group_id', NEW.group_id));
END;
DROP TRIGGER IF EXISTS karidns_audit_memberships_del;
CREATE TRIGGER karidns_audit_memberships_del AFTER DELETE ON memberships
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'memberships', 'D', NULL, NULL,
          json_object('member_id', OLD.member_id, 'group_id', OLD.group_id),
          NULL);
END;

-- rr_policies
DROP TRIGGER IF EXISTS karidns_audit_rr_policies_ins;
CREATE TRIGGER karidns_audit_rr_policies_ins AFTER INSERT ON rr_policies
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'rr_policies', 'I', NULL, NEW.id,
          NULL,
          json_object('id', NEW.id, 'name', NEW.name, 'allow_wildcard', NEW.allow_wildcard, 'allow_delegation', NEW.allow_delegation, 'allow_dname', NEW.allow_dname, 'apex_editable', NEW.apex_editable, 'ttl_min', NEW.ttl_min, 'ttl_max', NEW.ttl_max, 'max_rr', NEW.max_rr, 'created_by', NEW.created_by));
END;
DROP TRIGGER IF EXISTS karidns_audit_rr_policies_upd;
CREATE TRIGGER karidns_audit_rr_policies_upd AFTER UPDATE ON rr_policies
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'rr_policies', 'U', NULL, NEW.id,
          json_object('id', OLD.id, 'name', OLD.name, 'allow_wildcard', OLD.allow_wildcard, 'allow_delegation', OLD.allow_delegation, 'allow_dname', OLD.allow_dname, 'apex_editable', OLD.apex_editable, 'ttl_min', OLD.ttl_min, 'ttl_max', OLD.ttl_max, 'max_rr', OLD.max_rr, 'created_by', OLD.created_by),
          json_object('id', NEW.id, 'name', NEW.name, 'allow_wildcard', NEW.allow_wildcard, 'allow_delegation', NEW.allow_delegation, 'allow_dname', NEW.allow_dname, 'apex_editable', NEW.apex_editable, 'ttl_min', NEW.ttl_min, 'ttl_max', NEW.ttl_max, 'max_rr', NEW.max_rr, 'created_by', NEW.created_by));
END;
DROP TRIGGER IF EXISTS karidns_audit_rr_policies_del;
CREATE TRIGGER karidns_audit_rr_policies_del AFTER DELETE ON rr_policies
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'rr_policies', 'D', NULL, OLD.id,
          json_object('id', OLD.id, 'name', OLD.name, 'allow_wildcard', OLD.allow_wildcard, 'allow_delegation', OLD.allow_delegation, 'allow_dname', OLD.allow_dname, 'apex_editable', OLD.apex_editable, 'ttl_min', OLD.ttl_min, 'ttl_max', OLD.ttl_max, 'max_rr', OLD.max_rr, 'created_by', OLD.created_by),
          NULL);
END;

-- rr_policy_types
DROP TRIGGER IF EXISTS karidns_audit_rr_policy_types_ins;
CREATE TRIGGER karidns_audit_rr_policy_types_ins AFTER INSERT ON rr_policy_types
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'rr_policy_types', 'I', NULL, NULL,
          NULL,
          json_object('policy_id', NEW.policy_id, 'type', NEW.type));
END;
DROP TRIGGER IF EXISTS karidns_audit_rr_policy_types_upd;
CREATE TRIGGER karidns_audit_rr_policy_types_upd AFTER UPDATE ON rr_policy_types
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'rr_policy_types', 'U', NULL, NULL,
          json_object('policy_id', OLD.policy_id, 'type', OLD.type),
          json_object('policy_id', NEW.policy_id, 'type', NEW.type));
END;
DROP TRIGGER IF EXISTS karidns_audit_rr_policy_types_del;
CREATE TRIGGER karidns_audit_rr_policy_types_del AFTER DELETE ON rr_policy_types
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'rr_policy_types', 'D', NULL, NULL,
          json_object('policy_id', OLD.policy_id, 'type', OLD.type),
          NULL);
END;

-- grants
DROP TRIGGER IF EXISTS karidns_audit_grants_ins;
CREATE TRIGGER karidns_audit_grants_ins AFTER INSERT ON grants
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'grants', 'I', NEW.zone_name, NEW.id,
          NULL,
          json_object('id', NEW.id, 'principal_id', NEW.principal_id, 'role', NEW.role, 'data_schema', NEW.data_schema, 'zone_name', NEW.zone_name, 'name_suffix', NEW.name_suffix, 'rr_policy_id', NEW.rr_policy_id, 'granted_by', NEW.granted_by, 'granted_at', NEW.granted_at));
END;
DROP TRIGGER IF EXISTS karidns_audit_grants_upd;
CREATE TRIGGER karidns_audit_grants_upd AFTER UPDATE ON grants
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'grants', 'U', NEW.zone_name, NEW.id,
          json_object('id', OLD.id, 'principal_id', OLD.principal_id, 'role', OLD.role, 'data_schema', OLD.data_schema, 'zone_name', OLD.zone_name, 'name_suffix', OLD.name_suffix, 'rr_policy_id', OLD.rr_policy_id, 'granted_by', OLD.granted_by, 'granted_at', OLD.granted_at),
          json_object('id', NEW.id, 'principal_id', NEW.principal_id, 'role', NEW.role, 'data_schema', NEW.data_schema, 'zone_name', NEW.zone_name, 'name_suffix', NEW.name_suffix, 'rr_policy_id', NEW.rr_policy_id, 'granted_by', NEW.granted_by, 'granted_at', NEW.granted_at));
END;
DROP TRIGGER IF EXISTS karidns_audit_grants_del;
CREATE TRIGGER karidns_audit_grants_del AFTER DELETE ON grants
BEGIN
  INSERT INTO karidns_auth_audit (db_role, principal_id, principal_name, change_set, table_name, op, zone_name, row_id, before, after)
  VALUES ((SELECT db_role FROM karidns_auth_actor), (SELECT principal_id FROM karidns_auth_actor), (SELECT principal_name FROM karidns_auth_actor),
          (SELECT change_set FROM karidns_auth_actor), 'grants', 'D', OLD.zone_name, OLD.id,
          json_object('id', OLD.id, 'principal_id', OLD.principal_id, 'role', OLD.role, 'data_schema', OLD.data_schema, 'zone_name', OLD.zone_name, 'name_suffix', OLD.name_suffix, 'rr_policy_id', OLD.rr_policy_id, 'granted_by', OLD.granted_by, 'granted_at', OLD.granted_at),
          NULL);
END;

-- the version, last: a fresh file whose creation fails halfway has no version row
INSERT INTO schema_version (version) SELECT 3 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
UPDATE schema_version SET version = 3 WHERE version < 3;

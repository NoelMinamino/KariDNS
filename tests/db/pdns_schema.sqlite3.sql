-- tests/db/pdns_schema.sqlite3.sql - the tables of the PowerDNS 5.1 generic SQLite3 backend that karidns-dbloader
-- reads, written for the KariDNS tests from the column list of design 3.1 (names and types as PowerDNS 5.1 uses them;
-- indexes reduced to what the loader's queries use).  It is our own DDL, not a copy of PowerDNS's schema file.
--
-- Use:  sqlite3 DB < tests/db/pdns_schema.sqlite3.sql        (switches the file to WAL, which the loader requires)

PRAGMA journal_mode = WAL;

CREATE TABLE domains (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL COLLATE NOCASE,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INTEGER DEFAULT NULL,
  type                  VARCHAR(8) NOT NULL,
  notified_serial       INTEGER UNSIGNED DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  options               VARCHAR(65535) DEFAULT NULL,
  catalog               VARCHAR(255) DEFAULT NULL
);
CREATE UNIQUE INDEX name_index ON domains(name);
CREATE INDEX catalog_idx ON domains(catalog);

CREATE TABLE records (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INTEGER DEFAULT NULL,
  prio                  INTEGER DEFAULT NULL,
  disabled              BOOLEAN DEFAULT 0,
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 1
);
CREATE INDEX records_lookup_idx ON records(name, type);
CREATE INDEX records_lookup_id_idx ON records(domain_id, name, type);
CREATE INDEX records_order_idx ON records(domain_id, ordername);

CREATE TABLE domainmetadata (
  id                    INTEGER PRIMARY KEY,
  domain_id             INT NOT NULL,
  kind                  VARCHAR(32) COLLATE NOCASE,
  content               TEXT
);
CREATE INDEX domainmetaidindex ON domainmetadata(domain_id);

CREATE TABLE cryptokeys (
  id                    INTEGER PRIMARY KEY,
  domain_id             INT NOT NULL,
  flags                 INT NOT NULL,
  active                BOOL,
  published             BOOL DEFAULT 1,
  content               TEXT
);
CREATE INDEX domainidindex ON cryptokeys(domain_id);

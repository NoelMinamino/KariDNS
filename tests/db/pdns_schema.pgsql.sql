-- tests/db/pdns_schema.pgsql.sql - the tables of the PowerDNS 5.1 generic PostgreSQL backend that karidns-dbloader
-- reads, written for the KariDNS tests from the column list of design 3.1 (names and types as PowerDNS 5.1 uses them;
-- indexes reduced to what the loader's queries use).  It is our own DDL, not a copy of PowerDNS's schema file.
--
-- Use:  psql -v ON_ERROR_STOP=1 -f tests/db/pdns_schema.pgsql.sql DATABASE

CREATE TABLE domains (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INT DEFAULT NULL,
  type                  TEXT NOT NULL,
  notified_serial       BIGINT DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  options               TEXT DEFAULT NULL,
  catalog               TEXT DEFAULT NULL,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);
CREATE UNIQUE INDEX name_index ON domains(name);
CREATE INDEX catalog_idx ON domains(catalog);

CREATE TABLE records (
  id                    BIGSERIAL PRIMARY KEY,
  domain_id             INT DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INT DEFAULT NULL,
  prio                  INT DEFAULT NULL,
  disabled              BOOL DEFAULT 'f',
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 't',
  CONSTRAINT domain_exists FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);
CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);

CREATE TABLE domainmetadata (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  kind                  VARCHAR(32),
  content               TEXT
);
CREATE INDEX domainidmetaindex ON domainmetadata(domain_id);

CREATE TABLE cryptokeys (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  flags                 INT NOT NULL,
  active                BOOL,
  published             BOOL DEFAULT TRUE,
  content               TEXT
);
CREATE INDEX domainidindex ON cryptokeys(domain_id);

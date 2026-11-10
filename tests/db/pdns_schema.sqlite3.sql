-- tests/db/pdns_schema.sqlite3.sql: the four PowerDNS 5.1 tables (generic SQLite3 backend) that karidns-dbloader
-- reads, for the KariDNS tests only.  Written for KariDNS from the column list of design 3.1: the table and column
-- names and the column types are those a PowerDNS 5.1 database has (they are the interface the loader reads), and
-- so is the name of the unique index on domains.name (name_index: tests drop it to see the loader cope without it).
-- Everything else here (layout, the other index names, which indexes exist) is our own; the tables PowerDNS has and
-- the loader does not read are left out.  It is not PowerDNS's schema file: a real installation takes that one from
-- PowerDNS (docs/karidns-dbloader.md).
--
-- Use:  sqlite3 DB < tests/db/pdns_schema.sqlite3.sql        (switches the file to WAL, which the loader requires)

PRAGMA journal_mode = WAL;

-- one row per zone
CREATE TABLE domains (
    id integer PRIMARY KEY,
    name varchar(255) NOT NULL COLLATE NOCASE,
    master varchar(128) DEFAULT NULL,
    last_check integer DEFAULT NULL,
    type varchar(8) NOT NULL,
    notified_serial integer unsigned DEFAULT NULL,
    account varchar(40) DEFAULT NULL,
    options varchar(65535) DEFAULT NULL,
    catalog varchar(255) DEFAULT NULL
);
CREATE UNIQUE INDEX name_index ON domains (name);
CREATE INDEX domains_catalog_idx ON domains (catalog);

-- one row per record (content: the RDATA in presentation form, prio: MX / SRV preference)
CREATE TABLE records (
    id integer PRIMARY KEY,
    domain_id integer DEFAULT NULL,
    name varchar(255) DEFAULT NULL,
    type varchar(10) DEFAULT NULL,
    content varchar(65535) DEFAULT NULL,
    ttl integer DEFAULT NULL,
    prio integer DEFAULT NULL,
    disabled boolean DEFAULT 0,
    ordername varchar(255),
    auth bool DEFAULT 1
);
CREATE INDEX records_lookup_idx ON records (name, type);
CREATE INDEX records_lookup_id_idx ON records (domain_id, name, type);
CREATE INDEX records_order_idx ON records (domain_id, ordername);

-- settings per zone (kind / content pairs)
CREATE TABLE domainmetadata (
    id integer PRIMARY KEY,
    domain_id int NOT NULL,
    kind varchar(32) COLLATE NOCASE,
    content text
);
CREATE INDEX domainmetadata_domain_idx ON domainmetadata (domain_id);

-- DNSSEC keys (the loader only learns from it whether a zone has keys)
CREATE TABLE cryptokeys (
    id integer PRIMARY KEY,
    domain_id int NOT NULL,
    flags int NOT NULL,
    active bool,
    published bool DEFAULT 1,
    content text
);
CREATE INDEX cryptokeys_domain_idx ON cryptokeys (domain_id);

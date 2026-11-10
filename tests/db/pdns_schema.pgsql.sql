-- tests/db/pdns_schema.pgsql.sql: the four PowerDNS 5.1 tables (generic PostgreSQL backend) that karidns-dbloader
-- reads, for the KariDNS tests only.  Written for KariDNS from the column list of design 3.1: the table and column
-- names and the column types are those a PowerDNS 5.1 database has (they are the interface the loader reads), and so
-- are the name of the unique index on domains.name (name_index) and of the lower-case checks (c_lowercase_name):
-- tests drop them to see the loader cope with a database without them.  Everything else here (layout, how the checks
-- are written, the other index and constraint names, which indexes exist) is our own; the tables PowerDNS has and the
-- loader does not read are left out.  It is not PowerDNS's schema file: a real installation takes that one from
-- PowerDNS (docs/karidns-dbloader.md).
--
-- Use:  psql -v ON_ERROR_STOP=1 -f tests/db/pdns_schema.pgsql.sql DATABASE

-- one row per zone; zone names in lower case
CREATE TABLE domains (
    id serial PRIMARY KEY,
    name varchar(255) NOT NULL CONSTRAINT c_lowercase_name CHECK (name = lower(name)),
    master varchar(128) DEFAULT NULL,
    last_check int DEFAULT NULL,
    type text NOT NULL,
    notified_serial bigint DEFAULT NULL,
    account varchar(40) DEFAULT NULL,
    options text DEFAULT NULL,
    catalog text DEFAULT NULL
);
CREATE UNIQUE INDEX name_index ON domains (name);
CREATE INDEX domains_catalog_idx ON domains (catalog);

-- one row per record (content: the RDATA in presentation form, prio: MX / SRV preference); owner names in lower case
CREATE TABLE records (
    id bigserial PRIMARY KEY,
    domain_id int DEFAULT NULL CONSTRAINT records_domain_fk REFERENCES domains (id) ON DELETE CASCADE,
    name varchar(255) DEFAULT NULL CONSTRAINT c_lowercase_name CHECK (name = lower(name)),
    type varchar(10) DEFAULT NULL,
    content varchar(65535) DEFAULT NULL,
    ttl int DEFAULT NULL,
    prio int DEFAULT NULL,
    disabled bool DEFAULT false,
    ordername varchar(255),
    auth bool DEFAULT true
);
CREATE INDEX records_name_idx ON records (name);
CREATE INDEX records_name_type_idx ON records (name, type);
CREATE INDEX records_domain_idx ON records (domain_id);

-- settings per zone (kind / content pairs)
CREATE TABLE domainmetadata (
    id serial PRIMARY KEY,
    domain_id int REFERENCES domains (id) ON DELETE CASCADE,
    kind varchar(32),
    content text
);
CREATE INDEX domainmetadata_domain_idx ON domainmetadata (domain_id);

-- DNSSEC keys (the loader only learns from it whether a zone has keys)
CREATE TABLE cryptokeys (
    id serial PRIMARY KEY,
    domain_id int REFERENCES domains (id) ON DELETE CASCADE,
    flags int NOT NULL,
    active bool,
    published bool DEFAULT true,
    content text
);
CREATE INDEX cryptokeys_domain_idx ON cryptokeys (domain_id);

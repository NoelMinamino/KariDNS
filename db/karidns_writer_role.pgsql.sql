-- karidns_writer_role.pgsql.sql - the privileges of the PostgreSQL role that the ZoneImporter (karidns-zone import, dns_zone_import.c) connects as
-- (0.6.0, milestone M2).  The importer replaces or merges the records of a zone, the metadata it owns and the karidns_* rows of the zone, in one
-- transaction.  It never needs the key material of cryptokeys.
--
-- Manual: docs/karidns-dbloader.md (the schema and trigger files, the privileges, the drivers).  The packages karidns-sqlite3, karidns-postgresql
-- and karidns-db install this file in /usr/local/share/karidns/db/, next to karidns_loader_role.pgsql.sql (which the server's loader uses; do
-- not give the loader the rights of this role).
--
-- Create the role yourself (authentication is yours; a UNIX socket with peer authentication for the user who runs the importer is the simplest),
-- then, as a superuser (or the owner of the tables with CREATEROLE):
--     psql -v ON_ERROR_STOP=1 -v role=karidns_writer -v schema=public -f karidns_writer_role.pgsql.sql karidns
-- `role` is the importer's role, `schema` the schema that holds the PowerDNS and karidns_* tables (one run per schema when the views have schemas
-- of their own).  The script can be run again.
--
--   CREATE ROLE karidns_writer LOGIN;            -- or: ... LOGIN PASSWORD '...' for TCP with scram-sha-256
--
-- What it grants:
--   USAGE on the schema.
--   SELECT, INSERT, UPDATE, DELETE on domains, records and domainmetadata (the zone, its records, the metadata the importer owns:
--   PRESIGNED, NSEC3PARAM, X-KARIDNS-FORMAT; every other metadata row is only read, never touched).
--   SELECT on every karidns_* table of the schema (the schema version, the views, ...), and SELECT, INSERT, UPDATE, DELETE on the zone tables
--   the importer writes: karidns_domain_views, karidns_record_tags, karidns_record_tinydns, karidns_zone_tagdefs.
--   The change log: the triggers of db/karidns_ext.pgsql.sql run with the rights of the role that writes, so the importer needs INSERT on
--   karidns_changes (and SELECT and DELETE: the prune trigger deletes the oldest rows) and INSERT on karidns_reload_requests (`import --reload`;
--   the same prune trigger needs SELECT and DELETE there).
--   INSERT on karidns_zone_versions and karidns_zone_version_rrsets (the history of a zone: `import` and `apply` write a version row in the transaction of the
--   change; nothing but the prune trigger of the owner deletes them).
--   USAGE on the sequences of the tables above (domains.id, records.id, karidns_zone_tagdefs.id, karidns_changes.seq, karidns_zone_versions.id are serial columns).
--   cryptokeys: everything is revoked first, then only the COLUMN privilege SELECT (domain_id): the importer asks whether a zone has keys (to warn
--   that data without DNSSEC records makes the loader refuse a zone with keys).  It can never read `content`, the private keys.
--   Nothing on karidns_profiles (beyond SELECT), karidns_server_status, supermasters, comments, tsigkeys, ...
--   The role is not default_transaction_read_only: the importer's transactions write.

\if :{?role}
\else
\echo 'usage: psql -v ON_ERROR_STOP=1 -v role=ROLE -v schema=SCHEMA -f karidns_writer_role.pgsql.sql DATABASE'
\quit
\endif
\if :{?schema}
\else
\set schema public
\endif

GRANT USAGE ON SCHEMA :"schema" TO :"role";
GRANT SELECT, INSERT, UPDATE, DELETE ON :"schema".domains, :"schema".records, :"schema".domainmetadata TO :"role";
REVOKE ALL ON :"schema".cryptokeys FROM :"role";
GRANT SELECT (domain_id) ON :"schema".cryptokeys TO :"role";

-- every karidns_* table can be read (the schema version, the views, the tag tables)
SELECT format('GRANT SELECT ON %I.%I TO %I', :'schema', c.relname, :'role')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = :'schema' AND c.relkind IN ('r', 'p') AND c.relname LIKE 'karidns\_%' ESCAPE '\'
 ORDER BY c.relname
\gexec

-- the zone tables the importer writes
SELECT format('GRANT INSERT, UPDATE, DELETE ON %I.%I TO %I', :'schema', c.relname, :'role')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = :'schema' AND c.relkind IN ('r', 'p')
   AND c.relname IN ('karidns_domain_views', 'karidns_record_tags', 'karidns_record_tinydns', 'karidns_zone_tagdefs')
\gexec

-- the zone versions (item E): `import` and `apply` write one row per change; the prune trigger of the table deletes the old ones as the owner
SELECT format('GRANT INSERT ON %I.%I TO %I', :'schema', c.relname, :'role')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = :'schema' AND c.relkind IN ('r', 'p') AND c.relname IN ('karidns_zone_versions', 'karidns_zone_version_rrsets')
\gexec

-- the change log and the reload requests: written by the triggers (and by `import --reload`); pruned by their prune triggers
SELECT format('GRANT INSERT, DELETE ON %I.%I TO %I', :'schema', c.relname, :'role')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = :'schema' AND c.relkind IN ('r', 'p') AND c.relname IN ('karidns_changes', 'karidns_reload_requests')
\gexec

-- the sequences behind the serial columns of the tables the importer inserts into
SELECT format('GRANT USAGE ON SEQUENCE %I.%I TO %I', n.nspname, s.relname, :'role')
  FROM pg_class s
  JOIN pg_namespace n ON n.oid = s.relnamespace
  JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
  JOIN pg_class t ON t.oid = d.refobjid AND t.relnamespace = n.oid
 WHERE s.relkind = 'S' AND n.nspname = :'schema'
   AND t.relname IN ('domains', 'records', 'domainmetadata', 'karidns_zone_tagdefs', 'karidns_changes', 'karidns_zone_versions')
\gexec

-- Row level security (0.6.0 item B): once db/karidns_api_role.pgsql.sql or db/karidns_signer_role.pgsql.sql has switched RLS on for the tables of the
-- schema, a role without a policy sees no row.  karidns-zone is not bound by grants, so it joins karidns_rls_trusted, a NOLOGIN role whose policy on each of
-- those tables is USING (true) WITH CHECK (true); the role is created here if it is missing, so this script and the API / signer scripts work in either
-- order.  It gets nothing on karidns_auth (users, grants, credentials, the audit log).  Without RLS the membership changes nothing.
SELECT 'CREATE ROLE karidns_rls_trusted NOLOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'karidns_rls_trusted')
\gexec
GRANT karidns_rls_trusted TO :"role";

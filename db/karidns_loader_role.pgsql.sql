-- karidns_loader_role.pgsql.sql - the privileges of the PostgreSQL role that karidns-dbloader connects as (beta design 2.2, 7.1,
-- D11; milestone B10).  The loader only reads: SELECT on the PowerDNS tables it uses and on the karidns_* tables, and
-- nothing on the key material of cryptokeys.
--
-- Create the role yourself (authentication is yours: a UNIX socket with peer authentication for the user the loader runs
-- as is the simplest, see `conninfo-file` in docs/karidns.md), then, as the owner of the tables:
--     psql -v ON_ERROR_STOP=1 -v role=karidns_loader -v schema=public -f karidns_loader_role.pgsql.sql karidns
-- `role` is the loader's role, `schema` the schema that holds the PowerDNS and karidns_* tables (one run per schema when the
-- views have schemas of their own).  The script can be run again.
--
--   CREATE ROLE karidns_loader LOGIN;            -- or: ... LOGIN PASSWORD '...' for TCP with scram-sha-256
--
-- What it grants:
--   USAGE on the schema; SELECT on domains, records, domainmetadata; SELECT on every karidns_* table of the schema
--   (karidns_changes, karidns_domain_views, karidns_profiles, karidns_record_tags, karidns_record_tinydns,
--   karidns_zone_tagdefs, karidns_schema_version).  cryptokeys gets only the COLUMN privilege SELECT (domain_id, active,
--   published): the loader asks which zones have keys (a zone with keys but without PRESIGNED metadata is refused) and can
--   never read `content`, the private keys.  Everything else is revoked from the role on cryptokeys first.
--   default_transaction_read_only = on for the role (the loader also sets it per session and begins READ ONLY transactions).
-- Multi-server status (B11) will add INSERT / UPDATE on karidns_server_status for the same role.

\if :{?role}
\else
\echo 'usage: psql -v ON_ERROR_STOP=1 -v role=ROLE -v schema=SCHEMA -f karidns_loader_role.pgsql.sql DATABASE'
\quit
\endif
\if :{?schema}
\else
\set schema public
\endif

GRANT USAGE ON SCHEMA :"schema" TO :"role";
GRANT SELECT ON :"schema".domains, :"schema".records, :"schema".domainmetadata TO :"role";
REVOKE ALL ON :"schema".cryptokeys FROM :"role";
GRANT SELECT (domain_id, active, published) ON :"schema".cryptokeys TO :"role";

SELECT format('GRANT SELECT ON %I.%I TO %I', :'schema', c.relname, :'role')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = :'schema' AND c.relkind IN ('r', 'p') AND c.relname LIKE 'karidns\_%' ESCAPE '\'
 ORDER BY c.relname
\gexec

ALTER ROLE :"role" SET default_transaction_read_only = on;

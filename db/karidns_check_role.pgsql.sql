-- karidns_check_role.pgsql.sql - the privileges of the PostgreSQL role the KariDNS WebAdmin API runs its CHECK runs as: `karidns-zone apply --dry-run`
-- (0.6.0 items D and E; docs/karidns-zone.md "apply", docs/karidns-dbloader.md "The check role").
--
-- Why a role of its own.  A change set of a subdomain master has to be checked against the WHOLE zone (a CNAME beside other data, the size limits, the
-- loader's reader), and row level security shows the API's session only the part of the zone the principal has a grant on.  So the API runs the dry run as
-- a TRUSTED session: a member of karidns_rls_trusted, which sees every row and passes every write policy, and which writes the change, reads the zone back
-- through the loader's reader, and rolls back.  This session must never be able to change the database.  The role is therefore a member of the group role
-- karidns_never_commit, and a deferred constraint trigger on every table the dry run writes (karidns_auth.enable_never_commit) refuses the COMMIT of
-- any transaction of such a session that wrote a row: the transaction is rolled back with "the check role never commits".  The role cannot drop the
-- triggers (it owns nothing), cannot turn them off (it is not a superuser), and SET ROLE does not help (the triggers look at the login role).
--
-- Run it as the owner of the PowerDNS tables, who applied db/karidns_ext.pgsql.sql (schema version 3) and has CREATEROLE:
--     psql -v ON_ERROR_STOP=1 -v role=karidns_check -v schema=public -f karidns_check_role.pgsql.sql karidns
-- `role` is the check role (created as a NOLOGIN group role when it does not exist: GRANT it to the login role the API uses for its check runs, or create
-- the role yourself first, with LOGIN), `schema` the schema that holds the PowerDNS and karidns_* tables (one run per schema).  The script can be run again.
-- It STOPS (before it changes anything) when the role is a superuser, or is (or is a member of) the owner of the tables, or is (or is a member of) an API role.
--
-- What it does: everything db/karidns_writer_role.pgsql.sql does for the role (SELECT, INSERT, UPDATE, DELETE on domains, records, domainmetadata and the zone
-- tables, SELECT on every karidns_* table, INSERT on the zone versions, nothing on cryptokeys.content, membership of karidns_rls_trusted); USAGE on
-- karidns_auth and EXECUTE on karidns_auth.bump_serial (the dry run raises the serial the way the commit run does, for the principal it sets); membership of
-- karidns_never_commit; the never-commit triggers.
--
-- The role needs no grant on karidns_auth.  Use a login role of its own for it: not the one of the API role (db/karidns_api_role.pgsql.sql) and not a superuser.

\set ON_ERROR_STOP on
\if :{?role}
\else
\echo 'usage: psql -v ON_ERROR_STOP=1 -v role=ROLE -v schema=SCHEMA -f karidns_check_role.pgsql.sql DATABASE'
\quit
\endif
\if :{?schema}
\else
\set schema public
\endif

SELECT format('CREATE ROLE %I NOLOGIN', :'role') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role')
\gexec
SELECT 'CREATE ROLE karidns_rls_trusted NOLOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'karidns_rls_trusted')
\gexec
SELECT 'CREATE ROLE karidns_never_commit NOLOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'karidns_never_commit')
\gexec
-- stops the script here for a role that cannot be held to the rule
SELECT karidns_auth.assert_check_role(:'schema', :'role') AS role_checked \gset

-- the rights of the ZoneImporter's role, and the membership of karidns_rls_trusted
\ir karidns_writer_role.pgsql.sql

GRANT USAGE ON SCHEMA karidns_auth TO :"role";
GRANT EXECUTE ON FUNCTION karidns_auth.bump_serial(text, integer) TO :"role";

GRANT karidns_never_commit TO :"role";
SELECT karidns_auth.enable_never_commit(:'schema') AS never_commit_tables \gset

\echo 'The role' :role 'is a check role now: its transactions are refused at COMMIT when they wrote a row of schema' :schema '. Grant it to the login role of the API check runs.'

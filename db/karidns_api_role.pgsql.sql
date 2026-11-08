-- karidns_api_role.pgsql.sql - the privileges of the PostgreSQL role the KariDNS WebAdmin API connects as (0.6.0 item B, milestone M2), and the switch
-- that turns row level security (RLS) and the audit log on.  The API changes the zone data on behalf of logged-in users; RLS is the database's second
-- check after the API's own: every row the role reads or writes must be covered by a grant of the acting user.
--
-- Manual: docs/karidns-dbloader.md ("Roles and row level security").  The packages karidns-sqlite3, karidns-postgresql and karidns-db install this file
-- in /usr/local/share/karidns/db/, next to the loader and writer role scripts.
--
-- Run it as the owner of the PowerDNS tables, who applied db/karidns_ext.pgsql.sql (schema version 3) and has CREATEROLE (the script creates two NOLOGIN
-- roles if they are missing and writes karidns_auth.audit_restricted_roles / api_roles, which only the owner may write):
--     psql -v ON_ERROR_STOP=1 -v role=karidns_api -v schema=public -f karidns_api_role.pgsql.sql karidns
-- `role` is the API's role, `schema` the schema that holds the PowerDNS and karidns_* tables (one run per schema when the views have schemas of their
-- own; the grants on karidns_auth are made again each time, harmlessly).  The script can be run again.  If the role does not exist it is created as a
-- NOLOGIN group role: GRANT it to the login role the API uses (GRANT karidns_api TO karidns_web), or create the role yourself first, with LOGIN.
-- The script STOPS (before it changes anything) when the role is a superuser or has BYPASSRLS, when it is a member of karidns_rls_trusted, or when it
-- is, or is a member of, the owner of the tables (directly or through other roles): RLS would not bind it.  The same goes for the login role you grant
-- it to: do not make that role a member of karidns_rls_trusted, and do not make the owner a member of the API role (the trigger on grants would bind
-- the owner as if it were the API).
--
-- What it does:
--   * role: every earlier privilege of the role on the tables and sequences of the schema is revoked first, then: USAGE on the schema and on karidns_auth.
--     Data schema: SELECT, INSERT, UPDATE, DELETE on domains, records, domainmetadata, karidns_record_tags, karidns_record_tinydns, karidns_zone_tagdefs,
--     karidns_domain_views; SELECT and INSERT on karidns_reload_requests (the rows it sees and inserts are those of the zones it has a grant on); SELECT and INSERT on
--     karidns_key_requests (a global master or the domain master of the zone files a request for keys; the signer answers it); SELECT on karidns_signer_state
--     (the signer's schedule and last error of the zones it has a grant on; the signer writes it); SELECT on karidns_schema_version; on cryptokeys only the COLUMN privilege SELECT (id, domain_id, flags, active, published), never `content`; USAGE on the
--     sequences behind the serial columns.  Nothing on karidns_changes: the change log and the prune of the reload requests are written by the
--     triggers of the data tables, which run as the owner.  karidns_auth: SELECT, INSERT, UPDATE, DELETE on principals, memberships, rr_policies, grants and
--     credentials (the only role that reads them); SELECT, INSERT, UPDATE, DELETE on sessions, api_tokens, templates and template_records;
--     SELECT on principal_closure, audit_log and schema_version; EXECUTE on the RLS functions, bump_serial, session_lookup, api_token_lookup and sweep_expired.  Data schema, besides:
--     SELECT on karidns_server_status and karidns_zone_state, SELECT and INSERT on karidns_zone_versions and karidns_zone_version_rrsets (item E).
--     Nothing else: no TRUNCATE, no write to the audit log, nothing on the key material or karidns_profiles.
--   * the role's name is added to karidns_auth.audit_restricted_roles (it cannot turn the detail of the audit log off) and karidns_auth.api_roles (the trigger
--     on grants applies the no-escalation rules to its sessions, and to the sessions of the roles that are members of it).
--   * RLS is switched on (ALTER TABLE ... ENABLE ROW LEVEL SECURITY; the table owner is exempt) for domains, records, domainmetadata, cryptokeys,
--     karidns_record_tags, karidns_record_tinydns, karidns_zone_tagdefs, karidns_domain_views, karidns_reload_requests, karidns_key_requests, karidns_signer_state of the schema and for principals,
--     credentials, memberships, rr_policies, grants and audit_log of karidns_auth.  The policies themselves are created by db/karidns_ext.pgsql.sql; the role
--     karidns_rls_trusted gets a policy `USING (true) WITH CHECK (true)` on each table.  The audit triggers are attached (karidns_auth.enable_audit).
--
-- AFTER THIS SCRIPT every role that reads or writes these tables and is not the owner is refused (no rows, or "permission denied for function
-- karidns_auth.rr_visible"), unless it is a member of karidns_rls_trusted:
-- db/karidns_loader_role.pgsql.sql and db/karidns_writer_role.pgsql.sql make their role a member; for the PowerDNS gpgsql role, and for any other role
-- (backups, monitoring) that must see everything, run
--     GRANT karidns_rls_trusted TO <role>;

\set ON_ERROR_STOP on
\if :{?role}
\else
\echo 'usage: psql -v ON_ERROR_STOP=1 -v role=ROLE -v schema=SCHEMA -f karidns_api_role.pgsql.sql DATABASE'
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
-- stops the script here for a role that RLS would not bind
SELECT karidns_auth.assert_service_role(:'schema', :'role') AS role_checked \gset

-- the data schema: nothing the role had before stays
GRANT USAGE ON SCHEMA :"schema" TO :"role";
REVOKE ALL ON ALL TABLES IN SCHEMA :"schema" FROM :"role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA :"schema" FROM :"role";
GRANT SELECT, INSERT, UPDATE, DELETE ON :"schema".domains, :"schema".records, :"schema".domainmetadata, :"schema".karidns_record_tags,
  :"schema".karidns_record_tinydns, :"schema".karidns_zone_tagdefs, :"schema".karidns_domain_views TO :"role";
GRANT SELECT, INSERT ON :"schema".karidns_reload_requests TO :"role";
GRANT SELECT ON :"schema".karidns_schema_version TO :"role";
GRANT SELECT ON :"schema".karidns_key_requests TO :"role";
GRANT INSERT (domain_id, kind, algorithm, bits, key_type, nsec, requested_by) ON :"schema".karidns_key_requests TO :"role";     -- a request, not its answer (state, message, done_at, created_at keep their defaults)
GRANT SELECT ON :"schema".karidns_signer_state TO :"role";                         -- when a zone was signed, and why it was not (the signer owns the table)
GRANT SELECT ON :"schema".karidns_server_status TO :"role";                        -- per server: the generation it applied, ok, the zones that failed (the loaders write it)
GRANT SELECT ON :"schema".karidns_zone_state TO :"role";                            -- the generation of the zones it has a grant on (the triggers of the owner write it)
GRANT SELECT, INSERT ON :"schema".karidns_zone_versions, :"schema".karidns_zone_version_rrsets TO :"role";   -- the history of a zone: read it, append to it; no UPDATE, no DELETE
GRANT SELECT (id, domain_id, flags, active, published) ON :"schema".cryptokeys TO :"role";

-- the sequences behind the serial columns of the tables the role inserts into (karidns_reload_requests has an identity column: no grant needed)
SELECT format('GRANT USAGE ON SEQUENCE %I.%I TO %I', n.nspname, s.relname, :'role')
  FROM pg_class s
  JOIN pg_namespace n ON n.oid = s.relnamespace
  JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
  JOIN pg_class t ON t.oid = d.refobjid AND t.relnamespace = n.oid
 WHERE s.relkind = 'S' AND n.nspname = :'schema'
   AND t.relname IN ('domains', 'records', 'domainmetadata', 'karidns_zone_tagdefs', 'karidns_key_requests', 'karidns_zone_versions')
\gexec

-- karidns_auth: a clean slate first, then exactly the rights below
GRANT USAGE ON SCHEMA karidns_auth TO :"role";
REVOKE ALL ON ALL TABLES IN SCHEMA karidns_auth FROM :"role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA karidns_auth FROM :"role";
GRANT SELECT, INSERT, UPDATE, DELETE ON karidns_auth.principals, karidns_auth.memberships, karidns_auth.rr_policies, karidns_auth.grants,
  karidns_auth.credentials TO :"role";
GRANT SELECT ON karidns_auth.principal_closure, karidns_auth.audit_log, karidns_auth.schema_version TO :"role";
GRANT SELECT, INSERT, UPDATE, DELETE ON karidns_auth.sessions, karidns_auth.api_tokens, karidns_auth.templates, karidns_auth.template_records TO :"role";
GRANT USAGE ON SEQUENCE karidns_auth.principals_id_seq, karidns_auth.rr_policies_id_seq, karidns_auth.grants_id_seq, karidns_auth.api_tokens_id_seq,
  karidns_auth.templates_id_seq TO :"role";

-- the functions the policies call run as the role that runs the statement
GRANT EXECUTE ON FUNCTION karidns_auth.current_principal(), karidns_auth.my_groups(), karidns_auth.zone_grant(text, text), karidns_auth.is_global(),
  karidns_auth.rr_ok(text, text, text, text, integer), karidns_auth.rr_visible(text, text, text, text),
  karidns_auth.audit_visible(text, text, text, jsonb, jsonb) TO :"role", karidns_rls_trusted;
-- the functions of the fast path that create_policies() generates for this schema (the SELECT policies of domains and records call them)
SELECT format('GRANT EXECUTE ON FUNCTION %s(), %s(bigint, text) TO %I, karidns_rls_trusted', karidns_auth.fast_fn(:'schema', 'eff_grants'),
              karidns_auth.fast_fn(:'schema', 'name_in_zone'), :'role')
\gexec
GRANT EXECUTE ON FUNCTION karidns_auth.bump_serial(text, integer) TO :"role";
-- the lookups of a session by the hash of its cookie and of a token by its id and the hash of its secret (the policies show a principal its own rows only)
GRANT EXECUTE ON FUNCTION karidns_auth.session_lookup(bytea), karidns_auth.api_token_lookup(bigint, bytea) TO :"role";
-- the hourly sweep: deletes the expired sessions of every principal (the policy of sessions shows the role its own principal's rows only)
GRANT EXECUTE ON FUNCTION karidns_auth.sweep_expired() TO :"role";

-- the audit log cannot be switched to summary mode by the role, and the grant trigger applies to it
INSERT INTO karidns_auth.audit_restricted_roles (role_name) VALUES (:'role') ON CONFLICT DO NOTHING;
INSERT INTO karidns_auth.api_roles (role_name) VALUES (:'role') ON CONFLICT DO NOTHING;

-- audit on, RLS on (and the trusted role's policy), policies of this schema in place
SELECT karidns_auth.create_policies('karidns_auth') + karidns_auth.create_policies(:'schema') AS policies \gset
SELECT karidns_auth.enable_audit(:'schema') + karidns_auth.enable_audit('karidns_auth') AS audited \gset
SELECT karidns_auth.enable_rls(:'schema') + karidns_auth.enable_rls('karidns_auth') AS rls_tables \gset

\echo 'Row level security is on for the schema' :schema 'and karidns_auth. Roles that use these tables and are not the owner are now refused'
\echo 'unless they are members of karidns_rls_trusted. The loader and writer role scripts do that for their role; for the PowerDNS gpgsql role run:'
\echo '    GRANT karidns_rls_trusted TO <the PowerDNS gpgsql role>;'

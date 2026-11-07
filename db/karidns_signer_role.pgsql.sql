-- karidns_signer_role.pgsql.sql - the privileges of the PostgreSQL role the KariDNS signer daemon connects as (0.6.0 item B, milestone M2; release plan 4.9).
-- The signer reads everything, including the private keys of cryptokeys and the change log, and writes only what it owns: the DNSSEC records of a zone
-- (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS, CDNSKEY), the serial of the SOA, the ordername and auth columns of every record, the metadata PRESIGNED,
-- NSEC3PARAM and X-KARIDNS-SIGNER, new keys (INSERT into cryptokeys), the state of the key requests and its own schedule (karidns_signer_state).  It is a
-- trusted daemon: it is not bound by grants (db/karidns_ext.pgsql.sql, karidns_auth), but the database holds it to its types by row level security (RLS)
-- and a trigger.
--
-- Manual: docs/karidns-dbloader.md ("Roles and row level security").  Run it as the owner of the PowerDNS tables, who applied db/karidns_ext.pgsql.sql
-- (schema version 3) and has CREATEROLE:
--     psql -v ON_ERROR_STOP=1 -v role=karidns_signer -v schema=public -f karidns_signer_role.pgsql.sql karidns
-- `role` is the signer's role, `schema` the schema that holds the PowerDNS and karidns_* tables (one run per schema).  The script can be run again.  If the
-- role does not exist it is created as a NOLOGIN group role: GRANT it to the login role the signer uses, or create the role yourself first, with LOGIN.
-- The script STOPS (before it changes anything) when the role is a superuser or has BYPASSRLS, when it is a member of karidns_rls_trusted, or when it is,
-- or is a member of, the owner of the tables (directly or through other roles): RLS would not bind it.  The signer's login role must not be a member of
-- karidns_rls_trusted either.
--
-- What it does:
--   * every earlier privilege of the role on the tables and sequences of the schema is revoked first, then: USAGE on the schema; SELECT on domains, records,
--     domainmetadata, all of cryptokeys (the keys, `content` included) and every karidns_* table, the change log karidns_changes too (the signer follows
--     it to see which zones changed); INSERT, UPDATE, DELETE on records and domainmetadata, restricted by the policies below; INSERT on cryptokeys (new
--     keys; no UPDATE, no DELETE); SELECT, and UPDATE of (state, message, done_at), on karidns_key_requests (the requests the API files, which the signer answers); SELECT, INSERT, UPDATE,
--     DELETE on karidns_signer_state (its schedule); INSERT on karidns_reload_requests (the signer asks the loader to reload); USAGE on the sequences
--     behind the serial columns.  Nothing is written to karidns_changes (the triggers of the data tables write the change log as the owner), nothing on
--     karidns_auth (no USAGE on the schema).
--   * policies for the role: SELECT of every row; records: INSERT and DELETE of the DNSSEC-managed types only, UPDATE of every row (a trigger decides what
--     changes: below); domainmetadata: INSERT, UPDATE, DELETE of the kinds PRESIGNED, NSEC3PARAM and X-KARIDNS-SIGNER only; karidns_reload_requests: INSERT;
--     cryptokeys: INSERT; karidns_key_requests: UPDATE; karidns_signer_state: INSERT, UPDATE, DELETE.  The write policies of records and domainmetadata
--     are given twice, permissive and RESTRICTIVE: the policies of the API (which apply to every role) are OR-ed with the permissive ones, the
--     restrictive ones must also pass, so setting karidns.principal does not widen what the signer may write.
--   * a trigger on records (installed by db/karidns_ext.pgsql.sql, active for the roles in karidns_auth.signer_roles, which this script fills) holds the
--     signer to what it owns: a DNSSEC record may change in any column; every other record only in ordername and auth (the NSEC3 hash of its owner and
--     whether it is authoritative); an SOA row only in its serial, ordername and auth (type, name and domain_id stay, the rest of the content stays, no
--     record becomes an SOA, no SOA becomes another type) and the signer neither inserts nor deletes an SOA.
--   * the role's name is added to karidns_auth.signer_roles, and the audit triggers are attached.  The signer is NOT in audit_restricted_roles: it is a
--     trusted daemon whose output is machine generated, and `karidns-zone import --signer` asks for the audit's summary mode (one row per transaction,
--     table and operation) instead of a row per signature.
--   * RLS is switched on for the tables of the schema (as db/karidns_api_role.pgsql.sql does; both scripts may be run in any order).
--
-- AFTER THIS SCRIPT every role that reads or writes these tables and is not the owner is refused (no rows, or "permission denied for function
-- karidns_auth.rr_visible"), unless it is a member of karidns_rls_trusted:
-- db/karidns_loader_role.pgsql.sql and db/karidns_writer_role.pgsql.sql make their role a member; for the PowerDNS gpgsql role, and for any other role
-- (backups, monitoring) that must see everything, run
--     GRANT karidns_rls_trusted TO <role>;

\set ON_ERROR_STOP on
\if :{?role}
\else
\echo 'usage: psql -v ON_ERROR_STOP=1 -v role=ROLE -v schema=SCHEMA -f karidns_signer_role.pgsql.sql DATABASE'
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

GRANT USAGE ON SCHEMA :"schema" TO :"role";
REVOKE ALL ON ALL TABLES IN SCHEMA :"schema" FROM :"role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA :"schema" FROM :"role";
REVOKE ALL ON ALL TABLES IN SCHEMA karidns_auth FROM :"role";
REVOKE ALL ON SCHEMA karidns_auth FROM :"role";
GRANT SELECT ON :"schema".domains, :"schema".records, :"schema".domainmetadata, :"schema".cryptokeys TO :"role";
GRANT INSERT, UPDATE, DELETE ON :"schema".records, :"schema".domainmetadata TO :"role";
GRANT INSERT ON :"schema".karidns_reload_requests TO :"role";
-- the key tooling and the work queue of the signer (0.6.0 item C): new keys (INSERT only: a key is never changed or deleted by the signer), the
-- key requests it works off (SELECT, UPDATE of the state), its own schedule
GRANT INSERT ON :"schema".cryptokeys TO :"role";
GRANT SELECT ON :"schema".karidns_key_requests TO :"role";
GRANT UPDATE (state, message, done_at) ON :"schema".karidns_key_requests TO :"role";      -- the answer only: the request itself (zone, kind, algorithm, requester) stays as it was filed
GRANT SELECT, INSERT, UPDATE, DELETE ON :"schema".karidns_signer_state TO :"role";

-- every karidns_* table can be read (the change log too: the signer follows it)
SELECT format('GRANT SELECT ON %I.%I TO %I', :'schema', c.relname, :'role')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = :'schema' AND c.relkind IN ('r', 'p') AND c.relname LIKE 'karidns\_%' ESCAPE '\'
 ORDER BY c.relname
\gexec

-- the sequences behind the serial columns of the tables the role inserts into
SELECT format('GRANT USAGE ON SEQUENCE %I.%I TO %I', n.nspname, s.relname, :'role')
  FROM pg_class s
  JOIN pg_namespace n ON n.oid = s.relnamespace
  JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
  JOIN pg_class t ON t.oid = d.refobjid AND t.relnamespace = n.oid
 WHERE s.relkind = 'S' AND n.nspname = :'schema'
   AND t.relname IN ('records', 'domainmetadata', 'cryptokeys')
\gexec

-- the policies of the API (no TO clause) are evaluated for this role too: it may call the functions they use (it holds no principal, so they say no)
GRANT EXECUTE ON FUNCTION karidns_auth.current_principal(), karidns_auth.my_groups(), karidns_auth.zone_grant(text, text), karidns_auth.is_global(),
  karidns_auth.rr_ok(text, text, text, text, integer), karidns_auth.rr_visible(text, text, text, text),
  karidns_auth.audit_visible(text, text, text, jsonb, jsonb) TO :"role", karidns_rls_trusted;
-- the functions of the fast path that create_policies() generates for this schema (the SELECT policies of domains and records call them)
SELECT format('GRANT EXECUTE ON FUNCTION %s(), %s(bigint, text) TO %I, karidns_rls_trusted', karidns_auth.fast_fn(:'schema', 'eff_grants'),
              karidns_auth.fast_fn(:'schema', 'name_in_zone'), :'role')
\gexec

INSERT INTO karidns_auth.signer_roles (role_name) VALUES (:'role') ON CONFLICT DO NOTHING;

SELECT karidns_auth.create_policies(:'schema') AS policies \gset
SELECT karidns_auth.create_signer_policies(:'schema', :'role') AS signer_policies \gset
SELECT karidns_auth.enable_audit(:'schema') AS audited \gset
SELECT karidns_auth.enable_rls(:'schema') AS rls_tables \gset

\echo 'Row level security is on for the schema' :schema '- roles that use these tables and are not the owner are now refused'
\echo 'unless they are members of karidns_rls_trusted. The loader and writer role scripts do that for their role; for the PowerDNS gpgsql role run:'
\echo '    GRANT karidns_rls_trusted TO <the PowerDNS gpgsql role>;'

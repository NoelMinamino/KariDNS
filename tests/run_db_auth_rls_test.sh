#!/bin/sh
# run_db_auth_rls_test.sh - roles and row level security (RLS) of KariDNS 0.6.0 item B, milestone M2: the role scripts db/karidns_api_role.pgsql.sql and
# db/karidns_signer_role.pgsql.sql, the functions and policies of db/karidns_ext.pgsql.sql (karidns_auth.rr_ok, rr_visible, zone_grant, bump_serial, the
# trigger on grants), and the trusted membership (karidns_rls_trusted) the loader and writer role scripts give their role.  PostgreSQL only (SQLite3 has
# no roles: the API does it).  The table owner is the user that runs the test; the roles are created here (cluster wide, per process names, dropped at
# the end), the sessions are SET ROLE ... with SET LOCAL karidns.principal = '<id>'.
#
#   - a matrix of reads and writes of the API role: no / empty / non-numeric / unknown / disabled principal, a disabled group, groups and nested groups;
#     the label boundary (evilsub.example.com is not under sub.example.com), wildcard, delegation (NS below the apex), DNAME, the apex, TTL range (NULL
#     counts as 0), DNSSEC types, SOA (bump_serial() and the serial wrap), a record outside its zone, empty non-terminals and a NULL name, one grant per row
#     (two grants that each allow half do not combine), the tables of 4.4 (domains, domainmetadata and the kinds the signer owns, tags, tagdefs, views,
#     reload requests, cryptokeys: no `content`, credentials, principals, memberships, policies), the audit log (append only, redaction, visibility per role);
#   - the escalation trigger on grants: every field of the subset rule, subdomain masters, other zones, the global role, DELETE and UPDATE, granted_by, the
#     operator, a member of the API role;
#   - the signer role: what it reads (the keys too) and the writes it may and may not do, also with karidns.principal set (RESTRICTIVE policies), the
#     trigger that lets it change the serial of an SOA only; the role scripts refusing a role RLS would not bind; the maintenance triggers running as the owner
#     (no right on karidns_changes, reload requests pruned, the change log filled); TYPEnn aliases; INSERT ... ON CONFLICT; trailing-dot domains;
#   - item C (the signer): the signer reads the change log and adds keys but changes none; the key requests (filed by a global master or the domain master of the
#     zone as themselves, answered by the signer, unchangeable by the API) and the signer state (read by any grant on the zone, written by the signer); the columns of
#     a record (a trigger lets the signer change ordername and auth of any record, a DNSSEC record in any column, the SOA's serial); karidns-zone import --signer as
#     the signer role with RLS on (a second database): signed, re-signed, a stale file = exit status 3, an ordinary import refused;
#   - credentials unreadable for the loader, writer and signer roles; the loader and karidns-zone (writer role) read and write everything with RLS on, in both
#     script orders; a role that is not trusted sees nothing; one real dump with karidns-dbloader as the loader role and one import with karidns-zone.
# SKIP (exit 0, with the reason) when PostgreSQL is not reachable, the role may not create roles, or the user is not a superuser (the sessions are SET ROLE ... and
# the operator must not be a member of the API role).  Runs as any user (as root: the PostgreSQL user).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

PASS=0; FAILS=0; SKIPS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
skip() { SKIPS=$((SKIPS + 1)); echo "  [SKIP] $1"; }

LOADER=${LOADER:-$ROOT/karidns-dbloader}
ZONE_BIN=${ZONE:-$ROOT/karidns-zone}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_rls.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
ROLES=""; DB2=""; TRUSTED_NEW=0
cleanup() {
    pg_cleanup
    [ -n "$DB2" ] && psql -X -q -d "$PGMAINT" -c "DROP DATABASE IF EXISTS $DB2 WITH (FORCE)" > /dev/null 2>&1
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    [ "$TRUSTED_NEW" = 1 ] && psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS karidns_rls_trusted" > /dev/null 2>&1
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
pg_setup rls || exit 0

if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE kt_probe_$$ NOLOGIN" > /dev/null 2>&1; then
    echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"
    exit 0
fi
psql -X -q -d "$PGMAINT" -c "DROP ROLE kt_probe_$$" > /dev/null 2>&1
[ "$(psql -X -q -At -d "$PGMAINT" -c "SELECT count(*) FROM pg_roles WHERE rolname = 'karidns_rls_trusted'")" = "0" ] && TRUSTED_NEW=1

API=kt_api_$$; SIG=kt_sig_$$; APIM=kt_apim_$$; BARE=kt_bare_$$; LD2=kt_ld2_$$; WR2=kt_wr2_$$; LD1=kt_ld1_$$; WR1=kt_wr1_$$; LGN=kt_lgn_$$; OTH=kt_oth_$$; SG1=kt_sg1_$$
ROLES="$API $SIG $APIM $BARE $LD2 $WR2 $LD1 $WR1 $LGN $OTH $SG1"
HASH_A='$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g'
O=$T/o.out; E=$T/o.err

# ---------------------------------------------------------------- helpers
# ar ROLE PRINCIPAL SQL...: the SQL as ROLE, karidns.principal = PRINCIPAL (NONE: not set), in one transaction; stdout in $O, stderr in $E, status in $rc
ar() {
    _r=$1; _p=$2; shift 2
    case $_p in NONE) _pre="SET ROLE $_r;" ;; *) _pre="SET ROLE $_r; SET LOCAL karidns.principal = '$_p';" ;; esac
    psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "$_pre $*" > "$O" 2> "$E"; rc=$?
}
got() { tr '\n' ' ' < "$O" | sed 's/ $//'; }
a_eq() { _d=$1; _w=$2; shift 2; ar "$@"; _g=$(got); if [ $rc -eq 0 ] && [ "$_g" = "$_w" ]; then pass "$_d"; else fail "$_d: got '$_g' (status $rc: $(head -c 250 "$E")), wanted '$_w'"; fi; }
a_ok() { _d=$1; shift; ar "$@"; if [ $rc -eq 0 ]; then pass "$_d"; else fail "$_d: $(head -c 300 "$E")"; fi; }
a_err() { _d=$1; _pat=$2; shift 2; ar "$@"; if [ $rc -ne 0 ] && grep -Eqi -- "$_pat" "$E"; then pass "$_d"; else fail "$_d: status $rc, wanted an error matching '$_pat': $(head -c 250 "$E")$(head -c 100 "$O")"; fi; }
# a_n DESC N ROLE PRINCIPAL "UPDATE|DELETE|INSERT ...": the number of rows the statement changed
a_n() { _d=$1; _w=$2; _r=$3; _p=$4; shift 4; ar "$_r" "$_p" "WITH x AS ($* RETURNING 1) SELECT count(*) FROM x"; _g=$(got)
        if [ $rc -eq 0 ] && [ "$_g" = "$_w" ]; then pass "$_d"; else fail "$_d: changed '$_g' rows (status $rc: $(head -c 250 "$E")), wanted $_w"; fi; }
RLSERR='row-level security'
oq() { pq "$1"; }                                    # the owner's query
oeq() { _g=$(pq "$3"); if [ "$_g" = "$2" ]; then pass "$1"; else fail "$1: got '$_g', wanted '$2'"; fi; }
rs() { _s=$1; _ro=$2; _sc=$3; _c=${4:-$PGC}; psql -X -q -At -v ON_ERROR_STOP=1 -v role="$_ro" -v schema="$_sc" -f "db/$_s" "$_c" > "$T/rs.out" 2> "$T/rs.err"; }
pid() { pq "SELECT id FROM karidns_auth.principals WHERE name = '$1'"; }
did() { pq "SELECT id FROM domains WHERE name = '$1'"; }
ri() { echo "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($1, '$2', '$3', '$4', $5)"; }   # ri DOMAIN_ID NAME TYPE CONTENT TTL

# ---------------------------------------------------------------- the database: the owner's fixture
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
cat > "$T/fix1.sql" <<'EOF'
INSERT INTO domains (name, type) VALUES ('example.com', 'NATIVE'), ('other.test', 'NATIVE'), ('third.test', 'NATIVE'), ('nosoa.test', 'NATIVE'), ('dot.test.', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
SELECT d.id, v.name, v.type, v.content, v.ttl, v.prio, false
  FROM domains d JOIN (VALUES
   ('example.com', 'example.com',          'SOA',    'ns1.example.com hostmaster.example.com 100 7200 3600 1209600 300', 3600, NULL::int),
   ('example.com', 'example.com',          'NS',     'ns1.example.com', 3600, NULL),
   ('example.com', 'example.com',          'A',      '192.0.2.1', 300, NULL),
   ('example.com', 'example.com',          'DNSKEY', '257 3 13 AAAA', 3600, NULL),
   ('example.com', 'www.example.com',      'A',      '192.0.2.2', 300, NULL),
   ('example.com', 'www.example.com',      'RRSIG',  'A 13 3 300 20300101000000 20200101000000 1 example.com AAAA', 300, NULL),
   ('example.com', 'mail.example.com',     'MX',     'mail.example.com', 300, 10),
   ('example.com', 'a.sub.example.com',    'A',      '192.0.2.3', 300, NULL),
   ('example.com', 'sub.example.com',      'TXT',    'sub', 300, NULL),
   ('example.com', 'evilsub.example.com',  'A',      '192.0.2.4', 300, NULL),
   ('example.com', 'junk.evil.test',        'A',      '192.0.2.98', 300, NULL),
   ('dot.test.',   'dot.test',             'SOA',    'ns1.dot.test hostmaster.dot.test 1 7200 3600 1209600 300', 3600, NULL),
   ('dot.test.',   'www.dot.test',         'A',      '192.0.2.97', 300, NULL),
   ('other.test',  'other.test',           'SOA',    'ns1.other.test hostmaster.other.test 1 7200 3600 1209600 300', 3600, NULL),
   ('other.test',  'other.test',           'NS',     'ns1.other.test', 3600, NULL),
   ('other.test',  'www.other.test',       'A',      '192.0.2.5', 300, NULL),
   ('third.test',  'third.test',           'SOA',    'ns1.third.test hostmaster.third.test 7 7200 3600 1209600 300', 3600, NULL),
   ('third.test',  'third.test',           'NS',     'ns1.third.test', 3600, NULL)) AS v(zone, name, type, content, ttl, prio) ON v.zone = d.name;
INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, NULL, 'A', '192.0.2.99', 300 FROM domains WHERE name = 'example.com';
INSERT INTO domainmetadata (domain_id, kind, content)
SELECT d.id, v.kind, v.content FROM domains d JOIN (VALUES ('example.com', 'ALLOW-AXFR-FROM', '127.0.0.1'), ('other.test', 'SOA-EDIT', 'INCEPTION-EPOCH'),
  ('third.test', 'PRESIGNED', '1')) AS v(zone, kind, content) ON v.zone = d.name;
INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'internal' FROM domains WHERE name IN ('example.com', 'other.test');
INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) SELECT id, 'location', 'tokyo', '192.0.2.0/24' FROM domains WHERE name IN ('example.com', 'other.test');
INSERT INTO karidns_record_tags (record_id, location_tag) SELECT r.id, 'tokyo' FROM records r WHERE r.name IN ('www.example.com', 'www.other.test') AND r.type = 'A';
INSERT INTO karidns_record_tinydns (record_id, ttd) SELECT r.id, 1 FROM records r WHERE r.name = 'a.sub.example.com';

INSERT INTO karidns_auth.rr_policies (name, allowed_types, allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max, max_rr) VALUES
 ('std',        ARRAY['A','AAAA','CNAME','MX','TXT','SRV'],                              false, false, false, false, 60, 86400, NULL),
 ('wide',       ARRAY['A','AAAA','CNAME','MX','TXT','SRV','NS','DNAME','DS','SOA'],      true,  true,  true,  true,  0, 2147483647, 1000),
 ('all',        ARRAY['A','AAAA','CNAME','MX','TXT','SRV','NS','DNAME','DS','SOA'],      true,  true,  true,  true,  0, 2147483647, NULL),
 ('half_a',     ARRAY['A'],                                                              false, false, false, false, 0, 86400, NULL),
 ('half_b',     ARRAY['A','TXT'],                                                        false, false, false, false, 1000, 2000, NULL),
 ('only_a',     ARRAY['A'],                                                              false, false, false, false, 0, 86400, NULL),
 ('only_mx',    ARRAY['MX'],                                                             false, false, false, false, 0, 86400, NULL),
 ('esc',        ARRAY['A','AAAA','TXT','MX'],                                            false, false, false, false, 60, 86400, 100),
 ('esc_ok',     ARRAY['A','TXT'],                                                        false, false, false, false, 300, 3600, 50),
 ('esc_eq',     ARRAY['A','AAAA','TXT','MX'],                                            false, false, false, false, 60, 86400, 100),
 ('esc_type',   ARRAY['A','SRV'],                                                        false, false, false, false, 60, 86400, 100),
 ('esc_wc',     ARRAY['A'],                                                              true,  false, false, false, 60, 86400, 100),
 ('esc_del',    ARRAY['A'],                                                              false, true,  false, false, 60, 86400, 100),
 ('esc_dn',     ARRAY['A'],                                                              false, false, true,  false, 60, 86400, 100),
 ('esc_apex',   ARRAY['A'],                                                              false, false, false, true,  60, 86400, 100),
 ('esc_ttlmin', ARRAY['A'],                                                              false, false, false, false, 30, 86400, 100),
 ('esc_ttlmax', ARRAY['A'],                                                              false, false, false, false, 60, 100000, 100),
 ('esc_maxrr',  ARRAY['A'],                                                              false, false, false, false, 60, 86400, 101),
 ('esc_maxnul', ARRAY['A'],                                                              false, false, false, false, 60, 86400, NULL),
 ('alias',      ARRAY['A','NS','DNAME','TXT'],                                           false, false, false, false, 0, 2147483647, NULL);
INSERT INTO karidns_auth.principals (kind, name) VALUES
 ('user', 'gm'), ('user', 'gmn'), ('user', 'dm'), ('user', 'dmw'), ('user', 'sm'), ('user', 'smz'), ('user', 'eve'), ('user', 'gina'), ('user', 'dis'),
 ('user', 'nog'), ('user', 'half'), ('user', 'halfs'), ('user', 'dme'), ('user', 'tgt'), ('user', 'dma'), ('user', 'dotu'),
 ('group', 'g_ops'), ('group', 'team'), ('group', 'org');
INSERT INTO karidns_auth.memberships (member_id, group_id) SELECT m.id, g.id FROM karidns_auth.principals m, karidns_auth.principals g
 WHERE (m.name, g.name) IN (('eve', 'g_ops'), ('gina', 'team'), ('team', 'org'));
CREATE FUNCTION tst_grant(u text, r text, z text, s text, p text) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id)
  SELECT (SELECT id FROM karidns_auth.principals WHERE name = u), r, CASE WHEN r = 'global_master' THEN NULL ELSE 'public' END, z, s,
         (SELECT id FROM karidns_auth.rr_policies WHERE name = p)
$f$;
SELECT tst_grant('gm',   'global_master',    NULL,          NULL,              'all');
SELECT tst_grant('gmn',  'global_master',    NULL,          NULL,              'std');
SELECT tst_grant('dm',   'domain_master',    'example.com', NULL,              'std');
SELECT tst_grant('dmw',  'domain_master',    'example.com', NULL,              'wide');
SELECT tst_grant('sm',   'subdomain_master', 'example.com', 'sub.example.com', 'std');
SELECT tst_grant('smz',  'subdomain_master', 'example.com', 'example.com',     'wide');
SELECT tst_grant('g_ops','domain_master',    'other.test',  NULL,              'std');
SELECT tst_grant('org',  'domain_master',    'third.test',  NULL,              'std');
SELECT tst_grant('dis',  'domain_master',    'example.com', NULL,              'std');
SELECT tst_grant('half', 'domain_master',    'example.com', NULL,              'half_a');
SELECT tst_grant('half', 'domain_master',    'example.com', NULL,              'half_b');
SELECT tst_grant('halfs','subdomain_master', 'example.com', 'a.example.com',   'only_a');
SELECT tst_grant('halfs','subdomain_master', 'example.com', 'b.example.com',   'only_mx');
SELECT tst_grant('dme',  'domain_master',    'example.com', NULL,              'esc');
SELECT tst_grant('dma',  'domain_master',    'example.com', NULL,              'alias');
SELECT tst_grant('dotu', 'domain_master',    'dot.test',    NULL,              'std');
UPDATE karidns_auth.principals SET disabled = true WHERE name = 'dis';
EOF
pf "$T/fix1.sql" > /dev/null || { echo "  [FAIL] cannot load the fixture"; exit 1; }
pq "INSERT INTO karidns_auth.credentials (principal_id, password_hash, totp_enabled) SELECT id, '$HASH_A', false FROM karidns_auth.principals WHERE name IN ('gm', 'dm', 'sm')" > /dev/null || { echo "  [FAIL] cannot load the credentials"; exit 1; }
EX=$(did example.com); OTHER=$(did other.test); THIRD=$(did third.test); NOSOA=$(did nosoa.test)
GM=$(pid gm); GMN=$(pid gmn); DM=$(pid dm); DMW=$(pid dmw); SM=$(pid sm); SMZ=$(pid smz); EVE=$(pid eve); GINA=$(pid gina); DIS=$(pid dis); NOG=$(pid nog)
HALF=$(pid half); HALFS=$(pid halfs); DME=$(pid dme); TGT=$(pid tgt)

echo "-- the role scripts"
if rs karidns_api_role.pgsql.sql $API public; then pass "db/karidns_api_role.pgsql.sql applies (the role is created)"; else fail "the API role script"; head -5 "$T/rs.err"; fi
if rs karidns_api_role.pgsql.sql $API public; then pass "...and can be applied again"; else fail "second application of the API role script"; head -5 "$T/rs.err"; fi
if rs karidns_signer_role.pgsql.sql $SIG public && rs karidns_signer_role.pgsql.sql $SIG public; then pass "db/karidns_signer_role.pgsql.sql applies, twice"; else fail "the signer role script"; head -5 "$T/rs.err"; fi
oeq "the policies exist: 39 for the API on the schema's tables, 37 on karidns_auth, 1 for the trusted role on each of the 25 tables, 32 for the signer (3 + 3 permissive and restrictive on records and domainmetadata, 14 SELECT, 1 INSERT on reload requests, 1 on cryptokeys, 1 UPDATE on key requests, 3 on the signer state)" \
    "39 37 25 32" "SELECT (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace = 'public'::regnamespace AND p.polname LIKE 'karidns\_rls\_%' AND p.polname <> 'karidns_rls_trusted' AND p.polroles = '{0}')::text || ' ' || (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace = 'karidns_auth'::regnamespace AND p.polname LIKE 'karidns\_rls\_%' AND p.polname <> 'karidns_rls_trusted' AND p.polroles = '{0}')::text || ' ' || (SELECT count(*) FROM pg_policy WHERE polname = 'karidns_rls_trusted')::text || ' ' || (SELECT count(*) FROM pg_policy WHERE polname LIKE 'karidns\_signer\_%')::text"
oeq "RLS is on for the 14 tables of the schema and the 11 of karidns_auth (with oidc_states), and for nothing else" "25" "SELECT count(*) FROM pg_class WHERE relrowsecurity AND relnamespace IN ('public'::regnamespace, 'karidns_auth'::regnamespace)"
oeq "...and not forced (the owner is exempt)" "0" "SELECT count(*) FROM pg_class WHERE relforcerowsecurity"
oeq "the audit triggers are attached to the schema (the eight PowerDNS and KariDNS data tables and the two tables of the signer)" "10" "SELECT count(DISTINCT tgrelid) FROM pg_trigger WHERE tgname = 'karidns_audit_row' AND tgrelid::regclass::text IN ('domains','records','domainmetadata','cryptokeys','karidns_record_tags','karidns_record_tinydns','karidns_zone_tagdefs','karidns_domain_views','karidns_key_requests','karidns_signer_state')"
oeq "only the API role is in audit_restricted_roles (the signer is a trusted daemon that asks for summary mode); the API role is in api_roles (the signer is not)" "true|false|true|false" \
    "SELECT (SELECT count(*) = 1 FROM karidns_auth.audit_restricted_roles WHERE role_name = '$API') || '|' || (SELECT count(*) = 1 FROM karidns_auth.audit_restricted_roles WHERE role_name = '$SIG') || '|' || (SELECT count(*) = 1 FROM karidns_auth.api_roles WHERE role_name = '$API') || '|' || (SELECT count(*) = 1 FROM karidns_auth.api_roles WHERE role_name = '$SIG')"
oeq "karidns_rls_trusted exists, NOLOGIN" "f" "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'karidns_rls_trusted'"
oeq "the API role is NOLOGIN (created by the script)" "f" "SELECT rolcanlogin FROM pg_roles WHERE rolname = '$API'"
grep -q "GRANT karidns_rls_trusted TO" "$T/rs.out" && pass "the script prints the GRANT karidns_rls_trusted reminder" || fail "no reminder printed"
# the sessions are SET ROLE ...: a superuser needs no membership, and the operator must not be a member of the API role (the grant trigger would bind it)
if [ "$(pq "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" != "t" ]; then
    skip "the test user is not a superuser: the RLS matrix needs SET ROLE without a membership in the API role"
    echo; echo "=== run_db_auth_rls_test: $PASS checks passed, $FAILS FAILED, $SKIPS skipped ==="; [ "$FAILS" -eq 0 ] && exit 0 || exit 1
fi
# the keys are inserted after the audit triggers exist
pq "INSERT INTO cryptokeys (domain_id, flags, active, content) SELECT id, 257, true, 'SECRET-KEY-' || name FROM domains WHERE name IN ('example.com', 'other.test')" > /dev/null
RTOTAL=$(pq "SELECT count(*) FROM records")

echo "-- roles RLS would not bind are refused by the role scripts; earlier privileges do not survive"
OWNER=$(pq "SELECT current_user")
X1=kt_x1_$$; X2=kt_x2_$$; X3=kt_x3_$$; X4=kt_x4_$$; X5=kt_x5_$$; X6=kt_x6_$$
ROLES="$ROLES $X1 $X2 $X3 $X4 $X5 $X6"
pq "CREATE ROLE $X1 NOLOGIN; CREATE ROLE $X2 NOLOGIN; CREATE ROLE $X3 NOLOGIN; CREATE ROLE $X4 NOLOGIN SUPERUSER; CREATE ROLE $X5 NOLOGIN BYPASSRLS; CREATE ROLE $X6 NOLOGIN;
    GRANT karidns_rls_trusted TO $X1; GRANT karidns_rls_trusted TO $X2; GRANT $X2 TO $X3; GRANT $OWNER TO $X6" > /dev/null 2>&1
rs_err() { _d=$1; _pat=$2; shift 2; if rs "$@"; then fail "$_d: the script succeeded"; elif grep -Eqi -- "$_pat" "$T/rs.err"; then pass "$_d"; else fail "$_d: wrong error: $(head -c 250 "$T/rs.err")"; fi; }
for sc in karidns_api_role karidns_signer_role; do
    rs_err "$sc: a role in karidns_rls_trusted is refused" "member of karidns_rls_trusted" $sc.pgsql.sql $X1 public
    rs_err "$sc: ...also through another role (X3 in X2 in karidns_rls_trusted)" "member of karidns_rls_trusted" $sc.pgsql.sql $X3 public
    rs_err "$sc: a superuser is refused" "superuser or has BYPASSRLS" $sc.pgsql.sql $X4 public
    rs_err "$sc: a role with BYPASSRLS is refused" "superuser or has BYPASSRLS" $sc.pgsql.sql $X5 public
    rs_err "$sc: a member of the owner of the tables is refused" "owner of the tables" $sc.pgsql.sql $X6 public
done
oeq "...and the refused roles got nothing (no schema privilege, no entry in api_roles / signer_roles)" "0" "SELECT (SELECT count(*) FROM pg_roles r WHERE r.rolname IN ('$X1', '$X2', '$X3') AND has_table_privilege(r.oid, 'records', 'SELECT')) + (SELECT count(*) FROM karidns_auth.api_roles WHERE role_name LIKE 'kt\_x%') + (SELECT count(*) FROM karidns_auth.signer_roles WHERE role_name LIKE 'kt\_x%')"
# privileges the roles had before stay out: stray rights are revoked when the script runs again
pq "GRANT TRUNCATE, SELECT ON records TO $API; GRANT SELECT ON cryptokeys TO $API; GRANT SELECT ON karidns_profiles, karidns_changes TO $API; GRANT USAGE ON SEQUENCE karidns_changes_seq_seq TO $API;
    GRANT UPDATE, DELETE ON cryptokeys TO $SIG; GRANT SELECT, DELETE ON karidns_changes TO $SIG; GRANT INSERT ON karidns_profiles TO $SIG; GRANT DELETE ON karidns_reload_requests TO $SIG" > /dev/null
rs karidns_api_role.pgsql.sql $API public && rs karidns_signer_role.pgsql.sql $SIG public && pass "both scripts run again over stray privileges" || fail "re-run over stray privileges"
oeq "the API role: no TRUNCATE, no table-level or column SELECT on the keys, nothing on karidns_profiles or the change log or its sequence" "false|false|false|false|false|false" \
    "SELECT has_table_privilege('$API', 'records', 'TRUNCATE') || '|' || has_column_privilege('$API', 'cryptokeys', 'content', 'SELECT') || '|' || has_table_privilege('$API', 'cryptokeys', 'SELECT') || '|' || has_table_privilege('$API', 'karidns_profiles', 'SELECT') || '|' || has_table_privilege('$API', 'karidns_changes', 'SELECT') || '|' || has_sequence_privilege('$API', 'karidns_changes_seq_seq', 'USAGE')"
oeq "...and still the column privilege on id, domain_id, flags, active, published" "t" "SELECT has_column_privilege('$API', 'cryptokeys', 'domain_id', 'SELECT') AND has_column_privilege('$API', 'cryptokeys', 'published', 'SELECT')"
oeq "the signer role: no UPDATE or DELETE of the keys, SELECT but no DELETE on the change log, nothing on karidns_profiles, no DELETE on reload requests" "false|false|true|false|false|false" \
    "SELECT has_table_privilege('$SIG', 'cryptokeys', 'UPDATE') || '|' || has_table_privilege('$SIG', 'cryptokeys', 'DELETE') || '|' || has_table_privilege('$SIG', 'karidns_changes', 'SELECT') || '|' || has_table_privilege('$SIG', 'karidns_changes', 'DELETE') || '|' || has_table_privilege('$SIG', 'karidns_profiles', 'INSERT') || '|' || has_table_privilege('$SIG', 'karidns_reload_requests', 'DELETE')"
oeq "...and it still reads the keys and writes records" "t" "SELECT has_column_privilege('$SIG', 'cryptokeys', 'content', 'SELECT') AND has_table_privilege('$SIG', 'records', 'INSERT')"
oeq "the signer role (item C): INSERT on the keys; SELECT, and UPDATE only of columns (no table-wide UPDATE), not INSERT or DELETE, on the key requests; all four on its state" "true|true|false|false|false|true|true|true|true" \
    "SELECT has_table_privilege('$SIG', 'cryptokeys', 'INSERT') || '|' || has_table_privilege('$SIG', 'karidns_key_requests', 'SELECT') || '|' || has_table_privilege('$SIG', 'karidns_key_requests', 'UPDATE') || '|' || has_table_privilege('$SIG', 'karidns_key_requests', 'INSERT') || '|' || has_table_privilege('$SIG', 'karidns_key_requests', 'DELETE') || '|' || has_table_privilege('$SIG', 'karidns_signer_state', 'SELECT') || '|' || has_table_privilege('$SIG', 'karidns_signer_state', 'INSERT') || '|' || has_table_privilege('$SIG', 'karidns_signer_state', 'UPDATE') || '|' || has_table_privilege('$SIG', 'karidns_signer_state', 'DELETE')"
oeq "the API role (item C): SELECT, and INSERT only of columns (no table-wide INSERT), not UPDATE or DELETE, on the key requests; only SELECT on the signer state; no INSERT on the keys" "true|false|false|false|true|false|false|false|false" \
    "SELECT has_table_privilege('$API', 'karidns_key_requests', 'SELECT') || '|' || has_table_privilege('$API', 'karidns_key_requests', 'INSERT') || '|' || has_table_privilege('$API', 'karidns_key_requests', 'UPDATE') || '|' || has_table_privilege('$API', 'karidns_key_requests', 'DELETE') || '|' || has_table_privilege('$API', 'karidns_signer_state', 'SELECT') || '|' || has_table_privilege('$API', 'karidns_signer_state', 'INSERT') || '|' || has_table_privilege('$API', 'karidns_signer_state', 'UPDATE') || '|' || has_table_privilege('$API', 'karidns_signer_state', 'DELETE') || '|' || has_table_privilege('$API', 'cryptokeys', 'INSERT')"
oeq "the signer updates state, message and done_at of a key request, nothing else; the API role inserts domain_id, kind, algorithm, bits, key_type, nsec and requested_by, not the state, the message, done_at or the id" "true|true|true|false|false|false|false|true|true|true|true|true|true|true|false|false|false|false" \
    "SELECT has_column_privilege('$SIG', 'karidns_key_requests', 'state', 'UPDATE') || '|' || has_column_privilege('$SIG', 'karidns_key_requests', 'message', 'UPDATE') || '|' || has_column_privilege('$SIG', 'karidns_key_requests', 'done_at', 'UPDATE') || '|' || has_column_privilege('$SIG', 'karidns_key_requests', 'domain_id', 'UPDATE') || '|' || has_column_privilege('$SIG', 'karidns_key_requests', 'algorithm', 'UPDATE') || '|' || has_column_privilege('$SIG', 'karidns_key_requests', 'requested_by', 'UPDATE') || '|' || has_column_privilege('$SIG', 'karidns_key_requests', 'id', 'UPDATE') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'domain_id', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'kind', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'algorithm', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'bits', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'key_type', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'nsec', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'requested_by', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'state', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'message', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'done_at', 'INSERT') || '|' || has_column_privilege('$API', 'karidns_key_requests', 'id', 'INSERT')"
oeq "the maintenance triggers of the data tables run as the owner (the roles need no right on the change log)" "0" "SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND (p.proname LIKE 'karidns\_trg\_%\_fn' OR p.proname IN ('karidns_log_domains', 'karidns_changes_prune_fn', 'karidns_reload_requests_lock_fn', 'karidns_reload_requests_notify_fn', 'karidns_reload_requests_prune_fn')) AND NOT p.prosecdef"

echo "-- the acting principal"
a_eq "no setting: no rows of records" 0 $API NONE "SELECT count(*) FROM records"
a_eq "no setting: no rows of domains" 0 $API NONE "SELECT count(*) FROM domains"
a_eq "no setting: no rows of grants" 0 $API NONE "SELECT count(*) FROM karidns_auth.grants"
a_eq "no setting: no rows of credentials" 0 $API NONE "SELECT count(*) FROM karidns_auth.credentials"
a_eq "an empty setting is no principal" 0 $API '' "SELECT count(*) FROM records"
a_eq "a non-numeric setting is no principal (not an error)" 0 $API 'abc' "SELECT count(*) FROM records"
a_eq "...nor '12x', ' 5', '-1', '1e3'" "0 0 0 0" $API NONE "SET LOCAL karidns.principal = '12x'; SELECT count(*) FROM records; SET LOCAL karidns.principal = ' $GM'; SELECT count(*) FROM records; SET LOCAL karidns.principal = '-$GM'; SELECT count(*) FROM records; SET LOCAL karidns.principal = '1e3'; SELECT count(*) FROM records"
a_eq "a principal that does not exist" 0 $API 999999 "SELECT count(*) FROM records"
a_eq "karidns_auth.current_principal() is the id" "$DM" $API $DM "SELECT karidns_auth.current_principal()"
a_eq "...and NULL for garbage" "" $API abc "SELECT karidns_auth.current_principal()"
a_eq "...a group is a principal too (its own grants)" "$(pid org)" $API "$(pid org)" "SELECT karidns_auth.current_principal()"
a_eq "a disabled principal sees nothing" 0 $API $DIS "SELECT count(*) FROM records"
oq "UPDATE karidns_auth.principals SET disabled = false WHERE name = 'dis'" > /dev/null
a_eq "...and sees its zone once enabled again (the row without a name and the one outside the zone are not visible)" 10 $API $DIS "SELECT count(*) FROM records"
oq "UPDATE karidns_auth.principals SET disabled = true WHERE name = 'dis'" > /dev/null
a_err "no principal: an INSERT of a record is refused" "$RLSERR" $API NONE "$(ri $EX x.example.com A 192.0.2.1 300)"
a_err "no principal: an INSERT of a zone is refused" "$RLSERR" $API NONE "INSERT INTO domains (name, type) VALUES ('nope.test', 'NATIVE')"

echo "-- what each principal sees"
a_eq "a global master sees every record but the 2 whose name is missing or outside the zone" "$((RTOTAL - 2))" $API $GM "SELECT count(*) FROM records"
a_eq "...not the row without a name, not the one outside its zone (junk.evil.test): the owner repairs them" 0 $API $GM "SELECT count(*) FROM records WHERE name IS NULL OR name = 'junk.evil.test'"
a_eq "...every zone" 5 $API $GM "SELECT count(*) FROM domains"
a_eq "a domain master sees the records of its zone, not a row without a name or one outside the zone" 10 $API $DM "SELECT count(*) FROM records"
a_eq "...not junk.evil.test (in its domain, outside its zone)" 0 $API $DM "SELECT count(*) FROM records WHERE name = 'junk.evil.test' OR name IS NULL"
a_eq "...its zone only" "example.com" $API $DM "SELECT string_agg(name, ',') FROM domains"
a_eq "a subdomain master sees the suffix and the apex SOA and NS" "A,NS,SOA,TXT" $API $SM "SELECT string_agg(type, ',' ORDER BY type) FROM records"
a_eq "...and sees the zone row (it holds a grant on the zone)" "example.com" $API $SM "SELECT string_agg(name, ',') FROM domains"
a_eq "a user in a group sees the zone the group has (other.test)" 3 $API $EVE "SELECT count(*) FROM records"
a_eq "a user in a group in a group (gina, team, org)" 2 $API $GINA "SELECT count(*) FROM records"
a_eq "...and only that zone" "third.test" $API $GINA "SELECT string_agg(name, ',') FROM domains"
a_eq "a principal without grants sees no record" 0 $API $NOG "SELECT count(*) FROM records"
a_eq "...no zone" 0 $API $NOG "SELECT count(*) FROM domains"
oq "UPDATE karidns_auth.principals SET disabled = true WHERE name = 'org'" > /dev/null
a_eq "a grant of a disabled group does not count" 0 $API $GINA "SELECT count(*) FROM records"
oq "UPDATE karidns_auth.principals SET disabled = false WHERE name = 'org'" > /dev/null
a_eq "...it does again once the group is enabled" 2 $API $GINA "SELECT count(*) FROM records"
a_eq "domainmetadata: the zone's rows" "ALLOW-AXFR-FROM" $API $DM "SELECT string_agg(kind, ',') FROM domainmetadata"
a_eq "karidns_domain_views and karidns_zone_tagdefs: the zone's rows" "1 1" $API $DM "SELECT count(*) FROM karidns_domain_views; SELECT count(*) FROM karidns_zone_tagdefs"
a_eq "the tags of the records the principal sees (www.example.com; a.sub.example.com for tinydns)" "1 1" $API $DM "SELECT count(*) FROM karidns_record_tags; SELECT count(*) FROM karidns_record_tinydns"
a_eq "a subdomain master sees the tags of the records of its suffix only (none of www)" "0 1" $API $SM "SELECT count(*) FROM karidns_record_tags; SELECT count(*) FROM karidns_record_tinydns"
a_eq "a global master sees all tags" 2 $API $GM "SELECT count(*) FROM karidns_record_tags"

echo "-- cryptokeys"
a_eq "the key rows of the zones with a grant (id, domain_id, flags, active, published)" 1 $API $DM "SELECT count(*) FROM (SELECT id, domain_id, flags, active, published FROM cryptokeys) x"
a_eq "...a global master sees both" 2 $API $GM "SELECT count(*) FROM cryptokeys"
a_eq "...no grant, no key row" 0 $API $NOG "SELECT count(*) FROM cryptokeys"
a_err "cryptokeys.content is not readable by the API role" "permission denied" $API $GM "SELECT content FROM cryptokeys"
a_err "SELECT * FROM cryptokeys is denied" "permission denied" $API $GM "SELECT * FROM cryptokeys"
a_err "...also in a WHERE clause" "permission denied" $API $GM "SELECT id FROM cryptokeys WHERE content LIKE 'SECRET%'"
a_err "the API role cannot INSERT a key" "permission denied" $API $GM "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ($EX, 257, true, 'x')"
a_err "...UPDATE" "permission denied" $API $GM "UPDATE cryptokeys SET active = false"
a_err "...or DELETE one" "permission denied" $API $GM "DELETE FROM cryptokeys"

echo "-- record writes: dm (policy std: A AAAA CNAME MX TXT SRV, TTL 60..86400, no wildcard / delegation / DNAME / apex)"
CL0=$(pq "SELECT coalesce(max(seq), 0) FROM karidns_changes")
a_ok "an A record in the zone" $API $DM "$(ri $EX new1.example.com A 192.0.2.10 300)"
oeq "...the change log got a row for the zone (the trigger runs as the owner; the loader's auto reload depends on it)" "t" "SELECT count(*) >= 1 FROM karidns_changes WHERE seq > $CL0 AND domain_id = $EX"
a_ok "a TXT record at the TTL minimum (60) and maximum (86400)" $API $DM "$(ri $EX new2.example.com TXT hello 60); $(ri $EX new3.example.com TXT hello 86400)"
a_ok "a name below an existing one (a.b.c.example.com)" $API $DM "$(ri $EX a.b.c.example.com A 192.0.2.11 300)"
a_ok "a lower case type is the same type" $API $DM "$(ri $EX new4.example.com a 192.0.2.12 300)"
a_eq "INSERT ... RETURNING works (the new row passes the SELECT policy too)" "new5.example.com" $API $DM "$(ri $EX new5.example.com A 192.0.2.12 300) RETURNING name"
a_eq "...also for a subdomain master (RETURNING a name under its suffix)" "r.sub.example.com" $API $SM "$(ri $EX r.sub.example.com A 192.0.2.12 300) RETURNING name"
a_err "the API role has no TRUNCATE" "permission denied" $API $GM "TRUNCATE records"
a_err "the apex A record" "$RLSERR" $API $DM "$(ri $EX example.com A 192.0.2.13 300)"
a_err "a wildcard *.example.com" "$RLSERR" $API $DM "$(ri $EX '*.example.com' A 192.0.2.13 300)"
a_err "a wildcard label in the middle (x.*.example.com)" "$RLSERR" $API $DM "$(ri $EX 'x.*.example.com' A 192.0.2.13 300)"
a_ok "a * inside a label is not a wildcard (a*b.example.com)" $API $DM "$(ri $EX 'a*b.example.com' A 192.0.2.13 300)"
a_err "NS below the apex (a delegation)" "$RLSERR" $API $DM "$(ri $EX del.example.com NS ns.x.test 300)"
a_err "NS at the apex" "$RLSERR" $API $DM "$(ri $EX example.com NS ns.x.test 300)"
a_err "DNAME" "$RLSERR" $API $DM "$(ri $EX dn.example.com DNAME x.test 300)"
a_err "TTL below the minimum (30)" "$RLSERR" $API $DM "$(ri $EX ttl1.example.com A 192.0.2.14 30)"
a_err "TTL above the maximum (86401)" "$RLSERR" $API $DM "$(ri $EX ttl2.example.com A 192.0.2.14 86401)"
a_err "TTL NULL counts as 0 (below 60)" "$RLSERR" $API $DM "$(ri $EX ttl3.example.com A 192.0.2.14 NULL)"
a_err "a type the policy does not allow (PTR)" "$RLSERR" $API $DM "$(ri $EX ptr.example.com PTR x.test 300)"
for ty in RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY TYPE46 TYPE0048; do
    a_err "the DNSSEC-managed type $ty" "$RLSERR" $API $DM "$(ri $EX sig.example.com $ty x 300)"
done
a_err "SOA at the apex" "$RLSERR" $API $DM "$(ri $EX example.com SOA 'ns1.example.com hm.example.com 1 2 3 4 5' 300)"
a_err "a name outside the zone (evil.test)" "$RLSERR" $API $DM "$(ri $EX evil.test A 192.0.2.15 300)"
a_err "a name that only ends like the zone (notexample.com)" "$RLSERR" $API $DM "$(ri $EX notexample.com A 192.0.2.15 300)"
a_err "a name with a trailing dot" "$RLSERR" $API $DM "$(ri $EX 'trail.example.com.' A 192.0.2.15 300)"
a_err "a record of another zone (domain_id of other.test)" "$RLSERR" $API $DM "$(ri $OTHER www2.other.test A 192.0.2.16 300)"
a_err "a record in the other zone's domain_id with a name of the own zone" "$RLSERR" $API $DM "$(ri $OTHER www2.example.com A 192.0.2.16 300)"
a_err "a record without a domain" "$RLSERR" $API $DM "$(ri NULL orphan.example.com A 192.0.2.16 300)"
a_err "a record without a name" "$RLSERR" $API $DM "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($EX, NULL, 'A', '192.0.2.16', 300)"
a_ok "an empty non-terminal (type NULL)" $API $DM "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($EX, 'ent.example.com', NULL, NULL, NULL)"
a_err "...but not at the apex" "$RLSERR" $API $DM "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($EX, 'example.com', NULL, NULL, NULL)"
a_err "...nor a wildcard one" "$RLSERR" $API $DM "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($EX, '*.ent.example.com', NULL, NULL, NULL)"
a_err "...nor outside the zone" "$RLSERR" $API $DM "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($EX, 'ent.other.test', NULL, NULL, NULL)"
a_n "UPDATE of an existing record the grant covers (www A, new TTL)" 1 $API $DM "UPDATE records SET ttl = 600 WHERE name = 'www.example.com' AND type = 'A'"
a_n "UPDATE of the apex A (readable, not writable): no row changes" 0 $API $DM "UPDATE records SET ttl = 600 WHERE name = 'example.com' AND type = 'A'"
a_n "UPDATE of the SOA: no row changes" 0 $API $DM "UPDATE records SET content = 'ns1.example.com hostmaster.example.com 5 7200 3600 1209600 300' WHERE type = 'SOA'"
a_n "UPDATE of the DNSKEY: no row changes" 0 $API $DM "UPDATE records SET ttl = 1 WHERE type = 'DNSKEY'"
a_n "UPDATE of the row without a name: no row changes" 0 $API $DM "UPDATE records SET ttl = 1000 WHERE name IS NULL"
a_err "UPDATE to a TTL outside the policy" "$RLSERR" $API $DM "UPDATE records SET ttl = 10 WHERE name = 'www.example.com' AND type = 'A'"
a_err "UPDATE to a type the policy does not allow (NS)" "$RLSERR" $API $DM "UPDATE records SET type = 'NS' WHERE name = 'www.example.com' AND type = 'A'"
a_err "UPDATE that moves a record to the apex" "$RLSERR" $API $DM "UPDATE records SET name = 'example.com' WHERE name = 'www.example.com' AND type = 'A'"
a_err "UPDATE that moves a record to another zone" "$RLSERR" $API $DM "UPDATE records SET domain_id = $OTHER WHERE name = 'www.example.com' AND type = 'A'"
a_n "UPDATE of a record of another zone: not even visible" 0 $API $DM "UPDATE records SET ttl = 600 WHERE name = 'www.other.test'"
a_n "DELETE of a record the grant covers" 1 $API $DM "DELETE FROM records WHERE name = 'new1.example.com'"
a_n "DELETE of the apex A: no row" 0 $API $DM "DELETE FROM records WHERE name = 'example.com' AND type = 'A'"
a_n "DELETE of the SOA: no row" 0 $API $DM "DELETE FROM records WHERE type = 'SOA'"
a_n "DELETE of the RRSIG: no row" 0 $API $DM "DELETE FROM records WHERE type = 'RRSIG'"
a_n "DELETE of a record of another zone: no row" 0 $API $DM "DELETE FROM records WHERE name = 'www.other.test'"
a_n "DELETE of every row the principal may delete (5 of the fixture, 7 of its own, 1 of sm's); the rest stays" 13 $API $DM "DELETE FROM records WHERE true"
oeq "...the zone keeps its apex SOA, NS, A, the DNSKEY, the RRSIG, the row without a name and junk.evil.test" "7" "SELECT count(*) FROM records WHERE domain_id = $EX"
# restore the fixture rows the cases deleted
oq "$(ri $EX www.example.com A 192.0.2.2 300); INSERT INTO records (domain_id, name, type, content, ttl, prio) VALUES ($EX, 'mail.example.com', 'MX', 'mail.example.com', 300, 10); $(ri $EX a.sub.example.com A 192.0.2.3 300); $(ri $EX sub.example.com TXT sub 300); $(ri $EX evilsub.example.com A 192.0.2.4 300)" > /dev/null
oq "INSERT INTO karidns_record_tags (record_id, location_tag) SELECT id, 'tokyo' FROM records WHERE name = 'www.example.com'; INSERT INTO karidns_record_tinydns (record_id, ttd) SELECT id, 1 FROM records WHERE name = 'a.sub.example.com'" > /dev/null

echo "-- dmw (policy wide: wildcard, delegation, DNAME, apex, TTL 0.., SOA in the list)"
a_ok "a wildcard" $API $DMW "$(ri $EX '*.w.example.com' A 192.0.2.20 300)"
a_ok "NS below the apex (delegation)" $API $DMW "$(ri $EX del.example.com NS ns.x.test 300)"
a_ok "DNAME" $API $DMW "$(ri $EX dn.example.com DNAME x.test 300)"
a_ok "the apex A and the apex NS (apex_editable)" $API $DMW "$(ri $EX example.com A 192.0.2.21 300); $(ri $EX example.com NS ns9.x.test 300)"
a_ok "TTL 0 and TTL NULL (NULL counts as 0)" $API $DMW "$(ri $EX z1.example.com A 192.0.2.22 0); $(ri $EX z2.example.com A 192.0.2.22 NULL)"
a_err "an SOA insert, although the policy lists SOA and apex_editable (a domain master)" "$RLSERR" $API $DMW "$(ri $EX example.com SOA 'ns1.example.com hm.example.com 1 2 3 4 5' 300)"
a_n "an SOA UPDATE: no row" 0 $API $DMW "UPDATE records SET content = 'ns1.example.com hostmaster.example.com 5 7200 3600 1209600 300' WHERE type = 'SOA'"
a_err "a DNSSEC type, whatever the policy" "$RLSERR" $API $DMW "$(ri $EX k.example.com DNSKEY x 300)"
a_n "cleanup of the cases" 7 $API $DMW "DELETE FROM records WHERE name IN ('*.w.example.com', 'del.example.com', 'dn.example.com', 'z1.example.com', 'z2.example.com') OR (name = 'example.com' AND content IN ('192.0.2.21', 'ns9.x.test'))"

echo "-- gm (global master, policy all) and gmn (global master, policy std)"
a_ok "gm: a record in any zone (other.test)" $API $GM "$(ri $OTHER g1.other.test A 192.0.2.30 300)"
a_ok "gm: the apex NS and a delegation" $API $GM "$(ri $OTHER other.test NS ns9.x.test 300); $(ri $OTHER del.other.test NS ns9.x.test 300)"
a_n "gm: UPDATE of the SOA (policy lists SOA, apex_editable)" 1 $API $GM "UPDATE records SET content = 'ns1.other.test hostmaster.other.test 2 7200 3600 1209600 300' WHERE name = 'other.test' AND type = 'SOA'"
a_err "gm: a DNSSEC type, whatever the policy" "$RLSERR" $API $GM "$(ri $OTHER k.other.test RRSIG x 300)"
a_err "gm: a name outside the zone" "$RLSERR" $API $GM "$(ri $OTHER www.example.com A 192.0.2.31 300)"
a_ok "gmn: a record in any zone (third.test)" $API $GMN "$(ri $THIRD g2.third.test A 192.0.2.32 300)"
a_err "gmn: the policy applies to a global master (no apex)" "$RLSERR" $API $GMN "$(ri $THIRD third.test A 192.0.2.33 300)"
a_err "gmn: ...no delegation" "$RLSERR" $API $GMN "$(ri $THIRD del.third.test NS ns9.x.test 300)"
a_n "gmn: ...no SOA update" 0 $API $GMN "UPDATE records SET content = 'ns1.third.test hostmaster.third.test 8 7200 3600 1209600 300' WHERE type = 'SOA' AND name = 'third.test'"
oq "DELETE FROM records WHERE name IN ('g1.other.test', 'del.other.test', 'g2.third.test') OR (name = 'other.test' AND content = 'ns9.x.test')" > /dev/null

echo "-- generic type names (TYPE2 is NS, TYPE6 is SOA, TYPE39 is DNAME, TYPE46.. are DNSSEC types): dma has the policy alias (A NS DNAME TXT, no flags)"
DMA=$(pid dma)
a_ok "dma: an A record" $API $DMA "$(ri $EX al1.example.com A 192.0.2.80 300)"
a_err "dma: NS below the apex is a delegation (not allowed)" "$RLSERR" $API $DMA "$(ri $EX al2.example.com NS ns.x.test 300)"
a_err "dma: ...TYPE2 is NS and gets the same rule" "$RLSERR" $API $DMA "$(ri $EX al3.example.com TYPE2 ns.x.test 300)"
a_err "dma: ...TYPE0002 too" "$RLSERR" $API $DMA "$(ri $EX al3.example.com TYPE0002 ns.x.test 300)"
a_err "dma: DNAME is not allowed (allow_dname is false)" "$RLSERR" $API $DMA "$(ri $EX al4.example.com DNAME x.test 300)"
a_err "dma: ...TYPE39 is DNAME" "$RLSERR" $API $DMA "$(ri $EX al4.example.com TYPE39 x.test 300)"
a_err "dma: ...TYPE0039 too" "$RLSERR" $API $DMA "$(ri $EX al4.example.com TYPE0039 x.test 300)"
a_err "dma: TYPE6 at the apex is an SOA" "$RLSERR" $API $DMA "$(ri $EX example.com TYPE6 'ns1.example.com hm.example.com 1 2 3 4 5' 300)"
a_err "dma: TYPE6 below the apex is an SOA too" "$RLSERR" $API $DMA "$(ri $EX al5.example.com TYPE6 'ns1.example.com hm.example.com 1 2 3 4 5' 300)"
a_err "dma: TYPE48 is DNSKEY" "$RLSERR" $API $DMA "$(ri $EX al6.example.com TYPE48 x 300)"
a_err "dma: TYPE1 is not on its list (only the named A is): other generic forms are types of their own" "$RLSERR" $API $DMA "$(ri $EX al7.example.com TYPE1 x 300)"
a_err "dma: TYPE65280 neither" "$RLSERR" $API $DMA "$(ri $EX al7.example.com TYPE65280 x 300)"
a_err "UPDATE of a record into TYPE2 (an NS below the apex) is refused as well" "$RLSERR" $API $DMA "UPDATE records SET type = 'TYPE2' WHERE name = 'al1.example.com'"
a_ok "a policy with the generic form of an ordinary type is a valid policy (TYPE1)" $API $GM "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('tp1', ARRAY['TYPE1', 'TYPE65280'])"
for tp in TYPE2 TYPE0006 TYPE39 TYPE46 TYPE0060; do
    a_err "an rr_policy cannot list $tp (an alias of NS, SOA, DNAME or a DNSSEC type)" "check constraint" $API $GM "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('tp_$tp', ARRAY['A', '$tp'])"
done
a_ok "...but TYPE26 is nobody's alias" $API $GM "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('tp26', ARRAY['TYPE26'])"
oq "DELETE FROM karidns_auth.rr_policies WHERE name IN ('tp1', 'tp26'); DELETE FROM records WHERE name = 'al1.example.com'" > /dev/null
oeq "canon_type: the generic forms are read as the names" "NS|SOA|DNAME|RRSIG|NSEC3PARAM|CDNSKEY|TYPE1|TYPE99999|TYPE0|A|" \
    "SELECT karidns_auth.canon_type('type2') || '|' || karidns_auth.canon_type(' TYPE0006 ') || '|' || karidns_auth.canon_type('TYPE39') || '|' || karidns_auth.canon_type('TYPE46') || '|' || karidns_auth.canon_type('TYPE51') || '|' || karidns_auth.canon_type('TYPE60') || '|' || karidns_auth.canon_type('TYPE1') || '|' || karidns_auth.canon_type('TYPE99999') || '|' || karidns_auth.canon_type('TYPE0') || '|' || karidns_auth.canon_type('a') || '|' || coalesce(karidns_auth.canon_type(NULL), '')"

echo "-- sm (subdomain master sub.example.com, policy std), smz (suffix example.com, policy wide)"
a_ok "sm: a name under the suffix" $API $SM "$(ri $EX b.sub.example.com A 192.0.2.40 300)"
a_ok "sm: a name deep under the suffix" $API $SM "$(ri $EX x.y.sub.example.com A 192.0.2.40 300)"
a_ok "sm: the suffix itself" $API $SM "$(ri $EX sub.example.com TXT again 300)"
a_err "sm: evilsub.example.com (not under sub.example.com: label boundary)" "$RLSERR" $API $SM "$(ri $EX new.evilsub.example.com A 192.0.2.41 300)"
a_err "sm: ...nor the name evilsub.example.com itself" "$RLSERR" $API $SM "$(ri $EX evilsub.example.com A 192.0.2.41 300)"
a_err "sm: xsub.example.com" "$RLSERR" $API $SM "$(ri $EX xsub.example.com A 192.0.2.41 300)"
a_err "sm: a name beside the suffix (www.example.com)" "$RLSERR" $API $SM "$(ri $EX www2.example.com A 192.0.2.41 300)"
a_err "sm: the apex" "$RLSERR" $API $SM "$(ri $EX example.com A 192.0.2.41 300)"
a_err "sm: the wildcard under the suffix (policy std)" "$RLSERR" $API $SM "$(ri $EX '*.sub.example.com' A 192.0.2.41 300)"
a_n "sm: UPDATE of a record under the suffix" 1 $API $SM "UPDATE records SET ttl = 301 WHERE name = 'a.sub.example.com'"
a_n "sm: UPDATE of evilsub.example.com (not visible): no row" 0 $API $SM "UPDATE records SET ttl = 301 WHERE name = 'evilsub.example.com'"
a_n "sm: DELETE of evilsub.example.com: no row" 0 $API $SM "DELETE FROM records WHERE name = 'evilsub.example.com'"
a_n "sm: UPDATE of the apex NS (visible to every grant, not writable): no row" 0 $API $SM "UPDATE records SET ttl = 1 WHERE name = 'example.com' AND type = 'NS'"
a_ok "smz: a name under example.com" $API $SMZ "$(ri $EX w1.example.com A 192.0.2.42 300)"
a_err "smz: the apex, although the policy has apex_editable (a subdomain master)" "$RLSERR" $API $SMZ "$(ri $EX example.com A 192.0.2.42 300)"
a_err "smz: the apex NS" "$RLSERR" $API $SMZ "$(ri $EX example.com NS ns9.x.test 300)"
a_ok "smz: a delegation (allow_delegation)" $API $SMZ "$(ri $EX del2.example.com NS ns9.x.test 300)"
oq "DELETE FROM records WHERE name IN ('b.sub.example.com', 'x.y.sub.example.com', 'w1.example.com', 'del2.example.com') OR (name = 'sub.example.com' AND content = 'again')" > /dev/null

echo "-- one grant covers the row (grants are never combined)"
a_ok "half: A with TTL 100 (grant half_a)" $API $HALF "$(ri $EX h1.example.com A 192.0.2.50 100)"
a_ok "half: TXT with TTL 1500 (grant half_b)" $API $HALF "$(ri $EX h2.example.com TXT x 1500)"
a_err "half: TXT with TTL 100 (half_a has the TTL, half_b the type)" "$RLSERR" $API $HALF "$(ri $EX h3.example.com TXT x 100)"
a_err "half: TXT with TTL 0 (no grant has both the type and the TTL)" "$RLSERR" $API $HALF "$(ri $EX h4.example.com TXT x 0)"
a_ok "half: A with TTL 1500 (both grants allow it)" $API $HALF "$(ri $EX h5.example.com A 192.0.2.50 1500)"
a_ok "halfs: A under a.example.com (grant only_a)" $API $HALFS "$(ri $EX x.a.example.com A 192.0.2.51 300)"
a_ok "halfs: MX under b.example.com (grant only_mx)" $API $HALFS "$(ri $EX x.b.example.com MX 'mail.x.test' 300)"
a_err "halfs: MX under a.example.com (the scope of one grant, the type of the other)" "$RLSERR" $API $HALFS "$(ri $EX y.a.example.com MX 'mail.x.test' 300)"
a_err "halfs: A under b.example.com" "$RLSERR" $API $HALFS "$(ri $EX y.b.example.com A 192.0.2.51 300)"
oq "DELETE FROM records WHERE name IN ('h1.example.com', 'h2.example.com', 'h5.example.com', 'x.a.example.com', 'x.b.example.com')" > /dev/null

echo "-- bump_serial"
a_eq "a domain master adds 1 to the serial" 101 $API $DM "SELECT karidns_auth.bump_serial('public', $EX)"
oeq "...the SOA content has the new serial and nothing else changed" "ns1.example.com hostmaster.example.com 101 7200 3600 1209600 300" "SELECT content FROM records WHERE domain_id = $EX AND type = 'SOA'"
a_eq "a subdomain master may too (any grant on the zone)" 102 $API $SM "SELECT karidns_auth.bump_serial('public', $EX)"
a_eq "a global master may bump any zone" 8 $API $GM "SELECT karidns_auth.bump_serial('public', $THIRD)"
a_err "a principal without a grant on the zone" "no grant" $API $NOG "SELECT karidns_auth.bump_serial('public', $EX)"
a_err "a domain master of another zone" "no grant" $API $DM "SELECT karidns_auth.bump_serial('public', $OTHER)"
a_err "no principal" "no valid karidns.principal" $API NONE "SELECT karidns_auth.bump_serial('public', $EX)"
a_err "a disabled principal" "no valid karidns.principal" $API $DIS "SELECT karidns_auth.bump_serial('public', $EX)"
a_err "a zone that does not exist" "no grant" $API $GM "SELECT karidns_auth.bump_serial('public', 99999)"
a_err "a schema that is not a data schema" "not a KariDNS data schema" $API $GM "SELECT karidns_auth.bump_serial('karidns_auth', $EX)"
a_err "a zone without an SOA" "no SOA" $API $GM "SELECT karidns_auth.bump_serial('public', $NOSOA)"
oq "UPDATE records SET content = 'ns1.third.test hostmaster.third.test 4294967295 7200 3600 1209600 300' WHERE domain_id = $THIRD AND type = 'SOA'" > /dev/null
a_eq "RFC 1982: 4294967295 + 1 = 0" 0 $API $GM "SELECT karidns_auth.bump_serial('public', $THIRD)"
oeq "...the content has serial 0" "ns1.third.test hostmaster.third.test 0 7200 3600 1209600 300" "SELECT content FROM records WHERE domain_id = $THIRD AND type = 'SOA'"
oq "UPDATE records SET content = 'ns1.third.test hostmaster.third.test 4294967294 7200 3600 1209600 300' WHERE domain_id = $THIRD AND type = 'SOA'" > /dev/null
a_eq "...4294967294 + 1 = 4294967295" 4294967295 $API $GM "SELECT karidns_auth.bump_serial('public', $THIRD)"
oq "UPDATE records SET content = 'broken' WHERE domain_id = $THIRD AND type = 'SOA'" > /dev/null
a_err "an SOA whose serial cannot be read" "no serial" $API $GM "SELECT karidns_auth.bump_serial('public', $THIRD)"
oq "UPDATE records SET content = 'ns1.third.test hostmaster.third.test 7 7200 3600 1209600 300' WHERE domain_id = $THIRD AND type = 'SOA'" > /dev/null
oeq "the audit log has the bump as an UPDATE of records by the principal (name, zone, database role)" "U|dm|example.com|$API" \
    "SELECT op || '|' || principal_name || '|' || zone_name || '|' || db_role FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'U' AND principal_id = $DM AND row_id = (SELECT id FROM records WHERE domain_id = $EX AND type = 'SOA') ORDER BY id LIMIT 1"
oeq "...with the SOA before and after (serial 100 -> 101)" "t" "SELECT (before ->> 'content') LIKE '% 100 %' AND (after ->> 'content') LIKE '% 101 %' FROM karidns_auth.audit_log WHERE table_name = 'records' AND principal_id = $DM AND op = 'U' AND row_id = (SELECT id FROM records WHERE domain_id = $EX AND type = 'SOA') ORDER BY id LIMIT 1"
a_err "bump_serial is not callable by the signer role" "permission denied" $SIG NONE "SELECT karidns_auth.bump_serial('public', $EX)"

echo "-- the other tables"
a_err "domains: a domain master cannot create a zone" "$RLSERR" $API $DM "INSERT INTO domains (name, type) VALUES ('new.test', 'NATIVE')"
a_ok "domains: a global master can" $API $GM "INSERT INTO domains (name, type) VALUES ('new.test', 'NATIVE')"
a_n "domains: a domain master cannot UPDATE its zone: no row" 0 $API $DM "UPDATE domains SET account = 'x'"
a_n "domains: a global master can" 1 $API $GM "UPDATE domains SET account = 'x' WHERE name = 'new.test'"
a_n "domains: a domain master cannot DELETE: no row" 0 $API $DM "DELETE FROM domains"
a_ok "a grant on the new zone, then a global master deletes the zone" $API $GM "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) SELECT $DM, 'domain_master', 'public', 'new.test', id FROM karidns_auth.rr_policies WHERE name = 'std'"
a_n "domains: DELETE (through the trigger on domains the grant goes too)" 1 $API $GM "DELETE FROM domains WHERE name = 'new.test'"
oeq "...no grant of the zone is left" "0" "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'new.test'"
a_err "domainmetadata: a domain master cannot write (global master only)" "$RLSERR" $API $DM "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($EX, 'SOA-EDIT', 'EPOCH')"
a_ok "domainmetadata: a global master writes an ordinary kind" $API $GM "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($EX, 'SOA-EDIT', 'EPOCH')"
for k in PRESIGNED NSEC3PARAM X-KARIDNS-SIGNER presigned; do
    a_err "domainmetadata: a global master cannot write the signer's kind $k" "$RLSERR" $API $GM "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($EX, '$k', '1')"
done
a_err "domainmetadata: ...nor turn an ordinary row into one" "$RLSERR" $API $GM "UPDATE domainmetadata SET kind = 'PRESIGNED' WHERE kind = 'SOA-EDIT'"
a_n "domainmetadata: ...nor change or delete the signer's rows (third.test PRESIGNED)" 0 $API $GM "DELETE FROM domainmetadata WHERE kind = 'PRESIGNED'"
a_n "domainmetadata: a global master deletes an ordinary row" 1 $API $GM "DELETE FROM domainmetadata WHERE kind = 'SOA-EDIT' AND content = 'EPOCH'"
APEXA=$(pq "SELECT id FROM records WHERE name = 'example.com' AND type = 'A'"); OTHREC=$(pq "SELECT id FROM records WHERE name = 'www.other.test'")
a_ok "tags: a domain master tags a record it can write" $API $DM "INSERT INTO karidns_record_tags (record_id, location_tag) SELECT id, 'osaka' FROM records WHERE name = 'mail.example.com'"
a_err "tags: ...not a record it cannot (the apex A)" "$RLSERR" $API $DM "INSERT INTO karidns_record_tags (record_id, location_tag) VALUES ($APEXA, 'osaka')"
a_err "tags: ...nor a record of another zone" "$RLSERR" $API $DM "INSERT INTO karidns_record_tags (record_id, location_tag) VALUES ($OTHREC, 'osaka')"
a_n "tags: UPDATE of a tag of a writable record" 1 $API $DM "UPDATE karidns_record_tags SET location_tag = 'kyoto' WHERE record_id = (SELECT id FROM records WHERE name = 'mail.example.com')"
a_n "tags: DELETE" 1 $API $DM "DELETE FROM karidns_record_tags WHERE record_id = (SELECT id FROM records WHERE name = 'mail.example.com')"
a_ok "tinydns rows follow the same rule" $API $DM "INSERT INTO karidns_record_tinydns (record_id, ttd) SELECT id, 5 FROM records WHERE name = 'mail.example.com'"
a_err "...also for the record of another zone" "$RLSERR" $API $DM "INSERT INTO karidns_record_tinydns (record_id, ttd) VALUES ($OTHREC, 5)"
a_n "tinydns: DELETE" 1 $API $DM "DELETE FROM karidns_record_tinydns WHERE record_id = (SELECT id FROM records WHERE name = 'mail.example.com')"
a_ok "karidns_zone_tagdefs: a domain master writes" $API $DM "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES ($EX, 'location', 'osaka', '198.51.100.0/24')"
a_err "...not for another zone" "$RLSERR" $API $DM "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES ($OTHER, 'location', 'osaka', '198.51.100.0/24')"
a_err "...a subdomain master does not" "$RLSERR" $API $SM "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES ($EX, 'location', 'osaka', '198.51.100.0/24')"
a_n "...DELETE by the domain master" 1 $API $DM "DELETE FROM karidns_zone_tagdefs WHERE tag = 'osaka'"
a_err "karidns_domain_views: a domain master cannot (global master only)" "$RLSERR" $API $DM "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES ($EX, 'external')"
a_ok "...a global master can" $API $GM "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES ($EX, 'external')"
a_n "...and delete" 1 $API $GM "DELETE FROM karidns_domain_views WHERE view_name = 'external'"
a_ok "karidns_reload_requests: a request for the own zone" $API $DM "INSERT INTO karidns_reload_requests (zone) VALUES ('example.com')"
a_ok "...also a subdomain master (a grant on the zone)" $API $SM "INSERT INTO karidns_reload_requests (zone) VALUES ('example.com')"
a_err "...not for another zone" "$RLSERR" $API $DM "INSERT INTO karidns_reload_requests (zone) VALUES ('other.test')"
a_err "...nor for all zones (zone NULL) by a domain master" "$RLSERR" $API $DM "INSERT INTO karidns_reload_requests (zone, force) VALUES (NULL, false)"
a_ok "...a global master can ask for all zones" $API $GM "INSERT INTO karidns_reload_requests (zone) VALUES (NULL)"
a_err "...no principal, no request" "$RLSERR" $API NONE "INSERT INTO karidns_reload_requests (zone) VALUES ('example.com')"
a_eq "...a domain master sees the requests of its zone (two), not the one for all zones" 2 $API $DM "SELECT count(*) FROM karidns_reload_requests"
a_eq "...a domain master of another zone (eve: other.test) sees none of them" 0 $API $EVE "SELECT count(*) FROM karidns_reload_requests"
a_eq "...a principal without a grant sees none" 0 $API $NOG "SELECT count(*) FROM karidns_reload_requests"
a_eq "...no principal, none" 0 $API NONE "SELECT count(*) FROM karidns_reload_requests"
a_eq "...a global master sees all three" 3 $API $GM "SELECT count(*) FROM karidns_reload_requests"
a_eq "INSERT ... RETURNING of a request works (the new row is one the principal sees)" "example.com" $API $DM "INSERT INTO karidns_reload_requests (zone) VALUES ('example.com') RETURNING zone"
a_err "no API session can delete a request (no DELETE right)" "permission denied" $API $GM "DELETE FROM karidns_reload_requests"
a_err "the API role cannot read the change log" "permission denied" $API $GM "SELECT count(*) FROM karidns_changes"
a_err "...nor write it" "permission denied" $API $GM "INSERT INTO karidns_changes (domain_id, changed_at) VALUES ($EX, 0)"
a_err "...nor delete from it" "permission denied" $API $GM "DELETE FROM karidns_changes"
a_ok "a global master asks for 1100 reload requests of all zones in one statement (zone NULL)" $API $GM "INSERT INTO karidns_reload_requests (zone) SELECT NULL::varchar FROM generate_series(1, 1100)"
oeq "...the prune trigger (it runs as the owner) keeps the newest 1000" "1000" "SELECT count(*) FROM karidns_reload_requests"
a_eq "...a domain master still sees only its own zone's (the pruned ones are gone, the NULL zone ones are not its)" 0 $API $DM "SELECT count(*) FROM karidns_reload_requests"
a_err "the API role cannot UPDATE a reload request" "permission denied" $API $GM "UPDATE karidns_reload_requests SET force = true"

echo "-- karidns_auth: principals, memberships, policies, credentials, grants"
oeq "principals, memberships and rr_policies are readable by every API session (names are needed to grant; a login looks the user up)" "19 3 20" \
    "SELECT (SELECT count(*) FROM karidns_auth.principals)::text || ' ' || (SELECT count(*) FROM karidns_auth.memberships) || ' ' || (SELECT count(*) FROM karidns_auth.rr_policies)"
a_eq "...an API session without a principal reads them" "19 3 20" $API NONE "SELECT count(*) FROM karidns_auth.principals; SELECT count(*) FROM karidns_auth.memberships; SELECT count(*) FROM karidns_auth.rr_policies"
a_err "principals: a domain master cannot create one" "$RLSERR" $API $DM "INSERT INTO karidns_auth.principals (kind, name) VALUES ('user', 'zed')"
a_ok "...a global master can" $API $GM "INSERT INTO karidns_auth.principals (kind, name) VALUES ('user', 'zed')"
a_n "...a domain master cannot UPDATE (disable) one: no row" 0 $API $DM "UPDATE karidns_auth.principals SET disabled = true WHERE name = 'zed'"
a_n "...a global master can" 1 $API $GM "UPDATE karidns_auth.principals SET disabled = true WHERE name = 'zed'"
a_err "memberships: a domain master cannot add one" "$RLSERR" $API $DM "INSERT INTO karidns_auth.memberships (member_id, group_id) SELECT z.id, g.id FROM karidns_auth.principals z, karidns_auth.principals g WHERE z.name = 'zed' AND g.name = 'g_ops'"
a_ok "...a global master can (and the closure follows: the trigger is SECURITY DEFINER)" $API $GM "INSERT INTO karidns_auth.memberships (member_id, group_id) SELECT z.id, g.id FROM karidns_auth.principals z, karidns_auth.principals g WHERE z.name = 'zed' AND g.name = 'g_ops'"
a_eq "the new member is disabled: it sees nothing" 0 $API "$(pid zed)" "SELECT count(*) FROM records"
oq "UPDATE karidns_auth.principals SET disabled = false WHERE name = 'zed'" > /dev/null
a_eq "...enabled, it has the grants of g_ops (reads other.test)" 3 $API "$(pid zed)" "SELECT count(*) FROM records"
a_n "...a global master removes the membership" 1 $API $GM "DELETE FROM karidns_auth.memberships WHERE member_id = (SELECT id FROM karidns_auth.principals WHERE name = 'zed')"
a_n "...and the principal" 1 $API $GM "DELETE FROM karidns_auth.principals WHERE name = 'zed'"
a_err "rr_policies: a domain master cannot create one" "$RLSERR" $API $DM "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('mine', ARRAY['A'])"
a_ok "...a global master can" $API $GM "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('mine', ARRAY['A'])"
a_n "...a domain master cannot change it: no row" 0 $API $DM "UPDATE karidns_auth.rr_policies SET allow_wildcard = true WHERE name = 'mine'"
a_n "...a global master deletes it" 1 $API $GM "DELETE FROM karidns_auth.rr_policies WHERE name = 'mine'"
a_eq "credentials: a principal reads its own row only" 1 $API $DM "SELECT count(*) FROM karidns_auth.credentials"
a_eq "...a global master reads all (gm, dm, sm)" 3 $API $GM "SELECT count(*) FROM karidns_auth.credentials"
a_eq "...a principal without credentials none" 0 $API $NOG "SELECT count(*) FROM karidns_auth.credentials"
a_n "...a principal updates its own row" 1 $API $DM "UPDATE karidns_auth.credentials SET totp_enabled = true WHERE principal_id = $DM"
a_n "...not another one's: no row" 0 $API $DM "UPDATE karidns_auth.credentials SET totp_enabled = true WHERE principal_id = $SM"
a_err "...and cannot hand its row to another principal" "$RLSERR" $API $DM "UPDATE karidns_auth.credentials SET principal_id = $NOG WHERE principal_id = $DM"
a_err "...cannot create credentials" "$RLSERR" $API $DM "INSERT INTO karidns_auth.credentials (principal_id) VALUES ($NOG)"
a_n "...cannot delete its row: no row" 0 $API $DM "DELETE FROM karidns_auth.credentials WHERE principal_id = $DM"
a_ok "...a global master creates credentials" $API $GM "INSERT INTO karidns_auth.credentials (principal_id, oidc_issuer, oidc_subject) VALUES ($NOG, 'https://idp.example', 'nog')"
a_n "...and deletes them" 1 $API $GM "DELETE FROM karidns_auth.credentials WHERE principal_id = $NOG"
a_err "a plain text password hash is still refused" "check constraint" $API $DM "UPDATE karidns_auth.credentials SET password_hash = 'hunter2' WHERE principal_id = $DM"
# the sign-in with an OpenID Connect provider (item F, M5): no principal exists yet when it starts, so the API role has no right on the table and calls functions
H32="decode(repeat('ab', 32), 'hex')"
a_err "oidc_states: the API role cannot read the table" "permission denied" $API $GM "SELECT count(*) FROM karidns_auth.oidc_states"
a_err "...nor write it" "permission denied" $API $GM "INSERT INTO karidns_auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, expires_at) VALUES ($H32, $H32, 'p', 'n', repeat('v', 43), now())"
a_err "...nor delete from it" "permission denied" $API $GM "DELETE FROM karidns_auth.oidc_states"
a_eq "oidc_state_put() records a state without a principal (no one is signed in yet)" t $API NONE "SELECT karidns_auth.oidc_state_put($H32, $H32, 'idp', 'n', repeat('v', 43), '/zones', 600)"
a_eq "oidc_state_take() returns it once, with its route" "/zones" $API NONE "SELECT return_route FROM karidns_auth.oidc_state_take($H32)"
a_eq "...and a second time finds nothing" 0 $API NONE "SELECT count(*) FROM karidns_auth.oidc_state_take($H32)"
oq "SELECT karidns_auth.oidc_state_put($H32, $H32, 'idp', 'n', repeat('v', 43), '/', 1)" > /dev/null
oq "UPDATE karidns_auth.oidc_states SET created_at = now() - interval '1 minute', expires_at = now() - interval '30 seconds'" > /dev/null
a_eq "...a state that is over is not returned" 0 $API NONE "SELECT count(*) FROM karidns_auth.oidc_state_take($H32)"
oq "DELETE FROM karidns_auth.oidc_states" > /dev/null
a_err "...the table refuses a state that lives more than an hour" "check constraint|violates" $API NONE "SELECT karidns_auth.oidc_state_put($H32, $H32, 'idp', 'n', repeat('v', 43), '/', 7200)"
oq "INSERT INTO karidns_auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, expires_at) SELECT decode(lpad(to_hex(g), 64, '0'), 'hex'), $H32, 'idp', 'n', repeat('v', 43), now() + interval '5 minutes' FROM generate_series(1, 1000) g" > /dev/null
a_eq "oidc_state_put() refuses the 1001st waiting state" f $API NONE "SELECT karidns_auth.oidc_state_put($H32, $H32, 'idp', 'n', repeat('v', 43), '/', 600)"
oq "UPDATE karidns_auth.oidc_states SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute'" > /dev/null
a_eq "...and makes room when they are over" t $API NONE "SELECT karidns_auth.oidc_state_put($H32, $H32, 'idp', 'n', repeat('v', 43), '/', 600)"
oq "UPDATE karidns_auth.oidc_states SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute' WHERE state_hash = decode(repeat('ab', 32), 'hex')" > /dev/null
oq "INSERT INTO karidns_auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, expires_at) VALUES (decode(repeat('cd', 32), 'hex'), $H32, 'idp', 'n', repeat('v', 43), now() + interval '5 minutes')" > /dev/null
a_ok "sweep_expired() runs for the API role" $API NONE "SELECT karidns_auth.sweep_expired()"
oeq "...it deleted the states that are over and left the one that is not" "1" "SELECT count(*) FROM karidns_auth.oidc_states"
oq "DELETE FROM karidns_auth.oidc_states" > /dev/null
# 0.6.1: prune_audit(days), the audit-retention option of the WebAdmin (no role may delete from audit_log; the function does, for rows older than the days, at least 7)
a_err "the API role cannot delete from the audit log itself" "permission denied" $API $GM "DELETE FROM karidns_auth.audit_log"
a_err "prune_audit() refuses fewer than 7 days" "at least 7 days" $API NONE "SELECT karidns_auth.prune_audit(6)"
a_err "...and NULL" "at least 7 days" $API NONE "SELECT karidns_auth.prune_audit(NULL)"
a_err "the signer role has no EXECUTE on prune_audit()" "permission denied" $SIG NONE "SELECT karidns_auth.prune_audit(30)"
# (the function takes the ids to grow with the time, as they do: it looks at the oldest id first.  The rows of this test are older than the ones the log has, so the log is put
# aside while they are checked.)
oq "CREATE TABLE karidns_auth.zz_audit_save AS SELECT * FROM karidns_auth.audit_log; DELETE FROM karidns_auth.audit_log" > /dev/null
oq "INSERT INTO karidns_auth.audit_log (at, data_schema, table_name, op) SELECT now() - interval '100 days', 'public', 'prune_t', 'I' FROM generate_series(1, 10001)" > /dev/null
a_eq "a call deletes at most 10000 rows" 10000 $API NONE "SELECT karidns_auth.prune_audit(90)"
a_eq "...the caller repeats until fewer come back" 1 $API NONE "SELECT karidns_auth.prune_audit(90)"
a_eq "...and then there is nothing to do" 0 $API NONE "SELECT karidns_auth.prune_audit(90)"
oq "INSERT INTO karidns_auth.audit_log (at, data_schema, table_name, op) SELECT now() - make_interval(days => d), 'public', 'prune_t', 'I' FROM unnest(ARRAY[400, 40, 31, 10, 1]) d" > /dev/null
a_eq "prune_audit(30) deletes the rows older than 30 days" 3 $API NONE "SELECT karidns_auth.prune_audit(30)"
oeq "...the newer ones stay" "2" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'prune_t'"
a_eq "...a second call finds nothing to do" 0 $API NONE "SELECT karidns_auth.prune_audit(30)"
oq "DELETE FROM karidns_auth.audit_log; INSERT INTO karidns_auth.audit_log SELECT * FROM karidns_auth.zz_audit_save; DROP TABLE karidns_auth.zz_audit_save" > /dev/null
oq "UPDATE karidns_auth.credentials SET oidc_issuer = 'https://idp.example', oidc_subject = 'dm-sub' WHERE principal_id = $DM" > /dev/null
a_eq "oidc_lookup() finds the user an identity is linked to, without a principal" "$DM" $API NONE "SELECT karidns_auth.oidc_lookup('https://idp.example', 'dm-sub')"
a_eq "...not by another issuer or subject" 0 $API NONE "SELECT count(karidns_auth.oidc_lookup('https://idp.example', 'DM-SUB')) + count(karidns_auth.oidc_lookup('https://other.example', 'dm-sub'))"
oq "UPDATE karidns_auth.principals SET disabled = true WHERE id = $DM" > /dev/null
a_eq "...not a disabled user" 0 $API NONE "SELECT count(karidns_auth.oidc_lookup('https://idp.example', 'dm-sub'))"
oq "UPDATE karidns_auth.principals SET disabled = false WHERE id = $DM" > /dev/null
oq "UPDATE karidns_auth.credentials SET oidc_issuer = NULL, oidc_subject = NULL WHERE principal_id = $DM" > /dev/null
a_err "the signer role has no EXECUTE on the functions of the sign-in" "permission denied" $SIG NONE "SELECT karidns_auth.oidc_state_take($H32)"
a_err "...nor has PUBLIC (the functions are not for anybody to call)" "permission denied" $SIG NONE "SELECT karidns_auth.oidc_lookup('https://idp.example', 'x')"
a_eq "principal_closure is readable" t $API NONE "SELECT count(*) > 0 FROM karidns_auth.principal_closure"
a_err "...but not writable" "permission denied" $API $GM "DELETE FROM karidns_auth.principal_closure"
a_err "the schema_version row cannot be changed" "permission denied" $API $GM "UPDATE karidns_auth.schema_version SET version = 4"
a_err "karidns_auth.audit_restricted_roles is not readable" "permission denied" $API $GM "SELECT * FROM karidns_auth.audit_restricted_roles"
a_err "karidns_auth.api_roles is not readable" "permission denied" $API $GM "SELECT * FROM karidns_auth.api_roles"
GRC_DM=$(pq "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'example.com'")
a_eq "grants: a domain master sees the grants on its zone (every holder's)" "$GRC_DM" $API $DM "SELECT count(*) FROM karidns_auth.grants"
a_eq "grants: a subdomain master sees its own grant only" 1 $API $SM "SELECT count(*) FROM karidns_auth.grants"
a_eq "grants: a user sees the grants of its groups (gina: org's grant on third.test)" 1 $API $GINA "SELECT count(*) FROM karidns_auth.grants"
a_eq "grants: a global master sees all" "$(pq "SELECT count(*) FROM karidns_auth.grants")" $API $GM "SELECT count(*) FROM karidns_auth.grants"
a_eq "grants: no principal, no grants" 0 $API NONE "SELECT count(*) FROM karidns_auth.grants"
a_eq "grants: a domain master does not see the global master's grant" 0 $API $DM "SELECT count(*) FROM karidns_auth.grants WHERE role = 'global_master'"

echo "-- the audit log"
a_err "audit_log: the API role cannot INSERT" "permission denied" $API $GM "INSERT INTO karidns_auth.audit_log (data_schema, table_name, op) VALUES ('public', 'records', 'I')"
a_err "...UPDATE" "permission denied" $API $GM "UPDATE karidns_auth.audit_log SET zone_name = NULL"
a_err "...DELETE" "permission denied" $API $GM "DELETE FROM karidns_auth.audit_log"
a_err "...TRUNCATE" "permission denied" $API $GM "TRUNCATE karidns_auth.audit_log"
a_err "the signer cannot read it" "permission denied" $SIG NONE "SELECT count(*) FROM karidns_auth.audit_log"
oq "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) SELECT $TGT, 'domain_master', 'ord1', 'example.com', id FROM karidns_auth.rr_policies WHERE name = 'std'" > /dev/null
oq "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) SELECT $TGT, 'domain_master', 'public', 'other.test', id FROM karidns_auth.rr_policies WHERE name = 'std'" > /dev/null
oq "UPDATE records SET ttl = ttl WHERE name = 'www.other.test'; UPDATE records SET ttl = ttl WHERE name = 'www.example.com'" > /dev/null
ALLA=$(pq "SELECT count(*) FROM karidns_auth.audit_log")
EXA=$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE zone_name = 'example.com' AND NOT (table_name = 'grants' AND coalesce(after, before) ->> 'data_schema' <> 'public')")
a_eq "a domain master of example.com in another data schema (ord1) reads only its own rows, not the public ones" 1 $API $TGT "SELECT count(DISTINCT zone_name) FROM karidns_auth.audit_log WHERE zone_name = 'example.com'"
a_eq "a global master reads the whole log" "$ALLA" $API $GM "SELECT count(*) FROM karidns_auth.audit_log"
a_eq "a domain master reads the rows of its zone (the grants rows of another data schema's example.com are not its)" "$EXA" $API $DM "SELECT count(*) FROM karidns_auth.audit_log"
a_eq "...all of them name its zone" "example.com" $API $DM "SELECT DISTINCT zone_name FROM karidns_auth.audit_log"
a_eq "a subdomain master reads none" 0 $API $SM "SELECT count(*) FROM karidns_auth.audit_log"
a_eq "a user without a grant reads none" 0 $API $NOG "SELECT count(*) FROM karidns_auth.audit_log WHERE zone_name = 'example.com'"
a_eq "...a domain master of another zone (g_ops: other.test) reads that zone's rows" "other.test" $API $EVE "SELECT DISTINCT zone_name FROM karidns_auth.audit_log"
a_eq "no principal, no audit rows" 0 $API NONE "SELECT count(*) FROM karidns_auth.audit_log"
oq "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT" > /dev/null
a_eq "credentials secrets are redacted in the log the API reads" "<redacted>" $API $GM "SELECT DISTINCT after ->> 'password_hash' FROM karidns_auth.audit_log WHERE table_name = 'credentials' AND op = 'I' AND after ->> 'password_hash' IS NOT NULL"
a_eq "cryptokeys.content is redacted too (and the rows of the keys are there)" "<redacted> 2" $API $GM "SELECT DISTINCT after ->> 'content' FROM karidns_auth.audit_log WHERE table_name = 'cryptokeys'; SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'cryptokeys'"
oeq "no audit row holds the key material or a hash" "0" "SELECT count(*) FROM karidns_auth.audit_log WHERE coalesce(before::text, '') || coalesce(after::text, '') LIKE '%SECRET-KEY%' OR coalesce(before::text, '') || coalesce(after::text, '') LIKE '%argon2id%'"
a_eq "the changes of the API role are in the log under the principal's name and the database role" "dm|$API" $API $GM "SELECT DISTINCT principal_name || '|' || db_role FROM karidns_auth.audit_log WHERE principal_id = $DM AND table_name = 'records' AND op = 'I' LIMIT 1"

echo "-- escalation: the trigger on grants (dme: domain master of example.com, policy esc: A AAAA TXT MX, TTL 60..86400, max_rr 100, no flags)"
GI="INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id) SELECT $TGT"
pol() { echo "(SELECT id FROM karidns_auth.rr_policies WHERE name = '$1')"; }
a_ok "a domain master grants domain_master on its zone with a narrower policy" $API $DME "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
oeq "...granted_by is the domain master" "$DME" "SELECT granted_by FROM karidns_auth.grants WHERE principal_id = $TGT AND rr_policy_id = $(pol esc_ok)"
a_ok "...with the same policy" $API $DME "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_eq'"
a_ok "...a subdomain_master grant under the zone" $API $DME "$GI, 'subdomain_master', 'public', 'example.com', 'x.example.com', id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_ok "...with a policy that sets the same flags (none) and max_rr 100" $API $DME "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc'"
for p in esc_type esc_wc esc_del esc_dn esc_apex esc_ttlmin esc_ttlmax esc_maxrr esc_maxnul wide all; do
    a_err "a policy that is wider than the granter's: $p" "may not make this grant" $API $DME "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = '$p'"
done
a_err "a global_master grant" "may not make this grant" $API $DME "$GI, 'global_master', NULL, NULL, NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_err "a grant on another zone of the same schema" "may not make this grant" $API $DME "$GI, 'domain_master', 'public', 'other.test', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_err "a grant on the same zone name of another data schema" "may not make this grant" $API $DME "$GI, 'domain_master', 'ord1', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_err "a subdomain master grant on another zone" "may not make this grant" $API $DME "$GI, 'subdomain_master', 'public', 'other.test', 'a.other.test', id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_err "a subdomain master cannot grant (sm)" "may not make this grant" $API $SM "$GI, 'subdomain_master', 'public', 'example.com', 'sub.example.com', id FROM karidns_auth.rr_policies WHERE name = 'only_a'"
a_err "no principal, no grant" "no valid karidns.principal" $API NONE "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_err "a disabled principal cannot grant" "no valid karidns.principal" $API $DIS "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
a_ok "a global master grants anything (a global grant with the widest policy)" $API $GM "$GI, 'global_master', NULL, NULL, NULL, id FROM karidns_auth.rr_policies WHERE name = 'all'"
oeq "...granted_by is the global master (the trigger overrides a value the caller sent)" "$GM" "SELECT granted_by FROM karidns_auth.grants WHERE principal_id = $TGT AND role = 'global_master'"
a_ok "...also a value the caller sent is replaced" $API $DME "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id, granted_by) SELECT $TGT, 'domain_master', 'public', 'example.com', id, $GM FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
oeq "...(the domain master's id)" "$DME" "SELECT granted_by FROM karidns_auth.grants WHERE id = (SELECT max(id) FROM karidns_auth.grants WHERE principal_id = $TGT)"
a_n "UPDATE: a domain master narrows a grant it made" 1 $API $DME "UPDATE karidns_auth.grants SET rr_policy_id = $(pol esc_ok) WHERE principal_id = $TGT AND role = 'subdomain_master'"
oq "UPDATE karidns_auth.grants SET granted_by = NULL, granted_at = '2001-01-01 00:00:00+00' WHERE principal_id = $TGT AND role = 'subdomain_master'" > /dev/null
a_ok "UPDATE: a statement that sends granted_by and granted_at but changes nothing material" $API $DME "UPDATE karidns_auth.grants SET granted_by = $GM, granted_at = '2020-02-02 00:00:00+00' WHERE principal_id = $TGT AND role = 'subdomain_master'"
oeq "...keeps the old values (the forged ones are dropped)" "|2001-01-01" "SELECT coalesce(granted_by::text, '') || '|' || to_char(granted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') FROM karidns_auth.grants WHERE principal_id = $TGT AND role = 'subdomain_master'"
a_ok "UPDATE: a material change (the policy) sets granted_by to the principal and granted_at to now, whatever was sent" $API $DME "UPDATE karidns_auth.grants SET rr_policy_id = $(pol esc_eq), granted_by = $GM, granted_at = '2020-02-02 00:00:00+00' WHERE principal_id = $TGT AND role = 'subdomain_master'"
oeq "...granted_by is the principal, granted_at is now" "$DME|true" "SELECT granted_by || '|' || (granted_at > now() - interval '1 hour') FROM karidns_auth.grants WHERE principal_id = $TGT AND role = 'subdomain_master'"
a_ok "INSERT: granted_at is the trigger's too" $API $DME "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id, granted_at) SELECT $TGT, 'domain_master', 'public', 'example.com', id, '2001-01-01 00:00:00+00' FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
oeq "...granted_at is now" "t" "SELECT granted_at > now() - interval '1 hour' FROM karidns_auth.grants WHERE id = (SELECT max(id) FROM karidns_auth.grants WHERE principal_id = $TGT)"
a_err "UPDATE: ...but cannot widen it" "may not make this grant" $API $DME "UPDATE karidns_auth.grants SET rr_policy_id = $(pol esc_type) WHERE principal_id = $TGT AND role = 'subdomain_master'"
a_err "UPDATE: ...nor turn it into a global grant" "may not make this grant" $API $DME "UPDATE karidns_auth.grants SET role = 'global_master', data_schema = NULL, zone_name = NULL, name_suffix = NULL WHERE principal_id = $TGT AND role = 'subdomain_master'"
a_err "UPDATE: ...nor move it to another zone" "may not make this grant" $API $DME "UPDATE karidns_auth.grants SET zone_name = 'other.test', name_suffix = 'x.other.test' WHERE principal_id = $TGT AND role = 'subdomain_master'"
a_err "UPDATE: a domain master cannot touch a grant of its zone that is wider (dmw: wide)" "may change or remove" $API $DME "UPDATE karidns_auth.grants SET principal_id = $TGT WHERE principal_id = $DMW"
a_n "DELETE: a global grant is not even visible to a domain master: no row" 0 $API $DME "DELETE FROM karidns_auth.grants WHERE role = 'global_master'"
a_err "DELETE: a grant wider than the granter's (dmw: wide) is refused" "may change or remove" $API $DME "DELETE FROM karidns_auth.grants WHERE principal_id = $DMW"
a_n "DELETE: a grant it could make (the subdomain grant)" 1 $API $DME "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT AND role = 'subdomain_master'"
a_n "DELETE: a grant of another zone is not visible: no row" 0 $API $DME "DELETE FROM karidns_auth.grants WHERE zone_name = 'other.test'"
a_n "DELETE: a subdomain master cannot delete even its own grant: no row" 0 $API $SM "DELETE FROM karidns_auth.grants WHERE principal_id = $SM"
a_n "DELETE: a global master deletes any" 1 $API $GM "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT AND role = 'global_master'"
oq "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT" > /dev/null
# the operator and the roles that are members of the API role
oq "$GI, 'global_master', NULL, NULL, NULL, id FROM karidns_auth.rr_policies WHERE name = 'all'" > /dev/null && pass "the operator (the owner, not an API role) can insert anything" || fail "the operator's insert"
oeq "...and granted_by stays NULL" "" "SELECT granted_by FROM karidns_auth.grants WHERE principal_id = $TGT AND role = 'global_master'"
oq "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT" > /dev/null
oq "CREATE ROLE $APIM NOLOGIN; GRANT $API TO $APIM" > /dev/null 2>&1
a_err "a role that is a member of the API role is bound too (SET ROLE)" "may not make this grant" "$APIM" $DME "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'wide'"
a_ok "...and may do what the API role may" "$APIM" $DME "$GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'esc_ok'"
oq "CREATE ROLE $LGN LOGIN; CREATE ROLE $OTH NOLOGIN; GRANT $API TO $LGN; GRANT $OTH TO $LGN; GRANT USAGE ON SCHEMA karidns_auth TO $OTH; GRANT SELECT ON karidns_auth.rr_policies TO $OTH; GRANT EXECUTE ON FUNCTION karidns_auth.is_global(), karidns_auth.zone_grant(text, text), karidns_auth.current_principal(), karidns_auth.my_groups() TO $OTH; GRANT SELECT, INSERT ON karidns_auth.grants TO $OTH; GRANT USAGE ON SEQUENCE karidns_auth.grants_id_seq TO $OTH" > /dev/null 2>&1
if psql -X -q -At "$PGC" -c "SET SESSION AUTHORIZATION $LGN; SELECT 1" > /dev/null 2>&1; then
    psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "SET SESSION AUTHORIZATION $LGN; SET ROLE $OTH; SET LOCAL karidns.principal = '$DME'; $GI, 'domain_master', 'public', 'example.com', NULL, id FROM karidns_auth.rr_policies WHERE name = 'wide'" > "$O" 2> "$E"; rc=$?
    if [ $rc -ne 0 ] && grep -qi "may not make this grant" "$E"; then pass "the login role counts too: a member of the API role that SET ROLEs to another role is bound (session_user)"; else fail "session_user closure: status $rc: $(head -c 200 "$E")"; fi
else
    skip "SET SESSION AUTHORIZATION is not allowed: the login role case of the escalation trigger is not tested"
fi
oq "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT" > /dev/null

echo "-- INSERT ... ON CONFLICT, disabled groups, case and trailing dots, moving a name out of a suffix"
WWW=$(pq "SELECT id FROM records WHERE name = 'www.example.com' AND type = 'A'"); APEXA=$(pq "SELECT id FROM records WHERE name = 'example.com' AND type = 'A'")
UPS="INSERT INTO records (id, domain_id, name, type, content, ttl)"
a_ok "ON CONFLICT DO UPDATE on a record the grant covers (insert and update both pass)" $API $DM "$UPS VALUES ($WWW, $EX, 'www.example.com', 'A', '192.0.2.2', 300) ON CONFLICT (id) DO UPDATE SET ttl = 999"
oeq "...the row was updated" "999" "SELECT ttl FROM records WHERE id = $WWW"
oq "UPDATE records SET ttl = 300 WHERE id = $WWW" > /dev/null
a_err "ON CONFLICT DO UPDATE whose proposed row is not covered (the apex name): the INSERT check refuses" "$RLSERR" $API $DM "$UPS VALUES ($WWW, $EX, 'example.com', 'A', '192.0.2.2', 300) ON CONFLICT (id) DO UPDATE SET ttl = 1"
a_err "ON CONFLICT DO UPDATE of a row the principal can see but not write (the apex A): the UPDATE policy refuses" "$RLSERR" $API $DM "$UPS VALUES ($APEXA, $EX, 'upsert.example.com', 'A', '192.0.2.2', 300) ON CONFLICT (id) DO UPDATE SET ttl = 1"
oeq "...and the apex A is as it was" "300" "SELECT ttl FROM records WHERE id = $APEXA"
a_ok "ON CONFLICT DO NOTHING on a row it may not write does nothing and fails nothing" $API $DM "$UPS VALUES ($APEXA, $EX, 'upsert.example.com', 'A', '192.0.2.2', 300) ON CONFLICT (id) DO NOTHING"
oq "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id, granted_by) SELECT $TGT, 'domain_master', 'public', 'example.com', id, NULL FROM karidns_auth.rr_policies WHERE name = 'esc_ok'" > /dev/null
G1=$(pq "SELECT max(id) FROM karidns_auth.grants WHERE principal_id = $TGT")
oq "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id, granted_by) SELECT $TGT, 'domain_master', 'public', 'example.com', id, NULL FROM karidns_auth.rr_policies WHERE name = 'wide'" > /dev/null
G2=$(pq "SELECT max(id) FROM karidns_auth.grants WHERE principal_id = $TGT")
GUP="INSERT INTO karidns_auth.grants (id, principal_id, role, data_schema, zone_name, rr_policy_id)"
a_ok "ON CONFLICT DO UPDATE on grants: a domain master narrows... (the same size) a grant it may change" $API $DME "$GUP SELECT $G1, $TGT, 'domain_master', 'public', 'example.com', id FROM karidns_auth.rr_policies WHERE name = 'esc_eq' ON CONFLICT (id) DO UPDATE SET rr_policy_id = EXCLUDED.rr_policy_id"
oeq "...the policy changed and granted_by is the domain master" "esc_eq|$DME" "SELECT p.name || '|' || g.granted_by FROM karidns_auth.grants g JOIN karidns_auth.rr_policies p ON p.id = g.rr_policy_id WHERE g.id = $G1"
a_err "ON CONFLICT DO UPDATE on a grant wider than the granter's: the UPDATE path is refused" "may change or remove" $API $DME "$GUP SELECT $G2, $TGT, 'domain_master', 'public', 'example.com', id FROM karidns_auth.rr_policies WHERE name = 'esc_ok' ON CONFLICT (id) DO UPDATE SET rr_policy_id = EXCLUDED.rr_policy_id"
a_err "ON CONFLICT DO UPDATE whose proposed grant is wider than the granter's: the INSERT path is refused" "may not make this grant" $API $DME "$GUP SELECT $G1, $TGT, 'domain_master', 'public', 'example.com', id FROM karidns_auth.rr_policies WHERE name = 'wide' ON CONFLICT (id) DO UPDATE SET rr_policy_id = EXCLUDED.rr_policy_id"
oq "DELETE FROM karidns_auth.grants WHERE principal_id = $TGT" > /dev/null
# writes by a member of a disabled group (gina: team in org; org holds the domain_master grant on third.test)
a_ok "a user in team in org (gina) writes into third.test" $API $GINA "$(ri $THIRD dg1.third.test A 192.0.2.90 300)"
oq "UPDATE karidns_auth.principals SET disabled = true WHERE name = 'org'" > /dev/null
a_err "...INSERT is refused once the group that holds the grant is disabled" "$RLSERR" $API $GINA "$(ri $THIRD dg2.third.test A 192.0.2.90 300)"
a_n "...UPDATE changes nothing" 0 $API $GINA "UPDATE records SET ttl = 301 WHERE name = 'dg1.third.test'"
a_n "...DELETE changes nothing" 0 $API $GINA "DELETE FROM records WHERE name = 'dg1.third.test'"
a_err "...and a reload request is refused" "$RLSERR" $API $GINA "INSERT INTO karidns_reload_requests (zone) VALUES ('third.test')"
oq "UPDATE karidns_auth.principals SET disabled = false WHERE name = 'org'" > /dev/null
a_n "...the group enabled again, the DELETE works" 1 $API $GINA "DELETE FROM records WHERE name = 'dg1.third.test'"
# case and trailing dots
a_eq "rr_ok folds the case of the zone, the name and the type" t $API $DM "SELECT karidns_auth.rr_ok('public', 'EXAMPLE.com', 'WWW.Example.COM', 'a', 300)"
a_eq "rr_visible folds the case too" t $API $DM "SELECT karidns_auth.rr_visible('public', 'Example.COM', 'Www.EXAMPLE.com', 'A')"
a_eq "zone_grant folds the case of the zone" domain_master $API $DM "SELECT karidns_auth.zone_grant('public', 'Example.COM')"
a_eq "a zone argument with a trailing dot is no zone: rr_ok says no" f $API $DM "SELECT karidns_auth.rr_ok('public', 'example.com.', 'www.example.com', 'A', 300)"
a_eq "...and so does a name with a trailing dot" f $API $DM "SELECT karidns_auth.rr_ok('public', 'example.com', 'www.example.com.', 'A', 300)"
a_eq "...rr_visible too" f $API $DM "SELECT karidns_auth.rr_visible('public', 'example.com', 'www.example.com.', 'A')"
a_eq "the schema name is not folded: a grant on another data schema's zone is no grant" "" $API $DM "SELECT karidns_auth.zone_grant('PUBLIC', 'example.com')"
DOT=$(did 'dot.test.')
a_eq "a domain stored as 'dot.test.' (trailing dot) is the zone dot.test: the holder of that grant sees the domain" "dot.test." $API $(pid dotu) "SELECT name FROM domains"
a_eq "...and its records" 2 $API $(pid dotu) "SELECT count(*) FROM records"
a_ok "...writes into it" $API $(pid dotu) "$(ri $DOT b.dot.test A 192.0.2.91 300)"
a_ok "...asks for a reload with the name with or without the dot" $API $(pid dotu) "INSERT INTO karidns_reload_requests (zone) VALUES ('dot.test.'), ('dot.test')"
a_eq "...and bumps its serial" 2 $API $(pid dotu) "SELECT karidns_auth.bump_serial('public', $DOT)"
a_eq "...a domain master of example.com sees none of it" 0 $API $DM "SELECT count(*) FROM records WHERE domain_id = $DOT"
# a subdomain master moves a name out of its suffix (USING and WITH CHECK each alone)
a_ok "sm: a record under its suffix" $API $SM "$(ri $EX mv.sub.example.com A 192.0.2.92 300)"
a_err "WITH CHECK alone: the old row is sm's, the new name is outside the suffix" "violates row-level security policy for table" $API $SM "UPDATE records SET name = 'mv.example.com' WHERE name = 'mv.sub.example.com'"
a_n "USING alone: the old row (the apex NS) is visible but not sm's to write; the new row would be fine (an A under the suffix): no row changes" 0 $API $SM "UPDATE records SET name = 'mv2.sub.example.com', type = 'A', content = '192.0.2.93', ttl = 300 WHERE name = 'example.com' AND type = 'NS'"
oeq "...the apex NS is where it was, nothing was added" "1|0" "SELECT (SELECT count(*) FROM records WHERE name = 'example.com' AND type = 'NS') || '|' || (SELECT count(*) FROM records WHERE name = 'mv2.sub.example.com')"
a_n "sm: moving within the suffix works" 1 $API $SM "UPDATE records SET name = 'mv3.sub.example.com' WHERE name = 'mv.sub.example.com'"
a_n "cleanup" 1 $API $SM "DELETE FROM records WHERE name = 'mv3.sub.example.com'"
oq "DELETE FROM records WHERE name = 'b.dot.test'" > /dev/null

echo "-- the signer role (reads everything, writes DNSSEC records, SOA updates and its three metadata kinds)"
oq "$(ri $EX sigins.example.com A 192.0.2.60 300)" > /dev/null
sg_cnt() { pq "SELECT count(*) FROM $1"; }
a_eq "the signer reads every record" "$(sg_cnt records)" $SIG NONE "SELECT count(*) FROM records"
a_eq "...every zone" "$(sg_cnt domains)" $SIG NONE "SELECT count(*) FROM domains"
a_eq "...every metadata row" "$(sg_cnt domainmetadata)" $SIG NONE "SELECT count(*) FROM domainmetadata"
a_eq "...the private keys (cryptokeys.content)" "SECRET-KEY-example.com SECRET-KEY-other.test" $SIG NONE "SELECT content FROM cryptokeys ORDER BY content"
a_eq "...the tag tables" "$(sg_cnt karidns_record_tags)" $SIG NONE "SELECT count(*) FROM karidns_record_tags"
for ty in RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY TYPE46; do
    a_ok "the signer inserts $ty" $SIG NONE "$(ri $EX "s-$(echo $ty | tr A-Z a-z).example.com" $ty x 300)"
done
a_err "...but not an A record" "$RLSERR" $SIG NONE "$(ri $EX sx.example.com A 192.0.2.61 300)"
a_err "...nor an NS record" "$RLSERR" $SIG NONE "$(ri $EX sx.example.com NS ns.x.test 300)"
a_err "...nor an SOA record (the trigger on SOA rows says no before the policy does)" "cannot insert an SOA" $SIG NONE "$(ri $EX example.com SOA 'ns1.example.com hm.example.com 1 2 3 4 5' 300)"
a_n "the signer updates a DNSSEC record" 1 $SIG NONE "UPDATE records SET ttl = 301 WHERE name = 's-rrsig.example.com'"
a_n "...and the SOA (the serial)" 1 $SIG NONE "UPDATE records SET content = 'ns1.example.com hostmaster.example.com 200 7200 3600 1209600 300' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...but not another column of an A record (the trigger: only ordername and auth)" "ordername and auth" $SIG NONE "UPDATE records SET ttl = 301 WHERE name = 'www.example.com' AND type = 'A'"
a_err "...nor of the NS record" "ordername and auth" $SIG NONE "UPDATE records SET ttl = 301 WHERE type = 'NS'"
a_n "the signer deletes a DNSSEC record" 1 $SIG NONE "DELETE FROM records WHERE name = 's-nsec.example.com'"
a_n "...not an A record: no row" 0 $SIG NONE "DELETE FROM records WHERE name = 'www.example.com' AND type = 'A'"
a_n "...not the SOA: no row" 0 $SIG NONE "DELETE FROM records WHERE type = 'SOA'"
for k in PRESIGNED NSEC3PARAM X-KARIDNS-SIGNER presigned; do
    a_ok "the signer writes the metadata kind $k" $SIG NONE "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($OTHER, '$k', '1')"
done
a_err "...but not ALLOW-AXFR-FROM" "$RLSERR" $SIG NONE "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($OTHER, 'ALLOW-AXFR-FROM', '1')"
a_n "...and updates its own kinds" 4 $SIG NONE "UPDATE domainmetadata SET content = '2' WHERE domain_id = $OTHER AND upper(kind) IN ('PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER')"
a_n "...cannot delete another kind: no row" 0 $SIG NONE "DELETE FROM domainmetadata WHERE kind = 'ALLOW-AXFR-FROM'"
a_n "...deletes its own" 4 $SIG NONE "DELETE FROM domainmetadata WHERE domain_id = $OTHER AND upper(kind) IN ('PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER')"
a_ok "the signer asks for a reload" $SIG NONE "INSERT INTO karidns_reload_requests (zone) VALUES ('example.com')"
a_err "...cannot write a zone" "permission denied" $SIG NONE "INSERT INTO domains (name, type) VALUES ('sig.test', 'NATIVE')"
a_err "...cannot write a tag table" "permission denied" $SIG NONE "DELETE FROM karidns_record_tags"
a_err "...cannot change a key (it only adds new ones)" "permission denied" $SIG NONE "UPDATE cryptokeys SET active = false"
a_err "...has nothing on grants" "permission denied" $SIG NONE "SELECT count(*) FROM karidns_auth.grants"
a_err "...nothing on credentials" "permission denied" $SIG NONE "SELECT count(*) FROM karidns_auth.credentials"
a_err "...nothing on principals" "permission denied" $SIG NONE "SELECT count(*) FROM karidns_auth.principals"
a_err "...cannot call the RLS functions' bump_serial" "permission denied" $SIG NONE "SELECT karidns_auth.bump_serial('public', $EX)"
a_ok "the signer, with a principal set, is still the signer (the API policies say no, its own say yes)" $SIG $GM "UPDATE records SET ttl = 302 WHERE name = 's-rrsig.example.com'"
a_n "...and sees all rows" 1 $SIG $NOG "UPDATE records SET ttl = 303 WHERE name = 's-rrsig.example.com'"
# the permissive policies of the API must not widen the signer: karidns.principal changes nothing (RESTRICTIVE policies)
a_err "the signer with karidns.principal = a global master still cannot INSERT an A record" "$RLSERR" $SIG $GM "$(ri $EX sx2.example.com A 192.0.2.62 300)"
a_err "...nor UPDATE one (the trigger)" "ordername and auth" $SIG $GM "UPDATE records SET ttl = 302 WHERE name = 'www.example.com' AND type = 'A'"
a_n "...nor DELETE one" 0 $SIG $GM "DELETE FROM records WHERE name = 'www.example.com' AND type = 'A'"
a_err "...nor INSERT an NS record" "$RLSERR" $SIG $GM "$(ri $EX del9.example.com NS ns.x.test 300)"
a_err "...nor write ALLOW-AXFR-FROM" "$RLSERR" $SIG $GM "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($OTHER, 'ALLOW-AXFR-FROM', '1')"
a_n "...nor UPDATE it" 0 $SIG $GM "UPDATE domainmetadata SET content = '2' WHERE kind = 'ALLOW-AXFR-FROM'"
a_n "...nor DELETE it" 0 $SIG $GM "DELETE FROM domainmetadata WHERE kind = 'ALLOW-AXFR-FROM'"
a_err "...a domain master's principal does not help either" "$RLSERR" $SIG $DM "$(ri $EX sx3.example.com TXT x 300)"
a_ok "...it still writes what it owns with such a principal set" $SIG $GM "$(ri $EX s-set.example.com RRSIG x 300); UPDATE records SET ttl = 303 WHERE name = 's-set.example.com'; DELETE FROM records WHERE name = 's-set.example.com'"
oeq "the signer's role is in karidns_auth.signer_roles (the API's is not)" "true|false" "SELECT (SELECT count(*) = 1 FROM karidns_auth.signer_roles WHERE role_name = '$SIG') || '|' || (SELECT count(*) = 1 FROM karidns_auth.signer_roles WHERE role_name = '$API')"
# the signer changes an SOA in its serial only (trigger karidns_signer_soa_*)
SOAC="ns1.example.com hostmaster.example.com"
a_ok "the signer changes the serial of the SOA" $SIG NONE "UPDATE records SET content = '$SOAC 201 7200 3600 1209600 300' WHERE domain_id = $EX AND type = 'SOA'"
a_ok "...and may leave it as it is" $SIG NONE "UPDATE records SET content = content WHERE domain_id = $EX AND type = 'SOA'"
a_err "...but not the refresh time" "may change only the serial" $SIG NONE "UPDATE records SET content = '$SOAC 201 7201 3600 1209600 300' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor the minimum" "may change only the serial" $SIG NONE "UPDATE records SET content = '$SOAC 202 7200 3600 1209600 301' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor the primary name server" "may change only the serial" $SIG NONE "UPDATE records SET content = 'ns9.example.com hostmaster.example.com 202 7200 3600 1209600 300' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor the responsible mailbox" "may change only the serial" $SIG NONE "UPDATE records SET content = 'ns1.example.com other.example.com 202 7200 3600 1209600 300' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor make the content something else" "may change only the serial" $SIG NONE "UPDATE records SET content = 'broken' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor rename the SOA" "keeps its type, name and domain_id" $SIG NONE "UPDATE records SET name = 'www.example.com' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor move it to another zone" "keeps its type, name and domain_id" $SIG NONE "UPDATE records SET domain_id = $OTHER WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor write its type in another form (TYPE6)" "keeps its type, name and domain_id" $SIG NONE "UPDATE records SET type = 'TYPE6' WHERE domain_id = $EX AND type = 'SOA'"
a_err "...nor turn it into a DNSSEC record (the policy allows the new row)" "cannot become another type" $SIG NONE "UPDATE records SET type = 'RRSIG' WHERE domain_id = $EX AND type = 'SOA'"
oq "$(ri $EX s-conv.example.com RRSIG x 300); $(ri $EX s-conv.example.com RRSIG y 300)" > /dev/null
a_err "...nor turn a DNSSEC record into an SOA" "cannot become an SOA" $SIG NONE "UPDATE records SET type = 'SOA', content = '$SOAC 1 2 3 4 5' WHERE name = 's-conv.example.com' AND content = 'x'"
a_err "...also as TYPE6" "cannot become an SOA" $SIG NONE "UPDATE records SET type = 'TYPE6', content = '$SOAC 1 2 3 4 5' WHERE name = 's-conv.example.com' AND content = 'y'"
oq "DELETE FROM records WHERE name = 's-conv.example.com'" > /dev/null
oeq "...the SOA is as the signer left it" "$SOAC 201 7200 3600 1209600 300" "SELECT content FROM records WHERE domain_id = $EX AND type = 'SOA'"
# insert and delete of an SOA reach the trigger only when the policies do not stop them first: switch RLS off for these two cases
oq "SELECT karidns_auth.disable_rls('public')" > /dev/null
a_err "without RLS the trigger alone still stops the signer inserting an SOA" "cannot insert an SOA" $SIG NONE "$(ri $OTHER o2.other.test SOA 'ns1.other.test hm.other.test 1 2 3 4 5' 300)"
a_err "...and deleting one" "cannot delete an SOA" $SIG NONE "DELETE FROM records WHERE domain_id = $OTHER AND type = 'SOA'"
a_err "...also an SOA written TYPE6" "cannot insert an SOA" $SIG NONE "$(ri $OTHER o3.other.test TYPE6 'ns1.other.test hm.other.test 1 2 3 4 5' 300)"
a_ok "...the trigger does not touch the signer's other writes" $SIG NONE "$(ri $OTHER o4.other.test RRSIG x 300); DELETE FROM records WHERE name = 'o4.other.test'"
a_ok "...nor anyone else's: the API's bump_serial updates an SOA" $API $GM "SELECT karidns_auth.bump_serial('public', $OTHER)"
oq "SELECT karidns_auth.enable_rls('public')" > /dev/null
# the change log fills when the signer writes
CL1=$(pq "SELECT coalesce(max(seq), 0) FROM karidns_changes")
a_ok "the signer writes an RRSIG" $SIG NONE "$(ri $EX s-log.example.com RRSIG x 300)"
oeq "...the change log got a row (the trigger runs as the owner, the signer has no right on the log)" "t" "SELECT count(*) >= 1 FROM karidns_changes WHERE seq > $CL1 AND domain_id = $EX"
oq "DELETE FROM records WHERE name = 's-log.example.com'" > /dev/null
a_eq "the signer reads the change log (it follows it to see which zones changed)" "$(sg_cnt karidns_changes)" $SIG NONE "SELECT count(*) FROM karidns_changes"
a_eq "...with the xid of each row" "t" $SIG NONE "SELECT bool_and(xid IS NOT NULL) FROM karidns_changes"
a_err "...but cannot write it" "permission denied" $SIG NONE "INSERT INTO karidns_changes (domain_id, changed_at) VALUES ($EX, 0)"
a_err "...nor delete from it" "permission denied" $SIG NONE "DELETE FROM karidns_changes"
a_err "...nor delete reload requests" "permission denied" $SIG NONE "DELETE FROM karidns_reload_requests"
oeq "the audit rows of the signer name its database role" "$SIG" "SELECT DISTINCT db_role FROM karidns_auth.audit_log WHERE table_name = 'records' AND db_role = '$SIG'"
a_ok "the signer may turn the audit detail off (it is not a restricted role: karidns-zone import --signer asks for summary mode)" $SIG NONE "SET LOCAL karidns.audit = 'summary'; $(ri $EX sum1.example.com RRSIG x 300); $(ri $EX sum2.example.com RRSIG x 300)"
oeq "...one summary row for the two inserts (2 statements, 2 rows), no row records of them" "1|2|2|0" "SELECT count(*) || '|' || max((after ->> 'statements')::int) || '|' || max((after ->> 'rows')::int) || '|' || (SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'I' AND db_role = '$SIG' AND (after ->> 'summary') IS NULL AND after ->> 'name' IN ('sum1.example.com', 'sum2.example.com')) FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'I' AND db_role = '$SIG' AND (after ->> 'summary') IS NOT NULL"
oq "DELETE FROM records WHERE name LIKE 's-%.example.com' OR name IN ('sum1.example.com', 'sum2.example.com', 'sigins.example.com')" > /dev/null

echo "-- key requests, the signer's state, new keys and the columns of a record (item C)"
oq "TRUNCATE karidns_auth.audit_log; INSERT INTO karidns_key_requests (domain_id, requested_by, state, done_at) VALUES ($EX, $GM, 'done', now());
    INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($OTHER, $GM);
    INSERT INTO karidns_signer_state (domain_id, signed_serial) VALUES ($EX, 100), ($OTHER, 200), ($THIRD, 300)" > /dev/null
a_eq "the API: a global master sees every request" "2" $API $GM "SELECT count(*) FROM karidns_key_requests"
a_eq "...the domain master of example.com sees one request" "1" $API $DM "SELECT count(*) FROM karidns_key_requests"
a_eq "...a domain master through a group (eve in g_ops: other.test) sees that zone's request" "$OTHER" $API $EVE "SELECT domain_id FROM karidns_key_requests"
a_eq "...a subdomain master sees none" "0" $API $SM "SELECT count(*) FROM karidns_key_requests"
a_eq "...a principal without grants sees none" "0" $API $NOG "SELECT count(*) FROM karidns_key_requests"
a_eq "...no principal sees none" "0" $API NONE "SELECT count(*) FROM karidns_key_requests"
a_eq "...a disabled principal sees none" "0" $API $DIS "SELECT count(*) FROM karidns_key_requests"
a_ok "a global master files a request for any zone" $API $GM "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($THIRD, $GM)"
a_ok "a domain master files one for its zone (KSK, ECDSA P-384, NSEC3)" $API $DM "INSERT INTO karidns_key_requests (domain_id, algorithm, key_type, nsec, requested_by) VALUES ($EX, 14, 'ksk', 'nsec3', $DM)"
a_err "...not for another zone" "$RLSERR" $API $DM "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($OTHER, $DM)"
a_err "a second pending request for a zone is refused (one open request per zone)" "duplicate key|unique" $API $DM "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($EX, $DM)"
a_err "a subdomain master cannot file one" "$RLSERR" $API $SM "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($EX, $SM)"
a_err "a principal without grants cannot" "$RLSERR" $API $NOG "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($EX, $NOG)"
a_err "no principal cannot" "$RLSERR" $API NONE "INSERT INTO karidns_key_requests (domain_id) VALUES ($EX)"
a_err "a disabled principal cannot" "$RLSERR" $API $DIS "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($EX, $DIS)"
a_err "a request in the name of another principal is refused" "$RLSERR" $API $DM "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($EX, $GM)"
a_err "...also without a requester" "$RLSERR" $API $DM "INSERT INTO karidns_key_requests (domain_id) VALUES ($EX)"
a_err "a request that is already answered is refused (the state and done_at are not columns the API may write)" "permission denied" $API $DM "INSERT INTO karidns_key_requests (domain_id, state, done_at, requested_by) VALUES ($EX, 'done', now(), $DM)"
a_err "...also one with a message" "permission denied" $API $DM "INSERT INTO karidns_key_requests (domain_id, message, requested_by) VALUES ($EX, 'x', $DM)"
a_err "...nor one that sets the id" "permission denied" $API $DM "INSERT INTO karidns_key_requests (id, domain_id, requested_by) VALUES (99999, $EX, $DM)"
a_err "the CHECKs of the table still apply (algorithm 5)" "check constraint" $API $GM "INSERT INTO karidns_key_requests (domain_id, algorithm, requested_by) VALUES ($EX, 5, $GM)"
a_err "the API cannot change a request" "permission denied" $API $GM "UPDATE karidns_key_requests SET state = 'done', done_at = now()"
a_err "...nor delete one" "permission denied" $API $GM "DELETE FROM karidns_key_requests"
a_eq "the API: the state of a zone is read by the principals that have a grant on it (dm: example.com only)" "$EX" $API $DM "SELECT domain_id FROM karidns_signer_state"
a_eq "...a global master sees all three" "3" $API $GM "SELECT count(*) FROM karidns_signer_state"
a_eq "...a subdomain master the state of its zone" "100" $API $SM "SELECT signed_serial FROM karidns_signer_state"
a_eq "...eve the state of other.test" "200" $API $EVE "SELECT signed_serial FROM karidns_signer_state"
a_eq "...a principal without grants none" "0" $API $NOG "SELECT count(*) FROM karidns_signer_state"
a_err "...the API cannot write the state: INSERT" "permission denied" $API $GM "INSERT INTO karidns_signer_state (domain_id) VALUES ($NOSOA)"
a_err "...UPDATE" "permission denied" $API $GM "UPDATE karidns_signer_state SET attempts = 5"
a_err "...DELETE" "permission denied" $API $GM "DELETE FROM karidns_signer_state"
a_err "the API cannot add a key" "permission denied" $API $GM "INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES ($EX, 257, true, true, 'API-KEY')"
# the signer
a_eq "the signer reads every request and every state row" "4|3" $SIG NONE "SELECT (SELECT count(*) FROM karidns_key_requests) || '|' || (SELECT count(*) FROM karidns_signer_state)"
a_n "the signer answers a request" 1 $SIG NONE "UPDATE karidns_key_requests SET state = 'done', done_at = now(), message = 'ok' WHERE domain_id = $OTHER"
a_n "...also with the principal of a global master set (the API's policies do not widen it, nor narrow it)" 1 $SIG $GM "UPDATE karidns_key_requests SET state = 'failed', done_at = now(), message = 'no' WHERE domain_id = $THIRD"
a_err "...the check of the table applies: done without done_at" "check constraint" $SIG NONE "UPDATE karidns_key_requests SET state = 'done', done_at = NULL WHERE domain_id = $EX AND algorithm = 13"
a_err "the signer changes only state, message and done_at: not the algorithm" "permission denied" $SIG NONE "UPDATE karidns_key_requests SET algorithm = 8 WHERE domain_id = $OTHER"
a_err "...not the zone" "permission denied" $SIG NONE "UPDATE karidns_key_requests SET domain_id = $THIRD WHERE domain_id = $OTHER"
a_err "...not the requester" "permission denied" $SIG NONE "UPDATE karidns_key_requests SET requested_by = NULL WHERE domain_id = $OTHER"
a_err "the signer cannot file a request" "permission denied" $SIG NONE "INSERT INTO karidns_key_requests (domain_id) VALUES ($EX)"
a_err "...nor with a principal set" "permission denied" $SIG $GM "INSERT INTO karidns_key_requests (domain_id, requested_by) VALUES ($EX, $GM)"
a_err "...nor delete one" "permission denied" $SIG NONE "DELETE FROM karidns_key_requests"
a_ok "the signer writes its state: INSERT" $SIG NONE "INSERT INTO karidns_signer_state (domain_id, signed_serial, next_due) VALUES ($NOSOA, 5, now())"
a_n "...UPDATE" 1 $SIG NONE "UPDATE karidns_signer_state SET attempts = 2, last_error = 'dnssec-signzone failed' WHERE domain_id = $NOSOA"
a_n "...also with a principal set" 1 $SIG $NOG "UPDATE karidns_signer_state SET attempts = 3 WHERE domain_id = $NOSOA"
a_n "...DELETE" 1 $SIG NONE "DELETE FROM karidns_signer_state WHERE domain_id = $NOSOA"
a_ok "the signer adds a key" $SIG NONE "INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES ($NOSOA, 257, true, true, 'NEWKEY')"
a_err "...but changes none" "permission denied" $SIG NONE "UPDATE cryptokeys SET active = false WHERE content = 'NEWKEY'"
a_err "...and deletes none" "permission denied" $SIG NONE "DELETE FROM cryptokeys WHERE content = 'NEWKEY'"
oeq "the key went into the change log (the trigger of cryptokeys runs as the owner)" "t" "SELECT count(*) >= 1 FROM karidns_changes WHERE seq > $CL1 AND domain_id = $NOSOA"
oeq "its state and the key are audited under the signer's role, the key without its content" "true|<redacted>" \
    "SELECT (SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE table_name = 'karidns_signer_state' AND db_role = '$SIG') || '|' || (SELECT after ->> 'content' FROM karidns_auth.audit_log WHERE table_name = 'cryptokeys' AND db_role = '$SIG' AND op = 'I' ORDER BY id DESC LIMIT 1)"
oeq "the answers to the requests are audited too" "t" "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE table_name = 'karidns_key_requests' AND op = 'U' AND db_role = '$SIG'"
# the columns of a record: ordername and auth of any record, a DNSSEC record as a whole, the SOA's serial
oq "$(ri $EX sigcol.example.com RRSIG x 300); INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($EX, 'ent.example.com', NULL, NULL, NULL)" > /dev/null
a_n "the signer sets the ordername and auth of an A record" 1 $SIG NONE "UPDATE records SET ordername = 'abc', auth = false WHERE name = 'www.example.com' AND type = 'A'"
a_n "...of the apex NS" 1 $SIG NONE "UPDATE records SET ordername = 'abc', auth = true WHERE type = 'NS' AND domain_id = $EX"
a_n "...of the SOA (its serial and content are unchanged)" 1 $SIG NONE "UPDATE records SET ordername = 'abc', auth = true WHERE type = 'SOA' AND domain_id = $EX"
a_n "...of an empty non-terminal (a row without type)" 1 $SIG NONE "UPDATE records SET ordername = 'ent', auth = true WHERE name = 'ent.example.com'"
a_n "...of an MX record, with a principal set" 1 $SIG $NOG "UPDATE records SET ordername = 'mail', auth = true WHERE name = 'mail.example.com'"
a_n "...of a whole zone at once (like pdnsutil rectify-zone)" "$(pq "SELECT count(*) FROM records WHERE domain_id = $EX")" $SIG NONE "UPDATE records SET ordername = ordername, auth = auth WHERE domain_id = $EX"
a_n "...and NULL again" 1 $SIG NONE "UPDATE records SET ordername = NULL WHERE name = 'www.example.com' AND type = 'A'"
a_err "but not the TTL of an A record" "ordername and auth" $SIG NONE "UPDATE records SET ttl = 1 WHERE name = 'www.example.com' AND type = 'A'"
a_err "...not the content" "ordername and auth" $SIG NONE "UPDATE records SET content = '192.0.2.66' WHERE name = 'www.example.com' AND type = 'A'"
a_err "...not the name" "ordername and auth" $SIG NONE "UPDATE records SET name = 'x.example.com' WHERE name = 'www.example.com' AND type = 'A'"
a_err "...not the type (A to TXT)" "ordername and auth" $SIG NONE "UPDATE records SET type = 'TXT' WHERE name = 'www.example.com' AND type = 'A'"
a_err "...not the zone" "ordername and auth" $SIG NONE "UPDATE records SET domain_id = $OTHER WHERE name = 'www.example.com' AND type = 'A'"
a_err "...not the priority of an MX record" "ordername and auth" $SIG NONE "UPDATE records SET prio = 20 WHERE name = 'mail.example.com'"
a_err "...not the disabled flag" "ordername and auth" $SIG NONE "UPDATE records SET disabled = true WHERE name = 'www.example.com' AND type = 'A'"
a_err "...also when ordername and auth are set in the same statement" "ordername and auth" $SIG NONE "UPDATE records SET ordername = 'q', ttl = 1 WHERE name = 'www.example.com' AND type = 'A'"
a_err "...not an A record turned into a DNSSEC record" "ordername and auth" $SIG NONE "UPDATE records SET type = 'RRSIG' WHERE name = 'www.example.com' AND type = 'A'"
a_err "...nor a DNSSEC record turned into an A record" "ordername and auth" $SIG NONE "UPDATE records SET type = 'A', content = '192.0.2.67' WHERE name = 'sigcol.example.com'"
a_err "...not a typeless row given a type" "ordername and auth" $SIG NONE "UPDATE records SET type = 'A', content = '192.0.2.68' WHERE name = 'ent.example.com'"
a_err "...with the principal of a global master set it is the same" "ordername and auth" $SIG $GM "UPDATE records SET ttl = 1 WHERE name = 'www.example.com' AND type = 'A'"
a_n "a DNSSEC record may change in any column" 1 $SIG NONE "UPDATE records SET ttl = 7, content = 'y', name = 'sigcol2.example.com' WHERE name = 'sigcol.example.com'"
a_err "the SOA's TTL stays" "may change only the serial" $SIG NONE "UPDATE records SET ttl = 1 WHERE type = 'SOA' AND domain_id = $EX"
a_err "...and so does its disabled flag" "may change only the serial" $SIG NONE "UPDATE records SET disabled = true WHERE type = 'SOA' AND domain_id = $EX"
a_n "...the serial changes together with the ordername and auth" 1 $SIG NONE "UPDATE records SET content = '$SOAC 205 7200 3600 1209600 300', ordername = 'z', auth = true WHERE domain_id = $EX AND type = 'SOA'"
oq "DELETE FROM records WHERE name IN ('sigcol2.example.com', 'ent.example.com'); UPDATE records SET ordername = NULL, auth = true WHERE domain_id = $EX; UPDATE records SET content = '$SOAC 201 7200 3600 1209600 300' WHERE domain_id = $EX AND type = 'SOA';
    DELETE FROM cryptokeys WHERE content = 'NEWKEY'; DELETE FROM karidns_key_requests; DELETE FROM karidns_signer_state" > /dev/null

echo "-- credentials, and every other role; the loader and karidns-zone (writer) roles with RLS on (the API script ran first)"
psql -X -q -d "$PGMAINT" -c "CREATE ROLE $LD2 NOLOGIN; CREATE ROLE $WR2 NOLOGIN" > /dev/null 2>&1
if rs karidns_loader_role.pgsql.sql $LD2 public && rs karidns_writer_role.pgsql.sql $WR2 public; then pass "the loader and writer role scripts apply with RLS already on"; else fail "the loader / writer role scripts"; head -3 "$T/rs.err"; fi
if rs karidns_loader_role.pgsql.sql $LD2 public && rs karidns_writer_role.pgsql.sql $WR2 public; then pass "...and can be applied again"; else fail "the loader / writer role scripts, twice"; head -3 "$T/rs.err"; fi
oeq "the loader and the writer roles are members of karidns_rls_trusted" "2" "SELECT count(*) FROM pg_auth_members m JOIN pg_roles t ON t.oid = m.roleid JOIN pg_roles r ON r.oid = m.member WHERE t.rolname = 'karidns_rls_trusted' AND r.rolname IN ('$LD2', '$WR2')"
for r in $LD2 $WR2 $SIG; do
    a_err "credentials are unreadable for $r (password_hash)" "permission denied" $r NONE "SELECT password_hash FROM karidns_auth.credentials"
    a_err "...SELECT * from the principals table too" "permission denied" $r NONE "SELECT * FROM karidns_auth.principals"
done
a_err "the audit log is unreadable for the loader role" "permission denied" $LD2 NONE "SELECT count(*) FROM karidns_auth.audit_log"
a_err "...and for the writer role" "permission denied" $WR2 NONE "SELECT count(*) FROM karidns_auth.audit_log"
a_err "the writer role cannot write grants" "permission denied" $WR2 NONE "DELETE FROM karidns_auth.grants"
a_eq "loader role: reads every record" "$(sg_cnt records)" $LD2 NONE "SELECT count(*) FROM records"
a_eq "...zones, metadata, tags, views, tagdefs, reload requests" "$(sg_cnt domains) $(sg_cnt domainmetadata) $(sg_cnt karidns_record_tags) $(sg_cnt karidns_domain_views) $(sg_cnt karidns_zone_tagdefs) $(sg_cnt karidns_reload_requests)" $LD2 NONE \
    "SELECT count(*) FROM domains; SELECT count(*) FROM domainmetadata; SELECT count(*) FROM karidns_record_tags; SELECT count(*) FROM karidns_domain_views; SELECT count(*) FROM karidns_zone_tagdefs; SELECT count(*) FROM karidns_reload_requests"
a_eq "...the key columns it is granted" "2" $LD2 NONE "SELECT count(DISTINCT domain_id) FROM cryptokeys WHERE active"
a_err "...but not cryptokeys.content" "permission denied" $LD2 NONE "SELECT content FROM cryptokeys"
a_err "loader role: no write" "permission denied|read-only" $LD2 NONE "UPDATE records SET ttl = 1"
a_eq "writer role: reads every record" "$(sg_cnt records)" $WR2 NONE "SELECT count(*) FROM records"
a_ok "writer role: INSERT, UPDATE and DELETE on records (any zone, any type: it is not bound by grants)" $WR2 NONE "$(ri $OTHER wr1.other.test RRSIG x 300); UPDATE records SET ttl = 77 WHERE name = 'wr1.other.test'; DELETE FROM records WHERE name = 'wr1.other.test'"
a_ok "writer role: domains, domainmetadata, views, tagdefs, reload requests" $WR2 NONE "INSERT INTO domains (name, type) VALUES ('wr.test', 'NATIVE'); INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'wr.test'; INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'v' FROM domains WHERE name = 'wr.test'; INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) SELECT id, 'location', 't', '192.0.2.0/24' FROM domains WHERE name = 'wr.test'; INSERT INTO karidns_reload_requests (zone) VALUES ('wr.test')"
a_ok "...and the delete of the zone with the cascade" $WR2 NONE "DELETE FROM domains WHERE name = 'wr.test'"
CL2=$(pq "SELECT coalesce(max(seq), 0) FROM karidns_changes")
a_ok "the writer role changes a record" $WR2 NONE "UPDATE records SET ttl = ttl + 1 WHERE name = 'www.other.test'"
oeq "...and the change log got a row" "t" "SELECT count(*) >= 1 FROM karidns_changes WHERE seq > $CL2 AND domain_id = $OTHER"
oeq "...its changes are audited under its database role" "t" "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE db_role = '$WR2'"
a_err "writer role: cryptokeys.content stays unreadable" "permission denied" $WR2 NONE "SELECT content FROM cryptokeys"

echo "-- a role that is neither the API nor trusted"
oq "CREATE ROLE $BARE NOLOGIN; GRANT USAGE ON SCHEMA public TO $BARE; GRANT SELECT ON domains, records TO $BARE" > /dev/null
a_err "a role with SELECT on records, not trusted: the policies of the API deny it (it may not even call their functions)" "permission denied for function|row-level security" $BARE NONE "SELECT count(*) FROM records"
oq "GRANT karidns_rls_trusted TO $BARE" > /dev/null
a_eq "...after GRANT karidns_rls_trusted it sees every row" "$(sg_cnt records)" $BARE NONE "SELECT count(*) FROM records"
oq "REVOKE karidns_rls_trusted FROM $BARE" > /dev/null
a_err "...and is refused again after the REVOKE" "permission denied for function|row-level security" $BARE NONE "SELECT count(*) FROM records"
oeq "the owner is not bound by RLS" "t" "SELECT count(*) > 0 FROM records"

echo "-- the loader and writer role scripts first, the API script second; a real load and an import (a second database)"
DB2=${PGDB}_o1
if psql -X -q -d "$PGMAINT" -c "CREATE DATABASE $DB2" > /dev/null 2>&1; then
    if [ -n "${KARIDNS_TEST_PG:-}" ]; then PGC2="$KARIDNS_TEST_PG dbname=$DB2"; else PGC2="dbname=$DB2"; fi
    P2() { psql -X -q -At -v ON_ERROR_STOP=1 "$PGC2" "$@"; }
    P2 -f tests/db/pdns_schema.pgsql.sql > /dev/null && P2 -f db/karidns_ext.pgsql.sql > /dev/null || fail "cannot create the second database"
    PW2="pw$$x"
    psql -X -q -d "$PGMAINT" -c "CREATE ROLE $LD1 LOGIN PASSWORD '$PW2'; CREATE ROLE $WR1 LOGIN PASSWORD '$PW2'; CREATE ROLE $SG1 LOGIN PASSWORD '$PW2'" > /dev/null 2>&1
    P2 -c "INSERT INTO domains (name, type) VALUES ('o1.test', 'NATIVE');
           INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, v.n, v.t, v.c, 3600 FROM domains, (VALUES ('o1.test', 'SOA', 'ns1.o1.test hostmaster.o1.test 1 7200 3600 1209600 300'), ('o1.test', 'NS', 'ns1.o1.test'), ('ns1.o1.test', 'A', '192.0.2.1'), ('www.o1.test', 'A', '192.0.2.2')) AS v(n, t, c) WHERE domains.name = 'o1.test'" > /dev/null
    if rs karidns_loader_role.pgsql.sql $LD1 public "$PGC2" && rs karidns_writer_role.pgsql.sql $WR1 public "$PGC2"; then pass "the loader and writer scripts apply before RLS exists"; else fail "role scripts first"; head -3 "$T/rs.err"; fi
    if rs karidns_api_role.pgsql.sql $API public "$PGC2" && rs karidns_signer_role.pgsql.sql $SIG public "$PGC2" && rs karidns_signer_role.pgsql.sql $SG1 public "$PGC2"; then pass "the API and signer scripts apply after them"; else fail "API script second"; head -3 "$T/rs.err"; fi
    q2() { P2 -c "SET ROLE $1; $2" 2> "$E" | tr '\n' ' ' | sed 's/ $//'; }
    g=$(q2 $LD1 "SELECT count(*) FROM records; SELECT count(*) FROM domains"); [ "$g" = "4 1" ] && pass "the loader role still reads everything (RLS on, API script second)" || fail "loader role in the second order: '$g' $(head -c 200 "$E")"
    g=$(q2 $WR1 "INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'wr.o1.test', 'A', '192.0.2.9', 60 FROM domains; UPDATE records SET ttl = 61 WHERE name = 'wr.o1.test'; SELECT count(*) FROM records; DELETE FROM records WHERE name = 'wr.o1.test'")
    [ "$g" = "5" ] && pass "the writer role still reads and writes everything" || fail "writer role in the second order: '$g' $(head -c 200 "$E")"
    P2 -c "INSERT INTO cryptokeys (domain_id, flags, active, content) SELECT id, 257, true, 'K' FROM domains" > /dev/null
    g=$(q2 $LD1 "SELECT content FROM cryptokeys"); if [ -z "$g" ] && grep -qi "permission denied" "$E"; then pass "...and the loader role cannot read cryptokeys.content"; else fail "cryptokeys.content for the loader: '$g' $(head -c 200 "$E")"; fi
    g=$(q2 $SIG "SELECT count(*) FROM records; SELECT content FROM cryptokeys"); [ "$g" = "4 K" ] && pass "the signer role reads the records and the keys" || fail "signer in the second database: '$g' $(head -c 200 "$E")"
    g=$(q2 $API "SELECT count(*) FROM records"); [ "$g" = "0" ] && pass "the API role without a principal reads nothing" || fail "API role in the second database: '$g' $(head -c 200 "$E")"
    # one real load: karidns-dbloader --dump as the loader role equals the owner's stream (the loader refuses a zone with keys and no PRESIGNED)
    P2 -c "DELETE FROM cryptokeys" > /dev/null
    PORT=$(pq "SHOW port")
    RCL="host=127.0.0.1 port=$PORT user=$LD1 password=$PW2 dbname=$DB2"
    RCW="host=127.0.0.1 port=$PORT user=$WR1 password=$PW2 dbname=$DB2"
    RCS="host=127.0.0.1 port=$PORT user=$SG1 password=$PW2 dbname=$DB2"
    if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$RCL" -c "SELECT 1" > /dev/null 2>&1; then
        skip "the server does not accept a password login over 127.0.0.1:$PORT: the dump and the import are not tested"
    else
        chmod 777 "$T"
        if [ ! -x "$LOADER" ] || ! "$LOADER" --drivers | grep -qx postgresql; then
            skip "$LOADER is not built with the PostgreSQL driver: the dump is not tested"
        else
            printf '%s\n' "$PGC2" > "$T/ci_owner"; printf '%s\n' "$RCL" > "$T/ci_ld"
            for cf in ci_owner ci_ld; do [ -n "$PG_AS" ] && chown "$PG_AS" "$T/$cf"; chmod 600 "$T/$cf"; done
            as_pg "$PGLOADER" --dump "$T/owner.kdb" --driver postgresql --conninfo-file "$T/ci_owner" 2> "$T/owner.err"; ro=$?
            as_pg "$PGLOADER" --dump "$T/ld.kdb" --driver postgresql --conninfo-file "$T/ci_ld" 2> "$T/ld.err"; rl=$?
            if [ "$ro" -le 1 ] && [ "$rl" = "$ro" ] && cmp -s "$T/owner.kdb" "$T/ld.kdb" && [ -s "$T/ld.kdb" ]; then
                pass "karidns-dbloader --dump as the loader role (RLS on) writes the owner's stream, byte for byte ($(wc -c < "$T/ld.kdb" | tr -d ' ') bytes)"
            else fail "loader dump: exit $rl, owner $ro"; head -3 "$T/ld.err" "$T/owner.err"; fi
            pq "REVOKE karidns_rls_trusted FROM $LD1" > /dev/null
            as_pg "$PGLOADER" --dump "$T/ld0.kdb" --driver postgresql --conninfo-file "$T/ci_ld" 2> "$T/ld0.err"; rl0=$?
            if [ "$rl0" != 0 ] || ! cmp -s "$T/owner.kdb" "$T/ld0.kdb"; then pass "...without the trusted membership the same load fails or sees no zone (exit $rl0)"; else fail "the loader without karidns_rls_trusted still loads everything"; fi
            pq "GRANT karidns_rls_trusted TO $LD1" > /dev/null
        fi
        if [ ! -x "$ZONE_BIN" ] || ! "$ZONE_BIN" --version | grep -q postgresql; then
            skip "karidns-zone is not built with the PostgreSQL driver: the import is not tested"
        else
            Z=$T/karidns-zone; cp "$ZONE_BIN" "$Z" && chmod 755 "$Z"
            printf '%s\n' "$RCW" > "$T/ci_wr"; [ -n "$PG_AS" ] && chown "$PG_AS" "$T/ci_wr"; chmod 600 "$T/ci_wr"
            mkdir "$T/in" && chmod 755 "$T/in"
            for n in 1 2; do
                cat > "$T/in/rls$n.zone" <<EOF
\$ORIGIN rls.test.
\$TTL 3600
@ IN SOA ns1.rls.test. hostmaster.rls.test. $n 7200 3600 1209600 300
@ IN NS ns1.rls.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.$((n + 1))
EOF
            done
            chmod 644 "$T"/in/*
            zt() { as_pg "$Z" "$@" --no-config --conninfo-file "$T/ci_wr" > "$T/zt.out" 2> "$T/zt.err" < /dev/null; st=$?; }
            zt import rls.test "$T/in/rls1.zone"
            if [ "$st" = 0 ] && [ "$(P2 -c "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'rls.test'")" = "4" ]; then pass "karidns-zone import as the writer role with RLS on (a new zone, 4 records)"; else fail "karidns-zone import: exit $st"; head -3 "$T/zt.err"; fi
            zt import rls.test "$T/in/rls2.zone"
            if [ "$st" = 0 ] && [ "$(P2 -c "SELECT content FROM records WHERE name = 'www.rls.test'")" = "192.0.2.3" ]; then pass "...a replace import (delete, update, insert)"; else fail "karidns-zone replace: exit $st"; head -3 "$T/zt.err"; fi
            zt export rls.test
            if [ "$st" = 0 ] && grep -q "192.0.2.3" "$T/zt.out"; then pass "...and an export"; else fail "karidns-zone export: exit $st"; head -3 "$T/zt.err"; fi
            g=$(P2 -c "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE db_role = '$WR1' AND zone_name = 'rls.test'")
            [ "$g" = "t" ] && pass "...and the import is in the audit log under the writer role" || fail "no audit row of the import ('$g')"
            # item C: karidns-zone import --signer with the rights of the signer role alone (RLS on)
            printf '%s\n' "$RCS" > "$T/ci_sg"; [ -n "$PG_AS" ] && chown "$PG_AS" "$T/ci_sg"; chmod 600 "$T/ci_sg"
            for n in 3 4 5; do
                cat > "$T/in/rls_s$n.zone" <<EOF
\$ORIGIN rls.test.
\$TTL 3600
@ IN SOA ns1.rls.test. hostmaster.rls.test. $n 7200 3600 1209600 300
@ IN NS ns1.rls.test.
@ IN DNSKEY 257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN NSEC ns1.rls.test. NS SOA RRSIG NSEC DNSKEY
ns1 IN A 192.0.2.1
ns1 IN NSEC www.rls.test. A RRSIG NSEC
www IN A 192.0.2.3
www IN NSEC rls.test. A RRSIG NSEC
@ IN RRSIG SOA 8 2 3600 2030010${n}000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN RRSIG NS 8 2 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN RRSIG DNSKEY 8 2 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN RRSIG NSEC 8 2 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
ns1 IN RRSIG A 8 3 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
ns1 IN RRSIG NSEC 8 3 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
www IN RRSIG A 8 3 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
www IN RRSIG NSEC 8 3 3600 20300601000000 20200101000000 12345 rls.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
EOF
            done
            chmod 644 "$T"/in/*
            zs() { as_pg "$Z" "$@" --no-config --conninfo-file "$T/ci_sg" > "$T/zs.out" 2> "$T/zs.err" < /dev/null; st=$?; }
            zs import --signer --json rls.test "$T/in/rls_s3.zone"
            if [ "$st" = 0 ] && [ "$(P2 -c "SELECT content FROM records WHERE name = 'rls.test' AND type = 'SOA'")" = "ns1.rls.test hostmaster.rls.test 3 7200 3600 1209600 300" ]; then pass "karidns-zone import --signer as the signer role with RLS on: the zone is signed (SOA serial 2 -> 3)"; else fail "import --signer: exit $st"; head -5 "$T/zs.err" "$T/zs.out"; fi
            g=$(P2 -c "SELECT (SELECT count(*) FROM records WHERE name LIKE '%rls.test' AND type = 'RRSIG') || '|' || (SELECT count(*) FROM records WHERE type = 'DNSKEY' AND name = 'rls.test') || '|' || (SELECT string_agg(kind || '=' || content, ',' ORDER BY kind) FROM domainmetadata m JOIN domains d ON d.id = m.domain_id WHERE d.name = 'rls.test') || '|' || (SELECT ordername FROM records WHERE name = 'www.rls.test' AND type = 'A')")
            [ "$g" = "8|1|PRESIGNED=1,X-KARIDNS-SIGNER=1|www" ] && pass "...8 RRSIGs, the DNSKEY, PRESIGNED and X-KARIDNS-SIGNER, the ordername of www" || fail "after import --signer: '$g'"
            xid=$(sed -n 's/.*"xid": "\([0-9][0-9]*\)".*/\1/p' "$T/zs.out")
            g=$(P2 -c "SELECT count(*) > 0 FROM karidns_changes WHERE xid = '${xid:-0}'::xid8 AND domain_id = (SELECT id FROM domains WHERE name = 'rls.test')")
            [ -n "$xid" ] && [ "$g" = "t" ] && pass "...--json: the write id ($xid) is the xid of its rows in karidns_changes" || fail "write id '$xid' ($g): $(cat "$T/zs.out" | tr '\n' ' ' | cut -c1-300)"
            grep -q '"earliest_expire": "2030-01-03T00:00:00Z"' "$T/zs.out" && grep -q '"serial": 3' "$T/zs.out" && pass "...and the new serial and the earliest RRSIG expiration" || fail "json result: $(cat "$T/zs.out" | tr '\n' ' ' | cut -c1-400)"
            g=$(P2 -c "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE db_role = '$SG1' AND zone_name = 'rls.test' AND table_name = 'records'")
            [ "$g" = "t" ] && pass "...the import is in the audit log under the signer role" || fail "no audit row of the signer's import ('$g')"
            zs import --signer rls.test "$T/in/rls_s4.zone"
            if [ "$st" = 0 ] && [ "$(P2 -c "SELECT count(*) FROM records WHERE name LIKE '%rls.test' AND type = 'RRSIG'")" = "8" ] && [ "$(P2 -c "SELECT split_part(content, ' ', 3) FROM records WHERE name = 'rls.test' AND type = 'SOA'")" = "4" ]; then pass "...a second run replaces the signatures (serial 4)"; else fail "second import --signer: exit $st"; head -5 "$T/zs.err"; fi
            P2 -c "UPDATE records SET content = '192.0.2.77' WHERE name = 'www.rls.test' AND type = 'A'" > /dev/null
            zs import --signer rls.test "$T/in/rls_s5.zone"
            if [ "$st" = 3 ] && grep -q "changed" "$T/zs.err" && [ "$(P2 -c "SELECT split_part(content, ' ', 3) FROM records WHERE name = 'rls.test' AND type = 'SOA'")" = "4" ]; then pass "...a change of the zone since the file was made: exit status 3, nothing written"; else fail "import --signer of a stale file: exit $st"; head -3 "$T/zs.err"; fi
            zs import rls.test "$T/in/rls1.zone"
            if [ "$st" = 1 ] && [ "$(P2 -c "SELECT content FROM records WHERE name = 'www.rls.test' AND type = 'A'")" = "192.0.2.77" ]; then pass "the signer role cannot do an ordinary import (it may not write an A record): refused, nothing changed"; else fail "ordinary import as the signer role: exit $st"; head -3 "$T/zs.err"; fi
        fi
    fi
else
    skip "cannot create a second database: the order loader script first, the dump and the import are not tested"
fi

echo "-- switching RLS off and on again"
oeq "disable_rls('public') and ('karidns_auth') turn it off on 14 + 11 tables" "14 11" "SELECT karidns_auth.disable_rls('public') || ' ' || karidns_auth.disable_rls('karidns_auth')"
oq "GRANT SELECT ON domains, records TO $BARE" > /dev/null
a_eq "...a role that is not trusted sees the rows again" "$(sg_cnt records)" $BARE NONE "SELECT count(*) FROM records"
oeq "enable_rls() switches it on again" "14 11" "SELECT karidns_auth.enable_rls('public') || ' ' || karidns_auth.enable_rls('karidns_auth')"
a_err "...and the bare role is refused again" "permission denied for function|row-level security" $BARE NONE "SELECT count(*) FROM records"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_auth_rls_test: all $PASS checks passed ($SKIPS skipped) ==="; exit 0; fi
echo "=== run_db_auth_rls_test: $FAILS check(s) FAILED ($PASS passed, $SKIPS skipped) ==="
exit 1

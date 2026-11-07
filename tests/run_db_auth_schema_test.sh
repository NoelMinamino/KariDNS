#!/bin/sh
# run_db_auth_schema_test.sh - the auth schema of KariDNS 0.6.0 item B, milestone M1: the schema karidns_auth of db/karidns_ext.pgsql.sql, the audit tables of
# db/karidns_ext.sqlite3.sql, the SQLite3 audit triggers db/karidns_audit.sqlite3.sql and the auth file db/karidns_auth.sqlite3.sql (all schema version 3),
# and karidns-zone --audit rows|summary.  (Roles and row level security are milestone M2: tests/run_db_auth_rls_test.sh.)
#
# The same cases run on both dialects (PostgreSQL: the schema karidns_auth in a temporary database; SQLite3: the auth file; the SQLite3 part SKIPs without
# the sqlite3 command line tool, the PostgreSQL part without a server, see tests/db/pg_lib.sh):
#   - principal_closure follows every insert and delete of memberships and principals (compared with a recursive query after each change; a diamond, a
#     deleted middle group), a membership that makes a cycle (also a group in itself) or nests groups more than 8 levels deep is refused (also by joining
#     two chains), a user has no members, a membership cannot be updated, the kind of a principal in a membership (or with credentials) cannot change;
#   - credentials are for users only and a password hash must be a $argon2id$ or $scrypt$ string; an rr_policy takes no DNSSEC-managed type (each of the
#     seven), no lower case type, a TTL range that makes sense; grants: the scope of each role, canonical zone and suffix names (lower case, no trailing dot,
#     no empty label, 253 octets), a suffix that is the zone or ends in '.<zone>' (evilexample.com is not under example.com), the foreign keys.
# PostgreSQL only: the trigger on domains (DELETE removes the grants of the zone, a rename renames them, another schema's zone of the same name is not
#   touched), karidns_auth.enable_audit() / disable_audit() (idempotent, the PowerDNS tables have no audit trigger before it), the audit rows of INSERT /
#   UPDATE / DELETE (before / after, zone, row id, database role, principal and change set from the session, the cascade of a zone delete), cryptokeys.content
#   and the secrets of credentials written as "<redacted>", summary mode (one row per transaction, table, operation and zone; ignored for a role named
#   karidns_api), the audit log is append only for a role that is not the owner, a writer without any right on karidns_auth can still change the data, and
#   karidns-zone --audit rows|summary (usage errors included).
# Both dialects, item C (the signer): the tables karidns_key_requests and karidns_signer_state (their CHECKs, the foreign keys and the cascade of a zone delete, the
#   indexes, the audit rows of both, and that neither writes the change log).
# SQLite3 only: the audit triggers of the zone file (I / U / D, redaction, the cascade of a zone delete, the actor row), karidns-zone writing its actor row
#   (karidns-zone:<OS user>) and deleting it, a database without the actor table, the auth file's own audit with its actor row, and the principals delete
#   trigger with foreign keys off.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

PASS=0; FAILS=0; SKIPS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
skip() { SKIPS=$((SKIPS + 1)); echo "  [SKIP] $1"; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_auth.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
ROLES=""
cleanup() {
    pg_cleanup
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

ZONE_BIN=${ZONE:-$ROOT/karidns-zone}
HASH_A='$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g'
HASH_S='$scrypt$ln=15,r=8,p=1$c2FsdA$aGFzaA'
L63=$(printf '%063d' 0 | tr 0 a)
L61=$(printf '%061d' 0 | tr 0 a)
NAME253="$L63.$L63.$L63.$L61"
NAME254="$NAME253"a

# ================================================================ cases shared by both dialects
# The caller sets: P (the table prefix: "karidns_auth." or ""), DS (the data_schema literal of a zone grant: 'public' or NULL), and the functions
#   X_OK SQL            the statements must succeed
#   X_ERR DESC PATTERN SQL   the statements must fail with PATTERN (case-insensitive) in the message
#   X_Q SQL             the first column of the output
eq() { got=$(X_Q "$3"); if [ "$got" = "$2" ]; then pass "$1"; else fail "$1: got '$got', wanted '$2'"; fi; }
ok() { if X_OK "$2"; then pass "$1"; else fail "$1: the statement failed"; fi; }

closure_check() {   # closure_check DESC: principal_closure equals the closure computed from the memberships (with the shortest depth)
    exp="WITH RECURSIVE r(m, g, d) AS (SELECT id, id, 0 FROM ${P}principals UNION ALL SELECT r.m, ms.group_id, r.d + 1 FROM r JOIN ${P}memberships ms ON ms.member_id = r.g WHERE r.d < 9),
         e AS (SELECT m, g, min(d) AS d FROM r GROUP BY m, g)"
    eq "$1" "0|$(X_Q "SELECT count(*) FROM ${P}principal_closure")" \
       "$exp SELECT (((SELECT count(*) FROM (SELECT m, g, d FROM e EXCEPT SELECT member_id, group_id, depth FROM ${P}principal_closure) x) + (SELECT count(*) FROM (SELECT member_id, group_id, depth FROM ${P}principal_closure EXCEPT SELECT m, g, d FROM e) y)) || '|' || (SELECT count(*) FROM e))"
}

pid() { X_Q "SELECT id FROM ${P}principals WHERE name = '$1'"; }
member() { X_OK "INSERT INTO ${P}memberships (member_id, group_id) SELECT m.id, g.id FROM ${P}principals m, ${P}principals g WHERE m.name = '$1' AND g.name = '$2'"; }
member_err() { X_ERR "$1" "$2" "INSERT INTO ${P}memberships (member_id, group_id) SELECT m.id, g.id FROM ${P}principals m, ${P}principals g WHERE m.name = '$3' AND g.name = '$4'"; }
cdepth() { X_Q "SELECT depth FROM ${P}principal_closure c JOIN ${P}principals m ON m.id = c.member_id JOIN ${P}principals g ON g.id = c.group_id WHERE m.name = '$1' AND g.name = '$2'"; }

shared_cases() {
    # ---- principals and the closure
    ok "principals: users and groups" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'alice'), ('user', 'bob'), ('group', 'eng'), ('group', 'ops'), ('group', 'tenant'), ('group', 'other')"
    X_ERR "a kind other than user / group is refused" "check constraint" "INSERT INTO ${P}principals (kind, name) VALUES ('robot', 'r1')"
    X_ERR "a name is unique" "unique" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'alice')"
    X_ERR "a name is unique regardless of case" "unique" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'ALICE')"
    eq "every principal is in its own closure at depth 0" "6" "SELECT count(*) FROM ${P}principal_closure WHERE member_id = group_id AND depth = 0"
    member alice eng && member eng tenant && pass "alice in eng, eng in tenant" || fail "alice in eng, eng in tenant"
    eq "closure: alice reaches eng (1) and tenant (2)" "1|2" "SELECT '$(cdepth alice eng)|$(cdepth alice tenant)'"
    closure_check "the closure equals the one computed from the memberships"
    member alice ops && member ops tenant && pass "alice also in ops, ops in tenant (a diamond)" || fail "the diamond"
    eq "the diamond: alice reaches tenant at the shortest depth 2" "2" "SELECT depth FROM ${P}principal_closure c JOIN ${P}principals m ON m.id = c.member_id JOIN ${P}principals g ON g.id = c.group_id WHERE m.name = 'alice' AND g.name = 'tenant'"
    closure_check "the closure after the diamond"
    member bob ops && pass "bob in ops" || fail "bob in ops"
    member_err "a duplicate membership is refused" "duplicate|unique|constraint" alice eng
    eq "a membership that is refused changes nothing" "0" "SELECT count(*) FROM ${P}principal_closure WHERE member_id = (SELECT id FROM ${P}principals WHERE name = 'bob') AND group_id = (SELECT id FROM ${P}principals WHERE name = 'eng')"
    # ---- refusals: cycle, user as a group, update
    member_err "a cycle: tenant in eng (eng is in tenant)" "cycle" tenant eng
    member_err "a cycle through two levels: tenant in ops (ops is in tenant)" "cycle" tenant ops
    member_err "a group in itself" "cycle|check" eng eng
    member_err "a user has no members: eng in alice" "not a group" eng alice
    member_err "a user has no members: bob in alice" "not a group" bob alice
    X_ERR "a membership cannot be updated" "cannot be updated" "UPDATE ${P}memberships SET group_id = (SELECT id FROM ${P}principals WHERE name = 'other') WHERE member_id = (SELECT id FROM ${P}principals WHERE name = 'bob')"
    closure_check "the closure after the refusals"
    # ---- the kind of a principal
    X_ERR "a group that is in a membership cannot become a user" "in a membership" "UPDATE ${P}principals SET kind = 'user' WHERE name = 'eng'"
    X_ERR "a user that is in a membership cannot become a group" "in a membership" "UPDATE ${P}principals SET kind = 'group' WHERE name = 'bob'"
    ok "a principal in no membership may change its kind" "UPDATE ${P}principals SET kind = 'user' WHERE name = 'other'; UPDATE ${P}principals SET kind = 'group' WHERE name = 'other'"
    # ---- nesting depth: a chain of 8 memberships is the limit
    ok "ten groups g1..g10" "INSERT INTO ${P}principals (kind, name) SELECT 'group', 'g' || n FROM (SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) x"
    i=1; okc=0
    while [ $i -le 8 ]; do member "g$i" "g$((i + 1))" && okc=$((okc + 1)); i=$((i + 1)); done
    [ $okc -eq 8 ] && pass "a chain of 8 memberships g1 -> g2 -> ... -> g9 is accepted" || fail "the chain of 8 memberships: $okc accepted"
    eq "closure: g1 reaches g9 at depth 8" "8" "SELECT '$(cdepth g1 g9)'"
    member_err "a ninth membership in the chain is refused (g9 in g10)" "levels deep" g9 g10
    member_err "g10 in g1 puts a tenth principal on top of the chain of 8 (g10 -> g1 -> ... -> g9)" "levels deep" g10 g1
    ok "a user at the bottom of a shorter chain: bob in g2 (7 below + 1)" "INSERT INTO ${P}memberships (member_id, group_id) SELECT m.id, g.id FROM ${P}principals m, ${P}principals g WHERE m.name = 'bob' AND g.name = 'g2'"
    ok "two chains: g10 in other (other is in no group)" "INSERT INTO ${P}memberships (member_id, group_id) SELECT m.id, g.id FROM ${P}principals m, ${P}principals g WHERE m.name = 'g10' AND g.name = 'other'"
    member_err "joining two chains over the limit: other in g1 (g10 -> other -> g1 -> ... -> g9)" "levels deep" other g1
    closure_check "the closure after the chains"
    # ---- deleting: a middle group, a user, a membership
    ok "delete the middle group g5 of the chain" "DELETE FROM ${P}principals WHERE name = 'g5'"
    closure_check "the closure after deleting a middle group (g1 no longer reaches g9)"
    eq "g4 no longer reaches g6; g6 reaches g9" "||3" "SELECT '$(cdepth g4 g6)|$(cdepth g1 g9)|$(cdepth g6 g9)'"
    ok "a chain chd -> chg -> chp" "INSERT INTO ${P}principals (kind, name) VALUES ('group', 'chd'), ('group', 'chg'), ('group', 'chp')"
    member chd chg && member chg chp && pass "chd in chg, chg in chp" || fail "chd -> chg -> chp"
    eq "chd reaches chp over chg (depth 2)" "2" "SELECT '$(cdepth chd chp)'"
    ok "delete the middle group chg" "DELETE FROM ${P}principals WHERE name = 'chg'"
    eq "(chd, chp) is gone, chd and chp are still in their own closure" "|2" "SELECT '$(cdepth chd chp)|' || count(*) FROM ${P}principal_closure WHERE group_id = member_id AND member_id IN (SELECT id FROM ${P}principals WHERE name IN ('chd', 'chp'))"
    closure_check "the closure after deleting the middle group of a short chain"
    ok "delete bob (a user in ops and g2)" "DELETE FROM ${P}principals WHERE name = 'bob'"
    closure_check "the closure after deleting a user"
    ok "delete the membership alice in ops" "DELETE FROM ${P}memberships WHERE member_id = (SELECT id FROM ${P}principals WHERE name = 'alice') AND group_id = (SELECT id FROM ${P}principals WHERE name = 'ops')"
    eq "alice reaches tenant over eng only (still 2)" "2" "SELECT '$(cdepth alice tenant)'"
    ok "delete the membership eng in tenant" "DELETE FROM ${P}memberships WHERE member_id = (SELECT id FROM ${P}principals WHERE name = 'eng') AND group_id = (SELECT id FROM ${P}principals WHERE name = 'tenant')"
    eq "alice no longer reaches tenant" "" "SELECT '$(cdepth alice tenant)'"
    closure_check "the closure after deleting memberships"
    ok "a membership may be inserted again after the delete" "INSERT INTO ${P}memberships (member_id, group_id) SELECT m.id, g.id FROM ${P}principals m, ${P}principals g WHERE m.name = 'eng' AND g.name = 'tenant'"
    closure_check "the closure once more"

    # ---- credentials
    ok "credentials of a user: argon2id" "INSERT INTO ${P}credentials (principal_id, password_hash, totp_secret, oidc_issuer, oidc_subject) SELECT id, '$HASH_A', 'JBSWY3DP', 'https://idp.example', 'sub-alice' FROM ${P}principals WHERE name = 'alice'"
    ok "credentials of a user: scrypt, nothing else" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'carol'); INSERT INTO ${P}credentials (principal_id, password_hash) SELECT id, '$HASH_S' FROM ${P}principals WHERE name = 'carol'"
    ok "credentials without a password hash (OIDC only)" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'dave'); INSERT INTO ${P}credentials (principal_id, oidc_issuer, oidc_subject) SELECT id, 'https://idp.example', 'sub-dave' FROM ${P}principals WHERE name = 'dave'"
    X_ERR "credentials of a group are refused" "not a user" "INSERT INTO ${P}credentials (principal_id) SELECT id FROM ${P}principals WHERE name = 'eng'"
    X_ERR "a plain text password is refused" "check constraint" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'eve'); INSERT INTO ${P}credentials (principal_id, password_hash) SELECT id, 'hunter2' FROM ${P}principals WHERE name = 'eve'"
    X_ERR "a bcrypt hash is refused" "check constraint" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'frank'); INSERT INTO ${P}credentials (principal_id, password_hash) SELECT id, '\$2b\$12\$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345' FROM ${P}principals WHERE name = 'frank'"
    X_ERR "the OIDC subject of an issuer is unique" "unique" "INSERT INTO ${P}principals (kind, name) VALUES ('user', 'gina'); INSERT INTO ${P}credentials (principal_id, oidc_issuer, oidc_subject) SELECT id, 'https://idp.example', 'sub-alice' FROM ${P}principals WHERE name = 'gina'"
    X_ERR "an update to a plain text hash is refused" "check constraint" "UPDATE ${P}credentials SET password_hash = 'x' WHERE principal_id = (SELECT id FROM ${P}principals WHERE name = 'alice')"
    X_ERR "a user with credentials cannot become a group" "has credentials" "UPDATE ${P}principals SET kind = 'group' WHERE name = 'carol'"
    ok "deleting a user deletes its credentials" "DELETE FROM ${P}principals WHERE name = 'dave'"
    eq "no credentials of the deleted user are left" "2" "SELECT count(*) FROM ${P}credentials"

    # ---- rr_policies
    if [ "$P" = "karidns_auth." ]; then
        ok "a policy with ordinary types (DS included)" "INSERT INTO karidns_auth.rr_policies (name, allowed_types, allow_wildcard) VALUES ('web', ARRAY['A', 'AAAA', 'CNAME', 'TXT', 'DS', 'MX'], true)"
        for t in RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY; do
            X_ERR "the DNSSEC-managed type $t is refused in allowed_types" "check constraint" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('bad-$t', ARRAY['A', '$t'])"
        done
        for t in TYPE46 TYPE0047 TYPE48 TYPE00050 TYPE51 TYPE59 TYPE060 ANY AXFR IXFR OPT TSIG TKEY MAILA MAILB; do
            X_ERR "the type $t is refused in allowed_types" "check constraint" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('bad-$t', ARRAY['A', '$t'])"
        done
        ok "TYPE49 and TYPE257 are ordinary types" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('generic', ARRAY['TYPE49', 'TYPE257', 'TYPE460'])"
        X_ERR "a lower case type is refused" "check constraint" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('bad-lc', ARRAY['rrsig'])"
        X_ERR "a NULL type is refused" "check constraint" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('bad-null', ARRAY['A', NULL])"
        X_ERR "a type with a blank is refused" "check constraint" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('bad-sp', ARRAY['A B'])"
        X_ERR "allowed_types cannot be NULL" "null" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('bad-nn', NULL)"
        ok "an empty list of types is a policy that allows nothing" "INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('none', ARRAY[]::text[])"
        X_ERR "an update to a DNSSEC type is refused" "check constraint" "UPDATE karidns_auth.rr_policies SET allowed_types = ARRAY['DNSKEY'] WHERE name = 'web'"
    else
        ok "a policy with ordinary types (DS included)" "INSERT INTO rr_policies (name, allow_wildcard) VALUES ('web', 1); INSERT INTO rr_policy_types (policy_id, type) SELECT id, t FROM rr_policies, (SELECT 'A' AS t UNION ALL SELECT 'AAAA' UNION ALL SELECT 'CNAME' UNION ALL SELECT 'TXT' UNION ALL SELECT 'DS' UNION ALL SELECT 'MX') x WHERE name = 'web'"
        for t in RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY; do
            X_ERR "the DNSSEC-managed type $t is refused in rr_policy_types" "check constraint" "INSERT INTO rr_policy_types (policy_id, type) SELECT id, '$t' FROM rr_policies WHERE name = 'web'"
        done
        for t in TYPE46 TYPE0047 TYPE48 TYPE00050 TYPE51 TYPE59 TYPE060 ANY AXFR IXFR OPT TSIG TKEY MAILA MAILB; do
            X_ERR "the type $t is refused in rr_policy_types" "check constraint" "INSERT INTO rr_policy_types (policy_id, type) SELECT id, '$t' FROM rr_policies WHERE name = 'web'"
        done
        ok "TYPE49 and TYPE257 are ordinary types" "INSERT INTO rr_policies (name) VALUES ('generic'); INSERT INTO rr_policy_types (policy_id, type) SELECT id, t FROM rr_policies, (SELECT 'TYPE49' AS t UNION ALL SELECT 'TYPE257' UNION ALL SELECT 'TYPE460') x WHERE name = 'generic'"
        X_ERR "a lower case type is refused" "check constraint" "INSERT INTO rr_policy_types (policy_id, type) SELECT id, 'rrsig' FROM rr_policies WHERE name = 'web'"
        X_ERR "a type with a blank is refused" "check constraint" "INSERT INTO rr_policy_types (policy_id, type) SELECT id, 'A B' FROM rr_policies WHERE name = 'web'"
        ok "a policy that allows nothing" "INSERT INTO rr_policies (name) VALUES ('none')"
        X_ERR "an update to a DNSSEC type is refused" "check constraint" "UPDATE rr_policy_types SET type = 'DNSKEY' WHERE type = 'MX'"
    fi
    if [ "$P" = "karidns_auth." ]; then PT_COL=", allowed_types"; PT_VAL=", ARRAY['A']"; else PT_COL=""; PT_VAL=""; fi
    X_ERR "ttl_min above ttl_max is refused" "check constraint" "INSERT INTO ${P}rr_policies (name${PT_COL}, ttl_min, ttl_max) VALUES ('bad-ttl'${PT_VAL}, 100, 50)"
    X_ERR "a negative ttl_min is refused" "check constraint" "INSERT INTO ${P}rr_policies (name${PT_COL}, ttl_min) VALUES ('bad-neg'${PT_VAL}, -1)"
    X_ERR "a negative max_rr is refused" "check constraint" "INSERT INTO ${P}rr_policies (name${PT_COL}, max_rr) VALUES ('bad-max'${PT_VAL}, -1)"
    X_ERR "a policy name is unique" "unique" "INSERT INTO ${P}rr_policies (name${PT_COL}) VALUES ('web'${PT_VAL})"

    # ---- grants
    PW="(SELECT id FROM ${P}rr_policies WHERE name = 'web')"
    PA="(SELECT id FROM ${P}principals WHERE name = 'alice')"
    gins() { echo "INSERT INTO ${P}grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id) VALUES ($PA, $1)"; }
    ok "a global master (no scope)" "$(gins "'global_master', NULL, NULL, NULL, $PW")"
    ok "a domain master of a zone" "$(gins "'domain_master', $DS, 'example.com', NULL, $PW")"
    ok "a subdomain master: the suffix is a name below the zone" "$(gins "'subdomain_master', $DS, 'example.com', 'sub.example.com', $PW")"
    ok "a subdomain master: the suffix is the zone itself" "$(gins "'subdomain_master', $DS, 'example.com', 'example.com', $PW")"
    ok "a deeper suffix" "$(gins "'subdomain_master', $DS, 'example.com', 'a.b.sub.example.com', $PW")"
    ok "a 253 octet zone name" "$(gins "'domain_master', $DS, '$NAME253', NULL, $PW")"
    X_ERR "a role other than the three is refused" "check constraint" "$(gins "'owner', $DS, 'example.com', NULL, $PW")"
    X_ERR "a global master with a zone is refused" "grants_scope" "$(gins "'global_master', NULL, 'example.com', NULL, $PW")"
    X_ERR "a global master with a suffix is refused" "grants_scope" "$(gins "'global_master', NULL, NULL, 'example.com', $PW")"
    X_ERR "a domain master without a zone is refused" "grants_scope" "$(gins "'domain_master', $DS, NULL, NULL, $PW")"
    X_ERR "a domain master with a suffix is refused" "grants_scope" "$(gins "'domain_master', $DS, 'example.com', 'sub.example.com', $PW")"
    X_ERR "a subdomain master without a suffix is refused" "grants_scope" "$(gins "'subdomain_master', $DS, 'example.com', NULL, $PW")"
    X_ERR "a subdomain master without a zone is refused" "grants_scope" "$(gins "'subdomain_master', $DS, NULL, 'sub.example.com', $PW")"
    X_ERR "the suffix evilexample.com is not under example.com (label boundary)" "grants_suffix_under_zone" "$(gins "'subdomain_master', $DS, 'example.com', 'evilexample.com', $PW")"
    X_ERR "the suffix com is not under example.com" "grants_suffix_under_zone" "$(gins "'subdomain_master', $DS, 'example.com', 'com', $PW")"
    X_ERR "the suffix example.org is not under example.com" "grants_suffix_under_zone" "$(gins "'subdomain_master', $DS, 'example.com', 'x.example.org', $PW")"
    X_ERR "an upper case zone is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'Example.com', NULL, $PW")"
    X_ERR "a trailing dot is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'example.com.', NULL, $PW")"
    X_ERR "a leading dot is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, '.example.com', NULL, $PW")"
    X_ERR "an empty label is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a..example.com', NULL, $PW")"
    X_ERR "an empty zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, '', NULL, $PW")"
    if [ "$P" = "" ]; then CHRF=char; else CHRF=chr; fi
    X_ERR "a blank in the zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a b.example.com', NULL, $PW")"
    X_ERR "a tab in the zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a' || ${CHRF}(9) || 'b.example.com', NULL, $PW")"
    X_ERR "a control character (0x01) in the zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a' || ${CHRF}(1) || 'b.example.com', NULL, $PW")"
    X_ERR "DEL (0x7f) in the zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a' || ${CHRF}(127) || 'b.example.com', NULL, $PW")"
    X_ERR "a newline in the zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a' || ${CHRF}(10) || 'b.example.com', NULL, $PW")"
    X_ERR "a blank in the suffix is refused" "grants_suffix_canonical" "$(gins "'subdomain_master', $DS, 'example.com', 'a b.example.com', $PW")"
    X_ERR "a control character in the suffix is refused" "grants_suffix_canonical" "$(gins "'subdomain_master', $DS, 'example.com', 'a' || ${CHRF}(9) || 'b.example.com', $PW")"
    if [ "$P" = "" ]; then
        X_ERR "a NUL in the zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, 'a' || char(0) || 'b.example.com', NULL, $PW")"
    fi
    X_ERR "a 254 octet zone name is refused" "grants_zone_canonical" "$(gins "'domain_master', $DS, '$NAME254', NULL, $PW")"
    X_ERR "an upper case suffix is refused" "grants_suffix_canonical" "$(gins "'subdomain_master', $DS, 'example.com', 'Sub.example.com', $PW")"
    X_ERR "a suffix with a trailing dot is refused" "grants_suffix_canonical" "$(gins "'subdomain_master', $DS, 'example.com', 'sub.example.com.', $PW")"
    X_ERR "a suffix with an empty label is refused" "grants_suffix_canonical" "$(gins "'subdomain_master', $DS, 'example.com', 'a..example.com', $PW")"
    X_ERR "a grant needs an rr_policy that exists" "foreign key" "$(gins "'domain_master', $DS, 'nopolicy.example', NULL, 99999")"
    X_ERR "a grant needs a principal that exists" "foreign key" "INSERT INTO ${P}grants (principal_id, role, rr_policy_id) VALUES (99999, 'global_master', $PW)"
    X_ERR "a policy that a grant uses cannot be deleted" "foreign key" "DELETE FROM ${P}rr_policies WHERE name = 'web'"
    eq "six grants of alice" "6" "SELECT count(*) FROM ${P}grants WHERE principal_id = $PA"
    ok "deleting a principal deletes its grants" "INSERT INTO ${P}grants (principal_id, role, rr_policy_id) SELECT id, 'global_master', $PW FROM ${P}principals WHERE name = 'carol'; DELETE FROM ${P}principals WHERE name = 'carol'"
    eq "no grant of the deleted principal is left" "0" "SELECT count(*) FROM ${P}grants WHERE principal_id NOT IN (SELECT id FROM ${P}principals)"
    closure_check "the closure at the end of the shared cases"
}

# ================================================================ PostgreSQL
echo "== PostgreSQL"
if ! pg_setup auth > "$T/pgsetup.out"; then
    skip "$(sed 's/^SKIP: //' "$T/pgsetup.out")"
else
    cat "$T/pgsetup.out"
    pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > "$T/ext.out" 2>&1 || { fail "cannot create the schema"; cat "$T/ext.out"; }

    # psql with an error check
    pe() { out=$(psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "$3" 2>&1); rc=$?; if [ $rc -ne 0 ] && printf '%s\n' "$out" | grep -Eqi -- "$2"; then pass "$1"; else fail "$1 (exit $rc: $(printf '%s' "$out" | head -2))"; fi; }
    X_OK() { psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "$1" > "$T/x.out" 2>&1 || { head -3 "$T/x.out"; return 1; }; }
    X_ERR() { pe "$@"; }
    X_Q() { pq "$1" 2>&1; }
    P="karidns_auth."; DS="'public'"
    shared_cases

    # ---- the trigger on domains: a deleted zone takes its grants with it, a renamed zone keeps them
    echo "-- grants follow their zone"
    pq "CREATE SCHEMA oth" > /dev/null
    { echo "SET search_path TO oth;"; cat tests/db/pdns_schema.pgsql.sql db/karidns_ext.pgsql.sql; } > "$T/oth.sql"
    pf "$T/oth.sql" > /dev/null 2>&1 && pass "a second data schema applies the file (karidns_auth is shared)" || fail "the second data schema"
    [ "$(pq "SELECT count(*) FROM pg_namespace WHERE nspname = 'karidns_auth'")" = "1" ] && [ "$(pq "SELECT count(*) FROM karidns_auth.schema_version")" = "1" ] && pass "one karidns_auth for both schemas" || fail "karidns_auth is not shared"
    pq "INSERT INTO domains (name, type) VALUES ('example.com', 'NATIVE'), ('keep.test', 'NATIVE'), ('ren.test', 'NATIVE');
        INSERT INTO oth.domains (name, type) VALUES ('example.com', 'NATIVE');
        DELETE FROM karidns_auth.grants;
        INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id)
          SELECT (SELECT id FROM karidns_auth.principals WHERE name = 'alice'), v.role, v.ds, v.zone, v.suf, (SELECT id FROM karidns_auth.rr_policies WHERE name = 'web')
            FROM (VALUES ('global_master', NULL, NULL, NULL), ('domain_master', 'public', 'example.com', NULL), ('subdomain_master', 'public', 'example.com', 'a.sub.example.com'),
                         ('subdomain_master', 'public', 'example.com', 'example.com'), ('domain_master', 'oth', 'example.com', NULL), ('domain_master', 'public', 'keep.test', NULL),
                         ('subdomain_master', 'public', 'ren.test', 'x.ren.test'), ('domain_master', 'public', 'ren.test', NULL)) AS v(role, ds, zone, suf)" > /dev/null
    eq "eight grants" "8" "SELECT count(*) FROM karidns_auth.grants"
    pq "UPDATE domains SET type = 'MASTER' WHERE name = 'example.com'" > /dev/null
    eq "an UPDATE that keeps the name touches no grant" "8" "SELECT count(*) FROM karidns_auth.grants"
    pq "UPDATE domains SET name = 'renamed.test' WHERE name = 'ren.test'" > /dev/null
    eq "a rename moves the grants of the zone and its suffixes" "domain_master:renamed.test:|subdomain_master:renamed.test:x.renamed.test" \
       "SELECT string_agg(role || ':' || zone_name || ':' || coalesce(name_suffix, ''), '|' ORDER BY role) FROM karidns_auth.grants WHERE zone_name = 'renamed.test'"
    eq "nothing is left under the old name" "0" "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'ren.test' OR name_suffix LIKE '%ren.test'"
    pq "UPDATE domains SET name = 'deeper.renamed.test' WHERE name = 'renamed.test'" > /dev/null
    eq "a second rename: the grants follow, and the suffix keeps its label boundary" "2|x.deeper.renamed.test" "SELECT count(*) || '|' || max(name_suffix) FROM karidns_auth.grants WHERE zone_name = 'deeper.renamed.test'"
    pq "DELETE FROM domains WHERE name = 'example.com'" > /dev/null
    eq "deleting the zone deletes its grants (3 of public, not the one of oth, not the global master)" "5" "SELECT count(*) FROM karidns_auth.grants"
    eq "the grant on oth's example.com is still there" "1" "SELECT count(*) FROM karidns_auth.grants WHERE data_schema = 'oth' AND zone_name = 'example.com'"
    eq "the global master is still there" "1" "SELECT count(*) FROM karidns_auth.grants WHERE role = 'global_master'"
    pq "DELETE FROM oth.domains WHERE name = 'example.com'" > /dev/null
    eq "deleting oth's zone deletes oth's grant" "0" "SELECT count(*) FROM karidns_auth.grants WHERE data_schema = 'oth'"
    eq "enable_audit('oth') attaches the second data schema's 10 tables" "10" "SELECT karidns_auth.enable_audit('oth')"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO oth.domains (name, type) VALUES ('othaud.test', 'NATIVE');
        INSERT INTO oth.records (domain_id, name, type, content, ttl) SELECT id, 'a.othaud.test', 'A', '192.0.2.1', 60 FROM oth.domains WHERE name = 'othaud.test';
        INSERT INTO domains (name, type) VALUES ('pubaud.test', 'NATIVE')" > /dev/null
    eq "its rows are logged with data_schema oth and the zone; the audit of public is not on" "oth:domains:othaud.test|oth:records:othaud.test" "SELECT string_agg(data_schema || ':' || table_name || ':' || zone_name, '|' ORDER BY id) FROM karidns_auth.audit_log"
    eq "disable_audit('oth') takes it off again" "10" "SELECT karidns_auth.disable_audit('oth')"
    pq "DELETE FROM domains WHERE name = 'pubaud.test'; DELETE FROM karidns_auth.grants WHERE data_schema = 'oth'" > /dev/null
    eq "the grants of the other zones are still there (keep.test, the renamed zone)" "3" "SELECT count(*) FROM karidns_auth.grants WHERE zone_name IN ('keep.test', 'deeper.renamed.test')"
    pq "INSERT INTO domains (name, type) VALUES ('example.com', 'NATIVE')" > /dev/null
    eq "a new zone of a deleted zone's name has no grants" "0" "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'example.com'"
    pq "DROP SCHEMA oth CASCADE; DELETE FROM karidns_auth.grants; DELETE FROM domains" > /dev/null

    # ---- the audit: not attached by the file, attached by enable_audit
    echo "-- the audit log"
    eq "the file attached no audit trigger to the PowerDNS tables" "0" "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'karidns_audit%' AND tgrelid = 'domains'::regclass"
    pq "TRUNCATE karidns_auth.audit_log" > /dev/null
    pq "INSERT INTO domains (name, type) VALUES ('nolog.test', 'NATIVE'); DELETE FROM domains WHERE name = 'nolog.test'" > /dev/null
    eq "so a change of the PowerDNS tables is not logged" "0" "SELECT count(*) FROM karidns_auth.audit_log"
    eq "the audit of the karidns_auth tables is attached (5 tables)" "5" "SELECT count(*) FROM pg_trigger WHERE tgname = 'karidns_audit_row' AND tgrelid::regclass::text LIKE 'karidns_auth.%'"
    eq "enable_audit('public') attaches 10 tables (cryptokeys, the key requests and the signer state included)" "10" "SELECT karidns_auth.enable_audit('public')"
    eq "enable_audit is idempotent" "10" "SELECT karidns_auth.enable_audit('public')"
    eq "...with one row trigger, three statement triggers and the zone trigger on domains" "5" "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'karidns_audit%' AND tgrelid = 'domains'::regclass"
    eq "...and four on records" "4" "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'karidns_audit%' AND tgrelid = 'records'::regclass"
    eq "enable_audit of a schema that has no such tables attaches none" "0" "SELECT karidns_auth.enable_audit('pg_catalog_nosuch')"
    pq "TRUNCATE karidns_auth.audit_log" > /dev/null
    pq "SET LOCAL karidns.principal = '$(pid alice)'; SET LOCAL karidns.change_set = 'cs-42';
        INSERT INTO domains (name, type) VALUES ('aud.test', 'NATIVE');
        INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'www.aud.test', 'A', '192.0.2.1', 60 FROM domains WHERE name = 'aud.test';
        UPDATE records SET content = '192.0.2.2', ttl = 120 WHERE name = 'www.aud.test';
        DELETE FROM records WHERE name = 'www.aud.test'" > /dev/null
    eq "records: I, U, D in order, each with the zone (lower case)" "I:aud.test|U:aud.test|D:aud.test" "SELECT string_agg(op || ':' || zone_name, '|' ORDER BY id) FROM karidns_auth.audit_log WHERE table_name = 'records'"
    eq "INSERT: before NULL, after has the row" "true|192.0.2.1|www.aud.test" "SELECT (before IS NULL)::text || '|' || (after ->> 'content') || '|' || (after ->> 'name') FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'I'"
    eq "UPDATE: before and after" "192.0.2.1>192.0.2.2 60>120" "SELECT (before ->> 'content') || '>' || (after ->> 'content') || ' ' || (before ->> 'ttl') || '>' || (after ->> 'ttl') FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'U'"
    eq "DELETE: after NULL, before has the row" "true|192.0.2.2" "SELECT (after IS NULL)::text || '|' || (before ->> 'content') FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'D'"
    eq "row_id is the records.id of all three" "1" "SELECT count(DISTINCT row_id) FROM karidns_auth.audit_log WHERE table_name = 'records'"
    eq "domains: the INSERT names the zone in lower case" "I:aud.test" "SELECT op || ':' || zone_name FROM karidns_auth.audit_log WHERE table_name = 'domains'"
    eq "the principal and its name (copied) and the change set" "alice|cs-42" "SELECT DISTINCT principal_name || '|' || change_set FROM karidns_auth.audit_log WHERE table_name = 'records'"
    eq "the principal id is alice's" "$(pid alice)" "SELECT DISTINCT principal_id FROM karidns_auth.audit_log WHERE table_name = 'records'"
    eq "db_role is the role of the session" "$(pq "SELECT session_user")" "SELECT DISTINCT db_role FROM karidns_auth.audit_log"
    eq "data_schema and the xid8 of the transaction (one for all rows)" "public|1" "SELECT DISTINCT data_schema || '|' || (SELECT count(DISTINCT xid) FROM karidns_auth.audit_log) FROM karidns_auth.audit_log"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'x.aud.test', 'A', '192.0.2.5', 60 FROM domains WHERE name = 'aud.test'" > /dev/null
    eq "no principal and no change set in the session: NULL" "true|true" "SELECT (principal_id IS NULL)::text || '|' || (change_set IS NULL)::text FROM karidns_auth.audit_log WHERE table_name = 'records'"
    pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.principal = ''; SET LOCAL karidns.change_set = ''; UPDATE records SET ttl = 61 WHERE name = 'x.aud.test'" > /dev/null
    eq "an empty principal and change set count as none" "true|true" "SELECT (principal_id IS NULL)::text || '|' || (change_set IS NULL)::text FROM karidns_auth.audit_log WHERE table_name = 'records'"
    pe "a principal that is not a number stops the statement (the actor cannot be hidden)" "invalid input syntax" "SET LOCAL karidns.principal = 'alice'; UPDATE records SET ttl = 62 WHERE name = 'x.aud.test'"
    eq "...and nothing was changed" "61" "SELECT ttl FROM records WHERE name = 'x.aud.test'"
    # the other tables and the cascade of a zone delete
    pq "TRUNCATE karidns_auth.audit_log;
        INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'aud.test';
        INSERT INTO karidns_record_tags (record_id, location_tag) SELECT id, 'tokyo' FROM records WHERE name = 'x.aud.test';
        INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) SELECT id, 1, 'tk', false FROM records WHERE name = 'x.aud.test';
        INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) SELECT id, 'location', 'tokyo', '192.0.2.0/24' FROM domains WHERE name = 'aud.test';
        INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'internal' FROM domains WHERE name = 'aud.test'" > /dev/null
    eq "domainmetadata, tags, tinydns attributes, tag definitions and views are logged with the zone (the tags through the record)" \
       "domainmetadata:aud.test|karidns_domain_views:aud.test|karidns_record_tags:aud.test|karidns_record_tinydns:aud.test|karidns_zone_tagdefs:aud.test" \
       "SELECT string_agg(DISTINCT table_name || ':' || zone_name, '|' ORDER BY table_name || ':' || zone_name) FROM karidns_auth.audit_log"
    pq "TRUNCATE karidns_auth.audit_log; DELETE FROM domains WHERE name = 'aud.test'" > /dev/null
    eq "the cascade of a zone delete is logged with the name of the zone (the domains row is gone by then)" "domainmetadata|karidns_domain_views|karidns_zone_tagdefs|records" \
       "SELECT string_agg(DISTINCT table_name, '|' ORDER BY table_name) FROM karidns_auth.audit_log WHERE op = 'D' AND zone_name = 'aud.test' AND table_name <> 'domains'"
    eq "...except the tags and tinydns rows that go with their record: zone_name NULL (the record is gone by then)" "2|0" "SELECT (SELECT count(*) FROM karidns_auth.audit_log WHERE op = 'D' AND table_name IN ('karidns_record_tags', 'karidns_record_tinydns') AND zone_name IS NULL) || '|' || (SELECT count(*) FROM karidns_auth.audit_log WHERE op = 'D' AND table_name IN ('karidns_record_tags', 'karidns_record_tinydns') AND zone_name IS NOT NULL)"
    eq "...the D row of the record has the zone, and its row_id is the record_id of those rows" "aud.test|1" "SELECT r.zone_name || '|' || (SELECT count(DISTINCT t.row_id) FROM karidns_auth.audit_log t WHERE t.table_name = 'karidns_record_tags' AND t.row_id = r.row_id) FROM karidns_auth.audit_log r WHERE r.table_name = 'records' AND r.op = 'D' AND (r.before ->> 'name') = 'x.aud.test'"
    eq "...and the domains row itself" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE op = 'D' AND table_name = 'domains' AND zone_name = 'aud.test'"
    # redaction
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO domains (name, type) VALUES ('key.test', 'NATIVE');
        INSERT INTO cryptokeys (domain_id, flags, active, content) SELECT id, 257, true, 'Private-key-format: v1.2 SECRETKEYMATERIAL' FROM domains WHERE name = 'key.test'" > /dev/null
    eq "cryptokeys.content is written as <redacted>" "<redacted>|257" "SELECT (after ->> 'content') || '|' || (after ->> 'flags') FROM karidns_auth.audit_log WHERE table_name = 'cryptokeys'"
    pq "UPDATE cryptokeys SET content = 'ANOTHERSECRET', active = false; DELETE FROM cryptokeys" > /dev/null
    eq "...also in UPDATE and DELETE" "0" "SELECT count(*) FROM karidns_auth.audit_log WHERE (coalesce(before::text, '') || coalesce(after::text, '')) LIKE '%SECRET%'"
    eq "...and the log still says what happened" "<redacted>|<redacted>" "SELECT (before ->> 'content') || '|' || (after ->> 'content') FROM karidns_auth.audit_log WHERE table_name = 'cryptokeys' AND op = 'U'"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO karidns_auth.principals (kind, name) VALUES ('user', 'sec');
        INSERT INTO karidns_auth.credentials (principal_id, password_hash, totp_secret, oidc_issuer, oidc_subject) SELECT id, '$HASH_A', 'TOTPSECRETBASE32', 'iss', 'sub-sec' FROM karidns_auth.principals WHERE name = 'sec';
        UPDATE karidns_auth.credentials SET totp_secret = 'NEWTOTPSECRET', password_hash = '$HASH_S' WHERE oidc_subject = 'sub-sec'" > /dev/null
    eq "credentials: the password hash and the TOTP secret are redacted, the rest is not" "<redacted>|<redacted>|sub-sec" \
       "SELECT (after ->> 'password_hash') || '|' || (after ->> 'totp_secret') || '|' || (after ->> 'oidc_subject') FROM karidns_auth.audit_log WHERE table_name = 'credentials' AND op = 'I'"
    eq "...in UPDATE too, and no secret anywhere in the log" "0" "SELECT count(*) FROM karidns_auth.audit_log WHERE (coalesce(before::text, '') || coalesce(after::text, '')) ~ 'TOTP|argon2|scrypt'"
    eq "the other karidns_auth tables are logged (principals I)" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'principals' AND op = 'I' AND data_schema = 'karidns_auth'"
    pq "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) SELECT p.id, 'domain_master', 'public', 'grantlog.test', r.id FROM karidns_auth.principals p, karidns_auth.rr_policies r WHERE p.name = 'sec' AND r.name = 'web'" > /dev/null
    eq "the audit row of a grant carries zone_name" "grantlog.test" "SELECT zone_name FROM karidns_auth.audit_log WHERE table_name = 'grants' AND op = 'I'"
    pq "DELETE FROM karidns_auth.principals WHERE name = 'sec'" > /dev/null
    eq "the log keeps the rows of a deleted principal (principal_name is a copy)" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'principals' AND op = 'D' AND (before ->> 'name') = 'sec'"

    # ---- disable_audit
    eq "disable_audit('public') takes it off the 10 tables" "10" "SELECT karidns_auth.disable_audit('public')"
    eq "...no audit trigger is left on the PowerDNS tables" "0" "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'karidns_audit%' AND tgrelid = 'domains'::regclass"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO domains (name, type) VALUES ('off.test', 'NATIVE'); DELETE FROM domains WHERE name = 'off.test'" > /dev/null
    eq "so nothing is logged again" "0" "SELECT count(*) FROM karidns_auth.audit_log"
    pq "SELECT karidns_auth.enable_audit('public')" > /dev/null

    # ---- the tables of the signer (item C): karidns_key_requests, karidns_signer_state
    echo "-- the signer tables"
    pq "DELETE FROM domains; TRUNCATE karidns_auth.audit_log; INSERT INTO domains (name, type) VALUES ('sig.test', 'NATIVE'), ('sig2.test', 'NATIVE')" > /dev/null
    SD=$(pq "SELECT id FROM domains WHERE name = 'sig.test'")
    SD2=$(pq "SELECT id FROM domains WHERE name = 'sig2.test'")
    X_OK "INSERT INTO karidns_key_requests (domain_id) VALUES ($SD)" && pass "a key request with the defaults (enable, 13, csk, pending)" || fail "key request defaults"
    eq "...the defaults are kind enable, algorithm 13, key type csk, state pending, no nsec, no done_at" "enable|13|csk|pending||true" \
       "SELECT kind || '|' || algorithm || '|' || key_type || '|' || state || '|' || coalesce(nsec, '') || '|' || (done_at IS NULL AND created_at IS NOT NULL) FROM karidns_key_requests"
    X_ERR "a second pending request for a zone is refused (one open request per zone)" "unique|duplicate" "INSERT INTO karidns_key_requests (domain_id, kind) VALUES ($SD, 'add')"
    pq "UPDATE karidns_key_requests SET state = 'done', done_at = now() WHERE domain_id = $SD" > /dev/null
    ok "an add request with RSA and bits (the first one is done)" "INSERT INTO karidns_key_requests (domain_id, kind, algorithm, bits, key_type) VALUES ($SD, 'add', 8, 2048, 'zsk')"
    X_ERR "...and again one pending request per zone" "unique|duplicate" "INSERT INTO karidns_key_requests (domain_id, algorithm) VALUES ($SD, 8)"
    ok "an enable request with NSEC" "INSERT INTO karidns_key_requests (domain_id, algorithm, nsec) VALUES ($SD2, 15, 'nsec')"
    X_ERR "a kind other than enable / add is refused" "check constraint" "INSERT INTO karidns_key_requests (domain_id, kind) VALUES ($SD, 'roll')"
    X_ERR "an algorithm the signer does not sign with (RSASHA1, 5) is refused" "check constraint" "INSERT INTO karidns_key_requests (domain_id, algorithm) VALUES ($SD, 5)"
    X_ERR "bits only for RSA" "check constraint" "INSERT INTO karidns_key_requests (domain_id, algorithm, bits) VALUES ($SD, 13, 2048)"
    X_ERR "bits under 1024" "check constraint" "INSERT INTO karidns_key_requests (domain_id, algorithm, bits) VALUES ($SD, 8, 512)"
    X_ERR "a key type other than csk / ksk / zsk" "check constraint" "INSERT INTO karidns_key_requests (domain_id, key_type) VALUES ($SD, 'kzk')"
    X_ERR "nsec only nsec3 or nsec" "check constraint" "INSERT INTO karidns_key_requests (domain_id, nsec) VALUES ($SD, 'nsec5')"
    X_ERR "nsec only for an enable request" "check constraint" "INSERT INTO karidns_key_requests (domain_id, kind, nsec) VALUES ($SD, 'add', 'nsec3')"
    X_ERR "a state other than pending / done / failed" "check constraint" "INSERT INTO karidns_key_requests (domain_id, state, done_at) VALUES ($SD, 'running', now())"
    X_ERR "a pending request has no done_at" "check constraint" "INSERT INTO karidns_key_requests (domain_id, done_at) VALUES ($SD, now())"
    X_ERR "a request that is done has a done_at" "check constraint" "INSERT INTO karidns_key_requests (domain_id, state) VALUES ($SD, 'done')"
    ok "...and a failed one with a message" "INSERT INTO karidns_key_requests (domain_id, state, message, done_at) VALUES ($SD, 'failed', 'dnssec-keygen failed', now())"
    X_ERR "a request for a zone that does not exist" "foreign key" "INSERT INTO karidns_key_requests (domain_id) VALUES (999999)"
    eq "the key requests have an index on the zone, one on the pending ones and the unique one (one pending request per zone)" "karidns_key_requests_domain_idx|karidns_key_requests_one_pending_idx|karidns_key_requests_pending_idx" \
       "SELECT string_agg(indexname, '|' ORDER BY indexname) FROM pg_indexes WHERE tablename = 'karidns_key_requests' AND indexname LIKE 'karidns_key_requests_%' AND indexname <> 'karidns_key_requests_pkey'"
    ok "the signer state of a zone" "INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts, last_duration_ms) VALUES ($SD, now(), 11, now() + interval '14 days', now() + interval '10 days', 0, 1500)"
    eq "...next_due and attempts have defaults" "true|0" "SELECT (next_due IS NOT NULL) || '|' || attempts FROM karidns_signer_state WHERE domain_id = $SD"
    X_ERR "one state row per zone" "unique|duplicate|primary" "INSERT INTO karidns_signer_state (domain_id) VALUES ($SD)"
    X_ERR "a serial over 32 bits is refused" "check constraint" "INSERT INTO karidns_signer_state (domain_id, signed_serial) VALUES ($SD2, 4294967296)"
    X_ERR "a negative attempts count is refused" "check constraint" "INSERT INTO karidns_signer_state (domain_id, attempts) VALUES ($SD2, -1)"
    X_ERR "a state row of a zone that does not exist" "foreign key" "INSERT INTO karidns_signer_state (domain_id) VALUES (999999)"
    eq "the state table has the index on next_due" "karidns_signer_state_due_idx" "SELECT indexname FROM pg_indexes WHERE tablename = 'karidns_signer_state' AND indexname = 'karidns_signer_state_due_idx'"

    eq "the audit of the two tables is on: the inserts above were logged with the zone" "karidns_key_requests:sig.test|karidns_key_requests:sig2.test|karidns_signer_state:sig.test" \
       "SELECT string_agg(DISTINCT table_name || ':' || zone_name, '|') FROM karidns_auth.audit_log WHERE table_name IN ('karidns_key_requests', 'karidns_signer_state')"
    eq "...an UPDATE of the state is logged with before and after" "11>12" "UPDATE karidns_signer_state SET signed_serial = 12 WHERE domain_id = $SD; SELECT (before ->> 'signed_serial') || '>' || (after ->> 'signed_serial') FROM karidns_auth.audit_log WHERE table_name = 'karidns_signer_state' AND op = 'U'"
    eq "neither table writes the change log (the signer would follow its own state)" "0" "SELECT count(*) FROM pg_trigger WHERE tgrelid IN ('karidns_key_requests'::regclass, 'karidns_signer_state'::regclass) AND tgname LIKE 'karidns_trg_%'"
    pq "DELETE FROM karidns_changes" > /dev/null
    pq "UPDATE karidns_signer_state SET attempts = 1 WHERE domain_id = $SD; UPDATE karidns_key_requests SET state = 'done', done_at = now() WHERE domain_id = $SD AND state = 'pending'" > /dev/null
    eq "...an UPDATE of either table leaves the change log as it is" "0" "SELECT count(*) FROM karidns_changes"
    pq "DELETE FROM domains WHERE name = 'sig.test'" > /dev/null
    eq "deleting the zone deletes its key requests and its state row (ON DELETE CASCADE)" "1|0" "SELECT (SELECT count(*) FROM karidns_key_requests) || '|' || (SELECT count(*) FROM karidns_signer_state)"
    pq "DELETE FROM domains; TRUNCATE karidns_auth.audit_log" > /dev/null

    # ---- summary mode
    echo "-- summary mode"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO domains (name, type) VALUES ('sum.test', 'NATIVE')" > /dev/null
    pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.audit = 'summary';
        INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'h' || g || '.sum.test', 'A', '192.0.2.1', 60 FROM domains, generate_series(1, 100) g WHERE name = 'sum.test';
        INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'z.sum.test', 'A', '192.0.2.2', 60 FROM domains WHERE name = 'sum.test';
        UPDATE records SET ttl = 90 WHERE domain_id = (SELECT id FROM domains WHERE name = 'sum.test');
        DELETE FROM records WHERE name LIKE 'h1%.sum.test'" > /dev/null
    eq "summary: one row per table, operation and zone: I, U, D" "D:sum.test|I:sum.test|U:sum.test" "SELECT string_agg(op || ':' || zone_name, '|' ORDER BY op) FROM karidns_auth.audit_log WHERE table_name = 'records'"
    eq "...INSERT counted 2 statements and 101 rows" "2/101" "SELECT (after ->> 'statements') || '/' || (after ->> 'rows') FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'I'"
    eq "...UPDATE 1 statement, 101 rows; before and after both say so" "1/101/1/101" "SELECT (before ->> 'statements') || '/' || (before ->> 'rows') || '/' || (after ->> 'statements') || '/' || (after ->> 'rows') FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'U'"
    eq "...DELETE counted 12 rows (h1, h10..h19, h100) and has no after" "12/true" "SELECT (before ->> 'rows') || '/' || (after IS NULL)::text FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'D'"
    eq "...no row-level row was written (every row says summary)" "0" "SELECT count(*) FROM karidns_auth.audit_log WHERE coalesce(after, before) ->> 'summary' IS DISTINCT FROM 'true'"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO domains (name, type) VALUES ('sumdel.test', 'NATIVE');
        INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'a.sumdel.test', 'A', '192.0.2.1', 60 FROM domains WHERE name = 'sumdel.test';
        INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'sumdel.test';
        INSERT INTO karidns_record_tags (record_id, location_tag) SELECT id, 'x' FROM records WHERE name = 'a.sumdel.test'" > /dev/null
    pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.audit = 'summary'; DELETE FROM domains WHERE name = 'sumdel.test'" > /dev/null
    eq "summary: the rows of a zone delete and of its cascade name the zone" "domainmetadata:sumdel.test|domains:sumdel.test|records:sumdel.test" "SELECT string_agg(table_name || ':' || zone_name, '|' ORDER BY table_name) FROM karidns_auth.audit_log WHERE op = 'D' AND zone_name IS NOT NULL"
    eq "...except the tags that go with their record: zone_name NULL (documented)" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'karidns_record_tags' AND op = 'D' AND zone_name IS NULL"
    pq "TRUNCATE karidns_auth.audit_log; INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'after.sum.test', 'A', '192.0.2.9', 60 FROM domains WHERE name = 'sum.test'" > /dev/null
    eq "without the setting (or in the next transaction) rows are logged again" "t" "SELECT (after ->> 'summary') IS NULL FROM karidns_auth.audit_log WHERE table_name = 'records'"
    pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.audit = 'rows'; INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'rows.sum.test', 'A', '192.0.2.9', 60 FROM domains WHERE name = 'sum.test'" > /dev/null
    eq "karidns.audit = rows is the same as unset" "t" "SELECT (after ->> 'summary') IS NULL FROM karidns_auth.audit_log WHERE table_name = 'records'"
    pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.audit = 'summary'; UPDATE records SET ttl = 5 WHERE name = 'nosuchname.sum.test'; DELETE FROM records WHERE name = 'nosuchname.sum.test'" > /dev/null
    eq "a summary statement that changed no row is not logged" "0" "SELECT count(*) FROM karidns_auth.audit_log"
    pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.audit = 'summary'; INSERT INTO karidns_auth.principals (kind, name) VALUES ('group', 'sumgrp')" > /dev/null
    eq "the karidns_auth tables are always logged row by row" "t" "SELECT (after ->> 'summary') IS NULL FROM karidns_auth.audit_log WHERE table_name = 'principals'"
    pq "DELETE FROM karidns_auth.principals WHERE name = 'sumgrp'" > /dev/null

    # roles (cluster wide: created here, dropped at the end)
    mkrole() { if psql -X -q -d "$PGMAINT" -c "CREATE ROLE $1 NOLOGIN" > /dev/null 2>&1; then ROLES="$ROLES $1"; return 0; fi; [ "$(psql -X -q -At -d "$PGMAINT" -c "SELECT count(*) FROM pg_roles WHERE rolname = '$1'")" = "1" ]; }
    grant_data() { pq "GRANT ALL ON ALL TABLES IN SCHEMA public TO $1; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO $1" > /dev/null; }
    if mkrole karidns_api && grant_data karidns_api && pq "SET ROLE karidns_api; SELECT 1" > /dev/null 2>&1; then
        pq "TRUNCATE karidns_auth.audit_log; SET LOCAL ROLE karidns_api; SET LOCAL karidns.audit = 'summary';
            INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'h' || g || '.api.test', 'A', '192.0.2.1', 60 FROM domains, generate_series(1, 5) g WHERE name = 'sum.test'" > /dev/null
        eq "summary is ignored for a role named karidns_api (5 rows logged one by one, db_role karidns_api)" "5|karidns_api" "SELECT count(*) || '|' || min(db_role) FROM karidns_auth.audit_log WHERE table_name = 'records' AND (after ->> 'summary') IS NULL"
        pq "TRUNCATE karidns_auth.audit_log; SET LOCAL karidns.audit = 'summary';
            INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'h' || g || '.own.test', 'A', '192.0.2.1', 60 FROM domains, generate_series(1, 5) g WHERE name = 'sum.test'" > /dev/null
        eq "...the owner's own transaction in summary mode is one row" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'records'"
        if mkrole karidns_signer && grant_data karidns_signer; then
            pq "TRUNCATE karidns_auth.audit_log; SET LOCAL ROLE karidns_signer; SET LOCAL karidns.audit = 'summary'; INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'h' || g || '.sig.test', 'A', '192.0.2.1', 60 FROM domains, generate_series(1, 3) g WHERE name = 'sum.test'" > /dev/null
            eq "...but the signer (a trusted daemon, not in audit_restricted_roles) may: karidns-zone import --signer writes a zone in one summary row" "1|karidns_signer" "SELECT count(*) || '|' || min(db_role) FROM karidns_auth.audit_log WHERE table_name = 'records' AND (after ->> 'summary') IS NOT NULL"
        fi
    else
        skip "cannot create (or SET ROLE to) a role named karidns_api: the summary override is not tested"
    fi

    # the restricted roles are a table; the login role and the SET ROLE role count, with every role they are members of
    mkrolel() { if psql -X -q -d "$PGMAINT" -c "CREATE ROLE $1 LOGIN" > /dev/null 2>&1; then ROLES="$ROLES $1"; return 0; fi; return 1; }
    LM=karidns_t_lm_$$; OT=karidns_t_ot_$$; CU=karidns_t_cu_$$
    if mkrole karidns_api && mkrolel $LM && mkrolel $OT && mkrolel $CU && grant_data $LM && grant_data $OT && grant_data $CU &&
       pq "GRANT karidns_api TO $LM; GRANT $OT TO $LM; GRANT $CU TO $LM" > /dev/null 2>&1 && pq "SET SESSION AUTHORIZATION $LM; SELECT 1" > /dev/null 2>&1; then
        eq "audit_restricted_roles is seeded with karidns_api (only the WebAdmin's role is restricted)" "karidns_api" "SELECT string_agg(role_name, '|' ORDER BY role_name) FROM karidns_auth.audit_restricted_roles"
        RINS="INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'h' || g || '.rr.test', 'A', '192.0.2.1', 60 FROM domains, generate_series(1, 3) g WHERE name = 'sum.test'"

        pq "TRUNCATE karidns_auth.audit_log; SET SESSION AUTHORIZATION $LM; SET karidns.audit = 'summary'; $RINS" > /dev/null
        eq "a login role that is a member of karidns_api cannot turn the detail off (3 rows, not 1)" "3" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'records' AND (after ->> 'summary') IS NULL"
        pq "TRUNCATE karidns_auth.audit_log; SET SESSION AUTHORIZATION $LM; SET ROLE $OT; SET karidns.audit = 'summary'; $RINS" > /dev/null
        eq "...nor by SET ROLE to a role that is not restricted (the login role counts)" "3|$OT" "SELECT count(*) || '|' || min(db_role) FROM karidns_auth.audit_log WHERE table_name = 'records' AND (after ->> 'summary') IS NULL"
        pq "TRUNCATE karidns_auth.audit_log; SET ROLE $CU; SET karidns.audit = 'summary'; $RINS" > /dev/null
        eq "a role that is in no restricted role's closure may use summary (1 row)" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'records'"
        pq "INSERT INTO karidns_auth.audit_restricted_roles (role_name) VALUES ('$CU')" > /dev/null
        pq "TRUNCATE karidns_auth.audit_log; SET ROLE $CU; SET karidns.audit = 'summary'; $RINS" > /dev/null
        eq "a role added to audit_restricted_roles cannot (3 rows)" "3|$CU" "SELECT count(*) || '|' || min(db_role) FROM karidns_auth.audit_log WHERE table_name = 'records' AND (after ->> 'summary') IS NULL"
        pq "DELETE FROM karidns_auth.audit_restricted_roles WHERE role_name = '$CU'; TRUNCATE karidns_auth.audit_log; SET ROLE $CU; SET karidns.audit = 'summary'; $RINS" > /dev/null
        eq "...and when the row is removed it can again (1 row)" "1" "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'records'"
    else
        skip "cannot create the login roles or SET SESSION AUTHORIZATION: the restricted-roles cases are not tested"
    fi

    # memberships change only in READ COMMITTED; kind changes and credentials take the membership lock
    MI="INSERT INTO karidns_auth.memberships (member_id, group_id) SELECT m.id, g.id FROM karidns_auth.principals m, karidns_auth.principals g WHERE m.name = 'alice' AND g.name = 'other'"
    pe "a membership insert in a REPEATABLE READ transaction is refused, with the reason" "READ COMMITTED" "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; $MI"
    pe "...in a SERIALIZABLE transaction too" "READ COMMITTED" "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; $MI"
    pe "a membership delete in a REPEATABLE READ transaction is refused" "READ COMMITTED" "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; DELETE FROM karidns_auth.memberships WHERE member_id = (SELECT id FROM karidns_auth.principals WHERE name = 'alice') AND group_id = (SELECT id FROM karidns_auth.principals WHERE name = 'eng')"
    eq "...and nothing changed" "0|1" "SELECT (SELECT count(*) FROM karidns_auth.memberships m JOIN karidns_auth.principals g ON g.id = m.group_id JOIN karidns_auth.principals u ON u.id = m.member_id WHERE g.name = 'other' AND u.name = 'alice') || '|' || (SELECT count(*) FROM karidns_auth.memberships m JOIN karidns_auth.principals g ON g.id = m.group_id JOIN karidns_auth.principals u ON u.id = m.member_id WHERE g.name = 'eng' AND u.name = 'alice')"
    ok "in READ COMMITTED (the default) the same insert works" "$MI; DELETE FROM karidns_auth.memberships WHERE group_id = (SELECT id FROM karidns_auth.principals WHERE name = 'other') AND member_id = (SELECT id FROM karidns_auth.principals WHERE name = 'alice')"
    pq "INSERT INTO karidns_auth.principals (kind, name) VALUES ('group', 'kinder')" > /dev/null
    got=$(pq "UPDATE karidns_auth.principals SET kind = 'user' WHERE name = 'kinder'; UPDATE karidns_auth.principals SET kind = 'group' WHERE name = 'kinder'; SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()" | tail -1)
    [ "$got" -ge 1 ] 2> /dev/null && pass "a change of kind holds the advisory lock of the membership triggers until the end of the transaction" || fail "the kind change takes no advisory lock ('$got')"
    got=$(pq "INSERT INTO karidns_auth.principals (kind, name) VALUES ('user', 'locky'); INSERT INTO karidns_auth.credentials (principal_id) SELECT id FROM karidns_auth.principals WHERE name = 'locky'; SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()" | tail -1)
    [ "$got" -ge 1 ] 2> /dev/null && pass "an INSERT into credentials holds it too" || fail "the credentials trigger takes no advisory lock ('$got')"
    pq "DELETE FROM karidns_auth.principals WHERE name IN ('locky', 'kinder')" > /dev/null

    # append only, and a writer with no right on karidns_auth
    WR=karidns_t_aw_$$
    if mkrole "$WR" && grant_data "$WR"; then
        pq "TRUNCATE karidns_auth.audit_log; INSERT INTO domains (name, type) VALUES ('wr.test', 'NATIVE')" > /dev/null
        pq "INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) SELECT p.id, 'domain_master', 'public', 'wr.test', r.id FROM karidns_auth.principals p, karidns_auth.rr_policies r WHERE p.name = 'alice' AND r.name = 'web'" > /dev/null
        pq "SET LOCAL ROLE $WR; INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'a.wr.test', 'A', '192.0.2.1', 60 FROM domains WHERE name = 'wr.test'" > /dev/null 2>&1 &&
            pass "a role with no right on karidns_auth can change the data (the triggers are SECURITY DEFINER)" || fail "the writer role cannot write"
        eq "...its change is in the audit log under its name" "$WR" "SELECT db_role FROM karidns_auth.audit_log WHERE table_name = 'records' AND zone_name = 'wr.test'"
        pe "without USAGE the writer cannot see karidns_auth at all (the schema's denial)" "permission denied for schema" "SET ROLE $WR; SELECT * FROM karidns_auth.audit_log"
        pe "...nor insert" "permission denied for schema" "SET ROLE $WR; INSERT INTO karidns_auth.audit_log (data_schema, table_name, op) VALUES ('public', 'records', 'I')"
        pq "GRANT USAGE ON SCHEMA karidns_auth TO $WR; GRANT SELECT ON karidns_auth.audit_log TO $WR" > /dev/null
        X_OK "SET ROLE $WR; SELECT count(*) FROM karidns_auth.audit_log" && pass "(with USAGE and SELECT granted) the role can read the log" || fail "the role cannot read the log with SELECT"
        pe "the writer cannot call the trigger function to forge a row" "permission denied for function .*audit_row" "SET ROLE $WR; SELECT karidns_auth.audit_row()"
        pe "UPDATE of the audit log is refused even with USAGE and SELECT (the table's denial)" "permission denied for table audit_log" "SET ROLE $WR; UPDATE karidns_auth.audit_log SET table_name = 'x'"
        pe "DELETE from the audit log is refused" "permission denied for table audit_log" "SET ROLE $WR; DELETE FROM karidns_auth.audit_log"
        pe "INSERT into the audit log is refused" "permission denied for table audit_log" "SET ROLE $WR; INSERT INTO karidns_auth.audit_log (data_schema, table_name, op) VALUES ('public', 'records', 'I')"
        pe "TRUNCATE of the audit log is refused" "permission denied for table audit_log" "SET ROLE $WR; TRUNCATE karidns_auth.audit_log"
        pe "the table of restricted roles is the owner's too" "permission denied for table audit_restricted_roles" "SET ROLE $WR; SELECT * FROM karidns_auth.audit_restricted_roles"
        pe "a role with USAGE cannot attach the audit function to a table of its own" "permission denied for function .*audit_row" "SET ROLE $WR; CREATE TEMP TABLE tt (x int); CREATE TRIGGER tx AFTER INSERT ON tt FOR EACH ROW EXECUTE FUNCTION karidns_auth.audit_row()"
        pe "...nor a statement trigger function" "permission denied for function .*audit_stmt" "SET ROLE $WR; CREATE TEMP TABLE tt2 (x int); CREATE TRIGGER tx AFTER INSERT ON tt2 REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION karidns_auth.audit_stmt()"
        pe "...nor call enable_audit" "permission denied for function .*enable_audit" "SET ROLE $WR; SELECT karidns_auth.enable_audit('public')"
        pe "...nor disable_audit" "permission denied for function .*disable_audit" "SET ROLE $WR; SELECT karidns_auth.disable_audit('public')"
        pe "...nor a trigger function of the closure" "permission denied for function .*memberships_closure_fn" "SET ROLE $WR; CREATE TEMP TABLE tt3 (x int); CREATE TRIGGER tx AFTER INSERT ON tt3 FOR EACH ROW EXECUTE FUNCTION karidns_auth.memberships_closure_fn()"
        # the functions that CHECK constraints call keep their PUBLIC right: a non-owner can insert rows that pass the CHECKs
        pq "GRANT SELECT ON karidns_auth.principals TO $WR; GRANT INSERT, SELECT ON karidns_auth.rr_policies, karidns_auth.grants TO $WR; GRANT USAGE ON SEQUENCE karidns_auth.rr_policies_id_seq, karidns_auth.grants_id_seq TO $WR" > /dev/null
        X_OK "SET ROLE $WR; INSERT INTO karidns_auth.rr_policies (name, allowed_types) VALUES ('nonowner', ARRAY['A', 'TXT'])" && pass "a non-owner can insert an rr_policy (the CHECK calls rr_types_ok)" || fail "a non-owner cannot insert an rr_policy"
        X_OK "SET ROLE $WR; INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) SELECT p.id, 'domain_master', 'public', 'nonowner.test', r.id FROM karidns_auth.principals p, karidns_auth.rr_policies r WHERE p.name = 'alice' AND r.name = 'nonowner'" &&
            pass "...and a grant (the CHECK calls is_canonical_name)" || fail "a non-owner cannot insert a grant"
        pe "...and the CHECKs still refuse what they must" "grants_zone_canonical" "SET ROLE $WR; INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id) VALUES (1, 'domain_master', 'public', 'Bad.Test', 1)"
        pq "DELETE FROM karidns_auth.grants WHERE zone_name = 'nonowner.test'; DELETE FROM karidns_auth.rr_policies WHERE name = 'nonowner'" > /dev/null
        eq "nothing was granted on the audit log (or its sequence) to PUBLIC" "0|0" "SELECT (SELECT count(*) FROM pg_class c, aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a WHERE c.oid = 'karidns_auth.audit_log'::regclass AND a.grantee = 0) || '|' || (SELECT count(*) FROM pg_class c, aclexplode(coalesce(c.relacl, acldefault('S', c.relowner))) a WHERE c.oid = 'karidns_auth.audit_log_id_seq'::regclass AND a.grantee = 0)"
        eq "the role granted above holds SELECT and nothing else on it" "SELECT" "SELECT string_agg(a.privilege_type, ',' ORDER BY a.privilege_type) FROM pg_class c, aclexplode(c.relacl) a WHERE c.oid = 'karidns_auth.audit_log'::regclass AND a.grantee = '$WR'::regrole"
        # the trigger on domains runs for a role that cannot see karidns_auth
        pq "REVOKE ALL ON SCHEMA karidns_auth FROM $WR" > /dev/null
        pq "SET LOCAL ROLE $WR; DELETE FROM domains WHERE name = 'wr.test'" > /dev/null 2>&1 && pass "a role with no right on karidns_auth can delete a zone" || fail "the writer cannot delete a zone"
        eq "...and the grants of the zone went with it (the DEFINER trigger on domains)" "0" "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'wr.test'"
    else
        skip "cannot create a role: the append-only and the writer cases are not tested"
    fi
    pq "DELETE FROM domains" > /dev/null

    # ---- karidns-zone --audit
    echo "-- karidns-zone --audit"
    if [ ! -x "$ZONE_BIN" ]; then
        skip "$ZONE_BIN is not built"
    elif ! "$ZONE_BIN" --version | grep -q postgresql; then
        skip "karidns-zone has no PostgreSQL driver"
    else
        Z=$T/karidns-zone
        cp "$ZONE_BIN" "$Z" && chmod 755 "$Z"
        pq "DELETE FROM domains; SELECT karidns_auth.disable_audit('public'); TRUNCATE karidns_auth.audit_log" > /dev/null
        pg_conninfo_file "$T/ci"
        mkdir "$T/in" && chmod 755 "$T/in"
        for n in one two; do
            cat > "$T/in/$n.test.zone" <<EOF
\$ORIGIN $n.test.
\$TTL 3600
@ IN SOA ns1.$n.test. hostmaster.$n.test. 1 7200 3600 1209600 300
@ IN NS ns1.$n.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
mail IN A 192.0.2.3
EOF
        done
        chmod 644 "$T"/in/*
        zt() { as_pg "$Z" "$@" --no-config --conninfo-file "$T/ci" > "$T/zt.out" 2> "$T/zt.err" < /dev/null; st=$?; }
        zt import one.test "$T/in/one.test.zone"
        [ "$st" = "0" ] && pass "import without audit triggers (nothing to log into)" || { fail "import: exit $st"; head -3 "$T/zt.err"; }
        eq "no audit row (the triggers are not attached)" "0" "SELECT count(*) FROM karidns_auth.audit_log"
        pq "DELETE FROM domains; SELECT karidns_auth.enable_audit('public')" > /dev/null
        pq "TRUNCATE karidns_auth.audit_log" > /dev/null
        zt import one.test "$T/in/one.test.zone"
        [ "$st" = "0" ] && pass "import (default: --audit rows)" || { fail "import: exit $st"; head -3 "$T/zt.err"; }
        NREC=$(pq "SELECT count(*) FROM records")
        eq "rows: one audit row per record ($NREC), db_role the user of the tool" "$NREC|$(pq "SELECT session_user")" "SELECT count(*) || '|' || min(db_role) FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'I' AND zone_name = 'one.test' AND (after ->> 'summary') IS NULL"
        pq "TRUNCATE karidns_auth.audit_log" > /dev/null
        zt import --audit summary two.test "$T/in/two.test.zone"
        [ "$st" = "0" ] && pass "import --audit summary" || { fail "import --audit summary: exit $st"; head -3 "$T/zt.err"; }
        eq "summary: one row for the records of the zone: all $NREC rows in $NREC statements" "1|$NREC/$NREC" "SELECT count(*) || '|' || min((after ->> 'statements') || '/' || (after ->> 'rows')) FROM karidns_auth.audit_log WHERE table_name = 'records' AND op = 'I' AND zone_name = 'two.test'"
        eq "summary: the domains INSERT is one summary row; no row-level row was written" "1|0" "SELECT (SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'domains' AND op = 'I' AND (after ->> 'rows') = '1') || '|' || (SELECT count(*) FROM karidns_auth.audit_log WHERE (coalesce(after, before) ->> 'summary') IS DISTINCT FROM 'true')"
        pq "TRUNCATE karidns_auth.audit_log" > /dev/null
        sed 's/192.0.2.2/192.0.2.22/; s/ 1 7200/ 2 7200/' "$T/in/two.test.zone" > "$T/in/two2.zone"; chmod 644 "$T/in/two2.zone"
        zt import --audit summary two.test "$T/in/two2.zone"
        [ "$st" = "0" ] && pass "a replace with --audit summary (changed RRsets only)" || { fail "replace: exit $st"; head -3 "$T/zt.err"; }
        eq "...its audit rows are all summary rows" "0" "SELECT count(*) FROM karidns_auth.audit_log WHERE (coalesce(after, before) ->> 'summary') IS DISTINCT FROM 'true'"
        eq "...and there are some" "t" "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE table_name = 'records'"
        zt import --audit rows two.test "$T/in/two.test.zone" --serial keep
        [ "$st" = "0" ] && pass "import --audit rows (explicit)" || { fail "--audit rows: exit $st"; head -3 "$T/zt.err"; }
        zt import --audit bogus two.test "$T/in/two.test.zone"
        [ "$st" = "2" ] && grep -q "audit must be rows or summary" "$T/zt.err" && pass "--audit bogus is a usage error (exit 2)" || fail "--audit bogus: exit $st: $(head -1 "$T/zt.err")"
        zt export --audit rows two.test
        [ "$st" = "2" ] && grep -q "options of import" "$T/zt.err" && pass "--audit is an option of import: export refuses it (exit 2)" || fail "export --audit: exit $st: $(head -1 "$T/zt.err")"
        zt import --audit two.test "$T/in/two.test.zone"
        [ "$st" = "2" ] && pass "--audit needs a value (exit 2)" || fail "--audit without a value: exit $st"
        zt import --dry-run --audit summary --serial keep two.test "$T/in/two.test.zone"
        [ "$st" = "0" ] && pass "--dry-run --audit summary works" || fail "dry run: exit $st"
        "$Z" --help 2>&1 | grep -q -- "--audit rows|summary" && pass "the usage text names --audit" || fail "usage text"
    fi
fi

# ================================================================ SQLite3
echo "== SQLite3"
if ! command -v sqlite3 >/dev/null 2>&1; then
    skip "the sqlite3 command line tool is not installed"
else
    SCHEMA=tests/db/pdns_schema.sqlite3.sql
    # ---- the auth file
    AUTHDB=$T/auth.db
    sqlite3 "$AUTHDB" < db/karidns_auth.sqlite3.sql > "$T/a1.out" 2>&1 && sqlite3 "$AUTHDB" < db/karidns_auth.sqlite3.sql > "$T/a2.out" 2>&1 && pass "the auth file applies, twice" || { fail "the auth file: $(head -2 "$T/a1.out" "$T/a2.out")"; }
    [ "$(sqlite3 "$AUTHDB" "SELECT count(*) || '|' || max(version) FROM schema_version")" = "1|3" ] && pass "the auth file has its own version row: 3" || fail "the version row of the auth file"
    X_OK() { sqlite3 "$AUTHDB" "PRAGMA foreign_keys = ON;" "$1" > "$T/x.out" 2>&1 || { head -3 "$T/x.out"; return 1; }; }
    X_ERR() { out=$(sqlite3 "$AUTHDB" "PRAGMA foreign_keys = ON;" "$3" 2>&1); rc=$?; if [ $rc -ne 0 ] && printf '%s\n' "$out" | grep -Eqi -- "$2"; then pass "$1"; else fail "$1 (exit $rc: $(printf '%s' "$out" | head -2))"; fi; }
    X_Q() { sqlite3 "$AUTHDB" "PRAGMA foreign_keys = ON;" "$1" 2>&1; }
    P=""; DS="NULL"
    shared_cases
    # the actor and the audit of the auth file
    echo "-- the audit of the auth file"
    sqlite3 "$AUTHDB" "DELETE FROM karidns_auth_audit"
    sqlite3 "$AUTHDB" "PRAGMA foreign_keys = ON; INSERT INTO karidns_auth_actor (id, principal_id, principal_name, change_set, db_role) VALUES (1, 7, 'admin', 'cs-9', 'api');
        INSERT INTO principals (kind, name) VALUES ('user', 'zed');
        INSERT INTO credentials (principal_id, password_hash, totp_secret) SELECT id, '$HASH_A', 'TOTPSECRETBASE32' FROM principals WHERE name = 'zed';
        UPDATE credentials SET totp_secret = 'NEWTOTPSECRET' WHERE principal_id = (SELECT id FROM principals WHERE name = 'zed');
        DELETE FROM karidns_auth_actor"
    [ "$(sqlite3 "$AUTHDB" "SELECT group_concat(table_name || ':' || op, ',') FROM (SELECT * FROM karidns_auth_audit ORDER BY id)")" = "principals:I,credentials:I,credentials:U" ] && pass "the auth file's audit: principals I, credentials I and U" || fail "auth audit rows: $(sqlite3 "$AUTHDB" "SELECT group_concat(table_name || op) FROM karidns_auth_audit")"
    [ "$(sqlite3 "$AUTHDB" "SELECT DISTINCT principal_id || '|' || principal_name || '|' || change_set || '|' || db_role FROM karidns_auth_audit")" = "7|admin|cs-9|api" ] && pass "...with the actor of karidns_auth_actor" || fail "auth audit actor"
    [ "$(sqlite3 "$AUTHDB" "SELECT count(*) FROM karidns_auth_audit WHERE coalesce(before, '') || coalesce(after, '') GLOB '*TOTP*' OR coalesce(before, '') || coalesce(after, '') GLOB '*argon2*'")" = "0" ] && pass "...and no secret in it" || fail "secrets in the auth audit"
    [ "$(sqlite3 "$AUTHDB" "SELECT json_extract(after, '\$.password_hash') || '|' || json_extract(after, '\$.totp_secret') FROM karidns_auth_audit WHERE table_name = 'credentials' AND op = 'I'")" = "<redacted>|<redacted>" ] && pass "password_hash and totp_secret are written as <redacted>" || fail "redaction in the auth audit"
    sqlite3 "$AUTHDB" "INSERT INTO karidns_auth_actor (id) VALUES (1)"
    sqlite3 "$AUTHDB" "INSERT INTO karidns_auth_actor (id) VALUES (2)" 2> /dev/null && fail "a second actor row was accepted" || pass "karidns_auth_actor holds one row at most"
    sqlite3 "$AUTHDB" "DELETE FROM karidns_auth_actor"
    # foreign keys off: the delete trigger of principals does the cascades itself
    sqlite3 "$AUTHDB" "INSERT INTO principals (kind, name) VALUES ('group', 'fkoff'), ('user', 'fkuser');
        INSERT INTO memberships (member_id, group_id) SELECT u.id, g.id FROM principals u, principals g WHERE u.name = 'fkuser' AND g.name = 'fkoff';
        INSERT INTO credentials (principal_id) SELECT id FROM principals WHERE name = 'fkuser';
        INSERT INTO grants (principal_id, role, rr_policy_id) SELECT u.id, 'global_master', (SELECT min(id) FROM rr_policies) FROM principals u WHERE u.name = 'fkuser'"
    sqlite3 "$AUTHDB" "PRAGMA foreign_keys = OFF; DELETE FROM principals WHERE name = 'fkoff'; DELETE FROM principals WHERE name = 'fkuser'"
    [ "$(sqlite3 "$AUTHDB" "SELECT (SELECT count(*) FROM memberships WHERE member_id NOT IN (SELECT id FROM principals) OR group_id NOT IN (SELECT id FROM principals)) || (SELECT count(*) FROM credentials WHERE principal_id NOT IN (SELECT id FROM principals)) || (SELECT count(*) FROM grants WHERE principal_id NOT IN (SELECT id FROM principals)) || (SELECT count(*) FROM principal_closure WHERE member_id NOT IN (SELECT id FROM principals) OR group_id NOT IN (SELECT id FROM principals))")" = "0000" ] &&
        pass "with foreign keys off the principals delete trigger removes memberships, credentials, grants and closure rows" || fail "the delete trigger with foreign keys off"
    closure_check "the closure after the deletes with foreign keys off"

    # ---- the zone file: audit tables, audit triggers, the actor
    echo "-- the zone file"
    ZDB=$T/zone.db
    # the test schema has no foreign keys on records, domainmetadata and cryptokeys (PowerDNS's own has ON DELETE CASCADE): add them
    sed 's/^  domain_id             INTEGER DEFAULT NULL,/  domain_id             INTEGER DEFAULT NULL REFERENCES domains(id) ON DELETE CASCADE,/; s/^  domain_id             INT NOT NULL,/  domain_id             INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,/' "$SCHEMA" > "$T/schema_fk.sql"
    [ "$(grep -c 'ON DELETE CASCADE' "$T/schema_fk.sql")" = "3" ] || fail "the foreign keys were not added to the test schema"
    sqlite3 "$ZDB" < "$T/schema_fk.sql" > /dev/null
    sqlite3 "$ZDB" < db/karidns_ext.sqlite3.sql && pass "the ext file (version 3) applies" || fail "the ext file"
    [ "$(sqlite3 "$ZDB" "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'karidns_audit%'")" = "0" ] && pass "the ext file creates no audit trigger" || fail "audit triggers in the ext file"
    sqlite3 "$ZDB" "INSERT INTO domains (name, type) VALUES ('plain.test', 'NATIVE'); DELETE FROM domains"
    [ "$(sqlite3 "$ZDB" "SELECT count(*) FROM karidns_audit_log")" = "0" ] && pass "so nothing is logged before the audit file is applied" || fail "log without triggers"
    sqlite3 "$ZDB" < db/karidns_audit.sqlite3.sql && sqlite3 "$ZDB" < db/karidns_audit.sqlite3.sql && pass "the audit file applies, twice" || fail "the audit file"
    [ "$(sqlite3 "$ZDB" "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'karidns_audit%'")" = "30" ] && pass "30 audit triggers (10 tables x I / U / D)" || fail "audit trigger count $(sqlite3 "$ZDB" "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'karidns_audit%'")"
    sqz() { sqlite3 "$ZDB" "PRAGMA foreign_keys = ON;" "$1" 2>&1; }
    ZQ() { sqlite3 "$ZDB" "$1" 2>&1; }
    zeq() { got=$(ZQ "$3"); if [ "$got" = "$2" ]; then pass "$1"; else fail "$1: got '$got', wanted '$2'"; fi; }
    sqz "INSERT INTO karidns_audit_actor (id, principal_id, principal_name, change_set, db_role) VALUES (1, 3, 'bob', 'cs-1', 'api');
         INSERT INTO domains (name, type) VALUES ('aud.test', 'NATIVE');
         INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'www.aud.test', 'A', '192.0.2.1', 60 FROM domains WHERE name = 'aud.test';
         UPDATE records SET content = '192.0.2.2', ttl = 120 WHERE name = 'www.aud.test';
         DELETE FROM records WHERE name = 'www.aud.test';
         DELETE FROM karidns_audit_actor" > /dev/null
    zeq "records: I, U, D with the zone in lower case" "I:aud.test|U:aud.test|D:aud.test" "SELECT group_concat(op || ':' || zone_name, '|') FROM (SELECT * FROM karidns_audit_log WHERE table_name = 'records' ORDER BY id)"
    zeq "INSERT: before NULL, after has the row" "1|192.0.2.1" "SELECT (before IS NULL) || '|' || json_extract(after, '\$.content') FROM karidns_audit_log WHERE table_name = 'records' AND op = 'I'"
    zeq "UPDATE: before and after" "192.0.2.1>192.0.2.2 60>120" "SELECT json_extract(before, '\$.content') || '>' || json_extract(after, '\$.content') || ' ' || json_extract(before, '\$.ttl') || '>' || json_extract(after, '\$.ttl') FROM karidns_audit_log WHERE table_name = 'records' AND op = 'U'"
    zeq "DELETE: after NULL" "1|192.0.2.2" "SELECT (after IS NULL) || '|' || json_extract(before, '\$.content') FROM karidns_audit_log WHERE table_name = 'records' AND op = 'D'"
    zeq "the actor: principal, name, change set and role of the actor row" "3|bob|cs-1|api" "SELECT DISTINCT principal_id || '|' || principal_name || '|' || change_set || '|' || db_role FROM karidns_audit_log"
    zeq "row_id is the records.id" "1" "SELECT count(DISTINCT row_id) FROM karidns_audit_log WHERE table_name = 'records'"
    zeq "a time and data_schema main" "main|1" "SELECT DISTINCT data_schema || '|' || (at LIKE '20__-__-__T__:__:__Z') FROM karidns_audit_log"
    sqz "DELETE FROM karidns_audit_log; INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'noactor.aud.test', 'A', '192.0.2.5', 60 FROM domains WHERE name = 'aud.test'" > /dev/null
    zeq "no actor row: all four columns NULL" "1" "SELECT principal_id IS NULL AND principal_name IS NULL AND change_set IS NULL AND db_role IS NULL FROM karidns_audit_log WHERE table_name = 'records'"
    sqz "DELETE FROM karidns_audit_log;
         INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'aud.test';
         INSERT INTO karidns_record_tags (record_id, location_tag) SELECT id, 'tokyo' FROM records WHERE name = 'noactor.aud.test';
         INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) SELECT id, 1, 'tk', 0 FROM records WHERE name = 'noactor.aud.test';
         INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) SELECT id, 'location', 'tokyo', '192.0.2.0/24' FROM domains WHERE name = 'aud.test';
         INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'internal' FROM domains WHERE name = 'aud.test'" > /dev/null
    zeq "domainmetadata, tags, tinydns attributes, tag definitions and views are logged with the zone" \
        "domainmetadata:aud.test|karidns_domain_views:aud.test|karidns_record_tags:aud.test|karidns_record_tinydns:aud.test|karidns_zone_tagdefs:aud.test" \
        "SELECT group_concat(x, '|') FROM (SELECT DISTINCT table_name || ':' || zone_name AS x FROM karidns_audit_log ORDER BY 1)"
    sqz "DELETE FROM karidns_audit_log; DELETE FROM domains WHERE name = 'aud.test'" > /dev/null
    zeq "the cascade of a zone delete is logged with the name of the zone (the children are deleted before the domains AFTER trigger would run)" "domainmetadata|domains|karidns_domain_views|karidns_zone_tagdefs|records" \
        "SELECT group_concat(t, '|') FROM (SELECT DISTINCT table_name AS t FROM karidns_audit_log WHERE op = 'D' AND zone_name = 'aud.test' ORDER BY 1)"
    zeq "...except the tags and tinydns rows that go with their record: zone_name NULL (the record is gone by then)" "2|0" "SELECT (SELECT count(*) FROM karidns_audit_log WHERE op = 'D' AND table_name IN ('karidns_record_tags', 'karidns_record_tinydns') AND zone_name IS NULL) || '|' || (SELECT count(*) FROM karidns_audit_log WHERE op = 'D' AND table_name IN ('karidns_record_tags', 'karidns_record_tinydns') AND zone_name IS NOT NULL)"
    zeq "...the D row of the record has the zone, and its row_id is the record_id of those rows" "aud.test|1" "SELECT r.zone_name || '|' || (SELECT count(DISTINCT t.row_id) FROM karidns_audit_log t WHERE t.table_name = 'karidns_record_tags' AND t.row_id = r.row_id) FROM karidns_audit_log r WHERE r.table_name = 'records' AND r.op = 'D' AND json_extract(r.before, '\$.name') = 'noactor.aud.test'"
    # the tables of the signer (item C): the same CHECKs as on PostgreSQL, the cascade, the audit with the actor, no change log row
    echo "-- the signer tables"
    sqz "DELETE FROM karidns_audit_log; INSERT INTO domains (name, type) VALUES ('sigz.test', 'NATIVE'), ('sigz2.test', 'NATIVE')" > /dev/null
    SZ=$(ZQ "SELECT id FROM domains WHERE name = 'sigz.test'")
    SZ2=$(ZQ "SELECT id FROM domains WHERE name = 'sigz2.test'")
    ZINS() { if out=$(sqz "$1" 2>&1); then fail "$2: accepted"; else case $out in *"CHECK constraint"*|*"FOREIGN KEY"*|*UNIQUE*|*"constraint failed"*) pass "$2" ;; *) fail "$2: $out" ;; esac; fi; }
    sqz "INSERT INTO karidns_key_requests (domain_id) VALUES ($SZ)" > /dev/null
    zeq "a key request with the defaults (enable, 13, csk, pending)" "enable|13|csk|pending||1" "SELECT kind || '|' || algorithm || '|' || key_type || '|' || state || '|' || coalesce(nsec, '') || '|' || (done_at IS NULL AND created_at > 1700000000) FROM karidns_key_requests"
    ZINS "INSERT INTO karidns_key_requests (domain_id, kind) VALUES ($SZ, 'add')" "a second pending request for a zone is refused (one open request per zone)"
    sqz "UPDATE karidns_key_requests SET state = 'done', done_at = 5 WHERE domain_id = $SZ" > /dev/null
    sqz "INSERT INTO karidns_key_requests (domain_id, kind, algorithm, bits, key_type) VALUES ($SZ, 'add', 8, 2048, 'zsk'); INSERT INTO karidns_key_requests (domain_id, algorithm, nsec) VALUES ($SZ2, 15, 'nsec')" > /dev/null
    ZINS "INSERT INTO karidns_key_requests (domain_id, algorithm) VALUES ($SZ, 8)" "...and again one pending request per zone"
    zeq "an add request with RSA bits and an enable request with NSEC" "3" "SELECT count(*) FROM karidns_key_requests"
    ZINS "INSERT INTO karidns_key_requests (domain_id, kind) VALUES ($SZ, 'roll')" "a kind other than enable / add is refused"
    ZINS "INSERT INTO karidns_key_requests (domain_id, algorithm) VALUES ($SZ, 5)" "an algorithm the signer does not sign with is refused"
    ZINS "INSERT INTO karidns_key_requests (domain_id, algorithm, bits) VALUES ($SZ, 13, 2048)" "bits only for RSA"
    ZINS "INSERT INTO karidns_key_requests (domain_id, algorithm, bits) VALUES ($SZ, 8, 512)" "bits under 1024"
    ZINS "INSERT INTO karidns_key_requests (domain_id, key_type) VALUES ($SZ, 'kzk')" "a key type other than csk / ksk / zsk"
    ZINS "INSERT INTO karidns_key_requests (domain_id, kind, nsec) VALUES ($SZ, 'add', 'nsec3')" "nsec only for an enable request"
    ZINS "INSERT INTO karidns_key_requests (domain_id, done_at) VALUES ($SZ, 1)" "a pending request has no done_at"
    ZINS "INSERT INTO karidns_key_requests (domain_id, state) VALUES ($SZ, 'done')" "a request that is done has a done_at"
    ZINS "INSERT INTO karidns_key_requests (domain_id) VALUES (999999)" "a request for a zone that does not exist"
    sqz "INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts) VALUES ($SZ, 1, 11, 2, 3, 0)" > /dev/null
    ZINS "INSERT INTO karidns_signer_state (domain_id) VALUES ($SZ)" "one state row per zone"
    ZINS "INSERT INTO karidns_signer_state (domain_id, signed_serial) VALUES ($SZ2, 4294967296)" "a serial over 32 bits is refused"
    ZINS "INSERT INTO karidns_signer_state (domain_id, attempts) VALUES ($SZ2, -1)" "a negative attempts count is refused"
    zeq "the indexes: requests by zone, pending, one pending per zone; the state by next_due" "karidns_key_requests_domain_idx|karidns_key_requests_one_pending_idx|karidns_key_requests_pending_idx|karidns_signer_state_due_idx" "SELECT group_concat(name, '|') FROM (SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('karidns_key_requests_domain_idx', 'karidns_key_requests_one_pending_idx', 'karidns_key_requests_pending_idx', 'karidns_signer_state_due_idx') ORDER BY name)"
    ZP=$(sqlite3 "$ZDB" "EXPLAIN QUERY PLAN SELECT domain_id FROM karidns_signer_state WHERE next_due <= 100 ORDER BY next_due LIMIT 10")
    case $ZP in *karidns_signer_state_due_idx*) pass "the due zones are found by the index" ;; *) fail "the due query does not use the index: $ZP" ;; esac
    zeq "the audit of the two tables is on: the inserts were logged with the zone" "karidns_key_requests:sigz.test|karidns_key_requests:sigz2.test|karidns_signer_state:sigz.test" "SELECT group_concat(x, '|') FROM (SELECT DISTINCT table_name || ':' || zone_name AS x FROM karidns_audit_log WHERE table_name IN ('karidns_key_requests', 'karidns_signer_state') ORDER BY 1)"
    sqz "UPDATE karidns_signer_state SET signed_serial = 12 WHERE domain_id = $SZ" > /dev/null
    zeq "...an UPDATE of the state is logged with before and after" "11>12" "SELECT json_extract(before, '\$.signed_serial') || '>' || json_extract(after, '\$.signed_serial') FROM karidns_audit_log WHERE table_name = 'karidns_signer_state' AND op = 'U'"
    zeq "...and the key request's columns are in the JSON" "enable|13|csk" "SELECT json_extract(after, '\$.kind') || '|' || json_extract(after, '\$.algorithm') || '|' || json_extract(after, '\$.key_type') FROM karidns_audit_log WHERE table_name = 'karidns_key_requests' AND op = 'I' ORDER BY id LIMIT 1"
    zeq "neither table writes the change log" "0" "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name IN ('karidns_key_requests', 'karidns_signer_state') AND name LIKE 'karidns_trg_%'"
    CL0=$(ZQ "SELECT coalesce(max(seq), 0) FROM karidns_changes")
    sqz "UPDATE karidns_signer_state SET attempts = 1 WHERE domain_id = $SZ; UPDATE karidns_key_requests SET state = 'done', done_at = 5 WHERE domain_id = $SZ AND state = 'pending'" > /dev/null
    zeq "...an UPDATE of either table leaves the change log as it is" "$CL0" "SELECT coalesce(max(seq), 0) FROM karidns_changes"
    sqz "DELETE FROM domains WHERE name = 'sigz.test'" > /dev/null
    zeq "deleting the zone deletes its key requests and its state row (foreign keys on)" "1|0" "SELECT (SELECT count(*) FROM karidns_key_requests) || '|' || (SELECT count(*) FROM karidns_signer_state)"
    sqz "DELETE FROM domains WHERE name = 'sigz2.test'; DELETE FROM karidns_audit_log" > /dev/null

    # a zone of 20000 records is deleted in a time that does not grow with the square of its size (the lookup of the zone's name is an index seek)
    zeq "the lookup of a deleted zone's name uses the partial index" "1" "SELECT count(*) > 0 FROM pragma_index_list('karidns_audit_log') WHERE name = 'karidns_audit_log_zdel_idx' AND partial = 1"
    ZP=$(sqlite3 "$ZDB" "EXPLAIN QUERY PLAN SELECT zone_name FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'D' AND row_id = 1 ORDER BY id DESC LIMIT 1")
    case $ZP in *karidns_audit_log_zdel_idx*) pass "EXPLAIN QUERY PLAN: $(printf '%s' "$ZP" | tr '\n' ' ')" ;; *) fail "the lookup does not use the index: $ZP" ;; esac
    sqlite3 "$ZDB" "INSERT INTO domains (name, type) VALUES ('big.test', 'NATIVE');
        WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 20000)
        INSERT INTO records (domain_id, name, type, content, ttl) SELECT (SELECT id FROM domains WHERE name = 'big.test'), 'h' || n || '.big.test', 'A', '192.0.2.1', 60 FROM c"
    T0=$(date +%s)
    sqz "DELETE FROM domains WHERE name = 'big.test'" > /dev/null
    T1=$(date +%s)
    [ $((T1 - T0)) -lt 30 ] && pass "deleting a zone of 20000 records took $((T1 - T0)) s (under 30)" || fail "deleting a zone of 20000 records took $((T1 - T0)) s"
    zeq "...and every record has its D row with the zone name" "20000" "SELECT count(*) FROM karidns_audit_log WHERE table_name = 'records' AND op = 'D' AND zone_name = 'big.test'"
    sqz "DELETE FROM karidns_audit_log" > /dev/null
    sqz "DELETE FROM karidns_audit_log; INSERT INTO domains (name, type) VALUES ('key.test', 'NATIVE');
         INSERT INTO cryptokeys (domain_id, flags, active, content) SELECT id, 257, 1, 'Private-key-format: v1.2 SECRETKEYMATERIAL' FROM domains WHERE name = 'key.test';
         UPDATE cryptokeys SET content = 'ANOTHERSECRET'; DELETE FROM cryptokeys" > /dev/null
    zeq "cryptokeys.content is written as <redacted> (I, U, D) and no secret is in the log" "<redacted>|0" "SELECT json_extract(after, '\$.content') || '|' || (SELECT count(*) FROM karidns_audit_log WHERE coalesce(before, '') || coalesce(after, '') LIKE '%SECRET%') FROM karidns_audit_log WHERE table_name = 'cryptokeys' AND op = 'I'"
    zeq "...the other columns are kept" "257" "SELECT json_extract(after, '\$.flags') FROM karidns_audit_log WHERE table_name = 'cryptokeys' AND op = 'I'"
    sqz "DELETE FROM karidns_audit_log; UPDATE domains SET name = 'Renamed.Test' WHERE name = 'key.test'" > /dev/null
    zeq "a rename is an UPDATE of domains with the new name as the zone" "U:renamed.test" "SELECT op || ':' || zone_name FROM karidns_audit_log WHERE table_name = 'domains'"
    sqz "DELETE FROM domains; DELETE FROM karidns_audit_log" > /dev/null

    # ---- the audit file on a version 2 zone file (no audit tables) creates them; a changed trigger body reaches an existing database
    V2A=$T/v2audit.db
    sqlite3 "$V2A" < "$T/schema_fk.sql" > /dev/null && sqlite3 "$V2A" < db/karidns_ext.sqlite3.sql && sqlite3 "$V2A" "DROP TABLE karidns_audit_log; DROP TABLE karidns_audit_actor; UPDATE karidns_schema_version SET version = 2"
    sqlite3 "$V2A" < db/karidns_audit.sqlite3.sql && pass "the audit file applies to a version 2 zone file" || fail "the audit file on a version 2 zone file"
    [ "$(sqlite3 "$V2A" "SELECT count(*) FROM sqlite_master WHERE name IN ('karidns_audit_log', 'karidns_audit_actor', 'karidns_audit_log_zdel_idx', 'karidns_audit_log_zone_idx', 'karidns_audit_log_principal_idx', 'karidns_audit_log_change_set_idx')")" = "6" ] &&
        pass "...it created the two tables and their four indexes" || fail "tables or indexes missing after the audit file on a version 2 file"
    sqlite3 "$V2A" "PRAGMA foreign_keys = ON; INSERT INTO domains (name, type) VALUES ('v2a.test', 'NATIVE'); INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'a.v2a.test', 'A', '192.0.2.1', 60 FROM domains;
        UPDATE records SET ttl = 61; DELETE FROM domains" > "$T/v2a.out" 2>&1 && [ "$(sqlite3 "$V2A" "SELECT group_concat(table_name || op) FROM (SELECT * FROM karidns_audit_log ORDER BY id)")" = "domainsI,recordsI,recordsU,domainsD,recordsD" ] &&
        pass "...and the writes of that file work and are logged" || { fail "writes after the audit file on a version 2 file: $(head -2 "$T/v2a.out")"; }
    [ "$(sqlite3 "$V2A" "SELECT version FROM karidns_schema_version")" = "2" ] && pass "...the audit file does not change the version row (the ext file does)" || fail "version row after the audit file"
    sqlite3 "$V2A" "DROP TRIGGER karidns_audit_records_ins; CREATE TRIGGER karidns_audit_records_ins AFTER INSERT ON records BEGIN SELECT 1; END; DELETE FROM karidns_audit_log"
    sqlite3 "$V2A" < db/karidns_audit.sqlite3.sql && sqlite3 "$V2A" "INSERT INTO domains (name, type) VALUES ('v2b.test', 'NATIVE'); INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'a.v2b.test', 'A', '192.0.2.1', 60 FROM domains" &&
        [ "$(sqlite3 "$V2A" "SELECT count(*) FROM karidns_audit_log WHERE table_name = 'records' AND op = 'I'")" = "1" ] && pass "applying the audit file again replaces a trigger whose body differs" || fail "the audit file left an old trigger body"
    sqlite3 "$AUTHDB" "DROP TRIGGER karidns_memberships_no_update; CREATE TRIGGER karidns_memberships_no_update BEFORE UPDATE ON memberships BEGIN SELECT 1; END"
    sqlite3 "$AUTHDB" < db/karidns_auth.sqlite3.sql && [ "$(sqlite3 "$AUTHDB" "SELECT sql LIKE '%cannot be updated%' FROM sqlite_master WHERE name = 'karidns_memberships_no_update'")" = "1" ] && pass "applying the auth file again replaces a trigger whose body differs" || fail "the auth file left an old trigger body"

    # ---- karidns-zone on SQLite3
    echo "-- karidns-zone --audit (SQLite3)"
    if [ ! -x "$ZONE_BIN" ]; then
        skip "$ZONE_BIN is not built"
    elif ! "$ZONE_BIN" --version | grep -q sqlite3; then
        skip "karidns-zone has no SQLite3 driver"
    else
        # a database of its own for the tool: nothing left from the cases above
        ZDB=$T/tool.db
        sqlite3 "$ZDB" < "$SCHEMA" > /dev/null && sqlite3 "$ZDB" < db/karidns_ext.sqlite3.sql && sqlite3 "$ZDB" < db/karidns_audit.sqlite3.sql || fail "cannot create the database for karidns-zone"
        mkdir -p "$T/sin"
        for n in one two; do
            cat > "$T/sin/$n.test.zone" <<EOF
\$ORIGIN $n.test.
\$TTL 3600
@ IN SOA ns1.$n.test. hostmaster.$n.test. 1 7200 3600 1209600 300
@ IN NS ns1.$n.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
mail IN A 192.0.2.3
EOF
        done
        ME=$(id -un)
        szt() { "$ZONE_BIN" "$@" --no-config --sqlite3 "$ZDB" > "$T/szt.out" 2> "$T/szt.err" < /dev/null; st=$?; }
        szt import one.test "$T/sin/one.test.zone"
        [ "$st" = "0" ] && pass "karidns-zone import into a database with the audit triggers" || { fail "import: exit $st"; head -3 "$T/szt.err"; }
        NREC=$(ZQ "SELECT count(*) FROM records")
        zeq "every audit row names the tool and the OS user (karidns-zone:$ME)" "$NREC|karidns-zone:$ME|1" "SELECT count(*) || '|' || min(db_role) || '|' || count(DISTINCT db_role) FROM karidns_audit_log WHERE table_name = 'records'"
        zeq "...with no principal" "1" "SELECT count(*) = 0 FROM karidns_audit_log WHERE principal_id IS NOT NULL"
        zeq "...the domains INSERT is logged under it too" "karidns-zone:$ME" "SELECT db_role FROM karidns_audit_log WHERE table_name = 'domains' AND op = 'I'"
        zeq "the actor row is deleted before the commit" "0" "SELECT count(*) FROM karidns_audit_actor"
        sqz "DELETE FROM karidns_audit_log" > /dev/null
        szt import --audit summary two.test "$T/sin/two.test.zone"
        [ "$st" = "0" ] && pass "--audit summary is accepted on SQLite3 (the log has rows only)" || { fail "--audit summary: exit $st"; head -3 "$T/szt.err"; }
        zeq "...it writes the actor row all the same" "$NREC|karidns-zone:$ME" "SELECT count(*) || '|' || min(db_role) FROM karidns_audit_log WHERE table_name = 'records'"
        szt import --audit bogus two.test "$T/sin/two.test.zone"
        [ "$st" = "2" ] && pass "--audit bogus is a usage error (exit 2)" || fail "--audit bogus: exit $st"
        # a dry run and a failed import leave no actor row and no log row
        sqz "DELETE FROM karidns_audit_log" > /dev/null
        sed 's/192.0.2.2/192.0.2.99/; s/ 1 7200/ 2 7200/' "$T/sin/one.test.zone" > "$T/sin/one2.zone"
        szt import --dry-run one.test "$T/sin/one2.zone"
        zeq "a dry run: no actor row, no audit row" "0|0" "SELECT (SELECT count(*) FROM karidns_audit_actor) || '|' || (SELECT count(*) FROM karidns_audit_log)"
        printf '$ORIGIN one.test.\nwww IN A 192.0.2.7\n' > "$T/sin/bad.zone"
        szt import one.test "$T/sin/bad.zone"
        [ "$st" = "1" ] && pass "an import that fails (no SOA) exits 1" || fail "bad zone: exit $st"
        zeq "...it leaves no actor row and no audit row" "0|0" "SELECT (SELECT count(*) FROM karidns_audit_actor) || '|' || (SELECT count(*) FROM karidns_audit_log)"
        # a stale actor row of a crashed writer is replaced
        sqz "INSERT INTO karidns_audit_actor (id, db_role) VALUES (1, 'stale')" > /dev/null
        szt import one.test "$T/sin/one2.zone"
        zeq "a stale actor row is replaced by the tool's and deleted at the end" "0|karidns-zone:$ME" "SELECT (SELECT count(*) FROM karidns_audit_actor) || '|' || (SELECT DISTINCT db_role FROM karidns_audit_log)"
        # a database without the audit tables (schema version 2): nothing to write, nothing fails
        V2DB=$T/v2.db
        sqlite3 "$V2DB" < "$SCHEMA" > /dev/null
        sqlite3 "$V2DB" < db/karidns_ext.sqlite3.sql && sqlite3 "$V2DB" "DROP TABLE karidns_audit_log; DROP TABLE karidns_audit_actor; UPDATE karidns_schema_version SET version = 2"
        "$ZONE_BIN" import --no-config --sqlite3 "$V2DB" one.test "$T/sin/one.test.zone" > "$T/szt.out" 2> "$T/szt.err" < /dev/null; st=$?
        [ "$st" = "0" ] && [ "$(sqlite3 "$V2DB" "SELECT count(*) FROM records")" = "$NREC" ] && pass "a version 2 database (no karidns_audit_actor) imports as before" || { fail "version 2 database: exit $st"; head -3 "$T/szt.err"; }
    fi
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_auth_schema_test: all $PASS checks passed ($SKIPS skipped) ==="; exit 0; fi
echo "=== run_db_auth_schema_test: $FAILS check(s) FAILED ($PASS passed, $SKIPS skipped) ==="
exit 1

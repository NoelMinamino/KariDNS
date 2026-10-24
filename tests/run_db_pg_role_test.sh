#!/bin/sh
# run_db_pg_role_test.sh - the loader role of a PostgreSQL deployment (db/karidns_loader_role.pgsql.sql; beta design 2.2, D11;
# milestone B10): the loader reads everything it needs with SELECT on the PowerDNS tables and the karidns_* tables and the COLUMN
# privilege SELECT (domain_id, active, published) on cryptokeys, and nothing else.
#
# A role karidns_test_ro_<pid> (LOGIN, a random password, connection over TCP 127.0.0.1 with scram/md5) gets the script; then:
#   - karidns-dbloader --dump with that role writes the same bytes as the dump with the owner's rights, for a database with a signed
#     (PRESIGNED + cryptokeys) zone, tags, tinydns, profile, views: zones_with_keys works with only the column privilege;
#   - the role can read cryptokeys.domain_id but not cryptokeys.content (the private key), cannot INSERT / UPDATE / DELETE,
#     and its sessions are read only by default (default_transaction_read_only);
#   - without the column privilege on cryptokeys the dump fails (exit 3) and the message says permission denied;
#   - a conninfo-file with a wrong mode is refused before it is read; a file with the right mode but a bad password gives a
#     retry-able error (exit 4) whose message does not contain the password.
# SKIP (exit 0, with the reason) when PostgreSQL is not reachable, the role may not create roles, or the server does not accept
# password logins over 127.0.0.1.  Runs as any user (as root the loader runs as the PostgreSQL user, see tests/db/pg_lib.sh).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-$ROOT/karidns-dbloader}
Z2S=$ROOT/tests/db/zone2sql
Z2K=$ROOT/tests/db/zone2kdb
for b in "$LOADER" "$Z2S" "$Z2K"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: karidns-dbloader has no PostgreSQL driver"; exit 0; }
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pgrole.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
ROLE=""
cleanup() {
    pg_cleanup
    [ -n "$ROLE" ] && psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $ROLE" > /dev/null 2>&1
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
pg_setup pgrole || exit 0

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }

ROLE="karidns_test_ro_$$"
PW="pw$$x$(date +%s)"
if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $ROLE LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
    ROLE=""
    echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"
    exit 0
fi
PORT=$(pq "SHOW port")
RC="host=127.0.0.1 port=$PORT user=$ROLE password=$PW"
if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$RC dbname=$PGDB" -c "SELECT 1" > /dev/null 2>&1; then
    echo "SKIP: the server does not accept a password login of the new role over 127.0.0.1:$PORT (pg_hba.conf)"
    exit 0
fi
chmod 777 "$T"

# ---- the database: the PowerDNS schema, the extension, zones (one signed with keys), tags, a profile, views
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
for z in tests/db/tagz.test.zone tests/zones/example.com.zone; do
    "$Z2S" --dialect pgsql "$z" > "$T/zone.sql" 2>/dev/null && pf "$T/zone.sql" > /dev/null
done
cat > "$T/more.sql" <<'EOF'
INSERT INTO domains (id, name, type) VALUES (901, 'keys2.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
 (901, 'keys2.test', 'SOA', 'ns1.keys2.test hostmaster.keys2.test 1 7200 3600 1209600 300', 3600, NULL, false),
 (901, 'keys2.test', 'NS', 'ns1.keys2.test', 3600, NULL, false),
 (901, 'ns1.keys2.test', 'A', '192.0.2.1', 3600, NULL, false);
INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (901, 257, true, 'PRIVATE-KEY-MATERIAL-DO-NOT-READ');
INSERT INTO domainmetadata (domain_id, kind, content) VALUES (901, 'PRESIGNED', '1'), (901, 'X-KARIDNS-PROFILE', 'gold');
INSERT INTO karidns_profiles (name, settings) VALUES ('gold', 'also-notify { 192.0.2.7; };');
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (901, 'internal');
EOF
pf "$T/more.sql" > /dev/null || { echo "  [FAIL] cannot load the fixture"; exit 1; }

pg_conninfo_file "$T/ci_owner"
printf '%s dbname=%s\n' "$RC" "$PGDB" > "$T/ci_role"
[ -n "$PG_AS" ] && chown "$PG_AS" "$T/ci_role"
chmod 600 "$T/ci_role"

as_pg "$PGLOADER" --dump "$T/owner.kdb" --driver postgresql --conninfo-file "$T/ci_owner" 2> "$T/owner.err"; ro=$?
[ "$ro" -le 1 ] && pass "the dump with the owner's rights works (exit $ro)" || { fail "owner dump: exit $ro"; head -3 "$T/owner.err"; }
[ "$("$Z2K" --extract "$T/owner.kdb" keys2.test | wc -c | tr -d ' ')" -gt 100 ] && pass "keys2.test (PRESIGNED, with a cryptokeys row) is in the stream" || fail "keys2.test is not in the owner's stream"

# ---- before the script: the role has no rights at all
as_pg "$PGLOADER" --dump "$T/none.kdb" --driver postgresql --conninfo-file "$T/ci_role" 2> "$T/none.err"; rn=$?
[ "$rn" -eq 3 ] && grep -qi "permission denied\|does not exist\|no column\|is missing" "$T/none.err" && pass "a role without privileges cannot dump (exit 3)" || { fail "unprivileged role: exit $rn"; head -2 "$T/none.err"; }

# ---- the script
psql -X -q -At -v ON_ERROR_STOP=1 -v role=$ROLE -v schema=public -f db/karidns_loader_role.pgsql.sql "$PGC" > "$T/role.out" 2>&1 && pass "db/karidns_loader_role.pgsql.sql applies" || { fail "the role script"; cat "$T/role.out" | head -5; }
psql -X -q -At -v ON_ERROR_STOP=1 -v role=$ROLE -v schema=public -f db/karidns_loader_role.pgsql.sql "$PGC" > /dev/null 2>&1 && pass "the role script can be applied again" || fail "second application of the role script"
as_pg "$PGLOADER" --dump "$T/role.kdb" --driver postgresql --conninfo-file "$T/ci_role" 2> "$T/role.err"; rr=$?
[ "$rr" = "$ro" ] && pass "the dump with the loader role has the owner's exit status ($rr)" || { fail "role dump: exit $rr, owner $ro"; head -3 "$T/role.err"; }
cmp -s "$T/owner.kdb" "$T/role.kdb" && pass "the loader role's stream equals the owner's (byte for byte)" || fail "the streams differ"
[ "$("$Z2K" --extract "$T/role.kdb" keys2.test | wc -c | tr -d ' ')" -gt 100 ] && pass "the signed zone with keys is in the role's stream (zones_with_keys works with the column privilege only)" || fail "keys2.test missing from the role's stream"
as_pg "$PGLOADER" --dump "$T/role2.kdb" --driver postgresql --conninfo-file "$T/ci_role" --zone keys2.test 2> /dev/null && pass "--zone works with the loader role too" || fail "--zone with the loader role"

# ---- what the role may and may not do
rq() { PGCONNECT_TIMEOUT=5 psql -X -q -At "$RC dbname=$PGDB" -c "$1"; }
[ "$(rq "SELECT count(DISTINCT domain_id) FROM cryptokeys")" = "1" ] && pass "the role reads cryptokeys.domain_id" || fail "cryptokeys.domain_id"
rq "SELECT content FROM cryptokeys" > "$T/ck.out" 2>&1; grep -q "permission denied" "$T/ck.out" && ! grep -q "PRIVATE-KEY" "$T/ck.out" && pass "cryptokeys.content (the private keys) is not readable" || { fail "cryptokeys.content"; head -2 "$T/ck.out"; }
rq "SELECT * FROM cryptokeys" > "$T/ck2.out" 2>&1; grep -q "permission denied" "$T/ck2.out" && pass "SELECT * FROM cryptokeys is denied" || fail "SELECT * FROM cryptokeys"
rq "INSERT INTO domains (name, type) VALUES ('rw.test', 'NATIVE')" > "$T/w.out" 2>&1; grep -q "permission denied\|read-only" "$T/w.out" && pass "INSERT is denied" || { fail "INSERT"; head -2 "$T/w.out"; }
rq "UPDATE records SET ttl = 1" > "$T/w.out" 2>&1; grep -q "permission denied\|read-only" "$T/w.out" && pass "UPDATE is denied" || fail "UPDATE"
rq "DELETE FROM karidns_changes" > "$T/w.out" 2>&1; grep -q "permission denied\|read-only" "$T/w.out" && pass "DELETE is denied" || fail "DELETE"
[ "$(rq "SHOW default_transaction_read_only")" = "on" ] && pass "default_transaction_read_only is on for the role" || fail "default_transaction_read_only"
rq "SELECT count(*) FROM karidns_changes" > /dev/null 2>&1 && pass "karidns_changes is readable" || fail "karidns_changes"

# ---- the column privilege is what makes it work
pq "REVOKE SELECT (domain_id, active, published) ON cryptokeys FROM $ROLE" > /dev/null
as_pg "$PGLOADER" --dump "$T/nock.kdb" --driver postgresql --conninfo-file "$T/ci_role" 2> "$T/nock.err"; rk=$?
[ "$rk" -eq 3 ] && grep -qi "permission denied" "$T/nock.err" && pass "without the column privilege the dump fails with 'permission denied' (exit 3)" || { fail "no column privilege: exit $rk"; head -2 "$T/nock.err"; }
pq "GRANT SELECT (domain_id, active, published) ON cryptokeys TO $ROLE" > /dev/null
as_pg "$PGLOADER" --dump "$T/again.kdb" --driver postgresql --conninfo-file "$T/ci_role" 2> /dev/null && cmp -s "$T/owner.kdb" "$T/again.kdb" && pass "granted again: the dump works" || fail "dump after the grant"

# ---- the conninfo file
chmod 644 "$T/ci_role"
as_pg "$PGLOADER" --dump "$T/m.kdb" --driver postgresql --conninfo-file "$T/ci_role" 2> "$T/m.err"; rm_=$?
[ "$rm_" -eq 3 ] && grep -q "mode 0600 or 0400" "$T/m.err" && ! grep -q "$PW" "$T/m.err" && pass "mode 0644 is refused before the file is read, the password is not in the message" || { fail "mode check: exit $rm_"; head -2 "$T/m.err"; }
chmod 400 "$T/ci_role"
as_pg "$PGLOADER" --dump "$T/m.kdb" --driver postgresql --conninfo-file "$T/ci_role" 2> /dev/null && pass "mode 0400 is accepted" || fail "mode 0400"
if PGCONNECT_TIMEOUT=5 psql -X -q -At "host=127.0.0.1 port=$PORT user=$ROLE password=WRONG-$PW dbname=$PGDB" -c "SELECT 1" > /dev/null 2>&1; then
    echo "  [SKIP] this server trusts 127.0.0.1 (no password check): the wrong password case is not tested"
else
printf '%s dbname=%s\n' "host=127.0.0.1 port=$PORT user=$ROLE password=WRONG-$PW" "$PGDB" > "$T/ci_bad"
[ -n "$PG_AS" ] && chown "$PG_AS" "$T/ci_bad"
chmod 600 "$T/ci_bad"
as_pg "$PGLOADER" --dump "$T/m.kdb" --driver postgresql --conninfo-file "$T/ci_bad" 2> "$T/bad.err"; rb=$?
[ "$rb" -eq 4 ] && ! grep -q "WRONG-$PW\|$PW" "$T/bad.err" && pass "a wrong password: exit 4 (retry), the password is not in the message" || { fail "wrong password: exit $rb"; head -2 "$T/bad.err"; }
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_pg_role_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_pg_role_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

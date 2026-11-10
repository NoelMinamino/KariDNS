#!/bin/sh
# run_webadmin_pg_test.sh - karidns-webadmin (webadmin/, 0.6.0 items D and E, milestone M2) on PostgreSQL: the API connects as the role karidns_api
# (db/karidns_api_role.pgsql.sql: row level security on, the audit triggers on) and reads zones for the export as the check role
# (db/karidns_check_role.pgsql.sql).
#
# The same scenarios as tests/run_webadmin_test.sh (webadmin/test/it.mjs) against the real server; what PostgreSQL adds, checked here:
#   P1  the permission vectors (tests/auth_vectors.json) give the same answers from the SQL functions karidns_auth.rr_ok / rr_visible / zone_grant / is_global /
#       policy_subset / may_grant as from webadmin/lib/perm.js (webadmin/test/sql_vectors.mjs; the other half runs in webadmin/test/perm.test.js);
#   P2  row level security is the second check: as the API role with karidns.principal set to a subdomain master, a domain master, a member of a group, a
#       disabled user and nobody, a SELECT sees the rows the API would show, a write outside the scope is refused or changes no row (the queries the API would
#       never send);
#   P3  the server never logged that RLS refused what the API had allowed (that is a bug, planning 3.3 step 5);
#   P4  --create-admin needs the connection of the table owner (the API role cannot make the first user), the connection files are checked like the loader's.
# SKIP (exit 0) when PostgreSQL is not reachable (tests/db/pg_lib.sh), the role may not create roles, the password login over 127.0.0.1 is not accepted, node 22.13
# or newer, webadmin/node_modules/pg (run `npm ci --ignore-scripts` in webadmin/) or a binary is missing.  About 60 seconds.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
case $ZONE in /*) ;; *) ZONE=$ROOT/${ZONE#./} ;; esac
case $KARICHECK in /*) ;; *) KARICHECK=$ROOT/${KARICHECK#./} ;; esac
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed"; exit 0; }
[ -d webadmin/node_modules/pg ] || { echo "SKIP: webadmin/node_modules/pg is missing (run npm ci --ignore-scripts in webadmin/)"; exit 0; }
[ -x "$ZONE" ] && [ -x "$KARICHECK" ] || { echo "SKIP: $ZONE or $KARICHECK is not built"; exit 0; }
"$ZONE" --version | grep -q postgresql || { echo "SKIP: $ZONE has no PostgreSQL driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadminpg.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""; ROLES=""
cleanup() {
    [ -n "$SRV" ] && { kill -KILL "$SRV" 2>/dev/null; }
    pg_cleanup
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    chmod -R u+rwx "$T" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM
pg_setup webadmin || exit 0

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

RA=kw_api_$$; RK=kw_chk_$$; ROLES="$RA $RK"
PW="pw$$x$(date +%s)"
if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $RA LOGIN PASSWORD '$PW'" -c "CREATE ROLE $RK LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
    echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"
    exit 0
fi
PORT_PG=$(pq "SHOW port")
OWNER=$(pq "SELECT current_user")
PGSOCK=$(pq "SHOW unix_socket_directories" | cut -d, -f1)
rc_of() { echo "host=127.0.0.1 port=$PORT_PG user=$1 password=$PW dbname=$PGDB"; }
if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c "SELECT 1" > /dev/null 2>&1; then
    echo "SKIP: the server does not accept a password login over 127.0.0.1:$PORT_PG (pg_hba.conf)"
    exit 0
fi

echo "-- the database"
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
rolescript() { psql -X -q -At -v ON_ERROR_STOP=1 -v role="$2" -v schema=public -f "$1" "$PGC" > "$T/role.out" 2>&1 && ok "$3" || bad "$3" "$(head -5 "$T/role.out")"; }
rolescript db/karidns_api_role.pgsql.sql $RA "the API role script (row level security on)"
rolescript db/karidns_check_role.pgsql.sql $RK "the check role script"

# the programs and the server, where the user they run as can read them (as root that is the PostgreSQL user)
cp "$ZONE" "$T/karidns-zone" && chmod 755 "$T/karidns-zone"
mkdir -p "$T/app/webadmin" "$T/app/node" "$T/app/tests"
cp -R webadmin/bin webadmin/lib webadmin/ui webadmin/test webadmin/package.json webadmin/node_modules "$T/app/webadmin/" && cp -R node/lib "$T/app/node/" && cp tests/auth_vectors.json "$T/app/tests/" && chmod -R a+rX "$T/app"
mkci() { printf '%s\n' "$2" > "$1"; [ -n "$PG_AS" ] && chown "$PG_AS" "$1"; chmod 600 "$1"; }
mkci "$T/ci_owner" "host=$PGSOCK port=$PORT_PG user=$OWNER dbname=$PGDB"
mkci "$T/ci_api" "$(rc_of $RA)"
mkci "$T/ci_check" "$(rc_of $RK)"
asu() { as_pg "$@"; }
cat > "$T/example.test.zone" <<'EOF'
$ORIGIN example.test.
$TTL 300
@ IN SOA ns1 hostmaster 10 7200 3600 1209600 300
@ IN NS ns1
@ IN MX 10 mail
ns1 IN A 192.0.2.1
mail IN A 192.0.2.40
www IN A 192.0.2.10
www IN A 192.0.2.11
sub IN A 192.0.2.20
a.sub IN TXT "hello"
evilsub IN A 192.0.2.30
EOF
cat > "$T/other.test.zone" <<'EOF'
$ORIGIN other.test.
$TTL 300
@ IN SOA ns1 hostmaster 5 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 198.51.100.1
www IN A 198.51.100.2
EOF
chmod 644 "$T/example.test.zone" "$T/other.test.zone"
for z in example.test other.test; do
    asu "$T/karidns-zone" import --no-config --conninfo-file "$T/ci_owner" "$z" "$T/$z.zone" > "$T/import.out" 2>&1 && ok "$z is imported (as the owner)" || bad "import of $z" "$(cat "$T/import.out")"
done

PORT=$(kari_port 0 $((21000 + $$ % 20000)))
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
# karidns-webadmin test configuration (PostgreSQL)
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = pg
api-conninfo-file = $T/ci_api
check-conninfo-file = $T/ci_check
totp-key-file = $T/totp.key
karidns-zone = $T/karidns-zone
karicheck = $KARICHECK
scrypt-ln = 14
require-totp = global
session-idle = 8
rate-login = 60
rate-api = 1000
rate-write = 1000
log = stderr
EOF
chmod 644 "$CONF"
[ -n "$PG_AS" ] && chown "$PG_AS" "$T"
APP="$NODE $T/app/webadmin/bin/karidns-webadmin.js -c $CONF"

echo "-- the command line"
asu $APP --create-admin admin > "$T/admin0.out" 2> "$T/admin0.err" && bad "--create-admin without a trusted connection" || ok "--create-admin refuses to run with the API role's connection (it needs the owner's)"
grep -q "bootstrap-conninfo-file" "$T/admin0.err" && ok "...and says what to give" || bad "--create-admin message" "$(cat "$T/admin0.err")"
asu $APP --create-admin admin --bootstrap-conninfo-file "$T/ci_api" > /dev/null 2> "$T/admin1.err" && bad "--create-admin with the API role" || ok "the API role cannot make the first user (row level security)"
asu $APP --create-admin admin --bootstrap-conninfo-file "$T/ci_owner" > "$T/admin.out" 2> "$T/admin.err" && ok "--create-admin with the owner's connection" || bad "--create-admin" "$(cat "$T/admin.err")"
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
[ -n "$ADMIN_PW" ] && ok "...and shows a password once" || bad "no password in the output" "$(cat "$T/admin.out")"
asu $APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine on a good setup" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
chmod 644 "$T/ci_check"
asu $APP --check > /dev/null 2> "$T/check.err" && bad "--check accepts a connection file with mode 0644" || ok "--check refuses a connection file that others can read"
chmod 600 "$T/ci_check"

echo "-- the server"
rm -f "$T/server.pid"
asu sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$T/server.pid" $APP >> "$T/server.log" 2>&1 &
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
SRV=$(cat "$T/server.pid" 2>/dev/null)
if grep -q "karidns-webadmin [^ ]* started" "$T/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$T/server.log")"; exit 1; fi

IT_BASE="http://127.0.0.1:$PORT/api/v1" IT_ORIGIN="http://127.0.0.1:$PORT" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_SESSION_IDLE=8 "$NODE" webadmin/test/it.mjs > "$T/it.out" 2>&1
IT_RC=$?
cat "$T/it.out"
[ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it.mjs)" || bad "the integration scenarios failed"

echo "-- P1: the permission vectors against the SQL functions"
asu "$NODE" "$T/app/webadmin/test/sql_vectors.mjs" "$T/ci_owner" > "$T/vec.out" 2>&1 && ok "every vector gives the answer of perm.js ($(tail -1 "$T/vec.out"))" || bad "the vectors differ" "$(grep FAIL "$T/vec.out"; tail -3 "$T/vec.out")"

echo "-- P2: row level security as the second check"
id_of() { pq "SELECT id FROM karidns_auth.principals WHERE name = '$1'"; }
aq() { PGCONNECT_TIMEOUT=5 psql -X -q -At -v ON_ERROR_STOP=1 "$(rc_of $RA)" -c "BEGIN; SET LOCAL karidns.principal = '$1'; $2; ROLLBACK" 2>&1 | grep -v '^BEGIN$\|^SET$\|^ROLLBACK$'; }
DOM=$(id_of dom); SUBU=$(id_of sub); NOB=$(id_of nobody); ADM=$(id_of admin)
same "no principal: the API role sees no record" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c 'SELECT count(*) FROM records')" 0
same "the administrator sees every record" "$(aq "$ADM" 'SELECT count(*) FROM records')" "$(pq 'SELECT count(*) FROM records')"
same "a domain master sees the records of its zone" "$(aq "$DOM" 'SELECT count(*) FROM records')" "$(pq "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'example.test'")"
same "a member of a group sees the records of the zone the group has" "$(aq "$NOB" 'SELECT count(*) FROM records')" "$(pq "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'other.test'")"
# (the integration scenarios disabled the user 'sub' at the end: enabled again for these checks, disabled again below)
pq "UPDATE karidns_auth.principals SET disabled = false WHERE name = 'sub'" > /dev/null
same "a subdomain master sees its suffix and the apex SOA and NS" "$(aq "$SUBU" "SELECT string_agg(name || ' ' || type, ',' ORDER BY name, type) FROM records")" "a.sub.example.test TXT,example.test NS,example.test SOA,sub.example.test A"
same "...a write to a name it cannot see changes no row" "$(aq "$SUBU" "WITH u AS (UPDATE records SET content = '192.0.2.99' WHERE name = 'evilsub.example.test' RETURNING 1) SELECT count(*) FROM u")" 0
aq "$SUBU" "INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'evilsub.example.test', 'A', '192.0.2.99', 300 FROM domains WHERE name = 'example.test'" | grep -q "row-level security" && ok "...an insert there is refused by the policy" || bad "an insert outside the scope was not refused"
aq "$SUBU" "INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'x.sub.example.test', 'A', '192.0.2.99', 30 FROM domains WHERE name = 'example.test'" | grep -q "row-level security" && ok "...a TTL outside the policy is refused" || bad "a TTL outside the policy was accepted"
aq "$SUBU" "INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'x.sub.example.test', 'A', '192.0.2.99', 300 FROM domains WHERE name = 'example.test'" | grep -q "row-level" && bad "a record inside the scope was refused" || ok "...a record inside its scope and policy is accepted"
aq "$SUBU" "INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'x.sub.example.test', 'MX', '10 mail.example.test', 300 FROM domains WHERE name = 'example.test'" | grep -q "row-level security" && ok "...a type outside the policy is refused" || bad "a type outside the policy was accepted"
same "a domain master deletes no zone" "$(aq "$DOM" "WITH d AS (DELETE FROM domains RETURNING 1) SELECT count(*) FROM d")" 0
aq "$DOM" "SELECT content FROM cryptokeys" | grep -q "permission denied" && ok "the API role cannot read key material" || bad "cryptokeys.content is readable"
same "the audit log holds nothing for a subdomain master" "$(aq "$SUBU" 'SELECT count(*) FROM karidns_auth.audit_log')" 0
aq "$SUBU" "UPDATE karidns_auth.audit_log SET op = 'D'" | grep -q "permission denied" && ok "the audit log cannot be changed by the API role" || bad "the audit log is writable"
# a disabled principal has no rows
pq "UPDATE karidns_auth.principals SET disabled = true WHERE name = 'sub'" > /dev/null
same "a disabled user sees nothing" "$(aq "$SUBU" 'SELECT count(*) FROM records')" 0
same "...and its sessions are gone (the API deleted them when it disabled the user)" "$(pq "SELECT count(*) FROM karidns_auth.sessions s JOIN karidns_auth.principals p ON p.id = s.principal_id WHERE p.name = 'sub'")" 0

echo "-- afterwards"
kill -TERM "$SRV" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then bad "the server did not stop after SIGTERM"; kill -KILL "$SRV" 2>/dev/null; else ok "the server stops on SIGTERM"; fi
SRV=""
grep -q "stopped" "$T/server.log" && ok "...and says so" || bad "no 'stopped' in the log"
grep -q "(a bug)" "$T/server.log" && bad "row level security refused what the API had allowed (P3)" "$(grep '(a bug)' "$T/server.log" | head -3)" || ok "P3: row level security never disagreed with the API"
if grep -Fq "$ADMIN_PW" "$T/server.log" || grep -Eq 'Sunrise-Harbor|Maple-Anchor|Violet-Lantern|Cobalt-Ranger|a new password|karidns_session=|\$scrypt\$|kdt_' "$T/server.log" || grep -Fq "$PW" "$T/server.log"; then bad "the log holds a password, token, cookie or hash"; else ok "the log holds no password, token, cookie or hash"; fi
grep -Eq '^[^ ]+ error ' "$T/server.log" && bad "the server logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the server logged no error"
same "no password hash in the audit log" "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE before::text LIKE '%scrypt%' OR after::text LIKE '%scrypt%'")" 0
[ "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE principal_name = 'admin' AND db_role = '$RA'")" -gt 0 ] && ok "the administrator's changes are in the audit log under its name and the API role" || bad "no audit row names the administrator"

echo
echo "=== run_webadmin_pg_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

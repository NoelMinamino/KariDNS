#!/bin/sh
# run_webadmin_write_pg_test.sh - karidns-webadmin (webadmin/, 0.6.0 items D and E, milestone M3: the write side) on PostgreSQL, with a running karidns.
#
# The scenarios of tests/run_webadmin_write_test.sh (webadmin/test/it_write.mjs) with the API connected as the role karidns_api (db/karidns_api_role.pgsql.sql: row
# level security on, the audit triggers on) and its check runs as the check role (db/karidns_check_role.pgsql.sql): a real karidns with its loader serves
# example.test, other.test and signed.test (the metadata X-KARIDNS-SIGNER) from PostgreSQL; a change set is in the DNS answer after the reload request that the commit
# run files in karidns_reload_requests (NOTIFY wakes the loader), a write outside the grant is refused, max_rr, a conflict between the check run and the commit run,
# preconditions, a signer zone that no request reloads, the import, a zone made and deleted (the trigger takes its grants), metadata, key requests, the audit log
# (under the principal and the API role), and the cost of a change set of a small and of a zone of 20,000 records (the lines "[COST]").  Then: the reload requests
# the API filed, that the API role never saw a policy refuse what the API had allowed, and the expired sessions swept by karidns_auth.sweep_expired().
# Environment: ZONE, KARICHECK, KARIDNS, LOADER, NODE, BIG (default 20000).  Needs root and an unprivileged PostgreSQL user (KARIDNS_TEST_PG_USER); SKIP (exit 0,
# with the reason) when PostgreSQL is not reachable (tests/db/pg_lib.sh), the role may not create roles, the password login over 127.0.0.1 is not accepted,
# node 22.13 or newer, webadmin/node_modules/pg (npm ci --ignore-scripts in webadmin/) or a binary is missing.  About 2 minutes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
KARIDNS=${KARIDNS:-$ROOT/karidns}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
BIG=${BIG:-20000}
for v in ZONE KARICHECK KARIDNS LOADER; do eval "p=\$$v"; case $p in /*) ;; *) eval "$v=$ROOT/\${p#./}" ;; esac; done
[ "$(id -u)" = "0" ] || { echo "SKIP: needs root (the server drops to nobody; the loader must be root-owned)"; exit 0; }
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed"; exit 0; }
[ -d webadmin/node_modules/pg ] || { echo "SKIP: webadmin/node_modules/pg is missing (run npm ci --ignore-scripts in webadmin/)"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
for b in "$ZONE" "$KARICHECK" "$KARIDNS" "$LOADER" ./dag ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
"$ZONE" --version | grep -q postgresql || { echo "SKIP: $ZONE has no PostgreSQL driver"; exit 0; }
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_wpg.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""; WEB=""; ROLES=""
cleanup() {
    [ -n "$WEB" ] && kill -TERM "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$WEB" ] && kill -KILL "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    pg_cleanup
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    chmod -R u+rwx "$T" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM
pg_setup webadminw || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader and the API cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

RA=kww_api_$$; RK=kww_chk_$$; ROLES="$RA $RK"
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

mkdir -p "$T/app/webadmin" "$T/app/node" "$T/ctl"
chmod 777 "$T/ctl"
cp "$ZONE" "$T/karidns-zone-real"; cp "$KARICHECK" "$T/karicheck"; cp ./karictl "$T/karictl"; chmod 755 "$T/karidns-zone-real" "$T/karicheck" "$T/karictl"
cp -R webadmin/bin webadmin/lib webadmin/package.json webadmin/node_modules "$T/app/webadmin/" && cp -R node/lib "$T/app/node/" && chmod -R a+rX "$T/app"
mkci() { printf '%s\n' "$2" > "$1"; chown "$PG_AS" "$1"; chmod 600 "$1"; }
mkci "$T/ci_owner" "host=$PGSOCK port=$PORT_PG user=$OWNER dbname=$PGDB"
mkci "$T/ci_api" "$(rc_of $RA)"
mkci "$T/ci_check" "$(rc_of $RK)"
pg_conninfo_file "$T/ci_loader"
mkdir "$T/web"; chown "$PG_AS" "$T/web"
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
for z in other signed; do
    cat > "$T/$z.test.zone" <<EOF
\$ORIGIN $z.test.
\$TTL 300
@ IN SOA ns1 hostmaster 5 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 198.51.100.1
www IN A 192.0.2.20
EOF
done
chmod 644 "$T"/*.zone
for z in example other signed; do
    as_pg "$T/karidns-zone-real" import --no-config --conninfo-file "$T/ci_owner" "$z.test" "$T/$z.test.zone" > "$T/import.out" 2>&1 && ok "$z.test is imported (as the owner)" || bad "import of $z" "$(cat "$T/import.out")"
done
pq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'signed.test'" > /dev/null

# ---------------------------------------------------------------- karidns and its loader (the loader reads as the owner: row level security does not bind it)
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
WPORT=$(kari_port 1 $((PORT + 1)))
b64() { printf '%s' "$1" | openssl base64 -A; }
MAIN_SECRET=$(b64 "wr-test-main-secret-0123456789abc")
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karidns.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci_loader"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; };
};
control-channel { socket "$T/ctl.sock"; secret "$MAIN_SECRET"; };
EOF
chmod 644 "$T/karidns.conf"
printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$MAIN_SECRET" > "$T/main-karictl.conf"
chmod 600 "$T/main-karictl.conf"
"$KARIDNS" -c "$T/karidns.conf" -f > "$T/karidns.log" 2>&1 &
SRV=$!
if kari_wait_log "$T/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$T/karidns.log")"; exit 1; fi

# ---------------------------------------------------------------- the API, as the unprivileged user
cat > "$T/kz" <<EOF
#!/bin/sh
# karidns-zone for the API; the test makes it change example.test behind the API's back between the check run and the commit run
REAL="$T/karidns-zone-real"
if [ -f "$T/ctl/conflict.once" ] || [ -f "$T/ctl/conflict.always" ]; then
    case " \$* " in
    *" --dry-run "*example.test*)
        input=\$(cat)
        out=\$(printf '%s\n' "\$input" | "\$REAL" "\$@"); rc=\$?
        rm -f "$T/ctl/conflict.once"
        printf 'rr noise.example.test. 60 TXT "n%s"\n' "\$(date +%s)\$\$" | "\$REAL" apply --no-config --conninfo-file "$T/ci_owner" --schema public --changes - example.test > /dev/null 2>&1
        echo conflict >> "$T/ctl/wrapper.log"
        printf '%s\n' "\$out"
        exit \$rc ;;
    esac
fi
exec "\$REAL" "\$@"
EOF
chmod 755 "$T/kz"
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
listen = 127.0.0.1:$WPORT
public-origin = http://127.0.0.1:$WPORT
database = pg
api-conninfo-file = $T/ci_api
check-conninfo-file = $T/ci_check
totp-key-file = $T/web/totp.key
karidns-zone = $T/kz
karicheck = $T/karicheck
scrypt-ln = 14
require-totp = none
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr
EOF
chmod 644 "$CONF"
APP="$NODE $T/app/webadmin/bin/karidns-webadmin.js -c $CONF"
as_pg $APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
as_pg $APP --create-admin admin --bootstrap-conninfo-file "$T/ci_owner" > "$T/admin.out" 2> "$T/admin.err" || bad "--create-admin" "$(cat "$T/admin.err")"
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
rm -f "$T/web/server.pid"
as_pg sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$T/web/server.pid" $APP >> "$T/server.log" 2>&1 &
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin 0.6.0 started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
WEB=$(cat "$T/web/server.pid" 2>/dev/null)
if grep -q "karidns-webadmin 0.6.0 started" "$T/server.log"; then ok "the API started (pid $WEB)"; else bad "the API did not start" "$(cat "$T/server.log")"; exit 1; fi

if [ "$BIG" -gt 0 ]; then
    awk -v n="$BIG" 'BEGIN { print "$ORIGIN big.test."; print "$TTL 300"; print "@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300"; print "@ IN NS ns1"; print "ns1 IN A 192.0.2.1";
        for (i = 0; i < n / 2; i++) printf "h%d IN A 10.%d.%d.%d\ns%d.sub1 IN TXT \"x%d\"\n", i, int(i / 65536) % 256, int(i / 256) % 256, i % 256, i, i }' > "$T/big.zone"
    chmod 644 "$T/big.zone"
    s=$(date +%s)
    as_pg "$T/karidns-zone-real" import --no-config --conninfo-file "$T/ci_owner" big.test "$T/big.zone" > "$T/import.out" 2>&1 && ok "big.test is imported (about $BIG records, $(( $(date +%s) - s )) s)" || bad "import of big.test" "$(tail -3 "$T/import.out")"
fi

echo "-- the scenarios (webadmin/test/it_write.mjs)"
IT_BASE="http://127.0.0.1:$WPORT/api/v1" IT_ORIGIN="http://127.0.0.1:$WPORT" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_DNS_PORT=$PORT IT_DAG="$ROOT/dag" IT_DIR="$T/ctl" \
    IT_KARICTL="$ROOT/karictl" IT_KARICTL_CONF="$T/main-karictl.conf" IT_KARICTL_SOCK="$T/ctl.sock" IT_DB=pg IT_API_ROLE="$RA" IT_BIG="$BIG" "$NODE" webadmin/test/it_write.mjs > "$T/it.out" 2>&1
IT_RC=$?
cat "$T/it.out"
[ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it_write.mjs)" || bad "the integration scenarios failed"

echo "-- PostgreSQL: what the API left in the database"
[ "$(pq "SELECT count(*) FROM karidns_reload_requests WHERE zone IN ('example.test', 'new.test', 'other.test')")" -gt 3 ] && ok "the reload requests of the commit runs and of the update button are there (zone by zone)" || bad "too few reload requests"
[ "$(pq "SELECT count(*) FROM karidns_reload_requests WHERE zone = 'signed.test'")" = 0 ] && ok "none for the zone the signer keeps (the operator's karictl reloaded it)" || bad "the API filed a reload request for the signer's zone"
same "the loader applied them (karidns_server_status is ok)" "$(pq "SELECT bool_and(ok)::text FROM karidns_server_status")" true
same "the audit log names the API role and the principal for the change sets" "$(pq "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE principal_name = 'dom' AND db_role = '$RA' AND table_name = 'records' AND change_set IS NOT NULL")" t
same "the zone versions are there (version rows of the commit runs)" "$(pq "SELECT count(*) > 5 FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'example.test'")" t
same "the grants of the deleted zone went with it (trigger of the schema)" "$(pq "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'other.test'")" 0
# the sweep: expired sessions of every principal, by the SECURITY DEFINER function, as the API role
pq "INSERT INTO karidns_auth.sessions (id_hash, principal_id, csrf_hash, expires_at) SELECT decode(lpad(i::text, 64, '0'), 'hex'), (SELECT id FROM karidns_auth.principals WHERE name = 'dom'), decode(lpad('1', 64, '0'), 'hex'), now() - interval '1 hour' FROM generate_series(1, 3) i" > /dev/null
same "karidns_auth.sweep_expired() as the API role deletes the expired sessions of other principals" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c "SELECT karidns_auth.sweep_expired()")|$(pq "SELECT count(*) FROM karidns_auth.sessions WHERE expires_at <= now()")" "3|0"

echo "-- afterwards"
kill -TERM "$WEB" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$WEB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$WEB" 2>/dev/null; then bad "the API did not stop after SIGTERM"; kill -KILL "$WEB" 2>/dev/null; else ok "the API stops on SIGTERM"; fi
WEB=""
grep -q "(a bug)" "$T/server.log" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$T/server.log" | head -3)" || ok "row level security never disagreed with the API"
grep -Eq '^[^ ]+ error ' "$T/server.log" && bad "the API logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the API logged no error"
if grep -Eq 'Sunrise-Harbor|Maple-Anchor|Granite-Pine|karidns_session=|\$scrypt\$|kdt_|zone_text|192\.0\.2\.77' "$T/server.log" || grep -Fq "$PW" "$T/server.log"; then bad "the log holds a password, cookie, hash, token or request data"; else ok "the log holds no password, cookie, hash, token or record data"; fi
grep -q "ERROR\|assertion\|Assertion" "$T/karidns.log" && bad "karidns logged an error" "$(grep 'ERROR\|ssertion' "$T/karidns.log" | head -3)" || ok "karidns logged no error"

echo
echo "=== run_webadmin_write_pg_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

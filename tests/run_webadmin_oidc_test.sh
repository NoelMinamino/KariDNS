#!/bin/sh
# run_webadmin_oidc_test.sh - the sign-in with an OpenID Connect provider (karidns-webadmin, 0.6.0 item F, milestone M5), against the real service and a fake provider.
#
# The fake provider is a second process on the loopback address (webadmin/test/e2e/idp.mjs: discovery, JWK Set, authorization endpoint, token endpoint with the client
# password, the code and the PKCE verifier checked).  Its issuer is written http://localhost:PORT while the service is at 127.0.0.1: another site, so that the way back from
# the provider is a cross-site navigation, as it is with a real provider.  Three parts:
#   1  SQLite3:     the service with an [oidc idp] section and webadmin/test/it_oidc.mjs (link, sign in, every refusal, a replayed state, a state from another browser, hostile
#                   ID tokens, the TOTP step of a global master, unlink, the audit log, the state table empty at the end);
#   2  PostgreSQL:  the same scenarios as the API role of db/karidns_api_role.pgsql.sql (row level security on): oidc_states has no privilege for the role, the three
#                   SECURITY DEFINER functions do the work, and the service never logs that RLS refused what it had allowed;
#   3  the browser: Firefox headless (webadmin/test/e2e/gui_oidc.mjs) signs in at the provider and comes back (the cookie of a Strict session set by the redirect from
#                   another site is sent by the page: plan assumption 10), refusals, the link in the administration.
# Parts 1 and 2 by default (0.7): part 3 drives a browser and is run by tests/run_webadmin_oidc_gui_test.sh (OIDC_PARTS=3), a test of the category gui of
# tests/run_all_suite.sh, which the suite runs only with --with-gui or --only-gui; OIDC_PARTS="1 2 3" runs all three here.
# Environment: OIDC_PARTS (the parts, default "1 2"), ZONE (./karidns-zone), KARICHECK (./karicheck), NODE, FIREFOX, GECKODRIVER, KARIDNS_TEST_PG (a conninfo of a maintenance database), GUI_MAX_RSS_MIB.
# SKIP (exit 0, with the reason) a part without node 22.13, the sqlite3 tool, the binaries, PostgreSQL (and webadmin/node_modules/pg), Firefox or geckodriver.  About two minutes.
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
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
[ -x "$ZONE" ] && [ -x "$KARICHECK" ] || { echo "SKIP: $ZONE or $KARICHECK is not built"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_oidc.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""; IDP=""; GUI_MEM=""; PGDB=""; ROLES=""
. "$ROOT/tests/db/pg_lib.sh"
cleanup() {
    [ -n "$GUI_MEM" ] && kill "$GUI_MEM" 2>/dev/null
    for p in "$SRV" "$IDP"; do [ -n "$p" ] && { kill -TERM "$p" 2>/dev/null; sleep 0.2; kill -KILL "$p" 2>/dev/null; wait "$p" 2>/dev/null; }; done
    for p in $(pgrep -f "$T" 2>/dev/null); do kill -KILL "$p" 2>/dev/null; done
    pg_cleanup 2>/dev/null
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    chmod -R u+rwx "$T" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

want() { case " ${OIDC_PARTS:-1 2} " in *" $1 "*) return 0 ;; esac; return 1; }
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

CLIENT_ID=kari-test-client
CLIENT_SECRET=kari-test-secret-0123
printf '%s\n' "$CLIENT_SECRET" > "$T/idp.secret"
chmod 600 "$T/idp.secret"
cp "$ZONE" "$T/karidns-zone"

# start_idp PORT REDIRECT_URI -> IDP (the pid) and IDP_URL
start_idp() {
    IDP_PORT=$1 IDP_ISSUER_HOST=localhost IDP_REDIRECTS=$2 IDP_CLIENT_ID=$CLIENT_ID IDP_CLIENT_SECRET=$CLIENT_SECRET "$NODE" webadmin/test/e2e/idp.mjs > "$T/idp.out" 2>&1 &
    IDP=$!
    i=0; while [ $i -lt 50 ] && ! grep -q '^issuer ' "$T/idp.out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    IDP_URL=$(sed -n 's/^issuer //p' "$T/idp.out")
    [ -n "$IDP_URL" ] && ok "the fake provider is up at $IDP_URL" || { bad "the fake provider did not start" "$(cat "$T/idp.out")"; return 1; }
}
stop_idp() { [ -n "$IDP" ] && { kill -TERM "$IDP" 2>/dev/null; wait "$IDP" 2>/dev/null; IDP=""; }; }
# wait_started LOG: the service says it has started
wait_started() {
    i=0; while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$1" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    grep -q "karidns-webadmin [^ ]* started" "$1"
}
stop_server() {
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$SRV" 2>/dev/null; then bad "the server did not stop after SIGTERM"; kill -KILL "$SRV" 2>/dev/null; else ok "the server stops on SIGTERM"; fi
    SRV=""
}
# checks_after LOG: what must hold for the log of every service of this test
checks_after() {
    grep -q "(a bug)" "$1" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$1" | head -3)" || ok "the service never logged a disagreement with the database"
    grep -Eq '^[^ ]+ error ' "$1" && bad "the service logged an error" "$(grep ' error ' "$1" | head -3)" || ok "the service logged no error"
    if grep -Fq "$CLIENT_SECRET" "$1" || grep -Eq 'karidns_session=|karidns_oidc=|\$scrypt\$|kdt_' "$1" || { [ -n "${ADMIN_PW:-}" ] && grep -Fq "$ADMIN_PW" "$1"; }; then bad "the log holds a secret, cookie, hash or password"; else ok "the log holds no client secret, cookie, hash or password"; fi
    grep -q "auth: oidc idp: sign-in refused" "$1" && ok "the refusals are in the log with their reasons" || bad "no refusal in the log"
}

# ======================================================================================================================================================================
# part 1: SQLite3
# ======================================================================================================================================================================
echo "== 1 SQLite3 (webadmin/test/it_oidc.mjs)"
if ! want 1; then
    echo "(part 1 is not asked for)"
elif ! command -v sqlite3 >/dev/null 2>&1; then
    echo "SKIP: the sqlite3 command line tool is not installed"
elif ! "$ZONE" --version | grep -q sqlite3; then
    echo "SKIP: $ZONE has no SQLite3 driver"
else
    S=$T/s
    mkdir -p "$S"
    DB=$S/zones.sqlite3; AUTH=$S/auth.sqlite3
    sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
    sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
    chmod 600 "$AUTH"
    PORT=$(kari_port 0 $((23000 + $$ % 20000)))
    IPORT=$(kari_port 1 $((PORT + 1)))
    DPORT=$(kari_port 2 $((PORT + 2)))
    start_idp "$IPORT" "http://127.0.0.1:$PORT/api/v1/auth/oidc/idp/callback" || exit 1
    cat > "$S/karidns-webadmin.conf" <<EOF
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $S/totp.key
karidns-zone = $T/karidns-zone
karicheck = $KARICHECK
scrypt-ln = 14
require-totp = global
session-idle = 600
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr

[oidc idp]
issuer = $IDP_URL
client-id = $CLIENT_ID
client-secret-file = $T/idp.secret
label = Example ID
EOF
    APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $S/karidns-webadmin.conf"
    $APP --check > "$S/check.out" 2> "$S/check.err" && ok "--check is fine and does not touch the provider" || bad "--check" "$(cat "$S/check.err" "$S/check.out")"
    grep -q "^ok: oidc idp (.*redirect URI http://127.0.0.1:$PORT/api/v1/auth/oidc/idp/callback" "$S/check.out" && ok "...it names the provider and the redirect URI" || bad "--check does not name the provider" "$(cat "$S/check.out")"
    chmod 644 "$T/idp.secret"
    $APP --check > /dev/null 2> "$S/check2.err" && bad "--check accepts a client secret that others can read" || ok "--check refuses a client secret file with mode 0644"
    grep -q "client-secret-file" "$S/check2.err" && ok "...and names the file's setting" || bad "the complaint" "$(cat "$S/check2.err")"
    chmod 600 "$T/idp.secret"
    $APP --create-admin admin > "$S/admin.out" 2> "$S/admin.err" || bad "--create-admin" "$(cat "$S/admin.err")"
    ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$S/admin.out")
    $APP >> "$S/server.log" 2>&1 &
    SRV=$!
    if wait_started "$S/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$S/server.log")"; exit 1; fi
    # the fetch runs after the "started" line (a slow host, the coverage build): wait for its line
    i=0; while [ $i -lt 100 ] && ! grep -q "oidc: provider idp .* is reachable" "$S/server.log"; do sleep 0.1; i=$((i + 1)); done
    grep -q "oidc: provider idp .* is reachable" "$S/server.log" && ok "the documents of the provider were fetched at the start" || bad "no sign of the fetch at the start" "$(cat "$S/server.log")"
    printf '#!/bin/sh\nexec sqlite3 "%s" "SELECT count(*) FROM oidc_states"\n' "$AUTH" > "$S/states.sh"; chmod 755 "$S/states.sh"
    IT_BASE="http://127.0.0.1:$PORT/api/v1" IT_ORIGIN="http://127.0.0.1:$PORT" IT_IDP="$IDP_URL" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_STATES_SQL="$S/states.sh" "$NODE" webadmin/test/it_oidc.mjs > "$S/it.out" 2>&1
    IT_RC=$?
    cat "$S/it.out"
    [ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it_oidc.mjs, SQLite3)" || bad "the integration scenarios failed (SQLite3)"
    stop_server
    checks_after "$S/server.log"
    stop_idp
fi

# ======================================================================================================================================================================
# part 2: PostgreSQL
# ======================================================================================================================================================================
echo "== 2 PostgreSQL (the same scenarios as the API role, row level security on)"
PGOK=1
if ! want 2; then PGOK=0
elif [ ! -d webadmin/node_modules/pg ]; then echo "SKIP: webadmin/node_modules/pg is missing (run npm ci --ignore-scripts in webadmin/)"; PGOK=0
elif ! "$ZONE" --version | grep -q postgresql; then echo "SKIP: $ZONE has no PostgreSQL driver"; PGOK=0
elif ! pg_setup oidc; then PGOK=0
fi
if [ $PGOK = 1 ]; then
    RA=kw_oidc_api_$$; RK=kw_oidc_chk_$$; ROLES="$RA $RK"
    PW="pw$$x$(date +%s)"
    if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $RA LOGIN PASSWORD '$PW'" -c "CREATE ROLE $RK LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
        echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"; PGOK=0
    fi
fi
if [ $PGOK = 1 ]; then
    PORT_PG=$(pq "SHOW port")
    OWNER=$(pq "SELECT current_user")
    PGSOCK=$(pq "SHOW unix_socket_directories" | cut -d, -f1)
    rc_of() { echo "host=127.0.0.1 port=$PORT_PG user=$1 password=$PW dbname=$PGDB"; }
    if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c "SELECT 1" > /dev/null 2>&1; then
        echo "SKIP: the server does not accept a password login over 127.0.0.1:$PORT_PG (pg_hba.conf)"; PGOK=0
    fi
fi
if [ $PGOK = 1 ]; then
    P=$T/p
    mkdir -p "$P"
    chmod 755 "$P"
    pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
    psql -X -q -At -v ON_ERROR_STOP=1 -v role="$RA" -v schema=public -f db/karidns_api_role.pgsql.sql "$PGC" > "$P/role.out" 2>&1 && ok "the API role script (row level security on)" || bad "the API role script" "$(head -5 "$P/role.out")"
    psql -X -q -At -v ON_ERROR_STOP=1 -v role="$RK" -v schema=public -f db/karidns_check_role.pgsql.sql "$PGC" > "$P/role2.out" 2>&1 && ok "the check role script" || bad "the check role script" "$(head -5 "$P/role2.out")"
    # the API role has no right on the table of the states at all
    [ "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c 'SELECT count(*) FROM karidns_auth.oidc_states' 2>&1 | grep -c 'permission denied')" = 1 ] && ok "the API role cannot read karidns_auth.oidc_states (only its functions do)" || bad "the API role can read the table of the states"
    [ "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c "INSERT INTO karidns_auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, expires_at) VALUES (decode(repeat('0', 64), 'hex'), decode(repeat('0', 64), 'hex'), 'x', 'n', repeat('v', 43), now())" 2>&1 | grep -c 'permission denied')" = 1 ] && ok "...nor write it" || bad "the API role can write the table of the states"
    cp "$ZONE" "$P/karidns-zone" && chmod 755 "$P/karidns-zone"
    mkdir -p "$P/app/webadmin" "$P/app/node"
    cp -R webadmin/bin webadmin/lib webadmin/ui webadmin/test webadmin/package.json webadmin/node_modules "$P/app/webadmin/" && cp -R node/lib "$P/app/node/" && chmod -R a+rX "$P/app"
    mkci() { printf '%s\n' "$2" > "$1"; [ -n "$PG_AS" ] && chown "$PG_AS" "$1"; chmod 600 "$1"; }
    mkci "$P/ci_owner" "host=$PGSOCK port=$PORT_PG user=$OWNER dbname=$PGDB"
    mkci "$P/ci_api" "$(rc_of $RA)"
    mkci "$P/ci_check" "$(rc_of $RK)"
    cp "$T/idp.secret" "$P/idp.secret"; [ -n "$PG_AS" ] && chown "$PG_AS" "$P/idp.secret"; chmod 600 "$P/idp.secret"
    PORT=$(kari_port 3 $((24000 + $$ % 20000)))
    IPORT=$(kari_port 4 $((PORT + 1)))
    start_idp "$IPORT" "http://127.0.0.1:$PORT/api/v1/auth/oidc/idp/callback" || exit 1
    cat > "$P/karidns-webadmin.conf" <<EOF
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = pg
api-conninfo-file = $P/ci_api
check-conninfo-file = $P/ci_check
totp-key-file = $P/totp.key
karidns-zone = $P/karidns-zone
karicheck = $KARICHECK
scrypt-ln = 14
require-totp = global
session-idle = 600
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr

[oidc idp]
issuer = $IDP_URL
client-id = $CLIENT_ID
client-secret-file = $P/idp.secret
label = Example ID
EOF
    chmod 644 "$P/karidns-webadmin.conf"
    [ -n "$PG_AS" ] && chown "$PG_AS" "$P"
    APP="$NODE $P/app/webadmin/bin/karidns-webadmin.js -c $P/karidns-webadmin.conf"
    as_pg $APP --create-admin admin --bootstrap-conninfo-file "$P/ci_owner" > "$P/admin.out" 2> "$P/admin.err" || bad "--create-admin" "$(cat "$P/admin.err")"
    ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$P/admin.out")
    as_pg $APP --check > "$P/check.out" 2> "$P/check.err" && ok "--check is fine (PostgreSQL: karidns_auth.oidc_states is a table the service needs)" || bad "--check" "$(cat "$P/check.err" "$P/check.out")"
    rm -f "$P/server.pid"
    as_pg sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$P/server.pid" $APP >> "$P/server.log" 2>&1 &
    i=0; while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$P/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    SRV=$(cat "$P/server.pid" 2>/dev/null)
    if grep -q "karidns-webadmin [^ ]* started" "$P/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$P/server.log")"; exit 1; fi
    printf '#!/bin/sh\nexec psql -X -q -At "%s" -c "SELECT count(*) FROM karidns_auth.oidc_states"\n' "$PGC" > "$P/states.sh"; chmod 755 "$P/states.sh"
    IT_BASE="http://127.0.0.1:$PORT/api/v1" IT_ORIGIN="http://127.0.0.1:$PORT" IT_IDP="$IDP_URL" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_STATES_SQL="$P/states.sh" "$NODE" webadmin/test/it_oidc.mjs > "$P/it.out" 2>&1
    IT_RC=$?
    cat "$P/it.out"
    [ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it_oidc.mjs, PostgreSQL)" || bad "the integration scenarios failed (PostgreSQL)"
    # the sweep deletes the states that never came back, of every principal
    pq "INSERT INTO karidns_auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, created_at, expires_at) VALUES (decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 'idp', 'n', repeat('v', 43), now() - interval '2 hours', now() - interval '1 hour')" > /dev/null
    [ "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c 'SELECT 1 FROM (SELECT karidns_auth.sweep_expired()) s')" = 1 ] && [ "$(pq 'SELECT count(*) FROM karidns_auth.oidc_states')" = 0 ] && ok "karidns_auth.sweep_expired() deletes the states that are over" || bad "the sweep left a state"
    stop_server
    checks_after "$P/server.log"
    [ "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'oidc_states'")" = 0 ] && ok "the table of the states is not in the audit log" || bad "oidc_states is audited"
    stop_idp
fi

# ======================================================================================================================================================================
# part 3: the browser
# ======================================================================================================================================================================
echo "== 3 the browser (webadmin/test/e2e/gui_oidc.mjs)"
. "$ROOT/tests/lib_webadmin_gui.sh"
if ! want 3; then
    echo "(part 3 is not asked for)"
elif ! command -v sqlite3 >/dev/null 2>&1 || ! "$ZONE" --version | grep -q sqlite3; then
    echo "SKIP: the browser part runs on SQLite3 (the sqlite3 tool and a karidns-zone with the SQLite3 driver)"
elif gui_browser_check; then
    G=$T/g
    mkdir -p "$G"
    DB=$G/zones.sqlite3; AUTH=$G/auth.sqlite3
    sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
    sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
    chmod 600 "$AUTH"
    PORT=$(kari_port 5 $((25000 + $$ % 20000)))
    IPORT=$(kari_port 6 $((PORT + 1)))
    GUI_DPORT=$(kari_port 7 $((PORT + 2)))
    start_idp "$IPORT" "http://127.0.0.1:$PORT/api/v1/auth/oidc/idp/callback" || exit 1
    cat > "$G/karidns-webadmin.conf" <<EOF
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $G/totp.key
karidns-zone = $T/karidns-zone
karicheck = $KARICHECK
scrypt-ln = 14
require-totp = none
session-idle = 600
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr

[oidc idp]
issuer = $IDP_URL
client-id = $CLIENT_ID
client-secret-file = $T/idp.secret
label = Example ID
EOF
    APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $G/karidns-webadmin.conf"
    $APP --create-admin admin > "$G/admin.out" 2> "$G/admin.err" || bad "--create-admin" "$(cat "$G/admin.err")"
    ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$G/admin.out")
    $APP >> "$G/server.log" 2>&1 &
    SRV=$!
    if wait_started "$G/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$G/server.log")"; exit 1; fi
    gui_run_driver "sign-in with a provider, SQLite3" "$G/browser" webadmin/test/e2e/gui_oidc.mjs GUI_BASE="http://127.0.0.1:$PORT" GUI_IDP="$IDP_URL" GUI_ADMIN_PASSWORD="$ADMIN_PW"
    stop_server
    grep -Eq '^[^ ]+ error ' "$G/server.log" && bad "the service logged an error" "$(grep ' error ' "$G/server.log" | head -3)" || ok "the service logged no error"
    if grep -Fq "$CLIENT_SECRET" "$G/server.log" || grep -Eq 'karidns_session=|karidns_oidc=|\$scrypt\$' "$G/server.log" || grep -Fq "$ADMIN_PW" "$G/server.log"; then bad "the log holds a secret, cookie, hash or password"; else ok "the log holds no client secret, cookie, hash or password"; fi
    stop_idp
    _w=0; while [ $_w -lt 50 ] && pgrep -f "$T" > /dev/null 2>&1; do sleep 0.1; _w=$((_w + 1)); done   # a process that was just killed may take a moment to go
    if pgrep -f "$T" > /dev/null 2>&1; then bad "a process of the test is still running" "$(pgrep -fl "$T")"; else ok "no process of the test is left"; fi
fi

echo
echo "=== run_webadmin_oidc_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

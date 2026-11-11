#!/bin/sh
# run_webadmin_gui_pg_test.sh - the zone screens of the web interface (webadmin/ui, 0.6.0 item F, milestone M3) in a real browser, on PostgreSQL, with a running karidns.
#
# The scenarios of the zone part of tests/run_webadmin_gui_test.sh (webadmin/test/e2e/gui_zones.mjs) with the API connected as the role karidns_api (row level security on,
# the audit triggers on) and its check runs as the check role: Firefox (headless, a fresh profile that talks to nothing outside this machine) through geckodriver drives
# the zone list and search, the records of a zone in text form (MX round trip), an edit with the preview and the commit, the update button (a request in
# karidns_reload_requests, the loader reloads, `dag` sees the change; the page counts the servers that have applied it), conflicts made behind the page, refusals told at the
# record set, a draft that survives the end of the session, a subdomain master, new zones (template, form, zone file), import and export, settings and metadata, a zone
# deleted after its name is typed again, DNSSEC (keys, DS, the countdown, key requests), zones that are read only, the servers, hostile zone data, the keyboard alone.
# Milestone M4 adds the versions with a rollback (a change made with psql as the owner is marked and is a conflict), templates, the administration, what a domain master and
# a subdomain master see under row level security, and the audit log.
# Environment: ZONE, KARICHECK, KARIDNS, LOADER, DAG, NODE, FIREFOX and GECKODRIVER (default: from PATH), GUI_MAX_RSS_MIB (the resident size, in MiB, at which the browser is
# killed; default 4096), KEEP=1 to keep the work directory.  Needs root and an unprivileged PostgreSQL user (KARIDNS_TEST_PG_USER); SKIP (exit 0, with the reason) when
# PostgreSQL is not reachable (tests/db/pg_lib.sh), the role may not create roles, the password login over 127.0.0.1 is not accepted, node 22.13 or newer,
# webadmin/node_modules/pg (npm ci --ignore-scripts in webadmin/), Firefox, geckodriver, fonts or a binary is missing.  One browser, scenarios in sequence.  About 4 minutes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
KARIDNS=${KARIDNS:-$ROOT/karidns}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
DAG=${DAG:-$ROOT/dag}
for v in ZONE KARICHECK KARIDNS LOADER DAG; do eval "p=\$$v"; case $p in /*) ;; *) eval "$v=$ROOT/\${p#./}" ;; esac; done
[ "$(id -u)" = "0" ] || { echo "SKIP: needs root (the server drops to nobody; the loader must be root-owned)"; exit 0; }
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed"; exit 0; }
[ -d webadmin/node_modules/pg ] || { echo "SKIP: webadmin/node_modules/pg is missing (run npm ci --ignore-scripts in webadmin/)"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
for b in "$ZONE" "$KARICHECK" "$KARIDNS" "$LOADER" "$DAG" ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
"$ZONE" --version | grep -q postgresql || { echo "SKIP: $ZONE has no PostgreSQL driver"; exit 0; }
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_guipg.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""; WEB=""; ROLES=""; GUI_MEM=""
cleanup() {
    [ -n "$GUI_MEM" ] && kill "$GUI_MEM" 2>/dev/null
    [ -n "$WEB" ] && kill -TERM "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$WEB" ] && kill -KILL "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    # (nothing of the browser may stay: geckodriver and Firefox are children of the driver script, which stops them; this is for a script that was killed)
    for p in $(pgrep -f "$T" 2>/dev/null); do kill -KILL "$p" 2>/dev/null; done
    pg_cleanup
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    chmod -R u+rwx "$T" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM
pg_setup webadmingui || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader and the API cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
GUI_DPORT=$(kari_port 2 $((22000 + $$ % 20000 + 2)))
. "$ROOT/tests/lib_webadmin_gui.sh"
gui_browser_check || exit 0

RA=kwg_api_$$; RK=kwg_chk_$$; ROLES="$RA $RK"
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

mkdir -p "$T/app/webadmin" "$T/app/node" "$T/zones"
cp "$ZONE" "$T/karidns-zone-real"; cp "$KARICHECK" "$T/karicheck"; cp ./karictl "$T/karictl"; chmod 755 "$T/karidns-zone-real" "$T/karicheck" "$T/karictl"
cp -R webadmin/bin webadmin/lib webadmin/ui webadmin/package.json webadmin/node_modules "$T/app/webadmin/" && cp -R node/lib "$T/app/node/" && chmod -R a+rX "$T/app"
cp webadmin/test/e2e/zones/*.zone "$T/zones/" && chmod 644 "$T/zones/"*.zone
mkci() { printf '%s\n' "$2" > "$1"; chown "$PG_AS" "$1"; chmod 600 "$1"; }
mkci "$T/ci_owner" "host=$PGSOCK port=$PORT_PG user=$OWNER dbname=$PGDB"
mkci "$T/ci_api" "$(rc_of $RA)"
mkci "$T/ci_check" "$(rc_of $RK)"
pg_conninfo_file "$T/ci_loader"
mkdir "$T/web"; chown "$PG_AS" "$T/web"
for z in example.test dskey.example.com xss.test; do
    as_pg "$T/karidns-zone-real" import --no-config --conninfo-file "$T/ci_owner" "$z" "$T/zones/$z.zone" > "$T/import.out" 2>&1 && ok "$z is imported (as the owner)" || bad "import of $z" "$(cat "$T/import.out")"
done
# dskey.example.com is kept by the signer: its marker, the key of RFC 4034 section 5.4 (a key signing key: key tag 60486) and the signer's state (signed a day ago, the first signature runs out in five days)
DNSKEY_B64='AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw=='
pq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'dskey.example.com'" > /dev/null
pq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'dskey.example.com', 'DNSKEY', '257 3 5 $DNSKEY_B64', 3600, 0, false FROM domains WHERE name = 'dskey.example.com'" > /dev/null
pq "INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts, last_error) SELECT id, now() - interval '1 day', 1, now() + interval '5 days', now() + interval '1 hour', 2, 'could not sign <b>x</b>' FROM domains WHERE name = 'dskey.example.com'" > /dev/null && ok "the signer's zone has its key and its state" || bad "the fixtures of the signer's zone"

# ---------------------------------------------------------------- karidns and its loader (the loader reads as the owner: row level security does not bind it)
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
WPORT=$(kari_port 1 $((PORT + 1)))
b64() { printf '%s' "$1" | openssl base64 -A; }
MAIN_SECRET=$(b64 "gp-test-main-secret-0123456789abc")
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karidns.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci_loader"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; };
};
control-channel { socket "$T/ctl.sock"; secret "$MAIN_SECRET"; };
EOF
chmod 644 "$T/karidns.conf"
"$KARIDNS" -c "$T/karidns.conf" -f > "$T/karidns.log" 2>&1 &
SRV=$!
if kari_wait_log "$T/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$T/karidns.log")"; exit 1; fi
# zones the servers are not told about: a secondary zone and a zone signed elsewhere (the API only reads them)
pq "INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.99')" > /dev/null
pq "INSERT INTO domains (name, type) VALUES ('pre.test', 'NATIVE')" > /dev/null
pq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.' || name || ' hostmaster.' || name || ' 1 7200 3600 1209600 300', 300, 0, false FROM domains WHERE name IN ('slave.test', 'pre.test')" > /dev/null
pq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'pre.test'" > /dev/null && ok "a secondary zone and a zone signed elsewhere are in the database" || bad "the fixtures of the read-only zones"

# ---------------------------------------------------------------- the API, as the unprivileged user
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
listen = 127.0.0.1:$WPORT
public-origin = http://127.0.0.1:$WPORT
database = pg
api-conninfo-file = $T/ci_api
check-conninfo-file = $T/ci_check
totp-key-file = $T/web/totp.key
karidns-zone = $T/karidns-zone-real
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
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
WEB=$(cat "$T/web/server.pid" 2>/dev/null)
if grep -q "karidns-webadmin [^ ]* started" "$T/server.log"; then ok "the API started (pid $WEB)"; else bad "the API did not start" "$(cat "$T/server.log")"; exit 1; fi

echo "-- the browser (webadmin/test/e2e/gui_zones.mjs)"
# (a change made behind the API's back, as the owner: the history screens mark it)
printf '#!/bin/sh\nexec psql -X -q -At -v ON_ERROR_STOP=1 "%s" -c "$1"\n' "$PGC" > "$T/sql.sh"; chmod 755 "$T/sql.sh"
gui_run_driver "zone screens, PostgreSQL" "$T/browser" webadmin/test/e2e/gui_zones.mjs GUI_BASE="http://127.0.0.1:$WPORT" GUI_ADMIN_PASSWORD="$ADMIN_PW" GUI_DNS_PORT="$PORT" GUI_DAG="$DAG" GUI_DB=pg GUI_SQL="$T/sql.sh"
[ "$GUI_RC" = 3 ] && exit 0

echo "-- PostgreSQL: what the API left in the database"
[ "$(pq "SELECT count(*) FROM karidns_reload_requests WHERE zone IN ('example.test', 'new.test', 'tpl.test')")" -ge 1 ] && ok "the reload request of the update button is there (zone by zone)" || bad "no reload request of the update button"
[ "$(pq "SELECT count(*) FROM karidns_reload_requests WHERE zone = 'dskey.example.com'")" = 0 ] && ok "none for the zone the signer keeps" || bad "a reload request for the signer's zone"
same "the loader applied them (karidns_server_status is ok)" "$(pq "SELECT bool_and(ok)::text FROM karidns_server_status")" true
same "the audit log names the API role and the principal for the change sets" "$(pq "SELECT count(*) > 0 FROM karidns_auth.audit_log WHERE principal_name = 'dom' AND db_role = '$RA' AND table_name = 'records' AND change_set IS NOT NULL")" t
same "the zone versions are there (the edits of the page are versions)" "$(pq "SELECT count(*) >= 3 FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'example.test'")" t
same "the deleted zone left nothing behind (rows, grants)" "$(pq "SELECT count(*) FROM domains WHERE name = 'form.test'")|$(pq "SELECT count(*) FROM karidns_auth.grants WHERE zone_name = 'form.test'")" "0|0"
same "the key request of the page is a row of the table" "$(pq "SELECT count(*) FROM karidns_key_requests r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'example.test' AND r.state = 'pending'")" 1

echo "-- afterwards"
kill -TERM "$WEB" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$WEB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$WEB" 2>/dev/null; then bad "the API did not stop after SIGTERM"; kill -KILL "$WEB" 2>/dev/null; else ok "the API stops on SIGTERM"; fi
WEB=""
grep -q "ERROR\|assertion\|Assertion" "$T/karidns.log" && bad "karidns logged an error" "$(grep 'ERROR\|ssertion' "$T/karidns.log" | head -3)" || ok "karidns logged no error"
kari_kill_tree "$SRV"; SRV=""
_w=0; while [ $_w -lt 50 ] && pgrep -f "$T" > /dev/null 2>&1; do sleep 0.1; _w=$((_w + 1)); done   # a process that was just killed may take a moment to go
if pgrep -f "$T" > /dev/null 2>&1; then bad "a process of the test is still running" "$(pgrep -fl "$T")"; else ok "no process of the test is left"; fi
grep -q "(a bug)" "$T/server.log" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$T/server.log" | head -3)" || ok "row level security never disagreed with the API"
grep -Eq '^[^ ]+ error ' "$T/server.log" && bad "the API logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the API logged no error"
if grep -Eq 'karidns_session=|\$scrypt\$|kdt_|dora quartz lantern|sam granite pine|delta echo foxtrot|a new person 12345|wrong password 1234|hello from the web interface' "$T/server.log" || grep -Fq "$PW" "$T/server.log" || grep -Fq "$ADMIN_PW" "$T/server.log"; then bad "the log holds a password, cookie, hash, token or record data"; else ok "the log holds no password, cookie, hash, token or record data"; fi
[ -d "$T/browser" ] && ok "the profile, the downloads and the log of the browser are in the work directory" || bad "no work directory of the browser"

echo
echo "=== run_webadmin_gui_pg_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

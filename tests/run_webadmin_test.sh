#!/bin/sh
# run_webadmin_test.sh - karidns-webadmin (webadmin/, 0.6.0 items D and E, milestone M2: the Node service, authentication and the read side) on SQLite3.
#
# Sets up a zone file (the PowerDNS schema, db/karidns_ext.sqlite3.sql, db/karidns_audit.sqlite3.sql; example.test and other.test imported by karidns-zone) and
# an auth file (db/karidns_auth.sqlite3.sql, mode 0600), makes the first administrator with `karidns-webadmin --create-admin`, starts the real server on a real
# port and runs webadmin/test/it.mjs against it: the login with TOTP enrolment, users / groups / policies / grants, what a global, a domain and a subdomain
# master see (the label boundary), the paging of RRsets, the export through karidns-zone, no escalation, the audit log, tokens, CSRF and Origin, the lockout, the
# idle time of a session, a disabled user, the rate limit.  On SQLite3 these checks of the API are the only checks (docs/karidns-api.md).  Also: --check and its
# complaint about a mode of the auth file, --create-admin twice, SIGTERM, and that the log holds no secret.
# Environment: ZONE (default ./karidns-zone), KARICHECK (default ./karicheck), NODE.  SKIP (exit 0, with the reason) without node 22.13, the sqlite3 tool or the
# binaries.  Runs as any user.  About 40 seconds.
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
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
[ -x "$ZONE" ] && [ -x "$KARICHECK" ] || { echo "SKIP: $ZONE or $KARICHECK is not built"; exit 0; }
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin.XXXXXX") || exit 1
SRV=""
cleanup() {
    if [ -n "$SRV" ]; then kill -KILL "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; fi
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

DB=$T/zones.sqlite3
AUTH=$T/auth.sqlite3
cp "$ZONE" "$T/karidns-zone"
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
chmod 600 "$AUTH"
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
for z in example.test other.test; do
    "$ZONE" import --no-config --sqlite3 "$DB" "$z" "$T/$z.zone" > "$T/import.out" 2>&1 && ok "$z is imported" || bad "import of $z" "$(cat "$T/import.out")"
done

PORT=$(kari_port 0 $((21000 + $$ % 20000)))
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
# karidns-webadmin test configuration (SQLite3)
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
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
APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $CONF"

echo "-- the command line"
$APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine on a good setup" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
grep -q "schema version 3, all tables there" "$T/check.out" && ok "...and says so about the schema" || bad "--check output" "$(cat "$T/check.out")"
chmod 644 "$AUTH"
$APP --check > /dev/null 2> "$T/check.err" && bad "--check accepts an auth file with mode 0644" || ok "--check refuses an auth file that others can read"
grep -q "it must be 0600" "$T/check.err" && ok "...and says why" || bad "--check reason" "$(cat "$T/check.err")"
chmod 600 "$AUTH"
$APP --create-admin admin > "$T/admin.out" 2> "$T/admin.err" && ok "--create-admin makes the first administrator" || bad "--create-admin" "$(cat "$T/admin.err")"
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
[ -n "$ADMIN_PW" ] && ok "...and shows a password once" || bad "no password in the output" "$(cat "$T/admin.out")"
$APP --create-admin admin > /dev/null 2> "$T/admin2.err" && bad "--create-admin twice" || ok "a second --create-admin of the same name is refused"
$NODE webadmin/bin/karidns-webadmin.js -c "$T/nonexistent.conf" --check > /dev/null 2> "$T/e.err" && bad "--check with a missing file" || ok "a missing configuration file is an error"

echo "-- the server"
$APP >> "$T/server.log" 2>&1 &
SRV=$!
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
if grep -q "karidns-webadmin [^ ]* started" "$T/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$T/server.log")"; exit 1; fi

IT_BASE="http://127.0.0.1:$PORT/api/v1" IT_ORIGIN="http://127.0.0.1:$PORT" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_SESSION_IDLE=8 "$NODE" webadmin/test/it.mjs > "$T/it.out" 2>&1
IT_RC=$?
cat "$T/it.out"
[ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it.mjs)" || bad "the integration scenarios failed"

echo "-- afterwards"
kill -TERM "$SRV" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then bad "the server did not stop after SIGTERM"; kill -KILL "$SRV" 2>/dev/null; else wait "$SRV" 2>/dev/null; same "the server stops on SIGTERM with status 0" "$?" 0; fi
SRV=""
grep -q "stopped" "$T/server.log" && ok "...and says so" || bad "no 'stopped' in the log"
if grep -Fq "$ADMIN_PW" "$T/server.log" || grep -Eq 'Sunrise-Harbor|Maple-Anchor|Violet-Lantern|Cobalt-Ranger|a new password|karidns_session=|\$scrypt\$' "$T/server.log"; then bad "the log holds a password, cookie or hash"; else ok "the log holds no password, cookie or hash"; fi
grep -q "kdt_" "$T/server.log" && bad "the log holds a token" || ok "...and no token"
grep -q "auth: admin logged in" "$T/server.log" && ok "logins are logged (user and address)" || bad "no login line in the log"
grep -Eq '^.* error ' "$T/server.log" && bad "the server logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the server logged no error"
same "the actor row of the auth file is gone (nobody is writing)" "$(sqlite3 "$AUTH" 'SELECT count(*) FROM karidns_auth_actor')" 0
[ "$(sqlite3 "$AUTH" "SELECT count(*) FROM karidns_auth_audit WHERE principal_name = 'admin'")" -gt 0 ] && ok "the changes of the administrator are in the audit of the auth file under its name" || bad "no audit row names the administrator"
same "no password hash in the audit of the auth file" "$(sqlite3 "$AUTH" "SELECT count(*) FROM karidns_auth_audit WHERE before LIKE '%scrypt%' OR after LIKE '%scrypt%'")" 0

echo
echo "=== run_webadmin_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

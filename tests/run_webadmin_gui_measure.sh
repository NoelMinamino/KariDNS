#!/bin/sh
# run_webadmin_gui_measure.sh - what the web interface costs in a browser (0.6.0 item F, milestone M6; planning 8.2 "measured once"): loading the GUI, the records of a zone of
# BIG records (default 100000) a page at a time, the search, the preview and the commit of one record set.  SQLite3, one browser (Firefox headless through geckodriver, the
# memory watchdog of tests/lib_webadmin_gui.sh on), a global master with TOTP off, the service and the browser on the same host.  Not part of the suite: it measures, it
# does not test (webadmin/test/e2e/gui_measure.mjs prints the "[MEAS]" lines; docs/karidns-webadmin-gui.md "Measurements" has the numbers of the last run).
# Environment: BIG (records of big.test, default 100000), ZONE (./karidns-zone), KARICHECK (./karicheck), NODE, FIREFOX, GECKODRIVER, GUI_MAX_RSS_MIB (default 4096), KEEP=1.
# SKIP (exit 0, with the reason) without node 22.13, the sqlite3 tool, the binaries, Firefox, geckodriver or fonts.  Runs as any user.  About two minutes at 100000.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
BIG=${BIG:-100000}
case $ZONE in /*) ;; *) ZONE=$ROOT/${ZONE#./} ;; esac
case $KARICHECK in /*) ;; *) KARICHECK=$ROOT/${KARICHECK#./} ;; esac
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
[ -x "$ZONE" ] && [ -x "$KARICHECK" ] || { echo "SKIP: $ZONE or $KARICHECK is not built"; exit 0; }
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_measure.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""; GUI_MEM=""
cleanup() {
    [ -n "$GUI_MEM" ] && kill "$GUI_MEM" 2>/dev/null
    if [ -n "$SRV" ]; then kill -TERM "$SRV" 2>/dev/null; sleep 0.3; kill -KILL "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; fi
    for p in $(pgrep -f "$T" 2>/dev/null); do kill -KILL "$p" 2>/dev/null; done
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
. "$ROOT/tests/lib_webadmin_gui.sh"
gui_browser_check || exit 0

DB=$T/zones.sqlite3
AUTH=$T/auth.sqlite3
cp "$ZONE" "$T/karidns-zone"
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
chmod 600 "$AUTH"
awk -v n="$BIG" 'BEGIN { print "$ORIGIN big.test."; print "$TTL 300"; print "@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300"; print "@ IN NS ns1"; print "ns1 IN A 192.0.2.1";
    for (i = 0; i < n / 2; i++) printf "h%d IN A 10.%d.%d.%d\ns%d.sub1 IN TXT \"x%d\"\n", i, int(i / 65536) % 256, int(i / 256) % 256, i % 256, i, i }' > "$T/big.zone"
s=$(date +%s)
"$ZONE" import --no-config --sqlite3 "$DB" big.test "$T/big.zone" > "$T/import.out" 2>&1 && ok "big.test is imported (about $BIG records, $(( $(date +%s) - s )) s)" || { bad "import of big.test" "$(tail -3 "$T/import.out")"; exit 1; }
rm -f "$T/big.zone"
sleep 1

PORT=$(kari_port 0 $((22000 + $$ % 20000)))
GUI_DPORT=$(kari_port 1 $((PORT + 1)))
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
# karidns-webadmin measurement configuration (SQLite3, the web interface)
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $T/totp.key
karidns-zone = $T/karidns-zone
karicheck = $KARICHECK
scrypt-ln = 14
require-totp = none
session-idle = 120
rate-login = 100
rate-api = 1000
rate-write = 1000
log = stderr
EOF
APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $CONF"
$APP --create-admin admin > "$T/admin.out" 2> "$T/admin.err" || { bad "--create-admin" "$(cat "$T/admin.err")"; exit 1; }
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
$APP >> "$T/server.log" 2>&1 &
SRV=$!
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin 0.6.0 started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
grep -q "karidns-webadmin 0.6.0 started" "$T/server.log" && ok "the server started (pid $SRV)" || { bad "the server did not start" "$(cat "$T/server.log")"; exit 1; }
echo "-- $("$NODE" --version), $("$FIREFOX" --version 2>/dev/null | head -1), $(uname -sr)"

echo "-- the browser (webadmin/test/e2e/gui_measure.mjs), BIG=$BIG"
gui_run_driver "measurements" "$T/browser" "$ROOT/webadmin/test/e2e/gui_measure.mjs" GUI_BASE="http://127.0.0.1:$PORT" GUI_ADMIN_PASSWORD="$ADMIN_PW" GUI_BIG="$BIG"
[ "${GUI_RC:-1}" = 3 ] && exit 0

kill -TERM "$SRV" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2>/dev/null && { bad "the server did not stop after SIGTERM"; kill -KILL "$SRV" 2>/dev/null; } || { wait "$SRV" 2>/dev/null; ok "the server stops on SIGTERM"; }
SRV=""
if pgrep -f "$T" > /dev/null 2>&1; then bad "a process of the test is still running" "$(pgrep -fl "$T")"; else ok "no process of the browser is left"; fi
echo
echo "=== run_webadmin_gui_measure: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

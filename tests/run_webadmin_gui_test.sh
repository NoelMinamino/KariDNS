#!/bin/sh
# run_webadmin_gui_test.sh - the web interface of karidns-webadmin (webadmin/ui, 0.6.0 item F, milestone M2) in a real browser, on SQLite3.
#
# Sets up the same files as run_webadmin_test.sh (a zone file, an auth file, the first administrator), starts the real service on a real port with the files of
# webadmin/ui, and drives Firefox (headless, a fresh profile that talks to nothing outside this machine) through geckodriver with webadmin/test/e2e/gui.mjs: the
# sign-in and its refusals, the TOTP enrolment of a global master (the QR code, the key hidden until asked for), the second sign-in with a code, API tokens, the
# password, the keyboard alone, "log out everywhere" in a second tab, the idle warning and the end of the session (no request on its own), the language, hostile
# texts in names (nothing runs), the rate limit, the labels of every screen, the policy of the page (every resource of the origin, a violation reported).
# Environment: ZONE (./karidns-zone), KARICHECK (./karicheck), NODE, FIREFOX and GECKODRIVER (default: from PATH), GUI_MAX_RSS_MIB (the resident size, in MiB, at which the browser is killed; default 4096), KEEP=1 to keep the work directory.
# SKIP (exit 0, with the reason) without node 22.13, the sqlite3 tool, the binaries, Firefox,
# geckodriver (or one that cannot run: see webadmin/test/e2e/patch_geckodriver.mjs for a 15.0 userland), or fonts (Firefox crashes without any: pkg install dejavu).
# Runs as any user (the browser too: a root-owned HOME is made for it).  One browser, scenarios in sequence.  About a minute.
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
FIREFOX=${FIREFOX:-$(command -v firefox 2>/dev/null)}
GECKODRIVER=${GECKODRIVER:-$(command -v geckodriver 2>/dev/null)}
[ -n "$FIREFOX" ] && [ -x "$FIREFOX" ] || { echo "SKIP: Firefox is not installed (pkg install firefox)"; exit 0; }
[ -n "$GECKODRIVER" ] && [ -x "$GECKODRIVER" ] || { echo "SKIP: geckodriver is not installed (pkg install geckodriver)"; exit 0; }
"$FIREFOX" --version > /dev/null 2>&1 || { echo "SKIP: $FIREFOX does not run"; exit 0; }
# (Firefox crashes at the start when the system has no font at all)
if command -v fc-list > /dev/null 2>&1 && [ -z "$(fc-list 2>/dev/null | head -1)" ]; then echo "SKIP: the system has no fonts (pkg install dejavu)"; exit 0; fi

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_gui.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""; MEM=""
cleanup() {
    [ -n "$MEM" ] && kill "$MEM" 2>/dev/null
    if [ -n "$SRV" ]; then kill -TERM "$SRV" 2>/dev/null; sleep 0.3; kill -KILL "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; fi
    # (nothing of the browser may stay: geckodriver and Firefox are children of the driver script, which stops them; this is for a script that was killed)
    for p in $(pgrep -f "$T" 2>/dev/null); do kill -KILL "$p" 2>/dev/null; done
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

# a geckodriver of a 15.1 build does not start on a 15.0 userland (FBSD_1.9): use a patched copy
if ! "$GECKODRIVER" --version > /dev/null 2>&1; then
    if "$NODE" webadmin/test/e2e/patch_geckodriver.mjs "$GECKODRIVER" "$T/geckodriver" > /dev/null 2>&1 && "$T/geckodriver" --version > /dev/null 2>&1; then
        GECKODRIVER=$T/geckodriver
        ok "geckodriver needed a patched copy (libc of this userland is older than the package's)"
    else
        echo "SKIP: $GECKODRIVER does not run here"; exit 0
    fi
fi

DB=$T/zones.sqlite3
AUTH=$T/auth.sqlite3
cp "$ZONE" "$T/karidns-zone"
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
chmod 600 "$AUTH"

PORT=$(kari_port 0 $((22000 + $$ % 20000)))
DPORT=$(kari_port 1 $((PORT + 1)))
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
# karidns-webadmin test configuration (SQLite3, the web interface)
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
session-idle = 30
rate-login = 20
rate-api = 1000
rate-write = 1000
log = stderr
EOF
APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $CONF"
$APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine, and reports the files of the web interface" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
grep -q "^ok: ui " "$T/check.out" && ok "...it names the files" || bad "--check does not name the files of the web interface" "$(cat "$T/check.out")"
$APP --create-admin admin > "$T/admin.out" 2> "$T/admin.err" || bad "--create-admin" "$(cat "$T/admin.err")"
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
$APP >> "$T/server.log" 2>&1 &
SRV=$!
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin 0.6.0 started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
if grep -q "karidns-webadmin 0.6.0 started" "$T/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$T/server.log")"; exit 1; fi

# the page, with a plain HTTP client first: the headers of the GUI
if command -v curl > /dev/null 2>&1; then
    curl -sS -D "$T/page.hdr" -o "$T/page.html" "http://127.0.0.1:$PORT/" && grep -qi "^content-security-policy: default-src 'none'" "$T/page.hdr" && grep -q '<script type="module" src="/ui/js/app.js">' "$T/page.html" && ok "GET / is the page, with the policy of the GUI" || bad "GET /" "$(cat "$T/page.hdr")"
fi

# The memory of the browser: the host is a jail on a shared machine (an earlier benchmark made it kill other jails), and a limit on the address space (ulimit -v) stops
# Firefox from starting, so the resident size of everything below the driver (geckodriver, Firefox, its helpers) is read every two seconds, written down (it is the
# measurement of plan section 14, assumption 2) and the whole tree is killed when it passes GUI_MAX_RSS_MIB (default 4096).
tree() {
    ps -axo pid,ppid,rss 2>/dev/null | awk -v root="$1" '
        NR > 1 { pp[$1] = $2; rs[$1] = $3; all[NR] = $1 }
        END {
            mine[root] = 1
            do { n = 0; for (i in all) { p = all[i]; if (!(p in mine) && (pp[p] in mine)) { mine[p] = 1; n++ } } } while (n)
            sum = 0; list = ""
            for (p in mine) { sum += rs[p]; if (p != root) list = list " " p }
            print sum list
        }'
}

echo "-- the browser (webadmin/test/e2e/gui.mjs)"
GUI_BASE="http://127.0.0.1:$PORT" GUI_ADMIN_PASSWORD="$ADMIN_PW" GUI_DIR="$T/browser" GUI_GECKODRIVER="$GECKODRIVER" GUI_FIREFOX="$FIREFOX" GUI_DRIVER_PORT="$DPORT" \
    MOZ_HEADLESS=1 "$NODE" webadmin/test/e2e/gui.mjs > "$T/gui.out" 2>&1 &
GPID=$!
(
    while kill -0 "$GPID" 2>/dev/null; do
        set -- $(tree "$GPID")
        sum=$1; shift
        echo "$sum" >> "$T/mem.log"
        if [ "$sum" -gt $((${GUI_MAX_RSS_MIB:-4096} * 1024)) ]; then
            echo "the browser passed ${GUI_MAX_RSS_MIB:-4096} MiB resident ($((sum / 1024)) MiB) and was killed" >> "$T/mem.cap"
            kill -KILL "$@" 2>/dev/null
        fi
        sleep 2
    done
) &
MEM=$!
wait "$GPID"
GUI_RC=$?
cat "$T/gui.out"
kill "$MEM" 2>/dev/null; MEM=""
[ -f "$T/mem.cap" ] && bad "$(cat "$T/mem.cap")"
if [ $GUI_RC = 3 ]; then echo "SKIP: the browser did not start (see above)"; exit 0; fi
[ $GUI_RC = 0 ] && ok "the browser scenarios (webadmin/test/e2e/gui.mjs)" || bad "the browser scenarios failed"
PEAK=$(sort -n "$T/mem.log" 2>/dev/null | tail -1)
[ -n "$PEAK" ] && echo "  [MEM ] peak resident size of the driver, Firefox and geckodriver together: $((PEAK / 1024)) MiB"
[ -d "$T/browser/shots" ] && [ -n "$(ls "$T/browser/shots" 2>/dev/null)" ] && echo "  (pictures of the failures: $T/browser/shots; run with KEEP=1 to keep them)"

echo "-- afterwards"
kill -TERM "$SRV" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then bad "the server did not stop after SIGTERM"; kill -KILL "$SRV" 2>/dev/null; else wait "$SRV" 2>/dev/null; [ $? = 0 ] && ok "the server stops on SIGTERM with status 0" || bad "the server stopped with a status"; fi
SRV=""
if pgrep -f "$T" > /dev/null 2>&1; then bad "a process of the test is still running" "$(pgrep -fl "$T")"; else ok "no process of the browser is left"; fi
grep -Eq '^[^ ]+ error ' "$T/server.log" && bad "the server logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the server logged no error"
if grep -Eq 'karidns_session=|\$scrypt\$|kdt_|JBSWY|alpha bravo charlie|delta echo foxtrot|a long enough new password' "$T/server.log"; then bad "the log holds a password, cookie, hash, token or secret"; else ok "the log holds no password, cookie, hash, token or secret"; fi
# nothing outside the work directory: the browser's profile, downloads and geckodriver's log are all in $T
[ -d "$T/browser" ] && ok "the profile, the downloads and the log of the browser are in the work directory" || bad "no work directory of the browser"

echo
echo "=== run_webadmin_gui_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

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
#
# Milestone M3 adds a second part, the zone screens (webadmin/test/e2e/gui_zones.mjs), which needs root: a REAL karidns with its loader (as in run_webadmin_write_test.sh)
# serves the zones behind a second service, so that the update button is checked with `dag`: the zone list and search, the records of a zone in text form (MX round trip),
# an edit with the preview and the commit, the update button (the servers know nothing before it), conflicts made behind the page (both ways out, in English and Japanese),
# refusals told at the record set, a draft that survives the end of the session, a subdomain master, a new zone from a template / a form / a zone file, import (merge, replace,
# a file that is not UTF-8) and export (the downloaded file), settings and metadata, a zone deleted after its name is typed again, DNSSEC (keys, DS, the countdown, key
# requests), zones that are read only, hostile zone data (nothing runs), the keyboard alone.  Milestone M4 adds to the same driver the versions of a zone with a rollback
# (a change made behind the API's back with sqlite3 is marked and is a conflict that needs the question about force), templates (the real karicheck), the administration
# (users, a group, grants, the TOTP reset and the unlock, policies), what a domain master and a subdomain master see, and the audit log.  Without root that part prints SKIP.  The same part runs on PostgreSQL in
# run_webadmin_gui_pg_test.sh.  Environment: KARIDNS (./karidns), LOADER (./karidns-dbloader), DAG (./dag).
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
SRV=""; MEM=""; GUI_MEM=""; ZWEB=""; ZSRV=""
cleanup() {
    [ -n "$MEM" ] && kill "$MEM" 2>/dev/null
    [ -n "$GUI_MEM" ] && kill "$GUI_MEM" 2>/dev/null
    if [ -n "$ZWEB" ]; then kill -TERM "$ZWEB" 2>/dev/null; sleep 0.3; kill -KILL "$ZWEB" 2>/dev/null; fi
    [ -n "$ZSRV" ] && kari_kill_tree "$ZSRV"
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
GUI_DPORT=$DPORT
. "$ROOT/tests/lib_webadmin_gui.sh"
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
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
if grep -q "karidns-webadmin [^ ]* started" "$T/server.log"; then ok "the server started (pid $SRV)"; else bad "the server did not start" "$(cat "$T/server.log")"; exit 1; fi

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

if [ -n "${GUI_ZONES_ONLY:-}" ]; then
    echo "-- (GUI_ZONES_ONLY: the part of milestone M2 is not run)"
else
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
fi

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

# ======================================================================================================================================================================
# Part two, milestone M3: the zone screens with a real karidns behind the service (the setup of run_webadmin_write_test.sh)
# ======================================================================================================================================================================
echo "-- the zone screens (webadmin/test/e2e/gui_zones.mjs): a real karidns, its loader and dag"
KARIDNS=${KARIDNS:-$ROOT/karidns}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
DAG=${DAG:-$ROOT/dag}
for v in KARIDNS LOADER DAG; do eval "p=\$$v"; case $p in /*) ;; *) eval "$v=$ROOT/\${p#./}" ;; esac; done
ZSKIP=""
[ "$(id -u)" = "0" ] || ZSKIP="needs root (the server drops to nobody; the loader must be root-owned)"
[ -n "$ZSKIP" ] || id nobody >/dev/null 2>&1 || ZSKIP="no user nobody"
if [ -z "$ZSKIP" ]; then for b in "$KARIDNS" "$LOADER" "$DAG" ./karictl; do [ -x "$b" ] || { ZSKIP="$b is not built"; break; }; done; fi
[ -n "$ZSKIP" ] || "$LOADER" --drivers | grep -qx sqlite3 || ZSKIP="$LOADER has no SQLite3 driver"
if [ -n "$ZSKIP" ]; then
    echo "SKIP: the zone screens: $ZSKIP"
else
    Z=$T/z
    mkdir -p "$Z/db" "$Z/ctl"; chmod 777 "$Z/db" "$Z/ctl"
    ZDB=$Z/db/zones.sqlite3
    ZAUTH=$Z/auth.sqlite3
    sqlite3 "$ZDB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$ZDB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$ZDB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
    sqlite3 "$ZAUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
    chmod 600 "$ZAUTH"; chmod 666 "$ZDB"
    for z in example.test dskey.example.com xss.test; do
        "$ZONE" import --no-config --sqlite3 "$ZDB" "$z" "webadmin/test/e2e/zones/$z.zone" > "$Z/import.out" 2>&1 && ok "$z is imported" || bad "import of $z" "$(cat "$Z/import.out")"
    done
    # dskey.example.com is kept by the signer: its marker, the key of RFC 4034 section 5.4 (a key signing key: key tag 60486) and the signer's state (signed a day ago, the first signature runs out in five days)
    DNSKEY_B64='AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw=='
    sqlite3 "$ZDB" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'dskey.example.com';
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'dskey.example.com', 'DNSKEY', '257 3 5 $DNSKEY_B64', 3600, 0, 0 FROM domains WHERE name = 'dskey.example.com';
        INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts, last_error) SELECT id, CAST(strftime('%s', 'now') AS INTEGER) - 86400, 1, CAST(strftime('%s', 'now') AS INTEGER) + 5 * 86400, CAST(strftime('%s', 'now') AS INTEGER) + 3600, 2, 'could not sign <b>x</b>' FROM domains WHERE name = 'dskey.example.com'" && ok "the signer's zone has its key and its state" || bad "the fixtures of the signer's zone"
    chmod 666 "$ZDB"*

    ZPORT=$(kari_port 2 $((PORT + 2)))
    ZWPORT=$(kari_port 3 $((PORT + 3)))
    b64() { printf '%s' "$1" | openssl base64 -A; }
    MAIN_SECRET=$(b64 "gz-test-main-secret-0123456789abc")
    WEB_SECRET=$(b64 "gz-test-web-secret-0123456789abcd")
    install -o root -g wheel -m 755 "$LOADER" "$Z/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$Z/karidns-dbloader"; chown 0:0 "$Z/karidns-dbloader"; chmod 755 "$Z/karidns-dbloader"; }
    cat > "$Z/karidns.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $ZPORT;
    database { driver sqlite3; database-file "$ZDB"; loader-user "nobody"; loader-path "$Z/karidns-dbloader"; db-reload-timeout 10; };
};
key "web" { algorithm hmac-sha256; secret "$WEB_SECRET"; };
control-channel {
    socket "$Z/ctl.sock";
    secret "$MAIN_SECRET";
    keys { "web" read-only yes allow-commands { reload-zone; }; };
};
EOF
    chmod 644 "$Z/karidns.conf"
    printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$Z/ctl.sock" "$WEB_SECRET" > "$Z/web-karictl.conf"
    chmod 600 "$Z/web-karictl.conf"
    "$KARIDNS" -c "$Z/karidns.conf" -f > "$Z/karidns.log" 2>&1 &
    ZSRV=$!
    if kari_wait_log "$Z/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$Z/karidns.log")"; fi
    # zones the servers are not told about: a secondary zone and a zone signed elsewhere (the API only reads them)
    sqlite3 "$ZDB" "INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.99'); INSERT INTO domains (name, type) VALUES ('pre.test', 'NATIVE');
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.' || name || ' hostmaster.' || name || ' 1 7200 3600 1209600 300', 300, 0, 0 FROM domains WHERE name IN ('slave.test', 'pre.test');
        INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'pre.test'"
    chmod 666 "$ZDB"*

    ZCONF=$Z/karidns-webadmin.conf
    cat > "$ZCONF" <<EOF
listen = 127.0.0.1:$ZWPORT
public-origin = http://127.0.0.1:$ZWPORT
database = sqlite3
sqlite-file = $ZDB
auth-file = $ZAUTH
totp-key-file = $Z/totp.key
karidns-zone = $T/karidns-zone
karicheck = $KARICHECK
karictl = $ROOT/karictl
karictl-config = $Z/web-karictl.conf
scrypt-ln = 14
require-totp = none
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr
EOF
    ZAPP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $ZCONF"
    $ZAPP --check > "$Z/check.out" 2> "$Z/check.err" && ok "--check is fine for the zone screens' service" || bad "--check" "$(cat "$Z/check.err" "$Z/check.out")"
    $ZAPP --create-admin admin > "$Z/admin.out" 2> "$Z/admin.err" || bad "--create-admin" "$(cat "$Z/admin.err")"
    ZADMIN_PW=$(sed -n 's/^password (shown once): //p' "$Z/admin.out")
    $ZAPP >> "$Z/server.log" 2>&1 &
    ZWEB=$!
    i=0
    while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$Z/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    if grep -q "karidns-webadmin [^ ]* started" "$Z/server.log"; then ok "the service started (pid $ZWEB)"; else bad "the service did not start" "$(cat "$Z/server.log")"; fi
    printf '#!/bin/sh\nexec sqlite3 "%s" "$1"\n' "$ZDB" > "$Z/sql.sh"; chmod 755 "$Z/sql.sh"

    gui_run_driver "zone screens, SQLite3" "$Z/browser" webadmin/test/e2e/gui_zones.mjs GUI_BASE="http://127.0.0.1:$ZWPORT" GUI_ADMIN_PASSWORD="$ZADMIN_PW" GUI_DNS_PORT="$ZPORT" \
        GUI_DAG="$DAG" GUI_DB=sqlite GUI_SQL="$Z/sql.sh"

    echo "-- afterwards (the zone screens)"
    kill -TERM "$ZWEB" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$ZWEB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$ZWEB" 2>/dev/null; then bad "the service did not stop after SIGTERM"; kill -KILL "$ZWEB" 2>/dev/null; else wait "$ZWEB" 2>/dev/null; [ $? = 0 ] && ok "the service stops on SIGTERM with status 0" || bad "the service stopped with a status"; fi
    ZWEB=""
    grep -q "(a bug)" "$Z/server.log" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$Z/server.log" | head -3)" || ok "the service never logged a disagreement with the database"
    grep -Eq '^[^ ]+ error ' "$Z/server.log" && bad "the service logged an error" "$(grep ' error ' "$Z/server.log" | head -3)" || ok "the service logged no error"
    if grep -Eq 'karidns_session=|\$scrypt\$|kdt_|dora quartz lantern|sam granite pine|delta echo foxtrot|a new person 12345|wrong password 1234|hello from the web interface' "$Z/server.log" || grep -Fq "$ZADMIN_PW" "$Z/server.log"; then bad "the log holds a password, cookie, hash, token or record data"; else ok "the log holds no password, cookie, hash, token or record data"; fi
    kari_kill_tree "$ZSRV"; ZSRV=""
    grep -q "ERROR\|assertion\|Assertion" "$Z/karidns.log" && bad "karidns logged an error" "$(grep 'ERROR\|ssertion' "$Z/karidns.log" | head -3)" || ok "karidns logged no error"
    if pgrep -f "$T" > /dev/null 2>&1; then bad "a process of the test is still running" "$(pgrep -fl "$T")"; else ok "no process of the test is left"; fi
fi

echo
echo "=== run_webadmin_gui_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

#!/bin/sh
# run_db_hotparts_test.sh - a hot list of several parts, end to end (D1a step 7, design 8.4), with the real karidns, the real karidns-dbloader and SQLite3.
#
# One message of the stream holds at most KDB_MAX_BODY (1 MiB), so a hot list of zones with long names does not fit one HOT_LIST: the Backend sends it in parts
# (0, 1, ..., the last one marked), the loader puts them together (hot_part()), writes its state file and, after a restart, sends it back in parts (WARM_LIST), which
# the Backend puts together again.  8000 zones with names of 140 bytes (160 bytes an entry on the stream: 1.2 MiB) are asked for once each:
#   - the state file holds all 8000 zones (the loader did not lose a part, did not stop at the first one) and the entries need more than one message
#   - the loader did not drop the list ("does not follow")
#   - after a restart the Backend has received all 8000 zones of the list (the parts of the WARM_LIST) and read them
# Needs root (the loader runs as nobody).  SKIP without karidns, dag, karictl, karidns-dbloader (SQLite3), sqlite3 or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=8000
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_hotparts.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 200 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() { [ $FAILS -ne 0 ] && { echo "--- server log"; tail -20 "$T/srv.log" 2>/dev/null; }; stop_srv; rm -rf "$T"; }
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
ST="$T/st/hot.state"

mkdir "$T/db" "$T/st"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" <<SQL
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ - 1))), l(x) AS (SELECT replace(hex(zeroblob(42)), '00', 'x'))
INSERT INTO domains (name, type) SELECT printf('n%05d.', i) || x || '.' || x || '.' || x || '.test', 'NATIVE' FROM n, l;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
SQL
sqlite3 "$T/db/z.db" "SELECT name FROM domains ORDER BY id" | awk '{ print "www." $0 }' > "$T/names"
chown -R nobody "$T/db" "$T/st"; chmod 600 "$T/db/z.db"*; chmod 700 "$T/st"
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               memory-limit 512m; loader-state-file "$ST"; hot-list-interval 1; hot-list-size 10000; fetch-rate 100000; park-timeout 10000; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
start_srv() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete ($((i / 10)) s, $NZ zones)" || { fail "no 'initial load complete' after $((i / 10)) s"; tail -20 "$T/srv.log"; }
}
waitfor() {   # waitfor SECONDS COMMAND...
    w=$1; shift
    i=0
    while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
state_done() { tail -1 "$ST" 2>/dev/null | grep -q "^END $NZ [0-9a-f]\{8\}\$"; }

echo "== every zone is asked for once; the hot list is written in parts"
start_srv
R=$(perl tests/db/udp_a_sweep.pl 127.0.0.1 "$PORT" "$T/names")
[ "$R" = "sent=$NZ answered=$NZ noerror=$NZ" ] && pass "all $NZ zones answered ($R)" || fail "sweep: $R"
waitfor 60 state_done && pass "the state file lists $NZ zones (END $NZ)" || fail "state file: $(head -c 100 "$ST" 2>/dev/null | head -2) ... $(tail -1 "$ST" 2>/dev/null)"
LINES=$(grep -c "" "$ST" 2>/dev/null)
[ "${LINES:-0}" = "$((NZ + 2))" ] && pass "header, $NZ entries, END line" || fail "the file has $LINES lines"
BYTES=$(awk -F'\t' 'NF == 2 { s += length($1) + length($2) + 12 } END { print s + 0 }' "$ST")
[ "$BYTES" -gt 1048576 ] && pass "the entries need $BYTES bytes on the stream: more than one message (1 MiB), so the list went in parts" || fail "the entries need only $BYTES bytes"
[ "$(awk -F'\t' 'NF == 2 { print $2 }' "$ST" | sort -u | wc -l | tr -d ' ')" = "$NZ" ] && pass "$NZ different zones, none twice" || fail "zones in the file are not $NZ different ones"
grep -q "does not follow\|HOT_LIST.*dropped\|protocol error" "$T/srv.log" && fail "the loader dropped the list or the stream failed: $(grep 'does not follow\|dropped\|protocol error' "$T/srv.log" | head -2)" || pass "no part was dropped, no protocol error"
stop_srv

echo "== after a restart the Backend has all the parts of the WARM_LIST"
start_srv
warm_in() { grep -q "\[DB\] warm-up: $NZ zone(s) of the hot list received from the loader" "$T/srv.log"; }
waitfor 30 warm_in && pass "the log says $NZ zones of the hot list were received from the loader" || fail "no warm-up line for $NZ zones: $(grep 'warm-up' "$T/srv.log" | head -2)"
loaded_ok() { [ "$($KCTL dbstatus 2>/dev/null | grep '^warm:' | sed -n 's/.* loaded=\([0-9]*\).*/\1/p')" = "$NZ" ]; }
waitfor 120 loaded_ok && pass "the warm-up read all $NZ zones" || fail "warm line: $($KCTL dbstatus 2>/dev/null | grep '^warm:')"
grep -q "does not follow\|protocol error" "$T/srv.log" && fail "a part was dropped or the stream failed: $(grep 'does not follow\|protocol error' "$T/srv.log" | head -2)" || pass "no part was dropped, no protocol error"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

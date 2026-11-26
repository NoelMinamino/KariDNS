#!/bin/sh
# run_db_attach_shed_test.sh - 0.7 store: the attach of stored zones above what the store threads can make (a flood of random names against database zones, a memory-limit that holds few zones).
#
# A database of SHED_ZONES zones (tests/db/gen_sqlite3_zones.sh, SHED_RRS records each) is read once into a store; the server is started again with a memory-limit that holds a small part of them,
# COPY mode (no worker attaches a zone itself: every first touch is a request to the store threads) and one store thread, and dnsqps sends random names of those zones at SHED_RATE queries a
# second for SHED_SECS seconds (a 1 s client timeout), far more than one store thread attaches.  Before 0.7 the store threads took the requests in the order they came and made every one of them:
# once the queue was older than the clients' timeout every attach answered a query that its client had given up on, or none (the queries had gone at park-timeout), and the throughput fell far
# below what the threads attach (a store of 10M zones of 100 records: 20k offered against a knee of 15k gave 5.5k-11.6k answers).  Checked:
#   - the store threads were behind (requests taken newest first: `store.attach.newest_first` > 0) and dropped requests that nobody waited for any more (`store.attach.shed` > 0);
#   - most attaches answered a query in time: the answers the client counted are at least SHED_MIN_PCT % of the attaches made during the flood (the old order: about a tenth);
#   - keep serving: no SERVFAIL, no zone read from the database (`store.cold.fetch` and `fetch issued` do not move), and the queue empties after the flood (`store.attach.queued` back to 0,
#     a bounded wait) with a fresh zone answered at once.
# Needs root (the loader runs as nobody), sqlite3, the binaries (./dnsqps is made when missing).  SKIP without them.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
DQ=./dnsqps
for b in "$KARIDNS" ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
[ -x "$DQ" ] || make dnsqps >/dev/null 2>&1 || { echo "SKIP: no dnsqps"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=${SHED_ZONES:-40000}
RRS=${SHED_RRS:-60}
RATE=${SHED_RATE:-30000}
SECS=${SHED_SECS:-8}
MINPCT=${SHED_MIN_PCT:-40}
ML=${SHED_MEMLIMIT:-24m}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_attshed.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((22000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

echo "== the database: $NZ zones of $RRS records"
mkdir "$T/db"
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" "$RRS" > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/a.ctl.conf" <<EOF
socket "$T/a.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/a.ctl.conf"
KA="./karictl -c $T/a.ctl.conf"
conf() {   # conf "extra database statements"
    cat > "$T/a.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PA; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               store "$T/store"; store-mode copy; $1 };
};
control-channel { socket "$T/a.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/a.log"
    "$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/a.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/a.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/a.log"; }
}
stop_srv() {
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
fetches() { $KA dbstatus 2>/dev/null | grep '^fetch:' | head -1 | sed -n 's/.* issued=\([0-9]*\).*/\1/p'; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }
queue_empty() { [ "$(sf store.attach.queued)" = 0 ]; }
jv() { sed -n "s/.*\"$2\":\([0-9.]*\).*/\1/p" "$1" | head -1; }

echo "== the first fill: the zones go from the database into the store"
conf "memory-limit 4g;"
start_srv
waitfor 600 stored_all && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ zones"
stop_srv

echo "== the flood: $RATE random names a second for $SECS s, memory-limit $ML, one store thread"
conf "memory-limit $ML; store-hot-list no; store-threads 1;"
start_srv
# random names with repeats (a name that is in memory is answered from it; memory-limit holds a small part of the zones)
awk -v n="$NZ" -v m=$((RATE * SECS + RATE)) 'BEGIN { srand(11); for (i = 0; i < m; i++) printf "www.z%d.test A\n", 1 + int(rand() * n) }' > "$T/q.txt"
c0() { eval "$1=\$(sf $2)"; }
c0 A0 store.attach.count; c0 S0 store.attach.shed; c0 L0 store.attach.newest_first; c0 CF0 store.cold.fetch; c0 CA0 store.cold.attach; c0 CT0 store.cold.timeout
F0=$(fetches); F0=${F0:-0}
"$DQ" -s 127.0.0.1 -p "$PA" -d "$T/q.txt" -Q "$RATE" -l "$SECS" -t 1 -T 2 -c 4 --json > "$T/flood.json" 2> "$T/flood.err" || { cat "$T/flood.err"; fail "dnsqps: exit status $?"; }
# the parked queries end within park-timeout (1.5 s) after the last query; the attaches of the queue too (bounded wait)
waitfor 30 queue_empty && pass "the attach queue is empty after the flood" || fail "the attach queue holds $(sf store.attach.queued) slots 30 s after the flood"
c0 A1 store.attach.count; c0 S1 store.attach.shed; c0 L1 store.attach.newest_first; c0 CF1 store.cold.fetch; c0 CA1 store.cold.attach; c0 CT1 store.cold.timeout
F1=$(fetches); F1=${F1:-0}
SENT=$(jv "$T/flood.json" sent); COMP=$(jv "$T/flood.json" completed); SRVF=$(sed -n 's/.*"SERVFAIL":\([0-9]*\).*/\1/p' "$T/flood.json"); SRVF=${SRVF:-0}
ATT=$((${A1:-0} - ${A0:-0})); SHED=$((${S1:-0} - ${S0:-0})); NEWF=$((${L1:-0} - ${L0:-0}))
STATE="sent=$SENT completed=$COMP servfail=$SRVF attaches=$ATT shed=$SHED newest_first=$NEWF cold.attach=$((${CA1:-0} - ${CA0:-0})) cold.timeout=$((${CT1:-0} - ${CT0:-0})) cold.fetch=$((${CF1:-0} - ${CF0:-0})) fetch_issued=$F0->$F1 attach.p50_us=$(sf store.attach.p50_us) zones.attached=$(sf store.zones.attached)"
echo "  $STATE"
[ "$NEWF" -gt 0 ] 2>/dev/null && pass "the store thread was behind and took the newest requests first ($NEWF)" || fail "no request was taken newest first: the flood did not overload the store thread ($STATE)"
[ "$SHED" -gt 0 ] 2>/dev/null && pass "requests that nobody waited for were dropped unread ($SHED)" || fail "no request was dropped unread ($STATE)"
[ "$ATT" -gt 0 ] 2>/dev/null && [ $((${COMP:-0} * 100)) -ge $((ATT * MINPCT)) ] && pass "the client got $COMP answers in time for $ATT attaches (at least $MINPCT %)" || fail "the client got ${COMP:-?} answers in time for $ATT attaches (less than $MINPCT %: attaches for queries whose clients had given up; $STATE)"
[ "$SRVF" = 0 ] && pass "no SERVFAIL" || fail "$SRVF SERVFAIL ($STATE)"
[ "${CF1:-0}" = "${CF0:-0}" ] && [ "$F1" = "$F0" ] && pass "no stored zone was read from the database (cold.fetch ${CF0:-0} -> ${CF1:-0}, fetch issued $F0 -> $F1)" || fail "stored zones were read from the database ($STATE)"
# after the flood: a query for a stored zone is answered at once (the queue holds no old requests)
FRESH=$(awk -v n="$NZ" 'BEGIN { print n }')
cat > "$T/one.txt" <<EOF
www.z$FRESH.test A
EOF
"$DQ" -s 127.0.0.1 -p "$PA" -d "$T/one.txt" -N 1 -t 1 -T 1 --json > "$T/one.json" 2> "$T/one.err"
[ "$(jv "$T/one.json" completed)" = 1 ] && pass "a stored zone is answered after the flood" || fail "a stored zone after the flood: $(cat "$T/one.json" "$T/one.err")"
stop_srv

echo
echo "run_db_attach_shed_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

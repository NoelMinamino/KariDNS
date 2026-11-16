#!/bin/sh
# run_db_cold_burst_test.sh - 0.7 store, the cold path: a burst of first-touch queries against a fresh server whose store holds every zone ("a stored zone is answered, never
# sent to the database because a ring is full").
#
# A database of COLD_ZONES zones (default 100000, tests/db/gen_sqlite3_zones.sh) is read once into a store; the server is stopped cleanly and started again, so that no zone is in
# memory and the store has every image.  tests/db/udp_cold_burst.pl then sends one A query for every zone, in a random order, as fast as it can (4000 in flight), which is far more
# than the 128-slot rings and the attach rate of the store threads take at once.  Checked, once with `memory-limit` (large: nothing is taken out of memory) and once without:
#   - every query is answered with NOERROR and an answer (0 SERVFAIL, 0 lost);
#   - the loader read no zone for them (`fetch issued` stays 0: a stored zone is attached from the store, whatever the load);
#   - `karictl store -k` and `karictl dbstatus` answer while the burst runs (the longest wait is reported and bounded: the control thread does not walk the glue of every attached zone);
#   - 0.7 fix 7: in MAP mode the workers attach the zones themselves (the page cache of the first fill is kept): `store.attach.worker.ok` is most of the burst and few queries park; in COPY mode (ZFS)
#     they attach nothing (the store threads do);
#   - 0.7 fix 8: a first fill (an empty store) with the burst in parallel, `warm-before-serve` holding the queries until the first pass has listed the zones: every query is answered (0 SERVFAIL, 0
#     lost, 0 REFUSED) while the store is filled, and the store ends up with every zone; and a restart with hot.list attaches the zones of the last stop in the background (`store.hot.*`).
# Needs root (the loader runs as nobody), sqlite3, perl, the binaries.  SKIP without them.  COLD_ZONES=20000 makes a quick run (still more queries than the rings hold).
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=${COLD_ZONES:-100000}
KARICTL_MAX_S=${COLD_KARICTL_MAX_S:-1.5}          # the longest a karictl command may take during the burst
# The sender: one UDP socket, so every query lands on ONE worker; WINDOW queries are in flight and a query that nobody answered is sent again after 2 s, for WAIT seconds.  A slow (instrumented)
# host serves fewer queries a second, so the window is kept below what a worker parks at the default park-max (16384) with room to spare, and the wait is long.  What the server did on its own
# account is read from its counters (park_full, park_timeout, queue_full, queue_dropped: the only ways a stored zone is answered SERVFAIL) and not only from what the sender saw: a sender that
# loses datagrams in its own receive buffer shows as "lost" with all of these at 0, and is reported as that.
WINDOW=${COLD_WINDOW:-2000}
WAIT=${COLD_WAIT:-30}
# A first fill reads the zones that the queries ask for from the database by name (the loader serves a request of a query before one of the fill, so under a flood of queries the fill itself waits for
# the loader to have a moment): a query waits for its read and park-timeout is 5 s, so the window of that burst is what a slow host reads in that time (about 100 zones a second at the least).
FILL_WINDOW=${COLD_FILL_WINDOW:-500}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_coldburst.XXXXXX") || exit 1
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

echo "== the database: $NZ zones"
mkdir "$T/db"
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" 11 > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
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
               park-timeout 5000; store "$T/store"; $1 };
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
    i=0; while [ $i -lt 300 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
fqv() { $KA dbstatus 2>/dev/null | grep '^fetchq:' | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }      # a field of the fetchq: line
server_refusals() { echo "park_full=$(fqv park_full) park_timeout=$(fqv park_timeout) queue_full=$(fqv queue_full) queue_dropped=$(fqv queue_dropped) table_full=$(fqv table_full)"; }
fetches() { $KA dbstatus 2>/dev/null | grep '^fetch:' | head -1 | sed -n 's/.* issued=\([0-9]*\).*/\1/p'; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }

echo "== the first fill: the zones go from the database into the store"
conf "memory-limit 4g;"
start_srv
waitfor 600 stored_all && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ zones"
stop_srv

burst() {   # burst LABEL "database statements"
    label=$1
    echo "== the burst, $label"
    conf "$2"
    start_srv
    [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null && pass "$label: the restart found $(sf store.zones.stored) stored zones" || fail "$label: the store has $(sf store.zones.stored) zones after the restart"
    A0=$(sf store.zones.attached); A0=${A0:-0}
    F0=$(fetches); F0=${F0:-0}
    # a sampler: karictl store -k and dbstatus once in a while during the burst, the longest time is kept
    : > "$T/ctl.max"
    rm -f "$T/burst.done"
    (
        mx=0
        while [ ! -e "$T/burst.done" ]; do
            for c in "store -k" "dbstatus"; do
                t0=$(perl -MTime::HiRes=time -e 'print time')
                $KA $c > /dev/null 2>&1
                t1=$(perl -MTime::HiRes=time -e 'print time')
                mx=$(perl -e "my \$d = $t1 - $t0; print \$d > $mx ? \$d : $mx")
            done
            sleep 0.05
        done
        echo "$mx" > "$T/ctl.max"
    ) &
    SAMP=$!
    OUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" 7 "$WINDOW" "$WAIT")
    touch "$T/burst.done"
    wait $SAMP
    echo "  $OUT"
    sv() { echo "$OUT" | sed -n "s/.* $1=\([0-9.]*\).*/\1/p" | head -1; }
    SR0=$(server_refusals)
    case "$SR0" in
    "park_full=0 park_timeout=0 queue_full=0 queue_dropped=0 table_full=0") pass "$label: the server refused no stored zone on its own account ($SR0)" ;;
    *) fail "$label: the server answered SERVFAIL for stored zones itself: $SR0" ;;
    esac
    [ "$(sv noerror)" = "$NZ" ] && pass "$label: all $NZ queries answered with NOERROR" || fail "$label: noerror=$(sv noerror) servfail=$(sv servfail) other=$(sv other) lost=$(sv lost) of $NZ ($SR0)"
    [ "$(sv servfail)" = 0 ] && [ "$(sv lost)" = 0 ] && pass "$label: 0 SERVFAIL, 0 lost" || fail "$label: servfail=$(sv servfail) lost=$(sv lost)"
    # the server's own count: every query it was given has an answer (a wake-up that was lost leaves a query parked, whatever the sender sends again)
    SQ=$($KA stats 2>/dev/null | sed -n 's/^karidns_queries_total{proto="udp"} //p' | head -1)
    SR=$($KA stats 2>/dev/null | awk '/^karidns_responses_total/ { s += $2 } END { print s + 0 }')
    [ -n "$SQ" ] && [ "$SQ" = "$SR" ] && [ "$SQ" -ge "$NZ" ] && pass "$label: the server answered every query it was given ($SQ queries, $SR responses)" || fail "$label: the server counts $SQ queries and $SR responses"
    F1=$(fetches); F1=${F1:-0}
    [ "$F1" = "$F0" ] && pass "$label: the loader read no zone (fetch issued $F0 -> $F1)" || fail "$label: fetch issued went from $F0 to $F1: $($KA dbstatus | grep -E '^(fetch|fetchq):')"
    A1=$(sf store.zones.attached); A1=${A1:-0}
    echo "  attach: count=$(sf store.attach.count) p50=$(sf store.attach.p50_us) us p99=$(sf store.attach.p99_us) us; cold: attach=$(sf store.cold.attach) fetch=$(sf store.cold.fetch) timeout=$(sf store.cold.timeout) p50=$(sf store.cold.p50_us) us p99=$(sf store.cold.p99_us) us"
    WOK=$(sf store.attach.worker.ok); WOK=${WOK:-0}
    echo "  worker attach: ok=$WOK mean=$(sf store.attach.worker.mean_us) us not_resident=$(sf store.attach.worker.not_resident) claimed=$(sf store.attach.worker.claimed) failed=$(sf store.attach.worker.failed) declined=$(sf store.attach.worker.declined) full=$(sf store.attach.worker.full) registered=$(sf store.attach.worker.registered) dropped=$(sf store.attach.worker.dropped); parked: $($KA dbstatus | grep '^queries:')"
    MODE=$(sf store.mode)
    PARKED=$($KA dbstatus 2>/dev/null | sed -n 's/^queries: .* parked=\([0-9]*\) .*/\1/p' | head -1); PARKED=${PARKED:-0}
    if [ "$MODE" = map ]; then
        [ "$WOK" -ge $((NZ / 2)) ] && pass "$label: the workers attached $WOK of the $NZ zones themselves (MAP mode, the images are in the page cache)" || fail "$label: only $WOK zones were attached by the workers (not_resident=$(sf store.attach.worker.not_resident))"
        [ "$PARKED" -le $((NZ / 5)) ] && pass "$label: $PARKED queries parked (the burst was answered without parking)" || fail "$label: $PARKED of $NZ queries parked"
        [ "$(sf store.attach.worker.registered)" -ge $((WOK - WOK / 100 - 5)) ] 2>/dev/null && pass "$label: the store threads registered the zones the workers attached ($(sf store.attach.worker.registered) of $WOK)" || fail "$label: registered=$(sf store.attach.worker.registered) of $WOK"
    else
        [ "$WOK" = 0 ] && pass "$label: $MODE mode: the workers attached nothing (the store threads did)" || fail "$label: $MODE mode, but the workers attached $WOK zones"
    fi
    [ "$A1" -gt "$A0" ] 2>/dev/null && pass "$label: zones were attached from the store ($A0 -> $A1)" || fail "$label: attached $A0 -> $A1"
    MX=$(cat "$T/ctl.max" 2>/dev/null)
    echo "  longest karictl command during the burst: ${MX:-?} s (limit $KARICTL_MAX_S s)"
    perl -e "exit(('${MX:-99}' + 0) < $KARICTL_MAX_S ? 0 : 1)" && pass "$label: karictl answered during the burst (longest ${MX} s)" || fail "$label: a karictl command took ${MX} s during the burst"
    stop_srv
}
# (0.7 M4: without the hot list.  The threads of the list attach the zones of the last run at once, with no rate cap, so a restart with the list has most of the zones in memory before the burst comes
# and the workers have nothing to attach; the bursts here are of the attach itself: the workers in MAP mode, the store threads in COPY mode.  The list has its own part below.)
burst "with memory-limit" "memory-limit 4g; store-hot-list no;"
burst "without memory-limit" "store-hot-list no;"

# 0.7 M4: a run that leaves hot.list: the zones that are in memory at a clean stop are written to it (the two bursts above were with store-hot-list no: they wrote none)
echo "== a run that leaves hot.list"
conf "memory-limit 4g;"
start_srv
OUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" 8 "$WINDOW" "$WAIT")
echo "  $OUT"
stop_srv

# 0.7 fix 8: hot.list.  The server was stopped cleanly after a run that had the zones in memory: they are in hot.list, and the next start attaches them in the background
echo "== the restart with hot.list"
conf "memory-limit 4g;"
start_srv
HS=""
for i in $(seq 1 600); do HS=$(sf store.hot.state); [ "$HS" = done ] || [ "$HS" = high-mark ] && break; sleep 0.1; done
echo "  hot: state=$HS listed=$(sf store.hot.listed) attached=$(sf store.hot.attached) skipped=$(sf store.hot.skipped); attached zones $(sf store.zones.attached); worker attaches $(sf store.attach.worker.ok)"
[ "$HS" = done ] && pass "the background attach of hot.list ended" || fail "hot.list: state $HS"
[ "$(sf store.hot.listed)" -ge $((NZ / 2)) ] 2>/dev/null && pass "hot.list had $(sf store.hot.listed) zones (the zones in memory at the last stop)" || fail "hot.list listed $(sf store.hot.listed) zones"
[ "$(sf store.zones.attached)" -ge $((NZ / 2)) ] 2>/dev/null && pass "the zones of hot.list are in memory before any query: $(sf store.zones.attached) attached" || fail "only $(sf store.zones.attached) zones were attached by hot.list"
F0=$(fetches); F0=${F0:-0}
OUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" 9 "$WINDOW" "$WAIT")
echo "  $OUT"
sv2() { echo "$OUT" | sed -n "s/.* $1=\([0-9.]*\).*/\1/p" | head -1; }
[ "$(sv2 noerror)" = "$NZ" ] && [ "$(sv2 servfail)" = 0 ] && [ "$(sv2 lost)" = 0 ] && pass "after hot.list: all $NZ queries answered with NOERROR" || fail "after hot.list: $OUT"
PARKED=$($KA dbstatus 2>/dev/null | sed -n 's/^queries: .* parked=\([0-9]*\) .*/\1/p' | head -1)
[ "${PARKED:-9999999}" -le $((NZ / 20)) ] && pass "after hot.list: ${PARKED} queries parked of $NZ" || fail "after hot.list: $PARKED queries parked"
stop_srv
echo "== no hot.list with store-hot-list no"
conf "memory-limit 4g; store-hot-list no;"
start_srv
[ "$(sf store.hot.state)" = off ] && [ "$(sf store.hot.listed)" = 0 ] && pass "store-hot-list no: the list is not read" || fail "store-hot-list no: state $(sf store.hot.state)"
[ "$(sf store.zones.attached)" -le $((NZ / 5)) ] 2>/dev/null && pass "store-hot-list no: nothing is attached before a query asks ($(sf store.zones.attached))" || fail "store-hot-list no: $(sf store.zones.attached) zones attached"
# the TCP path of a worker attaches a zone too (the first touch of a stored zone over TCP)
W0=$(sf store.attach.worker.ok); W0=${W0:-0}
TBAD=0
for k in 7 1007 2007 3007 4007 5007; do      # (a few zones: the pages of a record that mincore() does not call resident go to a store thread, a few in a hundred)
    TOUT=$(perl tests/db/tcp_query.pl "$PA" "www.z$((NZ / 8 + k)).test" A 2>&1)
    [ "$TOUT" = "rcode=0 answers=1" ] || { TBAD=$((TBAD + 1)); echo "  TCP: $TOUT"; }
done
W1=$(sf store.attach.worker.ok); W1=${W1:-0}
[ "$TBAD" = 0 ] && pass "six first-touch queries over TCP are answered" || fail "$TBAD of six first-touch queries over TCP failed"
if [ "$(sf store.mode)" = map ]; then [ "$W1" -gt "$W0" ] && pass "... by the worker that took it (worker attaches $W0 -> $W1)" || fail "the TCP query was not attached by the worker ($W0 -> $W1; not_resident=$(sf store.attach.worker.not_resident))"; fi
stop_srv

# 0.7 fix 8: a first fill with the queries in parallel
echo "== the first fill (an empty store) with the queries in parallel"
rm -rf "$T/store"
conf "memory-limit 4g; warm-before-serve 60;"
: > "$T/a.log"
"$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 &
SRV=$!
i=0; while [ $i -lt 100 ] && ! $KA status > /dev/null 2>&1; do sleep 0.1; i=$((i + 1)); done
OUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" 5 "$FILL_WINDOW" "$WAIT")
echo "  $OUT"
sv3() { echo "$OUT" | sed -n "s/.* $1=\([0-9.]*\).*/\1/p" | head -1; }
[ "$(sv3 noerror)" = "$NZ" ] && pass "first fill: all $NZ queries answered with NOERROR (the queries were held until the first pass listed the zones, then read from the database or the store)" || fail "first fill: noerror=$(sv3 noerror) servfail=$(sv3 servfail) other=$(sv3 other) lost=$(sv3 lost) of $NZ"
[ "$(sv3 servfail)" = 0 ] && [ "$(sv3 lost)" = 0 ] && [ "$(sv3 other)" = 0 ] && pass "first fill: 0 SERVFAIL, 0 REFUSED, 0 lost" || fail "first fill: servfail=$(sv3 servfail) other=$(sv3 other) lost=$(sv3 lost)"
SQ=$($KA stats 2>/dev/null | sed -n 's/^karidns_queries_total{proto="udp"} //p' | head -1)
SR=$($KA stats 2>/dev/null | awk '/^karidns_responses_total/ { s += $2 } END { print s + 0 }')
[ -n "$SQ" ] && [ "$SQ" = "$SR" ] && pass "first fill: the server answered every query it was given ($SQ queries, $SR responses)" || fail "first fill: the server counts $SQ queries and $SR responses"
waitfor 600 stored_all && pass "first fill: the store holds all $NZ zones" || fail "first fill: the store holds $(sf store.zones.stored) of $NZ zones"
echo "  $($KA dbstatus | grep -E '^fetchq:' | sed 's/ hist=.*//')"
stop_srv

echo
echo "run_db_cold_burst_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

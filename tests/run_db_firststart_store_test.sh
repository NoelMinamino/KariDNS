#!/bin/sh
# run_db_firststart_store_test.sh - 0.7 M2, the first start of a zone store: the manifest pass is applied by the reconcile thread (dns_db_recon.c) in groups of up to 64 entries, off the thread that
# answers the fetches and the lookups.
#
# A database of FIRSTSTART_ZONES zones (default 30000, tests/db/gen_sqlite3_zones.sh) is read into an empty store by the real server and loader.  Checked:
#   1. queries during the pass: a cold burst for FIRSTSTART_QUERIES zones (default 5000, in a random order) starts with the server, while the pass and the fill go on; every one is NOERROR (a zone the pass
#      has not listed yet is looked up, one that is listed and has no body is fetched), none is REFUSED or SERVFAIL, none is lost, and the drops are 0 at this load (store.lookup.drop.*, store.park.drop.*);
#      the pass is applied by the thread (store.recon.thread, entries, pages) in group records (store.recon.group_entries = the zones, group_records about zones / 64: one journal record for 64 entries);
#      the stream thread of the Backend is not kept long by a frame: store.ingest.stream_max_us is at most FIRSTSTART_STREAM_US (default 250000, a generous bound: a loaded VM stalls a thread for tens of ms,
#      and the bound only shows that the thread is not busy for a pass; that no page is decoded or recorded there is shown by the counters, store.recon.thread_entries and pages, and by tests/test_db_store.c)
#      and the loop of the ingest thread is reported (store.ingest.loop_max_us, it also has the bodies of the fill: the zones the fill reads are built on that thread);
#   2. kill -9 the server in the middle of a pass (the loader is behind tests/db/slow_manifest.c with -DPACE_US, which sends the pages of the pass one at a time): the server is started again on the same
#      store, the pass is made again, and the store ends with every zone and a log with no message of a rebuild or a repair of the tables, and the zones answer (that a group record is there whole or not at all
#      is shown by tests/test_store.c, the kill loop with groups, not here: this only sees that the server comes up and fills the store again);
#   3. kill -9 the loader in the middle of a pass: the stream ends, the pass that was cut off sweeps nothing, the supervisor starts the loader again, the pass is made again, every zone is in the store.
# Needs sqlite3, perl, a C compiler (the proxy is built in the test's directory), the binaries; as root the loader and the server run as nobody, otherwise as the user who runs the test.  SKIP without them.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
DAG=${DAG:-./dag}
for b in "$KARIDNS" ./karictl "$LOADER" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler for the proxy of the loader"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
if [ "$(id -u)" = "0" ]; then
    id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
    RUNUSER=nobody
else
    RUNUSER=$(id -un)
fi

NZ=${FIRSTSTART_ZONES:-30000}
NQ=${FIRSTSTART_QUERIES:-5000}
KZ=${FIRSTSTART_KILL_ZONES:-60000}
STREAM_US=${FIRSTSTART_STREAM_US:-250000}
[ "$NQ" -gt "$NZ" ] && NQ=$NZ
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_firststart.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf"
    kari_kill_conf "$T/k.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((23000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

echo "== the databases: $NZ zones (the burst), $KZ zones (the kills)"
mkdir "$T/db"
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" 7 > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
sh tests/db/gen_sqlite3_zones.sh "$T/db/k.db" "$KZ" 7 > "$T/gen2.log" 2>&1 || { echo "gen failed"; cat "$T/gen2.log"; exit 1; }
chown -R "$RUNUSER" "$T/db" 2>/dev/null; chmod 600 "$T/db/"*.db*
if [ "$(id -u)" = "0" ]; then
    install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader.real" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader.real"; chown 0:0 "$T/karidns-dbloader.real"; chmod 755 "$T/karidns-dbloader.real"; }
else
    cp "$LOADER" "$T/karidns-dbloader.real"; chmod 755 "$T/karidns-dbloader.real"
fi
cc -O1 -o "$T/karidns-dbloader" tests/db/slow_manifest.c -DREAL_LOADER="\"$T/karidns-dbloader.real\"" -DRELEASE_FILE="\"$T/release\"" -DPACE_US=15000 > "$T/cc.log" 2>&1 || { echo "SKIP: the proxy does not build"; cat "$T/cc.log"; exit 0; }
chmod 755 "$T/karidns-dbloader"
cat > "$T/ctl.conf" <<EOF
socket "$T/a.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/ctl.conf"
KA="./karictl -c $T/ctl.conf"
# conf NAME DB LOADER-PATH
mkconf() {
    cat > "$T/$1.conf" <<EOF
options {
    user "$RUNUSER"; pid-file "none"; listen-on { 127.0.0.1; }; port $PA; notify no;
    database { driver sqlite3; database-file "$2"; loader-user "$RUNUSER"; loader-path "$3"; acl-ceiling { 127.0.0.1; };
               park-timeout 5000; store "$T/store"; store-threads 2; };
};
control-channel { socket "$T/a.sock"; secret "$SECRET"; };
EOF
}
mkconf a "$T/db/z.db" "$T/karidns-dbloader.real"
mkconf k "$T/db/k.db" "$T/karidns-dbloader"
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_n() { [ "$(( $(sf store.zones.stored) + 0 ))" -ge "$1" ] 2>/dev/null; }
all_known() { n=$(( $(sf store.zones.stored) + $(sf store.zones.known) )); [ "$n" -ge "$1" ] 2>/dev/null; }
dagq() { "$DAG" @127.0.0.1 -p "$PA" "$1" "${2:-A}" +nohexdump +time=10 +tries=1 2>&1; }
status_of() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
fv() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }
start_server() { "$KARIDNS" -c "$T/$1.conf" -f > "$T/$2" 2>&1 & SRV=$!; }
desc() { for c in $(pgrep -P "$1" 2>/dev/null); do echo "$c"; desc "$c"; done; }     # the processes below a process (only the ones of this test are touched)
stop_server() {
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$SRV" 2>/dev/null
    SRV=""
}

echo
echo "######## 1. queries during the pass"
start_server a a.log
kari_wait_log "$T/a.log" "loader stream connected" 30 && pass "the server is up and the loader is connected" || { fail "no loader"; tail -20 "$T/a.log"; }
sleep 0.2
BOUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NQ" 5 1000 60)
echo "  $BOUT"
[ "$(fv "$BOUT" noerror)" = "$NQ" ] && [ "$(fv "$BOUT" servfail)" = 0 ] && [ "$(fv "$BOUT" other)" = 0 ] && [ "$(fv "$BOUT" lost)" = 0 ] && pass "all $NQ zones of the burst answered NOERROR while the pass and the fill went on: no REFUSED, no SERVFAIL, none lost" || fail "the burst: $BOUT"
kari_wait_log "$T/a.log" "the manifest pass is over" 60 && pass "the pass ended" || { fail "the pass did not end"; tail -10 "$T/a.log"; }
waitfor 120 stored_n "$NZ" && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ zones (known $(sf store.zones.known))"
[ "$(sf store.recon.thread)" = 1 ] && pass "the reconcile thread runs (store.recon.thread=1)" || fail "store.recon.thread=$(sf store.recon.thread)"
[ "$(sf store.recon.thread_entries)" = "$NZ" ] && [ "$(sf store.recon.pass.entries)" = "$NZ" ] && pass "the thread applied the $NZ entries of the pass (store.recon.thread_entries, pages $(sf store.recon.thread_pages))" || fail "thread_entries=$(sf store.recon.thread_entries) pass.entries=$(sf store.recon.pass.entries)"
GE=$(sf store.recon.group_entries); GR=$(sf store.recon.group_records)
[ "${GE:-0}" -ge "$NZ" ] 2>/dev/null && [ "${GR:-0}" -ge $((NZ / 64)) ] 2>/dev/null && [ "${GR:-0}" -le $((NZ / 64 + NZ / 200 + 10)) ] 2>/dev/null && pass "the entries were recorded in groups: $GE entries in $GR journal records (64 an entry at most)" || fail "group_entries=$GE group_records=$GR"
SM=$(sf store.ingest.stream_max_us); LM=$(sf store.ingest.loop_max_us)
[ -n "$SM" ] && [ "$SM" -le "$STREAM_US" ] 2>/dev/null && pass "the stream thread was not kept more than ${STREAM_US} us by a frame (store.ingest.stream_max_us=$SM; the loop of the thread: store.ingest.loop_max_us=$LM)" || fail "store.ingest.stream_max_us=$SM (limit $STREAM_US), loop_max_us=$LM"
DR=0
for k in store.lookup.drop.room store.lookup.drop.timeout store.lookup.drop.queue store.lookup.servfail store.lookup.reask_suppressed store.lookup.shed store.lookup.expired; do
    v=$(sf "$k"); DR=$((DR + ${v:-0}))
done
for k in $($KA store -k 2>/dev/null | sed -n 's/^\(store\.park\.drop\.[a-z_]*\)=.*/\1/p'); do v=$(sf "$k"); DR=$((DR + ${v:-0})); done
[ "$DR" = 0 ] && pass "no query was dropped or failed at this load (the drop and failure counters of the lookups and of the park are 0)" || { fail "drops: $DR"; $KA store -k 2>/dev/null | egrep "drop|servfail|shed|expired" | head -20; }
echo "  stream_max_us=$SM loop_max_us=$LM busy_pct=$(sf store.recon.busy_pct) apply_ns_per_entry=$(sf store.recon.apply_ns_per_entry) ring_full_stops=$(sf store.recon.ring_full_stops) lookups: asked=$(sf store.lookup.asked) found=$(sf store.lookup.found)"
OUT=$(dagq "z$((NZ / 2)).test" SOA)
[ "$(echo "$OUT" | status_of)" = NOERROR ] && pass "a zone answers after the fill" || fail "z$((NZ / 2)).test: $(echo "$OUT" | status_of)"
grep -q "protocol error" "$T/a.log" && fail "a protocol error: $(grep 'protocol error' "$T/a.log" | head -2)" || pass "no protocol error"
stop_server

echo
echo "######## 2. kill -9 the server in the middle of a pass"
rm -rf "$T/store" "$T/release"
start_server k k.log
kari_wait_log "$T/k.log" "a manifest pass starts" 30 && pass "the first pass has started" || { fail "no pass"; tail -20 "$T/k.log"; }
: > "$T/release"
sleep 0.25
K1=$(( $(sf store.zones.stored) + $(sf store.zones.known) ))
if [ "$K1" -gt 0 ] && [ "$K1" -lt "$KZ" ]; then pass "the pass is in the middle: $K1 of $KZ zones are in the store"; else fail "the pass was not in the middle when the server was killed: $K1 of $KZ zones"; fi
kari_kill_tree "$SRV"
SRV=""
sleep 0.5
grep -q "the manifest pass is over" "$T/k.log" && fail "the pass had ended before the kill" || pass "the pass had not ended (the server was killed in the middle of it)"
start_server k k2.log
kari_wait_log "$T/k2.log" "the manifest pass is over" 90 && pass "the pass is made again and ends" || { fail "no second pass"; tail -20 "$T/k2.log"; }
waitfor 180 all_known "$KZ" && pass "the store has all $KZ zones after the restart" || fail "the store has $(( $(sf store.zones.stored) + $(sf store.zones.known) )) of $KZ zones"
grep -qE "rebuilt=1|damaged|repaired" "$T/k2.log" && fail "the store was rebuilt or repaired after the kill: $(grep -E 'rebuilt=1|damaged|repaired' "$T/k2.log" | head -2)" || pass "the log of the restart has no message of a rebuild or a repair of the store"
OUT=$(dagq "z$((KZ - 3)).test" SOA)
[ "$(echo "$OUT" | status_of)" = NOERROR ] && pass "a zone near the end of the manifest answers" || fail "z$((KZ - 3)).test: $(echo "$OUT" | status_of)"
[ "$(sf store.recon.pass.entries)" = "$KZ" ] && pass "the second pass listed $KZ zones" || fail "pass.entries=$(sf store.recon.pass.entries)"

echo
echo "######## 3. kill -9 the loader in the middle of a pass"
stop_server
rm -rf "$T/store" "$T/release"
start_server k k3.log
kari_wait_log "$T/k3.log" "a manifest pass starts" 30 && pass "the first pass has started" || { fail "no pass"; tail -20 "$T/k3.log"; }
: > "$T/release"
sleep 0.25
LP=$(for p in $(desc "$SRV"); do c=$(ps -o command= -p "$p" 2>/dev/null); case "$c" in "karidns-dbloader -s 3"*"(karidns-dbloader.re)") ;; "karidns-dbloader -s 3"*) echo "$p";; esac; done | head -1)
[ -n "$LP" ] && pass "the loader (behind the proxy) is process $LP" || fail "no loader process"
[ -n "$LP" ] && kill -KILL "$LP" 2>/dev/null
kari_wait_log "$T/k3.log" "was cut off" 30 && pass "the pass that the loader left was cut off (nothing is swept)" || { fail "no cut-off pass"; tail -10 "$T/k3.log"; }
kari_wait_log "$T/k3.log" "the manifest pass is over" 90 && pass "the supervisor started the loader again and the pass ended" || { fail "no pass after the restart of the loader"; tail -20 "$T/k3.log"; }
waitfor 180 all_known "$KZ" && pass "the store has all $KZ zones" || fail "the store has $(( $(sf store.zones.stored) + $(sf store.zones.known) )) of $KZ zones"
grep "the manifest pass is over" "$T/k3.log" | grep -q " 0 not offered by the loader, 0 of the" && pass "the pass that ended swept nothing" || fail "$(grep 'the manifest pass is over' "$T/k3.log" | head -2)"
grep -q "protocol error" "$T/k3.log" && fail "a protocol error: $(grep 'protocol error' "$T/k3.log" | head -2)" || pass "no protocol error"
OUT=$(dagq "z$((KZ - 5)).test" SOA)
[ "$(echo "$OUT" | status_of)" = NOERROR ] && pass "a zone answers" || fail "z$((KZ - 5)).test: $(echo "$OUT" | status_of)"
kill -0 "$SRV" 2>/dev/null && pass "the server is up" || fail "the server died"
stop_server

echo
echo "run_db_firststart_store_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

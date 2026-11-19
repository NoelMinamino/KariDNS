#!/bin/sh
# run_db_store_bulk_test.sh - 0.7, the unlogged bulk fill of an empty zone store ("THE BULK FILL" in dns_store.c, planning planing_0.7.x_first_fill_writes.md).
#
# A database of BULK_ZONES zones (default 200000, tests/db/gen_sqlite3_zones.sh) is read into an empty store by the real server (the test build, karidns-evict: the cadence of the bulk checkpoints is
# set small with KARIDNS_TEST_STORE_BULK_BYTES, default 8 MiB) and loader.  Checked:
#   1. the first fill: while it runs the store writes no journal record (store.journal.bytes_written stays at the headers of the journal files, BULK_JOURNAL_MAX, default 64 KiB), the pass and the bodies
#      are unlogged (store.bulk.unlogged_records), the body fill makes bulk checkpoints (store.bulk.checkpoints), the fill ends by itself (store.bulk.active=0) and every zone answers NOERROR;
#   2. kill -9 in the pass (the loader behind tests/db/slow_manifest.c, -DPACE_US): the restart says that the fill was cut off (store.bulk.recoveries=1), the fill goes on and every zone answers;
#   3. kill -9 in the body fill after a bulk checkpoint: the same, the store comes back at that checkpoint (zones with an image past it are KNOWN, store.bulk.recovered_known), the rest is fetched again;
#   4. a clean stop in the middle of the fill: the restart needs no rebuild, the fill goes on unlogged (store.bulk.resumed=1, store.bulk.recoveries=0) and ends.
# Root only (the loader runs as nobody, as in the other DB store tests); SKIP otherwise, and without sqlite3 / perl / a C compiler / the test build.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

[ "$(id -u)" = "0" ] || { echo "SKIP: run_db_store_bulk_test.sh needs root"; exit 0; }
KARIDNS=${KARIDNS:-./karidns-evict}
LOADER=${LOADER:-./karidns-dbloader}
DAG=${DAG:-./dag}
for b in "$KARIDNS" ./karictl "$LOADER" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built (make evict karictl karidns-dbloader dag)"; exit 0; }
done
grep -q KARIDNS_TEST_STORE_BULK_BYTES "$KARIDNS" 2>/dev/null || { echo "SKIP: $KARIDNS has no test knobs (make evict)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler for the proxy of the loader"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
RUNUSER=nobody
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"      # (the sanitizer build leaks what a SIGKILL'd server never frees)

NZ=${BULK_ZONES:-200000}
CKB=${BULK_CK_BYTES:-8388608}
JMAX=${BULK_JOURNAL_MAX:-65536}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_bulk.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf"
    kari_kill_conf "$T/p.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((24000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

echo "== the database: $NZ zones"
mkdir "$T/db"
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" 7 > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
chown -R "$RUNUSER" "$T/db"; chmod 600 "$T/db/"*.db*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader.real" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader.real"; chown 0:0 "$T/karidns-dbloader.real"; chmod 755 "$T/karidns-dbloader.real"; }
cc -O1 -o "$T/karidns-dbloader" tests/db/slow_manifest.c -DREAL_LOADER="\"$T/karidns-dbloader.real\"" -DRELEASE_FILE="\"$T/release\"" -DPACE_US=20000 > "$T/cc.log" 2>&1 || { echo "SKIP: the proxy does not build"; cat "$T/cc.log"; exit 0; }
chmod 755 "$T/karidns-dbloader"
cat > "$T/ctl.conf" <<EOF
socket "$T/a.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/ctl.conf"
KA="./karictl -c $T/ctl.conf"
# conf NAME LOADER-PATH
mkconf() {
    cat > "$T/$1.conf" <<EOF
options {
    user "$RUNUSER"; pid-file "none"; listen-on { 127.0.0.1; }; port $PA; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "$RUNUSER"; loader-path "$2"; acl-ceiling { 127.0.0.1; };
               park-timeout 5000; store "$T/store"; store-threads 2; };
};
control-channel { socket "$T/a.sock"; secret "$SECRET"; };
EOF
}
mkconf a "$T/karidns-dbloader.real"
mkconf p "$T/karidns-dbloader"
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
n0() { v=$(sf "$1"); echo "${v:-0}"; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_all() { [ "$(n0 store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }
bulk_over() { [ "$(sf store.bulk.active)" = 0 ]; }
fv() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }
start_server() { env KARIDNS_TEST_STORE_BULK_BYTES="$CKB" "$KARIDNS" -c "$T/$1.conf" -f > "$T/$2" 2>&1 & SRV=$!; }
stop_server() {
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt 300 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
burst_all() {     # every zone of the database answers NOERROR (one query for www.z<i>.test each, in a random order)
    B=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" 3 2000 60)
    echo "  $B"
    [ "$(fv "$B" noerror)" = "$NZ" ] && [ "$(fv "$B" servfail)" = 0 ] && [ "$(fv "$B" other)" = 0 ] && [ "$(fv "$B" lost)" = 0 ] && pass "$1: all $NZ zones answer NOERROR" || fail "$1: the burst: $B"
}
# watch_fill LOG: while the fill runs, the largest store.journal.bytes_written seen (JW), the bulk state, until the fill is over or 300 s
watch_fill() {
    JW=0; SEEN=0; i=0
    while [ $i -lt 3000 ]; do
        a=$(sf store.bulk.active); w=$(n0 store.journal.bytes_written)
        if [ "${a:-0}" != 0 ]; then SEEN=1; [ "$w" -gt "$JW" ] 2>/dev/null && JW=$w; fi
        [ "$SEEN" = 1 ] && [ "${a:-0}" = 0 ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

echo
echo "######## 1. the first fill is unlogged"
start_server a a1.log
kari_wait_log "$T/a1.log" "loader stream connected" 60 && pass "the server is up and the loader is connected" || { fail "no loader"; tail -20 "$T/a1.log"; }
watch_fill && pass "the fill ended by itself (store.bulk.active=0)" || fail "the fill did not end: bulk.active=$(sf store.bulk.active) stored=$(sf store.zones.stored) known=$(sf store.zones.known)"
[ "$SEEN" = 1 ] && pass "the fill was a bulk fill (store.bulk.active was set)" || fail "store.bulk.active was never set"
[ "$JW" -le "$JMAX" ] 2>/dev/null && pass "while it ran the journal took $JW bytes (the headers of its files; at most $JMAX)" || fail "the journal took $JW bytes during the fill (more than $JMAX)"
stored_all && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ (known $(sf store.zones.known))"
UR=$(n0 store.bulk.unlogged_records); BC=$(n0 store.bulk.checkpoints)
[ "$(sf store.bulk.fills)" = 1 ] && [ "$UR" -ge "$NZ" ] 2>/dev/null && pass "one bulk fill: $UR records unlogged" || fail "bulk.fills=$(sf store.bulk.fills) unlogged_records=$UR"
[ "$BC" -ge 1 ] 2>/dev/null && pass "the body fill made $BC bulk checkpoint(s) (segments $(sf store.segments.used_bytes) bytes, one at least every $CKB bytes doubled)" || fail "no bulk checkpoint: segments $(sf store.segments.used_bytes)"
grep -q "an unlogged bulk fill of the empty store begins" "$T/a1.log" && grep -q "the unlogged bulk fill is over" "$T/a1.log" && pass "the log says when the fill began and when it ended" || fail "the log lines of the fill are missing"
J0=$(n0 store.journal.bytes_written)
burst_all "after the fill"
echo "  checkpoints $(sf store.checkpoint.count), table bytes $(sf store.checkpoint.table_bytes), journal bytes $J0, commits $(sf store.writes.commits)"
stop_server

echo
echo "######## 2. kill -9 in the pass"
rm -rf "$T/store" "$T/release"
start_server p p1.log
kari_wait_log "$T/p1.log" "a manifest pass starts" 60 && pass "the pass has started" || { fail "no pass"; tail -20 "$T/p1.log"; }
: > "$T/release"
sleep 0.4
K1=$(( $(n0 store.zones.stored) + $(n0 store.zones.known) ))
[ "$(sf store.bulk.active)" = 1 ] && [ "$K1" -gt 0 ] && [ "$K1" -lt "$NZ" ] && pass "the pass of the bulk fill is in the middle: $K1 of $NZ zones" || fail "not in the middle of the pass: bulk.active=$(sf store.bulk.active), $K1 of $NZ zones"
kari_kill_tree "$SRV"; SRV=""
sleep 0.5
start_server p p2.log
kari_wait_log "$T/p2.log" "a bulk fill was cut off" 60 && pass "the restart says that the fill was cut off: $(grep -o 'the store is back at.*' "$T/p2.log" | head -1 | cut -c1-140)" || { fail "no message of the cut-off fill"; tail -20 "$T/p2.log"; }
[ "$(sf store.bulk.recoveries)" = 1 ] && pass "store.bulk.recoveries=1" || fail "store.bulk.recoveries=$(sf store.bulk.recoveries)"
watch_fill && stored_all && pass "the fill went on and ended: all $NZ zones are stored" || fail "after the restart: bulk.active=$(sf store.bulk.active) stored=$(sf store.zones.stored) of $NZ"
burst_all "after a kill in the pass"
stop_server

echo
echo "######## 3. kill -9 in the body fill after a bulk checkpoint"
rm -rf "$T/store" "$T/release"
start_server a b1.log
in_body() { [ "$(n0 store.bulk.checkpoints)" -ge 1 ] 2>/dev/null && [ "$(n0 store.zones.stored)" -lt $((NZ * 9 / 10)) ] 2>/dev/null; }
if waitfor 120 in_body; then
    S1=$(n0 store.zones.stored); BC1=$(n0 store.bulk.checkpoints)
    kari_kill_tree "$SRV"; SRV=""
    pass "killed after $BC1 bulk checkpoint(s) with $S1 of $NZ zones stored"
else
    fail "no bulk checkpoint before 90 % of the bodies: checkpoints=$(sf store.bulk.checkpoints) stored=$(sf store.zones.stored)"
    kari_kill_tree "$SRV"; SRV=""
fi
grep -q "the manifest pass is over" "$T/b1.log" && pass "the pass had ended before the kill (the body fill was killed)" || fail "the pass had not ended"
sleep 0.5
start_server a b2.log
kari_wait_log "$T/b2.log" "a bulk fill was cut off" 60 && pass "the restart: $(grep -o 'the store is back at.*' "$T/b2.log" | head -1 | cut -c1-200)" || { fail "no message of the cut-off fill"; tail -20 "$T/b2.log"; }
[ "$(sf store.bulk.recoveries)" = 1 ] && [ "$(sf store.recovery.rebuilt)" = 1 ] && pass "store.bulk.recoveries=1, rebuilt, $(sf store.bulk.recovered_known) zone(s) KNOWN with an image past the checkpoint, $(sf store.recovery.dropped_zones) dropped" || fail "recoveries=$(sf store.bulk.recoveries) rebuilt=$(sf store.recovery.rebuilt)"
grep -q "a manifest pass starts" "$T/b2.log" || kari_wait_log "$T/b2.log" "a manifest pass starts" 30
grep -q "a manifest pass starts" "$T/b2.log" && pass "the cursor was dropped: the loader lists every zone again" || fail "no pass after the restart"
watch_fill && stored_all && pass "the fill went on and ended: all $NZ zones are stored" || fail "after the restart: bulk.active=$(sf store.bulk.active) stored=$(sf store.zones.stored) of $NZ"
burst_all "after a kill in the body fill"
stop_server

echo
echo "######## 4. a clean stop in the middle of the fill"
rm -rf "$T/store" "$T/release"
start_server a c1.log
half() { s=$(n0 store.zones.stored); [ "$s" -ge $((NZ / 5)) ] 2>/dev/null && [ "$(sf store.bulk.active)" != 0 ]; }
waitfor 120 half && pass "the fill is in the middle: $(sf store.zones.stored) of $NZ stored" || fail "not in the middle: stored=$(sf store.zones.stored) bulk.active=$(sf store.bulk.active)"
stop_server
grep -q "the unlogged bulk fill is over" "$T/c1.log" && fail "the fill had ended before the stop" || pass "the fill had not ended at the stop"
start_server a c2.log
kari_wait_log "$T/c2.log" "loader stream connected" 60 || true
[ "$(sf store.bulk.resumed)" = 1 ] && [ "$(sf store.bulk.recoveries)" = 0 ] && [ "$(sf store.recovery.rebuilt)" = 0 ] && [ "$(sf store.recovery.was_clean)" = 1 ] && pass "the restart goes on with the fill: no rebuild, nothing to recover" || fail "resumed=$(sf store.bulk.resumed) recoveries=$(sf store.bulk.recoveries) rebuilt=$(sf store.recovery.rebuilt) was_clean=$(sf store.recovery.was_clean)"
grep -q "a bulk fill was cut off" "$T/c2.log" && fail "the restart took the clean stop for a cut-off fill" || pass "no message of a cut-off fill"
watch_fill && stored_all && pass "the fill ended: all $NZ zones are stored" || fail "bulk.active=$(sf store.bulk.active) stored=$(sf store.zones.stored) of $NZ"
[ "$JW" -le "$JMAX" ] 2>/dev/null && pass "the rest of the fill was unlogged too (the journal took $JW bytes)" || fail "the journal took $JW bytes in the rest of the fill"
burst_all "after a clean stop in the fill"
stop_server

echo
echo "run_db_store_bulk_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

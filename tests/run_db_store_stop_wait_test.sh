#!/bin/sh
# run_db_store_stop_wait_test.sh - 0.7: the Manager does not kill a Backend that is in the stop of its zone store (stopshare_t, SHUTDOWN_STORE_KILL_MS in dns_server_core.c).
#
# The clean checkpoint of the store at a stop ends in fsync()s; on ZFS under load they waited for the pool's transaction group for more than the 10 s after which the Manager kills the
# children that have not ended (suite 2026-11-26: a killed stop sent an unlogged first fill back to the empty store, and run_db_store_test then hung for 8 hours).  A Backend in the
# stop of its store is given up to 120 s.  The test build (karidns-evict) makes that stop take KARIDNS_TEST_STORE_STOP_DELAY_MS longer.  Checked:
#   1. a stop of the store of 15 s: the Manager says at 10 s that it waits, kills nothing, the server ends after the delay, and the next start finds the store clean with every zone;
#   2. a second SIGTERM while the Manager waits kills the Backend at once (said in the log), and the next start finds the stop unclean;
#   3. a server without a database store is not waited for: the stop is as quick as before.
# Root only (the loader runs as nobody, as in the other DB store tests); SKIP otherwise, and without sqlite3 / the test build.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

[ "$(id -u)" = "0" ] || { echo "SKIP: run_db_store_stop_wait_test.sh needs root"; exit 0; }
# the server with the test knob: ./karidns when it has it (the instrumented build of `make coverage` does, -DKARIDNS_TEST_EVICT), else ./karidns-evict (make evict).
# (CI audit 2026-11-26: a test that only looks for ./karidns-evict SKIPs in every CI job, as run_db_store_bulk_test.sh does)
has_knob() { [ -x "$1" ] && grep -q KARIDNS_TEST_STORE_STOP_DELAY_MS "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_knob ./karidns; then KARIDNS=./karidns; else KARIDNS=./karidns-evict; fi
fi
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built (make evict karictl karidns-dbloader)"; exit 0; }
done
has_knob "$KARIDNS" || { echo "SKIP: $KARIDNS has no test knobs (make evict)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
RUNUSER=nobody
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"      # (the sanitizer build leaks what a SIGKILL'd server never frees)

NZ=${STOP_WAIT_ZONES:-2000}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_stopwait.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf" "$T/n.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((26000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db"
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" 7 > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
chown -R "$RUNUSER" "$T/db"; chmod 600 "$T/db/"*.db*
# (the server starts only a loader that root owns)
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/ctl.conf" <<EOF
socket "$T/a.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/ctl.conf"
KA="./karictl -c $T/ctl.conf"
# mkconf NAME STORE-STATEMENT
mkconf() {
    cat > "$T/$1.conf" <<EOF
options {
    user "$RUNUSER"; pid-file "none"; listen-on { 127.0.0.1; }; port $PA; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "$RUNUSER"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               park-timeout 5000; $2 };
};
control-channel { socket "$T/a.sock"; secret "$SECRET"; };
EOF
}
mkconf a "store \"$T/store\"; store-threads 2;"
mkconf n "store none;"
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null && [ "$(sf store.bulk.active)" = 0 ] && [ "$(sf store.bulk.end_pending)" = 0 ]; }
# start CONF LOG DELAY-MS: the server with the stop of its store made DELAY-MS longer; up when the loader is connected
start() {
    env KARIDNS_TEST_STORE_STOP_DELAY_MS="$3" "$KARIDNS" -c "$T/$1.conf" -f > "$T/$2" 2>&1 &
    SRV=$!
    kari_wait_log "$T/$2" "loader stream connected" 60 || { fail "$2: the server did not come up"; tail -20 "$T/$2"; return 1; }
    return 0
}
# gone SECONDS: the server (SRV, the Manager) has ended within SECONDS; ELAPSED is the time it took, in whole seconds of the wall clock (a count of 0.1 s sleeps runs
# slow on a busy host: 15 s were counted as 13.1 s on pc101 next to a fuzzer, 2026-11-26)
gone() { _g0=$(date +%s); ELAPSED=0; while [ "$ELAPSED" -lt "$1" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; ELAPSED=$(($(date +%s) - _g0)); done; ELAPSED=$(($(date +%s) - _g0)); ! kill -0 "$SRV" 2>/dev/null; }
backend_pid() { sed -n 's/^KariDNS \([0-9]*\) - - \[Backend\] Shutting down.*/\1/p' "$T/$1" | head -1; }

echo "== 1. a stop of the store of 15 s: the Manager waits for it"
start a a1.log 15000 || exit 1
waitfor 120 stored_all && pass "the store holds all $NZ zones and the first fill is over" || fail "the store holds $(sf store.zones.stored) of $NZ (bulk.active=$(sf store.bulk.active) end_pending=$(sf store.bulk.end_pending))"
kill -TERM "$SRV"
gone 60 && pass "the server ended $ELAPSED s after SIGTERM" || fail "the server is still there 60 s after SIGTERM"
[ "$ELAPSED" -ge 14 ] && pass "it ended after the delay of the stop of the store (15 s), not at the 10 s of the kill" || fail "it ended after $ELAPSED s, before the delay of 15 s: was it killed?"
grep -q "is still writing the clean checkpoint of the zone store after 10 s: it is given up to 120 s" "$T/a1.log" && pass "the Manager said at 10 s that it waits for the stop of the store" || fail "no line of the Manager that it waits"
grep -q "did not stop; killing it" "$T/a1.log" && fail "the Manager killed a child: $(grep 'did not stop' "$T/a1.log" | head -2)" || pass "the Manager killed no child"
SRV=""
start a a2.log 0 || exit 1
[ "$(sf store.recovery.was_clean)" = 1 ] && [ "$(sf store.bulk.recoveries)" = 0 ] && pass "the next start found the store clean (was_clean=1, no bulk recovery)" || fail "the next start: was_clean=$(sf store.recovery.was_clean) bulk recoveries=$(sf store.bulk.recoveries)"
[ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null && pass "the store still holds all $NZ zones" || fail "stored=$(sf store.zones.stored) after the restart"
kill -TERM "$SRV"
gone 60 || fail "the server is still there 60 s after SIGTERM (no delay)"
SRV=""

echo "== 2. a second SIGTERM while the Manager waits kills the Backend at once"
start a a3.log 60000 || exit 1
kill -TERM "$SRV"
kari_wait_log "$T/a3.log" "it is given up to 120 s" 30 && pass "the Manager waits for the stop of the store" || fail "no line of the Manager that it waits"
BP=$(backend_pid a3.log)
kill -TERM "$SRV"
gone 10 && pass "after the second SIGTERM the server ended within $ELAPSED s" || fail "the server is still there 10 s after the second SIGTERM"
grep -q "Child process ${BP:-x} did not stop; killing it" "$T/a3.log" && pass "the Manager says that it killed the Backend ($BP)" || fail "no line of the kill of the Backend ${BP:-?}: $(grep 'Manager' "$T/a3.log" | tail -3)"
SRV=""
start a a4.log 0 || exit 1
[ "$(sf store.recovery.was_clean)" = 0 ] && pass "the next start found the stop unclean (the Backend was killed before its clean checkpoint)" || fail "the next start: was_clean=$(sf store.recovery.was_clean)"
kill -TERM "$SRV"
gone 60 || fail "the server is still there 60 s after SIGTERM (no delay)"
SRV=""

echo "== 3. without a database store the Manager does not wait"
start n n1.log 15000 || exit 1
kill -TERM "$SRV"
gone 60 && pass "the server ended $ELAPSED s after SIGTERM" || fail "the server is still there 60 s after SIGTERM"
[ "$ELAPSED" -lt 14 ] && ! grep -q "it is given up to" "$T/n1.log" && pass "it was not waited for (no store: the delay of the knob is that of a Backend that ignores SIGTERM)" || fail "the server without a store was waited for ($ELAPSED s): $(grep 'Manager' "$T/n1.log" | tail -2)"
SRV=""

echo "run_db_store_stop_wait_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

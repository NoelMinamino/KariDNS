#!/bin/sh
# run_db_zfs_copy_test.sh - 0.7 M4: the zone store on a ZFS dataset (COPY mode) after a restart.
#
# COPY mode has no attach by a worker (a ZFS pread can block): every first query for a zone that is not in memory waits for a store thread, and after a restart with the ARC warm that is
# the whole working set at once.  Two things make it fast: the threads of the hot list (three quarters of the store threads, at most six; hot.list is written at a clean stop and read at the
# next start) attach the zones of the last run in batches, in the order of their use, without waiting for the queries; and the registry's lock is taken once for a batch, and asks the
# store "is this record as it was read" with one word.  Checked here, on a dataset of its own (recordsize 16K, lz4, atime off) made on the first pool, with COLD_ZONES zones (default 50000):
#   - the store is in COPY mode on ZFS (`store.mode=copy`, `store.fstype=zfs`);
#   - the next start attaches the zones of hot.list in the background with the threads of the list (`store.hot.threads`), state `done`, and `store.hot.attached_per_s` is counted;
#   - a burst of first queries for every zone while the list is being attached is answered with NOERROR for every query (0 SERVFAIL, 0 lost, nothing refused by the server), the workers
#     attach nothing (COPY), and the list is not starved by the rush (it ends, and it has attached or skipped every zone it listed);
#   - a start with `store-hot-list no;` attaches nothing before a query asks, and the queries are answered by the store threads alone.
# SKIP without root, ZFS (zfs, zpool and a pool with 2 GB free), sqlite3, perl or the built binaries.  The dataset is destroyed at the end (and at an interrupt).
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (zfs create, and the loader runs as another user)"; exit 0; fi
command -v zfs >/dev/null 2>&1 && command -v zpool >/dev/null 2>&1 || { echo "SKIP: no ZFS (zfs, zpool)"; exit 0; }
POOL=$(zpool list -H -o name 2>/dev/null | head -1)
[ -n "$POOL" ] || { echo "SKIP: no ZFS pool is imported"; exit 0; }
AVAIL=$(zfs get -Hp -o value available "$POOL" 2>/dev/null)
[ "${AVAIL:-0}" -ge 2147483648 ] 2>/dev/null || { echo "SKIP: the pool $POOL has less than 2 GB free"; exit 0; }
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=${COLD_ZONES:-50000}
WINDOW=${COLD_WINDOW:-2000}
WAIT=${COLD_WAIT:-30}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_zfscopy.XXXXXX") || exit 1
chmod 755 "$T"
DS="$POOL/karidns_zfs_copy_test_$$"
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf"
    zfs destroy -rf "$DS" >/dev/null 2>&1
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((22000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/zfs" "$T/db"
zfs create -o recordsize=16K -o compression=lz4 -o atime=off -o mountpoint="$T/zfs" "$DS" >/dev/null 2>&1 || { echo "SKIP: cannot make a dataset on $POOL"; exit 0; }
echo "== the dataset $DS (recordsize 16K, lz4), the database: $NZ zones"
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
               park-timeout 5000; store "$T/zfs/store"; $1 };
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
fqv() { $KA dbstatus 2>/dev/null | grep '^fetchq:' | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
server_refusals() { echo "park_full=$(fqv park_full) park_timeout=$(fqv park_timeout) queue_full=$(fqv queue_full) queue_dropped=$(fqv queue_dropped) table_full=$(fqv table_full)"; }
fetches() { $KA dbstatus 2>/dev/null | grep '^fetch:' | head -1 | sed -n 's/.* issued=\([0-9]*\).*/\1/p'; }
park_drops() { echo "store.park.drop room=$(sf store.park.drop.room) timeout=$(sf store.park.drop.timeout) queue=$(sf store.park.drop.queue)"; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }
hot_ended() { s=$(sf store.hot.state); [ "$s" = done ] || [ "$s" = high-mark ]; }
burst_check() {   # burst_check LABEL SEED: a burst of one query for every zone, every one must be NOERROR
    OUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" "$2" "$WINDOW" "$WAIT")
    echo "  $OUT"
    bv() { echo "$OUT" | sed -n "s/.* $1=\([0-9.]*\).*/\1/p" | head -1; }
    [ "$(bv noerror)" = "$NZ" ] && [ "$(bv servfail)" = 0 ] && [ "$(bv lost)" = 0 ] && pass "$1: all $NZ queries answered with NOERROR (0 SERVFAIL, 0 lost)" || fail "$1: $OUT"; echo "  $(park_drops)"
    SR0=$(server_refusals)
    case "$SR0" in
    "park_full=0 park_timeout=0 queue_full=0 queue_dropped=0 table_full=0") pass "$1: the server refused no stored zone on its own account ($SR0)" ;;
    *) fail "$1: the server answered SERVFAIL for stored zones itself: $SR0" ;;
    esac
}

echo "== the first fill, and a burst, on ZFS"
conf "memory-limit 4g;"
start_srv
waitfor 600 stored_all && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ zones"
[ "$(sf store.mode)" = copy ] && [ "$(sf store.fstype)" = zfs ] && pass "the store is in COPY mode on zfs (store.mode=$(sf store.mode) store.fstype=$(sf store.fstype))" || fail "store.mode=$(sf store.mode) store.fstype=$(sf store.fstype), not copy on zfs"
burst_check "the first burst" 7
[ "$(sf store.zones.attached)" -ge $((NZ / 2)) ] 2>/dev/null && pass "$(sf store.zones.attached) zones are in memory at the stop" || fail "only $(sf store.zones.attached) zones are in memory"
stop_srv

echo "== the restart: hot.list is attached by the threads of the list while a burst of first queries comes"
conf "memory-limit 4g;"
start_srv
F0=$(fetches); F0=${F0:-0}
[ "$(sf store.hot.listed)" -ge $((NZ / 2)) ] 2>/dev/null && pass "hot.list listed $(sf store.hot.listed) zones" || fail "hot.list listed $(sf store.hot.listed) zones"
[ "$(sf store.hot.threads)" -ge 1 ] 2>/dev/null && [ "$(sf store.hot.threads)" -le 6 ] 2>/dev/null && pass "the list has $(sf store.hot.threads) thread(s) (three quarters of the store threads, at most six)" || fail "store.hot.threads=$(sf store.hot.threads)"
burst_check "the burst during the hot list" 9
waitfor 120 hot_ended && pass "the background attach of hot.list ended ($(sf store.hot.state)): not starved by the burst" || fail "hot.list: state $(sf store.hot.state) after the burst"
HL=$(sf store.hot.listed); HA=$(sf store.hot.attached); HK=$(sf store.hot.skipped)
echo "  hot: state=$(sf store.hot.state) listed=$HL attached=$HA skipped=$HK threads=$(sf store.hot.threads) per_s=$(sf store.hot.attached_per_s); cold: attach=$(sf store.cold.attach) p50=$(sf store.cold.p50_us) us p99=$(sf store.cold.p99_us) us; attach p50=$(sf store.attach.p50_us) us"
[ $((HA + HK)) -eq "$HL" ] 2>/dev/null && pass "the list was worked through (attached $HA + skipped $HK = listed $HL)" || fail "attached $HA + skipped $HK is not listed $HL"
[ "$(sf store.hot.attached_per_s)" -gt 0 ] 2>/dev/null && pass "store.hot.attached_per_s is counted ($(sf store.hot.attached_per_s))" || fail "store.hot.attached_per_s=$(sf store.hot.attached_per_s)"
[ "$(sf store.attach.worker.ok)" = 0 ] && pass "COPY mode: the workers attached nothing (the store threads did)" || fail "the workers attached $(sf store.attach.worker.ok) zones in COPY mode"
F1=$(fetches); F1=${F1:-0}
[ "$F1" = "$F0" ] && pass "the loader read no zone (fetch issued $F0 -> $F1)" || fail "fetch issued went from $F0 to $F1"
[ "$(sf store.zones.attached)" -ge $((NZ / 2)) ] 2>/dev/null && pass "$(sf store.zones.attached) zones are in memory" || fail "only $(sf store.zones.attached) zones are in memory"
stop_srv

echo "== store-hot-list no: nothing is attached before a query asks"
conf "memory-limit 4g; store-hot-list no;"
start_srv
[ "$(sf store.hot.state)" = off ] && [ "$(sf store.hot.threads)" = 0 ] && pass "store-hot-list no: no list, no thread" || fail "store-hot-list no: state $(sf store.hot.state) threads $(sf store.hot.threads)"
[ "$(sf store.zones.attached)" -le $((NZ / 5)) ] 2>/dev/null && pass "nothing is attached before a query asks ($(sf store.zones.attached))" || fail "$(sf store.zones.attached) zones attached without a list"
burst_check "the burst without a list (the store threads alone)" 11
stop_srv

echo
echo "run_db_zfs_copy_test: $PASS ok, $FAILS failed"
[ "$FAILS" = 0 ]

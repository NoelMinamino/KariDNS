#!/bin/sh
# run_db_cold_burst_test.sh - 0.7 store, the cold path: a burst of first-touch queries against a fresh server whose store holds every zone ("a stored zone is answered, never
# sent to the database because a ring is full").
#
# A database of COLD_ZONES zones (default 100000, tests/db/gen_sqlite3_zones.sh) is read once into a store; the server is stopped cleanly and started again, so that no zone is in
# memory and the store has every image.  tests/db/udp_cold_burst.pl then sends one A query for every zone, in a random order, as fast as it can (4000 in flight), which is far more
# than the 128-slot rings and the attach rate of the store threads take at once.  Checked, once with `memory-limit` (large: nothing is taken out of memory) and once without:
#   - every query is answered with NOERROR and an answer (0 SERVFAIL, 0 lost);
#   - the loader read no zone for them (`fetch issued` stays 0: a stored zone is attached from the store, whatever the load);
#   - `karictl store -k` and `karictl dbstatus` answer while the burst runs (the longest wait is reported and bounded: the control thread does not walk the glue of every attached zone).
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
    OUT=$(perl tests/db/udp_cold_burst.pl "$PA" "$NZ" 7 4000 10)
    touch "$T/burst.done"
    wait $SAMP
    echo "  $OUT"
    sv() { echo "$OUT" | sed -n "s/.* $1=\([0-9.]*\).*/\1/p" | head -1; }
    [ "$(sv noerror)" = "$NZ" ] && pass "$label: all $NZ queries answered with NOERROR" || fail "$label: noerror=$(sv noerror) servfail=$(sv servfail) other=$(sv other) lost=$(sv lost) of $NZ"
    [ "$(sv servfail)" = 0 ] && [ "$(sv lost)" = 0 ] && pass "$label: 0 SERVFAIL, 0 lost" || fail "$label: servfail=$(sv servfail) lost=$(sv lost)"
    # the server's own count: every query it was given has an answer (a wake-up that was lost leaves a query parked, whatever the sender sends again)
    SQ=$($KA stats 2>/dev/null | sed -n 's/^karidns_queries_total{proto="udp"} //p' | head -1)
    SR=$($KA stats 2>/dev/null | awk '/^karidns_responses_total/ { s += $2 } END { print s + 0 }')
    [ -n "$SQ" ] && [ "$SQ" = "$SR" ] && [ "$SQ" -ge "$NZ" ] && pass "$label: the server answered every query it was given ($SQ queries, $SR responses)" || fail "$label: the server counts $SQ queries and $SR responses"
    F1=$(fetches); F1=${F1:-0}
    [ "$F1" = "$F0" ] && pass "$label: the loader read no zone (fetch issued $F0 -> $F1)" || fail "$label: fetch issued went from $F0 to $F1: $($KA dbstatus | grep -E '^(fetch|fetchq):')"
    A1=$(sf store.zones.attached); A1=${A1:-0}
    echo "  attach: count=$(sf store.attach.count) p50=$(sf store.attach.p50_us) us p99=$(sf store.attach.p99_us) us; cold: attach=$(sf store.cold.attach) fetch=$(sf store.cold.fetch) timeout=$(sf store.cold.timeout) p50=$(sf store.cold.p50_us) us p99=$(sf store.cold.p99_us) us"
    [ "$A1" -gt "$A0" ] 2>/dev/null && pass "$label: zones were attached from the store ($A0 -> $A1)" || fail "$label: attached $A0 -> $A1"
    MX=$(cat "$T/ctl.max" 2>/dev/null)
    echo "  longest karictl command during the burst: ${MX:-?} s (limit $KARICTL_MAX_S s)"
    perl -e "exit(('${MX:-99}' + 0) < $KARICTL_MAX_S ? 0 : 1)" && pass "$label: karictl answered during the burst (longest ${MX} s)" || fail "$label: a karictl command took ${MX} s during the burst"
    stop_srv
}
burst "with memory-limit" "memory-limit 4g;"
burst "without memory-limit" ""

echo
echo "run_db_cold_burst_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

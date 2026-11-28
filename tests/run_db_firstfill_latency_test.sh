#!/bin/sh
# run_db_firstfill_latency_test.sh - 0.7 first-fill latency (planning W4): while a first fill runs, every query is answered within 1 s, and none is answered SERVFAIL.
#
# Phase 1, for loader-threads 1 (the small server: one worker, which the fill and the queries share) and loader-threads 4: a database of FFL_ZONES zones (default 200000,
# tests/db/gen_sqlite3_zones.sh), an empty store, and a slow database (the test loader waits FFL_DELAY_MS before every read of its fetch pool, KARIDNS_TEST_FETCH_DELAY_MS, as a
# statement of PostgreSQL costs).  From the moment the server answers its control channel until the store holds every zone, tools/dnsqps sends three loads in slices of
# FFL_SLICE seconds, each slice with fresh names and a time-out of one second:
#   known: z<i>.test SOA, i uniform over every zone (most are not filled yet: read for the query, or attached when the fill has stored them)
#   late:  z<i>.test SOA, i in the last tenth (zones the first pass lists last: looked up by name while it runs)
#   nx:    nx<i>.test SOA (no such zone: REFUSED)
# It fails on any query lost at 1 s, on any SERVFAIL, and on any store.park.drop.* / store.lookup.drop.* (the server's own count of what it did not answer).  The time from the start
# of the server to the first answer (the sockets are made before the fill, item 4 of the plan) is printed, not gated.  After the fill: the zones of a read of the fill
# ("fetch reads ... zones a read", the loader's line) with no query load, at least 32 (W5: the fill reads whole IN statements, not 2 zones a statement).
# Phase 2, a database that cannot be read (W3): five zones, `store none`, a zone taken out of memory (karictl evict) and the database file moved away: an ordinary query for it is not
# answered (dag: no answer), counted (store.park.drop.failed); an AXFR of a zone that is out of memory gets SERVFAIL + EDE 14 (transfers are not ordinary queries); one WARNING line
# in a window says how many queries were not answered (KARIDNS_TEST_DBDOWN_LOG_S=2), not one line a query.
# Phase 3, a flood of queries stalls the fill (loader-threads 1) while bodies of the fill expire (KARIDNS_TEST_FETCH_TIMEOUT_MS=1500): a stall of the queries'
# (store.ingest.fill_stalled_windows), not a failure.  Phase 4, the fill's reads fail (the test loader's KARIDNS_TEST_FILL_FAIL=1): store.ingest.fill_failed_windows, not a stall.
# Needs root (the loader runs as nobody), sqlite3, perl, ./dag, ./dnsqps, ./karictl, the server and the loader with the test switches (./karidns and ./karidns-dbloader of `make coverage`,
# else ./karidns-evict and ./karidns-dbloader-evict: make evict karidns-dbloader-evict).  SKIP without them.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
has_srv_knob() { [ -x "$1" ] && grep -q KARIDNS_TEST_DBDOWN_LOG_S "$1" 2>/dev/null; }
has_ldr_knob() { [ -x "$1" ] && grep -q KARIDNS_TEST_FETCH_DELAY_MS "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_srv_knob ./karidns; then KARIDNS=./karidns; else KARIDNS=./karidns-evict; fi
fi
if [ -z "${LOADER:-}" ]; then
    if has_ldr_knob ./karidns-dbloader; then LOADER=./karidns-dbloader; else LOADER=./karidns-dbloader-evict; fi
fi
for b in "$KARIDNS" "$LOADER" ./karictl ./dag ./dnsqps; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
has_srv_knob "$KARIDNS" || { echo "SKIP: $KARIDNS has no test switches (make evict)"; exit 0; }
has_ldr_knob "$LOADER" || { echo "SKIP: $LOADER has no test switches (make karidns-dbloader-evict)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=${FFL_ZONES:-200000}
DELAY=${FFL_DELAY_MS:-5}
SLICE=${FFL_SLICE:-5}
MAXS=${FFL_MAX_S:-600}                       # the longest a fill may take before the test gives up on it
Q_KNOWN=${FFL_QPS_KNOWN:-500}
Q_LATE=${FFL_QPS_LATE:-100}
Q_NX=${FFL_QPS_NX:-50}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_ffl.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
QPIDS=""
cleanup() {
    set +e
    for p in $QPIDS; do kill "$p" 2>/dev/null; done
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((23000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"      # (the evict command leaks what it takes out of memory on purpose)

PHASES=${FFL_PHASES:-1 3 4 2}                # (1: the fills, 3: a flood that stalls the fill, 4: the fill's reads fail, 2: the database that cannot be read)
mkdir "$T/db"
case " $PHASES " in *" 1 "*|*" 3 "*|*" 4 "*)
    echo "== the database: $NZ zones, the loader waits $DELAY ms before every read of its fetch pool"
    sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" 11 > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
    chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
;; esac
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader.real" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader.real"; chown 0:0 "$T/karidns-dbloader.real"; chmod 755 "$T/karidns-dbloader.real"; }
# the supervisor starts the loader with a cleared environment: a script in loader-path sets the switch
printf '#!/bin/sh\nKARIDNS_TEST_FETCH_DELAY_MS=%s; export KARIDNS_TEST_FETCH_DELAY_MS\nexec %s "$@"\n' "$DELAY" "$T/karidns-dbloader.real" > "$T/karidns-dbloader"
chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"
cat > "$T/a.ctl.conf" <<EOF
socket "$T/a.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/a.ctl.conf"
KA="./karictl -c $T/a.ctl.conf"
conf() {   # conf DATABASE-FILE "extra database statements" ["extra options statements"]
    cat > "$T/a.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PA; notify no; allow-transfer { 127.0.0.1; }; send-extended-errors yes; ${3:-}
    database { driver sqlite3; database-file "$1"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               park-timeout 5000; $2 };
};
control-channel { socket "$T/a.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/a.log"
    env KARIDNS_TEST_DBDOWN_LOG_S=2 ${SRV_ENV:-} "$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 &      # (SRV_ENV: more test switches of a phase)
    SRV=$!
}
stop_srv() {
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
ctl_up() { $KA status > /dev/null 2>&1; }
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }
now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }

# one class of queries, in slices of SLICE seconds with fresh names, until $T/fill.over exists: "t json" lines in $T/q_CLASS
qloop() {   # qloop CLASS QPS LO HI (LO = 0: nx names)
    k=0
    : > "$T/q_$1"
    while [ ! -e "$T/fill.over" ]; do
        k=$((k + 1))
        awk -v n=$(($2 * SLICE)) -v lo="$3" -v hi="$4" -v sd="$k$2" 'BEGIN { srand(sd); for (i = 0; i < n; i++) if (lo == 0) printf "nx%d.test SOA\n", int(rand() * 1000000000); else printf "z%d.test SOA\n", lo + int(rand() * (hi - lo + 1)) }' > "$T/qf_$1"
        j=$(./dnsqps -s 127.0.0.1 -p "$PA" -d "$T/qf_$1" -Q "$2" -l "$SLICE" -t 1 -T 1 --json 2>/dev/null)
        echo "$(( ($(now_ms) - T0) / 1000 )) $j" >> "$T/q_$1"
    done
}
jv() { echo "$2" | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" | head -1; }
jrc() { echo "$2" | sed -n "s/.*\"rcodes\":{[^}]*\"$1\":\([0-9]*\).*/\1/p" | head -1; }
jlat() { echo "$2" | sed -n "s/.*\"latency_s\":{[^}]*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }   # (seconds, a decimal: p50, p90, p99, max)
# the longest times of the server's own counters (diagnostics of a slow slice, flake row 103): only the ones this build reports
max_counters() {
    out=""
    for k in store.fetch.query.rtt.max_us store.ingest.loop_max_us store.cold.max_us store.attach.max_us store.lock.writer_hold_max_us store.checkpoint.max_us store.bulk.presync_max_us; do
        v=$(sf "$k"); [ -n "$v" ] && out="$out $k=$v"
    done
    echo "  max:${out:- (none reported)}"
}

fill_run() {   # fill_run LT: a first fill with loader-threads LT under the three loads
    lt=$1
    echo "== the first fill, loader-threads $lt, with queries from the start"
    rm -rf "$T/store" "$T/fill.over"
    conf "$T/db/z.db" "loader-threads $lt; store \"$T/store\"; memory-limit 4g;"
    T0=$(now_ms)
    start_srv
    waitfor 60 ctl_up || { fail "lt=$lt: the control channel did not answer"; tail -20 "$T/a.log"; stop_srv; return; }
    # the first answer: when the sockets answer at all (printed, not gated: the kernel queues what comes before)
    i=0; FIRST=""
    while [ $i -lt 300 ]; do
        if ./dag @127.0.0.1 -p "$PA" nx0.test SOA +short +nohexdump +time=1 +tries=1 > /dev/null 2>&1; then FIRST=$(( $(now_ms) - T0 )); break; fi
        i=$((i + 1))
    done
    echo "  the first answer $FIRST ms after the start"
    QPIDS=""
    qloop known "$Q_KNOWN" 1 "$NZ" & QPIDS="$QPIDS $!"
    qloop late "$Q_LATE" $((NZ - NZ / 10)) "$NZ" & QPIDS="$QPIDS $!"
    qloop nx "$Q_NX" 0 0 & QPIDS="$QPIDS $!"
    if waitfor "$MAXS" stored_all; then
        pass "lt=$lt: the store holds all $NZ zones after $(( ($(now_ms) - T0) / 1000 )) s"
    else
        fail "lt=$lt: the store holds $(sf store.zones.stored) of $NZ zones after $MAXS s"
    fi
    touch "$T/fill.over"
    for p in $QPIDS; do wait "$p" 2>/dev/null; done
    QPIDS=""
    sent=0; lost=0; sfail=0; bad=0; late=0
    for c in known late nx; do
        while read -r t j; do
            s=$(jv sent "$j"); l=$(jv lost "$j"); f=$(jrc SERVFAIL "$j"); u=$(jv unmatched "$j")
            [ -n "$s" ] || { bad=$((bad + 1)); echo "    $c t=$t: no report: $j"; continue; }
            sent=$((sent + s)); lost=$((lost + ${l:-0})); sfail=$((sfail + ${f:-0})); late=$((late + ${u:-0}))
            if [ "${l:-0}" != 0 ] || [ "${f:-0}" != 0 ] || [ "${u:-0}" != 0 ]; then echo "    $c slice at t=${t}s: $j"; fi
            p99=$(jlat p99 "$j")      # (output only: a slow slice, p99 above 0.25 s, with its spread; not gated)
            if [ -n "$p99" ] && awk -v p="$p99" 'BEGIN { exit !(p > 0.25) }'; then
                echo "    slow $c slice t=${t}s: sent=$s lost=${l:-0} p50=$(jlat p50 "$j") p90=$(jlat p90 "$j") p99=$p99 max=$(jlat max "$j")"
            fi
        done < "$T/q_$c"
    done
    echo "  queries: $sent sent, $lost lost at 1 s, $late answered after 1 s (unmatched), $sfail SERVFAIL"
    [ "$sent" -gt 0 ] && [ "$bad" = 0 ] && pass "lt=$lt: the loads ran ($sent queries in $(cat "$T/q_known" "$T/q_late" "$T/q_nx" | wc -l | tr -d ' ') slices)" || fail "lt=$lt: $bad slices without a report, $sent queries"
    [ "$lost" = 0 ] && pass "lt=$lt: no query lost at 1 s" || fail "lt=$lt: $lost queries lost at 1 s"
    [ "$late" = 0 ] && pass "lt=$lt: no answer came after 1 s" || fail "lt=$lt: $late answers came after 1 s (dnsqps unmatched: a late answer is a failure)"
    [ "$sfail" = 0 ] && pass "lt=$lt: no SERVFAIL" || fail "lt=$lt: $sfail SERVFAIL"
    DROPS=$($KA store -k 2>/dev/null | grep -E '^store\.(park|lookup)\.drop\.' | tr '\n' ' ')
    NZD=$(echo "$DROPS" | tr ' ' '\n' | grep -v '=0$' | grep -c .)
    [ "$NZD" = 0 ] && pass "lt=$lt: the server dropped nothing (store.park.drop.*, store.lookup.drop.* all 0)" || fail "lt=$lt: drops: $DROPS"
    if [ "$lost" != 0 ] || [ "$late" != 0 ] || [ "$sfail" != 0 ] || [ "$NZD" != 0 ]; then
        echo "  $($KA dbstatus 2>/dev/null | grep -E '^(fetchq|lookup of names)' | sed 's/ hist=.*//')"
        echo "  store.lookup.rtt.p99_us=$(sf store.lookup.rtt.p99_us) store.cold.p99=$(sf store.cold.p99_us) journal_wait_slices=$(sf store.ingest.journal_wait_slices)"
        max_counters
        kari_log_tail "$T/a.log" 2>/dev/null || tail -20 "$T/a.log"
    fi
    grep 'fetch reads in' "$T/a.log" | tail -3 | sed 's/^/  loader: /'
    stop_srv
}

case " $PHASES " in *" 1 "*)
fill_run 1
fill_run 4

echo "== the fill alone (no queries): the zones of a read of the fill"
rm -rf "$T/store" "$T/fill.over"
conf "$T/db/z.db" "loader-threads 4; store \"$T/store\"; memory-limit 4g;"
start_srv
waitfor 60 ctl_up || fail "the control channel did not answer"
waitfor "$MAXS" stored_all && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ zones"
i=0; while [ $i -lt 100 ] && ! grep -q 'fetch reads in' "$T/a.log"; do sleep 0.1; i=$((i + 1)); done
FR=$(grep 'fetch reads in' "$T/a.log" | tail -1)
ZPR=$(echo "$FR" | sed -n 's/.*(\([0-9.]*\) zones a read).*/\1/p')
echo "  loader: $FR"
perl -e "exit(!(${ZPR:-0} >= 32))" && pass "the fill reads ${ZPR} zones a read (at least 32: before, about 2)" || fail "the fill reads ${ZPR:-?} zones a read"
stop_srv
;; esac

case " $PHASES " in *" 3 "*)
# queries first (0.7, fq_pick()): a flood of queries that keeps the one worker of loader-threads 1 busy stalls the fill; the stall is counted and said once a window, and the fill goes on by
# itself when the flood stops (a NOTICE), to the end
echo "== a flood of queries stalls the fill (loader-threads 1, 20 ms a read), which goes on when it stops"
printf '#!/bin/sh\nKARIDNS_TEST_FETCH_DELAY_MS=20; export KARIDNS_TEST_FETCH_DELAY_MS\nexec %s "$@"\n' "$T/karidns-dbloader.real" > "$T/karidns-dbloader"
rm -rf "$T/store"
conf "$T/db/z.db" "loader-threads 1; store \"$T/store\"; memory-limit 4g;"
SRV_ENV="KARIDNS_TEST_FETCH_TIMEOUT_MS=1500"          # (review #279, A: the bodies of the fill that wait behind the flood expire, as they do in 30 s in production; the stall stays the queries')
start_srv
SRV_ENV=""
waitfor 60 ctl_up || fail "the control channel did not answer"
awk -v n=40000 -v hi="$NZ" 'BEGIN { srand(77); for (i = 0; i < n; i++) printf "z%d.test SOA\n", 1 + int(rand() * hi) }' > "$T/qf_flood"
./dnsqps -s 127.0.0.1 -p "$PA" -d "$T/qf_flood" -Q 4000 -l 10 -t 1 -T 1 --json > "$T/flood.json" 2>/dev/null
FS=$(sf store.ingest.fill_stalled_windows)
[ "${FS:-0}" -ge 1 ] && grep -q 'the fill of the store made no progress' "$T/a.log" && pass "the flood stalled the fill: counted (store.ingest.fill_stalled_windows $FS) and said ($(grep -c 'made no progress' "$T/a.log") lines)" \
    || fail "no stall seen: store.ingest.fill_stalled_windows ${FS:-?}, stored $(sf store.zones.stored); $(grep 'fetch reads in' "$T/a.log" | tail -1)"
FF=$(sf store.ingest.fill_failed_windows); FT=$(sf store.ingest.fetch_timeouts)
[ "${FT:-0}" -ge 1 ] && pass "bodies waited behind the flood until they expired (store.ingest.fetch_timeouts $FT)" || fail "no fetch expired (store.ingest.fetch_timeouts ${FT:-?}): the case below is not tested"
[ "${FF:-x}" = 0 ] && grep -q 'made no progress.*the queries take the loader first' "$T/a.log" && ! grep -q 'made no progress.*reads of the database failed' "$T/a.log" \
    && pass "the stall is said to be the queries' although bodies expired (store.ingest.fill_failed_windows 0: no read of the database failed)" \
    || fail "the stall is not told apart: store.ingest.fill_failed_windows ${FF:-?}, fetch_timeouts ${FT:-?}; $(grep 'made no progress' "$T/a.log" | tail -1)"
waitfor 30 grep -q 'the fill of the store goes on' "$T/a.log" && pass "the NOTICE that the fill goes on" || fail "no NOTICE that the fill goes on"
waitfor "$MAXS" stored_all && pass "the fill went on to the end: the store holds all $NZ zones" || fail "the fill did not end: $(sf store.zones.stored) of $NZ zones"
stop_srv
printf '#!/bin/sh\nKARIDNS_TEST_FETCH_DELAY_MS=%s; export KARIDNS_TEST_FETCH_DELAY_MS\nexec %s "$@"\n' "$DELAY" "$T/karidns-dbloader.real" > "$T/karidns-dbloader"
;; esac

case " $PHASES " in *" 4 "*)
# (review #279, A, B) the fill's own reads fail (the test loader answers every request of the fill with a read error, KARIDNS_TEST_FILL_FAIL=1): a window without progress is counted as
# failed and said so, not blamed on queries (there are none)
echo "== the fill's reads of the database fail"
printf '#!/bin/sh\nKARIDNS_TEST_FILL_FAIL=1; KARIDNS_TEST_FETCH_DELAY_MS=200; export KARIDNS_TEST_FILL_FAIL KARIDNS_TEST_FETCH_DELAY_MS\nexec %s "$@"\n' "$T/karidns-dbloader.real" > "$T/karidns-dbloader"   # (200 ms a read: the failing reads go on over several windows, not all in the first)
rm -rf "$T/store"
conf "$T/db/z.db" "loader-threads 2; store \"$T/store\"; memory-limit 4g;"
start_srv
waitfor 60 ctl_up || fail "the control channel did not answer"
waitfor 30 sh -c "[ \"\$($KA store -k 2>/dev/null | sed -n 's/^store.ingest.fill_failed_windows=//p')\" -ge 1 ] 2>/dev/null" \
    && grep -q 'made no progress.*reads of the database failed' "$T/a.log" \
    && pass "a fill whose reads fail is counted as failed and said so (store.ingest.fill_failed_windows $(sf store.ingest.fill_failed_windows))" \
    || fail "the failed fill is not told: fill_failed_windows $(sf store.ingest.fill_failed_windows), fill_stalled_windows $(sf store.ingest.fill_stalled_windows); $(grep 'made no progress' "$T/a.log" | tail -1)"
[ "$(sf store.ingest.fill_stalled_windows)" = 0 ] && ! grep -q 'made no progress.*the queries take the loader first' "$T/a.log" \
    && pass "and not as a stall of the queries (store.ingest.fill_stalled_windows 0)" || fail "the failed fill was blamed on queries: fill_stalled_windows $(sf store.ingest.fill_stalled_windows)"
stop_srv
printf '#!/bin/sh\nKARIDNS_TEST_FETCH_DELAY_MS=%s; export KARIDNS_TEST_FETCH_DELAY_MS\nexec %s "$@"\n' "$DELAY" "$T/karidns-dbloader.real" > "$T/karidns-dbloader"
;; esac

case " $PHASES " in *" 2 "*)
echo "== a database that cannot be read"
mkdir "$T/db2"
sh tests/db/gen_sqlite3_zones.sh "$T/db2/s.db" 5 11 > "$T/gen2.log" 2>&1 || { echo "gen failed"; cat "$T/gen2.log"; exit 1; }
chown -R nobody "$T/db2"; chmod 700 "$T/db2"; chmod 600 "$T/db2/s.db"*
conf "$T/db2/s.db" "store none; transfer-fetch-timeout 2000;"
start_srv
waitfor 60 ctl_up || fail "the control channel did not answer"
waitfor 60 sh -c "./dag @127.0.0.1 -p $PA www.z3.test A +short +nohexdump +time=1 +tries=1 2>/dev/null | grep -q ." && pass "the zones are served" || fail "z3.test is not served"
$KA evict z3.test > /dev/null 2>&1 && $KA evict z4.test > /dev/null 2>&1 && pass "z3.test and z4.test are out of memory" || fail "karictl evict: $($KA evict z3.test 2>&1)"
mv "$T/db2" "$T/db2.gone"
D0=$(sf store.park.drop.failed); D0=${D0:-0}
# NB queries at once (in one window of the WARNING, 2 s): none is answered, and the log has a line a window, not a line a query
NB=20
DPIDS=""
k=0; while [ $k -lt $NB ]; do
    ( ./dag @127.0.0.1 -p "$PA" www.z3.test A +nohexdump +time=1 +tries=1 > "$T/q2.$k.out" 2>&1; echo $? > "$T/q2.$k.rc" ) &
    DPIDS="$DPIDS $!"
    k=$((k + 1))
done
for p in $DPIDS; do wait "$p"; done          # (not a bare wait: the server is a child of this shell too)
NOANS=0
k=0; while [ $k -lt $NB ]; do
    if [ "$(cat "$T/q2.$k.rc")" = 9 ]; then NOANS=$((NOANS + 1)); else echo "  an answer: $(grep -E 'status:|EDE' "$T/q2.$k.out" | head -2 | tr '\n' ' ')"; fi
    k=$((k + 1))
done
[ "$NOANS" = "$NB" ] && pass "an ordinary query for a zone the database cannot give is not answered ($NOANS of $NB; dag exit 9)" || fail "$((NB - NOANS)) of $NB queries were answered"
waitfor 10 sh -c "[ \"\$($KA store -k 2>/dev/null | sed -n 's/^store.park.drop.failed=//p')\" -gt $D0 ] 2>/dev/null" && pass "the drops are counted (store.park.drop.failed $D0 -> $(sf store.park.drop.failed))" || fail "store.park.drop.failed stays $(sf store.park.drop.failed); $($KA dbstatus 2>/dev/null | grep -E '^fetchq' | sed 's/ hist=.*//')"
waitfor 15 grep -q 'queries were not answered in the last' "$T/a.log" && pass "the WARNING of the window: $(grep 'queries were not answered in the last' "$T/a.log" | head -1 | sed 's/.*\[DB\] //' | cut -c1-200)" || fail "no WARNING about the queries that were not answered"
NW=$(grep -c 'queries were not answered in the last' "$T/a.log")
NF=$(grep -c 'fetch of zone .* failed' "$T/a.log")
[ "$NW" -le 2 ] && [ "$NF" -le 2 ] && pass "a line a window, not a line a query ($NB queries: $NW lines of the window, $NF of a failed fetch)" || fail "$NB queries: $NW lines of the window, $NF of a failed fetch"
./dag @127.0.0.1 -p "$PA" z4.test AXFR +nohexdump +time=5 +tries=1 > "$T/x.out" 2>&1
# (dag prints "; Transfer failed." for an error rcode of a transfer, as dig does; the server says which: SERVFAIL, Not Ready = EDE 14 of RFC 8914 4.15, axfr_send_error())
grep -q 'Transfer failed' "$T/x.out" && waitfor 5 grep -q 'AXFR request failed: the zone data could not be read in time (SERVFAIL, Not Ready)' "$T/a.log" \
    && pass "an AXFR of a zone that is out of memory gets SERVFAIL + EDE 14 when the database cannot give it (a transfer is not an ordinary query)" \
    || { fail "AXFR of z4.test:"; sed 's/^/    /' "$T/x.out" | head -15; grep -i 'axfr' "$T/a.log" | tail -3; }
# options { not-ready-answer servfail; } (W6, reloadable): the same query gets SERVFAIL + EDE 14, as BIND
conf "$T/db2/s.db" "store none; transfer-fetch-timeout 2000;" "not-ready-answer servfail;"
$KA reload > /dev/null 2>&1
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    ./dag @127.0.0.1 -p "$PA" www.z3.test A +nohexdump +time=3 +tries=1 > "$T/q3.out" 2>&1
    grep -q 'status: SERVFAIL' "$T/q3.out" && { ok=1; break; }
    sleep 0.3                                      # (a bounded wait for the reload to be published)
done
[ "$ok" = 1 ] && grep -q 'EDE: 14' "$T/q3.out" && pass "not-ready-answer servfail: the query gets SERVFAIL + EDE 14" || { fail "not-ready-answer servfail:"; grep -E 'status:|EDE|reached' "$T/q3.out" | sed 's/^/    /'; }
conf "$T/db2/s.db" "store none; transfer-fetch-timeout 2000;"
$KA reload > /dev/null 2>&1
mv "$T/db2.gone" "$T/db2"
waitfor 30 sh -c "./dag @127.0.0.1 -p $PA www.z3.test A +short +nohexdump +time=1 +tries=1 2>/dev/null | grep -q ." && pass "the database is back: the zone is answered" || fail "the zone is not answered after the database came back"
waitfor 15 grep -q 'the database is read again' "$T/a.log" && pass "the NOTICE that the database is read again" || fail "no NOTICE that the database is read again"
stop_srv
;; esac

echo
echo "run_db_firstfill_latency_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

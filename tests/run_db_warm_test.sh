#!/bin/sh
# run_db_warm_test.sh - the hot list, the warm-up and warm-before-serve (D1a step 7, design 8.4 and 3.3), with the real karidns, the real karidns-dbloader and SQLite3.
#
# With database { memory-limit; loader-state-file } the Backend makes a list of the zones most asked for (every hot-list-interval seconds, from the frequencies the
# zones keep), sends it to the loader (HOT_LIST), which merges it into its state file; after a restart the loader sends the list back (WARM_LIST) and the Backend reads
# the zones in the order of the list, with the priority "warm" (below the queries, through fetch-rate), until memory-limit's high water mark.  Checked:
#   - the file is written, in the order of the frequencies (12 zones asked for 12, 11, ..., 1 times), with a header and an END line
#   - after a restart the zones are in memory before the first query (and the first query is not a miss); with a small memory-limit the warm-up stops at the high
#     water mark and the zones that are in memory are the hottest ones, in the order of the list
#   - a corrupt, a truncated and an empty state file are ignored (a log line, `karictl dbstatus`), the server serves, and the next hot list replaces the file
#   - a restart of the loader (kill -9) warms again what the Backend lost (needs the test hook of karidns-evict; that part is SKIPped without it)
#   - warm-before-serve: the queries wait until the hot list is read (fetch-rate 1: about 10 s), or until the time is up; karictl dbstatus works meanwhile
#   - karictl dbstatus: the new lines, and the old ones are still there; karicheck db checks the state file's directory and contents
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
# the test hook (karictl evict) is in karidns-evict; the phase that needs it runs that build (with the loader of this run)
has_hook() { [ -x "$1" ] && grep -q 'no such zone in memory' "$1" 2>/dev/null; }
HOOKBIN=""
if has_hook "$KARIDNS"; then HOOKBIN=$KARIDNS; elif has_hook ./karidns-evict; then HOOKBIN=./karidns-evict; fi

NZ=12            # zones z0001 .. z0012, 1000 A records each (a zone is about 100 KB in memory)
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_warm.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 200 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() { stop_srv; rm -rf "$T"; }
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
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $NZ)
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.1', 300, 0, 0 FROM domains;
WITH RECURSIVE m(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM m WHERE j < 999)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || m.j || '.' || d.name, 'A', '192.0.2.' || (m.j % 250 + 1), 300, 0, 0 FROM domains d, m;
SQL
chown -R nobody "$T/db" "$T/st"; chmod 600 "$T/db/z.db"*; chmod 700 "$T/st"
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf LIMIT EXTRA-OPTIONS
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               memory-limit $1; loader-state-file "$ST"; hot-list-interval 1; park-timeout 4000; $2 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_bg() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
}
wait_load() {
    i=0
    while [ $i -lt 600 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
}
start_srv() { start_bg; wait_load; }
dbs() { $KCTL dbstatus 2>/dev/null; }
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=5 +tries=1 2>/dev/null | head -1; }
zn() { printf 'z%04d' "$1"; }
waitfor() {   # waitfor SECONDS COMMAND...: the command succeeds within SECONDS
    w=$1; shift
    i=0
    while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
field() {   # field LINE-PREFIX KEY: the number after KEY= on the first dbstatus line that starts with LINE-PREFIX
    dbs | grep "^$1" | head -1 | sed -n "s/.* $2=\([0-9]*\).*/\1/p"
}
resident_zones() {   # the numbers of the zones in memory, in order
    n=1
    while [ $n -le $NZ ]; do
        z="$(zn $n).test"
        $KCTL dbstatus "$z" 2>/dev/null | grep -q "(the data is out of memory" || printf '%s ' "$n"
        n=$((n + 1))
    done
}
state_zones() { awk -F'\t' 'NF == 2 { sub(/\.test\.$/, "", $2); print $2 }' "$ST" 2>/dev/null | tr '\n' ' '; }
want_order() { n=1; while [ $n -le $NZ ]; do printf '%s ' "$(zn $n)"; n=$((n + 1)); done; }
state_ok() { [ "$(state_zones)" = "$(want_order)" ]; }
now_s() { perl -MTime::HiRes=time -e 'printf "%.2f\n", time'; }
fix_state() { chown nobody "$ST" 2>/dev/null; chmod 600 "$ST" 2>/dev/null; }

echo "== no memory-limit pressure: the hot list is written in the order of the frequencies"
conf 256m "fetch-rate 5000;"
start_srv
waitfor 15 sh -c "./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep -q '^warm: received=1 '" && pass "the loader's (empty) WARM_LIST has arrived" || fail "warm line: $(dbs | grep '^warm:')"
dbs | grep -q '^warm-before-serve: off' && pass "dbstatus: warm-before-serve is off by default" || fail "dbstatus shows no 'warm-before-serve: off'"
dbs | grep -q '^state-file: .* at_start=missing' && pass "dbstatus: the state file did not exist at the start" || fail "dbstatus state-file line: $(dbs | grep '^state-file')"
for line in '^zone directory: ' '^cache: limit=' '^residency: directory=' '^queries: answered=' '^warm: received=1 ' '^state-file: '; do
    dbs | grep -q "$line" && pass "dbstatus has a line '$line'" || fail "dbstatus has no line '$line'"
done
n=1
while [ $n -le $NZ ]; do                   # z0001 is asked for 12 times, z0002 11 times, ... z0012 once
    k=$((NZ + 1 - n))
    while [ $k -gt 0 ]; do q "www.$(zn $n).test" > /dev/null; k=$((k - 1)); done
    n=$((n + 1))
done
waitfor 20 state_ok && pass "the state file lists the 12 zones, the most asked for first" || fail "state file order: '$(state_zones)' (want '$(want_order)')"
head -1 "$ST" | grep -q '^KARIDNS-HOT-LIST 1$' && tail -1 "$ST" | grep -q "^END $NZ [0-9a-f]\{8\}$" && pass "the file has its header and an END line with the count" || fail "bad header or END line: $(head -1 "$ST") / $(tail -1 "$ST")"
[ "$(stat -f %Lp "$ST" 2>/dev/null || stat -c %a "$ST")" = "600" ] && pass "the file is private (0600)" || fail "mode of the state file is not 0600"
ls "$T/st" | grep -q 'tmp' && fail "a temporary file is left in the state directory: $(ls "$T/st")" || pass "no temporary file is left behind"
W=$(field state-file written); [ "${W:-0}" -ge 1 ] && pass "dbstatus: the loader acknowledged $W write(s) of the state file" || fail "dbstatus shows no written acknowledgement"
cp "$ST" "$T/good.state"
res_ok() { RES=$(field residency resident); [ "${RES:-0}" -ge "$NZ" ]; }       # (the residency line is counted at most once a second)
waitfor 5 res_ok
[ "${RES:-0}" -ge "$NZ" ] && pass "all $NZ zones are in memory (residency line: $RES)" || fail "residency line: resident=$RES"
queries_ok() { dbs | grep -q '^queries: answered=[1-9][0-9]* parked=[0-9]* hit_rate=[0-9.]*%'; }
waitfor 5 queries_ok
dbs | grep -q '^queries: answered=[1-9][0-9]* parked=[0-9]* hit_rate=[0-9.]*%' && pass "dbstatus shows answered / parked / hit_rate" || fail "queries line: $(dbs | grep '^queries')"
stop_srv

echo "== after a restart the zones are in memory before the first query"
cp "$T/good.state" "$ST"; fix_state
conf 256m "fetch-rate 5000;"
start_srv
waitfor 20 sh -c "[ \"\$(./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep '^warm:' | sed -n 's/.* loaded=\([0-9]*\).*/\1/p')\" = $NZ ]" && pass "the warm-up read all $NZ zones of the list" || fail "warm line: $(dbs | grep '^warm:')"
dbs | grep -q "^state-file: .* at_start=loaded ($NZ zones)" && pass "dbstatus: the state file was loaded at the start ($NZ zones)" || fail "state-file line: $(dbs | grep '^state-file')"
M0=$(field cache misses)
[ "$(q www.$(zn 1).test)" = "192.0.2.80" ] && [ "$(q www.$(zn 12).test)" = "192.0.2.80" ] && pass "the first queries are answered" || fail "no answer"
M1=$(field cache misses)
[ "${M0:-0}" = "${M1:-1}" ] && pass "... without a miss: the zones were in memory already (misses $M0 -> $M1)" || fail "the first queries parked (misses $M0 -> $M1)"
dbs | grep '^warm:' | grep -q ' skipped=0 ' && pass "nothing was skipped" || fail "warm line: $(dbs | grep '^warm:')"
grep -q '\[DB\] warm-up: .* received from the loader' "$T/srv.log" && pass "the log says the hot list was received" || fail "no warm-up line in the server log"
stop_srv

echo "== a small memory-limit: the warm-up stops at the high water mark, and the hottest zones are the ones in memory"
cp "$T/good.state" "$ST"; fix_state
conf 1m "fetch-rate 5000;"
start_srv
waitfor 30 sh -c "./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep '^warm:' | grep -q 'received=1 .* pending=0 in_flight=0'" && pass "the warm-up is over" || fail "warm line: $(dbs | grep '^warm:')"
sleep 1
R=$(resident_zones)
K=$(echo $R | wc -w | tr -d ' ')
echo "  zones in memory: $R(of $NZ)"
[ "$K" -ge 2 ] && [ "$K" -lt "$NZ" ] && pass "some of the zones are in memory ($K), not all of them" || fail "$K zones in memory"
n=1; exp=""; while [ $n -le "$K" ]; do exp="$exp$n "; n=$((n + 1)); done
[ "$R" = "$exp" ] && pass "they are the first $K zones of the list, the most asked for" || fail "in memory: '$R', want '$exp'"
MEMDROP=$(dbs | grep '^warm:' | sed -n 's/.*memory limit \([0-9]*\),.*/\1/p')
[ "${MEMDROP:-0}" -gt 0 ] && pass "dbstatus: $MEMDROP zone(s) were not read because of the memory limit" || fail "warm line: $(dbs | grep '^warm:')"
grep -q 'reached the high water mark of memory-limit' "$T/srv.log" && pass "the log says the warm-up stopped at the high water mark" || fail "no high water line in the log"
LIM=$(field cache limit); RSD=$(field cache resident)
[ "$RSD" -le $((LIM + LIM / 10)) ] && pass "the zones in memory ($RSD bytes) are within memory-limit ($LIM)" || fail "resident $RSD above the limit $LIM"
EV=$(field cache evictions)
[ "${EV:-1}" = "0" ] && pass "no zone was taken out of memory to warm others" || fail "$EV evictions during the warm-up"
stop_srv

echo "== a state file that is corrupt, truncated or empty is ignored"
conf 256m "fetch-rate 5000;"
for bad in garbage truncated empty badcount; do
    case $bad in
        garbage)   printf 'this is not a state file\nat all\n' > "$ST" ;;
        truncated) head -c 150 "$T/good.state" > "$ST" ;;
        empty)     : > "$ST" ;;
        badcount)  sed 's/^END [0-9]*/END 99/' "$T/good.state" > "$ST" ;;
    esac
    fix_state
    start_srv
    grep -q "state file $ST is ignored" "$T/srv.log" && pass "$bad: the loader says it ignores the file" || fail "$bad: no 'is ignored' line in the log"
    dbs | grep -q '^state-file: .* at_start=corrupt, ignored' && pass "$bad: dbstatus says: corrupt, ignored" || fail "$bad: state-file line: $(dbs | grep '^state-file')"
    [ "$(q www.$(zn 3).test)" = "192.0.2.80" ] && pass "$bad: the server answers" || fail "$bad: no answer"
    L=$(dbs | grep '^warm:' | sed -n 's/.* queued=\([0-9]*\).*/\1/p')
    [ "${L:-1}" = "0" ] && pass "$bad: nothing was warmed from it" || fail "$bad: warm line: $(dbs | grep '^warm:')"
    waitfor 15 sh -c "head -1 '$ST' | grep -q '^KARIDNS-HOT-LIST 1\$' && tail -1 '$ST' | grep -q '^END [0-9]'" && pass "$bad: the next hot list replaces the file" || fail "$bad: the file was not replaced: $(head -c 80 "$ST")"
    stop_srv
done
cp "$T/good.state" "$ST"; fix_state

if [ -n "$HOOKBIN" ]; then
    echo "== a restart of the loader warms again what the Backend lost"
    conf 256m "fetch-rate 5000;"
    KSAVE=$KARIDNS; KARIDNS=$HOOKBIN
    start_srv
    KARIDNS=$KSAVE
    waitfor 20 sh -c "[ \"\$(./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep '^warm:' | sed -n 's/.* loaded=\([0-9]*\).*/\1/p')\" = $NZ ]" && pass "the zones are warmed at the start" || fail "warm line: $(dbs | grep '^warm:')"
    for n in 1 2 3; do $KCTL evict "$(zn $n).test." 2>&1 | grep -q '^OK' || fail "evict $(zn $n)"; done
    sleep 1
    R=$(resident_zones)
    echo "  after evicting 1, 2, 3: in memory: $R"
    echo "$R" | grep -q '^4 ' && ! echo "$R" | grep -q '\b[123]\b' && pass "three zones are out of memory" || fail "in memory: $R"
    LP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1)
    if [ -n "$LP" ]; then
        kill -9 "$LP"
        waitfor 20 sh -c "P=\$(pgrep -P $SRV -f 'karidns-dbloader -s 3' | head -1); [ -n \"\$P\" ] && [ \"\$P\" != \"$LP\" ]" && pass "the supervisor started a new loader" || fail "no new loader"
        waitfor 20 sh -c "[ \"\$(./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep '^warm:' | sed -n 's/.* loaded=\([0-9]*\).*/\1/p')\" -ge $((NZ + 3)) ]" && pass "the warm-up read the three zones again" || fail "warm line: $(dbs | grep '^warm:')"
        R=$(resident_zones)
        [ "$R" = "$(n=1; while [ $n -le $NZ ]; do printf '%s ' $n; n=$((n + 1)); done)" ] && pass "all $NZ zones are in memory again, without a query" || fail "in memory: $R"
    else
        fail "no loader process"
    fi
    stop_srv

    echo "== the warm-up after a restart of the loader stops at the high water mark as the first one did (the estimate of the size of a zone is per session)"
    cp "$T/good.state" "$ST"; fix_state
    conf 1m "fetch-rate 5000;"
    KSAVE=$KARIDNS; KARIDNS=$HOOKBIN
    start_srv
    KARIDNS=$KSAVE
    warm_over() { dbs | grep '^warm:' | grep -q 'received=1 .* pending=0 in_flight=0'; }
    waitfor 30 warm_over && pass "the first warm-up is over" || fail "warm line: $(dbs | grep '^warm:')"
    sleep 1
    R1=$(resident_zones); K1=$(echo $R1 | wc -w | tr -d ' ')
    L0=$(field warm loaded)
    echo "  first warm-up: $K1 zones in memory ($R1)"
    for n in $R1; do $KCTL evict "$(zn $n).test." > /dev/null 2>&1; done
    sleep 3
    EV0=$(field cache evictions)
    LP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1)
    if [ -n "$LP" ]; then
        kill -9 "$LP"
        waitfor 30 sh -c "[ \"\$(./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep '^warm:' | sed -n 's/.* loaded=\([0-9]*\).*/\1/p')\" -gt $L0 ]" && pass "the second warm-up has started" || fail "warm line: $(dbs | grep '^warm:')"
        waitfor 30 warm_over && pass "the second warm-up is over" || fail "warm line: $(dbs | grep '^warm:')"
        sleep 1
        R2=$(resident_zones); K2=$(echo $R2 | wc -w | tr -d ' ')
        EV1=$(field cache evictions)
        echo "  second warm-up: $K2 zones in memory ($R2)"
        [ "$K2" -ge 2 ] && [ "$K2" -lt "$NZ" ] && [ "$K2" -le $((K1 + 1)) ] && pass "it read about as many zones as the first one ($K2, then $K1) and not all of them" || fail "$K2 zones in memory after the second warm-up, $K1 after the first"
        [ "$EV0" = "$EV1" ] && pass "no zone was taken out of memory by the second warm-up (evictions $EV0 -> $EV1)" || fail "evictions $EV0 -> $EV1: the second warm-up went over the high water mark"
    else
        fail "no loader process"
    fi
    stop_srv
else
    echo "  [SKIP] the restart of the loader needs karidns-evict (the test hook)"
fi

echo "== warm-before-serve: the queries wait for the hot list (fetch-rate 1: about ten seconds)"
cp "$T/good.state" "$ST"; fix_state
conf 256m "fetch-rate 1; warm-before-serve 60;"
start_bg
waitfor 30 sh -c "./karictl -c $T/karictl.conf dbstatus >/dev/null 2>&1" && pass "karictl works while the queries are held" || fail "karictl does not answer"
T0=$(now_s)
( a=$(./dag @127.0.0.1 -p "$PORT" "www.$(zn 1).test" A +short +nohexdump +time=70 +tries=1 2>/dev/null | head -1); echo "$(now_s) $a" > "$T/ans1" ) &
QP=$!
sleep 2
dbs | grep -q '^warm-before-serve: holding the queries' && pass "after 2 s dbstatus says the queries are held" || fail "dbstatus: $(dbs | grep '^warm-before-serve')"
[ ! -s "$T/ans1" ] && pass "and the query has no answer yet" || fail "the query was answered while the warm-up runs: $(cat "$T/ans1")"
wait "$QP"
T1=$(awk '{print $1}' "$T/ans1"); A1=$(awk '{print $2}' "$T/ans1")
EL=$(perl -e "printf '%d', $T1 - $T0")
echo "  the answer came after $EL s: $A1"
[ "$A1" = "192.0.2.80" ] && [ "$EL" -ge 5 ] && [ "$EL" -le 55 ] && pass "the query waited for the warm-up and was answered ($EL s)" || fail "answer '$A1' after $EL s"
dbs | grep -q '^warm-before-serve: queries accepted after [0-9]* ms' && pass "dbstatus: queries accepted after the warm-up" || fail "dbstatus: $(dbs | grep '^warm-before-serve')"
grep -q 'warm-before-serve: the hot list is read' "$T/srv.log" && pass "the log says the hot list was read" || fail "no 'hot list is read' line in the log"
L=$(field warm loaded); [ "${L:-0}" = "$NZ" ] && pass "all $NZ zones were loaded when the queries were let in" || fail "loaded=$L"
stop_srv

echo "== warm-before-serve: the time is up before the hot list is read"
conf 256m "fetch-rate 1; warm-before-serve 3;"
start_bg
waitfor 30 sh -c "./karictl -c $T/karictl.conf dbstatus >/dev/null 2>&1" || fail "karictl does not answer"
T0=$(now_s)
a=$(./dag @127.0.0.1 -p "$PORT" "www.$(zn 1).test" A +short +nohexdump +time=30 +tries=1 2>/dev/null | head -1)
T1=$(now_s)
EL=$(perl -e "printf '%.1f', $T1 - $T0")
echo "  the answer came after $EL s: $a"
[ "$a" = "192.0.2.80" ] && perl -e "exit(($EL >= 1.5 && $EL <= 12) ? 0 : 1)" && pass "the query was answered when the 3 s were up ($EL s)" || fail "answer '$a' after $EL s"
grep -q 'warm-before-serve: the time is up' "$T/srv.log" && pass "the log says the time was up" || fail "no 'time is up' line in the log"
dbs | grep -q '^warm-before-serve: queries accepted after [0-9]* ms' && pass "dbstatus shows when the queries were let in" || fail "dbstatus: $(dbs | grep '^warm-before-serve')"
stop_srv

echo "== karicheck db checks the state file"
if [ -x ./karicheck ]; then
    cp "$T/good.state" "$ST"; fix_state
    conf 256m "fetch-rate 5000;"
    out=$(./karicheck db "$T/k.conf" 2>&1); st=$?
    echo "$out" | grep -q "state file .*: $NZ zone(s) of the hot list" && ! echo "$out" | grep -q "ERROR" && pass "a good state file passes (karicheck db: $NZ zones of the hot list)" || fail "karicheck db (exit $st): $(echo "$out" | head -12)"
    printf 'junk\n' > "$ST"; fix_state
    out=$(./karicheck db "$T/k.conf" 2>&1); st=$?
    echo "$out" | grep -q "state file .* is not valid and will be ignored" && pass "a corrupt state file is a warning" || fail "karicheck db (exit $st): $(echo "$out" | head -12)"
    rm -f "$ST"
    sed "s|loader-state-file \"$ST\"|loader-state-file \"$T/nodir/hot.state\"|" "$T/k.conf" > "$T/k2.conf"
    out=$(./karicheck db "$T/k2.conf" 2>&1); st=$?
    echo "$out" | grep -q "state file .*nodir.*No such file" && [ "$st" -ne 0 ] && pass "a state file in a directory that does not exist is an error" || fail "karicheck db (exit $st): $(echo "$out" | head -12)"
    chmod 555 "$T/st"
    out=$(./karicheck db "$T/k.conf" 2>&1); st=$?
    echo "$out" | grep -q "cannot write in the directory" && [ "$st" -ne 0 ] && pass "a directory the loader cannot write in is an error" || fail "karicheck db (exit $st): $(echo "$out" | head -12)"
    chmod 700 "$T/st"
    sed 's/memory-limit 256m;//' "$T/k.conf" > "$T/k3.conf"
    out=$(./karicheck conf "$T/k3.conf" 2>&1)
    echo "$out" | grep -q "loader-state-file has no effect without memory-limit" && pass "karicheck conf warns: the state file needs memory-limit" || fail "karicheck conf: $(echo "$out" | head -5)"
else
    echo "  [SKIP] ./karicheck is not built"
fi

grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

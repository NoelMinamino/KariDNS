#!/bin/sh
# run_db_pg_fetch_test.sh - the D1a parts of the Backend that read zones on demand, with the PostgreSQL driver: the hot list and the warm-up, warm-before-serve, and
# the loader's pool of fetch workers (database { memory-limit }).  tests/run_db_warm_test.sh and tests/run_db_fetchconc_test.sh do the same with SQLite3; the
# state file and the stream are the same code for both drivers, so this test is the short version, and what is PostgreSQL's own is the fetch of one zone (a REPEATABLE
# READ snapshot per fetch) by several workers, each with its own connection.
#
# Part 1, 12 zones of 1000 addresses (z0001 .. z0012), the real karidns and karidns-dbloader:
#   - the hot list is written in the order of the frequencies (z0001 asked for 12 times, ..., z0012 once), with a header and an END line, mode 0600
#   - after a restart the zones are in memory before the first query (no miss)
#   - with memory-limit 1m the warm-up stops at the high water mark and the zones in memory are the hottest ones, in the order of the list
#   - warm-before-serve: a UDP and a TCP query wait until the hot list is read (fetch-rate 1: about ten seconds) and are answered; the time may be up first
# Part 2, 300 zones of 100 addresses (c0000 .. c0299), a burst of one query for every zone while the zones are out of memory:
#   - fetch-concurrency 2 sheds, loader-threads 4 without the setting allows 64 and sheds nothing, and every answer is the right one (the zones of the workers
#     do not mix on the fetch stream)
#   - a short stress with memory-limit 1m (the cache manager takes zones out while the bursts ask for them again) and reloads in between: no query gets the
#     address of another zone, and the server goes on answering
#
# Needs root (the server starts as root and drops to nobody; the loader runs as the unprivileged PostgreSQL user).  SKIP otherwise, and when PostgreSQL is not
# reachable (tests/db/pg_lib.sh: KARIDNS_TEST_PG, KARIDNS_TEST_PG_USER), the loader has no PostgreSQL driver, or a binary is missing.
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
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver (make karidns-dbloader DB_DRIVERS=\"sqlite3 postgresql\")"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=12            # part 1: zones z0001 .. z0012, 1000 A records each
NC=300           # part 2: zones c0000 .. c0299, 100 A records each
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pgfetch.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 200 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    stop_srv
    pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
pg_setup pgfetch || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
ST="$T/st/hot.state"

mkdir "$T/st"
chown "$PG_AS" "$T/st"; chmod 700 "$T/st"
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
pg_conninfo_file "$T/ci"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
LOG="$T/srv.log"

# zones of the given prefix: SOA, NS, ns1, www (192.0.2.80 for the z zones, 192.0.2.(n % 200 + 1) for the c zones) and M more addresses h<j>.<zone>
mkzones() {   # mkzones PREFIX FIRST LAST M
    pq "INSERT INTO domains (name, type) SELECT '$1' || lpad(i::text, 4, '0') || '.test', 'NATIVE' FROM generate_series($2, $3) i;
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
          SELECT d.id, d.name, 'SOA', 'ns1.' || d.name || '. host.' || d.name || '. 1 3600 600 86400 300', 300, 0, false FROM domains d WHERE d.name LIKE '$1%';
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, d.name, 'NS', 'ns1.' || d.name || '.', 300, 0, false FROM domains d WHERE d.name LIKE '$1%';
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, 'ns1.' || d.name, 'A', '192.0.2.1', 300, 0, false FROM domains d WHERE d.name LIKE '$1%';
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
          SELECT d.id, 'www.' || d.name, 'A', CASE WHEN '$1' = 'z' THEN '192.0.2.80' ELSE '192.0.2.' || (substring(d.name from 2 for 4)::int % 200 + 1) END, 300, 0, false
          FROM domains d WHERE d.name LIKE '$1%';
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
          SELECT d.id, 'h' || m.j || '.' || d.name, 'A', '10.0.' || (m.j % 250 + 1) || '.1', 300, 0, false FROM domains d, generate_series(0, $4 - 1) m(j) WHERE d.name LIKE '$1%';
        ANALYZE domains; ANALYZE records" > /dev/null
}
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { fail "cannot create the schema"; exit 1; }
mkzones z 1 $NZ 1000 || { fail "cannot fill the database (z zones)"; exit 1; }

conf() {   # conf LIMIT EXTRA-OPTIONS [STATE]   (STATE = no: no loader-state-file)
    st="loader-state-file \"$ST\"; hot-list-interval 1;"
    [ "${3:-}" = "no" ] && st=""
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               memory-limit $1; $st park-timeout 4000; $2 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_bg() {
    : > "$LOG"
    "$KARIDNS" -c "$T/k.conf" -f > "$LOG" 2>&1 &
    SRV=$!
}
wait_load() {
    i=0
    while [ $i -lt 900 ] && ! grep -q "\[DB\] initial load complete" "$LOG" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$LOG" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$LOG"; }
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
        $KCTL dbstatus "$(zn $n).test" 2>/dev/null | grep -q "(the data is out of memory" || printf '%s ' "$n"
        n=$((n + 1))
    done
}
state_zones() { awk -F'\t' 'NF == 2 { sub(/\.test\.$/, "", $2); print $2 }' "$ST" 2>/dev/null | tr '\n' ' '; }
want_order() { n=1; while [ $n -le $NZ ]; do printf '%s ' "$(zn $n)"; n=$((n + 1)); done; }
state_ok() { [ "$(state_zones)" = "$(want_order)" ]; }
now_s() { perl -MTime::HiRes=time -e 'printf "%.2f\n", time'; }
fix_state() { chown "$PG_AS" "$ST" 2>/dev/null; chmod 600 "$ST" 2>/dev/null; }
loaded_is() { [ "$(dbs | grep '^warm:' | sed -n 's/.* loaded=\([0-9]*\).*/\1/p')" = "$1" ]; }

echo "== part 1: the hot list is written in the order of the frequencies"
conf 256m "fetch-rate 5000;"
start_srv
waitfor 15 sh -c "./karictl -c $T/karictl.conf dbstatus 2>/dev/null | grep -q '^warm: received=1 '" && pass "the loader's (empty) WARM_LIST has arrived" || fail "warm line: $(dbs | grep '^warm:')"
dbs | grep -q '^state-file: .* at_start=missing' && pass "dbstatus: the state file did not exist at the start" || fail "dbstatus state-file line: $(dbs | grep '^state-file')"
n=1
while [ $n -le $NZ ]; do                   # z0001 is asked for 12 times, z0002 11 times, ... z0012 once
    k=$((NZ + 1 - n))
    while [ $k -gt 0 ]; do q "www.$(zn $n).test" > /dev/null; k=$((k - 1)); done
    n=$((n + 1))
done
waitfor 20 state_ok && pass "the state file lists the $NZ zones, the most asked for first" || fail "state file order: '$(state_zones)' (want '$(want_order)')"
head -1 "$ST" | grep -q '^KARIDNS-HOT-LIST 1$' && tail -1 "$ST" | grep -q "^END $NZ [0-9a-f]\{8\}$" && pass "the file has its header and an END line with the count" || fail "bad header or END line: $(head -1 "$ST") / $(tail -1 "$ST")"
[ "$(stat -f %Lp "$ST" 2>/dev/null || stat -c %a "$ST")" = "600" ] && pass "the file is private (0600)" || fail "mode of the state file is not 0600"
cp "$ST" "$T/good.state"
stop_srv

echo "== part 1: after a restart the zones are in memory before the first query"
cp "$T/good.state" "$ST"; fix_state
conf 256m "fetch-rate 5000;"
start_srv
waitfor 20 loaded_is $NZ && pass "the warm-up read all $NZ zones of the list" || fail "warm line: $(dbs | grep '^warm:')"
dbs | grep -q "^state-file: .* at_start=loaded ($NZ zones)" && pass "dbstatus: the state file was loaded at the start ($NZ zones)" || fail "state-file line: $(dbs | grep '^state-file')"
M0=$(field cache misses)
[ "$(q www.$(zn 1).test)" = "192.0.2.80" ] && [ "$(q www.$(zn $NZ).test)" = "192.0.2.80" ] && pass "the first queries are answered" || fail "no answer"
M1=$(field cache misses)
[ "${M0:-0}" = "${M1:-1}" ] && pass "... without a miss: the zones were in memory already (misses $M0 -> $M1)" || fail "the first queries parked (misses $M0 -> $M1)"
stop_srv

echo "== part 1: a small memory-limit: the warm-up stops at the high water mark, the hottest zones are in memory"
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
grep -q 'reached the high water mark of memory-limit' "$LOG" && pass "the log says the warm-up stopped at the high water mark" || fail "no high water line in the log"
LIM=$(field cache limit); RSD=$(field cache resident)
[ "$RSD" -le $((LIM + LIM / 10)) ] && pass "the zones in memory ($RSD bytes) are within memory-limit ($LIM)" || fail "resident $RSD above the limit $LIM"
n=$((K + 1)); ok=1
while [ $n -le $NZ ]; do [ "$(q "www.$(zn $n).test")" = "192.0.2.80" ] || ok=0; n=$((n + 1)); done
[ "$ok" = 1 ] && pass "the zones that are out of memory are fetched from PostgreSQL on a query and answered" || fail "a zone that was out of memory got no answer"
stop_srv

echo "== part 1: warm-before-serve: the queries (UDP and TCP) wait for the hot list (fetch-rate 1: about ten seconds)"
cp "$T/good.state" "$ST"; fix_state
conf 256m "fetch-rate 1; warm-before-serve 60;"
start_bg
waitfor 30 sh -c "./karictl -c $T/karictl.conf dbstatus >/dev/null 2>&1" || fail "karictl does not answer"
T0=$(now_s)
( a=$(./dag @127.0.0.1 -p "$PORT" "www.$(zn 1).test" A +short +nohexdump +time=70 +tries=1 2>/dev/null | head -1); echo "$(now_s) $a" > "$T/ans1" ) &
QP=$!
( a=$(./dag @127.0.0.1 -p "$PORT" "www.$(zn 2).test" A +tcp +short +nohexdump +time=70 +tries=1 2>/dev/null | head -1); echo "$(now_s) $a" > "$T/ans2" ) &
QPT=$!
sleep 2
dbs | grep -q '^warm-before-serve: holding the queries' && pass "after 2 s dbstatus says the queries are held" || fail "dbstatus: $(dbs | grep '^warm-before-serve')"
[ ! -s "$T/ans1" ] && [ ! -s "$T/ans2" ] && pass "and the queries have no answer yet" || fail "a query was answered while the warm-up runs: $(cat "$T/ans1" "$T/ans2" 2>/dev/null)"
wait "$QP" "$QPT"
for f in ans1 ans2; do
    a=$(awk '{print $2}' "$T/$f"); EL=$(perl -e "printf '%d', $(awk '{print $1}' "$T/$f") - $T0")
    [ "$a" = "192.0.2.80" ] && [ "$EL" -ge 5 ] && [ "$EL" -le 55 ] && pass "$f: the query waited for the warm-up and was answered ($EL s)" || fail "$f: answer '$a' after $EL s"
done
dbs | grep -q '^warm-before-serve: queries accepted after [0-9]* ms' && pass "dbstatus: queries accepted after the warm-up" || fail "dbstatus: $(dbs | grep '^warm-before-serve')"
grep -q 'warm-before-serve: the hot list is read' "$LOG" && pass "the log says the hot list was read" || fail "no 'hot list is read' line in the log"
L=$(field warm loaded); [ "${L:-0}" = "$NZ" ] && pass "all $NZ zones were loaded when the queries were let in" || fail "loaded=$L"
stop_srv

echo "== part 1: warm-before-serve: the time is up before the hot list is read"
conf 256m "fetch-rate 1; warm-before-serve 3;"
start_bg
waitfor 30 sh -c "./karictl -c $T/karictl.conf dbstatus >/dev/null 2>&1" || fail "karictl does not answer"
T0=$(now_s)
a=$(./dag @127.0.0.1 -p "$PORT" "www.$(zn 1).test" A +short +nohexdump +time=30 +tries=1 2>/dev/null | head -1)
EL=$(perl -e "printf '%.1f', $(now_s) - $T0")
[ "$a" = "192.0.2.80" ] && perl -e "exit(($EL >= 1.5 && $EL <= 12) ? 0 : 1)" && pass "the query was answered when the 3 s were up ($EL s)" || fail "answer '$a' after $EL s"
grep -q 'warm-before-serve: the time is up' "$LOG" && pass "the log says the time was up" || fail "no 'time is up' line in the log"
stop_srv

echo "== part 2: $NC zones; the default with loader-threads 4, and fetch-concurrency 2"
mkzones c 0 $((NC - 1)) 100 || { fail "cannot fill the database (c zones)"; exit 1; }
conc() { $KCTL dbstatus 2>/dev/null | grep '^fetch:' | sed -n 's/.* concurrency=\([0-9]*\).*/\1/p' | tail -1; }
shed() { $KCTL dbstatus 2>/dev/null | sed -n 's/.* shed=\([0-9]*\) .*/\1/p' | tail -1; }
q_one() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=10 +tries=1 2>/dev/null | head -1; }
burst() {   # burst OUTFILE: one query for www.<zone> of every c zone, 60 at a time; "name answer" per line
    perl -e 'for $i (0..'"$((NC - 1))"') { printf "www.c%04d.test\n", $i }' > "$T/names"
    xargs -P 60 -n 1 sh -c 'echo "$0 $(./dag @127.0.0.1 -p '"$PORT"' "$0" A +short +nohexdump +time=6 +tries=1 2>/dev/null | head -1)"' < "$T/names" | sort > "$1"
}
perl -e 'for $i (0..'"$((NC - 1))"') { printf "www.c%04d.test 192.0.2.%d\n", $i, $i % 200 + 1 }' | sort > "$T/expected"

conf 64m "fetch-rate 5000; loader-threads 4; fetch-concurrency 2;" no
start_srv
[ "$(conc)" = "2" ] && pass "fetch-concurrency 2: dbstatus shows concurrency=2" || fail "concurrency: '$(conc)'"
burst "$T/out2"
S2=$(shed)
[ "${S2:-0}" -gt 0 ] && pass "requests were shed ($S2): the limit is the configured one" || fail "nothing shed with fetch-concurrency 2"
stop_srv

conf 64m "fetch-rate 5000; loader-threads 4;" no
start_srv
[ "$(conc)" = "64" ] && pass "loader-threads 4: dbstatus shows concurrency=64" || fail "concurrency: '$(conc)'"
burst "$T/out"
S1=$(shed)
[ "${S1:-0}" = "0" ] && pass "nothing was shed" || fail "shed=$S1"
if cmp -s "$T/out" "$T/expected"; then pass "all $NC answers are the right ones (the zones of the four PostgreSQL connections did not mix)"; else fail "wrong or missing answers: $(diff "$T/expected" "$T/out" | head -5 | tr '\n' ' ')"; fi
grep -q "fetch worker\|protocol error" "$LOG" && fail "the log mentions a worker or a protocol error: $(grep 'fetch worker\|protocol error' "$LOG" | head -2)" || pass "no worker or protocol error in the log"
stop_srv

echo "== part 2: stress: bursts while zones are taken out of memory (memory-limit 1m) and the loader reloads"
conf 1m "fetch-rate 5000; loader-threads 4;" no
start_srv
RND=${FETCHCONC_STRESS_ROUNDS:-3}
r=0; WRONG=0; RIGHT=0; TOTAL=0
while [ $r -lt "$RND" ]; do
    ( $KCTL reload > /dev/null 2>&1; $KCTL reload > /dev/null 2>&1 ) &
    RLP=$!
    perl -e 'for $i (0..'"$((NC - 1))"') { printf "www.c%04d.test\n", ($i * 7 + '"$r"') % '"$NC"' }' > "$T/names"
    xargs -P 12 -n 1 sh -c 'echo "$0 $(./dag @127.0.0.1 -p '"$PORT"' "$0" A +short +nohexdump +time=15 +tries=1 2>/dev/null | head -1)"' < "$T/names" | sort > "$T/outs"
    wait "$RLP"
    # under this load a query may be shed or time out (no address): that is allowed; an address of another zone is not
    join "$T/expected" "$T/outs" > "$T/joined"
    WRONG=$((WRONG + $(awk 'NF == 3 && $3 != $2 { n++ } END { print n + 0 }' "$T/joined")))
    RIGHT=$((RIGHT + $(awk 'NF == 3 && $3 == $2 { n++ } END { print n + 0 }' "$T/joined")))
    TOTAL=$((TOTAL + NC))
    r=$((r + 1))
done
echo "  $RIGHT of $TOTAL queries got their address, $WRONG got another one"
[ "$WRONG" -eq 0 ] && pass "no query got the address of another zone" || fail "$WRONG answers with the data of another zone"
[ "$RIGHT" -ge $((TOTAL / 4)) ] && pass "a good part of the queries was answered ($RIGHT of $TOTAL) although the zones do not fit memory-limit" || fail "only $RIGHT of $TOTAL queries were answered"
EVS=$($KCTL dbstatus 2>/dev/null | grep '^cache:' | head -1 | sed -n 's/.* evictions=\([0-9]*\).*/\1/p')
[ "${EVS:-0}" -gt 0 ] && pass "the cache manager took zones out during the bursts ($EVS evictions)" || fail "no evictions: the stress did not churn the cache"
i=0; while [ $i -lt 100 ] && [ "$(q_one www.c0001.test)" != "192.0.2.2" ]; do sleep 0.1; i=$((i + 1)); done
[ "$(q_one www.c0001.test)" = "192.0.2.2" ] && pass "the server goes on answering" || fail "no answer after the stress"
grep -q "fetch worker\|protocol error" "$LOG" && fail "the log mentions a worker or a protocol error: $(grep 'fetch worker\|protocol error' "$LOG" | head -2)" || pass "no worker or protocol error in the log"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$LOG" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

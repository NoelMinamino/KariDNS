#!/bin/sh
# run_db_fetchconc_test.sh - the fetches in flight (database { fetch-concurrency }) and the loader's pool of fetch workers (D1a), with the real karidns, the real
# karidns-dbloader and SQLite3.
#
#   - dbstatus shows the limit: loader-threads x 16 (at least 16) when fetch-concurrency is not set, the value when it is
#   - fetch-concurrency 2 sheds a burst of queries for zones that are out of memory (the limit is the one in the configuration, not a constant)
#   - the default with loader-threads 4: the same burst sheds nothing, and every answer is the right one (the zones of the workers do not mix on the fetch stream)
#   - dbstatus "fetchq:" (0.7 B2 W3): all fields, peak under fetch-concurrency 2, the histogram, and a UDP burst with park-max 2 (park_full)
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

NZ=400
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_fetchconc.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
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

mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" <<SQL
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ - 1)))
INSERT INTO domains (name, type) SELECT printf('c%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'www.' || name, 'A', printf('192.0.2.%d', (CAST(substr(name, 2, 4) AS INTEGER) % 200) + 1), 300, 0, 0 FROM domains;
-- ... and 100 more addresses in each zone, so that the zones together are well over 1 MB (the stress at the end runs with memory-limit 1M)
WITH RECURSIVE m(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM m WHERE j < 99)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || m.j || '.' || d.name, 'A', '10.0.' || (m.j % 250 + 1) || '.1', 300, 0, 0 FROM domains d, m;
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf "EXTRA database statements" [MEMORY-LIMIT]
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate 5000; park-timeout 4000;
               acl-ceiling { 127.0.0.1; }; memory-limit ${2:-64m}; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete ($((i / 10)) s)" || { fail "no 'initial load complete' after $((i / 10)) s"; tail -20 "$T/srv.log"; }
    sleep 1
}
conc() { $KCTL dbstatus 2>/dev/null | grep '^fetch:' | sed -n 's/.* concurrency=\([0-9]*\).*/\1/p' | tail -1; }
q_one() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=10 +tries=1 2>/dev/null | head -1; }
shed() { $KCTL dbstatus 2>/dev/null | sed -n 's/.* shed=\([0-9]*\) .*/\1/p' | tail -1; }
fq() { $KCTL dbstatus 2>/dev/null | grep '^fetchq:' | tr ' ' '\n' | sed -n "s/^$1=\([0-9]*\).*/\1/p" | head -1; }   # a number of the fetchq: line
fq_hist() { $KCTL dbstatus 2>/dev/null | grep '^fetchq:' | tr ' ' '\n' | sed -n 's/^hist=//p' | tr ',' ' ' | awk '{ print $1 + $2 + $3 + $4 + $5 }'; }   # fetches installed, all buckets
udp_burst() {   # udp_burst N: one query for www.<zone> of N zones, all sent at once over one UDP socket (no pause: more fetches are wanted than the table holds)
    perl -MIO::Socket::INET -e 'my ($port, $n) = @ARGV; my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port", Proto => "udp") or die;
        for my $i (0 .. $n - 1) { $s->send(pack("nnnnnn", $i + 1, 0x0100, 1, 0, 0, 0) . join("", map { chr(length $_) . $_ } ("www", sprintf("c%04d", $i), "test")) . chr(0) . pack("nn", 1, 1)); }
        select(undef, undef, undef, 0.2)' "$PORT" "$1"
}
settle() {   # wait until no fetch is in flight (at most 15 s)
    i=0; while [ $i -lt 150 ] && [ "$(fq in_flight)" != "0" ]; do sleep 0.1; i=$((i + 1)); done
}
burst() {   # burst OUTFILE: one query for www.<zone> of every zone, 60 at a time; "name answer" per line
    perl -e 'for $i (0..'"$((NZ - 1))"') { printf "www.c%04d.test\n", $i }' > "$T/names"
    xargs -P 60 -n 1 sh -c 'echo "$0 $(./dag @127.0.0.1 -p '"$PORT"' "$0" A +short +nohexdump +time=6 +tries=1 2>/dev/null | head -1)"' < "$T/names" | sort > "$1"
}
perl -e 'for $i (0..'"$((NZ - 1))"') { printf "www.c%04d.test 192.0.2.%d\n", $i, $i % 200 + 1 }' | sort > "$T/expected"

echo "== the default: loader-threads x 16"
conf "loader-threads 3;"
start_srv
[ "$(conc)" = "48" ] && pass "loader-threads 3: dbstatus shows concurrency=48" || fail "concurrency: '$(conc)'"
stop_srv
conf ""
start_srv
[ "$(conc)" = "16" ] && pass "loader-threads 1: dbstatus shows concurrency=16 (the least)" || fail "concurrency: '$(conc)'"
stop_srv

echo "== fetch-concurrency 2: a burst of $NZ queries for zones out of memory is shed"
conf "loader-threads 4; fetch-concurrency 2;"
start_srv
[ "$(conc)" = "2" ] && pass "dbstatus shows concurrency=2" || fail "concurrency: '$(conc)'"
burst "$T/out2"
S2=$(shed)
[ "${S2:-0}" -gt 0 ] && pass "requests were shed ($S2): the limit is the configured one" || fail "nothing shed with fetch-concurrency 2"
settle
FQ=$($KCTL dbstatus 2>/dev/null | grep '^fetchq:')
case "$FQ" in
    "fetchq: in_flight="*" peak="*" table_full="*" ring_dropped="*" park_full="*" park_timeout="*" loader_busy="*" ingest_busy="*"% hist="*,*,*,*,*) pass "dbstatus has the fetchq: line with all its fields" ;;
    *) fail "no complete fetchq: line: '$FQ'" ;;
esac
[ "$(fq peak)" = "2" ] && pass "fetchq: peak=2 (never more than fetch-concurrency in flight)" || fail "fetchq: peak='$(fq peak)' with fetch-concurrency 2"
[ "$(fq in_flight)" = "0" ] && pass "fetchq: in_flight=0 after the burst" || fail "fetchq: in_flight='$(fq in_flight)'"
[ "$(fq_hist)" -gt 0 ] 2>/dev/null && pass "fetchq: the fetches that were installed are in hist ($(fq_hist))" || fail "fetchq: hist is empty"
stop_srv

echo "== the default with loader-threads 4: nothing is shed, the answers are the right ones"
conf "loader-threads 4;"
start_srv
[ "$(conc)" = "64" ] && pass "dbstatus shows concurrency=64" || fail "concurrency: '$(conc)'"
burst "$T/out"
S1=$(shed)
[ "${S1:-0}" = "0" ] && pass "nothing was shed" || fail "shed=$S1"
settle
[ "$(fq_hist)" -ge "$NZ" ] 2>/dev/null && pass "fetchq: hist counts the $NZ fetches ($(fq_hist)), peak=$(fq peak)" || fail "fetchq: hist=$(fq_hist) after $NZ fetches"
[ "$(fq peak)" -ge 1 ] 2>/dev/null && [ "$(fq in_flight)" = "0" ] && pass "fetchq: peak>=1 and in_flight=0 at rest" || fail "fetchq: peak='$(fq peak)' in_flight='$(fq in_flight)'"
[ "$(fq loader_busy)" = "0" ] && [ "$(fq park_full)" = "0" ] && pass "fetchq: no busy reply, no full park table in a normal burst" || fail "fetchq: loader_busy='$(fq loader_busy)' park_full='$(fq park_full)'"
if cmp -s "$T/out" "$T/expected"; then pass "all $NZ answers are the right ones (the zones of the loader's workers did not mix)"; else fail "wrong or missing answers: $(diff "$T/expected" "$T/out" | head -5 | tr '\n' ' ')"; fi
grep -q "fetch worker\|protocol error" "$T/srv.log" && fail "the log mentions a worker or a protocol error: $(grep 'fetch worker\|protocol error' "$T/srv.log" | head -2)" || pass "no worker or protocol error in the log"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

# An overload that the fetch path shows: one burst of UDP packets (more queries than the loader reads while it works through them), loader-threads 1, and a table of
# two parked queries per worker (park-max 2): the queries that find it full are answered "not ready" at once (park_full), fetch-concurrency (16) sheds the requests over it.
# table_full and loader_busy cannot be forced from here: with memory-limit, fetch-concurrency (at most the 256 places of the table) stops the requests first, and the
# loader's queue of 256 is never beaten by the Backend's 256 in flight.  Their fields are checked for presence (above) and by test_db_fetch.
echo "== an overload: a burst of $NZ queries over one socket with park-max 2 fills the table of parked queries"
conf "loader-threads 1; park-max 2;"
start_srv
udp_burst "$NZ"
settle
echo "  (park_full=$(fq park_full) park_timeout=$(fq park_timeout) ring_dropped=$(fq ring_dropped) table_full=$(fq table_full) loader_busy=$(fq loader_busy) peak=$(fq peak) hist=$(fq_hist) shed=$(shed))"
[ "$(fq park_full)" -gt 0 ] 2>/dev/null && pass "fetchq: park_full=$(fq park_full): queries found the table of parked queries full" || fail "fetchq: park_full='$(fq park_full)' after the burst"
[ "$(fq peak)" -ge 1 ] 2>/dev/null && [ "$(fq_hist)" -gt 0 ] 2>/dev/null && pass "fetchq: peak=$(fq peak), the fetches that went through are in hist ($(fq_hist))" || fail "fetchq: peak='$(fq peak)' hist='$(fq_hist)'"
[ "$(fq in_flight)" = "0" ] && pass "fetchq: in_flight=0 once the burst is over" || fail "fetchq: in_flight='$(fq in_flight)'"
i=0; while [ $i -lt 100 ] && [ "$(q_one www.c0001.test)" != "192.0.2.2" ]; do sleep 0.1; i=$((i + 1)); done
[ "$(q_one www.c0001.test)" = "192.0.2.2" ] && pass "the server answers after the overload" || fail "no answer after the overload"
stop_srv

# A stress of the loader's pool of fetch workers: the zones do not fit memory-limit, so the cache manager takes zones out while the bursts ask for them again (each
# one a new fetch for a worker), and reloads of the main loop run next to the workers.  Short (FETCHCONC_STRESS_ROUNDS, default 3); tests/run_rcu_tsan_test.sh runs
# the test with the TSan builds of the server and of the loader.
echo "== stress: bursts over the pool of fetch workers while zones are taken out of memory and the loader reloads"
conf "loader-threads 4;" 1m
start_srv
RND=${FETCHCONC_STRESS_ROUNDS:-3}
r=0; WRONG=0; RIGHT=0; TOTAL=0
while [ $r -lt "$RND" ]; do
    ( $KCTL reload > /dev/null 2>&1; $KCTL reload > /dev/null 2>&1 ) &
    RLP=$!
    perl -e 'for $i (0..'"$((NZ - 1))"') { printf "www.c%04d.test\n", ($i * 7 + '"$r"') % '"$NZ"' }' > "$T/names"
    xargs -P 12 -n 1 sh -c 'echo "$0 $(./dag @127.0.0.1 -p '"$PORT"' "$0" A +short +nohexdump +time=15 +tries=1 2>/dev/null | head -1)"' < "$T/names" | sort > "$T/outs"
    wait "$RLP"
    # under this load a query may be shed or time out (SERVFAIL, no address): that is allowed; an address of another zone is not
    join "$T/expected" "$T/outs" > "$T/joined"
    WRONG=$((WRONG + $(awk 'NF == 3 && $3 != $2 { n++ } END { print n + 0 }' "$T/joined")))
    RIGHT=$((RIGHT + $(awk 'NF == 3 && $3 == $2 { n++ } END { print n + 0 }' "$T/joined")))
    TOTAL=$((TOTAL + NZ))
    r=$((r + 1))
done
echo "  $RIGHT of $TOTAL queries got their address, $WRONG got another one"
[ "$WRONG" -eq 0 ] && pass "no query got the address of another zone (zones in flight on four workers, taken out and read again)" || fail "$WRONG answers with the data of another zone"
[ "$RIGHT" -ge $((TOTAL / 4)) ] && pass "a good part of the queries was answered ($RIGHT of $TOTAL) although the zones do not fit memory-limit" || fail "only $RIGHT of $TOTAL queries were answered"
EVS=$($KCTL dbstatus 2>/dev/null | grep '^cache:' | head -1 | sed -n 's/.* evictions=\([0-9]*\).*/\1/p')
[ "${EVS:-0}" -gt 0 ] && pass "the cache manager took zones out during the bursts ($EVS evictions): the workers had zones to read again" || fail "no evictions: the stress did not churn the cache"
i=0; while [ $i -lt 100 ] && [ "$(q_one www.c0001.test)" != "192.0.2.2" ]; do sleep 0.1; i=$((i + 1)); done
[ "$(q_one www.c0001.test)" = "192.0.2.2" ] && pass "the server goes on answering" || fail "no answer after the stress"
grep -q "fetch worker\|protocol error" "$T/srv.log" && fail "the log mentions a worker or a protocol error: $(grep 'fetch worker\|protocol error' "$T/srv.log" | head -2)" || pass "no worker or protocol error in the log"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

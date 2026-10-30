#!/bin/sh
# run_db_cache_test.sh - memory-limit of database { } with many more zones than fit (D1a step 5: cache manager, admission, pins).
#
# Real karidns, the real loader, SQLite3.  800 zones of 152 records each are about 12 MB in memory; memory-limit is 3 MB.  Four clients (tests/db/
# cache_stress.pl) ask for hosts of the zones with a Zipf distribution (s = 1) while a sampler reads `karictl dbstatus` every 0.2 s, from the start of
# the server on.  Checked:
#   - the limit holds: the largest (resident + retired) the sampler saw is within the limit and the documented slack (docs/karidns.md: the zones
#     that were loaded in the last CACHE_MIN_RESIDENT_MS = 100 ms, at most 16 fetches in flight, and the entries of evicted zones until the snapshot that
#     could show them is drained), at the start of the server (the zones that do not fit come cold) and under load
#   - every answer is right (a zone out of memory is fetched, the answer comes from the fetched copy), and almost every query is answered: the
#     rest got SERVFAIL + EDE 14 (the zone could not be had in time) and is counted
#   - the cache works: the miss rate of the Zipf load is far below what a cache that keeps nothing would have (every query for a zone that is out
#     of memory is a miss), zones were taken out (evictions) and some came cold at the start
#   - a pinned zone (metadata X-KARIDNS-CACHE pin) stays in memory
#   - a sweep over every zone, one query each, is answered correctly (the zones are loaded one after the other)
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

NZ=800; NH=150; LIMIT_MB=3; NCLIENT=4; NQ=${CACHE_TEST_QUERIES:-2500}
LIMIT=$((LIMIT_MB * 1024 * 1024))
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_cache.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    rm -f "$T/sampling"
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    rm -rf "$T"
}
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
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
WITH RECURSIVE k(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM k WHERE j < $((NH - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.%d.%d.%d', (CAST(substr(d.name, 2, 4) AS INTEGER) % 200) + 1, k.j / 200, k.j % 200 + 1), 300, 0, 0
  FROM domains d, k;
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-CACHE', 'pin' FROM domains WHERE name = 'z0600.test';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; memory-limit ${LIMIT_MB}m; fetch-rate 5000; park-timeout 4000; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF

: > "$T/samples"
touch "$T/sampling"
( while [ -f "$T/sampling" ]; do $KCTL dbstatus 2>/dev/null | grep '^cache:' >> "$T/samples"; sleep 0.2; done ) &
SAMPLER=$!
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!

i=0
while [ $i -lt 300 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
sleep 1.5
$KCTL dbstatus 2>/dev/null | grep '^cache:' > "$T/after_start"
read_stat() { sed -n "s/.* $1=\([0-9]*\).*/\1/p" "$2" | tail -1; }
RES0=$(read_stat resident "$T/after_start"); RET0=$(read_stat retired "$T/after_start"); COLD0=$(read_stat cold "$T/after_start")
[ -n "$RES0" ] && [ $((RES0 + RET0)) -le $LIMIT ] && pass "after the start the database zones hold $((RES0 + RET0)) bytes (limit $LIMIT)" || fail "after the start: resident ${RES0:-?} retired ${RET0:-?}, limit $LIMIT"
[ "${COLD0:-0}" -gt 0 ] && pass "$COLD0 of $NZ zones came cold at the start (the limit was reached)" || fail "no zone came cold at the start"

echo "== Zipf load: $NCLIENT clients, $NQ queries each"
pids=""
c=1
while [ $c -le $NCLIENT ]; do
    CACHE_STRESS_DELAY_MS=${CACHE_TEST_DELAY_MS:-3} perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ $NH $NQ $c > "$T/client$c.out" 2> "$T/client$c.err" &
    pids="$pids $!"
    c=$((c + 1))
done
for p in $pids; do wait "$p"; done
OK=0; WRONG=0; NR=0; TO=0
for c in $(seq 1 $NCLIENT); do
    line=$(cat "$T/client$c.out")
    OK=$((OK + $(echo "$line" | sed -n 's/.*ok=\([0-9]*\).*/\1/p')))
    WRONG=$((WRONG + $(echo "$line" | sed -n 's/.*wrong=\([0-9]*\).*/\1/p')))
    NR=$((NR + $(echo "$line" | sed -n 's/.*notready=\([0-9]*\).*/\1/p')))
    TO=$((TO + $(echo "$line" | sed -n 's/.*timeout=\([0-9]*\).*/\1/p')))
done
TOTAL=$((NCLIENT * NQ))
echo "  ok $OK, wrong $WRONG, not ready $NR, timeout $TO of $TOTAL"
[ "$WRONG" -eq 0 ] && [ "$((OK + NR + TO))" -eq "$TOTAL" ] && pass "no wrong answer" || { fail "wrong answers: $WRONG"; head -3 "$T"/client*.err; }
[ $((NR + TO)) -le $((TOTAL / 50)) ] && pass "at least 98% of the queries got their answer ($((NR + TO)) did not)" || fail "$((NR + TO)) of $TOTAL queries got no answer"

echo "== a sweep over every zone"
perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ $NH sweep > "$T/sweep.out" 2> "$T/sweep.err"
SW=$(cat "$T/sweep.out")
echo "  $SW"
echo "$SW" | grep -q "wrong=0" && echo "$SW" | grep -q "ok=$NZ " && pass "every zone answers right, loaded when needed" || { fail "the sweep: $SW"; head -3 "$T/sweep.err"; }

echo "== control commands that look at every zone, with zones out of memory"
$KCTL status > /dev/null 2>&1 && pass "karictl status" || fail "karictl status failed"
$KCTL dbstatus z0700.test > "$T/dbs1" 2>&1 && grep -q 'z0700' "$T/dbs1" && pass "karictl dbstatus <zone> of a zone that is (probably) out of memory" || fail "karictl dbstatus z0700.test: $(head -3 "$T/dbs1")"
$KCTL observatory > /dev/null 2>&1; kill -0 "$SRV" 2>/dev/null && pass "the server survives karictl observatory" || fail "the server is gone after karictl observatory"

echo "== a reconfiguration and a restart of the loader with zones out of memory"
out=$($KCTL reconfig 2>&1)
echo "$out" | grep -qi "error" && fail "karictl reconfig: $out" || pass "karictl reconfig with zones out of memory: $(echo "$out" | head -1)"
LP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1)
if [ -n "$LP" ]; then
    kill -9 "$LP"
    i=0; while [ $i -lt 100 ]; do NLP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1); [ -n "$NLP" ] && [ "$NLP" != "$LP" ] && break; sleep 0.1; i=$((i + 1)); done
    sleep 3                                      # the new loader compares its zones with the Backend's inventory: zones out of memory are not sent again
else
    fail "no loader process"
fi
CHECKS_AFTER=$(CACHE_STRESS_DELAY_MS=1 perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ $NH sweep 2> "$T/sweep2.err")
echo "  $CHECKS_AFTER"
echo "$CHECKS_AFTER" | grep -q "wrong=0" && echo "$CHECKS_AFTER" | grep -q "ok=$NZ " && pass "after the reconfiguration and the loader restart every zone still answers right" || { fail "sweep after the restart: $CHECKS_AFTER"; head -3 "$T/sweep2.err"; }

$KCTL dbstatus 2>/dev/null | grep '^cache:' > "$T/final"
rm -f "$T/sampling"
wait "$SAMPLER" 2>/dev/null
MAXUSED=$(sed -n 's/.* resident=\([0-9]*\) retired=\([0-9]*\).*/\1 \2/p' "$T/samples" | awk '{ u = $1 + $2; if (u > m) m = u } END { print m + 0 }')
NS=$(wc -l < "$T/samples" | tr -d ' ')
SLACK=$((LIMIT / 100 * 15 + 256 * 1024))                  # the tolerance the user decided: 15% of the limit + 256 KB (docs/karidns.md, "Memory limit")
echo "  largest resident + retired in $NS samples: $MAXUSED (limit $LIMIT, slack $SLACK)"
PEAK=$(read_stat peak "$T/final")
echo "  the server's own peak (at every zone it installed and every round of the cache manager): ${PEAK:-?}"
[ "$NS" -gt 20 ] && [ "$MAXUSED" -le $((LIMIT + SLACK)) ] && pass "the limit holds: at most $MAXUSED bytes under a limit of $LIMIT (slack $SLACK)" || fail "the largest use was $MAXUSED bytes, limit $LIMIT + slack $SLACK ($NS samples)"
[ -n "$PEAK" ] && [ "$PEAK" -le $((LIMIT + SLACK)) ] && pass "... and the server's own peak, $PEAK bytes, is within it too" || fail "the server's peak was ${PEAK:-?} bytes, limit $LIMIT + slack $SLACK"
EV=$(read_stat evictions "$T/final"); MISS=$(read_stat misses "$T/final"); PINNED=$(read_stat pinned "$T/final"); SHED=$(read_stat shed "$T/final")
echo "  evictions $EV, misses $MISS, shed $SHED, pinned $PINNED bytes"
cat "$T/final"
[ "${EV:-0}" -gt 0 ] && pass "zones were taken out of memory ($EV)" || fail "no zone was taken out"
# a cache that keeps nothing misses on every query for a zone that is out of memory; here the zones are ~4 times what fits, and the load is Zipf
ALLQ=$((TOTAL + 2 * NZ))
[ "${MISS:-$ALLQ}" -lt $((ALLQ / 2)) ] && pass "the miss rate is $((MISS * 100 / ALLQ))% of $ALLQ queries (the zones that are asked for stay in memory)" || fail "misses $MISS of $ALLQ queries"
[ "${PINNED:-0}" -gt 0 ] && pass "the pinned zone is in memory ($PINNED bytes)" || fail "no pinned bytes"
# the pinned zone answers without a wait
ans=$(./dag @127.0.0.1 -p "$PORT" h0.z0600.test A +short +nohexdump +time=2 +tries=1 2>/dev/null | head -1)
[ "$ans" = "10.1.0.1" ] && pass "the pinned zone answers" || fail "the pinned zone answered '$ans'"
if grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null; then fail "sanitizer report in the server log"; fi

echo
[ -n "${CACHE_TEST_DEBUG:-}" ] && { tail -40 "$T/srv.log"; cat "$T/samples"; }
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

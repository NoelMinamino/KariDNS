#!/bin/sh
# run_db_xfer_test.sh - AXFR / IXFR of database zones that are not in memory (D1a step 7, design 7, 12-6), with the real karidns, the real
# karidns-dbloader and SQLite3.
#
#   - the ACL (allow-transfer from the database, acl-ceiling) is checked before anything is read: a refused AXFR makes the server fetch nothing
#     (`fetch: ... issued=` of karictl dbstatus does not change) and the zone stays out of memory
#   - an AXFR of a zone that is out of memory waits for the zone (the transfer thread, not a worker), is complete (the same record set as the transfer
#     of the same zone from memory), and marks the zone evict-next: the cache manager takes it out of memory as soon as the transfer is over
#     (RFC 5936 2.2: the zone is sent whole, closed by the SOA)
#   - an IXFR from an old serial of a zone that is out of memory is answered with the whole zone (RFC 1995 4, there is no history), the same record set as
#     the transfer from memory; an IXFR from the serial the directory has (or a newer one) is the one SOA of RFC 1995 2, made from the summary:
#     the zone is not read (`issued=` does not change, the zone stays out of memory)
#   - after a change in the database (a summary with a new serial) the IXFR from the new serial is still answered from the summary, and the one from
#     the old serial reads the zone and gets the new version
#   - a zone that cannot be read (more records than max-zone-records) is answered SERVFAIL (RFC 5936 2.2; EDE 14) after `transfer-fetch-timeout`
#   - a zone that a query loaded is transferred from memory and stays in memory (it is not marked)
#   - a load of AXFR and IXFR clients (tests/db/xfer_stress.pl) and queries (tests/db/cache_stress.pl) at the same time under a small memory-limit: every
#     transfer that completes is complete, no query is answered wrong, the limit's slack holds, nothing breaks (run with karidns-tsan: run_rcu_tsan_test.sh)
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

NH=60            # hosts of a.test, c.test, d.test
NZ=300           # zones of the load part (z0000 ...)
NSH=150          # hosts of each of them
SECS=${XFER_TEST_SECONDS:-12}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_xfer.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
CPIDS=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    [ -n "$CPIDS" ] && kill $CPIDS 2>/dev/null     # (the clients of the load part, when the run fails in the middle of it)
    [ -n "$CPIDS" ] && wait $CPIDS 2>/dev/null
    stop_srv
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
# a: transferred; b: its allow-transfer does not list the client; c: IXFR; d: a change in the database; bad: more records than max-zone-records;
# z0000 ...: the load part
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE'), ('b.test', 'NATIVE'), ('c.test', 'NATIVE'), ('d.test', 'NATIVE'), ('bad.test', 'NATIVE');
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ - 1)))
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' ' || (CASE WHEN name LIKE 'z%' THEN 7 ELSE 5 END) || ' 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains WHERE name IN ('a.test', 'b.test', 'c.test', 'd.test');
WITH RECURSIVE k(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM k WHERE j < $((NH - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.0.%d.%d', k.j / 200, k.j % 200 + 1), 300, 0, 0 FROM domains d, k WHERE d.name IN ('a.test', 'b.test', 'c.test', 'd.test');
WITH RECURSIVE k(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM k WHERE j < 299)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.1.%d.%d', k.j / 200, k.j % 200 + 1), 300, 0, 0 FROM domains d, k WHERE d.name = 'bad.test';
WITH RECURSIVE k(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM k WHERE j < $((NSH - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.%d.%d.%d', (CAST(substr(d.name, 2, 4) AS INTEGER) % 200) + 1, k.j / 200, k.j % 200 + 1), 300, 0, 0 FROM domains d, k WHERE d.name LIKE 'z%';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE name <> 'b.test';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '192.0.2.1' FROM domains WHERE name = 'b.test';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf MEMORY-LIMIT
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate 5000; park-timeout 4000;
               acl-ceiling { 127.0.0.1; }; max-zone-records 200; transfer-fetch-timeout 3000; memory-limit $1; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 600 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
    sleep 1
}
stat() { $KCTL dbstatus 2>/dev/null | grep '^cache:' | sed -n "s/.* $1=\([0-9]*\).*/\1/p" | tail -1; }
issued() { $KCTL dbstatus 2>/dev/null | grep '^fetch:' | sed -n 's/.* issued=\([0-9]*\).*/\1/p' | tail -1; }
xstat() { $KCTL dbstatus 2>/dev/null | grep '^transfers of zones out of memory:' | sed -n "s/.* $1=\([0-9]*\).*/\1/p" | tail -1; }
oom() { $KCTL dbstatus "$1" 2>/dev/null | grep -q "out of memory"; }       # oom ZONE: its data is out of memory
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=5 +tries=1 2>/dev/null | head -1; }
wait_oom() {   # wait_oom ZONE SECONDS: the zone's data leaves memory (the cache manager)
    i=0; while [ $i -lt $(($2 * 10)) ] && ! oom "$1"; do sleep 0.1; i=$((i + 1)); done
    oom "$1"
}
D() { ./dag @127.0.0.1 -p "$PORT" "$@" 2>/dev/null; }
axfr() { D "$1" AXFR +nohexdump +noall +answer | sort; }                 # axfr ZONE: the records, sorted (the order of a transfer is not the point)
ixfr() { D "$1" "IXFR=$2" +nohexdump +noall +answer | sort; }
serial_of() { D "$1" SOA +short +nohexdump +noedns | awk '{ print $3 }' | head -1; }

echo "== a zone that is out of memory is transferred"
conf 64m
start_srv
oom a.test && oom b.test && oom c.test && pass "the zones start out of memory (a summary each)" || fail "a zone is in memory at the start"
I0=$(issued); W0=$(xstat waited); L0=$(xstat loaded)
echo "  fetches so far: ${I0:-?}"

# the ACL comes first
D b.test AXFR +nohexdump +noall +answer | grep -v '^;' > "$T/b.out"
D nosuch.test AXFR +nohexdump +noall +answer | grep -v '^;' > "$T/nosuch.out"
[ ! -s "$T/b.out" ] && [ ! -s "$T/nosuch.out" ] && pass "an AXFR the client may not make (allow-transfer) and one of a zone that does not exist give no records" || fail "records for a refused AXFR: $(head -2 "$T/b.out" "$T/nosuch.out")"
[ "$(issued)" = "$I0" ] && [ "$(xstat waited)" = "$W0" ] && oom b.test && pass "a refused AXFR costs no fetch (issued $I0, waited $W0) and b.test stays out of memory" || fail "fetches: issued $(issued) (was $I0), waited $(xstat waited) (was $W0)"
D b.test IXFR=1 +nohexdump +noall +answer | grep -v '^;' > "$T/b.out"
[ ! -s "$T/b.out" ] && [ "$(issued)" = "$I0" ] && oom b.test && pass "... and so does a refused IXFR" || fail "a refused IXFR: issued $(issued), $(head -2 "$T/b.out")"

# AXFR of a.test: waits for the zone, complete
axfr a.test > "$T/a.nr"
NA=$(wc -l < "$T/a.nr" | tr -d ' ')
EXPECT=$((NH + 1 + 1 + 1 + 2))        # hosts, www, NS, the address of ns1, the SOA at both ends
[ "$NA" -eq "$EXPECT" ] && pass "the AXFR of a.test (out of memory) is complete: $NA records" || fail "AXFR of a.test: $NA records, expected $EXPECT"
[ "$(issued)" = "$((I0 + 1))" ] && [ "$(xstat waited)" = "$((W0 + 1))" ] && [ "$(xstat loaded)" = "$((L0 + 1))" ] && pass "one fetch for it (issued $((I0 + 1)), waited, loaded)" || fail "issued $(issued), waited $(xstat waited), loaded $(xstat loaded)"
[ "$(xstat marked)" -ge 1 ] && pass "the zone was marked evict-next (marked=$(xstat marked))" || fail "marked=$(xstat marked)"
wait_oom a.test 15 && pass "the cache manager took a.test out of memory when the transfer was over (it is not kept for a transfer)" || fail "a.test stays in memory"

# the same zone from memory
q www.a.test > /dev/null
oom a.test && fail "a.test was not loaded by the query" || pass "a query loads a.test"
axfr a.test > "$T/a.res"
cmp -s "$T/a.nr" "$T/a.res" && pass "the AXFR from memory is the same record set as the AXFR of the zone that was out of memory ($NA records)" || { fail "the transfers differ"; diff "$T/a.nr" "$T/a.res" | head -5; }
W1=$(xstat waited)
sleep 3
oom a.test && fail "a.test, loaded by a query and transferred, was taken out of memory" || pass "a zone that a query loaded is not marked by a transfer: it stays in memory"
[ "$(xstat waited)" = "$W1" ] && pass "(the transfer from memory waited for nothing)" || fail "waited changed from $W1 to $(xstat waited)"

echo "== IXFR of a zone that is out of memory"
I1=$(issued)
SU0=$(xstat summary_answers)
ixfr c.test 5 > "$T/c5.out"
NC=$(wc -l < "$T/c5.out" | tr -d ' ')
[ "$NC" = "1" ] && grep -q " 5 3600 600 86400 300" "$T/c5.out" && pass "the IXFR from the serial the zone has is the one SOA" || fail "IXFR=5: $NC records: $(head -2 "$T/c5.out")"
ixfr c.test 9 > "$T/c9.out"
[ "$(wc -l < "$T/c9.out" | tr -d ' ')" = "1" ] && pass "... also from a newer serial (RFC 1982)" || fail "IXFR=9: $(head -2 "$T/c9.out")"
[ "$(issued)" = "$I1" ] && oom c.test && [ "$(xstat summary_answers)" = "$((SU0 + 2))" ] && pass "the zone was not read for them (issued $I1, summary_answers $((SU0 + 2)))" || fail "issued $(issued) (was $I1), summary_answers $(xstat summary_answers) (was $SU0), out of memory: $(oom c.test && echo yes || echo no)"
ixfr c.test 3 > "$T/c3.nr"
NC3=$(wc -l < "$T/c3.nr" | tr -d ' ')
[ "$NC3" -eq "$EXPECT" ] && pass "the IXFR from an old serial gets the whole zone (RFC 1995 4: no history): $NC3 records" || fail "IXFR=3: $NC3 records"
[ "$(issued)" = "$((I1 + 1))" ] && pass "it read the zone once" || fail "issued $(issued), was $I1"
wait_oom c.test 15 && pass "... and the zone was taken out of memory again" || fail "c.test stays in memory"
axfr c.test > "$T/c.nr"
cmp -s "$T/c3.nr" "$T/c.nr" && pass "the AXFR of the zone that is out of memory is the same record set as the AXFR-style IXFR" || { fail "IXFR and AXFR differ"; diff "$T/c3.nr" "$T/c.nr" | head -5; }
wait_oom c.test 15 > /dev/null
q www.c.test > /dev/null
ixfr c.test 3 > "$T/c3.res"
cmp -s "$T/c3.nr" "$T/c3.res" && pass "the IXFR from memory (no history: the whole zone) is the same record set" || { fail "the IXFR from memory differs"; diff "$T/c3.nr" "$T/c3.res" | head -5; }
ixfr c.test 5 > "$T/c5.res"
cmp -s "$T/c5.out" "$T/c5.res" && pass "the IXFR from the current serial from memory is the same one SOA" || fail "IXFR=5 from memory: $(cat "$T/c5.res")"

echo "== a change in the database: a summary with a new serial"
oom d.test && pass "d.test is out of memory" || fail "d.test is in memory"
sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.d.test host.d.test 6 3600 600 86400 300' WHERE type = 'SOA' AND name = 'd.test'; INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'new.d.test', 'A', '192.0.2.99', 300, 0, 0 FROM domains WHERE name = 'd.test';"
$KCTL reload d.test > /dev/null 2>&1
i=0; while [ $i -lt 50 ] && [ "$(serial_of d.test)" != "6" ]; do sleep 0.2; i=$((i + 1)); done
[ "$(serial_of d.test)" = "6" ] && oom d.test && pass "the directory has serial 6 and the zone is still out of memory (a summary)" || fail "d.test serial $(serial_of d.test)"
I2=$(issued)
ixfr d.test 6 > "$T/d6.out"
[ "$(wc -l < "$T/d6.out" | tr -d ' ')" = "1" ] && grep -q " 6 3600" "$T/d6.out" && [ "$(issued)" = "$I2" ] && oom d.test && pass "the IXFR from serial 6 is the one SOA of the new version, from the summary, no fetch" || fail "IXFR=6: $(cat "$T/d6.out"); issued $(issued) (was $I2)"
ixfr d.test 5 > "$T/d5.out"
grep -q "new.d.test" "$T/d5.out" && grep -q " 6 3600" "$T/d5.out" && pass "the IXFR from serial 5 reads the zone and gets the new version ($(wc -l < "$T/d5.out" | tr -d ' ') records)" || fail "IXFR=5: $(head -3 "$T/d5.out")"

echo "== a zone that cannot be read"
oom bad.test && pass "bad.test is out of memory" || fail "bad.test is in memory"
F0=$(xstat failed)
S=$(date +%s)
D bad.test AXFR +nohexdump > "$T/bad.out"
E=$(( $(date +%s) - S ))
grep -qi "SERVFAIL\|Transfer failed\|failed" "$T/bad.out" && pass "the AXFR of a zone the loader cannot read fails ($(grep -i -m1 'fail' "$T/bad.out"))" || fail "bad.test AXFR: $(head -5 "$T/bad.out")"
[ "$E" -ge 2 ] && [ "$E" -le 8 ] && pass "... after transfer-fetch-timeout (3 s): $E s" || fail "the failure came after $E s"
[ "$(xstat failed)" = "$((F0 + 1))" ] && pass "counted as failed" || fail "failed=$(xstat failed) (was $F0)"
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "the server goes on answering" || fail "no answer from the server after the failed transfer"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo "== transfers, queries and evictions at the same time (memory-limit 1m, $NZ zones)"
conf 1m
start_srv
RES0=$(stat resident)
echo "  resident after the start: ${RES0:-?}"
c=1
while [ $c -le 3 ]; do
    perl tests/db/xfer_stress.pl 127.0.0.1 "$PORT" $NZ $NSH "$SECS" $c > "$T/xc$c.out" 2> "$T/xc$c.err" &
    CPIDS="$CPIDS $!"
    c=$((c + 1))
done
c=1
while [ $c -le 2 ]; do
    CACHE_STRESS_DELAY_MS=${XFER_TEST_DELAY_MS:-4} perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ 1 ${XFER_TEST_QUERIES:-1500} $c > "$T/qc$c.out" 2> "$T/qc$c.err" &
    CPIDS="$CPIDS $!"
    c=$((c + 1))
done
MAXUSED=0
LIMIT=$((1024 * 1024))
t=0
while [ $t -lt $((SECS * 5)) ]; do
    U=$($KCTL dbstatus 2>/dev/null | grep '^cache:' | sed -n 's/.* resident=\([0-9]*\) retired=\([0-9]*\).*/\1 \2/p' | awk '{ print $1 + $2 }')
    [ -n "$U" ] && [ "$U" -gt "$MAXUSED" ] && MAXUSED=$U
    sleep 0.2; t=$((t + 1))
done
for p in $CPIDS; do wait "$p"; done
CPIDS=""
OK=0; OK1=0; BAD=0; SF=0; RF=0; OT=0
for c in 1 2 3; do
    l=$(cat "$T/xc$c.out")
    OK=$((OK + $(echo "$l" | sed -n 's/.*ok=\([0-9]*\) .*/\1/p'))); OK1=$((OK1 + $(echo "$l" | sed -n 's/.*ok1=\([0-9]*\).*/\1/p')))
    BAD=$((BAD + $(echo "$l" | sed -n 's/.*bad=\([0-9]*\).*/\1/p'))); SF=$((SF + $(echo "$l" | sed -n 's/.*servfail=\([0-9]*\).*/\1/p')))
    RF=$((RF + $(echo "$l" | sed -n 's/.*refused=\([0-9]*\).*/\1/p'))); OT=$((OT + $(echo "$l" | sed -n 's/.*other=\([0-9]*\).*/\1/p')))
done
echo "  transfers: complete $OK, one SOA $OK1, wrong $BAD, servfail $SF, refused $RF, other $OT"
QOK=0; QW=0; QNR=0; QTO=0
for c in 1 2; do
    l=$(cat "$T/qc$c.out")
    QOK=$((QOK + $(echo "$l" | sed -n 's/.*ok=\([0-9]*\).*/\1/p'))); QW=$((QW + $(echo "$l" | sed -n 's/.*wrong=\([0-9]*\).*/\1/p')))
    QNR=$((QNR + $(echo "$l" | sed -n 's/.*notready=\([0-9]*\).*/\1/p'))); QTO=$((QTO + $(echo "$l" | sed -n 's/.*timeout=\([0-9]*\).*/\1/p')))
done
echo "  queries: ok $QOK, wrong $QW, not ready $QNR, timeout $QTO"
[ "$BAD" -eq 0 ] && [ "$RF" -eq 0 ] && [ "$OT" -eq 0 ] && pass "every transfer was complete or the one error message (no wrong, refused or broken transfer)" || { fail "transfers: wrong $BAD, refused $RF, other $OT"; head -3 "$T"/xc*.err; }
[ "$OK" -gt 20 ] && [ "$OK1" -gt 5 ] && pass "transfers went through: $OK whole zones, $OK1 one-SOA answers" || fail "only $OK whole zones and $OK1 one-SOA answers"
[ "$QW" -eq 0 ] && pass "no query was answered wrong" || fail "$QW wrong answers: $(head -3 "$T"/qc*.err)"
echo "  largest resident + retired seen: $MAXUSED (limit $LIMIT); transfers: waited $(xstat waited), loaded $(xstat loaded), failed $(xstat failed), summary answers $(xstat summary_answers), marked $(xstat marked)"
SLACK=$((LIMIT / 100 * 15 + 256 * 1024))
[ "$MAXUSED" -le $((LIMIT + SLACK + 1024 * 1024)) ] && pass "the memory stayed near the limit under the load (transfers hold their zones: slack $SLACK + 1 MB)" || fail "resident + retired reached $MAXUSED (limit $LIMIT)"
[ "$(xstat loaded)" -gt 5 ] && [ "$(stat evictions)" -gt 5 ] && pass "zones were read for transfers and taken out of memory ($(stat evictions) evictions)" || fail "loaded $(xstat loaded), evictions $(stat evictions)"
kill -0 "$SRV" 2>/dev/null && pass "the server is running" || fail "the server is gone"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

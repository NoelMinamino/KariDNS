#!/bin/sh
# run_db_converge_test.sh - the loader's idea of what is in the Backend's memory converges, and what a zone out of memory keeps (D1a, review of
# milestone 4B / step 6), with the real karidns, the real karidns-dbloader and SQLite3.
#
#   - a control client that reads a reply a byte at a time does not hold the control thread for ever: the reply has a deadline (10 s) and the client
#     is dropped; `karictl status` is one write
#   - a zone the Backend fetched and the cache manager took out again (no message tells the loader) is changed in the database while the database zones
#     are above the high mark of memory-limit: the loader sends its body (it thinks the zone is in memory), the Backend leaves the data out and says so
#     (NOT_RESIDENT), the loader then sends the summary with the apex, and the SOA question is answered from it without reading the zone.  The apex
#     that the zone had when it left memory (built from its image) answers the SOA question before that.
#   - a reload that makes a zone keep an apex (notify no -> notify yes) gives the zones that are out of memory their apex (summary fetch), also while the database
#     zones are over the hard limit of memory-limit (a summary brings no zone data); a zone that cannot have an apex (nine NS names) is not asked again by the next reload
#   - the summary answer for an NS RRset that fits the EDNS size of the client and not 512 bytes is the answer of the zone in memory (UDP + EDNS, TCP)
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

NZ=1100          # (fillers: the reply of observatory is 664 bytes a zone, far more than the socket buffer)
BIGN=${BIGN:-10600}   # (records of the big pinned zone: about memory-limit 1m)
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_converge.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
H1=""; H2=""
cleanup() {
    [ -n "$H1$H2" ] && kill $H1 $H2 2>/dev/null   # (the held transfers of the hard limit part, when the run fails before it kills them)
    [ -n "$H1$H2" ] && wait $H1 $H2 2>/dev/null
    stop_srv; rm -rf "$T"
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
# e: the zone that is fetched, taken out and changed.  n: no allow-transfer (notify no keeps no apex for it).  l: eight NS targets with long names.
# big: pinned, about as large as memory-limit 1m, so that the database zones stay above the high mark.  x: nine NS names, which a summary cannot carry.
# z0000..: fillers.
LONGNS=""
for k in 1 2 3 4 5 6 7 8; do
    lab=$(printf '%055d' 0 | tr 0 "$k")
    LONGNS="$LONGNS INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns$k.$lab.hosting.example', 3600, 0, 0 FROM domains WHERE name = 'l.test';"
done
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('e.test', 'NATIVE'), ('n.test', 'NATIVE'), ('l.test', 'NATIVE'), ('big.test', 'NATIVE'), ('x.test', 'NATIVE');
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ - 1)))
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.hosting.example host.hosting.example 7 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.hosting.example', 3600, 0, 0 FROM domains WHERE name NOT IN ('l.test', 'e.test', 'x.test');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns2.hosting.example', 3600, 0, 0 FROM domains WHERE name NOT IN ('l.test', 'x.test');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, d.name, 'NS', 'nsx' || k.i || '.hosting.example', 3600, 0, 0 FROM domains d, (SELECT 1 AS i UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) k WHERE d.name = 'x.test';
-- e: one NS target inside the zone, with an AAAA and an A record (the AAAA first), and one outside every zone
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.e.test', 3600, 0, 0 FROM domains WHERE name = 'e.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.e.test', 'AAAA', '2001:db8::5', 600, 0, 0 FROM domains WHERE name = 'e.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.e.test', 'A', '192.0.2.5', 300, 0, 0 FROM domains WHERE name = 'e.test';
$LONGNS
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((BIGN - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, printf('h%05d.big.test', n.i), 'A', '192.0.2.' || (1 + n.i % 250), 300, 0, 0 FROM n, domains d WHERE d.name = 'big.test';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-CACHE', 'pin' FROM domains WHERE name = 'big.test';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '192.0.2.1' FROM domains WHERE name = 'l.test';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf OPTIONS-LINES DATABASE-LINES
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; $1
    database { driver sqlite3; database-file "${DBF:-$T/db/z.db}"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate ${FR:-5000}; park-timeout 4000; acl-ceiling { 127.0.0.1; }; $2 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/srv.log"          # (the background job below truncates it later: a "initial load complete" of the previous server must not be taken for this one's)
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 600 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
    sleep 1
}
stat() { $KCTL dbstatus 2>/dev/null | grep '^cache:' | sed -n "s/.* $1=\([0-9]*\).*/\1/p" | tail -1; }
oom() { $KCTL dbstatus "$1" 2>/dev/null | grep -q "out of memory"; }       # oom ZONE: its data is out of memory
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=5 +tries=1 2>/dev/null | head -1; }
probe() { perl tests/db/dns_soa_probe.pl 127.0.0.1 "$PORT" "$@"; }       # probe PROTO NAME QTYPE EDNS DO
soa_serial() { ./dag @127.0.0.1 -p "$PORT" "$1" SOA +short +noedns +nohexdump +time=5 +tries=1 2>/dev/null | head -1 | awk '{print $3}'; }
wait_walk() {   # wait_walk WALKS-BEFORE: the walk after a reload ran and is done, and every summary it asked for is answered (sets AS, the number asked for)
    i=0
    while [ $i -lt 600 ]; do
        A=$($KCTL dbstatus 2>/dev/null | grep "^apex:")
        AS=$(echo "$A" | sed -n 's/.*asked=\([0-9]*\).*/\1/p'); AN=$(echo "$A" | sed -n 's/.*answered=\([0-9]*\).*/\1/p'); AW=$(echo "$A" | sed -n 's/.*walking=\([0-9]*\).*/\1/p'); AK=$(echo "$A" | sed -n 's/.*walks=\([0-9]*\).*/\1/p'); AQ=$(echo "$A" | sed -n 's/.*queued=\([0-9]*\).*/\1/p')
        [ "${AK:-0}" -gt "$1" ] && [ "$AS" = "${AN:-x}" ] && [ "${AW:-1}" = "0" ] && [ "${AQ:-1}" = "0" ] && break
        sleep 0.2; i=$((i + 1))
    done
    echo "  $A"
}
walks_now() { $KCTL dbstatus 2>/dev/null | grep "^apex:" | sed -n 's/.*walks=\([0-9]*\).*/\1/p'; }
wait_oom() {   # wait_oom ZONE SECONDS: the zone's data leaves memory (the cache manager)
    i=0; while [ $i -lt $(($2 * 10)) ] && ! oom "$1"; do sleep 0.1; i=$((i + 1)); done
    oom "$1"
}

echo "== a control client that reads a byte at a time is dropped at the deadline"
conf "" ""
start_srv
FULL=$(perl tests/db/ctl_slow_reader.pl "$T/ctl.sock" "$SECRET" observatory 0 | sed -n 's/^bytes=//p')
echo "  the whole reply of observatory: ${FULL:-?} bytes"
[ "${FULL:-0}" -gt 600000 ] && pass "the reply is far larger than the socket buffer" || fail "observatory reply $FULL bytes"
S=$(date +%s)
SLOW=$(perl tests/db/ctl_slow_reader.pl "$T/ctl.sock" "$SECRET" observatory 13 | sed -n 's/^bytes=//p')
echo "  a client that reads a byte at a time for 13 s got ${SLOW:-?} bytes in $(( $(date +%s) - S )) s"
[ -n "$SLOW" ] && [ "$SLOW" -lt $((FULL / 2)) ] && pass "the reply was cut at the deadline (the connection was closed, not served to the end)" || fail "the slow client got $SLOW of $FULL bytes"
$KCTL status 2>&1 | grep -q "^version: KariDNS" && pass "the control thread serves the next client; status is written whole" || fail "karictl status: $($KCTL status 2>&1 | head -3)"
stop_srv

echo "== the loader's inventory converges after the Backend took a fetched zone out of memory"
conf "" "memory-limit 1m;"
start_srv
i=0; while [ $i -lt 100 ] && [ "$(stat resident)" -lt 900000 ]; do sleep 0.3; i=$((i + 1)); done
LIM=$(stat limit); RES=$(stat resident)
echo "  limit $LIM, resident $RES (the pinned zone)"
[ "$RES" -ge $((LIM / 100 * 96)) ] && [ "$RES" -le $((LIM / 10 * 11)) ] && pass "the database zones are above the high mark and below the hard limit (BIGN=$BIGN)" || fail "resident $RES is not between 96% and 110% of $LIM: set BIGN"
oom e.test && pass "e.test starts out of memory (a summary)" || fail "e.test is not out of memory"
[ "$(soa_serial e.test)" = "7" ] && oom e.test && pass "its SOA question is answered from the summary (the zone stays out of memory)" || fail "e.test SOA / out of memory: $(soa_serial e.test)"
UE0=$(probe udp e.test SOA 1232 0)
[ "$(echo "$UE0" | cut -c21-24)" = "0003" ] && pass "the summary answer has the glue of ns1.e.test: AAAA and A (and the OPT record) in Additional" || fail "e.test: ARCOUNT $(echo "$UE0" | cut -c21-24)"
q www.e.test > /dev/null
oom e.test && fail "e.test was not fetched" || pass "e.test is fetched for a query"
wait_oom e.test 20 && pass "the cache manager takes it out again (the loader is not told)" || fail "e.test stays in memory"
UE1=$(probe udp e.test SOA 1232 0)
[ "$(soa_serial e.test)" = "7" ] && oom e.test && pass "the SOA question is answered from the apex built from the image that left (no second fetch)" || fail "e.test was read again for its SOA question"
[ -n "$UE0" ] && [ "$UE0" = "$UE1" ] && pass "... and it is the answer of the summary, glue included, byte for byte (zone order, TTLs)" || fail "e.test: summary $UE0 / image $UE1"
C0=$(stat cold)
sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.hosting.example host.hosting.example 8 3600 600 86400 300' WHERE type = 'SOA' AND name = 'e.test'; INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'new.e.test', 'A', '192.0.2.99', 300, 0, 0 FROM domains WHERE name = 'e.test';"
$KCTL reload e.test > /dev/null 2>&1
sleep 2
C1=$(stat cold)
[ "$C1" -gt "$C0" ] && pass "the changed zone came as a body and was left out of memory (cold $C0 -> $C1)" || fail "cold $C0 -> $C1: the body was installed"
oom e.test && pass "e.test is still out of memory" || fail "e.test was admitted"
[ "$(soa_serial e.test)" = "8" ] && oom e.test && pass "its SOA question gives the new serial from the summary the loader sent after NOT_RESIDENT" || fail "e.test serial $(soa_serial e.test), out of memory: $(oom e.test && echo yes || echo no)"
sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.hosting.example host.hosting.example 9 3600 600 86400 300' WHERE type = 'SOA' AND name = 'e.test';"
$KCTL reload e.test > /dev/null 2>&1
sleep 2
[ "$(soa_serial e.test)" = "9" ] && oom e.test && pass "the next change is a summary: serial 9, still out of memory" || fail "e.test serial $(soa_serial e.test)"
[ "$(q new.e.test)" = "192.0.2.99" ] && pass "a query then loads the new version" || fail "new.e.test: $(q new.e.test)"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo "== a reload that makes the zones keep an apex gives the zones out of memory theirs"
# fetch-rate 100: the walk (1100 summaries) needs about ten seconds, and the queries must not be left without a token meanwhile
FR=100
conf "notify no;" "memory-limit 64m;"
start_srv
W0=$(walks_now)
conf "" "memory-limit 64m;"
$KCTL reconfig > /dev/null 2>&1
i=0; while [ $i -lt 100 ] && ! $KCTL dbstatus 2>/dev/null | grep -q "^apex: .*walking=1"; do sleep 0.05; i=$((i + 1)); done
# (a query for a zone out of memory, once the walk has used the burst and goes at the pace of the rate: it takes a token only from a bucket that is more than half full)
sleep 2
WQ=0
for z in e.test l.test z0100.test z0101.test z0102.test; do
    sleep 1
    $KCTL dbstatus 2>/dev/null | grep -q "^apex: .*walking=1" && [ "$(q www.$z)" = "192.0.2.80" ] && WQ=$((WQ + 1))
done
[ "$WQ" -eq 5 ] && pass "queries for zones out of memory are answered during the walk ($WQ of 5, each while it was running)" || fail "only $WQ of 5 queries were answered while the walk was running"
wait_walk "${W0:-0}"     # (every zone of the database asks for its summary)
FR=
AS1=$AS
[ "${AS1:-0}" -gt 1000 ] && pass "the walk asked for the summaries of the zones out of memory that have no apex ($AS1)" || fail "the walk asked for $AS1 summaries"
W1=$(walks_now)
conf "minimal-responses no;" "memory-limit 64m;"
$KCTL reconfig > /dev/null 2>&1
wait_walk "${W1:-0}"
[ "$AS" = "$AS1" ] && pass "a zone that cannot have an apex (x.test: nine NS names) is not asked again by the next reload (asked $AS1 -> $AS)" || fail "the second walk asked for $((AS - AS1)) more summaries"
oom n.test && pass "n.test is out of memory" || fail "n.test is not out of memory"
[ "$(soa_serial n.test)" = "7" ] && oom n.test && pass "n.test (no allow-transfer) was given an apex by the reload (summary fetch): its SOA question does not read it" || fail "n.test SOA: $(soa_serial n.test); out of memory: $(oom n.test && echo yes || echo no)"
stop_srv

echo "== two UPDATEs of big zones back to back, then a reload walk with zones that an UPDATE keeps in memory"
# two big zones that a dynamic UPDATE has changed stay in memory (an UPDATE-pinned zone is never taken out until the database replaces it) and count as pinned
cp "$T/db/z.db" "$T/db/z2.db"
sqlite3 "$T/db/z2.db" <<SQL
INSERT INTO domains (name, type) VALUES ('big2.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.hosting.example host.hosting.example 7 3600 600 86400 300', 900, 0, 0 FROM domains WHERE name = 'big2.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.hosting.example', 3600, 0, 0 FROM domains WHERE name = 'big2.test';
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 7999)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, printf('h%05d.big2.test', n.i), 'A', '192.0.2.' || (1 + n.i % 250), 300, 0, 0 FROM n, domains d WHERE d.name = 'big2.test';
DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-CACHE';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-DNSUPDATE-FROM', '127.0.0.1' FROM domains WHERE name IN ('big.test', 'big2.test');
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE name IN ('big.test', 'big2.test');
SQL
chown nobody "$T/db/z2.db"*; chmod 600 "$T/db/z2.db"*
DBF="$T/db/z2.db"
conf "notify no;" "memory-limit 1m;"
start_srv
# two UPDATEs of big zones back to back, each at the first try: the version the first one replaced is retired, not freed yet (it is at the next tick of one second),
# and that must not make the fetch for the second zone "not ready"
for z in big.test big2.test; do
    got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" udp-update $z 2>&1)
    echo "$got" | grep -q 'rcode=0$' && pass "the UPDATE of $z (a zone out of memory) is applied at the first try" || fail "UPDATE of $z: $got"
done
LIM=$(stat limit); RES=$(stat resident)
[ "$RES" -gt $((LIM / 10 * 11)) ] && pass "the zones changed by an UPDATE stay in memory, above 110% of the limit ($RES > $LIM)" || fail "resident $RES is not over 110% of $LIM"
W0=$(walks_now)
conf "" "memory-limit 1m;"
$KCTL reconfig > /dev/null 2>&1
wait_walk "${W0:-0}"
[ "${AS:-0}" -gt 1000 ] && pass "the walk finished (walking=0) with $AS summaries asked for and answered" || fail "the walk asked for $AS summaries"
[ "$(soa_serial n.test)" = "7" ] && oom n.test && pass "n.test has its apex: the SOA question does not read it" || fail "n.test SOA: $(soa_serial n.test); out of memory: $(oom n.test && echo yes || echo no)"
stop_srv

echo "== zones in memory above the hard limit of memory-limit (two big zones that a transfer holds)"
# a zone that is being transferred is not taken out of memory and is not counted among the pinned zones, so the zones in memory stay above 110% of the limit
# for as long as the transfers last: the fetches for queries are shed, the walk for the apex (summaries) is not held back, and the manager brings the memory down
# when the transfers end
conf "notify no;" "memory-limit 1m;"
start_srv
perl tests/db/hold_axfr.pl 127.0.0.1 "$PORT" big.test 120 30 > "$T/hold1.out" 2>&1 &
H1=$!
i=0; while [ $i -lt 300 ] && ! grep -q held "$T/hold1.out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
perl tests/db/hold_axfr.pl 127.0.0.1 "$PORT" big2.test 120 30 > "$T/hold2.out" 2>&1 &
H2=$!
i=0; while [ $i -lt 300 ] && ! grep -q held "$T/hold2.out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
grep -q held "$T/hold1.out" && grep -q held "$T/hold2.out" && pass "two big zones are held by transfers that the client does not read" || fail "the transfers: $(cat "$T/hold1.out" "$T/hold2.out" 2>&1 | tr '\n' ' ')"
sleep 1
LIM=$(stat limit); RES=$(stat resident)
[ "$RES" -gt $((LIM / 10 * 11)) ] && pass "the zones in memory are above 110% of the limit and stay there ($RES > $LIM)" || fail "resident $RES is not over 110% of $LIM"
[ -z "$(q www.e.test)" ] && oom e.test && pass "a query for a zone out of memory is answered not ready: its fetch is shed" || fail "www.e.test: $(q www.e.test)"
W0=$(walks_now)
conf "" "memory-limit 1m;"
$KCTL reconfig > /dev/null 2>&1
wait_walk "${W0:-0}"
[ "${AS:-0}" -gt 1000 ] && pass "the walk finished (walking=0) with $AS summaries asked for and answered, above the hard limit" || fail "the walk asked for $AS summaries"
[ "$(soa_serial n.test)" = "7" ] && oom n.test && pass "n.test has its apex: the SOA question does not read it" || fail "n.test SOA: $(soa_serial n.test); out of memory: $(oom n.test && echo yes || echo no)"
kill "$H1" "$H2" 2>/dev/null
wait "$H1" "$H2" 2>/dev/null
H1=""; H2=""
i=0; while [ $i -lt 300 ] && [ "$(stat resident)" -gt $((LIM / 100 * 95)) ]; do sleep 0.1; i=$((i + 1)); done
RES=$(stat resident)
[ "$RES" -le $((LIM / 100 * 95)) ] && pass "when the transfers end the cache manager takes the zones out of memory again ($RES bytes)" || fail "resident is still $RES (limit $LIM)"
[ "$(q www.e.test)" = "192.0.2.80" ] && pass "a query for a zone out of memory is answered again" || fail "www.e.test: $(q www.e.test)"
stop_srv
DBF=""

echo "== a summary answer that fits the EDNS size and not 512 bytes"
conf "" "memory-limit 64m;"
start_srv
UL=$(probe udp l.test SOA 1232 0); TL=$(probe tcp l.test SOA 0 0)
oom l.test && pass "the SOA questions (UDP + EDNS 1232, TCP) leave l.test out of memory" || fail "l.test was read"
[ "$(( ${#UL} / 2 ))" -gt 512 ] && pass "the answer is $(( ${#UL} / 2 )) bytes, more than the 512 of a plain UDP answer" || fail "the answer is ${#UL} hex digits"
q www.l.test > /dev/null
RL=$(probe udp l.test SOA 1232 0); RT=$(probe tcp l.test SOA 0 0)
[ -n "$UL" ] && [ "$UL" = "$RL" ] && pass "l.test: the summary answer is the answer of the zone in memory, byte for byte (UDP + EDNS 1232)" || fail "l.test UDP EDNS differ"
[ -n "$TL" ] && [ "$TL" = "$RT" ] && pass "l.test: ... over TCP" || fail "l.test TCP differ"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

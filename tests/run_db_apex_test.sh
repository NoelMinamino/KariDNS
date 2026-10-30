#!/bin/sh
# run_db_apex_test.sh - the SOA question for a zone that is not in memory is answered from its summary (D1a step 6, design 12-12), real karidns, real
# karidns-dbloader and SQLite3.
#
# With database { memory-limit } the loader sends, with the summary of a zone, its apex: the SOA (names, TTL, minimum) and the NS RRset.  A secondary
# that polls the SOA of a zone then does not make the server read the zone.  Checked:
#   - the answer to an SOA question at the apex of a zone that is out of memory (UDP, UDP with EDNS, TCP) leaves the zone out of memory, and is the
#     same bytes as the answer of the zone once it is in memory (RFC 1035 3.3.13 SOA, RFC 2181 5.2 the NS RRset has the lowest TTL, NS in Authority)
#   - a question that the summary cannot answer as the zone would (DO=1, a zone whose NS target has glue in the zone, another qtype) reads the zone
#   - minimal-responses yes: the same answer without the NS RRset
#   - `notify no` and no allow-transfer: the zone keeps no apex (its SOA question reads the zone); with allow-transfer it keeps it
#   - the apex follows the database: a changed SOA and NS RRset reach the next summary
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

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_apex.XXXXXX") || exit 1
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
# a e f: NS targets that no zone of this server contains; b: an NS target inside the zone, with an address; c: TTLs and the case of its own, the NS
# RRset has two TTLs (the lower one is the RRset's); d: allow-transfer
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE'), ('b.test', 'NATIVE'), ('c.test', 'NATIVE'), ('d.test', 'NATIVE'), ('e.test', 'NATIVE'), ('f.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.hosting.example host.hosting.example 7 3600 600 86400 300', 900, 0, 0 FROM domains WHERE name <> 'c.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'NS1.Hosting.Example hostmaster.c.test 2024010101 7200 1200 1209600 120', 7200, 0, 0 FROM domains WHERE name = 'c.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.hosting.example', 3600, 0, 0 FROM domains WHERE name NOT IN ('b.test', 'c.test');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns2.hosting.example', 3600, 0, 0 FROM domains WHERE name NOT IN ('b.test', 'c.test');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.hosting.example', 600, 0, 0 FROM domains WHERE name = 'c.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'Ns3.Hosting.example', 300, 0, 0 FROM domains WHERE name = 'c.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.b.test', 3600, 0, 0 FROM domains WHERE name = 'b.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.b.test', 'A', '192.0.2.53', 3600, 0, 0 FROM domains WHERE name = 'b.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '192.0.2.1' FROM domains WHERE name = 'd.test';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf OPTIONS-LINES
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; $1
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; memory-limit 64m; fetch-rate 5000; park-timeout 4000; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 300 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
    sleep 1
}
stat() { $KCTL dbstatus 2>/dev/null | grep '^cache:' | sed -n "s/.* $1=\([0-9]*\).*/\1/p" | tail -1; }
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=5 +tries=1 2>/dev/null | head -1; }
probe() { perl tests/db/dns_soa_probe.pl 127.0.0.1 "$PORT" "$@"; }       # probe PROTO NAME QTYPE EDNS DO

echo "== SOA at the apex of a zone that is out of memory"
conf ""
start_srv
RES0=$(stat resident); COLD0=$(stat cold)
echo "  resident ${RES0:-?} bytes, cold ${COLD0:-?}"
UA=$(probe udp a.test SOA 0 0); EA=$(probe udp a.test SOA 1232 0); TA=$(probe tcp a.test SOA 0 0)
UC=$(probe udp c.test SOA 0 0); EC=$(probe udp c.test SOA 1232 0); TC=$(probe tcp c.test SOA 0 0)
RES1=$(stat resident)
[ "$RES1" = "$RES0" ] && pass "the SOA questions (UDP, UDP + EDNS, TCP) left a.test and c.test out of memory (resident $RES0 -> $RES1)" || fail "resident $RES0 -> $RES1: the zones were read"
case "$UA" in 1234*) pass "a.test answers";; *) fail "a.test: $UA";; esac
probe udp a.test NS 0 0 > /dev/null          # not an SOA question: the zone is read
[ "$(stat resident)" -gt "$RES1" ] && pass "an NS question reads the zone (resident grows)" || fail "an NS question did not read the zone"
probe udp c.test NS 0 0 > /dev/null
sleep 1
for z in a c; do
    eval "u=\$U$(echo $z | tr a-z A-Z); e=\$E$(echo $z | tr a-z A-Z); t=\$T$(echo $z | tr a-z A-Z)"
    ru=$(probe udp $z.test SOA 0 0); re=$(probe udp $z.test SOA 1232 0); rt=$(probe tcp $z.test SOA 0 0)
    [ -n "$u" ] && [ "$u" = "$ru" ] && pass "$z.test: the answer from the summary is the answer of the zone in memory, byte for byte (UDP)" || fail "$z.test UDP: summary $u / zone $ru"
    [ -n "$e" ] && [ "$e" = "$re" ] && pass "$z.test: ... with EDNS" || fail "$z.test EDNS: summary $e / zone $re"
    [ -n "$t" ] && [ "$t" = "$rt" ] && pass "$z.test: ... over TCP" || fail "$z.test TCP: summary $t / zone $rt"
done
# c.test: the SOA TTL is the SOA's own, the NS RRset has the lowest TTL of its RRs
./dag @127.0.0.1 -p "$PORT" c.test SOA +nohexdump +noall +answer +authority +time=5 +tries=1 > "$T/c.out" 2>&1
grep -q '^c.test.[[:space:]]*7200[[:space:]]*IN[[:space:]]*SOA' "$T/c.out" && pass "c.test: the SOA has its own TTL (7200)" || fail "c.test SOA line: $(head -3 "$T/c.out")"
[ "$(grep -c '300[[:space:]]*IN[[:space:]]*NS' "$T/c.out")" = "2" ] && pass "c.test: the NS RRs have the lowest TTL of the RRset (300)" || fail "c.test NS lines: $(grep NS "$T/c.out")"

echo "== what the summary cannot answer reads the zone"
R=$(stat resident)
probe udp e.test SOA 1232 1 > /dev/null
[ "$(stat resident)" -gt "$R" ] && pass "e.test: DO=1 reads the zone (the RRSIGs are not in the summary)" || fail "e.test: DO=1 was answered without the zone"
R=$(stat resident)
probe udp b.test SOA 0 0 > /dev/null
[ "$(stat resident)" -gt "$R" ] && pass "b.test: an NS target inside the zone (glue) reads the zone" || fail "b.test was answered without the zone"
./dag @127.0.0.1 -p "$PORT" b.test SOA +nohexdump +noall +additional +time=5 +tries=1 2>&1 | grep -q '192.0.2.53' && pass "b.test: the answer has the glue" || fail "b.test: no glue in the answer"
stop_srv

echo "== minimal-responses yes"
conf "minimal-responses yes;"
start_srv
R=$(stat resident)
MU=$(probe udp a.test SOA 0 0)
[ "$(stat resident)" = "$R" ] && pass "a.test is answered from the summary" || fail "a.test was read"
q www.a.test > /dev/null
MR=$(probe udp a.test SOA 0 0)
[ -n "$MU" ] && [ "$MU" = "$MR" ] && pass "and it is what the zone in memory gives (with minimal-responses)" || fail "minimal-responses: summary $MU / zone $MR"
./dag @127.0.0.1 -p "$PORT" a.test SOA +nohexdump +noall +authority +time=5 +tries=1 > "$T/m.out" 2>&1
[ ! -s "$T/m.out" ] && pass "... without the NS RRset" || fail "authority section: $(cat "$T/m.out")"
stop_srv

echo "== notify no: only a zone with allow-transfer keeps its apex"
conf "notify no;"
start_srv
R=$(stat resident)
probe udp a.test SOA 0 0 > /dev/null
[ "$(stat resident)" -gt "$R" ] && pass "a.test (notify no, no allow-transfer) is read for its SOA question" || fail "a.test was answered without the zone"
R=$(stat resident)
probe udp d.test SOA 0 0 > /dev/null
[ "$(stat resident)" = "$R" ] && pass "d.test (allow-transfer) is answered from the summary" || fail "d.test was read"
stop_srv

echo "== the apex follows the database"
conf ""
start_srv
sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.hosting.example host.hosting.example 8 3600 600 86400 300', ttl = 1800 WHERE type = 'SOA' AND name = 'f.test'; INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns9.hosting.example', 3600, 0, 0 FROM domains WHERE name = 'f.test';"
$KCTL reload f.test > /dev/null 2>&1
sleep 1
R=$(stat resident)
S=$(probe udp f.test SOA 0 0)
[ "$(stat resident)" = "$R" ] && pass "f.test (changed in the database) is answered from the new summary" || fail "f.test was read"
q www.f.test > /dev/null
[ -n "$S" ] && [ "$S" = "$(probe udp f.test SOA 0 0)" ] && pass "and it is what the new zone in memory gives (serial 8, TTL 1800, three NS)" || fail "f.test: summary $S / zone differ"
stop_srv

grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

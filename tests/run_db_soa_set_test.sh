#!/bin/sh
# run_db_soa_set_test.sh - B8t-1 / B8t-2: database zones with several SOA rows / attributes on a SOA row.
#
# zone2sql writes one SOA row per tinydns "Z" line (with its karidns_record_tinydns row) and the tags of a tagged BIND SOA. The loader reads
# them (the SOA rows must have one serial, RFC 2181 s6.1) and sends the zone in the Extended AXFR version 3 encoding (SOA_SET, the SOA rows
# as wrapped body RRs; the frame is the reference SOA).  Three servers (127.0.0.1, one port each):
#   A  ss.test and bs.test from zone files           B  the same zones from SQLite3 through karidns-dbloader (acl-ceiling 127.0.0.0/24)
#   C  no file, no database: a secondary of B (Extended AXFR v3 carries the SOA set and the settings of B)
# Every client (127.0.0.1 = location in, 127.0.0.2 = ex, 127.0.0.3 = none) gets the same SOA, negative answers, positive answers and TTLs from
# A, B and C.  A serial mismatch between SOA rows is reported by the loader and the other zones are served.  The settings B sends to C are the
# database zone's settings cut at the ceiling.
#
# Needs root (loader owner, loopback aliases).  SKIP otherwise, and when a binary or the sqlite3 CLI is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
. "$ROOT/tests/lib_proc.sh"
if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./karidns-dbloader ./tests/db/zone2sql ./dag ./karictl; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbsoa.XXXXXX") || exit 1
chmod 755 "$T"
SA=""; SB=""; SC=""
ADDED=""
cleanup() {
    for p in "$SA" "$SB" "$SC"; do [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; done
    i=0
    while [ $i -lt 100 ]; do
        alive=0
        for p in "$SA" "$SB" "$SC"; do [ -n "$p" ] && kill -0 "$p" 2>/dev/null && alive=1; done
        [ $alive -eq 0 ] && break
        sleep 0.1; i=$((i + 1))
    done
    for p in "$SA" "$SB" "$SC"; do [ -n "$p" ] && kill -KILL "$p" 2>/dev/null; done
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
BASE=$(kari_port 0 $((20000 + $$ % 20000)))
PA=$BASE; PB=$((BASE + 1)); PC=$((BASE + 2))

for ip in 127.0.0.2 127.0.0.3; do
    ifconfig lo0 2>/dev/null | grep -q "inet $ip " && continue
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else echo "SKIP: loopback alias $ip cannot be added"; exit 0; fi
done

mkdir "$T/z" "$T/db"
cat > "$T/z/ss.test.data" <<'EOF'
%in:127.0.0.1
%ex:127.0.0.2
%no:127.0.0.3
Zss.test:ns1.in.ss.test.:hostmaster.ss.test.:7:3600:900:604800:300:300::in
Zss.test:ns1.ex.ss.test.:hostmaster.ss.test.:7:3600:900:604800:300:600::ex
&ss.test::ns1.ss.test:300
+ns1.ss.test:192.0.2.1:300
+www.ss.test:192.0.2.5:300
+inonly.ss.test:192.0.2.20:300::in
+multi.ss.test:192.0.2.51:60::in
+multi.ss.test:192.0.2.52:120::ex
+h.ss.test:192.0.2.60:300
+h.ss.test:192.0.2.61:100
+co.ss.test:192.0.2.70:300
+co.ss.test:192.0.2.71:60::in
EOF
cat > "$T/z/bs.test.zone" <<'EOF'
$TTL 300
$ORIGIN bs.test.
$LOCATION-TAG lt-in 127.0.0.1/32
$LOCATION-TAG lt-ex 127.0.0.2/32
$LOCATION lt-in
@ IN SOA ns1.in.bs.test. hostmaster.bs.test. ( 4 3600 900 604800 300 )
$LOCATION lt-ex
@ IN SOA ns1.ex.bs.test. hostmaster.bs.test. ( 4 3600 900 604800 600 )
$LOCATION
@ IN NS ns1.bs.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.40
$LOCATION lt-in
inonly IN A 192.0.2.41
EOF
cat > "$T/z/mm.test.data" <<'EOF'
%in:127.0.0.1
Zmm.test:ns1.in.mm.test.:hostmaster.mm.test.:7:3600:900:604800:300:300::in
Zmm.test:ns1.all.mm.test.:hostmaster.mm.test.:8:3600:900:604800:300:300:
&mm.test::ns1.mm.test:300
+ns1.mm.test:192.0.2.1:300
EOF
cat > "$T/z/ok.test.zone" <<'EOF'
$TTL 300
$ORIGIN ok.test.
@ IN SOA ns1.ok.test. hostmaster.ok.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.ok.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.5
EOF
chmod 644 "$T/z/"*
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
./tests/db/zone2sql --dialect sqlite3 --format tinydns "$T/z/ss.test.data" | sqlite3 "$T/db/z.db" && pass "ss.test imported" || fail "import of ss.test"
./tests/db/zone2sql --dialect sqlite3 "$T/z/bs.test.zone" | sqlite3 "$T/db/z.db" && pass "bs.test imported" || fail "import of bs.test"
./tests/db/zone2sql --dialect sqlite3 --format tinydns "$T/z/mm.test.data" | sqlite3 "$T/db/z.db" && pass "mm.test imported" || fail "import of mm.test"
./tests/db/zone2sql --dialect sqlite3 "$T/z/ok.test.zone" | sqlite3 "$T/db/z.db" && pass "ok.test imported" || fail "import of ok.test"
N=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'ss.test' AND r.type = 'SOA'")
[ "$N" = 2 ] && pass "the importer wrote one SOA row per Z line" || fail "SOA rows of ss.test: $N"
N=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id WHERE r.type = 'SOA' AND t.loc IS NOT NULL")
[ "$N" -ge 1 ] && pass "the location of a SOA row is in karidns_record_tinydns" || fail "no tinydns row on a SOA row"
# the database zone's settings: the AXFR ACL, the trusted resolvers; both are cut at the ceiling when they are sent to a secondary
sqlite3 "$T/db/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE name IN ('ss.test', 'bs.test')"
sqlite3 "$T/db/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '192.0.2.0/24' FROM domains WHERE name = 'ss.test'"
sqlite3 "$T/db/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-ECS-TRUSTED-RESOLVERS', '127.0.0.2, 10.0.0.0/8' FROM domains WHERE name = 'ss.test'"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
{
    printf 'options {\n    user "nobody"; pid-file "none"; ecs-enable yes; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PA"
    printf 'zone "ss.test" { type primary; file "%s/z/ss.test.data"; file-format tinydns; allow-transfer { 127.0.0.1; }; };\n' "$T"
    printf 'zone "bs.test" { type primary; file "%s/z/bs.test.zone"; allow-transfer { 127.0.0.1; }; };\n' "$T"
} > "$T/a.conf"
cat > "$T/b.conf" <<EOF
options {
    user "nobody"; pid-file "none"; ecs-enable yes; listen-on { 127.0.0.1; }; port $PB;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.0/24; }; db-reload-timeout 4; };
};
EOF
{
    printf 'options {\n    user "nobody"; pid-file "none"; ecs-enable yes; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PC"
    printf 'zone "ss.test" { type slave; masters { 127.0.0.1 port %s; }; };\n' "$PB"
    printf 'zone "bs.test" { type slave; masters { 127.0.0.1 port %s; }; };\n' "$PB"
} > "$T/c.conf"

"$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 & SA=$!
"$KARIDNS" -c "$T/b.conf" -f > "$T/b.log" 2>&1 & SB=$!
i=0
while [ $i -lt 300 ]; do grep -q "initial load complete" "$T/b.log" 2>/dev/null && break; sleep 0.1; i=$((i + 1)); done
grep -q "initial load complete" "$T/b.log" && pass "startup batch complete" || { fail "no initial load"; tail -20 "$T/b.log"; }
"$KARIDNS" -c "$T/c.conf" -f > "$T/c.log" 2>&1 & SC=$!
grep -q "zone 'mm.test'.*different serials (7 and 8)" "$T/b.log" && pass "mm.test: serial mismatch reported" || fail "mm.test: reason not logged"
grep -q "B8t-2" "$T/b.log" && fail "a zone is still refused for want of B8t-2" || pass "no zone is refused for want of the version 3 format"
[ "$(./dag www.ok.test A @127.0.0.1 -p "$PB" +short)" = "192.0.2.5" ] && pass "ok.test is served" || fail "ok.test is not served"

Q() {   # Q PORT SRC NAME TYPE: the status line and the RRs, message ID left out
    _p=$1; _s=$2; _n=$3; _t=$4
    ./dag "$_n" "$_t" @127.0.0.1 -p "$_p" -b "$_s" +nohexdump +time=2 +tries=1 2>&1 | sed 's/, id: [0-9]*//' | grep -E 'status:|flags:|[[:space:]]IN[[:space:]]+[A-Z]|EDE:'
}
same3() {   # same3 NAME SRC QNAME QTYPE: A, B and C answer the same
    _a=$(Q $PA "$2" "$3" "$4"); _b=$(Q $PB "$2" "$3" "$4"); _c=$(Q $PC "$2" "$3" "$4")
    if [ -n "$_a" ] && [ "$_a" = "$_b" ] && [ "$_b" = "$_c" ]; then pass "$1"; else fail "$1"; echo "file:"; echo "$_a"; echo "database:"; echo "$_b"; echo "secondary:"; echo "$_c"; fi
}
for z in ss.test bs.test; do
    j=0
    while [ $j -lt 100 ]; do
        o=$(Q $PC 127.0.0.1 www.$z A); [ -n "$o" ] && printf '%s' "$o" | grep -q 'status: NOERROR' && break
        sleep 0.2; j=$((j + 1))
    done
    [ $j -lt 100 ] && pass "C transferred $z from B" || { fail "C did not get $z"; tail -5 "$T/c.log"; }
done
for c in 127.0.0.1 127.0.0.2 127.0.0.3; do
    same3 "ss.test SOA from $c: file = database = secondary" $c ss.test SOA
    same3 "ss.test NXDOMAIN from $c" $c nx.ss.test A
    same3 "ss.test NODATA from $c" $c www.ss.test AAAA
    same3 "ss.test location record from $c" $c inonly.ss.test A
    same3 "ss.test TTL cases from $c (multi)" $c multi.ss.test A
    same3 "ss.test TTL cases from $c (harmonized)" $c h.ss.test A
    same3 "ss.test TTL cases from $c (co-visible)" $c co.ss.test A
    same3 "bs.test SOA from $c" $c bs.test SOA
    same3 "bs.test NXDOMAIN from $c" $c nx.bs.test A
    same3 "bs.test tagged record from $c" $c inonly.bs.test A
done
OUT=$(Q $PB 127.0.0.1 co.ss.test A)
printf '%s' "$OUT" | grep -Eq 'co\.ss\.test\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.70' && printf '%s' "$OUT" | grep -Eq 'co\.ss\.test\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.71' \
    && pass "database: the unrestricted (300) and the restricted (60) RR keep their TTLs" || { fail "database TTLs"; echo "$OUT"; }
OUT=$(Q $PB 127.0.0.1 h.ss.test A)
printf '%s' "$OUT" | grep -Eq 'h\.ss\.test\.[[:space:]]+100[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.60' && pass "database: an RRset of one visibility is harmonized (100)" || { fail "database harmonization"; echo "$OUT"; }
OUT=$(Q $PB 127.0.0.3 ss.test SOA)
printf '%s' "$OUT" | grep -q 'status: REFUSED' && printf '%s' "$OUT" | grep -q 'EDE: 18' && pass "a client that sees no SOA is refused (REFUSED, EDE 18)" || { fail "no-SOA client"; echo "$OUT"; }

echo "== the wire format and the settings B sends to C"
OUT=$(perl tests/lib_xfr_ext_probe.pl 127.0.0.1 "$PB" 127.0.0.1 ss.test 3)
printf '%s' "$OUT" | grep -Eq 'rcode=0 ext=3 soa=2 seq=S,65409,65408,' && printf '%s' "$OUT" | grep -q 'soaset=1/2' && pass "B: ss.test goes out in version 3: frame, SOA_SET (1/2), settings, ..." || { fail "B wire format"; echo "$OUT"; }
printf '%s' "$OUT" | grep -q 'settings=allow-transfer { 127.0.0.1; };|ecs-trusted-resolvers { 127.0.0.2; };|' && pass "B: the settings are cut at the ceiling (192.0.2.0/24 and 10.0.0.0/8 are not sent)" || { fail "B settings"; echo "$OUT"; }
OUT=$(perl tests/lib_xfr_ext_probe.pl 127.0.0.1 "$PB" 127.0.0.1 ss.test 2)
printf '%s' "$OUT" | grep -q 'rcode=5' && pass "B: a version 2 requester is refused" || { fail "B v2"; echo "$OUT"; }
OUT=$(perl tests/lib_axfr_probe.pl 127.0.0.1 "$PC" 127.0.0.1 ss.test AXFR)
printf '%s' "$OUT" | grep -q 'rcode=0 aa=1' && pass "C applies the allow-transfer it received" || { fail "C allow-transfer"; echo "$OUT"; }
OUT=$(perl tests/lib_axfr_probe.pl 127.0.0.1 "$PC" 127.0.0.2 ss.test AXFR)
printf '%s' "$OUT" | grep -q 'rcode=5' && pass "C refuses a client the received ACL does not list" || { fail "C refusal"; echo "$OUT"; }

echo "=== db SOA set (B8t-2): $PASS passed, $FAILS failed ==="
[ "$FAILS" = 0 ]

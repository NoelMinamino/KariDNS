#!/bin/sh
# run_db_soa_set_test.sh - B8t-1: database zones with several SOA rows / attributes on a SOA row.
#
# zone2sql writes one SOA row per tinydns "Z" line (with its karidns_record_tinydns row). The loader reads them (the SOA rows must have
# one serial, RFC 2181 s6.1); the KDB1 stream is still Extended AXFR v2, which cannot carry them, so until B8t-2 such a zone is reported
# as failed in the loader with a reason that names B8t-2, and the other zones are served. A serial mismatch is reported as such.
#
# Needs root (loader owner). SKIP otherwise, and when a binary or the sqlite3 CLI is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./karidns-dbloader ./tests/db/zone2sql ./dag; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbsoa.XXXXXX") || exit 1
chmod 755 "$T"
SP=""
cleanup() {
    [ -n "$SP" ] && kill -TERM "$SP" 2>/dev/null
    i=0
    while [ -n "$SP" ] && kill -0 "$SP" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SP" ] && kill -KILL "$SP" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$((20000 + $$ % 20000))

mkdir "$T/z" "$T/db"
cat > "$T/z/ss.test.data" <<'EOF'
%in:127.0.0.1
%ex:127.0.0.2
Zss.test:ns1.in.ss.test.:hostmaster.ss.test.:7:3600:900:604800:300:300::in
Zss.test:ns1.ex.ss.test.:hostmaster.ss.test.:7:3600:900:604800:300:300::ex
&ss.test::ns1.ss.test:300
+ns1.ss.test:192.0.2.1:300
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
./tests/db/zone2sql --dialect sqlite3 --format tinydns "$T/z/mm.test.data" | sqlite3 "$T/db/z.db" && pass "mm.test imported" || fail "import of mm.test"
./tests/db/zone2sql --dialect sqlite3 "$T/z/ok.test.zone" | sqlite3 "$T/db/z.db" && pass "ok.test imported" || fail "import of ok.test"
N=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'ss.test' AND r.type = 'SOA'")
[ "$N" = 2 ] && pass "the importer wrote one SOA row per Z line" || fail "SOA rows of ss.test: $N"
N=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id WHERE r.type = 'SOA' AND t.loc IS NOT NULL")
[ "$N" -ge 1 ] && pass "the location of a SOA row is in karidns_record_tinydns" || fail "no tinydns row on a SOA row"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/b.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.0/24; }; db-reload-timeout 4; };
};
EOF
"$KARIDNS" -c "$T/b.conf" -f > "$T/b.log" 2>&1 &
SP=$!
i=0
while [ $i -lt 300 ]; do grep -q "initial load complete" "$T/b.log" 2>/dev/null && break; sleep 0.1; i=$((i + 1)); done
grep -q "initial load complete" "$T/b.log" && pass "startup batch complete" || { fail "no initial load"; tail -20 "$T/b.log"; }
grep -q "zone 'ss.test'.*several SOA records or attributes.*B8t-2" "$T/b.log" && pass "ss.test: reported with the B8t-2 reason" || fail "ss.test: reason not logged"
grep -q "zone 'mm.test'.*different serials (7 and 8)" "$T/b.log" && pass "mm.test: serial mismatch reported" || fail "mm.test: reason not logged"
[ "$(./dag www.ok.test A @127.0.0.1 -p "$PORT" +short)" = "192.0.2.5" ] && pass "ok.test is served" || fail "ok.test is not served"
OUT=$(./dag ss.test SOA @127.0.0.1 -p "$PORT" +nohexdump 2>&1)
printf '%s' "$OUT" | grep -q "status: REFUSED" && pass "ss.test is not served" || fail "ss.test answered: $OUT"
echo "=== db SOA set (B8t-1): $PASS passed, $FAILS failed ==="
[ "$FAILS" = 0 ]

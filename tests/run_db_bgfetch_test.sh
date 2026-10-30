#!/bin/sh
# run_db_bgfetch_test.sh - a CNAME chain or the glue of a name server leads into a database zone that is not in memory (D1a step 8, design 5), with the real
# karidns, the real karidns-dbloader and SQLite3.
#
#   - the answer is what it is without the zone: the chain stops at the CNAME (RFC 1034 4.3.2: the resolver follows it itself), the glue of the sibling is left out
#     (RFC 9471 3.2); the zone is asked for in the background (the fetch stream, priority background; no waiting and no I/O in the query path)
#   - the partial answer is not stored in the response cache: once the zone is in memory the next query gets the whole chain, and the glue
#   - one request for a zone in a few seconds however often the query comes (a hundred queries: one fetch), none while its fetch is on its way
#   - a pattern of queries that chain into many zones cannot turn into a flood of fetches: the rate of fetches (fetch-rate) holds, and half of the bucket is
#     kept for the queries that wait for a zone
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

NB=300           # CNAMEs of bomb.test, each into a zone of its own
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_bgfetch.XXXXXX") || exit 1
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
INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE'), ('target.test', 'NATIVE'), ('ns.test', 'NATIVE'), ('prov2.test', 'NATIVE'), ('bomb.test', 'NATIVE'), ('dup.test', 'NATIVE'), ('dt.test', 'NATIVE');
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NB - 1)))
INSERT INTO domains (name, type) SELECT printf('t%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains WHERE name NOT IN ('ns.test');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.prov2.test', 3600, 0, 0 FROM domains WHERE name = 'ns.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 600, 0, 0 FROM domains WHERE name <> 'ns.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.a.test', 'CNAME', 't.target.test.', 300, 0, 0 FROM domains WHERE name = 'a.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ext.a.test', 'CNAME', 'h.far.example.', 300, 0, 0 FROM domains WHERE name = 'a.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 't.target.test', 'A', '192.0.2.77', 300, 0, 0 FROM domains WHERE name = 'target.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'x.dup.test', 'CNAME', 't.dt.test.', 300, 0, 0 FROM domains WHERE name = 'dup.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 't.dt.test', 'A', '192.0.2.66', 300, 0, 0 FROM domains WHERE name = 'dt.test';
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NB - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, printf('c%04d.bomb.test', n.i), 'CNAME', printf('h.t%04d.test.', n.i), 300, 0, 0 FROM n, domains d WHERE d.name = 'bomb.test';
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NB - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h.' || d.name, 'A', '192.0.2.200', 300, 0, 0 FROM domains d WHERE d.name LIKE 't0%' OR d.name LIKE 't1%' OR d.name LIKE 't2%';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf FETCH-RATE
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate $1; park-timeout 4000;
               acl-ceiling { 127.0.0.1; }; memory-limit 64m; };
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
issued() { $KCTL dbstatus 2>/dev/null | grep '^fetch:' | sed -n 's/.* issued=\([0-9]*\).*/\1/p' | tail -1; }
oom() { $KCTL dbstatus "$1" 2>/dev/null | grep -q "out of memory"; }       # oom ZONE: its data is out of memory
D() { ./dag @127.0.0.1 -p "$PORT" "$@" 2>/dev/null; }
ans() { D "$1" "$2" +noall +answer +nohexdump | awk '{ print $4 }' | tr '\n' ' '; }       # ans NAME TYPE: the types of the Answer section
addl() { D "$1" "$2" +noall +additional +nohexdump | awk '{ print $4 }' | tr '\n' ' '; }  # the types of the Additional section
wait_res() {   # wait_res ZONE SECONDS: the zone's data is in memory
    i=0; while [ $i -lt $(($2 * 10)) ] && oom "$1"; do sleep 0.1; i=$((i + 1)); done
    ! oom "$1"
}

echo "== a CNAME into a zone that is not in memory"
conf 5000
start_srv
oom target.test && oom prov2.test && pass "target.test and prov2.test start out of memory" || fail "a zone is in memory at the start"
A1=$(ans www.a.test A)
[ "$A1" = "CNAME " ] && pass "www.a.test: the answer is the CNAME alone (the chain stops at the zone that is not in memory)" || fail "www.a.test: '$A1'"
wait_res target.test 10 && pass "target.test was fetched in the background" || fail "target.test is still out of memory"
A2=$(ans www.a.test A)
[ "$A2" = "CNAME A " ] && pass "the next query gets the whole chain (the partial answer was not stored in the response cache)" || fail "www.a.test: '$A2'"
[ "$(ans ext.a.test A)" = "CNAME " ] && pass "a CNAME out of every zone of the view is as before (and asks for nothing)" || fail "ext.a.test: $(ans ext.a.test A)"

echo "== the glue of a name server in a zone that is not in memory"
N1=$(addl ns.test NS)
[ -z "$N1" ] && pass "ns.test NS: no glue (ns1.prov2.test is in prov2.test, which is not in memory)" || fail "ns.test: Additional '$N1'"
wait_res prov2.test 10 && pass "prov2.test was fetched in the background" || fail "prov2.test is still out of memory"
N2=$(addl ns.test NS)
[ "$N2" = "A " ] && pass "the next query has the glue (the answer without it was not stored)" || fail "ns.test: Additional '$N2'"

echo "== one request for a zone, however often the query comes"
oom dt.test && oom dup.test && pass "dup.test and dt.test start out of memory"
D x.dup.test A +short +nohexdump > /dev/null     # (dup.test is read for the query; dt.test is the target)
I0=$(issued)
k=0; while [ $k -lt 60 ]; do D x.dup.test A +short +nohexdump +time=1 +tries=1 > /dev/null; k=$((k + 1)); done
wait_res dt.test 10 && pass "dt.test was fetched" || fail "dt.test is out of memory"
I1=$(issued)
[ "$((I1 - I0))" -le 2 ] && pass "60 queries asked for dt.test at most twice ($((I1 - I0)) fetches)" || fail "$((I1 - I0)) fetches for 60 queries"
stop_srv

echo "== a pattern of queries that chain into $NB zones, fetch-rate 20"
conf 20
start_srv
D c0000.bomb.test A +short +nohexdump > /dev/null
I0=$(issued)
S=$(date +%s)
k=0; WRONG=0
while [ $k -lt $NB ]; do
    r=$(D "$(printf 'c%04d.bomb.test' $k)" A +noall +answer +nohexdump +time=2 +tries=1 | awk '{ print $4 }' | head -1)
    [ "$r" = "CNAME" ] || WRONG=$((WRONG + 1))
    k=$((k + 1))
done
E=$(( $(date +%s) - S ))
sleep 2
I1=$(issued)
echo "  $((I1 - I0)) fetches in $E s for $NB queries ($WRONG not answered with a CNAME)"
[ "$WRONG" -eq 0 ] && pass "every query was answered (the CNAME), whatever happened to the fetches" || fail "$WRONG queries were not answered"
[ "$((I1 - I0))" -le $((20 + 20 * (E + 3))) ] && pass "the rate of fetches held: at most fetch-rate (20 a second) and the burst" || fail "$((I1 - I0)) fetches in $E s"
[ "$((I1 - I0))" -lt $((NB - 20)) ] && pass "not every chain got its zone fetched (requests over the rate were held back)" || fail "no query was held back: $((I1 - I0)) fetches for $NB zones"
$KCTL dbstatus 2>/dev/null | grep -q "refused_by_rate=[1-9]" && pass "the requests over the rate were refused (refused_by_rate)" || fail "refused_by_rate: $($KCTL dbstatus 2>/dev/null | grep '^fetch:')"
[ "$(D www.a.test A +short +nohexdump | head -1)" != "" ] && pass "the server goes on answering" || fail "no answer after the pattern"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

#!/bin/sh
# run_db_fetchconc_test.sh - the fetches in flight (database { fetch-concurrency }) and the loader's pool of fetch workers (D1a), with the real karidns, the real
# karidns-dbloader and SQLite3.
#
#   - dbstatus shows the limit: loader-threads x 16 (at least 16) when fetch-concurrency is not set, the value when it is
#   - fetch-concurrency 2 sheds a burst of queries for zones that are out of memory (the limit is the one in the configuration, not a constant)
#   - the default with loader-threads 4: the same burst sheds nothing, and every answer is the right one (the zones of the workers do not mix on the fetch stream)
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

NZ=300
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
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf "EXTRA database statements"
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate 5000; park-timeout 4000;
               acl-ceiling { 127.0.0.1; }; memory-limit 64m; $1 };
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
shed() { $KCTL dbstatus 2>/dev/null | sed -n 's/.* shed=\([0-9]*\) .*/\1/p' | tail -1; }
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
stop_srv

echo "== the default with loader-threads 4: nothing is shed, the answers are the right ones"
conf "loader-threads 4;"
start_srv
[ "$(conc)" = "64" ] && pass "dbstatus shows concurrency=64" || fail "concurrency: '$(conc)'"
burst "$T/out"
S1=$(shed)
[ "${S1:-0}" = "0" ] && pass "nothing was shed" || fail "shed=$S1"
if cmp -s "$T/out" "$T/expected"; then pass "all $NZ answers are the right ones (the zones of the loader's workers did not mix)"; else fail "wrong or missing answers: $(diff "$T/expected" "$T/out" | head -5 | tr '\n' ' ')"; fi
grep -q "fetch worker\|protocol error" "$T/srv.log" && fail "the log mentions a worker or a protocol error: $(grep 'fetch worker\|protocol error' "$T/srv.log" | head -2)" || pass "no worker or protocol error in the log"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

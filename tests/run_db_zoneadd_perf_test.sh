#!/bin/sh
# run_db_zoneadd_perf_test.sh - T-ZONEADD (beta design 5.3, 9): with 100,000 zones from a SQLite3 database, a zone added to
# the database is served less than 1 s after `karictl reload <zone>` was typed (the answer of karictl arrives, and the zone
# answers at once).  Prints the measured times.  Milestone B6b.
#
# karidns with options { database { } } (SQLite3 filled with sqlite3: one SOA, one NS and one A per zone), the loader run as
# "nobody" with LOADER_THREADS threads (default 4).  Checked: the startup batch loads all zones; the added zone is applied,
# answers, and an unrelated zone keeps answering; a deleted zone is gone after `karictl reload <zone>`; the whole round trip
# of the add stays under LIMIT_MS (default 1000).
#
# ZONES=n changes the number of zones (default 100000).  Needs root; SKIP otherwise, and when karidns, dag, karictl,
# karidns-dbloader (SQLite3 driver), the sqlite3 CLI or perl (Time::HiRes) is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karidns-dbloader; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
perl -MTime::HiRes -e 1 2>/dev/null || { echo "SKIP: perl with Time::HiRes is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

ZONES=${ZONES:-100000}
LIMIT_MS=${LIMIT_MS:-1000}
LOADER_THREADS=${LOADER_THREADS:-4}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbzoneadd.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$((20000 + $$ % 20000))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
now_ms() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000'; }

mkdir "$T/db"
DB="$T/db/z.db"
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$DB" "PRAGMA journal_mode=WAL" > /dev/null
sqlite3 "$DB" < db/karidns_ext.sqlite3.sql
t0=$(now_ms)
sqlite3 "$DB" <<EOF
BEGIN;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $ZONES)
INSERT INTO domains (name, type) SELECT 'zone' || i || '.test', 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'NS', 'ns1.example.test.', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'www.' || name, 'A', '192.0.2.' || (id % 250 + 1), 300, 0, 0 FROM domains;
COMMIT;
EOF
echo "generated $ZONES zones in $(( $(now_ms) - t0 )) ms"
chown -R nobody "$T/db"; chmod 600 "$DB"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$DB"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 30; loader-threads $LOADER_THREADS; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
wait_log() {
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -q -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
ans() { ./dag @127.0.0.1 -p $PORT "$@" +short +nohexdump 2>/dev/null; }

echo "== startup with $ZONES zones (loader-threads $LOADER_THREADS)"
t0=$(now_ms)
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
if wait_log "$T/srv.log" "\[DB\] initial load complete" 300; then pass "the startup batch is complete after $(( $(now_ms) - t0 )) ms"; else fail "no 'initial load complete' line"; tail -5 "$T/srv.log" | sed 's/^/         /'; fi
[ "$(ans www.zone77.test A)" = "192.0.2.78" ] && pass "www.zone77.test answers" || fail "www.zone77.test: '$(ans www.zone77.test A)'"

echo "== T-ZONEADD: one zone added, karictl reload <zone>"
sqlite3 "$DB" <<EOF
INSERT INTO domains (name, type) VALUES ('added.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 7 3600 600 86400 300', 300, 0, 0 FROM domains WHERE name = 'added.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.example.test.', 300, 0, 0 FROM domains WHERE name = 'added.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.99', 300, 0, 0 FROM domains WHERE name = 'added.test';
EOF
t0=$(now_ms)
OUT=$($KCTL reload added.test 2>&1); RC=$?
t1=$(now_ms)
A=$(ans www.added.test A)
t2=$(now_ms)
printf '%s\n' "$OUT" | grep -q "^OK zone added.test. (view [_a-z]*): applied, serial 7$" && [ $RC -eq 0 ] && pass "karictl: $OUT" || fail "reload added.test: rc $RC '$OUT'"
[ "$A" = "192.0.2.99" ] && pass "www.added.test answers 192.0.2.99" || fail "www.added.test: '$A'"
echo "T-ZONEADD: karictl answered after $((t1 - t0)) ms, the zone answered after $((t2 - t0)) ms (limit $LIMIT_MS ms)"
[ $((t2 - t0)) -lt "$LIMIT_MS" ] && pass "added zone served $((t2 - t0)) ms after the command (< $LIMIT_MS ms)" || fail "added zone served only $((t2 - t0)) ms after the command"
[ "$(ans www.zone500.test A)" = "192.0.2.1" ] && pass "an unrelated zone keeps answering" || fail "www.zone500.test: '$(ans www.zone500.test A)'"

echo "== a second add and a delete"
sqlite3 "$DB" "UPDATE records SET content = '192.0.2.100' WHERE name = 'www.added.test'"
t0=$(now_ms)
OUT=$($KCTL reload added.test 2>&1)
A=$(ans www.added.test A)
t2=$(now_ms)
[ "$A" = "192.0.2.100" ] && pass "an edit of the zone is served $((t2 - t0)) ms after the command" || fail "edit: '$A' ($OUT)"
sqlite3 "$DB" "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'zone9.test'); DELETE FROM domains WHERE name = 'zone9.test'"
t0=$(now_ms)
OUT=$($KCTL reload zone9.test 2>&1)
t2=$(now_ms)
printf '%s\n' "$OUT" | grep -q "^OK zone zone9.test. (view [_a-z]*): deleted" && pass "delete: $OUT ($((t2 - t0)) ms)" || fail "delete: '$OUT'"
./dag @127.0.0.1 -p $PORT www.zone9.test A +nohexdump 2>/dev/null | grep -q "status: REFUSED" && pass "the deleted zone is gone" || fail "zone9.test still answers"

kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2>/dev/null && fail "karidns did not stop" || pass "karidns stopped"
SRV=""

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_zoneadd_perf_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_zoneadd_perf_test: $FAILS check(s) FAILED ($PASS passed) ==="
tail -40 "$T/srv.log" 2>/dev/null
exit 1

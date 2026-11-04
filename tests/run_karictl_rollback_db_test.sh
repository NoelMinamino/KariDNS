#!/bin/sh
# run_karictl_rollback_db_test.sh - karictl rollback for a zone served from a SQLite3 database (karidns-dbloader).
#
#   - a database install fills the previous version (the first load does not); `rollback` publishes it again with serial
#     = the served serial + 1, `zonestatus` / `dbstatus <zone>` say so;
#   - the rollback stays until the data in the database change: `reload <zone>` finds the content equal ("unchanged"), a full
#     `reload`, and a restart of the loader (it reconciles against the Backend's inventory) leave the old data served;
#   - the next change in the database is installed normally and ends the rolled-back state;
#   - a second rollback is refused; `reload <zone> force` sends the database's data again (the data that were rolled back).
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned).  SKIP otherwise, and when
# karidns, dag, karictl, karidns-dbloader (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbrollback.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
DAG="./dag @127.0.0.1 -p $PORT"
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db" "$T/z"
cat > "$T/z/db1.test.zone" <<'EOF'
$ORIGIN db1.test.
$TTL 300
@ SOA ns1.db1.test. host.db1.test. 10 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.10
EOF
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
./tests/db/zone2sql --dialect sqlite3 "$T/z/db1.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
sq() { sqlite3 "$T/db/z.db" "$@"; }
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
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 4; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
www() { $DAG www.db1.test A +short +nohexdump 2>/dev/null; }
serial() { $DAG db1.test SOA +short +nohexdump 2>/dev/null | awk '{print $3}'; }
check() {   # check DESCRIPTION WWW SERIAL
    [ "$(www)" = "$2" ] && [ "$(serial)" = "$3" ] && pass "$1 (www $2, serial $3)" || fail "$1 (got www '$(www)' serial '$(serial)', want $2 / $3)"
}

echo "== startup"
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
kari_wait_log "$T/srv.log" "\[DB\] initial load complete" 20 && pass "the startup batch is complete" || { fail "no initial load"; tail -10 "$T/srv.log"; }
check "the database zone" 192.0.2.10 10
OUT=$($KCTL rollback db1.test 2>&1); RC=$?
[ $RC -eq 3 ] && printf '%s\n' "$OUT" | grep -q '^ERROR no previous version' && pass "the first load kept nothing: $OUT" || fail "rollback before a change: rc $RC '$OUT'"

echo "== a change in the database, installed by reload <zone>"
sq "UPDATE records SET content = replace(content, ' 10 3600', ' 11 3600') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = 'db1.test')"
sq "UPDATE records SET content = '192.0.2.66' WHERE name = 'www.db1.test'"
OUT=$($KCTL reload db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'applied, serial 11$' && pass "applied: $OUT" || fail "reload db1.test: '$OUT'"
check "the new data" 192.0.2.66 11
OUT=$($KCTL zonestatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'source=database' && printf '%s\n' "$OUT" | grep -q 'previous version kept (serial 10,' && pass "zonestatus shows the previous version" || fail "zonestatus: $OUT"
OUT=$($KCTL dbstatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'previous version kept for rollback: serial 10,' && pass "dbstatus <zone> shows it too" || fail "dbstatus: $OUT"
OUT=$($KCTL dbstatus 2>&1)
printf '%s\n' "$OUT" | grep -q '^zone versions kept for karictl rollback (rollback-window): database zones [1-9][0-9]* bytes' && pass "dbstatus counts the bytes kept" || fail "dbstatus bytes: $(printf '%s\n' "$OUT" | grep -i rollback)"
OUT=$($KCTL status 2>&1)
printf '%s\n' "$OUT" | grep -q '^zone versions kept for rollback: database zones [1-9][0-9]* bytes' && pass "status counts the bytes kept" || fail "status bytes"

echo "== rollback"
OUT=$($KCTL rollback db1.test 2>&1); RC=$?
[ $RC -eq 0 ] && [ "$OUT" = "OK rolled back: serial 12 (was 11)" ] && pass "$OUT" || fail "rollback: rc $RC '$OUT'"
check "the old data, serial 12" 192.0.2.10 12
OUT=$($KCTL zonestatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'serial=12 ' && printf '%s\n' "$OUT" | grep -q 'rolled back (serial 12, from 11)' && pass "zonestatus: $OUT" || fail "zonestatus: $OUT"
OUT=$($KCTL dbstatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'rolled back: serial 12, from 11; pinned in memory' && pass "dbstatus <zone> says rolled back and pinned" || fail "dbstatus: $OUT"
OUT=$($KCTL rollback db1.test 2>&1); RC=$?
[ $RC -eq 3 ] && printf '%s\n' "$OUT" | grep -q '^ERROR no previous version' && pass "a second rollback is refused" || fail "second rollback: rc $RC '$OUT'"

echo "== it stays until the data in the database change"
OUT=$($KCTL reload db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'unchanged, serial 12$' && pass "reload <zone>: $OUT" || fail "reload db1.test: '$OUT'"
check "still the old data" 192.0.2.10 12
$KCTL reload > /dev/null 2>&1
sleep 3
check "after a full reload" 192.0.2.10 12
LP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1)
if [ -n "$LP" ]; then
    kill -9 "$LP"
    sleep 4
    check "after the loader restarted and reconciled" 192.0.2.10 12
else
    fail "no loader process to restart"
fi
OUT=$($KCTL zonestatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'rolled back (serial 12, from 11)' && pass "still marked as rolled back" || fail "zonestatus after the loader restart: $OUT"

echo "== force sends the database's data again; the next change is installed normally"
OUT=$($KCTL reload db1.test force 2>&1)
printf '%s\n' "$OUT" | grep -q 'applied, serial 11$' && pass "force: $OUT" || fail "reload force: '$OUT'"
check "the data that were rolled back are served again" 192.0.2.66 11
OUT=$($KCTL zonestatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'rolled back' && fail "still rolled back after the install: $OUT" || pass "the install ended the rolled-back state"
sq "UPDATE records SET content = replace(content, ' 11 3600', ' 12 3600') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = 'db1.test')"
sq "UPDATE records SET content = '192.0.2.10' WHERE name = 'www.db1.test'"
OUT=$($KCTL reload db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'applied, serial 12$' && pass "the fixed data: $OUT" || fail "reload fixed: '$OUT'"
check "the fixed data are served" 192.0.2.10 12
kill -0 "$SRV" 2>/dev/null && pass "the server runs" || fail "the server is gone"

echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ] && { echo "[+] karictl rollback (database zone) tests passed."; exit 0; }
exit 1

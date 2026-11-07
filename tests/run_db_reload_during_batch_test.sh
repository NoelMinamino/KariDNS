#!/bin/sh
# run_db_reload_during_batch_test.sh - a reload of karidns.conf that renumbers the views while a batch is running
# (review db_ingest [1]).
#
# CONFIG numbers the views by their position in karidns.conf, and ZONE_BEGIN names its view by that number.  The loader
# adopts a new CONFIG only between two batches, so the zones still to come in a running batch carry the numbers of the
# old one.  The Backend used to rebuild its table of view numbers as soon as it sent the new CONFIG: a reconfig that
# swaps two views during a batch put the rest of the batch into the other view.  Now the CONFIG is sent when the batch
# ends (before BATCH_RESULT, so that the loader has it before its next batch).
#   - view "a" (127.0.0.2) reads a.db with 30000 zones, view "b" (127.0.0.3) reads b.db with one zone;
#   - right after the start (the startup batch is running) karidns.conf is rewritten with b before a and `karictl reconfig`;
#   - the log says that the CONFIG waited for the end of the batch;
#   - the last zone of a.db is in view a only, and answers there; b.db's zone is in view b only.
#
# Needs root (the server starts as root and drops to nobody; loopback aliases 127.0.0.2-3 are added and removed).  SKIP
# otherwise, and when karidns, dag, karictl, karidns-dbloader (SQLite3 driver) or the sqlite3 CLI is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user, loopback aliases)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karidns-dbloader; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbrdb.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
ADDED=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

for ip in 127.0.0.2 127.0.0.3; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else echo "SKIP: cannot add the loopback alias $ip"; exit 0; fi
done

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
NZ=30000

mkdir "$T/db"
A="$T/db/a.db"; B="$T/db/b.db"
for f in "$A" "$B"; do
    sqlite3 "$f" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    sqlite3 "$f" "PRAGMA journal_mode=WAL" > /dev/null
done
sqlite3 "$A" "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $NZ)
INSERT INTO domains (name, type) SELECT 'za' || i || '.test', 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.1', 300, 0, 0 FROM domains;"
sqlite3 "$B" "INSERT INTO domains (name, type) VALUES ('bonly.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.bonly.test host.bonly.test 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.bonly.test', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.bonly.test', 'A', '192.0.2.2', 300, 0, 0 FROM domains;"
chown -R nobody "$T/db"; chmod 600 "$T/db"/*.db*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf FILE ORDER ("ab" or "ba")
    {
        cat <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$A"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 30; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
        va="view \"a\" { match-clients { 127.0.0.2; }; database-file \"$A\"; };"
        vb="view \"b\" { match-clients { 127.0.0.3; }; database-file \"$B\"; };"
        if [ "$2" = ab ]; then echo "$va"; echo "$vb"; else echo "$vb"; echo "$va"; fi
    } > "$1"
}
q() { ./dag @127.0.0.1 -p $PORT -b "$1" "$2" A +short +nohexdump 2>/dev/null; }
status_of() { ./dag @127.0.0.1 -p $PORT -b "$1" "$2" A +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
views_of() { $KCTL dbstatus "$1" 2>&1 | sed -n "s/^zone [^ ]* view \([^:]*\): .*/\1/p" | sort | tr '\n' ' ' | sed 's/ $//'; }

echo "== start with views a, b; swap them while the startup batch runs"
conf "$T/k.conf" ab
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
i=0
while [ $i -lt 100 ] && ! grep -q "\[DB\] loader connected" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
grep -q "\[DB\] loader connected" "$T/srv.log" && pass "the loader connected" || fail "the loader did not connect"
conf "$T/k.conf" ba
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig: $OUT" || fail "reconfig: '$OUT'"
if kari_wait_log "$T/srv.log" "\[DB\] initial load complete" 120; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; tail -20 "$T/srv.log" | sed 's/^/         /'; fi
cfg_line=$(grep -n "sent CONFIG generation .* (configuration reloaded)" "$T/srv.log" | head -1 | cut -d: -f1)
done_line=$(grep -n "\[DB\] batch 1 complete" "$T/srv.log" | head -1 | cut -d: -f1)
if grep -q "sent CONFIG generation .* (configuration reloaded during the batch)" "$T/srv.log"; then
    pass "the CONFIG of the reconfig waited for the end of the batch"
elif [ -n "$cfg_line" ] && [ -n "$done_line" ] && [ "$cfg_line" -lt "$done_line" ]; then
    fail "the CONFIG of the reconfig was sent during the batch (log line $cfg_line, batch end $done_line)"
else
    echo "  [INFO] the reconfig did not come during the batch (the batch was too short): the placement checks still run"
fi
# the loader reads the swapped views after the batch (the sources of the views moved): wait until it is quiet
sleep 3
kari_wait_log "$T/srv.log" "Backend result for batch" 60 2 >/dev/null 2>&1 || true
sleep 2

echo "== every zone in its own view"
LAST="za$NZ.test"
v=$(views_of "$LAST")
[ "$v" = "a" ] && pass "$LAST is in view a only" || fail "$LAST is in the views '$v', wanted 'a'"
v=$(views_of bonly.test)
[ "$v" = "b" ] && pass "bonly.test is in view b only" || fail "bonly.test is in the views '$v', wanted 'b'"
[ "$(q 127.0.0.2 "www.$LAST")" = "192.0.2.1" ] && pass "view a answers www.$LAST" || fail "view a: www.$LAST"
[ "$(status_of 127.0.0.3 "www.$LAST")" = "REFUSED" ] && pass "view b does not have $LAST" || fail "view b: www.$LAST is '$(status_of 127.0.0.3 "www.$LAST")'"
[ "$(q 127.0.0.3 www.bonly.test)" = "192.0.2.2" ] && pass "view b answers www.bonly.test" || fail "view b: www.bonly.test"
[ "$(status_of 127.0.0.2 www.bonly.test)" = "REFUSED" ] && pass "view a does not have bonly.test" || fail "view a: www.bonly.test is '$(status_of 127.0.0.2 www.bonly.test)'"
n=$($KCTL dbstatus 2>&1 | sed -n 's/^view b: .*zones=\([0-9]*\).*/\1/p' | head -1)
echo "  [INFO] dbstatus view b zones: ${n:-?}"

echo "== result: $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ] || { echo "--- server log (tail)"; tail -30 "$T/srv.log" | sed 's/^/    /'; exit 1; }
exit 0

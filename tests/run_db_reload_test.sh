#!/bin/sh
# run_db_reload_test.sh - diff reload, `karictl reload <zone> [force]`, D17-1 and D17-2 for zones served from a SQLite3
# database (beta design 5.1, 5.2, 4.5, 8.4; milestone B6a).
#
# karidns with options { database { } } (SQLite3 made with tests/db/zone2sql, PLUS db/karidns_ext.sqlite3.sql so that every
# edit is in the change log), the loader run as "nobody".  Checked:
#   - the startup batch sends every zone; `karictl reload` (all) answers at once ("DB reload requested (request N)") and
#     the loader sends only what changed: a serial change, an edit that keeps the serial (found through the change log),
#     nothing at all when nothing changed;
#   - `karictl reload <zone>` for a database zone: a zone just added to the database is found by name and answered
#     "applied" within a second; a deleted one "deleted"; the same content "unchanged"; `force` sends it again; a zone
#     the database does not have: "zone not found"; a zone with a bad row: "failed: reason", the last good version keeps
#     serving, and the next reload of the fixed zone is applied; zonestatus / notify / retransfer find database zones;
#   - a zone deleted from the database goes away with the next `karictl reload` (all) (ZONE_DELETE);
#   - a loader restart does not resend zones the Backend has (and sends the one that changed while the loader was down);
#   - the control thread never waits for the loader: with the loader stopped (SIGSTOP) `reload <zone>` stays parked while
#     status and zonestatus answer at once, the parked client gets its answer when the loader runs again, a client times
#     out after db-reload-timeout, and above 32 parked clients the next ones are refused;
#   - D-PRIO: a zone of karidns.conf hides the database zone of the same name; the reload of that name reads the file zone;
#   - D17-1: a catalog member with the name of a database zone wins (the database zone is hidden, in dbstatus and in the
#     answers), comes back when the member goes away, and a database zone that arrives behind an existing member is hidden;
#   - karictl --help lists the reload syntax and its examples run.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned).  SKIP otherwise, and when
# karidns, dag, karictl, karidns-dbloader (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.
# BULK=n sets bulk-threshold (default 25; 0 = every diff reads all records in one scan, 100 = one query per zone); the answers
# must not depend on it.  LOADER_THREADS=n sets loader-threads (default 1; B6b); the answers and the batch counts are the same.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karicheck ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbreload.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    LP2=$(pgrep -P "${SRV:-0}" -f 'karidns-dbloader -s 3' 2>/dev/null | head -1)
    [ -n "$LP2" ] && kill -CONT "$LP2" 2>/dev/null
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
DAG="./dag @127.0.0.1 -p $PORT"
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

# ---------------------------------------------------------------- fixtures
mkdir "$T/db" "$T/z"
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
EOF
}
mkzone db1.test 10 192.0.2.10
mkzone db2.test 20 192.0.2.20
mkzone db3.test 30 192.0.2.30
mkzone db5.test 50 192.0.2.50
mkzone db7.test 70 192.0.2.70
mkzone db4.test 40 192.0.2.40
mkzone db6.test 60 192.0.2.60
mkzone example.test 1 192.0.2.99
cat > "$T/file.zone" <<'EOF'
$TTL 300
@ SOA ns host 1 2 3 4 5
@ NS ns
ns A 192.0.2.1
www A 192.0.2.80
EOF
cat > "$T/db5_file.zone" <<'EOF'
$ORIGIN db5.test.
$TTL 300
@ SOA ns1.db5.test. host.db5.test. 99 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.55
EOF
cat > "$T/catalog.zone" <<'EOF'
$ORIGIN catalog.test.
$TTL 300
@ SOA invalid. invalid. 1 3600 600 86400 300
@ NS invalid.
version TXT "2"
EOF
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
for z in db1 db2 db3 db5 db7; do
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/$z.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
done
add_zone() { ./tests/db/zone2sql --dialect sqlite3 "$T/z/$1.zone" 2>/dev/null | sqlite3 "$T/db/z.db"; }
NZ=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM domains")
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
sq() { sqlite3 "$T/db/z.db" "$@"; }
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf FILE
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 4; bulk-threshold ${BULK:-25}; loader-threads ${LOADER_THREADS:-1}; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
zone "file.test" { type primary; file "$T/file.zone"; };
zone "db5.test" { type primary; file "$T/db5_file.zone"; };
zone "catalog.test" { type primary; file "$T/catalog.zone"; catalog-zone yes; };
EOF
}
wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
loader_pid() { pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1; }
ans() { $DAG "$@" +short +nohexdump 2>/dev/null; }
check_ans() {   # check_ans DESCRIPTION EXPECTED QNAME QTYPE
    got=$(ans "$3" "$4")
    [ "$got" = "$2" ] && pass "$1" || fail "$1 (got '$got', want '$2')"
}
dbst() { $KCTL dbstatus "$@" 2>&1; }
BN=0                              # batches the loader process has sent so far
next_batch() { BN=$((BN + 1)); }
wait_batch() {   # wait_batch DESCRIPTION: the loader sent batch $BN and got the Backend's result
    wait_log "$T/srv.log" "Backend result for batch $BN:" 15 && pass "$1: batch $BN done" || { fail "$1: no result for batch $BN"; tail -5 "$T/srv.log" | sed 's/^/         /'; }
}
batch_line() { grep "karidns-dbloader.* batch $BN (" "$T/srv.log" | tail -1 | sed 's/.* batch /batch /'; }
expect_batch() {   # expect_batch DESCRIPTION READ SENT FAILED DELETED UNCHANGED
    l=$(batch_line)
    case "$l" in
    *"sent: $2 zone(s) read, $3 sent, $4 failed in the loader, $5 deleted, $6 unchanged"*) pass "$1: $2 read, $3 sent, $4 failed, $5 deleted, $6 unchanged" ;;
    *) fail "$1: '$l' (wanted $2 read, $3 sent, $4 failed, $5 deleted, $6 unchanged)" ;;
    esac
}
now_s() { date +%s; }

# ================================================================ start
echo "== startup"
conf "$T/k.conf"
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
if wait_log "$T/srv.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$T/srv.log" | tail -20; fi
next_batch
wait_batch "startup"
expect_batch "startup" $NZ $NZ 0 0 0
grep -q "batch 1 (startup) sent" "$T/srv.log" && pass "the first batch is the startup batch" || fail "startup batch name"
check_ans "www.db1.test A" "192.0.2.10" www.db1.test A
check_ans "www.db5.test A is the configured zone's (D-PRIO)" "192.0.2.55" www.db5.test A
dbst db5.test | grep -q "status shadowed (hidden by a zone in karidns.conf)" && pass "dbstatus db5.test: hidden by a zone in karidns.conf" || { fail "dbstatus db5.test"; dbst db5.test | sed 's/^/         /'; }

# ================================================================ reload (all)
echo "== reload (all): serial change, edit without a serial bump, nothing"
sq "UPDATE records SET content = replace(content, ' 10 3600', ' 11 3600') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = 'db1.test')"
sq "UPDATE records SET content = '192.0.2.11' WHERE name = 'www.db1.test'"
OUT=$($KCTL reload 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK reloaded; DB reload requested (request [0-9][0-9]*)$" && [ $RC -eq 0 ] && pass "reload (all) answers at once: $OUT" || fail "reload (all): rc $RC '$OUT'"
next_batch
wait_batch "serial change"
expect_batch "serial change" 1 1 0 0 $((NZ - 1))
grep -q "karidns-dbloader.* batch $BN (diff) sent" "$T/srv.log" && pass "the batch is a diff batch" || fail "batch kind"
grep -q "batch $BN (diff) sent.*(answers a request)" "$T/srv.log" && pass "the batch answers the request of karictl" || fail "no request marker on the batch"
check_ans "www.db1.test A has the new address" "192.0.2.11" www.db1.test A
dbst db1.test | grep -q "serial 11, status applied" && pass "dbstatus db1.test: serial 11" || fail "dbstatus db1.test serial 11"

sq "UPDATE records SET content = '192.0.2.21' WHERE name = 'www.db2.test'"
$KCTL reload > /dev/null 2>&1
next_batch
wait_batch "edit without a serial bump"
expect_batch "edit without a serial bump (change log)" 1 1 0 0 $((NZ - 1))
check_ans "www.db2.test A has the new address, the serial is still 20" "192.0.2.21" www.db2.test A
dbst db2.test | grep -q "serial 20, status applied" && pass "dbstatus db2.test: serial 20" || fail "dbstatus db2.test"

$KCTL reload > /dev/null 2>&1
next_batch
wait_batch "nothing changed"
expect_batch "nothing changed" 0 0 0 0 $NZ

# ================================================================ reload <zone>
echo "== reload <zone>: add, unchanged, force, not found, delete"
add_zone db4.test
T0=$(now_s)
OUT=$($KCTL reload db4.test 2>&1); RC=$?
T1=$(now_s)
next_batch
printf '%s\n' "$OUT" | grep -q "^OK zone db4.test. (view [_a-z]*): applied, serial 40$" && [ $RC -eq 0 ] && pass "a zone just added to the database: $OUT" || fail "reload db4.test: rc $RC '$OUT'"
[ $((T1 - T0)) -le 2 ] && pass "answered within $((T1 - T0)) s" || fail "reload db4.test took $((T1 - T0)) s"
wait_batch "one-zone reload"
expect_batch "one-zone reload (db4)" 1 1 0 0 0
grep -q "batch $BN (zone) sent" "$T/srv.log" && pass "the batch is a zone batch" || fail "zone batch name"
check_ans "www.db4.test A" "192.0.2.40" www.db4.test A
dbst db4.test | grep -q "serial 40, status applied" && pass "dbstatus db4.test" || fail "dbstatus db4.test"
OUT=$($KCTL zonestatus db4.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK serial=40 refresh=3600 source=database view=[_a-z]* id=[0-9][0-9]* result=applied$" && pass "zonestatus of a database zone: $OUT" || fail "zonestatus db4.test: '$OUT'"
OUT=$($KCTL notify db4.test 2>&1); [ "$OUT" = "OK" ] && pass "notify of a database zone" || fail "notify db4.test: '$OUT'"
OUT=$($KCTL retransfer db4.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone is a primary zone from the database; read it again with 'karictl reload <zone>'$" && [ $RC -eq 3 ] && pass "retransfer of a database zone is refused and names reload" || fail "retransfer db4.test: rc $RC '$OUT'"

OUT=$($KCTL reload db4.test 2>&1); RC=$?
next_batch
printf '%s\n' "$OUT" | grep -q "^OK zone db4.test. (view [_a-z]*): unchanged, serial 40$" && [ $RC -eq 0 ] && pass "same content: $OUT" || fail "reload db4.test again: rc $RC '$OUT'"
wait_batch "unchanged"
expect_batch "unchanged zone" 1 0 0 0 1
OUT=$($KCTL reload db4.test force 2>&1); RC=$?
next_batch
printf '%s\n' "$OUT" | grep -q "^OK zone db4.test. (view [_a-z]*): applied, serial 40$" && [ $RC -eq 0 ] && pass "force sends it again: $OUT" || fail "reload db4.test force: rc $RC '$OUT'"
wait_batch "force"
expect_batch "force" 1 1 0 0 0
sq "UPDATE records SET content = '192.0.2.41' WHERE name = 'www.db4.test'"
OUT=$($KCTL reload db4.test 2>&1)
next_batch
printf '%s\n' "$OUT" | grep -q "applied, serial 40$" && pass "an edit that keeps the serial is applied by reload <zone>: $OUT" || fail "edit of db4: '$OUT'"
check_ans "www.db4.test A has the new address" "192.0.2.41" www.db4.test A

OUT=$($KCTL reload nothere.test 2>&1); RC=$?
next_batch
printf '%s\n' "$OUT" | grep -q "^ERROR zone not found" && [ $RC -eq 3 ] && pass "a zone the database does not have: $OUT" || fail "reload nothere.test: rc $RC '$OUT'"
OUT=$($KCTL notify nothere.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone not found$" && [ $RC -eq 3 ] && pass "notify of an unknown zone" || fail "notify nothere.test: rc $RC '$OUT'"
OUT=$($KCTL reload db4.test nosuchview 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone not found (view 'nosuchview' does not exist)$" && [ $RC -eq 3 ] && pass "an unknown view is named" || fail "unknown view: rc $RC '$OUT'"

sq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'db4.test'); DELETE FROM domains WHERE name = 'db4.test'"
OUT=$($KCTL reload db4.test 2>&1); RC=$?
next_batch
printf '%s\n' "$OUT" | grep -q "^OK zone db4.test. (view [_a-z]*): deleted (it is no longer in the database)$" && [ $RC -eq 0 ] && pass "a zone deleted from the database: $OUT" || fail "delete of db4: rc $RC '$OUT'"
wait_batch "delete"
expect_batch "delete" 0 0 0 1 0
$DAG www.db4.test A +nohexdump 2>/dev/null | grep -q "status: REFUSED" && pass "the deleted zone is gone (REFUSED)" || fail "db4.test still answers"
dbst db4.test | grep -q "not in the database registry" && pass "dbstatus: db4.test left the registry" || fail "dbstatus after the delete"

echo "== reload (all) removes a zone deleted from the database"
sq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'db7.test'); DELETE FROM domains WHERE name = 'db7.test'"
check_ans "db7.test still answers before the reload" "192.0.2.70" www.db7.test A
$KCTL reload > /dev/null 2>&1
next_batch
wait_batch "delete by reload (all)"
expect_batch "delete by reload (all)" 0 0 0 1 $((NZ - 1))
$DAG www.db7.test A +nohexdump 2>/dev/null | grep -q "status: REFUSED" && pass "db7.test is gone after reload (all)" || fail "db7.test still answers"

# ================================================================ a bad row
echo "== a bad row: the last good version keeps serving, the fixed zone is applied"
sq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES ((SELECT id FROM domains WHERE name = 'db2.test'), 'bad.db2.test', 'A', 'not.an.ip', 300, 0, 0)"
OUT=$($KCTL reload db2.test 2>&1); RC=$?
next_batch
printf '%s\n' "$OUT" | grep -q "^ERROR zone db2.test. (view [_a-z]*): failed: .*invalid IPv4" && [ $RC -eq 3 ] && pass "reload of a zone with a bad row: $OUT" || fail "bad row: rc $RC '$OUT'"
check_ans "www.db2.test A still answers (the last good version)" "192.0.2.21" www.db2.test A
dbst db2.test | grep -q "status rejected (serving the last good version, serial 20), last error: " && pass "dbstatus db2.test: rejected, serving serial 20, with the reason" || { fail "dbstatus db2.test"; dbst db2.test | sed 's/^/         /'; }
$KCTL reload > /dev/null 2>&1
next_batch
wait_batch "reload (all) with the bad row"
l=$(batch_line)
case "$l" in *"1 failed in the loader"*) pass "reload (all) offers the broken zone again and reports it" ;; *) fail "reload (all) with a bad row: '$l'" ;; esac
sq "DELETE FROM records WHERE name = 'bad.db2.test'"
OUT=$($KCTL reload db2.test 2>&1); RC=$?
next_batch
printf '%s\n' "$OUT" | grep -q "^OK zone db2.test. (view [_a-z]*): applied, serial 20$" && [ $RC -eq 0 ] && pass "the fixed zone is applied again (the data are the old ones: the error still clears): $OUT" || fail "fixed db2: rc $RC '$OUT'"
dbst db2.test | grep -q "serial 20, status applied$" && pass "dbstatus db2.test: applied, no error" || fail "dbstatus db2.test after the fix"

# ================================================================ D-PRIO
echo "== D-PRIO: a zone of karidns.conf with the name of a database zone"
OUT=$($KCTL reload db5.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK reloaded$" && pass "reload db5.test reads the file zone of karidns.conf: $OUT" || fail "reload db5.test: '$OUT'"
OUT=$($KCTL zonestatus db5.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK serial=99 refresh=3600$" && pass "zonestatus db5.test is the file zone's" || fail "zonestatus db5.test: '$OUT'"

# ================================================================ D17-1: catalog members win
echo "== D17-1: a catalog member with the name of a database zone wins"
add_catalog_members() {   # add_catalog_members NAME...  (the catalog zone gets a higher serial and one PTR per name)
    SERIAL=$((SERIAL + 1))
    {
        printf '$ORIGIN catalog.test.\n$TTL 300\n@ SOA invalid. invalid. %s 3600 600 86400 300\n@ NS invalid.\nversion TXT "2"\n' "$SERIAL"
        n=0
        for m in "$@"; do n=$((n + 1)); printf 'm%s.zones PTR %s.\n' "$n" "$m"; done
    } > "$T/catalog.zone"
}
SERIAL=1
add_catalog_members db3.test db6.test
OUT=$($KCTL reload catalog.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK reloaded$" && pass "the catalog zone was reloaded with two members" || fail "reload catalog.test: '$OUT'"
wait_log "$T/srv.log" "zone db3.test. from the DB is hidden by a catalog member of the same name" 10 && pass "log: db3.test is hidden by the catalog member" || { fail "no 'hidden by a catalog member' line"; grep -i "catalog" "$T/srv.log" | tail -5 | sed 's/^/         /'; }
dbst db3.test | grep -q "status shadowed (hidden by a catalog member)" && pass "dbstatus db3.test: hidden by a catalog member" || { fail "dbstatus db3.test"; dbst db3.test | sed 's/^/         /'; }
dbst | grep -q "hidden by catalog members" && pass "dbstatus summary counts it" || { fail "dbstatus summary"; dbst | sed 's/^/         /' | head -4; }
[ "$(ans www.db3.test A)" != "192.0.2.30" ] && pass "www.db3.test no longer answers from the database" || fail "the database zone still answers behind the catalog member"
check_ans "the other database zones are not affected" "192.0.2.11" www.db1.test A
# a database zone that arrives behind an existing member (db6.test is a member, not in the database yet)
add_zone db6.test
OUT=$($KCTL reload db6.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone db6.test. (view [_a-z]*): loaded, serial 60, but hidden by a catalog member of the same name$" && pass "a new database zone behind a member: $OUT" || fail "reload db6.test: rc $RC '$OUT'"
[ "$(ans www.db6.test A)" != "192.0.2.60" ] && pass "www.db6.test does not answer from the database" || fail "db6.test answers from the database"
# the member of db3 goes away: the database zone comes back
add_catalog_members db6.test
OUT=$($KCTL reload catalog.test 2>&1)
wait_log "$T/srv.log" "zone db3.test. (view '[_a-z]*') is served from the DB again: the catalog member is gone" 10 && pass "log: db3.test is served from the DB again" || fail "no 'served from the DB again' line"
check_ans "www.db3.test A answers from the database again" "192.0.2.30" www.db3.test A
dbst db3.test | grep -q "serial 30, status applied" && pass "dbstatus db3.test: applied again" || fail "dbstatus db3.test after the member left"
add_catalog_members
OUT=$($KCTL reload catalog.test 2>&1)
wait_log "$T/srv.log" "zone db6.test. (view '[_a-z]*') is served from the DB again: the catalog member is gone" 10 && pass "log: db6.test is served from the DB again" || fail "no 'served from the DB again' line for db6"
check_ans "www.db6.test A answers from the database again" "192.0.2.60" www.db6.test A
# a full reconfiguration lets the member win too (4.5): reconfig with the member present
add_catalog_members db3.test
$KCTL reload catalog.test > /dev/null 2>&1
wait_log "$T/srv.log" "zone db3.test. from the DB is hidden by a catalog member of the same name" 10 2 && pass "hidden again" || fail "db3.test not hidden the second time"
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig with the member present: $OUT" || fail "reconfig: '$OUT'"
dbst db3.test | grep -q "status shadowed (hidden by a catalog member)" && pass "still hidden after reconfig" || fail "dbstatus db3.test after reconfig"
add_catalog_members
$KCTL reload catalog.test > /dev/null 2>&1
wait_log "$T/srv.log" "zone db3.test. (view '[_a-z]*') is served from the DB again: the catalog member is gone" 10 2 && pass "back again" || fail "db3.test did not come back"

# ================================================================ loader restart
echo "== loader restart: nothing is sent again; a change made while the loader was down is"
LP=$(loader_pid)
kill -9 "$LP"
sq "UPDATE records SET content = '192.0.2.12' WHERE name = 'www.db1.test'"
i=0; P2=""
while [ $i -lt 100 ]; do P2=$(loader_pid); [ -n "$P2" ] && [ "$P2" != "$LP" ] && break; P2=""; sleep 0.1; i=$((i + 1)); done
[ -n "$P2" ] && pass "the loader was restarted (pid $P2)" || fail "no restarted loader"
BN=1
NDB=$(sq "SELECT count(*) FROM domains")
wait_log "$T/srv.log" "Backend result for batch 1:" 15 2 && pass "the restarted loader's startup batch is done" || fail "no result for the restarted loader's batch"
expect_batch "restart (db1 changed while the loader was down)" $NDB 1 0 0 $((NDB - 1))
check_ans "www.db1.test A has the address written while the loader was down" "192.0.2.12" www.db1.test A
kill -9 "$P2"
i=0; P3=""
while [ $i -lt 100 ]; do P3=$(loader_pid); [ -n "$P3" ] && [ "$P3" != "$P2" ] && break; P3=""; sleep 0.1; i=$((i + 1)); done
BN=1
wait_log "$T/srv.log" "Backend result for batch 1:" 15 3 && pass "second restart: batch done" || fail "second restart: no result"
l=$(grep "karidns-dbloader.* batch 1 (startup) sent" "$T/srv.log" | tail -1)
case "$l" in *"$NDB zone(s) read, 0 sent, 0 failed in the loader, 0 deleted, $NDB unchanged"*) pass "second restart: $NDB zones read, none sent" ;; *) fail "second restart: '$l'" ;; esac

# ================================================================ the control thread never waits for the loader
echo "== the control thread does not wait for the loader"
LP=$(loader_pid)
kill -STOP "$LP"
$KCTL reload db1.test > "$T/parked.out" 2>&1 &
PK=$!
sleep 1
T0=$(now_s)
OUT=$($KCTL zonestatus db1.test 2>&1)
OUT2=$($KCTL status 2>&1 | head -1)
T1=$(now_s)
printf '%s\n' "$OUT" | grep -q "^OK serial=" && pass "zonestatus answers while a reload is parked" || fail "zonestatus while parked: '$OUT'"
[ -n "$OUT2" ] && pass "status answers while a reload is parked" || fail "status while parked"
[ $((T1 - T0)) -le 1 ] && pass "both answered within $((T1 - T0)) s" || fail "the control thread was slow: $((T1 - T0)) s"
kill -0 "$PK" 2>/dev/null && pass "the parked client is still waiting" || fail "the parked client has already ended: $(cat "$T/parked.out")"
kill -CONT "$LP"
i=0; while [ $i -lt 100 ] && kill -0 "$PK" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
wait "$PK" 2>/dev/null
grep -q "^OK zone db1.test. (view [_a-z]*): unchanged, serial 11$" "$T/parked.out" && pass "the parked client got the loader's answer: $(cat "$T/parked.out")" || fail "parked answer: '$(cat "$T/parked.out")'"

echo "== db-reload-timeout"
kill -STOP "$LP"
T0=$(now_s)
OUT=$($KCTL reload db1.test 2>&1); RC=$?
T1=$(now_s)
printf '%s\n' "$OUT" | grep -q "^ERROR timeout: the database loader did not answer within db-reload-timeout" && [ $RC -eq 3 ] && pass "timeout after $((T1 - T0)) s: $OUT" || fail "timeout: rc $RC '$OUT'"
[ $((T1 - T0)) -ge 3 ] && [ $((T1 - T0)) -le 8 ] && pass "about db-reload-timeout (4 s)" || fail "timed out after $((T1 - T0)) s"
echo "== more than 32 parked clients"
PIDS=""
n=1; while [ $n -le 35 ]; do $KCTL reload "x$n.test" > "$T/park$n.out" 2>&1 & PIDS="$PIDS $!"; n=$((n + 1)); done
sleep 1.5
OUT=$($KCTL zonestatus db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK serial=" && pass "the control thread answers with 32 clients parked" || fail "zonestatus with parked clients: '$OUT'"
wait $PIDS
REFUSED=$(cat "$T"/park*.out | grep -c "^ERROR too many reloads are waiting for the database loader; try again later$")
TIMEDOUT=$(cat "$T"/park*.out | grep -c "^ERROR timeout")
[ "$REFUSED" -ge 3 ] && pass "$REFUSED of 35 clients were refused (the limit is 32)" || fail "refused $REFUSED of 35 (timeouts $TIMEDOUT)"
[ $((REFUSED + TIMEDOUT)) -eq 35 ] && pass "the others ($TIMEDOUT) timed out" || fail "answers: $REFUSED refused + $TIMEDOUT timed out of 35"
kill -CONT "$LP"
sleep 2
kill -0 "$SRV" 2>/dev/null && pass "the server is up after the stopped loader ran again" || fail "the server died"
OUT=$($KCTL reload db1.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK zone db1.test. " && pass "reload works again: $OUT" || fail "reload after the storm: '$OUT'"

# ================================================================ karictl --help
echo "== karictl --help"
HELP=$(./karictl --help 2>&1); RC=$?
[ $RC -eq 0 ] && printf '%s\n' "$HELP" | grep -q "reload <zone> \[view\] \[force\]" && pass "--help lists the reload syntax" || fail "--help: rc $RC"
add_zone example.test
OUT=$($KCTL reload example.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone example.test. " && [ $RC -eq 0 ] && pass "help example 1: karictl reload example.test: $OUT" || fail "help example 1: rc $RC '$OUT'"
OUT=$($KCTL reload example.test force 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone example.test. .*applied" && [ $RC -eq 0 ] && pass "help example 2: karictl reload example.test force: $OUT" || fail "help example 2: rc $RC '$OUT'"
OUT=$($KCTL zonestatus example.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK serial=1 " && [ $RC -eq 0 ] && pass "help example 3: karictl zonestatus example.test" || fail "help example 3: rc $RC '$OUT'"

# ================================================================ stop
echo "== SIGTERM"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then fail "karidns did not stop within 10 s"; else pass "karidns stopped"; fi
sleep 0.5
LEFT=$(pgrep -f "karidns.*$T" | tr '\n' ' ')
[ -z "$LEFT" ] && pass "no process of this server is left" || fail "left over: $LEFT"
SRV=""
grep -q "AddressSanitizer\|runtime error:" "$T/srv.log" && fail "sanitizer report in the server log" || true

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_reload_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_reload_test: $FAILS check(s) FAILED ($PASS passed) ==="
echo "--- server log (last 60 lines) ---"
tail -60 "$T/srv.log" 2>/dev/null
exit 1

#!/bin/sh
# run_db_reconcile_test.sh - the Backend's side of the store protocol (0.7 WP7b): the loader lists the zones (a manifest pass) or the changes, the Backend keeps the zone store
# right and fetches the bodies in the background.  The real karidns and karidns-dbloader on SQLite3 (RECON_DRIVER=sqlite3, the default) or PostgreSQL (run_db_pg_reconcile_test.sh).
#
# The database holds RECON_ZONES zones (default 20000; each has SOA, 2 NS, an apex address and MX, www and a host).  Checked:
#   - first fill from an empty store: a pass lists every zone, the bodies are fetched in the background (store.recon.* of `karictl store`), the store ends with every zone stored
#     and none known, the answers are right and a query that comes while the fill runs is answered
#   - restart with the loader running: no pass (the cursor and the identity of the database are in the store and in CONFIG), no zone is fetched, the zones answer from the store
#   - changes after the cursor: a deleted zone disappears (REFUSED), a changed zone shows its new data, a new zone is served, all by the change log (no pass)
#   - a database that lacks 30 percent of the zones (the file is replaced / the change log is gone: the loader makes a pass): the mass-delete guard (more than 20 percent and more
#     than 1000 zones) deletes nothing, the zones keep being served, the log has an ERROR line and `karictl store` and `karictl dbstatus` say that it holds and how to release it
#   - `karictl reload -force` is the release: the zones the database no longer lists are deleted, the guard is let go, and the next start makes no pass (the cursor was kept)
# Needs root (the loader runs as another user).  SKIP without the binaries, sqlite3 / PostgreSQL or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

DRV=${RECON_DRIVER:-sqlite3}
if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx "$DRV" || { echo "SKIP: $LOADER has no $DRV driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
if [ "$DRV" = sqlite3 ]; then
    command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
fi

NZ=${RECON_ZONES:-20000}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_recon.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_server() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    set +e
    stop_server
    kari_kill_conf "$T/k.conf"
    [ "$DRV" = postgresql ] && pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
if [ "$DRV" = postgresql ]; then
    . "$ROOT/tests/db/pg_lib.sh"
    pg_setup recon || exit 0
    [ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }
fi
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((22000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

echo "== the database ($DRV): $NZ zones"
if [ "$DRV" = sqlite3 ]; then
    mkdir "$T/db"
    DB="$T/db/z.db"
    sh tests/db/gen_sqlite3_zones.sh "$DB" "$NZ" 7 > /dev/null || { fail "cannot build the database"; exit 1; }
    sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE)" > /dev/null
    chown -R nobody "$T/db"; chmod 700 "$T/db"
    sql() { sqlite3 "$DB" "$1"; }
    FALSE=0
    SRC="database-file \"$DB\";"
    LUSER=nobody
    install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
else
    as_pg sh tests/db/gen_pgsql_zones.sh "$PGC" "$NZ" 7 > /dev/null || { fail "cannot build the database"; exit 1; }
    pf db/karidns_ext.pgsql.sql > /dev/null 2>&1
    sql() { pq "$1"; }
    FALSE=false
    pg_conninfo_file "$T/ci"
    SRC="conninfo-file \"$T/ci\";"
    LUSER=$PG_AS
    install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
fi
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
K="./karictl -c $T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver $DRV; $SRC loader-user "$LUSER"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; }; store "$T/store"; park-timeout 5000; db-reload-timeout 60; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
sf() { $K store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
waitfor() {   # waitfor SECONDS COMMAND...
    w=$1; shift
    i=0
    while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
start_server() {   # start_server LOG
    LOG=$1
    : > "$LOG"
    "$KARIDNS" -c "$T/k.conf" -f > "$LOG" 2>&1 &
    SRV=$!
    waitfor 120 grep -q "\[DB\] initial load complete" "$LOG" && pass "the startup batch is complete ($(grep -c . "$LOG") log lines)" || { fail "no 'initial load complete'"; tail -20 "$LOG"; }
}
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1; }
rcode() { ./dag @127.0.0.1 -p "$PORT" "$1" A +nohexdump +time=8 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
stored_is() { [ "$(sf store.zones.stored)" = "$1" ] && [ "$(sf store.zones.known)" = 0 ]; }
sample() {   # sample STEP: a query for every STEP-th zone; the number that were not answered with an address
    bad=0; n=0; z=1
    while [ "$z" -le "$NZ" ]; do
        a=$(q "www.z$z.test")
        case $a in 192.0.2.*) ;; *) bad=$((bad + 1)) ;; esac
        n=$((n + 1)); z=$((z + $1))
    done
    SAMPLE_N=$n; SAMPLE_BAD=$bad
}

echo "== first fill from an empty store: a pass, the bodies fetched in the background"
T0=$(date +%s)
start_server "$T/s1.log"
grep -q "a manifest pass starts" "$T/s1.log" && pass "the loader listed the zones (a manifest pass)" || fail "no manifest pass in the log"
waitfor 300 stored_is "$NZ" && pass "the store holds all $NZ zones, none without a body ($(( $(date +%s) - T0 )) s from the start)" || fail "the store holds $(sf store.zones.stored) of $NZ zones ($(sf store.zones.known) known)"
[ "$(sf store.recon.pass.entries)" = "$NZ" ] && [ "$(sf store.recon.pass.created)" = "$NZ" ] && pass "the pass listed $NZ zones, all new (store.recon.pass.entries / created)" || fail "pass: entries=$(sf store.recon.pass.entries) created=$(sf store.recon.pass.created)"
[ "$(sf store.recon.bodies.fetched)" = "$NZ" ] && [ "$(sf store.recon.bodies.failed)" = 0 ] && pass "every body was fetched once, none failed (store.recon.bodies.fetched)" || fail "fetched=$(sf store.recon.bodies.fetched) failed=$(sf store.recon.bodies.failed)"
[ "$(sf store.recon.passes)" = 1 ] && [ "$(sf store.recon.pass.active)" = 0 ] && [ "$(sf store.recon.guard.held_views)" = 0 ] && pass "one pass, over, the guard is not held" || fail "passes=$(sf store.recon.passes) active=$(sf store.recon.pass.active) guard=$(sf store.recon.guard.held_views)"
$K dbstatus 2>/dev/null | grep -q '^store pass: idle view=' && pass "karictl dbstatus has the pass line" || fail "dbstatus has no 'store pass:' line"
sample 400
[ "$SAMPLE_BAD" = 0 ] && pass "$SAMPLE_N zones answer after the fill" || fail "$SAMPLE_BAD of $SAMPLE_N queries are wrong"
[ "$(grep -c 'initial load complete' "$T/s1.log")" = 1 ] && pass "the loader's batch was answered when the entries were recorded (not when the bodies were)" || fail "initial load line count"
stop_server

echo "== a restart with the loader running: the cursor is in the store, no pass, nothing fetched"
start_server "$T/s2.log"
sleep 2
grep -q "a manifest pass starts" "$T/s2.log" && fail "the loader listed the zones again" || pass "no manifest pass (the loader went on from the cursor of the store)"
[ "$(sf store.recon.passes)" = 0 ] && [ "$(sf store.recon.bodies.fetched)" = 0 ] && pass "no pass, no body fetched since the start" || fail "passes=$(sf store.recon.passes) fetched=$(sf store.recon.bodies.fetched)"
stored_is "$NZ" && pass "the store still holds $NZ zones" || fail "the store holds $(sf store.zones.stored) stored / $(sf store.zones.known) known"
sample 1000
[ "$SAMPLE_BAD" = 0 ] && pass "the zones answer after the restart ($SAMPLE_N asked)" || fail "$SAMPLE_BAD of $SAMPLE_N queries are wrong"

echo "== changes: a deleted zone, a changed zone, a new zone (the change log, no pass)"
sql "DELETE FROM records WHERE domain_id = 7; DELETE FROM domains WHERE id = 7;" > /dev/null
sql "UPDATE records SET content = '192.0.2.250' WHERE domain_id = 9 AND name = 'www.z9.test' AND type = 'A';" > /dev/null
sql "INSERT INTO domains (name, type) VALUES ('znew.test', 'NATIVE');" > /dev/null
sql "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, $FALSE FROM domains WHERE name = 'znew.test';" > /dev/null
sql "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.example.test.', 300, 0, $FALSE FROM domains WHERE name = 'znew.test';" > /dev/null
sql "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.77', 300, 0, $FALSE FROM domains WHERE name = 'znew.test';" > /dev/null
$K reload 2>&1 | head -2 | sed 's/^/         /'
chg_done() { [ "$(rcode www.z7.test)" = REFUSED ] && [ "$(q www.z9.test)" = 192.0.2.250 ] && [ "$(q www.znew.test)" = 192.0.2.77 ]; }
waitfor 30 chg_done && pass "the deleted zone is gone (REFUSED), the changed zone shows its data, the new zone is served" || fail "z7 $(rcode www.z7.test), z9 '$(q www.z9.test)', znew '$(q www.znew.test)'"
grep -q "a manifest pass starts" "$T/s2.log" && fail "a pass was made for the changes" || pass "no pass: the change log was enough"
[ "$(sf store.recon.changes.deletes)" -ge 1 ] 2>/dev/null && pass "the delete came as a change entry (store.recon.changes.deletes=$(sf store.recon.changes.deletes), upserts=$(sf store.recon.changes.upserts))" || fail "changes: deletes=$(sf store.recon.changes.deletes) upserts=$(sf store.recon.changes.upserts)"
stored_is "$NZ" && pass "the store has $NZ zones again (one gone, one new)" || fail "the store holds $(sf store.zones.stored) stored / $(sf store.zones.known) known (want $NZ)"
stop_server

echo "== a database that lacks 30 percent of the zones: the loader lists the zones, the guard holds the sweep back"
MASS=$(sql "SELECT count(*) FROM domains WHERE id % 10 < 3")
if [ "$DRV" = sqlite3 ]; then
    # the database file is replaced by a copy without those zones (a restore from a backup): another file, another identity: the loader lists the zones
    sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE)" > /dev/null
    cp -p "$DB" "$DB.new"
    sqlite3 "$DB.new" "DELETE FROM records WHERE domain_id IN (SELECT id FROM domains WHERE id % 10 < 3); DELETE FROM domains WHERE id % 10 < 3; PRAGMA wal_checkpoint(TRUNCATE)" > /dev/null
    chown nobody "$DB.new"
    rm -f "$DB-wal" "$DB-shm"
    mv "$DB.new" "$DB"
else
    # the change log is cut (a restored database, a pruned log): the loader finds a gap and lists the zones
    sql "DELETE FROM karidns_changes" > /dev/null
    sql "DELETE FROM records WHERE domain_id IN (SELECT id FROM domains WHERE id % 10 < 3); DELETE FROM domains WHERE id % 10 < 3" > /dev/null
fi
LEFT=$(sql "SELECT count(*) FROM domains")
echo "  ($MASS zones deleted from the database, $LEFT left)"
start_server "$T/s3.log"
grep -q "a manifest pass starts" "$T/s3.log" && pass "the loader listed the zones (the cursor did not fit the database)" || fail "no manifest pass in the log"
held() { [ "$(sf store.recon.guard.held_views)" = 1 ]; }
waitfor 60 held && pass "the guard holds the sweep back (store.recon.guard.held_views=1)" || fail "the guard is not held: $(sf store.recon.guard.held_views)"
[ "$(sf store.recon.guard.unlisted)" = "$MASS" ] && pass "it says how many zones were not listed ($MASS of $(sf store.recon.guard.total))" || fail "guard.unlisted=$(sf store.recon.guard.unlisted), want $MASS"
[ "$(sf store.recon.guard.release | tr -d '"')" = "karictl reload -force" ] && pass "and how to release it" || fail "guard.release='$(sf store.recon.guard.release)'"
grep -E '\[Store\].*NOTHING IS DELETED' "$T/s3.log" | grep -q 'reload -force' && pass "the log has the ERROR line (nothing is deleted; reload -force)" || fail "no guard line in the log"
$K dbstatus 2>/dev/null | grep -q 'MASS-DELETE GUARD HELD' && pass "karictl dbstatus says that the guard holds" || fail "dbstatus does not show the guard"
[ "$(sf store.zones.stored)" = "$NZ" ] && pass "no zone was deleted ($NZ stored)" || fail "the store holds $(sf store.zones.stored) zones (want $NZ)"
[ "$(rcode www.z1.test)" = NOERROR ] && [ "$(q www.z1.test)" != "" ] && pass "a zone the database no longer has is still served (z1.test)" || fail "z1.test: $(rcode www.z1.test)"

echo "== karictl reload -force releases the guard: the zones are deleted"
$K reload -force 2>&1 | head -2 | sed 's/^/         /'
swept() { [ "$(sf store.recon.guard.held_views)" = 0 ] && [ "$(sf store.recon.sweep.deleted)" = "$MASS" ]; }
waitfor 120 swept && pass "the pass the operator asked for deleted the $MASS zones and let the guard go" || fail "guard held_views=$(sf store.recon.guard.held_views) deleted=$(sf store.recon.sweep.deleted)"
[ "$(sf store.zones.stored)" = "$LEFT" ] && pass "the store holds the $LEFT zones the database has" || fail "the store holds $(sf store.zones.stored) zones (want $LEFT)"
[ "$(rcode www.z1.test)" = REFUSED ] && pass "z1.test is gone (REFUSED)" || fail "z1.test: $(rcode www.z1.test)"
[ "$(q www.z3.test)" != "" ] && pass "a zone that stays is served" || fail "z3.test is not served"
stop_server

echo "== the cursor was kept after the release: the next start lists nothing"
start_server "$T/s4.log"
sleep 2
grep -q "a manifest pass starts" "$T/s4.log" && fail "the loader listed the zones again" || pass "no pass at the next start"
[ "$(sf store.recon.guard.held_views)" = 0 ] && [ "$(sf store.zones.stored)" = "$LEFT" ] && pass "the guard is not held, $LEFT zones are stored" || fail "held=$(sf store.recon.guard.held_views) stored=$(sf store.zones.stored)"
if grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T"/s*.log 2>/dev/null; then fail "sanitizer report in a server log"; else pass "no sanitizer report in the server logs"; fi
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

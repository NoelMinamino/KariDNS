#!/bin/sh
# run_db_signer_restart_test.sh - signer-wait across restarts and under memory-limit (0.7, P3 paths (c) and (d)), SQLite3 (SIGNER_DB=pg: PostgreSQL,
# tests/run_db_signer_restart_pg_test.sh).
#
# A zone with the domainmetadata X-KARIDNS-SIGNER=1 and a row in karidns_signer_state (what karidns-signer writes when it has signed the zone: signed_serial,
# signed_at) is changed by somebody else; the change waits for the signer.  Every part runs without the zone store (`store none;`) and with it.  Checked:
#   R1  (d) a restart of the server: with the store the signed version (the image) keeps serving after the start, the zone is named as waiting again and a
#       WARNING says so, until the signer has signed it (its state row) and asked for the reload; without the store there is no signed version after the
#       start: the zone is served as it is and that is said (the WARNING of signer-wait, store.recon.signer.unsigned / the dbstatus line).
#       Before 0.7 (d) the start of the loader released every hold: the store served the unsigned version after the restart.
#   R2  (d) a restart of the loader alone (the supervisor starts it again): the Backend keeps the signed version (in memory, or its image) and the zone waits
#       again, in both modes.  Before (d) the new loader's full comparison sent the unsigned version (store none) or released the hold (store).
#   R3  the signer's metadata is removed while the server is down: the zone does not wait any more, its version is read as it is after the start.
#   R4  a signer that keeps a zone waiting is said: KARIDNS_SIGNER_STUCK_MS (a wrapper of the loader sets it) makes the hourly WARNING come after 2 s.
#   C1  (c) `store none` + memory-limit: a big zone of the signer whose change waits stays in memory while a sweep over 200 other zones takes everything
#       else out (dbstatus "held there", "held in memory now: 1 zone(s)", the WARNING that the holds keep the zones above memory-limit) and every zone of the
#       sweep is still answered (the held bytes do not hold the fetches back).  Before (c) the zone was taken out and the next query read the unsigned version.
#       The WARNING is checked after memory-limit is lowered below the held zone (karictl reconfig): the sweep alone does not reach above the limit on a slow build.
#
# Needs root (the server starts as root and drops to nobody, the loader is root-owned).  SKIP otherwise and when a binary or the database is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
SIGNER_DB=${SIGNER_DB:-sqlite3}
NAME=run_db_signer_restart_test
[ "$SIGNER_DB" = pg ] && NAME=run_db_signer_restart_pg_test

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
if [ "$SIGNER_DB" = pg ]; then
    "$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }
else
    command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
    "$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_sigrst.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_server() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
if [ "$SIGNER_DB" = pg ]; then . "$ROOT/tests/db/pg_lib.sh"; fi
cleanup() {
    stop_server
    [ "$SIGNER_DB" = pg ] && pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
if [ "$SIGNER_DB" = pg ]; then
    pg_setup sigrst || exit 0
    [ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }
fi

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
mkdir "$T/z" "$T/db"; chmod 755 "$T/z"; chown nobody "$T/db"; chmod 777 "$T/db"
DB="$T/db/s.db"

# ---- the database, either driver
if [ "$SIGNER_DB" = pg ]; then
    sq() { pq "$1" > /dev/null; }
    sqv() { pq "$1"; }
    newdb() { pq "DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null; pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null; }
    loadz() { ./tests/db/zone2sql --dialect pgsql "$T/z/$1.zone" > "$T/z/$1.sql" 2>/dev/null && pf "$T/z/$1.sql" > /dev/null; }
    NOW="extract(epoch FROM now())::bigint"
    TS() { printf 'to_timestamp(%s)' "$1"; }
    SERIES() { printf 'SELECT generate_series(0, %s) AS i' "$(($1 - 1))"; }
    pg_conninfo_file "$T/ci"
    DBSTMT() { printf 'driver postgresql; conninfo-file "%s"; loader-user "%s";' "$T/ci" "$PG_AS"; }
else
    sq() { sqlite3 "$DB" "$1"; chmod 666 "$DB"* 2>/dev/null; }
    sqv() { sqlite3 "$DB" "$1"; }
    newdb() { rm -f "$DB" "$DB-wal" "$DB-shm"; sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null; sqlite3 "$DB" < db/karidns_ext.sqlite3.sql; chmod 666 "$DB"; }
    loadz() { ./tests/db/zone2sql --dialect sqlite3 "$T/z/$1.zone" 2>/dev/null | sqlite3 "$DB"; chmod 666 "$DB"*; }
    NOW="CAST(strftime('%s','now') AS INTEGER)"
    TS() { printf '%s' "$1"; }
    SERIES() { printf 'WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < %s) SELECT i FROM n' "$(($1 - 1))"; }
    DBSTMT() { printf 'driver sqlite3; database-file "%s"; loader-user "nobody";' "$DB"; }
fi
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
EOF
    loadz "$1"
}
# a zone of the signer, signed by it: the metadata and its state row (the serial it wrote, signed a second from now)
addsigner() {   # addsigner NAME SERIAL ADDRESS
    mkzone "$1" "$2" "$3"
    sq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = '$1'"
    signed "$1" "$2"
}
signed() {   # signed NAME SERIAL: what the signer writes after it has signed the zone
    sq "DELETE FROM karidns_signer_state WHERE domain_id = (SELECT id FROM domains WHERE name = '$1')"
    sq "INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial) SELECT id, $(TS "$NOW + 1"), $2 FROM domains WHERE name = '$1'"
}
change() {   # change NAME OLD-SERIAL NEW-SERIAL ADDRESS: somebody else changes the zone (the signer has not signed it)
    sq "UPDATE records SET content = '$4' WHERE name = 'www.$1' AND type = 'A'"
    sq "UPDATE records SET content = replace(content, ' $2 3600', ' $3 3600') WHERE type = 'SOA' AND name = '$1'"
}
# the loader, behind a wrapper (the supervisor clears the environment): KARIDNS_SIGNER_STUCK_MS makes the warning of a signer that keeps zones waiting come after 2 s
install -o root -g wheel -m 755 "$LOADER" "$T/kdl" 2>/dev/null || { cp "$LOADER" "$T/kdl"; chown 0:0 "$T/kdl"; chmod 755 "$T/kdl"; }
printf '#!/bin/sh\nKARIDNS_SIGNER_STUCK_MS=%s; export KARIDNS_SIGNER_STUCK_MS\nexec %s "$@"\n' "${STUCK_MS:-2000}" "$T/kdl" > "$T/karidns-dbloader"
chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf "DATABASE-OPTIONS"
    cat > "$T/s.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { $(DBSTMT) loader-path "$T/karidns-dbloader"; $(store_stmt "$T") db-reload-timeout 10; auto-reload yes; poll-interval 1; coalesce 300; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
LOG="$T/srv.log"
start_server() {
    : > "$LOG"
    "$KARIDNS" -c "$T/s.conf" -f > "$LOG" 2>&1 &
    SRV=$!
    if kari_wait_log "$LOG" "\[DB\] initial load complete" 30; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$LOG" | tail -20; fi
}
qa() { ./dag @127.0.0.1 -p $PORT "$1" A +short +nohexdump +time=2 +tries=1 2>/dev/null; }
wait_ans() {   # wait_ans NAME EXPECTED SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(qa "$1")" = "$2" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
# the answer stays EXPECTED for SECONDS (a check that something does NOT happen keeps its window)
stays_ans() {   # stays_ans NAME EXPECTED SECONDS
    i=0
    while [ $i -lt $(($3 * 5)) ]; do
        got=$(qa "$1")
        [ "$got" = "$2" ] || { echo "         (got '$got' after $((i / 5)) s)"; return 1; }
        sleep 0.2; i=$((i + 1))
    done
    return 0
}
dbst() { $KCTL dbstatus "$@" 2>&1; }
wait_dbst() {   # wait_dbst PATTERN SECONDS [ZONE]
    i=0
    while [ $i -lt $(($2 * 10)) ]; do dbst ${3:-} | grep -q -- "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
sfk() { $KCTL store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
lcount() { grep -c -- "$1" "$LOG" 2>/dev/null || true; }
wait_lcount() {   # wait_lcount PATTERN N SECONDS: the log has at least N lines of PATTERN
    i=0
    while [ $i -lt $(($3 * 10)) ]; do [ "$(lcount "$1")" -ge "$2" ] && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
loader_pid() { pgrep -f "^$T/kdl " | head -1; }

run_mode() {   # run_mode on|none
    DB_STORE=$1; export DB_STORE
    rm -rf "$T/store"
    echo "== store $1: R1 a restart of the server with a zone that waits for the signer"
    newdb
    mkzone plain.test 10 192.0.2.10
    addsigner sg.test 1 192.0.2.20
    conf ""
    start_server
    wait_ans www.sg.test 192.0.2.20 10 && pass "the signed version is served" || fail "sg.test is not served (got '$(qa www.sg.test)')"
    change sg.test 1 2 192.0.2.21
    wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 10 && pass "the change waits for the signer" || { fail "sg.test does not wait"; dbst | sed 's/^/         /'; }
    stays_ans www.sg.test 192.0.2.20 2 && pass "...and the signed version keeps serving" || fail "the unsigned change is served before the restart"
    stop_server
    start_server
    if [ "$1" = on ]; then
        wait_ans www.sg.test 192.0.2.20 5 && stays_ans www.sg.test 192.0.2.20 4 && pass "store: after the restart the signed version (the image) keeps serving" || fail "store: after the restart the version the signer has not signed is served"
        wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 10 && pass "store: the zone waits again after the restart (the loader read the signer's state)" || { fail "store: dbstatus does not name sg.test after the restart"; dbst | sed 's/^/         /'; }
        kari_wait_log "$LOG" "still wait for karidns-signer after the start" 5 && pass "store: a WARNING says that a zone still waits after the start" || { fail "store: no WARNING after the start"; grep -i signer "$LOG" | tail -5 | sed 's/^/         /'; }
        n=$(sfk store.recon.signer.carried); [ "${n:-0}" -ge 1 ] 2>/dev/null && pass "store: store.recon.signer.carried=$n" || fail "store: store.recon.signer.carried='$n'"
    else
        wait_ans www.sg.test 192.0.2.21 10 && pass "no store: nothing signed is here after the restart: the version is served as it is" || fail "no store: got '$(qa www.sg.test)' after the restart"
        kari_wait_log "$LOG" "zone 'sg\.test\.' .*signer-wait: .*a version the signer has not signed yet" 5 && pass "no store: ...and a WARNING says so" || { fail "no store: no WARNING about the unsigned version"; grep -i signer "$LOG" | tail -5 | sed 's/^/         /'; }
        wait_dbst "version(s) served that the signer has not signed yet" 5 && pass "no store: the dbstatus summary counts it" || { fail "no store: no signer-wait line in dbstatus"; dbst | grep -i signer | sed 's/^/         /'; }
    fi
    kari_wait_log "$LOG" "of karidns-signer have a version in the database that the signer has not signed yet" 5 && pass "the loader says at its start which zones wait" || fail "no loader line about the waiting zones"
    signed sg.test 2
    $KCTL reload sg.test > /dev/null 2>&1
    wait_ans www.sg.test 192.0.2.21 10 && pass "the signer has signed it and asked for the reload: the new version is served" || fail "after the signer's reload: got '$(qa www.sg.test)'"
    wait_dbst "waiting for the signer" 1 && { fail "the zone still waits after the reload"; dbst | sed 's/^/         /'; } || pass "...and nothing waits"

    echo "== store $1: R2 a restart of the loader alone"
    change sg.test 2 3 192.0.2.22
    wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 10 && pass "the next change waits" || { fail "sg.test does not wait"; dbst | sed 's/^/         /'; }
    LP=$(loader_pid)
    NC=$(lcount "\[DB\] loader connected")
    NI=$(lcount "\[DB\] initial load complete")
    if [ -n "$LP" ] && kill -TERM "$LP" 2>/dev/null; then pass "the loader (pid $LP) was stopped; the supervisor starts it again"; else fail "no loader process to stop"; fi
    wait_lcount "\[DB\] loader connected" $((NC + 1)) 20 && wait_lcount "\[DB\] initial load complete" $((NI + 1)) 20 && pass "a new loader connected and its first batch is complete" || { fail "no new loader"; tail -20 "$LOG" | sed 's/^/         /'; }
    stays_ans www.sg.test 192.0.2.21 4 && pass "the signed version keeps serving after the loader's restart" || fail "the loader's restart served the version the signer has not signed"
    wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 10 && pass "...and the zone waits again" || { fail "sg.test does not wait after the loader's restart"; dbst | sed 's/^/         /'; }
    [ "$1" = none ] && { dbst sg.test | grep -q "the version in memory (held there) keeps serving" && pass "no store: dbstatus sg.test: held in memory" || { fail "no store: dbstatus sg.test"; dbst sg.test | sed 's/^/         /'; }; }
    echo "== store $1: R4 a signer that keeps a zone waiting is said"
    kari_wait_log "$LOG" "zone(s) have waited for karidns-signer for more than 2 s (the longest: sg.test" 10 && pass "a WARNING names the zone that waits too long" || { fail "no WARNING about the signer that keeps sg.test waiting"; grep -i signer "$LOG" | tail -5 | sed 's/^/         /'; }
    signed sg.test 3
    $KCTL reload sg.test > /dev/null 2>&1
    wait_ans www.sg.test 192.0.2.22 10 && pass "signed and reloaded: the new version is served" || fail "after the reload: got '$(qa www.sg.test)'"

    echo "== store $1: R3 the signer's metadata is removed while the server is down"
    change sg.test 3 4 192.0.2.23
    wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 10 && pass "a change waits" || { fail "sg.test does not wait"; dbst | sed 's/^/         /'; }
    stop_server
    sq "DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-SIGNER' AND domain_id = (SELECT id FROM domains WHERE name = 'sg.test')"
    start_server
    wait_ans www.sg.test 192.0.2.23 10 && pass "no longer the signer's: its version is read as it is after the start" || { fail "the zone that lost the signer's metadata is still held (got '$(qa www.sg.test)')"; dbst sg.test | sed 's/^/         /'; }
    wait_dbst "waiting for the signer" 1 && { fail "the zone still waits"; dbst | sed 's/^/         /'; } || pass "...and nothing waits"
    stop_server
}

run_mode none
run_mode on

# ================================================================ C1: store none + memory-limit
echo "== C1 (c): store none + memory-limit, a zone of the signer whose change waits stays in memory"
DB_STORE=; export DB_STORE
NZ=200; NH=150; NS=12000
newdb
if [ "$SIGNER_DB" = pg ]; then sq "INSERT INTO domains (name, type) SELECT 'z' || lpad(i::text, 4, '0') || '.test', 'NATIVE' FROM ($(SERIES $NZ)) s"
else sq "INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM ($(SERIES $NZ)) s"; fi
sq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, $( [ "$SIGNER_DB" = pg ] && echo false || echo 0 ) FROM domains"
sq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, $( [ "$SIGNER_DB" = pg ] && echo false || echo 0 ) FROM domains"
if [ "$SIGNER_DB" = pg ]; then
    sq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, 'h' || k.i || '.' || d.name, 'A',
        '10.' || ((substr(d.name, 2, 4)::int % 200) + 1) || '.' || (k.i / 200) || '.' || (k.i % 200 + 1), 300, 0, false FROM domains d, ($(SERIES $NH)) k"
else
    sq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, 'h' || k.i || '.' || d.name, 'A',
        printf('10.%d.%d.%d', (CAST(substr(d.name, 2, 4) AS INTEGER) % 200) + 1, k.i / 200, k.i % 200 + 1), 300, 0, 0 FROM domains d, ($(SERIES $NH)) k"
fi
addsigner sg.test 1 192.0.2.20
sq "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, 'b' || k.i || '.sg.test', 'A', '198.51.100.' || (k.i % 250 + 1), 300, 0, $( [ "$SIGNER_DB" = pg ] && echo false || echo 0 ) FROM domains d, ($(SERIES $NS)) k WHERE d.name = 'sg.test'"
n=$(sqv "SELECT count(*) FROM domains")
[ "$n" -eq $((NZ + 1)) ] 2>/dev/null && pass "$n zones in the database" || fail "the database has '$n' zones, want $((NZ + 1))"
signed sg.test 1
conf "memory-limit 2m; fetch-rate 5000; park-timeout 4000;"
start_server
wait_ans www.sg.test 192.0.2.20 10 && pass "the signer's zone is in memory and served" || fail "sg.test is not served (got '$(qa www.sg.test)')"
wait_dbst "status applied$" 10 sg.test && pass "dbstatus sg.test: its data is in memory" || { fail "sg.test is not in memory"; dbst sg.test | sed "s/^/         /"; }
change sg.test 1 2 192.0.2.21
wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 10 && pass "its change waits for the signer" || { fail "sg.test does not wait"; dbst | sed 's/^/         /'; }
wait_dbst "the version in memory (held there) keeps serving" 10 sg.test && pass "dbstatus sg.test: the version in memory is held there" || { fail "dbstatus sg.test"; dbst sg.test | sed 's/^/         /'; }
for pass_no in 1 2; do
    SW=$(perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ $NH sweep 2> "$T/sweep.err")
    echo "$SW" | grep -q "wrong=0" && echo "$SW" | grep -q "ok=$NZ " && pass "sweep $pass_no over $NZ zones: every zone answers ($SW)" || { fail "sweep $pass_no: $SW"; head -3 "$T/sweep.err"; }
done
EV=$(dbst | sed -n 's/^residency: .* evictions=\([0-9]*\).*/\1/p' | head -1)
[ "${EV:-0}" -gt 0 ] 2>/dev/null && pass "memory-limit took zones out of memory (evictions=$EV)" || fail "no evictions (evictions='$EV')"
stays_ans www.sg.test 192.0.2.20 2 && pass "the signer's zone kept its signed version in memory (not taken out and read again unsigned)" || fail "the signer's zone was taken out and read as it is"
wait_dbst "held in memory now: 1 zone(s)" 10 && pass "dbstatus: one zone held in memory, counted against memory-limit" || { fail "dbstatus does not count the held zone"; dbst | grep -i "signer-wait" | sed 's/^/         /'; }
# The WARNING is said when the zones in memory are above memory-limit while a zone is held.  Under a 2 MB limit the cache manager keeps them under it (the
# other zones go first), and whether a round of the sweep finds them above it is a matter of timing (a slow coverage build never did): the limit is lowered
# below the size of the held zone instead (karictl reconfig: the cache manager reads it at once), so the held zone alone keeps them above it.
conf "memory-limit 1m; fetch-rate 5000; park-timeout 4000;"
OUT=$($KCTL reconfig 2>&1) && pass "memory-limit lowered to 1 MB, below the held zone ($OUT)" || fail "karictl reconfig: $OUT"
if kari_wait_log "$LOG" "signer-wait: the database zones (.*) are above memory-limit (.*) and 1 zone(s) of karidns-signer" 20; then
    pass "a WARNING says that the held zone keeps the zones above memory-limit"
else
    fail "no WARNING about memory-limit"
    dbst | grep -E "^cache:|^residency:|^signer-wait:" | sed 's/^/         /'
    grep -i "memory-limit\|signer-wait" "$LOG" | tail -5 | sed 's/^/         /'
fi
stays_ans www.sg.test 192.0.2.20 1 && pass "...and the held zone keeps its signed version under the lower limit" || fail "the held zone was let go under the lower limit"
signed sg.test 2
$KCTL reload sg.test > /dev/null 2>&1
wait_ans www.sg.test 192.0.2.21 10 && pass "signed and reloaded: the new version is served" || fail "after the reload: got '$(qa www.sg.test)'"
wait_dbst "held in memory now: 0 zone(s)" 15 && pass "...and nothing is held in memory any more" || { fail "the hold stays after the reload"; dbst | grep -i "signer-wait" | sed 's/^/         /'; }
stop_server

if grep -q "killed by signal\|AddressSanitizer\|ThreadSanitizer" "$LOG"; then fail "a process crashed"; grep -E "killed by signal|Sanitizer|#[0-9] " "$LOG" | head -12 | sed 's/^/         /'; fi
echo
if [ "$FAILS" -eq 0 ]; then echo "=== $NAME: all $PASS checks passed ==="; exit 0; fi
echo "=== $NAME: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

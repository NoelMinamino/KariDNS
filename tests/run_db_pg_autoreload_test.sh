#!/bin/sh
# run_db_pg_autoreload_test.sh - auto reload on PostgreSQL, `auto-reload yes;` with LISTEN karidns_changes (beta design 6, 8.4, 9;
# milestone B10; gate "auto reload on PG").
#
# karidns with options { database { driver postgresql; auto-reload yes; } }, the loader run as the user of the PostgreSQL role.
# The loader keeps one connection per view that LISTENs; its socket is in the loader's poll set, so a commit is seen at once, not
# at the next poll-interval (the interval is 20 s here, the latency bound a few seconds).  Checked:
#   S1  schema version 2 (db/karidns_ext.pgsql.sql):
#       - an edit that keeps the serial, a serial change, a new zone, a deleted zone (ZONE_DELETE) are served within the bound
#         although poll-interval is 20 s: the notification, not the timer, wakes the loader;
#       - a burst of commits inside the coalesce window gives ONE auto batch; dbstatus shows the settings;
#       - ordering: a transaction that is still open when another one commits (the other took the higher seq number; and the
#         case where the open transaction has the HIGHER xid and the lower seq) loses nothing: the committed edit is served
#         at once, the open one when it commits (the change log cursor of the PostgreSQL driver is the snapshot's xmin);
#       - the loader's connections are terminated (pg_terminate_backend): the loader notices, reconnects, and an edit made
#         while it was disconnected is picked up (catch-up after a reconnect);
#       - a failed read (the role loses SELECT on a table) is reported by dbstatus and recovers when the privilege is back;
#       - the conninfo (database name) never appears in the server log;
#   S2  schema version 1 (no karidns_changes.xid): warned once, zones are compared by serial (a serial bump is picked up, an edit
#       that keeps the serial is not), the migration script db/karidns_ext_v1_to_v2.pgsql.sql turns the change log on.
#   S3  two views, each with a database-schema of its own (loopback aliases 127.0.0.2/3): each has its data, an edit in one schema
#       reaches only that view.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned and runs as the unprivileged user that
# can connect to PostgreSQL).  SKIP otherwise, and when PostgreSQL is not reachable (tests/db/pg_lib.sh) or a binary is missing.
# BOUND_MS: the latency bound (default 2500).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
case $(date +%s%N 2>/dev/null) in ""|*N*) echo "SKIP: date has no %N (milliseconds are measured)"; exit 0 ;; esac

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pgauto.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""
TXPIDS=""
stop_server() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
ADDED=""
cleanup() {
    stop_server
    for p in $TXPIDS; do kill "$p" 2>/dev/null; done
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
pg_setup pgauto || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$((20000 + $$ % 20000))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
BOUND_MS=${BOUND_MS:-2500}

mkdir "$T/z"; chmod 755 "$T/z"
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
addz() {   # addz NAME SERIAL ADDRESS
    mkzone "$1" "$2" "$3"
    ./tests/db/zone2sql --dialect pgsql "$T/z/$1.zone" > "$T/z/$1.sql" 2>/dev/null && pf "$T/z/$1.sql" > /dev/null
}
newdb() {   # newdb [v1]: empty PowerDNS schema + the extension; v1: without the xid column / tagdefs.id (a database of schema version 1)
    pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || return 1
    if [ "${1:-}" = v1 ]; then
        pq "DROP INDEX karidns_changes_xid_idx; ALTER TABLE karidns_changes DROP COLUMN xid; ALTER TABLE karidns_zone_tagdefs DROP COLUMN id; UPDATE karidns_schema_version SET version = 1" > /dev/null
    fi
}
resetdb() { pq "DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null; }

install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
pg_conninfo_file "$T/ci"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf FILE "DATABASE-OPTIONS"
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; $2 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
LOG="$T/srv.log"
wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -Ec -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
start_server() {   # start_server CONF
    : > "$LOG"
    "$KARIDNS" -c "$1" -f > "$LOG" 2>&1 &
    SRV=$!
    if wait_log "$LOG" "\[DB\] initial load complete" 30; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$LOG" | tail -20; fi
}
msnow() { echo $(( $(date +%s%N) / 1000000 )); }
SRCB=""
qa() { ./dag @127.0.0.1 -p $PORT ${SRCB:+-b $SRCB} "$1" A +short +nohexdump 2>/dev/null; }
status_of() { ./dag @127.0.0.1 -p $PORT ${SRCB:+-b $SRCB} "$1" A +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
WAIT_MS=0
wait_ans() {   # wait_ans NAME EXPECTED MAXMS
    t0=$(msnow); got=""
    while :; do
        got=$(qa "$1"); now=$(msnow)
        [ "$got" = "$2" ] && { WAIT_MS=$((now - t0)); return 0; }
        [ $((now - t0)) -ge "$3" ] && { WAIT_MS=$((now - t0)); return 1; }
        sleep 0.05
    done
}
wait_status() {
    t0=$(msnow)
    while :; do
        got=$(status_of "$1"); now=$(msnow)
        [ "$got" = "$2" ] && { WAIT_MS=$((now - t0)); return 0; }
        [ $((now - t0)) -ge "$3" ] && { WAIT_MS=$((now - t0)); return 1; }
        sleep 0.05
    done
}
check_ans() { got=$(qa "$3"); [ "$got" = "$2" ] && pass "$1" || fail "$1 (got '$got', want '$2')"; }
dbst() { $KCTL dbstatus "$@" 2>&1; }
n_auto() { grep -c "karidns-dbloader.* batch [0-9]* (auto) sent" "$LOG" 2>/dev/null; }
wait_dbst() { i=0; while [ $i -lt $(($2 * 10)) ]; do dbst | grep -q -- "$1" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
latency() {   # latency DESCRIPTION NAME EXPECTED BOUND_MS
    if wait_ans "$2" "$3" 15000; then
        [ "$WAIT_MS" -le "$4" ] && pass "$1: served after $WAIT_MS ms (bound $4 ms)" || fail "$1: served after $WAIT_MS ms, bound $4 ms"
    else fail "$1: not served within $WAIT_MS ms (got '$got', want '$3')"; fi
}

# open transactions: psql sessions that read their commands from a FIFO (fd 7, 8)
tx_open() {   # tx_open N
    mkfifo "$T/tx$1.in"; chmod 666 "$T/tx$1.in"
    psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" < "$T/tx$1.in" > "$T/tx$1.out" 2>&1 &
    TXPIDS="$TXPIDS $!"
    eval "exec $((6 + $1))> \"$T/tx$1.in\""
}
tx() { n=$1; shift; eval "printf '%s\n' \"\$*\" >&$((6 + n))"; }
tx_sync() {   # tx_sync N: wait until the session has run everything sent so far
    TXSEQ=$((${TXSEQ:-0} + 1)); tag="sync$$_$TXSEQ"
    tx "$1" "SELECT '$tag';"
    i=0; while [ $i -lt 100 ]; do grep -q "$tag" "$T/tx$1.out" 2>/dev/null && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
tx_close() { eval "exec $((6 + $1))>&-"; }

# ================================================================ S1
echo "== S1: schema version 2, auto-reload yes, poll-interval 20 s: the notification wakes the loader"
newdb || { fail "cannot create the schema"; exit 1; }
addz z1.test 10 192.0.2.10; addz z2.test 20 192.0.2.20; addz z3.test 30 192.0.2.30
conf "$T/s1.conf" "auto-reload yes; poll-interval 20; coalesce 300;"
start_server "$T/s1.conf"
check_ans "www.z1.test A" "192.0.2.10" www.z1.test
wait_dbst "^auto reload: on (poll-interval 20 s, coalesce 300 ms)" 5 && pass "dbstatus: auto reload: on (20 s, 300 ms)" || { fail "dbstatus"; dbst | sed 's/^/         /' | head -6; }
wait_dbst "^  view [^:]*: last poll " 25 && pass "dbstatus lists the view" || { fail "dbstatus view line"; dbst | sed 's/^/         /' | head -6; }
sleep 1

echo "== S1: latency (the timer would need up to 20 s)"
pq "UPDATE records SET content = '192.0.2.11' WHERE name = 'www.z1.test'" > /dev/null
latency "an edit that keeps the serial" www.z1.test 192.0.2.11 "$BOUND_MS"
sleep 0.5
pq "UPDATE records SET content = replace(content, ' 10 3600', ' 11 3600') WHERE type = 'SOA' AND name = 'z1.test'; UPDATE records SET content = '192.0.2.12' WHERE name = 'www.z1.test'" > /dev/null
latency "a serial change" www.z1.test 192.0.2.12 "$BOUND_MS"
sleep 0.5
addz z4.test 40 192.0.2.40
latency "a new zone" www.z4.test 192.0.2.40 "$BOUND_MS"
sleep 0.5
pq "DELETE FROM domains WHERE name = 'z4.test'" > /dev/null
if wait_status www.z4.test REFUSED 15000; then [ "$WAIT_MS" -le "$BOUND_MS" ] && pass "a deleted zone is gone after $WAIT_MS ms (bound $BOUND_MS ms)" || fail "a deleted zone is gone after $WAIT_MS ms, bound $BOUND_MS ms"; else fail "the deleted zone still answers"; fi
grep "karidns-dbloader.* (auto) sent" "$LOG" | grep -q "1 deleted" && pass "the delete went as ZONE_DELETE in an auto batch" || fail "no auto batch with 1 deleted"
check_ans "the other zones are untouched" "192.0.2.20" www.z2.test
sleep 1

echo "== S1: coalescing: a burst of commits is one batch"
B0=$(n_auto)
n=1; while [ $n -le 8 ]; do pq "UPDATE records SET content = '192.0.2.1$n' WHERE name = 'www.z2.test'" > /dev/null; n=$((n + 1)); done
if wait_ans www.z2.test 192.0.2.18 8000; then pass "the last value of the burst is served ($WAIT_MS ms after the burst)"; else fail "the burst: last value not served (got '$got')"; fi
sleep 1.5
B1=$(n_auto)
[ $((B1 - B0)) -le 2 ] && [ $((B1 - B0)) -ge 1 ] && pass "8 commits gave $((B1 - B0)) auto batch(es), not 8" || fail "8 commits gave $((B1 - B0)) auto batches"

echo "== S1: a transaction that stays open does not hide later commits, and loses nothing when it commits"
# (a) T1 took the lower seq and stays open; an autocommit edit of another zone is served at once; T1's edit when it commits
tx_open 1
tx 1 "BEGIN;"
tx 1 "UPDATE records SET content = '192.0.2.51' WHERE name = 'www.z2.test';"
tx_sync 1 || fail "psql session 1 does not answer"
pq "UPDATE records SET content = '192.0.2.52' WHERE name = 'www.z3.test'" > /dev/null
latency "(a) a commit behind an open transaction" www.z3.test 192.0.2.52 "$BOUND_MS"
check_ans "(a) the open transaction's edit is not visible yet" "192.0.2.18" www.z2.test
tx 1 "COMMIT;"
tx_sync 1
latency "(a) the edit of the transaction that committed last" www.z2.test 192.0.2.51 "$BOUND_MS"
sleep 0.5
# (b) T2 gets its xid FIRST but takes the HIGHER seq and commits first; T1 (higher xid, lower seq) commits last: a position
# kept as a seq number would skip T1's row
tx_open 2
tx 2 "BEGIN;"
tx 2 "SELECT pg_current_xact_id();"
tx_sync 2
tx 1 "BEGIN;"
tx 1 "UPDATE records SET content = '192.0.2.61' WHERE name = 'www.z2.test';"
tx_sync 1
tx 2 "UPDATE records SET content = '192.0.2.62' WHERE name = 'www.z3.test';"
tx 2 "COMMIT;"
tx_sync 2
latency "(b) the higher seq with the lower xid commits first" www.z3.test 192.0.2.62 "$BOUND_MS"
check_ans "(b) the other edit is still open" "192.0.2.51" www.z2.test
sleep 1.2
tx 1 "COMMIT;"
tx_sync 1
latency "(b) the lower seq committed last is not skipped" www.z2.test 192.0.2.61 "$BOUND_MS"
tx_close 1; tx_close 2
sleep 1

echo "== S1: the loader's connections are terminated; it reconnects and catches up"
conf "$T/s1.conf" "auto-reload yes; poll-interval 2; coalesce 300;"
$KCTL reconfig > /dev/null 2>&1
wait_dbst "^auto reload: on (poll-interval 2 s, coalesce 300 ms)" 5 && pass "reconfig: poll-interval 2" || fail "dbstatus after the reconfig"
sleep 2.5
pq "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = 'karidns-dbloader' AND datname = '$PGDB'" > "$T/term.out"
[ "$(cat "$T/term.out")" -ge 1 ] && pass "terminated $(cat "$T/term.out") loader connection(s)" || fail "no loader connection was found to terminate"
pq "UPDATE records SET content = '192.0.2.71' WHERE name = 'www.z1.test'" > /dev/null
if wait_ans www.z1.test 192.0.2.71 15000; then pass "an edit made while the loader was disconnected is served after $WAIT_MS ms"; else fail "the edit after the disconnect was not picked up (got '$got')"; fi
wait_log "$LOG" "auto reload: poll failed|auto reload reopened the database" 10 && pass "log: the loader noticed the lost connection and reopened it" || { fail "no reconnect line in the log"; grep -i "auto reload" "$LOG" | tail -5 | sed 's/^/         /'; }
sleep 3
pq "UPDATE records SET content = '192.0.2.72' WHERE name = 'www.z1.test'" > /dev/null
latency "after the reconnect, LISTEN works again" www.z1.test 192.0.2.72 4500
wait_dbst "last error: none" 10 && pass "dbstatus: last error: none" || { fail "dbstatus after the reconnect"; dbst | sed 's/^/         /' | head -6; }

echo "== S1: a failed read is reported and recovers"
# the loader cannot read a table that is gone: rename it
pq "ALTER TABLE domainmetadata RENAME TO domainmetadata_off" > /dev/null
pq "UPDATE records SET content = '192.0.2.81' WHERE name = 'www.z1.test'" > /dev/null
wait_dbst "last error: cannot read the database" 15 && pass "dbstatus names the failed read" || { fail "dbstatus does not show the read error"; dbst | sed 's/^/         /' | head -8; }
check_ans "the last good zone keeps answering" "192.0.2.72" www.z1.test
pq "ALTER TABLE domainmetadata_off RENAME TO domainmetadata" > /dev/null
if wait_ans www.z1.test 192.0.2.81 20000; then pass "the edit is served after the table is back ($WAIT_MS ms)"; else fail "no recovery after the table came back (got '$got')"; fi
wait_dbst "last error: none" 10 && pass "dbstatus: last error: none" || { fail "dbstatus after the recovery"; dbst | sed 's/^/         /' | head -6; }

echo "== S1: nothing about the connection string in the log"
if grep -q "dbname=$PGDB\|$PGDB" "$LOG"; then fail "the database name (conninfo) appears in the server log"; grep -n "$PGDB" "$LOG" | head -3 | sed 's/^/         /'; else pass "the conninfo does not appear in the log"; fi
kill -0 "$SRV" 2>/dev/null && pass "the server is up" || fail "the server died"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$LOG" && fail "sanitizer report in the server log" || true
stop_server

# ================================================================ S2
echo "== S2: schema version 1 (no karidns_changes.xid): serial only, then the migration"
resetdb
newdb v1 || { fail "cannot create the version 1 schema"; exit 1; }
addz z1.test 10 192.0.2.10; addz z2.test 20 192.0.2.20
conf "$T/s2.conf" "auto-reload yes; poll-interval 2; coalesce 300;"
start_server "$T/s2.conf"
check_ans "www.z1.test A" "192.0.2.10" www.z1.test
wait_log "$LOG" "auto-reload is on but the database has no usable karidns_changes table" 10 && pass "warned: no usable karidns_changes (schema version 1)" || { fail "no warning"; grep -i "karidns_changes" "$LOG" | head -3 | sed 's/^/         /'; }
pq "UPDATE records SET content = replace(content, ' 10 3600', ' 11 3600') WHERE type = 'SOA' AND name = 'z1.test'; UPDATE records SET content = '192.0.2.11' WHERE name = 'www.z1.test'" > /dev/null
latency "version 1: a serial bump is picked up" www.z1.test 192.0.2.11 6000
pq "UPDATE records SET content = '192.0.2.12' WHERE name = 'www.z1.test'" > /dev/null
sleep 4
check_ans "version 1: an edit that keeps the serial is not picked up (serial-only)" "192.0.2.11" www.z1.test
OUT=$($KCTL reload z1.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reload <zone> reads it: $OUT" || fail "reload z1.test: '$OUT'"
check_ans "reload <zone> applied the edit" "192.0.2.12" www.z1.test
pf db/karidns_ext_v1_to_v2.pgsql.sql > /dev/null 2> "$T/mig.err" && pass "the migration script applies" || { fail "the migration script"; cat "$T/mig.err"; }
[ "$(pq "SELECT version FROM karidns_schema_version")" = "2" ] && pass "karidns_schema_version is 2" || fail "schema version after the migration"
OUT=$($KCTL reload 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "karictl reload after the migration: $OUT" || fail "reload: '$OUT'"
sleep 3
pq "UPDATE records SET content = '192.0.2.13' WHERE name = 'www.z1.test'" > /dev/null
latency "after the migration an edit that keeps the serial is picked up" www.z1.test 192.0.2.13 8000
kill -0 "$SRV" 2>/dev/null && pass "the server is up" || fail "the server died"
stop_server

# ================================================================ S3
echo "== S3: two views, each with its own schema (database-schema), auto reload"
ALIASES=1
for ip in 127.0.0.2 127.0.0.3; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else ALIASES=0; fi
done
if [ "$ALIASES" = 0 ]; then
    echo "  [SKIP] cannot add the loopback aliases 127.0.0.2/3"
else
    resetdb
    for v in a b; do
        { printf 'CREATE SCHEMA karidns_test_v%s;\nSET search_path TO karidns_test_v%s;\n' "$v" "$v"; cat tests/db/pdns_schema.pgsql.sql db/karidns_ext.pgsql.sql; } > "$T/v$v.sql"
        pf "$T/v$v.sql" > /dev/null || fail "cannot create the schema karidns_test_v$v"
    done
    mkzone vw.test 10 192.0.2.10; ./tests/db/zone2sql --dialect pgsql "$T/z/vw.test.zone" > "$T/z/vw.sql" 2>/dev/null
    mkzone vx.test 10 192.0.2.60; ./tests/db/zone2sql --dialect pgsql "$T/z/vx.test.zone" > "$T/z/vx.sql" 2>/dev/null
    { echo "SET search_path TO karidns_test_va;"; cat "$T/z/vw.sql"; } > "$T/z/va_load.sql"; pf "$T/z/va_load.sql" > /dev/null
    { echo "SET search_path TO karidns_test_vb;"; cat "$T/z/vw.sql" "$T/z/vx.sql"; } > "$T/z/vb_load.sql"; pf "$T/z/vb_load.sql" > /dev/null
    pq "SET search_path TO karidns_test_vb; UPDATE records SET content = '192.0.2.20' WHERE name = 'www.vw.test'" > /dev/null    # the same zone name, another address in view b
    cat > "$T/s3.conf" <<ENDCONF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; auto-reload yes; poll-interval 20; coalesce 300; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
view "a" { match-clients { 127.0.0.2; }; database-schema "karidns_test_va"; };
view "b" { match-clients { 127.0.0.3; }; database-schema "karidns_test_vb"; };
ENDCONF
    start_server "$T/s3.conf"
    SRCB=127.0.0.2; check_ans "view a: www.vw.test from its schema" "192.0.2.10" www.vw.test
    [ "$(status_of www.vx.test)" = REFUSED ] && pass "view a does not have vx.test (only in the schema of view b)" || fail "view a: vx.test '$(status_of www.vx.test)'"
    SRCB=127.0.0.3; check_ans "view b: www.vw.test from its schema" "192.0.2.20" www.vw.test
    check_ans "view b: www.vx.test" "192.0.2.60" www.vx.test
    wait_dbst "^  view a: last poll " 25 && wait_dbst "^  view b: last poll " 25 && pass "dbstatus lists both views" || { fail "dbstatus views"; dbst | sed 's/^/         /' | head -8; }
    sleep 1
    pq "SET search_path TO karidns_test_va; UPDATE records SET content = '192.0.2.11' WHERE name = 'www.vw.test'" > /dev/null
    SRCB=127.0.0.2; latency "an edit in the schema of view a reaches view a" www.vw.test 192.0.2.11 "$BOUND_MS"
    SRCB=127.0.0.3; check_ans "view b is untouched" "192.0.2.20" www.vw.test
    sleep 0.5
    pq "SET search_path TO karidns_test_vb; UPDATE records SET content = '192.0.2.21' WHERE name = 'www.vw.test'" > /dev/null
    SRCB=127.0.0.3; latency "an edit in the schema of view b reaches view b" www.vw.test 192.0.2.21 "$BOUND_MS"
    SRCB=127.0.0.2; check_ans "view a is untouched" "192.0.2.11" www.vw.test
    kill -0 "$SRV" 2>/dev/null && pass "the server is up" || fail "the server died"
    SRCB=""
    stop_server
fi


echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_pg_autoreload_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_pg_autoreload_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

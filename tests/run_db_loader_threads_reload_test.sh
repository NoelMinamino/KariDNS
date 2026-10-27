#!/bin/sh
# run_db_loader_threads_reload_test.sh - regression test of milestone B11b: with loader-threads > 1 a reload of two or more zones, read one
# query each (below bulk-threshold), from a SQLite3 database that has the extension tables (db/karidns_ext.sqlite3.sql).
#
# The workers of the loader's pool open connections of their own.  They did not call check_schema(), so the driver did not know the
# optional tables of the source (has_ext), and scan_ext() failed with "the ... tables do not exist in this database": the whole
# batch failed and none of the changed zones was served.  A single changed zone is read by the main thread and never showed it.
#
#   S1  - loader-threads 4, bulk-threshold 100 (never the bulk scan), no auto-reload: three zones are edited, `karictl reload`
#         (diff) must read the three zones, send them and serve the new data; no "tables do not exist" in the log; a request for
#         one zone (main thread) still works;
#   S2  - the same with auto-reload yes: three zones edited in one commit are served without a request.
#
# Needs root (the loader must be root-owned and runs as nobody).  SKIP otherwise and when a binary or the sqlite3 CLI is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbthreads.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] || return 0
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kari_kill_tree "$SRV"
    SRV=""
}
cleanup() { stop_srv; kari_kill_conf "$T/k.conf"; rm -rf "$T"; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db" "$T/z"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
for n in 1 2 3 4 5 6; do
    cat > "$T/z/t$n.test.zone" <<EOF
\$ORIGIN t$n.test.
\$TTL 300
@ SOA ns1.t$n.test. host.t$n.test. $n 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.1$n
EOF
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/t$n.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
done
[ "$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM domains")" = 6 ] && pass "six zones and the extension tables are in the database" || fail "the database was not filled"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
sq() { sqlite3 "$T/db/z.db" "$@"; }
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf "DATABASE-OPTIONS"
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; bulk-threshold 100; loader-threads 4; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
wait_log() {   # wait_log LOG PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -Eq -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
start() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    if wait_log "$T/srv.log" "\[DB\] initial load complete" 30; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; tail -10 "$T/srv.log" | sed 's/^/         /'; fi
}
ans() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump 2>/dev/null; }
wait_ans() {   # wait_ans NAME EXPECTED: bounded, 20 s
    i=0
    while [ $i -lt 200 ]; do
        [ "$(ans "$1")" = "$2" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
setaddr() { sq "UPDATE records SET content = '$2' WHERE name = 'www.$1' AND type = 'A'"; }

echo "== S1: loader-threads 4, bulk-threshold 100, reload of three zones"
conf ""
start
for n in 1 2 3; do [ "$(ans www.t$n.test)" = "192.0.2.1$n" ] && pass "www.t$n.test is served after the start" || fail "www.t$n.test after the start: '$(ans www.t$n.test)'"; done
setaddr t1.test 192.0.2.101; setaddr t2.test 192.0.2.102; setaddr t3.test 192.0.2.103
OUT=$($KCTL reload 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karictl reload: $OUT" || fail "karictl reload: rc $RC '$OUT'"
for n in 1 2 3; do
    wait_ans www.t$n.test 192.0.2.10$n && pass "www.t$n.test serves the new address" || fail "www.t$n.test still '$(ans www.t$n.test)' (want 192.0.2.10$n)"
done
grep -q "batch [0-9]* (diff) sent: 3 zone(s) read, 3 sent, 0 failed in the loader" "$T/srv.log" && pass "the diff batch read and sent the three zones (the pool read them one by one)" || { fail "no 'diff ... 3 zone(s) read, 3 sent' batch line"; grep "batch .* sent" "$T/srv.log" | tail -3 | sed 's/^/         /'; }
grep -q "tables do not exist in this database" "$T/srv.log" && fail "the loader could not read the extension tables" || pass "no 'tables do not exist' in the log"
setaddr t4.test 192.0.2.104
OUT=$($KCTL reload t4.test 2>&1); RC=$?
[ $RC -eq 0 ] && wait_ans www.t4.test 192.0.2.104 && pass "a reload of one zone (main thread) works: $OUT" || fail "reload t4.test: rc $RC '$OUT'"
stop_srv

echo "== S2: the same with auto-reload yes"
conf "auto-reload yes; poll-interval 2; coalesce 300;"
start
sq "UPDATE records SET content = '192.0.2.115' WHERE name = 'www.t5.test' AND type = 'A'; UPDATE records SET content = '192.0.2.116' WHERE name = 'www.t6.test' AND type = 'A'; UPDATE records SET content = '192.0.2.117' WHERE name = 'www.t1.test' AND type = 'A';"
wait_ans www.t5.test 192.0.2.115 && wait_ans www.t6.test 192.0.2.116 && wait_ans www.t1.test 192.0.2.117 && pass "three zones changed in one commit are served by the auto reload" || fail "auto reload: t5 '$(ans www.t5.test)' t6 '$(ans www.t6.test)' t1 '$(ans www.t1.test)'"
grep -q "tables do not exist in this database" "$T/srv.log" && fail "auto reload: the loader could not read the extension tables" || pass "auto reload: no 'tables do not exist' in the log"
grep -q "batch [0-9]* (auto) sent: 3 zone(s) read, 3 sent" "$T/srv.log" && pass "one auto batch read and sent the three zones" || { fail "no 'auto ... 3 zone(s) read, 3 sent' batch line"; grep "batch .* sent" "$T/srv.log" | tail -3 | sed 's/^/         /'; }
stop_srv

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_loader_threads_reload_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_loader_threads_reload_test: $FAILS check(s) FAILED ($PASS passed) ==="
tail -40 "$T/srv.log" 2>/dev/null
exit 1

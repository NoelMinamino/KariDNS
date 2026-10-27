#!/bin/sh
# run_db_reload_requests_test.sh - several karidns servers on one PostgreSQL database: reload requests and per-server status
# (milestone B11, release plan 4.8; db/karidns_ext.pgsql.sql karidns_reload_requests / karidns_server_status).
#
# One PostgreSQL database, two karidns servers (server-id ns1 and ns2, ports of their own on 127.0.0.1, no auto-reload), each with
# its own karidns-dbloader.  Checked:
#   S1  - an edit is not served by either server until a request row is inserted; one INSERT (and its NOTIFY) makes BOTH reload
#         within the bound (the poll-interval is 2 s, the coalesce window 300 ms), and both status rows show the same generation, ok;
#       - a request for one zone reloads that zone only; several requests inserted together are ONE reload of the highest generation;
#         force, a zone name in another case with a trailing dot, an invalid zone name (reported, not fatal);
#       - broken zones (two records the loader cannot read) give ok = false and a failed_zones line per
#         zone; fixing them and asking again gives ok = true and an empty failed_zones; karictl dbstatus shows server-id,
#         generation and ok;
#       - one server stopped: only its row stays behind; started again, its startup load catches up and writes its row;
#       - the status table loses INSERT / UPDATE: dbstatus names the error, the log says it once, both servers keep answering and
#         keep applying requests; the privilege back: the row is written again and the error is gone;
#       - the watchers' connections are terminated (pg_terminate_backend): they reconnect and apply the request made meanwhile;
#         the requests table cannot be read: dbstatus names it, the server keeps answering, the next request is applied once the
#         table is back;
#   S2  - two views with a database-schema of their own (loopback aliases 127.0.0.2/3): a request in one schema reloads that view
#         only and is reported in that schema's status table;
#   S3  - a database without the multi-server tables: nothing is reported, no warning; no server-id: the host name is the id.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned and runs as the unprivileged user that
# can connect to PostgreSQL).  SKIP otherwise, and when PostgreSQL is not reachable (tests/db/pg_lib.sh) or a binary is missing.
# BOUND_MS: the latency bound of a reload after a request (default 4000).
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
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
case $(date +%s%N 2>/dev/null) in ""|*N*) echo "SKIP: date has no %N (milliseconds are measured)"; exit 0 ;; esac

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pgreq.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
PIDA=""; PIDB=""
stop_one() {   # stop_one PID: TERM, wait up to 15 s, then the whole tree
    [ -n "$1" ] || return 0
    kill -TERM "$1" 2>/dev/null
    i=0; while [ $i -lt 150 ] && kill -0 "$1" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kari_kill_tree "$1"
}
ADDED=""
cleanup() {
    stop_one "$PIDA"; stop_one "$PIDB"
    kari_kill_conf "$T/a.conf" "$T/b.conf" "$T/v.conf" "$T/s3.conf"
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
pg_setup pgreq || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT_A=$(kari_port 0 $((20000 + $$ % 20000)))
PORT_B=$((PORT_A + 1))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
BOUND_MS=${BOUND_MS:-4000}

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
setaddr() { pq "UPDATE records SET content = '$2' WHERE name = 'www.$1'" > /dev/null; }
newdb() { pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null; }

install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
pg_conninfo_file "$T/ci"
for n in a b s3; do
    cat > "$T/ctl_$n.conf" <<EOF
socket "$T/ctl_$n.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
    chmod 600 "$T/ctl_$n.conf"
done
kct() { n=$1; shift; ./karictl -c "$T/ctl_$n.conf" "$@" 2>&1; }

conf() {   # conf FILE PORT CTLNAME "DATABASE-OPTIONS" [EXTRA-TOP-LEVEL]
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $2;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; poll-interval 2; coalesce 300; $4 };
};
control-channel { socket "$T/ctl_$3.sock"; secret "$SECRET"; };
${5:-}
EOF
}
wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -Ec -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
start() {   # start NAME PORT: runs $T/NAME.conf, log $T/NAME.log, pid in PIDA / PIDB
    : > "$T/$1.log"
    "$KARIDNS" -c "$T/$1.conf" -f > "$T/$1.log" 2>&1 &
    if [ "$1" = b ]; then PIDB=$!; else PIDA=$!; fi
    if wait_log "$T/$1.log" "\[DB\] initial load complete" 30; then pass "server $1: the startup batch is complete"; else fail "server $1: no 'initial load complete' line"; sed 's/^/         /' "$T/$1.log" | tail -20; fi
}
msnow() { echo $(( $(date +%s%N) / 1000000 )); }
qa() { ./dag @127.0.0.1 -p "$1" ${SRCB:+-b $SRCB} "$2" A +short +nohexdump 2>/dev/null; }
WAIT_MS=0
wait_ans() {   # wait_ans PORT NAME EXPECTED MAXMS
    t0=$(msnow); got=""
    while :; do
        got=$(qa "$1" "$2"); now=$(msnow)
        [ "$got" = "$3" ] && { WAIT_MS=$((now - t0)); return 0; }
        [ $((now - t0)) -ge "$4" ] && { WAIT_MS=$((now - t0)); return 1; }
        sleep 0.05
    done
}
both() {   # both DESCRIPTION NAME EXPECTED: both servers serve EXPECTED within the bound
    for p in $PORT_A $PORT_B; do
        if wait_ans "$p" "$2" "$3" 15000; then
            [ "$WAIT_MS" -le "$BOUND_MS" ] && pass "$1: port $p serves it after $WAIT_MS ms" || fail "$1: port $p served it after $WAIT_MS ms, bound $BOUND_MS ms"
        else fail "$1: port $p does not serve it (got '$got', want '$3')"; fi
    done
}
check_ans() { got=$(qa "$3" "$4"); [ "$got" = "$2" ] && pass "$1" || fail "$1 (got '$got', want '$2')"; }
row() { pq "SELECT generation || '|' || ok || '|' || replace(failed_zones, chr(10), '~') FROM karidns_server_status WHERE server_id = '$1'"; }
wait_row() {   # wait_row SID PATTERN SECONDS: the row of SID matches the grep pattern
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        row "$1" 2>/dev/null | grep -q -- "$2" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
wait_dbst() {   # wait_dbst NAME PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        kct "$1" dbstatus | grep -q -- "$2" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
request() { pq "$1" > /dev/null; }

# ================================================================ S1
echo "== S1: two servers on one database (ns1, ns2), no auto-reload"
newdb || { fail "cannot create the schema"; exit 1; }
addz z1.test 10 192.0.2.10; addz z2.test 20 192.0.2.20
conf "$T/a.conf" "$PORT_A" a 'server-id "ns1";'
conf "$T/b.conf" "$PORT_B" b 'server-id "ns2";'
start a; start b
check_ans "ns1 serves www.z1.test" 192.0.2.10 "$PORT_A" www.z1.test
check_ans "ns2 serves www.z1.test" 192.0.2.10 "$PORT_B" www.z1.test
for n in a b; do
    sid=ns1; [ $n = b ] && sid=ns2
    wait_dbst $n "^reload requests (view [^)]*): server-id $sid, last applied generation 0, ok yes, status written never, last error: none" 10 \
        && pass "server $n: dbstatus shows server-id $sid, generation 0, ok yes, status written never" || { fail "server $n: dbstatus"; kct $n dbstatus | sed 's/^/         /' | head -12; }
done
[ "$(pq "SELECT count(*) FROM karidns_server_status")" = 0 ] && pass "no status row before the first request" || fail "status rows before any request"

echo "== S1: an edit is not served until a request is made"
setaddr z1.test 192.0.2.11
sleep 3
check_ans "ns1 does not see the edit (no auto-reload, no request)" 192.0.2.10 "$PORT_A" www.z1.test
check_ans "ns2 does not see the edit" 192.0.2.10 "$PORT_B" www.z1.test
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
both "one request row (generation 1)" www.z1.test 192.0.2.11
for s in ns1 ns2; do
    wait_row $s "^1|true|$" 10 && pass "$s: karidns_server_status has generation 1, ok" || { fail "$s: status row '$(row $s)'"; }
done
for n in a b; do
    wait_dbst $n "last applied generation 1, ok yes, status written 20[0-9][0-9]-" 10 && pass "server $n: dbstatus shows generation 1, ok yes and a time" || { fail "server $n: dbstatus after the request"; kct $n dbstatus | sed 's/^/         /' | head -12; }
done
wait_log "$T/a.log" "karidns-dbloader.* batch [0-9]* \(diff\) sent" 5 && pass "ns1: the request was a diff batch (all zones)" || fail "ns1: no diff batch for an all-zones request"

echo "== S1: a request for one zone reloads that zone only"
setaddr z1.test 192.0.2.12
setaddr z2.test 192.0.2.22
request "INSERT INTO karidns_reload_requests (zone) VALUES ('z2.test')"
both "request for z2.test (generation 2)" www.z2.test 192.0.2.22
check_ans "ns1: z1.test was not reloaded" 192.0.2.11 "$PORT_A" www.z1.test
check_ans "ns2: z1.test was not reloaded" 192.0.2.11 "$PORT_B" www.z1.test
wait_row ns1 "^2|true|$" 10 && wait_row ns2 "^2|true|$" 10 && pass "both rows are at generation 2" || fail "rows after the zone request: '$(row ns1)' '$(row ns2)'"
wait_log "$T/a.log" "karidns-dbloader.* batch [0-9]* \(zone\) sent" 5 && pass "ns1: a zone batch" || fail "ns1: no zone batch"

echo "== S1: requests that arrive together are one reload"
request "INSERT INTO karidns_reload_requests (zone) VALUES ('z1.test'), ('z2.test'), ('Z1.TEST.')"
both "three requests in one statement (generations 3..5)" www.z1.test 192.0.2.12
wait_row ns1 "^5|true|$" 10 && wait_row ns2 "^5|true|$" 10 && pass "both rows are at generation 5 (the highest of the three)" || fail "rows after the burst: '$(row ns1)' '$(row ns2)'"
[ "$(grep -c "reload request(s) up to generation [345] " "$T/a.log")" = 1 ] && pass "ns1: one reload for the three requests" || { fail "ns1: not one reload for generations 3..5"; grep "reload request" "$T/a.log" | sed 's/^/         /'; }

echo "== S1: force, and a zone name that is not a name"
request "INSERT INTO karidns_reload_requests (zone, force) VALUES ('z1.test', true)"
wait_row ns1 "^6|true|$" 10 && wait_row ns2 "^6|true|$" 10 && pass "force request (generation 6): applied, ok" || fail "rows after force: '$(row ns1)' '$(row ns2)'"
grep -q "up to generation 6 applied (listed zones, force)" "$T/a.log" && pass "ns1: logged as listed zones, force" || fail "ns1: log line of the force request"
request "INSERT INTO karidns_reload_requests (zone) VALUES ('bad..name')"
wait_row ns1 "^7|false|bad..name: not a valid zone name" 10 && wait_row ns2 "^7|false|bad..name: not a valid zone name" 10 && pass "an invalid zone name: generation 7 applied, ok = false, the name is in failed_zones" || fail "rows after the invalid name: '$(row ns1)' '$(row ns2)'"
check_ans "ns1 keeps answering" 192.0.2.12 "$PORT_A" www.z1.test
wait_dbst a "last applied generation 7, ok no," 10 && pass "dbstatus says ok no" || { fail "dbstatus after the invalid name"; kct a dbstatus | sed 's/^/         /' | head -12; }

echo "== S1: broken zones: ok = false and failed_zones; then fixed"
pq "WITH d AS (INSERT INTO domains (name, type) VALUES ('bad.test', 'NATIVE') RETURNING id)
    INSERT INTO records (domain_id, name, type, content, ttl, disabled)
    SELECT d.id, v.n, v.t, v.c, 300, false FROM d, (VALUES ('bad.test', 'SOA', 'ns1.bad.test hostmaster.bad.test 1 3600 600 86400 300'), ('bad.test', 'NS', 'ns1.bad.test'),
      ('ns1.bad.test', 'A', '192.0.2.1'), ('www.bad.test', 'A', 'not-an-address')) AS v(n, t, c)" > /dev/null
pq "WITH d AS (INSERT INTO domains (name, type) VALUES ('cn.test', 'NATIVE') RETURNING id)
    INSERT INTO records (domain_id, name, type, content, ttl, disabled)
    SELECT d.id, v.n, v.t, v.c, 300, false FROM d, (VALUES ('cn.test', 'SOA', 'ns1.cn.test hostmaster.cn.test 1 3600 600 86400 300'), ('cn.test', 'NS', 'ns1.cn.test'),
      ('ns1.cn.test', 'A', '192.0.2.1'), ('www.cn.test', 'MX', 'notanumber mail.cn.test')) AS v(n, t, c)" > /dev/null
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
for s in ns1 ns2; do
    wait_row $s "^8|false|.*bad.test" 15 && pass "$s: generation 8, ok = false, bad.test is in failed_zones" || fail "$s: row '$(row $s)'"
    row $s | grep -q "cn.test" && pass "$s: cn.test is in failed_zones too" || fail "$s: no cn.test in '$(row $s)'"
    row $s | grep -q "~" && pass "$s: one line per zone" || fail "$s: failed_zones has no second line"
done
wait_dbst b "last applied generation 8, ok no," 10 && pass "ns2: dbstatus says ok no" || { fail "ns2: dbstatus"; kct b dbstatus | sed 's/^/         /' | head -12; }
check_ans "the good zones are still served" 192.0.2.12 "$PORT_B" www.z1.test
pq "DELETE FROM domains WHERE name IN ('bad.test', 'cn.test')" > /dev/null
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
for s in ns1 ns2; do
    wait_row $s "^9|true|$" 15 && pass "$s: generation 9, ok = true, failed_zones empty again" || fail "$s: row after the fix '$(row $s)'"
done
wait_dbst a "last applied generation 9, ok yes," 10 && pass "ns1: dbstatus says ok yes again" || fail "ns1: dbstatus after the fix"

echo "== S1: one server stopped: only its row stays behind"
stop_one "$PIDB"; PIDB=""
setaddr z1.test 192.0.2.13
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
if wait_ans "$PORT_A" www.z1.test 192.0.2.13 15000; then pass "ns1 applied generation 10 ($WAIT_MS ms)"; else fail "ns1 did not apply the request"; fi
wait_row ns1 "^10|true|$" 10 && pass "ns1's row is at generation 10" || fail "ns1's row '$(row ns1)'"
sleep 1
row ns2 | grep -q "^9|true|$" && pass "ns2's row stays at generation 9 (it is down)" || fail "ns2's row '$(row ns2)'"
start b
check_ans "ns2, started again, serves the new data (its startup load)" 192.0.2.13 "$PORT_B" www.z1.test
wait_row ns2 "^10|true|$" 15 && pass "ns2's row caught up to generation 10 (the outcome of its startup load)" || fail "ns2's row after the restart '$(row ns2)'"
wait_dbst b "last applied generation 10, ok yes," 10 && pass "ns2: dbstatus shows generation 10" || fail "ns2: dbstatus after the restart"

echo "== S1: the status table cannot be written: shown, logged once, serving goes on"
ME=$(pq "SELECT current_user")
if [ "$(pq "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" = "t" ]; then
    # a superuser ignores privileges: make the write fail another way
    pq "ALTER TABLE karidns_server_status RENAME TO karidns_server_status_off" > /dev/null
    RESTORE="ALTER TABLE karidns_server_status_off RENAME TO karidns_server_status"
else
    pq "REVOKE INSERT, UPDATE ON karidns_server_status FROM $ME" > /dev/null
    RESTORE="GRANT INSERT, UPDATE ON karidns_server_status TO $ME"
fi
setaddr z1.test 192.0.2.14
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
both "the request is applied although the status cannot be written" www.z1.test 192.0.2.14
for n in a b; do
    wait_dbst $n "last applied generation 11, ok yes, status written .*, last error: cannot write karidns_server_status" 10 && pass "server $n: dbstatus names the write error" || { fail "server $n: dbstatus"; kct $n dbstatus | sed 's/^/         /' | head -12; }
done
sleep 12
for n in a b; do
    c=$(grep -c "reload requests: cannot write karidns_server_status" "$T/$n.log")
    [ "$c" = 1 ] && pass "server $n: the error is logged once ($c line after two retries)" || fail "server $n: the error is logged $c times"
done
kill -0 "$PIDA" 2>/dev/null && kill -0 "$PIDB" 2>/dev/null && pass "both servers are up" || fail "a server died"
setaddr z1.test 192.0.2.15
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
both "requests are still applied (generation 12)" www.z1.test 192.0.2.15
pq "$RESTORE" > /dev/null
for s in ns1 ns2; do
    wait_row $s "^12|true|$" 20 && pass "$s: the row is written again (generation 12) after the privilege is back" || fail "$s: row '$(row $s)'"
done
for n in a b; do
    wait_dbst $n "last applied generation 12, ok yes, status written 20[0-9][0-9]-[^,]*, last error: none" 10 && pass "server $n: dbstatus: no error" || { fail "server $n: dbstatus after the grant"; kct $n dbstatus | sed 's/^/         /' | head -12; }
done
grep -q "reload requests: the status row is written again" "$T/a.log" && pass "ns1: logged that the status row is written again" || fail "ns1: no recovery line"

echo "== S1: the watchers' connections are terminated: they reconnect and apply what was requested meanwhile"
pq "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = 'karidns-dbloader' AND datname = '$PGDB'" > "$T/term.out"
[ "$(cat "$T/term.out")" -ge 2 ] && pass "terminated $(cat "$T/term.out") loader connection(s)" || fail "fewer than two loader connections were found to terminate ($(cat "$T/term.out"))"
setaddr z1.test 192.0.2.16
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
for p in $PORT_A $PORT_B; do
    if wait_ans "$p" www.z1.test 192.0.2.16 20000; then pass "port $p applied the request made while its watcher was disconnected ($WAIT_MS ms)"; else fail "port $p did not apply it (got '$got')"; fi
done
for s in ns1 ns2; do
    wait_row $s "^13|true|$" 20 && pass "$s: the row is at generation 13" || fail "$s: row '$(row $s)'"
done
wait_log "$T/a.log" "reload requests: the connection was lost|reload requests: cannot read the requests" 5 && pass "ns1: the lost connection was noticed" || fail "ns1: no line about the lost connection"
wait_dbst a "last applied generation 13, ok yes, status written 20[0-9][0-9]-[^,]*, last error: none" 10 && pass "ns1: dbstatus: the error is gone after the reconnect" || { fail "ns1: dbstatus after the reconnect"; kct a dbstatus | sed 's/^/         /' | head -12; }

echo "== S1: the requests cannot be read: shown, serving goes on, recovers"
pq "ALTER TABLE karidns_reload_requests RENAME TO karidns_reload_requests_off" > /dev/null
wait_dbst a "last error: cannot read the requests" 15 && wait_dbst b "last error: cannot read the requests" 15 && pass "dbstatus names the failed read of the requests" || { fail "dbstatus after the rename"; kct a dbstatus | sed 's/^/         /' | head -12; }
check_ans "ns1 keeps answering" 192.0.2.16 "$PORT_A" www.z1.test
pq "ALTER TABLE karidns_reload_requests_off RENAME TO karidns_reload_requests" > /dev/null
setaddr z1.test 192.0.2.17
request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
for p in $PORT_A $PORT_B; do
    if wait_ans "$p" www.z1.test 192.0.2.17 20000; then pass "port $p applies the next request after the table is back ($WAIT_MS ms)"; else fail "port $p: no recovery (got '$got')"; fi
done
wait_dbst a "last applied generation 14, ok yes, status written 20[0-9][0-9]-[^,]*, last error: none" 15 && pass "ns1: dbstatus: no error" || { fail "ns1: dbstatus after the recovery"; kct a dbstatus | sed 's/^/         /' | head -12; }

echo "== S1: the log"
for n in a b; do
    if grep -q "$PGDB" "$T/$n.log"; then fail "server $n: the database name (conninfo) appears in the log"; else pass "server $n: the conninfo does not appear in the log"; fi
    grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/$n.log" && fail "server $n: sanitizer report" || true
done
stop_one "$PIDA"; PIDA=""; stop_one "$PIDB"; PIDB=""

# ================================================================ S2
echo "== S2: two views, each with its own schema (database-schema)"
ALIASES=1
for ip in 127.0.0.2 127.0.0.3; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else ALIASES=0; fi
done
if [ "$ALIASES" = 0 ]; then
    echo "  [SKIP] cannot add the loopback aliases 127.0.0.2/3"
else
    pq "DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null
    for v in a b; do
        { printf 'CREATE SCHEMA karidns_test_v%s;\nSET search_path TO karidns_test_v%s;\n' "$v" "$v"; cat tests/db/pdns_schema.pgsql.sql db/karidns_ext.pgsql.sql; } > "$T/v$v.sql"
        pf "$T/v$v.sql" > /dev/null || fail "cannot create the schema karidns_test_v$v"
    done
    mkzone vw.test 10 192.0.2.10; ./tests/db/zone2sql --dialect pgsql "$T/z/vw.test.zone" > "$T/z/vw.sql" 2>/dev/null
    { echo "SET search_path TO karidns_test_va;"; cat "$T/z/vw.sql"; } > "$T/z/va_load.sql"; pf "$T/z/va_load.sql" > /dev/null
    { echo "SET search_path TO karidns_test_vb;"; cat "$T/z/vw.sql"; } > "$T/z/vb_load.sql"; pf "$T/z/vb_load.sql" > /dev/null
    conf "$T/v.conf" "$PORT_A" a 'server-id "nsv";' 'view "a" { match-clients { 127.0.0.2; }; database-schema "karidns_test_va"; };
view "b" { match-clients { 127.0.0.3; }; database-schema "karidns_test_vb"; };'
    start v
    for n in a b; do
        wait_dbst a "^reload requests (view $n): server-id nsv, last applied generation 0" 10 && pass "dbstatus: view $n has its request line" || { fail "dbstatus view $n"; kct a dbstatus | sed 's/^/         /' | head -12; }
    done
    pq "SET search_path TO karidns_test_va; UPDATE records SET content = '192.0.2.11' WHERE name = 'www.vw.test'" > /dev/null
    pq "SET search_path TO karidns_test_vb; UPDATE records SET content = '192.0.2.21' WHERE name = 'www.vw.test'" > /dev/null
    pq "SET search_path TO karidns_test_va; INSERT INTO karidns_reload_requests DEFAULT VALUES" > /dev/null
    SRCB=127.0.0.2
    if wait_ans "$PORT_A" www.vw.test 192.0.2.11 15000; then pass "a request in the schema of view a reloads view a ($WAIT_MS ms)"; else fail "view a did not reload (got '$got')"; fi
    SRCB=127.0.0.3
    sleep 2
    check_ans "view b was not touched" 192.0.2.10 "$PORT_A" www.vw.test
    [ "$(pq "SET search_path TO karidns_test_va; SELECT generation || '|' || ok FROM karidns_server_status WHERE server_id = 'nsv'")" = "1|true" ] && pass "the status row is in the schema of view a" || fail "view a status row"
    [ "$(pq "SET search_path TO karidns_test_vb; SELECT count(*) FROM karidns_server_status")" = "0" ] && pass "no status row in the schema of view b" || fail "view b has a status row"
    pq "SET search_path TO karidns_test_vb; INSERT INTO karidns_reload_requests DEFAULT VALUES" > /dev/null
    if wait_ans "$PORT_A" www.vw.test 192.0.2.21 15000; then pass "a request in the schema of view b reloads view b ($WAIT_MS ms)"; else fail "view b did not reload (got '$got')"; fi
    wait_dbst a "^reload requests (view b): server-id nsv, last applied generation 1, ok yes" 10 && pass "dbstatus: view b is at generation 1" || fail "dbstatus view b after its request"
    SRCB=""
    kill -0 "$PIDA" 2>/dev/null && pass "the server is up" || fail "the server died"
    stop_one "$PIDA"; PIDA=""
fi

# ================================================================ S3
echo "== S3: a database without the multi-server tables"
pq "DROP SCHEMA IF EXISTS karidns_test_va CASCADE; DROP SCHEMA IF EXISTS karidns_test_vb CASCADE; DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null
newdb || { fail "cannot create the schema"; exit 1; }
addz z1.test 10 192.0.2.10
pq "DROP TABLE karidns_reload_requests, karidns_server_status" > /dev/null
conf "$T/s3.conf" "$PORT_A" s3 ''
start s3
check_ans "the zone is served" 192.0.2.10 "$PORT_A" www.z1.test
sleep 3
kct s3 dbstatus | grep -q "^reload requests" && fail "dbstatus shows reload requests for a database without the tables" || pass "dbstatus has no reload requests line"
grep -q "reload requests" "$T/s3.log" && { fail "the log mentions reload requests"; grep "reload requests" "$T/s3.log" | head -3 | sed 's/^/         /'; } || pass "nothing about reload requests in the log"
stop_one "$PIDA"; PIDA=""

echo "== S3: no server-id: the host name"
pq "DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null
newdb || { fail "cannot create the schema"; exit 1; }
addz z1.test 10 192.0.2.10
HN=$(hostname)
if [ -z "$HN" ] || [ ${#HN} -gt 64 ] || printf '%s' "$HN" | grep -q "['\"\\\\]"; then
    echo "  [SKIP] the host name '$HN' cannot be used as a server id here"
else
    start s3
    setaddr z1.test 192.0.2.30
    request "INSERT INTO karidns_reload_requests DEFAULT VALUES"
    wait_row "$HN" "^1|true|$" 15 && pass "the row is under the host name '$HN'" || fail "no row for the host name '$HN' (rows: $(pq "SELECT server_id FROM karidns_server_status"))"
    wait_dbst s3 "server-id $HN, last applied generation 1" 10 && pass "dbstatus shows the host name as server-id" || fail "dbstatus without server-id"
    stop_one "$PIDA"; PIDA=""
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_reload_requests_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_reload_requests_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

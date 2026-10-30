#!/bin/sh
# run_db_park_test.sh - queries for a database zone that is not in memory (D1a milestone 2: the park table, the fetch stream, the wake-up), with
# the real karidns, the real karidns-dbloader and SQLite3.
#
# Nothing in the server takes a zone out of memory yet (that comes with memory-limit), so the test uses karidns-evict: karidns built with
# the TEST-ONLY control command `karictl evict <zone>` (make evict; the command does not exist in any other build), which puts a DB zone
# in the state of an evicted one: in the directory, no data in memory.  `evict` answers OK only for a zone that is in memory, so a second
# `evict` after a query shows that the query brought the zone back through the fetch stream.  Checked:
#   - a UDP query and a TCP query for an evicted zone are answered with the data of the database (parked, fetched, woken)
#   - NOTIFY and UPDATE (UDP and TCP) for an evicted zone are answered at once (REFUSED) and do not fetch the zone
#   - an UPDATE (UDP and TCP) for an evicted zone parks, the zone is read, the UPDATE is applied and the zone stays in memory (pinned, dbstatus)
#   - a karictl reconfig that adds a zone does not drop the zone that is out of memory (it still parks, fetches and answers)
#   - TCP: three queries in one write (the first one for the evicted zone) are answered in order; a client that closes while its request
#     is parked does not hurt the server; after a parked query the connection ends by tcp-idle-timeout
#   - the loader does not answer (stopped): the answer after park-timeout is SERVFAIL + Extended DNS Error 14 (Not Ready), UDP and TCP;
#     `karictl reload <zone>` with db-reload-timeout 1 gets the timeout error (control_park_timeouts)
#   - the stopped loader goes on: its late answer installs the zone
#   - kill -9 of the loader: the supervisor starts another with a new pair of streams and fetches work again
#   - no sanitizer report in the server log (karidns-evict is an ASan + UBSan build)
# Needs root (the loader runs as nobody).  SKIP when karidns-evict, dag, karictl, karidns-dbloader (SQLite3), zone2sql, sqlite3 or perl is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
# the server with the test hook: ./karidns when it has it (the instrumented build of `make coverage` does), else ./karidns-evict (make evict)
has_hook() { [ -x "$1" ] && grep -q 'no such zone in memory' "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_hook ./karidns; then KARIDNS=./karidns; else KARIDNS=./karidns-evict; fi
fi
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
has_hook "$KARIDNS" || { echo "SKIP: $KARIDNS has no test hook (make evict)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_park.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    LP=$(loader_pid 2>/dev/null)
    [ -n "$LP" ] && kill -CONT "$LP" 2>/dev/null
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
ADDED=""
ALIAS=""
if ifconfig lo0 2>/dev/null | grep -q "inet 127.0.0.2 " || [ "$(uname -s)" = "Linux" ]; then ALIAS=127.0.0.2
elif ifconfig lo0 inet 127.0.0.2/32 alias 2>/dev/null; then ALIAS=127.0.0.2; ADDED=127.0.0.2; fi

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"      # (the evict command leaks the entries it takes out of memory on purpose; no effect on a build without ASan)

mkdir "$T/db" "$T/z"
chown nobody "$T/db"; chmod 777 "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
for n in a b c d; do
    cat > "$T/z/$n.test.zone" <<EOF
\$ORIGIN $n.test.
\$TTL 300
@ SOA ns1.$n.test. host.$n.test. 1 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.80
EOF
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/$n.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
done
sqlite3 "$T/db/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-DNSUPDATE-FROM', '127.0.0.1' FROM domains WHERE name IN ('b.test', 'c.test');"
chmod 666 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; directory "$T/z"; listen-on { 127.0.0.1; }; port $PORT; tcp-idle-timeout 3000ms; tcp-connection-reuse yes; allow-query { 127.0.0.1; };
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 1; park-timeout 1000; acl-ceiling { 127.0.0.1; }; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF

wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
loader_pid() { pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1; }
q() {   # q ZONE-OWNER [dag options]: the A record, short
    n=$1; shift
    ./dag @127.0.0.1 -p "$PORT" "$n" A +short +nohexdump +time=5 +tries=1 "$@" 2>/dev/null | head -1
}
evict() { $KCTL evict "$1" 2>&1; }
evicted() { evict "$1" | grep -q '^OK' && pass "$2" || fail "$2 (karictl evict: $(evict "$1" | head -1))"; }
resident_again() {   # the zone is in memory again: evict says OK (and takes it out again, so a query brings it back for the next step)
    evict "$1" | grep -q '^OK' && pass "$2" || fail "$2"
    q "www.${1%.}" > /dev/null
}

echo "== start"
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
wait_log "$T/srv.log" "\[DB\] initial load complete" 60 && pass "the startup batch is complete" || { fail "no 'initial load complete' line"; sed 's/^/         /' "$T/srv.log" | tail -20; }
[ "$(q www.a.test)" = "192.0.2.80" ] && [ "$(q www.b.test)" = "192.0.2.80" ] && pass "both zones answer from memory" || fail "the zones do not answer"

echo "== UDP and TCP query for an evicted zone"
evicted a.test. "a.test is out of memory (the test hook)"
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "the UDP query is answered with the data of the database" || fail "UDP: '$(q www.a.test)'"
resident_again a.test. "... and the zone is in memory again (it came through the fetch stream)"
evicted a.test. "a.test is out of memory again"
[ "$(q www.a.test +tcp)" = "192.0.2.80" ] && pass "the TCP query is answered with the data of the database" || fail "TCP: '$(q www.a.test +tcp)'"
resident_again a.test. "... and the zone is in memory again"

echo "== allow-query is evaluated before the query parks"
if [ -z "$ALIAS" ]; then
    echo "  [SKIP] no loopback alias 127.0.0.2 for a client that may not ask"
else
    evicted a.test. "a.test is out of memory"
    for tr in "" "+tcp"; do
        out=$(./dag @127.0.0.1 -b "$ALIAS" -p "$PORT" www.a.test A $tr +nohexdump +time=5 +tries=1 2>&1)
        echo "$out" | grep -q 'REFUSED' && pass "${tr:-UDP}: a client that may not ask is REFUSED" || fail "${tr:-UDP}: not REFUSED: $(echo "$out" | head -4)"
        echo "$out" | grep -qi 'not ready' && fail "${tr:-UDP}: the refused client learned that the zone is in the database"
    done
    # the zone is still out of memory: nothing was fetched for the refused clients (evict says OK only for a zone in memory)
    evict a.test. | grep -q '^ERROR' && pass "... and the zone was not fetched for them" || fail "the zone was fetched for a client that may not ask"
    [ "$(q www.a.test)" = "192.0.2.80" ] && pass "a client that may ask still waits for the zone and gets the answer" || fail "the allowed client got no answer"
fi

echo "== NOTIFY and UPDATE for an evicted zone neither park nor fetch"
evicted a.test. "a.test is out of memory"
for tr in udp tcp; do
    got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" "$tr-op" 4 a.test 2>&1)
    echo "$got" | grep -q 'rcode=5$' && pass "$tr: NOTIFY is REFUSED at once ($got)" || fail "$tr: NOTIFY: $got"
    got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" "$tr-op" 5 a.test 2>&1)
    echo "$got" | grep -q 'rcode=5$' && pass "$tr: UPDATE without allow-update is REFUSED at once ($got)" || fail "$tr: UPDATE: $got"
done
evict a.test. | grep -q '^ERROR' && pass "... and the zone was not fetched for them" || fail "NOTIFY/UPDATE fetched the zone"
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "a query still brings the zone back" || fail "a.test does not answer after the NOTIFY/UPDATE probes"

echo "== UPDATE for an evicted zone: the zone is read, the UPDATE is applied, the zone is kept in memory"
evicted b.test. "b.test is out of memory"
got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" udp-update b.test 2>&1)
echo "$got" | grep -q 'rcode=0$' && pass "udp: the UPDATE of an evicted zone is applied (NOERROR: $got)" || fail "udp UPDATE: $got"
[ "$(q new.b.test)" = "192.0.2.99" ] && pass "the added record is served" || fail "new.b.test: '$(q new.b.test)'"
evict b.test. | grep -q '^ERROR' && pass "the zone with the UPDATE is not taken out of memory (design 12-8)" || fail "b.test was taken out of memory after an UPDATE"
$KCTL dbstatus 2>/dev/null | grep -q '^updated: 1 zone' && pass "karictl dbstatus shows the pinned zone" || fail "dbstatus: $($KCTL dbstatus 2>&1 | grep updated)"
evicted c.test. "c.test is out of memory"
got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" tcp-update c.test 2>&1)
echo "$got" | grep -q 'rcode=0$' && pass "tcp: the UPDATE of an evicted zone is applied (NOERROR: $got)" || fail "tcp UPDATE: $got"
[ "$(q new.c.test +tcp)" = "192.0.2.99" ] && pass "the added record is served (TCP)" || fail "new.c.test: '$(q new.c.test +tcp)'"

echo "== a reconfig that adds a zone keeps the zone that is out of memory"
cat > "$T/z/extra.test.zone" <<EOF
\$ORIGIN extra.test.
\$TTL 300
@ SOA ns1.extra.test. host.extra.test. 1 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.81
EOF
chmod 644 "$T/z/extra.test.zone"
evicted a.test. "a.test is out of memory"
echo "zone \"extra.test\" { type master; file \"extra.test.zone\"; };" >> "$T/k.conf"      # (the zone directory is opened at the start)
out=$($KCTL reconfig 2>&1)
echo "$out" | grep -qi 'error\|fail' && fail "reconfig: $out"
sleep 1
[ "$(q www.extra.test)" = "192.0.2.81" ] && pass "the new zone answers" || fail "the zone added by the reconfig does not answer"
evict a.test. | grep -q '^ERROR' && pass "a.test is still out of memory after the reconfig (not dropped)" || fail "the reconfig brought a.test back or lost it: $(evict a.test. | head -1)"
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "a query for a.test still parks, fetches and is answered" || fail "a.test does not answer after the reconfig"
resident_again a.test. "... and it came through the fetch stream"

echo "== TCP: pipelining, EOF while parked, idle timeout after a parked query"
evicted a.test. "a.test is out of memory"
got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" pipeline www.a.test www.b.test www.a.test 2>&1)
want=$(printf 'id=101 rcode=0 an=1\nid=102 rcode=0 an=1\nid=103 rcode=0 an=1')
[ "$got" = "$want" ] && pass "three queries in one write: three answers, in order" || { fail "pipelined answers: $got"; }
evicted a.test. "a.test is out of memory"
perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" eof www.a.test > /dev/null 2>&1
sleep 2
kill -0 "$SRV" 2>/dev/null && [ "$(q www.b.test +tcp)" = "192.0.2.80" ] && pass "a client that closed while its request was parked did not hurt the server" || fail "the server does not answer after an EOF while parked"
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "the zone that was fetched for it answers" || fail "a.test does not answer after the EOF case"
evict a.test. > /dev/null
got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" idle www.a.test 2>&1)
echo "$got" | grep -q '^id=301 rcode=0 an=1' && pass "the parked TCP query is answered" || fail "idle probe: $got"
secs=$(echo "$got" | sed -n 's/^closed after \([0-9]*\)\..*/\1/p')
[ -n "$secs" ] && [ "$secs" -le 5 ] && pass "the connection ends by tcp-idle-timeout (3 s) or at once, not later (${secs} s)" || fail "idle: $got"

echo "== the loader does not answer: the time is up"
LP=$(loader_pid)
[ -n "$LP" ] && kill -STOP "$LP" || fail "no loader process"
evicted a.test. "a.test is out of memory"
T0=$(date +%s)
out=$(./dag @127.0.0.1 -p "$PORT" www.a.test A +nohexdump +time=8 +tries=1 2>&1)
T1=$(date +%s)
echo "$out" | grep -q 'SERVFAIL' && pass "UDP: SERVFAIL after the time is up" || fail "UDP: no SERVFAIL: $(echo "$out" | head -5)"
echo "$out" | grep -qi 'not ready' && pass "UDP: Extended DNS Error 14, Not Ready" || fail "UDP: no EDE 14 in: $(echo "$out" | grep -i 'EDE\|opt' | head -3)"
[ $((T1 - T0)) -ge 1 ] && [ $((T1 - T0)) -le 5 ] && pass "... after about park-timeout (1 s): $((T1 - T0)) s" || fail "the answer took $((T1 - T0)) s"
out=$(./dag @127.0.0.1 -p "$PORT" www.a.test A +tcp +nohexdump +time=8 +tries=1 2>&1)
echo "$out" | grep -q 'SERVFAIL' && echo "$out" | grep -qi 'not ready' && pass "TCP: SERVFAIL + EDE 14 after the time is up" || fail "TCP: $(echo "$out" | head -5)"
out=$($KCTL reload a.test. 2>&1)
echo "$out" | grep -qi 'timeout' && pass "karictl reload of a zone gets the db-reload-timeout error while the loader does not answer" || fail "reload: $out"
kill -CONT "$LP" 2>/dev/null
sleep 2
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "the loader goes on: the zone answers" || fail "a.test does not answer after SIGCONT"

echo "== the loader is killed: a new pair of streams, fetches work again"
evicted a.test. "a.test is out of memory"
LP=$(loader_pid)
kill -9 "$LP"
wait_log "$T/srv.log" "\[DB\] batch 1 complete" 30 2 && pass "the supervisor started another loader (new startup batch)" || fail "no new startup batch"
sleep 1
# the startup batch of the new loader compares digests: a zone without data in memory is sent again or fetched; either way it answers
[ "$(q www.a.test)" = "192.0.2.80" ] && pass "a query for the zone that was out of memory is answered by the new loader" || fail "a.test does not answer after the loader restart"
evicted d.test. "d.test is out of memory"
[ "$(q www.d.test)" = "192.0.2.80" ] && pass "a fetch on the new fetch stream works" || fail "d.test does not answer"
resident_again d.test. "... and it came through the new fetch stream"

if grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null; then fail "sanitizer report in the server log"; grep -m3 "AddressSanitizer\|runtime error:" "$T/srv.log"; else pass "no sanitizer report in the server log"; fi
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

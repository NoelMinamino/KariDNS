#!/bin/sh
# run_db_dironly_test.sh - the start reads the directory only (D1a milestone 4, design 3.3 and 6.3), with the real karidns, the real karidns-dbloader and SQLite3.
#
# With database { memory-limit } the loader sends the summary of a zone the Backend has no data of (settings, serial, SOA timers; no records), so a start,
# a restart of the loader and a full comparison move no zone bodies.  Checked:
#   - after the start every zone is in the directory (cold) and no zone data is in memory (resident bytes ~ 0); a pinned zone is read by itself
#   - a query for a zone loads it (fetch) and the answer is right; the second query is answered from memory
#   - kill -9 of the loader: the new loader's comparison sends no body for the zones (the zone that was loaded stays loaded, the rest stays cold)
#   - a zone that changes in the database while it is out of memory: its summary (the new serial) reaches the directory, nothing is built; a query then
#     loads the new version
#   - without memory-limit nothing changes: every zone is loaded at the start (cold 0)
# Needs root (the loader runs as nobody).  SKIP without karidns, dag, karictl, karidns-dbloader (SQLite3), sqlite3 or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=1500          # (the observatory reply is 664 bytes a zone: more than net.local.stream.sendspace, 64 KiB, so the reply needs several sends)
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dironly.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() { stop_srv; rm -rf "$T"; }
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" <<SQL
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ - 1)))
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-CACHE', 'pin' FROM domains WHERE name = 'z0200.test';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-DNSUPDATE-FROM', '127.0.0.1' FROM domains WHERE name = 'z0010.test';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf LIMIT-LINE
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; }; $1 park-timeout 4000; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/srv.log"          # (the background job below truncates it later: a "initial load complete" of the previous server must not be taken for this one's)
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 300 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
    sleep 1
}
stat() { $KCTL dbstatus 2>/dev/null | grep '^cache:' | sed -n "s/.* $1=\([0-9]*\).*/\1/p" | tail -1; }
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=5 +tries=1 2>/dev/null | head -1; }
loader_pid() { pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1; }

echo "== with memory-limit: the start reads the directory only"
conf "memory-limit 64m; fetch-rate 5000;"
start_srv
RES=$(stat resident); COLD=$(stat cold)
echo "  resident ${RES:-?} bytes, cold ${COLD:-?}"
[ "${COLD:-0}" -ge $((NZ - 2)) ] && pass "$COLD of $NZ zones are in the directory without data" || fail "only ${COLD:-?} of $NZ zones came without data"
sleep 1
RES=$(stat resident)
[ -n "$RES" ] && [ "$RES" -lt 200000 ] && pass "the zone data in memory is $RES bytes (about one zone: the pinned one was read by itself)" || fail "resident ${RES:-?} bytes; the zone bodies were streamed"
[ "$RES" -gt 0 ] && pass "the pinned zone has been read" || fail "the pinned zone is not in memory"
[ "$(q www.z0007.test)" = "192.0.2.80" ] && pass "a query for a zone without data loads it and is answered" || fail "z0007 does not answer"
RES2=$(stat resident)
[ "$RES2" -gt "$RES" ] && pass "the zone is in memory now ($RES -> $RES2 bytes)" || fail "the zone was not loaded ($RES -> $RES2)"
[ "$(q www.z0007.test)" = "192.0.2.80" ] && pass "the second query is answered from memory" || fail "second query failed"

$KCTL observatory > "$T/obs.out" 2> "$T/obs.err"; rc=$?
[ "$rc" -eq 0 ] && kill -0 "$SRV" 2>/dev/null && pass "karictl observatory with zones out of memory (rc $rc)" || fail "karictl observatory: rc $rc: $(head -3 "$T/obs.err")"

echo "== kill -9 of the loader: the comparison sends no body for the zones"
LP=$(loader_pid)
if [ -n "$LP" ]; then
    kill -9 "$LP"
    i=0; while [ $i -lt 100 ]; do NLP=$(loader_pid); [ -n "$NLP" ] && [ "$NLP" != "$LP" ] && break; sleep 0.1; i=$((i + 1)); done
    sleep 3
    RES3=$(stat resident); COLD3=$(stat cold)
    [ "$RES3" -le $((RES2 + 1000)) ] && pass "no zone body came with the new loader ($RES2 -> $RES3 bytes)" || fail "resident grew from $RES2 to $RES3 after the loader restart"
    [ "$COLD3" -ge "$COLD" ] && pass "the zones that were without data still are ($COLD3)" || fail "cold $COLD -> $COLD3"
    [ "$(q www.z0050.test)" = "192.0.2.80" ] && pass "a zone is loaded by the new loader's fetch stream" || fail "z0050 does not answer after the restart"
else
    fail "no loader process"
fi

echo "== a zone that changes while it is out of memory"
sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.z0100.test host.z0100.test 2 3600 600 86400 300' WHERE type = 'SOA' AND name = 'z0100.test';
                       UPDATE records SET content = '192.0.2.99' WHERE name = 'www.z0100.test';"
out=$($KCTL reload z0100.test 2>&1)
echo "  reload: $out"
RES4=$(stat resident)
[ "$RES4" -le $((RES3 + 20000)) ] && pass "the changed zone was not built (resident $RES3 -> $RES4)" || fail "resident grew from $RES3 to $RES4"
[ "$(q www.z0100.test)" = "192.0.2.99" ] && pass "a query loads the new version" || fail "z0100 does not give the new data"
stop_srv

wait_ans() {   # wait_ans NAME EXPECTED SECONDS: the answer for NAME becomes EXPECTED
    i=0
    while [ $i -lt $(($3 * 10)) ]; do [ "$(q "$1")" = "$2" ] && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
batches() { grep -c '\[DB\] batch [0-9]* complete: [1-9]' "$T/srv.log"; }     # batches in which the loader sent zones
db_rejected() { $KCTL dbstatus 2>/dev/null | sed -n 's/^since start: [0-9]* applied, \([0-9]*\) rejected.*/\1/p'; }
sqlite3_serial() {   # sqlite3_serial ZONE SERIAL: the zone's SOA gets that serial
    sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.$1 host.$1 $2 3600 600 86400 300' WHERE type = 'SOA' AND name = '$1';"
}

echo "== a zone that a query loaded is replaced when the database changes (the inventory knows it is in memory)"
conf "memory-limit 64m; fetch-rate 5000; auto-reload yes; poll-interval 1;"
start_srv
[ "$(q www.z0007.test)" = "192.0.2.80" ] && pass "z0007 is loaded by a query" || fail "z0007 does not answer"
[ "$(q www.z0200.test)" = "192.0.2.80" ] && pass "the pinned z0200 answers (read by the warm-up)" || fail "z0200 does not answer"
sqlite3 "$T/db/z.db" "UPDATE records SET content = '192.0.2.77' WHERE name = 'www.z0007.test'; UPDATE records SET content = '192.0.2.78' WHERE name = 'www.z0200.test';"
sqlite3_serial z0007.test 2
sqlite3_serial z0200.test 2
wait_ans www.z0007.test 192.0.2.77 15 && pass "the new data of the zone that was loaded by a query is served" || fail "z0007 still gives $(q www.z0007.test) after the database changed"
wait_ans www.z0200.test 192.0.2.78 15 && pass "the new data of the warmed, pinned zone is served" || fail "z0200 still gives $(q www.z0200.test)"
sleep 1
B1=$(batches); R1=$(db_rejected)
sleep 6
B2=$(batches); R2=$(db_rejected)
[ "$B1" = "$B2" ] && pass "no zone is sent again in the polls that follow (batches with zones: $B1 -> $B2)" || fail "the loader sends zones in every poll ($B1 -> $B2 batches with zones)"
[ "${R1:-x}" = "${R2:-y}" ] && [ "${R2:-1}" = "0" ] && pass "and none is counted as rejected ($R2)" || fail "rejected $R1 -> $R2"

echo "== an UPDATE-pinned zone is replaced by the next load from the database"
got=$(perl tests/db/dns_tcp_probe.pl 127.0.0.1 "$PORT" udp-update z0010.test 2>&1)
echo "$got" | grep -q 'rcode=0$' && pass "the UPDATE of a zone that was out of memory is applied ($got)" || fail "UPDATE: $got"
[ "$(q new.z0010.test)" = "192.0.2.99" ] && pass "the added name is served" || fail "new.z0010.test: $(q new.z0010.test)"
$KCTL dbstatus 2>/dev/null | grep -q '^updated: 1 zone' && pass "dbstatus shows the zone as pinned by the UPDATE" || fail "dbstatus: $($KCTL dbstatus 2>&1 | grep updated)"
sqlite3 "$T/db/z.db" "UPDATE records SET content = '192.0.2.55' WHERE name = 'www.z0010.test';"
sqlite3_serial z0010.test 2
wait_ans www.z0010.test 192.0.2.55 15 && pass "the database's version replaces the zone" || fail "z0010 still gives $(q www.z0010.test)"
[ -z "$(q new.z0010.test)" ] && pass "what the UPDATE added is gone" || fail "new.z0010.test is still served: $(q new.z0010.test)"
$KCTL dbstatus 2>/dev/null | grep -q '^updated: [1-9]' && fail "dbstatus still shows an UPDATE-pinned zone" || pass "the zone is no longer pinned by the UPDATE"
sleep 1
B1=$(batches)
sleep 5
B2=$(batches)
[ "$B1" = "$B2" ] && pass "no zone is sent again afterwards ($B1 -> $B2)" || fail "zones are sent again ($B1 -> $B2)"
stop_srv

echo "== without memory-limit nothing changes"
conf ""
start_srv
RESU=$($KCTL dbstatus 2>/dev/null | sed -n 's/^zone versions and IXFR deltas: database zones \([0-9]*\) bytes resident.*/\1/p')
$KCTL dbstatus 2>/dev/null | grep -q '^cache: no memory-limit' && pass "dbstatus says: no memory-limit" || fail "dbstatus shows a limit"
[ "${RESU:-0}" -gt 100000 ] && pass "every zone is loaded at the start ($RESU bytes)" || fail "resident ${RESU:-?} bytes; the zones were not loaded"
[ "$(q www.z0007.test)" = "192.0.2.77" ] && pass "and answers (with the data of the database change above)" || fail "no answer without a limit"
# every zone is in memory: the observatory reply is one record of 664 bytes a zone, many times the socket buffer (net.local.stream.sendspace, 64 KiB)
$KCTL observatory > "$T/obs2.out" 2> "$T/obs2.err"; rc=$?
NOBS=$(grep -c '^Zone: ' "$T/obs2.out")
SS=$(sysctl -n net.local.stream.sendspace 2>/dev/null || echo 0)
echo "  observatory lists $NOBS zone(s); the reply is about $((NOBS * 664)) bytes, net.local.stream.sendspace is $SS"
[ "$rc" -eq 0 ] && kill -0 "$SRV" 2>/dev/null && pass "karictl observatory with every zone in memory (rc $rc)" || fail "karictl observatory: rc $rc: $(head -3 "$T/obs2.err")"
[ "$NOBS" -ge $((NZ - 2)) ] && pass "every zone is in the reply, however long ($NOBS of $NZ)" || fail "the reply lists only $NOBS of $NZ zones"
[ "$((NOBS * 664))" -gt "${SS:-0}" ] && pass "the reply is longer than the socket buffer, so it took several sends" || fail "the reply fits the socket buffer: the test proves nothing"
stop_srv

grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

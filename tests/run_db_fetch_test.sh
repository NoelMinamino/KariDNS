#!/bin/sh
# run_db_fetch_test.sh - the loader's side of the fetch stream (D1a milestone 2, design 6.1, 6.2).
#
# tests/db/fetch_backend.c stands in for the Backend: it starts the real karidns-dbloader with the two streams (-s 3 --fetch-fd 4), answers
# the handshake of the first stream, and then sends FETCH_REQ messages on the second one.  Every answer goes through the state machine of the
# fetch stream (the rules the Backend applies to hostile input), so a loader that answers wrongly fails here as it would in the server.
# Checked:
#   - a request for a zone is answered with ZONE_BEGIN .. ZONE_DATA .. ZONE_END that carries the request id; the zone has the records of the
#     database; a request for the summary is answered with the summary flag, no data, the serial, the SOA timers and the presigned flag
#   - a SLAVE zone comes as a secondary (no data); an unknown zone, a PRODUCER zone, a zone without SOA and a range request are answered with
#     ZONE_FAILED and the reason, never with silence
#   - the queue serves priority 0 before 1 before 2 (a big zone keeps the thread busy while three requests wait)
#   - more requests than the queue holds: the surplus is answered "busy", the loader stays healthy and serves the next request
#   - bytes that are not KDB1 on the fetch stream close that stream, and a loader without its fetch stream ends with an error (the supervisor
#     starts one with a new pair); the same when the Backend just closes the fetch stream; a FETCH_REQ on the first stream is a protocol error
#     there (the loader ends with an error)
# No root needed (the loader runs as the current user).  SKIP when the sqlite3 command line tool, a compiler or a binary is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-./karidns-dbloader}
[ -x "$LOADER" ] || { echo "SKIP: $LOADER is not built"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
FB=${FETCH_BACKEND:-./fetch_backend}
[ -x "$FB" ] || { echo "SKIP: $FB is not built (make fetch_backend)"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbfetch.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }

DB="$T/zones.db"
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$DB" "PRAGMA journal_mode=WAL" > /dev/null
mkzone() {   # mkzone NAME SERIAL
    sqlite3 "$DB" "INSERT INTO domains (name, type) VALUES ('$1', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.$1 host.$1 $2 3600 600 86400 300', 300, 0, 0 FROM domains WHERE name = '$1';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.$1', 300, 0, 0 FROM domains WHERE name = '$1';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.$1', 'A', '192.0.2.80', 300, 0, 0 FROM domains WHERE name = '$1';"
}
mkzone small.test 2024010101
mkzone signed.test 77
sqlite3 "$DB" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '1' FROM domains WHERE name = 'signed.test'"
mkzone big.test 5
sqlite3 "$DB" "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 30000)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, 'h' || x || '.big.test', 'A', '192.0.2.' || (x % 250 + 1), 300, 0, 0 FROM c, domains d WHERE d.name = 'big.test'"
sqlite3 "$DB" "INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.1')"
sqlite3 "$DB" "INSERT INTO domains (name, type) VALUES ('producer.test', 'PRODUCER')"
sqlite3 "$DB" "INSERT INTO domains (name, type) VALUES ('nosoa.test', 'NATIVE')
"
sqlite3 "$DB" "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.nosoa.test', 300, 0, 0 FROM domains WHERE name = 'nosoa.test'"

run() {   # run ITEM... : the harness output in $T/out, its status in $RC
    "$FB" "$LOADER" "$DB" "$@" > "$T/out" 2> "$T/err"
    RC=$?
}
has() { grep -Eq -- "$2" "$T/out" && pass "$1" || { fail "$1"; head -8 "$T/out" | sed 's/^/         /'; echo "         ..."; tail -4 "$T/out" | sed 's/^/         /'; }; }
hasnt() { grep -Eq -- "$2" "$T/out" && { fail "$1"; sed 's/^/         /' "$T/out" | head -20; } || pass "$1"; }

echo "== a zone, a summary, a secondary, the refusals"
run req:1:small.test.:0:0 req:2:small.test.:0:1 req:3:signed.test.:0:1 req:4:slave.test.:0:0 req:5:slave.test.:1:1 req:6:nope.test.:0:0 \
    req:7:producer.test.:0:0 req:8:nosoa.test.:0:0 range:9:small.test.:a.small.test.:m.small.test. wait:9
[ $RC -eq 0 ] && pass "the harness ran to the end" || { fail "the harness failed (status $RC)"; cat "$T/out" "$T/err" | head -20; }
has "the zone: id 1, records of the database (SOA, NS, www, closing SOA), serial" '^ANS id=1 zone=small.test. kind=primary summary=0 presigned=0 serial=2024010101 rr=4 data=[1-9]'
has "the summary: no data, the serial and the SOA timers" '^ANS id=2 zone=small.test. kind=primary summary=1 presigned=0 serial=2024010101 rr=0 data=0 timers=3600,600,86400$'
has "the summary of a presigned zone carries the flag" '^ANS id=3 zone=signed.test. kind=primary summary=1 presigned=1 serial=77 rr=0 data=0'
has "a SLAVE zone comes as a secondary without data" '^ANS id=4 zone=slave.test. kind=secondary summary=0 .* rr=0 data=0'
has "the summary request of a SLAVE zone is answered by the same message" '^ANS id=5 zone=slave.test. kind=secondary'
has "an unknown zone: ZONE_FAILED with the reason" '^FAILED id=6 zone=nope.test. reason=.*not in the database'
has "a PRODUCER zone: ZONE_FAILED with the reason" '^FAILED id=7 zone=producer.test. reason=.*producer'
has "a zone without SOA: ZONE_FAILED" '^FAILED id=8 zone=nosoa.test. reason=.*SOA'
has "a range request: ZONE_FAILED, not silence" '^FAILED id=9 zone=small.test. reason=.*range'
has "the loader ended well when the Backend closed the streams" '^DONE answers=9 loader=0$'

echo "== priorities: 0 before 1 before 2 while the thread is busy"
run req:1:big.test.:1:0 begin:1 req:2:small.test.:2:0 req:3:small.test.:1:0 req:4:small.test.:0:0 wait:4
order=$(grep -E '^(ANS|FAILED)' "$T/out" | sed -E 's/^[A-Z]+ id=([0-9]+).*/\1/' | tr '\n' ' ')
[ "$order" = "1 4 3 2 " ] && pass "the answers come in the order 1 (busy), 4 (priority 0), 3 (1), 2 (2)" || { fail "answer order '$order'"; cat "$T/out"; }
has "the big zone arrived whole" '^ANS id=1 zone=big.test. kind=primary summary=0 .* rr=30004 '

echo "== more requests than the queue holds"
run req:1:big.test.:1:0 begin:1 flood:1500:small.test. sleep:6000 req:77:small.test.:0:0 begin:77 sleep:500
busy=$(grep -c 'reason=busy' "$T/out")
[ "$busy" -ge 1 ] && pass "requests beyond the queue were answered busy ($busy)" || { fail "no busy answer"; tail -5 "$T/out"; }
hasnt "no protocol error" 'PROTOCOL ERROR'
has "the loader answers the request after the flood" '^ANS id=77 zone=small.test.'
has "the loader ended well" '^DONE answers=[0-9]+ loader=0$'

echo "== hostile bytes"
run garbage:fetch req:1:small.test.:0:0 sleep:500
has "bytes that are not KDB1 close the fetch stream" '^FETCH closed$'
hasnt "no answer after the close" '^ANS'
has "a loader that has lost its fetch stream ends (the supervisor starts one with a new pair of streams)" '^LOADER ended$'
has "... with an error status" '^DONE answers=0 loader=3$'
echo "== the Backend drops the fetch stream (a protocol error of the loader, a full send buffer, memory)"
run closefetch
has "the loader ends when the fetch stream is closed" '^LOADER ended$'
has "... with an error status, the restart is the supervisor's" '^DONE answers=0 loader=3$'
run badmain
has "a FETCH_REQ on the first stream ends the loader" '^LOADER ended$'
has "... with an error status" '^DONE answers=0 loader=3$'

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

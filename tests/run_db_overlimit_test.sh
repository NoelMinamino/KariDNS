#!/bin/sh
# run_db_overlimit_test.sh - room on demand above the hard limit of memory-limit (0.7 B2 W8, P-B), with the real karidns, the real karidns-dbloader and SQLite3.
#
# With memory-limit a query for a zone that is out of memory is never refused for the zones in memory being above 110% of the limit (there is no `over-limit` option any
# more: it was removed before it was released).  It parks like any other query, the ingest thread takes the coldest zones out of memory on demand (the minimum residency only
# relaxed for zones whose queries have been answered) and fetches the zone, and the query is answered when the zone is there.  Checked:
#   - rounds of parallel queries for zones that do not fit memory-limit (24 zones of about 100 KB, memory-limit 1m, 4 queries at a time, each round at once after the last):
#     every query is answered on the first try (no EDE 14), nothing is shed, room_evictions > 0 (the zones were taken out on demand), dbstatus has no over_limit field,
#     nothing waits, is in flight or holds a place afterwards, and the zones in memory stay within a bound
#   - the same with fetch-concurrency 2 and fetch-rate 100 (the requests wait for a place and for the bucket as well as for room)
#   - reloads (karictl reconfig, changing fetch-concurrency and fetch-rate) while the rounds run: every query is still answered, nothing is lost or left behind (places,
#     the queue, the claim marks: dbstatus is idle afterwards and the server answers)
#   - karicheck: `over-limit` is not an option any more (an error), and a configuration with memory-limit has no message about it
# Needs root (the loader runs as nobody).  SKIP without karidns, dag, karictl, karicheck, karidns-dbloader (SQLite3), sqlite3 or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl ./karicheck "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=24            # zones z0001 .. z0024, 1000 A records each (a zone is about 100 KB in memory)
P=4              # queries at a time
ROUNDS=${OVERLIMIT_ROUNDS:-30}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_overlimit.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 200 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
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
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $NZ)
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.1', 300, 0, 0 FROM domains;
WITH RECURSIVE m(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM m WHERE j < 999)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || m.j || '.' || d.name, 'A', '192.0.2.' || (m.j % 250 + 1), 300, 0, 0 FROM domains d, m;
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf "EXTRA database statements"
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               memory-limit 1m; fetch-rate 5000; park-timeout 4000; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 600 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
}
dbs() { $KCTL dbstatus 2>/dev/null; }
field() {   # field LINE-PREFIX KEY: the number after KEY= on the first dbstatus line that starts with LINE-PREFIX
    dbs | grep "^$1" | head -1 | sed -n "s/.* $2=\([0-9]*\).*/\1/p"
}
waitfor() {   # waitfor SECONDS COMMAND...
    w=$1; shift
    i=0
    while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
idle() { [ "$(field fetchq in_flight)" = "0" ] && [ "$(field fetchq places)" = "0" ] && [ "$(field fetchq queued)" = "0" ] && [ "$(field cache room_waiting)" = "0" ]; }
# rounds(): ROUNDS rounds of P parallel queries for the next P zones (round after round at once), the zones in turn: the zones that do not fit memory-limit are read again and again.
# GOOD, REFUSED and ODD count the answers: the right address, SERVFAIL with EDE 14, anything else
rounds() {
    GOOD=0; REFUSED=0; ODD=0
    r=0; z=0
    while [ $r -lt "$ROUNDS" ]; do
        k=0; PIDS=""
        while [ $k -lt $P ]; do
            z=$((z % NZ + 1))
            ./dag @127.0.0.1 -p "$PORT" "www.$(printf 'z%04d' $z).test" A +nohexdump +time=8 +tries=1 > "$T/a.$k" 2>/dev/null &
            PIDS="$PIDS $!"
            k=$((k + 1))
        done
        wait $PIDS
        k=0
        while [ $k -lt $P ]; do
            o=$(cat "$T/a.$k")
            case "$o" in
                *"192.0.2.80"*) GOOD=$((GOOD + 1)) ;;
                *"status: SERVFAIL"*"EDE: 14"*) REFUSED=$((REFUSED + 1)) ;;
                *) ODD=$((ODD + 1)) ;;
            esac
            k=$((k + 1))
        done
        r=$((r + 1))
    done
}

echo "== above the hard limit every query waits for room and is answered on the first try"
conf ""
start_srv
dbs | grep -q 'over_limit' && fail "dbstatus still has an over_limit field: $(dbs | grep '^cache:')" || pass "dbstatus has no over_limit field (there is one behaviour)"
rounds
echo "  answered $GOOD, refused $REFUSED, other $ODD of $((ROUNDS * P)); $(dbs | grep '^cache:' | sed 's/.*evictions=/evictions=/')"
[ "$GOOD" = "$((ROUNDS * P))" ] && pass "all $GOOD queries were answered on the first try" || fail "answered $GOOD of $((ROUNDS * P)), refused $REFUSED, other $ODD"
[ "$(field cache shed)" = "0" ] && pass "nothing was shed" || fail "shed=$(field cache shed)"
RE=$(field cache room_evictions)
[ "${RE:-0}" -gt 0 ] && pass "zones were taken out of memory on demand ($RE, $(field cache room_relaxed) of them younger than the minimum residency)" || fail "no zone was taken out on demand: $(dbs | grep '^cache:')"
waitfor 10 idle && pass "nothing waits for room, is in flight or holds a place afterwards" || fail "fetchq: $(dbs | grep '^fetchq:'); $(dbs | grep '^cache:')"
LIM=$(field cache limit); PEAK=$(field cache peak)
[ "${PEAK:-0}" -lt $((LIM * 3)) ] && pass "the zones in memory stayed within a bound (peak $PEAK bytes, limit $LIM)" || fail "peak $PEAK against a limit of $LIM"
[ "$(field cache room_timeouts)" = "0" ] && [ "$(field fetchq queue_dropped)" = "0" ] && pass "no request ran out of time waiting" || fail "room_timeouts=$(field cache room_timeouts) queue_dropped=$(field fetchq queue_dropped)"
[ "$(field fetchq queue_full)" = "0" ] && pass "the queue never filled up" || fail "queue_full=$(field fetchq queue_full)"
stop_srv

echo "== the same with fetch-concurrency 2 and fetch-rate 100: the requests wait for a place and for the bucket as well"
conf "fetch-concurrency 2; fetch-rate 100;"
start_srv
rounds
echo "  answered $GOOD, refused $REFUSED, other $ODD of $((ROUNDS * P)); fetchq: $(dbs | grep '^fetchq:' | sed 's/.*queued=/queued=/')"
[ "$GOOD" = "$((ROUNDS * P))" ] && pass "all $GOOD queries were answered on the first try" || fail "answered $GOOD of $((ROUNDS * P)), refused $REFUSED, other $ODD"
[ "$(field cache shed)" = "0" ] && [ "$(dbs | grep '^fetch:' | sed -n 's/.* refused_by_rate=\([0-9]*\).*/\1/p')" = "0" ] && pass "nothing was shed or refused by rate" || fail "shed=$(field cache shed); $(dbs | grep '^fetch:')"
[ "$(field fetchq peak)" -le 2 ] 2>/dev/null && pass "never more than 2 fetches in flight (peak $(field fetchq peak))" || fail "peak=$(field fetchq peak) with fetch-concurrency 2"
waitfor 10 idle && pass "nothing waits, is in flight or holds a place afterwards" || fail "fetchq: $(dbs | grep '^fetchq:')"
stop_srv

echo "== reloads while the requests wait: nothing is lost, nothing is left behind"
conf ""
start_srv
( n=0; while [ $n -lt 8 ]; do
      case $((n % 4)) in
          0) conf "fetch-concurrency 3;" ;;
          1) conf "fetch-concurrency 2; fetch-rate 200;" ;;
          2) conf "fetch-concurrency 64; fetch-rate 5000;" ;;
          3) conf "" ;;
      esac
      $KCTL reconfig > /dev/null 2>&1
      sleep 0.4
      n=$((n + 1))
  done ) &
RLP=$!
rounds
wait "$RLP"
echo "  answered $GOOD, refused $REFUSED, other $ODD of $((ROUNDS * P)) (eight reloads meanwhile)"
[ "$GOOD" = "$((ROUNDS * P))" ] && pass "all $GOOD queries were answered on the first try although the configuration was reloaded eight times meanwhile" || fail "answered $GOOD of $((ROUNDS * P)), refused $REFUSED, other $ODD"
[ "$(field cache shed)" = "0" ] && pass "nothing was shed" || fail "shed=$(field cache shed)"
waitfor 10 idle && pass "nothing waits for room, is in flight or holds a place afterwards (the places, the queue and the claims are clean)" || fail "fetchq: $(dbs | grep '^fetchq:'); $(dbs | grep '^cache:')"
[ "$(./dag @127.0.0.1 -p "$PORT" www.z0001.test A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)" = "192.0.2.80" ] && pass "the server answers after the reloads" || fail "no answer after the reloads"
rounds
[ "$GOOD" = "$((ROUNDS * P))" ] && pass "and a second set of rounds is answered on the first try ($GOOD): no claim mark was left behind" || fail "second rounds: answered $GOOD of $((ROUNDS * P)), refused $REFUSED, other $ODD"
waitfor 10 idle && pass "idle again" || fail "fetchq: $(dbs | grep '^fetchq:')"
stop_srv

echo "== karicheck: over-limit is not an option any more"
kc() { ./karicheck conf "$T/k.conf" 2>&1; }
conf ""
kc | grep -q 'over-limit' && fail "karicheck mentions over-limit for a plain configuration: $(kc | grep over-limit)" || pass "a configuration with memory-limit: no message about over-limit"
conf "over-limit wait;"
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1
KRC=$?
[ "$KRC" != 0 ] && grep -qi 'over-limit' "$T/kc.out" && pass "over-limit wait is an error (unknown option): $(grep -i over-limit "$T/kc.out" | head -1)" || fail "karicheck accepted 'over-limit wait' (rc $KRC): $(head -3 "$T/kc.out")"

echo
echo "run_db_overlimit_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

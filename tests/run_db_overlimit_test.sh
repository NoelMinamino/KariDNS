#!/bin/sh
# run_db_overlimit_test.sh - database { over-limit refuse | wait } (0.7 B2 W8), with the real karidns, the real karidns-dbloader and SQLite3.
#
# With memory-limit a query for a zone that is out of memory is answered SERVFAIL + EDE 14 at once while the zones in memory are above 110% of the limit (over-limit
# refuse, the default).  With over-limit wait it parks like any other query: the ingest thread takes the coldest zones out of memory on demand (the minimum residency only
# relaxed for zones whose queries have been answered) and fetches the zone, and the query is answered when the zone is there.  Checked:
#   - rounds of parallel queries for zones that do not fit memory-limit (24 zones of about 100 KB, memory-limit 1m, 4 queries at a time, each round at once after the last):
#       refuse: every answer is the right one or "not ready" (SERVFAIL + EDE 14), `shed` of dbstatus counts the refusals, dbstatus says over_limit=refuse and the room counters are 0
#       wait:   every query is answered on the first try (no EDE 14), nothing is shed, dbstatus says over_limit=wait and room_evictions > 0 (the zones were taken out on demand),
#               nothing waits or is in flight afterwards and no place is held; the zones in memory stay within a bound
#   - a reload (karictl reconfig) switches the mode both ways, and the server keeps answering
#   - karicheck: over-limit wait without memory-limit is a warning (conf.database.over-limit), with it there is none; a value other than refuse / wait is an error
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
mode() { dbs | grep '^cache:' | head -1 | sed -n 's/.* over_limit=\([a-z]*\).*/\1/p'; }
wait_mode() {   # wait_mode refuse|wait: dbstatus shows the mode within 5 s
    i=0; while [ $i -lt 50 ] && [ "$(mode)" != "$1" ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(mode)" = "$1" ]
}
waitfor() {   # waitfor SECONDS COMMAND...
    w=$1; shift
    i=0
    while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
idle() { [ "$(field fetchq in_flight)" = "0" ] && [ "$(field fetchq places)" = "0" ] && [ "$(field cache room_waiting)" = "0" ]; }
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

echo "== over-limit refuse (the default): the old behaviour"
conf ""
start_srv
wait_mode refuse && pass "dbstatus: over_limit=refuse" || fail "dbstatus cache line: $(dbs | grep '^cache:')"
rounds
echo "  answered $GOOD, refused (SERVFAIL + EDE 14) $REFUSED, other $ODD of $((ROUNDS * P)); shed=$(field cache shed) evictions=$(field cache evictions)"
[ "$ODD" = 0 ] && pass "every query was answered or got 'not ready' (SERVFAIL, EDE 14)" || fail "$ODD queries got neither an answer nor 'not ready'"
[ "$GOOD" -gt 0 ] && pass "queries for zones out of memory were answered ($GOOD)" || fail "no query was answered"
SH=$(field cache shed)
[ "${SH:-x}" = "$REFUSED" ] && pass "shed counts the refusals ($SH)" || fail "shed=$SH but $REFUSED queries were refused"
[ "$(field cache room_evictions)" = "0" ] && [ "$(field cache room_waits)" = "0" ] && [ "$(field cache room_timeouts)" = "0" ] && pass "no room was made on demand" || fail "room counters: $(dbs | grep '^cache:')"
[ "$REFUSED" -gt 0 ] && pass "the zones in memory went over 110% of memory-limit: $REFUSED queries were refused at once" || echo "  (no query was refused: the rounds did not push the zones over 110% this time)"
waitfor 10 idle && pass "nothing is in flight or held afterwards" || fail "fetchq: $(dbs | grep '^fetchq:')"
REFUSE_REF=$REFUSED
stop_srv

echo "== over-limit wait: the same rounds, every query answered on the first try"
conf "over-limit wait;"
start_srv
wait_mode wait && pass "dbstatus: over_limit=wait" || fail "dbstatus cache line: $(dbs | grep '^cache:')"
rounds
echo "  answered $GOOD, refused $REFUSED, other $ODD of $((ROUNDS * P)); $(dbs | grep '^cache:' | sed 's/.*evictions=/evictions=/')"
[ "$GOOD" = "$((ROUNDS * P))" ] && pass "all $GOOD queries were answered on the first try (the refuse run refused $REFUSE_REF)" || fail "answered $GOOD of $((ROUNDS * P)), refused $REFUSED, other $ODD"
[ "$(field cache shed)" = "0" ] && pass "nothing was shed" || fail "shed=$(field cache shed)"
RE=$(field cache room_evictions)
[ "${RE:-0}" -gt 0 ] && pass "zones were taken out of memory on demand ($RE, $(field cache room_relaxed) of them younger than the minimum residency)" || fail "no zone was taken out on demand: $(dbs | grep '^cache:')"
waitfor 10 idle && pass "nothing waits for room, is in flight or holds a place afterwards" || fail "fetchq: $(dbs | grep '^fetchq:'); $(dbs | grep '^cache:')"
LIM=$(field cache limit); PEAK=$(field cache peak)
[ "${PEAK:-0}" -lt $((LIM * 3)) ] && pass "the zones in memory stayed within a bound (peak $PEAK bytes, limit $LIM)" || fail "peak $PEAK against a limit of $LIM"
[ "$(field cache room_timeouts)" = "0" ] && pass "no request ran out of time waiting for room" || fail "room_timeouts=$(field cache room_timeouts)"
dbs | grep -q '^cache:.* over_limit=wait ' && pass "the cache line still says over_limit=wait" || fail "cache line: $(dbs | grep '^cache:')"

echo "== a reload switches the mode, both ways"
conf ""
$KCTL reconfig > /dev/null 2>&1
wait_mode refuse && pass "after karictl reconfig without over-limit: over_limit=refuse" || fail "mode after reconfig: '$(mode)'"
[ "$(./dag @127.0.0.1 -p "$PORT" www.z0001.test A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)" = "192.0.2.80" ] && pass "the server answers" || fail "no answer after the reload to refuse"
conf "over-limit wait;"
$KCTL reconfig > /dev/null 2>&1
wait_mode wait && pass "after karictl reconfig with over-limit wait: over_limit=wait" || fail "mode after reconfig: '$(mode)'"
rounds
[ "$GOOD" = "$((ROUNDS * P))" ] && pass "the rounds are answered on the first try after the switch ($GOOD)" || fail "after the switch: answered $GOOD of $((ROUNDS * P)), refused $REFUSED, other $ODD"
waitfor 10 idle && pass "nothing waits or is held afterwards" || fail "fetchq: $(dbs | grep '^fetchq:')"
stop_srv

echo "== karicheck: the option is checked"
kc() { ./karicheck conf "$T/k.conf" 2>&1; }
conf "over-limit wait;"
kc | grep -q 'over-limit' && fail "karicheck complains about over-limit wait with memory-limit: $(kc | grep over-limit)" || pass "over-limit wait with memory-limit: no message about it"
sed 's/memory-limit 1m;//' "$T/k.conf" > "$T/k2.conf"
./karicheck conf "$T/k2.conf" 2>&1 | grep -q 'over-limit wait has no effect without memory-limit' && pass "over-limit wait without memory-limit is a warning" || fail "no warning: $(./karicheck conf "$T/k2.conf" 2>&1 | grep -i over-limit)"
conf "over-limit sometimes;"
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1
KRC=$?
[ "$KRC" != 0 ] && grep -q 'over-limit' "$T/kc.out" && pass "over-limit sometimes is an error (refuse or wait): $(grep over-limit "$T/kc.out" | head -1)" || fail "karicheck accepted 'over-limit sometimes' (rc $KRC): $(head -3 "$T/kc.out")"

echo
echo "run_db_overlimit_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]

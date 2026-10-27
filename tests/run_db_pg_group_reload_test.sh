#!/bin/sh
# run_db_pg_group_reload_test.sh - the PostgreSQL driver reads the changed zones of a reload several at a time (scan_records_in /
# scan_metadata_in / scan_ext_in: one statement per table for up to 128 zones, instead of fifteen round trips for each zone).
#
# 700 zones in PostgreSQL, a server that serves them; 160 of them (22.9%, below the default bulk-threshold of 25%, so the loader reads
# them as a group of 128 and a group of 32, not with one scan of everything) change in one transaction: a new address for www, a new
# SOA serial for some, the zone type for one (NATIVE -> SLAVE: no records are read for it, its data go away), and one zone is deleted.
# Checked after `karictl reload`: every changed zone serves exactly what the database says (first, last and the borders of the groups,
# and every seventh), the others are untouched, the loader log says that 160 zones were read and sent (not 700), and a second reload
# with nothing changed reads and sends nothing.  The byte-for-byte equality with the one-zone-at-a-time read is
# checked by tests/test_db_pgsql.c (scan_*_in against scan_*); here the whole path is run.
#
# Needs root (the server starts as root and drops to nobody; the loader runs as the unprivileged PostgreSQL user).  SKIP otherwise, and
# when PostgreSQL is not reachable (tests/db/pg_lib.sh) or a binary is missing.
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
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pggroup.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
pg_setup pggroup || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
N=700
CH=160

install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
pg_conninfo_file "$T/ci"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 30; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
LOG="$T/srv.log"
KCTL="./karictl -c $T/karictl.conf"
qa() { ./dag @127.0.0.1 -p $PORT "$1" A +short +nohexdump 2>/dev/null; }
status_of() { ./dag @127.0.0.1 -p $PORT "$1" A +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
check_ans() { got=$(qa "$2"); [ "$got" = "$3" ] && pass "$1" || fail "$1 (got '$got', want '$3')"; }
wait_log() {   # wait_log PATTERN SECONDS [COUNT]
    i=0; want=${3:-1}
    while [ $i -lt $(($2 * 10)) ]; do
        [ "$(grep -Ec -- "$1" "$LOG" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { fail "cannot create the schema"; exit 1; }
# zone g<i>.test: SOA (serial 1), NS, ns1 A, www A 192.0.2.(i % 200 + 1)
pq "INSERT INTO domains (name, type) SELECT 'g' || i || '.test', 'NATIVE' FROM generate_series(1, $N) i;
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
      SELECT d.id, d.name, 'SOA', 'ns1.' || d.name || '. host.' || d.name || '. 1 3600 600 86400 300', 300, 0, false FROM domains d;
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, d.name, 'NS', 'ns1.' || d.name || '.', 300, 0, false FROM domains d;
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT d.id, 'ns1.' || d.name, 'A', '192.0.2.250', 300, 0, false FROM domains d;
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
      SELECT d.id, 'www.' || d.name, 'A', '192.0.2.' || (substring(d.name from 2 for position('.' in d.name) - 2)::int % 200 + 1), 300, 0, false FROM domains d;
    ANALYZE domains; ANALYZE records" > /dev/null || { fail "cannot fill the database"; exit 1; }

: > "$LOG"
"$KARIDNS" -c "$T/k.conf" -f > "$LOG" 2>&1 &
SRV=$!
if wait_log "\[DB\] initial load complete" 60; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; tail -20 "$LOG" | sed 's/^/         /'; fi
check_ans "g1: www before" www.g1.test 192.0.2.2
check_ans "g$N: www before" www.g$N.test 192.0.2.$((N % 200 + 1))

BASE=$(pq "SELECT coalesce(max(seq), 0) FROM karidns_changes")
# 160 zones change: ids 100..259 -> new www address; ids divisible by 5 of them also get serial 2; zone 150 becomes SLAVE; zone 200 is deleted
pq "BEGIN;
    UPDATE records SET content = '192.0.2.201' WHERE type = 'A' AND name LIKE 'www.%' AND domain_id BETWEEN 100 AND 259;
    UPDATE records SET content = replace(content, ' 1 3600', ' 2 3600') WHERE type = 'SOA' AND domain_id BETWEEN 100 AND 259 AND domain_id % 5 = 0;
    UPDATE domains SET type = 'SLAVE', master = '192.0.2.77' WHERE id = 150;
    DELETE FROM domains WHERE id = 200;
    COMMIT" > /dev/null || fail "cannot edit the database"
CHG=$(pq "SELECT count(DISTINCT domain_id) FROM karidns_changes WHERE seq > $BASE")
[ "$CHG" = "$CH" ] && pass "the change log lists $CH zones" || fail "the change log lists '$CHG' zones, want $CH"

$KCTL reload > "$T/reload.out" 2>&1
i=0; while [ $i -lt 600 ]; do grep -Eq "karidns-dbloader.* batch [0-9]+ \(diff\) sent" "$LOG" && break; sleep 0.1; i=$((i + 1)); done
sleep 1
grep "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG" | tail -1 | sed 's/^/         /'
# the zone of id 150 (SLAVE) is read (its metadata) but sends nothing as a primary; id 200 is a ZONE_DELETE
if grep "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG" | tail -1 | grep -Eq "(159|160|161) zone\(s\) read"; then pass "the batch read the $CH changed zones, not $N"; else fail "the batch did not read about $CH zones"; fi
grep "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG" | tail -1 | grep -q " 1 deleted" && pass "the deleted zone went as ZONE_DELETE" || fail "no ZONE_DELETE in the batch"

for i in 99 100 101 127 128 129 130 140 149 151 227 228 229 230 258 259 260 261; do
    if [ "$i" -ge 100 ] && [ "$i" -le 259 ]; then want=192.0.2.201; else want=192.0.2.$((i % 200 + 1)); fi
    check_ans "g$i www after the reload" www.g$i.test "$want"
done
bad=0
i=100; while [ $i -le 259 ]; do
    if [ $i -ne 150 ] && [ $i -ne 200 ]; then [ "$(qa www.g$i.test)" = "192.0.2.201" ] || { bad=$((bad + 1)); echo "         g$i: '$(qa www.g$i.test)'"; }; fi
    i=$((i + 7))
done
[ "$bad" = 0 ] && pass "every seventh changed zone serves its new address" || fail "$bad changed zones are wrong"
[ "$(status_of www.g200.test)" = "REFUSED" ] && pass "the deleted zone is gone" || fail "the deleted zone still answers ($(status_of www.g200.test))"
SERIAL=$(./dag @127.0.0.1 -p $PORT g105.test SOA +short +nohexdump 2>/dev/null | awk '{print $3}')
[ "$SERIAL" = "2" ] && pass "g105 serves SOA serial 2" || fail "g105 serves SOA serial '$SERIAL'"
SERIAL=$(./dag @127.0.0.1 -p $PORT g106.test SOA +short +nohexdump 2>/dev/null | awk '{print $3}')
[ "$SERIAL" = "1" ] && pass "g106 (www changed, serial kept) serves SOA serial 1" || fail "g106 serves SOA serial '$SERIAL'"

# nothing changed: nothing is read, nothing is sent
before=$(grep -c "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG")
$KCTL reload > "$T/reload2.out" 2>&1
i=0; while [ $i -lt 300 ]; do [ "$(grep -c "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG")" -gt "$before" ] && break; sleep 0.1; i=$((i + 1)); done
sleep 0.5
if grep "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG" | tail -1 | grep -q " 0 zone(s) read, 0 sent"; then pass "a second reload reads and sends nothing"; else fail "the second reload read zones"; grep "karidns-dbloader.* batch [0-9]* (diff) sent" "$LOG" | tail -1 | sed 's/^/         /'; fi

echo "=== run_db_pg_group_reload_test: $PASS passed, $FAILS failed ==="
[ "$FAILS" -eq 0 ]

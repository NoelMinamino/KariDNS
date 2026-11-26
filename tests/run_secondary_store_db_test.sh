#!/bin/sh
# run_secondary_store_db_test.sh - the database secondaries (SLAVE, CONSUMER) keep what they transferred in the zone store (0.7, P3).
#
# planing_0.7.x_secondary_store.md 3.3, 4.4, 5 and section 13, integration test 15.  A primary P1 (zone files) and the server under test S whose zones
# come from a SQLite3 database (tests/db/pdns_schema.sqlite3.sql + db/karidns_ext.sqlite3.sql) with `database { store "<dir>"; }`.  The SLAVE and CONSUMER
# zones of the database are transferred from P1; their copies are records of the store's reserved view.  Checked:
#   1. the copies are written (xfr.records, dbstatus says a copy is kept; P4: the `Store:` lines of zonestatus and dbstatus);
#   2. a restart with the database file moved away (the loader cannot read it) and P1 down: the SLAVE zones and the catalog consumer's member are answered from
#      their copies at once (the restore jobs of the ingest thread, without the loader);
#   3. a restart with the database back and P1 up: the restore jobs and the loader's jobs of the same zones make one entry per zone (dbstatus `status applied`,
#      no transfer: the copy is up to date); a row deleted while stopped, a row renamed (same domains.id) and a SLAVE made NATIVE take their copies with them
#      (the zone goes, the renamed zone is transferred under its new name, the NATIVE zone answers from its rows);
#   4. purge_view: S reads the zones of another database file (the view's identity changes): the store drops the view's records and with them the copies of its
#      secondaries, which are transferred again.
#
# Needs root (the loader must be root-owned and runs as nobody).  SKIP otherwise, and when karidns, dag, karictl, karidns-dbloader (SQLite3 driver), zone2sql
# or the sqlite3 CLI is missing.  KARIDNS=./karidns-asan runs it on the ASan build.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
. "$ROOT/tests/lib_proc.sh"

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_secstdb.XXXXXX") || exit 1
chmod 755 "$T"
P1=""; SRV=""
stop_pid() {   # stop_pid PID CONF: TERM, a bounded wait for the manager (it stops its children first), then whatever is left of CONF is killed
    [ -n "$1" ] || return 0
    kill -TERM "$1" 2>/dev/null
    i=0; while [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$1" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -0 "$1" 2>/dev/null && { echo "  (pid $1 did not stop after TERM: killed)"; kari_kill_tree "$1"; }
    wait "$1" 2>/dev/null
    kari_kill_conf "$2"
    i=0; while [ $i -lt 100 ] && [ -n "$(kari_conf_pids "$2")" ]; do sleep 0.1; i=$((i + 1)); done
    return 0
}
cleanup() {
    stop_pid "$SRV" "$T/s.conf"
    stop_pid "$P1" "$T/p1.conf"
    if [ -n "${KARI_KEEP:-}" ]; then echo "kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -f "$T/s.log" ] && tail -n 25 "$T/s.log" | sed 's/^/         s: /'; }
BASE=$(kari_port 0 $((20000 + $$ % 20000)))
PM1=$BASE; PS=$((BASE + 1))
DAG="./dag @127.0.0.1 -p $PS"
S_CTL="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

# ---------------------------------------------------------------- fixtures
mkdir "$T/db" "$T/z"
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS: the zone file text (refresh one hour: a refresh after a restore asks the SOA once, nothing else)
    cat <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
EOF
}
mkzone slv.test 10 192.0.2.10 > "$T/z/slv.zone"
mkzone del.test 10 192.0.2.12 > "$T/z/del.zone"
mkzone ren.test 10 192.0.2.13 > "$T/z/ren.zone"
mkzone ren2.test 10 192.0.2.14 > "$T/z/ren2.zone"
mkzone nat.test 10 192.0.2.15 > "$T/z/nat.zone"
mkzone m1.test 1 192.0.2.41 > "$T/z/m1.zone"
cat > "$T/z/cat.zone" <<EOF
\$ORIGIN cat.test.
\$TTL 300
@ SOA ns1.cat.test. hostmaster.cat.test. 1 3600 600 86400 60
@ NS invalid.
version TXT "2"
uid1.zones PTR m1.test.
EOF
{
    echo "options { user \"nobody\"; pid-file \"none\"; listen-on { 127.0.0.1; }; port $PM1; };"
    for z in slv del ren ren2 nat m1 cat; do echo "zone \"$z.test\" { type primary; file \"$T/z/$z.zone\"; allow-transfer { 127.0.0.1; }; };"; done
} > "$T/p1.conf"

sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
sq() { sqlite3 "$T/db/z.db" "$@"; }
for z in slv del ren nat; do sq "INSERT INTO domains (name, master, type) VALUES ('$z.test', '127.0.0.1:$PM1', 'SLAVE')"; done
sq "INSERT INTO domains (name, master, type) VALUES ('cat.test', '127.0.0.1:$PM1', 'CONSUMER')"
mkzone prim.test 3 192.0.2.30 > "$T/z/prim.zone"
./tests/db/zone2sql --dialect sqlite3 "$T/z/prim.zone" 2>/dev/null | sq
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$S_CTL"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
mkdir "$T/store"
write_sconf() {   # write_sconf DBFILE
    cat > "$T/s.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PS;
    database { driver sqlite3; database-file "$1"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 4; store "$T/store"; };
};
control-channel { socket "$T/ctl.sock"; secret "$S_CTL"; };
EOF
}

ans() { $DAG "$@" +short +nohexdump +time=1 +tries=1 2>/dev/null; }
wait_ans() {   # wait_ans EXPECTED QNAME QTYPE [SECONDS]
    i=0; max=$(( ${4:-15} * 10 ))
    while [ $i -lt $max ]; do
        [ "$(ans "$2" "$3")" = "$1" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
rcode() { $DAG "$1" SOA +nohexdump +time=1 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
wait_rcode() {   # wait_rcode WANT ZONE [SECONDS]
    i=0; max=$(( ${3:-15} * 10 ))
    while [ $i -lt $max ]; do
        [ "$(rcode "$2")" = "$1" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
dbst() { $KCTL dbstatus "$@" 2>&1; }
xfr() { $KCTL store -k 2>/dev/null | awk -F= -v k="$1" '$1 == k { print $2 }'; }
wait_xfr() {   # wait_xfr KEY OP VALUE SECONDS (OP: -ge, -eq, -le)
    i=0
    while [ "$i" -lt $(($4 * 10)) ]; do
        v=$(xfr "$1")
        [ -n "$v" ] && [ "$v" "$2" "$3" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
transfers() { $KCTL observatory "$1" 2>/dev/null | sed -n 's/.*Transfers (In): *\(AXFR=[0-9]* IXFR=[0-9]*\).*/\1/p'; }
start_p1() {
    "$KARIDNS" -c "$T/p1.conf" -f > "$T/p1.log" 2>&1 &
    P1=$!
    kari_wait_answer ./dag "$PM1" slv.test. 15 || { fail "P1 did not start"; tail -5 "$T/p1.log"; }
}
start_s() {   # start_s: the log of this run is s.log (the one before is appended to s.all)
    [ -f "$T/s.log" ] && cat "$T/s.log" >> "$T/s.all"
    "$KARIDNS" -c "$T/s.conf" -f > "$T/s.log" 2>&1 &
    SRV=$!
    i=0
    while ! $KCTL status > /dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 200 ] || { fail "S did not start"; return 1; }
        kill -0 "$SRV" 2>/dev/null || { fail "S exited"; return 1; }
        sleep 0.1
    done
}

# ================================================================ 1. the copies are written
echo "== 1. the copies of the database secondaries"
start_p1
write_sconf "$T/db/z.db"
start_s
if kari_wait_log "$T/s.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; fi
for zw in slv:192.0.2.10 del:192.0.2.12 ren:192.0.2.13 nat:192.0.2.15 m1:192.0.2.41; do
    z=${zw%%:*}; w=${zw#*:}
    wait_ans "$w" "www.$z.test" A 20 && pass "$z.test transferred, www answers" || fail "$z.test does not answer"
done
wait_ans 192.0.2.30 www.prim.test A 20 && pass "the NATIVE zone prim.test answers" || fail "prim.test does not answer"
# slv del ren nat cat (database kinds 4 and 5) and the member m1 (kind 3)
wait_xfr xfr.records -ge 6 20 && pass "xfr.records: the six copies are stored ($(xfr xfr.records))" || fail "xfr.records $(xfr xfr.records), want 6"
dbst slv.test | grep -q "transfer: last successful .*serial 10 (a copy is kept in the zone store" && pass "dbstatus: a copy is kept in the zone store" || { fail "dbstatus slv.test"; dbst slv.test | sed 's/^/         /'; }
# P4 (11): the `Store:` lines of a database secondary, in zonestatus and (indented) in dbstatus; the copy is written after the install, so it is waited for
i=0; until $KCTL zonestatus slv.test 2>&1 | grep -q "^Store: copy serial 10, "; do i=$((i + 1)); [ "$i" -lt 50 ] || break; sleep 0.2; done
$KCTL zonestatus slv.test 2>&1 | grep -q "^Store: copy serial 10, " && $KCTL zonestatus slv.test 2>&1 | grep -q "^Last-refresh: 20" && pass "zonestatus: the Store: and Last-refresh: lines of a database secondary" || { fail "zonestatus slv.test"; $KCTL zonestatus slv.test 2>&1 | sed 's/^/         /'; }
dbst slv.test | grep -q "^  Store: copy serial 10, " && pass "dbstatus: the Store: line of a database secondary" || { fail "dbstatus slv.test Store:"; dbst slv.test | sed 's/^/         /'; }
# the store's figures for the database are not the copies' (a copy is no zone of a database view)
OUT=$(dbst)
printf '%s\n' "$OUT" | grep -q "^ *store pass:" && pass "dbstatus has its store pass line" || true

# ================================================================ 2. the database and the primary away
echo "== 2. restart with the database file moved away and P1 down"
stop_pid "$SRV" "$T/s.conf"; SRV=""
stop_pid "$P1" "$T/p1.conf"; P1=""
mv "$T/db/z.db" "$T/db/z.db.away"
start_s
kari_wait_log "$T/s.log" "\[DB\] secondaries: [1-9][0-9]* database secondary zone(s) restored from their stored copies" 15 && pass "the restore jobs ran without the loader: $(grep -o '[0-9]* database secondary zone(s) restored' "$T/s.log" | tail -1)" || fail "no restore line of the database secondaries"
for zw in slv:192.0.2.10 del:192.0.2.12 ren:192.0.2.13 nat:192.0.2.15 m1:192.0.2.41; do
    z=${zw%%:*}; w=${zw#*:}
    wait_ans "$w" "www.$z.test" A 10 && pass "$z.test answered from its copy (no database, no primary)" || fail "$z.test is not answered from its copy"
done
grep -q "ECAPMODE\|Not permitted in capability mode" "$T/s.log" && fail "ECAPMODE in the log" || pass "no ECAPMODE"

# ================================================================ 3. back: one entry per zone; deleted, renamed, NATIVE while stopped
echo "== 3. restart with the database back and P1 up; rows changed while stopped"
stop_pid "$SRV" "$T/s.conf"; SRV=""
mv "$T/db/z.db.away" "$T/db/z.db"
sq "DELETE FROM domains WHERE name = 'del.test'"
sq "UPDATE domains SET name = 'ren2.test' WHERE name = 'ren.test'"
NID=$(sq "SELECT id FROM domains WHERE name = 'nat.test'")
sq "UPDATE domains SET type = 'NATIVE', master = NULL WHERE id = $NID"
sq "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($NID, 'nat.test', 'SOA', 'ns1.nat.test. host.nat.test. 20 3600 600 86400 300', 300), ($NID, 'nat.test', 'NS', 'ns1.nat.test', 300), ($NID, 'ns1.nat.test', 'A', '192.0.2.1', 300), ($NID, 'www.nat.test', 'A', '192.0.2.99', 300)"
start_p1
start_s
kari_wait_log "$T/s.log" "\[DB\] initial load complete" 20 && pass "the startup batch is complete" || fail "no 'initial load complete' line"
wait_ans 192.0.2.10 www.slv.test A 10 && pass "slv.test answers" || fail "slv.test"
OUT=$(dbst slv.test)
[ "$(printf '%s\n' "$OUT" | grep -c '^zone slv.test')" = 1 ] && printf '%s\n' "$OUT" | grep -q "status applied" && pass "dbstatus: one slv.test, applied (the restore job and the loader's job made one entry)" || { fail "dbstatus slv.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
sleep 2   # (a window for a second transfer that must not happen)
# P1 sends its settings with the zone (Extended AXFR v3, `settings=primary`); they are not kept with the copy until P4 (design D5, R2), so the first refresh after a restore asks for the
# whole zone once: one AXFR at most, never a transfer per entry (the restore job and the loader's job of slv.test made one entry)
case "$(transfers slv.test)" in
    "AXFR=0 IXFR=0"|"AXFR=1 IXFR=0") pass "slv.test: at most one transfer after the restart ($(transfers slv.test))" ;;
    *) fail "slv.test transfers: '$(transfers slv.test)'" ;;
esac
wait_rcode REFUSED del.test 20 && pass "del.test (row deleted while stopped) is gone" || fail "del.test is still served"
wait_rcode REFUSED ren.test 20 && pass "ren.test (renamed while stopped) is gone under its old name" || fail "ren.test is still served"
wait_ans 192.0.2.14 www.ren2.test A 20 && pass "ren2.test (the same domains.id) is transferred under its new name" || fail "ren2.test does not answer"
wait_ans 192.0.2.99 www.nat.test A 20 && pass "nat.test (SLAVE -> NATIVE while stopped) answers from its rows" || { fail "nat.test as NATIVE"; dbst nat.test | sed 's/^/         /'; }
wait_ans 192.0.2.41 www.m1.test A 10 && pass "the member m1.test answers" || fail "m1.test"
# copies now: slv, cat, m1, ren2 (del, ren and nat went)
wait_xfr xfr.records -eq 4 20 && pass "xfr.records: 4 (the copies of del.test, ren.test and nat.test were deleted, ren2.test stored)" || { fail "xfr.records $(xfr xfr.records), want 4"; $KCTL store -k 2>/dev/null | grep '^xfr\.' | sed 's/^/         /'; }

# ================================================================ 4. purge_view: another database file
echo "== 4. another database file: the view's records and the copies of its secondaries are dropped"
stop_pid "$SRV" "$T/s.conf"; SRV=""
cp "$T/db/z.db" "$T/db/z2.db"; chown nobody "$T/db/z2.db"; chmod 600 "$T/db/z2.db"
write_sconf "$T/db/z2.db"
start_s
kari_wait_log "$T/s.log" "were read from another database: they are dropped" 15 && pass "the store dropped the view's zones (purge_view)" || fail "no purge line"
kari_wait_log "$T/s.log" " 0 database secondary zone(s) restored from their stored copies, [1-9][0-9]* copy(ies) of zones no longer in the database deleted" 15 && pass "the restore jobs found no record of the reconcile: no zone restored, the copies went ($(grep -o "[0-9]* copy(ies) of zones no longer" "$T/s.log" | tail -1))" || { fail "no line of the restore jobs with the copies deleted"; grep -F "[DB] secondaries:" "$T/s.log" | sed "s/^/         /"; }
wait_ans 192.0.2.10 www.slv.test A 20 && pass "slv.test is transferred again" || fail "slv.test does not answer after the purge"
i=0; while [ $i -lt 100 ] && [ "$(transfers slv.test)" != "AXFR=1 IXFR=0" ]; do sleep 0.1; i=$((i + 1)); done
[ "$(transfers slv.test)" = "AXFR=1 IXFR=0" ] && pass "one AXFR of slv.test (its copy had gone with the view)" || fail "slv.test transfers: '$(transfers slv.test)'"

if grep -q "AddressSanitizer\|runtime error:" "$T/s.log" "$T/s.all" "$T/p1.log" 2>/dev/null; then fail "sanitizer report in a server log"; fi
echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_secondary_store_db_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_secondary_store_db_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

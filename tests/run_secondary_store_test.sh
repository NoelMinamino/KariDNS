#!/bin/sh
# ==============================================================================
# tests/run_secondary_store_test.sh - the secondaries keep what they transferred in the zone store (0.7)
# ==============================================================================
# planing_0.7.x_secondary_store.md section 13 (integration).  A primary and a secondary on 127.0.0.1; the secondary has
# options { zone-store "<dir>"; } and no database block (D1).  Zones have REFRESH 2 / RETRY 1 and EXPIRE 8 or 20, with
# min-refresh-time 1, min-retry-time 1 as tests/run_zone_type_secondary_test.sh.
#
#  1. restart with the primary down: the stored copy is answered at the first query, no transfer, zonestatus "Store: copy"
#  2. the expire clock is not reset by a restart (RFC 1034 §4.3.5): (a) expired while stopped -> SERVFAIL + EDE 24 at once (EDE 3 with
#     serve-stale); (b) not yet expired -> expires on the original schedule
#  3. an up-to-date-only zone (from `file`, never transferred) keeps its expire clock across a restart (M2)
#  4. IXFR on a stored base after a restart
#  5. the downstream EXPIRE option after a restart is the remaining time (RFC 7314 §3)
#  6. slave -> master + reconfig: the copy is deleted by the GC; master -> slave starts without a copy
#  7. file vs store (D7): a retransfer to a lower serial, then a restart with the older high-serial file: the store wins; a newer file
#     with a greater serial wins
#  8. disk full (KARIDNS_TEST_XFR_PUT_FAIL): the put fails, a restart serves the previous copy
#  9. a kill between the install and the put (KARIDNS_TEST_XFR_KILL_BEFORE_PUT): the previous copy, then a refresh
# 10. an unclean stop and a start under another boot id (store_repair): the copy is restored
# 11. quarantine (damaged superblocks): the ERROR line, the server starts, the zone transfers again
# 12. catalog zones (RFC 9432): restart with the primary down -> catalog and members answered; the catalog's copy unusable at the
#     restart -> the members' copies are kept (GC exemption) and restored when the catalog arrives; a change of ownership with the same
#     unique-id across a restart keeps the copy; a unique-id change while stopped resets that member
# 16. zone-store none: no store; a config-only server: the store is made, Capsicum on, no ECAPMODE
# 17. secondary-stale-max: EDE 3 up to the limit, then SERVFAIL + EDE 24 and the stale-limit ERROR
# D9. the `[Zone] secondary-expired:` lines (expired, still-expired, refreshed, summary above 20 zones)
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
. "$DIR/lib_proc.sh"

for b in karicheck karidns dag karictl; do
    [ -x "$ROOT/$b" ] || make -C "$ROOT" "$b"
done
KARICHECK="$ROOT/karicheck"
KARIDNS="$ROOT/karidns"
DAG="$ROOT/dag"
KARICTL="$ROOT/karictl"

W="$(mktemp -d /tmp/secstore.XXXXXX)"
chmod 755 "$W"
PPORT=$(kari_port 0 $((25000 + $$ % 5000)))
SPORT=$((PPORT + 1))
PPID_=""
SPID=""

cleanup() {
    set +e
    [ -n "$PPID_" ] && kari_kill_tree "$PPID_"
    [ -n "$SPID" ] && kari_kill_tree "$SPID"
    kari_kill_conf "$W/primary.conf" "$W/secondary.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

NPASS=0
pass() { NPASS=$((NPASS + 1)); echo "[OK] $*"; }
fail() {
    echo "[FAIL] $*"
    [ -f "$W/q.txt" ] && sed 's/^/    q: /' "$W/q.txt"
    [ -f "$W/s.log" ] && tail -40 "$W/s.log" | sed 's/^/    s: /'
    exit 1
}

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"

# zone <name> <serial> <expire> [extra]: a zone file of the primary
zone() {
    cat > "$W/p/$1.zone.tmp" <<EOF
\$ORIGIN $1.
\$TTL 60
@    IN SOA ns1 hostmaster $2 2 1 $3 60
@    IN NS  ns1
ns1  IN A   192.0.2.1
www  IN A   192.0.2.$(( $2 % 200 + 1 ))
${4:-}
EOF
    mv "$W/p/$1.zone.tmp" "$W/p/$1.zone"
}
mkdir -p "$W/p" "$W/s"
zone sec.test 1 20
zone exp.test 1 8
zone file.test 5 20
zone gc.test 1 20
zone d7.test 50 20
zone m1.test 1 20
zone m2.test 1 20
for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21; do zone "s$i.test" 1 4; done
catalog() { # serial m2-unique-id [extra]
    cat > "$W/p/cat.test.zone" <<EOF
\$ORIGIN cat.test.
\$TTL 60
@ IN SOA ns1 hostmaster $1 2 1 20 60
@ IN NS ns1
ns1 IN A 192.0.2.1
version IN TXT "2"
u1.zones IN PTR m1.test.
$2.zones IN PTR m2.test.
${3:-}
EOF
}
catalog 1 u2
cat > "$W/p/cat2.test.zone" <<EOF
\$ORIGIN cat2.test.
\$TTL 60
@ IN SOA ns1 hostmaster 1 2 1 20 60
@ IN NS ns1
ns1 IN A 192.0.2.1
version IN TXT "2"
EOF

pzone() { echo "zone \"$1\" { type primary; file \"$W/p/$1.zone\"; allow-transfer { 127.0.0.1; }; $2 };"; }
write_primary() { # [extra zones]
    {
        echo "options { port $PPORT; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
        for z in sec.test exp.test file.test gc.test d7.test m1.test m2.test; do pzone "$z" ""; done
        for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21; do pzone "s$i.test" ""; done
        pzone cat.test "catalog-zone yes;"
        pzone cat2.test "catalog-zone yes;"
    } > "$W/primary.conf"
}
write_primary

# (sec.test takes no settings from its primary: its refresh after a restore is an IXFR; the others take them, and their first refresh after a restore is a whole transfer, R2)
szone() { _ps=""; [ "$1" = sec.test ] && _ps="primary-settings no;"; echo "zone \"$1\" { type secondary; masters { 127.0.0.1 port $PPORT; }; $_ps $2 };"; }
# write_secondary <options extra> <zones...>: the secondary's configuration (zone-store "$W/store" unless the extra says otherwise)
write_secondary() {
    _opt="$1"
    shift
    {
        echo "options { port $SPORT; bind-address { 127.0.0.1; }; pid-file \"none\"; min-refresh-time 1; min-retry-time 1; $USER_OPT $_opt };"
        echo "control-channel { socket \"$W/ctl.sock\"; algorithm hmac-sha256; secret \"$SECRET\"; };"
        for z in "$@"; do echo "$z"; done
    } > "$W/secondary.conf"
}
printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$W/ctl.sock" "$SECRET" > "$W/karictl.conf"
chmod 600 "$W/karictl.conf"
ctl() { "$KARICTL" -f "$W/karictl.conf" "$@" 2>&1; }
STORE="zone-store \"$W/store\";"

start_primary() {
    "$KARIDNS" -f "$W/primary.conf" > "$W/p.log" 2>&1 &
    PPID_=$!
    kari_wait_answer "$DAG" "$PPORT" sec.test. 15 || { cat "$W/p.log"; fail "the primary did not start"; }
}
stop_primary() { [ -n "$PPID_" ] && kari_kill_tree "$PPID_"; PPID_=""; sleep 0.3; }
# start_secondary [env...]: the log of this run is $W/s.log (the one before is appended to $W/s.all)
start_secondary() {
    [ -f "$W/s.log" ] && cat "$W/s.log" >> "$W/s.all"
    env "$@" "$KARIDNS" -f "$W/secondary.conf" > "$W/s.log" 2>&1 &
    SPID=$!
    i=0
    while ! ctl status > /dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "the secondary did not start"
        kill -0 "$SPID" 2>/dev/null || fail "the secondary exited"
        sleep 0.1
    done
}
stop_secondary() { [ -n "$SPID" ] && kari_kill_tree "$SPID"; SPID=""; kari_kill_conf "$W/secondary.conf"; sleep 0.3; }

q() { # name type [dag options]
    _n=$1; _t=$2; shift 2
    "$DAG" @127.0.0.1 -p "$SPORT" "$_n" "$_t" +nohexdump +norec +time=1 +tries=1 "$@" > "$W/q.txt" 2>&1 || true
}
serial_of() { q "$1" SOA; awk -v z="$1." '$4 == "SOA" && $1 == z { print $7 }' "$W/q.txt"; }
wait_serial() { # zone serial seconds
    i=0
    while [ "$i" -lt $(($3 * 5)) ]; do
        [ "$(serial_of "$1")" = "$2" ] && return 0
        sleep 0.2
        i=$((i + 1))
    done
    return 1
}
xfr() { ctl store -k | awk -F= -v k="$1" '$1 == k { print $2 }'; }
wait_xfr_ge() { # key value seconds
    i=0
    while [ "$i" -lt $(($3 * 5)) ]; do
        v=$(xfr "$1")
        [ -n "$v" ] && [ "$v" -ge "$2" ] && return 0
        sleep 0.2
        i=$((i + 1))
    done
    return 1
}

for c in primary secondary; do
    write_secondary "$STORE" "$(szone sec.test '')"
    "$KARICHECK" conf "$W/$c.conf" > "$W/kc.txt" 2>&1 || { cat "$W/kc.txt"; fail "karicheck rejected $c.conf"; }
done

# --- karicheck: zone-store and the reserved view name -------------------------------------------------------------------------
cat > "$W/bad1.conf" <<EOF
options { zone-store "/nonexistent/a"; database { driver sqlite3; database-file "/nonexistent/z.db"; store "/nonexistent/b"; }; };
EOF
cat > "$W/bad2.conf" <<EOF
view "_karidns-xfr" { match-clients { any; }; };
EOF
"$KARICHECK" conf "$W/bad1.conf" > "$W/kc.txt" 2>&1 && fail "karicheck accepted zone-store and a different database store"
grep -q "name different stores" "$W/kc.txt" || { cat "$W/kc.txt"; fail "karicheck: no message for zone-store vs database store"; }
"$KARICHECK" conf "$W/bad2.conf" > "$W/kc.txt" 2>&1 && fail "karicheck accepted the reserved view name"
grep -q "is reserved" "$W/kc.txt" || { cat "$W/kc.txt"; fail "karicheck: no message for the reserved view name"; }
pass "karicheck: zone-store against a different database store, and the view name _karidns-xfr, are errors"

ALLZ="$(szone sec.test '') $(szone exp.test '')"
# =========================================================================================================== 1, 2, 5, D9
start_primary
write_secondary "$STORE serve-stale no;" "$(szone sec.test '')" "$(szone exp.test '')" "$(szone file.test "file \"$W/s/file.test.zone\";")"
# file.test: the secondary's own file, of the primary's serial, two days old: never transferred, only up to date (M2)
sed 's/^www .*/www  IN A   192.0.2.6/' "$W/p/file.test.zone" > "$W/s/file.test.zone"
touch -t "$(date -v-2d +%Y%m%d%H%M 2>/dev/null || date -d '2 days ago' +%Y%m%d%H%M)" "$W/s/file.test.zone"
start_secondary
wait_serial sec.test 1 10 || fail "sec.test was not transferred"
wait_serial exp.test 1 10 || fail "exp.test was not transferred"
wait_xfr_ge xfr.puts 2 10 || fail "the copies were not stored (xfr.puts $(xfr xfr.puts))"
wait_xfr_ge xfr.puts_uptodate 1 10 || fail "the up-to-date-only file.test was not stored whole (xfr.puts_uptodate $(xfr xfr.puts_uptodate))"
ctl zonestatus sec.test > "$W/zs.txt"
grep -q "^Store: copy serial 1, " "$W/zs.txt" || { cat "$W/zs.txt"; fail "zonestatus has no Store: copy line"; }
grep -q "^Last-refresh: 20" "$W/zs.txt" || { cat "$W/zs.txt"; fail "zonestatus has no Last-refresh line"; }
[ -d "$W/store" ] || fail "the config-only server made no store directory"
grep -q "ECAPMODE" "$W/s.log" && fail "ECAPMODE in the log of the config-only server"
pass "a config-only secondary stores its copies (zone-store, the reserved view; no ECAPMODE); zonestatus shows the copy; the up-to-date-only zone is stored whole"
sleep 2
TKILLP=$(date +%s)
stop_primary
stop_secondary
sleep 9                                                     # exp.test (EXPIRE 8) expires while both are stopped; sec.test (EXPIRE 20) does not
T0=$(date +%s)
start_secondary KARIDNS_TEST_STALE_LOG_INTERVAL=2
q www.sec.test A
grep -q "status: NOERROR" "$W/q.txt" && grep -q "192.0.2.2" "$W/q.txt" || fail "1: the stored copy of sec.test was not answered at the first query after the restart"
grep -q "Successfully transferred" "$W/s.log" && fail "1: a transfer after the restart (the primary is down)"
kari_wait_log "$W/s.log" "secondaries: [0-9]* restored (1 expired while stopped)" 5 || fail "1: no start summary line of the restore"
ctl zonestatus sec.test > "$W/zs.txt"
grep -q "^Store: copy serial 1" "$W/zs.txt" || { cat "$W/zs.txt"; fail "1: zonestatus after the restart"; }
pass "1: restart with the primary down: the copy is answered at once, no transfer"
q exp.test SOA
grep -q "status: SERVFAIL" "$W/q.txt" && grep -q "EDE: 24" "$W/q.txt" || fail "2a: exp.test expired while stopped is not SERVFAIL + EDE 24 at once"
grep -q "\[Zone\] secondary-expired: expired zone 'exp.test.' view '[^']*' expired while stopped at" "$W/s.log" || fail "D9: no 'expired while stopped' line"
pass "2a: a zone that expired while stopped answers SERVFAIL + EDE 24 from the first query"
q file.test SOA
grep -q "status: NOERROR" "$W/q.txt" || fail "3: the up-to-date-only zone lost its expire clock (its file is two days old)"
pass "3: the up-to-date-only zone keeps its expire clock across the restart"
# 5: the EXPIRE option is the time left of the restored deadline (RFC 7314 §3)
q sec.test SOA +expire
EXP=$(sed -n 's/^; EXPIRE: \([0-9]*\).*/\1/p' "$W/q.txt")
[ -n "$EXP" ] && [ "$EXP" -gt 0 ] && [ "$EXP" -le $((20 - (T0 - TKILLP) + 1)) ] || fail "5: EXPIRE option $EXP after the restart (left: at most $((20 - (T0 - TKILLP))))"
pass "5: the EXPIRE option after the restart is the time left ($EXP s)"
kari_wait_log "$W/s.log" "secondary-expired: still-expired zone 'exp.test.'" 6 || fail "D9: no hourly still-expired line (interval 2 s for the test)"
# 2b: sec.test expires on its original schedule: 20 s after the last refresh, not 20 s after the restart
i=0
while :; do
    q www.sec.test A
    grep -q "status: SERVFAIL" "$W/q.txt" && break
    i=$((i + 1))
    [ "$i" -lt 150 ] || fail "2b: sec.test did not expire"
    sleep 0.2
done
T1=$(date +%s)
[ $((T1 - TKILLP)) -le 23 ] || fail "2b: sec.test expired $((T1 - TKILLP)) s after the last refresh (EXPIRE 20): the restart reset the clock"
pass "2b: a zone not yet expired at the restart expires on its original schedule ($((T1 - TKILLP)) s after the primary went away)"
start_primary
wait_serial exp.test 1 10 || fail "exp.test was not refreshed when the primary came back"
kari_wait_log "$W/s.log" "secondary-expired: refreshed zone 'exp.test.' view '[^']*' serving again, serial 1" 10 || fail "D9: no refreshed line"
kari_wait_log "$W/p.log" "transfer of .exp.test/IN.: Extended AXFR started (serial 1)" 5 || fail "R2: the restored copy whose primary settings were not kept did not ask for the whole zone"
pass "R2: a restored copy with received settings asks for the whole zone once (serial unchanged)"
pass "D9: expired / still-expired / refreshed lines with the fixed prefix"
# 4: IXFR on the stored base
zone sec.test 2 20 "new IN A 192.0.2.99"
kill -HUP "$PPID_"
wait_serial sec.test 2 10 || fail "4: sec.test did not move to serial 2"
grep -q "IXFR started.*serial 1 -> 2\|IXFR.*1 -> 2" "$W/p.log" || { grep -i "xfr" "$W/p.log" | tail -5; fail "4: the refresh from the restored copy was not an IXFR"; }
pass "4: IXFR from the restored copy (serial 1 -> 2)"
stop_secondary

# =========================================================================================================== 8, 9, 10
# 8: no room for the put (the fault knob of the tests): the old copy and its state stay
zone sec.test 3 20
kill -HUP "$PPID_"
start_secondary KARIDNS_TEST_XFR_PUT_FAIL=1000
wait_serial sec.test 3 10 || fail "8: sec.test did not move to serial 3"
wait_xfr_ge xfr.put_nospc 1 10 || fail "8: the put did not fail"
kari_wait_log "$W/s.log" "no room for the copy of secondary zone" 5 || fail "8: no WARNING for the put without room"
stop_secondary
stop_primary
start_secondary
[ "$(serial_of sec.test)" = 2 ] || fail "8: after the put without room the restart does not serve the previous copy (serial $(serial_of sec.test))"
pass "8: a put without room keeps the previous copy; the restart serves it"
stop_secondary
# 9: killed between the install of serial 3 and its put
start_primary
start_secondary KARIDNS_TEST_XFR_KILL_BEFORE_PUT=sec.test.
i=0
while kill -0 "$SPID" 2>/dev/null && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
grep -q "KARIDNS_TEST_XFR_KILL_BEFORE_PUT" "$W/s.log" || fail "9: the kill point was not reached"
stop_secondary
stop_primary
start_secondary
[ "$(serial_of sec.test)" = 2 ] || fail "9: after a kill between install and put the restart does not serve the previous copy"
start_primary
wait_serial sec.test 3 10 || fail "9: no refresh after the restart"
wait_xfr_ge xfr.puts 1 10 || fail "9: the copy was not stored by the refresh"
pass "9: a kill between the install and the put: the previous copy, then the refresh"
# 10: an unclean stop (kill -9 right after the put) and a start under another boot id: the derived tables are rebuilt, the copy is good
stop_secondary
start_secondary KARIDNS_TEST_STORE_BOOT_ID=4242
[ "$(serial_of sec.test)" = 3 ] || fail "10: the copy after a start under another boot id"
[ "$(xfr store.recovery.rebuilt)" = 1 ] || fail "10: the store did not rebuild its tables under another boot id"
pass "10: an unclean stop and another boot id: the tables are rebuilt, the copy is restored"
stop_secondary

# =========================================================================================================== 7 (D7)
# d7.test: the secondary's file has serial 100; the primary's zone went down to 50 (a new primary): karictl retransfer takes 50
sed 's/ 50 2 1 20 60/ 100 2 1 20 60/' "$W/p/d7.test.zone" > "$W/s/d7.test.zone"
touch -t "$(date -v-1d +%Y%m%d%H%M 2>/dev/null || date -d '1 day ago' +%Y%m%d%H%M)" "$W/s/d7.test.zone"
write_secondary "$STORE" "$(szone sec.test '')" "$(szone d7.test "file \"$W/s/d7.test.zone\";")"
start_secondary
wait_serial d7.test 100 10 || fail "7: the file of d7.test was not loaded"
ctl retransfer d7.test > "$W/rc.txt" || { cat "$W/rc.txt"; fail "karictl retransfer"; }
wait_serial d7.test 50 10 || fail "7: karictl retransfer did not take the lower serial"
i=0; until ctl zonestatus d7.test | grep -q "^Store: copy serial 50"; do i=$((i + 1)); [ "$i" -lt 50 ] || fail "7: the retransfer was not stored"; sleep 0.2; done
stop_secondary
stop_primary
start_secondary
[ "$(serial_of d7.test)" = 50 ] || fail "7: the old file with the higher serial won against the newer copy (serial $(serial_of d7.test))"
stop_secondary
sed 's/ 50 2 1 20 60/ 101 2 1 20 60/' "$W/p/d7.test.zone" > "$W/s/d7.test.zone"        # a newer file with a greater serial
start_secondary
[ "$(serial_of d7.test)" = 101 ] || fail "7: a newer file with a greater serial did not win"
[ "$(xfr xfr.file_won)" = 1 ] || fail "7: xfr.file_won"
pass "7: D7: a retransfer to a lower serial beats the older high-serial file; a newer file with a greater serial wins"
stop_secondary

# =========================================================================================================== 6 (GC)
start_primary
cp "$W/p/gc.test.zone" "$W/s/gc.test.zone"      # (the secondary reads its file at the start: the Backend opens the directory then, a reconfig reads beneath it)
write_secondary "$STORE" "$(szone sec.test '')" "$(szone gc.test "file \"$W/s/gc.test.zone\";")"
start_secondary
wait_serial gc.test 1 10 || fail "6: gc.test was not transferred"
wait_xfr_ge xfr.records 2 10 || fail "6: gc.test was not stored"
R0=$(xfr xfr.records)
write_secondary "$STORE" "$(szone sec.test '')" "zone \"gc.test\" { type primary; file \"$W/s/gc.test.zone\"; };"
G0=$(xfr xfr.gc_deleted)
ctl reconfig > "$W/rc.txt" || { cat "$W/rc.txt"; fail "karictl reconfig"; }
wait_xfr_ge xfr.gc_deleted $((G0 + 1)) 10 || fail "6: the copy of the zone that became a primary was not deleted"
[ "$(xfr xfr.records)" -lt "$R0" ] || fail "6: xfr.records did not go down"
write_secondary "$STORE" "$(szone sec.test '')" "$(szone gc.test '')"
ctl reconfig > "$W/rc.txt" || { cat "$W/rc.txt"; fail "karictl reconfig"; }
wait_serial gc.test 1 10 || fail "6: gc.test as a secondary again did not transfer"
ctl zonestatus gc.test | grep -q "^Store: " || fail "6: zonestatus of gc.test"
pass "6: slave -> master: the copy is deleted (diff GC); master -> slave starts without a copy and transfers"
stop_secondary

# =========================================================================================================== 17, D9 summary
write_secondary "$STORE serve-stale yes;" "$(szone exp.test 'secondary-stale-max 3;')"
start_secondary
wait_serial exp.test 1 10 || fail "17: exp.test was not transferred"
stop_primary
i=0
while :; do
    q www.exp.test A
    grep -q "EDE: 3" "$W/q.txt" && break
    i=$((i + 1)); [ "$i" -lt 100 ] || fail "17: exp.test did not expire"; sleep 0.2
done
grep -q "status: NOERROR" "$W/q.txt" || fail "17: serve-stale before the limit"
i=0
while :; do
    q www.exp.test A
    grep -q "status: SERVFAIL" "$W/q.txt" && break
    i=$((i + 1)); [ "$i" -lt 50 ] || fail "17: secondary-stale-max 3 did not end the stale answers"; sleep 0.2
done
grep -q "EDE: 24" "$W/q.txt" || fail "17: SERVFAIL past secondary-stale-max without EDE 24"
kari_wait_log "$W/s.log" "secondary-expired: stale-limit zone 'exp.test.' view '[^']*' expired for .*, secondary-stale-max 3s reached: answering SERVFAIL (EDE 24) from now on" 5 ||
    fail "17: no stale-limit ERROR"
pass "17: secondary-stale-max: EDE 3 up to the limit, then SERVFAIL + EDE 24 and the stale-limit line"
stop_secondary
# D9: more than 20 expired zones: one summary line instead of the per-zone lines (the event lines above 20 a minute are counted in it)
start_primary
write_secondary "$STORE serve-stale yes; transfers-per-ns 64; transfers-in 64;" "$(szone exp.test 'secondary-stale-max 3;')" \
    "$(for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21; do szone "s$i.test" ''; done)"
start_secondary KARIDNS_TEST_STALE_LOG_INTERVAL=2
wait_serial exp.test 1 10 || fail "D9: exp.test was not transferred"
wait_serial s21.test 1 20 || fail "D9: s21.test was not transferred"
stop_primary
kari_wait_log "$W/s.log" "secondary-expired: summary: 22 zone(s) expired (21 serving stale, 1 SERVFAIL), oldest '" 20 || fail "D9: no summary line above 20 expired zones"
[ "$(xfr secondary.expired_zones)" = 22 ] || fail "D9: secondary.expired_zones"
q www.s01.test A
grep -q "EDE: 3" "$W/q.txt" || fail "D9: a stale answer of s01.test"
[ "$(xfr secondary.stale_answers)" -ge 1 ] || fail "D9: secondary.stale_answers"
pass "D9: the summary line above 20 expired zones; the counters"
stop_secondary

# =========================================================================================================== 12 (catalog)
start_primary
CATZ="zone \"cat.test\" { type secondary; masters { 127.0.0.1 port $PPORT; }; catalog-zone yes; };"
CAT2Z="zone \"cat2.test\" { type secondary; masters { 127.0.0.1 port $PPORT; }; catalog-zone yes; };"
write_secondary "$STORE" "$CATZ" "$CAT2Z"
start_secondary
wait_serial m1.test 1 15 || fail "12: the member m1.test was not transferred"
wait_serial m2.test 1 15 || fail "12: the member m2.test was not transferred"
wait_xfr_ge xfr.records 4 10 || fail "12: the catalog and its members were not stored"
stop_secondary
stop_primary
start_secondary
[ "$(serial_of m1.test)" = 1 ] && [ "$(serial_of m2.test)" = 1 ] && [ "$(serial_of cat.test)" = 1 ] || fail "12: catalog and members after a restart with the primary down"
pass "12: catalog and members are answered after a restart with the primary down"
stop_secondary
# the catalog's copy cannot be used at the restart (a byte of its image changed): the members are not made, their copies are kept
perl -e '
    my ($dir) = @ARGV;
    opendir(my $d, $dir) or die;
    for my $f (grep { /^seg\./ } readdir($d)) {
        open(my $h, "+<", "$dir/$f") or die; binmode $h; local $/; my $b = <$h>;
        my $p = index($b, "c.cat.test");
        next if $p < 0;
        my $o = $p + 160; substr($b, $o, 1) = chr(ord(substr($b, $o, 1)) ^ 0x55);
        seek($h, 0, 0); print $h $b; close $h; print "damaged $f at $o\n"; exit 0;
    }
    exit 1;' "$W/store" > /dev/null || fail "12: the catalog's record was not found in the segments"
start_secondary
q m1.test SOA
grep -q "status: REFUSED\|status: SERVFAIL" "$W/q.txt" || fail "12: a member was made though the catalog's copy is unusable"
[ "$(xfr xfr.restore_bad)" = 1 ] || fail "12: xfr.restore_bad"
[ "$(xfr xfr.gc_deleted)" = 0 ] || fail "12: the GC deleted the members' copies while the catalog had not refreshed"
start_primary
wait_serial cat.test 1 15 || fail "12: the catalog was not transferred"
wait_xfr_ge xfr.restored 3 15 || fail "12: the members were not restored from their kept copies when the catalog arrived"
[ "$(xfr xfr.restore_identity)" = 0 ] || fail "12: identity mismatch of a member"
pass "12: the catalog's copy unusable at the restart: the members' copies are kept and restored when the catalog arrives"
# a change of ownership with the same unique-id (RFC 9432 §5.5), then a restart: the copy is kept
catalog 2 u2 "coo.u1.zones IN PTR cat2.test."
cat >> "$W/p/cat2.test.zone" <<EOF
u1.zones IN PTR m1.test.
EOF
sed -i.bak 's/hostmaster 1 2 1 20 60/hostmaster 2 2 1 20 60/' "$W/p/cat2.test.zone"
kill -HUP "$PPID_"
wait_serial cat.test 2 10 || fail "12: catalog serial 2"
wait_serial cat2.test 2 10 || fail "12: cat2 serial 2"
kari_wait_log "$W/s.log" "CoO transfer: retained state for 'm1.test.'" 10 || fail "12: no change of ownership"
stop_secondary
stop_primary
start_secondary
[ "$(serial_of m1.test)" = 1 ] || fail "12: m1.test after the change of ownership and a restart"
[ "$(xfr xfr.restore_identity)" = 0 ] || fail "12: the change of ownership with the same unique-id lost the copy"
pass "12: a change of ownership with the same unique-id keeps the member's copy across a restart"
stop_secondary
# a new unique-id while stopped (RFC 9432 §5.4: a removal and a new member): that member's copy goes when the catalog says so
catalog 3 u2new "coo.u1.zones IN PTR cat2.test."
start_primary
start_secondary
wait_serial cat.test 3 15 || fail "12: catalog serial 3"
wait_xfr_ge xfr.restore_identity 1 15 || fail "12: the member with a new unique-id kept the old copy"
wait_serial m2.test 1 15 || fail "12: the reset member did not transfer"
pass "12: a unique-id change while stopped resets that member (its old copy is deleted)"
stop_secondary

# =========================================================================================================== 11 (quarantine)
dd if=/dev/urandom of="$W/store/super.a" bs=512 count=8 conv=notrunc 2>/dev/null
dd if=/dev/urandom of="$W/store/super.b" bs=512 count=8 conv=notrunc 2>/dev/null
write_secondary "$STORE" "$(szone sec.test '')"
start_secondary
kari_wait_log "$W/s.log" "secondaries: the store was quarantined: 1 secondary zone(s) start without their copy" 5 || fail "11: no ERROR line after the quarantine"
wait_serial sec.test 3 15 || fail "11: sec.test did not transfer after the quarantine"
pass "11: damaged superblocks: the store is quarantined (ERROR), the server starts, the zone transfers again"
stop_secondary

# =========================================================================================================== 16
write_secondary "zone-store none;" "$(szone sec.test '')"
rm -rf "$W/store"
start_secondary
wait_serial sec.test 3 10 || fail "16: zone-store none: no transfer"
[ -d "$W/store" ] && fail "16: zone-store none made a store"
ctl zonestatus sec.test | grep -q "^Store: off" || fail "16: zonestatus with zone-store none"
pass "16: zone-store none: no store, the secondary works as before"
stop_secondary
# R2 (test 19): a zone-store that cannot be used (a file) is an ERROR and a start without the store; a secondary that a reconfiguration adds transfers (no pending bit)
echo x > "$W/notadir"
write_secondary "zone-store \"$W/notadir\";" "$(szone sec.test '')"
start_secondary
wait_serial sec.test 3 10 || fail "19: no transfer with an unusable zone-store"
kari_wait_log "$W/s.log" "the zone store is off: .*the secondary zones are kept in memory only" 5 || fail "19: no ERROR for the unusable zone-store"
write_secondary "zone-store \"$W/notadir\";" "$(szone sec.test '')" "$(szone gc.test '')"
ctl reconfig > "$W/rc.txt" || { cat "$W/rc.txt"; fail "karictl reconfig"; }
wait_serial gc.test 1 10 || fail "19: the secondary a reconfiguration added did not transfer"
grep -q "ECAPMODE" "$W/s.log" && fail "19: ECAPMODE"
pass "19: an unusable zone-store: a start without the store (ERROR), and a secondary added by reconfig transfers"
stop_secondary
stop_primary

echo "[PASS] secondary store: $NPASS checks"
exit 0

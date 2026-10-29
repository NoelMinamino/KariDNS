#!/bin/sh
# ==============================================================================
# tests/run_xfr_failover_test.sh - several primaries, the secondary timers and the transfer limits (BIND 9.20, batch 4)
# ==============================================================================
#   F  a secondary asks its primaries in the order written: the first one down -> the second answers; a primary that is behind is logged
#      ("serial number (N) received from primary ... < ours (M)") unless multi-master yes; the first primary is used again when it is
#      ahead; an up-to-date answer does not stop the search for a primary that is ahead (multi-master secondary ends at the newest serial)
#   C  min/max-refresh-time and min/max-retry-time hold the SOA's values (zonestatus shows what the zone uses; the expire timer is
#      raised to refresh + retry)
#   I  request-ixfr no (SOA first, AXFR only when the primary is ahead), provide-ixfr no (a client that is behind gets the whole zone, one that is up to date the one SOA),
#      request-expire no (the transfer request has no EXPIRE option; a mock primary logs it)
#   S  max-transfer-idle-in and max-transfer-time-in give up a stalled / endless transfer (KARIDNS_XFER_MINUTE_SECS makes a "minute" a
#      few seconds), transfers-in 1 starts one inbound transfer at a time
#   O  transfers-out refuses a transfer over the limit, max-transfer-idle-out frees the slot of a client that does not read
#   Q  serial-query-rate 1 starts one refresh check a second
# No root is needed (everything is on 127.0.0.1).
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl dag >/dev/null || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-xfrfo.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
SECRET="cDEwLXhmci1mYWlsb3Zlci10ZXN0LWNvbnRyb2wta2V5"
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
M="perl $DIR/mock_xfr_notify.pl"

P1=$(kari_port 0) P2=$(kari_port 1) P3=$(kari_port 2) PQ=$(kari_port 12)      # primaries
SA=$(kari_port 3) SB=$(kari_port 4) SC=$(kari_port 5)                           # secondaries: failover, multi-master, timers
SR=$(kari_port 6) SG=$(kari_port 7) SQ=$(kari_port 8) SO=$(kari_port 9) SX=$(kari_port 10) SE=$(kari_port 11)
MG1=$(kari_port 20) MG2=$(kari_port 21) MH=$(kari_port 22) MEA=$(kari_port 23) MEB=$(kari_port 24) MG3=$(kari_port 25) MG4=$(kari_port 26)

PIDS=""
FAILS=0
PASSES=0
pass() { echo "PASS: $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/p1.conf" "$W/p2.conf" "$W/p3.conf" "$W/pq.conf" "$W/sa.conf" "$W/sb.conf" "$W/sc.conf" "$W/sr.conf" "$W/sg.conf" \
        "$W/sq.conf" "$W/so.conf" "$W/sx.conf" "$W/se.conf"
    if [ "$FAILS" -ne 0 ]; then
        for f in p1 p2 p3 pq sa sb sc sr sg sq so sx se; do echo "--- $f.log (tail)"; tail -12 "$W/$f.log" 2>/dev/null; done
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P1 $P2 $P3 $PQ $SA $SB $SC $SR $SG $SQ $SO $SX $SE $MG1 $MG2 $MH $MEA $MEB $MG3 $MG4; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

wait_grep() { # PATTERN FILE [SECONDS]
    _i=0
    while [ $_i -lt "${3:-10}" ]; do grep -q -- "$1" "$2" 2>/dev/null && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
dag_soa() { "$DAG" @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump +time=1 +tries=1 2>/dev/null; }
serial_of() { dag_soa "$1" "$2" | awk '{print $3}'; }
wait_serial() { # PORT ZONE SERIAL [SECONDS]
    _i=0
    while [ $_i -lt "${4:-20}" ]; do [ "$(serial_of "$1" "$2")" = "$3" ] && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
zone() { # zone FILE ORIGIN SERIAL [REFRESH RETRY EXPIRE]
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s %s %s %s 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' \
        "$2" "$3" "${4:-2}" "${5:-1}" "${6:-3600}" > "$1"
}
primary() { # primary NAME PORT [OPTIONS] : $W/NAME.conf serving the zones listed in ZONES ("origin:file"), allow-transfer 127.0.0.1
    {
        echo "options { port $2; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify no; ${3:-} };"
        echo "control-channel { socket \"$W/$1.sock\"; algorithm hmac-sha256; secret \"$SECRET\"; };"
        for zf in $ZONES; do
            echo "zone \"${zf%%:*}\" { type master; file \"${zf#*:}\"; allow-transfer { 127.0.0.1; }; };"
        done
    } > "$W/$1.conf"
}
start() { # start NAME [VAR=value ...] : karidns on $W/NAME.conf with the extra environment
    n=$1; shift
    env X=1 "$@" "$KARIDNS" -f "$W/$n.conf" > "$W/$n.log" 2>&1 &
    PIDS="$PIDS $!"
}
ctl() { n=$1; shift; "$KARICTL" -s "$W/$n.sock" -f "$W/ctl.conf" "$@" 2>&1; }

# ------------------------------------------------------------------------------------------------ F: failover
zone "$W/f2.zone" f.test 5
zone "$W/t1.zone" t1.test 1 9999 8888 1000000
zone "$W/t2.zone" t2.test 1 1 1 2
ZONES="f.test:$W/f2.zone t1.test:$W/t1.zone t2.test:$W/t2.zone"
primary p2 "$P2"
start p2
kari_wait_answer "$DAG" "$P2" f.test. || true
cat > "$W/sa.conf" <<EOF
options { port $SA; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT min-refresh-time 1; min-retry-time 1; };
control-channel { socket "$W/sa.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "f.test" { type slave; primaries { 127.0.0.1 port $P1; 127.0.0.1 port $P2; }; };
EOF
start sa
if wait_serial "$SA" f.test 5 20; then pass "F1: the first primary is down: the zone came from the second (serial 5)"
else fail "F1: f.test was not transferred from the second primary while the first is down"; fi

zone "$W/f1.zone" f.test 3
ZONES="f.test:$W/f1.zone"
primary p1 "$P1"
start p1
kari_wait_answer "$DAG" "$P1" f.test. || true
if wait_grep "serial number (3) received from primary 127.0.0.1 < ours (5)" "$W/sa.log" 15; then
    pass "F2: a primary that is behind is logged ('serial number (3) received from primary ... < ours (5)') and is not an error"
else fail "F2: no 'serial number (3) received from primary' line for the primary that is behind"; fi
if grep -q "Failed to transfer zone f.test. from 127.0.0.1" "$W/sa.log"; then
    # the first primary refused connections at the very start (that failure is expected); none may follow the start of p1
    n_fail=$(grep -c "Failed to transfer zone f.test. from 127.0.0.1" "$W/sa.log")
    n_beh=$(grep -c "received from primary" "$W/sa.log")
    if [ "$n_fail" -le 2 ] && [ "$n_beh" -ge 1 ]; then pass "F2b: the primary that is behind is not counted as a failed transfer ($n_fail failures logged, all from the start)"
    else fail "F2b: $n_fail failed transfers logged next to $n_beh 'behind' lines"; fi
else pass "F2b: the primary that is behind is not logged as a failed transfer"; fi
[ "$(serial_of "$SA" f.test)" = "5" ] && pass "F3: the zone stays at serial 5 (the older primary is not followed)" || fail "F3: the serial of the secondary is $(serial_of "$SA" f.test)"

cat > "$W/sb.conf" <<EOF
options { port $SB; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT min-refresh-time 1; min-retry-time 1; multi-master yes; };
control-channel { socket "$W/sb.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "f.test" { type slave; primaries { 127.0.0.1 port $P1; 127.0.0.1 port $P2; }; };
EOF
start sb
if wait_serial "$SB" f.test 5 25; then pass "F4: with the older primary first, an up-to-date answer does not stop the search: the secondary ended at the newest serial (5)"
else fail "F4: the multi-master secondary is at serial $(serial_of "$SB" f.test), not 5"; fi
sleep 5
if ! grep -q "received from primary" "$W/sb.log"; then pass "F5: multi-master yes: a primary that is behind is not logged"
else fail "F5: multi-master yes logged a primary that is behind"; grep "received from primary" "$W/sb.log" | head -2; fi

zone "$W/f1.zone" f.test 7
ctl p1 reload > /dev/null
if wait_serial "$SA" f.test 7 20 && wait_serial "$SB" f.test 7 20; then
    pass "F6: the first primary is used again as soon as it is ahead (serial 7), with and without multi-master"
else fail "F6: after the first primary reached serial 7 the secondaries are at $(serial_of "$SA" f.test) and $(serial_of "$SB" f.test)"; fi

# ------------------------------------------------------------------------------------------------ C: timers
cat > "$W/sc.conf" <<EOF
options { port $SC; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
  min-refresh-time 4; max-refresh-time 6; min-retry-time 3; max-retry-time 5; };
control-channel { socket "$W/sc.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "t1.test" { type slave; primaries { 127.0.0.1 port $P2; }; };
zone "t2.test" { type slave; primaries { 127.0.0.1 port $P2; }; };
EOF
start sc
wait_serial "$SC" t1.test 1 15; wait_serial "$SC" t2.test 1 15
st=$(ctl sc zonestatus t1.test)
case "$st" in *"refresh=6 retry=5 expire=1000000"*) pass "C1: SOA refresh 9999 / retry 8888 are held to max-refresh-time 6 / max-retry-time 5 ($st)" ;; *) fail "C1: zonestatus t1.test: $st" ;; esac
st=$(ctl sc zonestatus t2.test)
case "$st" in *"refresh=4 retry=3 expire=7"*) pass "C2: SOA refresh 1 / retry 1 / expire 2 become min-refresh-time 4 / min-retry-time 3 / expire 7 = refresh + retry ($st)" ;; *) fail "C2: zonestatus t2.test: $st" ;; esac

# ------------------------------------------------------------------------------------------------ I: request-ixfr, provide-ixfr, request-expire
zone "$W/r.zone" r.test 5
zone "$W/pn.zone" pn.test 5
{
    echo "options { port $P3; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify no; };"
    echo "control-channel { socket \"$W/p3.sock\"; algorithm hmac-sha256; secret \"$SECRET\"; };"
    echo "zone \"r.test\" { type master; file \"$W/r.zone\"; allow-transfer { 127.0.0.1; }; };"
    echo "zone \"pn.test\" { type master; file \"$W/pn.zone\"; allow-transfer { 127.0.0.1; }; provide-ixfr no; };"
} > "$W/p3.conf"
start p3
kari_wait_answer "$DAG" "$P3" r.test. || true
n=$("$DAG" @127.0.0.1 -p "$P3" r.test IXFR=5 +nohexdump +short +tcp 2>/dev/null | wc -l | tr -d ' ')
m=$("$DAG" @127.0.0.1 -p "$P3" pn.test IXFR=5 +nohexdump +short +tcp 2>/dev/null | wc -l | tr -d ' ')
mo=$("$DAG" @127.0.0.1 -p "$P3" pn.test IXFR=4 +nohexdump +short +tcp 2>/dev/null | wc -l | tr -d ' ')
no=$("$DAG" @127.0.0.1 -p "$P3" r.test IXFR=4 +nohexdump +short +tcp 2>/dev/null | wc -l | tr -d ' ')
# BIND ns_xfr_start(): the up-to-date test (DNS_SERIAL_GE, "IXFR poll") comes before provide-ixfr, so provide-ixfr no answers a client that already has
# the serial with the one SOA too; only a client that is behind gets the whole zone (an AXFR-style IXFR, RFC 1995 §4)
if [ "$n" -eq 1 ] && [ "$m" -eq 1 ] && [ "$mo" -ge 3 ] && [ "$no" -ge 3 ]; then pass "I1: provide-ixfr: an IXFR from the serial the zone has gets the one SOA ($n line; with provide-ixfr no $m line); a client that is behind gets the whole zone with provide-ixfr no ($mo lines) and with no history ($no lines)"
else fail "I1: IXFR answers: current serial default $n / provide-ixfr no $m line(s) (expected 1 and 1), older serial provide-ixfr no $mo / default $no (expected >= 3)"; fi
tcn=$("$DAG" @127.0.0.1 -p "$P3" r.test IXFR=5 +notcp +nohexdump 2>&1 | grep -c "Truncated, retrying in TCP mode")
tcp=$("$DAG" @127.0.0.1 -p "$P3" pn.test IXFR=5 +notcp +nohexdump 2>&1 | grep -c "Truncated, retrying in TCP mode")
tco=$("$DAG" @127.0.0.1 -p "$P3" pn.test IXFR=4 +notcp +nohexdump 2>&1 | grep -c "Truncated, retrying in TCP mode")
if [ "$tcn" -eq 0 ] && [ "$tcp" -eq 0 ] && [ "$tco" -ge 1 ]; then pass "I1b: over UDP a client that is up to date gets the SOA also with provide-ixfr no (no TC); one that is behind is sent to TCP (TC, dag retries in TCP)"
else fail "I1b: UDP IXFR: TC retries default/current $tcn, provide-ixfr no/current $tcp (expected 0 and 0), provide-ixfr no/older $tco (expected >= 1)"; fi
cat > "$W/sr.conf" <<EOF
options { port $SR; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT min-refresh-time 1; min-retry-time 1; request-ixfr no; };
control-channel { socket "$W/sr.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "r.test" { type slave; primaries { 127.0.0.1 port $P3; }; };
EOF
start sr
wait_serial "$SR" r.test 5 15 || fail "I2: r.test was not transferred"
sleep 6   # several refresh checks (SOA first) with nothing to transfer
zone "$W/r.zone" r.test 6
ctl p3 reload > /dev/null
if wait_serial "$SR" r.test 6 15; then
    obs=$(ctl sr observatory r.test)
    axfr=$(echo "$obs" | sed -n 's/.*AXFR=\([0-9]*\) IXFR=\([0-9]*\).*/\1/p')
    ixfr=$(echo "$obs" | sed -n 's/.*AXFR=\([0-9]*\) IXFR=\([0-9]*\).*/\2/p')
    if [ "${axfr:-0}" -eq 2 ] && [ "${ixfr:-1}" -eq 0 ]; then pass "I2: request-ixfr no: the first copy and the change came by AXFR (2), none by IXFR, and the quiet refresh checks transferred nothing (SOA first)"
    else fail "I2: request-ixfr no: AXFR=$axfr IXFR=$ixfr (expected 2 and 0)"; echo "$obs"; fi
else fail "I2: request-ixfr no: r.test did not follow the primary to serial 6"; fi
$M xfr-primary --port "$MEA" --zone ea.test --mode ok --serial 10 --log "$W/mea.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MEB" --zone eb.test --mode ok --serial 10 --log "$W/meb.log" & PIDS="$PIDS $!"
sleep 1
cat > "$W/se.conf" <<EOF
options { port $SE; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "ea.test" { type slave; primaries { 127.0.0.1 port $MEA; }; request-expire no; };
zone "eb.test" { type slave; primaries { 127.0.0.1 port $MEB; }; };
EOF
start se
wait_grep "REQ qtype=252" "$W/mea.log" 10; wait_grep "REQ qtype=252" "$W/meb.log" 10
if grep -q "REQ qtype=252 expire=0" "$W/mea.log" && grep -q "REQ qtype=252 expire=1" "$W/meb.log"; then
    pass "I3: request-expire no leaves the EDNS EXPIRE option out of the transfer request; the default asks for it"
else fail "I3: request-expire: ea.test -> $(head -1 "$W/mea.log" 2>/dev/null), eb.test -> $(head -1 "$W/meb.log" 2>/dev/null)"; fi

# ------------------------------------------------------------------------------------------------ S: max-transfer-*-in, transfers-in
$M xfr-primary --port "$MG1" --zone g1.test --mode stall --log "$W/mg1.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MG3" --zone g1.test --mode stall --log "$W/mg3.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MG4" --zone g2.test --mode stall --log "$W/mg4.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MH" --zone h.test --mode drip --log "$W/mh.log" & PIDS="$PIDS $!"
sleep 1
cat > "$W/sg.conf" <<EOF
options { port $SG; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT max-transfer-idle-in 1; max-transfer-time-in 40320; };
zone "g1.test" { type slave; primaries { 127.0.0.1 port $MG1; }; };
zone "h.test" { type slave; primaries { 127.0.0.1 port $MH; }; max-transfer-idle-in 40320; max-transfer-time-in 2; };
EOF
# a "minute" of max-transfer-* is 3 seconds here (KARIDNS_XFER_MINUTE_SECS): idle 3 s, total 6 s
start sg KARIDNS_XFER_MINUTE_SECS=3
if wait_grep "zone 'g1.test.': giving up the transfer: no data for 3 seconds" "$W/sg.log" 12; then pass "S1: max-transfer-idle-in gives up a transfer that stalls after its first message"
else fail "S1: the stalled transfer of g1.test was not given up"; fi
if wait_grep "zone 'h.test.': giving up the transfer: it took longer than max-transfer-time-in" "$W/sg.log" 15; then pass "S2: max-transfer-time-in gives up a transfer that never ends although data keeps coming"
else fail "S2: the endless transfer of h.test was not given up"; fi
[ -z "$(dag_soa "$SG" g1.test)" ] && [ -z "$(dag_soa "$SG" h.test)" ] && pass "S3: nothing of a given-up transfer is served" || fail "S3: a zone of a given-up transfer is served"

cat > "$W/sq.conf" <<EOF
options { port $SQ; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT transfers-in 1; max-transfer-idle-in 1; };
zone "g1.test" { type slave; primaries { 127.0.0.1 port $MG3; }; };
zone "g2.test" { type slave; primaries { 127.0.0.1 port $MG4; }; };
EOF
start sq KARIDNS_XFER_MINUTE_SECS=4
wait_grep "STALL" "$W/mg3.log" 10; wait_grep "STALL" "$W/mg4.log" 14
t1=$(sed -n 's/.* t=\([0-9]*\)$/\1/p' "$W/mg3.log" | head -1)
t2=$(sed -n 's/.* t=\([0-9]*\)$/\1/p' "$W/mg4.log" | head -1)
if [ -n "$t1" ] && [ -n "$t2" ]; then
    d=$((t1 > t2 ? t1 - t2 : t2 - t1))
    if [ "$d" -ge 3 ]; then pass "S4: transfers-in 1: the second inbound transfer started $d s after the first (after the first was given up)"
    else fail "S4: transfers-in 1: the two transfers started $d s apart (expected >= 3)"; fi
else fail "S4: transfers-in 1: both mock primaries should have been asked ($t1 / $t2)"; fi

# ------------------------------------------------------------------------------------------------ O: transfers-out, max-transfer-idle-out
perl -e 'print "\$TTL 300\n\$ORIGIN big.test.\n\@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n\@ IN NS ns1\nns1 IN A 192.0.2.1\n"; for my $i (1..30000) { printf "h%d IN TXT \"%s\"\n", $i, "x" x 200 }' > "$W/big.zone"
ZONES="big.test:$W/big.zone"
primary so "$SO" "transfers-out 1; max-transfer-idle-out 1;"
start so KARIDNS_XFER_MINUTE_SECS=3
kari_wait_answer "$DAG" "$SO" big.test. || true
perl "$DIR/lib_slow_axfr_client.pl" "$SO" big.test 9 > "$W/slow.out" 2>&1 &
PIDS="$PIDS $!"
sleep 1
out=$("$DAG" @127.0.0.1 -p "$SO" big.test AXFR +nohexdump +time=3 2>&1 | head -40)
if echo "$out" | grep -qi "refused\|Transfer failed"; then pass "O1: transfers-out 1: a second transfer while one is in progress is refused"
else fail "O1: the second AXFR was not refused"; echo "$out" | head -8; fi
sleep 5   # max-transfer-idle-out 1 minute = 3 s: the client that does not read is dropped
n=$("$DAG" @127.0.0.1 -p "$SO" big.test AXFR +nohexdump +time=10 2>&1 | grep -c "TXT")
if [ "$n" -ge 30000 ]; then pass "O2: max-transfer-idle-out freed the slot of the client that does not read: the next transfer completed ($n records)"
else fail "O2: after max-transfer-idle-out the next AXFR returned $n TXT records (expected 30000)"; fi
sleep 5
if grep -q "BYTES=" "$W/slow.out"; then
    b=$(sed -n 's/.*BYTES=\([0-9]*\).*/\1/p' "$W/slow.out")
    [ "${b:-0}" -lt 3000000 ] && pass "O3: the stalled client was cut off (it got $b bytes of a zone of about 7 MB)" || fail "O3: the stalled client received the whole zone ($b bytes)"
else fail "O3: no result of the slow client"; cat "$W/slow.out"; fi
primary so "$SO" "transfers-out 0;"
ctl so reload > /dev/null
sleep 1
out=$("$DAG" @127.0.0.1 -p "$SO" big.test AXFR +nohexdump +time=3 2>&1 | head -40)
if echo "$out" | grep -qi "refused\|Transfer failed"; then pass "O4: transfers-out 0: every transfer is refused (after a reload)"
else fail "O4: transfers-out 0 did not refuse"; echo "$out" | head -8; fi

# ------------------------------------------------------------------------------------------------ Q: serial-query-rate
ZONES=""
for i in 1 2 3 4 5; do zone "$W/q$i.zone" "q$i.test" 1; ZONES="$ZONES q$i.test:$W/q$i.zone"; done
primary pq "$PQ"
start pq
{
    echo "options { port $SX; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; serial-query-rate 1; };"
    for i in 1 2 3 4 5; do echo "zone \"q$i.test\" { type slave; primaries { 127.0.0.1 port $PQ; }; };"; done
} > "$W/sx.conf"
kari_wait_answer "$DAG" "$PQ" q1.test. || true
start sx
t0=$(date +%s)
last=0
i=0
while [ $i -lt 40 ]; do
    ok=0
    for z in 1 2 3 4 5; do [ "$(serial_of "$SX" q$z.test)" = "1" ] && ok=$((ok + 1)); done
    if [ "$ok" -eq 5 ]; then last=$(date +%s); break; fi
    sleep 1; i=$((i + 1))
done
dt=$((last - t0))
if [ "$last" -ne 0 ] && [ "$dt" -ge 3 ]; then pass "Q1: serial-query-rate 1: five zones took $dt s to get their first copy (one refresh check a second)"
else fail "Q1: serial-query-rate 1: five zones loaded in $dt s (expected >= 3 s)"; fi

echo "== $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

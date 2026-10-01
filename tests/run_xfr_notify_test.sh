#!/bin/sh
# Zone transfer, NOTIFY and secondary behaviour (phase 10: R-15, R-16, R-17, D-09, R-19, R-21, R-28, O-06,
# X-19, X-24). Runs as a normal user on 127.0.0.1; tests/mock_xfr_notify.pl plays NOTIFY receivers and
# broken primaries.
#
#   R-17 / RFC 1996 §3.6   NOTIFY is retransmitted until an answer with the same ID/QNAME/address/port,
#                          on the notify-retries / notify-retry-interval / notify-retry-backoff schedule
#   D-09 / RFC 8945 §5.4   NOTIFY of a zone with tsig-key is signed; only a verified answer stops it
#   R-21 / RFC 1996 §4.5   a reload that changes the serial sends NOTIFY, one that does not stays quiet
#   R-19 / RFC 5936 §2.2.1 the transfer client rejects wrong ID / question, stops at an error RCODE,
#          RFC 1995 §4     and falls back to AXFR when IXFR gets NOTIMP
#   R-15 / RFC 1995 §2, §3 equal or newer serial -> current SOA only (TCP and UDP); no SOA -> FORMERR
#   R-16 / RFC 5936 §2.2.5 OPT in the first AXFR message when the query had one
#   X-19                   AXFR of a zone without data -> SERVFAIL + EDE 14
#   O-06                   karictl retransfer only for secondaries
#   R-28 / RFC 9432 §5.4   a catalog group change does not reset the member zone
#   X-24                   a KariDNS secondary gets IXFR (not a full Extended AXFR) from a KariDNS primary
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl dag >/dev/null || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-xfrnotify.XXXXXX")"
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
M="perl $DIR/mock_xfr_notify.pl"
PP=15471   # primary
PS=15472   # secondary (TSIG key nk)
PW=15473   # secondary with a wrong secret for nk
PK=15474   # secondary for the catalog and X-24
SINK1=15481 SINK2=15482 SINK3=15483 SINK4=15484
MX1=15491 MX2=15492 MX3=15493 MX4=15494
SECRET="cDEwLXhmci1ub3RpZnktdGVzdC1jb250cm9sLWtleQ=="
NK="bmstdGVzdC1zZWNyZXQtZm9yLXRoZS1ub3RpZnkta2V5IQ=="
NK_WRONG="d3Jvbmctc2VjcmV0LWZvci10aGUtbm90aWZ5LWtleSEh"
PIDS=""
FAILS=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    kari_kill_tree $PIDS
    kari_kill_conf "$W/p.conf" "$W/s.conf" "$W/w.conf" "$W/k.conf"
    if [ "$FAILS" -ne 0 ]; then
        for f in p s w k; do echo "--- $f.log (tail)"; tail -25 "$W/$f.log" 2>/dev/null; done
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $PP $PS $PW $PK $SINK1 $SINK2 $SINK3 $SINK4 $MX1 $MX2 $MX3 $MX4; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

# wait_grep PATTERN FILE [SECONDS]
wait_grep() {
    _i=0
    while [ $_i -lt "${3:-10}" ]; do grep -q -- "$1" "$2" 2>/dev/null && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
count() { grep -c -- "$1" "$2" 2>/dev/null || true; }
zone() { # zone FILE ORIGIN SERIAL [extra lines]
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n%s' \
        "$2" "$3" "${4:-}" > "$1"
}

for z in n1 n2 n3 s; do zone "$W/$z.test.zone" "$z.test" 1; done
zone "$W/k.test.zone" k.test 1
zone "$W/m1.test.zone" m1.test 1
printf '$TTL 300\n@ IN SOA ns1.cat.test. hostmaster.cat.test. 1 3600 600 86400 60\n@ IN NS invalid.\nversion IN TXT "2"\nabc.zones IN PTR m1.test.\n' > "$W/cat.test.zone"
zone "$W/x2.test.zone" x2.test 5   # the secondary's initial copy, so its first refresh asks IXFR

KEYS="key \"nk\" { algorithm hmac-sha256; secret \"$NK\"; };"
cat > "$W/p.conf" <<EOF
options { port $PP; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$W/p.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$KEYS
zone "n1.test" { type master; file "$W/n1.test.zone"; also-notify { 127.0.0.1 port $SINK1; };
                 notify-retries 4; notify-retry-interval 1; notify-retry-backoff exponential; };
zone "n2.test" { type master; file "$W/n2.test.zone"; also-notify { 127.0.0.1 port $SINK2; };
                 notify-retries 2; notify-retry-interval 1; };
zone "n3.test" { type master; file "$W/n3.test.zone"; also-notify { 127.0.0.1 port $SINK3; };
                 allow-transfer { 127.0.0.1; }; };
zone "s.test" { type master; file "$W/s.test.zone"; tsig-key "nk"; allow-transfer { key "nk"; };
                also-notify { 127.0.0.1 port $PS; 127.0.0.1 port $PW; 127.0.0.1 port $SINK4; };
                notify-retries 3; notify-retry-interval 1; };
zone "k.test" { type master; file "$W/k.test.zone"; allow-transfer { 127.0.0.1; }; allow-update { 127.0.0.1; };
                also-notify { 127.0.0.1 port $PK; }; notify-retry-interval 1; };
zone "cat.test" { type master; file "$W/cat.test.zone"; allow-transfer { 127.0.0.1; }; };
zone "m1.test" { type master; file "$W/m1.test.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$W/s.conf" <<EOF
options { port $PS; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$W/s.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$KEYS
zone "s.test" { type slave; masters { 127.0.0.1 port $PP; }; tsig-key "nk"; };
zone "x1.test" { type slave; masters { 127.0.0.1 port $MX1; }; allow-transfer { 127.0.0.1; }; };
zone "x2.test" { type slave; file "$W/x2.test.zone"; masters { 127.0.0.1 port $MX2; }; };
zone "x3.test" { type slave; masters { 127.0.0.1 port $MX3; }; };
zone "x4.test" { type slave; masters { 127.0.0.1 port $MX4; }; };
EOF
cat > "$W/w.conf" <<EOF
options { port $PW; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
key "nk" { algorithm hmac-sha256; secret "$NK_WRONG"; };
zone "s.test" { type slave; masters { 127.0.0.1 port $PP; }; tsig-key "nk"; };
EOF
cat > "$W/k.conf" <<EOF
options { port $PK; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$W/k.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "k.test" { type slave; masters { 127.0.0.1 port $PP; }; };
zone "cat.test" { type slave; masters { 127.0.0.1 port $PP; }; catalog-zone yes; };
EOF
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
CP="$KARICTL -s $W/p.sock -f $W/ctl.conf"
CS="$KARICTL -s $W/s.sock -f $W/ctl.conf"
CK="$KARICTL -s $W/k.sock -f $W/ctl.conf"

$M notify-sink --port $SINK1 --log "$W/sink1.log" --answer-after 2 & PIDS="$PIDS $!"
$M notify-sink --port $SINK2 --log "$W/sink2.log" & PIDS="$PIDS $!"
$M notify-sink --port $SINK3 --log "$W/sink3.log" & PIDS="$PIDS $!"
$M notify-sink --port $SINK4 --log "$W/sink4.log" & PIDS="$PIDS $!"
$M xfr-primary --port $MX1 --zone x1.test --mode refused --log "$W/mx1.log" & PIDS="$PIDS $!"
$M xfr-primary --port $MX2 --zone x2.test --mode notimp-ixfr --log "$W/mx2.log" & PIDS="$PIDS $!"
$M xfr-primary --port $MX3 --zone x3.test --mode badid --log "$W/mx3.log" & PIDS="$PIDS $!"
$M xfr-primary --port $MX4 --zone x4.test --mode badq --log "$W/mx4.log" & PIDS="$PIDS $!"
"$KARIDNS" -f "$W/p.conf" > "$W/p.log" 2>&1 & PIDS="$PIDS $!"
sleep 2
"$KARIDNS" -f "$W/s.conf" > "$W/s.log" 2>&1 & PIDS="$PIDS $!"
"$KARIDNS" -f "$W/w.conf" > "$W/w.log" 2>&1 & PIDS="$PIDS $!"
"$KARIDNS" -f "$W/k.conf" > "$W/k.log" 2>&1 & PIDS="$PIDS $!"
sleep 3
for f in sink1 sink2 sink3 sink4; do : > "$W/$f.log"; done
: > "$W/p.log.mark"

# ---------------------------------------------------------------- R-17, D-09: NOTIFY retransmission
$CP notify n1.test >/dev/null; $CP notify n2.test >/dev/null; $CP notify n3.test >/dev/null; $CP notify s.test >/dev/null
sleep 9
n=$(count NOTIFY "$W/sink1.log")
ids=$(sed -n 's/.* id=\([0-9]*\) .*/\1/p' "$W/sink1.log" | sort -u | wc -l | tr -d ' ')
if [ "$n" -eq 3 ] && [ "$ids" -eq 1 ]; then
    pass "R-17: NOTIFY retransmitted after 1 s and 2 s (exponential), same ID, stopped by the answer to the 3rd"
else fail "R-17: receiver answering the 3rd NOTIFY got $n NOTIFY(s) with $ids ID(s), expected 3 with 1"; cat "$W/sink1.log"; fi
n=$(count NOTIFY "$W/sink2.log")
if [ "$n" -eq 3 ] && grep -q "zone 'n2.test.': no answer from 127.0.0.1 port $SINK2 after 3 NOTIFY message(s)" "$W/p.log"; then
    pass "R-17: notify-retries 2 -> 3 NOTIFYs to a silent receiver, then logged as unanswered"
else fail "R-17: silent receiver got $n NOTIFY(s) (expected 3) or no 'no answer' log line"; fi
n=$(count NOTIFY "$W/sink3.log")
if [ "$n" -eq 1 ]; then pass "R-17: default schedule (60 s) sends no retransmission within 9 s"
else fail "R-17: default schedule: $n NOTIFYs within 9 s (expected 1)"; fi

if grep -q "tsig=1" "$W/sink4.log" && ! grep -q "tsig=0" "$W/sink4.log"; then pass "D-09: NOTIFY of a zone with tsig-key is signed"
else fail "D-09: NOTIFY to the receiver is not signed"; cat "$W/sink4.log"; fi
if grep -q "zone 's.test.': no answer from 127.0.0.1 port $SINK4" "$W/p.log" &&
   ! grep -q "zone 's.test.': no answer from 127.0.0.1 port $PS " "$W/p.log"; then
    pass "D-09: the secondary's signed answer stops the retransmission (silent receiver still times out)"
else fail "D-09: retransmission to the KariDNS secondary with the right key was not stopped"; fi
if grep -q "zone 's.test.': ignoring NOTIFY answer from 127.0.0.1 port $PW that fails TSIG verification" "$W/p.log" &&
   grep -q "zone 's.test.': no answer from 127.0.0.1 port $PW " "$W/p.log"; then
    pass "D-09: an answer that fails TSIG verification (wrong secret) is logged and does not stop it (RFC 8945 §5.4)"
else fail "D-09: answer of the secondary with the wrong secret not logged/ignored"; fi

# ---------------------------------------------------------------- R-21: NOTIFY after a reload
: > "$W/sink3.log"
$CP reload n3.test >/dev/null
sleep 2
n=$(count NOTIFY "$W/sink3.log")
if [ "$n" -eq 0 ]; then pass "R-21: reload without a serial change sends no NOTIFY"; else fail "R-21: unchanged reload sent $n NOTIFY(s)"; fi
zone "$W/n3.test.zone" n3.test 2
$CP reload n3.test >/dev/null
if wait_grep NOTIFY "$W/sink3.log" 3; then pass "R-21: reload with a new serial sends NOTIFY"; else fail "R-21: no NOTIFY after the serial changed"; fi

# ---------------------------------------------------------------- R-19: transfer client
if grep -q "zone 'x1.test.': primary answered the AXFR request with REFUSED (5)" "$W/s.log"; then
    pass "R-19: REFUSED ends the transfer at once and is logged with the RCODE"
else fail "R-19: REFUSED answer not recognised"; grep "x1.test" "$W/s.log" | head -3; fi
if wait_grep "zone x2.test.: 127.0.0.1 does not support IXFR, retrying with AXFR" "$W/s.log" 5 &&
   [ "$(sed -n 's/REQ qtype=//p' "$W/mx2.log" | head -2 | tr '\n' ' ')" = "251 252 " ] &&
   "$DAG" @127.0.0.1 -p $PS www.x2.test A +short +nohexdump | grep -qx 192.0.2.80; then
    pass "R-19: NOTIMP to IXFR -> one AXFR retry, zone served (RFC 1995 §4)"
else fail "R-19: IXFR -> AXFR fallback"; cat "$W/mx2.log"; grep "x2.test" "$W/s.log" | head -5; fi
if grep -q "zone 'x3.test.': rejecting AXFR response: ID" "$W/s.log"; then pass "R-19: answer with another message ID rejected"
else fail "R-19: wrong-ID answer not rejected"; fi
if grep -q "zone 'x4.test.': rejecting AXFR response: question 'other.x4.test.'" "$W/s.log"; then
    pass "R-19: answer with another question rejected"
else fail "R-19: wrong-question answer not rejected"; fi

# ---------------------------------------------------------------- R-15, R-16, X-19: transfer responses
out=$($M probe --port $PP --name n3.test --qtype IXFR --serial 100)
case "$out" in *"rcode=0 qd=1 an=1 "*"soa=2"*) pass "R-15: IXFR with a newer serial -> current SOA only (TCP)";;
    *) fail "R-15: IXFR newer serial over TCP: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype IXFR --serial 2 --udp)
case "$out" in *"tc=0 rcode=0 qd=1 an=1 "*) pass "R-15: IXFR with the current serial over UDP -> SOA, no TC";;
    *) fail "R-15: IXFR current serial over UDP: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype IXFR --serial 100 --udp)
case "$out" in *"tc=0 rcode=0 qd=1 an=1 "*) pass "R-15: IXFR with a newer serial over UDP -> SOA, no TC";;
    *) fail "R-15: IXFR newer serial over UDP: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype IXFR --serial 1)
case "$out" in *"rcode=0 "*"soa=2,1,"*) pass "R-15: IXFR with an older serial -> the differences 1 -> 2";;
    *) fail "R-15: older serial: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype IXFR --nosoa --edns)
case "$out" in *"aa=0 tc=0 rcode=1 qd=1 an=0 "*"opt=1"*) pass "R-15: IXFR without SOA -> FORMERR with OPT (RFC 1995 §3)";;
    *) fail "R-15: IXFR without SOA: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype IXFR --nosoa --udp)
case "$out" in *"rcode=1 qd=1 an=0 "*) pass "R-15: IXFR without SOA over UDP -> FORMERR";; *) fail "R-15: UDP IXFR without SOA: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype AXFR --edns | head -1)
case "$out" in *"rcode=0 "*"opt=1 "*) pass "R-16: AXFR with EDNS -> OPT in the first message";; *) fail "R-16: $out";; esac
out=$($M probe --port $PP --name n3.test --qtype AXFR | head -1)
case "$out" in *"ar=0 opt=0 "*) pass "R-16: AXFR without EDNS -> no OPT";; *) fail "R-16 (no EDNS): $out";; esac
out=$($M probe --port $PS --name x1.test --qtype AXFR --edns)
case "$out" in *"rcode=2 qd=1 an=0 "*"opt=1"*) pass "X-19: AXFR of a zone without data -> SERVFAIL at once";;
    *) fail "X-19: AXFR of an empty secondary zone: $out";; esac

# ---------------------------------------------------------------- O-06: retransfer
$CP retransfer n3.test > "$W/o6.out" 2>&1; rc=$?
if [ $rc -eq 3 ] && grep -q "ERROR zone is not a secondary" "$W/o6.out" && $CP zonestatus n3.test | grep -q "serial=2 "; then
    pass "O-06: retransfer of a primary zone is refused, serial unchanged"
else fail "O-06: retransfer on a primary: rc=$rc $(cat "$W/o6.out")"; fi
if $CS retransfer s.test | grep -q "^OK"; then pass "O-06: retransfer of a secondary zone still works"
else fail "O-06: retransfer of a secondary zone failed"; fi

# ---------------------------------------------------------------- R-28: catalog group change
if wait_grep "Added new member 'm1.test.'" "$W/k.log" 5 &&
   "$DAG" @127.0.0.1 -p $PK www.m1.test A +short +nohexdump | grep -qx 192.0.2.10; then
    printf 'group.abc.zones IN TXT "g1"\n' >> "$W/cat.test.zone"
    sed -i.bak 's/ 1 3600 600/ 2 3600 600/' "$W/cat.test.zone"
    $CP reload cat.test >/dev/null
    sleep 1
    $CK retransfer cat.test >/dev/null
    if wait_grep "Updated group property of member 'm1.test.'" "$W/k.log" 5 &&
       [ "$(count "Added new member 'm1.test.'" "$W/k.log")" -eq 1 ] &&
       "$DAG" @127.0.0.1 -p $PK www.m1.test A +short +nohexdump | grep -qx 192.0.2.10; then
        pass "R-28: group change updates the member in place (not re-added, still answering)"
    else fail "R-28: group change re-added the member or broke it"; grep -E "Catalog|m1.test" "$W/k.log" | tail -6; fi
else fail "R-28: the catalog member was not created on the secondary"; fi

# ---------------------------------------------------------------- X-24: KariDNS primary -> secondary IXFR
transfers() { $CK observatory k.test 2>/dev/null | sed -n 's/.*Transfers (In): *\(AXFR=[0-9]* IXFR=[0-9]*\).*/\1/p'; }
before=$(transfers)
"$DAG" k.test A @127.0.0.1 -p $PP --update-add "new.k.test 300 A 192.0.2.99" +nohexdump >/dev/null 2>&1
i=0; while [ $i -lt 10 ]; do
    "$DAG" @127.0.0.1 -p $PK new.k.test A +short +nohexdump | grep -qx 192.0.2.99 && break; sleep 1; i=$((i + 1)); done
after=$(transfers)
if [ "$before" = "AXFR=1 IXFR=0" ] && [ "$after" = "AXFR=1 IXFR=1" ]; then
    pass "X-24: the KariDNS secondary received the UPDATE as IXFR ($before -> $after)"
else fail "X-24: transfers $before -> $after (expected AXFR=1 IXFR=0 -> AXFR=1 IXFR=1)"; fi

for f in p s w k; do
    if grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error" "$W/$f.log"; then fail "sanitizer report in $f.log"; fi
done
if [ "$FAILS" -eq 0 ]; then echo "=== run_xfr_notify_test: all checks passed ==="; exit 0; fi
echo "=== run_xfr_notify_test: $FAILS check(s) failed ==="
exit 1

#!/bin/sh
# run_also_notify_test.sh - also-notify as BIND 9.20 has it (ARM "also-notify", "remote-servers"): options-level default, zone override,
# `port` before the list, remote-servers list names, per-address `key` (TSIG, RFC 8945 / RFC 1996), and `karicheck conf` errors that
# name the file and line.  karidns runs as a normal user on 127.0.0.1; tests/mock_also_notify.pl plays the NOTIFY receivers and checks
# the TSIG MAC (RFC 8945 section 4.3) of what arrives.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$KARICHECK" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl karicheck dag >/dev/null || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }
perl -MDigest::SHA -MMIME::Base64 -MIO::Select -e 1 2>/dev/null || { echo "SKIP: perl modules Digest::SHA, MIME::Base64, IO::Select missing"; exit 0; }

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-alsonotify.XXXXXX")"
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
PM=$(kari_port 1 15601)
L1=$(kari_port 2 15602); L2=$(kari_port 3 15603); L3=$(kari_port 4 15604); L4=$(kari_port 5 15605)
L5=$(kari_port 6 15606); L6=$(kari_port 7 15607); L7=$(kari_port 8 15608); L8=$(kari_port 9 15609)
PP=$(kari_port 10 15610); PS=$(kari_port 11 15611); L9=$(kari_port 12 15612); L10=$(kari_port 13 15613)
WK="d3Jvbmcta2V5LXNlY3JldC1mb3ItYWxzby1ub3RpZnkh"
SECRET="cDEwLWFsc28tbm90aWZ5LXRlc3QtY29udHJvbC1rZXk="
NK="bmstdGVzdC1zZWNyZXQtZm9yLWFsc28tbm90aWZ5IQ=="
ZK="emstdGVzdC1zZWNyZXQtZm9yLXRoZS16b25lLWtleSEh"
PIDS=""
FAILS=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    kari_kill_tree $PIDS
    kari_kill_conf "$W/m.conf" "$W/p.conf" "$W/s.conf"
    if [ "$FAILS" -ne 0 ]; then
        echo "--- m.log (tail)"; tail -25 "$W/m.log" 2>/dev/null
        echo "--- recv.log"; cat "$W/recv.log" 2>/dev/null
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $PM $L1 $L2 $L3 $L4 $L5 $L6 $L7 $L8 $PP $PS $L9 $L10; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

zone() { # zone NAME
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\n@ IN NS ns2\nns1 IN A 192.0.2.1\nns2 IN A 192.0.2.2\n' "$1" > "$W/$1.zone"
}
for z in za zb zc zd ze zf zg zh zi sx sy sz sw sv; do zone "$z.test"; done

KEYS="key \"nk\" { algorithm hmac-sha256; secret \"$NK\"; };
key \"zk\" { algorithm hmac-sha256; secret \"$ZK\"; };"
cat > "$W/m.conf" <<EOF
options { port $PM; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
          also-notify { 127.0.0.1 port $L1; }; };
control-channel { socket "$W/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$KEYS
zone "za.test" { type master; file "$W/za.test.zone"; };
zone "zb.test" { type master; file "$W/zb.test.zone"; also-notify { 127.0.0.1 port $L2; }; };
zone "zc.test" { type master; file "$W/zc.test.zone"; also-notify port $L3 { 127.0.0.1; 127.0.0.1 port $L4; }; };
zone "zd.test" { type master; file "$W/zd.test.zone"; also-notify { grp; }; };
zone "ze.test" { type master; file "$W/ze.test.zone"; also-notify { 127.0.0.1 port $L7 key "nk"; }; };
zone "zf.test" { type master; file "$W/zf.test.zone"; tsig-key "zk"; also-notify { 127.0.0.1 port $L7 key nk; 127.0.0.1 port $L8; }; };
zone "zg.test" { type master; file "$W/zg.test.zone"; also-notify { }; };
zone "zh.test" { type master; file "$W/zh.test.zone"; notify no; also-notify { 127.0.0.1 port $L1; }; };
zone "zi.test" { type master; file "$W/zi.test.zone"; notify explicit; also-notify { 127.0.0.1 port $L2; }; };
remote-servers grp port $L5 { 127.0.0.1; 127.0.0.1 port $L6; };
EOF
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
CT="$KARICTL -s $W/ctl.sock -f $W/ctl.conf"

: > "$W/recv.log"
perl "$DIR/mock_also_notify.pl" --log "$W/recv.log" --ports "$L1,$L2,$L3,$L4,$L5,$L6,$L7,$L8,$L9,$L10" --key "nk:$NK" --key "zk:$ZK" 2> "$W/mock.err" &
PIDS="$PIDS $!"
i=0; while ! grep -q READY "$W/mock.err" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
grep -q READY "$W/mock.err" || { fail "the NOTIFY receivers did not start"; cat "$W/mock.err"; exit 1; }

"$KARIDNS" -f "$W/m.conf" > "$W/m.log" 2>&1 & PIDS="$PIDS $!"
i=0; while ! [ -S "$W/ctl.sock" ] && [ $i -lt 100 ]; do sleep 0.2; i=$((i + 1)); done
[ -S "$W/ctl.sock" ] || { fail "karidns did not start"; exit 1; }
sleep 1
: > "$W/recv.log"

for z in za zb zc zd ze zf zg zh zi; do $CT notify "$z.test" >/dev/null 2>&1; done
sleep 3

# ports that received a NOTIFY for the zone, sorted
ports() { sed -n "s/^NOTIFY port=\([0-9]*\) qname=$1\.test .*/\1/p" "$W/recv.log" | sort -n | uniq | tr '\n' ' '; }
want() { for _p in "$@"; do echo "$_p"; done | sort -n | tr '\n' ' '; }
expect_ports() { # expect_ports ZONE LABEL PORT...
    _z=$1; _l=$2; shift 2
    _got=$(ports "$_z"); _want=$(want "$@")
    if [ "$_got" = "$_want" ]; then pass "$_l"; else fail "$_l: $_z.test got NOTIFY on [$_got], expected [$_want]"; fi
}

expect_ports za "options-level also-notify is the default of a zone without its own" "$L1"
expect_ports zb "a zone also-notify replaces the options list (not both)" "$L2"
expect_ports zc "port before the list is the default port, an element port overrides it" "$L3" "$L4"
expect_ports zd "a remote-servers list name expands to its addresses (list port, element port)" "$L5" "$L6"
expect_ports ze "an element with a key gets its NOTIFY (and the options list is replaced)" "$L7"
expect_ports zf "two elements, one with a key" "$L7" "$L8"
expect_ports zg "an empty zone also-notify switches the inherited list off"
expect_ports zh "notify no: nothing is sent, not even to the also-notify list (also for karictl notify)"
expect_ports zi "notify explicit: the also-notify list is used" "$L2"
sent() { $CT observatory "$1.test" 2>/dev/null | sed -n "s/.*Sent=\([0-9]*\).*/\1/p"; }
if [ "$(sent za)" = 2 ] && [ "$(sent zi)" = 1 ] && [ "$(sent zh)" = 0 ]; then
    pass "notify explicit leaves out the NS hosts (za: also-notify + NS host = 2 targets, zi: 1), notify no sends 0"
else fail "NOTIFY target counts: za=$(sent za) (want 2) zi=$(sent zi) (want 1) zh=$(sent zh) (want 0)"; fi

if grep -q "^NOTIFY port=$L7 qname=ze.test tsig=nk mac=ok$" "$W/recv.log"; then
    pass "element key: the NOTIFY is TSIG-signed with that key and the MAC verifies (RFC 8945 section 4.3)"
else fail "element key: no NOTIFY signed with nk and a valid MAC for ze.test"; fi
if grep -q "^NOTIFY port=$L7 qname=zf.test tsig=nk mac=ok$" "$W/recv.log"; then
    pass "precedence: the key of the element wins over the tsig-key of the zone"
else fail "precedence: zf.test to port $L7 is not signed with nk"; fi
if grep -q "^NOTIFY port=$L8 qname=zf.test tsig=zk mac=ok$" "$W/recv.log"; then
    pass "precedence: an element without a key is signed with the tsig-key of the zone"
else fail "precedence: zf.test to port $L8 is not signed with zk"; fi
if ! grep -E "qname=(za|zb|zc|zd).test" "$W/recv.log" | grep -qv "tsig=none"; then
    pass "elements without a key in a zone without tsig-key are not signed"
else fail "an unsigned zone sent a signed NOTIFY"; fi

# ---------------------------------------------------------------- primaries (zone) and notify primary-only
# A primary that wants TSIG for transfers, and a secondary that names it in different ways:
#   sx: a remote-servers list name whose address has the key        sy: a key that the primary does not know (transfer fails)
#   sz: the zone's tsig-key                                         sw: a wrong zone tsig-key, overridden by the key of the primary
#   sv: key of the primary; the primary NOTIFYs it unsigned (refused); notify primary-only: the secondary passes nothing on
cat > "$W/p.conf" <<EOF
options { port $PP; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$W/p.sock"; algorithm hmac-sha256; secret "$SECRET"; };
key "nk" { algorithm hmac-sha256; secret "$NK"; };
zone "sx.test" { type master; file "$W/sx.test.zone"; allow-transfer { key "nk"; }; also-notify { 127.0.0.1 port $PS key nk; }; };
zone "sy.test" { type master; file "$W/sy.test.zone"; allow-transfer { key "nk"; }; };
zone "sz.test" { type master; file "$W/sz.test.zone"; allow-transfer { key "nk"; }; };
zone "sw.test" { type master; file "$W/sw.test.zone"; allow-transfer { key "nk"; }; };
zone "sv.test" { type master; file "$W/sv.test.zone"; allow-transfer { key "nk"; }; also-notify { 127.0.0.1 port $PS; }; };
EOF
cat > "$W/s.conf" <<EOF
options { port $PS; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$W/s.sock"; algorithm hmac-sha256; secret "$SECRET"; };
key "nk" { algorithm hmac-sha256; secret "$NK"; };
key "wk" { algorithm hmac-sha256; secret "$WK"; };
zone "sx.test" { type slave; primaries { plist; }; also-notify { 127.0.0.1 port $L9; }; };
zone "sy.test" { type slave; primaries { 127.0.0.1 port $PP key wk; }; };
zone "sz.test" { type slave; tsig-key "nk"; primaries { 127.0.0.1 port $PP; }; };
zone "sw.test" { type slave; tsig-key "wk"; primaries { 127.0.0.1 port $PP key nk; }; };
zone "sv.test" { type slave; primaries { 127.0.0.1 port $PP key nk; }; notify primary-only; also-notify { 127.0.0.1 port $L10; }; };
remote-servers plist { 127.0.0.1 port $PP key nk; };
EOF
CTP="$KARICTL -s $W/p.sock -f $W/ctl.conf"
"$KARIDNS" -f "$W/p.conf" > "$W/p.log" 2>&1 & PIDS="$PIDS $!"
kari_wait_answer "$DAG" "$PP" sx.test 15 || { fail "the primary did not start"; exit 1; }
"$KARIDNS" -f "$W/s.conf" > "$W/s.log" 2>&1 & PIDS="$PIDS $!"
serial() { "$DAG" @127.0.0.1 -p "$PS" "$1.test" SOA +short +nohexdump +time=1 +tries=1 2>/dev/null | awk '{print $3}'; }
wait_serial() { # wait_serial ZONE SERIAL [SECONDS]
    _i=0
    while [ $_i -lt $(( ${3:-20} * 2 )) ]; do [ "$(serial "$1")" = "$2" ] && return 0; sleep 0.5; _i=$((_i + 1)); done
    return 1
}
wait_serial sx 1 && pass "primaries { list name }: the secondary transfers sx.test with the key of the primary in the list" || fail "sx.test was not transferred"
wait_serial sz 1 2 && pass "primaries without a key: the zone's tsig-key signs the transfer" || fail "sz.test was not transferred"
wait_serial sw 1 2 && pass "precedence: the key of the primary wins over a wrong zone tsig-key" || fail "sw.test was not transferred"
wait_serial sv 1 2 || fail "sv.test was not transferred"
sleep 2
if [ -z "$(serial sy)" ]; then pass "a key the primary does not know: the transfer fails and the zone is not served"
else fail "sy.test is served although its key is wrong"; fi
if grep -q "^NOTIFY port=$L9 qname=sx.test " "$W/recv.log"; then pass "a secondary passes a transfer on to its also-notify list (notify yes)"
else fail "no NOTIFY from the secondary for sx.test"; fi
if ! grep -q "qname=sv.test " "$W/recv.log"; then pass "notify primary-only: a secondary sends no NOTIFY after a transfer"
else fail "notify primary-only: the secondary sent a NOTIFY for sv.test"; fi

# NOTIFY is accepted from a primary only with that primary's key (RFC 1996 section 4.5, RFC 8945 section 5.2)
sed 's/hostmaster 1 /hostmaster 2 /' "$W/sx.test.zone" > "$W/sx.tmp" && mv "$W/sx.tmp" "$W/sx.test.zone"
sed 's/hostmaster 1 /hostmaster 2 /' "$W/sv.test.zone" > "$W/sv.tmp" && mv "$W/sv.tmp" "$W/sv.test.zone"
$CTP reload sx.test >/dev/null 2>&1; $CTP reload sv.test >/dev/null 2>&1
if wait_serial sx 2 10; then pass "NOTIFY signed with the key of the primary is accepted: the secondary refreshes at once"
else fail "sx.test was not refreshed by the signed NOTIFY"; fi
sleep 2
if [ "$(serial sv)" = 1 ]; then pass "an unsigned NOTIFY from a primary that has a key is refused: the secondary keeps its serial"
else fail "sv.test followed an unsigned NOTIFY (serial $(serial sv))"; fi

# ---------------------------------------------------------------- karicheck conf
chk() { # chk LABEL EXPECT(ok|error) PATTERN CONF-BODY
    printf '%s\n' "$4" > "$W/c.conf"
    _out=$("$KARICHECK" conf "$W/c.conf" 2>&1); _rc=$?
    case "$2" in
    ok) if [ $_rc -eq 0 ] && ! printf '%s\n' "$_out" | grep -Eq "ERROR|also-notify"; then pass "karicheck: $1"
        else fail "karicheck: $1 (rc $_rc)"; printf '%s\n' "$_out" | head -5; fi ;;
    error) if [ $_rc -ne 0 ] && printf '%s\n' "$_out" | grep -q -- "$3"; then pass "karicheck: $1"
        else fail "karicheck: $1 (rc $_rc, wanted '$3')"; printf '%s\n' "$_out" | head -5; fi ;;
    esac
}
Z="zone \"za.test\" { type master; file \"$W/za.test.zone\"; %s };"
zc() { printf "$Z" "$1"; }
chk "every valid form is accepted without a word" ok "" "options { also-notify port 5353 { sec; 192.0.2.9 key nk; }; };
$KEYS
$(zc 'also-notify { 192.0.2.1; 2001:db8::1 port 5301 key "zk"; };')
remote-servers sec port 5300 { 192.0.2.7; sec2 key nk; };
primaries sec2 { 2001:db8::7; };"
chk "an unknown list name names the file and line" error "c.conf:3: zone 'za.test.' also-notify: 'nolist'" "options { };

$(zc 'also-notify { nolist; };')"
chk "an unknown list name in options" error "c.conf:2: options also-notify: 'nolist'" "options {
  also-notify { nolist; }; };"
chk "an undefined key" error "c.conf:2: .*key 'nokey' is not defined" "options {
  also-notify { 192.0.2.1 key nokey; }; };"
chk "a syntax error (missing ';') names the line" error "c.conf:2: options also-notify: expected ';' after '192.0.2.1'" "options { also-notify {
  192.0.2.1 }; };"
chk "tls is refused" error "'tls' is not supported" "options { also-notify { 192.0.2.1 tls t; }; };"
chk "a list that includes itself" error "nested more than" "options { also-notify { l; }; };
remote-servers l { 192.0.2.1; l; };"
chk "masters syntax error names the line" error "c.conf:2: zone 'za.test.' masters" "$(zc 'masters {
  192.0.2.1 port x; };')"

chk "primaries / masters lists, notify in options, view and zone are accepted without a word" ok "" "options { notify explicit; };
$KEYS
zone \"s.test\" { type slave; primaries port 5300 { sec; 192.0.2.9 key nk; }; notify primary-only; };
masters sec { 192.0.2.7 key zk; };"
chk "an unknown primaries list names the file and line" error "c.conf:2: zone 's.test.' primaries: 'nolist'" "options { };
zone \"s.test\" { type slave; primaries { nolist; }; };"
chk "an undefined primary key" error "c.conf:2: .*key 'nokey' is not defined" "zone \"s.test\" { type slave;
 masters { 192.0.2.1 key nokey; }; };"
chk "tls on a primary is refused" error "'tls' is not supported" "zone \"s.test\" { type slave; primaries { 192.0.2.1 tls t; }; };"
chk "a bad notify value names the line" error "c.conf:2: options notify: invalid value 'maybe'" "options {
 notify maybe; };"
chk "notify is no longer reported as a BIND-only option" ok "" "zone \"s.test\" { type slave; masters { 192.0.2.1; }; notify yes; };"

echo "$FAILS failure(s)"
[ "$FAILS" -eq 0 ]

#!/bin/sh
# ==============================================================================
# run_axfr_stall_reload_test.sh
#
# R11: an outbound zone transfer to a client that stops reading holds back nothing but the one zone version it sends.  Clients with a small
# receive buffer ask for a zone of about 1 MB and read nothing until the test lets them (tests/lib_stall_xfr_client.pl); meanwhile:
#   A. (one primary, TSIG) the zone file changes and `karictl reload` answers "OK reloaded" within 2 s, no zone failed, queries see the new
#      serial; a dynamic UPDATE is answered at once (NOERROR) and served; an IXFR client stalled at the start of a difference keeps it while
#      UPDATEs push it out of the history (ixfr-history 2).  When the clients read: the AXFR is the old version, message for message the same
#      as an AXFR taken before the change (compared without the TSIG RRs, whose time stamps differ), every TSIG MAC verifies (RFC 8945 5.3.1),
#      and the IXFR is the difference it started with (RFC 1995 4: the server's current SOA of that time first and last).
#   B. `karictl reconfig` removes one zone and changes the type of another while their transfers are stalled: it answers OK, the zones are
#      gone / a secondary, and the stalled transfers still deliver the old data.
#   C. a secondary that relays a zone: a downstream client is stalled; the primary's zone changes, the secondary transfers the new version in
#      (the inbound swap is not refused or postponed), and the stalled downstream transfer delivers the old version.
#   D. 140 transfers stalled at once (transfers-out 200; more than the 128 auxiliary reader slots): karictl status answers within 3 s and
#      counts them, a reload answers OK.
#   E. (root, the server with the test hooks: ./karidns-evict, SQLite3) a database zone: its transfer stalled, `karictl evict` (TEST ONLY) is
#      refused while the transfer runs; the loader replaces the zone (a new serial in the database, `karictl reload`); the transfer delivers
#      the old version; after it the zone can be taken out of memory.
# The server is ./karidns-asan when it is built (a sanitizer report fails the test), else ./karidns.  KARIDNS=... picks another (STALL_TEST_TIME_MULT=n
# multiplies the time bounds, for a TSan server).  Waits are on conditions, never fixed
# sleeps.  Loopback only.  SKIP when perl, dag or karictl is missing; part E is skipped (said in the output) without its prerequisites.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
perl -MDigest::SHA -e 1 2>/dev/null || { echo "SKIP: perl has no Digest::SHA"; exit 0; }
for b in ./dag ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
if [ -z "${KARIDNS:-}" ]; then
    if [ -x ./karidns-asan ]; then KARIDNS=./karidns-asan; elif [ -x ./karidns ]; then KARIDNS=./karidns; else echo "SKIP: karidns is not built"; exit 0; fi
fi
CLIENT="perl $SCRIPT_DIR/lib_stall_xfr_client.pl"

T=$(mktemp -d "${TMPDIR:-/tmp}/axfr_stall_reload.XXXXXX") || exit 1
chmod 755 "$T"
PIDS=""
CPIDS=""
cleanup() {
    for p in $CPIDS; do kill "$p" 2>/dev/null; done
    for p in $PIDS; do kari_kill_tree "$p"; done
    rm -rf "$T" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

FAILED=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
now_ms() { perl -MTime::HiRes=time -e 'printf("%d\n", time * 1000)'; }
TMUL=${STALL_TEST_TIME_MULT:-1}     # the time bounds below are multiplied by this (tests/run_rcu_tsan_test.sh part 7: a TSan server is slower)
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0}"

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
SECRET="cnMxMS1zdGFsbC1yZWxvYWQtdGVzdC1rZXktMDAwMDA="
XKEY="xk:dGhlLXN0YWxsLXRyYW5zZmVyLWtleS0wMTIzNDU2Nzg5YWI="
XSEC=${XKEY#xk:}

# big_zone ZONE SERIAL [EXTRA-LINE [FILL]]: about 1 MB (5000 TXT RRs of 200 octets; the first 1000 of FILL, default x, the others of x)
big_zone() {
    {
        echo '$TTL 300'
        echo "\$ORIGIN $1."
        echo "@ IN SOA ns1.$1. hostmaster.$1. ( $2 3600 600 86400 60 )"
        echo "@ IN NS ns1.$1."
        echo 'ns1 IN A 192.0.2.1'
        [ -n "${3:-}" ] && echo "$3"
        perl -e 'my $f = shift; for my $i (1 .. 5000) { my $c = $i <= 1000 ? $f : "x"; printf("r%05d IN TXT \"%s\"\n", $i, $c x 200) }' "${4:-x}"
    }
}
# start NAME CONF PORT: start a server, wait for its first answer
start() {
    "$KARIDNS" -f "$2" > "$T/$1.log" 2>&1 &
    PIDS="$PIDS $!"
    eval "PID_$1=$!"
    kari_wait_answer ./dag "$3" "${4:-example.test}" 20 || { fail "$1 did not start"; cat "$T/$1.log"; exit 1; }
}
ctl() { ./karictl -s "$T/$1.sock" -f "$T/ctl.conf" "$2" ${3:-} ${4:-} 2>&1; }
status_num() { ctl "$1" status | sed -n "s/^$2: \([0-9][0-9]*\).*/\1/p" | head -1; }
serial_of() { ./dag @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump +time=2 +tries=2 2>/dev/null | awk '{print $3}' | head -1; }
# stalled NAME ARGS...: a client in the background that reads when $T/go.NAME exists; its result line goes to $T/NAME.res, its messages to
# $T/NAME.body; returns when its request is sent
stalled() {
    n=$1; shift
    rm -f "$T/$n.ready" "$T/go.$n"
    $CLIENT "$@" --go "$T/go.$n" --ready "$T/$n.ready" --body "$T/$n.body" > "$T/$n.res" 2> "$T/$n.err" &
    CPIDS="$CPIDS $!"
    eval "CPID_$n=$!"
    i=0; while [ ! -s "$T/$n.ready" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i + 1)); done
    [ -s "$T/$n.ready" ] || fail "client $n did not send its request: $(cat "$T/$n.err")"
}
# release NAME: the client reads; wait for it (not in a subshell: $(...) cannot wait for a child of this shell); its line is in $T/NAME.res
release() {
    : > "$T/go.$1"
    eval "wait \$CPID_$1"
}
# wait_xfers SERVER N: until karictl status counts N transfers
wait_xfers() {
    i=0; while [ "$(status_num "$1" "xfers running")" != "$2" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(status_num "$1" "xfers running")" = "$2" ]
}
# timed_ok LABEL MAXMS COMMAND...: COMMAND prints a line starting with "OK" within MAXMS
timed_ok() {
    l=$1; mx=$2; shift 2
    t0=$(now_ms); out=$("$@"); t1=$(now_ms)
    case "$out" in
        OK*) [ $((t1 - t0)) -le $((mx * TMUL)) ] && pass "$l ($((t1 - t0)) ms: $out)" || fail "$l: $((t1 - t0)) ms ($out)" ;;
        *) fail "$l: '$out'" ;;
    esac
}
# update PORT ZONE OWNER IPV4: a dynamic UPDATE adding OWNER A IPV4 (RFC 2136 2.5.1), unsigned, over UDP; prints "rcode=<n> ms=<elapsed>"
update() {
    perl -MSocket -MTime::HiRes=time -e '
        my ($port, $zone, $owner, $ip) = @ARGV;
        sub wn { my $n = lc shift; $n =~ s/\.$//; join("", map { chr(length $_) . $_ } split /\./, $n) . "\0" }
        my $m = pack("nnnnnn", 0x7777, 5 << 11, 1, 0, 1, 0) . wn($zone) . pack("nn", 6, 1) .
                wn($owner) . pack("nnNn", 1, 1, 60, 4) . inet_aton($ip);
        socket(my $s, PF_INET, SOCK_DGRAM, 0) or die;
        my $t0 = time;
        send($s, $m, 0, sockaddr_in($port, inet_aton("127.0.0.1"))) or die;
        my $rin = ""; vec($rin, fileno($s), 1) = 1;
        if (!select($rin, undef, undef, 8)) { print "rcode=timeout\n"; exit }
        recv($s, my $r, 512, 0);
        printf("rcode=%d ms=%d\n", unpack("n", substr($r, 2, 2)) & 15, (time - $t0) * 1000);' "$@"
}
sanitizer_clean() {
    if grep -q "ERROR: AddressSanitizer\|runtime error:\|ERROR: ThreadSanitizer" "$T/$1.log"; then
        fail "$1: a sanitizer report: $(grep -m1 'ERROR: AddressSanitizer\|runtime error:\|ERROR: ThreadSanitizer' "$T/$1.log")"
    else
        pass "$1: no sanitizer report"
    fi
}
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$T/ctl.conf"
chmod 600 "$T/ctl.conf"

echo "=== R11: a stalled outbound transfer holds back only its version ($(basename "$KARIDNS")) ==="

# ---------------------------------------------------------------------------------------------------------------- A
echo "== A. reload, UPDATE and IXFR history churn during stalled transfers (TSIG)"
PA=$(kari_port 0 $((27000 + $$ % 4000)))
big_zone example.test 1 > "$T/example.test.zone"
cat > "$T/a.conf" <<EOF
options { port $PA; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT ixfr-history 2; };
control-channel { socket "$T/a.sock"; algorithm hmac-sha256; secret "$SECRET"; };
key "xk" { algorithm hmac-sha256; secret "$XSEC"; };
zone "example.test" { type primary; file "$T/example.test.zone"; allow-transfer { key "xk"; }; allow-update { 127.0.0.1; }; notify no; };
EOF
chmod 644 "$T/example.test.zone" "$T/a.conf"
start a "$T/a.conf" "$PA"
REF=$($CLIENT --port "$PA" --zone example.test --key "$XKEY" --body "$T/ref.body" --rcvbuf 262144)
echo "   reference AXFR: $REF"
case "$REF" in *"FIRST=1 LAST=1 TSIG=ok RCODE=0"*) pass "the reference AXFR (serial 1, every TSIG verifies)" ;; *) fail "the reference AXFR: $REF" ;; esac
stalled s1 --port "$PA" --zone example.test --key "$XKEY"
wait_xfers a 1 && pass "the AXFR is stalled (xfers running: 1)" || fail "xfers running: $(status_num a "xfers running")"

big_zone example.test 2 "changed IN A 192.0.2.2" y > "$T/example.test.zone.new"
mv "$T/example.test.zone.new" "$T/example.test.zone"
chmod 644 "$T/example.test.zone"
timed_ok "reload after the zone file changed, the transfer stalled: OK within 2 s, no zone failed" 2000 ctl a reload
[ "$(serial_of "$PA" example.test)" = "2" ] && pass "queries see the new serial (2)" || fail "serial: $(serial_of "$PA" example.test)"
U=$(update "$PA" example.test u1.example.test 192.0.2.11)
case "$U" in "rcode=0 "*) M=${U#*ms=}; [ "$M" -lt $((2000 * TMUL)) ] && pass "a dynamic UPDATE during the stall: NOERROR at once ($U)" || fail "the UPDATE took $M ms" ;; *) fail "the UPDATE: $U" ;; esac
./dag @127.0.0.1 -p "$PA" u1.example.test A +short +nohexdump +time=2 +tries=2 | grep -q 192.0.2.11 && pass "the update is served" || fail "u1.example.test not served"
[ "$(serial_of "$PA" example.test)" = "3" ] && pass "serial 3 after the UPDATE" || fail "serial: $(serial_of "$PA" example.test)"
# an IXFR from serial 1 (the differences 1 -> 2, 1000 TXT RRs changed by the reload, and 2 -> 3, the UPDATE: about 450 KB), stalled; then UPDATEs
# push both differences out of the history (depth 2)
stalled i1 --port "$PA" --zone example.test --type IXFR --ixfr-serial 1 --key "$XKEY"
wait_xfers a 2 && pass "an IXFR is stalled too (xfers running: 2)" || fail "xfers running: $(status_num a "xfers running")"
for k in 2 3 4; do update "$PA" example.test "u$k.example.test" "192.0.2.1$k" > /dev/null; done
[ "$(serial_of "$PA" example.test)" = "6" ] && pass "three more UPDATEs (serial 6; the differences from serial 1 have left the history)" || fail "serial: $(serial_of "$PA" example.test)"
NOW=$($CLIENT --port "$PA" --zone example.test --type IXFR --ixfr-serial 1 --key "$XKEY" --rcvbuf 262144)
case "$NOW" in *"FIRST=6 LAST=6"*) pass "an IXFR from serial 1 now is a full transfer of serial 6 ($NOW)" ;; *) fail "a new IXFR from 1: $NOW" ;; esac
timed_ok "a second reload is not postponed" 2000 ctl a reload
W=$(status_num a "retired zone snapshots waiting")
[ "$W" = "0" ] && pass "retired zone snapshots waiting: 0" || fail "retired zone snapshots waiting: $W"
release s1; R1=$(cat "$T/s1.res")
echo "   stalled AXFR: $R1"
case "$R1" in *"FIRST=1 LAST=1 TSIG=ok RCODE=0"*) pass "the stalled AXFR delivers serial 1 and every TSIG MAC verifies" ;; *) fail "the stalled AXFR: $R1" ;; esac
cmp -s "$T/ref.body" "$T/s1.body" && pass "message for message the AXFR taken before the change (without the TSIG RRs)" || fail "the stalled AXFR differs from the reference"
release i1; R2=$(cat "$T/i1.res")
echo "   stalled IXFR: $R2"
case "$R2" in *"FIRST=3 LAST=3 TSIG=ok RCODE=0"*) pass "the stalled IXFR is the two differences it started with (current SOA 3 first and last; TSIG verifies)" ;; *) fail "the stalled IXFR: $R2" ;; esac
perl -0777 -ne 'exit(/\x02u1(?:\x07example|[\xC0-\xFF])/ ? 0 : 1)' "$T/i1.body" \
    && pass "the IXFR carries the UPDATE's record" || fail "the IXFR does not carry u1"
i=0; while [ "$(status_num a "retired zone versions waiting")" != "0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num a "retired zone versions waiting")" = "0" ] && pass "the transfers over, no retired version waits" || fail "retired zone versions waiting: $(status_num a "retired zone versions waiting")"
BAD='failed to load\|[Rr]eload postponed\|postponed: active AXFR\|rejected: active AXFR'
grep -q "$BAD" "$T/a.log" && fail "the log: $(grep "$BAD" "$T/a.log" | head -2)" || pass "no failed, postponed or rejected change in the log"
sanitizer_clean a

# ---------------------------------------------------------------------------------------------------------------- B
echo "== B. reconfig removes one zone and changes the type of another during their stalled transfers"
PB=$(kari_port 1 $((PA + 1)))
PDEAD=$(kari_port 2 $((PA + 2)))
big_zone gone.test 7 > "$T/gone.test.zone"
big_zone retype.test 8 > "$T/retype.test.zone"
chmod 644 "$T/gone.test.zone" "$T/retype.test.zone"
cat > "$T/b.conf" <<EOF
options { port $PB; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$T/b.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "example.test" { type primary; file "$T/example.test.zone"; };
zone "gone.test" { type primary; file "$T/gone.test.zone"; allow-transfer { 127.0.0.1; }; notify no; };
zone "retype.test" { type primary; file "$T/retype.test.zone"; allow-transfer { 127.0.0.1; }; notify no; };
EOF
chmod 644 "$T/b.conf"
start b "$T/b.conf" "$PB"
$CLIENT --port "$PB" --zone gone.test --body "$T/gref.body" --rcvbuf 262144 > /dev/null
$CLIENT --port "$PB" --zone retype.test --body "$T/tref.body" --rcvbuf 262144 > /dev/null
stalled g1 --port "$PB" --zone gone.test
stalled t1 --port "$PB" --zone retype.test
wait_xfers b 2 && pass "two transfers stalled" || fail "xfers running: $(status_num b "xfers running")"
cat > "$T/b.conf" <<EOF
options { port $PB; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$T/b.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "example.test" { type primary; file "$T/example.test.zone"; };
zone "retype.test" { type secondary; masters { 127.0.0.1 port $PDEAD; }; };
EOF
timed_ok "reconfig: gone.test removed, retype.test now a secondary (OK within 2 s)" 2000 ctl b reconfig
./dag @127.0.0.1 -p "$PB" gone.test SOA +nohexdump +time=2 +tries=1 2>/dev/null | grep -q "status: REFUSED" && pass "gone.test is not served any more" || fail "gone.test is still served"
release g1; G=$(cat "$T/g1.res")
case "$G" in *"FIRST=7 LAST=7"*) cmp -s "$T/gref.body" "$T/g1.body" && pass "the stalled transfer of the removed zone delivers its data ($G)" || fail "gone.test: the stream differs" ;; *) fail "gone.test: $G" ;; esac
release t1; R=$(cat "$T/t1.res")
case "$R" in *"FIRST=8 LAST=8"*) cmp -s "$T/tref.body" "$T/t1.body" && pass "the stalled transfer of the retyped zone delivers its old data ($R)" || fail "retype.test: the stream differs" ;; *) fail "retype.test: $R" ;; esac
kill -0 "$PID_b" 2>/dev/null && pass "the server runs" || fail "the server is gone"
sanitizer_clean b

# ---------------------------------------------------------------------------------------------------------------- C
echo "== C. a secondary that relays: its inbound transfer is not refused while a downstream transfer is stalled"
PP=$(kari_port 3 $((PA + 3)))
PS=$(kari_port 4 $((PA + 4)))
big_zone relay.test 10 > "$T/relay.test.zone"
chmod 644 "$T/relay.test.zone"
cat > "$T/p.conf" <<EOF
options { port $PP; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$T/p.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "relay.test" { type primary; file "$T/relay.test.zone"; allow-transfer { 127.0.0.1; }; also-notify { 127.0.0.1 port $PS; }; notify explicit; };
EOF
cat > "$T/s.conf" <<EOF
options { port $PS; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$T/s.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "relay.test" { type secondary; masters { 127.0.0.1 port $PP; }; allow-transfer { 127.0.0.1; }; allow-notify { 127.0.0.1; }; notify no; };
EOF
chmod 644 "$T/p.conf" "$T/s.conf"
start p "$T/p.conf" "$PP" relay.test
start s "$T/s.conf" "$PS" relay.test
i=0; while [ "$(serial_of "$PS" relay.test)" != "10" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(serial_of "$PS" relay.test)" = "10" ] && pass "the secondary has serial 10" || fail "the secondary: '$(serial_of "$PS" relay.test)'"
$CLIENT --port "$PS" --zone relay.test --body "$T/rref.body" --rcvbuf 262144 > /dev/null
stalled d1 --port "$PS" --zone relay.test
wait_xfers s 1 && pass "a downstream transfer from the secondary is stalled" || fail "xfers running: $(status_num s "xfers running")"
big_zone relay.test 11 "new IN A 192.0.2.111" > "$T/relay.test.zone.new"
mv "$T/relay.test.zone.new" "$T/relay.test.zone"; chmod 644 "$T/relay.test.zone"
timed_ok "the primary reloads" 2000 ctl p reload
ctl s retransfer relay.test > /dev/null
i=0; while [ "$(serial_of "$PS" relay.test)" != "11" ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(serial_of "$PS" relay.test)" = "11" ] && pass "the secondary installed serial 11 while its downstream transfer is stalled" || fail "the secondary: '$(serial_of "$PS" relay.test)'"
grep -q "Inbound transfer swap.*postponed" "$T/s.log" && fail "the inbound swap was postponed" || pass "no postponed inbound swap in the log"
release d1; D=$(cat "$T/d1.res")
case "$D" in *"FIRST=10 LAST=10"*) cmp -s "$T/rref.body" "$T/d1.body" && pass "the stalled downstream transfer delivers serial 10 as before ($D)" || fail "relay: the stream differs" ;; *) fail "relay: $D" ;; esac
sanitizer_clean p
sanitizer_clean s

# ---------------------------------------------------------------------------------------------------------------- D
echo "== D. 140 stalled transfers at once (transfers-out 200): the control channel still answers"
PD=$(kari_port 5 $((PA + 5)))
cat > "$T/d.conf" <<EOF
options { port $PD; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT transfers-out 200; };
control-channel { socket "$T/d.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "example.test" { type primary; file "$T/example.test.zone"; allow-transfer { 127.0.0.1; }; notify no; };
EOF
chmod 644 "$T/d.conf"
start d "$T/d.conf" "$PD"
rm -f "$T/many.ready" "$T/go.many"
$CLIENT --port "$PD" --zone example.test --count 140 --ready "$T/many.ready" --go "$T/go.many" > "$T/many.res" 2> "$T/many.err" &
MANY=$!
CPIDS="$CPIDS $MANY"
i=0; while [ ! -s "$T/many.ready" ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i + 1)); done
i=0; while [ "$(status_num d "xfers running")" != "140" ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i + 1)); done
t0=$(now_ms); N=$(status_num d "xfers running"); t1=$(now_ms)
[ "$N" = "140" ] && [ $((t1 - t0)) -lt $((3000 * TMUL)) ] && pass "karictl status answers in $((t1 - t0)) ms with 140 transfers running" || fail "status: '$N' transfers, $((t1 - t0)) ms ($(cat "$T/many.err"))"
timed_ok "a reload with 140 stalled transfers" 3000 ctl d reload
: > "$T/go.many"
wait "$MANY" 2>/dev/null
i=0; while [ "$(status_num d "xfers running")" != "0" ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num d "xfers running")" = "0" ] && pass "the clients gone, the transfers end" || fail "xfers running: $(status_num d "xfers running")"
sanitizer_clean d

# ---------------------------------------------------------------------------------------------------------------- E
echo "== E. a database zone: eviction deferred and the loader's replacement during a stalled transfer"
E_SKIP=""
[ "$(id -u)" = "0" ] || E_SKIP="needs root (the loader runs as another user)"
[ -z "$E_SKIP" ] && { [ -x ./karidns-evict ] && grep -q 'no such zone in memory' ./karidns-evict 2>/dev/null || E_SKIP="./karidns-evict is not built (make evict)"; }
[ -z "$E_SKIP" ] && { [ -x ./karidns-dbloader ] && ./karidns-dbloader --drivers | grep -qx sqlite3 || E_SKIP="./karidns-dbloader with SQLite3 is not built"; }
[ -z "$E_SKIP" ] && { [ -x ./tests/db/zone2sql ] || E_SKIP="tests/db/zone2sql is not built"; }
[ -z "$E_SKIP" ] && { command -v sqlite3 >/dev/null 2>&1 || E_SKIP="the sqlite3 command line tool is not installed"; }
[ -z "$E_SKIP" ] && { id nobody >/dev/null 2>&1 || E_SKIP="no user nobody"; }
if [ -n "$E_SKIP" ]; then
    echo "  SKIP (part E): $E_SKIP"
else
    PE=$(kari_port 6 $((PA + 6)))
    mkdir "$T/db"
    chown nobody "$T/db"; chmod 777 "$T/db"
    sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    big_zone dbz.test 20 | sed 's/( 20 3600 600 86400 60 )/20 3600 600 86400 60/' > "$T/dbz.test.zone"
    ./tests/db/zone2sql --dialect sqlite3 "$T/dbz.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
    sqlite3 "$T/db/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE name = 'dbz.test';"
    chmod 666 "$T/db/z.db"*
    install -o root -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    cat > "$T/e.conf" <<EOF
options {
    user "nobody"; pid-file "none"; port $PE; bind-address { 127.0.0.1; };
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 1; acl-ceiling { 127.0.0.1; }; };
};
control-channel { socket "$T/e.sock"; algorithm hmac-sha256; secret "$SECRET"; };
EOF
    chmod 644 "$T/e.conf"
    KARIDNS_SAVE=$KARIDNS; KARIDNS=./karidns-evict
    start e "$T/e.conf" "$PE" dbz.test
    KARIDNS=$KARIDNS_SAVE
    i=0; while [ "$(serial_of "$PE" dbz.test)" != "20" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(serial_of "$PE" dbz.test)" = "20" ] && pass "the database zone is served (serial 20)" || fail "dbz.test: '$(serial_of "$PE" dbz.test)'"
    $CLIENT --port "$PE" --zone dbz.test --body "$T/eref.body" --rcvbuf 262144 > "$T/eref.res"
    case "$(cat "$T/eref.res")" in *"FIRST=20 LAST=20"*) pass "the reference transfer of the database zone" ;; *) fail "the reference: $(cat "$T/eref.res")" ;; esac
    stalled e1 --port "$PE" --zone dbz.test
    wait_xfers e 1 && pass "the transfer of the database zone is stalled" || fail "xfers running: $(status_num e "xfers running")"
    ctl e evict dbz.test | grep -q '^ERROR' && pass "karictl evict (TEST ONLY) is refused while the transfer runs (the zone stays in memory)" || fail "the zone was evicted during its transfer"
    sqlite3 "$T/db/z.db" "UPDATE records SET content = REPLACE(content, ' 20 3600 ', ' 21 3600 ') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = 'dbz.test');"
    ctl e reload > /dev/null
    i=0; while [ "$(serial_of "$PE" dbz.test)" != "21" ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(serial_of "$PE" dbz.test)" = "21" ] && pass "the loader replaced the zone (serial 21) during the stalled transfer" || fail "dbz.test after the change: '$(serial_of "$PE" dbz.test)'"
    release e1; E1=$(cat "$T/e1.res")
    case "$E1" in *"FIRST=20 LAST=20"*) cmp -s "$T/eref.body" "$T/e1.body" && pass "the stalled transfer delivers the old version ($E1)" || fail "dbz.test: the stream differs" ;; *) fail "dbz.test: $E1" ;; esac
    i=0; while [ "$(status_num e "xfers running")" != "0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    i=0; until ctl e evict dbz.test | grep -q '^OK' || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
    [ $i -lt 50 ] && pass "after the transfer the zone can be taken out of memory" || fail "karictl evict after the transfer: $(ctl e evict dbz.test)"
    sanitizer_clean e
fi

if [ "$FAILED" -eq 0 ]; then
    echo "=== run_axfr_stall_reload_test: all checks passed ==="
    exit 0
fi
echo "=== run_axfr_stall_reload_test: $FAILED check(s) FAILED ==="
exit 1

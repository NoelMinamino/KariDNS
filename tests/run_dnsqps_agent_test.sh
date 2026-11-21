#!/bin/sh
# dnsqps with several client hosts (docs/dnsqps.md "Several client hosts"): a controller (--agents) and two agents (--agent) on loopback addresses, against a real
# karidns when ./karidns exists, else against dnsqps's own reflector.  The sums of the senders, the exact merge, --no-local, the shared key, an agent that is
# killed in the run (the controller aborts the others and exits 3), an agent that is never ready, an agent that refuses the run, and a raw client that sends the
# agent garbage, an oversized message and options it must not take (the agent stays up and serves the next controller).  Bounded waits only.
# The transport is TCP on 127.0.0.1; the agents' load goes over the socket paths.  No real domain names: example.test.  SKIP without perl (the raw client).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
cd "$ROOT" || exit 1
DQ="${DNSQPS:-./dnsqps}"
BIN="./karidns"
[ -x "$DQ" ] || { echo "SKIP: no $DQ"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: no perl"; exit 0; }
PORT=$(kari_port 0 15751)
A1=$(kari_port 1 15752)
A2=$(kari_port 2 15753)
A3=$(kari_port 3 15754)
A4=$(kari_port 4 15755)
W=$(mktemp -d "${TMPDIR:-/tmp}/dnsqps_agent.XXXXXX")
chmod 755 "$W"
PIDS=""
SRV=""
cleanup() {
    set +e
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
jnum() { sed -n "s/.*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }
# wait_exit PID SECONDS: wait for the process to end (it is a child of this shell), bounded
wait_exit() {
    _i=0
    while kill -0 "$1" 2>/dev/null; do
        _i=$((_i + 1)); [ "$_i" -le $(($2 * 10)) ] || return 1
        sleep 0.1
    done
    return 0
}
start_agent() { # port [extra args]: starts an agent, waits until it listens, adds its PID to PIDS and AGENT_PID
    _p=$1; shift
    "$DQ" -r --agent "127.0.0.1:$_p" "$@" > "$W/agent$_p.log" 2>&1 &
    AGENT_PID=$!
    PIDS="$PIDS $AGENT_PID"
    kari_wait_log "$W/agent$_p.log" "agent listening" 10 || { cat "$W/agent$_p.log"; fail "agent $_p did not start"; }
}

# ---------------------------------------------------------------- the target: karidns, or the reflector
if [ -x "$BIN" ]; then
    cat > "$W/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
mail IN A 192.0.2.11
EOF
    USER_OPT=""
    [ "$(id -u)" = "0" ] && USER_OPT='user "nobody"; group "nobody";'
    cat > "$W/server.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "example.test" { type master; file "$W/example.test.zone"; };
EOF
    "$BIN" -f "$W/server.conf" > "$W/server.log" 2>&1 &
    SRV=$!
    i=0
    until [ -x ./dag ] && ./dag example.test SOA @127.0.0.1 -p "$PORT" +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1; do
        i=$((i + 1)); [ "$i" -le 50 ] || { cat "$W/server.log"; fail "karidns did not start"; exit 1; }
        sleep 0.3
    done
    TARGET="karidns"
else
    "$DQ" -r --reflect "127.0.0.1:$PORT" > "$W/refl.log" 2>&1 &
    PIDS="$PIDS $!"
    kari_wait_log "$W/refl.log" reflecting 10 || fail "the reflector did not start"
    TARGET="the reflector"
fi
printf 'www.example.test A\nmail.example.test MX +dnssec\nnothere.example.test A +cookie=random\nwww.example.test AAAA\n' > "$W/q.txt"
CTL="-s 127.0.0.1 -p $PORT -d $W/q.txt -T 1 -q 64 -t 1 --agent-timeout 10"

# ---------------------------------------------------------------- 1. two agents and the controller: the sums are exact
start_agent "$A1"; P1=$AGENT_PID
start_agent "$A2"; P2=$AGENT_PID
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1,127.0.0.1:$A2" $CTL -N 30000 --json > "$W/r1.json" 2> "$W/r1.err"; rc=$?
[ "$rc" -eq 0 ] || { cat "$W/r1.err"; fail "controller with two agents: exit $rc"; }
sent=$(jnum sent < "$W/r1.json"); done_=$(jnum completed < "$W/r1.json"); lost=$(jnum lost < "$W/r1.json")
[ "$sent" = "30000" ] || fail "merged sent $sent, expected 30000"
[ "${done_:-0}" -ge 28500 ] && [ $(( ${done_:-0} + ${lost:-0} )) -eq 30000 ] || fail "merged completed ${done_:-?} lost ${lost:-?} of 30000"
grep -q '"server":"127.0.0.1:[0-9]*, 3 senders"' "$W/r1.json" || fail "the merged report does not name 3 senders: $(head -c 300 "$W/r1.json")"
a1=$(sed -n "s/^\[Agent 127.0.0.1:$A1\] sent \([0-9]*\),.*/\1/p" "$W/r1.err"); a2=$(sed -n "s/^\[Agent 127.0.0.1:$A2\] sent \([0-9]*\),.*/\1/p" "$W/r1.err")
l0=$(sed -n 's/^\[Local\] sent \([0-9]*\),.*/\1/p' "$W/r1.err")
[ "$a1" = "10000" ] && [ "$a2" = "10000" ] && [ "$l0" = "10000" ] || fail "the shares of -N 30000: local ${l0:-?}, agents ${a1:-?} and ${a2:-?}, expected 10000 each"
[ "$(( ${a1:-0} + ${a2:-0} + ${l0:-0} ))" = "$sent" ] || fail "the lines of the senders do not add up to the merged sent"
grep -q '"p99":' "$W/r1.json" || fail "no merged latency"
echo "ok: controller + 2 agents ($TARGET): sent $sent, completed $done_, shares $l0/$a1/$a2"

# the text report, an open loop shared among the senders (-Q 3000: 1000 each), interval lines of the sum
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1,127.0.0.1:$A2" $CTL -Q 3000 -l 3.5 -S 1 > "$W/r2.out" 2> "$W/r2.err"; rc=$?
[ "$rc" -eq 0 ] || { cat "$W/r2.err"; fail "open loop with agents: exit $rc"; }
sent=$(sed -n 's/^  Queries sent: *\([0-9]*\)$/\1/p' "$W/r2.out")
{ [ "${sent:-0}" -ge 8500 ] && [ "${sent:-0}" -le 11500 ]; } || fail "-Q 3000 for 3.5 s over 3 senders: sent ${sent:-?}, expected about 10500"
n=$(grep -c '^\[Interval\]' "$W/r2.out"); [ "$n" -ge 2 ] || fail "interval lines of the merged run: $n"
grep -q 'Queries per second' "$W/r2.out" && grep -q 'Average Latency' "$W/r2.out" || fail "text report of the merged run"
echo "ok: open loop shared: sent $sent, $n interval lines"

# ---------------------------------------------------------------- 2. --no-local
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1,127.0.0.1:$A2" --no-local $CTL -N 5000 --json -S 1 > "$W/r3.json" 2> "$W/r3.err"; rc=$?
[ "$rc" -eq 0 ] || { cat "$W/r3.err"; fail "--no-local: exit $rc"; }
sent=$(jnum sent < "$W/r3.json")
[ "$sent" = "5000" ] && grep -q '2 senders' "$W/r3.json" && ! grep -q '^\[Local\]' "$W/r3.err" || fail "--no-local: sent ${sent:-?}, $(head -c 200 "$W/r3.json")"
echo "ok: --no-local: sent $sent"

# ---------------------------------------------------------------- 3. an agent that refuses: a query file it cannot read
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1" --no-local -s 127.0.0.1 -p "$PORT" -d "$W/missing.txt" -N 100 --agent-timeout 10 > "$W/r4.out" 2> "$W/r4.err"; rc=$?
[ "$rc" -eq 2 ] && grep -q "agent 127.0.0.1:$A1: .*missing.txt" "$W/r4.err" || fail "an agent that cannot read the query file: exit $rc: $(cat "$W/r4.err")"
echo "ok: an agent that refuses the run: exit $rc"
# the local set-up fails: the agents are told to abort, exit 2
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1" -s 127.0.0.1 -p "$PORT" -d "$W/missing.txt" -N 100 --agent-timeout 10 > "$W/r5.out" 2> "$W/r5.err"; rc=$?
[ "$rc" -eq 2 ] || fail "local set-up failure: exit $rc"
# and the agent is free for the next controller (one at a time, and after an abort)
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1" $CTL -N 2000 --json > "$W/r6.json" 2>/dev/null; rc=$?
[ "$rc" -eq 0 ] && [ "$(jnum sent < "$W/r6.json")" = "2000" ] || fail "the agent did not serve the run after an aborted one: exit $rc"
echo "ok: an aborted run frees the agent"

# ---------------------------------------------------------------- 4. an agent that never gets ready
cat > "$W/hung.pl" <<'PERL'
use strict; use warnings; use IO::Socket::INET;
my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $ARGV[0], Proto => 'tcp', Listen => 2, ReuseAddr => 1) or die "listen: $!";
print STDERR "listening\n";
my $c = $s->accept or die;
my $m = "HELLO\nv=1\nnonce=00112233445566778899aabbccddeeff\nauth=0\n";
print $c pack('N', length $m), $m;
sleep 30;   # takes the run, says nothing
PERL
perl "$W/hung.pl" "$A4" 2> "$W/hung.err" &
PIDS="$PIDS $!"
kari_wait_log "$W/hung.err" listening 10 || fail "the silent agent did not start"
t0=$(date +%s)
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A4" $CTL -N 1000 --agent-timeout 2 > "$W/r7.out" 2> "$W/r7.err"; rc=$?
t1=$(date +%s)
[ "$rc" -eq 2 ] && grep -q 'not ready in time' "$W/r7.err" || fail "an agent that is not ready: exit $rc: $(cat "$W/r7.err")"
[ $((t1 - t0)) -le 10 ] || fail "the controller waited $((t1 - t0)) s for an agent that is not ready (--agent-timeout 2)"
echo "ok: an agent that is not ready in time: exit $rc after $((t1 - t0)) s"
# an agent that is not there at all
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A3" $CTL -N 1000 --agent-timeout 2 > "$W/r8.out" 2> "$W/r8.err"; rc=$?
[ "$rc" -eq 2 ] && grep -q "agent 127.0.0.1:$A3" "$W/r8.err" || fail "no agent at the address: exit $rc: $(cat "$W/r8.err")"
echo "ok: no agent at the address: exit $rc"

# ---------------------------------------------------------------- 5. an agent killed in the run
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1,127.0.0.1:$A2" $CTL -Q 2000 -l 30 -S 1 > "$W/r9.out" 2> "$W/r9.err" &
CTLPID=$!
PIDS="$PIDS $CTLPID"
kari_wait_log "$W/r9.out" '^\[Interval\]' 30 2 || fail "the run did not start (no interval lines)"
kill -9 "$P2" 2>/dev/null
wait_exit "$CTLPID" 20 || { kill "$CTLPID" 2>/dev/null; fail "the controller did not end 20 s after an agent was killed"; }
wait "$CTLPID"; rc=$?
[ "$rc" -eq 3 ] && grep -q "aborted: agent 127.0.0.1:$A2" "$W/r9.err" || fail "an agent killed in the run: exit $rc: $(tail -3 "$W/r9.err")"
! grep -q '^Statistics:' "$W/r9.out" || fail "a merged report was printed although an agent was lost"
echo "ok: an agent killed in the run: exit $rc, no merged report"
# the other agent noticed the abort and is free again
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A1" $CTL -N 2000 --json > "$W/r10.json" 2>/dev/null; rc=$?
[ "$rc" -eq 0 ] && [ "$(jnum sent < "$W/r10.json")" = "2000" ] || fail "the surviving agent is not free after the abort: exit $rc"
echo "ok: the surviving agent stopped its load and serves again"
start_agent "$A2"; P2=$AGENT_PID

# ---------------------------------------------------------------- 6. the shared key
printf 'a-shared-secret-of-some-length\n' > "$W/key"
printf 'another-secret-of-some-length!\n' > "$W/key2"
start_agent "$A3" --agent-key "$W/key"; P3=$AGENT_PID
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A3" --agent-key "$W/key" $CTL -N 3000 --json > "$W/r11.json" 2> "$W/r11.err"; rc=$?
[ "$rc" -eq 0 ] && [ "$(jnum sent < "$W/r11.json")" = "3000" ] || fail "the right key: exit $rc: $(cat "$W/r11.err")"
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A3" --agent-key "$W/key2" $CTL -N 3000 > "$W/r12.out" 2> "$W/r12.err"; rc=$?
[ "$rc" -eq 2 ] && grep -q 'authentication failed' "$W/r12.err" || fail "the wrong key: exit $rc: $(cat "$W/r12.err")"
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A3" $CTL -N 3000 > "$W/r13.out" 2> "$W/r13.err"; rc=$?
[ "$rc" -eq 2 ] && grep -q 'wants a key' "$W/r13.err" || fail "no key for an agent that wants one: exit $rc: $(cat "$W/r13.err")"
echo "ok: the shared key: right key runs, wrong key and no key are refused"

# ---------------------------------------------------------------- 7. a raw client: garbage, an oversized message, options an agent must not take
cat > "$W/raw.pl" <<'PERL'
use strict; use warnings; use IO::Socket::INET; use IO::Select;
my ($port, $case) = @ARGV;
my $c = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port", Proto => 'tcp') or die "connect: $!";
sub rd { my ($n) = @_; my $b = ''; my $sel = IO::Select->new($c);
    while (length $b < $n) { return undef unless $sel->can_read(5); my $r = sysread($c, my $x, $n - length $b); return undef unless $r; $b .= $x } $b }
sub msg { my $h = rd(4); return undef unless defined $h; my $n = unpack('N', $h); return undef if $n > 262144; rd($n) }
my $hello = msg(); die "no hello\n" unless defined $hello && $hello =~ /^HELLO\n/;
if ($case eq 'garbage') { syswrite($c, "\xff\xff\xff\xffgarbage") }
elsif ($case eq 'zero') { syswrite($c, pack('N', 0)) }
elsif ($case eq 'badverb') { my $m = "run\nv=1\n"; syswrite($c, pack('N', length $m) . $m) }
elsif ($case eq 'nokv') { my $m = "RUN\nv=1\narg=-h\n"; syswrite($c, pack('N', length $m) . $m) }
elsif ($case eq 'reflect') { my $m = "RUN\nv=1\narg=--reflect\narg=127.0.0.1:1\n"; syswrite($c, pack('N', length $m) . $m) }
elsif ($case eq 'agent') { my $m = "RUN\nv=1\narg=--agent=127.0.0.1:9\n"; syswrite($c, pack('N', length $m) . $m) }
elsif ($case eq 'badopt') { my $m = "RUN\nv=1\narg=--nosuchoption\n"; syswrite($c, pack('N', length $m) . $m) }
elsif ($case eq 'slow') { syswrite($c, pack('N', 100) . "RUN\nv=1\n"); sleep 1 }   # a cut message, then the end of the connection
my $r = msg();
if (defined $r && $r =~ /^ERR\nmsg=(.*)\n/) { print "ERR $1\n" } elsif (defined $r) { print "OTHER ", (split /\n/, $r)[0], "\n" } else { print "CLOSED\n" }
PERL
for c in garbage zero badverb nokv reflect agent badopt slow; do
    out=$(perl "$W/raw.pl" "$A2" "$c" 2>&1 | head -1)
    case "$c:$out" in
        garbage:CLOSED|zero:CLOSED|slow:CLOSED|badverb:CLOSED) ;;
        nokv:ERR*|reflect:ERR*|agent:ERR*|badopt:ERR*) ;;
        *) fail "raw client '$c': $out" ;;
    esac
done
echo "ok: the agent answers garbage, a bad length, a bad verb, banned options and a bad option with an error or a close"
# the agent still serves
# shellcheck disable=SC2086
"$DQ" -r --agents "127.0.0.1:$A2" $CTL -N 2000 --json > "$W/r14.json" 2>/dev/null; rc=$?
[ "$rc" -eq 0 ] && [ "$(jnum sent < "$W/r14.json")" = "2000" ] || fail "the agent does not serve after the bad clients: exit $rc"
echo "ok: the agent serves a controller after the bad clients"

# ---------------------------------------------------------------- 7b. netmap on the interface of the control connection (FreeBSD: 127.0.0.1 is on lo0)
# The agent's own --io / --iface are used (not the controller's); netmap there would take the interface from the host stack, so both sides refuse
# before anything is opened.
if [ "$(uname -s)" = "FreeBSD" ]; then
    A5=$(kari_port 5 15756)
    start_agent "$A5" --io netmap --iface lo0
    # shellcheck disable=SC2086
    "$DQ" -r --agents "127.0.0.1:$A5" $CTL -N 100 > "$W/r15.out" 2> "$W/r15.err"; rc=$?
    [ "$rc" -eq 2 ] && grep -q "agent 127.0.0.1:$A5: netmap on lo0" "$W/r15.err" || fail "an agent with netmap on its control interface: exit $rc: $(cat "$W/r15.err")"
    # shellcheck disable=SC2086
    "$DQ" -r --io netmap --iface lo0 --agents "127.0.0.1:$A1" $CTL -N 100 > "$W/r16.out" 2> "$W/r16.err"; rc=$?
    [ "$rc" -eq 2 ] && grep -q "netmap on lo0" "$W/r16.err" || fail "a controller with netmap on its control interface: exit $rc: $(cat "$W/r16.err")"
    # the controller's --io netmap is not the agent's: an agent with the socket paths serves a netmap controller's command line (--no-local)
    # shellcheck disable=SC2086
    "$DQ" -r --io netmap --iface lo0 --no-local --agents "127.0.0.1:$A1" $CTL -N 2000 --json > "$W/r17.json" 2> "$W/r17.err"; rc=$?
    [ "$rc" -eq 0 ] && [ "$(jnum sent < "$W/r17.json")" = "2000" ] || fail "an agent with its own sending path: exit $rc: $(cat "$W/r17.err")"
    echo "ok: the sending path is the agent's own; netmap on the control interface is refused on both sides"
fi

# ---------------------------------------------------------------- 8. usage errors
for bad in "--agent 0.0.0.0:5301" "--agent 127.0.0.1" "--agents nohost" "--no-local" "--agent-key $W/key"; do
    # shellcheck disable=SC2086
    "$DQ" -r $bad -s 127.0.0.1 -d "$W/q.txt" -N 10 >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] || fail "'$bad' should be a usage error, exit $rc"
done
echo "ok: usage errors of --agent / --agents"

grep -qE "AddressSanitizer|runtime error:" "$W"/agent*.log "$W"/r*.err 2>/dev/null && fail "sanitizer report"
[ "$FAILED" -eq 0 ] || { echo "FAIL: dnsqps agent test"; exit 1; }
echo "PASS: dnsqps agent test"
exit 0

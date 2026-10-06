#!/bin/sh
# ==============================================================================
# run_forward_failover_test.sh
#
# Phase 13 (D-20): forward zones share forward-timeout between the forwarders.
#  1. The first forwarder never answers: the remaining time is split, so the
#     second forwarder still answers within forward-timeout (it used to get
#     nothing: the first poll() used the whole budget -> SERVFAIL).
#  2. A forwarder first sends a datagram with the wrong ID, then the real
#     answer: the wrong datagram is discarded and the wait goes on (it used to
#     end the wait for that forwarder -> SERVFAIL with a single forwarder).
# Mock forwarders: one Perl process with three UDP sockets (silent / wrong ID
# first / normal).
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag
KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

PORT=$((26000 + $$ % 4000))
SILENT=$((PORT + 1))
WRONG=$((PORT + 2))
GOOD=$((PORT + 3))
TMP_DIR="/tmp/forward_failover_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
MOCK_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

cat > "$TMP_DIR/mockfwd.pl" <<'EOF'
use strict; use warnings;
use IO::Socket::INET; use IO::Select; use Time::HiRes qw(sleep);
my ($silent, $wrong, $good) = @ARGV;
my %s = map { $_ => IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $_, Proto => 'udp') || die "bind $_: $!" }
        ($silent, $wrong, $good);
sub answer { my ($q, $ip) = @_;
    my ($id) = unpack('n', $q); my $qd = substr($q, 12);
    my $end = 0; $end += 1 + ord(substr($qd, $end, 1)) while ord(substr($qd, $end, 1)); $qd = substr($qd, 0, $end + 5);
    return pack('nnnnnn', $id, 0x8180, 1, 1, 0, 0) . $qd . pack('nnnNn', 0xC00C, 1, 1, 60, 4) . pack('C4', split(/\./, $ip)); }
my $sel = IO::Select->new(values %s);
$| = 1; print "ready\n";
while (1) {
    for my $sock ($sel->can_read(1)) {
        my $peer = $sock->recv(my $q, 512) or next;
        my $port = $sock->sockport;
        next if $port == $silent;                       # never answers
        if ($port == $wrong) {                          # wrong ID first, the real answer 300 ms later
            my $bad = answer($q, '192.0.2.99'); substr($bad, 0, 2) = pack('n', (unpack('n', $q) ^ 0x5555));
            $sock->send($bad, 0, $peer); sleep 0.3;
            $sock->send(answer($q, '192.0.2.54'), 0, $peer);
        } else {
            $sock->send(answer($q, '192.0.2.53'), 0, $peer);
        }
    }
}
EOF
perl "$TMP_DIR/mockfwd.pl" "$SILENT" "$WRONG" "$GOOD" > "$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!

cat > "$TMP_DIR/karidns.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "f1.test" { type forward; forwarders { 127.0.0.1 port $SILENT; 127.0.0.1 port $GOOD; }; forward-timeout 2000; };
zone "f2.test" { type forward; forwarders { 127.0.0.1 port $WRONG; }; forward-timeout 2000; };
EOF
chmod 644 "$TMP_DIR"/*

echo "=== forward failover (D-20) ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" x.f1.test A +time=1 +tries=1 +nohexdump > /dev/null 2>&1 && break
    sleep 0.1; i=$((i + 1))
done

# 1. silent first forwarder
start=$(perl -MTime::HiRes=time -e 'printf "%d", time * 1000')
out=$("$DAG" @127.0.0.1 -p "$PORT" a.f1.test A +time=5 +tries=1 +nohexdump 2>&1)
end=$(perl -MTime::HiRes=time -e 'printf "%d", time * 1000')
if echo "$out" | grep -q "status: NOERROR" && echo "$out" | grep -q "192\.0\.2\.53"; then
    pass "second forwarder answered after the first stayed silent ($((end - start)) ms, forward-timeout 2000)"
else
    fail "silent first forwarder: expected the second forwarder's answer, got: $(echo "$out" | grep -E 'status:|192\.0\.2' | tr '\n' ' ')"
fi
[ $((end - start)) -lt 2500 ] && pass "answer within the forward-timeout budget" \
                              || fail "answer took $((end - start)) ms"

# 2. a datagram with the wrong ID does not end the wait
out=$("$DAG" @127.0.0.1 -p "$PORT" b.f2.test A +time=5 +tries=1 +nohexdump 2>&1)
if echo "$out" | grep -q "status: NOERROR" && echo "$out" | grep -q "192\.0\.2\.54" && ! echo "$out" | grep -q "192\.0\.2\.99"; then
    pass "mismatched datagram discarded, the real answer accepted"
else
    fail "mismatched datagram: got $(echo "$out" | grep -E 'status:|192\.0\.2' | tr '\n' ' ')"
fi

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: forwarders share forward-timeout and mismatched datagrams do not end the wait"
exit 0

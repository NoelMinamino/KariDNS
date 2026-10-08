#!/bin/sh
# ==============================================================================
# run_tcp_timeouts_test.sh
#
# Phase 13 (D-06, R-24 / RFC 7766 §6.2.3): TCP connection timeouts.
#  1. A connection that sends nothing is closed after tcp-initial-timeout
#     (it used to be a fixed 10 s).
#  2. With tcp-connection-reuse, the deadline for the next message is
#     tcp-idle-timeout after the last complete message; trickling single bytes
#     of a new message does not extend it (it used to re-arm 3 s on every
#     segment, up to the 60 s cap).
#  3. Pipelined queries on one connection are all answered in order.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] || make -C "$ROOT_DIR" karidns
KARIDNS="$ROOT_DIR/karidns"

PORT=$((26000 + $$ % 4000))
TMP_DIR="/tmp/tcp_timeouts_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

cat > "$TMP_DIR/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
EOF
cat > "$TMP_DIR/karidns.conf" <<EOF
options {
    port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
    tcp-connection-reuse yes;
    tcp-initial-timeout 1500;
    tcp-idle-timeout 1200;
};
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
chmod 644 "$TMP_DIR"/*

echo "=== TCP timeouts (D-06, R-24) ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!

# Measures with Perl: prints the elapsed time in ms until the server closes the
# connection (or "timeout" after the given limit).
cat > "$TMP_DIR/tcpclient.pl" <<'EOF'
use strict; use warnings;
use IO::Socket::INET; use Time::HiRes qw(time sleep);
my ($port, $mode, $limit) = @ARGV;
sub query { my ($id) = @_;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0) . "\x03www\x07example\x04test\x00" . pack('nn', 1, 1);
    return pack('n', length $q) . $q; }
sub read_msg { my ($s) = @_; my $l = ''; while (length $l < 2) { my $n = sysread($s, $l, 2 - length $l, length $l); return undef unless $n; }
    my $len = unpack('n', $l); my $m = ''; while (length $m < $len) { my $n = sysread($s, $m, $len - length $m, length $m); return undef unless $n; } return $m; }
sub wait_eof { my ($s, $t0, $limit, $trickle) = @_;
    $s->blocking(0); my @bytes = $trickle ? split(//, query(9)) : ();
    my $next = time + 0.3;
    while (time - $t0 < $limit) {
        my $buf; my $n = sysread($s, $buf, 1);
        return sprintf("%d", (time - $t0) * 1000) if defined $n && $n == 0;
        if (@bytes && time >= $next) { syswrite($s, shift @bytes); $next = time + 0.3; }
        sleep 0.02;
    }
    return "timeout"; }
my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp') or die "connect: $!";
if ($mode eq 'silent') {
    print wait_eof($s, time, $limit, 0), "\n";
} elsif ($mode eq 'trickle') {
    syswrite($s, query(1)); my $r = read_msg($s) or die "no answer";
    print wait_eof($s, time, $limit, 1), "\n";
} elsif ($mode eq 'pipeline') {
    syswrite($s, query(11) . query(12) . query(13));
    my @ids; for (1 .. 3) { my $m = read_msg($s) or last; push @ids, unpack('n', $m); }
    print join(',', @ids), "\n";
}
EOF

ok=0
for i in $(seq 1 50); do
    if perl "$TMP_DIR/tcpclient.pl" "$PORT" pipeline 3 > "$TMP_DIR/p.out" 2>/dev/null && grep -q '^11,12,13$' "$TMP_DIR/p.out"; then
        ok=1; break
    fi
    sleep 0.1
done
[ "$ok" = 1 ] && pass "three pipelined queries answered in order on one connection" \
               || fail "pipelined queries: $(cat "$TMP_DIR/p.out" 2>/dev/null)"

# 1. nothing sent: closed after tcp-initial-timeout (1500 ms), not after 10 s
t=$(perl "$TMP_DIR/tcpclient.pl" "$PORT" silent 6)
if [ "$t" != "timeout" ] && [ "$t" -ge 1200 ] && [ "$t" -le 3500 ]; then
    pass "idle new connection closed after ${t} ms (tcp-initial-timeout 1500)"
else
    fail "idle new connection: closed after '$t' ms, expected about 1500"
fi

# 2. after one answered query, single bytes every 300 ms do not extend the deadline
t=$(perl "$TMP_DIR/tcpclient.pl" "$PORT" trickle 6)
if [ "$t" != "timeout" ] && [ "$t" -ge 900 ] && [ "$t" -le 3000 ]; then
    pass "trickled partial message: closed ${t} ms after the last complete message (tcp-idle-timeout 1200)"
else
    fail "trickled partial message: closed after '$t' ms, expected about 1200 (a partial message must not extend it)"
fi

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: TCP timeouts follow tcp-initial-timeout / tcp-idle-timeout"
exit 0

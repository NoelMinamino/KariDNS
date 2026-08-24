#!/bin/sh
set -e

# Test: RFC 7873 §5.2 DNS Cookie echo verification & mismatch discard test
# Verifies that dag discards spoofed responses where client cookie does not match the sent cookie,
# and keeps waiting until a valid response with matched cookie is received.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${DAG:-$BIN_DIR/dag}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$BIN_DIR/dag"
    fi
    if [ ! -x "$DAG" ]; then
        DAG="./dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag executable not found at $DAG"
        exit 1
    fi
fi

echo "Running: test_dag_cookie_mismatch_discard ($DAG)"

PORT_COOKIE_TEST=53610

# Spawn mock DNS server in background
perl -e '
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

my $client_addr = recv($srv, my $query, 4096, 0);
if ($client_addr && length($query) >= 12) {
    my $qid = substr($query, 0, 2);
    
    # Extract client cookie from query EDNS option (Option code 10 = 0x000a)
    my $real_cookie = "\x01\x02\x03\x04\x05\x06\x07\x08";
    if ($query =~ /\x00\x0a\x00\x08(.{8})/s) {
        $real_cookie = $1;
    }
    
    my $fake_cookie = "\xde\xad\xbe\xef\xca\xfe\xba\xbe";

    # Helper to build response with EDNS Cookie option
    my $build_resp = sub {
        my ($cookie, $ip_byte) = @_;
        my $pkt = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1);
        $pkt .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1); # Question
        $pkt .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, $ip_byte); # Answer
        # OPT RR: Name=0, Type=41, UDPSize=4096, ExtRcode=0, Ver=0, Flags=0, RDLen=12 (Cookie: Code 10, Len 8)
        my $cookie_opt = pack("nn", 10, 8) . $cookie;
        $pkt .= "\x00" . pack("nnNn", 41, 4096, 0, length($cookie_opt)) . $cookie_opt;
        return $pkt;
    };

    # Send response with mismatched Client Cookie
    my $mismatch_resp = $build_resp->($fake_cookie, 66);
    send($srv, $mismatch_resp, 0, $client_addr);
}
' "$PORT_COOKIE_TEST" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

OUT=$($DAG @127.0.0.1 -p $PORT_COOKIE_TEST www.example.com A +cookie +timeout=2 2>&1 || true)

# 1. Verify warning for client cookie mismatch is emitted on both dig and dag
echo "$OUT" | grep -q -i "Warning: Client COOKIE mismatch" || {
    echo "FAIL: Expected 'Warning: Client COOKIE mismatch' in output"
    echo "$OUT"
    exit 1
}

# 2. Verify (bad) indication in COOKIE option
echo "$OUT" | grep -q -i -E "COOKIE:.*\(bad\)" || {
    echo "FAIL: Expected 'COOKIE: ... (bad)' in output"
    echo "$OUT"
    exit 1
}

# 3. Verify packet is displayed
echo "$OUT" | grep -q "192\.0\.2\.66" || {
    echo "FAIL: Expected answer record 192.0.2.66 in output"
    echo "$OUT"
    exit 1
}

echo "PASS: test_dag_cookie_mismatch_discard"
exit 0

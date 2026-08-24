#!/bin/sh
set -e

# Test: UDP transaction ID mismatch packet discard and retry (RFC 5452)
# When a response with an incorrect QID arrives first, dag MUST discard it,
# log a warning, and keep waiting until the legitimate response with matching QID arrives.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${DAG:-$BIN_DIR/dag}"
if [ ! -x "$DAG" ]; then
    DAG="./dag"
fi

if [ ! -x "$DAG" ]; then
    echo "Error: dag executable not found at $DAG"
    exit 1
fi

PORT_MOCK=53593

perl -e '
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];

socket(my $s, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
bind($s, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

my $rin = "";
vec($rin, fileno($s), 1) = 1;
if (select(my $rout = $rin, undef, undef, 5.0) > 0) {
    my $buf;
    my $client_addr = recv($s, $buf, 4096, 0);
    if (defined $client_addr && length($buf) >= 2) {
        my $sent_id = (ord(substr($buf, 0, 1)) << 8) | ord(substr($buf, 1, 1));
        my $bad_id = ($sent_id + 1) & 0xFFFF;

        # 1. Send MISMATCHED ID response first
        my $buf_bad = $buf;
        substr($buf_bad, 0, 1) = chr(($bad_id >> 8) & 0xFF);
        substr($buf_bad, 1, 1) = chr($bad_id & 0xFF);
        vec($buf_bad, 2, 8) = 0x81;
        vec($buf_bad, 3, 8) = 0x80;
        send($s, $buf_bad, 0, $client_addr);

        # 2. Wait a short interval, then send CORRECT ID response
        select(undef, undef, undef, 0.2);
        my $buf_good = $buf;
        vec($buf_good, 2, 8) = 0x81;
        vec($buf_good, 3, 8) = 0x80;
        send($s, $buf_good, 0, $client_addr);
    }
}
' "$PORT_MOCK" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

echo "Running: test_udp_id_mismatch_discard"
OUT=$($DAG @127.0.0.1 -p $PORT_MOCK idtest.example.com A +timeout=2 2>&1 || true)

# Verify that a warning was emitted for the discarded ID mismatch
echo "$OUT" | grep -q "Warning: ID mismatch: expected" || {
    echo "FAIL: Expected ID mismatch warning"
    echo "$OUT"
    exit 1
}

# Verify that the legitimate response was ultimately received and parsed
echo "$OUT" | grep -q -E "(idtest\.example\.com|NOERROR|opcode: QUERY)" || {
    echo "FAIL: Expected query to succeed after discarding bad ID packet"
    echo "$OUT"
    exit 1
}

echo "PASS: test_udp_id_mismatch_discard"
exit 0

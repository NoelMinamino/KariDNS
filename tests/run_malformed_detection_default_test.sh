#!/bin/sh
set -e

# Test: Structural malformation detection in default mode (RFC / dig diagnostic quality)
# Verifies that dag detects malformed packets (trailing garbage bytes, RR count mismatch)
# and emits warning even without explicit +besteffort.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${1:-${DAG:-$BIN_DIR/dag}}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
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

echo "Running: test_malformed_detection_default ($DAG)"

PORT_MALFORMED_TEST=53616

# Spawn mock DNS server in background
perl -e '
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

while (1) {
    my $client_addr = recv($srv, my $query, 4096, 0);
    last unless $client_addr && length($query) >= 12;
    my $qid = substr($query, 0, 2);

    if ($query =~ /trailing/i) {
        # Normal response + 16 trailing garbage bytes
        my $pkt = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $pkt .= "\x08trailing\x07example\x03com\x00" . pack("nn", 1, 1); # Question
        $pkt .= "\x08trailing\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 1); # Answer
        $pkt .= "1234567890ABCDEF"; # 16 extra bytes at end
        send($srv, $pkt, 0, $client_addr);
    } elsif ($query =~ /mismatch/i) {
        # Header says ANCOUNT=5, but only 1 Answer RR is provided
        my $pkt = $qid . pack("nnnnn", 0x8180, 1, 5, 0, 0);
        $pkt .= "\x08mismatch\x07example\x03com\x00" . pack("nn", 1, 1); # Question
        $pkt .= "\x08mismatch\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 2); # Answer (only 1)
        send($srv, $pkt, 0, $client_addr);
    } else {
        # Normal
        my $pkt = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $pkt .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1);
        $pkt .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 3);
        send($srv, $pkt, 0, $client_addr);
    }
}
' "$PORT_MALFORMED_TEST" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

# Test 1: Trailing garbage bytes detection without +besteffort (default settings)
echo -n "Testing trailing garbage bytes in default mode ... "
OUT1=$($DAG @127.0.0.1 -p $PORT_MALFORMED_TEST trailing.example.com A +timeout=2 2>&1 || true)
echo "$OUT1" | grep -q -i -E "(Warning: Message parser reports malformed|Message has 16 extra bytes)" || {
    echo "FAILED"
    echo "$OUT1"
    exit 1
}
echo "OK"

# Test 2: Header count mismatch detection in default mode
echo -n "Testing header RR count mismatch in default mode ... "
OUT2=$($DAG @127.0.0.1 -p $PORT_MALFORMED_TEST mismatch.example.com A +timeout=2 2>&1 || true)
echo "$OUT2" | grep -q -i -E "(Warning: Message parser reports malformed|Got bad packet|unexpected end of input)" || {
    echo "FAILED"
    echo "$OUT2"
    exit 1
}
echo "OK"

# Test 3: +besteffort continues to parse and display available records
echo -n "Testing +besteffort on mismatched packet displays available record ... "
OUT3=$($DAG @127.0.0.1 -p $PORT_MALFORMED_TEST mismatch.example.com A +besteffort +timeout=2 2>&1 || true)
echo "$OUT3" | grep -q "192\.0\.2\.2" || {
    echo "FAILED"
    echo "$OUT3"
    exit 1
}
echo "OK"

echo "PASS: test_malformed_detection_default"
exit 0

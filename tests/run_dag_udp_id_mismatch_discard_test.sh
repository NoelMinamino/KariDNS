#!/bin/sh
set -e

# Test: UDP transaction ID mismatch packet discard and retry per RFC 5452 §9.2
# Verifies that responses with mismatched QIDs are discarded while the valid response is accepted.
# Compatible with both dag and dig.

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

PORT_ID_TEST=53591

echo "Running: test_dag_udp_id_mismatch_discard ($DAG)"

perl -e '
use strict;
use warnings;
use Socket;

my ($port) = @ARGV;

socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

my $rin = "";
vec($rin, fileno($srv), 1) = 1;
if (select(my $rout = $rin, undef, undef, 5.0) > 0) {
    my $client_addr = recv($srv, my $query, 512, 0);
    my $real_qid = substr($query, 0, 2);
    my $fake_qid = pack("n", (unpack("n", $real_qid) ^ 0x1234));

    # 1. First packet: Wrong QID
    my $fake_resp = $fake_qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $fake_resp .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1);
    $fake_resp .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 77);
    send($srv, $fake_resp, 0, $client_addr);

    # Brief delay before sending valid response
    select(undef, undef, undef, 0.05);

    # 2. Second packet: Correct QID
    my $valid_resp = $real_qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $valid_resp .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1);
    $valid_resp .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 88);
    send($srv, $valid_resp, 0, $client_addr);
}
' "$PORT_ID_TEST" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

OUT=$($DAG @127.0.0.1 -p $PORT_ID_TEST www.example.com A +timeout=2 2>&1 || true)

# Verify that the valid response was accepted
echo "$OUT" | grep -q "192\.0\.2\.88" || {
    echo "FAIL: Valid response with matched QID was not accepted!"
    echo "$OUT"
    exit 1
}

# Verify that the spoofed record was NOT accepted
if echo "$OUT" | grep -q "192\.0\.2\.77"; then
    echo "FAIL: Mismatched ID packet was erroneously accepted!"
    echo "$OUT"
    exit 1
fi

echo "PASS: test_dag_udp_id_mismatch_discard"
exit 0

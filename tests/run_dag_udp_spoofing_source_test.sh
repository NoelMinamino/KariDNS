#!/bin/sh
set -e

# Test: UDP spoofing source rejection per RFC 5452 §9.1
# Verifies that responses originating from an unexpected source port are discarded.
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

PORT_QUERY=53592
PORT_SPOOF=53593

echo "Running: test_dag_udp_spoofing_source ($DAG)"

perl -e '
use strict;
use warnings;
use Socket;

my ($qport, $sport) = @ARGV;

socket(my $qsrv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($qsrv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($qsrv, sockaddr_in($qport, INADDR_ANY)) or die "bind: $!";

socket(my $ssrv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($ssrv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($ssrv, sockaddr_in($sport, INADDR_ANY)) or die "bind: $!";

my $rin = "";
vec($rin, fileno($qsrv), 1) = 1;
if (select(my $rout = $rin, undef, undef, 5.0) > 0) {
    my $client_addr = recv($qsrv, my $query, 512, 0);
    my ($client_port, $client_ip) = sockaddr_in($client_addr);
    my $qid = substr($query, 0, 2);

    # Forge response packet from spoofing port ($sport)
    # Header: ID=$qid, Flags=0x8180 (Response, RA), QD=1, AN=1, NS=0, AR=0
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $resp .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1);
    # Answer: www.example.com 300 IN A 192.0.2.99
    $resp .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 99);

    # Send spoofed packet from $ssrv
    send($ssrv, $resp, 0, $client_addr);
}
' "$PORT_QUERY" "$PORT_SPOOF" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

OUT=$($DAG @127.0.0.1 -p $PORT_QUERY www.example.com A +timeout=1 2>&1 || true)

# The client connected to $PORT_QUERY MUST reject the spoofed packet from $PORT_SPOOF.
if echo "$OUT" | grep -q "192\.0\.2\.99"; then
    echo "FAIL: Spoofed response from unauthorized port was accepted!"
    echo "$OUT"
    exit 1
fi

echo "PASS: test_dag_udp_spoofing_source"
exit 0

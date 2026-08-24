#!/bin/sh
set -e

# Test: RFC 7050 DNS64 prefix discovery (+dns64prefix) validation
# Verifies that dag +dns64prefix queries ipv4only.arpa for AAAA and correctly calculates Pref64::/n.

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

echo "Running: test_dag_dns64prefix ($DAG)"

PORT_DNS64_TEST=53612

# Spawn mock DNS server in background
perl -e '
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

for (1..2) {
    my $client_addr = recv($srv, my $query, 4096, 0);
    next unless $client_addr && length($query) >= 12;
    my $qid = substr($query, 0, 2);

    # Check if querying ipv4only.arpa AAAA (Type 28)
    if ($query =~ /ipv4only/i) {
        # Return both RFC 7050 Well-Known IPv4-embedded AAAA records:
        # 1) 64:ff9b::192.0.0.170
        # 2) 64:ff9b::192.0.0.171
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 2, 0, 0);
        $resp .= "\x08ipv4only\x04arpa\x00" . pack("nn", 28, 1); # Question AAAA
        # Answer 1: ipv4only.arpa 300 IN AAAA 64:ff9b::c000:aa
        $resp .= "\x08ipv4only\x04arpa\x00" . pack("nnNn", 28, 1, 300, 16) .
                 pack("nnnnnnnn", 0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x00aa);
        # Answer 2: ipv4only.arpa 300 IN AAAA 64:ff9b::c000:ab
        $resp .= "\x08ipv4only\x04arpa\x00" . pack("nnNn", 28, 1, 300, 16) .
                 pack("nnnnnnnn", 0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x00ab);
        send($srv, $resp, 0, $client_addr);
    } else {
        # Normal query answer
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1); # Question A
        $resp .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 10);
        send($srv, $resp, 0, $client_addr);
    }
}
' "$PORT_DNS64_TEST" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

OUT=$($DAG @127.0.0.1 -p $PORT_DNS64_TEST ipv4only.arpa AAAA +dns64prefix +timeout=2 2>&1 || true)

# 1. Verify that DNS64 prefix 64:ff9b::/96 was discovered and printed identically on both dig and dag
echo "$OUT" | grep -q -E "^64:ff9b::/96" || echo "$OUT" | grep -q "64:ff9b::/96" || {
    echo "FAIL: Expected '64:ff9b::/96' in output"
    echo "$OUT"
    exit 1
}

# 2. Verify that ipv4only.arpa AAAA response records were also printed
echo "$OUT" | grep -q -i -E "64:ff9b::(c000:aa|192\.0\.0\.170)" || {
    echo "FAIL: Expected AAAA record in response output"
    echo "$OUT"
    exit 1
}

echo "PASS: test_dag_dns64prefix"
exit 0

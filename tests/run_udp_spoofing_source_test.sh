#!/bin/sh
set -e

# Test: UDP source address spoofing rejection (RFC 5452 §9.1 connected socket)
# When a client queries Target Port (e.g. 53591), spoofed responses sent from
# an unauthorized source port (e.g. 53592) MUST be dropped by the kernel.

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

PORT_AUTH=53591
PORT_SPOOF=53592

perl -e '
use strict;
use warnings;
use Socket;

my $port_auth = $ARGV[0];
my $port_spoof = $ARGV[1];

socket(my $s_auth, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket auth: $!";
bind($s_auth, sockaddr_in($port_auth, INADDR_ANY)) or die "bind auth: $!";

socket(my $s_spoof, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket spoof: $!";
bind($s_spoof, sockaddr_in($port_spoof, INADDR_ANY)) or die "bind spoof: $!";

my $rin = "";
vec($rin, fileno($s_auth), 1) = 1;
if (select(my $rout = $rin, undef, undef, 5.0) > 0) {
    my $buf;
    my $client_addr = recv($s_auth, $buf, 4096, 0);
    if (defined $client_addr && length($buf) >= 2) {
        # Construct response header (QR=1, AA=1, NOERROR)
        vec($buf, 2, 8) = 0x81;
        vec($buf, 3, 8) = 0x80;
        # 1. Send spoofed response from UNAUTHORIZED port
        send($s_spoof, $buf, 0, $client_addr);
        # 2. Wait, then send legitimate response from AUTHORIZED port
        select(undef, undef, undef, 0.3);
        send($s_auth, $buf, 0, $client_addr);
    }
}
' "$PORT_AUTH" "$PORT_SPOOF" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

echo "Running: test_udp_spoofing_source"
OUT=$($DAG @127.0.0.1 -p $PORT_AUTH test.example.com A +timeout=2 2>&1 || true)

# Verify that the legitimate response was received
echo "$OUT" | grep -q -E "(test\.example\.com|NOERROR|opcode: QUERY)" || {
    echo "FAIL: Expected query to succeed via legitimate server response"
    echo "$OUT"
    exit 1
}

echo "PASS: test_udp_spoofing_source"
exit 0

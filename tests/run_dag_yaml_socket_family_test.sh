#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML socket_family Accuracy Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag with make ==="
make -C "$ROOT_DIR" dag

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$ROOT_DIR/dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag binary not found at $DAG"
        exit 1
    fi
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT4=$((20000 + $$ % 5000))
PORT6=$((25000 + $$ % 5000))
TMP_DIR="/tmp/karidns_yaml_sockfam_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV4_PID" ] && kill -9 "$SRV4_PID" 2>/dev/null || true
    [ -n "$SRV6_PID" ] && kill -9 "$SRV6_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server on IPv4 127.0.0.1
cat <<'PL_EOF' > "$TMP_DIR/mock_udp4.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

while (1) {
    my $client_addr = recv($srv, my $query, 4096, 0);
    next unless $client_addr && length($query) >= 12;
    my $qid = substr($query, 0, 2);
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 0, 0, 0);
    $resp .= "\x07example\x03com\x00" . pack("nn", 1, 1);
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_udp4.pl" "$PORT4" &
SRV4_PID=$!
sleep 0.3

echo "=== 1. Testing IPv4 Socket Family Output (INET) ==="
echo -n "Test: IPv4 server produces socket_family: INET ... "
OUT_V4=$($DAG @127.0.0.1 -p $PORT4 example.com A +yaml 2>&1 || true)
if echo "$OUT_V4" | grep -q "socket_family: INET"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT_V4"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing IPv6 Socket Family Output (INET6) ==="
# Attempt to bind and query on IPv6 loopback ::1
cat <<'PL_EOF' > "$TMP_DIR/mock_udp6.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
eval {
    socket(my $srv, PF_INET6, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
    setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
    bind($srv, sockaddr_in6($port, Socket::IN6ADDR_LOOPBACK)) or die "bind: $!";
    while (1) {
        my $client_addr = recv($srv, my $query, 4096, 0);
        next unless $client_addr && length($query) >= 12;
        my $qid = substr($query, 0, 2);
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 0, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 1, 1);
        send($srv, $resp, 0, $client_addr);
    }
};
exit 0;
PL_EOF

if perl "$TMP_DIR/mock_udp6.pl" "$PORT6" 2>/dev/null & SRV6_PID=$!; then
    sleep 0.3
    echo -n "Test: IPv6 server ::1 produces socket_family: INET6 ... "
    OUT_V6=$($DAG @::1 -p $PORT6 example.com A +yaml 2>&1 || true)
    if echo "$OUT_V6" | grep -q "socket_family: INET6"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output:"
        echo "$OUT_V6"
        FAILED=$((FAILED + 1))
    fi
else
    echo "Test: IPv6 Loopback ::1 ... SKIP (IPv6 loopback not supported on environment)"
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML SOCKET_FAMILY TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML SOCKET_FAMILY TESTS FAILED!"
    exit 1
fi

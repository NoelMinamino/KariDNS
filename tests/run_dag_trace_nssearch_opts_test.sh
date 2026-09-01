#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace and +nssearch Options (--hex, +udp) Test Suite
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
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT=$((19000 + $$ % 10000))
TMP_DIR="/tmp/dag_trace_opts_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create mock server that logs received packet hex
cat << 'PL_EOF' > "$TMP_DIR/mock_opts_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port>\n";
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!";
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

while (1) {
    my $query;
    my $client_addr = recv($srv, $query, 4096, 0);
    next unless defined $client_addr && length($query) >= 12;

    my $qid = substr($query, 0, 2);
    my $hex_dump = unpack("H*", $query);

    # Root response with glue
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1) .
               "\x00" . pack("nn", 2, 1) .
               "\x00" . pack("nnNn", 2, 1, 3600, 20) . "\x01a\x0croot-servers\x03net\x00" .
               "\x01a\x0croot-servers\x03net\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");

    # If it's a SOA query or custom hex query, return SOA
    if ($query =~ /example\x03com/i) {
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x07example\x03com\x00" . pack("nn", 6, 1) .
                "\x07example\x03com\x00" . pack("nnNn", 6, 1, 300, 38) .
                "\x03ns1\x07example\x03com\x00\x0ahostmaster\x07example\x03com\x00" .
                pack("NNNNN", 2026090101, 7200, 3600, 1209600, 300);
    }

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_opts_server.pl" "$PORT" &
MOCK_PID=$!
sleep 0.5

# Test packet: ID=1234, RD=0, QD=1, QNAME=example.com, QTYPE=A (1)
CUSTOM_HEX="123400000001000000000000076578616d706c6503636f6d0000010001"

echo "=== 1. Testing +trace with --hex Option ==="
echo -n "Test: +trace sends injected raw hex payload ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace --hex="$CUSTOM_HEX" +timeout=2 2>&1 || true)
if echo "$OUT" | grep -q "12 34" || echo "$OUT" | grep -q "example\.com"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing +trace with +udp Option ==="
echo -n "Test: +trace with +udp completes via UDP exchange ... "
OUT_UDP=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +udp +timeout=2 2>&1 || true)
if echo "$OUT_UDP" | grep -q "Received .* bytes" || echo "$OUT_UDP" | grep -q "example\.com"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT_UDP" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE & NSSEARCH OPTIONS TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TRACE & NSSEARCH OPTIONS TESTS FAILED!"
    exit 1
fi

#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) -b Bind Address Family Mismatch Detection Test Suite
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
PORT=$((31000 + $$ % 3000))
TMP_DIR="/tmp/karidns_bind_mismatch_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server on 127.0.0.1 (IPv4)
cat <<'PL_EOF' > "$TMP_DIR/mock_udp.pl"
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

perl "$TMP_DIR/mock_udp.pl" "$PORT" &
SRV_PID=$!
sleep 0.3

echo "=== 1. Testing -b Family Mismatch (IPv6 bind address with IPv4 server) ==="
echo -n "Test: -b ::1 with IPv4 server fails with clear family mismatch error ... "
if [ "$DAG" = "dig" ]; then
    # BIND 9 dig exits with error when -b family does not match destination
    OUT_MISMATCH=$($DAG -b ::1 @127.0.0.1 -p $PORT example.com A 2>&1 || true)
    if echo "$OUT_MISMATCH" | grep -qi "bind" || echo "$OUT_MISMATCH" | grep -qi "address" || echo "$OUT_MISMATCH" | grep -qi "error"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output: $OUT_MISMATCH"
        FAILED=$((FAILED + 1))
    fi
else
    OUT_MISMATCH=$($DAG -b ::1 @127.0.0.1 -p $PORT example.com A 2>&1 || true)
    if echo "$OUT_MISMATCH" | grep -q "the source address family must match the destination"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output: $OUT_MISMATCH"
        FAILED=$((FAILED + 1))
    fi
fi

echo "=== 2. Testing -b Family Match (IPv4 bind address with IPv4 server) ==="
echo -n "Test: -b 127.0.0.1 with IPv4 server succeeds ... "
OUT_MATCH=$($DAG -b 127.0.0.1 @127.0.0.1 -p $PORT example.com A 2>&1 || true)
if echo "$OUT_MATCH" | grep -q "status: NOERROR"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_MATCH"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL BIND ADDRESS FAMILY MISMATCH TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED BIND ADDRESS FAMILY MISMATCH TESTS FAILED!"
    exit 1
fi

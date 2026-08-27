#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Long Label (63-byte) Domain Name Expansion Test Suite
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
PORT=$((35000 + $$ % 3000))
TMP_DIR="/tmp/karidns_long_label_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server returning packet with 63-byte labels and compression pointers
cat <<'PL_EOF' > "$TMP_DIR/mock_long_label.pl"
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

    # Construct the exact response with 63-byte label and compression pointers
    my $resp = $qid . pack("H*",
        "81000001000000050006036d73670473697a65097463707265706c6179036e65740000010001" .
        "c00c000200010000012c005d046e7330333f" .
        ("78" x 63) .
        "036d73670473697a65097463707265706c6179036e657400" .
        "c00c000200010000012c0007046e733034c039" .
        "c00c000200010000012c0007046e733032c039" .
        "c00c000200010000012c0007046e733031c039" .
        "c00c000200010000012c0007046e733035c039" .
        "c0d6000100010000012c0004364d80fe" .
        "c09d000100010000012c0004364d80fe" .
        "c034000100010000012c0004364d80fe" .
        "c0b0000100010000012c0004364d80fe" .
        "c0c3000100010000012c0004364d80fe" .
        "00002904d0000000000000"
    );
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_long_label.pl" "$PORT" &
SRV_PID=$!
sleep 0.3

echo "=== 1. Testing 63-byte Long Label Name Expansion ==="
echo -n "Test: Name with 63-byte label is parsed without (unparsable name) ... "
OUT=$($DAG @127.0.0.1 -p $PORT msg.size.tcpreplay.net A 2>&1 || true)
if echo "$OUT" | grep -q "unparsable" || echo "$OUT" | grep -q "unexpected end of input"; then
    echo "FAILED"
    echo "  Output: $OUT"
    FAILED=$((FAILED + 1))
else
    if echo "$OUT" | grep -q "ns03\.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\.msg\.size\.tcpreplay\.net\." && \
       echo "$OUT" | grep -q "54\.77\.128\.254"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output: $OUT"
        FAILED=$((FAILED + 1))
    fi
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL LONG LABEL EXPANSION TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED LONG LABEL EXPANSION TESTS FAILED!"
    exit 1
fi

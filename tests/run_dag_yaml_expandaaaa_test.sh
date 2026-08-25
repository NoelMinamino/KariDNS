#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML AAAA Standard Notation Compatibility Test Suite
# (dig compatibility: in YAML mode, AAAA always outputs standard compressed form)
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
PORT=$((33000 + $$ % 3000))
TMP_DIR="/tmp/karidns_yaml_expandaaaa_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server returning AAAA 2001:db8::10
cat <<'PL_EOF' > "$TMP_DIR/mock_aaaa.pl"
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

    my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $resp .= "\x07example\x03com\x00" . pack("nn", 28, 1);
    my $aaaa_raw = pack("nnnnnnnn", 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);
    $resp .= "\x07example\x03com\x00" . pack("nnNn", 28, 1, 3600, 16) . $aaaa_raw;
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_aaaa.pl" "$PORT" &
SRV_PID=$!
sleep 0.3

echo "=== 1. Testing AAAA Output under +yaml +expandaaaa ==="
echo -n "Test: AAAA output formatted in standard compressed notation in YAML ... "
OUT_EXP=$($DAG @127.0.0.1 -p $PORT example.com AAAA +yaml +expandaaaa 2>&1 || true)
if echo "$OUT_EXP" | grep -q "2001:db8::10"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_EXP"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing AAAA Output under +yaml +noexpandaaaa ==="
echo -n "Test: AAAA output formatted in standard compressed notation in YAML ... "
OUT_NOEXP=$($DAG @127.0.0.1 -p $PORT example.com AAAA +yaml +noexpandaaaa 2>&1 || true)
if echo "$OUT_NOEXP" | grep -q "2001:db8::10"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_NOEXP"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML EXPANDAAAA TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML EXPANDAAAA TESTS FAILED!"
    exit 1
fi

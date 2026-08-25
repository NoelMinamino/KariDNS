#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML RRSIG Structured Decoding Test Suite
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
PORT=$((34000 + $$ % 3000))
TMP_DIR="/tmp/karidns_yaml_rrsig_decode_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server returning RRSIG
cat <<'PL_EOF' > "$TMP_DIR/mock_rrsig.pl"
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
    $resp .= "\x07example\x03com\x00" . pack("nn", 46, 1);
    # Covered=A(1), Alg=8, Labels=2, OrigTTL=86400, Exp=1700000000, Inc=1690000000, Keytag=12345, Signer=example.com, Sig
    my $rrsig_rdata = pack("nCCNNNn", 1, 8, 2, 86400, 1700000000, 1690000000, 12345) . "\x07example\x03com\x00" . ("\x55\xaa" x 16);
    $resp .= "\x07example\x03com\x00" . pack("nnNn", 46, 1, 86400, length($rrsig_rdata)) . $rrsig_rdata;
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_rrsig.pl" "$PORT" &
SRV_PID=$!
sleep 0.3

echo "=== 1. Testing RRSIG Structured Output under +yaml ==="
echo -n "Test: RRSIG decoded to structured format (not \\# generic hex) in YAML ... "
OUT_RRSIG=$($DAG @127.0.0.1 -p $PORT example.com RRSIG +yaml 2>&1 || true)
if echo "$OUT_RRSIG" | grep -q "RRSIG A 8 2 86400" && ! echo "$OUT_RRSIG" | grep -q "RRSIG \\\\#"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_RRSIG"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML RRSIG DECODE TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML RRSIG DECODE TESTS FAILED!"
    exit 1
fi

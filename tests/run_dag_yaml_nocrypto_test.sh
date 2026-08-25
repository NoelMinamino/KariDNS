#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML +nocrypto Compatibility Test Suite
# (dig compatibility: in YAML mode, +nocrypto does not strip RDATA base64/hex)
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
PORT=$((32000 + $$ % 3000))
TMP_DIR="/tmp/karidns_yaml_nocrypto_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server returning DNSKEY, DS, and RRSIG
cat <<'PL_EOF' > "$TMP_DIR/mock_dnssec.pl"
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

    if ($query =~ /\x07example\x03com\x00\x00\x30/s) {
        # DNSKEY (Type 48)
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 48, 1);
        my $key_rdata = pack("nCC", 257, 3, 13) . ("\x01\x02\x03\x04" x 16);
        $resp .= "\x07example\x03com\x00" . pack("nnNn", 48, 1, 3600, length($key_rdata)) . $key_rdata;
        send($srv, $resp, 0, $client_addr);
    } elsif ($query =~ /\x07example\x03com\x00\x00\x2b/s) {
        # DS (Type 43)
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 43, 1);
        my $ds_rdata = pack("nCC", 12345, 8, 2) . ("\xab\xcd\xef\x01" x 8);
        $resp .= "\x07example\x03com\x00" . pack("nnNn", 43, 1, 3600, length($ds_rdata)) . $ds_rdata;
        send($srv, $resp, 0, $client_addr);
    } elsif ($query =~ /\x07example\x03com\x00\x00\x2e/s) {
        # RRSIG (Type 46)
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 46, 1);
        my $rrsig_rdata = pack("nCCNNNn", 1, 8, 2, 3600, 1700000000, 1690000000, 12345) . "\x07example\x03com\x00" . ("\x55\xaa" x 16);
        $resp .= "\x07example\x03com\x00" . pack("nnNn", 46, 1, 3600, length($rrsig_rdata)) . $rrsig_rdata;
        send($srv, $resp, 0, $client_addr);
    }
}
PL_EOF

perl "$TMP_DIR/mock_dnssec.pl" "$PORT" &
SRV_PID=$!
sleep 0.3

echo "=== 1. Testing DNSKEY Output under +yaml +nocrypto ==="
echo -n "Test: DNSKEY output in YAML under +nocrypto ... "
OUT_DNSKEY=$($DAG @127.0.0.1 -p $PORT example.com DNSKEY +yaml +nocrypto 2>&1 || true)
if echo "$OUT_DNSKEY" | grep -q "DNSKEY 257 3 13"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_DNSKEY"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing DS Output under +yaml +nocrypto ==="
echo -n "Test: DS output in YAML under +nocrypto ... "
OUT_DS=$($DAG @127.0.0.1 -p $PORT example.com DS +yaml +nocrypto 2>&1 || true)
if echo "$OUT_DS" | grep -q "DS 12345 8 2"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_DS"
    FAILED=$((FAILED + 1))
fi

echo "=== 3. Testing RRSIG Output under +yaml +nocrypto ==="
echo -n "Test: RRSIG output in YAML under +nocrypto ... "
OUT_RRSIG=$($DAG @127.0.0.1 -p $PORT example.com RRSIG +yaml +nocrypto 2>&1 || true)
if echo "$OUT_RRSIG" | grep -q "RRSIG A 8 2 3600"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output: $OUT_RRSIG"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML NOCRYPTO TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML NOCRYPTO TESTS FAILED!"
    exit 1
fi

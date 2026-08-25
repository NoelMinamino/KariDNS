#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +multiline DS Single-Line Formatting Test Suite
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
PORT=$((28000 + $$ % 3000))
TMP_DIR="/tmp/karidns_multiline_ds_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server returning DS and DNSKEY records
cat <<'PL_EOF' > "$TMP_DIR/mock_dnssec_server.pl"
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

    my $is_dnskey = ($query =~ /\x07example\x03com\x00\x00\x30/s) ? 1 : 0;
    
    if ($is_dnskey) {
        # DNSKEY (Type 48) response
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 48, 1);
        # Flags=257(KSK), Proto=3, Alg=8(RSA/SHA-256), KeyData
        my $key_rdata = pack("nCC", 257, 3, 8) . ("\x01\x02\x03\x04" x 16);
        $resp .= "\x07example\x03com\x00" . pack("nnNn", 48, 1, 3600, length($key_rdata)) . $key_rdata;
        send($srv, $resp, 0, $client_addr);
    } else {
        # DS (Type 43) response
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 43, 1);
        # Keytag=12345, Alg=8, DigestType=2(SHA-256), Digest(32 bytes)
        my $ds_rdata = pack("nCC", 12345, 8, 2) . ("\xab\xcd\xef\x01" x 8);
        $resp .= "\x07example\x03com\x00" . pack("nnNn", 43, 1, 3600, length($ds_rdata)) . $ds_rdata;
        send($srv, $resp, 0, $client_addr);
    }
}
PL_EOF

perl "$TMP_DIR/mock_dnssec_server.pl" "$PORT" &
SRV_PID=$!
sleep 0.3

echo "=== 1. Testing DS Record Output Format under +multiline ==="
echo -n "Test: DS record uses multi-line parentheses format under +multiline ... "
OUT_DS=$($DAG @127.0.0.1 -p $PORT example.com DS +multiline 2>&1 || true)
if echo "$OUT_DS" | grep -q "12345 8 2 (" && echo "$OUT_DS" | grep -q ")"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT_DS"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing DNSKEY Record Output Format under +multiline ==="
echo -n "Test: DNSKEY record maintains multi-line parentheses format under +multiline ... "
OUT_DNSKEY=$($DAG @127.0.0.1 -p $PORT example.com DNSKEY +multiline 2>&1 || true)
if echo "$OUT_DNSKEY" | grep -q "257 3 8 (" && echo "$OUT_DNSKEY" | grep -q ")"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT_DNSKEY"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL MULTILINE DS TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED MULTILINE DS TESTS FAILED!"
    exit 1
fi

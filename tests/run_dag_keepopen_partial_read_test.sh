#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +keepopen Partial Read TCP Cache Invalidation Test Suite
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
    echo "[-] perl is not installed; skipping mock TCP server test."
    exit 0
fi

FAILED=0
PORT=$((17000 + $$ % 10000))
TMP_DIR="/tmp/karidns_keepopen_partial_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock TCP server:
# Connection 1: send 2-byte length (100) + 10 bytes of payload, then stall (trigger client timeout)
# Connection 2: send valid full DNS response
cat <<'PL_EOF' > "$TMP_DIR/mock_tcp_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen($srv, 5) or die "listen: $!";

# Accept first connection (partial read stall)
if (my $paddr = accept(my $client, $srv)) {
    my $len_buf;
    read($client, $len_buf, 2);
    if (length($len_buf) == 2) {
        my $qlen = unpack("n", $len_buf);
        my $qbody;
        read($client, $qbody, $qlen);
        
        # Send 100 bytes length prefix, but only 10 bytes of body
        print $client pack("n", 100);
        print $client "1234567890";
        $client->flush() if $client->can('flush');
        # Wait until client closes connection on timeout (EOF)
        my $dummy;
        read($client, $dummy, 1);
    }
    close($client);
}

# Accept second connection (valid full response)
if (my $paddr = accept(my $client, $srv)) {
    my $len_buf;
    read($client, $len_buf, 2);
    if (length($len_buf) == 2) {
        my $qlen = unpack("n", $len_buf);
        my $qbody;
        read($client, $qbody, $qlen);
        my $qid = substr($qbody, 0, 2);
        
        my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
        $resp .= "\x07example\x03com\x00" . pack("nn", 1, 1);
        $resp .= "\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 93, 184, 216, 34);
        
        print $client pack("n", length($resp)) . $resp;
        $client->flush() if $client->can('flush');
    }
    close($client);
}
close($srv);
PL_EOF

perl "$TMP_DIR/mock_tcp_server.pl" "$PORT" &
SRV_PID=$!
sleep 0.5

echo "=== 1. Testing First Query Timeout on Partial TCP Read ==="
echo -n "Test: Query 1 handles partial receive and times out ... "
OUT1=$($DAG @127.0.0.1 -p $PORT example.com A +tcp +keepopen +timeout=1 +tries=1 2>&1 || true)
if echo "$OUT1" | grep -E -q "(timed out|no usable response|communications error|no servers could be reached)"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output 1: $OUT1"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing Second Query Successfully Reconnects without Stream Desync ==="
echo -n "Test: Query 2 re-establishes clean TCP connection ... "
OUT2=$($DAG @127.0.0.1 -p $PORT example.com A +tcp +keepopen +timeout=2 +tries=1 2>&1 || true)
if echo "$OUT2" | grep -q "93\.184\.216\.34"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output 2: $OUT2"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL KEEPOPEN PARTIAL READ TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED KEEPOPEN PARTIAL READ TESTS FAILED!"
    exit 1
fi

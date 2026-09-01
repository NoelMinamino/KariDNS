#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) DoH Connection Cache Invalidation (D-1) Test Suite
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
TMP_DIR="/tmp/dag_doh_cache_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create a mock plain HTTP DoH server that returns an invalid chunk on first query,
# but stays connected. The second query on a clean connection must succeed.
cat << 'PL_EOF' > "$TMP_DIR/mock_doh_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port>\n";
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";
listen($srv, SOMAXCONN) or die "listen: $!";

while (my $client = accept(my $conn, $srv)) {
    my $req_header = "";
    while (my $line = <$conn>) {
        $req_header .= $line;
        last if $line eq "\r\n";
    }

    my $cl = 0;
    if ($req_header =~ /Content-Length:\s*(\d+)/i) {
        $cl = int($1);
    }
    my $req_body = "";
    if ($cl > 0) {
        read($conn, $req_body, $cl);
    }

    my $qid = (length($req_body) >= 2) ? substr($req_body, 0, 2) : "\x12\x34";

    if ($req_header =~ /badchunk/i || $req_body =~ /badchunk/i) {
        # Return invalid chunked transfer encoding (syntax error in chunk size)
        my $http_resp = "HTTP/1.1 200 OK\r\n" .
                        "Content-Type: application/dns-message\r\n" .
                        "Transfer-Encoding: chunked\r\n" .
                        "Connection: keep-alive\r\n\r\n" .
                        "ZZZZ\r\n"; # Invalid hex chunk size
        syswrite($conn, $http_resp);
    } else {
        # Normal DoH response
        my $resp_dns = $qid . "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" . # ID, QR=1, AA=1, QD=1, AN=1
                       "\x04good\x07example\x03com\x00\x00\x01\x00\x01" .
                       "\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01"; # A 192.0.2.1
        my $http_resp = "HTTP/1.1 200 OK\r\n" .
                        "Content-Type: application/dns-message\r\n" .
                        "Content-Length: " . length($resp_dns) . "\r\n" .
                        "Connection: close\r\n\r\n" .
                        $resp_dns;
        syswrite($conn, $http_resp);
    }
    close($conn);
}
PL_EOF

perl "$TMP_DIR/mock_doh_server.pl" "$PORT" &
MOCK_PID=$!
sleep 0.5

# Test 1: Invalid chunk error causes cache invalidation and does not desync subsequent queries
cat << EOF > "$TMP_DIR/batch.txt"
badchunk.example.com A
good.example.com A
EOF

echo "=== 1. Testing DoH Batch Mode with Corrupted Chunk Response ==="
echo -n "Test: Subsequent query in batch succeeds after corrupted framing ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT +http-plain +keepopen -f "$TMP_DIR/batch.txt" 2>&1 || true)
if echo "$OUT" | grep -q "192\.0\.2\.1"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL DOH CACHE CLEANUP TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED DOH CACHE CLEANUP TESTS FAILED!"
    exit 1
fi

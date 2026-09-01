#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) IXFR Up-to-Date (Single SOA) Completion Test Suite
# (RFC 1995 §3: Up-to-date zone returns single SOA and closes without hang)
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
TMP_DIR="/tmp/dag_ixfr_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create a mock TCP DNS server that returns a single SOA (RFC 1995 §3 Up-to-Date IXFR response)
# and forks to keep each connection idle for 3 seconds without blocking the accept loop.
cat << 'PL_EOF' > "$TMP_DIR/mock_ixfr_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port>\n";
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";
listen($srv, SOMAXCONN) or die "listen: $!";

while (my $client = accept(my $conn, $srv)) {
    my $pid = fork();
    if (defined $pid && $pid == 0) {
        close($srv);
        my $len_buf;
        if (read($conn, $len_buf, 2) == 2) {
            my $qlen = unpack("n", $len_buf);
            my $query;
            if (read($conn, $query, $qlen) == $qlen && length($query) >= 12) {
                my $qid = substr($query, 0, 2);

                # Build single SOA response:
                # Header: QR=1, AA=1, RCODE=0, QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
                my $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0);

                # Question section: example.com. IN IXFR (251)
                $resp .= "\x07example\x03com\x00" . pack("nn", 251, 1);

                # Answer section: 1 SOA record (RFC 1995 §3 up-to-date)
                # Name: example.com. (pointer 0xc00c), Type: SOA (6), Class: IN (1), TTL: 300
                my $soa_rdata = "\x03ns1\x07example\x03com\x00" .  # MNAME
                                "\x0ahostmaster\x07example\x03com\x00" . # RNAME
                                pack("NNNNN", 2026090101, 7200, 3600, 1209600, 300); # Serial + Timers
                $resp .= pack("n", 0xc00c) . pack("nnNn", 6, 1, 300, length($soa_rdata)) . $soa_rdata;

                my $resp_len = pack("n", length($resp));
                syswrite($conn, $resp_len . $resp);

                # Sleep to verify dag terminates immediately upon receiving single SOA without hanging
                sleep 3;
            }
        }
        close($conn);
        exit 0;
    }
    close($conn);
}
PL_EOF

perl "$TMP_DIR/mock_ixfr_server.pl" "$PORT" &
MOCK_PID=$!
sleep 0.5

CURRENT_SERIAL="2026090101"

echo "=== 1. Testing IXFR with Current Serial (Up-to-Date: Single SOA) ==="
echo -n "Test: IXFR up-to-date query completes immediately without hanging ... "
START_TIME=$(date +%s)
OUT=$("$DAG" example.com "IXFR=$CURRENT_SERIAL" @127.0.0.1 -p $PORT +tcp +timeout=2 2>&1 || true)
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

if [ "$ELAPSED" -ge 2 ]; then
    echo "FAILED (timed out / hung for $ELAPSED seconds)"
    echo "  Output: $OUT"
    FAILED=$((FAILED + 1))
elif echo "$OUT" | grep -q "SOA.*2026090101"; then
    echo "OK (completed in ${ELAPSED}s)"
else
    echo "FAILED (missing SOA in response)"
    echo "  Output: $OUT"
    FAILED=$((FAILED + 1))
fi

echo -n "Test: IXFR up-to-date query contains only 1 SOA and no extra records ... "
SOA_COUNT=$(echo "$OUT" | grep -c "SOA" || true)
if [ "$SOA_COUNT" -eq 1 ]; then
    echo "OK"
else
    echo "FAILED (expected 1 SOA, got $SOA_COUNT)"
    echo "  Output: $OUT"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing IXFR with Current Serial in Short Mode (+short) ==="
echo -n "Test: IXFR up-to-date query in +short mode completes immediately ... "
START_TIME=$(date +%s)
OUT_SHORT=$("$DAG" example.com "IXFR=$CURRENT_SERIAL" @127.0.0.1 -p $PORT +tcp +short +timeout=2 2>&1 || true)
END_TIME=$(date +%s)
ELAPSED_SHORT=$((END_TIME - START_TIME))

if [ "$ELAPSED_SHORT" -ge 2 ]; then
    echo "FAILED (timed out / hung for $ELAPSED_SHORT seconds in +short mode)"
    echo "  Output: $OUT_SHORT"
    FAILED=$((FAILED + 1))
elif echo "$OUT_SHORT" | grep -q "ns1\.example\.com\."; then
    echo "OK (completed in ${ELAPSED_SHORT}s)"
else
    echo "FAILED (missing short SOA rdata)"
    echo "  Output: $OUT_SHORT"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL IXFR UP-TO-DATE COMPLETION TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED IXFR UP-TO-DATE COMPLETION TESTS FAILED!"
    exit 1
fi

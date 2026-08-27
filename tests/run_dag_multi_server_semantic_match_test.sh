#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Multi-Server Semantic Match Test Suite
# (Verify that responses with identical RR sets but different compression
#  or RR ordering correctly match as "Semantic Match")
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag with make ==="
make -C "$ROOT_DIR" dag

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    echo "[-] dig does not support multi-server comparison summary; skipping."
    exit 0
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
PORT1=$((36000 + $$ % 1500))
PORT2=$((PORT1 + 1))
TMP_DIR="/tmp/karidns_semantic_match_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV1_PID" ] && kill -9 "$SRV1_PID" 2>/dev/null || true
    [ -n "$SRV2_PID" ] && kill -9 "$SRV2_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock Server 1: Uncompressed response (Large)
cat <<'PL_EOF' > "$TMP_DIR/mock_large.pl"
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

    # Uncompressed RR format (full domain names in RDATA)
    my $resp = $qid . pack("H*",
        "81000001000000020000" .
        "036d73670473697a65097463707265706c6179036e65740000010001" .
        "036d73670473697a65097463707265706c6179036e657400000200010000012c0022" .
        "046e733031036d73670473697a65097463707265706c6179036e657400" .
        "036d73670473697a65097463707265706c6179036e657400000200010000012c0022" .
        "046e733032036d73670473697a65097463707265706c6179036e657400"
    );
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

# Start Mock Server 2: Compressed response with swapped RR order (Small)
cat <<'PL_EOF' > "$TMP_DIR/mock_small.pl"
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

    # Compressed RR format with inverted order (ns02 first, ns01 second)
    my $resp = $qid . pack("H*",
        "81000001000000020000" .
        "036d73670473697a65097463707265706c6179036e65740000010001" .
        "c00c000200010000012c0007046e733032c00c" .
        "c00c000200010000012c0007046e733031c00c"
    );
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_large.pl" "$PORT1" &
SRV1_PID=$!
perl "$TMP_DIR/mock_small.pl" "$PORT2" &
SRV2_PID=$!
sleep 0.3

echo "=== 1. Testing Multi-Server Semantic Match across compression and RR order ==="
echo -n "Test: Multi-server summary reports Semantic Match ... "
OUT=$($DAG msg.size.tcpreplay.net @127.0.0.1#$PORT1,127.0.0.1#$PORT2 2>&1 || true)

if echo "$OUT" | grep -q "Record Match"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL MULTI-SERVER SEMANTIC MATCH TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED MULTI-SERVER SEMANTIC MATCH TESTS FAILED!"
    exit 1
fi

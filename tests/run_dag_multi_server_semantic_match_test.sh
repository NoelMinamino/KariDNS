#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Multi-Server Status Match Test Suite
# (Verify [BASE], MATCH_EXACT, MATCH_SEMANTIC, and [DIFF] statuses in summary)
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
PORT3=$((PORT1 + 2))
PORT4=$((PORT1 + 3))
TMP_DIR="/tmp/karidns_semantic_match_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV1_PID" ] && kill -9 "$SRV1_PID" 2>/dev/null || true
    [ -n "$SRV2_PID" ] && kill -9 "$SRV2_PID" 2>/dev/null || true
    [ -n "$SRV3_PID" ] && kill -9 "$SRV3_PID" 2>/dev/null || true
    [ -n "$SRV4_PID" ] && kill -9 "$SRV4_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock Server 1: Uncompressed response (Base)
cat <<'PL_EOF' > "$TMP_DIR/mock_srv1.pl"
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

    # Uncompressed RR format (full domain names in RDATA, len = 29 = 0x1d)
    my $resp = $qid . pack("H*",
        "81000001000000020000" .
        "036d73670473697a65097463707265706c6179036e65740000010001" .
        "036d73670473697a65097463707265706c6179036e657400000200010000012c001d" .
        "046e733031036d73670473697a65097463707265706c6179036e657400" .
        "036d73670473697a65097463707265706c6179036e657400000200010000012c001d" .
        "046e733032036d73670473697a65097463707265706c6179036e657400"
    );
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

# Start Mock Server 2: Exact byte match to Server 1 (MATCH_EXACT)
cat <<'PL_EOF' > "$TMP_DIR/mock_srv2.pl"
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

    # Identical wire format to Server 1 (MATCH_EXACT)
    my $resp = $qid . pack("H*",
        "81000001000000020000" .
        "036d73670473697a65097463707265706c6179036e65740000010001" .
        "036d73670473697a65097463707265706c6179036e657400000200010000012c001d" .
        "046e733031036d73670473697a65097463707265706c6179036e657400" .
        "036d73670473697a65097463707265706c6179036e657400000200010000012c001d" .
        "046e733032036d73670473697a65097463707265706c6179036e657400"
    );
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

# Start Mock Server 3: Compressed response with swapped RR order (MATCH_SEMANTIC)
cat <<'PL_EOF' > "$TMP_DIR/mock_srv3.pl"
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

# Start Mock Server 4: Different response / NXDOMAIN ([DIFF])
cat <<'PL_EOF' > "$TMP_DIR/mock_srv4.pl"
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

    # NXDOMAIN response ([DIFF])
    my $resp = $qid . pack("H*",
        "81830001000000000000" .
        "036d73670473697a65097463707265706c6179036e65740000010001"
    );
    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_srv1.pl" "$PORT1" &
SRV1_PID=$!
perl "$TMP_DIR/mock_srv2.pl" "$PORT2" &
SRV2_PID=$!
perl "$TMP_DIR/mock_srv3.pl" "$PORT3" &
SRV3_PID=$!
perl "$TMP_DIR/mock_srv4.pl" "$PORT4" &
SRV4_PID=$!
sleep 0.3

echo "=== 1. Testing Multi-Server Summary Comparison Matrix ([BASE], MATCH_EXACT, MATCH_SEMANTIC, [DIFF]) ==="
OUT=$($DAG msg.size.tcpreplay.net @127.0.0.1#$PORT1,127.0.0.1#$PORT2,127.0.0.1#$PORT3,127.0.0.1#$PORT4 2>&1 || true)

echo -n "Test: Multi-server summary outputs [BASE] for reference server ... "
if echo "$OUT" | grep -q "\[BASE\]"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Expected [BASE] in output"
    echo "  Output:"
    echo "$OUT"
    FAILED=$((FAILED + 1))
fi

echo -n "Test: Multi-server summary outputs MATCH_EXACT for identical server ... "
if echo "$OUT" | grep -q "MATCH_EXACT"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Expected MATCH_EXACT in output"
    echo "  Output:"
    echo "$OUT"
    FAILED=$((FAILED + 1))
fi

echo -n "Test: Multi-server summary outputs MATCH_SEMANTIC for semantically identical server ... "
if echo "$OUT" | grep -q "MATCH_SEMANTIC"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Expected MATCH_SEMANTIC in output"
    echo "  Output:"
    echo "$OUT"
    FAILED=$((FAILED + 1))
fi

echo -n "Test: Multi-server summary outputs [DIFF] for differing server ... "
if echo "$OUT" | grep -q "\[DIFF\]"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Expected [DIFF] in output"
    echo "  Output:"
    echo "$OUT"
    FAILED=$((FAILED + 1))
fi

echo -n "Test: Multi-server summary does NOT contain obsolete MATCH_BASE or MATCH_DIFF ... "
if echo "$OUT" | grep -q -E "MATCH_BASE|MATCH_DIFF"; then
    echo "FAILED"
    echo "  Found obsolete MATCH_BASE or MATCH_DIFF in output!"
    echo "  Output:"
    echo "$OUT"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL MULTI-SERVER SEMANTIC MATCH TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED MULTI-SERVER SEMANTIC MATCH TESTS FAILED!"
    exit 1
fi

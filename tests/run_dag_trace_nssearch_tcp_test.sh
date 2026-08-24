#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace / +nssearch TCP Validation Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag and karidns with make ==="
make -C "$ROOT_DIR" dag karidns

DAG="$ROOT_DIR/dag"
KARIDNS="$ROOT_DIR/karidns"

if [ ! -x "$DAG" ] || [ ! -x "$KARIDNS" ]; then
    echo "dag or karidns binary not found"
    exit 1
fi

FAILED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    echo -n "Test: $NAME ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$EXPECT"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

echo "=== 1. Testing Help Message for +trace & +nssearch ==="
run_check "--help contains +trace TCP note" "$DAG --help" "honors \+tcp; falls back to TCP on truncated responses"
run_check "--help contains +nssearch TCP note" "$DAG --help" "Search all authoritative nameservers for zone \(honors \+tcp"

echo "=== 2. Testing +nssearch +tcp & +trace +tcp with Single KariDNS Instance ==="
CONF_FILE="/tmp/karidns_trace_tcp_test.conf"
PORT=15398

# Clean up any existing instances before start
killall -9 karidns 2>/dev/null || true
sleep 0.5

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
};

zone "example.com" {
    type master;
    file "$ROOT_DIR/tests/zones/example.com.zone";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > /tmp/karidns_trace_test.log 2>&1 &
SERVER_PID=$!
sleep 0.5

# Test that querying karidns with +nssearch +tcp logs TCP in summary table
run_check "+nssearch +tcp logs TCP protocol in summary" "$DAG @127.0.0.1 -p $PORT example.com +nssearch +tcp +timeout=2" "\|\s*TCP\s*\|"

# Test that querying karidns with +trace +tcp successfully communicates via TCP
run_check "+trace +tcp receives response from root probe" "$DAG @127.0.0.1 -p $PORT example.com +trace +tcp +timeout=2" "Received [0-9]+ bytes from 127\.0\.0\.1#$PORT"

kill $SERVER_PID 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
rm -f "$CONF_FILE" /tmp/karidns_trace_test.log

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE/NSSEARCH TCP TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

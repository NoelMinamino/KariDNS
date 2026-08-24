#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace / +nssearch TCP Validation Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag and karidns with make ==="
make -C "$ROOT_DIR" dag karidns

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"
KARIDNS="${KARIDNS:-$ROOT_DIR/karidns}"

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
        DAG="./dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag executable not found at $DAG"
        exit 1
    fi
fi

if [ ! -x "$KARIDNS" ]; then
    KARIDNS="./karidns"
fi
if [ ! -x "$KARIDNS" ]; then
    echo "Error: karidns binary not found at $KARIDNS"
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
if [ "$DAG" != "dig" ] && [ "$(basename "$DAG")" != "dig" ]; then
    run_check "--help contains +trace TCP note" "$DAG --help" "honors \+tcp; falls back to TCP on truncated responses"
    run_check "--help contains +nssearch TCP note" "$DAG --help" "Search all authoritative nameservers for zone \(honors \+tcp"
else
    echo "Test: --help checks ... SKIP (dig-specific options)"
fi

echo "=== 2. Testing +nssearch +tcp & +trace +tcp with Single KariDNS Instance ==="
CONF_FILE="/tmp/karidns_trace_tcp_test.conf"
ZONE_FILE="/tmp/karidns_trace_tcp_test.zone"
PORT=15398

# Clean up any existing instances before start
killall -9 karidns 2>/dev/null || true
sleep 0.5

cat <<EOF > "$ZONE_FILE"
\$TTL 86400
\$ORIGIN example.com.
@       IN SOA  localhost. hostmaster.example.com. (
                2026071001 ; serial
                3600       ; refresh
                900        ; retry
                1209600    ; expire
                86400 )    ; minimum
        IN NS   localhost.
localhost IN A  127.0.0.1
www     IN A    192.0.2.10
EOF

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
};

zone "example.com" {
    type master;
    file "$ZONE_FILE";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > /tmp/karidns_trace_test.log 2>&1 &
SERVER_PID=$!
sleep 0.5

# Test that querying karidns with +nssearch +tcp resolves SOA from zone nameservers (identical output on dig and dag)
run_check "+nssearch +tcp queries nameservers for SOA" "$DAG @127.0.0.1 -p $PORT example.com +nssearch +tcp +timeout=2" "SOA\s+localhost\.\s+hostmaster\.example\.com\..*from server 127\.0\.0\.1"

# Test that querying karidns with +trace +tcp successfully communicates via TCP
run_check "+trace +tcp receives response from root probe" "$DAG @127.0.0.1 -p $PORT example.com +trace +tcp +timeout=2" "Received [0-9]+ bytes from 127\.0\.0\.1#$PORT"

kill $SERVER_PID 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
rm -f "$CONF_FILE" "$ZONE_FILE" /tmp/karidns_trace_test.log

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE/NSSEARCH TCP TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

#!/bin/sh
set -e

# Test: TCP/TLS connect timeout test (RFC 7858, RFC 8484)
# Verifies that +timeout=N is enforced during TCP connection establishment phase,
# terminating around N seconds rather than hanging on OS default long connection timeout.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${DAG:-$BIN_DIR/dag}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$BIN_DIR/dag"
    fi
    if [ ! -x "$DAG" ]; then
        DAG="./dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag executable not found at $DAG"
        exit 1
    fi
fi

echo "Running: test_dag_tcp_connect_timeout ($DAG)"

# Use RFC 5737 TEST-NET-1 unrouted address 192.0.2.1:53 with +tcp +timeout=2
START_TIME=$(date +%s)
OUT=$($DAG @192.0.2.1 -p 53 example.com A +tcp +timeout=2 +tries=1 2>&1 || true)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Verify duration is bounded within 1 to 5 seconds (not OS default 20-100s)
if [ "$DURATION" -gt 5 ]; then
    echo "FAIL: TCP connect took $DURATION seconds, expected <= 5s under +timeout=2"
    echo "$OUT"
    exit 1
fi

# Verify timeout indication or failure exit
if [ "$DAG" != "dig" ]; then
    echo "$OUT" | grep -q -i -E "timed out|no usable response" || {
        echo "FAIL: Expected timeout indication in output"
        echo "$OUT"
        exit 1
    }
fi

echo "PASS: test_dag_tcp_connect_timeout (completed in ${DURATION}s)"
exit 0

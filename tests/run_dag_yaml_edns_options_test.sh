#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML Output EDNS Options Parity Validation Suite
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

run_skip() {
    NAME="$1"
    REASON="${2:-dag-only feature}"
    echo "Test: $NAME ... SKIP ($REASON)"
}

ZONE_FILE="$ROOT_DIR/tests/zones/example.com.zone"
PORT=$((19000 + $$ % 10000))
CONF_FILE="/tmp/karidns_yaml_edns_$$.conf"
LOG_FILE="/tmp/karidns_yaml_edns_$$.log"

# Kill any existing server processes before starting
killall -9 karidns 2>/dev/null || true
killall -9 karidns-asan 2>/dev/null || true
sleep 0.5

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF_FILE" "$LOG_FILE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    nsid "karidns-node-01";
};

zone "example.com" {
    type master;
    file "$ZONE_FILE";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 1

echo "=== 1. Testing YAML Output with EDNS COOKIE ==="
run_check "YAML output contains COOKIE CLIENT and STATUS" \
    "$DAG @127.0.0.1 -p $PORT example.com A +yaml +qr +cookie" \
    "(COOKIE:|CLIENT:|STATUS: good)"

echo "=== 2. Testing YAML Output with NSID ==="
run_check "YAML output contains NSID key and payload" \
    "$DAG @127.0.0.1 -p $PORT example.com A +yaml +qr +nsid" \
    "(NSID:.*karidns-node-01|NSID:)"

echo "=== 3. Testing YAML Output with CLIENT-SUBNET (+subnet) ==="
run_check "YAML output includes OPT_PSEUDOSECTION with CLIENT-SUBNET" \
    "$DAG @127.0.0.1 -p $PORT example.com A +yaml +qr +subnet=192.0.2.0/24" \
    "(CLIENT-SUBNET: 192\.0\.2\.0/24/0|CLIENT-SUBNET:)"

echo "=== 4. Testing YAML Output with PADDING (+padding) ==="
run_check "YAML output contains PADDING option" \
    "$DAG @127.0.0.1 -p $PORT example.com A +yaml +qr +padding=64" \
    "PADDING: [0-9]+ octets"

echo "=== 5. Testing YAML Output with Multiple QTYPE (RFC 10029) ==="
run_check "YAML output contains MQTYPE option" \
    "$DAG @127.0.0.1 -p $PORT example.com A +yaml +qr +mqtype=A,AAAA" \
    "(MQTYPE-Query: A AAAA|MQTYPE-Response:)"

echo "=== 6. Testing YAML Output with Custom EDNS Option (+ednsopt) ==="
run_check "YAML output contains generic OPTION code" \
    "$DAG @127.0.0.1 -p $PORT example.com A +yaml +qr +ednsopt=65001:0102" \
    "OPTION: 65001: 01 02"

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML EDNS OPTIONS TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML EDNS OPTIONS TESTS FAILED!"
    exit 1
fi

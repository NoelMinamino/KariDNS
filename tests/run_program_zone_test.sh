#!/bin/sh
set -e

# ==============================================================================
# KariDNS type "program" Plugin Zone Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICHECK="${BIN_DIR}/karicheck"
DAG="${DAG:-$BIN_DIR/dag}"
PLUGIN_SCRIPT="${BASE_DIR}/tests/plugins/dnstestscript.pl"

# Ensure clean slate before running
killall -9 karidns karidns-asan 2>/dev/null || true

TMP_DIR="$(mktemp -d /tmp/karidns_program_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((28000 + $$ % 5000))
FAILED=0
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECTED="$3"

    echo -n "Test: $NAME ... "
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUTPUT" | grep -E -q "$EXPECTED"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
}

chmod +x "$PLUGIN_SCRIPT" || true

echo "=== 1. Testing karicheck validation for type program ==="

cat << EOF > "$TMP_DIR/no_opt.conf"
zone "brokentest.example." {
    type program;
    program "$PLUGIN_SCRIPT";
};
EOF

run_check "karicheck rejects type program when allow-program-zones is missing" \
    "$KARICHECK conf $TMP_DIR/no_opt.conf" \
    "allow-program-zones.*not enabled"

cat << EOF > "$TMP_DIR/with_opt.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "named";
    allow-program-zones yes;
};

zone "brokentest.example." {
    type program;
    program "$PLUGIN_SCRIPT";
    program-args { };
    program-timeout 2000;
    program-max-failures 5;
};
EOF

run_check "karicheck accepts type program when allow-program-zones is enabled" \
    "$KARICHECK conf $TMP_DIR/with_opt.conf" \
    "Config file .* is valid"

echo ""
echo "=== 2. Testing KariDNS execution with type program zone ==="

cat << EOF > "$TMP_DIR/karidns_run.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
};

zone "brokentest.example." {
    type program;
    program "$PLUGIN_SCRIPT";
    program-timeout 2000;
    program-max-failures 5;
};
EOF

# Start karidns
"$KARIDNS" -f "$TMP_DIR/karidns_run.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

# Test standard query
run_check "Query to program zone returns plugin-generated response" \
    "$DAG @127.0.0.1 -p $PORT normal.brokentest.example A +timeout=2 +tries=1" \
    "192\.0\.2\.1"

# Test intentionally broken query
run_check "Query with truncated RDATA is handled without server crash" \
    "$DAG @127.0.0.1 -p $PORT trunc-rdata.brokentest.example A +timeout=2 +tries=1" \
    "ANSWER: 1"

if [ "$FAILED" -gt 0 ] && [ -f "$TMP_DIR/karidns.log" ]; then
    echo "=== Server Log ==="
    cat "$TMP_DIR/karidns.log"
fi

# Stop server
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo ""
echo "=== Test Summary ==="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL PROGRAM ZONE TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

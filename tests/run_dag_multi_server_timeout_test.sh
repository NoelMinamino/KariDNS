#!/bin/sh
set -e

# ==============================================================================
# DAG Multi-Server Partial Failure & Summary Output Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
DAG="${DAG:-$BIN_DIR/dag}"
KARIDNS="${BIN_DIR}/karidns"

TMP_DIR="$(mktemp -d /tmp/dag_multi_server_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT1=$((33000 + $$ % 4000))
PORT2=$((PORT1 + 1))
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

echo "=== Building dag and karidns ==="
(cd "$BASE_DIR" && make -j4 dag karidns)

cat << 'EOF' > "$TMP_DIR/test.zone"
$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026090201 3600 900 1800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
test1 IN TXT "hello from test1"
EOF

cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

zone "example.com" {
    type master;
    file "$TMP_DIR/test.zone";
};
EOF

echo "=== Starting KariDNS Server on port $PORT1 ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

# Non-responding port (PORT2 is not listening)
echo "=== Testing Multi-Server Query with One Non-Responding Server ==="
# We test with timeout=1 to keep test fast
run_check "Multi-server query continues past unreachable server and outputs comparison summary" \
    "$DAG @127.0.0.1#$PORT1,127.0.0.1#$PORT2 test1.example.com TXT +tcp +timeout=1 +tries=1" \
    "MULTI-SERVER COMPARISON SUMMARY"

run_check "Multi-server query outputs response from responding server" \
    "$DAG @127.0.0.1#$PORT1,127.0.0.1#$PORT2 test1.example.com TXT +tcp +timeout=1 +tries=1" \
    "hello from test1"

echo "=== Summary ==="
if [ $FAILED -eq 0 ]; then
    echo "ALL DAG MULTI-SERVER TIMEOUT TESTS PASSED!"
    exit 0
else
    echo "$FAILED TEST(S) FAILED."
    cat "$TMP_DIR/server.log"
    exit 1
fi

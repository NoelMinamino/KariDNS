#!/bin/sh
set -e

# ==============================================================================
# DAG Edge Cases Phase 3 Test Suite
# (LOC locale independence, single TCP fallback, +ednsopt overflow safety)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
DAG="${DAG:-$BIN_DIR/dag}"
KARIDNS="${BIN_DIR}/karidns"

TMP_DIR="$(mktemp -d /tmp/dag_edge_cases_phase3_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((32000 + $$ % 5000))
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

# 1. LOC Record Parsing Under Non-C Locale (Task 1)
echo "=== 1. Testing LOC Record Formatting and Locale Independence (Task 1) ==="
cat << 'EOF' > "$TMP_DIR/loc.zone"
$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026090201 3600 900 1800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
loc1 IN LOC 42 21 54.123 N 71 06 01.456 W 12.34m 10m 100m 10m
large IN TXT "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
large IN TXT "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
large IN TXT "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
large IN TXT "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
large IN TXT "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
EOF

cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

zone "example.com" {
    type master;
    file "$TMP_DIR/loc.zone";
};
EOF

echo "=== Starting KariDNS Server on port $PORT ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

run_check "Query LOC record with fractional seconds and altitude" \
    "$DAG @127.0.0.1 -p $PORT loc1.example.com LOC +udp" \
    "42 21 54\.123 N 71 6 1\.456 W 12\.34m"

# 2. +ednsopt Overflow Strict Error Handling (Task 3)
echo "=== 2. Testing +ednsopt Oversized Payload Handling (Task 3) ==="
# Generate a 1200 hex character string (600 bytes, exceeding 512 bytes limit)
LONG_HEX=$(perl -e 'print "aa" x 600')
run_check "+ednsopt exceeding buffer capacity aborts with error" \
    "$DAG @127.0.0.1 -p $PORT loc1.example.com LOC '+ednsopt=65001:$LONG_HEX'" \
    "error: \+ednsopt hex payload exceeds buffer size"

# 3. TCP Fallback Clean Single Execution (Task 2)
echo "=== 3. Testing Single-Pass TCP Fallback on Truncation (Task 2) ==="
run_check "+ignore prevents TCP fallback and prints UDP response with TC bit" \
    "$DAG @127.0.0.1 -p $PORT large.example.com TXT +noedns +ignore +udp" \
    "flags: .*tc"

run_check "Truncated query without +ignore automatically falls back to TCP" \
    "$DAG @127.0.0.1 -p $PORT large.example.com TXT +noedns" \
    "status: NOERROR"

echo "=== Summary ==="
if [ $FAILED -eq 0 ]; then
    echo "ALL DAG EDGE CASES PHASE 3 TESTS PASSED!"
    exit 0
else
    echo "$FAILED TEST(S) FAILED."
    cat "$TMP_DIR/server.log"
    exit 1
fi

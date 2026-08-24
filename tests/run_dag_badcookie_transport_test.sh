#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) BADCOOKIE Transport, +keepopen, +expire, +allcompare Tests
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

echo "=== 1. Testing +keepopen Option Acceptance & Help Message ==="
run_check "--help contains +keepopen RFC 7766 note" "$DAG --help" "Keep TCP socket open between consecutive queries \(RFC 7766\)"
run_check "+keepopen flag accepted" "$DAG @127.0.0.1 -p 10053 example.com A +tcp +keepopen +timeout=1" "(opcode: QUERY|timed out|no usable response|status:)"

echo "=== 2. Testing +expire EDNS Option (RFC 7314) Generation ==="
# +expire should include EDNS Option Code 9 (0x0009) with length 0 (0x0000)
run_check "+expire emits EDNS option 9 in query" "$DAG @127.0.0.1 -p 10053 example.com A +expire +qr +timeout=1" "(00 09 00 00|EXPIRE)"

echo "=== 3. Testing Real Queries against KariDNS ==="
CONF_FILE="/tmp/karidns_badcookie_test.conf"
PORT=15399

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

"$KARIDNS" -f "$CONF_FILE" > /tmp/karidns_badcookie_test.log 2>&1 &
SERVER_PID=$!
sleep 0.5

# 3.1 +allcompare header test (multi-server comparison summary)
run_check "+allcompare displays SEM_HASH(+TTL) header" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +allcompare +timeout=2" "SEM_HASH\(\+TTL\)"
run_check "default comparison displays SEM_HASH header" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +timeout=2" "SEM_HASH\s*\|"

# 3.2 BADCOOKIE transport retention on retry
run_check "+tcp +cookie retry on KariDNS maintains TCP" "$DAG @127.0.0.1 -p $PORT example.com A +tcp +cookie=0102030405060708 +timeout=2" "\(TCP\)"

# 3.3 +keepopen consecutive queries
run_check "+tcp +keepopen consecutive queries on KariDNS" "$DAG @127.0.0.1 -p $PORT example.com A +tcp +keepopen example.com TXT @127.0.0.1 -p $PORT +tcp +keepopen +timeout=2" "\(TCP\)"

kill $SERVER_PID 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
rm -f "$CONF_FILE" /tmp/karidns_badcookie_test.log

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL BADCOOKIE / EXPIRE / KEEPOPEN TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

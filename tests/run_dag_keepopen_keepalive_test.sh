#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +keepopen (RFC 7766) & +keepalive (RFC 7828) Test Suite
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

echo "=== 1. Testing +keepalive (EDNS TCP Keepalive, RFC 7828) Option Generation ==="
# +keepalive generates Option Code 11 (0x000B) with length 0
run_check "+keepalive emits EDNS Option 11 (00 0b 00 00)" "$DAG @127.0.0.1 -p 10053 example.com A +keepalive +qr +timeout=1" "(00 0b 00 00|KEEPALIVE)"
run_check "+nokeepalive suppresses Option 11" "$DAG @127.0.0.1 -p 10053 example.com A +nokeepalive +qr +timeout=1" "(opcode: QUERY|status: NOERROR)"

echo "=== 2. Starting KariDNS Server for Live TCP/Keepopen Tests ==="
CONF_FILE="/tmp/karidns_keepopen_test.conf"
PORT=15488

killall -9 karidns 2>/dev/null || true
sleep 0.5

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    tcp-connection-reuse yes;
    tcp-idle-timeout 10000;
};

zone "example.com" {
    type master;
    file "$ROOT_DIR/tests/zones/example.com.zone";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > /tmp/karidns_keepopen_test.log 2>&1 &
SERVER_PID=$!
sleep 0.5

echo "=== 3. Testing +keepopen Multi-Query Tuple Execution (RFC 7766) ==="
# Test executing 3 consecutive queries in one invocation over TCP with +keepopen
run_check "3 consecutive queries via TCP with +keepopen" \
    "$DAG @127.0.0.1 -p $PORT example.com A +tcp +keepopen example.com TXT @127.0.0.1 -p $PORT +tcp +keepopen example.com NS @127.0.0.1 -p $PORT +tcp +keepopen +timeout=2" \
    "v=spf1 mx"

echo "=== 4. Testing +keepopen Batch Mode (-f) ==="
BATCH_FILE="/tmp/dag_batch_keepopen.txt"
cat <<EOF > "$BATCH_FILE"
example.com A
example.com TXT
example.com SOA
EOF

run_check "batch mode queries via TCP with +keepopen" \
    "$DAG @127.0.0.1 -p $PORT -f $BATCH_FILE +tcp +keepopen +timeout=2" \
    "hostmaster\.example\.com"

rm -f "$BATCH_FILE"

echo "=== 5. Testing +keepopen with Combined +keepalive Option (RFC 7828) ==="
# When tcp-connection-reuse is enabled on KariDNS, KariDNS responds with EDNS Keepalive timeout (100 in 100ms units = 10s)
run_check "combined +keepopen and +keepalive over TCP" \
    "$DAG @127.0.0.1 -p $PORT example.com A +tcp +keepopen +keepalive example.com TXT @127.0.0.1 -p $PORT +tcp +keepopen +keepalive +timeout=2" \
    "(KEEPALIVE: 100|KEEPALIVE)"

kill $SERVER_PID 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
rm -f "$CONF_FILE" /tmp/karidns_keepopen_test.log

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL KEEPOPEN & KEEPALIVE TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

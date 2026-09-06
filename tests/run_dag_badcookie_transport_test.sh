#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) BADCOOKIE Transport, +keepopen, +expire, +allcompare Tests
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -x "$ROOT_DIR/dag" ] || [ ! -x "$ROOT_DIR/karidns" ]; then
    echo "=== Building dag and karidns with make ==="
    make -C "$ROOT_DIR" dag karidns
fi

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

run_skip() {
    NAME="$1"
    REASON="${2:-dag-only feature}"
    echo "Test: $NAME ... SKIP ($REASON)"
}

CONF_FILE="/tmp/karidns_badcookie_test_$$.conf"
LOG_FILE="/tmp/karidns_badcookie_test_$$.log"
PORT=$((15000 + $$ % 10000))
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        pkill -P "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$CONF_FILE" "$LOG_FILE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== 1. Testing +keepopen Option Acceptance & Help Message ==="
if [ "$DAG" = "dig" ]; then
    run_skip "--help contains +keepopen RFC 7766 note"
    run_skip "+keepopen flag accepted"
else
    run_check "--help contains +keepopen RFC 7766 note" "$DAG --help" "Keep TCP socket open between consecutive queries \(RFC 7766\)"
    run_check "+keepopen flag accepted" "$DAG @127.0.0.1 -p 10053 example.com A +tcp +keepopen +timeout=1" "(opcode: QUERY|timed out|no usable response|status:|no servers could be reached)"
fi

echo "=== 2. Testing +expire EDNS Option (RFC 7314) Generation ==="
# +expire should include EDNS Option Code 9 (0x0009) with length 0 (0x0000)
run_check "+expire emits EDNS option 9 in query" "$DAG @127.0.0.1 -p 10053 example.com A +expire +qr +timeout=1" "(00 09 00 00|EXPIRE)"

echo "=== 3. Testing Real Queries against KariDNS ==="

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

zone "example.com" {
    type master;
    file "$ROOT_DIR/tests/zones/example.com.zone";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 0.5

# 3.1 +allcompare header test (multi-server comparison summary)
if [ "$DAG" = "dig" ]; then
    run_skip "+allcompare displays SEM_HASH(+TTL) header"
    run_skip "+allcompare with +cookie"
    run_skip "+allcompare with +tcp +timeout=2"
    run_skip "+allcompare with +time=2"
    run_skip "default comparison displays SEM_HASH header"
else
    run_check "+allcompare displays SEM_HASH(+TTL) header" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +allcompare +timeout=2" "SEM_HASH\(\+TTL\)"
    run_check "+allcompare with +cookie" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +cookie +allcompare +timeout=2" "SEM_HASH\(\+TTL\)"
    run_check "+allcompare with +tcp +timeout=2" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +tcp +timeout=2 +allcompare" "SEM_HASH\(\+TTL\)"
    run_check "+allcompare with +time=2" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +time=2 +allcompare" "SEM_HASH\(\+TTL\)"
    run_check "default comparison displays SEM_HASH header" "$DAG @127.0.0.1,127.0.0.1 -p $PORT example.com A +timeout=2" "SEM_HASH\s*\|"
fi

# 3.2 BADCOOKIE transport retention on retry
run_check "+tcp +cookie retry on KariDNS maintains TCP" "$DAG @127.0.0.1 -p $PORT example.com A +tcp +cookie=0102030405060708 +timeout=2" "\(TCP\)"

# 3.3 +keepopen consecutive queries
if [ "$DAG" = "dig" ]; then
    run_skip "+tcp +keepopen consecutive queries on KariDNS"
else
    run_check "+tcp +keepopen consecutive queries on KariDNS" "$DAG @127.0.0.1 -p $PORT example.com A +tcp +keepopen example.com TXT @127.0.0.1 -p $PORT +tcp +keepopen +timeout=2" "\(TCP\)"
fi

cleanup

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL BADCOOKIE / EXPIRE / KEEPOPEN TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

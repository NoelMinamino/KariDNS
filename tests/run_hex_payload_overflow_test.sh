#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Hex Payload Buffer Overflow & Sentinel Validation Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building tools/dag with make ==="
make -C "$ROOT_DIR" dag

DAG="$ROOT_DIR/dag"
if [ ! -x "$DAG" ]; then
    echo "dag binary not found at $DAG"
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

run_exit_check() {
    NAME="$1"
    CMD="$2"
    EXP_CODE="$3"
    echo -n "Exit code test: $NAME ... "
    set +e
    eval "$CMD" >/dev/null 2>&1
    ACT_CODE=$?
    set -e
    if [ "$ACT_CODE" -eq "$EXP_CODE" ]; then
        echo "OK (code $ACT_CODE)"
    else
        echo "FAILED (expected $EXP_CODE, got $ACT_CODE)"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Running Hex Payload Boundary & Overflow Tests ==="

# 1. Generate an oversized hex string (140,000 hex characters = 70,000 bytes > 65,535 bytes buffer)
OVERSIZED_HEX=$(python3 -c "print('aa' * 70000)" 2>/dev/null || perl -e 'print "aa" x 70000' 2>/dev/null || printf '%0.sAA' $(seq 1 70000))

# Test 1: Oversized hex payload must be rejected without crashing (Exit code 1)
run_check "Oversized hex payload error message" "$DAG @127.0.0.1 -p 10053 --hex $OVERSIZED_HEX" "Invalid, empty, or oversized hex payload"
run_exit_check "Oversized hex payload exit code 1" "$DAG @127.0.0.1 -p 10053 --hex $OVERSIZED_HEX" 1

# Test 2: Empty hex payload must be rejected (Exit code 1)
run_check "Empty hex payload rejection" "$DAG @127.0.0.1 -p 10053 --hex ''" "Invalid, empty, or oversized hex payload"
run_exit_check "Empty hex payload exit code 1" "$DAG @127.0.0.1 -p 10053 --hex ''" 1

# Test 3: Invalid non-hex characters only must be rejected (Exit code 1)
run_check "Non-hex payload rejection" "$DAG @127.0.0.1 -p 10053 --hex 'zz--!!@@'" "Invalid, empty, or oversized hex payload"
run_exit_check "Non-hex payload exit code 1" "$DAG @127.0.0.1 -p 10053 --hex 'zz--!!@@'" 1

# Test 4: Valid minimal DNS query hex payload format validation
# Query ID: 0x1234, Flags: 0x0100 (RD), QDCOUNT: 1, QNAME: example.com, QTYPE: A, QCLASS: IN
VALID_HEX="123401000001000000000000076578616d706c6503636f6d0000010001"
run_check "Valid hex payload parses without error" "$DAG @127.0.0.1 -p 10053 --hex $VALID_HEX +timeout=1" "(Query \(29 bytes\)|opcode: QUERY|timed out|no usable response)"

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL HEX PAYLOAD OVERFLOW TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

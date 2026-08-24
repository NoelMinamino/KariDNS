#!/bin/sh
set -e

# Test: Duplicate --break kind parameter override validation (last-wins)
# Verifies that specifying the same --break kind multiple times correctly overrides earlier parameters
# and outputs a note message.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${1:-${DAG:-$BIN_DIR/dag}}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    echo "Test: duplicate --break kind override ... SKIP (dag-only feature)"
    exit 0
fi

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

echo "Running: test_break_duplicate_kind_override ($DAG)"

# Test 1: Verify override note message and that last parameter (param=10) wins
echo -n "Testing --break too-short=2 --break too-short=10 ... "
OUT1=$($DAG example.com A @127.0.0.1 +qr --break too-short=2 --break too-short=10 +timeout=1 2>&1 || true)

# 1. Check override note message
echo "$OUT1" | grep -q -i "note: --break 'too-short' overrides previous value for this kind" || {
    echo "FAILED: Expected override note message"
    echo "$OUT1"
    exit 1
}

# 2. Check that the query length is 10 bytes (not 2 bytes)
echo "$OUT1" | grep -q "Query (10 bytes):" || {
    echo "FAILED: Expected 'Query (10 bytes):' in output (got earlier param=2 or other length)"
    echo "$OUT1"
    exit 1
}
echo "OK"

# Test 2: Verify structural break override with same kind (oversized-qname) works without 'already set' warning
echo -n "Testing duplicate structural break kind override ... "
OUT2=$($DAG example.com A @127.0.0.1 --break oversized-qname --break oversized-qname +timeout=1 2>&1 || true)
if echo "$OUT2" | grep -q -i "structural break kind is already set"; then
    echo "FAILED: Expected duplicate structural break of SAME kind to be allowed as override"
    echo "$OUT2"
    exit 1
fi
echo "$OUT2" | grep -q -i "note: --break 'oversized-qname' overrides previous value" || {
    echo "FAILED: Expected override note for duplicate oversized-qname"
    echo "$OUT2"
    exit 1
}
echo "OK"

echo "PASS: test_break_duplicate_kind_override"
exit 0

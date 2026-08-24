#!/bin/sh
set -e

# Test: --update-del with type omitted (RFC 2136 §2.5.2 delete all RRsets on name)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${DAG:-$BIN_DIR/dag}"
if [ ! -x "$DAG" ]; then
    DAG="./dag"
fi

if [ ! -x "$DAG" ]; then
    echo "Error: dag executable not found at $DAG"
    exit 1
fi

echo "Running: test_update_del_no_type"
OUT=$($DAG @127.0.0.1 example.com --update-del "obsolete.example.com" +qr +timeout=1 2>&1 || true)

# 1. Verify opcode: UPDATE
echo "$OUT" | grep -q -i "opcode:[[:space:]]*UPDATE" || {
    echo "FAIL: Expected UPDATE opcode in output"
    echo "$OUT"
    exit 1
}

# 2. Verify AUTHORITY count is 1 (where update records reside)
echo "$OUT" | grep -q -i "AUTHORITY:[[:space:]]*1" || {
    echo "FAIL: Expected AUTHORITY: 1 in query packet"
    echo "$OUT"
    exit 1
}

# 3. Verify wire bytes contains TYPE=255 (00 ff) and CLASS=255 (00 ff)
echo "$OUT" | grep -q -E "00[[:space:]]+ff[[:space:]]+00[[:space:]]+ff" || {
    echo "FAIL: Expected TYPE=ANY(255) and CLASS=ANY(255) in wire query"
    echo "$OUT"
    exit 1
}

echo "PASS: test_update_del_no_type"
exit 0

#!/bin/sh
set -e

# Test: --update-del-exact with 'name TTL type rdata' (class omitted) & robustness against unknown types

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

echo "Running: test_update_del_exact_ttl_notype_crash"

# 1. Test class omitted with TTL: 'host.example.com 300 A 192.0.2.1'
OUT1=$($DAG @127.0.0.1 example.com --update-del-exact "host.example.com 300 A 192.0.2.1" +qr +timeout=1 2>&1 || true)

echo "$OUT1" | grep -q -i "opcode:[[:space:]]*UPDATE" || {
    echo "FAIL: Expected UPDATE opcode in test 1"
    echo "$OUT1"
    exit 1
}
echo "$OUT1" | grep -q -i "AUTHORITY:[[:space:]]*1" || {
    echo "FAIL: Expected AUTHORITY: 1 in test 1"
    echo "$OUT1"
    exit 1
}

# 2. Test unknown type does not crash the entire process, skips bad op, and proceeds with other ops
OUT2=$($DAG @127.0.0.1 example.com \
    --update-del-exact "bad.example.com BOGUSTYPE 192.0.2.1" \
    --update-add "valid.example.com 300 A 192.0.2.2" \
    +qr +timeout=1 2>&1 || true)

echo "$OUT2" | grep -q -i "warning: unknown record type 'BOGUSTYPE'" || {
    echo "FAIL: Expected warning for unknown record type in test 2"
    echo "$OUT2"
    exit 1
}
echo "$OUT2" | grep -q -i "AUTHORITY:[[:space:]]*1" || {
    echo "FAIL: Expected valid operation to be serialized (AUTHORITY: 1) in test 2"
    echo "$OUT2"
    exit 1
}

# 3. Symmetry test: --update-add and --update-del-exact accept identical format
OUT3=$($DAG @127.0.0.1 example.com \
    --update-add "sym.example.com 300 A 192.0.2.5" \
    --update-del-exact "sym.example.com 300 A 192.0.2.5" \
    +qr +timeout=1 2>&1 || true)

echo "$OUT3" | grep -q -i "AUTHORITY:[[:space:]]*2" || {
    echo "FAIL: Expected both operations to be serialized (AUTHORITY: 2) in test 3"
    echo "$OUT3"
    exit 1
}

echo "PASS: test_update_del_exact_ttl_notype_crash"
exit 0

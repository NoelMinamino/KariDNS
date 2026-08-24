#!/bin/sh
set -e

# Test: Regression test for --update-del-exact TTL support and unknown type safety
# 1. Verifies that `dag --update-del-exact 'host.example.com 300 A 1.2.3.4'` without explicit CLASS parses correctly
# 2. Verifies that unknown RR type name (e.g. UNKNOWNTYPE999) does not crash the process with exit(1)
# 3. Verifies symmetry with --update-add

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${DAG:-$BIN_DIR/dag}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
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
fi

echo "Running: test_dag_update_del_exact_ttl_notype_crash"

# 1. TTL parsing with omitted class: TYPE=1 (00 01), CLASS=NONE (00 fe per RFC 2136 §2.5.4), TTL=0, RDLEN=4, RDATA=1.2.3.4 (01 02 03 04)
OUT_EXACT=$($DAG @127.0.0.1 example.com SOA --update-del-exact 'host.example.com 300 A 1.2.3.4' +qr +timeout=1 2>&1 || true)
echo "$OUT_EXACT" | grep -q -i "01 00 fe 00 00 00 00 00  04 01 02 03 04" || {
    echo "FAIL: Expected wire format for --update-del-exact with TTL omitted class"
    echo "$OUT_EXACT"
    exit 1
}

# 2. Unknown RR type graceful recovery without exit(1) crash
OUT_UNKNOWN=$($DAG @127.0.0.1 example.com SOA --update-del 'host.example.com UNKNOWNTYPE999' +qr +timeout=1 2>&1 || true)
echo "$OUT_UNKNOWN" | grep -q -i "Warning: unknown record type 'UNKNOWNTYPE999'" || {
    echo "FAIL: Expected warning for unknown record type"
    echo "$OUT_UNKNOWN"
    exit 1
}

# Query should still be built and executed
echo "$OUT_UNKNOWN" | grep -q -i "Query (" || {
    echo "FAIL: Query execution aborted on unknown record type"
    echo "$OUT_UNKNOWN"
    exit 1
}

# 3. Symmetry check: --update-add with omitted class
OUT_ADD=$($DAG @127.0.0.1 example.com SOA --update-add 'host.example.com 300 A 1.2.3.4' +qr +timeout=1 2>&1 || true)
echo "$OUT_ADD" | grep -q -i "01 00 01 00 00 01 2c 00  04 01 02 03 04" || {
    echo "FAIL: Expected wire format for --update-add with omitted class"
    echo "$OUT_ADD"
    exit 1
}

echo "PASS: test_dag_update_del_exact_ttl_notype_crash"
exit 0

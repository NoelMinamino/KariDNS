#!/bin/sh
set -e

# Test: dag --break help examples validation
# Verifies that all --break examples listed in dag --help are valid supported kinds and do not emit 'unknown --break kind' warnings.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${1:-${DAG:-$BIN_DIR/dag}}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    echo "Test: --break help examples ... SKIP (dag-only feature)"
    echo "PASS: test_dag_break_help_examples (skipped for dig)"
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

echo "Running: test_dag_break_help_examples ($DAG)"

# Test all examples from help:
# --break oversized-qname
# --break compression-loop
# --break too-short=2
# --break all

FAILED=0
for ex in "oversized-qname" "compression-loop" "too-short=2" "all"; do
    echo -n "Testing example: dag example.com A @127.0.0.1 --break $ex +timeout=1 ... "
    OUT=$($DAG example.com A @127.0.0.1 --break "$ex" +timeout=1 2>&1 || true)
    if echo "$OUT" | grep -q -i "unknown --break kind"; then
        echo "FAILED (emitted unknown --break kind warning)"
        echo "$OUT"
        FAILED=$((FAILED + 1))
    else
        echo "OK"
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED examples failed"
    exit 1
fi

echo "PASS: test_dag_break_help_examples"
exit 0

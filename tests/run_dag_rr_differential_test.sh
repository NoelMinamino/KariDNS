#!/bin/sh
# ==============================================================================
# run_dag_rr_differential_test.sh
#
# Runner for the Structured RR Differential & Semantic Oracle test suite.
# ==============================================================================

set -u
cd "$(dirname "$0")/.."

DAG="${DAG:-./dag}"

if [ ! -x "$DAG" ]; then
    make dag >/dev/null 2>&1 || true
fi

if [ ! -x "$DAG" ]; then
    echo "[-] Error: dag binary not found at $DAG"
    exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping test."
    exit 0
fi

perl tests/rr_differential_test.pl --dag "$DAG" --iterations 20
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "PASS: RR Differential test suite passed successfully."
    exit 0
else
    echo "FAIL: RR Differential test suite failed with exit code $EXIT_CODE."
    exit 1
fi

#!/bin/sh
# ==============================================================================
# tests/run_dag_fuzzer_test.sh - dag libFuzzer corpus regression
# ==============================================================================
# Runs every dag libFuzzer harness (tests/fuzz/fuzz_dag_*.c) once over every input
# of its corpus (libFuzzer -runs=0: execute the inputs, no mutation), so each
# stored reproducer and seed is checked against the current code under ASan/UBSan.
# Mutation runs are done by tests/run_fuzz_smoke_test.sh (TEST_MATRIX #160).
# A harness that is not built is built with "make fuzz_dag_all" (as $SUDO_USER
# under sudo, so the tree gets no root-owned objects); a build failure fails.
set -u
cd "$(dirname "$0")/.."

TARGETS=$(ls tests/fuzz/fuzz_dag_*.c | sed 's|tests/fuzz/||; s|\.c$||')
missing=0
for t in $TARGETS; do
    [ -x "tests/fuzz/$t" ] || missing=1
done
if [ "$missing" -eq 1 ]; then
    echo "[+] Building the dag fuzzers (make fuzz_dag_all)..."
    if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
        su -m "$SUDO_USER" -c "make fuzz_dag_all" > /tmp/run_dag_fuzzer_build.$$.log 2>&1
    else
        make fuzz_dag_all > /tmp/run_dag_fuzzer_build.$$.log 2>&1
    fi
    rc=$?
    if [ "$rc" -ne 0 ]; then
        tail -n 30 /tmp/run_dag_fuzzer_build.$$.log
        rm -f /tmp/run_dag_fuzzer_build.$$.log
        echo "[FAIL] make fuzz_dag_all failed"
        exit 1
    fi
    rm -f /tmp/run_dag_fuzzer_build.$$.log
fi

FAILED=0
TOTAL=0
LOG=$(mktemp /tmp/run_dag_fuzzer.XXXXXX)
trap 'rm -f "$LOG"' EXIT INT TERM
for t in $TARGETS; do
    bin="tests/fuzz/$t"
    corpus="tests/fuzz/corpus_$t"
    if [ ! -x "$bin" ]; then
        echo "[FAIL] $t: not built"
        FAILED=$((FAILED + 1))
        continue
    fi
    n=$(ls -1 "$corpus" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -eq 0 ]; then
        echo "[FAIL] $t: corpus $corpus is missing or empty"
        FAILED=$((FAILED + 1))
        continue
    fi
    if "$bin" -runs=0 -close_fd_mask=3 "$corpus" > "$LOG" 2>&1; then
        echo "[OK] $t: $n corpus inputs"
        TOTAL=$((TOTAL + n))
    else
        echo "[FAIL] $t: crash or error on the corpus"
        tail -n 40 "$LOG"
        FAILED=$((FAILED + 1))
    fi
done
# reproducer kept outside the per-target corpora (long RDATA, fuzz_dag_response)
if tests/fuzz/fuzz_dag_response -runs=0 -close_fd_mask=3 tests/fuzz/corpus/dag_long_rdata.bin > "$LOG" 2>&1; then
    echo "[OK] fuzz_dag_response: tests/fuzz/corpus/dag_long_rdata.bin"
else
    echo "[FAIL] fuzz_dag_response: tests/fuzz/corpus/dag_long_rdata.bin"
    tail -n 40 "$LOG"
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -ne 0 ]; then
    echo "[FAIL] $FAILED dag fuzzer corpus run(s) failed"
    exit 1
fi
echo "[+] All $(echo $TARGETS | wc -w | tr -d ' ') dag fuzzers ran their corpora ($TOTAL inputs) without a crash."
exit 0

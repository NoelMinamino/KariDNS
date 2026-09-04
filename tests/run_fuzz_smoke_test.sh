#!/bin/sh
# Lightweight Fuzzer Smoke Test for KariDNS and dag(1)
#
# Runs parallel fuzzers with mutations (default 1,000 runs per target).
# Suppresses noisy engine output and packet data dumps.
# Displays progress (OK/FAIL) and only prints logs on failure.
#
# Usage:
#   sh tests/run_fuzz_smoke_test.sh dag      # Test all dag fuzzers
#   sh tests/run_fuzz_smoke_test.sh karidns  # Test all KariDNS server fuzzers
#   sh tests/run_fuzz_smoke_test.sh all      # Test all fuzzers
#
# Options:
#   FUZZ_RUNS=1000          # Number of runs per target (default: 1000)
#   FUZZ_SMOKE_SECONDS=5    # Time limit per target (used if FUZZ_RUNS is empty)

set -u
cd "$(dirname "$0")/.."

MODE="${1:-dag}"
FUZZ_RUNS="${FUZZ_RUNS:-1000}"
FUZZ_SMOKE_SECONDS="${FUZZ_SMOKE_SECONDS:-}"

FAILED=0
log_fail() { echo "  -> FAIL: $1"; FAILED=1; }
log_ok()   { echo "  -> OK: $1"; }

run_fuzz_group() {
    title="$1"
    shift
    targets="$@"

    echo "=========================================="
    if [ -n "${FUZZ_RUNS:-}" ] && [ "$FUZZ_RUNS" -gt 0 ]; then
        echo "$title (${FUZZ_RUNS} runs per target in parallel)"
    else
        echo "$title (${FUZZ_SMOKE_SECONDS:-5}s per target in parallel)"
    fi
    echo "=========================================="

    pids=""
    for target in $targets; do
        bin="tests/fuzz/$target"
        corpus="tests/fuzz/corpus_$target"
        [ -d "$corpus" ] || corpus="tests/fuzz/corpus"
        logf="fuzz_${target}.log"

        if [ ! -x "$bin" ]; then
            echo "  -> SKIP: $bin not built"
            continue
        fi

        count=$(ls -1 "$corpus" 2>/dev/null | wc -l)
        if [ "$count" -le 0 ]; then
            log_fail "$target (corpus $corpus is empty!)"
            continue
        fi

        # -close_fd_mask=3 closes stdout/stderr during LLVMFuzzerTestOneInput
        # to prevent terminal mojibake and noisy parser dumps.
        # Output is directed to logf in background.
        if [ -n "${FUZZ_RUNS:-}" ] && [ "$FUZZ_RUNS" -gt 0 ]; then
            "$bin" -runs="$FUZZ_RUNS" -close_fd_mask=3 "$corpus" > "$logf" 2>&1 &
        else
            "$bin" -max_total_time="${FUZZ_SMOKE_SECONDS:-5}" -close_fd_mask=3 "$corpus" > "$logf" 2>&1 &
        fi
        pids="$pids $target:$!"
    done

    for tp in $pids; do
        target="${tp%%:*}"
        pid="${tp##*:}"
        wait $pid
        if [ $? -ne 0 ]; then
            log_fail "$target (crash / error detected, see fuzz_${target}.log)"
            echo "=========================================="
            tail -n 40 "fuzz_${target}.log"
            echo "=========================================="
        else
            if [ -n "${FUZZ_RUNS:-}" ] && [ "$FUZZ_RUNS" -gt 0 ]; then
                log_ok "$target (${FUZZ_RUNS} runs, no crash)"
            else
                log_ok "$target (${FUZZ_SMOKE_SECONDS}s, no crash)"
            fi
            rm -f "fuzz_${target}.log"
        fi
    done
}

if [ "$MODE" = "dag" ] || [ "$MODE" = "all" ]; then
    run_fuzz_group "DAG Fuzzer Smoke Run" \
        fuzz_dag_response fuzz_dag_hash fuzz_dag_chunked_http \
        fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file
fi

if [ "$MODE" = "karidns" ] || [ "$MODE" = "all" ]; then
    [ "$MODE" = "all" ] && echo ""
    run_fuzz_group "KariDNS Server Fuzzer Smoke Run" \
        fuzz_dns_wire fuzz_dns_server_core fuzz_zone_parser \
        fuzz_conf_parser fuzz_tsig_sign fuzz_tsig_verify
fi

echo ""
echo "=========================================="
if [ "$FAILED" -eq 0 ]; then
    echo "All fuzzer smoke tests passed."
    exit 0
else
    echo "One or more fuzzer smoke tests FAILED. See logs above / *.log files."
    exit 1
fi

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
#   sh tests/run_fuzz_smoke_test.sh all      # Test all fuzzers (default; tests/run_all_suite.sh uses it)
#
# A harness that is not built is built with make first (as $SUDO_USER when the script runs under sudo, so the
# tree does not get root-owned objects); a harness that cannot be built is a failure, not a skip (X-06).
#
# Options:
#   FUZZ_RUNS=1000          # Number of runs per target (default: 1000)
#   FUZZ_SMOKE_SECONDS=5    # Time limit per target (used if FUZZ_RUNS is empty)

set -u
cd "$(dirname "$0")/.."

MODE="${1:-all}"
case "$MODE" in
    dag|karidns|all) ;;
    *) echo "usage: $0 [dag|karidns|all]"; exit 2 ;;
esac
FUZZ_RUNS="${FUZZ_RUNS:-1000}"
FUZZ_SMOKE_SECONDS="${FUZZ_SMOKE_SECONDS:-}"

FAILED=0
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/kari_fuzz_smoke.XXXXXX") || exit 1
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
log_fail() { echo "  -> FAIL: $1"; FAILED=1; }
log_ok()   { echo "  -> OK: $1"; }

# make target that builds tests/fuzz/<binary> (see the Makefile)
make_target_of() {
    case "$1" in
        fuzz_dns_wire)         echo fuzz ;;
        fuzz_dns_server_core)  echo fuzz_core ;;
        fuzz_zone_parser)      echo fuzz_zone ;;
        fuzz_conf_parser)      echo fuzz_conf ;;
        fuzz_tsig_sign)        echo fuzz_tsig ;;
        fuzz_dag_response)     echo fuzz_dag ;;
        *)                     echo "$1" ;;
    esac
}

build_fuzzer() {
    t=$(make_target_of "$1")
    echo "  -> building $1 (make $t)"
    if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
        su -m "$SUDO_USER" -c "make $t" > "fuzz_build_$1.log" 2>&1
    else
        make "$t" > "fuzz_build_$1.log" 2>&1
    fi
}

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
            if ! build_fuzzer "$target" || [ ! -x "$bin" ]; then
                log_fail "$target (not built and the build failed, see fuzz_build_$target.log)"
                tail -n 20 "fuzz_build_$target.log"
                continue
            fi
            rm -f "fuzz_build_$target.log"
        fi

        count=$(ls -1 "$corpus" 2>/dev/null | wc -l)
        if [ "$count" -le 0 ]; then
            log_fail "$target (corpus $corpus is empty!)"
            continue
        fi

        # -close_fd_mask=3 closes stdout/stderr during LLVMFuzzerTestOneInput
        # to prevent terminal mojibake and noisy parser dumps.
        # Output is directed to logf in background.
        # New inputs go to the first directory: a scratch one, so the corpus in git is only read.
        newdir="$SCRATCH/$target"
        mkdir -p "$newdir"
        if [ -n "${FUZZ_RUNS:-}" ] && [ "$FUZZ_RUNS" -gt 0 ]; then
            "$bin" -runs="$FUZZ_RUNS" -close_fd_mask=3 "$newdir" "$corpus" > "$logf" 2>&1 &
        else
            "$bin" -max_total_time="${FUZZ_SMOKE_SECONDS:-5}" -close_fd_mask=3 "$newdir" "$corpus" > "$logf" 2>&1 &
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
        fuzz_dag_response fuzz_dag_hash fuzz_dag_iter_classify fuzz_dag_chunked_http \
        fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file \
        fuzz_dag_replay_pcap_reader fuzz_dag_replay_diff fuzz_dag_tcp_reassembly
fi

if [ "$MODE" = "karidns" ] || [ "$MODE" = "all" ]; then
    [ "$MODE" = "all" ] && echo ""
    run_fuzz_group "KariDNS Server Fuzzer Smoke Run" \
        fuzz_dns_wire fuzz_dns_server_core fuzz_zone_parser \
        fuzz_conf_parser fuzz_tsig_sign fuzz_tsig_verify \
        fuzz_query_engine fuzz_xfr_packet fuzz_dynamic_update
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

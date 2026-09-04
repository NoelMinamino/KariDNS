#!/bin/sh
set -e
cd "$(dirname "$0")/.."

MODE="${1:-dag}"

if [ "$MODE" = "dag" ] || [ "$MODE" = "all" ]; then
    echo "=== Running DAG Fuzzer Smoke Tests ==="
    for target in fuzz_dag_response fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file; do
        corpus="tests/fuzz/corpus_$target"
        [ -d "$corpus" ] || corpus="tests/fuzz/corpus"
        count=$(ls -1 "$corpus" 2>/dev/null | wc -l)
        echo "Checking $target (corpus files: $count)"
        [ "$count" -gt 0 ] || { echo "Error: corpus $corpus is empty!"; exit 1; }
        ./tests/fuzz/$target -runs=1 "$corpus" || exit 1
    done
    echo "🎉 ALL DAG FUZZER SMOKE TESTS PASSED!"
fi

if [ "$MODE" = "karidns" ] || [ "$MODE" = "all" ]; then
    echo "=== Running KariDNS Server Fuzzer Smoke Tests ==="
    for target in fuzz_dns_wire fuzz_dns_server_core fuzz_zone_parser fuzz_conf_parser fuzz_tsig_sign fuzz_tsig_verify; do
        corpus="tests/fuzz/corpus_$target"
        [ -d "$corpus" ] || corpus="tests/fuzz/corpus"
        count=$(ls -1 "$corpus" 2>/dev/null | wc -l)
        echo "Checking $target (corpus files: $count)"
        [ "$count" -gt 0 ] || { echo "Error: corpus $corpus is empty!"; exit 1; }
        ./tests/fuzz/$target -runs=1 "$corpus" || exit 1
    done
    echo "🎉 ALL KARIDNS FUZZER SMOKE TESTS PASSED!"
fi

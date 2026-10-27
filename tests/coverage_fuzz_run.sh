#!/bin/sh
# ==============================================================================
# tests/coverage_fuzz_run.sh - Replay fuzz corpuses for coverage data
# ==============================================================================
set -u

COV_DIR="${1:-coverage_raw}"
mkdir -p "$COV_DIR"

if [ -d "coverage_fuzz" ]; then
    for t in coverage_fuzz/fuzz_*; do
        if [ -x "$t" ]; then
            bname=$(basename "$t")
            corpus="tests/fuzz/corpus_${bname}"
            # as tests/run_fuzz_smoke_test.sh: a harness without its own corpus replays the shared one
            # (an empty directory made here would also make the smoke test fail later in this tree)
            [ -d "$corpus" ] || corpus="tests/fuzz/corpus"
            echo "=== Running coverage fuzz corpus replay: $bname"
            LLVM_PROFILE_FILE="$(pwd)/${COV_DIR}/fuzz_%p_%m.profraw" ./"$t" "$corpus" -runs=0 >/dev/null 2>&1 || true
        fi
    done
fi
exit 0

#!/bin/sh
# Nightly deep fuzzing: one shard of the libFuzzer harnesses of tests/fuzz/targets.sh (.github/workflows/fuzzing.yml).
#
# Shard k of n takes the targets whose position in FUZZ_ALL_TARGETS is k modulo n, and runs them FUZZ_JOBS at a
# time, each for FUZZ_SECONDS (or FUZZ_RUNS inputs).  The run must end inside the job's time limit: the script
# refuses a plan whose rounds x FUZZ_SECONDS exceed FUZZ_BUDGET.  Until 2026-11 the workflow ran all 41 targets
# 1800 s each, 2 at a time (10.5 h), was cancelled at 6 h every night and 17 targets never started.
#
# Every target leaves $FUZZ_OUT/<target>.log; a failing one also leaves its crash / oom / timeout input
# ($FUZZ_OUT/<target>-crash-...) and that input run once more with stdout and stderr open
# ($FUZZ_OUT/<target>.repro.log: the harness's reason and the stack).  The binaries must be built
# (make fuzz_all).  New corpus inputs go to tests/fuzz/corpus_<target>, which the workflow caches.
#
# Usage: FUZZ_SHARD=0 FUZZ_SHARDS=4 FUZZ_SECONDS=2700 sh tests/run_fuzz_nightly.sh
#   FUZZ_RUNS=n       runs per target instead of a time limit
#   FUZZ_JOBS=n       parallel targets (default: the number of CPUs)
#   FUZZ_RSS_MB=n     libFuzzer -rss_limit_mb (default 2500)
#   FUZZ_BUDGET=s     upper bound of rounds x FUZZ_SECONDS (default 16200 = 4.5 h)
#   FUZZ_OUT=dir      logs and artifacts (default fuzz_out)
# Exit status 1 if a target failed, was not built, or the plan does not fit the budget.

set -u
cd "$(dirname "$0")/.."
. tests/fuzz/targets.sh

SHARD="${FUZZ_SHARD:-0}"
SHARDS="${FUZZ_SHARDS:-1}"
SECONDS_PER="${FUZZ_SECONDS:-2700}"
RUNS="${FUZZ_RUNS:-}"
JOBS="${FUZZ_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2)}"
RSS_MB="${FUZZ_RSS_MB:-2500}"
BUDGET="${FUZZ_BUDGET:-16200}"
OUT="${FUZZ_OUT:-fuzz_out}"

case "$SHARD$SHARDS$SECONDS_PER$JOBS$RSS_MB$BUDGET$RUNS" in
    *[!0-9]*) echo "FUZZ_SHARD, FUZZ_SHARDS, FUZZ_SECONDS, FUZZ_RUNS, FUZZ_JOBS, FUZZ_RSS_MB and FUZZ_BUDGET are numbers"; exit 1 ;;
esac
[ "$SHARDS" -ge 1 ] && [ "$SHARD" -lt "$SHARDS" ] && [ "$JOBS" -ge 1 ] || { echo "need 0 <= FUZZ_SHARD < FUZZ_SHARDS and FUZZ_JOBS >= 1"; exit 1; }

fuzz_targets_check || exit 1

mine=""
n=0
i=0
for t in $FUZZ_ALL_TARGETS; do
    [ $((i % SHARDS)) -eq "$SHARD" ] && { mine="$mine $t"; n=$((n + 1)); }
    i=$((i + 1))
done
rounds=$(( (n + JOBS - 1) / JOBS ))
if [ -z "$RUNS" ] && [ $((rounds * SECONDS_PER)) -gt "$BUDGET" ]; then
    echo "shard $SHARD/$SHARDS: $n targets, $JOBS at a time = $rounds rounds x ${SECONDS_PER}s = $((rounds * SECONDS_PER))s > FUZZ_BUDGET ${BUDGET}s"
    exit 1
fi
echo "shard $SHARD/$SHARDS: $n of $i targets, $JOBS at a time, $rounds rounds, ${RUNS:+$RUNS runs}${RUNS:-${SECONDS_PER}s} per target, rss limit ${RSS_MB} MB:$mine"

mkdir -p "$OUT"
started=0
finished=0
failed=0
summary=""

finish() {      # target pid
    ft=$1
    if wait "$2"; then
        finished=$((finished + 1))
        res="OK"
    else
        failed=$((failed + 1))
        res="FAIL ($(grep -m1 '^SUMMARY:\|ERROR: libFuzzer' "$OUT/$ft.log" | sed 's/^==[0-9]*== //'))"
        echo "::error::fuzz target $ft failed: see $OUT/$ft.log"
        tail -n 60 "$OUT/$ft.log"
        for a in "$OUT/$ft"-crash-* "$OUT/$ft"-oom-* "$OUT/$ft"-timeout-* "$OUT/$ft"-leak-*; do
            [ -f "$a" ] || continue
            echo "--- $a run again with stdout / stderr open ($OUT/$ft.repro.log) ---"
            "tests/fuzz/$ft" -rss_limit_mb="$RSS_MB" "$a" > "$OUT/$ft.repro.log" 2>&1
            grep -v '^\(INFO\|Running\|Executed\|\*\*\*\)' "$OUT/$ft.repro.log" | head -n 60
            break
        done
    fi
    execs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$OUT/$ft.log" | tail -n 1)
    rss=$(sed -n 's/^stat::peak_rss_mb: *//p' "$OUT/$ft.log" | tail -n 1)
    summary="$summary
$(printf '%-30s %-12s %-8s %s' "$ft" "${execs:--}" "${rss:--}" "$res")"
}

set -- $mine
while [ $# -gt 0 ]; do
    pids=""
    k=0
    while [ $# -gt 0 ] && [ "$k" -lt "$JOBS" ]; do
        t=$1
        shift
        k=$((k + 1))
        bin="tests/fuzz/$t"
        corpus="tests/fuzz/corpus_$t"
        if [ ! -x "$bin" ]; then
            echo "::error::fuzz target $t is not built ($bin)"
            failed=$((failed + 1))
            summary="$summary
$(printf '%-30s %-12s %-8s %s' "$t" - - "FAIL (not built)")"
            continue
        fi
        mkdir -p "$corpus"
        seeds=""
        [ -n "$(ls -A "$corpus" 2>/dev/null)" ] || seeds="tests/fuzz/corpus"   # no corpus of its own yet: the shared seeds
        echo "[+] start $t ($(ls -1 "$corpus" | wc -l | tr -d ' ') corpus files${seeds:+, seeds from $seeds})"
        # -close_fd_mask=3: the dag harnesses print every response; a failure's output comes from the repro run
        if [ -n "$RUNS" ]; then
            "$bin" -runs="$RUNS" -rss_limit_mb="$RSS_MB" -close_fd_mask=3 -print_final_stats=1 -artifact_prefix="$OUT/$t-" "$corpus" $seeds > "$OUT/$t.log" 2>&1 &
        else
            "$bin" -max_total_time="$SECONDS_PER" -rss_limit_mb="$RSS_MB" -close_fd_mask=3 -print_final_stats=1 -artifact_prefix="$OUT/$t-" "$corpus" $seeds > "$OUT/$t.log" 2>&1 &
        fi
        pids="$pids $t:$!"
        started=$((started + 1))
    done
    for tp in $pids; do
        finish "${tp%%:*}" "${tp##*:}"
    done
done

echo ""
printf '%-30s %-12s %-8s %s\n' target executions peak_MB result
echo "$summary" | sed '/^$/d'
echo "shard $SHARD/$SHARDS: $n targets, $started started, $finished finished without a failure, $failed failed"
[ "$failed" -eq 0 ] && [ "$finished" -eq "$n" ]

#!/bin/sh
# suite_durations.sh - tests/suite_durations.tsv from the summaries of suite runs.
#
# usage: sh tests/suite_durations.sh SUMMARY.tsv... > tests/suite_durations.tsv
#
# A SUMMARY.tsv is tests/.test_logs/summary.tsv of a run of tests/run_all_suite.sh (status|command|category|seconds|exit code|description|note).
# The output has one line "name<TAB>seconds" per test that PASSed, sorted by name: the name is the command of the plan (tests/run_x_test.sh or
# the name of a unit test binary), as tests/run_all_suite.sh --shard reads it.  A test that appears in several files (or twice) gets its largest
# time; a test that did not pass (FAIL: cut short, SKIP: did not run) is left out, so it counts the default of 10 s until a run measures it.
# CI uploads the summaries of the coverage shards as the artifact "suite-durations" (tests/TEST_MATRIX.md, "Shards").
set -u

if [ "$#" -eq 0 ]; then
    echo "usage: $0 SUMMARY.tsv... > tests/suite_durations.tsv" >&2
    exit 2
fi
for f in "$@"; do
    [ -r "$f" ] || { echo "$0: cannot read $f" >&2; exit 1; }
done

echo "# name <TAB> seconds: the time of a test in the coverage run (4 slots), the cost of tests/run_all_suite.sh --shard.  name = the command of the plan"
echo "# (tests/run_x_test.sh or a unit test binary); a test not listed counts 10 s.  Refresh: tests/TEST_MATRIX.md (Shards), tests/suite_durations.sh."
cat "$@" | awk -F'|' '
    $1 == "PASS" && $2 != "" && $4 ~ /^[0-9]+$/ { if (!($2 in t) || $4 + 0 > t[$2]) t[$2] = $4 + 0 }
    END { for (n in t) printf "%s\t%d\n", n, t[n] }
' | LC_ALL=C sort -t "$(printf '\t')" -k1,1

#!/bin/sh
# coverage_shards_check.sh - the verdict of a sharded coverage run (make coverage-suite-check-shards).
#
# usage: sh tests/coverage_shards_check.sh [DIR]      (default coverage_shards)
#
# DIR holds the status file of every part: *.status, the coverage_suite.status that tests/run_all_suite.sh wrote for its part
# (KARI_SUITE_STATUS; total=... passed=... failed=... skipped=... on the first line, then failed_tests=, shard=I/N, selected=).
# The run passes only when
#   - there are exactly N files, one for each of the parts 1..N of the same N,
#   - every part selected the same number of tests, and the totals of the parts add up to it (every test ran in exactly one part),
#   - no part has a failed test.
# Otherwise it prints what is wrong (and the failing tests) and exits 1.
set -u

dir="${1:-coverage_shards}"
files=$(ls "$dir"/*.status 2>/dev/null)
if [ -z "$files" ]; then
    echo "Error: no status file of a part in $dir (coverage-shard jobs did not deliver their results)."
    exit 1
fi

# one line per file: file|shard I|shard N|selected|total|passed|failed|skipped|failed tests
for f in $files; do
    awk -v file="$f" '
        /^total=/ {
            for (i = 1; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] }
        }
        /^failed_tests=/ { sub(/^failed_tests=/, ""); ft = $0 }
        /^shard=/ { sub(/^shard=/, ""); sh = $0 }
        /^selected=/ { sub(/^selected=/, ""); sel = $0 }
        END {
            split(sh, p, "/")
            printf "%s|%s|%s|%s|%s|%s|%s|%s|%s\n", file, p[1], p[2], sel, v["total"], v["passed"], v["failed"], v["skipped"], ft
        }
    ' "$f"
done | awk -F'|' '
    {
        nf++
        file = $1; i = $2; n = $3; sel = $4; tot = $5; fl = $7; ft = $9
        if (i !~ /^[0-9]+$/ || n !~ /^[0-9]+$/ || sel !~ /^[0-9]+$/ || tot !~ /^[0-9]+$/ || fl !~ /^[0-9]+$/) {
            printf "Error: %s is not the status file of a part (no shard=, selected= or counts): %s\n", file, $0; bad = 1; next
        }
        if (N == "") N = n
        if (n != N) { printf "Error: %s is part %s/%s, another is of %s parts\n", file, i, n, N; bad = 1 }
        if (S == "") S = sel
        if (sel != S) { printf "Error: %s selected %s tests, another part %s\n", file, sel, S; bad = 1 }
        if (i in seen) { printf "Error: part %s/%s is there twice (%s, %s)\n", i, n, seen[i], file; bad = 1 }
        seen[i] = file
        sum += tot; passed += $6; failed += fl; skipped += $8
        if (fl > 0) { printf "Error: part %s/%s has %d failing test(s):\n", i, n, fl; m = split(ft, t, " "); for (k = 1; k <= m; k++) printf "  FAILED: %s\n", t[k]; bad = 1 }
    }
    END {
        if (nf == 0) { print "Error: no status file"; exit 1 }
        if (N != "" && nf != N + 0) { printf "Error: %d status file(s) for %s parts\n", nf, N; bad = 1 }
        if (N != "") for (i = 1; i <= N + 0; i++) if (!(i in seen)) { printf "Error: part %d/%s is missing\n", i, N; bad = 1 }
        if (S != "" && sum != S + 0) { printf "Error: the parts ran %d tests, %s were selected\n", sum, S; bad = 1 }
        if (bad) exit 1
        printf "Test suite (%s parts): total=%d passed=%d failed=%d skipped=%d, every selected test ran once\n", N, sum, passed, failed, skipped
    }
'

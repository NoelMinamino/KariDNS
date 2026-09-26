#!/bin/sh
# coverage_merge.sh - merge LLVM raw profiles, skipping unreadable ones.
#
# usage: sh tests/coverage_merge.sh <llvm-profdata> <raw-profile-dir> <output.profdata>
#
# Why this exists: `llvm-profdata merge a.profraw b.profraw ...` aborts with
#   "error: no profile can be merged"
# as soon as ONE input is invalid (default failure mode = "any"). Under `make coverage` every process forked
# from one karidns instance (manager, connect broker, backend, frontends) inherits the same, already expanded
# LLVM_PROFILE_FILE name, and they write it at exit -- some as the dropped-privilege user, some killed by the
# test teardown. A single truncated file ("file header is corrupt") therefore used to throw away the data of
# all ~hundreds of valid files. Validate each file on its own, merge the valid ones, report the rest.
set -u

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <llvm-profdata> <raw-profile-dir> <output.profdata>" >&2
    exit 2
fi
PROFDATA=$1
RAWDIR=$2
OUT=$3

LIST="${RAWDIR}/.valid_profraw.list"
PROBE="${RAWDIR}/.probe.profdata"
: > "$LIST" || { echo "Error: cannot write $LIST" >&2; exit 1; }

total=0
bad=0
for f in "$RAWDIR"/*.profraw; do
    [ -e "$f" ] || continue
    total=$((total + 1))
    # An empty file is never valid; otherwise let llvm-profdata itself be the judge, using the same
    # operation (merge) that is about to be performed for real.
    if [ -s "$f" ] && "$PROFDATA" merge -sparse "$f" -o "$PROBE" >/dev/null 2>&1; then
        printf '%s\n' "$f" >> "$LIST"
    else
        bad=$((bad + 1))
        size=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
        echo "  [coverage] skipping unreadable profile (${size:-?} bytes): $f"
    fi
done
rm -f "$PROBE"

valid=$((total - bad))
echo "  [coverage] raw profiles: total=${total} valid=${valid} skipped=${bad}"

if [ "$valid" -le 0 ]; then
    rm -f "$LIST"
    echo "Error: no valid profile data in ${RAWDIR}." >&2
    exit 1
fi

"$PROFDATA" merge -sparse -f "$LIST" -o "$OUT"
rc=$?
rm -f "$LIST"
exit $rc

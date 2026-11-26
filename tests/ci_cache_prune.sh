#!/bin/sh
# ci_cache_prune.sh - keep one cache per key prefix and ref: delete the older caches of this ref once this run's cache is saved (CI runner, gh).
#
# usage: sh tests/ci_cache_prune.sh PREFIX...     (GH_TOKEN with actions: write; GITHUB_REPOSITORY, GITHUB_REF, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT)
#
# The key of this run's cache is PREFIX<run id>-<attempt> (.github/workflows/freebsd.yml, ci.yml).  When it is not there (the save failed or was
# skipped) nothing is deleted: the older cache stays the one the next run restores.  Only caches of this ref (--ref) are looked at, so a branch
# never deletes main's.
set -u
: "${GITHUB_REPOSITORY:?}" "${GITHUB_REF:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
for p in "$@"; do
    new="${p}${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    keys=$(gh cache list --repo "$GITHUB_REPOSITORY" --ref "$GITHUB_REF" --key "$p" --limit 100 --json id,key,sizeInBytes \
        --jq '.[] | "\(.id) \(.key) \(.sizeInBytes)"') || { echo "gh cache list failed for $p: nothing deleted"; continue; }
    if ! echo "$keys" | awk -v k="$new" '$2 == k { f = 1 } END { exit !f }'; then
        echo "$new is not saved: the older caches of $p stay"
        continue
    fi
    echo "$keys" | while read -r id key size; do
        [ -n "$id" ] || continue
        if [ "$key" = "$new" ]; then echo "kept $key ($size bytes)"; continue; fi
        gh cache delete "$id" --repo "$GITHUB_REPOSITORY" > /dev/null && echo "deleted $key ($size bytes)"
    done
done
exit 0

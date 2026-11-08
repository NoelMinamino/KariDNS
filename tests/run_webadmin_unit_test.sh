#!/bin/sh
# run_webadmin_unit_test.sh - the unit tests of karidns-webadmin (webadmin/test/*.test.js and the shared node/test/*.test.js, node --test; 0.6.0 items D and E, M2).
# No package is needed for the tests (node:test, node:assert, node:sqlite): the HTTP server runs on SQLite3 files made from db/*.sql, the PostgreSQL side against a fake
# pool.  SKIP (exit 0) without node 22.13 or newer.  Function coverage of webadmin/lib and node/lib must be 100% (and lines 90%): `node --test --experimental-test-coverage`
# prints the table, this script checks it.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT/webadmin" || exit 1
NODE=${NODE:-node}
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }

OUT=$(mktemp "${TMPDIR:-/tmp}/karidns_webadmin_unit.XXXXXX") || exit 1
trap 'rm -f "$OUT"' EXIT
"$NODE" --test --experimental-test-coverage "test/*.test.js" "../node/test/*.test.js" > "$OUT" 2>&1
RC=$?
grep -E '^(not ok|# (tests|pass|fail))|^ℹ (tests|pass|fail|skipped)|✖' "$OUT" | head -40
sed -n '/start of coverage report/,/end of coverage report/p' "$OUT"
if [ $RC -ne 0 ]; then echo "=== run_webadmin_unit_test: the unit tests FAILED ==="; grep -B2 -A12 '^✖\|not ok' "$OUT" | head -80; exit 1; fi
ALL=$(grep -E 'all files' "$OUT" | head -1)
LINES=$(printf '%s' "$ALL" | awk -F'|' '{ gsub(/[^0-9.]/, "", $2); print $2 }')
FUNCS=$(printf '%s' "$ALL" | awk -F'|' '{ gsub(/[^0-9.]/, "", $4); print $4 }')
if [ -z "$LINES" ] || [ -z "$FUNCS" ]; then echo "=== run_webadmin_unit_test: no coverage table in the output ==="; exit 1; fi
if [ "${FUNCS%.*}" -lt 100 ] || [ "${LINES%.*}" -lt 90 ]; then echo "=== run_webadmin_unit_test: coverage too low (functions $FUNCS%, lines $LINES%; 100 and 90 are needed) ==="; exit 1; fi
echo "=== run_webadmin_unit_test: all unit tests passed (functions $FUNCS%, lines $LINES%) ==="
exit 0

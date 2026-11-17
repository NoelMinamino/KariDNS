#!/bin/sh
# run_db_batch_status_test.sh - the loader's side of BATCH_RESULT tag 7 (0.7, KDB_FEAT_BATCH_STATUS): a batch the Backend's store could not record.
#
# tests/db/fetch_backend.c stands in for the Backend (--store, every message through the Backend's state machine) and answers one chosen BATCH_END
# with tag 7 = ENOSPC (--fail-batch=N).  The real karidns-dbloader runs on a SQLite3 database with the karidns_* change log.  Checked:
#   - the loader offers the feature in HELLO (0x10)
#   - a diff batch (a reload drained from the cursor) answered with tag 7: the loader logs the error, stays up, and the next reload sends the same
#     changes again from the same position (the same entries, the same end cursor); after a batch that was recorded nothing is sent again
#   - a view first read by the failed batch (the startup pass of a first fill) is listed again by the next load; without the failure that reload is
#     a drain (no pass)
# The Backend side (tag 7 only to a loader that offers the feature, the batch end failing when the store cannot record it) is in tests/test_db_store.c.
# No root needed.  SKIP when the sqlite3 command line tool or a binary is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-./karidns-dbloader}
[ -x "$LOADER" ] || { echo "SKIP: $LOADER is not built"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
FB=${FETCH_BACKEND:-./fetch_backend}
[ -x "$FB" ] || { echo "SKIP: $FB is not built (make fetch_backend)"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbbstat.XXXXXX") || exit 1
trap 'if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }

DB="$T/z.db"
sh tests/db/gen_sqlite3_zones.sh "$DB" 40 7 > /dev/null || { fail "cannot build the database"; exit 1; }

# run NAME OPTION... -- ITEM...: the harness output in $T/NAME.out (the entries in $T/NAME.log, the loader's log in $T/NAME.err), its status in $RC
run() {
    n=$1; shift
    opts=""
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do opts="$opts $1"; shift; done
    [ $# -gt 0 ] && shift
    # shellcheck disable=SC2086
    "$FB" --store --log="$T/$n.log" $opts "$LOADER" "$DB" "$@" > "$T/$n.out" 2> "$T/$n.err"
    RC=$?
}
has() { grep -Eq -- "$3" "$T/$2" && pass "$1" || { fail "$1"; head -16 "$T/$2" | sed 's/^/         /'; }; }
hasnt() { grep -Eq -- "$3" "$T/$2" && { fail "$1"; grep -E -- "$3" "$T/$2" | head -5 | sed 's/^/         /'; } || pass "$1"; }
cnt() { grep -Ec -- "$2" "$T/$1" 2>/dev/null; }
is() { [ "$2" = "$3" ] && pass "$1" || fail "$1 (got '$2', want '$3')"; }
ok_run() { [ $RC -eq 0 ] && pass "$1: the harness ran to the end" || { fail "$1: the harness failed (status $RC)"; cat "$T/$1.out" "$T/$1.err" | head -20; }; }

echo "== first fill (recorded)"
run first -- sleep:300
ok_run first
has "the loader offers KDB_FEAT_BATCH_STATUS (HELLO features 31)" first.out '^HELLO features=31$'
has "the startup batch is answered as recorded" first.out '^BR batch=[0-9]+ store_error=0$'
grep '^STATE ' "$T/first.out" > "$T/st1"
has "the Backend keeps a cursor" st1 '^STATE view=0 cursor=[0-9]+ valid=1 '

echo "== a diff batch the store could not record: the next load reads the same changes again"
SQ="UPDATE records SET content = 'ns1.example.test. host.example.test. 9 3600 600 86400 300' WHERE domain_id = 5 AND type = 'SOA'"
run rew --fail-batch=2 --cursor=state:"$T/st1" -- sleep:200 "sh:sqlite3 $DB \"$SQ\"" reload batches:2 sleep:300 reload batches:3 sleep:300 reload batches:4 sleep:300
ok_run rew
is "four batches (startup, three reloads)" "$(cnt rew.out '^BB ')" 4
is "one BATCH_RESULT with tag 7 (ENOSPC), the second" "$(grep -E '^BR ' "$T/rew.out" | sed -n 2p | sed 's/.* //')" "store_error=28"
is "... and only that one" "$(cnt rew.out 'store_error=[1-9]')" 1
hasnt "no pass: the reloads are drains" rew.out '^MB '
is "the changed zone is sent twice: in the failed batch and again in the next one" "$(cnt rew.log '^C 0 up 5 z5\.test\. ')" 2
is "two drains carry it" "$(cnt rew.out '^CH view=0 cursor=[0-9]+ last=1 up=1 del=0$')" 2
C2=$(grep -E '^CH view=0 cursor=[0-9]+ last=1 up=1 ' "$T/rew.out" | sed -n 1p | sed 's/.* cursor=\([0-9]*\) .*/\1/')
C3=$(grep -E '^CH view=0 cursor=[0-9]+ last=1 up=1 ' "$T/rew.out" | sed -n 2p | sed 's/.* cursor=\([0-9]*\) .*/\1/')
is "the second drain ends where the failed one did (it started again from the old position)" "${C3:-x}" "${C2:-y}"
C1=$(sed -n 's/.* cursor=\([0-9]*\) .*/\1/p' "$T/st1" | head -1)
[ "${C2:-0}" -gt "${C1:-0}" ] && pass "the drain went past the first cursor ($C1 -> $C2)" || fail "the drain did not move the cursor ($C1 -> ${C2:-?})"
is "after the recorded batch the last reload sends nothing again" "$(cnt rew.out 'up=[1-9]')" 2
has "the Backend keeps the cursor of the recorded drain" rew.out "^STATE view=0 cursor=$C2 valid=1 "
grep -q "could not record batch" "$T/rew.err" && pass "the loader logs the batch the store could not record" || fail "the loader does not log it"
has "the loader stayed up and ended cleanly" rew.out '^DONE answers=0 loader=0$'

echo "== a view first read by the failed batch is listed again"
run fresh --fail-batch=1 -- sleep:300 reload batches:2 sleep:300
ok_run fresh
has "the startup pass is answered with tag 7" fresh.out '^BR batch=[0-9]+ store_error=28$'
is "the reload lists the view again (two passes)" "$(cnt fresh.out '^ME view=0 .*complete=1 ')" 2
run control -- sleep:300 reload batches:2 sleep:300
ok_run control
is "without the failure the reload is a drain (one pass)" "$(cnt control.out '^MB ')" 1

echo
echo "run_db_batch_status_test: $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

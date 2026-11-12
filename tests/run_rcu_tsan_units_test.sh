#!/bin/sh
# R-25 regression, the unit-test half of tests/run_rcu_tsan_test.sh: the unit tests of the lock-free parts under ThreadSanitizer.
#   test_epoch_rcu-tsan (publish order, grace period, reuse stress); test_zone_dir-tsan (the zone directory, D1a);
#   test_park-tsan, test_db_fetch-tsan, test_park_worker-tsan, test_db_stream-tsan, test_pdns_reader-tsan, test_db_registry-tsan (parked queries,
#   D1a milestone 2); test_server_core-tsan (the logger threads and the control thread).
# A test of its own (0.6.2) so that it runs next to the other tests: the servers half stays "serial" (tests/run_all_suite.sh).
# Any ThreadSanitizer report fails the test.

. "$(dirname "$0")/lib_proc.sh"
set -u

cd "$(dirname "$0")/.." || exit 1

echo "=== R-25 RCU TSan unit tests ==="

# One parallel make (Makefile: tsan-test-bins), as the invoking user (kari_make).
JOBS=$( (sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2) | head -n 1)
if ! kari_make -j"$JOBS" tsan-test-bins >/dev/null 2>&1; then
    echo "FAIL: could not build the TSan unit tests (make tsan-test-bins)"
    exit 1
fi

WORK="$(mktemp -d /tmp/karidns-rcu-tsan-units.XXXXXX)" || exit 1
trap '[ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT INT TERM

# run_unit BINARY SUMMARY_PATTERN : run one TSan unit test; an error exit or a ThreadSanitizer report fails the test
run_unit() {
    if ! TSAN_OPTIONS="halt_on_error=0" "./$1" >"$WORK/$1.log" 2>&1; then
        echo "FAIL: $1 exited with an error"
        cat "$WORK/$1.log"
        exit 1
    fi
    if grep -q "WARNING: ThreadSanitizer" "$WORK/$1.log"; then
        echo "FAIL: ThreadSanitizer reports in $1"
        cat "$WORK/$1.log"
        exit 1
    fi
    grep "$2" "$WORK/$1.log"
}

echo "--- part 1: test_epoch_rcu-tsan"
run_unit test_epoch_rcu-tsan "reads="

echo "--- part 1b: test_zone_dir-tsan (the zone directory under concurrent readers, D1a)"
run_unit test_zone_dir-tsan "inconsistencies"

# part 1c (D1a milestone 2): the park table, the wake and fetch rings, workers and the ingest thread; the Backend side of the fetch stream
# with the real ingest thread; a worker parking and answering a UDP query
for t in test_park test_db_fetch test_park_worker test_db_stream test_pdns_reader test_db_registry test_server_core; do
    echo "--- part 1c: ${t}-tsan"
    run_unit "${t}-tsan" "checks,"
done

echo "PASS: no ThreadSanitizer report"
exit 0

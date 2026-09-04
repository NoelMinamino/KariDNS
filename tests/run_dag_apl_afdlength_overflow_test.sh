#!/bin/sh
# run_dag_apl_afdlength_overflow_test.sh
#
# Regression test for a stack-buffer-overflow (CWE-121/CWE-787) found in
# tools/dag.c: format_rdata_for_display(), case 42 (APL / RFC 3123).
#
# afdlength (the address-family-dependent length field of an APL element)
# can be attacker-controlled up to 127 (0x7F), but was memcpy()'d directly
# into a fixed uint8_t addr[16] scratch buffer without any upper-bound
# check. format_rdata_for_display() is reached by calculate_packet_hashes(),
# which is called unconditionally by run_test() -- i.e. by any ordinary
# single-server `dag @server name type` query, not just a special mode.
#
# This script starts the Perl mock DNS server's `apl-overflow.example`
# scenario (an APL record with afdlength=127) and queries it with an
# ASan/UBSan-instrumented dag build, asserting that:
#   1. No AddressSanitizer/UndefinedBehaviorSanitizer error is raised.
#   2. dag exits successfully (not killed by SIGABRT/SIGSEGV).
#   3. The malformed element is reported as invalid rather than silently
#      mis-decoded, so future regressions are visible in the output too.
#
# Usage: ./tests/run_dag_apl_afdlength_overflow_test.sh
# Exit code: 0 = PASS, 1 = FAIL

set -u
cd "$(dirname "$0")/.."

PORT="${DAG_APL_TEST_PORT:-15953}"
MOCK_LOG="mock_apl_overflow.log"
DAG_LOG="dag_apl_overflow.log"

FAILED=0
log_fail() { echo "  -> FAIL: $1"; FAILED=1; }
log_ok()   { echo "  -> OK: $1"; }

cleanup() {
    [ -n "${MOCK_PID:-}" ] && kill -9 "$MOCK_PID" >/dev/null 2>&1
    pkill -9 -f "mock_dns_server.pl --port $PORT" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

echo "=========================================="
echo "APL (TYPE 42) afdlength overflow regression"
echo "=========================================="

echo "Step 1: Build dag-asan"
make dag-asan >/dev/null 2>build_dag_asan.log
if [ ! -x ./dag-asan ]; then
    log_fail "could not build dag-asan (see build_dag_asan.log)"
    exit 1
fi
log_ok "build"

echo "Step 2: Start mock DNS server"
perl tests/mock_dns_server.pl --port "$PORT" --host 127.0.0.1 > "$MOCK_LOG" 2>&1 &
MOCK_PID=$!
sleep 1
if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    log_fail "mock DNS server failed to start (see $MOCK_LOG)"
    exit 1
fi
log_ok "mock server listening on 127.0.0.1:$PORT"

echo "Step 3: Query apl-overflow.example APL with dag-asan"
export ASAN_OPTIONS=abort_on_error=1:halt_on_error=1
export UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1
./dag-asan apl-overflow.example APL @127.0.0.1 -p "$PORT" > "$DAG_LOG" 2>&1
DAG_EXIT=$?

if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" "$DAG_LOG"; then
    log_fail "dag-asan reported a sanitizer error (see $DAG_LOG)"
    tail -n 40 "$DAG_LOG"
elif [ "$DAG_EXIT" -ge 128 ]; then
    log_fail "dag-asan crashed (signal $((DAG_EXIT - 128)), see $DAG_LOG)"
    tail -n 40 "$DAG_LOG"
else
    log_ok "dag-asan completed without a sanitizer error or crash (exit $DAG_EXIT)"
fi

echo "Step 4: Verify the malformed APL element is reported, not mis-decoded"
if grep -q "APL afdlength=127 invalid for AFI=1" "$DAG_LOG"; then
    log_ok "malformed APL element correctly reported as invalid"
elif [ "$FAILED" -eq 0 ]; then
    log_fail "expected '[APL afdlength=127 invalid for AFI=1]' in output (see $DAG_LOG); dag may be an unpatched/older build"
    tail -n 40 "$DAG_LOG"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "PASS: APL afdlength overflow regression test"
    exit 0
else
    echo "FAIL: APL afdlength overflow regression test"
    exit 1
fi

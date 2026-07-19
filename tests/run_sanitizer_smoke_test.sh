#!/bin/sh
# FreeBSD Native Sanitizer Smoke Test for KariDNS
#
# A lightweight version with a different purpose than `run_stress_test.sh`:
#   - Does not perform long-running concurrent execution tests using dnsperf/dig
#   - Intended to verify within a few minutes whether ASan, UBSan, TSan, and the fuzzer are “working properly”
#   - Intended to be run after every commit or as part of CI
#
# Usage: ./tests/run_sanitizer_smoke_test.sh
# Exit code: 0 = All tests PASS, 1 = At least one test failed

set -u

export ASAN_OPTIONS=abort_on_error=1:halt_on_error=1
export UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1
export TSAN_OPTIONS=halt_on_error=1

cd "$(dirname "$0")/.."

CONF_FILE="tests/karidns-test.conf"
CTL_CONF="tests/karictl-test.conf"
ZONE_FILE="tests/zones/example.com.zone"
ZONE_NAME="example.com"

# $INCLUDE Test fixture (Use if present; if not, skip and issue a warning only)
INCLUDE_VALID_ZONE="tests/include_tests/valid_parent.zone"
INCLUDE_CYCLIC_ZONE="tests/include_tests/cyclic_a.zone"
INCLUDE_ERROR_ZONE="tests/include_tests/error_caret.zone"
INCLUDE_MISSING_ZONE="tests/include_tests/missing_file.zone"
INCLUDE_CYCLIC_3_ZONE="tests/include_tests/cyclic_3_a.zone"

# $GENERATE Test fixture
GENERATE_NORMAL="tests/zones/generate_normal.zone"
GENERATE_BAD_RANGE="tests/zones/generate_bad_range.zone"
GENERATE_BAD_WIDTH="tests/zones/generate_bad_width.zone"

FUZZ_SMOKE_SECONDS=60   # Time (in seconds) spent on each fuzz target. Keep it short since this is for routine checks

FAILED=0
log_fail() { echo "  -> FAIL: $1"; FAILED=1; }
log_ok()   { echo "  -> OK: $1"; }

cleanup() {
    [ -n "${KARIDNS_PID:-}" ] && kill -9 "$KARIDNS_PID" >/dev/null 2>&1
    pkill -9 -f karidns-asan >/dev/null 2>&1
    pkill -9 -f karidns-tsan >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

echo "=========================================="
echo "Step 0: Build"
echo "=========================================="
make asan >/dev/null || { log_fail "make asan"; exit 1; }
make tsan >/dev/null || { log_fail "make tsan"; exit 1; }
make tools-asan >/dev/null || { log_fail "make tools-asan (karicheck-asan/dag-asan/karictl-asan)"; exit 1; }
log_ok "build"

echo ""
echo "=========================================="
echo "Step 1: Unit-level ASan/UBSan (dns_wire / dns_zone_parser / dns_config_parser)"
echo "=========================================="
make asan_test > unit_asan.log 2>&1
if [ $? -ne 0 ] || grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" unit_asan.log; then
    log_fail "make asan_test (see unit_asan.log)"
    tail -n 40 unit_asan.log
else
    log_ok "make asan_test"
fi

echo ""
echo "=========================================="
echo "Step 2: karicheck-asan (conf / zone / \$INCLUDE)"
echo "=========================================="
if [ -f "$CONF_FILE" ]; then
    ./karicheck-asan conf "$CONF_FILE" > karicheck_conf_asan.log 2>&1
    if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" karicheck_conf_asan.log; then
        log_fail "karicheck-asan conf (see karicheck_conf_asan.log)"
    else
        log_ok "karicheck-asan conf"
    fi
else
    echo "  -> SKIP: $CONF_FILE not found"
fi

for pair in "$ZONE_FILE:$ZONE_NAME:normal" \
            "$INCLUDE_VALID_ZONE:$ZONE_NAME:\$INCLUDE valid" \
            "$INCLUDE_CYCLIC_ZONE:$ZONE_NAME:\$INCLUDE circular (expect reject, not crash)" \
            "$INCLUDE_CYCLIC_3_ZONE:$ZONE_NAME:\$INCLUDE circular 3-level (expect reject, not crash)" \
            "$INCLUDE_ERROR_ZONE:$ZONE_NAME:\$INCLUDE child syntax error (expect reject, not crash)" \
            "$INCLUDE_MISSING_ZONE:$ZONE_NAME:\$INCLUDE missing file (expect reject, not crash)" \
            "$GENERATE_NORMAL:$ZONE_NAME:\$GENERATE valid" \
            "$GENERATE_BAD_RANGE:$ZONE_NAME:\$GENERATE stop<start (expect reject)" \
            "$GENERATE_BAD_WIDTH:$ZONE_NAME:\$GENERATE width out of bounds (expect reject)"; do
    zfile=$(echo "$pair" | cut -d: -f1)
    zname=$(echo "$pair" | cut -d: -f2)
    label=$(echo "$pair" | cut -d: -f3)
    if [ -f "$zfile" ]; then
        ./karicheck-asan zone "$zname" "$zfile" > karicheck_zone_asan.log 2>&1
        if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" karicheck_zone_asan.log; then
            log_fail "karicheck-asan zone [$label] (see karicheck_zone_asan.log)"
            tail -n 40 karicheck_zone_asan.log
        else
            log_ok "karicheck-asan zone [$label] (ASan clean; pass/reject judged separately by karicheck's own exit code)"
        fi
    else
        echo "  -> SKIP: $label ($zfile not found; add a fixture to cover this path)"
    fi
done

echo ""
echo "=========================================="
echo "Step 3: karidns-asan / karidns-tsan quick start-query-stop"
echo "=========================================="
for variant in asan tsan; do
    bin="./karidns-$variant"
    logf="server_${variant}_smoke.log"
    if [ ! -x "$bin" ]; then
        echo "  -> SKIP: $bin not built"
        continue
    fi
    "$bin" -f "$CONF_FILE" > "$logf" 2>&1 &
    KARIDNS_PID=$!
    sleep 2
    if ! kill -0 "$KARIDNS_PID" 2>/dev/null; then
        log_fail "$variant server crashed on startup (see $logf)"
        cat "$logf"
        continue
    fi
    ./dag-asan "$ZONE_NAME" A "@127.0.0.1" -p 10053 +short >/dev/null 2>&1
    ./karictl-asan -f "$CTL_CONF" reload >/dev/null 2>&1
    ./dag-asan "$ZONE_NAME" AXFR "@127.0.0.1" -p 10053 +tcp +short >/dev/null 2>&1 &
    PID1=$!
    ./dag-asan "$ZONE_NAME" TYPE65280 "@127.0.0.1" -p 10053 +short >/dev/null 2>&1 &
    PID2=$!
    ./dag-asan "network.$ZONE_NAME" APL "@127.0.0.1" -p 10053 +short >/dev/null 2>&1 &
    PID3=$!
    ./dag-asan "office.$ZONE_NAME" LOC "@127.0.0.1" -p 10053 +short >/dev/null 2>&1 &
    PID4=$!
    ./dag-asan "$ZONE_NAME" AXFR "@127.0.0.1" -p 10053 +tcp +short >/dev/null 2>&1 &
    PID5=$!
    wait $PID1 $PID2 $PID3 $PID4 $PID5
    ./karictl-asan -f "$CTL_CONF" stop >/dev/null 2>&1
    sleep 1
    if kill -0 "$KARIDNS_PID" 2>/dev/null; then
        kill -9 "$KARIDNS_PID" 2>/dev/null
    fi
    unset KARIDNS_PID
    if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)|WARNING: ThreadSanitizer" "$logf"; then
        log_fail "$variant quick smoke (Sanitizer error, see $logf)"
        cat "$logf"
    elif grep -q "Failed to read file" "$logf" || grep -q "failed to load" "$logf"; then
        log_fail "$variant quick smoke (Zone reload failed in capability mode, see $logf)"
        cat "$logf"
    else
        log_ok "$variant quick smoke (start / query / reload / AXFR / stop)"
    fi
done

echo ""
echo "=========================================="
echo "Step 4: Fuzzer smoke run (${FUZZ_SMOKE_SECONDS}s per target)"
echo "=========================================="
make fuzz >/dev/null 2>&1
make fuzz_core >/dev/null 2>&1
make fuzz_zone >/dev/null 2>&1
make fuzz_conf >/dev/null 2>&1
make fuzz_tsig >/dev/null 2>&1

for target in fuzz_dns_wire fuzz_dns_server_core fuzz_zone_parser fuzz_conf_parser fuzz_tsig; do
    bin="tests/fuzz/$target"
    corpus="tests/fuzz/corpus_$target"
    if [ ! -x "$bin" ]; then
        echo "  -> SKIP: $bin not built"
        continue
    fi
    mkdir -p "$corpus"
    "$bin" -max_total_time="$FUZZ_SMOKE_SECONDS" -close_fd_mask=3 "$corpus" > "fuzz_${target}.log" 2>&1
    if [ $? -ne 0 ]; then
        log_fail "$target (see fuzz_${target}.log)"
        tail -n 40 "fuzz_${target}.log"
    else
        log_ok "$target (${FUZZ_SMOKE_SECONDS}s, no crash)"
    fi
done

echo ""
echo "=========================================="
if [ "$FAILED" -eq 0 ]; then
    echo "All sanitizer smoke tests passed."
    exit 0
else
    echo "One or more sanitizer smoke tests FAILED. See logs above / *.log files."
    exit 1
fi
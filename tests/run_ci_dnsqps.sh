#!/bin/sh
# CI step of dnsqps on every platform (Linux, macOS, Windows MinGW; FreeBSD builds it with `make all` and runs the suite): build dnsqps from scratch and fail on
# any compiler warning of its sources (-Wall -Wextra is in the Makefile's CFLAGS), then the unit tests plain and under ASan/UBSan, then the CLI and engine
# test (tests/run_dnsqps_test.sh).  --no-unit: Windows, which only builds dnsqps and runs the CLI test.
#
# Usage: sh tests/run_ci_dnsqps.sh [--no-unit]
set -u
cd "$(dirname "$0")/.." || exit 1
UNIT=1
[ "${1:-}" = "--no-unit" ] && UNIT=0
LOG="dnsqps_build.log"

build() { # make target...: the sources of dnsqps are rebuilt, and a warning in them is a failure
    rm -f tools/dnsqps*.o tests/test_dnsqps*.o
    make "$@" > "$LOG" 2>&1 || { cat "$LOG"; echo "FAIL: make $*"; exit 1; }
    cat "$LOG"
    if grep -E '(dnsqps|test_dnsqps)[a-z_]*\.c:[0-9]+(:[0-9]+)?: (warning|error)' "$LOG"; then
        echo "FAIL: make $*: warnings in the dnsqps sources (above)"
        exit 1
    fi
}

build dnsqps
if [ "$UNIT" = "1" ]; then
    build test_dnsqps
    ./test_dnsqps || { echo "FAIL: test_dnsqps"; exit 1; }
    build test_dnsqps-asan
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=0" UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" ./test_dnsqps-asan || { echo "FAIL: test_dnsqps-asan"; exit 1; }
fi
[ -x ./dnsqps.exe ] && export DNSQPS=./dnsqps.exe
sh tests/run_dnsqps_test.sh || exit 1
echo "PASS: dnsqps CI step"

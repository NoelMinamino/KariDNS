#!/bin/sh

# Setup environment for sanitizers
export ASAN_OPTIONS=abort_on_error=1
export TSAN_OPTIONS=halt_on_error=1

# Change to repo root to find binaries
cd "$(dirname "$0")/.."

CONF_FILE="karidns.conf.sample"

if [ ! -f "$CONF_FILE" ]; then
    echo "Error: Configuration file $CONF_FILE not found."
    exit 1
fi

echo "=========================================="
echo "Phase 1: TSan Data Race Test"
echo "=========================================="

if [ ! -f "./karidns-tsan" ]; then
    echo "Error: karidns-tsan not found. Please run 'make tsan' first."
    exit 1
fi

# 1. Start TSan binary in foreground mode as background job
./karidns-tsan -f "$CONF_FILE" 2> tsan_error.log &
TSAN_PID=$!

# Wait for server to start
sleep 2

# 2. Run dnsperf
dnsperf -s 127.0.0.1 -p 10053 -d tests/test_queries.txt -l 60 &
DNSPERF_PID=$!

# 3. Reload in a loop
echo "Sending reload commands for 60 seconds..."
while kill -0 $DNSPERF_PID 2>/dev/null; do
    ./karictl reload > /dev/null 2>&1
    sleep 1
done

# 4. Check for errors
echo "Stopping TSan process..."
kill $TSAN_PID
wait $TSAN_PID 2>/dev/null

if grep -q "WARNING: ThreadSanitizer: data race" tsan_error.log; then
    echo "TSan Test FAILED: Data race detected."
    cat tsan_error.log
    exit 1
else
    echo "TSan Test PASSED."
fi

echo ""
echo "=========================================="
echo "Phase 2: ASan Memory Corruption Test"
echo "=========================================="

if [ ! -f "./karidns-asan" ]; then
    echo "Error: karidns-asan not found. Please run 'make asan' first."
    exit 1
fi

# 1. Start ASan binary in foreground mode as background job
./karidns-asan -f "$CONF_FILE" 2> asan_error.log &
ASAN_PID=$!

# Wait for server to start
sleep 2

# 2. Run dag with --break options
echo "Running dag --break compression-loop"
./dag example.com A @127.0.0.1 -p 10053 --break compression-loop

echo "Running dag --break label-too-long"
./dag example.com A @127.0.0.1 -p 10053 --break label-too-long

echo "Running dag --break tcp-length-overclaim"
./dag example.com A @127.0.0.1 -p 10053 --tcp --break tcp-length-overclaim

# Wait briefly for queries to process
sleep 1

# 3. Check survival and ASan errors
if ! kill -0 $ASAN_PID 2>/dev/null; then
    echo "ASan Test FAILED: Process crashed."
    cat asan_error.log
    exit 1
fi

echo "Stopping ASan process..."
kill $ASAN_PID
wait $ASAN_PID 2>/dev/null

if grep -q "ERROR: AddressSanitizer" asan_error.log; then
    echo "ASan Test FAILED: Memory corruption detected."
    cat asan_error.log
    exit 1
else
    echo "ASan Test PASSED."
fi

echo "All stress tests passed successfully."

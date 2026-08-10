#!/bin/sh
set -e

make karidns-asan dag-asan

./karidns-asan -f tests/karidns-test.conf > server_asan.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 1

# Query for sub.glue.test A
# Without EDNS payload size, UDP size defaults to 512.
# The NS records will fit, but the 40 AAAA glue records will not fit in 512 bytes.
# The server should truncate the additional section and set TC=1.
output=$(./dag-asan sub.glue.test A @127.0.0.1 -p 10053 2>&1)

if ! echo "$output" | grep -q "flags:.*tc.*;"; then
    echo "[FAIL] TC=1 flag was NOT set!"
    echo "Output:"
    echo "$output"
    exit 1
fi

echo "[OK] TC=1 flag was successfully set on truncated glue response."
exit 0

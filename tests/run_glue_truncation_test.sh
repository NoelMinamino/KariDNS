#!/bin/sh
set -e
. "$(dirname "$0")/lib_proc.sh"

[ -x karidns-asan ] && [ -x dag-asan ] || make karidns-asan dag-asan

# own port and control socket: the shared tests/karidns-test.conf binds 10053 and the default control socket
PORT=$(kari_port 0 10053)
TMP_DIR="/tmp/glue_truncation_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
kari_test_conf tests/karidns-test.conf "$TMP_DIR/karidns.conf" "$PORT" "$TMP_DIR/ctl.sock"

./karidns-asan -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/server_asan.log" 2>&1 &
SERVER_PID=$!
cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    kari_kill_tree "${SERVER_PID:-}"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM
kari_wait_answer ./dag-asan "$PORT" example.com. || true   # the query below reports a server that did not start

# Query for sub.glue.test A
# Without EDNS payload size, UDP size defaults to 512.
# The NS records will fit, but the 40 AAAA glue records will not fit in 512 bytes.
# The server should truncate the additional section and set TC=1.
# +ignore prevents automatic TCP fallback so we can verify the UDP TC bit.
output=$(./dag-asan sub.glue.test A @127.0.0.1 -p "$PORT" +ignore 2>&1)

if ! echo "$output" | grep -q "flags:.*tc.*;"; then
    echo "[FAIL] TC=1 flag was NOT set!"
    echo "Output:"
    echo "$output"
    exit 1
fi

echo "[OK] TC=1 flag was successfully set on truncated glue response."
exit 0

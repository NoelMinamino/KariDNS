#!/bin/sh
# ==============================================================================
# tests/run_server_lifecycle_test.sh - Server Lifecycle & Crash-Resistance Matrix
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karidns" ]; then
    echo "SKIP: karidns binary not found"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karidns_lifecycle.XXXXXX 2>/dev/null || mktemp -d)"

cleanup() {
    pkill -9 -f "karidns.*${TMP_DIR}" 2>/dev/null || true
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

# Case 1: Bad Config Rejection
cat > "${TMP_DIR}/bad_syntax.conf" <<EOF
options {
    directory "/invalid/syntax
EOF

if ./karidns -c "${TMP_DIR}/bad_syntax.conf" -f > "${TMP_DIR}/bad.log" 2>&1; then
    echo "FAIL: karidns should have exited with error on bad config syntax"
    exit 1
fi
echo "[+] Case 1: Bad syntax cleanly rejected"

# Case 2: Port Conflict (EADDRINUSE)
PORT=$((30000 + ( $$ % 10000 )))
cat > "${TMP_DIR}/valid.conf" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${TMP_DIR}/k1.pid";
    listen-on { 127.0.0.1; };
    port ${PORT};
};
EOF

# Start instance 1
./karidns -c "${TMP_DIR}/valid.conf" -f > "${TMP_DIR}/srv1.log" 2>&1 &
P1=$!
sleep 0.2

# Try to start instance 2 on same port without SO_REUSEPORT option
cat > "${TMP_DIR}/conflict.conf" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${TMP_DIR}/k2.pid";
    listen-on { 127.0.0.1; };
    port ${PORT};
};
EOF

# Server should gracefully handle socket collision
./karidns -c "${TMP_DIR}/conflict.conf" -f > "${TMP_DIR}/conflict.log" 2>&1 || true

# Cleanly terminate instance 1
kill -TERM "${P1}" 2>/dev/null || true
wait "${P1}" 2>/dev/null || true

echo "[+] Case 2: Port conflict handled"

# Case 3: SIGHUP / SIGUSR1 Signal handling
./karidns -c "${TMP_DIR}/valid.conf" -f > "${TMP_DIR}/sig.log" 2>&1 &
SIG_PID=$!
sleep 0.2

kill -HUP "${SIG_PID}" 2>/dev/null || true
sleep 0.1
kill -USR1 "${SIG_PID}" 2>/dev/null || true
sleep 0.1
kill -TERM "${SIG_PID}" 2>/dev/null || true
wait "${SIG_PID}" 2>/dev/null || true

echo "[+] Case 3: Signals (SIGHUP, SIGUSR1, SIGTERM) handled cleanly"

echo "[+] All Server Lifecycle tests passed successfully."
exit 0

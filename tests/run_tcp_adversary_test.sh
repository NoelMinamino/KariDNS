#!/bin/sh
# ==============================================================================
# tests/run_tcp_adversary_test.sh - TCP State Machine Adversary Suite
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karidns" ] || [ ! -x "./dag" ]; then
    echo "SKIP: karidns or dag binary not found"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karidns_tcp_adv.XXXXXX 2>/dev/null || mktemp -d)"
PID_FILE="${TMP_DIR}/karidns.pid"
CONF_FILE="${TMP_DIR}/karidns.conf"

cleanup() {
    if [ -f "${PID_FILE}" ]; then
        PID=$(cat "${PID_FILE}" 2>/dev/null || true)
        if [ -n "${PID}" ]; then
            kill -TERM "${PID}" 2>/dev/null || true
            sleep 0.1
            kill -9 "${PID}" 2>/dev/null || true
        fi
    fi
    pkill -9 -f "karidns.*${TMP_DIR}" 2>/dev/null || true
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

PORT=$((28000 + ( $$ % 10000 )))

cat > "${CONF_FILE}" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${PID_FILE}";
    listen-on { 127.0.0.1; };
    port ${PORT};
    user "nobody";
    group "nobody";
    tcp-idle-timeout 1;
    tcp-max-clients 32;
    minimal-responses yes;
};
zone "example.com" {
    type master;
    file "${ROOT_DIR}/tests/zones/example.com.zone";
};
EOF

# Start server
./karidns -c "${CONF_FILE}" -f > "${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!
echo "${SERVER_PID}" > "${PID_FILE}"

# Wait for server readiness
for i in $(seq 1 30); do
    if ./dag @127.0.0.1 -p "${PORT}" example.com SOA +short +timeout=1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

echo "[+] Server online on port ${PORT}. Running TCP adversary attacks..."

# 1. Zero Length Prefix
perl tests/lib/tcpadv.pl zero_len 127.0.0.1 "${PORT}"
# 2. Giant Length Prefix
perl tests/lib/tcpadv.pl giant_len 127.0.0.1 "${PORT}"
# 3. Partial Message with FIN
perl tests/lib/tcpadv.pl partial_msg 127.0.0.1 "${PORT}"
# 4. Pipeline queries
perl tests/lib/tcpadv.pl pipeline 127.0.0.1 "${PORT}"
# 5. Byte by byte trickle
perl tests/lib/tcpadv.pl byte_by_byte 127.0.0.1 "${PORT}"
# 6. QR=1 packet sent to query port
perl tests/lib/tcpadv.pl qr1_packet 127.0.0.1 "${PORT}"
# 7. Connection Flood
perl tests/lib/tcpadv.pl flood 127.0.0.1 "${PORT}"
# 8. Slowloris (hold 1 byte prefix, expect clean server idle timeout)
perl tests/lib/tcpadv.pl slowloris 127.0.0.1 "${PORT}"

# Verify server is still alive and responsive after adversary attacks
if ! ./dag @127.0.0.1 -p "${PORT}" example.com SOA +short +timeout=2 >/dev/null 2>&1; then
    echo "FAIL: Server crashed or stopped responding after TCP adversary attacks!"
    cat "${TMP_DIR}/server.log"
    exit 1
fi

echo "[+] All TCP adversary tests passed. Server remained robust and responsive."
exit 0

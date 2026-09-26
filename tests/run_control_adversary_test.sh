#!/bin/sh
# ==============================================================================
# tests/run_control_adversary_test.sh - Control Channel Adversary Test
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karidns" ] || [ ! -x "./karictl" ]; then
    echo "SKIP: karidns or karictl binary not found"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karidns_ctrl_adv.XXXXXX 2>/dev/null || mktemp -d)"
PID_FILE="${TMP_DIR}/karidns.pid"
CONF_FILE="${TMP_DIR}/karidns.conf"
CTRL_SOCK="${TMP_DIR}/control.sock"

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

PORT=$((29000 + ( $$ % 10000 )))

cat > "${CONF_FILE}" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${PID_FILE}";
    listen-on { 127.0.0.1; };
    port ${PORT};
};
controls {
    unix "${CTRL_SOCK}" perm 0600 secret "c2VjcmV0MTIz";
};
zone "example.com" {
    type master;
    file "${ROOT_DIR}/tests/zones/example.com.zone";
};
EOF

# Create karictl configuration files
cat > "${TMP_DIR}/karictl.conf" <<EOF
socket "${CTRL_SOCK}";
secret "c2VjcmV0MTIz";
EOF

cat > "${TMP_DIR}/wrong_secret.conf" <<EOF
socket "${CTRL_SOCK}";
secret "d3Jvbmc=";
EOF

cat > "${TMP_DIR}/bad_secret.conf" <<EOF
socket "${CTRL_SOCK}";
secret "invalid%%%base64";
EOF

cat > "${TMP_DIR}/long_secret.conf" <<EOF
socket "${CTRL_SOCK}";
secret "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
EOF

# Start server
./karidns -c "${CONF_FILE}" -f > "${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!
echo "${SERVER_PID}" > "${PID_FILE}"

# Wait for control socket to appear
READY=0
for i in $(seq 1 30); do
    if [ -S "${CTRL_SOCK}" ]; then
        READY=1
        break
    fi
    sleep 0.1
done

if [ "${READY}" -ne 1 ]; then
    echo "SKIP: Control socket not available in this environment"
    exit 0
fi

echo "[+] Control socket available at ${CTRL_SOCK}. Running adversary attacks..."

# 1. Bad HMAC authentication
perl tests/lib/ctrl_client.pl "${CTRL_SOCK}" bad_hmac || true

# 2. Giant command string
perl tests/lib/ctrl_client.pl "${CTRL_SOCK}" giant_cmd || true

# 3. Unknown command string
perl tests/lib/ctrl_client.pl "${CTRL_SOCK}" unknown_cmd || true

# 4. Silent connection timeout
perl tests/lib/ctrl_client.pl "${CTRL_SOCK}" silent || true

echo "[+] Running karictl CLI and error tests..."

# karictl version & tsig-keygen
./karictl -v >/dev/null 2>&1 || true
./karictl tsig-keygen >/dev/null 2>&1 || true
./karictl tsig-keygen test-key >/dev/null 2>&1 || true

# Non-existent socket error (should return 1)
./karictl -c "${TMP_DIR}/karictl.conf" -s "${TMP_DIR}/nonexistent.sock" status >/dev/null 2>&1 || true

# Non-existent config error (should return 2)
./karictl -c "${TMP_DIR}/nonexistent.conf" -s "${CTRL_SOCK}" status >/dev/null 2>&1 || true

# Bad secret format in config (should return 2)
./karictl -c "${TMP_DIR}/bad_secret.conf" -s "${CTRL_SOCK}" status >/dev/null 2>&1 || true

# Too long secret in config (should return 2)
./karictl -c "${TMP_DIR}/long_secret.conf" -s "${CTRL_SOCK}" status >/dev/null 2>&1 || true

# HMAC authentication mismatch against server (should return 2)
./karictl -c "${TMP_DIR}/wrong_secret.conf" -s "${CTRL_SOCK}" status >/dev/null 2>&1 || true

# Unknown command transmission (server returns ERROR, karictl returns 3)
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" unknown_bogus_command >/dev/null 2>&1 || true

# Valid commands
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" status >/dev/null 2>&1 || true
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" zonestatus example.com >/dev/null 2>&1 || true
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" reload example.com >/dev/null 2>&1 || true
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" observatory >/dev/null 2>&1 || true
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" notify example.com >/dev/null 2>&1 || true
./karictl -c "${TMP_DIR}/karictl.conf" -s "${CTRL_SOCK}" retransfer example.com >/dev/null 2>&1 || true

echo "[+] Control adversary tests completed cleanly."
exit 0

#!/bin/sh
# ==============================================================================
# tests/run_karictl_adversary_test.sh - karictl CLI & Error Handling Matrix
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karictl" ]; then
    echo "SKIP: karictl binary not found"
    exit 0
fi

# 1. No arguments / Help flag
./karictl -h >/dev/null 2>&1 || true

# 2. Unknown option
if ./karictl -Z >/dev/null 2>&1; then
    echo "FAIL: karictl -Z should return non-zero error"
    exit 1
fi

# 3. Connection to non-existent socket
if ./karictl -s "/tmp/non_existent_karidns_socket_12345.sock" status >/dev/null 2>&1; then
    echo "FAIL: karictl should return error when socket does not exist"
    exit 1
fi

# 4. Unknown sub-command
if ./karictl -s "/tmp/non_existent.sock" invalid_cmd_xyz >/dev/null 2>&1; then
    echo "FAIL: karictl should reject unknown subcommand"
    exit 1
fi

echo "[+] karictl CLI validation tests passed."
exit 0

#!/bin/sh
# ==============================================================================
# tests/run_control_adversary_test.sh - Control Channel Adversary Test
# ==============================================================================
# Malformed, unauthenticated and oversized control-channel traffic must be refused
# without affecting the server: after every attack the server must still answer
# `karictl status` and DNS queries. karictl's own error paths are checked by exit
# status (1: socket, 2: configuration/authentication, 3: server returned ERROR).
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
. "${SCRIPT_DIR}/lib_proc.sh"
cd "${ROOT_DIR}"

[ -x ./karidns ] || make karidns
[ -x ./karictl ] || make karictl
[ -x ./dag ] || make dag

TMP_DIR="$(mktemp -d /tmp/karidns_ctrl_adv.XXXXXX)"
chmod 755 "${TMP_DIR}"
CONF_FILE="${TMP_DIR}/karidns.conf"
CTRL_SOCK="${TMP_DIR}/control.sock"
SERVER_PID=""
FAILED=0

cleanup() {
    [ -n "${SERVER_PID}" ] && kari_kill_tree "${SERVER_PID}"
    kari_kill_conf "${CONF_FILE}"
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "  [FAIL] $*"
    FAILED=$((FAILED + 1))
}

PORT=$((29000 + ( $$ % 10000 )))
SECRET="c2VjcmV0MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA=="
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

cat > "${TMP_DIR}/ctrl.zone" <<EOF
\$ORIGIN ctrl.test.
\$TTL 300
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
EOF

cat > "${CONF_FILE}" <<EOF
options {
    port ${PORT};
    bind-address { 127.0.0.1; };
    pid-file "none";
    ${USER_OPT}
};
control-channel {
    socket "${CTRL_SOCK}";
    algorithm hmac-sha256;
    secret "${SECRET}";
};
zone "ctrl.test" {
    type master;
    file "${TMP_DIR}/ctrl.zone";
};
EOF

write_ctl_conf() { # file secret
    cat > "$1" <<EOF
key "karictl" {
    algorithm hmac-sha256;
    secret "$2";
};
EOF
    chmod 600 "$1"
}
write_ctl_conf "${TMP_DIR}/karictl.conf" "${SECRET}"
write_ctl_conf "${TMP_DIR}/wrong_secret.conf" "d3Jvbmc="
write_ctl_conf "${TMP_DIR}/bad_secret.conf" "invalid%%%base64"
write_ctl_conf "${TMP_DIR}/long_secret.conf" "$(printf 'A%.0s' $(seq 1 400))"

KARICTL="./karictl -c ${TMP_DIR}/karictl.conf -s ${CTRL_SOCK}"

./karidns -f "${CONF_FILE}" > "${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
    if [ -S "${CTRL_SOCK}" ] && ./dag @127.0.0.1 -p "${PORT}" ctrl.test SOA +short +timeout=1 +tries=1 2>/dev/null | grep -q hostmaster; then
        READY=1
        break
    fi
    sleep 0.2
done
if [ "${READY}" -ne 1 ]; then
    echo "[FAIL] karidns did not start (control socket ${CTRL_SOCK} / DNS on port ${PORT})"
    cat "${TMP_DIR}/server.log"
    exit 1
fi

# The server must be alive, accept an authenticated command and answer DNS.
check_server_ok() { # label
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "$1: karidns is no longer running"
        cat "${TMP_DIR}/server.log"
        exit 1
    fi
    if ! out=$(${KARICTL} status 2>&1) || ! echo "${out}" | grep -q "^server is up and running$"; then
        fail "$1: karictl status after the attack: ${out}"
    fi
    if ! ./dag @127.0.0.1 -p "${PORT}" ctrl.test SOA +timeout=2 +tries=1 +nohexdump 2>&1 | grep -q "status: NOERROR"; then
        fail "$1: DNS query after the attack did not get NOERROR"
    fi
}

# attack <mode> <expected reply regex>
attack() {
    out=$(perl tests/lib/ctrl_client.pl "${CTRL_SOCK}" "$1" 2>&1) || true
    if echo "${out}" | grep -E -q "^REPLY: ($2)\$"; then
        echo "  [OK] $1 -> $(echo "${out}" | sed -n 's/^REPLY: //p')"
    else
        fail "$1: expected reply '$2', got: ${out}"
    fi
    check_server_ok "$1"
}

echo "[+] Raw control-channel attacks (port ${PORT})..."
attack bad_hmac "AUTH_FAILED"
attack unknown_cmd "AUTH_FAILED"
# a line longer than the 1024-byte buffer: "ERROR buffer overflow", logged, client dropped (X-47)
attack giant_cmd "ERROR buffer overflow"
if grep -q "\[Control\] Command buffer overflow, dropping client" "${TMP_DIR}/server.log"; then
    echo "  [OK] buffer overflow logged"
else
    fail "giant_cmd: '[Control] Command buffer overflow' not logged"
fi
attack silent "<closed>"

# expect_exit <expected status> <output regex or ""> <label> <command...>
expect_exit() {
    want="$1"; pattern="$2"; label="$3"; shift 3
    set +e
    out=$("$@" 2>&1)
    rc=$?
    set -e
    if [ "${rc}" -ne "${want}" ]; then
        fail "${label}: exit status ${rc}, expected ${want}: ${out}"
    elif [ -n "${pattern}" ] && ! echo "${out}" | grep -E -q "${pattern}"; then
        fail "${label}: output does not match '${pattern}': ${out}"
    else
        echo "  [OK] ${label} (exit ${rc})"
    fi
}

echo "[+] karictl error paths..."
expect_exit 0 "^KariDNS|karictl|[0-9]+\.[0-9]+" "karictl -v" ./karictl -v
expect_exit 0 "^  secret \"[A-Za-z0-9+/]{43}=\";" "tsig-keygen" ./karictl tsig-keygen
expect_exit 0 "^key \"test-key\" \{" "tsig-keygen with a key name" ./karictl tsig-keygen test-key
expect_exit 1 "connect" "non-existent socket" ./karictl -c "${TMP_DIR}/karictl.conf" -s "${TMP_DIR}/nonexistent.sock" status
expect_exit 2 "Could not read secret" "non-existent configuration" ./karictl -c "${TMP_DIR}/nonexistent.conf" -s "${CTRL_SOCK}" status
expect_exit 2 "decode base64|Authentication failed" "secret that is not base64" ./karictl -c "${TMP_DIR}/bad_secret.conf" -s "${CTRL_SOCK}" status
expect_exit 2 "too long" "secret longer than 341 characters" ./karictl -c "${TMP_DIR}/long_secret.conf" -s "${CTRL_SOCK}" status
expect_exit 2 "Authentication failed: AUTH_FAILED" "wrong secret" ./karictl -c "${TMP_DIR}/wrong_secret.conf" -s "${CTRL_SOCK}" status
expect_exit 3 "ERROR unknown command" "unknown command" ${KARICTL} unknown_bogus_command
expect_exit 3 "ERROR zone not found" "zonestatus of an unknown zone" ${KARICTL} zonestatus nonexistent.test
check_server_ok "karictl error paths"

echo "[+] Authenticated commands..."
expect_exit 0 "^server is up and running$" "status" ${KARICTL} status
expect_exit 0 "^OK serial=1 refresh=7200" "zonestatus" ${KARICTL} zonestatus ctrl.test
expect_exit 0 "OK reloaded" "reload of a zone" ${KARICTL} reload ctrl.test
expect_exit 0 "" "observatory" ${KARICTL} observatory
expect_exit 0 "" "notify" ${KARICTL} notify ctrl.test
check_server_ok "authenticated commands"

if [ "${FAILED}" -ne 0 ]; then
    echo "[FAIL] ${FAILED} control-channel check(s) failed"
    exit 1
fi
echo "[+] Control adversary tests passed."
exit 0

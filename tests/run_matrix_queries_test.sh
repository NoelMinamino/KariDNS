#!/bin/sh
# ==============================================================================
# tests/run_matrix_queries_test.sh - Table-driven Matrix Query Engine Verification
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karidns" ] || [ ! -x "./dag" ]; then
    echo "SKIP: karidns or dag binary not found"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karidns_matrix_test.XXXXXX 2>/dev/null || mktemp -d)"
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

# Select random dynamic port
PORT=$((25000 + ( $$ % 15000 )))

cat > "${CONF_FILE}" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${PID_FILE}";
    listen-on { 127.0.0.1; };
    port ${PORT};
    user "nobody";
    group "nobody";
    minimal-responses yes;
};

zone "wildcard.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/wildcard.zone";
};

zone "dname.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/dname.zone";
};

zone "deleg.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/deleg.zone";
};

zone "nsec.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/nsec_signed.zone";
};

zone "chain.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/cname_chain.zone";
};

zone "alltypes.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/all_types.zone";
};
EOF

# Start server
./karidns -c "${CONF_FILE}" -f > "${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!
echo "${SERVER_PID}" > "${PID_FILE}"

# Poll until ready
READY=0
for i in $(seq 1 30); do
    if ./dag @127.0.0.1 -p "${PORT}" wildcard.test SOA +short +timeout=1 >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.1
done

if [ "${READY}" -ne 1 ]; then
    echo "FAIL: karidns failed to start within 3s on port ${PORT}"
    cat "${TMP_DIR}/server.log"
    exit 1
fi

echo "[+] Server started on port ${PORT}. Executing table-driven query matrix..."

# Read and execute TSV rows
PASSED_COUNT=0
TOTAL_COUNT=0

while IFS='	' read -r _zone _qname _qtype _flags _expect_rcode _expect_ans _expect_auth _rfc_ref; do
    # Skip comments and empty lines
    case "${_zone}" in
        \#*|"") continue ;;
    esac

    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    
    # Run dag query with yaml format
    OUT=$(./dag @127.0.0.1 -p "${PORT}" "${_qname}" "${_qtype}" ${_flags} +yaml +timeout=2 2>&1 || true)
    
    # Check RCODE / status
    if ! echo "${OUT}" | grep -qiE "(status|rcode): *${_expect_rcode}"; then
        echo "[-] FAIL: Matrix test ${_qname} ${_qtype} expected RCODE ${_expect_rcode} (${_rfc_ref})"
        echo "${OUT}"
        exit 1
    fi

    # Check Answer count if specified and not '-'
    if [ "${_expect_ans}" != "-" ]; then
        if ! echo "${OUT}" | grep -qiE "(ANSWER|ancount): *${_expect_ans}"; then
            echo "[-] FAIL: Matrix test ${_qname} ${_qtype} expected ANCOUNT ${_expect_ans} (${_rfc_ref})"
            echo "${OUT}"
            exit 1
        fi
    fi

    # Check Authority section type if specified and not '-'
    if [ "${_expect_auth}" != "-" ]; then
        if ! echo "${OUT}" | grep -qiE "IN ${_expect_auth}"; then
            echo "[-] FAIL: Matrix test ${_qname} ${_qtype} expected Authority type ${_expect_auth} (${_rfc_ref})"
            echo "${OUT}"
            exit 1
        fi
    fi

    PASSED_COUNT=$((PASSED_COUNT + 1))
done < "${ROOT_DIR}/tests/matrix/queries.tsv"

echo "[+] Matrix query engine verification completed: ${PASSED_COUNT}/${TOTAL_COUNT} tests passed successfully."
exit 0

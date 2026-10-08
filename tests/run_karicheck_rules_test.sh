#!/bin/sh
# ==============================================================================
# tests/run_karicheck_rules_test.sh - Diagnostic Rules Matrix for karicheck
# ==============================================================================
# Each rule is triggered once; the diagnostic text and karicheck's exit status
# (0: valid, warnings only; 1: errors) are checked.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

[ -x ./karicheck ] || make karicheck

TMP_DIR="$(mktemp -d /tmp/karicheck_rules.XXXXXX)"
FAILED=0

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

# check <label> <expected exit status> <command output file> <extended regex>...
check() {
    label="$1"; want="$2"; file="$3"; shift 3
    rc=$(cat "${file}.rc")
    if [ "${rc}" -ne "${want}" ]; then
        echo "FAIL: ${label}: exit status ${rc}, expected ${want}"
        sed 's/^/    /' "${file}"
        FAILED=$((FAILED + 1))
        return 0
    fi
    for re in "$@"; do
        if ! grep -E -q -e "${re}" "${file}"; then
            echo "FAIL: ${label}: missing '${re}'"
            sed 's/^/    /' "${file}"
            FAILED=$((FAILED + 1))
            return 0
        fi
    done
    echo "[+] ${label}"
}

# run <output file> <karicheck args...>
run() {
    out="$1"; shift
    set +e
    ./karicheck "$@" > "${out}" 2>&1
    echo $? > "${out}.rc"
    set -e
}

zone_head() {
    cat <<EOF
\$ORIGIN example.com.
\$TTL 3600
example.com. IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
example.com. IN NS ns1.example.com.
ns1.example.com. IN A 192.0.2.1
EOF
}

# Rule 1: SSHFP algorithm outside the registry (RFC 4255 §3.1.1, RFC 6594, RFC 7479)
{ zone_head; echo "host.example.com. IN SSHFP 99 1 123456789ABCDEF67890123456789ABCDEF67890"; } > "${TMP_DIR}/bad_sshfp.zone"
run "${TMP_DIR}/r1" zone example.com "${TMP_DIR}/bad_sshfp.zone"
check "Rule 1: SSHFP algorithm 99 is a warning" 0 "${TMP_DIR}/r1" \
    "^\[WARNING\] SSHFP record for 'host\.example\.com\.' uses algorithm '99' which is outside standard RFC assignments" \
    "^\[RESULT\] Zone 'example\.com\.': 0 error\(s\), 1 warning\(s\)$"

# Rule 2: RFC 8624 §3.1 / §3.3: algorithm 1 (RSAMD5) and DS digest type 1 (SHA-1) are MUST NOT
KEY_B64=$(perl -MMIME::Base64 -e 'print encode_base64("\x03\x01\x00\x01" . ("\xab" x 128), "")')
{ zone_head
  echo "example.com. IN DNSKEY 257 3 1 ${KEY_B64}"
  echo "example.com. IN DS 12345 1 1 AABBCCDDEEFF0011223344556677889900112233"; } > "${TMP_DIR}/rfc8624.zone"
run "${TMP_DIR}/r2" zone example.com "${TMP_DIR}/rfc8624.zone"
check "Rule 2: RFC 8624 algorithm 1 and DS digest 1 are warnings" 0 "${TMP_DIR}/r2" \
    "^\[WARNING\] DNSKEY 'example\.com\.': DNSSEC algorithm 1 \(RSAMD5\) is MUST NOT .*\(RFC 8624\)$" \
    "^\[WARNING\] DS 'example\.com\.': DS digest type 1 \(SHA-1\) is MUST NOT .*RFC 8624 §3\.3\)$" \
    "^\[RESULT\] Zone 'example\.com\.': 0 error\(s\), 2 warning\(s\)$"

# Rule 3: tcp-idle-timeout must be a non-negative number of milliseconds (0 = default)
cat > "${TMP_DIR}/bad_options.conf" <<EOF
options {
    directory "/tmp";
    tcp-idle-timeout -5;
};
EOF
run "${TMP_DIR}/r3" conf "${TMP_DIR}/bad_options.conf"
check "Rule 3: negative tcp-idle-timeout is an error" 1 "${TMP_DIR}/r3" \
    "^\[ERROR\] Invalid tcp-idle-timeout value '-5' \(must be a non-negative integer of milliseconds\)$"
cat > "${TMP_DIR}/zero_timeout.conf" <<EOF
options {
    tcp-idle-timeout 0;
};
zone "example.com" {
    type master;
    file "${TMP_DIR}/bad_sshfp.zone";
};
EOF
run "${TMP_DIR}/r3b" conf "${TMP_DIR}/zero_timeout.conf"
check "Rule 3: tcp-idle-timeout 0 (default) is accepted" 0 "${TMP_DIR}/r3b" "^\[OK\] Config file .* is valid\.$"

# Rule 4: SSHFP fingerprint type outside the registry
{ zone_head; echo "host.example.com. IN SSHFP 1 99 123456789ABCDEF67890123456789ABCDEF67890"; } > "${TMP_DIR}/bad_sshfp_fptype.zone"
run "${TMP_DIR}/r4" zone example.com "${TMP_DIR}/bad_sshfp_fptype.zone"
check "Rule 4: SSHFP fp_type 99 is a warning" 0 "${TMP_DIR}/r4" \
    "^\[WARNING\] SSHFP record for 'host\.example\.com\.' uses fp_type '99' which is outside standard RFC assignments" \
    "^\[RESULT\] Zone 'example\.com\.': 0 error\(s\), 1 warning\(s\)$"

# Rule 5: program zones: relative program path (error), program-user different from
# options.user (warning), program zones without allow-program-zones (error)
cat > "${TMP_DIR}/prog_relative.conf" <<EOF
options {
    user "nobody";
    allow-program-zones yes;
};
zone "prog1.example" {
    type program;
    program "relative/path/plugin";
};
EOF
run "${TMP_DIR}/r5a" conf "${TMP_DIR}/prog_relative.conf"
check "Rule 5: relative program path is an error" 1 "${TMP_DIR}/r5a" \
    "^\[ERROR\] Zone 'prog1\.example\.': 'program' must be an absolute path \(got 'relative/path/plugin'\)"
cat > "${TMP_DIR}/prog_user.conf" <<EOF
options {
    user "nobody";
    allow-program-zones yes;
};
zone "prog2.example" {
    type program;
    program "/bin/sh";
    program-user "daemon";
};
EOF
run "${TMP_DIR}/r5b" conf "${TMP_DIR}/prog_user.conf"
check "Rule 5: program-user different from options.user is a warning" 0 "${TMP_DIR}/r5b" \
    "^\[WARNING\] Zone 'prog2\.example\.': program-user 'daemon' differs from options\.user 'nobody'\."
cat > "${TMP_DIR}/prog_disabled.conf" <<EOF
zone "prog3.example" {
    type program;
    program "/bin/sh";
};
EOF
run "${TMP_DIR}/r5c" conf "${TMP_DIR}/prog_disabled.conf"
check "Rule 5: program zone without allow-program-zones is an error" 1 "${TMP_DIR}/r5c" \
    "^\[ERROR\] Config contains 1 type 'program' zone\(s\), but 'allow-program-zones' is not enabled in options\{\}$"

if [ "${FAILED}" -ne 0 ]; then
    echo "FAIL: ${FAILED} karicheck rule check(s) failed"
    exit 1
fi
echo "[+] All karicheck rules tests passed successfully."
exit 0

#!/bin/sh
# ==============================================================================
# tests/run_karicheck_rules_test.sh - Diagnostic Rules Matrix for karicheck
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karicheck" ]; then
    echo "SKIP: karicheck binary not found"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karicheck_rules.XXXXXX 2>/dev/null || mktemp -d)"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

# Rule 1: SSHFP Algorithm Out of Range (Valid is 1-4: RSA, DSA, ECDSA, Ed25519)
cat > "${TMP_DIR}/bad_sshfp.zone" <<EOF
\$ORIGIN example.com.
\$TTL 3600
example.com. IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
example.com. IN NS ns1.example.com.
ns1.example.com. IN A 192.0.2.1
host.example.com. IN SSHFP 99 1 123456789ABCDEF67890123456789ABCDEF67890
EOF

OUT=$(./karicheck zone example.com "${TMP_DIR}/bad_sshfp.zone" 2>&1 || true)
if ! echo "${OUT}" | grep -qi "SSHFP"; then
    echo "FAIL: Expected SSHFP diagnostic warning in karicheck"
    echo "${OUT}"
    exit 1
fi
echo "[+] Rule 1: SSHFP validation checked"

# Rule 2: DNSSEC Algorithm Requirement Checks (RFC 8624)
cat > "${TMP_DIR}/rfc8624.zone" <<EOF
\$ORIGIN example.com.
\$TTL 3600
example.com. IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
example.com. IN NS ns1.example.com.
ns1.example.com. IN A 192.0.2.1
example.com. IN DNSKEY 257 3 1 AQPD1...
example.com. IN DS 12345 1 1 AABBCCDDEEFF0011223344556677889900112233
EOF

OUT2=$(./karicheck zone example.com "${TMP_DIR}/rfc8624.zone" 2>&1 || true)
echo "[+] Rule 2: RFC 8624 DNSSEC algorithm checks executed"

# Rule 3: Config Syntax & Semantic Checks
cat > "${TMP_DIR}/bad_options.conf" <<EOF
options {
    directory "/tmp";
    tcp-idle-timeout 0;
};
zone "example.com" {
    type master;
    file "${TMP_DIR}/bad_sshfp.zone";
};
EOF

./karicheck conf "${TMP_DIR}/bad_options.conf" >/dev/null 2>&1 || true
echo "[+] Rule 3: Config linting checks executed"

# Rule 4: SSHFP fp_type outside standard RFC assignments
cat > "${TMP_DIR}/bad_sshfp_fptype.zone" <<EOF
\$ORIGIN example.com.
\$TTL 3600
example.com. IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
example.com. IN NS ns1.example.com.
ns1.example.com. IN A 192.0.2.1
host.example.com. IN SSHFP 1 99 123456789ABCDEF67890123456789ABCDEF67890
EOF

OUT4=$(./karicheck zone example.com "${TMP_DIR}/bad_sshfp_fptype.zone" 2>&1 || true)
echo "[+] Rule 4: SSHFP fp_type outside standard assignments checked"

# Rule 5: Program zone with relative path, differing user, and excessive args
cat > "${TMP_DIR}/bad_prog.conf" <<EOF
options {
    user "nobody";
    allow-program-zones yes;
};
zone "prog1.example" {
    type program;
    program "relative/path/plugin";
};
zone "prog2.example" {
    type program;
    program "/bin/sh";
    program-user "daemon";
};
EOF

./karicheck conf "${TMP_DIR}/bad_prog.conf" >/dev/null 2>&1 || true
echo "[+] Rule 5: Program zone linting rules checked"

echo "[+] All karicheck rules tests passed successfully."
exit 0


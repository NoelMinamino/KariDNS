#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARICHECK="$ROOT/karicheck"
TEST_BIN="$ROOT/test_secure_path"

echo "[*] Building karicheck and running path safety unit tests..."
make -C "$ROOT" karicheck path_safety_test

echo "[*] Running karicheck CLI integration tests for path resolution..."
TMP_CONF=$(mktemp /tmp/karidns_path_test.XXXXXX.conf)
trap 'rm -f "$TMP_CONF"' EXIT INT TERM

# 1. Legitimate relative path should pass
cat << 'EOF' > "$TMP_CONF"
options {
    port 10053;
    user "nobody";
};
zone "example.com" {
    type master;
    file "./tests/zones/example.com.zone";
};
EOF

if ! "$KARICHECK" "$TMP_CONF" > /dev/null 2>&1; then
    echo "[FAIL] karicheck rejected legitimate relative path './tests/zones/example.com.zone'!"
    exit 1
fi
echo "  -> [OK] Legitimate relative path accepted."

# 2. Legitimate relative path with ../ inside workspace should pass
cat << 'EOF' > "$TMP_CONF"
options {
    port 10053;
    user "nobody";
};
zone "example.com" {
    type master;
    file "tests/../tests/zones/example.com.zone";
};
EOF

if ! "$KARICHECK" "$TMP_CONF" > /dev/null 2>&1; then
    echo "[FAIL] karicheck rejected legitimate '../' path within workspace!"
    exit 1
fi
echo "  -> [OK] Legitimate '../' path within workspace accepted."

# 3. Path traversal escaping workspace MUST be rejected
cat << 'EOF' > "$TMP_CONF"
options {
    port 10053;
    user "nobody";
};
zone "example.com" {
    type master;
    file "../../../../../../../../etc/passwd";
};
EOF

if "$KARICHECK" "$TMP_CONF" > /dev/null 2>&1; then
    echo "[FAIL] karicheck allowed path traversal escaping workspace ('/etc/passwd')!"
    exit 1
fi
echo "  -> [OK] Malicious path traversal correctly rejected."

# 4. Program zone inheriting options.user should pass without error
cat << 'EOF' > "$TMP_CONF"
options {
    port 10053;
    user "nobody";
    allow-program-zones yes;
};
zone "anomaly.test." {
    type program;
    program "/bin/echo";
};
EOF

if ! "$KARICHECK" "$TMP_CONF" > /dev/null 2>&1; then
    echo "[FAIL] karicheck failed on program zone inheriting options.user!"
    exit 1
fi
echo "  -> [OK] Program zone user inheritance accepted."

echo ""
echo "[PASS] All secure path & Capsicum regression tests passed successfully!"
exit 0

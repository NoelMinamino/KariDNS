#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARICHECK="$ROOT/karicheck"

echo "[*] Building karicheck..."
make -C "$ROOT" karicheck

BAD_LABEL_ZONE="$DIR/zones/bad_label_len.zone"
BAD_NAME_ZONE="$DIR/zones/bad_name_len.zone"
GOOD_ZONE="$DIR/zones/good_label_len.zone"

mkdir -p "$DIR/zones"

# 1. 64-character label (RFC 1035 §3.1 limit is 63)
cat << 'EOF' > "$BAD_LABEL_ZONE"
$ORIGIN example.com.
$TTL 3600
@   IN SOA  ns1.example.com. hostmaster.example.com. 2026082401 7200 3600 1209600 3600
@   IN NS   ns1.example.com.
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa IN A 192.0.2.1
EOF

# 2. Total wire length > 255 octets
cat << 'EOF' > "$BAD_NAME_ZONE"
$ORIGIN example.com.
$TTL 3600
@   IN SOA  ns1.example.com. hostmaster.example.com. 2026082401 7200 3600 1209600 3600
@   IN NS   ns1.example.com.
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee IN A 192.0.2.1
EOF

# 3. Valid 63-character label (maximum allowed)
cat << 'EOF' > "$GOOD_ZONE"
$ORIGIN example.com.
$TTL 3600
@   IN SOA  ns1.example.com. hostmaster.example.com. 2026082401 7200 3600 1209600 3600
@   IN NS   ns1.example.com.
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa IN A 192.0.2.1
EOF

cleanup() {
    rm -f "$BAD_LABEL_ZONE" "$BAD_NAME_ZONE" "$GOOD_ZONE"
}
trap cleanup EXIT INT TERM

# Test 1: Check bad label length rejection
echo "[*] Testing karicheck on label > 63 octets..."
if "$KARICHECK" zone example.com "$BAD_LABEL_ZONE" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected label > 63 octets!"
    exit 1
fi
echo "[OK] karicheck correctly rejected label > 63 octets."

# Test 2: Check total wire name length > 255 rejection
echo "[*] Testing karicheck on total name > 255 octets..."
if "$KARICHECK" zone example.com "$BAD_NAME_ZONE" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected total name > 255 octets!"
    exit 1
fi
echo "[OK] karicheck correctly rejected total name > 255 octets."

# Test 3: Check valid max label (63 octets) acceptance
echo "[*] Testing karicheck on valid 63-octet label..."
if ! "$KARICHECK" zone example.com "$GOOD_ZONE" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted valid 63-octet label!"
    exit 1
fi
echo "[OK] karicheck correctly accepted valid 63-octet label."

echo "[PASS] All RFC 1035 §3.1 domain name length validations passed successfully!"
exit 0

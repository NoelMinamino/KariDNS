#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARICHECK="$ROOT/karicheck"

echo "[*] Building karicheck..."
make -C "$ROOT" karicheck

CONF_PRIMARY="$DIR/conf_type_primary.conf"
CONF_SECONDARY="$DIR/conf_type_secondary.conf"
CONF_INVALID="$DIR/conf_type_invalid.conf"

cleanup() {
    rm -f "$CONF_PRIMARY" "$CONF_SECONDARY" "$CONF_INVALID"
}
trap cleanup EXIT INT TERM

cat << 'EOF' > "$CONF_PRIMARY"
options {
    port 10053;
    user "nobody";
    group "nobody";
};
zone "example1.com" {
    type primary;
    file "zones/example1.zone";
};
EOF

cat << 'EOF' > "$CONF_SECONDARY"
options {
    port 10053;
    user "nobody";
    group "nobody";
};
zone "example2.com" {
    type secondary;
    masters { 192.0.2.1; };
};
EOF

cat << 'EOF' > "$CONF_INVALID"
options {
    port 10053;
    user "nobody";
    group "nobody";
};
zone "example3.com" {
    type invalid_zone_type;
    file "zones/example3.zone";
};
EOF

# Test 1: Check primary accepted
echo "[*] Testing karicheck on type primary..."
if ! "$KARICHECK" conf "$CONF_PRIMARY" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted type primary!"
    exit 1
fi
echo "[OK] karicheck accepted type primary."

# Test 2: Check secondary accepted
echo "[*] Testing karicheck on type secondary..."
if ! "$KARICHECK" conf "$CONF_SECONDARY" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted type secondary!"
    exit 1
fi
echo "[OK] karicheck accepted type secondary."

# Test 3: Check unknown type rejected
echo "[*] Testing karicheck on unknown zone type..."
if "$KARICHECK" conf "$CONF_INVALID" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected unknown zone type!"
    exit 1
fi
echo "[OK] karicheck correctly rejected unknown zone type."

echo "[PASS] All zone type validation tests passed successfully!"
exit 0

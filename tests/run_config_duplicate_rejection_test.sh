#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARICHECK="$ROOT/karicheck"

echo "[*] Building karicheck..."
make -C "$ROOT" karicheck

CONF_DUP_ZONE="$DIR/conf_dup_zone.conf"
CONF_DUP_KEY="$DIR/conf_dup_key.conf"
CONF_DUP_VIEW="$DIR/conf_dup_view.conf"
CONF_DUP_VIEW_ZONE="$DIR/conf_dup_view_zone.conf"
CONF_GOOD="$DIR/conf_good.conf"

cleanup() {
    rm -f "$CONF_DUP_ZONE" "$CONF_DUP_KEY" "$CONF_DUP_VIEW" "$CONF_DUP_VIEW_ZONE" "$CONF_GOOD"
}
trap cleanup EXIT INT TERM

# 1. Duplicate top-level zone
cat << 'EOF' > "$CONF_DUP_ZONE"
options {
    port 10053;
};
zone "example.com" {
    type master;
    file "zones/example.zone";
};
zone "example.com" {
    type master;
    file "zones/example2.zone";
};
EOF

# 2. Duplicate key
cat << 'EOF' > "$CONF_DUP_KEY"
options {
    port 10053;
};
key "transfer-key" {
    algorithm hmac-sha256;
    secret "k123456789012345678901234567890123456789012=";
};
key "transfer-key" {
    algorithm hmac-sha256;
    secret "k999999999012345678901234567890123456789012=";
};
EOF

# 3. Duplicate view
cat << 'EOF' > "$CONF_DUP_VIEW"
options {
    port 10053;
};
view "internal" {
    zone "example1.com" {
        type master;
        file "zones/example1.zone";
    };
};
view "internal" {
    zone "example2.com" {
        type master;
        file "zones/example2.zone";
    };
};
EOF

# 4. Duplicate zone inside view
cat << 'EOF' > "$CONF_DUP_VIEW_ZONE"
options {
    port 10053;
};
view "internal" {
    zone "example.com" {
        type master;
        file "zones/example1.zone";
    };
    zone "example.com" {
        type master;
        file "zones/example2.zone";
    };
};
EOF

# 5. Valid configuration
cat << 'EOF' > "$CONF_GOOD"
options {
    port 10053;
};
key "key1" {
    algorithm hmac-sha256;
    secret "k123456789012345678901234567890123456789012=";
};
key "key2" {
    algorithm hmac-sha256;
    secret "k999999999012345678901234567890123456789012=";
};
zone "example1.com" {
    type master;
    file "zones/example1.zone";
};
zone "example2.com" {
    type master;
    file "zones/example2.zone";
};
EOF

echo "[*] Testing karicheck on duplicate top-level zone..."
if "$KARICHECK" conf "$CONF_DUP_ZONE" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected duplicate top-level zone!"
    exit 1
fi
echo "[OK] karicheck correctly rejected duplicate top-level zone."

echo "[*] Testing karicheck on duplicate TSIG key..."
if "$KARICHECK" conf "$CONF_DUP_KEY" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected duplicate TSIG key!"
    exit 1
fi
echo "[OK] karicheck correctly rejected duplicate TSIG key."

echo "[*] Testing karicheck on duplicate view..."
if "$KARICHECK" conf "$CONF_DUP_VIEW" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected duplicate view!"
    exit 1
fi
echo "[OK] karicheck correctly rejected duplicate view."

echo "[*] Testing karicheck on duplicate zone in view..."
if "$KARICHECK" conf "$CONF_DUP_VIEW_ZONE" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected duplicate zone in view!"
    exit 1
fi
echo "[OK] karicheck correctly rejected duplicate zone in view."

echo "[*] Testing karicheck on valid configuration..."
if ! "$KARICHECK" conf "$CONF_GOOD" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted valid configuration!"
    exit 1
fi
echo "[OK] karicheck correctly accepted valid configuration."

echo "[PASS] All duplicate block rejection and configuration checks passed successfully!"
exit 0

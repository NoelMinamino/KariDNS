#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARICHECK="$ROOT/karicheck"

echo "[*] Building karicheck..."
make -C "$ROOT" karicheck

CONF_SLAVE_UPD="$DIR/conf_slave_update.conf"
CONF_MASTER_UPD="$DIR/conf_master_update.conf"

cleanup() {
    rm -f "$CONF_SLAVE_UPD" "$CONF_MASTER_UPD"
}
trap cleanup EXIT INT TERM

cat << 'EOF' > "$CONF_SLAVE_UPD"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
key "test-key" {
    algorithm hmac-sha256;
    secret "k123456789012345678901234567890123456789012=";
};
zone "slave.example.com" {
    type slave;
    masters { 192.0.2.1; };
    allow-update { key "test-key"; };
};
EOF

cat << 'EOF' > "$CONF_MASTER_UPD"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
key "test-key" {
    algorithm hmac-sha256;
    secret "k123456789012345678901234567890123456789012=";
};
zone "master.example.com" {
    type master;
    file "zones/master.zone";
    allow-update { key "test-key"; };
};
EOF

echo "[*] Testing karicheck on master zone with allow-update..."
if ! "$KARICHECK" conf "$CONF_MASTER_UPD" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted master zone with allow-update!"
    exit 1
fi
echo "[OK] karicheck accepted master zone with allow-update."

echo "[*] Testing karicheck on slave zone with allow-update (should warn but load)..."
if ! "$KARICHECK" conf "$CONF_SLAVE_UPD" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted slave zone configuration (with warning)!"
    exit 1
fi
echo "[OK] karicheck processed slave zone with allow-update."

echo "[PASS] All allow-update zone configuration checks passed successfully!"
exit 0

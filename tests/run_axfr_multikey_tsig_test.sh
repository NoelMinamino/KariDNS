#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"
PORT=15492

echo "[*] Building karidns and dag..."
make -C "$ROOT" karidns dag

CONF_FILE="$DIR/axfr_multikey_test.conf"
ZONE_FILE="$DIR/axfr_multikey_test.zone"

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -f "$CONF_FILE" "$ZONE_FILE" /tmp/karidns_axfr_multikey.log
}
trap cleanup EXIT INT TERM

cat << 'EOF' > "$ZONE_FILE"
$ORIGIN multikey.test.
$TTL 3600
@       IN SOA  ns1.multikey.test. hostmaster.multikey.test. (
                2026082501 ; serial
                7200       ; refresh
                3600       ; retry
                1209600    ; expire
                3600       ; minimum
                )
        IN NS   ns1.multikey.test.
ns1     IN A    192.0.2.1
www     IN A    192.0.2.100
EOF

KEY_A_SECRET="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
KEY_B_SECRET="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
KEY_UNAUTH_SECRET="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="

cat << EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

key "keyA" {
    algorithm hmac-sha256;
    secret "$KEY_A_SECRET";
};

key "keyB" {
    algorithm hmac-sha256;
    secret "$KEY_B_SECRET";
};

key "unauthKey" {
    algorithm hmac-sha256;
    secret "$KEY_UNAUTH_SECRET";
};

zone "multikey.test" {
    type master;
    file "$ZONE_FILE";
    allow-transfer { key "keyA"; key "keyB"; };
};
EOF

echo "[*] Starting KariDNS on port $PORT..."
"$BIN" -f "$CONF_FILE" > /tmp/karidns_axfr_multikey.log 2>&1 &
SERVER_PID=$!
sleep 0.5

# Test 1: AXFR with keyA (should succeed)
echo "[*] Test 1: AXFR with keyA..."
OUT_A=$("$DAG" multikey.test AXFR "@127.0.0.1" -p $PORT -y "hmac-sha256:keyA:$KEY_A_SECRET" +tcp 2>&1)
echo "$OUT_A" | grep -q "www.multikey.test." || {
    echo "[FAIL] AXFR with keyA failed!"
    echo "Output:"
    echo "$OUT_A"
    cat /tmp/karidns_axfr_multikey.log
    exit 1
}
echo "[OK] AXFR with keyA succeeded."

# Test 2: AXFR with keyB (should succeed)
echo "[*] Test 2: AXFR with keyB..."
OUT_B=$("$DAG" multikey.test AXFR "@127.0.0.1" -p $PORT -y "hmac-sha256:keyB:$KEY_B_SECRET" +tcp 2>&1)
echo "$OUT_B" | grep -q "www.multikey.test." || {
    echo "[FAIL] AXFR with keyB failed!"
    echo "Output:"
    echo "$OUT_B"
    cat /tmp/karidns_axfr_multikey.log
    exit 1
}
echo "[OK] AXFR with keyB succeeded."

# Test 3: AXFR with unauthKey (defined in server but not in allow-transfer -> should be rejected / NOTAUTH / REFUSED / BADKEY)
echo "[*] Test 3: AXFR with unauthKey (should be rejected)..."
OUT_UNAUTH=$("$DAG" multikey.test AXFR "@127.0.0.1" -p $PORT -y "hmac-sha256:unauthKey:$KEY_UNAUTH_SECRET" +tcp 2>&1 || true)
if echo "$OUT_UNAUTH" | grep -q "www.multikey.test."; then
    echo "[FAIL] AXFR with unauthKey unexpectedly succeeded!"
    echo "Output:"
    echo "$OUT_UNAUTH"
    exit 1
fi
echo "[OK] AXFR with unauthKey correctly rejected."

# Test 4: Unsigned AXFR (should be rejected)
echo "[*] Test 4: Unsigned AXFR (should be rejected)..."
OUT_UNSIGNED=$("$DAG" multikey.test AXFR "@127.0.0.1" -p $PORT +tcp 2>&1 || true)
if echo "$OUT_UNSIGNED" | grep -q "www.multikey.test."; then
    echo "[FAIL] Unsigned AXFR unexpectedly succeeded!"
    echo "Output:"
    echo "$OUT_UNSIGNED"
    exit 1
fi
echo "[OK] Unsigned AXFR correctly rejected."

echo "[PASS] AXFR multiple TSIG key authorization test passed successfully!"
exit 0

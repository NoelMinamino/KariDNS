#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"
PORT=15492

echo "[*] Building karidns and dag..."
[ -x "$ROOT/karidns" ] && [ -x "$ROOT/dag" ] || make -C "$ROOT" karidns dag

CONF_FILE="$DIR/axfr_multikey_test.conf"
ZONE_FILE="$DIR/axfr_multikey_test.zone"
MIXED_ZONE="$DIR/axfr_multikey_mixed.zone"
OTHER_ZONE="$DIR/axfr_multikey_other.zone"

cleanup() {
    kari_kill_tree "${SERVER_PID:-}"
    rm -f "$CONF_FILE" "$ZONE_FILE" "$MIXED_ZONE" "$OTHER_ZONE" /tmp/karidns_axfr_multikey.log
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

# X-41: addresses and keys in one allow-transfer list: both are required (docs/karidns.md allow-transfer)
for z in mixed other; do
    f="$DIR/axfr_multikey_$z.zone"
    sed -e "s/multikey\.test\./$z.multikey.test./g" "$ZONE_FILE" > "$f"
done

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

zone "mixed.multikey.test" {
    type master;
    file "$MIXED_ZONE";
    allow-transfer { key "keyA"; 127.0.0.1; };
};

zone "other.multikey.test" {
    type master;
    file "$OTHER_ZONE";
    allow-transfer { key "keyA"; 192.0.2.99; };
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

# Test 5-7 (X-41): allow-transfer { key "keyA"; <address>; } needs the address AND the key
# (docs/karidns.md: unlike BIND, the key is not one more first-match entry).
# dag prints only "; Transfer failed." for a refused transfer (like dig), so the RCODE is read with
# tests/tsig_query.pl: "rcode=5" is REFUSED, "tsig=ok" a signed answer that verifies.
xfr_rcode() {
    perl "$DIR/tsig_query.pl" --server 127.0.0.1 --port $PORT --tcp --name "$1" --type AXFR $2 2>&1 | head -1
}
echo "[*] Test 5: signed AXFR from the listed address (should succeed)..."
OUT=$("$DAG" mixed.multikey.test AXFR "@127.0.0.1" -p $PORT -y "hmac-sha256:keyA:$KEY_A_SECRET" +tcp 2>&1 || true)
if ! printf '%s\n' "$OUT" | grep -q "^www.mixed.multikey.test."; then
    echo "[FAIL] signed AXFR from 127.0.0.1 was not answered with the zone"; echo "$OUT"; exit 1
fi
echo "[OK] signed AXFR from the listed address succeeded."

echo "[*] Test 6: unsigned AXFR from the listed address (should be REFUSED)..."
ST=$(xfr_rcode mixed.multikey.test)
OUT=$("$DAG" mixed.multikey.test AXFR "@127.0.0.1" -p $PORT +tcp +nohexdump 2>&1 || true)
if ! printf '%s\n' "$ST" | grep -q "^rcode=5 .*tsig=none" || printf '%s\n' "$OUT" | grep -q "^www.mixed.multikey.test."; then
    echo "[FAIL] unsigned AXFR from 127.0.0.1: expected REFUSED without records, got '$ST'"; echo "$OUT"; exit 1
fi
echo "[OK] unsigned AXFR from the listed address was REFUSED."

echo "[*] Test 7: signed AXFR from an address that is not listed (should be REFUSED)..."
ST=$(xfr_rcode other.multikey.test "--key keyA:$KEY_A_SECRET")
OUT=$("$DAG" other.multikey.test AXFR "@127.0.0.1" -p $PORT -y "hmac-sha256:keyA:$KEY_A_SECRET" +tcp +nohexdump 2>&1 || true)
if ! printf '%s\n' "$ST" | grep -q "^rcode=5 .*tsig=ok" || printf '%s\n' "$OUT" | grep -q "^www.other.multikey.test."; then
    echo "[FAIL] signed AXFR from an unlisted address: expected a signed REFUSED without records, got '$ST'"; echo "$OUT"; exit 1
fi
echo "[OK] signed AXFR from an unlisted address was REFUSED (signed)."

echo "[PASS] AXFR multiple TSIG key authorization test passed successfully!"
exit 0

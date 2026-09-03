#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
make -C "$ROOT" karidns dag

CONF="$DIR/section_order_test.conf"
ZONE="$DIR/zones/section_order_example.com.zone"

mkdir -p "$DIR/zones"

# RFC 2606 (example.com), RFC 5737 (192.0.2.0/24, 198.51.100.0/24), RFC 3849 (2001:db8::/32)
cat << 'EOF' > "$ZONE"
$ORIGIN example.com.
$TTL 1800
@           IN SOA   ns1.example.com. hostmaster.example.com. 2026090301 7200 3600 1209600 1800
@           IN NS    ns1.example.com.
@           IN NS    ns2.v6.example.com.
@           IN NS    ns3.v6.example.com.
ns1         IN A     192.0.2.1
ns2.v6      IN AAAA  2001:db8:1::1
ns2.v6      IN A     192.0.2.2
ns3.v6      IN AAAA  2001:db8:2::1
ns3.v6      IN A     192.0.2.3
@           IN MX    10 mail1.example.com.
@           IN MX    20 mail2.example.com.
mail1       IN A     198.51.100.1
mail2       IN A     198.51.100.2
EOF

cat << EOF > "$CONF"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
zone "example.com" {
    type master;
    file "$ZONE";
};
EOF

echo "[*] Starting KariDNS on port 10053..."
$BIN -f -c "$CONF" > "$DIR/server_section_order.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF" "$ZONE" "$DIR/server_section_order.log"
}
trap cleanup EXIT INT TERM

sleep 2

# =============================================================================
# Test 1: NS Query (User's reported regression scenario)
# =============================================================================
echo "[*] Test 1: Querying NS example.com..."
NS_OUT=$($DAG NS example.com @127.0.0.1 -p 10053 +norec)
echo "$NS_OUT"

# Extract ANSWER SECTION
ANS_SEC=$(echo "$NS_OUT" | awk '/;; ANSWER SECTION:/{flag=1; next} /^;;/{flag=0} flag')
# Extract ADDITIONAL SECTION
ADD_SEC=$(echo "$NS_OUT" | awk '/;; ADDITIONAL SECTION:/{flag=1; next} /^;;/{flag=0} flag')

# 1-a. ANSWER SECTION must contain ONLY NS records
if echo "$ANS_SEC" | grep -E "\s+IN\s+(A|AAAA)\s+" ; then
    echo "[FAIL] ANSWER SECTION contains unexpected A or AAAA records!"
    exit 1
fi
ANS_NS_COUNT=$(echo "$ANS_SEC" | grep -c -E "\s+IN\s+NS\s+" || true)
if [ "$ANS_NS_COUNT" -ne 3 ]; then
    echo "[FAIL] Expected 3 NS records in ANSWER SECTION, got $ANS_NS_COUNT"
    exit 1
fi

# 1-b. ADDITIONAL SECTION must NOT contain NS records
if echo "$ADD_SEC" | grep -E "\s+IN\s+NS\s+" ; then
    echo "[FAIL] ADDITIONAL SECTION contains unexpected NS records (pushed out from ANSWER)!"
    exit 1
fi
ADD_GLUE_COUNT=$(echo "$ADD_SEC" | grep -c -E "\s+IN\s+(A|AAAA)\s+" || true)
if [ "$ADD_GLUE_COUNT" -ne 5 ]; then
    echo "[FAIL] Expected 5 glue records in ADDITIONAL SECTION, got $ADD_GLUE_COUNT"
    exit 1
fi

echo "[PASS] Test 1 (NS Query Section Order) passed!"

# =============================================================================
# Test 2: MX Query (Multiple MX targets with glue)
# =============================================================================
echo "[*] Test 2: Querying MX example.com..."
MX_OUT=$($DAG MX example.com @127.0.0.1 -p 10053 +norec)
echo "$MX_OUT"

ANS_MX=$(echo "$MX_OUT" | awk '/;; ANSWER SECTION:/{flag=1; next} /^;;/{flag=0} flag')
ADD_MX=$(echo "$MX_OUT" | awk '/;; ADDITIONAL SECTION:/{flag=1; next} /^;;/{flag=0} flag')

if echo "$ANS_MX" | grep -E "\s+IN\s+(A|AAAA)\s+" ; then
    echo "[FAIL] MX ANSWER SECTION contains unexpected A/AAAA glue records!"
    exit 1
fi
if echo "$ADD_MX" | grep -E "\s+IN\s+MX\s+" ; then
    echo "[FAIL] MX ADDITIONAL SECTION contains unexpected MX records!"
    exit 1
fi

echo "[PASS] Test 2 (MX Query Section Order) passed!"

# =============================================================================
# Test 3: Standard A Record Query (Authority NS + Glue order)
# =============================================================================
echo "[*] Test 3: Querying A ns1.example.com..."
A_OUT=$($DAG A ns1.example.com @127.0.0.1 -p 10053 +norec)
echo "$A_OUT"

AUTH_A=$(echo "$A_OUT" | awk '/;; AUTHORITY SECTION:/{flag=1; next} /^;;/{flag=0} flag')
ADD_A=$(echo "$A_OUT" | awk '/;; ADDITIONAL SECTION:/{flag=1; next} /^;;/{flag=0} flag')

if echo "$AUTH_A" | grep -E "\s+IN\s+(A|AAAA)\s+" ; then
    echo "[FAIL] AUTHORITY SECTION contains unexpected A/AAAA records!"
    exit 1
fi
if echo "$ADD_A" | grep -E "\s+IN\s+NS\s+" ; then
    echo "[FAIL] ADDITIONAL SECTION contains unexpected NS records!"
    exit 1
fi

echo "[PASS] Test 3 (Authority NS Section Order) passed!"

echo ""
echo "[PASS] All Response Section Ordering tests passed successfully!"
exit 0

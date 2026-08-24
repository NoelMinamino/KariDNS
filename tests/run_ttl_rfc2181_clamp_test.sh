#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
make -C "$ROOT" karidns dag

CONF="$DIR/ttl_clamp_test.conf"
ZONE="$DIR/zones/ttl_clamp_test.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE"
$ORIGIN ttlclamp.test.
$TTL 4000000000
@   IN SOA  ns1.ttlclamp.test. hostmaster.ttlclamp.test. (
            2026082401
            4000000000 ; refresh
            4000000000 ; retry
            4000000000 ; expire
            4000000000 ; minimum
            )
@   IN NS   ns1.ttlclamp.test.
ns1 IN A    127.0.0.1
www 4000000000 IN A 192.0.2.1
unit 46296d17m IN A 192.0.2.2
EOF

cat << EOF > "$CONF"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
zone "ttlclamp.test" {
    type master;
    file "$ZONE";
};
EOF

echo "[*] Starting KariDNS on port 10053..."
$BIN -f -c "$CONF" > "$DIR/server_ttl_clamp.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF" "$ZONE" "$DIR/server_ttl_clamp.log"
}
trap cleanup EXIT INT TERM

sleep 2

# 1. Query record with purely numeric 4000000000 TTL (MUST be clamped to 2147483647 per RFC 2181 §8)
echo "[*] Querying www.ttlclamp.test (pure numeric 4000000000 TTL)..."
WWW_OUT=$($DAG www.ttlclamp.test A @127.0.0.1 -p 10053)
echo "$WWW_OUT"

if ! echo "$WWW_OUT" | grep -q "www.ttlclamp.test.*2147483647.*IN.*A.*192.0.2.1"; then
    echo "[FAIL] Pure numeric TTL 4000000000 was NOT clamped to 2147483647!"
    exit 1
fi

# 2. Query record with unit-suffixed 46296d17m TTL (MUST also be clamped to 2147483647)
echo "[*] Querying unit.ttlclamp.test (unit suffixed 46296d17m TTL)..."
UNIT_OUT=$($DAG unit.ttlclamp.test A @127.0.0.1 -p 10053)
echo "$UNIT_OUT"

if ! echo "$UNIT_OUT" | grep -q "unit.ttlclamp.test.*2147483647.*IN.*A.*192.0.2.2"; then
    echo "[FAIL] Unit-suffixed TTL was NOT clamped to 2147483647!"
    exit 1
fi

# 3. Query NXDOMAIN (negative caching TTL from SOA minimum MUST be clamped to 2147483647)
echo "[*] Querying NXDOMAIN nonexist.ttlclamp.test..."
NX_OUT=$($DAG nonexist.ttlclamp.test A @127.0.0.1 -p 10053)
echo "$NX_OUT"

if ! echo "$NX_OUT" | grep -q "ttlclamp.test.*2147483647.*IN.*SOA"; then
    echo "[FAIL] Negative response SOA TTL was NOT clamped to 2147483647!"
    exit 1
fi

echo "[PASS] Both pure numeric and unit-suffixed TTL values are consistently clamped to 2147483647 (RFC 2181 §8)!"
exit 0

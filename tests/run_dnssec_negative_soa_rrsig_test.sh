#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
make -C "$ROOT" karidns dag

CONF="$DIR/dnssec_neg_test.conf"
ZONE="$DIR/zones/dnssec_neg_test.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE"
$ORIGIN signed.test.
$TTL 3600
@   IN SOA   ns1.signed.test. hostmaster.signed.test. 2026082401 7200 3600 1209600 3600
@   IN RRSIG SOA 13 2 3600 20300101000000 20200101000000 12345 signed.test. dGVzdHNvYXJyc2ln
@   IN NS    ns1.signed.test.
@   IN RRSIG NS 13 2 3600 20300101000000 20200101000000 12345 signed.test. dGVzdG5zcnJzaWc=
ns1 IN A     127.0.0.1
ns1 IN RRSIG A 13 3 3600 20300101000000 20200101000000 12345 signed.test. dGVzdGFycnNpZw==
www IN A     192.0.2.1
www IN RRSIG A 13 3 3600 20300101000000 20200101000000 12345 signed.test. dGVzdGFycnNpZzI=
@   IN NSEC  ns1.signed.test. SOA NS RRSIG NSEC
@   IN RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 signed.test. dGVzdG5zZWNycnNpZw==
ns1 IN NSEC  www.signed.test. A RRSIG NSEC
ns1 IN RRSIG NSEC 13 3 3600 20300101000000 20200101000000 12345 signed.test. dGVzdG5zZWNycnNpZzI=
www IN NSEC  signed.test. A RRSIG NSEC
www IN RRSIG NSEC 13 3 3600 20300101000000 20200101000000 12345 signed.test. dGVzdG5zZWNycnNpZzM=
EOF

cat << EOF > "$CONF"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
zone "signed.test" {
    type master;
    file "$ZONE";
};
EOF

echo "[*] Starting KariDNS on port 10053..."
$BIN -f -c "$CONF" > "$DIR/server_dnssec_neg.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF" "$ZONE" "$DIR/server_dnssec_neg.log"
}
trap cleanup EXIT INT TERM

sleep 2

# 1. NXDOMAIN Test: Query non-existent name with DO bit (+dnssec)
echo "[*] Querying NXDOMAIN with +dnssec (nonexist.signed.test A)..."
NX_OUT=$($DAG +dnssec nonexist.signed.test A @127.0.0.1 -p 10053)
echo "$NX_OUT"

if ! echo "$NX_OUT" | grep -q "status: NXDOMAIN"; then
    echo "[FAIL] Expected status NXDOMAIN!"
    exit 1
fi

if ! echo "$NX_OUT" | grep -q "signed.test.*IN.*SOA"; then
    echo "[FAIL] SOA record missing in Authority section for NXDOMAIN response!"
    exit 1
fi

if ! echo "$NX_OUT" | grep -q "signed.test.*IN.*RRSIG.*SOA"; then
    echo "[FAIL] Covering RRSIG for SOA record missing in Authority section for NXDOMAIN response!"
    exit 1
fi

# 2. NODATA Test: Query existing name for non-existent type with DO bit (+dnssec)
echo "[*] Querying NODATA with +dnssec (www.signed.test TXT)..."
NODATA_OUT=$($DAG +dnssec www.signed.test TXT @127.0.0.1 -p 10053)
echo "$NODATA_OUT"

if ! echo "$NODATA_OUT" | grep -q "status: NOERROR"; then
    echo "[FAIL] Expected status NOERROR for NODATA query!"
    exit 1
fi

if ! echo "$NODATA_OUT" | grep -q "signed.test.*IN.*SOA"; then
    echo "[FAIL] SOA record missing in Authority section for NODATA response!"
    exit 1
fi

if ! echo "$NODATA_OUT" | grep -q "signed.test.*IN.*RRSIG.*SOA"; then
    echo "[FAIL] Covering RRSIG for SOA record missing in Authority section for NODATA response!"
    exit 1
fi

echo "[PASS] DNSSEC negative responses (NXDOMAIN/NODATA) correctly include covering RRSIG for SOA (RFC 4035 compliant)!"
exit 0

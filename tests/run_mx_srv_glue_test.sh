#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
make -C "$ROOT" karidns dag

CONF="$DIR/mx_srv_glue_test.conf"
ZONE="$DIR/zones/mx_srv_glue_test.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE"
$ORIGIN example.com.
$TTL 3600
@           IN SOA   ns1.example.com. hostmaster.example.com. 2026082401 7200 3600 1209600 3600
@           IN NS    ns1.example.com.
ns1         IN A     127.0.0.1
@           IN MX    10 mail.example.com.
@           IN MX    20 mail.example.com.
mail        IN A     192.0.2.10
mail        IN AAAA  2001:db8::10
_sip._tcp   IN SRV   10 60 5060 sip.example.com.
sip         IN A     192.0.2.20
external    IN MX    10 mail.otherdomain.net.
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
$BIN -f -c "$CONF" > "$DIR/server_glue.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF" "$ZONE" "$DIR/server_glue.log"
}
trap cleanup EXIT INT TERM

sleep 2

# 1. Test MX Query (Additional section should contain mail.example.com A and AAAA)
echo "[*] Querying MX example.com..."
MX_OUT=$($DAG MX example.com @127.0.0.1 -p 10053)
echo "$MX_OUT"

if ! echo "$MX_OUT" | grep -q "mail.example.com.*192.0.2.10"; then
    echo "[FAIL] Additional A record for mail.example.com missing in MX response!"
    exit 1
fi

if ! echo "$MX_OUT" | grep -q "mail.example.com.*2001:db8::10"; then
    echo "[FAIL] Additional AAAA record for mail.example.com missing in MX response!"
    exit 1
fi

# 2. Test SRV Query (Additional section should contain sip.example.com A)
echo "[*] Querying SRV _sip._tcp.example.com..."
SRV_OUT=$($DAG SRV _sip._tcp.example.com @127.0.0.1 -p 10053)
echo "$SRV_OUT"

if ! echo "$SRV_OUT" | grep -q "sip.example.com.*192.0.2.20"; then
    echo "[FAIL] Additional A record for sip.example.com missing in SRV response!"
    exit 1
fi

# 3. Test Out-of-bailiwick MX Query (Additional section should NOT contain otherdomain.net)
echo "[*] Querying MX external.example.com (out-of-bailiwick)..."
EXT_OUT=$($DAG MX external.example.com @127.0.0.1 -p 10053)
echo "$EXT_OUT"

if echo "$EXT_OUT" | grep -i "otherdomain.net.*IN.*A"; then
    echo "[FAIL] Out-of-bailiwick target was incorrectly added to Additional section!"
    exit 1
fi

echo "[PASS] All MX and SRV Additional section Glue tests passed successfully!"
exit 0

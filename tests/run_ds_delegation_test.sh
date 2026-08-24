#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
make -C "$ROOT" karidns dag

CONF="$DIR/ds_delegation_test.conf"
ZONE="$DIR/zones/ds_delegation_test.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE"
$ORIGIN example.com.
$TTL 3600
@           IN SOA   ns1.example.com. hostmaster.example.com. 2026082401 7200 3600 1209600 3600
@           IN NS    ns1.example.com.
ns1         IN A     127.0.0.1

; 1. Secure delegation point (NS + DS)
secure      IN NS    ns1.secure.example.com.
secure      IN DS    12345 13 2 2BB1834370273412E81E3272C18B868FD63804EB61A086C38D04FF2DEDFE2516
ns1.secure  IN A     192.0.2.53

; 2. Insecure delegation point (NS only, no DS)
insecure    IN NS    ns1.insecure.example.com.
ns1.insecure IN A    192.0.2.54
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
$BIN -f -c "$CONF" > "$DIR/server_ds_delegation.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF" "$ZONE" "$DIR/server_ds_delegation.log"
}
trap cleanup EXIT INT TERM

sleep 2

# 1. Query DS at secure delegation point (MUST return Authoritative Answer with AA=1)
echo "[*] Querying DS secure.example.com (RFC 4035 §3.1.4.1 authoritative response)..."
DS_OUT=$($DAG DS secure.example.com @127.0.0.1 -p 10053)
echo "$DS_OUT"

if ! echo "$DS_OUT" | grep -q "flags:.*aa.*"; then
    echo "[FAIL] AA flag was NOT set for delegation point DS query!"
    exit 1
fi

if ! echo "$DS_OUT" | grep -q "secure.example.com.*IN.*DS"; then
    echo "[FAIL] Answer section did not contain DS record!"
    exit 1
fi

# 2. Query NS at delegation point (MUST return Referral with AA=0, NS in Authority)
echo "[*] Querying NS secure.example.com (referral response)..."
NS_OUT=$($DAG NS secure.example.com @127.0.0.1 -p 10053)
echo "$NS_OUT"

if echo "$NS_OUT" | grep -q "flags:.*aa.*"; then
    echo "[FAIL] AA flag was incorrectly set for NS referral query!"
    exit 1
fi

if ! echo "$NS_OUT" | grep -q "secure.example.com.*IN.*NS.*ns1.secure.example.com"; then
    echo "[FAIL] Authority section did not contain delegation NS record!"
    exit 1
fi

# 3. Query A at sub-domain under delegation (MUST return Referral with AA=0)
echo "[*] Querying A host.secure.example.com (referral response)..."
SUB_OUT=$($DAG A host.secure.example.com @127.0.0.1 -p 10053)
echo "$SUB_OUT"

if echo "$SUB_OUT" | grep -q "flags:.*aa.*"; then
    echo "[FAIL] AA flag was incorrectly set for sub-zone referral!"
    exit 1
fi

# 4. Query DS at insecure delegation point without DS (MUST return Authoritative NODATA with AA=1 and SOA)
echo "[*] Querying DS insecure.example.com (NODATA authoritative response)..."
INSEC_OUT=$($DAG DS insecure.example.com @127.0.0.1 -p 10053)
echo "$INSEC_OUT"

if ! echo "$INSEC_OUT" | grep -q "flags:.*aa.*"; then
    echo "[FAIL] AA flag was NOT set for insecure delegation DS NODATA query!"
    exit 1
fi

if ! echo "$INSEC_OUT" | grep -q "example.com.*IN.*SOA"; then
    echo "[FAIL] Authority section did not contain SOA record for DS NODATA response!"
    exit 1
fi

echo "[PASS] Delegation point DS queries and NS referrals correctly handled according to RFC 4035 §3.1.4.1!"
exit 0

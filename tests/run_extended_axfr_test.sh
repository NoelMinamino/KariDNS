#!/bin/sh
set -e

# ==============================================================================
# KariDNS Extended AXFR (Source Directive Preserving Transfer) Test Suite
#
# Verifies:
# 1. KariDNS-to-KariDNS Extended AXFR:
#    - Automatic negotiation via EDNS Option 65153
#    - Wire serialization and restoration of BIND $LOCATION-TAG, $LOCATION,
#      $ECS-SUBNET-TAG, and $ECS-SUBNET directives on Secondary
#    - Secondary serves queries with accurate location and subnet filtering
# 2. Plan B Fallback to Standard AXFR:
#    - Standard AXFR clients without Option 65153 receive default/untagged records
#    - Location/ECS/tinydns tagged records and CLASS 65302 markers are hidden
# 3. tinydns Format Extended AXFR:
#    - Wire wrapping of tinydns records (TYPE 65406) and location definitions (%)
#    - Secondary unwraps records and filters by client location
# 4. Dynamic Update & Retransfer:
#    - Updating tag definitions on Master propagates cleanly to Secondary
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"
KARICHECK="$ROOT_DIR/karicheck"

echo "=== Building karidns, karictl, and dag with make ==="
make -C "$ROOT_DIR" karidns karictl dag

FAILED=0
PORT1=$((25000 + $$ % 3500))
PORT2=$((PORT1 + 2))
TMP_DIR="/tmp/karidns_ext_axfr_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

PID1=""
PID2=""

cleanup() {
    [ -n "$PID1" ] && kill -9 "$PID1" 2>/dev/null || true
    [ -n "$PID2" ] && kill -9 "$PID2" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"

# ------------------------------------------------------------------------------
# Test Zone Setup
# ------------------------------------------------------------------------------

# Master Zone 1: BIND format with $LOCATION and $ECS-SUBNET directives
cat << 'EOF' > "$TMP_DIR/ext_bind.zone"
$TTL 300
$ORIGIN ext.example.com.
@       IN  SOA ns1.ext.example.com. hostmaster.ext.example.com. (
            2026090501 ; Serial
            3600 600 86400 300
)
@       IN  NS  ns1.ext.example.com.
ns1     IN  A   127.0.0.1

$LOCATION-TAG local 127.0.0.1/32
$LOCATION-TAG remote 192.0.2.0/24
$ECS-SUBNET-TAG eu-tier 198.51.100.0/24
$ECS-SUBNET-TAG us-tier 203.0.113.0/24

; Location-filtered records
$LOCATION local
loc-test IN A   10.1.1.1
$LOCATION remote
loc-test IN A   10.2.2.2
$LOCATION ""
loc-test IN A   10.0.0.1

; ECS-filtered records
$ECS-SUBNET eu-tier
ecs-test IN A   172.16.1.1
$ECS-SUBNET us-tier
ecs-test IN A   172.16.2.2
$ECS-SUBNET ""
ecs-test IN A   172.16.0.1

; Untagged default record
default-rec IN A 192.168.1.100
EOF

# Master Zone 2: tinydns format with % location tags
cat << 'EOF' > "$TMP_DIR/ext_tiny.data"
.tiny.example.com:127.0.0.1:ns1.tiny.example.com:300
%lo:127.0.0.1/32
%re:192.0.2.0/24
+srv.tiny.example.com:10.10.1.1:300::lo
+srv.tiny.example.com:10.10.2.2:300::re
+srv.tiny.example.com:10.10.0.1:300
+def.tiny.example.com:10.99.99.1:300
EOF

# Master Server Configuration (Port $PORT1)
cat << EOF > "$TMP_DIR/master.conf"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 127.0.0.1; };
};

control-channel {
    socket "$TMP_DIR/ctl_master.sock";
    algorithm hmac-sha256;
    secret "$SECRET";
};

zone "ext.example.com" {
    type master;
    file "$TMP_DIR/ext_bind.zone";
    allow-transfer { 127.0.0.1; };
};

zone "tiny.example.com" {
    type master;
    file "$TMP_DIR/ext_tiny.data";
    file-format tinydns;
    allow-transfer { 127.0.0.1; };
};
EOF

# Secondary Server Configuration (Port $PORT2)
cat << EOF > "$TMP_DIR/slave.conf"
options {
    port $PORT2;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 127.0.0.1; };
};

control-channel {
    socket "$TMP_DIR/ctl_slave.sock";
    algorithm hmac-sha256;
    secret "$SECRET";
};

zone "ext.example.com" {
    type slave;
    masters { 127.0.0.1 port $PORT1; };
};

zone "tiny.example.com" {
    type slave;
    masters { 127.0.0.1 port $PORT1; };
};
EOF

# karictl configuration
cat << EOF > "$TMP_DIR/karictl.conf"
key "karictl" {
    algorithm hmac-sha256;
    secret "$SECRET";
};
EOF

echo "=== Starting Master on Port $PORT1 and Secondary on Port $PORT2 ==="
"$KARIDNS" -f "$TMP_DIR/master.conf" > "$TMP_DIR/master.log" 2>&1 &
PID1=$!
sleep 1

if ! kill -0 "$PID1" 2>/dev/null; then
    echo "[FAIL] Master failed to start. Log output:"
    cat "$TMP_DIR/master.log"
    exit 1
fi

"$KARIDNS" -f "$TMP_DIR/slave.conf" > "$TMP_DIR/slave.log" 2>&1 &
PID2=$!
sleep 1

if ! kill -0 "$PID2" 2>/dev/null; then
    echo "[FAIL] Secondary failed to start. Log output:"
    cat "$TMP_DIR/slave.log"
    exit 1
fi

# ------------------------------------------------------------------------------
# Test 1: BIND Format Extended AXFR Transfer to Secondary
# ------------------------------------------------------------------------------
echo ""
echo "=== Test 1: BIND Format Extended AXFR to Secondary ==="

echo -n "Waiting for Secondary to transfer ext.example.com ... "
TRANSFER_OK=0
for i in $(seq 1 30); do
    DEF_ANS=$("$DAG" @127.0.0.1 -p "$PORT2" default-rec.ext.example.com A +short 2>&1 || true)
    if [ "$DEF_ANS" = "192.168.1.100" ]; then
        TRANSFER_OK=1
        break
    fi
    sleep 0.5
done

if [ "$TRANSFER_OK" -eq 1 ]; then
    echo "OK (Transfer completed)"
else
    echo "FAILED"
    echo "  Secondary query output: '$DEF_ANS'"
    echo "  Secondary log:"
    cat "$TMP_DIR/slave.log"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Secondary client location filtering (127.0.0.1 matches 'local') ... "
LOC_ANS=$("$DAG" @127.0.0.1 -p "$PORT2" loc-test.ext.example.com A +short 2>&1 || true)
if echo "$LOC_ANS" | grep -q "10.1.1.1" && echo "$LOC_ANS" | grep -q "10.0.0.1" && ! echo "$LOC_ANS" | grep -q "10.2.2.2"; then
    echo "OK (Restored \$LOCATION-TAG local: received 10.1.1.1 and 10.0.0.1, excluded remote 10.2.2.2)"
else
    echo "FAILED (Unexpected answer: '$LOC_ANS')"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Secondary ECS filtering for 'eu-tier' (198.51.100.10) ... "
ECS_EU_ANS=$("$DAG" @127.0.0.1 -p "$PORT2" ecs-test.ext.example.com A +short +subnet=198.51.100.10 2>&1 || true)
if echo "$ECS_EU_ANS" | grep -q "172.16.1.1" && echo "$ECS_EU_ANS" | grep -q "172.16.0.1" && ! echo "$ECS_EU_ANS" | grep -q "172.16.2.2"; then
    echo "OK (Restored \$ECS-SUBNET-TAG eu-tier: received 172.16.1.1 and default 172.16.0.1)"
else
    echo "FAILED (Unexpected answer: '$ECS_EU_ANS')"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Secondary ECS filtering for 'us-tier' (203.0.113.20) ... "
ECS_US_ANS=$("$DAG" @127.0.0.1 -p "$PORT2" ecs-test.ext.example.com A +short +subnet=203.0.113.20 2>&1 || true)
if echo "$ECS_US_ANS" | grep -q "172.16.2.2" && echo "$ECS_US_ANS" | grep -q "172.16.0.1" && ! echo "$ECS_US_ANS" | grep -q "172.16.1.1"; then
    echo "OK (Restored \$ECS-SUBNET-TAG us-tier: received 172.16.2.2 and default 172.16.0.1)"
else
    echo "FAILED (Unexpected answer: '$ECS_US_ANS')"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Secondary default answer when no ECS is provided ... "
ECS_NONE_ANS=$("$DAG" @127.0.0.1 -p "$PORT2" ecs-test.ext.example.com A +short +nosubnet 2>&1 || true)
if [ "$ECS_NONE_ANS" = "172.16.0.1" ]; then
    echo "OK (Only default record 172.16.0.1 returned)"
else
    echo "FAILED (Unexpected answer: '$ECS_NONE_ANS')"
    FAILED=$((FAILED + 1))
fi

# ------------------------------------------------------------------------------
# Test 2: Standard AXFR Fallback (Plan B) on Master
# ------------------------------------------------------------------------------
echo ""
echo "=== Test 2: Standard AXFR Fallback (Plan B) on Master ==="

echo -n "Requesting standard AXFR from Master without Option 65153 ... "
STD_AXFR=$("$DAG" ext.example.com AXFR @127.0.0.1 -p "$PORT1" +tcp 2>&1 || true)

if echo "$STD_AXFR" | grep -q "192.168.1.100" && echo "$STD_AXFR" | grep -q "10.0.0.1" && echo "$STD_AXFR" | grep -q "172.16.0.1"; then
    echo "OK (Default records transferred)"
else
    echo "FAILED (Missing default records in standard AXFR)"
    echo "$STD_AXFR"
    FAILED=$((FAILED + 1))
fi

echo -n "Checking that tagged records are NOT leaked in standard AXFR ... "
LEAK_FOUND=0
if echo "$STD_AXFR" | grep -E -q "10\.1\.1\.1|10\.2\.2\.2|172\.16\.1\.1|172\.16\.2\.2"; then
    LEAK_FOUND=1
fi
if echo "$STD_AXFR" | grep -E -q "65401|65402|65403|65404|65405|65406|65302"; then
    LEAK_FOUND=1
fi

if [ "$LEAK_FOUND" -eq 0 ]; then
    echo "OK (Tagged records and internal CLASS 65302 markers properly hidden)"
else
    echo "FAILED (Tagged records or marker RRs leaked into standard AXFR response!)"
    echo "$STD_AXFR"
    FAILED=$((FAILED + 1))
fi

# ------------------------------------------------------------------------------
# Test 3: tinydns Format Extended AXFR Transfer to Secondary
# ------------------------------------------------------------------------------
echo ""
echo "=== Test 3: tinydns Format Extended AXFR to Secondary ==="

echo -n "Waiting for Secondary to transfer tiny.example.com ... "
TINY_OK=0
for i in $(seq 1 30); do
    DEF_TINY=$("$DAG" @127.0.0.1 -p "$PORT2" def.tiny.example.com A +short 2>&1 || true)
    if [ "$DEF_TINY" = "10.99.99.1" ]; then
        TINY_OK=1
        break
    fi
    sleep 0.5
done

if [ "$TINY_OK" -eq 1 ]; then
    echo "OK (Transfer completed)"
else
    echo "FAILED"
    echo "  Secondary tiny query output: '$DEF_TINY'"
    echo "  Secondary log:"
    cat "$TMP_DIR/slave.log"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Secondary tinydns location filtering (%lo matches 127.0.0.1) ... "
SRV_TINY=$("$DAG" @127.0.0.1 -p "$PORT2" srv.tiny.example.com A +short 2>&1 || true)
if echo "$SRV_TINY" | grep -q "10.10.1.1" && echo "$SRV_TINY" | grep -q "10.10.0.1" && ! echo "$SRV_TINY" | grep -q "10.10.2.2"; then
    echo "OK (Restored tinydns %lo tag: received 10.10.1.1 and 10.10.0.1, excluded %re 10.10.2.2)"
else
    echo "FAILED (Unexpected answer: '$SRV_TINY')"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Master standard AXFR of tinydns zone filters location tags ... "
TINY_STD_AXFR=$("$DAG" tiny.example.com AXFR @127.0.0.1 -p "$PORT1" +tcp 2>&1 || true)
if echo "$TINY_STD_AXFR" | grep -q "10.10.0.1" && echo "$TINY_STD_AXFR" | grep -q "10.99.99.1" && \
   ! echo "$TINY_STD_AXFR" | grep -E -q "10\.10\.1\.1|10\.10\.2\.2"; then
    echo "OK (Standard AXFR hid location-specific tinydns records)"
else
    echo "FAILED (Standard AXFR did not filter tagged records properly)"
    echo "$TINY_STD_AXFR"
    FAILED=$((FAILED + 1))
fi

# ------------------------------------------------------------------------------
# Test 4: Dynamic Update & Retransfer to Secondary
# ------------------------------------------------------------------------------
echo ""
echo "=== Test 4: Dynamic Retransfer after Updating Tags on Master ==="

echo -n "Updating Master zone file with new serial and new tag definition ... "
cat << 'EOF' > "$TMP_DIR/ext_bind.zone"
$TTL 300
$ORIGIN ext.example.com.
@       IN  SOA ns1.ext.example.com. hostmaster.ext.example.com. (
            2026090502 ; Bumped Serial
            3600 600 86400 300
)
@       IN  NS  ns1.ext.example.com.
ns1     IN  A   127.0.0.1

$LOCATION-TAG local 127.0.0.1/32
$ECS-SUBNET-TAG asia-tier 198.51.100.0/24

$LOCATION local
loc-test IN A   10.5.5.5
$LOCATION ""
loc-test IN A   10.0.0.1

$ECS-SUBNET asia-tier
ecs-test IN A   172.20.20.20
$ECS-SUBNET ""
ecs-test IN A   172.16.0.1

default-rec IN A 192.168.1.200
EOF

"$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl_master.sock" reload ext.example.com >/dev/null 2>&1
sleep 1
"$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl_slave.sock" retransfer ext.example.com >/dev/null 2>&1

echo -n "Waiting for Secondary to reflect retransferred zone ... "
RETRANS_OK=0
for i in $(seq 1 30); do
    NEW_DEF=$("$DAG" @127.0.0.1 -p "$PORT2" default-rec.ext.example.com A +short 2>&1 || true)
    if [ "$NEW_DEF" = "192.168.1.200" ]; then
        RETRANS_OK=1
        break
    fi
    sleep 0.5
done

if [ "$RETRANS_OK" -eq 1 ]; then
    echo "OK (Retransfer verified)"
else
    echo "FAILED"
    echo "  Secondary query output: '$NEW_DEF'"
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying updated tag records on Secondary ... "
NEW_LOC=$("$DAG" @127.0.0.1 -p "$PORT2" loc-test.ext.example.com A +short 2>&1 || true)
NEW_ECS=$("$DAG" @127.0.0.1 -p "$PORT2" ecs-test.ext.example.com A +short +subnet=198.51.100.5 2>&1 || true)

if echo "$NEW_LOC" | grep -q "10.5.5.5" && echo "$NEW_ECS" | grep -q "172.20.20.20"; then
    echo "OK (Updated location and ECS tag records active on Secondary)"
else
    echo "FAILED (NEW_LOC='$NEW_LOC', NEW_ECS='$NEW_ECS')"
    FAILED=$((FAILED + 1))
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "======================================================================"
    echo "  [SUCCESS] All Extended AXFR Tests Passed Successfully!"
    echo "======================================================================"
    exit 0
else
    echo "======================================================================"
    echo "  [FAILURE] $FAILED test(s) failed."
    echo "======================================================================"
    exit 1
fi

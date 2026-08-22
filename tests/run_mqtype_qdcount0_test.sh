#!/bin/sh
# Test RFC 10029 FORMERR cases and ID preservation:
# 1. QDCOUNT=0 with MQTYPE-Query option (Opcode=0)
# 2. QDCOUNT>=1 with MQTYPE-Response option in Query (Opcode=0)
# 3. NOTIFY (Opcode=4) with MQTYPE-Query option
# 4. UPDATE (Opcode=5) with MQTYPE-Query option
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/.."
TEST_DIR="mqtype_qdcount0_test_dir"

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

cat << EOF > karidns.conf
options {
    port 53531;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    rfc10029-mqtype yes;
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "${SCRIPT_DIR}/zones/example.com.zone";
    };
};
EOF

"$BIN_DIR/karidns" -f karidns.conf > karidns.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "========================================================"
echo "Test 1: QDCOUNT=0 query with MQTYPE-Query option (Opcode=0)"
echo "========================================================"
HEX_PKT1="1234000000000000000000010000291000000000000006001400020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT1" @127.0.0.1 -p 53531 > dag_out1.txt 2>&1 || true
cat dag_out1.txt
grep "status: FORMERR" dag_out1.txt || { echo "FAIL: Test 1 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 4660" dag_out1.txt || { echo "FAIL: Test 1 transaction ID mismatch (expected 0x1234 = 4660)"; exit 1; }
echo "[+] Test 1 passed: ID 0x1234 preserved on FORMERR."

echo "========================================================"
echo "Test 2: QDCOUNT=1 query with MQTYPE-Response option (Opcode=0)"
echo "========================================================"
HEX_PKT2="234500000001000000000001076578616d706c6503636f6d00000100010000291000000000000006001500020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT2" @127.0.0.1 -p 53531 > dag_out2.txt 2>&1 || true
cat dag_out2.txt
grep "status: FORMERR" dag_out2.txt || { echo "FAIL: Test 2 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 9029" dag_out2.txt || { echo "FAIL: Test 2 transaction ID mismatch (expected 0x2345 = 9029)"; exit 1; }
echo "[+] Test 2 passed: ID 0x2345 preserved on FORMERR."

echo "========================================================"
echo "Test 3: NOTIFY query with MQTYPE-Query option (Opcode=4)"
echo "========================================================"
HEX_PKT3="345620000001000000000001076578616d706c6503636f6d00000600010000291000000000000006001400020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT3" @127.0.0.1 -p 53531 > dag_out3.txt 2>&1 || true
cat dag_out3.txt
grep "status: FORMERR" dag_out3.txt || { echo "FAIL: Test 3 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 13398" dag_out3.txt || { echo "FAIL: Test 3 transaction ID mismatch (expected 0x3456 = 13398)"; exit 1; }
echo "[+] Test 3 passed: ID 0x3456 preserved on FORMERR."

echo "========================================================"
echo "Test 4: UPDATE query with MQTYPE-Query option (Opcode=5)"
echo "========================================================"
HEX_PKT4="456728000001000000000001076578616d706c6503636f6d00000600010000291000000000000006001400020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT4" @127.0.0.1 -p 53531 > dag_out4.txt 2>&1 || true
cat dag_out4.txt
grep "status: FORMERR" dag_out4.txt || { echo "FAIL: Test 4 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 17767" dag_out4.txt || { echo "FAIL: Test 4 transaction ID mismatch (expected 0x4567 = 17767)"; exit 1; }
echo "[+] Test 4 passed: ID 0x4567 preserved on FORMERR."

echo "[+] All RFC 10029 FORMERR & ID preservation tests passed successfully!"
exit 0

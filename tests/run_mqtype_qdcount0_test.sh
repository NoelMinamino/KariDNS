#!/bin/sh
# Test RFC 10029 FORMERR cases and ID preservation:
# 1. QDCOUNT=0 with MQTYPE-Query option (Opcode=0)
# 2. QDCOUNT>=1 with MQTYPE-Response option in Query (Opcode=0)
# 3. NOTIFY (Opcode=4) with MQTYPE-Query option
# 4. UPDATE (Opcode=5) with MQTYPE-Query option
# 5-7. QDCOUNT=0 QUERY without OPT, with OPT, with a COOKIE option only (RFC 9619, RFC 7873 5.4)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
PORT=$(kari_port 0 53531)
BIN_DIR="$SCRIPT_DIR/.."
TEST_DIR="mqtype_qdcount0_test_dir"

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

cat << EOF > karidns.conf
options {
    port ${PORT};
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    rfc10029-mqtype yes;
};

control-channel {
    socket "${TEST_DIR_ABS}/ctl.sock";
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
kari_wait_answer "$BIN_DIR/dag" "$PORT" example.com. || true   # the tests below report a server that did not start

cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    kari_kill_tree "${SERVER_PID:-}"
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "========================================================"
echo "Test 1: QDCOUNT=0 query with MQTYPE-Query option (Opcode=0)"
echo "========================================================"
HEX_PKT1="1234000000000000000000010000291000000000000006001400020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT1" @127.0.0.1 -p ${PORT} > dag_out1.txt 2>&1 || true
cat dag_out1.txt
grep "status: FORMERR" dag_out1.txt || { echo "FAIL: Test 1 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 4660" dag_out1.txt || { echo "FAIL: Test 1 transaction ID mismatch (expected 0x1234 = 4660)"; exit 1; }
echo "[+] Test 1 passed: ID 0x1234 preserved on FORMERR."

echo "========================================================"
echo "Test 2: QDCOUNT=1 query with MQTYPE-Response option (Opcode=0)"
echo "========================================================"
HEX_PKT2="234500000001000000000001076578616d706c6503636f6d00000100010000291000000000000006001500020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT2" @127.0.0.1 -p ${PORT} > dag_out2.txt 2>&1 || true
cat dag_out2.txt
grep "status: FORMERR" dag_out2.txt || { echo "FAIL: Test 2 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 9029" dag_out2.txt || { echo "FAIL: Test 2 transaction ID mismatch (expected 0x2345 = 9029)"; exit 1; }
echo "[+] Test 2 passed: ID 0x2345 preserved on FORMERR."

echo "========================================================"
echo "Test 3: NOTIFY query with MQTYPE-Query option (Opcode=4)"
echo "========================================================"
HEX_PKT3="345620000001000000000001076578616d706c6503636f6d00000600010000291000000000000006001400020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT3" @127.0.0.1 -p ${PORT} > dag_out3.txt 2>&1 || true
cat dag_out3.txt
grep "status: FORMERR" dag_out3.txt || { echo "FAIL: Test 3 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 13398" dag_out3.txt || { echo "FAIL: Test 3 transaction ID mismatch (expected 0x3456 = 13398)"; exit 1; }
echo "[+] Test 3 passed: ID 0x3456 preserved on FORMERR."

echo "========================================================"
echo "Test 4: UPDATE query with MQTYPE-Query option (Opcode=5)"
echo "========================================================"
HEX_PKT4="456728000001000000000001076578616d706c6503636f6d00000600010000291000000000000006001400020010"
"$BIN_DIR/dag" "--hex=$HEX_PKT4" @127.0.0.1 -p ${PORT} > dag_out4.txt 2>&1 || true
cat dag_out4.txt
grep "status: FORMERR" dag_out4.txt || { echo "FAIL: Test 4 status is not FORMERR"; cat karidns.log; exit 1; }
grep "id: 17767" dag_out4.txt || { echo "FAIL: Test 4 transaction ID mismatch (expected 0x4567 = 17767)"; exit 1; }
echo "[+] Test 4 passed: ID 0x4567 preserved on FORMERR."

echo "========================================================"
echo "Test 5-7: QDCOUNT=0 QUERY (RFC 9619, RFC 7873 5.4; BIND 9.20)"
echo "========================================================"
# 5. no OPT -> FORMERR, the header only; 6. OPT without COOKIE -> FORMERR with OPT;
# 7. COOKIE only -> NOERROR with the client cookie and a server cookie. UDP and TCP.
HEX_PKT5="567801000000000000000000"
HEX_PKT6="5678010000000000000000010000291000000000000000"
HEX_PKT7="567801000000000000000001000029100000000000000c000a00080102030405060708"
for T in "+udp" "+tcp"; do   # --hex is sent as an ANY query: dag goes to TCP unless +udp is given
    "$BIN_DIR/dag" "--hex=$HEX_PKT5" $T @127.0.0.1 -p ${PORT} > dag_out5.txt 2>&1 || true
    cat dag_out5.txt
    grep -q "status: FORMERR" dag_out5.txt && grep -q "QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0" dag_out5.txt \
        || { echo "FAIL: Test 5 ($T) QDCOUNT=0 without OPT is not a header-only FORMERR"; exit 1; }
    "$BIN_DIR/dag" "--hex=$HEX_PKT6" $T @127.0.0.1 -p ${PORT} > dag_out6.txt 2>&1 || true
    cat dag_out6.txt
    grep -q "status: FORMERR" dag_out6.txt && grep -q "QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1" dag_out6.txt \
        && grep -q "OPT PSEUDOSECTION" dag_out6.txt \
        || { echo "FAIL: Test 6 ($T) QDCOUNT=0 with OPT is not a FORMERR with OPT"; exit 1; }
    # +nocookie: the client cookie is the one in the payload, not dag's own (dag would drop the UDP answer as a mismatch)
    "$BIN_DIR/dag" "--hex=$HEX_PKT7" $T +nocookie @127.0.0.1 -p ${PORT} > dag_out7.txt 2>&1 || true
    cat dag_out7.txt
    grep -q "status: NOERROR" dag_out7.txt && grep -q "COOKIE: 0102030405060708[0-9a-f]\{32\}" dag_out7.txt \
        || { echo "FAIL: Test 7 ($T) cookie-only query is not NOERROR with a server cookie"; exit 1; }
done
echo "[+] Tests 5-7 passed: QDCOUNT=0 FORMERR without COOKIE, NOERROR for a cookie-only query."

echo "[+] All RFC 10029 FORMERR & ID preservation tests passed successfully!"
exit 0

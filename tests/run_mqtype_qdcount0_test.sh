#!/bin/sh
# Test RFC 10029 §3.3: MQTYPE-Query option with QDCOUNT=0 MUST return FORMERR.
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
    if [ -n "$SERVER_PID" ]; then
        kill -9 $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Send raw DNS query using dag --hex=
# Packet breakdown:
# 1234 : ID
# 0000 : Opcode=0, Flags=0
# 0000 : QDCOUNT=0
# 0000 : ANCOUNT=0
# 0000 : NSCOUNT=0
# 0001 : ARCOUNT=1 (OPT)
# 00   : Root name
# 0029 : Type OPT (41)
# 1000 : UDP payload size (4096)
# 00000000 : Ext RCODE / Flags
# 0006 : RDLEN = 6
# 0014 : Option code 20 (MQTYPE-Query)
# 0002 : Option length 2
# 0010 : QTYPE TXT (16)
HEX_PKT="1234000000000000000000010000291000000000000006001400020010"

echo "[+] Sending QDCOUNT=0 query with MQTYPE-Query option via dag --hex=..."
"$BIN_DIR/dag" "--hex=$HEX_PKT" @127.0.0.1 -p 53531 > dag_out.txt 2>&1 || true
cat dag_out.txt

grep "status: FORMERR" dag_out.txt || {
    echo "FAIL: Expected status: FORMERR for QDCOUNT=0 query with MQTYPE-Query"
    cat karidns.log
    exit 1
}

echo "[+] RFC 10029 §3.3 QDCOUNT=0 MQTYPE test passed successfully (FORMERR verified)."
exit 0

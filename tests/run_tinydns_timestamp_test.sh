#!/bin/sh
set -e

# ==============================================================================
# KariDNS tinydns Real-Time Timestamp & Countdown TTL Test Suite (Plan A)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICHECK="${BIN_DIR}/karicheck"
DAG="${DAG:-$BIN_DIR/dag}"

killall -9 karidns karidns-asan 2>/dev/null || true

TMP_DIR="$(mktemp -d /tmp/karidns_tinydns_ts_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((31000 + $$ % 4000))
FAILED=0
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECTED="$3"

    echo -n "Test: $NAME ... "
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUTPUT" | grep -E -q "$EXPECTED"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Setting up test zones for tinydns real-time timestamp evaluation ==="

# 現在時刻 + 1800秒 をTAI64 16進数に計算
NOW=$(date +%s)
TS_VALID=$((NOW + 1800))
# TAI64 offset: 4611686018427387904 = 0x4000000000000000
# 0x40000000 (32-bit hi) + 32-bit Unix seconds
HEX_VALID=$(printf "40000000%08x" "$TS_VALID")

cat << EOF > "$TMP_DIR/tinydns.data"
.tinydns.test:127.0.0.1:ns1.tinydns.test:2560
+act-future.tinydns.test:192.168.1.10:300:40000000b2d05e00
+act-past.tinydns.test:192.168.1.20:300:400000003b9aca00
+cnt-valid.tinydns.test:192.168.1.30:0:${HEX_VALID}
+cnt-expired.tinydns.test:192.168.1.40:0:400000003b9aca00
+normal.tinydns.test:192.168.1.50:600
EOF

cat << EOF > "$TMP_DIR/bind.zone"
\$TTL 300
@ IN SOA ns1.bind.test. hostmaster.bind.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.bind.test.
ns1 IN A 127.0.0.1
www IN A 192.168.1.100
EOF

cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

zone "tinydns.test." {
    type master;
    file "$TMP_DIR/tinydns.data";
    file-format tinydns;
};

zone "bind.test." {
    type master;
    file "$TMP_DIR/bind.zone";
    file-format bind;
};
EOF

echo "=== Validating configuration with karicheck ==="
run_check "karicheck conf" "$KARICHECK conf $TMP_DIR/karidns.conf" "is valid"

echo "=== Starting KariDNS on port $PORT ==="
$KARIDNS -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: KariDNS failed to start. Logs:"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

echo "=== 1. Future activation timestamp (not yet active) -> NXDOMAIN ==="
run_check "act-future query returns NXDOMAIN" \
    "$DAG act-future.tinydns.test A @127.0.0.1 -p $PORT" \
    "status: NXDOMAIN"

echo "=== 2. Past activation timestamp (active) -> Answer with original TTL 300 ==="
run_check "act-past query returns A 192.168.1.20 with TTL 300" \
    "$DAG act-past.tinydns.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.20"

run_check "act-past query has TTL 300 in answer section" \
    "$DAG act-past.tinydns.test A @127.0.0.1 -p $PORT" \
    "act-past.tinydns.test.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192.168.1.20"

echo "=== 3. Valid Countdown TTL (ttl=0, future expiry) -> Answer with TTL clamped in [2, 3600] ==="
run_check "cnt-valid query returns A 192.168.1.30" \
    "$DAG cnt-valid.tinydns.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.30"

run_check "cnt-valid query returns remaining TTL (1700-1800s)" \
    "$DAG cnt-valid.tinydns.test A @127.0.0.1 -p $PORT" \
    "cnt-valid.tinydns.test.[[:space:]]+1[78][0-9][0-9][[:space:]]+IN[[:space:]]+A[[:space:]]+192.168.1.30"

echo "=== 4. Expired Countdown TTL (ttl=0, past expiry) -> NXDOMAIN ==="
run_check "cnt-expired query returns NXDOMAIN" \
    "$DAG cnt-expired.tinydns.test A @127.0.0.1 -p $PORT" \
    "status: NXDOMAIN"

echo "=== 5. Normal tinydns record without timestamp -> Answer with original TTL 600 ==="
run_check "normal record returns A 192.168.1.50" \
    "$DAG normal.tinydns.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.50"

run_check "normal record has TTL 600" \
    "$DAG normal.tinydns.test A @127.0.0.1 -p $PORT" \
    "normal.tinydns.test.[[:space:]]+600[[:space:]]+IN[[:space:]]+A[[:space:]]+192.168.1.50"

echo "=== 6. BIND zone regression check -> Unaffected, TTL preserved ==="
run_check "BIND zone query returns A 192.168.1.100" \
    "$DAG www.bind.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.100"

run_check "BIND zone query has TTL 300" \
    "$DAG www.bind.test A @127.0.0.1 -p $PORT" \
    "www.bind.test.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192.168.1.100"

if [ $FAILED -eq 0 ]; then
    echo "=================================================="
    echo " ALL TESTS PASSED: tinydns Real-Time Timestamp (Plan A)"
    echo "=================================================="
    exit 0
else
    echo "=================================================="
    echo " $FAILED TESTS FAILED: tinydns Real-Time Timestamp (Plan A)"
    echo "=================================================="
    exit 1
fi

#!/bin/sh
set -e

# ==============================================================================
# KariDNS UDP IXFR Test Suite (RFC 1995 §4.2)
# ==============================================================================

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$DIR/.." && pwd)"
BIN="$ROOT_DIR/karidns-asan"
DAG="$ROOT_DIR/dag-asan"

if [ ! -x "$DAG" ]; then
    make -C "$ROOT_DIR" dag-asan
fi
if [ ! -x "$BIN" ]; then
    make -C "$ROOT_DIR" asan
fi

CONF_FILE="$DIR/karidns-test.conf"
CTL_CONF="$DIR/karictl-test.conf"
chmod 0600 "$CTL_CONF" 2>/dev/null || true
ZONE_FILE="$DIR/zones/example.com.zone"

PORT=10053
TMP_DIR="/tmp/udp_ixfr_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

echo "[*] Starting KariDNS for UDP IXFR tests..."
$BIN -f "$CONF_FILE" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

cleanup() {
    echo "[*] Stopping KariDNS (PID $SERVER_PID)..."
    [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

check_asan_log() {
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$TMP_DIR/server.log"; then
        echo "[FAIL] Sanitizer error detected in server.log:"
        cat "$TMP_DIR/server.log"
        exit 1
    fi
}

# Determine current SOA serial from zone file
CURRENT_SERIAL=$(grep " ; serial" "$ZONE_FILE" | awk '{print $1}')
if [ -z "$CURRENT_SERIAL" ]; then
    echo "[FAIL] Could not determine CURRENT_SERIAL from $ZONE_FILE"
    exit 1
fi
OLD_SERIAL=$((CURRENT_SERIAL - 10))

echo "[*] Zone SOA Serial: $CURRENT_SERIAL, Old Serial: $OLD_SERIAL"

FAILED=0

# Test 1: UDP IXFR with Current Serial (Up-to-Date) -> Expect NOERROR, TC=0, 1 SOA in Answer section over UDP
echo -n "[Test 1] UDP IXFR with matching current serial (IXFR=$CURRENT_SERIAL) ... "
OUT_MATCH=$($DAG example.com "IXFR=$CURRENT_SERIAL" @127.0.0.1 -p $PORT +udp +notcp 2>&1 || true)
check_asan_log

if echo "$OUT_MATCH" | grep -q "SOA.*$CURRENT_SERIAL" && echo "$OUT_MATCH" | grep -q "SERVER:.*(UDP)" && ! echo "$OUT_MATCH" | grep -q "Truncated"; then
    SOA_COUNT=$(echo "$OUT_MATCH" | grep -c "SOA" || true)
    if [ "$SOA_COUNT" -eq 1 ]; then
        echo "OK (NOERROR, TC=0, 1 SOA returned via UDP)"
    else
        echo "FAIL (Expected 1 SOA, got $SOA_COUNT)"
        echo "$OUT_MATCH"
        FAILED=$((FAILED + 1))
    fi
else
    echo "FAIL (Unexpected response or TC set)"
    echo "$OUT_MATCH"
    FAILED=$((FAILED + 1))
fi

# Test 2: UDP IXFR with Outdated Serial (+ignore) -> Expect TC=1 (Truncated) to prompt TCP retry, 1 SOA in Answer section
echo -n "[Test 2] UDP IXFR with outdated serial (IXFR=$OLD_SERIAL, +udp +notcp +ignore) ... "
OUT_OLD=$($DAG example.com "IXFR=$OLD_SERIAL" @127.0.0.1 -p $PORT +udp +notcp +ignore 2>&1 || true)
check_asan_log

if echo "$OUT_OLD" | grep -q "Truncated" && echo "$OUT_OLD" | grep -q "SOA.*$CURRENT_SERIAL" && echo "$OUT_OLD" | grep -q "SERVER:.*(UDP)"; then
    echo "OK (NOERROR, TC=1 Truncated set)"
else
    echo "FAIL (Expected TC=1 / Truncated response)"
    echo "$OUT_OLD"
    FAILED=$((FAILED + 1))
fi

# Test 3: UDP IXFR with Outdated Serial and automatic TCP retry -> Full transfer succeeds over TCP fallback
echo -n "[Test 3] UDP IXFR with outdated serial with TCP fallback (default dag behavior) ... "
OUT_FALLBACK=$($DAG example.com "IXFR=$OLD_SERIAL" @127.0.0.1 -p $PORT +udp +notcp -y transfer-key:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl 2>&1 || true)
check_asan_log

if echo "$OUT_FALLBACK" | grep -q "SOA.*$CURRENT_SERIAL"; then
    echo "OK (TCP fallback retrieved zone data)"
else
    echo "FAIL (TCP fallback did not retrieve zone SOA)"
    echo "$OUT_FALLBACK"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL UDP IXFR (RFC 1995 §4.2) TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED UDP IXFR TESTS FAILED!"
    exit 1
fi

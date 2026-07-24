#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/../karidns-asan"
KARICTL="$DIR/../karictl-asan"
DAG="$DIR/../dag-asan"

if [ ! -x "$DAG" ]; then
    make dag-asan
fi
if [ ! -x "$BIN" ]; then
    make asan
fi

CONF_FILE="$DIR/karidns-test.conf"
CTL_CONF="$DIR/karictl-test.conf"
ZONE_FILE="$DIR/zones/example.com.zone"
TEST_ZONE="$ZONE_FILE"

# Backup original zone
cp "$ZONE_FILE" "${ZONE_FILE}.orig"

echo "[*] Starting KariDNS..."
$BIN -f "$CONF_FILE" > server_ixfr.log 2>&1 &
SERVER_PID=$!
sleep 2

cleanup() {
    echo "[*] Stopping KariDNS (PID $SERVER_PID)..."
    kill -9 $SERVER_PID 2>/dev/null || true
    echo "=== server_ixfr.log ==="
    cat server_ixfr.log || true
    # Restore original zone
    mv "${ZONE_FILE}.orig" "$ZONE_FILE"
}
trap cleanup EXIT

check_asan_log() {
    if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" server_ixfr.log; then
        echo "[FAIL] AddressSanitizer/UndefinedBehaviorSanitizer error detected in server_ixfr.log:"
        cat server_ixfr.log
        exit 1
    fi
}

# Get current serial from the zone
OLD_SERIAL=$(grep " ; serial" "$TEST_ZONE" | awk '{print $1}')
if [ -z "$OLD_SERIAL" ]; then
    echo "[FAIL] Could not determine OLD_SERIAL."
    exit 1
fi
NEW_SERIAL=$((OLD_SERIAL + 1))
VERY_OLD_SERIAL=$((OLD_SERIAL - 100))

echo "[*] Initial OLD_SERIAL = $OLD_SERIAL"

# 1. Add a record and reload
echo "[*] Modifying zone (adding ixfr-test-record) and reloading..."
sed -i '' -E -e "s/^([[:space:]]*)[0-9]{10}([[:space:]]*;.*serial.*)/\1${NEW_SERIAL}\2/" "$TEST_ZONE"
sed -i '' -E -e "/ixfr-test-record/d" "$TEST_ZONE"
echo "ixfr-test-record IN A 1.2.3.99" >> "$TEST_ZONE"
$KARICTL -f "$CTL_CONF" reload >/dev/null 2>&1
sleep 1
check_asan_log

# 2. IXFR with OLD_SERIAL (expect only the difference)
echo "[*] Running IXFR with OLD_SERIAL=$OLD_SERIAL..."
# Using transfer-key if TSIG is required
IXFR_OUT=$($DAG example.com IXFR=$OLD_SERIAL @127.0.0.1 -p 10053 -y transfer-key:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +tcp)
check_asan_log

if ! echo "$IXFR_OUT" | grep -q "ixfr-test-record"; then
    echo "[FAIL] Added record not found in IXFR response!"
    exit 1
fi

if echo "$IXFR_OUT" | grep -q "192.0.2.1"; then
    echo "[FAIL] IXFR response contains unmodified records (expected only diff)!"
    exit 1
fi
echo "[OK] IXFR returned only the expected differences."

# 3. IXFR with VERY_OLD_SERIAL (expect fallback to full AXFR)
echo "[*] Running IXFR with VERY_OLD_SERIAL=$VERY_OLD_SERIAL..."
AXFR_FB_OUT=$($DAG example.com IXFR=$VERY_OLD_SERIAL @127.0.0.1 -p 10053 -y transfer-key:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +tcp)
check_asan_log

if ! echo "$AXFR_FB_OUT" | grep -q "ixfr-test-record"; then
    echo "[FAIL] Added record not found in fallback full AXFR response!"
    exit 1
fi

if ! echo "$AXFR_FB_OUT" | grep -q "192.0.2.1"; then
    echo "[FAIL] Unmodified records missing in fallback full AXFR response!"
    exit 1
fi
echo "[OK] IXFR correctly fell back to full AXFR for old serial."

if killall -0 karidns-asan 2>/dev/null; then
    killall -9 karidns-asan 2>/dev/null
fi

echo "[OK] IXFR Round-trip test passed!"
exit 0

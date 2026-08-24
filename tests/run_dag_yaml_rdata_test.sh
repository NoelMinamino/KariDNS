#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML Output RDATA & Section Validation Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag and karidns with make ==="
make -C "$ROOT_DIR" dag karidns

DAG="$ROOT_DIR/dag"
KARIDNS="$ROOT_DIR/karidns"

if [ ! -x "$DAG" ] || [ ! -x "$KARIDNS" ]; then
    echo "dag or karidns binary not found"
    exit 1
fi

FAILED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    echo -n "Test: $NAME ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$EXPECT"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

ZONE_FILE="$ROOT_DIR/tests/zones/example.com.zone"
CONF_FILE="/tmp/karidns_yaml_test.conf"
PORT=15397

killall -9 karidns 2>/dev/null || true
sleep 0.5

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
};

zone "example.com" {
    type master;
    file "$ZONE_FILE";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > /tmp/karidns_yaml_test.log 2>&1 &
SERVER_PID=$!
sleep 0.5

echo "=== 1. Testing YAML Structure & Header Fields ==="
run_check "YAML document start marker" "$DAG @127.0.0.1 -p $PORT example.com A +yaml" "^---"
run_check "YAML header fields" "$DAG @127.0.0.1 -p $PORT example.com A +yaml" "(id:|opcode:|rcode:|flags:|qdcount:)"
run_check "YAML question section" "$DAG @127.0.0.1 -p $PORT example.com A +yaml" "(question:|- name: \"example\.com\.\")"

echo "=== 2. Testing YAML RDATA for Record Types (A, AAAA, MX, TXT, etc.) ==="
# A record
run_check "YAML Answer RDATA for A record" "$DAG @127.0.0.1 -p $PORT www.example.com A +yaml" "rdata: \"192\.0\.2\.10\""
# AAAA record
run_check "YAML Answer RDATA for AAAA record" "$DAG @127.0.0.1 -p $PORT www.example.com AAAA +yaml" "rdata: \"2001:db8::10\""
# MX record
run_check "YAML Answer RDATA for MX record" "$DAG @127.0.0.1 -p $PORT example.com MX +yaml" "rdata: \"10 mail\.example\.com\.\""
# TXT record
run_check "YAML Answer RDATA for TXT record" "$DAG @127.0.0.1 -p $PORT example.com TXT +yaml" "rdata: \".*v=spf1"
# Authority section for NXDOMAIN
run_check "YAML Authority section for NXDOMAIN" "$DAG @127.0.0.1 -p $PORT nonexistent.example.com A +yaml" "(authority:|- name: \"example\.com\.\")"

kill $SERVER_PID 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
rm -f "$CONF_FILE" /tmp/karidns_yaml_test.log

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML RDATA TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML RDATA TESTS FAILED!"
    exit 1
fi

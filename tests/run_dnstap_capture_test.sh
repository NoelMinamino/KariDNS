#!/bin/sh
# ==============================================================================
# run_dnstap_capture_test.sh
#
# Integration test for KariDNS dnstap logging via Frame Streams (fstrm).
# Starts mock_dnstap_receiver.pl, launches karidns with dnstap enabled,
# sends queries with dag, and verifies captured dnstap Protobuf frames.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

PORT=${KARIDNS_TEST_PORT:-$((26000 + $$ % 4000))}
TMP_DIR="/tmp/karidns_dnstap_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

SOCK_PATH="$TMP_DIR/dnstap.sock"
LOG_PATH="$TMP_DIR/dnstap_capture.log"
CONF_PATH="$TMP_DIR/karidns.conf"
ZONE_PATH="$TMP_DIR/example.com.zone"
SERVER_LOG="$TMP_DIR/karidns_server.log"
PID_RECEIVER=""
PID_SERVER=""

cleanup() {
    [ -n "$PID_SERVER" ] && kill -TERM "$PID_SERVER" 2>/dev/null || true
    [ -n "$PID_RECEIVER" ] && kill -TERM "$PID_RECEIVER" 2>/dev/null || true
    pkill -f "$CONF_PATH" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

echo "=== Running KariDNS dnstap Capture Test ==="

KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

# Build binaries
echo "[+] Building karidns..."
make -C "$ROOT_DIR" karidns
echo "[+] Building dag..."
make -C "$ROOT_DIR" dag

# 1. Create Zone File
cat << 'EOF' > "$ZONE_PATH"
$TTL 300
$ORIGIN example.com.
@   IN  SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 900 1209600 300 )
@   IN  NS  ns1.example.com.
ns1 IN  A   127.0.0.1
www IN  A   192.0.2.1
EOF
chmod 644 "$ZONE_PATH"

# 2. Create Conf File
cat << EOF > "$CONF_PATH"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

dnstap {
    socket "$SOCK_PATH";
    identity "karidns-test";
    version "0.3.0";
    log-queries yes;
    log-responses yes;
    queue-size 1024;
};

zone "example.com" {
    type primary;
    file "$ZONE_PATH";
    allow-transfer { 127.0.0.1; };
};
EOF
chmod 644 "$CONF_PATH"
chmod 755 "$TMP_DIR"

# 3. Start mock_dnstap_receiver
echo "[+] Starting mock dnstap receiver on $SOCK_PATH..."
perl "$SCRIPT_DIR/mock_dnstap_receiver.pl" --socket "$SOCK_PATH" --output "$LOG_PATH" --max-frames 6 --timeout 10 &
PID_RECEIVER=$!

# Wait for socket to appear
for i in 1 2 3 4 5; do
    if [ -S "$SOCK_PATH" ]; then
        break
    fi
    sleep 0.2
done

if [ ! -S "$SOCK_PATH" ]; then
    echo "FAIL: mock dnstap receiver socket not created."
    exit 1
fi
chmod 777 "$SOCK_PATH" 2>/dev/null || true

# 4. Start karidns
echo "[+] Starting karidns on port $PORT..."
"$KARIDNS" -f -c "$CONF_PATH" > "$SERVER_LOG" 2>&1 &
PID_SERVER=$!
sleep 1

if ! kill -0 "$PID_SERVER" 2>/dev/null; then
    echo "FAIL: karidns failed to start or crashed immediately. Server log:"
    cat "$SERVER_LOG"
    exit 1
fi

# 5. Send queries via dag
echo "[+] Sending UDP query via dag..."
"$DAG" @127.0.0.1 -p $PORT www.example.com A || true

echo "[+] Sending TCP query via dag..."
"$DAG" @127.0.0.1 -p $PORT +tcp www.example.com A || true

echo "[+] Sending TCP AXFR query via dag..."
"$DAG" @127.0.0.1 -p $PORT +tcp example.com AXFR || true

# 6. Wait for receiver to finish capturing 6 frames (3 queries + 3 responses)
wait $PID_RECEIVER 2>/dev/null || true
PID_RECEIVER=""

# 7. Verify dnstap capture output
echo "[+] Verifying captured dnstap frames..."
if [ ! -s "$LOG_PATH" ]; then
    echo "FAIL: dnstap log file $LOG_PATH is empty or missing."
    if [ -f "$SERVER_LOG" ]; then
        echo "=== karidns server log ==="
        cat "$SERVER_LOG"
    fi
    exit 1
fi

cat "$LOG_PATH"

if grep -q "type=AUTH_QUERY" "$LOG_PATH" && grep -q "type=AUTH_RESPONSE" "$LOG_PATH"; then
    echo "  PASS: Captured both AUTH_QUERY and AUTH_RESPONSE."
else
    echo "FAIL: Missing AUTH_QUERY or AUTH_RESPONSE in dnstap log."
    exit 1
fi

NUM_FRAMES=$(grep -c "^\[DNSTAP\] Frame" "$LOG_PATH" || true)
if [ "$NUM_FRAMES" -ge 6 ]; then
    echo "  PASS: Captured $NUM_FRAMES frames (UDP, TCP, and AXFR responses)."
else
    echo "FAIL: Expected at least 6 frames, got $NUM_FRAMES."
    exit 1
fi

if grep -q "identity=karidns-test" "$LOG_PATH"; then
    echo "  PASS: dnstap identity matched 'karidns-test'."
else
    echo "FAIL: dnstap identity mismatch."
    exit 1
fi

if grep -q "version=0.3.0" "$LOG_PATH"; then
    echo "  PASS: dnstap version matched '0.3.0'."
else
    echo "FAIL: dnstap version mismatch."
    exit 1
fi

# 8. Test require-connect yes enforcement
echo "[+] Testing require-connect yes enforcement..."
if [ -n "$PID_SERVER" ]; then
    kill -TERM "$PID_SERVER" 2>/dev/null || true
    wait "$PID_SERVER" 2>/dev/null || true
    PID_SERVER=""
fi
PORT_REQ=$((PORT + 10))
CONF_REQUIRE_CONNECT="$TMP_DIR/karidns_require_connect.conf"
cat << EOF > "$CONF_REQUIRE_CONNECT"
options {
    port $PORT_REQ;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

dnstap {
    socket "$TMP_DIR/non_existent_dnstap.sock";
    require-connect yes;
    log-queries yes;
};

zone "example.com" {
    type primary;
    file "$ZONE_PATH";
};
EOF

set +e
"$KARIDNS" -f -c "$CONF_REQUIRE_CONNECT" > "$TMP_DIR/require_connect.log" 2>&1
RC_EXIT=$?
set -e

if [ $RC_EXIT -ne 0 ]; then
    echo "  PASS: karidns aborted on start with non-zero exit code ($RC_EXIT) when dnstap socket was missing and require-connect was enabled."
else
    echo "FAIL: karidns unexpectedly succeeded or did not abort when require-connect was enabled. Server log:"
    cat "$TMP_DIR/require_connect.log" 2>/dev/null || true
    exit 1
fi

echo "=== KariDNS dnstap Capture Test Passed Successfully ==="

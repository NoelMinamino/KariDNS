#!/bin/sh
# ==============================================================================
# run_karictl_observatory_test.sh
#
# Integration test for KariDNS DNS Observatory and karictl observatory command.
# Configures a primary zone, starts server, sends varied queries with dag,
# invokes karictl observatory, and validates the per-zone operational stats.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building karidns, karictl, and dag ==="
make -C "$ROOT_DIR" karidns karictl dag

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

PORT=$((25000 + $$ % 5000))
CTRL_PORT=$((PORT + 1))
TMP_DIR="/tmp/karictl_observatory_test_$$"
CTRL_SOCK="$TMP_DIR/control.sock"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

# 1. Prepare Zone
cat << 'EOF' > "$TMP_DIR/obs.example.com.zone"
$TTL 300
@ IN SOA ns1.obs.example.com. hostmaster.obs.example.com. (
    2026091101 ; Serial
    3600 600 86400 300 )
@       IN NS   ns1.obs.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.1
mail    IN A    192.0.2.2
EOF

# 2. Prepare karidns.conf
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

control-channel {
    socket "$CTRL_SOCK";
    algorithm hmac-sha256;
    secret "b2JzZXJ2YXRvcnktdGVzdC1zZWNyZXQta2V5LTAwMQ==";
};

zone "obs.example.com" {
    type primary;
    file "$TMP_DIR/obs.example.com.zone";
};
EOF

# 3. Prepare karictl.conf
cat << EOF > "$TMP_DIR/karictl.conf"
socket "$CTRL_SOCK";
key "karictl" {
    algorithm hmac-sha256;
    secret "b2JzZXJ2YXRvcnktdGVzdC1zZWNyZXQta2V5LTAwMQ==";
};
EOF

chmod 755 "$TMP_DIR"
chmod 644 "$TMP_DIR/obs.example.com.zone" "$TMP_DIR/karidns.conf" "$TMP_DIR/karictl.conf"

# 4. Start Server
echo "[+] Starting karidns on port $PORT (control: $CTRL_SOCK)..."
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns failed to start. Log:"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

# 5. Send Queries via dag
echo "[+] Sending DNS queries to generate observatory metrics..."
# UDP query -> NOERROR
"$DAG" @127.0.0.1 -p $PORT www.obs.example.com A > /dev/null 2>&1 || true

# TCP query -> NOERROR
"$DAG" @127.0.0.1 -p $PORT +tcp mail.obs.example.com A > /dev/null 2>&1 || true

# DNSSEC DO + EDNS query -> NOERROR
"$DAG" @127.0.0.1 -p $PORT +dnssec www.obs.example.com A > /dev/null 2>&1 || true

# Non-existent name -> NXDOMAIN
"$DAG" @127.0.0.1 -p $PORT nonexistent.obs.example.com A > /dev/null 2>&1 || true

# NODATA query (TXT record on name with only A) -> NODATA (NOERROR, ancount=0)
"$DAG" @127.0.0.1 -p $PORT www.obs.example.com TXT > /dev/null 2>&1 || true

sleep 0.5

# 6. Run karictl observatory
echo "[+] Executing karictl observatory..."
OBS_OUT=$("$KARICTL" -s "$CTRL_SOCK" -f "$TMP_DIR/karictl.conf" observatory)
echo "$OBS_OUT"

# 7. Validate Metrics Output
if echo "$OBS_OUT" | grep -q "Zone: obs.example.com"; then
    echo "  PASS: Zone name displayed in observatory output."
else
    echo "  FAIL: Zone name not found in observatory output."
    exit 1
fi

if echo "$OBS_OUT" | grep -q "SOA Serial:            2026091101"; then
    echo "  PASS: SOA serial 2026091101 correctly tracked."
else
    echo "  FAIL: SOA serial incorrect."
    exit 1
fi

if echo "$OBS_OUT" | grep -E -q "Queries Total:[[:space:]]+[4-9]"; then
    echo "  PASS: Queries Total count >= 4."
else
    echo "  FAIL: Queries Total count not incremented."
    exit 1
fi

if echo "$OBS_OUT" | grep -E -q "TCP:[[:space:]]+[1-9]"; then
    echo "  PASS: TCP queries tracked."
else
    echo "  FAIL: TCP queries not incremented."
    exit 1
fi

if echo "$OBS_OUT" | grep -E -q "EDNS=[1-9]"; then
    echo "  PASS: EDNS queries tracked."
else
    echo "  FAIL: EDNS queries not incremented."
    exit 1
fi

if echo "$OBS_OUT" | grep -E -q "DO=[1-9]"; then
    echo "  PASS: DNSSEC DO queries tracked."
else
    echo "  FAIL: DO queries not incremented."
    exit 1
fi

if echo "$OBS_OUT" | grep -E -q "NXDOMAIN=[1-9]"; then
    echo "  PASS: NXDOMAIN responses tracked."
else
    echo "  FAIL: NXDOMAIN responses not incremented."
    exit 1
fi

# 8. Test specific zone query
echo "[+] Testing specific zone query: karictl observatory obs.example.com..."
OBS_SPECIFIC=$("$KARICTL" -s "$CTRL_SOCK" -f "$TMP_DIR/karictl.conf" observatory obs.example.com)
if echo "$OBS_SPECIFIC" | grep -q "Zone: obs.example.com"; then
    echo "  PASS: Specific zone query returned metrics."
else
    echo "  FAIL: Specific zone query failed."
    exit 1
fi

echo "=== All DNS Observatory Tests Passed! ==="

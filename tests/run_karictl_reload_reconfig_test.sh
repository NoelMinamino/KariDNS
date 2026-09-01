#!/bin/sh
set -e

# ==============================================================================
# KariDNS karictl reload & reconfig Behavior Test Suite
#
# Verifies:
# 1. Unchanged zones are skipped during 'reconfig' (mtime match).
# 2. Changed zones are reloaded during 'reconfig', while unchanged zones are skipped.
# 3. Full 'reload' (no args) re-reads karidns.conf and adds new zones.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building karidns, karictl, and dag with make ==="
make -C "$ROOT_DIR" karidns karictl dag

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

FAILED=0
PORT=$((21000 + $$ % 8000))
CTRL_PORT=$((PORT + 1))
TMP_DIR="/tmp/karictl_reload_reconfig_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Prepare initial zone files
cat << 'EOF' > "$TMP_DIR/zone1.example.com.zone"
$TTL 300
@ IN SOA ns1.zone1.example.com. hostmaster.zone1.example.com. (
    2026090101 ; Serial
    3600       ; Refresh
    600        ; Retry
    86400      ; Expire
    300        ; Minimum
)
@       IN NS   ns1.zone1.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.1
EOF

cat << 'EOF' > "$TMP_DIR/zone2.example.com.zone"
$TTL 300
@ IN SOA ns1.zone2.example.com. hostmaster.zone2.example.com. (
    2026090101 ; Serial
    3600       ; Refresh
    600        ; Retry
    86400      ; Expire
    300        ; Minimum
)
@       IN NS   ns1.zone2.example.com.
ns1     IN A    127.0.0.1
app     IN A    192.0.2.2
EOF

# Prepare configuration
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    port $CTRL_PORT;
    bind-address 127.0.0.1;
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "zone1.example.com" {
        type master;
        file "$TMP_DIR/zone1.example.com.zone";
    };
    zone "zone2.example.com" {
        type master;
        file "$TMP_DIR/zone2.example.com.zone";
    };
};
EOF

cat << EOF > "$TMP_DIR/karictl.conf"
server 127.0.0.1;
port $CTRL_PORT;
key "karictl" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF

# Kill any existing server and start local test server
killall -9 karidns 2>/dev/null || true
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

echo "=== 1. Testing 'reconfig' when zone files are UNCHANGED ==="
echo -n "Test: 'reconfig' skips reload for unchanged zones (mtime match) ... "
"$KARICTL" -f "$TMP_DIR/karictl.conf" reconfig >/dev/null 2>&1
sleep 0.5
if grep -q "zone 'zone1\.example\.com\.' file unchanged (mtime match), skipping reload" "$TMP_DIR/karidns.log" && \
   grep -q "zone 'zone2\.example\.com\.' file unchanged (mtime match), skipping reload" "$TMP_DIR/karidns.log"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Log tail:"
    tail -n 20 "$TMP_DIR/karidns.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing 'reconfig' when ONLY ONE zone file is CHANGED ==="
sleep 1 # Ensure timestamp advances
cat << 'EOF' > "$TMP_DIR/zone1.example.com.zone"
$TTL 300
@ IN SOA ns1.zone1.example.com. hostmaster.zone1.example.com. (
    2026090102 ; Serial (updated)
    3600
    600
    86400
    300
)
@       IN NS   ns1.zone1.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.100 ; Updated IP
EOF

echo -n "Test: 'reconfig' reloads only changed zone1 and skips unchanged zone2 ... "
"$KARICTL" -f "$TMP_DIR/karictl.conf" reconfig >/dev/null 2>&1
sleep 0.5

OUT1=$("$DAG" @127.0.0.1 -p $PORT www.zone1.example.com A +short 2>&1 || true)
if [ "$OUT1" = "192.0.2.100" ] && \
   grep -q "Reload successful for 'zone1\.example\.com\.'" "$TMP_DIR/karidns.log" && \
   grep -q "zone 'zone2\.example\.com\.' file unchanged (mtime match), skipping reload" "$TMP_DIR/karidns.log"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Query result for zone1: $OUT1"
    echo "  Log tail:"
    tail -n 20 "$TMP_DIR/karidns.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 3. Testing full 'reload' (no args) when a NEW ZONE is added to karidns.conf ==="
cat << 'EOF' > "$TMP_DIR/zone3.example.com.zone"
$TTL 300
@ IN SOA ns1.zone3.example.com. hostmaster.zone3.example.com. (
    2026090101 ; Serial
    3600
    600
    86400
    300
)
@       IN NS   ns1.zone3.example.com.
ns1     IN A    127.0.0.1
api     IN A    192.0.2.33
EOF

cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    port $CTRL_PORT;
    bind-address 127.0.0.1;
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "zone1.example.com" {
        type master;
        file "$TMP_DIR/zone1.example.com.zone";
    };
    zone "zone2.example.com" {
        type master;
        file "$TMP_DIR/zone2.example.com.zone";
    };
    zone "zone3.example.com" {
        type master;
        file "$TMP_DIR/zone3.example.com.zone";
    };
};
EOF

echo -n "Test: Full 'reload' (no args) re-reads karidns.conf and loads newly added zone3 ... "
"$KARICTL" -f "$TMP_DIR/karictl.conf" reload >/dev/null 2>&1
sleep 0.5

OUT3=$("$DAG" @127.0.0.1 -p $PORT api.zone3.example.com A +short 2>&1 || true)
if [ "$OUT3" = "192.0.2.33" ]; then
    echo "OK"
else
    echo "FAILED"
    echo "  Query result for zone3: $OUT3 (expected 192.0.2.33)"
    echo "  Log tail:"
    tail -n 20 "$TMP_DIR/karidns.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL KARICTL RELOAD / RECONFIG TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

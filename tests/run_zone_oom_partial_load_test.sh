#!/bin/sh
set -e

# ==============================================================================
# KariDNS Zone Load OOM Fault Injection & Partial Load Test Suite
#
# Verifies Task 3 fixes:
# 1. When create_new_zone_entry() fails (OOM), KariDNS does NOT crash.
# 2. Failed zone is skipped without leaving NULL holes in vs->entries[].
# 3. syslog records error: "[Core] Failed to allocate memory for zone '...' in view '...', skipping this zone this reload cycle".
# 4. Non-failing zones are loaded correctly and respond to DNS queries.
# 5. old_snap reads with holes / subsequent reloads do not crash.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/karictl" ] && [ -x "$ROOT_DIR/dag" ] || {
    echo "=== Building karidns, karictl, and dag with make ==="
    [ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/karictl" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns karictl dag
}

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

FAILED=0
PORT=$((23000 + $$ % 8000))
CTRL_PORT=$((PORT + 1))
TMP_DIR="/tmp/zone_oom_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Build the OOM wrapper shared library
echo "=== Building OOM wrapper shared library ==="
cc -shared -fPIC -I"$ROOT_DIR" -o "$TMP_DIR/oom_zone_wrapper.so" "$ROOT_DIR/tests/oom_zone_wrapper.c" -ldl -lpthread

# Prepare 3 zone files
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
www     IN A    192.0.2.2
EOF

cat << 'EOF' > "$TMP_DIR/zone3.example.com.zone"
$TTL 300
@ IN SOA ns1.zone3.example.com. hostmaster.zone3.example.com. (
    2026090101 ; Serial
    3600       ; Refresh
    600        ; Retry
    86400      ; Expire
    300        ; Minimum
)
@       IN NS   ns1.zone3.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.3
EOF

# Configuration containing all 3 zones
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

cat << EOF > "$TMP_DIR/karictl.conf"
server 127.0.0.1;
port $CTRL_PORT;
key "karictl" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF

# Kill any existing server
killall -9 karidns 2>/dev/null || true

echo "=== 1. Starting KariDNS with fault-injected OOM on zone2 (call #1) ==="
# OOM_FAIL_NTH_ZONE_CALLOC=1 will fail create_new_zone_entry() for the 2nd zone (zone2.example.com)
OOM_FAIL_NTH_ZONE_CALLOC=1 LD_PRELOAD="$TMP_DIR/oom_zone_wrapper.so" "$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1.5

# Test 1: Server survival
echo -n "Test 1: Server survives startup with OOM on zone2 ... "
if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "OK"
else
    echo "FAILED (Server crashed on startup!)"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

# Test 2: Error log verification
echo -n "Test 2: Check error logged in syslog/output for skipped zone2 ... "
if grep -q "Failed to allocate memory for zone 'zone2\.example\.com\.*' in view 'default', skipping this zone this reload cycle" "$TMP_DIR/karidns.log"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Expected error log not found in log output:"
    cat "$TMP_DIR/karidns.log"
    FAILED=$((FAILED + 1))
fi

# Test 3: Zone1 query returns 192.0.2.1
echo -n "Test 3: Query zone1.example.com returns 192.0.2.1 ... "
OUT1=$("$DAG" @127.0.0.1 -p $PORT www.zone1.example.com A +short 2>&1 || true)
if [ "$OUT1" = "192.0.2.1" ]; then
    echo "OK"
else
    echo "FAILED (got '$OUT1', expected '192.0.2.1')"
    FAILED=$((FAILED + 1))
fi

# Test 4: Zone3 query returns 192.0.2.3 (shows entries after skipped zone are indexed properly)
echo -n "Test 4: Query zone3.example.com returns 192.0.2.3 ... "
OUT3=$("$DAG" @127.0.0.1 -p $PORT www.zone3.example.com A +short 2>&1 || true)
if [ "$OUT3" = "192.0.2.3" ]; then
    echo "OK"
else
    echo "FAILED (got '$OUT3', expected '192.0.2.3')"
    FAILED=$((FAILED + 1))
fi

# Test 5: Zone2 query is REFUSED or NXDOMAIN (was not loaded)
echo -n "Test 5: Query zone2.example.com is not resolved ... "
OUT2=$("$DAG" @127.0.0.1 -p $PORT www.zone2.example.com A +short 2>&1 || true)
if [ "$OUT2" != "192.0.2.2" ]; then
    echo "OK"
else
    echo "FAILED (zone2 should not have been loaded, but returned '$OUT2')"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing subsequent reload (old_snap traversal & recovery) ==="
# Trigger karictl reload. Since OOM_FAIL_NTH_ZONE_CALLOC was for call #1 (which already fired),
# subsequent calloc calls succeed, and old_snap is traversed without crashes.
echo -n "Test 6: karictl reload completes and server stays alive ... "
"$KARICTL" -f "$TMP_DIR/karictl.conf" reload >/dev/null 2>&1 || true
sleep 1

if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "OK"
else
    echo "FAILED (Server crashed during reload!)"
    cat "$TMP_DIR/karidns.log"
    FAILED=$((FAILED + 1))
fi

echo -n "Test 7: After reload, zone2 is recovered and resolves to 192.0.2.2 ... "
OUT2_RELOAD=$("$DAG" @127.0.0.1 -p $PORT www.zone2.example.com A +short 2>&1 || true)
if [ "$OUT2_RELOAD" = "192.0.2.2" ]; then
    echo "OK"
else
    echo "FAILED (got '$OUT2_RELOAD', expected '192.0.2.2')"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL ZONE OOM PARTIAL LOAD TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

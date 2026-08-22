#!/bin/sh
# Test BIND-compatible TTL unit suffix parsing (w/d/h/m/s)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"
TEST_DIR="ttl_suffix_test_dir"

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

echo "[+] Checking zone syntax with karicheck..."
"$BIN_DIR/karicheck" zone example.com "$ZONES_DIR/ttl_suffix_test.zone" || {
    echo "FAIL: karicheck rejected ttl_suffix_test.zone"
    exit 1
}

cat << EOF > karidns.conf
options {
    port 53532;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "${ZONES_DIR}/ttl_suffix_test.zone";
    };
};
EOF

"$BIN_DIR/karidns" -f karidns.conf > karidns.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[+] Testing query for SOA (default $TTL 1D -> 86400)..."
"$BIN_DIR/dag" example.com. SOA @127.0.0.1 -p 53532 > out_soa.txt 2>&1
cat out_soa.txt
grep "86400" out_soa.txt || { echo "FAIL: Expected TTL 86400 for SOA"; cat karidns.log; exit 1; }

echo "[+] Testing query for NS (TTL 3h -> 10800)..."
"$BIN_DIR/dag" example.com. NS @127.0.0.1 -p 53532 > out_ns.txt 2>&1
cat out_ns.txt
grep "10800" out_ns.txt || { echo "FAIL: Expected TTL 10800 for NS"; cat karidns.log; exit 1; }

echo "[+] Testing query for www.example.com. A (TTL 90 -> 90)..."
"$BIN_DIR/dag" www.example.com. A @127.0.0.1 -p 53532 > out_www.txt 2>&1
cat out_www.txt
grep "90" out_www.txt || { echo "FAIL: Expected TTL 90 for www A"; cat karidns.log; exit 1; }

echo "[+] Testing query for mixed.example.com. A (TTL 1h30m -> 5400)..."
"$BIN_DIR/dag" mixed.example.com. A @127.0.0.1 -p 53532 > out_mixed.txt 2>&1
cat out_mixed.txt
grep "5400" out_mixed.txt || { echo "FAIL: Expected TTL 5400 for mixed A"; cat karidns.log; exit 1; }

echo "[+] All TTL unit suffix parsing tests passed successfully!"
exit 0

#!/bin/sh
# ==============================================================================
# run_dag_replay_diff_test.sh
#
# Integration test for dag DNS Replay and Differential Testing engine.
# Tests text query file replay, differential comparison across two servers,
# rate limiting, worker thread pool, and JSON / text reporting.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$BASE_DIR"

PORT1=${KARIDNS_REPLAY_PORT1:-$((28000 + $$ % 1000))}
PORT2=$((PORT1 + 1))

TMP_DIR="$(mktemp -d /tmp/karidns_replay_test.XXXXXX)"
CONF1="$TMP_DIR/server1.conf"
CONF2="$TMP_DIR/server2.conf"
ZONE1="$TMP_DIR/server1.zone"
ZONE2="$TMP_DIR/server2.zone"
QUERY_FILE="$TMP_DIR/queries.txt"
PID1=""
PID2=""
LOG1="$TMP_DIR/server1.log"
LOG2="$TMP_DIR/server2.log"

cleanup() {
    [ -n "$PID1" ] && kill "$PID1" 2>/dev/null || true
    [ -n "$PID2" ] && kill "$PID2" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

echo "=== Running dag DNS Replay & Differential Testing Suite ==="

# Build binaries if missing
if [ ! -f ./karidns ]; then
    echo "[+] Building karidns..."
    make karidns
fi
if [ ! -f ./dag ]; then
    echo "[+] Building dag..."
    make dag
fi

# 1. Prepare Zones
# Zone 1
cat << 'EOF' > "$ZONE1"
$ORIGIN example.com.
$TTL 300
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1
match1  IN  A   192.0.2.1
match2  IN  A   192.0.2.2
differ  IN  A   192.0.2.10
EOF

# Zone 2 (differ record differs)
cat << 'EOF' > "$ZONE2"
$ORIGIN example.com.
$TTL 300
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1
match1  IN  A   192.0.2.1
match2  IN  A   192.0.2.2
differ  IN  A   192.0.2.99
EOF

# 2. Prepare Configs
cat << EOF > "$CONF1"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    $USER_OPT
};
zone "example.com" {
    type primary;
    file "$ZONE1";
};
EOF

cat << EOF > "$CONF2"
options {
    port $PORT2;
    bind-address { 127.0.0.1; };
    $USER_OPT
};
zone "example.com" {
    type primary;
    file "$ZONE2";
};
EOF

# 3. Prepare Query File
cat << 'EOF' > "$QUERY_FILE"
match1.example.com A
match2.example.com A
differ.example.com A
EOF

chmod 755 "$TMP_DIR"
chmod 644 "$CONF1" "$CONF2" "$ZONE1" "$ZONE2" "$QUERY_FILE"

# 4. Start Servers
echo "[+] Starting Server 1 on 127.0.0.1:$PORT1..."
./karidns -f -c "$CONF1" > "$LOG1" 2>&1 &
PID1=$!

echo "[+] Starting Server 2 on 127.0.0.1:$PORT2..."
./karidns -f -c "$CONF2" > "$LOG2" 2>&1 &
PID2=$!
sleep 1

if ! kill -0 "$PID1" 2>/dev/null; then
    echo "FAIL: Server 1 failed to start. Log:"
    cat "$LOG1"
    exit 1
fi
if ! kill -0 "$PID2" 2>/dev/null; then
    echo "FAIL: Server 2 failed to start. Log:"
    cat "$LOG2"
    exit 1
fi

# 5. Test 1: Single Server Replay
echo "[+] Test 1: Single server replay..."
OUT1=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1")
echo "$OUT1"
if echo "$OUT1" | grep -q "Server 1: 3 responses"; then
    echo "  PASS: Single server replay completed with 3 responses."
else
    echo "FAIL: Expected 3 responses from server 1."
    exit 1
fi

# 6. Test 2: Differential Replay with Text Report
echo "[+] Test 2: Differential replay (text output)..."
OUT2=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff)
echo "$OUT2"
if echo "$OUT2" | grep -q "Identical responses: 2" && echo "$OUT2" | grep -q "Mismatched responses: 1"; then
    echo "  PASS: Differential test detected 2 matching and 1 differing response."
else
    echo "FAIL: Differential test mismatch count unexpected."
    exit 1
fi

# 7. Test 3: Differential Replay with JSON Output
echo "[+] Test 3: Differential replay (JSON output)..."
OUT3=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output json)
echo "$OUT3"
if echo "$OUT3" | grep -q '"mismatched_queries": 1' && echo "$OUT3" | grep -q '"identical_queries": 2'; then
    echo "  PASS: JSON report accurately reported identical and mismatched query counts."
else
    echo "FAIL: JSON output did not contain expected fields."
    exit 1
fi

# 8. Test 4: Rate Limiting & Max Queries
echo "[+] Test 4: Rate limit and max-queries limit..."
OUT4=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1" --rate 50 --workers 2 --max-queries 2)
echo "$OUT4"
if echo "$OUT4" | grep -q "Server 1: 2 responses"; then
    echo "  PASS: Max queries limit (2) correctly enforced."
else
    echo "FAIL: Max queries limit not enforced."
    exit 1
fi

echo "=== All dag DNS Replay & Differential Tests Passed! ==="

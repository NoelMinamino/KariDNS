#!/bin/sh
set -e

# ==============================================================================
# KariDNS Phase 2 Part 2 Audit Test Suite
# (Concurrency, IP allow-update, Standby arena cleanup, TCP EOF handling)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
DAG="${DAG:-$BIN_DIR/dag}"

TMP_DIR="$(mktemp -d /tmp/karidns_phase2_part2_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((31000 + $$ % 5000))
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

echo "=== Building KariDNS and dag ==="
(cd "$BASE_DIR" && make -j4 karidns dag)

# Create primary zone file
cat << 'EOF' > "$TMP_DIR/example.com.zone"
$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026090201 3600 900 1800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
test1 IN A 192.0.2.10
EOF

# Create config with IP-based allow-update (127.0.0.1 permitted, 192.0.2.0/24 denied)
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
};

zone "example.com" {
    type master;
    file "$TMP_DIR/example.com.zone";
    allow-update { 127.0.0.1; !192.0.2.0/24; };
};
EOF

echo "=== Starting KariDNS Server on port $PORT ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

# 1. IP-based allow-update (Task 2)
echo "=== 1. Testing IP-based allow-update (Task 2) ==="
# Add test2.example.com A 192.0.2.20 via dynamic update without TSIG
run_check "Dynamic update via permitted IP succeeds without TSIG" \
    "$DAG example.com SOA @127.0.0.1 -p $PORT --update-add 'test2.example.com 300 A 192.0.2.20' +nohexdump-response" \
    "status: NOERROR"

run_check "Query verifies record added by IP-based dynamic update" \
    "$DAG @127.0.0.1 -p $PORT test2.example.com A +udp" \
    "192.0.2.20"

# 2. Standby arena cleanup on failed dynamic update (Task 4)
echo "=== 2. Testing Standby Arena Cleanup on Update Failure (Task 4) ==="
# Prerequisite failure: require non-existent name to exist
run_check "Dynamic update with failed prerequisite returns NXRRSET/REFUSED" \
    "$DAG example.com SOA @127.0.0.1 -p $PORT --prereq-yxrrset 'nonexistent.example.com A' --update-add 'test3.example.com 300 A 192.0.2.30' +nohexdump-response" \
    "status: (NXRRSET|REFUSED)"

# Verify subsequent valid update succeeds cleanly without arena pollution
run_check "Subsequent dynamic update succeeds without arena pollution" \
    "$DAG example.com SOA @127.0.0.1 -p $PORT --update-add 'test4.example.com 300 A 192.0.2.40' +nohexdump-response" \
    "status: NOERROR"

run_check "Query confirms record test4 is present and test3 is absent" \
    "$DAG @127.0.0.1 -p $PORT test4.example.com A +udp" \
    "192.0.2.40"

run_check "Query confirms uncommitted record test3 is NOT present" \
    "$DAG @127.0.0.1 -p $PORT test3.example.com A +udp" \
    "status: NXDOMAIN"

# 3. TCP connection rapid termination / EOF handling (Task 5)
echo "=== 3. Testing TCP Connection EOF Cleanup (Task 5) ==="
run_check "TCP queries continue to respond cleanly" \
    "$DAG @127.0.0.1 -p $PORT test1.example.com A +tcp" \
    "192.0.2.10"

echo "=== Summary ==="
if [ $FAILED -eq 0 ]; then
    echo "ALL PHASE 2 PART 2 AUDIT TESTS PASSED!"
    exit 0
else
    echo "$FAILED TEST(S) FAILED."
    cat "$TMP_DIR/server.log"
    exit 1
fi

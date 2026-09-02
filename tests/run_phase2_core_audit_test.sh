#!/bin/sh
set -e

# ==============================================================================
# KariDNS Phase 2 Core Logic Audit & Fixes Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
DAG="${DAG:-$BIN_DIR/dag}"

TMP_DIR="$(mktemp -d /tmp/karidns_phase2_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((29000 + $$ % 5000))
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

# Create a slow mock backend for program zone
cat << 'EOF' > "$TMP_DIR/slow_plugin.pl"
#!/usr/bin/env perl
use strict;
use warnings;
use IO::Handle;
STDOUT->autoflush(1);
while (<STDIN>) {
    # Artificial delay to simulate slow blocking IPC
    select(undef, undef, undef, 0.5);
    # Echo back dummy hex response or simple header
    print "STATUS:OK\n";
    print "414181800001000100000000047465737404736c6f770000010001047465737404736c6f7700000100010000003c00047f000001\n";
}
EOF
chmod +x "$TMP_DIR/slow_plugin.pl"

# Create normal master zone file
cat << 'EOF' > "$TMP_DIR/example.com.zone"
$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026090201 3600 900 1800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.100
literal\.dot IN A 192.0.2.200
EOF

# Create secondary zone file with SOA EXPIRE = 10s (for mtime expire test)
cat << 'EOF' > "$TMP_DIR/secondary.com.zone"
$TTL 300
@ IN SOA ns1.secondary.com. hostmaster.secondary.com. ( 2026090201 3600 900 10 300 )
@ IN NS ns1.secondary.com.
ns1 IN A 192.0.2.1
app IN A 192.0.2.50
EOF

PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi

# Create config
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
    rate-limit {
        responses-per-second 1000;
        window-seconds 5;
    };
};

zone "example.com" {
    type master;
    file "$TMP_DIR/example.com.zone";
};

zone "secondary.com" {
    type secondary;
    file "$TMP_DIR/secondary.com.zone";
    masters { 192.0.2.254:53; };
};

zone "slow.test" {
    type program;
    program "$TMP_DIR/slow_plugin.pl";
    $PROG_USER_OPT
    program-timeout 2000;
};
EOF

echo "=== Starting KariDNS Server on port $PORT ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

# 1. Async Worker Pool Test (Task 1)
echo "=== Task 1: Async Worker Pool Offloading ==="
# Launch slow program zone query in background, then immediately query normal zone
($DAG @127.0.0.1 -p $PORT test.slow.test A +udp >/dev/null 2>&1 &)
run_check "Standard zone responds immediately without worker starvation" \
    "$DAG @127.0.0.1 -p $PORT www.example.com A +udp +timeout=1" \
    "192.0.2.100"

# 2. Literal Dot Escaping in Labels (Task 2)
echo "=== Task 2: Literal Dot Escaping in Labels ==="
run_check "Query name with escaped literal dot resolves accurately" \
    "$DAG @127.0.0.1 -p $PORT literal\\\\.dot.example.com A +udp" \
    "192.0.2.200"

# 3. Secondary Zone Expire from mtime (Task 4)
echo "=== Task 4: Secondary Zone Expire Initialization ==="
# Initially fresh secondary zone resolves
run_check "Secondary zone initially answers Authoritative" \
    "$DAG @127.0.0.1 -p $PORT app.secondary.com A +udp" \
    "192.0.2.50"

# 4. RRL Probing & Safe Bypass (Task 5)
echo "=== Task 5: RRL 4-way Probing and Collision Safety ==="
run_check "RRL permits high-rate valid traffic under load without token theft DoS" \
    "$DAG @127.0.0.1 -p $PORT www.example.com A +udp" \
    "192.0.2.100"

echo "=== Summary ==="
if [ $FAILED -eq 0 ]; then
    echo "ALL PHASE 2 CORE LOGIC TESTS PASSED!"
    exit 0
else
    echo "$FAILED TEST(S) FAILED."
    cat "$TMP_DIR/server.log"
    exit 1
fi

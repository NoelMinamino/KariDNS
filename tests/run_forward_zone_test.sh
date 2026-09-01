#!/bin/sh
set -e

# ==============================================================================
# KariDNS type "forward" Zone Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICHECK="${BIN_DIR}/karicheck"
DAG="${DAG:-$BIN_DIR/dag}"
MOCK_SERVER="${BASE_DIR}/tests/mock_dns_server.pl"

# Ensure clean slate before running
killall -9 karidns karidns-asan 2>/dev/null || true

TMP_DIR="$(mktemp -d /tmp/karidns_forward_test.XXXXXX)"
SERVER_PID=""
MOCK_PID1=""
MOCK_PID2=""
MOCK_MISMATCH_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$MOCK_PID1" ]; then
        kill -9 "$MOCK_PID1" 2>/dev/null || true
    fi
    if [ -n "$MOCK_PID2" ]; then
        kill -9 "$MOCK_PID2" 2>/dev/null || true
    fi
    if [ -n "$MOCK_MISMATCH_PID" ]; then
        kill -9 "$MOCK_MISMATCH_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((29000 + $$ % 4000))
MOCK_PORT1=$((PORT + 10))
MOCK_PORT2=$((PORT + 20))
MOCK_MISMATCH_PORT=$((PORT + 30))
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

echo "=== 1. Testing karicheck validation for type forward ==="

cat << EOF > "$TMP_DIR/no_forwarders.conf"
zone "corp.example.com." {
    type forward;
};
EOF

run_check "karicheck rejects type forward when forwarders is missing" \
    "$KARICHECK conf $TMP_DIR/no_forwarders.conf" \
    "has type 'forward' but no 'forwarders' specified"

cat << EOF > "$TMP_DIR/valid_forward.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
};

zone "corp.example.com." {
    type forward;
    forwarders { 127.0.0.1 port $MOCK_PORT1; 127.0.0.1 port $MOCK_PORT2; };
    forward-timeout 1000;
};
EOF

run_check "karicheck accepts valid type forward configuration" \
    "$KARICHECK conf $TMP_DIR/valid_forward.conf" \
    "Config file .* is valid"

echo ""
echo "=== 2. Starting Mock Upstream DNS Servers ==="

# Mock Server 1 (Standard upstream responding to ttl-test.example -> A 192.0.2.1)
perl "$MOCK_SERVER" --port "$MOCK_PORT1" --host 127.0.0.1 > "$TMP_DIR/mock1.log" 2>&1 &
MOCK_PID1=$!

# Mock Server 2 (Backup upstream)
perl "$MOCK_SERVER" --port "$MOCK_PORT2" --host 127.0.0.1 > "$TMP_DIR/mock2.log" 2>&1 &
MOCK_PID2=$!

# Mock Server with Question Mismatch
cat << 'PERL_EOF' > "$TMP_DIR/mock_mismatch.pl"
#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket::INET;
my $port = shift || 10555;
my $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die $!;
while (1) {
    my $req;
    my $peer = $sock->recv($req, 65535);
    next unless defined $peer && length($req) >= 12;
    my $id = substr($req, 0, 2);
    # Intentionally return mismatched question section: mismatched.example instead of requested name
    my $mismatched_q = "\x0amismatched\x07example\x00\x00\x01\x00\x01";
    my $resp = $id . "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" . $mismatched_q . $mismatched_q . "\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01";
    $sock->send($resp, 0, $peer);
}
PERL_EOF
perl "$TMP_DIR/mock_mismatch.pl" "$MOCK_MISMATCH_PORT" > "$TMP_DIR/mock_mismatch.log" 2>&1 &
MOCK_MISMATCH_PID=$!

sleep 1

echo ""
echo "=== 3. Testing KariDNS execution with type forward zone ==="

DEAD_PORT=$((PORT + 99))
cat << EOF > "$TMP_DIR/karidns_forward.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

zone "ttl-test.example." {
    type forward;
    forwarders { 127.0.0.1 port $MOCK_PORT1; };
    forward-timeout 1000;
};

zone "fwd-dead.example." {
    type forward;
    forwarders { 127.0.0.1 port $DEAD_PORT; };
    forward-timeout 500;
};

zone "failover.ttl.test." {
    type forward;
    forwarders { 127.0.0.1 port $DEAD_PORT; 127.0.0.1 port $MOCK_PORT2; };
    forward-timeout 500;
};

zone "fwd-mismatch.example." {
    type forward;
    forwarders { 127.0.0.1 port $MOCK_MISMATCH_PORT; };
    forward-timeout 500;
};
EOF

"$KARIDNS" -f "$TMP_DIR/karidns_forward.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

# Scenario 2: Normal query relay through single forwarder
run_check "Query to forward zone returns upstream-generated response" \
    "$DAG @127.0.0.1 -p $PORT ttl-test.example A +timeout=2 +tries=1" \
    "(192\.0\.2\.1|NOERROR)"

# Scenario 3: Dead upstream returns SERVFAIL immediately instead of hanging
run_check "Query to unreachable forwarder returns SERVFAIL" \
    "$DAG @127.0.0.1 -p $PORT test.fwd-dead.example A +timeout=2 +tries=1" \
    "SERVFAIL"

# Scenario 4: Failover to second forwarder when first is dead
run_check "Query fails over to second forwarder when first is unreachable" \
    "$DAG @127.0.0.1 -p $PORT host.failover.ttl.test A +timeout=2 +tries=1" \
    "(192\.0\.2\.1|NOERROR)"

# Scenario 5: Mismatched Question section is discarded and results in SERVFAIL
run_check "Mismatched question section from upstream is rejected and returns SERVFAIL" \
    "$DAG @127.0.0.1 -p $PORT test.fwd-mismatch.example A +timeout=2 +tries=1" \
    "SERVFAIL"

# Scenario 6: Mixed-case (0x20 encoding) question section matches properly
run_check "Mixed-case query to forward zone returns upstream-generated response" \
    "$DAG @127.0.0.1 -p $PORT TtL-TeSt.ExAmPlE A +timeout=2 +tries=1" \
    "(192\.0\.2\.1|NOERROR)"

# Scenario 7: NOTIFY and UPDATE return NOTIMP
run_check "NOTIFY to forward zone is rejected with NOTIMP" \
    "$DAG @127.0.0.1 -p $PORT ttl-test.example SOA +opcode=NOTIFY +timeout=1" \
    "NOTIMP"

run_check "UPDATE to forward zone is rejected with NOTIMP" \
    "$DAG @127.0.0.1 -p $PORT ttl-test.example SOA +opcode=UPDATE +timeout=1" \
    "NOTIMP"

if [ "$FAILED" -gt 0 ] && [ -f "$TMP_DIR/karidns.log" ]; then
    echo "=== Server Log ==="
    cat "$TMP_DIR/karidns.log"
fi

# Stop server
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "ALL FORWARD ZONE TESTS PASSED!"
    exit 0
else
    echo "SOME FORWARD ZONE TESTS FAILED ($FAILED failure(s))"
    exit 1
fi

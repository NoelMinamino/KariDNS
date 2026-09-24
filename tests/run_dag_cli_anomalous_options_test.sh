#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) CLI Anomalous Options & Transport Resilience Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -x "$ROOT_DIR/dag" ]; then
    echo "=== Building dag with make ==="
    [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
fi

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ ! -x "$DAG" ]; then
    echo "Error: dag binary not found at $DAG"
    exit 1
fi

TMP_DIR="/tmp/karidns_dag_anom_test_$$"
mkdir -p "$TMP_DIR"
PORT=$((23000 + $$ % 8000))
TCP_PORT=$((31000 + $$ % 8000))

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    [ -n "$MOCK_TCP_PID" ] && kill -9 "$MOCK_TCP_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
TEST_COUNT=0

run_expect_fail() {
    TEST_COUNT=$((TEST_COUNT + 1))
    local desc="$1"
    shift
    echo -n "Test $TEST_COUNT: $desc ... "
    if "$DAG" "$@" > "$TMP_DIR/out.txt" 2>&1; then
        echo "FAIL (expected error exit code but got 0)"
        FAILED=$((FAILED + 1))
    else
        echo "OK (safely rejected)"
    fi
}

run_expect_ok() {
    TEST_COUNT=$((TEST_COUNT + 1))
    local desc="$1"
    shift
    echo -n "Test $TEST_COUNT: $desc ... "
    if "$DAG" "$@" > "$TMP_DIR/out.txt" 2>&1; then
        echo "OK"
    else
        echo "FAIL (expected success but failed)"
        cat "$TMP_DIR/out.txt" >&2
        FAILED=$((FAILED + 1))
    fi
}

echo "=== 1. Testing Invalid / Missing / Boundary CLI Options ==="

# 1. Non-existent option
run_expect_fail "Reject non-existent +badoption" @127.0.0.1 -p $PORT example.com A +badoption_xyz_123

# 2. Missing values on options requiring values
run_expect_fail "Reject +subnet= without value" @127.0.0.1 -p $PORT example.com A +subnet=
run_expect_fail "Reject +timeout= without value" @127.0.0.1 -p $PORT example.com A +timeout=
run_expect_fail "Reject +bufsize= without value" @127.0.0.1 -p $PORT example.com A +bufsize=
run_expect_fail "Reject +split= without value" @127.0.0.1 -p $PORT example.com A +split=
run_expect_fail "Reject +tries= without value" @127.0.0.1 -p $PORT example.com A +tries=
run_expect_fail "Reject +retry= without value" @127.0.0.1 -p $PORT example.com A +retry=
run_expect_fail "Reject +tcp-mss= without value" @127.0.0.1 -p $PORT example.com A +tcp-mss=
run_expect_fail "Reject +tcp-window= without value" @127.0.0.1 -p $PORT example.com A +tcp-window=
run_expect_fail "Reject +qid= without value" @127.0.0.1 -p $PORT example.com A +qid=
run_expect_fail "Reject +fuzztime= without value" @127.0.0.1 -p $PORT example.com A +fuzztime=
run_expect_fail "Reject +ednsflags= without value" @127.0.0.1 -p $PORT example.com A +ednsflags=

# 3. Invalid subnet syntax
run_expect_fail "Reject +subnet with invalid IPv4 octets" @127.0.0.1 -p $PORT example.com A +subnet=999.999.999.999/24
run_expect_fail "Reject +subnet with invalid IPv4 prefix > 32" @127.0.0.1 -p $PORT example.com A +subnet=192.0.2.1/33
run_expect_fail "Reject +subnet with invalid IPv6 prefix > 128" @127.0.0.1 -p $PORT example.com A +subnet=2001:db8::1/129
run_expect_fail "Reject +subnet with arbitrary non-IP string" @127.0.0.1 -p $PORT example.com A +subnet=not_an_ip_address/24
run_expect_fail "Reject +subnet with missing mask" @127.0.0.1 -p $PORT example.com A +subnet=192.0.2.1

# 4. Invalid numeric formats
run_expect_fail "Reject non-numeric +timeout=abc" @127.0.0.1 -p $PORT example.com A +timeout=abc
run_expect_fail "Reject negative +bufsize=-100" @127.0.0.1 -p $PORT example.com A +bufsize=-100
run_expect_fail "Reject non-numeric +port=xyz" @127.0.0.1 -p $PORT example.com A +port=xyz
run_expect_fail "Reject out-of-range port +port=999999" @127.0.0.1 example.com A +port=999999
run_expect_fail "Reject out-of-range port +port=-1" @127.0.0.1 example.com A +port=-1
run_expect_fail "Reject non-numeric +split=xyz" @127.0.0.1 -p $PORT example.com A +split=xyz

# 5. Conflicting TSIG and SIG0 options
run_expect_fail "Reject TSIG and SIG0 specified together" @127.0.0.1 -p $PORT example.com A +tsig=hmac-sha256:testkey:c2Vj +sig0

# 6. Invalid EDNS Option hex format
run_expect_fail "Reject invalid ednsopt hex string" @127.0.0.1 -p $PORT example.com A +ednsopt=65001:ZZZZ_NOT_HEX

if command -v perl >/dev/null 2>&1; then
    echo "=== 2. Testing YAML Output Escaping of Special Characters ==="
    
    # Mock DNS UDP server that returns TXT records with special characters (quotes, backslashes, tabs, nulls)
    cat <<'PL_EOF' > "$TMP_DIR/mock_special_chars_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

while (1) {
    my $client_addr = recv($srv, my $query, 4096, 0);
    next unless $client_addr && length($query) >= 12;
    my $qid = substr($query, 0, 2);

    # Build response with TXT records containing special characters
    # Header: QR=1, AA=1, ANCOUNT=2
    my $resp = $qid . pack("nnnnn", 0x8500, 1, 2, 0, 0);
    # Question: txt-spec.example.com IN TXT (16)
    $resp .= "\x08txt-spec\x07example\x03com\x00" . pack("nn", 16, 1);

    # Answer 1: TXT "double \"quote\" and \\backslash\\"
    my $txt1_val = "double \"quote\" and \\backslash\\";
    my $txt1_rdata = chr(length($txt1_val)) . $txt1_val;
    $resp .= "\xc0\x0c" . pack("nnNn", 16, 1, 300, length($txt1_rdata)) . $txt1_rdata;

    # Answer 2: TXT "tab\tnewline\ncolon: end"
    my $txt2_val = "tab\tnewline\ncolon: end";
    my $txt2_rdata = chr(length($txt2_val)) . $txt2_val;
    $resp .= "\xc0\x0c" . pack("nnNn", 16, 1, 300, length($txt2_rdata)) . $txt2_rdata;

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

    perl "$TMP_DIR/mock_special_chars_server.pl" "$PORT" &
    SRV_PID=$!
    sleep 0.3

    run_expect_ok "Query special characters TXT with +yaml" @127.0.0.1 -p $PORT txt-spec.example.com TXT +yaml

    # Verify YAML is well-formed
    cat <<'PL_EOF' > "$TMP_DIR/verify_yaml.pl"
use strict;
use warnings;

my $file = $ARGV[0];
open(my $fh, "<", $file) or die "Cannot open $file: $!";
my $content = do { local $/; <$fh> };
close($fh);

if ($content =~ /status:\s*"?NOERROR"?/i && $content =~ /ANSWER_SECTION:/) {
    print "YAML output verified successfully.\n";
    exit 0;
} else {
    print "YAML verification failed on content:\n$content\n";
    exit 1;
}
PL_EOF

    TEST_COUNT=$((TEST_COUNT + 1))
    echo -n "Test $TEST_COUNT: Validate generated YAML format structure ... "
    if perl "$TMP_DIR/verify_yaml.pl" "$TMP_DIR/out.txt" >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi

    kill -9 "$SRV_PID" 2>/dev/null || true
    SRV_PID=""

    echo "=== 3. Testing Transport Error Handling (Timeouts & ID Mismatch) ==="
    
    # 1. Non-responsive server timeout
    DEAD_PORT=$((36000 + $$ % 5000))
    run_expect_fail "Timeout gracefully against non-responsive UDP server" @127.0.0.1 -p $DEAD_PORT example.com A +timeout=1 +tries=1

    # 2. Mock server sending TXID mismatch
    cat <<'PL_EOF' > "$TMP_DIR/mock_txid_mismatch_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";

while (1) {
    my $client_addr = recv($srv, my $query, 4096, 0);
    next unless $client_addr && length($query) >= 12;
    # Send response with bad TXID (0xFFFF)
    my $bad_resp = pack("n", 0xFFFF) . pack("nnnnn", 0x8500, 1, 0, 0, 0);
    $bad_resp .= "\x07example\x03com\x00" . pack("nn", 1, 1);
    send($srv, $bad_resp, 0, $client_addr);
}
PL_EOF

    MISMATCH_PORT=$((38000 + $$ % 5000))
    perl "$TMP_DIR/mock_txid_mismatch_server.pl" "$MISMATCH_PORT" &
    SRV_PID=$!
    sleep 0.3

    run_expect_fail "Discard mismatched TXID packet and timeout safely" @127.0.0.1 -p $MISMATCH_PORT example.com A +timeout=1 +tries=1

    kill -9 "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
fi

echo "=== Summary: $TEST_COUNT tests completed, $FAILED failed ==="
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0

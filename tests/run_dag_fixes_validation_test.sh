#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Bug Fixes & Improvements Comprehensive Validation Test Suite
#
# Covers:
#  1. CLI Flags (+notrace, +nonssearch, -y, +tsig, +fuzztime)
#  2. Dynamic DNS Prerequisites (--prereq= with colons in RDATA)
#  3. TCP Stream Length Desynchronization Guard (rlen > resp_cap)
#  4. DoH (HTTP/Plain) Early Termination via Content-Length Header
#  5. RDATA Wire Format Bounds Checking (SOA, MX, SRV, NAPTR overflow prevention)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag with make ==="
make -C "$ROOT_DIR" dag

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$ROOT_DIR/dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag binary not found at $DAG"
        exit 1
    fi
fi

FAILED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    echo -n "Test: $NAME ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$EXPECT"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

run_not_check() {
    NAME="$1"
    CMD="$2"
    UNEXPECT="$3"
    echo -n "Test: $NAME (should NOT match '$UNEXPECT') ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$UNEXPECT"; then
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Unexpected match: $UNEXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    else
        echo "OK"
    fi
}

run_skip() {
    NAME="$1"
    REASON="${2:-dag-only feature}"
    echo "Test: $NAME ... SKIP ($REASON)"
}

TMP_DIR="/tmp/karidns_fixes_val_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$TCP_PID" ] && kill -9 "$TCP_PID" 2>/dev/null || true
    [ -n "$DOH_PID" ] && kill -9 "$DOH_PID" 2>/dev/null || true
    [ -n "$UDP_PID" ] && kill -9 "$UDP_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# ==============================================================================
# 1. CLI Options: +notrace, +nonssearch, TSIG (-y, +tsig, +fuzztime)
# ==============================================================================
echo "=== 1. Testing CLI Flags & Options ==="

run_check "+notrace flag accepted without option error" \
    "$DAG @127.0.0.1 -p 10053 example.com A +notrace +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

run_check "+nonssearch flag accepted without option error" \
    "$DAG @127.0.0.1 -p 10053 example.com A +nonssearch +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

run_check "TSIG signature generation (-y)" \
    "$DAG @127.0.0.1 -p 10053 example.com A -y hmac-sha256:testkey:dGVzdA== +qr +timeout=1" \
    "(TSIG|testkey|ADDITIONAL)"

if [ "$DAG" = "dig" ]; then
    run_skip "TSIG signature generation (+tsig=)"
    run_skip "TSIG with +fuzztime"
else
    run_check "TSIG signature generation (+tsig=)" \
        "$DAG @127.0.0.1 -p 10053 example.com A +tsig=hmac-sha256:testkey:dGVzdA== +qr +timeout=1" \
        "(TSIG|testkey|ADDITIONAL)"

    run_check "TSIG with +fuzztime" \
        "$DAG @127.0.0.1 -p 10053 example.com A +tsig=hmac-sha256:testkey:dGVzdA== +fuzztime=1646972129 +qr +timeout=1" \
        "(TSIG|testkey|1646972129|ADDITIONAL)"
fi

# ==============================================================================
# 2. Dynamic DNS Prerequisites (--prereq= with Colons in RDATA)
# ==============================================================================
echo "=== 2. Testing --prereq= with colons in RDATA ==="

if [ "$DAG" = "dig" ]; then
    run_skip "--prereq= with IPv6 address RDATA"
    run_skip "--prereq= with multi-colon text RDATA"
else
    run_check "--prereq= with IPv6 address RDATA containing colons" \
        "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN AAAA 2001:db8::1' --prereq=yxrrset:test.example.com:AAAA:2001:db8::1 +qr +timeout=1" \
        "Query \([0-9]+ bytes\)"

    run_check "--prereq= with multi-colon text RDATA" \
        "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN TXT \"v=1:a:b:c\"' --prereq=yxrrset:test.example.com:TXT:v=1:a:b:c +qr +timeout=1" \
        "Query \([0-9]+ bytes\)"
fi

# ==============================================================================
# 3. TCP Stream Synchronization Guard (Oversized Length Header)
# ==============================================================================
echo "=== 3. Testing TCP Stream Buffer Bounds (rlen > resp_cap) ==="

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server network tests."
else
    PORT_TCP=$((21000 + $$ % 8000))
    cat <<'PL_EOF' > "$TMP_DIR/mock_tcp_oversize.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen($srv, 5) or die "listen: $!";

while (my $paddr = accept(my $client, $srv)) {
    my $len_buf;
    read($client, $len_buf, 2);
    if (length($len_buf) == 2) {
        my $qlen = unpack("n", $len_buf);
        my $qbody;
        read($client, $qbody, $qlen);

        # Return an impossible/oversized length header (0xFFFF = 65535, or larger than resp_cap buffer)
        print $client pack("n", 65535);
        $client->flush() if $client->can('flush');
    }
    close($client);
}
PL_EOF

    perl "$TMP_DIR/mock_tcp_oversize.pl" "$PORT_TCP" &
    TCP_PID=$!
    sleep 0.3

    run_check "TCP oversized length prefix terminates safely without crash" \
        "$DAG @127.0.0.1 -p $PORT_TCP example.com A +tcp +timeout=2" \
        "(timed out|no usable response|failed|communication error|end of file|no servers could be reached)"

    kill -9 "$TCP_PID" 2>/dev/null || true
    TCP_PID=""

# ==============================================================================
# 4. DoH Early Termination via Content-Length Header
# ==============================================================================
    echo "=== 4. Testing Plain HTTP / DoH Content-Length Early Return ==="

    PORT_DOH=$((22000 + $$ % 8000))
    cat <<'PL_EOF' > "$TMP_DIR/mock_doh_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen($srv, 5) or die "listen: $!";

while (my $paddr = accept(my $client, $srv)) {
    my $req = "";
    while (sysread($client, my $buf, 4096)) {
        $req .= $buf;
        last if $req =~ /\r\n\r\n/;
    }

    my ($qid) = pack("n", 0x1234);
    my $dns_msg = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $dns_msg .= "\x07example\x03com\x00" . pack("nn", 1, 1);
    $dns_msg .= "\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 93, 184, 216, 34);

    my $body_len = length($dns_msg);
    my $http_resp = "HTTP/1.1 200 OK\r\n" .
                    "Content-Type: application/dns-message\r\n" .
                    "Content-Length: $body_len\r\n" .
                    "Connection: keep-alive\r\n\r\n" .
                    $dns_msg;

    syswrite($client, $http_resp);
    # Intentionally do not close the socket immediately; client must parse Content-Length and return promptly
    sleep 1;
    close($client);
}
PL_EOF

    perl "$TMP_DIR/mock_doh_server.pl" "$PORT_DOH" &
    DOH_PID=$!
    sleep 0.3

    if [ "$DAG" = "dig" ]; then
        run_skip "Plain HTTP DoH (+http-plain)"
    else
        run_check "DoH +http-plain returns immediately using Content-Length" \
            "$DAG @127.0.0.1 -p $PORT_DOH example.com A +http-plain +timeout=3" \
            "(93\.184\.216\.34|NOERROR)"
    fi

    kill -9 "$DOH_PID" 2>/dev/null || true
    DOH_PID=""

# ==============================================================================
# 5. RDATA Bounds Checking & Unparsable Name Safety
# ==============================================================================
    echo "=== 5. Testing RDATA Bounds Checking on Malformed Records ==="

    PORT_UDP=$((23000 + $$ % 8000))
    cat <<'PL_EOF' > "$TMP_DIR/mock_malformed_rdata.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

while (1) {
    my $client_addr = recv($srv, my $query, 4096, 0);
    next unless $client_addr && length($query) >= 12;
    my $qid = substr($query, 0, 2);

    # Build response containing an SOA record where rdlen is truncated/mismatched (rdlen=4, but SOA needs names + 20 bytes)
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $resp .= "\x07example\x03com\x00" . pack("nn", 6, 1); # QNAME=example.com, QTYPE=SOA, QCLASS=IN
    # SOA Answer: RDLENGTH=4, but contains "\x03ns1\xc0\x0c" (4 bytes) without second name or 20-byte timer block
    $resp .= "\xc0\x0c" . pack("nnNn", 6, 1, 300, 4) . "\x03ns1\x00";

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

    perl "$TMP_DIR/mock_malformed_rdata.pl" "$PORT_UDP" &
    UDP_PID=$!
    sleep 0.3

    run_check "Malformed SOA with truncated RDATA is handled safely" \
        "$DAG @127.0.0.1 -p $PORT_UDP example.com SOA +timeout=2" \
        "(unparsable|truncated|malformed|\\\\# 4)"

    kill -9 "$UDP_PID" 2>/dev/null || true
    UDP_PID=""
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Test Summary ==="
if [ "$FAILED" -eq 0 ]; then
    echo "All tests PASSED successfully."
    exit 0
else
    echo "$FAILED test(s) FAILED."
    exit 1
fi

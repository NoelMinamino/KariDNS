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

run_check "+cookie flag accepted" \
    "$DAG @127.0.0.1 -p 10053 example.com A +cookie +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

run_check "+cookie=HEX flag accepted" \
    "$DAG @127.0.0.1 -p 10053 example.com A +cookie=0102030405060708 +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

if [ "$DAG" != "dig" ]; then
    run_check "+cookies typo flag rejected as invalid option" \
        "$DAG @127.0.0.1 -p 10053 example.com A +cookies +timeout=1" \
        "Invalid option: \+cookies"
fi

run_check "+subnet=0 privacy flag accepted" \
    "$DAG @127.0.0.1 -p 10053 example.com A +subnet=0 +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

run_check "+subnet=0/0, +subnet=0.0.0.0/0, +subnet=::/0 accepted" \
    "$DAG @127.0.0.1 -p 10053 example.com A +subnet=0/0 +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

run_check "+padding=128 block padding alignment (+qr)" \
    "$DAG @127.0.0.1 -p 10053 example.com A +padding=128 +qr +timeout=1" \
    "Query \(128 bytes\)"

run_check "+ednsopt=100:01020304 hex decode accepted" \
    "$DAG @127.0.0.1 -p 10053 example.com A +ednsopt=100:01020304 +qr +timeout=1" \
    "Query \([0-9]+ bytes\)"

cat <<'KEY_EOF' > "$TMP_DIR/tsig_test.key"
key "tsig-file-key" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
KEY_EOF

run_check "TSIG keyfile loading (-k)" \
    "$DAG @127.0.0.1 -p 10053 -k $TMP_DIR/tsig_test.key example.com A +qr +timeout=1" \
    "(TSIG|tsig-file-key|ADDITIONAL)"

run_check "+nodnssec, +nonsid, +nosubnet flags accepted" \
    "$DAG @127.0.0.1 -p 10053 example.com A +nodnssec +nonsid +nosubnet +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

if [ "$DAG" = "dig" ]; then
    run_skip "+nopadding, +hexdump, +nohttps flags" "dag-specific CLI flags"
    run_skip "--break too-short=0" "dag-specific break flag"
else
    run_check "+nopadding, +hexdump, +nohttps flags accepted" \
        "$DAG @127.0.0.1 -p 10053 example.com A +nopadding +hexdump +nohttps +timeout=1" \
        "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

    run_check "--break too-short=0 terminates safely without crash" \
        "$DAG @127.0.0.1 -p 10053 example.com A --break too-short=0 +timeout=1" \
        "(timed out|no usable response|connection|status:|timed out|no servers could be reached)"
fi

echo "example.com A @127.0.0.1" > "$TMP_DIR/test_batch.txt"
run_check "Batch mode (-f) with @server syntax" \
    "$DAG -f $TMP_DIR/test_batch.txt -p 10053 +timeout=1" \
    "(opcode: QUERY|timed out|no usable response|status:|connection refused|no servers could be reached)"

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
# 4. DoH (DNS-over-HTTPS) & Content-Length Handling
# ==============================================================================
    echo "=== 4. Testing DoH (DNS-over-HTTPS) with Public DNS & Local Mock ==="

    echo "--- 4-1. Public DoH Server Queries (@8.8.8.8 / @1.1.1.1) ---"
    run_check "DoH standard query (+https) against @8.8.8.8" \
        "$DAG @8.8.8.8 example.com A +https +timeout=5" \
        "(NOERROR|status: NOERROR|timed out|no servers could be reached|connection refused)"

    run_check "DoH GET method query (+https-get) against @8.8.8.8" \
        "$DAG @8.8.8.8 example.com A +https-get +timeout=5" \
        "(NOERROR|status: NOERROR|timed out|no servers could be reached|connection refused)"

    run_check "DoH POST method query (+https-post) against @8.8.8.8" \
        "$DAG @8.8.8.8 example.com A +https-post +timeout=5" \
        "(NOERROR|status: NOERROR|timed out|no servers could be reached|connection refused)"

    echo "--- 4-2. Local Mock HTTP Server (Content-Length & URI Building) ---"
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

    if (my $req_line = (split(/\r\n/, $req))[0]) {
        # If request path contains existing query params (e.g. /dns-query?foo=bar), verify &dns= is used
        if ($req_line =~ /GET \/dns-query\?foo=bar([?&])dns=/) {
            my $sep = $1;
            if ($sep ne '&') {
                # Protocol error: duplicate '?' used instead of '&'
                my $err_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                syswrite($client, $err_resp);
                close($client);
                next;
            }
        }
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
        run_skip "Local Plain HTTP DoH (+http-plain)" "dig requires HTTP/2 cleartext framing for plain HTTP"
        run_skip "Local DoH GET URI with query params (+http-plain-get=/path?foo=bar)" "dig rejects paths containing '?'"
    else
        run_check "DoH +http-plain returns immediately using Content-Length" \
            "$DAG @127.0.0.1 -p $PORT_DOH example.com A +http-plain +timeout=3" \
            "(93\.184\.216\.34|NOERROR)"

        run_check "DoH GET URI correctly uses '&dns=' when path has existing '?'" \
            "$DAG @127.0.0.1 -p $PORT_DOH example.com A +http-plain-get=/dns-query?foo=bar +timeout=3" \
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

# ==============================================================================
# 6. +short Output Mode with TTL Options (+ttlid, +ttlunits)
# ==============================================================================
    echo "=== 6. Testing +short with +ttlid and +ttlunits ==="

    PORT_SHORT=$((24000 + $$ % 8000))
    cat <<'PL_EOF' > "$TMP_DIR/mock_short_ttl.pl"
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

    # Response: example.com A 3600 192.0.2.10
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $resp .= "\x07example\x03com\x00" . pack("nn", 1, 1); # QNAME=example.com, QTYPE=A, QCLASS=IN
    $resp .= "\xc0\x0c" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("192.0.2.10");

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

    perl "$TMP_DIR/mock_short_ttl.pl" "$PORT_SHORT" &
    SHORT_PID=$!
    sleep 0.3

    run_check "+short alone prints only RDATA" \
        "$DAG @127.0.0.1 -p $PORT_SHORT example.com A +short +timeout=2" \
        "^192\.0\.2\.10$"

    run_check "+short +ttlid prints numeric TTL and RDATA" \
        "$DAG @127.0.0.1 -p $PORT_SHORT example.com A +short +ttlid +timeout=2" \
        "^3600 192\.0\.2\.10$"

    run_check "+short +ttlid +ttlunits prints formatted TTL and RDATA" \
        "$DAG @127.0.0.1 -p $PORT_SHORT example.com A +short +ttlid +ttlunits +timeout=2" \
        "^1h 192\.0\.2\.10$"

    kill -9 "$SHORT_PID" 2>/dev/null || true
    SHORT_PID=""

# ==============================================================================
# 7. Additional Protocol & Search Semantics (IXFR serial, LOC ver, search abs)
# ==============================================================================
    echo "=== 7. Testing IXFR serial default, LOC version != 0, and search absolute name ==="

    run_check "IXFR without explicit serial defaults to serial 0 (+qr)" \
        "$DAG @127.0.0.1 -p 10053 example.com IXFR +qr +timeout=1" \
        "(IXFR|Query \([0-9]+ bytes\))"

    run_check "+search with absolute domain name (trailing dot) does not expand" \
        "$DAG @127.0.0.1 -p 10053 example.com. A +search +domain=sub.example.net +qr +timeout=1" \
        "example\.com\."

    PORT_LOC=$((25000 + $$ % 8000))
    cat <<'PL_EOF' > "$TMP_DIR/mock_loc.pl"
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

    # Response with LOC record having VERSION=1 (RFC 1876 requires fallback to generic hex)
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $resp .= "\x07example\x03com\x00" . pack("nn", 29, 1); # QNAME=example.com, QTYPE=LOC, QCLASS=IN
    # LOC Answer: 16 bytes with VERSION=1
    $resp .= "\xc0\x0c" . pack("nnNn", 29, 1, 300, 16) . "\x01\x12\x16\x13" . ("\x00" x 12);

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

    perl "$TMP_DIR/mock_loc.pl" "$PORT_LOC" &
    LOC_PID=$!
    sleep 0.3

    run_check "LOC with VERSION != 0 falls back to unknown format (\\# 16)" \
        "$DAG @127.0.0.1 -p $PORT_LOC example.com LOC +timeout=2" \
        "\\\\# 16"

    kill -9 "$LOC_PID" 2>/dev/null || true
    LOC_PID=""
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

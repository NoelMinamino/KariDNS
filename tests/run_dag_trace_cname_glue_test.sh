#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace Glue Fallback and CNAME Chain Tracing Test Suite
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
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT=$((19000 + $$ % 10000))
TMP_DIR="/tmp/dag_trace_cname_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create a mock DNS server handling trace steps:
# 1. Root query (". NS") -> returns NS "a.root-servers.net" with glue "127.0.0.1"
# 2. Query "example.com A" -> returns referral to "ns1.external.org" WITHOUT glue
# 3. Query "ns1.external.org A" (glue resolution fallback) -> returns "127.0.0.1"
# 4. Query "example.com A" to authoritative -> returns "example.com CNAME cdn.example.net"
# 5. Query "cdn.example.net A" (CNAME re-trace) -> returns "192.0.2.100"
cat << 'PL_EOF' > "$TMP_DIR/mock_trace_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port>\n";
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!";
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

my $example_count = 0;

while (1) {
    my $query;
    my $client_addr = recv($srv, $query, 4096, 0);
    next unless defined $client_addr && length($query) >= 12;

    my $qid = substr($query, 0, 2);

    # Parse Question name
    my $off = 12;
    my $qname = "";
    while ($off < length($query)) {
        my $len = ord(substr($query, $off, 1));
        $off++;
        last if $len == 0;
        $qname .= substr($query, $off, $len) . ".";
        $off += $len;
    }

    my $resp = "";
    if ($qname eq "" || $qname eq ".") {
        # Root NS query: return a.root-servers.net with glue 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1) .
                "\x00" . pack("nn", 2, 1) .
                "\x00" . pack("nnNn", 2, 1, 3600, 20) . "\x01a\x0croot-servers\x03net\x00" .
                "\x01a\x0croot-servers\x03net\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^ns1\.external\.org\./i) {
        # Glue resolution query: return 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0) .
                "\x03ns1\x08external\x03org\x00" . pack("nn", 1, 1) .
                "\x03ns1\x08external\x03org\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^example\.com\./i) {
        $example_count++;
        if ($example_count == 1) {
            # Referral without glue (Authority section only)
            $resp = $qid . pack("nnnnn", 0x8000, 1, 0, 1, 0) .
                    "\x07example\x03com\x00" . pack("nn", 1, 1) .
                    "\x07example\x03com\x00" . pack("nnNn", 2, 1, 300, 18) . "\x03ns1\x08external\x03org\x00";
        } else {
            # Authoritative response: CNAME cdn.example.net
            $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                    "\x07example\x03com\x00" . pack("nn", 1, 1) .
                    "\x07example\x03com\x00" . pack("nnNn", 5, 1, 300, 17) . "\x03cdn\x07example\x03net\x00";
        }
    } elsif ($qname =~ /^cdn\.example\.net\./i) {
        # Re-traced target: return final A record 192.0.2.100
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x03cdn\x07example\x03net\x00" . pack("nn", 1, 1) .
                "\x03cdn\x07example\x03net\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("192.0.2.100");
    } else {
        $resp = $qid . pack("nnnnn", 0x8183, 1, 0, 0, 0) . substr($query, 12, $off + 4 - 12);
    }

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_trace_server.pl" "$PORT" &
MOCK_PID=$!
sleep 0.5

echo "=== 1. Testing +trace with Out-of-Bailiwick Delegation (No Glue Fallback) ==="
echo -n "Test: Trace succeeds through glue resolution and CNAME re-trace ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 2>&1 || true)
if echo "$OUT" | grep -q "ns1\.external\.org" && echo "$OUT" | grep -q "cdn\.example\.net"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE GLUE & CNAME TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TRACE GLUE & CNAME TESTS FAILED!"
    exit 1
fi

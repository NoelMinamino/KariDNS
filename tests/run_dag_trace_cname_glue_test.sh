#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace Glue Fallback and CNAME Chain Tracing Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -x "$ROOT_DIR/dag" ]; then
    echo "=== Building dag with make ==="
    [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
fi

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
#    (default +noglue ignores that glue and asks "a.root-servers.net A" -> "127.0.0.1")
# 2. Query "example.com A" -> returns referral to "ns1.external.org" WITHOUT glue
# 3. Query "ns1.external.org A" (glue resolution fallback) -> returns "127.0.0.1"
# 4. Query "example.com A" to authoritative -> returns "example.com CNAME cdn.example.net"
# 5. Query "cdn.example.net A" (CNAME re-trace) -> returns "192.0.2.100"
cat << 'PL_EOF' > "$TMP_DIR/mock_trace_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port> [query_log] [authonly]\n";
my $query_log = $ARGV[1];
# authonly: behave like an authoritative-only root server (RA=0) whose NS name
# can only be resolved through the system resolver (e.g. dig +trace @198.41.0.4)
my $authonly = (defined $ARGV[2] && $ARGV[2] eq "authonly");
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

    my $qtype = unpack("n", substr($query, $off, 2));
    if ($query_log && open(my $lfh, ">>", $query_log)) {
        print $lfh "$qname $qtype\n";
        close($lfh);
    }

    my $resp = "";
    if ($authonly && ($qname eq "" || $qname eq ".")) {
        # Root NS query (AA=1, RA=0): NS ns.root.invalid with glue 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 1) .
                "\x00" . pack("nn", 2, 1) .
                "\x00" . pack("nnNn", 2, 1, 3600, 17) . "\x02ns\x04root\x07invalid\x00" .
                "\x02ns\x04root\x07invalid\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    } elsif ($authonly) {
        # Authoritative-only server refuses recursion
        $resp = $qid . pack("nnnnn", 0x8405, 1, 0, 0, 0) . substr($query, 12, $off + 4 - 12);
    } elsif ($qname eq "" || $qname eq ".") {
        $example_count = 0;
        # Root NS query: return a.root-servers.net with glue 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1) .
                "\x00" . pack("nn", 2, 1) .
                "\x00" . pack("nnNn", 2, 1, 3600, 20) . "\x01a\x0croot-servers\x03net\x00" .
                "\x01a\x0croot-servers\x03net\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^a\.root-servers\.net\./i && $qtype == 1) {
        # Root server address resolution (+noglue): return 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0) .
                "\x01a\x0croot-servers\x03net\x00" . pack("nn", 1, 1) .
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

QUERY_LOG="$TMP_DIR/queries.log"
perl "$TMP_DIR/mock_trace_server.pl" "$PORT" "$QUERY_LOG" &
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

echo "=== 2. Testing +trace default (+noglue) ignores ADDITIONAL section glue ==="
echo -n "Test: Root server address is resolved via resolver instead of glue ... "
: > "$QUERY_LOG"
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 2>&1 || true)
if grep -q "^a\.root-servers\.net\. 1$" "$QUERY_LOG" && echo "$OUT" | grep -q "cdn\.example\.net"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$QUERY_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 3. Testing +trace +glue uses ADDITIONAL section glue (legacy behavior) ==="
echo -n "Test: Root server glue is used without resolver lookup ... "
: > "$QUERY_LOG"
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +glue +timeout=2 2>&1 || true)
if ! grep -q "^a\.root-servers\.net\." "$QUERY_LOG" && echo "$OUT" | grep -q "ns1\.external\.org" && echo "$OUT" | grep -q "cdn\.example\.net"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$QUERY_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 4. Testing +trace against authoritative-only @server (RA=0) ==="
echo -n "Test: NS names are resolved via system resolver, not the non-recursive @server ... "
AUTH_PORT=$((PORT + 1))
AUTH_LOG="$TMP_DIR/auth_queries.log"
: > "$AUTH_LOG"
perl "$TMP_DIR/mock_trace_server.pl" "$AUTH_PORT" "$AUTH_LOG" authonly &
AUTH_PID=$!
sleep 0.5
OUT=$("$DAG" @127.0.0.1 -p $AUTH_PORT example.com A +trace +timeout=1 +tries=1 2>&1 || true)
kill -9 "$AUTH_PID" 2>/dev/null || true
if echo "$OUT" | grep -q "couldn't get address for 'ns\.root\.invalid'" && ! grep -q "^ns\.root\.invalid\." "$AUTH_LOG" && ! echo "$OUT" | grep -q "from 127\.0\.0\.1#$AUTH_PORT\$"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$AUTH_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 5. Testing +trace +ldnsz emits ldns.jp trace viewer URL ==="
if [ "$DAG" = "dig" ]; then
    echo "Test: +trace +ldnsz emits https://ldns.jp/trace/#c= URL ... SKIP (dag-only +ldnsz option)"
else
    echo -n "Test: +trace +ldnsz emits https://ldns.jp/trace/#c= URL ... "
    OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +ldnsz +timeout=2 2>&1 || true)
    if echo "$OUT" | grep -q "https://ldns\.jp/trace/#c=" && ! echo "$OUT" | grep -q "https://ldns\.jp/diff/"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE GLUE & CNAME TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TRACE GLUE & CNAME TESTS FAILED!"
    exit 1
fi

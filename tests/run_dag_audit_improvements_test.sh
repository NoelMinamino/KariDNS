#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) & BIND 9 dig(1) Audit Improvements Test (P2-1, P3-1, P3-2, P3-4, P4-1)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"
IS_DIG=0
CLIENT_NAME="KariDNS dag"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found in PATH"
        exit 1
    fi
    IS_DIG=1
    CLIENT_NAME="BIND 9 dig ($(dig -v 2>&1 | head -n 1))"
else
    echo "=== Building dag with make ==="
    make -C "$ROOT_DIR" dag
    if [ ! -x "$DAG" ]; then
        DAG="$ROOT_DIR/dag"
    fi
    if [ ! -x "$DAG" ]; then
        DAG="./dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag executable not found at $DAG"
        exit 1
    fi
fi

echo "Testing with DNS client: $CLIENT_NAME ($DAG)"

FAILED=0
SKIPPED=0

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
        echo "  Expected pattern: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

TMP_DIR="/tmp/dag_audit_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    if [ -n "$MOCK_TLS_PID" ] && kill -0 "$MOCK_TLS_PID" 2>/dev/null; then
        kill -9 "$MOCK_TLS_PID" 2>/dev/null || true
    fi
    if [ -n "$MOCK_DOH_PID" ] && kill -0 "$MOCK_DOH_PID" 2>/dev/null; then
        kill -9 "$MOCK_DOH_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# 1. P2-1: Opportunistic TLS Handshake Failure Diagnostics Test
# ------------------------------------------------------------------------------
echo "=== 1. Testing P2-1 (Opportunistic TLS Handshake Error Message) ==="

MOCK_TLS_PORT=18853
# Start a simple TCP server that accepts connections and closes immediately
perl -MIO::Socket::INET -e '
    my $server = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1",
        LocalPort => '$MOCK_TLS_PORT',
        Proto     => "tcp",
        Listen    => 5,
        ReuseAddr => 1
    ) or die "Cannot bind TCP: $!";
    while (my $client = $server->accept()) {
        # Close connection without performing TLS handshake
        close($client);
    }
' >/dev/null 2>&1 &
MOCK_TLS_PID=$!
sleep 1

if [ "$IS_DIG" -eq 1 ]; then
    # BIND 9 dig outputs ";; communications error to ...: end of file" or "TLS error" or connection failure
    run_check "P2-1: Opportunistic TLS handshake failure output (dig)" \
        "\"$DAG\" @127.0.0.1 -p $MOCK_TLS_PORT example.com A +tls +timeout=2 +tries=1" \
        "(communications error to 127\.0\.0\.1#$MOCK_TLS_PORT|connection refused|no servers could be reached|TLS error)"
else
    # KariDNS dag outputs explicit handshake diagnostics: ";; TLS handshake with ... failed: <reason>"
    run_check "P2-1: Opportunistic TLS handshake failure output (dag)" \
        "\"$DAG\" @127.0.0.1 -p $MOCK_TLS_PORT example.com A +tls +timeout=2 +tries=1" \
        ";; TLS handshake with 127\.0\.0\.1#$MOCK_TLS_PORT failed"
fi

kill -9 "$MOCK_TLS_PID" 2>/dev/null || true
MOCK_TLS_PID=""

# ------------------------------------------------------------------------------
# 2. P3-2: +search FQDN Buffer Overflow Safety Test
# ------------------------------------------------------------------------------
echo "=== 2. Testing P3-2 (+search FQDN Buffer Safety) ==="

# Construct a domain name exceeding 512 bytes with search domain appended
LONG_NAME=$(perl -e 'print "a" x 520')

if [ "$IS_DIG" -eq 1 ]; then
    # BIND 9 dig rejects names exceeding 255 bytes with "name too long" without crashing
    run_check "P3-2: Long domain with +search skips gracefully without crash (dig)" \
        "\"$DAG\" @127.0.0.1 \"$LONG_NAME\" A +search +domain=example.local +timeout=1 +tries=1" \
        "(too long|name too long)"
else
    # KariDNS dag skips oversized candidates with a warning and exits cleanly without crashing
    run_check "P3-2: Long domain with +search skips gracefully without crash (dag)" \
        "\"$DAG\" @127.0.0.1 \"$LONG_NAME\" A +search +domain=example.local +timeout=1 +tries=1" \
        ";; warning: search-list candidate exceeds maximum buffer size, skipping"
fi

# ------------------------------------------------------------------------------
# 3. P3-4: DoH Transfer-Encoding: chunked Decoding Test
# ------------------------------------------------------------------------------
echo "=== 3. Testing P3-4 (DoH Chunked Transfer Decoding) ==="

MOCK_DOH_PORT=18880
# Minimal DNS NOERROR response for example.com A -> 192.0.2.1
perl -MIO::Socket::INET -e '
    my $server = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1",
        LocalPort => '$MOCK_DOH_PORT',
        Proto     => "tcp",
        Listen    => 5,
        ReuseAddr => 1
    ) or die "Cannot bind TCP: $!";
    while (my $client = $server->accept()) {
        my $req = "";
        my $content_len = 0;
        while (my $line = <$client>) {
            $req .= $line;
            if ($line =~ /Content-Length:\s*(\d+)/i) {
                $content_len = $1;
            }
            last if $line =~ /^\r?\n$/;
        }
        my $body = "";
        if ($content_len > 0) {
            read($client, $body, $content_len);
        }
        my $qid = 0x1234;
        if (length($body) >= 2) {
            $qid = unpack("n", substr($body, 0, 2));
        }

        # Craft DNS response wire bytes matching query ID
        my $dns_resp = pack("n", $qid) .    # Matched ID
                       pack("n", 0x8180) .  # Flags (QR, RD, RA, NOERROR)
                       pack("n", 1) .       # QDCOUNT
                       pack("n", 1) .       # ANCOUNT
                       pack("n", 0) .       # NSCOUNT
                       pack("n", 0) .       # ARCOUNT
                       "\x07example\x03com\x00" . pack("n", 1) . pack("n", 1) . # Question: example.com A IN
                       "\xc0\x0c" . pack("n", 1) . pack("n", 1) . pack("N", 300) . pack("n", 4) . pack("C4", 192, 0, 2, 1); # Answer

        # Send HTTP 200 OK with Transfer-Encoding: chunked
        my $chunk1 = substr($dns_resp, 0, 20);
        my $chunk2 = substr($dns_resp, 20);

        print $client "HTTP/1.1 200 OK\r\n" .
                      "Content-Type: application/dns-message\r\n" .
                      "Transfer-Encoding: chunked\r\n" .
                      "Connection: close\r\n\r\n" .
                      sprintf("%x\r\n", length($chunk1)) . $chunk1 . "\r\n" .
                      sprintf("%x\r\n", length($chunk2)) . $chunk2 . "\r\n" .
                      "0\r\n\r\n";
        close($client);
    }
' >/dev/null 2>&1 &
MOCK_DOH_PID=$!
sleep 1

# Both dag and BIND 9.20+ dig support +http-plain
run_check "P3-4: DoH chunked transfer decode and assemble ($CLIENT_NAME)" \
    "\"$DAG\" @127.0.0.1 -p $MOCK_DOH_PORT example.com A +http-plain +timeout=3 +tries=1" \
    "(192\.0\.2\.1|NOERROR)"

kill -9 "$MOCK_DOH_PID" 2>/dev/null || true
MOCK_DOH_PID=""

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    if [ "$SKIPPED" -gt 0 ]; then
        echo "🎉 ALL TESTS PASSED! ($SKIPPED skipped for $CLIENT_NAME)"
    else
        echo "🎉 ALL AUDIT IMPROVEMENT TESTS PASSED FOR $CLIENT_NAME!"
    fi
    exit 0
else
    echo "❌ $FAILED TESTS FAILED! ($SKIPPED skipped for $CLIENT_NAME)"
    exit 1
fi

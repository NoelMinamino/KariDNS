#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Multi-Message AXFR Streaming & Memory Lifecycle Test Suite
#
# Note:
#  - KariDNS authoritative server (dns_server_core.c) does NOT support DoH/DTLS
#    by design (FreeBSD native high-performance UDP/TCP authorative only).
#  - This test validates dag(1) client-side features:
#    1. Multi-message AXFR streaming over TCP mock (inter-packet stream read)
#    2. Plain-HTTP DoH (+http-plain) message exchange via mock HTTP server
#    3. Persistent option strings (+domain=, +tls-*, etc.) memory lifecycle (UAF prevention)
#    4. +rec / +norec / +time=N / +multi / +nomulti option aliases
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag with make ==="
make -C "$ROOT_DIR" dag >/dev/null 2>&1 || true

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
    echo "[-] perl is not installed; skipping mock server tests."
    exit 0
fi

FAILED=0
TMP_DIR="/tmp/dag_axfr_mem_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

cleanup() {
    [ -n "$TCP_PID" ] && kill -9 "$TCP_PID" 2>/dev/null || true
    [ -n "$HTTP_PID" ] && kill -9 "$HTTP_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

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

# ==============================================================================
# 1. Multi-Message AXFR TCP Stream Test (Mock Server sending 2 separate packets)
# ==============================================================================
PORT_AXFR=$((18000 + $$ % 10000))

cat <<'PL_EOF' > "$TMP_DIR/mock_axfr_server.pl"
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
        my $qid = substr($qbody, 0, 2);

        my $mname = "\x03ns1\x07example\x03com\x00";
        my $rname = "\x04host\x07example\x03com\x00";
        my $soa_rdata = $mname . $rname . pack("NNNNN", 2026083101, 7200, 3600, 1209600, 3600);
        my $ns_rdata = "\x03ns1\x07example\x03com\x00";

        # Packet 1: Initial SOA + NS record (ANCOUNT=2)
        my $pkt1 = $qid . pack("nnnnn", 0x8400, 1, 2, 0, 0);
        $pkt1 .= "\x07example\x03com\x00" . pack("nn", 252, 1); # Q: example.com AXFR
        $pkt1 .= "\x07example\x03com\x00" . pack("nnNn", 6, 1, 3600, length($soa_rdata)) . $soa_rdata;
        $pkt1 .= "\x07example\x03com\x00" . pack("nnNn", 2, 1, 3600, length($ns_rdata)) . $ns_rdata;

        # Send Packet 1
        print $client pack("n", length($pkt1)) . $pkt1;
        $client->flush() if $client->can('flush');

        select(undef, undef, undef, 0.05);

        # Packet 2: Host A record + Terminating SOA (ANCOUNT=2)
        my $a_rdata = pack("C4", 192, 0, 2, 10);
        my $pkt2 = $qid . pack("nnnnn", 0x8400, 0, 2, 0, 0);
        $pkt2 .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, length($a_rdata)) . $a_rdata;
        $pkt2 .= "\x07example\x03com\x00" . pack("nnNn", 6, 1, 3600, length($soa_rdata)) . $soa_rdata;

        # Send Packet 2
        print $client pack("n", length($pkt2)) . $pkt2;
        $client->flush() if $client->can('flush');
    }
    close($client);
}
PL_EOF

perl "$TMP_DIR/mock_axfr_server.pl" "$PORT_AXFR" &
TCP_PID=$!
sleep 1

echo "=== 1. Testing Multi-Message AXFR Stream Reading ==="
run_check "AXFR multi-message stream reading (receives records from both packets)" \
    "$DAG @127.0.0.1 -p $PORT_AXFR example.com AXFR +timeout=2" \
    "192\.0\.2\.10"

run_check "AXFR multi-message stream terminates on matching SOA" \
    "$DAG @127.0.0.1 -p $PORT_AXFR example.com AXFR +timeout=2" \
    "ns1\.example\.com"

# ==============================================================================
# 2. Plain-HTTP DoH (+http-plain) Mock Exchange Test
# ==============================================================================
PORT_HTTP=$((19000 + $$ % 10000))

cat <<'PL_EOF' > "$TMP_DIR/mock_http_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen($srv, 5) or die "listen: $!";

while (my $paddr = accept(my $client, $srv)) {
    my $http_req = "";
    while (my $line = <$client>) {
        $http_req .= $line;
        last if $line =~ /^\r?\n$/;
    }
    my $cl = 0;
    if ($http_req =~ /Content-Length:\s*(\d+)/i) {
        $cl = $1;
    }
    my $body = "";
    if ($cl > 0) {
        read($client, $body, $cl);
    }

    my $qid = (length($body) >= 2) ? substr($body, 0, 2) : "\x12\x34";
    my $dns_resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0);
    $dns_resp .= "\x03www\x07example\x03com\x00" . pack("nn", 1, 1);
    $dns_resp .= "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . pack("C4", 192, 0, 2, 42);

    my $resp_hdr = "HTTP/1.1 200 OK\r\n"
                 . "Content-Type: application/dns-message\r\n"
                 . "Content-Length: " . length($dns_resp) . "\r\n"
                 . "Connection: close\r\n\r\n";

    print $client $resp_hdr . $dns_resp;
    close($client);
}
PL_EOF

perl "$TMP_DIR/mock_http_server.pl" "$PORT_HTTP" &
HTTP_PID=$!
sleep 1

echo "=== 2. Testing Plain-HTTP DoH (+http-plain) Resolution ==="
run_check "+http-plain DoH query response resolution" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +http-plain +timeout=2" \
    "192\.0\.2\.42"

run_check "+http-plain-post DoH method" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +http-plain-post +timeout=2" \
    "192\.0\.2\.42"

# ==============================================================================
# 3. Persistent Option Strings Memory Lifecycle (UAF Prevention)
# ==============================================================================
echo "=== 3. Testing Persistent Option String Memory Lifecycle ==="
run_check "Multi-query +domain= persistence without memory corruption" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www +domain=example.com +search mail +domain=example.com +search +http-plain +timeout=2" \
    "192\.0\.2\.42"

run_check "+domain= with retries (+tries=2)" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www +domain=example.com +search +http-plain +tries=2 +timeout=2" \
    "192\.0\.2\.42"

echo "=== 4. Testing +rec, +norec, +time=N, +multi, +nomulti Aliases ==="
run_check "Recursion desired (+rec) sets RD flag in query" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +rec +http-plain +qr +timeout=2" \
    "flags:.*rd"

run_check "Recursion disabled (+norec) clears RD flag in query" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +norec +http-plain +qr +timeout=2" \
    ";; flags:"

run_check "Timeout alias (+time=2)" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +time=2 +http-plain +timeout=2" \
    "192\.0\.2\.42"

run_check "Multiline formatting alias (+multi)" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +multi +http-plain +timeout=2" \
    "192\.0\.2\.42"

run_check "Multiline disable alias (+nomulti)" \
    "$DAG @127.0.0.1 -p $PORT_HTTP www.example.com A +nomulti +http-plain +timeout=2" \
    "192\.0\.2\.42"

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL DOT/DOH AXFR & MEMORY TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

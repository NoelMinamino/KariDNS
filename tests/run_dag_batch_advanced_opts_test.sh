#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Batch Mode Advanced Options & NS Search Glue Test Suite
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
TMP_DIR="/tmp/dag_batch_glue_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create a mock DNS server handling both UDP and TCP requests
cat << 'PL_EOF' > "$TMP_DIR/mock_ns_server.pl"
use strict;
use warnings;
use Socket;
use IO::Select;

my $port = $ARGV[0] or die "Usage: $0 <port>\n";

# UDP Socket
socket(my $udp_srv, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "udp socket: $!";
bind($udp_srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "udp bind: $!";

# TCP Socket
socket(my $tcp_srv, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "tcp socket: $!";
setsockopt($tcp_srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($tcp_srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "tcp bind: $!";
listen($tcp_srv, 10) or die "tcp listen: $!";

my $sel = IO::Select->new($udp_srv, $tcp_srv);

sub build_response {
    my ($query) = @_;
    return "" if length($query) < 12;
    my $qid = substr($query, 0, 2);

    my $off = 12;
    my $qname = "";
    while ($off < length($query)) {
        my $len = ord(substr($query, $off, 1));
        $off++;
        last if $len == 0;
        $qname .= substr($query, $off, $len) . ".";
        $off += $len;
    }
    my ($qtype, $qclass) = unpack("nn", substr($query, $off, 4));

    if ($qtype == 2) { # NS query for test.internal.zone.
        # Return NS record in ANSWER and in-bailiwick Glue A record in ADDITIONAL
        return $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1) .
               "\x04test\x08internal\x04zone\x00" . pack("nn", 2, 1) .
               # Answer: test.internal.zone NS ns1.test.internal.zone (rdlength = 24)
               "\x04test\x08internal\x04zone\x00" . pack("nnNn", 2, 1, 300, 24) . "\x03ns1\x04test\x08internal\x04zone\x00" .
               # Additional: ns1.test.internal.zone A 127.0.0.1 (GLUE) (rdlength = 4)
               "\x03ns1\x04test\x08internal\x04zone\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
    } elsif ($qtype == 6) { # SOA query (from nssearch)
        # mname: \x03ns1\x04test\x08internal\x04zone\x00 (24 bytes)
        # rname: \x04host\x04test\x08internal\x04zone\x00 (25 bytes)
        # numbers: 5 * 4 = 20 bytes -> total rdlength = 69 bytes
        return $qid . pack("nnnnn", 0x8580, 1, 1, 0, 0) .
               "\x04test\x08internal\x04zone\x00" . pack("nn", 6, 1) .
               "\x04test\x08internal\x04zone\x00" . pack("nnNn", 6, 1, 300, 69) .
               "\x03ns1\x04test\x08internal\x04zone\x00\x04host\x04test\x08internal\x04zone\x00" .
               pack("NNNNN", 2026090101, 3600, 600, 86400, 300);
    } else {
        # Normal A query
        return $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0) .
               substr($query, 12, $off + 4 - 12) .
               "\x04test\x08internal\x04zone\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
    }
}

while (1) {
    my @ready = $sel->can_read(1.0);
    for my $fh (@ready) {
        if ($fh == $udp_srv) {
            my $query;
            my $client = recv($udp_srv, $query, 4096, 0);
            if ($client) {
                my $resp = build_response($query);
                send($udp_srv, $resp, 0, $client) if length($resp) > 0;
            }
        } elsif ($fh == $tcp_srv) {
            my $client;
            accept($client, $tcp_srv);
            if ($client) {
                my $len_buf;
                read($client, $len_buf, 2);
                if (defined $len_buf && length($len_buf) == 2) {
                    my $len = unpack("n", $len_buf);
                    my $query;
                    read($client, $query, $len);
                    my $resp = build_response($query);
                    my $out = pack("n", length($resp)) . $resp;
                    syswrite($client, $out);
                }
                close($client);
            }
        }
    }
}
PL_EOF

perl "$TMP_DIR/mock_ns_server.pl" "$PORT" &
MOCK_PID=$!
sleep 0.5

echo "=== 1. Testing +nssearch In-Bailiwick Glue Utilization ==="
echo -n "Test: +nssearch +glue resolves SOA using in-bailiwick Glue without system resolver ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT test.internal.zone +nssearch +glue +timeout=2 2>&1 || true)
if echo "$OUT" | grep -q "SOA ns1\.test\.internal\.zone\." && echo "$OUT" | grep -q "2026090101"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing Batch Mode (-f) with Advanced Per-Line Options ==="
cat << EOF > "$TMP_DIR/batch.txt"
test.internal.zone A +tcp +nohexdump
test.internal.zone A +yaml +nohexdump
test.internal.zone +nssearch +glue +nohexdump
EOF

echo -n "Test: Batch mode executes per-line +tcp, +yaml, and +nssearch +glue without warnings ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT -f "$TMP_DIR/batch.txt" 2>&1 || true)
if echo "$OUT" | grep -q "type: MESSAGE" && echo "$OUT" | grep -q "SOA ns1\.test\.internal\.zone\." && ! echo "$OUT" | grep -qi "unexpected extra token"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL BATCH & NSSEARCH GLUE TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED BATCH & NSSEARCH GLUE TESTS FAILED!"
    exit 1
fi

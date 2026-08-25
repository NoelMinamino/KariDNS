#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML DNS Cookie STATUS Verification Test Suite
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

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT=$((19000 + $$ % 10000))
TMP_DIR="/tmp/karidns_yaml_cookie_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS TCP server capable of echoing valid or spoofed/corrupted cookie
cat <<'PL_EOF' > "$TMP_DIR/mock_cookie_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0];
socket(my $srv, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen($srv, 5) or die "listen: $!";

while (my $client = accept(my $conn, $srv)) {
    my $len_buf;
    next unless read($conn, $len_buf, 2) == 2;
    my $qlen = unpack("n", $len_buf);
    my $query;
    next unless read($conn, $query, $qlen) == $qlen;
    next if length($query) < 12;
    my $qid = substr($query, 0, 2);

    # Extract client cookie from query if present
    # Mock behavior: if query name contains "badcookie", return mismatching cookie
    my $is_bad = ($query =~ /badcookie/i) ? 1 : 0;
    my $client_cookie = "\x01\x02\x03\x04\x05\x06\x07\x08";
    if ($query =~ /\x00\x0a\x00\x08(.{8})/s) {
        $client_cookie = $1;
    }

    if ($is_bad) {
        # Corrupt client cookie to trigger mismatch
        $client_cookie = "\xde\xad\xbe\xef\x00\x00\x00\x00";
    }
    my $server_cookie = "\xaa\xbb\xcc\xdd\xee\xff\x11\x22";
    my $cookie_rdata = pack("nn", 10, length($client_cookie . $server_cookie)) . $client_cookie . $server_cookie;

    # Build response: QR=1, RCODE=0
    my $resp = $qid . pack("nnnnn", 0x8180, 1, 0, 0, 1);
    # Question
    if ($is_bad) {
        $resp .= "\x09badcookie\x07example\x03com\x00" . pack("nn", 1, 1);
    } else {
        $resp .= "\x0aexpectedcc\x07example\x03com\x00" . pack("nn", 1, 1);
    }
    # OPT record in Additional: name=0, type=41, udp=1232, ext_flags=0, rdlen
    $resp .= "\x00" . pack("nnNn", 41, 1232, 0, length($cookie_rdata)) . $cookie_rdata;

    my $resp_len = pack("n", length($resp));
    syswrite($conn, $resp_len . $resp);
    close($conn);
}
PL_EOF

perl "$TMP_DIR/mock_cookie_server.pl" "$PORT" &
SRV_PID=$!
sleep 0.5

echo "=== 1. Testing YAML Cookie Matching Status (STATUS: good) ==="
echo -n "Test: Matching client cookie produces STATUS: good ... "
OUT1=$($DAG @127.0.0.1 -p $PORT expectedcc.example.com A +tcp +cookie +yaml 2>&1 || true)
if echo "$OUT1" | grep -q "STATUS: good"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT1"
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing YAML Cookie Mismatch Status (STATUS: bad) ==="
echo -n "Test: Mismatched client cookie produces STATUS: bad ... "
OUT2=$($DAG @127.0.0.1 -p $PORT badcookie.example.com A +tcp +cookie +yaml 2>&1 || true)
if echo "$OUT2" | grep -q "STATUS: bad"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT2"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML COOKIE STATUS TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML COOKIE STATUS TESTS FAILED!"
    exit 1
fi

#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace Deep CNAME Stack Exhaustion Test Suite (CWE-674 / CWE-789)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    echo "PASS: +trace deep CNAME stack test (skipped for dig)"
    exit 0
fi

if [ ! -x "$DAG" ]; then
    if [ -x "$ROOT_DIR/dag-asan" ]; then
        DAG="$ROOT_DIR/dag-asan"
    elif [ -x "$ROOT_DIR/dag" ]; then
        DAG="$ROOT_DIR/dag"
    else
        make -C "$ROOT_DIR" dag >/dev/null 2>&1 || true
        DAG="$ROOT_DIR/dag"
    fi
fi

if [ ! -x "$DAG" ]; then
    echo "Error: dag executable not found at $DAG"
    exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT=$((19000 + $$ % 10000))
TMP_DIR="/tmp/dag_trace_deep_cname_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "${MOCK_PID:-}" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create mock DNS server handling 16-hop CNAME, excessive CNAME, and root NS
cat << 'PL_EOF' > "$TMP_DIR/mock_trace_deep_cname.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port> [ready_file]\n";
my $ready_file = $ARGV[1];
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!";
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

if ($ready_file) {
    if (open(my $rfh, ">", $ready_file)) {
        close($rfh);
    }
}

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
    } elsif ($qname =~ /^c(\d+)\.example\.com\./i) {
        my $n = int($1);
        my $qwire = substr($query, 12, $off - 12);
        if ($n < 16) {
            my $target_name = "c" . ($n + 1) . ".example.com";
            my $target_wire = "";
            for my $p (split /\./, $target_name) {
                $target_wire .= chr(length($p)) . $p;
            }
            $target_wire .= "\x00";

            $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                    $qwire . pack("nn", 1, 1) .
                    $qwire . pack("nnNn", 5, 1, 300, length($target_wire)) . $target_wire;
        } else {
            # Final 16th hop target: return A 192.0.2.1
            $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                    $qwire . pack("nn", 1, 1) .
                    $qwire . pack("nnNn", 1, 1, 300, 4) . inet_aton("192.0.2.1");
        }
    } elsif ($qname =~ /^loop(\d+)\.example\.com\./i) {
        my $n = int($1);
        my $qwire = substr($query, 12, $off - 12);
        my $target_name = "loop" . ($n + 1) . ".example.com";
        my $target_wire = "";
        for my $p (split /\./, $target_name) {
            $target_wire .= chr(length($p)) . $p;
        }
        $target_wire .= "\x00";

        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                $qwire . pack("nn", 1, 1) .
                $qwire . pack("nnNn", 5, 1, 300, length($target_wire)) . $target_wire;
    } else {
        $resp = $qid . pack("nnnnn", 0x8183, 1, 0, 0, 0) . substr($query, 12, $off + 4 - 12);
    }

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

READY_FILE="$TMP_DIR/mock_ready"
rm -f "$READY_FILE"
perl "$TMP_DIR/mock_trace_deep_cname.pl" "$PORT" "$READY_FILE" &
MOCK_PID=$!

for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -f "$READY_FILE" ]; then break; fi
    sleep 0.05
done

if [ ! -f "$READY_FILE" ]; then
    echo "Error: mock DNS server failed to bind on port $PORT"
    exit 1
fi

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    echo -n "Test: $NAME ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -qE "(ERROR: AddressSanitizer|stack-overflow|Abort trap)"; then
        echo "FAILED (sanitizer/crash detected)"
        echo "  Command: $CMD"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    elif echo "$OUT" | grep -E -q "$EXPECT"; then
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

echo "=== 1. Testing 16-Hop CNAME Resolution via +trace ==="
run_check "16-hop CNAME chain resolves to final A target (192.0.2.1)" \
    "$DAG @127.0.0.1 -p $PORT c0.example.com A +trace +timeout=2" \
    "192\.0\.2\.1"

echo "=== 2. Testing Excessive CNAME Chain Cut-off (TRACE_MAX_CNAME_DEPTH) ==="
echo -n "Test: Excessive CNAME chain cleanly terminates at depth 16 ... "
OUT=$("$DAG" @127.0.0.1 -p "$PORT" loop0.example.com A +trace +timeout=2 2>&1 || true)
if echo "$OUT" | grep -qE "(ERROR: AddressSanitizer|stack-overflow|Abort trap)"; then
    echo "FAILED (sanitizer/crash detected)"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
elif echo "$OUT" | grep -q "loop16\.example\.com" && ! echo "$OUT" | grep -q "loop18\.example\.com"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 3. Testing Stack Safety under Restricted Stack Limit ==="
STACK_LIMIT=2048
if ( ulimit -s "$STACK_LIMIT" >/dev/null 2>&1 ); then
    echo -n "Test: Trace runs without stack overflow under ulimit -s $STACK_LIMIT ... "
    OUT=$( ( ulimit -s "$STACK_LIMIT" && "$DAG" @127.0.0.1 -p "$PORT" loop0.example.com A +trace +timeout=2 ) 2>&1 || true )
    if echo "$OUT" | grep -qE "(ERROR: AddressSanitizer|stack-overflow|Abort trap)"; then
        echo "FAILED (stack overflow detected)"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    elif echo "$OUT" | grep -q "loop16\.example\.com"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
else
    echo "Test: Restricted stack limit ... SKIP (ulimit -s not supported)"
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE DEEP CNAME STACK TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TRACE DEEP CNAME STACK TESTS FAILED!"
    exit 1
fi

#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML EDE (Extended DNS Error) Double-Quote Escaping Test Suite
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
PORT=$((18000 + $$ % 10000))
TMP_DIR="/tmp/karidns_yaml_ede_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Start Mock DNS UDP server that returns EDE option code 18 (Prohibited)
# with extra-text containing double-quotes and backslashes:
# text = "blocked by \"firewall\" \\policy\\"
cat <<'PL_EOF' > "$TMP_DIR/mock_ede_server.pl"
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

    # Build EDE option: code 15, info-code 18 (Prohibited), text 'blocked by "policy" and \rules\'
    my $ede_text = 'blocked by "policy" and \\rules\\';
    my $ede_rdata = pack("n", 18) . $ede_text;
    my $opt_rdata = pack("nn", 15, length($ede_rdata)) . $ede_rdata;
    
    # Response header: QR=1, RCODE=5 (REFUSED)
    my $resp = $qid . pack("nnnnn", 0x8185, 1, 0, 0, 1);
    # Question
    $resp .= "\x07example\x03com\x00" . pack("nn", 1, 1);
    # OPT record in Additional: name=root(0), type=41(OPT), udp=1232, ext_flags=0, rdlen
    $resp .= "\x00" . pack("nnNn", 41, 1232, 0, length($opt_rdata)) . $opt_rdata;

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

perl "$TMP_DIR/mock_ede_server.pl" "$PORT" &
SRV_PID=$!
sleep 0.5

echo "=== 1. Testing YAML EDE Double-Quote and Backslash Escaping ==="
echo -n "Test: EDE EXTRA-TEXT is escaped with backslashes in YAML mode ... "
YAML_OUT="$TMP_DIR/out.yaml"
$DAG @127.0.0.1 -p $PORT example.com A +yaml > "$YAML_OUT" 2>&1 || true

cat <<'PL_EOF' > "$TMP_DIR/verify_yaml.pl"
use strict;
use warnings;

my $file = $ARGV[0];
open(my $fh, "<", $file) or die "Cannot open $file: $!";
my $content = do { local $/; <$fh> };
close($fh);

if ($content =~ /EXTRA-TEXT:\s*"(.+)"/) {
    my $val = $1;
    if ($val eq 'blocked by \"policy\" and \\\\rules\\\\') {
        exit 0;
    } else {
        die "Unescaped or malformed EXTRA-TEXT string in YAML: $val\n";
    }
} else {
    die "EXTRA-TEXT key not found or quotes malformed in YAML output\n";
}
PL_EOF

if ERR=$(perl "$TMP_DIR/verify_yaml.pl" "$YAML_OUT" 2>&1); then
    echo "OK"
else
    echo "FAILED"
    echo "  Error: $ERR"
    echo "  YAML Content:"
    sed 's/^/    /' "$YAML_OUT"
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML EDE ESCAPING TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML EDE ESCAPING TESTS FAILED!"
    exit 1
fi

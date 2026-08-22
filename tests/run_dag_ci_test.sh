#!/bin/sh
# ==============================================================================
# KariDNS dag(1) & BIND 9 dig(1) Comprehensive Test Suite
# Usage:
#   sh tests/run_dag_ci_test.sh       # Runs tests with ./dag (Default)
#   sh tests/run_dag_ci_test.sh dig   # Runs tests with system dig
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="dag_ci_test_dir"
PORT=53555

CLIENT_ARG="${1:-dag}"
if [ "$CLIENT_ARG" = "dig" ]; then
    if ! command -v dig >/dev/null 2>&1; then
        echo "Error: 'dig' command not found in PATH."
        exit 1
    fi
    DAG="dig"
    CLIENT_NAME="BIND 9 dig ($(dig -v 2>&1 | head -n 1))"
    make -C "$BIN_DIR" all >/dev/null 2>&1
else
    make -C "$BIN_DIR" all >/dev/null 2>&1
    DAG="$BIN_DIR/dag"
    CLIENT_NAME="KariDNS dag"
fi

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

KARIDNS="$BIN_DIR/karidns"

echo "========================================================"
echo "Running Test Suite with: $CLIENT_NAME"
echo "========================================================"

# Configure local KariDNS authoritative server
cat << EOF > karidns.conf
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "${SCRIPT_DIR}/zones/example.com.zone";
    };
};
EOF

# Start local server in background
"$KARIDNS" -f karidns.conf > karidns.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
    echo "=== Cleaning up ==="
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

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

run_exit_check() {
    NAME="$1"
    CMD="$2"
    EXP_CODE="$3"
    echo -n "Exit code test: $NAME ... "
    set +e
    eval "$CMD" >/dev/null 2>&1
    ACT_CODE=$?
    set -e
    if [ "$ACT_CODE" -eq "$EXP_CODE" ]; then
        echo "OK (code $ACT_CODE)"
    else
        echo "FAILED (expected $EXP_CODE, got $ACT_CODE)"
        FAILED=$((FAILED + 1))
    fi
}

echo "========================================================"
echo "1. Basic Queries & Transport (UDP, TCP, Short, Stats)"
echo "========================================================"
run_check "Standard UDP Query" "$DAG @127.0.0.1 -p $PORT www.example.com A" "192.0.2.10"
run_check "Standard TCP Query (+tcp)" "$DAG @127.0.0.1 -p $PORT www.example.com A +tcp" "192.0.2.10"
run_check "Short mode (+short)" "$DAG @127.0.0.1 -p $PORT www.example.com A +short" "^192\.0\.2\.10$"
run_check "Show Query (+qr)" "$DAG @127.0.0.1 -p $PORT www.example.com A +qr" ";; Sending:"
run_check "Microsecond stats (-u)" "$DAG @127.0.0.1 -p $PORT www.example.com A -u" ";; Query time:.*usec"
if [ "$DAG" = "dig" ]; then
    run_exit_check "Memory & Rusage Stats flag (-m)" "$DAG @127.0.0.1 -p $PORT www.example.com A -m" 0
else
    run_check "Memory & Rusage Stats (-m)" "$DAG @127.0.0.1 -p $PORT www.example.com A -m" ";; Memory usage: maxrss="
fi
run_check "No comments (+nocomments)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nocomments" "192\.0\.2\.10"

echo "========================================================"
echo "2. Layout, Class & TTL Formatting"
echo "========================================================"
run_check "No class (+noclass)" "$DAG @127.0.0.1 -p $PORT www.example.com A +noclass" "www\.example\.com\.[[:space:]]+[0-9]+[[:space:]]+A[[:space:]]+192\.0\.2\.10"
run_check "TTL units (+ttlunits)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ttlunits" "www\.example\.com\.[[:space:]]+[0-9]+[smhd][[:space:]]+IN[[:space:]]+A"
run_check "Unknown format (+unknownformat)" "$DAG @127.0.0.1 -p $PORT www.example.com A +unknownformat" 'CLASS1[[:space:]]+TYPE1[[:space:]]+\\#[[:space:]]+[0-9]+'
run_check "TTL ID toggling (+ttlid / +nottlid)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nottlid" "www\.example\.com\.[[:space:]]+IN[[:space:]]+A"
run_check "Multiline mode (+multiline)" "$DAG @127.0.0.1 -p $PORT example.com SOA +multiline" "serial"

echo "========================================================"
echo "3. DNSSEC & RR Comments & Crypto formatting"
echo "========================================================"
run_check "RR Comments on DNSKEY (+rrcomments)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +rrcomments" "; KSK; alg =.*key id ="
run_check "Omit crypto on DNSKEY (+nocrypto)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +nocrypto" "\[key id ="
run_check "Split width (+split=16)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +split=16" "257 3 [0-9]+ [A-Za-z0-9+/=]{16} [A-Za-z0-9+/=]{16}"
run_check "DNSSEC OK flag (+dnssec / +do)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +dnssec +qr" "flags: do"

echo "========================================================"
echo "4. EDNS0 & RFC 9824 Options"
echo "========================================================"
run_check "EDNS CO flag (+coflag)" "$DAG @127.0.0.1 -p $PORT www.example.com A +coflag +qr" "flags: co"
run_check "EDNS Cookie (+cookie)" "$DAG @127.0.0.1 -p $PORT www.example.com A +cookie=0102030405060708 +qr" "; COOKIE: 0102030405060708"
run_check "EDNS Subnet (+subnet)" "$DAG @127.0.0.1 -p $PORT www.example.com A +subnet=192.0.2.0/24 +qr" "; CLIENT-SUBNET: 192\.0\.2\.0/24"
run_check "EDNS Padding (+padding)" "$DAG @127.0.0.1 -p $PORT www.example.com A +padding=64 +qr" "; PADDING:"
run_check "EDNS Keepalive (+keepalive)" "$DAG @127.0.0.1 -p $PORT www.example.com A +keepalive +qr" "; (TCP-)?KEEPALIVE"
run_check "Generic EDNS option (+ednsopt)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ednsopt=65001:01020304 +qr" "; (OPTION:[[:space:]]+|OPT=)65001"

echo "========================================================"
echo "5. Query & Header Overrides"
echo "========================================================"
run_check "Header only / QDCOUNT=0 (+header-only)" "$DAG @127.0.0.1 -p $PORT www.example.com A +header-only +qr" "QUERY: 0"
run_check "QID override (+qid=4660)" "$DAG @127.0.0.1 -p $PORT www.example.com A +qid=4660 +qr" "id: 4660"
run_check "Opcode override (+opcode=NOTIFY)" "$DAG @127.0.0.1 -p $PORT www.example.com A +opcode=NOTIFY +qr" "opcode: NOTIFY"
run_check "Flags override (+adflag +cdflag +aaflag +tcflag +zflag)" "$DAG @127.0.0.1 -p $PORT www.example.com A +adflag +cdflag +aaflag +tcflag +zflag +qr" "flags:.*(ad|cd|aa|tc)"

echo "========================================================"
echo "6. Batch Files & .digrc Configuration"
echo "========================================================"
cat << 'EOF' > batch_test.txt
www.example.com A
mail.example.com A
example.com NS
EOF
run_check "Batch query file (-f)" "$DAG @127.0.0.1 -p $PORT -f batch_test.txt" "192\.0\.2\.20"

# Test .digrc loading
cat << 'EOF' > .digrc
+short
EOF
HOME="$TEST_DIR_ABS" run_check ".digrc default option loading" "HOME='$TEST_DIR_ABS' $DAG @127.0.0.1 -p $PORT www.example.com A" "^192\.0\.2\.10$"
HOME="$TEST_DIR_ABS" run_check "Ignore .digrc (-r)" "HOME='$TEST_DIR_ABS' $DAG @127.0.0.1 -p $PORT www.example.com A -r" ";; ->>HEADER<<-"

echo "========================================================"
echo "7. Exit Code Specification (0, 1, 8, 9)"
echo "========================================================"
run_exit_check "Exit code 0 on success" "$DAG @127.0.0.1 -p $PORT www.example.com A" 0
run_exit_check "Exit code 1 on usage error / bad option" "$DAG -X" 1
run_exit_check "Exit code 8 on missing batch file" "$DAG -f /nonexistent/batch/file.txt" 8
run_exit_check "Exit code 9 on unreachable server / timeout" "$DAG @127.0.0.1 -p 19999 www.example.com A +timeout=1 +tries=1" 9

echo "========================================================"
echo "8. Live DoT / DoH Checks (against public resolvers)"
echo "========================================================"
# Check if outbound internet is accessible
if "$DAG" @1.1.1.1 example.com A +timeout=2 +tries=1 >/dev/null 2>&1; then
    echo "Internet connectivity detected. Running Live DoT & DoH tests..."
    run_check "Live DoT (RFC 7858) @8.8.8.8" "$DAG @8.8.8.8 www.google.com A +tls +timeout=4" "142\.25[0-9]\.[0-9]+"
    run_check "Live DoH (RFC 8484) @1.1.1.1" "$DAG @1.1.1.1 www.cloudflare.com A +https +timeout=4" "104\.1[0-9]\.[0-9]+"
else
    echo "No direct outbound internet connectivity. Skipping live DoT/DoH network tests."
fi

echo "========================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL DAG COMPREHENSIVE CI TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

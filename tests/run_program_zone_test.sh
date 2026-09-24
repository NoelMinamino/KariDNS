#!/bin/sh
set -e

# ==============================================================================
# KariDNS type "program" Plugin Zone Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICHECK="${BIN_DIR}/karicheck"
DAG="${DAG:-$BIN_DIR/dag}"
PLUGIN_SCRIPT="${BASE_DIR}/tests/plugins/dnstestscript.pl"

TMP_DIR="$(mktemp -d /tmp/karidns_program_test.XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        pkill -P "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((28000 + $$ % 5000))
FAILED=0
USER_OPT=""
PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECTED="$3"

    echo -n "Test: $NAME ... "
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUTPUT" | grep -E -q "$EXPECTED"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
}

chmod +x "$PLUGIN_SCRIPT" || true

echo "=== 1. Testing karicheck validation for type program ==="

cat << EOF > "$TMP_DIR/no_opt.conf"
zone "brokentest.example." {
    type program;
    program "$PLUGIN_SCRIPT";
};
EOF

run_check "karicheck rejects type program when allow-program-zones is missing" \
    "$KARICHECK conf $TMP_DIR/no_opt.conf" \
    "allow-program-zones.*not enabled"

cat << EOF > "$TMP_DIR/with_opt.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    allow-program-zones yes;
};

zone "brokentest.example." {
    type program;
    program "$PLUGIN_SCRIPT";
    program-user "nobody";
    program-args { };
    program-timeout 2000;
    program-max-failures 5;
};
EOF

run_check "karicheck accepts type program when allow-program-zones is enabled" \
    "$KARICHECK conf $TMP_DIR/with_opt.conf" \
    "Config file .* is valid"

echo ""
echo "=== 2. Testing KariDNS execution with type program zone ==="

cat << EOF > "$TMP_DIR/karidns_run.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
};

zone "brokentest.example." {
    type program;
    program "$PLUGIN_SCRIPT";
    $PROG_USER_OPT
    program-timeout 2000;
    program-max-failures 5;
    # default disable-auto-tc-flag no (auto-TC active)
};

zone "notc.example." {
    type program;
    program "$PLUGIN_SCRIPT";
    $PROG_USER_OPT
    program-timeout 2000;
    program-max-failures 5;
    disable-auto-tc-flag yes;
};

zone "autotc.example." {
    type program;
    program "$PLUGIN_SCRIPT";
    $PROG_USER_OPT
    program-timeout 2000;
    program-max-failures 5;
    disable-auto-tc-flag no;
};
EOF

# Start karidns
"$KARIDNS" -f "$TMP_DIR/karidns_run.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

# Test standard query
run_check "Query to program zone returns plugin-generated response" \
    "$DAG @127.0.0.1 -p $PORT normal.brokentest.example A +timeout=2 +tries=1" \
    "192\.0\.2\.1"

# Test intentionally broken query
run_check "Query with truncated RDATA is handled without server crash" \
    "$DAG @127.0.0.1 -p $PORT trunc-rdata.brokentest.example A +timeout=2 +tries=1" \
    "ANSWER: 1"

# Test oversized response (>1232 bytes) with UDP when disable-auto-tc-flag is default (no) - should return TC bit
run_check "Oversized query via UDP with default disable-auto-tc-flag (no) returns TC bit" \
    "$DAG @127.0.0.1 -p $PORT oversized.brokentest.example TXT +ignore +timeout=2 +tries=1" \
    "flags:.*tc"

# Test oversized response (>1232 bytes) with UDP when disable-auto-tc-flag is yes - should NOT have TC bit and return full answer
run_check "Oversized query via UDP with disable-auto-tc-flag yes returns full response without TC" \
    "$DAG @127.0.0.1 -p $PORT oversized.notc.example TXT +timeout=2 +tries=1" \
    "ANSWER: 10"

# Test oversized response (>1232 bytes) with UDP when disable-auto-tc-flag is no - should return TC bit
run_check "Oversized query via UDP with disable-auto-tc-flag no returns TC bit" \
    "$DAG @127.0.0.1 -p $PORT oversized.autotc.example TXT +ignore +timeout=2 +tries=1" \
    "flags:.*tc"

# Test oversized response via TCP (should return full 10 TXT records)
run_check "Oversized query via TCP returns full response" \
    "$DAG @127.0.0.1 -p $PORT oversized.brokentest.example TXT +tcp +timeout=2 +tries=1" \
    "ANSWER: 10"

# Test large TCP request (>5000 bytes, exceeding 4096 BUFFER_SIZE) to synthetic program zone
LARGE_TCP_TEST="perl -e '
use strict;
use warnings;
use Socket;

my \$port = \$ARGV[0];
my \$ip = \"127.0.0.1\";

socket(my \$sock, PF_INET, SOCK_STREAM, getprotobyname(\"tcp\")) or die \"socket: \$!\";
my \$dest = sockaddr_in(\$port, inet_aton(\$ip));
connect(\$sock, \$dest) or die \"connect: \$!\";

my \$pad_len = 5000;
my \$txid = pack(\"n\", 0x1234);
my \$flags = pack(\"n\", 0x0100);
my \$counts = pack(\"nnnn\", 1, 0, 0, 1);
my \$qname = \"\\x06normal\\x0Abrokentest\\x07example\\x00\";
my \$qtype_qclass = pack(\"nn\", 1, 1);
my \$opt_rr = \"\\x00\" . pack(\"nnNn\", 41, 4096, 0, \$pad_len + 4) . pack(\"nn\", 12, \$pad_len) . (\"\\x00\" x \$pad_len);
my \$dns_msg = \$txid . \$flags . \$counts . \$qname . \$qtype_qclass . \$opt_rr;
my \$msg_len = length(\$dns_msg);

send(\$sock, pack(\"n\", \$msg_len) . \$dns_msg, 0);

my \$len_buf;
read(\$sock, \$len_buf, 2) or die \"read length failed\";
my \$res_len = unpack(\"n\", \$len_buf);

my \$res_body = \"\";
while (length(\$res_body) < \$res_len) {
    my \$chunk;
    my \$r = read(\$sock, \$chunk, \$res_len - length(\$res_body));
    last unless \$r;
    \$res_body .= \$chunk;
}

my (\$res_id, \$res_flags, \$qdcount, \$ancount) = unpack(\"nnnn\", substr(\$res_body, 0, 8));
my \$rcode = \$res_flags & 0x0F;
if (\$rcode == 0 && \$ancount >= 1 && \$res_body =~ /\\xC0\\x00\\x02\\x01/) {
    print \"SUCCESS: Large TCP query (\$msg_len bytes) processed without truncation\\n\";
} else {
    print \"FAIL: rcode=\$rcode ancount=\$ancount\\n\";
}
' $PORT"

run_check "Large TCP query (>5000 bytes) to async program zone is not truncated" \
    "$LARGE_TCP_TEST" \
    "SUCCESS: Large TCP query"

if [ "$FAILED" -gt 0 ] && [ -f "$TMP_DIR/karidns.log" ]; then
    echo "=== Server Log ==="
    cat "$TMP_DIR/karidns.log"
fi

# Stop server
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo ""
echo "=== Test Summary ==="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL PROGRAM ZONE TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TESTS FAILED!"
    exit 1
fi

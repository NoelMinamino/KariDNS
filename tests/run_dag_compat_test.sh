#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) BIND 9.20.26 Compatibility Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MOCK_PL="$SCRIPT_DIR/mock_dns_server.pl"
PORT=10530

echo "=== Building tools/dag with make ==="
make -C "$ROOT_DIR" dag

DAG="$ROOT_DIR/dag"
if [ ! -x "$DAG" ]; then
    echo "dag binary not found at $DAG"
    exit 1
fi

echo "=== Starting Mock DNS Server on port $PORT ==="
perl "$MOCK_PL" --port="$PORT" &
MOCK_PID=$!

cleanup() {
    echo "=== Cleaning up ==="
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

sleep 1

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

echo "=== Running Option & Compatibility Tests ==="

# 1. Base query & flags
run_check "Standard A query" "$DAG @127.0.0.1 -p $PORT example.com A" "93.184.216.34"
run_check "Show Query (+qr)" "$DAG @127.0.0.1 -p $PORT example.com A +qr" ";; Sending:"
run_check "Microsecond stats (-u)" "$DAG @127.0.0.1 -p $PORT example.com A -u" ";; Query time:.*usec"

# 2. Layout & Formatting
run_check "No class (+noclass)" "$DAG @127.0.0.1 -p $PORT example.com A +noclass" "example.com\.[[:space:]]+[0-9]+[[:space:]]+A[[:space:]]+93\.184\.216\.34"
run_check "TTL units (+ttlunits)" "$DAG @127.0.0.1 -p $PORT example.com A +ttlunits" "example.com\.[[:space:]]+[0-9]+[smhd][[:space:]]+IN[[:space:]]+A"
run_check "Unknown format (+unknownformat)" "$DAG @127.0.0.1 -p $PORT example.com A +unknownformat" 'CLASS1[[:space:]]+TYPE1[[:space:]]+\\#[[:space:]]+[0-9]+'

# 3. DNSSEC & Crypto
run_check "DNSSEC OK (+dnssec)" "$DAG @127.0.0.1 -p $PORT crypto.example DNSKEY +dnssec" "flags: do"
run_check "Omit crypto (+nocrypto DNSKEY)" "$DAG @127.0.0.1 -p $PORT crypto.example DNSKEY +nocrypto" "\[key id ="
run_check "RR Comments (+rrcomments)" "$DAG @127.0.0.1 -p $PORT crypto.example DNSKEY +rrcomments" "; KSK; alg =.*key id ="

# 4. EDNS & RFC 9824 Compact Denial of Existence (CO flag)
run_check "EDNS CO flag (+coflag)" "$DAG @127.0.0.1 -p $PORT example.com A +coflag +qr" "flags: co"

# 5. Recovery & Error Handling
run_check "BADCOOKIE auto retry (+badcookie)" "$DAG @127.0.0.1 -p $PORT badcookie.example A +badcookie" ";; BADCOOKIE, retrying\."
run_check "BADVERS retry (+ednsnegotiation)" "$DAG @127.0.0.1 -p $PORT badvers.example A +edns=1 +ednsnegotiation" ";; BADVERS, retrying with EDNS version 0\."
run_check "BADVERS no retry (+noednsnegotiation)" "$DAG @127.0.0.1 -p $PORT badvers.example A +edns=1 +noednsnegotiation" "status: BADVERS"
run_check "Best effort parser (+besteffort)" "$DAG @127.0.0.1 -p $PORT malformed-trunc.example A +besteffort" ";; Warning: Message parser reports malformed message packet\."

# 6. Header overrides & formatting
run_check "Header only / QDCOUNT=0 (+header-only)" "$DAG @127.0.0.1 -p $PORT example.com A +header-only +qr" "QUERY: 0"
run_check "QID override (+qid=4660)" "$DAG @127.0.0.1 -p $PORT example.com A +qid=4660 +qr" "id: 4660"
run_check "Split width (+split=16)" "$DAG @127.0.0.1 -p $PORT crypto.example DNSKEY +split=16" "257 3 8 [A-Za-z0-9+/=]{16} [A-Za-z0-9+/=]{16}"

# 7. Exit Codes
run_exit_check "Exit code 0 on success" "$DAG @127.0.0.1 -p $PORT example.com A" 0
run_exit_check "Exit code 8 on missing batch file" "$DAG -f /nonexistent/file/path.txt" 8
run_exit_check "Exit code 9 on unreachable server / timeout" "$DAG @127.0.0.1 -p 19999 example.com A +timeout=1 +tries=1" 9
run_exit_check "Exit code 1 on bad class argument" "$DAG -c INVALIDCLASS example.com" 1

echo "=================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "ALL DAG COMPATIBILITY TESTS PASSED!"
    exit 0
else
    echo "$FAILED TESTS FAILED!"
    exit 1
fi

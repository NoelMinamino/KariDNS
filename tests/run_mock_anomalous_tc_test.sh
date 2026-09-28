#!/bin/sh
set -e

# ==============================================================================
# run_mock_anomalous_tc_test.sh
#
# UDP auto-TC policy of tests/mock_anomalous_dns_server.pl (apply_udp_tc_policy).
#   - tcp-size-<N> / packet-size-<N> / tcp-max-65535: truncated to TC=1 over UDP when
#     larger than the EDNS UDP payload size (min 512), or 1232 bytes without EDNS.
#     Truncated responses carry an OPT RR (udp 1232) when the query had EDNS
#     (RFC 6891 §7).
#   - udp-size-<N> / edns-bufsize-exceeded: never truncated, returned as-is.
#
# Both response paths of the mock are exercised:
#   1. plugin mode behind KariDNS (type program, disable-auto-tc-flag yes)
#   2. standalone mode (--port), queried directly
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
DAG="${DAG:-$BIN_DIR/dag}"
PLUGIN_SCRIPT="${SCRIPT_DIR}/mock_anomalous_dns_server.pl"

TMP_DIR="$(mktemp -d /tmp/karidns_mock_tc_test.XXXXXX)"
SERVER_PID=""
MOCK_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        pkill -P "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

KARIDNS_PORT=$((37000 + $$ % 5000))
MOCK_PORT=$((KARIDNS_PORT + 1))
FAILED=0
USER_OPT=""
PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi

TC_FLAG='flags:[a-z ]* tc[ ;]'

# run_check NAME CMD EXPECTED [UNEXPECTED]
run_check() {
    NAME="$1"
    CMD="$2"
    EXPECTED="$3"
    UNEXPECTED="$4"

    printf "Test: %s ... " "$NAME"
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    if ! echo "$OUTPUT" | grep -E -q -- "$EXPECTED"; then
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    elif [ -n "$UNEXPECTED" ] && echo "$OUTPUT" | grep -E -q -- "$UNEXPECTED"; then
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Unexpected: $UNEXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    else
        echo "OK"
    fi
}

# run_exit_check NAME CMD EXPECTED_EXIT
run_exit_check() {
    printf "Test: %s ... " "$1"
    set +e
    OUTPUT=$(eval "$2" 2>&1)
    RC=$?
    set -e
    if [ "$RC" -eq "$3" ]; then
        echo "OK"
    else
        echo "FAILED (exit $RC, expected $3)"
        echo "  Command: $2"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
}

run_cases() {
    LABEL="$1"
    PORT="$2"
    Q="$DAG @127.0.0.1 -p $PORT"
    O="+timeout=2 +tries=1"

    echo ""
    echo "=== $LABEL ==="

    # tcp-size: truncated over UDP, full over TCP
    # (dag, unlike dig, sends no OPT by default; EDNS cases pass +bufsize explicitly)
    run_check "[$LABEL] tcp-size-2000 over UDP (bufsize 1232) is truncated"         "$Q tcp-size-2000.anomaly.test NULL +bufsize=1232 +ignore $O"         "$TC_FLAG.*ANSWER: 0"
    run_check "[$LABEL] truncated response carries OPT (udp 1232)"         "$Q tcp-size-5000.anomaly.test NULL +bufsize=4096 +ignore $O"         "; EDNS: version: 0, flags:; udp: 1232"
    run_check "[$LABEL] tcp-size-2000 over UDP retries in TCP and gets 2000 bytes"         "$Q tcp-size-2000.anomaly.test NULL +bufsize=1232 $O"         "MSG SIZE  rcvd: 2000"
    run_check "[$LABEL] tcp-size-2000 over TCP is not truncated"         "$Q tcp-size-2000.anomaly.test NULL +tcp $O"         "MSG SIZE  rcvd: 2000" "$TC_FLAG"
    run_check "[$LABEL] tcp-size-1232 over UDP (bufsize 1232) fits"         "$Q tcp-size-1232.anomaly.test NULL +bufsize=1232 +ignore $O"         "MSG SIZE  rcvd: 1232" "$TC_FLAG"
    run_check "[$LABEL] tcp-size-1233 over UDP (bufsize 1232) is truncated"         "$Q tcp-size-1233.anomaly.test NULL +bufsize=1232 +ignore $O"         "$TC_FLAG"

    # EDNS payload size drives the limit; below 512 is treated as 512 (RFC 6891 §6.2.5)
    run_check "[$LABEL] tcp-size-4000 with +bufsize=4096 fits" \
        "$Q tcp-size-4000.anomaly.test NULL +bufsize=4096 +ignore $O" \
        "MSG SIZE  rcvd: 4000" "$TC_FLAG"
    run_check "[$LABEL] tcp-size-5000 with +bufsize=4096 is truncated" \
        "$Q tcp-size-5000.anomaly.test NULL +bufsize=4096 +ignore $O" \
        "$TC_FLAG"
    run_check "[$LABEL] tcp-size-500 with +bufsize=100 fits (floor 512)" \
        "$Q tcp-size-500.anomaly.test NULL +bufsize=100 +ignore $O" \
        "MSG SIZE  rcvd: 500" "$TC_FLAG"
    run_check "[$LABEL] tcp-size-600 with +bufsize=100 is truncated (floor 512)" \
        "$Q tcp-size-600.anomaly.test NULL +bufsize=100 +ignore $O" \
        "$TC_FLAG"

    # Without EDNS the limit is 1232 and no OPT is added
    run_check "[$LABEL] tcp-size-1200 with +noedns fits" \
        "$Q tcp-size-1200.anomaly.test NULL +noedns +ignore $O" \
        "MSG SIZE  rcvd: 1200" "$TC_FLAG"
    run_check "[$LABEL] tcp-size-1300 with +noedns is truncated without OPT" \
        "$Q tcp-size-1300.anomaly.test NULL +noedns +ignore $O" \
        "$TC_FLAG" "OPT PSEUDOSECTION"

    # packet-size follows the same auto-TC policy as tcp-size
    run_check "[$LABEL] packet-size-2000 over UDP is truncated" \
        "$Q packet-size-2000.anomaly.test NULL +ignore $O" \
        "$TC_FLAG"

    # udp-size is never truncated
    run_check "[$LABEL] udp-size-2000 over UDP is returned as-is" \
        "$Q udp-size-2000.anomaly.test NULL $O" \
        "MSG SIZE  rcvd: 2000" "$TC_FLAG"
    run_check "[$LABEL] udp-size-5000 with +bufsize=512 is returned as-is" \
        "$Q udp-size-5000.anomaly.test NULL +bufsize=512 $O" \
        "MSG SIZE  rcvd: 5000" "$TC_FLAG"
    run_exit_check "[$LABEL] udp-size-65535 over UDP cannot be sent (timeout, exit 9)" \
        "$Q udp-size-65535.anomaly.test NULL +timeout=1 +tries=1" 9
    run_check "[$LABEL] server still answers after udp-size-65535" \
        "$Q normal.anomaly.test A $O" \
        "192\.0\.2\.1"

    # edns-bufsize-exceeded keeps TC=0 on purpose
    run_check "[$LABEL] edns-bufsize-exceeded is not truncated" \
        "$Q edns-bufsize-exceeded.anomaly.test NULL +ignore $O" \
        "ANSWER: 1" "$TC_FLAG"

    # 65535-byte answer: with disable-auto-tc-flag yes this used to be sent
    # as-is over UDP (exceeds the UDP maximum, so the client timed out)
    run_check "[$LABEL] tcp-max-65535 over UDP is truncated"         "$Q tcp-max-65535.anomaly.test NULL +ignore $O"         "$TC_FLAG"
    run_check "[$LABEL] tcp-max-65535 over UDP completes via TCP fallback"         "$Q tcp-max-65535.anomaly.test NULL $O"         "MSG SIZE  rcvd: 65535"
}

chmod +x "$PLUGIN_SCRIPT" || true

# ------------------------------------------------------------------------------
# 1. Plugin mode behind KariDNS
# ------------------------------------------------------------------------------
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $KARIDNS_PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
};

zone "anomaly.test." {
    type program;
    program "$PLUGIN_SCRIPT";
    $PROG_USER_OPT
    program-timeout 2000;
    program-max-failures 500;
    disable-auto-tc-flag yes;
};
EOF

"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: KariDNS failed to start. Log output:"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

run_cases "karidns plugin" "$KARIDNS_PORT"

kill "$SERVER_PID" 2>/dev/null || true
pkill -P "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

# ------------------------------------------------------------------------------
# 2. Standalone mode
# ------------------------------------------------------------------------------
perl "$PLUGIN_SCRIPT" --host 127.0.0.1 --port "$MOCK_PORT" > "$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!
sleep 1
if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "ERROR: mock server failed to start. Log output:"
    cat "$TMP_DIR/mock.log"
    exit 1
fi

run_cases "standalone" "$MOCK_PORT"

if [ "$FAILED" -gt 0 ]; then
    echo "=== KariDNS Log ==="
    cat "$TMP_DIR/karidns.log" 2>/dev/null || true
fi

echo ""
echo "=== Test Summary ==="
if [ "$FAILED" -eq 0 ]; then
    echo "ALL MOCK AUTO-TC TESTS PASSED"
    exit 0
else
    echo "$FAILED TESTS FAILED"
    exit 1
fi

#!/bin/sh
set -e

# ==============================================================================
# run_dag_dig_anomalous_suite.sh
#
# Comprehensive Anomalous DNS Packet Test Suite via KariDNS Plugin Zone.
# Launches KariDNS loaded with mock_anomalous_dns_server.pl as a 'type program'
# zone, then tests both 'dag' and 'dig' against the entire spectrum of malformed,
# truncated, looping, and edge-case DNS wire packets.
#
# Usage:
#   sh tests/run_dag_dig_anomalous_suite.sh [dag|dig|both]
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"

KARIDNS="${BIN_DIR}/karidns"
DAG_BIN="${DAG_BIN:-$BIN_DIR/dag}"
DIG_BIN="${DIG_BIN:-dig}"
PLUGIN_SCRIPT="${SCRIPT_DIR}/mock_anomalous_dns_server.pl"

TARGET="${1:-dag}"

# Ensure clean slate before running
killall -9 karidns karidns-asan 2>/dev/null || true

TMP_DIR="$(mktemp -d /tmp/karidns_anomalous_test.XXXXXX)"
PORT=$((32000 + $$ % 5000))
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

chmod +x "$PLUGIN_SCRIPT" || true

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

# ------------------------------------------------------------------------------
# 1. Start KariDNS with Anomalous Plugin Zone
# ------------------------------------------------------------------------------
cat << EOF > "$TMP_DIR/karidns_anomalous.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
};

zone "anomaly.test." {
    type program;
    program "$PLUGIN_SCRIPT";
    program-timeout 2000;
    program-max-failures 500;
};
EOF

echo "Starting KariDNS with Anomalous Plugin Zone on port $PORT..."
"$KARIDNS" -f "$TMP_DIR/karidns_anomalous.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

# Check if KariDNS is alive
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: KariDNS failed to start. Log output:"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_single_test() {
    CLI_NAME="$1"
    CLI_PATH="$2"
    TEST_NAME="$3"
    QUERY_DOMAIN="$4"
    EXTRA_FLAGS="$5"
    EXPECTED_PATTERN="$6"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    printf "  [%-4s] %-55s ... " "$CLI_NAME" "$TEST_NAME"

    set +e
    CMD="$CLI_PATH @127.0.0.1 -p $PORT $QUERY_DOMAIN A +timeout=2 +tries=1 $EXTRA_FLAGS"
    OUTPUT=$(eval "$CMD" 2>&1)
    EXIT_CODE=$?
    set -e

    # Check for crash (SIGSEGV=139, SIGBUS=138, SIGABRT=134)
    if [ "$EXIT_CODE" -ge 128 ]; then
        printf "${RED}CRASHED (Exit $EXIT_CODE)${NC}\n"
        echo "    Command: $CMD"
        echo "    Output: $OUTPUT"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return
    fi

    # Pattern check
    if [ -n "$EXPECTED_PATTERN" ]; then
        if echo "$OUTPUT" | grep -E -q -i "$EXPECTED_PATTERN"; then
            printf "${GREEN}PASS${NC}\n"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            printf "${RED}FAILED${NC}\n"
            echo "    Command: $CMD"
            echo "    Expected: $EXPECTED_PATTERN"
            echo "    Output:"
            echo "$OUTPUT" | sed 's/^/      /'
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        printf "${GREEN}PASS (Safe)${NC}\n"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
}

run_suite_for_tool() {
    TOOL_NAME="$1"
    TOOL_PATH="$2"

    if [ "$TOOL_NAME" = "dig" ] && ! command -v "$TOOL_PATH" >/dev/null 2>&1; then
        echo "${YELLOW}Skipping dig suite: 'dig' binary not found in PATH${NC}"
        return
    fi
    if [ "$TOOL_NAME" = "dag" ] && [ ! -x "$TOOL_PATH" ]; then
        echo "${RED}Error: dag binary not found at '$TOOL_PATH'. Run 'make dag' first.${NC}"
        exit 1
    fi

    printf "\n"
    printf "${BOLD}${BLUE}======================================================${NC}\n"
    printf "${BOLD}${BLUE} Testing %s via KariDNS type 'program' Plugin${NC}\n" "$TOOL_NAME"
    printf "${BOLD}${BLUE}======================================================${NC}\n"

    # Section 1: Baseline
    printf "${BOLD}[1. Baseline Normal Query]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Normal NOERROR response" \
        "normal.anomaly.test" "" "192\.0\.2\.1"

    # Section 2: Header & Structure Anomalies
    printf "${BOLD}[2. Header & Structural Anomalies]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Header-only packet (QD=0, AN=0)" \
        "header-only.anomaly.test" "" "(NOERROR|status: NOERROR|Got bad packet)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Short truncated header (< 12 bytes)" \
        "short-header.anomaly.test" "" "(malformed|bad packet|error|connection)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Trailing garbage bytes at packet end" \
        "trailing-garbage.anomaly.test" "" "(192\.0\.2\.1|Warning:.*malformed|extra bytes)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "QDCOUNT header mismatch" \
        "qdcount-mismatch.anomaly.test" "" "(malformed|bad packet|FORMERR|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "ANCOUNT underflow (missing records)" \
        "ancount-underflow.anomaly.test" "" "(malformed|bad packet|unexpected end)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "ANCOUNT with +besteffort" \
        "ancount-underflow.anomaly.test" "+besteffort" "192\.0\.2\.1"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "ANCOUNT overflow (extra record)" \
        "ancount-overflow.anomaly.test" "" "192\.0\.2\.1"

    # Section 3: Name Compression & Pointer Anomalies
    printf "${BOLD}[3. Name Compression & Pointer Safety]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Direct pointer compression loop" \
        "compression-loop.anomaly.test" "" "(malformed|bad packet|loop|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Forward/out-of-bounds pointer" \
        "compression-forward-ptr.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Unclosed/unterminated label" \
        "unclosed-label.anomaly.test" "" "(malformed|bad packet|error)"

    # Section 4: RDATA Truncation & Boundary Violations
    printf "${BOLD}[4. RDATA Truncation & Boundary Safety]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Truncated A record (2 bytes RDATA)" \
        "rdata-short-a.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Truncated AAAA record (8 bytes RDATA)" \
        "rdata-short-aaaa.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Truncated SOA record" \
        "rdata-soa-truncated.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Truncated MX record" \
        "rdata-mx-truncated.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "TXT record length mismatch" \
        "rdata-txt-len-mismatch.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "SVCB TargetName length overflow" \
        "rdata-svcb-overflow.anomaly.test" "" "(malformed|bad packet|error)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "OPT RR truncated option" \
        "rdata-opt-truncated.anomaly.test" "" "(malformed|bad packet|error|OPT Pseudo)"

    # Section 5: Protocol & Security Flags
    printf "${BOLD}[5. Protocol & Security Flags]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "BADCOOKIE (RCODE 23) auto-retry" \
        "cookie-badcookie.anomaly.test" "+cookie" "(BADCOOKIE|192\.0\.2\.1|COOKIE:)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Truncated TC=1 UDP response" \
        "truncated-tc.anomaly.test" "" "(flags:.*tc|Truncated, retrying in TCP|192\.0\.2\.1)"

    # Section 6: RFC Standard & Extended RCODEs
    printf "${BOLD}[6. DNS RCODE Responses]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 1: FORMERR" \
        "rcode-formerr.anomaly.test" "" "FORMERR"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 2: SERVFAIL" \
        "rcode-servfail.anomaly.test" "" "SERVFAIL"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 3: NXDOMAIN" \
        "rcode-nxdomain.anomaly.test" "" "NXDOMAIN"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 4: NOTIMP" \
        "rcode-notimp.anomaly.test" "" "NOTIMP"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 5: REFUSED" \
        "rcode-refused.anomaly.test" "" "REFUSED"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 6: YXDOMAIN" \
        "rcode-yxdomain.anomaly.test" "" "YXDOMAIN"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 7: YXRRSET" \
        "rcode-yxrrset.anomaly.test" "" "YXRRSET"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 8: NXRRSET" \
        "rcode-nxrrset.anomaly.test" "" "NXRRSET"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 9: NOTAUTH" \
        "rcode-notauth.anomaly.test" "" "NOTAUTH"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "RCODE 10: NOTZONE" \
        "rcode-notzone.anomaly.test" "" "NOTZONE"

    # Section 7: Extended DNS Errors (EDE, RFC 8914)
    printf "${BOLD}[7. Extended DNS Errors (EDE)]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "EDE Code 18 (Prohibited)" \
        "ede-prohibited.anomaly.test" "" "(EDE: 18|Prohibited|Query blocked)"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "EDE Long description string" \
        "ede-long-text.anomaly.test" "" "(EDE: 0|ExtendedErrorDescription|AAAA)"

    # Section 8: Drop / Timeout
    printf "${BOLD}[8. Drop / Silent Discard Handling]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Silent query drop handling" \
        "drop.anomaly.test" "" "(no servers could be reached|connection timed out|communications error)"

    # Section 9: AXFR & TXT Usage Guide
    printf "${BOLD}[9. Usage Guide & Help (AXFR / TXT)]${NC}\n"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "AXFR Zone Transfer Usage Guide" \
        "anomaly.test" "AXFR" "KariDNS Anomalous DNS Packet Test Server"
    run_single_test "$TOOL_NAME" "$TOOL_PATH" "Apex TXT Query Usage Guide" \
        "anomaly.test" "TXT" "KariDNS Anomalous DNS Packet Test Server"
}

# Run target suites
if [ "$TARGET" = "dag" ] || [ "$TARGET" = "both" ]; then
    run_suite_for_tool "dag" "$DAG_BIN"
fi

if [ "$TARGET" = "dig" ] || [ "$TARGET" = "both" ]; then
    run_suite_for_tool "dig" "$DIG_BIN"
fi

printf "\n"
printf "${BOLD}======================================================${NC}\n"
printf "${BOLD} Test Suite Summary${NC}\n"
printf "${BOLD}======================================================${NC}\n"
printf "  Total Executed Tests : %d\n" "$TOTAL_TESTS"
printf "  Passed Tests         : ${GREEN}%d${NC}\n" "$PASSED_TESTS"
if [ "$FAILED_TESTS" -eq 0 ]; then
    printf "  Failed Tests         : ${GREEN}0${NC}\n\n"
    printf "${BOLD}${GREEN}🎉 ALL ANOMALOUS PACKET TESTS PASSED SUCCESSFULLY!${NC}\n"
    exit 0
else
    printf "  Failed Tests         : ${RED}%d${NC}\n\n" "$FAILED_TESTS"
    printf "${BOLD}${RED}❌ %d TEST(S) FAILED!${NC}\n" "$FAILED_TESTS"
    exit 1
fi

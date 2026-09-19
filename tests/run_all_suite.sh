#!/bin/sh
# ==============================================================================
# KariDNS & dag Integrated Test Suite Runner
# ==============================================================================
# Runs all or categorized test scripts and unit test binaries, performs
# pre/post-test process cleanup, measures execution time, and produces a
# formatted summary report.
#
# Usage:
#   sh tests/run_all_suite.sh [options]
#
# Options:
#   -c, --category <name>   Run tests matching category (unit, xfr, dnssec,
#                           update, edns, rrl, catalog, tinydns, core, dag,
#                           regression, all). Comma-separated or multiple -c.
#   -f, --filter <pattern>  Run tests whose name matches pattern.
#   -q, --quick             Run fast unit and core tests only.
#   -x, --stop-on-failure   Abort immediately upon first test failure.
#   -v, --verbose           Print verbose real-time test output.
#   -l, --list              List all registered test cases with categories.
#   -h, --help              Show this help message.
# ==============================================================================

set -u

# ANSI Color codes (disabled if not terminal or NO_COLOR set)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
    C_RED="\033[31m"
    C_GREEN="\033[32m"
    C_YELLOW="\033[33m"
    C_BLUE="\033[34m"
    C_CYAN="\033[36m"
    C_WHITE="\033[37m"
    C_BG_RED="\033[41m\033[37m"
    C_BG_GREEN="\033[42m\033[30m"
else
    C_RESET=""
    C_BOLD=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_CYAN=""
    C_WHITE=""
    C_BG_RED=""
    C_BG_GREEN=""
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}" || exit 1

LOG_DIR="${ROOT_DIR}/tests/.test_logs"
mkdir -p "${LOG_DIR}"

SELECTED_CATEGORIES=""
NAME_FILTER=""
STOP_ON_FAILURE=0
VERBOSE=0
QUICK_MODE=0
LIST_ONLY=0
SKIP_DAG=0

# Ensure LLVM_PROFILE_FILE is an absolute path so sub-scripts that change directory still write profdata
if [ -n "${LLVM_PROFILE_FILE:-}" ]; then
    case "${LLVM_PROFILE_FILE}" in
        /*) ;; # already absolute
        *)  LLVM_PROFILE_FILE="${ROOT_DIR}/${LLVM_PROFILE_FILE}"
            export LLVM_PROFILE_FILE
            ;;
    esac
fi

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--category)
            shift
            if [ $# -gt 0 ]; then
                if [ -z "${SELECTED_CATEGORIES}" ]; then
                    SELECTED_CATEGORIES="$1"
                else
                    SELECTED_CATEGORIES="${SELECTED_CATEGORIES},$1"
                fi
            fi
            ;;
        --category=*)
            CAT_VAL="${1#*=}"
            if [ -z "${SELECTED_CATEGORIES}" ]; then
                SELECTED_CATEGORIES="${CAT_VAL}"
            else
                SELECTED_CATEGORIES="${SELECTED_CATEGORIES},${CAT_VAL}"
            fi
            ;;
        -f|--filter)
            shift
            [ $# -gt 0 ] && NAME_FILTER="$1"
            ;;
        --filter=*)
            NAME_FILTER="${1#*=}"
            ;;
        -q|--quick)
            QUICK_MODE=1
            ;;
        -x|--stop-on-failure)
            STOP_ON_FAILURE=1
            ;;
        -v|--verbose)
            VERBOSE=1
            ;;
        -l|--list)
            LIST_ONLY=1
            ;;
        --no-dag|--skip-dag)
            SKIP_DAG=1
            ;;
        -h|--help)
            echo "KariDNS Test Suite Runner"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -c, --category <name>   Filter by category (comma-separated or multiple):"
            echo "                          unit, xfr, dnssec, update, edns, rrl, catalog,"
            echo "                          dnstap, tinydns, core, regression, dag, all"
            echo "  --no-dag, --skip-dag    Skip dag diagnostic client test suite"
            echo "  -f, --filter <pattern>  Filter tests matching name substring"
            echo "  -q, --quick             Run quick unit and core tests only"
            echo "  -x, --stop-on-failure   Stop on first test failure"
            echo "  -v, --verbose           Print verbose output during execution"
            echo "  -l, --list              List all available tests and exit"
            echo "  -h, --help              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Run with -h or --help for usage." >&2
            exit 1
            ;;
    esac
    shift
done

# Environment cleanup helper
cleanup_stale_processes() {
    # 1. Kill stale background servers / mocks gracefully with TERM, then KILL
    pkill -TERM -f "karidns" 2>/dev/null || true
    pkill -TERM -f "mock_server.pl" 2>/dev/null || true
    pkill -TERM -f "mock_anomalous_dns_server.pl" 2>/dev/null || true
    pkill -TERM -f "mock_dnstap_receiver.pl" 2>/dev/null || true
    pkill -TERM -f "mock_dns_server.pl" 2>/dev/null || true
    pkill -TERM -f "rr_differential_test.pl" 2>/dev/null || true
    sleep 0.1 2>/dev/null || true
    pkill -9 -f "karidns" 2>/dev/null || true
    pkill -9 -f "mock_server.pl" 2>/dev/null || true
    pkill -9 -f "mock_anomalous_dns_server.pl" 2>/dev/null || true
    pkill -9 -f "mock_dnstap_receiver.pl" 2>/dev/null || true
    pkill -9 -f "mock_dns_server.pl" 2>/dev/null || true
    pkill -9 -f "rr_differential_test.pl" 2>/dev/null || true
    
    # 2. Cleanup temporary sockets and test pipes
    rm -f /tmp/karidns*.sock /tmp/dnstap*.sock /tmp/karidns_test_*.pipe 2>/dev/null || true
    rm -f tests/*.tmp tests/zones/*.tmp /tmp/karictl*.sock 2>/dev/null || true
    
    # Small pause to allow kernel socket release
    sleep 0.05 2>/dev/null || true
}

# Array-like test registration
TEST_COUNT=0
REGISTERED_TESTS=""

register_test() {
    # $1: Category, $2: ExecType (bin|sh), $3: Command/Path, $4: Description
    _cat="$1"
    _type="$2"
    _cmd="$3"
    _desc="$4"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    REGISTERED_TESTS="${REGISTERED_TESTS}${_cat}|${_type}|${_cmd}|${_desc}\n"
}

# ==============================================================================
# Test Registry (All Server & Core Tests + Optional dag Suite)
# ==============================================================================

# 1. Unit Tests (C Binaries)
register_test "unit" "bin" "test_vulnerability_fixes" "Vulnerability & Epoch RCU robustness test"
register_test "unit" "bin" "test_query_engine_expanded" "All-RR types, wildcards, DNAME & 0x20 bit preservation"
register_test "unit" "bin" "test_response_cache" "Response cache lock-free lookup & invalidation"
register_test "unit" "bin" "test_dnstap_engine" "DNSTAP Protobuf encoder, frame sender & ring buffers"
register_test "unit" "bin" "test_edns_ecs_engine" "EDNS Cookies, EDE error codes & ECS subnet LPM resolution"
register_test "unit" "bin" "test_dynamic_update_engine" "RFC 2136 SOA serial bump & NOTIFY deduplication"
register_test "unit" "bin" "test_axfr_ixfr_engine" "RFC 1995 IXFR differential computation & Option 65153"
register_test "unit" "bin" "test_rrl_engine" "SipHash token bucket rate limiter & SLIP responses"
register_test "unit" "bin" "test_catalog_zone_engine" "RFC 9432 Catalog zone processing & broken catalog rejection"
register_test "unit" "bin" "test_snapshot_sandbox_engine" "Capsicum directory caching, sandbox & snapshot RCU"
register_test "unit" "bin" "test_dag_tools" "TCP stream reassembly (in-order, OOO, LRU) & TSIG parser"
register_test "unit" "bin" "test_asan_overflow" "ASan boundary checks, CLASS validation & parsers"
register_test "unit" "bin" "test_tinydns_parser" "tinydns data file syntax & record decoder"
register_test "unit" "bin" "test_cidr" "CIDR prefix matching & binary ACL evaluator"
register_test "unit" "bin" "test_conf_include" "Config file tokenizer & \$INCLUDE nesting"
register_test "unit" "bin" "test_hash_table" "Fixed-size FNV1a hash table collisions"

# 2. Zone Transfer / Redundancy (AXFR / IXFR)
register_test "xfr" "sh" "tests/run_capsicum_axfr_test.sh" "Capsicum sandbox capability mode AXFR"
register_test "xfr" "sh" "tests/run_ixfr_roundtrip_test.sh" "RFC 1995 IXFR incremental diff roundtrip"
register_test "xfr" "sh" "tests/run_extended_axfr_test.sh" "KariDNS Extended AXFR (Option 65153)"
register_test "xfr" "sh" "tests/run_axfr_multikey_tsig_test.sh" "Multi-key TSIG authentication in AXFR"
register_test "xfr" "sh" "tests/run_udp_ixfr_test.sh" "RFC 1995 IXFR single-UDP packet transfer"
register_test "xfr" "sh" "tests/run_zone_type_secondary_test.sh" "Secondary zone SOA refresh polling"

# 3. DNSSEC & Message Digests
register_test "dnssec" "sh" "tests/run_zonemd_val_test.sh" "RFC 8976 ZONEMD verification against test vectors"
register_test "dnssec" "sh" "tests/run_dnssec_negative_soa_rrsig_test.sh" "RFC 4035 Negative response SOA covering RRSIG"
register_test "dnssec" "sh" "tests/run_ds_delegation_test.sh" "RFC 4034 DS delegation record referral in NS responses"

# 4. Dynamic Update (RFC 2136)
register_test "update" "sh" "tests/run_dynamic_update_test.sh" "RFC 2136 Prerequisites & Update Section handling"
register_test "update" "sh" "tests/run_update_slave_notauth_test.sh" "RFC 2136 §3.8 Slave rejection with NOTAUTH"
register_test "update" "sh" "tests/run_ttl_harmonization_update_test.sh" "TTL harmonization on dynamic updates"

# 5. EDNS / Cookies / ECS / Multi-QTYPE
register_test "edns" "sh" "tests/run_bind_ecs_subnet_test.sh" "RFC 7871 \$ECS-SUBNET tag split-horizon routing"
register_test "edns" "sh" "tests/run_mqtype_qdcount0_test.sh" "RFC 10029 Multi-QTYPE & RFC 9619 QDCOUNT=0"

# 6. Response Rate Limiting (RRL) & Anti-DoS
register_test "rrl" "sh" "tests/run_rrl_window_test.sh" "RRL sliding window rate limit & SLIP truncated responses"
register_test "rrl" "sh" "tests/run_query_log_rate_limit_test.sh" "Query log ring buffer rate limiting"
register_test "rrl" "sh" "tests/run_glue_truncation_test.sh" "Additional section glue truncation & TC bit"

# 7. Catalog Zones (RFC 9432)
register_test "catalog" "sh" "tests/run_catalog_zone_test.sh" "RFC 9432 Catalog Zone member provisioning"
register_test "catalog" "sh" "tests/run_cve_coo_test.sh" "RFC 9432 Change of Ownership (CoO) migration"

# 8. DNSTAP Telemetry Logging
register_test "dnstap" "sh" "tests/run_dnstap_capture_test.sh" "DNSTAP frame streams capture verification"

# 9. tinydns Format & Location
register_test "tinydns" "sh" "tests/run_tinydns_location_test.sh" "tinydns %location split-horizon resolution"
register_test "tinydns" "sh" "tests/run_tinydns_timestamp_test.sh" "tinydns TTL countdown & TTD expiration"

# 10. Server Core & Resolution
register_test "core" "sh" "tests/run_paren_check_test.sh" "Zone file multi-line parentheses tokenizer"
register_test "core" "sh" "tests/run_ttl_suffix_test.sh" "TTL time unit suffixes (s, m, h, d, w)"
register_test "core" "sh" "tests/run_roundtrip_test.sh" "Zone parser to wire serialization roundtrip"
register_test "core" "sh" "tests/run_karicheck_glue_test.sh" "karicheck in-bailiwick glue record verification"
register_test "core" "sh" "tests/run_karicheck_semantic_lint_test.sh" "karicheck RFC semantic linter checks"
register_test "core" "sh" "tests/run_phase2_core_audit_test.sh" "Phase 2 Core architecture audit test"
register_test "core" "sh" "tests/run_phase2_audit_part2_test.sh" "Phase 2 Security & boundary validation"
register_test "core" "sh" "tests/run_response_section_order_test.sh" "RFC 1035 Response section ordering"
register_test "core" "sh" "tests/run_sibling_additional_test.sh" "Sibling zone glue synthesis in Additional section"
register_test "core" "sh" "tests/run_multi_instance_test.sh" "Multi-instance isolation & SO_REUSEPORT"
register_test "core" "sh" "tests/run_forward_zone_test.sh" "RFC 5452 Forward zone upstream resolution & failover"
register_test "core" "sh" "tests/run_program_zone_test.sh" "Dynamic backend records via program zone plugin"
register_test "core" "sh" "tests/run_karictl_observatory_test.sh" "karictl observatory IPC metrics query"
register_test "core" "sh" "tests/run_karictl_reload_reconfig_test.sh" "karictl reload & dynamic reconfig IPC"
register_test "core" "sh" "tests/run_config_duplicate_rejection_test.sh" "Duplicate view/zone rejection in config parser"
register_test "core" "sh" "tests/run_domain_length_rfc1035_test.sh" "RFC 1035 255-byte domain & 63-byte label limits"
register_test "core" "sh" "tests/run_logging_channel_validation_test.sh" "Syslog & file logging channels configuration"
register_test "core" "sh" "tests/run_mx_srv_glue_test.sh" "MX & SRV target additional glue inclusion"
register_test "core" "sh" "tests/run_notify_source_test.sh" "RFC 1996 notify-source address binding"
register_test "core" "sh" "tests/run_privilege_drop_root_test.sh" "FreeBSD setuid/setgid privilege drop"
register_test "core" "sh" "tests/run_response_cache_test.sh" "Response cache hit/miss functional verification"
register_test "core" "sh" "tests/run_ttl_harmonization_test.sh" "RRset TTL harmonization on zone load"
register_test "core" "sh" "tests/run_ttl_rfc2181_clamp_test.sh" "RFC 2181 31-bit signed TTL clamp"
register_test "core" "sh" "tests/run_zone_oom_partial_load_test.sh" "OOM fail-closed zone loading rollback"

# 11. Regression, Sanitizer & Concurrency Stress
register_test "regression" "sh" "tests/run_sanitizer_smoke_test.sh" "ASan & UBSan runtime memory error smoke test"
register_test "regression" "sh" "tests/run_stress_test.sh" "TSan & ASan concurrency stress test (dnsperf + IXFR)"
register_test "regression" "sh" "tests/run_fuzz_smoke_test.sh" "libFuzzer crash-resistance smoke verification"

# 12. dag Diagnostic Client Suite (Run with -c dag or --include-dag)
register_test "dag" "sh" "tests/run_dag_ci_test.sh" "dag comprehensive CI test suite (Part 1-19 + Part 20-21 parallel sub-suites)"
register_test "dag" "sh" "tests/run_dag_batch_advanced_opts_test.sh" "dag Batch mode (-f) with advanced options"
register_test "dag" "sh" "tests/run_dag_fuzzer_test.sh" "dag fuzzer smoke execution"

# If -l or --list, print tests and exit
if [ "${LIST_ONLY}" -eq 1 ]; then
    printf "${C_BOLD}%-4s %-12s %-6s %-45s %s${C_RESET}\n" "ID" "CATEGORY" "TYPE" "TARGET" "DESCRIPTION"
    printf "%s\n" "-----------------------------------------------------------------------------------------------------"
    _idx=1
    printf "%b" "${REGISTERED_TESTS}" | while IFS='|' read -r _cat _type _cmd _desc; do
        [ -z "${_cat}" ] && continue
        printf "%-4d %-12s %-6s %-45s %s\n" "${_idx}" "${_cat}" "${_type}" "${_cmd}" "${_desc}"
        _idx=$((_idx + 1))
    done
    echo ""
    echo "Total registered tests: ${TEST_COUNT}"
    exit 0
fi

# Quick mode defaults to unit + core
if [ "${QUICK_MODE}" -eq 1 ] && [ -z "${SELECTED_CATEGORIES}" ]; then
    SELECTED_CATEGORIES="unit,core"
fi

# Function to check if a category is selected
is_category_selected() {
    _target_cat="$1"
    if [ "${SKIP_DAG}" -eq 1 ] && [ "${_target_cat}" = "dag" ]; then
        return 1
    fi
    if [ -z "${SELECTED_CATEGORIES}" ] || [ "${SELECTED_CATEGORIES}" = "all" ]; then
        return 0
    fi
    OLD_IFS="$IFS"
    IFS=','
    for _c in ${SELECTED_CATEGORIES}; do
        if [ "${_c}" = "${_target_cat}" ] || [ "${_c}" = "all" ]; then
            IFS="$OLD_IFS"
            return 0
        fi
    done
    IFS="$OLD_IFS"
    return 1
}

# Function to check if name filter matches
is_name_matched() {
    _name="$1"
    if [ -z "${NAME_FILTER}" ]; then
        return 0
    fi
    case "${_name}" in
        *"${NAME_FILTER}"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Clean environment before starting suite
cleanup_stale_processes

# Build binaries if missing
if [ ! -x "./karidns" ] || [ ! -x "./dag" ] || [ ! -x "./karicheck" ] || [ ! -x "./karictl" ]; then
    echo "${C_CYAN}==> Building core binaries (make all)...${C_RESET}"
    make all >/dev/null 2>&1 || {
        echo "${C_RED}ERROR: 'make all' failed to build binaries.${C_RESET}" >&2
        exit 1
    }
fi

echo "${C_BOLD}======================================================================${C_RESET}"
echo "${C_BOLD}             KariDNS Automated Test Suite Runner${C_RESET}"
echo "${C_BOLD}======================================================================${C_RESET}"
[ -n "${SELECTED_CATEGORIES}" ] && echo "  Category Filter : ${C_CYAN}${SELECTED_CATEGORIES}${C_RESET}"
[ -n "${NAME_FILTER}" ]        && echo "  Name Filter     : ${C_CYAN}${NAME_FILTER}${C_RESET}"
[ "${QUICK_MODE}" -eq 1 ]      && echo "  Mode            : ${C_YELLOW}Quick Mode${C_RESET}"
echo ""

TOTAL_RUN=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
START_TIME=$(date +%s 2>/dev/null || perl -e 'print time')
FAILED_TEST_NAMES=""

# Ensure unit test binaries are built if category 'unit' is active
if is_category_selected "unit"; then
    echo "${C_CYAN}==> Ensuring unit test binaries are built...${C_RESET}"
    make test_vulnerability_fixes test_response_cache test_asan_overflow test_tinydns_parser test_conf_include test_hash_table test_cidr >/dev/null 2>&1 || true
fi

SUMMARY_FILE="${LOG_DIR}/summary.tsv"
rm -f "${SUMMARY_FILE}"
touch "${SUMMARY_FILE}"

# Run test cases
printf "%b" "${REGISTERED_TESTS}" | while IFS='|' read -r _cat _type _cmd _desc; do
    [ -z "${_cat}" ] && continue
    
    if ! is_category_selected "${_cat}"; then
        continue
    fi
    
    if ! is_name_matched "${_cmd}"; then
        continue
    fi
    
    TOTAL_RUN=$((TOTAL_RUN + 1))
    _log="${LOG_DIR}/test_${TOTAL_RUN}.log"
    rm -f "${_log}"
    
    cleanup_stale_processes
    
    T_START=$(date +%s 2>/dev/null || perl -e 'print time')
    
    _status="PASS"
    _exit_code=0
    _skip_reason=""
    
    if [ "${_type}" = "bin" ]; then
        if [ ! -x "./${_cmd}" ]; then
            _status="SKIP"
            _skip_reason="binary ./${_cmd} not found"
        else
            if [ "${VERBOSE}" -eq 1 ]; then
                "./${_cmd}" 2>&1 | tee "${_log}"
                _exit_code=$?
            else
                "./${_cmd}" > "${_log}" 2>&1
                _exit_code=$?
            fi
            [ ${_exit_code} -ne 0 ] && _status="FAIL"
        fi
    else
        if [ ! -f "${_cmd}" ]; then
            _status="SKIP"
            _skip_reason="script ${_cmd} not found"
        else
            if [ "${VERBOSE}" -eq 1 ]; then
                sh "${_cmd}" 2>&1 | tee "${_log}"
                _exit_code=$?
            else
                sh "${_cmd}" > "${_log}" 2>&1
                _exit_code=$?
            fi
            [ ${_exit_code} -ne 0 ] && _status="FAIL"
        fi
    fi
    
    T_END=$(date +%s 2>/dev/null || perl -e 'print time')
    T_ELAPSED=$((T_END - T_START))
    
    echo "${_status}|${_cmd}|${_cat}|${T_ELAPSED}|${_exit_code}|${_desc}" >> "${SUMMARY_FILE}"
    
    if [ "${_status}" = "PASS" ]; then
        printf "  [ ${C_GREEN}PASS${C_RESET} ] %-42s (${T_ELAPSED}s) ${C_WHITE}%s${C_RESET}\n" "${_cmd}" "${_desc}"
    elif [ "${_status}" = "SKIP" ]; then
        printf "  [ ${C_YELLOW}SKIP${C_RESET} ] %-42s (${_skip_reason})\n" "${_cmd}"
    else
        printf "  [ ${C_RED}FAIL${C_RESET} ] %-42s (${T_ELAPSED}s) ${C_RED}%s (Exit: ${_exit_code})${C_RESET}\n" "${_cmd}" "${_desc}"
        echo "  ${C_RED}------------------------- [ Error Log Tail: ${_cmd} ] -------------------------${C_RESET}"
        tail -n 25 "${_log}" | sed 's/^/    /'
        echo "  ${C_RED}----------------------------------------------------------------------------------${C_RESET}"
        
        if [ "${STOP_ON_FAILURE}" -eq 1 ]; then
            echo ""
            echo "${C_BG_RED} ABORT ${C_RESET} Test failure encountered with --stop-on-failure. Stopping."
            cleanup_stale_processes
            exit 1
        fi
    fi
done
PIPELINE_STATUS=$?

cleanup_stale_processes

if [ ! -f "${SUMMARY_FILE}" ] || [ ! -s "${SUMMARY_FILE}" ]; then
    echo "${C_YELLOW}No matching tests found for execution.${C_RESET}"
    exit 0
fi

TOTAL_COUNT=0
PASSED_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

while IFS='|' read -r _s _c _cat _t _code _d; do
    [ -z "${_s}" ] && continue
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    case "${_s}" in
        PASS) PASSED_COUNT=$((PASSED_COUNT + 1)) ;;
        FAIL) FAILED_COUNT=$((FAILED_COUNT + 1)) ;;
        SKIP) SKIPPED_COUNT=$((SKIPPED_COUNT + 1)) ;;
    esac
done < "${SUMMARY_FILE}"

END_TIME=$(date +%s 2>/dev/null || perl -e 'print time')
TOTAL_DURATION=$((END_TIME - START_TIME))

echo ""
echo "${C_BOLD}======================================================================${C_RESET}"
echo "${C_BOLD}                     Test Suite Summary Report${C_RESET}"
echo "${C_BOLD}======================================================================${C_RESET}"
printf "  Total Tests Executed : ${C_BOLD}%d${C_RESET}\n" "${TOTAL_COUNT}"
printf "  Passed               : ${C_GREEN}%d${C_RESET}\n" "${PASSED_COUNT}"
if [ "${FAILED_COUNT}" -gt 0 ]; then
    printf "  Failed               : ${C_RED}%d${C_RESET}\n" "${FAILED_COUNT}"
else
    printf "  Failed               : %d\n" "${FAILED_COUNT}"
fi
if [ "${SKIPPED_COUNT}" -gt 0 ]; then
    printf "  Skipped              : ${C_YELLOW}%d${C_RESET}\n" "${SKIPPED_COUNT}"
fi
printf "  Total Execution Time : %ds\n" "${TOTAL_DURATION}"
echo "${C_BOLD}======================================================================${C_RESET}"

if [ "${FAILED_COUNT}" -gt 0 ]; then
    echo ""
    echo "${C_RED}Failed Tests:${C_RESET}"
    while IFS='|' read -r _s _c _cat _t _code _d; do
        if [ "${_s}" = "FAIL" ]; then
            printf "  - ${C_RED}%-45s${C_RESET} [Category: %s, Exit Code: %s]\n" "${_c}" "${_cat}" "${_code}"
        fi
    done < "${SUMMARY_FILE}"
    echo ""
    echo "${C_BG_RED} FAILURE ${C_RESET} One or more tests failed. Check logs in ${LOG_DIR}."
    exit 1
else
    echo ""
    echo "${C_BG_GREEN} SUCCESS ${C_RESET} All ${TOTAL_COUNT} test cases passed successfully!"
    exit 0
fi

# tests/fuzz/targets.sh - the one list of the libFuzzer harnesses (sourced by sh scripts; no shebang, not run on its own).
#
# Sourced by tests/run_fuzz_smoke_test.sh, tests/run_sanitizer_smoke_test.sh and tests/run_fuzz_nightly.sh
# (.github/workflows/fuzzing.yml).  A harness tests/fuzz/fuzz_<name>.c that is in neither list fails
# fuzz_targets_check, so a new harness cannot be left out of the nightly run again (in the nightly run of
# 2026-11, 17 of 41 harnesses never started and 3 were in no smoke list).
#
# The binary is tests/fuzz/<name>; "make fuzz_karidns" builds the first list, "make fuzz_dag_all" the second.

FUZZ_KARIDNS_TARGETS="fuzz_dns_wire fuzz_dns_server_core fuzz_zone_parser fuzz_zone_image fuzz_zone_image_validate
fuzz_conf_parser fuzz_tsig_sign fuzz_tsig_verify fuzz_query_engine fuzz_xfr_packet fuzz_dynamic_update
fuzz_db_stream fuzz_db_image_frames fuzz_pdns_content fuzz_pdns_metadata fuzz_db_checkline fuzz_json_escape
fuzz_zone_text fuzz_zone_changes fuzz_db_logline fuzz_plugin_msg fuzz_nsec3_rebuild fuzz_alias_response
fuzz_forward_response fuzz_xfr_state fuzz_ipc_frame"

FUZZ_DAG_TARGETS="fuzz_dag_response fuzz_dag_hash fuzz_dag_iter_classify fuzz_dag_chunked_http
fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file
fuzz_dag_replay_pcap_reader fuzz_dag_replay_diff fuzz_dag_tcp_reassembly fuzz_tapstat
fuzz_dnsqps_resp fuzz_dnsqps_args fuzz_dnsqps_msg"

FUZZ_ALL_TARGETS="$FUZZ_KARIDNS_TARGETS $FUZZ_DAG_TARGETS"

# Every tests/fuzz/fuzz_*.c is in a list and every listed name has its source.  Run from the top of the tree.
# Prints each mismatch; returns 1 if there is one.
fuzz_targets_check() {
    _ftc_rc=0
    for _ftc_src in tests/fuzz/fuzz_*.c; do
        _ftc_t=${_ftc_src#tests/fuzz/}
        _ftc_t=${_ftc_t%.c}
        case " $(echo $FUZZ_ALL_TARGETS) " in
            *" $_ftc_t "*) ;;
            *) echo "fuzz target $_ftc_t ($_ftc_src) is not in tests/fuzz/targets.sh"; _ftc_rc=1 ;;
        esac
    done
    for _ftc_t in $FUZZ_ALL_TARGETS; do
        [ -f "tests/fuzz/$_ftc_t.c" ] || { echo "tests/fuzz/targets.sh lists $_ftc_t, but tests/fuzz/$_ftc_t.c does not exist"; _ftc_rc=1; }
    done
    return $_ftc_rc
}

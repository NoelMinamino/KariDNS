# KariDNS Test Suite Matrix & RFC Traceability Document

This document provides a comprehensive traceability matrix mapping every test in the KariDNS test suite (164 test targets registered in `tests/run_all_suite.sh` — C unit test binaries, integration shell scripts, sanitizer tests and fuzzing harnesses — plus the targets listed in §3.13) to its corresponding **IETF RFC / Technical Specification**, target **KariDNS Component**, and **Test Classification** (Positive, Negative, Boundary, Concurrency/RCU, Memory/ASan, Fuzzing).

It directly cross-references the implementation status documented in [`KariDNS_RFC_GUIDELINE.md`](../KariDNS_RFC_GUIDELINE.md).

---

## 1. Test Suite Architecture & Organization

The KariDNS automated test suite is managed via the unified runner script [`tests/run_all_suite.sh`](run_all_suite.sh) and the project [`Makefile`](../Makefile).

[`tests/run_dag_ci_test.sh`](run_dag_ci_test.sh) is the umbrella runner for the dag CLI checks (Part 1-19 plus the Part 20-21 parallel sub-suites); the other dag test scripts are registered individually in `run_all_suite.sh`.

### 1.1 Test Category Distribution in `run_all_suite.sh`

| Category Code | Category Name | Target Domain | Registered Tests | Primary Execution Method |
|:---|:---|:---|:---:|:---|
| `unit` | **Unit Tests & Fault Injection** | C unit tests (also built with ASan/UBSan by `make unit-tests-asan`), fail-Nth FI sweeps and coverage sweeps | 39 | Native binary execution |
| `xfr` | **Zone Transfer** | RFC 5936 AXFR, RFC 1995 IXFR, Extended AXFR, Capsicum, RFC 7314 EXPIRE | 7 | Shell script + multi-instance KariDNS |
| `dnssec` | **DNSSEC & Digest** | RFC 4034/4035 DNSSEC serving, RFC 8976 ZONEMD, SIG(0) | 3 | Shell script + `karicheck` / `dag` |
| `update` | **Dynamic Update** | RFC 2136 DNS UPDATE prerequisites & updates | 3 | Shell script + `dag` UPDATE |
| `edns` | **EDNS & Extensions** | RFC 7871 ECS split-horizon, RFC 10029 Multi-QTYPE, RFC 9619 | 2 | Shell script + `dag` |
| `rrl` | **Anti-DoS & RRL** | Response Rate Limiting (RRL), SLIP truncation, log throttling | 3 | Shell script + high-rate UDP client |
| `catalog` | **Catalog Zones** | RFC 9432 DNS Catalog Zones, Change of Ownership (CoO) | 2 | Shell script + multi-zone provisioning |
| `dnstap` | **dnstap Logging** | Frame Streams / Protobuf logging | 1 | Shell script + receiver |
| `tinydns` | **tinydns Format** | djbdns data format, %location split-horizon, TAI64 timestamps | 2 | Shell script + `karidns` |
| `core` | **Server Core Engine** | RFC 1034/1035 resolution, forward & program zones, glue, RCU reload, lifecycle, adversarial inputs, `karicheck` / `karictl` | 38 | Shell script + `karidns` / `karictl` / `karicheck` |
| `dag` | **Diagnostic Tool** | `run_dag_ci_test.sh` (Part 1-19 + Part 20-21 parallel sub-suites) and the individual dag test scripts | 58 | Shell scripts (included by default; skip with `--no-dag`) |
| `regression` | **Regression & Fuzz** | ASan/UBSan smoke, concurrency stress, libFuzzer harnesses, coverage tooling, BIND differential | 6 | Shell script + libFuzzer / ASan binaries |
| **Total** | | | **164** | *(106 without the `dag` category)* |

---

## 2. RFC Cross-Reference Index

This table maps RFC standards recognized in [`KariDNS_RFC_GUIDELINE.md`](../KariDNS_RFC_GUIDELINE.md) directly to the specific automated test cases that validate their behavior.

| RFC / Standard | Specification Title | KariDNS Implementation Evidence | Validating Test Scripts / Binaries |
|:---|:---|:---|:---|
| **RFC 1034** | Domain Names - Concepts and Facilities | `dns_query_engine.c`, `dns_server_core.c` | [`tests/test_response_cache.c`](test_response_cache.c), [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c), [`tests/run_sibling_additional_test.sh`](run_sibling_additional_test.sh), [`tests/run_zone_type_secondary_test.sh`](run_zone_type_secondary_test.sh) |
| **RFC 1035** | Domain Names - Implementation and Specification | `dns_wire.c`, `dns_zone_parser.c` | [`tests/test_asan_overflow.c`](test_asan_overflow.c), [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c), [`tests/run_domain_length_rfc1035_test.sh`](run_domain_length_rfc1035_test.sh), [`tests/run_response_section_order_test.sh`](run_response_section_order_test.sh), [`tests/run_roundtrip_test.sh`](run_roundtrip_test.sh), [`tests/run_paren_check_test.sh`](run_paren_check_test.sh), [`tests/run_malformed_detection_default_test.sh`](run_malformed_detection_default_test.sh) |
| **RFC 1912** | Common DNS Operational & Configuration Errors | `tools/karicheck.c` | [`tests/run_karicheck_semantic_lint_test.sh`](run_karicheck_semantic_lint_test.sh) |
| **RFC 1982** | Serial Number Arithmetic | `dns_utils.c`, `dns_axfr_ixfr.c`, `dns_dynamic_update.c` | [`tests/test_dynamic_update_engine.c`](test_dynamic_update_engine.c), [`tests/test_axfr_ixfr_engine.c`](test_axfr_ixfr_engine.c), [`tests/run_ixfr_roundtrip_test.sh`](run_ixfr_roundtrip_test.sh), [`tests/run_extended_axfr_test.sh`](run_extended_axfr_test.sh) |
| **RFC 1995** | Incremental Zone Transfer (IXFR) | `dns_axfr_ixfr.c`, `dns_server_core.c` | [`tests/test_axfr_ixfr_engine.c`](test_axfr_ixfr_engine.c), [`tests/run_ixfr_roundtrip_test.sh`](run_ixfr_roundtrip_test.sh), [`tests/run_udp_ixfr_test.sh`](run_udp_ixfr_test.sh), [`tests/run_dag_ixfr_uptodate_test.sh`](run_dag_ixfr_uptodate_test.sh) |
| **RFC 1996** | Prompt Notification of Zone Changes (NOTIFY) | `dns_query_engine.c`, `dns_dynamic_update.c`, `dns_tsig_acl.c` | [`tests/test_dynamic_update_engine.c`](test_dynamic_update_engine.c), [`tests/run_notify_source_test.sh`](run_notify_source_test.sh), [`tests/run_zone_type_secondary_test.sh`](run_zone_type_secondary_test.sh) |
| **RFC 2136** | Dynamic Updates in the DNS (DNS UPDATE) | `dns_dynamic_update.c`, `dns_epoch_rcu.c` | [`tests/test_dynamic_update_engine.c`](test_dynamic_update_engine.c), [`tests/test_vulnerability_fixes.c`](test_vulnerability_fixes.c), [`tests/run_dynamic_update_test.sh`](run_dynamic_update_test.sh), [`tests/run_update_slave_notauth_test.sh`](run_update_slave_notauth_test.sh), [`tests/run_dag_update_del_no_type_test.sh`](run_dag_update_del_no_type_test.sh), [`tests/run_dag_update_del_exact_ttl_notype_crash_test.sh`](run_dag_update_del_exact_ttl_notype_crash_test.sh) |
| **RFC 2181** | Clarifications to the DNS Specification | `dns_wire.c`, `dns_query_engine.c` | [`tests/run_ttl_rfc2181_clamp_test.sh`](run_ttl_rfc2181_clamp_test.sh), [`tests/run_ttl_harmonization_test.sh`](run_ttl_harmonization_test.sh), [`tests/run_ttl_harmonization_update_test.sh`](run_ttl_harmonization_update_test.sh) |
| **RFC 2782** | Location of Services (SRV) | `dns_wire.c`, `dns_query_engine.c` | [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c), [`tests/run_mx_srv_glue_test.sh`](run_mx_srv_glue_test.sh) |
| **RFC 2931 / 3007** | DNS Request and Transaction Signatures (SIG(0)) | `tools/dag_tsig_client.c`, `dns_wire.c` | [`tests/run_dag_sig0_update_test.sh`](run_dag_sig0_update_test.sh) |
| **RFC 3123** | Lists of Address Prefixes (APL RR) | `dns_wire.c`, `tools/dag_output_yaml.c` | [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c), [`tests/run_dag_apl_afdlength_overflow_test.sh`](run_dag_apl_afdlength_overflow_test.sh) |
| **RFC 3597** | Handling of Unknown DNS RR Types (`TYPE<n>`, `\#`) | `dns_utils.c`, `dns_wire.c` | [`tests/test_asan_overflow.c`](test_asan_overflow.c), [`tests/run_dag_ci_test.sh`](run_dag_ci_test.sh) |
| **RFC 4034 / 4035** | DNSSEC Protocol & Resource Records (Static Serving) | `dns_query_engine.c`, `dns_wire.c` | [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c), [`tests/run_dnssec_negative_soa_rrsig_test.sh`](run_dnssec_negative_soa_rrsig_test.sh), [`tests/run_ds_delegation_test.sh`](run_ds_delegation_test.sh), [`tests/run_dag_yaml_rrsig_decode_test.sh`](run_dag_yaml_rrsig_decode_test.sh) |
| **RFC 5452** | Measures for Making DNS Resilient against Forged Answers | `dns_server_core.c`, `tools/dag_transport.c` | [`tests/run_dag_udp_id_mismatch_discard_test.sh`](run_dag_udp_id_mismatch_discard_test.sh), [`tests/run_dag_udp_spoofing_source_test.sh`](run_dag_udp_spoofing_source_test.sh), [`tests/run_forward_zone_test.sh`](run_forward_zone_test.sh) |
| **RFC 5936** | DNS Zone Transfer Protocol (AXFR) | `dns_axfr_ixfr.c`, `dns_priv_sandbox.c` | [`tests/test_axfr_ixfr_engine.c`](test_axfr_ixfr_engine.c), [`tests/run_capsicum_axfr_test.sh`](run_capsicum_axfr_test.sh), [`tests/run_extended_axfr_test.sh`](run_extended_axfr_test.sh), [`tests/run_axfr_multikey_tsig_test.sh`](run_axfr_multikey_tsig_test.sh), [`tests/run_dag_doh_dot_axfr_test.sh`](run_dag_doh_dot_axfr_test.sh) |
| **RFC 6672** | DNAME Redirection in the DNS | `dns_query_engine.c`, `dns_wire.c` | [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c) |
| **RFC 6891** | Extension Mechanisms for DNS (EDNS(0)) | `dns_wire.c`, `dns_edns_ecs.c`, `tools/dag_edns_client.c` | [`tests/test_edns_ecs_engine.c`](test_edns_ecs_engine.c), [`tests/run_dag_yaml_edns_options_test.sh`](run_dag_yaml_edns_options_test.sh), [`tests/run_dag_ci_test.sh`](run_dag_ci_test.sh) |
| **RFC 7050** | Discovery of IPv6 Prefix (DNS64) | `tools/dag.c`, `tools/dag_output_yaml.c` | [`tests/run_dag_dns64prefix_test.sh`](run_dag_dns64prefix_test.sh), [`tests/run_dag_dns64prefix_short_yaml_test.sh`](run_dag_dns64prefix_short_yaml_test.sh) |
| **RFC 7314** | Extension Mechanisms for DNS (EDNS) EXPIRE Option | `dns_wire.c`, `dns_query_engine.c`, `dns_axfr_ixfr.c` | [`tests/test_axfr_ixfr_engine.c`](test_axfr_ixfr_engine.c), [`tests/run_edns_expire_test.sh`](run_edns_expire_test.sh) |
| **RFC 7766 / 9210** | DNS Transport over TCP (Connection Reuse / Keepopen) | `dns_server_core.c`, `tools/dag_transport.c` | [`tests/run_dag_keepopen_keepalive_test.sh`](run_dag_keepopen_keepalive_test.sh), [`tests/run_dag_keepopen_partial_read_test.sh`](run_dag_keepopen_partial_read_test.sh), [`tests/run_dag_keepopen_tls_partial_read_test.sh`](run_dag_keepopen_tls_partial_read_test.sh) |
| **RFC 7858** | DNS over TLS (DoT - Client `dag`) | `tools/dag_transport.c` | [`tests/run_dag_doh_dot_axfr_test.sh`](run_dag_doh_dot_axfr_test.sh), [`tests/run_dag_keepopen_tls_partial_read_test.sh`](run_dag_keepopen_tls_partial_read_test.sh) |
| **RFC 7871** | Client Subnet in DNS Queries (ECS) | `dns_edns_ecs.c`, `dns_wire.c` | [`tests/test_edns_ecs_engine.c`](test_edns_ecs_engine.c), [`tests/run_bind_ecs_subnet_test.sh`](run_bind_ecs_subnet_test.sh), [`tests/run_dag_yaml_edns_options_test.sh`](run_dag_yaml_edns_options_test.sh) |
| **RFC 7873 / 9018** | DNS Cookies & Interoperable Server Cookies | `dns_wire.c`, `dns_edns_ecs.c`, `dns_query_engine.c`, `dns_config_parser.c` | [`tests/test_rfc_vectors.c`](test_rfc_vectors.c), [`tests/test_query_engine_expanded.c`](test_query_engine_expanded.c), [`tests/test_edns_ecs_engine.c`](test_edns_ecs_engine.c), [`tests/run_dag_badcookie_transport_test.sh`](run_dag_badcookie_transport_test.sh), [`tests/run_dag_cookie_mismatch_discard_test.sh`](run_dag_cookie_mismatch_discard_test.sh), [`tests/run_dag_yaml_cookie_status_test.sh`](run_dag_yaml_cookie_status_test.sh) |
| **RFC 8482** | Minimal ANY Responses | `dns_query_engine.c` | [`tests/test_vulnerability_fixes.c`](test_vulnerability_fixes.c), [`tests/run_dag_ci_test.sh`](run_dag_ci_test.sh) |
| **RFC 8484** | DNS over HTTPS (DoH - Client `dag`) | `tools/dag_transport.c` | [`tests/run_dag_doh_dot_axfr_test.sh`](run_dag_doh_dot_axfr_test.sh), [`tests/run_dag_doh_cache_cleanup_test.sh`](run_dag_doh_cache_cleanup_test.sh), [`tests/run_dag_audit_improvements_test.sh`](run_dag_audit_improvements_test.sh) |
| **RFC 8624** | DNSSEC Algorithm Implementation Requirements | `tools/karicheck.c` | [`tests/run_karicheck_semantic_lint_test.sh`](run_karicheck_semantic_lint_test.sh) |
| **RFC 8914** | Extended DNS Errors (EDE) | `dns_wire.c`, `dns_edns_ecs.c`, `tools/dag_edns_client.c` | [`tests/test_edns_ecs_engine.c`](test_edns_ecs_engine.c), [`tests/run_dag_ede_truncation_regression_test.sh`](run_dag_ede_truncation_regression_test.sh), [`tests/run_dag_yaml_ede_escaping_test.sh`](run_dag_yaml_ede_escaping_test.sh) |
| **RFC 8945** | Secret Key Transaction Authentication (TSIG) | `dns_tsig_acl.c`, `dns_wire.c` | [`tests/test_vulnerability_fixes.c`](test_vulnerability_fixes.c), [`tests/run_axfr_multikey_tsig_test.sh`](run_axfr_multikey_tsig_test.sh), [`tests/run_dag_axfr_tsig_unsigned_intermediate_test.sh`](run_dag_axfr_tsig_unsigned_intermediate_test.sh) |
| **RFC 8976** | Message Digest for DNS Zones (ZONEMD) | `tools/karicheck.c`, `dns_wire.c` | [`tests/run_zonemd_val_test.sh`](run_zonemd_val_test.sh) |
| **RFC 9276** | Guidance for NSEC3 Parameter Settings | `tools/karicheck.c` | [`tests/run_karicheck_semantic_lint_test.sh`](run_karicheck_semantic_lint_test.sh) |
| **RFC 9432** | DNS Catalog Zones | `dns_catalog_zone.c`, `dns_snapshot_rcu.c` | [`tests/run_catalog_zone_test.sh`](run_catalog_zone_test.sh), [`tests/run_cve_coo_test.sh`](run_cve_coo_test.sh) |
| **RFC 9471** | DNS Glue Requirements in Referrals | `dns_query_engine.c`, `tools/karicheck.c` | [`tests/run_karicheck_glue_test.sh`](run_karicheck_glue_test.sh), [`tests/run_sibling_additional_test.sh`](run_sibling_additional_test.sh), [`tests/run_mx_srv_glue_test.sh`](run_mx_srv_glue_test.sh) |
| **RFC 9619** | QDCOUNT Is (Usually) One | `dns_query_engine.c` | [`tests/run_mqtype_qdcount0_test.sh`](run_mqtype_qdcount0_test.sh), [`tests/test_query_engine_protocol.c`](test_query_engine_protocol.c) |
| **RFC 9824** | Compact Denial of Existence in DNSSEC (NXNAME) | `tools/karicheck.c`, `dns_utils.c` | [`tests/run_karicheck_semantic_lint_test.sh`](run_karicheck_semantic_lint_test.sh) |
| **RFC 10029** | DNS Multiple QTYPEs (MQTYPE) | `dns_wire.c`, `dns_query_engine.c` | [`tests/run_mqtype_qdcount0_test.sh`](run_mqtype_qdcount0_test.sh), [`tests/run_dag_ci_test.sh`](run_dag_ci_test.sh) |
| **RRL Draft** | DNS Response Rate Limiting | `dns_rrl.c`, `dns_server_core.c` | [`tests/test_rrl_engine.c`](test_rrl_engine.c), [`tests/run_rrl_window_test.sh`](run_rrl_window_test.sh), [`tests/bench_rrl.c`](bench_rrl.c) |
| **DNSTAP** | DNS Telemetry & Frame Streams | `dns_dnstap.c`, `dns_wire.c` | [`tests/test_dnstap_engine.c`](test_dnstap_engine.c), [`tests/run_dnstap_capture_test.sh`](run_dnstap_capture_test.sh) |
| **FreeBSD Capsicum** | Capability Mode Sandboxing | `dns_priv_sandbox.c` | [`tests/run_capsicum_axfr_test.sh`](run_capsicum_axfr_test.sh), [`tests/test_vulnerability_fixes.c`](test_vulnerability_fixes.c) |
| **Epoch RCU** | Lock-free publish / grace period (R-25) | `dns_epoch_rcu.c`, `dns_snapshot_rcu.c`, `dns_server_core.c`, `dns_dynamic_update.c`, `dns_axfr_ixfr.c` | [`tests/test_epoch_rcu.c`](test_epoch_rcu.c), [`tests/run_rcu_tsan_test.sh`](run_rcu_tsan_test.sh), [`tests/test_vulnerability_fixes.c`](test_vulnerability_fixes.c) |

---

## 3. Exhaustive Test Inventory (164 Registered Tests)

The complete inventory of all test targets registered in `tests/run_all_suite.sh` (`sh tests/run_all_suite.sh --list`), grouped by their registered category in registration order. `bin` targets are C unit test binaries built by the Makefile; the others are shell scripts.

### 3.1 Unit Tests (C Binaries) - Category: `unit`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 1 | [`test_vulnerability_fixes`](test_vulnerability_fixes.c) | `dns_query_engine.c`, `dns_snapshot_rcu.c`, `dns_epoch_rcu.c`, `dns_wire.c`, `dns_dynamic_update.c`, `dns_axfr_ixfr.c` | RFC 2136 §3.2.5, RFC 8482, RFC 8945, Capsicum | **Positive / Negative / Concurrency** | Validates NOTZONE rejection on out-of-zone updates, minimal ANY in DNSSEC zones, TSIG ID mismatch defenses, Capsicum capability rights, and multithreaded Epoch RCU lifecycle safety. |
| 2 | [`test_query_engine_expanded`](test_query_engine_expanded.c) | `dns_query_engine.c`, `dns_wire.c`, `dns_zone_parser.c` | RFC 1034, RFC 1035, RFC 6672, RFC 4034/4035, RFC 10029 | **Positive / Negative** | Validates all supported DNS RR types, wildcard expansions, DNAME synthesis, ANY queries, negative responses, RFC 10029 MQTYPE truncation & QDCOUNT=0 FORMERR handling, SERVFAIL RCODE clearing, response section ordering, and fast question wire parsing. RFC 4592 §2.2.1 wildcard golden responses (owner/RDATA/AA/section checks), RFC 5155 App. A/B.1 NSEC3 hash vectors, and RFC 9018 cookie handling in the engine (BADCOOKIE, 30-min refresh, TCP exemption, secret rollover). |
| 3 | [`test_coverage_sweep`](test_coverage_sweep.c) | `dns_query_engine.c`, `dns_wire.c`, `dns_zone_parser.c`, `dns_config_parser.c`, `dns_catalog_zone.c`, `dns_axfr_ixfr.c`, `dns_dynamic_update.c`, `dns_rrl.c`, `dns_edns_ecs.c`, `dns_dnstap.c` | RFC 1035, RFC 2136, RFC 5936, RFC 6891, RFC 8945, RFC 9432 | **Coverage sweep / Mutation** | Systematic branch-coverage sweeps of the server engine: query matrix, truncation and mutation, wire + TSIG + EDNS, zone and config parsers, catalog zones, XFR, UPDATE, RRL, ECS and dnstap. |
| 4 | [`test_coverage_sweep_dag`](test_coverage_sweep_dag.c) | `tools/dag*.c` | dig option syntax, RFC 7050, RFC 9460 | **Coverage sweep** | Every dag command-line option token (bare, `no` form, `=value` with valid, empty, out-of-range and garbage values) through `parse_query_arg_token()`, the `print_response` display-option matrix, and DNS64/SVCB corner cases. |
| 5 | [`test_coverage_sweep_net`](test_coverage_sweep_net.c) | `tools/dag_transport.c`, `tools/dag_trace.c`, `tools/dag_axfr_client.c`, `tools/dag_tsig_client.c`, `tools/dag_replay.c` | RFC 1035, RFC 5936, RFC 7858, RFC 8484, RFC 2136, RFC 2931 | **Coverage sweep / Network** | End-to-end sweeps of dag network paths against an in-process fake server (UDP, TCP, DoT, DoH, plain-HTTP DoH with a self-signed certificate): trace/nssearch, AXFR/IXFR, UPDATE, SIG(0) keys, `--replay` of PCAP and dnstap input. `--replay` over DoT and DoH (`--server1-transport tls|doh`) compared with TCP (exit 0), a failed TLS handshake (exit 1) and an unknown transport (exit 1). |
| 6 | [`test_coverage_sweep_tools`](test_coverage_sweep_tools.c) | `tools/karicheck.c`, `tools/karictl.c` | RFC 1912, RFC 8624, RFC 8976, RFC 9276 | **Coverage sweep** | Every karicheck lint rule triggered by a BIND or tinydns-data zone or a config (real `main()` in a forked child), and the karictl CHALLENGE/AUTH control-socket protocol against a fake control socket. karictl uses the `algorithm` of karictl.conf (quoted or bare HMAC-SHA512 verified by the fake server, wrong algorithm denied, unsupported name exits 2). |
| 7 | [`test_dnstap_engine`](test_dnstap_engine.c) | `dns_dnstap.c`, `dns_wire.c` | DNSTAP Protobuf Specification | **Positive / Negative / Concurrency** | Validates Protobuf varint, fixed32, and bytes field encoders, DNSTAP AUTH_QUERY and AUTH_RESPONSE payload packing, Frame Streams handshake protocol, wire buffer truncation tracking, and SPSC/MPSC event ring buffers. Also: the message type mask (`dnstap_set_message_types`) filters AUTH_QUERY / AUTH_RESPONSE events. |
| 8 | [`test_edns_ecs_engine`](test_edns_ecs_engine.c) | `dns_edns_ecs.c`, `dns_wire.c`, `dns_cidr.c` | RFC 7871, RFC 7873/9018, RFC 8914, tinydns %loc | **Positive / Negative** | Validates SipHash-2-4 Server Cookie generation (structure, determinism, address binding), Extended DNS Error (EDE) packing & statistics, $ECS-SUBNET tag definition binary serialization/unserialization, and IPv4/IPv6 Longest Prefix Match routing. Also `is_ecs_trusted_resolver()` source precedence (zone data > zone config > server config, parsed vs textual ACL, fail-closed when unset, first-match `!` negation, IPv6). Also: Extended AXFR v2 TYPE 65405 unpacking (bit length + 4-octet network, v1 layout rejected) and bit-granular longest-prefix tinydns location matching. |
| 9 | [`test_rfc_vectors`](test_rfc_vectors.c) | `dns_edns_ecs.c`, `dns_siphash.h`, `dns_wire.c`, `dns_config_parser.c` | RFC 9018 (App. A.1–A.4, §4.2–4.4, §5), SipHash-2-4, RFC 4034 §5.4 | **Positive / Negative / Boundary (published vectors)** | Golden-vector conformance: SipHash-2-4 reference outputs; RFC 9018 Appendix A Server Cookies (incl. Reserved-bytes hashing, 30-min refresh, secret rollover); RFC 1982 timestamp window across the 2106 wrap; exact 16-byte length; single-bit-flip rejection; `cookie-secret` / `cookie-algorithm` parsing errors; RFC 4034 §5.4 DNSKEY key tag (60485); RFC 8945 TSIG sign/verify for every HMAC algorithm (MAC sizes per §6) after `tsig_prewarm_crypto()`. Expected values come from the RFCs or an independent implementation, never from KariDNS output. |
| 10 | [`test_dynamic_update_engine`](test_dynamic_update_engine.c) | `dns_dynamic_update.c`, `dns_wire.c`, `dns_snapshot_rcu.c`, `dns_query_engine.c` | RFC 2136, RFC 1982, RFC 1996 | **Positive / Negative** | Validates SOA serial number arithmetic bumping, wrap-around handling, RFC 1996 NOTIFY message wire construction, destination deduplication, update section Add/Delete processing, RFC 2136 §3.4.2.4 apex NS deletion protection via Class NONE, and multiple TSIG keys in allow-update authorization. |
| 11 | [`test_axfr_ixfr_engine`](test_axfr_ixfr_engine.c) | `dns_axfr_ixfr.c`, `dns_wire.c`, `dns_snapshot_rcu.c` | RFC 1995, RFC 5936, Option 65153 | **Positive / Negative** | Validates IXFR difference computation between zone arena snapshots, transaction history ring rotation and memory lifecycle, XFR wire packet parsing, and EDNS Option 65153 (Extended AXFR) hash negotiation. |
| 12 | [`test_rrl_engine`](test_rrl_engine.c) | `dns_rrl.c`, `dns_config_parser.c` | Response Rate Limiting (RRL) | **Positive / Negative / Anti-DoS** | Validates SipHash-2-4 hash calculation, response classification (NOERROR, NODATA, NXDOMAIN, ERROR), token bucket leak rates, IPv4 /24 and IPv6 /56 subnet aggregation, and SLIP (TC=1) truncation. |
| 13 | [`test_catalog_zone_engine`](test_catalog_zone_engine.c) | `dns_catalog_zone.c`, `dns_config_parser.c` | RFC 9432 | **Positive / Negative** | Validates RFC 9432 catalog zone membership processing, member hash computation, broken catalog rejection (duplicate PTRs, multiple unique-Ns to same domain), static config collisions, and bookkeeping cleanup. |
| 14 | [`test_snapshot_sandbox_engine`](test_snapshot_sandbox_engine.c) | `dns_priv_sandbox.c`, `dns_snapshot_rcu.c` | Capsicum, RCU | **Positive / Negative / Security** | Validates directory file descriptor caching, Capsicum capability mode rights limitation, ENOTCAPABLE rejection on uncached paths, snapshot retain/release, arena deep cloning, and suffix hash lookup. |
| 15 | [`test_dag_tools`](test_dag_tools.c) | `tools/dag_tcp_reassembly.c`, `tools/dag_tsig_client.c` | RFC 7766, RFC 8945 | **Positive / Negative** | Validates in-order and out-of-order TCP segment reassembly, missing gap draining, stream LRU eviction, BIND TSIG keyfile parsing, and algorithm inference. |
| 16 | [`test_asan_overflow`](test_asan_overflow.c) | `dns_wire.c`, `dns_zone_parser.c`, `dns_tinydns_parser.c`, `dns_cidr.c`, `dns_tsig_acl.c` | RFC 1035, RFC 3597 | **Negative / Memory (ASan)** | Boundary overflow defense on corrupt DNS packets, invalid CLASS tokens, non-numeric TTL overflows, and RFC 3597 unknown RDATA syntax under AddressSanitizer. |
| 17 | [`test_tinydns_parser`](test_tinydns_parser.c) | `dns_tinydns_parser.c`, `dns_zone_parser.c`, `dns_wire.c` | tinydns data format | **Positive / Negative** | Parsing djbdns data format record leading characters (`+`, `@`, `.`, `&`, `=`, `^`, `'`, `:`, `%`), TTL overrides, and syntax error recovery. Also: `%lo:prefix/n` CIDR prefix lengths (masking, missing octets, `/0`) and rejection of invalid `/n`. |
| 18 | [`test_cidr`](test_cidr.c) | `dns_cidr.c`, `dns_tsig_acl.c` | RFC 4632, RFC 4291 | **Positive / Boundary** | Evaluates IPv4 and IPv6 bitmask calculations, prefix containment logic, and binary ACL matching rules. |
| 19 | [`test_conf_include`](test_conf_include.c) | `dns_config_parser.c` | BIND 9 config format | **Positive / Negative** | Nested `$INCLUDE` configuration parsing, detection of circular file dependencies, and token syntax error isolation. |
| 20 | [`test_config_directives`](test_config_directives.c) | `dns_config_parser.c` | BIND 9 config format, README (KariDNS extensions) | **Positive / Negative / Boundary** | Table-driven directive coverage: defaults; every boolean option (`yes`/`true`/`no`/`false`); numeric options with boundary and malformed values (`query-log-buffer-size` power-of-two range, `max-mqtypes` clamp, `udp-*buf-size` K/M/G suffixes and `INT_MAX` clamp, rejected negative/garbage values); `additional-from-auth` at options and zone level; missing-value / missing-`;` rejection for each options directive; `ecs-tags` / `location-tags` / `ecs-trusted-resolvers` (both scopes, malformed blocks); `dnstap{}` (aliases, defaults, repeated properties); zone `type` normalisation, `file-format`, `catalog-zone`, `masters` ports, `program-*` + `program-user` inheritance, `forwarders`, per-zone `rate-limit`; ACL lists incl. `!`, negated blocks and double negation; `key{}` (all HMAC algorithms, independently decoded secret, too-long/empty secret, duplicates) and `control-channel{}`; `logging{}` size suffixes / categories / undefined-channel rejection; top-level zone-vs-view mixing and undefined `tsig-key` references. Every rejection case is malformed input; expectations are derived from the directive semantics, not from parser output. Also: dnstap message types (both logged when neither `log-queries` nor `log-responses` is given, only the given ones otherwise) and rejection of `key` entries in `match-clients`. |
| 21 | [`test_wire_helpers`](test_wire_helpers.c) | `dns_wire.c`, `dns_utils.c` | RFC 1035 §4.1.4 / §2.3.4, RFC 3597 §5, RFC 4343 §2.1, RFC 8945 §5.1 | **Positive / Negative / Boundary** | `parse_query_question_fast` (root and multi-label names, `.`/`\\` escaping, QCLASS passthrough, truncation, 63/64-octet label boundary, NULL/optional out-params); `packet_has_tsig` (TSIG last-only, duplicate TSIG rejected, ARCOUNT/RDLENGTH overrun); `skip_wire_name` (pointer end offset, self/mutual pointer loops, reserved label types, truncation); name compression per the RFC 1035 §4.1.4 `F.ISI.ARPA` example incl. case-insensitive matching, packet-generation reset/wrap and `register_wire_name_for_compression`; `dns_type_to_string` (IANA mnemonics, `TYPEnnn`), `strchr_unescaped`, `split_path_for_openat` (traversal / size rejections) and `domain_names_match_ci`. Expected wire bytes are computed by hand from the RFCs. |
| 22 | [`test_zone_parser_paths`](test_zone_parser_paths.c) | `dns_zone_parser.c`, `dns_wire.c` | RFC 1035 §5, RFC 3123 §4, RFC 3596, RFC 4034, RFC 5155, RFC 6698, RFC 9460, RFC 3597 | **Positive / Negative / Golden wire / Robustness** | 91 RR presentation forms parse and serialize; 44 RDATA layouts compared byte-for-byte with independently computed RFC wire formats; parse-time and serialize-time rejection tables; field truncation/corruption (3,204 mutations); `$ORIGIN`/`$TTL`/`$INCLUDE`/`$GENERATE`/`$ECS-*`/`$LOCATION-*`; DNAME validation. Known lenient inputs are executed but not pinned. |
| 23 | [`test_tinydns_paths`](test_tinydns_paths.c) | `dns_tinydns_parser.c` | tinydns-data format (djbdns), RFC 1035 §3.1 | **Positive / Negative / Robustness** | Valid lines of every record type with produced record types/counts; a 64-byte label or over-long name in every FQDN position must be rejected (with `err_out`, without `err_out`, and with no context); generic records and unknown type characters; field truncation and junk substitution. Known-lenient inputs (invalid IPv4 such as 300.0.2.10, meta-types 249/250/251/255 in generic records) are executed but not pinned. |
| 24 | [`test_sig0_sign`](test_sig0_sign.c) | `dns_wire.c` (`sig0_sign_packet`, `compute_sig0_keytag`) | RFC 2931 §3.1, RFC 4034 App. B, RFC 3110, RFC 6605, RFC 8080 | **Independent cryptographic verification** | RSASHA256 / ECDSAP256SHA256 / Ed25519 signatures verified with OpenSSL over `RDATA \| request(original ARCOUNT)`; key tags recomputed independently; SIG RR structure; tamper detection; argument/size/algorithm error paths with ARCOUNT restore. |
| 25 | [`test_snapshot_rebuild`](test_snapshot_rebuild.c) | `dns_snapshot_rcu.c` | zone loading & RCU snapshot semantics | **Positive / Negative** | Multi-view snapshot build from real zone files, suffix lookup, `lookup_zone_across_views`, `reload_master_zone` verdicts (OK / PARSE / MISSING_SOA / FILE_READ) and non-disturbance of the served zone on failure. |
| 26 | [`test_dag_reassembly`](test_dag_reassembly.c) | `tools/dag_pcap_l4.c`, `tools/dag_tcp_reassembly.c` | RFC 791, RFC 8200, RFC 793 / RFC 9293 §3.4 (sequence arithmetic), RFC 7766 (DNS over TCP framing) | **Randomized model / Golden frames** | Frames built byte by byte for every link type (Ethernet, 802.1Q, Linux SLL, raw IP, auto-detect): padding and trailers, IP options, fragments, truncation at every length. Deterministic pseudo-random TCP model: random segmentation, duplicate and overlapping retransmissions, bounded reordering, both directions, interleaved streams, sequence-number wraparound; every DNS message must be delivered exactly once, byte-identical, in order. Buffer cap, LRU eviction, mid-stream capture. Found and covers: TCP padding counted as payload, non-first IPv4 fragments parsed as L4, unsigned sequence comparisons stalling streams across the 2^32 wrap. |
| 27 | [`test_dag_format`](test_dag_format.c) | `tools/dag.c` (`format_rdata_for_display`) | RFC 1035 §5.1, RFC 3597 §5, RFC 8777 §4.1, RFC 9460 §2.1 | **Golden / Round trip / Robustness** | Character-string escaping (`\"`, `\\`, decimal `\DDD`, all 256 octets) for TXT/SPF/AVC/NINFO/CAA/HINFO/X25/ISDN/GPOS/NAPTR; AMTRELAY D bit / relay type; display -> zone parser -> wire round trip for 85 RR forms must reproduce the original RDATA; RDATA truncated at every length displayed without out-of-bounds reads (ASan). Found and covers: octal escapes, unescaped quotes/backslashes in HINFO/X25/ISDN/GPOS/NAPTR, AMTRELAY D-bit misdecoding. |
| 28 | [`test_query_engine_protocol`](test_query_engine_protocol.c) | `dns_query_engine.c` (`process_dns_query_impl`) | RFC 6891 §6.1.3, RFC 9619, RFC 1035 §4.1.1, RFC 5936, RFC 1995 §2, RFC 7873, RFC 1035 §3.3.13, RFC 8767, RFC 1996, RFC 8945 §5.3-5.4 | **Positive / Negative / Mutation-verified** | BADVERS with OPT version 0; FORMERR for QDCOUNT>1, cut-off question, AXFR over UDP, NOTIFY/UPDATE without a question; NOTIMP for opcodes 1-3 and 6-15; REFUSED for CH/HS; IXFR over UDP (current client: single SOA, older client: TC); cookie not issued for an unparsable client address; SOA EXPIRE exceeded -> SERVFAIL / serve-stale; NOTIFY authorization matrix (master address x TSIG present/absent/wrong key/corrupted MAC, response TSIG verified against the request MAC, forward/program zones -> NOTIMP). |
| 29 | [`test_response_cache`](test_response_cache.c) | `dns_query_engine.c`, `dns_snapshot_rcu.c`, `dns_wire.c` | RFC 1034, RFC 7873 | **Positive / Consistency** | Pre-rendered wire-format response cache: cached answers byte-for-byte identical to uncached ones (with and without EDNS), DNS Cookie queries served from the cache with a per-client server cookie, 0x20 case preservation, every cache-exclusion criterion, `wire-cache-max-records` parsing and thresholds, and the observatory hit/miss counters. |
| 30 | [`test_dnssec_proofs`](test_dnssec_proofs.c) | `dns_query_engine.c` (`resolve_name`), `dns_wire.c` | RFC 5155 App. A/B, RFC 4035 App. A/B, RFC 4592 §2.2, RFC 8020 | **Golden (RFC worked examples)** | The RFCs' own example zones (NSEC3 opt-out chain, NSEC chain) queried with DO=1: NXDOMAIN, NODATA, empty non-terminal, opt-out referral, wildcard answer / NODATA, wraparound, DS handling. The set of NSEC/NSEC3 owners in AUTHORITY must equal the RFC's. Hashed owners come from an independent SHA-1/base32hex implementation. Found and covers the fixes for: ENT answered NXDOMAIN, wildcard synthesized over an ENT, NSEC3 with empty bitmap failing to serialize. |
| 31 | [`test_hash_table`](test_hash_table.c) | `dns_snapshot_rcu.c`, `dns_utils.c`, `dns_wire.c` | FNV-1a Hash, RCU Snapshot | **Positive / Boundary** | Production snapshot RCU exact and suffix hash table lookup, case-insensitivity, longest-match fallback, missing teeth tolerance, and zero-zone views. |
| 32 | [`test_server_core`](test_server_core.c) | `dns_server_core.c`, `dns_snapshot_rcu.c`, `dns_wire.c`, `dns_dnstap.c` | RFC 1034, RFC 1035, RFC 7766, BIND Logging | **Positive / Boundary / Concurrency** | Dedicated unit testing of `dns_server_core.c` internal machinery: fast IPv4 serialization, RFC 1035/BIND qname log escaping, log file size and date rotation, TCP message stream framing & chunking, query log ring buffer rate limiting & 80% circuit breaker, response logging ring, zone observatory snapshots, synthetic zone detection, safe directory creation, and (FreeBSD) that `tsig_prewarm_crypto()` keeps every TSIG/karictl HMAC usable after `cap_enter()` (regression guard: OpenSSL lazy init inside Capsicum capability mode raises SIGTRAP). Also: `-p` value classification (`parse_cli_port_arg`: all-digit port 1-65535, invalid numbers, PID file paths) and the control-channel challenge-response with the configured HMAC (`hmac-sha512`, `hmac-md5`, wrong algorithm rejected, empty AUTH never accepted). |
| 33 | [`test_fi_parsers`](test_fi_parsers.c) | `dns_zone_parser.c`, `dns_config_parser.c`, `dns_tinydns_parser.c` | RFC 1035, BIND config, tinydns | **Fault Injection / Memory** | Exhaustive fail-Nth fault injection sweeps across memory allocations during zone, config, and tinydns parsing to verify clean error paths and zero leaks. |
| 34 | [`test_fi_wire`](test_fi_wire.c) | `dns_wire.c`, `dns_tsig_acl.c` | RFC 1035, RFC 8945 | **Fault Injection / Wire** | Fail-Nth fault injection sweeps across wire format serialization, compression, and TSIG cryptographic signing/verification failure modes. |
| 35 | [`test_fi_snapshot`](test_fi_snapshot.c) | `dns_snapshot_rcu.c`, `dns_priv_sandbox.c` | RCU, Capsicum | **Fault Injection / RCU** | Fail-Nth fault injection sweeps across RCU snapshot rebuilding, view structures, and Capsicum directory caching. |
| 36 | [`test_fi_xfr`](test_fi_xfr.c) | `dns_axfr_ixfr.c`, `dns_dynamic_update.c` | RFC 5936, RFC 1995, RFC 1982 | **Fault Injection / XFR** | Fail-Nth fault injection sweeps across AXFR/IXFR inbound packet parsing and SOA serial incrementation. |
| 37 | [`test_fi_misc`](test_fi_misc.c) | `dns_dynamic_update.c`, `dns_catalog_zone.c`, `dns_dnstap.c`, `dns_edns_ecs.c` | RFC 2136, RFC 9432, DNSTAP | **Fault Injection / Extensions** | Fail-Nth fault injection sweeps across dynamic updates, catalog zone bookkeeping, and DNSTAP Protobuf message construction. |
| 38 | [`test_fi_dag`](test_fi_dag.c) | `tools/dag.c`, `tools/dag_output_yaml.c` | RFC 1035, YAML | **Fault Injection / Tools** | Fail-Nth fault injection sweeps across dag client query packet generation and YAML formatting helpers. |
| 162 | [`test_epoch_rcu`](test_epoch_rcu.c) | `dns_epoch_rcu.c` | Epoch RCU (R-25) | **Positive / Concurrency** | `rcu_writer_publish()` makes the new pointer visible before the epoch advances and returns the pre-publish epoch; a reader that entered before the publish blocks `rcu_writer_wait_until_safe(retire)`, one that entered after does not; auxiliary reader slots (nesting keeps the outer epoch, pin/unpin, release); 3-thread double-buffer stress where the writer poisons the retired buffer after the grace period and readers must never see it. Also built as `test_epoch_rcu-tsan` and run by `run_rcu_tsan_test.sh`. |

---

### 3.2 Zone Transfer & Redundancy - Category: `xfr`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 39 | [`run_capsicum_axfr_test.sh`](run_capsicum_axfr_test.sh) | `dns_priv_sandbox.c`, `dns_axfr_ixfr.c`, `dns_server_core.c` | RFC 5936, Capsicum | **Positive / Security** | Inbound AXFR stream ingestion inside strict FreeBSD `cap_enter()` capability mode sandbox. |
| 40 | [`run_ixfr_roundtrip_test.sh`](run_ixfr_roundtrip_test.sh) | `dns_axfr_ixfr.c`, `dns_server_core.c` | RFC 1995 | **Positive** | RFC 1995 IXFR incremental difference roundtrip serialization and client playback. |
| 41 | [`run_extended_axfr_test.sh`](run_extended_axfr_test.sh) | `dns_axfr_ixfr.c`, `dns_wire.c`, `dns_server_core.c` | RFC 5936, Option 65153 | **Positive** | KariDNS Extended AXFR transfer stream over EDNS Option 65153 with chunk compression. |
| 42 | [`run_axfr_multikey_tsig_test.sh`](run_axfr_multikey_tsig_test.sh) | `dns_tsig_acl.c`, `dns_axfr_ixfr.c` | RFC 5936 §4.3, RFC 8945 | **Positive / Negative** | Multi-key TSIG authentication, proper key selection, and rogue key rejection during AXFR transfers. |
| 43 | [`run_udp_ixfr_test.sh`](run_udp_ixfr_test.sh) | `dns_axfr_ixfr.c`, `dns_server_core.c` | RFC 1995 §4.1 | **Positive** | UDP IXFR query processing when diff fits within single unfragmented UDP datagram. |
| 44 | [`run_zone_type_secondary_test.sh`](run_zone_type_secondary_test.sh) | `dns_server_core.c`, `dns_axfr_ixfr.c` | RFC 1034 §4.3.5, RFC 1996 | **Positive** | Secondary zone SOA refresh timer polling, retry timers, and expiry behavior. |
| 45 | [`run_edns_expire_test.sh`](run_edns_expire_test.sh) | `dns_axfr_ixfr.c`, `dns_query_engine.c`, `dns_wire.c` | RFC 7314 | **Positive / Negative** | EDNS EXPIRE option: the primary returns SOA EXPIRE (SOA, other types, wire cache hits, AXFR), no option for a zone the server is not authoritative for or without the option in the query; a secondary returns the remaining expire timer; in primary -> A -> B, B follows A's timer after the primary stops and both expire together. |

---

### 3.3 DNSSEC & Message Digests - Category: `dnssec`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 46 | [`run_zonemd_val_test.sh`](run_zonemd_val_test.sh) | `tools/karicheck.c`, `dns_wire.c` | RFC 8976, RFC 6840 | **Positive / Verification** | RFC 8976 ZONEMD digest computation verified against official test vectors (including `uri.arpa.`). |
| 47 | [`run_dnssec_negative_soa_rrsig_test.sh`](run_dnssec_negative_soa_rrsig_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 4035 §3.1.3 | **Positive** | Authority section SOA covering RRSIG inclusion in NXDOMAIN and NODATA negative responses. |
| 48 | [`run_ds_delegation_test.sh`](run_ds_delegation_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 4034 §5, RFC 4035 | **Positive** | Referral responses containing delegation DS RRset and covering RRSIG records. |

---

### 3.4 Dynamic Update - Category: `update`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 49 | [`run_dynamic_update_test.sh`](run_dynamic_update_test.sh) | `dns_dynamic_update.c`, `dns_epoch_rcu.c` | RFC 2136 | **Positive / Negative** | RFC 2136 Prerequisites (YXDOMAIN, NXDOMAIN, YXRRSET, NXRRSET) and update sections. |
| 50 | [`run_update_slave_notauth_test.sh`](run_update_slave_notauth_test.sh) | `dns_dynamic_update.c`, `dns_server_core.c` | RFC 2136 §3.8 | **Negative** | Clean rejection of dynamic updates targeted at secondary/slave zones with NOTAUTH (RCODE 9). |
| 51 | [`run_ttl_harmonization_update_test.sh`](run_ttl_harmonization_update_test.sh) | `dns_dynamic_update.c`, `dns_query_engine.c` | RFC 2181 §5.2 | **Positive** | Enforcing RRset TTL harmonization when dynamically adding RRs with differing TTL values. |

---

### 3.5 EDNS, Cookies & Transport Extensions - Category: `edns`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 52 | [`run_bind_ecs_subnet_test.sh`](run_bind_ecs_subnet_test.sh) | `dns_edns_ecs.c`, `dns_query_engine.c` | RFC 7871 | **Positive / Steering** | Parsing ECS client prefix from trusted resolvers, `$ECS-SUBNET` routing, and SCOPE echo. |
| 53 | [`run_mqtype_qdcount0_test.sh`](run_mqtype_qdcount0_test.sh) | `dns_wire.c`, `dns_server_core.c` | RFC 10029, RFC 9619 | **Positive / Negative** | RFC 10029 Multi-QTYPE response aggregation; RFC 9619 QDCOUNT=0 minimal reply & QDCOUNT>1 FORMERR. |

---

### 3.6 Response Rate Limiting (RRL) & Anti-DoS - Category: `rrl`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 54 | [`run_rrl_window_test.sh`](run_rrl_window_test.sh) | `dns_rrl.c`, `dns_server_core.c` | RRL Draft, RFC 5452 | **Positive / Anti-DoS** | Keyed hash bucket sliding window rate limiting and SLIP truncated (TC=1) response generation. |
| 55 | [`run_query_log_rate_limit_test.sh`](run_query_log_rate_limit_test.sh) | `dns_server_core.c` | Operational Practice | **Positive / Resource** | Query log ring buffer throttling to prevent disk I/O exhaustion under flood attack. |
| 56 | [`run_glue_truncation_test.sh`](run_glue_truncation_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 1035 §4.1.1, RFC 6891 | **Positive / Boundary** | Additional section glue truncation and TC bit setting when exceeding UDP buffer size. |

---

### 3.7 Catalog Zones - Category: `catalog`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 57 | [`run_catalog_zone_test.sh`](run_catalog_zone_test.sh) | `dns_catalog_zone.c`, `dns_snapshot_rcu.c` | RFC 9432 | **Positive / Dynamic** | Automated provisioning and de-provisioning of member zones via catalog zone updates. |
| 58 | [`run_cve_coo_test.sh`](run_cve_coo_test.sh) | `dns_catalog_zone.c`, `dns_snapshot_rcu.c` | RFC 9432 §4.3 | **Security / Negative** | Strict Change of Ownership (CoO) property validation preventing catalog member hijacking. |

---

### 3.8 dnstap Logging - Category: `dnstap`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 59 | [`run_dnstap_capture_test.sh`](run_dnstap_capture_test.sh) | `dns_dnstap.c`, `dns_server_core.c` | Frame Streams / Protobuf | **Positive / Telemetry** | Asynchronous DNSTAP query/response logging over Unix domain sockets. Also `log-queries yes;` alone: only AUTH_QUERY frames are sent. |

---

### 3.9 tinydns Compatibility - Category: `tinydns`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 60 | [`run_tinydns_location_test.sh`](run_tinydns_location_test.sh) | `dns_tinydns_parser.c`, `dns_query_engine.c` | tinydns location format | **Positive / Geo** | 2-character location code split-horizon routing matching client IP subnets. |
| 61 | [`run_tinydns_timestamp_test.sh`](run_tinydns_timestamp_test.sh) | `dns_tinydns_parser.c`, `dns_query_engine.c` | Tai64n timestamp | **Positive / Expiry** | Automatic TTL countdown based on Tai64n timestamp and record suppression post-TTD. |

---

### 3.10 Server Core & Resolution - Category: `core`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 62 | [`run_server_core_matrix_test.sh`](run_server_core_matrix_test.sh) | `dns_server_core.c`, `dns_query_engine.c`, `dns_dnstap.c` | RFC 1996, RFC 7766, RFC 6891 | **Positive / Negative / Robustness** | Server runtime paths the feature tests leave alone: dual-stack wildcard listeners and IPv6 clients, IPv6 NOTIFY targets and `notify-source`, TC on oversized UDP answers, TCP edge cases (idle hold, zero length, a DNS response sent to the query port, pipelining, bursts), dnstap receiver going away, query-log rotation. |
| 63 | [`run_server_core_fi_test.sh`](run_server_core_fi_test.sh) | `dns_server_core.c`, `dns_priv_sandbox.c`, `tests/fi/kari_fi_preload.c` | Robustness | **Fault Injection** | Starts karidns repeatedly with one system call (socket, bind, setsockopt, socketpair, fork, pthread_create, kqueue, privilege-drop calls, ...) failing on its Nth invocation and drives UDP/TCP queries, AXFR, NOTIFY and control commands; the process must fail cleanly or keep serving. |
| 64 | [`run_paren_check_test.sh`](run_paren_check_test.sh) | `dns_zone_parser.c` | RFC 1035 §5.1 | **Positive** | Tokenizer support for multi-line parenthesized RR definitions (SOA, TXT, etc.). |
| 65 | [`run_ttl_suffix_test.sh`](run_ttl_suffix_test.sh) | `dns_zone_parser.c`, `dns_utils.c` | BIND 9 Syntax | **Positive** | Parsing time unit suffixes (`s`, `m`, `h`, `d`, `w`) across zone files and config. |
| 66 | [`run_roundtrip_test.sh`](run_roundtrip_test.sh) | `dns_zone_parser.c`, `dns_wire.c` | RFC 1035 §3.2 | **Positive** | Parity of text zone parser -> wire serialization -> wire parser roundtrip. |
| 67 | [`run_karicheck_glue_test.sh`](run_karicheck_glue_test.sh) | `tools/karicheck.c` | RFC 1034 §4.2.2, RFC 9471 | **Positive / Lint** | `karicheck` detection and warning for missing in-bailiwick glue records. |
| 68 | [`run_karicheck_semantic_lint_test.sh`](run_karicheck_semantic_lint_test.sh) | `tools/karicheck.c` | RFC 1912, RFC 8624, RFC 9276 | **Positive / Lint** | Semantic linter checks for CNAME co-existence, deprecated DNSSEC algorithms, and NSEC3 params. |
| 69 | [`run_karicheck_matrix_test.sh`](run_karicheck_matrix_test.sh) | `tools/karicheck.c` (`check_zone`, `check_config`) | RFC 2915/3403 (NAPTR), RFC 2782 (SRV), RFC 8659 (CAA), RFC 4255 (SSHFP), RFC 5155 & RFC 9276 (NSEC3 parameters), RFC 8976 (ZONEMD), RFC 9432 (catalog zones), RFC 1912 | **Fixture matrix (74 cases)** | Each lint diagnostic is provoked by a minimal input; the message and the exit-status contract (1 on any [ERROR], 0 for clean zones and warnings) are asserted. Covers RDATA validation, DNSSEC parameter lint, zone structure, tinydns-data zones, catalog zones, config lint and command-line handling. Runs against any binary via `KARICHECK=`. |
| 70 | [`run_phase2_core_audit_test.sh`](run_phase2_core_audit_test.sh) | `dns_server_core.c`, `dns_query_engine.c` | RFC 1034/1035 | **Positive / Audit** | Phase 2 server core resolution pipeline architecture audit. |
| 71 | [`run_phase2_audit_part2_test.sh`](run_phase2_audit_part2_test.sh) | `dns_server_core.c`, `dns_wire.c` | RFC 1035 | **Boundary / Security** | Wire format boundary safety, compression pointer loops, and malformed label lengths. |
| 72 | [`run_response_section_order_test.sh`](run_response_section_order_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 1035 §4.1.2 | **Positive** | Canonical response section ordering: Question, Answer, Authority, Additional. |
| 73 | [`run_sibling_additional_test.sh`](run_sibling_additional_test.sh) | `dns_query_engine.c` | RFC 1034 §4.3.2 | **Positive** | Automatic inclusion of sibling domain glue records in the Additional section. |
| 74 | [`run_multi_instance_test.sh`](run_multi_instance_test.sh) | `dns_server_core.c`, `dns_axfr_ixfr.c` | RFC 5936 | **Positive / Isolation** | Several KariDNS instances in foreground mode (`-f`) with separate ports, PID files and control sockets run side by side without PID-lock collisions, and transfer a zone between each other. |
| 75 | [`run_forward_zone_test.sh`](run_forward_zone_test.sh) | `dns_server_core.c`, `dns_query_engine.c` | RFC 5452, Forwarding | **Positive / Negative** | Forward zone relaying, shared deadline budgets, upstream failover, and TC fallback. |
| 76 | [`run_program_zone_test.sh`](run_program_zone_test.sh) | `dns_server_core.c`, `dns_query_engine.c` | Program Zone IPC | **Positive / Extensibility** | Evaluation of dynamic backend records via external pipe-based program zone plugins. |
| 77 | [`run_karictl_observatory_test.sh`](run_karictl_observatory_test.sh) | `tools/karictl.c`, `dns_server_core.c` | KariDNS control protocol | **Positive / Management** | `karictl observatory` per-zone statistics after a mix of queries: role, SOA serial, query and RCODE counters, EDNS/DO/ECS counters, RRL counters, NOTIFY/transfer counters and wire-cache statistics. |
| 78 | [`run_karictl_reload_reconfig_test.sh`](run_karictl_reload_reconfig_test.sh) | `tools/karictl.c`, `dns_snapshot_rcu.c` | Epoch RCU Architecture | **Positive / RCU** | Zero-downtime zone reloading and configuration updates via Epoch RCU pointer swap. |
| 79 | [`run_config_duplicate_rejection_test.sh`](run_config_duplicate_rejection_test.sh) | `dns_config_parser.c` | Config Syntax | **Negative** | Rejection of duplicate view names and duplicate zone definitions during startup. |
| 80 | [`run_domain_length_rfc1035_test.sh`](run_domain_length_rfc1035_test.sh) | `dns_wire.c`, `dns_zone_parser.c` | RFC 1035 §2.3.4 | **Negative / Boundary** | Strict enforcement of 255-byte total domain length and 63-byte per-label limits. |
| 81 | [`run_logging_channel_validation_test.sh`](run_logging_channel_validation_test.sh) | `dns_config_parser.c`, `tools/karicheck.c` | Logging configuration | **Positive / Negative** | `karicheck` accepts a valid `logging {}` configuration and rejects `queries` / `responses` categories that reference an undefined channel. |
| 82 | [`run_mx_srv_glue_test.sh`](run_mx_srv_glue_test.sh) | `dns_query_engine.c` | RFC 1035 §3.3.9, RFC 2782 | **Positive** | In-bailiwick A/AAAA address record inclusion for MX and SRV target hosts. |
| 83 | [`run_notify_source_test.sh`](run_notify_source_test.sh) | `dns_server_core.c` | RFC 1996 §4.4 | **Positive** | Source address selection and explicit IP binding for outgoing NOTIFY datagrams. |
| 84 | [`run_privilege_drop_root_test.sh`](run_privilege_drop_root_test.sh) | `dns_server_core.c`, `dns_priv_sandbox.c` | POSIX privileges | **Negative / Security** | Started as root without a `user` directive, karidns refuses to start (skipped when not run as root). |
| 85 | [`run_nonroot_startup_test.sh`](run_nonroot_startup_test.sh) | `dns_server_core.c`, `dns_priv_sandbox.c` | POSIX privileges | **Positive / Negative** | Starting karidns as an unprivileged user (or as root dropping to `user`): ports below 1024 or already in use, and log / PID / control-socket paths that cannot be written, must abort startup with a clear error. |
| 86 | [`run_response_cache_test.sh`](run_response_cache_test.sh) | `dns_query_engine.c`, `dns_snapshot_rcu.c` | RFC 1034, RFC 7873 | **Positive** | Builds and runs `test_response_cache` with ASan/UBSan (or runs the existing binary). |
| 87 | [`run_ttl_harmonization_test.sh`](run_ttl_harmonization_test.sh) | `dns_zone_parser.c`, `dns_query_engine.c` | RFC 2181 §5.2 | **Positive / Semantic** | Enforcing consistent TTL values across all records within the same RRset on zone load. |
| 88 | [`run_ttl_rfc2181_clamp_test.sh`](run_ttl_rfc2181_clamp_test.sh) | `dns_wire.c` | RFC 2181 §8 | **Boundary** | Clamping TTL values with the high bit set (≥ 2^31) to 0 during wire serialization. |
| 89 | [`run_zone_oom_partial_load_test.sh`](run_zone_oom_partial_load_test.sh) | `dns_zone_parser.c`, `dns_snapshot_rcu.c` | Robustness | **Negative / Fault Injection** | Fail-closed atomic rollback to previous zone version upon encountering simulated OOM. |
| 90 | [`run_coverage_merge_test.sh`](run_coverage_merge_test.sh) | `tests/coverage_merge.sh` (used by `make coverage-report`) | LLVM source-based coverage | **Negative / Regression** | A process SIGKILLed while writing its `.profraw` at exit leaves a truncated file (`file header is corrupt`); the default `llvm-profdata merge` then aborts with `no profile can be merged` and the whole report is lost. Uses a stub `llvm-profdata` (same abort-on-any-invalid behaviour): corrupt/empty/wrong-magic files are skipped and named, valid ones are merged, no temporary files are left behind, and "no valid profile at all" / wrong usage still fail. |
| 91 | [`run_malformed_detection_default_test.sh`](run_malformed_detection_default_test.sh) | `dns_wire.c`, `dns_server_core.c` | RFC 1035 §4.1.1 | **Negative** | FORMERR error response generation upon receiving malformed or truncated queries. |
| 92 | [`run_matrix_queries_test.sh`](run_matrix_queries_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 1034, RFC 1035, RFC 6672, RFC 4035 | **Table-Driven Matrix** | Matrix validation of query/response across all supported RR types, negative caching, and wildcard/DNAME delegations. |
| 93 | [`run_server_lifecycle_test.sh`](run_server_lifecycle_test.sh) | `dns_server_core.c` | Process lifecycle | **Robustness** | Server lifecycle and crash-resistance matrix: startup, reload, signals and shutdown of the manager, frontend and backend processes. |
| 94 | [`run_tcp_adversary_test.sh`](run_tcp_adversary_test.sh) | `dns_server_core.c` | RFC 7766 | **Negative / Adversarial** | TCP state machine adversary suite: slow, partial, oversized and abandoned TCP streams must not stall or crash the server. |
| 95 | [`run_control_adversary_test.sh`](run_control_adversary_test.sh) | `dns_server_core.c` (control channel) | KariDNS control protocol | **Negative / Security** | Control channel adversary test: malformed, unauthenticated and oversized control-socket traffic is rejected without affecting the server. |
| 96 | [`run_karicheck_rules_test.sh`](run_karicheck_rules_test.sh) | `tools/karicheck.c` | RFC 1035, RFC 1912, RFC 2181 | **Positive / Lint** | Diagnostic rules matrix for karicheck: each rule is triggered and its message and exit status are checked. |
| 97 | [`run_karicheck_deep_rules_test.sh`](run_karicheck_deep_rules_test.sh) | `tools/karicheck.c` | RFC 8624, RFC 9276, RFC 8976, RFC 9432 | **Positive / Lint** | Deep static lint rules of karicheck (DNSSEC parameters, ZONEMD, catalog zones and RDATA field checks). |
| 98 | [`run_zone_parser_error_paths_test.sh`](run_zone_parser_error_paths_test.sh) | `dns_zone_parser.c`, `tools/karicheck.c` | RFC 1035 §5, BIND `$GENERATE` | **Negative / Robustness** | Zone parser negative paths: anomalous directives, `$GENERATE` ranges and modifiers, and malformed RDATA handling. |
| 99 | [`run_karictl_adversary_test.sh`](run_karictl_adversary_test.sh) | `tools/karictl.c` | KariDNS control protocol | **Negative** | karictl command-line and error-handling matrix: bad options, missing or unreadable configuration, wrong secrets, unreachable sockets and server error replies. |

---

### 3.11 Diagnostic Client (`dag`) Suite - Category: `dag`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 100 | [`run_dag_scenario_matrix_test.sh`](run_dag_scenario_matrix_test.sh) | `tools/dag*.c`, `tools/karictl.c` | RFC 1034, RFC 1035 | **Positive / Composite** | Multi-protocol scenario matrix for dag and karictl: `+trace` delegation with and without glue, CNAME chains and loop detection, `+tcp` / `+yaml` / `+short` output, and related control operations. |
| 101 | [`run_dag_ci_test.sh`](run_dag_ci_test.sh) | `dag` (`tools/dag*.c`) | RFC 1035, RFC 3597, RFC 6891, RFC 10029 | **Positive / Composite** | Comprehensive CLI flag and option test matrix (+short, +yaml, +qr, +trace, +multiline). |
| 102 | [`run_dag_cli_anomalous_options_test.sh`](run_dag_cli_anomalous_options_test.sh) | `tools/dag.c`, `tools/dag_transport.c` | dig option syntax | **Negative / Robustness** | dag CLI anomalous option values and transport resilience (invalid, empty and conflicting options must be rejected or ignored without crashing). |
| 103 | [`run_dag_batch_advanced_opts_test.sh`](run_dag_batch_advanced_opts_test.sh) | `dag` (`tools/dag_batch.c`) | Batch Processing | **Positive** | Batch file execution (`-f`) supporting mixed per-query options and comments. |
| 104 | [`run_dag_fuzzer_test.sh`](run_dag_fuzzer_test.sh) | `dag` fuzz targets in `tests/fuzz/` | libFuzzer | **Fuzzing Smoke** | Smoke execution of LLVM libFuzzer targets for dag client parsers. |
| 105 | [`run_dag_apl_afdlength_overflow_test.sh`](run_dag_apl_afdlength_overflow_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 3123 | **Boundary / Security** | Boundary check preventing buffer overflow on malformed APL AFDLENGTH values. |
| 106 | [`run_dag_audit_improvements_test.sh`](run_dag_audit_improvements_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7230, RFC 7858, RFC 8484 | **Positive / Transport** | TLS handshake error message, `+search` FQDN buffer safety, and HTTP/1.1 chunked transfer decoding for DoH. |
| 107 | [`run_dag_axfr_tsig_unsigned_intermediate_test.sh`](run_dag_axfr_tsig_unsigned_intermediate_test.sh) | `dag` (`tools/dag_tsig_client.c`) | RFC 8945 §5.3.1 | **Positive / Negative** | TSIG verification across multi-message AXFR streams where intermediate records omit TSIG. |
| 108 | [`run_dag_badcookie_transport_test.sh`](run_dag_badcookie_transport_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 7873, RFC 9018 | **Positive / Recovery** | Automated client retry with extracted server cookie upon receiving BADCOOKIE response. |
| 109 | [`run_dag_bind_address_family_mismatch_test.sh`](run_dag_bind_address_family_mismatch_test.sh) | `dag` (`tools/dag_transport.c`) | Socket API | **Negative** | Error reporting when local `-b` address family conflicts with destination server family. |
| 110 | [`run_dag_break_help_examples_test.sh`](run_dag_break_help_examples_test.sh) | `dag` (`tools/dag.c`) | CLI Help | **Positive** | Verification that every command example in `dag --help` runs cleanly. |
| 111 | [`run_dag_cli_options_test.sh`](run_dag_cli_options_test.sh) | `dag` (`tools/dag.c`) | CLI Parsing | **Positive / Negative** | Parsing short options, long options, negation flags (`+no...`), and value assignments. dig-compatible defaults: EDNS0 with udp 1232 and a client cookie by default, `+noedns`, `+nocookie`, `+bufsize`, and no OPT on UPDATE / NOTIFY unless `+edns` is given. |
| 112 | [`run_dag_compat_test.sh`](run_dag_compat_test.sh) | `dag` (`tools/dag.c`) | BIND 9 dig Parity | **Positive** | Output structure parity with standard BIND 9 dig. |
| 113 | [`run_dag_cookie_mismatch_discard_test.sh`](run_dag_cookie_mismatch_discard_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 7873 §5.2.3 | **Negative** | Discarding spoofed server responses whose client cookie does not match the outgoing cookie. |
| 114 | [`run_dag_dig_anomalous_suite.sh`](run_dag_dig_anomalous_suite.sh) | `dag` (`tools/dag.c`) | Robustness | **Negative / Robustness** | Handling corrupt headers, truncated RRs, and malformed packets without crashing. |
| 115 | [`run_mock_anomalous_tc_test.sh`](run_mock_anomalous_tc_test.sh) | [`mock_anomalous_dns_server.pl`](mock_anomalous_dns_server.pl), `karidns` (`disable-auto-tc-flag yes`) | RFC 1035 §4.1.1, RFC 6891 §6.2.5, §7 | **Positive / Negative** | UDP auto-TC of the anomalous mock in plugin and standalone modes: `tcp-size`/`packet-size`/`tcp-max-65535` truncated above the EDNS payload size (min 512) or 1232 without EDNS, OPT (udp 1232) on truncated replies; `udp-size` and `edns-bufsize-exceeded` returned as-is. |
| 116 | [`run_dag_dns64prefix_short_yaml_test.sh`](run_dag_dns64prefix_short_yaml_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 7050 | **Positive** | Formatting `+dns64prefix` results in `+short` and `+yaml` output modes. |
| 117 | [`run_dag_dns64prefix_test.sh`](run_dag_dns64prefix_test.sh) | `dag` (`tools/dag.c`) | RFC 7050 | **Positive** | Extracting synthetic IPv6 prefixes from `ipv4only.arpa` queries. |
| 118 | [`run_dag_doh_cache_cleanup_test.sh`](run_dag_doh_cache_cleanup_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 8484 | **Resource** | Socket cleanup and session termination for DoH HTTP connections. |
| 119 | [`run_dag_doh_dot_axfr_test.sh`](run_dag_doh_dot_axfr_test.sh) | `dag` (`tools/dag_axfr_client.c`) | RFC 5936, RFC 7858, RFC 8484 | **Positive / Transport** | Performing AXFR zone transfers over encrypted DoH and DoT transport channels. |
| 120 | [`run_dag_ede_truncation_regression_test.sh`](run_dag_ede_truncation_regression_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 8914, RFC 6891 | **Positive / Boundary** | Extended DNS Error (EDE) option parsing and truncation boundary safety. |
| 121 | [`run_dag_edge_cases_audit_test.sh`](run_dag_edge_cases_audit_test.sh) | `dag` (`tools/dag*.c`) | RFC 8945, RFC 9460 §2.2, RFC 7830 | **Boundary / Regression** | TSIG applied to the background queries of `+trace` / `+nssearch` / `+dns64prefix`, SVCB/HTTPS TargetName never compressed, `+padding` default block size, and ZONEMD hex splitting under `+yaml`. |
| 122 | [`run_dag_edge_cases_phase3_test.sh`](run_dag_edge_cases_phase3_test.sh) | `dag` (`tools/dag.c`, `tools/dag_transport.c`) | RFC 1876, RFC 6891 | **Boundary / Fault** | LOC formatting independent of the locale, a single TCP fallback after truncation, and `+ednsopt` overflow safety. |
| 123 | [`run_dag_fixes_validation_test.sh`](run_dag_fixes_validation_test.sh) | `dag` (`tools/dag*.c`) | Regression Suite | **Positive / Negative** | Consolidated validation of past bug fixes and formatting corrections. |
| 124 | [`run_dag_hex_payload_overflow_test.sh`](run_dag_hex_payload_overflow_test.sh) | `dag` (`tools/dag.c`) | Raw Hex Input | **Boundary / Security** | Buffer size validation when injecting arbitrary hex DNS packet payloads via `--hex`. |
| 125 | [`run_dag_ixfr_uptodate_test.sh`](run_dag_ixfr_uptodate_test.sh) | `dag` (`tools/dag_axfr_client.c`) | RFC 1995 §4.2 | **Positive** | Handling IXFR response when client SOA serial is equal to current zone SOA (single SOA response). |
| 126 | [`run_dag_keepopen_keepalive_test.sh`](run_dag_keepopen_keepalive_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7766, RFC 7828 | **Positive** | TCP connection reuse (`+keepopen`) with EDNS TCP keepalive negotiation. |
| 127 | [`run_dag_keepopen_partial_read_test.sh`](run_dag_keepopen_partial_read_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7766 §7.2 | **Boundary** | Framing reassembly when TCP stream delivers fragmented length prefixes. |
| 128 | [`run_dag_keepopen_tls_partial_read_test.sh`](run_dag_keepopen_tls_partial_read_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7858 | **Boundary** | TLS record stream reassembly across fragmented TLS frames under `+keepopen`. |
| 129 | [`run_dag_long_label_name_expansion_test.sh`](run_dag_long_label_name_expansion_test.sh) | `dag` (`tools/dag.c`) | RFC 1035 §2.3.4 | **Boundary** | Rendering max-length 63-byte labels in presentation format without truncation. |
| 130 | [`run_dag_multi_server_semantic_match_test.sh`](run_dag_multi_server_semantic_match_test.sh) | `dag` (`tools/dag.c`) | Multi-Server Queries | **Positive** | Parallel querying of multiple servers and comparing response parity. |
| 131 | [`run_dag_multi_server_timeout_test.sh`](run_dag_multi_server_timeout_test.sh) | `dag` (`tools/dag_transport.c`) | Timeout Handling | **Negative / Timeout** | Handling individual server timeouts in multi-server batch mode without blocking. |
| 132 | [`run_dag_multiline_ds_single_line_test.sh`](run_dag_multiline_ds_single_line_test.sh) | `dag` (`tools/dag.c`) | dig output format | **Positive** | DS and DNSKEY records use the multi-line parenthesized format under `+multiline`. |
| 133 | [`run_dag_replay_compare_recorded_test.sh`](run_dag_replay_compare_recorded_test.sh) | `dag` (`tools/dag_replay.c`) | PCAP Replay | **Positive** | Replaying captured PCAP queries against live server and verifying response parity. The exit status is 1 exactly when mismatches were reported. |
| 134 | [`run_dag_replay_diff_test.sh`](run_dag_replay_diff_test.sh) | `dag` (`tools/dag_replay.c`) | PCAP Replay | **Positive** | Diff engine output generation for PCAP query differences. The exit status is 1 exactly when mismatches were reported. |
| 135 | [`run_dag_rr_differential_test.sh`](run_dag_rr_differential_test.sh) | `dag`, `dns_wire.c` | Wire Format | **Positive** | Differential RR parser comparison across all supported DNS resource record types. |
| 136 | [`run_dag_sig0_update_test.sh`](run_dag_sig0_update_test.sh) | `dag` (`tools/dag_tsig_client.c`) | RFC 2931, RFC 3007 | **Positive / Crypto** | SIG(0) public-key transaction signing and verification for dynamic update messages. |
| 137 | [`run_dag_tcp_connect_timeout_test.sh`](run_dag_tcp_connect_timeout_test.sh) | `dag` (`tools/dag_transport.c`) | TCP Transport | **Negative / Timeout** | Non-blocking TCP connect timeout enforcement. |
| 138 | [`run_dag_trace_cname_glue_test.sh`](run_dag_trace_cname_glue_test.sh) | `dag` (`tools/dag_trace.c`) | Iterative Trace | **Positive** | `+trace` following CNAME referrals and resolving glue records iteratively. |
| 139 | [`run_dag_trace_deep_cname_stack_test.sh`](run_dag_trace_deep_cname_stack_test.sh) | `dag` (`tools/dag_trace.c`) | RFC 1034 §3.6.2 | **Boundary** | `+trace` resolving 10+ hop deep CNAME redirection stacks without loop or overflow. |
| 140 | [`run_dag_trace_nssearch_opts_test.sh`](run_dag_trace_nssearch_opts_test.sh) | `dag` (`tools/dag_trace.c`) | Authoritative Polling | **Positive** | `+nssearch` polling all authoritative nameservers for zone SOA serials. |
| 141 | [`run_dag_trace_nssearch_tcp_test.sh`](run_dag_trace_nssearch_tcp_test.sh) | `dag` (`tools/dag_trace.c`) | Authoritative Polling | **Positive** | `+nssearch` execution forced over TCP transport. |
| 142 | [`run_dag_trace2_test.sh`](run_dag_trace2_test.sh) | `dag` (`tools/dag_iter.c`), `karidns` | RFC 1034 §5.3.3, RFC 8109, RFC 9156, RFC 9471 | **Positive / Negative** | `+trace2` full iterative resolution over four KariDNS instances plus [`mock_trace2_server.pl`](mock_trace2_server.pl) (127.0.0.1-5) forming a root/TLD/SLD tree: glue and glueless delegations, CNAME/DNAME chasing, CNAME (in-zone and cross-zone) and NS dependency loops, in-domain NS without glue, lame servers, timeouts, TC=1 to TCP fallback, FORMERR to non-EDNS retry, query budget, QNAME minimisation (A/NS, NXDOMAIN fallback), priming failures and glueless priming answers, host-name `@server`, `+roothints`, `-6` without IPv6, `+ldnsz` trace URL, batch `-f`, YAML/short output. Skips when loopback aliases are unavailable. |
| 143 | [`run_dag_udp_id_mismatch_discard_test.sh`](run_dag_udp_id_mismatch_discard_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 5452 §4.3 | **Negative / Security** | Discarding UDP datagrams with mismatched transaction IDs. |
| 144 | [`run_dag_udp_spoofing_source_test.sh`](run_dag_udp_spoofing_source_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 5452 §4.1 | **Negative / Security** | Discarding spoofed UDP packets originating from unexpected source addresses. |
| 145 | [`run_dag_update_del_exact_ttl_notype_crash_test.sh`](run_dag_update_del_exact_ttl_notype_crash_test.sh) | `dag` (`tools/dag.c`) | RFC 2136 §2.5.4 | **Boundary / Negative** | `dag` client crash resistance when parsing update delete commands with exact TTL and omitted type. |
| 146 | [`run_dag_update_del_no_type_test.sh`](run_dag_update_del_no_type_test.sh) | `dag` (`tools/dag.c`) | RFC 2136 §2.5.2 | **Positive** | CLASS=ANY whole-domain record deletion updates. |
| 147 | [`run_dag_yaml_apostrophe_escaping_test.sh`](run_dag_yaml_apostrophe_escaping_test.sh) | `dag` (`tools/dag_output_yaml.c`) | YAML 1.2 | **Positive / Escaping** | Escaping single quotes in TXT/RDATA strings within YAML output. |
| 148 | [`run_dag_yaml_cookie_status_test.sh`](run_dag_yaml_cookie_status_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 7873 | **Positive** | YAML representation of DNS cookie status (`OK`, `BADCOOKIE`, `MISSING`). |
| 149 | [`run_dag_yaml_ede_escaping_test.sh`](run_dag_yaml_ede_escaping_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 8914 §2 | **Boundary / Security** | YAML string escaping for arbitrary binary/special characters inside EDE extra-text fields. |
| 150 | [`run_dag_yaml_edns_options_test.sh`](run_dag_yaml_edns_options_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 6891, RFC 7871, RFC 8914 | **Positive** | Structured YAML serialization of NSID, Cookie, ECS, EDE, Padding, and Keepalive options. |
| 151 | [`run_dag_yaml_expandaaaa_test.sh`](run_dag_yaml_expandaaaa_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 5952 | **Positive** | `+yaml +expandaaaa` rendering uncompressed 32-character IPv6 hex addresses. |
| 152 | [`run_dag_yaml_no_spurious_resolve_error_test.sh`](run_dag_yaml_no_spurious_resolve_error_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Error Formatting | **Positive** | Suppression of false resolve errors on legitimate NODATA (empty answer) responses. |
| 153 | [`run_dag_yaml_nocrypto_test.sh`](run_dag_yaml_nocrypto_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Security Redaction | **Positive** | `+yaml +nocrypto` redacting cryptographic key materials and signatures. |
| 154 | [`run_dag_yaml_rdata_test.sh`](run_dag_yaml_rdata_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Structured Output | **Positive** | YAML output: decoded `rdata:` fields and section contents for the standard RR types. |
| 155 | [`run_dag_yaml_rrsig_decode_test.sh`](run_dag_yaml_rrsig_decode_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 4034 §3.1 | **Positive** | Decoding RRSIG inception and expiration timestamps into human-readable ISO dates. |
| 156 | [`run_dag_yaml_socket_family_force_test.sh`](run_dag_yaml_socket_family_force_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Socket Telemetry | **Positive** | Verifying socket family forcing and telemetry in YAML outputs. |
| 157 | [`run_dag_yaml_socket_family_test.sh`](run_dag_yaml_socket_family_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Socket Telemetry | **Positive** | Transport family telemetry reporting in YAML statistics section. |

---

### 3.12 Regression, Stress & Fuzzing - Category: `regression`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 158 | [`run_sanitizer_smoke_test.sh`](run_sanitizer_smoke_test.sh) | All core binaries & parsers | ASan / UBSan | **Sanitizer Smoke** | Running core smoke queries against binaries compiled with `-fsanitize=address,undefined`. |
| 159 | [`run_stress_test.sh`](run_stress_test.sh) | `dns_server_core.c`, `dns_snapshot_rcu.c` | Concurrency Stress | **Standalone Benchmark** | High-throughput concurrent query flood (dnsperf 60s); run manually outside automated suite. |
| 160 | [`run_fuzz_smoke_test.sh`](run_fuzz_smoke_test.sh) | `tests/fuzz/` (all 10 harnesses) | LLVM libFuzzer | **Fuzzing Smoke** | Crash-resistance verification across wire, config, zone, TSIG, and server core fuzzers. |
| 161 | [`run_break_duplicate_kind_override_test.sh`](run_break_duplicate_kind_override_test.sh) | `dag` (`tools/dag_edns_client.c`) | dag `--break` | **Positive** | Giving the same `--break` kind several times: the last parameter wins and a note is printed. |
| 163 | [`run_rcu_tsan_test.sh`](run_rcu_tsan_test.sh) | `dns_epoch_rcu.c`, `dns_snapshot_rcu.c`, `dns_server_core.c`, `dns_dynamic_update.c`, `dns_axfr_ixfr.c`, `dns_catalog_zone.c` | Epoch RCU (R-25) | **Concurrency / TSan** | Builds `karidns-tsan` and `test_epoch_rcu-tsan`. Part 1: the unit test under TSan. Part 2: `karidns-tsan` primary; UDP and TCP (connection reuse) queries from 4 clients concurrently with SIGHUP reloads (config swap, snapshot rebuild, zone reload, Pass 2 prelink), dynamic UPDATEs and AXFRs. Part 3: `karidns-tsan` secondary of a `karidns` primary with a catalog zone; queries concurrently with UPDATE-triggered NOTIFY/IXFR, catalog membership changes and SIGHUP reloads of the secondary. Fails on any ThreadSanitizer report, if a server exits, stops answering, or the last UPDATE does not reach the secondary. Load is adjustable with `CLIENTS`, `ROUNDS`, `HUPS`, `UPDATES`. |
| 164 | [`run_bind_differential_test.sh`](run_bind_differential_test.sh) | `dns_query_engine.c` (`resolve_name`) | RFC 4592 §2.2, RFC 1034 §4.3.2 | **Differential (BIND oracle)** | Serves `tests/matrix/zones/wildcard.zone` from KariDNS and from BIND `named` on two ports and compares the RCODE and the sorted answer RDATA of wildcard, wildcard-under-subdomain, exact-match, empty-non-terminal and NXDOMAIN-below-existing-name queries. Fails if either server does not answer, if `named` returns no status line, or on any difference. SKIP when `named` is not installed. |

---

### 3.13 Built and Run Outside `run_all_suite.sh`

These targets are not registered in `tests/run_all_suite.sh`: `test_dag_iter` runs with `make unit-tests` (`make dag_iter_test`), and the libFuzzer harnesses run with `make fuzz_dag_all` / `sh tests/run_fuzz_smoke_test.sh dag`.

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| E1 | [`test_dag_iter`](test_dag_iter.c) | `tools/dag_iter.c`, `tools/dag_roothints.c` | RFC 1034 §5.3.3, RFC 2181 §5.4.1, RFC 6672, RFC 9156 | **Positive / Negative / Robustness** | `+trace2` response classification (referral, answer, CNAME/DNAME, NXDOMAIN, NODATA, lame, bogus), bailiwick filtering of glue, truncated-packet sweep, named.root parsing and CLI option parsing. |
| E2 | [`fuzz_dag_iter_classify`](fuzz/fuzz_dag_iter_classify.c) | `tools/dag_iter.c`, `tools/dag_roothints.c` | RFC 1035, RFC 2181 §5.4.1 | **Fuzz / Robustness** | libFuzzer harness: untrusted nameserver responses through `dag_iter_classify()` (question-matched, fuzzer-chosen zone cut) and named.root text through `roothints_parse_text()`; checks NUL-termination and array bounds of the classification result. |

---

## 4. Execution & Coverage Measurement Guide

### 4.1 Running Tests

```bash
# 1. Run full test suite with formatted summary report
sh tests/run_all_suite.sh

# 2. Run specific category
sh tests/run_all_suite.sh --category unit
sh tests/run_all_suite.sh --category xfr,dnssec,update

# 3. Filter by test name
sh tests/run_all_suite.sh --filter axfr

# 4. Skip tests whose name contains any of the given substrings
sh tests/run_all_suite.sh --exclude run_stress_test,run_fuzz_smoke_test

# 5. Quick mode (fast unit and core tests only)
sh tests/run_all_suite.sh --quick

# 6. Skip the dag category
sh tests/run_all_suite.sh --no-dag

# 7. Stop immediately on first failure / print test output in real time
sh tests/run_all_suite.sh --stop-on-failure
sh tests/run_all_suite.sh --verbose

# 8. List all registered tests
sh tests/run_all_suite.sh --list
```

Integration tests that need loopback aliases (127.0.0.2 and up) add them when run as root and report SKIP otherwise.

Tests stop only the servers they started, so other karidns instances on the host (another working copy, a long-running server) survive a suite run. Test scripts source [`tests/lib_proc.sh`](lib_proc.sh) and use `kari_kill_tree "$SERVER_PID"` (the karidns supervisor and its backend/router/broker children) or `kari_kill_conf <test-specific config path>`; do not use `killall` or an unscoped `pkill`/`pgrep`. `run_all_suite.sh` records the karidns processes that exist when it starts and its stale-process cleanup leaves those alone.

Unit test binaries can also be built and run from the Makefile: `make unit-tests` (all), `make <name>_test` (one), and `make unit-tests-asan` / `make test_<name>-asan` for ASan/UBSan builds.

### 4.2 Measuring Code Coverage with Clang

KariDNS supports Clang source-based code coverage (`-fprofile-instr-generate -fcoverage-mapping`):

```bash
# Clean, instrument build, execute test suite, and generate HTML report
make coverage

# Individual coverage steps:
make coverage-clean   # Remove previous raw and HTML coverage files
make coverage-build   # Compile all targets with instrumentation
make coverage-run     # Run tests/run_all_suite.sh (excluding COV_SUITE_EXCLUDE) and the fuzz corpora with LLVM_PROFILE_FILE
make coverage-report  # Merge .profraw files, generate coverage_html/ and run tests/coverage_gate.pl
```

HTML coverage reports with line and branch-level precision will be written to `coverage_html/index.html`. `coverage-run` needs root for the integration tests that use loopback aliases. The CI job "Coverage gate" checks the per-tier thresholds with `perl tests/coverage_gate.pl --phase=2 --strict`; the latest measured values are in [`docs/COVERAGE_STATUS.md`](../docs/COVERAGE_STATUS.md).

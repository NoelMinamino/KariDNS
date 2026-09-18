# KariDNS Test Suite Matrix & RFC Traceability Document

This document provides a comprehensive traceability matrix mapping every test in the KariDNS test suite (~112 test targets comprising C unit test binaries, integration shell scripts, sanitizer tests, and fuzzing harnesses) to its corresponding **IETF RFC / Technical Specification**, target **KariDNS Component**, and **Test Classification** (Positive, Negative, Boundary, Concurrency/RCU, Memory/ASan, Fuzzing).

It directly cross-references the implementation status documented in [`KariDNS_RFC_GUIDELINE.md`](file:///c:/git/my_dns/KariDNS_RFC_GUIDELINE.md).

---

## 1. Test Suite Architecture & Organization

The KariDNS automated test suite is managed via the unified runner script [`tests/run_all_suite.sh`](file:///c:/git/my_dns/tests/run_all_suite.sh) and the project [`Makefile`](file:///c:/git/my_dns/Makefile).

To avoid duplicate test execution (二重起動), the comprehensive diagnostic client suite [`tests/run_dag_ci_test.sh`](file:///c:/git/my_dns/tests/run_dag_ci_test.sh) acts as the umbrella runner for dag-related sub-tests (running sections 1-19 and 55 parallel sub-tests), while [`tests/run_all_suite.sh`](file:///c:/git/my_dns/tests/run_all_suite.sh) registers the distinct top-level test suites.

### 1.1 Test Category Distribution in `run_all_sui| Category Code | Category Name | Target Domain | Top-Level Count | Primary Execution Method |
|:---|:---|:---|:---:|:---|
| `unit` | **Unit Tests** | C unit tests compiled with ASan/UBSan | 13 | Native binary execution |
| `xfr` | **Zone Transfer** | RFC 5936 AXFR, RFC 1995 IXFR, Extended AXFR, Capsicum | 6 | Shell script + multi-instance KariDNS |
| `dnssec` | **DNSSEC & Digest** | RFC 4034/4035 DNSSEC serving, RFC 8976 ZONEMD | 3 | Shell script + `karicheck` |
| `update` | **Dynamic Update** | RFC 2136 DNS UPDATE prerequisites & updates | 3 | Shell script + `dag` UPDATE |
| `edns` | **EDNS & Extensions** | RFC 7871 ECS split-horizon, RFC 10029 Multi-QTYPE, RFC 9619 | 2 | Shell script + `dag` |
| `rrl` | **Anti-DoS & RRL** | Response Rate Limiting (RRL), SLIP truncation, Log throttling | 3 | Shell script + high-rate UDP client |
| `catalog` | **Catalog Zones** | RFC 9432 DNS Catalog Zones, Change of Ownership (CoO) | 2 | Shell script + multi-zone provisioning |
| `dnstap` | **DNSTAP Logging** | Frame Streams / Protobuf logging | 1 | Shell script + mock receiver |
| `tinydns` | **tinydns Format** | djbdns data format, %location split-horizon, Tai64n TTL | 2 | Shell script + `karidns` |
| `core` | **Server Core Engine** | RFC 1034/1035 resolution, section order, forward, program, glue, RCU reload | 24 | Shell script + `karidns` / `karictl` / `karicheck` |
| `regression` | **Regression & Fuzz** | ASan/UBSan smoke, concurrency stress, libFuzzer harnesses | 3 | Shell script + libFuzzer / ASan binaries |
| `dag` | **Diagnostic Tool** | `run_dag_ci_test.sh` (Part 1-19 + 55 parallel sub-tests) + batch opts + dag fuzzer | 3 | Master runner + parallel workers (Included by default; skip with `--no-dag`) |
| **Total Runner Entries** | | | **65** | *(62 server engine tests + 3 dag diagnostic client entries = 65 integrated targets)* |

---

## 2. RFC Cross-Reference Index

This table maps RFC standards recognized in [`KariDNS_RFC_GUIDELINE.md`](file:///c:/git/my_dns/KariDNS_RFC_GUIDELINE.md) directly to the specific automated test cases that validate their behavior.

| RFC / Standard | Specification Title | KariDNS Implementation Evidence | Validating Test Scripts / Binaries |
|:---|:---|:---|:---|
| **RFC 1034** | Domain Names - Concepts and Facilities | `dns_query_engine.c`, `dns_server_core.c` | [`tests/test_response_cache.c`](file:///c:/git/my_dns/tests/test_response_cache.c), [`tests/test_query_engine_expanded.c`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c), [`tests/run_sibling_additional_test.sh`](file:///c:/git/my_dns/tests/run_sibling_additional_test.sh), [`tests/run_zone_type_secondary_test.sh`](file:///c:/git/my_dns/tests/run_zone_type_secondary_test.sh) |
| **RFC 1035** | Domain Names - Implementation and Specification | `dns_wire.c`, `dns_zone_parser.c` | [`tests/test_asan_overflow.c`](file:///c:/git/my_dns/tests/test_asan_overflow.c), [`tests/test_query_engine_expanded.c`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c), [`tests/run_domain_length_rfc1035_test.sh`](file:///c:/git/my_dns/tests/run_domain_length_rfc1035_test.sh), [`tests/run_response_section_order_test.sh`](file:///c:/git/my_dns/tests/run_response_section_order_test.sh), [`tests/run_roundtrip_test.sh`](file:///c:/git/my_dns/tests/run_roundtrip_test.sh), [`tests/run_paren_check_test.sh`](file:///c:/git/my_dns/tests/run_paren_check_test.sh), [`tests/run_malformed_detection_default_test.sh`](file:///c:/git/my_dns/tests/run_malformed_detection_default_test.sh) |
| **RFC 1912** | Common DNS Operational & Configuration Errors | `tools/karicheck.c` | [`tests/run_karicheck_semantic_lint_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_semantic_lint_test.sh) |
| **RFC 1982** | Serial Number Arithmetic | `dns_server_core.c`, `dns_axfr_ixfr.c`, `dns_dynamic_update.c` | [`tests/test_dynamic_update_engine.c`](file:///c:/git/my_dns/tests/test_dynamic_update_engine.c), [`tests/test_axfr_ixfr_engine.c`](file:///c:/git/my_dns/tests/test_axfr_ixfr_engine.c), [`tests/run_ixfr_roundtrip_test.sh`](file:///c:/git/my_dns/tests/run_ixfr_roundtrip_test.sh), [`tests/run_extended_axfr_test.sh`](file:///c:/git/my_dns/tests/run_extended_axfr_test.sh) |
| **RFC 1995** | Incremental Zone Transfer (IXFR) | `dns_axfr_ixfr.c`, `dns_server_core.c` | [`tests/test_axfr_ixfr_engine.c`](file:///c:/git/my_dns/tests/test_axfr_ixfr_engine.c), [`tests/run_ixfr_roundtrip_test.sh`](file:///c:/git/my_dns/tests/run_ixfr_roundtrip_test.sh), [`tests/run_udp_ixfr_test.sh`](file:///c:/git/my_dns/tests/run_udp_ixfr_test.sh), [`tests/run_dag_ixfr_uptodate_test.sh`](file:///c:/git/my_dns/tests/run_dag_ixfr_uptodate_test.sh) |
| **RFC 1996** | Prompt Notification of Zone Changes (NOTIFY) | `dns_server_core.c`, `dns_dynamic_update.c`, `dns_tsig_acl.c` | [`tests/test_dynamic_update_engine.c`](file:///c:/git/my_dns/tests/test_dynamic_update_engine.c), [`tests/run_notify_source_test.sh`](file:///c:/git/my_dns/tests/run_notify_source_test.sh), [`tests/run_zone_type_secondary_test.sh`](file:///c:/git/my_dns/tests/run_zone_type_secondary_test.sh) |
| **RFC 2136** | Dynamic Updates in the DNS (DNS UPDATE) | `dns_dynamic_update.c`, `dns_epoch_rcu.c` | [`tests/test_dynamic_update_engine.c`](file:///c:/git/my_dns/tests/test_dynamic_update_engine.c), [`tests/test_vulnerability_fixes.c`](file:///c:/git/my_dns/tests/test_vulnerability_fixes.c), [`tests/run_dynamic_update_test.sh`](file:///c:/git/my_dns/tests/run_dynamic_update_test.sh), [`tests/run_update_slave_notauth_test.sh`](file:///c:/git/my_dns/tests/run_update_slave_notauth_test.sh), [`tests/run_dag_update_del_no_type_test.sh`](file:///c:/git/my_dns/tests/run_dag_update_del_no_type_test.sh), [`tests/run_dag_update_del_exact_ttl_notype_crash_test.sh`](file:///c:/git/my_dns/tests/run_dag_update_del_exact_ttl_notype_crash_test.sh) |
| **RFC 2181** | Clarifications to the DNS Specification | `dns_wire.c`, `dns_query_engine.c` | [`tests/run_ttl_rfc2181_clamp_test.sh`](file:///c:/git/my_dns/tests/run_ttl_rfc2181_clamp_test.sh), [`tests/run_ttl_harmonization_test.sh`](file:///c:/git/my_dns/tests/run_ttl_harmonization_test.sh), [`tests/run_ttl_harmonization_update_test.sh`](file:///c:/git/my_dns/tests/run_ttl_harmonization_update_test.sh) |
| **RFC 2782** | Location of Services (SRV) | `dns_wire.c`, `dns_query_engine.c` | [`tests/test_query_engine_expanded.c`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c), [`tests/run_mx_srv_glue_test.sh`](file:///c:/git/my_dns/tests/run_mx_srv_glue_test.sh) |
| **RFC 2931 / 3007** | DNS Request and Transaction Signatures (SIG(0)) | `tools/dag_tsig_client.c`, `dns_wire.c` | [`tests/run_dag_sig0_update_test.sh`](file:///c:/git/my_dns/tests/run_dag_sig0_update_test.sh) |
| **RFC 3123** | Lists of Address Prefixes (APL RR) | `dns_wire.c`, `tools/dag_output_yaml.c` | [`tests/test_query_engine_expanded.c`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c), [`tests/run_dag_apl_afdlength_overflow_test.sh`](file:///c:/git/my_dns/tests/run_dag_apl_afdlength_overflow_test.sh) |
| **RFC 3597** | Handling of Unknown DNS RR Types (`TYPE<n>`, `\#`) | `dns_utils.c`, `dns_wire.c` | [`tests/test_asan_overflow.c`](file:///c:/git/my_dns/tests/test_asan_overflow.c), [`tests/run_dag_ci_test.sh`](file:///c:/git/my_dns/tests/run_dag_ci_test.sh) |
| **RFC 4034 / 4035** | DNSSEC Protocol & Resource Records (Static Serving) | `dns_query_engine.c`, `dns_wire.c` | [`tests/test_query_engine_expanded.c`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c), [`tests/run_dnssec_negative_soa_rrsig_test.sh`](file:///c:/git/my_dns/tests/run_dnssec_negative_soa_rrsig_test.sh), [`tests/run_ds_delegation_test.sh`](file:///c:/git/my_dns/tests/run_ds_delegation_test.sh), [`tests/run_dag_yaml_rrsig_decode_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_rrsig_decode_test.sh) |
| **RFC 5452** | Measures for Making DNS Resilient against Forged Answers | `dns_server_core.c`, `tools/dag_transport.c` | [`tests/run_dag_udp_id_mismatch_discard_test.sh`](file:///c:/git/my_dns/tests/run_dag_udp_id_mismatch_discard_test.sh), [`tests/run_dag_udp_spoofing_source_test.sh`](file:///c:/git/my_dns/tests/run_dag_udp_spoofing_source_test.sh), [`tests/run_forward_zone_test.sh`](file:///c:/git/my_dns/tests/run_forward_zone_test.sh) |
| **RFC 5936** | DNS Zone Transfer Protocol (AXFR) | `dns_axfr_ixfr.c`, `dns_priv_sandbox.c` | [`tests/test_axfr_ixfr_engine.c`](file:///c:/git/my_dns/tests/test_axfr_ixfr_engine.c), [`tests/run_capsicum_axfr_test.sh`](file:///c:/git/my_dns/tests/run_capsicum_axfr_test.sh), [`tests/run_extended_axfr_test.sh`](file:///c:/git/my_dns/tests/run_extended_axfr_test.sh), [`tests/run_axfr_multikey_tsig_test.sh`](file:///c:/git/my_dns/tests/run_axfr_multikey_tsig_test.sh), [`tests/run_dag_doh_dot_axfr_test.sh`](file:///c:/git/my_dns/tests/run_dag_doh_dot_axfr_test.sh) |
| **RFC 6672** | DNAME Redirection in the DNS | `dns_query_engine.c`, `dns_wire.c` | [`tests/test_query_engine_expanded.c`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c) |
| **RFC 6891** | Extension Mechanisms for DNS (EDNS(0)) | `dns_wire.c`, `dns_edns_ecs.c`, `tools/dag_edns_client.c` | [`tests/test_edns_ecs_engine.c`](file:///c:/git/my_dns/tests/test_edns_ecs_engine.c), [`tests/run_dag_yaml_edns_options_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_edns_options_test.sh), [`tests/run_dag_ci_test.sh`](file:///c:/git/my_dns/tests/run_dag_ci_test.sh) |
| **RFC 7050** | Discovery of IPv6 Prefix (DNS64) | `tools/dag.c`, `tools/dag_output_yaml.c` | [`tests/run_dag_dns64prefix_test.sh`](file:///c:/git/my_dns/tests/run_dag_dns64prefix_test.sh), [`tests/run_dag_dns64prefix_short_yaml_test.sh`](file:///c:/git/my_dns/tests/run_dag_dns64prefix_short_yaml_test.sh) |
| **RFC 7766 / 9210** | DNS Transport over TCP (Connection Reuse / Keepopen) | `dns_server_core.c`, `tools/dag_transport.c` | [`tests/run_dag_keepopen_keepalive_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_keepalive_test.sh), [`tests/run_dag_keepopen_partial_read_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_partial_read_test.sh), [`tests/run_dag_keepopen_tls_partial_read_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_tls_partial_read_test.sh) |
| **RFC 7858** | DNS over TLS (DoT - Client `dag`) | `tools/dag_transport.c` | [`tests/run_dag_doh_dot_axfr_test.sh`](file:///c:/git/my_dns/tests/run_dag_doh_dot_axfr_test.sh), [`tests/run_dag_keepopen_tls_partial_read_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_tls_partial_read_test.sh) |
| **RFC 7871** | Client Subnet in DNS Queries (ECS) | `dns_edns_ecs.c`, `dns_wire.c` | [`tests/test_edns_ecs_engine.c`](file:///c:/git/my_dns/tests/test_edns_ecs_engine.c), [`tests/run_bind_ecs_subnet_test.sh`](file:///c:/git/my_dns/tests/run_bind_ecs_subnet_test.sh), [`tests/run_dag_yaml_edns_options_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_edns_options_test.sh) |
| **RFC 7873 / 9018** | DNS Cookies & Interoperable Server Cookies | `dns_wire.c`, `dns_edns_ecs.c`, `dns_server_core.c` | [`tests/test_edns_ecs_engine.c`](file:///c:/git/my_dns/tests/test_edns_ecs_engine.c), [`tests/run_dag_badcookie_transport_test.sh`](file:///c:/git/my_dns/tests/run_dag_badcookie_transport_test.sh), [`tests/run_dag_cookie_mismatch_discard_test.sh`](file:///c:/git/my_dns/tests/run_dag_cookie_mismatch_discard_test.sh), [`tests/run_dag_yaml_cookie_status_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_cookie_status_test.sh) |
| **RFC 8482** | Minimal ANY Responses | `dns_query_engine.c` | [`tests/test_vulnerability_fixes.c`](file:///c:/git/my_dns/tests/test_vulnerability_fixes.c), [`tests/run_dag_ci_test.sh`](file:///c:/git/my_dns/tests/run_dag_ci_test.sh) |
| **RFC 8484** | DNS over HTTPS (DoH - Client `dag`) | `tools/dag_transport.c` | [`tests/run_dag_doh_dot_axfr_test.sh`](file:///c:/git/my_dns/tests/run_dag_doh_dot_axfr_test.sh), [`tests/run_dag_doh_cache_cleanup_test.sh`](file:///c:/git/my_dns/tests/run_dag_doh_cache_cleanup_test.sh), [`tests/run_dag_audit_improvements_test.sh`](file:///c:/git/my_dns/tests/run_dag_audit_improvements_test.sh) |
| **RFC 8624** | DNSSEC Algorithm Implementation Requirements | `tools/karicheck.c` | [`tests/run_karicheck_semantic_lint_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_semantic_lint_test.sh) |
| **RFC 8914** | Extended DNS Errors (EDE) | `dns_wire.c`, `dns_edns_ecs.c`, `tools/dag_edns_client.c` | [`tests/test_edns_ecs_engine.c`](file:///c:/git/my_dns/tests/test_edns_ecs_engine.c), [`tests/run_dag_ede_truncation_regression_test.sh`](file:///c:/git/my_dns/tests/run_dag_ede_truncation_regression_test.sh), [`tests/run_dag_yaml_ede_escaping_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_ede_escaping_test.sh) |
| **RFC 8945** | Secret Key Transaction Authentication (TSIG) | `dns_tsig_acl.c`, `dns_wire.c` | [`tests/test_vulnerability_fixes.c`](file:///c:/git/my_dns/tests/test_vulnerability_fixes.c), [`tests/run_axfr_multikey_tsig_test.sh`](file:///c:/git/my_dns/tests/run_axfr_multikey_tsig_test.sh), [`tests/run_dag_axfr_tsig_unsigned_intermediate_test.sh`](file:///c:/git/my_dns/tests/run_dag_axfr_tsig_unsigned_intermediate_test.sh) |
| **RFC 8976** | Message Digest for DNS Zones (ZONEMD) | `tools/karicheck.c`, `dns_wire.c` | [`tests/run_zonemd_val_test.sh`](file:///c:/git/my_dns/tests/run_zonemd_val_test.sh) |
| **RFC 9276** | Guidance for NSEC3 Parameter Settings | `tools/karicheck.c` | [`tests/run_karicheck_semantic_lint_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_semantic_lint_test.sh) |
| **RFC 9432** | DNS Catalog Zones | `dns_catalog_zone.c`, `dns_snapshot_rcu.c` | [`tests/run_catalog_zone_test.sh`](file:///c:/git/my_dns/tests/run_catalog_zone_test.sh), [`tests/run_cve_coo_test.sh`](file:///c:/git/my_dns/tests/run_cve_coo_test.sh) |
| **RFC 9471** | DNS Glue Requirements in Referrals | `dns_query_engine.c`, `tools/karicheck.c` | [`tests/run_karicheck_glue_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_glue_test.sh), [`tests/run_sibling_additional_test.sh`](file:///c:/git/my_dns/tests/run_sibling_additional_test.sh), [`tests/run_mx_srv_glue_test.sh`](file:///c:/git/my_dns/tests/run_mx_srv_glue_test.sh) |
| **RFC 9619** | QDCOUNT Is (Usually) One | `dns_server_core.c` | [`tests/run_mqtype_qdcount0_test.sh`](file:///c:/git/my_dns/tests/run_mqtype_qdcount0_test.sh) |
| **RFC 9824** | Compact Denial of Existence in DNSSEC (NXNAME) | `tools/karicheck.c`, `dns_utils.c` | [`tests/run_karicheck_semantic_lint_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_semantic_lint_test.sh) |
| **RFC 10029** | DNS Multiple QTYPEs (MQTYPE) | `dns_wire.c`, `dns_query_engine.c` | [`tests/run_mqtype_qdcount0_test.sh`](file:///c:/git/my_dns/tests/run_mqtype_qdcount0_test.sh), [`tests/run_dag_ci_test.sh`](file:///c:/git/my_dns/tests/run_dag_ci_test.sh) |
| **RRL Draft** | DNS Response Rate Limiting | `dns_rrl.c`, `dns_server_core.c` | [`tests/test_rrl_engine.c`](file:///c:/git/my_dns/tests/test_rrl_engine.c), [`tests/run_rrl_window_test.sh`](file:///c:/git/my_dns/tests/run_rrl_window_test.sh), [`tests/bench_rrl.c`](file:///c:/git/my_dns/tests/bench_rrl.c) |
| **DNSTAP** | DNS Telemetry & Frame Streams | `dns_dnstap.c`, `dns_wire.c` | [`tests/test_dnstap_engine.c`](file:///c:/git/my_dns/tests/test_dnstap_engine.c), [`tests/run_dnstap_capture_test.sh`](file:///c:/git/my_dns/tests/run_dnstap_capture_test.sh) |
| **FreeBSD Capsicum** | Capability Mode Sandboxing | `dns_priv_sandbox.c` | [`tests/run_capsicum_axfr_test.sh`](file:///c:/git/my_dns/tests/run_capsicum_axfr_test.sh), [`tests/test_vulnerability_fixes.c`](file:///c:/git/my_dns/tests/test_vulnerability_fixes.c) |

---

## 3. Exhaustive Test Inventory (118 Tests)

The complete inventory of all test targets registered in `tests/run_all_suite.sh`:

### 3.1 Unit Tests (C Binaries) - Category: `unit`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|:---|
| 1 | [`test_vulnerability_fixes`](file:///c:/git/my_dns/tests/test_vulnerability_fixes.c) | `dns_query_engine.c`, `dns_snapshot_rcu.c`, `dns_epoch_rcu.c`, `dns_wire.c`, `dns_dynamic_update.c`, `dns_axfr_ixfr.c` | RFC 2136 §3.2.5, RFC 8482, RFC 8945, Capsicum | **Positive / Negative / Concurrency** | Validates NOTZONE rejection on out-of-zone updates, minimal ANY in DNSSEC zones, TSIG ID mismatch defenses, Capsicum capability rights, and multithreaded Epoch RCU lifecycle safety. |
| 2 | [`test_query_engine_expanded`](file:///c:/git/my_dns/tests/test_query_engine_expanded.c) | `dns_query_engine.c`, `dns_wire.c`, `dns_zone_parser.c` | RFC 1034, RFC 1035, RFC 6672, RFC 4034/4035 | **Positive / Negative** | Validates all supported DNS RR types (A, AAAA, NS, SOA, MX, TXT, CAA, PTR, SRV, NAPTR, SSHFP, TLSA, DS, DNSKEY, RRSIG, NSEC, NSEC3, SVCB, HTTPS, APL, LOC, ZONEMD), wildcard expansions (*.wild), RFC 6672 DNAME synthesis, ANY queries, negative responses (NODATA, NXDOMAIN, REFUSED), and 0x20 bit casing preservation. |
| 3 | [`test_response_cache`](file:///c:/git/my_dns/tests/test_response_cache.c) | `dns_query_engine.c`, `dns_snapshot_rcu.c`, `dns_wire.c` | RFC 1034, RFC 2181 | **Positive / Concurrency** | Lock-free response cache lookups, atomic LRU eviction, TTL decrement calculations, and cache invalidation upon dynamic updates. |
| 4 | [`test_dnstap_engine`](file:///c:/git/my_dns/tests/test_dnstap_engine.c) | `dns_dnstap.c`, `dns_wire.c` | DNSTAP Protobuf Specification | **Positive / Negative / Concurrency** | Validates Protobuf varint, fixed32, and bytes field encoders, DNSTAP AUTH_QUERY and AUTH_RESPONSE payload packing, Frame Streams handshake protocol, wire buffer truncation tracking, and SPSC/MPSC event ring buffers. |
| 5 | [`test_edns_ecs_engine`](file:///c:/git/my_dns/tests/test_edns_ecs_engine.c) | `dns_edns_ecs.c`, `dns_wire.c`, `dns_cidr.c` | RFC 7871, RFC 7873/9018, RFC 8914, tinydns %loc | **Positive / Negative** | Validates HMAC-SHA256 Server Cookie generation/verification, Extended DNS Error (EDE) packing & statistics, $ECS-SUBNET tag definition binary serialization/unserialization, and IPv4/IPv6 Longest Prefix Match routing. |
| 6 | [`test_dynamic_update_engine`](file:///c:/git/my_dns/tests/test_dynamic_update_engine.c) | `dns_dynamic_update.c`, `dns_wire.c`, `dns_snapshot_rcu.c` | RFC 2136, RFC 1982, RFC 1996 | **Positive / Negative** | Validates SOA serial number arithmetic bumping, wrap-around handling, RFC 1996 NOTIFY message wire construction, destination deduplication, and update section Add/Delete processing. |
| 7 | [`test_axfr_ixfr_engine`](file:///c:/git/my_dns/tests/test_axfr_ixfr_engine.c) | `dns_axfr_ixfr.c`, `dns_wire.c`, `dns_snapshot_rcu.c` | RFC 1995, RFC 5936, Option 65153 | **Positive / Negative** | Validates IXFR difference computation between zone arena snapshots, transaction history ring rotation and memory lifecycle, XFR wire packet parsing, and EDNS Option 65153 (Extended AXFR) hash negotiation. |
| 8 | [`test_rrl_engine`](file:///c:/git/my_dns/tests/test_rrl_engine.c) | `dns_rrl.c`, `dns_config_parser.c` | Response Rate Limiting (RRL) | **Positive / Negative / Anti-DoS** | Validates SipHash-2-4 hash calculation, response classification (NOERROR, NODATA, NXDOMAIN, ERROR), token bucket leak rates, IPv4 /24 and IPv6 /56 subnet aggregation, and SLIP (TC=1) truncation. |
| 9 | [`test_asan_overflow`](file:///c:/git/my_dns/tests/test_asan_overflow.c) | `dns_wire.c`, `dns_zone_parser.c`, `dns_tinydns_parser.c`, `dns_cidr.c`, `dns_tsig_acl.c` | RFC 1035, RFC 3597 | **Negative / Memory (ASan)** | Boundary overflow defense on corrupt DNS packets, invalid CLASS tokens, non-numeric TTL overflows, and RFC 3597 unknown RDATA syntax under AddressSanitizer. |
| 10 | [`test_tinydns_parser`](file:///c:/git/my_dns/tests/test_tinydns_parser.c) | `dns_tinydns_parser.c`, `dns_zone_parser.c`, `dns_wire.c` | tinydns data format | **Positive / Negative** | Parsing djbdns data format record leading characters (`+`, `@`, `.`, `&`, `=`, `^`, `'`, `:`, `%`), TTL overrides, and syntax error recovery. |
| 11 | [`test_cidr`](file:///c:/git/my_dns/tests/test_cidr.c) | `dns_cidr.c`, `dns_tsig_acl.c` | RFC 4632, RFC 4291 | **Positive / Boundary** | Evaluates IPv4 and IPv6 bitmask calculations, prefix containment logic, and binary ACL matching rules. |
| 12 | [`test_conf_include`](file:///c:/git/my_dns/tests/test_conf_include.c) | `dns_config_parser.c` | BIND 9 config format | **Positive / Negative** | Nested `$INCLUDE` configuration parsing, detection of circular file dependencies, and token syntax error isolation. |
| 13 | [`test_hash_table`](file:///c:/git/my_dns/tests/test_hash_table.c) | Core hash routines | FNV-1a Hash | **Positive / Boundary** | Fixed-size hash table distribution, collision bucket resolution, and key deletion. |letion. |

---

### 3.2 Zone Transfer & Redundancy - Category: `xfr`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 8 | [`run_capsicum_axfr_test.sh`](file:///c:/git/my_dns/tests/run_capsicum_axfr_test.sh) | `dns_priv_sandbox.c`, `dns_axfr_ixfr.c`, `dns_server_core.c` | RFC 5936, Capsicum | **Positive / Security** | Inbound AXFR stream ingestion inside strict FreeBSD `cap_enter()` capability mode sandbox. |
| 9 | [`run_ixfr_roundtrip_test.sh`](file:///c:/git/my_dns/tests/run_ixfr_roundtrip_test.sh) | `dns_axfr_ixfr.c`, `dns_server_core.c` | RFC 1995 | **Positive** | RFC 1995 IXFR incremental difference roundtrip serialization and client playback. |
| 10 | [`run_extended_axfr_test.sh`](file:///c:/git/my_dns/tests/run_extended_axfr_test.sh) | `dns_axfr_ixfr.c`, `dns_wire.c`, `dns_server_core.c` | RFC 5936, Option 65153 | **Positive** | KariDNS Extended AXFR transfer stream over EDNS Option 65153 with chunk compression. |
| 11 | [`run_axfr_multikey_tsig_test.sh`](file:///c:/git/my_dns/tests/run_axfr_multikey_tsig_test.sh) | `dns_tsig_acl.c`, `dns_axfr_ixfr.c` | RFC 5936 §4.3, RFC 8945 | **Positive / Negative** | Multi-key TSIG authentication, proper key selection, and rogue key rejection during AXFR transfers. |
| 12 | [`run_udp_ixfr_test.sh`](file:///c:/git/my_dns/tests/run_udp_ixfr_test.sh) | `dns_axfr_ixfr.c`, `dns_server_core.c` | RFC 1995 §4.1 | **Positive** | UDP IXFR query processing when diff fits within single unfragmented UDP datagram. |
| 13 | [`run_dag_doh_dot_axfr_test.sh`](file:///c:/git/my_dns/tests/run_dag_doh_dot_axfr_test.sh) | `dag` (`tools/dag_axfr_client.c`) | RFC 5936, RFC 7858, RFC 8484 | **Positive / Transport** | Performing AXFR zone transfers over encrypted DoH and DoT transport channels. |
| 14 | [`run_dag_ixfr_uptodate_test.sh`](file:///c:/git/my_dns/tests/run_dag_ixfr_uptodate_test.sh) | `dag` (`tools/dag_axfr_client.c`) | RFC 1995 §4.2 | **Positive** | Handling IXFR response when client SOA serial is equal to current zone SOA (single SOA response). |
| 15 | [`run_dag_axfr_tsig_unsigned_intermediate_test.sh`](file:///c:/git/my_dns/tests/run_dag_axfr_tsig_unsigned_intermediate_test.sh) | `dag` (`tools/dag_tsig_client.c`) | RFC 8945 §5.3.1 | **Positive / Negative** | TSIG verification across multi-message AXFR streams where intermediate records omit TSIG. |
| 16 | [`run_zone_type_secondary_test.sh`](file:///c:/git/my_dns/tests/run_zone_type_secondary_test.sh) | `dns_server_core.c`, `dns_axfr_ixfr.c` | RFC 1034 §4.3.5, RFC 1996 | **Positive** | Secondary zone SOA refresh timer polling, retry timers, and expiry behavior. |

---

### 3.3 DNSSEC & Message Digests - Category: `dnssec`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 17 | [`run_zonemd_val_test.sh`](file:///c:/git/my_dns/tests/run_zonemd_val_test.sh) | `tools/karicheck.c`, `dns_wire.c` | RFC 8976, RFC 6840 | **Positive / Verification** | RFC 8976 ZONEMD digest computation verified against official test vectors (including `uri.arpa.`). |
| 18 | [`run_dnssec_negative_soa_rrsig_test.sh`](file:///c:/git/my_dns/tests/run_dnssec_negative_soa_rrsig_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 4035 §3.1.3 | **Positive** | Authority section SOA covering RRSIG inclusion in NXDOMAIN and NODATA negative responses. |
| 19 | [`run_ds_delegation_test.sh`](file:///c:/git/my_dns/tests/run_ds_delegation_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 4034 §5, RFC 4035 | **Positive** | Referral responses containing delegation DS RRset and covering RRSIG records. |
| 20 | [`run_dag_sig0_update_test.sh`](file:///c:/git/my_dns/tests/run_dag_sig0_update_test.sh) | `dag` (`tools/dag_tsig_client.c`) | RFC 2931, RFC 3007 | **Positive / Crypto** | SIG(0) public-key transaction signing and verification for dynamic update messages. |

---

### 3.4 Dynamic Update - Category: `update`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 21 | [`run_dynamic_update_test.sh`](file:///c:/git/my_dns/tests/run_dynamic_update_test.sh) | `dns_dynamic_update.c`, `dns_epoch_rcu.c` | RFC 2136 | **Positive / Negative** | RFC 2136 Prerequisites (YXDOMAIN, NXDOMAIN, YXRRSET, NXRRSET) and update sections. |
| 22 | [`run_update_slave_notauth_test.sh`](file:///c:/git/my_dns/tests/run_update_slave_notauth_test.sh) | `dns_dynamic_update.c`, `dns_server_core.c` | RFC 2136 §3.8 | **Negative** | Clean rejection of dynamic updates targeted at secondary/slave zones with NOTAUTH (RCODE 9). |
| 23 | [`run_ttl_harmonization_update_test.sh`](file:///c:/git/my_dns/tests/run_ttl_harmonization_update_test.sh) | `dns_dynamic_update.c`, `dns_query_engine.c` | RFC 2181 §5.2 | **Positive** | Enforcing RRset TTL harmonization when dynamically adding RRs with differing TTL values. |
| 24 | [`run_dag_update_del_exact_ttl_notype_crash_test.sh`](file:///c:/git/my_dns/tests/run_dag_update_del_exact_ttl_notype_crash_test.sh) | `dag` (`tools/dag.c`) | RFC 2136 §2.5.4 | **Boundary / Negative** | `dag` client crash resistance when parsing update delete commands with exact TTL and omitted type. |
| 25 | [`run_dag_update_del_no_type_test.sh`](file:///c:/git/my_dns/tests/run_dag_update_del_no_type_test.sh) | `dag` (`tools/dag.c`) | RFC 2136 §2.5.2 | **Positive** | CLASS=ANY whole-domain record deletion updates. |

---

### 3.5 EDNS, Cookies & Transport Extensions - Category: `edns`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 26 | [`run_bind_ecs_subnet_test.sh`](file:///c:/git/my_dns/tests/run_bind_ecs_subnet_test.sh) | `dns_edns_ecs.c`, `dns_query_engine.c` | RFC 7871 | **Positive / Steering** | Parsing ECS client prefix from trusted resolvers, `$ECS-SUBNET` routing, and SCOPE echo. |
| 27 | [`run_mqtype_qdcount0_test.sh`](file:///c:/git/my_dns/tests/run_mqtype_qdcount0_test.sh) | `dns_wire.c`, `dns_server_core.c` | RFC 10029, RFC 9619 | **Positive / Negative** | RFC 10029 Multi-QTYPE response aggregation; RFC 9619 QDCOUNT=0 minimal reply & QDCOUNT>1 FORMERR. |
| 28 | [`run_dag_badcookie_transport_test.sh`](file:///c:/git/my_dns/tests/run_dag_badcookie_transport_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 7873, RFC 9018 | **Positive / Recovery** | Automated client retry with extracted server cookie upon receiving BADCOOKIE response. |
| 29 | [`run_dag_cookie_mismatch_discard_test.sh`](file:///c:/git/my_dns/tests/run_dag_cookie_mismatch_discard_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 7873 §5.2.3 | **Negative** | Discarding spoofed server responses whose client cookie does not match the outgoing cookie. |
| 30 | [`run_dag_ede_truncation_regression_test.sh`](file:///c:/git/my_dns/tests/run_dag_ede_truncation_regression_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 8914, RFC 6891 | **Positive / Boundary** | Extended DNS Error (EDE) option parsing and truncation boundary safety. |
| 31 | [`run_dag_yaml_edns_options_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_edns_options_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 6891, RFC 7871, RFC 8914 | **Positive** | Structured YAML serialization of NSID, Cookie, ECS, EDE, Padding, and Keepalive options. |
| 32 | [`run_dag_yaml_cookie_status_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_cookie_status_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 7873 | **Positive** | YAML representation of DNS cookie status (`OK`, `BADCOOKIE`, `MISSING`). |
| 33 | [`run_dag_yaml_ede_escaping_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_ede_escaping_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 8914 §2 | **Boundary / Security** | YAML string escaping for arbitrary binary/special characters inside EDE extra-text fields. |

---

### 3.6 Response Rate Limiting (RRL) & Anti-DoS - Category: `rrl`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 34 | [`run_rrl_window_test.sh`](file:///c:/git/my_dns/tests/run_rrl_window_test.sh) | `dns_rrl.c`, `dns_server_core.c` | RRL Draft, RFC 5452 | **Positive / Anti-DoS** | Keyed hash bucket sliding window rate limiting and SLIP truncated (TC=1) response generation. |
| 35 | [`run_query_log_rate_limit_test.sh`](file:///c:/git/my_dns/tests/run_query_log_rate_limit_test.sh) | `dns_server_core.c` | Operational Practice | **Positive / Resource** | Query log ring buffer throttling to prevent disk I/O exhaustion under flood attack. |
| 36 | [`run_glue_truncation_test.sh`](file:///c:/git/my_dns/tests/run_glue_truncation_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 1035 §4.1.1, RFC 6891 | **Positive / Boundary** | Additional section glue truncation and TC bit setting when exceeding UDP buffer size. |

---

### 3.7 Catalog Zones - Category: `catalog`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 37 | [`run_catalog_zone_test.sh`](file:///c:/git/my_dns/tests/run_catalog_zone_test.sh) | `dns_catalog_zone.c`, `dns_snapshot_rcu.c` | RFC 9432 | **Positive / Dynamic** | Automated provisioning and de-provisioning of member zones via catalog zone updates. |
| 38 | [`run_cve_coo_test.sh`](file:///c:/git/my_dns/tests/run_cve_coo_test.sh) | `dns_catalog_zone.c`, `dns_snapshot_rcu.c` | RFC 9432 §4.3 | **Security / Negative** | Strict Change of Ownership (CoO) property validation preventing catalog member hijacking. |

---

### 3.8 tinydns Compatibility - Category: `tinydns`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 39 | [`run_tinydns_location_test.sh`](file:///c:/git/my_dns/tests/run_tinydns_location_test.sh) | `dns_tinydns_parser.c`, `dns_query_engine.c` | tinydns location format | **Positive / Geo** | 2-character location code split-horizon routing matching client IP subnets. |
| 40 | [`run_tinydns_timestamp_test.sh`](file:///c:/git/my_dns/tests/run_tinydns_timestamp_test.sh) | `dns_tinydns_parser.c`, `dns_query_engine.c` | Tai64n timestamp | **Positive / Expiry** | Automatic TTL countdown based on Tai64n timestamp and record suppression post-TTD. |

---

### 3.9 Server Core & Resolution - Category: `core`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 41 | [`run_paren_check_test.sh`](file:///c:/git/my_dns/tests/run_paren_check_test.sh) | `dns_zone_parser.c` | RFC 1035 §5.1 | **Positive** | Tokenizer support for multi-line parenthesized RR definitions (SOA, TXT, etc.). |
| 42 | [`run_ttl_suffix_test.sh`](file:///c:/git/my_dns/tests/run_ttl_suffix_test.sh) | `dns_zone_parser.c`, `dns_utils.c` | BIND 9 Syntax | **Positive** | Parsing time unit suffixes (`s`, `m`, `h`, `d`, `w`) across zone files and config. |
| 43 | [`run_roundtrip_test.sh`](file:///c:/git/my_dns/tests/run_roundtrip_test.sh) | `dns_zone_parser.c`, `dns_wire.c` | RFC 1035 §3.2 | **Positive** | Parity of text zone parser -> wire serialization -> wire parser roundtrip. |
| 44 | [`run_karicheck_glue_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_glue_test.sh) | `tools/karicheck.c` | RFC 1034 §4.2.2, RFC 9471 | **Positive / Lint** | `karicheck` detection and warning for missing in-bailiwick glue records. |
| 45 | [`run_karicheck_semantic_lint_test.sh`](file:///c:/git/my_dns/tests/run_karicheck_semantic_lint_test.sh) | `tools/karicheck.c` | RFC 1912, RFC 8624, RFC 9276 | **Positive / Lint** | Semantic linter checks for CNAME co-existence, deprecated DNSSEC algorithms, and NSEC3 params. |
| 46 | [`run_phase2_core_audit_test.sh`](file:///c:/git/my_dns/tests/run_phase2_core_audit_test.sh) | `dns_server_core.c`, `dns_query_engine.c` | RFC 1034/1035 | **Positive / Audit** | Phase 2 server core resolution pipeline architecture audit. |
| 47 | [`run_phase2_audit_part2_test.sh`](file:///c:/git/my_dns/tests/run_phase2_audit_part2_test.sh) | `dns_server_core.c`, `dns_wire.c` | RFC 1035 | **Boundary / Security** | Wire format boundary safety, compression pointer loops, and malformed label lengths. |
| 48 | [`run_response_section_order_test.sh`](file:///c:/git/my_dns/tests/run_response_section_order_test.sh) | `dns_query_engine.c`, `dns_wire.c` | RFC 1035 §4.1.2 | **Positive** | Canonical response section ordering: Question, Answer, Authority, Additional. |
| 49 | [`run_sibling_additional_test.sh`](file:///c:/git/my_dns/tests/run_sibling_additional_test.sh) | `dns_query_engine.c` | RFC 1034 §4.3.2 | **Positive** | Automatic inclusion of sibling domain glue records in the Additional section. |
| 50 | [`run_multi_instance_test.sh`](file:///c:/git/my_dns/tests/run_multi_instance_test.sh) | `dns_server_core.c`, `dns_priv_sandbox.c` | FreeBSD `SO_REUSEPORT` | **Concurrency** | Multi-process worker socket binding and port-sharing load distribution. |
| 51 | [`run_dnstap_capture_test.sh`](file:///c:/git/my_dns/tests/run_dnstap_capture_test.sh) | `dns_dnstap.c`, `dns_server_core.c` | Frame Streams / Protobuf | **Positive / Telemetry** | Asynchronous DNSTAP query/response logging over Unix domain sockets. |
| 52 | [`run_karictl_observatory_test.sh`](file:///c:/git/my_dns/tests/run_karictl_observatory_test.sh) | `tools/karictl.c`, `dns_server_core.c` | KariDNS IPC | **Positive / Management** | `karictl` observatory IPC querying real-time server latency histograms and cache stats. |
| 53 | [`run_karictl_reload_reconfig_test.sh`](file:///c:/git/my_dns/tests/run_karictl_reload_reconfig_test.sh) | `tools/karictl.c`, `dns_snapshot_rcu.c` | Epoch RCU Architecture | **Positive / RCU** | Zero-downtime zone reloading and configuration updates via Epoch RCU pointer swap. |
| 54 | [`run_config_duplicate_rejection_test.sh`](file:///c:/git/my_dns/tests/run_config_duplicate_rejection_test.sh) | `dns_config_parser.c` | Config Syntax | **Negative** | Rejection of duplicate view names and duplicate zone definitions during startup. |
| 55 | [`run_domain_length_rfc1035_test.sh`](file:///c:/git/my_dns/tests/run_domain_length_rfc1035_test.sh) | `dns_wire.c`, `dns_zone_parser.c` | RFC 1035 §2.3.4 | **Negative / Boundary** | Strict enforcement of 255-byte total domain length and 63-byte per-label limits. |
| 56 | [`run_forward_zone_test.sh`](file:///c:/git/my_dns/tests/run_forward_zone_test.sh) | `dns_server_core.c`, `dns_query_engine.c` | RFC 5452, Forwarding | **Positive / Negative** | Forward zone relaying, shared deadline budgets, upstream failover, and TC fallback. |
| 57 | [`run_logging_channel_validation_test.sh`](file:///c:/git/my_dns/tests/run_logging_channel_validation_test.sh) | `dns_config_parser.c`, `dns_server_core.c` | Logging Subsystem | **Positive / Validation** | Configuration of syslog and file logging channels with severity filtering. |
| 58 | [`run_malformed_detection_default_test.sh`](file:///c:/git/my_dns/tests/run_malformed_detection_default_test.sh) | `dns_wire.c`, `dns_server_core.c` | RFC 1035 §4.1.1 | **Negative** | FORMERR error response generation upon receiving malformed or truncated queries. |
| 59 | [`run_mx_srv_glue_test.sh`](file:///c:/git/my_dns/tests/run_mx_srv_glue_test.sh) | `dns_query_engine.c` | RFC 1035 §3.3.9, RFC 2782 | **Positive** | In-bailiwick A/AAAA address record inclusion for MX and SRV target hosts. |
| 60 | [`run_notify_source_test.sh`](file:///c:/git/my_dns/tests/run_notify_source_test.sh) | `dns_server_core.c` | RFC 1996 §4.4 | **Positive** | Source address selection and explicit IP binding for outgoing NOTIFY datagrams. |
| 61 | [`run_privilege_drop_root_test.sh`](file:///c:/git/my_dns/tests/run_privilege_drop_root_test.sh) | `dns_priv_sandbox.c`, `dns_server_core.c` | FreeBSD POSIX Security | **Positive / Security** | Port 53 binding under root privilege followed by clean UID/GID drop to nobody:nobody. |
| 62 | [`run_program_zone_test.sh`](file:///c:/git/my_dns/tests/run_program_zone_test.sh) | `dns_server_core.c`, `dns_query_engine.c` | Program Zone IPC | **Positive / Extensibility** | Evaluation of dynamic backend records via external pipe-based program zone plugins. |
| 63 | [`run_response_cache_test.sh`](file:///c:/git/my_dns/tests/run_response_cache_test.sh) | `dns_query_engine.c`, `dns_snapshot_rcu.c` | RFC 1034 / RFC 2181 | **Positive** | Functional query cache hits, cache misses, and TTL countdown behavior. |
| 64 | [`run_ttl_harmonization_test.sh`](file:///c:/git/my_dns/tests/run_ttl_harmonization_test.sh) | `dns_zone_parser.c`, `dns_query_engine.c` | RFC 2181 §5.2 | **Positive / Semantic** | Enforcing consistent TTL values across all records within the same RRset on zone load. |
| 65 | [`run_ttl_rfc2181_clamp_test.sh`](file:///c:/git/my_dns/tests/run_ttl_rfc2181_clamp_test.sh) | `dns_wire.c` | RFC 2181 §8 | **Boundary** | Clamping TTL values with the high bit set (≥ 2^31) to 0 during wire serialization. |
| 66 | [`run_zone_oom_partial_load_test.sh`](file:///c:/git/my_dns/tests/run_zone_oom_partial_load_test.sh) | `dns_zone_parser.c`, `dns_snapshot_rcu.c` | Robustness | **Negative / Fault Injection** | Fail-closed atomic rollback to previous zone version upon encountering simulated OOM. |
| 67 | [`run_break_duplicate_kind_override_test.sh`](file:///c:/git/my_dns/tests/run_break_duplicate_kind_override_test.sh) | `dns_config_parser.c` | Config Grammar | **Negative** | Validation of config directive precedence and rejection of conflicting keyword overrides. |

---

### 3.10 Diagnostic Client (`dag`) Suite - Category: `dag`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 68 | [`run_dag_ci_test.sh`](file:///c:/git/my_dns/tests/run_dag_ci_test.sh) | `dag` (`tools/dag*.c`) | RFC 1035, RFC 3597, RFC 6891, RFC 10029 | **Positive / Composite** | Comprehensive CLI flag and option test matrix (+short, +yaml, +qr, +trace, +multiline). |
| 69 | [`run_dag_apl_afdlength_overflow_test.sh`](file:///c:/git/my_dns/tests/run_dag_apl_afdlength_overflow_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 3123 | **Boundary / Security** | Boundary check preventing buffer overflow on malformed APL AFDLENGTH values. |
| 70 | [`run_dag_audit_improvements_test.sh`](file:///c:/git/my_dns/tests/run_dag_audit_improvements_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7230, RFC 7858, RFC 8484 | **Positive / Transport** | Opportunistic TLS upgrade and HTTP/1.1 chunked transfer decoding. |
| 71 | [`run_dag_batch_advanced_opts_test.sh`](file:///c:/git/my_dns/tests/run_dag_batch_advanced_opts_test.sh) | `dag` (`tools/dag_batch.c`) | Batch Processing | **Positive** | Batch file execution (`-f`) supporting mixed per-query options and comments. |
| 72 | [`run_dag_bind_address_family_mismatch_test.sh`](file:///c:/git/my_dns/tests/run_dag_bind_address_family_mismatch_test.sh) | `dag` (`tools/dag_transport.c`) | Socket API | **Negative** | Error reporting when local `-b` address family conflicts with destination server family. |
| 73 | [`run_dag_break_help_examples_test.sh`](file:///c:/git/my_dns/tests/run_dag_break_help_examples_test.sh) | `dag` (`tools/dag.c`) | CLI Help | **Positive** | Verification that every command example in `dag --help` runs cleanly. |
| 74 | [`run_dag_cli_options_test.sh`](file:///c:/git/my_dns/tests/run_dag_cli_options_test.sh) | `dag` (`tools/dag.c`) | CLI Parsing | **Positive / Negative** | Parsing short options, long options, negation flags (`+no...`), and value assignments. |
| 75 | [`run_dag_compat_test.sh`](file:///c:/git/my_dns/tests/run_dag_compat_test.sh) | `dag` (`tools/dag.c`) | BIND 9 dig Parity | **Positive** | Output structure parity with standard BIND 9 dig. |
| 76 | [`run_dag_cookie_mismatch_discard_test.sh`](file:///c:/git/my_dns/tests/run_dag_cookie_mismatch_discard_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 7873 | **Negative** | Rejecting answers with invalid or mismatched client cookies. |
| 77 | [`run_dag_dig_anomalous_suite.sh`](file:///c:/git/my_dns/tests/run_dag_dig_anomalous_suite.sh) | `dag` (`tools/dag.c`) | Robustness | **Negative / Robustness** | Handling corrupt headers, truncated RRs, and malformed packets without crashing. |
| 78 | [`run_dag_dns64prefix_short_yaml_test.sh`](file:///c:/git/my_dns/tests/run_dag_dns64prefix_short_yaml_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 7050 | **Positive** | Formatting `+dns64prefix` results in `+short` and `+yaml` output modes. |
| 79 | [`run_dag_dns64prefix_test.sh`](file:///c:/git/my_dns/tests/run_dag_dns64prefix_test.sh) | `dag` (`tools/dag.c`) | RFC 7050 | **Positive** | Extracting synthetic IPv6 prefixes from `ipv4only.arpa` queries. |
| 80 | [`run_dag_doh_cache_cleanup_test.sh`](file:///c:/git/my_dns/tests/run_dag_doh_cache_cleanup_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 8484 | **Resource** | Socket cleanup and session termination for DoH HTTP connections. |
| 81 | [`run_dag_ede_truncation_regression_test.sh`](file:///c:/git/my_dns/tests/run_dag_ede_truncation_regression_test.sh) | `dag` (`tools/dag_edns_client.c`) | RFC 8914 | **Boundary** | Regression test for EDE option parsing near wire packet boundaries. |
| 82 | [`run_dag_edge_cases_audit_test.sh`](file:///c:/git/my_dns/tests/run_dag_edge_cases_audit_test.sh) | `dag` (`tools/dag_transport.c`) | Transport Edge Cases | **Boundary / Fault** | Error handling on unexpected EOF, zero-length reads, and connection resets. |
| 83 | [`run_dag_edge_cases_phase3_test.sh`](file:///c:/git/my_dns/tests/run_dag_edge_cases_phase3_test.sh) | `dag` (`tools/dag_transport.c`) | Transport Edge Cases | **Boundary / Fault** | Phase 3 transport failover across mixed IPv4/IPv6 dual-stack nameservers. |
| 84 | [`run_dag_fixes_validation_test.sh`](file:///c:/git/my_dns/tests/run_dag_fixes_validation_test.sh) | `dag` (`tools/dag*.c`) | Regression Suite | **Positive / Negative** | Consolidated validation of past bug fixes and formatting corrections. |
| 85 | [`run_dag_hex_payload_overflow_test.sh`](file:///c:/git/my_dns/tests/run_dag_hex_payload_overflow_test.sh) | `dag` (`tools/dag.c`) | Raw Hex Input | **Boundary / Security** | Buffer size validation when injecting arbitrary hex DNS packet payloads via `--hex`. |
| 86 | [`run_dag_keepopen_keepalive_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_keepalive_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7766, RFC 7828 | **Positive** | TCP connection reuse (`+keepopen`) with EDNS TCP keepalive negotiation. |
| 87 | [`run_dag_keepopen_partial_read_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_partial_read_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7766 §7.2 | **Boundary** | Framing reassembly when TCP stream delivers fragmented length prefixes. |
| 88 | [`run_dag_keepopen_tls_partial_read_test.sh`](file:///c:/git/my_dns/tests/run_dag_keepopen_tls_partial_read_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 7858 | **Boundary** | TLS record stream reassembly across fragmented TLS frames under `+keepopen`. |
| 89 | [`run_dag_long_label_name_expansion_test.sh`](file:///c:/git/my_dns/tests/run_dag_long_label_name_expansion_test.sh) | `dag` (`tools/dag.c`) | RFC 1035 §2.3.4 | **Boundary** | Rendering max-length 63-byte labels in presentation format without truncation. |
| 90 | [`run_dag_multi_server_semantic_match_test.sh`](file:///c:/git/my_dns/tests/run_dag_multi_server_semantic_match_test.sh) | `dag` (`tools/dag.c`) | Multi-Server Queries | **Positive** | Parallel querying of multiple servers and comparing response parity. |
| 91 | [`run_dag_multi_server_timeout_test.sh`](file:///c:/git/my_dns/tests/run_dag_multi_server_timeout_test.sh) | `dag` (`tools/dag_transport.c`) | Timeout Handling | **Negative / Timeout** | Handling individual server timeouts in multi-server batch mode without blocking. |
| 92 | [`run_dag_multiline_ds_single_line_test.sh`](file:///c:/git/my_dns/tests/run_dag_multiline_ds_single_line_test.sh) | `dag` (`tools/dag_output_yaml.c`) | YAML Formatting | **Positive** | Rendering multi-line DS/DNSKEY records in compact YAML single-line format. |
| 93 | [`run_dag_replay_compare_recorded_test.sh`](file:///c:/git/my_dns/tests/run_dag_replay_compare_recorded_test.sh) | `dag` (`tools/dag_replay.c`) | PCAP Replay | **Positive** | Replaying captured PCAP queries against live server and verifying response parity. |
| 94 | [`run_dag_replay_diff_test.sh`](file:///c:/git/my_dns/tests/run_dag_replay_diff_test.sh) | `dag` (`tools/dag_replay.c`) | PCAP Replay | **Positive** | Diff engine output generation for PCAP query differences. |
| 95 | [`run_dag_rr_differential_test.sh`](file:///c:/git/my_dns/tests/run_dag_rr_differential_test.sh) | `dag`, `dns_wire.c` | Wire Format | **Positive** | Differential RR parser comparison across all supported DNS resource record types. |
| 96 | [`run_dag_tcp_connect_timeout_test.sh`](file:///c:/git/my_dns/tests/run_dag_tcp_connect_timeout_test.sh) | `dag` (`tools/dag_transport.c`) | TCP Transport | **Negative / Timeout** | Non-blocking TCP connect timeout enforcement. |
| 97 | [`run_dag_trace_cname_glue_test.sh`](file:///c:/git/my_dns/tests/run_dag_trace_cname_glue_test.sh) | `dag` (`tools/dag_trace.c`) | Iterative Trace | **Positive** | `+trace` following CNAME referrals and resolving glue records iteratively. |
| 98 | [`run_dag_trace_deep_cname_stack_test.sh`](file:///c:/git/my_dns/tests/run_dag_trace_deep_cname_stack_test.sh) | `dag` (`tools/dag_trace.c`) | RFC 1034 §3.6.2 | **Boundary** | `+trace` resolving 10+ hop deep CNAME redirection stacks without loop or overflow. |
| 99 | [`run_dag_trace_nssearch_opts_test.sh`](file:///c:/git/my_dns/tests/run_dag_trace_nssearch_opts_test.sh) | `dag` (`tools/dag_trace.c`) | Authoritative Polling | **Positive** | `+nssearch` polling all authoritative nameservers for zone SOA serials. |
| 100 | [`run_dag_trace_nssearch_tcp_test.sh`](file:///c:/git/my_dns/tests/run_dag_trace_nssearch_tcp_test.sh) | `dag` (`tools/dag_trace.c`) | Authoritative Polling | **Positive** | `+nssearch` execution forced over TCP transport. |
| 101 | [`run_dag_udp_id_mismatch_discard_test.sh`](file:///c:/git/my_dns/tests/run_dag_udp_id_mismatch_discard_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 5452 §4.3 | **Negative / Security** | Discarding UDP datagrams with mismatched transaction IDs. |
| 102 | [`run_dag_udp_spoofing_source_test.sh`](file:///c:/git/my_dns/tests/run_dag_udp_spoofing_source_test.sh) | `dag` (`tools/dag_transport.c`) | RFC 5452 §4.1 | **Negative / Security** | Discarding spoofed UDP packets originating from unexpected source addresses. |
| 103 | [`run_dag_yaml_apostrophe_escaping_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_apostrophe_escaping_test.sh) | `dag` (`tools/dag_output_yaml.c`) | YAML 1.2 | **Positive / Escaping** | Escaping single quotes in TXT/RDATA strings within YAML output. |
| 104 | [`run_dag_yaml_expandaaaa_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_expandaaaa_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 5952 | **Positive** | `+yaml +expandaaaa` rendering uncompressed 32-character IPv6 hex addresses. |
| 105 | [`run_dag_yaml_no_spurious_resolve_error_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_no_spurious_resolve_error_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Error Formatting | **Positive** | Suppression of false resolve errors on legitimate NODATA (empty answer) responses. |
| 106 | [`run_dag_yaml_nocrypto_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_nocrypto_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Security Redaction | **Positive** | `+yaml +nocrypto` redacting cryptographic key materials and signatures. |
| 107 | [`run_dag_yaml_rdata_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_rdata_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Structured Output | **Positive** | Structured JSON/YAML object decoding for all standard RR types. |
| 108 | [`run_dag_yaml_rrsig_decode_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_rrsig_decode_test.sh) | `dag` (`tools/dag_output_yaml.c`) | RFC 4034 §3.1 | **Positive** | Decoding RRSIG inception and expiration timestamps into human-readable ISO dates. |
| 109 | [`run_dag_yaml_socket_family_force_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_socket_family_force_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Socket Telemetry | **Positive** | Verifying socket family forcing and telemetry in YAML outputs. |
| 110 | [`run_dag_yaml_socket_family_test.sh`](file:///c:/git/my_dns/tests/run_dag_yaml_socket_family_test.sh) | `dag` (`tools/dag_output_yaml.c`) | Socket Telemetry | **Positive** | Transport family telemetry reporting in YAML statistics section. |

---

### 3.11 Regression, Stress & Fuzzing - Category: `regression`

| ID | Test Target | Subsystems / Files | RFC / Spec | Test Classification | Verification Objective |
|:---:|:---|:---|:---|:---|:---|
| 111 | [`run_sanitizer_smoke_test.sh`](file:///c:/git/my_dns/tests/run_sanitizer_smoke_test.sh) | All core binaries & parsers | ASan / UBSan | **Sanitizer Smoke** | Running core smoke queries against binaries compiled with `-fsanitize=address,undefined`. |
| 112 | [`run_stress_test.sh`](file:///c:/git/my_dns/tests/run_stress_test.sh) | `dns_server_core.c`, `dns_snapshot_rcu.c` | Concurrency Stress | **Standalone Benchmark** | High-throughput concurrent query flood (dnsperf 60s); run manually outside automated suite. |
| 113 | [`run_dag_fuzzer_test.sh`](file:///c:/git/my_dns/tests/run_dag_fuzzer_test.sh) | `dag` fuzz targets in `tests/fuzz/` | libFuzzer | **Fuzzing Smoke** | Smoke execution of LLVM libFuzzer targets for dag client parsers. |
| 114 | [`run_fuzz_smoke_test.sh`](file:///c:/git/my_dns/tests/run_fuzz_smoke_test.sh) | `tests/fuzz/` (all 10 harnesses) | LLVM libFuzzer | **Fuzzing Smoke** | Crash-resistance verification across wire, config, zone, TSIG, and server core fuzzers. |

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

# 4. Quick mode (fast unit and core tests only)
sh tests/run_all_suite.sh --quick

# 5. Stop immediately on first failure
sh tests/run_all_suite.sh --stop-on-failure

# 6. List all registered tests
sh tests/run_all_suite.sh --list
```

### 4.2 Measuring Code Coverage with Clang

KariDNS supports Clang source-based code coverage (`-fprofile-instr-generate -fcoverage-mapping`):

```bash
# Clean, instrument build, execute test suite, and generate HTML report
make coverage

# Individual coverage steps:
make coverage-clean   # Remove previous raw and HTML coverage files
make coverage-build   # Compile all targets with instrumentation
make coverage-run     # Run tests/run_all_suite.sh with LLVM_PROFILE_FILE
make coverage-report  # Merge .profraw files and generate coverage_html/
```

HTML coverage reports with line and branch-level precision will be written to `coverage_html/index.html`.

# KariDNS Code Coverage Status & Improvement Log

## 1. Current Metrics

Measured on 2026-09-28 at commit `bea0c17` (`main`).

- **Toolchain:** clang / llvm-cov / llvm-profdata 19.1.7 (FreeBSD 15.1-RELEASE / amd64), continuous-mode profiling (`COV_CONTINUOUS=1`)
- **Procedure:** the `make coverage` steps: `make coverage-clean coverage-build` as a normal user, `make coverage-run` as root (integration tests that need loopback aliases run only as root), then `make coverage-report` and `perl tests/coverage_gate.pl --llvm-cov=llvm-cov19 --profdata=coverage.profdata --phase=2`
- **Test suite:** `tests/run_all_suite.sh` with `run_sanitizer_smoke_test`, `run_stress_test` and `run_fuzz_smoke_test` excluded (`COV_SUITE_EXCLUDE`, they run only non-instrumented sanitizer/fuzzer binaries): 157 suites executed, 157 passed, 0 failed. The libFuzzer corpora are replayed by `coverage-fuzz-run` and included.
- **Functions:** 100.00% (596 / 596)
- **Lines:** 92.10% (32,997 / 35,826)
- **Regions:** 89.97% (37,587 / 41,779)
- **Branches:** 78.88% (21,443 / 27,186)

### Coverage Gate (`tests/coverage_gate.pl`)

The CI job "Coverage gate" runs the Phase 2 thresholds with `--strict`. The tiers are defined in `tests/coverage_gate.pl`: Tier A = protocol and parser modules (`dns_wire.c`, `dns_zone_parser.c`, `dns_config_parser.c`, `dns_tinydns_parser.c`, `dns_utils.c`, `dns_cidr.c`, `dns_tsig_acl.c`, `dns_query_engine.c`, `dns_axfr_ixfr.c`, `dns_dynamic_update.c`, `dns_catalog_zone.c`, `dns_rrl.c`, `dns_edns_ecs.c`), Tier B = server runtime (`dns_server_core.c`, `dns_snapshot_rcu.c`, `dns_dnstap.c`, `dns_priv_sandbox.c`, `dns_epoch_rcu.c`), Tier C = tools (`tools/dag*.c`, `tools/karicheck.c`, `tools/karictl.c`).

| Tier | Line (target) | Region (target) | Branch (target) | Status |
|---|---|---|---|---|
| Tier A | 93.83% (93.0%) | 91.36% (89.0%) | 82.56% (80.0%) | **PASS** |
| Tier B | 89.08% (87.0%) | 89.01% (80.0%) | 76.25% (68.0%) | **PASS** |
| Tier C | 91.62% (90.0%) | 88.87% (84.0%) | 75.78% (72.0%) | **PASS** |
| Total, Phase 1 | 92.10% (90.0%) | 89.97% (84.0%) | 78.88% (72.0%) | **PASS** |
| Total, Phase 2 | 92.10% (92.0%) | 89.97% (85.0%) | 78.88% (75.0%) | **PASS** |

### Per-File Results

| File | Lines | Regions | Branches |
|---|---|---|---|
| `dns_axfr_ixfr.c` | 93.78% | 90.54% | 74.87% |
| `dns_catalog_zone.c` | 98.92% | 97.51% | 87.50% |
| `dns_cidr.c` | 99.07% | 90.64% | 81.82% |
| `dns_config_parser.c` | 93.86% | 91.91% | 83.46% |
| `dns_dnstap.c` | 92.02% | 92.53% | 78.99% |
| `dns_dynamic_update.c` | 95.21% | 95.84% | 73.39% |
| `dns_edns_ecs.c` | 95.25% | 93.15% | 87.50% |
| `dns_epoch_rcu.c` | 91.03% | 91.51% | 76.79% |
| `dns_priv_sandbox.c` | 88.63% | 91.26% | 77.00% |
| `dns_query_engine.c` | 89.42% | 87.64% | 76.94% |
| `dns_rrl.c` | 96.30% | 96.27% | 89.16% |
| `dns_server_core.c` | 87.93% | 87.60% | 73.95% |
| `dns_snapshot_rcu.c` | 91.27% | 91.30% | 79.62% |
| `dns_tinydns_parser.c` | 96.36% | 89.30% | 83.28% |
| `dns_tsig_acl.c` | 100.00% | 93.81% | 85.19% |
| `dns_utils.c` | 97.31% | 96.48% | 96.05% |
| `dns_wire.c` | 96.69% | 92.80% | 86.10% |
| `dns_zone_parser.c` | 91.71% | 91.33% | 82.66% |
| `tools/dag.c` | 95.07% | 92.48% | 83.16% |
| `tools/dag_axfr_client.c` | 88.24% | 83.87% | 65.91% |
| `tools/dag_batch.c` | 95.00% | 89.04% | 74.00% |
| `tools/dag_edns_client.c` | 97.79% | 95.69% | 82.94% |
| `tools/dag_iter.c` | 91.03% | 85.65% | 71.40% |
| `tools/dag_output_yaml.c` | 98.39% | 87.36% | 59.01% |
| `tools/dag_pcap_l4.c` | 100.00% | 98.55% | 92.22% |
| `tools/dag_replay.c` | 87.21% | 82.30% | 68.67% |
| `tools/dag_roothints.c` | 77.56% | 84.76% | 65.38% |
| `tools/dag_tcp_reassembly.c` | 80.62% | 82.69% | 73.33% |
| `tools/dag_trace.c` | 88.27% | 80.48% | 62.44% |
| `tools/dag_trace_common.c` | 97.50% | 82.17% | 67.39% |
| `tools/dag_transport.c` | 86.86% | 86.39% | 68.25% |
| `tools/dag_tsig_client.c` | 91.77% | 89.16% | 67.95% |
| `tools/karicheck.c` | 90.02% | 89.16% | 76.42% |
| `tools/karictl.c` | 89.41% | 88.92% | 79.21% |

Header files with inline functions (`dns_epoch_rcu.h`, `dns_siphash.h`, `dns_utils.h`, `dns_wire.h`, `dns_zone_parser.h`, `tools/dag_internal.h`) are included in the totals but not in the table.

---

## 2. Work Package Execution Log

### WP-1: Macro Denominator Normalization
- **Status:** Complete
- **Changes:**
  - `dns_axfr_ixfr.c`: Replaced multi-line macros `SERIALIZE_ADD_RECORD` and `EMIT_ZONE_RECORD` (which expanded across 23 call sites, bloating region/branch AST nodes) with `axfr_emit_ctx_t` and `static int axfr_emit_record(...)` / `static int axfr_emit_zone_record(...)`. Wire format byte outputs remain 100% identical.
  - `tools/dag_replay.c`: Replaced 13 repetitive macro instantiations of `APPEND_DIFF_FLAG` with a table-driven loop (`k_diff_flags[]`).

### WP-2: Configurable Test Limits (Knobs)
- **Status:** Complete
- **Changes:**
  - Introduced `#ifndef KARIDNS_AXFR_MSG_LIMIT` (default 65000) allowing unit tests to simulate small message boundary chunking and oversized record rejection without generating massive zone files.

### WP-3: Fault Injection Infrastructure Expansion
- **Status:** Complete
- **Changes:**
  - `tests/fi/kari_fi.h` & `tests/fi/kari_fi.c`: Implemented complete wrapping for all declared `fi_kind_t` enumerations: `send`, `recv`, `sendto`, `recvfrom`, `close`, `pipe`, `fork`, `execv`, `socket`, `bind`, `listen`, `accept`, `connect`, `getsockname`, `fcntl`, `setsockopt`, `kevent`, `poll`, `select`, `SSL_CTX_new`, `SSL_connect`, `SSL_read`, `SSL_write`.
  - Added short-write/short-read injection (`fi_arm_short`) and errno sweep macros (`FI_SWEEP_ERRNO`).
  - `tests/fi/kari_fi_preload.c`: Rebuilt as a generic environment-variable-driven interceptor (`KARI_FI_SPEC`).
  - `Makefile`: Updated `FI_WRAP_LDFLAGS` and `FI_WRAP_SSL_LDFLAGS`.

### WP-4: File-Specific Unit & Protocol Tests
- **Status:** Complete
- **Changes:**
  - `tests/test_axfr_ixfr_engine.c`: Implemented cases 151-157:
    - Case 151: Outbound IXFR request packet assembly (`active_serial != 0`) in Authority section.
    - Case 152: Outbound transfer TSIG signing success and error handling.
    - Case 153: Extended AXFR tinydns unwrap fallback when `!reconstructed`.
    - Case 154: `handle_axfr_event` TSIG validation, intermediate unsigned message buffering, and `unsigned_msgs` memory cleanup.
    - Case 155: Multi-packet chunking and QDCOUNT preservation in `send_axfr_response`.
    - Case 156: "Record too large to fit in any TCP message" error handling.
    - Case 157: `axfr_error:` cleanup label and transaction reference release.
  - `tests/test_server_core.c`: Implemented cases 151-155:
    - Case 151: NOTIFY source address binding and ephemeral fallback.
    - Case 152: TCP ACL refusal with `REFUSED` + EDE 18 and `send-extended-errors`.
    - Case 153: TCP ACL refusal with TSIG signing.
    - Case 154: Shutdown dnstap ring buffer and aux ring draining.
    - Case 155: Program zone reload fingerprint comparison and new zone notice.
  - `tests/test_query_engine_protocol.c`:
    - RFC 8482 `minimal-any` synthesis (HINFO, DO=0/1, CNAME bypass, truncation).
    - Sibling zone additional glue resolution with alternate hash lookup.
    - Effective TTL resolution (`eff_ttl`) and tinydns timestamp clamping.
  - `tests/test_fi_xfr.c`: Added `FI_SEND` and `FI_WRITE` sweeps on AXFR response serialization.

### WP-5: Matrix Tests & Table-Driven Coverage
- **Status:** Complete
- **Changes:**
  - Created `tests/matrix/zones/all_types.zone` covering every supported DNS record type.
  - Expanded `tests/matrix/queries.tsv` with all RR types and negative response assertions.
  - Expanded `tests/run_dag_cli_options_test.sh` to test `+nsid`, `+cookie`, `+bufsize`, numeric parameters, YAML formatting, and UPDATE prerequisites.

---

## 3. Unreachable & Defensive Code Classification (§9)

| Category | Classification Description | Code Locations / Examples | Handling Strategy |
|---|---|---|---|
| **A** | Reachable via regular input / queries | Protocol paths, RR types, wildcard, DNAME, CNAME chains, minimal-any | Covered by unit and matrix tests (WP-4, WP-5) |
| **B** | Reachable via Fault Injection | Heap allocation failure, socket/bind error, SSL failures, short write | Covered by `kari_fi` fail-Nth and short-write wrappers (WP-3) |
| **C** | Platform-specific (FreeBSD / Capsicum) | `cap_rights_limit`, `cap_enter`, `kqueue`/`kevent`, `procctl` | Verified under FreeBSD CI environment; recorded as platform-specific for Linux builds |
| **D** | Invariant / Defensive guards | Unreachable switch default, defensive NULL checks after validated invariants | Replaced silent if-returns with `assert()` where appropriate, or commented with rationale |

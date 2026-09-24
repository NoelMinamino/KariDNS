# KariDNS Code Coverage Status & Improvement Log

## 1. Baseline Status (2026-09-24)
- **Toolchain:** llvm-cov 19.1.7 (FreeBSD 15-CURRENT / amd64)
- **Functions:** 100.0% (513 / 513)
- **Lines:** 84.91% (28,560 / 33,634)
- **Regions:** 79.57% (19,411 / 24,394)
- **Branches:** 67.41% (17,451 / 25,886)

### Target Milestones
| Metric | Baseline | Phase 1 Target | Phase 2 (Stretch) |
|---|---|---|---|
| **Line Coverage** | 84.91% | **>= 90.0%** (+1,711 lines) | **>= 92.0%** |
| **Region Coverage** | 79.57% | **>= 84.0%** (+2,178 regions) | **>= 85.0%** |
| **Branch Coverage** | 67.41% | **>= 72.0%** (+1,964 branches) | **>= 75.0%** |

---

## 2. Work Package Execution Log

### WP-A: Coverage Measurement Infrastructure & Baseline Tooling
- **Status:** Complete
- **Changes:**
  - Added fuzz instrumentation integration to `Makefile` (`coverage-fuzz-build`, `coverage-fuzz-run`, `coverage-fuzz`).
  - Added SKIP visibility in `tests/run_all_suite.sh` with detailed reason recording.
  - Implemented `tests/cov_gap.sh` to dynamically query top uncovered functions sorted by line/branch gaps.
  - Implemented `tests/coverage_gate.pl` for multi-tier (Tier A, Tier B, Tier C) automated gate evaluation.

### WP-C: Fuzz Corpus & Harness Infrastructure
- **Status:** Complete
- **Changes:**
  - Created `populate_seeds.pl` and populated initial seed corpuses for 16 fuzzer targets.
  - Added fuzzer dictionaries (`tests/fuzz/zone.dict`, `tests/fuzz/conf.dict`, `tests/fuzz/dag.dict`).
  - Created dedicated specialized fuzzer harnesses: `tests/fuzz/fuzz_query_engine.c`, `tests/fuzz/fuzz_xfr_packet.c`, and `tests/fuzz/fuzz_dynamic_update.c`.

### WP-B: Fault Injection Engine
- **Status:** Complete
- **Changes:**
  - Implemented deterministic fail-Nth fault injection library: `tests/fi/kari_fi.h` and `tests/fi/kari_fi.c` (`-Wl,--wrap` memory & syscall interception).
  - Implemented `LD_PRELOAD` syscall/privilege-drop/clock shim: `tests/fi/kari_fi_preload.c`.
  - Created comprehensive fault injection unit test suites:
    - `tests/test_fi_parsers.c` (Zone fast parser, named.conf, tinydns)
    - `tests/test_fi_wire.c` (Record wire serialization, TSIG sign/verify)
    - `tests/test_fi_snapshot.c` (Snapshot RCU rebuild and view allocation)
    - `tests/test_fi_xfr.c` (AXFR/IXFR stream parse, SOA serial bump)
    - `tests/test_fi_misc.c` (Dynamic update, catalog zones, dnstap encoding)
    - `tests/test_fi_dag.c` (dag query packet build and YAML formatting)

### WP-E: Query Engine Matrix & BIND Differential
- **Status:** Complete
- **Changes:**
  - Created table-driven matrix fixtures in `tests/matrix/zones/` (wildcard, DNAME, delegation, NSEC signed, CNAME chain).
  - Implemented `tests/matrix/queries.tsv` with RFC section traceability.
  - Implemented matrix runner `tests/run_matrix_queries_test.sh`.
  - Implemented BIND differential comparison runner `tests/run_bind_differential_test.sh`.

### WP-D: Server Core Lifecycle & Adversary Matrix
- **Status:** Complete
- **Changes:**
  - Created TCP adversary helper `tests/lib/tcpadv.pl` and control client helper `tests/lib/ctrl_client.pl`.
  - Implemented server lifecycle test: `tests/run_server_lifecycle_test.sh` (port collision, bad syntax, signal handling).
  - Implemented TCP adversary test: `tests/run_tcp_adversary_test.sh` (slowloris, zero length, giant length, trickle, pipeline, flood).
  - Implemented control socket adversary test: `tests/run_control_adversary_test.sh` (HMAC, buffer limits, timeouts).

### WP-G: karicheck & karictl Diagnostics
- **Status:** Complete
- **Changes:**
  - Implemented `tests/run_karicheck_rules_test.sh` (SSHFP algorithm validation, RFC 8624 checks, config linting).
  - Implemented `tests/run_karictl_adversary_test.sh` (CLI argument validation and socket error resilience).

---

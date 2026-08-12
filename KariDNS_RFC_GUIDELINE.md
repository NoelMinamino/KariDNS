# KariDNS RFC Compliance Guideline

This document catalogs the DNS-related standards (RFCs, etc.) implemented by KariDNS, in the same
spirit as NLnet Labs' (NSD) [RFC Compliance](https://nsd.docs.nlnetlabs.nl/en/latest/reference/rfc-compliance.html)
page and PowerDNS's [Compliance](https://www.powerdns.com/compliance) page.

**This document is based on direct source-code inspection.** Each entry cites the relevant file /
function name as evidence. "Test coverage" is tracked separately in `RFC_COVERAGE.md` (the QA test
suite's RFC coverage report). **Implementation status and test coverage are two different axes** —
many items are implemented but not yet covered by automated tests, and vice versa.

Legend:
- ✅ **Full** — Core requirements (MUST/SHOULD) are implemented
- 🟡 **Partial** — Partially implemented, or implemented with limitations
- ❌ **No** — Not implemented
- ➖ **N/A** — Out of scope for this server's purpose (authoritative, non-recursive, static DNSSEC)

---

## 1. Core Protocol

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 1034 | Domain Names - Concepts and Facilities | ✅ Full | Core namespace model |
| RFC 1035 | Domain Names - Implementation and Specification | ✅ Full | Zone file syntax, wire format, base record types. Text string escaping (`\DDD`, `\X`) is fully supported per §5.1 (`dns_zone_parser.c`, `dns_wire.c`) |
| RFC 1123 | Requirements for Internet Hosts (applicable parts) | ✅ Full | General hostname rules |
| RFC 1912 | Common DNS Operational and Configuration Errors | ✅ Full | `karicheck` now warns when MX/NS/SOA(MNAME) targets point to a CNAME, and when a CNAME co-exists with non-DNSSEC record types at the same owner name (`tools/karicheck.c`, `is_cname()` and related checks) |
| RFC 1982 | Serial Number Arithmetic | ✅ Full | Serial number arithmetic is used to evaluate SOA serial increments during IXFR/NOTIFY (`dns_server_core.c`, e.g., `(int32_t)(new_serial - old_serial) <= 0`) |
| RFC 1995 | Incremental Zone Transfer (IXFR) | ✅ Full | `ixfr_history_t`, `compute_ixfr_diff` (`dns_server_core.c`) |
| RFC 1996 | A Mechanism for Prompt Notification of Zone Changes (NOTIFY) | ✅ Full | Send and receive supported. Inbound NOTIFY authenticated via `masters` IP match, plus optional TSIG (`dns_server_core.c`) |
| RFC 2181 | Clarifications to the DNS Specification | ✅ Full | TTL values with the high bit set (≥ 2^31) are now capped to 0 at the single conversion point in `serialize_dns_record` (`dns_wire.c`), per §8 |
| RFC 2308 | Negative Caching of DNS Queries | ✅ Full | On NXDOMAIN/NODATA, the SOA MINIMUM field is used as the TTL override for the authority-section SOA (`dns_server_core.c`, ~line 2697) |
| RFC 2782 | A DNS RR for specifying the location of services (SRV) | ✅ Full | SRV supported in the record-type table (`dns_utils.c`) |
| RFC 3596 | DNS Extensions to Support IP Version 6 (AAAA) | ✅ Full | AAAA supported (`dns_utils.c`) |
| RFC 3597 | Handling of Unknown DNS Resource Record (RR) Types | ✅ Full | `TYPE<n>` syntax supported (`dns_utils.c`, `get_type_code`) |
| RFC 4343 | DNS Case Insensitivity Clarification | ✅ Full | Name comparisons consistently use `strcasecmp` throughout (`dns_server_core.c`, `dns_zone_parser.c`) |
| RFC 4592 | The Definition of Phrases with Wildcards in the Domain Name System | ✅ Full | Wildcard expansion/synthesis (e.g., `*.example.com`) is fully implemented in the resolution path (`dns_server_core.c`) |
| RFC 6672 | DNAME Redirection in the DNS | ✅ Full | DNAME→CNAME synthesis logic present (`dns_server_core.c`, `synth_name`) |
| RFC 6698 | DANE TLSA | ✅ Full | TLSA supported (`dns_utils.c`) |
| RFC 6891 | Extension Mechanisms for DNS (EDNS(0)) | ✅ Full | OPT pseudo-RR parsing and assembly (`dns_wire.c`) |
| RFC 7766 | DNS Transport over TCP - Implementation Requirements | ✅ Full (opt-in, default OFF) | TCP connection reuse/pipelining is now supported, gated behind `tcp-connection-reuse yes;` (default `no`, preserving the original one-query-per-connection behavior unless explicitly enabled). Idle timeout defaults to 10s per RFC 9210 §4.5 and is configurable via `tcp-idle-timeout` (`dns_server_core.c`, `dns_config_parser.c`/`.h`) |
| RFC 8482 | Providing Minimal-Sized Responses to ANY Queries | ✅ Full | `minimal_any` / `minimal_any_ttl` settings (`dns_config_parser.h`) |
| RFC 8767 | Serving Stale Data to Improve DNS Resiliency | 🟡 Partial | This RFC targets recursive resolver caches; KariDNS repurposes the term for a `serve-stale` toggle controlling whether a secondary keeps serving its last-known zone data after the SOA EXPIRE interval has passed without a successful refresh. Scope differs from the RFC's original target (recursive caching) |
| RFC 8906 | A Common Operational Problem in DNS Servers: Failure to Communicate (Fragmentation) | ✅ Full | EDNS UDP payload size is force-clamped to 1232 bytes (avoids IP fragmentation, matches the 2020 DNS Flag Day recommendation) |
| RFC 9210 | DNS Transport over TCP - Operational Requirements | ✅ Full (opt-in, default OFF) | Same mechanism as RFC 7766 above; default idle timeout (10s) matches §4.5's recommendation |
| RFC 9471 | DNS Glue Requirements in Referral Responses | ✅ Full | `append_glue_records` adds both A(1) and AAAA(28) glue (`dns_server_core.c`) |

## 2. Zone Transfer / Redundancy

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 5936 | DNS Zone Transfer Protocol (AXFR) | ✅ Full | `handle_axfr_event` (`dns_server_core.c`) |
| RFC 1995 | IXFR | ✅ Full | See section 1 above |
| RFC 9432 | DNS Catalog Zones | ✅ Full | `catalog_process_membership`, `is_catalog` (`dns_server_core.c`, `dns_config_parser.h`) |

## 3. DNSSEC

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 4033/4034/4035 | DNS Security Introduction / Resource Records / Protocol Modifications | 🟡 Partial | **Static DNSSEC support**: pre-signed RRSIG/DNSKEY/DS etc. placed in the zone file are served correctly. No online signing or automated key management (ZSK/KSK rollover) |
| RFC 5155 | DNSSEC Hashed Authenticated Denial of Existence (NSEC3) | ✅ Full | `zone_uses_nsec3` detection, NSEC3 response generation (`dns_server_core.c`) |
| RFC 6840 | Clarifications and Implementation Notes for DNSSEC | ✅ Full | The canonical-form errata this RFC documents (NSEC's Next Domain Name is NOT lowercased; RRSIG's Signer's Name IS lowercased) is now correctly implemented in the canonical-serialization path used for ZONEMD verification (`dns_wire.c`, `write_uncompressed_name_ext`) |
| RFC 7344 | Automating DNSSEC Delegation Trust Maintenance (CDS/CDNSKEY) | 🟡 Partial | CDS(59)/CDNSKEY(60) record types are recognized, stored, and served (`dns_utils.c`). The RFC's core automation (scanning CDS/CDNSKEY and reflecting them into the parent's DS) is not implemented — static serving only |
| RFC 8080 | EdDSA for DNSSEC | 🟡 Partial | The DNSKEY/RRSIG Algorithm field is passed through opaquely with no algorithm-specific logic (confirmed in `dns_wire.c`'s `serialize_dns_record`). Ed25519(15)/Ed448(16) can therefore be served, but this is a byproduct of algorithm-agnostic passthrough rather than dedicated EdDSA support |
| RFC 8624 | Algorithm Implementation Requirements and Usage Guidance for DNSSEC | ✅ Full | `karicheck` now maintains a table of DNSSEC algorithm numbers and their RFC 8624 status, and emits a warning (non-fatal) when a DNSKEY/CDNSKEY/RRSIG uses an algorithm marked MUST NOT or NOT RECOMMENDED (e.g., RSAMD5, DSA, RSASHA1) (`tools/karicheck.c`). The server itself remains algorithm-agnostic by design (static DNSSEC); this is an advisory check only |
| RFC 8901 | Multi-Signer DNSSEC Models | ➖ N/A | Not applicable — this server does not perform online signing, so multi-signer coordination models don't apply |
| RFC 8976 | Message Digest for DNS Zones (ZONEMD) | ✅ Full | `karicheck --verify-zonemd` implements the full RFC 8976 §3 digest algorithm: canonical RRset ordering (owner name → type → RDATA per RFC 4034 §6.3), canonical (uncompressed, lowercased per §6.2/RFC 6840) wire-form serialization, exclusion of the apex ZONEMD RRset **and** its covering RRSIG from the digest input, and deduplication of identical RRs. **Verified against the official RFC 8976 Appendix A test vectors, including the most complex signed example (Appendix A.4, `uri.arpa.`), which passes end-to-end** (independently reproduced during this review) |

## 4. Dynamic Update / Authentication

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 2136 | Dynamic Updates in the Domain Name System (DNS UPDATE) | ✅ Full | Ephemeral UPDATE (no persistence). `process_update_sections`, `handle_dynamic_update` (`dns_wire.c`, `dns_server_core.c`) |
| RFC 3007 | Secure Domain Name System (DNS) Dynamic Update | ✅ Full | Effectively satisfied by the combination of RFC 2136 (UPDATE) and RFC 8945 (TSIG); no dedicated code path, but the requirements are met |
| RFC 8945 | Secret Key Transaction Authentication for DNS (TSIG) | ✅ Full | Extensively hardened during this review: exact-match algorithm dispatch (MD5/SHA1/SHA224/SHA256/SHA384/SHA512), BADALG handling, RFC 4635-compliant MAC truncation, and NOTAUTH + TSIG RR responses on both UPDATE and NOTIFY failure paths (`dns_wire.c`, `dns_server_core.c`) |
| RFC 2930 | Secret Key Establishment for DNS (TKEY) | ❌ No | Not implemented (explicitly out of scope) |
| RFC 7873 | Domain Name System (DNS) Cookies | ✅ Full | Client/server cookie parsing and generation (`dns_wire.c`) |
| RFC 9018 | Interoperable Domain Name System (DNS) Server Cookies | ✅ Full | `generate_server_cookie()` implements the interoperable 16-byte format (Version(1) + Reserved(3) + Timestamp(4) + Hash(8)) recommended by RFC 9018 (`dns_server_core.c`, ~line 2778) |

## 5. Rate Limiting / Operations

| RFC / Draft | Title | Status | Evidence / Notes |
|---|---|---|---|
| (Not formally standardized; de facto industry practice. Originating draft `draft-vixie-dnsext-rrl` has expired) | Response Rate Limiting (RRL) | ✅ Full | Keyed-hash bucket table, per-class token buckets, slip mechanism (`dns_server_core.c`) |
| RFC 8914 | Extended DNS Errors (EDE) | ✅ Full | `add_ede` used across numerous response paths (`dns_server_core.c`) |
| RFC 5452 | Measures for Making DNS More Resilient against Forged Answers | ✅ Full | Audited and confirmed: `broker_connect` (used for outbound AXFR/IXFR TCP connections) never explicitly `bind()`s a local port, relying on OS-assigned ephemeral ports; transaction IDs for both AXFR/IXFR pulls and outbound NOTIFY are generated via `arc4random() & 0xFFFF` (cryptographically secure). No code changes were required — the existing architecture already satisfied the requirements |

## 6. Newer Query Mechanisms

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 10029 | DNS Multiple QTYPEs (MQTYPE) | ✅ Full (opt-in, default OFF) | Implemented and hardened over multiple review rounds during this engagement, including strict truncation-avoidance semantics (additional QTYPEs must never force truncation of the primary response) and full FORMERR coverage. Disabled unless `rfc10029-mqtype yes;` is explicitly set (`dns_server_core.c`, `dns_wire.c`, `dns_config_parser.c`) |
| RFC 9460 | Service Binding and Parameter Specification via the DNS (SVCB/HTTPS) | ✅ Full | A complete server-side serialization implementation exists in `dns_wire.c`'s `serialize_dns_record`, correctly encoding `alpn`, `port`, `ipv4hint`/`ipv6hint`, `ech`, `mandatory`, and generic `keyNNN` SvcParams from zone-file text syntax into wire format |

## 7. Out of Scope

| RFC | Title | Status | Notes |
|---|---|---|---|
| RFC 7858 | DNS over TLS (DoT) | ➖ N/A | Out of scope given the current authoritative-server design |
| RFC 8484 | DNS over HTTPS (DoH) | ➖ N/A | Same as above |
| RFC 9250 | DNS over QUIC (DoQ) | ➖ N/A | Same as above |
| RFC 9498 | Fully Encrypted Authority | ➖ N/A | Depends on encrypted-transport infrastructure outside the current design's scope |
| RFC 7871 | Client Subnet in DNS Queries (ECS) | ❌ No | No corresponding code in the EDNS option parser. Deliberately deprioritized — `view`/`match-clients` (source-IP-based split-horizon) already covers this deployment's needs, since ECS specifically solves the "query arrives via a third-party recursive resolver, true client subnet unknown" problem, which does not apply when clients query KariDNS directly |
| RFC 7828 | The edns-tcp-keepalive EDNS0 Extension | ❌ No | No corresponding code |
| RFC 7830 | The EDNS(0) Padding Option | ❌ No | No corresponding code |
| RFC 5001 | DNS Name Server Identifier (NSID) Option | ❌ No | No corresponding code |
| RFC 8020 | NXDOMAIN: There Really Is Nothing Underneath | ➖ N/A | Recursive-resolver caching guidance; does not apply to an authoritative server |
| RFC 8499 | DNS Terminology | ➖ N/A | Glossary; not an implementation target |
| RFC 6895 | DNS IANA Considerations | ➖ N/A | Registry operating procedures; not an implementation target |
| RFC 7208 | Sender Policy Framework (SPF) | ✅ Full (as TXT) | The dedicated SPF RR type (99) is recognized, but the RFC itself mandates using TXT instead of a dedicated type going forward — KariDNS serves TXT correctly, satisfying the RFC's actual guidance |

---

## Verification Status Note

Items marked ✅ Full for changes made during this review round (RFC 8624, RFC 2181, RFC 8976/ZONEMD,
RFC 7766/9210, RFC 1912, RFC 5452) have been confirmed to compile cleanly (all touched files rebuilt
individually with zero errors) and, where feasible from this reviewer's Linux-based sandbox, verified
functionally:
- ZONEMD verification was independently re-run against the official RFC 8976 Appendix A.4 test vector
  and confirmed VALID.
- `karicheck` was rebuilt as a real binary and run against every existing test zone in the repository
  with no crashes or parsing regressions attributable to the `unescape_string_in_place` fix.

**Full-stack runtime verification (server startup, live AXFR, TCP connection-reuse behavior under
load, ASan/UBSan smoke tests) requires a FreeBSD environment and has not yet been independently
confirmed by this reviewer.** Confirm this on real FreeBSD hardware/VM before considering the branch
final.

## Remaining Open Items (for future consideration)

- **RFC 8624**: consider extending the `karicheck` algorithm-status table as new algorithms are
  registered by IANA/added to future RFC 8624 successors.
- **RFC 7344**: automated CDS/CDNSKEY → parent DS reflection remains unimplemented (static serving
  only); would require an out-of-band publication mechanism, likely out of scope for this server's
  architecture.
- **RFC 8976**: duplicate-RR detection currently relies on adjacent-after-sort comparison; sufficient
  for the common case but worth revisiting if non-adjacent duplicate patterns are ever a concern.

---

*This document reflects a source-code audit performed at a specific point in time. Update it whenever
the implementation changes.*

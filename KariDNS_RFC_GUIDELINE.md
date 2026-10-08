# KariDNS RFC Compliance Guideline

This document catalogs the DNS-related standards (RFCs, etc.) implemented by KariDNS, in the same
spirit as NLnet Labs' (NSD) [RFC Compliance](https://nsd.docs.nlnetlabs.nl/en/latest/reference/rfc-compliance.html)
page and PowerDNS's [Compliance](https://www.powerdns.com/compliance) page.

**This document is based on direct source-code inspection.** Each entry cites the relevant file /
function name as evidence. Test coverage is tracked separately: the tests are indexed in
[`tests/TEST_MATRIX.md`](tests/TEST_MATRIX.md) (section 2 maps each RFC to its tests) and line/branch coverage in
[`docs/COVERAGE_STATUS.md`](docs/COVERAGE_STATUS.md). **Implementation status and test coverage are two different axes.**

Legend:
- ✅ **Full** — Core requirements (MUST/SHOULD) are implemented. Deliberate deviations are named in the notes.
- 🟡 **Partial** — Partially implemented, or implemented with limitations (listed in the notes)
- ❌ **No** — Not implemented
- ➖ **N/A** — Out of scope for this server's purpose (authoritative, non-recursive, static DNSSEC)

---

## 1. Core Protocol

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 1034 | Domain Names - Concepts and Facilities | ✅ Full | Core namespace model and the §4.3.2 lookup algorithm (`dns_query_engine.c`). After a CNAME or DNAME the zone for the new name is chosen again among the zones of the client's view (§4.3.2 step 3a, `find_zone_for_query()`). Records outside the zone are not loaded or transferred (§4.2, logged as "ignoring out-of-zone data") |
| RFC 1035 | Domain Names - Implementation and Specification | ✅ Full | Wire format, name compression only where §4.1.4 / RFC 3597 §4 allow it, base record types. Master files (§5.1): `\DDD` / `\X` escapes in names and character strings, case-insensitive type and class mnemonics, `$ORIGIN` / `$INCLUDE` / `$TTL`, and BIND's extensions (`$GENERATE`, omitted-TTL rules) (`dns_zone_parser.c`). Names are kept in one canonical text form by every loader, the query parser and the XFR/UPDATE decoders (`dns_wire.c`, `dns_utils.c`). A compression pointer in the question name is answered with FORMERR (§4.1.4: it cannot point to an earlier name) |
| RFC 1123 | Requirements for Internet Hosts (applicable parts) | ✅ Full | General hostname rules |
| RFC 1912 | Common DNS Operational and Configuration Errors | ✅ Full | `karicheck` warns when NS/MX/SOA MNAME targets point to a CNAME (and SRV targets, RFC 2782), and when a CNAME co-exists with non-DNSSEC record types at the same owner name (`tools/karicheck.c`) |
| RFC 1982 | Serial Number Arithmetic | ✅ Full | Used for IXFR, NOTIFY, refresh and UPDATE serial comparisons (`serial_is_newer()` in `dns_utils.c`) |
| RFC 1995 | Incremental Zone Transfer (IXFR) | ✅ Full | Server: history of differences per zone (`ixfr_history_t`, `compute_ixfr_diff()` in `dns_axfr_ixfr.c`); a client serial that is equal to or newer than the zone's gets the current SOA only, over TCP and UDP (§2); a request without the client's SOA in the Authority section gets FORMERR (§3); a full AXFR-style answer when the history does not reach back. A KariDNS secondary's IXFR is answered incrementally unless the zone carries KariDNS-only data (location/ECS tags, then Extended AXFR). Client (secondary): refreshes with IXFR and falls back once to AXFR when the primary answers FORMERR or NOTIMP (§4) |
| RFC 1996 | A Mechanism for Prompt Notification of Zone Changes (NOTIFY) | ✅ Full | Outbound: to `also-notify` and the apex NS hosts except the SOA MNAME host, after UPDATE, a successful transfer and a reload that changes the serial; retransmitted until answered (§3.6; `notify-retries`, `notify-retry-interval`, `notify-retry-backoff`, default 60 s and 5 retransmissions), signed with the zone's `tsig-key` and the answer verified (`dns_dynamic_update.c`). Inbound: accepted from a `masters` address and, when the zone has `tsig-key`, only when signed with that key (`dns_query_engine.c`). `forward` / `program` zones answer NOTIFY with NOTIMP (question and OPT only, EDE 21) |
| RFC 2181 | Clarifications to the DNS Specification | ✅ Full | TTL values with the high bit set (≥ 2^31) are served as 2147483647 (RFC 8767 §4 amends §8) on every path: zone file parser, record encoder (`serialize_dns_record()`), zone transfer and UPDATE receive paths, tinydns loader. RRsets are written whole (§5; `emit_rrset()`), and a response that does not fit sets TC (§9) |
| RFC 2308 | Negative Caching of DNS Queries | ✅ Full | NXDOMAIN/NODATA carry the zone SOA in the Authority section with TTL = min(SOA TTL, SOA MINIMUM) (§3, §5), and its RRSIG with the same TTL when DO=1 (`dns_query_engine.c`) |
| RFC 2317 | Classless IN-ADDR.ARPA Delegation (BCP 20) | ✅ Full | Sub-/24 reverse DNS delegation is supported via standard CNAME redirection |
| RFC 3225 | Indicating Resolver Support of DNSSEC (DO bit in EDNS) | ✅ Full | DO bit (0x8000) parsed from the EDNS flags and used to gate RRSIG/NSEC/NSEC3 inclusion (`dns_wire.c`, `dns_query_engine.c`) |
| RFC 3597 | Handling of Unknown DNS Resource Record (RR) Types | ✅ Full | `TYPE<n>`, `CLASS<n>` and the `\#` RDATA syntax in zone files (§5), no name compression in unknown RDATA (§4) (`dns_utils.c` `get_type_code()`, `dns_wire.c`) |
| RFC 4343 | DNS Case Insensitivity Clarification | ✅ Full | Owner names are compared label by label, ASCII case-insensitively, also for names with escaped octets (`dns_wire.c`, `dns_utils.c`). TSIG key names are compared as DNS names. UPDATE and IXFR compare RDATA in RFC 4034 canonical form, so names in RDATA match regardless of case. |
| RFC 4592 | The Definition of Phrases with Wildcards in the Domain Name System | ✅ Full | Wildcard expansion/synthesis (e.g., `*.example.com`) in the resolution path, including NODATA for empty non-terminals (`dns_query_engine.c`) |
| RFC 6891 | Extension Mechanisms for DNS (EDNS(0)) | ✅ Full | OPT parsing and assembly (`dns_wire.c`). An unusable OPT (several OPTs, owner not root, not in the Additional section, truncated RDATA) gets FORMERR without OPT; other FORMERR, BADVERS and error responses to a query with OPT carry an OPT (§7). EDNS version > 0 gets BADVERS, for queries and for AXFR/IXFR (§6.1.3). A UDP payload size below 512 is treated as 512 (§6.2.5). Unknown options are ignored (§6.1.2). Obsoletes RFC 2671 |
| RFC 7766 | DNS Transport over TCP - Implementation Requirements | 🟡 Partial | Connection reuse is supported but off by default (`tcp-connection-reuse yes;`; §6.2.1 says servers SHOULD support it). Pipelined queries are read and answered in the order they arrive, not concurrently (§6.2.1.1 SHOULD). Timeouts (§6.2.3): `tcp-initial-timeout` (default 10 s) for the first query, `tcp-idle-timeout` (default 10 s, RFC 9210 §4.5) between queries; partially received messages do not extend the deadline; every connection is closed 60 s after it was opened at the latest. Length and message are sent in one write (§8) (`dns_server_core.c`). `dag` reuses connections with `+keepopen` (`tools/dag_transport.c`). Obsoletes RFC 5966 |
| RFC 8482 | Providing Minimal-Sized Responses to ANY Queries | ✅ Full | `minimal-any` / `minimal-any-ttl` settings (`dns_config_parser.h`) |
| RFC 8767 | Serving Stale Data to Improve DNS Resiliency | 🟡 Partial | This RFC targets recursive resolver caches; KariDNS repurposes the term for a `serve-stale` toggle controlling whether a secondary keeps serving its last-known zone data after the SOA EXPIRE interval has passed without a successful refresh (answers then carry EDE 3, Stale Answer; with `serve-stale no` the zone answers SERVFAIL with EDE 24, Invalid Data). §4 (TTLs ≥ 2^31 become 2147483647) is implemented, see RFC 2181 |
| RFC 8906 | A Common Operational Problem in DNS Servers: Failure to Communicate (Fragmentation) | ✅ Full | The UDP response size and the advertised EDNS UDP payload size are capped at 1232 bytes by default (avoids IP fragmentation, matches the 2020 DNS Flag Day recommendation). The cap can be changed with `udp-bufsize` / `zone-udp-bufsize` (512–4096); the requestor's smaller payload size always wins, including exactly 512 |
| RFC 9619 | In the DNS, QDCOUNT Is (Usually) One | ✅ Full | §4: a QUERY (OPCODE 0) with QDCOUNT > 1 is answered with FORMERR. A QUERY with QDCOUNT = 0 is not treated as malformed: it gets a NOERROR header without a question (with OPT and a fresh server cookie for a cookie-only query, RFC 7873 §5.4); with an MQTYPE option it is FORMERR (RFC 10029). NOTIFY and UPDATE need QDCOUNT (ZOCOUNT) = 1 (`dns_query_engine.c`) |
| RFC 9210 | DNS Transport over TCP - Operational Requirements | 🟡 Partial | Same mechanism and limits as RFC 7766 above (connection reuse off by default); the default idle timeout (10 s) matches §4.5's recommendation |
| RFC 9471 | DNS Glue Requirements in Referral Responses | ✅ Full | Referrals carry the A and AAAA glue that the zone holds for the delegation's name servers, and TC is set when it does not fit (§3; RFC 2181 §9: no partial address RRsets) (`append_glue_records()` in `dns_query_engine.c`). `karicheck` reports delegations without the glue they need |
| RFC 7314 | Extension Mechanisms for DNS (EDNS) EXPIRE Option | ✅ Full (Server) / ✅ Full (Client `dag`) | §3: queries with a zero-length option 9 to an authoritative zone get the SOA EXPIRE (primary) or the remaining expire timer (secondary), also in the first AXFR/IXFR message; §3.3: no option in responses the server is not authoritative for (`dns_query_engine.c`, `send_axfr_response()` in `dns_axfr_ixfr.c`). §4: a secondary adds the option to its AXFR/IXFR requests and sets its expire timer from the returned value (transfer: initialised from it; up to date: the larger of it and the current timer), capped by SOA EXPIRE (`xfr_expire_deadline()`). KariDNS secondaries refresh with IXFR/AXFR only (no separate SOA refresh query). `dag` sends the option with `+expire` and prints the value like `dig` (`EXPIRE: N (duration)`) |
| RFC 5001 | DNS Name Server Identifier (NSID) Option | ✅ Full (requires `nsid` config) | Server responds with a configured identifier string via EDNS option code 3 when queried with an empty NSID option, provided `nsid "<value>";` is set. `dag` client supports requesting and decoding NSID (`+nsid`) |
| RFC 7828 | The edns-tcp-keepalive EDNS0 Extension | ✅ Full (Server, opt-in, tied to `tcp-connection-reuse`) / 🟡 Partial (Client `dag`) | Server: when `tcp-connection-reuse yes;` is set and a client sends the option over TCP, the server returns its idle timeout (`tcp-idle-timeout`, in 100 ms units, §3.2); never in UDP responses (§3.2.1) (`dns_wire.c`). `dag +keepalive` also sends the option over UDP, as `dig` 9.20 does, although §3.2.1 says clients MUST NOT (deliberate, for `dig` compatibility) |
| RFC 7871 | Client Subnet in DNS Queries (ECS) | ✅ Full (Server, authoritative record steering) / ✅ Full (Client `dag`) | Server: the option is used only from `ecs-trusted-resolvers` with `ecs-enable yes;` (with `ecs-enable no` it is ignored, §7.1.1); a malformed option is FORMERR with OPT (§6, §7.2.1). The response echoes FAMILY, SOURCE PREFIX-LENGTH and ADDRESS unchanged (§6) and sets SCOPE PREFIX-LENGTH to the shortest prefix around the client address for which the answer is the same (§7.2.1, overlapping tags split); SCOPE 0 when the answer does not depend on the subnet and for negative answers and referrals (§7.4) (`resolve_ecs_subnet_tag()` in `dns_edns_ecs.c`, `dns_wire.c`). This is authoritative-side record steering, not recursive-resolver ECS forwarding/caching. `dag` sends and prints the option (`+subnet=addr/prefix`) |

---

## 2. Zone Transfer / Redundancy / Forwarding

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 5936 | DNS Zone Transfer Protocol (AXFR) | ✅ Full | Serving: `send_axfr_response()` (`dns_axfr_ixfr.c`): access through `allow-transfer` / `tsig-key` (refused without them), an OPT in the first message when the query had one (§2.2.5), SERVFAIL with EDE 14 for a zone without data, at most 4 transfers per zone at a time. Receiving (secondary zones): `handle_axfr_event()` checks the ID, QR, OPCODE and question of every message (§2.2.1), ends the transfer at an error RCODE, verifies the TSIG of signed transfers, keeps DNSSEC records as received (RDATA unchanged) and skips out-of-zone records with a log line instead of rejecting the zone |
| RFC 1995 | IXFR | ✅ Full | See section 1 above |
| RFC 9432 | DNS Catalog Zones | ✅ Full | Schema version 2 (`version.<catalog> TXT "2"` required), members under `zones.<catalog>` served as secondary zones, `coo` (change of ownership, §5.3.1) and `group` properties; members are identified by (name, unique-id), so a property change does not reset the member zone (§5.4) (`catalog_process_membership()` in `dns_catalog_zone.c`, `catalog-zone yes;`) |
| RFC 7477 | Child-to-Parent Synchronization in DNS (CSYNC) | ✅ Full | Record type supported and serialized (`dns_wire.c`, case 62); the synchronization itself is the parent's job |
| RFC 9859 | Generalized DNS Notifications (DSYNC) | ✅ Full | DSYNC(66) is serialized in the wire-format path (`dns_wire.c`, case 66), including the notify-RRtype, scheme (`NOTIFY` or numeric), port, and target fields. `karicheck` additionally validates that the DSYNC RRtype mnemonic is a recognized type (`tools/karicheck.c`). `dag` client formats DSYNC RDATA per RFC 9859 |
| (Zone Forwarding) | Forward Zone Query Relaying | ✅ Full | `type "forward"` zones forward queries to the `forwarders` in order within one `forward-timeout` budget: each forwarder gets the remaining time divided by the number of forwarders not tried yet; replies whose ID, QR bit or question do not match are discarded and the wait continues (RFC 5452 §9.1); random transaction IDs; TC triggers a TCP retry within the remaining budget (`dispatch_forward_zone()` in `dns_query_engine.c`) |

---

## 3. DNSSEC

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 4033/4034/4035 | DNS Security Introduction / Resource Records / Protocol Modifications | ✅ Full (serving pre-signed zones) / ➖ N/A (signing, key management) | Pre-signed RRSIG/DNSKEY/DS/NSEC/NSEC3 from the zone file or from a transfer are served with DO=1 (RFC 4035 §3.1): every RRset is followed by its RRSIGs (`emit_rrset()`), in the Answer, in the Authority section (apex NS, negative-answer SOA, NSEC/NSEC3 proofs, DS or its denial at referrals) and for in-zone address records in the Additional section (glue stays unsigned, §2.2); TC is set when required RRSIGs do not fit (§3.1.1); no RRSIG or NSEC is written twice (ANY). A DS query for the apex of a child zone that the server also serves is answered from the parent zone (§3.1.4.1, `find_zone_for_query()`). AD is never set. **Deviation**: the CD bit of the query is copied into the response as BIND does (§3.1.6 says SHOULD clear; maintainer decision). No online signing or automated key management (ZSK/KSK rollover). Obsoletes RFC 2535 |
| RFC 5155 | DNSSEC Hashed Authenticated Denial of Existence (NSEC3) | ✅ Full (serving) | Closest-encloser, next-closer and wildcard proofs for NXDOMAIN, NODATA and wildcard answers (§7.2), DS NODATA and opt-out proofs at delegations (§7.2.4, §7.2.7), no NSEC for NSEC3-signed zones (`dns_query_engine.c`). One NSEC3PARAM is chosen per zone when the index is built (Flags 0 only, salt of up to 255 octets, a complete chain first; §4.1.2, §7.3), and lookups use a sorted index per chain with binary search (`build_zone_index()`, `select_nsec3_params()` in `dns_zone_parser.c`). Direct NSEC3/NSEC3PARAM queries are answered |
| RFC 6840 | Clarifications and Implementation Notes for DNSSEC | ✅ Full | §5.1 canonical form: only the RDATA names of the types listed in RFC 4034 §6.2 (without NSEC's Next Domain Name) are lower-cased, in the comparisons that need the canonical form (UPDATE, IXFR) and in `karicheck`'s ZONEMD digest (`kc_canonical_rr()`). Answers keep the case of the zone, so RRSIGs over RRsets with upper-case names in the RDATA of other types validate |
| RFC 7344 | Automating DNSSEC Delegation Trust Maintenance (CDS/CDNSKEY) | 🟡 Partial (serving only, automation ➖ N/A by design) | CDS(59)/CDNSKEY(60) record types are recognized, stored, and served (`dns_utils.c`), fulfilling this server's role as the *child*-side authoritative server. The RFC's automation mechanism (parent-side scanning of CDS/CDNSKEY, or child-side push to the parent registrar) is intentionally out of scope: it either belongs to the parent registry's own software, or to a registrar-API integration layer that is architecturally independent of an authoritative DNS server. This is a permanent design decision consistent with this server's "static DNSSEC only" scope, not a pending TODO. |
| RFC 8078 | Managing DS Records from the Parent via CDS/CDNSKEY | 🟡 Partial (serving only, automation ➖ N/A by design) | Updates RFC 7344 for parent-side automation. Child-side CDS/CDNSKEY serving is supported; `karicheck` checks the delete signals. Parent-side registry synchronization is out of scope by design |
| RFC 8080 | EdDSA for DNSSEC | 🟡 Partial | The DNSKEY/RRSIG Algorithm field is passed through opaquely with no algorithm-specific logic (`serialize_dns_record()` in `dns_wire.c`). Ed25519(15)/Ed448(16) can therefore be served, but this is a byproduct of algorithm-agnostic passthrough rather than dedicated EdDSA support |
| RFC 8624 | Algorithm Implementation Requirements and Usage Guidance for DNSSEC | ✅ Full | `karicheck` keeps a table of DNSSEC algorithm numbers and their RFC 8624 status, and warns (non-fatal) when a DNSKEY/CDNSKEY/RRSIG uses an algorithm marked MUST NOT or NOT RECOMMENDED (e.g., RSAMD5, DSA, RSASHA1) (`tools/karicheck.c`). The server itself is algorithm-agnostic by design (static DNSSEC); this is an advisory check only. Obsoletes RFC 6944 |
| draft-westerbaan-dnssec-mldsa (-04) | ML-DSA for DNSSEC (algorithm 18, `MLDSA44`) | 🟡 Partial | Server: algorithm-agnostic passthrough as for the other algorithms, plus support for the large values — a 1312-octet public key and a 2420-octet signature (3228 base64 characters) that signed zones split into more pieces than `MAX_RDATA`: the zone parser joins the trailing base64/hex pieces of DNSKEY/RRSIG/KEY/SIG/DS/... (`trailing_blob_lead_fields()` in `dns_zone_parser.c`) and the base64 decoder is no longer limited to 2 KiB (`decode_concat_b64_rdata()` in `dns_wire.c`). `karicheck` knows algorithm 18 (MAY) and warns when its public key / signature is not 1312 / 2420 octets. `dag`: shows `alg = MLDSA44`, and signs SIG(0) with ML-DSA-44 keys (pure ML-DSA, empty context; PEM or BIND `.private` with the 32-octet seed or the 2560-octet private key) when built against OpenSSL 3.5+ (`sig0_sign_packet()` in `dns_wire.c`, `tools/dag_tsig_client.c`). No validation (KariDNS is not a validator) |
| RFC 8901 | Multi-Signer DNSSEC Models | ➖ N/A | Not applicable — this server does not perform online signing, so multi-signer coordination models don't apply |
| RFC 9824 | Compact Denial of Existence in DNSSEC (NXNAME) | ➖ N/A (mechanism) / 🟡 Partial (validation) | The Compact DoE *mechanism* itself requires online signing and is out of scope for this static-DNSSEC server. However, `karicheck` enforces the RFC's own requirement that NXNAME(128) — a synthetic meta-type — must never appear as a standalone RRset in zone-file data, flagging it as an error if found (`tools/karicheck.c`). The NXNAME(128) type mnemonic is also recognized by the record-type table (`dns_utils.c`) |
| RFC 8976 | Message Digest for DNS Zones (ZONEMD) | ✅ Full (`karicheck`) / ❌ No (server verification) | `karicheck zone` / `karicheck zones` verify every ZONEMD record with scheme 1 (SIMPLE) and hash algorithm 1 (SHA-384) or 2 (SHA-512) (`verify_zonemd()` in `tools/karicheck.c`): RRs in DNSSEC canonical form and order (§3.3.1, RFC 4034 §6.2 and §6.3, RFC 6840 §5.1), duplicates digested once, the apex ZONEMD RRset and its RRSIGs excluded and non-apex ZONEMD RRs included, out-of-zone records not part of the zone; a duplicated (scheme, hash algorithm) pair or a wrong digest length is an error, other schemes and algorithms are reported as not verified (§4). Checked against all RFC 8976 Appendix A examples (A.1–A.5) and against `ldns-signzone` output. The server serves ZONEMD records but does not verify them, neither at load time nor after a transfer (§4 verification by recipients is left to `karicheck` before publication) |
| RFC 9276 | Guidance for NSEC3 Parameter Settings | ✅ Full | `karicheck` warns when NSEC3PARAM or an NSEC3 chain has iterations > 0 (error above 100), a salt, or opt-out set (§3.1), and checks each NSEC3 chain against the NSEC3PARAM the server uses (`tools/karicheck.c`) |

---

## 4. Dynamic Update / Authentication

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 2136 | Dynamic Updates in the Domain Name System (DNS UPDATE) | 🟡 Partial | Prerequisite and update sections follow the §3.2.5 and §3.4.2.7 pseudocode (`process_update_sections()` in `dns_wire.c`, `handle_dynamic_update()` in `dns_dynamic_update.c`): a zone section that does not name a zone of the client's view gets NOTAUTH, out-of-zone RRs NOTZONE; RRs that §3.4.2 says to ignore (CNAME conflicts, an SOA that is not newer, deletion of the apex SOA or of the last apex NS) are ignored; an error leaves the zone unchanged; an SOA with a newer serial is kept, other changes increment the serial (§3.6; SERVFAIL if that fails), and an update that changes nothing keeps the serial. RRs are compared in canonical form. Enabled per zone with `allow-update`. Limits: updates are kept in memory only and lost on restart or reload (§3.5 requires nonvolatile storage; out of scope by design), and an update sent to a secondary zone is answered with REFUSED (EDE 18) instead of being forwarded to the primary (§6). `forward` / `program` zones answer UPDATE with NOTIMP |
| RFC 3007 | Secure Domain Name System (DNS) Dynamic Update | 🟡 Partial | Updates can be authorized by TSIG keys (`allow-update { key "<name>"; }`, RFC 8945) or by address. The server does not verify SIG(0) (RFC 2931); `dag` can sign updates with SIG(0) for other servers |
| RFC 8945 | Secret Key Transaction Authentication for DNS (TSIG) | ✅ Full | HMAC-MD5/SHA1/SHA224/SHA256/SHA384/SHA512. The request TSIG is checked first, with the key the request names, the same way for QUERY, NOTIFY, UPDATE and AXFR/IXFR (§5.2): a malformed or misplaced TSIG, several TSIGs or a MAC size outside §5.2.2.1 → FORMERR; unknown key or algorithm → BADKEY and a bad MAC → BADSIG (NOTAUTH, unsigned, §5.3.2); a time outside the fudge → BADTIME (signed, the client's Time Signed and Fudge, server time in Other Data, §5.2.3); a truncated MAC → BADTRUNC (signed; truncated MACs are not accepted, like BIND without `digest-bits`). Original ID is used for the digest (§4.2). Every response to a validly signed request is signed with the request's key (§5.3), including access-control REFUSED and RRL slip answers; a signed response that does not fit UDP is truncated. Outbound NOTIFY and transfer requests are signed with the zone's `tsig-key` and their answers verified (`dns_wire.c`, `dns_tsig_acl.c`, `dns_query_engine.c`, `dns_axfr_ixfr.c`). Key names are compared as DNS names. Obsoletes RFC 2845 and RFC 4635 |
| RFC 2930 | Secret Key Establishment for DNS (TKEY) | ❌ No | Not implemented (explicitly out of scope) |
| RFC 7873 | Domain Name System (DNS) Cookies | ✅ Full | Client/server cookie parsing and generation; a COOKIE option of the wrong length is FORMERR with OPT (§5.2.2) (`dns_wire.c`, `dns_edns_ecs.c`, `dns_query_engine.c`) |
| RFC 9018 | Interoperable Domain Name System (DNS) Server Cookies | ✅ Full | Version-1 Server Cookie (Version(1) + Reserved(3) + Timestamp(4) + Hash(8)) with `Hash = SipHash-2-4(Client Cookie \| Version \| Reserved \| Timestamp \| Client-IP, Server Secret)` (`dns_edns_ecs.c`: `generate_server_cookie()` / `verify_server_cookie()`, `dns_siphash.h`). Server Secret is configurable via `cookie-secret` (up to 4; first generates, all verify = RFC 9018 §5 rollover); `cookie-algorithm` accepts only `siphash24`. Reserved is zero on construction and hashed as received on verification (§4.2); timestamps use RFC 1982 serial arithmetic with a 1 h past / 5 min future window (§4.3); cookies older than 30 min are refreshed; the option length must be exactly 16 (§4.4). Without `cookie-secret` a random per-process secret is used (valid, but not interoperable across servers). Verified by RFC 9018 Appendix A.1–A.4 vectors in `tests/test_rfc_vectors.c` and end-to-end in `tests/test_query_engine_expanded.c` |

---

## 5. Rate Limiting / Operations

| RFC / Draft | Title | Status | Evidence / Notes |
|---|---|---|---|
| (Not formally standardized; de facto industry practice. Originating draft `draft-vixie-dnsext-rrl` has expired) | Response Rate Limiting (RRL) | ✅ Full | Token buckets keyed like BIND 9: client prefix (`ipv4-prefix-length` / `ipv6-prefix-length`, default /24 and /56), response kind, and QNAME / zone / delegation point; `responses-per-second`, `nodata-per-second`, `nxdomains-per-second`, `errors-per-second`, `referrals-per-second`, `all-per-second`, `window`, `slip` (`dns_rrl.c`). Server-wide or per-zone `rate-limit` blocks; applies to standard, forward and program zones (`early-drop` skips the program for exhausted clients). Slip answers to signed requests are signed. Differences from BIND are listed in `docs/karidns.md` |
| RFC 8914 | Extended DNS Errors (EDE) | ✅ Full | `add_ede()` (`dns_edns_ecs.c`) on error paths, e.g. 3 Stale Answer, 14 Not Ready, 18 Prohibited, 20 Not Authoritative, 21 Not Supported, 24 Invalid Data (`dns_query_engine.c`, `dns_server_core.c`); can be disabled with `send-extended-errors no;` |
| (dnstap, not an RFC) | dnstap query/response logging | ✅ Full | `AUTH_QUERY` / `AUTH_RESPONSE` messages over Frame Streams to a UNIX socket (`dns_dnstap.c`), configured with `dnstap { socket ...; }`; reconnects through the connect broker, ends the stream with STOP/FINISH at shutdown |
| RFC 5452 | Measures for Making DNS More Resilient against Forged Answers | ✅ Full | Outbound connections use OS-assigned ephemeral ports; transaction IDs for AXFR/IXFR requests, outbound NOTIFY and forward zones come from `arc4random()`. Answers are accepted only with the matching ID, QR, OPCODE and question: forward zones (mismatches discarded, waiting continues), zone transfers, NOTIFY answers, and `dag` over UDP and TCP (§9.1) |

---

## 6. Newer Query Mechanisms & Transport Extensions

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 10029 | DNS Multiple QTYPEs (MQTYPE) | ✅ Full (opt-in, default OFF) | Additional QTYPEs never force truncation of the primary response; a duplicated option, an MQTYPE-Response option in a query, or an MQTYPE-Query with QDCOUNT = 0 is FORMERR (§3.3). With DO=1 the RRSIGs of the QTYPE and of each additional type are included. Gated behind `rfc10029-mqtype yes;`, at most `max-mqtypes` (default 4) additional types (`dns_query_engine.c`, `dns_wire.c`, `dns_config_parser.c`). `dag` formats MQTYPE-Query / MQTYPE-Response per Appendix A.1 (`tools/dag.c`) |
| RFC 9460 | Service Binding and Parameter Specification via the DNS (SVCB/HTTPS) | ✅ Full | Server-side serialization in `serialize_dns_record()` (`dns_wire.c`), encoding `alpn`, `port`, `ipv4hint`/`ipv6hint`, `ech`, `mandatory`, and generic `keyNNN` SvcParams; TargetName never compressed. `dag` supports structured decoding and presentation |
| RFC 6066 | Transport Layer Security (TLS) Extensions: Extension Definitions (SNI) | ✅ Full (Client `dag`) | `dag` enforces RFC 6066 §3 by stripping trailing dots from domain names before setting TLS Server Name Indication (`clean_sni_host`, `tools/dag_transport.c`) |
| RFC 7230 | Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing | ✅ Full (Client `dag`) | `dag` DoH exchange enforces RFC 7230 §3.3.3 framing precedence where `Transfer-Encoding: chunked` overrides `Content-Length` (`decode_http_response_body()` in `tools/dag_transport.c`) |
| RFC 7050 | Discovery of the IPv6 Prefix Used for IPv6 Address Synthesis | ✅ Full (Client `dag`) | `dag` supports RFC 7050 prefix discovery queries via `+dns64prefix` (`tools/dag.c`) |

---

## 7. Specific Resource Records

| RFC | Title | Status | Evidence / Notes |
|---|---|---|---|
| RFC 1035 | Base Record Types (A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT) | ✅ Full | Parsed and serialized in wire format (`dns_wire.c`, `dns_utils.c`, `dns_zone_parser.c`). WKS accepts protocol and port mnemonics (§3.4.2) |
| RFC 1183 | New DNS RR Definitions (AFSDB, RT, RP, X25, ISDN) | ✅ Full | Custom wire serialization logic is implemented for all these types (`dns_wire.c`, cases 17-21) |
| RFC 1876 | A Means for Expressing Location Information in the Domain Name System (LOC) | ✅ Full | Supported and serialized (`dns_wire.c`, case 29) |
| RFC 2230 | Key Exchange Delegation Record for the DNS (KX) | ✅ Full | Supported and serialized (`dns_wire.c`, case 36) |
| RFC 2535 / RFC 2931 | DNS Security Extensions (SIG, KEY, NXT) | ✅ Full (legacy serving) | Supported in record-type table and wire serialization (`dns_wire.c`, `dns_utils.c`) |
| RFC 2782 | A DNS RR for specifying the location of services (SRV) | ✅ Full | SRV supported and serialized with uncompressed target name per RFC 2782 (`dns_wire.c`, case 33) |
| RFC 3123 | A DNS RR Type for Lists of Address Prefixes (APL) | ✅ Full | Supported and serialized (`dns_wire.c`, case 42) |
| RFC 3403 | Dynamic Delegation Discovery System (DNS) Database (NAPTR) | ✅ Full | NAPTR supported and serialized (`dns_wire.c`, case 35) |
| RFC 3596 | DNS Extensions to Support IP Version 6 (AAAA) | ✅ Full | AAAA supported and cached (`dns_wire.c`, case 28) |
| RFC 4025 | A Method for Storing IPsec Keying Material in DNS (IPSECKEY) | ✅ Full | Supported and serialized, including gateway type 0 (`.`) and an omitted public key (§3.1) (`dns_wire.c`, case 45) |
| RFC 4255 | Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints (SSHFP) | ✅ Full | SSHFP supported and serialized (`dns_wire.c`, case 44) |
| RFC 4398 | Storing Certificates in the Domain Name System (CERT) | ✅ Full | Supported and serialized (`dns_wire.c`, case 37) |
| RFC 4701 | Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID) | ✅ Full | Supported and serialized (`dns_wire.c`, case 49) |
| RFC 6672 | DNAME Redirection in the DNS | ✅ Full | DNAME→CNAME synthesis, YXDOMAIN when the synthesized name is too long (`synth_name` in `dns_query_engine.c`). Obsoletes RFC 2672 |
| RFC 6698 | DANE TLSA | ✅ Full | TLSA supported and serialized (`dns_wire.c`, case 52) |
| RFC 6742 | DNS Resource Records for ILNP (NID, L32, L64, LP) | ✅ Full | Supported and serialized (`dns_wire.c`, cases 104-107) |
| RFC 7043 | Resource Records for EUI-48 and EUI-64 Addresses in the DNS | ✅ Full | Supported and serialized (`dns_wire.c`, cases 108-109) |
| RFC 7553 | The Uniform Resource Identifier (URI) DNS Resource Record | ✅ Full | Supported and serialized (`dns_wire.c`, case 256) |
| RFC 7929 | DNS-Based Authentication of Named Entities Bindings for OpenPGP | ✅ Full | Supported and serialized (`dns_wire.c`, case 61) |
| RFC 8005 | Host Identity Protocol (HIP) Domain Name System (DNS) Extension | ✅ Full | Supported and serialized (`dns_wire.c`, case 55) |
| RFC 8162 | Using Secure DNS to Associate Certificates for S/MIME (SMIMEA) | ✅ Full | Supported and serialized (`dns_wire.c`, case 53) |
| RFC 8659 | DNS Certification Authority Authorization (CAA) Resource Record | ✅ Full | CAA supported and serialized (`dns_wire.c`, case 257). Obsoletes RFC 6844 |
| RFC 8777 | DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery (AMTRELAY) | ✅ Full | Supported and serialized (`dns_wire.c`, case 260) |

---

## 8. Out of Scope / Historical / Client-Side

| RFC | Title | Status | Notes |
|---|---|---|---|
| RFC 7858 | DNS over TLS (DoT) | ➖ N/A (Server) / ✅ Full (Client `dag`) | Server does not terminate DoT directly (Capsicum separation). `dag` client natively supports DoT (`+tls`, `+tls-ca`, `+tls-hostname`, `+tls-certfile`, `+tls-keyfile`) |
| RFC 8484 | DNS over HTTPS (DoH) | ➖ N/A (Server) / 🟡 Partial (Client `dag`) | Server does not terminate DoH directly. `dag` supports DoH (`+https`, `+https-get`, `+https-post`, `+http-plain`) over HTTP/1.1 (§5.2 recommends HTTP/2, which `dig` uses), with a random message ID like `dig` (§4.1 recommends 0) |
| RFC 9250 | DNS over QUIC (DoQ) | ➖ N/A | Out of scope given the current authoritative-server design |
| RFC 9498 | Fully Encrypted Authority | ➖ N/A | Depends on encrypted-transport infrastructure outside the current design's scope |
| RFC 7830 | The EDNS(0) Padding Option | ❌ No (Server) / ✅ Full (Client `dag`) | Server does not pad responses. `dag` client supports sending and displaying EDNS padding (`+padding=N`) |
| RFC 8020 | NXDOMAIN: There Really Is Nothing Underneath | ➖ N/A | Recursive-resolver caching guidance; does not apply to an authoritative server |
| RFC 9156 | DNS Query Name Minimisation to Improve Privacy | ➖ N/A (Server) / ✅ Full (Client `dag +trace2 +qmin`) | Obsoletes RFC 7816. Recursive-resolver upstream query minimization; authoritative servers handle minimized queries transparently. `dag +trace2` can minimise its own iterative queries (`+qmin` / `+qmin=ns`, `tools/dag_iter.c`) |
| RFC 8499 | DNS Terminology | ➖ N/A | Glossary; not an implementation target. Obsoletes RFC 7719 |
| RFC 6895 | DNS IANA Considerations | ➖ N/A | Registry operating procedures; not an implementation target |
| RFC 6761 | Special-Use Domain Names | ➖ N/A | Operational guidance for IANA special-use names |
| RFC 6563 | Moving A6 to Historic Status | ➖ N/A | Formally deprecated A6 (TYPE 38) in favor of AAAA (RFC 3596); KariDNS serves AAAA |
| RFC 8749 | Moving DNSSEC Lookaside Validation (DLV) to Historic Status | ➖ N/A | DLV (TYPE 32769) retired; legacy type code supported in parsing/wire serialization |
| RFC 7208 | Sender Policy Framework (SPF) | ✅ Full (as TXT) | The dedicated SPF RR type (99) is recognized, but the RFC itself mandates using TXT instead of a dedicated type going forward — KariDNS serves TXT correctly, satisfying the RFC's actual guidance. Obsoletes RFC 4408 |

---

## Verification Status Note

The table was rewritten on 2026-10-08 after an RFC compliance audit of the server and tools and the fixes that
followed it. Each statement above was checked against the source code and, for the cited sections, against the RFC
text. Where a claim is backed by an automated test, the test is listed for that RFC in
[`tests/TEST_MATRIX.md`](tests/TEST_MATRIX.md) section 2, for example:
- ZONEMD: `tests/run_zonemd_val_test.sh` (RFC 8976 Appendix A.1–A.5) and `tests/run_karicheck_zonemd_ldns_test.sh`
  (differential test against `ldns-signzone`; SKIP when ldns is not installed).
- DNSSEC answers, DS at a hosted child, NSEC3 parameters and transfers of signed zones:
  `tests/run_dnssec_answer_sections_test.sh`, `tests/run_ds_delegation_test.sh`, `tests/test_dnssec_proofs.c` (the RFC 4035 and RFC 5155 example zones),
  `tests/run_dnssec_secondary_test.sh`, `tests/run_nsec3_nxdomain_perf_test.sh`.
- TSIG: `tests/run_tsig_error_matrix_test.sh`, `tests/run_axfr_multikey_tsig_test.sh`, `tests/run_rrl_slip_tsig_test.sh`.
- UPDATE: `tests/run_dynamic_update_test.sh`, `tests/test_dynamic_update_engine.c`.
- Zone transfers and NOTIFY: `tests/run_xfr_notify_test.sh`, `tests/run_ixfr_roundtrip_test.sh`.
- Response headers and EDNS error responses: `tests/run_response_header_test.sh`.

`dag` output is compared with `dig` 9.20 by the `run_dag_*compat*` tests (see `docs/dag.md`).

---

*This document reflects a source-code audit performed at a specific point in time. Update it whenever
the implementation changes.*

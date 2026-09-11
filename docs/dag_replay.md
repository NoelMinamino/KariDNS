# DAG-REPLAY(1) — KariDNS Reference Manual

```text
DAG-REPLAY(1)                  KariDNS Manual                  DAG-REPLAY(1)
```

---

## NAME

**dag --replay** — High-Performance DNS Traffic Replay and Differential Testing Engine

---

## SYNOPSIS

```sh
dag --replay <traffic_file> --server1 <host[:port]> [--server2 <host[:port]>]
    [--diff] [--ignore-ttl] [--output-diff <file>]
    [--rate <qps>] [--workers <N>] [--timeout-ms <ms>]
    [--stop-after <N>] [--max-queries <N>]
    [--transport <udp|tcp>] [--server1-transport <transport>] [--server2-transport <transport>]
    [--output <text|json>] [+dnssec | +do] [+nodnssec | +nodo]
```

---

## DESCRIPTION

`dag --replay` is an asynchronous, multi-threaded traffic replay and differential testing utility built into the [`dag(1)`](dag.md) diagnostic suite.

It reads DNS queries from live traffic capture files (**PCAP**, **dnstap / Frame Streams**) or plain text query lists, transmits them concurrently across one or two target DNS nameservers, and evaluates response consistency.

When dual servers are specified (`--server1` and `--server2`), `dag --replay` performs **semantic, order-independent differential comparison** of the responses across every DNS section (Header, Question, Answer, Authority, and Additional). It categorizes differences into granular bitmask flags, detects subtle protocol inconsistencies (such as glue record omissions, DNSSEC RRSIG/NSEC differences, and CNAME chain discrepancies), and outputs structured statistics in human-readable or JSON format.

---

## OPTIONS

### Server Target Specifications

`--server1 <host[:port]>`
: Address and optional port of the primary target nameserver (default port: `53`). Supports IPv4 addresses, IPv6 addresses, and hostnames.

`--server2 <host[:port]>`
: Address and optional port of the secondary comparison nameserver (default port: `53`). Specifying `--server2` automatically enables differential testing mode (`--diff`).

### Replay & Engine Control

`--replay <traffic_file>`
: Path to the input traffic source. Automatically detects format:
  - **PCAP file** (magic `0xa1b2c3d4` or `0xd4c3b2a1`)
  - **dnstap Frame Streams file** (initial escape word `0x00000000`)
  - **Text query file** (line-by-line domain name and type)

`--rate <qps>`, `--rate-limit <qps>`
: Limit the maximum query transmission rate to the specified queries-per-second (QPS). Replay pacing applies microsecond sleeps between task generation. When omitted or set to `0`, queries are dispatched as fast as the workers and targets permit.

`--workers <N>`, `--concurrency <N>`
: Number of concurrent worker threads processing the replay queue (default: `1`, maximum: `64`). Each worker thread independently handles network exchanges and response comparisons.

`--max-queries <N>`
: Stop replay processing after dispatching `N` queries.

`--timeout-ms <ms>`
: Network socket I/O timeout in milliseconds for each query-response exchange (default: `2000` ms).

### Differential Testing Options

`--diff`
: Explicitly enable differential response comparison. Automatically activated when `--server2` is provided.

`--ignore-ttl`
: Ignore TTL differences when comparing resource records across servers. When enabled, two identical record sets with differing TTL values (e.g., due to caching state or differing zone minimum TTL configurations) are treated as identical.

`--stop-after <N>`
: Early termination threshold. Immediately halts replay after encountering `N` mismatched query responses between `--server1` and `--server2`. Useful for automated CI regressions where an early failure should abort immediately.

`--output-diff <file>`
: Write detailed per-query difference summaries to `<file>`. Use `-` to stream difference reports directly to `stdout`.

### Transport Control

`--transport <udp|tcp>`
: Explicitly force the global transport protocol for all replayed queries, overriding any transport recorded in the input capture file.

`--server1-transport <udp|tcp>`
: Force the transport protocol specifically for queries sent to `--server1`. Allows cross-transport differential testing (e.g., UDP vs. TCP validation on the same server).

`--server2-transport <udp|tcp>`
: Force the transport protocol specifically for queries sent to `--server2`.

### Query Options & Output Format

`+dnssec`, `+do`
: Set the DNSSEC OK (DO) bit (0x8000) in the EDNS0 OPT record for synthetic queries generated from text query lists.

`+nodnssec`, `+nodo`
: Clear the DO bit in EDNS0 OPT records for synthetic text queries (default).

`--output <text|json>`, `--output-format <text|json>`
: Select report output format. `text` (default) prints a formatted console summary. `json` emits a machine-readable JSON document containing latency histograms, RCODE breakdowns, and differential counters.

---

## INPUT FORMATS & PROTOCOL PRESERVATION

`dag --replay` supports three distinct traffic input sources:

### 1. dnstap Frame Streams (`.fstrm` / `.dnstap`)

Standard binary log format specified by Farsight Security and widely implemented in KariDNS, BIND 9, Unbound, NSD, and Knot DNS.

- **Handshake & Frame Handling**: Parses the bidirectional Frame Streams container, safely skipping control frames (`START`, `STOP`, `READY`, `ACCEPT`, `FINISH`).
- **Protobuf Deserialization**: Decodes Google Protocol Buffers `dnstap.Dnstap` wrapper and extracts `dnstap.Message` content.
- **Query Extraction**: Extracts `query_message` (field 10) wire payloads. Verifies `QR == 0` and `QDCOUNT >= 1`, automatically ignoring server response frames (`response_message`, field 14).
- **Transport Fidelity**: Extracts `socket_protocol` (field 3: `1 = UDP`, `2 = TCP`). Replayed queries faithfully reproduce the recorded transport protocol without requiring command-line flags.

### 2. PCAP Live Captures (`.pcap`)

Standard packet capture format generated by `tcpdump`, `wireshark`, or switch port mirrors.

- **Link Layer Decoding**: Supports Ethernet (`LINKTYPE_ETHERNET`, 1), Linux cooked capture (`LINKTYPE_LINUX_SLL`, 113), Raw IP (`LINKTYPE_RAW`, 12 / 101), and Loopback (`LINKTYPE_NULL`, 0).
- **VLAN Support**: Transparently unpacks 802.1Q tagged Ethernet frames (Ethertype `0x8100`).
- **Network & Transport Layer**: Inspects IPv4 and IPv6 headers. Correctly handles variable-length IP options and TCP header extensions.
- **Protocol Fidelity**: Distinguishes between UDP (`IPPROTO_UDP`, 17) and TCP (`IPPROTO_TCP`, 6). For TCP captures, the 2-byte DNS length prefix is stripped and parsed into wire-format queries. Original transport is retained for each replayed packet.
- **Query Filtering**: Validates that the packet is a query (`QR == 0`) with at least one question. Non-DNS or response packets are ignored.

### 3. Plain Text Query Lists (`.txt`)

Convenient human-readable query list format with one entry per line:

```text
# Domain Name               QTYPE   [Options]
example.com                 A
www.example.com             AAAA
sec.example.com             DNSKEY  +dnssec
mail.example.com            MX      +tcp
corp.example.com            AXFR    +tcp
```

- **Comment & Empty Line Skipping**: Lines beginning with `#` or `;` and blank lines are ignored.
- **Transport Flags**: Adding `+tcp` or `+udp` on a line sets the transport for that individual query.
- **DNSSEC Flags**: Adding `+dnssec` or `+do` sets the DO bit in EDNS0 OPT for that query.
- **Packet Construction**: Automatically generates RFC 1035 compliant DNS wire packets with randomized Transaction IDs and standard RD flags.

---

## TRANSPORT RESOLUTION HIERARCHY

When dispatching queries to target servers, `dag --replay` determines the transport protocol using the following strict priority:

1. **Per-Server Transport Option (`--server1-transport` / `--server2-transport`)**  
   If set on the CLI, this overrides all other settings for the corresponding server.
2. **Global Transport Option (`--transport`)**  
   If explicitly specified on the CLI (e.g., `--transport tcp`), forces all replayed queries across both servers to use the given transport.
3. **Capture Transport (`task.transport`)**  
   If no CLI transport override is provided, the engine uses the original transport recorded in the input:
   - dnstap: `Message.socket_protocol` (`UDP` or `TCP`)
   - PCAP: L4 IP header protocol (`UDP` or `TCP`)
   - Text files: Per-line `+tcp` or `+udp` directive
4. **Default Transport**  
   If none of the above apply, defaults to `"udp"`.

---

## DIFFERENTIAL COMPARISON ENGINE

When comparing responses from `--server1` and `--server2`, `dag --replay` employs an order-independent RRset comparison algorithm. DNS servers are permitted by RFC 1035 and RFC 2181 to return resource records within an RRset in any order (round-robin rotation) and use varying compression pointer schemes.

The comparison engine normalizes and evaluates differences across 13 distinct categories:

| Flag Name | Bitmask | Description |
|---|---|---|
| **`DIFF_RCODE`** | `0x0001` | Response RCODE mismatch (e.g., `NOERROR` vs. `NXDOMAIN` or `SERVFAIL`). |
| **`DIFF_FLAGS`** | `0x0002` | Header flags mismatch (`AA`, `TC`, `RD`, `RA`, `AD`, `CD`). |
| **`DIFF_ANCOUNT`** | `0x0004` | Record count mismatch in the Answer section. |
| **`DIFF_NSCOUNT`** | `0x0008` | Record count mismatch in the Authority section. |
| **`DIFF_ARCOUNT`** | `0x0010` | Record count mismatch in the Additional section. |
| **`DIFF_ANSWER_RRSET`** | `0x0020` | Semantic mismatch in Answer RRset data (owner name, type, class, or RDATA). |
| **`DIFF_AUTH_RRSET`** | `0x0040` | Semantic mismatch in Authority RRset data. |
| **`DIFF_ADD_RRSET`** | `0x0080` | Semantic mismatch in Additional RRset data. |
| **`DIFF_GLUE_MISSING`** | `0x0100` | In-bailiwick glue record missing or mismatched in referral responses. |
| **`DIFF_EDNS`** | `0x0200` | EDNS0 presence, buffer size, version, or option code mismatch. |
| **`DIFF_DNSSEC_RRSIG`**| `0x0400` | DNSSEC RRSIG signature presence, type covered, or validity difference. |
| **`DIFF_DNSSEC_NSEC`** | `0x0800` | DNSSEC NSEC / NSEC3 denial of existence record difference. |
| **`DIFF_CNAME_CHAIN`** | `0x1000` | CNAME redirection alias chain length or target mismatch. |

---

## OUTPUT FORMATS

### 1. Standard Text Report (Default)

Printed to standard output upon completion:

```text
=== DNS Replay & Differential Report ===
Total queries processed: 1000
Replay duration: 0.85s (1176.47 QPS)

[Server 1: 127.0.0.1:53]
  Sent:               1000
  Received:           1000 (100.0%)
  Timeouts:           0
  Average RTT:        0.42 ms
  RCODE NOERROR:      950
  RCODE NXDOMAIN:     50

[Server 2: 127.0.0.1:5353]
  Sent:               1000
  Received:           1000 (100.0%)
  Timeouts:           0
  Average RTT:        0.38 ms
  RCODE NOERROR:      950
  RCODE NXDOMAIN:     50

[Differential Results]
  Total compared:     1000
  Identical:          998 (99.8%)
  Mismatched:         2 (0.2%)
    RCODE diffs:      0
    Flags diffs:      0
    Answer diffs:     1
    Authority diffs:  0
    Additional diffs: 0
    Glue diffs:       0
    EDNS diffs:       0
    DNSSEC RRSIG:     1
    DNSSEC NSEC:      0
    CNAME Chain:      0
```

### 2. JSON Report (`--output json`)

Structured document suitable for CI/CD assertions and telemetry ingestion:

```json
{
  "total_queries": 1000,
  "server1": {
    "target": "127.0.0.1:53",
    "sent": 1000,
    "received": 1000,
    "timeouts": 0,
    "avg_rtt_ms": 0.42,
    "noerror": 950,
    "nxdomain": 50,
    "servfail": 0
  },
  "server2": {
    "target": "127.0.0.1:5353",
    "sent": 1000,
    "received": 1000,
    "timeouts": 0,
    "avg_rtt_ms": 0.38,
    "noerror": 950,
    "nxdomain": 50,
    "servfail": 0
  },
  "diff": {
    "compared": 1000,
    "identical": 998,
    "identical_queries": 998,
    "mismatched_queries": 2,
    "rcode_mismatches": 0,
    "flags_mismatches": 0,
    "ancount_mismatches": 1,
    "rrset_mismatches": 1,
    "glue_missing_diffs": 0,
    "edns_diffs": 0,
    "dnssec_rrsig_diffs": 1,
    "dnssec_nsec_diffs": 0,
    "cname_chain_diffs": 0
  }
}
```

### 3. Difference Stream (`--output-diff <file>`)

Each mismatch records the sequence number, description, and hexadecimal bitmask:

```text
[DIFF #42] Reachability mismatch: S1=OK S2=TIMEOUT (flags=0x0001)
[DIFF #108] RRSIG presence mismatch: S1=present S2=absent (flags=0x0420)
[DIFF #512] Answer RRset record count mismatch: S1=2 S2=1 (flags=0x0024)
```

---

## EXIT STATUS

`0`
: Replay completed successfully. In differential mode (`--diff`), all compared responses matched identically (`mismatched_queries == 0`).

`1`
: Syntax error, input file read error, socket binding failure, or one or more response mismatches detected in differential testing mode.

---

## EXAMPLES

### 1. Replay dnstap Traffic to a Target Nameserver

Replay a live dnstap log captured via `fstrm_capture` or KariDNS against a local server:

```sh
dag --replay /var/log/dnstap.fstrm --server1 127.0.0.1:53
```

*Note: Queries that were originally received over TCP will automatically be replayed over TCP; queries received over UDP will be replayed over UDP.*

### 2. Differential Regression Testing Across Implementations

Verify consistency between BIND 9 and KariDNS using a captured PCAP trace:

```sh
dag --replay traffic.pcap \
    --server1 127.0.0.1:53 \
    --server2 127.0.0.1:5353 \
    --diff --ignore-ttl \
    --output-diff /tmp/differences.log
```

### 3. High-Concurrency Stress & Benchmarking

Replay a 100,000 query text list at 10,000 QPS across 16 worker threads:

```sh
dag --replay queries.txt \
    --server1 192.0.2.1:53 \
    --rate 10000 \
    --workers 16
```

### 4. Continuous Integration Early Abort

In automated CI pipelines, fail immediately upon the first response mismatch:

```sh
dag --replay regression_suite.txt \
    --server1 127.0.0.1:53 \
    --server2 127.0.0.1:1053 \
    --diff --stop-after 1 \
    --output json
```

### 5. Cross-Protocol Validation (UDP vs. TCP)

Verify that a server produces identical answers whether queried over UDP or TCP:

```sh
dag --replay queries.txt \
    --server1 127.0.0.1:53 --server1-transport udp \
    --server2 127.0.0.1:53 --server2-transport tcp \
    --diff
```

---

## SEE ALSO

[`dag(1)`](dag.md), [`karidns(8)`](karidns.md), [`karicheck(1)`](karicheck.md), [`karictl(8)`](karictl.md)

# DAG(1) — KariDNS Reference Manual

```text
DAG(1)                         KariDNS Manual                         DAG(1)
```

---

## NAME

**dag** — DNS Anomaly Generator, Protocol Inspector, and Multi-Server Verification Utility

---

## SYNOPSIS

```sh
dag [@server[:port][,...]] [-p port] [-b address[#port]] [-c class] [-f filename]
    [-k keyfile] [-m] [-q name] [-t type] [-u] [-v] [-x addr]
    [-y [hmac:]name:secret] [-4 | -6] [name] [type] [class] [queryopt...]

dag [-h | --help]

dag [--break-help]

dag [global-queryopt...] [query...]
```

---

## DESCRIPTION

`dag` (**DNS Anomaly Generator**) is a DNS test client, protocol inspector, multi-server consistency checker, and packet fuzzer developed for the **KariDNS** project.

`dag` provides dig-compatible command-line syntax and output formatting, while offering additional testing capabilities:

1. **Protocol Mutation & Fuzzing (`--break`)**:
   `dag` can craft malformed, edge-case, or boundary-testing DNS packets (such as compression pointer loops, oversized labels, invalid header counts, or TCP stream anomalies) to evaluate the robustness of DNS server implementations.
2. **Multi-Server Consistency Comparison (`+allcompare`)**:
   Users can supply a comma-separated list of nameservers (e.g., `@1.1.1.1,8.8.8.8,9.9.9.9:5353`). `dag` queries each server and can output a matrix comparing response equivalence (`MATCH_EXACT`, `MATCH_SEMANTIC`, or `[DIFF]`).
3. **Web Wire-Format Inspection (`+ldnsz`)**:
   Encodes the raw wire-format query and response using zlib compression and Base64URL encoding, generating inspection URLs for [ldns.jp](https://ldns.jp/) or multi-server binary diff URLs.
4. **Transports & Protocol Extensions**:
   Support for **DNS over TLS (DoT)**, **DNS over HTTPS (DoH)**, **Plain HTTP DNS**, **HAProxy PROXYv2**, **EDNS Client Subnet (ECS)**, **DNS Cookies**, **Extended DNS Errors (EDE)**, **Multiple QTYPE (RFC 10029)**, and **Dynamic Updates (RFC 2136)**.
5. **Memory Arenas**:
   Uses bump-allocated memory arenas (`zone_arena_t`) for scratch allocations during query processing.

### Default Lookup Behavior

- Unless `@server` is explicitly provided, `dag` reads nameserver addresses from `/etc/resolv.conf`. If no server is found, it queries `127.0.0.1`.
- When no domain name is supplied, `dag` queries the root zone (`.`) for `NS` records. If a domain name is supplied without a type, it defaults to `A` (or `PTR` if `-x` is specified).
- Per-user defaults can be configured via `${HOME}/.digrc`. This file is read and its options applied before command-line arguments, unless the `-r` option is supplied.

---

## OPTIONS

### Query Target & General Options

`-4`
: Force query transport over IPv4 only.

`-6`
: Force query transport over IPv6 only.

`-b address[#port]`
: Set the source IP address and optional source port for the query. `address` must be a valid interface address on the local host.

`-c class`
: Set the query class. The default is `IN` (Internet). Other supported classes include `CH` / `CHAOS`, `HS` / `HESIOD`, or numeric `CLASSnn` syntax (e.g., `CLASS3`).

`-f filename`
: Batch mode. Reads a list of query requests from `filename` line by line. Blank lines and lines beginning with `#` or `;` are ignored. Each line is processed as an independent set of query arguments.

`-h`, `--help`
: Print a comprehensive usage summary and exit.

`--break-help`
: Print the list of all available `--break` mutation and fuzzing options and exit.

`-k keyfile`
: Sign queries using TSIG with credentials read from a BIND-compatible key file.

`-m`
: Enable memory usage debugging. Upon completion, `dag` prints process maximum resident set size (`ru_maxrss`) via `getrusage(2)`. *(Not available on Windows)*

`-p port`
: Send queries to the specified port instead of the default port 53 (or 853 for DoT, 443 for DoH, 80 for Plain HTTP).

`-q name`
: Explicitly specify the domain name to query. Useful to distinguish domain names that overlap with record types or options.

`-r`
: Do not read options from `${HOME}/.digrc`.

`-t type`
: Explicitly specify the resource record type. Supports standard mnemonics (`A`, `AAAA`, `NS`, `SOA`, `MX`, `TXT`, `SRV`, `HTTPS`, `SVCB`, `DS`, `DNSKEY`, `ANY`, `AXFR`, `IXFR=serial`, etc.) as well as generic `TYPEnn` syntax (RFC 3597).

`-u`
: Display query elapsed times in microseconds (µs) instead of milliseconds (ms).

`-v`, `--version`
: Display the version string (`KariDNS dag v...`) and exit.

`-x addr`
: Simplified reverse DNS lookup for IPv4 and IPv6 addresses. Automatically converts dotted-decimal IPv4 addresses into `in-addr.arpa` and colon-delimited IPv6 addresses into `ip6.arpa` (nibble format), setting the query type to `PTR` and class to `IN`.

`-y [hmac:]name:secret`
: Sign queries using TSIG with the provided base64-encoded shared secret. The algorithm prefix can be `hmac-md5`, `hmac-sha1`, `hmac-sha224`, `hmac-sha256` (default), `hmac-sha384`, or `hmac-sha512`.

`--hex <hex>`, `--hex=<hex>`
: Transmit an arbitrary raw DNS wire-format packet provided as a hexadecimal string (up to 65,535 bytes). Allows direct crafting and replay of custom or malformed DNS messages.

---

## TRANSPORT & PROTOCOL OPTIONS

`+[no]tcp`, `+[no]vc`
: Use TCP transport instead of UDP. `+vc` ("virtual circuit") is a synonym for `+tcp`. `+novc` disables TCP. `AXFR` and large `IXFR` queries automatically elevate to TCP unless `+udp` is explicitly forced.

`+udp`
: Force UDP transport.

`+[no]tls`
: Use **DNS over TLS (DoT)** (RFC 7858). When enabled, default destination port switches to 853.

`+tls-ca[=file]`
: Enable TLS server certificate verification. If a PEM `file` is specified, certificate authorities are loaded from it; otherwise, the system default trust store is used. `+notls-ca` disables certificate validation.

`+tls-certfile=file`, `+tls-keyfile=file`
: Set client certificate chain and private key in PEM format for mutual TLS (mTLS) authentication. Both options must be provided together.

`+tls-hostname=hostname`
: Specify the expected Server Name Indication (SNI) and hostname for TLS certificate verification.

`+[no]https[=endpoint]`
: Use **DNS over HTTPS (DoH)** (RFC 8484) over TLS. Default port is 443; default endpoint URI path is `/dns-query`. Request method defaults to HTTP POST.

`+[no]https-get[=endpoint]`
: Use DoH with HTTP GET method (transmitting wire query as Base64URL in `?dns=` query parameter).

`+[no]https-post[=endpoint]`
: Use DoH with HTTP POST method (transmitting wire query in HTTP payload body).

`+[no]http-plain[=endpoint]`, `+[no]http-plain-get`, `+[no]http-plain-post`
: Send DNS queries over unencrypted plain HTTP (RFC 8484). Default port is 80; default endpoint is `/dns-query`.

`+[no]proxy[=spec]`
: Prepend a **HAProxy PROXYv2** binary header before the DNS packet.
  - If `spec` is omitted (`+proxy`), sends a PROXYv2 header with `LOCAL` command.
  - If `spec` is provided in `src_addr[#src_port]-dst_addr[#dst_port]` format (e.g., `+proxy=192.0.2.1#1234-192.0.2.2#53`), sends a PROXYv2 `PROXY` command reflecting the specified connection endpoints.
  - For encrypted transports (DoT/DoH), the PROXYv2 header is sent after the TLS handshake completes.

`+[no]proxy-plain[=spec]`
: Same as `+proxy`, but transmits PROXYv2 headers ahead of TLS encryption handshakes.

`+[no]keepalive`
: Include the EDNS TCP Keepalive option (RFC 7828) in the query.

`+[no]keepopen`
: Keep the TCP or TLS socket open between consecutive queries when executing multiple queries in a batch. *(Note: HTTP Keep-Alive is currently unsupported in DoH `+https` mode, and connections will be closed after each query).*

`+[no]dns64prefix`
: Automatically query `ipv4only.arpa` for `AAAA` records to discover local DNS64 prefixes (RFC 7050).

`+timeout=N`, `+time=N`
: Set query network timeout in seconds (default: 5 seconds). `+time=N` functions as a synonym/alias.

`+tries=N`
: Set the total number of transmission attempts to `N` (default: 1 attempt).

`+retry=N`
: Set the number of transmission retries to `N` (total attempts will be `N + 1`).

---

## DNS HEADER & QUERY FLAGS

`+[no]rec`, `+[no]recurse`, `+[no]rdflag`
: Set or clear the **RD (Recursion Desired)** header bit. Recursion is enabled by default. Automatically disabled when `+trace` or `+nssearch` is active.

`+[no]adflag`
: Set or clear the **AD (Authenticated Data)** bit in the query header.

`+[no]cdflag`
: Set or clear the **CD (Checking Disabled)** bit in the query header, requesting the upstream server not to perform DNSSEC validation.

`+[no]aaflag`, `+[no]aaonly`
: Set or clear the **AA (Authoritative Answer)** bit in the query header.

`+[no]tcflag`
: Set or clear the **TC (Truncation)** bit in the query header.

`+[no]raflag`
: Set or clear the **RA (Recursion Available)** bit in the query header.

`+[no]zflag`
: Set or clear the reserved **Z** bit in the DNS header.

`+opcode=N`
: Override the DNS header **OPCODE**. Accepts numeric values (0–15) or standard mnemonic strings (`QUERY`, `IQUERY`, `STATUS`, `NOTIFY`, `UPDATE`). Example: `+opcode=UPDATE` or `+opcode=5`.

`+qid=N`
: Override the 16-bit DNS Query ID (0–65535). If omitted, a cryptographically secure random ID is generated via `arc4random(3)` (or platform CSPRNG / OpenSSL `RAND_bytes` on non-BSD platforms).

`+[no]header-only`
: Send a query containing only the 12-byte DNS header with `QDCOUNT=0` (no QUESTION section).

`+[no]ignore`
: Ignore truncation (`TC=1`) in UDP responses instead of automatically retrying over TCP.

`+[no]fail`
: When querying multiple nameservers or using failover lists, controls whether to try the next nameserver when receiving a `SERVFAIL` response.

`+[no]trace`
: Trace the DNS delegation path iteratively starting from the root nameservers (`.`). `dag` follows referrals down to authoritative servers and displays each intermediate answer. Honors `+tcp` and automatically falls back to TCP when receiving truncated (`TC=1`) responses.

`+[no]nssearch`
: Look up authoritative nameservers for the zone containing the query name and display the SOA record from each responding nameserver. Honors `+tcp` and automatically falls back to TCP when receiving truncated (`TC=1`) responses.
  - **BIND 9 `dig` との互換性**: BIND 9 の `dig +nssearch` は NS 応答取得後、同梱された Glue レコードを無視して OS のシステムリゾルバ（`/etc/resolv.conf` の `getaddrinfo`）でのみ NS 名の名前解決を行います。これに対し `dag` はデフォルト（`+glue`）で NS 応答の `ADDITIONAL` セクション（In-bailiwick Glue A/AAAA）を自律的にスキャンして直接ネームサーバーへ問い合わせるため、閉鎖環境やテスト網のローカルゾーンでも外部リゾルバに依存せず正しく動作します。BIND 9 `dig` と同等の挙動（システムリゾルバ限定）を強制したい場合は `+noglue` を併用してください。

`+[no]glue`
: Control whether `+trace` and `+nssearch` prioritize in-bailiwick Glue records (A/AAAA) present in the `ADDITIONAL` section of delegation and NS response packets (default: `+glue`). When disabled with `+noglue`, `dag` bypasses Glue records and resolves nameserver addresses strictly using the resolver (`getaddrinfo` / initial upstream resolver), matching BIND 9 `dig` behavior.

`+[no]search`, `+[no]defname`
: Enable or disable domain search list processing as defined in `/etc/resolv.conf`.

`+domain=name`
: Set the search list to contain the single domain `name` and enable search processing.

`+ndots=N`
: Set the threshold for the number of dots that must appear in a domain name for it to be considered absolute before search domain appending takes place.

`+[no]idn`
: Toggle Internationalized Domain Names (IDN) processing for both input and output simultaneously.

`+[no]idnin`, `+[no]idnout`
: Independently control IDN conversion for input query domain names (Punycode encoding via `libidn2`) and output response domain names (Unicode decoding).

---

## EDNS0 EXTENSIONS

`+[no]edns[=N]`
: Specify the EDNS version to advertise in the OPT pseudo-RR (default: 0). `+noedns` completely disables EDNS0 in the query.

`+bufsize=N`
: Set the advertised EDNS0 UDP buffer size (default: 1232 bytes, compliant with DNS Flag Day recommendations).

`+[no]dnssec`, `+[no]do`
: Set the **DO (DNSSEC OK)** bit in the EDNS0 OPT record, requesting DNSSEC RRs (RRSIG, NSEC, NSEC3, DS) from the authoritative server.

`+[no]keepopen`
: Keep the TCP or TLS socket open between consecutive queries to the same nameserver (RFC 7766 DNS over TCP connection reuse).

`+[no]keepalive`
: Send the **EDNS TCP Keepalive (RFC 7828)** option (Option Code 11) in the OPT pseudo-RR.

`+[no]expire`
: Send the **EDNS EXPIRE (RFC 7314)** option (Option Code 9) in query and highlight the zone expiration TTL field in SOA responses.

`+[no]cookie[=hex]`
: Send the **DNS Cookie (RFC 7873 / RFC 9018)** option. If `hex` is supplied, sets the client (8 bytes) or client+server cookie value. If omitted, a random 8-byte client cookie is generated.

`+[no]badcookie`
: Automatically retry the query once if the server returns a `BADCOOKIE` error, attaching the returned Server Cookie. Enabled by default.

`+[no]showbadcookie`
: Print a diagnostic message when a `BADCOOKIE` retry occurs.

`+subnet=addr[/prefix]`
: Send the **EDNS Client Subnet (ECS)** option (RFC 7871) with the specified IPv4 or IPv6 network prefix (e.g., `+subnet=192.0.2.0/24` or `+subnet=2001:db8::/56`). Specifying `+subnet=0` sends an empty source address with prefix length 0 to signal privacy preference.

`+[no]nsid`
: Request the **Name Server Identifier (NSID)** option (RFC 5001).

`+padding[=N]`
: Add exactly `N` bytes of EDNS0 Padding option payload (useful for packet size fuzzing).

`+mqtype=TYPE[,TYPE...]`
: Send the **Multiple QTYPE (RFC 10029)** EDNS option (Option Code 20), requesting multiple resource record types (e.g., `+mqtype=A,AAAA,HTTPS`) in a single query transaction.

`+ednsopt=code[:hex]`
: Specify a custom EDNS option code (0–65535) and optional payload encoded in hexadecimal string. Multiple `+ednsopt` parameters can be supplied.

`+noednsopt`
: Clear all configured custom EDNS options.

`+ednsflags=N`, `+[no]ednsflags`
: Set or reset the raw 16-bit EDNS Z-flags in the OPT record. `+ednsflags=N` sets the flag bits to `N`, while `+ednsflags` (without `=`) or `+noednsflags` resets the flags to `0`.

`+[no]coflag`, `+[no]co`
: Set the **Compact Answers OK (CO)** flag in the OPT record to signal support for Compact Denial of Existence.

`+[no]ednsnegotiation`
: Enable EDNS version negotiation fallback if a server returns `BADVERS`.

`+[no]showbadvers`
: Display diagnostic output when EDNS version negotiation is triggered.

---

## TSIG TRANSACTION SECURITY

`dag` supports TSIG (RFC 8945) transaction signatures to authenticate requests (such as AXFR, IXFR, Dynamic Updates, and NOTIFY) against authoritative servers.

`-y [hmac:]name:secret`
: Set TSIG key inline. `hmac` specifies the HMAC algorithm:
  - `hmac-md5`
  - `hmac-sha1`
  - `hmac-sha224`
  - `hmac-sha256` (default)
  - `hmac-sha384`
  - `hmac-sha512`
  `name` is the TSIG key identity; `secret` is the base64-encoded secret.

`+tsig=[hmac:]name:secret`
: Query-option equivalent of `-y`.

`-k keyfile`
: Read TSIG key definition from a BIND-style key file (e.g., generated by `tsig-keygen`):
  ```
  key "tsig-key.example.com" {
      algorithm hmac-sha256;
      secret "6p9y...==";
  };
  ```

`+fuzztime[=timestamp]`
: Manually override the TSIG signing time (seconds since Unix epoch) to test clock skew tolerances and replay attack defenses. Default timestamp if `+fuzztime` is passed without argument is `1646972129`. `+nofuzztime` restores current system clock.

---

## DYNAMIC DNS UPDATE (RFC 2136)

`dag` can formulate and send Dynamic DNS UPDATE requests (`OPCODE=5`), supporting record additions, deletions, and prerequisite evaluations.

### Update Operations

`--update-add <RR>`
: Add a resource record to the zone. Format: `"<name> <ttl> [class] <type> <rdata>"`
  ```sh
  dag example.com @127.0.0.1 -k update.key --update-add "web.example.com 300 IN A 192.0.2.10"
  ```

`--update-del <name> [type]`
: Delete all records for `<name>`, or delete all records of `<type>` on `<name>`.
  ```sh
  dag example.com @127.0.0.1 -k update.key --update-del "oldhost.example.com A"
  ```

`--update-del-exact <RR>`
: Delete a specific resource record matching full RDATA.
  ```sh
  dag example.com @127.0.0.1 -k update.key --update-del-exact "web.example.com 0 IN A 192.0.2.10"
  ```

### Prerequisites

`--prereq-yxdomain <name>`
: Prerequisite: Domain `<name>` must exist (at least one RR of any type).

`--prereq-nxdomain <name>`
: Prerequisite: Domain `<name>` must NOT exist.

`--prereq-yxrrset <name> <type> [rdata]`
: Prerequisite: RRset of `<type>` on `<name>` must exist (optionally matching exact `<rdata>`).

`--prereq-nxrrset <name> <type>`
: Prerequisite: RRset of `<type>` on `<name>` must NOT exist.

`--prereq=<kind:name[:type][:rdata]>`
: Alternative colon-delimited format for specifying prerequisites (e.g., `--prereq=nxdomain:host.example.com` or `--prereq=yxrrset:host.example.com:A:192.0.2.1`).

---

## PROTOCOL ANOMALY GENERATOR & FUZZING (`--break`)

> [!WARNING]
> **Intended for Local Testing & Security Audits Only**
> Do not execute `--break` anomaly tests against external or production public DNS servers without explicit authorization.

> [!NOTE]
> Only one *structural* `--break` mutation (e.g. `compression-loop`, `compression-forward`, `label-too-long`, `reserved-length-bits`, `oversized-qname`, `truncated-question`, `notify-no-question`) can be active per query. If multiple structural breaks are specified, only the first one is applied and subsequent ones are ignored with a warning. Transport/header flags can be combined freely.

`dag` provides built-in packet mutators to test server resilience against protocol edge cases, malformed wire formats, and parser exploits.

### Mutation Kinds (`--break <kind>[=<param>]`)

| Mutation Kind | Description | Tested Vulnerability / Spec |
| :--- | :--- | :--- |
| `compression-loop` | Generates a self-referencing DNS compression pointer (`0xC00C -> 0xC00C`). | Infinite pointer recursion / CPU DoS |
| `compression-forward` | Compression pointer targeting an unread forward offset in the packet. | Out-of-bounds read / illegal pointer |
| `label-too-long[=N]` | Sets a domain label length byte to `N` (`63 < N < 192`, default: 100). | Buffer overflow (> 63 octet RFC limit) |
| `reserved-length-bits` | Sets label length byte to `0x40` (unallocated RFC 1035 bit pattern). | Parser crash on unassigned label types |
| `oversized-qname` | Builds a QNAME exceeding 255 total octets using chained subdomains. | Domain name buffer overflow |
| `qdcount=N` | Overrides header `QDCOUNT` with `N` (e.g., `qdcount=2` without second question). | Question section out-of-bounds reading |
| `truncated-question` | Truncates the wire packet abruptly in the middle of a label or type field. | Premature EOF parsing panic |
| `opt-rdlen=N` | Overstates OPT record `RDLENGTH` (e.g., 500 bytes when actual payload is small). | EDNS0 RDATA boundary overrun |
| `arcount=N` | Overrides header `ARCOUNT` to indicate non-existent additional records. | Additional record array indexing errors |
| `opcode=N` | Sets an unallocated or reserved DNS `OPCODE` (`N=15`). | Unhandled Opcode crash / state machine |
| `qr-bit` | Sets the `QR` bit to 1 on an outgoing query (sending a response as a query). | Server reflection / loop amplification |
| `notify-no-question` | Sends `OPCODE=4` (NOTIFY) with `QDCOUNT=0`. | RFC 1996 missing zone question panic |
| `too-short` | Sends only the first 3 bytes of a DNS message. | Short packet header read violation |
| `tcp-length-overclaim[=N]` | (*TCP only*) Prefixes a 2-byte TCP length `N` bytes larger than sent data. | TCP frame starvation / hanging worker |
| `tcp-zero-length` | (*TCP only*) Sends a 2-byte TCP length prefix of `0`. | Zero-length packet hang or memory leak |
| `tcp-idle-hold[=SEC]` | (*TCP only*) Sends length prefix, holds connection open for `SEC` seconds. | Slowloris / connection pool exhaustion |
| `update-meta-type[=N]` | (*UPDATE only*) Injects a meta-type RR (e.g., OPT / TSIG) into the Update Section. | Meta-RR validation in dynamic updates |

### Automated Batch Fuzzing

`--break all`, `--test-all`
: Sequentially executes the predefined set of built-in anomaly test cases against the target server, printing the response status or timeout for each test case.

`--hex=<hexstring>`
: Directly transmits the raw hexadecimal byte stream as a DNS packet without validation or reconstruction.

---

## MULTI-SERVER QUERY & CONSISTENCY COMPARISON (`+allcompare`, `+ldnsz`)

`dag` allows querying multiple nameservers in parallel or sequentially within a single invocation.

### Multi-Server Target Syntax

Multiple servers are specified via a comma-separated list after `@`:
```sh
dag example.com A @1.1.1.1,8.8.8.8,9.9.9.9:5353,[2001:4860:4860::8888]
```

### Response Equivalence Comparison (`+allcompare`)

When `+allcompare` is specified, `dag` performs automated differential analysis across all responding servers:

- `[BASE]`: The reference response from the base server.
- `MATCH_EXACT`: Binary byte-for-byte match (excluding the 16-bit Query ID).
- `MATCH_SEMANTIC`: Semantic match — all Resource Records, RDATA sets, and section counts match regardless of record ordering or TTL differences.
- `[DIFF]`: Discrepancy detected in RCODE, flags, answer sets, or authority data.

A summary table is printed:
```text
;; --- Multi-Server Query Summary ---
SERVER               | PROTO | RCODE    | QD | AN | NS | AR | TIME   | STATUS
---------------------+-------+----------+----+----+----+----+--------+------------------------
1.1.1.1              | UDP   | NOERROR  | 1  | 1  | 0  | 1  | 12 ms  | [BASE]
8.8.8.8              | UDP   | NOERROR  | 1  | 1  | 0  | 1  | 18 ms  | MATCH_SEMANTIC
9.9.9.9:5353         | UDP   | NOERROR  | 1  | 1  | 0  | 1  | 15 ms  | MATCH_EXACT
```

### LDNSZ Web Inspection URLs (`+ldnsz`)

When `+ldnsz` is supplied:
- **Single Server**: Generates a web inspector URL on `https://ldns.jp/?dnsz=<payload>`, allowing detailed GUI analysis of wire-format packets.
- **Multiple Servers**: Generates a diff URL on `https://ldns.jp/diff/#c=<payload1>,<payload2>`, allowing visual side-by-side binary comparison.

---

## DISPLAY & FORMATTING OPTIONS

`+[no]short`
: Provide a terse, machine-readable answer containing only the RDATA of the ANSWER section.

`+[no]multiline`, `+[no]multi`
: Print records (such as SOA, DNSKEY, RRSIG, and HTTPS) in human-readable multi-line format with field descriptions and structured comments. Short form (`+[no]multi`) is also supported.

`+[no]yaml`
: Output the complete parsed DNS response in structured YAML format.

`+[no]ttlunits`
: Display TTL values using human-friendly time unit suffixes (`s`, `m`, `h`, `d`, `w`).

`+[no]class`
: Toggle display of the CLASS field in record listings.

`+[no]ttlid`
: Toggle display of the TTL field in record listings.

`+[no]unknownformat`
: Format all record RDATA using RFC 3597 unknown record presentation format (`\# <length> <hex>`).

`+[no]crypto`
: Toggle display of raw cryptographic key data in DNSKEY, DS, and RRSIG records. When disabled, keys are displayed as `[ key id = ... ]` or `[omitted]`.

`+[no]rrcomments`
: Display explanatory inline comments for DNSSEC records (e.g., Key Tag, algorithm name).

`+[no]comments`
: Toggle display of comment banners (;; ->>HEADER<<-, opcode, status, flags).

`+[no]cmd`
: Toggle printing of the initial command-line version banner.

`+[no]stats`
: Toggle printing of query statistics (query time, server IP, timestamp, message size).

`+[no]question`, `+[no]answer`, `+[no]authority`, `+[no]additional`
: Individually toggle display of the respective DNS packet sections.

`+[no]all`
: Turn all display section flags on (`+all`) or off (`+noall`).

`+[no]qr`
: Print the outgoing query packet representation before transmitting.

`+[no]identify`
: When `+short` is enabled, display the responding server IP and port alongside the answer.

`+[no]idn`
: Enable or disable Internationalized Domain Name (IDN) Punycode conversion.

`+[no]onesoa`
: Print only the initial SOA record during AXFR transfers instead of both starting and ending SOAs.

`+[no]expandaaaa`
: Display IPv6 AAAA record addresses in fully expanded 8-group notation (e.g. `2001:0db8:0000:0000:...`) instead of compressed notation.

`+[no]split=N`
: Split long base64 and hex strings into chunks of `N` characters (default: 56; 44 in multiline mode). `+nosplit` disables splitting.

`+[no]besteffort`
: Attempt to parse and print malformed or corrupted packets.

`+[no]expire`
: Request and display the zone expiration timer for SOA queries.

`+[no]nohexdump`
: Suppress binary hex dumps for both outgoing query and incoming response packets.

`+[no]nohexdump-query`
: Suppress hex dump for outgoing queries only.

`+[no]nohexdump-response`
: Suppress hex dump for incoming responses only.

`+[no]yaml`
: Output parsed response in structured YAML format (including headers, question, answer, authority, and additional sections with decoded `rdata:` fields).

---

## MULTIPLE QUERIES & BATCH PROCESSING

`dag` allows specifying multiple query tuples on a single command line:

```sh
dag +qr example.com A @1.1.1.1 +subnet=192.0.2.0/24 -x 192.0.2.1 @8.8.8.8 +noqr
```

In this mode:
- Options preceding the first domain name tuple act as **global defaults**.
- Query-specific options override the global options for that particular query.
- Options like `+cmd` and `+short` maintain global effect across all queries.

---

## EXIT STATUS

`0`
: Successful transaction. A valid DNS response was received from the server (including `NXDOMAIN`, `REFUSED`, or other standard DNS error RCODEs).

`1`
: Usage error, invalid command-line options, or DNS query formulation failure.

`8`
: Could not open batch file specified via `-f`.

`9`
: Network error or timeout. No reply was received from any target nameserver.

`10`
: Internal execution error or out of memory.

---

## FILES

`/etc/resolv.conf`
: Default system nameserver configuration and search domains.

`${HOME}/.digrc`
: User default options applied automatically on every invocation unless `-r` is provided.

---

## EXAMPLES

### Basic Lookups
```sh
# Query A record using system resolver
dag example.com A

# Query specific nameserver on custom port
dag example.com AAAA @127.0.0.1 -p 5353

# Reverse DNS lookup
dag -x 192.0.2.53 @127.0.0.1
```

### DNSSEC & Extended Protocol Testing
```sh
# Query with DO bit, NSID, and EDNS Client Subnet
dag example.com A @127.0.0.1 +dnssec +nsid +subnet=203.0.113.0/24

# Output structured YAML with microsecond resolution
dag example.com ANY @127.0.0.1 +yaml -u

# Trace delegation hierarchy from root
dag example.com A +trace
```

### Multi-Server Comparison & LDNSZ Integration
```sh
# Compare answers across Quad9, Cloudflare, and Google DNS
dag example.com A @9.9.9.9,1.1.1.1,8.8.8.8 +allcompare

# Generate visual online diff URL
dag example.com A @1.1.1.1,8.8.8.8 +ldnsz
```

### Modern Transports (DoT / DoH / PROXYv2)
```sh
# Query via DNS over TLS (DoT)
dag example.com A @127.0.0.1 +tls +tls-ca=/etc/ssl/cert.pem

# Query via DNS over HTTPS (DoH) using GET
dag example.com A @cloudflare-dns.com +https-get

# Query via HAProxy PROXYv2 encapsulation
dag example.com A @127.0.0.1 +proxy=192.0.2.10#45000-192.0.2.1#53
```

### Zone Transfers & Updates
```sh
# Full zone transfer over TCP with TSIG
dag example.com AXFR @127.0.0.1 -k /etc/rndc.key

# Incremental zone transfer from serial 2026082301
dag example.com IXFR=2026082301 @127.0.0.1

# Dynamic DNS Update (add record with prerequisite)
dag example.com @127.0.0.1 -k /etc/rndc.key \
    --prereq-nxdomain newhost.example.com \
    --update-add "newhost.example.com 300 IN A 192.0.2.99"
```

### Protocol Fuzzing & Anomaly Testing
```sh
# Test server compression loop handling
dag example.com A @127.0.0.1 --break compression-loop

# Test oversized label handling
dag example.com A @127.0.0.1 --break label-too-long=120

# Run complete automated anomaly fuzzing suite
dag example.com A @127.0.0.1 --test-all
```

---

## STANDARDS & RFC COMPLIANCE

`dag` strictly adheres to IETF RFC standards:

- **RFC 1034 / RFC 1035**: Domain Names — Concepts and Implementation
- **RFC 1995**: Incremental Zone Transfer in DNS (IXFR)
- **RFC 1996**: Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
- **RFC 2136 / RFC 3007**: Dynamic Updates in the Domain Name System (DNS UPDATE)
- **RFC 3597**: Handling of Unknown DNS Resource Record Types
- **RFC 4033 / RFC 4034 / RFC 4035**: Resource Records for the DNS Security Extensions (DNSSEC)
- **RFC 5001**: DNS Name Server Identifier (NSID) Option
- **RFC 5936**: DNS Zone Transfer Protocol (AXFR)
- **RFC 7050**: Discovery of the IPv6 Prefix Used for IPv6 Address Synthesis (DNS64)
- **RFC 7828**: The edns-tcp-keepalive EDNS0 Option
- **RFC 7830 / RFC 8467**: The EDNS(0) Padding Option & Padding Policies
- **RFC 7858**: Specification for DNS over Transport Layer Security (DoT)
- **RFC 7871**: Client Subnet in DNS Queries (ECS)
- **RFC 7873 / RFC 9018**: Domain Name System (DNS) Cookies
- **RFC 8484**: DNS Queries over HTTPS (DoH)
- **RFC 8914**: Extended DNS Errors (EDE)
- **RFC 8945**: Secret Key Transaction Authentication for DNS (TSIG)
- **RFC 9460**: Service Binding and Parameter Specification via the DNS (SVCB / HTTPS RRs)
- **RFC 10029**: Multiple Question Types in DNS Queries (MQTYPE)

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karictl(8)`](karictl.md) — KariDNS server management and control utility
- [`karicheck(1)`](karicheck.md) — Zone file syntax and ZONEMD validation utility
- [`dag.c`](../tools/dag.c) — Source implementation of the DNS Anomaly Generator
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                          August 2026                          DAG(1)
```

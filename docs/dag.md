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

dag --replay <traffic_file> --server1 <host[:port]> [replay-opts...]

dag [global-queryopt...] [query...]
```

---

## DESCRIPTION

`dag` (**DNS Anomaly Generator**) is a DNS test client, protocol inspector, multi-server consistency checker, and packet fuzzer developed for the **KariDNS** project.

`dag` provides dig-compatible command-line syntax and output formatting, while offering additional testing capabilities:

1. **Protocol Mutation & Fuzzing (`--break`)**:
   `dag` can craft malformed, edge-case, or boundary-testing DNS packets (such as compression pointer loops, oversized labels, invalid header counts, or TCP stream anomalies) to evaluate the robustness of DNS server implementations.
2. **Multi-Server Consistency Comparison (`+allcompare`)**:
   Users can supply a comma-separated list of nameservers (e.g., `@192.0.2.1,198.51.100.1,203.0.113.1:5353`). `dag` queries each server and can output a matrix comparing response equivalence (`MATCH_EXACT`, `MATCH_SEMANTIC`, or `[DIFF]`).
3. **Web Wire-Format Inspection (`+ldnsz`)**:
   Encodes the raw wire-format query and response using zlib compression and Base64URL encoding, generating inspection URLs for [ldns.jp](https://ldns.jp/) or multi-server binary diff URLs.
4. **Transports & Protocol Extensions**:
   Support for **DNS over TLS (DoT)**, **DNS over HTTPS (DoH)**, **Plain HTTP DNS**, **HAProxy PROXYv2**, **EDNS Client Subnet (ECS)**, **DNS Cookies**, **Extended DNS Errors (EDE)**, **Multiple QTYPE (RFC 10029)**, **Dynamic Updates (RFC 2136)**, and **Transaction Security (TSIG / SIG(0))**.
5. **Traffic Replay & Differential Engine (`--replay`)**:
   Asynchronously replays recorded DNS queries from PCAP traces, dnstap Frame Streams, or text query lists against target nameservers, providing order-independent semantic differential testing across dual servers and automatic protocol preservation (TCP/UDP). See [`dag_replay(1)`](dag_replay.md) for full reference.
6. **Memory Arenas**:
   Uses bump-allocated memory arenas (`zone_arena_t`) for scratch allocations during query processing.

### Default Lookup Behavior

- Unless `@server` is explicitly provided, `dag` reads nameserver addresses from `/etc/resolv.conf` (on Windows, from the system's DNS server list). If no server is found, it queries `127.0.0.1` (on Windows: `1.1.1.1`).
- When no domain name is supplied, `dag` queries the root zone (`.`) for `NS` records. If a domain name is supplied without a type, it defaults to `A` (or `PTR` if `-x` is specified). The name, type and class may be given in any order.
- The query has the RD and AD bits set, like `dig`.
- Like `dig`, queries carry an EDNS0 OPT record (version 0, UDP payload size 1232) with a random 8-byte client cookie by default; `+noedns` and `+nocookie` turn them off. Dynamic UPDATE and NOTIFY messages (`--update-*`, `--prereq-*`, `+opcode=UPDATE`, `+opcode=NOTIFY`) get no OPT record unless an EDNS option is given explicitly, like `nsupdate`.
- In the normal output format, a hex dump of the query (`Query (N bytes):`) and of the response is printed in addition to the dig-style sections. Use `+nohexdump` to turn this off; the dumps are not printed with `+short` or `+yaml` (and the response dump not with `+nocomments`).
- Per-user defaults can be configured via `${HOME}/.digrc`. This file is read and its options applied before command-line arguments, unless the `-r` option is supplied.
- Up to 64 queries can be given on one command line (see [MULTIPLE QUERIES & BATCH PROCESSING](#multiple-queries--batch-processing)).

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
: Sign queries using TSIG with credentials read from a BIND-compatible key file, or with SIG(0) when the file is a BIND `.private` key (see [TSIG TRANSACTION SECURITY](#tsig-transaction-security)).

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
: Use TCP transport instead of UDP. `+vc` ("virtual circuit") and `--tcp` are synonyms for `+tcp`. `+novc` / `+notcp` force UDP. `AXFR` and large `IXFR` queries automatically elevate to TCP unless `+udp` is explicitly forced.

`+udp`
: Force UDP transport.

`+tcp-mss=N`
: Set the TCP maximum segment size (`TCP_MAXSEG`) of the query connection to `N` bytes. Implies `+tcp`. Corresponds to the server's `tcp-mss` (see [karidns(8)](karidns.md#transport-tuning-tcp-mss--window-udp-payload-size)).

`+tcp-window=N`
: Set the TCP receive and send buffer sizes (`SO_RCVBUF` / `SO_SNDBUF`) of the query connection to `N` bytes before connecting. Implies `+tcp`.

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

`+[no]http-plain[=endpoint]`, `+[no]http-plain-get[=endpoint]`, `+[no]http-plain-post[=endpoint]`
: Send DNS queries over unencrypted plain HTTP (RFC 8484 message format). Default port is 80; default endpoint is `/dns-query`; the default method is POST. `+http`, `+http-get` and `+http-post` are aliases.

`+[no]proxy[=spec]`
: Prepend a **HAProxy PROXYv2** binary header before the DNS packet.
  - If `spec` is omitted (`+proxy`), sends a PROXYv2 header with `LOCAL` command.
  - If `spec` is provided in `src_addr[#src_port]-dst_addr[#dst_port]` format (e.g., `+proxy=192.0.2.1#1234-192.0.2.2#53`), sends a PROXYv2 `PROXY` command reflecting the specified connection endpoints.
  - On TCP-based transports the header is sent right after the TCP connection is established, **before** any TLS handshake (DoT/DoH). On UDP it is prepended to each datagram.

`+[no]proxy-plain[=spec]`
: Alias for `+proxy`, kept for `dig`/`kdig` compatibility; behaves identically.

`+[no]keepopen`
: Keep the TCP, TLS or HTTPS connection open between consecutive queries to the same server (RFC 7766 connection reuse), e.g. when several queries are given on the command line or in a batch file.

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
: Trace the DNS delegation path iteratively starting from the root nameservers (`.`). By default (`+noglue`, matching BIND 9.20+ `dig` behavior), `dag +trace` ignores the `ADDITIONAL` section of referral responses and resolves the delegated nameserver names (A/AAAA) to follow delegation paths down to authoritative servers, displaying each intermediate answer. Nameserver names are resolved through `@server` when it offers recursion (`RA=1` in its root `NS` response); when `@server` is authoritative-only (e.g. a root server address such as `@192.0.2.1`), they are resolved through the system resolver (`/etc/resolv.conf`, port 53) like BIND `dig`, and names that cannot be resolved are reported as `;; couldn't get address for '<name>'`. Specify `+glue` to restore the previous behavior of using in-bailiwick Glue records from the `ADDITIONAL` section (falling back to resolver lookups only when no glue is present). Honors `+tcp` and automatically falls back to TCP when receiving truncated (`TC=1`) responses. Like BIND `dig`, `+trace` implies `+noadditional`, so the `ADDITIONAL` section of each hop is not displayed; give `+additional` after `+trace` to show it again. Each hop ends with `;; Received N bytes from ADDR#PORT(name) in T ms`, where `name` is the `@server` text (or the system resolver address) for the first query and the nameserver name the address belongs to for the later ones, as in BIND `dig`. Like BIND `dig` 9.20, the trace ends at the authoritative answer: a `CNAME` (or `DNAME`) in the final answer is displayed but not followed; use `+trace2` to follow CNAME/DNAME chains across zones.

`+[no]trace2[=brief|normal|verbose]`
: Resolve the name the way a full iterative resolver (BIND `named`, Unbound) does, **without relying on any local or system resolver**. Unlike `+trace`, which asks `@server` / `/etc/resolv.conf` for the root NS set and for nameserver addresses, `+trace2` primes from built-in root hints (IANA `named.root`; or `@server` / `+roothints=FILE` when given) with a `. NS` query (RFC 8109), follows referrals with RD=0, and resolves nameserver names that come without glue (e.g. `example.jp. NS ns1.example.net.`) itself, starting from the closest zone cut it has already learned. Referral data outside the queried zone's bailiwick is discarded (RFC 2181 §5.4.1). CNAME and DNAME chains are followed across zones; DS queries are sent to the parent side of the zone cut. Lame servers (REFUSED, upward/sideways referrals, non-authoritative empty answers), SERVFAIL and timeouts make it try the next server; FORMERR/NOTIMP to an EDNS query is retried without EDNS. CNAME loops, nameserver dependency loops (`a.test NS ns.b.alt` / `b.alt NS ns.a.test`), recursion depth (8) and the total query budget (`+trace2-maxqueries`, default 200) all end the resolution with `;; resolution failed: <reason>` instead of looping. Every hop on the main delegation path is displayed like `+trace` (`;; Received N bytes from ADDR#PORT(ns-name) in T ms`). The mode selects how nameserver-name sub-resolutions are shown: `normal` (default) prints one line per sub-resolution (`;; [sub] ns1.example.net -> 192.0.2.53 (4 queries)`), `verbose` prints every sub query and response prefixed with `;; [sub N] name/type @addr(ns) for zone`, and `brief` hides them. A final summary line reports the status, total/sub-resolution query counts, lame servers, timeouts and elapsed time. Query IDs are randomized per query. `-p` applies to every hop (useful for test hierarchies); `-4`/`-6`, `+tcp`, `+time`, `+tries`, `+edns`/`+bufsize`/`+dnssec` apply to every query. Glue: by default (and with `+glue`/`+glue=all`) any glue within the bailiwick of the referring zone is used; `+glue=indomain` or an explicit `+noglue` uses only in-domain glue (which a delegation cannot work without, RFC 9471) and resolves the rest. Glue outside the bailiwick of the referring zone (e.g. an `A` record for `ns.other.example.` returned in a referral from the `zone.example.` servers) is never trusted, not even with `+glue=all`, because those servers are not authoritative for it; it is reported as `;; ignoring out-of-bailiwick glue for '<ns>' (not under <zone>)` and the nameserver name is resolved from its own authoritative servers instead. Implies `+noadditional`. Cannot be combined with `+trace` or `+nssearch`. `+trace2` does not validate DNSSEC. Like `dig +trace`, the exit status is 0 whenever the trace ran, including when resolution fails (`;; resolution failed: ...` / `;; trace2: SERVFAIL`); it is 9 only when priming fails (no root server could be reached). When given on the command line with `-f`, `+trace2` and its options apply to every line of the batch file.

`+[no]qmin`, `+qmin=a|ns|off`
: QNAME minimisation (RFC 9156) for `+trace2`. Off by default. When enabled, each zone is asked only for the next label below it (`+qmin` / `+qmin=a` probes with type A as RFC 9156 recommends; `+qmin=ns` probes with type NS as in RFC 7816) until the delegation for the full name is reached, then the real question is sent. If a server answers a minimised probe with NXDOMAIN or an error, `dag` falls back to the full name (relaxed mode, like Unbound). At most 10 minimised queries are sent per resolution.

`+roothints=FILE`
: Use root hints from `FILE` (named.root format: `. NS name` and `name A/AAAA address` lines, TTL and class optional; plain `name address` lines are also accepted) instead of the built-in hints for `+trace2` priming. `@server` takes precedence.

`+trace2-maxqueries=N`
: Abort `+trace2` after `N` queries in total (1-100000, default 200), counting priming and nameserver-name sub-resolutions.

`+[no]nssearch`
: Look up authoritative nameservers for the zone containing the query name and display the SOA record from each responding nameserver. Honors `+tcp` and automatically falls back to TCP when receiving truncated (`TC=1`) responses. By default, `dag +nssearch` resolves nameserver addresses using the system resolver (matching BIND 9 `dig` behavior, `+noglue`). You can also specify `+glue` to query nameservers directly using in-bailiwick A/AAAA records from the `ADDITIONAL` section without consulting `/etc/resolv.conf` (useful in isolated or test network environments).

`+[no]glue`
: Control whether in-bailiwick Glue records (A/AAAA) present in the `ADDITIONAL` section are prioritized over system resolver lookups (`/etc/resolv.conf`). For `+trace`, `+noglue` is the default (matching BIND 9.20+ `dig`, which no longer trusts `ADDITIONAL` section data while tracing); `+glue` restores the legacy behavior of following referral chains via attached glue records. For `+nssearch`, `+noglue` is the default (matching BIND 9 `dig`), and enabling `+glue` allows `dag` to query authoritative nameservers directly using attached glue records from NS responses without relying on the system resolver.

`+glue=all|indomain`
: Select which glue records `+glue` trusts. `all` is the same as plain `+glue` (any A/AAAA in `ADDITIONAL` whose owner matches an NS target). `indomain` reproduces the stricter glue checking introduced in BIND `named` 9.18.41 / 9.20.15 / 9.21.14 ([ISC KB: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue)): glue is trusted only when the NS target (right side) is a subdomain of the NS owner (left side), e.g. `example.org. NS ns1.example.org.`. Sibling or unrelated glue (e.g. `a.example. NS ns1.b.example.`) is ignored and reported as `;; ignoring out-of-domain glue for '<ns>' (NS of '<zone>')`, and those NS names are resolved instead. This is useful for checking whether a delegation that relied on out-of-domain glue still resolves on updated BIND resolvers. Applies to both `+trace` and `+nssearch`.

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

Queries carry an EDNS0 OPT record and a client cookie by default (like `dig`). UPDATE and NOTIFY messages get an OPT record only when one of the options in this section is given.

`+[no]edns[=N]`
: Send an OPT pseudo-RR (on by default); `+edns=N` sets the EDNS version to `N` (default: 0). `+noedns` sends no OPT record.

`+bufsize=N`
: Set the advertised EDNS0 UDP buffer size, 0–65535 (default: 1232 bytes, compliant with DNS Flag Day recommendations). Enables EDNS.

`+[no]dnssec`, `+[no]do`
: Set the **DO (DNSSEC OK)** bit in the EDNS0 OPT record, requesting DNSSEC RRs (RRSIG, NSEC, NSEC3, DS) from the authoritative server.

`+[no]keepalive`
: Send the **EDNS TCP Keepalive (RFC 7828)** option (Option Code 11) in the OPT pseudo-RR.

`+[no]expire`
: Send the **EDNS EXPIRE (RFC 7314)** option (Option Code 9) in query and highlight the zone expiration TTL field in SOA responses.

`+[no]cookie[=hex]`
: Send the **DNS Cookie (RFC 7873 / RFC 9018)** option. Sent by default with a random 8-byte client cookie (like `dig`); `+nocookie` turns it off. If `hex` is supplied, sets the client (8 bytes) or client+server cookie value.

`+[no]badcookie`
: Automatically retry the query once if the server returns a `BADCOOKIE` error, attaching the returned Server Cookie. Enabled by default.

`+[no]showbadcookie`
: Print a diagnostic message when a `BADCOOKIE` retry occurs.

`+subnet=addr[/prefix]`
: Send the **EDNS Client Subnet (ECS)** option (RFC 7871) with the specified IPv4 or IPv6 network prefix (e.g., `+subnet=192.0.2.0/24` or `+subnet=2001:db8::/56`). Specifying `+subnet=0` (or `0/0`, `0.0.0.0/0`, `::/0`) sends an empty source address with prefix length 0 to signal privacy preference. `+nosubnet` removes the option.

`+[no]nsid`
: Request the **Name Server Identifier (NSID)** option (RFC 5001).

`+padding[=N]`, `+nopadding`
: Add the EDNS(0) Padding option (RFC 7830) so that the query size becomes a multiple of the block size `N` (default: 468, the RFC 8467 recommendation). The expected TSIG record is taken into account when TSIG is used.

`+[no]mqtype=TYPE[,TYPE...]`
: Send the **Multiple QTYPE (RFC 10029)** EDNS option (Option Code 20), requesting multiple resource record types (e.g., `+mqtype=A,AAAA,HTTPS`) in a single query transaction. Up to 16 types; `+nomqtype` removes the option.

`+ednsopt=code[:hex]`
: Specify a custom EDNS option code (0–65535) and optional payload encoded in hexadecimal string. Up to 8 `+ednsopt` parameters can be supplied.

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
: Read TSIG key definition or BIND SIG(0) private key from file. `dag` automatically determines the key type:
  - **TSIG (Shared Secret)**: Standard BIND-style key file (e.g., generated by `tsig-keygen`):
    ```
    key "tsig-key.example.com" {
        algorithm hmac-sha256;
        secret "6p9y...==";
    };
    ```
  - **SIG(0) (Public-Key / DNSSEC Private Key)**: BIND `dnssec-keygen` generated `.private` file (e.g., `Kexample.com.+013+12345.private`). When a file starting with `Private-key-format:` is passed, `dag` automatically switches to SIG(0) signing, deriving the signer domain name, algorithm, and key tag from the file and filename without needing extra flags, matching BIND `dig` behavior.

`+fuzztime[=timestamp]`
: Manually override the TSIG or SIG(0) signing time (seconds since Unix epoch) to test clock skew tolerances and replay attack defenses. Default timestamp if `+fuzztime` is passed without argument is `1646972129`. `+nofuzztime` restores current system clock.

---

## SIG(0) TRANSACTION SECURITY (RFC 2931 / RFC 3007)

`dag` supports client-side SIG(0) asymmetric key transaction signatures (RFC 2931 / RFC 3007) for authenticating Dynamic DNS UPDATE and query requests using public-key cryptography (RSA, ECDSA P-256/P-384, Ed25519). Server-side verification in KariDNS is out of scope.

`+sig0-pkey=file`
: Specify the private key file in PKCS#8 / traditional PEM format (`.key` or `.pem`) or BIND DNSSEC private key format (`.private`). The key algorithm is auto-detected (supporting RSA, ECDSA P-256, and Ed25519). Setting this option automatically enables SIG(0) signing.

`+sig0-name=name`
: Specify the signer's domain name (identity of the KEY RR), e.g., `update-key.example.com.`. Required when using PEM keys; automatically extracted when using BIND `-k` / `.private` keys.

`+sig0-alg=N`
: Override the algorithm number (e.g., 8 for RSASHA256, 13 for ECDSAP256SHA256, 15 for ED25519). If omitted, `dag` automatically determines the algorithm from the loaded private key.

`+sig0-keytag=N`
: Override the 16-bit key tag (0–65535). If omitted, `dag` automatically computes the key tag from the public key using RFC 4034 Appendix B and standard KEY RR wire formatting.

`+[no]sig0`
: Toggle SIG(0) transaction signing. Automatically enabled when `+sig0-pkey` or a BIND `.private` key via `-k` is provided. `+nosig0` disables SIG(0) signing.

> [!NOTE]
> TSIG (`-y`, `+tsig`, or `-k <tsig_file>`) and SIG(0) (`+sig0-pkey`, `+sig0`, or `-k <private_file>`) are mutually exclusive per transaction. `+fuzztime` controls the signature inception and expiration timestamps for testing.

---

## DYNAMIC DNS UPDATE (RFC 2136)

`dag` can formulate and send Dynamic DNS UPDATE requests (`OPCODE=5`), supporting record additions, deletions, and prerequisite evaluations. The query name is used as the zone name. Up to 16 update operations and 16 prerequisites can be given per message. The header bits between Opcode and RCODE are Z in an UPDATE message (RFC 2136 §2.2), so RD and AD are sent as 0 unless `+rec` or `+adflag` is given explicitly.

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
| `opcode=N` | Overrides the header `OPCODE` with `N` (e.g. an unassigned value such as 15). | Unhandled Opcode crash / state machine |
| `qr-bit` | Sets the `QR` bit to 1 on an outgoing query (sending a response as a query). | Server reflection / loop amplification |
| `notify-no-question` | Sends `OPCODE=4` (NOTIFY) with `QDCOUNT=0`. | RFC 1996 missing zone question panic |
| `too-short[=N]` | Sends only the first `N` bytes of the message (default: 3). | Short packet header read violation |
| `short-header[=N]` | Alias for `too-short[=N]`. | (same as `too-short`) |
| `tcp-length-overclaim[=N]` | (*TCP only*) Prefixes a 2-byte TCP length `N` bytes larger than sent data (default: `N=10`). | TCP frame starvation / hanging worker |
| `tcp-zero-length` | (*TCP only*) Sends a 2-byte TCP length prefix of `0`. | Zero-length packet hang or memory leak |
| `tcp-idle-hold[=SEC]` | (*TCP only*) Sends only the length prefix, holds the connection for up to `SEC` seconds (default: `SEC=20`) and reports when/if the server disconnects. | Slowloris / connection pool exhaustion |
| `update-meta-type[=N]` | (*UPDATE only*) Injects a meta-type RR of type `N` (default: 41 = OPT) into the Update Section. | Meta-RR validation in dynamic updates |

The TCP-only kinds require `+tcp` (or `--tcp`).

### Automated Batch Fuzzing

`--break all`, `--test-all`
: Sequentially executes the predefined set of built-in anomaly test cases against the target server (each with a 1-second timeout and a single try), printing the response status or timeout for each test case.

`--hex=<hexstring>`
: Directly transmits the raw hexadecimal byte stream as a DNS packet without validation or reconstruction.

---

## MULTI-SERVER QUERY & CONSISTENCY COMPARISON (`+allcompare`, `+ldnsz`)

`dag` allows querying multiple nameservers in parallel or sequentially within a single invocation.

### Multi-Server Target Syntax

Multiple servers are specified via a comma-separated list after `@`:
```sh
dag example.com A @192.0.2.1,198.51.100.1,203.0.113.1:5353,[2001:db8::53]
```

### Response Equivalence Comparison (`+allcompare`)

When more than one response to the same question is collected (several servers, or a UDP answer followed by a TCP retry), `dag` prints a comparison summary after the individual answers. Each response is compared with the base response, the first complete (non-truncated) response to the same question (QNAME, QTYPE, QCLASS) and, for zone transfers, the same message number. The summary is not printed for `+trace`, `+trace2` and `+nssearch`, whose responses answer different questions (BIND `dig` prints no such table either); `+ldnsz` still produces the trace viewer URL for them.

- `[BASE]`: The reference response.
- `MATCH_EXACT`: Binary byte-for-byte match (excluding the 16-bit Query ID).
- `MATCH_SEMANTIC`: Same RCODE, and the same set of resource records in the answer, authority and additional sections, regardless of record order. By default TTLs are ignored.
- `[DIFF]`: Different RCODE or a different record set.

`+allcompare` makes the semantic comparison stricter: TTLs are included in the record hash (column `SEM_HASH(+TTL)`), so records that differ only in their TTL are reported as `[DIFF]`.

```text
;; === MULTI-SERVER COMPARISON SUMMARY ===
SERVER             | PROTO | RCODE   | ANS | AUT | ADD | SEM_HASH   | TIME   | MATCH STATUS
-------------------+-------+---------+-----+-----+-----+------------+--------+------------------------
192.0.2.1          | UDP   | NOERROR |   1 |   0 |   1 | 0x5A3C19E2 |   12ms | [BASE]
198.51.100.1       | UDP   | NOERROR |   1 |   0 |   1 | 0x5A3C19E2 |   18ms | MATCH_SEMANTIC
203.0.113.1#5353   | UDP   | NOERROR |   1 |   0 |   1 | 0x5A3C19E2 |   15ms | MATCH_EXACT
-------------------+-------+---------+-----+-----+-----+------------+--------+------------------------
```

> **Note on TC (Truncation) Retries:**
> When a query triggers automatic TCP retry due to a truncated UDP response (`TC=1`), `dag` intentionally records and displays both the UDP attempt and the TCP retry as separate rows in the summary table. This allows users to explicitly observe and diagnose the transport fallback process.

### LDNSZ Web Inspection URLs (`+ldnsz`)

When `+ldnsz` is supplied:
- **Single Server**: Generates a web inspector URL on `https://ldns.jp/?dnsz=<payload>`, allowing detailed GUI analysis of wire-format packets.
- **Multiple Servers**: Generates a diff URL on `https://ldns.jp/diff/#c=<payload1>,<payload2>`, allowing visual side-by-side binary comparison.
- **`+trace`**: Generates a trace viewer URL on `https://ldns.jp/trace/#c=<payload1>,<payload2>,...` (one payload per delegation hop, same encoding as the diff URL), allowing the delegation path to be inspected step by step.

---

## DISPLAY & FORMATTING OPTIONS

`+[no]short`
: Provide a terse, machine-readable answer containing only the RDATA of the ANSWER section.

`+[no]multiline`, `+[no]multi`
: Print records (such as SOA, DNSKEY, RRSIG, and HTTPS) in human-readable multi-line format with field descriptions and structured comments. Short form (`+[no]multi`) is also supported.

`+[no]yaml`
: Output the complete parsed DNS response in structured YAML format.

`+[no]ttlunits`
: Display TTL values using human-friendly time unit suffixes (`s`, `m`, `h`, `d`, `w`). Implies `+ttlid`.

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
: Split long base64 and hex strings into chunks of `N` characters, rounded up to a multiple of 4 (default: 56; 44 in multiline mode). `+nosplit` or `+split=0` disables splitting.

`+[no]besteffort`
: Attempt to parse and print malformed or corrupted packets.

`+[no]showsearch`
: Show the intermediate results of search list processing (implies `+search`).

`+[no]hexdump`
: Show (default) or suppress the hex dumps of both the outgoing query and the incoming response.

`+[no]hexdump-query`
: Show or suppress the hex dump of the outgoing query only.

`+[no]hexdump-response`
: Show or suppress the hex dump of the incoming response only.

---

## MULTIPLE QUERIES & BATCH PROCESSING

`dag` allows specifying multiple query tuples on a single command line:

```sh
dag +qr example.com A @192.0.2.53 +subnet=192.0.2.0/24 -x 192.0.2.1 @198.51.100.53 +noqr
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

# Resolve like a full resolver, without any local resolver
dag example.jp A +trace2

# Same, showing every query made to resolve glueless nameservers, with QNAME minimisation
dag example.jp A +trace2=verbose +qmin
```

### Multi-Server Comparison & LDNSZ Integration
```sh
# Compare answers across three servers (TTLs included)
dag example.com A @192.0.2.1,198.51.100.1,203.0.113.1 +allcompare

# Generate visual online diff URL
dag example.com A @192.0.2.1,198.51.100.1 +ldnsz
```

### Modern Transports (DoT / DoH / PROXYv2)
```sh
# Query via DNS over TLS (DoT)
dag example.com A @127.0.0.1 +tls +tls-ca=/etc/ssl/cert.pem

# Query via DNS over HTTPS (DoH) using GET
dag example.com A @doh.example.net +https-get

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

# Dynamic DNS Update with SIG(0) transaction signature (RFC 3007 / RFC 2931)
dag example.com @127.0.0.1 +sig0-pkey=key.pem +sig0-name=update-key.example.com. \
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
- **RFC 2136**: Dynamic Updates in the Domain Name System (DNS UPDATE)
- **RFC 2931**: DNS Request and Transaction Signatures ( SIG(0)s ) (client-side transaction signing in `dag`; server-side verification is out of scope)
- **RFC 3007**: Secure Domain Name System (DNS) Dynamic Update (client-side SIG(0) transaction signing in `dag`; server-side verification is out of scope)
- **RFC 3597**: Handling of Unknown DNS Resource Record Types
- **RFC 4033 / RFC 4034 / RFC 4035**: Resource Records for the DNS Security Extensions (DNSSEC)
- **RFC 5001**: DNS Name Server Identifier (NSID) Option
- **RFC 5936**: DNS Zone Transfer Protocol (AXFR)
- **RFC 7050**: Discovery of the IPv6 Prefix Used for IPv6 Address Synthesis (DNS64)
- **RFC 7314**: Extension Mechanisms for DNS (EDNS) EXPIRE Option
- **RFC 7766**: DNS Transport over TCP - Implementation Requirements
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
- [`karicheck(1)`](karicheck.md) — Configuration and zone file validation utility
- [`dag_replay(1)`](dag_replay.md) — Traffic replay and differential testing (`dag --replay`)
- [`dag.c`](../tools/dag.c) — Source implementation of the DNS Anomaly Generator
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## SECURITY & FUZZING

### Historical Vulnerability Fixes

- **APL (TYPE 42) afdlength Stack Buffer Overflow (CWE-121 / CWE-787)**:
  `format_rdata_for_display()` (used during `+yaml` formatting and `+allcompare` record hash calculation) copied `afdlength` bytes into a fixed `uint8_t addr[16]` buffer without upper-bound clamping. Fixed by clamping copy length: `copy_len = (afdlength > sizeof(addr)) ? sizeof(addr) : afdlength;` and emitting a diagnostic indicator `[APL afdlength=%u invalid for AFI=%u]`.
  Regression testing is automated via `tests/run_dag_apl_afdlength_overflow_test.sh` and continuous fuzzer `tests/fuzz/fuzz_dag_hash`.

- **`+trace` CNAME Tracking Stack Exhaustion via Deep Recursion (CWE-674 / CWE-789)**:
  `run_trace_query_impl()` recursively invoked itself up to `TRACE_MAX_CNAME_DEPTH` (16) times when traversing CNAME delegation chains. Each recursive frame allocated ~270 KB of stack buffers (`root_qbuf`, `root_resp`, `qbuf`, `resp` at 65,535 bytes each plus local arrays), consuming up to 4.3 MB of stack under unoptimized (`-O0`) or instrumented (ASan/TSan) builds where Tail Call Optimization (TCO) is inhibited. Fixed by converting the CNAME resolution into an iterative loop (`cname_depth` loop) and allocating the four 65 KB I/O buffers on the heap with guaranteed cleanup, reducing per-call stack usage to a single ~16 KB frame. Since then `+trace` no longer follows CNAMEs at all (it stops at the CNAME answer like BIND `dig` 9.20; chains are followed by `+trace2`, which bounds them at 16 links and detects loops).
  Regression testing is automated via `tests/run_dag_trace_deep_cname_stack_test.sh`.

### Fuzzing & Differential Test Harnesses

`make fuzz_dag_all` builds the following libFuzzer harnesses (`sh tests/run_fuzz_smoke_test.sh dag` runs a short smoke test of them):

| Target | Description | Scope |
|---|---|---|
| `fuzz_dag` (`fuzz_dag_response`) | Response parser and display | Response decoding and dig-style formatting |
| `fuzz_dag_hash` | Packet semantic hash & RDATA formatting | `calculate_packet_hashes()` → `format_rdata_for_display()` |
| `fuzz_dag_iter_classify` | `+trace2` response classification | `dag_iter_classify()`: CNAME/DNAME chains, referral and glue extraction with bailiwick checks, SOA detection |
| `fuzz_dag_replay_pcap_reader` | `--replay` PCAP frame decoder | Link-layer (Ethernet, Linux SLL, raw, NULL) / IP / UDP / TCP decoding |
| `fuzz_dag_replay_diff` | `--replay` differential engine | `diff_dns_responses()` |
| `fuzz_dag_tcp_reassembly` | TCP stream reassembly for PCAP replay | Segment ordering and DNS-over-TCP framing |
| `fuzz_dag_chunked_http` | DoH HTTP/1.1 chunked transfer decoder | `decode_http_response_body()` boundary values |
| `fuzz_dag_rdata_yaml` | Direct RDATA parser & display formatter | `format_rdata_for_display()` with `dopt=NULL` and `+yaml` |
| `fuzz_dag_axfr_stream` | Multi-message AXFR streaming state machine | Stateful multi-packet `axfr_state_t` sequence transitions |
| `fuzz_dag_cli_args` | Command-line option & malformation parser | `parse_arg_slice()`, `parse_break_arg()` |
| `fuzz_dag_batch_file` | Batch query file (`-f`) tokenizer & parser | Line tokenizer and token boundary validation |
| `rr_differential_test.pl`| Structured RR semantic oracle / diff test | NAPTR, SRV, SOA, CAA, MX field transpositions |

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                        DAG(1)
```

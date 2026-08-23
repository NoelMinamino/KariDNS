# KariDNS
**(Kqueue Arena-based RCU Immoral DNS)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: FreeBSD](https://img.shields.io/badge/Platform-FreeBSD-red.svg)](https://www.freebsd.org/)
[![Build CI](https://github.com/NoelMinamino/KariDNS/actions/workflows/ci.yml/badge.svg)](https://github.com/NoelMinamino/KariDNS/actions/workflows/ci.yml)

KariDNS is an authoritative DNS server designed for FreeBSD. It utilizes FreeBSD kernel features—including `kqueue` for event handling and `Capsicum` for sandboxing—together with an RCU-based data model and pre-allocated memory arenas.

---

## Architecture & Design

- **Dual-Process Model & Capsicum Sandboxing:**
  - **Frontend:** Binds privileged ports (UDP/TCP 53) and manages network sockets.
  - **Backend:** Enters Capsicum capability mode (`cap_enter()`) to parse DNS queries and generate responses without direct filesystem or network socket creation privileges. Zone and configuration files are reloaded using pre-opened directory descriptors (`openat`/`renameat`).
- **Memory Arenas:**
  - Zone data is loaded into memory arenas (`zone_arena_t`), avoiding `malloc`/`free` allocations during query processing.
- **Lock-Free Read-Copy-Update (RCU):**
  - Thread synchronization uses C11 atomic operations (`stdatomic.h`) to swap zone and configuration pointers without blocking worker threads during reloads.
- **Kqueue-based Event Loop:**
  - Network I/O is managed using FreeBSD's native `kqueue` subsystem for TCP and UDP connections.

---

## Features

- **Authoritative Master & Slave Roles:** Supports AXFR (RFC 5936) and IXFR (RFC 1995) zone transfers, as well as inbound and outbound NOTIFY (RFC 1996) with TSIG authentication.
- **Dynamic DNS Update:** Ephemeral DNS UPDATE handling (RFC 2136 / RFC 3007) with prerequisite evaluation and TSIG verification.
- **DNSSEC Support (Static):** Serves pre-signed DNSSEC records (DNSKEY, RRSIG, NSEC, DS, CDS, CDNSKEY, CSYNC, etc.). Includes RFC 8976 (ZONEMD) digest validation.
- **Security & Rate Limiting:**
  - **Response Rate Limiting (RRL):** BIND9-compatible token-bucket rate limiting with response classification, CIDR aggregation, and `slip` truncation.
  - **DNS Cookies (RFC 7873 / RFC 9018):** Generates and validates client and server cookies.
  - **TSIG (RFC 8945):** Transaction authentication supporting HMAC-MD5, SHA1, SHA224, SHA256, SHA384, and SHA512.
  - **Extended DNS Errors (EDE, RFC 8914):** Returns diagnostic error codes when queries cannot be fulfilled normally.
- **Protocol Extensions:**
  - **SVCB / HTTPS Records (RFC 9460):** Serialization of structured SvcParams (`alpn`, `port`, `ipv4hint`, `ipv6hint`, `ech`, etc.).
  - **Multiple QTYPEs (MQTYPE, RFC 10029):** Resolving multiple record types in a single query (configurable via `rfc10029-mqtype`).
  - **TCP Connection Reuse & Keepalive (RFC 7766, RFC 9210, RFC 7828):** Configurable TCP connection reuse and idle timeout parameters.
  - **Minimal ANY & Minimal Responses (RFC 8482):** Prevents ANY query response amplification.
  - **NSID (RFC 5001):** Server identifier transmission via EDNS.
- **Views:** Split-horizon configuration using `view` blocks and `match-clients` IP matching.
- **Logging:** Non-blocking multi-producer single-consumer (MPSC) logging channels with size- and date-based rotation.

---

## Standards & RFC Compliance

KariDNS implements specifications according to official IETF RFC standards. For a detailed list of supported RFCs, implementation notes, and design boundaries, please consult:

- **[KariDNS RFC Compliance Guideline](KariDNS_RFC_GUIDELINE.md)**
- **[Installation & Multi-Platform Distribution Guide (FreeBSD, Linux, macOS, Homebrew)](docs/distribution.md)**

---

## Supported Record Types & Zone Directives

### Supported Record Types
`A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `TXT`, `SPF`, `SRV`, `DNAME`, `LOC`, `APL`, `CAA`, `URI`, `HINFO`, `MINFO`, `RP`, `AFSDB`, `RT`, `KX`, `LP`, `PX`, `X25`, `ISDN`, `NSAP`, `GPOS`, `NID`, `L32`, `L64`, `SSHFP`, `TLSA`, `SMIMEA`, `CERT`, `NAPTR`, `NSEC3PARAM`, `HTTPS`, `SVCB`, `OPENPGPKEY`, `DHCID`, `EUI48`, `EUI64`, `ZONEMD`, `CSYNC`, `DS`, `CDS`, `DNSKEY`, `CDNSKEY`, `IPSECKEY`, `AMTRELAY`, `AVC`, `DSYNC`, `NXNAME`

### Zone File Directives
- `$ORIGIN <domain>`
- `$TTL <default-ttl>` (supports BIND-compatible time unit suffixes: `w`, `d`, `h`, `m`, `s`)
- `$INCLUDE <filename> [origin]` (supports up to 32 files and 16 nesting levels within Capsicum constraints)
- `$GENERATE <range> <template>`

---

## Included Tools

### 1. `karidns`
The main authoritative DNS server daemon. For detailed architecture and configuration options, see the **[karidns(8) Manual](docs/karidns.md)**.

### 2. `karictl`
An authenticated management tool (RNDC-style) that communicates with the server over a UNIX domain socket using HMAC-SHA256. For command reference and configuration details, see the **[karictl(8) Manual](docs/karictl.md)**.

```sh
# Check server status
./karictl status

# Reload configuration and zone files without restart
./karictl reload

# Send NOTIFY to slave servers for a specific zone
./karictl notify example.com

# Request an AXFR zone transfer from the master
./karictl retransfer example.com

# Stop the server
./karictl stop
```

### 3. `karicheck`
A zone file syntax and configuration validation utility. It performs pre-flight checks and validates RFC 8976 ZONEMD message digests. For command options and verification details, see the **[karicheck(1) Manual](docs/karicheck.md)**.

```sh
# Validate configuration syntax
./karicheck conf /usr/local/etc/karidns/karidns.conf

# Validate all zones referenced in the configuration
./karicheck zones /usr/local/etc/karidns/karidns.conf

# Validate a specific zone file and verify ZONEMD digest
./karicheck zone example.com /path/to/example.com.zone
```

### 4. `dag` (DNS Anomaly Generator)
A test client, protocol debugger, and packet fuzzer for DNS servers. For full option specifications and fuzzing modes, see the **[dag(1) Manual](docs/dag.md)**.

`dag` can construct custom queries (including EDNS options, Cookie, EDNS Client Subnet, IXFR, Dynamic Updates, etc.), output formatted responses (`+short`, `+yaml`, `+multiline`), generate web links (`+ldnsz`) for online wire-format analysis, and intentionally generate malformed or boundary-testing packets using the `--break` option.

> [!WARNING]
> **Intended for Local Testing Only**
> Do not use this tool (especially the `--break` fuzzing options) against external or public DNS servers that you do not own or operate.

#### Common `dag` Usage Examples:
```sh
# Standard query
./dag example.com A @127.0.0.1 -p 53

# Query with DNSSEC (DO bit), NSID, and EDNS Client Subnet
./dag example.com AAAA @127.0.0.1 +dnssec +nsid +subnet=192.0.2.0/24

# Perform an IXFR query over TCP (automatically appends SOA)
./dag example.com IXFR=2026082201 @127.0.0.1

# Send a Dynamic Update (RFC 2136)
./dag example.com @127.0.0.1 --update-add "host.example.com 300 IN A 192.0.2.50"

# Output response as YAML
./dag example.com ANY @127.0.0.1 +yaml

# Trace delegation hierarchy (+trace)
./dag example.com A @127.0.0.1 +trace
```

#### Protocol Robustness & Fuzzing (`--break`):
`dag` supports various packet modification modes to evaluate how DNS servers handle malformed or edge-case wire formats:

```sh
# Test compression pointer loop handling
./dag example.com A @127.0.0.1 --break compression-loop

# Test oversized domain label handling (> 63 octets)
./dag example.com A @127.0.0.1 --break label-too-long

# Test invalid QDCOUNT handling
./dag example.com A @127.0.0.1 --break qdcount:2

# Test malformed OPT RDLEN
./dag example.com A @127.0.0.1 --break opt-rdlen:500

# Test TCP length overclaim
./dag example.com A @127.0.0.1 --tcp --break tcp-length-overclaim:50

# Run all built-in anomaly tests sequentially
./dag example.com A @127.0.0.1 --break all

# View full list of available --break options
./dag --break-help
```

For complete command-line options, advanced transport modes (DoT/DoH/PROXYv2), multi-server consistency checking (`+allcompare`), and protocol anomaly generator specifications, please consult the dedicated manual:

- **[KariDNS `dag(1)` Reference Manual](docs/dag.md)**

---

## Building and Running

### Prerequisites
- **Operating System:** FreeBSD (tested on FreeBSD 14.x / 15.0-CURRENT)
- **Compiler:** Clang or GCC (C11 support required)
- **Libraries:** OpenSSL (`libcrypto`), `libidn2` (optional, for IDN support), `pthread`

### Compilation
To compile the server and companion utilities:
```sh
make all
```

To run test suites with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan):
```sh
make asan_test
```

### Running the Server
Start KariDNS by providing the configuration file path:
```sh
./karidns /usr/local/etc/karidns/karidns.conf
```

---

## Configuration Example

### Server Configuration (`karidns.conf`)
```
options {
    port 53;
    bind-address { 127.0.0.1; 192.0.2.1; };
    user "bind";
    group "bind";

    tcp-connection-reuse yes;
    tcp-idle-timeout 10;
    minimal-any yes;
    nsid "karidns-node-01";

    rate-limit {
        responses-per-second 50;
        nxdomains-per-second 20;
        errors-per-second 10;
        window 15;
        slip 2;
        exempt-clients { 127.0.0.1/32; 192.168.0.0/16; };
    };
};

key "tsig-key-primary" {
    algorithm hmac-sha256;
    secret "c2VjcmV0LWtleS1leGFtcGxlCg==";
};

control-channel {
    algorithm hmac-sha256;
    secret "Y29udHJvbC1zZWNyZXQta2V5Cg==";
};

logging {
    channel query_log {
        file "/var/log/karidns/queries.log" versions 5 size 100m;
        severity info;
        print-time yes;
        print-category yes;
    };
    category queries { query_log; };
};

zone "example.com" {
    type master;
    file "master/example.com.zone";
    also-notify { 198.51.100.2 port 53; };
    allow-transfer { key "tsig-key-primary"; };
};

zone "slave.example.net" {
    type slave;
    file "slave/slave.example.net.zone";
    masters { 192.0.2.100 port 53; };
    tsig-key "tsig-key-primary";
};
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---
*Copyright (c) 2026 Noel Minamino*

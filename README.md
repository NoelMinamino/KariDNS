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

- **Authoritative Zone Roles & Formats:**
  - **Master (Primary) & Slave (Secondary):** Supports standard BIND-style zone files and djbdns/tinydns-style plain-text `data` files (`file-format tinydns;`). Supports AXFR (RFC 5936) and IXFR (RFC 1995) zone transfers, inbound and outbound NOTIFY (RFC 1996) with TSIG authentication.
  - **Forward Zones (`type forward`):** Transparent query forwarding to multiple upstream nameservers with per-zone timeouts, shared deadline budgeting, automatic failover, transaction ID randomization, and response verification.
  - **Program Zone Plugins (`type program`):** Test-only dynamic external process-backed zones communicating over stdin/stdout pipes with strict privilege dropping and automatic circuit-breaker failure isolation.
- **Dynamic DNS Update:** Ephemeral DNS UPDATE handling (RFC 2136 / RFC 3007) with prerequisite evaluation and TSIG verification.
- **DNSSEC Support (Static):** Serves pre-signed DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, DS, CDS, CDNSKEY, CSYNC, etc.). Includes RFC 8976 (ZONEMD) digest validation.
- **Security & Rate Limiting:**
  - **Response Rate Limiting (RRL):** BIND9-compatible token-bucket rate limiting with response classification, CIDR aggregation, and `slip` truncation.
  - **DNS Cookies (RFC 7873 / RFC 9018):** Generates and validates client and server cookies.
  - **TSIG (RFC 8945):** Transaction authentication supporting HMAC-MD5, SHA1, SHA224, SHA256, SHA384, and SHA512.
  - **Extended DNS Errors (EDE, RFC 8914):** Returns diagnostic error codes when queries cannot be fulfilled normally.
- **Protocol Extensions:**
  - **SVCB / HTTPS Records (RFC 9460):** Serialization of structured SvcParams (`alpn`, `port`, `ipv4hint`, `ipv6hint`, `ech`, `mandatory`, and generic `keyNNN`).
  - **Multiple QTYPEs (MQTYPE, RFC 10029):** Resolving multiple record types in a single query (configurable via `rfc10029-mqtype`).
  - **Delegation Synchronization (DSYNC, RFC 9859):** Full support for DSYNC record formatting, parsing, and wire-format serialization.
  - **TCP Connection Reuse & Keepalive (RFC 7766, RFC 9210, RFC 7828):** Configurable TCP connection reuse and idle timeout parameters.
  - **Minimal ANY & Minimal Responses (RFC 8482):** Prevents ANY query response amplification.
  - **NSID (RFC 5001):** Server identifier transmission via EDNS.
- **Views:** Split-horizon configuration using `view` blocks and `match-clients` IP matching.
- **Client Geolocation & Subnet Steering (ECS & Location Tags):**
  - **BIND Zone Steering:** Granular record-level split-horizon steering based on immediate client IP (`$LOCATION` / `$LOCATION-TAG`) and EDNS0 Client Subnet (`$ECS-SUBNET` / `$ECS-SUBNET-TAG`, RFC 7871) with ACL validation (`ecs-trusted-resolvers`).
  - **tinydns `%` Location Steering:** Native djbdns-compatible IPv4 longest-prefix matching and record steering.
  - **KariDNS Extended AXFR:** Primary-to-Secondary zone replication preserving location and ECS directives via EDNS Option 65153 negotiation, with automatic fallback (Plan B) to standard AXFR for non-KariDNS secondaries.
  - For detailed configuration, usage, and examples, see **[KariDNS: Client Geolocation & Subnet Steering Guide](docs/KariDNS_How_to_use_ECS_and_location.md)**.
- **Logging:** Non-blocking multi-producer single-consumer (MPSC) logging channels with size- and date-based rotation.

---

## Standards & RFC Compliance

KariDNS implements specifications according to official IETF RFC standards. For a detailed list of supported RFCs, implementation notes, and design boundaries, please consult:

- **[KariDNS RFC Compliance Guideline](KariDNS_RFC_GUIDELINE.md)**
- **[Client Geolocation & Subnet Steering Guide (ECS & Location)](docs/KariDNS_How_to_use_ECS_and_location.md)**
- **[Installation & Multi-Platform Distribution Guide (FreeBSD, Linux, macOS, Homebrew)](docs/distribution.md)**

---

## Supported Record Types & Zone Directives

### Supported Resource Record (RR) Types
KariDNS natively parses, validates, and serializes the following standard and experimental DNS record types, as well as RFC 3597 unknown record syntax (`TYPE<n>` / `\#`):

- **Core & Routing:** `A`, `AAAA`, `NS`, `CNAME`, `DNAME`, `PTR`, `MX`, `SOA`, `TXT`, `SPF`, `SRV`, `LOC`, `APL`, `CAA`, `URI`, `HINFO`, `MINFO`, `RP`, `AFSDB`, `RT`, `KX`, `LP`, `PX`, `WKS`, `X25`, `ISDN`, `NSAP`, `NSAP-PTR`, `GPOS`, `NULL`, `MD`, `MF`, `MB`, `MG`, `MR`, `NXT`, `EID`, `NIMLOC`, `ATMA`, `A6`, `SINK`
- **DNSSEC & Cryptographic Identities:** `DS`, `CDS`, `DNSKEY`, `CDNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `SSHFP`, `TLSA`, `SMIMEA`, `CERT`, `OPENPGPKEY`, `IPSECKEY`, `HIP`, `TA`, `DLV`, `SIG`, `KEY`
- **Modern Web, Discovery & Service Bindings:** `HTTPS`, `SVCB`, `NAPTR`, `DSYNC`, `ZONEMD`, `CSYNC`, `DHCID`, `EUI48`, `EUI64`, `NID`, `L32`, `L64`, `NXNAME`, `AVC`, `DOA`, `AMTRELAY`
- **Pseudo & Meta Types:** `OPT` (EDNS0), `TSIG`, `TKEY`, `AXFR`, `IXFR`, `ANY` (RFC 8482), `MAILB`, `MAILA`, `TYPE<n>` (RFC 3597)

### Zone File Formats & Directives
- **Standard BIND Format (Default):**
  - Directives: `$ORIGIN`, `$TTL`, `$INCLUDE` (supports up to 32 files and 16 nesting levels within Capsicum constraints), `$GENERATE`, `$LOCATION`, `$LOCATION-TAG`, `$ECS-SUBNET`, `$ECS-SUBNET-TAG`.
- **djbdns/tinydns Plain-Text Format (`file-format tinydns;`):**
  - Loads zone data directly from djbdns/tinydns plain-text `data` files (not compiled `data.cdb`).
  - Supports record markers `.` (SOA+NS+A), `&` (NS+A), `+` (A), `=` (A+PTR), `-` (disabled/comment), `@` (MX+A), `'` (TXT, 127-byte chunking), `^` (PTR), `C` (CNAME), `Z` (complete SOA), and `:` (generic RR).
  - Handles client geolocation steering with `%` location prefixes and trailing `:loc` record tags, parent/child zone delegation with longest-suffix matching, and load-time TAI64 `timestamp` / countdown TTL evaluation.

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

## Installation & Distribution

KariDNS and its tools are distributed as pre-built packages for FreeBSD, Linux, and macOS.

> [!IMPORTANT]
> **Platform Support Scope:**
> - **FreeBSD (Full Suite):** Includes the authoritative server daemon (`karidns`), management tool (`karictl`), syntax validator (`karicheck`), and DNS testing client (`dag`), along with sample configs and `rc.d` service scripts.
> - **Linux, macOS & Windows (Client Only):** Since `karidns` relies on FreeBSD-native kernel features (`kqueue`, `Capsicum`), non-FreeBSD platforms distribute **`dag` only** (as an ultra-fast, feature-rich DNS query tool and fuzzer alternative to `dig`).

### 1. FreeBSD Installation (`karidns` Full Suite)

Download the `.pkg` file matching your FreeBSD version from [GitHub Releases](https://github.com/NoelMinamino/KariDNS/releases) and install as root (`su -`):

```sh
# Switch to root
su -

# For FreeBSD 14.x (amd64)
pkg add https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/karidns-?.?.?-FreeBSD-14-amd64.pkg

# For FreeBSD 15.x (amd64)
pkg add https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/karidns-?.?.?-FreeBSD-15-amd64.pkg

# Or install locally downloaded package
pkg add karidns-?.?.?-FreeBSD-14-amd64.pkg
```

**Starting the service (as root):**
```sh
# Copy sample configuration
cp /usr/local/etc/karidns/karidns.conf.sample /usr/local/etc/karidns/karidns.conf
cp /usr/local/etc/karidns/zones/example.local.zone.sample /usr/local/etc/karidns/zones/example.local.zone

# Enable and start daemon
sysrc karidns_enable="YES"
service karidns start
```

---

### 2. macOS Installation (`dag` only)

#### Option A: Generic Tarball (.tar.gz) [Fastest]
```sh
# For Apple Silicon (M1/M2/M3/M4):
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-macos-arm64.tar.gz
tar -xzf dag-?.?.?-macos-arm64.tar.gz
sudo cp dag-?.?.?/dag /usr/local/bin/

# For Intel Macs:
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-macos-x86_64.tar.gz
tar -xzf dag-?.?.?-macos-x86_64.tar.gz
sudo cp dag-?.?.?/dag /usr/local/bin/
```

#### Option B: Standalone DMG (.dmg)
1. Download `dag-?.?.?-macos-arm64.dmg` (or `x86_64`) from GitHub Releases.
2. Double-click the DMG and copy `dag` to `/usr/local/bin` (or your preferred `$PATH`).

#### Option C: Homebrew Tap
```sh
brew install NoelMinamino/tap/dag
```

---

### 3. Linux Installation (`dag` only)

#### RPM-based (RHEL 9, Rocky Linux 9, AlmaLinux 9, Fedora)
```sh
# Download and install with DNF / RPM
sudo dnf install https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-1.el9.x86_64.rpm

# Or via rpm command
sudo rpm -ivh dag-?.?.?-1.el9.x86_64.rpm
```

#### DEB-based (Ubuntu 22.04 / 24.04, Debian 11 / 12)
```sh
# Download and install with DPKG
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag_?.?.?_amd64.deb
sudo dpkg -i dag_?.?.?_amd64.deb
```

#### Generic Linux Tarball (.tar.gz)
```sh
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-linux-x86_64.tar.gz
tar -xzf dag-?.?.?-linux-x86_64.tar.gz
sudo cp dag-?.?.?/dag /usr/local/bin/
```

---

### 4. Windows Installation (`dag.exe` only)

Download `dag-?.?.?-windows-x86_64.zip` from [GitHub Releases](https://github.com/NoelMinamino/KariDNS/releases).

1. Extract the ZIP archive.
2. Place `dag.exe` in a directory registered in your system `%PATH%` (e.g., `C:\Windows\System32` or your local tools directory).
3. Open Command Prompt or PowerShell:
   ```cmd
   dag.exe www.google.com A @8.8.8.8
   ```

For complete packaging details and checksum verification, see the **[Distribution Guide](docs/distribution.md)**.

---

## Building from Source

### Prerequisites
- **Operating System:** FreeBSD (for full suite), Linux / macOS (for `dag` client)
- **Compiler:** Clang or GCC (C11 support required)
- **Libraries:** OpenSSL (`libcrypto`, `libssl`), `zlib`, `libidn2` (optional, for IDN support), `pthread`

### Compilation
To compile all utilities on FreeBSD:
```sh
make all
```

To compile only the `dag` client (on Linux, macOS, or FreeBSD):
```sh
make dag
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

    allow-program-zones yes; # Required if using type program zones
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

# Standard BIND-format master zone
zone "example.com" {
    type master;
    file "master/example.com.zone";
    file-format bind; # "bind" (default) or "tinydns"
    also-notify { 198.51.100.2 port 53; };
    allow-transfer { key "tsig-key-primary"; };
};

# djbdns/tinydns plain-text data format master zone
zone "tinydns.example.com" {
    type master;
    file "data/tinydns.example.com.data";
    file-format tinydns; # loads djbdns plain-text data file (not .cdb)
};

zone "slave.example.net" {
    type slave;
    file "slave/slave.example.net.zone";
    masters { 192.0.2.100 port 53; };
    tsig-key "tsig-key-primary";
};

# Transparent forward zone
zone "corp.example.org" {
    type forward;
    forwarders { 192.0.2.53; 198.51.100.53 port 5353; };
    forward-timeout 2000; # timeout in milliseconds
};

# Dynamic external program plugin zone (testing/anomaly fuzzing)
zone "anomaly.test" {
    type program;
    program "/usr/local/bin/mock_dns_server.pl";
    program-args { "--verbose"; };
    program-timeout 2000; # timeout in milliseconds
    program-user "nobody"; # optional privilege drop
};
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---
*Copyright (c) 2026 Noel Minamino*

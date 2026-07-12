# KariDNS
**(Kqueue Arena-based RCU Immoral DNS)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: FreeBSD](https://img.shields.io/badge/Platform-FreeBSD-red.svg)](https://www.freebsd.org/)
[![Build CI](https://github.com/NoelMinamino/KariDNS/actions/workflows/ci.yml/badge.svg)](https://github.com/NoelMinamino/KariDNS/actions/workflows/ci.yml)

KariDNS is a high-performance, lightweight, and modern authoritative DNS server designed specifically for FreeBSD. It focuses on extreme concurrency and low-latency query processing by leveraging advanced system-level features.

## Key Features

- **Kqueue-based Event Loop:** Highly optimized asynchronous I/O using FreeBSD's native `kqueue`, ensuring scalable handling of thousands of concurrent TCP and UDP connections.
- **Arena-based Memory Management:** Zero-allocation in the hot path. Zone data is loaded into memory arenas, minimizing fragmentation and providing lightning-fast memory access during query resolution.
- **RCU (Read-Copy-Update) Architecture:** Lock-free, concurrent data structure swaps. Configuration and zone files can be hot-reloaded instantly without dropping a single query or blocking worker threads.
- **Master/Slave Support:** Built-in support for AXFR (Authoritative Zone Transfer), handling both master (sending) and slave (receiving) roles concurrently with background workers.
- **Security & Reliability:**
- **Advanced Capsicum Sandboxing & Dual-Process Architecture:** 
  - KariDNS adopts a strictly isolated two-process model (Frontend Router and Backend Workers). The Frontend binds privileged ports and routes UDP traffic while remaining outside the sandbox. The Backend drops privileges, enters the Capsicum sandbox (`cap_enter()`), and securely processes DNS logic without any filesystem or network socket creation rights.
  - Configuration reloading inside the sandbox is achieved safely using pre-opened directory file descriptors (`openat`/`renameat`).
- **Robust TSIG (Transaction Signature):** Verification for zone transfers and NOTIFY messages.
- **DNS Cookies (RFC 7873/9018):** Mitigates IP spoofing and amplification attacks by issuing and verifying client/server cookies.
- **Extended DNS Errors (EDE, RFC 8914):** Provides enhanced troubleshooting by returning specific error codes (e.g., Not Authoritative, Unsupported DNSKEY Algorithm, DNSSEC Bogus) when appropriate.
- **Privilege Dropping:** Supports `user` / `group` directives to run with least privilege.
- **RRL (Response Rate Limiting):** Protects against DNS reflection and amplification attacks with BIND9-compatible configuration, precise response classification, CIDR aggregations, and `slip` (truncation) fallback logic.
- **BIND-compatible Query Logging:** Thread-safe query logging with automatic rotation by size or date.
- **RNDC-style Control Channel (`karictl`):** Secure local administration using a UNIX domain socket and HMAC-SHA256 challenge-response authentication.

## Building and Running

### Prerequisites
- FreeBSD operating system (tested on FreeBSD 15.0p9)
- Clang or GCC compiler
- OpenSSL (for TSIG and Control Channel HMAC-SHA256 support)

### Compilation
Simply run `make` or `make all` in the project root to compile the server and the `karictl` client:
```sh
make all
```

### Running the Server
Start KariDNS by passing the path to your configuration file as the first argument:
```sh
./karidns /path/to/karidns.conf
```

To reload the configuration and zone files dynamically without restarting the server, you can use the `karictl` tool:
```sh
./karictl reload
```

### DNS Anomaly Generator (`dag`)

Included with KariDNS is `dag`, a versatile DNS test client and protocol fuzzer. It allows you to construct custom DNS queries (including EDNS, Cookie, Subnet, and IXFR, etc.), generate web links (`+ldnsz`) for wire-format workbench, and intentionally malform packets using the `--break` flag to test server resilience.

> [!WARNING]
> **Intended for Local Testing Only**
> We strongly advise against using this tool (especially the `--break` fuzzing options) against external or public DNS servers that you do not own or manage.

```sh
# Normal query
./dag example.com A @127.0.0.1 -p 53

# IXFR query over TCP (automatically adds SOA record)
./dag example.com IXFR=2026070603 @127.0.0.1

# Test server handling of structural packet errors
./dag example.com A @127.0.0.1 --break label-too-long
```

## Control Channel & Configuration Format

KariDNS supports an administrative control channel similar to BIND's `rndc`. 

### karidns.conf (Server Side)
To enable the control channel on the server, add the `control-channel` block to your `karidns.conf`:
```
control-channel {
    algorithm hmac-sha256;
    secret "your-base64-secret-here";
};
```

### Response Rate Limiting (RRL)

RRL helps mitigate DNS amplification attacks by limiting the number of identical responses sent to a single client subnet. It is disabled by default. You can enable it globally in `options` or override it per-zone:

```
options {
    rate-limit {
        responses-per-second 50;
        nxdomains-per-second 20;
        errors-per-second 10;
        window 15;
        slip 2;
        exempt-clients { 127.0.0.1/32; 192.168.0.0/16; };
    };
};
```

### karictl.conf (Client Side)
Create a file at `/usr/local/etc/karictl.conf` (or any path) for the `karictl` client with a matching secret block:
```
key "karictl" {
    algorithm hmac-sha256;
    secret "your-base64-secret-here";
};
```

### Using karictl
`karictl` uses `/usr/local/etc/karictl.conf` by default. You can specify a custom config path using the `-f` flag.
```sh
# Check server status
./karictl -f /custom/karictl.conf status

# Reload configuration and all zones
./karictl reload

# Stop the server gracefully
./karictl stop

# Send NOTIFY to slaves for a specific zone
./karictl notify example.com

# Request a zone transfer (AXFR) from the master
./karictl retransfer example.com
```

## Logging

KariDNS provides thread-safe, high-performance logging capabilities that are compatible with BIND9 formats. Logging is entirely asynchronous and utilizes a lock-free Multi-Producer Single-Consumer (MPSC) ring buffer to ensure the hot path (query processing) is never blocked.

You can configure separate channels for `queries` and `responses`, and apply them in your configuration.

```
logging {
    channel query_log {
        file "/var/log/karidns/queries.log" versions 3 size 50m;
        severity info;
        print-time yes;
        print-category yes;
    };
    
    channel response_log {
        file "/var/log/karidns/responses.log" versions 3 size 50m;
        severity info;
        print-time yes;
        print-category yes;
    };

    category queries { query_log; };
    category responses { response_log; };
};
```

- **Query Logging (`category queries`)**: Logs incoming DNS requests.
- **Response Logging (`category responses`)**: Logs the exact responses generated by the server, including RCODEs, EDNS statuses, and DNSSEC validation results, without degrading query throughput.

Both file size (`size`) and date-based rotation (`suffix-timestamp`) are supported.

## Configuration Examples

To get started, you can refer to the provided sample files:

- **Main Configuration:** `karidns.conf.sample`
  Demonstrates how to configure listen ports, privilege dropping, TSIG keys, and set up thread-safe query logging with size/date-based rotation.
- **Zone File:** `example.com.zone.sample`
  Provides a standard master zone file template for KariDNS.

## License

This project is licensed under the MIT License.

---
*Copyright (c) 2026 Noel Minamino*
*Developed with Gemini Pro & Claude Sonnet.*

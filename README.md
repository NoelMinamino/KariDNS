# KariDNS
**(Kqueue Arena-based RCU Immoral DNS)**

KariDNS is a high-performance, lightweight, and modern authoritative DNS server designed specifically for FreeBSD. It focuses on extreme concurrency and low-latency query processing by leveraging advanced system-level features.

## Key Features

- **Kqueue-based Event Loop:** Highly optimized asynchronous I/O using FreeBSD's native `kqueue`, ensuring scalable handling of thousands of concurrent TCP and UDP connections.
- **Arena-based Memory Management:** Zero-allocation in the hot path. Zone data is loaded into memory arenas, minimizing fragmentation and providing lightning-fast memory access during query resolution.
- **RCU (Read-Copy-Update) Architecture:** Lock-free, concurrent data structure swaps. Configuration and zone files can be hot-reloaded instantly without dropping a single query or blocking worker threads.
- **Master/Slave Support:** Built-in support for AXFR (Authoritative Zone Transfer), handling both master (sending) and slave (receiving) roles concurrently with background workers.
- **Security & Reliability:**
  - **Capsicum Sandbox:** Runs in FreeBSD's capability mode. Filesystem access is restricted to pre-opened directory descriptors (using `openat`/`renameat`), enabling secure config reloading and log rotation without escaping the sandbox. Network sockets are protected via `cap_rights_limit`.
  - Robust TSIG (Transaction Signature) verification for zone transfers and NOTIFY messages.
  - Privilege dropping (`user` / `group` directives).
  - RRL (Response Rate Limiting) against DNS amplification attacks.
- **BIND-compatible Query Logging:** Thread-safe query logging with automatic rotation by size or date.

## Building and Running

### Prerequisites
- FreeBSD operating system(I tested FreeBSD 15.0p9)
- Clang or GCC compiler
- OpenSSL (for TSIG HMAC-SHA256 support)

### Compilation
Simply run `make` or `make all` in the project root to compile the server:
```sh
make all
```

### Running the Server
Start KariDNS by passing the path to your configuration file as the first argument:
```sh
./karidns /path/to/karidns.conf
```

To reload the configuration and zone files dynamically without restarting the server (zero downtime), send a `SIGHUP` signal to the process:
```sh
pkill -HUP karidns
```

## Configuration Examples

To get started, you can refer to the provided sample files:

- **Main Configuration:** [karidns.conf.sample](karidns.conf.sample)
  Demonstrates how to configure listen ports, privilege dropping, TSIG keys, and set up thread-safe query logging with size/date-based rotation.
- **Zone File:** [example.com.zone.sample](example.com.zone.sample)
  Provides a standard master zone file template for KariDNS.

## License

This project is licensed under the MIT License.

---
*Copyright (c) 2026 Noel Minamino*
*Developed with Gemini Pro & Claude Sonnet.*

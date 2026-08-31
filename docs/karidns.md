# KARIDNS(8) — KariDNS Reference Manual

```text
KARIDNS(8)                     KariDNS Manual                     KARIDNS(8)
```

---

## NAME

**karidns** — Authoritative DNS Server Daemon for FreeBSD

---

## SYNOPSIS

```sh
karidns [-f] [-v | --version] <config_file>
```

---

## DESCRIPTION

`karidns` is an authoritative DNS server designed for FreeBSD. It uses a two-process privilege separation architecture with FreeBSD `Capsicum` sandboxing, atomic RCU-based configuration/zone management, and pre-allocated memory arenas.

### Architectural Structure

1. **Privilege Separation & Capsicum Sandboxing**:
   - **Frontend Process**: Manages privileged network socket binding (UDP/TCP port 53), drops root privileges, and dispatches network traffic.
   - **Backend Process**: Operates in FreeBSD Capsicum capability mode (`cap_enter(2)`). DNS packet parsing and response generation are performed without direct filesystem access or socket creation permissions. Configuration and zone files are accessed via pre-opened directory descriptors (`openat(2)` / `renameat(2)`).
2. **Read-Copy-Update (RCU) Architecture**:
   - Zone data and configuration pointers are swapped atomically using C11 atomic operations (`memory_order_acquire` / `memory_order_release`), allowing worker threads to serve queries concurrently during zone reloads without locking.
3. **Memory Arena Allocator (`zone_arena_t`)**:
   - For ordinary read-only queries (e.g. standard `QUERY` lookups), dynamic memory allocations (`malloc`/`free`) are not used; stack buffers and bump-allocated memory arenas (`zone_arena_t`) are used for request handling.
   - The exception is Dynamic Update (`RFC 2136`, OPCODE=5): applying an update clones the zone's active arena into the standby arena (`clone_zone_arena`, using `realloc`) and computes an IXFR diff (`compute_ixfr_diff`, using `malloc`) so that secondaries can be notified incrementally. This path is synchronous with the query but is inherently a write path, not the hot read path.
4. **Kqueue Event Loop**:
   - Network I/O events for TCP connections and UDP sockets are managed using FreeBSD `kqueue(2)`.

---

## OPTIONS & ARGUMENTS

`<config_file>`
: Positional argument specifying the path to the configuration file (e.g., `/usr/local/etc/karidns/karidns.conf`). This argument is required.

`-f`
: Run in the foreground instead of daemonizing into the background.

`-v`, `--version`, `-V`
: Print the version information and exit.

> [!NOTE]
> **User, Group, and Sandboxing Controls:**
> - Process privileges (`user` and `group`) are configured exclusively via the `options { user "..."; group "..."; }` directive in the configuration file rather than command-line arguments.
> - Traditional `chroot` is not implemented; filesystem and system call sandboxing is enforced via FreeBSD native **Capsicum** (`cap_enter(2)` capability mode) in the backend worker process.

---

## CONFIGURATION OVERVIEW

The configuration file format follows standard structured block syntax.

```
options {
    port 53;
    bind-address { 0.0.0.0; ::; };
    user "named";
    group "named";
    udp-recvbuf-size 4M;
    udp-sndbuf-size 4M;

    rate-limit {
        responses-per-second 50;
        nxdomains-per-second 20;
        errors-per-second 10;
        window 15;
        slip 2;
        exempt-clients { 127.0.0.1/32; 192.168.0.0/16; ::1/128; };
    };
};

logging {
    channel queries_log {
        file "/var/log/named/queries.log" versions 3 size 10M;
        print-time yes;
        print-category yes;
        print-severity yes;
    };
    category queries { queries_log; };
};

control-channel {
    algorithm "hmac-sha256";
    secret "BASE64_SECRET_HERE=";
};

key "transfer-key" {
    algorithm "hmac-sha256";
    secret "BASE64_SECRET_HERE=";
};

zone "example.com" {
    type master;
    file "/usr/local/etc/namedb/master/example.com.zone";
    allow-transfer { 192.168.1.100; };
    also-notify { 192.168.1.100 port 53; };
    notify-source "192.168.1.1";
};
```

---

## CONTROL CHANNEL & MANAGEMENT

Runtime administration of `karidns` is managed over a local UNIX domain socket (`/var/run/karidns/control.sock`) authenticated via HMAC-SHA256 challenge-response using the [`karictl(8)`](karictl.md) utility.

---

---

## PROGRAM ZONE PLUGINS (TEST-ONLY FEATURE)

KariDNS supports dynamic external program-backed zones (`type program;`) exclusively for testing and anomaly fuzzing.

```
options {
    allow-program-zones yes; # Required to enable type program zones
};

zone "anomaly.test." {
    type program;
    program "/usr/local/bin/mock_server.pl";
    program-args { "--verbose"; };
    program-timeout 2000; # timeout in milliseconds (default: 2000)
    program-user "nobody"; # optional privilege drop for plugin process
};
```

> [!NOTE]
> **Design Boundaries and Processing Semantics:**
> - **Pre-filtering & Packet Validation**: KariDNS enforces standard basic DNS header validation (QDCOUNT, valid OPCODES, EDNS version <= 0, valid QCLASS) prior to dispatching queries to the program plugin. Corrupted queries that violate fundamental DNS framing are responded to directly by KariDNS (e.g. FORMERR / NOTIMP / REFUSED) before reaching the plugin.
> - **TCP & AXFR Semantics**: TCP queries (including `AXFR` / `IXFR`) sent to a program zone are forwarded directly to the plugin as a single query-response transaction. Multi-envelope streaming AXFR is not supported.
> - **Security & Isolation**: Plugin child processes are spawned prior to Capsicum capability mode and drop privileges (`program-user`). All internal control channels, frontend IPC, and network sockets are strictly closed via `closefrom(3)` before executing the plugin.

---

## FORWARD ZONES

KariDNS supports forwarding queries for specific zones to designated upstream nameservers (`type forward;`).

```
zone "corp.example.com." {
    type forward;
    forwarders { 192.0.2.53; 198.51.100.53 port 5353; };
    forward-timeout 2000; # timeout in milliseconds per forwarder (default: 2000)
};
```

> [!NOTE]
> **Forward Zone Processing Semantics:**
> - **Transparent Query Relaying**: KariDNS does not maintain zone resource records locally for forward zones. Incoming queries matching the zone are forwarded directly to the configured `forwarders` list in order.
> - **No Subprocess Overhead**: Unlike `type program` zones, forward zones do not spawn external processes and do not require global opt-in flags like `allow-program-zones`.
> - **Immediate Reload Support**: Changes to `forwarders` or `forward-timeout` take effect immediately upon configuration reload (`SIGHUP` / `karictl reload`) without requiring a full server restart.
> - **Unsupported Operations**: Dynamic Update (RFC 2136), Zone Transfer (`AXFR`/`IXFR`), and `NOTIFY` requests are not supported on forward zones and are rejected with `NOTIMP`.
> - **Security & Transaction ID Randomization**: When relaying to upstream forwarders, KariDNS assigns a fresh cryptographic random transaction ID (`arc4random`) and verifies that the upstream response Question section and ID match before relaying the answer with the client's original transaction ID restored.

---

## SIGNALS

`SIGHUP`
: Reloads the configuration file and all master/slave zone files gracefully using atomic RCU pointer swapping.

`SIGTERM`, `SIGINT`
: Gracefully shuts down the server, completing in-flight transactions and closing sockets.

---

## FILES

`/usr/local/etc/karidns/karidns.conf`
: Default primary configuration file.

`/var/run/karidns/control.sock`
: UNIX domain socket for control communication with `karictl`.

`/var/run/karidns/karidns.pid`
: Process ID file.

---

## SEE ALSO

- [`karictl(8)`](karictl.md) — KariDNS server management and control utility
- [`karicheck(1)`](karicheck.md) — Zone file syntax and ZONEMD validation utility
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                          August 2026                      KARIDNS(8)
```

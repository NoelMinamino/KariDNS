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
karidns [-f] [-p pid_file] [-c config_file | config_file] [-v | --version]
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

`<config_file>`, `-c config_file`
: Specify the path to the configuration file (e.g., `/usr/local/etc/karidns/karidns.conf`). This argument is required.

`-f`
: Run in the foreground instead of daemonizing into the background. In foreground mode, PID file creation is disabled by default unless explicitly specified.

`-p pid_file`
: Path to the PID lock file (overrides `options { pid-file "..."; }`; default: `/var/run/karidns/karidns.pid` when daemonized). Specify `"none"` to disable PID locking.

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
    pid-file "/var/run/karidns/karidns.pid"; // "none" to disable
    udp-recvbuf-size 4M;
    udp-sndbuf-size 4M;

    rate-limit {
        responses-per-second 50;
        nodata-per-second 50;
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
    socket "/var/run/karidns/control.sock";
    algorithm "hmac-sha256";
    secret "UkVQTEFDRS1NRTpvcGVuc3NsLXJhbmQtYmFzZTY0LTMy"; // placeholder: replace with `openssl rand -base64 32`
};

key "transfer-key" {
    algorithm "hmac-sha256";
    secret "UkVQTEFDRS1NRTpvcGVuc3NsLXJhbmQtYmFzZTY0LTMy"; // placeholder: replace with `openssl rand -base64 32`
};

zone "example.com" {
    type master;
    file "/usr/local/etc/namedb/master/example.com.zone";
    file-format bind;   # "bind" (default) or "tinydns"; see TINYDNS ZONE FORMAT below
    allow-transfer { 192.168.1.100; };
    also-notify { 192.168.1.100 port 53; };
    notify-source "192.168.1.1";
};
```

---

## TRANSPORT TUNING (TCP MSS / WINDOW, UDP PAYLOAD SIZE)

These directives correspond to `dag`'s `+tcp-mss`, `+tcp-window` and `+bufsize`. Each has a server-wide
form in `options {}` and a per-zone override in `zone {}`. All of them default to "not set", which keeps
the previous behaviour (OS defaults for TCP, a 1232-byte UDP payload cap).

```
options {
    tcp-mss 1220;          # 536..65495
    tcp-window 256K;       # 4K..64M, K/M suffix allowed
    udp-bufsize 1232;      # 512..4096
};

zone "example.com" {
    type master;
    file "/usr/local/etc/namedb/master/example.com.zone";
    zone-tcp-mss 1200;     # 536..65495
    zone-tcp-window 128K;  # 4K..64M (receive side, SO_RCVBUF)
    zone-tcp-sndbuf 2M;    # 4K..64M (send side, SO_SNDBUF; e.g. faster AXFR)
    zone-udp-bufsize 1400; # 512..4096
};
```

Out-of-range or malformed values (`1k` for an MSS, `2MB`, `65M`, ...) are rejected at load time instead of
being clamped, so a tuning setting can never be silently ignored.

| Directive | Applied to | When | Effect |
|---|---|---|---|
| `tcp-window` | `SO_RCVBUF` and `SO_SNDBUF` of every TCP listener | before `listen()` | Inherited by accepted connections, so it covers the initial window advertised in the SYN-ACK. **Needs a restart**: listeners are not recreated on reload. Also the default for secondary-zone transfers (see below). |
| `tcp-mss` | `TCP_MAXSEG` of each accepted connection | right after `accept()` | Lowers the MSS KariDNS **sends** with. Picked up on reload by new connections. |
| `zone-tcp-mss` | `TCP_MAXSEG` of the connection | after a query for the zone is read | Same as `tcp-mss`, and can only lower the MSS further (see limits). |
| `zone-tcp-window` | `SO_RCVBUF` of the connection | after a query for the zone is read | Receive window, within the window scale already agreed in the handshake. |
| `zone-tcp-sndbuf` | `SO_SNDBUF` of the connection | after a query for the zone is read | Send buffer; the setting that matters for large responses and AXFR/IXFR. Applied before the transfer thread takes over the connection. |
| `udp-bufsize` / `zone-udp-bufsize` | UDP response size cap and the payload size advertised in the response OPT | per query | Replaces the built-in 1232. The requestor's own EDNS payload size still wins when it is smaller; TCP responses are not affected. |

### Limits of the per-zone TCP settings

A DNS server only learns which zone a TCP connection is for once it has read the query, i.e. after the
three-way handshake. The `zone-tcp-*` settings are therefore applied with `setsockopt()` to the already
established connection, which means:

- **MSS can only go down.** On FreeBSD, `TCP_MAXSEG` on an established connection accepts only values at
  or below the current MSS (larger values fail with `EINVAL` and are ignored), and the MSS the client was
  told in the SYN-ACK does not change. `zone-tcp-mss` therefore only shrinks the segments KariDNS sends,
  and once lowered the value stays for the rest of the connection. If `tcp-mss` and `zone-tcp-mss` (or two
  zones queried over one connection) disagree, the smallest value wins. The SYN-ACK MSS itself comes from
  the route MTU; to change it, use the route MTU or a packet-filter MSS clamp (for example pf `scrub max-mss`).
- **The window scale is fixed by the handshake.** `zone-tcp-window` can resize the receive buffer only
  within that scale. Queries are small, so for a DNS server the send side (`zone-tcp-sndbuf`) is usually the
  one worth tuning.
- **Setting a buffer turns off the kernel's automatic sizing** for that socket (FreeBSD
  `net.inet.tcp.sendbuf_auto` / `recvbuf_auto`).
- **Several zones on one connection.** With `tcp-connection-reuse`, a client can query more than one zone over
  the same connection. The buffers are switched per query, and only when the value changes. A query for
  a zone without `zone-tcp-window` / `zone-tcp-sndbuf` puts back the value the socket had before any zone
  setting was applied (that is, the `tcp-window` value or the OS default).
- Values above `kern.ipc.maxsockbuf` are truncated by the kernel; `tcp-window` logs a warning when that
  happens.

When no zone uses `zone-tcp-*`, the TCP query path does no extra zone lookup and no `setsockopt()` calls.

### Secondary zones: transfers from the primary

For a `type slave;` / `type secondary;` zone, KariDNS is the TCP *client* of the zone transfer, and the
connection to the primary is opened by the privilege-separated connect broker. The same settings apply
there, taken from the zone and falling back to the server-wide values (catalog member zones have no
`zone {}` block and use the server-wide values):

| Socket option | Value used | When |
|---|---|---|
| `SO_RCVBUF` | `zone-tcp-window`, else `tcp-window` | before `connect()`, so it covers the window advertised in the SYN; this is the one that speeds up receiving a large AXFR/IXFR |
| `SO_SNDBUF` | `zone-tcp-sndbuf`, else `tcp-window` | before `connect()` |
| `TCP_MAXSEG` | `zone-tcp-mss`, else `tcp-mss` | after `connect()`: lowers the send MSS only, for the same FreeBSD reason as above |

Per-zone UDP *socket* buffers are not possible: all zones share the same UDP sockets. The server-wide
`udp-recvbuf-size` / `udp-sndbuf-size` stay the knobs for those. What can be set per zone on UDP is the
EDNS payload size (`zone-udp-bufsize`). Values above 1232 risk IP fragmentation on paths with a smaller
MTU (this is the reason for the DNS Flag Day 2020 default); lower values push more answers to TCP.

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
>
> For full architectural details, IPC wire specifications, and complete runnable examples in Perl, Python, C, Rust, and Go, see **[KariDNS: Complete Guide to 'type program' Zones](KariDNS_how_to_use_type_program_zone.md)**.

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

## TINYDNS ZONE FORMAT

KariDNS can load zone data directly from djbdns/tinydns-style plain-text
`data` files (not the compiled `data.cdb`), in addition to standard
BIND-style zone files.

```
zone "example.com." {
    type master;
    file "/usr/local/etc/karidns/data/example.com.tinydns";
    file-format tinydns;   # omit for the default "bind" format
};
```

A single `data` file that mixes forward-zone records (e.g. `=host:ip`)
and reverse-zone records (`in-addr.arpa.`) can be referenced from
multiple `zone {}` blocks simultaneously; each zone automatically keeps
only the records belonging to it (longest-suffix match against all
configured zone names, so parent/child zone delegation is handled
correctly without duplicate records).

> [!NOTE]
> **tinydns Format Support Scope:**
> - **Verified against djbdns 1.05 source**: Record types `.` `&` `+`
>   `=` `-` `@` `'` `^` `C` `Z` `:` are supported, including exact
>   default TTL values, the `x` (nameserver/MX target) expansion rules,
>   127-byte TXT character-string chunking, and the same lenient IPv4
>   octet parsing (no range validation, trailing garbage tolerated) as
>   the original `tinydns-data`.
> - **`timestamp` field**: Supported with **real-time query evaluation**,
>   identical to original djbdns behavior. A record whose `timestamp` is in
>   the future is excluded dynamically on every query (not just at load time).
>   The `ttl=0` "countdown TTL" variant is likewise computed on every query:
>   the remaining seconds until the timestamp are clamped to [2, 3600] and
>   served as the record TTL.
> - **`%` location (split-horizon by client IP)**: Supported natively
>   during query resolution. KariDNS compiles `%<loc>:<prefix>` location
>   lines and trailing `:loc` record fields into memory, performing bitwise
>   longest-prefix matching against the querying client's source IPv4
>   address with zero heap allocation on the hot path.

---

## CLIENT GEOLOCATION & SUBNET STEERING (ECS & LOCATION)

KariDNS provides high-performance, record-level split-horizon response steering across both BIND and tinydns zone formats:

- **BIND Zone `$LOCATION` & `$LOCATION-TAG`**: Steers responses based on the querying client's immediate socket IP address (IPv4 and IPv6). Tags can be defined directly in zone files (`$LOCATION-TAG <tag> <cidrs>`) or in `karidns.conf` (`ecs-tags`).
- **BIND Zone `$ECS-SUBNET` & `$ECS-SUBNET-TAG`**: Steers responses based on EDNS0 Client Subnet (ECS, RFC 7871) options supplied by trusted recursive resolvers (`ecs-trusted-resolvers`).
- **tinydns `location` (`%`)**: Steers responses based on client IPv4 longest-prefix matching declared with `%<loc>:<prefix>` lines and trailing `:loc` record tags.
- **KariDNS Extended AXFR (Option 65153)**: Replicates zone directives and tags across KariDNS primary and secondary servers, while providing a clean standard AXFR fallback (Plan B) for non-KariDNS clients.

For complete configuration syntax, query evaluation flows, and Extended AXFR details, see **[KariDNS: Client Geolocation & Subnet Steering Guide](KariDNS_How_to_use_ECS_and_location.md)**.

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
- [`KariDNS 'type program' Zone Guide`](KariDNS_how_to_use_type_program_zone.md) — Complete guide to external dynamic program zone plugins (IPC specs, Perl/Python/C/Rust/Go implementations)
- [`KariDNS Client Geolocation & Subnet Steering Guide`](KariDNS_How_to_use_ECS_and_location.md) — Comprehensive guide for BIND $LOCATION, $ECS-SUBNET, tinydns location, and Extended AXFR
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                          August 2026                      KARIDNS(8)
```

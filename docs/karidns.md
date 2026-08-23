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
karidns [-c config_file] [-t directory] [-u user] [-g group] [-d level] [-f] [-v]
karidns [-h | --help]
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
   - Dynamic memory allocations (`malloc`/`free`) are not used on the query processing path. Stack buffers and bump-allocated memory arenas (`zone_arena_t`) are used for request handling.
4. **Kqueue Event Loop**:
   - Network I/O events for TCP connections and UDP sockets are managed using FreeBSD `kqueue(2)`.

---

## OPTIONS

`-c config_file`
: Specify the path to the primary configuration file (default: `/usr/local/etc/karidns/karidns.conf`).

`-t directory`
: Chroot into `directory` after opening configuration files and initializing directory descriptors.

`-u user`
: Set user ID to `user` after binding privileged network ports.

`-g group`
: Set group ID to `group` after initialization.

`-d level`
: Set daemon debug logging level (0–9).

`-f`
: Run in the foreground instead of daemonizing into the background.

`-v`
: Print the version information and build configuration, then exit.

`-h`, `--help`
: Display usage information and command-line summary.

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

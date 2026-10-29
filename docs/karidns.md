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
karidns [-v | --version | -V] [-f] [-p port | -p pid_file] [-P pid_file] [-c config_file | config_file]
```

---

## DESCRIPTION

`karidns` is an authoritative DNS server designed for FreeBSD. It uses a privilege-separated multi-process architecture with FreeBSD `Capsicum` sandboxing, atomic RCU-based configuration/zone management, and pre-allocated memory arenas.

### Architectural Structure

1. **Privilege Separation & Capsicum Sandboxing**:
   - **Manager (Supervisor) Process**: The process started by the administrator. It parses the configuration, performs the startup checks, forks the other processes and supervises them: if any child exits, all children are stopped and the manager exits. The one exception is `karidns-dbloader` (the database loader, see `database { ... }` below), which is restarted after 1 s, 2 s, 4 s ... 60 s while the Backend keeps answering. `SIGHUP` is forwarded to the backend.
   - **Frontend Router Processes**: Bind the privileged network sockets (UDP/TCP port 53) and dispatch network traffic to the backend workers. One router is started on hosts with up to 3 CPU cores, two on larger hosts.
   - **Backend Process**: Operates in FreeBSD Capsicum capability mode (`cap_enter(2)`). DNS packet parsing and response generation are performed by the worker threads (one or two on hosts with up to 3 cores, otherwise the number of cores minus two) without direct filesystem access or socket creation permissions. Configuration and zone files are accessed via pre-opened directory descriptors (`openat(2)` / `renameat(2)`).
   - **Connect Broker**: A small unprivileged helper that opens the outbound connections the sandboxed backend cannot create itself (zone transfers of secondary zones from their primary, forward-zone queries, and reconnecting to the dnstap collector). It starts a non-blocking `connect(2)` and hands the socket back at once; the backend waits for the connection to complete within its own time limit, so one slow server does not hold up other outbound connections. It only connects to UNIX sockets for the `dnstap` socket configured at startup.
   - **Startup order**: user and group are looked up once, before any thread is started, and the same identity is used by all processes and for log and control-socket ownership. Control commands (`karictl`), `SIGHUP` and the control thread's timers are processed only after the backend has dropped privileges and entered capability mode.
   - If the kernel has no `CAPABILITY_MODE` (`cap_enter(2)` fails with `ENOSYS`), the backend logs `Capsicum is not available ... running WITHOUT the capability-mode sandbox` at `LOG_CRIT` and keeps running. Any other `cap_enter(2)` failure aborts startup.
   - **Shutdown**: on `SIGTERM`/`SIGINT`, `karictl stop`, or when the manager process goes away, the backend sends the dnstap frames that are still queued, ends the Frame Streams session (STOP / FINISH) and exits. A second signal exits at once.
2. **Read-Copy-Update (RCU) Architecture**:
   - Zone data and configuration pointers are swapped atomically using C11 atomic operations (`memory_order_acquire` / `memory_order_release`), allowing worker threads to serve queries concurrently during zone reloads without locking.
3. **Memory Arena Allocator (`zone_arena_t`)**:
   - For ordinary read-only queries (e.g. standard `QUERY` lookups) over UDP and TCP, dynamic memory allocations (`malloc`/`free`) are not used; stack buffers and bump-allocated memory arenas (`zone_arena_t`) are used for request handling. TCP connection state comes from a pool of 1000 connection contexts allocated when the backend starts (memory pages are only used once a context has been used), and each worker thread builds its TCP responses in a buffer allocated at startup.
   - Exceptions:
     - Dynamic Update (`RFC 2136`, OPCODE=5): applying an update thaws the zone's published image into a builder (`thaw_zone_arena`, using `realloc`), applies the update, freezes a new image and publishes it as a new version (the old version is freed after the RCU grace period), and computes an IXFR diff (`compute_ixfr_diff`, using `malloc`) so that secondaries can be notified incrementally. This path is synchronous with the query but is inherently a write path, not the hot read path.
     - `type forward` and `type program` zones: the query is copied to the heap and handed to a separate pool of I/O threads through a queue protected by a mutex, so that waiting for the forwarder or the program does not block a worker thread.
     - Outgoing zone transfers (AXFR/IXFR): each transfer runs in its own thread, which receives its parameters in a heap block.
4. **Kqueue Event Loop**:
   - Network I/O events for TCP connections and UDP sockets are managed using FreeBSD `kqueue(2)`.

---

## OPTIONS & ARGUMENTS

`<config_file>`, `-c config_file`
: Path to the configuration file (e.g., `/usr/local/etc/karidns/karidns.conf`). This argument is required; there is no built-in default path. Any argument that is not one of the options below is taken as the configuration file.

`-f`
: Run in the foreground instead of daemonizing into the background. In foreground mode, no PID file is created unless one is set explicitly (`-P`, `-p <path>` or `pid-file`).

`-p port`, `-p pid_file`
: The meaning depends on the value. If the whole value is a decimal number, it is the **listen port** (1–65535; other numbers are an error) and overrides `options { port ...; }` (also on reload); for example `-p 10053`. Any other value is taken as the path of the PID lock file, like `-P`, with a warning that recommends `-P`.

`-P pid_file`
: Path to the PID lock file (overrides `options { pid-file "..."; }`; default: `/var/run/karidns/karidns.pid` when daemonized). Specify `none` to disable PID locking.

`-v`, `--version`, `-V`
: Print the version information and exit.

> [!NOTE]
> **User, Group, and Sandboxing Controls:**
> - Process privileges (`user` and `group`) are configured exclusively via the `options { user "..."; group "..."; }` directive in the configuration file rather than command-line arguments.
> - Traditional `chroot` is not implemented; filesystem and system call sandboxing is enforced via FreeBSD native **Capsicum** (`cap_enter(2)` capability mode) in the backend worker process.

### Running as a non-root user

`karidns` does not have to be started as root. There are two supported ways to run it:

| Started as | `options { user ...; }` | Behavior |
|---|---|---|
| root | set | Binds sockets and opens files as root, then drops to `user`/`group` (recommended for port 53). |
| root | not set | Refused: running as root without a privilege drop is not permitted. |
| non-root user *U* | not set | Runs as *U*. |
| non-root user *U* | `user "U";` (itself) | Runs as *U*; the privilege drop is skipped. |
| non-root user *U* | another user | Refused: a non-root process cannot switch users. |

When started as a non-root user, `group` (if set) must be that user's current primary group, and `program-user` of `type program` zones (which defaults to `options { user }`) must be that user as well.

Everything the process needs must then be usable by that user. **karidns refuses to start** (non-zero exit status and an `[ERROR]` message on stderr and syslog) instead of running half-broken when:

- the listen port cannot be bound over UDP **or** TCP — ports below 1024 (such as 53) require root, so use e.g. `port 10053;` or `-p 10053`; a port already in use by another process is refused too;
- a `logging { channel { file "..."; }; }` file cannot be opened (e.g. under `/var/log`); choose a directory the user can write to;
- the PID file cannot be created: when daemonized, the default is `/var/run/karidns/karidns.pid`, so pass `-P <path>` / `pid-file "<path>";`, or `pid-file "none";`;
- `control-channel` is enabled and its UNIX socket cannot be bound: the default is `/var/run/karidns/control.sock`, so set `control-channel { socket "<path>"; ... };` to a path in a directory the user can write to (and point `karictl` at the same path).

These checks run **before** the process daemonizes, so in daemon mode the failure is reported to the invoking shell/rc script as well. The same fail-closed rules apply when started as root (a log file that cannot be opened, an unbindable port or control socket all abort startup). On `karictl reconfig` / `SIGHUP`, a configuration whose log files cannot be opened is rejected and the running configuration is kept.

Example (`/home/dns/karidns.conf`, started by user `dns` with `karidns /home/dns/karidns.conf`):

```text
options {
    port 10053;
    user "dns";                          // optional: the invoking user itself
    pid-file "/home/dns/run/karidns.pid";
};
logging {
    channel queries_log { file "/home/dns/log/queries.log" versions 3 size 10M; };
    category queries { queries_log; };
};
control-channel {
    socket "/home/dns/run/control.sock";
    algorithm "hmac-sha256";
    secret "...";
};
```

---

## CONFIGURATION OVERVIEW

The configuration file uses the `named.conf`-style block syntax. A complete reference of every statement follows in [CONFIGURATION REFERENCE](#configuration-reference).

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

## CONFIGURATION REFERENCE

### General syntax

- Statements end with `;`, and blocks are written as `name { ... };` (the `;` after the closing brace is required).
- Comments: `# ...`, `// ...` and `/* ... */`.
- Values may be quoted (`"..."`) or bare words. A single token is limited to 4096 bytes (longer tokens are truncated with a warning). The configuration file (and each included file) may be at most 256 MiB.
- `include "file";` may appear anywhere and inserts the file in place. Relative paths are resolved against `options { directory }` when it is set (BIND 9.20), otherwise against the directory of the file that contains the `include`. Includes can be nested up to 16 levels deep; circular includes are rejected.
- Boolean values accept `yes` / `true` / `1` and `no` / `false` / `0` (case-insensitive), in every statement, as BIND does. Any other value is a configuration error.
- An unknown statement inside `zone { }` or `view { }` is a configuration error (reload and startup fail, `karicheck conf` shows it): it used to be skipped silently, so a typo such as `alow-transfer` left a zone open or closed. Options that BIND 9 documents for those statements but KariDNS does not implement (`allow-query`, `inline-signing`, `dnssec-policy`, `auto-dnssec`, `key-directory`, `max-journal-size`, `zone-statistics`, `check-names`, `recursion`, ...) are skipped with a warning. An unknown key in `control-channel { }` is a configuration error as well. So is an unknown statement in `options { }` and in `key { }`, with the file and line (`[ERROR] karidns.conf:12: options: unknown option 'bind-adress' ...`): a misspelt `bind-address`, `user`, `pid-file`, `secret` or `algorithm` used to have no effect. The options that BIND 9.18 or 9.20 documents for `options { }` but KariDNS does not implement (`recursion`, `allow-transfer`, `version`, `forwarders`, ...; the list is the union of the two ARMs plus the options of older BIND versions) are skipped with a warning (`[WARNING] karidns.conf:3: options: 'recursion' is a BIND option that KariDNS does not implement; it is ignored`). `key { }` takes `algorithm` and `secret`, each once, and both are required (BIND does too): a key that lacks one, or has any other statement, is an error. Unknown statements in `logging` and in unknown top-level blocks are still skipped without a message.
- Zone names are normalized to their fully qualified form (a trailing `.` is added), so `"example.com"` and `"example.com."` are the same zone. A class after the zone or view name is accepted as in BIND 9.20 (`zone "example.com" IN { ... };`, `view "v" IN { ... };`): `IN` in any letter case is ignored, any other class (`CH`, `HS`, `CLASSnn`, ...) is a configuration error with the file and line (`zone 'example.com.': class 'CH' is not supported (only IN)`).
- Relative file paths (zone `file`, log `file`, `pid-file`, the `control-channel` and `dnstap` sockets, `database-file`, `conninfo-file`, `include`, `$INCLUDE`) are resolved against `options { directory "<dir>"; }` when it is written (BIND 9.20: "all relative paths use this directory as a base"; see the option below), otherwise against the working directory `karidns` was started from, including paths that contain `../`. **Working directory.** As BIND does, `karidns` changes into `options { directory }` once, when it starts (a missing or unreadable directory is a start-up error), and `daemonize()` does not change directory (it used to `chdir("/")`): the daemon keeps the directory it was started in, or `directory`, so that a relative name means the same before and after it daemonizes. This is what the UNIX socket paths of `control-channel` and `dnstap` rely on: they are used as written, not made absolute (a UNIX socket path holds only 103 bytes, `sun_path`), so a relative `socket "karidns.sock";` is created in, and connected from, that directory; a path longer than 103 bytes is a start-up error with a message (before the daemon forks, so it reaches the terminal). The cost is the one BIND has: that directory's file system stays busy (it cannot be unmounted while `karidns` runs), and a core dump is written there. A reload never changes directory. The paths handed to something that does not share the working directory are made absolute at start-up (against `directory`, else the starting directory): `pid-file` (also `-P`), and `loader-path`, `database-file` and `conninfo-file` of `options { database }` (`karidns-dbloader` runs as `loader-user` and is started from `/`; so are the `type program` plugins). Exceptions: `program` stays absolute-only, and a path given on the command line (`-c`, `-P`) is relative to the directory `karidns` was started from, even when `options { directory }` is set. The server opens the directories of zone and log files when it starts, before it enters the Capsicum sandbox; a zone or log file that a reload adds in a directory the server has not used before cannot be opened unless it lies below `directory` or below the directory of a zone file that was loaded at start-up (those trees are reached through the directory file descriptors opened then, with `openat()`) (the zone answers SERVFAIL and `karictl reload` / `reconfig` report it) until the next restart.
- Unknown statements and options in `logging` and in unknown top-level blocks are skipped silently (up to the next `;` at the same block level; not in `options`, `key`, `zone`, `view` and `control-channel`, see above), so a misspelled option has no effect. Use [`karicheck conf`](karicheck.md) to validate a configuration.
- Settings that are fixed when the server starts (`port`, `bind-address`, `listen-on`, `listen-on-v6`, `user`, `group`, `pid-file`, `udp-recvbuf-size`, `udp-sndbuf-size`, `tcp-window`, the `control-channel` socket path, `dnstap`, the `type program` zone processes, and the interface snapshot that `localhost` / `localnets` in address match lists are evaluated against) need a restart; a reload (`SIGHUP`, `karictl reload` / `reconfig`) applies everything else. When a reload changes one of them, the server logs a warning that names it, and `karictl` shows it as `OK (restart needed for: ...)`.
- A reload that cannot be applied (the file cannot be read, a configuration error, a log file that cannot be opened) keeps the running configuration. A reload whose zone files fail to load applies the configuration and serves SERVFAIL for those zones; the failed zones are logged. If readers of the previous configuration are still active after 10 seconds, the reload is postponed and retried every second until it runs. `SIGHUP` signals that arrive while a reload is running are merged into one reload.

### Top-level statements

| Statement | Description |
|---|---|
| `options { ... };` | Server-wide options (below). |
| `zone "<name>" { ... };` | A zone. Top-level zones and `view` blocks cannot be mixed in one configuration. |
| `view "<name>" { ... };` | A view containing `match-clients` and `zone` blocks. |
| `key "<name>" { ... };` | A TSIG key, visible in every view (a `key` inside a `view` is visible in that view only; see `key`). |
| `server <prefix> { ... };` | Settings for the remote servers an address or prefix covers: the TSIG key, source addresses and other options of the requests to them (BIND `server` statement; see `server`). Also allowed inside `view`. |
| `remote-servers "<name>" [ port <n> ] { ... };` | A named list of servers for `also-notify` (also written `primaries` or `masters`). See `also-notify` and `remote-servers` below. |
| `control-channel { ... };` | Enables the [`karictl(8)`](karictl.md) control socket. |
| `logging { ... };` | Log channels and categories. |
| `dnstap { ... };` | dnstap output (same block as inside `options`). |
| `acl "<name>" { ... };` | A named address match list (see Address match lists). |
| `include "<file>";` | Includes another file. |

Duplicate zones (in the same view or at top level), duplicate views, duplicate keys and duplicate `acl` names (names compared case-insensitively) are rejected. Zone names are compared as DNS names, so `example.com` and `example.com.` are the same zone.

### `options { ... }`

| Option | Default | Description |
|---|---|---|
| `port <n>;` | `53` | Listen port (UDP and TCP), 1–65535. A value that is not a number in that range is a configuration error with the file and line. The port of a `listen-on` / `listen-on-v6` statement that has no `port` of its own (see "Listening addresses"). Overridden by `-p <port>`, which replaces this port and the ports written in `listen-on` / `listen-on-v6` too. |
| `directory "<path>";` | none | BIND 9.20 ARM: "This sets the working directory of the server"; the ARM recommends an absolute path. Every relative path of the configuration is relative to it: zone `file`, `pid-file`, log channel `file`, the `control-channel` and `dnstap` sockets, `database-file` and `conninfo-file`, `include` and the relative `$INCLUDE` lines of zone files. Without it, relative paths are relative to the directory `karidns` was started in (and a relative `include` to the file that contains it). `karidns` changes into the directory once at start-up, as BIND does when it reads the statement, and keeps it when it daemonizes (see "Relative file paths" in General syntax); a relative `socket` of `control-channel` or `dnstap` is therefore looked for there. It may be written anywhere in `options` (and, for an `include`, it must be in the main configuration file: a `directory` that only an included file contains, after a relative `include` was already read, is refused). The directory is opened once, when the server starts, and the server refuses to start without it; **a reload keeps using the directory the server was started with**: a different or removed `directory` in the file is a warning, `karictl` answers `OK (restart needed for: directory)`, and relative paths keep resolving against the old one until the next restart. `karicheck conf` checks that it exists and is a directory. |
| `bind-address { <addr>; ... };` or `bind-address <addr>;` | all addresses (`0.0.0.0` and `::`) | KariDNS's own statement: addresses to listen on (IPv4 and IPv6), each at `port`. An element that is not an IPv4 or IPv6 address is a configuration error with the file and line (it used to bind nothing, silently). Combined with `listen-on` / `listen-on-v6`: the union (see "Listening addresses"). |
| `listen-on [ port <n> ] { <address match list>; ... };` and `listen-on-v6 [ port <n> ] { ... };` | `0.0.0.0` and `::` | BIND 9.20 syntax, may be written several times: the IPv4 / IPv6 addresses of this host that the list allows, at the port of the statement. See "Listening addresses". `tls`, `http` and `proxy` are configuration errors (this server has no DNS-over-TLS, DNS-over-HTTPS or PROXYv2 listener). |
| `blackhole { <address match list>; ... };` | none | BIND 9.20 syntax: requests from an address the list matches (first match decides; a non-negated match drops) are dropped without any response, over UDP and TCP (a TCP connection is closed at once). It is read for every request, so a reload adds, changes or removes it without a restart. See "Listening addresses". |
| `user "<name>";` | none | User to drop to after binding sockets. Required when started as root. A name that resolves to uid 0 (`root`, `toor`) is refused by `karicheck conf` and at start (a reload cannot change it: it takes effect after a restart, and the Backend does not resolve names). |
| `group "<name>";` | the user's primary group | Group to drop to. The group that is used (this one, else the user's primary group) must not be gid 0: a root group, also under another name, is refused like root. |
| `pid-file "<path>";` | `/var/run/karidns/karidns.pid` when daemonized, none in foreground | PID lock file; `"none"` disables it. Overridden by `-P` / `-p <path>`. A relative name (also from `-P`) is made absolute once at start-up, against `directory` when it is set, else the directory `karidns` was started in; a name that is longer than 1023 bytes once absolute is a start-up error, never a truncated path. BIND's `named` writes a relative pid file relative to its working directory, i.e. `directory`. |
| `udp-recvbuf-size <size>;` | `4M` | `SO_RCVBUF` of the UDP sockets. Accepts a `K`/`M`/`G` suffix; an invalid value keeps the default. The kernel caps it at `kern.ipc.maxsockbuf`. |
| `udp-sndbuf-size <size>;` | `4M` | `SO_SNDBUF` of the UDP sockets (same syntax). |
| `tcp-mss <n>;` | not set (OS default) | 536–65495. See [TRANSPORT TUNING](#transport-tuning-tcp-mss--window-udp-payload-size). |
| `tcp-window <size>;` | not set (OS default) | 4K–64M, `K`/`M` suffix allowed. See TRANSPORT TUNING. |
| `udp-bufsize <n>;` | `1232` | 512–4096. Maximum UDP response size and the payload size advertised in the response OPT. See TRANSPORT TUNING. |
| `tcp-connection-reuse yes\|no;` | `no` | Keep TCP connections open for further queries (RFC 7766 §6.2.1). With `no`, the connection is closed after the first response. With `yes`, pipelined queries are read and answered in the order they arrive (not concurrently, RFC 7766 §6.2.1.1 is a SHOULD), up to 16 per turn of the event loop. Any TCP connection is closed 60 s after it was opened at the latest. |
| `tcp-initial-timeout <ms>;` | `10000` | Time in **milliseconds** a new TCP connection may take to deliver its first complete query (0 means the default). |
| `tcp-idle-timeout <ms>;` | `10000` | Time in **milliseconds** after a complete query in which the next one must have arrived completely (0 means the default). It is not extended while only part of a message has arrived (RFC 7766 §6.2.3), so a client that sends a message a few bytes at a time is disconnected. Also the value advertised in edns-tcp-keepalive (RFC 7828). |
| `minimal-responses yes\|no;` | `no` | Do not add glue / additional-section records. |
| `minimal-any yes\|no;` | `no` | RFC 8482: answer `QTYPE=ANY` with a synthesized `HINFO "RFC8482" ""` record instead of all RRsets. When the query has DO=1 and the name has RRSIG records, a single RRset is returned instead (RFC 8482 §4.2). |
| `minimal-any-ttl <seconds>;` | `86400` | TTL of the synthesized RFC 8482 `HINFO` record. |
| `additional-from-auth yes\| `alias-resolver { <addr> [port <n>]; ... };` | none | The resolvers that expand the ALIAS records of every zone (PowerDNS `expand-alias`); 1 to 8 IP addresses. Without it ALIAS is stored and transferred and A / AAAA at an ALIAS name are NODATA. Can be overridden per zone. See [POWERDNS ALIAS AND LUA RECORDS](#powerdns-alias-and-lua-records-milestone-b9a). |
|in-domain\|no;` | `yes` | Whether additional-section data (glue, MX/SRV targets) is taken from the server's authoritative data. `in-domain` (alias `in-zone`) limits it to names inside the zone of the answer. Additional-section addresses ignore ECS: only records without an ECS tag (`$ECS-SUBNET default` / `none`) are given there, whatever the client subnet, and they do not change the ECS SCOPE of the response (RFC 7871 §7.4: "Addresses in the Additional section SHOULD therefore ignore ECS data"; §7.3.1: a resolver does not tie them to a network). Location tags and tinydns locations, which follow the client's own address, still apply. Glue taken from another zone of the view is chosen with that zone's own location tags, tinydns locations and SOA visibility, as if the client had asked that zone. Any other value is a configuration error. Can be overridden per zone. When a referral does not fit the message, TC=1 is set only if glue for a name server inside the delegated zone is left out (RFC 9471 §3.1); glue of other (sibling) name servers that does not fit is left out without TC (RFC 9471 §3.2, RFC 2181 §9). |
| `send-extended-errors yes\|no;` | `yes` | Add Extended DNS Errors (EDE, RFC 8914) to responses of EDNS queries. |
| `ixfr-history <n>;` | `4` | 0–32. How many past versions of a zone are kept as IXFR differences (RFC 1995 §4). A secondary that is at most this many versions behind gets an incremental transfer; a secondary that is further behind, or any secondary when the value is `0`, gets the whole zone in the AXFR-style IXFR answer that RFC 1995 §4 allows when an incremental answer is not available (a client that is already up to date still gets a single SOA, §2). The history is kept in memory only and is allocated when the first difference is stored, so a zone that never changes after loading costs nothing. `0` also skips computing differences. A reload that lowers the value drops the oldest differences at once; a higher value takes effect with the next stored difference. A value outside 0–32 is a configuration error. Can be overridden per zone. |
| `max-zone-records <n>;` | `10000000` | 2..4294967295. The most RRs one inbound AXFR/IXFR of a secondary zone may bring (the size of the zone being built, after an IXFR's deletions); a transfer that goes over is refused as a whole and the zone keeps its last version (the log says `max-zone-records`). Same name, range and default as the `database` block. Can be overridden per zone. |
| `max-zone-bytes <size>;` | `1G` | 65535..64G (K, M, G suffixes). The most message octets one inbound AXFR/IXFR of a secondary zone may bring; over it the transfer is refused. Can be overridden per zone. Independently of both limits, a transfer signed with TSIG that has more than 99 messages in a row without a TSIG is refused (RFC 8945 section 5.3.1: a primary signs at least every 100th message), and so is an IXFR whose difference sequences do not start from the secondary's serial and chain to the current one (RFC 1995 section 4; karidns then asks for an AXFR), and a transfer that carries a record of another class than IN (RFC 5936 section 2.2.1). A zone may carry at most 4096 Extended AXFR `LOC_TAGDEF` and 4096 `ECS_TAGDEF` records and 65536 CIDRs in them. |
| `also-notify [ port <n> ] { <addr> [port <n>] [key <name>]; <list>; ... };` | none | Servers that receive NOTIFY in addition to the apex NS hosts, for every zone (and catalog member) that has no `also-notify` of its own or of its view. Same grammar and meaning as in `zone`; see `also-notify` and `remote-servers` below. |
| `notify yes\|no\|explicit\|primary-only\|master-only;` | `yes` | Which NOTIFY messages are sent; same meaning as in `zone` (BIND 9.20 ARM "notify"). Can be overridden per view and per zone. |
| `notify-retries <n>;` | `2` | 0–10. How many times a NOTIFY that got no answer is sent again over UDP (RFC 1996 §3.6); after the last one the NOTIFY is made once over TCP, see [NOTIFY over TCP](#notify-over-tcp). The default is BIND 9.20's `udpretries` of a NOTIFY (`notify_send_toaddr()`). Can be overridden per zone. |
| `notify-retry-interval <seconds>;` | `5` | 1–3600. Time from sending a NOTIFY to its first retransmission, and the wait for an answer after the last one. The default is BIND 9.20's `udptimeout` of a NOTIFY. Can be overridden per zone. |
| `notify-retry-backoff fixed\|exponential;` | `fixed` | `fixed` keeps `notify-retry-interval` between all retransmissions; `exponential` doubles it after each one (capped at 3600 s). The defaults (2 retransmissions, 5 s, `fixed`) are what BIND 9.20 does when nothing is configured: `notify_send_toaddr()` passes `udptimeout` 5 and `udpretries` 2 to `dns_request_create()`, which sends the datagram at 0, 5 and 10 s and gives up at 15 s, and `notify_done()` then makes the NOTIFY over TCP. A NOTIFY to a silent peer therefore reaches TCP after about 15 s (the earlier defaults of 60 s and 5 retransmissions took about 6 minutes). `notify-retry-interval 3; notify-retry-backoff exponential;` retransmits after 3, 6, 12, 24 and 48 s. Can be overridden per zone. |
| `notify-tcp-timeout <seconds>;` | `15` | 1–300. The time one attempt of a NOTIFY over TCP may take, the connection and the answer together ([NOTIFY over TCP](#notify-over-tcp)). BIND 9.20 has no such option: its TCP request has a fixed timeout of 15 s (`notify_send_toaddr()`), which is the default here. A peer that does not answer holds one thread for at most this long per attempt (`tcp-only` makes two attempts). Can be overridden per zone. |
| `allow-query { <acl>; ... };` | any host | Who may ask the zones ordinary questions (BIND 9.20 ARM "allow-query"). A client that is not allowed gets REFUSED with Extended DNS Error 18 (Prohibited) over UDP and TCP. The default of every zone; a `view` or `zone` statement replaces it. A list is read as described in [Address match lists](#address-match-lists-acls). |
| `allow-query-on { <acl>; ... };` | any local address | Which local addresses accept ordinary questions: the address the query was sent to (BIND 9.20 ARM "allow-query-on"). A query must be allowed by `allow-query` **and** `allow-query-on`. Inherited like `allow-query`. |
| `allow-transfer { <acl>; ... };` | none | Who may transfer the zones (AXFR/IXFR over TCP). BIND 9.20 ARM: "If allow-transfer is not specified, then the default is none". The default of every zone; a `view` or `zone` statement replaces it. `port` and `transport` in front of the braces (BIND 9.20) are configuration errors. |
| `allow-update { <acl>; ... };` | none | Who may send Dynamic Updates (RFC 2136); the default of every primary zone, replaced by a `view` or `zone` statement. BIND advises writing it per zone: a default at this level opens every primary zone to those clients. |
| `allow-notify { <acl>; ... };` | the zone's primaries only | Who may send NOTIFY to the secondary zones, in addition to their primaries (BIND 9.20 ARM "allow-notify"); a `key` element is the TSIG key the NOTIFY is signed with. It applies to secondary zones only. |
| `serve-stale yes\|no;` | `yes` | When a secondary zone has expired (SOA EXPIRE passed since the last successful transfer, or earlier when the server it transfers from returned a shorter EDNS EXPIRE value, RFC 7314), keep answering from the stale data (with EDE 3, Stale Answer). With `no` such queries get SERVFAIL with EDE 24 (Invalid Data, RFC 8914 §4.25). |
| `nsid "<string>";` | not set | NSID (RFC 5001) value returned to queries that request it. |
| `cookie-secret "<32 hex digits>";` | random per process | 128-bit SipHash-2-4 server cookie secret (RFC 7873 / RFC 9018). Up to 4 entries: the first creates cookies, all of them are accepted (secret rollover). Use the same secret on all servers of an anycast set. |
| `cookie-algorithm siphash24;` | `siphash24` | The only supported algorithm (RFC 9018); any other value is an error. |
| `rfc10029-mqtype yes\|no;` | `no` | Enables multiple QTYPEs in one query (RFC 10029). |
| `max-mqtypes <n>;` | `4` | Maximum number of additional QTYPEs processed per query (0–16; `0` means the default 4). |
| `ecs-enable yes\|no;` | `no` | Enables EDNS Client Subnet (RFC 7871) processing, used by `$ECS-SUBNET` steering. Global only. |
| `ecs-trusted-resolvers { <addr/cidr>; ... };` | none | Resolvers whose ECS option is trusted. Can be overridden per zone. |
| `ecs-tags { tag "<name>" { <cidr>; ... }; ... };` | none | ECS tag definitions used by `$ECS-SUBNET` (see [TAG BLOCKS](#ecs-tags--location-tags)). |
| `location-tags { tag "<name>" { <cidr>; ... }; ... };` | none | Location tag definitions used by `$LOCATION`. |
| `allow-program-zones yes\|no;` | `no` | Must be `yes` for `type program` zones to be loaded. |
| `response-cache-size <size>;` | `32M` | Size of the response cache shared by all worker threads (allocated once at startup; suffixes `K` and `M`, at most `1024M`; an invalid value is a configuration error). Answers are added when they are first asked for: NOERROR authoritative answers of plain queries (no DO bit, ECS, MQTYPE or other options that change the answer) that fit in 512 octets. Every reload, transfer, UPDATE or glue change of a zone, and every configuration reload, gives the zone a new key, so a stale answer is never returned. An answer whose Additional section holds glue taken from another zone of the view (additional-from-auth) is not cached, because the other zone can change without changing the key. Each cached answer takes about 160 octets (the answer itself plus a 32-octet index entry), so `32M` holds about 200,000 answers. `0` disables the cache. Changing it needs a restart. |
| `wire-cache-max-records <n>;` | `0` (no limit) | Answers of zones with more records than this are not put into the response cache. Answers of tinydns zones and of zones using location/ECS steering are never cached. |
| `query-log-max-qps <n>;` | `5000` | Maximum number of query log lines per second, shared by all worker threads (`0` means 5000). Queries over the limit are not logged. |
| `query-log-buffer-size <n>;` | `32768` | Entries in each worker's query log ring buffer; a power of two between 1024 and 1048576. When a ring is 80 % full, query logging is suspended to protect query processing. |
| `rate-limit { ... };` | not set (no RRL) | Response Rate Limiting (below). |
| `dnstap { ... };` | not set | dnstap output (below). |

### Listening addresses: `listen-on`, `listen-on-v6`, `bind-address`, `blackhole`

`listen-on [ port <n> ] { <address match list>; };` and `listen-on-v6 ...` follow BIND 9.20 (ARM "Interfaces"): the list is matched against the addresses of the interfaces of this host, and the server listens (UDP and TCP) on each IPv4 address (`listen-on`) or IPv6 address (`listen-on-v6`) the list allows. The list is an ordinary address match list (CIDR prefixes, `!`, `any`, `none`, `localhost`, `localnets`, acl names, nested lists; first match decides, see "Address match lists"); a `key` element is an error. A statement without `port` uses `options { port }` (53 by default, wherever in `options` it is written). The statements may be repeated, e.g. `listen-on { 192.0.2.1; }; listen-on port 5353 { 198.51.100.1; };`.

- **`any` and `none`.** A list that is just `any` (also through an acl block or a nested list) listens on the wildcard address (`0.0.0.0` or `::`), as BIND does for `listen-on-v6 { any; }`; BIND binds each IPv4 interface address separately for `listen-on { any; }`, this server uses the wildcard there too, so an address added to the host later is served as well. Any other list, e.g. `{ !192.0.2.1; any; }`, listens on each interface address it allows, one socket each. `listen-on-v6 { none; }` opens no IPv6 socket; `listen-on { none; }` no IPv4 socket.
- **Interface addresses are those of the start-up snapshot** (the same table `localhost` / `localnets` use). An address in the list that no interface has gets nothing (BIND does not listen on it either); `karidns` and `karicheck conf` print a warning with the file and line (`[WARNING] karidns.conf:3: options listen-on: '192.0.2.99' matches no address of an interface of this host: nothing is listened on for it`). An IPv6 address in `listen-on` (or IPv4 in `listen-on-v6`) is ignored with a warning, as in BIND. IPv6 link-local interface addresses are not listened on (the snapshot carries no scope id); use `any` or a global address.
- **Defaults.** Neither `listen-on` / `listen-on-v6` nor `bind-address`: `0.0.0.0` and `::`, as before. With a `listen-on` or `listen-on-v6` statement, a family that is not written anywhere (no statement, no `bind-address` element of that family) listens on its wildcard address, which is BIND's default ("all IPv6 interfaces"): write `listen-on-v6 { none; };` to stay off IPv6. With only `bind-address`, exactly the addresses listed, as before.
- **Union with `bind-address`.** The addresses of all `listen-on`, `listen-on-v6` and `bind-address` statements are added together (a `bind-address` element is at `options { port }`). The same address and port twice is one socket. **The same address with two different ports is a configuration error** naming both places (`options listen-on: address 192.0.2.1 is listened on at port 53 (karidns.conf:2) and at port 5353`): this server gives an address one port. A wildcard address makes the specific addresses of the same family and port redundant (`listen-on { any; }; bind-address { 127.0.0.1; };` is just `0.0.0.0`).
- **Limit.** At most 64 addresses (UDP sockets of the Frontend, notify-source pre-binds included); more is a configuration error. `any` is one address however many interfaces there are.
- **`-p <port>`** replaces `options { port }` and the port of every `listen-on` / `listen-on-v6` statement (the command line overrides the file, as it did when the file had one port).
- **Nothing selected.** If the statements select no address (`listen-on { none; }; listen-on-v6 { none; };`, or lists that match no interface), `karicheck conf` warns and `karidns` refuses to start.
- **Reload.** The sockets are opened once, at start-up, by the Frontend (and the workers, for TCP); a reload that changes the set of addresses or ports logs a warning and `karictl` shows `OK (restart needed for: listen-on)`; the old sockets stay and no new one is opened. The list is evaluated against the start-up interface snapshot, so a reload does not notice new addresses either.
- `karicheck conf` prints the result (`[INFO] Listening (UDP and TCP) on: 127.0.0.1:53 [::1]:53`) and reports the errors above with the file and line.

`blackhole { <list>; };` (ARM "blackhole", default `none`): a request from an address for which the first matching element of the list is not negated is dropped before it is read, logged or looked up in the response cache; a TCP connection from such an address is accepted and closed at once. UDP packets from it that are NOTIFY answers are dropped too. As the ARM warns, `!address;` alone only exempts `address` and drops nothing (nothing else matches); `blackhole { !192.0.2.1; any; };` drops everyone except 192.0.2.1. Only requests received are affected: this server does not apply the list to the NOTIFY messages and SOA queries it sends or the transfers it starts. A `key` element is an error.

### `rate-limit { ... }` (in `options` or `zone`)

A `rate-limit` block in a zone replaces the server-wide block for that zone. `0` means no limit for that class. Only UDP responses are limited.

Responses are counted like BIND (`lib/dns/rrl.c`): clients are grouped by address prefix (`ipv4-prefix-length`, `ipv6-prefix-length`), and within a client prefix each kind of response has its own budget per name:

| Response | Counted per |
|---|---|
| NOERROR with data | QNAME + QTYPE + QCLASS. Answers made from a wildcard share one budget per zone (`*.<zone>`). |
| NODATA | QNAME + QCLASS (wildcard: `*.<zone>`) |
| NXDOMAIN | the zone (random names under one zone share one budget) |
| Referral (delegation) | the delegation point + QCLASS |
| Errors (SERVFAIL, REFUSED, FORMERR, ...) | the client prefix only |
| `all-per-second` | the client prefix only, all responses |

Differences from BIND: the table has a fixed size of 131072 entries (`min-table-size` / `max-table-size` are accepted and ignored); `qps-scale` is accepted and ignored; `nxdomains-per-second` and `errors-per-second` default to `0` (no limit) instead of `responses-per-second`; responses that carry a valid server cookie are limited like any other.

| Option | Default | Description |
|---|---|---|
| `responses-per-second <n>;` | `0` | Limit for positive (NOERROR with data) responses. |
| `nodata-per-second <n>;` | value of `responses-per-second` | Limit for NODATA responses. |
| `nxdomains-per-second <n>;` | `0` | Limit for NXDOMAIN responses. |
| `referrals-per-second <n>;` | value of `responses-per-second` | Limit for referrals (delegations to a child zone). |
| `errors-per-second <n>;` | `0` | Limit for error responses. |
| `all-per-second <n>;` | `0` | Limit for all responses to one client prefix, whatever the name. When both limits apply, this one decides. |
| `ipv4-prefix-length <n>;` | `24` | 0–32. IPv4 clients in the same prefix share their budgets. |
| `ipv6-prefix-length <n>;` | `56` | 0–128. IPv6 clients in the same prefix share their budgets. |
| `qps-scale`, `min-table-size`, `max-table-size` | — | Accepted for BIND compatibility; no effect (warning). |
| `window <seconds>;` | `15` | Accounting window (maximum 3600). |
| `slip <n>;` | `2` | Every *n*-th limited UDP response is sent truncated (TC=1) instead of being dropped; `0` drops all. |
| `log-only yes\|no;` | `no` | Only log what would be limited. |
| `early-drop yes\|no;` | `no` | For `type program` zones: drop UDP queries before they are passed to the program when the client's budget for a positive answer to this QNAME/QTYPE (or its `all-per-second` budget) is already exhausted. |
| `exempt-clients { <addr/cidr>; ... };` | none | Clients that are never limited. |

Negative or non-numeric values are ignored with a warning; unknown keys are ignored with a warning.

### `dnstap { ... }` (top level or in `options`)

| Option | Default | Description |
|---|---|---|
| `socket "<path>";` (alias `socket-path`) | none | UNIX socket of the Frame Streams collector (e.g. `fstrm_capture`). The first connection is made at startup. When the collector goes away (or was not running at startup), the server reconnects through the connect broker, first after 1 s and then with the interval doubling up to 60 s; events produced while disconnected are dropped. The reconnection runs as the `user` karidns runs as, so that user must be allowed to connect to the socket. |
| `identity "<string>";` | none | dnstap `identity` field. |
| `version "<string>";` | none | dnstap `version` field. |
| `queue-size <n>;` (alias `queue_size`) | `4096` | Entries in each worker's dnstap ring buffer (values below 64 use the default; rounded up to a power of two). |
| `require-connect yes\|no;` | `no` | Abort startup when the collector cannot be reached (otherwise startup continues and the server keeps trying to connect). |
| `log-queries yes\|no;` (alias `auth-query`) | see below | Emit `AUTH_QUERY` messages. |
| `log-responses yes\|no;` (alias `auth-response`) | see below | Emit `AUTH_RESPONSE` messages. |

When neither `log-queries` nor `log-responses` is given, both queries and responses are logged. When one of them is given, only the types set to `yes` are logged (the other one defaults to `no`). The message types are taken over on reload; a changed `socket` path needs a restart.

`AUTH_QUERY` and `AUTH_RESPONSE` messages carry `query_zone` (the zone that contains the QNAME in the client's view, looked up when the message is sent). At shutdown the queued messages are sent and the Frame Streams session is ended with STOP / FINISH.

`karictl status` reports the number of truncated dnstap messages.

### `ecs-tags` / `location-tags`

```
ecs-tags {
    tag "eu-tier" { 198.51.100.0/24; 2001:db8:ee::/48; };
    tag "us-tier" { 203.0.113.0/24; };
};
```

The same syntax is used for `location-tags`. The blocks can be placed in `options` and in `zone`. For each zone, tags defined inside the zone file (`$ECS-SUBNET-TAG` / `$LOCATION-TAG`) take precedence, then the `zone` block, then `options`. Tags are checked in the order they are defined and the first tag with a matching CIDR wins. ECS tags steer the Answer section only: Additional-section addresses and the NS / DS RRsets of the Authority section are chosen as for a query without ECS (RFC 7871 §7.3.1, §7.4); location tags apply everywhere. See the [Client Geolocation & Subnet Steering Guide](KariDNS_How_to_use_ECS_and_location.md).

### `logging { ... }`

```
logging {
    channel <name> {
        file "<path>" [versions <n>] [size <n>[K|M|G]] [suffix timestamp];
        print-time yes|no;
        print-category yes|no;
        print-severity yes|no;
        max-qps <n>;
    };
    category queries   { <channel>; };
    category responses { <channel>; };
};
```

| Item | Description |
|---|---|
| `file` | Log file. With `size`, the file is rotated when it would exceed the size: with `versions <n>` the old files are kept as `<path>.0` … `<path>.<n-1>`, without `versions` the file is truncated. With `suffix timestamp`, the file is also rotated daily, and every rotation (daily or by size) renames it to `<path>.YYYYMMDD`; a second rotation on the same day uses `<path>.YYYYMMDD.1`, then `.2`, … (up to `.9999`), so no rotated file is overwritten. With `suffix timestamp` and `versions <n>`, only the `n` newest `<path>.YYYYMMDD[.N]` files are kept and older ones are deleted after each rotation, as BIND does; without `versions` (or with `versions unlimited`) none are deleted. Other files in the directory are never removed. |
| `print-time`, `print-category`, `print-severity` | Add the timestamp, category and severity to each line (default `no`). |
| `max-qps` | Per-channel override of `query-log-max-qps` for the `queries` category. |
| `category queries` | Query log. |
| `category responses` | Response log. |

**Directories and files (root start).** karidns creates the directory of a log file when it is missing and hands over only a directory it created itself to `user`/`group`; an existing directory keeps its owner and mode (as BIND does): prepare it so that the run user can write to it (and, for a rotation, create files in it). A log file is accepted only when it is a regular file with one link whose owner is root, the user karidns runs as, or the run user; a hard link, another type of file or a file of a third user makes the start (or the reload) fail with `Refusing to use log file`, so that a planted link cannot make karidns append to, or hand over, another file.

Only the `queries` and `responses` categories exist; other categories are ignored with a warning. A category may list several channels (`category queries { a; b; };`), but only the first one is used and the others are ignored with a warning; an empty list (`{ };`) turns the category off. A category that names an undefined channel is an error. Other channel options (such as BIND's `severity`) are ignored. Operational messages go to syslog (facility `daemon`).

### `key "<name>" { ... }`

| Option | Description |
|---|---|
| `algorithm "<name>";` | `hmac-md5` (also `hmac-md5.sig-alg.reg.int`), `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. MD5 and SHA-1 are accepted with a deprecation warning (RFC 8945). When omitted, `hmac-sha256` is used. |
| `secret "<base64>";` | Shared secret. Invalid base64 is an error. |

Keys are referenced by `allow-transfer { key "<name>"; }`, `allow-update`, `tsig-key`, the `key` of a `primaries` / `also-notify` element and the `keys` of a `server` statement. Key names are domain names: references match regardless of case and of a trailing dot (`key "K1"` is referenced by `key "k1."`). A zone that references an undefined key in `tsig-key` or `allow-transfer` is an error. [`karictl tsig-keygen`](karictl.md) prints a new key block.

TSIG processing (RFC 8945 §5.2, §5.3) is the same for every opcode (QUERY, NOTIFY, UPDATE) and for AXFR/IXFR. The server first checks the request's TSIG against the key that the request names (key name and algorithm); only then does it apply `allow-transfer`, `allow-update` or `masters`/`tsig-key`:

| Request | Response |
|---|---|
| Several TSIG records, a TSIG that is not the last record, or a MAC size outside RFC 8945 §5.2.2.1 | FORMERR, no TSIG |
| Unknown key name or algorithm | NOTAUTH, TSIG error BADKEY, unsigned (MAC size 0) with the request's key name |
| MAC does not verify | NOTAUTH, TSIG error BADSIG, unsigned |
| Time Signed outside the fudge | NOTAUTH, TSIG error BADTIME, signed with the request's key; Time Signed and Fudge are the client's, Other Data is the server time |
| MAC truncated (shorter than the full hash length) | NOTAUTH, TSIG error BADTRUNC, signed. KariDNS has no setting for truncated MACs, like BIND without `digest-bits` |
| Valid TSIG, but not allowed by the zone's access control | REFUSED, signed with the request's key |
| Valid TSIG | The normal response, signed with the request's key |
| No TSIG | The normal response or REFUSED, unsigned |

A signed response that would not fit the client's UDP size with its TSIG is truncated (TC=1). A NOTIFY is accepted from a `masters` address and, when that primary has a `key` (or else the zone has `tsig-key`), only when it is signed with that key. `allow-update` is evaluated in BIND's order: a `key` element matches a request signed with that key (see "Address match lists"). A truncated RRL `slip` response to a signed request is signed with the request's key as well, as in BIND 9.20 (signed requests are not exempt from rate limiting).

### `control-channel { ... }`

`control-channel` is a statement of its own, at the top level of the configuration, next to `options` and `zone`. Written inside `options { ... }` it is a configuration error (the server refuses to start and `karicheck conf` reports it) instead of being ignored, which used to leave the server without a control socket.

| Option | Default | Description |
|---|---|---|
| `socket "<path>";` (alias `socket-path`) | `/var/run/karidns/control.sock` | UNIX socket for `karictl`. |
| `secret "<base64>";` | none | Shared secret; must match `karictl.conf`. Authentication is an HMAC challenge-response. |
| `algorithm "<name>";` | `hmac-sha256` | HMAC of the challenge-response: one of the TSIG algorithm names above. `karictl.conf` must name the same algorithm. |

Any other key is a configuration error that names the key (`control-channel: unknown option 'port' (supported: socket, secret, algorithm)`): the server refuses to start, a `karictl reload` / `reconfig` is refused and keeps the running configuration, and `karicheck conf` reports it as an error. The channel is a UNIX socket only; there is no `port` or `bind-address`. A misspelt `secret` or `socket` used to be skipped, which left the channel without the secret or on the default socket without a word. Servers that run side by side need a `socket` each: without it every one binds `/var/run/karidns/control.sock`, and the last one to start takes the path over.

**Keys in a view.** A `key` statement inside `view { }` has the same options and is visible only to that view: its zones' `allow-transfer`, `allow-update`, `allow-query`, `tsig-key`, `primaries` / `also-notify` `key` and the view's `server` statements may name it, and a request that reaches the view is verified with the keys of that view and the global keys (BIND `bin/named/tsigconf.c`: the ring of a view is the global keys plus its own). The same name may be used in two different views with different secrets. A name that is already a global key, or twice in one view, is a configuration error, exactly as in BIND (`lib/isccfg/check.c`; the view's keys do not *shadow* a global key). A name used in a view that is neither global nor in that view is rejected for that view (`key 'k' is not defined in any key {} block`). The view is chosen first, by the client's address (`match-clients`), and then the request's TSIG is verified against that view's keys; a `key` entry in `match-clients` is still not supported. Limits: a named `acl { }` block, a `remote-servers` / `primaries` list and the settings of a database zone are global and can name only global keys.

### `view "<name>" { ... }`

| Item | Description |
|---|---|
| `match-clients { <acl>; ... };` | Clients that use this view, by source address only; a `key` entry is a configuration error. A view without `match-clients` matches every client. |
| `notify yes\|no\|explicit\|primary-only\|master-only;` | Replaces the `options` value for the zones of this view that have no `notify` of their own. |
| `also-notify [ port <n> ] { ... };` | Replaces the `options` list for the zones of this view that have no `also-notify` of their own. See `also-notify` and `remote-servers` below. |
| `allow-query`, `allow-query-on`, `allow-transfer`, `allow-update`, `allow-notify { <acl>; ... };` | Each replaces the `options` statement of the same name for the zones of this view that have none of their own (a zone's statement replaces the view's, the view's replaces `options`'; the lists are not merged). A `view` without `allow-query` uses the `options` statement; both default as described in the `options` table. |
| `key "<name>" { ... };` | A TSIG key of this view only (see `key`). |
| `server <prefix> { ... };` | Server statements of this view. When a view has any, they replace the top-level `server` statements as a whole (BIND uses the first list that exists, it does not merge); `karicheck conf` notes it. |
| `zone "<name>" { ... };` | Zones of this view. The same zone name may appear in several views. |

The view name is at most 63 characters; a longer name is a configuration error. Views are checked in the order they are defined; the first match is used. A query from a client that matches no view is answered as if no zone matched (REFUSED). Without any `view` block, all top-level zones are placed in an implicit view that matches all clients.

### `also-notify` and `remote-servers`

Grammar (BIND 9.20 ARM, "also-notify" and "remote-servers"), the same in `options`, `view` and `zone`:

```
also-notify [ port <n> ] { ( <list-name> | <ipv4> [ port <n> ] | <ipv6> [ port <n> ] ) [ key <name> ]; ... };
remote-servers <name> [ port <n> ] { ( <list-name> | <ipv4> [ port <n> ] | <ipv6> [ port <n> ] ) [ key <name> ]; ... };
```

- **Where it applies.** The ARM: in `options` it is a global list; in a `zone` it "overrides any global statement"; in a `view` it overrides the global one for that view. KariDNS reads the list of a zone from the zone's own statement, else the statement of its view, else `options`. The lists are never merged; an empty `also-notify { };` in a zone (or view) switches the inherited list off. A catalog member and a zone without a `zone { }` use the view's or the `options` list. A later statement of the same kind in the same block replaces the earlier one.
- **`port`.** `port <n>` before the `{` is the port of the addresses written directly in that statement that have no port of their own; an address's own `port` wins. Without any, 53. (The `options { port }` listening port is not used: BIND takes the default NOTIFY port from it, KariDNS always sends to 53 unless told otherwise.) A list name takes no `port` of its own, but the `port` of the statement it is written in is passed to it: the addresses of a nested list that have no port take the `port` of their own list, else the `port` of the list that names it (and so on outwards), else 53 (BIND `named_config_getipandkeylist()`; the `source` of a list is not inherited).
- **List names.** A name that is not an IP address must be a `remote-servers` (`primaries`, `masters`) list of this configuration; it is replaced by the addresses of the list, with their ports and keys. A list may name other lists (at most 8 deep; a list that includes itself is an error) and may be written after the statement that uses it. A `key` written after a list name is the key of those addresses of the list that have none of their own. An unknown name is a configuration error, shown by `karicheck conf` and by `karidns` at startup and reload (a rejected reload keeps the running configuration). After expansion a statement may have at most 256 addresses; NOTIFY is sent to at most 64 different addresses per zone change including the NS hosts.
- **`key <name>`.** The NOTIFY to that address is signed with the TSIG key `name` (RFC 8945 section 5.1; RFC 1996 section 4.5 for the NOTIFY itself), and only an answer that verifies stops the retransmission (RFC 8945 section 5.4). The key must be defined in a `key { }` block, otherwise the configuration is rejected. **Precedence:** the `key` of an address wins over the `keys` of the `server` statement that covers the address, which wins over the zone's `tsig-key`; an address without any (and every NS host) is sent unsigned. (BIND: the element's key, else the server's; the zone `tsig-key` is KariDNS.)
- **Not supported (a configuration error, not a silent no-op).** `tls <name>` (NOTIFY has no encrypted transport; it goes over UDP, or over TCP: see `tcp-only` of the `server` statement). `source ( <ipv4> | * )` / `source-v6 ( <ipv6> | * )` before the braces (no port) is the local address of the NOTIFY messages to the addresses written in that statement, ahead of `notify-source`; see [Transfer and NOTIFY options](#transfer-and-notify-options-source-addresses-secondary-timers-limits-bind-920).
- **`notify`.** `notify yes | no | explicit | primary-only | master-only;` in `options`, `view` and `zone` (BIND 9.20 ARM "notify"; boolean spellings `true`, `false`, `1`, `0` too). The zone's value overrides the view's, which overrides `options`'; default `yes`. `yes`: NOTIFY goes to the apex NS hosts (except the SOA MNAME host, RFC 1996 section 3.2) and to the `also-notify` list. `no`: no NOTIFY is sent. `explicit`: only to the `also-notify` list (the NS hosts are left out). `primary-only` (older `master-only`): as `yes`, but only for primary zones; a secondary zone and a catalog member send nothing after a transfer (KariDNS secondaries pass a transfer on to their NS hosts and `also-notify` list by default, as BIND does). Every NOTIFY path follows the setting: updates, reloads, transfers and `karictl notify <zone>` (the ARM says only that `rndc notify` "resends NOTIFY messages for the zone"; a zone with `notify no` therefore sends nothing). The value is not part of a database zone's settings text (refused there).
- **Errors.** A syntax error says what and where, for example `[ERROR] /etc/karidns/karidns.conf:12: zone 'example.test.' also-notify: expected ';' after '192.0.2.1' but found '}'`; an unknown list or undefined key names the line of the element: `[ERROR] karidns.conf:7: options also-notify: 'sec' is neither an IP address nor a remote-servers / primaries / masters list defined in this configuration`.
- **Database zones.** The settings text of a database zone (`ALSO-NOTIFY` and the masters of a `SLAVE` / `CONSUMER` zone, see Settings of database zones) takes addresses and ports only (also `port <n>` before the `{`): no list name, no `key`, no `tls`. A database zone whose settings have no `also-notify` uses the `options` list (or that of its view) like any zone; one that has it, even an empty one, uses its own.

Example:

```
key "nk" { algorithm hmac-sha256; secret "..."; };
options { also-notify { 192.0.2.53; }; };
remote-servers secondaries port 5353 { 192.0.2.54; 2001:db8::54 key "nk"; };
zone "example.test" { type master; file "example.test.zone"; also-notify { secondaries; 192.0.2.99 port 5300; }; };
```

A zone that appears in several views is a separate zone in each view: its own file, data, additional-section glue from the other zones of the same view, wire cache settings and `program` plugin. `karictl reload <zone> <view>` reloads one view's copy. If a reload changes a zone's `type` (for example `master` to `slave`), the zone is recreated with the new type.

### Transfer and NOTIFY options: source addresses, secondary timers, limits (BIND 9.20)

The statements below are those of the BIND 9.20 ARM ("Zone Transfers", "Boolean Options", the `zone` statement); defaults come from BIND's `bin/named/config.c`, ranges from `lib/isccfg/check.c`. They are written in `options`, `view` and `zone`; for each option separately **the zone's statement wins over the view's, which wins over `options`'** (never merged); a value out of range is a configuration error with `file:line`. `startup-notify-rate` ... `transfers-per-ns` exist in `options` only.

| Option | Default | Meaning |
|---|---|---|
| `notify-source ( <ipv4> \| * );`, `notify-source-v6 ( <ipv6> \| * );` | `*` | Local address of NOTIFY messages (no port: the 9.20 grammar has none, a `port` is an error). `*` = the system chooses. The `source` of the `also-notify` list an address is written in wins over it, and the `notify-source` of a `server` statement for the address wins over both. The KariDNS zone statement `notify-source <address>` keeps its old meaning (either family, no warning); `notify-source-v6` of the same zone wins for IPv6. |
| `transfer-source ( <ipv4> \| * );`, `transfer-source-v6 ( <ipv6> \| * );` | `*` | Local address of the TCP connections a secondary opens to its primaries (the zone transfer and the refresh check -- KariDNS checks with an IXFR or a SOA query over TCP, so both leave from it). The `source` / `source-v6` of the `primaries` list the primary is written in wins over it (`source *` counts as not written), and the `transfer-source` of a `server` statement for the primary wins over both. |
| `min-refresh-time`, `max-refresh-time` | `300`, `2419200` | Seconds, 1..4294967295 (0 is an error, as in BIND). The SOA REFRESH a secondary uses is held to this range (BIND `RANGE()`; if min > max the result is max, `karicheck conf` warns). |
| `min-retry-time`, `max-retry-time` | `500`, `1209600` | The same for the SOA RETRY. The expire timer is `SOA EXPIRE` held to `[refresh + retry, 24 weeks]`. `karictl zonestatus` shows `refresh=`, `retry=` and `expire=` as used. **These defaults are BIND's: a secondary whose primary publishes REFRESH 60 checks every 300 s unless `min-refresh-time` says otherwise.** |
| `max-transfer-time-in`, `max-transfer-idle-in`, `max-transfer-time-out`, `max-transfer-idle-out` | `120`, `60`, `120`, `60` | Minutes, 0..40320 (28 days); 0 = no limit. An inbound transfer is given up after the total time, or when no message arrives for the idle time; an outbound one when it takes longer than the total time or a send waits the idle time for the client. (The environment variable `KARIDNS_XFER_MINUTE_SECS=n`, 1..60, makes a "minute" n seconds -- a test hook, like BIND's `named -T transferinsecs`.) |
| `transfers-in`, `transfers-out`, `transfers-per-ns` | `10`, `10`, `2` | Concurrent inbound transfers, concurrent outbound transfers (a request over the limit is REFUSED), inbound transfers from one primary address. A refresh over a limit waits for a later tick. `0` is accepted (no inbound transfer / every outbound one refused). `transfers-out` replaces the former fixed limit of 4 transfers of one zone. |
| `serial-query-rate`, `notify-rate` | `20` | Per second; 0 is raised to 1 (BIND). `serial-query-rate` limits how many refresh checks start in a second (KariDNS has no separate SOA query: the IXFR / SOA check is the query); `notify-rate` the first NOTIFY messages of a second, the rest follow at the next ticks. |
| `startup-notify-rate` | `20` | Accepted and range-checked, **not enforced**: KariDNS sends no NOTIFY when it starts (only after a zone changed or a secondary transferred), so there is nothing to limit. `karicheck conf` says so. |
| `notify-delay` | `5` | Seconds between two sets of NOTIFY messages for one zone; a request inside the delay (also `karictl notify`) waits for its end. |
| `notify-to-soa yes\|no;` | `no` | `yes`: the NS host that is the SOA MNAME also gets a NOTIFY (otherwise not, RFC 1996 §3.2). |
| `request-ixfr yes\|no;` | `yes` | `no`: the secondary asks for the SOA first (over TCP) and transfers the whole zone by AXFR only when the primary's serial is newer. |
| `provide-ixfr yes\|no;` | `yes` | `no`: an IXFR request is answered with the whole zone (also to a client that is up to date). BIND allows it in `options`, `view` and `server`; KariDNS also in `zone`. A `server` statement for the requester wins over the others. |
| `request-expire yes\|no;` | `yes` | `no`: the transfer request has no EDNS EXPIRE option (RFC 7314). |
| `try-tcp-refresh yes\|no;` | `yes` | Accepted; `no` has no effect (KariDNS checks over TCP only) and is reported with a warning. |
| `multi-master yes\|no;` | `no` | Looked at only when a secondary has more than one primary. |

**Primaries in order (BIND `refresh_callback()`).** A secondary asks its `primaries` in the order written, from the first at every refresh: a primary that does not answer, answers wrongly or is rejected is skipped; one that has the same serial is noted and the search goes on (a later one may be ahead); one that is **behind** (older serial, RFC 1982) is logged as `serial number (N) received from primary ... < ours (M)` -- not as a failed transfer -- unless `multi-master yes`, and the search goes on; the first primary that is ahead is transferred from and ends the refresh. If any primary answered (up to date or transferred) the SOA REFRESH timer applies, if none did the RETRY timer. Each primary uses its own `port`, `key` and `source`; catalog member zones use the primaries of their catalog zone. At most 32 primaries are used. Differences from BIND: the check is an IXFR (or the TCP SOA query of `request-ixfr no`), not a UDP SOA query; there is no cache of unreachable primaries; there is no jitter on the timers.

**Source addresses.** Every address a configuration names (`notify-source`, `transfer-source`, `source` of a list, at any level) is bound once when the server starts: if it cannot be bound the server does not start (`karidns: Refusing to start: karidns.conf:12: transfer-source 192.0.2.9: cannot use it as a source address: Can't assign requested address`). The Router (NOTIFY over UDP, an ephemeral port: the address is **not** a listening address) and the connect broker (transfers, and NOTIFY over TCP, port 0) take the addresses from that start-up set, so **an address that is added by a reload is applied after a restart**: the reload answers `OK reloaded (restart needed for: source-address)`, the log names the statement, and until the restart the system chooses the source. `karicheck conf` accepts a source it cannot test (it may belong to another host) and lists them.

Example:

```
options { transfer-source 192.0.2.1; notify-source 192.0.2.1; min-refresh-time 60; transfers-in 20; };
primaries ns-b source 192.0.2.2 { 198.51.100.1; 198.51.100.2 key "tk"; };
zone "example.test" { type secondary; primaries { ns-b; 203.0.113.9 port 5353; }; multi-master yes; };
```

### `server <prefix> { ... }` (BIND 9.20)

```
server <ipv4-address>[/<length>] | <ipv6-address>[/<length>] {
    keys <key-name>;   keys { <key-name>; };
    transfers <n>;
    transfer-format one-answer | many-answers;
    transfer-source ( <ipv4> | * );   transfer-source-v6 ( <ipv6> | * );
    notify-source ( <ipv4> | * );     notify-source-v6 ( <ipv6> | * );
    request-ixfr yes|no;  provide-ixfr yes|no;  request-expire yes|no;
    edns yes|no;  edns-udp-size <n>;  edns-version <n>;  request-nsid yes|no;  max-udp-size <n>;
    bogus yes|no;  tcp-only yes|no;  tcp-keepalive yes|no;  padding <n>;
    send-cookie yes|no;  require-cookie yes|no;  query-source [ address ] ( <ipv4> | * ) [ port ... ];  query-source-v6 ...;
};
```

Top level or inside a `view`. The statement describes the remote servers an address or prefix covers (BIND `lib/isccfg/namedconf.c` `server_clauses`, `bin/named/server.c` `configure_peer()`). **The most specific prefix wins** (BIND `dns_peerlist_addpeer()` / `dns_peerlist_peerbyaddr()`: the list is ordered longest prefix first; equal lengths keep the order written; an IPv4 prefix never covers an IPv6 address). **A view that has `server` statements uses only its own**; the top-level ones are used by the views that have none (BIND takes the first `server` list it finds, view before global; it does not merge). The checks are those of BIND's `check_servers()`: bits beyond the prefix length (`192.0.2.1/24`) are an error, so is the same prefix twice in one list (`already exists, previous definition: file:line`), a `-v6` source for an IPv4 server and a plain source for an IPv6 server (`transfer-source-v6 is not legal for an IPv4 server`), an unknown key (`unknown key 'k' (in view 'v')`: the key must be global or in the view that uses the statement), an unknown, ancient (`request-sit`, `support-ixfr`) or twice-written option, and a value that is not a number or boolean. The clamps of `configure_peer()` apply without a message (`edns-udp-size` and `max-udp-size` 512..4096, `edns-version` at most 255, `padding` at most 512 with a warning).

What the options do on an authoritative server (the BIND source places are `lib/dns/zone.c` `soa_query()`, `notify_send_toaddr()`, `zmgr_start_xfrin_ifquota()`, `xfrin.c`, `lib/ns/xfrout.c`, `lib/ns/client.c`):

| Option | Effect in KariDNS |
|---|---|
| `keys` | The TSIG key that signs the refresh check, the IXFR/AXFR request and the NOTIFY to that server, and verifies its answers. **Precedence, highest first:** the `key` written on the `primaries` / `also-notify` element, the `keys` of the `server` statement, the zone's `tsig-key` (KariDNS). The `keys` of a server statement never makes an *incoming* NOTIFY from that server require a signature (BIND uses it for requests only); a `key` written on a `primaries` element still does, as before. |
| `transfer-source`, `transfer-source-v6`, `notify-source`, `notify-source-v6` | Local address of the TCP connection to the server / of the NOTIFY to it (the UDP datagram, or the TCP connection of a NOTIFY over TCP). **Precedence, highest first:** the server statement, the `source` of the `primaries` / `also-notify` list the address is written in, the zone, the view, `options` (`*` at a level ends the search: the system chooses). The addresses are bound once at start-up like every source address (see above): an address new in a reload needs a restart, and one that cannot be bound makes the server refuse to start, naming the `file:line` of the option. |
| `request-ixfr`, `request-expire` | Replace the zone's / view's / `options`' value for requests to that server (`request-ixfr no`: the SOA check comes first, signed if the server has a key). |
| `provide-ixfr` | Replaces the zone's / view's / `options`' value for IXFR requests *from* that server (UDP and TCP). |
| `transfers` | Replaces `transfers-per-ns` for that server: at most this many inbound transfers from the address at a time (`0`: none). |
| `transfer-format` | `one-answer`: an AXFR or IXFR to that client has one resource record in each message (RFC 5936 section 2.2 allows it). `many-answers` is the default. |
| `max-udp-size` | Replaces the view's UDP limit for answers to that client (the client's own EDNS size still applies if smaller). Looked up only when some `server` statement writes it, without allocation. |
| `edns no` | The requests carry no OPT record: no EXPIRE option (RFC 7314) and no Extended AXFR option, so the transfer is a standard one. |
| `edns-udp-size`, `edns-version`, `request-nsid` | The UDP size and version in the OPT of the requests to the server; an empty NSID option (RFC 5001). `edns-version` other than 0 makes a server answer BADVERS, as in BIND. |
| `bogus`, `tcp-keepalive`, `padding`, `send-cookie`, `require-cookie`, `query-source`, `query-source-v6` | Accepted and checked; **no effect in KariDNS** (BIND uses them for its resolver, DS checks of `parental-agents` or encrypted transports; KariDNS sends no DNS COOKIE). `karicheck conf` and the server print `accepted, no effect in KariDNS` with `file:line`. |
| `tcp-only` | `yes`: the NOTIFY to that server goes over TCP from the start (BIND `notify_send_toaddr()`, `dns_peer_getforcetcp()`); see [NOTIFY over TCP](#notify-over-tcp). The refresh check and the transfers use TCP anyway. |

`server` is not part of a database zone's settings text. Example:

```
key "xk" { algorithm hmac-sha256; secret "..."; };
server 192.0.2.0/24 { keys xk; transfer-source 192.0.2.1; request-ixfr no; };
server 192.0.2.77   { transfers 1; keys xk; };
zone "example.test" { type secondary; primaries { 192.0.2.77; 192.0.2.78; }; };
view "inside" { match-clients { 10.0.0.0/8; };
  key "vk" { algorithm hmac-sha256; secret "..."; };
  server 198.51.100.1 { keys vk; };
  zone "example.test" { type secondary; primaries { 198.51.100.1; }; };
};
```

### NOTIFY over TCP

A NOTIFY goes over TCP in two cases, both as BIND 9.20 does it (`lib/dns/zone.c` `notify_send_toaddr()` and `notify_done()`, `lib/dns/request.c`):

- **`tcp-only yes;`** in the `server` statement that covers the target (the most specific prefix of the zone's view, else the top-level ones; it applies to the addresses of `also-notify` and to the NS hosts alike). The NOTIFY is not sent over UDP at all.
- **After the UDP attempts.** A NOTIFY over UDP that gets no answer after the last retransmission (`notify-retries`, `notify-retry-interval`, `notify-retry-backoff`: the defaults are BIND's own UDP schedule, 3 tries 5 s apart, then TCP at 15 s), or whose answer cannot be used (the TSIG of an answer to a signed NOTIFY does not verify: no TSIG, BADSIG, BADKEY, BADTIME), is made once more over TCP. A bad UDP answer starts the TCP attempt at once, the remaining retransmissions are not waited for.

The exchange is one DNS message each way with the two-octet length in front (RFC 1035 section 4.2.2). It has `notify-tcp-timeout` seconds (default 15, BIND's TCP timeout of a NOTIFY) for the connection and the answer together. A failed attempt of `tcp-only` is made a second time, as BIND does (`notify_done()` finds the `DNS_NOTIFY_TCP` flag clear when only the server statement asked for TCP and retries); after the UDP attempts there is one TCP attempt. The failure is logged: `NOTIFY to 192.0.2.1 port 53 over TCP failed: <reason>` (cannot connect, timed out, the connection was closed before the answer, the answer has an impossible length, the reply is not an answer to this NOTIFY, the answer fails TSIG verification ...). The NOTIFY is signed exactly as over UDP (the `key` of the `also-notify` element, else the `keys` of the `server` statement, else the zone's `tsig-key`; a fresh time signed for every attempt) and only an answer with the same ID and QNAME whose TSIG verifies (RFC 8945 section 5.3) counts. The answer is the peer's: its length is checked before it is read, and a peer that sends nothing, one octet at a time, or garbage holds only its own attempt for at most `notify-tcp-timeout` seconds.

The connection leaves from the address a UDP NOTIFY would leave from: the `notify-source` of the server statement, else the `source` of the `also-notify` list, else the zone's, view's, `options`' `notify-source` / `notify-source-v6` (`*` ends the search; see [Transfer and NOTIFY options](#transfer-and-notify-options-source-addresses-secondary-timers-limits-bind-920)). Like a transfer, it is made by the connect broker, not by the sandboxed Backend (which may not `connect()`), and it runs in a thread of its own so that nothing waits for a slow peer: at most 64 exchanges run at a time and the others wait their turn in the table of pending NOTIFYs. `notify-rate` counts the first message of an exchange like a first UDP message. `karictl observatory` counts the NOTIFY once (`Sent`), whichever transport it used.

```
server 192.0.2.53 { tcp-only yes; keys xk; notify-source 192.0.2.1; };
zone "example.test" { type master; file "example.test.zone"; also-notify { 192.0.2.53; }; };
```

### `database { ... }` (in `options`) and the view database options

Zones can come from a PowerDNS 5.1 database (SQLite3 or PostgreSQL). The loader, its options, the SQL files, the packages that contain it and the measurements are described in [`karidns-dbloader(8)`](karidns-dbloader.md). The server never links a database library: it starts `karidns-dbloader` (the loader), which reads the database and sends the zones to the Backend over a socket (stream `KDB1`). The loader runs as `loader-user`, without access to this configuration file. The Backend builds every zone it receives into a zone of its own (the same engine as for zone files, so a zone answers byte for byte the same from a file and from the database) and serves it as a primary (a `SLAVE` or `CONSUMER` zone is a secondary, see "Database zone types" below). File zones answer at once; DB zones appear as the batches of the loader are published (new zones become visible when a batch ends and at least once a second during a long batch), and a line `initial load complete` is logged when the first batch is done. A zone that fails the Backend's checks (the data does not match its declared count, a record outside the zone, no closing SOA, a malformed record, ...) is rejected alone: it keeps its last good version, or is absent when there is none, and `karictl dbstatus` shows the reason. A zone from the database whose name is also defined by a `zone { }` of `karidns.conf` (a `file`, `program`, `forward` or secondary zone) is hidden by it: the configured zone answers, a warning is logged, `karictl dbstatus` says `shadowed (hidden by a zone in karidns.conf)`, and the DB zone is served again at the next reload after the configured zone is removed. A catalog member of the same name hides the database zone too, on every path (a catalog update, a full reconfiguration, and a database zone that arrives after the member): the member answers, `karictl dbstatus` says `shadowed (hidden by a catalog member)`, and the database zone comes back as soon as the catalog drops the member. The settings of a DB zone (who may transfer it or update it, `also-notify`, `ixfr-history`, ...) come from its `domainmetadata` and its profile and are applied as described under "Settings of database zones" below; a zone without any runs with the defaults, so transfers and dynamic updates are refused. **Reload.** The loader keeps a list of what the server has (view, zone, `domains.id`, serial and the digest of the stream it sent) and, on `karictl reload`, compares it with the database in one snapshot: new zones, zones whose serial differs, zones the change log lists (an edit that keeps the serial; the change log needs `db/karidns_ext.sqlite3.sql` or `db/karidns_ext.pgsql.sql`, which also ship the other `karidns_*` tables; without it only serials are compared and the loader logs that once) and zones whose last version was refused are read and converted, and a converted zone whose digest is the one the server has is not sent. A zone that is no longer in the database gets a `ZONE_DELETE` and leaves the server with the next batch. `bulk-threshold` decides how a diff reads: above that percentage of the source's zones one scan of all records (skipping the unchanged), below it one query per zone. A restarted loader (or a changed source) compares every zone by digest and sends only what differs from the server's list, so a loader restart does not resend the zones. `karictl reload <zone> [force]` reads one zone, also one that was just added to the database; see [`karictl(8)`](karictl.md). A zone whose last version was refused is offered again by every reload and every loader restart until it is accepted.

```
options {
    database {
        driver sqlite3;
        database-file "/var/db/karidns/zones.sqlite3";
        loader-user "karidns-db";
        loader-path "/usr/local/libexec/karidns-dbloader";
    };
};
view "internal" { match-clients { 10.0.0.0/8; }; database-file "/var/db/karidns/internal.sqlite3"; };
view "other"    { database none; };
```

| Option | Default | Description |
|---|---|---|
| `driver <name>;` | required | `sqlite3` or `postgresql`. The loader must have been built with it (`karidns-dbloader --drivers`). Restart only. |
| `database-file "<path>";` | | sqlite3: the database of the views without their own file. The file must be in WAL mode. An error with `postgresql`. |
| `conninfo-file "<path>";` | | postgresql (required): the libpq conninfo. Mode 0600 or 0400, owned by `loader-user`. An error with `sqlite3`. |
| `schema "<name>";` | | postgresql: the schema of the views without their own. An error with `sqlite3`. |
| `loader-user "<user>";` `loader-group "<group>";` | none | Identity of the loader. `loader-user` is required when karidns starts as root (the loader never runs as root); a `loader-user` or `loader-group` that resolves to uid/gid 0 (also under another name) is refused by `karicheck conf` and at start (restart only); started as another user, it must be that user. Restart only. |
| `loader-path "<path>";` | `/usr/local/libexec/karidns-dbloader` | The loader binary: a regular executable owned by root (or by the running user when not root) and not writable by group or others; checked at the start and before every restart. The check is made on the open file that is then executed (fexecve(2) on FreeBSD), so the file cannot be swapped between the check and the start; a script (`#!`) is executed from the descriptor only when fdescfs(4) is mounted on `/dev/fd`, otherwise by its path after the same checks. The loader starts with an empty environment (only `TZ`) and no descriptor above 3. Restart only. |
| `acl-ceiling { ... };` | none | Upper bound for the ACLs of database zones (addresses, `!` exclusions, `key "name"` of a defined key, named `acl`s). A client passes a database ACL only if it is also inside the ceiling; **with no ceiling, database ACLs refuse everybody**. Exact rules under "Settings of database zones". |
| `acl-ceiling-match any\|all;` | `any` | How the ceiling combines its entries when it lists both addresses and keys (milestone B7b): `any` = a client is inside when its address matches **or** its request is signed with a listed key (the meaning of B7a); `all` = the address matches **and** the request is signed with a listed key. With only one kind of entry in the ceiling that kind decides, whatever the mode is (`karicheck conf` warns that `all` has no effect then). BIND's ACLs cannot say "this address and this key", which is why this is a separate option. |
| `auto-reload yes;` | `no` | Reload by itself when the database changes (milestone B9; sqlite3; see "Auto reload" below). Off: nothing polls and only `karictl reload` reads the database again. Reloads with `karictl reconfig` / `SIGHUP`, without restarting the loader. |
| `poll-interval <n>;` | `2` | Seconds, 1..60: how often the loader asks a view's database whether anything was committed (`auto-reload yes` only); with PostgreSQL also how often it reads `karidns_reload_requests` when no notification came and how soon it tries again after an error. |
| `coalesce <ms>;` | `1000` | Milliseconds, 0..10000: after the first change the loader waits this long for more before it makes one batch (`auto-reload yes` only); with PostgreSQL also the window in which several reload requests become one reload. |
| `default-ttl <n>;` | `3600` | TTL for a `records.ttl` that is NULL, 1..2147483647. |
| `bulk-threshold <percent>;` | `25` | 0..100. When a reload has to read more than this percentage of a source's zones, the loader reads all records of the source in one scan (skipping the unchanged zones); below it, the changed zones are read without scanning the rest: one query per zone, or with PostgreSQL up to 128 zones per statement. A start, a loader restart or a changed source always compares every zone. |
| `max-zone-records <n>;` | `10000000` | Records of one zone, 2..4294967295. |
| `max-zone-bytes <size>;` | `1G` | Bytes of one zone on the stream, 65535..64G (K, M, G suffixes). |
| `db-reload-timeout <s>;` | `30` | 1..3600. How long a `karictl reload <zone>` of a database zone waits for the loader's answer; then it gets `ERROR timeout` (the reload may still be applied). The control thread never waits itself: the client is parked (at most 32 at once). |
| `ingest-threads <n>;` `loader-threads <n>;` | `1` | 1..16 each. `ingest-threads` is the number of builder threads of the Backend: with 1 the thread that reads the stream also builds the zones; with more, complete zones are handed to that many builders (at most that many zones in flight; read when the server starts). `loader-threads` is the number of workers of the loader: each has its own database connection and snapshot and reads and converts a disjoint set of zones (consecutive zones in `domains.id` order); the loader writes the results to the stream in `domains.id` order whatever the number is, so the stream (and `karidns-dbloader --dump`) is byte for byte the same with 1 and with 16 workers. More workers help when converting is the cost (many zones, a cold start); one zone or a handful is always read by the loader's main thread. Zones that wait for their turn are held in memory (at most 256 MB). Measured on 4 vCPU (10^7 records, or 10^6 zones of 11 records): `loader-threads 2` cuts a start by about 40%, `ingest-threads 2` with it a little more; the defaults stay 1 (see [`karidns-dbloader(8)`](karidns-dbloader.md), "Measurements"). |

| `server-id "<id>";` | the host name | postgresql (milestone B11): the name under which this server writes its row of `karidns_server_status` (1..64 bytes; keep to ASCII letters, digits and `. - _ :`: `karicheck conf` warns about anything else). Every server that shares a database needs its own. When it is not set the host name is used; a host name longer than 64 bytes means no status row is written (one warning in the log, `dbstatus` says so) until `server-id` is set. A warning in `karicheck conf` with sqlite3 (ignored). See "Several servers on one PostgreSQL database" below. |
| `alias-resolver { <ip>; ... };` | none | The resolvers for the ALIAS records of the zones of the database when neither the zone's settings nor `options { alias-resolver }` name any (port 53; see POWERDNS ALIAS AND LUA RECORDS). |

In a `view`: `database-file "<path>";` (sqlite3) or `database-schema "<name>";` (postgresql) gives the view its own source; `database none;` makes it take no DB zones. A view without these uses the global source.

**Which zones a view gets (`karidns_domain_views`, milestone B6b).** A view that uses the global source takes the zones the table `karidns_domain_views (domain_id, view_name)` of that database assigns to it (`db/karidns_ext.*.sql`; edits are in the change log, so `karictl reload` moves a zone between views, with a `ZONE_DELETE` in the old one):

- a domain with **no row** is served by every view that uses the global source (D6); a database without the table behaves the same;
- a domain with rows is served by the views they name and by no other; view names are compared case-insensitively;
- a row that names a view that does not use this database as its source (no such view, a view with `database none;`, a view with its own file) is logged once per batch and ignored; a zone that only such rows map is served by no view (so a database shared with another server, whose views are not here, is never served by mistake), and a syslog warning names such zones (the first three and their count, once per batch);
- a view with its **own** `database-file` / `database-schema` takes all zones of that file; a `karidns_domain_views` inside it is ignored; a view with `database none;` takes none.

`karidns-dbloader --dump ... --map-view <view>` applies the same rule to a dump. File paths and schema names may contain any valid UTF-8 and are used byte for byte (`%XX` is not decoded); invalid UTF-8 and control characters are configuration errors.

**PostgreSQL (milestone B10).**

`driver postgresql;` reads the same PowerDNS 5.1 tables as the SQLite3 driver (`karidns-dbloader --drivers` lists `postgresql` when the loader was built with `make karidns-dbloader DB_DRIVERS="sqlite3 postgresql"`; `karidns` itself never links libpq). PostgreSQL 13 or newer.

- **Connection.** `conninfo-file` names a file with the libpq connection string (`host=/tmp dbname=pdns user=karidns_loader`, or a `postgresql://` URI; `#` starts a comment line). It must be a regular file owned by `loader-user` with mode 0600 or 0400 (it can hold a password), else the loader refuses it before reading it; its content is never logged and libpq's own text is not copied into a message when the string is invalid. A UNIX socket or `sslmode=verify-full` is recommended (`karicheck conf` warns otherwise). Keywords in the string win over the loader's defaults (`connect_timeout=10`, TCP keepalives, `application_name=karidns-dbloader`). The session is read only (`default_transaction_read_only`), `client_encoding` is `SQL_ASCII` (bytes are passed through like the SQLite3 driver does), and `statement_timeout` (15 min per statement or FETCH), `lock_timeout` (10 s) and `idle_in_transaction_session_timeout` (1 h) are set.
- **Schemas.** `schema "<name>";` (global) and `database-schema "<name>";` (per view) set the `search_path` of the connection to that schema; a view without one uses the global source and `karidns_domain_views`, exactly as with SQLite3.
- **Reading.** A consistent read is `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`; every scan is a cursor fetched 1000 rows at a time, so a table of 10^7 records is never held in memory. The loader role needs `SELECT` on the PowerDNS tables and the `karidns_*` tables and only the column privilege `SELECT (domain_id, active, published)` on `cryptokeys` (it never reads key material): `db/karidns_loader_role.pgsql.sql` grants exactly that (`psql -v role=karidns_loader -v schema=public -f db/karidns_loader_role.pgsql.sql DB`).
- **Errors.** A lost connection, an administrator shutdown, a statement or lock timeout and similar transient SQLSTATEs make the loader back off (1, 2, 4 ... 30 s) and read again with a new connection; other errors (a missing table or column, a denied privilege) fail the view and are shown by `karictl dbstatus`; the last good zones keep being served.
- **Change log and auto reload.** `db/karidns_ext.pgsql.sql` (schema version 2) creates `karidns_changes` with statement-level triggers (one row per distinct domain per statement) and `NOTIFY karidns_changes`. With `auto-reload yes;` the loader keeps one connection per view that does `LISTEN karidns_changes`; its socket is in the loader's `poll()` set, so a commit is seen at once (about the `coalesce` window plus the time to read and build the zones), not at the next `poll-interval`. After a reconnect the loader compares what changed meanwhile. Rows become visible when their transaction commits, in another order than their `seq` numbers were taken, so each log row carries the `xid8` of its transaction and the loader's position in the log is the `xmin` of its snapshot, not a `seq`: a transaction that took a lower `seq` but commits later is never skipped (`dbstatus` shows that position as `applied change seq`). Rows of transactions that are still open are read again by the next batch (the comparison after them is idempotent). The log keeps the newest 1,000,000 rows; a loader that finds its position pruned compares every zone.
- **Schema version 1** (`karidns_changes` without `xid`, `karidns_zone_tagdefs` without `id`) is read: the loader serves it without a change log (zones are compared by serial; `karidns_zone_tagdefs` in physical order) and says so; `db/karidns_ext_v1_to_v2.pgsql.sql` converts a database (SQLite3: `db/karidns_ext_v1_to_v2.sqlite3.sql`). A `karidns_schema_version` above 2 is refused by both drivers.
- **Several servers on one database** (milestone B11): `karidns_reload_requests` / `karidns_server_status` and `server-id`, see the next section.

**Sizes and times (milestone B13).** Measured on 4 vCPU with SQLite3: 10,000 zones of 1,000 records (10^7 records) are served 24 s after the start (13 s with `ingest-threads 2; loader-threads 2;`) and use about 1.1 GB in the Backend; 1,000,000 zones of 11 records take 33 s (19 s) and about 3 GB. A restart reads the whole database again (there are no persisted images in this release), and so does a restarted loader before it reports its first batch, while the Backend keeps answering. `karictl reload <zone>` of one zone takes about 20-30 ms at 10,000 zones and 76 ms at 100,000 zones (`tests/run_db_zoneadd_perf_test.sh`) and 5-11 ms at 1,000,000 zones (the loader looks the zone up by name). At 1,000,000 zones a one-zone change is served 15-25 ms after the command (100 changes); the occasional 0.13-0.52 s of the beta (the control thread's one-second walk of every zone, and the grace-period wait whose sleeps doubled to 131 ms) is gone; auto reload follows a commit within about `poll-interval` plus `coalesce` (1.0-1.3 s with 1 s and 200 ms). If the loader dies it is restarted after 1 s, 2 s, 4 s ... 60 s. All figures, the thread sweep and the recommended `ingest-threads` / `loader-threads` are in [`karidns-dbloader(8)`](karidns-dbloader.md), "Measurements".

**Auto reload (`auto-reload yes;`, milestone B9).** Every `poll-interval` seconds the loader asks each view's database, on a connection it keeps open for that, for `PRAGMA data_version` (a change made by any other connection; one pragma, whatever the size of the database). Only when it changed does it look at the end of the change log `karidns_changes`: no new rows, nothing to do. The first change starts a coalescing window of `coalesce` milliseconds (later changes do not extend it); when it ends the loader makes one **batch of kind `auto`** for that view: the same comparison as `karictl reload` (the zones the change log lists since the last load, zones whose serial differs, zones the Backend refused, `ZONE_DELETE` for zones that left the database, and the digest gate: a zone whose data did not change is not sent). The serial need not change. A change is visible after at most `poll-interval` + `coalesce` + the time to read and build the zones (about 3 to 4 s with the defaults, measured in `tests/run_db_autoreload_test.sh`).

- A view that shares the global source polls and loads on its own (its zones come from `karidns_domain_views`); a view with its own `database-file` has its own connection.
- A gap in the change log (rows pruned before the loader read them) or a log that was reset makes the batch compare every zone. A **database file that was replaced** by another file (another inode) or deleted is noticed by name at every poll: the loader reopens it and compares every zone; while the file is missing the zones keep being served, `karictl dbstatus` shows the error, and the loader tries again at every poll. A failed poll or load is logged once, shown by `dbstatus` and retried at the next poll.
- Without `karidns_changes` (a plain PowerDNS database) auto reload still notices every commit, but compares zones by serial only, so an edit that keeps the serial is not picked up (`karictl reload <zone>` reads one zone). The loader says so in the log once at the start of the view. Apply `db/karidns_ext.sqlite3.sql` to get the full behaviour.
- Switching `auto-reload` on with `karictl reconfig` or `SIGHUP` checks once for what changed while it was off; switching it off, or changing `poll-interval` / `coalesce`, takes effect at once. An explicit `karictl reload` is answered as always, between auto batches (a batch in progress finishes first); the auto batch that follows finds nothing to send.
- `karictl dbstatus` shows `auto reload: on (poll-interval ..., coalesce ...)`, the number of auto batches since the start and, per view, the time of the last poll, the change log position of the last complete load (`applied change seq`), the changes seen and not applied yet (`pending changes`) and the last error; the last batch line says `kind auto`. The loader reports these with the stream message `AUTO_STATUS` (see `dns_db_stream.h`).
- PostgreSQL does not poll: see "PostgreSQL" below (`LISTEN`); `poll-interval` is then only the interval of a liveness check and of the reconnect attempts.
- **A PostgreSQL hot standby** refuses `LISTEN` ("cannot execute LISTEN during recovery"), so nothing announces a commit there. The loader says so once ("auto reload: the server refuses LISTEN (a standby?); the change log is read every N s instead") and, every `poll-interval` seconds, reads a fingerprint of `karidns_changes` (the number of rows and the highest `seq`, one index-only count); when it changed, the batch is made as after a notification. The latency is then the `poll-interval`, the `coalesce` window and the replication lag (about 0.8-1.0 s with `poll-interval 1` and `coalesce 200` on a local standby, see [karidns-dbloader](karidns-dbloader.md)). Reload requests (`karidns_reload_requests`) and `karictl reload` work as on a primary; the status row cannot be written on a read-only server: that is logged once and shown by `dbstatus`, and the server keeps serving.

**Several servers on one PostgreSQL database (milestone B11).** The tables `karidns_reload_requests` and `karidns_server_status` (`db/karidns_ext.pgsql.sql`, per schema like the other `karidns_*` tables; PostgreSQL only, they are optional and need no new schema version: apply the file again to a version 2 database) let a management tool make every server reload and see what each of them did. This is the "WebAdmin inserts a row" design of the release plan (4.8): no network path to the DNS hosts and no agent.

- **Asking for a reload.** After the data is committed, insert a row: `INSERT INTO karidns_reload_requests DEFAULT VALUES;` (every zone of the schema), `INSERT INTO karidns_reload_requests (zone) VALUES ('example.test');` (one zone), or with `force` true (compare and send everything even when the Backend has the version; like `karictl reload <zone> force`). The `generation` of the row (an identity column) numbers the requests. An `AFTER INSERT` trigger sends `NOTIFY karidns_reload`; only the newest 1000 requests are kept. A `BEFORE INSERT` trigger takes a transaction-level advisory lock on the table so that two requesters get their generations in the order they commit, which is what lets a loader remember "the last generation I applied" without ever skipping a request; the second requester waits until the first commits, so commit soon after inserting. Because the request row is committed after the data, a replica that shows the request already has the data (WAL order).
- **What each server does.** Every `karidns-dbloader` of a PostgreSQL view whose schema has `karidns_reload_requests` keeps one more connection (one per schema, shared by the views that read it) that does `LISTEN karidns_reload` (its socket is in the loader's `poll()` set) and, every `poll-interval` seconds, reads the rows above the last generation it applied; a standby that cannot `LISTEN` is served by that timer alone. `auto-reload` is **not** needed. At start the highest generation counts as applied: the startup load, which comes after the connection is opened, covers it. Requests that arrive within the `coalesce` window are one reload: a request for all zones (zone NULL), a hole in the generations (requests pruned or rolled back), or more than 64 different zones makes it a comparison of the whole schema (a batch of kind `diff`, the same as `karictl reload`), otherwise each listed zone is reloaded (kind `zone`); `force` is the OR of the requests. A zone name that is not a valid name is ignored and reported as a failed zone. A request counts as applied only after every view that reads the schema was loaded; when the database cannot be read the same requests are read again at the next poll.
- **What each server reports.** When the Backend has answered the zones of that reload, the loader writes one row to `karidns_server_status` (`server_id`, `generation` = the highest request applied, `applied_at`, `ok`, `failed_zones`) in a `BEGIN READ WRITE ... COMMIT` of its own (an upsert on `server_id`). `ok` is false when any zone failed: one the loader could not read or convert (a record that does not parse) or one the Backend rejected; `failed_zones` then has one `zone: reason` line per zone (at most 64 lines and 4 KiB, then `... and N more`; control characters, DEL and bytes above 0x7E are written as `\DDD`). The outcome of the startup load is reported the same way when requests exist. `SELECT server_id, generation, ok, applied_at FROM karidns_server_status;` is the overview: a server that is down, or behind, keeps its older generation. "At the same time" means within seconds with visible status; it is not atomic.
- **The role.** `db/karidns_loader_role.pgsql.sql` gives the loader role `SELECT` on `karidns_reload_requests` (with the other `karidns_*` tables) and `INSERT, UPDATE` on `karidns_server_status` when the table exists (run it again after adding the tables). It stays `default_transaction_read_only = on`; only the status write is an explicit `READ WRITE` transaction on the watcher's own connection, never inside the `REPEATABLE READ` snapshot a load reads from.
- **When the status cannot be written** (no privilege, the table is gone, the connection is lost) the server keeps serving and keeps applying requests; the loader is not put into an error state. It logs the error once (again when the text changes), tries the write again every 10 s and `karictl dbstatus` shows it (below).
- **`karictl dbstatus`** shows, per view that has the tables, `reload requests (view v): server-id ns1, last applied generation 7, ok yes, status written <time>, last error: none` (`ok no` when a zone of the last reload failed; `status written never` before the first write; the last error is the text of a failed read of the requests or write of the status). The loader reports this in the optional tags 6..11 of the `AUTO_STATUS` stream message (`dns_db_stream.h`).
- **Not replicated:** Dynamic UPDATE (the changes are discarded when the zone reloads, as for file zones); a request cannot make a server do anything but reload.

**Several servers as primaries (milestone B11b).** Two or more servers that read one database can all be the primary of a zone: a secondary can take the zone from any of them, or from all of them in turn. For that, the same database state (and the same configuration) must give the same zone on every server, and it does; `tests/run_db_dual_primary_test.sh` checks it with two servers.

- **The same on every server.** `karidns-dbloader --dump` of one state is byte for byte the same from separate processes (with 1 or 16 `loader-threads`, per schema, per `--map-view`): the loader orders every scan by the primary keys of the tables (the tag definitions of a schema version 1 database by their physical position) and nothing in the stream depends on the process, the host or the time. The SOA serial is the one stored in the database (no `SOA-EDIT` emulation; the metadata kind is ignored with a warning). The AXFR of every zone is the same RR sequence, in the same order, not only the same set: NSEC / NSEC3 zones that are rebuilt from the PowerDNS presigned layout, tinydns zones and `$LOCATION` / ECS tagged zones (as each requester address sees them), zones of views, and the ALIAS and LUA RRs themselves. Query answers are the same too (the order of the RRs of an RRset is the stored one; KariDNS does not rotate it). LUA records are never run (see POWERDNS ALIAS AND LUA RECORDS), so they need no care.
- **IXFR (RFC 1995 §4, §6).** The differences a server keeps (`ixfr-history`) are in memory and are the versions *that server* loaded; a server that was restarted has none, and a server that applied two edits in one reload (the `coalesce` window) has one step where another has two. An IXFR from version X is the chain of the differences from X up to the current version. Two servers give **the same answer when both hold the same chain** (for example X to the current version is one step on both: that step is the same RRs in the same order). A server that does not hold X answers with the whole zone, AXFR style, which RFC 1995 §4 allows ("if incremental zone transfer is not available, the entire zone is returned"); §6 describes the same trade-off for servers that condense versions. The secondary ends in the same state either way. What is *not* promised is that two servers answer one IXFR with the same bytes when their histories differ.
- **Not the same on every server** (listed so that nothing is a surprise):
  - *ALIAS expansion.* With an `alias-resolver` the A and AAAA answers at an ALIAS name are what each server's resolver gave at the moment of its lookup (addresses, remaining TTL, stale answers after a failure), so two servers can differ, also between two queries of one server. The zone transfers carry the ALIAS RR itself and are the same. `karicheck conf` warns when `server-id` and an `alias-resolver` are both set.
  - *Dynamic UPDATE* is applied to the server that receives it and is not mirrored (D-UPDATE); persistent changes go through the database and a reload request. The update is gone when that zone reloads.
  - *tinydns time stamps and countdown TTLs* are evaluated at the moment of the query or transfer with the clock of the server: when a time stamp passes, the servers differ by the difference of their clocks, and the serial does not change (keep the servers on NTP). An Extended AXFR carries the time stamps themselves.
  - *Server cookies* are made with a random secret per process unless `cookie-secret` is set; use the same `cookie-secret` on all servers that answer for one address or are used by one client (RFC 7873 §6, RFC 9018 §5).
  - *Time.* "At the same time" is within seconds (see the reload requests above): a request that has been applied by ns1 and not yet by ns2 shows two serials, and `auto-reload` makes each server follow on its own schedule. Compare `karidns_server_status` (or `dag <zone> SOA` at each server) to see that both are at the state you expect. Servers that read different replicas also see the states of different moments.
  - *Configuration.* Options that change the data a server serves (`default-ttl`, `ixfr-history`, `max-zone-records`, `acl-ceiling`, `alias-resolver`, ...) must be the same on all servers, and so must the zones that are not in the database.

Everything except `driver`, `loader-user`, `loader-group`, `loader-path` and the presence of the block reloads (`SIGHUP` / `karictl reload`): the Backend then sends the loader a CONFIG with the new generation. These four are logged as "take effect only after a restart".

The supervisor starts the loader after the other processes. A loader exit is not fatal: it is restarted after 1, 2, 4 ... 60 s (back to 1 s after 10 minutes of uptime), with a new socket handed to the Backend. File zones keep answering meanwhile. `SIGHUP` to all processes (`pkill -HUP karidns`) does not affect the loader; it ends on `SIGTERM` with the other processes. The Backend treats everything from the loader as untrusted: a protocol violation is logged once, the stream is closed and the loader is restarted. `karicheck conf` checks the block without opening a database (driver in the loader, users, loader file, SQLite WAL and mode, conninfo-file). More than 1024 views that take DB zones (not marked `database none;`) are a configuration error for `karidns` and `karicheck conf`: the CONFIG message that tells the loader its views lists at most 1024.

`karicheck db [view]` (B12) checks the database before the data goes live: it runs `karidns-dbloader --check` (read only, the same reader as the load) as `loader-user` when root runs it, and reports the schema, every zone with the checks of `karicheck zone`, the settings texts against the keys and `acl-ceiling`, the views a zone is mapped to, and the zones of `karidns.conf` that hide a database zone (see [`karicheck(1)`](karicheck.md) "Database checks"). `karicheck conf` still checks the block without a connection.

### Settings of database zones (milestone B7a)

A zone in `karidns.conf` takes its per-zone options from its `zone { }` statement; a database zone takes them from its PowerDNS `domainmetadata` and, optionally, from a **profile**. The loader turns the metadata into a *settings text* in `zone { }` syntax and sends it with the zone; the Backend parses it with the configuration parser in a restricted mode and applies it. The text is treated as hostile: only the statements listed below are accepted, and anything else (`file`, `type`, `program*`, `forwarders`, `rate-limit`, `ecs-tags`, `include`, a named `acl` of `karidns.conf`, an unknown word, unbalanced braces, an ACL entry that is not an address) rejects that zone alone: it keeps its last good version **and its last good settings** (or is absent when it has none), and `karictl dbstatus <zone>` shows the reason. A TSIG key that the settings name must be defined in `karidns.conf` or the zone is rejected the same way.

| Metadata `kind` (PowerDNS 5.1) | Settings statement | Notes |
|---|---|---|
| `ALLOW-AXFR-FROM` (one address or prefix per row) | `allow-transfer { <addr>; };` | `AUTO-NS`, a name or anything else that is not an address or prefix is left out with a warning of the loader (the list never becomes wider). |
| `TSIG-ALLOW-AXFR` (one key name per row) | `allow-transfer { key "<name>"; };` | Both kinds: `allow-transfer { ...; key "..."; }; transfer-acl-match any;` |
| `ALLOW-DNSUPDATE-FROM`, `TSIG-ALLOW-DNSUPDATE` | `allow-update { ... };` | Both kinds: `update-acl-match all;` is added. |
| `ALSO-NOTIFY` | `also-notify { ... };` | `ip`, `ip:port`, `[ip]:port`. Addresses only (no list name, no key); without it the zone uses the `options` / view `also-notify`. |
| `AXFR-MASTER-TSIG` | `tsig-key "<name>";` | The key of the primary of a secondary zone (`SLAVE` / `CONSUMER`, milestone B7b). It is **not** a key that may transfer the zone. |
| `domains.master` (a column, not metadata) | `masters { <addr> [port <n>]; ... };` | Only for `SLAVE` and `CONSUMER` zones: see "Database zone types". `masters` and `primaries` are the same statement. |
| `X-KARIDNS-<OPTION>` | `<option> <value>;` | `NOTIFY-RETRIES`, `NOTIFY-RETRY-INTERVAL`, `NOTIFY-RETRY-BACKOFF`, `NOTIFY-TCP-TIMEOUT`, `IXFR-HISTORY`, `ADDITIONAL-FROM-AUTH`, `DISABLE-AUTO-TC-FLAG`, `ZONE-UDP-BUFSIZE`, `ZONE-TCP-MSS`, `ZONE-TCP-WINDOW`, `ZONE-TCP-SNDBUF`, with the ranges of the zone options. An invalid value or an unknown option is dropped with a warning. |
| `X-KARIDNS-PROFILE` | the profile of the zone | See below. |
| `X-KARIDNS-ECS-TRUSTED-RESOLVERS` | `ecs-trusted-resolvers { <addr>; ... };` | Addresses and prefixes, a leading `!` excludes; bounded by `acl-ceiling` when queries are answered: see "Location / ECS tags and tinydns zones in the database". |
| (a profile text or the loader's own text, no metadata kind) | `alias-resolver { <addr> [port <n>]; ... };` | May be written in a profile (`karidns_profiles`); the ALIAS resolvers of the zone, see POWERDNS ALIAS AND LUA RECORDS. Not sent with Extended AXFR. |
| `PRESIGNED`, `NSEC3PARAM`, `X-KARIDNS-FORMAT` | (zone flags, not settings) | `X-KARIDNS-FORMAT tinydns`: B8. |

Other kinds are ignored; those that change answers in PowerDNS (`SOA-EDIT`, `NSEC3NARROW`, ...) get a warning once per zone; `ENABLE-LUA-RECORDS` with the value 1 rejects the zone (LUA records are not run). A zone with `ALLOW-AXFR-FROM` rows but none of them usable gets `allow-transfer { none; }`.

**Match modes: `transfer-acl-match any|all;` and `update-acl-match any|all;`** are zone options of `karidns.conf` too. They only matter for an ACL that has both addresses and keys. The settings of a database zone (and the settings a secondary receives from its primary) are always evaluated in this way and never in BIND's first-match order; for them "the default" below is what applies when the text does not say. A zone of `karidns.conf` that does not write the options uses BIND's first-match order since the ACL batch of the BIND compatibility work (see "Address match lists"). For `allow-transfer`: `all` (the default for these settings, as in earlier versions) needs a matching address **and** a listed key; `any` accepts a matching address **or** a request signed with a listed key. For `allow-update`: `any` (the default) accepts a matching address **or** a request signed with a listed key; `all` needs every kind of entry that is written to match (addresses only: the address; keys only: the key; both: the address **and** the key). The loader writes `transfer-acl-match any;` and `update-acl-match all;`, which is the PowerDNS meaning (AXFR is allowed by `ALLOW-AXFR-FROM` or by a `TSIG-ALLOW-AXFR` signature; an UPDATE needs `ALLOW-DNSUPDATE-FROM` and a `TSIG-ALLOW-DNSUPDATE` signature). PowerDNS also adds its server-wide `allow-axfr-ips` and `allow-dnsupdate-from` (default `127.0.0.0/8, ::1`) to these lists; KariDNS applies exactly the lists in the database. `karicheck conf` warns when an option has nothing to choose between.

**`acl-ceiling`.** A database cannot widen access beyond what `karidns.conf` allows. The ceiling is a list of addresses (a prefix, `any`, `!` exclusions; the first matching entry decides, as in every address list) and `key "<name>"` entries. A client is **inside the ceiling** when its source address matches the address entries or its request was verified (RFC 8945 §5.2) with a key the ceiling names. A request to a database zone (AXFR/IXFR or dynamic update) is allowed only if the zone's ACL (with its match mode) allows it **and** the client is inside the ceiling; so a database ACL `any;` means "every client the ceiling lets in", and an address the database lists but the ceiling does not cover is usable only with a request signed by a ceiling key. With **no ceiling configured, every database ACL refuses everybody** (logged once; `karicheck conf` warns). File zones are not subject to the ceiling. **`acl-ceiling-match all;`** (milestone B7b) changes "inside the ceiling" for a ceiling that lists both addresses and keys: the request must come from a listed address **and** be signed with a listed key. That is something BIND's ACLs cannot express (a key in an address match list is an alternative to the addresses, or a second ACL ANDs nothing), and it is the strict form for a server whose database may be edited by many people: only the transfer agents (a known address) that also hold the key get in. `any` (the default) is the form described above. The ceiling and the keys are read from the active configuration for every request, so `karictl reconfig` takes effect at once, without reading any data again. Entries that can never match because of the ceiling are warned about when the settings are first installed and listed by `karictl dbstatus <zone>` (`allow-transfer 198.51.100.0/24 lies outside acl-ceiling`). A TSIG key that a database ACL names but `karidns.conf` no longer defines (after a reload) closes that ACL: transfers (or updates) of the zone are refused for everybody until the key is back; the log, `karictl dbstatus <zone>` (`settings error`) and the summary line say so.

**Profiles.** `karidns_profiles (name, settings)` holds named settings texts in the same statements; a zone names its profile with `domainmetadata` `X-KARIDNS-PROFILE`. The profile is the base and the zone's own metadata overrides it **statement by statement**: a statement the zone's metadata produce (`allow-transfer`, `also-notify`, an option, ...) replaces the profile's statement of the same name completely, including its keys. The merge is done in the Backend: the loader sends the profile text in a `PROFILE` message before the first zone of the batch that uses it and the zone's own text in `ZONE_BEGIN`, and the Backend parses the profile text, the zone text and the two together (profile first), so a profile cannot swallow the zone's statements and a hostile loader cannot get a statement past the whitelist by the way it splits them. Settings with the same profile name, profile text and zone text are shared by all zones that have them (one parsed block; `karictl dbstatus` counts the distinct ones). An unknown profile fails the zone in the loader (`the profile 'x' is not defined in karidns_profiles`); a profile text the Backend refuses rejects every zone that uses it. A profile text is limited to printable ASCII, TAB and LF and 65,535 bytes; the Backend keeps at most 16 MiB of profile text per batch.

**Edits and reload.** The digest of a zone covers the data **and** the settings text, the profile name and the profile text, so an edit of metadata or of a profile that keeps the serial is applied by `karictl reload <zone>` and by `karictl reload`, and `karictl reload <zone>` of an unchanged zone says `unchanged`. The triggers of `db/karidns_ext.*.sql` log every domain whose `X-KARIDNS-PROFILE` names an inserted, edited, renamed or deleted profile, so `karictl reload` finds the zones of an edited profile through the change log. `karictl reload` and `karictl reconfig` re-check the settings of all database zones against the new configuration (the log says how many name a key that is not defined).

### Database zone types (milestone B7b)

`domains.type` decides what the loader makes of a row (PowerDNS 5.1 names, case-insensitive):

| `domains.type` | KariDNS |
|---|---|
| `NATIVE`, `MASTER` | a primary zone; its data comes from `records` |
| `SLAVE` | a **secondary** zone: the masters come from `domains.master`, the TSIG key from the `AXFR-MASTER-TSIG` metadata (it must be defined in `karidns.conf`, or the zone is rejected like any zone that names an undefined key). The data comes by AXFR/IXFR, never from `records` |
| `CONSUMER` | a **catalog consumer**: like a `zone { type slave; catalog-zone yes; }` of `karidns.conf` (RFC 9432); the member zones the catalog lists are created, transferred from the same masters and removed again like those of a configured catalog zone. Masters and key as for `SLAVE` |
| `PRODUCER` | the catalog zone itself is not supported yet (a later 0.6.x release): it is reported (`ZONE_FAILED`, `karictl dbstatus <zone>`) and not served, so secondaries that take the catalog from KariDNS do not get it. Its member zones (`domains.catalog`) are ordinary zones and are served, so a PowerDNS database that has catalog zones can be migrated; `karicheck db` reports the `PRODUCER` zone as a warning, not an error |
| anything else | the zone is skipped and reported |

**SOA serial 0.** A zone whose apex SOA serial is 0 is loaded and served with serial 0, and the loader logs a warning once for each version of the zone it sends (`zone 'x.test.' (domains.id N): the SOA serial is 0; ...`), not on every reload of an unchanged zone. PowerDNS may compute the served serial (`SOA-EDIT`, auto-serial); KariDNS uses the stored number, so secondaries and NOTIFY see serial 0 until the zone gets a higher serial. `karicheck db` gives the same finding as a warning.

**Masters.** `domains.master` is a list of addresses separated by commas (blanks are tolerated), each `ip`, `ip:port`, `[ipv6]:port` or a bare IPv6 address (PowerDNS syntax). A host name, a bad port, an empty or NULL column fails that zone in the loader (`domains.master entry 'x' is not an IP address[:port] (host names are not supported)`); at most 16 entries are used. The loader writes them as `masters { 192.0.2.1 port 5353; 2001:db8::1; };` in the settings text of the zone, next to `tsig-key` and the usual ACLs (`ALLOW-AXFR-FROM` and so on: a database secondary can itself be transferred, bounded by `acl-ceiling`), and sends `ZONE_BEGIN` with the zone kind secondary (or catalog) and **no data** (`rr_count 0`, no `ZONE_DATA`). `masters` and `primaries` are the same statement; in a settings text they accept IP addresses only (at most 32).

**How the Backend runs it.** The Backend keeps an ordinary zone entry for the zone and the secondary machinery of the control thread does the rest, exactly as for a `zone { type slave; }`: the first transfer at the first tick (about a second after the zone arrived), then the SOA refresh / retry / expire timers (an expired zone answers SERVFAIL, RFC 1034 §4.3.5), IXFR with a fallback to AXFR (RFC 1995), NOTIFY accepted from the listed masters and, when `tsig-key` is set, only when signed with that key (RFC 1996, RFC 8945 §5.2), `also-notify` towards downstream secondaries after every transfer. As for configured secondaries, the masters are asked in order, each at every refresh until one is ahead (see Transfer and NOTIFY options), and the options of the view and of `options` (timers, `transfer-source`, ...) apply; a master's `source` cannot be written in the settings text.

**Data lives in memory only.** PowerDNS writes what a slave transfers into the database; KariDNS does not. After a restart of `karidns` a `SLAVE` zone is empty until its first transfer, and the rows of `records` of a `SLAVE` zone (a copy PowerDNS made) are ignored. A restart of the **loader** costs nothing: the loader compares the settings of every zone with what the Backend has (the digest of a secondary covers its settings text, profile and kind, not its data) and sends nothing for an unchanged zone, so no zone is transferred again.

**Changes.** A change of `domains.master`, of `AXFR-MASTER-TSIG`, of the ACL metadata or of the profile is applied by the next reload (`karictl reload`, `karictl reload <zone>`, the change log): the settings of the zone are replaced, the zone keeps its data, and a refresh from the new masters is started at once (an IXFR from the serial it holds; use `karictl retransfer <zone>` for a full transfer when the new master has an older serial, which a secondary refuses to follow). A zone whose type changes between `NATIVE` and `SLAVE`, or between `SLAVE` and `CONSUMER`, gets a new entry (the data of the old one goes). A deleted row removes the zone with the next reload, and a deleted `CONSUMER` takes the member zones it created with it. `karictl retransfer <zone>` works for `SLAVE` and `CONSUMER` zones; `karictl reload <zone>` re-reads the settings (it does not start a transfer), `karictl notify <zone>` sends NOTIFY to the zone's `also-notify` addresses; `karictl dbstatus <zone>` shows the masters, the key, the last successful transfer and its serial.

**Precedence (D17-1).** A catalog member of the same name hides a database zone of that name on every path, a `SLAVE` or `CONSUMER` included, and the database zone is served again when the member goes away (also when the whole catalog consumer is deleted). A `zone { }` of `karidns.conf` of the same name hides the database zone as before; a hidden `SLAVE` makes no transfers.

### Location / ECS tags and tinydns zones in the database (milestone B8)

A zone file with `$LOCATION` / `$ECS-SUBNET` tags or a tinydns data file is not a thing a PowerDNS database can hold, so KariDNS keeps the **parsed** result in its own tables (`db/karidns_ext.*.sql`, created together with the change-log triggers; PowerDNS ignores them, so on a database that PowerDNS also serves the tags and the tinydns time stamps and locations have no effect there):

| Table | Content |
|---|---|
| `karidns_record_tags (record_id, location_tag, ecs_tag)` | the `$LOCATION` and `$ECS-SUBNET` tag in force for that row of `records` (NULL = none). A tag name is 1-63 printable characters without blanks; `none` and `default` are reserved (they clear a tag in a zone file). Tags compare without regard to case. A row with a tag is answered to the clients that match the tag, in addition to the untagged rows. |
| `karidns_zone_tagdefs (domain_id, kind, tag, cidr)` | one row per CIDR: `kind` `location` (`$LOCATION-TAG`), `ecs` (`$ECS-SUBNET-TAG`) or `tinydns` (a `%` line: `tag` is the 1-2 character location code, `cidr` an IPv4 prefix). **The order of the rows of a zone is the order of the definitions** (the first definition that matches a client wins; consecutive rows of one tag are one definition): insert them in file order. SQLite3 reads them in `rowid` order. |
| `karidns_record_tinydns (record_id, ttd, loc, countdown)` | the tinydns time stamp (unix time of the TAI64 label; NULL = none), the 1-2 character location code of the line, and `countdown` (a record with TTL 0 and a time stamp: its TTL counts down to the time stamp, 2 to 3600 s). A time stamp on a record with a TTL is the time from which the record is served. |
| `domainmetadata` `X-KARIDNS-FORMAT` = `tinydns` | the zone is a tinydns zone (time-dependent TTLs, answers never cached), also when no row has a time stamp or a location. |
| `domainmetadata` `X-KARIDNS-ECS-TRUSTED-RESOLVERS` | the zone option `ecs-trusted-resolvers`: addresses and prefixes, separated by commas or blanks, one or several rows, a leading `!` excludes (first match decides). An entry that is not an address or prefix fails the zone. |

**How it travels.** The loader sends these tables in the zone's `ZONE_DATA` as Extended AXFR records, written by the same encoder as Extended AXFR out (`xext_*` in `dns_wire.c`); `ZONE_BEGIN` flag bit1 (extended) says the records are there, bit2 (tinydns) is the tinydns flag. The Backend reads them with the transfer parser a secondary uses and accepts them only in a zone that announced them; a malformed definition, state or wrapper record, a tag longer than 63 octets, more than 4096 tinydns locations or an `ECS_TRUSTED` record rejects the zone. The digest of a zone covers the attributes and the tinydns flag, so an edit of a tag or a definition is applied by `karictl reload`. A database zone is transferred out as Extended AXFR to a KariDNS secondary like a zone file (`allow-transfer` as usual): the secondary answers every client like the primary.

**`acl-ceiling` and the trusted resolvers.** The list of `X-KARIDNS-ECS-TRUSTED-RESOLVERS` is bounded by the ceiling **when a query is answered**: a resolver is trusted only if the zone's list and the **address entries** of `acl-ceiling` both accept its address (keys of the ceiling do not matter: ECS trust has no key; with no ceiling configured nobody is trusted; a zone without the metadata uses the `ecs-trusted-resolvers` of `options`, which is not bounded). `karidns-dbloader` / the Backend log the entries that lie outside the ceiling once per distinct settings text. A server that is a secondary of a database zone gets the list in the Extended AXFR (it is the primary's data) and applies its own configuration to it.

**What does not carry over.** (1) The SOA serial that a tinydns `.` line takes from the data file's modification time: the database stores the number the importer saw; whoever edits the zone bumps it (a `Z` line carries an explicit serial). (2) The data file as text: comments, line grouping, one line that writes into two zones (`=` makes an A and a PTR: two independent rows in two zones), a data file with many zones (the importer writes one zone per SOA). (3) Several SOA rows for the apex, and tags or tinydns attributes (time stamp, location) on a SOA row (milestone B8t-1): `karidns-dbloader` reads them like any other row (the SOA rows must have one serial; the SOA without attributes, else the first row, is the reference SOA and gives the zone serial; a presigned zone cannot have them) and the rules of "Several SOA records" below apply to a zone file. Milestone B8t-2: the stream between the loader and the Backend is the Extended AXFR version 3 format, which carries them (the frame is the reference SOA, `SOA_SET` announces the number of SOA rows and each SOA row is a body RR in a wrapper record, with its tinydns attributes and tags). The Backend checks what the loader sent: every SOA at the apex, one serial (the one `ZONE_BEGIN` declares), no two SOA rows for the same clients, the opening SOA is the reference SOA, the number announced; a zone that fails a check is rejected and the last good version keeps serving. At most 4096 SOA rows. (4) `karidns_*` rows of a record that is disabled or does not exist are ignored with a warning.

**Importer.** `tests/db/zone2sql` (the seed of the later ZoneImporter) writes all of this: `zone2sql --dialect sqlite3|pgsql zone` for a zone file with tags, `zone2sql --format tinydns data` for a tinydns data file; apply `db/karidns_ext.*.sql` first.

### Address match lists (ACLs)

`allow-query`, `allow-query-on`, `allow-transfer`, `allow-update` and `allow-notify` (in `options`, `view` and `zone`), `match-clients`, `ecs-trusted-resolvers` and `acl` take an address match list, as in BIND 9.20 (ARM "Address Match Lists"):

```
address_match_list = address_match_element; ...
address_match_element = [ ! ] ( <ip_address> | <ip_prefix> | key <key_id> | <acl_name> | { address_match_list } )
```

An element is an IPv4/IPv6 address, a prefix, `any`, `none`, `localhost`, `localnets`, `key "<name>"`, the name of an `acl` block or a nested `{ ... }` list; a leading `!` negates it. **The elements are tried in order and the first one that matches decides**: a non-negated match allows, a negated match denies, and a client that matches nothing is denied (ARM: "If there is no match, access is denied"; "Order of insertion is significant"). `none` matches nothing. A `key` element matches a request that is signed with a TSIG key of that name and whose signature verified (RFC 8945 §5.2), whatever the client's address; key names are compared as domain names (case and a trailing dot do not matter), and a key must be defined in a `key { }` block. A nested list matches when *its own* first match is a non-negated one; a negative match inside it counts as "no match" for the element that holds it (BIND's `lib/dns/acl.c` does the same), which is what makes `!{ !192.0.2.1; any; }; key "k1";` BIND's idiom for "from 192.0.2.1 **and** signed with k1". In `allow-update` the bare name of a defined key is accepted as well (`allow-update { k1; };` is `key "k1"`).

`acl "<name>" { ... };` defines a named list; it may be written before or after its first use, may contain `key`, other `acl` names, nested lists and `!`, and is evaluated like a nested list at the place where its name stands (`!name` denies a client the list allows; a client the list excludes with `!` is "no match" and the next element decides). An `acl` that contains itself, directly or through others, and lists nested more than 8 deep are configuration errors, as is any entry that is not an address, a prefix, a built-in name, a defined `acl` (or key) -- `karicheck conf` reports them with `file:line`. `match-clients` and `ecs-trusted-resolvers` look at the address only: `key` is an error there, and they read the list as flat entries (a `!{ ... }` block negates each of its entries).

**Where the statements apply.** For each of the five statements the list that applies to a zone is the zone's own, else its view's, else the one in `options` (BIND 9.20 ARM: the zone statement "overrides" the options statement); the lists are never merged, and `{ }` written at a lower level matches nobody. Defaults: `allow-query` and `allow-query-on` allow everybody (so a configuration that has no `allow-query` anywhere is exactly as before); `allow-transfer` and `allow-update` allow nobody ("If allow-transfer is not specified, then the default is none"); `allow-notify` adds nobody to the zone's primaries and applies to secondary zones only.

- **`allow-query`** is checked for every QUERY (opcode 0) for a name in a zone, **before** anything is looked up and **before** the shared response cache: a client that is not allowed gets REFUSED (AA=0) with EDE 18 (Prohibited, RFC 8914 §4.19) and a question section, nothing of the zone (not even that the name does not exist, or that the zone has expired). It applies on UDP and TCP alike, to zones of every type (`master`, `slave`, `forward`, `program`, database zones, catalog members) and to a UDP IXFR/SOA-only answer. The cached answers do not depend on the client; because the check comes first, an answer cached for a client that may ask is never given to one that may not (tested with the cache warm). A CNAME that leads into another zone of the view is followed only if the client may ask *that* zone as well; otherwise the answer ends with the CNAME that has been collected (NOERROR) and is not cached, and glue taken from another zone is left out for such a client. A request signed with a key is checked with that key (`key` elements); a request whose TSIG fails is answered NOTAUTH before this check, as before. Zone transfers (AXFR/IXFR over TCP) are governed by `allow-transfer` only, NOTIFY by the primaries and `allow-notify`, UPDATE by `allow-update`; `allow-query` does not apply to them.
- **`allow-query-on`** is checked against the address the query came to, with the same effect. On TCP it is the local address of the connection (`getsockname`), on UDP the destination address of the datagram (the Frontend reads `IP_RECVDSTADDR` / `IPV6_PKTINFO` from every UDP socket, wildcard or not, and passes it to the Backend with the packet). If the address is unknown the only element that can match is `any`. The answer is refused when either `allow-query` or `allow-query-on` does not allow the query.
- **`allow-transfer`** may be written in `options` and `view`; `key` elements, `!`, nested lists and named lists work as above. See "Order of evaluation and `transfer-acl-match`" below for what changed for lists that mix addresses and keys.
- **`allow-update`** may be written in `options` and `view`. A zone that is not a primary refuses updates whatever the lists say.
- **Database zones** take `allow-query` and `allow-query-on` from their view and `options` like any zone (their settings text cannot carry them), and `allow-notify` for a database secondary. Their `allow-transfer` / `allow-update` come from the settings text only and stay bounded by `acl-ceiling`: the statements of `options` and `view` are not a default for them (a database zone without an ACL refuses transfers and updates, as before).
- **`allow-notify`**: for a secondary zone a NOTIFY is accepted when it comes from one of the zone's primaries (with the key rule of `primaries`) **or** the list allows the sender; a `key` element is the TSIG key the NOTIFY is signed with.

**Order of evaluation and `transfer-acl-match` / `update-acl-match`.** Before this release KariDNS read `allow-transfer` as "an address in the list **and** a listed key" when it had both kinds of entry, and `allow-update` as "an address in the list **or** a listed key", ignoring the order of the entries. Without `transfer-acl-match` / `update-acl-match` a configuration file now uses BIND's evaluation for both:

| | before | now (no `*-acl-match`) | to keep the old meaning |
|---|---|---|---|
| `allow-transfer { 192.0.2.1; key "k"; };` | address **and** key | first match: the address **or** the key (`allow-transfer { key "k"; 192.0.2.1; };` also accepts an unsigned request from 192.0.2.1) -- **more permissive** | `transfer-acl-match all;` in the zone (or write `{ !{ !192.0.2.1; any; }; key "k"; };`) |
| `allow-transfer { 192.0.2.1; };` with `tsig-key "k"` in the zone | address **and** a request signed with the key | unchanged: the list says who may ask, and a zone that has a `tsig-key` and addresses in its list still needs a request signed with the `tsig-key` (or a key of the list). With a list of keys only, the `tsig-key` is one more key that may transfer, as before | |
| `allow-update { !192.0.2.9; 192.0.2.0/24; key "k"; };` | the address list matched **or** the request was signed with a listed key (`!` entries only ever removed addresses) | first match: a request from 192.0.2.9 is refused even when it is signed with k -- stricter | `update-acl-match any;` |
| addresses only, or keys only | unchanged | unchanged | |

`karicheck conf` warns about the first and the third row for every zone that writes its own list (see karicheck(1)), so a configuration that has become more permissive is found before it is loaded. Writing `transfer-acl-match any|all;` / `update-acl-match any|all;` keeps the meaning of the earlier releases exactly (`any`/`all` as described in the zone table): the list is then split into its address entries (evaluated in order, as above) and its key entries, and combined as the option says; the options cannot be used with a negated key (`!key "k"`), which is a configuration error there. The lists of **database zones** are not affected: the settings the database loader writes (see "Settings of database zones") are evaluated as before, with `transfer-acl-match any` / `update-acl-match all` written by the loader, `acl-ceiling` as the bound, and no `acl` names, `localhost`, `localnets` or nesting in them; the same holds for the settings a secondary receives from its primary (they replace what `options` or the view say, but not a statement written in the secondary's own `zone { }`; the settings a primary sends contain only the zone's own `allow-transfer`, not the one of its view or of `options`).

**`localhost` and `localnets`** (BIND 9.20 ARM, `acl`): `localhost` matches the IPv4 and IPv6 addresses of all network interfaces of the host, `localnets` any host on an IPv4 or IPv6 network for which the host has an interface (the address and netmask of the interface; for IPv6 the prefix length the system reports). The Backend runs in capability mode and cannot ask the kernel for its interfaces, so the server takes **one snapshot of the interfaces at start-up** (`getifaddrs(3)`, before the privileges are dropped) and evaluates the two names against it. **A reload does not take a new snapshot, and BIND's periodic re-scan (`interface-interval`) does not exist: an address added or removed after start-up is noticed after a restart.** Interfaces that are down are not part of the snapshot. In the flat lists that `match-clients`, `ecs-trusted-resolvers` and the settings sent to secondaries use, `localhost`/`localnets` stand for the addresses/networks of the same snapshot.

### `zone "<name>" { ... }`

| Option | Applies to | Description |
|---|---|---|
| `type <type>;` | all | `master` (alias `primary`, the default), `slave` (alias `secondary`), `forward`, or `program`. Case-insensitive. The BIND zone types of a resolving or caching server, `hint`, `stub`, `static-stub`, `mirror`, `redirect` (and `delegation-only` of older BIND versions), are accepted so that a stock BIND `named.conf` can be read: the zone is **not loaded**, the rest of its block is skipped, and a warning with the file and line says so (`karicheck conf` shows it). `forward` keeps its KariDNS meaning (this server relays the queries of the zone; in BIND it is a resolver-side type, which `karicheck conf` notes). `in-view` is a configuration error (a zone cannot be shared between views yet). Any other value is an error. |
| `file "<path>";` | master, slave | Zone file. For a secondary zone the file is optional: if it exists it is loaded at startup as the initial data, and the zone is then refreshed from the primary. Transferred data is kept in memory only and is never written to the file, so after a restart a secondary serves the file's data (or nothing) until its first transfer. Ignored (with a warning) for `forward` and `program` zones. Records whose owner is not at or below the zone name (out-of-zone data, including address records for name servers outside the zone) are not loaded; each is logged as "ignoring out-of-zone data", as BIND does (RFC 1034 §4.2). A secondary likewise skips and logs out-of-zone records received in a transfer instead of rejecting the transfer. A record that the zone file parser accepts but whose RDATA cannot be encoded for its type (for example a WKS port name that is not in the built-in service table) is also left out with a warning ("its RDATA cannot be encoded"); the rest of the zone is served and transferred. `karicheck` reports such a record as an error. |
| `file-format bind\|tinydns;` | master | `bind` (default) or `tinydns` (djbdns `data` file). See TINYDNS ZONE FORMAT. |
| `primaries [ port <n> ] { ( <list> \| <addr> [port <n>] ) [key <name>]; ... };` (also `masters`) | slave, catalog | Primary servers (BIND 9.20 ARM "primaries"; list names, `port`, `key`, errors: see `also-notify` and `remote-servers`). NOTIFY is accepted from any listed address, and when that address has a `key` (or else the zone has `tsig-key`) only when signed with it; the refresh and transfer ask the entries **in order** (a failure, an up-to-date answer or a primary that is behind goes on to the next; the first one that is ahead is transferred from): SOA, IXFR and AXFR requests to an entry are signed with its `key`, else with the zone's `tsig-key`, and the answers are verified with the same key (the `key` of the primary wins over `tsig-key`). An address may also be a prefix (`10.0.0.0/8`, as before: it only widens who may send NOTIFY; do not use it for the first entry). A list name is replaced by the addresses of the list. `tls` is a configuration error. `source ( <ipv4> | * ) [ source-v6 ... ]` before the braces is the local address of the connections to the addresses written in that statement (an address taken from a named list keeps that list's source). A later `primaries`/`masters` statement replaces the earlier one. Port default 53. Transfer requests carry the EDNS EXPIRE option (RFC 7314); the returned value (capped by SOA EXPIRE) sets the zone's expire timer, so a secondary that transfers from another secondary expires no later than its source. The refresh sends IXFR (AXFR when the zone has no data yet, or after `karictl retransfer`). Every message of the answer must carry the request's ID, QR=1 and OPCODE 0, and the first one the request's question (RFC 5936 §2.2.1); otherwise the transfer is rejected and logged. An answer with an error RCODE ends the transfer at once and is logged with the RCODE (and the TSIG error, when the primary rejected the zone's `tsig-key`); a primary that answers IXFR with FORMERR or NOTIMP is asked once more with AXFR (RFC 1995 §4). |
| `tsig-key "<name>";` | slave, master | Key used to sign SOA/AXFR/IXFR requests to the primary. On a primary it is also accepted for incoming transfers. Outgoing NOTIFY messages of the zone are signed with it. |
| `allow-query { <acl>; ... };`, `allow-query-on { <acl>; ... };` | all | Who may ask this zone ordinary questions, and on which local addresses (BIND 9.20 ARM). Replaces the `view` and `options` statements; REFUSED with EDE 18 otherwise. See [Address match lists](#address-match-lists-acls). |
| `allow-notify { <acl>; ... };` | slave | Who may send NOTIFY for this zone in addition to its `primaries`. Replaces the `view` and `options` statements. |
| `allow-transfer { <acl>; key "<name>"; ... };` | master, slave | Who may transfer the zone (AXFR/IXFR over TCP); replaces the `view` and `options` statements (written `{ }` it allows nobody). **Without an `allow-transfer` at any level and without `tsig-key`, transfers are refused.** The list is evaluated in BIND's order (first match decides; a `key` element matches a request signed with that key; the zone's `tsig-key` still has to sign the request when the list has addresses); with `transfer-acl-match` written it is the older "address and key" / "address or key" combination: see [Address match lists](#address-match-lists-acls). At most 4 transfers per zone run at the same time. The first message of an answer carries an OPT when the request had one (RFC 5936 §2.2.5). An IXFR request needs the client's SOA in the Authority section (RFC 1995 §3), otherwise it gets FORMERR; a client whose serial is the same as or newer than the zone's (RFC 1982 comparison) gets the current SOA only (RFC 1995 §2), also over UDP. A transfer request for a zone that has no data yet (a secondary before its first transfer) gets SERVFAIL with EDE 14 (Not Ready). |
| `also-notify [ port <n> ] { <addr> [port <n>] [key <name>]; <list>; ... };` | master | Additional servers that receive NOTIFY (RFC 1996) when the zone changes; replaces the list of the view or `options` (grammar, lists, keys: see `also-notify` and `remote-servers`). NOTIFY is also sent to the addresses of the apex NS hosts, except the SOA MNAME host (RFC 1996 §3.2). NOTIFY is sent after an UPDATE, after `karictl notify`, after a reload (`karictl reload`, `reconfig`, SIGHUP) that changed the zone's serial (not at the first load at startup), and by a secondary after each transfer. Each NOTIFY goes over UDP (over TCP for a server with `tcp-only yes`, see [NOTIFY over TCP](#notify-over-tcp)) and is retransmitted until the server answers with the same ID and QNAME from the address and port it was sent to (RFC 1996 §3.6); see `notify-retries` (by default 2 retransmissions 5 s apart, then TCP). When the zone has `tsig-key`, every NOTIFY is signed with that key and only an answer whose TSIG verifies ends the exchange (RFC 8945 §5.4); an answer that fails verification is logged and ignored, and the NOTIFY is made over TCP at once. A NOTIFY that gets no answer over UDP after the last retransmission is made once over TCP. |
| `notify yes|no|explicit|primary-only|master-only;` | master, slave | Per-zone override of the view and `options` value (default `yes`): `no` sends nothing, `explicit` only to `also-notify`, `primary-only` / `master-only` only for primary zones. See `also-notify` and `remote-servers`. |
| `notify-retries <n>;`, `notify-retry-interval <seconds>;`, `notify-retry-backoff fixed\|exponential;`, `notify-tcp-timeout <seconds>;` | master, slave | Per-zone override of the `options` values below. |
| `ixfr-history <n>;` | master, slave | Per-zone override of the `options` value: how many past versions are kept as IXFR differences, 0–32 (default 4; see the options table). `0` answers every IXFR request with the whole zone. |
| `max-zone-records <n>;`, `max-zone-bytes <size>;` | secondary | Per-zone override of the `options` values: the most RRs and message octets of one inbound AXFR/IXFR (see the options table). |
| `transfer-acl-match any\|all;`, `update-acl-match any\|all;` | master, slave | Which kinds of entry of `allow-transfer` / `allow-update` have to match when the list has both addresses and keys: `transfer-acl-match all` = address **and** key, `any` = address **or** key; `update-acl-match any` = address or key, `all` = address and key. **Not written** (the default), a list in `karidns.conf` is evaluated in BIND's order: the first element that matches decides ("Address match lists" above; before, an `allow-transfer` with addresses and keys meant `all`). The options are what the database loader writes for database zones, whose settings are evaluated as before (see "Settings of database zones"). `karicheck conf` warns when a list has become more permissive. |
| `notify-source "<addr>";` | master | Source address of outgoing NOTIFY messages (either family; BIND's `notify-source` / `notify-source-v6` and the other transfer and NOTIFY options -- `transfer-source`, `min-refresh-time`, `max-transfer-time-in`, `multi-master`, `request-ixfr`, ... -- are also written in a `zone`, see Transfer and NOTIFY options). |
| `allow-update { <acl>; key "<name>"; ... };` | master | Enables Dynamic Update (RFC 2136) for matching clients or TSIG keys; replaces the `view` and `options` statements. The list is evaluated in BIND's order (first match decides) unless `update-acl-match` is written. Updates are kept in memory only. An update sent to a secondary zone is answered with REFUSED (EDE 18) whether or not the client matches `allow-update`: KariDNS does not forward updates to the primary (RFC 2136 §6); a warning is printed at load time. Processing follows RFC 2136 §3: an update whose zone section does not name a zone of the client's view gets NOTAUTH; update RRs that §3.4.2 says to ignore (a CNAME next to other data or other data next to a CNAME, an SOA whose serial is not newer, deletion of the apex SOA, of the apex NS RRset or of the last apex NS) are ignored and the rest of the update is applied; an error anywhere leaves the zone unchanged. An update that replaces the SOA with a newer serial keeps that serial; any other change increments the serial by one. An update that changes nothing (only prerequisites, or only ignored or already present records) answers NOERROR without changing the serial or sending NOTIFY. |
| `catalog-zone yes;` | master, slave | Marks the zone as a catalog zone (RFC 9432, schema version 2: `version.<zone> TXT "2"` is required). Member zones listed under `zones.<zone>` are served as secondary zones that transfer from the catalog zone's first `masters` entry. |
| `rate-limit { ... };` | all | Per-zone RRL block (replaces the server-wide one). |
| `ecs-tags { ... };`, `location-tags { ... };` | master, slave | Per-zone tag definitions. |
| `ecs-trusted-resolvers { ... };` | master, slave | Per-zone trusted ECS resolvers. |
| `primary-settings yes\|no;` | slave | `yes` (default): use the settings the primary sends with the zone (Extended AXFR version 3: `allow-transfer`, `transfer-acl-match`, `ecs-trusted-resolvers`, `additional-from-auth`, `zone-udp-bufsize`); a statement written in this `zone {}` still wins. `no`: ignore them. See "Secondary zones: Extended AXFR version 3 and the settings of the primary". |
| `additional-from-auth yes\|in-domain\|no;` | all | Per-zone override of the `options` value. |
| `disable-auto-tc-flag yes\|no;` | program | See PROGRAM ZONE PLUGINS. Any other value is an error. |
| `zone-tcp-mss`, `zone-tcp-window`, `zone-tcp-sndbuf`, `zone-udp-bufsize` | all | Per-zone transport settings; see TRANSPORT TUNING. |
| `alias-resolver { <addr> [port <n>]; ... };` | master, slave | The resolvers that expand the ALIAS records of this zone; replaces the `options` value. See POWERDNS ALIAS AND LUA RECORDS. |
| `forwarders { <addr> [port <n>]; ... };` | forward | Upstream servers; see FORWARD ZONES. |
| `forward-timeout <ms>;` | forward | Total time budget in milliseconds (default 2000), shared by the forwarders: each one gets the remaining time divided by the number of forwarders not tried yet. |
| `program "<path>";`, `program-args { "<arg>"; ... };`, `program-user "<user>";`, `program-timeout <ms>;`, `program-max-failures <n>;` | program | See PROGRAM ZONE PLUGINS. |

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

### Secondary zones: Extended AXFR version 3 and the settings of the primary (milestone B8t-2)

Between two KariDNS servers the transfer carries more than the RRs (EDNS option 65153, see "Extended AXFR" in
`KariDNS_How_to_use_ECS_and_location.md`). Version 3 adds two things, both in private-use records of CLASS 65302 (RFC 6895 §3).

**Versions.** The secondary asks for version 3. A primary answers version 2 and 3 with a stream of the version asked; a version 2
secondary of a version 3 primary therefore keeps working (it is refused only for a zone with several or restricted SOA records,
see "Several SOA records"), and a version 3 secondary of a version 2 primary keeps its tags and tinydns attributes: a version 2 primary does not know
version 3 and answers a standard transfer, so the secondary stops that transfer at its first message (nothing is installed), asks again
with version 2 and uses the version 2 stream (no `SOA_SET`, no settings). It remembers per zone, in memory, that the primary speaks
version 2 and asks for version 2 directly from then on; after 6 hours (`XFR_EXT_REPROBE_SECS`) it asks for version 3 again, so an
upgraded primary is found. A primary that answers a standard transfer to version 2 as well (not KariDNS) costs one extra request and
is then remembered the same way (version 3 asked, a standard answer accepted at once, re-probed after 6 hours). Upgrading the secondaries
first therefore does not degrade service. Any other version, or a request without the option, is a standard transfer. A version 3 stream of a plain zone (one unrestricted SOA) differs from the
version 2 stream by the version in the OPT, the settings record, and by sending the trusted resolvers of the *configuration* in the
settings instead of as `ECS_TRUSTED` (65407); the zone data is the same.

**The SOA set.** For a zone with several or restricted apex SOA records (see "Several SOA records") the stream is: the reference
SOA (frame), `SOA_SET` (65409: flags, number of apex SOA records), `SETTINGS`, the definitions, then every record in file order
with each apex SOA as a TINYDNS_WRAP (65406) record that carries its attributes (and the `LOC_STATE` / `ECS_STATE` records of its
tags), the resetting state records, the frame. The secondary does not store the frame as data, takes its serial and timers from it,
and ends up with exactly the SOA set of the primary; a stream that announces another number of SOA records, has a SOA of another
serial or not at the apex, or puts `SOA_SET` anywhere but right after the opening SOA is refused. A change of the SOA set or of a
SOA attribute reaches a secondary with a full transfer (an IXFR request is answered with an AXFR for such a zone, and also when an
earlier version of it had a SOA set).

**The settings of the primary.** The primary sends one `SETTINGS` record (65408): the zone's effective settings as text in the
syntax of a `zone {}` block, the statements of the restricted parser of "Settings of database zones". The statements sent, each
with the value the primary applies (the zone's own, else `options`'):

| Statement | Sent when |
|---|---|
| `allow-transfer { <addresses> key "<name>"; ... };` and `transfer-acl-match` | the zone has an `allow-transfer` (or a `tsig-key`, which on a primary may also transfer): the addresses (with their `!`), the key *names* |
| `ecs-trusted-resolvers { ... };` | the zone or `options` has the list and the zone's own data has none |
| `additional-from-auth`, `zone-udp-bufsize` | the zone or `options` sets them |

Only the zone's own `allow-transfer` is sent: the one of its view or of `options` is not (the secondary has its own). A zone's list that has a negated key (`!key "k"`) is sent as `allow-transfer { none; };`, because the flat form cannot say it. Never sent: `acl-ceiling`, TSIG secrets (only key names), `masters`, `also-notify`, `allow-update`, `allow-query` or any other server-level policy.
The ACLs of a *database* zone are cut at the primary's `acl-ceiling` before they are sent: an address or prefix that is not
entirely inside the ceiling and a key that the ceiling does not name are left out, and a database zone's ACL without a configured
ceiling is sent as `none` (the secondary must never get a wider list than the primary applies). A text longer than 32,768 octets is
not sent (logged). The same record is sent in an IXFR (right after the opening SOA) and in an AXFR, and a secondary that serves
the zone to others sends the settings in force on it. The tag definitions of the configuration (`location-tags` / `ecs-tags` of the
zone, else `options`) that the records of the zone use are sent as tag definitions (65403 / 65404) when the zone data defines no
tags of its own; the secondary then resolves tags as the primary does and needs no `location-tags` of its own for the zone.

**On the secondary.** The text is parsed with the restricted parser (`file`, `type`, `include`, unknown statements are errors; a
text that does not parse is dropped with a warning), and merged with the zone as the secondary has it:
**a statement written in the secondary's own `zone {}` > the received statement > the secondary's `options`**. Statements the
secondary does not take from the primary (`masters`, `tsig-key`, `also-notify`, ...) are parsed and ignored. A TSIG key name in
the received `allow-transfer` is valid only if the secondary defines that key; otherwise that ACL fails closed (`none`, logged and
shown by `zonestatus`) while the rest of the settings apply. `primary-settings no;` in the zone ignores the received settings
altogether. The received settings are replaced by every successful transfer (a transfer without a `SETTINGS` record clears them), are
kept when a refresh fails or the primary is down, follow a changed `karidns.conf` (the secondary's own statements are re-read), and
live in memory only, like the data; a catalog member zone and a database secondary use them in the same way (for a database zone
the settings of its database row take the place of the `zone {}` block). `karictl zonestatus` shows `settings=primary` while
received settings are in force. A change of the settings alone (no new serial) reaches the secondary with its next transfer.

> [!WARNING]
> Over an unsigned transfer a path attacker (or anybody who can answer instead of the primary) can change the ACLs of the
> secondary: widen `allow-transfer`, add a trusted ECS resolver. Sign the transfer with a TSIG key (`tsig-key` in the secondary's
> zone, `allow-transfer { key ...; }` on the primary) whenever the settings are accepted, or write the statements that matter in the
> secondary's own `zone {}` (they win) or set `primary-settings no;`.

### Forward and program zones: not applied upstream

The TCP connection a `type forward;` zone opens to its forwarder (the fallback after a truncated UDP answer)
does not use `zone-tcp-*` / `tcp-mss` / `tcp-window`; it keeps the OS defaults. The right values for that
connection depend on the forwarder and the path to it, not on the zone's settings. A `type program;` zone
talks to its program over a pipe, so there is no TCP connection to tune. In both cases the settings still
apply to the client's connection to KariDNS, like for any other zone.

Per-zone UDP *socket* buffers are not possible: all zones share the same UDP sockets. The server-wide
`udp-recvbuf-size` / `udp-sndbuf-size` stay the knobs for those. What can be set per zone on UDP is the
EDNS payload size (`zone-udp-bufsize`). Values above 1232 risk IP fragmentation on paths with a smaller
MTU (this is the reason for the DNS Flag Day 2020 default); lower values push more answers to TCP.

---

## CONTROL CHANNEL & MANAGEMENT

Runtime administration of `karidns` is managed over a local UNIX domain socket (default `/var/run/karidns/control.sock`, see `control-channel`) authenticated via an HMAC challenge-response (`control-channel { algorithm }`, default HMAC-SHA256) using the [`karictl(8)`](karictl.md) utility.

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
    program-max-failures 5; # consecutive failures before the circuit breaker opens (default: 5)
    program-user "nobody"; # optional privilege drop for plugin process (default: options { user })
    disable-auto-tc-flag no; # yes: send oversized UDP replies as-is (default: no)
};
```

> [!NOTE]
> **Design Boundaries and Processing Semantics:**
> - **Pre-filtering & Packet Validation**: KariDNS enforces standard basic DNS header validation (QDCOUNT, valid OPCODES, EDNS version <= 0, valid QCLASS) prior to dispatching queries to the program plugin. Corrupted queries that violate fundamental DNS framing are responded to directly by KariDNS (e.g. FORMERR / NOTIMP / REFUSED) before reaching the plugin.
> - **UDP Truncation (`disable-auto-tc-flag`)**: With the default `no`, a plugin reply larger than the UDP limit (EDNS UDP payload size, capped by the server's UDP buffer size; 512 without EDNS) is replaced by a TC=1 reply with an empty answer. With `yes`, KariDNS sends the plugin reply as-is (up to 65,535 bytes), so the plugin itself is responsible for setting TC=1 on UDP.
> - **TCP & AXFR Semantics**: TCP queries (including `AXFR` / `IXFR`) sent to a program zone are forwarded directly to the plugin as a single query-response transaction. Multi-envelope streaming AXFR is not supported.
> - **Security & Isolation**: Plugin child processes are spawned prior to Capsicum capability mode and drop privileges (`program-user`). All internal control channels, frontend IPC, and network sockets are strictly closed via `closefrom(3)` before executing the plugin. The plugin starts with an empty environment (only `TZ` of the server is kept). A `program-user` that resolves to uid 0 or whose primary group is gid 0 is refused (by `karicheck conf` and at start; the plugins are started at startup).
> - **Reload**: Plugin processes are started only at server startup. A program zone added by a reload returns SERVFAIL until the next restart, and changes to `program`, `program-args`, `program-user`, `program-timeout` or `program-max-failures` are logged but take effect only after a restart.
>
> For full architectural details, IPC wire specifications, and complete runnable examples in Perl, Python, C, Rust, and Go, see **[KariDNS: Complete Guide to 'type program' Zones](KariDNS_how_to_use_type_program_zone.md)**.

---

## FORWARD ZONES

KariDNS supports forwarding queries for specific zones to designated upstream nameservers (`type forward;`).

```
zone "corp.example.com." {
    type forward;
    forwarders { 192.0.2.53; 198.51.100.53 port 5353; };
    forward-timeout 2000; # total time budget in milliseconds for all forwarders (default: 2000)
};
```

> [!NOTE]
> **Forward Zone Processing Semantics:**
> - **Transparent Query Relaying**: KariDNS does not maintain zone resource records locally for forward zones. Incoming queries matching the zone are forwarded to the configured `forwarders` list in order, failing over to the next forwarder within the shared `forward-timeout` budget. Each forwarder gets the remaining time divided by the number of forwarders not tried yet (with two forwarders and the default 2000 ms: 1000 ms each, the second one also gets what the first one did not use). A reply whose ID, QR bit or question does not match is discarded and the wait for that forwarder continues (RFC 5452 §9.1). The fallback to TCP after a truncated reply, including its connection setup, uses the time that is still left.
> - **No Subprocess Overhead**: Unlike `type program` zones, forward zones do not spawn external processes and do not require global opt-in flags like `allow-program-zones`.
> - **Immediate Reload Support**: Changes to `forwarders` or `forward-timeout` take effect immediately upon configuration reload (`SIGHUP` / `karictl reload`) without requiring a full server restart.
> - **Unsupported Operations**: Dynamic Update (RFC 2136), Zone Transfer (`AXFR`/`IXFR`), and `NOTIFY` requests are not supported on forward zones and are rejected with `NOTIMP`.
> - **Security & Transaction ID Randomization**: When relaying to upstream forwarders, KariDNS assigns a fresh cryptographic random transaction ID (`arc4random`) and verifies that the upstream response Question section and ID match before relaying the answer with the client's original transaction ID restored.

---

## POWERDNS ALIAS AND LUA RECORDS (milestone B9a)

KariDNS reads, serves and transfers the two record types that PowerDNS adds to the DNS: **ALIAS** (a name that stands for the addresses of another name, the "ANAME" idea) and **LUA** (a record whose answer is the result of a Lua snippet). They are not IETF types. PowerDNS stores them as private-use types of CLASS IN and sends them like that in a zone transfer (RFC 6895 §3.1): ALIAS is **TYPE65401** (RDATA = the target name, uncompressed, RFC 3597 §4) and LUA is **TYPE65402** (RDATA = the 16-bit type of the answer, then the code as `<character-string>`s). KariDNS keeps exactly that form, so an AXFR out is byte for byte what PowerDNS sends (`outgoing-axfr-expand-alias=no`), and a zone transferred in from PowerDNS keeps its ALIAS and LUA records.

> [!NOTE]
> The Extended AXFR records of KariDNS use the same two type numbers (65401, 65402) in **CLASS 65302**. Everything that reads or writes a transfer tells them apart by the pair (type, class), never by the type alone: a record of CLASS IN is a zone record, whatever its type number; a record of CLASS 65302 is an Extended AXFR record, whatever it holds.

**Zone files.** `ALIAS <target>` and `LUA <type> "<code>" ["<more code>" ...]` are accepted next to the generic forms (`TYPE65401 \# 15 ...`, RFC 3597 §5). A relative target is relative to the origin. The code of a LUA record is cut into `<character-string>`s of at most 255 octets, as PowerDNS does. In a PowerDNS database the rows are `type = ALIAS` with the target in `content` (`t.target.example.`) and `type = LUA` with `A ";return {'192.0.2.1'}"`. `tests/db/zone2sql` writes these rows.

```
@    300 IN ALIAS lb.target.example.      ; A / AAAA of the apex from another name (RFC 1034 §3.6.2 forbids a CNAME here)
www  300 IN ALIAS lb.target.example.
txt  300 IN LUA   TXT ";return 'hello'"   ; kept for transfers, never answered
```

**Zone rules** (a zone that breaks them is not loaded; `karicheck zone` and `karicheck zones` report them; a database zone that breaks them is rejected with the reason in the log and in `karictl dbstatus`; an incoming transfer that breaks them is refused):

- an ALIAS name must not also own an A or AAAA RRset (the ALIAS stands for them). TXT, MX, NS and the other types may coexist;
- a zone with an ALIAS must not hold DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM), and a database zone with `PRESIGNED` metadata must not hold an ALIAS: an expanded answer cannot be signed offline. KariDNS does no online signing;
- the RDATA of both types must be well formed (one uncompressed name; a type and `<character-string>`s that fill the RDATA);
- `ENABLE-LUA-RECORDS` metadata with the value `1` rejects the database zone (LUA records are not run, so enabling them would silently change the answers); `0` or no row is fine.

### Default behaviour (no `alias-resolver`)

This is PowerDNS with `expand-alias=no` and `enable-lua-records=no`, and the answers are the same (checked against PowerDNS 5.1.4, `tests/run_db_alias_lua_test.sh`):

| Query | Answer |
|---|---|
| A or AAAA (or any other type the name does not own) at an ALIAS name | NOERROR, no data |
| `TYPE65401` at an ALIAS name, and `ANY` there | the ALIAS RR (`ANY` lists it with the other RRsets) |
| ALIAS at a wildcard, a name below it | the ALIAS RR for `TYPE65401` and `ANY`, no data for A and AAAA (an ALIAS RR is a plain RR in this mode) |
| anything at a name that owns **only LUA** records, including `TYPE65402` and `ANY` | NXDOMAIN (as if the name did not exist; a wildcard that holds only LUA records is not there either) |
| `ANY` or `TYPE65402` at a name with LUA and other records | `ANY` lists the other RRsets only; `TYPE65402` gets no data |
| AXFR / IXFR, Extended AXFR | every ALIAS and LUA RR, as TYPE65401 / TYPE65402 |

A name that owns LUA records and descendants is an empty non-terminal like any other (NOERROR, no data).

### Expansion (`alias-resolver`)

```
options { alias-resolver { 192.0.2.53; 2001:db8::53 port 5353; }; };   # every zone
zone "example.test." { ...; alias-resolver { 192.0.2.54; }; };         # this zone only (replaces the options value)
```

`alias-resolver` names 1 to 8 resolvers (IP addresses, never names). A zone's list replaces the options list; for the zones of the database the order is the zone's settings text (or its profile), then `options { alias-resolver }`, then `options { database { alias-resolver } }`. It works for file zones, transferred zones and database zones alike. A statement may be written in the settings text of a database zone and in a profile (it is not sent with Extended AXFR: a resolver address is local to the server). A configuration reload takes effect at once.

With it, A and AAAA at an ALIAS name are answered with the addresses the resolver gives for the target, as PowerDNS does with `expand-alias=yes` and `resolver=...`:

| Query | Answer |
|---|---|
| A, AAAA | the addresses of the target (the CNAME chain of the resolver's answer is followed, at most 8 hops); NOERROR with no data when the target has none |
| `ANY` | the expanded A and AAAA only (PowerDNS answers `ANY` at an ALIAS name with these two and leaves the other RRsets out) |
| `TYPE65401` | no data: the ALIAS RR is not an answer any more (AXFR still carries it) |
| a target that cannot be resolved: the resolver does not answer, or answers SERVFAIL, REFUSED or NXDOMAIN, a CNAME loop or a chain longer than 8 | SERVFAIL (with EDE 22 when the client sent EDNS and `send-extended-errors` is on) |
| a wildcard ALIAS | not expanded (as in PowerDNS 5.1.4): no data for A and AAAA, the ALIAS RR for `ANY` |
| the glue of an MX / NS / SRV target that is an ALIAS name | none |

**How it is done.** The Backend never waits for a resolver. One auxiliary thread resolves every ALIAS target of the published zones in advance, through the same broker path as the forwarders of a `type forward` zone and the transfers of a secondary (no socket call is added to the sandboxed Backend): a UDP query with RD=1 and EDNS0, TCP when the answer is truncated; the answer must come back on the connected socket with the right ID and the question asked, and RCODE NOERROR (RFC 5452 §9.1). The thread publishes the results as one immutable table that queries only read (the table is replaced and the old one freed after a grace period, like zone versions). Answers that carry expanded addresses are never put into the shared response cache. The resolver is trusted: nothing is DNSSEC-validated.

- **TTL.** The TTL of an expanded answer is the smaller of the ALIAS record's TTL and what is left of the TTL of the resolver's answer (the TTL of the final A / AAAA RRset, as PowerDNS takes it; CNAME TTLs are not mixed in), counting down, so a downstream cache never keeps the data longer than the resolver allowed. (PowerDNS gives the upstream TTL as it is, without the ALIAS record's TTL and without counting down.)
- **Refresh.** A target is queried again after two thirds of its TTL and at least 5 seconds after the last time (an upstream TTL of 0 gives a 5 second refresh and TTL 0 answers). A new zone version keeps the results of the targets it still has; a target that no zone has any more is dropped.
- **Failure.** A target that has **never** been resolved (a zone that was just loaded, or a resolver that is down since the start) answers SERVFAIL until the first resolution works; PowerDNS resolves at the first query, so the first answers after a load may be SERVFAIL where PowerDNS would wait. A target that **was** resolved keeps its last result when a refresh fails: it is served for up to one day after its TTL ran out, with TTL 30 (RFC 8767 §4, §5; the answer is the last known data, not an error), and the refresh is retried in the background after 5 s, 10 s, 20 s ... up to 320 s. After a day without a success the target answers SERVFAIL. A resolver set that does not answer at all is left alone for 10 s between tries.
- **Bounds.** At most 1,024 ALIAS records per zone are looked at (the rest answer SERVFAIL, logged), 16,384 jobs in all (a target is two jobs: A and AAAA), 32 addresses per type, 64 different resolver lists, 20 upstream queries per 200 ms tick (about 100 per second) and 3 s for one resolution. The results are about 100 octets each.
- **Logs.** The first failure of a target and its recovery are logged once (`[Alias] ...` in syslog).

Differences from PowerDNS, on purpose: the TTL rule above; the stale answers and the "never resolved" SERVFAIL window; the SOA record that every NODATA answer carries (RFC 2308 §2.2; PowerDNS 5.1.4 sends none with the NODATA of an expansion); a truncated answer of the resolver is retried over TCP (PowerDNS 5.1.4 takes it for an answer without data); an ALIAS beside A / AAAA and an ALIAS in a signed zone are zone errors; `ENABLE-LUA-RECORDS=1` is refused. LUA records themselves are **not** run: this release implements what PowerDNS does with `enable-lua-records=no` (design decision D13).

> [!NOTE]
> Dynamic Update (RFC 2136) works on zones that hold ALIAS records, but an update that would put an A or AAAA RR at an ALIAS name is refused with the rest of the zone check (SERVFAIL), and the "name is in use" prerequisite counts a name that holds only LUA records as in use although queries get NXDOMAIN.

> [!NOTE]
> Several servers that share one PostgreSQL database answer the A and AAAA queries at an ALIAS name from their own resolver and at their own moment, so those answers can differ between the servers (zone transfers and SOA serials do not); LUA records are never run and so are the same. See "Several servers as primaries" under the PostgreSQL driver, and `karicheck conf`, which warns about `server-id` together with `alias-resolver`.

---

## ZONE FILE FORMAT

The default `file-format` is the master file format of RFC 1035 §5 as BIND reads it.

- **Records**: `<owner> [<TTL>] [<class>] <type> <RDATA>`; TTL and class may appear in either order, each once.
  PowerDNS's `ALIAS <target>` and `LUA <type> "<code>"` are accepted too (see POWERDNS ALIAS AND LUA RECORDS).
  Type and class mnemonics are case-insensitive (`in a`, `IN Mx`). Unknown types and classes use the RFC 3597
  forms `TYPEnn`, `CLASSnn` and `\# <length> <hex>`. The generic form of a type the server knows must carry RDATA
  that is valid for that type (RFC 3597 §5): `PTR \# 0`, `NS \# 3 010203` or a compressed name in the hex are
  zone file errors, reported by `karicheck zone` at the record's line. Zero-length RDATA is legal for a type
  without a defined format (`TYPE65534 \# 0`) and is transferred (AXFR/IXFR) and served like any other record.
- **Case of names**: owner names and the domain names inside RDATA are answered and transferred with the letters as
  written (RFC 4343 §4.1), for every type, from a zone file and from a database alike. The only exception is name
  compression (types NS, CNAME, PTR, MX, SOA, MINFO and the owner): a name that is compressed against an earlier name of the
  same message that differs only in case shows the case of the earlier one, as RFC 4343 §4.1 allows. The lower-case form
  of RFC 4034 §6.2 is used only where DNSSEC needs the canonical form (ZONEMD digests, UPDATE and IXFR comparisons,
  `karicheck`).
- **Classes**: `IN` (the default when the class is omitted), `CH`, `HS` and `CLASSnn` are kept with the record. The
  server answers queries of class IN and CH; records of other classes are loaded but not answered (queries of
  those classes are REFUSED). `NONE`, `ANY`, `CLASS0` and class 65302 (used internally by KariDNS) are errors.
- **Omitted TTL** (same order as BIND): the TTL on the record; else `$TTL` (RFC 2308 §4); else the last TTL
  written explicitly on a record (RFC 1035 §5.1, also across `$INCLUDE`); else, for an SOA record, its MINIMUM
  field, which then acts like `$TTL`; else 3600. BIND rejects such a zone ("no TTL specified"); here the zone loads, the server logs a warning with the number of records that got 3600, and `karicheck zone` / `karicheck conf` warn.
- **TTL notation** (BIND 9.20 ARM 3.5.3 and 3.5.5.4: "Valid TTLs are of the range 0-2147483647 seconds"): digits with `s`, `m`, `h`, `d`, `w` units in any letter case, e.g. `3600`, `1h30m`, `1w2d`; as in BIND (lib/dns/ttl.c `bind_ttl()`) a number without a unit is accepted only on its own (`30`), not after a unit (`1h30` is an error), and the text may be at most 63 characters long. A `$TTL` or record TTL that is not in that notation (`1x`, `abc`, a sign, `1h-5`) or above 2147483647 is a zone file error at that position, as is a `$TTL` without a value. It used to be read as 3600 without a word. The SOA refresh, retry, expire and minimum fields use the same notation (up to 4294967295) and are errors when malformed. **The SOA serial** must be a plain decimal number 0-4294967295 (leading zeros allowed): BIND 9.20 reads it as a number token (lib/dns/rdata/generic/soa_6.c `fromtext_soa()`, lib/isc/lex.c, lib/isc/parseint.c) and rejects the zone for a sign, a unit, a hex prefix, an empty value or a value above 32 bits; here such a serial is a zone file error (`Invalid SOA serial ...` / `SOA serial out of range ...`) at its position, also in the `Z` line of a tinydns data file (an empty tinydns serial still means the time stamp of the data file). It used to be read as 0 or cut to 32 bits. A TTL above 2147483647 in a transferred or database record is still served as 2147483647 (RFC 8767 §4).
- **`$ORIGIN <name>`** and the origin argument of **`$INCLUDE <file> [<origin>]`**: a name without a trailing dot
  is relative to the current origin (RFC 1035 §5.1). `$INCLUDE` does not change the origin of the including file.
- **`$INCLUDE` paths** (BIND 9.20 ARM 3.5.5.3: "The filename can be an absolute path, or a relative path"): a relative name is read from `options { directory }` when it is set (BIND: named's working directory), otherwise from the directory of the zone file. The server reads files in capability mode and can open only directories that it opened when it started, so the file must lie inside one of two trees: the directory of the zone file, or `directory`. An absolute path, or a path that leaves the base through `..`, is accepted only when the normalized path (no symbolic link is looked at) stays inside one of those trees; any other is a zone file error, for example `$INCLUDE '/etc/hosts' is outside the directories opened at startup (zone file dir, directory): the sandboxed server can read only below them`. `karicheck zone` applies the same rules and gives the same message. A reload may bring in a file in a sub-directory that did not exist at start-up, as long as it is below one of those trees.
- **`$GENERATE <range> <lhs> [<TTL>] [<class>] <type> <rhs>`** (BIND syntax): `<range>` is `start-stop[/step]`
  (at most 100,000 records). For each value, `$` in `<lhs>` and `<rhs>` is replaced by the value,
  `${offset[,width[,base]]}` with base `d`, `o`, `x`, `X`, `n` or `N` (`n`/`N`: nibbles in reverse order separated
  by dots, as for `ip6.arpa`; the width counts the dots), `$$` gives `$` and `\$` a literal `$`. Any RR type can be
  generated; the resulting line is read like any other record line, so `$ECS-SUBNET`/`$LOCATION` tags and the TTL
  rules apply. `<rhs>` is one field: quote RDATA that contains spaces, e.g.
  `$GENERATE 1-10 host$ MX "10 mail$"`.

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
> - **Extensions** (not in djbdns 1.05). Empty numeric fields are 0; the
>   default TTL is 86400; `timestamp` and `lo` work as for the other types:
>   - `3fqdn:ip6:ttl:timestamp:lo`: AAAA. `ip6` is 32 hex digits without
>     colons (e.g. `20010db8000000000000000000000001`).
>   - `6fqdn:ip6:ttl:timestamp:lo`: AAAA plus PTR records under `ip6.arpa`
>     and `ip6.int`.
>   - `Sfqdn:ip:x:port:weight:priority:ttl:timestamp:lo`: SRV with target
>     `x` (a full name, no expansion), plus an A record for `x` when `ip`
>     is given.
>   - `Nfqdn:order:pref:flags:service:regexp:replacement:ttl:timestamp:lo`:
>     NAPTR. `flags`, `service` and `regexp` take the octal escapes of `:`
>     records.
>   - `_fqdn:algorithm:fptype:fingerprint:ttl:timestamp:lo`: SSHFP with a
>     hex fingerprint; a line whose fingerprint is not valid hex is skipped.
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
>   address with zero heap allocation on the hot path. As an extension,
>   `<prefix>` may end in `/n` (`/0`–`/32`) to give the prefix length in
>   bits, e.g. `%in:10.0.0.0/8`.

### Several SOA records, and a client that sees none (milestone B8t-1)

A zone can have one SOA record per client group: a `Z` line per location in a tinydns data file (the format allows it: `tinydns-data.c` stores the SOA like every record, with its location and time stamp), or `$LOCATION` / `$ECS-SUBNET`-tagged SOA records in a zone file. Several SOA records that every client sees stay an error (`karicheck`). The rules, for a zone file and for a database zone alike:

- **One serial.** All SOA records of the zone have the same serial (RFC 2181 §6.1: one SOA per zone, so one zone serial). A zone that breaks this is not loaded: a reload logs `zone '...' not loaded from '...': the SOA records of zone '...' have different serials (...)` and the version in service stays; `karicheck` reports an error. A zone that holds DNSSEC records (RRSIG, DNSKEY, NSEC, NSEC3) cannot have several or restricted SOA records either: the signature of the SOA RRset would not hold for every client.
- **Reference SOA.** The SOA record without a location, time stamp or tag if there is one, else the first in file (row) order. Everything that is zone-wide comes from it: the serial (SOA queries of a secondary, NOTIFY, IXFR, the serial that Dynamic Update raises in all of them), refresh / retry / expire, and the EDNS EXPIRE value (RFC 7314).
- **Answers.** The SOA a client gets is the first SOA it can see, with the rules that decide the other records (its tinydns location, its `$LOCATION` / `$ECS-SUBNET` tag, the tinydns time stamp and countdown, as `tdlookup.c` does). A query for the SOA (or ANY) at the apex gets that one SOA only. NXDOMAIN and NODATA carry it in the authority section (RFC 2308 §3) and its MINIMUM is the negative TTL (RFC 2308 §5).
- **A client that sees no SOA** of the zone, whether or not it sees an NS record, gets **REFUSED with AA=0 and Extended DNS Error 18 (Prohibited, RFC 8914 §4.19)**, for every name and type of the zone and for a zone transfer. This is the answer of BIND 9.20 to a client a zone is not served to (no matching view, `allow-query` denial); `tdlookup.c` differs: with a visible NS it answers a referral without AA, and with nothing visible it sends no response. The zone is treated as not served to that client: the closest zone decides, there is no fall back to the answer of a parent zone (a parent's referral to the child is not shown), and a CNAME chain that leads into such a zone ends at the CNAME.
- **Standard AXFR and IXFR** (a request without the KariDNS extension, e.g. from BIND, NSD or `dig`) of a zone with per-client records is the zone **as the requester sees it now**, as `axfrdns.c` builds it: the RRs the requester's address does not match (tinydns location, `$LOCATION` tag) or that are not active (time stamp) are not sent, a record with a countdown TTL is sent with TTL 2, no location, tag or time stamp is sent, an `$ECS-SUBNET`-tagged RR is not sent (a transfer has no client subnet), the opening and closing SOA is the first SOA the requester sees, and a requester that sees none is refused (REFUSED, AA=0, EDE 18). Every other SOA record is left out of the body. A zone without such RRs is transferred as before. (Before this release a standard transfer left out every restricted RR, and it kept all SOA records.) An IXFR of such a zone is answered with the whole zone, as RFC 1995 §4 allows, unless the requester is up to date (then one SOA).
- **Extended AXFR of such a zone (milestone B8t-2)** is the whole zone, for a KariDNS secondary that speaks version 3 (see "Secondary zones: Extended AXFR version 3 and the settings of the primary"): the frame is the reference SOA, every SOA record travels in the body with its attributes, and the secondary ends up with exactly the SOA set of the primary and answers each client as the primary does. A secondary of version 2 is refused (REFUSED with a text): sending it the reference SOA alone would show a hidden SOA to everybody. A KariDNS secondary outside every SOA's location can still refresh: the extension makes the primary answer with the reference SOA whatever the requester's address is (a SOA or IXFR question that carries the extension option for the zone gets it too).
- **TTLs of an RRset (milestone B8t-2).** The TTLs of the RRs of one name and type are brought to the lowest one (RFC 2181 §5.2) only among RRs that are seen by the same clients: no location / tag / time stamp, or the same. An RR that only some clients see keeps the TTL it was written with, also when an RR that everybody sees has the same name and type: a client that sees both gets an RRset whose RRs have different TTLs, as it does from tinydns (`+www:192.0.2.1:300` and `+www:192.0.2.2:60::in`). `karicheck` warns for that case (an unrestricted and a restricted RR of one name and type with different TTLs). A zone without such RRs is unchanged. The rule is the same for zone files, database zones and zones received from a primary.
- **Cache.** A zone with restricted RRs is never served from the response cache, so the answer cannot be shared between clients.

The reference run against djbdns 1.05 (`tests/run_tinydns_soa_location_test.sh` with `DJBDNS_DIR`) shows the same SOA for each location, the same NXDOMAIN and the same transfer records; the difference is the client that sees no SOA (above).

---

## CLIENT GEOLOCATION & SUBNET STEERING (ECS & LOCATION)

KariDNS provides high-performance, record-level split-horizon response steering across both BIND and tinydns zone formats:

- **BIND Zone `$LOCATION` & `$LOCATION-TAG`**: Steers responses based on the querying client's immediate socket IP address (IPv4 and IPv6). Tags can be defined directly in zone files (`$LOCATION-TAG <tag> <cidrs>`) or in `karidns.conf` (`location-tags`).
- **BIND Zone `$ECS-SUBNET` & `$ECS-SUBNET-TAG`**: Steers responses based on EDNS0 Client Subnet (ECS, RFC 7871) options supplied by trusted recursive resolvers (`ecs-enable yes;` and `ecs-trusted-resolvers`). Tags can be defined in zone files (`$ECS-SUBNET-TAG`) or in `karidns.conf` (`ecs-tags`).
- **tinydns `location` (`%`)**: Steers responses based on client IPv4 longest-prefix matching declared with `%<loc>:<prefix>` lines and trailing `:loc` record tags.
- **Several SOA records per zone (B8t-1)**: a SOA can carry a tinydns location or time stamp, or a `$LOCATION` / `$ECS-SUBNET` tag; a client gets the first SOA it sees, and a client that sees none is refused. See "Several SOA records, and a client that sees none" in the tinydns section.
- **TTLs of records that only some clients see (B8t-2)**: the lowest-TTL rule for an RRset (RFC 2181 §5.2) applies only among records with the same location, tag and time stamp; a record with a location, tag or time stamp keeps the TTL it was written with, also beside a record for everybody. `karicheck` warns when the two have different TTLs. See "Several SOA records, and a client that sees none".
- **KariDNS Extended AXFR (Option 65153)**: Replicates zone directives, tags, the SOA set and (version 3) the primary's zone settings across KariDNS primary and secondary servers, while providing a standard AXFR fallback (Plan B) for non-KariDNS clients: the zone as the requester sees it. See "Secondary zones: Extended AXFR version 3 and the settings of the primary".

For complete configuration syntax, query evaluation flows, and Extended AXFR details, see **[KariDNS: Client Geolocation & Subnet Steering Guide](KariDNS_How_to_use_ECS_and_location.md)**.

---

## EXIT STATUS

`0`
: `-v` / `--version`, or the server was stopped (`SIGTERM`, `SIGINT`, `karictl stop`).

`1`
: The server did not start or stopped on an error: the configuration file cannot be read or has errors, a port, log file, PID file or control socket cannot be opened, or the server could not carry on.

`2`
: Usage error: no configuration file was given, or the value of `-p` is a number outside 1-65535. The usage text goes to standard error (and syslog); nothing was started. The tools `karicheck`, `karictl` and `karidns-dbloader` use 2 for usage errors in the same way; `dag` follows `dig` instead.

---

## SIGNALS

`SIGHUP`
: Same as `karictl reconfig`: re-reads the configuration file and swaps it in atomically (RCU). Zone files whose modification time and size have not changed since they were loaded are not re-read; use `karictl reload` to re-read all zone files. Send it to the manager process (the PID in the PID file); the manager forwards it to the backend. When it reaches every process (`pkill -HUP karidns`), the server still reloads once: the backend acts only on the manager's forward, and a `SIGHUP` sent to the backend process alone is logged and ignored.

`SIGTERM`, `SIGINT`
: Sent to the manager process, stops all child processes (backend, frontend routers, connect broker), removes the PID file and exits. A child that has not ended 10 seconds after the SIGTERM it was sent is killed with SIGKILL (logged); a second `SIGTERM` or `SIGINT` to the manager kills the remaining children at once. The exit status is then non-zero.

---

## FILES

`/usr/local/etc/karidns/karidns.conf`
: Configuration file used by the FreeBSD `rc.d` script (`karidns_config`). The package installs `karidns.conf.sample` next to it.

`/var/run/karidns/control.sock`
: Default UNIX domain socket for control communication with `karictl`.

`/var/run/karidns/karidns.pid`
: Default process ID file when daemonized.

`/usr/local/libexec/karidns-dbloader`
: The database loader (the packages `karidns-sqlite3`, `karidns-postgresql` and `karidns-db`; the default `loader-path`).

`/usr/local/share/karidns/db/`
: The SQL files for the databases (`karidns_ext.*.sql`, `karidns_ext_v1_to_v2.*.sql`, `karidns_loader_role.pgsql.sql`); `db/` in a source tree. See [`karidns-dbloader(8)`](karidns-dbloader.md).

`/usr/local/share/doc/karidns/`
: These manuals (`karidns.md`, `karictl.md`, `karicheck.md`, `dag.md`, `dag_replay.md` and, with the loader, `karidns-dbloader.md`).

---

## SEE ALSO

- [`karictl(8)`](karictl.md) — KariDNS server management and control utility
- [`karicheck(1)`](karicheck.md) — Configuration and zone file validation utility
- [`karidns-dbloader(8)`](karidns-dbloader.md) — The database loader: drivers, SQL files, privileges, packages, measurements
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS 'type program' Zone Guide`](KariDNS_how_to_use_type_program_zone.md) — Complete guide to external dynamic program zone plugins (IPC specs, Perl/Python/C/Rust/Go implementations)
- [`KariDNS Client Geolocation & Subnet Steering Guide`](KariDNS_How_to_use_ECS_and_location.md) — Comprehensive guide for BIND $LOCATION, $ECS-SUBNET, tinydns location, and Extended AXFR
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                    KARIDNS(8)
```

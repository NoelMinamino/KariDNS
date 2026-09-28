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
   - **Manager (Supervisor) Process**: The process started by the administrator. It parses the configuration, performs the startup checks, forks the other processes and supervises them: if any child exits, all children are stopped. `SIGHUP` is forwarded to the backend.
   - **Frontend Router Processes**: Bind the privileged network sockets (UDP/TCP port 53) and dispatch network traffic to the backend workers. One router is started on hosts with up to 3 CPU cores, two on larger hosts.
   - **Backend Process**: Operates in FreeBSD Capsicum capability mode (`cap_enter(2)`). DNS packet parsing and response generation are performed by the worker threads (one or two on hosts with up to 3 cores, otherwise the number of cores minus two) without direct filesystem access or socket creation permissions. Configuration and zone files are accessed via pre-opened directory descriptors (`openat(2)` / `renameat(2)`).
   - **Connect Broker**: A small unprivileged helper that opens the outbound TCP connections the sandboxed backend cannot create itself (for example zone transfers of secondary zones from their primary).
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
: Path to the configuration file (e.g., `/usr/local/etc/karidns/karidns.conf`). This argument is required; there is no built-in default path. Any argument that is not one of the options below is taken as the configuration file.

`-f`
: Run in the foreground instead of daemonizing into the background. In foreground mode, no PID file is created unless one is set explicitly (`-P`, `-p <path>` or `pid-file`).

`-p port`, `-p pid_file`
: The meaning depends on the value. If it starts with a digit, it is the **listen port** and overrides `options { port ...; }` (also on reload); for example `-p 10053`. Otherwise it is the path of the PID lock file, like `-P`.

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
- `include "file";` may appear anywhere and inserts the file in place. Relative paths are resolved against the directory of the file that contains the `include`. Includes can be nested up to 16 levels deep; circular includes are rejected.
- Boolean values accept `yes` / `true` and `no` / `false`. For the `rate-limit` and `dnstap` flags, `1` is accepted as true as well, and any other value means false.
- Zone names are normalized to their fully qualified form (a trailing `.` is added), so `"example.com"` and `"example.com."` are the same zone. A class after the zone name (`zone "example.com" IN { ... };`) is **not** accepted.
- Relative file paths (zone `file`, log `file`, `pid-file`, ...) are resolved against the working directory `karidns` was started from. Use absolute paths when starting from an rc script.
- Unknown statements and options are skipped silently (up to the next `;` at the same block level), so a misspelled option has no effect. Use [`karicheck conf`](karicheck.md) to validate a configuration.
- Settings that are fixed when the server starts (`port`, `bind-address`, `user`, `group`, `pid-file`, `udp-recvbuf-size`, `udp-sndbuf-size`, `tcp-window`, the `control-channel` socket path, `dnstap`, the `type program` zone processes) need a restart; a reload (`SIGHUP`, `karictl reload` / `reconfig`) applies everything else.

### Top-level statements

| Statement | Description |
|---|---|
| `options { ... };` | Server-wide options (below). |
| `zone "<name>" { ... };` | A zone. Top-level zones and `view` blocks cannot be mixed in one configuration. |
| `view "<name>" { ... };` | A view containing `match-clients` and `zone` blocks. |
| `key "<name>" { ... };` | A TSIG key. |
| `control-channel { ... };` | Enables the [`karictl(8)`](karictl.md) control socket. |
| `logging { ... };` | Log channels and categories. |
| `dnstap { ... };` | dnstap output (same block as inside `options`). |
| `include "<file>";` | Includes another file. |

Duplicate zones (in the same view or at top level), duplicate views and duplicate keys (names compared case-insensitively) are rejected.

### `options { ... }`

| Option | Default | Description |
|---|---|---|
| `port <n>;` | `53` | Listen port (UDP and TCP), 1–65535. An invalid value keeps the default. Overridden by `-p <port>`. |
| `bind-address { <addr>; ... };` or `bind-address <addr>;` | all addresses (`0.0.0.0` and `::`) | Addresses to listen on (IPv4 and IPv6). |
| `user "<name>";` | none | User to drop to after binding sockets. Required when started as root. |
| `group "<name>";` | the user's primary group | Group to drop to. |
| `pid-file "<path>";` | `/var/run/karidns/karidns.pid` when daemonized, none in foreground | PID lock file; `"none"` disables it. Overridden by `-P` / `-p <path>`. |
| `udp-recvbuf-size <size>;` | `4M` | `SO_RCVBUF` of the UDP sockets. Accepts a `K`/`M`/`G` suffix; an invalid value keeps the default. The kernel caps it at `kern.ipc.maxsockbuf`. |
| `udp-sndbuf-size <size>;` | `4M` | `SO_SNDBUF` of the UDP sockets (same syntax). |
| `tcp-mss <n>;` | not set (OS default) | 536–65495. See [TRANSPORT TUNING](#transport-tuning-tcp-mss--window-udp-payload-size). |
| `tcp-window <size>;` | not set (OS default) | 4K–64M, `K`/`M` suffix allowed. See TRANSPORT TUNING. |
| `udp-bufsize <n>;` | `1232` | 512–4096. Maximum UDP response size and the payload size advertised in the response OPT. See TRANSPORT TUNING. |
| `tcp-connection-reuse yes\|no;` | `no` | Keep TCP connections open for further queries (RFC 7766). |
| `tcp-idle-timeout <ms>;` | `10000` | Idle timeout of TCP connections in **milliseconds** (0 means the default). |
| `minimal-responses yes\|no;` | `no` | Do not add glue / additional-section records. |
| `minimal-any yes\|no;` | `no` | RFC 8482: answer `QTYPE=ANY` with a synthesized `HINFO "RFC8482" ""` record instead of all RRsets. When the query has DO=1 and the name has RRSIG records, a single RRset is returned instead (RFC 8482 §4.2). |
| `minimal-any-ttl <seconds>;` | `86400` | TTL of the synthesized RFC 8482 `HINFO` record. |
| `additional-from-auth yes\|in-domain\|no;` | `yes` | Whether additional-section data (glue, MX/SRV targets) is taken from the server's authoritative data. `in-domain` (alias `in-zone`) limits it to names inside the zone of the answer. Unknown values are treated as `yes` with a warning. Can be overridden per zone. |
| `send-extended-errors yes\|no;` | `yes` | Add Extended DNS Errors (EDE, RFC 8914) to responses of EDNS queries. |
| `serve-stale yes\|no;` | `yes` | When a secondary zone has expired (SOA EXPIRE passed since the last successful transfer), keep answering from the stale data. With `no` such queries get SERVFAIL with EDE 3. |
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
| `wire-cache-max-records <n>;` | `0` (no limit) | Zones with more records than this do not get the precomputed wire-format response cache. The cache is never built for tinydns zones or zones using location/ECS steering. |
| `query-log-max-qps <n>;` | `5000` | Maximum number of query log lines per second, shared by all worker threads (`0` means 5000). Queries over the limit are not logged. |
| `query-log-buffer-size <n>;` | `32768` | Entries in each worker's query log ring buffer; a power of two between 1024 and 1048576. When a ring is 80 % full, query logging is suspended to protect query processing. |
| `rate-limit { ... };` | not set (no RRL) | Response Rate Limiting (below). |
| `dnstap { ... };` | not set | dnstap output (below). |

### `rate-limit { ... }` (in `options` or `zone`)

A `rate-limit` block in a zone replaces the server-wide block for that zone. Rates are per client address and response class; `0` means no limit for that class.

| Option | Default | Description |
|---|---|---|
| `responses-per-second <n>;` | `0` | Limit for positive (NOERROR with data) responses. |
| `nodata-per-second <n>;` | value of `responses-per-second` | Limit for NODATA responses. |
| `nxdomains-per-second <n>;` | `0` | Limit for NXDOMAIN responses. |
| `errors-per-second <n>;` | `0` | Limit for error responses. |
| `window <seconds>;` | `15` | Accounting window (maximum 3600). |
| `slip <n>;` | `2` | Every *n*-th limited UDP response is sent truncated (TC=1) instead of being dropped; `0` drops all. |
| `log-only yes\|no;` | `no` | Only log what would be limited. |
| `early-drop yes\|no;` | `no` | For `type program` zones: drop UDP queries from clients whose budget is already exhausted before the query is passed to the program. |
| `exempt-clients { <addr/cidr>; ... };` | none | Clients that are never limited. |

Negative or non-numeric values are ignored with a warning; unknown keys are ignored with a warning.

### `dnstap { ... }` (top level or in `options`)

| Option | Default | Description |
|---|---|---|
| `socket "<path>";` (alias `socket-path`) | none | UNIX socket of the Frame Streams collector (e.g. `fstrm_capture`). The connection is made once at startup. |
| `identity "<string>";` | none | dnstap `identity` field. |
| `version "<string>";` | none | dnstap `version` field. |
| `queue-size <n>;` (alias `queue_size`) | `4096` | Entries in each worker's dnstap ring buffer (values below 64 use the default; rounded up to a power of two). |
| `require-connect yes\|no;` | `no` | Abort startup when the collector cannot be reached (otherwise dnstap is disabled with a warning). |
| `log-queries` / `auth-query`, `log-responses` / `auth-response` | `no` | Accepted for compatibility but currently have no effect: `AUTH_QUERY` and `AUTH_RESPONSE` messages are always both emitted. |

`karictl status` reports the number of truncated dnstap messages.

### `ecs-tags` / `location-tags`

```
ecs-tags {
    tag "eu-tier" { 198.51.100.0/24; 2001:db8:ee::/48; };
    tag "us-tier" { 203.0.113.0/24; };
};
```

The same syntax is used for `location-tags`. The blocks can be placed in `options` and in `zone`. For each zone, tags defined inside the zone file (`$ECS-SUBNET-TAG` / `$LOCATION-TAG`) take precedence, then the `zone` block, then `options`. Tags are checked in the order they are defined and the first tag with a matching CIDR wins. See the [Client Geolocation & Subnet Steering Guide](KariDNS_How_to_use_ECS_and_location.md).

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
| `file` | Log file. With `size`, the file is rotated when it would exceed the size: with `versions <n>` the old files are kept as `<path>.0` … `<path>.<n-1>`, without `versions` the file is truncated. With `suffix timestamp`, the file is also rotated daily and renamed to `<path>.YYYYMMDD`. |
| `print-time`, `print-category`, `print-severity` | Add the timestamp, category and severity to each line (default `no`). |
| `max-qps` | Per-channel override of `query-log-max-qps` for the `queries` category. |
| `category queries` | Query log. |
| `category responses` | Response log. |

Only the `queries` and `responses` categories exist; other categories are ignored with a warning. Each category uses one channel (the first name in the braces), and a category that names an undefined channel is an error. Other channel options (such as BIND's `severity`) are ignored. Operational messages go to syslog (facility `daemon`).

### `key "<name>" { ... }`

| Option | Description |
|---|---|
| `algorithm "<name>";` | `hmac-md5` (also `hmac-md5.sig-alg.reg.int`), `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. MD5 and SHA-1 are accepted with a deprecation warning (RFC 8945). When omitted, `hmac-sha256` is used. |
| `secret "<base64>";` | Shared secret. Invalid base64 is an error. |

Keys are referenced by `allow-transfer { key "<name>"; }`, `allow-update`, and `tsig-key`. A zone that references an undefined key in `tsig-key` or `allow-transfer` is an error. [`karictl tsig-keygen`](karictl.md) prints a new key block.

### `control-channel { ... }`

| Option | Default | Description |
|---|---|---|
| `socket "<path>";` (alias `socket-path`) | `/var/run/karidns/control.sock` | UNIX socket for `karictl`. |
| `secret "<base64>";` | none | Shared secret; must match `karictl.conf`. Authentication is an HMAC-SHA256 challenge-response. |
| `algorithm "<name>";` | — | Checked against the TSIG algorithm names above, but the control channel always uses HMAC-SHA256. |

### `view "<name>" { ... }`

| Item | Description |
|---|---|
| `match-clients { <acl>; ... };` | Clients that use this view. A view without `match-clients` matches every client. |
| `zone "<name>" { ... };` | Zones of this view. The same zone name may appear in several views. |

Views are checked in the order they are defined; the first match is used. A query from a client that matches no view is answered as if no zone matched (REFUSED). Without any `view` block, all top-level zones are placed in an implicit view that matches all clients.

### Address match lists (ACLs)

`allow-transfer`, `allow-update`, `match-clients` and `ecs-trusted-resolvers` take a list of entries evaluated in order; the first matching entry decides. An entry is an IPv4/IPv6 address, a CIDR prefix or `any`; a leading `!` (or a nested `! { ... };` block) negates it. A client that matches no entry is denied. In `allow-transfer` and `allow-update`, `key "<name>";` adds a TSIG key.

### `zone "<name>" { ... }`

| Option | Applies to | Description |
|---|---|---|
| `type <type>;` | all | `master` (alias `primary`, the default), `slave` (alias `secondary`), `forward`, or `program`. |
| `file "<path>";` | master, slave | Zone file. For a secondary zone, the transferred zone is written there. Ignored (with a warning) for `forward` and `program` zones. |
| `file-format bind\|tinydns;` | master | `bind` (default) or `tinydns` (djbdns `data` file). See TINYDNS ZONE FORMAT. |
| `masters { <addr> [port <n>]; ... };` | slave, catalog | Primary servers. NOTIFY is accepted from any listed address; the refresh and transfer use the **first** entry. Port default 53. |
| `tsig-key "<name>";` | slave, master | Key used to sign SOA/AXFR/IXFR requests to the primary. On a primary it is also accepted for incoming transfers. |
| `allow-transfer { <acl>; key "<name>"; ... };` | master, slave | Who may transfer the zone (AXFR/IXFR over TCP). **Without `allow-transfer` and `tsig-key`, transfers are refused.** If both addresses and keys are listed, a request must match an address **and** be signed with one of the keys. At most 4 transfers per zone run at the same time. |
| `also-notify { <addr> [port <n>]; ... };` | master | Additional servers that receive NOTIFY (RFC 1996) when the zone changes. NOTIFY is also sent to the addresses of the apex NS hosts, except the SOA MNAME host (RFC 1996 §3.2). |
| `notify-source "<addr>";` | master | Source address of outgoing NOTIFY messages. |
| `allow-update { <acl>; key "<name>"; ... };` | master | Enables Dynamic Update (RFC 2136) for matching clients or TSIG keys. Updates are kept in memory only. On a secondary zone, updates are rejected with NOTAUTH (a warning is printed at load time). |
| `catalog-zone yes;` | master, slave | Marks the zone as a catalog zone (RFC 9432, schema version 2: `version.<zone> TXT "2"` is required). Member zones listed under `zones.<zone>` are served as secondary zones that transfer from the catalog zone's first `masters` entry. |
| `rate-limit { ... };` | all | Per-zone RRL block (replaces the server-wide one). |
| `ecs-tags { ... };`, `location-tags { ... };` | master, slave | Per-zone tag definitions. |
| `ecs-trusted-resolvers { ... };` | master, slave | Per-zone trusted ECS resolvers. |
| `additional-from-auth yes\|in-domain\|no;` | all | Per-zone override of the `options` value. |
| `disable-auto-tc-flag yes\|no;` | program | See PROGRAM ZONE PLUGINS. Any other value is an error. |
| `zone-tcp-mss`, `zone-tcp-window`, `zone-tcp-sndbuf`, `zone-udp-bufsize` | all | Per-zone transport settings; see TRANSPORT TUNING. |
| `forwarders { <addr> [port <n>]; ... };` | forward | Upstream servers; see FORWARD ZONES. |
| `forward-timeout <ms>;` | forward | Total time budget in milliseconds (default 2000). |
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

Runtime administration of `karidns` is managed over a local UNIX domain socket (default `/var/run/karidns/control.sock`, see `control-channel`) authenticated via HMAC-SHA256 challenge-response using the [`karictl(8)`](karictl.md) utility.

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
> - **Security & Isolation**: Plugin child processes are spawned prior to Capsicum capability mode and drop privileges (`program-user`). All internal control channels, frontend IPC, and network sockets are strictly closed via `closefrom(3)` before executing the plugin.
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
> - **Transparent Query Relaying**: KariDNS does not maintain zone resource records locally for forward zones. Incoming queries matching the zone are forwarded to the configured `forwarders` list in order, failing over to the next forwarder within the shared `forward-timeout` budget.
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

- **BIND Zone `$LOCATION` & `$LOCATION-TAG`**: Steers responses based on the querying client's immediate socket IP address (IPv4 and IPv6). Tags can be defined directly in zone files (`$LOCATION-TAG <tag> <cidrs>`) or in `karidns.conf` (`location-tags`).
- **BIND Zone `$ECS-SUBNET` & `$ECS-SUBNET-TAG`**: Steers responses based on EDNS0 Client Subnet (ECS, RFC 7871) options supplied by trusted recursive resolvers (`ecs-enable yes;` and `ecs-trusted-resolvers`). Tags can be defined in zone files (`$ECS-SUBNET-TAG`) or in `karidns.conf` (`ecs-tags`).
- **tinydns `location` (`%`)**: Steers responses based on client IPv4 longest-prefix matching declared with `%<loc>:<prefix>` lines and trailing `:loc` record tags.
- **KariDNS Extended AXFR (Option 65153)**: Replicates zone directives and tags across KariDNS primary and secondary servers, while providing a clean standard AXFR fallback (Plan B) for non-KariDNS clients.

For complete configuration syntax, query evaluation flows, and Extended AXFR details, see **[KariDNS: Client Geolocation & Subnet Steering Guide](KariDNS_How_to_use_ECS_and_location.md)**.

---

## SIGNALS

`SIGHUP`
: Same as `karictl reconfig`: re-reads the configuration file and swaps it in atomically (RCU). Zone files whose modification time has not changed since they were loaded are not re-read; use `karictl reload` to re-read all zone files.

`SIGTERM`, `SIGINT`
: Sent to the manager process, stops all child processes (backend, frontend routers, connect broker), removes the PID file and exits.

---

## FILES

`/usr/local/etc/karidns/karidns.conf`
: Configuration file used by the FreeBSD `rc.d` script (`karidns_config`). The package installs `karidns.conf.sample` next to it.

`/var/run/karidns/control.sock`
: Default UNIX domain socket for control communication with `karictl`.

`/var/run/karidns/karidns.pid`
: Default process ID file when daemonized.

---

## SEE ALSO

- [`karictl(8)`](karictl.md) — KariDNS server management and control utility
- [`karicheck(1)`](karicheck.md) — Configuration and zone file validation utility
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

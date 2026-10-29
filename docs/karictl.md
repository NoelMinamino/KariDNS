# KARICTL(8) — KariDNS Reference Manual

```text
KARICTL(8)                     KariDNS Manual                     KARICTL(8)
```

---

## NAME

**karictl** — Remote Control and Management Utility for KariDNS

---

## SYNOPSIS

```sh
karictl [-c config_path | -f config_path] [-s socket_path] <command> [arguments...]
karictl -v | --version
karictl -h | --help
karictl tsig-keygen [keyname]
```

---

## DESCRIPTION

`karictl` is the management utility for the [`karidns(8)`](karidns.md) authoritative DNS server daemon. It communicates with the daemon over a local UNIX domain socket (default `/var/run/karidns/control.sock`) and authenticates each connection with an HMAC challenge-response handshake: the server sends a 64-character challenge, and `karictl` answers with the HMAC of the challenge keyed with the shared secret. The HMAC algorithm is `control-channel { algorithm }` on the server and `algorithm` in `karictl.conf` (both default to `hmac-sha256`).

---

## OPTIONS

`-c config_path`, `-f config_path`
: Path to the `karictl` configuration file (default: `/usr/local/etc/karidns/karictl.conf`; if that file does not exist and `/usr/local/etc/karictl.conf` does, the latter is used).

`-s socket_path`
: UNIX domain socket to connect to. Takes precedence over the `socket` setting of the configuration file (default: `/var/run/karidns/control.sock`).

`-v`, `--version`
: Display version information and exit.

`-h`, `--help`
: Print the command list with the `reload <zone> [view] [force]` syntax and examples, and exit.

---

## COMMANDS

Commands that take a zone name accept an optional view name as the next argument. The view name is required when the zone exists in more than one view; otherwise the command fails with `ERROR zone exists in multiple views; specify view`.

`status`
: Query and display runtime statistics from the running `karidns` daemon:
  - Version, host name, OS, architecture and kernel release and CPU count of the running server (taken when it started), and its worker thread count
  - Server boot time, time of the last successful (re)configuration (both to the second) and the configuration file path

  `karictl` and `karidns` must be the same version: the reply is a binary structure, and a reply of another size is shown as is and exits with status 3.
  - Number of zones and number of running AXFR/IXFR transfers
  - Whether query and response logging are enabled
  - Current and high-water TCP connection counts
  - Frontend process health status
  - Security counters: RRL dropped/slipped responses, Extended DNS Error counters (18 Prohibited, 20 Not Authoritative, 21 Not Supported, other) and truncated dnstap messages

`reload [zone [view] [force]]`
: Without arguments, re-read the configuration file and **all** zone files (see `reconfig` for the replies; a full reload also drops the changes of dynamic updates), then, when the configuration has a `database` block, ask the database loader to compare its databases with the zones served: the loader sends the zones that are new, whose serial differs, that the change log (`karidns_changes`, see `db/karidns_ext.*.sql`) lists as edited, or whose last version was refused, and a `ZONE_DELETE` for the zones that left the database. The reply does not wait for the loader: `OK reloaded; DB reload requested (request N)`; `karictl dbstatus` shows the batch when it is done. With a zone name, reload only that zone: a primary zone re-reads its zone file (errors such as a missing file, a parse error, a missing SOA or a running AXFR are reported), and a secondary zone starts a new transfer from its primary.
  A zone that is not in `karidns.conf` is looked up in the database. For a **database zone** the loader reads that zone only (also a zone just added to the database, which the server does not know yet). When several views take database zones and no view is named, the loader is asked about every one of them (a mapping in `karidns_domain_views` may have moved the zone) and the reply is one line, `<z>: view <v1>: <result>; view <v2>: <result>`, `OK` when at least one view has the zone and `ERROR` when it is rejected or failed there or when no view has it (`zone not found (it is not in the database of any view that takes database zones)`); a named view gives the single-view replies below, converts it, and sends it when its content differs from the version the server serves, whatever its serial; `force` sends it even when the content is the same. `karictl` waits for the loader's answer, but the server does not: the connection is parked and answered when the result arrives, or after `db-reload-timeout` seconds (`ERROR timeout: ...`; the reload may still be applied). At most 32 clients wait at once; the next ones get `ERROR too many reloads are waiting for the database loader; try again later`. Replies (all `OK` unless marked):
  - `OK zone <z> (view <v>): applied, serial <n>`: the new version is served.
  - `OK zone <z> (view <v>): unchanged, serial <n>`: the loader found the content equal to the served version.
  - `OK zone <z> (view <v>): loaded, serial <n>, but hidden by the zone in karidns.conf` (or `... by a catalog member of the same name`).
  - `OK zone <z> (view <v>): deleted (it is no longer in the database)`.
  - `ERROR zone <z> (view <v>): rejected: <reason>; the last good version, if any, keeps serving`: the server refused the zone.
  - `ERROR zone <z> (view <v>): failed: <reason>`: the loader could not read or convert the zone (a bad row, a missing SOA, an unreadable database); the last good version keeps serving.
  - `ERROR zone not found (...)`: the database does not have the zone (or the view does not exist).
  - several views, none named: `OK zone <z>: view a: not in the database; view b: applied, serial <n>`: the result of each view that takes database zones, in configuration order (`not in the database`, `applied, serial <n>`, `unchanged, serial <n>`, `deleted (...)`, `rejected: ...`, `failed: ...`).
  ```sh
  karictl reload                       # configuration, zone files, and a comparison of the databases
  karictl reload example.test          # one zone, from its file or from the database
  karictl reload example.test force    # send the database zone even if it is unchanged
  ```

`reconfig`
: Re-read the configuration file and apply it (added or removed zones, ACLs, rate limits, ...). Zone files whose modification time and size have not changed are not re-read. This is the same as sending `SIGHUP` to the server. When the `zone { }` blocks of every view are the ones of the running configuration, the zones served from the database are taken over as they are (a reload at 1,000,000 database zones takes about 30 ms instead of walking every zone), and the loader is told about the new configuration afterwards.
  `reload` (without arguments) and `reconfig` answer:
  - `OK` (`OK reloaded` for `reload`): the configuration was applied and every zone loaded. When a setting that needs a restart changed, `(restart needed for: port, ...)` follows.
  - `ERROR configuration applied, but N zone(s) failed to load: <zones>`: the new configuration is in use, and the listed zones (also logged to syslog) answer SERVFAIL until their files can be loaded.
  - `ERROR configuration not applied: <reason>`: the file could not be read, has an error (see syslog or `karicheck conf`), or a log file could not be opened; the running configuration is kept.
  - `ERROR reload postponed: ...`: readers of the previous configuration were still active; the server retries the reload by itself every second.

  Every `ERROR` reply makes `karictl` exit with status 3.

`stop`
: Stop the `karidns` daemon.

`notify <zone> [view]`
: Send DNS NOTIFY messages for `<zone>` now: to the `also-notify` servers and to the addresses of the zone's apex NS hosts, except the host named in the SOA MNAME field (RFC 1996 §3.2). Zones served from a database are found too; one that is hidden by a configured zone or a catalog member of the same name answers `ERROR zone is not served from the database ...`.

`retransfer <zone> [view]`
: For a secondary zone (including a catalog member zone), discard the current serial and start a new transfer (AXFR) from the primary immediately. For any other zone the server answers `ERROR zone is not a secondary` and karictl exits with status 3; the zone is not changed. A `SLAVE` or `CONSUMER` zone from the database (milestone B7b) is a secondary and is transferred again like any other; a `NATIVE` / `MASTER` zone from the database is a primary zone: the answer is `ERROR zone is a primary zone from the database; read it again with 'karictl reload <zone>'`.

`zonestatus <zone> [view]`
: Display the SOA serial and refresh interval of `<zone>` (`OK serial=<n> refresh=<n> retry=<n> expire=<n>`; for a secondary the values the zone uses, held to `min-refresh-time` ... `max-retry-time`). For a zone from the database the line goes on with `source=database view=<v> id=<domains.id> result=<applied|rejected|shadowed (hidden by ...)>` and the last error, if any. A secondary that applies settings received from its primary (Extended AXFR version 3, see karidns(8)) adds `settings=primary` (and `note: ...` when part of them is not in force, e.g. a TSIG key the received `allow-transfer` names is not defined here).

`observatory [zone [view]]`
: Display per-zone statistics for all zones, or only for the given zone (and view): role (primary/secondary), SOA serial, query counts (total and TCP), response codes (NOERROR, NXDOMAIN, NODATA, SERVFAIL, REFUSED), EDNS/DO/ECS query counts, RRL dropped/slipped counts, successful inbound AXFR/IXFR transfers (secondary) or NOTIFY messages sent (primary) with the time of the last one, and response cache hits and misses (the cache is shared by all zones, so it has no per-zone size). A zone that other views share with `zone { in-view }` (karidns(8) "Zones shared between views") is listed once, in the view that owns it, as `Zone: <name> (view: <owner>, shared to views: <a>, <b>)`; `status` counts it once, and `notify`, `zonestatus` and `reload` name it with or without a view (a referencing view's name reaches the owner's zone).

`dbstatus [zone [view]]`
: Show the state of the zones served from a database (`options { database { ... }; }`, SQLite3 or PostgreSQL through `karidns-dbloader`). Without arguments: whether the loader is connected (with its process ID, version and drivers, and since when), how many DB zones the server holds (served, hidden by a zone of the same name in `karidns.conf`, hidden by a catalog member of the same name, and zones with a rejected version), the last batch the loader delivered (id, kind `startup` / `full` / `diff` / `zone` / `auto`; a `reload` is a `diff` batch, a `reload <zone>` a `zone` batch, time, and its applied / rejected / shadowed / deleted counts), the state of auto reload (`auto reload: off`, or `on` with poll-interval, coalesce, the number of auto batches since the start and, per view, the last poll, the applied change log position, the pending changes and the last error; B9), for a PostgreSQL view whose schema has the multi-server tables (B11) one line `reload requests (view <name>): server-id <id>, last applied generation <n>, ok yes|no, status written <time>|never, last error: <text>|none` (the id this server reports under in `karidns_server_status`, the highest `karidns_reload_requests` generation it has applied, whether every zone of that reload loaded, when its status row was last written, and why a read of the requests or a write of the status row failed; the server keeps serving when it cannot write the row), the totals since the server started, and the last protocol error of the loader link. With a zone name (and optionally a view): that zone's view, database id, SOA serial, status (`applied`, `rejected` or `shadowed`) and the last error, then, for a `SLAVE` or `CONSUMER` zone (B7b), its type, masters and TSIG key and the last successful transfer with the serial (the data of such a zone is kept in memory only; `settings from the primary: in force` when the primary sent settings, B8t-2), then (B7a) the settings it runs with: where they come from (`profile 'name'` with the zone's own metadata overriding it, `the zone's own metadata`, or `none`), its `allow-transfer` and `allow-update` entries with their match mode, the entries `acl-ceiling` cuts away (`lies outside acl-ceiling`, `is narrowed by acl-ceiling`, or `no acl-ceiling is configured: these ACLs refuse everybody`) and a `settings error` line when a TSIG key the settings name is no longer defined in `karidns.conf`. The summary also counts the distinct settings (zones with the same settings share one block) and the zones that name an undefined key. A zone that was rejected keeps serving its last good version (its serial is shown). Without a `database` block the server answers `ERROR no database block is configured`.
  ```sh
  karictl dbstatus
  karictl dbstatus example.test
  ```

`tsig-keygen [keyname]`
: Generate a 256-bit random TSIG secret with OpenSSL `RAND_bytes(3)` and print a `key` block (`algorithm hmac-sha256`) ready for `karidns.conf`. The default key name is `transfer-key`. This command does not contact the server and does not read the configuration file.
  ```sh
  karictl tsig-keygen transfer-key
  ```

---

## CONFIGURATION FILE (`karictl.conf`)

By default, `karictl` reads the shared secret from `/usr/local/etc/karidns/karictl.conf`. The package installs `karictl.conf.sample` next to it.

### Configuration Syntax

```
socket "/var/run/karidns/control.sock";

key "karictl" {
    algorithm "hmac-sha256";
    secret "UkVQTEFDRS1NRTpvcGVuc3NsLXJhbmQtYmFzZTY0LTMy"; // placeholder: replace with `openssl rand -base64 32`
};
```

The `secret` defined in `karictl.conf` must match the secret configured in the `control-channel` block of [`karidns.conf`](karidns.md).

The file is not parsed as a full configuration file: `karictl` takes the quoted value that follows the **first** occurrence of the word `secret`, and the quoted value that follows the first occurrence of the word `socket`, anywhere in the file (comments included). The value after the first `algorithm` (quoted or not) selects the HMAC: `hmac-md5`, `hmac-sha1`, `hmac-sha224`, `hmac-sha256` (default), `hmac-sha384` or `hmac-sha512`; it must match the server's `control-channel { algorithm }`, and an unsupported name exits with status 2. The key name is not used. The secret may decode to at most 256 bytes. `karictl` prints a warning when the file is readable by group or other users; it should have mode `0600`.

---

## EXIT STATUS

`0`
: Command executed successfully (including `tsig-keygen` and `-v`).

`1`
: Socket path too long, connection failure to the control socket, or failure to receive the challenge.

`2`
: Usage error (no command, an unknown option, `notify` / `retransfer` / `zonestatus` without a zone name; the usage text goes to standard error and nothing is sent to the server), or the secret could not be read or decoded from the configuration file, the challenge was invalid, or authentication failed. A command the server does not know is not a usage error for `karictl`: the server answers `ERROR unknown command` and the exit status is 3. `-h` and `--help` print the usage text to standard output and exit with 0.

`3`
: The server returned an error (`ERROR ...`, including a failed `reload` or `reconfig`, a database zone that was rejected or could not be read, and a reload that timed out) or an invalid `status` or `observatory` response (also `dbstatus` without a database block).

---

## FILES

`/usr/local/etc/karidns/karictl.conf`
: Default control channel client configuration file.

`/var/run/karidns/control.sock`
: Default UNIX domain socket endpoint monitored by the `karidns` daemon.

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karicheck(1)`](karicheck.md) — Configuration and zone file validation utility
- [`karidns-dbloader(8)`](karidns-dbloader.md) — The database loader that `reload` and `dbstatus` talk to
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                    KARICTL(8)
```

# Changes

Release notes of KariDNS, newest first. Every entry names the pull request that made the change (`#N`, in
[NoelMinamino/KariDNS](https://github.com/NoelMinamino/KariDNS)); the detailed behaviour is in the manuals under
`docs/`. Operators upgrading from 0.6 should follow the checklist in [docs/UPGRADING.md](docs/UPGRADING.md).

A pull request that changes behaviour adds its line here (docs/RELEASING.md).

## 0.7.0 (unreleased)

The pull requests of this section are #178 to #256 (the 0.6.2 tag is at #177). Figures are the ones the pull
request bodies report; the host, load and method are in the pull request.

### Upgrade notes / incompatible changes

What changes, what it breaks, and what to do. The step-by-step version is [docs/UPGRADING.md](docs/UPGRADING.md).

- **The zone store is on by default** (#185, #203, #239). A configuration with a `database { }` block, or with
  secondary zones, uses `/var/db/karidns/store` when `/var/db/karidns` exists (the server makes the last component,
  mode 0700, owned by the run user). It needs disk space (about 1.2-1.6 KB per small database zone, #185) and, for a
  database, a first fill after the first start. Keep the 0.6 behaviour with `store none;` (database block) or
  `zone-store none;` (options). `make install` and the FreeBSD package create `/var/db/karidns`.
- **Secondary zones keep their copies in the store** (#203, #239, #240). A restart serves the last good copy at
  once, and the SOA expire clock is no longer reset by a restart (RFC 1034 section 4.3.5). A new optional
  `secondary-stale-max` (default 0, unlimited) limits how long an expired copy is served stale (RFC 8767 section 5).
  The name `_karidns-xfr` is reserved as a view name.
- **The store format is quarantined, not migrated, when it changes** (docs/RELEASING.md). 0.6 had no store, so the upgrade to 0.7.0 drops nothing; a later release that changes `STORE_FORMAT_VERSION` says so in its notes.
- **`fetch-rate` defaults to unlimited** (was 200 zones/s) and database zones are answered, not refused (#184).
  A query beyond `fetch-concurrency` or a configured rate waits (parked) instead of being shed. Under overload a
  query for a database zone is dropped and counted, not answered REFUSED or SERVFAIL (#194, #195).
- **More threads by default, and different ones** (#220, #226, #227).
  - Router and worker counts follow the CPUs the process may run on (`cpuset`, jails); from 4 CPUs half of them are
    routers (4: 2+2, 8: 4+4, 16: 8+8; 1-3 CPUs: unchanged). New restart-only `router-threads` (1..8) and
    `worker-threads` (1..128).
  - `udp-receive backend` is the default: each worker reads its own `SO_REUSEPORT_LB` socket, the routers only send
    the replies. There is one socket per worker and listen address; the start is refused above 4096 sockets or
    `RLIMIT_NOFILE`. `udp-receive frontend` is the 0.6 behaviour.
  - `store-threads` defaults to 8 (it was 2, docs/karidns.md).
- **A default `memory-limit` for database zones in the store** (#256). A `database { }` block whose zones go to the
  zone store and that does not write `memory-limit` gets one from the RAM: half of the RAM above 256 MB, at least
  `64M` (512 MB: `128M`, 1 GB: `384M`, 16 GB: `8064M`). The coldest zones above it are taken out of memory and read
  again from the store when asked for; before, every attached zone stayed in memory and a database larger than the
  host grew the Backend until the kernel killed it. The start logs it at NOTICE (`[DB] memory-limit is not set: 384M
  is used (the default: half of the 1.0 GB of RAM above 256 MB, at least 64M) ...`), `karictl dbstatus` shows
  `memory-limit=384M (default)` and `limit_default=1`, and `karicheck db` says the default of its host. Keep the old
  behaviour with `memory-limit unlimited;`. Without the store (`store none;`, `zone-store none;`) an unset
  `memory-limit` is still no limit. In a jail or container whose memory is limited below the host's RAM, write
  `memory-limit` (hw.physmem is the host's).
- **Socket buffers**: the kernel refuses (does not clip) a `SO_RCVBUF` / `SO_SNDBUF` above about 8/9 of
  `kern.ipc.maxsockbuf`. On a stock system the `4M` default of `udp-recvbuf-size` was refused and the sockets stayed
  at 16 KiB. 0.7 asks for the most the kernel gives and logs a WARNING that names the sysctl to raise (#224).
- **Stricter configuration** (#248, #234, #211, #220). `karidns` refuses to start, and `karicheck conf` reports an
  error with file and line, for: an invalid `rate-limit` value (negative, above INT_MAX, not a number, `window 0`,
  prefix length out of range; it was a warning and the default stayed, #248); an `alias-max-refresh-time` outside 5 s
  .. 1 day (#234); a `store-max-zones` outside 1024..2^31 (#211); `router-threads` / `worker-threads` out of range
  (#220). Fix: correct the value; `karicheck conf` finds them before the upgrade.
- **Stricter zone files** (#247). 0.7 refuses what 0.6 loaded wrongly or dropped silently. Fix: run `karicheck zone`
  on every zone file before the upgrade (docs/UPGRADING.md lists them).
  - tinydns IPv4: exactly four decimal octets 0-255 in every line type (`999.1.1.1`, `1.2.3.4junk` and `not-an-ip`
    were accepted or dropped).
  - A NUL byte in a zone file, `$INCLUDE` file, tinydns file or configuration is an error (`io.nul-byte`); the
    records after it used to be lost while the load succeeded.
  - `$GENERATE`: at most 1,000,000 generated records per zone, and a statement that would pass `max-records` fails
    while parsing.
  - A quoted string must be a field of its own (`"abc"def` is an error), tag names above 63 characters are errors, and
    several tinydns fields (IPv6, location code, time stamp, NAPTR strings, SSHFP fingerprint) are errors.
  - `karidns-zone import` and `karicheck` refuse a file above 256 MiB (#180).
  - The diagnostic `zone.tinydns.skipped` is retired (the cases are errors now); scripts that match on codes need
    to follow (`karicheck --json`).
- **Forward zones and ALIAS resolvers use DNS Cookies** (RFC 7873; #234, #238, #243). A forwarder that never sent a
  server cookie is answered as before; once it did, its UDP answers without one are discarded. The client's COOKIE
  option is replaced on the hop and the forwarder's cookies never reach the client. `require-server-cookie` and the
  BADCOOKIE answer now also apply to queries for `type forward` and `type program` zones, and are answered before
  every REFUSED / SERVFAIL (#243): clients with a bad server cookie get BADCOOKIE for those zones too.
- **`signer-wait` keeps the signed version across restarts** (#237, #244, #246). A zone that waits for
  `karidns-signer` (`X-KARIDNS-SIGNER` = 1 and a `karidns_signer_state` row that is not up to date) is no longer
  served unsigned after a restart of the server or the loader, nor under `memory-limit`; it keeps serving the
  signed version until the signer signs it. If no signed version exists the server serves the unsigned one and
  warns. Keep the signer running; `karictl dbstatus <zone>` shows the waiting zones.
- **`karidns-dbloader --dump <file>`** follows a symbolic link and replaces its target through a temporary file
  (mode 0600, then the replaced file's mode, 0644 for a new file); it used to write in place. A path whose temporary
  name is too long is an error; a device or FIFO is written in place and never removed (#249).
- **Database drivers read integers strictly** (#249, #250). An integer cell that is not exactly `-?digits` in range is
  an error that names the column (PostgreSQL), SQLite3 bind failures fail the statement, and `karicheck db` warns when an
  integer column of the PowerDNS tables is not int2/int4/int8.
- **`karictl` and `karidns` must be the same version** (#179, #180): `karidns_status_t` grew. `karictl ipcstats` is a
  separate text command so that an older server only shows nothing (#224).
- **Database schema**: the schema version stays 3, but the SQL files changed. Re-apply them, as the owner of the
  PowerDNS tables (#187): PostgreSQL `db/karidns_ext.pgsql.sql` then `db/karidns_api_role.pgsql.sql` (and the
  writer, signer and check role scripts for the `MAINTAIN` grant on PostgreSQL 17+); SQLite3
  `db/karidns_auth.sqlite3.sql`. Until then `karidns-webadmin --check` and the start refuse with
  `missing tables: auth.preferences` or the missing privileges.
- **WebAdmin / signer file and connection checks** (#187). The TOTP key file and the TLS key must be owned by the
  service user and are opened once with `O_NOFOLLOW` and checked on the descriptor; `sslmode` `allow` / `prefer` to a
  host that is not local is refused (node-pg would send plain text); the service refuses to start while
  `totp.key.new` exists.
- **`karidns-zone` uses libidn2** when it is found (`karidns-zone idn`, #196, #200); the FreeBSD packages already
  depend on it through dag. dag's `+idnin` follows dig 9.20 exactly: an ASCII name is sent as typed (no lower
  casing) and a name libidn2 rejects as DISALLOWED is converted again transitionally (#197).
- **dag and karicheck no longer write the shared parsers' lines to the host's syslog** (#180); what a user needed is a
  `karicheck` diagnostic now. `karicheck conf` prints a few diagnostics that were syslog-only before (an include that
  cannot be read, ignored `rate-limit` options, `conf.tsig.algorithm-deprecated`).
- **Logging** (#179). With `options { directory }` and the default routing, `<directory>/karidns.run` is created
  (empty until the debug level is above 0). A refused start now removes the pid file and control socket it made, and
  a log directory made by the start that is, or is above, the pid-file or control-socket directory is refused.
- **Packages and installation** (#181). `make install` / `make uninstall` exist; the FreeBSD packages are staged
  through them (owners root:wheel, modes 0555 for programs and 0444 for documents and SQL). The rc scripts never
  change an existing `/var/log/named`, signer work directory or WebAdmin key directory; a missing one is made for the
  configuration's user, or the start is refused and says what to set (`karidns_log_owner`); no fallback to `bind`.
  `karidns-signer` requires `karidns-zone` (docs/distribution.md has the upgrade order).
- **Defaults still to land**: the `memory-limit` default for small VPS installs is not in main yet (see
  docs/UPGRADING.md).

### Security

Fixes from the external reviews and audits of the 0.7 cycle. Each has a test that fails before the fix.

- **Server core review, group 1** (#248): a TCP client that reads a few bytes now and then no longer holds a worker in
  a send for ever (`tcp-idle-timeout` bounds the send of one answer, RFC 7766 section 6.2.3); a rollback check at
  serial 0 (a secondary at serial 0 accepted an older first SOA); the dnstap socket rights are cut where it is
  connected; a length from `snprintf()` is clamped before `write()` (loader child, supervisor, control channel,
  karicheck, karictl, dag DoH request header); the Backend's IPC `addr_len` is clamped on every router use.
- **Zone parse, import and export review, group 2** (#247): `$GENERATE` amplification (a 350 KB file could ask for
  10^9 records), NUL bytes, presigned-row empty non-terminals dropped silently, tinydns IPv4 parsing, and the low
  items listed in the pull request.
- **Database layer review, group 3** (#249, #250): the store sweep and rename paths delete the registry element
  before they forget the entry, and a failed delete fails the pass; the PostgreSQL manifest page bounds its join; the
  loader's pipe errors and hand-over failure are reported; `--dump` no longer truncates a symbolic link's target or
  creates a 0666 temporary file.
- **Audit leftovers and hardening** (#180, #183): the unsigned-transfer warning for secondaries with `primary-settings`,
  the missing-proof report for signed zones, and the audit-hardening items of B1.
- **DNS Cookies (RFC 7873) for the ALIAS resolvers and forwarders** (#234, #238, #243): protection against off-path
  forging of upstream answers; `alias-max-refresh-time` caps how long a forged long TTL stays (default 1 h, was up to
  about 16 h for a TTL of 86400).
- **Backend and loader stay hostile-input boundaries**: zone images are the only way a database zone reaches the
  Backend and are validated (`zone_image_validate_ex()`, libFuzzer target, hostile-loader test, #194); the debug level
  and log records the Backend sends to the other processes are limited to appending to files the start-up
  configuration used (#179).
- **WebAdmin / API** (#187): private files are read once through a checked descriptor (TOCTOU), the unix socket is
  made 0660 under a umask, `--check` reports group API tokens and half-applied upgrades, `rate-reload` limits the
  reload endpoints per principal (default 6 a minute).
- **No secret at any debug level** (#179): `tests/run_log_secrets_test.sh` at `-d 99` searches every channel for TSIG
  keys, the control secret, `cookie-secret`, plugin arguments and a PostgreSQL password.
- **A forward zone relays only this server's cookies** (#238): the forwarder's cookies are removed from the reply
  because a client holding them could forge the next answers.

### New features

- **The zone store** (#185, #191, #193, #194, #195, #199, #201, #204, #206, #209, #211): database zones are answered
  from a mapped zone image store owned by the Backend, so the Backend's and the loader's memory are nearly independent
  of the number of zones (loader about 15 MB at 1M zones, was about 600 MB). Redo journal with group commit, fuzzy
  copy checkpoints, background cleaner, scrub (`store-scrub-interval`), hot list for fast restarts, MAP mode on UFS and
  COPY mode on ZFS, first fill without a journal (bulk fill), `fsync()` at every durability point, address space
  sized from the RAM (`store-max-zones`). `karictl store` shows it (schema 1 keys). New options: `store`,
  `store-mode`, `store-threads`, `store-hot-list`, `store-segment-size`, `store-max-zones`,
  `store-scrub-interval`.
- **Zone images** (#194): the loader sends every database zone as a frozen image (`ZONE_IMAGE`); the old streaming
  mode is removed.
- **Secondary zones in the store** (#203, #239, #240): `options { zone-store "<dir>" | none; }`, kept state and
  settings of the primaries, `[Zone] secondary-expired:` log lines, `karictl status` and `karictl store` counters.
- **Database zones in more places**: names are looked up during the first pass (#191); `signer-wait` works with the
  store (#237).
- **Threads**: `router-threads`, `worker-threads`, `udp-receive` (#220, #226, #227); worker to router replies are
  packed into few IPC datagrams (#230) and wait for a full queue instead of being dropped (#252).
- **Observability**: `karictl ipcstats` and `ipc.*` in `karictl stats` count every IPC / UDP drop (#224, #225);
  dnstap loss counters (#180); the debug level in force (`karidns -d`, `karictl trace` / `notrace`, `karidns.run`,
  63 debug messages, #179); reclaim and long-reader counters (#183); store, memory-advice and park diagnostics
  (#184, #195).
- **DNS Cookie client**: for forwarders and ALIAS resolvers (#234, #238),
  `alias-max-refresh-time` (#234).
- **WebAdmin** (#187, #188, #196): per-user idle sign-out (`PUT /auth/idle-timeout`), `--rotate-totp-key`,
  `rate-reload`, IDN names converted as dig does (`karidns-zone idn`, `GET /idn`), a refreshed look with a colour
  scheme choice (system / light / dark), links to ldns.jp.
- **Installation** (#181): `make install` / `uninstall` (`PREFIX`, `SYSCONFDIR`, `LIBEXECDIR`, `DESTDIR`), manual
  pages (11 pages) generated from the Markdown manuals by `make man`.
- **dnsqps** (#210, #228, #233, #236): a new multi-platform DNS load generator written from scratch (sendto, mmsg,
  AF_XDP, netmap; open and closed loop; agent / controller mode); manual `docs/dnsqps.md`.

### Bug fixes

- **NSEC3 Opt-Out**: below an empty non-terminal that exists only above an insecure delegation the server now uses
  the closest provable encloser (RFC 5155 section 7.2.1); NXDOMAIN and DS answers validate (#180).
- **Cookies**: the server cookie checks now come before the forward / program dispatch and before every
  REFUSED / SERVFAIL, and no answer carries BADCOOKIE's upper RCODE bits on another RCODE (wire RCODE 21 / 18) (#243).
- **Router**: a refused batch is spilled to the next worker instead of dropped, and the socket buffer size is set
  correctly under a low `kern.ipc.maxsockbuf` (#224).
- **Transfers and reload**: an outbound transfer no longer holds an RCU read section for its whole duration, so
  reloads, UPDATEs and database batches no longer wait for it; a reload no longer stalls up to 60 s behind a long
  reader (#183).
- **Store**: `ENOMEM` on open is not damage and no longer moves the store aside (#209); a power cut on UFS no longer
  loses the superblock or the journal tail (#209); a zone id reused by another zone, `adopt_job()` without a view and
  a fetch-stream buffer shared by two streams ("bad magic" under load) are fixed (#191); a quarantine reopens the
  store (#203).
- **signer-wait with the store**: PostgreSQL scans outside a snapshot, SQLite3 holding zones the Backend did not have,
  and the missing version stamp of a one-zone reload (#237).
- **Memory accounting**: `memory-limit` counts the per-zone fixed cost and the allocator's real block sizes (it used to
  count about 1.2 of about 3.1 KB per zone) (#184).
- **Start-up**: a refused start cleans up what it made (#179); the Backend's virtual size is no longer 5.9 GB on a
  small host (#211).
- **dag**: `+idnin` follows dig 9.20 (#197, #200).
- **karidns-zone**: an import reports a record that cannot be encoded as an error instead of dropping it; RRSIG times are
  read by the parser's reader (no 31 February); `export --force` keeps the permission bits (#247).
- Test-timing flakes fixed on the way (#189, #190, #207, #231, #232, #235 and the `tests:` pull requests) change no
  behaviour.

### Performance

Numbers are from the pull request bodies. They are measurements on the project's lab hosts (FreeBSD 15.1; the
server on pc31 with 8 CPUs and a one-queue em0, or on a VM; the client on another host), not guarantees.

- **Routers and workers** (#226, #227, #230; pc31, 8 CPUs, 20,000 zone-file domains, loss at most 0.1 %):
  - routers = half the CPUs: 550k qps (2:6, netmap) to a client-limited 650k offered with 4:4; sockets 475-480k to
    600k (`-T 3`) and 625k (`-T 4`) (#226);
  - one CPU (cpuset), 2 routers + 6 workers gave 90k qps against 175k with 1 + 1 (#220);
  - workers reading their own sockets (#227) and reply packing (#230): worker CPU at 550k 72 % to 55 %, router CPU
    46 % to 36 %, `memset` of `edns_info_t` 9.5 % to 1.2 % of the worker; 1 CPU 120k to at least 210k, 2 CPUs 225k to
    300k. Known: with packing the routers lose 0.13-0.23 % at 650k and above on the one-queue NIC (#230).
- **Database fetch path** (#184): 500 to 2,638 zones/s with defaults, average latency 8 to 1.5 ms, maximum 0.65 s to
  22 ms.
- **Cold start of 10M zones on ZFS COPY** (#193, #194; 8 vCPU VM): 95 % of the steady rate after 4-5 s instead of
  7-17 s; with a 3 GiB ARC 239-340k qps against 129-182k.
- **First fill** (#194, #195, #204, #206): the manifest pass under 400k qps load 110-125 s (was 287 s) at 10M zones on
  UFS; no REFUSED in the first second (180-273 before); writer hold maximum 1919 ms to 9.3 ms (#204); the unlogged
  bulk fill writes 4.27 GiB to the device instead of 23.3 GiB for 10M zones on ZFS, fill 410 s against 454 s (#206).
- **Clean open** of the store: 9 ms at 1M zones, 23 ms at 10M (#185).
- **Backend heap**: a small attached zone 739 B (was 1128 B) (#185); `zone_db_entry_t` 1032 to 584 bytes (#184); the
  Backend's virtual size on a 512 MB host 5.9 GB to 1.0 GB (#211).
- **WebAdmin / karidns-zone**: the RRset page right after a bulk load 124-678 ms to 3-4 ms after the automatic
  `ANALYZE` (PostgreSQL 18, 100k records) (#187).

### Documentation / tools

- New manuals: `docs/dnsqps.md`, `docs/UPGRADING.md`; manual pages for every tool (`man/`, generated by `make man`,
  #181); the dnstap consumer stream, the store, secondary zones and the memory limit in `docs/karidns.md`.
- `karicheck`: new codes (`conf.zone.primary-settings-unsigned`, `conf.alias-max-refresh-time`, `io.nul-byte`,
  `zone.record.wire`, `internal.oom`); `karicheck db` warns on non-integer PowerDNS columns (#180, #234, #247, #250).
- Reserved example names and addresses in tests, fixtures, fuzz seeds and documents; the package maintainer address
  is the GitHub no-reply address (#182).
- CI: sharded FreeBSD suite with merged coverage (#186), FreeBSD built once per release (#208).

## 0.6.x and earlier

Earlier releases are tagged `v0.6.2` (2026-11-13), `v0.6.1` (2026-11-12), `v0.6.0` (2026-11-11), `v0.5.0`
(2026-10-08) and before (`git tag`). Their pull requests are #133 to #177 for 0.6.0 to 0.6.2; this file does not
list them. The 0.6.0 database layer, the auth schema and the signer are described in `docs/karidns-dbloader.md`,
`docs/karidns-signer.md` and `docs/karidns-webadmin.md`; 0.6.x behaviour that still matters is marked "(0.6.x)" in
`docs/`.

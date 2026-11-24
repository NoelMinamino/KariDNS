# Upgrading from 0.6 to 0.7

## NAME

**UPGRADING** — a checklist for operators who move a KariDNS server from 0.6.x to 0.7.

What changed, release by release, is in [CHANGES.md](../CHANGES.md) (every entry names its pull request). This page
is the order of work. The manuals have the detail: [karidns(8)](karidns.md), [karicheck(8)](karicheck.md),
[karictl(8)](karictl.md), [karidns-dbloader(8)](karidns-dbloader.md), [karidns-zone(8)](karidns-zone.md),
[karidns-signer(8)](karidns-signer.md), [karidns-webadmin(8)](karidns-webadmin.md) and
[distribution.md](distribution.md) (packages).

## 1. Before the upgrade

1. **Back up** what you cannot make again: the configuration (`karidns.conf` and its includes, the `karictl.conf`,
   TSIG key files), the zone files of primary zones, and the database
   (PostgreSQL `pg_dump`, SQLite3 `.backup`, not `cp`). With the WebAdmin also the **TOTP key file**
   ([BACKUP, RESTORE, UPGRADE](karidns-webadmin.md)). `karidns-zone export --all --dir <dir>` writes every database
   zone as a zone file.
2. **Check the configuration with the new `karicheck`** (install it first; it does not need the new server running):

   ```sh
   karicheck conf /usr/local/etc/karidns/karidns.conf
   karicheck --json conf /usr/local/etc/karidns/karidns.conf     # one document, a code for every message
   ```

   0.7 refuses to start on values that 0.6 accepted with a warning (#248, #234, #211, #220):

   | Statement | What 0.7 refuses |
   |---|---|
   | `rate-limit { ... }` | a negative value, a value above `INT_MAX`, a non-number, `window 0`, a prefix length out of range (an unknown option in the block stays a warning) |
   | `alias-max-refresh-time` | below 5 seconds or above 1 day (`conf.alias-max-refresh-time`) |
   | `store-max-zones` | below 1024 or above 2^31 |
   | `router-threads`, `worker-threads` | outside 1..8 and 1..128 |

   Fix what `karicheck conf` reports with its file and line before you install the new server.
3. **Check every zone file** with the new `karicheck` (0.7 is stricter, #247, #180). A file that loaded under 0.6
   can be refused under 0.7; the server then keeps the zone out or keeps the old data (as for any bad zone), so find
   them first:

   ```sh
   karicheck zones /usr/local/etc/karidns/karidns.conf           # every zone of the configuration
   karicheck zone example.test /path/to/example.test.zone        # one file
   ```

   What 0.7 now rejects (each is an error at its line):

   - tinydns IPv4 addresses that are not exactly four decimal octets 0-255 (`999.1.1.1`, `1.2.3.4junk`,
     `not-an-ip`: 0.6 accepted or dropped them), in every line type and the `%` prefix;
   - a NUL byte in a zone file, an `$INCLUDE` file, a tinydns data file or a configuration file (`io.nul-byte`);
   - `$GENERATE` that makes more than 1,000,000 records in a zone, or that would take the zone past `max-records`;
   - a quoted string that is not a field of its own (`"abc"def`), tag names above 63 characters, bad tinydns IPv6,
     location code (above 2 characters), time stamp, NAPTR strings or SSHFP fingerprint;
   - a file above 256 MiB (also for `karidns-zone import`);
   - a record that cannot be encoded (it was dropped silently, `zone.record.wire`).

   `karicheck zone` also stops reporting `zone.tinydns.skipped` (the cases are errors now): update any script that
   matches on that code.
4. **Database zones**: run `karicheck db` (it runs `karidns-dbloader --check`, no database library in karicheck).
   On PostgreSQL it now warns when an integer column of the PowerDNS tables is not int2, int4 or int8 (#250), and the
   drivers read integers strictly: a cell that is not exactly `-?digits` is an error that names the column (#249,
   #250).
5. **File permissions are checked more** (#187, #185):
   - the WebAdmin's TOTP key file and TLS key must be owned by the service user (they are opened once with
     `O_NOFOLLOW` and checked on the descriptor: a symbolic link is refused);
   - the zone store directory must be owned by root or the user the server runs as, not writable by group or others,
     and not locked by another server, otherwise the server refuses to start (a name you gave) or runs without a
     store (the default directory);
   - `sslmode` `allow` / `prefer` in a PostgreSQL `conninfo` to a host that is not local is refused by the WebAdmin and
     the signer (node-pg would send plain text): use `require` or better (`disable` stays a warning).
6. **`karictl` and `karidns` of one release.** The status structure grew (#179, #180); install both together.
7. **Plan the disk**: with a database or secondary zones the store is on by default (section 3). About 1.2-1.6 KB of
   disk per small database zone (#185), and free space for the first fill and the cleaner.
8. Read "CHANGES.md / Upgrade notes" once for the items that are specific to your setup (DNS Cookies, `signer-wait`).

## 2. Install

Packages: `pkg add` the 0.7 packages. An installation keeps its `karidns.conf` and with it the user it names
(`bind`, `named` or `karidns`); the rc scripts never change an existing `/var/log/named`, signer work directory or
WebAdmin key directory (#181). If a directory is missing the start is refused and says what to set
(`karidns_log_owner`). **Order with the signer and the WebAdmin**: `karidns-signer` and `karidns-webadmin` require
`karidns-zone` from a 0.7 database package: `pkg add` the database package first, or `pkg upgrade` (the table in
[distribution.md](distribution.md), 2.6 "The signer package").

From source: `./configure && make && make install` (docs/building.md; `make install` never builds anything and never
overwrites an existing configuration file, it installs `*.sample`).

Then `karicheck conf` again with the installed binary and `service karidns restart`. A `reload` does not
change the options that need a restart (`OK reloaded (restart needed for: ...)`).

## 3. Changed defaults

| What | 0.6 | 0.7 | Keep the old behaviour |
|---|---|---|---|
| Zone store | none | on in `/var/db/karidns/store` when `/var/db/karidns` exists and there is a `database { }` block or a secondary zone (#185, #203) | `store none;` in `database { }`, `zone-store none;` in `options` |
| `fetch-rate` | 200 zones/s | `unlimited` (#184) | `fetch-rate 200;` |
| Requests over `fetch-concurrency` or `fetch-rate` | shed | wait in an ordered queue (#184) | none |
| Query for a database zone under overload | REFUSED / SERVFAIL | dropped and counted (#194, #195) | none |
| UDP receive | routers read, workers answer over IPC | `udp-receive backend`: each worker reads its own socket (#227) | `udp-receive frontend;` |
| Routers / workers | by all CPUs of the machine (from 4 CPUs: 2 routers + the rest) | by the CPUs the process may run on; from 4 CPUs half of them routers, up to 8 (#220, #226) | `router-threads N; worker-threads N;` |
| `store-threads` | 2 | 8 (docs/karidns.md) | `store-threads 2;` |
| `udp-recvbuf-size` (4M) | refused by the kernel on a stock system, sockets stayed at 16 KiB | the most the kernel gives, with a WARNING (#224) | raise the sysctls (section 6) |
| `alias-max-refresh-time` | a forged TTL of 86400 stayed about 16 h | 3600 s cap (#234) | `alias-max-refresh-time 1d;` |
| DNS Cookies to forwarders and ALIAS resolvers | none | sent and checked (#234, #238) | none; a resolver that never sends a server cookie is accepted |
| `secondary-stale-max` | n/a | `0` (unlimited), new (#203) | already the default |
| Forwarder warnings (`[Forward] ...`) | one line per event, written at once | event lines: rate-limited per category and second, a summary says how many were left out (#260) | none |
| Loader log lines | the loader chose the priority and the prefix | always `[DB] ...`, at most `LOG_ERR` (#260) | none |
| `KARIDNS_TEST_IPC_REPLY_BUDGET_US` / `_QUEUE` | read from the environment by every build | test build only (#260) | none (test switches) |
| `memory-limit` | none | none (**TODO: change this row when the small-VPS default lands**; it is not in main yet) | `memory-limit` set explicitly |

Memory notes: the Backend holds about 70 MB fixed plus about 0.45 KB for every database zone in the directory;
`memory-limit` bounds the zones in memory, not that part (docs/karidns.md "Memory limit"). The store's tables are
counted against `memory-limit` before the zones (#199).

## 4. New required settings

Nothing is required for a small install. For a very large database (more than about 30 million zones, or fewer
with little RAM) set the store's address space:

```
database {
    store-max-zones 100000000;      # restart-only, 1024 .. 2^31
};
```

The default is sized from the RAM (zones = `hw.physmem` / 256 B rounded up to a power of two, 1M .. 32M zones: a 512
MB host reserves 2M, a 16 GB host 32M; #211). A table at its reservation refuses new zones (an ERROR a minute names
`store-max-zones`; the zone is served from the database). The log line `store: address space reserved for the tables`
and `karictl store` (`store.reserve.*`) show it. Reservations are `PROT_NONE`: they show in `ulimit -v` and VSZ
monitoring, not in memory.

For a ZFS host: make the dataset of the store with `recordsize=16K` (or 8K), `compression=lz4`, `atime=off`
(docs/karidns.md "The zone store", ZFS); the server logs `store.fs.recordsize_warning` above 32 KiB.

## 5. Database schema and migrations

- **Schema version stays 3.** No `karidns_ext_v1_to_v2` style migration is needed from 0.6.x. The SQL files changed,
  so apply them again as the owner of the PowerDNS tables (they only create what is missing and replace functions;
  #187):
  - PostgreSQL: `db/karidns_ext.pgsql.sql`, then `db/karidns_api_role.pgsql.sql`, and the role scripts you use
    (`db/karidns_writer_role.pgsql.sql`, `db/karidns_signer_role.pgsql.sql`, `db/karidns_check_role.pgsql.sql`):
    they add the table `karidns_auth.preferences`, the function `karidns_auth.group_tokens()`, an ordered
    `karidns_changes` write, and on PostgreSQL 17+ the `MAINTAIN` privilege on `records` for the writer, signer and
    API roles (not the check role) so that `karidns-zone` can run `ANALYZE` after a large import;
  - SQLite3: `db/karidns_ext.sqlite3.sql`, `db/karidns_audit.sqlite3.sql` and `db/karidns_auth.sqlite3.sql` (the
    auth file gets the table `preferences` and its audit triggers).
- Until the SQL is applied `karidns-webadmin --check` and the service refuse to start with `missing tables:
  auth.preferences` or the names of the missing privileges.
- `karidns-webadmin --check` also warns about API tokens that belong to groups (the API no longer makes them).
- The server, `karidns-dbloader` and `karicheck db` use none of the WebAdmin objects, so a server-only installation
  has nothing to apply.

## 6. The zone store: first fill and disk use

- **First start.** A database server with an empty store does a **first fill**: the loader makes a manifest pass
  (the zone names, in `domains.id` order) and the Backend fetches the bodies in the background; queries are answered
  meanwhile (a zone not yet read is fetched for the query, #184, #191, #194). The first fill of an empty store keeps
  no journal (the database is the source of truth, #206): after a crash during it the pass is read again. Measured
  (10M zones, lab host): about 2 minutes for the pass on UFS under load, about 7 minutes for the whole fill on ZFS
  (CHANGES.md, Performance).
- **Disk use.** About 1.2-1.6 KB per small database zone, plus a journal ring (64 MiB of address space) and segment
  files (`store-segment-size`, 256 MiB). Free space is read at every checkpoint; the cleaner needs room to copy
  before it frees a segment, and a new image is refused below that (docs/karidns.md "The zone store").
- **Secondary zones** (also without a database): the default store is made on the first start and a NOTICE says so;
  the copies appear with the first refresh of each zone (a zone that does not change is stored by its "up to date"
  answer). The first start after the upgrade transfers or checks every secondary as before; later restarts serve the
  last good copy at once, also with the primary down, and the expire clock is kept (#203). `[Zone]
  secondary-expired:` lines report expired, stale and refreshed zones; `secondary-stale-max` limits staleness.
- **Never touch the store while the server runs.** One store belongs to one server (a lock file).
  `karictl store` shows state, `karictl store scrub start` and `karictl store compact` run maintenance.
- **`signer-wait` zones** are held across restarts (#246): a zone whose signer state is not current waits for
  `karidns-signer` and keeps serving its signed version; keep the signer running after the upgrade. A zone with no
  signed version is served unsigned and warned about (`karictl dbstatus <zone>`).

## 7. Signer and WebAdmin

- Upgrade `karidns-webadmin`, `karidns-signer`, `karidns-zone` and `karicheck` **with the same release**: the service
  refuses a `karidns-zone` that speaks another JSON schema.
- Apply the SQL files (section 5), then `service karidns_webadmin configtest`, then restart.
- New settings and behaviour (docs/karidns-webadmin.md, docs/karidns-api.md): `rate-reload` (6 reloads a minute per
  principal; the GUI counts down), a per-user idle sign-out (the effective idle is the smaller of `session-idle` and the
  user's choice), `karidns-webadmin --rotate-totp-key` (with the service stopped; the old key stays as `totp.key.old`,
  the service refuses to start while `totp.key.new` exists), and IDN names converted as dig does (needs libidn2 for
  `karidns-zone idn`; the packages depend on it).
- `karidns-zone` runs `ANALYZE records` after an import that changed 1000 records or more (#187).

## 8. Recommended sysctls

Since 0.7 the server logs a WARNING at start-up when the kernel refuses a socket buffer (#224). On a stock FreeBSD
(`kern.ipc.maxsockbuf` 2 MiB) the `udp-recvbuf-size 4M` default is refused and the server falls back to about
1.8 MB:

```sh
sysctl kern.ipc.maxsockbuf=8388608            # to get the 4M buffers; put it in /etc/sysctl.conf
sysctl net.local.dgram.maxdgram=65616         # replies above 8112 octets through the IPC (type program zones; docs)
```

`net.local.dgram.maxdgram` limits one IPC message: a reply above it is refused with `EMSGSIZE` and logged (the
default 8192 gives 8112 bytes of reply; the program-zone guide says 65616 or more for 65,535). Reply frames are sized
under it (at most 64 KiB, #230). `karictl ipcstats` shows `ipcbuf.*.asked` / `.got` and every drop; `got` below `asked` means
the sysctl held the request down. Also see `net.local.dgram.recvspace` in karictl(8).

The Backend's virtual size follows the RAM since 0.7 (about 1 GB on a 512 MB host, was 5.9 GB), so a `ulimit -v` of 1 GB on a 512 MB host no longer stops the store from opening; a store that cannot reserve its tables still falls back to database-only and the log says so (#209, #211).

## 9. After the upgrade: check

```sh
karictl status          # "[Startup] N routers, M workers (C CPUs usable of T)" is in the log
karictl ipcstats        # ipc.dropped.total should stay near 0; ipcbuf.*.got = asked
karictl store           # store.* keys; store.reserve.refused must be 0
karictl dbstatus        # held= long_reader=, signer-wait: lines
```

Watch the log for `[IPC] WARNING`, `[Network] WARNING`, `[Store]` and `[Zone] secondary-expired:` lines for a day.

## 10. Rolling back

- **Server and tools**: `pkg add` the 0.6.x packages (with `-f` to replace). `karictl` and `karidns` must be of the
  same release.
- **Configuration**: a 0.7 configuration that uses `store-*`, `zone-store`, `router-threads`, `worker-threads`,
  `udp-receive`, `secondary-stale-max` or `alias-max-refresh-time` is not understood by 0.6: remove those lines first
  (0.6 does not know them).
- **The store**: 0.6 reads no store. Stop the server cleanly first (the manual says to downgrade only after a clean stop, #199), then the directory can be removed; database zones are read from the database as in 0.6.
  Secondary zones start as in 0.6 (zone file or nothing, then a transfer) and lose their stored copies and expire
  clocks (docs/karidns.md "Upgrade and downgrade").
- **Database**: the SQL files only add objects (`auth.preferences`, `group_tokens()`, grants) that 0.6 ignores; a
  schema rollback is not needed. Restore from the backup of step 1 if you changed data.
- **WebAdmin**: rotate-key writes `totp.key.old`; to go back keep the key file that matches the database.

## Pending items

- **`memory-limit` default for small VPS installs**: TODO, not merged yet; update section 3 when it lands.
- Open pull request #253 (signer / WebAdmin review group A: key order, re-sign floor, file checks, atomic failure
  record, column allowlist) is not in main; add its notes if it merges before the release.

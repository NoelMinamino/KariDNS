# KARIDNS-DBLOADER(8) — KariDNS Database Loader

## NAME

**karidns-dbloader** — reads the PowerDNS 5.1 tables of a SQLite3 or PostgreSQL database and hands the zones to the KariDNS Backend

## SYNOPSIS

```text
karidns-dbloader --drivers
karidns-dbloader --dump OUT --driver sqlite3 --database-file PATH [options]
karidns-dbloader --dump OUT --driver postgresql --conninfo-file FILE [--schema NAME] [options]
karidns-dbloader --check --driver sqlite3 --database-file PATH [options]
karidns-dbloader --check --driver postgresql --conninfo-file FILE [--schema NAME] [options]
karidns-dbloader -s FD
```

`-s FD` is the mode `karidns` runs; you do not start it by hand. `--drivers`, `--dump` and `--check` are for administrators and for tests.

## DESCRIPTION

`karidns` never links a database library. When `options { database { ... }; }` (or a `view` database option) is configured, the manager process starts **`karidns-dbloader`** (the loader) as a child. The loader opens the database, reads the zones, converts every zone with the same readers and checks as the zone-file parsers, and sends the result to the Backend over a socket pair that the manager created before it dropped privileges (stream `KDB1`, framed messages whose zone data is in Extended AXFR format). The Backend builds the zones with the engine that also builds zone-file zones, so a zone answers byte for byte the same from a file and from the database. See [`karidns(8)`](karidns.md), "`database { ... }` (in `options`) and the view database options", for the configuration options and for everything a database zone can carry (settings, ACLs, tags, secondary zones, ALIAS records).

What the loader does while `karidns` runs:

- **Start.** It says HELLO (version, drivers), receives the configuration of the databases from the Backend, asks for the Backend's inventory (the zones it already has) and reads every zone. A zone whose content digest equals the Backend's version is not sent. The first zones are served as soon as the first batch part is published; a line `initial load complete` is logged when the first batch is done.
- **Reload.** `karictl reload` makes it compare the databases with the inventory: new zones, zones whose SOA serial differs, zones the change log table `karidns_changes` lists as edited, and zones the Backend refused last time are read and sent; zones that left the database get a delete. `karictl reload <zone>` reads that one zone. When a reload has to read more than `bulk-threshold` percent of the zones, one scan of all records replaces the per-zone queries.
- **Auto reload** (`auto-reload yes;`). The loader polls (SQLite3) or listens (PostgreSQL `LISTEN`) and sends a batch by itself after the first commit plus the `coalesce` window.
- **Several servers on one PostgreSQL database.** It reads `karidns_reload_requests` and writes its outcome to `karidns_server_status` (see [`karidns(8)`](karidns.md), "Several servers on one PostgreSQL database").
- **Serial 0.** A zone whose SOA serial is 0 is loaded as it is; the loader logs a warning (`the SOA serial is 0; ...`) when it sends that version of the zone, not again while the zone is unchanged. `--check` reports the same as a warning.
- **Crash.** If the loader dies, `karidns` keeps answering from the zones it has and the manager starts a new loader (after 1 s, 2 s, 4 s ... 60 s; the delay restarts after 10 minutes without a crash). A new loader compares **every** zone with the Backend's inventory before it reports its first batch (the whole database is read once; see "Measurements").

### Privileges

- The loader runs as `loader-user` / `loader-group` and **never as root** (`loader-user` is required when `karidns` starts as root). It has no access to `karidns.conf`, only to the database and to its socket; everything else reaches it over the stream.
- It is an ordinary process (not in a Capsicum sandbox): it needs the database library and file or socket access, and what it reads from the database is untrusted input that the shared reader validates. What it sends is untrusted for the Backend, which validates the stream again and stays in capability mode: all descriptors are opened by the manager at start, the Backend opens nothing new.
- It reads only. The SQLite3 driver opens the file read-write (a reader of a WAL database must write the `-shm` file) but sets `PRAGMA query_only=1`, so no statement of the connection can change data; PostgreSQL transactions are `READ ONLY` and the role should have no more than `db/karidns_loader_role.pgsql.sql` gives it. The one thing the PostgreSQL loader writes is its own row in `karidns_server_status`.
- `loader-path` (default `/usr/local/libexec/karidns-dbloader`) must be a regular executable file owned by root (or by the user who runs `karidns` when that is not root) and not writable by group or others; `karidns` checks this at start and before every restart. `karicheck conf` reports a problem in advance.
- **SQLite3:** the database must be in WAL mode (`PRAGMA journal_mode = WAL`). A reader of a WAL database still writes the `-shm` file, so `loader-user` needs read and write permission on the database file and on its directory (to create `-wal` and `-shm`), and the file should not be readable by everyone. **PostgreSQL:** the `conninfo-file` has mode 0600 or 0400 and belongs to `loader-user`; use a UNIX socket or `sslmode=verify-full`.
- `karicheck db` checks all of this in advance, from the same code (below).

### Drivers

The loader has the drivers it was built with: `karidns-dbloader --drivers` prints them, one per line, and the loader says them in its HELLO. `karidns` refuses `database { driver x; }` when the installed loader does not have `x` (and `karicheck conf` says `driver x is not available in this installation`). To build:

```text
make karidns-dbloader DB_DRIVERS="sqlite3 postgresql"
```

`DB_DRIVERS` is any subset of `sqlite3 postgresql` (default `sqlite3`); the SQLite3 driver needs `libsqlite3`, the PostgreSQL driver `libpq` (PostgreSQL 13 or newer on the server). The FreeBSD packages are described under "Packages".

## OPTIONS

`--dump OUT`
: Write the stream exactly as the loader sends it to the Backend (HELLO, BATCH_BEGIN, per zone ZONE_BEGIN / ZONE_DATA... / ZONE_END or ZONE_FAILED, BATCH_END) to the file `OUT` (`-` = standard output). Zones come in `domains.id` order and the HELLO of a dump carries pid 0, so two runs on one database state write the same bytes, whatever the number of `--loader-threads`. It reads the database in one snapshot and does not start a server. The output file is removed on an error.

`--check`
: Check mode, what `karicheck db` runs. It reads the same tables through the same code as the production load, sends nothing, writes nothing to the database, and prints what is wrong or odd as lines of the check protocol on standard output (the schema, every zone with the checks of `karicheck zone`, the settings texts, the views a zone is mapped to). Run it as the user the loader runs as; its output is meant to be read by `karicheck`. No `--dump`.

`--drivers`
: Print the compiled-in drivers, one per line, and exit.

`-s FD`
: Stream mode: `FD` is the socket to the Backend. Started by `karidns`. The loader logs to syslog and ends when the Backend closes the stream or on `SIGTERM` / `SIGINT` (also in the middle of a long load: it stops at the next zone, within milliseconds); `SIGHUP` is ignored.

`--driver DRIVER`
: `sqlite3` or `postgresql` (a driver that was compiled in).

`--database-file FILE`
: SQLite3: the database file; it must be in WAL mode. The name is used byte for byte (`%XX` is not decoded); a name that starts with `file:` is refused (write `./file:...`).

`--conninfo-file FILE`
: PostgreSQL: the file that holds the libpq connection string (owned by the user that runs the loader, mode 0600 or 0400; its content is never logged).

`--schema NAME`
: PostgreSQL: the schema that holds the tables (default: the `search_path` of the role).

`--view-index N`
: The view index in ZONE_BEGIN / ZONE_FAILED, 0..65535, default 0.

`--zone NAME`
: Dump only this zone, read with one query per zone instead of the bulk scan.

`--default-ttl N`
: TTL for a `records.ttl` that is NULL, 1..2147483647, default 3600.

`--loader-threads N`
: 1..16, default 1. N workers, each with its own database connection, read and convert disjoint sets of zones (consecutive zones in `domains.id` order); the output is written in `domains.id` order whatever N is. In stream mode the number comes from the configuration (`loader-threads`).

`--map-view NAME`
: Keep only the zones that `karidns_domain_views` maps to the view `NAME` (a domain without a row is kept): what a view that uses the shared source of a server gets.

`-s FD`, `--fetch-fd FD`
: Stream mode, what `karidns` runs: `FD` is the socket to the Backend (descriptor 3). `--fetch-fd FD` (descriptor 4) is the second stream, for fetches (below); without it the loader works as before.

`--auto-reload`, `--server-id ID`, `--ecs-tag NAME`, `--location-tag NAME`, `--max-zone-records N`, `--max-zone-bytes N`
: With `--check` only: the values of the configuration that change what is an error (change log triggers are required with auto reload; `server-id` of a PostgreSQL view; the tags of `options { ecs-tags }` / `location-tags` records may name; the limits of the database block). `karicheck db` passes them from `karidns.conf`.

`--version`, `-h`, `--help`
: Print the version, or the usage text.

## THE FETCH STREAM

D1a (milestone 2). `karidns` starts the loader with a second socket, descriptor 4, next to the stream on descriptor 3 (`-s 3 --fetch-fd 4`); a restart makes a new pair of each and hands the Backend's two ends over together. It is a second KDB1 stream (see `dns_db_stream.h`) for the one thing that must not wait behind a batch: the Backend asks for one zone because a parked query waits for it.

- **Requests.** `FETCH_REQ` (request id, view, zone, priority 0 query / 1 warm-up / 2 background, mode 0 the zone / 1 its summary; an optional range, which this loader refuses). A thread of the loader reads them into a queue of 256, takes the most urgent first (the oldest within a priority) and reads the zone through the same code as a one-zone reload: its own connection and snapshot, no batch, no inventory, no results. A request beyond the queue is answered `ZONE_FAILED` "busy" (the first eight; more are dropped and the Backend's own time-out ends them).
- **Answers.** `ZONE_BEGIN` .. `ZONE_DATA` .. `ZONE_END` with the request id in `ZONE_BEGIN` (a secondary or catalog zone has no data, as in a batch); or the **summary** (mode 1, primary zones): `ZONE_BEGIN` with the summary flag and `ZONE_END`, carrying the serial, the SOA refresh / retry / expire and whether the zone is presigned (metadata `PRESIGNED=1`), no records, a zero digest. The summary of a zone with no location tags or tinydns attributes also carries its **apex** (ZONE_BEGIN tags 15 to 21; the same in the summaries of a batch): the SOA's names, minimum and TTL, the NS targets (at most 8, the lowest TTL of the RRset) and the A / AAAA records of the NS targets that are inside the zone (at most 8 for a name, in the order of the zone, the lowest TTL of the records of one type), read with `scan_apex`; a zone with more than that sends no apex. With them goes tag 22, the **NOTIFY addresses** (D1a step 7): the A and AAAA records, in **any zone of the same source**, whose name is an NS target that is *outside* the zone (found by name, `records.name = lower(<NS target>)`: an equality on the name index, one lookup per NS record; PowerDNS stores names in lower case, a name stored with capitals is not found), at most 8 for one target and 1152 bytes in all (the first ones in `records.id` order; more do not take the apex away, they are cut), as records of the NS index in tag 20, the type and the address. The Backend keeps them with the apex only for a zone that sends NOTIFY to its NS hosts (`notify yes` or `primary-only`) and sends NOTIFY to them when the zone changes while its data is out of memory (`karidns(8)`, "Zone transfers" and "NOTIFY"); it checks the list again (format, the index of a name outside the zone). A loader that does not send the tag costs the NOTIFY to those hosts, nothing else. The Backend answers an SOA question for a zone that is out of memory from it (`karidns(8)`, "SOA questions for a zone that is out of memory"). After a reload that makes a zone keep an apex, the Backend asks for the summary of the zones out of memory that have none (mode 1, priority warm-up). Or `ZONE_FAILED` with the request id and the reason (the zone is not in the database, its type is not supported, no SOA, the database could not be read, busy). Never silence. The Backend's state machine for this stream (`kdb_sm_init_fetch()`) accepts nothing else, and discards a zone it did not ask for.
- **The end of the stream.** The fetch stream is as vital as the first one: when the Backend closes it (it does after a protocol error of the loader, a full send buffer or an out-of-memory) or it breaks, the loader ends with status 3 and the supervisor starts another one with a new pair of streams (after the usual 1, 2, 4 ... 60 s). A loader that went on without a fetch stream would fail every later fetch "not connected" until it died for some other reason.
- **Inventory.** The Backend's `INVENTORY` entries have a `resident` flag (0 for a zone whose data was taken out of memory or left out because of `memory-limit`: the entry then carries the serial and no digest). A zone that is not resident is not sent by a full comparison (no digest to compare); a zone that changed still is.
- **Not in this milestone.** The settings text and the addresses of name servers outside the zone in the summary (design 7), and a request for a range of a zone.

## EXIT STATUS

`0`
: Every zone was written (`--dump`), or nothing wrong was found (`--check`).

`1`
: The stream is complete but some zones went out as ZONE_FAILED (the reason is on standard error), or `--check` found errors.

`2`
: Usage error (a bad option or option value, a stray argument, a missing or contradicting option; the usage text or the reason goes to standard error); nothing was read. `-h` / `--help` print the usage text to standard output and exit with 0. The other tools use 2 for usage errors too (`karicheck`, `karictl`, `karidns`).

`3`
: Error: database, schema, output or memory.

`4`
: Transient database error (busy); try again.

## SCHEMA AND TRIGGER FILES

The loader reads the tables of the **PowerDNS 5.1 generic SQLite3 / PostgreSQL backend** (`domains`, `records`, `domainmetadata`, `cryptokeys`; the PowerDNS schema file is not part of KariDNS: take `schema.sqlite3.sql` or `schema.pgsql.sql` from PowerDNS). KariDNS adds its own tables and triggers in the files below. The extension is optional; without it a database still loads, but there is no change log (zones are compared by SOA serial only), no view mapping, no profiles and no tags, and `karicheck db` says what that costs.

| File | Content |
|---|---|
| `db/karidns_ext.sqlite3.sql` | SQLite3: schema version 2. `karidns_changes` (the change log: which domain changed, written by triggers on `domains`, `records`, `domainmetadata`, `cryptokeys` and the tables below), a trigger that keeps the newest 1,000,000 log rows, `karidns_domain_views`, `karidns_profiles`, `karidns_record_tags`, `karidns_record_tinydns`, `karidns_zone_tagdefs`, `karidns_schema_version`. Apply it once, as the owner of the database, after the PowerDNS schema. It can be applied again. |
| `db/karidns_ext.pgsql.sql` | PostgreSQL: the same tables with statement-level triggers (one log row per distinct domain per statement), `NOTIFY karidns_changes` for auto reload, and the multi-server tables `karidns_reload_requests` and `karidns_server_status`. PostgreSQL 13 or newer. Apply it in the schema that holds the PowerDNS tables. |
| `db/karidns_ext_v1_to_v2.sqlite3.sql`, `db/karidns_ext_v1_to_v2.pgsql.sql` | Convert a database from schema version 1 (the extension files of the early betas) to version 2. The loader reads both versions and serves a version 1 database without a change log. |
| `db/karidns_loader_role.pgsql.sql` | PostgreSQL: the privileges of the loader's role (`psql -v role=... -v schema=...`). `SELECT` on the PowerDNS tables and the `karidns_*` tables, only the column privilege `SELECT (domain_id, active, published)` on `cryptokeys` (never the private keys), `default_transaction_read_only = on`, and `INSERT, UPDATE` on `karidns_server_status` when the table exists. It does not create the role (the authentication is yours) and can be run again. |

A bulk import writes one change-log row per changed row (SQLite3) or per statement (PostgreSQL); a big import makes the next reload compare every zone once. The files carry their own documentation in their first lines.

### Indexes

The extension files create `karidns_zone_tagdefs_domain_idx` on `karidns_zone_tagdefs (domain_id)` (the loader reads the tag definitions of one zone at a time; without the index every such read scans the table). It was added after schema version 2, which stays 2: apply `db/karidns_ext.*.sql` (or the `v1_to_v2` script) again to get it on an existing database.

**The loader is read-only and never creates an index.** Two optional PostgreSQL indexes on the PowerDNS tables make the big reads faster; create them yourself when the database is large:

| Index | Effect |
|---|---|
| `CREATE INDEX records_soa_cover_idx ON records (domain_id) INCLUDE (name, content) WHERE type = 'SOA' AND disabled = false;` | The zone list of every full comparison (`karictl reload`, auto reload, a loader restart) joins each domain to its apex SOA. With this partial covering index the join is an index-only merge over one row per zone. The loader looks the index up once per connection (`pg_indexes`) and then leaves the planner's `cursor_tuple_fraction` at its default (0.1) for the list; without the index it plans the list for all of its rows (`1`), which is then the faster plan. Measured at 1,000,000 zones x 11 records (`psql`, 3 runs): without the index 2.2 s planned for all rows (one pass over the SOA rows) against 2.6 s at the default (a walk of the whole `records` table through its `domain_id` index); with the index 1.7 s planned for all rows (the planner still reads every SOA row) against 1.0 s at the default (the index-only merge). |
| `CREATE INDEX domains_lower_name_idx ON domains (lower(name));` | A one-zone read of a zone that is not in the database (a deletion, a typo in `karictl reload <zone>`) falls back to `lower(d.name)`, a table scan of `domains` without this expression index (about 0.2 s at 1,000,000 zones). |

**Zone names that differ only in case are not supported.** PowerDNS stores `domains.name` in lower case, and so should the data: two rows of one source such as `Example.test` and `example.test` are two rows for PostgreSQL's case-sensitive unique index (the PowerDNS PostgreSQL schema has a `CHECK` constraint `c_lowercase_name` that refuses upper case, and SQLite3's schema declares the column `COLLATE NOCASE`; such rows only exist when a constraint was dropped or the data was written around it). The loader keeps the one-zone lookup (`--zone`, used by reload requests and auto reload) fast: it matches the indexed name exactly first and falls back to `lower()` only when that finds nothing. With such duplicates a full read and a one-zone read may therefore pick different rows. `karicheck db` (`karidns-dbloader --check`) warns about every pair of `domains` rows of one source whose names are equal ignoring case, with both `domains.id` values (both drivers); fix the data, do not rely on either row.

## PACKAGES

`packaging/freebsd/build_pkg.sh --db none|sqlite3|postgresql|both` builds four FreeBSD packages from the same server and tools; only the loader and its dependencies differ. They install the same files, so they `conflicts` with each other (install one).

| Package | `karidns-dbloader` | Dependencies added |
|---|---|---|
| `karidns` | not installed | none |
| `karidns-sqlite3` | SQLite3 driver | `databases/sqlite3` |
| `karidns-postgresql` | PostgreSQL driver | `databases/postgresqlNN-client` (libpq; NN is the version the build host linked) |
| `karidns-db` | both drivers | both |

The database packages install `/usr/local/libexec/karidns-dbloader` (root:wheel, mode 0555), this manual, and the SQL files of their drivers in `/usr/local/share/karidns/db/`. In a package without the loader `karicheck db` reports `DB support is not installed`. See [Distribution Guide](distribution.md).

## MEASUREMENTS

Measured on 2026-10-26 on the FreeBSD 15.1 build host (4 vCPU, about 10 GB RAM, virtual disk), `karidns` 0.5.0 built from the v0.6 beta branch (milestone B12), SQLite3 3.53.3, a SQLite3 source whose file was copied just before each run (warm page cache). The database generator is `tests/db/gen_sqlite3_zones.sh`; the measurement scripts and raw results are kept with the project's benchmark records, outside the source tree. Every figure is **one run** unless it says "median"; the host is shared with the load generator, so differences of a few percent are noise.

| Data set | Zones x records | Records | SQLite3 file |
|---|---|---:|---:|
| `z10k` | 10,000 x 1,000 | 10,000,000 | 1.30 GB |
| `z1m` | 1,000,000 x 11 | 11,000,000 | 1.51 GB |

(`tests/db/gen_sqlite3_zones.sh`: names `z<i>.test`, per zone SOA, 2 NS, apex A and MX, `www`, and A / CNAME / AAAA / TXT / MX hosts; `db/karidns_ext.sqlite3.sql` applied after the bulk load. Each database is made in about 30 s.)

**PostgreSQL measurements (the beta leftovers).** The same two data sets in PostgreSQL 18.6 on the same host, with `tests/db/gen_pgsql_zones.sh CONNINFO ZONES RRS` (the same rows as the SQLite3 generator, `tests/db/pdns_schema.pgsql.sql`, `db/karidns_ext.pgsql.sql` applied after the load, `ANALYZE domains, records`; 90 s for `z10k` and 103 s for `z1m`, about 2.4 GB and 2.6 GB). Every run worked on a clone of the database (`CREATE DATABASE ... TEMPLATE`, 3.1 s) that was dropped afterwards, as the SQLite3 runs worked on a copy of the file. The loader connected over the UNIX socket as an unprivileged role with a `conninfo-file`, the server had its default settings (`max_connections 20`, no tuning), the default thread counts (`ingest-threads 1`, `loader-threads 1`), and the edits of the steps were made with `psql`. The harness is the one of the SQLite3 figures with those edits changed; the steps are the same (start, `karictl reload` with nothing / 1% / 10% changed, `karictl reload <zone>` five times for an add, five for a change, one delete, and auto reload eight times with `poll-interval 1` and `coalesce 200`). One run each unless it says otherwise; the database server shares the host with `karidns` and the load generator, and the virtual disk is slow, so single outliers (a checkpoint) are in the figures.

| Target (PostgreSQL 18.6) | `z10k`: before; after | `z1m`: before; after | SQLite3 `z10k` / `z1m` |
|---|---:|---:|---:|
| T-START: first answer / `initial load complete` | 1.7-2.1 s / 31.7-32.2 s (2 runs); 1.2 s / 31.4-31.6 s (2 runs) | 3.2 s / 37.8-38.2 s (2 runs); 3.0 s / 38.0-38.2 s (2 runs) | 1.0 s / 24.1 s, 1.9 s / 33.4 s |
| Peak RSS of the Backend / of the loader | 1,077 MB / 12.5 MB; 1,077 MB / 11-12 MB | 2,970 MB / 281 MB; 2,936-2,940 MB / 280-281 MB | 1,079 MB / 15 MB, 2,998 MB / 280-380 MB |
| `karictl reload`, nothing changed | 0.82 s; **0.22 s** | 4.5 s; 4.2 s | 0.04 s, 3.3 s |
| `karictl reload`, 1% of the zones edited | 1.5 s; **0.89 s** | 9.6 s; **5.3 s** | 0.29 s, 3.9 s |
| `karictl reload`, 10% edited, under load (20 s `dnsperf`; QPS before / mean while reloading / lowest second, queries lost, longest latency) | 10.5 s (467k / 322k / 178k, 0, 0.94 s); **4.3-4.6 s** (333k / 258k / 135k, 0, 0.85 s and 560k / 261k / 160k, 0, 0.76 s) | 60 s (377k / 237k / 92k, 0, 0.94 s; the load ended before the reload did); **14.2-15.0 s** (463k / 274k / 34k, 0, 1.83 s and 320k / 229k / 6k, 0, 1.87 s) | 2.6 s, 17.7 s |
| T-ZONEADD: add a zone, `karictl reload <zone>` (5 runs) | 13-14 ms; 13-14 ms | 43-69 ms; 44-76 ms | 7-8 ms, 28-44 ms |
| one zone changed (5 runs) / deleted | 19-21 ms / 36 ms; 18-21 ms / 39-40 ms | 12-15 ms, twice 0.38 s and 0.93 s / 272 ms; 13-14 ms, once 35 ms / 1.1-1.2 s | 11-12 ms / 7 ms, 6-8 ms / 27-37 ms |
| T-AUTORELOAD: commit to served (8 runs) | 0.95 s (0.946-0.959; 0.84-0.85 s with `coalesce 100`); **0.41-0.43 s** | 2.7-2.8 s; 2.5-2.6 s | 0.28-1.02 s, 1.2-2.2 s |

(Each pair is the figure of the first measurement, then the figure after this change: the zone list query and the grouped reads of changed zones, see below. The second figure is from two rounds on the same day, the best-known state of the host; the old binary measured again in rounds of its own gave `z10k` 0.75-0.90 s for the reload without changes, 1.4-1.9 s for 1%, 9.8 s for 10% and 0.94-0.97 s for auto reload, `z1m` 4.7-4.8 s, 10.3-10.6 s, 60-69 s and 2.7-2.9 s, so the earlier column stands. One round of the old binary also had single outliers while the host was busy (43 s for the 10% reload at `z10k`, 19 s and 28 s for the first two auto reloads at `z1m`); they are not in the figures. The deletion at `z1m` is the `lower(d.name)` scan of the second `find_zone` query described below; it took 0.4-1.3 s in every series on the same day, old binary and new.)

Notes on PostgreSQL:

- **The start** is 30% (`z10k`) and 15% (`z1m`) slower than with SQLite3 and the first answer comes 1-1.3 s later; the loader reading alone takes 29.0 s / 34.4 s (see the thread sweep), so the Backend adds the same 2-3.5 s as before. The goal (answering within 60 s) is met.
- **A reload that compares everything is slower than with SQLite3.** Where the time goes (a timestamp at every step of the loader, `z1m`, nothing changed, 4.2 s): 1.95 s are in the Backend before the loader is asked anything (`karictl reconfig` alone takes the same 1.95 s: the new snapshot is built from the 1,000,000 database zones of the registry, a cost of the Backend that has nothing to do with the database driver and that SQLite3 pays too), 2.0 s in the zone list (the query is 1.7 s in `psql`: one pass over the 11,000,000 records for the 1,000,000 SOA rows), 0.25 s in the comparison with the Backend's inventory, 0.03 s to free the list. At `z10k` the same steps take 0.2 s in all.
  - **The zone list.** It used to join each domain to its apex SOA on `lower(r.name) = lower(d.name)`, which PostgreSQL could answer only by reading the records of every zone (0.8 s at `z10k`, 2.0 s at `z1m`), and the list is read by every full comparison, so by every auto batch. It joins on the plain name now (`r.name = d.name`, served by the standard indexes on `records`), with the case-insensitive comparison as a per-zone fallback for a zone whose SOA owner differs in case (which the schema's `c_lowercase_name` constraint forbids), and the loader plans the list for all of its rows (`SET LOCAL cursor_tuple_fraction = 1` for this one query; a cursor is planned for its first 10% by default): 0.2 s at `z10k` (the reload without changes 0.8 s to 0.22 s, the auto reload 0.95 s to 0.42 s, of which 0.2 s is `coalesce`) and 1.8 s at `z1m` (the planner reads the SOA rows once there; 2.0 s before). If one zone has SOA records of two spellings of its name, the list takes the lowest `records.id` of the exact spelling (before: of all spellings); that is a data error anyway, as for `domains.name` below. The SQLite3 driver now orders the same way (`ORDER BY d.id, r.id`: the smallest `records.id` among several enabled SOAs, explicitly).
  - **The changed zones.** A reload that changes fewer zones than `bulk-threshold` percent (default 25) of the source reads them without scanning everything. A zone read on its own costs a statement per table and three round trips per statement (`DECLARE`, `FETCH`, `CLOSE`): about fifteen with the extension tables, 0.55 ms per zone on the local socket (`z1m`, 100,000 changed zones: metadata 7.1 s, records 11.4 s, tags and tinydns attributes 29.6 s, conversion 6.5 s of the 54.6 s the loader spent). The PostgreSQL driver now has `scan_records_in`, `scan_metadata_in` and `scan_ext_in`: up to 128 changed zones (consecutive in the list) are read with one statement per table (`domain_id = ANY ($1::bigint[])`), the records still streamed through the cursor, so the loader holds the metadata and extension rows of 128 zones and the records of one, as before. The zones are converted and sent in the same order, the stream is the same bytes (`tests/test_db_pgsql.c` compares the group calls with the single-zone calls row by row; `tests/run_db_pg_group_reload_test.sh` runs 160 changed zones among 700). The loader spent 11.0 s instead of 54.6 s on the 100,000 zones; the whole reload 14-15 s instead of 60 s. `bulk-threshold` keeps its meaning (the share of zones above which one scan of all records is cheaper than reading the changed ones); only the cost of reading below it fell, so the break-even moved: for PostgreSQL a higher threshold than 25% may now pay. A reload of one zone (`karictl reload <zone>`, `--zone`) is read as before. SQLite3 reads zone by zone (a statement costs no round trip there). With `loader-threads` above 1 each worker reads groups of up to 64 zones.
  - **What is left.** The reload without changes at `z1m` (4.2 s) is the Backend's 1.95 s, the list's 2.0 s and the comparison's 0.25 s; the list could only be made much cheaper by not comparing the SOA serials, which the design keeps as the safety net behind the change log, and the PostgreSQL server of the host has `max_parallel_workers_per_gather 0`. A reload that changes 10% of 10,000 zones of 1,000 records (4.3-4.6 s) is dominated by converting and sending 1,000,000 records, not by round trips. More `loader-threads` (each thread opens its own connection, mind `max_connections`) help both, as in the thread sweep.
- **`find_zone` for a zone that is not there** (a deletion, or a typo in `karictl reload`): the exact-spelling query uses the index on `domains.name` (0.04-0.2 ms at 1,000,000 zones, whether the zone exists or not); when it finds nothing, the second query with `lower(d.name)` scans the table: 189-218 ms at 1,000,000 zones (5 runs with `psql`; `Seq Scan on domains`), which is most of the 272 ms of the delete above. It is the price of finding a zone stored with capital letters; PowerDNS stores names in lower case, and `karicheck db` warns about two rows that differ only in case. An index `CREATE INDEX ON domains (lower(name))` would make the fallback an index search too; the loader does not need it and does not create it.
- **Auto reload** with `LISTEN` sees a commit at once; the figures above are the comparison that follows. A hot standby refuses `LISTEN`; see below.

**A PostgreSQL hot standby (streaming replica).** Tried with a scratch primary and a standby of it on the build host (two throwaway clusters under their own directory, ports 5442 and 5443, started by the `postgres` user, removed afterwards): 50 zones, `karidns` reading the standby over the UNIX socket as an ordinary role. `LISTEN` is refused (`cannot execute LISTEN during recovery`), and the loader behaves as follows.

- *Reload requests* (`karidns_reload_requests`, written on the primary and replicated): the loader logs once that it cannot `LISTEN karidns_reload` and reads the requests every `poll-interval`; a request inserted on the primary is applied after 0.6 s (replication lag, the timer, one zone read). `karictl reload` works as on a primary.
- *The status row* (`karidns_server_status`) cannot be written on a read-only server (`cannot set transaction read-write mode during recovery`): the loader logs it once (it stayed one line for four requests), `karictl dbstatus` shows it as the last error of the reload requests (`status written never`), the requests are still applied and the server keeps answering.
- *Auto reload* (`auto-reload yes`) did not work on a standby before: the loader's change detector needed the notification, so every poll failed (`cannot watch the database: ... LISTEN`, `last poll never` in `dbstatus`) and no change was ever picked up. The PostgreSQL driver now reads a fingerprint of `karidns_changes` (the number of rows and the highest `seq`) every `poll-interval` when `LISTEN` is refused, the loader logs `the server refuses LISTEN (a standby?); the change log is read every N s instead` once, and a zone added on the primary is served after 0.75 s, a changed record after 1.0 s (`poll-interval 1`, `coalesce 200`, local replication). The cost is one index-only `count(*)` per poll over at most 1,000,000 log rows. `tests/test_db_pgsql.c` tests the fingerprint (a commit, a row with a lower `seq` that commits last, a lost connection) by setting the driver's `listen_failed` flag; the standby itself is a manual procedure: `pg_basebackup -R` of a primary with `wal_level replica`, the standby started with its own `-p`, the database block pointing at the standby's socket and port.

**Targets of the release plan with the default settings** (`ingest-threads 1`, `loader-threads 1`):

| Target | `z10k` | `z1m` | Goal | Met |
|---|---:|---:|---|---|
| T-START: start to answering (first zones / `initial load complete`) | 1.0 s / 24.1 s | 1.9 s / 33.4 s | answering within 60 s | yes |
| T-START with `ingest-threads 2`, `loader-threads 2` | 1.1 s / 12.8 s | 1.9 s / 19.2 s | | yes |
| Peak RSS of the Backend (all zones loaded) | 1,079 MB | 2,998 MB | | |
| Peak RSS of the loader | 15 MB | 280-380 MB | | |
| T-ZONEADD: add a zone, `karictl reload <zone>` to the answer (5 runs, 2 series) | 7-8 ms (before the fixes below: 27 ms) | 28-44 ms (before: 0.17-0.19 s, once 0.71 s; before the one-zone lookup fix: 0.8-1.3 s on a fresh run, 1.1-2.7 s in the long run) | under 1 s | yes |
| one zone changed / deleted, the same | 11-12 ms / 7 ms (before: 18-19 ms / 26 ms) | 6-8 ms, once 0.56 s / 27-37 ms (before: 26-45 ms / 0.18-0.64 s; before the one-zone lookup fix: 0.3-1.5 s / 0.75-1.0 s) | under 1 s | yes |
| T-AUTORELOAD: commit to served (8 runs, `poll-interval 1`, `coalesce 200`) | 0.28-1.02 s | 1.2-2.2 s (median 1.25 s) | a few seconds | yes |
| T-RECOVER, Backend killed (`kill -9`): the server exits and was started again at once: first answer / `initial load complete` | 1.0 s / 24.2 s | 2.0 s / 33.6 s | within T-START | yes |
| T-RECOVER, loader killed: answers continue; new loader connected / has compared every zone | 1.06 s / 24.4 s | 1.1 s / 29.4 s | | |
| `karictl reload`, nothing changed | 0.04 s | 3.3 s | | |
| `karictl reload`, 1% of the zones edited | 0.29 s | 3.9 s | | |
| `karictl reload`, 10% of the zones edited, under load (see below) | 2.6 s | 17.7 s | | |

Notes:

- **There are no persisted images in this release**, so "restart" is a start: the whole database is read again. T-START is met without them for 10^7 records and for 10^6 zones on this host; the time is the time the loader needs to read and convert the database (`karidns-dbloader --dump` alone: 23.6 s for `z10k`, 27.9 s for `z1m` with one thread), the Backend adds about 0.5 s (`z10k`) and 5 s (`z1m`).
- **A restarted loader reads the whole database** (it compares every zone with the Backend's inventory before its first batch; 24 s / 29 s above). The Backend answers from its zones all the time. T-RECOVER for a killed Backend was measured by starting the server again immediately after it exited (it exits 0.06-0.16 s after the kill).
- **T-ZONEADD at 1,000,000 zones.** The first measurement missed the target because a one-zone reload read the list of all zones of the source. The loader now looks the zone up by name (`find_zone` of the drivers, an index on `domains.name`; PostgreSQL falls back to `lower()` only when the exact spelling is not found) and asks the inventory for that one name. What remained (an add 0.17 s, a delete 0.2-0.6 s at 1,000,000 zones) was profiled in the beta leftovers: 58 ms were still in the loader, because the SQLite3 `find_zone` was written `name = ? OR name = ?` with an explicit `COLLATE`, for which SQLite chooses `SCAN domains` (8,400 pages) instead of the index; it is an `IN` list now (`EXPLAIN QUERY PLAN`: `SEARCH name_index`). About 105 ms were in the Backend: `snapshot_apply_db_delta()` copied the zone list of the view and rebuilt both hash tables from every name (90 ms of the 105; the delta of the first second of a start does the same with 25,000 zones). It now copies the hash tables of the old snapshot (`memcpy`) and patches them: an added zone is appended and linked, a removed one is unlinked and the last entry takes its slot, so the work per change is a chain walk; the tables are rebuilt only when the load factor would pass one half, or when a catalog consumer leaves. What was still proportional to the number of zones was the copy of the tables (about 30 MB at 1,000,000 zones) and one reference count per zone for the new snapshot (and one release per zone when the old snapshot was freed by its cleanup thread): `snapshot_apply_db_delta()` took 19 ms instead of 105 ms. D1a (the zone directory) removed that: the views of a snapshot share one directory per view, `snapshot_apply_db_delta()` inserts and removes the changed elements in place (open addressing; a tombstone for a removal, a bigger table only when the load would pass one half) and publishes a snapshot that only holds the names, the match-clients and a reference of each directory, so the work is proportional to the change. What leaves the directory is freed when the snapshot that was current at that time and every older one are drained. A new entry that replaces a served one (a database zone that changes kind, for example from primary to secondary) takes the place of the old one in the directory at the commit, not at the next delta. The other 10-20 ms of an add are the loader's read, the stream and the first query. Of about 40 single reloads one in twenty was delayed by about 0.5 s (0.56 s once, 0.57 s before the change); it also happened for a change, which publishes no delta, and the cause was not found.
- **The 0.13 / 0.26 / 0.52 s one-zone reloads** (about one in twenty at 1,000,000 zones, with either source, add, change or delete, delta or not) had two causes in the Backend, both fixed after B13: the control thread's one-second tick walked every zone of the snapshot inside an RCU read section (90-250 ms at 1,000,000 zones) looking for secondaries to refresh and for NOTIFY requests, so a `karictl reload <zone>` that arrived during the walk waited for it, and the grace period of the batch (`zone_retire_process`) waited for that read section with sleeps that doubled up to 131 ms, which made a walk of 70 ms cost 131 ms and one of 250 ms cost 524 ms. The tick now looks only at the view's list of secondaries and catalog members (`tick_entries`, built with the hash tables and inherited by the one-zone delta), walks every zone only when a NOTIFY was requested since its last full walk, and the grace-period wait sleeps at most 1 ms at a time. Measured afterwards with 100 one-zone changes at 1,000,000 zones (SQLite3): `karictl reload <zone>` answered in 5-11 ms and the change was served 15-25 ms after the command (the tail up to 77 ms is the `dag` process of the measurement; 0 ms of query time). The tick also no longer costs 10-25% of a core at 1,000,000 zones.
- **T-AUTORELOAD** depends on `poll-interval` (SQLite3) and `coalesce`; the table uses 1 s and 200 ms. With PostgreSQL a commit is seen by `LISTEN` at once; the latency is then the `coalesce` window plus the comparison, see the PostgreSQL table below.
- **Reload under load.** `dnsperf -c 4 -T 2 -q 200` ran for 20 s over random names of the data set while 10% of the zones were edited and `karictl reload` was started 4 s in. Queries per second before the reload / mean / lowest second during it: `z10k` 550k / 198k / 6.6k, `z1m` 403k / 227k / 12k; no query was lost and the longest latency was 0.56 s (`z10k`) and 1.2 s (`z1m`). Queries are still answered, but throughput falls while the reload is busy, in some seconds nearly to zero: on 4 vCPU the load generator, the two query threads, the Backend's builder and the loader compete for the same cores, so part of this is the test setup; the T-RELOAD target (p99 within a small factor of idle) was not measured.
- **Memory.** About 108 bytes per record (`z10k`) and 3.0 KB per zone of 11 records (`z1m`) in the Backend; the loader stays at 15 MB for a few large zones and needs about 300 MB for the inventory and the zone list of 1,000,000 zones. A reload that edits 10% of the zones keeps the old versions of the changed zones until they are freed: the Backend peaked 82 MB above its idle size at `z10k` (1,000 zones of 1,000 records) and 34 MB at `z1m`. Each extra `loader-thread` adds about 25-40 MB to the loader with large zones (15, 53, 93 MB for 1, 2, 4 threads at `z10k`) and little with small ones.
- **T-QPS (L)** (no database block, `tests/karidns-test.conf`, `dnsperf -c 4 -T 2 -q 200 -l 20`, three runs, host idle): the v0.6 beta branch 475k (median of 6 runs; 495k and 461k in the two rounds) against 483k for `main` before the database work (484k and 465k), the figure of 2026-10-09 being 481k. The spread between runs of one build (445k-508k) is larger than the difference: no regression.

**Thread sweep.** Start of `karidns` with each combination, in seconds until `initial load complete` (one run each; reloads in the full results):

| `ingest-threads` | `loader-threads` | `z10k` | `z1m` | `z10k` reload, 10% changed, under load | `z1m` reload, 10% changed, under load |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 24.1 | 33.8 | 2.6 s | 14.3 s |
| 1 | 2 | 14.7 | 21.0 | 1.5 s | 8.7 s |
| 1 | 4 | 15.3 | 21.2 | 1.6 s | 9.0 s |
| 2 | 1 | 24.1 | 34.8 | 2.7 s | 16.9 s |
| 2 | 2 | 12.8 | 19.2 | 1.4 s | 10.1 s |
| 2 | 4 | 10.9 | 19.0 | 1.3 s | 7.6 s |
| 4 | 1 | 24.1 | 34.4 | 2.9 s | 15.0 s |
| 4 | 2 | 14.2 | 20.0 | 1.4 s | 10.7 s |
| 4 | 4 | 10.5 | 20.1 | 1.2 s | 11.9 s |

The loader alone (`--dump`, 1 / 2 / 4 threads): `z10k` 23.6 / 12.4 / 6.7 s and `z1m` 27.9 / 15.2 / 8.3 s with SQLite3; 29.0 / 15.5 / 8.6 s and 34.4 / 19.6 / 11.5 s with PostgreSQL 18.6 on the same host (database of 2.6 GB for `z1m`). The start of `karidns` with a PostgreSQL source is in the next section.

**Recommended values** (the defaults stay 1, so a small host or a database of a few zones needs no tuning):

- The loader is the bottleneck of a start and of a big reload: with `loader-threads 1`, more `ingest-threads` change nothing (24 s, 34 s above). **`loader-threads 2`** takes about 40% off (`z10k` 24.1 to 14.7 s, `z1m` 33.8 to 21.0 s).
- **`ingest-threads 2` together with `loader-threads 2`** is the best general setting on 4 cores: 12.8 s and 19.2 s, nearly the best of the sweep, and it leaves two cores for the query threads. `loader-threads 4` gains up to another 15% with large zones (`z10k` 10.9 s) and nothing with many small ones (`z1m` 19.0 s), and takes the cores the query threads need while a reload runs. `ingest-threads 4` gave nothing over 2.
- Rule of thumb: `loader-threads` and `ingest-threads` of about half the number of cores, never more than the cores minus the query threads; 1 on hosts with one or two cores. `ingest-threads` is read when the server starts.
- For PostgreSQL the same holds; each loader thread opens its own connection, so check `max_connections`.

## EXAMPLES

The examples were run once with the package `karidns-db` installed under a scratch root, so `/usr/local/...` below is a path of that installation (`sqlite3` is the SQLite3 command line tool, `schema.sqlite3.sql` the PowerDNS schema file; names are test names). `example.test` and `192.0.2.0/24` are reserved for documentation.

**A SQLite3 database with one zone.**

```text
$ sqlite3 zones.sqlite3 < schema.sqlite3.sql
wal
$ sqlite3 zones.sqlite3 < /usr/local/share/karidns/db/karidns_ext.sqlite3.sql
$ cat zone.sql
INSERT INTO domains (name, type) VALUES ('example.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'example.test', 'SOA', 'ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300', 3600, 0, 0 FROM domains WHERE name = 'example.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'example.test', 'NS', 'ns1.example.test.', 3600, 0, 0 FROM domains WHERE name = 'example.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'www.example.test', 'A', '192.0.2.10', 300, 0, 0 FROM domains WHERE name = 'example.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'ns1.example.test', 'A', '192.0.2.1', 3600, 0, 0 FROM domains WHERE name = 'example.test';
$ sqlite3 zones.sqlite3 < zone.sql
```

**Which drivers, which version.**

```text
$ karidns-dbloader --drivers
sqlite3
postgresql
$ karidns-dbloader --version
karidns-dbloader 0.5.0
```

**Write the stream the Backend would get.** The bytes do not depend on the number of loader threads, and `--zone` reads one zone with a query of its own:

```text
$ karidns-dbloader --dump zones.kdb --driver sqlite3 --database-file zones.sqlite3
$ karidns-dbloader --dump zones4.kdb --driver sqlite3 --database-file zones.sqlite3 --loader-threads 4 && cmp zones.kdb zones4.kdb
$ karidns-dbloader --dump - --driver sqlite3 --database-file zones.sqlite3 --zone example.test | wc -c
     579
```

**Check the database before it goes live.** `--check` prints lines of the check protocol (`I` information, `Z` a zone, `E` an error, `W` a warning, `R` the result: zones, errors, warnings), `karicheck db` prints the same in the style of `karicheck zone`:

```text
$ karidns-dbloader --check --driver sqlite3 --database-file zones.sqlite3
I		0	karidns_* schema version 2
Z	example.test.	1	primary	*
R	1	0	0
$ cat karidns.conf
options {
    pid-file "none";
    database { driver sqlite3; database-file "/home/claude/b13doc/zones.sqlite3"; loader-path "/usr/local/libexec/karidns-dbloader"; acl-ceiling { 192.0.2.0/24; }; };
};
$ karicheck db karidns.conf
[INFO] Loading config karidns.conf...
[INFO] Checking Database file '/home/claude/b13doc/zones.sqlite3' (the default view) with the rights of the user claude (uid 1002)
[INFO] Database file '/home/claude/b13doc/zones.sqlite3': karidns_* schema version 2
[RESULT] Database file '/home/claude/b13doc/zones.sqlite3': 1 zone(s) read, 0 error(s), 0 warning(s)
[OK] Database file '/home/claude/b13doc/zones.sqlite3' is valid.
[INFO] Checked 1 database (1 zone). Errors: 0, warnings: 0
```

A row the loader would refuse (the exit status is 1; `--dump` would send the zone as `ZONE_FAILED`):

```text
$ sqlite3 zones.sqlite3 "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'bad.example.test', 'A', '192.0.2.999', 300, 0, 0 FROM domains WHERE name = 'example.test';"
$ karicheck db karidns.conf
[INFO] Loading config karidns.conf...
[INFO] Checking Database file '/home/claude/b13doc/zones.sqlite3' (the default view) with the rights of the user claude (uid 1002)
[INFO] Database file '/home/claude/b13doc/zones.sqlite3': karidns_* schema version 2
[ERROR] Database file '/home/claude/b13doc/zones.sqlite3': zone 'example.test.' (domains.id 1): records.id 5: invalid IPv4 address literal in A record
[RESULT] Database file '/home/claude/b13doc/zones.sqlite3': 1 zone(s) read, 1 error(s), 0 warning(s)
[INFO] Checked 1 database (1 zone). Errors: 1, warnings: 0
[FAIL] Database file '/home/claude/b13doc/zones.sqlite3' has errors.
```

**PostgreSQL.** The role `karidns_loader` was created by `CREATE ROLE karidns_loader LOGIN;`, the PowerDNS tables exist in the database `karidns`, the extension file is applied by the owner of the tables, and the role script by a superuser such as `postgres` (it alters the role, which needs more than the right to the tables). The loader then reads with the privileges of that role only:

```text
$ psql -d karidns -f /usr/local/share/karidns/db/karidns_ext.pgsql.sql
$ psql -v ON_ERROR_STOP=1 -v role=karidns_loader -v schema=public -f /usr/local/share/karidns/db/karidns_loader_role.pgsql.sql karidns
$ psql -d karidns -c "SET ROLE karidns_loader; SELECT content FROM cryptokeys"
SET
ERROR:  permission denied for table cryptokeys
$ cat conninfo
host=/tmp dbname=karidns
$ karidns-dbloader --check --driver postgresql --conninfo-file conninfo
W		0	the role claude can read cryptokeys.content (the private keys); the loader needs only domain_id (db/karidns_loader_role.pgsql.sql grants just that)
I		0	karidns_* schema version 2
R	0	0	1
```

(The last `--check` ran as the owner of the tables, hence the warning about `cryptokeys.content`; with `user=karidns_loader` in the conninfo file and the loader running as that role it does not appear. The conninfo file must have mode 0600 and belong to the user who runs the loader.)

## FILES

`/usr/local/libexec/karidns-dbloader`
: The loader (database packages).

`/usr/local/share/karidns/db/`
: The SQL files above (database packages; `db/` in a source tree).

`tests/db/gen_sqlite3_zones.sh`
: The generator of the measurement databases (source tree).

`tests/db/gen_pgsql_zones.sh`
: The same data set in a PostgreSQL database (source tree).

## SEE ALSO

- [`karidns(8)`](karidns.md) — the `database` block, database zones, settings, auto reload, several servers
- [`karictl(8)`](karictl.md) — `reload`, `dbstatus`
- [`karicheck(1)`](karicheck.md) — `karicheck db`
- [Distribution Guide](distribution.md) — the four FreeBSD packages

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

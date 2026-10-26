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

`--auto-reload`, `--server-id ID`, `--ecs-tag NAME`, `--location-tag NAME`, `--max-zone-records N`, `--max-zone-bytes N`
: With `--check` only: the values of the configuration that change what is an error (change log triggers are required with auto reload; `server-id` of a PostgreSQL view; the tags of `options { ecs-tags }` / `location-tags` records may name; the limits of the database block). `karicheck db` passes them from `karidns.conf`.

`--version`, `-h`, `--help`
: Print the version, or the usage text.

## EXIT STATUS

`0`
: Every zone was written (`--dump`), or nothing wrong was found (`--check`).

`1`
: The stream is complete but some zones went out as ZONE_FAILED (the reason is on standard error), or `--check` found errors.

`2`
: Usage error; nothing was read.

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

**Targets of the release plan with the default settings** (`ingest-threads 1`, `loader-threads 1`):

| Target | `z10k` | `z1m` | Goal | Met |
|---|---:|---:|---|---|
| T-START: start to answering (first zones / `initial load complete`) | 1.0 s / 24.1 s | 1.9 s / 33.4 s | answering within 60 s | yes |
| T-START with `ingest-threads 2`, `loader-threads 2` | 1.1 s / 12.8 s | 1.9 s / 19.2 s | | yes |
| Peak RSS of the Backend (all zones loaded) | 1,079 MB | 2,998 MB | | |
| Peak RSS of the loader | 15 MB | 280-380 MB | | |
| T-ZONEADD: add a zone, `karictl reload <zone>` to the answer (5 runs) | 27 ms | 0.17-0.19 s, once 0.71 s (before the one-zone lookup fix: 0.8-1.3 s on a fresh run, 1.1-2.7 s in the long run) | under 1 s | yes |
| one zone changed / deleted, the same | 18-19 ms / 26 ms | 26-45 ms / 0.64 s (before: 0.3-1.5 s / 0.75-1.0 s) | under 1 s | yes |
| T-AUTORELOAD: commit to served (8 runs, `poll-interval 1`, `coalesce 200`) | 0.28-1.02 s | 1.2-2.2 s (median 1.25 s) | a few seconds | yes |
| T-RECOVER, Backend killed (`kill -9`): the server exits and was started again at once: first answer / `initial load complete` | 1.0 s / 24.2 s | 2.0 s / 33.6 s | within T-START | yes |
| T-RECOVER, loader killed: answers continue; new loader connected / has compared every zone | 1.06 s / 24.4 s | 1.1 s / 29.4 s | | |
| `karictl reload`, nothing changed | 0.04 s | 3.3 s | | |
| `karictl reload`, 1% of the zones edited | 0.29 s | 3.9 s | | |
| `karictl reload`, 10% of the zones edited, under load (see below) | 2.6 s | 17.7 s | | |

Notes:

- **There are no persisted images in this release**, so "restart" is a start: the whole database is read again. T-START is met without them for 10^7 records and for 10^6 zones on this host; the time is the time the loader needs to read and convert the database (`karidns-dbloader --dump` alone: 23.6 s for `z10k`, 27.9 s for `z1m` with one thread), the Backend adds about 0.5 s (`z10k`) and 5 s (`z1m`).
- **A restarted loader reads the whole database** (it compares every zone with the Backend's inventory before its first batch; 24 s / 29 s above). The Backend answers from its zones all the time. T-RECOVER for a killed Backend was measured by starting the server again immediately after it exited (it exits 0.06-0.16 s after the kill).
- **T-ZONEADD at 1,000,000 zones.** The first measurement missed the target because a one-zone reload read the list of all zones of the source. The loader now looks the zone up by name (`find_zone` of the drivers, an index on `domains.name`; PostgreSQL falls back to `lower()` only when the exact spelling is not found) and asks the inventory for that one name. What remains at 1,000,000 zones (0.17 s for an add, 0.64 s for a delete) is not in the loader and was not analysed (the Backend applies a view change).
- **T-AUTORELOAD** depends on `poll-interval` (SQLite3) and `coalesce`; the table uses 1 s and 200 ms. With PostgreSQL a commit is seen by `LISTEN` at once (not measured here).
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

The loader alone (`--dump`, 1 / 2 / 4 threads): `z10k` 23.6 / 12.4 / 6.7 s and `z1m` 27.9 / 15.2 / 8.3 s with SQLite3; 29.0 / 15.5 / 8.6 s and 34.4 / 19.6 / 11.5 s with PostgreSQL 18.6 on the same host (database of 2.6 GB for `z1m`). The start of `karidns` with a PostgreSQL source was not measured.

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

## SEE ALSO

- [`karidns(8)`](karidns.md) — the `database` block, database zones, settings, auto reload, several servers
- [`karictl(8)`](karictl.md) — `reload`, `dbstatus`
- [`karicheck(1)`](karicheck.md) — `karicheck db`
- [Distribution Guide](distribution.md) — the four FreeBSD packages

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

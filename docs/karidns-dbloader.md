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
karidns-dbloader -s FD [--fetch-fd FD] [--state-file PATH] [--log-stderr] [--debug N]
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
- `loader-path` (default `/usr/local/libexec/karidns-dbloader`, or `DIR/karidns-dbloader` for a build with `./configure --libexecdir=DIR`) must be a regular executable file owned by root (or by the user who runs `karidns` when that is not root) and not writable by group or others; `karidns` checks this at start and before every restart. `karicheck conf` reports a problem in advance.
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

`--state-file PATH`
: With `-s` (started by `karidns` when `loader-state-file` is set): the file the loader keeps the hot list in (D1a step 7). The loader reads it at its start, sends its zones to the Backend as `WARM_LIST` after the startup load, and writes it again (`PATH.tmp`, mode 0600, `fsync`, `rename`) when the Backend sends a `HOT_LIST`, merged with what it had. A file that is missing is the first start; one that is empty, truncated, damaged (the last line is `END <count> <checksum>`) or larger than 64 MiB is ignored with a log line and replaced by the next list. The loader user needs write permission on the **directory** of the file. The Backend never names this path to the loader (it comes from the command line the supervisor builds from `karidns.conf`), so a compromised Backend cannot make the loader write anywhere. With `--check`: check that the loader can use it (the directory exists and can be written, the file can be read and is valid); `karicheck db` passes it.

`--drivers`
: Print the compiled-in drivers, one per line, and exit.

`-s FD`
: Stream mode: `FD` is the socket to the Backend. Started by `karidns`. The loader ends when the Backend closes the stream or on `SIGTERM` / `SIGINT` (also in the middle of a long load: it stops at the next zone, within milliseconds); `SIGHUP` is ignored.

`--log-stderr`
: With `-s`: write the messages to standard error instead of syslog, one line each, `<N>[DB] text` with `N` the syslog priority (0 .. 7) and a newline at the end, at most 500 bytes (a longer text is cut and ends in `...`; control characters become `?`). `karidns` starts the loader this way, with a pipe as its standard error, reads the lines and logs them in the `database` category (see MESSAGES). Since 0.7 this includes the messages of the code the loader shares with the server (the zone checks, such as `[Zone] example.com.: using NSEC3PARAM ...`), which went to syslog before: the line is `<N>[DB] [Zone] text`. Without this option `-s` logs to syslog (identity `karidns-dbloader`, `[DB]` in front of the text). If standard error cannot be written (the pipe is closed), the message goes to syslog. It is an error without `-s`.

`--debug N`
: The debug level, 0 .. 99 (default 0): the debug messages up to it are written (0.7).  `karidns` passes the level in force when it starts the loader (`karidns -d`, `karictl trace`), so a loader started again while the level is raised comes up with it, and in stream mode the Backend tells the loader every later change (the KDB1 message `DEBUG`).  With `--log-stderr` a debug message is the line `<7:L>[DB] text`, `L` its level; without it, syslog priority `debug`; with `--dump` a line on standard error; `--check` writes none.  At level 1 the loader says when it connected (driver, file named), its level changes and its batches; at level 2 also each zone it sent (serial, size, a summary or for a fetch) or left out because the Backend has its version, each fetch request of the Backend (queued, answered busy or refused because too many wait) and a connection used again.  No debug message contains a password, the content of a conninfo file or a driver's error text (which can repeat parts of the connection string): the files are named, never read out.

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
: 1..16, default 1. N workers, each with its own database connection, read and convert disjoint sets of zones (consecutive zones in `domains.id` order); the output is written in `domains.id` order whatever N is. The workers take their snapshots after the main thread took its own (the zone list, the metadata and the keys); with SQLite3 each of them also reads the change log position of its snapshot, and if a commit came in between (a position other than the main thread's) the source is read again from the start, before anything of it is sent, up to three readings (the last one goes on and logs that a zone can be a mix of two commits until the next reload). PostgreSQL does not make this check (its change log cursor is the xmin of the snapshot). In stream mode the number comes from the configuration (`loader-threads`). The fetch stream (the zones the Backend asks for) is served by a pool of the same size: one thread reads the requests, and up to N workers (started when a request finds none idle) read one zone each on a connection of their own; the messages of one zone go out together, so zones of two workers never mix. Before, one thread read the zones one at a time (about 500 a second at 11 records a zone in SQLite3).

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

## THE HOT LIST AND THE STATE FILE

D1a step 7. With `--state-file` the loader keeps, for the Backend, the list of the zones that are asked for most (see `karidns.conf`, `loader-state-file`, `hot-list-size`, `hot-list-interval` and `warm-before-serve`). Two messages on the first stream carry it, both in parts (at most 16384 zones and 1 MiB each; the zones are named by view name and zone name, because the file outlives a reconfiguration):

- **`HOT_LIST`** (Backend to loader): the zones most asked for, hottest first, with the size the file may have. The loader checks it as it checks everything the Backend sends: at most 100000 zones, the parts in order (a part that does not follow drops the list, not the stream), a view that its CONFIG does not have is dropped, the names are canonical (the stream decoder refuses anything else). When the last part has come the loader merges it into the list of the file (the new zones first, then the zones of the old list that are not in the new one, up to the size), writes the file if the list changed, and answers **`HOT_ACK`** (written, unchanged, failed with the reason, or no file configured). A HOT_ACK is sent between two batches, never inside one.
- **`WARM_LIST`** (loader to Backend): once, after the startup load, the zones of the file in order (an empty list when the file is missing or damaged), with what the loader found in the file at its start (`loaded`, `missing`, `corrupt`, `unreadable`) for `karictl dbstatus`.

The file is text: `KARIDNS-HOT-LIST 1`, one line `view<TAB>zone` for each zone, hottest first, and `END <count> <checksum>` (FNV-1a over the entry lines, eight hex digits). **Permissions.** The loader runs as `loader-user` and writes in the directory of the file: give it a directory of its own, owned by `loader-user`, mode 0700 (`install -d -o karidns-db -m 0700 /var/db/karidns/state`). The file is created with mode 0600. The Backend, in capability mode, never opens it. The loader opens the file with `O_NOFOLLOW`, so **a state file that is a symbolic link is UNREADABLE** (`karictl dbstatus` shows `state-file: ... at_start=unreadable, ignored`), even when the link points to a good file: give `loader-state-file` the real path (a link in a directory *above* the file is fine; only the last component counts). A state file that exists and cannot be read (permissions, a link, not a regular file) is **not replaced**: the loader says so in its log and in the acknowledgement of every hot list (`failed`), and keeps going without a state file until it is fixed or removed. The count and checksum of the `END` line must have exactly the form written (decimal digits, one space, eight lower case hex digits); the limit of a list is the one its first part says. The file is not trusted when it is read: it may be damaged, or written by somebody who could write in the directory; whatever its contents, the Backend reads only zones it has in its directory, at most 100000 of them, at the rate of `fetch-rate`.

## MESSAGES

Run on its own (`--dump`, `--check`), the loader writes its messages to standard error, `karidns-dbloader: text`, as it always did (the dump tests and scripts read those lines).

Started by `karidns` (`-s`), the loader's standard error is a pipe that the supervisor (the manager process, which also restarts the loader) creates for every start: `karidns-dbloader -s 3 [--fetch-fd 4] [--state-file PATH] --log-stderr`. The loader writes `<N>[DB] text` lines; the supervisor reads the pipe without blocking and logs each line in the `database` category of BIND's `logging { }` statement, with the severity of `N` (`<3>` error, `<4>` warning, `<5>` notice, `<6>` info) and, for a debug message (0.7, `--debug`), `<7:L>` with `L` its debug level, 1 .. 99, logged at `debug L` (a channel with `severity dynamic` writes it while the debug level in force is at least `L`, `severity debug <n>` when `n` is at least `L`; the text is cut at 255 bytes), so a configuration such as

```
logging {
    channel dbfile { file "/var/log/karidns/database.log" versions 5 size 10m; severity info; print-time yes; print-severity yes; print-category yes; };
    category database { dbfile; };
};
```

collects the messages of the loader together with the `[DB]` messages of the Backend (stream, batches, installs). Example lines:

```
28-Oct-2026 12:34:56.789 database: warning: [DB] zone 'zero.example.test.' (domains.id 2): the SOA serial is 0; PowerDNS may compute the served serial (SOA-EDIT, auto-serial), but KariDNS uses the stored value as it is, so secondaries and NOTIFY see serial 0
28-Oct-2026 12:34:56.790 database: info: [DB] state file /var/db/karidns/hot.list: 12 zone(s) of the hot list
28-Oct-2026 12:35:10.001 database: warning: [DB] 480 line(s) of the loader's output were not logged (more than 50 per second)
```

A message is logged once: when the loader is supervised it does not also write to syslog (syslog is only the fallback when the pipe cannot be written), and with no `category database` the lines go to the channels of `default` / `default_syslog` like any other category. The bytes of the pipe are untrusted input of the manager, which runs with root's rights until it drops them:

- a line is cut at 512 bytes of text and ends in `...`; the rest of a longer line is read and thrown away, never kept;
- everything but printable ASCII is written as `\xNN` (a NUL, ESC, a CR that does not end a CRLF, bytes of 0x80 and above), a tab as a space, so that nothing a database name contains can start a line of the log or hide in it;
- a line without `<N>` (or `<7:L>` with `L` 1 .. 99 written without a leading 0) is logged at `notice` with the text as it is, so a line of another version is never lost; empty lines are dropped; the end of the stream or the loader's end logs a last line that has no newline;
- at most 50 lines per second are logged; the others are counted and reported by one `warning` line when their second is over (also when the loader writes nothing more);
- one read takes at most 64 KiB, and the manager looks at its signals between reads, so a loader that floods the pipe cannot keep the manager from `SIGTERM`; a full pipe makes the loader wait;
- the pipe is made for every start (close-on-exec, read end non-blocking), drained when the loader ends and then closed: restarts do not leave descriptors behind.

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
| `db/karidns_ext.sqlite3.sql` | SQLite3: schema version 3 (version 2 plus the tables `karidns_audit_log` and `karidns_audit_actor`, and `karidns_key_requests` and `karidns_signer_state` of the signer, which the loader does not use; the audit triggers are in `db/karidns_audit.sqlite3.sql`, applied when the WebAdmin or the signer is used, and the users, groups and grants of the WebAdmin in the file `db/karidns_auth.sqlite3.sql`, which the API ATTACHes: the loader never opens it). `karidns_changes` (the change log: which domain changed, written by triggers on `domains`, `records`, `domainmetadata`, `cryptokeys` and the tables below), a trigger that keeps the newest 1,000,000 log rows, `karidns_domain_views`, `karidns_profiles`, `karidns_record_tags`, `karidns_record_tinydns`, `karidns_zone_tagdefs`, `karidns_schema_version`. Apply it once, as the owner of the database, after the PowerDNS schema. It can be applied again. |
| `db/karidns_ext.pgsql.sql` | PostgreSQL: schema version 3 (version 2 plus the schema `karidns_auth`: users, groups, grants, the audit log, the RLS functions and policies; see THE AUTH SCHEMA, ROLES AND THE AUDIT LOG below). The same tables with statement-level triggers (one log row per distinct domain per statement), `NOTIFY karidns_changes` for auto reload, and the multi-server tables `karidns_reload_requests` and `karidns_server_status`. PostgreSQL 13 or newer. Apply it in the schema that holds the PowerDNS tables. |
| `db/karidns_ext_v1_to_v2.sqlite3.sql`, `db/karidns_ext_v1_to_v2.pgsql.sql` | Convert a database from schema version 1 (the extension files of the early betas) to version 2. The loader reads both versions and serves a version 1 database without a change log. |
| `db/karidns_writer_role.pgsql.sql` | PostgreSQL: the privileges of the role that [`karidns-zone`](karidns-zone.md) imports with (`psql -v role=... -v schema=...`). `SELECT, INSERT, UPDATE, DELETE` on `domains`, `records` and `domainmetadata`, the `karidns_*` zone tables, what the change-log triggers need, and only the column privilege `SELECT (domain_id)` on `cryptokeys` (never `content`, the private keys). Not for the loader: give the loader `karidns_loader_role.pgsql.sql`. |

A bulk import writes one change-log row per changed row (SQLite3) or per statement (PostgreSQL); a big import makes the next reload compare every zone once. The files carry their own documentation in their first lines.

The users, groups, grants, database roles, row level security and the audit log of the WebAdmin and the signer (the schema `karidns_auth`, `db/karidns_api_role.pgsql.sql`, `db/karidns_signer_role.pgsql.sql`, `db/karidns_audit.sqlite3.sql`, `db/karidns_auth.sqlite3.sql`) are described in THE AUTH SCHEMA, ROLES AND THE AUDIT LOG, below.

### Indexes

The extension files create `karidns_zone_tagdefs_domain_idx` on `karidns_zone_tagdefs (domain_id)` (the loader reads the tag definitions of one zone at a time; without the index every such read scans the table). It was added after schema version 2, which stays 2: apply `db/karidns_ext.*.sql` (or the `v1_to_v2` script) again to get it on an existing database.

**The loader is read-only and never creates an index.** Two optional PostgreSQL indexes on the PowerDNS tables make the big reads faster; create them yourself when the database is large:

| Index | Effect |
|---|---|
| `CREATE INDEX records_soa_cover_idx ON records (domain_id) INCLUDE (name, content) WHERE type = 'SOA' AND disabled = false;` | The zone list of every full comparison (`karictl reload`, auto reload, a loader restart) joins each domain to its apex SOA. With this partial covering index the join is an index-only merge over one row per zone. The loader looks the index up once per connection (`pg_indexes`) and then leaves the planner's `cursor_tuple_fraction` at its default (0.1) for the list; without the index it plans the list for all of its rows (`1`), which is then the faster plan. Measured at 1,000,000 zones x 11 records (`psql`, 3 runs): without the index 2.2 s planned for all rows (one pass over the SOA rows) against 2.6 s at the default (a walk of the whole `records` table through its `domain_id` index); with the index 1.7 s planned for all rows (the planner still reads every SOA row) against 1.0 s at the default (the index-only merge). |
| `CREATE INDEX domains_lower_name_idx ON domains (lower(name));` | A one-zone read of a zone that is not in the database (a deletion, a typo in `karictl reload <zone>`) falls back to `lower(d.name)`, a table scan of `domains` without this expression index (about 0.2 s at 1,000,000 zones). |

**Migration note: `records.name` of address rows must be in lower case.** When a zone is out of memory (`memory-limit`), the Backend sends its NOTIFY from the zone's summary, and the summary carries the addresses of the NS targets that are *outside* the zone (tag 22 of `ZONE_BEGIN`, `KDB_NOTIFY_ADDR_PER_NS` per name). The loader reads them with `g.name = lower(<NS target>)` (SQLite3 and PostgreSQL alike), an exact comparison that the index on `records (name)` serves; it does not fold the case of `records.name`. An A / AAAA row of such a target whose `name` has an upper case letter is not found, and that name server gets no NOTIFY while the zone is out of memory (the addresses *inside* the zone are matched case-insensitively and are not affected). PowerDNS stores names in lower case, so a database written by PowerDNS or by `zone2sql` is fine; before pointing the loader at data from another source or edited by hand, check `SELECT id, name FROM records WHERE type IN ('A', 'AAAA') AND name <> lower(name);` and fix the rows (`UPDATE records SET name = lower(name) WHERE name <> lower(name);`).

**Zone names that differ only in case are not supported.** PowerDNS stores `domains.name` in lower case, and so should the data: two rows of one source such as `Example.test` and `example.test` are two rows for PostgreSQL's case-sensitive unique index (the PowerDNS PostgreSQL schema has a `CHECK` constraint `c_lowercase_name` that refuses upper case, and SQLite3's schema declares the column `COLLATE NOCASE`; such rows only exist when a constraint was dropped or the data was written around it). The loader keeps the one-zone lookup (`--zone`, used by reload requests and auto reload) fast: it matches the indexed name exactly first and falls back to `lower()` only when that finds nothing. With such duplicates a full read and a one-zone read may therefore pick different rows. `karicheck db` (`karidns-dbloader --check`) warns about every pair of `domains` rows of one source whose names are equal ignoring case, with both `domains.id` values (both drivers); fix the data, do not rely on either row.

## THE AUTH SCHEMA, ROLES AND THE AUDIT LOG (0.6.0)

Schema version 3 adds what the WebAdmin API and the signer daemon need: users, groups and grants, database roles held to their grants by row level security (RLS, PostgreSQL only), an audit log, and the signer's two tables. The server and `karidns-dbloader` use none of it (but for the metadata `X-KARIDNS-SIGNER`, below). A database that only has the loader's and the importer's roles behaves as it did before: RLS is off and nothing is logged.

**The signer's tables (0.6.0 item C).** The daemon that uses them is [`karidns-signer(8)`](karidns-signer.md). `karidns_key_requests` and `karidns_signer_state` are in `db/karidns_ext.pgsql.sql` and `db/karidns_ext.sqlite3.sql` (per data schema, like the other `karidns_*` tables; apply the file again to a version 3 database that lacks them; the schema version stays 3). They go away with their zone (`ON DELETE CASCADE`), are covered by the audit (`enable_audit`; the SQLite3 audit file has their triggers) and write **no** row to `karidns_changes`: the signer writes its state after every run, and a signer that followed its own state would never stop.

| Table | Columns |
|---|---|
| `karidns_key_requests` | `id`, `domain_id`, `kind` (`enable` = start signing the zone: generate the first key or keys, set the metadata; `add` = one more key), `algorithm` (8, 10, 13, 14, 15, 16; default 13), `bits` (RSA only, 1024..8192), `key_type` (`csk`, `ksk`, `zsk`; default `csk`), `nsec` (`nsec3`, `nsec`; `enable` only), `state` (`pending`, `done`, `failed`), `message`, `requested_by` (a principal id), `created_at`, `done_at` (set when the state is not `pending`). The WebAdmin (a global master or the domain master of the zone) or an operator files a row; the signer answers it. A unique partial index (`karidns_key_requests_one_pending_idx`) allows **one pending request per zone**: a second one is refused until the first is answered. On PostgreSQL the WebAdmin's role may `INSERT` only the columns `domain_id`, `kind`, `algorithm`, `bits`, `key_type`, `nsec` and `requested_by` (not the state, the message, `done_at` or the id), and the signer's role may `UPDATE` only `state`, `message` and `done_at`. |
| `karidns_signer_state` | `domain_id` (the key), `signed_at`, `signed_serial`, `min_expire` (the earliest RRSIG expiration of the zone, as `karidns-zone import --signer` reports it), `next_due` (when the signer wants to look at the zone again; indexed), `attempts` (failed runs since the last success), `last_error`, `last_duration_ms`. Only the signer writes it. |
| `karidns_signer_monitor` (a view) | one row per zone with `X-KARIDNS-SIGNER` = 1 (0.6.1): `domain_id`, `zone`, the columns of `karidns_signer_state` (empty for a zone without a state row), `status` (the first that applies of `expired`, `failing`, `overdue` (`next_due` over an hour ago), `expiring` (signatures end within two days), `unsigned`, `ok`) and `seconds_to_expiry`. For a monitoring system: [`karidns-signer(8)`](karidns-signer.md), "Monitoring". PostgreSQL: it is the owner's and does not apply the reader's row level security; grant `SELECT` on the view to the monitoring role and on nothing else. |

PostgreSQL stores the times as `timestamptz`; SQLite3 as unix seconds (`INTEGER`), like `karidns_changes.changed_at`.

**The zones of the signer (`X-KARIDNS-SIGNER`).** `karidns-zone import --signer` writes the metadata `X-KARIDNS-SIGNER` = `1` on a zone the signer keeps signed. The server and the loader know it in one place: with `database { signer-wait yes; }` (the default) the loader does not reload such a zone because of the change log or a moved serial, only on a reload request or in a full comparison, so a change that is not signed yet is not served ([`karidns(8)`](karidns.md), "The signer's zones"). **PowerDNS** on the same database reads it live and serves a change at once, signed or not: there the zone is only as safe as the order of the writes; keep PowerDNS and the signer apart, or let the signer be the only writer of a signed zone's DNSSEC records.

### What version 3 adds

PostgreSQL (`db/karidns_ext.pgsql.sql`)
: The schema `karidns_auth` with the tables `principals`, `credentials`, `memberships`, `principal_closure`, `rr_policies`, `grants`, `audit_log` and `schema_version`; the functions and triggers that keep them consistent; the RLS policies for the tables of the data schema (they do nothing while RLS is off); and the audit triggers of `karidns_auth` itself. There is one `karidns_auth` for the whole database, shared by every data schema (a view that has a schema of its own applies the same file there and adds its own triggers and policies).

SQLite3
: `db/karidns_ext.sqlite3.sql` adds the tables `karidns_audit_log` and `karidns_audit_actor` to the zone file. The users, groups and grants live in a file of their own, `db/karidns_auth.sqlite3.sql`, so that the loader, which only opens the zone file, can never read a password hash. SQLite3 has no roles and no RLS: the API does the checks that PostgreSQL does in the policies.

Items D and E (the API, templates, zone versions) add tables and functions to version 3 in the same way (below, "The API tables, the zone generation and versions, and the check role"). Both: the version row says 3 (`karidns_auth.schema_version` and `karidns_schema_version`). The loader and `karicheck db` read versions 1, 2 and 3. There is no v2-to-v3 file: apply the version 3 file again and the database becomes version 3 (it only adds objects). Version 1 needs the `v1_to_v2` file first.

### Files and the order to apply them

1. The PowerDNS schema (from PowerDNS, not part of KariDNS).
2. PostgreSQL: `db/karidns_ext.pgsql.sql`, as the owner of the PowerDNS tables, who needs `CREATE` on the database (for `CREATE SCHEMA karidns_auth`). Once per data schema; it can be applied again. SQLite3: `sqlite3 zones.sqlite3 < db/karidns_ext.sqlite3.sql`, and `sqlite3 auth.sqlite3 < db/karidns_auth.sqlite3.sql` as the user of the API.
3. The roles of the tools, as an administrator, once per data schema: `db/karidns_loader_role.pgsql.sql` (the server's loader), `db/karidns_writer_role.pgsql.sql` (`karidns-zone`), `db/karidns_api_role.pgsql.sql` (the WebAdmin API), `db/karidns_signer_role.pgsql.sql` (the signer). They can be run in any order and again.
4. `GRANT karidns_rls_trusted TO <the PowerDNS gpgsql role>;` and the same for every other role that must see everything (backup, monitoring). The loader and writer scripts do it for their role.
5. SQLite3 only, when the API or the signer is used: `sqlite3 zones.sqlite3 < db/karidns_audit.sqlite3.sql` (the audit triggers).

```
psql -v ON_ERROR_STOP=1 -f db/karidns_ext.pgsql.sql karidns
psql -v ON_ERROR_STOP=1 -v role=karidns_api    -v schema=public -f db/karidns_api_role.pgsql.sql karidns
psql -v ON_ERROR_STOP=1 -v role=karidns_signer -v schema=public -f db/karidns_signer_role.pgsql.sql karidns
```

The ext file only creates things. RLS and the audit triggers on the PowerDNS tables are switched on by the API and signer role scripts (`karidns_auth.enable_rls()`, `enable_audit()`); switching RLS on in the ext file would hide every row from the loader, from `karidns-zone` and from PowerDNS itself. `karidns_auth.disable_rls('public')` and `disable_audit('public')` switch them off again.

### Users, groups and tenants

A **principal** is a user or a group (`principals.kind`). Names are unique ignoring case. A **user** may have `credentials` (a password hash as a PHC string, `$argon2id$` or `$scrypt$`: the database checks the prefix only; an opaque TOTP secret, which the API should store encrypted with a key of its own; an OIDC issuer and subject; failed-login and lock fields). Only the API role reads the credentials, and only a user's own row and, for a global master, all of them.

A **membership** puts a user or a group into a group. Groups nest, at most 8 deep; a cycle is refused, and so is a user as a group. `principal_closure` lists every principal with all the groups it is in, directly or not (plus itself at depth 0); triggers keep it, so a policy joins it instead of recursing. A group that is in no group is a **tenant**; a principal's tenants are the top groups of its closure. The database only stores this; the API uses it ("grant only inside my tenant", lists). A disabled principal, or a grant held through a disabled group, counts for nothing.

### Record policies (`rr_policies`)

A grant carries a record policy: `allowed_types` (a list; never a DNSSEC-managed type: `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `DNSKEY`, `CDS`, `CDNSKEY`; `DS` is an ordinary type), `allow_wildcard`, `allow_delegation` (`NS` below the apex), `allow_dname`, `apex_editable`, `ttl_min` and `ttl_max`, and `max_rr`. All the flags default to false. The database enforces everything but `max_rr`, which the API checks.

### Grants

A grant gives a principal a role on zones. The zone is named by **(data schema, zone name)**, not by `domains.id`: there is one `karidns_auth` and several data schemas, and in SQLite3 the grants are in another file. Names are stored lower case without the final dot.

`global_master`
: Every zone of the database. Its record policy still limits the records it may write.

`domain_master`
: One zone: all its records that the record policy allows.

`subdomain_master`
: One zone, and only the names at or below a suffix inside it (at a label boundary: `evilsub.example.com` is not under `sub.example.com`). It may not change the apex.

The principal's effective grants are its own and those of every group it is in. A trigger on `domains` removes the grants of a zone that is deleted and renames them when the zone is renamed, so a grant never moves to a new zone of the same name that someone else creates later. On SQLite3 the API does this cleanup itself (the grants are in another file).

**No escalation.** A trigger on `karidns_auth.grants` binds the sessions of the API role (and of every role that is a member of it; the owner and other roles are the operator and are not bound). A global master may grant anything. A domain master may grant `domain_master` or `subdomain_master` on its own zone, with a record policy that is a **subset** of the one it holds (fewer types, no flag it lacks, a TTL range inside its own, `max_rr` not higher; no limit counts as the highest). A subdomain master may not grant. A grant may be deleted by a global master, or by a domain master of the zone for a grant it could have made. `granted_by` and `granted_at` are set by the trigger. A record policy that a global master changes later is trusted.

### Roles (PostgreSQL)

The role scripts take `-v role=` and `-v schema=`, so a site can name its roles. Each script revokes every earlier privilege of its role on the tables of the schema first.

| File | The role |
|---|---|
| `db/karidns_api_role.pgsql.sql` | The role the API connects as (created `NOLOGIN` if it does not exist: `GRANT` it to the login role, which must not be a member of `karidns_rls_trusted`). `SELECT, INSERT, UPDATE, DELETE` on `domains`, `records`, `domainmetadata` and the `karidns_*` zone tables, only the column privilege `SELECT (id, domain_id, flags, active, published)` on `cryptokeys` (never `content`), the users, groups, grants and credentials of `karidns_auth` (the only role that reads `credentials`), `SELECT` on the audit log, `EXECUTE` on `karidns_auth.bump_serial()`. `SELECT` and `INSERT` (no `DELETE`) on `karidns_reload_requests`; nothing on `karidns_changes`. No `TRUNCATE`, no write to the audit log. It switches RLS and the audit log on. The script stops, before it changes anything, if the role is a superuser or has `BYPASSRLS`, is a member of `karidns_rls_trusted`, or is, or is a member of, the owner of the tables (directly or through other roles). |
| `db/karidns_signer_role.pgsql.sql` | The signer: reads every table including `cryptokeys.content` and the change log `karidns_changes` (it follows the log to see which zones changed); inserts and deletes the DNSSEC-managed record types; updates records (a trigger decides what: below); writes the metadata kinds `PRESIGNED`, `NSEC3PARAM` and `X-KARIDNS-SIGNER`; inserts reload requests and new keys (`INSERT` on `cryptokeys`, no `UPDATE` or `DELETE`); answers the key requests (`SELECT`, and `UPDATE` of the columns `state`, `message` and `done_at` only, on `karidns_key_requests`); keeps its schedule (`SELECT`, `INSERT`, `UPDATE`, `DELETE` on `karidns_signer_state`). Nothing on `karidns_auth`, nothing written to `karidns_changes`. It is a trusted daemon held to its types by RLS and a trigger, not bound by grants, and its role is **not** in `karidns_auth.audit_restricted_roles` (`karidns-zone import --signer` writes the audit in summary mode: a re-sign replaces every signature, and a row per signature is a log that nobody reads). Its write policies of `records` and `domainmetadata` exist twice, permissive and `RESTRICTIVE`, so setting `karidns.principal` to a global master does not let it write an `A` record. The trigger on `records` (for the roles in `karidns_auth.signer_roles`) holds it to its columns: a DNSSEC record may change in any column; **every other record only in `ordername` and `auth`** (the NSEC3 hash of its owner and the authoritative flag, which a signature chain needs; the trigger is declared `BEFORE UPDATE OF` every column but those two, so it does not fire for an `UPDATE` of just those two, like `pdnsutil rectify-zone`'s, and costs nothing there); an SOA row only in its serial, `ordername` and `auth` (type, name, domain, TTL, priority, the flag and the rest of the content stay), and it neither inserts nor deletes an SOA. The same refusals as for the API role apply at install time. |
| `db/karidns_check_role.pgsql.sql` | The check role of the API (items D and E): the writer role's privileges, membership of `karidns_rls_trusted` and of `karidns_never_commit`, `USAGE` on `karidns_auth` and `EXECUTE` on `bump_serial`; its transactions cannot commit a write (below). |
| `db/karidns_loader_role.pgsql.sql`, `db/karidns_writer_role.pgsql.sql` | As before, plus membership in `karidns_rls_trusted`. Nothing on `karidns_auth`. The loader and `karidns-zone` read and write everything with RLS on, in either script order. |
| the owner | Owns everything and is not subject to RLS (no `FORCE`). The only role that may `UPDATE` or `DELETE` audit rows. |

Nobody gets `BYPASSRLS` or superuser.

### What row level security checks

The API sets `SET LOCAL karidns.principal = '<id>'` in every transaction; the policies read it. A missing, empty or non-numeric setting, a principal that does not exist and a disabled principal are all "no principal": no rows, no writes.

A row is **writable** when one effective grant of the principal covers it: the name is in the grant's scope, the type is allowed and not DNSSEC-managed, the TTL (NULL counts as 0) is in the policy's range, a wildcard label needs `allow_wildcard`, `NS` below the apex needs `allow_delegation`, `DNAME` needs `allow_dname`, and the apex needs `apex_editable` and a role other than subdomain master. Two grants never combine for one row. The SOA changes only through `karidns_auth.bump_serial(schema, domain_id)` (adds 1, RFC 1982; any grant on the zone may call it), or for a global master whose policy allows it. The type names `TYPE2`, `TYPE6`, `TYPE39` and `TYPE46` ... `TYPE60` are read as the names they stand for, so an alias gets the rules of the name. A record outside its zone, a row without a name and (outside the apex) an empty non-terminal follow the same scope rule.

A row is **visible** when a grant of the principal reaches it: a domain master sees the records of its zone, a subdomain master those of its suffix, a global master every zone; the SOA and the apex `NS` are visible to every grant on the zone. A row without a name, a row whose name is outside its zone and a row without a zone are invisible to the API, a global master included (the owner repairs them). A trailing dot of `domains.name` is ignored.

The signer's tables follow the same rule: a global master or the domain master of the zone files a key request (`INSERT` into `karidns_key_requests`: state `pending`, no message, `requested_by` the acting principal itself) and sees the requests of its zones; any grant on the zone reads `karidns_signer_state`; the API cannot change either table (the signer does).

The other tables follow the zone: `domains`, `domainmetadata`, the tag tables, the key table (without `content`) and the views are visible to a grant on the zone; a global master writes `domains`, `domainmetadata` (not the kinds the signer owns) and `karidns_domain_views`; a domain master writes `karidns_zone_tagdefs`; the tag rows of a record follow the record. `principals`, `memberships` and `rr_policies` are readable by every API session (a login looks the user up by name before it has a principal id) and changed by a global master. The audit log is visible to a global master (all of it) and to a domain master (the rows of its zones).

**What the API must check itself.** The database cannot see: that one grant allows a whole change set (it checks each row alone), `max_rr`, a CNAME beside other data and the other zone checks (`karicheck --json`), and that a change set stays in one zone.

### karidns_rls_trusted

The policies bind every role that is not a member of `karidns_rls_trusted`, a `NOLOGIN` role the scripts create. A role that must see and write everything joins it: the loader and writer scripts do it for their role, and for the PowerDNS `gpgsql` backend's role and any other role you run

```
GRANT karidns_rls_trusted TO <the PowerDNS gpgsql role>;
```

A role that uses the tables without it is refused (no rows, or `permission denied for function`) once RLS is on. The table owner is not subject to RLS and is the "operator" for the grant trigger: do not make the owner a member of the API role. The maintenance triggers of the data tables (the change log `karidns_changes` and its prune, the reload requests and their prune) run as the owner with a pinned `search_path`, so the API and signer roles need no right on the change log and cannot read, forge or delete it.

### The trust boundary

`karidns.principal` is a custom setting that any session can set. The API is trusted to set it to the logged-in user. RLS catches the API's own mistakes (a missing `WHERE`, a wrong zone id); it does not stop a compromised API process or a stolen database password of the API role. That is why the API role gets nothing of `cryptokeys.content`, nothing of what the signer or the owner may do, and no way to change or delete audit rows. Treat the API's database password like the key to every zone it has a grant on.

### The audit log

With the audit triggers on, every change of the tables of the data schema and of `karidns_auth` is logged. PostgreSQL: `karidns_auth.audit_log`; SQLite3: `karidns_audit_log` in the zone file and `karidns_auth_audit` in the auth file. The columns:

| Column | Meaning |
|---|---|
| `id`, `at` | A running number, the time. |
| `xid` | The transaction (PostgreSQL), to group the rows of one commit. |
| `db_role` | The database role (the role after `SET ROLE`, else the login role). `karidns-zone` on SQLite3: `karidns-zone:<OS user>`. |
| `principal_id`, `principal_name` | `karidns.principal` of the session and its name (copied, so it survives the deletion of the principal). NULL without one. |
| `change_set` | `karidns.change_set` of the session: the API's change set. |
| `data_schema`, `table_name`, `op`, `zone_name`, `row_id` | Where: the table, `I`, `U` or `D`, the zone, the row's id. |
| `before`, `after` | The row as JSON. |

**Redaction.** `cryptokeys.content`, `credentials.password_hash` and `credentials.totp_secret` are written as `"<redacted>"`: the API reads the audit log, and keys and secrets must not reach it.

**Summary mode.** A big import writes two rows per record (the old row and the new one). A role other than the API role may `SET LOCAL karidns.audit = 'summary'` (`karidns-zone import --audit summary` does, and `import --signer` does by default): the audit then writes one row per transaction, table, operation and zone that counts the statements and the rows (`{"summary": true, "statements": 100000, "rows": 100000}`), filled in when the transaction commits. The API role and any role that is a member of it (also after `SET ROLE`) cannot turn the detail off; the restricted roles are the rows of `karidns_auth.audit_restricted_roles`, which only the owner writes. The tables of `karidns_auth` are always logged row by row. SQLite3 has no summary mode.

**Append only.** Only the owner has `INSERT`, `UPDATE` or `DELETE` on the log; the triggers are `SECURITY DEFINER` and insert as the owner. Nobody gets `TRUNCATE`, and a `TRUNCATE` of an audited table is not logged (use `DELETE`).

**Pruning.** Nothing is pruned automatically. The owner deletes by date:

```
DELETE FROM karidns_auth.audit_log WHERE at < now() - interval '1 year';
```

Run it in batches on a big log (`WHERE id IN (SELECT id ... LIMIT 100000)`) and `VACUUM` afterwards. At scale, partition the table by month (declare `audit_log` partitioned by `at` and drop old partitions); that needs a migration of the table and is planned for 0.7.

### SQLite3

- The audit triggers are in `db/karidns_audit.sqlite3.sql`; a site that does not use the API or the signer does not apply them and logs nothing. Persistent triggers can only read their own database, so the actor lives in the zone file: `karidns_audit_actor` has one row (principal, change set, database role). SQLite3 has one writer at a time (`BEGIN IMMEDIATE`): the API writes the actor row first in its transaction and deletes it last. A writer that does not is logged with a NULL principal. `karidns-zone` writes its own row (`karidns-zone:<OS user>`) and deletes it before the commit.
- The auth file holds the principals, credentials, memberships, record policies and grants. Its own changes are logged by triggers into `karidns_auth_audit` in the auth file. **The auth file belongs to the user of the API and has mode 0600**; the loader's user must not be able to read it (it holds the password hashes). Run `PRAGMA foreign_keys=ON` on the connection.
- The checks that need no API are in the file: the `CHECK` constraints, users only in `credentials`, no cycle, depth 8, and the closure table. What PostgreSQL does in policies and in the escalation trigger, the API must do on SQLite3, and it must delete or rename the grants of a zone it deletes or renames.

### The API tables, the zone generation and versions, and the check role (0.6.0 items D and E)

The API with permission checks, the zone templates and the zone versions add these objects to schema version 3 (the version row stays 3: 0.6.0 is not released). **The server, `karidns-dbloader` and `karicheck db` use none of them**: they do not read the tables, and a database that has them passes `karicheck db` and the loader's schema check as it did without them. The commands that use them are `karidns-zone apply` and `import` (generation, versions) and the WebAdmin API ([`karidns-webadmin`](karidns-api.md): `GET /auth/me`, the sessions, tokens, principals, policies, grants and the audit log are these tables).

| Table | Where | What it holds |
|---|---|---|
| `karidns_zone_state` | each data schema / the zone file | `domain_id`, `generation`, `changed_at`: the **generation** of the zone. Written by the triggers of the owner only (PostgreSQL: `karidns_log_domains()`, the function that writes the change log, grows it the first time a transaction changes a zone, so a row-by-row import of a million records bumps it once; SQLite3: the trigger `karidns_changes_generation` on `karidns_changes`, once per changed row). It follows exactly the set of tables that write `karidns_changes`. A zone with no row has generation 0. `ON DELETE CASCADE`. |
| `karidns_zone_versions`, `karidns_zone_version_rrsets` | each data schema / the zone file | The **versions** of a zone, one row per committed change set: `version` (per zone, from 1), `kind` (`create`, `edit`, `template`, `import`, `rollback`), `change_set`, `principal_id`, `principal_name`, `db_role`, `at`, `comment` (1 KiB), `serial_before`, `serial_after`, `generation_before`, `generation_after`, `rollback_of`, `delta_complete`; and the RRsets the version changed (`owner` in the form of `records.name`, `type`, `before` and `after`: canonical lines `<ttl> <TYPE> <rdata>` joined by LF, NULL for absent). The newest 100 versions per zone are kept (a constant in `karidns_zone_versions_prune_fn` / the trigger `karidns_zone_versions_prune`). Not audited: they are derived from the audited rows. |
| `sessions`, `api_tokens` | `karidns_auth` / the auth file | Browser sessions and API tokens: the SHA-256 of the cookie (`id_hash`) and of the CSRF token (`csrf_hash`), `principal_id`, times (`created_at`, `last_seen`, `expires_at`), `totp_ok`, `client`; for a token its `name`, `secret_hash`, `read_only`, `expires_at` (at most 366 days after `created_at`), `last_used_at`, `revoked_at`. Deleted with their principal. The audit writes the hashes as `<redacted>` and does not log a change of `last_seen` alone. |
| `oidc_states` | `karidns_auth` / the auth file | The state of a sign-in with an OpenID Connect provider that has started and not come back (item F, milestone M5): the SHA-256 of the `state` parameter (the key) and of the cookie that ties the flow to the browser, the provider's name, the nonce, the PKCE code verifier, the route to return to, `created_at`, `expires_at` (ten minutes; at most an hour by a constraint). Used once: read and deleted by the callback. Not audited. **PostgreSQL: the API role has no privilege on the table**; it calls the SECURITY DEFINER functions `oidc_state_put(...)` (false when 1000 are waiting), `oidc_state_take(state_hash)` (returns the row of an unexpired state and deletes it) and `oidc_lookup(issuer, subject)` (the id of the user, not disabled, whom the identity `credentials.oidc_issuer`, `oidc_subject` is linked to), and `sweep_expired()` deletes the states that are over. |
| `templates`, `template_records` | `karidns_auth` / the auth file | Zone data templates: name, description, `revision` (grows by one with every change of the template or of a record), the SOA defaults (`soa_mname`, `soa_rname`, `soa_refresh`, `soa_retry`, `soa_expire`, `soa_minimum`); the records `(template_id, ordinal)` with `owner` (`@` or a relative name in lower case, no final dot), `type` (no DNSSEC type), `ttl`, `content`. Written by a global master, read by every principal; audited. |

**Row level security (PostgreSQL).** `sessions` and `api_tokens`: the principal's own rows, a global master all of them. `templates` and `template_records`: everybody reads, a global master writes. `karidns_zone_state`: readable with a grant on the zone. `karidns_zone_versions`: readable with a grant on the zone, insertable by the principal itself (`principal_id = karidns.principal`); `karidns_zone_version_rrsets`: readable and insertable by the rule of `rr_visible` (a subdomain master reads the history of its names only). Nobody with an API policy updates or deletes a version. A request that carries only a cookie or a token cannot find its row under those policies, so two SECURITY DEFINER lookups return the row of an unexpired credential of a principal that is not disabled and nothing else: `karidns_auth.session_lookup(id_hash)` and `karidns_auth.api_token_lookup(id, secret_hash)` (`EXECUTE` is granted to the API role). A third SECURITY DEFINER function, `karidns_auth.sweep_expired()`, deletes the sessions whose absolute time is over, of every principal (the policy shows the API role the rows of its own principal only): the hourly sweep of the API calls it. The API role also gets `SELECT` on `karidns_server_status`. A fourth SECURITY DEFINER function, `karidns_auth.prune_audit(days)` (0.6.1), deletes the audit rows older than `days` days (at least 7, the oldest 10,000 a call): no role has a right on `audit_log`, so this is how the WebAdmin's option `audit-retention` prunes it; it is granted to the API role only.

**Why the generation counts every change.** The signer's re-sign writes DNSSEC records, the ordername and auth of other records, the SOA serial and its own metadata, and the trigger counts them like any other change; skipping some rows would need the content of an SOA to be parsed in SQL on both databases and would leave a hole in "every writer bumps it". The price is that a signed zone can make a commit run of the API fail with "changed" once per signing, which the API repeats; the "changed outside the API" mark of the version list (a gap between `generation_after` of one version and `generation_before` of the next) is therefore noisy on signed zones and the API ignores a gap in which only DNSSEC rows and the SOA serial changed.

**The check role (`db/karidns_check_role.pgsql.sql`).** A change set of a subdomain master is checked against the whole zone, and row level security shows the API's session only the part its principal has a grant on. The API therefore runs `karidns-zone apply --dry-run` as a **check role**: a member of `karidns_rls_trusted` (it sees every row and passes every write policy) that **can never commit**. The script makes the role a member of the group role `karidns_never_commit` and attaches to every table the dry run writes (`domains`, `records`, `domainmetadata`, the `karidns_*` zone tables, `karidns_changes`, `karidns_zone_state`, the version tables, `karidns_key_requests`, and `karidns_auth.audit_log`) a deferred constraint trigger, `karidns_auth.enable_never_commit(schema)`, whose function raises at COMMIT for a session whose login role (`session_user`) is a member of `karidns_never_commit` and is not a superuser. The test is two built-in calls in the `WHEN` condition, so other roles pay almost nothing. `SET ROLE`, `SET CONSTRAINTS ALL IMMEDIATE` and a `PREPARE TRANSACTION` do not get around it (the last fires deferred triggers; keep `max_prepared_transactions` at 0 anyway), and the role cannot drop the triggers (it owns nothing). The script refuses a superuser, the owner of the tables (or a member of it) and a member of an API role (`karidns_auth.assert_check_role()`), grants the writer role's privileges (by running `db/karidns_writer_role.pgsql.sql` for the role), `USAGE` on `karidns_auth` and `EXECUTE` on `karidns_auth.bump_serial`. Use a login role of its own for it. `karidns_auth.disable_never_commit(schema)` removes the triggers; do it before you drop `karidns_never_commit`.

**Migration.** There is no new schema version. A database made before these objects (version 2 or version 3) gets them when the files are applied again: PostgreSQL `db/karidns_ext.pgsql.sql` (once per data schema, as the owner; it creates `karidns_zone_state` with a row of generation 0 for every zone, the version tables, the `karidns_auth` tables and functions, the new triggers and policies, and replaces `karidns_log_domains()`), then the role scripts again (`db/karidns_api_role.pgsql.sql`, `db/karidns_writer_role.pgsql.sql`, `db/karidns_signer_role.pgsql.sql`, the new `db/karidns_check_role.pgsql.sql`; they grant on the new tables and create the policies; the loader role needs nothing, it already reads every `karidns_*` table); SQLite3 `db/karidns_ext.sqlite3.sql` on the zone file, `db/karidns_audit.sqlite3.sql` if the audit is used, and `db/karidns_auth.sqlite3.sql` on the auth file. Applied again, every file only adds objects. `tests/run_db_schema_migrate_test.sh` runs it.

### What RLS and the audit cost

Measured on 2026-11-06 with `tests/perf/auth_rls_bench.sh` on the FreeBSD 15.1 build host (4 vCPU, shared with other jails), PostgreSQL 18.6 with `shared_buffers` 128 MB, `fsync` off, a private cluster. Each figure is the median of 3 runs, each run a new connection. The big zone has 100,000 records; the user is in a group that is domain master of it. Times are the client's, with the rows sent to `/dev/null`.

| What | Without RLS (the owner) | `karidns_api`, RLS on | Notes |
|---|---|---|---|
| `SELECT *` of the 100,000 records of the zone, domain master | 33.6 ms | 193.9 ms | 5.8 times; 150 ms on a connection that is already warm |
| the same with 100,001 zones and 10,002 grants in the database | 35.6 ms | 207.1 ms | the grant lookups are by index: the time stays flat |
| the same, global master | 33.6 ms | 745 ms (815 ms) | every row also checks its name against its own zone |
| `SELECT count(*)` of the zones, a user with one zone out of 100,001 | - | 9.0 ms | 1,330 ms before the grants were read once per statement |
| one record by name | - | 2.7 ms | |
| change set: `INSERT` of 1,000 records (one statement, one transaction) | 82 ms (15 ms with the audit off) | 172 ms (155 ms with 100,001 zones) | |
| change set: `UPDATE` of 1,000 records | 85 ms (24 ms with the audit off) | 257 ms (234 ms) | the policy is checked for the old and the new row |
| change set: `DELETE` of 1,000 records | 80 ms (13 ms with the audit off) | 166 ms (156 ms) | |

The owner's change sets above have the audit triggers on (the API scripts switch them on); the figures in brackets are the same measurement with the other 100,000 zones and 10,000 grants. The cost of RLS on a read is the checks that make a row visible: the name must be inside the zone (and, for a subdomain master, inside its suffix). Writes are checked row by row with the full rules. The grants are read once per statement, not once per row; the lookups use the indexes `grants (data_schema, zone_name)` and `grants (principal_id)` and the key of `principal_closure` (an index-only scan of 0.02 ms, the whole lookup 0.04 ms). The measurement used 100,000 zones and 10,000 grants because the host is shared; the lookups are by index, so more zones should not change them.

`karidns-zone import` (replace mode, `--serial keep`) of the same 100,000 records as the writer role, a zone that already has them (so 100,000 rows are deleted and inserted again), RLS on:

| Audit | Time | Audit rows |
|---|---|---|
| off (`karidns_auth.disable_audit('public')`) | 17.2 s | 0 |
| on, `--audit rows` | 36.1 s (2.1 times) | 200,000 |
| on, `--audit summary` | 35.7 s | 2 |

The audit costs about 0.1 ms per changed row (the row trigger builds the JSON of the old and the new row and looks up the zone) or, in summary mode, about 0.2 ms per statement (the importer inserts one row per statement). Summary mode saves the space of the log, not the time. Both figures include the statement triggers with transition tables and the maintenance triggers that run as the owner (the change log; the trigger of the signer is described next).

**The trigger of the signer and what it costs the others.** The trigger `karidns_signer_soa_upd` on `records` is `BEFORE UPDATE OF <every column but ordername and auth> FOR EACH ROW`, so an `UPDATE` of just `ordername` and `auth` (the signer's own, `pdnsutil rectify-zone`'s) never calls it. The column list is part of the trigger (it is read from the table when `db/karidns_ext.pgsql.sql` is applied, so a column a later PowerDNS adds is covered when the file is applied again), and PostgreSQL will not drop a listed column of `records` while the trigger exists: `DROP TRIGGER karidns_signer_soa_upd ON records` first, then apply the file again. For any other `UPDATE` it runs once per row for **every** role, the operator's and PowerDNS's too, and asks `karidns_auth.is_signer_caller()` first: is the login role or the `SET ROLE` role one of the rows of `karidns_auth.signer_roles` or a member of one? That function does not run a recursive query: `pg_has_role(.., 'MEMBER')` walks the memberships through the backend's own cache, a superuser (the operator; the role scripts refuse a superuser as the signer) is answered from the server's `is_superuser` setting (with `SET ROLE` in use the login role's `rolsuper` is looked up, because `pg_has_role` says yes for every superuser), and the answer is **not** cached in a transaction-local setting: any session can set a custom setting, so a signer could write "I am no signer" before its first `UPDATE`. For a signer the row is then compared as JSON without `ordername` and `auth`, and an SOA row is held to its serial. Measured on PostgreSQL 18, FreeBSD, 100,000 rows of `records` (one `UPDATE` of all of them by the owner, median of five runs after a `VACUUM`): `SET ttl = ttl + 1`: 4.3 s with the former trigger (a `WHEN` clause with `canon_type()` and two `to_jsonb()` per row, and a recursive query in `is_signer_caller()`), 0.90 s now, 0.69 s with no signer trigger at all; `SET content = content`: 2.1 s, 0.87 s, 0.69 s; `SET ordername = .., auth = ..`: 2.1 s, 0.72 s (the trigger does not fire), 0.69 s.

**A re-sign writes a few change-log rows and `NOTIFY`s.** `karidns-zone import --signer` does not write a record per statement: the DNSSEC records are deleted by a `DELETE ... WHERE id = ANY(...)`, inserted by one `INSERT ... SELECT FROM unnest(...)` and the ordername and auth of the other records updated by one `UPDATE ... FROM unnest(...)` (a statement for every 20,000 rows or 200,000 ids). The change log (`karidns_changes`) and the audit in summary mode are written by statement triggers, so a zone of 2000 hosts, signed again, gives 5 rows in `karidns_changes` and 3 in the audit log (`tests/run_karidns_zone_pg_test.sh`), and `NOTIFY karidns_changes` a few times, not once per record. SQLite3 runs the single-row statements: its triggers fire per row, so the change log has a row per changed row there (one write transaction, one `NOTIFY`-less poll of `PRAGMA data_version` for the loader) and the audit a row per row.

## PACKAGES

`packaging/freebsd/build_pkg.sh --db none|sqlite3|postgresql|both` builds four FreeBSD packages from the same server and tools; only the loader and its dependencies differ. They install the same files, so they `conflicts` with each other (install one).

| Package | `karidns-dbloader` | Dependencies added |
|---|---|---|
| `karidns` | not installed | none |
| `karidns-sqlite3` | SQLite3 driver | `databases/sqlite3` |
| `karidns-postgresql` | PostgreSQL driver | `databases/postgresqlNN-client` (libpq; NN is the version the build host linked) |
| `karidns-db` | both drivers | both |

The database packages install `/usr/local/libexec/karidns-dbloader` (root:wheel, mode 0555), [`karidns-zone`](karidns-zone.md) (`/usr/local/bin/karidns-zone`, with the same drivers, and its manual), this manual, and the SQL files of their drivers in `/usr/local/share/karidns/db/`. The signer daemon [`karidns-signer`](karidns-signer.md) is a package of its own (`karidns-signer`, [Distribution Guide](distribution.md), 2.6). In a package without the loader `karicheck db` reports `DB support is not installed`. See [Distribution Guide](distribution.md).

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
karidns-dbloader 0.6.2
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

`/usr/local/bin/karidns-zone`
: The importer and exporter of zones (database packages; [`karidns-zone(1)`](karidns-zone.md)).

`/usr/local/libexec/karidns-signer/`, `/usr/local/sbin/karidns-signer`
: The signer daemon and its wrapper (the package `karidns-signer`; [`karidns-signer(8)`](karidns-signer.md)).
`/usr/local/share/karidns/db/`
: The SQL files above (database packages; `db/` in a source tree).

the file of `loader-state-file` (default: none)
: The hot list (above), text, mode 0600, written by the loader in its own directory.

`tests/db/gen_sqlite3_zones.sh`
: The generator of the measurement databases (source tree).

`tests/db/gen_pgsql_zones.sh`
: The same data set in a PostgreSQL database (source tree).

## SEE ALSO

- [`karidns(8)`](karidns.md) — the `database` block, database zones, settings, auto reload, several servers
- [`karictl(8)`](karictl.md) — `reload`, `dbstatus`
- [`karidns-zone(1)`](karidns-zone.md) — import and export of zones (writes the tables this loader reads)
- [`karidns-signer(8)`](karidns-signer.md) — keeps the zones signed; uses the signer tables, role and reload requests described here
- [Distribution Guide](distribution.md) — the four FreeBSD packages

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

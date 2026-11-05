# KARIDNS-ZONE(1) — KariDNS Zone Importer and Exporter

## NAME

**karidns-zone** — writes a zone file into a PowerDNS 5.1 database (`import`) and a zone of the database into a zone file (`export`)

## SYNOPSIS

```text
karidns-zone import [options] <zone> <file|->
karidns-zone import --all [options] <tinydns-data-file>
karidns-zone export [options] <zone> [<file>]
karidns-zone export --all --dir <dir> [options]
karidns-zone --version | -h | --help
```

## DESCRIPTION

`karidns-zone` is the command line of the 0.6.0 ZoneImporter and ZoneExporter. It reads the settings of the database the way [`karidns-dbloader(8)`](karidns-dbloader.md) and `karicheck db` do (the `database { }` block and the views of `karidns.conf`), or takes them from the command line. It is an ordinary program: it runs as an ordinary user and never needs root. The server and the loader do not use it; it is how zone files get into the database and out of it again (backups, the DB-outage fallback below, a signer that writes its records through `--types`).

- **import** reads a zone file (BIND format, with `$INCLUDE`, `$GENERATE`, `$LOCATION` and `$ECS-SUBNET` tags; or a tinydns data file) with the parser of the server and writes the zone as rows of the PowerDNS schema, in ONE transaction per zone: owners in lower case without the final dot, MX and SRV priorities in `prio`, a signed zone in the layout PowerDNS stores for a zone with `PRESIGNED=1` (see [`karidns(8)`](karidns.md), "Database zones"), tags and tinydns attributes in the `karidns_*` tables. It does not run SQL text: every value is a bound parameter.
- **export** writes a zone of the database as a zone file. The zone is read the way the loader reads it (every row checked, a presigned zone with the NSEC3PARAM / NSEC3 / NSEC records the server rebuilds), so what is exported is what the server serves. The text is in **canonical order** (RFC 4034 section 6.1, owner names first, then type, then RDATA), so two exports of the same zone are the same file and `diff` shows the real change. The text is parsed again before a byte is written and must give the same records.

### What an import does

1. Reads the text (a file, `-` for standard input, at most 64 MiB there) and parses it. A syntax error names the file and the line.
2. Runs the checks of `karicheck zone` on it (with the `check-*` options of the configuration, below). An **error** fails the import and nothing is written. A **warning** is printed and the import goes on; `--strict` makes a warning fail it.
3. In one transaction: finds the zone or creates it, applies the serial rule, deletes and inserts the rows, puts the zone in the view, adds the reload request.
4. **Reads the zone back in the same transaction** through the loader's reader (`dns_pdns_reader.c`), applies the size limits of the configuration and the checks of `karicheck db` to it, and commits **only if the loader would load what was written.** A merge that puts a CNAME beside other data, an ALIAS beside an A record, a zone over `max-records`, rows the reader refuses: the transaction is rolled back and the database is as it was (`db.import.verify`, `zone.limits`, `zone.cname.coexists`, ...). A dry run does all of this too.
5. Commits. The triggers of `db/karidns_ext.*.sql` write the change to `karidns_changes`, so a running server with `auto-reload` picks the zone up by itself; `--reload` also adds a row to `karidns_reload_requests` (PostgreSQL), and otherwise `karictl reload` does it.

The type of an existing zone (`domains.type`) is never changed; a new zone is `NATIVE` (what `pdnsutil load-zone` creates), or `MASTER` with `--type MASTER`. A zone whose `domains.type` is not `NATIVE` or `MASTER` is not a zone the server serves from records: the import goes on, with the warning `db.import.not-primary`, and the records are not read back.

### Modes

`--mode replace` (the default)
: The records of the zone are replaced by the file's. The metadata the importer owns (`PRESIGNED`, `NSEC3PARAM`, `X-KARIDNS-FORMAT`) and the zone's tag definitions (`karidns_zone_tagdefs`) are replaced too; every other `domainmetadata` row of the zone (`ALLOW-AXFR-FROM`, profile names, ...) is kept.

`--mode merge`
: **RRset merge.** Every (owner, type) in the file replaces that RRset in the database; the RRsets that are not in the file stay. Deleting needs replace mode. The file may be a part of the zone: the checks of the file do not demand SOA, NS and glue then (the whole zone is checked when it is read back). The owned metadata the file declares replaces the database's.

`--types T1,T2`
: Limits either mode to records of these types: only they are deleted and only they are written; metadata and tag definitions are not touched. (The later signer uses `--mode merge --types RRSIG,NSEC3,DNSKEY,...`.) Up to 64 types, case does not matter.

`--dry-run` (`-n`)
: Does everything except the commit. The RRsets that would be added, replaced or deleted are listed (`db.import.change`, notes), and the summary says `dry run, nothing was written`. `--verbose` lists them for a real import too.

### SOA serial (RFC 1982)

For an existing zone whose SOA is written, the new serial must be **greater** than the serial in the database (serial number arithmetic, RFC 1982 section 3.2); otherwise the import fails with `db.import.serial`. Secondaries and IXFR only see a change when the serial grows.

`--serial grow` (the default)
: The rule above.

`--serial increment`
: Writes the database serial + 1, whatever the file says.

`--serial keep`
: Writes the file's serial as it is (restoring a backup, importing an export of the same zone).

A new zone takes the file's serial. A merge or a `--types` import that does not write the SOA does not touch the serial.

### Views and the database

The database comes from, in this order: `--sqlite3 FILE` or `--conninfo-file FILE` (with `--schema NAME`), else the configuration. `-c FILE` names the configuration; without it `/usr/local/etc/karidns/karidns.conf` (or `/usr/local/etc/karidns.conf`) is read when it exists. `--no-config` reads none. With a configuration:

- `options { database { driver ...; database-file ...; } }` (or `conninfo-file`, `schema`) is the database; `--view NAME` selects a view of the configuration: its `database-file` / `database-schema` if it has one of its own, else the shared source. A view with `database none;` takes no zones (`db.view-none`); a view that is not defined is `db.view-not-found`.
- With `--view` and the shared source, `import` puts the zone in that view (`karidns_domain_views`; the loader serves a zone without any row in every view) and `export` lists only the zones of that view. A view with a source of its own ignores `karidns_domain_views`: no row is written.
- **The server's rules for a database zone of that view are applied, so a zone the server would refuse is not written:** the `check-*` options (`check-names`, `check-mx`, `check-integrity`, `check-wildcard`, ... as `karicheck` and `karidns-dbloader --check` use them), the size limits `max-records`, `max-records-per-type`, `max-types-per-name` and `max-zone-ttl` (options, view), the location and ECS tag definitions of `options { }`, and `default-ttl`, `max-zone-records` and `max-zone-bytes` of the database block (for the reader that reads the zone back, and for `export`).
- **The file zones of the configuration** (`zone "x" { type master; file ...; };` of the view, or of every view without `--view`) are passed to the importer: importing a zone that is also a file zone prints `db.import.file-zone`: the file zone has priority, so the server keeps serving the file, not the database zone (see [`karidns(8)`](karidns.md), D-PRIO).

Without a configuration the checks have their default severities and there are no limits.

### Formats

`--format bind|tinydns|auto` (import)
: The format of the input. `auto` (the default) takes a tinydns data file for a name ending in `.tinydns` or `.data` or called `data`, and BIND format for everything else, including standard input. `--all` always reads a tinydns data file. A tinydns zone is imported as a zone with `X-KARIDNS-FORMAT tinydns`; the time stamps, countdown TTLs and location codes go to `karidns_record_tinydns`, the `%` lines to `karidns_zone_tagdefs`. A BIND-format file cannot hold those.

`--format bind|tinydns|auto` (export)
: `auto` (the default) writes a zone with `X-KARIDNS-FORMAT tinydns` as a tinydns data file and every other zone in BIND format. `--format bind` of a tinydns zone fails and names the record when it has an attribute BIND format cannot say. Tags and tag definitions are written as `$LOCATION`, `$ECS-SUBNET` and `$LOCATION-TAG` / `$ECS-SUBNET-TAG`, so an import of the export gives the same rows.

A signed (PRESIGNED) zone is exported as the server serves it, with the NSEC3PARAM / NSEC3 / NSEC records the server rebuilds from the rows, so **the file alone can serve the zone** (below).

## OPTIONS

`-c`, `--config FILE`
: The configuration file (above).

`--no-config`
: Read no configuration.

`--view NAME`
: The view (above).

`--sqlite3 FILE`
: The SQLite3 database file. The importer needs read and write permission on the file and its directory (the database is in WAL mode).

`--conninfo-file FILE`, `--schema NAME`
: PostgreSQL: the file with the libpq connection string (a regular file owned by the user running the tool, mode 0600 or 0400; checked before it is read), and the schema that holds the tables (default: the `search_path` of the role).

`--all`
: `import`: every zone with an SOA (`.` or `Z` line) of a tinydns data file, each in a transaction of its own; a zone that fails does not stop the others. `export`: every primary zone of the database (needs `--dir`).

`--mode replace|merge`, `--types T1,T2`, `--dry-run` (`-n`), `--serial grow|increment|keep`, `--verbose`
: Above.

`--strict`
: A warning of the zone checks fails the import. Without it warnings are printed and the import goes on. An error always fails.

`--reload`
: Also add a row to `karidns_reload_requests` in the transaction (PostgreSQL), so every server on the database reloads the zone. A database without the table gives the warning `db.import.no-reload`.

`--type NATIVE|MASTER`
: `domains.type` of a **new** zone (default `NATIVE`).

`--format bind|tinydns|auto`
: Above.

`--dir DIR`
: `export --all`: the directory for one file per zone; made when it does not exist (one level).

`--force`
: `export`: replace output files that exist. Without it an existing file is an error and is not touched.

`--json`
: One JSON document on standard output (below).

`-h`, `--help`
: Print the usage and exit with 0.

`-v`, `--version`
: Print the version and the drivers this build has, and exit with 0.

## EXPORT OUTPUT

`export <zone>` writes to standard output; `export <zone> <file>` writes the file (`-` is standard output). `<zone>` is a name with or without the final dot, in any case. Only primary zones (`NATIVE`, `MASTER`) have records the server serves; a `SLAVE`, `CONSUMER` or `PRODUCER` zone is `db.export.zone-type`. A zone with a row in `cryptokeys` but without `PRESIGNED` is refused (the server does not serve it: online signing is not supported).

The BIND text is `$ORIGIN`, `$TTL` (the TTL most records have), the tag definitions, then one record per line: owners relative to the zone (`@` for the apex), names inside the zone in RDATA relative, other names absolute with the dot, TTL written when it differs from `$TTL`, strings quoted, long base64 / hex blobs not wrapped. Every name, string and tag that comes from the database is escaped, so no value can end its line, start a directive or a comment or open a group; a record the format cannot hold makes the export fail and names it (`record 12 (www.example.test. A): ...`).

**Files.** A file is written to a temporary file in its directory and moved into place: a zone that cannot be read leaves nothing, and a reader never sees half a file. Without `--force` the name is taken with `link(2)`, so a file that appeared in between is never replaced. Output files are never opened through a symbolic link: an existing link is not followed (without `--force` it is an error, with `--force` the link itself is replaced). With `--json` the zone text cannot go to standard output: give a file.

**`export --all --dir DIR`** writes `<name>.zone` (BIND format) or `<name>.tinydns` (a tinydns data file) for every primary zone, in the order of the names. The name is the zone name with every byte that is not a letter, digit, `-`, `_` or `.` (a dot as the first character included) written as `%XX`, so a name never contains a path separator, starts with a dot or contains a control character, and two zones never give the same file. A zone that cannot be exported (the reader refuses its rows) is reported and the others are written; the exit status is 1. With `--view` only the zones of the view are written.

## JSON OUTPUT

`karidns-zone --json <command> ...` writes the document of [`karicheck --json`](karicheck.md#json-output) with the first key `"karidns-zone": 1` and `"command": "import"` or `"export"`; `messages[]`, `counts` and `zones[]` are as there (`zones[]` has one entry per zone imported or exported; `format` is `bind`, `tinydns`, or `database` for a zone that failed before its format was known; `file` is the input or output file). Standard output carries only the document, standard error nothing; the exit status is the one of the text mode. The codes are those of [`karicheck(1)`](karicheck.md) (`usage.*`, `io.*`, `conf.*`, `zone.*`, `db.import.*`, `db.export.*`, `db.zone.*`; the list is in the manual of `karicheck`).

## EXIT STATUS

`0`
: Every zone was imported or exported (warnings do not change this).

`1`
: Something failed: an error of the zone checks, a serial that does not grow, a zone the loader would refuse, the database, a configuration that cannot be read, an output file. Nothing of a failed zone was written to the database.

`2`
: Usage error (an unknown option or command, a missing value, an option of the other command, a wrong number of arguments, `--json` with an export to standard output). The usage goes to standard error (the message only, in the document, with `--json`); nothing was done.

## THE WRITER ROLE (PostgreSQL)

`import` writes `domains`, `records`, `domainmetadata` and the `karidns_*` zone tables; `export` only reads. `db/karidns_writer_role.pgsql.sql` gives a role exactly that and no more (the database packages install it in `/usr/local/share/karidns/db/`, next to `karidns_loader_role.pgsql.sql`, which the server's loader uses; do not give the loader this role):

```text
psql -X -v ON_ERROR_STOP=1 -c "CREATE ROLE karidns_writer LOGIN"
psql -X -v ON_ERROR_STOP=1 -v role=karidns_writer -v schema=public -f /usr/local/share/karidns/db/karidns_writer_role.pgsql.sql karidns
```

(`role` is the importer's role, `schema` the schema of the tables; run it once per schema when views have schemas of their own; it can be run again.) The role gets `SELECT, INSERT, UPDATE, DELETE` on `domains`, `records` and `domainmetadata`; `SELECT` on every `karidns_*` table and `INSERT, UPDATE, DELETE` on the zone tables (`karidns_domain_views`, `karidns_record_tags`, `karidns_record_tinydns`, `karidns_zone_tagdefs`); what the change log and the reload requests need (`INSERT, DELETE` on `karidns_changes` and `karidns_reload_requests`, because the triggers run with the rights of the writer); `USAGE` on the sequences. For `cryptokeys` all rights are revoked and only the **column** privilege `SELECT (domain_id)` is granted (the importer asks whether a zone has keys, to warn that unsigned data makes the loader refuse a zone with keys): **the role can never read `cryptokeys.content`**, the private keys. Authentication is yours: a UNIX socket with peer authentication for the user who runs the tool is the simplest; put the connection string in a file of mode 0600:

```text
# /usr/local/etc/karidns/writer.conninfo
host=/var/run/postgresql dbname=karidns user=karidns_writer
```

`karidns-zone import --conninfo-file /usr/local/etc/karidns/writer.conninfo example.test example.test.zone`. SQLite3 has no roles: the user running the tool needs read and write access to the database file and its directory.

## EXAMPLES

Import a zone file into the database of the configuration, then check what was written:

```text
karidns-zone import -c /usr/local/etc/karidns/karidns.conf example.test /var/zones/example.test.zone
karicheck db
```

See what a merge would change without writing it; take the data from standard input:

```text
karidns-zone import --sqlite3 /var/db/karidns/pdns.sqlite3 --dry-run --mode merge example.test - < new-records.zone
```

Import every zone of a tinydns data file (each in its own transaction), then export one back:

```text
karidns-zone import --all --sqlite3 /var/db/karidns/pdns.sqlite3 /var/tinydns/root/data
karidns-zone export -c /usr/local/etc/karidns/karidns.conf example.test > example.test.zone
```

Take the serial from the database (a changed file whose serial was not raised), or restore a backup as it was:

```text
karidns-zone import --serial increment -c karidns.conf example.test example.test.zone
karidns-zone import --serial keep      -c karidns.conf example.test /var/backups/zones/example.test.zone
```

### Backups with `export --all`

```text
karidns-zone export --all --dir /var/backups/zones/$(date +%Y%m%d) -c /usr/local/etc/karidns/karidns.conf
```

writes one file per zone (`example.test.zone`, `lan.example.tinydns`, ...). The files are canonical, so a `diff -r` of two backups shows what changed; a restore is `karidns-zone import --serial keep` of the files. The round trip is exact: file -> import -> export -> import -> export gives the same bytes both times, for signed, tagged, tinydns, `$GENERATE` and `$INCLUDE` zones (`tests/run_karidns_zone_test.sh`).

### When the database is down: export, then a file zone

The loader needs the database; a file zone does not. Keep a recent export and serve it from a file when the database is gone (D-PRIO: a file zone in `karidns.conf` has priority over the database zone of the same name, so the server serves the file as soon as it is configured):

```text
karidns-zone export -c karidns.conf example.test /usr/local/etc/karidns/zones/example.test.zone
```

```text
zone "example.test" { type master; file "/usr/local/etc/karidns/zones/example.test.zone"; };
```

then `karictl reconfig`. A signed zone is exported with its signatures and the NSEC3 records, so the file serves it as the database did. Remove the `zone` statement when the database is back (`karidns-zone import --serial increment` first if the file was changed).

## LIMITS

- `import` reads up to 64 MiB from standard input. A zone file read from standard input cannot use `$INCLUDE` (there is no directory to read from; `zone.include-stdin`).
- One zone per `import <zone> <file>`: a BIND-format file with several zones is not split. `import --all` reads tinydns data files only.
- The size limits are those of the configuration (`max-records`, ...) and of the database block (`max-zone-records`, `max-zone-bytes`); the loader reads at most `max-zone-records` records of a zone.
- What does not carry over from a tinydns data file: the SOA serial a `.` line takes from the data file's modification time is stored as the number the importer saw (use a `Z` line, or `--serial`), and the text of the data file (comments, order, `-` lines) is not kept.
- Two importers of one zone wait for each other (a transaction-level advisory lock on PostgreSQL, `BEGIN IMMEDIATE` on SQLite3) and give up after the busy timeout with `db.import.busy`; try again.
- `export` of a zone with more records than `max-zone-records` (default 10,000,000 for the reader) fails like the loader does.

## FILES

`/usr/local/etc/karidns/karidns.conf`
: The configuration read when `-c` is not given.

`/usr/local/share/karidns/db/karidns_writer_role.pgsql.sql`
: The privileges of the PostgreSQL role that imports (database packages; `db/` in a source tree).

`/usr/local/bin/karidns-zone`
: The tool (database packages; the SQLite3 / PostgreSQL drivers of the package are linked in: `karidns-zone --version` lists them).

## SEE ALSO

- [`karidns-dbloader(8)`](karidns-dbloader.md) — the loader that reads the zones the importer writes; the SQL files, the packages
- [`karicheck(1)`](karicheck.md) — the zone checks (`karicheck zone`), `karicheck db`, the JSON document and the message codes
- [`karictl(8)`](karictl.md) — `reload`, `dbstatus`, `rollback`
- [`karidns(8)`](karidns.md) — the `database` block, views, database zones, `check-*` options and limits
- [Distribution Guide](distribution.md) — the FreeBSD packages

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

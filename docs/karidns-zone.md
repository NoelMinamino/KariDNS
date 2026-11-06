# KARIDNS-ZONE(1) — KariDNS Zone Importer and Exporter

## NAME

**karidns-zone** — writes a zone file into a PowerDNS 5.1 database (`import`) and a zone of the database into a zone file (`export`)

## SYNOPSIS

```text
karidns-zone import [options] <zone> <file|->
karidns-zone import --all [options] <tinydns-data-file>
karidns-zone import --signer [options] <zone> <signed-zone-file|->
karidns-zone export [options] <zone> [<file>]
karidns-zone export --signer [options] <zone> [<file>]
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
: Limits either mode to records of these types: only they are deleted and only they are written; metadata and tag definitions are not touched. (The signer does not use it: it has `--signer`, below.) Up to 64 types, case does not matter.

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

### Signer mode (`--signer`)

`karidns-zone import --signer <zone> <file>` writes a zone that `karidns-signer` signed (0.6.0 item C). The file is the zone as `dnssec-signzone` wrote it from an **export** of the zone; the tool takes from it the DNSSEC records and nothing else, so it works with the rights of the signer role alone (below) and cannot change the data of the zone. In ONE transaction:

1. The `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM` and `DNSKEY` records of the database are replaced by the file's, in the layout PowerDNS stores a presigned zone in (no `NSEC`, `NSEC3` or `NSEC3PARAM` rows, the chain is rebuilt by the reader; `ordername` is the NSEC3 hash, or the reversed relative name of an NSEC zone). `CDS` and `CDNSKEY` are not touched.
2. The SOA of the file must be the database's SOA but for the serial, which must be **greater** (RFC 1982); it is written with `UPDATE`.
3. **Every other record of the file must equal the database's**, compared as RRsets in canonical form (RFC 4034 section 6.2): owner (without regard to case), type, class, the RDATA in wire form with the names inside the RDATA of the types that section lists in lower case, and the TTL of the RRset (the lowest of its records, RFC 2181 section 5.2: the TTL the server serves). Both sides are read the way the server reads a zone (the zone parser for the file, the loader's reader for the rows; the DNSSEC records left out), so the way a row is spelled does not matter: hex or names in upper case, an AAAA that is not compressed, a TXT without quotes or with escapes, the same row twice, an RRset whose rows have different TTLs, a NULL TTL (the default TTL of the loader), a disabled row (not served, not compared). An export of a zone, signed and given back, is accepted whatever the rows look like; a real change is not. If the zone changed since the export, nothing is written: the message is `db.import.changed` (it names the first RRset that differs), the `--json` document has `"signer": {"changed": true}` and the exit status is **3**. The signer then signs the zone again. The same goes for a serial that does not grow, and for a change that another session commits while the tool writes: on PostgreSQL the transaction is `REPEATABLE READ`, so a row it writes that another session changed after the tool read the zone (SQLSTATE 40001, or a record that is gone) is a change of the zone, not a failure; on SQLite3 the one write lock rules it out.
4. `ordername` and `auth` of the records that stay (and of the empty non-terminals the database holds) are set as a presigned zone has them (`auth` 0 for the NS records of a delegation and the names below it), with `UPDATE` where they differ.
5. The metadata `PRESIGNED` = 1, `NSEC3PARAM` (none for an NSEC zone) and `X-KARIDNS-SIGNER` = 1 are written. A running server then no longer reloads the zone because of the change log, only on a reload request ([`karidns(8)`](karidns.md), `signer-wait`).
6. The zone is read back through the loader's reader as for any import; a zone the loader would refuse is not committed.

`--signer` takes a zone that exists, is a primary zone (`NATIVE` or `MASTER`) and has one SOA at the apex, and a file in BIND format that is signed (RRSIG records and a complete NSEC or NSEC3 chain; otherwise `db.import.signer`). It cannot be combined with `--mode`, `--types`, `--serial`, `--view`, `--type`, `--all` or a tinydns data file: those are usage errors (exit status 2). `--dry-run`, `--reload` (PostgreSQL: the reload request is committed with the data, so the loader sees both together), `--strict`, `--verbose`, `--audit` and `--json` work as for any import. A signer import writes a whole zone again (every signature), so on PostgreSQL it asks for the audit in **summary mode** unless `--audit rows` is given, and it writes ordername and auth, the DNSSEC rows and the metadata in a few statements (`unnest()` of arrays): the change log gets a few rows and `karidns_changes` one `NOTIFY` per statement, not one per record. (SQLite3 triggers fire per row whatever the statements: the change log and the audit have a row per changed row.)

The first signing needs nothing in the database but the zone: no `cryptokeys` rows and no `PRESIGNED` metadata. `karidns-zone export` writes the zone as the unsigned zone it is, and `import --signer` of the signed text then sets `PRESIGNED`, `NSEC3PARAM` (NSEC3) and `X-KARIDNS-SIGNER`; the signer inserts the keys it signed with after that.

**A normal import into a zone the signer signs.** A zone with the metadata `X-KARIDNS-SIGNER` = 1 keeps its DNSSEC records when an operator imports into it with a plain `karidns-zone import` (replace or merge): the `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `DNSKEY`, `CDS` and `CDNSKEY` rows and the metadata `PRESIGNED` and `NSEC3PARAM` stay as they are, and only the other data is replaced (or merged); a file with DNSSEC records of its own is taken without them (the message `db.import.signer-zone` says how many were ignored). The read-back checks the zone without its DNSSEC records. The loader does not serve the new data before the signer has signed it (`signer-wait`); the signer notices the change in the change log and signs the zone again.

**Result.** The text output ends with `Zone 'x' signed: SOA serial A -> B, N DNSSEC record(s) written, M removed, K record(s) updated (ordername, auth); the earliest RRSIG expires T`. With `--json` the document has one more key, `signer`, after `zones`:

```json
"signer": { "zone": "example.test", "changed": false, "committed": true, "serial": 11, "old_serial": 10,
            "dnssec_records_written": 20, "dnssec_records_removed": 0, "records_updated": 9,
            "rrsets_added": 16, "rrsets_replaced": 0, "rrsets_deleted": 0,
            "earliest_expire": "2026-11-20T02:29:12Z", "earliest_expire_epoch": 1795141752,
            "write_id": { "xid": null, "seq_first": 11, "seq_last": 42 } }
```

- `earliest_expire` is the earliest signature expiration of the zone **after** the write, as a UTC time (and `earliest_expire_epoch`, unix seconds). The expiration field of an RRSIG is a 32-bit number of seconds modulo 2^32, compared with serial number arithmetic (RFC 4034 section 3.1.5, RFC 1982), so the earliest is the one that comes first in that order, and the 32-bit value is put into the 64-bit time nearest to now. The signer schedules the next run from it: the earliest expiration minus its refresh interval.
- `write_id` says which rows of `karidns_changes` this write made, so that the signer does not take its own write for a change of the zone. PostgreSQL: `xid` is `pg_current_xact_id()` of the write transaction (the `xid` column of the rows the triggers wrote), `seq_first` and `seq_last` are null. SQLite3: `seq_first` and `seq_last` are the first and the last `karidns_changes.seq` of the transaction (the transaction holds the one write lock, so all rows between them are its own; both null when it wrote no row, and `xid` is null).
- With `changed` true there is no other key but `zone` and `committed` (false). A dry run gives the same numbers with `committed` false.

**Busy.** When another importer holds the zone, or the database is locked for longer than the tool waits (SQLite3: 5 seconds; PostgreSQL: `lock_timeout`, 10 seconds), nothing is written and the exit status is **4** (`db.import.busy`; `"signer": {"changed": false, "committed": false, "busy": true}` with `--json`), not 1: try again. Any other import exits with 1 in this case.

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

`--signer`
: `import`: the file is a zone signed by `karidns-signer`; write its DNSSEC records and nothing else (above). Exit status 3 when the zone changed since the file was made, 4 when the zone is busy. The audit is in summary mode unless `--audit rows` is given.
: `export`: the zone as the input of `dnssec-signzone` (below, "Export for the signer"): the NSEC / NSEC3 chain, the signatures over it and the metadata `PRESIGNED` and `NSEC3PARAM` are left out, the other signatures and the DNSKEY records stay.

`--strict`
: A warning of the zone checks fails the import. Without it warnings are printed and the import goes on. An error always fails.

`--reload`
: Also add a row to `karidns_reload_requests` in the transaction (PostgreSQL), so every server on the database reloads the zone. A database without the table gives the warning `db.import.no-reload`.

`--type NATIVE|MASTER`
: `domains.type` of a **new** zone (default `NATIVE`).

`--audit rows|summary`
: `import`: how the audit log sees this import (default `rows`; see AUDIT below). Any other value is a usage error, and so is the option with `export`.

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

### Export for the signer (`--signer`)

`karidns-zone export --signer <zone> <file>` writes the zone as the **input of `dnssec-signzone`**, which is what `karidns-signer` needs. The plain export is the zone as the server serves it, and the server serves a signed zone only when its NSEC3 chain is complete: a zone that someone changed after it was signed (a new name has no NSEC3 record and no signature over it yet) is refused by the reader (`presigned zone: no RRSIG(NSEC3) owner for 'new.example.test.'`), and so by the plain export. With `--signer` the rows are read without the chain: the NSEC, NSEC3 and NSEC3PARAM records, the RRSIG records that cover them and the metadata `PRESIGNED` and `NSEC3PARAM` are left out, so there is nothing to rebuild or check. The other RRSIG records and the DNSKEY, CDS and CDNSKEY records stay, so that `dnssec-signzone -i` keeps the signatures that are still good (an RRset that changed has a signature that no longer verifies, and is signed again); the signer makes the chain again. The text is the data of the database as it is, signed and unsigned alike; the check "a zone with a row in `cryptokeys` but without `PRESIGNED` is refused" is not made, because the metadata is not read. On an unsigned zone `--signer` gives the same text as the plain export. It takes the options of `export` (`--all --dir` as well) and none of `import`.

## JSON OUTPUT

`karidns-zone --json <command> ...` writes the document of [`karicheck --json`](karicheck.md#json-output) with the first key `"karidns-zone": 1` and `"command": "import"` or `"export"`; `import --signer` adds the key `signer` after `zones` (above); `messages[]`, `counts` and `zones[]` are as there (`zones[]` has one entry per zone imported or exported; `format` is `bind`, `tinydns`, or `database` for a zone that failed before its format was known; `file` is the input or output file). Standard output carries only the document, standard error nothing; the exit status is the one of the text mode. The codes are those of [`karicheck(1)`](karicheck.md) (`usage.*`, `io.*`, `conf.*`, `zone.*`, `db.import.*`, `db.export.*`, `db.zone.*`; the list is in the manual of `karicheck`).

## AUDIT

A database of schema version 3 (`db/karidns_ext.*.sql`) has an audit log: `karidns_auth.audit_log` on PostgreSQL, `karidns_audit_log` on SQLite3. It is empty and stays empty until the audit triggers are attached (PostgreSQL: `SELECT karidns_auth.enable_audit('public')`, which the role scripts of the WebAdmin do; SQLite3: apply `db/karidns_audit.sqlite3.sql`). With the triggers on, every row `karidns-zone import` changes is logged: the table, the operation (`I`, `U`, `D`), the zone, the row before and after as JSON, and who did it.

**Who.** PostgreSQL: the database role of the connection (`db_role`), and no principal. SQLite3: triggers can only read their own database, so the importer writes one row to the table `karidns_audit_actor` first in its transaction and deletes it before the commit; the row says `karidns-zone:<OS user>`. A database without that table (schema version 2) gets no row and the import is as before. The importer does not set `karidns.principal`: a session that does (the WebAdmin) is logged under that principal.

`--audit rows` (the default)
: One audit row per changed record, tag, tag definition and metadata row. A replace-import of a zone of a million records writes two million rows.

`--audit summary`
: PostgreSQL: each write transaction of the run begins with `SET LOCAL karidns.audit = 'summary'`. The audit then writes one row for the transaction, the table, the operation and the zone, which counts the statements and the rows (`{"summary": true, "statements": 1000000, "rows": 1000000}` in `after`); the first statement inserts the row and the totals are written into it when the transaction commits. The role of the WebAdmin (`karidns_api`) cannot turn the detail off, and neither can a login role that is a member of it, also after `SET ROLE` to another role: the restricted roles are the rows of the table `karidns_auth.audit_restricted_roles` (owner only; the role script of the WebAdmin adds the role name it was given). The importer's role can, and so can the signer's (`karidns_signer`: a trusted daemon whose output is machine made; `import --signer` uses summary mode by default). SQLite3: the audit has rows only; the option is accepted and the actor row is written as with `rows`.

**Zone names in the log.** Every audit row of a zone's data names the zone (`zone_name`), also the rows that a zone delete removes through foreign keys (records, metadata, tag definitions, views). The one exception: the rows of `karidns_record_tags` and `karidns_record_tinydns` that go with their record (when the record or its zone is deleted) have `zone_name` NULL, because the record is gone when they are deleted. The `D` row of the record carries the zone, and its `row_id` is the `record_id` of those rows. (PostgreSQL remembers the name of a zone that is being deleted in a transaction-local setting `karidns.zc_<hash of the schema>_<domain id>`; it ends with the transaction.)

**Row level security.** When the role script of the WebAdmin or of the signer has switched row level security on (PostgreSQL), the importer's role must be a member of `karidns_rls_trusted`, or it sees no rows. `db/karidns_writer_role.pgsql.sql` makes its role a member, whichever script ran first. See THE AUTH SCHEMA, ROLES AND THE AUDIT LOG in [`karidns-dbloader(8)`](karidns-dbloader.md).

**Cost.** A replace-import of 100,000 records into PostgreSQL 18 (one `INSERT` per record, one transaction) took 17 s without the audit, 36 s with `--audit rows` and 36 s with `--audit summary`. Summary mode saves space in the log, not time.

## EXIT STATUS

`0`
: Every zone was imported or exported (warnings do not change this).

`1`
: Something failed: an error of the zone checks, a serial that does not grow, a zone the loader would refuse, the database, a configuration that cannot be read, an output file. Nothing of a failed zone was written to the database.

`2`
: Usage error (an unknown option or command, a missing value, an option of the other command, a wrong number of arguments, `--json` with an export to standard output, `--signer` with `--mode`, `--types`, `--serial`, `--view`, `--type` or `--all`). The usage goes to standard error (the message only, in the document, with `--json`); nothing was done.

`3`
: `import --signer` only: the zone in the database is no longer the zone the signed file was made from (a record or the SOA differs, or the serial does not grow, or another session changed the zone while the tool wrote it). Nothing was written (`db.import.changed`). Sign the zone again.

`4`
: `import --signer` only: the zone is locked by another import, or the database is busy for longer than the tool waits. Nothing was written (`db.import.busy`). Try again.

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

### The signer role

`import --signer` needs less: `db/karidns_signer_role.pgsql.sql` (see [`karidns-dbloader(8)`](karidns-dbloader.md), "Roles and row level security") gives the signer's role `SELECT` on everything, `INSERT` and `DELETE` on the DNSSEC records, `UPDATE` of records (a trigger lets it change only `ordername` and `auth` of a record that is not a DNSSEC record, and of an SOA record only the serial besides), and the three metadata kinds it owns. The tool deletes the DNSSEC records by id and never touches the tag tables, so that role is enough, with row level security on.

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

Write a zone that `dnssec-signzone` signed from an export of it (what `karidns-signer` does; the exit status is 3 when the zone changed meanwhile):

```text
karidns-zone export --signer -c karidns.conf example.test example.test.in
dnssec-signzone -o example.test -f example.test.signed -N increment -3 - -H 0 -K keys example.test.in Kexample.test.+013+11111 Kexample.test.+013+22222
karidns-zone import --signer --json -c karidns.conf example.test example.test.signed
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

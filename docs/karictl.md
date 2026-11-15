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
karictl [-c config_path | -f config_path] [-s socket_path] [-t seconds] <command> [arguments...]
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

`-t seconds`
: How long to wait for each part of the server's reply: the challenge, and then each read of the answer (1–86400, default 60, as `rndc -t`). When the server sends nothing for that long, `karictl` prints `no reply from the server within N s` and fails. A full `reload` of the zone files answers when the reload is done, so a server with very many zone files may need a larger value; database zones answer at once (`karictl dbstatus` shows the progress).

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
  - Number of zones, `debug level: N` (the debug level in force: `karidns -d`, `trace`, `notrace`; where `rndc status` prints it) and number of running AXFR/IXFR transfers
  - Whether query and response logging are enabled
  - Current and high-water TCP connection counts
  - Size of the zone versions and IXFR deltas (D1a): the bytes of the published versions of the zones (the version, its image and its glue block) and of the IXFR deltas the zones keep (the records of the difference and the data in them as it is used, with the overhead of each block: a difference of one SOA counts about 1.8 KB; 0.7), for the zones that come from the database and for the others, as `resident` (what the zones serve now) and `retired` (versions that a newer one replaced and that are not freed yet, because a reader or a transfer may still hold them). Since 0.7 the bytes of the zone entry itself (the entry, the lock it makes, a database zone's settings block, about 0.85 KB) are in it, counted with the zone's first version, and the images and glue blocks are counted at the size the allocator really holds. The directory, the response cache and the park tables are not in it. An IXFR delta that left the history stays counted as resident until the last transfer that reads it has released it. A database zone that `memory-limit` takes out of memory gives up its IXFR deltas at once (they are not served while the zone is out of memory, and the zone comes back without them), so evicting and fetching a zone again does not add to the resident bytes. Read only: nothing limits them yet
  - The bytes the zones keep for `rollback` (the previous versions, see `rollback`): `zone versions kept for rollback: database zones N bytes, other zones N bytes`. They are not served; they are freed when the `rollback-window` is over, or earlier when the database `memory-limit` needs the room
  - What waits to be freed (0.7): `retired zone snapshots waiting: N (oldest N ms)` (zone-db snapshots that a reload or a change replaced and that a reader still holds: a dynamic update, a control command, a zone transfer that waits for a database zone to be read (`transfer-fetch-timeout`), or a thread inside a read section; they are freed in order, so one held snapshot keeps the later ones too. A transfer that is being sent holds none, 0.7 R11), `retired zone versions waiting: N` (zone versions and objects on the retire stack, not freed yet: a reader that stays in its read section keeps every version replaced after it entered (a reload, an UPDATE, a database batch never wait for it: the count rises and falls when it leaves), a reader holds them, or the version is the one a running outbound transfer sends: it is freed when that transfer ends) and `reclaim warnings (snapshot held over 60 s): N`. Nothing limits these and no reader is cut off; when the oldest snapshot has waited more than 60 s, karidns writes a warning in the category `general` (`[GC] the oldest retired zone snapshot has waited N s ...: held by ...`, naming the kind of reader slot or the retained references), at most once a minute while it waits
  - Frontend process health status
  - Security counters: RRL dropped/slipped responses, Extended DNS Error counters (18 Prohibited, 20 Not Authoritative, 21 Not Supported, other) and truncated dnstap messages
  - dnstap (0.7): `dnstap dropped (queue full): N` (messages lost because a ring was full: the collector reads too slowly, or `queue-size` is too small), `dnstap dropped (not connected): N` (messages lost while no collector was connected), `dnstap connected: yes|no|no (not configured)` and `dnstap reconnects: N` (connections made by the background retry); see karidns(8) `dnstap` "Loss". Without a `dnstap` block the counters are 0, as `dnstap truncated` is

`reload [-force | zone [view] [force]]`
: Without arguments, re-read the configuration file and **all** zone files (see `reconfig` for the replies; a full reload also drops the changes of dynamic updates), then, when the configuration has a `database` block, ask the database loader to compare its databases with the zones served: the loader sends the zones that are new, whose serial differs, that the change log (`karidns_changes`, see `db/karidns_ext.*.sql`) lists as edited, or whose last version was refused, and a `ZONE_DELETE` for the zones that left the database. The reply does not wait for the loader: `OK reloaded; DB reload requested (request N)`; `karictl dbstatus` shows the batch when it is done. With a zone name, reload only that zone: a primary zone re-reads its zone file (errors such as a missing file, a parse error, a missing SOA or a running AXFR are reported), and a secondary zone starts a new transfer from its primary. For a **program zone** (`type program`, 0.6.2) the operator who names the zone asks for its data to be read again, and the plugin is dealt with by the first of these that applies: (1) the zone's program settings (`program`, `program-args`, `program-user`, `program-timeout`, `program-max-failures`, `disable-auto-tc-flag`, `program-reload-line`) in the active configuration are not those of its running plugin: a new plugin is started, and when it is up the old one is stopped, as for a reload; (2) the settings are the same and the zone has `program-reload-line yes;`: the plugin gets the `RELOAD` line and is not restarted; (3) the settings are the same and the zone has no `program-reload-line` (or `no`): a plugin without that line can read its data again only by starting again, so a new plugin with the same settings is started and replaces the old one in the same way (queries are answered throughout). This differs from a full `reload` (and `reconfig`, `SIGHUP`), which leaves a plugin whose settings did not change alone, with the `RELOAD` line where configured. The reload of a zone does not read `karidns.conf` again (run `reconfig` or a full `reload` first to apply an edit; those already replace the plugins of changed zones, so case 1 arises when that replacement was refused or has not been answered yet, and the reload asks for it again at once). `force` has no effect. The replies: `OK reloaded (program zone: the program settings changed; a new plugin was asked for, the old one answers until it is up)` (1), `OK reloaded (program zone: RELOAD line sent to the plugin)` (2), `OK reloaded (program zone: no program-reload-line; a new plugin with the same settings was asked for, the old one answers until it is up)` (3), `OK reloaded (program zone: a plugin was asked for; the zone answers when it is up)` (a plugin that never came up, or a refused replacement, is asked for again), `OK reloaded (program zone: a new plugin with these settings is already on its way)`, and `ERROR no plugin runs for this zone: allow-program-zones is not yes, or the zone has no program`.
  `reload -force` (0.7, the zone store) is the full reload for which the loader lists every zone of its databases again (a manifest pass) instead of reading the change log from its cursor. With the zone store the Backend deletes the zones of a view that the pass does not list, unless that would delete more than 20 percent of the view's zones and more than 1,000: then nothing is deleted, `ERROR` is logged, `karictl dbstatus` shows `MASS-DELETE GUARD HELD` and `karictl store` has `store.recon.guard.*`. **The operator's release of that guard is `reload -force`**: the pass it asks for is not held back, the zones the database no longer lists are deleted and the guard is let go. It needs the permission `reload` of a restricted control key, like a full `reload`.
  A zone that is not in `karidns.conf` is looked up in the database. For a **database zone** the loader reads that zone only (also a zone just added to the database, which the server does not know yet). When several views take database zones and no view is named, the loader is asked about every one of them (a mapping in `karidns_domain_views` may have moved the zone) and the reply is one line, `<z>: view <v1>: <result>; view <v2>: <result>`, `OK` when at least one view has the zone and `ERROR` when it is rejected or failed there or when no view has it (`zone not found (it is not in the database of any view that takes database zones)`); a named view gives the single-view replies below, converts it, and sends it when its content differs from the version the server serves, whatever its serial; `force` sends it even when the content is the same (D1a: not a zone that is out of memory and unchanged; there is nothing in memory to replace, the next query reads it from the database, and the reply is `unchanged, serial <n> (not in memory)`). With the zone store (0.7) a reload of one zone without `force` is decided by the version stamp of the database (`karidns_zone_state`; the serial for a source without stamps; a zone without a stamp is always read): a zone that did not change is `unchanged, serial <n> (not in memory)` and is not read, one that changed has its body read, and the answer waits for it; `force` reads the body whatever the stamp says, also for a zone that is not in memory (nearly every zone of a big server is stored and not in memory). `karictl` waits for the loader's answer, but the server does not: the connection is parked and answered when the result arrives, or after `db-reload-timeout` seconds (`ERROR timeout: ...`; the reload may still be applied). At most 32 clients wait at once; the next ones get `ERROR too many reloads are waiting for the database loader; try again later`. Replies (all `OK` unless marked):
  - `OK zone <z> (view <v>): applied, serial <n>`: the new version is served.
  - `OK zone <z> (view <v>): unchanged, serial <n>`: the loader found the content equal to the served version. With memory-limit, ` (not in memory)` follows for a zone whose data is out of memory; it is not read, also with `force`.
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
  `reload` and `reconfig` answer when the configuration and the zones are applied, not when the memory they replaced is freed (0.7): a thread that stays in a read section of the server only keeps that memory longer (`retired zone versions waiting` in `status`).
  `reload` (without arguments) and `reconfig` answer:
  - `OK` (`OK reloaded` for `reload`): the configuration was applied and every zone loaded. When a setting that needs a restart changed, `(restart needed for: port, ...)` follows.
  - `ERROR configuration applied, but N zone(s) failed to load: <zones>`: the new configuration is in use, and the listed zones (also logged to syslog) answer SERVFAIL until their files can be loaded. A zone transfer that is being sent does not make a zone fail (0.7: before, a reload waited 5 s for it and listed the zone here); it goes on with the version it started with.
  - `ERROR configuration not applied: <reason>`: the file could not be read, has an error (see syslog or `karicheck conf`), or a log file could not be opened; the running configuration is kept.
  - `ERROR reload postponed: ...`: a thread of the server was still reading the configuration before the last one. The configuration is kept in two buffers and the new one is read into the one that thread may still hold, so the reload is not done now. `reload` and `reconfig` first wait for such readers as long as they last in normal operation: the longest `program-timeout` or `forward-timeout` of the configuration plus 0.5 s, at least 1 s and at most 5 s (a worker that waits for a program zone's plugin or a forward zone's forwarders reads the configuration meanwhile). Only a reader that stays longer gives this reply, within that time. The server then applies the reload by itself, with what the command was to do (`reload`: every zone file and the request to the database loader), within a second of the reader leaving; the log says when (`The postponed reload was applied`). karictl exits with status 3 for this reply, as for every `ERROR`. A zone transfer that waits for a slow client is not such a reader (0.7).

  Every `ERROR` reply makes `karictl` exit with status 3.

`stop`
: Stop the `karidns` daemon.

`notify <zone> [view]`
: Send DNS NOTIFY messages for `<zone>` now: to the `also-notify` servers and to the addresses of the zone's apex NS hosts, except the host named in the SOA MNAME field (RFC 1996 §3.2). Zones served from a database are found too; one that is hidden by a configured zone or a catalog member of the same name answers `ERROR zone is not served from the database ...`. A database zone of the zone store (0.7) that is not in memory is attached first (the answer is `OK (the zone is not in memory: it is attached first)`), and its NOTIFY is sent when it is there; if a name server of the zone is in another stored zone that is not in memory, that zone is asked for too and the NOTIFY waits for it for a second at the most.

`retransfer <zone> [view]`
: For a secondary zone (including a catalog member zone), discard the current serial and start a new transfer (AXFR) from the primary immediately. For any other zone the server answers `ERROR zone is not a secondary` and karictl exits with status 3; the zone is not changed. A `SLAVE` or `CONSUMER` zone from the database (milestone B7b) is a secondary and is transferred again like any other; a `NATIVE` / `MASTER` zone from the database is a primary zone: the answer is `ERROR zone is a primary zone from the database; read it again with 'karictl reload <zone>'`.

`rollback <zone> [view] [local]`
: Put the zone back to the version it had before its last reload. The server keeps the version that a **zone-file reload** (`reload`, `reload <zone>`, `reconfig` that re-reads the file) or an **install from the database** replaces, for `rollback-window` (default 1 hour; `0` keeps nothing; `options`, `view` and `zone`, see karidns(8)). A dynamic update, a zone transfer and a rollback do not replace it: after a reload and three updates, `rollback` goes back to the version before the reload and the three updates are gone with it. A reload that brings the very same content does not replace it either, so a second `reload` of the file you just fixed does not push the good version out.
  The old content is published again with **SOA serial = the current serial + 1** (RFC 1982; a serial of 4294967295 gives 1), an IXFR difference is recorded and NOTIFY is sent, as for a reload, so the secondaries follow and never see a serial that goes back. Reply: `OK rolled back: serial <new> (was <current>)`. `zonestatus` shows ` rolled back (serial <new>, from <current>)` until the next publication (a reload, an update, a database install), and, while a previous version is kept, ` previous version kept (serial <n>, <bytes> bytes, <s> s left)`.
  With `local` the old version is published **unchanged, with its old serial, on this server only**: no NOTIFY is sent and the IXFR history of the zone is dropped, so a secondary that has the newer serial does not follow (it never accepts a lower serial) and a secondary that is behind transfers the whole zone. Use it for a signed zone, or to look at the old data. The view name is written first when there are both: `rollback example.test internal local` (a view that is itself named `local` is written twice: `rollback example.test local local`).
  Replies that are `ERROR` (karictl exits with 3, nothing is changed):
  - `no previous version: ...`: the zone was not reloaded within `rollback-window` since it was loaded, the window ran out, or it was rolled back already (**once per reload**; there is no redo; reload the file again to get a version to go back to).
  - `rollback-window is 0 for this zone: no previous version is kept`.
  - `rollback is for primary zones; a secondary gets its data from the primary`: a secondary, a catalog member, a `forward` zone. A catalog zone (`a catalog zone cannot be rolled back`) and a `program` zone are refused too.
  - `zone is signed; roll back in the DB and re-sign`: the version to go back to holds RRSIG or DNSKEY records. KariDNS cannot sign, and a new serial would leave the SOA with a signature that does not match. Roll back where the zone is signed, or use `local`.
  - `the zone was taken out of memory; nothing to roll back` (a database zone whose data left memory, or one hidden by a zone of the same name).
  What a later reload does:
  - **Zone file.** `reload <zone>` and a full `reload` keep the rolled-back version while the file is the one that was read (same modification time and size), and say so (`OK kept the rolled-back version: ...`). Fix the file and reload, or `reload <zone> force` to read it again (which brings the data back that you rolled back). A change only in a file that the zone `$INCLUDE`s is not noticed by that check: use `force`. `reconfig` already skips files that did not change. A restart reads the file again.
  - **Database zone in the zone store (0.7).** A zone that is in memory is found like any other. One that is not in memory has no previous version to go back to (the store holds the current image only; the version before the last one is kept with the zone in memory): the answer is `ERROR the zone is in the zone store and not in memory: it has no previous version to roll back to ...`.
  - **Database zone.** The server compares the loader's (source id, serial, digest) with what it recorded when it installed the zone, and a rollback does not change that record, so the rolled-back version stays until the data in the database change; the next change is installed normally. Meanwhile the zone is pinned in memory like one that a dynamic update changed (`dbstatus <zone>` says `rolled back: serial N, from M; pinned in memory ...`), because the database cannot give the old version back. With several servers on one database, a rollback on one makes them differ until the database changes; a rollback in the database (`karidns_*` data) is the durable fix.
  - The command needs the permission `rollback` of a restricted control key (`allow-commands { rollback; }`), and is logged with the key name like the other commands.
  ```sh
  karictl reload example.test          # the new file has a mistake
  karictl rollback example.test        # serial N+1, the old data, the secondaries follow
  karictl rollback example.test local  # the old version as it was, this server only
  ```

`zonestatus <zone> [view]`
: Display the SOA serial
 and refresh interval of `<zone>` (`OK serial=<n> refresh=<n> retry=<n> expire=<n>`; for a secondary the values the zone uses, held to `min-refresh-time` ... `max-retry-time`). For a zone from the database the line goes on with `source=database view=<v> id=<domains.id> result=<applied|rejected|shadowed (hidden by ...)>` and the last error, if any; a zone of the zone store (0.7) that is not in memory shows the record of the store (its serial and id) and `(in the zone store, not in memory)`, or `(in the zone store without a body yet: ...)` for a zone the store knows and has not read from the database yet. A secondary that applies settings received from its primary (Extended AXFR version 3, see karidns(8)) adds `settings=primary` (and `note: ...` when part of them is not in force, e.g. a TSIG key the received `allow-transfer` names is not defined here).

`observatory [zone [view]]`
: Display per-zone statistics for all zones, or only for the given zone (and view): role (primary/secondary), SOA serial, query counts (total and TCP), response codes (NOERROR, NXDOMAIN, NODATA, SERVFAIL, REFUSED), EDNS/DO/ECS query counts, RRL dropped/slipped counts, successful inbound AXFR/IXFR transfers (secondary, with `Failed-refreshes`: the refreshes that failed at every primary asked) or NOTIFY messages sent (primary) with the time of the last one, and response cache hits and misses (the cache is shared by all zones, so it has no per-zone size). A zone that other views share with `zone { in-view }` (karidns(8) "Zones shared between views") is listed once, in the view that owns it, as `Zone: <name> (view: <owner>, shared to views: <a>, <b>)`; `status` counts it once, and `notify`, `zonestatus` and `reload` name it with or without a view (a referencing view's name reaches the owner's zone).

`stats [-f prometheus|json] [zone [view]] [--zones PATTERN] [--limit N] [--after CURSOR]`
: Print the counters of the server, its views and zones, for monitoring. The default format is the Prometheus text exposition format (metric names `karidns_*`, labels `zone`, `view`, `rcode`, `proto`, ...), which the node_exporter textfile collector reads; `-f json` (or `--format json`) prints one JSON object. (`-f` after `stats` is the format; the `-f` before the command is still the configuration file.) The exit status is 0 only when the whole output was written, so `karictl stats > file.$$ && mv file.$$ file` never leaves a half-written file.
  The output has a **server** part (version, boot time, zone count, workers, TCP clients, zone memory, query, response, EDNS, NOTIFY, transfer, response-cache, rate-limit and Extended DNS Error counters, failed transfers, failed reloads, raised alerts, the reclaim queue (the gauges `karidns_reclaim_snapshots_waiting`, `karidns_reclaim_oldest_snapshot_age_seconds`, `karidns_reclaim_zone_versions_waiting` and the counter `karidns_reclaim_warnings_total`; in JSON `reclaim` `{snapshots_waiting, oldest_snapshot_age_ms, zone_versions_waiting, warnings}` in `server`) and dnstap (`karidns_dnstap_truncated_total`, `karidns_dnstap_dropped_total{reason="queue_full"|"not_connected"}`, the gauge `karidns_dnstap_connected` (1 or 0; 0 also without a `dnstap` block) and `karidns_dnstap_reconnects_total`; in JSON `dnstap_truncated`, `dnstap_dropped` `{queue_full, not_connected}`, `dnstap_connected` (true / false) and `dnstap_reconnects`)), then **views** (zones, queries and responses summed per view; only when every zone is listed), then one set of series **per zone** (queries by transport, responses by RCODE, EDNS / DO / ECS queries, rate-limit drops and slips, NOTIFY, transfers in and their failures, response cache hits and misses, SOA serial, role, time of the last transfer). The counters are cumulative since the server started (Prometheus `counter`s); a zone that a reload replaces starts again at 0, which `rate()` handles as a counter reset.
  Queries that no zone answered (REFUSED for a name outside every zone, FORMERR, NOTIMP, ...) belong to no zone: they are in `karidns_unzoned_responses_total{rcode}`, and `karidns_responses_total{rcode}` is the zones' responses plus those. `karidns_queries_total{proto}` counts the queries answered for a zone.
  `stats <zone> [view]` prints one zone (the same as `observatory <zone>`, without the other zones). Without a zone name every zone is listed, fetched in pages of 2000 (the server never builds one reply with all zones) in the order of its zone tables (the order of the names' hashes, not alphabetical; a zone added or removed while the listing runs may or may not be seen). `--zones PATTERN` lists only the zones whose name matches the glob (`*`, `?`, `[a-z]`, at most four `*`; case-insensitive; `example.*` matches `example.test.`), `--limit N` stops after N zones and, if there are more, ends the output with `# more zones: karictl stats --after <cursor>` (JSON: `"more":true,"after":"<cursor>"`), and `--after CURSOR` continues there. A cursor is a position in the server's zone tables, so a page costs the server the page, not the number of zones (at most 65536 table slots are looked at for one page; a glob that matches little gives short pages that karictl asks for one after the other). A cursor from before a reload that rebuilt the tables is refused (`cursor is stale`, exit 3); a text listing that meets this while it runs starts again (up to three times), a JSON listing, which is written as it comes, stops with the error. The totals of the zones' counters in the server part (queries by transport, NODATA, EDNS, NOTIFY, transfers) are summed with one walk of all zones per command (see the release notes for the time at 1,000,000 zones). Values with white space are refused (write a space in a name as `\032`).
  The text format is valid exposition format whatever the number of zones: karictl collects the zones first (184 bytes and the zone name, about 25 bytes, per zone: about 210 MB for 1,000,000 zones; use `--zones` and `--limit` to bound it) and writes every metric family once, in one piece, with `# HELP` and `# TYPE` once. `-f json` is written as the pages come and keeps nothing. The command needs the read permission of a restricted control key, like `observatory`.
  ```sh
  karictl stats > /var/tmp/node_exporter/karidns.prom.$$ && mv /var/tmp/node_exporter/karidns.prom.$$ /var/tmp/node_exporter/karidns.prom
  karictl stats -f json example.test
  karictl stats --zones '*.example.test' --limit 100
  ```

`dbstatus [zone [view]]`
: Show the state of the zones served from a database (`options { database { ... }; }`, SQLite3 or PostgreSQL through `karidns-dbloader`). Without arguments: whether the loader is connected (with its process ID, version and drivers, and since when), how many DB zones the server holds (served, hidden by a zone of the same name in `karidns.conf`, hidden by a catalog member of the same name, and zones with a rejected version), the last batch the loader delivered (id, kind `startup` / `full` / `diff` / `zone` / `auto`; a `reload` is a `diff` batch, a `reload <zone>` a `zone` batch, time, and its applied / rejected / shadowed / deleted counts), the state of auto reload (`auto reload: off`, or `on` with poll-interval, coalesce, the number of auto batches since the start and, per view, the last poll, the applied change log position, the pending changes and the last error; B9; under a view a line `waiting for the signer: N zone(s): a, b, ...` when zones with the metadata `X-KARIDNS-SIGNER` = `1` changed and wait for `karidns-signer` to sign them and ask for a reload, see `signer-wait` in [`karidns(8)`](karidns.md)), for a PostgreSQL view whose schema has the multi-server tables (B11) one line `reload requests (view <name>): server-id <id>, last applied generation <n>, ok yes|no, status written <time>|never, last error: <text>|none` (the id this server reports under in `karidns_server_status`, the highest `karidns_reload_requests` generation it has applied, whether every zone of that reload loaded, when its status row was last written, and why a read of the requests or a write of the status row failed; the server keeps serving when it cannot write the row), the size of the zone versions and IXFR deltas (the same numbers as in `status`), the fetches of whole zones from the database (`fetch: rate=unlimited|N/s refused_by_rate=N issued=N concurrency=N`; `rate=unlimited` is the default (`fetch-rate`, 0.7); `refused_by_rate` counts only the background requests that found the bucket short (a query waits for a token); `issued` counts the zones the Backend asked the loader for: a query, a transfer, the warm-up), then `fetchq: in_flight=N places=N peak=N table_full=N ring_dropped=N park_full=N park_timeout=N loader_busy=N ingest_busy=P% hist=A,B,C,D,E queued=N queue_peak=N waited=N queue_dropped=N queue_full=N` (0.7: where a fetch is held up; all counted since the start except `in_flight`, `queued` and `ingest_busy`: `in_flight` and `peak` are the fetches on their way now and the most there have been at one time; `places`, the places of `fetch-concurrency` in use now (whole-zone fetches in flight: 0 at rest); `queued`, `queue_peak` and `waited`, the requests that wait now for a place of `fetch-concurrency`, a token of `fetch-rate` or room under `memory-limit` (they are not refused: they wait in order, up to `park-timeout`), the most there have been, and how many had to wait; `queue_dropped`, those that ran out of `park-timeout`; `queue_full`, those refused because the queue of 8192 was full; `table_full`, requests refused because the 256 places of the fetch table were all taken; `ring_dropped`, requests the workers could not hand to the ingest thread because their ring of 128 was full; `park_full`, queries that found the table of parked queries full (`park-max`); `park_timeout`, parked queries whose zone was not there before `park-timeout`; `loader_busy`, fetches the loader turned away because its queue was full; `ingest_busy`, the share of the last ten seconds the ingest thread was working instead of waiting, 0 for the first ten seconds; `hist`, the time from the request to the install of the fetches that succeeded: up to 1 ms, up to 10 ms, up to 100 ms, up to 1 s, more; see "`karictl dbstatus` shows it" under "Memory limit (D1a)" in [`karidns(8)`](karidns.md)), the NOTIFY of zones that are out of memory (D1a: `notify of zones out of memory: queued=N deferred=N`, the zones whose serial changed while their data was out of memory that were handed to the control thread, and the ones that did not fit in the ring of 1024 and are queued later), the zone transfers of zones that are out of memory (D1a, `transfers of zones out of memory: waited=N loaded=N failed=N summary_answers=N marked=N timeout=Nms`: transfers that had to wait for the zone, the zones they got, the ones that ended with SERVFAIL, the IXFRs answered from the summary without reading the zone, the zones marked evict-next, and `transfer-fetch-timeout`) and the cost of the zone directory (`zone directory: N elements, B bytes in the registry + I bytes in the indexes of the views (P bytes per zone)`; the entries and images are not in it), then `alias: scans=N` (0.7: how many times the thread that resolves the targets of ALIAS records scanned the zone directory for them since the start; a scan follows a zone with ALIAS records coming, changing, going or being taken out of memory and a reconfiguration, not every zone that is fetched or evicted, so the number stays where it is while zones without ALIAS records come and go; see "Expansion" under POWERDNS ALIAS AND LUA RECORDS in [`karidns(8)`](karidns.md)). The warm-up and the cache (D1a step 7): `residency: directory=N resident=N out_of_memory=N evictions=N` (the zones of the directory with and without data in memory), `queries: answered=N parked=N hit_rate=P%` (the queries the zones answered, and the ones that had to wait for their zone; the hit rate is the share answered by a zone already in memory), `warm: received=0|1 queued=N loaded=N skipped=N (memory limit N, already in memory or gone N) failed=N pending=N in_flight=N` (the zones of the loader's hot list: queued to read, read, not read because the memory limit's high water mark was reached or because they were in memory or gone, failed, still waiting, being read), `warm-before-serve: off`, `holding the queries (N ms left)` or `queries accepted after N ms` (the queries are held while the hot list is read; the control channel is not), and `state-file: <path> at_start=... hot_lists_sent=N ... acks: written=N unchanged=N failed=N ...` (what the loader found in its state file at its start, how many hot lists the Backend sent, and what the loader answered; `state-file: none` without `loader-state-file`). The line `memory:` (0.7) says what the database needs in memory and what `memory-limit` does about it: `memory: zones=N (how the size of a zone was found) all_resident: zone_data=X backend=X loader=X | memory-limit=L fit=P% backend=X loader=X | recommended=R (half of the zones: at least H) | status=ok|notice|warning|error`; `zone_data` is what `memory-limit` would count with every zone in memory, `backend` and `loader` the resident sizes of the processes (`backend` after `all_resident:` with every zone in memory, after `memory-limit=` under the limit), `fit` the share of the zones that fit under the limit, `recommended` the `memory-limit` that keeps every zone, `status` the level of the syslog line the server says about it (`notice`: below what every zone needs, `warning`: less than half of the zones fit, `error`: the limit cannot hold the zones of the reads in flight). Without `memory-limit`: `| no memory-limit | recommended=R | status=ok`. The same figures are in syslog at every start and reload (docs/karidns.md, "Memory limit"). These lines come after the `zone directory:` line; the lines before keep their form. Then, the totals since the server started, and the last protocol error of the loader link. With a zone name (and optionally a view): that zone's view, database id, SOA serial, status (`applied`, `rejected` or `shadowed`) and the last error, then, for a `SLAVE` or `CONSUMER` zone (B7b), its type, masters and TSIG key and the last successful transfer with the serial (the data of such a zone is kept in memory only; `settings from the primary: in force` when the primary sent settings, B8t-2), then (B7a) the settings it runs with: where they come from (`profile 'name'` with the zone's own metadata overriding it, `the zone's own metadata`, or `none`), its `allow-transfer` and `allow-update` entries with their match mode, the entries `acl-ceiling` cuts away (`lies outside acl-ceiling`, `is narrowed by acl-ceiling`, or `no acl-ceiling is configured: these ACLs refuse everybody`) and a `settings error` line when a TSIG key the settings name is no longer defined in `karidns.conf`. The summary also counts the distinct settings (zones with the same settings share one block) and the zones that name an undefined key. A zone that was rejected keeps serving its last good version (its serial is shown). Without a `database` block the server answers `ERROR no database block is configured`. With the zone store (0.7) the `store pass:` line shows the reconcile with the loader: the pass that runs or ran last (the entries it listed, new / changed / renamed / unchanged / already asked for / refused with this version), the sweep (zones the pass did not list, deleted), the bodies (records without one now, fetched, failed, in flight) and the changes applied; a `MASS-DELETE GUARD HELD:` line says that a sweep was held back (more than 20 percent of a view's zones and more than 1,000 are not in the database) and that `karictl reload -force` releases it.
  ```sh
  karictl dbstatus
  karictl dbstatus example.test
  ```

`store [-j | -k] [zone <name> [view]]`
: Show the zone store of the database zones (0.7): its state, the zones in it, the zones in memory, how often zones were attached and how fast, the queries that had to wait for a zone ("cold" queries), the second-level cache and the memory advice. Every figure is a counter, a value kept where it changes, or a bounded sample: a request never walks the zones, and a poll costs the same at 10 million zones as at a hundred, so it is safe once a second. Reading never resets a counter. `store` needs the same permission as `dbstatus` (a `read-only yes` key has it).

  Three forms of the same figures: the default is text in sections for a person; `-j` is one JSON object; `-k` is one `key=value` line per figure for shell scripts. WebAdmin and the dnstap-live dashboard poll the JSON form. `zone <name> [view]` shows the record of one zone instead: one index lookup, the zone is not attached (a name that exists in several views needs the view; case and a trailing dot do not matter). Without a store in the configuration, or before the Backend has opened it, the command still works: `store.state` is `none`, and the attach counters and the memory figures are there.
  ```sh
  karictl store
  karictl store -j
  karictl store -k | grep '^store.attach.p99_us='
  karictl store zone example.test
  karictl store -j zone example.test external
  ```

  On ZFS the server cannot read the ARC statistics (it runs in a sandbox); `store.cache.kind` is `arc`, and `karictl` itself appends the `store.cache.arc.*` keys from `kstat.zfs.misc.arcstats.*`. On UFS the share of segment pages that are in memory is a `mincore(2)` sample of at most 4096 random pages, taken at most every 10 seconds; where `mincore` is not allowed `store.cache.page.available` is 0 and `store.cache.page.note` says `n/a` and why.

  **The names of the keys are an interface.** They are flat and dotted, the same in the `-j` and the `-k` form; in JSON every number is a number (an integer, never a string, never a float) and every other value a string. `schema` is the version of the list (now 1): a key is never renamed or given another unit within a schema, new keys can appear at any time, so a reader takes the keys it knows and ignores the others. Names ending in `_bytes` are bytes, `_us` microseconds, `_pct` an integer percentage; a latency percentile is the upper bound of the bucket it falls in (the buckets are 1, 2, 4, ... 8388608 microseconds, so it is exact to a factor of 2); `max_us` is exact. A rate is the difference of a counter between two polls divided by the difference of `store.time.mono_ms` (the server's monotonic clock in milliseconds; `store.time.unix` is the wall clock in seconds).

  | Key | Meaning |
  |---|---|
  | `schema` | Version of this key list (1) |
  | `store.time.mono_ms`, `store.time.unix` | Server's monotonic clock in milliseconds, wall clock in seconds, at the moment of the reply |
  | `store.state` | `none` (no store), `ok`, or `degraded` (the disk is full: new and changed zones are kept without an image until room is back; `store.space.*`) |
  | `store.state_bits` | The state as bits: 1 disk full (degraded, or the last write failed for lack of room), 2 repaired at the last open |
  | `store.format`, `store.mode`, `store.fstype`, `store.uuid` | Store format version; `map` (segments mapped) or `copy` (read with `pread`, for ZFS); file system type; store identity (32 hex digits). With `store.state` `none` this and every key down to `store.cache.*` is absent |
  | `store.clean_flag` | 1 when the superblock on disk says "clean stop" (0 while the server runs) |
  | `store.zones.known`, `.stored`, `.rejected`, `.free` | Zones in the store by state: known without an image (the database fetch has them), stored (an image is in the store), rejected (flagged by the last reconcile), free table slots |
  | `store.zones.nonstore` | Zones of the database whose name the store cannot hold (the root zone): they have no record and are served from the heap directory (with the store protocol; the line is there when a loader is running) |
  | `store.zones.attached` | Zones attached (in memory as images) now: successful attaches minus detaches |
  | `store.zones.image_bytes` | Bytes of the stored images (records) |
  | `store.views.count` | Views in the store |
  | `store.view.<n>.name`, `.known`, `.stored`, `.rejected`, `.image_bytes` | The same per view, `<n>` = 0, 1, ... (the store's view number) |
  | `store.tables.zt_records`, `.zt_capacity`, `.nx_used_bytes`, `.nx_dead_bytes` | Zone table records in use and room; long names, used and dead |
  | `store.tables.ix_gen`, `.ix_slots`, `.ix_used`, `.ix_live`, `.sx_gen`, `.sx_slots`, `.sx_used`, `.sx_live` | Name index and source index: generation, slots, slots used, live entries |
  | `store.segments.count`, `.used_bytes`, `.live_bytes`, `.dead_pct` | Image segments: highest segment number in use, bytes appended to the segments that exist, bytes still referenced, share that the cleaner can win |
  | `store.segments.free_numbers`, `.draining`, `.pinned` | Segment numbers that are free (the segment was cleaned and removed; the number is used again), segments with no live record that wait for a checkpoint, a grace period or the end of the references, segments that an attached zone's image points into (MAP mode) |
  | `store.journal.lsn`, `.checkpoint_lsn`, `.committed_lsn`, `.bytes`, `.gen`, `.max_bytes` | Journal position, last checkpoint, last durable commit, size, generation, the size at which a checkpoint is forced (100 MiB: a replay of that takes about a second) |
  | `store.checkpoint.count`, `.last_unix`, `.last_us` | Checkpoints since the open, when the last one ended, how long it took |
  | `store.writes.commits`, `.puts`, `.replaces`, `.deletes`, `.growths`, `.errors` | Writer counters since the open |
  | `store.recovery.created`, `.was_clean`, `.used_older_super`, `.rebuilt`, `.journals_read`, `.records_replayed`, `.journal_torn`, `.rebuilt_zones`, `.dropped_zones`, `.open_us` | What the last open found and did, and how long it took |
  | `store.open.ix_read_us`, `.zt_readahead_us`, `.zt_readahead_done` | The open reads the name index once before the first answer (`ix_read_us`: how long that took); a thread then reads the zone table into memory in the background (`zt_readahead_us`, 0 until `zt_readahead_done` is 1) |
  | `store.errors.total` | Texts put into the error ring (`err.ring`, the last 65,536 are kept) since it was made: why a zone was refused or failed |
  | `store.entries.available` | 1 when the figures of the server's own tables below are there (a server with the store on) |
  | `store.entries.pool_used`, `.pool_slabs`, `.pool_slab_bytes`, `.pool_slot_bytes`, `.pool_free_slots` | The pool of zone entries: slots in use (one for every zone in memory), slabs, bytes of a slab, bytes of a slot (256), free slots |
  | `store.entries.attach_table_slots`, `.attach_table_grows`, `.attach_table_shrinks` | The table that finds a zone in memory by its zone id: slots now, how often it was made larger and smaller |
  | `store.fold.zones`, `.rows`, `.replaced` | Zones that left memory with their counters folded into the totals of their view, rows of the table of the top zones (those with the most queries that are not in memory), rows a busier zone took over |
  | `store.errors.memory_texts`, `.memory_noted`, `.memory_pushed_out` | The texts of rejected zones in the ring in memory (512), how many were noted since the start, how many were pushed out by newer ones (the file `err.ring` still has them; `store.errors.total`) |
  | `store.detach.sampled` | Zones that were taken out of memory because the sample of the attach table chose them (also in `store.detach.count`) |
  | `store.compact.runs`, `.moved_records`, `.moved_bytes`, `.segments_freed`, `.last_unix` | The cleaner (since the open): segments it began to clean, records and bytes it copied to the open segment, segments it removed, when it last worked |
  | `store.compact.bad_records`, `.pinned_skips`, `.incomplete` | Live records that failed their checksum when the cleaner was to copy them (the zone became known and is read from the database again), emptied segments that were held by an attached image (counted once each), segments the cleaner could not empty (a record it cannot read; it tries again after ten minutes) |
  | `store.compact.rate_bytes`, `.candidates`, `.dead_bytes` | Bytes a second the cleaner may copy (0 = no limit), segments that are dead enough (half dead and at least a quarter of a segment or 1 MiB dead) now, dead bytes of all segments but the open one |
  | `store.compact.nx_reclaims`, `.nx_reclaimed_bytes` | Passes that gave back the space of long zone names that were deleted (`store.tables.nx_dead_bytes`), and the bytes they gave back |
  | `store.space.level` | `ok`, `low` (a WARNING was said: the file system is getting full), `degraded` (no room: new and changed zones are kept without an image) |
  | `store.space.fs_total_bytes`, `.fs_free_bytes`, `.checked_unix` | The file system of the store, as of the last check (at every checkpoint, about every second while images are written) |
  | `store.space.reserve_bytes`, `.store_bytes` | Free bytes that only the cleaner may use (images are refused below that: half a segment, 256 KiB to 128 MiB); what the store occupies |
  | `store.space.growth_bytes_per_hour`, `.full_in_hours` | The growth over the last hour (0 until five minutes of history exist, or when the store shrinks) and the hours until the file system is full at that growth (0 = not known) |
  | `store.space.degraded_puts`, `.enospc_events`, `.degraded_since_unix` | Zones that were kept without an image because no room was left (since the open), writes that found no room, when the degraded state began (0 = not degraded) |
  | `store.fs.blksize`, `.recordsize_warning` | `st_blksize` of a table file (on ZFS the record size of the dataset) and 1 when it is above 32 KiB (the server says so in syslog; see "The zone store" in karidns.md) |
  | `store.scrub.interval_s`, `.running`, `.progress_pct` | Seconds between two scrubs (0 = never), whether a pass runs, how far it is |
  | `store.scrub.passes`, `.last_start_unix`, `.last_end_unix`, `.zones_checked`, `.bytes_checked` | Passes since the open, when the last began and ended, zones and bytes read |
  | `store.scrub.bad_images`, `.bad_cells`, `.bad_index`, `.io_errors` | What the scrub found since the open: images whose checksum or structure was wrong (the zone became known and is read again), damaged table records, index entries that did not lead to their zone (both repaired at the end of the pass), read errors |
  | `store.cache.kind` | `page` (UFS: `mincore` sample), `arc` (ZFS), `copy` |
  | `store.cache.page.available` | 1 when the sample worked, else 0 and `store.cache.page.note` ("n/a: ...") |
  | `store.cache.page.sampled_pages`, `.resident_pages`, `.resident_pct`, `.sample_age_ms` | The sample: pages looked at, of them in memory, the share, age of the sample |
  | `store.cache.note` | On ZFS: `see karictl (ARC kstats)` |
  | `store.cache.arc.available`, `.size_bytes`, `.target_bytes`, `.target_min_bytes`, `.target_max_bytes`, `.hits`, `.misses`, `.hit_pct`, `.compressed_bytes`, `.uncompressed_bytes` | ARC figures, added by `karictl` on ZFS (a kstat that cannot be read is left out) |
  | `store.memory.arc.backend_bytes`, `.arc_max_bytes`, `.loader_bytes`, `.other_bytes`, `.total_bytes`, `.ram_bytes`, `.pct`, `.level`, `.text` | Added by `karictl` on ZFS: the Backend's heap (with `memory-limit` its size under the limit, else with every zone in memory), `vfs.zfs.arc.max`, the loader, about 1 GB for the system, their sum against `hw.physmem`, the share in percent, `ok` / `notice` (above 85 percent) / `warning` (above RAM) and the sentence (in the text form: the section `arc sum`) |
  | `store.attach.count` | Zones attached from the store since the start |
  | `store.attach.failed` | Attaches that failed; `store.attach.fail.checksum`, `.record`, `.invalid`, `.io`, `.memory`, `.other` by cause |
  | `store.attach.p50_us`, `.p90_us`, `.p99_us`, `.max_us` | Time of an attach |
  | `store.attach.hist.le_<2^i>us`, `.hist.more` | The histogram: attaches that took at most 1, 2, 4, ... 8388608 microseconds (each in its own bucket, not cumulative), and longer; not in the text form |
  | `store.detach.count` | Zones taken out of memory; `store.detach.limit` (memory-limit), `.room` (to make room for another zone), `.operator`, `.other` by reason |
  | `store.cold.attach`, `.fetch`, `.timeout` | Queries for a zone that was not attached: answered after an attach, sent to a database fetch (a zone with no image, or a damaged one), ended by the park time-out |
  | `store.cold.p50_us`, `.p90_us`, `.p99_us`, `.max_us`, `.hist.le_<2^i>us`, `.hist.more` | Time from the parked query to its answer, for `store.cold.attach` |
  | `store.memory.available` | 1 when the figures below are there |
  | `store.memory.zones`, `.records`, `.basis` | Zones and records the estimate is for, and where the size of a zone comes from (`assumed`, `resident`, `records`) |
  | `store.memory.counted_all_bytes`, `.avg_zone_bytes`, `.backend_all_bytes`, `.loader_all_bytes`, `.directory_bytes` | What `memory-limit` counts with every zone in memory, the average zone, the Backend and the loader with every zone in memory, the directory alone |
  | `store.memory.recommended_limit_bytes`, `.working_min_bytes`, `.fit_min_bytes`, `.limit_bytes`, `.fit_pct`, `.backend_limit_bytes`, `.loader_limit_bytes` | `memory-limit` that keeps every zone, that keeps half, below which the server says ERROR, the one in force (0 = none), the share of the zones that fit, the Backend and the loader under it |
  | `store.memory.level` | `ok`, `notice`, `warning` or `error`: what the server says in syslog about `memory-limit` |
  | `store.recon.available` | 1 when the figures below are there (the Backend has a loader that speaks the store protocol) |
  | `store.recon.pass.active`, `.view`, `.started_unix`, `.duration_ms`, `.estimate` | The pass of the loader that is running or was the last: its view, when it started, how long it took (so far), the entries the loader announced |
  | `store.recon.pass.entries`, `.created`, `.changed`, `.renamed`, `.same`, `.pending`, `.kept`, `.skipped` | What the pass found: zones listed, new, with another stamp, renamed, unchanged, already asked for, refused with this stamp and not asked for again, and the ones the loader could not offer (`n_skipped`) |
  | `store.recon.sweep.total`, `.unlisted`, `.deleted` | The last sweep: zones of the view in the store, of them not listed by the pass, deleted |
  | `store.recon.passes`, `.wanted`, `.cursors_kept` | Since the start: passes, zones whose body was asked for by a pass or a change, cursors made durable |
  | `store.recon.bodies.known`, `.fetched`, `.failed`, `.in_flight` | Records without a body now (known), and what the background fetch has done since the start: bodies brought, failed, asked for and not here yet |
  | `store.recon.changes.upserts`, `.deletes` | Entries of the change log applied (upserts and deletes) |
  | `store.recon.guard.held_views` | Views whose sweep the mass-delete guard holds back (0 normally). With 1 or more: `.view`, `.unlisted` (zones the pass did not list), `.total`, `.since_unix` and `.release` (`karictl reload -force`) |
  | `store.zone.name`, `.view`, `.zid`, `.state` | With `zone <name>`: the record of one zone (only these keys, besides `schema` and `store.time.*`): name, view, zone id, `stored` or `known` |
  | `store.zone.serial`, `.flags`, `.source`, `.source_id`, `.stamp_gen`, `.stamp_time`, `.settings` | SOA serial of the stored version, flag bits, source number and the zone's id in that database, version stamp, settings id |
  | `store.zone.image_bytes`, `.segment`, `.offset`, `.digest` | Size of the image, where it lies (segment and byte offset; not for a known zone), digest of the zone content (hex) |
  | `store.zone.attached` | 1 when the zone is attached now (where the server can tell) |

  A bad argument, a zone that is not in the store (`ERROR zone not found`), a name in several views without a view, or `zone` without a store are answered `ERROR ...` (exit status 3).

`store compact`, `store checkpoint`, `store scrub start`, `store scrub stop`
: Change the store (0.7); they are not read commands, so they need the main control key (a restricted key, read-only or with `allow-commands`, does not have them). `store compact` asks the cleaner to run without its rate limit until no segment is dead enough (it returns at once; `store.compact.*` shows the progress), then the server writes a checkpoint and removes the segments that are empty. The cleaner runs by itself, at 16 MiB a second at most, whenever a segment is half dead; this is for after a mass change, or before a measurement. `store checkpoint` writes a checkpoint now (the journal is cut, what was written is durable) and answers when it is done. `store scrub start` begins a scrub pass at once (the scrub reads every record, at most 16 MiB a second; `store-scrub-interval` starts one by itself); `store scrub stop` ends the pass that runs. The answers are `OK ...` or `ERROR ...` (exit status 3).
  ```sh
  karictl store compact
  karictl store -k | grep '^store.compact.'
  karictl store scrub start
  ```

`trace [level]`
: Change the debug level in force of the server (0.7; `rndc trace`): without an argument one more (at most 99), with one that level, a number from 0 to 99. The reply is `OK debug level is now N`; a level that is not a number from 0 to 99 is answered `ERROR trace: the debug level must be a number from 0 to 99`, a second argument `ERROR trace takes one argument at most: ...` (exit status 3, the level is not changed). The server logs each change as `[Control] debug level is now N` (category `general`, notice). The channels with `severity dynamic` write the messages up to the level, and the built-in `default_debug` (the file `karidns.run` in `options { directory }`) writes everything up to it while it is above 0; see karidns(8), `logging`. The level is not kept across a restart (`karidns -d` sets it at the start). Every process of the server follows (0.7): the sandboxed process, which has the control channel, hands the level to the supervisor (with the supervisors of the plugins and of `karidns-dbloader`), the UDP routers, the connect broker and the loader, and a loader that is started again later comes up with the level in force.
  ```sh
  karictl trace 3      # the debug 3 lines of query-errors (why a query was REFUSED) appear in the dynamic channels
  karictl notrace
  ```

`notrace`
: Set the debug level to 0 (`rndc notrace`); the reply is `OK debug level is now 0`. An argument is refused (`ERROR notrace takes no argument`).

  `trace` and `notrace` need the permission `trace` of a restricted control key (`allow-commands { trace; }`); a `read-only yes` key alone does not have it.

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

The file is not parsed as a full configuration file: `karictl` takes the quoted value that follows the **first** occurrence of the word `secret`, and the quoted value that follows the first occurrence of the word `socket`, anywhere in the file **outside comments (`#`, `//`, `/* */`) and quoted strings** (the sample's own comment mentions `{ secret "..."; }`, which an earlier version took for the secret). White space after the `=` padding of the secret is ignored. The value after the first `algorithm` (quoted or not) selects the HMAC: `hmac-md5`, `hmac-sha1`, `hmac-sha224`, `hmac-sha256` (default), `hmac-sha384` or `hmac-sha512`; it must match the server's `control-channel { algorithm }`, and an unsupported name exits with status 2. The key name is not used. The secret may decode to at most 256 bytes. `karictl` prints a warning when the file is readable by group or other users; it should have mode `0600`.

**Restricted keys.** The server can hold several keys, each allowed to run only some commands (`control-channel { keys { } }` in [`karidns.conf`](karidns.md), "Restricted control keys"). `karictl` needs nothing for that: give each user a `karictl.conf` with the `secret` and the `algorithm` of the key it should use. The server finds the key by the response to its challenge. A command the key may not run is answered with `ERROR command not allowed for key "<name>"` and `karictl` exits with status 3; the server logs it with the key name. To let a user other than the server's in, the server's `control-channel { allow-group }` must name a group that user belongs to (the socket is then group-writable); the user needs the `karictl.conf` of its key and no access to `karidns.conf`.

---

## EXIT STATUS

`0`
: Command executed successfully (including `tsig-keygen` and `-v`).

`1`
: Socket path too long, connection failure to the control socket, or failure to receive the challenge.

`2`
: Usage error (no command, an unknown option, `notify` / `retransfer` / `zonestatus` / `rollback` without a zone name; the usage text goes to standard error and nothing is sent to the server), or the secret could not be read or decoded from the configuration file, the challenge was invalid, or authentication failed. A command the server does not know is not a usage error for `karictl`: the server answers `ERROR unknown command` and the exit status is 3. `-h` and `--help` print the usage text to standard output and exit with 0.

`3`
: The server returned an error (`ERROR ...`, including a failed `reload` or `reconfig`, a `trace` level that is not a number from 0 to 99, a command that the key is not allowed to run, a database zone that was rejected or could not be read, and a reload that timed out) or an invalid `status` or `observatory` response (also `dbstatus` without a database block).

---

## FILES

`/usr/local/etc/karidns/karictl.conf`
: Default control channel client configuration file.

`/var/run/karidns/control.sock`
: Default UNIX domain socket endpoint monitored by the `karidns` daemon.

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karicheck(8)`](karicheck.md) — Configuration and zone file validation utility
- [`karidns-dbloader(8)`](karidns-dbloader.md) — The database loader that `reload` and `dbstatus` talk to
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                    KARICTL(8)
```

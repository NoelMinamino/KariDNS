# KARIDNS-SIGNER(8) — KariDNS Signer Daemon

## NAME

**karidns-signer** — keeps the zones of a KariDNS database (PostgreSQL or SQLite3) signed: static DNSSEC, signed again before the signatures run out and whenever a zone changes

## SYNOPSIS

```text
karidns-signer [-c <config>]
karidns-signer [-c <config>] --check
karidns-signer --version | -h | --help
```

## DESCRIPTION

`karidns-signer` (0.6.0, item C) is a Node.js daemon that **orchestrates** the signing of the zones in a PowerDNS 5.1 database that [`karidns(8)`](karidns.md) serves through [`karidns-dbloader(8)`](karidns-dbloader.md). It does no DNSSEC arithmetic and does not touch the zone data itself:

| Task | Done by |
|---|---|
| generate keys | BIND 9.20 `dnssec-keygen` |
| sign the zone (NSEC / NSEC3 chain, RRSIG, SOA serial) | BIND 9.20 `dnssec-signzone` (its own verification step is `verify`) |
| read the zone, write the DNSSEC records back | [`karidns-zone`](karidns-zone.md) (`export --signer`, `import --signer`) |
| check the signed zone | [`karicheck zone`](karicheck.md) |
| ask the server to read the zone | a row in `karidns_reload_requests` (PostgreSQL) or `karictl reload` (SQLite3) |

What Node does itself: the schedule (`karidns_signer_state`), the key requests (`karidns_key_requests`), the keys (`cryptokeys` rows to `K*.private` / `K*.key` files and back, with `node:crypto` for the public half of a key), and the child processes. The only npm package is `pg` (exact version, `package-lock.json`, installed with `npm ci --ignore-scripts`); SQLite3 uses the `node:sqlite` of Node. Node 22.13 or newer is needed (the package uses Node 24).

The signer serves the model of the rest of KariDNS: **static** DNSSEC. The signed zone is data in the database, the server serves it as it is. There is no online signing, **no automated key rollover** (the procedure is the operator's, below), and no CDS / CDNSKEY publication; those belong to a later release.

A zone is the signer's when it has the domain metadata `X-KARIDNS-SIGNER` = `1`. The signer sets it itself: **a key request of kind `enable` is how a zone is put under the signer** (below), or `karidns-zone import --signer` of a zone you signed yourself.

## OPTIONS

`-c`, `--config` *file*
: The configuration file. Default `/usr/local/etc/karidns/karidns-signer.conf`.

`--check`
: Read the configuration, check the permissions of the work directory and of the `conninfo-file`, that the SQLite3 file can be opened for writing, the versions of `dnssec-keygen`, `dnssec-signzone`, `karidns-zone` (and that it has the driver of `database`), `karicheck` and, with SQLite3, `karictl`; then exit. Every line is `ok: ...` or `problem: ...`. Exit status 0 when fine, 1 when there is a problem. It does not connect to the database.

`-v`, `--version`
: Print the version.

`-h`, `--help`
: Print the usage.

**Signals.** `SIGTERM` and `SIGINT` stop the daemon after the zones that are being signed are finished (their key files are wiped), exit status 0; a second signal does not interrupt a zone. `SIGHUP` reads the configuration file again: a file with a mistake is refused and the old settings stay. `database`, `conninfo-file`, `sqlite-file`, `schema` and `work-dir` need a restart (SIGHUP logs a warning and keeps the old value); so do `log` and the paths of the tools (`karidns-zone`, `karicheck`, `karictl`, `bind-tools`), which are read at start only. Everything else (`workers`, the signature times, `verify`, `nsec3-opt-out`, the per-zone sections, `timeout`, `debounce`, `karictl-config`, `karictl-socket`) is used from the next zone on.

**Exit status.** 0 after `SIGTERM` / `SIGINT`, or for `--help`, `--version` and a fine `--check`; 1 for a configuration or database problem, a fatal error while running (the connection to the database is lost and cannot be made again) or a `--check` problem; 2 for a usage error.

## CONFIGURATION FILE

Lines of `key = value`; `#` starts a comment (in a value, after white space); a value may be in double quotes; `[zone <name>]` starts the section of one zone. A key written twice in one place, an unknown key and a bad value are errors that name the line. Durations are a number with an optional unit `s`, `m`, `h`, `d` or `w` (a bare number is seconds). `karidns-signer.conf.sample` shows all of it.

| Key | Default | Meaning |
|---|---|---|
| `database` | (required) | `pg` or `sqlite3`. |
| `conninfo-file` | | `pg`: the file with the connection string of the signer's role. A regular file (no link) owned by the user the signer runs as, mode `0600` or `0400` (checked like the loader checks its own). Keywords: `host`, `port`, `dbname`, `user`, `password`, `sslmode`, `connect_timeout`, `application_name`; another keyword is refused. |
| `schema` | the role's `search_path` | `pg`: the schema of the PowerDNS and `karidns_*` tables. |
| `sqlite-file` | | `sqlite3`: the database file. The user needs write access to the file **and its directory** (`<file>.signer.lock` is created there, WAL files too). |
| `karictl-config` | | `sqlite3`: the `karictl` configuration of the restricted key that asks the server to reload a zone (below). Required for `sqlite3`. |
| `karictl-socket` | from that file | `sqlite3`: the control socket (`karictl -s`). |
| `work-dir` | `/var/db/karidns-signer/work` | Where the key files and the work files of a zone live while it is signed: `<work-dir>/<zone>.<pid>.<n>/`, mode `0700`, files `0600`. It must be a directory of the signer's user with no access for group or others (checked at start). Put it on tmpfs (the rc script does). |
| `workers` | half of the CPUs, at least 1 | Zones signed at the same time (1 to 256). |
| `karidns-zone` | `/usr/local/bin/karidns-zone` | Must have the driver of `database` (`karidns-zone --version` lists them). |
| `karicheck` | `/usr/local/bin/karicheck` | |
| `karictl` | `/usr/local/bin/karictl` | `sqlite3` only. |
| `bind-tools` | `/usr/local/bin` | The directory of `dnssec-keygen` and `dnssec-signzone` (BIND 9.20, the FreeBSD package `bind-tools`). |
| `validity` | `14d` | How long a signature is valid (`dnssec-signzone -e now+validity`). At least 60 s. |
| `refresh` | `302400` (3.5 days) | A signature is made again when this much of its life is left. |
| `jitter` | `1d` | A random part of it, per run, is taken off the due time (and given to `dnssec-signzone -j`), so many zones do not all fall due at the same second. |
| `verify` | `yes` | `no` passes `-P` to `dnssec-signzone`: no verification of the signed zone. |
| `nsec3-opt-out` | `no` | NSEC3 Opt-Out (RFC 5155 section 6) for the zone's chain; `-A`. It applies from the next run. |
| `debounce` | `5` | Seconds after the last change of a zone before it is signed again; a burst of changes waits at most 6 times as long (30 s). |
| `timeout` | `1800` | Seconds a child process may run (at least 10); then it is killed and the zone fails. |
| `log` | `stderr` | `stderr`, or a syslog facility (`daemon`, `local0` ... `local7`, ...): lines go to `logger(1)`, tag `karidns-signer`, priority `notice`. |

`validity`, `refresh`, `jitter`, `verify` and `nsec3-opt-out` can also be set per zone, in a `[zone <name>]` section; the zone name is plain LDH (letters, digits, hyphen, underscore; IDNs in their punycode form) and written once. The whole must satisfy `refresh > 0` and **`refresh + jitter < validity`** for the global values and for every zone (otherwise every signature would fall due at once); `--check` and `SIGHUP` say which one does not.

```text
database = pg
conninfo-file = /usr/local/etc/karidns/signer.conninfo
log = daemon
workers = 2
validity = 14d
refresh = 3d
jitter = 12h

[zone example.test]
validity = 30d
refresh = 7d
jitter = 2d

[zone optout.example.test]
nsec3-opt-out = yes
```

## SETUP

1. **The database** must be at schema version 3 with the signer's tables: apply `db/karidns_ext.pgsql.sql` or `db/karidns_ext.sqlite3.sql` ([`karidns-dbloader(8)`](karidns-dbloader.md), "The signer's tables"). PostgreSQL: `psql -v ON_ERROR_STOP=1 -v role=karidns_signer -v schema=public -f db/karidns_signer_role.pgsql.sql <db>` as the owner, then `GRANT karidns_signer TO <login role>` (or create the role with `LOGIN`). The script refuses a role that could bypass row level security.
2. **The signer's user.** The FreeBSD package `karidns-signer` (install one of `karidns-sqlite3`, `karidns-postgresql` or `karidns-db` first: it needs their `karidns-zone`) installs the program under `/usr/local/libexec/karidns-signer` with its `node_modules`, a wrapper `/usr/local/sbin/karidns-signer`, the rc script `karidns_signer`, `karidns-signer.conf.sample` and the user and group `karidns-signer`; it depends on `node24` and `bind-tools` ([Distribution Guide](distribution.md), 2.6). The signer must **not** run as root, as the server's user or as the database owner.
3. **The configuration file** and, for PostgreSQL, the conninfo file (`chown karidns-signer`, `chmod 0600`). Check it as the signer's user: `service karidns_signer configtest`, or `su -m karidns-signer -c 'karidns-signer --check -c /usr/local/etc/karidns/karidns-signer.conf'`.
4. **The server.** `database { signer-wait yes; }` is the default; see "The server waits for the signer". With SQLite3 add the restricted control key of the signer to the server (below).
5. **Start:** `sysrc karidns_signer_enable=YES; service karidns_signer start`. The rc script mounts a tmpfs (`karidns_signer_tmpfs_size`, default 256m, mode `0700`) on the `work-dir` of the configuration file, starts the daemon with `daemon(8)` (restart after 10 s if it dies, for instance because the database was down at boot), sets `ulimit -c 0`, and unmounts the tmpfs on stop. Under the rc script standard error goes to /dev/null, so set `log = daemon` (or another facility) in the configuration file. `service karidns_signer reload` sends `SIGHUP`. `karidns_signer_cpuset="2-3"` starts it under `cpuset -l`.
6. **Put a zone under the signer** (next section).

## KEY REQUESTS

A row in `karidns_key_requests` asks the signer for something. The WebAdmin files the rows (a global master or the zone's domain master); an operator can do it with SQL:

```sql
-- start signing example.test: a CSK, ECDSA P-256, NSEC3 without salt and with 0 iterations (RFC 9276)
INSERT INTO karidns_key_requests (domain_id, kind)
  SELECT id, 'enable' FROM domains WHERE name = 'example.test';
-- more of it: KSK + ZSK instead of a CSK, ECDSA P-384, NSEC instead of NSEC3
INSERT INTO karidns_key_requests (domain_id, kind, algorithm, key_type, nsec)
  SELECT id, 'enable', 14, 'ksk', 'nsec' FROM domains WHERE name = 'example.test';
-- the answer
SELECT r.id, d.name, r.kind, r.state, r.message FROM karidns_key_requests r JOIN domains d ON d.id = r.domain_id ORDER BY r.id DESC LIMIT 10;
```

| Column | |
|---|---|
| `kind` | `enable`: start signing the zone. The signer generates the first key (a `csk`) or keys (`key_type` `ksk` or `zsk` makes a KSK **and** a ZSK), signs the zone, stores the keys, and sets the metadata `X-KARIDNS-SIGNER`, `PRESIGNED` and (NSEC3) `NSEC3PARAM`. `add`: one more key (`ksk` or `zsk`; `csk` makes a key with the SEP bit, like `ksk`) for a zone the signer signs; the zone is signed again with it at once. |
| `algorithm` | 8 (RSASHA256), 10 (RSASHA512), 13 (ECDSAP256SHA256, the default), 14 (ECDSAP384SHA384), 15 (Ed25519), 16 (Ed448). Algorithms 5 and 7 (SHA-1) are refused (RFC 8624). |
| `bits` | RSA only, 1024 to 8192. |
| `key_type` | `csk` (default; one key with the SEP bit signs everything), `ksk` (flags 257) or `zsk` (flags 256). |
| `nsec` | `enable` only: `nsec3` (default) or `nsec`. A zone that is signed already keeps its chain; the parameters are those of its `NSEC3PARAM` metadata. |
| `state`, `message`, `done_at` | `pending`, then `done` or `failed` with the reason. One pending request per zone: a second is refused until the first is answered. |

The requests are polled every 5 seconds, 50 at a time; when a batch is started in full, the next one is read at once, so a bulk of requests is not held to 10 zones per second. An `enable` request for a zone that has keys and the metadata `PRESIGNED` already (for instance a zone PowerDNS signed, keys in `cryptokeys`) generates **no** key: the signer takes over with the keys that are there. A zone with keys but without `PRESIGNED` is refused, because the server does not serve such a zone (no online signing).

**Where the keys go.** `dnssec-keygen` runs in the work directory; the key is read from its `.private` file (Private-key-format v1.2, the form PowerDNS keeps in `cryptokeys.content`), the files are wiped, the tag computed by the signer is compared with the one `dnssec-keygen` chose (RFC 4034 appendix B). The key is stored in `cryptokeys` (`flags` 257 or 256, `active` and `published` true) **after** the signed zone is written, so a key can never be in the database without a zone that uses it. If that `INSERT` fails (database failover, say) the signer tries again for about 10 minutes (15 times, from 1 s to 60 s) with the same key; if it cannot, the request is `failed` with the message that the keys were lost and the DNSKEYs have to be replaced with a request of kind `add`.

## HOW A ZONE IS SIGNED

For each zone, in a work directory of its own (wiped on every path, also after an error and at start):

1. **Lock.** PostgreSQL: `pg_try_advisory_lock(hashtextextended('karidns-signer:<id>', 0))`, so several signer instances can share a database and a zone is signed by one of them (a zone that another instance holds is tried again after 30 s). SQLite3: one signer per database file (`<file>.signer.lock`).
2. **Keys.** The `cryptokeys` rows with `active` or `published` become the DNSKEY RRs of the zone; the `active` ones are written as key files (`0600`) and sign. The zone needs an active key with the SEP bit (flags 257), because the DS record at the parent is made from one.
3. **Export.** `karidns-zone export --signer`: the zone as the input of `dnssec-signzone`, without the NSEC / NSEC3 chain and its signatures (the chain is built again every run, because a zone that was changed since it was signed has no complete chain), with the data signatures that are still good. The DNSKEY lines are replaced by the ones of the keys.
4. **Sign.** `dnssec-signzone -q -o <zone> -O full -e now+<validity> -i <refresh+jitter> -j <jitter> -N increment -R [-3 - -H 0 [-A]] [-P] (-z | -x)` with the key files of the `active` keys. A CSK or a lone key signs everything (`-z`); with a KSK and a ZSK only the KSK signs the DNSKEY RRset (`-x`). The SOA serial is increased by one (`-N increment`). Signatures that have more than `refresh + jitter` left are kept (`-i`), so a change does not re-sign the whole zone. `-R` drops the signatures of keys that are no longer in the zone. `dnssec-signzone` verifies the result unless `-P` (`verify no`).
5. **Check.** `karicheck zone <zone> <signed file>`.
6. **Write.** `karidns-zone import --signer --json [--reload]` in one transaction: the DNSSEC rows are replaced, the SOA serial updated, `ordername` / `auth` updated, the metadata set. If the zone changed since the export, nothing is written (exit status 3) and the signer starts again at once (up to 3 times in a row, then it counts as an error). The result carries the new serial, the **earliest RRSIG expiration** and the id of the write.
7. **Reload.** PostgreSQL: the row in `karidns_reload_requests` is written by `import --signer --reload` in the same transaction as the signatures. SQLite3: `karictl reload <zone>` with the signer's restricted key. A failed reload is a warning (the zone is signed; the server serves the old version until it reloads).
8. **State.** `karidns_signer_state`: `signed_at`, `signed_serial`, `min_expire`, `next_due`, `attempts` = 0, `last_error` NULL. Keys of an `enable` request are stored now (see above) and the request is answered.

**Deviations from a plain `dnssec-signzone` run, and why.** `-i` is `refresh + jitter` (the run is placed up to `jitter` before the refresh point). No timing metadata is written to the key files (`-S` is not used) and `-Q` is not used (without timing metadata it would sign everything again on every run). The DNSKEY RRs of all active and published keys are appended to the input, because `dnssec-signzone` 9.20 takes the keys from the zone's DNSKEY RRset. The NSEC / NSEC3 chain and its signatures are rebuilt in every run: more CPU for a big zone, and an IXFR carries the whole chain each time. A retired key (published, not active) keeps the signatures it made over RRsets that did not change until they expire; on a changed RRset its old signature (invalid, harmless) stays next to the new one.

**On error** nothing is written: the zone keeps its last good signed data. `attempts` is increased, `last_error` is set (cut to 1 KB, no key material), and `next_due` is now plus 1 minute, doubling to 1 hour. An operator who has fixed the cause resets it with `UPDATE karidns_signer_state SET next_due = <now>` (PostgreSQL: `now()`, SQLite3: `strftime('%s','now')`); the signer sees it within a few seconds. A zone whose `X-KARIDNS-SIGNER` metadata was removed is skipped and its state row dropped.

## SCHEDULING

* **Before expiry.** `next_due` = the earliest RRSIG expiration of the zone − `refresh` − a random part of `jitter`. (Not `signed_at + validity − refresh`: `-i` keeps older signatures that still have time, so some of them expire earlier than the new ones.) The due zones are read in `next_due` order with a limit (an index), so a million zones cost no full scan. A signer zone without a state row is due at once.
* **On change.** PostgreSQL: `LISTEN karidns_changes` (and a look at the change log every 30 s as a safety net); SQLite3: a poll of `karidns_changes` every 2 s. A change to a signer zone makes it due `debounce` seconds after the last change. The signer's own writes (the id the importer reports: the transaction id on PostgreSQL, the range of `seq` on SQLite3) are not changes; a record merged in without a serial bump is. A change that the signer had read when a run of the zone started (the signer reads the change log before it starts a run; a key request right after the zone was made) is covered by that run when it signs the zone: it is not signed a second time for it; a run that does not sign the zone (busy, locked, skipped, failed) leaves the change to make the zone due.
* **At start and every hour** a catch-up scan makes due the zones that have no state row, that changed after their last signature, or whose SOA serial is not the one the signer wrote. A change log that was pruned beyond the signer's position triggers the same scan.
* **Workers.** `workers` zones are signed at a time. A database that is busy (exit status 4 of `karidns-zone`, or a PostgreSQL write that was rolled back for a concurrent update: `could not serialize access`, `deadlock detected`) is tried again after 5 s, doubling to 1 minute; nothing was written.

## THE SERVER WAITS FOR THE SIGNER

A change to a signed zone (by the WebAdmin, a script, `karidns-zone import`) puts records into the database that have no valid signature yet. A validating resolver must never see a changed RRset with a stale signature, so with `database { signer-wait yes; }` (the default; [`karidns(8)`](karidns.md), "The signer's zones") the loader **does not reload a zone with `X-KARIDNS-SIGNER` = 1 because of the change log**. It reloads on a reload request: the signer's after it has written the signatures. Until then the server serves the last signed version. Consequences:

* **Latency.** A change is served `debounce` + the signing time + the reload later. The signing time of a small zone is a fraction of a second; see the measurements.
* **A stopped or failing signer** keeps changes from being served. `karictl dbstatus` shows `waiting for the signer: N zone(s): ...`; a count that does not go down means the signer is not working. `signer-wait no;` serves changes at once, unsigned.
* **Not held back:** a zone the server does not have yet, a full comparison (start, restart, `karictl reload` of every zone, a replaced database file) and a refused zone. In those moments an unsigned change can be served; the signer catches up within seconds.
* **PowerDNS** on the same database reads it live and serves a change at once, signed or not. Keep it apart from the zones the signer signs.

## DATABASE ROLES, AND RELOADS WITH SQLITE3

**PostgreSQL.** The signer connects as the role of `db/karidns_signer_role.pgsql.sql` (row level security on). It reads the tables and `cryptokeys.content` and the change log; inserts and deletes the DNSSEC record types; updates `ordername`, `auth` and the SOA serial (a trigger holds it to that); writes the three metadata kinds; **inserts** keys (no update, no delete); answers key requests (`state`, `message`, `done_at`); owns `karidns_signer_state`; inserts reload requests. It cannot write an A record, change a key or touch the users and grants. The WebAdmin's role files key requests and reads the state table; it cannot read `cryptokeys.content`. Details: [`karidns-dbloader(8)`](karidns-dbloader.md), "Roles and row level security". PostgreSQL 13 or newer.

**SQLite3.** There are no roles: the file is opened by the signer's user (and by the server's loader and the API), so keep the file and its directory in a group both can write, or run the loader's user and the signer under one account of your choosing. SQLite3 has no reload requests, so the signer asks the server over the control channel with `karictl`, with a key that can do **nothing but `reload-zone`**:

```text
# karidns.conf
key "signer" { algorithm hmac-sha256; secret "c2lnbmVyLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMw=="; };   # a secret of your own
options {
    control-channel {
        socket "/var/run/karidns/karidns.sock";
        keys { "signer" read-only yes allow-commands { reload-zone; }; };
    };
};
```

```text
# /usr/local/etc/karidns/signer-karictl.conf (owner karidns-signer, mode 0600); karictl-config points here
socket "/var/run/karidns/karidns.sock";
key "signer" { algorithm hmac-sha256; secret "c2lnbmVyLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMw=="; };
```

The key may reload one named zone (`karictl reload <zone>`), never all, and can read nothing else of the server ([`karidns(8)`](karidns.md), "Restricted control keys"). The control socket must be reachable by the signer's user.

## SECURITY

* **No shell.** Every child process is `spawn(file, argv)` with absolute paths, a fixed environment (`PATH`, `LANG=C`, `LC_ALL=C`, `TZ=UTC`, `HOME`, and `LLVM_PROFILE_FILE` when it is set, which only a coverage build reads), a timeout and a cap of 1 MB on each output stream.
* **Zone names** are checked (canonical, plain LDH, no leading hyphen) before they reach a file name or an argv word.
* **Key material** exists only in the database, in the `0700` work directory (on tmpfs) for the time a zone is signed, and in the memory of `dnssec-signzone`. The files are overwritten and unlinked after each zone and on every error path; leftovers of a crash (`kill -9`) are wiped at the next start. The rc script and the wrapper set `ulimit -c 0`. Keys and key text are never logged; messages of the tools are cut to 1 KB.
* **Privilege.** Its own user, no root. The database role cannot write user data (above). The conninfo file is checked like the loader's.
* **The one npm dependency** is `pg` with an exact version and an integrity hash in `package-lock.json`; install scripts are off (`--ignore-scripts`), CI runs `npm audit --audit-level=high`.
* **The tools.** BIND's `dnssec-signzone` parses the exported zone, which is data from your own database; it runs in the work directory as the signer's user.

## MONITORING

Look at `karidns_signer_state` and the key requests. A healthy zone has `last_error` NULL and a `next_due` that moves forward after each signing. **A zone whose signatures run out is the failure to alert on**: the server serves signatures that validating resolvers reject once they expire (SERVFAIL for the whole zone).

```sql
-- PostgreSQL: zones with an error, zones overdue, zones whose signatures end within two days
SELECT d.name, s.attempts, s.last_error, s.signed_at, s.min_expire, s.next_due
  FROM karidns_signer_state s JOIN domains d ON d.id = s.domain_id
 WHERE s.last_error IS NOT NULL OR s.next_due < now() - interval '1 hour' OR s.min_expire < now() + interval '2 days';
-- SQLite3: the same with unix seconds
SELECT d.name, s.attempts, s.last_error, s.signed_at, s.min_expire, s.next_due
  FROM karidns_signer_state s JOIN domains d ON d.id = s.domain_id
 WHERE s.last_error IS NOT NULL OR s.next_due < strftime('%s','now') - 3600 OR s.min_expire < strftime('%s','now') + 172800;
-- signer zones that have no state row (not signed yet, or the signer is not running)
SELECT d.name FROM domains d JOIN domainmetadata m ON m.domain_id = d.id AND m.kind = 'X-KARIDNS-SIGNER' AND m.content = '1'
 WHERE NOT EXISTS (SELECT 1 FROM karidns_signer_state s WHERE s.domain_id = d.id);
```

Also watch: `karictl dbstatus` (zones waiting for the signer), the requests with `state = 'failed'` or `pending` for a long time, the daemon's log (`signed <zone>: serial N, M ms`; errors as `<zone>: ...`), and an external check of the served zone (`dag @server example.test SOA +dnssec` and `dnssec-verify` on an export). The signing time of the last run is in `last_duration_ms`.

## KEY ROLLOVER

The signer does not roll keys by itself; it follows the columns `active` and `published` of `cryptokeys`: the DNSKEY RRset is made of the rows with either set, and the `active` keys sign. The operator does the rollover with the timing of RFC 7583 (section 3 defines the intervals; section 4 the methods). Take the TTLs from your zone and the parent: **the DNSKEY TTL, the largest TTL of the signed RRsets, the DS TTL at the parent, the propagation delay between your servers, and the signature `validity`**. Use a database owner session; the signer's role cannot update or delete keys.

**ZSK, pre-publish (RFC 7583 section 4).** The new key is published before it signs.

1. Make a key with `dnssec-keygen -a 13 -K <dir> example.test` (a ZSK; flags 256). Insert it **published, not active**: `INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES (<id>, 256, false, true, '<the text of the .private file>');`. The insert is in the change log, the signer signs the zone again (the DNSKEY RRset now has the new key and is signed). *A request of kind `add` makes a key that is active at once; that is a double-signature rollover, also valid, but not this one.*
2. Wait at least the DNSKEY TTL plus the propagation delay.
3. Switch: `UPDATE cryptokeys SET active = true WHERE id = <new>; UPDATE cryptokeys SET active = false WHERE id = <old>;`. The zone is signed again: the new key signs every RRset at once, and the signatures of the old key stay next to them until they expire (every RRset carries both for now; an RRset that changes later is signed by the new key only). The old key stays published.
4. Wait the largest TTL of the zone plus the propagation delay, so that every cache has seen the new signatures.
5. Retire: `DELETE FROM cryptokeys WHERE id = <old>;`. The signer drops the old DNSKEY RR and the signatures of the old key (`-R`) and nothing else changes.

Every step makes the signer sign the zone again (a few hundred milliseconds for a small zone); `dnssec-verify` accepts the zone after each of them (checked on pc200 with a KSK, two ZSKs and a small zone).

**KSK, double-DS (RFC 7583 section 4).** With a CSK the same applies (a CSK is a KSK).

1. File a request `add` with `key_type` `ksk` (or insert a key with flags 257). The new KSK is active and published; both KSKs sign the DNSKEY RRset. (When the old key is a CSK, both keys sign the whole zone until the old one is retired, a double signature.)
2. Compute the DS of the new key (`dag @server example.test DNSKEY +short`, then `dnssec-dsfromkey -f <file> example.test`, or from the `.key` text) and add it at the parent. Wait until the parent serves it and its TTL has passed.
3. Remove the old DS at the parent. Wait the DS TTL and the propagation delay.
4. Stop signing with the old key: `UPDATE cryptokeys SET active = false WHERE id = <old>`; wait the DNSKEY TTL; `DELETE FROM cryptokeys WHERE id = <old>`.

Algorithm rollovers (RFC 6781) follow the same steps with the two algorithms' keys both present; plan them by hand. Never delete a key whose DS is still at the parent.

## LIMITS

* **The first signing of a zone is also the longest**; the NSEC / NSEC3 chain is rebuilt on every run (above), so a re-sign of a big zone costs nearly as much CPU as the first signing (the measurements show the factor), while the signatures that are still good are kept.
* **Catch-up limit.** A change by someone else without a serial bump within about 1 to 2 seconds of the last signature is found only at the next change of the zone or at expiry, not by the change log (it cannot be told from the signer's own rows by time). The hourly scan compares the SOA serial and finds the usual cases. On PostgreSQL a long-running transaction elsewhere (an old `xmin`) can leave a signed zone listed as waiting until its next reload.
* **Retired keys** keep their old signatures until they expire (above).
* **SQLite3: a row per changed row.** Its triggers write one change-log row per changed row (PostgreSQL: a few per write), and the signer reads 20,000 rows per poll (every 2 s). The rows of its own write for a zone of 100,000 records are therefore skipped over some 10 seconds; a change made by someone else in that time is seen after it. Memory: a run of `karidns-zone import --signer` for 100,000 records peaks at 640 to 750 MB (see the measurements); with big zones keep `workers` low.
* **Algorithms** 8, 10, 13, 14, 15, 16. Algorithm 5 and 7 are refused. A zone name must be plain LDH.
* **Zone types.** Only primary zones (`NATIVE`, `MASTER`) with one SOA at the apex.
* **One signer per SQLite3 file**; several on PostgreSQL (advisory locks).
* **Not in this release:** automated rollover, CDS / CDNSKEY, online signing, DNSSEC validation, signing with an HSM.
* **NSEC or NSEC3** is chosen by the request that starts the signing; a signed zone keeps the setting in its `NSEC3PARAM` metadata (`nsec3-opt-out` is read at every run). There is no request to change it.

## RUNNING IT ELSEWHERE

The signer never competes with the server for CPU if you do not let it. Signing is CPU heavy for a short time (a big zone, many zones due together), `dnssec-signzone` is single threaded, and `workers` multiplies it.

* **Same host:** `karidns_signer_cpuset="2-3"` in `rc.conf` (`cpuset -l 2-3`), or `cpuset -l 2-3 -p <pid>`, and `workers` no larger than the CPUs you give it. `rtprio` / `nice` do not matter for a CPU set of its own.
* **Other host:** the signer needs only the database (and, with SQLite3, the file and the server's control socket, which is why PostgreSQL is the choice for this), `karidns-zone`, `karicheck`, `bind-tools` and Node. Install the same package on a host that runs no server, enable only `karidns_signer`, and use a conninfo file that names the database host (`sslmode=verify-full`). The signed data reaches the servers through the database; their loaders reload on the reload requests.
* **Several instances** on one PostgreSQL database share the zones (advisory locks). They need the same configuration.

## MEASUREMENTS

Measured on the build host of the project on 2026-11-06, with the defaults of this manual (ECDSA P-256 CSK, NSEC3 without salt and with 0 iterations, `validity` 14d, `refresh` 3.5 days, `jitter` 1 day, `verify yes`), `log = stderr`, the work directory on the ordinary disk (the jail has no tmpfs), and no server: the SQLite3 reload (`karictl reload`) fails fast on every zone (no socket), so each run includes one failed `karictl`. The numbers are the host's, not a guarantee.

| | |
|---|---|
| Host | FreeBSD 15.1-RELEASE-p4 amd64, a jail on a shared host, 4 vCPUs (QEMU Virtual CPU version 2.5+), 10 GiB RAM |
| Software | Node.js 24.19.0, BIND 9.20.29 (`bind-tools`), SQLite 3.53.3, PostgreSQL 18.6 (a private local cluster, TCP over 127.0.0.1, `fsync` off, `shared_buffers` 128 MB), `pg` 8.23.1 |
| Signer | `workers` = 2 (the default for 4 CPUs) unless said otherwise; one signer process |

**One zone of 100,000 records** (SOA, 2 NS, 99,997 A; SQLite3, 93 MB database file after signing; `workers` 2, one zone):

| | First signing (key request) | Signing again after one new A record |
|---|---|---|
| The run of the signer (log: `signed <zone>: ... ms`) | 27.2 s (27.1 to 27.3 in three runs) | 31.7 s (31.7 to 31.8) |
| `karidns-zone export --signer` | 0.7 s, 131 MB peak RSS | 2.2 s, 340 MB |
| `dnssec-signzone` | 14.9 s (18.4 s CPU), 168 MB | 16.3 s (22.7 s CPU), 162 MB |
| `karidns-zone import --signer` | 9.7 s, 638 MB (994 MB before the memory work below) | 11.4 s, 747 MB (1,085 MB before) |
| Peak RSS of the signer (Node) | 160 to 200 MB over the runs (it holds no zone data) | |
| From the request, or the change, to the new serial in the database | 28 s | 39 s (2 s poll of the change log + 5 s `debounce` + the run) |

The signing again is not faster than the first signing: the NSEC3 chain and its signatures are made new in every run (see "How a zone is signed"), and the importer writes the chain again. The exported signed zone is 46 MB; `dnssec-verify -z` takes 13 s on it. `karidns-zone import --signer` is the largest of the three: it holds the parsed signed file (400,000 records for this zone, about 320 MB), the rows made from it and the zone read back from the database to check it. It frees the file's text and arena as soon as they are compared and the rows before it reads the written zone back, so the peak is that read-back (PostgreSQL: 997 MB before, 628 MB now, 10.5 s). Two such zones at once would use about 1.3 GB together for these programs: keep `workers` low for big zones.

**Many small zones** (6 records each: SOA, 2 NS, 3 A; SQLite3 unless said; the run is the whole pipeline of a zone: `dnssec-keygen` (first signing only), export, `dnssec-signzone`, `karicheck`, import, reload attempt):

| | `workers` | zones | First signing (key requests) | Signing again (every zone due at once) | Peak RSS of Node |
|---|---|---|---|---|---|
| SQLite3 | 1 | 2,000 | 286 s = 7.0 zones/s (136 ms per run) | 265 s = 7.5 zones/s (127 ms) | 281 MB |
| SQLite3 | 2 (default) | 2,000 | 160 s = 12.5 zones/s (150 ms) | 145 s = 13.8 zones/s (137 ms) | 284 MB |
| SQLite3 | 2 (default) | 10,000 | 840 s = 11.9 zones/s (162 ms) | 696 s = 14.4 zones/s (134 ms) | 276 MB |
| PostgreSQL (signer role, RLS on) | 2 (default) | 2,000 | 166 s = 12.0 zones/s (154 ms) | 155 s = 12.9 zones/s (147 ms) | 199 MB |

Two workers give 1.8 times the throughput of one on 4 CPUs. At 14 zones a second (1.2 million a day) and a zone signed again about every 10 days (`validity` 14d, `refresh` 3.5d, `jitter` 1d), the re-signing of about 12 million small zones would use the two workers fully, with the CPUs to themselves (arithmetic from the table, not measured; the changes of the zones and the load of the database come on top). The CI runs PostgreSQL 17; the numbers above are PostgreSQL 18.

## FILES

`/usr/local/etc/karidns/karidns-signer.conf`
: The configuration file (`karidns-signer.conf.sample`).

`/usr/local/sbin/karidns-signer`
: The wrapper (`ulimit -c 0`, then `/usr/local/bin/node /usr/local/libexec/karidns-signer/signer/bin/karidns-signer.js`).

`/usr/local/libexec/karidns-signer/`
: The program (`signer/bin/`, `signer/lib/`), the Node code it shares with `karidns-webadmin` (`node/lib/`, imported as `../../node/lib`) and its `node_modules` (`pg`). `root:wheel`, not writable.

`/usr/local/etc/rc.d/karidns_signer`
: The rc script (`karidns_signer_enable`, `_config`, `_user`, `_tmpfs`, `_tmpfs_size`, `_cpuset`, `_flags`; commands `start`, `stop`, `restart`, `status`, `reload`, `configtest`).

`/var/db/karidns-signer/work`
: The default work directory (tmpfs, `0700`, owned by `karidns-signer`).

`/var/run/karidns_signer/`
: The pid files of `daemon(8)` (`supervisor.pid` for `service karidns_signer stop`, `child.pid` for `reload`); the directory belongs to the signer's user because the rc script runs `daemon` as that user (rc.subr does it with `su -m`, for `karidns_signer_user`), so `daemon` writes them as that user.

`<sqlite-file>.signer.lock`
: The lock file of a SQLite3 database (the pid of the signer).

`/usr/local/share/karidns/db/karidns_signer_role.pgsql.sql`
: The privileges of the PostgreSQL role (`db/` in a source tree).

## EXAMPLES

Check a configuration as the signer's user, then start the daemon in the foreground with the log on the terminal:

```sh
su -m karidns-signer -c 'karidns-signer --check -c /usr/local/etc/karidns/karidns-signer.conf'
su -m karidns-signer -c 'karidns-signer -c /usr/local/etc/karidns/karidns-signer.conf'      # log = stderr in that file
```

Sign a new zone and look at the answer:

```sh
karidns-zone import -c /usr/local/etc/karidns/karidns.conf example.test example.test.zone
psql -c "INSERT INTO karidns_key_requests (domain_id, kind) SELECT id, 'enable' FROM domains WHERE name = 'example.test'" pdns
psql -c "SELECT state, message FROM karidns_key_requests ORDER BY id DESC LIMIT 1" pdns
dag @192.0.2.53 example.test DNSKEY +dnssec +nohexdump
```

Check the signed zone of the database from outside:

```sh
karidns-zone export -c /usr/local/etc/karidns/karidns.conf example.test example.test.signed
dnssec-verify -z -o example.test example.test.signed      # -z: a CSK (one key with the SEP bit signs everything) is not a "missing ZSK"; leave -z out for a KSK and a ZSK
```

## SEE ALSO

- [`karidns-zone(1)`](karidns-zone.md) — `import --signer`, `export --signer`
- [`karidns-dbloader(8)`](karidns-dbloader.md) — the schema, the signer's tables, roles and row level security
- [`karidns(8)`](karidns.md) — `database { signer-wait }`, "The signer's zones", restricted control keys
- [`karictl(8)`](karictl.md) — `reload`, `dbstatus`
- [`karicheck(1)`](karicheck.md) — `karicheck zone`
- [Distribution Guide](distribution.md) — the FreeBSD packages
- RFC 4034, RFC 4035 (DNSSEC), RFC 5155 (NSEC3), RFC 6781 and RFC 7583 (key rollover), RFC 8624 (algorithms), RFC 9276 (NSEC3 parameters)

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

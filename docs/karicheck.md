# KARICHECK(1) — KariDNS Reference Manual

```text
KARICHECK(1)                   KariDNS Manual                   KARICHECK(1)
```

---

## NAME

**karicheck** — Configuration and Zone File Validation Utility for KariDNS

---

## SYNOPSIS

```sh
karicheck conf [config_path]

karicheck zones [config_path]

karicheck zone <domain> [config_path]

karicheck zone <domain> <zone_file_path>

karicheck db [view] [config_path]

karicheck -v | --version

karicheck -h | --help
```

---

## DESCRIPTION

`karicheck` is a static validation and syntax inspection tool for [`karidns(8)`](karidns.md) configuration files and zone files (BIND-style RFC 1035 master files and djbdns/tinydns `data` files). It is the KariDNS counterpart of BIND's `named-checkconf` / `named-checkzone`.

It validates configuration files and zone files for syntax errors, structural constraints, record-level field ranges, DNSSEC algorithm recommendations (RFC 8624), CDS/CDNSKEY delete signals (RFC 8078), and RFC 8976 ZONEMD message digests. The configuration file is parsed with the same parser as `karidns`.

When `config_path` is omitted, `/usr/local/etc/karidns/karidns.conf` is used (or `/usr/local/etc/karidns.conf` if only that file exists).

---

## COMMANDS

`conf [config_path]`
: Validate the configuration file (see [Configuration checks](#configuration-checks)).

`zones [config_path]`
: Validate the configuration file, then every `type master` / `type primary` zone declared in it (the type name is case-insensitive), using each zone's `file-format`. Secondary, forward and program zones are not checked and are reported as skipped. Prints the number of checked and skipped zones and the number of errors at the end (`Checked N zones (M skipped). Errors: E`).

`zone <domain> [config_path]`
: Look up `<domain>` in the configuration file and validate its zone file with the zone's settings (`file-format`, `catalog-zone`, tags). If several views define the zone, each view's definition is checked; the exit status is 1 if any of them fails.

`zone <domain> <zone_file_path>`
: Standalone mode: parse and validate `<zone_file_path>` as a BIND-format zone for `<domain>` without a configuration file. The third argument is treated as a configuration file if it contains `.conf`, and as a zone file otherwise. A relative path is resolved against the current directory; the server resolves relative zone paths (also with `../`) against the directory it was started from.

`db [view] [config_path]`
: Read the PowerDNS tables of `options { database { } }` (read only, through `karidns-dbloader --check`) and check the schema, every zone (with the checks of `zone`), the settings texts, the views, and the zones of the configuration that hide a database zone. With `view`, only the zones that view gets are reported. A single argument is a view unless it contains a `/` or ends in `.conf`. See [Database checks](#database-checks-karicheck-db).

`-v`, `--version`
: Print the version and exit.

---

## VALIDATION CHECKS

### Configuration checks

- Syntax of the whole file, including `include` files, with the same rules as `karidns` (undefined TSIG keys in `tsig-key` / `allow-transfer`, duplicate zones/views/keys/acls, invalid option values, ...).
- Boolean values other than `yes`/`true`/`1`/`no`/`false`/`0` are errors.
- `also-notify` (in `options`, `view` and `zone`) and the top-level `remote-servers` / `primaries` / `masters` lists are checked with the BIND 9.20 grammar (see [`karidns(8)`](karidns.md), "`also-notify` and `remote-servers`"). A syntax error names the file, the line and the statement (`[ERROR] karidns.conf:12: zone 'example.test.' also-notify: expected ';' after '192.0.2.1' but found '}'`). These are errors: a list name that is not defined (or an address that is not an IP address), a list that includes itself or nests deeper than 8 levels, a list defined twice, a `key` that no `key { }` block defines, a `port` outside 1-65535 or on a list name, more than 256 addresses after the lists are expanded, and `tls` (not implemented). The same checks apply to `primaries` / `masters` of a zone (a list name is resolved through the same lists, a per-primary `key` must be defined) and `notify` takes `yes`, `no`, `explicit`, `primary-only` or `master-only` in `options`, `view` and `zone` (anything else is an error naming the line).
- An unknown statement inside `zone { }` or `view { }` is an error (`[ERROR] zone 'example.test.': unknown option 'alow-transfer' ...`): `karidns` used to skip such a statement without a word, so a typo silently left a zone open or closed. Options that BIND 9 documents for a `zone` or `view` statement but KariDNS does not implement (`allow-query`, `inline-signing`, `dnssec-policy`, `auto-dnssec`, `key-directory`, `max-journal-size`, `zone-statistics`, `check-names`, `recursion`, ...) give a warning (`[WARNING] ... is a BIND option that KariDNS does not implement; it is ignored`) and are skipped. An unknown key inside `control-channel { }` is an error too (`[ERROR] control-channel: unknown option 'port' (supported: socket, secret, algorithm)`): `karidns` refuses to start with it, so `karicheck conf` does not call such a file valid. The same holds for `options { }` and `key { }`, with the file and line (`[ERROR] karidns.conf:12: options: unknown option 'bind-adress' ...`); BIND options of `options { }` that KariDNS does not implement (`recursion`, `version`, ...) give a warning, and a `key` without `secret` or `algorithm` is an error. `logging { }` and `controls { }` are strict as well (an unknown statement or option, a channel with no or two destinations, an unknown category, an undefined channel, an invalid size or severity, a `unix` control, an unknown key or a duplicate address in `controls` are errors with the file and line); what KariDNS accepts but does not do (`buffered yes`, a `size` without `versions`, an `inet` control, `statistics-channels`) gives a warning. Unknown top-level blocks are still skipped without a message.
- Address match lists (BIND 9.20 ARM "Address Match Lists"): `allow-query`, `allow-query-on`, `allow-transfer`, `allow-update` and `allow-notify` (in `options`, `view` and `zone`), `match-clients`, `ecs-trusted-resolvers` and `acl` take an address, a prefix, `any`, `none`, `localhost`, `localnets`, `key <name>` (not in `match-clients` and `ecs-trusted-resolvers`), a defined `acl` name, or a nested `{ ... }` list, each optionally negated with `!`; in `allow-update` the bare name of a defined key is accepted as well. Anything else is an error, and so is a statement written twice in the same block, `port` / `transport` in front of the braces of `allow-transfer`, an `acl` that contains itself, lists nested more than 8 deep, and `transfer-acl-match` / `update-acl-match` with an `allow-transfer` / `allow-update` that has a negated key (the flat evaluation they ask for cannot say that). Errors name the place of the element (`[ERROR] karidns.conf:12: zone 'example.test.' allow-query: entry 'internal' is not an address, prefix, any, none, localhost, localnets or a defined acl`, `... key 'k9' is not defined in any key {} block`, `... expected ';' after the element but found '}'`). `localhost` and `localnets` are expanded from the interfaces of the host `karicheck` runs on where the flat lists need them; the server evaluates them against its own start-up snapshot (see karidns(8) "Address match lists").
- **Warnings when a list means something else since the first-match evaluation** (karidns(8) "Address match lists"): for a zone that writes its own `allow-transfer` with no `transfer-acl-match`, a list that has addresses and `key` elements now lets in a client from a listed address **or** signed with a listed key, where it used to need the address **and** the key (more permissive: `[WARNING] Zone 'example.test.': allow-transfer lists addresses and keys: it now lets in ...`); write `transfer-acl-match all;` to keep the old meaning, or `any` to say it on purpose. For `allow-update` with keys and negated entries, the order now decides, so a negated entry before a key refuses that key's requests (stricter; `update-acl-match any;` keeps the old meaning). No warning is printed for a list of addresses only, for a list with an explicit `transfer-acl-match` / `update-acl-match`, or for a zone whose ACL comes from `options` or `view` (those statements did nothing before).
- `server <prefix> { ... }` and `key { }` in `view { }` (BIND 9.20; karidns(8) "`server`" and "`key`"). Errors with file and line: an unknown, ancient (`request-sit`, `support-ixfr`) or twice-written option, a bad value, bits beyond the prefix length (`'192.0.2.1/24' is an invalid prefix (extra bits specified)`), the same prefix twice in one list (`already exists, previous definition: file:line`), `transfer-source-v6` / `notify-source-v6` for an IPv4 server and `transfer-source` / `notify-source` for an IPv6 server (`... is not legal for an IPv4 server`), a `keys` name that is not defined for **every view that uses the statement** (`server '192.0.2.1': unknown key 'k' (in view 'v2')`: a view's own keys count only in that view), a view key with the name of a global key or a second key of one name in a view, and a key used in a zone of a view (`tsig-key`, `allow-transfer`, `allow-update`, a `primaries` / `also-notify` `key`) that is neither global nor in that view. Warnings (`accepted, no effect in KariDNS`): `bogus`, `tcp-keepalive`, `padding`, `send-cookie`, `require-cookie`, `query-source`, `query-source-v6`; `padding` above 512 says `lowered to 512`. `[NOTE]` for a view that has `server` statements of its own while the top level has some: the top-level ones do not apply in that view. The source addresses of `server` statements are in the `[INFO] Source addresses` line.
- A logging `category` may list several channels (up to 8; BIND writes to all of them). A `size` without `versions` on a log file gives a warning: the file stops at that size (BIND behaviour) instead of being truncated as earlier KariDNS versions did.
- `type program` zones: `program` must be set and be an absolute path, and `program-args` may have at most 62 entries (errors); a `program` that is not executable and a `program-user` that differs from `options { user }` give warnings. `allow-program-zones yes;` is required when any program zone exists.
- `alias-resolver { ... };` (in `options`, in a zone, and in `options { database { } }`): at most 8 entries, each an IP address (a host name is an error).
- `listen-on` / `listen-on-v6` / `blackhole` / `bind-address` (BIND 9.20 ARM "Interfaces", "blackhole"; karidns(8) "Listening addresses"): the lists are evaluated against the interface addresses of the machine `karicheck` runs on, and `[INFO] Listening (UDP and TCP) on: ...` shows the addresses that result (IPv6 as `[addr]:port`). Errors with file and line: `tls`, `http` or `proxy` (not supported), an invalid or repeated `port`, an unknown acl name or a `key` element in the list, a `bind-address` element that is not an IP address, one address with two ports (`options listen-on: address 192.0.2.1 is listened on at port 53 (karidns.conf:2) and at port 5353`), more than 64 addresses. Warnings: an address in a `listen-on` list that no interface of this machine has (BIND does not listen on it either), an IPv6 address in `listen-on` (or IPv4 in `listen-on-v6`), and statements that select no address at all (`karidns` refuses to start then). A configuration written for another host therefore warns about its addresses when checked here.
- `type forward` zones must have `forwarders`; a forwarder equal to one of the addresses the server listens on (`listen-on`, `listen-on-v6`, `bind-address`, with their ports) gives a self-loop warning. A note (`[INFO]`) reminds that in BIND `type forward` is a resolver-side zone type, so a BIND configuration that relies on it is not equivalent.
- BIND 9.20 compatibility of paths and syntax: `options { directory }` must exist and be a directory (errors; a relative one gives a warning, BIND recommends an absolute path), and the relative `file`, `include`, `pid-file` and log paths are resolved against it as `karidns` does. A class after a zone or view name is accepted when it is `IN` and an error with file and line otherwise (`zone 'x.test.': class 'CH' is not supported (only IN)`). The zone types `hint`, `stub`, `static-stub`, `mirror`, `redirect` (and `delegation-only`) give a warning with file and line (`the zone is not loaded`) and the rest of their block is skipped, so a stock BIND `named.conf` passes with warnings only; `in-view` is an error. A `port` that is not a number in 1-65535 is an error with file and line.
- Every CIDR in `ecs-tags` and `location-tags` (in `options` and in zones) must be valid; `ecs-tags` without `ecs-enable yes;` gives a warning.
- `transfer-acl-match` and `update-acl-match` take `any` or `all` (anything else is an error). A warning says when an option has nothing to choose between: without `allow-transfer` / `allow-update` (the zone's, the view's or `options`' counts), or with an ACL that lists only addresses or only keys (see karidns(8) "Address match lists" and "Settings of database zones").
- `options { database { ... }; }` (no database connection is opened): the driver is built into `karidns-dbloader` (`--drivers`); `loader-user` / `loader-group` exist; `loader-path` is a regular executable owned by root (or by the user who runs `karicheck`, standing in for the user who runs `karidns`, when that is not root) and not writable by group or others (a loader that fails these checks is an error, is not executed, and the check is made on the open file that is then executed, as karidns does); a `loader-user` / `loader-group` / `user` / `group` / `program-user` that resolves to uid or gid 0, also under another name (`root`, `toor`, `wheel`), is an error (karidns refuses it); and not writable by group or others; a SQLite3 file exists, is a database in WAL mode and is not readable by everyone; a PostgreSQL `conninfo-file` has mode 0600 or 0400, belongs to the loader user and names a UNIX socket or `sslmode=verify-full` (warning otherwise); with PostgreSQL the `server-id` (the name of this server's row in `karidns_server_status`; 1 to 64 bytes, the parser enforces that) gives a warning when it has characters other than ASCII letters, digits and `. - _ :`, and so does a missing `server-id` when the host name (the default) is empty or longer than 64 bytes (then no status row can be written); a `server-id` together with an `alias-resolver` (in `options { database { } }` or in `options`) gives a warning that ALIAS answers can differ between the servers that share the database, because each server's resolver and the moment of its lookup decide them (milestone B11b; the SOA serials and the zone transfers are the same; a resolver named only in a zone's profile text is not seen; LUA records are never run, so they need no warning); `acl-ceiling` entries are valid and its keys are defined. `acl-ceiling-match` must be `any` or `all`; `all` gives a warning when the ceiling lists only addresses or only keys (that kind alone decides then). A database block **without `acl-ceiling`** gives a warning: the ACLs a database zone carries (transfers, dynamic updates) refuse every client until a ceiling is set.

### Zone checks

1. **Zone File Directives**:
   - `$ORIGIN`, `$TTL`, `$INCLUDE` (up to 16 nesting levels and 32 files per zone), `$GENERATE` (BIND syntax, any RR type, at most 100,000 records per directive; see karidns(8) "ZONE FILE FORMAT")
   - `$INCLUDE` follows the rules of the server (karidns(8) "ZONE FILE FORMAT"): a relative name is read from `options { directory }` when `karicheck` knows one (a zone checked through a configuration), else from the directory of the zone file; an absolute path or one that leaves the base through `..` is accepted only inside the directory of the zone file or `directory`, and anything else is an error (`$INCLUDE '/etc/hosts' is outside the directories opened at startup (zone file dir, directory): ...`), so the verdict is the same as `karidns`' (standalone mode used to accept any absolute path).
   - TTLs: a `$TTL`, record TTL or `$GENERATE` TTL that is not digits with optional `s`/`m`/`h`/`d`/`w` units, or above 2147483647, is an error at its position (it used to become 3600); so are malformed SOA refresh, retry, expire and minimum fields and a SOA serial that is not a plain number 0-4294967295 (BIND 9.20 `fromtext_soa()`; the same in the `Z` line of a tinydns file); a number after a unit (`1h30`) is not a TTL. A zone in which some record has no TTL at all (no `$TTL`, no earlier TTL, no SOA to take the minimum from) gives a warning: BIND rejects it ("no TTL specified"), `karidns` serves those records with 3600.
   - KariDNS steering directives `$LOCATION`, `$LOCATION-TAG`, `$ECS-SUBNET`, `$ECS-SUBNET-TAG`: records that reference an undefined location or ECS tag are errors
   - tinydns `data` files (through a configuration file with `file-format tinydns;`): invalid location prefix lengths (`/n` above 32, error), duplicate location codes, malformed IPv6 fields of `3`/`6` lines, and SRV/NAPTR/SSHFP field ranges of generic lines
2. **Zone Integrity & Structural Invariants**:
   - Exactly one SOA record at the zone apex that every client sees, and at least one NS record at the apex. A tinydns zone (one `Z` line per location) and a zone with `$LOCATION` / `$ECS-SUBNET` tags may hold more SOA records when each of the others has a location, a time stamp or a tag; every SOA record of the zone must have the same serial (error, RFC 2181 §6.1), none may be restricted (or accompanied by another SOA) in a zone that holds DNSSEC records (RRSIG, DNSKEY, NSEC, NSEC3: error, the signature of the SOA RRset would not hold for every client), and a SOA restricted to a tinydns location the zone does not define, or whose countdown time stamp is over, is seen by nobody (warning). Several SOA records that every client sees are an error as before. See karidns(8) "Several SOA records".
   - CNAME exclusivity (CNAME must not co-exist with other record types at the same owner name, except DNSSEC RRs), CNAME loops, CNAME chains (warning), NS/MX targets that point to a CNAME (error, RFC 2181 §10.3) and SRV targets that point to a CNAME (warning, RFC 2782 "the name MUST NOT be an alias"; BIND's `check-srv-cname` default is also a warning)
   - Out-of-zone records (owner not at or below the zone name, e.g. address records for name servers outside the zone) give a warning and are left out of all further checks, because the server does not load them (RFC 1034 §4.2); the exit status is not affected
   - In-bailiwick NS targets (apex and delegations) must have an A/AAAA record in the zone (error); in-bailiwick MX and SRV targets without A/AAAA give a warning only, because no RFC requires an address for them. Records occluded by a delegation give warnings
   - Inconsistent TTLs within one RRset (warning); RRs with a location, time stamp or tag are not harmonized with RRs that every client sees, and an unrestricted and a restricted RR of one name and type with different TTLs are reported as such (a client that sees both gets an RRset with differing TTLs; the TTLs are kept)
   - SOA MNAME pointing to a CNAME (warning)
   - Meta-types (e.g. `OPT`, `TSIG`, `AXFR`) must not appear in zone data
   - PowerDNS ALIAS and LUA records (TYPE65401 / TYPE65402 of CLASS IN, see karidns(8) "POWERDNS ALIAS AND LUA RECORDS"): an ALIAS name that also owns an A or AAAA RRset, an ALIAS in a zone with DNSKEY, RRSIG, NSEC, NSEC3 or NSEC3PARAM records, and malformed ALIAS / LUA RDATA are errors (the server does not load such a zone); an `[INFO]` line counts the ALIAS records (A and AAAA at those names are NODATA unless an `alias-resolver` is configured), and a warning says that LUA records are kept for transfers and never answered
   - Every record must be serializable to wire format
   - Catalog zones (`catalog-zone yes;`): `version.<zone> TXT "2"` is required, and group TXT records without a member PTR record give warnings
3. **Record Field Validation**:
   - A/AAAA addresses; SRV, NAPTR, CAA (RFC 8659 tags and flags), SSHFP, HIP, WKS, GPOS, X25, ISDN, EUI48/EUI64, CSYNC, DSYNC and SVCB/HTTPS target fields
   - WKS: the protocol is a number (0-255) or `TCP` / `UDP` (any case), as the server reads it; a port is a number (0-65535) or a service name from the server's built-in table (RFC 1035 §3.4.2; the IANA names of the common ports, e.g. `smtp`, `http`, `domain`); any other port gives a warning, and the record is reported as an error because the server cannot load it
   - NSEC3PARAM at the apex: Flags other than 0 are an error (RFC 5155 §4.1.2: such an NSEC3PARAM MUST be ignored, and the server ignores it); a hash algorithm other than 1 (SHA-1), an iteration count other than 0 (RFC 9276 §3.1: MUST be 0) and a non-empty salt (RFC 9276 §3.1: SHOULD NOT) give warnings; more than 100 iterations are an error. A warning is also given when no NSEC3PARAM is usable, or when the one the server uses has no NSEC3 RRs
   - NSEC3 records are checked once per chain (RRs with the same hash algorithm, iterations and salt), not once per RR: hash algorithm, reserved flag bits, opt-out (RFC 9276 §3.1), iterations and salt as above, and a warning for a chain that matches no NSEC3PARAM with Flags 0 (the server does not use it)
4. **DNSSEC Algorithm & Digest Verification (RFC 8624 / RFC 8078)**:
   - Evaluates DNSSEC algorithms in DNSKEY and RRSIG records against RFC 8624 status recommendations (e.g., flagging deprecated SHA-1 or MD5 algorithms)
   - Validates DS digest types (warning on deprecated digests)
   - ML-DSA-44 (algorithm 18, draft-westerbaan-dnssec-mldsa): warns when a DNSKEY/CDNSKEY public key is not 1312 octets or an RRSIG signature is not 2420 octets
   - Recognizes RFC 8078 CDS and CDNSKEY delete signals (Algorithm=0 / DigestType=0) without false-positive warnings
5. **RFC 8976 ZONEMD Message Digest Verification**:
   - The ZONEMD serial must match the SOA serial, and ZONEMD should be at the zone apex.
   - ZONEMD records with scheme 1 (SIMPLE) and hash algorithm 1 (SHA-384) or 2 (SHA-512) are verified by computing the zone digest of RFC 8976 §3.3: RRs in DNSSEC canonical form and order (RFC 4034 §6.2 and §6.3, with RFC 6840 §5.1: owner names and the domain names in the RDATA of the types listed there in lower case), duplicates digested once, occluded data and non-apex ZONEMD RRs included, the apex ZONEMD RRs and their RRSIG left out. Out-of-zone records are not part of the zone and therefore not part of the digest.
   - Other schemes and hash algorithms are reported as not verified (`[INFO]`). Two ZONEMD RRs with the same scheme and hash algorithm, and a digest whose length does not match the hash algorithm, are errors (RFC 8976 §4).
   - Every ZONEMD with a supported scheme and hash algorithm must match. This is stricter than the RFC 8976 §4 verifier rule (one matching ZONEMD is enough): karicheck checks the zone before it is published, and a recipient may support only one of the hash algorithms.
   - The digest is verified even when the zone has other errors.

Each zone check prints `[RESULT] Zone '<zone>': <n> error(s), <n> warning(s)` followed by `[OK]` or `[FAIL]`. The counts are the numbers of `[ERROR]` and `[WARNING]` lines printed for that zone, including the ZONEMD verification; `[INFO]` lines are not counted.

### Database checks (`karicheck db`)

`karicheck db [view] [config_path]` reads the PowerDNS tables that `options { database { } }` names, **read only**, and reports what the server would refuse or what looks wrong, before the data goes live. It links no database library: it runs `karidns-dbloader --check` (see [`karidns(8)`](karidns.md) "Settings of database zones") once per database the views read, and prints what the loader finds in the style of `karicheck zone`. The loader reads through the same driver calls and the same reader as the production load, so a zone that `--check` accepts is a zone the loader sends, and the other way round. Nothing is written to the database (the connection is `query_only` / `READ ONLY`, no status row is written, no `LISTEN`).

`[view]` limits the output to the zones that view gets: those of its own database, or, for a view on the shared database, those `karidns_domain_views` maps to it (or all, when a zone has no row). A single argument is a view unless it contains a `/` or ends in `.conf`, in which case it is the configuration file. `karicheck conf` still does the checks that need no connection; `karicheck db` assumes it was run. It needs a loader that can be executed and has the driver, and it checks the loader file the way `karidns` does before it runs it (a regular file owned by root, or by the user who runs `karicheck` when that is not root, and not writable by group or others; a violation is an error, as in `karicheck conf`); if `loader-path` does not exist, it says `DB support is not installed` (the package without `karidns-dbloader`).

**Rights.** The check should see the database the way the loader of `karidns` does:

- run by **root**, `karicheck` drops to `loader-user` / `loader-group` before it executes the loader (it refuses to run the loader as root, so `loader-user` must be set); so does `karicheck conf` for `--drivers`: the loader is never run as root, nor with a loader that failed the owner and mode checks; the child gets an empty environment, working directory `/` and no descriptor above 2;
- run by **another user**, it uses that user's rights.

The first `[INFO]` line of each database names the rights used. When the database file or the `conninfo-file` cannot be used with them, the message names the file and the missing permission (`is not readable by the user ...: it needs read permission`, `has no search (x) permission on the directory ...`, SQLite3: `is not writable by the user ...` because even a reader of a WAL database writes the `-shm` file, and its directory or the `-wal` / `-shm` files must be writable), and no zone is read.

Every database gets a line `[RESULT] Database ...: N zone(s) read, E error(s), W warning(s)` followed by `[OK]` or `[FAIL]`, then one summary line. A zone the loader would refuse is reported with its first failing row, as the loader does (one bad row fails the zone): `zone 'example.test.' (domains.id 3): records.id 41: ...`. Everything that came from the database is escaped before it is printed. The exit status is 1 when any error was found or the check could not be run, else 0 (warnings do not change it). `--json` comes with a later release.

| Check | Level |
|---|---|
| **Schema** | |
| a PowerDNS table or column the loader reads is missing (`domains`, `records`, `domainmetadata`, `cryptokeys`; all missing columns are named) | error |
| none of the `karidns_*` tables exists (a plain PowerDNS database), or one is missing or incomplete (what it costs is said: no change log, no view mapping, no profiles, no tags) | warning |
| `karidns_schema_version` is newer than 2 / has no row | error / warning |
| `auto-reload yes` and `karidns_changes` is missing, or change log triggers are missing (named) | error |
| PostgreSQL: `karidns_changes` has no `xid` column (schema version 1: no change log) | warning |
| PostgreSQL: the role cannot `SELECT` a table the loader reads, or `cryptokeys.domain_id` | error |
| PostgreSQL: the role can read `cryptokeys.content` (the private keys) | warning |
| PostgreSQL: the role cannot `INSERT` / `UPDATE` `karidns_server_status`; only one of the multi-server tables exists; `server-id` is set but they are missing | warning |
| the schema named by `database-schema` does not exist | error |
| **Every zone** | |
| the reader's refusals, with `records.id`: a content the zone parser rejects, an unsupported type, an owner outside the zone, a name that is not a domain name, a prio that contradicts the content (MX / SRV), a TTL out of range, a row that is not safe as a line of text, no enabled apex SOA, a `SLAVE` / `CONSUMER` without usable `masters` | error |
| `ALIAS` in a `PRESIGNED` zone, `ENABLE-LUA-RECORDS=1`, malformed `ALIAS` / `LUA` data | error |
| `LUA` records (kept for transfers, never answered); `ALIAS` records (`[INFO]`, NODATA unless an `alias-resolver` is set) | warning / info |
| records with a NULL `ttl` (`default-ttl` is used); a `prio` on a type other than MX / SRV; metadata that is ignored | warning |
| the SOA serial is 0 | warning |
| every check of `karicheck zone` on the zone (the very same code): missing NS at the apex, CNAME with other data, glue and delegation rules, inconsistent TTLs in an RRset, field ranges of SRV / NAPTR / CAA / SSHFP / HIP / WKS ..., DNSSEC algorithm and digest recommendations, NSEC3 and NSEC3PARAM rules, ZONEMD verification | as in `karicheck zone` |
| a `PRODUCER` zone: the catalog zone itself is not served yet (decision D9, a later 0.6.x release), but its member zones are (`its N member zones are served`); secondaries that take the catalog from KariDNS will not get it. Migrating from PowerDNS works; only the catalog zone is missing. Exit status 0 when this is the only finding | warning |
| `domains.catalog` names a zone that is not a `PRODUCER` zone of the database | warning |
| two `domains` rows of one source whose names are equal ignoring case (`Example.test` and `example.test`; both drivers; the message names both `domains.id`): not supported, PowerDNS stores names in lower case, and a full read and a one-zone read (reload request, auto reload) may pick different rows | warning |
| **Keys and presigned zones** | |
| `cryptokeys` rows without `PRESIGNED=1` (PowerDNS would sign online, KariDNS serves signed data only) | error |
| `NSEC3PARAM` metadata with a bad syntax; a presigned NSEC3 or NSEC chain that does not match the zone (a name without its `RRSIG(NSEC3)` owner, an `ordername` that is not the hash, parameters outside RFC 5155 §10.3) | error |
| NSEC3 iterations other than 0 (RFC 9276) | warning |
| **Settings (metadata and profiles)** | |
| the settings text of a zone or of its profile (`karidns_profiles`) does not parse in restricted mode, the profile is not defined | error |
| the settings name a TSIG key that `karidns.conf` does not define | error |
| an `allow-transfer` / `allow-update` / `ecs-trusted-resolvers` entry that lies outside `acl-ceiling`, a key that `acl-ceiling` does not list, or ACLs while no `acl-ceiling` is configured (a database ACL refuses every client then) | warning |
| **Zones of `karidns.conf` and views** | |
| a zone of the same name in the view of the configuration hides the database zone: with `file` / `type master` (D-PRIO), `type program` / `type forward` (D-PROG) | warning |
| a `karidns_domain_views` row names a view that is not defined, or one that does not read the database through the shared source | warning |
| a zone that only such rows map is served by no view | warning |

Examples (the paths are those of a test installation; `example.test` and friends are test names):

```text
$ karicheck db /usr/local/etc/karidns/karidns.conf
[INFO] Loading config /usr/local/etc/karidns/karidns.conf...
[INFO] Checking Database file '/usr/local/etc/karidns/zones.sqlite3' (the default view) with the rights of the user claude (uid 1002)
[INFO] Database file '/usr/local/etc/karidns/zones.sqlite3': karidns_* schema version 2
[WARNING] Database file '/usr/local/etc/karidns/zones.sqlite3': zone 'example.test.' (domains.id 1): records.id 4: 1 record(s) have a NULL ttl; default-ttl 3600 used (first shown)
[WARNING] Database file '/usr/local/etc/karidns/zones.sqlite3': zone 'example.test.' (domains.id 1): allow-transfer entry '198.51.100.0/24' is outside acl-ceiling; a client there is refused
[ERROR] Database file '/usr/local/etc/karidns/zones.sqlite3': zone 'broken.test.' (domains.id 2): records.id 9: invalid IPv4 address literal in A record
[WARNING] Database file '/usr/local/etc/karidns/zones.sqlite3': zone 'shadow.test.' (domains.id 3): D-PRIO: the default view has a zone with this name in the configuration (file '/usr/local/etc/karidns/shadow.zone'); it hides the database zone
[RESULT] Database file '/usr/local/etc/karidns/zones.sqlite3': 3 zone(s) read, 1 error(s), 3 warning(s)
[FAIL] Database file '/usr/local/etc/karidns/zones.sqlite3' has errors.
[INFO] Checked 1 database (3 zones). Errors: 1, warnings: 3
```

Run by root, the same check says `with the rights of loader-user 'karidns-db' (karicheck was run by root and drops to it, as karidns does for the loader)`. A package without the loader, and a database file the user cannot read:

```text
$ karicheck db /usr/local/etc/karidns/noloader.conf
[ERROR] DB support is not installed: the database loader '/usr/local/etc/karidns/no-such-loader' does not exist (this installation has no karidns-dbloader; install the karidns-sqlite3, karidns-postgresql or karidns-db package, or set loader-path)

$ karicheck db /usr/local/etc/karidns/karidns.conf
[ERROR] Database file '/usr/local/etc/karidns/zones.sqlite3': database file '/usr/local/etc/karidns/zones.sqlite3' is not readable by the user claude (uid 1002): it needs read permission (mode 0000, owner uid 1002, group gid 0)
```


---

## EXIT STATUS

`0`
: All checked configuration files and zone files are valid. Warnings do not change the exit status. `-h` and `--help` print the usage text to standard output and also exit with 0 (as `karictl` and `karidns-dbloader` do).

`1`
: Problems found: unreadable file, syntax error, validation error, or ZONEMD digest mismatch detected. `db`: an error in the database or its data, a database that cannot be read with the rights of the loader, or a loader that is not installed (`DB support is not installed`).

`2`
: Usage error (a missing or unknown command, missing or too many arguments; the usage text goes to standard error). Nothing was checked. Before this release a usage error exited with 1.

---

## EXAMPLES

### Check Configuration File Syntax
```sh
karicheck conf /usr/local/etc/karidns/karidns.conf
```

### Validate All Zones Declared in Configuration
```sh
karicheck zones /usr/local/etc/karidns/karidns.conf
```

### Validate a Zone Using Its Configuration
```sh
karicheck zone example.com /usr/local/etc/karidns/karidns.conf
```

### Validate a Specific Master Zone Standalone
```sh
karicheck zone example.com master/example.com.zone
```

### Check the Zones of a Database
```sh
karicheck db /usr/local/etc/karidns/karidns.conf
karicheck db internal /usr/local/etc/karidns/karidns.conf
```

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karictl(8)`](karictl.md) — KariDNS server management and control utility
- [`karidns-dbloader(8)`](karidns-dbloader.md) — The database loader that `karicheck db` runs with `--check`
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                  KARICHECK(1)
```

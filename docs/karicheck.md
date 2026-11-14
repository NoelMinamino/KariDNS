# KARICHECK(8) — KariDNS Reference Manual

```text
KARICHECK(8)                   KariDNS Manual                   KARICHECK(8)
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

karicheck zone <domain> -

karicheck db [view] [config_path]

karicheck --json conf|zones|zone|db ...

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

`zone <domain> -`
: The zone text is read from standard input (BIND format, at most 64 MiB; a bigger input is refused with `io.stdin.too-large`, it is not cut). The messages and the JSON document call the file `<stdin>`. `$INCLUDE` is refused (`zone.include-stdin`): there is no directory to include from. This is for a caller that holds the zone in memory (a web interface that validates an edited zone before it writes it to the database) and wants no temporary file.

`--json` *command* ...
: Write the result as one JSON document on standard output (see [JSON OUTPUT](#json-output)) instead of the text lines. `--json` comes before the command. Standard output then carries nothing but the document, and standard error nothing at all (except when the document cannot be written). The exit status is the same as without `--json`. `-h` and `-v` are not commands with `--json`: they are usage errors.

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
- An unknown statement inside `zone { }` or `view { }` is an error (`[ERROR] zone 'example.test.': unknown option 'alow-transfer' ...`): `karidns` used to skip such a statement without a word, so a typo silently left a zone open or closed. Options that BIND 9 documents for a `zone` or `view` statement but KariDNS does not implement (`allow-query`, `inline-signing`, `dnssec-policy`, `auto-dnssec`, `key-directory`, `max-journal-size`, `zone-statistics`, `recursion`, ...) give a warning (`[WARNING] ... is a BIND option that KariDNS does not implement; it is ignored`) and are skipped. An unknown key inside `control-channel { }` is an error too (`[ERROR] control-channel: unknown option 'port' (supported: socket, secret, algorithm, allow-group, keys)`): `karidns` refuses to start with it, so `karicheck conf` does not call such a file valid. The same holds for `options { }` and `key { }`, with the file and line (`[ERROR] karidns.conf:12: options: unknown option 'bind-adress' ...`); BIND options of `options { }` that KariDNS does not implement (`recursion`, `forwarders`, ...) give a warning, and a `key` without `secret` or `algorithm` is an error. `logging { }` and `controls { }` are strict as well (an unknown statement or option, a channel with no or two destinations, an unknown category, an undefined channel, an invalid size or severity, a `unix` control, an unknown key or a duplicate address in `controls` are errors with the file and line); what KariDNS accepts but does not do (`buffered yes`, a `size` without `versions`, an `inet` control, `statistics-channels`) gives a warning. Unknown top-level blocks are still skipped without a message.
- Address match lists (BIND 9.20 ARM "Address Match Lists"): `allow-query`, `allow-query-on`, `allow-transfer`, `allow-update` and `allow-notify` (in `options`, `view` and `zone`), `match-clients`, `ecs-trusted-resolvers` and `acl` take an address, a prefix, `any`, `none`, `localhost`, `localnets`, `key <name>` (not in `ecs-trusted-resolvers`; in `match-clients` it selects the view by the TSIG key of the request), a defined `acl` name, or a nested `{ ... }` list, each optionally negated with `!`; in `allow-update` the bare name of a defined key is accepted as well. Anything else is an error, and so is a statement written twice in the same block, `port` / `transport` in front of the braces of `allow-transfer`, an `acl` that contains itself, lists nested more than 8 deep, and `transfer-acl-match` / `update-acl-match` with an `allow-transfer` / `allow-update` that has a negated key (the flat evaluation they ask for cannot say that). Errors name the place of the element (`[ERROR] karidns.conf:12: zone 'example.test.' allow-query: entry 'internal' is not an address, prefix, any, none, localhost, localnets or a defined acl`, `... key 'k9' is not defined in any key {} block`, `... expected ';' after the element but found '}'`). `localhost` and `localnets` are expanded from the interfaces of the host `karicheck` runs on where the flat lists need them; the server evaluates them against its own start-up snapshot (see karidns(8) "Address match lists"). A view whose `match-clients` names a `key` and that follows a view which surely matches every client (`any`, `0.0.0.0/0` with `::/0`, no `match-clients`) gets a `[WARNING]` with `file:line` ("KariDNS warning (BIND does not check this) ... can never be chosen"); it is not an error.
- **Warnings when a list means something else since the first-match evaluation** (karidns(8) "Address match lists"): for a zone that writes its own `allow-transfer` with no `transfer-acl-match`, a list that has addresses and `key` elements now lets in a client from a listed address **or** signed with a listed key, where it used to need the address **and** the key (more permissive: `[WARNING] Zone 'example.test.': allow-transfer lists addresses and keys: it now lets in ...`); write `transfer-acl-match all;` to keep the old meaning, or `any` to say it on purpose. For `allow-update` with keys and negated entries, the order now decides, so a negated entry before a key refuses that key's requests (stricter; `update-acl-match any;` keeps the old meaning). No warning is printed for a list of addresses only, for a list with an explicit `transfer-acl-match` / `update-acl-match`, or for a zone whose ACL comes from `options` or `view` (those statements did nothing before).
- `server <prefix> { ... }` and `key { }` in `view { }` (BIND 9.20; karidns(8) "`server`" and "`key`"). Errors with file and line: an unknown, ancient (`request-sit`, `support-ixfr`) or twice-written option, a bad value, bits beyond the prefix length (`'192.0.2.1/24' is an invalid prefix (extra bits specified)`), the same prefix twice in one list (`already exists, previous definition: file:line`), `transfer-source-v6` / `notify-source-v6` for an IPv4 server and `transfer-source` / `notify-source` for an IPv6 server (`... is not legal for an IPv4 server`), a `keys` name that is not defined for **every view that uses the statement** (`server '192.0.2.1': unknown key 'k' (in view 'v2')`: a view's own keys count only in that view), a view key with the name of a global key or a second key of one name in a view, and a key used in a zone of a view (`tsig-key`, `allow-transfer`, `allow-update`, a `primaries` / `also-notify` `key`) that is neither global nor in that view. Warnings (`accepted, no effect in KariDNS`): `bogus`, `tcp-keepalive`, `padding`, `send-cookie`, `require-cookie`, `query-source`, `query-source-v6`; `padding` above 512 says `lowered to 512`. `[NOTE]` for a view that has `server` statements of its own while the top level has some: the top-level ones do not apply in that view. The source addresses of `server` statements are in the `[INFO] Source addresses` line.
- A logging `category` may list several channels (up to 8; BIND writes to all of them). A `size` without `versions` on a log file gives a warning: the file stops at that size (BIND behaviour) instead of being truncated as earlier KariDNS versions did.
- BIND option values (karidns(8) "BIND option values"): `tcp-idle-timeout` and `tcp-initial-timeout` are in BIND's unit of 100 ms, a number written in the old KariDNS milliseconds needs the suffix `ms`, and a bare number above 1200 is an error with file and line (`options tcp-idle-timeout: 10000 is more than the maximum of 1200 (120 seconds) ... write 10000ms`); a value below BIND's minimum gives the BIND warning (`value is out of range: raising to 25`). `version`, `hostname` and `server-id` take a quoted string, `none` (and `hostname` for `server-id`); a `server-id` that differs from `nsid` is an error. `minimal-responses` takes `yes`, `no`, `no-auth` or `no-auth-recursive` in `options` and in `view` (the view's value is the one its clients get). `max-records`, `max-records-per-type`, `max-types-per-name`, `max-zone-ttl`, `serial-update-method`, `rollback-window` (a number of seconds or a time with units; `0` keeps no previous version for `karictl rollback`; a bad value is an error with file and line), `masterfile-format` (`raw` is an error) and the `check-*` options are read in `options`, `view` and `zone`. Both names of a buffer setting with two values (`udp-recvbuf-size` and `udp-receive-buffer`, `udp-bufsize` and `max-udp-size`) are an error. `dnstap` is read in BIND's grammar too (`dnstap { auth; }; dnstap-output unix "...";`; `dnstap-output file`, mixing the two grammars and `dnstap` without `dnstap-output` are errors). `catalog-zones` marks the zones it names; a name that is no zone gives a warning. `update-policy` rules are checked (an unsupported `deny`, `local`, a count such as `A(3)`, and `allow-update` in the same zone are errors; an unsupported `grant` is dropped with a warning). What is accepted without effect gives a warning (`check-sibling`, `check-spf`, `check-svcb`, `edns-udp-size`, `tcp-keepalive-timeout`, `fstrm-set-*`, `default-primaries`).
- `control-channel { keys { } }` (karidns(8) "Restricted control keys"): an `allow-group` that names no group (or a bad gid) is an error with file and line (the name is looked up on the host karicheck runs on); an unknown key name, a key listed twice, two keys with one secret, `allow-commands` without `read-only yes` and an unknown or test-only command name are errors with file and line. A key listed in `keys { }` that is also used for TSIG anywhere (`allow-transfer`, `allow-update`, `allow-notify`, `allow-query`, `match-clients`, a zone's `tsig-key`, `primaries` / `also-notify` entries, `server { keys }`, `update-policy`, an `acl { }` block, `acl-ceiling`) is a warning with the place of the use: whoever holds the key for DNS could also control the server.
- `type program` zones: `program` must be set and be an absolute path, and `program-args` may have at most 62 entries, and there may be at most 256 program zones (errors); a `program` that is not executable and a `program-user` that differs from `options { user }` give warnings. `allow-program-zones yes;` is required when any program zone exists.
- `alias-resolver { ... };` (in `options`, in a zone, and in `options { database { } }`): at most 8 entries, each an IP address (a host name is an error).
- `listen-on` / `listen-on-v6` / `blackhole` / `bind-address` (BIND 9.20 ARM "Interfaces", "blackhole"; karidns(8) "Listening addresses"): the lists are evaluated against the interface addresses of the machine `karicheck` runs on, and `[INFO] Listening (UDP and TCP) on: ...` shows the addresses that result (IPv6 as `[addr]:port`). Errors with file and line: `tls`, `http` or `proxy` (not supported), an invalid or repeated `port`, an unknown acl name or a `key` element in the list, a `bind-address` element that is not an IP address, one address with two ports (`options listen-on: address 192.0.2.1 is listened on at port 53 (karidns.conf:2) and at port 5353`), more than 64 addresses. Warnings: an address in a `listen-on` list that no interface of this machine has (BIND does not listen on it either), an IPv6 address in `listen-on` (or IPv4 in `listen-on-v6`), and statements that select no address at all (`karidns` refuses to start then). A configuration written for another host therefore warns about its addresses when checked here.
- `type forward` zones must have `forwarders`; a forwarder equal to one of the addresses the server listens on (`listen-on`, `listen-on-v6`, `bind-address`, with their ports) gives a self-loop warning. A note (`[INFO]`) reminds that in BIND `type forward` is a resolver-side zone type, so a BIND configuration that relies on it is not equivalent.
- BIND 9.20 compatibility of paths and syntax: `options { directory }` must exist and be a directory (errors; a relative one gives a warning, BIND recommends an absolute path), and the relative `file`, `include`, `pid-file` and log paths are resolved against it as `karidns` does. A class after a zone or view name is accepted when it is `IN` and an error with file and line otherwise (`zone 'x.test.': class 'CH' is not supported (only IN)`). The zone types `hint`, `stub`, `static-stub`, `mirror`, `redirect` (and `delegation-only`) give a warning with file and line (`the zone is not loaded`) and the rest of their block is skipped, so a stock BIND `named.conf` passes with warnings only. `in-view` is checked as BIND does (`lib/isccfg/check.c`): the zone must exist in a view that is defined earlier -- as a `zone { }` of it, or, when that view takes zones from the database or has a catalog zone, as a name that is looked for in the database or the catalog at run time and so cannot be checked here (D1a, in-view phase 2) (`'in-view' zone 'x.test.' does not exist in view 'v1', or view 'v1' is not yet defined`; a type that cannot be shared in KariDNS gives its own message), only `in-view`, `forward` and `forwarders` may be written with it (`zone 'x.test.': 'in-view' used with incompatible zone options`; `allow-query`, `allow-query-on`, `allow-transfer`, `allow-update` and `allow-notify` are accepted with the KariDNS `in-view-settings view`), and `in-view-settings` takes `owner` or `view`; every message has the file and line. `karicheck zones` and `karicheck zone` check a shared zone once, in the view that owns it. `max-records-per-type` or `max-types-per-name` above BIND's default of 100 gives a warning (the value is applied as written). A `port` that is not a number in 1-65535 is an error with file and line.
- Every CIDR in `ecs-tags` and `location-tags` (in `options` and in zones) must be valid (the server refuses to start with one that is not, too); `ecs-tags` without `ecs-enable yes;` gives a warning.
- The lexer reports a `/* comment` or a quoted string that is never closed, and a token longer than 4096 bytes, as syntax errors; an unknown top-level statement is a warning that names it and its line (`unknown statement 'zonee' is skipped`); an address-list element with host bits below the prefix length (`10.0.0.1/8`) is a warning with file and line.
- The placeholder secret of `karidns.conf.sample` is an error for the `control-channel` secret and for a key that an ACL, an `update-policy` rule or `control-channel { keys }` uses (`conf.tsig.secret-placeholder-used`), and a warning for a key nobody uses. A database configuration whose CONFIG message for the loader would exceed 1 MiB is an error.
- `transfer-acl-match` and `update-acl-match` take `any` or `all` (anything else is an error). A warning says when an option has nothing to choose between: without `allow-transfer` / `allow-update` (the zone's, the view's or `options`' counts), or with an ACL that lists only addresses or only keys (see karidns(8) "Address match lists" and "Settings of database zones").
- `options { database { ... }; }` (no database connection is opened): the driver is built into `karidns-dbloader` (`--drivers`); `loader-user` / `loader-group` exist; `loader-path` is a regular executable owned by root (or by the user who runs `karicheck`, standing in for the user who runs `karidns`, when that is not root) and not writable by group or others (a loader that fails these checks is an error, is not executed, and the check is made on the open file that is then executed, as karidns does); a `loader-user` / `loader-group` / `user` / `group` / `program-user` that resolves to uid or gid 0, also under another name (`root`, `toor`, `wheel`), is an error (karidns refuses it); and not writable by group or others; a SQLite3 file exists, is a database in WAL mode and is not readable by everyone; a PostgreSQL `conninfo-file` has mode 0600 or 0400, belongs to the loader user and names a UNIX socket or `sslmode=verify-full` (warning otherwise); with PostgreSQL the `server-id` (the name of this server's row in `karidns_server_status`; 1 to 64 bytes, the parser enforces that) gives a warning when it has characters other than ASCII letters, digits and `. - _ :`, and so does a missing `server-id` when the host name (the default) is empty or longer than 64 bytes (then no status row can be written); a `server-id` together with an `alias-resolver` (in `options { database { } }` or in `options`) gives a warning that ALIAS answers can differ between the servers that share the database, because each server's resolver and the moment of its lookup decide them (milestone B11b; the SOA serials and the zone transfers are the same; a resolver named only in a zone's profile text is not seen; LUA records are never run, so they need no warning); `acl-ceiling` entries are valid and its keys are defined. `acl-ceiling-match` must be `any` or `all`; `all` gives a warning when the ceiling lists only addresses or only keys (that kind alone decides then). A database block **without `acl-ceiling`** gives a warning: the ACLs a database zone carries (transfers, dynamic updates) refuse every client until a ceiling is set.

### Zone checks

1. **Zone File Directives**:
   - `$ORIGIN`, `$TTL`, `$INCLUDE` (up to 16 nesting levels and 32 files per zone), `$GENERATE` (BIND syntax, any RR type, at most 100,000 records per directive; see karidns(8) "ZONE FILE FORMAT")
   - `$INCLUDE` follows the rules of the server (karidns(8) "ZONE FILE FORMAT"): a relative name is read from `options { directory }` when `karicheck` knows one (a zone checked through a configuration), else from the directory of the zone file; an absolute path or one that leaves the base through `..` is accepted only inside the directory of the zone file or `directory`, and anything else is an error (`$INCLUDE '/etc/hosts' is outside the directories opened at startup (zone file dir, directory): ...`), so the verdict is the same as `karidns`' (standalone mode used to accept any absolute path).
   - TTLs: a `$TTL`, record TTL or `$GENERATE` TTL that is not digits with optional `s`/`m`/`h`/`d`/`w` units, or above 2147483647, is an error at its position (it used to become 3600); so are malformed SOA refresh, retry, expire and minimum fields and a SOA serial that is not a plain number 0-4294967295 (BIND 9.20 `fromtext_soa()`; the same in the `Z` line of a tinydns file); a number after a unit (`1h30`) is not a TTL. A zone in which some record has no TTL at all (no `$TTL`, no earlier TTL, no SOA to take the minimum from) gives a warning that names the file and line of the first such record (`zone.db:12: no TTL specified for 'www.example.test.' ...`, the path of the `$INCLUDE` file when it is in one) and how many records there are: BIND rejects it ("no TTL specified"), `karidns` serves those records with 3600.
   - Classes: a zone has the class of its first record; a record of another class is an error at its line (`class 'CH' != zone class 'IN'`, as BIND `lib/dns/master.c`).
   - `RESINFO` is a singleton type (RFC 9606 §3): two different RESINFO records at one name are an error (`multiple RRs of singleton type`, the server does not load the zone).
   - TXT-like types (`TXT`, `SPF`, `AVC`, `NINFO`, `RESINFO`, `WALLET`): a `<character-string>` of more than 255 octets gives a warning with file and line, `BIND rejects this`; `karidns` serves it split into 255-octet strings.
   - `\# <length> <hex>` RDATA may be written in any number of tokens (up to the 512 fields of a line) for every type.
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
   - The `check-*` options of the zone's configuration set the severity of some of the findings above and add checks that report nothing without them (karidns(8) "BIND option values"): `check-integrity` (the NS glue and the MX / SRV addresses; `no` skips them), `check-mx-cname` (an MX target that is a CNAME: error without the option), `check-srv-cname` (warning without the option), `check-wildcard` (a `*` label that is not the first), `check-dup-records` (the same RR twice), `check-mx` (an MX target that is an IP address) and `check-names` (host names of A, AAAA and MX owners and of NS, MX, SRV and SOA MNAME targets). The size limits `max-records`, `max-records-per-type`, `max-types-per-name` and `max-zone-ttl` (primary zones) are errors here because the server does not load such a zone. `karicheck db` passes the options-level severities to `karidns-dbloader --check --zone-checks`.
   - Every record must be serializable to wire format
   - A name with two different CNAME records, or two different DNAME records, is an error (`zone.pdns-types`; BIND: "multiple RRs of singleton type"); the same RR twice, and records that tinydns locations or `$LOCATION-TAG` / `$ECS-SUBNET-TAG` tags keep apart, are not
   - Zone file syntax that BIND also refuses: a `$` word that is not a directive, `$ORIGIN` without a name, a record line that starts with a blank before any record ("no current owner name"), a `\DDD` escape above 255, `\000` in a field that is not a TXT string, an entry of a `$LOCATION-TAG` / `$ECS-SUBNET-TAG` definition that is not an address or CIDR; in tinydns data a TTL that is not decimal digits and more than 4096 `%` location lines
   - Catalog zones (`catalog-zone yes;`): `version.<zone> TXT "2"` is required, and group TXT records without a member PTR record give warnings
3. **Record Field Validation**:
   - A/AAAA addresses; SRV, NAPTR, CAA (RFC 8659 tags and flags), SSHFP, HIP, WKS, GPOS, X25, ISDN, EUI48/EUI64, CSYNC, DSYNC and SVCB/HTTPS target fields
   - WKS: the protocol is a number (0-255) or `TCP` / `UDP` (any case), as the server reads it; a port is a number (0-65535) or a service name from the server's built-in table (RFC 1035 §3.4.2; the IANA names of the common ports, e.g. `smtp`, `http`, `domain`); any other port gives a warning, and the record is reported as an error because the server cannot load it
   - NSEC3PARAM at the apex: Flags other than 0 are an error (RFC 5155 §4.1.2: such an NSEC3PARAM MUST be ignored, and the server ignores it); a hash algorithm other than 1 (SHA-1), an iteration count other than 0 (RFC 9276 §3.1: MUST be 0) and a non-empty salt (RFC 9276 §3.1: SHOULD NOT) give warnings; more than 100 iterations are an error, and more than 150 (RFC 9276 §3.2) are refused with `zone.pdns-types` because the server does not load such a zone (a zone file, a transfer and a database or presigned zone are all held to this limit; BIND 9.20 only warns above 50 and loads the zone). A warning is also given when no NSEC3PARAM is usable, or when the one the server uses has no NSEC3 RRs
   - NSEC3 records are checked once per chain (RRs with the same hash algorithm, iterations and salt), not once per RR: hash algorithm, reserved flag bits, opt-out (RFC 9276 §3.1), iterations and salt as above, and a warning for a chain that matches no NSEC3PARAM with Flags 0 (the server does not use it)
4. **DNSSEC Algorithm & Digest Verification (RFC 8624 / RFC 8078)**:
   - Evaluates DNSSEC algorithms in DNSKEY and RRSIG records against RFC 8624 status recommendations (e.g., flagging deprecated SHA-1 or MD5 algorithms)
   - Validates DS digest types (warning on deprecated digests) and, for the known types, the length of the DS / CDS digest (SHA-1 20, SHA-256 32, GOST 32, SHA-384 48 octets: RFC 4034 §5.1.4, RFC 4509 §2, RFC 6605 §5; an error, as BIND refuses it); SSHFP fingerprints are checked the same way (SHA-1 20, SHA-256 32 octets: RFC 4255 §3.1.2, RFC 6594 §5), in a zone file and in a tinydns `_` line
   - The algorithm numbers of the IANA registry are known: 17 (SM2SM3), 23 (ECC-GOST12) and the private 252-254 draw no "unknown algorithm" warning; SSHFP algorithm 6 (Ed448, RFC 8709) is assigned; CAA `issuemail` (RFC 9495) and `issuevmc` are known tags
   - The address records that another delegation of the zone names as an NS target (sibling glue, RFC 9471) are not reported as occluded; BIND does not report them either
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

Every database gets a line `[RESULT] Database ...: N zone(s) read, E error(s), W warning(s)` followed by `[OK]` or `[FAIL]`, then one summary line. A zone the loader would refuse is reported with its first failing row, as the loader does (one bad row fails the zone): `zone 'example.test.' (domains.id 3): records.id 41: ...`. Everything that came from the database is escaped before it is printed. The exit status is 1 when any error was found or the check could not be run, else 0 (warnings do not change it). With `--json` each finding is a message of the document (code, place and zone), and the zones are the entries of `zones` (`"format": "database"`; `file` is null).

| Check | Level |
|---|---|
| **Schema** | |
| a PowerDNS table or column the loader reads is missing (`domains`, `records`, `domainmetadata`, `cryptokeys`; all missing columns are named) | error |
| none of the `karidns_*` tables exists (a plain PowerDNS database), or one is missing or incomplete (what it costs is said: no change log, no view mapping, no profiles, no tags) | warning |
| `karidns_schema_version` is newer than 3 / has no row | error / warning |
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
| a presigned NSEC3 zone without an `RRSIG(NSEC3PARAM)` at the apex: the TTL of the rebuilt `NSEC3PARAM` is the SOA MINIMUM, because the TTL the signer used is unknown | warning |
| **Settings (metadata and profiles)** | |
| the settings text of a zone or of its profile (`karidns_profiles`) does not parse in restricted mode, the profile is not defined | error |
| the settings name a TSIG key that `karidns.conf` does not define | error |
| an `allow-transfer` / `allow-update` / `ecs-trusted-resolvers` entry that lies outside `acl-ceiling`, a key that `acl-ceiling` does not list, or ACLs while no `acl-ceiling` is configured (a database ACL refuses every client then) | warning |
| `loader-state-file` (D1a step 7): the directory does not exist or cannot be written by the loader user (the loader writes `<file>.tmp` there and renames it), the file cannot be read by it | error |
| `loader-state-file` that is not a valid hot list (empty, truncated, a bad count or checksum: the loader ignores it and the next list replaces it); a directory that everybody can write in; `loader-state-file` or `warm-before-serve` without `memory-limit` (`karicheck conf`) | warning |
| **Memory (0.7, only when the whole configuration is checked, not for `karicheck db VIEW`)** | |
| the zones and the records the loaders counted (`karidns-dbloader --check` prints an `M` line), what they need in memory (the Backend with every zone resident, the loader) and the `memory-limit` that keeps every zone, with the share of zones that fit under the configured `memory-limit` (the same figures and lines the server says in syslog at its start; `db.memory.estimate`); without `memory-limit` that is all it says | info |
| `memory-limit` is below what every zone needs (`db.memory.limit-below-all`) | note |
| `memory-limit` keeps less than half of the zones in memory (`db.memory.limit-low`): counted in the warnings | warning |
| `memory-limit` cannot hold the zones of the reads in flight, 4 x `fetch-concurrency` (`db.memory.limit-tiny`): counted in the errors, exit status 1 | error |
| **Zones of `karidns.conf` and views** | |
| a zone of the same name in the view of the configuration hides the database zone: with `file` / `type master` (D-PRIO), `type program` / `type forward` (D-PROG) | warning |
| a `karidns_domain_views` row names a view that is not defined, or one that does not read the database through the shared source | warning |
| a zone that only such rows map is served by no view | warning |

Examples (the paths are those of a test installation; `example.test` and friends are test names):

```text
$ karicheck db /usr/local/etc/karidns/karidns.conf
[INFO] Loading config /usr/local/etc/karidns/karidns.conf...
[INFO] Checking Database file '/usr/local/etc/karidns/zones.sqlite3' (the default view) with the rights of the user dnsadmin (uid 1001)
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
[ERROR] Database file '/usr/local/etc/karidns/zones.sqlite3': database file '/usr/local/etc/karidns/zones.sqlite3' is not readable by the user dnsadmin (uid 1001): it needs read permission (mode 0000, owner uid 1002, group gid 0)
```


---

## JSON OUTPUT

`karicheck --json <command> ...` runs the same checks as the text mode and writes one JSON document (RFC 8259, UTF-8) on standard output when the run is over. A caller that always parses standard output gets an answer for every run, a usage error included. Nothing else is written to standard output, and nothing to standard error unless the document itself cannot be written (then the status is 1 and a line says so).

```json
{
  "karicheck": 1,
  "version": "0.6.2",
  "command": "zone",
  "result": "fail",
  "counts": { "error": 1, "warning": 2, "checked": 1, "skipped": 0, "dropped": 0 },
  "truncated": false,
  "messages": [
    { "severity": "error", "code": "zone.syntax", "text": "Syntax error in db/example.test.zone at line 12\nReason: invalid TTL", "file": "db/example.test.zone", "line": 12, "zone": "example.test.", "view": null }
  ],
  "zones": [
    { "zone": "example.test.", "view": null, "file": "db/example.test.zone", "format": "bind", "result": "fail", "errors": 1, "warnings": 2 }
  ]
}
```

| Field | Meaning |
|---|---|
| `karicheck` | The schema version, an integer. It is raised only when a field changes its meaning or goes away; a new field does not raise it. Read the fields you know and ignore the others. |
| `version` | The version of `karicheck`. |
| `command` | `conf`, `zones`, `zone` or `db` (`import` or `export` for `karidns-zone`); `null` when the command line named none that exists. |
| `result` | `ok` (exit status 0), `fail` (1: problems found) or `usage` (2: usage error). |
| `counts.error`, `counts.warning` | The messages of those severities, also the ones that did not fit into `messages`. |
| `counts.checked`, `counts.skipped` | Zones checked and zones skipped (a type that has no zone file); for `db`, `checked` is the number of zones read. 0 for `conf`. |
| `counts.dropped`, `truncated` | At most 10000 messages and 100000 `zones` entries are kept; the rest is only counted. `dropped` is the number of messages left out, `truncated` is true when anything was left out. |
| `messages[]` | Every finding in the order `karicheck` found it. |
| `messages[].severity` | `error`, `warning`, `note` or `info`. |
| `messages[].code` | The code of the problem (below); a string, in every message. |
| `messages[].text` | The text the text mode prints, without the `[ERROR]` tag and the final line feed. A continuation (`Reason: ...` of a syntax error, the expected and computed digest of a ZONEMD mismatch) follows after a line feed. May hold any characters (it quotes names from the files). |
| `messages[].file`, `.line` | Where the problem is: the file (`<stdin>` for standard input), and the line (a positive integer) or `null` when it is not known. For `db` both are `null`. |
| `messages[].zone`, `.view` | The zone (absolute name, as `karicheck` shows it) and the view the message is about, or `null`. The view of a configuration without `view { }` is `__default__`; `null` when there is no view (a standalone zone file, a message about the configuration as a whole). |
| `zones[]` | One entry per zone checked, in order: `zone`, `view` and `file` (`null` when unknown), `format` (`bind`, `tinydns` or `database`), `result` (`ok` or `fail`) and the numbers of `errors` and `warnings` found while it was checked. |

`karidns-zone --json` ([`karidns-zone(8)`](karidns-zone.md)) writes the same document: the first key is `"karidns-zone": 1` instead of `"karicheck": 1`, `command` is `import` or `export`, `zones[]` has one entry per zone imported or exported (`file` is the input or output file), and the codes are the `db.import.*`, `db.export.*` and `db.zone.*` ones below (with `usage.*`, `io.*`, `conf.*` and `zone.*`).

All strings are valid JSON strings: `"` and `\` are escaped, every control character (below U+0020, and U+007F) is written as `\u00XX`, and a byte that is not part of valid UTF-8 (a zone file, a file name or the database can hold anything) is replaced by U+FFFD. A text longer than 4096 bytes is cut and ends with `...`.

**Stability.** A code is never renamed and never used for another problem once released. A code that is no longer printed stays in the list, marked retired. A code names the problem, not the text: the same code may come with several texts (they carry the details), and the text of a message may change without its code. New codes may appear in any release; treat a code you do not know by its `severity`. The codes of `karidns-dbloader` findings that carry none of their own are `db.finding`.

Examples:

```sh
karicheck --json zone example.test /etc/karidns/zones/example.test.zone
karicheck --json zone example.test - < edited.zone
karicheck --json conf /usr/local/etc/karidns/karidns.conf
karicheck --json db /usr/local/etc/karidns/karidns.conf
```

### Message codes

Severity is the usual one of the code; a check whose severity the configuration sets (`check-*` options) prints the severity in force.

<!-- BEGIN CODES (generated by tests/check_diag_codes.pl --print-docs; do not edit) -->

| Code | Severity | Meaning |
|---|---|---|
| `usage.command.missing` | error | no command was given |
| `usage.command.unknown` | error | the command is not one the tool has (karicheck: conf, zones, zone, db; karidns-zone: import, export) |
| `usage.args` | error | a command got too few or too many arguments |
| `usage.option` | error | an option is unknown, lacks its value, has a value that is not valid, or cannot be used with another option |
| `io.open` | error | a file could not be opened |
| `io.not-regular` | error | a path that must be a regular file is not one |
| `io.read` | error | a file could not be read |
| `io.stat` | error | a file could not be examined with stat |
| `io.stdin.read` | error | reading standard input failed |
| `io.stdin.too-large` | error | the zone text on standard input is larger than 64 MiB |
| `io.file.too-large` | error | a configuration or zone file is larger than the server reads (256 MiB) |
| `io.pipe` | error | a pipe for the database loader could not be created |
| `io.fork` | error | the database loader could not be started |
| `internal.oom` | error | out of memory |
| `conf.syntax` | error | a syntax error in a configuration statement |
| `conf.value.invalid` | error | the value of an option is not one the option accepts |
| `conf.value.range` | error | a numeric option is outside its range |
| `conf.warning` | warning | an option is accepted but has no effect, or is written in a way KariDNS reads differently from BIND |
| `conf.acl.entry` | error | an entry of an ACL is not valid |
| `conf.acl.list` | error | an address match list cannot be resolved |
| `conf.acl.duplicate` | error | an acl is defined twice or has a built-in name |
| `conf.alias-resolver` | error | an alias-resolver entry is not an IP address, or the list is too long |
| `conf.server.key-unknown` | error | a server statement names a TSIG key that is not defined |
| `conf.key.view-clash` | error | a key in a view has the name of a top-level key |
| `conf.key.duplicate` | error | a TSIG key is defined twice |
| `conf.view.key-duplicate` | error | a TSIG key is defined twice in a view |
| `conf.option.bind-unimplemented` | warning | a BIND option that KariDNS does not implement is ignored |
| `conf.option.unknown` | error | an option that is neither a KariDNS option nor a BIND option for the statement |
| `conf.tsig.algorithm` | error | a TSIG algorithm that KariDNS does not support |
| `conf.tsig.algorithm-deprecated` | warning | a TSIG algorithm that is deprecated and insecure (HMAC-MD5, HMAC-SHA1; RFC 8945) |
| `conf.tsig.secret-length` | error | a TSIG secret is too long for its algorithm |
| `conf.tsig.secret-base64` | error | a TSIG secret is not valid base64 |
| `conf.tsig.secret-placeholder` | warning | a secret is still the placeholder of the sample configuration |
| `conf.tsig.secret-placeholder-used` | error | the secret of the control channel, or of a key that an ACL or an update-policy rule uses, is the placeholder of the sample configuration |
| `conf.zone.name` | error | a zone name is not valid (bad escape, empty label, or too long) |
| `conf.zone.duplicate` | error | a zone is defined twice |
| `conf.zone.type-resolver` | warning | a BIND zone type for resolvers is not loaded |
| `conf.zone.type-unknown` | error | an unknown zone type |
| `conf.zone.file-format` | error | file-format is neither bind nor tinydns |
| `conf.zone.update-on-secondary` | warning | allow-update on a secondary zone is refused at run time |
| `conf.zone.tsig-key-undefined` | error | the tsig-key of a zone is not defined |
| `conf.zone.transfer-key-undefined` | error | an allow-transfer key of a zone is not defined |
| `conf.database` | error | an error in options { database { } } or in the database options of a view |
| `conf.notify` | error | an error in also-notify or in a remote-servers list |
| `conf.xfr-source.limit` | error | more distinct transfer or NOTIFY source addresses than KariDNS can bind |
| `conf.directory.changed` | warning | options { directory } differs from the directory the running server uses |
| `conf.cookie.secret` | error | cookie-secret is not 32 hexadecimal digits |
| `conf.cookie.secret-count` | error | more cookie-secret entries than the limit |
| `conf.cookie.algorithm` | error | a cookie-algorithm other than siphash24 |
| `conf.query-log.max-qps` | error | query-log-max-qps is not valid |
| `conf.query-log.buffer-size` | error | query-log-buffer-size is not a power of 2 in range |
| `conf.minimal-any-ttl` | error | minimal-any-ttl is not a non-negative integer |
| `conf.wire-cache.max-records` | error | wire-cache-max-records is not a non-negative integer |
| `conf.control-channel.placement` | error | control-channel is written inside options { } |
| `conf.control-channel.option` | error | an unknown option in control-channel { } |
| `conf.view.name-length` | error | a view name is too long |
| `conf.view.duplicate` | error | a view is defined twice |
| `conf.loading` | info | the configuration file that is being checked |
| `conf.parse-failed` | error | the configuration file could not be parsed (the reason is in the messages before it) |
| `conf.listen` | info | the addresses the server listens on |
| `conf.xfr-source.list` | info | the transfer and NOTIFY source addresses |
| `conf.startup-notify-rate` | note | startup-notify-rate is accepted but has no effect |
| `conf.transfers-in-zero` | warning | transfers-in 0: no zone is transferred in |
| `conf.transfers-out-zero` | warning | transfers-out 0: every zone transfer request is refused |
| `conf.transfers-per-ns-zero` | warning | transfers-per-ns 0: no zone is transferred in |
| `conf.view.servers-override` | note | a view with its own server statements does not use the top-level ones |
| `conf.zone.secondary-options-on-primary` | note | refresh and inbound-transfer options have no effect in a primary zone |
| `conf.zone.multi-master` | note | multi-master has no effect with fewer than two primaries |
| `conf.zone.refresh-range` | warning | min-refresh-time is larger than max-refresh-time |
| `conf.zone.retry-range` | warning | min-retry-time is larger than max-retry-time |
| `conf.zone.primary-settings-unsigned` | warning | a secondary takes the settings of its primary over a transfer without TSIG |
| `conf.control-key.tsig` | warning | a control-channel key is also used for TSIG |
| `conf.directory.access` | error | options { directory } cannot be accessed |
| `conf.directory.not-dir` | error | options { directory } is not a directory |
| `conf.directory.relative` | warning | options { directory } is a relative path |
| `conf.acl.transfer-match` | warning | transfer-acl-match has no effect |
| `conf.acl.transfer-order` | warning | allow-transfer with addresses and keys is evaluated in BIND's first-match order |
| `conf.acl.update-match` | warning | update-acl-match has no effect |
| `conf.acl.update-order` | warning | allow-update with keys and negated entries is evaluated in BIND's first-match order |
| `conf.zone.program-path` | error | the program of a program zone is not an absolute path |
| `conf.zone.program-exec` | warning | the program of a program zone is not executable |
| `conf.zone.program-user-root` | error | program-user is root by another name |
| `conf.zone.program-user-differs` | warning | program-user differs from options user |
| `conf.zone.program-args` | error | program-args has more entries than supported |
| `conf.zone.program-count` | error | more zones of type program than supported (256) |
| `conf.zone.program-missing` | error | a program zone has no program path |
| `conf.zone.forward` | info | type forward keeps its KariDNS meaning, which differs from BIND |
| `conf.zone.forward-missing` | error | a forward zone has no forwarders |
| `conf.zone.forward-loop` | warning | a forwarder points at this server itself |
| `conf.program-zones.disabled` | error | program zones are configured but allow-program-zones is not enabled |
| `conf.tag.cidr` | error | a CIDR in ecs-tags or location-tags is not valid |
| `conf.ecs.disabled` | warning | ecs-tags are defined but ecs-enable is not set |
| `conf.identity.root` | error | options user or group is root by another name |
| `conf.database.no-driver` | error | options { database { } } has no driver |
| `conf.database.loader-user` | error | the loader-user does not exist |
| `conf.database.loader-user-missing` | warning | no loader-user is set |
| `conf.database.loader-group` | error | the loader-group does not exist |
| `conf.database.identity-root` | error | loader-user or loader-group is root by another name |
| `conf.database.loader-file` | error | the loader file fails the ownership, mode or execute checks |
| `conf.database.loader-answer` | error | the loader did not answer --drivers |
| `conf.database.driver` | error | the loader was not built with the configured driver |
| `conf.database.drivers-not-run` | warning | --drivers was not run because karicheck is run by root |
| `conf.database.state-file` | warning | loader-state-file has no effect without memory-limit |
| `conf.database.warm` | warning | warm-before-serve has no effect without memory-limit |
| `conf.database.acl-ceiling` | warning | no acl-ceiling: the ACLs of database zones refuse every client |
| `conf.database.acl-ceiling-match` | warning | acl-ceiling-match all has no effect with one kind of entry |
| `conf.database.file` | error | the SQLite3 database file does not exist |
| `conf.database.file-type` | error | the SQLite3 database file is not a regular file |
| `conf.database.file-readable` | warning | the SQLite3 database file is readable by everyone |
| `conf.database.dir-writable` | warning | the directory of the SQLite3 database file is writable by everyone |
| `conf.database.file-unreadable` | warning | the SQLite3 database file cannot be read to check its journal mode |
| `conf.database.file-empty` | error | the SQLite3 database file is empty |
| `conf.database.file-format` | error | the file is not an SQLite3 database |
| `conf.database.wal` | error | the SQLite3 database is not in WAL mode |
| `conf.database.conninfo-file` | error | the conninfo-file cannot be examined |
| `conf.database.conninfo-mode` | error | the conninfo-file mode is not 0600 or 0400 |
| `conf.database.conninfo-owner` | error | the conninfo-file does not belong to the loader user |
| `conf.database.conninfo-tls` | warning | the connection has neither a UNIX socket host nor sslmode=verify-full |
| `conf.database.server-id-sqlite` | warning | server-id is ignored with sqlite3 |
| `conf.database.server-id-chars` | warning | server-id has characters other than letters, digits and . - _ : |
| `conf.database.server-id-host` | warning | server-id is not set and the host name does not fit |
| `conf.alerts.option` | error | an unknown statement in alerts { }, or interval / reload-failures-above in the alerts { } of a zone |
| `conf.alerts.range` | error | an alerts { } value is not a number, is negative, is above 100 for servfail-ratio-above, or is outside 10..3600 for interval |
| `conf.alerts.empty` | warning | an alerts { } block sets no limit, so nothing is checked |
| `conf.database.alias-resolver` | warning | an alias-resolver with server-id: servers sharing a database can answer ALIAS names differently |
| `zone.not-found` | error | the zone is not in the configuration |
| `zone.skipped` | info | a zone without a zone file is not checked |
| `zone.summary` | info | the number of zones checked and skipped, and the errors |
| `zone.syntax` | error | a syntax error in the zone file or a record that the zone parser or a zone validation refuses |
| `zone.include-stdin` | error | $INCLUDE is refused in a zone read from standard input |
| `zone.empty` | error | the zone has no records |
| `zone.out-of-zone` | warning | a record outside the zone is ignored |
| `zone.tinydns.out-of-zone` | warning | tinydns records that belong to no zone of the view are ignored |
| `zone.tinydns.skipped` | warning | tinydns lines with data that cannot be kept are left out |
| `zone.ttl.missing` | warning | records have no TTL and no $TTL |
| `zone.string.long` | warning | a character-string of more than 255 octets |
| `zone.limits` | error | the zone breaks a size limit of the configuration |
| `zone.pdns-types` | error | records the server does not accept: bad ALIAS or LUA, a second CNAME / DNAME / RESINFO at a name, NSEC3 iterations above 150 |
| `zone.program-skipped` | info | a program zone has no zone file to validate |
| `zone.dnssec.algorithm-deprecated` | warning | a DNSSEC algorithm that RFC 8624 forbids or does not recommend |
| `zone.dnssec.algorithm-unknown` | warning | an unknown DNSSEC algorithm number |
| `zone.dnssec.key-base64` | warning | a DNSSEC key or signature is not valid base64 |
| `zone.dnssec.mldsa-length` | warning | an ML-DSA key or signature has the wrong length |
| `zone.ds.digest-null` | warning | DS digest type 0 outside of the CDS delete signal |
| `zone.ds.digest-deprecated` | warning | a DS digest type that is deprecated |
| `zone.ds.digest-unknown` | warning | an unknown DS digest type |
| `zone.ds.digest-length` | error | a DS or CDS digest whose length does not fit its digest type |
| `zone.cds.delete-content` | warning | a CDS or CDNSKEY delete signal whose content is not the one RFC 8078 section 4 gives |
| `zone.dnskey.protocol` | warning | a DNSKEY or CDNSKEY whose protocol field is not 3 |
| `zone.zonemd.scheme-invalid` | warning | the ZONEMD scheme is not a number from 0 to 255 |
| `zone.zonemd.hash-invalid` | warning | the ZONEMD hash algorithm is not a number from 0 to 255 |
| `zone.zonemd.canonical` | error | a record cannot be put in canonical form, so the ZONEMD digest is not computed |
| `zone.zonemd.serial-mismatch` | error | the ZONEMD serial differs from the SOA serial |
| `zone.zonemd.unsupported` | info | a ZONEMD with an unsupported scheme or hash algorithm is not verified |
| `zone.zonemd.duplicate` | error | more than one ZONEMD with the same scheme and hash algorithm |
| `zone.zonemd.digest-length` | error | the ZONEMD digest has the wrong length |
| `zone.zonemd.compute-failed` | error | the ZONEMD digest could not be computed |
| `zone.zonemd.mismatch` | error | the ZONEMD digest does not match the zone |
| `zone.zonemd.not-apex` | warning | a ZONEMD record is not at the zone apex |
| `zone.zonemd.fields` | warning | a ZONEMD record has fewer than four fields |
| `zone.glue.missing` | error | an in-bailiwick NS target has no A or AAAA record |
| `zone.target.no-address` | warning | an in-bailiwick MX, SRV or similar target has no A or AAAA record |
| `zone.cname.coexists` | error | a CNAME shares its name with other record types |
| `zone.cname.coexists-other` | warning | a CNAME co-exists with other records (RFC 1912) |
| `zone.record.occluded` | warning | a record is hidden by a delegation above it |
| `zone.cut.data` | warning | a record other than NS, DS, DNSSEC or address data at a delegation point |
| `zone.cname.target` | error | an NS or MX record points to a CNAME |
| `zone.srv.cname` | warning | an SRV record points to a CNAME |
| `zone.cname.loop` | error | a CNAME points to itself |
| `zone.cname.chain` | warning | a CNAME points to another CNAME |
| `zone.wildcard.non-terminal` | warning | an owner name contains a wildcard that is not the leftmost label |
| `zone.dup-records` | warning | an RRset has duplicate records |
| `zone.mx.address` | warning | an MX target is an IP address |
| `zone.names.owner` | error | an owner name is not a valid host name (check-names) |
| `zone.names.target` | error | a name in record data is not a valid host name (check-names) |
| `zone.nsec3param.not-apex` | warning | an NSEC3PARAM is not at the zone apex |
| `zone.nsec3param.hash-algorithm` | warning | an NSEC3PARAM with a hash algorithm other than 1 |
| `zone.nsec3param.flags` | error | an NSEC3PARAM with Flags other than 0 |
| `zone.nsec3param.iterations-high` | error | NSEC3PARAM iterations that are excessively high |
| `zone.nsec3param.iterations` | warning | NSEC3PARAM iterations other than 0 (RFC 9276) |
| `zone.nsec3param.salt` | warning | an NSEC3PARAM that uses a salt (RFC 9276) |
| `zone.nsec3param.unusable` | warning | no NSEC3PARAM of the zone is usable |
| `zone.nsec3.chain-missing` | warning | no NSEC3 records with the parameters of the NSEC3PARAM |
| `zone.nsec3.hash-algorithm` | warning | an NSEC3 chain with a hash algorithm other than 1 |
| `zone.nsec3.flags-reserved` | warning | NSEC3 records with reserved Flags bits set |
| `zone.nsec3.opt-out` | warning | NSEC3 opt-out is set |
| `zone.nsec3.iterations-high` | error | NSEC3 iterations that are excessively high |
| `zone.nsec3.iterations` | warning | NSEC3 iterations other than 0 (RFC 9276) |
| `zone.nsec3.salt` | warning | an NSEC3 chain that uses a salt (RFC 9276) |
| `zone.nsec3.chain-orphan` | warning | an NSEC3 chain that matches no usable NSEC3PARAM |
| `zone.ttl.inconsistent` | warning | the records of an RRset have different TTLs (RFC 2181 section 5.2) |
| `zone.ttl.inconsistent-visibility` | warning | restricted and unrestricted records of an RRset have different TTLs |
| `zone.alias.present` | info | the zone has ALIAS records |
| `zone.lua.present` | warning | the zone has LUA records, which are never executed |
| `zone.location.prefix` | error | a tinydns location prefix longer than /32 |
| `zone.location.duplicate` | warning | a tinydns location code is defined twice |
| `zone.location.tag-undefined` | error | a record names a location tag that is not defined |
| `zone.ecs.tag-undefined` | error | a record names an ECS subnet tag that is not defined |
| `zone.tinydns.ipv6-hex` | error | a tinydns line needs a 32-character hexadecimal IPv6 address |
| `zone.tinydns.ip6int` | info | a tinydns type 6 line generates a PTR in the deprecated ip6.int |
| `zone.a.fields` | error | an A record without exactly one field |
| `zone.a.address` | error | an A record with an invalid IPv4 address |
| `zone.aaaa.fields` | error | an AAAA record without exactly one field |
| `zone.aaaa.address` | error | an AAAA record with an invalid IPv6 address |
| `zone.csync.type-unknown` | warning | a CSYNC record names an unknown type |
| `zone.svcb.target-dot` | warning | an SVCB or HTTPS TargetName does not end with a dot |
| `zone.hip.fields` | warning | a HIP record has fewer than three fields |
| `zone.hip.key-base64` | error | the public key of a HIP record is not valid base64 |
| `zone.wks.protocol` | warning | the protocol of a WKS record is neither a number nor TCP or UDP |
| `zone.wks.port` | warning | a port of a WKS record is neither a number nor a known service |
| `zone.gpos.fields` | warning | a GPOS record does not have exactly three fields |
| `zone.x25.fields` | warning | an X25 record has no field |
| `zone.isdn.fields` | warning | an ISDN record does not have one or two fields |
| `zone.eui48` | warning | an EUI48 record is not six octets |
| `zone.eui64` | warning | an EUI64 record is not eight octets |
| `zone.srv.fields` | error | an SRV record without four fields |
| `zone.srv.priority-range` | error | the priority of an SRV record is out of range |
| `zone.srv.weight-range` | error | the weight of an SRV record is out of range |
| `zone.srv.port-range` | error | the port of an SRV record is out of range |
| `zone.naptr.fields` | error | a NAPTR record without six fields |
| `zone.naptr.order-range` | error | the order of a NAPTR record is out of range |
| `zone.naptr.preference-range` | error | the preference of a NAPTR record is out of range |
| `zone.naptr.flags` | error | the flags of a NAPTR record are not alphanumeric |
| `zone.naptr.regexp-replacement` | error | a NAPTR record sets both a regexp and a replacement |
| `zone.caa.fields` | error | a CAA record without three fields |
| `zone.caa.flags-range` | error | the flags of a CAA record are out of range |
| `zone.caa.flags-undefined` | warning | a CAA record sets undefined flag bits |
| `zone.caa.tag-syntax` | error | a CAA tag does not match the RFC 8659 syntax |
| `zone.caa.tag-critical` | error | an unknown CAA tag with the critical flag set |
| `zone.caa.tag-unknown` | warning | an unrecognized CAA tag |
| `zone.sshfp.fields` | error | an SSHFP record without three fields |
| `zone.sshfp.algorithm-range` | error | the algorithm of an SSHFP record is out of range |
| `zone.sshfp.algorithm-unassigned` | warning | an SSHFP algorithm that is not assigned |
| `zone.sshfp.fptype-range` | error | the fingerprint type of an SSHFP record is out of range |
| `zone.sshfp.fptype-unassigned` | warning | an SSHFP fingerprint type that is not assigned |
| `zone.sshfp.fingerprint-hex` | error | the fingerprint of an SSHFP record is not hexadecimal |
| `zone.sshfp.fingerprint-length` | error | the fingerprint of an SSHFP record does not have the length of its fingerprint type |
| `zone.soa.mname-cname` | warning | the SOA MNAME points to a CNAME |
| `zone.meta-type` | error | a meta-type appears as a standalone RRset |
| `zone.dsync.type-unknown` | warning | a DSYNC record names an unknown RR type |
| `zone.record.wire` | error | a record cannot be serialized to wire format |
| `zone.soa.missing` | error | the zone has no SOA record at the apex |
| `zone.soa.multiple` | error | more than one SOA record that every client sees |
| `zone.soa.invalid` | error | the SOA records of the zone are not valid |
| `zone.soa.location-undefined` | warning | the SOA record is restricted to a location the zone does not define |
| `zone.soa.expired` | warning | the SOA record has expired |
| `zone.ns.missing` | error | the zone has no NS record at the apex |
| `zone.catalog.version` | error | a catalog zone lacks its version TXT record |
| `zone.catalog.name-too-long` | error | a name in a catalog zone is too long to check |
| `zone.catalog.orphan-group` | warning | a group TXT record of a catalog zone has no member PTR record |
| `zone.catalog.member-ptrs` | error | a member node of a catalog zone has more than one PTR record |
| `zone.catalog.member-duplicate` | error | two member nodes of a catalog zone name the same zone |
| `db.finding` | error | a finding of karidns-dbloader --check that carries no code of its own (the severity is the message's) |
| `db.checking` | info | the database that is being checked |
| `db.summary` | info | the number of databases and zones checked |
| `db.memory.estimate` | info | what the database needs in memory, computed from its zone and record counts: the Backend, the loader, and the memory-limit that keeps every zone |
| `db.memory.limit-below-all` | note | memory-limit is below what every zone needs: the share of zones that fit, and the recommended memory-limit |
| `db.memory.limit-low` | warning | memory-limit keeps less than half of the zones in memory: most queries will wait for a read of the database |
| `db.memory.limit-tiny` | error | memory-limit cannot hold the zones of the reads that run at once (fetch-concurrency): nearly every query for a database zone waits or fails |
| `db.disabled` | error | the configuration has no database block |
| `db.loader-missing` | error | the database loader is not installed |
| `db.view-not-found` | error | the view named on the command line is not defined |
| `db.view-none` | error | the view takes no zones from the database |
| `db.nothing` | error | no view reads a database |
| `db.identity.no-loader-user` | error | run by root without a loader-user, so there are no rights to check with |
| `db.identity.root` | error | loader-user or loader-group is root by another name |
| `db.identity.user` | error | the loader-user does not exist |
| `db.identity.group` | error | the loader-group does not exist |
| `db.loader.line-too-long` | error | the loader wrote a line that is too long |
| `db.loader.failed` | error | the loader did not finish its check |
| `db.loader.protocol` | warning | the loader printed lines that are not part of its protocol |
| `db.protocol.zone` | error | a zone line of the loader does not decode |
| `db.protocol.settings` | error | a settings line of the loader does not decode |
| `db.view.undefined` | warning | karidns_domain_views names a view that is not defined |
| `db.view.not-shared` | warning | karidns_domain_views names a view that does not read the shared source |
| `db.view.unserved` | warning | karidns_domain_views maps the zone only to views that do not read it |
| `db.zone.shadowed` | warning | a zone of the configuration hides the database zone |
| `db.zone.shadowed-program` | warning | a program or forward zone of the configuration hides the database zone |
| `db.settings.ceiling-entry` | warning | an ACL entry of the settings is outside acl-ceiling |
| `db.settings.ceiling-key` | warning | a key of the settings is not listed in acl-ceiling |
| `db.settings.ceiling-missing` | warning | the settings have ACL entries but acl-ceiling is not configured |
| `db.settings.profile` | error | the settings text of a profile does not parse |
| `db.settings.zone` | error | the settings of a zone do not parse |
| `db.settings.combined` | error | the settings of a profile and of its zone together do not parse |
| `db.settings.key-undefined` | error | the settings name a TSIG key that is not defined |
| `db.import.open` | error | the database could not be opened for writing |
| `db.import.schema` | error | the database lacks a table or a column the import needs |
| `db.import.option` | error | an import option is not valid: a zone type, a view name or a record type of the types filter |
| `db.import.zone-name` | error | the zone name is not valid, or the zone is not in the tinydns data file |
| `db.import.rows` | error | the zone cannot be written as rows of the PowerDNS schema |
| `db.import.serial` | error | the SOA serial of the file does not grow past the serial in the database (RFC 1982) |
| `db.import.checks` | error | the zone checks found errors; nothing was written |
| `db.import.strict` | error | the zone checks printed warnings and strict mode is on |
| `db.import.busy` | error | another import holds the zone or the database; nothing was written |
| `db.import.write` | error | a database write failed; the transaction was rolled back and nothing was written |
| `db.import.keys` | warning | the zone has cryptokeys but the imported data is not presigned, so the loader refuses the zone |
| `db.import.file-zone` | warning | the zone is also a file zone of the configuration, and the file zone is served |
| `db.import.no-reload` | warning | a reload request was asked for but the database has no karidns_reload_requests table |
| `db.import.dry-run` | info | a dry run: everything but the commit was done, and nothing was written |
| `db.import.verify` | error | the zone read back from the transaction is not one the loader would load; the transaction was rolled back |
| `db.import.not-primary` | warning | the zone in the database is not a primary zone, so the records written were not checked |
| `db.import.done` | info | a zone was imported, with the number of RRsets added, replaced and deleted |
| `db.import.summary` | info | the end of an import of several zones: how many were imported and how many failed |
| `db.import.change` | note | an RRset the import adds, replaces or deletes (listed for --dry-run and --verbose) |
| `db.import.changed` | error | the zone changed under the tool (import --signer: it is not the zone the file was made from; apply: not at --expect-generation); nothing was written (exit 3) |
| `db.apply.changes` | error | apply: the change file is not valid: a line, an owner, a type, a TTL or an RDATA a change file does not take |
| `db.apply.zone` | error | apply: the zone is not there (or is there, with --create), is not a primary zone, or the change would take its SOA away |
| `db.render.input` | error | render: the records on standard input are not lines of the form owner TAB type TAB prio TAB content, or there are too many |
| `db.import.signer` | error | import --signer cannot take this file or zone: the file is not a signed zone, or the zone is not a primary zone of the database; nothing was written |
| `db.import.signer-zone` | info | the zone is signed by karidns-signer: the import kept its DNSSEC records and signer metadata, and the zone is served again after the next signing |
| `db.export.open` | error | the database could not be opened |
| `db.export.not-found` | error | the zone is not in the database, or not in the view asked for |
| `db.export.zone-type` | error | the zone is not a primary zone: its records are not what the server serves |
| `db.export.read` | error | the rows of the zone could not be read |
| `db.export.zone` | error | the rows of the zone do not make a zone the server would load |
| `db.export.write` | error | the zone could not be written as text |
| `db.export.warning` | warning | the reader of the database zone printed a warning about the rows it exports |
| `db.export.done` | info | a zone was exported to a file, or every zone to a directory |
| `db.zone.no-source` | error | no database was named: no --sqlite3 or --conninfo-file, and no configuration with options { database { } } |
| `db.zone.driver` | error | the database driver is not one this build of karidns-zone has |
| `db.zone.output` | error | an output file or directory could not be used, created, written or renamed |
| `db.zone.output-exists` | error | an output file exists and --force was not given |

<!-- END CODES -->

---

## EXIT STATUS

`0`
: All checked configuration files and zone files are valid. Warnings do not change the exit status. `-h` and `--help` print the usage text to standard output and also exit with 0 (as `karictl` and `karidns-dbloader` do).

`1`
: Problems found: unreadable file, syntax error, validation error, or ZONEMD digest mismatch detected. `db`: an error in the database or its data, a database that cannot be read with the rights of the loader, or a loader that is not installed (`DB support is not installed`).

`2`
: Usage error (a missing or unknown command, missing or too many arguments; the usage text goes to standard error). Nothing was checked. Before this release a usage error exited with 1. With `--json` the document holds the usage error (`usage.*`) and nothing is written to standard error.

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
KariDNS                         September 2026                  KARICHECK(8)
```

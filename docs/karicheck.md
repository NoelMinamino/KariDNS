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

karicheck -v | --version
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

`-v`, `--version`
: Print the version and exit.

---

## VALIDATION CHECKS

### Configuration checks

- Syntax of the whole file, including `include` files, with the same rules as `karidns` (undefined TSIG keys in `tsig-key` / `allow-transfer`, duplicate zones/views/keys/acls, invalid option values, ...).
- Boolean values other than `yes`/`true`/`1`/`no`/`false`/`0` are errors.
- An unknown statement inside `zone { }` or `view { }` is an error (`[ERROR] zone 'example.test.': unknown option 'alow-transfer' ...`): `karidns` used to skip such a statement without a word, so a typo silently left a zone open or closed. Options that BIND 9 documents for a `zone` or `view` statement but KariDNS does not implement (`allow-query`, `notify`, `inline-signing`, `dnssec-policy`, `auto-dnssec`, `key-directory`, `max-journal-size`, `zone-statistics`, `check-names`, `recursion`, ...) give a warning (`[WARNING] ... is a BIND option that KariDNS does not implement; it is ignored`) and are skipped. Unknown statements elsewhere (`options`, `key`, `logging`, `control-channel` ...) are still skipped without a message.
- Every entry of `allow-transfer`, `allow-update`, `match-clients`, `ecs-trusted-resolvers` and `acl` must be an address, a prefix, `any`, `none`, a defined `acl` (or, in `allow-update`, a defined key); anything else, including `localhost` and `localnets`, is an error.
- A logging `category` that lists more than one channel gives a warning (only the first one is used).
- `type program` zones: `program` must be set and be an absolute path, and `program-args` may have at most 62 entries (errors); a `program` that is not executable and a `program-user` that differs from `options { user }` give warnings. `allow-program-zones yes;` is required when any program zone exists.
- `alias-resolver { ... };` (in `options`, in a zone, and in `options { database { } }`): at most 8 entries, each an IP address (a host name is an error).
- `type forward` zones must have `forwarders`; a forwarder equal to one of the server's own `bind-address` / `port` pairs gives a self-loop warning.
- Every CIDR in `ecs-tags` and `location-tags` (in `options` and in zones) must be valid; `ecs-tags` without `ecs-enable yes;` gives a warning.
- `transfer-acl-match` and `update-acl-match` take `any` or `all` (anything else is an error). A warning says when an option has nothing to choose between: without `allow-transfer` / `allow-update`, or with an ACL that lists only addresses or only keys (see karidns(8) "Settings of database zones").
- `options { database { ... }; }` (no database connection is opened): the driver is built into `karidns-dbloader` (`--drivers`); `loader-user` / `loader-group` exist; `loader-path` is a regular executable owned by root and not writable by group or others; a SQLite3 file exists, is a database in WAL mode and is not readable by everyone; a PostgreSQL `conninfo-file` has mode 0600 or 0400, belongs to the loader user and names a UNIX socket or `sslmode=verify-full` (warning otherwise); with PostgreSQL the `server-id` (the name of this server's row in `karidns_server_status`; 1 to 64 bytes, the parser enforces that) gives a warning when it has characters other than ASCII letters, digits and `. - _ :`, and so does a missing `server-id` when the host name (the default) is empty or longer than 64 bytes (then no status row can be written); a `server-id` together with an `alias-resolver` (in `options { database { } }` or in `options`) gives a warning that ALIAS answers can differ between the servers that share the database, because each server's resolver and the moment of its lookup decide them (milestone B11b; the SOA serials and the zone transfers are the same; a resolver named only in a zone's profile text is not seen; LUA records are never run, so they need no warning); `acl-ceiling` entries are valid and its keys are defined. `acl-ceiling-match` must be `any` or `all`; `all` gives a warning when the ceiling lists only addresses or only keys (that kind alone decides then). A database block **without `acl-ceiling`** gives a warning: the ACLs a database zone carries (transfers, dynamic updates) refuse every client until a ceiling is set.

### Zone checks

1. **Zone File Directives**:
   - `$ORIGIN`, `$TTL`, `$INCLUDE` (up to 16 nesting levels and 32 files per zone), `$GENERATE` (BIND syntax, any RR type, at most 100,000 records per directive; see karidns(8) "ZONE FILE FORMAT")
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

---

## EXIT STATUS

`0`
: All checked configuration files and zone files are valid. Warnings do not change the exit status.

`1`
: Usage error, unreadable file, syntax error, validation error, or ZONEMD digest mismatch detected.

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

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karictl(8)`](karictl.md) — KariDNS server management and control utility
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                  KARICHECK(1)
```

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
- Every entry of `allow-transfer`, `allow-update`, `match-clients`, `ecs-trusted-resolvers` and `acl` must be an address, a prefix, `any`, `none`, a defined `acl` (or, in `allow-update`, a defined key); anything else, including `localhost` and `localnets`, is an error.
- A logging `category` that lists more than one channel gives a warning (only the first one is used).
- `type program` zones: `program` must be set and be an absolute path, and `program-args` may have at most 62 entries (errors); a `program` that is not executable and a `program-user` that differs from `options { user }` give warnings. `allow-program-zones yes;` is required when any program zone exists.
- `type forward` zones must have `forwarders`; a forwarder equal to one of the server's own `bind-address` / `port` pairs gives a self-loop warning.
- Every CIDR in `ecs-tags` and `location-tags` (in `options` and in zones) must be valid; `ecs-tags` without `ecs-enable yes;` gives a warning.

### Zone checks

1. **Zone File Directives**:
   - `$ORIGIN`, `$TTL`, `$INCLUDE` (up to 16 nesting levels and 32 files per zone), `$GENERATE` (BIND syntax, any RR type, at most 100,000 records per directive; see karidns(8) "ZONE FILE FORMAT")
   - KariDNS steering directives `$LOCATION`, `$LOCATION-TAG`, `$ECS-SUBNET`, `$ECS-SUBNET-TAG`: records that reference an undefined location or ECS tag are errors
   - tinydns `data` files (through a configuration file with `file-format tinydns;`): invalid location prefix lengths (`/n` above 32, error), duplicate location codes, malformed IPv6 fields of `3`/`6` lines, and SRV/NAPTR/SSHFP field ranges of generic lines
2. **Zone Integrity & Structural Invariants**:
   - Exactly one SOA record at the zone apex, and at least one NS record at the apex
   - CNAME exclusivity (CNAME must not co-exist with other record types at the same owner name, except DNSSEC RRs), CNAME loops, CNAME chains (warning), and NS/MX/SRV targets that point to a CNAME (RFC 2181 §10.3)
   - Out-of-zone records (owner not at or below the zone name, e.g. address records for name servers outside the zone) give a warning and are left out of all further checks, because the server does not load them (RFC 1034 §4.2); the exit status is not affected
   - In-bailiwick NS targets (apex and delegations) must have an A/AAAA record in the zone (error); in-bailiwick MX and SRV targets without A/AAAA give a warning only, because no RFC requires an address for them. Records occluded by a delegation give warnings
   - Inconsistent TTLs within one RRset (warning)
   - SOA MNAME pointing to a CNAME (warning)
   - Meta-types (e.g. `OPT`, `TSIG`, `AXFR`) must not appear in zone data
   - Every record must be serializable to wire format
   - Catalog zones (`catalog-zone yes;`): `version.<zone> TXT "2"` is required, and group TXT records without a member PTR record give warnings
3. **Record Field Validation**:
   - A/AAAA addresses; SRV, NAPTR, CAA (RFC 8659 tags and flags), SSHFP, HIP, WKS, GPOS, X25, ISDN, EUI48/EUI64, CSYNC, DSYNC and SVCB/HTTPS target fields
   - WKS: the protocol is a number (0-255) or `TCP` / `UDP` (any case), as the server reads it; a port that is not a number (0-65535), e.g. a service name, gives a warning because the server leaves it out of the bit map
   - NSEC3PARAM at the apex: Flags other than 0 are an error (RFC 5155 §4.1.2: such an NSEC3PARAM MUST be ignored, and the server ignores it); a hash algorithm other than 1 (SHA-1), an iteration count other than 0 (RFC 9276 §3.1: MUST be 0) and a non-empty salt (RFC 9276 §3.1: SHOULD NOT) give warnings; more than 100 iterations are an error. A warning is also given when no NSEC3PARAM is usable, or when the one the server uses has no NSEC3 RRs
   - NSEC3 records are checked once per chain (RRs with the same hash algorithm, iterations and salt), not once per RR: hash algorithm, reserved flag bits, opt-out (RFC 9276 §3.1), iterations and salt as above, and a warning for a chain that matches no NSEC3PARAM with Flags 0 (the server does not use it)
4. **DNSSEC Algorithm & Digest Verification (RFC 8624 / RFC 8078)**:
   - Evaluates DNSSEC algorithms in DNSKEY and RRSIG records against RFC 8624 status recommendations (e.g., flagging deprecated SHA-1 or MD5 algorithms)
   - Validates DS digest types (warning on deprecated digests)
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

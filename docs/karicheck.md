# KARICHECK(1) — KariDNS Reference Manual

```text
KARICHECK(1)                   KariDNS Manual                   KARICHECK(1)
```

---

## NAME

**karicheck** — Zone File Syntax and Server Configuration Validation Utility

---

## SYNOPSIS

```sh
karicheck conf [config_path]

karicheck zones [config_path]

karicheck zone <domain> [config_path]

karicheck zone <domain> <zone_file_path>
```

---

## DESCRIPTION

`karicheck` is a static validation and syntax inspection tool for [`karidns(8)`](karidns.md) configuration files and RFC 1035 zone master files.

It validates configuration files and RFC 1035 zone master files for syntax errors, structural constraints, DNSSEC algorithm recommendations (RFC 8624), CDS/CDNSKEY delete signals (RFC 8078), and RFC 8976 ZONEMD message digests.

---

## COMMANDS

`conf [config_path]`
: Validate the syntax of the specified `karidns.conf` configuration file (default: `/usr/local/etc/karidns.conf`). Verifies options, logging channels, rate-limiting directives, ACLs, and zone statements.

`zones [config_path]`
: Parse `karidns.conf` and sequentially validate all master and primary zone files declared within it.

`zone <domain> [config_path]`
: Look up `<domain>` in `karidns.conf` and validate its corresponding zone file.

`zone <domain> <zone_file_path>`
: Standalone zone validation mode. Parse and validate `<zone_file_path>` against `<domain>` without requiring a configuration file.

---

## VALIDATION CHECKS

`karicheck` performs the following verification checks:

1. **RFC 1035 / BIND Zone Directives**:
   - `$ORIGIN`, `$TTL` (with standard time unit suffixes: `w`, `d`, `h`, `m`, `s`)
   - `$INCLUDE` nesting hierarchy (within Capsicum security constraints)
   - `$GENERATE` range and template expansions
2. **Zone Integrity & Structural Invariants**:
   - Single valid SOA record at zone apex
   - Authoritative NS record presence at zone origin
   - CNAME exclusivity (ensuring CNAME does not co-exist with other record types at the same owner name, except DNSSEC RRs)
   - Out-of-zone data rejection
   - Required in-bailiwick Glue record presence for child delegations
3. **DNSSEC Algorithm & Digest Verification (RFC 8624 / RFC 8078)**:
   - Evaluates DNSSEC algorithms in DNSKEY and RRSIG records against RFC 8624 status recommendations (e.g., flagging deprecated SHA-1 or MD5 algorithms)
   - Validates DS digest types (warning on deprecated digests)
   - Recognizes RFC 8078 CDS and CDNSKEY delete signals (Algorithm=0 / DigestType=0) without false-positive warnings
4. **RFC 8976 ZONEMD Message Digest Verification**:
   - Verifies RFC 8976 ZONEMD resource records by computing canonical zone hashes (SHA-384 / SHA-512) and comparing against advertised digest values.

---

## EXIT STATUS

`0`
: All checked configuration files and zone files are syntactically valid and pass validation tests.

`1`
: Syntax error, missing file, missing glue, invalid record combination, or ZONEMD digest mismatch detected.

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

### Validate a Specific Master Zone Standalone
```sh
karicheck zone example.com /var/named/etc/namedb/master/example.com.zone
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
KariDNS                          August 2026                    KARICHECK(1)
```

# KariDNS: Client Geolocation & Subnet Steering Guide (tinydns `location` and BIND `$ECS-SUBNET`)

This document describes how to configure and utilize client-specific record steering in KariDNS.
KariDNS provides two distinct, high-performance mechanisms for record-level split-horizon response steering:

1. **tinydns `location` (`%`) Directive**: Native djbdns/tinydns compatible geolocation steering based on client source IPv4 prefixes.
2. **BIND Zone `$ECS-SUBNET` Directive & `ecs-tags`**: A KariDNS BIND zone extension providing record-level steering based on EDNS0 Client Subnet (ECS, RFC 7871).

---

## 1. Overview & Comparison

| Feature | tinydns `location` (`%`) | BIND `$ECS-SUBNET` |
| :--- | :--- | :--- |
| **Zone Format** | tinydns data file format (`file-format tinydns;`) | Standard BIND zone format (`file-format bind;`) |
| **Client Identifier** | Direct Client Source IP (IPv4) | EDNS Client Subnet (ECS, IPv4 & IPv6, RFC 7871) |
| **Granularity** | Record-level (within the same zone) | Record-level (within the same zone) |
| **Tagging Syntax** | Trailing field `:loc` in record line (e.g. `::in`) | In-band `$ECS-SUBNET <tag>` directive |
| **Tag Definition** | In zone file: `%<loc>:<ip-prefix>` | In `karidns.conf`: `ecs-tags { tag "<name>" { <cidrs>; }; };` |
| **Scope of Tag Def** | Zone-level only | Global `options {}` or overridden per `zone {}` |
| **Resolver Security** | Evaluates direct client/resolver socket address | Strict ACL validation via `ecs-trusted-resolvers` |
| **Coexistence in Zone** | **Mutually Exclusive**: Cannot be used in BIND zones | **Mutually Exclusive**: Cannot be used in tinydns data files |
| **Memory Allocation** | Zero allocation on hot path | Zero allocation on hot path |

---

### 1.1 Mutual Exclusivity and Non-Coexistence

> [!IMPORTANT]
> **These two features CANNOT coexist within the same zone file.**
> They are strictly segregated by zone file format and query evaluation pipeline:
>
> 1. **Zone File Level Non-Coexistence**:
>    - A zone in KariDNS is either a **tinydns zone** (`file-format tinydns;`) or a **BIND zone** (`file-format bind;` / default).
>    - You **cannot** use `$ECS-SUBNET` inside a tinydns data file (the tinydns parser will treat it as a syntax error).
>    - You **cannot** use `%` location directives or tinydns trailing `:loc` fields inside a BIND zone file (the BIND parser will reject them).
>
> 2. **Query Evaluation Level Non-Coexistence**:
>    - **tinydns `location`** operates strictly on the **underlying UDP/TCP socket source IP** (the immediate client or recursive resolver). It completely ignores EDNS Client Subnet (Option 8) data even if present.
>    - **BIND `$ECS-SUBNET`** operates strictly on the **EDNS Client Subnet (Option 8)** option provided by trusted resolvers. It does not map direct socket IPs to location tags.
>
> 3. **Server-Wide Multi-Zone Operation**:
>    - While a single zone cannot mix both features, a single `karidns` process can host multiple zones where some zones use `file-format tinydns;` (using `%` location) and other zones use `file-format bind;` (using `$ECS-SUBNET`).
>    - Each zone strictly adheres to its own evaluation pipeline, ensuring zero interference between the two mechanisms.

---

## 2. tinydns `location` (`%`) Directive

The tinydns location feature allows you to return different IP addresses or resource records depending on the source IP of the querying client or resolver.

### 2.1 Zone File Syntax

In a tinydns data file, locations are declared with `%` directives, and individual records reference these location codes in their optional trailing location field.

```text
# Syntax: %<2-char-code>:<ipv4-prefix>
%in:192.168.
%in:10.
%ex:172.16.
%df:

# Syntax: +<fqdn>:<ip>:<ttl>:<timestamp>:<location>
+www.example.com:192.168.1.10:300::in
+www.example.com:172.16.1.10:300::ex
+www.example.com:1.2.3.4:300

# Records without location tag match ALL clients:
+mail.example.com:192.168.1.25:300
```

#### Syntax Rules:
- **Location Definition**: `%<loc>:<prefix>`
  - `<loc>`: Exactly two ASCII alphanumeric characters (e.g. `in`, `ex`, `us`, `jp`, `df`).
  - `<prefix>`: Decimal IPv4 prefix with 1 to 4 octets separated by dots (e.g. `192.168.` represents `192.168.0.0/16`, `10.` represents `10.0.0.0/8`, `192.168.1.4` represents `/32`).
  - Empty prefix `%<loc>:` (or `%df:`): Catch-all location matched when no specific prefix matches the client.
- **Record Assignment**:
  - The 6th field of standard tinydns record lines (`+`, `=`, `@`, `^`, `C`, etc.) specifies the location code.
  - If the location field is empty (e.g. `+www.example.com:1.2.3.4:300`), the record is **unrestricted** and is eligible to be returned to all clients.

### 2.2 Evaluation Logic

1. **Longest Prefix Match (LPM)**:
   - When a query arrives, KariDNS extracts the client's IPv4 address from the socket.
   - It performs a bit-level longest-prefix match against all `%` entries loaded in the zone's `zone_arena_t`.
   - If a match is found, the client is tagged with the corresponding 2-character code (e.g., `in`).
   - If no prefix matches, KariDNS falls back to the catch-all location entry (`prefix_len == 0`), if defined.
2. **Record Filtering**:
   - A record tagged with location code `L` is included in the response **only if** the querying client's matched location equals `L`.
   - Records with **no location code** are unrestricted and are **always included** alongside any matching location-tagged records.
   - Records tagged with other location codes (`!= L`) are strictly excluded.

---

## 3. BIND Zone `$ECS-SUBNET` Directive & `ecs-tags`

KariDNS introduces the `$ECS-SUBNET` directive for BIND zone files. It enables granular, record-level steering based on EDNS0 Client Subnet (ECS) options sent by recursive resolvers (e.g. Google Public DNS, Cloudflare, OpenDNS).

### 3.1 Configuration Syntax (`karidns.conf`)

ECS tags and trusted resolvers are configured in `karidns.conf`.

#### Global Configuration (`options {}`)

```text
options {
    port 53;
    bind-address { 127.0.0.1; };

    # 1. Enable ECS processing globally (default: no)
    ecs-enable yes;

    # 2. Trusted recursive resolvers permitted to supply ECS options (ACL)
    # Queries from untrusted resolvers will have their ECS options ignored!
    ecs-trusted-resolvers {
        127.0.0.1;
        10.0.0.0/8;
        192.168.1.53;
    };

    # 3. Global ECS Tag definitions (Mapping tag names to IPv4 / IPv6 CIDRs)
    ecs-tags {
        tag "us" {
            8.8.8.0/24;
            1.1.1.0/24;
        };
        tag "eu" {
            5.6.7.0/24;
            2001:db8:ee::/32;
        };
        tag "jp" {
            203.0.113.0/24;
        };
    };
};
```

#### Zone-Level Override (`zone {}`)

A zone block can override `ecs-tags` completely. When `ecs-tags` is declared inside a `zone {}` block, KariDNS uses **only** that zone's tag definitions. It does not merge with or fall back to the global tags for that zone.

```text
zone "cdn.example.com." {
    type master;
    file "/var/named/cdn.example.com.zone";

    # Full override: only us-east, us-west, and eu are recognized in this zone
    ecs-tags {
        tag "us-east" { 8.8.8.0/24; };
        tag "us-west" { 1.2.3.0/24; };
        tag "eu"      { 5.6.7.0/24; };
    };
};
```

### 3.2 Zone File Directive (`$ECS-SUBNET`)

The `$ECS-SUBNET` directive operates similarly to `$TTL` or `$ORIGIN`: it changes the active tag state for all subsequent records in the zone.

```zone
$TTL 300
$ORIGIN example.com.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   192.0.2.1

; ==============================================================================
; US Clients (matches tag "us")
; ==============================================================================
$ECS-SUBNET us
www     IN  A   192.0.2.1
api     IN  A   192.0.2.11

; ==============================================================================
; EU Clients (matches tag "eu")
; ==============================================================================
$ECS-SUBNET eu
www     IN  A   192.0.2.2
api     IN  A   192.0.2.22

; ==============================================================================
; Default / Unrestricted (matches ALL clients, including untagged subnets)
; ==============================================================================
$ECS-SUBNET default
www     IN  A   192.0.2.3
api     IN  A   192.0.2.33

; ==============================================================================
; Explicit "none" clears tag state back to default
; ==============================================================================
$ECS-SUBNET none
mail    IN  A   192.0.2.25
```

#### Directive Semantics:
- **`$ECS-SUBNET <tag>`**:
  All records defined after this directive are associated with `<tag>` until another `$ECS-SUBNET` directive is encountered.
- **`$ECS-SUBNET default` and `$ECS-SUBNET none`**:
  Resets the tag to `NULL` (unrestricted). Records defined under `default` or `none` are returned to all clients.
- **`$INCLUDE` Penetration**:
  If an included file modifies `$ECS-SUBNET`, the new tag persists after returning to the parent file (consistent with `$TTL` propagation).
- **`$GENERATE` Propagation**:
  Range records generated via `$GENERATE` inherit the active tag state at that point in the file.

### 3.3 Query Processing & Evaluation Logic

```text
   Client Query with EDNS Option 8 (ECS)
                     │
                     ▼
      Is ecs-enable set to "yes"?
             │               │
            Yes              No ──► Ignore ECS, serve default/none records
             ▼
   Is Resolver IP in ecs-trusted-resolvers?
             │               │
            Yes              No ──► Fail-Closed: Ignore ECS, serve default/none records
             ▼
   Extract ECS Subnet & Family (IPv4 / IPv6)
                     │
                     ▼
   Does Zone define ecs-tags?
      ├── Yes ──► Match against Zone ecs-tags ONLY
      └── No  ──► Match against Global options.ecs-tags
                     │
                     ▼
           Matched Tag Found?
             │               │
            Yes              No ──► client_ecs_tag = NULL (matches default/none only)
             ▼
   Filter Records:
   - Records with ecs_subnet_tag == matched_tag : MATCH
   - Records with ecs_subnet_tag == NULL        : MATCH (default / none)
   - Records with any other tag                 : EXCLUDE
```

#### Security & Fail-Closed Behavior:
1. **Untrusted Resolvers**: If a resolver IP is not in `ecs-trusted-resolvers`, the ECS option is discarded immediately.
2. **Missing or Non-Matching Subnet**: If a client sends no ECS, or the ECS subnet does not match any configured tag, only `default`/`none` records are returned. Tagged records are never leaked to unauthorized or unknown networks.
3. **Comprehensive Code Path Coverage**: ECS filtering is enforced consistently across all answer and authority phases:
   - Direct QNAME exact matches (`A`, `AAAA`, `TXT`, `MX`, etc.)
   - `ANY` queries
   - `CNAME` delegation and target chain resolution
   - `DNAME` synthesis (RFC 6672)
   - Wildcard synthesis (`*.example.com`)
   - Negative responses (`SOA` minimum TTL synthesis)
   - `NSEC` denial-of-existence proof records
   - Delegation `NS` and glue record synthesis

---

## 4. Verification & Diagnostics with `karicheck`

KariDNS's configuration validator, `karicheck`, includes full linting and static analysis for both `ecs-tags` and `$ECS-SUBNET`.

### 4.1 Syntax Validation Rules

Run `karicheck` on your configuration:
```sh
karicheck conf /usr/local/etc/karidns.conf
karicheck zones /usr/local/etc/karidns.conf
```

`karicheck` enforces the following constraints:
- **Undefined Tag Detection (`[ERROR]`)**:
  If a zone file contains an `$ECS-SUBNET <tag>` directive where `<tag>` is not declared in the active `ecs-tags` block, `karicheck` aborts with an error:
  ```text
  [ERROR] Zone 'example.com.': record 'www' references undefined ECS subnet tag 'apac'
  ```
- **CIDR Format Validation (`[ERROR]`)**:
  `karicheck` validates that every subnet in `ecs-tags` is valid IPv4 or IPv6 notation with a valid prefix length (`0`–`32` for IPv4, `0`–`128` for IPv6). An invalid prefix length (e.g. `8.8.8.0/35`) results in an immediate syntax error.
- **Dormant Configuration Warning (`[WARNING]`)**:
  If `ecs-tags` blocks are defined but `ecs-enable` is omitted or set to `no`, `karicheck` outputs a warning:
  ```text
  [WARNING] ecs-tags defined, but ecs-enable is not set to 'yes' in options{}
  ```

---

## 5. Testing Queries with `dag`

You can test both tinydns location and BIND `$ECS-SUBNET` configurations using the included `dag` DNS client.

### 5.1 Testing tinydns Location

Query from different source IP addresses using the `-b` (bind local IP) option:

```sh
# Query from internal IP (matches %in):
dag www.example.com A @127.0.0.1 -p 53 -b 192.168.1.100 +short

# Query from external IP (matches %ex):
dag www.example.com A @127.0.0.1 -p 53 -b 172.16.1.100 +short
```

### 5.2 Testing BIND `$ECS-SUBNET`

Use `dag`'s `+subnet=<addr[/prefix]>` option to inject EDNS Client Subnet data into the query:

```sh
# Query with US IPv4 client subnet (matches tag "us"):
dag www.example.com A @127.0.0.1 -p 53 +short +subnet=8.8.8.50
# Returns:
# 192.0.2.1   (US record)
# 192.0.2.3   (default record)

# Query with EU IPv6 client subnet (matches tag "eu"):
dag www.example.com A @127.0.0.1 -p 53 +short +subnet=2001:db8:ee:1234::1
# Returns:
# 192.0.2.2   (EU record)
# 192.0.2.3   (default record)

# Query with unknown subnet (matches only "default"):
dag www.example.com A @127.0.0.1 -p 53 +short +subnet=198.51.100.1
# Returns:
# 192.0.2.3   (default record only)

# Query without ECS option:
dag www.example.com A @127.0.0.1 -p 53 +short +nosubnet
# Returns:
# 192.0.2.3   (default record only)
```

---

## 6. Implementation Architecture & System Constraints

The implementation strictly adheres to KariDNS's core design rules:

1. **Zero Dynamic Allocation on the Hot Path (Rule 1)**:
   - `resolve_ecs_subnet_tag()` and `tinydns_resolve_client_location()` perform all IP formatting and comparisons using stack-allocated buffers (`char ip_buf[INET6_ADDRSTRLEN]`) and bitwise operations.
   - Hot-path query resolution does not invoke `malloc`, `realloc`, or `free`.
2. **Capsicum Capability Mode Sandbox (Rule 2)**:
   - All `ecs-tags`, CIDR lists, and location definitions are parsed and compiled into memory structures before privilege drop and Capsicum sandboxing (`cap_enter(2)`).
   - No filesystem, socket, or device calls are made by the backend worker process during query evaluation.
3. **Record Duplicate Deduplication Safety**:
   - `compare_records()` inspects `ecs_subnet_tag`, `tinydns_loc`, `tinydns_ttd`, and `tinydns_ttl_countdown`.
   - Records with identical domain names, types, and RDATA but different tags (e.g. US vs EU endpoints) are preserved as distinct records and are never mistakenly deduplicated or collated during zone loading or dynamic updates.
4. **Strict Mechanism Isolation**:
   - The query resolution engine strictly separates the evaluation pipelines: `tinydns_resolve_client_location()` is executed only when `current_zone->is_tinydns_format` is true, while `resolve_ecs_subnet_tag()` is executed only for zones receiving validated EDNS ECS options from trusted resolvers. The two mechanisms never interfere or cross-evaluate.

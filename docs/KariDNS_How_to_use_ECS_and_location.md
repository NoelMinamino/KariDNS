# KariDNS: Client Geolocation & Subnet Steering Guide (tinydns Location, BIND `$LOCATION`, and BIND `$ECS-SUBNET`)

This document describes how to configure and utilize client-specific record steering in KariDNS.
KariDNS provides high-performance, record-level split-horizon response steering mechanisms across both BIND and tinydns zone formats, coupled with **KariDNS Extended AXFR** for full directive preservation across primary and secondary servers.

---

## 1. Overview & Feature Comparison

KariDNS supports three steering mechanisms tailored for authoritative DNS deployment:

1. **tinydns `location` (`%`)**: Client source IPv4 steering in djbdns/tinydns format zones.
2. **BIND `$LOCATION` & `$LOCATION-TAG`**: Client source IP (direct socket IPv4/IPv6) steering in BIND format zones.
3. **BIND `$ECS-SUBNET` & `$ECS-SUBNET-TAG`**: EDNS0 Client Subnet (ECS, IPv4/IPv6, RFC 7871) steering in BIND format zones via trusted recursive resolvers.

| Feature | tinydns `location` (`%`) | BIND `$LOCATION` | BIND `$ECS-SUBNET` |
| :--- | :--- | :--- | :--- |
| **Zone Format** | tinydns data file (`file-format tinydns;`) | Standard BIND zone (`file-format bind;`) | Standard BIND zone (`file-format bind;`) |
| **Client Identifier** | Direct Client Source IP (IPv4) | Direct Client Source IP (IPv4 & IPv6) | EDNS Client Subnet (IPv4 & IPv6, RFC 7871) |
| **Granularity** | Record-level | Record-level | Record-level |
| **Tagging Syntax** | Trailing `:loc` field (e.g. `::in`) | In-band `$LOCATION <tag>` directive | In-band `$ECS-SUBNET <tag>` directive |
| **Tag Definition** | In-zone `%<loc>:<ip-prefix>` | In-zone `$LOCATION-TAG <tag> <cidrs>` or `ecs-tags` | In-zone `$ECS-SUBNET-TAG <tag> <cidrs>` or `ecs-tags` |
| **Scope of Tag Def** | Zone file only | Zone file or `karidns.conf` | Zone file or `karidns.conf` |
| **Security & ACL** | Direct socket address | Direct socket address | Evaluated only via `ecs-trusted-resolvers` |
| **Coexistence** | Distinct zone format | **Coexists** with `$ECS-SUBNET` in BIND zone | **Coexists** with `$LOCATION` in BIND zone |
| **Extended AXFR** | Preserved via TYPE 65405/65406 wrapping | Preserved via Extended AXFR | Preserved via Extended AXFR |
| **Hot Path Memory** | Zero allocation (`malloc`/`free` = 0) | Zero allocation (`malloc`/`free` = 0) | Zero allocation (`malloc`/`free` = 0) |

---

## 2. tinydns `location` (`%`) Directive

The tinydns location feature allows returning distinct resource records depending on the source IPv4 address of the querying client or resolver.

### 2.1 Zone File Syntax

In a tinydns data file (`file-format tinydns;`), location prefixes are defined with `%` lines, and records reference them using the 6th field:

```text
# Syntax: %<2-char-code>:<ipv4-prefix>
%lo:127.0.0.1/32
%in:192.168.
%ex:172.16.
%df:

# Syntax: +<fqdn>:<ip>:<ttl>:<timestamp>:<location>
+srv.example.com:10.10.1.1:300::lo
+srv.example.com:192.168.1.10:300::in
+srv.example.com:172.16.1.10:300::ex
+srv.example.com:10.10.0.1:300

# Records without location tag match ALL clients:
+def.example.com:10.99.99.1:300
```

#### Syntax Rules:
- **Location Definition**: `%<loc>:<prefix>`
  - `<loc>`: 2-character ASCII identifier (e.g. `lo`, `in`, `ex`, `df`).
  - `<prefix>`: Decimal IPv4 prefix with 1 to 4 octets separated by dots (e.g. `192.168.` = `/16`, `10.` = `/8`, `127.0.0.1/32` or `127.0.0.1` = `/32`).
  - Empty prefix `%<loc>:` (or `%df:`): Catch-all location when no other prefix matches.
- **Record Assignment**:
  - The 6th field of standard tinydns record lines (`+`, `=`, `@`, `^`, `C`, etc.) specifies the location code.
  - If the location field is omitted, the record is **unrestricted** and is served to all clients.

### 2.2 Evaluation Logic
1. **Longest Prefix Match (LPM)**: KariDNS performs a bitwise longest-prefix match against all `%` entries loaded in the zone.
2. **Filtering**: If the client matches location `L`, records tagged with `L` are returned alongside any unrestricted (untagged) records. Records with non-matching locations are excluded.

---

## 3. BIND Zone `$LOCATION` & `$LOCATION-TAG` Directives

KariDNS extends standard BIND zone files with `$LOCATION` and `$LOCATION-TAG` to steer responses based on the querying client's immediate socket IP (supporting both IPv4 and IPv6).

### 3.1 Zone File Syntax

```zone
$TTL 300
$ORIGIN example.com.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026090501 3600 600 86400 300 )
@       IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1

; Define location tags directly in zone file:
$LOCATION-TAG local 127.0.0.1/32 ::1/128
$LOCATION-TAG remote 192.0.2.0/24 2001:db8:1::/48

; Records for "local" clients:
$LOCATION local
loc-test IN A   10.1.1.1

; Records for "remote" clients:
$LOCATION remote
loc-test IN A   10.2.2.2

; Reset location filter to unrestricted (matches all clients):
$LOCATION ""
loc-test IN A   10.0.0.1
default-rec IN A 192.168.1.100
```

#### Directive Semantics:
- **`$LOCATION-TAG <tag> <cidr> [<cidr2> ...]`**:
  Declares a location tag `<tag>` mapping to one or more IPv4/IPv6 CIDR blocks.
- **`$LOCATION <tag>`**:
  Activates `<tag>` for subsequent records in the zone.
- **`$LOCATION ""` / `$LOCATION none` / `$LOCATION default`**:
  Resets the location tag state to unrestricted (`NULL`).

---

## 4. BIND Zone `$ECS-SUBNET` & `$ECS-SUBNET-TAG` Directives

The `$ECS-SUBNET` directive steers responses based on the client subnet provided in the EDNS0 Client Subnet (ECS, RFC 7871) option by recursive resolvers.

### 4.1 Configuration Syntax (`karidns.conf`)

ECS processing requires enabling `ecs-enable` and declaring authorized recursive resolvers:

```text
options {
    port 53;
    bind-address { 0.0.0.0; ::; };

    # Enable ECS processing globally
    ecs-enable yes;

    # Trusted resolvers permitted to supply ECS options
    ecs-trusted-resolvers {
        127.0.0.1;
        10.0.0.0/8;
        192.168.1.53;
    };

    # Global ECS / Location tag definitions (can also be defined in-zone):
    ecs-tags {
        tag "eu-tier" {
            198.51.100.0/24;
            2001:db8:ee::/48;
        };
        tag "us-tier" {
            203.0.113.0/24;
        };
    };
};
```

### 4.2 In-Zone Syntax

Tags can be defined in-zone via `$ECS-SUBNET-TAG` or inherited from `ecs-tags` in `karidns.conf`:

```zone
$TTL 300
$ORIGIN example.com.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026090501 3600 600 86400 300 )
@       IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1

; In-zone ECS tag definitions:
$ECS-SUBNET-TAG eu-tier 198.51.100.0/24
$ECS-SUBNET-TAG us-tier 203.0.113.0/24

$ECS-SUBNET eu-tier
ecs-test IN A   172.16.1.1

$ECS-SUBNET us-tier
ecs-test IN A   172.16.2.2

$ECS-SUBNET ""
ecs-test IN A   172.16.0.1
```

#### Directive Semantics:
- **`$ECS-SUBNET-TAG <tag> <cidr> [<cidr2> ...]`**:
  Declares an ECS tag in-zone without requiring edits to `karidns.conf`.
- **`$ECS-SUBNET <tag>`**:
  Applies `<tag>` to subsequent records.
- **`$ECS-SUBNET ""` / `$ECS-SUBNET none` / `$ECS-SUBNET default`**:
  Clears the ECS tag filter back to unrestricted.
- **Fail-Closed Security**:
  If a query arrives from a resolver not listed in `ecs-trusted-resolvers`, or if no ECS option is provided, only unrestricted (default) records are returned.

---

## 5. Coexistence of `$LOCATION` and `$ECS-SUBNET` in BIND Zones

Within BIND zone files, `$LOCATION` and `$ECS-SUBNET` can be used together to establish multi-tier steering:
- A record can be tagged with **both** a `$LOCATION` tag and an `$ECS-SUBNET` tag.
- For example, you can steer direct internal monitoring queries via `$LOCATION` while steering public internet queries via `$ECS-SUBNET`.

---

## 6. KariDNS Extended AXFR (Option 65153)

Traditional AXFR (RFC 5936) transfers plain DNS resource records and loses proprietary steering directives, leaving secondaries unable to perform location or subnet filtering.

KariDNS solves this with **Extended AXFR**:

### 6.1 Automatic Negotiation (EDNS Option 65153)
- When a KariDNS secondary requests an AXFR from a master, it attaches EDNS Option `65153` containing a version marker and domain hash.
- A KariDNS primary recognizes Option 65153 and replies with an Extended AXFR stream containing:
  - In BIND zones: tag definitions (`$LOCATION-TAG`, `$ECS-SUBNET-TAG`) and record state transitions (`$LOCATION`, `$ECS-SUBNET`).
  - In tinydns zones: location definitions (`%`) and wrapped records (TYPE `65406`) preserving location tags and countdown timestamps.
- Secondary seamlessly unwraps the transfer and populates its in-memory arena, enabling identical steering on the secondary server.

### 6.2 Standard AXFR Fallback (Plan B)
- When a standard AXFR client (such as BIND9, NSD, or `dig`) requests a transfer without Option 65153:
  - KariDNS filters out all location-tagged, ECS-tagged, and tinydns-tagged records.
  - KariDNS hides all internal CLASS `65302` directive markers.
  - The standard slave receives a clean, compliant zone containing only unrestricted (default) records.
  - This prevents confidential internal steering records and unknown meta-records from leaking to external secondary servers.

---

## 7. Diagnostics and Testing

### 7.1 Static Validation with `karicheck`
`karicheck` verifies configuration files and zone files:
```sh
karicheck conf /usr/local/etc/karidns.conf
karicheck zones /usr/local/etc/karidns.conf
```
- Warns on undefined location tags or ECS tags referenced by records.
- Verifies CIDR network address and prefix length validity.

### 7.2 Query Testing with `dag`
Test client source-IP steering:
```sh
# Query matching $LOCATION local (127.0.0.1):
dag loc-test.example.com A @127.0.0.1 -p 53 +short

# Query matching tinydns %in (using local source binding -b):
dag www.example.com A @127.0.0.1 -p 53 -b 192.168.1.100 +short
```

Test EDNS Client Subnet steering:
```sh
# Query with eu-tier subnet:
dag ecs-test.example.com A @127.0.0.1 -p 53 +short +subnet=198.51.100.10

# Query without ECS option (returns default record only):
dag ecs-test.example.com A @127.0.0.1 -p 53 +short +nosubnet
```

Test Extended AXFR:
```sh
# Request AXFR over TCP:
dag example.com AXFR @127.0.0.1 -p 53 +tcp
```

---

## 8. Architectural Guarantees

- **Zero Hot-Path Allocations (Rule 1)**: Tag resolution and prefix matching are implemented with bitwise comparisons and stack buffers; no `malloc` or `free` calls occur during query processing.
- **Capsicum Sandbox Safety (Rule 2)**: All tags and network structures are compiled prior to sandbox entry (`cap_enter(2)`).
- **Lock-Free RCU Updates**: Dynamic zone reloads (`karictl reload`) swap arena snapshots atomically, ensuring zero-downtime steering updates.

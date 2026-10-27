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
| **Tag Definition** | In-zone `%<loc>:<ip-prefix>` | In-zone `$LOCATION-TAG <tag> <cidrs>` or `location-tags` | In-zone `$ECS-SUBNET-TAG <tag> <cidrs>` or `ecs-tags` |
| **Scope of Tag Def** | Zone file only | Zone file, `zone {}` or `options {}` in `karidns.conf` | Zone file, `zone {}` or `options {}` in `karidns.conf` |
| **Security & ACL** | Direct socket address | Direct socket address | Requires `ecs-enable yes;` and a query from `ecs-trusted-resolvers` |
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
  - `<loc>`: 1- or 2-character ASCII identifier (e.g. `lo`, `in`, `ex`, `df`); only the first two characters are used.
  - `<prefix>`: Decimal IPv4 prefix with 1 to 4 octets separated by dots, as in djbdns. The prefix length is the number of octets times 8 (e.g. `192.168.` = `/16`, `10.` = `/8`, `127.0.0.1` = `/32`).
  - KariDNS extension: a `/n` suffix (`/0` to `/32`) sets the prefix length in bits, e.g. `10.0.0.0/8`, `10.16.0.0/12` or `192.168/24` (missing octets are zero). Bits beyond the prefix are cleared (`10.16.3.4/12` is `10.16.0.0/12`). Any other text after `/` or a length above 32 is a parse error. djbdns `tinydns-data` does not understand `/n`, so such a file is KariDNS-specific.
  - Empty prefix `%<loc>:` (or `%df:`): Catch-all location when no other prefix matches.
  - At most 4096 `%` lines are loaded per zone; further lines are ignored with a warning.
- **Record Assignment**:
  - The 6th field of standard tinydns record lines (`+`, `=`, `@`, `^`, `C`, etc.) specifies the location code.
  - If the location field is omitted, the record is **unrestricted** and is served to all clients.

### 2.2 Evaluation Logic
1. **Longest Prefix Match (LPM)**: KariDNS performs a bitwise longest-prefix match against all `%` entries loaded in the zone (on equal lengths, the entry defined first wins). Only IPv4 clients can match.
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
- **Tag sources and matching**: If the zone file defines any `$LOCATION-TAG`, only those definitions are used for the zone. Otherwise the `location-tags` block of the `zone {}` statement is used, and without one the `location-tags` block of `options {}`. The client address is checked against the tags in the order they are defined, and the **first** tag with a matching CIDR is the client's location (not the longest prefix).
- A client receives the records tagged with its location plus all unrestricted records.

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

    # Global ECS tag definitions (can also be defined in-zone or in zone {}):
    ecs-tags {
        tag "eu-tier" {
            198.51.100.0/24;
            2001:db8:ee::/48;
        };
        tag "us-tier" {
            203.0.113.0/24;
        };
    };

    # Global location tag definitions for $LOCATION (same syntax):
    location-tags {
        tag "local" { 127.0.0.1/32; ::1/128; };
    };
};
```

`ecs-enable` is a global option. `ecs-trusted-resolvers`, `ecs-tags` and `location-tags` can also be set in a `zone {}` block, which overrides `options {}` for that zone. Tag sources and matching follow the same rules as for `$LOCATION` (zone file first, then `zone {}`, then `options {}`; first matching tag in definition order).

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
  If `ecs-enable yes;` is not set, if a query arrives from a resolver not listed in `ecs-trusted-resolvers`, or if no ECS option is provided, only unrestricted (default) records are returned.

### 4.3 ECS Option in Responses (SCOPE PREFIX-LENGTH)

When a query carries an ECS option and `ecs-enable yes;` is set, the response carries an ECS option too (RFC 7871 §7.2.1):

- **FAMILY, SOURCE PREFIX-LENGTH and ADDRESS** are copied unchanged from the query. Resolvers discard responses in which they differ (RFC 7871 §11).
- **SCOPE PREFIX-LENGTH** tells the resolver for which network it may cache the answer:
  - If an RRset in the Answer section has `$ECS-SUBNET` variants (whether or not the client matched one of them), SCOPE is the shortest prefix around the client address for which every address gets the same tag decision. For a client inside a tag, that is the prefix of the matching CIDR, made longer where an earlier-defined CIDR lies inside it. For a client in no tag, it is the prefix that keeps clear of every defined CIDR of the same family. Overlapping definitions are therefore split into non-overlapping prefixes, as RFC 7871 §7.2.1 requires ("MUST NOT overlap prefixes"); nothing is rejected at load time.
  - SCOPE can be longer than SOURCE PREFIX-LENGTH when the client sent too few bits to decide (for example SOURCE /24 against /25 tags). RFC 7871 §7.2.1 allows this; resolvers then keep the answer for that source prefix only.
  - SCOPE is 0 when the answer does not depend on the subnet: the name has no tagged variants, the resolver is not in `ecs-trusted-resolvers`, or no tag of the client's address family exists.
  - Negative answers (NXDOMAIN, NODATA) and referrals always have SCOPE 0 (RFC 7871 §7.4). A name that exists only for some tags therefore gets a negative answer with SCOPE 0 for the other clients, which resolvers may cache for all networks. Give such names an unrestricted (default) record if clients outside the tags must not see a negative answer.
- `$LOCATION` and tinydns `%` locations use the resolver's own address, not the ECS option, and do not change SCOPE.
- Addresses in the Additional section (glue, the addresses of MX/SRV/NS targets) ignore ECS: only their untagged (`default` / `none`) records are given there, for every client subnet, and they do not change SCOPE (RFC 7871 §7.4; a resolver caches Additional data for all networks, §7.3.1). A client gets the tagged address of such a name when it asks for the name itself. Give a target name an untagged record if it must appear in the Additional section.
- The NS RRsets of the Authority section (the zone's NS after a positive answer, the NS and DS of a referral) ignore ECS in the same way (RFC 7871 §7.3.1: Authority data is not tied to a network; §7.4: SCOPE 0 on delegations). A query for the NS RRset itself is an Answer and is still steered, with SCOPE. Steering NS by location (`$LOCATION`, tinydns `%`) is not affected: it follows the resolver's own address. The SOA of negative answers keeps its `$ECS-SUBNET` tag (one SOA per client group, karidns(8) "Several SOA records").

---

## 5. Coexistence of `$LOCATION` and `$ECS-SUBNET` in BIND Zones

Within BIND zone files, `$LOCATION` and `$ECS-SUBNET` can be used together to establish multi-tier steering:
- A record can be tagged with **both** a `$LOCATION` tag and an `$ECS-SUBNET` tag. Such a record is returned only when both tags match the query.
- For example, you can steer direct internal monitoring queries via `$LOCATION` while steering public internet queries via `$ECS-SUBNET`.

---

### 5.1 TTLs of tagged and located records

The TTLs of the records of one name and type are brought to the lowest one (RFC 2181 §5.2) only among records that the same clients see: no location / tag / time stamp, or the same ones. A record with a `$LOCATION`, `$ECS-SUBNET`, tinydns location or time stamp keeps the TTL it was written with, also beside an unrestricted record of the same name and type; a client that sees both gets an RRset whose records have different TTLs (as it does from tinydns). `karicheck` warns about that case. Zone files, database zones and zones received by Extended AXFR follow the same rule.

## 6. KariDNS Extended AXFR (Option 65153)

Traditional AXFR (RFC 5936) transfers plain DNS resource records and loses proprietary steering directives, leaving secondaries unable to perform location or subnet filtering.

KariDNS solves this with **Extended AXFR**:

### 6.1 Automatic Negotiation (EDNS Option 65153)
- When a KariDNS secondary requests an AXFR from a master, it attaches EDNS Option `65153` containing a version number and an FNV-1a hash of the zone name. The primary uses the extended format only when both match. The current version is **3**. A primary answers a version 2 or version 3 request with a stream of that version (version 2: TYPE `65405` carries the location prefix length in bits and a 4-octet network; version 3 adds the SOA set, TYPE `65409`, and the primary's zone settings, TYPE `65408`); any other version (a version 1 server) falls back to a standard AXFR (Plan B). A version 3 secondary whose primary answers a standard transfer asks again with version 2 and remembers it (per zone, in memory, re-probed after 6 hours), so a secondary upgraded before its primary keeps the tags and attributes; see karidns(8).
- A KariDNS primary recognizes Option 65153 and replies with an Extended AXFR stream in which the KariDNS-specific data is carried as private-use record types in the private CLASS `65302`:
  - In BIND zones: tag definitions (`$LOCATION-TAG` as TYPE `65403`, `$ECS-SUBNET-TAG` as TYPE `65404`), record state transitions (`$LOCATION` as TYPE `65401`, `$ECS-SUBNET` as TYPE `65402`) and the zone's trusted ECS resolvers (TYPE `65407`).
  - In tinydns zones: location definitions (`%`, TYPE `65405`) and wrapped records (TYPE `65406`) preserving location tags and countdown timestamps.
- An IXFR request that carries Option 65153 is answered with a full Extended AXFR only when the zone has KariDNS-specific data (tag definitions, location definitions, tinydns data, or trusted ECS resolvers for the zone or the server; with version 3 the trusted resolvers of the configuration travel in the settings record and do not force it, and a zone with several or restricted SOA records always does). Otherwise it is answered like any IXFR (RFC 1995): a single SOA when the secondary is up to date, the differences when the primary's history covers the secondary's serial, else a full (Extended) AXFR. A secondary that receives an IXFR copies its current data and applies the differences, so changes of KariDNS-specific data always reach it by a full transfer.
- A zone with several SOA records or a restricted SOA record (a tinydns `Z` line per location, a `$LOCATION`-tagged SOA) is sent as an Extended AXFR of **version 3**: the frame (opening and closing SOA) is the reference SOA, `SOA_SET` (TYPE `65409`) announces the number of apex SOA records, and each of them is a body record in a TYPE `65406` wrapper with its attributes. A version 2 requester is refused (REFUSED), since its format cannot carry them. The secondary does not store the frame as data and serves exactly the SOA set of the primary.
- A version 3 stream also carries the settings of the primary for the zone (TYPE `65408`, text in the syntax of a `zone {}` block): `allow-transfer` (addresses and key names, never TSIG secrets), `transfer-acl-match`, `ecs-trusted-resolvers`, `additional-from-auth` and `zone-udp-bufsize`, each with the value the primary applies. The tag definitions of the configuration (`location-tags` / `ecs-tags` of the zone or `options`) that the zone's records use are sent as tag definitions (TYPE `65403` / `65404`). See karidns(8) "Secondary zones: Extended AXFR version 3 and the settings of the primary".
- Secondary seamlessly unwraps the transfer and populates its in-memory arena, enabling identical steering on the secondary server.

### 6.2 Standard AXFR Fallback (Plan B)
- When a standard AXFR client (such as BIND9, NSD, or `dig`) requests a transfer without Option 65153:
  - KariDNS sends the zone **as the requester sees it now** (the way `axfrdns` of djbdns does): the unrestricted records, plus the records whose tinydns location or `$LOCATION` tag matches the requester's address and whose tinydns time stamp is active. Records of other locations and tags are not sent, and neither are `$ECS-SUBNET`-tagged records (a transfer has no client subnet). A tinydns countdown record is sent with TTL 2.
  - The opening and closing SOA is the first SOA the requester sees (a zone can have one SOA per location or tag, all with one serial; see karidns(8) "Several SOA records"); every other SOA record is left out. A requester that sees no SOA is refused (REFUSED, AA=0, EDE 18).
  - KariDNS hides all internal CLASS `65302` directive markers, locations, tags and time stamps: the standard slave receives a clean, compliant zone.
  - This prevents the records of other locations and tags, and unknown meta-records, from leaking to external secondary servers. (Before B8t-1 only the unrestricted records were sent.)
  - A standard IXFR of a zone with such records is answered with the whole zone (RFC 1995 §4).

---

## 7. Diagnostics and Testing

### 7.1 Static Validation with `karicheck`
`karicheck` verifies configuration files and zone files:
```sh
karicheck conf /usr/local/etc/karidns/karidns.conf
karicheck zones /usr/local/etc/karidns/karidns.conf
```
- Reports an error for records that reference an undefined location tag or ECS tag.
- Verifies the CIDR syntax (address and prefix length) in `ecs-tags` and `location-tags`, and warns when `ecs-tags` are defined without `ecs-enable yes;`.
- Reports invalid tinydns location prefix lengths (`/n` above 32) and duplicate location codes.

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

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)


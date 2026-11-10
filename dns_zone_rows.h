#ifndef DNS_ZONE_ROWS_H
#define DNS_ZONE_ROWS_H

/*
 * dns_zone_rows.h - zone file -> rows of the PowerDNS 5.1 schema (beta design 8.2; the seed of the 0.6.0 ZoneImporter).  It was
 * tests/db/zone2sql.c; the row generation is a library so the importer, zone2sql and the unit tests get the rows in memory, and
 * tests/db/zone2sql.c is the command line that prints them as SQL.
 *
 * Layout, the way PowerDNS stores a zone: one `domains` row (NATIVE); `records` with lowercase owner names without
 * the trailing dot, content with names without the trailing dot, MX / SRV priority in `prio` (and not in `content`),
 * auth 1, disabled 0, rows in file order.  A zone with NSEC3 / NSEC records is written in the layout PowerDNS 5.1.4 stores
 * for a zone AXFRed with PRESIGNED=1 (verified on the build host, design 3.6): PRESIGNED (and NSEC3PARAM) metadata, no
 * NSEC3 / NSEC3PARAM / NSEC rows, RRSIGs kept, `ordername` (NSEC3 hash, or the reversed relative name for NSEC), `auth` 0
 * for NS at delegation points and for names below them, ENT rows with type NULL.  zrows_plain_signed = true keeps them
 * as ordinary rows (tests of the "stored as is" rule, design D8).
 * B8: the Extended AXFR attributes of the zone parser go into the karidns_* tables of db/karidns_ext.*.sql (design 3.6a, 3.7): $LOCATION /
 * $ECS-SUBNET tags of a record into karidns_record_tags, the tinydns time stamp / countdown flag / location code of a record into
 * karidns_record_tinydns, $LOCATION-TAG / $ECS-SUBNET-TAG definitions (kind location / ecs) and the % lines of a tinydns data file (kind
 * tinydns) into karidns_zone_tagdefs (one CIDR per row, in definition order), and X-KARIDNS-FORMAT tinydns into domainmetadata.  Rows of
 * those tables follow the record insert that owns them.  What is not carried: the SOA serial a tinydns . line takes from the data
 * file's mtime (the row stores the number the parser made; use a Z line or edit the row), and the text of the data file.
 *
 * Ordinary process code (malloc allowed): the importer, the exporter and the tests; never the server.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "dns_pdns_reader.h"

typedef struct { const char *loc, *ecs; } zrows_tag_t;                 /* karidns_record_tags of a row (NULL = none) */
typedef struct { bool has; int64_t ttd; char loc[3]; bool countdown; } zrows_td_t;     /* karidns_record_tinydns of a row */
typedef struct { const char *kind, *tag, *cidr; } zrows_def_t;          /* karidns_zone_tagdefs */

typedef struct {
    char zone[DNS_NAME_TEXT_SIZE];  /* domains.name: lowercase, no trailing dot */
    db_record_row_t *rows;          /* ids 1..n in file order; strings are owned by pool */
    size_t n;
    char **pool;
    size_t n_pool, cap_pool;
    bool signed_zone;               /* the zone has NSEC / NSEC3 / RRSIG records */
    uint8_t *auth;                  /* per row: records.auth (0/1); NULL = all 1 */
    bool presigned;                 /* PRESIGNED=1 metadata is written */
    char *nsec3param;               /* NSEC3PARAM metadata ("alg flags iterations salt") or NULL */
    zrows_tag_t *tags;              /* per row, or NULL when no record has a tag */
    zrows_td_t *td;                 /* per row, or NULL when no record has a tinydns attribute */
    zrows_def_t *defs;              /* tag definitions and tinydns location definitions, in definition order */
    size_t ndefs;
    bool tinydns;                   /* X-KARIDNS-FORMAT tinydns metadata is written */
} zrows_t;

/* Read a zone file with $INCLUDE (relative to the file's directory) and return its arena.  The zone is the owner
 * of the first SOA record (apex_override: that name instead).  Records outside it are dropped (as the server does),
 * so are records that cannot be encoded.  false: *err says why.  Free with zone_arena_destroy(). */
bool zrows_load_zone_file(const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                          size_t apex_cap, char *err, size_t errlen);

/* B8: a tinydns data file.  apex_override: the zone (NULL: the owner of the first SOA); zones: the apexes of the whole file (NULL: just this
 * one), so that a record of a child zone is left out of the parent (the data file parser's ownership rule, as the server loads it).  The
 * SOA serial of a . line is the file's mtime. */
bool zrows_load_tinydns_file(const char *path, const char *apex_override, const char *const *zones, int nzones, zone_arena_t *arena,
                             char *apex_out, size_t apex_cap, char *err, size_t errlen);
/* the apex of every SOA record of a tinydns data file (names of the zone parser's form, malloc'd; free each and the array) */
bool zrows_tinydns_apexes(const char *path, char ***names, int *n, char *err, size_t errlen);

/* M2 (the ZoneImporter): the same loaders on text the caller already holds (a file read by the caller, or standard input).  path names the
 * file (NULL = standard input: there is no directory to $INCLUDE from, so $INCLUDE is refused); the text is copied.  info (may be NULL)
 * gets what karicheck warns about and the importer reports: records dropped as outside the zone, records without a TTL, character-strings
 * longer than 255 octets, tinydns records that belong to no zone of the data file; include_refused is set when the parse failed on a
 * $INCLUDE in standard input.  A parse error is "file:line: reason". */
typedef struct {
    size_t out_of_zone;
    char first_out_of_zone[DNS_NAME_TEXT_SIZE];
    size_t no_ttl;
    char no_ttl_owner[DNS_NAME_TEXT_SIZE], no_ttl_file[512];
    size_t no_ttl_line;
    size_t long_txt;
    char long_txt_owner[DNS_NAME_TEXT_SIZE], long_txt_file[512];
    size_t long_txt_line;
    size_t tinydns_out_of_zone;
    char first_tinydns_out_of_zone[DNS_NAME_TEXT_SIZE];
    bool include_refused;
} zrows_info_t;
bool zrows_load_zone_text(const char *text, size_t len, const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                          size_t apex_cap, zrows_info_t *info, char *err, size_t errlen);
/* mtime: the SOA serial of a . line (the file's mtime; 0 = the time of the load) */
bool zrows_load_tinydns_text(const char *text, size_t len, const char *path, time_t mtime, const char *apex_override, const char *const *zones, int nzones,
                             zone_arena_t *arena, char *apex_out, size_t apex_cap, zrows_info_t *info, char *err, size_t errlen);
bool zrows_tinydns_apexes_text(const char *text, size_t len, const char *path, time_t mtime, char ***names, int *n, zrows_info_t *info, char *err,
                               size_t errlen);

/* Do two names of a database (domains.name; with or without one final dot) name the same zone?  ASCII case-insensitive, decided in C (never by an SQL
 * collation), like names_equal() of karidns-dbloader. */
bool zrows_names_equal(const char *a, const char *b);

extern bool zrows_plain_signed;
/* Converts the rows of a signed zone to the presigned layout (called by zrows_from_arena unless zrows_plain_signed). */
bool zrows_make_presigned(zrows_t *o, char *err, size_t errlen);

/* Rows from a parsed zone.  apex is the zone name as returned by zrows_load_zone_file(). */
bool zrows_from_arena(zone_arena_t *arena, const char *apex, zrows_t *out, char *err, size_t errlen);
void zrows_free(zrows_t *r);

/* ------------------------------------------------------------------------------------------------------------------------------
 * What an RDATA field is: ONE table for the row content (dns_zone_rows.c) and the zone-file writer (dns_zone_text.c).  rdata[j] of a
 * parsed record (dns_record_t) is a text field; the zone parser keeps some of them as names, some as the bytes of a character-string.
 *   ZF_NAME    a domain name the parser keeps in the canonical text form (dns_wire.h) with its escapes and expands to an absolute name
 *   ZF_EXPAND  a name the parser expands against $ORIGIN (every ZF_NAME field; the IPSECKEY / AMTRELAY gateway and the SVCB / HTTPS
 *              target are names only for gateway type 3 and a target other than "."): a name inside the zone may be written relative
 *   ZF_NODOT   PowerDNS stores the name without the trailing dot (checked with pdnsutil load-zone on 5.1.4): NS CNAME PTR DNAME, the
 *              MX and AFSDB target, the SRV target, both SOA names, both RP names and the RRSIG signer.  It keeps the dot (as the zone
 *              file has the absolute name) in NAPTR, SVCB / HTTPS, NSEC (next name), KX, LP and MINFO.
 *   ZF_STRING  the bytes of a <character-string>: written in quotes
 *   ZF_ABS     a name the zone parser keeps as typed (it expands none: SIG / RRSIG signer, NSEC next name, DSYNC target): a zone file for
 *              another server needs the absolute form, so the writer gives it the dot it lacks
 * zrows_field_flags() looks at the record for the fields whose meaning depends on another field (A6, IPSECKEY, AMTRELAY, SVCB, HTTPS).
 * zrows_blob_lead(): the number of leading fields before a base64 / hex blob that may be split into several tokens (-1: none) - the same
 * table as the zone parser's trailing_blob_lead_fields().
 * ------------------------------------------------------------------------------------------------------------------------------ */
#define ZF_NAME   0x01u
#define ZF_EXPAND 0x02u
#define ZF_NODOT  0x04u
#define ZF_STRING 0x08u
#define ZF_ABS    0x10u
unsigned zrows_field_flags(const dns_record_t *r, int j);
int zrows_blob_lead(uint16_t type);

#endif

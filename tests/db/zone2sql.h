#ifndef ZONE2SQL_H
#define ZONE2SQL_H

/*
 * zone2sql - test importer: zone file -> rows of the PowerDNS 5.1 schema (beta design 8.2).  The row generation is a
 * library (this header) so unit tests get the rows in memory; tests/db/zone2sql.c adds the command line that prints
 * SQL for both dialects.  The seed of the 0.6.1 ZoneImporter.
 *
 * Layout, the way PowerDNS stores a zone: one `domains` row (NATIVE); `records` with lowercase owner names without
 * the trailing dot, content with names without the trailing dot, MX / SRV priority in `prio` (and not in `content`),
 * auth 1, disabled 0, rows in file order.  A zone with NSEC3 / NSEC records is written in the layout PowerDNS 5.1.4 stores
 * for a zone AXFRed with PRESIGNED=1 (verified on the build host, design 3.6): PRESIGNED (and NSEC3PARAM) metadata, no
 * NSEC3 / NSEC3PARAM / NSEC rows, RRSIGs kept, `ordername` (NSEC3 hash, or the reversed relative name for NSEC), `auth` 0
 * for NS at delegation points and for names below them, ENT rows with type NULL.  z2s_plain_signed = true keeps them
 * as ordinary rows (tests of the "stored as is" rule, design D8).
 * B8: the Extended AXFR attributes of the zone parser go into the karidns_* tables of db/karidns_ext.*.sql (design 3.6a, 3.7): $LOCATION /
 * $ECS-SUBNET tags of a record into karidns_record_tags, the tinydns time stamp / countdown flag / location code of a record into
 * karidns_record_tinydns, $LOCATION-TAG / $ECS-SUBNET-TAG definitions (kind location / ecs) and the % lines of a tinydns data file (kind
 * tinydns) into karidns_zone_tagdefs (one CIDR per row, in definition order), and X-KARIDNS-FORMAT tinydns into domainmetadata.  Rows of
 * those tables follow the record insert that owns them (last_insert_rowid() / lastval()), so the SQL needs the ext tables, which
 * the caller creates first (db/karidns_ext.sqlite3.sql).  What is not carried: the SOA serial a tinydns . line takes from the data
 * file's mtime (the row stores the number the parser made; use a Z line or edit the row), and the text of the data file.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include "../../dns_pdns_reader.h"

typedef struct { const char *loc, *ecs; } z2s_tag_t;                 /* karidns_record_tags of a row (NULL = none) */
typedef struct { bool has; int64_t ttd; char loc[3]; bool countdown; } z2s_td_t;     /* karidns_record_tinydns of a row */
typedef struct { const char *kind, *tag, *cidr; } z2s_def_t;          /* karidns_zone_tagdefs */

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
    z2s_tag_t *tags;                /* per row, or NULL when no record has a tag */
    z2s_td_t *td;                   /* per row, or NULL when no record has a tinydns attribute */
    z2s_def_t *defs;                /* tag definitions and tinydns location definitions, in definition order */
    size_t ndefs;
    bool tinydns;                   /* X-KARIDNS-FORMAT tinydns metadata is written */
} z2s_rows_t;

/* Read a zone file with $INCLUDE (relative to the file's directory) and return its arena.  The zone is the owner
 * of the first SOA record (apex_override: that name instead).  Records outside it are dropped (as the server does),
 * so are records that cannot be encoded.  false: *err says why.  Free with zone_arena_destroy(). */
bool z2s_load_zone_file(const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                        size_t apex_cap, char *err, size_t errlen);

/* B8: a tinydns data file.  apex_override: the zone (NULL: the owner of the first SOA); zones: the apexes of the whole file (NULL: just this
 * one), so that a record of a child zone is left out of the parent (the data file parser's ownership rule, as the server loads it).  The
 * SOA serial of a . line is the file's mtime. */
bool z2s_load_tinydns_file(const char *path, const char *apex_override, const char *const *zones, int nzones, zone_arena_t *arena,
                           char *apex_out, size_t apex_cap, char *err, size_t errlen);
/* the apex of every SOA record of a tinydns data file (names of the zone parser's form, malloc'd; free each and the array) */
bool z2s_tinydns_apexes(const char *path, char ***names, int *n, char *err, size_t errlen);

extern bool z2s_plain_signed;
/* Converts the rows of a signed zone to the presigned layout (called by z2s_rows_from_arena unless z2s_plain_signed). */
bool z2s_make_presigned(z2s_rows_t *o, char *err, size_t errlen);

/* Rows from a parsed zone.  apex is the zone name as returned by z2s_load_zone_file(). */
bool z2s_rows_from_arena(zone_arena_t *arena, const char *apex, z2s_rows_t *out, char *err, size_t errlen);
void z2s_rows_free(z2s_rows_t *r);
/* B8: the extension rows (tags, tinydns attributes, tag definitions) and the X-KARIDNS-FORMAT metadata of r into a reader zone, the way the
 * loader hands them over (row ids are 1..n in file order, as the import gives them).  Call before pdns_zone_finish(); 0, or -1 (z->failed). */
int z2s_feed_ext(const z2s_rows_t *r, pdns_zone_t *z);

typedef enum { Z2S_SQLITE3, Z2S_PGSQL } z2s_dialect_t;
void z2s_print_sql(FILE *fp, z2s_dialect_t d, const z2s_rows_t *r);

#endif

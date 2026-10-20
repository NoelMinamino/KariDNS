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
 * TODO(B8): tags / tinydns into the karidns_* tables.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include "../../dns_pdns_reader.h"

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
} z2s_rows_t;

/* Read a zone file with $INCLUDE (relative to the file's directory) and return its arena.  The zone is the owner
 * of the first SOA record (apex_override: that name instead).  Records outside it are dropped (as the server does),
 * so are records that cannot be encoded.  false: *err says why.  Free with zone_arena_destroy(). */
bool z2s_load_zone_file(const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                        size_t apex_cap, char *err, size_t errlen);

extern bool z2s_plain_signed;
/* Converts the rows of a signed zone to the presigned layout (called by z2s_rows_from_arena unless z2s_plain_signed). */
bool z2s_make_presigned(z2s_rows_t *o, char *err, size_t errlen);

/* Rows from a parsed zone.  apex is the zone name as returned by z2s_load_zone_file(). */
bool z2s_rows_from_arena(zone_arena_t *arena, const char *apex, z2s_rows_t *out, char *err, size_t errlen);
void z2s_rows_free(z2s_rows_t *r);

typedef enum { Z2S_SQLITE3, Z2S_PGSQL } z2s_dialect_t;
void z2s_print_sql(FILE *fp, z2s_dialect_t d, const z2s_rows_t *r);

#endif

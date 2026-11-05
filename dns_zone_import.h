#ifndef DNS_ZONE_IMPORT_H
#define DNS_ZONE_IMPORT_H

/*
 * dns_zone_import.h - the ZoneImporter of 0.6.0: a zone file (or a tinydns data file) into a PowerDNS 5.1 database, in one transaction.
 * The command line tool `karidns-zone import` (M3) is a thin shell over this.  Ordinary process code (malloc allowed); the server does not
 * link it.  See planing_0.6.x_zone_import_export.md, sections 5 and 6, for the decisions this implements.
 *
 * What one import does
 *   1. reads the text (a file, "-" = standard input, or text the caller holds) and parses it with the server's parser through
 *      dns_zone_rows.c (the rows: lowercase owners without the dot, MX / SRV priority in prio, signed zones in the PowerDNS PRESIGNED layout,
 *      tags and tinydns attributes for the karidns_* tables);
 *   2. runs the zone checks of `karicheck zone` (dns_zone_lint.c) on it: an error fails the import and nothing is written; a warning is
 *      printed and the import goes on, unless strict (then a warning fails it);
 *   3. in ONE transaction (dns_db_driver.h, open_write): locks the zone against a concurrent importer, finds it or creates it (a new zone is
 *      NATIVE unless a type is given; the type of an existing zone is never changed), applies the serial rule, deletes and inserts rows,
 *      puts the zone in a view, adds a reload request, READS THE ZONE BACK in the same transaction through the loader's path (dns_zone_export.c
 *      zx_read_zone(): dns_pdns_reader.c, the checks of `karicheck db`, and the size limits of the server) and commits only when the loader
 *      would load what was written (a merge that put a CNAME beside other data, an ALIAS beside an A record, a zone over max-records: refused,
 *      rolled back).  A dry run does the same.  Any error rolls back: nothing is written.
 *
 * Modes
 *   ZI_REPLACE (default)  the records of the zone are replaced by the file's; the metadata the importer owns (PRESIGNED, NSEC3PARAM,
 *                         X-KARIDNS-FORMAT) and the zone's tag definitions are replaced too; every other domainmetadata row is kept.
 *   ZI_MERGE              RRset merge: every (owner, type) of the file replaces that RRset of the database; the other RRsets are kept.  The
 *                         owned metadata the file declares replaces the database's (what the file does not declare is kept); the tag
 *                         definitions the file makes replace those of the same kind and tag.
 *   types                 limits either mode to records of these types (both the rows deleted and the rows inserted); metadata and tag
 *                         definitions are then not touched.  The signer of a later milestone uses this.
 *   dry_run               everything but the commit (the transaction is rolled back) and the same report.
 * The report (zi_report_fn) names every RRset the import adds ('+'), replaces with other data ('~') or deletes ('-'), in owner, type order.
 *
 * Serial (RFC 1982): for an existing zone whose SOA is written, the new SOA serial must be greater than the one in the database (the serial
 * the zone list shows: the enabled SOA at the apex), else the import fails (ZI_SERIAL_GROW); ZI_SERIAL_INCREMENT writes database serial + 1;
 * ZI_SERIAL_KEEP writes the file's serial as it is (a restore).  A new zone takes the file's serial.
 *
 * Messages go through dns_diag (zmsg_t NULL) with the codes of dns_diag_codes.h (db.import.*, and zone.* / io.* from the checks and the
 * input), or to the zmsg_t of the options.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "dns_db_driver.h"
#include "dns_zone_lint.h"
#include "dns_zone_msg.h"

typedef enum { ZI_REPLACE = 0, ZI_MERGE } zi_mode_t;
typedef enum { ZI_SERIAL_GROW = 0, ZI_SERIAL_INCREMENT, ZI_SERIAL_KEEP } zi_serial_t;

/* what: '+' the RRset is new, '-' it is deleted, '~' it is replaced with other data.  type "ENT" is an empty non-terminal row. */
typedef void (*zi_report_fn)(void *ud, char what, const char *owner, const char *type);

typedef struct {
    const db_driver_t *drv;             /* needs open_write (the SQLite3 and PostgreSQL drivers have it) */
    db_source_t src;                    /* the same fields as for the loader; busy_timeout_ms is how long a second importer waits for the zone */
    zi_mode_t mode;
    zi_serial_t serial;
    const char *const *types;           /* record types that limit the import (ASCII case-insensitive), ntypes of them; NULL / 0: no limit */
    size_t ntypes;
    bool dry_run;
    bool strict;                        /* a warning of the zone checks fails the import */
    bool reload;                        /* also add a row to karidns_reload_requests (PostgreSQL); a warning when the table is missing */
    const char *view;                   /* NULL, or the view (karidns_domain_views) the zone is put in */
    const char *zone_type;              /* domains.type of a NEW zone: NATIVE (NULL), MASTER, SLAVE, PRODUCER or CONSUMER */
    const char *const *file_zones;      /* names of the zones the server configuration serves from files (D-PRIO); only for the warning */
    size_t nfile_zones;
    /* What the server applies to a database zone of the view (the options of karidns.conf: zone_vopts_effective() / zone_limits_effective() of
     * the view, the tag definitions of options { }); all zero = the server's defaults (no limit, every check keeps its default severity).  The
     * checks run on the file and, with the limits, on the zone read back from the database before the commit. */
    const uint8_t *chk;                 /* the check-* severities, ZC_N values of CHK_* (zone_veff_t.chk); NULL: every check keeps its default */
    uint8_t chk_names;                  /* check-names of a primary zone (zone_veff_t.chk[ZC_NAMES_PRIMARY]) */
    const ecs_tag_def_t *ecs_tags;      /* options { ecs-tags } / { location-tags }: used when the zone defines none of its own */
    int n_ecs_tags;
    const ecs_tag_def_t *loc_tags;
    int n_loc_tags;
    zone_limits_t limits;               /* max-records, max-records-per-type, max-types-per-name, max-zone-ttl; 0 = no limit */
    pdns_opts_t reader;                 /* default-ttl, max-zone-records and max-zone-bytes of options { database { } } for the read-back; zero = the loader's defaults */
    zi_report_fn report;                /* NULL: no report */
    void *report_ud;
    zmsg_t msg;                         /* where the messages go; zero: dns_diag */
} zi_opts_t;

/* The text to import: text (len bytes; copied, may not contain NUL) when set, else the file path ("-" = standard input, at most 64 MiB).
 * path also names the text in messages.  Standard input and memory text have no directory: $INCLUDE is refused. */
typedef struct {
    const char *path;
    const char *text;
    size_t len;
    time_t mtime;                       /* tinydns: the SOA serial of a . line (0: now); a file's own mtime is used */
} zi_input_t;

typedef struct {
    char zone[DNS_NAME_TEXT_SIZE];      /* domains.name: lowercase, no final dot */
    int64_t domain_id;
    bool created;                       /* the zone did not exist */
    bool committed;
    bool dry_run;
    size_t rrsets_added, rrsets_replaced, rrsets_deleted;
    size_t records_inserted, records_deleted;
    bool has_old_serial;                /* the database had an SOA */
    uint32_t old_serial, new_serial;    /* new_serial: the SOA written (0 when none) */
    bool wrote_soa;
    size_t warnings;                    /* of the zone checks */
} zi_result_t;

typedef enum { ZI_OK = 0, ZI_FAIL = 1, ZI_BUSY = 2 } zi_status_t;      /* ZI_BUSY: another importer holds the zone; try again */

typedef struct zi_s zi_t;

/* Validate the options, open the database for writing and check its schema.  NULL (a message was given) on failure.  Pointers in o (view,
 * zone_type, file_zones, src) must stay valid until zi_close(). */
zi_t *zi_open(const zi_opts_t *o);
void zi_close(zi_t *z);

/* One zone from a BIND zone file.  zone: its name (NULL: the owner of the first SOA).  res may be NULL.  ZI_OK, ZI_FAIL, ZI_BUSY. */
int zi_import_zone(zi_t *z, const zi_input_t *in, const char *zone, zi_result_t *res);

/* The zones of a tinydns data file, each in a transaction of its own: zone, or every zone with an SOA (. or Z line) when zone is NULL (the
 * "--all" case).  A zone that fails does not stop the others.  fn (may be NULL) is called once per zone with its result and status.  The
 * return value is ZI_OK when every zone was imported, else the highest status of the failed ones. */
typedef void (*zi_result_fn)(void *ud, const zi_result_t *res, int status);
int zi_import_tinydns(zi_t *z, const zi_input_t *in, const char *zone, zi_result_fn fn, void *ud);

#endif

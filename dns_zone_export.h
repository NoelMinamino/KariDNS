#ifndef DNS_ZONE_EXPORT_H
#define DNS_ZONE_EXPORT_H

/*
 * dns_zone_export.h - the ZoneExporter of 0.6.0: a zone of a PowerDNS 5.1 database as zone-file text.  The command line tool
 * `karidns-zone export` (M3) is a thin shell over this.  Ordinary process code (malloc allowed); the server does not link it.
 *
 * The zone is read the way karidns-dbloader reads it: the driver's read functions in one snapshot, and the rows go through the PowerDNS
 * reader (dns_pdns_reader.c) - every row checked, a presigned zone with the NSEC3PARAM / NSEC3 / NSEC records dns_presigned.c rebuilds, a
 * zone with cryptokeys but without PRESIGNED refused.  What is exported is therefore what the server serves.  The text is written by
 * dns_zone_text.c (canonical order, verified by parsing it again): BIND format, or tinydns format for a zone with X-KARIDNS-FORMAT tinydns.
 * Only primary zones (NATIVE, MASTER) have records the server serves; a SLAVE / CONSUMER / PRODUCER zone is refused.
 *
 * Messages go through dns_diag (zmsg_t zero) with the codes db.export.* or to the zmsg_t.
 */

#include <stdbool.h>
#include "dns_db_driver.h"
#include "dns_zone_msg.h"
#include "dns_zone_text.h"

typedef struct zx_s zx_t;

/* Open the database read only and check its schema.  NULL (a message was given) on failure.  msg may be NULL (dns_diag). */
zx_t *zx_open(const db_driver_t *drv, const db_source_t *src, const zmsg_t *msg);
void zx_close(zx_t *x);
/* The options of the loader's reader for the zones read from now on (default-ttl, max-zone-records, max-zone-bytes of options { database { } }); the default is all zero (the loader's own defaults). */
void zx_set_reader_opts(zx_t *x, const pdns_opts_t *o);

/* The names (domains.name) of the primary zones of the database, sorted by name; with view, only the zones of that view (a zone without a row
 * in karidns_domain_views is in every view; the view name is compared without case).  fn returns non-zero to stop.  0, or -1 (a message was given). */
typedef int (*zx_zone_fn)(void *ud, const char *name);
int zx_list_zones(zx_t *x, const char *view, zx_zone_fn fn, void *ud);

/* One zone to sink, in the format fmt (NULL: automatic, verified).  zone: the name with or without the final dot, any case.  With view, a zone
 * that is not in that view is "not found".  0, or -1 (a message was given; nothing was handed to the sink when the verified write failed). */
int zx_export_zone(zx_t *x, const char *zone, const char *view, const dzt_opts_t *fmt, dzt_sink_t sink, void *ud);
/* The same with ZX_PLAIN_* (0: the zone as the server serves it).  ZX_PLAIN_CHAIN also skips the check that a zone with cryptokeys is PRESIGNED (the metadata is not read). */
int zx_export_zone_ex(zx_t *x, const char *zone, const char *view, const dzt_opts_t *fmt, dzt_sink_t sink, void *ud, unsigned plain);

/* One zone of the database through the loader's reader: the rows of the zone id called name (domains.name) are read with scan_records / scan_metadata / scan_ext on c, inside an open snapshot or write transaction (the importer
 * reads back what it wrote before it commits), added to a pdns_zone_t and finished (every row checked, a presigned zone rebuilt, the checks of the zone).  has_keys (may be NULL) is set to whether the zone has a row in
 * cryptokeys.  opts may be NULL (all zero).  ZX_READ_OK: *out is the finished zone.  ZX_READ_ZONE: the reader refused the zone, *out is the failed zone and out->error says why.  ZX_READ_DB: a read failed (the driver's
 * errmsg), ZX_READ_OOM: out of memory; *out is NULL.  Free *out with pdns_zone_free(). */
enum { ZX_READ_OK = 0, ZX_READ_ZONE, ZX_READ_DB, ZX_READ_OOM };
/* The same with the DNSSEC records a signer owns left out, so that the zone is read as the plain zone it holds (0.6.0 item C): ZX_PLAIN_DNSSEC leaves out the rows of
 * RRSIG, NSEC, NSEC3, NSEC3PARAM and DNSKEY and the metadata PRESIGNED and NSEC3PARAM (no chain to rebuild or check); ZX_PLAIN_CDS also CDS and CDNSKEY. */
#define ZX_PLAIN_DNSSEC 1u
#define ZX_PLAIN_CDS 2u
/* ZX_PLAIN_CHAIN (alone): the zone as the input of dnssec-signzone (karidns-zone export --signer): the NSEC, NSEC3 and NSEC3PARAM rows, the RRSIG rows over them and the metadata PRESIGNED and NSEC3PARAM are left out, so there is no
 * chain to rebuild or check and a zone that someone changed after it was signed can be read (a new name has no RRSIG(NSEC3) yet; the reader refuses such a zone).  The other RRSIG rows and the DNSKEY, CDS and CDNSKEY rows stay, so
 * that dnssec-signzone -i keeps the signatures that are still good; the signer makes the chain again. */
#define ZX_PLAIN_CHAIN 4u
int zx_read_zone_ex(const db_driver_t *d, db_conn_t *c, bool has_ext, const char *name, int64_t id, const pdns_opts_t *opts, unsigned plain, pdns_zone_t **out,
                    bool *has_keys);

#endif

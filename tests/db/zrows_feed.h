#ifndef ZROWS_FEED_H
#define ZROWS_FEED_H

/* tests only: the rows of dns_zone_rows.c into a reader zone, the way the loader hands them over.  Links with dns_pdns_reader.c. */
#include "../../dns_zone_rows.h"

/* B8: the extension rows (tags, tinydns attributes, tag definitions) and the X-KARIDNS-FORMAT metadata of r into a reader zone, the way the
 * loader hands them over (row ids are 1..n in file order, as the import gives them).  Call before pdns_zone_finish(); 0, or -1 (z->failed). */
static inline int zrows_feed_ext(const zrows_t *r, pdns_zone_t *z) {
    if (r->tinydns) {
        db_meta_row_t m = { 1, "X-KARIDNS-FORMAT", "tinydns" };
        if (pdns_zone_add_meta(z, &m) != 0) return -1;
    }
    for (size_t i = 0; i < r->n; i++) {
        if (r->tags && (r->tags[i].loc || r->tags[i].ecs)) {
            db_tag_row_t t = { r->rows[i].id, r->tags[i].loc, r->tags[i].ecs };
            if (pdns_zone_add_tags(z, &t) != 0) return -1;
        }
        if (r->td && r->td[i].has) {
            db_tinydns_row_t t = { r->rows[i].id, false, r->td[i].ttd, r->td[i].loc[0] ? r->td[i].loc : NULL, r->td[i].countdown };
            if (pdns_zone_add_tinydns(z, &t) != 0) return -1;
        }
    }
    for (size_t i = 0; i < r->ndefs; i++) {
        db_tagdef_row_t d = { r->defs[i].kind, r->defs[i].tag, r->defs[i].cidr };
        if (pdns_zone_add_tagdef(z, &d) != 0) return -1;
    }
    return 0;
}

#endif

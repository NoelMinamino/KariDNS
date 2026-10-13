#ifndef TEST_IMAGE_HELPER_H
#define TEST_IMAGE_HELPER_H

/*
 * S5 B-1: the query engine and the response cache read the zone image (dns_zone_image.h), not the builder
 * (zone_arena_t.records[]). A test that builds an arena by hand freezes it once the builder is indexed, so the
 * engine has an image to read; the arena stays the handle of the published version (zone_arena_destroy() frees the
 * image). Include after dns_zone_parser.h and dns_zone_image.h.
 */

#include <stdlib.h>
#include <string.h>
#include "../dns_zone_parser.h"
#include "../dns_zone_image.h"

/* The apex the image is frozen with: the owner of the first SOA, else NULL. */
static inline const char *test_apex_of(const zone_arena_t *a) {
    for (size_t i = 0; i < a->count; i++)
        if (a->records[i].type_code == 6 && a->records[i].name) return a->records[i].name;
    return NULL;
}

/* (Re)build the arena's image from its current records and index. 0 = ok, -1 = freeze failed. */
static inline int test_freeze(zone_arena_t *a) {
    free(a->image);
    a->image = zone_image_freeze(a, test_apex_of(a));
    return a->image ? 0 : -1;
}

/* build_zone_index() followed by the freeze: what the loaders do before they publish a zone. */
static inline int test_build_index(zone_arena_t *a, bool harmonize_ttls) {
    int rc = build_zone_index(a, harmonize_ttls);
    if (rc != 0) return rc;
    return test_freeze(a);
}

/* The image RR (index) of builder record `rec` of arena `a`: the RRs of one owner are contiguous in the image and
 * keep the builder's order, so it is the first RR of the owner plus the number of earlier records of that owner. */
static inline uint32_t test_rr_of(const zone_arena_t *a, const dns_record_t *rec) {
    if (!a->image || !rec || rec < a->records || rec >= a->records + a->count) return ZONE_IMAGE_NONE;
    uint32_t id = zone_image_find_name(a->image, rec->name);
    if (id == ZONE_IMAGE_NONE) return ZONE_IMAGE_NONE;
    uint32_t before = 0;
    for (const dns_record_t *r = a->records; r < rec; r++)
        if (r->name && domain_names_match_ci(r->name, rec->name)) before++;
    return zone_image_name_first_rr(a->image, id) + before;
}

/* The builder record behind an image RR (the inverse of test_rr_of()); NULL for ZONE_IMAGE_NONE. */
static inline const dns_record_t *test_rec_of(const zone_arena_t *a, uint32_t rr) {
    if (!a->image || rr == ZONE_IMAGE_NONE) return NULL;
    uint32_t id = zone_image_rr_name(a->image, rr);
    uint32_t want = rr - zone_image_name_first_rr(a->image, id);
    const char *text = zone_image_name_text(a->image, id);
    uint32_t seen = 0;
    for (size_t i = 0; i < a->count; i++) {
        if (a->records[i].name && domain_names_match_ci(a->records[i].name, text)) {
            if (seen++ == want) return &a->records[i];
        }
    }
    return NULL;
}

/* The image NSEC3 chain with the parameters of the NSEC3 / NSEC3PARAM record `param` (what the engine took from the
 * record before it read the image), ZONE_IMAGE_NONE when the zone has none. The image keeps the builder's chain order. */
static inline uint32_t test_chain_of(const zone_arena_t *a, const dns_record_t *param) {
    const nsec3_chain_t *c = param ? zone_find_nsec3_chain(a, param) : NULL;
    return c ? (uint32_t)(c - a->nsec3_chains) : ZONE_IMAGE_NONE;
}

/* A one-RR image of a copy of `rec`: the engine functions that took a hand-built dns_record_t take an RR of an image
 * now. A missing owner becomes "t.test.", a missing class IN, a missing type/RDATA the A record 192.0.2.1. The record
 * must be one serialize_dns_record() can write (the image never holds another). Free the image with free(); the RR
 * is index 0. NULL if the record cannot be frozen. */
static inline zone_image_t *test_image_of_record(const dns_record_t *rec) {
    zone_arena_t a;
    zone_arena_init(&a);
    a.records = calloc(1, sizeof(dns_record_t));
    if (!a.records) return NULL;
    a.records_cap = 1;
    a.records[0] = *rec;
    dns_record_t *r = &a.records[0];
    if (!r->name) r->name = (char *)"t.test.";
    if (!r->class_val) r->class_val = 1;
    if (r->type_code == 0 && r->rdata_count == 0) {
        static const char *a_rdata[1] = { "192.0.2.1" };
        r->type_code = 1;
        r->rdata = (char **)a_rdata;
        r->rdata_count = 1;
    }
    a.count = 1;
    zone_image_t *img = NULL;
    if (build_zone_index(&a, false) == 0) img = zone_image_freeze(&a, NULL);
    zone_arena_destroy(&a);
    return img;
}

#endif

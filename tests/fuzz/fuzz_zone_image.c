/*
 * fuzz_zone_image.c - S5 Phase B-0: zone text -> builder (parse + index) -> zone image -> serialize every RR both
 * ways (serialize_dns_record() and image_serialize_rr()) -> abort() on any difference; also the decoding
 * accessors (memory safety) and the thaw / freeze round trip.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>

#include "../../dns_zone_parser.h"
#include "../../dns_zone_image.h"

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
#include <stdarg.h>
#include <stdio.h>
void syslog(int priority, const char *format, ...) {
    (void)priority;
    if (getenv("KARI_FUZZ_VERBOSE")) { va_list ap; va_start(ap, format); vfprintf(stderr, format, ap); fputc(10, stderr); va_end(ap); }
}

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

static const char *g_zones[] = { "fuzz.local.", "sub.fuzz.local.", "other.test.", "a\\.b.fuzz.local." };

static void drop_cb(const dns_record_t *rec, void *ud) { (void)rec; (void)ud; }

static uint8_t g_ra[65536], g_rb[65536];
static compress_ctx_t g_ca, g_cb;

#include <stdio.h>
static void fail_at(int line) {
    fprintf(stderr, "fuzz_zone_image: mismatch at line %d\n", line);
    abort();
}
#define fail() fail_at(__LINE__)

/* one RR through both writers at message size `max` (a prime context when `primed`): status, bytes, table */
static void compare_one(const zone_image_t *img, const dns_record_t *rec, uint32_t k, size_t max, bool use_ctx,
                        const char *owner, uint32_t ovr_ttl, const dns_record_t *prime, uint32_t prime_k) {
    compress_ctx_t *ca = use_ctx ? &g_ca : NULL, *cb = use_ctx ? &g_cb : NULL;
    uint16_t oa = 12, ob = 12;
    if (use_ctx) {
        compress_ctx_init(&g_ca);
        compress_ctx_init(&g_cb);
        if (prime) {
            int x = serialize_dns_record(g_ra, 65535, &oa, prime, ca, NULL, 0xFFFFFFFFu);
            int y = image_serialize_rr(img, prime_k, g_rb, 65535, &ob, cb, NULL, zone_image_rr_ttl(img, prime_k));
            if (x != y) fail();
            if (x != 0) return; /* the prime does not fit: the context is in an unspecified state */
            if (oa != ob) fail();
        }
    }
    uint16_t sa = oa, sb = ob;
    uint32_t ttl = zone_image_rr_ttl(img, k);
    if (ovr_ttl != 0xFFFFFFFFu && ovr_ttl < ttl) ttl = ovr_ttl;
    int x = serialize_dns_record(g_ra, max, &oa, rec, ca, owner, ovr_ttl);
    int y = image_serialize_rr(img, k, g_rb, max, &ob, cb, owner, ttl);
    if (x != y) fail();
    if (x == 0) {
        if (oa != ob || memcmp(g_ra + sa, g_rb + sb, (size_t)(oa - sa)) != 0) fail();
        if (use_ctx && memcmp(g_ca.table, g_cb.table, sizeof(g_ca.table)) != 0) fail();
    }
}

static void exercise_accessors(const zone_image_t *img) {
    char b1[DNS_NAME_TEXT_SIZE], b2[DNS_NAME_TEXT_SIZE];
    volatile uint32_t sink = 0;
    for (uint32_t k = 0; k < img->n_rrs; k++) {
        zone_image_soa_t n;
        uint16_t u = 0, v = 0, w = 0;
        zone_image_nsec3_t n3;
        if (zone_image_rr_target(img, k, b1, sizeof(b1)) == 0) sink += (uint32_t)b1[0];
        if (zone_image_soa(img, k, b1, sizeof(b1), b2, sizeof(b2), &n) == 0) sink += n.serial;
        if (zone_image_mx_pref(img, k, &u) == 0) sink += u;
        if (zone_image_srv(img, k, &u, &v, &w) == 0) sink += u + v + w;
        if (zone_image_rrsig_covered(img, k, &u) == 0) sink += u;
        if (zone_image_nsec3(img, k, &n3) == 0) sink += n3.salt_len + n3.next_len;
        for (unsigned t = 0; t < 70; t++) if (zone_image_rr_bitmap_has(img, k, (uint16_t)(t * 3))) sink++;
        (void)zone_image_rr_ext(img, k);
    }
    for (uint32_t i = 0; i < img->n_nsec; i++) sink += zone_image_nsec_rr(img, i);
    for (uint32_t c = 0; c < img->n_n3chains; c++) {
        const zone_image_n3chain_t *ch = zone_image_n3chain(img, c);
        for (uint32_t e = 0; e < ch->count; e++) {
            size_t hl;
            const char *h = zone_image_n3chain_hash(img, c, e, &hl);
            sink += (uint32_t)zone_image_n3chain_lower_bound(img, c, h, hl);
        }
    }
    for (uint32_t i = 0; i < img->n_canon; i++) {
        const char *t = zone_image_name_text(img, zone_image_canon_name(img, i));
        if (zone_image_find_name(img, t) != zone_image_canon_name(img, i)) fail();
        bool exact = false;
        if (zone_image_canon_floor(img, t, &exact) != i || !exact) fail();
        sink += zone_image_nsec_floor(img, t);
    }
    (void)sink;
}

static void check_image(zone_arena_t *a, const char *apex) {
    zone_image_t *img = zone_image_freeze(a, apex);
    if (!img) fail(); /* every record serializes (drop_unencodable ran) and the builder is indexed */
    if (img->n_rrs > 0) {
        /* builder record -> image RR: RRs of one owner are contiguous in file order */
        uint32_t *used = calloc(img->n_names ? img->n_names : 1, sizeof(uint32_t));
        uint32_t *map = malloc((a->count ? a->count : 1) * sizeof(uint32_t));
        if (!used || !map) fail();
        for (size_t i = 0; i < a->count; i++) {
            map[i] = ZONE_IMAGE_NONE;
            if (!a->records[i].name) continue;
            uint32_t id = zone_image_find_name(img, a->records[i].name);
            if (id == ZONE_IMAGE_NONE) fail();
            map[i] = zone_image_name_first_rr(img, id) + used[id]++;
            if (used[id] > zone_image_name_rr_count(img, id)) fail();
        }
        size_t prev = (size_t)-1;
        unsigned boundary = 0;
        for (size_t i = 0; i < a->count; i++) {
            if (map[i] == ZONE_IMAGE_NONE) continue;
            const dns_record_t *rec = &a->records[i];
            compare_one(img, rec, map[i], 65535, true, NULL, 0xFFFFFFFFu, NULL, 0);
            compare_one(img, rec, map[i], 512, true, NULL, 0xFFFFFFFFu, NULL, 0);
            compare_one(img, rec, map[i], 65535, false, NULL, 0xFFFFFFFFu, NULL, 0);
            compare_one(img, rec, map[i], 1232, true, "Qn.Wild.Fuzz.Test.", 120, NULL, 0);
            if (prev != (size_t)-1) compare_one(img, rec, map[i], 65535, true, NULL, 0xFFFFFFFFu, &a->records[prev], map[prev]);
            if (boundary < 200) {
                /* every message size around the RR (the fits / does-not-fit decision), plain and behind a prime */
                uint16_t len = 12;
                compress_ctx_init(&g_ca);
                if (serialize_dns_record(g_ra, 65535, &len, rec, &g_ca, NULL, 0xFFFFFFFFu) == 0 && len <= 400) {
                    for (size_t m = 12; m <= (size_t)len + 1; m++) {
                        compare_one(img, rec, map[i], m, true, NULL, 0xFFFFFFFFu, NULL, 0);
                        if (prev != (size_t)-1) compare_one(img, rec, map[i], m + 40, true, NULL, 0xFFFFFFFFu, &a->records[prev], map[prev]);
                    }
                    boundary++;
                }
            }
            prev = i;
        }
        free(used);
        free(map);
        exercise_accessors(img);

        /* thaw: records equal, and freezing again gives the same RDATA */
        zone_arena_t b;
        zone_arena_init(&b);
        if (zone_image_thaw(img, &b) != 0) fail();
        if (b.count != img->n_rrs) fail();
        zone_image_t *img2 = zone_image_freeze(&b, apex);
        if (!img2) fail();
        if (img2->n_rrs != img->n_rrs || img2->n_names != img->n_names) fail();
        for (uint32_t k = 0; k < img->n_rrs; k++) {
            if (zone_image_rr_type(img, k) != zone_image_rr_type(img2, k) || zone_image_rr_ttl(img, k) != zone_image_rr_ttl(img2, k) ||
                zone_image_rr_rdlen(img, k) != zone_image_rr_rdlen(img2, k) ||
                (zone_image_rr_rdlen(img, k) && memcmp(zone_image_rr_rdata(img, k), zone_image_rr_rdata(img2, k), zone_image_rr_rdlen(img, k)) != 0))
                fail();
        }
        zone_image_free(img2);
        zone_arena_destroy(&b);
    }
    zone_image_free(img);
}

static void run(const uint8_t *data, size_t size, bool tinydns) {
    char *buf = malloc(size + 1);
    if (!buf) return;
    memcpy(buf, data, size);
    buf[size] = '\0';
    zone_arena_t a;
    zone_arena_init(&a);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "fuzz.local.";
    int rc;
    if (tinydns) {
        ctx.all_zone_names = g_zones;
        ctx.all_zone_count = (int)(sizeof(g_zones) / sizeof(g_zones[0]));
        rc = parse_tinydns_data(buf, size, &a, &ctx);
    } else {
        rc = parse_zone_fast(buf, size, &a, &ctx);
    }
    if (rc >= 0) {
        zone_arena_drop_out_of_zone(&a, "fuzz.local.", drop_cb, NULL);
        zone_arena_drop_unencodable(&a, drop_cb, NULL);
        zone_arena_shrink_records(&a);
        if (build_zone_index(&a, true) == 0) check_image(&a, "fuzz.local.");
    }
    zone_arena_destroy(&a);
    free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (1u << 20)) return 0;
    run(data + 1, size - 1, (data[0] & 1) != 0);
    return 0;
}

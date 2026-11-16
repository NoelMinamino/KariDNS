/*
 * zimg_msgs.h - zone images and the messages of a zone for the tests that play the database loader (0.7 M3).
 *
 * The data of a database zone is a zone image (dns_zone_image.h): ZONE_BEGIN with the image flag and the image size, ZONE_IMAGE messages, ZONE_END.  A test makes the image of a zone from zone
 * file lines (zi_from_text(): the parser, drop out of zone, index, zone_image_freeze(), what the loader does) and sends it with zi_zone_msgs().  The zones are small: a test that needs a
 * hostile image makes the bytes by hand (the helpers here only build and send).
 *
 * Include after dns_db_stream.h, dns_zone_image.h and dns_zone_parser.h; the translation unit links the zone parser and dns_zone_image.c.
 */
#ifndef ZIMG_MSGS_H
#define ZIMG_MSGS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../dns_db_stream.h"
#include "../../dns_zone_image.h"
#include "../../dns_zone_parser.h"

static int zi_www_varies;                       /* a test sets it: the address of www follows the serial of the zone (192.0.2.80 + serial % 4), so that two versions differ */
static inline void zi_silent(const dns_record_t *rec, void *ud) { (void)rec; (void)ud; }

/* The image of the zone-file text `text` ($ORIGIN and the records) with the apex `apex` (canonical absolute).  malloc()ed (zone_image_free()); NULL: it does not parse or freeze.
 * keep_out_of_zone: records outside the zone are kept (for a hostile image). */
static inline zone_image_t *zi_from_text_ex(const char *apex, const char *text, bool keep_out_of_zone) {
    zone_arena_t a;
    zone_arena_init(&a);
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base_dir = ".";
    ctx.default_origin = apex;
    ctx.is_standalone_mode = true;
    ctx.err_out = &err;
    char *copy = arena_strdup(&a, text);
    zone_image_t *img = NULL;
    if (copy && parse_zone_fast(copy, strlen(copy), &a, &ctx) >= 0) {
        if (!keep_out_of_zone) zone_arena_drop_out_of_zone(&a, apex, zi_silent, NULL);
        zone_arena_drop_unencodable(&a, zi_silent, NULL);
        zone_arena_shrink_records(&a);
        if (build_zone_index(&a, true) == 0) img = zone_image_freeze(&a, apex);
    }
    zone_arena_destroy(&a);
    return img;
}
static inline zone_image_t *zi_from_text(const char *apex, const char *text) { return zi_from_text_ex(apex, text, false); }

/* The usual test zone: SOA (serial `serial`), NS ns1 (or `ns`, an absolute name, when given; `ns2` a second NS at the apex), www A 192.0.2.80 + (serial & 3) and, when nA > 0, nA more
 * A records h<k>.  zone: canonical absolute ("name.test.").  malloc()ed. */
static inline zone_image_t *zi_zone(const char *zone, uint32_t serial, const char *ns, const char *ns2, int nA) {
    size_t cap = 512 + (size_t)(nA > 0 ? nA : 0) * 40;
    char *t = malloc(cap);
    if (!t) return NULL;
    size_t n = (size_t)snprintf(t, cap, "$ORIGIN %s\n$TTL 300\n@ SOA ns1 host %u 3600 600 86400 300\n@ NS %s\n", zone, (unsigned)serial, ns ? ns : "ns1");
    if (ns2) n += (size_t)snprintf(t + n, cap - n, "@ NS %s\n", ns2);
    n += (size_t)snprintf(t + n, cap - n, "www A 192.0.2.%u\n", 80u + (zi_www_varies ? (serial & 3u) : 0u));
    for (int k = 0; k < nA; k++) n += (size_t)snprintf(t + n, cap - n, "h%d A 192.0.2.%d\n", k, 1 + k % 250);
    zone_image_t *img = zi_from_text(zone, t);
    free(t);
    return img;
}

/* ZONE_BEGIN of an image zone into e: view, zone, source id, the serial it declares, the digest (all `digest_byte`), the flags besides the image flag, the request id (0 = a batch), the
 * settings text and the profile name (NULL: none).  rr_count and the size are the image's. */
static inline void zi_begin(kdb_enc_t *e, uint16_t view, const char *zone, int64_t sid, uint32_t serial, int digest_byte, uint32_t flags, uint64_t req, const char *settings, const char *profile,
                            uint64_t rr_count, uint64_t size) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, digest_byte, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, flags | KDB_ZF_IMAGE); kdb_enc_u64(e, 7, rr_count); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    if (settings) kdb_enc_str(e, 9, settings);
    if (profile) kdb_enc_str(e, 10, profile);
    if (req) kdb_enc_u64(e, 11, req);
    kdb_enc_u64(e, 23, size);
    kdb_enc_end(e);
}

/* the image as ZONE_IMAGE messages of at most `chunk` octets (0: KDB_MAX_BODY); the first holds the header */
static inline void zi_chunks(kdb_enc_t *e, const void *img, size_t len, size_t chunk) {
    if (chunk == 0 || chunk > KDB_MAX_BODY) chunk = KDB_MAX_BODY;
    for (size_t off = 0; off < len;) {
        size_t n = len - off < chunk ? len - off : chunk;
        if (off == 0 && n < sizeof(zone_image_t)) n = len < sizeof(zone_image_t) ? len : sizeof(zone_image_t);
        kdb_enc_raw_msg(e, KDB_T_ZONE_IMAGE, (const uint8_t *)img + off, n);
        off += n;
    }
}

static inline void zi_end(kdb_enc_t *e, uint64_t rr_count) {
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, rr_count);
    kdb_enc_end(e);
}

/* ZONE_BEGIN, the image, ZONE_END of an image the caller made; `declared_serial` is what ZONE_BEGIN says (a test that wants the refusal says another one than the SOA's) */
static inline void zi_zone_msgs(kdb_enc_t *e, uint16_t view, const char *zone, int64_t sid, uint32_t declared_serial, const zone_image_t *img, uint64_t req, const char *settings,
                                const char *profile, uint32_t flags, int digest_byte) {
    zi_begin(e, view, zone, sid, declared_serial, digest_byte, flags, req, settings, profile, img->n_rrs, img->total_size);
    zi_chunks(e, img, img->total_size, 0);
    zi_end(e, img->n_rrs);
}

/* the usual zone, in one go: the serial of the zone is the one declared, the digest is filled with the serial */
static inline void zi_std_msgs(kdb_enc_t *e, uint16_t view, const char *zone, int64_t sid, uint32_t serial, uint64_t req, const char *settings, const char *profile) {
    zone_image_t *img = zi_zone(zone, serial, NULL, NULL, 0);
    if (!img) { e->err = true; return; }
    zi_zone_msgs(e, view, zone, sid, serial, img, req, settings, profile, 0, (int)serial);
    zone_image_free(img);
}

#endif

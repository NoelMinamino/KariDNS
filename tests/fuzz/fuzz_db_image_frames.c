/*
 * fuzz_db_image_frames.c - the zone image frames of the loader -> Backend stream (0.7 M3): the framer, the state machine, the reassembly of the ZONE_IMAGE messages, zone_image_validate_ex() with the
 * policy that ZONE_BEGIN gives, and the limits of the zone (zone_image_check_limits()).  An image the Backend accepts must be one that every reader can use without a further check
 * (zone_image_validate() agrees, zimg_walk() reads all of it), and what the machine promised about the sizes and the counts must hold.
 *
 * Input: byte 0 is a selector, byte 1 a deviation, the rest are the bytes of a zone image (bit 6 of the selector clear: the rest is a stream, as fuzz_db_stream.c reads it):
 *   bit 7      feed the stream whole (else in chunks of 1 + selector % 61 bytes)
 *   bit 6      the rest is an image, and the harness wraps it as the loader would: ZONE_BEGIN (name, serial and counts from the image), ZONE_IMAGE messages, ZONE_END;
 *              the deviation byte makes the loader lie
 *   bit 4      (stream) start inside a batch, else the stream begins with its HELLO
 *   bit 5      tiny limits (6 records, 4096 bytes: the caps are reachable)
 *   bit 3      the fetch stream machine (kdb_sm_init_fetch())
 *   bits 0-1   how the image is cut into ZONE_IMAGE messages: 0 one, 1 the header and the rest, 2 thirds (the first holds the header), 3 pieces of 997 octets (the first holds the header)
 * Deviations (byte 1 % 12): 0 none; 1 rr_count + 1; 2 announced size + 8; 3 serial + 1; 4 extended flag toggled; 5 tinydns flag toggled; 6 the last ZONE_IMAGE message missing;
 *   7 one more ZONE_IMAGE message; 8 the zone name of ZONE_BEGIN is another; 9 ZONE_END with rr_count + 1; 10 the magic of the header flipped; 11 the first message cut in the header.
 * The stream is run whole and in chunks and must give the same verdict, the same number of frames and the same accepted images.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>

#include "../../dns_db_stream.h"
#include "../../dns_wire.h"
#include "../../dns_zone_parser.h"
#include "../../dns_zone_image.h"
#include "../zone_image_walk.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

static uint8_t g_buf[KDB_MAX_BODY];

typedef struct {
    kdb_rc_t rc;
    int nframes;
    uint32_t accepted;      /* images that passed zone_image_validate_ex() */
    uint64_t sum;           /* of everything the harness saw, to compare the runs */
    kdb_state_t state;
} run_t;

static void mix(uint64_t *h, uint64_t v) { *h = (*h ^ v) * 1099511628211ull; }

/* the image of one zone as the Backend reassembles it, and what ZONE_BEGIN said about it */
typedef struct {
    bool open;
    char name[DNS_NAME_TEXT_SIZE];
    uint32_t serial;
    uint64_t rr_count, size;
    uint32_t flags;
    uint8_t *img;
    size_t have, cap;
} zone_t;

static void zone_drop(zone_t *z) {
    free(z->img);
    memset(z, 0, sizeof(*z));
}

static void check_image(const zone_t *z, const kdb_limits_t *lim, run_t *r) {
    char why[300];
    const zone_image_policy_t pol = { z->name, z->serial, z->rr_count, z->size, lim->max_zone_bytes, lim->max_zone_records, (z->flags & KDB_ZF_EXTENDED) != 0, (z->flags & KDB_ZF_TINYDNS) != 0, false };
    if (z->have != z->size) abort();                             /* the machine accepted ZONE_END: the image is complete */
    const int vr = zone_image_validate_ex(z->img, z->have, &pol, why, sizeof(why));
    mix(&r->sum, (uint64_t)(vr + 3));
    if (vr != 0) return;
    r->accepted++;
    const zone_image_t *img = (const zone_image_t *)(const void *)z->img;
    /* what the policy promised */
    if (img->total_size != z->size || img->n_rrs != z->rr_count || z->size > lim->max_zone_bytes || z->rr_count > lim->max_zone_records || z->rr_count == 0) abort();
    /* and the image is one that every reader takes without a check */
    if (zone_image_validate(z->img, z->have, why, sizeof(why)) != 0) abort();
    /* RFC 9276 section 3.2: no NSEC3 iteration count above the cap in an image that was accepted (the header, the chains, every NSEC3 / NSEC3PARAM RR), and the hash table is not fuller than three quarters */
    if (img->n3_iterations > ZONE_MAX_NSEC3_ITERATIONS || (uint64_t)img->hash_size * 3 < (uint64_t)img->n_names * 4) abort();
    for (uint32_t c = 0; c < img->n_n3chains; c++)
        if (zone_image_n3chains(img)[c].iterations > ZONE_MAX_NSEC3_ITERATIONS) abort();
    for (uint32_t k = 0; k < img->n_rrs; k++) {
        const uint16_t t = zone_image_rr_type(img, k);
        if ((t == 50 || t == 51) && zone_image_rr_rdlen(img, k) >= 4) {
            const uint8_t *rd = zone_image_rr_rdata(img, k);
            if ((unsigned)((rd[2] << 8) | rd[3]) > ZONE_MAX_NSEC3_ITERATIONS) abort();
        }
    }
    unsigned bad = 0;
    mix(&r->sum, zimg_walk(img, &bad));
    if (bad) abort();
    zone_limits_t zl;
    memset(&zl, 0, sizeof(zl));
    zl.max_records = 3;                                          /* any verdict, no crash: a limit the zone may or may not break */
    zl.max_per_type = 2;
    zl.max_types_per_name = 2;
    zl.max_zone_ttl = 100;
    char lerr[200];
    mix(&r->sum, (uint64_t)(zone_image_check_limits(img, &zl, lerr, sizeof(lerr)) + 3));
    memset(&zl, 0, sizeof(zl));
    if (zone_image_check_limits(img, &zl, lerr, sizeof(lerr)) != 0) abort();     /* no limit, no refusal */
}

static void run_one(const uint8_t *p, size_t n, size_t chunk, uint8_t sel, run_t *r) {
    kdb_framer_t f;
    kdb_sm_t sm;
    kdb_msg_t m;
    kdb_limits_t lim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, 3 };
    if (sel & 0x20) { lim.max_zone_records = 6; lim.max_zone_bytes = 4096; }
    kdb_framer_init(&f, KDB_FROM_LOADER, g_buf, sizeof(g_buf));
    if (sel & 0x08) kdb_sm_init_fetch(&sm, &lim);
    else { kdb_sm_init(&sm, &lim); if (sel & 0x50) sm.state = KDB_S_IN_BATCH; }          /* (the wrapped image is a ZONE_BEGIN: a batch has begun) */
    memset(r, 0, sizeof(*r));
    r->sum = 1469598103934665603ull;
    zone_t z;
    memset(&z, 0, sizeof(z));
    size_t off = 0;
    do {
        size_t c = chunk ? (n - off < chunk ? n - off : chunk) : n - off;
        kdb_rc_t rc = kdb_framer_feed(&f, p + off, c);
        off += c;
        while (rc == KDB_OK) {
            kdb_frame_t fr;
            rc = kdb_framer_next(&f, &fr);
            if (rc == KDB_MORE) { rc = KDB_OK; break; }
            if (rc != KDB_OK) break;
            rc = kdb_sm_accept(&sm, &fr, &m);
            if (rc != KDB_OK) break;
            r->nframes++;
            mix(&r->sum, fr.type);
            if (fr.type == KDB_T_ZONE_BEGIN) {
                zone_drop(&z);
                const kdb_zone_begin_t *zb = &m.u.zone_begin;
                if (!!(zb->flags & KDB_ZF_IMAGE) != sm.zone_image) abort();
                if (sm.zone_image) {
                    z.open = true;
                    snprintf(z.name, sizeof(z.name), "%s", zb->name);
                    z.serial = zb->serial;
                    z.rr_count = zb->rr_count;
                    z.size = zb->image_size;
                    z.flags = zb->flags;
                    if (z.size != sm.zone_image_size || z.size > lim.max_zone_bytes || z.size < sizeof(zone_image_t) + 8 || (z.size & 7)) abort();
                }
            } else if (fr.type == KDB_T_ZONE_IMAGE) {
                /* the octets come to the size that was announced and never past it; the buffer is the Backend's own reassembly (zone_image_asm_add(), what dns_db_ingest.c job_image() calls): one buffer of the announced size */
                if (!z.open || sm.zone_image_have > z.size || sm.zone_image_have != z.have + m.u.zone_image.len) abort();
                if (zone_image_asm_add(&z.img, &z.have, &z.cap, z.size, m.u.zone_image.body, m.u.zone_image.len) != 0) abort();     /* (the machine accepted the message: it is within the size, and the memory is there) */
                if (z.cap != z.size || z.have != sm.zone_image_have) abort();
                mix(&r->sum, m.u.zone_image.len);
            } else if (fr.type == KDB_T_ZONE_END) {
                if (z.open) {
                    check_image(&z, &lim, r);
                    zone_drop(&z);
                }
            } else if (fr.type == KDB_T_ZONE_ABORT) {
                zone_drop(&z);
            }
        }
        if (rc != KDB_OK) { r->rc = rc; break; }
    } while (off < n);
    r->state = sm.state;
    zone_drop(&z);
}

/* the image as the loader sends it, wrapped in ZONE_BEGIN .. ZONE_END with the deviation the fuzzer asked for; 0 = e is filled */
static int wrap(kdb_enc_t *e, const uint8_t *img, size_t len, uint8_t sel, uint8_t dev) {
    uint8_t digest[KDB_DIGEST_LEN];
    memset(digest, 0x5A, sizeof(digest));
    zone_image_t h;
    if (len < sizeof(h) + 8) return -1;
    memcpy(&h, img, sizeof(h));
    uint8_t *copy = malloc(len);
    if (!copy) return -1;
    memcpy(copy, img, len);
    uint64_t rr = h.n_rrs, size = len, end_rr = h.n_rrs;
    uint32_t serial = 7, flags = KDB_ZF_IMAGE | KDB_ZF_EXTENDED;
    char zname[DNS_NAME_TEXT_SIZE] = "fuzz.test.";
    const char *name = zname;
    {   /* an image that is valid says which zone it is and which serial it has: the loader's ZONE_BEGIN says the same, so that the images the fuzzer made valid can be accepted */
        char why[200];
        const zone_image_t *vi = (const zone_image_t *)(const void *)copy;
        if (zone_image_validate(copy, len, why, sizeof(why)) == 0 && vi->apex_name != ZONE_IMAGE_NONE) {
            snprintf(zname, sizeof(zname), "%s", zone_image_name_text(vi, vi->apex_name));
            const uint32_t soa = zone_image_apex_soa(vi);
            zone_image_soa_t s;
            if (soa != ZONE_IMAGE_NONE && zone_image_soa(vi, soa, NULL, 0, NULL, 0, &s) == 0) serial = s.serial;
            if (vi->flags & ZONE_IMAGE_F_TINYDNS) flags |= KDB_ZF_TINYDNS;
        }
    }
    dev %= 12;
    if (dev == 1) rr++;
    if (dev == 2) size += 8;
    if (dev == 3) serial++;
    if (dev == 4) flags ^= KDB_ZF_EXTENDED;
    if (dev == 5) flags ^= KDB_ZF_TINYDNS;
    if (dev == 8) name = "other.fuzz.";
    if (dev == 9) end_rr++;
    if (dev == 10) copy[0] ^= 1;
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, 0); kdb_enc_name(e, 2, name); kdb_enc_i64(e, 3, 1); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, flags); kdb_enc_u64(e, 7, rr); kdb_enc_bytes(e, 8, digest, sizeof(digest));
    if (sel & 0x08) kdb_enc_u64(e, 11, 1);
    kdb_enc_u64(e, 23, size);
    kdb_enc_end(e);
    size_t pieces[16], np = 0, total = len;
    switch (sel & 0x03) {
    case 0: pieces[np++] = total; break;
    case 1: pieces[np++] = sizeof(h); pieces[np++] = total - sizeof(h); break;
    case 2: {
        size_t t = total / 3 < sizeof(h) ? sizeof(h) : total / 3;
        pieces[np++] = t;
        pieces[np++] = (total - t) / 2;
        pieces[np++] = total - t - (total - t) / 2;
        break;
    }
    default: {
        size_t at = 0;
        while (at < total && np < 15) {
            size_t c = total - at < 997 ? total - at : 997;
            if (at == 0 && c < sizeof(h)) c = sizeof(h);
            pieces[np++] = c;
            at += c;
        }
        if (at < total) pieces[np++] = total - at;
        break;
    }
    }
    if (dev == 11) { pieces[0] = sizeof(h) - 8; pieces[1 < np ? 1 : 0] += (np > 1 ? 8 : 0); }
    size_t at = 0;
    for (size_t k = 0; k < np; k++) {
        if (pieces[k] == 0) continue;
        if (at + pieces[k] > total) pieces[k] = total - at;
        if (dev == 6 && k + 1 == np) break;                      /* the last message is missing */
        if (pieces[k]) kdb_enc_raw_msg(e, KDB_T_ZONE_IMAGE, copy + at, pieces[k]);
        at += pieces[k];
    }
    if (dev == 7) kdb_enc_raw_msg(e, KDB_T_ZONE_IMAGE, copy, 8);
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, end_rr);
    kdb_enc_end(e);
    free(copy);
    return e->err ? -1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    const uint8_t sel = data[0], dev = data[1];
    const uint8_t *p = data + 2;
    size_t n = size - 2;
    kdb_enc_t e;
    kdb_enc_init(&e);
    if (sel & 0x40) {
        if (wrap(&e, p, n, sel, dev) != 0) { kdb_enc_free(&e); return 0; }
        p = e.buf;
        n = e.len;
    }
    const size_t chunk = (sel & 0x80) ? 0 : (size_t)(1 + sel % 61);
    run_t a, b;
    run_one(p, n, 0, sel, &a);
    run_one(p, n, chunk, sel, &b);
    if (a.rc != b.rc || a.nframes != b.nframes || a.sum != b.sum || a.state != b.state || a.accepted != b.accepted) abort();
    kdb_enc_free(&e);
    return 0;
}

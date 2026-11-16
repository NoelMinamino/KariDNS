/*
 * fake_dbloader.c - a stand-in for karidns-dbloader that speaks KDB1 wrongly (tests/run_db_loader_lifecycle_test.sh,
 * tests/run_db_hostile_loader_test.sh).
 *
 *   fake_dbloader -s FD MODE
 *
 * It sends a correct HELLO (version 1, driver sqlite3, zone images: KDB_FEAT_IMAGE and the image version), reads the CONFIG, and then misbehaves.  The framing of the stream is
 * written by hand (the encoder of dns_db_stream.c would only make correct messages); the zone images are made with the zone parser and zone_image_freeze() (tests/db/zimg_msgs.h) and
 * then spoilt where a mode needs it.  Modes of the lifecycle test (the stream is wrong; the Backend closes it):
 *   bad-magic  a message whose magic is not "KDB1"
 *   bad-order  ZONE_END without BATCH_BEGIN / ZONE_BEGIN (a message type that is not legal in the state)
 *   bad-view   BATCH_BEGIN followed by a ZONE_BEGIN naming a view index beyond the configured views
 *   silent     nothing more (the Backend must keep waiting without harm)
 * Modes of the hostile loader test, each one batch of ok1.test, <the bad zone bad.test>, ok2.test:
 *   good             no bad zone (the sanity run: both zones are installed)
 *   owner-outside    bad.test has an A record with an owner outside the zone            -> zone rejected
 *   soa-subdomain    the only SOA belongs to sub.bad.test, not the apex                  -> zone rejected
 *   two-soa          two SOA records at the apex without the extended flag               -> zone rejected
 *   other-zone       the image of another zone                                          -> zone rejected
 *   non-in-class     an RR of class CH                                                  -> zone rejected
 *   image-serial     ZONE_BEGIN declares another serial than the SOA of the image        -> zone rejected
 *   image-tinydns    the image says tinydns, ZONE_BEGIN does not                         -> zone rejected
 *   image-garbage    the octets after the header are noise                               -> zone rejected
 *   secondary-kind   zone_kind secondary, rr_count 0, no settings (B7b: no masters)              -> zone rejected
 *   secondary-data   zone_kind secondary with rr_count 2                                         -> protocol error
 *   secondary-flag   zone_kind secondary with the presigned flag                                 -> zone rejected
 *   secondary-host   secondary whose masters statement names a host name                         -> zone rejected
 *   secondary-prim   a primary zone whose settings name masters                                   -> zone rejected
 *   secondary-ok     secondary with masters { 127.0.0.1 port 1; } (the transfer fails, the zone is registered) -> applied
 *   catalog-ok       zone_kind catalog (a CONSUMER) with masters                                  -> applied
 *   ext-flag-bit     a reserved zone flag bit (32: bit 3 is the fetch summary since D1a, bit 4 the zone image since M3)          -> protocol error
 *   ext-image-flag   the zone image flag without the size of the image                                                          -> protocol error
 *   ext-ok           the extended flag on a zone                                         -> applied
 *   again            ok1.test twice in one batch (the second replaces the first)       -> both applied
 *   slow             ok1.test, a pause of 8 s, ok2.test: ok1.test must answer during the pause (the view delta runs
 *                    at least once a second, design 4.4)
 *   delete-unknown   ZONE_DELETE of a zone that is not registered                       -> "unchanged"
 *   huge-frame       a ZONE_IMAGE message above 1 MiB                                   -> protocol error
 *   end-count        ZONE_END with another RR count than ZONE_BEGIN                     -> protocol error
 *   begin-count      ZONE_BEGIN declares 9 RRs, the image has 3                         -> protocol error
 *   unknown-tag      ZONE_BEGIN with an unknown TLV tag                                 -> protocol error
 *   zone-data        a message of type 5 (the ZONE_DATA of the loaders before 0.7 M3)   -> protocol error
 *   no-image-flag    a primary zone that is not an image                                -> protocol error
 *   hello-no-image   a HELLO without KDB_FEAT_IMAGE                                     -> protocol error
 *   hello-version    a HELLO with another image version                                 -> protocol error
 *   image-magic      the header of the image has another magic                           -> protocol error
 *   image-size-hdr   the size in the header is not the one of ZONE_BEGIN                 -> protocol error
 *   image-short      ZONE_END before the image is complete                              -> protocol error
 *   image-extra      one more ZONE_IMAGE message than the size announced                -> protocol error
 * Modes of the settings part (B7a):
 *   settings-key     settings text naming a TSIG key karidns.conf does not define          -> zone rejected
 *   settings-include settings text with an include statement                               -> zone rejected
 *   settings-file    settings text with a file statement                                   -> zone rejected
 *   settings-slave   settings text with type / masters statements                          -> zone rejected
 *   settings-brace   settings text with a stray closing brace                              -> zone rejected
 *   profile-missing  ZONE_BEGIN names a profile that was not sent                          -> zone rejected
 *   profile-flood    270 PROFILE messages of 64000 bytes (more than the Backend keeps)    -> protocol error
 *   settings-ok      settings text and a profile the Backend accepts                       -> both applied
 * Then it waits until the Backend closes the stream and exits 0.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zimg_msgs.h"

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }

static size_t tlv(uint8_t *b, uint16_t tag, const void *v, uint16_t n) {
    put16(b, tag);
    put16(b + 2, n);
    memcpy(b + 4, v, n);
    return 4u + n;
}

static uint8_t g_buf[(2u << 20) + 64];

static void send_msg(int fd, const char *magic, uint16_t type, const uint8_t *body, size_t n) {
    memcpy(g_buf, magic, 4);
    put16(g_buf + 4, type);
    put16(g_buf + 6, 0);
    put32(g_buf + 8, (uint32_t)n);
    memcpy(g_buf + 12, body, n);
    size_t off = 0, len = 12 + n;
    while (off < len) {
        ssize_t w = write(fd, g_buf + off, len - off);
        if (w <= 0) exit(0);
        off += (size_t)w;
    }
}

/* ---------------------------------------------------------------- KDB1 pieces */
static uint64_t g_batch = 1;
static uint32_t g_nzones, g_ndel;

static void batch_begin(int fd) {
    uint8_t b[64], kind = 0, zero8[8] = { 0 };
    size_t n = 0;
    uint8_t id[8];
    put64(id, g_batch);
    n += tlv(b + n, 1, id, 8);
    n += tlv(b + n, 2, &kind, 1);
    n += tlv(b + n, 3, zero8, 8);
    send_msg(fd, "KDB1", 3, b, n);
}

static void batch_end(int fd, uint32_t deleted) {
    uint8_t b[64], id[8], v[4];
    size_t n = 0;
    put64(id, g_batch);
    n += tlv(b + n, 1, id, 8);
    put32(v, g_nzones); n += tlv(b + n, 2, v, 4);
    put32(v, 0); n += tlv(b + n, 3, v, 4);
    put32(v, deleted); n += tlv(b + n, 4, v, 4);
    send_msg(fd, "KDB1", 11, b, n);
}

static uint32_t g_zb_serial = 1;              /* the serial ZONE_BEGIN declares (the SOA serial of the zone) */

/* ZONE_BEGIN; image_size != 0: tag 23 (the flags carry the image flag by themselves) */
static void zone_begin_ex(int fd, const char *zone, uint8_t kind, uint32_t flags, uint64_t declared, uint64_t image_size, uint16_t extra_tag,
                          const char *settings, const char *profile) {
    uint8_t b[1024], view[2] = { 0, 0 }, serial[4], fl[4], rrs[8], digest[32] = { 0 }, src[8] = { 0 }, isz[8];
    char canon[300];
    snprintf(canon, sizeof(canon), "%s.", zone);
    put32(serial, g_zb_serial);
    put32(fl, flags);
    put64(rrs, declared);
    put64(src, 100 + g_nzones);
    put64(isz, image_size);
    size_t n = 0;
    n += tlv(b + n, 1, view, 2);
    n += tlv(b + n, 2, canon, (uint16_t)strlen(canon));
    n += tlv(b + n, 3, src, 8);
    n += tlv(b + n, 4, &kind, 1);
    n += tlv(b + n, 5, serial, 4);
    n += tlv(b + n, 6, fl, 4);
    n += tlv(b + n, 7, rrs, 8);
    n += tlv(b + n, 8, digest, 32);
    if (settings) n += tlv(b + n, 9, settings, (uint16_t)strlen(settings));
    if (profile) n += tlv(b + n, 10, profile, (uint16_t)strlen(profile));
    if (image_size) n += tlv(b + n, 23, isz, 8);
    if (extra_tag) n += tlv(b + n, extra_tag, "x", 1);
    send_msg(fd, "KDB1", 4, b, n);
}

static void zone_begin(int fd, const char *zone, uint8_t kind, uint32_t flags, uint64_t declared, uint16_t extra_tag) {
    zone_begin_ex(fd, zone, kind, flags, declared, 0, extra_tag, NULL, NULL);
}

static void zone_end(int fd, uint64_t count) {
    uint8_t b[16];
    put64(b + 4, count);
    put16(b, 1);
    put16(b + 2, 8);
    send_msg(fd, "KDB1", 6, b, 12);
    g_nzones++;
}

/* the octets of an image as ZONE_IMAGE messages: the header, then the rest in one message (or `msgs` pieces) */
static void image_msgs(int fd, const uint8_t *img, size_t len) {
    size_t h = len < sizeof(zone_image_t) ? len : sizeof(zone_image_t);
    send_msg(fd, "KDB1", 20, img, h);
    if (len > h) send_msg(fd, "KDB1", 20, img + h, len - h);
}

/* a zone that is an image: ZONE_BEGIN (flags | image), the image, ZONE_END.  declared == 0: the image's own count */
static void image_zone_ex(int fd, const char *zone, uint32_t serial, uint32_t flags, const zone_image_t *img, uint64_t declared, const char *settings, const char *profile) {
    g_zb_serial = serial;
    if (!declared) declared = img->n_rrs;
    zone_begin_ex(fd, zone, 0, flags | KDB_ZF_IMAGE, declared, img->total_size, 0, settings, profile);
    image_msgs(fd, (const uint8_t *)img, img->total_size);
    zone_end(fd, declared);
}

static zone_image_t *good_image(const char *zone, uint32_t serial) {
    char apex[300], text[1200];
    snprintf(apex, sizeof(apex), "%s.", zone);
    snprintf(text, sizeof(text), "$ORIGIN %s\n$TTL 300\n@ SOA ns host %u 3600 600 86400 300\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.10\nmail A 192.0.2.25\n", apex, (unsigned)serial);
    zone_image_t *img = zi_from_text(apex, text);
    if (!img) { fprintf(stderr, "fake_dbloader: cannot make the image of %s\n", zone); exit(3); }
    return img;
}

/* a correct zone: SOA, NS, 3 A */
static void good_zone(int fd, const char *zone, uint32_t serial) {
    zone_image_t *img = good_image(zone, serial);
    image_zone_ex(fd, zone, serial, 0, img, 0, NULL, NULL);
    zone_image_free(img);
}

static zone_image_t *text_image(const char *zone, const char *body, bool keep_out_of_zone) {
    char apex[300], text[2400];
    snprintf(apex, sizeof(apex), "%s.", zone);
    snprintf(text, sizeof(text), "$ORIGIN %s\n$TTL 300\n%s", apex, body);
    zone_image_t *img = zi_from_text_ex(apex, text, keep_out_of_zone);
    if (!img) { fprintf(stderr, "fake_dbloader: cannot make the image of %s\n", zone); exit(3); }
    return img;
}

/* the bad zone of a mode: bad.test */
static void bad_zone(int fd, const char *mode) {
    const char *z = "bad.test";
    static const char soa5[] = "@ SOA ns host 5 3600 600 86400 300\n";
    char t[1200];
    zone_image_t *img = NULL;
    if (strcmp(mode, "owner-outside") == 0) {
        snprintf(t, sizeof(t), "%s@ NS ns\nns A 192.0.2.1\nhost.other.test. A 192.0.2.99\n", soa5);
        img = text_image(z, t, true);
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "soa-subdomain") == 0) {
        img = text_image(z, "sub SOA ns host 5 3600 600 86400 300\n@ NS ns\nns A 192.0.2.1\n", true);
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "two-soa") == 0) {
        snprintf(t, sizeof(t), "%s@ SOA ns2 host 5 3600 600 86400 300\n@ NS ns\nns A 192.0.2.1\n", soa5);
        img = text_image(z, t, true);
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "other-zone") == 0) {
        img = good_image("other.test", 5);
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "non-in-class") == 0) {
        snprintf(t, sizeof(t), "%s@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n", soa5);
        img = text_image(z, t, false);
        zone_image_rr_t *rr = (zone_image_rr_t *)(void *)((uint8_t *)img + img->off_rrs);
        for (uint32_t k = 0; k < img->n_rrs; k++)
            if (rr[k].type == 1) { rr[k].class_val = 3; break; }
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "image-serial") == 0) {
        img = good_image(z, 5);
        image_zone_ex(fd, z, 6, 0, img, 0, NULL, NULL);                 /* ZONE_BEGIN says 6, the SOA says 5 */
    } else if (strcmp(mode, "image-tinydns") == 0) {
        img = good_image(z, 5);
        img->flags |= ZONE_IMAGE_F_TINYDNS;
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "image-garbage") == 0) {
        img = good_image(z, 5);
        for (size_t i = sizeof(zone_image_t); i < img->total_size; i++) ((uint8_t *)img)[i] = (uint8_t)(i * 37 + 11);
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "secondary-kind") == 0) {
        zone_begin(fd, z, 1, 0, 0, 0); zone_end(fd, 0);
    } else if (strcmp(mode, "secondary-data") == 0) {
        zone_begin_ex(fd, z, 1, 0, 2, 0, 0, "masters { 192.0.2.1; };", NULL); zone_end(fd, 2);
    } else if (strcmp(mode, "secondary-flag") == 0) {
        zone_begin_ex(fd, z, 1, 1, 0, 0, 0, "masters { 192.0.2.1; };", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "secondary-host") == 0) {
        zone_begin_ex(fd, z, 1, 0, 0, 0, 0, "masters { ns1.example.net; };", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "secondary-prim") == 0) {
        img = good_image(z, 5);
        image_zone_ex(fd, z, 5, 0, img, 0, "masters { 192.0.2.1; };", NULL);
    } else if (strcmp(mode, "secondary-ok") == 0) {
        zone_begin_ex(fd, z, 1, 0, 0, 0, 0, "masters { 127.0.0.1 port 1; 2001:db8::1; }; ixfr-history 3;", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "catalog-ok") == 0) {
        zone_begin_ex(fd, z, 2, 0, 0, 0, 0, "masters { 127.0.0.1 port 1; };", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "ext-flag-bit") == 0) {              /* a reserved zone flag: protocol error */
        zone_begin(fd, z, 0, 32, 2, 0);
    } else if (strcmp(mode, "ext-image-flag") == 0) {            /* the zone image flag (bit 4) with no image size (tag 23): protocol error */
        zone_begin(fd, z, 0, 16, 2, 0);
    } else if (strcmp(mode, "ext-ok") == 0) {                    /* the extended flag on a zone that has no extension: accepted */
        img = good_image(z, 5);
        image_zone_ex(fd, z, 5, KDB_ZF_EXTENDED, img, 0, NULL, NULL);
    } else if (strcmp(mode, "huge-frame") == 0) {
        static uint8_t big[(1u << 20) + 8];
        img = good_image(z, 5);
        memcpy(big, img, img->total_size);
        g_zb_serial = 5;
        zone_begin_ex(fd, z, 0, KDB_ZF_IMAGE, img->n_rrs, img->total_size, 0, NULL, NULL);
        send_msg(fd, "KDB1", 20, big, sizeof(big));
    } else if (strcmp(mode, "end-count") == 0) {
        img = good_image(z, 5);
        g_zb_serial = 5;
        zone_begin_ex(fd, z, 0, KDB_ZF_IMAGE, img->n_rrs, img->total_size, 0, NULL, NULL);
        image_msgs(fd, (const uint8_t *)img, img->total_size);
        zone_end(fd, 7);
    } else if (strcmp(mode, "begin-count") == 0) {
        img = good_image(z, 5);
        image_zone_ex(fd, z, 5, 0, img, 9, NULL, NULL);          /* ZONE_BEGIN says 9 RRs, the header says 5 */
    } else if (strcmp(mode, "unknown-tag") == 0) {
        zone_begin(fd, z, 0, 0, 2, 99);
    } else if (strcmp(mode, "zone-data") == 0) {
        uint8_t b[32] = { 0x12, 0x34, 0x84, 0 };
        send_msg(fd, "KDB1", 5, b, sizeof(b));
    } else if (strcmp(mode, "no-image-flag") == 0) {
        zone_begin(fd, z, 0, 0, 4, 0);
    } else if (strcmp(mode, "image-magic") == 0) {
        img = good_image(z, 5);
        img->magic ^= 1;
        image_zone_ex(fd, z, 5, 0, img, 0, NULL, NULL);
    } else if (strcmp(mode, "image-size-hdr") == 0) {
        img = good_image(z, 5);
        zone_begin_ex(fd, z, 0, KDB_ZF_IMAGE, img->n_rrs, img->total_size + 8, 0, NULL, NULL);
        image_msgs(fd, (const uint8_t *)img, img->total_size);
    } else if (strcmp(mode, "image-short") == 0) {
        img = good_image(z, 5);
        g_zb_serial = 5;
        zone_begin_ex(fd, z, 0, KDB_ZF_IMAGE, img->n_rrs, img->total_size, 0, NULL, NULL);
        image_msgs(fd, (const uint8_t *)img, img->total_size - 8);
        zone_end(fd, img->n_rrs);
    } else if (strcmp(mode, "image-extra") == 0) {
        img = good_image(z, 5);
        g_zb_serial = 5;
        zone_begin_ex(fd, z, 0, KDB_ZF_IMAGE, img->n_rrs, img->total_size, 0, NULL, NULL);
        image_msgs(fd, (const uint8_t *)img, img->total_size);
        send_msg(fd, "KDB1", 20, (const uint8_t *)img, 8);
    } else if (strcmp(mode, "settings-key") == 0 || strcmp(mode, "settings-include") == 0 || strcmp(mode, "settings-file") == 0 ||
               strcmp(mode, "settings-slave") == 0 || strcmp(mode, "settings-brace") == 0 || strcmp(mode, "profile-missing") == 0 ||
               strcmp(mode, "settings-ok") == 0) {
        const char *st = NULL, *pr = NULL;
        if (strcmp(mode, "settings-key") == 0) st = "allow-transfer { 127.0.0.1; key \"ghost\"; };";
        else if (strcmp(mode, "settings-include") == 0) st = "include \"/etc/passwd\"; allow-transfer { any; };";
        else if (strcmp(mode, "settings-file") == 0) st = "ixfr-history 2; file \"/etc/passwd\";";
        else if (strcmp(mode, "settings-slave") == 0) st = "type slave; masters { 192.0.2.1; };";
        else if (strcmp(mode, "settings-brace") == 0) st = "allow-transfer { 127.0.0.1; }; };";
        else if (strcmp(mode, "profile-missing") == 0) pr = "p1";
        else st = "allow-transfer { 127.0.0.1; }; ixfr-history 3;";
        if (strcmp(mode, "settings-ok") == 0) {                   /* a profile first, then a zone that uses it and has own text */
            uint8_t pb[256];
            size_t pn = 0;
            pn += tlv(pb + pn, 1, "p1", 2);
            pn += tlv(pb + pn, 2, "notify-retries 2;", 17);
            send_msg(fd, "KDB1", 10, pb, pn);
            pr = "p1";
        }
        img = good_image(z, 5);
        image_zone_ex(fd, z, 5, 0, img, 0, st, pr);
    } else if (strcmp(mode, "profile-flood") == 0) {
        static uint8_t pb[64100];
        static char text[64001];
        memset(text, '#', 64000);
        for (int i = 0; i < 270; i++) {
            char name[16];
            size_t pn = 0;
            snprintf(name, sizeof(name), "p%d", i);
            pn += tlv(pb + pn, 1, name, (uint16_t)strlen(name));
            pn += tlv(pb + pn, 2, text, 64000);
            send_msg(fd, "KDB1", 10, pb, pn);
        }
    } else if (strcmp(mode, "delete-unknown") == 0) {
        uint8_t b[128], view[2] = { 0, 0 }, src[8] = { 0 };
        size_t n = 0;
        put64(src, 4242);
        n += tlv(b + n, 1, view, 2);
        n += tlv(b + n, 2, "nothere.test.", 13);
        n += tlv(b + n, 3, src, 8);
        send_msg(fd, "KDB1", 9, b, n);
        g_ndel++;
    }
    zone_image_free(img);
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "-s") != 0) return 2;
    int fd = atoi(argv[2]);
    const char *mode = argc > 3 ? argv[3] : "bad-magic";
    uint8_t b[512];
    size_t n = 0;
    uint8_t v16[2] = { 0, 1 }, pid[4], feat[4], iver[4];
    put32(pid, (uint32_t)getpid());
    put32(feat, KDB_FEAT_IMAGE);
    put32(iver, ZONE_IMAGE_VERSION + (strcmp(mode, "hello-version") == 0 ? 1u : 0u));
    n += tlv(b + n, 1, v16, 2);
    n += tlv(b + n, 2, "fake", 4);
    n += tlv(b + n, 3, "sqlite3", 7);
    n += tlv(b + n, 4, pid, 4);
    if (strcmp(mode, "hello-no-image") != 0) {
        n += tlv(b + n, 5, feat, 4);
        n += tlv(b + n, 6, iver, 4);
    }
    send_msg(fd, "KDB1", 1, b, n);

    uint8_t rbuf[4096];                      /* the CONFIG */
    ssize_t r = read(fd, rbuf, sizeof(rbuf));
    (void)r;
    uint8_t one[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
    n = 0;
    if (strcmp(mode, "bad-magic") == 0) {
        send_msg(fd, "XXXX", 2, b, 0);
    } else if (strcmp(mode, "bad-order") == 0) {
        n += tlv(b + n, 1, one, 8);
        send_msg(fd, "KDB1", 6, b, n);       /* ZONE_END in READY */
    } else if (strcmp(mode, "bad-view") == 0) {
        uint8_t kind = 0, zero8[8] = { 0 };
        n += tlv(b + n, 1, one, 8);
        n += tlv(b + n, 2, &kind, 1);
        n += tlv(b + n, 3, zero8, 8);
        send_msg(fd, "KDB1", 3, b, n);       /* BATCH_BEGIN */
        uint8_t view[2] = { 0x12, 0x34 }, serial[4] = { 0, 0, 0, 1 }, flags[4] = { 0 }, rrs[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };
        uint8_t digest[32] = { 0 }, src[8] = { 0 }, zk = 0;
        n = 0;
        n += tlv(b + n, 1, view, 2);
        n += tlv(b + n, 2, "bad.test.", 9);
        n += tlv(b + n, 3, src, 8);
        n += tlv(b + n, 4, &zk, 1);
        n += tlv(b + n, 5, serial, 4);
        n += tlv(b + n, 6, flags, 4);
        n += tlv(b + n, 7, rrs, 8);
        n += tlv(b + n, 8, digest, 32);
        send_msg(fd, "KDB1", 4, b, n);       /* ZONE_BEGIN with view 0x1234 */
    } else if (strcmp(mode, "hello-no-image") == 0 || strcmp(mode, "hello-version") == 0) {
        /* the HELLO was the mistake */
    } else if (strcmp(mode, "silent") != 0) {
        /* zone-level modes: one batch, ok1.test, the bad zone, ok2.test */
        batch_begin(fd);
        good_zone(fd, "ok1.test", 1);
        if (strcmp(mode, "slow") == 0) sleep(8);   /* long enough for the checks during the batch on a loaded host (3 s was not, 0.6.2 suite at -j 4) */
        else if (strcmp(mode, "good") != 0) bad_zone(fd, mode);
        if (strcmp(mode, "again") == 0) good_zone(fd, "ok1.test", 2);
        good_zone(fd, "ok2.test", 1);
        batch_end(fd, g_ndel);
    }
    for (;;) {                                /* until the Backend closes the stream */
        ssize_t k = read(fd, rbuf, sizeof(rbuf));
        if (k == 0) return 0;
        if (k < 0) sleep(1);
    }
}

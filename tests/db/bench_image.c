/*
 * bench_image.c - what one zone costs in the database loader and in the Backend with the ZONE_DATA stream and with a zone image (0.7 M3).
 *
 * Usage: bench_image [ZONES [RRS_PER_ZONE]]     (default 20000 zones of 10 RRs; zone shape as tests/db/gen_sqlite3_zones.sh makes it)
 *
 * The zones are made in memory from rows (the reader of the loader, dns_pdns_reader.c), one thread, one zone after the other, and every step is timed by itself, in
 * microseconds per zone:
 *   rows -> zone     pdns_zone_add_record() for every row and pdns_zone_finish() (zone text, zone file parser, checks): the same for both
 *   ZONE_DATA        loader: pdns_zone_encode_kdb() (digest pass and message pass); Backend: parse_xfr_packet() of every message, then what the install does
 *                    with the arena (drop unencodable, index, zone_image_freeze())
 *   image            loader: pdns_zone_build_image() = reorder, index, freeze, flags, zone_image_validate_ex(); pdns_zone_encode_image() = that and the digest and the
 *                    messages; the parts of it again by themselves: build_zone_index(), zone_image_freeze(), zone_image_validate_ex(), zone_image_check_limits()
 * Nothing here is a test: it prints numbers (a build host that is shared with other work makes them move by 20 %).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include "../../dns_pdns_reader.h"
#include "../../dns_config_parser.h"
#include "../../dns_utils.h"
#include "xfr_mocks.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

typedef struct { uint8_t *buf; size_t len, cap; } sink_t;

static int sink_emit(void *ud, const uint8_t *msg, size_t n) {
    sink_t *b = ud;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 65536;
        while (nc < b->len + n) nc *= 2;
        uint8_t *nb = realloc(b->buf, nc);
        if (!nb) return -1;
        b->buf = nb;
        b->cap = nc;
    }
    memcpy(b->buf + b->len, msg, n);
    b->len += n;
    return 0;
}

#define MAXROWS 4096
typedef struct {
    db_record_row_t rows[MAXROWS];
    char name[MAXROWS][96], content[MAXROWS][96];
    size_t n;
} rows_t;

static void add(rows_t *r, int64_t id, const char *name, const char *type, const char *content, int64_t prio) {
    size_t i = r->n++;
    snprintf(r->name[i], sizeof(r->name[i]), "%s", name);
    snprintf(r->content[i], sizeof(r->content[i]), "%s", content);
    memset(&r->rows[i], 0, sizeof(r->rows[i]));
    r->rows[i].id = id; r->rows[i].name = r->name[i]; r->rows[i].type = type; r->rows[i].content = r->content[i]; r->rows[i].ttl = 300; r->rows[i].prio = prio;
}

/* the rows of zone z<i>.test as tests/db/gen_sqlite3_zones.sh makes them */
static void make_rows(rows_t *r, unsigned zi, unsigned rrs) {
    char zn[64], nm[96], ct[96];
    r->n = 0;
    snprintf(zn, sizeof(zn), "z%u.test", zi);
    int64_t id = 1;
    add(r, id++, zn, "SOA", "ns1.example.test. host.example.test. 1 3600 600 86400 300", 0);
    add(r, id++, zn, "NS", "ns1.example.test.", 0);
    add(r, id++, zn, "NS", "ns2.example.test.", 0);
    snprintf(ct, sizeof(ct), "192.0.2.%u", zi % 250 + 1);
    add(r, id++, zn, "A", ct, 0);
    snprintf(ct, sizeof(ct), "www.%s.", zn);
    add(r, id++, zn, "MX", ct, 10);
    snprintf(nm, sizeof(nm), "www.%s", zn);
    snprintf(ct, sizeof(ct), "192.0.2.%u", (zi + 7) % 250 + 1);
    add(r, id++, nm, "A", ct, 0);
    for (unsigned k = 1; k + 6 <= rrs && r->n < MAXROWS; k++) {
        snprintf(nm, sizeof(nm), "h%u.%s", k, zn);
        unsigned m = k % 20;
        if (m < 8) { snprintf(ct, sizeof(ct), "192.0.2.%u", (zi + k) % 250 + 1); add(r, id++, nm, "A", ct, 0); }
        else if (m < 12) { snprintf(ct, sizeof(ct), "www.%s.", zn); add(r, id++, nm, "CNAME", ct, 0); }
        else if (m < 15) { snprintf(ct, sizeof(ct), "2001:db8::%x", k); add(r, id++, nm, "AAAA", ct, 0); }
        else if (m < 19) { snprintf(ct, sizeof(ct), "\"v=%u-%u\"", zi, k); add(r, id++, nm, "TXT", ct, 0); }
        else { snprintf(ct, sizeof(ct), "www.%s.", zn); add(r, id++, nm, "MX", ct, 10); }
    }
}

static pdns_zone_t *make_zone(const rows_t *r, unsigned zi) {
    char zn[64];
    snprintf(zn, sizeof(zn), "z%u.test", zi);
    pdns_zone_t *z = pdns_zone_new(zn, NULL);
    if (!z) return NULL;
    for (size_t i = 0; i < r->n; i++) pdns_zone_add_record(z, &r->rows[i]);
    if (pdns_zone_finish(z) != 0) {
        fprintf(stderr, "zone %s: %s\n", zn, z->error);
        pdns_zone_free(z);
        return NULL;
    }
    return z;
}

int main(int argc, char **argv) {
    unsigned zones = argc > 1 ? (unsigned)atoi(argv[1]) : 20000, rrs = argc > 2 ? (unsigned)atoi(argv[2]) : 10;
    if (zones == 0 || rrs < 7) { fprintf(stderr, "usage: %s [ZONES [RRS_PER_ZONE >= 7]]\n", argv[0]); return 2; }
    rows_t *rows = malloc(sizeof(*rows));
    sink_t sk = { 0 }, ski = { 0 };
    double t_zone = 0, t_enc = 0, t_parse = 0, t_idx_old = 0, t_freeze_old = 0, t_build = 0, t_encimg = 0, t_idx = 0, t_freeze = 0, t_val = 0, t_valbase = 0, t_lim = 0;
    double bytes_old = 0, bytes_img = 0;
    char err[400], why[300];
    for (unsigned zi = 1; zi <= zones; zi++) {
        make_rows(rows, zi, rrs);
        double t0 = now_us();
        pdns_zone_t *z = make_zone(rows, zi), *z2 = make_zone(rows, zi);
        if (!z || !z2) return 1;
        t_zone += (now_us() - t0) / 2;

        /* the ZONE_DATA stream and what the Backend makes of it */
        pdns_kdb_params_t kp = { 0, 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL, 0 };
        sk.len = 0;
        t0 = now_us();
        if (pdns_zone_encode_kdb(z, &kp, sink_emit, &sk, err, sizeof(err)) != 0) { fprintf(stderr, "encode: %s\n", err); return 1; }
        t_enc += now_us() - t0;
        bytes_old += (double)sk.len;
        zone_arena_t sb;
        zone_arena_init(&sb);
        axfr_session_t sess;
        memset(&sess, 0, sizeof(sess));
        sess.db_stream = true;
        t0 = now_us();
        for (size_t off = 0; off < sk.len;) {          /* the messages: header (12 octets), type, length; ZONE_DATA bodies only */
            uint32_t bl = ((uint32_t)sk.buf[off + 8] << 24) | ((uint32_t)sk.buf[off + 9] << 16) | ((uint32_t)sk.buf[off + 10] << 8) | sk.buf[off + 11];
            uint16_t ty = (uint16_t)((sk.buf[off + 4] << 8) | sk.buf[off + 5]);
            if (ty == KDB_T_ZONE_DATA && parse_xfr_packet(sk.buf + off + 12, bl, &sb, NULL, &sess, z->name) != 0) { fprintf(stderr, "parse_xfr_packet\n"); return 1; }
            off += 12 + bl;
        }
        t_parse += now_us() - t0;
        t0 = now_us();
        zone_arena_drop_unencodable(&sb, NULL, NULL);
        zone_arena_shrink_records(&sb);
        build_zone_index(&sb, true);
        t_idx_old += now_us() - t0;
        t0 = now_us();
        zone_image_t *ib = zone_image_freeze(&sb, z->name);
        t_freeze_old += now_us() - t0;
        if (!ib) return 1;
        zone_image_free(ib);
        zone_arena_destroy(&sb);

        /* the image: the loader */
        t0 = now_us();
        zone_image_t *img = pdns_zone_build_image(z2, err, sizeof(err));
        t_build += now_us() - t0;
        if (!img) { fprintf(stderr, "build: %s\n", err); return 1; }
        bytes_img += (double)img->total_size;
        /* the parts, again by themselves on the arena that is built */
        t0 = now_us();
        build_zone_index(&z2->arena, true);
        t_idx += now_us() - t0;
        t0 = now_us();
        zone_image_t *again = zone_image_freeze(&z2->arena, z2->name);
        t_freeze += now_us() - t0;
        zone_image_free(again);
        zone_image_policy_t pol = { z2->name, z2->serial, img->n_rrs, img->total_size, z2->opts.max_zone_bytes, z2->opts.max_records, z2->has_ext,
                                    (img->flags & ZONE_IMAGE_F_TINYDNS) != 0 };
        t0 = now_us();
        int vr = zone_image_validate_ex(img, img->total_size, &pol, why, sizeof(why));
        t_val += now_us() - t0;
        t0 = now_us();
        int vb = zone_image_validate(img, img->total_size, why, sizeof(why));
        t_valbase += now_us() - t0;
        zone_limits_t lim = { 10000000, 100, 100, 0 };
        t0 = now_us();
        int lr = zone_image_check_limits(img, &lim, err, sizeof(err));
        t_lim += now_us() - t0;
        if (vr != 0 || vb != 0 || lr != 0) { fprintf(stderr, "validate %d %d limits %d: %s\n", vr, vb, lr, why); return 1; }
        zone_image_free(img);
        ski.len = 0;
        t0 = now_us();
        if (pdns_zone_encode_image(z2, &kp, sink_emit, &ski, err, sizeof(err)) != 0) { fprintf(stderr, "encode image: %s\n", err); return 1; }
        t_encimg += now_us() - t0;
        pdns_zone_free(z);
        pdns_zone_free(z2);
    }
    double n = (double)zones;
    printf("%u zones of %u RRs, microseconds per zone (one thread):\n", zones, rrs);
    printf("  rows -> zone (reader, both paths)               %8.1f\n", t_zone / n);
    printf("  ZONE_DATA, loader   pdns_zone_encode_kdb()      %8.1f   (%.0f bytes of stream)\n", t_enc / n, bytes_old / n);
    printf("  ZONE_DATA, Backend  parse_xfr_packet() x msgs   %8.1f\n", t_parse / n);
    printf("  ZONE_DATA, Backend  drop + index                %8.1f\n", t_idx_old / n);
    printf("  ZONE_DATA, Backend  zone_image_freeze()         %8.1f\n", t_freeze_old / n);
    printf("  ZONE_DATA, total after the reader               %8.1f\n", (t_enc + t_parse + t_idx_old + t_freeze_old) / n);
    printf("  image, loader       pdns_zone_build_image()     %8.1f   (%.0f bytes of image)\n", t_build / n, bytes_img / n);
    printf("      of it, by themselves: build_zone_index()    %8.1f\n", t_idx / n);
    printf("                            zone_image_freeze()   %8.1f\n", t_freeze / n);
    printf("                            validate_ex()         %8.1f   (zone_image_validate() alone %.1f)\n", t_val / n, t_valbase / n);
    printf("  image, loader       pdns_zone_encode_image()    %8.1f   (all of it: build, digest, messages)\n", t_encimg / n);
    printf("  image, Backend      validate_ex() + limits      %8.1f   (check_limits() %.1f)\n", (t_val + t_lim) / n, t_lim / n);
    free(sk.buf);
    free(ski.buf);
    free(rows);
    return 0;
}

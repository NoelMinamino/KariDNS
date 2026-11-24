/*
 * pdns_roundtrip.h - shared by tests/test_pdns_reader.c and tests/fuzz/fuzz_pdns_content.c.
 *
 * A converted zone is encoded with pdns_zone_encode_kdb() (the zone image the loader sends), the bytes go through the framer, decoder and Backend state machine (dns_db_stream.c), the
 * image is reassembled, validated as the Backend validates it (zone_image_validate_ex()) and thawed (zone_image_thaw()).  The RRs that come out must be the RRs that went in.
 *
 * Include after dns_pdns_reader.h and dns_axfr_ixfr.h; the translation unit needs the mocks of xfr_mocks.h.
 */
#ifndef PDNS_ROUNDTRIP_H
#define PDNS_ROUNDTRIP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <openssl/evp.h>

#include "../../dns_pdns_reader.h"
#include "../../dns_db_stream.h"
#include "../../dns_axfr_ixfr.h"
#include "../../dns_zone_image.h"

typedef struct { uint8_t *buf; size_t len, cap; size_t n_msgs; } rt_buf_t;

static int rt_emit(void *ud, const uint8_t *msg, size_t n) {
    rt_buf_t *b = ud;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + n) nc *= 2;
        uint8_t *nb = realloc(b->buf, nc);
        if (!nb) return -1;
        b->buf = nb;
        b->cap = nc;
    }
    memcpy(b->buf + b->len, msg, n);
    b->len += n;
    b->n_msgs++;
    return 0;
}

typedef struct {
    size_t n_chunks;              /* ZONE_IMAGE messages */
    size_t max_body;              /* largest ZONE_IMAGE body */
    uint64_t rr_count;            /* ZONE_BEGIN rr_count (the image's n_rrs: the RRs of the zone, the SOA among them once) */
    uint64_t image_size;          /* ZONE_BEGIN image_size */
    uint32_t serial;
    uint32_t flags;               /* ZONE_BEGIN flags without KDB_ZF_IMAGE (which every zone with rows has) */
    uint8_t digest[KDB_DIGEST_LEN];
    size_t stream_len;
} rt_info_t;

/* The canonical form the comparisons use: lowercase owner, type, class, TTL and the RDATA in canonical wire form
 * (dns_record_canonical_rdata: names of the RFC 4034 6.2 types in lowercase), as one line of text.  Owners differ in
 * case between a zone file and PowerDNS (which lowercases them), so the owner is compared case-insensitively. */
static char *rt_canon(const dns_record_t *r) {
    static uint8_t rd[65535];
    long n = dns_record_canonical_rdata(r, rd, sizeof(rd));
    size_t ol = r->name ? strlen(r->name) : 0;
    char *s = malloc(ol + 64 + (n > 0 ? (size_t)n * 2 : 8) + (r->bind_location_tag ? strlen(r->bind_location_tag) : 0) + (r->ecs_subnet_tag ? strlen(r->ecs_subnet_tag) : 0) + 64);
    if (!s) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < ol; i++) s[k++] = (char)tolower((unsigned char)r->name[i]);
    k += (size_t)sprintf(s + k, " %u %u %u ", (unsigned)r->type_code, (unsigned)(r->class_val ? r->class_val : 1),
                         (unsigned)(r->ttl_value > 0x7FFFFFFFu ? 0x7FFFFFFFu : r->ttl_value));
    if (n < 0) {
        strcpy(s + k, "ERR");
    } else {
        for (long i = 0; i < n; i++) k += (size_t)sprintf(s + k, "%02x", rd[i]);
        s[k] = '\0';
    }
    /* B8: the Extended AXFR attributes are part of the record: tags (compared without case, as the server matches them), tinydns time
     * stamp / countdown flag / location */
    k = strlen(s);
    if (r->bind_location_tag || r->ecs_subnet_tag || r->tinydns_ttd || r->tinydns_loc[0] || r->tinydns_loc[1]) {
        k += (size_t)sprintf(s + k, " |loc=");
        for (const char *p = r->bind_location_tag; p && *p; p++) s[k++] = (char)tolower((unsigned char)*p);
        k += (size_t)sprintf(s + k, "|ecs=");
        for (const char *p = r->ecs_subnet_tag; p && *p; p++) s[k++] = (char)tolower((unsigned char)*p);
        k += (size_t)sprintf(s + k, "|td=%lld|%d|%02x%02x", (long long)r->tinydns_ttd, r->tinydns_ttl_countdown ? 1 : 0,
                             (unsigned)(uint8_t)r->tinydns_loc[0], (unsigned)(uint8_t)r->tinydns_loc[1]);
    }
    return s;
}

/* B8: the zone level tables of an arena as one text, flattened the way the database holds them: every (tag, CIDR) of the location
 * definitions, of the ECS definitions, and every tinydns location, in definition order.  Two consecutive definitions of one tag and
 * one definition with all their CIDRs read the same (the first matching tag wins), so the zone file and the database give one text. */
static char *rt_flat_tables(const zone_arena_t *a) {
    size_t cap = 256;
    for (int i = 0; i < a->bind_location_tag_count; i++)
        for (int j = 0; j < a->bind_location_tags[i].cidr_count; j++) cap += strlen(a->bind_location_tags[i].tag) + strlen(a->bind_location_tags[i].cidrs[j].cidr) + 8;
    for (int i = 0; i < a->bind_ecs_tag_count; i++)
        for (int j = 0; j < a->bind_ecs_tags[i].cidr_count; j++) cap += strlen(a->bind_ecs_tags[i].tag) + strlen(a->bind_ecs_tags[i].cidrs[j].cidr) + 8;
    cap += (size_t)a->location_count * 40;
    char *s = malloc(cap);
    if (!s) return NULL;
    size_t k = 0;
    for (int i = 0; i < a->bind_location_tag_count; i++)
        for (int j = 0; j < a->bind_location_tags[i].cidr_count; j++)
            k += (size_t)sprintf(s + k, "L %s %s\n", a->bind_location_tags[i].tag, a->bind_location_tags[i].cidrs[j].cidr);
    for (int i = 0; i < a->bind_ecs_tag_count; i++)
        for (int j = 0; j < a->bind_ecs_tags[i].cidr_count; j++)
            k += (size_t)sprintf(s + k, "E %s %s\n", a->bind_ecs_tags[i].tag, a->bind_ecs_tags[i].cidrs[j].cidr);
    for (int i = 0; i < a->location_count; i++) {
        const tinydns_location_entry_t *l = &a->locations[i];
        k += (size_t)sprintf(s + k, "T %02x%02x %u.%u.%u.%u/%u\n", (unsigned)(uint8_t)l->code[0], (unsigned)(uint8_t)l->code[1], l->prefix[0], l->prefix[1],
                             l->prefix[2], l->prefix[3], l->prefix_bits);
    }
    s[k] = '\0';
    return s;
}

static int rt_cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* canonical lines of an arena, sorted; the caller frees each line and the array */
static char **rt_sorted_lines(const zone_arena_t *a, size_t *n_out) {
    char **v = calloc(a->count ? a->count : 1, sizeof(char *));
    if (!v) return NULL;
    for (size_t i = 0; i < a->count; i++) {
        v[i] = rt_canon(&a->records[i]);
        if (!v[i]) {
            for (size_t j = 0; j < i; j++) free(v[j]);
            free(v);
            return NULL;
        }
    }
    qsort(v, a->count, sizeof(char *), rt_cmp_str);
    *n_out = a->count;
    return v;
}

static void rt_free_lines(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

/* ---- 0.7 M3: the zone image of a database zone, as the loader sends it and the Backend reads it ----
 *
 * pdns_zone_encode_kdb() builds the image of the zone (it changes z: the arena is reordered and indexed as the image is) and writes ZONE_BEGIN, ZONE_IMAGE messages and ZONE_END.  The stream goes
 * through the framer and the state machine of dns_db_stream.c, the image is reassembled, checked the way the Backend checks it (zone_image_validate_ex() with the policy that ZONE_BEGIN gives:
 * size, count, serial, flags, the limits of the zone) and turned back into a builder with zone_image_thaw().  The RRs that come out must be the RRs that went in (z->arena, after the encode),
 * the tag and location tables the same, ZONE_BEGIN must say what the zone and the image say, and the digest is SHA-256 of the image bytes (plus the markers: see image_digest() in dns_pdns_reader.c). */
#define RT_FAIL(...) do { snprintf(why, whylen, __VA_ARGS__); goto done; } while (0)

/* true: the round trip gave the zone back.  why gets the reason otherwise.  info may be NULL.  z is changed (see above). */
static bool pdns_roundtrip(pdns_zone_t *z, rt_info_t *info, char *why, size_t whylen) {
    bool ok = false;
    rt_buf_t out = {0};
    uint8_t *fbuf = malloc(KDB_MAX_BODY);
    uint8_t *img = NULL;
    size_t have = 0, want_size = 0;
    zone_arena_t standby;
    zone_arena_init(&standby);
    char **want = NULL, **got = NULL;
    size_t nwant = 0, ngot = 0;
    rt_info_t inf;
    memset(&inf, 0, sizeof(inf));
    if (!fbuf) RT_FAIL("out of memory");

    char err[400] = "";
    pdns_kdb_params_t kp = { 3, 4711, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL, 0 };
    int erc = pdns_zone_encode_kdb(z, &kp, rt_emit, &out, err, sizeof(err));
    if (erc != 0) RT_FAIL("encode: %s", err);
    inf.stream_len = out.len;

    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_LOADER, fbuf, KDB_MAX_BODY);
    kdb_sm_t sm;
    kdb_sm_init(&sm, NULL);
    sm.state = KDB_S_IN_BATCH;          /* the HELLO / BATCH_BEGIN preamble is not the subject here */
    kdb_rc_t rc = kdb_framer_feed(&f, out.buf, out.len);
    if (rc != KDB_OK) RT_FAIL("framer feed: %s", kdb_rc_name(rc));
    bool begun = false, ended = false;
    uint32_t zflags = 0;
    uint64_t zrr = 0;
    for (;;) {
        kdb_frame_t fr;
        rc = kdb_framer_next(&f, &fr);
        if (rc == KDB_MORE) break;
        if (rc != KDB_OK) RT_FAIL("framer: %s (%s)", kdb_rc_name(rc), f.reason);
        kdb_msg_t m;
        rc = kdb_sm_accept(&sm, &fr, &m);
        if (rc != KDB_OK) RT_FAIL("state machine: %s (%s)", kdb_rc_name(rc), sm.reason);
        if (ended) RT_FAIL("message after ZONE_END");
        if (fr.type == KDB_T_ZONE_BEGIN) {
            begun = true;
            zflags = m.u.zone_begin.flags;
            zrr = m.u.zone_begin.rr_count;
            inf.rr_count = zrr;
            inf.image_size = m.u.zone_begin.image_size;
            inf.serial = m.u.zone_begin.serial;
            inf.flags = zflags & ~(uint32_t)KDB_ZF_IMAGE;
            memcpy(inf.digest, m.u.zone_begin.digest, KDB_DIGEST_LEN);
            if (strcmp(m.u.zone_begin.name, z->name) != 0) RT_FAIL("ZONE_BEGIN name '%s'", m.u.zone_begin.name);
            if (m.u.zone_begin.serial != z->serial) RT_FAIL("ZONE_BEGIN serial");
            if (!(zflags & KDB_ZF_IMAGE) || inf.image_size == 0 || inf.image_size > (1u << 30)) RT_FAIL("ZONE_BEGIN is not an image zone (flags 0x%x, size %llu)", zflags, (unsigned long long)inf.image_size);
            want_size = (size_t)inf.image_size;
            img = malloc(want_size);                          /* (malloc: 8-aligned, as the Backend's reassembly buffer is) */
            if (!img) RT_FAIL("out of memory");
        } else if (fr.type == KDB_T_ZONE_IMAGE) {
            inf.n_chunks++;
            if (fr.len > inf.max_body) inf.max_body = fr.len;
            if (!img || have + fr.len > want_size) RT_FAIL("more image octets than ZONE_BEGIN announced");
            memcpy(img + have, m.u.zone_image.body, fr.len);
            have += fr.len;
        } else if (fr.type == KDB_T_ZONE_END) {
            ended = true;
        }
    }
    if (!begun || !ended) RT_FAIL("stream without ZONE_BEGIN / ZONE_END");
    if (have != want_size) RT_FAIL("%zu image octets, ZONE_BEGIN announced %zu", have, want_size);
    {
        zone_image_policy_t pol = { z->name, z->serial, zrr, inf.image_size, z->opts.max_zone_bytes, z->opts.max_records, (zflags & KDB_ZF_EXTENDED) != 0, (zflags & KDB_ZF_TINYDNS) != 0, false };
        char vw[300];
        if (zone_image_validate_ex(img, have, &pol, vw, sizeof(vw)) != 0) RT_FAIL("the Backend's validation refuses the image: %s", vw);
    }
    if (!(z->flags & PDNS_F_PRESIGNED) && !(z->settings && *z->settings) && !z->profile[0]) {      /* the digest is SHA-256 of the image bytes, with nothing after them */
        uint8_t dg[EVP_MAX_MD_SIZE];
        unsigned dl = 0;
        if (EVP_Digest(img, have, dg, &dl, EVP_sha256(), NULL) != 1 || dl != KDB_DIGEST_LEN || memcmp(dg, inf.digest, dl) != 0) RT_FAIL("the digest is not SHA-256 of the image");
    }
    {   /* the other digests: SHA-256 of the image and the markers (a PRESIGNED zone) */
        const zone_image_t *zi = (const zone_image_t *)img;
        if (((zflags & KDB_ZF_EXTENDED) != 0) != z->has_ext) RT_FAIL("ZONE_BEGIN flags 0x%x but the zone has_ext is %d", zflags, (int)z->has_ext);
        if (((zflags & KDB_ZF_PRESIGNED) != 0) != ((z->flags & PDNS_F_PRESIGNED) != 0)) RT_FAIL("ZONE_BEGIN flags 0x%x, the zone presigned flag is %d", zflags, (int)((z->flags & PDNS_F_PRESIGNED) != 0));
        if (((zflags & KDB_ZF_TINYDNS) != 0) != ((zi->flags & ZONE_IMAGE_F_TINYDNS) != 0)) RT_FAIL("ZONE_BEGIN flags 0x%x, the image says tinydns %d", zflags, (int)((zi->flags & ZONE_IMAGE_F_TINYDNS) != 0));
        if ((z->flags & PDNS_F_TINYDNS) && !(zflags & KDB_ZF_TINYDNS)) RT_FAIL("ZONE_BEGIN flags 0x%x lack the tinydns bit", zflags);
        if (zi->n_rrs != z->arena.count) RT_FAIL("the image has %u RRs, the zone %zu", (unsigned)zi->n_rrs, z->arena.count);
    }
    if (zone_image_thaw((const zone_image_t *)img, &standby) != 0) RT_FAIL("thaw failed");
    {
        char *tin = rt_flat_tables(&z->arena), *tout = rt_flat_tables(&standby);
        bool same = tin && tout && strcmp(tin, tout) == 0;
        free(tin);
        free(tout);
        if (!same) RT_FAIL("the tag and location definitions that came out are not the ones that went in");
    }
    if (standby.count != z->arena.count) RT_FAIL("%zu RRs came back, %zu went in", standby.count, z->arena.count);
    if (standby.count == 0) RT_FAIL("an image without RRs");

    want = rt_sorted_lines(&z->arena, &nwant);
    got = rt_sorted_lines(&standby, &ngot);
    if (!want || !got) RT_FAIL("out of memory");
    for (size_t i = 0; i < nwant; i++)
        if (strcmp(want[i], got[i]) != 0) RT_FAIL("RR differs: in '%.150s' out '%.150s'", want[i], got[i]);
    ok = true;
done:
    if (want) rt_free_lines(want, nwant);
    if (got) rt_free_lines(got, ngot);
    zone_arena_destroy(&standby);
    free(img);
    free(fbuf);
    free(out.buf);
    if (info) *info = inf;
    return ok;
}
#undef RT_FAIL

/* Is the zone's error the reader's own "internal error" (a bug for the harnesses)?  The message is "zone 'Z': MSG" or
 * "zone 'Z' records.id N: MSG" and MSG may quote row text, so only an MSG that starts with "internal error" counts (a
 * fuzzed tag name "einternal error.0/24" inside a message is not one). */
static inline bool pdns_error_is_internal(const pdns_zone_t *z) {
    const char *e = z->error;
    size_t zl = strlen(z->name);
    if (strncmp(e, "zone '", 6) != 0 || strncmp(e + 6, z->name, zl) != 0 || e[6 + zl] != '\'') return false;
    const char *p = e + 6 + zl + 1;
    if (strncmp(p, " records.id ", 12) == 0) {
        p += 12;
        if (*p == '-') p++;
        while (isdigit((unsigned char)*p)) p++;
    }
    if (strncmp(p, ": ", 2) != 0) return false;
    return strncmp(p + 2, "internal error", 14) == 0;
}

#endif

/*
 * pdns_roundtrip.h - shared by tests/test_pdns_reader.c and tests/fuzz/fuzz_pdns_content.c.
 *
 * A converted zone is encoded with pdns_zone_encode_kdb(), the bytes go through the B1 framer, decoder and Backend
 * state machine (dns_db_stream.c) and every ZONE_DATA message through parse_xfr_packet() (dns_axfr_ixfr.c), the way
 * the Backend ingest will read it.  The RRs that come out must be the RRs that went in.
 *
 * Include after dns_pdns_reader.h and dns_axfr_ixfr.h; the translation unit needs the mocks of xfr_mocks.h.
 *
 * 0.7 M3 step 1: with image_diff the zone is also built as the image the loader will send (pdns_zone_build_image(), which changes the zone: the arena is
 * reordered and indexed as the image is) and that image is compared byte for byte with the one the Backend makes of the stream it has read (rt_image_diff()).
 * pdns_roundtrip() does it when the translation unit defines RT_IMAGE_DIFF as 1 before it includes this file.
 */
#ifndef RT_IMAGE_DIFF
#define RT_IMAGE_DIFF 0
#endif
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
    size_t n_zone_data;           /* ZONE_DATA messages */
    size_t max_body;              /* largest ZONE_DATA body */
    uint64_t rr_count;            /* ZONE_BEGIN rr_count (both SOAs) */
    uint32_t serial;
    uint32_t flags;
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

/* ---- 0.7 M3 step 1: the image the loader builds against the image the Backend builds from the ZONE_DATA stream ----
 *
 * `sb` is the zone as the Backend read it from the stream (the arena parse_xfr_packet() filled; the ZONE_BEGIN flags are `zflags`): what db_zone_build_install() and
 * zone_install_builder() do with it is done here (the tinydns flag, the unencodable RRs dropped, the arena shrunk, build_zone_index(true), zone_image_freeze() with the
 * name of the zone), and the image that comes out is compared byte for byte with the one pdns_zone_build_image() makes of the loader's arena (which it changes: z is
 * consumed).  Then the stream pdns_zone_encode_image() writes goes through the framer and the state machine with images accepted: the image that is reassembled is that
 * image, ZONE_BEGIN says what the image says, the digest is what it should be, and the validation the Backend will run accepts it. */
static const char *rt_section_of(const zone_image_t *img, size_t off) {
    const struct { const char *name; uint32_t start; } sec[] = {
        { "header", 0 }, { "names", img->off_names }, { "rrs", img->off_rrs }, { "ext", img->off_ext }, { "n3chains", img->off_n3chains }, { "hash", img->off_hash },
        { "canon", img->off_canon }, { "nsec", img->off_nsec }, { "n3entries", img->off_n3entries }, { "glue", img->off_glue }, { "perm", img->off_perm },
        { "zattr", img->off_zattr }, { "strings", img->off_strings } };
    const char *best = "header";
    uint32_t best_start = 0;
    for (size_t i = 0; i < sizeof(sec) / sizeof(sec[0]); i++)
        if (sec[i].start && sec[i].start <= off && sec[i].start >= best_start) { best = sec[i].name; best_start = sec[i].start; }
    return best;
}

static bool rt_image_diff(pdns_zone_t *z, zone_arena_t *sb, uint32_t zflags, char *why, size_t whylen) {
    bool ok = false;
    zone_image_t *A = NULL, *B = NULL, *A2 = NULL;
    rt_buf_t out = { 0 };
    uint8_t *got = NULL;
    char err[400] = "";
#define RTI_FAIL(...) do { snprintf(why, whylen, "image: " __VA_ARGS__); goto done; } while (0)
    /* the Backend */
    if (zflags & KDB_ZF_TINYDNS) sb->is_tinydns_format = true;
    zone_arena_drop_unencodable(sb, NULL, NULL);
    zone_arena_shrink_records(sb);
    if (build_zone_index(sb, true) != 0) RTI_FAIL("the Backend's index (out of memory)");
    B = zone_image_freeze(sb, z->name);
    /* the loader */
    A = pdns_zone_build_image(z, err, sizeof(err));
    if (!B) {
        if (A) RTI_FAIL("the Backend cannot freeze this zone, the loader built an image");
        ok = true;                                    /* both refuse it */
        goto done;
    }
    if (!A && strstr(err, "same clients")) {          /* db_zone_build_install() refuses two SOA RRs that the same clients see; the transfer parser, which this test stops at, does not */
        ok = true;
        goto done;
    }
    if (!A) RTI_FAIL("the loader cannot build the image the Backend builds (%zu bytes): %s", (size_t)B->total_size, err);
    if (A->total_size != B->total_size || memcmp(A, B, A->total_size) != 0) {
        size_t n = A->total_size < B->total_size ? A->total_size : B->total_size, at = 0;
        while (at < n && ((const uint8_t *)A)[at] == ((const uint8_t *)B)[at]) at++;
        char where[160] = "";
        if (strcmp(rt_section_of(A, at), "rrs") == 0 && A->n_rrs == B->n_rrs) {       /* RR index and field (zone_image_rr_t) */
            size_t k = (at - A->off_rrs) / sizeof(zone_image_rr_t), fo = (at - A->off_rrs) % sizeof(zone_image_rr_t);
            const zone_image_rr_t *ra = &zone_image_rrs(A)[k], *rb = &zone_image_rrs(B)[k];
            snprintf(where, sizeof(where), ": RR %zu (type %u, '%.60s') field offset %zu, flags loader %x Backend %x", k, (unsigned)ra->type,
                     zone_image_name_text(A, ra->name_id), fo, (unsigned)ra->flags, (unsigned)rb->flags);
        }
        RTI_FAIL("the loader's image (%u bytes) differs from the Backend's (%u bytes), first at offset %zu in the %s%s (loader n_names %u n_rrs %u n_ext %u flags %x, Backend %u %u %u %x)",
                 A->total_size, B->total_size, at, rt_section_of(A, at), where, A->n_names, A->n_rrs, A->n_ext, A->flags, B->n_names, B->n_rrs, B->n_ext, B->flags);
    }
    /* what is built from a zone that is built is the same image again */
    A2 = pdns_zone_build_image(z, err, sizeof(err));
    if (!A2 || A2->total_size != A->total_size || memcmp(A, A2, A->total_size) != 0) RTI_FAIL("building the image twice gives two images");
    /* the stream */
    {
        pdns_kdb_params_t kp = { 3, 4711, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL, 0 };
        if (pdns_zone_encode_image(z, &kp, rt_emit, &out, err, sizeof(err)) != 0) RTI_FAIL("encode: %s", err);
        uint8_t *fbuf = malloc(KDB_MAX_BODY);
        got = malloc(A->total_size + 8);
        if (!fbuf || !got) { free(fbuf); RTI_FAIL("out of memory"); }
        kdb_framer_t f;
        kdb_framer_init(&f, KDB_FROM_LOADER, fbuf, KDB_MAX_BODY);
        kdb_sm_t sm;
        kdb_sm_init(&sm, NULL);
        sm.state = KDB_S_IN_BATCH;
        sm.image_hello = true;
        kdb_sm_set_image(&sm, true);
        kdb_rc_t rc = kdb_framer_feed(&f, out.buf, out.len);
        size_t have = 0;
        bool begun = false, ended = false;
        uint8_t digest[KDB_DIGEST_LEN];
        while (rc == KDB_OK) {
            kdb_frame_t fr;
            rc = kdb_framer_next(&f, &fr);
            if (rc == KDB_MORE) { rc = KDB_OK; break; }
            if (rc != KDB_OK) break;
            kdb_msg_t m;
            rc = kdb_sm_accept(&sm, &fr, &m);
            if (rc != KDB_OK) break;
            if (fr.type == KDB_T_ZONE_BEGIN) {
                begun = true;
                if (!(m.u.zone_begin.flags & KDB_ZF_IMAGE) || m.u.zone_begin.image_size != A->total_size || m.u.zone_begin.rr_count != A->n_rrs ||
                    m.u.zone_begin.serial != z->serial || strcmp(m.u.zone_begin.name, z->name) != 0) { free(fbuf); RTI_FAIL("ZONE_BEGIN does not say what the image says"); }
                /* the flags of the old stream are the new ones, but for the image flag, and the tinydns flag that the image has also for a zone with locations */
                if ((m.u.zone_begin.flags & ~(KDB_ZF_IMAGE | KDB_ZF_TINYDNS)) != (zflags & ~KDB_ZF_TINYDNS) ||
                    ((m.u.zone_begin.flags & KDB_ZF_TINYDNS) != 0) != ((A->flags & ZONE_IMAGE_F_TINYDNS) != 0))
                { free(fbuf); RTI_FAIL("ZONE_BEGIN flags %x, the ZONE_DATA stream had %x", m.u.zone_begin.flags, zflags); }
                memcpy(digest, m.u.zone_begin.digest, KDB_DIGEST_LEN);
            } else if (fr.type == KDB_T_ZONE_IMAGE) {
                if (have + fr.len > A->total_size) { free(fbuf); RTI_FAIL("more image octets than the image has"); }
                memcpy(got + have, m.u.zone_image.body, fr.len);
                have += fr.len;
            } else if (fr.type == KDB_T_ZONE_END) {
                ended = true;
            }
        }
        free(fbuf);
        if (rc != KDB_OK) RTI_FAIL("the stream: %s (%s)", kdb_rc_name(rc), sm.reason);
        if (!begun || !ended || have != A->total_size || memcmp(got, A, A->total_size) != 0) RTI_FAIL("the stream does not carry the image");
        if (!(z->flags & PDNS_F_PRESIGNED) && !(z->settings && *z->settings) && !z->profile[0]) {
            uint8_t want[EVP_MAX_MD_SIZE];
            unsigned wl = 0;
            if (EVP_Digest(A, A->total_size, want, &wl, EVP_sha256(), NULL) != 1 || wl != KDB_DIGEST_LEN || memcmp(want, digest, KDB_DIGEST_LEN) != 0)
                RTI_FAIL("the digest is not SHA-256 of the image");
        }
        zone_image_policy_t pol = { z->name, z->serial, A->n_rrs, A->total_size, z->opts.max_zone_bytes, z->opts.max_records, (zflags & KDB_ZF_EXTENDED) != 0,
                                    (A->flags & ZONE_IMAGE_F_TINYDNS) != 0 };
        char vw[300];
        if (zone_image_validate_ex(got, have, &pol, vw, sizeof(vw)) != 0) RTI_FAIL("the Backend's validation refuses it: %s", vw);
    }
    ok = true;
done:
#undef RTI_FAIL
    zone_image_free(A);
    zone_image_free(A2);
    free(B);
    free(out.buf);
    free(got);
    return ok;
}

#define RT_FAIL(...) do { snprintf(why, whylen, __VA_ARGS__); goto done; } while (0)

/* true: the round trip gave the zone back.  why gets the reason otherwise.  info may be NULL.  image_diff: see above; z is then changed. */
static bool pdns_roundtrip_ex(pdns_zone_t *z, bool image_diff, rt_info_t *info, char *why, size_t whylen) {
    bool ok = false;
    rt_buf_t out = {0};
    uint8_t *fbuf = malloc(KDB_MAX_BODY);
    zone_arena_t standby;
    zone_arena_init(&standby);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.db_stream = true;            // B8: the Backend reads the loader's stream strictly (dns_db_install.c)
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    char **want = NULL, **got = NULL;
    size_t nwant = 0, ngot = 0;
    rt_info_t inf;
    memset(&inf, 0, sizeof(inf));
    if (!fbuf || !md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) RT_FAIL("out of memory");

    char err[300] = "";
    pdns_kdb_params_t kp = { 3, 4711, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL, 0 };
    if (pdns_zone_encode_kdb(z, &kp, rt_emit, &out, err, sizeof(err)) != 0) RT_FAIL("encode: %s", err);
    inf.stream_len = out.len;

    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_LOADER, fbuf, KDB_MAX_BODY);
    kdb_sm_t sm;
    kdb_sm_init(&sm, NULL);
    sm.state = KDB_S_IN_BATCH;          /* the HELLO / BATCH_BEGIN preamble is not the subject here */
    kdb_rc_t rc = kdb_framer_feed(&f, out.buf, out.len);
    if (rc != KDB_OK) RT_FAIL("framer feed: %s", kdb_rc_name(rc));
    bool begun = false, ended = false;
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
            inf.rr_count = m.u.zone_begin.rr_count;
            inf.serial = m.u.zone_begin.serial;
            inf.flags = m.u.zone_begin.flags;
            memcpy(inf.digest, m.u.zone_begin.digest, KDB_DIGEST_LEN);
            if (strcmp(m.u.zone_begin.name, z->name) != 0) RT_FAIL("ZONE_BEGIN name '%s'", m.u.zone_begin.name);
            if (m.u.zone_begin.serial != z->serial) RT_FAIL("ZONE_BEGIN serial");
        } else if (fr.type == KDB_T_ZONE_DATA) {
            inf.n_zone_data++;
            if (m.u.zone_data.len > inf.max_body) inf.max_body = m.u.zone_data.len;
            if (EVP_DigestUpdate(md, m.u.zone_data.body, m.u.zone_data.len) != 1) RT_FAIL("digest");
            if (parse_xfr_packet(m.u.zone_data.body, m.u.zone_data.len, &standby, NULL, &session, z->name) != 0)
                RT_FAIL("parse_xfr_packet rejected ZONE_DATA message %zu", inf.n_zone_data);
        } else if (fr.type == KDB_T_ZONE_END) {
            ended = true;
        }
    }
    if (!begun || !ended) RT_FAIL("stream without ZONE_BEGIN / ZONE_END");
    {
        if (inf.flags & KDB_ZF_TINYDNS) {                       /* B8: the tinydns flag is part of the digest (dns_pdns_reader.c) */
            static const uint8_t ftag[] = "KDB1-TINYDNS";
            EVP_DigestUpdate(md, ftag, sizeof(ftag));
        }
        if (inf.flags & KDB_ZF_PRESIGNED) {                     /* L2: so is the PRESIGNED flag (a toggle with unchanged rows must change the digest) */
            static const uint8_t ptag[] = "KDB1-PRESIGNED";
            EVP_DigestUpdate(md, ptag, sizeof(ptag));
        }
        uint8_t dg[EVP_MAX_MD_SIZE];
        unsigned dl = 0;
        if (EVP_DigestFinal_ex(md, dg, &dl) != 1 || dl != KDB_DIGEST_LEN || memcmp(dg, inf.digest, dl) != 0)
            RT_FAIL("digest in ZONE_BEGIN does not match the ZONE_DATA bodies");
    }
    if (!session.is_finished) RT_FAIL("transfer not finished (closing SOA missing)");
    /* B8t-2: the opening SOA of a SOA set (SOA_SET) is the frame and is not stored */
    if (standby.count + 1 + session.ext_records + (session.soa_set ? 1 : 0) != inf.rr_count)
        RT_FAIL("rr_count %llu but %zu RRs and %llu extension RRs parsed", (unsigned long long)inf.rr_count, standby.count + 1,
                (unsigned long long)session.ext_records);
    if (((inf.flags & KDB_ZF_EXTENDED) != 0) != z->has_ext || (z->has_ext != (session.ext_records > 0 || session.ext_wrapped > 0)))
        RT_FAIL("ZONE_BEGIN flags 0x%x but the zone has_ext is %d and %llu extension RRs were read", inf.flags, (int)z->has_ext,
                (unsigned long long)session.ext_records);
    if (((inf.flags & KDB_ZF_TINYDNS) != 0) != ((z->flags & PDNS_F_TINYDNS) != 0)) RT_FAIL("ZONE_BEGIN flags 0x%x lack the tinydns bit", inf.flags);
    {
        char *tin = rt_flat_tables(&z->arena), *tout = rt_flat_tables(&standby);
        bool same = tin && tout && strcmp(tin, tout) == 0;
        free(tin);
        free(tout);
        if (!same) RT_FAIL("the tag and location definitions that came out are not the ones that went in");
    }
    /* the flag alone is applied by db_zone_build_new() (dns_db_install.c), not by the transfer parser */
    {   /* a wrapper without a tinydns attribute (a SOA of a SOA set that has a tag only) does not make a tinydns zone */
        bool tattr = z->arena.location_count > 0;
        for (size_t k = 0; k < z->arena.count; k++)
            if (z->arena.records[k].tinydns_loc[0] || z->arena.records[k].tinydns_loc[1] || z->arena.records[k].tinydns_ttd) tattr = true;
        if (tattr != standby.is_tinydns_format) RT_FAIL("is_tinydns_format %d after the transfer", (int)standby.is_tinydns_format);
    }
    if (standby.count != z->arena.count) RT_FAIL("%zu RRs came back, %zu went in", standby.count, z->arena.count);
    if (standby.count == 0 || (!session.soa_set && standby.records[0].type_code != 6)) RT_FAIL("first RR is not the SOA");

    want = rt_sorted_lines(&z->arena, &nwant);
    got = rt_sorted_lines(&standby, &ngot);
    if (!want || !got) RT_FAIL("out of memory");
    for (size_t i = 0; i < nwant; i++)
        if (strcmp(want[i], got[i]) != 0) RT_FAIL("RR differs: in '%.150s' out '%.150s'", want[i], got[i]);
    if (image_diff && !rt_image_diff(z, &standby, inf.flags, why, whylen)) goto done;
    ok = true;
done:
    if (want) rt_free_lines(want, nwant);
    if (got) rt_free_lines(got, ngot);
    EVP_MD_CTX_free(md);
    zone_arena_destroy(&standby);
    free(fbuf);
    free(out.buf);
    if (info) *info = inf;
    return ok;
}
#undef RT_FAIL

static bool pdns_roundtrip(pdns_zone_t *z, rt_info_t *info, char *why, size_t whylen) { return pdns_roundtrip_ex(z, RT_IMAGE_DIFF != 0, info, why, whylen); }

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

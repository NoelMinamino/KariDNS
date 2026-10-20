/*
 * pdns_roundtrip.h - shared by tests/test_pdns_reader.c and tests/fuzz/fuzz_pdns_content.c.
 *
 * A converted zone is encoded with pdns_zone_encode_kdb(), the bytes go through the B1 framer, decoder and Backend
 * state machine (dns_db_stream.c) and every ZONE_DATA message through parse_xfr_packet() (dns_axfr_ixfr.c), the way
 * the Backend ingest will read it.  The RRs that come out must be the RRs that went in.
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
    /* Known gap (reported, not fixed here): parse_resource_record() keeps a zero-length RDATA of a type it has no decoder
     * for as generic_data == NULL, so the record has no readable RDATA (the zone parser uses an empty string). Compare
     * it as the empty RDATA it is. */
    if (n < 0 && r->generic_data == NULL && r->generic_len == 0 && r->rdata_count == 0) n = 0;
    size_t ol = r->name ? strlen(r->name) : 0;
    char *s = malloc(ol + 64 + (n > 0 ? (size_t)n * 2 : 8));
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

#define RT_FAIL(...) do { snprintf(why, whylen, __VA_ARGS__); goto done; } while (0)

/* true: the round trip gave the zone back.  why gets the reason otherwise.  info may be NULL. */
static bool pdns_roundtrip(const pdns_zone_t *z, rt_info_t *info, char *why, size_t whylen) {
    bool ok = false;
    rt_buf_t out = {0};
    uint8_t *fbuf = malloc(KDB_MAX_BODY);
    zone_arena_t standby;
    zone_arena_init(&standby);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    char **want = NULL, **got = NULL;
    size_t nwant = 0, ngot = 0;
    rt_info_t inf;
    memset(&inf, 0, sizeof(inf));
    if (!fbuf || !md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) RT_FAIL("out of memory");

    char err[300] = "";
    pdns_kdb_params_t kp = { 3, 4711, KDB_ZK_PRIMARY, NULL };
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
        uint8_t dg[EVP_MAX_MD_SIZE];
        unsigned dl = 0;
        if (EVP_DigestFinal_ex(md, dg, &dl) != 1 || dl != KDB_DIGEST_LEN || memcmp(dg, inf.digest, dl) != 0)
            RT_FAIL("digest in ZONE_BEGIN does not match the ZONE_DATA bodies");
    }
    if (!session.is_finished) RT_FAIL("transfer not finished (closing SOA missing)");
    if (standby.count + 1 != inf.rr_count) RT_FAIL("rr_count %llu but %zu RRs parsed", (unsigned long long)inf.rr_count, standby.count);
    if (standby.count != z->arena.count) RT_FAIL("%zu RRs came back, %zu went in", standby.count, z->arena.count);
    if (standby.count == 0 || standby.records[0].type_code != 6) RT_FAIL("first RR is not the SOA");

    want = rt_sorted_lines(&z->arena, &nwant);
    got = rt_sorted_lines(&standby, &ngot);
    if (!want || !got) RT_FAIL("out of memory");
    for (size_t i = 0; i < nwant; i++)
        if (strcmp(want[i], got[i]) != 0) RT_FAIL("RR differs: in '%.150s' out '%.150s'", want[i], got[i]);
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

#endif

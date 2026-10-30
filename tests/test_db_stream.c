/*
 * test_db_stream.c - KDB1 stream codec and Backend state machine (dns_db_stream.c).
 *
 * Round trip of every message type, one test per rejection rule of the framer / decoder / state machine, and
 * byte-at-a-time feeding against whole-buffer feeding.  Expected values come from the protocol rules in
 * dns_db_stream.h (beta design 1.4), RFC 1035 4.1.1 (header layout) and RFC 5936 2.2 (AXFR message rules).
 *
 * `test_db_stream --gen-corpus DIR` writes the seed corpus of tests/fuzz/fuzz_db_stream.c (valid streams).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>

#include "../dns_db_stream.h"
#include "../dns_db_checkproto.h"

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_RC(label, got, want) do { g_checks++; kdb_rc_t g_ = (got), w_ = (want); if (g_ != w_) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: got %s (%d), want %s (%d)\n", __FILE__, __LINE__, label, kdb_rc_name(g_), (int)g_, \
           kdb_rc_name(w_), (int)w_); } } while (0)
#define CHECK_STR(actual, expected) do { g_checks++; const char *a_ = (actual); const char *e_ = (expected); \
    if (!a_ || strcmp(a_, e_) != 0) { g_failed++; printf("  [FAIL] %s:%d: %s == \"%s\" (got \"%s\")\n", \
        __FILE__, __LINE__, #actual, e_, a_ ? a_ : "(null)"); } } while (0)

#define ZN "example.test."
#define NVIEWS 3

static uint8_t g_rbuf[KDB_MAX_BODY];

/* ---------------------------------------------------------------- message builders (loader side) */
static void m_hello(kdb_enc_t *e, uint16_t ver) {
    kdb_enc_begin(e, KDB_T_HELLO);
    kdb_enc_u16(e, 1, ver);
    kdb_enc_str(e, 2, "karidns-dbloader 0.6");
    kdb_enc_str(e, 3, "sqlite3");
    kdb_enc_u32(e, 4, 1234);
    kdb_enc_end(e);
}
static void m_inv_req(kdb_enc_t *e) { kdb_enc_begin(e, KDB_T_INVENTORY_REQ); kdb_enc_end(e); }
static void m_batch_begin(kdb_enc_t *e, uint64_t id) {
    kdb_enc_begin(e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(e, 1, id);
    kdb_enc_u8(e, 2, KDB_BATCH_FULL);
    kdb_enc_u64(e, 3, 99);
    kdb_enc_end(e);
}
static void zb_required(kdb_enc_t *e, uint16_t view, const char *name, uint64_t rr) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, 0xAB, sizeof(dig));
    kdb_enc_u16(e, 1, view);
    kdb_enc_name(e, 2, name);
    kdb_enc_i64(e, 3, -5);
    kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, 2024010101u);
    kdb_enc_u32(e, 6, KDB_ZF_PRESIGNED);
    kdb_enc_u64(e, 7, rr);
    kdb_enc_bytes(e, 8, dig, sizeof(dig));
}
static void m_zone_begin(kdb_enc_t *e, uint16_t view, const char *name, uint64_t rr) {
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    zb_required(e, view, name, rr);
    kdb_enc_end(e);
}
/* B7b: a ZONE_BEGIN of another kind (secondary / catalog consumer zones carry no data) */
static void m_zone_begin_kind(kdb_enc_t *e, uint16_t view, const char *name, uint64_t rr, uint8_t kind) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, 0xCD, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, name); kdb_enc_i64(e, 3, 9); kdb_enc_u8(e, 4, kind);
    kdb_enc_u32(e, 5, 0); kdb_enc_u32(e, 6, 0); kdb_enc_u64(e, 7, rr); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    kdb_enc_str(e, 9, "masters { 192.0.2.1; };");
    kdb_enc_end(e);
}
/* ZONE_DATA: DNS header (RFC 1035 4.1.1) with the given flags / counts, then pad bytes standing for the RRs */
static void m_zone_data_raw(kdb_enc_t *e, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar, size_t pad) {
    uint8_t b[12 + 4096];
    memset(b, 0x5A, sizeof(b));
    b[0] = 0x12; b[1] = 0x34;
    b[2] = (uint8_t)(flags >> 8); b[3] = (uint8_t)flags;
    b[4] = (uint8_t)(qd >> 8); b[5] = (uint8_t)qd;
    b[6] = (uint8_t)(an >> 8); b[7] = (uint8_t)an;
    b[8] = (uint8_t)(ns >> 8); b[9] = (uint8_t)ns;
    b[10] = (uint8_t)(ar >> 8); b[11] = (uint8_t)ar;
    kdb_enc_raw_msg(e, KDB_T_ZONE_DATA, b, 12 + pad);
}
#define FLAGS_OK 0x8400   /* QR=1, opcode 0, AA=1, RCODE 0 */
static void m_zone_data(kdb_enc_t *e, uint16_t an, uint16_t ar, size_t pad) { m_zone_data_raw(e, FLAGS_OK, 0, an, 0, ar, pad); }
static void m_zone_end(kdb_enc_t *e, uint64_t n) { kdb_enc_begin(e, KDB_T_ZONE_END); kdb_enc_u64(e, 1, n); kdb_enc_end(e); }
static void m_zone_abort(kdb_enc_t *e) { kdb_enc_begin(e, KDB_T_ZONE_ABORT); kdb_enc_str(e, 1, "bad row"); kdb_enc_end(e); }
static void m_zone_failed(kdb_enc_t *e) {
    kdb_enc_begin(e, KDB_T_ZONE_FAILED);
    kdb_enc_u16(e, 1, 2); kdb_enc_name(e, 2, "failed.test."); kdb_enc_i64(e, 3, 77); kdb_enc_str(e, 4, "NSEC3 mismatch");
    kdb_enc_end(e);
}
static void m_zone_delete(kdb_enc_t *e) {
    kdb_enc_begin(e, KDB_T_ZONE_DELETE);
    kdb_enc_u16(e, 1, 0); kdb_enc_name(e, 2, "gone.test."); kdb_enc_i64(e, 3, 3);
    kdb_enc_end(e);
}
static void m_profile(kdb_enc_t *e) {
    kdb_enc_begin(e, KDB_T_PROFILE);
    kdb_enc_str(e, 1, "default");
    kdb_enc_str(e, 2, "allow-transfer 192.0.2.0/24\nttl 3600\n");
    kdb_enc_end(e);
}
static void m_batch_end(kdb_enc_t *e, uint64_t id, uint32_t z, uint32_t f, uint32_t d) {
    kdb_enc_begin(e, KDB_T_BATCH_END);
    kdb_enc_u64(e, 1, id); kdb_enc_u32(e, 2, z); kdb_enc_u32(e, 3, f); kdb_enc_u32(e, 4, d);
    kdb_enc_end(e);
}
/* B9: AUTO_STATUS with n entries (view index i % 3) */
static void m_auto_status(kdb_enc_t *e, unsigned n) {
    kdb_enc_begin(e, KDB_T_AUTO_STATUS);
    for (unsigned i = 0; i < n; i++) {
        kdb_enc_nest_begin(e, 1);
        kdb_enc_u16(e, 1, (uint16_t)(i % 3)); kdb_enc_u64(e, 2, 1700000000u + i); kdb_enc_u64(e, 3, 41 + i); kdb_enc_u32(e, 4, i);
        if (i == 1) kdb_enc_str(e, 5, "cannot open the database");
        if (i == 2) {                                   /* B11: the reload request fields */
            kdb_enc_u8(e, 6, KDB_AS_AUTO | KDB_AS_REQ); kdb_enc_str(e, 7, "ns1"); kdb_enc_u64(e, 8, 7); kdb_enc_u8(e, 9, 1);
            kdb_enc_str(e, 10, "cannot write karidns_server_status"); kdb_enc_u64(e, 11, 1700000000u);
        }
        kdb_enc_nest_end(e);
    }
    kdb_enc_end(e);
}
/* a message of the given type that is well formed and acceptable in the state where the type is legal */
static void m_valid(kdb_enc_t *e, uint16_t t) {
    switch (t) {
    case KDB_T_HELLO: m_hello(e, 1); break;
    case KDB_T_INVENTORY_REQ: m_inv_req(e); break;
    case KDB_T_BATCH_BEGIN: m_batch_begin(e, 7); break;
    case KDB_T_ZONE_BEGIN: m_zone_begin(e, 1, ZN, 10); break;
    case KDB_T_ZONE_DATA: m_zone_data(e, 1, 0, 8); break;
    case KDB_T_ZONE_END: m_zone_end(e, 10); break;
    case KDB_T_ZONE_ABORT: m_zone_abort(e); break;
    case KDB_T_ZONE_FAILED: m_zone_failed(e); break;
    case KDB_T_ZONE_DELETE: m_zone_delete(e); break;
    case KDB_T_PROFILE: m_profile(e); break;
    case KDB_T_BATCH_END: m_batch_end(e, 7, 0, 0, 0); break;
    case KDB_T_AUTO_STATUS: m_auto_status(e, 2); break;
    }
}

/* ---------------------------------------------------------------- Backend-side builders */
static void m_config(kdb_enc_t *e) {
    kdb_enc_begin(e, KDB_T_CONFIG);
    kdb_enc_u64(e, 1, 5);
    kdb_enc_str(e, 2, "sqlite3");
    kdb_enc_str(e, 3, "ns1");
    for (unsigned i = 0; i < 2; i++) {
        kdb_enc_nest_begin(e, 4);
        kdb_enc_u16(e, 1, (uint16_t)i);
        kdb_enc_str(e, 2, i ? "internal" : "external");
        if (i) kdb_enc_str(e, 3, "/var/db/karidns/internal.sqlite3");
        kdb_enc_u8(e, 5, (uint8_t)i);
        kdb_enc_u32(e, 6, 2);
        kdb_enc_u32(e, 7, 1000);
        kdb_enc_u64(e, 8, KDB_DEFAULT_MAX_ZONE_RECORDS);
        kdb_enc_u64(e, 9, KDB_DEFAULT_MAX_ZONE_BYTES);
        if (!i) kdb_enc_u8(e, 10, 1);                 /* B6b: the first view uses the shared source */
        kdb_enc_nest_end(e);
    }
    kdb_enc_end(e);
}
static void m_reload_req(kdb_enc_t *e, bool one) {
    kdb_enc_begin(e, KDB_T_RELOAD_REQ);
    kdb_enc_u64(e, 1, 42);
    kdb_enc_u8(e, 2, one ? 1 : 0);
    if (one) { kdb_enc_u16(e, 3, 1); kdb_enc_name(e, 4, ZN); }
    kdb_enc_u8(e, 5, 1);
    kdb_enc_end(e);
}
static void inv_entry(kdb_enc_t *e, uint16_t view, const char *name, int64_t sid) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (int)sid, sizeof(dig));
    kdb_enc_nest_begin(e, 1);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, name); kdb_enc_i64(e, 3, sid); kdb_enc_u32(e, 4, 100 + (uint32_t)sid);
    kdb_enc_bytes(e, 5, dig, sizeof(dig));
    kdb_enc_nest_end(e);
}
static void m_inventory(kdb_enc_t *e) {
    kdb_enc_begin(e, KDB_T_INVENTORY);
    inv_entry(e, 0, "a.test.", 1);
    inv_entry(e, 1, "b.test.", 2);
    inv_entry(e, 2, ".", 3);
    kdb_enc_end(e);
}
static void m_inventory_end(kdb_enc_t *e) { kdb_enc_begin(e, KDB_T_INVENTORY_END); kdb_enc_u64(e, 1, 11); kdb_enc_u64(e, 2, 3); kdb_enc_end(e); }
static void m_zone_result(kdb_enc_t *e) {
    kdb_enc_begin(e, KDB_T_ZONE_RESULT);
    kdb_enc_u16(e, 1, 2); kdb_enc_name(e, 2, ZN); kdb_enc_u8(e, 3, KDB_ST_REJECTED); kdb_enc_str(e, 4, "unknown key");
    kdb_enc_end(e);
}
static void m_batch_result(kdb_enc_t *e) {
    uint8_t ids[16] = { 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 1, 0 };
    kdb_enc_begin(e, KDB_T_BATCH_RESULT);
    kdb_enc_u64(e, 1, 9); kdb_enc_bytes(e, 2, ids, sizeof(ids));
    kdb_enc_u32(e, 3, 4); kdb_enc_u32(e, 4, 3); kdb_enc_u32(e, 5, 2); kdb_enc_u32(e, 6, 1);
    kdb_enc_end(e);
}

/* ---------------------------------------------------------------- sessions: framer + state machine */
typedef struct {
    kdb_framer_t f;
    kdb_sm_t sm;
    kdb_msg_t m;
    int nframes;
    uint16_t types[256];
    kdb_rc_t rc;
    char reason[KDB_REASON_LEN];
} sess_t;

static const kdb_limits_t LIM = { 1000, 100000, NVIEWS };

static void sess_init(sess_t *s, const kdb_limits_t *lim) {
    memset(s, 0, sizeof(*s));
    kdb_framer_init(&s->f, KDB_FROM_LOADER, g_rbuf, sizeof(g_rbuf));
    kdb_sm_init(&s->sm, lim ? lim : &LIM);
}

/* chunk == 0: whole buffer.  Stops at the first error (sticky in s->rc). */
static kdb_rc_t sess_feed(sess_t *s, const uint8_t *p, size_t n, size_t chunk) {
    if (s->rc != KDB_OK) return s->rc;
    if (n == 0) return KDB_OK;
    size_t off = 0;
    do {
        size_t c = chunk ? (n - off < chunk ? n - off : chunk) : n - off;
        kdb_rc_t rc = kdb_framer_feed(&s->f, p + off, c);
        off += c;
        for (; rc == KDB_OK;) {
            kdb_frame_t fr;
            rc = kdb_framer_next(&s->f, &fr);
            if (rc == KDB_MORE) { rc = KDB_OK; break; }
            if (rc != KDB_OK) { snprintf(s->reason, sizeof(s->reason), "%s", s->f.reason); break; }
            rc = kdb_sm_accept(&s->sm, &fr, &s->m);
            if (rc != KDB_OK) { snprintf(s->reason, sizeof(s->reason), "%s", s->sm.reason); break; }
            if (s->nframes < 256) s->types[s->nframes] = fr.type;
            s->nframes++;
        }
        if (rc != KDB_OK) { s->rc = rc; return rc; }
    } while (off < n);
    return KDB_OK;
}

/* bring a fresh session to the state st with valid messages */
static void sess_to(sess_t *s, kdb_state_t st) {
    kdb_enc_t e;
    kdb_enc_init(&e);
    if (st >= KDB_S_READY) m_hello(&e, 1);
    if (st >= KDB_S_IN_BATCH) m_batch_begin(&e, 7);
    if (st >= KDB_S_IN_ZONE) { m_zone_begin(&e, 1, ZN, 10); m_zone_data(&e, 4, 0, 8); }
    CHECK(!e.err);
    CHECK_RC("prefix", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.state == st);
    kdb_enc_free(&e);
}

/* send message bytes in state st; returns the result for those bytes */
static kdb_rc_t send_in(kdb_state_t st, const uint8_t *p, size_t n, const kdb_limits_t *lim, char *reason) {
    sess_t *s = malloc(sizeof(*s));
    sess_init(s, lim);
    sess_to(s, st);
    kdb_rc_t rc = sess_feed(s, p, n, 0);
    if (reason) snprintf(reason, KDB_REASON_LEN, "%s", s->reason);
    free(s);
    return rc;
}
static kdb_rc_t send_enc(kdb_state_t st, const kdb_enc_t *e) {
    CHECK(!e->err);
    return send_in(st, e->buf, e->len, NULL, NULL);
}

/* ---------------------------------------------------------------- round trips */
static void test_roundtrip_loader(void) {
    printf("[round trip: loader -> Backend]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    m_hello(&e, 1);
    m_inv_req(&e);
    m_batch_begin(&e, 7);
    m_profile(&e);
    kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);          /* with the optional tags */
    zb_required(&e, 2, ZN, 4);
    kdb_enc_str(&e, 9, "ixfr-history 5\n");
    kdb_enc_str(&e, 10, "default");
    kdb_enc_end(&e);
    m_zone_data(&e, 3, 1, 20);
    m_zone_data(&e, 1, 0, 9);
    m_zone_end(&e, 4);
    m_zone_begin(&e, 0, "second.test.", 2);       /* aborted */
    m_zone_data(&e, 1, 0, 5);
    m_zone_abort(&e);
    m_zone_failed(&e);
    m_zone_delete(&e);
    m_batch_end(&e, 7, 1, 1, 1);
    CHECK(!e.err);

    sess_t *s = malloc(sizeof(*s));
    for (size_t chunk = 0; chunk <= 1; chunk++) {
        sess_init(s, &LIM);
        const uint8_t *p = e.buf;
        size_t n = e.len, off = 0;
        int idx = 0;
        /* walk by hand to look at every decoded message */
        do {
            size_t c = chunk ? 1 : n;
            CHECK_RC("feed", kdb_framer_feed(&s->f, p + off, c), KDB_OK);
            off += c;
            for (;;) {
                kdb_frame_t fr;
                kdb_rc_t rc = kdb_framer_next(&s->f, &fr);
                if (rc == KDB_MORE) break;
                CHECK_RC("next", rc, KDB_OK);
                if (rc != KDB_OK) goto done;
                rc = kdb_sm_accept(&s->sm, &fr, &s->m);
                CHECK_RC("accept", rc, KDB_OK);
                if (rc != KDB_OK) goto done;
                const kdb_msg_t *m = &s->m;
                switch (idx) {
                case 0: CHECK(m->type == KDB_T_HELLO && m->u.hello.proto == 1 && m->u.hello.pid == 1234);
                    CHECK(m->u.hello.driver.len == 7 && memcmp(m->u.hello.driver.p, "sqlite3", 7) == 0);
                    CHECK(m->u.hello.loader_version.len == 20); break;
                case 1: CHECK(m->type == KDB_T_INVENTORY_REQ); break;
                case 2: CHECK(m->u.batch_begin.batch_id == 7 && m->u.batch_begin.kind == KDB_BATCH_FULL && m->u.batch_begin.change_seq == 99); break;
                case 3: CHECK(m->u.profile.name.len == 7 && m->u.profile.settings.len == 37 && m->u.profile.settings.p[27] == '\n'); break;
                case 4: CHECK(m->u.zone_begin.view == 2 && m->u.zone_begin.source_id == -5 && m->u.zone_begin.rr_count == 4);
                    CHECK_STR(m->u.zone_begin.name, ZN);
                    CHECK(m->u.zone_begin.serial == 2024010101u && m->u.zone_begin.flags == KDB_ZF_PRESIGNED);
                    CHECK(m->u.zone_begin.digest[0] == 0xAB && m->u.zone_begin.digest[31] == 0xAB);
                    CHECK(m->u.zone_begin.settings.len == 15 && m->u.zone_begin.profile.len == 7); break;
                case 5: CHECK(m->u.zone_data.ancount == 3 && m->u.zone_data.arcount == 1 && m->u.zone_data.len == 32); break;
                case 6: CHECK(m->u.zone_data.ancount == 1 && m->u.zone_data.arcount == 0); break;
                case 7: CHECK(m->u.zone_end.rr_count == 4); break;
                case 8: CHECK(m->u.zone_begin.settings.p == NULL && m->u.zone_begin.profile.p == NULL); break;
                case 9: break;
                case 10: CHECK(m->u.zone_abort.reason.len == 7); break;
                case 11: CHECK(m->u.zone_failed.view == 2 && m->u.zone_failed.source_id == 77);
                    CHECK_STR(m->u.zone_failed.name, "failed.test.");
                    CHECK(m->u.zone_failed.reason.len == 14); break;
                case 12: CHECK(m->u.zone_delete.view == 0 && m->u.zone_delete.source_id == 3); CHECK_STR(m->u.zone_delete.name, "gone.test."); break;
                case 13: CHECK(m->u.batch_end.batch_id == 7 && m->u.batch_end.n_zones == 1 && m->u.batch_end.n_failed == 1 && m->u.batch_end.n_deleted == 1); break;
                }
                idx++;
            }
        } while (off < n);
        CHECK(idx == 14);
        CHECK(s->sm.state == KDB_S_READY);
    }
done:
    free(s);
    kdb_enc_free(&e);
}

static void test_roundtrip_backend(void) {
    printf("[round trip: Backend -> loader]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    m_config(&e);
    m_reload_req(&e, false);
    m_reload_req(&e, true);
    m_inventory(&e);
    m_inventory_end(&e);
    m_zone_result(&e);
    m_batch_result(&e);
    CHECK(!e.err);
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_BACKEND, g_rbuf, sizeof(g_rbuf));
    CHECK_RC("feed", kdb_framer_feed(&f, e.buf, e.len), KDB_OK);
    int idx = 0;
    for (;;) {
        kdb_frame_t fr;
        kdb_rc_t rc = kdb_framer_next(&f, &fr);
        if (rc == KDB_MORE) break;
        CHECK_RC("next", rc, KDB_OK);
        if (rc != KDB_OK) break;
        kdb_msg_t m;
        char why[KDB_REASON_LEN];
        rc = kdb_decode(&fr, NVIEWS, &m, why, sizeof(why));
        CHECK_RC(why, rc, KDB_OK);
        if (rc != KDB_OK) break;
        switch (idx) {
        case 0: {
            CHECK(m.u.config.generation == 5 && m.u.config.n_views == 2);
            CHECK(m.u.config.driver.len == 7 && m.u.config.server_id.len == 3);
            kdb_iter_t it;
            kdb_config_view_t v;
            kdb_config_views(&m, &it);
            CHECK(kdb_config_views_next(&it, &v) && v.index == 0 && v.name.len == 8 && v.source.p == NULL && v.auto_reload == 0 && v.shared_source == 1);
            CHECK(v.poll_interval == 2 && v.coalesce_ms == 1000 && v.max_zone_records == KDB_DEFAULT_MAX_ZONE_RECORDS);
            CHECK(kdb_config_views_next(&it, &v) && v.index == 1 && v.source.len == 32 && v.auto_reload == 1 && v.shared_source == 0);
            CHECK(v.max_zone_bytes == KDB_DEFAULT_MAX_ZONE_BYTES);
            CHECK(!kdb_config_views_next(&it, &v));
            break;
        }
        case 1: CHECK(m.u.reload_req.request_id == 42 && m.u.reload_req.scope == 0 && !m.u.reload_req.has_zone && m.u.reload_req.force == 1); break;
        case 2: CHECK(m.u.reload_req.scope == 1 && m.u.reload_req.has_zone && m.u.reload_req.view == 1); CHECK_STR(m.u.reload_req.zone, ZN); break;
        case 3: {
            CHECK(m.u.inventory.n_entries == 3);
            kdb_iter_t it;
            kdb_inventory_entry_t en;
            kdb_inventory_entries(&m, &it);
            CHECK(kdb_inventory_entries_next(&it, &en) && en.view == 0 && en.source_id == 1 && en.serial == 101 && en.digest[0] == 1);
            CHECK_STR(en.name, "a.test.");
            CHECK(kdb_inventory_entries_next(&it, &en) && en.view == 1 && en.source_id == 2);
            CHECK(kdb_inventory_entries_next(&it, &en) && en.view == 2); CHECK_STR(en.name, ".");
            CHECK(!kdb_inventory_entries_next(&it, &en));
            break;
        }
        case 4: CHECK(m.u.inventory_end.last_change_seq == 11 && m.u.inventory_end.n_zones == 3); break;
        case 5: CHECK(m.u.zone_result.view == 2 && m.u.zone_result.status == KDB_ST_REJECTED && m.u.zone_result.reason.len == 11); CHECK_STR(m.u.zone_result.name, ZN); break;
        case 6: CHECK(m.u.batch_result.batch_id == 9 && m.u.batch_result.n_request_ids == 2 && m.u.batch_result.request_ids[7] == 42);
            CHECK(m.u.batch_result.n_applied == 4 && m.u.batch_result.n_unchanged == 3 && m.u.batch_result.n_rejected == 2 && m.u.batch_result.n_deleted == 1); break;
        }
        idx++;
    }
    CHECK(idx == 7);
    /* the loader-side types are unknown on the loader -> Backend stream and vice versa */
    sess_t *s = malloc(sizeof(*s));
    sess_init(s, &LIM);
    CHECK_RC("backend type on loader stream", sess_feed(s, e.buf, e.len, 0), KDB_E_TYPE);
    free(s);
    kdb_enc_free(&e);
}

/* ---------------------------------------------------------------- framer rejections */
static void test_framer_rejects(void) {
    printf("[framer header rules]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    char reason[KDB_REASON_LEN];

    m_hello(&e, 1);
    e.buf[0] = 'X';
    CHECK_RC("bad magic", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, reason), KDB_E_MAGIC);
    CHECK(strstr(reason, "magic") != NULL);

    kdb_enc_reset(&e); m_hello(&e, 1);
    e.buf[4] = 0x00; e.buf[5] = 0xFF;
    CHECK_RC("unknown type", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, NULL), KDB_E_TYPE);
    kdb_enc_reset(&e); m_hello(&e, 1);
    e.buf[4] = 0x00; e.buf[5] = 0x00;
    CHECK_RC("type 0", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, NULL), KDB_E_TYPE);

    kdb_enc_reset(&e); m_hello(&e, 1);
    e.buf[7] = 1;
    CHECK_RC("flags != 0", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, NULL), KDB_E_FLAGS);
    kdb_enc_reset(&e); m_hello(&e, 1);
    e.buf[6] = 0x80;
    CHECK_RC("flags high bit", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, NULL), KDB_E_FLAGS);

    /* length above the limit is refused from the header alone, before any body arrives */
    uint8_t hdr[KDB_HEADER_LEN] = { 'K', 'D', 'B', '1', 0, KDB_T_ZONE_DATA, 0, 0, 0, 1, 0, 0 };   /* 65536 */
    CHECK_RC("ZONE_DATA 65536", send_in(KDB_S_IN_ZONE, hdr, sizeof(hdr), NULL, reason), KDB_E_LENGTH);
    hdr[9] = 0; hdr[10] = 0xFF; hdr[11] = 0xFF;                                                      /* 65535 is fine: wait for body */
    CHECK_RC("ZONE_DATA 65535 header", send_in(KDB_S_IN_ZONE, hdr, sizeof(hdr), NULL, NULL), KDB_OK);
    hdr[5] = KDB_T_HELLO; hdr[8] = 0; hdr[9] = 0x10; hdr[10] = 0; hdr[11] = 1;                       /* 1 MiB + 1 */
    CHECK_RC("HELLO 1MiB+1", send_in(KDB_S_AWAIT_HELLO, hdr, sizeof(hdr), NULL, NULL), KDB_E_LENGTH);
    hdr[8] = 0xFF; hdr[9] = 0xFF; hdr[10] = 0xFF; hdr[11] = 0xFF;
    CHECK_RC("HELLO 4GiB", send_in(KDB_S_AWAIT_HELLO, hdr, sizeof(hdr), NULL, NULL), KDB_E_LENGTH);
    hdr[8] = 0; hdr[9] = 0x10; hdr[10] = 0; hdr[11] = 0;                                              /* exactly 1 MiB passes the header */
    CHECK_RC("HELLO 1MiB header", send_in(KDB_S_AWAIT_HELLO, hdr, sizeof(hdr), NULL, NULL), KDB_OK);

    /* length above the caller's receive buffer */
    uint8_t small[64];
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_LOADER, small, sizeof(small));
    kdb_enc_reset(&e); m_zone_data(&e, 1, 0, 100);
    kdb_frame_t fr;
    CHECK_RC("feed", kdb_framer_feed(&f, e.buf, e.len), KDB_OK);
    CHECK_RC("buffer too small", kdb_framer_next(&f, &fr), KDB_E_LENGTH);
    CHECK_RC("sticky", kdb_framer_next(&f, &fr), KDB_E_LENGTH);
    CHECK_RC("feed after error", kdb_framer_feed(&f, e.buf, 1), KDB_E_LENGTH);

    /* feed twice without draining */
    kdb_framer_init(&f, KDB_FROM_LOADER, g_rbuf, sizeof(g_rbuf));
    CHECK_RC("feed 1", kdb_framer_feed(&f, e.buf, 5), KDB_OK);
    CHECK_RC("feed 2", kdb_framer_feed(&f, e.buf, 5), KDB_E_STATE);
    CHECK_RC("drain", kdb_framer_next(&f, &fr), KDB_MORE);
    CHECK_RC("feed 3", kdb_framer_feed(&f, e.buf, 5), KDB_OK);

    /* an empty body is a complete message */
    kdb_framer_init(&f, KDB_FROM_LOADER, g_rbuf, sizeof(g_rbuf));
    kdb_enc_reset(&e); m_inv_req(&e); m_inv_req(&e);
    CHECK_RC("feed", kdb_framer_feed(&f, e.buf, e.len), KDB_OK);
    CHECK_RC("empty 1", kdb_framer_next(&f, &fr), KDB_OK);
    CHECK(fr.type == KDB_T_INVENTORY_REQ && fr.len == 0);
    CHECK_RC("empty 2", kdb_framer_next(&f, &fr), KDB_OK);
    CHECK_RC("empty end", kdb_framer_next(&f, &fr), KDB_MORE);
    kdb_enc_free(&e);
}

/* ---------------------------------------------------------------- TLV rejections (state: where the type is legal) */
static void test_tlv_rejects(void) {
    printf("[TLV rules]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    char reason[KDB_REASON_LEN];

    /* truncated TLV header (3 bytes) and a value running past the body */
    static const uint8_t t3[3] = { 0, 1, 0 };
    kdb_enc_raw_msg(&e, KDB_T_HELLO, t3, sizeof(t3));
    CHECK_RC("truncated header", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, reason), KDB_E_TLV_TRUNC);
    CHECK(strstr(reason, "HELLO") != NULL);
    static const uint8_t tl[6] = { 0, 1, 0, 9, 0, 1 };
    kdb_enc_reset(&e); kdb_enc_raw_msg(&e, KDB_T_HELLO, tl, sizeof(tl));
    CHECK_RC("value past body", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, NULL), KDB_E_TLV_TRUNC);

    /* duplicate tag */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "x"); kdb_enc_str(&e, 3, "y"); kdb_enc_u32(&e, 4, 1); kdb_enc_u32(&e, 4, 2);
    kdb_enc_end(&e);
    CHECK_RC("duplicate tag", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_DUP);

    /* unknown tags: beyond the table and 0 */
    kdb_enc_reset(&e); m_hello(&e, 1);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "x"); kdb_enc_str(&e, 3, "y"); kdb_enc_u32(&e, 4, 1); kdb_enc_u8(&e, 5, 0);
    kdb_enc_end(&e);
    CHECK_RC("unknown tag 5", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_UNKNOWN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u8(&e, 0, 1);
    kdb_enc_end(&e);
    CHECK_RC("tag 0", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_UNKNOWN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY_REQ); kdb_enc_u8(&e, 1, 1); kdb_enc_end(&e);
    CHECK_RC("tag in empty message", send_enc(KDB_S_READY, &e), KDB_E_TLV_UNKNOWN);

    /* missing required tag */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "x"); kdb_enc_str(&e, 3, "y");
    kdb_enc_end(&e);
    CHECK_RC("missing pid", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, reason), KDB_E_TLV_MISSING);
    CHECK(strstr(reason, "tag 4") != NULL);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_END); kdb_enc_end(&e);
    CHECK_RC("ZONE_END without count", send_enc(KDB_S_IN_ZONE, &e), KDB_E_TLV_MISSING);

    /* bad integer lengths */
    static const uint8_t b3[3] = { 0, 0, 1 };
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_bytes(&e, 1, b3, 3); kdb_enc_str(&e, 2, "x"); kdb_enc_str(&e, 3, "y"); kdb_enc_u32(&e, 4, 1);
    kdb_enc_end(&e);
    CHECK_RC("u16 as 3 bytes", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_LEN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "x"); kdb_enc_str(&e, 3, "y"); kdb_enc_u64(&e, 4, 1);
    kdb_enc_end(&e);
    CHECK_RC("u32 as 8 bytes", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_LEN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_END); kdb_enc_bytes(&e, 1, b3, 0); kdb_enc_end(&e);
    CHECK_RC("u64 as 0 bytes", send_enc(KDB_S_IN_ZONE, &e), KDB_E_TLV_LEN);
    uint8_t dig31[31] = { 0 };
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
    zb_required(&e, 0, ZN, 4); kdb_enc_end(&e);
    CHECK_RC("valid ZONE_BEGIN", send_enc(KDB_S_IN_BATCH, &e), KDB_OK);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
    zb_required(&e, 0, ZN, 4);
    e.len -= 4 + KDB_DIGEST_LEN;   /* drop the 32-byte digest, add 31 */
    kdb_enc_bytes(&e, 8, dig31, sizeof(dig31)); kdb_enc_end(&e);
    CHECK_RC("digest of 31 bytes", send_enc(KDB_S_IN_BATCH, &e), KDB_E_TLV_LEN);

    /* strings: non-printable bytes, NUL, high bit, too long */
    static const char *bad_str[] = { "ab\001c", "ab\x7f", "a\x80", "tab\there", "line\nfeed" };
    for (size_t i = 0; i < sizeof(bad_str) / sizeof(bad_str[0]); i++) {
        kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
        kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, bad_str[i]); kdb_enc_str(&e, 3, "y"); kdb_enc_u32(&e, 4, 1);
        kdb_enc_end(&e);
        CHECK_RC("non-printable string", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_STR);
    }
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_bytes(&e, 2, "a\0b", 3); kdb_enc_str(&e, 3, "y"); kdb_enc_u32(&e, 4, 1);
    kdb_enc_end(&e);
    CHECK_RC("NUL in string", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_STR);
    char longs[100];
    memset(longs, 'a', sizeof(longs));
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_bytes(&e, 2, longs, 65); kdb_enc_str(&e, 3, "y"); kdb_enc_u32(&e, 4, 1);
    kdb_enc_end(&e);
    CHECK_RC("loader_version 65 bytes", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_TLV_STR);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_PROFILE);
    kdb_enc_bytes(&e, 1, longs, 0); kdb_enc_str(&e, 2, "x");
    kdb_enc_end(&e);
    CHECK_RC("empty profile name", send_enc(KDB_S_IN_BATCH, &e), KDB_E_TLV_STR);
    /* settings text: TAB and LF are allowed there, other controls are not */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_PROFILE);
    kdb_enc_str(&e, 1, "p"); kdb_enc_str(&e, 2, "a\tb\n\x01");
    kdb_enc_end(&e);
    CHECK_RC("control in settings", send_enc(KDB_S_IN_BATCH, &e), KDB_E_TLV_STR);
    {   /* 65535 bytes of settings fit, the TLV length is a u16 */
        char *big = malloc(65535);
        memset(big, 'x', 65535);
        kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_PROFILE);
        kdb_enc_str(&e, 1, "p"); kdb_enc_bytes(&e, 2, big, 65535);
        kdb_enc_end(&e);
        CHECK(!e.err);
        CHECK_RC("settings 65535", send_enc(KDB_S_IN_BATCH, &e), KDB_OK);
        kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_PROFILE);
        CHECK(kdb_enc_bytes(&e, 2, big, 65536) != 0 && e.err);   /* the encoder refuses a value above a u16 */
        free(big);
    }

    /* names */
    char lbl65[80];
    memset(lbl65, 'a', 65);
    strcpy(lbl65 + 65, ".test.");
    struct { const char *name; const char *why; } bad_names[] = {
        { "example.test", "relative" }, { "", "empty" }, { "a..test.", "empty label" }, { ".a.test.", "leading dot" },
        { "a b.test.", "space" }, { "a\\b.test.", "non-canonical escape" }, { "a\\.b\\", "dangling escape" },
        { "\\999.test.", "bad decimal escape" }, { "a\x01.test.", "control" }, { "a\xc3\xa9.test.", "UTF-8" },
        { lbl65, "label of 65 octets" },
    };
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, bad_names[i].name); kdb_enc_i64(&e, 3, 1);
        kdb_enc_end(&e);
        kdb_rc_t rc = send_in(KDB_S_IN_BATCH, e.buf, e.len, NULL, NULL);
        if (rc != KDB_E_TLV_NAME) printf("  name case: %s\n", bad_names[i].why);
        CHECK_RC("bad name", rc, KDB_E_TLV_NAME);
    }
    {   /* a name of 256 octets on the wire; and a text longer than 1024 */
        char nm[1200];
        size_t o = 0;
        for (int l = 0; l < 5; l++) { memset(nm + o, 'a', 63); o += 63; nm[o++] = '.'; }   /* 5 * 64 = 320 > 255 */
        nm[o] = '\0';
        kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, nm); kdb_enc_i64(&e, 3, 1); kdb_enc_end(&e);
        CHECK_RC("name above 255 octets", send_enc(KDB_S_IN_BATCH, &e), KDB_E_TLV_NAME);
        memset(nm, 'a', 1100); nm[1100] = '\0';
        kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, nm); kdb_enc_i64(&e, 3, 1); kdb_enc_end(&e);
        CHECK_RC("name text above 1024", send_enc(KDB_S_IN_BATCH, &e), KDB_E_TLV_NAME);
    }
    {   /* names that are accepted */
        static const char *good[] = { ".", "a.", "A.Test.", "a\\.b.test.", "a\\032b.test.", "\\000.test.", "_dmarc.example.test." };
        for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
            kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
            kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, good[i]); kdb_enc_i64(&e, 3, 1); kdb_enc_end(&e);
            kdb_rc_t rc = send_enc(KDB_S_IN_BATCH, &e);
            if (rc != KDB_OK) printf("  rejected: %s\n", good[i]);
            CHECK_RC("good name", rc, KDB_OK);
        }
    }

    /* view index and enumerations out of range */
    kdb_enc_reset(&e); m_zone_begin(&e, NVIEWS, ZN, 4);
    CHECK_RC("view index == view count", send_in(KDB_S_IN_BATCH, e.buf, e.len, NULL, reason), KDB_E_RANGE);
    CHECK(strstr(reason, "view index") != NULL);
    kdb_enc_reset(&e); m_zone_begin(&e, NVIEWS - 1, ZN, 4);
    CHECK_RC("view index == count - 1", send_enc(KDB_S_IN_BATCH, &e), KDB_OK);
    kdb_enc_reset(&e); m_zone_begin(&e, 65535, ZN, 4);
    CHECK_RC("view index 65535", send_enc(KDB_S_IN_BATCH, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); m_zone_delete(&e);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
    kdb_enc_u16(&e, 1, 3); kdb_enc_name(&e, 2, ZN); kdb_enc_i64(&e, 3, 1); kdb_enc_end(&e);
    CHECK_RC("ZONE_DELETE view 3", send_enc(KDB_S_IN_BATCH, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
    kdb_enc_u16(&e, 1, 9); kdb_enc_name(&e, 2, ZN); kdb_enc_i64(&e, 3, 1); kdb_enc_str(&e, 4, "r"); kdb_enc_end(&e);
    CHECK_RC("ZONE_FAILED view 9", send_enc(KDB_S_IN_BATCH, &e), KDB_E_RANGE);
    {
        kdb_limits_t any = { 1000, 100000, KDB_VIEWS_ANY };
        kdb_enc_reset(&e); m_zone_begin(&e, 65535, ZN, 4);
        CHECK_RC("view check off", send_in(KDB_S_IN_BATCH, e.buf, e.len, &any, NULL), KDB_OK);
        kdb_limits_t none = { 1000, 100000, 0 };
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 4);
        CHECK_RC("zero views", send_in(KDB_S_IN_BATCH, e.buf, e.len, &none, NULL), KDB_E_RANGE);
    }
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(&e, 1, 1); kdb_enc_u8(&e, 2, 5); kdb_enc_u64(&e, 3, 1); kdb_enc_end(&e);
    CHECK_RC("batch kind 5", send_enc(KDB_S_READY, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
    zb_required(&e, 0, ZN, 4);
    /* header, tag 1 (u16), tag 2 (name), tag 3 (i64), then tag 4 header: the zone_kind value byte follows */
    e.buf[KDB_HEADER_LEN + (4 + 2) + (4 + (int)strlen(ZN)) + (4 + 8) + 4] = 3;
    kdb_enc_end(&e);
    CHECK_RC("zone kind 3", send_enc(KDB_S_IN_BATCH, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
    {   /* reserved zone flag bit */
        uint8_t dig[KDB_DIGEST_LEN] = { 0 };
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, ZN); kdb_enc_i64(&e, 3, 1); kdb_enc_u8(&e, 4, 0); kdb_enc_u32(&e, 5, 1);
        kdb_enc_u32(&e, 6, 16); kdb_enc_u64(&e, 7, 4); kdb_enc_bytes(&e, 8, dig, sizeof(dig));
    }
    kdb_enc_end(&e);
    CHECK_RC("reserved zone flag (bit 4; bit 2 is the tinydns flag since B8, bit 3 the fetch summary of D1a)", send_enc(KDB_S_IN_BATCH, &e), KDB_E_RANGE);
    kdb_enc_free(&e);
}

/* Backend -> loader direction: the same rules (decoder only) */
static kdb_rc_t decode_backend(const kdb_enc_t *e, uint32_t vc) {
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_BACKEND, g_rbuf, sizeof(g_rbuf));
    kdb_rc_t rc = kdb_framer_feed(&f, e->buf, e->len);
    kdb_frame_t fr;
    if (rc == KDB_OK) rc = kdb_framer_next(&f, &fr);
    if (rc != KDB_OK) return rc;
    kdb_msg_t m;
    char why[KDB_REASON_LEN];
    return kdb_decode(&fr, vc, &m, why, sizeof(why));
}

static void test_backend_direction_rejects(void) {
    printf("[Backend -> loader decoder rules]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    m_config(&e);
    CHECK_RC("config ok", decode_backend(&e, 2), KDB_OK);
    /* B6b: shared_source is 0 or 1 */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3");
    kdb_enc_nest_begin(&e, 4);
    kdb_enc_u16(&e, 1, 0); kdb_enc_str(&e, 2, "v"); kdb_enc_u8(&e, 5, 0); kdb_enc_u32(&e, 6, 2); kdb_enc_u32(&e, 7, 1000);
    kdb_enc_u64(&e, 8, 1); kdb_enc_u64(&e, 9, 1); kdb_enc_u8(&e, 10, 2);
    kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("shared_source 2 is refused", decode_backend(&e, 2), KDB_E_RANGE);
    /* unknown tag inside a nested VIEW entry */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3");
    kdb_enc_nest_begin(&e, 4); kdb_enc_u16(&e, 77, 0); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("unknown nested tag", decode_backend(&e, 2), KDB_E_TLV_UNKNOWN);
    /* nested entry missing a required tag */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3");
    kdb_enc_nest_begin(&e, 4); kdb_enc_u16(&e, 1, 0); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("nested missing tag", decode_backend(&e, 2), KDB_E_TLV_MISSING);
    /* nested entry truncated: the nested TLV claims more than its parent holds */
    static const uint8_t bad[] = { 0, 4, 0, 3, 0, 1, 0 };
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3"); kdb_enc_bytes(&e, 4, bad + 4, 3);
    kdb_enc_end(&e);
    CHECK_RC("nested truncated", decode_backend(&e, 2), KDB_E_TLV_TRUNC);
    /* too many views */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3");
    for (int i = 0; i <= KDB_MAX_CONFIG_VIEWS; i++) {
        kdb_enc_nest_begin(&e, 4);
        kdb_enc_u16(&e, 1, (uint16_t)i); kdb_enc_str(&e, 2, "v"); kdb_enc_u8(&e, 5, 0); kdb_enc_u32(&e, 6, 1);
        kdb_enc_u32(&e, 7, 1); kdb_enc_u64(&e, 8, 1); kdb_enc_u64(&e, 9, 1);
        kdb_enc_nest_end(&e);
    }
    kdb_enc_end(&e);
    CHECK(!e.err);
    CHECK_RC("1025 views", decode_backend(&e, 2), KDB_E_RANGE);
    /* auto_reload not 0/1 */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3");
    kdb_enc_nest_begin(&e, 4);
    kdb_enc_u16(&e, 1, 0); kdb_enc_str(&e, 2, "v"); kdb_enc_u8(&e, 5, 2); kdb_enc_u32(&e, 6, 1);
    kdb_enc_u32(&e, 7, 1); kdb_enc_u64(&e, 8, 1); kdb_enc_u64(&e, 9, 1);
    kdb_enc_nest_end(&e); kdb_enc_end(&e);
    CHECK_RC("auto_reload 2", decode_backend(&e, 2), KDB_E_RANGE);
    /* RELOAD_REQ scope / target consistency */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_RELOAD_REQ);
    kdb_enc_u64(&e, 1, 1); kdb_enc_u8(&e, 2, 1); kdb_enc_u8(&e, 5, 0); kdb_enc_end(&e);
    CHECK_RC("scope 1 without zone", decode_backend(&e, 2), KDB_E_TLV_MISSING);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_RELOAD_REQ);
    kdb_enc_u64(&e, 1, 1); kdb_enc_u8(&e, 2, 0); kdb_enc_u16(&e, 3, 0); kdb_enc_name(&e, 4, ZN); kdb_enc_u8(&e, 5, 0); kdb_enc_end(&e);
    CHECK_RC("scope 0 with zone", decode_backend(&e, 2), KDB_E_RANGE);
    kdb_enc_reset(&e); m_reload_req(&e, true);
    CHECK_RC("reload view 1 of 1", decode_backend(&e, 1), KDB_E_RANGE);
    CHECK_RC("reload view 1 of 2", decode_backend(&e, 2), KDB_OK);
    /* INVENTORY entry: bad name, view out of range, digest length */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "rel"); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    { uint8_t d[32] = { 0 }; kdb_enc_bytes(&e, 5, d, 32); }
    kdb_enc_nest_end(&e); kdb_enc_end(&e);
    CHECK_RC("inventory bad name", decode_backend(&e, 2), KDB_E_TLV_NAME);
    kdb_enc_reset(&e); m_inventory(&e);
    CHECK_RC("inventory view 2 of 2", decode_backend(&e, 2), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "a."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    { uint8_t d[8] = { 0 }; kdb_enc_bytes(&e, 5, d, 8); }
    kdb_enc_nest_end(&e); kdb_enc_end(&e);
    CHECK_RC("inventory digest 8", decode_backend(&e, 2), KDB_E_TLV_LEN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY); kdb_enc_u8(&e, 2, 0); kdb_enc_end(&e);
    CHECK_RC("inventory unknown tag", decode_backend(&e, 2), KDB_E_TLV_UNKNOWN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY); kdb_enc_end(&e);
    CHECK_RC("empty inventory chunk", decode_backend(&e, 2), KDB_OK);
    /* ZONE_RESULT status, BATCH_RESULT request ids */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_ZONE_RESULT);
    kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, ZN); kdb_enc_u8(&e, 3, 5); kdb_enc_end(&e);
    CHECK_RC("status 5", decode_backend(&e, 2), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_BATCH_RESULT);
    { uint8_t ids[12] = { 0 };
      kdb_enc_u64(&e, 1, 1); kdb_enc_bytes(&e, 2, ids, 12); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0); kdb_enc_u32(&e, 5, 0); kdb_enc_u32(&e, 6, 0); }
    kdb_enc_end(&e);
    CHECK_RC("request ids of 12 bytes", decode_backend(&e, 2), KDB_E_TLV_LEN);
    /* loader types on the Backend stream are unknown there */
    kdb_enc_reset(&e); m_hello(&e, 1);
    CHECK_RC("HELLO on Backend stream", decode_backend(&e, 2), KDB_E_TYPE);
    kdb_enc_free(&e);
}

/* CONFIG with one view whose source (tag 3) is `src` bytes long */
static kdb_rc_t decode_config_source(const void *src, size_t n, kdb_config_view_t *out) {
    kdb_enc_t e;
    kdb_enc_init(&e);
    kdb_enc_begin(&e, KDB_T_CONFIG);
    kdb_enc_u64(&e, 1, 1); kdb_enc_str(&e, 2, "sqlite3");
    kdb_enc_nest_begin(&e, 4);
    kdb_enc_u16(&e, 1, 0); kdb_enc_str(&e, 2, "v"); kdb_enc_bytes(&e, 3, src, n); kdb_enc_u8(&e, 5, 0);
    kdb_enc_u32(&e, 6, 1); kdb_enc_u32(&e, 7, 1); kdb_enc_u64(&e, 8, 1); kdb_enc_u64(&e, 9, 1);
    kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_BACKEND, g_rbuf, sizeof(g_rbuf));
    kdb_rc_t rc = kdb_framer_feed(&f, e.buf, e.len);
    kdb_frame_t fr;
    if (rc == KDB_OK) rc = kdb_framer_next(&f, &fr);
    kdb_msg_t m;
    char why[KDB_REASON_LEN];
    if (rc == KDB_OK) rc = kdb_decode(&fr, 1, &m, why, sizeof(why));
    if (rc == KDB_OK && out) {
        kdb_iter_t it;
        kdb_config_views(&m, &it);
        if (!kdb_config_views_next(&it, out)) rc = KDB_E_TLV_MISSING;
    }
    kdb_enc_free(&e);
    return rc;
}

static void test_path_charset(void) {
    printf("[paths: UTF-8 accepted, kept byte for byte; invalid UTF-8 and controls rejected]\n");
    kdb_config_view_t v;
    /* UTF-8 (2-, 3- and 4-byte sequences) and percent signs are taken literally, not decoded */
    static const char utf8[] = "/var/db/\xE6\x97\xA5\xE6\x9C\xAC/z\xC3\xA9%65 \xF0\x9F\x98\x80.sqlite3";
    CHECK_RC("UTF-8 path", decode_config_source(utf8, sizeof(utf8) - 1, &v), KDB_OK);
    CHECK(v.source.len == sizeof(utf8) - 1 && memcmp(v.source.p, utf8, sizeof(utf8) - 1) == 0);
    static const char pct[] = "/var/db/a%65%2F%00.sqlite3";
    CHECK_RC("percent sequences", decode_config_source(pct, sizeof(pct) - 1, &v), KDB_OK);
    CHECK(v.source.len == sizeof(pct) - 1 && memcmp(v.source.p, pct, sizeof(pct) - 1) == 0);
    static const char max4[] = "\xF4\x8F\xBF\xBF";   /* U+10FFFF */
    CHECK_RC("U+10FFFF", decode_config_source(max4, 4, NULL), KDB_OK);
    static const struct { const char *label; const char *b; size_t n; } bad[] = {
        { "lone continuation byte", "/a\x80", 3 },
        { "overlong 2-byte (C0 AF)", "/a\xC0\xAF", 4 },
        { "overlong 3-byte (E0 80 AF)", "/a\xE0\x80\xAF", 5 },
        { "overlong 4-byte (F0 80 80 AF)", "/a\xF0\x80\x80\xAF", 6 },
        { "surrogate U+D800", "/a\xED\xA0\x80", 5 },
        { "above U+10FFFF (F4 90 80 80)", "/a\xF4\x90\x80\x80", 6 },
        { "F5 lead byte", "/a\xF5\x80\x80\x80", 6 },
        { "truncated 3-byte sequence", "/a\xE3\x81", 4 },
        { "missing continuation", "/a\xE3\x41\x41", 5 },
        { "C0 control", "/a\x01", 3 },
        { "newline", "/a\nb", 4 },
        { "DEL", "/a\x7F", 3 },
        { "C1 control U+0085", "/a\xC2\x85", 4 },
        { "NUL", "/a\0b", 4 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK_RC(bad[i].label, decode_config_source(bad[i].b, bad[i].n, NULL), KDB_E_TLV_STR);
    CHECK_RC("empty path", decode_config_source("", 0, NULL), KDB_E_TLV_STR);
    static char longp[1025];
    memset(longp, 'a', sizeof(longp));
    CHECK_RC("1023-byte path", decode_config_source(longp, 1023, NULL), KDB_OK);
    CHECK_RC("1024-byte path", decode_config_source(longp, 1024, NULL), KDB_E_TLV_STR);
}

/* ---------------------------------------------------------------- state machine */
static void test_state_matrix(void) {
    printf("[state machine: type x state]\n");
    static const uint16_t types[] = { KDB_T_HELLO, KDB_T_INVENTORY_REQ, KDB_T_BATCH_BEGIN, KDB_T_ZONE_BEGIN,
        KDB_T_ZONE_DATA, KDB_T_ZONE_END, KDB_T_ZONE_ABORT, KDB_T_ZONE_FAILED, KDB_T_ZONE_DELETE, KDB_T_PROFILE,
        KDB_T_BATCH_END, KDB_T_AUTO_STATUS };
    /* legal[state][type index] */
    static const bool legal[4][12] = {
        /* AWAIT_HELLO */ { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        /* READY       */ { 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        /* IN_BATCH    */ { 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0 },
        /* IN_ZONE     */ { 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0 },
    };
    kdb_enc_t e;
    kdb_enc_init(&e);
    for (int st = 0; st < 4; st++)
        for (size_t t = 0; t < 12; t++) {
            kdb_enc_reset(&e);
            m_valid(&e, types[t]);
            kdb_rc_t rc = send_enc((kdb_state_t)st, &e);
            if (legal[st][t]) {
                if (rc == KDB_E_STATE) printf("  state %d type %s rejected as out of state\n", st, kdb_type_name(types[t]));
                CHECK(rc != KDB_E_STATE);
            } else {
                if (rc != KDB_E_STATE) printf("  state %d type %s was not refused\n", st, kdb_type_name(types[t]));
                CHECK_RC("illegal in state", rc, KDB_E_STATE);
            }
        }
    /* the messages that complete a legal transition end in the next state */
    sess_t *s = malloc(sizeof(*s));
    sess_init(s, &LIM);
    sess_to(s, KDB_S_IN_ZONE);
    kdb_enc_reset(&e); m_zone_data(&e, 6, 0, 8); m_zone_end(&e, 10);
    CHECK_RC("finish zone", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.state == KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_batch_end(&e, 7, 1, 0, 0);
    CHECK_RC("finish batch", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.state == KDB_S_READY);
    kdb_enc_reset(&e); m_inv_req(&e);
    CHECK_RC("INVENTORY_REQ after a batch", sess_feed(s, e.buf, e.len, 0), KDB_E_STATE);
    CHECK_RC("sticky error", sess_feed(s, e.buf, 0, 0), KDB_E_STATE);
    CHECK(s->sm.state == KDB_S_ERROR);
    /* INVENTORY_REQ only once */
    sess_init(s, &LIM);
    sess_to(s, KDB_S_READY);
    kdb_enc_reset(&e); m_inv_req(&e); m_inv_req(&e);
    CHECK_RC("INVENTORY_REQ twice", sess_feed(s, e.buf, e.len, 0), KDB_E_STATE);
    /* HELLO twice, version mismatch */
    sess_init(s, &LIM);
    sess_to(s, KDB_S_READY);
    kdb_enc_reset(&e); m_hello(&e, 1);
    CHECK_RC("HELLO twice", sess_feed(s, e.buf, e.len, 0), KDB_E_STATE);
    kdb_enc_reset(&e); m_hello(&e, 2);
    char reason[KDB_REASON_LEN];
    CHECK_RC("version 2", send_in(KDB_S_AWAIT_HELLO, e.buf, e.len, NULL, reason), KDB_E_VERSION);
    CHECK(strstr(reason, "version") != NULL);
    kdb_enc_reset(&e); m_hello(&e, 0);
    CHECK_RC("version 0", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_VERSION);
    /* a Backend -> loader message handed to the machine is refused in every state */
    for (int st = 0; st < 4; st++) {
        kdb_enc_reset(&e); m_zone_result(&e);
        sess_t *q = malloc(sizeof(*q));
        sess_init(q, &LIM);
        sess_to(q, (kdb_state_t)st);
        kdb_frame_t fr = { KDB_T_ZONE_RESULT, e.buf + KDB_HEADER_LEN, (uint32_t)(e.len - KDB_HEADER_LEN) };
        CHECK_RC("Backend type to the machine", kdb_sm_accept(&q->sm, &fr, &q->m), KDB_E_STATE);
        free(q);
    }
    /* ZONE_ABORT returns to IN_BATCH and another zone can start */
    sess_init(s, &LIM);
    sess_to(s, KDB_S_IN_ZONE);
    kdb_enc_reset(&e); m_zone_abort(&e); m_zone_begin(&e, 0, "next.test.", 2); m_zone_data(&e, 2, 0, 4); m_zone_end(&e, 2);
    CHECK_RC("abort then next zone", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.state == KDB_S_IN_BATCH && s->sm.n_zones == 1);
    free(s);
    kdb_enc_free(&e);
}

static void test_zone_data_header(void) {
    printf("[ZONE_DATA header rules (RFC 1035 4.1.1, RFC 5936 2.2)]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    static const struct { const char *what; uint16_t flags, qd, an, ns, ar; } bad[] = {
        { "QR=0", 0x0400, 0, 1, 0, 0 },
        { "opcode NOTIFY", 0xA400, 0, 1, 0, 0 },
        { "opcode 15", 0xFC00, 0, 1, 0, 0 },
        { "AA=0", 0x8000, 0, 1, 0, 0 },
        { "TC=1", 0x8600, 0, 1, 0, 0 },
        { "RCODE SERVFAIL", 0x8402, 0, 1, 0, 0 },
        { "RCODE 15", 0x840F, 0, 1, 0, 0 },
        { "QDCOUNT 1", 0x8400, 1, 1, 0, 0 },
        { "NSCOUNT 1", 0x8400, 0, 1, 1, 0 },
        { "ARCOUNT 2", 0x8400, 0, 1, 0, 2 },
        { "ANCOUNT 0", 0x8400, 0, 0, 0, 0 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        kdb_enc_reset(&e);
        m_zone_data_raw(&e, bad[i].flags, bad[i].qd, bad[i].an, bad[i].ns, bad[i].ar, 8);
        kdb_rc_t rc = send_enc(KDB_S_IN_ZONE, &e);
        if (rc != KDB_E_DNSHDR) printf("  case: %s\n", bad[i].what);
        CHECK_RC("ZONE_DATA header", rc, KDB_E_DNSHDR);
    }
    /* shorter than 12 bytes */
    for (size_t n = 0; n < 12; n++) {
        uint8_t b[12] = { 0x12, 0x34, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
        kdb_enc_reset(&e); kdb_enc_raw_msg(&e, KDB_T_ZONE_DATA, b, n);
        CHECK_RC("short ZONE_DATA", send_enc(KDB_S_IN_ZONE, &e), KDB_E_DNSHDR);
    }
    /* what is allowed: ID, RD, RA, AD, CD bits; exactly 12 bytes with ANCOUNT 1 (the RR bytes are not parsed here) */
    kdb_enc_reset(&e); m_zone_data_raw(&e, 0x8400 | 0x0100 | 0x0080 | 0x0020 | 0x0010, 0, 1, 0, 0, 0);
    CHECK_RC("RD/RA/AD/CD are ignored", send_enc(KDB_S_IN_ZONE, &e), KDB_OK);

    /* OPT: allowed in the first ZONE_DATA only */
    sess_t *s = malloc(sizeof(*s));
    sess_init(s, &LIM);
    sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 4, 1, 20);
    CHECK_RC("OPT in the first message", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    kdb_enc_reset(&e); m_zone_data(&e, 4, 1, 20);
    char reason[KDB_REASON_LEN];
    CHECK_RC("OPT in the second message", sess_feed(s, e.buf, e.len, 0), KDB_E_OPT);
    snprintf(reason, sizeof(reason), "%s", s->reason);
    CHECK(strstr(reason, "ARCOUNT") != NULL);
    /* the next zone may carry one again, an aborted zone does not leak the "first" flag */
    sess_init(s, &LIM);
    sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 4, 0, 20); m_zone_abort(&e);
    m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 4, 1, 20);
    CHECK_RC("OPT first after an abort", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    sess_init(s, &LIM);
    sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 4, 0, 20); m_zone_data(&e, 4, 1, 20);
    CHECK_RC("OPT in the second message (no OPT first)", sess_feed(s, e.buf, e.len, 0), KDB_E_OPT);
    free(s);
    kdb_enc_free(&e);
}

static void test_counts_and_limits(void) {
    printf("[counts and limits]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    char reason[KDB_REASON_LEN];
    sess_t *s = malloc(sizeof(*s));

    /* ZONE_BEGIN rr_count */
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 1);
    CHECK_RC("rr_count 1", send_enc(KDB_S_IN_BATCH, &e), KDB_E_COUNT);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 0);
    CHECK_RC("rr_count 0", send_enc(KDB_S_IN_BATCH, &e), KDB_E_COUNT);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 1000);
    CHECK_RC("rr_count == limit", send_enc(KDB_S_IN_BATCH, &e), KDB_OK);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 1001);
    CHECK_RC("rr_count limit + 1", send_in(KDB_S_IN_BATCH, e.buf, e.len, NULL, reason), KDB_E_LIMIT_RECORDS);
    CHECK(strstr(reason, "max-zone-records") != NULL);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, UINT64_MAX);
    CHECK_RC("rr_count 2^64-1", send_enc(KDB_S_IN_BATCH, &e), KDB_E_LIMIT_RECORDS);
    /* B7b: secondary and catalog consumer zones have rr_count 0 and no ZONE_DATA (the primary rule of two SOAs does not apply) */
    for (uint8_t zk = KDB_ZK_SECONDARY; zk <= KDB_ZK_CATALOG; zk++) {
        kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 0, zk);
        CHECK_RC("secondary kind, rr_count 0", send_enc(KDB_S_IN_BATCH, &e), KDB_OK);
        kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 2, zk);
        CHECK_RC("secondary kind, rr_count 2", send_enc(KDB_S_IN_BATCH, &e), KDB_E_COUNT);
        kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 1, zk);
        CHECK_RC("secondary kind, rr_count 1", send_enc(KDB_S_IN_BATCH, &e), KDB_E_COUNT);
        sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 0, zk); m_zone_end(&e, 0);
        CHECK_RC("secondary kind: BEGIN, END", sess_feed(s, e.buf, e.len, 0), KDB_OK);
        CHECK(s->sm.state == KDB_S_IN_BATCH && s->sm.n_zones == 1);
        sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 0, zk); m_zone_data(&e, 1, 0, 8);
        CHECK_RC("secondary kind: ZONE_DATA is more than declared", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
        sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 0, zk); m_zone_end(&e, 2);
        CHECK_RC("secondary kind: ZONE_END count differs", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    }
    kdb_enc_reset(&e); m_zone_begin_kind(&e, 0, ZN, 0, KDB_ZK_PRIMARY);
    CHECK_RC("primary kind, rr_count 0", send_enc(KDB_S_IN_BATCH, &e), KDB_E_COUNT);
    {   /* the default limits */
        kdb_limits_t d = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, KDB_VIEWS_ANY };
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, KDB_DEFAULT_MAX_ZONE_RECORDS);
        CHECK_RC("10M records", send_in(KDB_S_IN_BATCH, e.buf, e.len, &d, NULL), KDB_OK);
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, KDB_DEFAULT_MAX_ZONE_RECORDS + 1);
        CHECK_RC("10M + 1 records", send_in(KDB_S_IN_BATCH, e.buf, e.len, &d, NULL), KDB_E_LIMIT_RECORDS);
        kdb_sm_t sm;
        kdb_sm_init(&sm, NULL);
        CHECK(sm.lim.max_zone_records == 10000000ull && sm.lim.max_zone_bytes == (1ull << 30) && sm.lim.view_count == KDB_VIEWS_ANY);
    }

    /* more RRs in ZONE_DATA than declared */
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 5); m_zone_data(&e, 3, 0, 8); m_zone_data(&e, 3, 0, 8);
    CHECK_RC("ANCOUNT sum above declared", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 5); m_zone_data(&e, 65535, 0, 8);
    CHECK_RC("ANCOUNT 65535", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    /* the sum is 64-bit: 65535 messages of 65535 RRs against a declared 2^32 + a bit */
    {
        kdb_limits_t big = { UINT64_MAX, UINT64_MAX, KDB_VIEWS_ANY };
        sess_init(s, &big); sess_to(s, KDB_S_IN_BATCH);
        uint64_t decl = 65535ull * 66000ull;
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, decl);
        CHECK_RC("begin", sess_feed(s, e.buf, e.len, 0), KDB_OK);
        kdb_enc_reset(&e); m_zone_data(&e, 65535, 0, 0);
        for (int i = 0; i < 66000; i++) {
            if (sess_feed(s, e.buf, e.len, 0) != KDB_OK) break;
        }
        CHECK(s->rc == KDB_OK && s->sm.zone_rr_sum == decl && s->sm.zone_rr_sum > UINT32_MAX);
        kdb_enc_reset(&e); m_zone_end(&e, decl);
        CHECK_RC("end after a 64-bit sum", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    }

    /* ZONE_END */
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_ZONE);   /* declared 10, sum 4 */
    kdb_enc_reset(&e); m_zone_end(&e, 11);
    CHECK_RC("ZONE_END count != ZONE_BEGIN", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    CHECK(strstr(s->reason, "ZONE_END") != NULL);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_ZONE);
    kdb_enc_reset(&e); m_zone_end(&e, 10);
    CHECK_RC("ZONE_END count == ZONE_BEGIN, ANCOUNT sum short", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    CHECK(strstr(s->reason, "ANCOUNT") != NULL);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_ZONE);
    kdb_enc_reset(&e); m_zone_end(&e, 4);
    CHECK_RC("ZONE_END count == sum != ZONE_BEGIN", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_ZONE);
    kdb_enc_reset(&e); m_zone_data(&e, 6, 0, 8); m_zone_end(&e, 10);
    CHECK_RC("ZONE_END exact", sess_feed(s, e.buf, e.len, 0), KDB_OK);

    /* bytes: sum of the ZONE_DATA bodies of one zone */
    {
        kdb_limits_t lb = { 1000, 100, NVIEWS };       /* each ZONE_DATA below: 12 + 38 = 50 bytes */
        sess_init(s, &lb); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 1, 0, 38); m_zone_data(&e, 1, 0, 38);
        CHECK_RC("bytes == limit", sess_feed(s, e.buf, e.len, 0), KDB_OK);
        kdb_enc_reset(&e); m_zone_data(&e, 1, 0, 0);
        CHECK_RC("bytes limit + 12", sess_feed(s, e.buf, e.len, 0), KDB_E_LIMIT_BYTES);
        CHECK(strstr(s->reason, "max-zone-bytes") != NULL);
        /* the counter restarts with the next zone */
        sess_init(s, &lb); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 4); m_zone_data(&e, 1, 0, 38); m_zone_data(&e, 1, 0, 38); m_zone_abort(&e);
        m_zone_begin(&e, 0, ZN, 4); m_zone_data(&e, 1, 0, 38); m_zone_data(&e, 1, 0, 38);
        CHECK_RC("bytes per zone", sess_feed(s, e.buf, e.len, 0), KDB_OK);
        sess_init(s, &lb); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 1, 0, 89);
        CHECK_RC("one ZONE_DATA of 101 bytes", sess_feed(s, e.buf, e.len, 0), KDB_E_LIMIT_BYTES);
        kdb_limits_t zero = { 1000, 0, NVIEWS };
        sess_init(s, &zero); sess_to(s, KDB_S_IN_BATCH);
        kdb_enc_reset(&e); m_zone_begin(&e, 0, ZN, 10); m_zone_data(&e, 1, 0, 0);
        CHECK_RC("limit 0", sess_feed(s, e.buf, e.len, 0), KDB_E_LIMIT_BYTES);
    }

    /* BATCH_END */
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_batch_end(&e, 8, 0, 0, 0);
    CHECK_RC("BATCH_END other id", sess_feed(s, e.buf, e.len, 0), KDB_E_SEQ);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_batch_end(&e, 7, 1, 0, 0);
    CHECK_RC("BATCH_END zones", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_failed(&e); m_zone_delete(&e); m_zone_delete(&e); m_batch_end(&e, 7, 0, 1, 1);
    CHECK_RC("BATCH_END deleted", sess_feed(s, e.buf, e.len, 0), KDB_E_COUNT);
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e); m_zone_failed(&e); m_zone_delete(&e); m_batch_end(&e, 7, 0, 1, 1);
    CHECK_RC("BATCH_END exact", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    /* an aborted zone is not counted */
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_ZONE);
    kdb_enc_reset(&e); m_zone_abort(&e); m_batch_end(&e, 7, 0, 0, 0);
    CHECK_RC("aborted zone not counted", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    /* a second batch starts its counters again */
    kdb_enc_reset(&e); m_batch_begin(&e, 8); m_zone_delete(&e); m_batch_end(&e, 8, 0, 0, 1);
    CHECK_RC("second batch", sess_feed(s, e.buf, e.len, 0), KDB_OK);

    /* profile count per batch */
    sess_init(s, &LIM); sess_to(s, KDB_S_IN_BATCH);
    kdb_enc_reset(&e);
    for (unsigned i = 0; i < KDB_MAX_PROFILES; i++) m_profile(&e);
    CHECK_RC("65535 profiles", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    kdb_enc_reset(&e); m_profile(&e);
    CHECK_RC("65536th profile", sess_feed(s, e.buf, e.len, 0), KDB_E_LIMIT_PROFILES);
    free(s);
    kdb_enc_free(&e);
}

/* ---------------------------------------------------------------- feeding granularity */
static void test_chunking(void) {
    printf("[byte-at-a-time == whole buffer]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    m_hello(&e, 1); m_inv_req(&e); m_batch_begin(&e, 7); m_profile(&e);
    m_zone_begin(&e, 0, ZN, 4); m_zone_data(&e, 3, 1, 300); m_zone_data(&e, 1, 0, 9); m_zone_end(&e, 4);
    m_zone_failed(&e); m_zone_delete(&e); m_batch_end(&e, 7, 1, 1, 1);
    size_t good_len = e.len;
    CHECK(!e.err);

    sess_t *a = malloc(sizeof(*a)), *b = malloc(sizeof(*b));
    /* the valid stream, and every truncation / single corruption of it */
    for (size_t variant = 0; variant < good_len * 2 + 1; variant++) {
        uint8_t *buf = malloc(good_len);
        memcpy(buf, e.buf, good_len);
        size_t n = good_len;
        if (variant > 0 && variant <= good_len) n = variant - 1;                 /* truncated */
        else if (variant > good_len) buf[variant - good_len - 1] ^= 0xFF;       /* one byte flipped */
        sess_init(a, &LIM);
        sess_init(b, &LIM);
        kdb_rc_t ra = sess_feed(a, buf, n, 0);
        kdb_rc_t rb = sess_feed(b, buf, n, 1);
        kdb_rc_t rc7 = KDB_OK;
        if (variant % 16 == 0) { sess_t *c = malloc(sizeof(*c)); sess_init(c, &LIM); rc7 = sess_feed(c, buf, n, 7); CHECK(rc7 == ra && c->nframes == a->nframes); free(c); }
        if (ra != rb || a->nframes != b->nframes || a->sm.state != b->sm.state ||
            memcmp(a->types, b->types, sizeof(uint16_t) * (a->nframes < 256 ? a->nframes : 256)) != 0 ||
            strcmp(a->reason, b->reason) != 0) {
            printf("  variant %zu differs: whole %s/%d, bytes %s/%d\n", variant, kdb_rc_name(ra), a->nframes, kdb_rc_name(rb), b->nframes);
            g_failed++;
        }
        g_checks++;
        if (variant == 0) { CHECK_RC("valid stream", ra, KDB_OK); CHECK(a->nframes == 11 && a->sm.state == KDB_S_READY); }
        free(buf);
    }
    free(a);
    free(b);
    kdb_enc_free(&e);
}

static void test_encoder(void) {
    printf("[encoder]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    CHECK(kdb_enc_u8(&e, 1, 0) != 0 && e.err);                    /* no open message */
    kdb_enc_reset(&e);
    CHECK(kdb_enc_begin(&e, 0x1234) != 0 && e.err);               /* unknown type */
    kdb_enc_reset(&e);
    CHECK(kdb_enc_begin(&e, KDB_T_HELLO) == 0 && kdb_enc_begin(&e, KDB_T_HELLO) != 0);   /* nested begin */
    kdb_enc_reset(&e);
    kdb_enc_begin(&e, KDB_T_HELLO);
    CHECK(kdb_enc_nest_begin(&e, 4) == 0 && kdb_enc_nest_begin(&e, 4) != 0);             /* one level only */
    kdb_enc_reset(&e);
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_nest_begin(&e, 4);
    CHECK(kdb_enc_end(&e) != 0);                                  /* nest still open */
    kdb_enc_reset(&e);
    {   /* ZONE_DATA above 65535 bytes through begin/end */
        static uint8_t big[40000];
        kdb_enc_begin(&e, KDB_T_ZONE_DATA);
        kdb_enc_bytes(&e, 1, big, sizeof(big));
        kdb_enc_bytes(&e, 2, big, sizeof(big));
        CHECK(kdb_enc_end(&e) != 0);
    }
    kdb_enc_reset(&e);
    {   /* a nested entry above 65535 bytes */
        static uint8_t big[40000];
        kdb_enc_begin(&e, KDB_T_INVENTORY);
        kdb_enc_nest_begin(&e, 1);
        kdb_enc_bytes(&e, 1, big, sizeof(big));
        kdb_enc_bytes(&e, 2, big, sizeof(big));
        CHECK(kdb_enc_nest_end(&e) != 0);
    }
    kdb_enc_reset(&e);
    m_hello(&e, 1);                                               /* the buffer is reusable after a reset */
    CHECK(!e.err && e.len > KDB_HEADER_LEN);
    CHECK(memcmp(e.buf, "KDB1", 4) == 0 && e.buf[4] == 0 && e.buf[5] == KDB_T_HELLO && e.buf[6] == 0 && e.buf[7] == 0);
    uint32_t bl = ((uint32_t)e.buf[8] << 24) | ((uint32_t)e.buf[9] << 16) | ((uint32_t)e.buf[10] << 8) | e.buf[11];
    CHECK(bl == e.len - KDB_HEADER_LEN);
    /* HELLO, byte by byte as written in the header comment: tag 1 = u16 version 1 */
    CHECK(e.buf[12] == 0 && e.buf[13] == 1 && e.buf[14] == 0 && e.buf[15] == 2 && e.buf[16] == 0 && e.buf[17] == 1);
    kdb_enc_free(&e);
    CHECK(kdb_type_name(KDB_T_ZONE_BEGIN)[0] == 'Z' && strcmp(kdb_type_name(0x7777), "?") == 0);
}

/* ---------------------------------------------------------------- seed corpus for fuzz_db_stream */
static int write_seed(const char *dir, const char *name, uint8_t selector, const kdb_enc_t *e) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *fp = fopen(path, "wb");
    if (!fp) { perror(path); return -1; }
    fputc(selector, fp);       /* fuzz_db_stream: byte 0 selects chunking and options */
    fwrite(e->buf, 1, e->len, fp);
    fclose(fp);
    return 0;
}

static int gen_corpus_fetch(const char *dir);

static int gen_corpus(const char *dir) {
    kdb_enc_t e;
    kdb_enc_init(&e);
    int rc = 0;
    m_hello(&e, 1); m_inv_req(&e); m_batch_begin(&e, 7); m_profile(&e);
    kdb_enc_begin(&e, KDB_T_ZONE_BEGIN); zb_required(&e, 1, ZN, 4); kdb_enc_str(&e, 9, "ixfr-history 5\n"); kdb_enc_str(&e, 10, "default"); kdb_enc_end(&e);
    m_zone_data(&e, 3, 1, 40); m_zone_data(&e, 1, 0, 20); m_zone_end(&e, 4);
    m_zone_failed(&e); m_zone_delete(&e); m_batch_end(&e, 7, 1, 1, 1);
    rc |= write_seed(dir, "seed_loader_batch.bin", 0x80, &e);
    kdb_enc_reset(&e);
    m_batch_begin(&e, 3); m_zone_begin(&e, 0, ZN, 4); m_zone_data(&e, 2, 0, 30); m_zone_abort(&e);
    m_zone_begin(&e, 2, "b.test.", 3); m_zone_data(&e, 3, 0, 30); m_zone_end(&e, 3); m_batch_end(&e, 3, 1, 0, 0);
    rc |= write_seed(dir, "seed_loader_abort.bin", 0xC0, &e);   /* bit 6: start in READY */
    kdb_enc_reset(&e);
    kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);       /* B6a: a batch that answers a RELOAD_REQ (tag 4), empty */
    kdb_enc_u64(&e, 1, 9); kdb_enc_u8(&e, 2, KDB_BATCH_ZONE); kdb_enc_u64(&e, 3, 0); kdb_enc_u64(&e, 4, 4242);
    kdb_enc_end(&e);
    m_batch_end(&e, 9, 0, 0, 0);
    rc |= write_seed(dir, "seed_loader_request_batch.bin", 0xC0, &e);
    kdb_enc_reset(&e);
    kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);       /* ... with the one deleted zone it was asked for */
    kdb_enc_u64(&e, 1, 10); kdb_enc_u8(&e, 2, KDB_BATCH_ZONE); kdb_enc_u64(&e, 3, 0); kdb_enc_u64(&e, 4, 4243);
    kdb_enc_end(&e);
    m_zone_delete(&e); m_batch_end(&e, 10, 0, 0, 1);
    rc |= write_seed(dir, "seed_loader_request_delete.bin", 0xC0, &e);
    kdb_enc_reset(&e);
    m_config(&e); m_reload_req(&e, false); m_reload_req(&e, true); m_inventory(&e); m_inventory_end(&e);
    m_zone_result(&e); m_batch_result(&e);
    rc |= write_seed(dir, "seed_backend.bin", 0x80, &e);
    kdb_enc_reset(&e);        /* B7b: a SLAVE and a CONSUMER zone (no data), a primary around them; start inside a batch for the install run */
    m_zone_begin(&e, 0, ZN, 4); m_zone_data(&e, 3, 1, 40); m_zone_data(&e, 1, 0, 20); m_zone_end(&e, 4);
    m_zone_begin_kind(&e, 0, "s.test.", 0, KDB_ZK_SECONDARY); m_zone_end(&e, 0);
    m_zone_begin_kind(&e, 1, "c.test.", 0, KDB_ZK_CATALOG); m_zone_end(&e, 0);
    m_zone_begin_kind(&e, 0, "s.test.", 0, KDB_ZK_SECONDARY); m_zone_end(&e, 0);
    m_zone_begin(&e, 0, "s.test.", 4); m_zone_data(&e, 3, 1, 40); m_zone_data(&e, 1, 0, 20); m_zone_end(&e, 4);
    rc |= write_seed(dir, "seed_install_secondary.bin", 0xD0, &e);
    kdb_enc_reset(&e);
    m_hello(&e, 1); m_batch_begin(&e, 1);
    rc |= write_seed(dir, "seed_hello_batch_chunked.bin", 0x05, &e);
    kdb_enc_reset(&e);        /* B9: the auto reload report between two batches */
    m_batch_begin(&e, 2); m_batch_end(&e, 2, 0, 0, 0); m_auto_status(&e, 3); m_batch_begin(&e, 3); m_batch_end(&e, 3, 0, 0, 0);
    rc |= write_seed(dir, "seed_loader_auto_status.bin", 0xC0, &e);
    kdb_enc_free(&e);
    return rc | gen_corpus_fetch(dir);
}

/* B6a: BATCH_BEGIN tag 4 request_id (optional u64): the batch answers that RELOAD_REQ */
static void test_batch_request_id(void) {
    kdb_enc_t e;
    kdb_enc_init(&e);
    kdb_msg_t m;
    char why[KDB_REASON_LEN];
    kdb_frame_t fr;
    kdb_framer_t f;
    /* with the tag */
    kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(&e, 1, 5); kdb_enc_u8(&e, 2, KDB_BATCH_ZONE); kdb_enc_u64(&e, 3, 0); kdb_enc_u64(&e, 4, 0x0102030405060708ull);
    kdb_enc_end(&e);
    kdb_framer_init(&f, KDB_FROM_LOADER, g_rbuf, sizeof(g_rbuf));
    CHECK_RC("feed", kdb_framer_feed(&f, e.buf, e.len), KDB_OK);
    CHECK_RC("next", kdb_framer_next(&f, &fr), KDB_OK);
    CHECK_RC("decode with request_id", kdb_decode(&fr, NVIEWS, &m, why, sizeof(why)), KDB_OK);
    CHECK(m.u.batch_begin.request_id == 0x0102030405060708ull && m.u.batch_begin.kind == KDB_BATCH_ZONE);
    /* the state machine accepts it and the id of BATCH_END still has to match batch_id */
    CHECK_RC("state machine", send_enc(KDB_S_READY, &e), KDB_OK);
    /* without the tag: request_id 0 */
    kdb_enc_reset(&e); m_batch_begin(&e, 5);
    kdb_framer_init(&f, KDB_FROM_LOADER, g_rbuf, sizeof(g_rbuf));
    CHECK_RC("feed2", kdb_framer_feed(&f, e.buf, e.len), KDB_OK);
    CHECK_RC("next2", kdb_framer_next(&f, &fr), KDB_OK);
    CHECK_RC("decode without request_id", kdb_decode(&fr, NVIEWS, &m, why, sizeof(why)), KDB_OK);
    CHECK(m.u.batch_begin.request_id == 0);
    /* a duplicate tag 4, a short tag 4 and an unknown tag 5 are protocol errors */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(&e, 1, 5); kdb_enc_u8(&e, 2, 3); kdb_enc_u64(&e, 3, 0); kdb_enc_u64(&e, 4, 1); kdb_enc_u64(&e, 4, 2); kdb_enc_end(&e);
    CHECK_RC("duplicate request_id", send_enc(KDB_S_READY, &e), KDB_E_TLV_DUP);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(&e, 1, 5); kdb_enc_u8(&e, 2, 3); kdb_enc_u64(&e, 3, 0); kdb_enc_u32(&e, 4, 1); kdb_enc_end(&e);
    CHECK_RC("request_id of 4 bytes", send_enc(KDB_S_READY, &e), KDB_E_TLV_LEN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(&e, 1, 5); kdb_enc_u8(&e, 2, 3); kdb_enc_u64(&e, 3, 0); kdb_enc_u64(&e, 4, 1); kdb_enc_u64(&e, 5, 1); kdb_enc_end(&e);
    CHECK_RC("tag 5 is unknown", send_enc(KDB_S_READY, &e), KDB_E_TLV_UNKNOWN);
    kdb_enc_free(&e);
}

/* B9: AUTO_STATUS, the loader's report on auto reload (legal between batches only, no state change) */
static void test_auto_status(void) {
    printf("[AUTO_STATUS]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    sess_t *s = malloc(sizeof(*s));
    sess_init(s, &LIM);
    sess_to(s, KDB_S_READY);
    m_auto_status(&e, 3);
    CHECK_RC("accepted between batches", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.state == KDB_S_READY && s->m.type == KDB_T_AUTO_STATUS && s->m.u.auto_status.n_entries == 3);
    kdb_iter_t it;
    kdb_auto_status_entry_t en;
    kdb_auto_status_entries(&s->m, &it);
    for (unsigned i = 0; i < 3; i++) {
        CHECK(kdb_auto_status_entries_next(&it, &en));
        CHECK(en.view == i && en.last_poll == 1700000000u + i && en.applied_seq == 41 + i && en.pending == i);
        CHECK(i == 1 ? (en.error.len == 24 && memcmp(en.error.p, "cannot open the database", 24) == 0) : en.error.p == NULL);
    }
    CHECK(!kdb_auto_status_entries_next(&it, &en));
    /* a batch follows and ends as usual; a report after it is fine again */
    kdb_enc_reset(&e); m_batch_begin(&e, 8); m_batch_end(&e, 8, 0, 0, 0); m_auto_status(&e, 1); m_batch_begin(&e, 9);
    CHECK_RC("around a batch", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.state == KDB_S_IN_BATCH);
    /* an empty report is valid */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS); kdb_enc_end(&e);
    CHECK_RC("no entries", send_enc(KDB_S_READY, &e), KDB_OK);
    /* decoded with chunks of one byte too */
    sess_init(s, &LIM);
    sess_to(s, KDB_S_READY);
    kdb_enc_reset(&e); m_auto_status(&e, 2);
    CHECK_RC("one byte at a time", sess_feed(s, e.buf, e.len, 1), KDB_OK);
    CHECK(s->m.u.auto_status.n_entries == 2);
    /* the rules of an entry */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, NVIEWS); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("view index out of range", send_enc(KDB_S_READY, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u32(&e, 4, 1); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("missing applied_seq", send_enc(KDB_S_READY, &e), KDB_E_TLV_MISSING);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u16(&e, 4, 1); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("pending of 2 bytes", send_enc(KDB_S_READY, &e), KDB_E_TLV_LEN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_u8(&e, 12, 1); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("unknown tag 12", send_enc(KDB_S_READY, &e), KDB_E_TLV_UNKNOWN);
    /* B11: the optional tags 6..11 (reload requests of a multi-server database) */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 1); kdb_enc_u64(&e, 2, 0); kdb_enc_u64(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
    kdb_enc_u8(&e, 6, KDB_AS_REQ); kdb_enc_str(&e, 7, "ns1"); kdb_enc_u64(&e, 8, 1234567890123ull); kdb_enc_u8(&e, 9, 1);
    kdb_enc_str(&e, 10, "cannot write karidns_server_status"); kdb_enc_u64(&e, 11, 1700000001u); kdb_enc_nest_end(&e);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 2); kdb_enc_u64(&e, 2, 5); kdb_enc_u64(&e, 3, 6); kdb_enc_u32(&e, 4, 7); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    sess_init(s, &LIM);
    sess_to(s, KDB_S_READY);
    CHECK_RC("request fields", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    kdb_auto_status_entries(&s->m, &it);
    CHECK(kdb_auto_status_entries_next(&it, &en));
    CHECK(en.view == 1 && en.flags == KDB_AS_REQ && en.server_id.len == 3 && memcmp(en.server_id.p, "ns1", 3) == 0 &&
          en.req_generation == 1234567890123ull && en.req_ok && en.req_error.len == 34 && en.req_time == 1700000001u);
    CHECK(kdb_auto_status_entries_next(&it, &en));
    CHECK(en.view == 2 && en.flags == KDB_AS_AUTO && en.server_id.p == NULL && en.req_generation == 0 && !en.req_ok &&
          en.req_error.p == NULL && en.req_time == 0);      /* an entry of B9 / B10 (no flags) is about auto reload */
    CHECK(!kdb_auto_status_entries_next(&it, &en));
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_u8(&e, 6, 4); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("flags above 3", send_enc(KDB_S_READY, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_u8(&e, 9, 2); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("req_ok above 1", send_enc(KDB_S_READY, &e), KDB_E_RANGE);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_str(&e, 7, ""); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("empty server id", send_enc(KDB_S_READY, &e), KDB_E_TLV_STR);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_str(&e, 7, "01234567890123456789012345678901234567890123456789012345678901234"); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("server id of 65 bytes", send_enc(KDB_S_READY, &e), KDB_E_TLV_STR);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_bytes(&e, 10, "bad\x01text", 8); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("control character in req_error", send_enc(KDB_S_READY, &e), KDB_E_TLV_STR);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_u32(&e, 8, 1); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("req_generation of 4 bytes", send_enc(KDB_S_READY, &e), KDB_E_TLV_LEN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_bytes(&e, 5, "bad\x01text", 8); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("control character in the error", send_enc(KDB_S_READY, &e), KDB_E_TLV_STR);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    kdb_enc_u8(&e, 2, 1);
    kdb_enc_end(&e);
    CHECK_RC("tag 2 at the top is unknown", send_enc(KDB_S_READY, &e), KDB_E_TLV_UNKNOWN);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_AUTO_STATUS);
    for (int i = 0; i <= KDB_MAX_CONFIG_VIEWS; i++) {
        kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_u64(&e, 2, 1); kdb_enc_u64(&e, 3, 1); kdb_enc_u32(&e, 4, 1); kdb_enc_nest_end(&e);
    }
    kdb_enc_end(&e);
    CHECK(!e.err);
    CHECK_RC("1025 entries", send_enc(KDB_S_READY, &e), KDB_E_RANGE);
    /* before the HELLO it is refused */
    kdb_enc_reset(&e); m_auto_status(&e, 1);
    CHECK_RC("before HELLO", send_enc(KDB_S_AWAIT_HELLO, &e), KDB_E_STATE);
    free(s);
    kdb_enc_free(&e);
}

/* ---------------------------------------------------------------- the check protocol (B12, dns_db_checkproto.h) */
static void test_checkproto(void) {
    char out[64], back[64];
    bool trunc;
    /* escape: printable ASCII as it is; TAB, LF, backslash, DEL and bytes above 0x7e as \DDD (decimal) */
    size_t n = chk_escape("a b\tc\n\\d\x7f\xc3\xa9", 11, out, sizeof(out), &trunc);
    CHECK_STR(out, "a b\\009c\\010\\092d\\127\\195\\169");
    CHECK(n == strlen(out) && !trunc);
    /* round trip, byte for byte, with a NUL in the middle */
    const char raw[] = { 'x', 0, 'y', '\r', '"', '\'', (char)0xff, '\\', '1', '2', '3' };
    n = chk_escape(raw, sizeof(raw), out, sizeof(out), &trunc);
    CHECK(!trunc);
    size_t m = chk_unescape(out, n, back, sizeof(back));
    CHECK(m == sizeof(raw) && memcmp(back, raw, sizeof(raw)) == 0);
    /* truncation never cuts an escape, and says so */
    n = chk_escape("\x01\x02\x03\x04", 4, out, 10, &trunc);
    CHECK(trunc && n == 8 && strcmp(out, "\\001\\002") == 0);
    n = chk_escape("abcdef", 6, out, 4, &trunc);
    CHECK(trunc && n == 3 && strcmp(out, "abc") == 0);
    CHECK(chk_escape("abc", 3, out, 0, &trunc) == 0 && !trunc);
    /* unescape: every malformed input is refused */
    CHECK(chk_unescape("a\\", 2, back, sizeof(back)) == (size_t)-1);          /* a backslash at the end */
    CHECK(chk_unescape("\\12", 3, back, sizeof(back)) == (size_t)-1);         /* two digits */
    CHECK(chk_unescape("\\1x3", 4, back, sizeof(back)) == (size_t)-1);        /* not a digit */
    CHECK(chk_unescape("\\256", 4, back, sizeof(back)) == (size_t)-1);        /* above 255 */
    CHECK(chk_unescape("a\tb", 3, back, sizeof(back)) == (size_t)-1);         /* a raw TAB */
    CHECK(chk_unescape("\x80", 1, back, sizeof(back)) == (size_t)-1);         /* a high byte */
    CHECK(chk_unescape("abcd", 4, back, 4) == (size_t)-1);                    /* does not fit with its NUL */
    CHECK(chk_unescape("abc", 3, back, 4) == 3 && strcmp(back, "abc") == 0);
    CHECK(chk_unescape("", 0, back, 1) == 0);
    CHECK(chk_unescape("a", 1, back, 0) == (size_t)-1);
    /* split */
    char line[] = "E\t\ta.test.\t12\ttext";
    char *f[8];
    CHECK(chk_split(line, f, 8) == 5 && strcmp(f[0], "E") == 0 && f[1][0] == '\0' && strcmp(f[4], "text") == 0);
    char l2[] = "R\t1\t2\t3";
    CHECK(chk_split(l2, f, 3) == -1);                                          /* more fields than room */
    char l2b[] = "R\t1\t2\t3";
    CHECK(chk_split(l2b, f, 4) == 4);
    char l3[] = "Z\tbad\001ctl";
    CHECK(chk_split(l3, f, 8) == -1);                                          /* a control character other than TAB */
    char l4[] = "";
    CHECK(chk_split(l4, f, 8) == 1 && f[0][0] == '\0');
    char l5[] = "a\t";
    CHECK(chk_split(l5, f, 8) == 2 && f[1][0] == '\0');
    /* printable */
    char p[] = "ok\x01\x1b[31m\x7f\xc3z";
    chk_printable(p);
    CHECK_STR(p, "ok??[31m??z");
}

/* ---------------------------------------------------------------- the fetch stream (D1a, design 6.1) */
static void fz_begin(kdb_enc_t *e, uint16_t view, const char *name, uint64_t rr, uint32_t flags, uint8_t kind, uint64_t req) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (flags & KDB_ZF_SUMMARY) ? 0 : 0x6B, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, name); kdb_enc_i64(e, 3, 5); kdb_enc_u8(e, 4, kind);
    kdb_enc_u32(e, 5, 77); kdb_enc_u32(e, 6, flags); kdb_enc_u64(e, 7, rr); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    if (kind != KDB_ZK_PRIMARY) kdb_enc_str(e, 9, "masters { 192.0.2.1; };");
    if (req) kdb_enc_u64(e, 11, req);
    kdb_enc_end(e);
}
static void fz_failed(kdb_enc_t *e, uint64_t req) {
    kdb_enc_begin(e, KDB_T_ZONE_FAILED);
    kdb_enc_u16(e, 1, 2); kdb_enc_name(e, 2, "failed.test."); kdb_enc_i64(e, 3, 7); kdb_enc_str(e, 4, "busy");
    if (req) kdb_enc_u64(e, 5, req);
    kdb_enc_end(e);
}
static void fz_fetch_req(kdb_enc_t *e, uint64_t id, uint16_t view, const char *name, uint8_t prio, uint8_t mode) {
    kdb_enc_begin(e, KDB_T_FETCH_REQ);
    kdb_enc_u64(e, 1, id); kdb_enc_u16(e, 2, view); kdb_enc_name(e, 3, name); kdb_enc_u8(e, 4, prio); kdb_enc_u8(e, 5, mode);
}
static void sess_init_fetch(sess_t *s, const kdb_limits_t *lim) {
    memset(s, 0, sizeof(*s));
    kdb_framer_init(&s->f, KDB_FROM_LOADER, g_rbuf, sizeof(g_rbuf));
    kdb_sm_init_fetch(&s->sm, lim ? lim : &LIM);
}
/* the bytes of e into a fresh fetch session that has been brought to `st` (READY, or IN_ZONE after a primary ZONE_BEGIN) */
static kdb_rc_t fetch_send(kdb_state_t st, const kdb_enc_t *e, char *reason) {
    CHECK(!e->err);
    sess_t *s = malloc(sizeof(*s));
    sess_init_fetch(s, NULL);
    if (st == KDB_S_IN_ZONE) {
        kdb_enc_t p;
        kdb_enc_init(&p);
        fz_begin(&p, 1, ZN, 10, 0, KDB_ZK_PRIMARY, 9);
        CHECK_RC("prefix", sess_feed(s, p.buf, p.len, 0), KDB_OK);
        kdb_enc_free(&p);
    }
    CHECK(s->sm.state == st);
    kdb_rc_t rc = sess_feed(s, e->buf, e->len, 0);
    if (reason) snprintf(reason, KDB_REASON_LEN, "%s", s->reason);
    free(s);
    return rc;
}
/* decode one Backend -> loader frame */
static kdb_rc_t dec_backend(const kdb_enc_t *e, kdb_msg_t *m, char *why) {
    kdb_framer_t f;
    kdb_frame_t fr;
    kdb_framer_init(&f, KDB_FROM_BACKEND, g_rbuf, sizeof(g_rbuf));
    kdb_rc_t rc = kdb_framer_feed(&f, e->buf, e->len);
    if (rc == KDB_OK) rc = kdb_framer_next(&f, &fr);
    if (rc != KDB_OK) { snprintf(why, KDB_REASON_LEN, "%s", f.reason); return rc; }
    return kdb_decode(&fr, NVIEWS, m, why, KDB_REASON_LEN);
}

static void test_fetch_req_and_inventory(void) {
    printf("[FETCH_REQ and the INVENTORY resident flag]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    kdb_msg_t m;
    char why[KDB_REASON_LEN];
    /* FETCH_REQ: every field comes back */
    fz_fetch_req(&e, 0x0102030405060708ull, 2, "fetch.test.", KDB_FETCH_PRIO_WARM, KDB_FETCH_SUMMARY);
    kdb_enc_end(&e);
    CHECK_RC("FETCH_REQ", dec_backend(&e, &m, why), KDB_OK);
    CHECK(m.type == KDB_T_FETCH_REQ && m.u.fetch_req.request_id == 0x0102030405060708ull && m.u.fetch_req.view == 2 &&
          strcmp(m.u.fetch_req.name, "fetch.test.") == 0 && m.u.fetch_req.priority == KDB_FETCH_PRIO_WARM &&
          m.u.fetch_req.mode == KDB_FETCH_SUMMARY && !m.u.fetch_req.has_range);
    CHECK_STR(kdb_type_name(KDB_T_FETCH_REQ), "FETCH_REQ");
    /* with a range (both ends) */
    kdb_enc_reset(&e); fz_fetch_req(&e, 3, 0, ZN, 0, 0); kdb_enc_name(&e, 6, "a.example.test."); kdb_enc_name(&e, 7, "m.example.test."); kdb_enc_end(&e);
    CHECK_RC("FETCH_REQ with a range", dec_backend(&e, &m, why), KDB_OK);
    CHECK(m.u.fetch_req.has_range && strcmp(m.u.fetch_req.range_lo, "a.example.test.") == 0 && strcmp(m.u.fetch_req.range_hi, "m.example.test.") == 0);
    /* rejected: one end of a range, request id 0, priority 3, mode 2, view out of range, unknown tag 8, a missing field, a bad name, a duplicate */
    kdb_enc_reset(&e); fz_fetch_req(&e, 3, 0, ZN, 0, 0); kdb_enc_name(&e, 6, "a.test."); kdb_enc_end(&e);
    CHECK_RC("range_lo alone", dec_backend(&e, &m, why), KDB_E_TLV_MISSING);
    kdb_enc_reset(&e); fz_fetch_req(&e, 3, 0, ZN, 0, 0); kdb_enc_name(&e, 7, "a.test."); kdb_enc_end(&e);
    CHECK_RC("range_hi alone", dec_backend(&e, &m, why), KDB_E_TLV_MISSING);
    kdb_enc_reset(&e); fz_fetch_req(&e, 0, 0, ZN, 0, 0); kdb_enc_end(&e);
    CHECK_RC("request id 0", dec_backend(&e, &m, why), KDB_E_RANGE);
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, 0, ZN, KDB_FETCH_PRIO_N, 0); kdb_enc_end(&e);
    CHECK_RC("priority 3", dec_backend(&e, &m, why), KDB_E_RANGE);
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, 0, ZN, 0, 2); kdb_enc_end(&e);
    CHECK_RC("mode 2", dec_backend(&e, &m, why), KDB_E_RANGE);
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, NVIEWS, ZN, 0, 0); kdb_enc_end(&e);
    CHECK_RC("view out of range", dec_backend(&e, &m, why), KDB_E_RANGE);
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, 0, ZN, 0, 0); kdb_enc_u8(&e, 8, 1); kdb_enc_end(&e);
    CHECK_RC("unknown tag 8", dec_backend(&e, &m, why), KDB_E_TLV_UNKNOWN);
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, 0, ZN, 0, 0); kdb_enc_u8(&e, 5, 1); kdb_enc_end(&e);
    CHECK_RC("duplicate tag", dec_backend(&e, &m, why), KDB_E_TLV_DUP);
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, 0, "not canonical", 0, 0); kdb_enc_end(&e);
    CHECK_RC("bad name", dec_backend(&e, &m, why), KDB_E_TLV_NAME);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_FETCH_REQ); kdb_enc_u64(&e, 1, 1); kdb_enc_u16(&e, 2, 0); kdb_enc_name(&e, 3, ZN); kdb_enc_u8(&e, 4, 0); kdb_enc_end(&e);
    CHECK_RC("mode missing", dec_backend(&e, &m, why), KDB_E_TLV_MISSING);
    /* the loader cannot send it, and the Backend cannot receive a loader message on this direction */
    kdb_enc_reset(&e); fz_fetch_req(&e, 1, 0, ZN, 0, 0); kdb_enc_end(&e);
    CHECK_RC("FETCH_REQ from the loader", send_in(KDB_S_READY, e.buf, e.len, NULL, NULL), KDB_E_TYPE);

    /* INVENTORY: resident (explicit or by default) needs its digest, a non-resident entry has none */
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, 0x33, sizeof(dig));
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "res.test."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 10);
    kdb_enc_bytes(&e, 5, dig, sizeof(dig)); kdb_enc_u8(&e, 6, 1); kdb_enc_nest_end(&e);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 1); kdb_enc_name(&e, 2, "cold.test."); kdb_enc_i64(&e, 3, 2); kdb_enc_u32(&e, 4, 20);
    kdb_enc_u8(&e, 6, 0); kdb_enc_nest_end(&e);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 2); kdb_enc_name(&e, 2, "dflt.test."); kdb_enc_i64(&e, 3, 3); kdb_enc_u32(&e, 4, 30);
    kdb_enc_bytes(&e, 5, dig, sizeof(dig)); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("INVENTORY with a cold entry", dec_backend(&e, &m, why), KDB_OK);
    CHECK(m.u.inventory.n_entries == 3);
    kdb_iter_t it;
    kdb_inventory_entry_t en;
    kdb_inventory_entries(&m, &it);
    CHECK(kdb_inventory_entries_next(&it, &en) && en.resident && strcmp(en.name, "res.test.") == 0 && en.digest[0] == 0x33);
    CHECK(kdb_inventory_entries_next(&it, &en) && !en.resident && strcmp(en.name, "cold.test.") == 0 && en.digest[0] == 0 && en.serial == 20);
    CHECK(kdb_inventory_entries_next(&it, &en) && en.resident && strcmp(en.name, "dflt.test.") == 0 && en.digest[31] == 0x33);
    CHECK(!kdb_inventory_entries_next(&it, &en));
    /* a cold entry may carry a digest anyway; a resident entry without one is refused, by default too */
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "x.test."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_bytes(&e, 5, dig, sizeof(dig)); kdb_enc_u8(&e, 6, 0); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("cold entry with a digest", dec_backend(&e, &m, why), KDB_OK);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "x.test."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_u8(&e, 6, 1); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("resident without a digest", dec_backend(&e, &m, why), KDB_E_TLV_MISSING);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "x.test."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("no flag and no digest", dec_backend(&e, &m, why), KDB_E_TLV_MISSING);
    kdb_enc_reset(&e); kdb_enc_begin(&e, KDB_T_INVENTORY);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "x.test."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 1);
    kdb_enc_u8(&e, 6, 2); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    CHECK_RC("resident 2", dec_backend(&e, &m, why), KDB_E_RANGE);
    kdb_enc_free(&e);
}

static void test_fetch_stream_machine(void) {
    printf("[the fetch stream state machine]\n");
    kdb_enc_t e;
    kdb_enc_init(&e);
    char why[KDB_REASON_LEN];
    /* a whole conversation: a profile and a primary with data, a summary, a secondary, a failure, an aborted zone; byte at a time too */
    m_profile(&e);
    fz_begin(&e, 1, ZN, 4, 0, KDB_ZK_PRIMARY, 11);
    m_zone_data(&e, 3, 1, 20); m_zone_data(&e, 1, 0, 9); m_zone_end(&e, 4);
    fz_begin(&e, 0, "sum.test.", 0, KDB_ZF_SUMMARY | KDB_ZF_PRESIGNED, KDB_ZK_PRIMARY, 12); m_zone_end(&e, 0);
    fz_begin(&e, 2, "sec.test.", 0, 0, KDB_ZK_SECONDARY, 13); m_zone_end(&e, 0);
    fz_failed(&e, 14);
    fz_begin(&e, 0, "ab.test.", 3, 0, KDB_ZK_PRIMARY, 15); m_zone_data(&e, 1, 0, 9); m_zone_abort(&e);
    CHECK(!e.err);
    for (int chunk = 0; chunk <= 7; chunk += 7) {
        sess_t *s = malloc(sizeof(*s));
        sess_init_fetch(s, NULL);
        CHECK(s->sm.state == KDB_S_READY && s->sm.fetch);
        CHECK_RC("conversation", sess_feed(s, e.buf, e.len, (size_t)chunk), KDB_OK);
        CHECK(s->nframes == 13 && s->sm.state == KDB_S_READY && s->sm.n_profiles == 0);
        free(s);
    }
    sess_t *s = malloc(sizeof(*s));
    sess_init_fetch(s, NULL);
    kdb_enc_t p;
    kdb_enc_init(&p);
    fz_begin(&p, 1, ZN, 4, 0, KDB_ZK_PRIMARY, 77);
    CHECK_RC("begin", sess_feed(s, p.buf, p.len, 0), KDB_OK);
    CHECK(s->sm.state == KDB_S_IN_ZONE && s->sm.zone_req_id == 77 && s->m.u.zone_begin.request_id == 77);
    free(s);
    kdb_enc_free(&p);

    /* what the fetch stream does not take, in READY: everything but PROFILE, ZONE_BEGIN and ZONE_FAILED */
    static const uint16_t no_ready[] = { KDB_T_HELLO, KDB_T_INVENTORY_REQ, KDB_T_BATCH_BEGIN, KDB_T_ZONE_DATA, KDB_T_ZONE_END, KDB_T_ZONE_ABORT,
                                         KDB_T_ZONE_DELETE, KDB_T_BATCH_END, KDB_T_AUTO_STATUS };
    for (size_t i = 0; i < sizeof(no_ready) / sizeof(no_ready[0]); i++) {
        kdb_enc_reset(&e);
        m_valid(&e, no_ready[i]);
        CHECK_RC(kdb_type_name(no_ready[i]), fetch_send(KDB_S_READY, &e, why), KDB_E_STATE);
    }
    /* ... and in a zone: only the data, the end and the abort */
    static const uint16_t no_zone[] = { KDB_T_HELLO, KDB_T_INVENTORY_REQ, KDB_T_BATCH_BEGIN, KDB_T_ZONE_BEGIN, KDB_T_ZONE_FAILED, KDB_T_PROFILE,
                                        KDB_T_ZONE_DELETE, KDB_T_BATCH_END, KDB_T_AUTO_STATUS };
    for (size_t i = 0; i < sizeof(no_zone) / sizeof(no_zone[0]); i++) {
        kdb_enc_reset(&e);
        if (no_zone[i] == KDB_T_ZONE_BEGIN) fz_begin(&e, 1, ZN, 10, 0, KDB_ZK_PRIMARY, 8);
        else if (no_zone[i] == KDB_T_ZONE_FAILED) fz_failed(&e, 8);
        else m_valid(&e, no_zone[i]);
        CHECK_RC(kdb_type_name(no_zone[i]), fetch_send(KDB_S_IN_ZONE, &e, why), KDB_E_STATE);
    }
    /* the request id: required on the fetch stream, forbidden on the batch stream, never 0 */
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 10, 0, KDB_ZK_PRIMARY, 0);
    CHECK_RC("ZONE_BEGIN without a request id", fetch_send(KDB_S_READY, &e, why), KDB_E_STATE);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 10, 0, KDB_ZK_PRIMARY, 0); { /* request id 0 written out */
        kdb_enc_t z; kdb_enc_init(&z);
        uint8_t dig[KDB_DIGEST_LEN] = { 0 };
        kdb_enc_begin(&z, KDB_T_ZONE_BEGIN);
        kdb_enc_u16(&z, 1, 1); kdb_enc_name(&z, 2, ZN); kdb_enc_i64(&z, 3, 5); kdb_enc_u8(&z, 4, KDB_ZK_PRIMARY); kdb_enc_u32(&z, 5, 1); kdb_enc_u32(&z, 6, 0);
        kdb_enc_u64(&z, 7, 10); kdb_enc_bytes(&z, 8, dig, sizeof(dig)); kdb_enc_u64(&z, 11, 0); kdb_enc_end(&z);
        CHECK_RC("ZONE_BEGIN request id 0", fetch_send(KDB_S_READY, &z, why), KDB_E_RANGE);
        kdb_enc_free(&z);
    }
    kdb_enc_reset(&e); fz_failed(&e, 0);
    CHECK_RC("ZONE_FAILED without a request id", fetch_send(KDB_S_READY, &e, why), KDB_E_STATE);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 10, 0, KDB_ZK_PRIMARY, 5);
    CHECK_RC("batch stream: ZONE_BEGIN with a request id", send_enc(KDB_S_IN_BATCH, &e), KDB_E_STATE);
    kdb_enc_reset(&e); fz_failed(&e, 5);
    CHECK_RC("batch stream: ZONE_FAILED with a request id", send_enc(KDB_S_IN_BATCH, &e), KDB_E_STATE);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 0, KDB_ZF_SUMMARY, KDB_ZK_PRIMARY, 0);
    CHECK_RC("batch stream: a summary", send_enc(KDB_S_IN_BATCH, &e), KDB_E_STATE);
    /* the SOA timers of a summary: all three or none */
    {
        uint8_t zd[KDB_DIGEST_LEN] = { 0 };
        for (int nt = 0; nt <= 3; nt++) {
            kdb_enc_reset(&e);
            kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
            kdb_enc_u16(&e, 1, 1); kdb_enc_name(&e, 2, ZN); kdb_enc_i64(&e, 3, 5); kdb_enc_u8(&e, 4, KDB_ZK_PRIMARY); kdb_enc_u32(&e, 5, 9);
            kdb_enc_u32(&e, 6, KDB_ZF_SUMMARY); kdb_enc_u64(&e, 7, 0); kdb_enc_bytes(&e, 8, zd, sizeof(zd)); kdb_enc_u64(&e, 11, 5);
            if (nt >= 1) kdb_enc_u32(&e, 12, 3600);
            if (nt >= 2) kdb_enc_u32(&e, 13, 600);
            if (nt >= 3) kdb_enc_u32(&e, 14, 1209600);
            kdb_enc_end(&e);
            sess_t *ts = malloc(sizeof(*ts));
            sess_init_fetch(ts, NULL);
            kdb_rc_t trc = sess_feed(ts, e.buf, e.len, 0);
            if (nt == 0 || nt == 3) {
                CHECK_RC("SOA timers", trc, KDB_OK);
                CHECK(ts->m.u.zone_begin.has_soa_timers == (nt == 3));
                if (nt == 3) CHECK(ts->m.u.zone_begin.soa_refresh == 3600 && ts->m.u.zone_begin.soa_retry == 600 && ts->m.u.zone_begin.soa_expire == 1209600);
            } else {
                CHECK_RC("SOA timers, not all three", trc, KDB_E_TLV_MISSING);
            }
            free(ts);
        }
    }
    /* summaries: rr_count 0, only a primary, no data afterwards */
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 3, KDB_ZF_SUMMARY, KDB_ZK_PRIMARY, 5);
    CHECK_RC("summary with records", fetch_send(KDB_S_READY, &e, why), KDB_E_COUNT);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 0, KDB_ZF_SUMMARY, KDB_ZK_SECONDARY, 5);
    CHECK_RC("summary of a secondary", fetch_send(KDB_S_READY, &e, why), KDB_E_RANGE);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 0, KDB_ZF_SUMMARY, KDB_ZK_PRIMARY, 5); m_zone_data(&e, 1, 0, 9);
    CHECK_RC("data after a summary", fetch_send(KDB_S_READY, &e, why), KDB_E_COUNT);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 1, 0, KDB_ZK_PRIMARY, 5);
    CHECK_RC("a full zone needs two SOAs", fetch_send(KDB_S_READY, &e, why), KDB_E_COUNT);
    /* the usual limits still hold: a zone above the byte limit, an END with the wrong count, a view out of range */
    kdb_limits_t tiny = { 1000, 100, NVIEWS };
    s = malloc(sizeof(*s));
    sess_init_fetch(s, &tiny);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 4, 0, KDB_ZK_PRIMARY, 6); m_zone_data(&e, 4, 0, 400);
    CHECK_RC("zone above max-zone-bytes", sess_feed(s, e.buf, e.len, 0), KDB_E_LIMIT_BYTES);
    CHECK_RC("sticky", sess_feed(s, e.buf, e.len, 0), KDB_E_LIMIT_BYTES);
    free(s);
    kdb_enc_reset(&e); fz_begin(&e, 1, ZN, 4, 0, KDB_ZK_PRIMARY, 6); m_zone_end(&e, 4);
    CHECK_RC("END without the data", fetch_send(KDB_S_READY, &e, why), KDB_E_COUNT);
    kdb_enc_reset(&e); fz_begin(&e, NVIEWS, ZN, 4, 0, KDB_ZK_PRIMARY, 6);
    CHECK_RC("view out of range", fetch_send(KDB_S_READY, &e, why), KDB_E_RANGE);
    /* the profile count of a zone starts again after it (65,535 PROFILEs are allowed between two zones) */
    s = malloc(sizeof(*s));
    sess_init_fetch(s, NULL);
    kdb_enc_reset(&e); m_profile(&e); m_profile(&e);
    CHECK_RC("profiles", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.n_profiles == 2);
    kdb_enc_reset(&e); fz_failed(&e, 9);
    CHECK_RC("failed", sess_feed(s, e.buf, e.len, 0), KDB_OK);
    CHECK(s->sm.n_profiles == 0 && s->sm.state == KDB_S_READY);
    free(s);
    kdb_enc_free(&e);
}

/* the seeds of the fetch stream (selector bit 3) and of the Backend side messages of D1a */
static int gen_corpus_fetch(const char *dir) {
    kdb_enc_t e;
    kdb_enc_init(&e);
    int rc = 0;
    m_profile(&e);
    fz_begin(&e, 1, ZN, 4, 0, KDB_ZK_PRIMARY, 11);
    m_zone_data(&e, 3, 1, 20); m_zone_data(&e, 1, 0, 9); m_zone_end(&e, 4);
    fz_begin(&e, 0, "sum.test.", 0, KDB_ZF_SUMMARY | KDB_ZF_PRESIGNED, KDB_ZK_PRIMARY, 12); m_zone_end(&e, 0);
    fz_begin(&e, 2, "sec.test.", 0, 0, KDB_ZK_SECONDARY, 13); m_zone_end(&e, 0);
    fz_failed(&e, 14);
    fz_begin(&e, 0, "ab.test.", 3, 0, KDB_ZK_PRIMARY, 15); m_zone_data(&e, 1, 0, 9); m_zone_abort(&e);
    rc |= write_seed(dir, "seed_fetch_stream.bin", 0x88, &e);
    rc |= write_seed(dir, "seed_fetch_stream_install.bin", 0x08, &e);        /* (also through the install run) */
    kdb_enc_reset(&e);
    fz_fetch_req(&e, 1, 0, ZN, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL); kdb_enc_end(&e);
    fz_fetch_req(&e, 2, 1, "w.test.", KDB_FETCH_PRIO_WARM, KDB_FETCH_SUMMARY); kdb_enc_name(&e, 6, "a.w.test."); kdb_enc_name(&e, 7, "m.w.test."); kdb_enc_end(&e);
    kdb_enc_begin(&e, KDB_T_INVENTORY);
    uint8_t dig[KDB_DIGEST_LEN] = { 7 };
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "res.test."); kdb_enc_i64(&e, 3, 1); kdb_enc_u32(&e, 4, 10);
    kdb_enc_bytes(&e, 5, dig, sizeof(dig)); kdb_enc_u8(&e, 6, 1); kdb_enc_nest_end(&e);
    kdb_enc_nest_begin(&e, 1); kdb_enc_u16(&e, 1, 1); kdb_enc_name(&e, 2, "cold.test."); kdb_enc_i64(&e, 3, 2); kdb_enc_u32(&e, 4, 20);
    kdb_enc_u8(&e, 6, 0); kdb_enc_nest_end(&e);
    kdb_enc_end(&e);
    rc |= write_seed(dir, "seed_backend_fetch.bin", 0x80, &e);
    kdb_enc_free(&e);
    return rc;
}

/* the names the loader and the Backend log for a result code and a message type: one each, none empty, "?" for the unknown */
static void test_names(void) {
    printf("result code and message type names\n");
    static const struct { kdb_rc_t rc; const char *name; } rcs[] = {
        { KDB_OK, "ok" }, { KDB_MORE, "more" }, { KDB_E_MAGIC, "bad magic" }, { KDB_E_TYPE, "unknown type" },
        { KDB_E_FLAGS, "bad flags" }, { KDB_E_LENGTH, "bad length" }, { KDB_E_TLV_TRUNC, "truncated TLV" },
        { KDB_E_TLV_DUP, "duplicate tag" }, { KDB_E_TLV_UNKNOWN, "unknown tag" }, { KDB_E_TLV_MISSING, "missing tag" },
        { KDB_E_TLV_LEN, "bad value length" }, { KDB_E_TLV_STR, "bad string" }, { KDB_E_TLV_NAME, "bad name" },
        { KDB_E_RANGE, "value out of range" }, { KDB_E_STATE, "message not allowed in this state" },
        { KDB_E_VERSION, "protocol version mismatch" }, { KDB_E_DNSHDR, "bad ZONE_DATA DNS header" },
        { KDB_E_OPT, "OPT outside the first ZONE_DATA" }, { KDB_E_COUNT, "RR count mismatch" }, { KDB_E_SEQ, "batch mismatch" },
        { KDB_E_LIMIT_BYTES, "zone byte limit exceeded" }, { KDB_E_LIMIT_RECORDS, "zone record limit exceeded" },
        { KDB_E_LIMIT_PROFILES, "profile limit exceeded" },
    };
    for (size_t i = 0; i < sizeof(rcs) / sizeof(rcs[0]); i++) CHECK_STR(kdb_rc_name(rcs[i].rc), rcs[i].name);
    CHECK_STR(kdb_rc_name((kdb_rc_t)9999), "?");
    CHECK_STR(kdb_type_name(KDB_T_HELLO), "HELLO");
    CHECK_STR(kdb_type_name(KDB_T_ZONE_FAILED), "ZONE_FAILED");
    CHECK_STR(kdb_type_name(0x7fff), "?");
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--gen-corpus") == 0) return gen_corpus(argv[2]) ? 1 : 0;
    test_roundtrip_loader();
    test_roundtrip_backend();
    test_framer_rejects();
    test_tlv_rejects();
    test_backend_direction_rejects();
    test_path_charset();
    test_state_matrix();
    test_zone_data_header();
    test_counts_and_limits();
    test_chunking();
    test_encoder();
    test_batch_request_id();
    test_auto_status();
    test_checkproto();
    test_fetch_req_and_inventory();
    test_fetch_stream_machine();
    test_names();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

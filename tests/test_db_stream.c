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
            CHECK(kdb_config_views_next(&it, &v) && v.index == 0 && v.name.len == 8 && v.source.p == NULL && v.auto_reload == 0);
            CHECK(v.poll_interval == 2 && v.coalesce_ms == 1000 && v.max_zone_records == KDB_DEFAULT_MAX_ZONE_RECORDS);
            CHECK(kdb_config_views_next(&it, &v) && v.index == 1 && v.source.len == 32 && v.auto_reload == 1);
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
        kdb_enc_u32(&e, 6, 4); kdb_enc_u64(&e, 7, 4); kdb_enc_bytes(&e, 8, dig, sizeof(dig));
    }
    kdb_enc_end(&e);
    CHECK_RC("reserved zone flag", send_enc(KDB_S_IN_BATCH, &e), KDB_E_RANGE);
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
        KDB_T_BATCH_END };
    /* legal[state][type index] */
    static const bool legal[4][11] = {
        /* AWAIT_HELLO */ { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        /* READY       */ { 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
        /* IN_BATCH    */ { 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1 },
        /* IN_ZONE     */ { 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
    };
    kdb_enc_t e;
    kdb_enc_init(&e);
    for (int st = 0; st < 4; st++)
        for (size_t t = 0; t < 11; t++) {
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
    kdb_enc_reset(&e);
    m_hello(&e, 1); m_batch_begin(&e, 1);
    rc |= write_seed(dir, "seed_hello_batch_chunked.bin", 0x05, &e);
    kdb_enc_free(&e);
    return rc;
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
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

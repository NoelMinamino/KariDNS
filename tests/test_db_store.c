/*
 * test_db_store.c - the zone store in the server (0.7 store S2): dns_db_store.c with the real db ingest thread, dns_park.c and dns_snapshot_rcu.c.
 *
 * The test is the loader (a stream and a fetch stream, as test_db_fetch.c) and a worker (it asks for attaches as udp_park() does).  Cases:
 *   1. write-through: zones that a batch installs are in the store (stored, serial, source id, digest, image bytes); the same version again is not written again;
 *      a zone the database deletes is deleted from the store
 *   2. attach: a zone taken out of memory is attached from the store at the worker's request: it wakes the worker, the loader is not asked, and the answers
 *      (a set of queries, whole messages) are the bytes of the answers before the zone left memory
 *   3. accounting: what the version counts for memory-limit when it is attached is given back when it is freed (the totals return to where they were, never below
 *      zero), the image is given back to the store (no version is live afterwards)
 *   4. stale (another serial in the directory), missing (no record), damaged (a byte of the record changed): the attach falls back to the fetch (the queries that wait
 *      get a retry key, the loader gets the request); a damaged record is set back to "known" and written again by the install
 *   5. a version that is attached is read by another thread while the zone is taken out of memory and attached again, over and over (TSan, ASan)
 * The store is in MAP mode; run with the argument `copy` for COPY mode (main() runs both when it is started without one).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "../dns_config_parser.h"
#include "../dns_db_ingest.h"
#include "../dns_db_store.h"
#include "../dns_db_stream.h"
#include "../dns_epoch_rcu.h"
#include "../dns_park.h"
#include "../dns_query_engine.h"
#include "../dns_server_internal.h"
#include "../dns_snapshot_rcu.h"
#include "../dns_store.h"
#include "../dns_utils.h"

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---------------------------------------------------------------- the loader's end of a stream */
typedef struct {
    int fd;
    kdb_framer_t fr;
    uint8_t body[KDB_MAX_BODY];
    uint8_t buf[65536];
} ch_t;

static void ch_init(ch_t *c, int fd, kdb_dir_t dir) {
    c->fd = fd;
    kdb_framer_init(&c->fr, dir, c->body, sizeof(c->body));
}

static bool ch_next(ch_t *c, kdb_msg_t *m, int ms) {
    for (;;) {
        kdb_frame_t fr;
        kdb_rc_t rc = kdb_framer_next(&c->fr, &fr);
        if (rc == KDB_OK) {
            char why[KDB_REASON_LEN];
            if (kdb_decode(&fr, KDB_VIEWS_ANY, m, why, sizeof(why)) != KDB_OK) return false;
            return true;
        }
        if (rc != KDB_MORE) return false;
        struct pollfd p = { c->fd, POLLIN, 0 };
        if (poll(&p, 1, ms) <= 0) return false;
        ssize_t n = read(c->fd, c->buf, sizeof(c->buf));
        if (n <= 0) return false;
        if (kdb_framer_feed(&c->fr, c->buf, (size_t)n) != KDB_OK) return false;
    }
}

static void ch_send(int fd, kdb_enc_t *e) {
    CHECK(!e->err);
    size_t off = 0;
    while (off < e->len) {
        ssize_t n = write(fd, e->buf + off, e->len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    kdb_enc_reset(e);
}

/* ---------------------------------------------------------------- zone data */
static size_t put_name(uint8_t *b, const char *name) {
    size_t o = 0;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t l = dot ? (size_t)(dot - name) : strlen(name);
        b[o++] = (uint8_t)l;
        memcpy(b + o, name, l);
        o += l;
        name += l + (dot ? 1 : 0);
    }
    b[o++] = 0;
    return o;
}
static size_t put_u16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; return 2; }
static size_t put_u32(uint8_t *b, uint32_t v) { put_u16(b, (uint16_t)(v >> 16)); put_u16(b + 2, (uint16_t)v); return 4; }

static size_t put_rr_head(uint8_t *b, const char *owner, uint16_t type, size_t rdlen_pos_out[1]) {
    size_t o = put_name(b, owner);
    o += put_u16(b + o, type);
    o += put_u16(b + o, 1);
    o += put_u32(b + o, 300);
    rdlen_pos_out[0] = o;
    return o + 2;
}

/* ZONE_DATA of the zone (SOA, NS, A www, SOA); `extra`: a changing A record so that two versions of a zone differ */
static size_t zone_message(uint8_t *b, const char *zone, uint32_t serial) {
    memset(b, 0, 12);
    b[2] = 0x84;
    put_u16(b + 6, 4);
    size_t o = 12, rp[1];
    for (int k = 0; k < 4; k++) {
        char owner[300], ns[300], mail[300];
        snprintf(ns, sizeof(ns), "ns1.%s", zone);
        snprintf(mail, sizeof(mail), "host.%s", zone);
        snprintf(owner, sizeof(owner), "%s%s", k == 2 ? "www." : "", zone);
        uint16_t type = (k == 0 || k == 3) ? 6 : k == 1 ? 2 : 1;
        size_t rd = put_rr_head(b + o, owner, type, rp);
        size_t start = o + rd;
        size_t l = 0;
        if (type == 6) {
            l += put_name(b + start, ns);
            l += put_name(b + start + l, mail);
            l += put_u32(b + start + l, serial);
            l += put_u32(b + start + l, 3600);
            l += put_u32(b + start + l, 600);
            l += put_u32(b + start + l, 86400);
            l += put_u32(b + start + l, 300);
        } else if (type == 2) {
            l += put_name(b + start, ns);
        } else {
            b[start] = 192; b[start + 1] = 0; b[start + 2] = 2; b[start + 3] = (uint8_t)(80 + (serial & 3));
            l = 4;
        }
        put_u16(b + o + rp[0], (uint16_t)l);
        o = start + l;
    }
    return o;
}

static void send_zone(int fd, kdb_enc_t *e, const char *zone, uint32_t serial, uint64_t req, int64_t sid) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (int)serial, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, 0); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, 0); kdb_enc_u64(e, 7, 4); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    if (req) kdb_enc_u64(e, 11, req);
    kdb_enc_end(e);
    uint8_t msg[2048];
    size_t n = zone_message(msg, zone, serial);
    kdb_enc_raw_msg(e, KDB_T_ZONE_DATA, msg, n);
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, 4);
    kdb_enc_end(e);
    ch_send(fd, e);
}

static void batch_begin(int fd, kdb_enc_t *e, uint64_t id, int kind) {
    kdb_enc_begin(e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(e, 1, id); kdb_enc_u8(e, 2, (uint8_t)kind); kdb_enc_u64(e, 3, 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}

/* BATCH_END and the answers up to BATCH_RESULT */
static void batch_end(int fd, kdb_enc_t *e, ch_t *mainc, uint64_t id, uint32_t nz, uint32_t ndel) {
    kdb_msg_t m;
    kdb_enc_begin(e, KDB_T_BATCH_END);
    kdb_enc_u64(e, 1, id); kdb_enc_u32(e, 2, nz); kdb_enc_u32(e, 3, 0); kdb_enc_u32(e, 4, ndel);
    kdb_enc_end(e);
    ch_send(fd, e);
    while (ch_next(mainc, &m, 5000) && m.type != KDB_T_BATCH_RESULT) {}
    CHECK(m.type == KDB_T_BATCH_RESULT);
}

/* ---------------------------------------------------------------- the worker's side */
static bool wake_next(park_key_t *k, int ms) {
    park_wake_ring_t *r = park_wake_ring(0);
    for (int i = 0; i < ms / 2; i++) {
        if (park_wake_pop(r, k)) return true;
        usleep(2000);
    }
    return false;
}

static void drain_wakes(void) {
    park_key_t kk;
    while (park_wake_pop(park_wake_ring(0), &kk)) {}
    (void)park_wake_take_overflow(park_wake_ring(0));
}

static zdir_elem_t *elem_of(const char *zone) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    zdir_elem_t *e = zdir_find_exact(snapshot_find_view(s, "default"), zone);
    release_zone_snapshot(s);
    return e;
}

static size_t build_q(uint8_t *b, uint16_t id, const char *name, uint16_t qtype) {
    memset(b, 0, 12);
    b[0] = (uint8_t)(id >> 8); b[1] = (uint8_t)id;
    b[2] = 0x01;
    b[5] = 1;
    size_t o = 12;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t l = dot ? (size_t)(dot - name) : strlen(name);
        b[o++] = (uint8_t)l;
        memcpy(b + o, name, l);
        o += l;
        name += l + (dot ? 1 : 0);
    }
    b[o++] = 0;
    b[o++] = (uint8_t)(qtype >> 8); b[o++] = (uint8_t)qtype; b[o++] = 0; b[o++] = 1;
    return o;
}

static void no_bg_fetch(const char *view, const char *zone) { (void)view; (void)zone; }
static worker_ctx_t g_wctx;
static compress_ctx_t g_cc;

/* the answer to one question, as the engine builds it (a worker in its read section) */
static int ask_engine(worker_ctx_t *wc, compress_ctx_t *cc, const char *name, uint16_t qtype, uint8_t *out) {
    uint8_t qb[512];
    size_t ql = build_q(qb, 0x5151, name, qtype);
    (void)wc;
    rcu_aux_read_lock();                                                    /* (a thread that is not a worker: the writers and the reclaim thread see its read section) */
    zone_db_snapshot_t *sn = acquire_zone_snapshot();
    memset(cc, 0, sizeof(*cc));
    int rl = process_dns_query_cap(qb, ql, out, 1232, 0, name, qtype, "127.0.0.1", cc, false, NULL, sn);
    rcu_aux_read_unlock();
    return rl;
}

typedef struct { uint8_t b[1232]; int len; } ans_t;
static const char *g_qn[] = { "", "ns1.", "www.", "nx.", "x.www." };         /* prefixes: the apex, an NS target (no A: glue absent), an A, a name that is not there, below a leaf */
static const uint16_t g_qt[] = { 6, 2, 1, 1, 1 };
#define NQ 5
static void answers_of(const char *zone, ans_t a[NQ + 2]) {
    char nm[300];
    for (int i = 0; i < NQ; i++) {
        snprintf(nm, sizeof(nm), "%s%s", g_qn[i], zone);
        a[i].len = ask_engine(&g_wctx, &g_cc, nm, g_qt[i], a[i].b);
    }
    snprintf(nm, sizeof(nm), "%s", zone);
    a[NQ].len = ask_engine(&g_wctx, &g_cc, nm, 2, a[NQ].b);
    a[NQ + 1].len = ask_engine(&g_wctx, &g_cc, nm, 255, a[NQ + 1].b);
}
static bool same_answers(const ans_t *x, const ans_t *y) {
    for (int i = 0; i < NQ + 2; i++)
        if (x[i].len != y[i].len || x[i].len <= 0 || memcmp(x[i].b, y[i].b, (size_t)x[i].len) != 0) return false;
    return true;
}

/* take the zone out of memory and wait until the registry's reference of its entry is gone (the garbage of the next delta is freed) */
static bool evict_zone(const char *zone) {
    if (!dbreg_test_evict("default", zone)) return false;
    for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(25000);
    return true;
}

static uint64_t resident_bytes(void) {
    zone_bytes_t zb;
    zone_bytes_get(ZBYTES_DB, &zb);
    return zb.resident;
}

/* an attach as the worker asks for it: true when it woke the worker with the zone, false when the key says retry or failed */
static int attach_by_worker(const char *zone, park_key_t *k) {
    drain_wakes();
    if (!park_attach_request(0, "default", zone)) return -1;
    if (!wake_next(k, 5000)) return -2;
    return (k->failed || k->retry) ? 0 : 1;
}

/* damage one byte of the record of a zone in the segment files of the store (a plain write through another descriptor) */
static bool damage_record(const char *dir, const char *zone) {
    for (int n = 1; n <= 4; n++) {
        char p[512];
        snprintf(p, sizeof(p), "%s/seg.%d", dir, n);
        int fd = open(p, O_RDWR);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); continue; }
        char *buf = malloc((size_t)st.st_size);
        if (!buf || pread(fd, buf, (size_t)st.st_size, 0) != st.st_size) { free(buf); close(fd); continue; }
        char pat[300];
        snprintf(pat, sizeof(pat), "www.%s", zone);
        size_t pl = strlen(pat);
        for (off_t i = 0; i + (off_t)pl < st.st_size; i++) {
            if (memcmp(buf + i, pat, pl) == 0) {
                char c = buf[i + 2] ^ 0x20;
                bool ok = pwrite(fd, &c, 1, i + 2) == 1;
                free(buf);
                close(fd);
                return ok;
            }
        }
        free(buf);
        close(fd);
    }
    return false;
}

/* ---------------------------------------------------------------- a reader of a zone that comes and goes */
static _Atomic bool g_rd_stop;
static _Atomic uint64_t g_rd_ok, g_rd_gone, g_rd_bad;
static void *reader_thread(void *arg) {
    const char *name = arg;
    static worker_ctx_t wc;
    static compress_ctx_t cc;
    memset(&wc, 0, sizeof(wc));
    uint8_t out[1232];
    while (!atomic_load(&g_rd_stop)) {
        int rl = ask_engine(&wc, &cc, name, 1, out);
        if (rl > 12 && (out[3] & 0x0F) == 0 && ((out[6] << 8) | out[7]) == 1) {
            /* the A record of www: 192.0.2.8x somewhere in the message */
            bool found = false;
            for (int i = 12; i + 4 <= rl; i++)
                if (out[i] == 192 && out[i + 1] == 0 && out[i + 2] == 2 && out[i + 3] >= 80 && out[i + 3] <= 83) found = true;
            if (found) atomic_fetch_add(&g_rd_ok, 1);
            else atomic_fetch_add(&g_rd_bad, 1);
        } else if (rl > 12) {
            atomic_fetch_add(&g_rd_gone, 1);                      /* (not ready, or refused: the zone was out of memory) */
        } else {
            atomic_fetch_add(&g_rd_bad, 1);
        }
    }
    return NULL;
}

static int run_mode(const char *mode) {
    printf("[the zone store in the server: %s mode]\n", mode);
    char dir[] = "/tmp/test_db_store.XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);

    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode %s; "
             "store-threads 2; store-paranoid yes; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir, mode);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    CHECK(cfg.database.store_dir && strcmp(cfg.database.store_dir, sdir) == 0 && cfg.database.store_threads == 2 && cfg.database.store_paranoid);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);

    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled());
    db_store_counters_t c0, c1;

    int a[2], f[2], cs[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0 && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, cs) == 0);
    int ends[3] = { a[1], f[1], cs[1] };
    for (int i = 0; i < 3; i++) fcntl(ends[i], F_SETFL, fcntl(ends[i], F_GETFL, 0) | O_NONBLOCK);
    park_register_worker(0, -1);
    CHECK(db_ingest_start(a[1], cs[1], f[1]));
    static ch_t mainc, fetchc;
    ch_init(&mainc, a[0], KDB_FROM_BACKEND);
    ch_init(&fetchc, f[0], KDB_FROM_BACKEND);
    kdb_enc_t e;
    kdb_enc_init(&e);
    kdb_msg_t m;
    park_key_t k;
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);

    store_t *st = db_store_handle();
    CHECK(st != NULL);
    memset(&g_wctx, 0, sizeof(g_wctx));
    g_query_bg_fetch = no_bg_fetch;                                          /* (a query for a zone that is out of memory would ask for it in the background) */

    /* -- 1. write-through */
    enum { NZ = 8 };
    char nm[NZ][24];
    batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP);
    for (int i = 0; i < NZ; i++) {
        snprintf(nm[i], sizeof(nm[i]), "a%d.test.", i);
        send_zone(a[0], &e, nm[i], (uint32_t)(i + 1), 0, 100 + i);
    }
    batch_end(a[0], &e, &mainc, 1, NZ, 0);
    CHECK(db_store_sync(5000));
    db_store_counters(&c0);
    CHECK(c0.wt_put == NZ && c0.wt_errors == 0);
    {
        store_stats_t ss;
        store_stats(st, &ss);
        CHECK(ss.zones_stored == NZ);
        bool all = true;
        store_read_lock();
        for (int i = 0; i < NZ; i++) {
            char sn[24];
            snprintf(sn, sizeof(sn), "a%d.test", i);
            int vid = store_view_id(st, "default");
            uint32_t zid = vid >= 0 ? store_find(st, (uint16_t)vid, sn, strlen(sn)) : STORE_NONE;
            store_zone_t z;
            uint8_t dig[STORE_DIGEST_LEN];
            memset(dig, i + 1, sizeof(dig));
            if (zid == STORE_NONE || store_zone_get(st, zid, &z) != 0 || z.state != STORE_STATE_STORED || z.serial != (uint32_t)(i + 1) || z.source_id != 100 + i ||
                memcmp(z.digest, dig, sizeof(dig)) != 0 || z.img_len == 0)
                all = false;
        }
        store_read_unlock();
        CHECK(all);
    }
    /* the same versions again (a later batch, nothing changed): the store has them, nothing is written */
    batch_begin(a[0], &e, 2, KDB_BATCH_DIFF);
    for (int i = 0; i < NZ; i++) send_zone(a[0], &e, nm[i], (uint32_t)(i + 1), 0, 100 + i);
    batch_end(a[0], &e, &mainc, 2, NZ, 0);
    CHECK(db_store_sync(5000));
    db_store_counters(&c1);
    CHECK(c1.wt_put == c0.wt_put && c1.wt_skipped == c0.wt_skipped + NZ);
    for (int i = 0; i < 100 && !elem_of("a0.test."); i++) usleep(50000);
    CHECK(elem_of("a0.test.") != NULL && zdir_entry(elem_of("a0.test.")) != NULL);

    /* -- 2. attach, and the answers are the same bytes */
    ans_t before[NQ + 2], after[NQ + 2];
    answers_of("a1.test.", before);
    CHECK(before[0].len > 12 && (before[0].b[3] & 0x0F) == 0 && before[2].len > 12);
    const uint64_t res_in = resident_bytes();
    zone_db_entry_t *old_entry = dbreg_lookup_entry("default", "a1.test.");
    const zone_image_t *old_img = old_entry ? atomic_load(&old_entry->rcu.active)->image : NULL;
    uint8_t *old_copy = NULL;
    size_t old_len = 0;
    if (old_img) {
        old_len = old_img->total_size;
        old_copy = malloc(old_len);
        if (old_copy) memcpy(old_copy, old_img, old_len);
    }
    CHECK(evict_zone("a1.test."));
    CHECK(resident_bytes() < res_in);
    CHECK(db_store_attach_possible("default", "a1.test.", 2));
    CHECK(!db_store_attach_possible("default", "a1.test.", 3));            /* (not the version the directory has) */
    CHECK(!db_store_attach_possible("default", "nosuch.test.", 1));
    db_store_counters(&c0);
    CHECK(attach_by_worker("a1.test.", &k) == 1 && strcmp(k.zone, "a1.test.") == 0);
    {
        zdir_elem_t *el = elem_of("a1.test.");
        CHECK(el && zdir_entry(el) != NULL && atomic_load(&el->state) == ZDIR_ST_RESIDENT && zdir_serial(el) == 2);
        zone_version_t *v = el && zdir_entry(el) ? atomic_load(&zdir_entry(el)->rcu.active) : NULL;
        CHECK(v && v->image_free != NULL && v->counted && v->image && old_copy && v->image->total_size == old_len && memcmp(v->image, old_copy, old_len) == 0);
    }
    CHECK(!ch_next(&fetchc, &m, 150));                                       /* the loader was not asked */
    db_store_counters(&c1);
    CHECK(c1.attach_ok == c0.attach_ok + 1 && c1.versions_live == c0.versions_live + 1 && c1.attached_bytes > c0.attached_bytes);
    answers_of("a1.test.", after);
    CHECK(same_answers(before, after));
    CHECK(zdir_entry(elem_of("a1.test.")) != NULL && zdir_entry(elem_of("a1.test."))->serial == 2);

    /* -- 3. accounting: taken out again, the version's bytes are given back, the image goes back to the store */
    CHECK(evict_zone("a1.test."));
    zone_retire_process(true);
    for (int i = 0; i < 100; i++) {
        db_store_counters(&c1);
        if (c1.versions_live == c0.versions_live) break;
        zone_retire_process(true);
        usleep(20000);
    }
    db_store_counters(&c1);
    CHECK(c1.versions_live == c0.versions_live && c1.attached_bytes == c0.attached_bytes);
    CHECK(zone_bytes_underflows() == 0);
    CHECK(resident_bytes() < res_in);
    CHECK(attach_by_worker("a1.test.", &k) == 1);                            /* (and again) */
    answers_of("a1.test.", after);
    CHECK(same_answers(before, after));
    {
        /* every byte counted when the version was attached is given back when it is gone: the total is where it was with the zone in memory +- the allocator's rounding of the image */
        zone_bytes_t zb;
        zone_bytes_get(ZBYTES_DB, &zb);
        CHECK(zb.resident + 4096 >= res_in && zb.resident <= res_in + 4096);
    }

    /* -- 4. stale: the directory has another serial than the store (a summary came): the attach falls back to the fetch */
    CHECK(evict_zone("a2.test."));
    CHECK(dbreg_commit_cold("default", "a2.test.", 102, 9, (const uint8_t[32]){ 0 }, NULL) == 0);
    CHECK(!db_store_attach_possible("default", "a2.test.", 9));
    db_store_counters(&c0);
    CHECK(attach_by_worker("a2.test.", &k) == 0 && k.retry && !k.failed);
    db_store_counters(&c1);
    CHECK(c1.attach_stale == c0.attach_stale + 1 && c1.attach_fallback == c0.attach_fallback + 1);
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "a2.test.") == 0);
    send_zone(f[0], &e, "a2.test.", 9, m.u.fetch_req.request_id, 102);
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "a2.test.") == 0 && !k.failed && !k.retry);
    CHECK(db_store_sync(5000));
    CHECK(db_store_attach_possible("default", "a2.test.", 9));               /* (the install wrote the new version; the zone is not taken out again here: the NOTIFY of its new serial waits for the control thread) */

    /* missing: the record is not there (deleted behind the server's back) */
    CHECK(evict_zone("a3.test."));
    {
        store_read_lock();
        uint32_t zid = store_find(st, (uint16_t)store_view_id(st, "default"), "a3.test", 7);
        store_read_unlock();
        CHECK(zid != STORE_NONE && store_delete(st, zid) == 0);
    }
    CHECK(!db_store_attach_possible("default", "a3.test.", 4));
    db_store_counters(&c0);
    CHECK(attach_by_worker("a3.test.", &k) == 0 && k.retry);
    db_store_counters(&c1);
    CHECK(c1.attach_missing == c0.attach_missing + 1);
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "a3.test.") == 0);
    send_zone(f[0], &e, "a3.test.", 4, m.u.fetch_req.request_id, 103);
    CHECK(wake_next(&k, 5000) && !k.failed && !k.retry);
    CHECK(db_store_sync(5000));
    CHECK(evict_zone("a3.test.") && db_store_attach_possible("default", "a3.test.", 4));        /* (the fetch wrote it again) */

    /* damaged: a byte of the record changed */
    CHECK(damage_record(sdir, "a4.test."));
    CHECK(evict_zone("a4.test."));
    db_store_counters(&c0);
    CHECK(attach_by_worker("a4.test.", &k) == 0 && k.retry);
    db_store_counters(&c1);
    CHECK(c1.attach_damaged == c0.attach_damaged + 1);
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "a4.test.") == 0);
    CHECK(db_store_sync(5000));
    {
        store_read_lock();
        uint32_t zid = store_find(st, (uint16_t)store_view_id(st, "default"), "a4.test", 7);
        store_zone_t z;
        CHECK(zid != STORE_NONE && store_zone_get(st, zid, &z) == 0 && z.state == STORE_STATE_KNOWN);      /* (set back to known: the next install writes it again) */
        store_read_unlock();
    }
    CHECK(!db_store_attach_possible("default", "a4.test.", 5));
    send_zone(f[0], &e, "a4.test.", 5, m.u.fetch_req.request_id, 104);
    CHECK(wake_next(&k, 5000) && !k.failed && !k.retry);
    CHECK(db_store_sync(5000));
    CHECK(evict_zone("a4.test.") && attach_by_worker("a4.test.", &k) == 1);

    /* an attach for a zone that is in memory wakes the worker (a second request after the first one's attach) and one for a zone that is not there is a retry */
    CHECK(attach_by_worker("a4.test.", &k) == 1);
    CHECK(attach_by_worker("none.test.", &k) == 0);

    /* a zone the database deletes is deleted from the store */
    batch_begin(a[0], &e, 3, KDB_BATCH_DIFF);
    kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
    kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "a5.test."); kdb_enc_i64(&e, 3, 105);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_ZONE_RESULT && m.u.zone_result.status == KDB_ST_DELETED);
    batch_end(a[0], &e, &mainc, 3, 0, 1);
    CHECK(db_store_sync(5000));
    {
        store_read_lock();
        CHECK(store_find(st, (uint16_t)store_view_id(st, "default"), "a5.test", 7) == STORE_NONE);
        store_read_unlock();
    }
    {
        store_check_report_t rep;
        CHECK(store_check(st, &rep) == 0);
        if (rep.errors) printf("  store_check: %s\n", rep.first_error);
    }

    /* -- 5. a reader of a zone that is taken out of memory and attached again, over and over */
    {
        pthread_t rt;
        atomic_store(&g_rd_stop, false);
        CHECK(pthread_create(&rt, NULL, reader_thread, (void *)(uintptr_t)"www.a6.test.") == 0);
        int cycles = 0;
        for (int i = 0; i < 60; i++) {
            if (!dbreg_test_evict("default", "a6.test.")) {
                static int shown;
                zdir_elem_t *el = elem_of("a6.test.");
                zone_db_entry_t *en = el ? zdir_entry(el) : NULL;
                if (shown++ < 3 && el) printf("  evict refused: state %d flags %x entry %p refs %d axfr %d updated %d\n", (int)atomic_load(&el->state), el->flags, (void *)en, en ? (int)atomic_load(&en->snapshot_refs) : -1, en ? (int)atomic_load(&en->active_axfr) : -1, en ? (int)atomic_load(&en->updated) : -1);
                usleep(5000);
                continue;
            }
            usleep(2000);
            for (int w = 0; w < 400 && !(elem_of("a6.test.") && zdir_entry(elem_of("a6.test."))); w++) {
                if (w % 100 == 0) {
                    drain_wakes();
                    (void)park_attach_request(0, "default", "a6.test.");
                }
                usleep(1000);
            }
            if (zdir_entry(elem_of("a6.test."))) cycles++;
            for (int w = 0; w < 100 && dbreg_evict_inflight() != 0; w++) usleep(1000);
        }
        atomic_store(&g_rd_stop, true);
        pthread_join(rt, NULL);
        db_store_counters(&c1);
        printf("  reader: %llu answers, %llu while the zone was out of memory, %llu not understood, %d cycles; attach ok %llu stale %llu missing %llu damaged %llu fallback %llu resident %llu busy %llu\n",
               (unsigned long long)atomic_load(&g_rd_ok), (unsigned long long)atomic_load(&g_rd_gone), (unsigned long long)atomic_load(&g_rd_bad), cycles, (unsigned long long)c1.attach_ok,
               (unsigned long long)c1.attach_stale, (unsigned long long)c1.attach_missing, (unsigned long long)c1.attach_damaged, (unsigned long long)c1.attach_fallback,
               (unsigned long long)c1.attach_resident, (unsigned long long)c1.attach_busy);
        CHECK(cycles >= 20 && atomic_load(&g_rd_ok) > 0 && atomic_load(&g_rd_bad) == 0);
    }
    for (int i = 0; i < 100 && dbreg_evict_inflight() != 0; i++) usleep(20000);
    zone_retire_process(true);
    CHECK(zone_bytes_underflows() == 0);

    free(old_copy);
    gc_snapshot_wait_idle();                                                 /* (the reclaim thread that the last delta started: joined, not left to the exit) */
    db_store_stop();
    char cmd[700];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)!system(cmd);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc > 1) return run_mode(strcmp(argv[1], "copy") == 0 ? "copy" : "map");
    /* the second mode is a second process: the ingest thread and the store are process wide */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s copy", argv[0]);
    int rc = system(cmd);
    int rc2 = run_mode("map");
    return (rc != 0 || rc2 != 0) ? 1 : 0;
}

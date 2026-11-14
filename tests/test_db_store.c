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
#include "../dns_zone_image.h"

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

/* a zone of nA address records (SOA, NS, nA x A, SOA), in ZONE_DATA messages of 1000 records */
static void send_big_zone(int fd, kdb_enc_t *e, const char *zone, uint32_t serial, int64_t sid, int nA) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (int)serial, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, 0); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, 0); kdb_enc_u64(e, 7, (uint64_t)nA + 3); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    kdb_enc_end(e);
    ch_send(fd, e);
    static uint8_t msg[60000];
    for (int start = 0; start < nA || start == 0; start += 1000) {
        int n = nA - start < 1000 ? nA - start : 1000;
        bool head = start == 0, tail = start + 1000 >= nA;
        memset(msg, 0, 12);
        msg[2] = 0x84;
        size_t o = 12, rp[1];
        int cnt = 0;
        for (int k = -2; k < n + 1; k++) {
            char owner[300], ns[300], mail[300];
            snprintf(ns, sizeof(ns), "ns1.%s", zone);
            snprintf(mail, sizeof(mail), "host.%s", zone);
            uint16_t type;
            if (k == -2) { if (!head) continue; type = 6; snprintf(owner, sizeof(owner), "%s", zone); }
            else if (k == -1) { if (!head) continue; type = 2; snprintf(owner, sizeof(owner), "%s", zone); }
            else if (k == n) { if (!tail) continue; type = 6; snprintf(owner, sizeof(owner), "%s", zone); }
            else { type = 1; snprintf(owner, sizeof(owner), "h%d.%s", start + k, zone); }
            size_t rd = put_rr_head(msg + o, owner, type, rp);
            size_t s = o + rd, l = 0;
            if (type == 6) {
                l += put_name(msg + s, ns);
                l += put_name(msg + s + l, mail);
                l += put_u32(msg + s + l, serial); l += put_u32(msg + s + l, 3600); l += put_u32(msg + s + l, 600); l += put_u32(msg + s + l, 86400); l += put_u32(msg + s + l, 300);
            } else if (type == 2) {
                l += put_name(msg + s, ns);
            } else {
                msg[s] = 192; msg[s + 1] = 0; msg[s + 2] = 2; msg[s + 3] = (uint8_t)(1 + (start + k) % 250);
                l = 4;
            }
            put_u16(msg + o + rp[0], (uint16_t)l);
            o = s + l;
            cnt++;
        }
        put_u16(msg + 6, (uint16_t)cnt);
        kdb_enc_raw_msg(e, KDB_T_ZONE_DATA, msg, o);
        ch_send(fd, e);
    }
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, (uint64_t)nA + 3);
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
/* the next key for `zone`: the keys of other zones are skipped.  A wake of an earlier request can arrive late (the ingest thread answers a fetch request of an attach that fell
 * back after the store thread's own retry key was read: a request for a zone that is not there is woken "failed" by the ingest thread some time after the attach thread's
 * "retry"), and a loaded host makes the gap long.  Such a key belongs to another zone or to an earlier request, never to the one that is being waited for. */
static bool wake_for(const char *zone, park_key_t *k, int ms) {
    int64_t end = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    end = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + ms;
    for (;;) {
        if (park_wake_pop(park_wake_ring(0), k)) {
            if (strcmp(k->zone, zone) == 0) return true;
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 >= end) return false;
        usleep(1000);
    }
}

static void drain_wakes(void) {
    park_key_t kk;
    while (park_wake_pop(park_wake_ring(0), &kk)) {}
    (void)park_wake_take_overflow(park_wake_ring(0));
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
    if (!wake_for(zone, k, 5000)) return -2;
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

/* the lookup of the directory as a worker makes it for `zone` (a name in the view "default"); true: the directory has the zone (in memory or in the store) */
static bool zref_of(const char *zone, zref_t *z) {
    rcu_aux_read_lock();
    zone_db_snapshot_t *s = acquire_zone_snapshot();
    bool r = zref_find_exact(snapshot_find_view(s, "default"), zone, z);
    rcu_aux_read_unlock();
    return r;
}
static bool in_memory(const char *zone) {
    zref_t z;
    return zref_of(zone, &z) && z.entry != NULL;
}
/* the zone is in the store and not in memory: the lookup says so, and no registry element is kept for it */
static bool stored_only(const char *zone) {
    zref_t z;
    return zref_of(zone, &z) && z.entry == NULL && z.el == NULL && z.zid != ZREF_NOZID && z.zstate == ZREF_ST_ABSENT && dbreg_lookup_entry("default", zone) == NULL;
}

/* the calls of the name index that a lookup makes (the depth skip of design 2.2): ops that count and pass on */
static _Atomic uint64_t g_find_calls;
static dbdir_ops_t g_spy_ops;
static const dbdir_ops_t *g_real_ops;
static bool counting_find(int sid, const char *fname, size_t len, zref_t *out) {
    atomic_fetch_add(&g_find_calls, 1);
    return g_real_ops->find(sid, fname, len, out);
}

static uint64_t find_calls_for(view_snapshot_t *v, const char *qname, zref_t *z) {
    uint64_t before = atomic_load(&g_find_calls);
    rcu_aux_read_lock();
    (void)zref_find_suffix(v, qname, z);
    rcu_aux_read_unlock();
    return atomic_load(&g_find_calls) - before;
}

/* a reader that looks up zones at random while the table of attached zones grows and shrinks (TSan, ASan) */
static _Atomic uint64_t g_gr_found, g_gr_bad;
static void *grow_reader_thread(void *arg) {
    int nz = (int)(uintptr_t)arg;
    unsigned seed = 12345;
    while (!atomic_load(&g_rd_stop)) {
        char nm[64];
        int i = (int)(rand_r(&seed) % (unsigned)nz);
        snprintf(nm, sizeof(nm), "g%d.grow.test.", i);
        zref_t z;
        rcu_aux_read_lock();
        zone_db_snapshot_t *s = acquire_zone_snapshot();
        bool f = zref_find_exact(snapshot_find_view(s, "default"), nm, &z);
        if (f && z.entry) {
            if (!domain_names_match_ci(z.entry->domain, nm) || z.zid == ZREF_NOZID || z.el == NULL) atomic_fetch_add(&g_gr_bad, 1);
            else atomic_fetch_add(&g_gr_found, 1);
        } else if (f && !(z.zid != ZREF_NOZID && !z.entry)) {
            atomic_fetch_add(&g_gr_bad, 1);
        }
        rcu_aux_read_unlock();
    }
    return NULL;
}

static int run_mode(const char *mode) {
    printf("[the zone store is the directory of the database zones: %s mode]\n", mode);
    char dir[] = "/tmp/test_db_store.XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);

    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode %s; "
             "store-threads 2; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir, mode);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    CHECK(cfg.database.store_dir && strcmp(cfg.database.store_dir, sdir) == 0 && cfg.database.store_threads == 2);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);

    char msg[400];
    CHECK(dbdir() == NULL);                                                  /* (no store yet: the heap directory alone, as before 0.7) */
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled());
    CHECK(dbdir() != NULL);
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
    g_query_bg_attach = no_bg_fetch;

    /* -- 1. an install goes to the store and is attached; the heap directory has none of these zones, and no snapshot is published for them */
    enum { NZ = 8 };
    char nm[NZ][24];
    zone_db_snapshot_t *snap0 = atomic_load(&g_zone_db_active);
    batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP);
    for (int i = 0; i < NZ; i++) {
        snprintf(nm[i], sizeof(nm[i]), "a%d.test.", i);
        send_zone(a[0], &e, nm[i], (uint32_t)(i + 1), 0, 100 + i);
    }
    batch_end(a[0], &e, &mainc, 1, NZ, 0);
    db_store_counters(&c0);
    CHECK(c0.wt_put == NZ && c0.wt_errors == 0);
    {
        store_stats_t ss;
        store_stats(st, &ss);
        CHECK(ss.zones_stored == NZ);
        bool all = true, mem = true, heap_free = true;
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
            zref_t zr;
            if (!zref_of(nm[i], &zr) || !zr.entry || !zr.el || zr.zid != zid || !(zr.el->kind & ZDIR_K_STORED)) mem = false;
            rcu_aux_read_lock();
            if (zdir_find_exact(snapshot_find_view(acquire_zone_snapshot(), "default"), nm[i]) != NULL) heap_free = false;
            rcu_aux_read_unlock();
        }
        store_read_unlock();
        CHECK(all);
        CHECK(mem);                                                          /* (they are found through the store's index and the attach table) */
        CHECK(heap_free);                                                    /* (and not in the heap directory) */
        CHECK(dbdir()->attach_count() == NZ);
    }
    CHECK(atomic_load(&g_zone_db_active) == snap0);                          /* (no zone-database snapshot was published) */
    /* the same versions again (a later batch, nothing changed): the store has them, nothing is written */
    batch_begin(a[0], &e, 2, KDB_BATCH_DIFF);
    for (int i = 0; i < NZ; i++) send_zone(a[0], &e, nm[i], (uint32_t)(i + 1), 0, 100 + i);
    batch_end(a[0], &e, &mainc, 2, NZ, 0);
    db_store_counters(&c1);
    CHECK(c1.wt_put == c0.wt_put && c1.wt_skipped == c0.wt_skipped + NZ);

    /* -- 2. detach: the record stays, the element goes (nothing is published), the lookup finds the zone in the store alone */
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
    size_t nel0, rb0, ib0, nel1, rb1, ib1;
    dbreg_dir_bytes(&nel0, &rb0, &ib0);
    CHECK(evict_zone("a1.test."));
    CHECK(resident_bytes() < res_in);
    CHECK(atomic_load(&g_zone_db_active) == snap0);
    CHECK(stored_only("a1.test."));
    dbreg_dir_bytes(&nel1, &rb1, &ib1);
    CHECK(nel1 + 1 == nel0);                                                 /* (the zone costs the registry nothing: its element is gone) */
    {
        zref_t z;
        CHECK(zref_of("a1.test.", &z) && z.serial == 2 && strcmp(zref_name(&z), "a1.test.") == 0 && z.hview && strcmp(z.hview, "default") == 0);
        CHECK(zref_of("A1.TEST", &z) && z.zid != ZREF_NOZID && strcmp(zref_name(&z), "a1.test.") == 0);        /* (case does not matter, nor the trailing dot) */
    }
    dbdir_rec_t rec;
    CHECK(dbdir()->rec_get("default", "a1.test.", &rec) && rec.state == STORE_STATE_STORED && rec.serial == 2 && rec.source_id == 101);
    CHECK(!dbdir()->rec_get("default", "nosuch.test.", &rec));

    /* -- 3. attach at the worker's request: it wakes the worker, the loader is not asked, and the answers are the bytes they were */
    db_store_counters(&c0);
    CHECK(attach_by_worker("a1.test.", &k) == 1 && strcmp(k.zone, "a1.test.") == 0);
    {
        zref_t z;
        CHECK(zref_of("a1.test.", &z) && z.entry && z.el && atomic_load(&z.el->state) == ZDIR_ST_RESIDENT && zdir_serial(z.el) == 2);
        zone_version_t *v = z.entry ? atomic_load(&z.entry->rcu.active) : NULL;
        CHECK(v && v->image_free != NULL && v->counted && v->image && old_copy && v->image->total_size == old_len && memcmp(v->image, old_copy, old_len) == 0);
    }
    CHECK(!ch_next(&fetchc, &m, 150));                                       /* the loader was not asked */
    db_store_counters(&c1);
    CHECK(c1.attach_ok == c0.attach_ok + 1 && c1.versions_live == c0.versions_live + 1 && c1.attached_bytes > c0.attached_bytes);
    answers_of("a1.test.", after);
    CHECK(same_answers(before, after));
    CHECK(atomic_load(&g_zone_db_active) == snap0);

    /* -- 4. accounting: taken out again, the version's bytes are given back, the image goes back to the store */
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
        zone_bytes_t zb;
        zone_bytes_get(ZBYTES_DB, &zb);
        CHECK(zb.resident + 4096 >= res_in && zb.resident <= res_in + 4096);
    }

    /* -- 5. the record of a zone is not there (deleted behind the server's back): the attach finds nothing and the zone is not a zone of the directory any more */
    CHECK(evict_zone("a3.test."));
    {
        store_read_lock();
        uint32_t zid = store_find(st, (uint16_t)store_view_id(st, "default"), "a3.test", 7);
        store_read_unlock();
        CHECK(zid != STORE_NONE && store_delete(st, zid) == 0);
    }
    {
        zref_t z;
        CHECK(!zref_of("a3.test.", &z));
        db_store_counters(&c0);
        CHECK(attach_by_worker("a3.test.", &k) != 1);
        db_store_counters(&c1);
        CHECK(c1.attach_fallback == c0.attach_fallback + 1);
    }

    /* damaged: a byte of the record changed.  The attach falls back to the fetch, the record is set back to "known", the loader sends the zone, and it is stored and attached */
    CHECK(damage_record(sdir, "a4.test."));
    CHECK(evict_zone("a4.test."));
    db_store_counters(&c0);
    CHECK(attach_by_worker("a4.test.", &k) == 0 && k.retry);
    db_store_counters(&c1);
    CHECK(c1.attach_damaged == c0.attach_damaged + 1);
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "a4.test.") == 0);
    {
        zref_t z;
        CHECK(zref_of("a4.test.", &z) && z.entry == NULL && z.zid != ZREF_NOZID && z.zstate == ZREF_ST_KNOWN);     /* (set back to known: a query for it is read from the database) */
    }
    send_zone(f[0], &e, "a4.test.", 5, m.u.fetch_req.request_id, 104);
    CHECK(wake_for("a4.test.", &k, 5000) && !k.failed && !k.retry);
    CHECK(in_memory("a4.test."));
    {
        zref_t z;
        CHECK(zref_of("a4.test.", &z) && z.entry && z.serial == 0 && zdir_serial(z.el) == 5);
        store_zone_t zi;
        store_read_lock();
        uint32_t zid = store_find(st, (uint16_t)store_view_id(st, "default"), "a4.test", 7);
        CHECK(zid != STORE_NONE && store_zone_get(st, zid, &zi) == 0 && zi.state == STORE_STATE_STORED && zi.serial == 5);       /* (the install wrote it again) */
        store_read_unlock();
    }
    CHECK(evict_zone("a4.test.") && attach_by_worker("a4.test.", &k) == 1);
    CHECK(attach_by_worker("a4.test.", &k) == 1);                            /* (a second request for a zone that is in memory wakes the worker) */
    CHECK(attach_by_worker("none.test.", &k) != 1);
    CHECK(wake_for("none.test.", &k, 5000));                   /* (two keys: the attach thread's retry and the ingest thread's failure of a request for a zone it does not have, in either order) */

    /* -- a fetch of the zone is on its way (LOADING): the attach that finds it busy gives the queries that wait the park-timeout (a retry key) */
    CHECK(evict_zone("a2.test."));
    CHECK(dbreg_fetch_begin("default", "a2.test.") == DBREG_FETCH_STARTED);            /* (the zone is out of memory, its record is stored) */
    drain_wakes();
    db_store_counters(&c0);
    CHECK(park_attach_request(0, "default", "a2.test.") && wake_for("a2.test.", &k, 5000) && k.retry && !k.failed);
    db_store_counters(&c1);
    CHECK(c1.attach_busy == c0.attach_busy + 1);
    dbreg_fetch_end("default", "a2.test.");
    CHECK(stored_only("a2.test."));                                          /* (the fetch that did not bring the zone leaves no element) */
    CHECK(attach_by_worker("a2.test.", &k) == 1);

    /* -- the commit of an attach is conditional: a delete that comes after the record was read wins, nothing is made */
    CHECK(evict_zone("a0.test."));
    {
        dbreg_attach_info_t ai;
        CHECK(dbreg_attach_begin("default", "a0.test.", &ai) == DBREG_ATT_STARTED && ai.serial == 1 && ai.source_id == 100);
        CHECK(dbreg_delete("default", "a0.test.", 100) == 1);
        bool sh = false;
        CHECK(dbreg_commit_attach("default", "a0.test.", NULL, &ai, ai.digest, &sh) != 0);
        if (ai.sh) zone_ext_shared_unref(ai.sh);
        CHECK(!in_memory("a0.test."));
        zref_t z;
        CHECK(!zref_of("a0.test.", &z));                                     /* (deleted from the store too) */
        batch_begin(a[0], &e, 20, KDB_BATCH_DIFF);                           /* (and the loader may send it again) */
        send_zone(a[0], &e, "a0.test.", 1, 0, 100);
        batch_end(a[0], &e, &mainc, 20, 1, 0);
        CHECK(in_memory("a0.test."));
    }

    /* -- a record whose image has the right checksum and a wrong structure (a forgery: the checksum is not keyed) is not served: it is found invalid at the attach */
    {
        uint8_t *forged = old_len ? malloc(old_len) : NULL;
        size_t at = 0;
        char vw[96];
        for (size_t off = sizeof(zone_image_t); forged && off < old_len && !at; off++) {
            for (int x = 0; x < 3 && !at; x++) {
                memcpy(forged, old_copy, old_len);
                forged[off] = x == 0 ? (uint8_t)(forged[off] ^ 0xff) : x == 1 ? 0xff : 0x00;
                if (forged[off] != old_copy[off] && zone_image_validate(forged, old_len, vw, sizeof(vw)) != 0) at = off;
            }
        }
        CHECK(forged && at != 0);
        store_zone_t zi;
        store_read_lock();
        uint32_t zid = store_find(st, (uint16_t)store_view_id(st, "default"), "a7.test", 7);
        CHECK(zid != STORE_NONE && store_zone_get(st, zid, &zi) == 0 && zi.state == STORE_STATE_STORED);
        store_read_unlock();
        store_meta_t meta;
        memset(&meta, 0, sizeof(meta));
        meta.source_id = zi.source_id; meta.source = zi.source; meta.flags = zi.flags; meta.serial = zi.serial; meta.settings = zi.settings;
        meta.stamp_gen = zi.stamp_gen; meta.stamp_time = zi.stamp_time;
        memcpy(meta.digest, zi.digest, sizeof(meta.digest));
        CHECK(forged && store_put(st, (uint16_t)store_view_id(st, "default"), "a7.test", 7, &meta, forged, old_len, NULL) == 0);
        CHECK(evict_zone("a7.test."));
        db_store_counters(&c0);
        CHECK(attach_by_worker("a7.test.", &k) == 0 && k.retry);
        db_store_counters(&c1);
        CHECK(c1.attach_damaged == c0.attach_damaged + 1 && c1.validated == c0.validated + 1);
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "a7.test.") == 0);
        send_zone(f[0], &e, "a7.test.", 8, m.u.fetch_req.request_id, 107);
        CHECK(wake_for("a7.test.", &k, 5000) && !k.failed && !k.retry);
        CHECK(evict_zone("a7.test.") && attach_by_worker("a7.test.", &k) == 1);            /* (the install wrote a good record) */
        free(forged);
    }

    /* -- a new version of a zone in memory replaces it in place; the record follows */
    {
        batch_begin(a[0], &e, 21, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "a6.test.", 40, 0, 106);
        batch_end(a[0], &e, &mainc, 21, 1, 0);
        zref_t z;
        CHECK(zref_of("a6.test.", &z) && z.entry && zdir_serial(z.el) == 40);
        CHECK(dbdir()->rec_get("default", "a6.test.", &rec) && rec.state == STORE_STATE_STORED && rec.serial == 40);
        CHECK(atomic_load(&g_zone_db_active) == snap0);
    }

    /* -- the lookup order: the heap directory first at every suffix, then the store (design 2.2) */
    {
        view_snapshot_t *dv;
        zone_db_snapshot_t *sn = acquire_retained_zone_snapshot();
        dv = snapshot_find_view(sn, "default");
        zref_t z;
        /* a zone of karidns.conf shadows a database zone of the same name: the loader's zone is stored, and not served */
        batch_begin(a[0], &e, 22, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "static.test.", 3, 0, 150);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_ZONE_RESULT && m.u.zone_result.status == KDB_ST_SHADOWED);
        batch_end(a[0], &e, &mainc, 22, 1, 0);
        CHECK(dbdir()->rec_get("default", "static.test.", &rec) && rec.state == STORE_STATE_STORED && rec.serial == 3);
        rcu_aux_read_lock();
        CHECK(zref_find_suffix(dv, "www.static.test.", &z) && z.el && (z.el->kind & ZDIR_K_STATIC) && !(z.el->kind & ZDIR_K_STORED) && z.zid == ZREF_NOZID);
        CHECK(zref_find_suffix(dv, "STATIC.test.", &z) && z.el && (z.el->kind & ZDIR_K_STATIC));
        rcu_aux_read_unlock();
        /* a longer database apex wins over a shorter zone of karidns.conf */
        batch_begin(a[0], &e, 23, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "x.static.test.", 1, 0, 151);
        batch_end(a[0], &e, &mainc, 23, 1, 0);
        rcu_aux_read_lock();
        CHECK(zref_find_suffix(dv, "www.x.static.test.", &z) && z.zid != ZREF_NOZID && z.entry && strcmp(z.entry->domain, "x.static.test.") == 0);
        CHECK(zref_find_suffix(dv, "www.y.static.test.", &z) && z.zid == ZREF_NOZID && (z.el->kind & ZDIR_K_STATIC));
        rcu_aux_read_unlock();
        /* a catalog member (an element of the heap directory) hides a database zone of the same name: a directory of this one name, in the view of the store */
        {
            static zone_db_entry_t cat_entry;
            memset(&cat_entry, 0, sizeof(cat_entry));
            cat_entry.domain = "a2.test.";
            snprintf(cat_entry.view_name, sizeof(cat_entry.view_name), "default");
            cat_entry.is_catalog_member = true;
            cat_entry.kind = ZONE_KIND_SECONDARY;
            cat_entry.is_secondary = true;
            zone_db_entry_t *ents[1] = { &cat_entry };
            view_snapshot_t cv;
            memset(&cv, 0, sizeof(cv));
            cv.name = (char *)"default";
            CHECK(view_set_entries(&cv, ents, 1));
            CHECK(in_memory("a2.test."));
            rcu_aux_read_lock();
            CHECK(zref_find_suffix(&cv, "www.a2.test.", &z) && z.el && z.entry == &cat_entry && z.zid == ZREF_NOZID);     /* (the member, not the stored zone of that name) */
            CHECK(zref_find_suffix(&cv, "www.a5.test.", &z) && z.zid != ZREF_NOZID);                                        /* (the others come from the store) */
            rcu_aux_read_unlock();
            view_clear_dir(&cv);
        }
        /* a zone shared by in-view from the database of another view: the name is in the view's table, the zone is the owner's, in memory or in the store */
        {
            view_snapshot_t iv;
            memset(&iv, 0, sizeof(iv));
            iv.name = (char *)"other";
            CHECK(view_ivdb_alloc(&iv, 2));
            CHECK(view_ivdb_add(&iv, "a5.test.", dv));
            CHECK(view_ivdb_add(&iv, "a1.test.", dv));
            CHECK(evict_zone("a1.test."));
            rcu_aux_read_lock();
            CHECK(zref_find_suffix(&iv, "www.a5.test.", &z) && z.entry && z.zid != ZREF_NOZID && z.hview && strcmp(z.hview, "default") == 0);
            CHECK(zref_find_suffix(&iv, "www.a1.test.", &z) && z.entry == NULL && z.zid != ZREF_NOZID && z.zstate == ZREF_ST_ABSENT && strcmp(z.hview, "default") == 0);
            CHECK(!zref_find_suffix(&iv, "www.a2.test.", &z));                                                             /* (not a name of this view) */
            rcu_aux_read_unlock();
            CHECK(attach_by_worker("a1.test.", &k) == 1);
            view_ivdb_free(&iv);
        }
        /* a stub of the view (zone "x" { in-view "owner"; }) hides a zone of that name in the view's own database, as a zone { } block does (D-PRIO): the owner has none, the name is nobody's */
        {
            view_snapshot_t owner, own;
            memset(&owner, 0, sizeof(owner));
            memset(&own, 0, sizeof(own));
            owner.name = (char *)"owner";
            own.name = (char *)"default";
            CHECK(in_memory("a2.test."));
            rcu_aux_read_lock();
            CHECK(zref_find_suffix(&own, "www.a2.test.", &z) && z.zid != ZREF_NOZID);          /* (no stub: the zone of the view's own database) */
            rcu_aux_read_unlock();
            CHECK(view_ivdb_alloc(&own, 1) && view_ivdb_add(&own, "a2.test.", &owner));
            rcu_aux_read_lock();
            CHECK(!zref_find_suffix(&own, "www.a2.test.", &z));                                  /* (the stub hides it, the owner has no such zone) */
            CHECK(!zref_find_exact(&own, "a2.test.", &z));
            CHECK(zref_find_suffix(&own, "www.a5.test.", &z) && z.zid != ZREF_NOZID);          /* (the other zones are the view's own) */
            rcu_aux_read_unlock();
            view_ivdb_free(&own);
        }
        /* DS at the apex of a child zone is answered by the parent (R-32), a parent that is not in memory is the zone to wait for */
        batch_begin(a[0], &e, 24, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "dsp.test.", 1, 0, 160);
        send_zone(a[0], &e, "c.dsp.test.", 1, 0, 161);
        batch_end(a[0], &e, &mainc, 24, 2, 0);
        zone_db_entry_t *ent;
        rcu_aux_read_lock();
        ent = find_zone_for_query_zref(dv, "c.dsp.test.", 43, &z);
        CHECK(ent && strcmp(ent->domain, "dsp.test.") == 0 && z.zid != ZREF_NOZID);
        ent = find_zone_for_query_zref(dv, "c.dsp.test.", 1, &z);
        CHECK(ent && strcmp(ent->domain, "c.dsp.test.") == 0);
        ent = find_zone_for_query_zref(dv, "www.c.dsp.test.", 43, &z);
        CHECK(ent && strcmp(ent->domain, "c.dsp.test.") == 0);               /* (a name inside the child is the child's) */
        rcu_aux_read_unlock();
        CHECK(evict_zone("dsp.test."));
        rcu_aux_read_lock();
        ent = find_zone_for_query_zref(dv, "c.dsp.test.", 43, &z);
        CHECK(ent == NULL && zref_present(&z) && z.entry == NULL && strcmp(zref_name(&z), "dsp.test.") == 0 && z.zstate == ZREF_ST_ABSENT);       /* (the parent is the zone to wait for) */
        rcu_aux_read_unlock();
        CHECK(attach_by_worker("dsp.test.", &k) == 1);
        /* the depth skip: a name much deeper than any stored zone does not make a probe for every suffix */
        g_real_ops = atomic_load(&g_dbdir);
        g_spy_ops = *g_real_ops;
        g_spy_ops.find = counting_find;
        atomic_store(&g_dbdir, &g_spy_ops);
        const unsigned dmax = g_real_ops->depth_max(g_real_ops->view_sid("default"));
        CHECK(dmax == 3);                                                    /* c.dsp.test */
        CHECK(find_calls_for(dv, "a.b.c.d.e.f.g.h.a5.test.", &z) == 2 && z.entry && strcmp(z.entry->domain, "a5.test.") == 0);        /* (the 10-label name: nothing is asked above 3 labels; h.a5.test misses, a5.test hits) */
        CHECK(find_calls_for(dv, "w.x.y.z.nomatch.invalid.", &z) == 4 && !zref_present(&z));          /* (3 labels and fewer: 3 suffixes + the root zone, not 7 probes) */
        CHECK(find_calls_for(dv, "www.c.dsp.test.", &z) == 1 && z.entry);
        atomic_store(&g_dbdir, g_real_ops);
        release_zone_snapshot(sn);
    }

    /* -- the first fill over the limit: the zone is in the store, and not kept in memory */
    {
        dbreg_cache_test_pause(true);                                        /* (the cache manager would take every zone out at once) */
        dbreg_cache_set_limit(1);
        batch_begin(a[0], &e, 25, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "cold1.test.", 1, 0, 170);
        batch_end(a[0], &e, &mainc, 25, 1, 0);
        dbreg_cache_set_limit(0);
        dbreg_cache_test_pause(false);
        CHECK(stored_only("cold1.test."));
        CHECK(dbdir()->rec_get("default", "cold1.test.", &rec) && rec.state == STORE_STATE_STORED && rec.serial == 1);
        CHECK(attach_by_worker("cold1.test.", &k) == 1 && in_memory("cold1.test."));
    }

    /* -- settings: the interned text is kept by id; a zone that is not in memory is answered (allow-query) from them, and the id is what its record names */
    {
        uint8_t dig[KDB_DIGEST_LEN];
        memset(dig, 9, sizeof(dig));
        static const char stext[] = "allow-transfer { 127.0.0.1; };";
        batch_begin(a[0], &e, 26, KDB_BATCH_DIFF);
        kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "set1.test."); kdb_enc_i64(&e, 3, 180); kdb_enc_u8(&e, 4, KDB_ZK_PRIMARY);
        kdb_enc_u32(&e, 5, 1); kdb_enc_u32(&e, 6, 0); kdb_enc_u64(&e, 7, 4); kdb_enc_bytes(&e, 8, dig, sizeof(dig));
        kdb_enc_str(&e, 9, stext);
        kdb_enc_end(&e);
        uint8_t zm[2048];
        size_t zn = zone_message(zm, "set1.test.", 1);
        kdb_enc_raw_msg(&e, KDB_T_ZONE_DATA, zm, zn);
        kdb_enc_begin(&e, KDB_T_ZONE_END);
        kdb_enc_u64(&e, 1, 4);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        batch_end(a[0], &e, &mainc, 26, 1, 0);
        CHECK(in_memory("set1.test."));
        CHECK(dbdir()->rec_get("default", "set1.test.", &rec) && rec.settings != 0);
        zone_ext_shared_t *sh = dbdir()->settings(rec.settings);
        CHECK(sh && sh->ext.allow_transfer_count == 1);
        CHECK(evict_zone("set1.test."));
        zref_t z;
        CHECK(zref_of("set1.test.", &z) && z.entry == NULL && z.settings == rec.settings);
        rcu_aux_read_lock();
        zone_ext_shared_t *zs = zref_settings(&z);
        CHECK(zs == sh && zs->ext.allow_transfer_count == 1);
        rcu_aux_read_unlock();
        CHECK(attach_by_worker("set1.test.", &k) == 1);
        zref_t z2;
        CHECK(zref_of("set1.test.", &z2) && z2.entry);
        const zone_config_t *dc = atomic_load(&z2.entry->dbcfg);
        CHECK(dc && dc->ext_shared && dc->ext && dc->ext->allow_transfer_count == 1);                    /* (the entry of the attach has the zone's settings) */
        CHECK(dbdir()->settings_id(sh) == rec.settings);                                       /* (one id per text) */
    }

    /* -- the cost of the validation grows with the image (O(size)): a zone of 20000 addresses, attached three times */
    {
        batch_begin(a[0], &e, 4, KDB_BATCH_DIFF);
        send_big_zone(a[0], &e, "big.test.", 1, 200, 20000);
        batch_end(a[0], &e, &mainc, 4, 1, 0);
        CHECK(in_memory("big.test."));
        dbdir_rec_t br;
        CHECK(dbdir()->rec_get("default", "big.test.", &br) && br.state == STORE_STATE_STORED);
        CHECK(evict_zone("big.test.") && stored_only("big.test."));
        db_store_counters(&c0);
        int okc = 0;
        for (int i = 0; i < 3; i++) {
            okc += attach_by_worker("big.test.", &k) == 1;
            CHECK(evict_zone("big.test."));
        }
        db_store_counters(&c1);
        CHECK(okc == 3 && c1.validated == c0.validated + 3);
        store_zone_t zi;
        store_read_lock();
        uint32_t zid = store_find(st, (uint16_t)store_view_id(st, "default"), "big.test", 8);
        CHECK(zid != STORE_NONE && store_zone_get(st, zid, &zi) == 0);
        store_read_unlock();
        printf("  zone_image_validate() of a zone of 20000 addresses: %u bytes, %.2f ms each (%.1f ns/byte)\n", (unsigned)zi.img_len,
               (double)(c1.validate_ns - c0.validate_ns) / 3.0 / 1e6, (double)(c1.validate_ns - c0.validate_ns) / 3.0 / (double)(zi.img_len ? zi.img_len : 1));
    }

    /* -- a zone the database deletes is deleted from the store and its element */
    batch_begin(a[0], &e, 3, KDB_BATCH_DIFF);
    kdb_enc_begin(&e, KDB_T_ZONE_DELETE);
    kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "a5.test."); kdb_enc_i64(&e, 3, 105);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_ZONE_RESULT && m.u.zone_result.status == KDB_ST_DELETED);
    batch_end(a[0], &e, &mainc, 3, 0, 1);
    {
        zref_t z;
        CHECK(!zref_of("a5.test.", &z));
        CHECK(dbreg_lookup_entry("default", "a5.test.") == NULL);
        store_read_lock();
        CHECK(store_find(st, (uint16_t)store_view_id(st, "default"), "a5.test", 7) == STORE_NONE);
        store_read_unlock();
    }
    {
        store_check_report_t rep;
        CHECK(store_check(st, &rep) == 0);
        if (rep.errors) printf("  store_check: %s\n", rep.first_error);
    }

    /* -- the attach table grows and shrinks while readers look zones up (TSan, ASan): 1500 zones, then they leave memory */
    {
        enum { GZ = 1500 };
        pthread_t rt[3];
        atomic_store(&g_rd_stop, false);
        atomic_store(&g_gr_found, 0);
        atomic_store(&g_gr_bad, 0);
        for (int i = 0; i < 3; i++) CHECK(pthread_create(&rt[i], NULL, grow_reader_thread, (void *)(uintptr_t)GZ) == 0);
        batch_begin(a[0], &e, 30, KDB_BATCH_DIFF);
        for (int i = 0; i < GZ; i++) {
            char zn[64];
            snprintf(zn, sizeof(zn), "g%d.grow.test.", i);
            send_zone(a[0], &e, zn, 1, 0, 1000 + i);
        }
        batch_end(a[0], &e, &mainc, 30, GZ, 0);
        CHECK(dbdir()->attach_count() >= GZ);
        int gone = 0;
        for (int i = 0; i < GZ; i += 3) {
            char zn[64];
            snprintf(zn, sizeof(zn), "g%d.grow.test.", i);
            if (dbreg_test_evict("default", zn)) gone++;
        }
        CHECK(gone > GZ / 4);
        for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(5000);
        usleep(100000);
        atomic_store(&g_rd_stop, true);
        for (int i = 0; i < 3; i++) pthread_join(rt[i], NULL);
        printf("  attach table: %llu lookups of zones in memory, %llu wrong; %d zones left memory\n", (unsigned long long)atomic_load(&g_gr_found), (unsigned long long)atomic_load(&g_gr_bad), gone);
        CHECK(atomic_load(&g_gr_found) > 0 && atomic_load(&g_gr_bad) == 0);
    }

    /* -- a reader of a zone that is taken out of memory and attached again, over and over */
    {
        pthread_t rt;
        atomic_store(&g_rd_stop, false);
        atomic_store(&g_rd_ok, 0);
        atomic_store(&g_rd_gone, 0);
        atomic_store(&g_rd_bad, 0);
        CHECK(pthread_create(&rt, NULL, reader_thread, (void *)(uintptr_t)"www.a6.test.") == 0);
        int cycles = 0;
        for (int i = 0; i < 60; i++) {
            if (!dbreg_test_evict("default", "a6.test.")) {
                usleep(5000);
                continue;
            }
            usleep(2000);
            for (int w = 0; w < 400 && !in_memory("a6.test."); w++) {
                if (w % 100 == 0) {
                    drain_wakes();
                    (void)park_attach_request(0, "default", "a6.test.");
                }
                usleep(1000);
            }
            if (in_memory("a6.test.")) cycles++;
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
    /* -- a stop is a clean stop: the next open says so, replays nothing and (after a reboot) does not rebuild */
    {
        int dfd = open(sdir, O_RDONLY | O_DIRECTORY);
        store_opts_t so;
        store_opts_default(&so);
        so.boot_id = 4242;                                                   /* (another boot than the one the store was written in) */
        store_t *s2 = NULL;
        CHECK(dfd >= 0 && store_open(dfd, &so, &s2) == 0 && s2);
        if (s2) {
            store_stats_t ss2;
            store_stats(s2, &ss2);
            CHECK(ss2.recovery.was_clean && ss2.recovery.records_replayed == 0 && !ss2.recovery.rebuilt && !ss2.recovery.journal_torn);
            CHECK(ss2.zones_stored >= NZ - 1);
            (void)store_close(s2);
        }
        if (dfd >= 0) close(dfd);
    }
    char cmd[700];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)!system(cmd);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

/* ---------------------------------------------------------------- M1: the lock file of the directory */
/* The directory belongs to the user the server runs as, so that user can put anything under the name "lock" before the start.  Run as root, the start is privileged: it must not
 * give a file of root's to the run user (a hard link), wait for a FIFO, follow a link, or trust a file of another user; run by a user, the same files are refused or replaced.
 * The file the link names is never touched, and the lock file in the end is a plain file with one name that belongs to the user the server runs as. */
static bool same_file(const struct stat *a, const struct stat *b) { return a->st_ino == b->st_ino && a->st_dev == b->st_dev; }
static int lock_tests(void) {
    printf("[the lock file of the store directory]\n");
    char base[] = "/tmp/test_db_store_lock.XXXXXX";
    if (!mkdtemp(base)) { perror("mkdtemp"); return 1; }
    const bool root = geteuid() == 0;
    const uid_t run_uid = root ? 65534 : (uid_t)-1;
    const gid_t run_gid = root ? 65534 : (gid_t)-1;
    char victim[700], sdir[700], lock[800], msg[400];
    snprintf(victim, sizeof(victim), "%s/victim", base);
    snprintf(sdir, sizeof(sdir), "%s/s", base);
    snprintf(lock, sizeof(lock), "%s/lock", sdir);
    database_config_t db;
    memset(&db, 0, sizeof(db));
    db.enabled = true;
    db.store_dir = sdir;
    for (int kase = 0; kase < 5; kase++) {
        char cmd[800];
        snprintf(cmd, sizeof(cmd), "rm -rf %s %s", sdir, victim);
        (void)!system(cmd);
        int vfd = open(victim, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        CHECK(vfd >= 0 && write(vfd, "secret", 6) == 6);
        if (vfd >= 0) close(vfd);
        CHECK(mkdir(sdir, 0700) == 0);
        struct stat v0, l0;
        memset(&l0, 0, sizeof(l0));
        CHECK(stat(victim, &v0) == 0);
        const char *what = "";
        switch (kase) {
        case 0: what = "a hard link to another file (its owner is not changed, the name is replaced)"; CHECK(link(victim, lock) == 0); break;
        case 1: what = "a FIFO"; CHECK(mkfifo(lock, 0600) == 0); break;
        case 2: what = "a symbolic link"; CHECK(symlink(victim, lock) == 0); break;
        case 3: what = "a plain file (kept)"; { int fd = open(lock, O_CREAT | O_RDWR, 0600); CHECK(fd >= 0); if (fd >= 0) close(fd); } CHECK(stat(lock, &l0) == 0); break;
        case 4: what = "a file of another user"; if (root) { int fd = open(lock, O_CREAT | O_RDWR, 0600); CHECK(fd >= 0); if (fd >= 0) close(fd); CHECK(chown(lock, 12345, 12345) == 0); } else { what = "nothing"; } break;
        }
        printf("  %s\n", what);
        alarm(30);                                                           /* (a FIFO that is opened the wrong way blocks for ever: the alarm ends the test) */
        bool ok = db_store_frontend_open(&db, root, run_uid, run_gid, msg, sizeof(msg));
        alarm(0);
        CHECK(ok && db_store_dir_fd() >= 0);
        struct stat v1, l1;
        CHECK(stat(victim, &v1) == 0 && v1.st_uid == v0.st_uid && v1.st_gid == v0.st_gid && (v1.st_mode & 07777) == (v0.st_mode & 07777) && v1.st_size == 6 && v1.st_nlink == 1);
        CHECK(lstat(lock, &l1) == 0 && S_ISREG(l1.st_mode) && l1.st_nlink == 1 && !same_file(&l1, &v1));
        CHECK(l1.st_uid == (root ? run_uid : geteuid()));
        if (kase == 3) CHECK(same_file(&l0, &l1));                           /* a lock file that is fine is kept, not made again */
        db_store_frontend_close();
    }
    char cmd[800];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", base);
    (void)!system(cmd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) return run_mode(strcmp(argv[1], "copy") == 0 ? "copy" : "map");
    if (lock_tests() != 0 || g_failed) { printf("%d checks, %d failed\n", g_checks, g_failed); return 1; }
    printf("lock file: %d checks\n", g_checks);
    /* the second mode is a second process: the ingest thread and the store are process wide */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s copy", argv[0]);
    int rc = system(cmd);
    int rc2 = run_mode("map");
    return (rc != 0 || rc2 != 0) ? 1 : 0;
}

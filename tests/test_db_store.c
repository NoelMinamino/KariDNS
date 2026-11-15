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
 *   6. (0.7 WP7b, the processes proto0, proto1, proto2: run_proto()) the store protocol: the loader's manifest and changes against the store: a first fill from an empty store, the
 *      bodies fetched in the background and by a query, changes (stamps, unstamped zones, forced reload, delete by id and by name, rename), the sweep, the mass-delete guard and its
 *      release by a forced pass, an incomplete pass, secondary zones, the cursor and the identity kept in the store and sent in CONFIG, and a restart (a new process on the store left
 *      by a process that was not stopped): only the interrupted work is asked for, and only the changes after the cursor are applied
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
#include "../dns_dynamic_update.h"
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
static const char *g_zone_ns;                                          /* the NS target of the zones that zone_message() makes (NULL: ns1.<zone>) */
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
            l += put_name(b + start, g_zone_ns ? g_zone_ns : ns);
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


/* ---- helpers of the review-fix cases (run_mode): the hooks that record what the control thread asks for in the background, the walk of the attach table, a thread that asks the registry for a record ---- */
static int g_nsa_n, g_nsf_n;
static char g_nsa_zone[256], g_nsf_zone[256];
static void rec_bg_attach(const char *view, const char *zone) {
    (void)view;
    g_nsa_n++;
    snprintf(g_nsa_zone, sizeof(g_nsa_zone), "%s", zone);
}
static void rec_bg_fetch(const char *view, const char *zone) {
    (void)view;
    g_nsf_n++;
    snprintf(g_nsf_zone, sizeof(g_nsf_zone), "%s", zone);
}

typedef struct { int *seen; int nseen; uint32_t base; int calls; bool grown; bool grew; zdir_elem_t **grow; int ngrow; } walk_ud_t;
static walk_ud_t g_walk_ud;
static bool walk_fn(zdir_elem_t *el, void *ud) {
    walk_ud_t *w = ud;
    if (el->zid >= w->base && el->zid < w->base + (uint32_t)w->nseen) w->seen[el->zid - w->base]++;
    return true;
}
static void walk_reset(void *ud) { (void)ud; }
static void walk_grow_hook(void) {                                       /* (after the 150th element of the walk: zones come and go until the table is made again: it was made big for thousands of zones, few are left, so the new one is small and the position of the walk is beyond its end) */
    if (++g_walk_ud.calls == 150 && !g_walk_ud.grown) {
        g_walk_ud.grown = true;
        const uint64_t id0 = dbdir()->attach_tab_id();
        for (int i = 0; i < g_walk_ud.ngrow && dbdir()->attach_tab_id() == id0; i++) {
            (void)dbdir()->attach_put(g_walk_ud.grow[i]);
            dbdir()->attach_remove(g_walk_ud.grow[i]);                   /* (a tombstone: the table fills up with them until it is made again) */
        }
        g_walk_ud.grew = dbdir()->attach_tab_id() != id0;
    }
}

static bool g_zv_found;
static void *zv_thread(void *arg) {
    (void)arg;
    int64_t sid;
    uint32_t sr;
    g_zv_found = dbreg_zone_version("default", "r6b.test.", &sid, &sr);
    return NULL;
}

zone_db_entry_t *glue_shared_entry(view_snapshot_t *view, const view_snapshot_t *owner, const char *domain);      /* (dns_snapshot_rcu.c) */
void notify_zone_by_name(const char *view, const char *zone);               /* (dns_server_core.c: the control thread's NOTIFY of a zone by name) */

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
    {   /* a query name of 900+ characters of escapes: the suffix that is the zone is found far beyond the 260 bytes the folded copy once had (ASan: no read past it), and names over 255 ask nothing */
        static char qn[1100];
        qn[0] = '\0';
        for (int k = 0; k < 225; k++) strcat(qn, "\x5c" "097");
        strcat(qn, ".A1.TEST.");
        rcu_aux_read_lock();
        zone_db_snapshot_t *s = acquire_zone_snapshot();
        zref_t z;
        bool ok = zref_find_suffix(snapshot_find_view(s, "default"), qn, &z);
        rcu_aux_read_unlock();
        CHECK(ok && z.zid != ZREF_NOZID && strcmp(zref_name(&z), "a1.test.") == 0);
        char big[300];
        memset(big, 'a', 255);
        big[255] = '\0';
        zref_clear(&z);
        CHECK(!dbdir()->find(0, big, 255, &z) || z.busy || z.zid == ZREF_NOZID);          /* (a name of the store's limit: the lookup is bounded by zref_t.name) */
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


    /* ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ */
    /* the fixes of the review of S3 + S4 (the legacy stream): M3, L6, M4, L3, L4, L5, L9                                                                                                   */
    /* ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ */
    {
        dbdir_rec_t rr;

        /* -- M3: the table of attached zones has no room when the version a fetch brings is committed.  The zone is not registered, the entry that the install made belongs to the caller alone, and nothing
         *    in the registry points at it (before: the element held the entry the caller then freed).  A later install works. */
        batch_begin(a[0], &e, 40, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "r3.test.", 1, 0, 301);
        batch_end(a[0], &e, &mainc, 40, 1, 0);
        CHECK(in_memory("r3.test."));
        CHECK(damage_record(sdir, "r3.test."));
        CHECK(evict_zone("r3.test."));
        CHECK(attach_by_worker("r3.test.", &k) == 0 && k.retry);               /* (the record is damaged: the zone is fetched) */
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "r3.test.") == 0);
        db_store_test_attach_reserve_fail = 1;
        send_zone(f[0], &e, "r3.test.", 2, m.u.fetch_req.request_id, 301);
        CHECK(wake_for("r3.test.", &k, 5000));
        CHECK(db_store_test_attach_reserve_fail == 0);                         /* (the commit asked for the room, and was refused) */
        CHECK(!in_memory("r3.test."));
        CHECK(dbreg_lookup_entry("default", "r3.test.") == NULL);              /* (a dangling entry would be found here) */
        batch_begin(a[0], &e, 41, KDB_BATCH_DIFF);                             /* (the loader sends it again: the table has room) */
        send_zone(a[0], &e, "r3.test.", 3, 0, 301);
        batch_end(a[0], &e, &mainc, 41, 1, 0);
        CHECK(in_memory("r3.test."));
        {
            uint8_t out[1232];
            int rl = ask_engine(&g_wctx, &g_cc, "www.r3.test.", 1, out);
            CHECK(rl > 12 && (out[3] & 0x0F) == 0 && ((out[6] << 8) | out[7]) == 1);
        }

        /* -- L6: a domain that is renamed in the database: the zone of the old name is gone from the store, the attach table and the registry (before: the store alone lost it, and the element stayed, counted) */
        batch_begin(a[0], &e, 42, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "r6.test.", 1, 0, 306);
        batch_end(a[0], &e, &mainc, 42, 1, 0);
        CHECK(in_memory("r6.test."));
        const size_t att0 = dbdir()->attach_count();
        batch_begin(a[0], &e, 43, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "r6b.test.", 1, 0, 306);
        batch_end(a[0], &e, &mainc, 43, 1, 0);
        CHECK(in_memory("r6b.test.") && !in_memory("r6.test."));
        CHECK(dbreg_lookup_entry("default", "r6.test.") == NULL);
        CHECK(dbdir()->attach_count() == att0);                                /* (one zone in, one out) */
        CHECK(!dbdir()->rec_get("default", "r6.test.", &rr) && dbdir()->rec_get("default", "r6b.test.", &rr) && rr.source_id == 306);

        /* -- M4: the control commands find a zone of the store: in memory (the entry is held for the command) and not (the record) */
        {
            zone_db_snapshot_t *sn = acquire_retained_zone_snapshot();
            bool held = false;
            zone_db_entry_t *ce = dbreg_ctl_entry(sn, "default", "r6b.test.", &held);
            CHECK(ce != NULL && held && domain_names_match_ci(ce->domain, "r6b.test."));
            if (ce && held) xfr_entry_release(ce);
            CHECK(dbreg_snapshot_entry(sn, "default", "r6b.test.") == NULL);      /* (the heap directory does not have it: the reason for dbreg_ctl_entry()) */
            CHECK(evict_zone("r6b.test."));
            ce = dbreg_ctl_entry(sn, "default", "r6b.test.", &held);
            CHECK(ce == NULL && !held);
            dbreg_info_t inf[2];
            CHECK(dbreg_find_info("default", "r6b.test.", inf, 2) == 1 && !inf[0].has_entry && inf[0].store_state == 1 && inf[0].source_id == 306);
            release_zone_snapshot(sn);
            CHECK(attach_by_worker("r6b.test.", &k) == 1);
        }

        /* -- L10: a view that shares a zone of the store by in-view reaches it through its ivdb: the lookup of the glue refresh finds the zone (the heap directory's zdir_find_exact() has none of them) */
        {
            view_snapshot_t v2;
            memset(&v2, 0, sizeof(v2));
            v2.name = (char *)"v2";
            rcu_aux_read_lock();
            zone_db_snapshot_t *sn = acquire_zone_snapshot();
            view_snapshot_t *dv = snapshot_find_view(sn, "default");
            CHECK(dv != NULL && view_ivdb_alloc(&v2, 1) && view_ivdb_add(&v2, "r6b.test.", dv));
            CHECK(zdir_find_exact(&v2, "r6b.test.") == NULL);
            zone_db_entry_t *se = glue_shared_entry(&v2, dv, "r6b.test.");
            CHECK(se != NULL && strcmp(se->view_name, "default") == 0);
            CHECK(glue_shared_entry(&v2, dv, "r3.test.") == NULL);              /* (a name the view does not share) */
            view_ivdb_free(&v2);
            rcu_aux_read_unlock();
        }

        /* -- L3: the NOTIFY of a zone whose name server is in a zone of the store that is not in memory: no attach on the control thread; the zone is asked for in the background, and the NOTIFY waits and
         *    is made again.  A zone that is known without a body gets a request for its body (before: the zone that was stored was attached on the spot, the one that was known was left alone). */
        g_nsa_n = g_nsf_n = 0;
        g_query_bg_attach = rec_bg_attach;
        g_query_bg_fetch = rec_bg_fetch;
        batch_begin(a[0], &e, 44, KDB_BATCH_DIFF);
        send_zone(a[0], &e, "sib3.test.", 1, 0, 313);
        g_zone_ns = "ns1.sib3.test.";
        send_zone(a[0], &e, "n3.test.", 1, 0, 314);
        g_zone_ns = NULL;
        batch_end(a[0], &e, &mainc, 44, 2, 0);
        CHECK(in_memory("sib3.test.") && in_memory("n3.test."));
        CHECK(evict_zone("sib3.test.") && stored_only("sib3.test."));
        {
            zone_db_snapshot_t *sn = acquire_retained_zone_snapshot();
            bool held = false;
            zone_db_entry_t *ne = dbreg_ctl_entry(sn, "default", "n3.test.", &held);
            CHECK(ne != NULL);
            CHECK(notify_wait_count(false) == 0);
            if (ne) send_notify_to_all(ne);
            CHECK(stored_only("sib3.test."));                                  /* (not attached by the control thread) */
            CHECK(g_nsa_n == 1 && strcmp(g_nsa_zone, "sib3.test.") == 0 && g_nsf_n == 0);
            CHECK(notify_wait_count(false) == 1);                             /* (the NOTIFY waits for the zone) */
            if (ne && held) xfr_entry_release(ne);
            release_zone_snapshot(sn);
        }
        CHECK(attach_by_worker("sib3.test.", &k) == 1);                        /* (a store thread brought it in) */
        (void)notify_wait_count(true);                                         /* (the wait is over) */
        {
            char wv[64], wz[256];
            CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)) && strcmp(wv, "default") == 0 && strcmp(wz, "n3.test.") == 0);
            notify_zone_by_name(wv, wz);                                       /* (what the control thread does with it) */
            CHECK(notify_wait_count(false) == 0 && g_nsa_n == 1);              /* (the address is there: the NOTIFY is made, nothing waits any more) */
        }
        /* a name server in a zone that is known and has no body: its body is asked for */
        {
            store_meta_t km;
            memset(&km, 0, sizeof(km));
            km.source_id = 315;
            km.source = (uint16_t)store_view_id(st, "default");
            CHECK(store_set_known(st, (uint16_t)store_view_id(st, "default"), "sib4.test", 9, &km, NULL) == 0);
            batch_begin(a[0], &e, 45, KDB_BATCH_DIFF);
            g_zone_ns = "ns1.sib4.test.";
            send_zone(a[0], &e, "n4.test.", 1, 0, 316);
            g_zone_ns = NULL;
            batch_end(a[0], &e, &mainc, 45, 1, 0);
            zone_db_snapshot_t *sn = acquire_retained_zone_snapshot();
            bool held = false;
            zone_db_entry_t *ne = dbreg_ctl_entry(sn, "default", "n4.test.", &held);
            CHECK(ne != NULL);
            if (ne) send_notify_to_all(ne);
            CHECK(g_nsf_n == 1 && strcmp(g_nsf_zone, "sib4.test.") == 0 && notify_wait_count(false) == 1);
            if (ne && held) xfr_entry_release(ne);
            release_zone_snapshot(sn);
            (void)notify_wait_count(true);
            char wv[64], wz[256];
            while (notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz))) notify_wait_drop(wv, wz);          /* (the wait ends: a few tries, then the NOTIFY goes with what is known) */
            CHECK(notify_wait_count(false) == 0);
        }

        /* -- L4: the zone whose NOTIFY was queued is detached before the control thread looks at it: the zone is asked for and the NOTIFY waits (before: the zone was found, had no entry, and the NOTIFY was dropped) */
        g_nsa_n = 0;
        CHECK(evict_zone("n3.test.") && stored_only("n3.test."));
        notify_zone_by_name("default", "n3.test.");
        CHECK(g_nsa_n == 1 && strcmp(g_nsa_zone, "n3.test.") == 0 && notify_wait_count(false) == 1);
        CHECK(attach_by_worker("n3.test.", &k) == 1);
        (void)notify_wait_count(true);
        {
            char wv[64], wz[256];
            CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
            notify_zone_by_name(wv, wz);
            CHECK(notify_wait_count(false) == 0);
        }
        g_query_bg_attach = no_bg_fetch;
        g_query_bg_fetch = no_bg_fetch;
    }

    /* -- L5: a walk of the attach table that sees the table made again starts again, and sees every zone (before: the position was a position in the old table; when the new one is smaller, the zones that were
     *    not seen yet were never seen: the walk ended at once) */
    {
        enum { NFAKE = 300, NBIG = 6000, NGROW = 40000, BASEZID = 4000000 };
        static zdir_elem_t *fakes[NFAKE + NBIG + NGROW];
        for (int i = 0; i < NFAKE + NBIG + NGROW; i++) {
            fakes[i] = calloc(1, sizeof(zdir_elem_t) + 16);
            fakes[i]->zid = (uint32_t)(BASEZID + i);
        }
        for (int i = NFAKE; i < NFAKE + NBIG; i++) CHECK(dbdir()->attach_put(fakes[i]));        /* (the table grows for thousands of zones ...) */
        for (int i = NFAKE; i < NFAKE + NBIG; i++) dbdir()->attach_remove(fakes[i]);            /* (... and they go: few are left, and the tombstones) */
        for (int i = 0; i < NFAKE; i++) CHECK(dbdir()->attach_put(fakes[i]));
        static int seen[NFAKE];
        memset(seen, 0, sizeof(seen));
        g_walk_ud.seen = seen;
        g_walk_ud.nseen = NFAKE;
        g_walk_ud.base = BASEZID;
        g_walk_ud.calls = 0;
        g_walk_ud.grow = fakes + NFAKE + NBIG;
        g_walk_ud.ngrow = NGROW;
        g_attach_walk_between = walk_grow_hook;
        rcu_aux_read_lock();
        CHECK(attach_walk(walk_fn, walk_reset, &g_walk_ud));
        rcu_aux_read_unlock();
        g_attach_walk_between = NULL;
        int missed = 0;
        for (int i = 0; i < NFAKE; i++) missed += seen[i] == 0;
        CHECK(g_walk_ud.grown && g_walk_ud.grew);                          /* (the table did grow in the middle of the walk) */
        CHECK(missed == 0);
        for (int i = 0; i < NFAKE + NBIG + NGROW; i++) {
            dbdir()->attach_remove(fakes[i]);
            free(fakes[i]);
        }
    }

    /* -- L9: a cell of the store that is being written does not make the registry wait: the lookup under the registry's lock never sleeps (before: up to half a second with the lock held) */
    {
        dbdir_rec_t rr;
        CHECK(evict_zone("r6b.test.") && stored_only("r6b.test."));
        CHECK(dbdir()->rec_get("default", "r6b.test.", &rr));
        char zcp[700];
        snprintf(zcp, sizeof(zcp), "%s/zc.1", sdir);
        int zfd = open(zcp, O_RDWR);
        CHECK(zfd >= 0);
        uint32_t odd = 1, even = 0;
        const off_t cell = (off_t)16384 + (off_t)rr.zid * 64 + 60;           /* (the sequence counter of the cell: odd while a writer is in it) */
        CHECK(zfd >= 0 && pwrite(zfd, &odd, 4, cell) == 4);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        dbdir_rec_t r2;
        CHECK(dbdir()->rec_get_nb("default", "r6b.test.", &r2) == -1);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        CHECK((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < 100);
        pthread_t zt;
        g_zv_found = true;
        CHECK(pthread_create(&zt, NULL, zv_thread, NULL) == 0);
        usleep(3000);
        size_t tt, rj, sh;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        dbreg_counts(&tt, &rj, &sh);                                           /* (takes the registry's lock) */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        const long waited_ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
        CHECK(waited_ms < 100);
        pthread_join(zt, NULL);
        CHECK(!g_zv_found);                                                    /* (the cell was busy the whole time: not known, and the lookup gave up) */
        CHECK(zfd >= 0 && pwrite(zfd, &even, 4, cell) == 4);
        int64_t zsid;
        uint32_t zsr;
        CHECK(dbreg_zone_version("default", "r6b.test.", &zsid, &zsr) && zsid == 306);
        if (zfd >= 0) close(zfd);
    }

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

/* ---------------------------------------------------------------- 0.7 WP7b: the store protocol (the Backend's side of the loader's manifest and changes) */
/* The test is the loader of the store protocol: HELLO with features bit 0, a MANIFEST pass, CHANGES, and the answers to the Backend's FETCH_REQs on the fetch stream.  Phase 1 makes a first
 * fill, changes, a rename, deletes, a sweep, the mass-delete guard and its release by a forced pass, and ends without a clean stop (the process just exits: the store is recovered from its
 * journal); phase 2 is a new process on the same directory: the CONFIG carries the cursor and the identity, nothing is asked for except the work that was interrupted, only the changes after
 * the cursor are applied. */
#define PN 5000                                                         /* zones of the first fill */
static const char *g_pident = "ident-1";

static void pn_name(char *out, size_t cap, int i) { snprintf(out, cap, "m%04d.test.", i); }
static int pn_index(const char *name) { return name[0] == 'm' && name[1] >= '0' && name[1] <= '9' ? atoi(name + 1) : -1; }

static void p_batch_begin(int fd, kdb_enc_t *e, uint64_t id, int kind, uint64_t req) {
    kdb_enc_begin(e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(e, 1, id); kdb_enc_u8(e, 2, (uint8_t)kind); kdb_enc_u64(e, 3, 0);
    if (req) kdb_enc_u64(e, 4, req);
    kdb_enc_end(e);
    ch_send(fd, e);
}
static void p_manifest_begin(int fd, kdb_enc_t *e, uint64_t batch, uint64_t count, uint64_t cursor, bool valid) {
    kdb_enc_begin(e, KDB_T_MANIFEST_BEGIN);
    kdb_enc_u64(e, 1, batch); kdb_enc_u16(e, 2, 0); kdb_enc_u64(e, 3, count); kdb_enc_u64(e, 4, cursor); kdb_enc_u8(e, 5, valid ? 1 : 0);
    kdb_enc_bytes(e, 6, g_pident, strlen(g_pident)); kdb_enc_u32(e, 7, 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}
typedef struct { int64_t sid; char name[64]; uint8_t kind; bool stamped; uint64_t gen, time; } pz_t;
static void p_manifest_page(int fd, kdb_enc_t *e, uint64_t batch, uint32_t page, const pz_t *z, int n) {
    kdb_enc_begin(e, KDB_T_MANIFEST);
    kdb_enc_u64(e, 1, batch); kdb_enc_u16(e, 2, 0); kdb_enc_u32(e, 3, page);
    for (int i = 0; i < n; i++) {
        kdb_enc_nest_begin(e, 4);
        kdb_enc_i64(e, 1, z[i].sid); kdb_enc_name(e, 2, z[i].name); kdb_enc_u8(e, 3, z[i].kind); kdb_enc_u64(e, 4, z[i].gen); kdb_enc_u64(e, 5, z[i].time);
        if (z[i].stamped) kdb_enc_u8(e, 6, KDB_EF_STAMPED);
        kdb_enc_nest_end(e);
    }
    kdb_enc_end(e);
    ch_send(fd, e);
}
static void p_manifest_end(int fd, kdb_enc_t *e, uint64_t batch, uint64_t n, uint64_t skipped, uint64_t cursor, bool complete) {
    kdb_enc_begin(e, KDB_T_MANIFEST_END);
    kdb_enc_u64(e, 1, batch); kdb_enc_u16(e, 2, 0); kdb_enc_u64(e, 3, n); kdb_enc_u64(e, 4, skipped); kdb_enc_u64(e, 5, cursor); kdb_enc_u8(e, 6, 1);
    kdb_enc_bytes(e, 7, g_pident, strlen(g_pident)); kdb_enc_u8(e, 8, complete ? 1 : 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}
typedef struct { int64_t sid; uint8_t op; char name[400]; bool has_name; uint8_t kind; bool stamped; uint64_t gen, time; bool force; } pc_t;
static void p_changes(int fd, kdb_enc_t *e, uint64_t batch, uint64_t cursor, bool last, const pc_t *c, int n) {
    kdb_enc_begin(e, KDB_T_CHANGES);
    kdb_enc_u64(e, 1, batch); kdb_enc_u16(e, 2, 0); kdb_enc_u64(e, 3, cursor); kdb_enc_u8(e, 4, last ? 1 : 0); kdb_enc_bytes(e, 5, g_pident, strlen(g_pident));
    for (int i = 0; i < n; i++) {
        kdb_enc_nest_begin(e, 6);
        kdb_enc_i64(e, 1, c[i].sid); kdb_enc_u8(e, 2, c[i].op);
        if (c[i].has_name) kdb_enc_name(e, 3, c[i].name);
        if (c[i].op == KDB_CH_UPSERT) {
            kdb_enc_u8(e, 4, c[i].kind); kdb_enc_u64(e, 5, c[i].gen); kdb_enc_u64(e, 6, c[i].time);
            uint8_t fl = (uint8_t)((c[i].stamped ? KDB_EF_STAMPED : 0) | (c[i].force ? KDB_EF_FORCE : 0));
            if (fl) kdb_enc_u8(e, 7, fl);
        }
        kdb_enc_nest_end(e);
    }
    kdb_enc_end(e);
    ch_send(fd, e);
}
static void p_batch_end(int fd, kdb_enc_t *e, uint64_t id, uint32_t nz, uint32_t ndel) {
    kdb_enc_begin(e, KDB_T_BATCH_END);
    kdb_enc_u64(e, 1, id); kdb_enc_u32(e, 2, nz); kdb_enc_u32(e, 3, 0); kdb_enc_u32(e, 4, ndel);
    kdb_enc_end(e);
    ch_send(fd, e);
}
/* BATCH_RESULT of the batch (the answers of a store batch are only that) */
static bool p_result(ch_t *mainc, kdb_msg_t *m, int ms) {
    while (ch_next(mainc, m, ms)) {
        if (m->type == KDB_T_BATCH_RESULT) return true;
    }
    return false;
}

/* the versions the test's database has: serial of zone i (the body the loader sends) */
static uint32_t g_pserial[PN + 16];
static int g_pasked[PN + 16];                                           /* FETCH_REQs seen for zone i */
static int g_pprio[PN + 16];
static int64_t g_psid[PN + 16];
static int g_pother;                                                    /* requests for names that are not mNNNN */
static char g_pothername[16][64];

/* answer the FETCH_REQs that arrive within `ms` of silence (the loader of the store protocol: the body of every zone asked for); returns how many were answered.  skip: leave the answer out of
 * the zones with an index in [skip_lo, skip_hi) (an interrupted fill) */
static int serve_fetches(ch_t *fetchc, int fd, kdb_enc_t *e, int ms, int skip_lo, int skip_hi) {
    int n = 0;
    kdb_msg_t m;
    while (ch_next(fetchc, &m, ms)) {
        if (m.type != KDB_T_FETCH_REQ) continue;
        const kdb_fetch_req_t *r = &m.u.fetch_req;
        if (getenv("H3DBG")) fprintf(stderr, "FETCHREQ len=%zu [%.20s]" "\n", strlen(r->name), r->name);
        int i = pn_index(r->name);
        if (i < 0 || i >= PN + 16) {
            if (g_pother < 16) snprintf(g_pothername[g_pother], sizeof(g_pothername[0]), "%s", r->name);
            g_pother++;
            kdb_enc_begin(e, KDB_T_ZONE_FAILED);
            kdb_enc_u16(e, 1, r->view); kdb_enc_name(e, 2, r->name); kdb_enc_i64(e, 3, r->source_id); kdb_enc_str(e, 4, "no body in the test"); kdb_enc_u64(e, 5, r->request_id);
            kdb_enc_end(e);
            ch_send(fd, e);
            continue;
        }
        g_pasked[i]++;
        g_pprio[i] = r->priority;
        g_psid[i] = r->source_id;
        if (i >= skip_lo && i < skip_hi) continue;
        send_zone(fd, e, r->name, g_pserial[i] ? g_pserial[i] : 1, r->request_id, r->source_id);
        n++;
    }
    return n;
}

static int64_t p_sid(int i) { return 1000 + i; }

static void store_counts(store_t *st, uint64_t *known, uint64_t *stored) {
    store_stats_t ss;
    store_read_lock();
    store_stats(st, &ss);
    store_read_unlock();
    *known = ss.zones_known;
    *stored = ss.zones_stored;
}

static bool wait_stored(store_t *st, uint64_t want, int ms) {
    for (int t = 0; t < ms / 20; t++) {
        uint64_t k, s;
        store_counts(st, &k, &s);
        if (s == want && k == 0) return true;
        usleep(20000);
    }
    return false;
}

static bool zrec(store_t *st, const char *name, store_zone_t *z) {
    store_read_lock();
    int vid = store_view_id(st, "default");
    uint32_t zid = vid >= 0 ? store_find(st, (uint16_t)vid, name, strlen(name)) : STORE_NONE;
    bool ok = zid != STORE_NONE && store_zone_get(st, zid, z) == 0;
    store_read_unlock();
    return ok;
}


/* the zones listed by a full pass: every zone but the omitted ones; zone 30 is "m0030b" (renamed), zone 12 has no stamp (a row of the database without a state row) */
static bool g_renamed30;
static void p_zone(pz_t *z, int i) {
    memset(z, 0, sizeof(*z));
    z->sid = p_sid(i);
    if (i == 30 && g_renamed30) snprintf(z->name, sizeof(z->name), "m0030b.test.");
    else pn_name(z->name, sizeof(z->name), i);
    z->stamped = i != 12;
    z->gen = z->stamped ? g_pserial[i] : 0;
    z->time = z->stamped ? 10 * z->gen : 0;
}

static void full_pass(int fd, kdb_enc_t *e, uint64_t batch, const bool *omit, uint64_t cursor, bool complete) {
    static pz_t page[2048];
    int n = 0;
    uint32_t pg = 0;
    uint64_t total = 0;
    p_manifest_begin(fd, e, batch, PN, cursor, true);
    for (int i = 0; i < PN; i++) {
        if (omit && omit[i]) continue;
        p_zone(&page[n++], i);
        total++;
        if (n == 2048) {
            p_manifest_page(fd, e, batch, pg++, page, n);
            n = 0;
        }
    }
    if (n) p_manifest_page(fd, e, batch, pg++, page, n);
    p_manifest_end(fd, e, batch, total, 3, cursor, complete);
}

/* the cursor the store keeps for view "default": its value, the loader's identity after the configuration's 8 bytes */
static bool cursor_is(store_t *st, uint64_t want) {
    bool valid = false;
    uint64_t cur = 0;
    uint8_t id[STORE_IDENT_MAX];
    size_t il = 0;
    int vid = store_view_id(st, "default");
    if (vid < 0 || store_get_cursor(st, (uint16_t)vid, &valid, &cur, id, &il) != 0) return false;
    return valid && cur == want && il == 8 + strlen(g_pident) && memcmp(id + 8, g_pident, strlen(g_pident)) == 0;
}

static uint64_t zones_now(store_t *st) {
    uint64_t k, s;
    store_counts(st, &k, &s);
    return k + s;
}

static int count_asked(int lo, int hi) {
    int n = 0;
    for (int i = lo; i < hi; i++) n += g_pasked[i];
    return n;
}

static bool cursor_unset(store_t *st);
static int run_proto(int phase, const char *dir) {
    printf("[the store protocol: phase %d]\n", phase);
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled());
    store_t *st = db_store_handle();
    CHECK(st != NULL);
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
    memset(&g_wctx, 0, sizeof(g_wctx));
    g_query_bg_fetch = no_bg_fetch;
    g_query_bg_attach = no_bg_fetch;
    for (int i = 0; i < PN + 16; i++) g_pserial[i] = 1;

    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242);
    if (phase > 0) kdb_enc_u32(&e, 5, KDB_FEAT_STORE);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
    CHECK(m.u.config.store_proto == (phase > 0));
    {
        kdb_iter_t it;
        kdb_config_view_t cv;
        kdb_config_views(&m, &it);
        CHECK(kdb_config_views_next(&it, &cv));
        if (phase <= 1) {
            CHECK(!cv.has_cursor);                                       /* (a legacy loader gets none; a first fill has none) */
        } else {
            CHECK(cv.has_cursor && cv.cursor == 230 && cv.ident_len == strlen(g_pident) && memcmp(cv.ident, g_pident, cv.ident_len) == 0);
        }
    }
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    if (phase == 0) {
        /* the loader that does not offer the protocol gets the inventory as before: INVENTORY_REQ is answered (an inventory of the store: empty) */
        kdb_enc_begin(&e, KDB_T_INVENTORY_REQ);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        bool end = false;
        while (!end && ch_next(&mainc, &m, 5000)) end = m.type == KDB_T_INVENTORY_END;
        CHECK(end);
        CHECK(!ch_next(&fetchc, &m, 200));
        goto done;
    }
    uint64_t kn, sd;
    const int vid = store_view_id(st, "default");
    CHECK(vid >= 0);

    if (phase == 1) {
        CHECK(!ch_next(&fetchc, &m, 200));                               /* an empty store has nothing to ask for */

        /* -- A. the first fill: a pass.  BATCH_RESULT comes when the entries are recorded, the bodies follow */
        p_batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP, 0);
        full_pass(a[0], &e, 1, NULL, 77, true);
        p_batch_end(a[0], &e, 1, PN, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_applied == PN && m.u.batch_result.n_rejected == 0);
        store_counts(st, &kn, &sd);
        CHECK(kn == PN && sd == 0);                                      /* (no body has come: the loader is not answering yet) */
        CHECK(cursor_is(st, 77));                                        /* (the cursor is kept once the entries are recorded) */
        {
            store_zone_t z;
            CHECK(zrec(st, "m0010.test", &z) && z.state == STORE_STATE_KNOWN && z.source_id == p_sid(10) && z.stamp_gen == 1 && z.stamp_time == 10);
            zref_t zr;
            CHECK(zref_of("m4000.test.", &zr) && zr.entry == NULL && zr.zid != ZREF_NOZID && zr.zstate == ZREF_ST_KNOWN);      /* (the name index is complete: the zone is known) */
        }
        /* a query for a zone that is known and has no body goes to the fetch queue (priority 0, with the domain id) and is answered */
        drain_wakes();
        CHECK(park_fetch_request(0, "default", "m4000.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
        int n = serve_fetches(&fetchc, f[0], &e, 1500, -1, -1);
        CHECK(n >= PN - 100);
        CHECK(wake_for("m4000.test.", &k, 5000) && !k.failed && !k.retry);
        CHECK(g_pprio[4000] == 0 && g_psid[4000] == p_sid(4000));       /* (asked for by the query, and with the id the record holds) */
        CHECK(g_pprio[1000] == KDB_FETCH_PRIO_BACKGROUND && g_psid[1000] == p_sid(1000));
        CHECK(wait_stored(st, PN, 30000));
        {
            uint8_t out[1232];
            int rl = ask_engine(&g_wctx, &g_cc, "www.m4000.test.", 1, out);
            CHECK(rl > 12 && (out[3] & 0x0F) == 0 && ((out[6] << 8) | out[7]) == 1);
            store_zone_t z;
            CHECK(zrec(st, "m0010.test", &z) && z.state == STORE_STATE_STORED && z.serial == 1 && z.stamp_gen == 1 && z.stamp_time == 10 && !(z.flags & STORE_F_STALE));
        }
        int bad = 0;
        for (int i = 0; i < PN; i++) bad += g_pasked[i] != 1;
        CHECK(bad == 0);                                                 /* (every zone was asked for once) */

        /* -- B. changes: a new stamp, the same stamp, an unstamped zone, a forced one, deletes by id and by name, a rename */
        memset(g_pasked, 0, sizeof(g_pasked));
        g_pserial[10] = 2;
        g_pserial[12] = 7;
        pc_t c[8];
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = p_sid(10), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 2, .time = 20 };  pn_name(c[0].name, sizeof(c[0].name), 10);
        c[1] = (pc_t){ .sid = p_sid(11), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  pn_name(c[1].name, sizeof(c[1].name), 11);
        c[2] = (pc_t){ .sid = p_sid(12), .op = KDB_CH_UPSERT, .has_name = true, .stamped = false };                       pn_name(c[2].name, sizeof(c[2].name), 12);
        c[3] = (pc_t){ .sid = p_sid(20), .op = KDB_CH_DELETE };
        c[4] = (pc_t){ .sid = p_sid(21), .op = KDB_CH_DELETE, .has_name = true };                                           pn_name(c[4].name, sizeof(c[4].name), 21);
        c[5] = (pc_t){ .sid = p_sid(30), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  snprintf(c[5].name, sizeof(c[5].name), "m0030b.test.");
        c[6] = (pc_t){ .sid = p_sid(13), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10, .force = true };  pn_name(c[6].name, sizeof(c[6].name), 13);
        CHECK(evict_zone("m0010.test."));                                /* (the zone whose stamp changes is out of memory: its NOTIFY is queued when the new body is installed, as for a summary before) */
        { char nv[64], nz[300]; while (dbreg_notify_pop(nv, sizeof(nv), nz, sizeof(nz))) {} }
        p_batch_begin(a[0], &e, 2, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 2, 90, true, c, 7);
        p_batch_end(a[0], &e, 2, 5, 2);
        { bool pr = p_result(&mainc, &m, 10000); if (!pr || m.u.batch_result.n_applied != 4) printf("  B: got=%d applied=%u unchanged=%u rejected=%u deleted=%u\n", pr, m.u.batch_result.n_applied, m.u.batch_result.n_unchanged, m.u.batch_result.n_rejected, m.u.batch_result.n_deleted); CHECK(pr && m.u.batch_result.n_applied == 4 && m.u.batch_result.n_unchanged == 1 && m.u.batch_result.n_deleted == 2); }
        CHECK(serve_fetches(&fetchc, f[0], &e, 700, -1, -1) == 4);
        CHECK(g_pasked[10] == 1 && g_pasked[11] == 0 && g_pasked[12] == 1 && g_pasked[13] == 1 && g_pasked[30] == 1 && count_asked(0, PN) == 4);
        {
            char nv[64], nz[300];
            bool m10 = false;
            for (int t = 0; t < 100 && !m10; t++) {
                while (dbreg_notify_pop(nv, sizeof(nv), nz, sizeof(nz))) { if (strcmp(nz, "m0010.test.") == 0) m10 = true; }
                if (!m10) usleep(20000);
            }
            CHECK(m10);                                                  /* (the NOTIFY of a zone that changed while it was out of memory is queued) */
        }
        CHECK(wait_stored(st, PN - 2, 10000));
        {
            store_zone_t z;
            CHECK(zrec(st, "m0010.test", &z) && z.state == STORE_STATE_STORED && z.serial == 2 && z.stamp_gen == 2 && z.stamp_time == 20 && !(z.flags & STORE_F_STALE));
            CHECK(zrec(st, "m0011.test", &z) && z.serial == 1 && z.stamp_gen == 1);
            CHECK(zrec(st, "m0012.test", &z) && z.serial == 7 && z.stamp_gen == 0 && z.stamp_time == 0);
            CHECK(!zrec(st, "m0020.test", &z) && !zrec(st, "m0021.test", &z) && !zrec(st, "m0030.test", &z));       /* (deleted by id, by name; renamed) */
            CHECK(zrec(st, "m0030b.test", &z) && z.source_id == p_sid(30) && z.state == STORE_STATE_STORED);
            zref_t zr;
            CHECK(!zref_of("m0020.test.", &zr) && !zref_of("m0030.test.", &zr) && zref_of("m0030b.test.", &zr));
        }
        CHECK(cursor_is(st, 90));
        g_renamed30 = true;

        /* -- C. a pass that finds the same versions asks for nothing (but the zone that has no stamp, which is always asked for) */
        memset(g_pasked, 0, sizeof(g_pasked));
        static bool omit[PN];
        memset(omit, 0, sizeof(omit));
        omit[20] = omit[21] = true;                                      /* (gone from the database) */
        p_batch_begin(a[0], &e, 3, KDB_BATCH_FULL, 0);
        full_pass(a[0], &e, 3, omit, 100, true);
        p_batch_end(a[0], &e, 3, PN - 2, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 0);
        (void)serve_fetches(&fetchc, f[0], &e, 700, -1, -1);
        CHECK(count_asked(0, PN) == 1 && g_pasked[12] == 1);
        CHECK(zones_now(st) == PN - 2 && cursor_is(st, 100));

        /* -- D. a pass that does not list 200 zones (4 percent): they are deleted */
        memset(omit, 0, sizeof(omit));
        omit[20] = omit[21] = true;
        for (int i = 100; i < 300; i++) omit[i] = true;
        memset(g_pasked, 0, sizeof(g_pasked));
        p_batch_begin(a[0], &e, 4, KDB_BATCH_FULL, 0);
        full_pass(a[0], &e, 4, omit, 110, true);
        p_batch_end(a[0], &e, 4, PN - 202, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 200);
        (void)serve_fetches(&fetchc, f[0], &e, 500, -1, -1);
        CHECK(zones_now(st) == PN - 202 && cursor_is(st, 110));
        {
            store_zone_t z;
            CHECK(!zrec(st, "m0100.test", &z) && !zrec(st, "m0299.test", &z) && zrec(st, "m0300.test", &z));
        }

        /* -- E. the mass-delete guard: a pass that does not list 1600 zones (32 percent) deletes nothing, keeps the cursor, and says so */
        memset(omit, 0, sizeof(omit));
        omit[20] = omit[21] = true;
        for (int i = 100; i < 300; i++) omit[i] = true;
        for (int i = 1000; i < 2600; i++) omit[i] = true;
        p_batch_begin(a[0], &e, 5, KDB_BATCH_FULL, 0);
        full_pass(a[0], &e, 5, omit, 120, true);
        p_batch_end(a[0], &e, 5, PN - 202 - 1600, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 0);
        CHECK(zones_now(st) == PN - 202);                                /* (nothing was deleted) */
        {
            store_zone_t z;
            CHECK(zrec(st, "m1500.test", &z) && z.state == STORE_STATE_STORED);
            db_recon_status_t rs;
            db_recon_status(&rs);
            CHECK(rs.guard_views == 1 && rs.guard_unlisted == 1600 && strcmp(rs.guard_view, "default") == 0);
            static char kv[STORE_STATUS_OUT_MAX];
            CHECK(store_status_format(kv, sizeof(kv), STORE_FMT_KV, NULL) > 0);
            CHECK(strstr(kv, "store.recon.guard.held_views=1") != NULL && strstr(kv, "store.recon.guard.unlisted=1600") != NULL && strstr(kv, "store.recon.guard.release=\"karictl reload -force\"") != NULL);
        }
        CHECK(cursor_unset(st));                                         /* (not advanced: it is made invalid, so that a restart makes a pass again; L7) */
        /* changes while the guard holds: the cursor stays unset too */
        p_batch_begin(a[0], &e, 6, KDB_BATCH_AUTO, 0);
        c[0] = (pc_t){ .sid = p_sid(11), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  pn_name(c[0].name, sizeof(c[0].name), 11);
        p_changes(a[0], &e, 6, 130, true, c, 1);
        p_batch_end(a[0], &e, 6, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        CHECK(cursor_unset(st));

        /* -- F. the operator's `karictl reload -force` is a pass the guard does not hold back */
        uint64_t rid = db_ingest_reload(true, NULL, NULL, true);
        CHECK(rid > 0);
        bool got = false;
        while (!got && ch_next(&mainc, &m, 5000)) got = m.type == KDB_T_RELOAD_REQ;
        CHECK(got && m.u.reload_req.request_id == rid && m.u.reload_req.scope == 0 && m.u.reload_req.force == 1);
        p_batch_begin(a[0], &e, 7, KDB_BATCH_FULL, rid);
        full_pass(a[0], &e, 7, omit, 200, true);
        p_batch_end(a[0], &e, 7, PN - 202 - 1600, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 1600);
        CHECK(zones_now(st) == PN - 202 - 1600);
        {
            store_zone_t z;
            db_recon_status_t rs;
            db_recon_status(&rs);
            CHECK(!zrec(st, "m1500.test", &z) && zrec(st, "m0999.test", &z) && zrec(st, "m2600.test", &z));
            CHECK(rs.guard_views == 0 && rs.swept == 1600);
        }
        CHECK(cursor_is(st, 200));

        /* -- G. a pass the loader could not finish (complete = 0) deletes nothing and keeps no cursor */
        memset(omit, 1, sizeof(omit));
        p_batch_begin(a[0], &e, 8, KDB_BATCH_FULL, 0);
        full_pass(a[0], &e, 8, omit, 300, false);
        p_batch_end(a[0], &e, 8, 0, 0);
        CHECK(p_result(&mainc, &m, 10000));
        CHECK(zones_now(st) == PN - 202 - 1600 && cursor_is(st, 200));

        /* -- H. a secondary zone: a record that only remembers it (no query finds it), asked for once, again when its stamp changes */
        g_pother = 0;
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = 9001, .op = KDB_CH_UPSERT, .has_name = true, .kind = KDB_ZK_SECONDARY, .stamped = true, .gen = 1, .time = 5 };  snprintf(c[0].name, sizeof(c[0].name), "sec1.test.");
        p_batch_begin(a[0], &e, 9, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 9, 210, true, c, 1);
        p_batch_end(a[0], &e, 9, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        (void)serve_fetches(&fetchc, f[0], &e, 700, -1, -1);
        CHECK(g_pother == 1 && strcmp(g_pothername[0], "sec1.test.") == 0);
        {
            store_zone_t z;
            zref_t zr;
            CHECK(zrec(st, "sec1.test", &z) && (z.flags & STORE_F_NONSTORE) && z.state == STORE_STATE_KNOWN);
            CHECK(!zref_of("sec1.test.", &zr));                          /* (a heap zone: the store's index does not show it to a query) */
        }
        p_batch_begin(a[0], &e, 10, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 10, 215, true, c, 1);                       /* (the same stamp) */
        p_batch_end(a[0], &e, 10, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        (void)serve_fetches(&fetchc, f[0], &e, 500, -1, -1);
        CHECK(g_pother == 1);
        c[0].gen = 2;
        p_batch_begin(a[0], &e, 11, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 11, 216, true, c, 1);                       /* (a new stamp) */
        p_batch_end(a[0], &e, 11, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        (void)serve_fetches(&fetchc, f[0], &e, 700, -1, -1);
        CHECK(g_pother == 2);

        /* -- H2. karictl reload <zone>: the loader marks the entry of a one-zone reload FORCE; without `force` the stamp decides (a zone that did not change is "unchanged" and is not read, BATCH_RESULT
         * comes at once), with `force` the body is read and BATCH_RESULT, which the loader waits for, is held until it is installed */
        {
            db_reload_result_t rr;
            memset(&rr, 0, sizeof(rr));
            memset(g_pasked, 0, sizeof(g_pasked));
            uint64_t r1 = db_ingest_reload(false, "default", "m0300.test.", false);
            CHECK(r1 > 0);
            bool got1 = false;
            while (!got1 && ch_next(&mainc, &m, 5000)) got1 = m.type == KDB_T_RELOAD_REQ;
            CHECK(got1 && m.u.reload_req.request_id == r1 && m.u.reload_req.scope == 1 && m.u.reload_req.force == 0);
            pc_t c1[1];
            memset(c1, 0, sizeof(c1));
            c1[0] = (pc_t){ .sid = p_sid(300), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10, .force = true };
            pn_name(c1[0].name, sizeof(c1[0].name), 300);
            p_batch_begin(a[0], &e, 20, KDB_BATCH_ZONE, r1);
            p_changes(a[0], &e, 20, 0, false, c1, 1);
            p_batch_end(a[0], &e, 20, 1, 0);
            CHECK(p_result(&mainc, &m, 5000) && m.u.batch_result.n_unchanged == 1 && m.u.batch_result.n_applied == 0);
            bool have = false;
            for (int t = 0; t < 200 && !have; t++) { have = db_ingest_reload_result(&rr); if (!have) usleep(10000); }
            CHECK(have && rr.id == r1 && rr.ok && strstr(rr.text, "unchanged, serial 1") != NULL);
            CHECK(!ch_next(&fetchc, &m, 200));                           /* (nothing was read) */
            uint64_t r2 = db_ingest_reload(false, "default", "m0300.test.", true);
            CHECK(r2 > 0);
            bool got2 = false;
            while (!got2 && ch_next(&mainc, &m, 5000)) got2 = m.type == KDB_T_RELOAD_REQ;
            CHECK(got2 && m.u.reload_req.request_id == r2 && m.u.reload_req.force == 1);
            p_batch_begin(a[0], &e, 21, KDB_BATCH_ZONE, r2);
            p_changes(a[0], &e, 21, 0, false, c1, 1);
            p_batch_end(a[0], &e, 21, 1, 0);
            CHECK(!p_result(&mainc, &m, 300));                           /* (the answer waits for the body) */
            CHECK(serve_fetches(&fetchc, f[0], &e, 500, -1, -1) == 1 && g_pasked[300] == 1);
            CHECK(p_result(&mainc, &m, 5000) && m.u.batch_result.n_applied == 1);
            have = false;
            for (int t = 0; t < 200 && !have; t++) { have = db_ingest_reload_result(&rr); if (!have) usleep(10000); }
            CHECK(have && rr.id == r2 && rr.ok && strstr(rr.text, "serial 1") != NULL && strstr(rr.text, "applied") != NULL);
        }

        /* -- H3. the root zone, which the store cannot name: no record; the Backend asks for the body like a secondary zone's (it becomes a zone of the heap directory), counts it
         * (store.zones.nonstore), asks again only for a new stamp, and does not keep the cursor of the view while it has one.  A name of over 255 bytes of text (escapes) can be neither stored nor keyed by
         * the heap directory: it is refused (rejected), as before */
        {
            char longn[400];                                              /* (5 labels of 30 dots written as escapes: 300 bytes of text, 156 on the wire: over the 255 the store and the directory key) */
            longn[0] = '\0';
            for (int j = 0; j < 5; j++) {
                for (int k = 0; k < 30; k++) strcat(longn, "\\.");
                strcat(longn, ".");
            }
            memset(c, 0, sizeof(c));
            c[0] = (pc_t){ .sid = 9100, .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 5 };  snprintf(c[0].name, sizeof(c[0].name), ".");
            c[1] = (pc_t){ .sid = 9101, .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 5 };  snprintf(c[1].name, sizeof(c[1].name), "%s", longn);
            g_pother = 0;
            p_batch_begin(a[0], &e, 30, KDB_BATCH_AUTO, 0);
            p_changes(a[0], &e, 30, 220, true, c, 2);
            p_batch_end(a[0], &e, 30, 2, 0);
            CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_applied == 1 && m.u.batch_result.n_rejected == 1);
            (void)serve_fetches(&fetchc, f[0], &e, 700, -1, -1);
            {
                store_zone_t z;
                db_recon_status_t rs;
                db_recon_status(&rs);
                CHECK(g_pother == 1);
                CHECK(strcmp(g_pothername[0], ".") == 0);
                CHECK(rs.nonstore == 1);
                CHECK(!zrec(st, "", &z));                                /* (no record) */
            }
            CHECK(cursor_is(st, 216));                                   /* (not advanced while the view has such a zone) */
            p_batch_begin(a[0], &e, 31, KDB_BATCH_AUTO, 0);
            p_changes(a[0], &e, 31, 221, true, c, 2);                    /* (the same stamps: not asked for again) */
            p_batch_end(a[0], &e, 31, 2, 0);
            CHECK(p_result(&mainc, &m, 10000));
            (void)serve_fetches(&fetchc, f[0], &e, 400, -1, -1);
            CHECK(g_pother == 1);
            c[0].gen = 2;
            p_batch_begin(a[0], &e, 32, KDB_BATCH_AUTO, 0);
            p_changes(a[0], &e, 32, 222, true, c, 1);                    /* (a new stamp of the root zone) */
            p_batch_end(a[0], &e, 32, 1, 0);
            CHECK(p_result(&mainc, &m, 10000));
            (void)serve_fetches(&fetchc, f[0], &e, 700, -1, -1);
            CHECK(g_pother == 2);
            c[0] = (pc_t){ .sid = 9100, .op = KDB_CH_DELETE };                /* (by source id: the loader has no name for a zone whose row is gone) */
            c[1] = (pc_t){ .sid = 9101, .op = KDB_CH_DELETE };
            p_batch_begin(a[0], &e, 33, KDB_BATCH_AUTO, 0);
            p_changes(a[0], &e, 33, 223, true, c, 2);                    /* (the refused zone is not known: nothing to delete) */
            p_batch_end(a[0], &e, 33, 0, 2);
            CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 1);
            {
                db_recon_status_t rs;
                db_recon_status(&rs);
                CHECK(rs.nonstore == 0);
            }
            CHECK(cursor_is(st, 223));                                   /* (no such zone: the cursor goes on) */
        }

        /* -- I. work that is interrupted: three zones change and the loader does not answer; the process ends as if it were killed */
        memset(g_pasked, 0, sizeof(g_pasked));
        memset(c, 0, sizeof(c));
        for (int j = 0; j < 3; j++) {
            c[j] = (pc_t){ .sid = p_sid(500 + j), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 5, .time = 50 };
            pn_name(c[j].name, sizeof(c[j].name), 500 + j);
        }
        g_pserial[500] = g_pserial[501] = g_pserial[502] = 5;
        p_batch_begin(a[0], &e, 12, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 12, 230, true, c, 3);
        p_batch_end(a[0], &e, 12, 3, 0);
        CHECK(p_result(&mainc, &m, 10000));
        (void)serve_fetches(&fetchc, f[0], &e, 700, 500, 503);          /* (the three requests are read and not answered) */
        CHECK(g_pasked[500] == 1 && g_pasked[501] == 1 && g_pasked[502] == 1);
        {
            store_zone_t z;
            CHECK(zrec(st, "m0500.test", &z) && z.state == STORE_STATE_STORED && (z.flags & STORE_F_STALE) && z.serial == 1 && z.stamp_gen == 5);     /* (the old image serves, the new stamp is the wanted one) */
        }
        CHECK(cursor_is(st, 230));
        db_store_batch_end();
        printf("%d checks, %d failed\n", g_checks, g_failed);
        fflush(stdout);
        _exit(g_failed ? 1 : 0);                                         /* (no clean stop: the next start recovers the store from its journal) */
    }

    /* -- phase 2: a new process on the same store.  The CONFIG carried the cursor (230) and the identity.  Nothing is listed again: only the interrupted work is asked for, and the changes after the cursor are applied */
    store_counts(st, &kn, &sd);
    CHECK(sd == PN - 202 - 1600 && kn == 1);                              /* (the zones, and the secondary's record) */
    CHECK(cursor_is(st, 230));
    CHECK(attach_by_worker("m0700.test.", &k) == 1);                     /* (the loader has said nothing: the zone comes from the store alone) */
    for (int i = 0; i < PN + 16; i++) g_pserial[i] = 1;
    g_pserial[500] = g_pserial[501] = g_pserial[502] = 5;
    g_pother = 0;
    int answered = serve_fetches(&fetchc, f[0], &e, 1500, -1, -1);
    CHECK(answered == 3 && g_pasked[500] == 1 && g_pasked[501] == 1 && g_pasked[502] == 1 && count_asked(0, PN) == 3);      /* (the three zones whose bodies were not here, nothing else) */
    CHECK(g_pother == 1 && strcmp(g_pothername[0], "sec1.test.") == 0);  /* (and the secondary zone, once per run) */
    {
        store_zone_t z;
        CHECK(zrec(st, "m0500.test", &z) && z.state == STORE_STATE_STORED && z.serial == 5 && !(z.flags & STORE_F_STALE));
    }
    memset(g_pasked, 0, sizeof(g_pasked));
    {
        pc_t c[2];
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = p_sid(600), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 9, .time = 90 };  pn_name(c[0].name, sizeof(c[0].name), 600);
        g_pserial[600] = 9;
        p_batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP, 0);
        p_changes(a[0], &e, 1, 240, true, c, 1);
        p_batch_end(a[0], &e, 1, 1, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_applied == 1);
        CHECK(serve_fetches(&fetchc, f[0], &e, 700, -1, -1) == 1 && g_pasked[600] == 1 && count_asked(0, PN) == 1);
        store_zone_t z;
        CHECK(zrec(st, "m0600.test", &z) && z.serial == 9 && z.stamp_gen == 9);
        CHECK(cursor_is(st, 240));
    }
done:
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    _exit(g_failed ? 1 : 0);
}


/* ---------------------------------------------------------------- the fixes of the review of S3 + S4 (phases 3, 4, 5) */
/* Phase 3 is a loader of the store protocol on a new store, with the store's writes made to fail where a disk can fail (store_test_write_fault) and the memory of a pass to run out (db_store_test_bits_fail):
 *   H1  an entry that could not be recorded is not swept as unlisted (and a pass in which one failed keeps no cursor); the same when the bit of a zone could not be set
 *   M5  a CHANGES delete that the store cannot make is not counted as done (the cursor is not kept) and is made again
 *   M6  a body that is dropped because the stamp moved asks for the zone again (a fetch that was in flight when the stamp changed)
 *   M7  a zone of 63 labels or more is found (the depth skip of the lookup), and the depth bound is exact with several threads that put zones and delete them
 *   L8  the records of the secondary and catalog zones are not counted with the zones of the directory twice
 *   L11 the reserve of a pass is bounded by what the store holds, not by what the loader claims
 *   L7  the hold of the mass-delete guard is in the store: the cursor of the view is not valid, so a restart makes a pass
 * Phase 4 (a legacy loader) makes three zones with three settings texts, and phase 5 is the next start with a settings.dat in which the id of one text cannot be taken (L2): the file is not cut, the ids that
 * follow are not reused. */
#define NF 1200                                                         /* zones of the first fill of phase 3 */
static uint32_t g_fx_zid;
static const char *g_fx_op;
static int g_fx_err;
static int fx_fault(const char *op, uint32_t zid) { return (g_fx_op && strcmp(op, g_fx_op) == 0 && zid == g_fx_zid) ? g_fx_err : 0; }

static void fx_pass(int fd, kdb_enc_t *e, uint64_t batch, int n, const bool *omit, uint64_t cursor, bool complete) {
    static pz_t page[2048];
    int k = 0;
    uint32_t pg = 0;
    uint64_t total = 0;
    p_manifest_begin(fd, e, batch, (uint64_t)n, cursor, true);
    for (int i = 0; i < n; i++) {
        if (omit && omit[i]) continue;
        p_zone(&page[k], i);
        page[k].stamped = true;
        page[k].gen = g_pserial[i];
        page[k].time = 10 * g_pserial[i];
        k++;
        total++;
        if (k == 2048) {
            p_manifest_page(fd, e, batch, pg++, page, k);
            k = 0;
        }
    }
    if (k) p_manifest_page(fd, e, batch, pg++, page, k);
    p_manifest_end(fd, e, batch, total, 0, cursor, complete);
}

/* the cursor is there and is the configuration's hash only: nothing of the loader's (what a hold of the guard leaves) */
static bool cursor_unset(store_t *st) {
    bool valid = false;
    uint64_t cur = 0;
    uint8_t id[STORE_IDENT_MAX];
    size_t il = 0;
    int vid = store_view_id(st, "default");
    if (vid < 0 || store_get_cursor(st, (uint16_t)vid, &valid, &cur, id, &il) != 0) return false;
    uint64_t c2;
    uint8_t i2[STORE_IDENT_MAX];
    size_t l2 = 0;
    return valid && il == 8 && !db_recon_cursor_get("default", &c2, i2, &l2);
}

/* a name of `labels` labels (the last is "test"), the first one `first`; written to out */
static void fx_deep_name(char *out, size_t cap, int labels, const char *first) {
    size_t o = (size_t)snprintf(out, cap, "%s.", first);
    for (int i = 1; i < labels - 1 && o < cap; i++) o += (size_t)snprintf(out + o, cap - o, "a.");
    if (o < cap) snprintf(out + o, cap - o, "test.");
}

#define FX_THREADS 4
#define FX_EACH 60
static void *fx_put_thread(void *arg) {
    const int k = (int)(intptr_t)arg;
    for (int i = 0; i < FX_EACH; i++) {
        char first[32], name[400];
        snprintf(first, sizeof(first), "w%di%d", k, i);
        const int labels = 3 + (i * 7 + k * 11) % 70;                    /* 3..72 labels: the zones of 63 and more among them */
        fx_deep_name(name, sizeof(name), labels, first);
        db_recon_entry_t re;
        memset(&re, 0, sizeof(re));
        re.source_id = 500000 + k * 1000 + i;
        re.name = name;
        re.kind = KDB_ZK_PRIMARY;
        re.stamped = true;
        re.gen = 1;
        re.time = 1;
        uint32_t zid;
        (void)db_recon_change("default", &re, &zid);
        if (i % 3 == 2) (void)db_recon_delete("default", re.source_id - 1, NULL);             /* (the refresh of the bound runs in between) */
    }
    return NULL;
}

static int run_fixes(const char *dir) {
    printf("[the store protocol: the fixes of the review of S3 + S4 (phase 3)]\n");
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled());
    store_t *st = db_store_handle();
    CHECK(st != NULL);
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
    memset(&g_wctx, 0, sizeof(g_wctx));
    g_query_bg_fetch = no_bg_fetch;
    g_query_bg_attach = no_bg_fetch;
    for (int i = 0; i < PN + 16; i++) g_pserial[i] = 1;
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_STORE);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG && m.u.config.store_proto);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    const int vid = store_view_id(st, "default");
    CHECK(vid >= 0);
    static bool omit[PN + 16];
    memset(omit, 0, sizeof(omit));
    store_zone_t z;
    store_test_write_fault = fx_fault;

    /* -- a first fill */
    p_batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP, 0);
    fx_pass(a[0], &e, 1, NF, NULL, 100, true);
    p_batch_end(a[0], &e, 1, NF, 0);
    CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_applied == NF);
    (void)serve_fetches(&fetchc, f[0], &e, 1500, -1, -1);
    CHECK(wait_stored(st, NF, 30000));
    CHECK(cursor_is(st, 100));

    /* -- H1: a zone whose new stamp could not be recorded (the disk is full) is listed by the database: it is not swept, with the zone the database no longer lists in the same pass, and the pass keeps no
     *    cursor.  (Before: the entry did not set the bit of its zone, and the sweep deleted it.) */
    g_pserial[3] = 2;
    CHECK(zrec(st, "m0003.test", &z));
    g_fx_zid = z.zid;
    g_fx_op = "set_stamp";
    g_fx_err = -ENOSPC;
    omit[1100] = true;
    p_batch_begin(a[0], &e, 2, KDB_BATCH_AUTO, 0);
    fx_pass(a[0], &e, 2, NF, omit, 200, true);
    p_batch_end(a[0], &e, 2, NF - 1, 0);
    CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_rejected == 1 && m.u.batch_result.n_deleted == 0);
    CHECK(zrec(st, "m0003.test", &z) && z.state == STORE_STATE_STORED && z.stamp_gen == 1 && z.serial == 1);       /* (kept as it was) */
    CHECK(zrec(st, "m1100.test", &z));                                  /* (the database does not list it, and nothing was swept) */
    CHECK(zones_now(st) == NF && cursor_is(st, 100));
    g_fx_op = NULL;
    p_batch_begin(a[0], &e, 3, KDB_BATCH_AUTO, 0);                     /* (the next pass: the disk has room) */
    fx_pass(a[0], &e, 3, NF, omit, 300, true);
    p_batch_end(a[0], &e, 3, NF - 1, 0);
    CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_rejected == 0);
    (void)serve_fetches(&fetchc, f[0], &e, 1000, -1, -1);
    CHECK(wait_stored(st, NF - 1, 30000));
    CHECK(!zrec(st, "m1100.test", &z) && zrec(st, "m0003.test", &z) && z.serial == 2 && z.stamp_gen == 2 && cursor_is(st, 300));

    /* -- H1: the bit of a zone that the pass lists cannot be set (no memory): the same, nothing is swept */
    omit[1101] = true;
    db_store_test_bits_fail = 4;
    p_batch_begin(a[0], &e, 4, KDB_BATCH_AUTO, 0);
    fx_pass(a[0], &e, 4, NF, omit, 400, true);
    p_batch_end(a[0], &e, 4, NF - 2, 0);
    CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 0);
    CHECK(zrec(st, "m1101.test", &z) && zones_now(st) == NF - 1 && cursor_is(st, 300));
    db_store_test_bits_fail = 0;
    p_batch_begin(a[0], &e, 5, KDB_BATCH_AUTO, 0);
    fx_pass(a[0], &e, 5, NF, omit, 500, true);
    p_batch_end(a[0], &e, 5, NF - 2, 0);
    CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 1);
    CHECK(!zrec(st, "m1101.test", &z) && cursor_is(st, 500));

    /* -- M5: the store cannot delete a zone the change log deletes: not counted as done, the zone stays, the cursor is not kept; the same delete later works.  (Before: counted, the cursor saved, the record
     *    survived and came back after a restart.) */
    CHECK(zrec(st, "m0005.test", &z));
    g_fx_zid = z.zid;
    g_fx_op = "delete";
    g_fx_err = -EIO;
    {
        pc_t c[1];
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = p_sid(5), .op = KDB_CH_DELETE, .has_name = true };
        pn_name(c[0].name, sizeof(c[0].name), 5);
        p_batch_begin(a[0], &e, 6, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 6, 600, true, c, 1);
        p_batch_end(a[0], &e, 6, 0, 1);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 0 && m.u.batch_result.n_rejected == 1);
        CHECK(zrec(st, "m0005.test", &z) && cursor_is(st, 500));
        g_fx_op = NULL;
        p_batch_begin(a[0], &e, 7, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 7, 610, true, c, 1);
        p_batch_end(a[0], &e, 7, 0, 1);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 1);
        CHECK(!zrec(st, "m0005.test", &z) && cursor_is(st, 610));
    }

    /* -- M6: a fetch of a zone is in flight when the database changes the zone again; the body that arrives is for the old stamp and is dropped, and the zone is asked for again.  (Before: nothing asked
     *    again, the record stayed wanted for ever.) */
    {
        pc_t c[1];
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = p_sid(1300), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };
        pn_name(c[0].name, sizeof(c[0].name), 1300);
        g_pserial[1300] = 1;
        p_batch_begin(a[0], &e, 8, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 8, 620, true, c, 1);
        p_batch_end(a[0], &e, 8, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "m1300.test.") == 0);
        const uint64_t rid = m.u.fetch_req.request_id;
        c[0].gen = 2;
        c[0].time = 20;
        p_batch_begin(a[0], &e, 9, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 9, 630, true, c, 1);
        p_batch_end(a[0], &e, 9, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        send_zone(f[0], &e, "m1300.test.", 1, rid, p_sid(1300));         /* (the body of the first stamp) */
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "m1300.test.") == 0);
        send_zone(f[0], &e, "m1300.test.", 2, m.u.fetch_req.request_id, p_sid(1300));
        CHECK(wait_stored(st, NF - 2, 30000));
        CHECK(zrec(st, "m1300.test", &z) && z.state == STORE_STATE_STORED && z.serial == 2 && z.stamp_gen == 2 && !(z.flags & STORE_F_STALE));
    }

    /* -- L8: the record of a secondary zone is the memory of a zone of the heap directory: not a zone of the directory's total */
    {
        pc_t c[1];
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = 9001, .op = KDB_CH_UPSERT, .has_name = true, .kind = KDB_ZK_SECONDARY, .stamped = true, .gen = 1, .time = 5 };
        snprintf(c[0].name, sizeof(c[0].name), "sec1.test.");
        p_batch_begin(a[0], &e, 10, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 10, 640, true, c, 1);
        p_batch_end(a[0], &e, 10, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        (void)serve_fetches(&fetchc, f[0], &e, 800, -1, -1);
        store_stats_t ss;
        store_stats(st, &ss);
        CHECK(ss.zones_nonstore == 1 && ss.zones_known + ss.zones_stored == (uint64_t)NF - 2 + 1);
        CHECK(dbdir()->counters(0) == (uint64_t)NF - 2);             /* (the secondary's record is not in it) */
    }

    /* -- M7: a zone of 63 labels and more is found; the bound is exact when threads put and delete zones */
    {
        pc_t c[1];
        memset(c, 0, sizeof(c));
        c[0] = (pc_t){ .sid = 700001, .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };
        fx_deep_name(c[0].name, sizeof(c[0].name), 70, "deep");
        char deepcopy[400];
        snprintf(deepcopy, sizeof(deepcopy), "%s", c[0].name);
        p_batch_begin(a[0], &e, 11, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, 11, 650, true, c, 1);
        p_batch_end(a[0], &e, 11, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        CHECK(dbdir()->depth_max(vid) == 63);
        zref_t zr;
        CHECK(zref_of(deepcopy, &zr) && zr.zid != ZREF_NOZID);             /* (before: the depth skip hid it until a restart) */
        (void)serve_fetches(&fetchc, f[0], &e, 800, -1, -1);
        pthread_t th[FX_THREADS];
        for (int k = 0; k < FX_THREADS; k++) CHECK(pthread_create(&th[k], NULL, fx_put_thread, (void *)(intptr_t)k) == 0);
        for (int k = 0; k < FX_THREADS; k++) pthread_join(th[k], NULL);
        CHECK(dbdir()->depth_max(vid) == store_view_depth_max(st, (uint16_t)vid));
        CHECK(dbdir()->depth_max(vid) == 63);
        (void)serve_fetches(&fetchc, f[0], &e, 1500, -1, -1);
    }

    /* -- L11: a loader that claims four million zones makes the store reserve what it can hold plus a million, not four million records */
    {
        char why[200];
        store_stats_t s1;
        CHECK(db_recon_begin("default", 4000000, false, why, sizeof(why)));
        store_stats(st, &s1);
        CHECK(s1.zt_capacity < 3000000);
        db_recon_abort();
    }

    /* -- L7: the guard holds a pass that lists 100 of the zones; the hold is in the store (the cursor of the view is not valid), and nothing is deleted.  (Before: the old cursor stayed, and a restart read
     *    only the changes after it and never made the pass that finds the same again.) */
    {
        const uint64_t before = zones_now(st);
        memset(omit, 0, sizeof(omit));
        for (int i = 100; i < NF; i++) omit[i] = true;
        omit[5] = true;                                                  /* (deleted above) */
        p_batch_begin(a[0], &e, 12, KDB_BATCH_FULL, 0);
        fx_pass(a[0], &e, 12, NF, omit, 700, true);
        p_batch_end(a[0], &e, 12, 99, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 0);
        CHECK(zones_now(st) == before);
        db_recon_status_t rs;
        db_recon_status(&rs);
        CHECK(rs.guard_views == 1);
        CHECK(cursor_unset(st));
    }
    store_test_write_fault = NULL;
    db_store_batch_end();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    _exit(g_failed ? 1 : 0);
}

/* phase 4: a legacy loader (no store protocol) installs three zones with three settings texts; the process ends without a clean stop.  Phase 5: the next start, with the second record of settings.dat made
 * unusable by the test (no room for its id): the file is not cut, the ids of the others are what they were, and a new text gets the next id */
static int run_settings(int phase, const char *dir) {
    printf("[the settings of the zones are kept by id: phase %d]\n", phase);
    char sdir[600], sizefile[700];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    snprintf(sizefile, sizeof(sizefile), "%s/settings.size", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    if (phase == 5) db_store_test_set_fail = 2;                         /* (the second record of settings.dat has no room for its id) */
    CHECK(db_store_start(&cfg) && db_store_enabled());
    db_store_test_set_fail = 0;
    struct stat sb;
    char setfile[700];
    snprintf(setfile, sizeof(setfile), "%s/settings.dat", sdir);
    long long size_at_start = stat(setfile, &sb) == 0 ? (long long)sb.st_size : -1;      /* (what the start made of the file, before this run adds a text) */
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
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    const int first = phase == 4 ? 1 : 4;                               /* the texts of this run: 1..3 in phase 4, a fourth in phase 5 */
    const int count = phase == 4 ? 3 : 1;
    batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP);
    for (int i = first; i < first + count; i++) {
        char zn[32], stext[96];
        snprintf(zn, sizeof(zn), "set%d.test.", i);
        snprintf(stext, sizeof(stext), "allow-transfer { 127.0.0.%d; };", i);
        uint8_t dig[KDB_DIGEST_LEN];
        memset(dig, 9, sizeof(dig));
        kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, zn); kdb_enc_i64(&e, 3, 700 + i); kdb_enc_u8(&e, 4, KDB_ZK_PRIMARY);
        kdb_enc_u32(&e, 5, 1); kdb_enc_u32(&e, 6, 0); kdb_enc_u64(&e, 7, 4); kdb_enc_bytes(&e, 8, dig, sizeof(dig));
        kdb_enc_str(&e, 9, stext);
        kdb_enc_end(&e);
        uint8_t zm[2048];
        size_t zn_len = zone_message(zm, zn, 1);
        kdb_enc_raw_msg(&e, KDB_T_ZONE_DATA, zm, zn_len);
        kdb_enc_begin(&e, KDB_T_ZONE_END);
        kdb_enc_u64(&e, 1, 4);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
    }
    batch_end(a[0], &e, &mainc, 1, (uint32_t)count, 0);
    dbdir_rec_t rec;
    if (phase == 4) {
        for (int i = 1; i <= 3; i++) {
            char zn[32];
            snprintf(zn, sizeof(zn), "set%d.test.", i);
            CHECK(dbdir()->rec_get("default", zn, &rec) && rec.settings == (uint32_t)i);
        }
        CHECK(stat(setfile, &sb) == 0);
        FILE *sf = fopen(sizefile, "w");
        CHECK(sf != NULL);
        if (sf) {
            fprintf(sf, "%lld\n", (long long)sb.st_size);
            fclose(sf);
        }
    } else {
        long long want = -1;
        FILE *sf = fopen(sizefile, "r");
        if (sf) {
            if (fscanf(sf, "%lld", &want) != 1) want = -1;
            fclose(sf);
        }
        CHECK(want > 0 && size_at_start == want);                           /* (not cut) */
        CHECK(dbdir()->settings(1) != NULL && dbdir()->settings(2) == NULL && dbdir()->settings(3) != NULL);      /* (the id that could not be taken is unused, the ones after it are what they were) */
        CHECK(dbdir()->rec_get("default", "set4.test.", &rec) && rec.settings == 4);             /* (the new text gets the next id: 3 was not given to it) */
        CHECK(dbdir()->rec_get("default", "set3.test.", &rec) && rec.settings == 3 && dbdir()->settings(3)->ext.allow_transfer_count == 1);
    }
    db_store_batch_end();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    _exit(g_failed ? 1 : 0);
}

static int proto_main(const char *self) {
    char dir[600];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/test_db_store_proto.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    int bad = 0;
    for (int phase = 0; phase < 6; phase++) {
        char cmd[900];
        snprintf(cmd, sizeof(cmd), "%s proto%d %s", self, phase, dir);
        if (system(cmd) != 0) bad++;
        if (phase == 0 || phase == 2 || phase == 3) {                    /* (phase 0 is the legacy loader on an empty store, phase 3 the fixes of the review, phase 4 the settings: the next phases start on a new store; phase 5 follows phase 4 on its store) */
            char rm[700];
            snprintf(rm, sizeof(rm), "rm -rf %s/s", dir);
            (void)!system(rm);
        }
    }
    char rm[700];
    snprintf(rm, sizeof(rm), "rm -rf %s", dir);
    (void)!system(rm);
    return bad ? 1 : 0;
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
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] == '3') return run_fixes(argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && (argv[1][5] == '4' || argv[1][5] == '5')) return run_settings(argv[1][5] - '0', argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] >= '0' && argv[1][5] <= '2') return run_proto(argv[1][5] - '0', argv[2]);
    if (argc > 1) return run_mode(strcmp(argv[1], "copy") == 0 ? "copy" : "map");
    if (lock_tests() != 0 || g_failed) { printf("%d checks, %d failed\n", g_checks, g_failed); return 1; }
    printf("lock file: %d checks\n", g_checks);
    /* the second mode is a second process: the ingest thread and the store are process wide */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s copy", argv[0]);
    int rc = system(cmd);
    int rc2 = run_mode("map");
    int rc3 = proto_main(argv[0]);
    return (rc != 0 || rc2 != 0 || rc3 != 0) ? 1 : 0;
}

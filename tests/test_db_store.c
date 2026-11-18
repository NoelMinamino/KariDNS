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
#include <signal.h>
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
#include <sys/wait.h>

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
#include "../dns_store_status.h"
#include "../dns_utils.h"
#include "../dns_xfr_state.h"
#include "../dns_xfr_store.h"
#include "../dns_zone_image.h"
#include "db/zimg_msgs.h"
#include "../dns_zone_image.h"

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)

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
/* the zone images of the zones of this test: SOA, NS (g_zone_ns, else ns1.<zone>; g_zone_ns2: a second one), www A (the address changes with the serial, so that two versions of a zone differ) */
static const char *g_zone_ns;                                          /* the NS target of the zones that zone_img() makes (NULL: ns1.<zone>) */
static const char *g_zone_ns2;                                         /* a second NS target (NULL: none): the zone has five records */
static zone_image_t *zone_img(const char *zone, uint32_t serial) { return zi_zone(zone, serial, g_zone_ns, g_zone_ns2, 0); }

static void send_zone(int fd, kdb_enc_t *e, const char *zone, uint32_t serial, uint64_t req, int64_t sid) {
    zone_image_t *img = zone_img(zone, serial);
    zi_zone_msgs(e, 0, zone, sid, serial, img, req, NULL, NULL, 0, (int)serial);
    zone_image_free(img);
    ch_send(fd, e);
}

/* a zone whose declared serial is not the one of its SOA (the install refuses it: "the SOA serial is not the one ZONE_BEGIN declared") */
static void send_bad_zone(int fd, kdb_enc_t *e, const char *zone, uint32_t serial, uint64_t req, int64_t sid) {
    zone_image_t *img = zone_img(zone, serial);
    zi_zone_msgs(e, 0, zone, sid, serial + 1000, img, req, NULL, NULL, 0, (int)serial);
    zone_image_free(img);
    ch_send(fd, e);
}

/* a zone of nA address records (SOA, NS, www, nA x A): one image, in ZONE_IMAGE messages of 64 KiB */
static void send_big_zone(int fd, kdb_enc_t *e, const char *zone, uint32_t serial, int64_t sid, int nA) {
    zone_image_t *img = zi_zone(zone, serial, NULL, NULL, nA);
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (int)serial, sizeof(dig));
    zi_begin(e, 0, zone, sid, serial, (int)serial, 0, 0, NULL, NULL, img->n_rrs, img->total_size);
    ch_send(fd, e);
    for (size_t off = 0; off < img->total_size; off += 65536) {
        zi_chunks(e, (const uint8_t *)img + off, img->total_size - off < 65536 ? img->total_size - off : 65536, 0);
        ch_send(fd, e);
    }
    zi_end(e, img->n_rrs);
    ch_send(fd, e);
    zone_image_free(img);
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
            if (park_key_is(k, "default", zone)) return true;
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 >= end) return false;
        usleep(1000);
    }
}

/* is the lookup of the name remembered as shed (the table of the shed names) at this moment? */
static int run_part(const char *cmd);
static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static bool shed_held_now(const char *name) {
    return park_shed_held(park_lookup_claim_key("default", name), mono_ms());
}

/* the counters of the lookups (store.lookup.*) */
static store_lookup_t lk_stats(void) {
    store_lookup_t k;
    (void)db_ingest_lookup_stats(&k);
    return k;
}
/* the places of fetch-concurrency in use: a lookup holds one from its request to the end of its answer (or of the fetch of the zone that came with it) */
static bool places_are(uint32_t n, int ms) {
    for (int i = 0; i < ms / 5 && park_places_used() != n; i++) usleep(5000);
    return park_places_used() == n;
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

/* wait until the bytes of the zones that were taken out of memory are given back.  The retire stack is processed here, as the control thread does it in the server: nobody else does in this test, and
 * the wait was whatever came by (25 ms for every call, 135 s in a run). */
static void wait_retired(void) {
    for (int i = 0; i < 5000; i++) {
        zone_retire_process(true);
        if (dbreg_evict_inflight() == 0) break;
        usleep(1000);
    }
}

/* The phases of this test run as processes of their own and end with _exit() (a child must not run the destructors of the parent's state).  A coverage build writes its counters at exit(): this
 * writes them first, so that what a phase reaches is counted (the symbols are there in a coverage build only: the instrumentation of `make coverage`, and gcov's). */
extern int __llvm_profile_write_file(void) __attribute__((weak));
extern void __gcov_dump(void) __attribute__((weak));
__attribute__((noreturn)) static void test_exit(int rc) {
    fflush(stdout);
    if (__llvm_profile_write_file) (void)__llvm_profile_write_file();
    if (__gcov_dump) __gcov_dump();
    _exit(rc);
}

/* the image of a version that a test made from a record of the store: given back with the version */
static void timg_free(void *p) {
    struct { store_t *st; store_img_t img; } *t = p;
    store_img_release(t->st, &t->img);
    free(t);
}

/* take the zone out of memory and wait until the registry's reference of its entry is gone (the garbage of the next delta is freed) */
/* versions_live once nothing more is retired: a version freed by an earlier step can leave after dbreg_evict_inflight() is 0 (its image is released at a later pass of the retire stack), so a
 * number read right after it may still fall; read it when three passes in a row leave it unchanged */
static uint64_t settled_versions(void) {
    db_store_counters_t c;
    uint64_t prev = UINT64_MAX;
    for (int i = 0, same = 0; i < 1000; i++) {
        zone_retire_process(true);
        db_store_counters(&c);
        if (c.versions_live == prev) {
            if (++same >= 3) break;
        } else {
            same = 0;
            prev = c.versions_live;
        }
        usleep(2000);
    }
    return c.versions_live;
}

static bool evict_zone(const char *zone) {
    if (!dbreg_test_evict("default", zone)) return false;
    wait_retired();
    return true;
}

static uint64_t resident_bytes(void) {
    zone_bytes_t zb;
    zone_bytes_get(ZBYTES_DB, &zb);
    return zb.resident;
}

static bool zref_of(const char *zone, zref_t *z);
/* the request a worker makes for a stored zone that is not in memory (dns_server_core.c park_ask()): the zone's id in the store, one claim for the zone */
static bool attach_request(const char *zone) {
    zref_t z;
    if (!zref_of(zone, &z) || z.zid == ZREF_NOZID || z.sview < 0) return park_attach_request_any("default", zone);       /* (the lookup does not know the zone, or could not read its cell: the request goes by name) */
    if (park_att_claim((uint16_t)z.sview, z.zid, 0) == 0) return true;      /* (the request of the claim is in a ring already) */
    if (!park_attach_zid(0, (uint16_t)z.sview, z.zid)) return false;
    park_att_requested((uint16_t)z.sview, z.zid);
    return true;
}

/* an attach as the worker asks for it: true when it woke the worker with the zone, false when the key says retry or failed */
static int attach_by_worker(const char *zone, park_key_t *k) {
    drain_wakes();
    if (!attach_request(zone)) return -1;
    if (!wake_for(zone, k, 5000)) return -2;
    return (k->failed || k->retry) ? 0 : 1;
}

static int g_hook_calls;
static bool g_hook_locked;
static void under_lock_hook(void *arg) {
    (void)arg;
    g_hook_calls++;
    if (pthread_mutex_trylock(&g_zone_db_rebuild_lock) == 0) {            /* (it must be held by this thread: a mutex that is not recursive is busy) */
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        g_hook_locked = false;
    }
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
static _Atomic int g_rd_pause_us;                          /* a reader that waits between its questions (0: none) */
static void *reader_thread(void *arg) {
    const char *name = arg;
    static _Thread_local worker_ctx_t wc;                                    /* (one for each reader: they are not shared) */
    static _Thread_local compress_ctx_t cc;
    memset(&wc, 0, sizeof(wc));
    uint8_t out[1232];
    while (!atomic_load(&g_rd_stop)) {
        const int pause_us = atomic_load(&g_rd_pause_us);
        if (pause_us) usleep((useconds_t)pause_us);
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
extern int g_notify_ipc[2];                                                  /* (dns_server_core.c: where the NOTIFY messages go to the Frontend; a test reads them) */
extern int g_notify_test_fail;                                               /* (dns_dynamic_update.c: the next this many NOTIFY messages cannot be made) */

/* the NOTIFY messages that the control thread put on the NOTIFY pair since the last call: the last octet of each IPv4 destination (192.0.2.x) in last[], at most max; returns how many there were */
static int nt_take(int *last, int max) {
    int n = 0;
    for (;;) {
        _Alignas(8) uint8_t buf[2048];
        ssize_t k = recv(g_notify_ipc[0], buf, sizeof(buf), MSG_DONTWAIT);
        if (k <= 0) break;
        const udp_ipc_t *m = (const udp_ipc_t *)buf;
        if (n < max) last[n] = m->client_addr.ss_family == AF_INET ? (int)(ntohl(m->client_addr.sin.sin_addr.s_addr) & 0xFF) : -1;
        n++;
    }
    return n;
}

#if defined(__SANITIZE_THREAD__)
#define UNDER_TSAN_TEST 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define UNDER_TSAN_TEST 1
#endif
#endif
#ifndef UNDER_TSAN_TEST
#define UNDER_TSAN_TEST 0
#endif

/* a store thread that is held before it registers a staged zone (W5b) */
static _Atomic bool g_adopt_hold;
static _Atomic int g_bh_arm;
static void batch_stale_hook(dbdir_rec_t *r) {
    if (atomic_exchange(&g_bh_arm, 0)) {
        r->seq += 2;                                                             /* (as if a version came after the record was read) */
        r->serial += 1;
    }
}
static void adopt_hold_hook(void) {
    for (int t = 0; t < 5000 && atomic_load(&g_adopt_hold); t++) usleep(1000);
}

/* 0.7 fix 7: a thread that attaches the zones as the worker does, as fast as they leave memory */
static _Atomic bool g_wa_stop;
static _Atomic uint64_t g_wa_done;
struct wa_arg { const dbdir_ops_t *ops; char (*names)[24]; };
static bool dbreg_test_evict_default(const char *zone) { return dbreg_test_evict("default", zone); }
/* The pages of a record that was just written are in the page cache only in part (a page that the writer has not filled is partly valid, and mincore() does not call it resident: the first touch
 * would read the rest from the disk).  A read of the image through the mapping makes them whole, as the first query of a zone does, and the worker's attach then finds the image resident. */
static void warm_zone(const char *zone) {
    zref_t zr;
    store_t *st = db_store_handle();
    if (!zref_of(zone, &zr) || zr.zid == ZREF_NOZID || !st) return;
    store_img_t im;
    store_read_lock();
    if (store_image_read(st, zr.zid, &im) == 0) {
        volatile uint8_t sink = 0;
        for (size_t i = 0; i < im.len; i += 64) sink ^= ((const uint8_t *)im.data)[i];
        (void)sink;
        store_img_release(st, &im);
    }
    store_read_unlock();
}
static void *wa_thread(void *p) {
    struct wa_arg *a = p;
    int i = 0;
    while (!atomic_load(&g_wa_stop)) {
        rcu_aux_read_lock();
        zone_db_snapshot_t *sn = acquire_zone_snapshot();
        view_snapshot_t *vs = snapshot_find_view(sn, "default");
        zref_t z;
        if (vs && zref_find_exact(vs, a->names[i % 6], &z) && !z.el && z.zid != ZREF_NOZID && z.zstate == ZREF_ST_ABSENT && a->ops->worker_attach(vs, &z, 0)) atomic_fetch_add(&g_wa_done, 1);
        rcu_aux_read_unlock();
        i++;
        if ((i & 63) == 0) usleep(100);
    }
    return NULL;
}

/* ---------------------------------------------------------------- 0.7 fix 7: queries through udp_one() (the worker's attach is part of what a worker does with a query) */
void udp_one(udp_pass_t *w, udp_ipc_t *ipc_msg, uint8_t *req_buf, ssize_t payload_received);
void park_service(udp_pass_t *w, int kq);
typedef struct {
    udp_pass_t w;
    park_table_t table;
    worker_ctx_t wctx;
    compress_ctx_t cc;
    int sk[2];
    int tag;
} wk_t;

static void wk_init(wk_t *k) {
    memset(k, 0, sizeof(*k));
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, k->sk) == 0);
    int buf = 1 << 20;
    setsockopt(k->sk[0], SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(k->sk[1], SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    fcntl(k->sk[1], F_SETFL, fcntl(k->sk[1], F_GETFL, 0) | O_NONBLOCK);
    CHECK(park_init(&k->table, 64));
    k->w.ctx = &k->wctx;
    k->w.batch = &k->wctx.batch;
    k->w.cc = &k->cc;
    k->w.active_fd = k->sk[0];
    k->w.park = &k->table;
    k->w.worker_idx = 0;
    k->w.park_timeout_ms = 5000;
    udp_batch_ctx_t *b = &k->wctx.batch;
    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        memset(&b->tx_msgs[i], 0, sizeof(b->tx_msgs[i]));
        b->tx_msgs[i].msg_hdr.msg_iov = &b->tx_iov[i];
        b->tx_msgs[i].msg_hdr.msg_iovlen = 1;
    }
}

static void wk_free(wk_t *k) {
    park_free(&k->table);
    close(k->sk[0]);
    close(k->sk[1]);
}

/* one query as the worker's UDP loop gets it; returns what udp_one() left: the answers in the batch (n_tx), the table (nwait) */
static void wk_send(wk_t *k, const char *name, uint16_t qtype) {
    udp_batch_ctx_t *b = &k->wctx.batch;
    uint8_t *rx = b->rx_buffers[0];
    size_t ql = build_q(rx + sizeof(udp_ipc_t), (uint16_t)(0x4000 + k->tag++), name, qtype);
    udp_ipc_t *ipc = (udp_ipc_t *)rx;
    memset(ipc, 0, sizeof(*ipc));
    ipc->sock_fd_idx = 7;
    ipc->addr_len = sizeof(struct sockaddr_in);
    ipc->payload_len = (uint16_t)ql;
    ipc->client_addr.sin.sin_family = AF_INET;
    ipc->client_addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipc->client_addr.sin.sin_port = htons(40000);
#if defined(__FreeBSD__) || defined(__APPLE__)
    ipc->client_addr.sin.sin_len = sizeof(struct sockaddr_in);
#endif
    k->w.n_tx = 0;
    rcu_aux_read_lock();                                          /* (this thread is not one of the registered workers: the writers wait for it as an auxiliary reader) */
    udp_one(&k->w, ipc, rx + sizeof(udp_ipc_t), (ssize_t)ql);
    rcu_aux_read_unlock();
}

/* the answer the worker sent (what the batch holds is sent first): the DNS message, its length; -1: nothing */
static int wk_get(wk_t *k, uint8_t *out) {
    udp_batch_ctx_t *b = &k->wctx.batch;
    for (int i = 0; i < k->w.n_tx; i++) send(k->sk[0], b->tx_buffers[i], b->tx_iov[i].iov_len, 0);
    k->w.n_tx = 0;
    uint8_t buf[UDP_IPC_BUFFER_SIZE];
    ssize_t n = recv(k->sk[1], buf, sizeof(buf), 0);
    if (n <= (ssize_t)sizeof(udp_ipc_t)) return -1;
    memcpy(out, buf + sizeof(udp_ipc_t), (size_t)n - sizeof(udp_ipc_t));
    return (int)(n - sizeof(udp_ipc_t));
}

/* a query that was parked: the store thread wakes the worker, the worker answers (up to ms) */
static bool wk_wait_answer(wk_t *k, uint8_t *out, int *len, int ms) {
    for (int t = 0; t < ms / 2; t++) {
        rcu_aux_read_lock();
        park_service(&k->w, -1);
        rcu_aux_read_unlock();
        *len = wk_get(k, out);
        if (*len > 0) return true;
        usleep(2000);
    }
    return false;
}

static const char *g_self = "";
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
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
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
    CHECK(attach_by_worker("a1.test.", &k) == 1 && park_key_is(&k, "default", "a1.test."));
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

    /* review L2: a request for a zone id that has no record (a deleted zone, a cell that cannot be read, an id of another view): the store thread has no name to wake by.  It tells the workers of the claim the id, so that the queries that wait for it ask for their zones themselves (they were left to run into their time) */
    {
        drain_wakes();
        const uint16_t sv = (uint16_t)store_view_id(st, "default");
        const uint32_t bogus = 0x00ABCDEFu;
        CHECK(park_att_claim(sv, bogus, 0) == 1 && park_attach_zid(0, sv, bogus));
        park_att_requested(sv, bogus);
        bool gotz = false;
        for (int t = 0; t < 5000 && !gotz; t++) {
            park_key_t kz;
            if (park_wake_pop(park_wake_ring(0), &kz)) gotz = kz.ask == 2 && kz.key == (((uint64_t)sv << 32) | bogus);
            else usleep(1000);
        }
        CHECK(gotz);
        CHECK(park_att_take(sv, bogus) == PARK_ATT_ALL);                       /* (the claim was taken with it) */
    }

    /* review L4: a query's request leaves the fill's share of the places free only while the fill has work (not in the pause after a failed round, not without a loader, not when its scan is over) */
    {
        extern bool db_ingest_test_qplace(bool bg_on, bool loader, uint32_t nbulk, int64_t retry_ms, uint32_t used, uint32_t conc);
        CHECK(!db_ingest_test_qplace(true, true, 0, 0, 7, 8));                   /* (8 places, the fill's share is 2: 7 used leave room for the fill only) */
        CHECK(!db_ingest_test_qplace(true, true, 0, 1, 7, 8));                   /* (a pause that is over) */
        CHECK(db_ingest_test_qplace(true, true, 0, INT64_MAX / 2, 7, 8));        /* (in the pause: the places are the queries') */
        CHECK(db_ingest_test_qplace(false, true, 0, 0, 7, 8));                   /* (the scan is over) */
        CHECK(db_ingest_test_qplace(true, false, 0, 0, 7, 8));                   /* (no loader) */
        CHECK(db_ingest_test_qplace(true, true, 2, 0, 7, 8));                    /* (the fill has its share in flight: those places are used already) */
        CHECK(!db_ingest_test_qplace(true, true, 0, 0, 8, 8) && !db_ingest_test_qplace(false, true, 0, 0, 8, 8));   /* (all places used: nobody) */
        {   /* the places the lookups may take (lk_share()): three quarters, but one place is always left to the fetches of zones (the share was all of the places at 1 to 3) */
            extern uint32_t db_ingest_test_lk_share(uint32_t conc);
            CHECK(db_ingest_test_lk_share(1) == 1 && db_ingest_test_lk_share(2) == 1 && db_ingest_test_lk_share(3) == 2 && db_ingest_test_lk_share(4) == 3 && db_ingest_test_lk_share(5) == 4);
            CHECK(db_ingest_test_lk_share(8) == 6 && db_ingest_test_lk_share(16) == 12 && db_ingest_test_lk_share(256) == 192);
            for (uint32_t c = 2; c <= 256; c++) CHECK(db_ingest_test_lk_share(c) < c);
        }
    }

    /* -- a fetch of the zone is on its way (LOADING): the attach that finds it busy gives the queries that wait the park-timeout (a retry key) */
    CHECK(evict_zone("a2.test."));
    CHECK(dbreg_fetch_begin("default", "a2.test.") == DBREG_FETCH_STARTED);            /* (the zone is out of memory, its record is stored) */
    drain_wakes();
    db_store_counters(&c0);
    CHECK(attach_request("a2.test.") && wake_for("a2.test.", &k, 5000) && k.retry && !k.failed);
    db_store_counters(&c1);
    CHECK(c1.attach_busy == c0.attach_busy + 1);
    dbreg_fetch_end("default", "a2.test.");
    CHECK(stored_only("a2.test."));                                          /* (the fetch that did not bring the zone leaves no element) */
    CHECK(attach_by_worker("a2.test.", &k) == 1);

    /* -- (M2 of the review of S5 + S6) the scrub finds the image of a zone that is attached damaged.  In MAP mode the zone serves the pages of the segment: it is taken out of memory, the record is KNOWN, and the zone is read from
     *    the database again (the answers are the ones it had).  In COPY mode the zone has a copy of its own and stays. */
    {
        const bool map = strcmp(mode, "copy") != 0;
        ans_t b5[NQ + 2], a5[NQ + 2];
        zref_t z5;
        CHECK(evict_zone("a5.test.") && attach_by_worker("a5.test.", &k) == 1);                  /* (attached from the store: its image is the store's) */
        CHECK(in_memory("a5.test.") && zref_of("a5.test.", &z5) && z5.entry);
        const zone_version_t *v5 = z5.entry ? atomic_load(&z5.entry->rcu.active) : NULL;
        CHECK(v5 && v5->image_free != NULL && v5->image_ref != NULL);
        answers_of("a5.test.", b5);
        CHECK(damage_record(sdir, "a5.test."));
        store_scrub_report_t srep;
        CHECK(store_scrub_run(st, &srep) == 0 && srep.bad_images >= 1);
        if (map) {
            for (int i = 0; i < 200 && in_memory("a5.test."); i++) usleep(25000);              /* (the tick asks again when the zone was busy) */
            CHECK(!in_memory("a5.test."));                                                       /* (before: it kept serving the damaged pages) */
            wait_retired();
            CHECK(zref_of("a5.test.", &z5) && z5.entry == NULL && z5.zid != ZREF_NOZID && z5.zstate == ZREF_ST_KNOWN);
            CHECK(dbdir()->rec_get("default", "a5.test.", &rec) && rec.state == STORE_STATE_KNOWN);
            CHECK(attach_by_worker("a5.test.", &k) == 0 && k.retry);                             /* (the next query reads it from the database) */
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "a5.test.") == 0);
            send_zone(f[0], &e, "a5.test.", 6, m.u.fetch_req.request_id, 105);
            CHECK(wake_for("a5.test.", &k, 5000) && !k.failed && !k.retry);
            CHECK(in_memory("a5.test."));
        } else {
            usleep(300000);
            CHECK(in_memory("a5.test."));
            batch_begin(a[0], &e, 19, KDB_BATCH_DIFF);                                         /* (the record is KNOWN: the loader sends the zone again, and it is stored) */
            send_zone(a[0], &e, "a5.test.", 6, 0, 105);
            batch_end(a[0], &e, &mainc, 19, 1, 0);
            CHECK(dbdir()->rec_get("default", "a5.test.", &rec) && rec.state == STORE_STATE_STORED);
        }
        answers_of("a5.test.", a5);
        CHECK(same_answers(b5, a5));
        CHECK(zone_bytes_underflows() == 0);
    }

    /* -- (0.7 store) only the workers that asked are woken: worker 0 parks a query and asks, worker 1 does not (its ring stays empty); a worker that joins the claim of the zone is woken with it */
    {
        park_register_worker(1, -1);
        park_key_t k1;
        while (park_wake_pop(park_wake_ring(1), &k1)) {}
        (void)evict_zone("a1.test.");
        CHECK(attach_by_worker("a1.test.", &k) == 1 && park_key_is(&k, "default", "a1.test."));
        CHECK(!park_wake_pop(park_wake_ring(1), &k1) && !park_wake_pending(park_wake_ring(1)));
        zref_t z;
        (void)evict_zone("a1.test.");
        CHECK(zref_of("a1.test.", &z) && z.zid != ZREF_NOZID);
        drain_wakes();
        CHECK(park_att_claim((uint16_t)z.sview, z.zid, 0) == 1 && park_att_claim((uint16_t)z.sview, z.zid, 1) == 2);        /* (worker 1 joined before the request was made: it asks too) */
        CHECK(park_attach_zid(0, (uint16_t)z.sview, z.zid));
        park_att_requested((uint16_t)z.sview, z.zid);
        CHECK(wake_for("a1.test.", &k, 5000));
        for (int i = 0; i < 2000 && !park_wake_pending(park_wake_ring(1)); i++) usleep(1000);
        CHECK(park_wake_pop(park_wake_ring(1), &k1) && park_key_is(&k1, "default", "a1.test.") && !k1.failed && !k1.retry);
        CHECK(in_memory("a1.test."));
        park_unregister_worker(1);
    }

    /* -- (B1) a zone id that another zone has now: the claim was made for a zone that waited (a worker's query for "gone.test." parked for the attach of the id), the id is the record of "b1.test." when the store thread
     *    looks: the workers of the claim are woken by the name of the zone that is attached, and then told the id, so that the query for the zone that is gone asks for its own fetch (it was left to run to its park-timeout) */
    {
        zref_t zb;
        (void)evict_zone("a1.test.");
        CHECK(zref_of("a1.test.", &zb) && zb.zid != ZREF_NOZID);
        drain_wakes();
        const uint16_t sv = (uint16_t)zb.sview;
        CHECK(park_att_claim_tag(sv, zb.zid, 0, park_name_key("default", "gone.test.")) == 1 && park_attach_zid(0, sv, zb.zid));
        park_att_requested(sv, zb.zid);
        bool named = false, byid = false;
        for (int t = 0; t < 5000 && !byid; t++) {
            park_key_t kz;
            if (park_wake_pop(park_wake_ring(0), &kz)) {
                if (kz.ask == 0 && park_key_is(&kz, "default", "a1.test.")) named = true;
                else if (kz.ask == 2 && kz.key == (((uint64_t)sv << 32) | zb.zid)) byid = named;      /* (after the wake by name: the order of the ring) */
            } else {
                usleep(1000);
            }
        }
        CHECK(named && byid);
        CHECK(in_memory("a1.test."));
        /* the same claim made for the zone itself: no wake by the id (nothing was left behind) */
        (void)evict_zone("a1.test.");
        drain_wakes();
        CHECK(park_att_claim_tag(sv, zb.zid, 0, park_name_key("default", "a1.test.")) == 1 && park_attach_zid(0, sv, zb.zid));
        park_att_requested(sv, zb.zid);
        CHECK(wake_for("a1.test.", &k, 5000));
        usleep(50000);
        park_key_t kz2;
        bool idwake = false;
        while (park_wake_pop(park_wake_ring(0), &kz2)) idwake |= kz2.ask == 2;
        CHECK(!idwake);
        CHECK(in_memory("a1.test."));
    }

    /* -- the attach is one section of the registry's lock: what it finds at the commit is told apart (dbreg_attach_store(): resident, a fetch on its way, a record that is not the one that was read) */
    {
        dbdir_rec_t rec;
        CHECK(evict_zone("a1.test."));
        CHECK(dbdir()->rec_get("default", "a1.test.", &rec) && rec.state == STORE_STATE_STORED);
        CHECK(dbreg_fetch_begin("default", "a1.test.") == DBREG_FETCH_STARTED);
        zone_db_entry_t *ent = db_ingest_new_entry("default", "a1.test.", NULL);
        CHECK(ent != NULL && dbreg_attach_store("default", "a1.test.", &rec, ent, false, NULL, NULL) == DBREG_ATT_BUSY);       /* (a fetch has the zone) */
        /* the hook that dbreg_attach_store() calls under the registry's lock, once, whatever the outcome (the worker's staged element leaves its table in it: a later removal let a worker find an entry that an eviction retired) */
        g_hook_calls = 0;
        g_hook_locked = true;
        CHECK(dbreg_attach_store("default", "a1.test.", &rec, ent, false, under_lock_hook, NULL) == DBREG_ATT_BUSY && g_hook_calls == 1 && g_hook_locked);
        dbreg_fetch_end("default", "a1.test.");
        rec.serial += 1;
        rec.seq += 2;                                                                                                          /* (0.7 M4: the registry asks the store whether the record is as it was read, by its sequence word: a newer version has another one) */
        g_hook_calls = 0;
        CHECK(dbreg_attach_store("default", "a1.test.", &rec, ent, false, NULL, NULL) == DBREG_ATT_STALE);                      /* (the record is another version than the one that was read) */
        CHECK(dbreg_attach_store("default", "a1.test.", &rec, ent, false, under_lock_hook, NULL) == DBREG_ATT_STALE && g_hook_calls == 1 && g_hook_locked);
        free_zone_db_entry(ent);
        CHECK(attach_by_worker("a1.test.", &k) == 1);
        CHECK(dbdir()->rec_get("default", "a1.test.", &rec));
        ent = db_ingest_new_entry("default", "a1.test.", NULL);
        CHECK(ent != NULL && dbreg_attach_store("default", "a1.test.", &rec, ent, false, NULL, NULL) == DBREG_ATT_RESIDENT);   /* (in memory already) */
        CHECK(dbreg_attach_store("default", "a1.test.", &rec, ent, false, under_lock_hook, NULL) == DBREG_ATT_RESIDENT && g_hook_calls == 2 && g_hook_locked);
        free_zone_db_entry(ent);
    }

    /* -- 0.7 M4: dbreg_attach_store_n(): up to DBREG_ATT_BATCH attaches in one section of the lock, each judged as dbreg_attach_store() judges it.  The record that the store read has a sequence word; the
     * registry asks the store whether it is unchanged (one word), where it used to read the record again by name.  (The entries that it takes are tested through the hot list below: they need an image.) */
    {
        const char *nm[5] = { "a2.test.", "a4.test.", "a1.test.", "a5.test.", "a2.test." };
        dbdir_rec_t rcs[5];
        zone_db_entry_t *en[5];
        dbreg_att_item_t it[5];
        const bool a2_was = in_memory("a2.test."), a4_was = in_memory("a4.test."), a5_was = in_memory("a5.test.");
        (void)evict_zone("a2.test."); (void)evict_zone("a4.test."); (void)evict_zone("a5.test.");                       /* (the ones that are in memory leave it) */
        CHECK(!in_memory("a2.test.") && !in_memory("a4.test.") && !in_memory("a5.test.") && in_memory("a1.test."));
        for (int i = 0; i < 4; i++) {
            CHECK(dbdir()->rec_get("default", nm[i], &rcs[i]) && rcs[i].seq_set);
            en[i] = db_ingest_new_entry("default", nm[i], NULL);
            CHECK(en[i] != NULL);
        }
        CHECK(dbdir()->rec_unchanged(&rcs[0]));                                       /* (as it was read) */
        rcs[0].seq += 2; rcs[0].serial += 1;   /* a2: a version came after the record was read (the word moves, and the record is not the same version: the word alone is no reason, see W5d) */
        CHECK(!dbdir()->rec_unchanged(&rcs[0]));
        CHECK(dbreg_fetch_begin("default", "a4.test.") == DBREG_FETCH_STARTED);       /* a4: a fetch is on its way */
        rcs[3].seq_set = false;                                                       /* a5: a record that carries no sequence word is looked at again by name: another version */
        rcs[3].serial += 1;
        rcs[4] = rcs[0];
        en[4] = NULL;                                                                /* (not an entry of a store zone) */
        for (int i = 0; i < 5; i++) {
            it[i].view = "default";
            it[i].name = nm[i];
            it[i].rec = &rcs[i];
            it[i].entry = en[i];
            it[i].bg = false;
            it[i].result = -99;
        }
        dbreg_attach_store_n(it, 5);
        CHECK(it[0].result == DBREG_ATT_STALE && it[1].result == DBREG_ATT_BUSY && it[2].result == DBREG_ATT_RESIDENT && it[3].result == DBREG_ATT_STALE && it[4].result == DBREG_ATT_NOT);
        dbreg_fetch_end("default", "a4.test.");
        for (int i = 0; i < 4; i++) free_zone_db_entry(en[i]);                       /* (none of them was taken) */
        CHECK(!in_memory("a2.test.") && !in_memory("a4.test.") && !in_memory("a5.test."));
        dbreg_attach_store_n(it, 0);                                                 /* (nothing to do) */
        {
            /* more items than a batch: the registry takes DBREG_ATT_BATCH of them, and says NOT for the rest (the caller keeps their entries) */
            enum { BIG = DBREG_ATT_BATCH + 8 };
            static dbdir_rec_t rb;
            static zone_db_entry_t *eb[BIG];
            static dbreg_att_item_t ib[BIG];
            CHECK(in_memory("a1.test.") && dbdir()->rec_get("default", "a1.test.", &rb));
            for (int i = 0; i < BIG; i++) {
                eb[i] = db_ingest_new_entry("default", "a1.test.", NULL);
                ib[i].view = "default";
                ib[i].name = "a1.test.";
                ib[i].rec = &rb;
                ib[i].entry = eb[i];
                ib[i].bg = false;
                ib[i].result = -99;
            }
            dbreg_attach_store_n(ib, BIG);
            bool ok = true;
            for (int i = 0; i < BIG; i++) ok = ok && ib[i].result == (i < DBREG_ATT_BATCH ? DBREG_ATT_RESIDENT : DBREG_ATT_NOT);
            CHECK(ok);
            for (int i = 0; i < BIG; i++) free_zone_db_entry(eb[i]);
        }
        CHECK(dbdir()->attach_count() > 0);
        if (a2_was) CHECK(attach_by_worker("a2.test.", &k) == 1);                          /* (as it was) */
        if (a4_was) CHECK(attach_by_worker("a4.test.", &k) == 1);
        if (a5_was) CHECK(attach_by_worker("a5.test.", &k) == 1);
        {
            /* a batched job whose record changed (a version) between the read and the registration: the registry says STALE for it, and the store thread reads the record again and attaches the zone */
            CHECK(evict_zone("a2.test.") && !in_memory("a2.test."));
            db_store_counters_t cs0, cs1;
            db_store_counters(&cs0);
            atomic_store(&g_bh_arm, 1);
            db_store_test_batch_hook = batch_stale_hook;
            CHECK(attach_by_worker("a2.test.", &k) == 1);
            db_store_test_batch_hook = NULL;
            db_store_counters(&cs1);
            CHECK(atomic_load(&g_bh_arm) == 0);                                      /* (the hook changed the record of the job) */
            CHECK(in_memory("a2.test.") && cs1.attach_ok == cs0.attach_ok + 1);     /* (attached by the second try, counted once) */
        }
    }

    /* -- the commit of an attach is conditional: a delete that comes after the record was read wins, nothing is made */
    CHECK(evict_zone("a0.test."));
    {
        dbdir_rec_t rec;
        CHECK(dbdir()->rec_get("default", "a0.test.", &rec) && rec.state == STORE_STATE_STORED && rec.serial == 1 && rec.source_id == 100);
        CHECK(dbreg_delete("default", "a0.test.", 100) == 1);
        zone_db_entry_t *ent = db_ingest_new_entry("default", "a0.test.", NULL);
        CHECK(ent != NULL);
        CHECK(dbreg_attach_store("default", "a0.test.", &rec, ent, false, NULL, NULL) == DBREG_ATT_STALE);       /* (the registry looks at the record again, inside its lock: it is gone) */
        free_zone_db_entry(ent);
        CHECK(!in_memory("a0.test."));
        zref_t z;
        CHECK(!zref_of("a0.test.", &z));                                     /* (deleted from the store too) */
        batch_begin(a[0], &e, 20, KDB_BATCH_DIFF);                           /* (and the loader may send it again) */
        send_zone(a[0], &e, "a0.test.", 1, 0, 100);
        batch_end(a[0], &e, &mainc, 20, 1, 0);
        CHECK(in_memory("a0.test."));
        /* a new entry for a zone that is in memory already (an install that was built before an attach made the zone resident, a SLAVE that becomes a primary) replaces the old one: the commit retires the
         * old entry for the readers that may hold it, and gives it back after the grace period.  The entry is made as an attach makes it, from the image of the record. */
        {
            typedef struct { store_t *st; store_img_t img; } timg_t;
            dbdir_rec_t rr;
            CHECK(dbdir()->rec_get("default", "a0.test.", &rr) && rr.state == STORE_STATE_STORED);
            timg_t *ti = calloc(1, sizeof(*ti));
            ti->st = st;
            store_read_lock();
            CHECK(store_image_read(st, rr.zid, &ti->img) == 0);
            store_read_unlock();
            zone_db_entry_t *ne = db_ingest_new_entry("default", "a0.test.", NULL);
            zone_version_t *nv = ti->img.data ? zone_version_new_ext((zone_image_t *)(uintptr_t)ti->img.data, ti->img.len, timg_free, ti) : NULL;
            CHECK(ne != NULL && nv != NULL);
            if (ne && nv) {
                atomic_store_explicit(&ne->serial, rr.serial, memory_order_relaxed);
                zone_install_version(ne, nv, NULL, false);
                bool shd = false;
                zone_db_entry_t *old = dbreg_lookup_entry("default", "a0.test.");
                CHECK(old != NULL && old != ne && dbreg_commit("default", "a0.test.", ne, true, rr.source_id, rr.serial, rr.digest, &shd) == 0);
                wait_retired();
                CHECK(dbreg_lookup_entry("default", "a0.test.") == ne && zone_bytes_underflows() == 0);
            }
        }
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
            cat_entry.view_name = "default";
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
        for (int w = 0; w < 500; w++) {                                     /* (the install runs on a builder thread: the limit stays until the zone is in the store, or a slow host installs it after the limit is gone) */
            if (dbdir()->rec_get("default", "cold1.test.", &rec) && rec.state == STORE_STATE_STORED && dbreg_lookup_entry("default", "cold1.test.") == NULL) break;
            usleep(10000);
        }
        dbreg_cache_set_limit(0);
        dbreg_cache_test_pause(false);
        CHECK(stored_only("cold1.test."));
        CHECK(dbdir()->rec_get("default", "cold1.test.", &rec) && rec.state == STORE_STATE_STORED && rec.serial == 1);
        CHECK(attach_by_worker("cold1.test.", &k) == 1 && in_memory("cold1.test."));
    }

    /* -- settings: the interned text is kept by id; a zone that is not in memory is answered (allow-query) from them, and the id is what its record names */
    {
        static const char stext[] = "allow-transfer { 127.0.0.1; };";
        batch_begin(a[0], &e, 26, KDB_BATCH_DIFF);
        zone_image_t *simg = zone_img("set1.test.", 1);
        zi_zone_msgs(&e, 0, "set1.test.", 180, 1, simg, 0, stext, NULL, 0, 9);
        zone_image_free(simg);
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
        wait_retired();
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
                    (void)attach_request("a6.test.");
                }
                usleep(1000);
            }
            if (in_memory("a6.test.")) cycles++;
            wait_retired();
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
    wait_retired();
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
        /* -- the timing of the NOTIFY of a zone whose two name servers are in two zones of the store that come into memory one after the other (a slow attach, made exact: the hook only records the request and the test attaches
         *    when it wants).  What is known is sent at once; the zone that is missing is waited for, and the next look sends to the missing address only; a look that finds nothing new sends nothing; a request that nobody popped
         *    (another change) notifies everybody again; the wait is bounded, and the NOTIFY that is sent when it ends does not repeat the ones that are done. */
        {
            const int ipc0 = g_notify_ipc[0], ipc1 = g_notify_ipc[1];
            CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) == 0);
            int dst[8], nd;
            char wv[64], wz[256];
            int tries = 0;
            g_nsa_n = 0;
            batch_begin(a[0], &e, 46, KDB_BATCH_DIFF);
            send_zone(a[0], &e, "s5a.test.", 1, 0, 320);                      /* www.s5a.test. = 192.0.2.81 */
            send_zone(a[0], &e, "s5b.test.", 2, 0, 321);                      /* www.s5b.test. = 192.0.2.82 */
            g_zone_ns = "www.s5a.test.";
            g_zone_ns2 = "www.s5b.test.";
            send_zone(a[0], &e, "n5.test.", 1, 0, 322);
            g_zone_ns = g_zone_ns2 = NULL;
            batch_end(a[0], &e, &mainc, 46, 3, 0);
            CHECK(in_memory("n5.test."));
            CHECK(evict_zone("s5a.test.") && evict_zone("s5b.test.") && stored_only("s5a.test.") && stored_only("s5b.test."));
            (void)nt_take(dst, 8);
            zone_db_snapshot_t *sn = acquire_retained_zone_snapshot();
            bool held = false;
            zone_db_entry_t *ne = dbreg_ctl_entry(sn, "default", "n5.test.", &held);
            CHECK(ne != NULL);
            if (ne) {
                /* neither address is known: nothing is sent, both zones are asked for, the NOTIFY waits */
                send_notify_to_all(ne);
                CHECK(nt_take(dst, 8) == 0 && g_nsa_n == 2 && stored_only("s5a.test.") && stored_only("s5b.test."));
                CHECK(notify_wait_count(false) == 1 && notify_wait_done("default", "n5.test.", &tries) == 0 && tries == 1);
                /* s5a comes into memory (s5b is still on its way): the look sends to 192.0.2.81 only, and waits for the other */
                CHECK(attach_by_worker("s5a.test.", &k) == 1);
                (void)notify_wait_count(true);
                CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
                notify_zone_by_name(wv, wz);
                nd = nt_take(dst, 8);
                CHECK(nd == 1 && dst[0] == 81);
                CHECK(notify_wait_count(false) == 1 && notify_wait_done("default", "n5.test.", &tries) == 1 && tries == 2);
                /* a look that finds nothing new (the attach is slow): nothing is sent, the one that is done is not sent again */
                (void)notify_wait_count(true);
                CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
                notify_zone_by_name(wv, wz);
                CHECK(nt_take(dst, 8) == 0 && notify_wait_count(false) == 1 && notify_wait_done("default", "n5.test.", &tries) == 1 && tries == 3);
                /* s5b comes into memory: the next look sends to 192.0.2.82 only and the wait is over */
                CHECK(attach_by_worker("s5b.test.", &k) == 1);
                (void)notify_wait_count(true);
                CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
                notify_zone_by_name(wv, wz);
                nd = nt_take(dst, 8);
                CHECK(nd == 1 && dst[0] == 82 && notify_wait_count(false) == 0);
                /* a request that nobody popped (the zone changed again, karictl notify) is a round of its own: both addresses */
                send_notify_to_all(ne);
                nd = nt_take(dst, 8);
                CHECK(nd == 2 && ((dst[0] == 81 && dst[1] == 82) || (dst[0] == 82 && dst[1] == 81)) && notify_wait_count(false) == 0);

                /* s5b goes out of memory again: 192.0.2.81 now, the wait for the other; a fresh request in the middle of the wait starts the round again (81 again, the tries from one) */
                CHECK(evict_zone("s5b.test.") && stored_only("s5b.test."));
                send_notify_to_all(ne);
                nd = nt_take(dst, 8);
                CHECK(nd == 1 && dst[0] == 81 && notify_wait_count(false) == 1);
                for (int i = 0; i < 2; i++) {
                    (void)notify_wait_count(true);
                    CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
                    notify_zone_by_name(wv, wz);
                }
                CHECK(nt_take(dst, 8) == 0 && notify_wait_done("default", "n5.test.", &tries) == 1 && tries == 3);
                send_notify_to_all(ne);
                nd = nt_take(dst, 8);
                CHECK(nd == 1 && dst[0] == 81 && notify_wait_done("default", "n5.test.", &tries) == 1 && tries == 1);

                /* the zone never comes: a bounded number of looks (the first look made one try, 12 more looks use the rest: 12 tries), none of them repeats 192.0.2.81, and the wait ends */
                int looks = 0, again = 0;
                while (notify_wait_count(false) > 0 && looks < 40) {
                    (void)notify_wait_count(true);
                    if (!notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz))) break;
                    notify_zone_by_name(wv, wz);
                    again += nt_take(dst, 8);
                    looks++;
                }
                CHECK(notify_wait_count(false) == 0 && looks == 12 && again == 0);
                CHECK(notify_wait_done("default", "n5.test.", &tries) == -1);
                CHECK(attach_by_worker("s5b.test.", &k) == 1);
                send_notify_to_all(ne);                                           /* (the next change of the zone: both again, nothing waits) */
                CHECK(nt_take(dst, 8) == 2 && notify_wait_count(false) == 0);
            }
            if (ne && held) xfr_entry_release(ne);
            release_zone_snapshot(sn);
            close(g_notify_ipc[0]);
            close(g_notify_ipc[1]);
            g_notify_ipc[0] = ipc0;
            g_notify_ipc[1] = ipc1;
        }
        /* -- (L5 of the review of S5 + S6) a NOTIFY that cannot be made (the key does not fit, no memory) is not done: the next look of the round sends it (before: it was marked done before it was sent, and never sent) */
        {
            const int ipc0 = g_notify_ipc[0], ipc1 = g_notify_ipc[1];
            CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) == 0);
            int dst[8], nd;
            char wv[64], wz[256];
            int tries = 0;
            g_nsa_n = 0;
            batch_begin(a[0], &e, 47, KDB_BATCH_DIFF);
            send_zone(a[0], &e, "s6a.test.", 1, 0, 330);                      /* www.s6a.test. = 192.0.2.81 */
            send_zone(a[0], &e, "s6b.test.", 2, 0, 331);                      /* www.s6b.test. = 192.0.2.82 */
            g_zone_ns = "www.s6a.test.";
            g_zone_ns2 = "www.s6b.test.";
            send_zone(a[0], &e, "n6.test.", 1, 0, 332);
            g_zone_ns = g_zone_ns2 = NULL;
            batch_end(a[0], &e, &mainc, 47, 3, 0);
            CHECK(in_memory("n6.test."));
            CHECK(evict_zone("s6a.test.") && evict_zone("s6b.test.") && stored_only("s6a.test.") && stored_only("s6b.test."));
            (void)nt_take(dst, 8);
            zone_db_snapshot_t *sn = acquire_retained_zone_snapshot();
            bool held = false;
            zone_db_entry_t *ne = dbreg_ctl_entry(sn, "default", "n6.test.", &held);
            CHECK(ne != NULL);
            if (ne) {
                send_notify_to_all(ne);                                       /* (neither address is known: the NOTIFY waits) */
                CHECK(nt_take(dst, 8) == 0 && notify_wait_count(false) == 1);
                CHECK(attach_by_worker("s6a.test.", &k) == 1);
                g_notify_test_fail = 1;                                       /* (the NOTIFY to 192.0.2.81 cannot be made) */
                (void)notify_wait_count(true);
                CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
                notify_zone_by_name(wv, wz);
                CHECK(g_notify_test_fail == 0 && nt_take(dst, 8) == 0);
                CHECK(notify_wait_count(false) == 1 && notify_wait_done("default", "n6.test.", &tries) == 0);          /* (not done) */
                (void)notify_wait_count(true);
                CHECK(notify_wait_pop(wv, sizeof(wv), wz, sizeof(wz)));
                notify_zone_by_name(wv, wz);                                  /* (the next look sends it) */
                nd = nt_take(dst, 8);
                CHECK(nd == 1 && dst[0] == 81 && notify_wait_done("default", "n6.test.", &tries) == 1);
                notify_wait_drop("default", "n6.test.");
                CHECK(notify_wait_count(false) == 0);
            }
            g_notify_test_fail = 0;
            if (ne && held) xfr_entry_release(ne);
            release_zone_snapshot(sn);
            close(g_notify_ipc[0]);
            close(g_notify_ipc[1]);
            g_notify_ipc[0] = ipc0;
            g_notify_ipc[1] = ipc1;
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
        /* the walk of the glue (the control thread used to make it, the glue thread does now) is the same walk: a table made again in the middle of it starts it again, and what it had collected is given back */
        g_walk_ud.calls = 0;
        g_walk_ud.grown = g_walk_ud.grew = false;
        g_attach_walk_between = walk_grow_hook;
        zone_glue_refresh_dependents(true);
        g_attach_walk_between = NULL;
        CHECK(g_walk_ud.grown);
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
        store_t *zs = db_store_handle();                                      /* (the tables are private memory since 0.7: the cell is changed there, not in zc.1) */
        const uint64_t cell = (uint64_t)rr.zid * 64 + 56, w7 = store_test_peek(zs, 1, cell) & 0xffffffffull;
        store_test_poke(zs, 1, cell, w7 | (1ull << 32));                     /* (the sequence counter of the cell: odd while a writer is in it) */
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
        store_test_poke(zs, 1, cell, w7);
        int64_t zsid;
        uint32_t zsr;
        CHECK(dbreg_zone_version("default", "r6b.test.", &zsid, &zsr) && zsid == 306);
    }

    /* -- W. 0.7 fix 7: the worker attaches a zone whose image is in the page cache, and answers at once.  MAP mode: no wait, no store thread in the answer, the registration follows;
     *    COPY mode (and an image that is not in the page cache): the query parks and a store thread attaches, as before. */
    {
        const bool map = strcmp(mode, "map") == 0;
        static wk_t wk;
        atomic_store(&db_store_test_resident, map);                /* (mincore() reports the pages that were written through a file descriptor as resident only on some file systems: UFS yes, ZFS no; the test is of the worker's attach, not of the file system) */
        const dbdir_ops_t *ops = dbdir();
        enum { NWQ = 8 };
        batch_begin(a[0], &e, 89, KDB_BATCH_DIFF);
        for (int i = 0; i < NWQ; i++) {
            char wn[24];
            snprintf(wn, sizeof(wn), "wq%d.test.", i);
            send_zone(a[0], &e, wn, (uint32_t)(i + 1), 0, 7000 + i);
        }
        batch_end(a[0], &e, &mainc, 89, NWQ, 0);
        for (int i = 0; i < NWQ; i++) {
            char wn[24];
            snprintf(wn, sizeof(wn), "wq%d.test.", i);
            warm_zone(wn);
        }
        wk_init(&wk);
        db_store_counters_t w0, w1;
        uint8_t ref[1232], got[1232];
        int rlen = 0, glen = 0;
        CHECK(in_memory("wq3.test."));
        wk_send(&wk, "wq3.test.", 6);
        rlen = wk_get(&wk, ref);
        CHECK(rlen > 12 && (ref[3] & 0x0F) == 0 && wk.table.nwait == 0);              /* (the answer of a zone in memory) */

        /* W1: a stored zone, nothing else in the way */
        CHECK(evict_zone("wq3.test.") && stored_only("wq3.test."));
        drain_wakes();
        db_store_counters(&w0);
        wk_send(&wk, "wq3.test.", 6);
        if (map) {
            glen = wk_get(&wk, got);
            CHECK(wk.table.nwait == 0 && glen == rlen && memcmp(got + 2, ref + 2, (size_t)rlen - 2) == 0);          /* (answered by the worker that looked: nothing parked, the same bytes) */
            { db_store_counters_t d; db_store_counters(&d); printf("  W1: ok %llu cold %llu over %llu claim %llu fail %llu decline %llu full %llu\n", (unsigned long long)d.wa_ok, (unsigned long long)d.wa_cold, (unsigned long long)d.wa_over, (unsigned long long)d.wa_claim, (unsigned long long)d.wa_fail, (unsigned long long)d.wa_decline, (unsigned long long)d.wa_full); }
            db_store_counters(&w1);
            CHECK(w1.wa_ok == w0.wa_ok + 1 && w1.wa_cold == w0.wa_cold && w1.wa_fail == w0.wa_fail);
            CHECK(in_memory("wq3.test."));                                              /* (staged, or registered already) */
            zref_t z;
            CHECK(zref_of("wq3.test.", &z) && z.entry && z.el && zdir_serial(z.el) == 4);
            bool reg = false;
            for (int t = 0; t < 2500 && !reg; t++) {                                   /* (a store thread registers it: the registry has the zone, the attach table has the element) */
                reg = zref_of("wq3.test.", &z) && z.el && dbreg_lookup_entry("default", "wq3.test.") == z.entry && dbdir()->attach_get(z.zid) == z.el;
                if (!reg) usleep(2000);
            }
            CHECK(reg);
            db_store_counters(&w1);
            CHECK(w1.wa_adopted == w0.wa_adopted + 1 && w1.attach_ok == w0.attach_ok + 1 && w1.wa_lost == w0.wa_lost);
            CHECK(!ch_next(&fetchc, &m, 100));                                         /* (the loader was not asked) */
            CHECK(park_att_claim(0, z.zid, 5) == 1 && park_att_leave(0, z.zid, 5));   /* (the claim of the zone was taken: it is free) */
            wk_send(&wk, "wq3.test.", 6);
            CHECK(wk_get(&wk, got) == rlen && memcmp(got + 2, ref + 2, (size_t)rlen - 2) == 0 && wk.table.nwait == 0);       /* (and the registered zone answers the same) */
        } else {
            CHECK(wk.w.n_tx == 0 && wk.table.nwait == 1);                              /* (COPY: the query parks, a store thread attaches) */
            CHECK(wk_wait_answer(&wk, got, &glen, 5000) && glen == rlen && memcmp(got + 2, ref + 2, (size_t)rlen - 2) == 0);
            db_store_counters(&w1);
            CHECK(w1.wa_ok == w0.wa_ok && w1.wa_cold == w0.wa_cold && w1.attach_ok == w0.attach_ok + 1);        /* (no worker attach was tried: the mode has no page cache to ask) */
        }

        if (map) {
            /* W2: the image is not in the page cache: nothing is done on the worker, the query parks and a store thread attaches */
            CHECK(evict_zone("wq4.test.") && stored_only("wq4.test."));
            drain_wakes();
            db_store_counters(&w0);
            atomic_store(&db_store_test_not_resident, true);
            wk_send(&wk, "wq4.test.", 6);
            atomic_store(&db_store_test_not_resident, false);
            CHECK(wk.w.n_tx == 0 && wk.table.nwait == 1);
            CHECK(wk_wait_answer(&wk, got, &glen, 5000) && (got[3] & 0x0F) == 0);
            db_store_counters(&w1);
            CHECK(w1.wa_cold == w0.wa_cold + 1 && w1.wa_ok == w0.wa_ok && w1.attach_ok == w0.attach_ok + 1);

            /* W3: another worker has the zone's claim: this worker joins it and parks (it does not attach beside it) */
            CHECK(evict_zone("wq5.test.") && stored_only("wq5.test."));
            drain_wakes();
            zref_t z5;
            CHECK(zref_of("wq5.test.", &z5) && z5.zid != ZREF_NOZID);
            db_store_counters(&w0);
            CHECK(park_att_claim((uint16_t)z5.sview, z5.zid, 3) == 1);
            wk_send(&wk, "wq5.test.", 6);
            CHECK(wk.w.n_tx == 0 && wk.table.nwait == 1);
            db_store_counters(&w1);
            CHECK(w1.wa_claim == w0.wa_claim + 1);
            CHECK(wk_wait_answer(&wk, got, &glen, 5000) && (got[3] & 0x0F) == 0);     /* (the worker's own request for the zone: a store thread did it) */

            /* W4: the staging table refuses (full): the zone is not attached by the worker and the entry that was made is given back */
            CHECK(evict_zone("wq6.test."));
            drain_wakes();
            db_store_counters(&w0);
            db_store_test_stg_fail = 1;
            wk_send(&wk, "wq6.test.", 6);
            CHECK(wk.w.n_tx == 0 && wk.table.nwait == 1);
            db_store_counters(&w1);
            CHECK(w1.wa_full == w0.wa_full + 1 && w1.wa_ok == w0.wa_ok);
            CHECK(wk_wait_answer(&wk, got, &glen, 5000) && (got[3] & 0x0F) == 0);
            /* (nothing is left of the worker's entry: the store thread that was asked attached the zone meanwhile, and its version is the only one more; read before the answer the count raced with that attach) */
            db_store_counters(&w1);
            CHECK(w1.wa_ok == w0.wa_ok && w1.versions_live == w0.versions_live + 1);
            zref_t z6;
            CHECK(zref_of("wq6.test.", &z6) && z6.zid != ZREF_NOZID && park_att_claim((uint16_t)z6.sview, z6.zid, 6) == 1 && park_att_leave((uint16_t)z6.sview, z6.zid, 6));   /* (the claim was left) */

            /* W5: the worker attach as the lookup would make it (a direct call): staged, then registered or dropped by a store thread */
            CHECK(evict_zone("wq7.test."));
            drain_wakes();
            db_store_counters(&w0);
            zref_t z7;
            CHECK(zref_of("wq7.test.", &z7) && z7.zid != ZREF_NOZID);
            rcu_aux_read_lock();
            zone_db_snapshot_t *snw = acquire_zone_snapshot();
            view_snapshot_t *vsw = snapshot_find_view(snw, "default");
            CHECK(vsw != NULL);
            bool wa = vsw && ops->worker_attach(vsw, &z7, 0);
            rcu_aux_read_unlock();
            CHECK(wa);                                                                   /* (staged: answers from the worker's entry) */
            db_store_counters(&w1);
            CHECK(w1.wa_ok == w0.wa_ok + 1);
            for (int t = 0; t < 2500 && w1.wa_adopted == w0.wa_adopted; t++) {
                usleep(2000);
                db_store_counters(&w1);
            }
            CHECK(w1.wa_adopted + w1.wa_lost == w0.wa_adopted + w0.wa_lost + 1);

            /* W5b: the zone is deleted from the store between the staging and the registration (a store thread is held): the registration finds no record, the staged zone and its entry go, and
             *      nothing is left of them (a worker's answer from the staged entry was the version the record had) */
            {
                batch_begin(a[0], &e, 93, KDB_BATCH_DIFF);
                send_zone(a[0], &e, "wd.test.", 3, 0, 5100);
                batch_end(a[0], &e, &mainc, 93, 1, 0);
                warm_zone("wd.test.");
                CHECK(evict_zone("wd.test."));
                zref_t zd;
                CHECK(zref_of("wd.test.", &zd) && zd.zid != ZREF_NOZID);
                const uint64_t vl0 = settled_versions();
                db_store_counters(&w0);
                atomic_store(&g_adopt_hold, true);
                db_store_test_adopt_hook = adopt_hold_hook;
                rcu_aux_read_lock();
                snw = acquire_zone_snapshot();
                vsw = snapshot_find_view(snw, "default");
                const bool staged = vsw && ops->worker_attach(vsw, &zd, 0);
                rcu_aux_read_unlock();
                CHECK(staged);
                CHECK(in_memory("wd.test."));                                          /* (answered from the staged entry) */
                CHECK(dbreg_delete("default", "wd.test.", 0) >= 0);                       /* (the store forgets the zone: the registry never had it) */
                atomic_store(&g_adopt_hold, false);                                      /* (the store thread goes on) */
                for (int t = 0; t < 2500; t++) {
                    db_store_counters(&w1);
                    if (w1.wa_lost > w0.wa_lost) break;
                    usleep(2000);
                }
                db_store_test_adopt_hook = NULL;
                CHECK(w1.wa_lost == w0.wa_lost + 1 && w1.wa_adopted == w0.wa_adopted);
                CHECK(!zref_of("wd.test.", &zd));                                       /* (not in the store, not staged, not in memory) */
                wait_retired();
                db_store_counters(&w1);
                CHECK(settled_versions() == vl0);                             /* (the entry was given back) */
            }

            /* W5c: the registration of a staged zone finds no view for the store's id (the store is closing, or the id is not one): the staged element leaves the table all the same (it held the zone's slot and its entry for ever) */
            {
                batch_begin(a[0], &e, 94, KDB_BATCH_DIFF);
                send_zone(a[0], &e, "wn.test.", 3, 0, 5200);
                batch_end(a[0], &e, &mainc, 94, 1, 0);
                warm_zone("wn.test.");
                CHECK(evict_zone("wn.test."));
                zref_t zn;
                CHECK(zref_of("wn.test.", &zn) && zn.zid != ZREF_NOZID);
                drain_wakes();
                const uint64_t vl0 = settled_versions();
                db_store_counters(&w0);
                atomic_store(&db_store_test_adopt_noview, true);
                rcu_aux_read_lock();
                snw = acquire_zone_snapshot();
                vsw = snapshot_find_view(snw, "default");
                const bool staged = vsw && ops->worker_attach(vsw, &zn, 0);
                rcu_aux_read_unlock();
                CHECK(staged);
                for (int t = 0; t < 2500; t++) {
                    db_store_counters(&w1);
                    if (w1.wa_lost > w0.wa_lost) break;
                    usleep(2000);
                }
                atomic_store(&db_store_test_adopt_noview, false);
                CHECK(w1.wa_lost == w0.wa_lost + 1 && w1.wa_adopted == w0.wa_adopted);
                wait_retired();
                db_store_counters(&w1);
                CHECK(settled_versions() == vl0);                             /* (the entry was given back) */
                CHECK(stored_only("wn.test."));                                         /* (not in memory, not staged) */
                rcu_aux_read_lock();
                snw = acquire_zone_snapshot();
                vsw = snapshot_find_view(snw, "default");
                CHECK(vsw && zref_of("wn.test.", &zn) && ops->worker_attach(vsw, &zn, 0));       /* (the zone's slot of the staging table is free: it is staged again) */
                rcu_aux_read_unlock();
                for (int t = 0; t < 2500 && !(in_memory("wn.test.") && dbdir()->attach_get(zn.zid)); t++) usleep(2000);
                CHECK(in_memory("wn.test.") && dbdir()->attach_get(zn.zid) != NULL);        /* (and registered this time) */
            }

            /* W5d (0.7 M4): a write to the record that is no new version (a stamp, a flag: the store's sequence word moves) between the staging and the registration does not take the zone away: the record is compared
             *      as it always was when the word is not the same, and it is the same version */
            {
                batch_begin(a[0], &e, 95, KDB_BATCH_DIFF);
                send_zone(a[0], &e, "wf.test.", 3, 0, 5300);
                batch_end(a[0], &e, &mainc, 95, 1, 0);
                warm_zone("wf.test.");
                CHECK(evict_zone("wf.test."));
                zref_t zf;
                CHECK(zref_of("wf.test.", &zf) && zf.zid != ZREF_NOZID);
                dbdir_rec_t rf0, rf1;
                CHECK(ops->rec_get("default", "wf.test.", &rf0) && rf0.seq_set);
                db_store_counters(&w0);
                atomic_store(&g_adopt_hold, true);
                db_store_test_adopt_hook = adopt_hold_hook;
                rcu_aux_read_lock();
                snw = acquire_zone_snapshot();
                vsw = snapshot_find_view(snw, "default");
                const bool staged = vsw && ops->worker_attach(vsw, &zf, 0);
                rcu_aux_read_unlock();
                CHECK(staged);
                ops->note_flags(zf.zid, 0x0100, 0);                                    /* (a write to the record: the word moves, the version does not) */
                CHECK(ops->rec_get("default", "wf.test.", &rf1) && rf1.seq != rf0.seq && rf1.serial == rf0.serial && memcmp(rf1.digest, rf0.digest, 32) == 0);
                CHECK(!ops->rec_unchanged(&rf0));
                atomic_store(&g_adopt_hold, false);
                for (int t = 0; t < 2500; t++) {
                    db_store_counters(&w1);
                    if (w1.wa_adopted + w1.wa_lost > w0.wa_adopted + w0.wa_lost) break;
                    usleep(2000);
                }
                db_store_test_adopt_hook = NULL;
                CHECK(w1.wa_adopted == w0.wa_adopted + 1 && w1.wa_lost == w0.wa_lost);        /* (registered, not dropped) */
                CHECK(in_memory("wf.test.") && ops->attach_get(zf.zid) != NULL);
                ops->note_flags(zf.zid, 0, 0x0100);
            }

            /* W6: a zone whose record is damaged: the worker does not attach it (the checksum), says nothing, and the zone is left to the store threads that read it from the database */
            {
                const char *wz = "w1.test.";
                batch_begin(a[0], &e, 90, KDB_BATCH_DIFF);
                send_zone(a[0], &e, wz, 5, 0, 5001);
                batch_end(a[0], &e, &mainc, 90, 1, 0);
                warm_zone(wz);
                CHECK(evict_zone(wz) && damage_record(sdir, wz));
                zref_t zw;
                CHECK(zref_of(wz, &zw) && zw.zid != ZREF_NOZID);
                db_store_counters(&w0);
                rcu_aux_read_lock();
                snw = acquire_zone_snapshot();
                vsw = snapshot_find_view(snw, "default");
                const bool bad = vsw && ops->worker_attach(vsw, &zw, 0);
                rcu_aux_read_unlock();
                CHECK(!bad);
                db_store_counters(&w1);
                CHECK(w1.wa_fail == w0.wa_fail + 1 && w1.wa_ok == w0.wa_ok && w1.versions_live == w0.versions_live);
                CHECK(park_att_claim((uint16_t)zw.sview, zw.zid, 6) == 1 && park_att_leave((uint16_t)zw.sview, zw.zid, 6));                         /* (the claim was left) */
            }

            /* W7: the zone's name server is in another stored zone that is not in memory: the worker leaves it to the store threads, which attach both (the glue of the first answer) */
            {
                g_zone_ns = "ns.sib.test.";
                batch_begin(a[0], &e, 91, KDB_BATCH_DIFF);
                send_zone(a[0], &e, "w2.test.", 6, 0, 5002);
                g_zone_ns = NULL;
                send_zone(a[0], &e, "sib.test.", 7, 0, 5003);
                batch_end(a[0], &e, &mainc, 91, 2, 0);
                warm_zone("w2.test.");
                warm_zone("sib.test.");
                CHECK(evict_zone("w2.test.") && evict_zone("sib.test."));
                drain_wakes();
                db_store_counters(&w0);
                wk_send(&wk, "w2.test.", 6);
                CHECK(wk.w.n_tx == 0 && wk.table.nwait == 1);
                db_store_counters(&w1);
                CHECK(w1.wa_decline == w0.wa_decline + 1 && w1.wa_ok == w0.wa_ok);
                CHECK(wk_wait_answer(&wk, got, &glen, 5000) && (got[3] & 0x0F) == 0);
                CHECK(in_memory("w2.test.") && in_memory("sib.test."));
            }

            /* W8: above the hard line of memory-limit the store threads make room first: the worker leaves it */
            CHECK(evict_zone("wq2.test.") && stored_only("wq2.test."));
            drain_wakes();
            db_store_counters(&w0);
            dbreg_cache_set_limit(1);
            wk_send(&wk, "wq2.test.", 6);
            dbreg_cache_set_limit(0);
            CHECK(wk.w.n_tx == 0 && wk.table.nwait == 1);
            db_store_counters(&w1);
            CHECK(w1.wa_over == w0.wa_over + 1);
            CHECK(wk_wait_answer(&wk, got, &glen, 5000) && (got[3] & 0x0F) == 0);

            /* W9: the zone's name is not the record's (the zone id is another zone's now), a state that is not stored, a view that is shared by in-view: nothing is done */
            /* (W8's room making may have taken wq1 out of memory already) */
            {
                zref_t zz;
                zref_clear(&zz);
                CHECK((!in_memory("wq1.test.") || evict_zone("wq1.test.")) && zref_of("wq1.test.", &zz) && zz.zid != ZREF_NOZID);
                rcu_aux_read_lock();
                snw = acquire_zone_snapshot();
                vsw = snapshot_find_view(snw, "default");
                zref_t bad1 = zz;
                snprintf(bad1.name, sizeof(bad1.name), "a1.tesx.");                      /* (the same length, another name) */
                zref_t bad2 = zz;
                bad2.hview = "another";
                zref_t bad3 = zz;
                bad3.zstate = ZREF_ST_KNOWN;
                zref_t bad4 = zz;
                bad4.zid = ZREF_NOZID;
                CHECK(vsw && !ops->worker_attach(vsw, &bad1, 0) && !ops->worker_attach(vsw, &bad2, 0) && !ops->worker_attach(vsw, &bad3, 0) && !ops->worker_attach(vsw, &bad4, 0));
                rcu_aux_read_unlock();
                atomic_store(&g_rd_stop, false);
            }
        }

        /* W10: attaches and detaches that race (TSan, ASan): a worker attaches zones as fast as they leave, other threads answer from them; afterwards every entry that was made is accounted for */
        if (map) {
            enum { RZ = 6 };
            static char rzn[RZ][24];
            batch_begin(a[0], &e, 92, KDB_BATCH_DIFF);
            for (int i = 0; i < RZ; i++) {
                snprintf(rzn[i], sizeof(rzn[i]), "rc%d.test.", i);
                send_zone(a[0], &e, rzn[i], (uint32_t)(10 + i), 0, 6000 + i);
            }
            batch_end(a[0], &e, &mainc, 92, RZ, 0);
            for (int i = 0; i < RZ; i++) warm_zone(rzn[i]);
            for (int i = 0; i < RZ; i++) CHECK(evict_zone(rzn[i]));                                       /* (out of memory: what the race attaches is counted from nothing) */
            db_store_counters_t base;
            db_store_counters(&base);
            const int64_t vbase = (int64_t)base.versions_live - (int64_t)dbdir()->attach_count();         /* (zones that an install made have no version of the store's attach) */
            atomic_store(&g_rd_stop, false);
            atomic_store(&g_rd_pause_us, 200);
            atomic_store(&g_rd_ok, 0);
            atomic_store(&g_rd_gone, 0);
            atomic_store(&g_rd_bad, 0);
            pthread_t rt[2], at;
            CHECK(pthread_create(&rt[0], NULL, reader_thread, (void *)(uintptr_t)"www.rc1.test.") == 0);
            CHECK(pthread_create(&rt[1], NULL, reader_thread, (void *)(uintptr_t)"www.rc4.test.") == 0);
            atomic_store(&g_wa_stop, false);
            atomic_store(&g_wa_done, 0);
            struct wa_arg { const dbdir_ops_t *ops; char (*names)[24]; } wargs = { ops, rzn };
            CHECK(pthread_create(&at, NULL, wa_thread, &wargs) == 0);
            uint64_t ev = 0;
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            do {
                for (int i = 0; i < RZ; i++) ev += dbreg_test_evict_default(rzn[i]) ? 1 : 0;
                usleep(400);                                                   /* (the registry's lock is not the evictor's alone: the registrations of the staged zones take it) */
                clock_gettime(CLOCK_MONOTONIC, &t1);
            } while ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < (UNDER_TSAN_TEST ? 2500 : 1200));
            atomic_store(&g_rd_stop, true);
            atomic_store(&g_rd_pause_us, 0);
            atomic_store(&g_wa_stop, true);
            pthread_join(at, NULL);
            pthread_join(rt[0], NULL);
            pthread_join(rt[1], NULL);
            printf("  attach race: %llu evictions, %llu worker attaches, reader: ok %llu not-ready %llu bad %llu\n", (unsigned long long)ev, (unsigned long long)atomic_load(&g_wa_done),
                   (unsigned long long)atomic_load(&g_rd_ok), (unsigned long long)atomic_load(&g_rd_gone), (unsigned long long)atomic_load(&g_rd_bad));
            CHECK(atomic_load(&g_rd_bad) == 0);
            CHECK(atomic_load(&g_wa_done) > 0);
            /* quiet: every staged zone was registered or dropped; no entry of a worker attach is left over */
            uint64_t last = 0;
            for (int t = 0; t < 2500; t++) {
                db_store_counters(&w1);
                if (w1.wa_adopted + w1.wa_lost == w1.wa_ok && !park_attach_pending() && w1.wa_ok == last) break;
                last = w1.wa_ok;
                usleep(4000);
            }
            db_store_counters(&w1);
            CHECK(w1.wa_adopted + w1.wa_lost == w1.wa_ok);
            wait_retired();
            db_store_counters(&w1);
            CHECK((int64_t)w1.versions_live - (int64_t)dbdir()->attach_count() == vbase + 0);               /* (one version for every zone in memory: no entry was lost to the race) */
        }
        wk_free(&wk);
        atomic_store(&db_store_test_resident, false);
    }

    free(old_copy);
    gc_snapshot_wait_idle();                                                 /* (the reclaim thread that the last delta started: joined, not left to the exit) */
    /* -- 0.7 fix 8: the zones that are in memory when the server stops are written to hot.list, the most used first: wq5 is asked for most, wq2 next */
    uint32_t hot_zid5 = STORE_NONE, hot_zid2 = STORE_NONE, hot_zid3 = STORE_NONE;
    size_t hot_attached = 0;
    {
        uint8_t out[1232];
        zref_t zq;
        /* (the W section's room making under the hard line may have taken wq5 or wq2 out of memory: the engine alone does not attach, so put them back first) */
        if (!in_memory("wq5.test.")) db_store_attach_zone("default", "wq5.test.");
        if (!in_memory("wq2.test.")) db_store_attach_zone("default", "wq2.test.");
        for (int i = 0; i < 40000; i++) (void)ask_engine(&g_wctx, &g_cc, "www.wq5.test.", 1, out);
        for (int i = 0; i < 30000; i++) (void)ask_engine(&g_wctx, &g_cc, "www.wq2.test.", 1, out);
        CHECK(zref_of("wq5.test.", &zq) && zq.entry);
        hot_zid5 = zq.zid;
        CHECK(zref_of("wq2.test.", &zq) && zq.entry);
        hot_zid2 = zq.zid;
        /* 0.7 fix D: only the zones that have answered a query since they came into memory are on the list: wq3 is made resident again by an attach that nobody asked for (a fresh entry with no query) */
        if (in_memory("wq3.test.")) CHECK(evict_zone("wq3.test."));
        db_store_attach_zone("default", "wq3.test.");
        CHECK(zref_of("wq3.test.", &zq) && zq.entry && zone_queries32(zq.entry) == 0);
        hot_zid3 = zq.zid;
        const size_t resident = dbdir()->attach_count();
        size_t pos = 0;
        for (zdir_elem_t *z; (z = dbdir()->attach_next(&pos)) != NULL;) {
            zone_db_entry_t *ze = zdir_entry(z);
            if (ze && ze->source == ZONE_SRC_DB && (z->kind & ZDIR_K_STORED) && zone_queries32(ze) > 0) hot_attached++;
        }
        CHECK(hot_attached >= 2 && hot_attached < resident);                     /* (wq5 and wq2 are asked for, wq3 is resident and is not) */
    }
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
            uint32_t *hids = NULL;
            size_t hn = 0;
            CHECK(store_hot_read(s2, &hids, &hn) == 0 && hn == hot_attached && hids);        /* (every zone that was asked for, once) */
            bool has3 = false;
            for (size_t i = 0; hids && i < hn; i++) has3 = has3 || hids[i] == hot_zid3;
            CHECK(!has3);                                                                    /* (and not the one that only an attach made resident) */
            CHECK(hids && hn >= 2 && hids[0] == hot_zid5 && hids[1] == hot_zid2);              /* (the most asked for first) */
            bool dup = false;
            for (size_t i = 0; hids && i < hn; i++)
                for (size_t j = i + 1; j < hn; j++) dup = dup || hids[i] == hids[j];
            CHECK(!dup);
            free(hids);
            db_store_counters_t hc;
            db_store_counters(&hc);
            CHECK(hc.hot_written == hot_attached && hc.hot_state == 0);
            (void)store_close(s2);
        }
        if (dfd >= 0) close(dfd);
    }
    db_store_frontend_close();                                                  /* (the directory and its lock are the next process's) */
    char cmd[700];
    if (strcmp(mode, "map") == 0 && g_self[0]) {                             /* the next start (a process of its own): hot.list is read and attached in the background */
        for (int ph = 0; ph < 5; ph++) {
            snprintf(cmd, sizeof(cmd), "%s hot %s %d", g_self, dir, ph);
            CHECK(run_part(cmd) == 0);
        }
        snprintf(cmd, sizeof(cmd), "%s attab %s", g_self, dir);                 /* 0.7 M4: the attach table grows outside the registry's lock */
        CHECK(run_part(cmd) == 0);
    }
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)!system(cmd);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

/* ---------------------------------------------------------------- 0.7 M4: the table of the attached zones grows outside the registry's lock */
/* The table (dns_db_store.c, AT) was made again inside the registry's lock at every doubling: 500,000 zones took 50 to 100 ms in which every attach waited.  A thread now makes the next table when the
 * table is three eighths full, the writers go on, and what they did meanwhile is done again on the new table inside the lock before it is put in.  Here a writer puts 400,000 elements (and takes a part of them
 * out again, so that the log has removals) while readers look every id up in a read section: an element that was put and not taken out is always found, whatever table the reader has; one that is found is
 * the right one.  The longest put (the room and the put of one element) is measured, and the growths that were made inside the lock are counted (the first table, and a table that filled up before the next
 * one was ready: at most a few; before this every doubling). */
#define AT_N (UNDER_TSAN_TEST ? 60000 : 400000)
static _Atomic uint32_t g_at_hi;                 /* the ids up to this one are put */
static _Atomic bool g_at_stop;
static _Atomic uint64_t g_at_bad, g_at_looks;
static zdir_elem_t **g_at_el;
static void *at_reader(void *arg) {
    uint64_t x = (uint64_t)(uintptr_t)arg * 0x9E3779B97F4A7C15ull + 1;
    while (!atomic_load(&g_at_stop)) {
        const uint32_t hi = atomic_load_explicit(&g_at_hi, memory_order_acquire);
        if (hi == 0) continue;
        for (int k = 0; k < 64; k++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            const uint32_t z = 1 + (uint32_t)(x % hi);
            rcu_aux_read_lock();
            const zdir_elem_t *e = dbdir()->attach_get(1000000 + z);
            rcu_aux_read_unlock();
            atomic_fetch_add(&g_at_looks, 1);
            if (e && e->zid != 1000000 + z) atomic_fetch_add(&g_at_bad, 1);               /* (the wrong element) */
            if (!e && z % 7 != 0) atomic_fetch_add(&g_at_bad, 1);               /* (an element that is in the table, and was never taken out, is missing) */
        }
    }
    return NULL;
}
/* The prepared growth in the cases that a writer that goes on makes hard.  The thread that prepares the table is held (db_store_test_prep_hook) after it has copied the table and before it takes the lock, and the
 * test does what the registry does meanwhile; then it is let go and the table is looked at: an element that was re-keyed and hidden is nowhere (it was put under the old id in the new table by the log, with
 * the id it has now: a stale element that a lock-free reader would find, and use after it was freed), an element that was taken out is not there, the one that was re-keyed and put back is there under its new id. */
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define AT_SLOW 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define AT_SLOW 1
#endif
#endif
#ifndef AT_SLOW
#define AT_SLOW 0
#endif
static _Atomic bool g_pp_hold;
static _Atomic int g_pp_calls;
static void prep_hold_hook(int where) {
    (void)where;
    atomic_fetch_add(&g_pp_calls, 1);
    for (int t = 0; t < 20000 && atomic_load(&g_pp_hold); t++) usleep(1000);
}
static zdir_elem_t *at_new(uint32_t zid) {
    zdir_elem_t *el = calloc(1, sizeof(*el));
    el->zid = zid;
    return el;
}
static bool at_put(const dbdir_ops_t *ops, zdir_elem_t *el) { return ops->attach_reserve() && ops->attach_put(el); }
static void at_rekey(zdir_elem_t *el, uint32_t zid) { __atomic_store_n(&el->zid, zid, __ATOMIC_RELAXED); }
static bool at_wait_prep(const dbdir_ops_t *ops, bool on, int ms) {
    for (int t = 0; t < ms; t++) {
        if ((ops->counters(9) != 0) == on) return true;
        usleep(1000);
    }
    return false;
}
/* the number of elements of the table that are the pointer `p` */
static int at_count_ptr(const dbdir_ops_t *ops, const zdir_elem_t *p) {
    int n = 0;
    size_t pos = 0;
    rcu_aux_read_lock();
    for (zdir_elem_t *e; (e = ops->attach_next(&pos)) != NULL;) n += e == p;
    rcu_aux_read_unlock();
    return n;
}
/* every element of the table has the id that it is put under (a stale element has another) */
static size_t at_scan_ok(const dbdir_ops_t *ops) {
    size_t n = 0, pos = 0;
    rcu_aux_read_lock();
    for (zdir_elem_t *e; (e = ops->attach_next(&pos)) != NULL;) {
        if (ops->attach_get(e->zid) == e) n++;
        else n += 1000000000ull;                                                /* (a stale one: the sum is then far off) */
    }
    rcu_aux_read_unlock();
    return n;
}
/* fills the table with elements of ids base.. until a growth is being prepared (the hook holds the thread when it has copied the table); false: it did not start */
static bool at_fill_to_prep(const dbdir_ops_t *ops, uint32_t base, zdir_elem_t ***arr, uint32_t *n) {
    const uint32_t max = 200000;
    *arr = calloc(max, sizeof(**arr));
    *n = 0;
    while (*n < max && ops->counters(9) == 0) {
        zdir_elem_t *el = at_new(base + *n);
        (*arr)[(*n)++] = el;
        if (!at_put(ops, el)) return false;
    }
    return ops->counters(9) != 0;
}
static void at_drop_all(const dbdir_ops_t *ops, zdir_elem_t **arr, uint32_t n) {
    CHECK(at_wait_prep(ops, false, 20000));                                       /* (a thread that makes a table reads the elements: they are not freed meanwhile) */
    for (uint32_t i = 0; i < n; i++) ops->attach_remove(arr[i]);
    (void)rcu_writer_wait_until_safe(rcu_writer_advance_epoch(), 5000);
    for (uint32_t i = 0; i < n; i++) free(arr[i]);
    free(arr);
}

static void at_scenarios(const dbdir_ops_t *ops) {
    zdir_elem_t **a;
    uint32_t n;
    /* A: re-keyed and hidden, re-keyed and put back, put and hidden, taken out, all while the table is made */
    atomic_store(&g_pp_hold, true);
    atomic_store(&g_pp_calls, 0);
    db_store_test_prep_hook = prep_hold_hook;
    CHECK(at_fill_to_prep(ops, 3000000, &a, &n));
    for (int t = 0; t < 20000 && atomic_load(&g_pp_calls) == 0; t++) usleep(1000);
    CHECK(atomic_load(&g_pp_calls) == 1 && ops->counters(9) == 1);               /* (the table is copied; the thread waits) */
    const uint64_t bg0 = ops->counters(8);
    zdir_elem_t *x = a[100], *r = a[200], *w = a[300];
    ops->attach_remove(x);                                                       /* x: the zone is re-keyed and then hidden (shadowed): taken out, given the id of its new record, never put back */
    at_rekey(x, 7000000);
    ops->attach_remove(r);                                                       /* r: taken out (evicted), and freed later */
    ops->attach_remove(w);                                                       /* w: re-keyed and put back */
    at_rekey(w, 7000300);
    CHECK(at_put(ops, w));
    zdir_elem_t *y = at_new(5000001), *z = at_new(5000011);
    CHECK(at_put(ops, y) && at_put(ops, z));                                     /* put while the table is made, with the id they had then ... */
    ops->attach_remove(y);                                                       /* y: re-keyed and put back under another id */
    at_rekey(y, 5000002);
    CHECK(at_put(ops, y));
    ops->attach_remove(z);                                                       /* z: re-keyed and hidden: the logged put has the id it had then, not the one it has now */
    at_rekey(z, 5000012);
    atomic_store(&g_pp_hold, false);
    CHECK(at_wait_prep(ops, false, 20000));
    CHECK(ops->counters(8) == bg0 + 1);                                          /* (the prepared table was put in) */
    rcu_aux_read_lock();
    CHECK(ops->attach_get(3000100) == NULL && ops->attach_get(7000000) == NULL);   /* x: nowhere */
    CHECK(ops->attach_get(3000200) == NULL);                                       /* r: out */
    CHECK(ops->attach_get(3000300) == NULL && ops->attach_get(7000300) == w);      /* w: under the new id only */
    CHECK(ops->attach_get(5000001) == NULL && ops->attach_get(5000002) == y);      /* y: under the new id only */
    CHECK(ops->attach_get(5000011) == NULL && ops->attach_get(5000012) == NULL);   /* z: nowhere */
    rcu_aux_read_unlock();
    CHECK(at_count_ptr(ops, x) == 0 && at_count_ptr(ops, r) == 0 && at_count_ptr(ops, z) == 0 && at_count_ptr(ops, y) == 1 && at_count_ptr(ops, w) == 1);
    CHECK(at_scan_ok(ops) == (size_t)n - 1);                                           /* (n put; x and r are out, z is nowhere, y is new: n - 2 + 1) */
    free(x);                                                                     /* (freed after the table was put in, as the registry does after the grace period: nothing of the table has them) */
    free(r);
    free(z);
    CHECK(at_scan_ok(ops) == (size_t)n - 1);                                           /* (a stale pointer to a freed element would be read here) */
    a[100] = a[200] = a[300] = NULL;
    ops->attach_remove(y);
    free(y);
    for (uint32_t i = 0; i < n; i++)
        if (a[i]) {
            ops->attach_remove(a[i]);
            free(a[i]);
        }
    ops->attach_remove(w);
    free(w);
    free(a);
    db_store_test_prep_hook = NULL;
    CHECK(at_wait_prep(ops, false, 2000));

    /* B: the log of the writers cannot grow: the prepared table is dropped and the growth is made inside the lock, as it was */
    atomic_store(&g_pp_hold, true);
    atomic_store(&g_pp_calls, 0);
    db_store_test_prep_hook = prep_hold_hook;
    CHECK(at_fill_to_prep(ops, 4000000, &a, &n));
    for (int t = 0; t < 20000 && atomic_load(&g_pp_calls) == 0; t++) usleep(1000);
    const uint64_t bg1 = ops->counters(8), gr1 = ops->counters(6);
    atomic_store(&db_store_test_plog_fail, 1);                                    /* (from here: the table is copied, the thread waits; the next put cannot be logged) */
    zdir_elem_t *e1 = at_new(4900001), *e2 = at_new(4900002);
    CHECK(at_put(ops, e1) && at_put(ops, e2));                                   /* (the first of them cannot be logged) */
    atomic_store(&g_pp_hold, false);
    CHECK(at_wait_prep(ops, false, 20000));
    CHECK(ops->counters(8) == bg1 && ops->counters(6) == gr1);                    /* (nothing was put in) */
    CHECK(atomic_load(&db_store_test_plog_fail) == 0);
    db_store_test_prep_hook = NULL;
    zdir_elem_t **more = calloc(40000, sizeof(*more));
    for (int i = 0; i < 40000; i++) {                                            /* (the table goes on to fill and grows inside the lock when it is half full, or by a new preparation) */
        more[i] = at_new(4950000 + (uint32_t)i);
        CHECK(at_put(ops, more[i]));
        if (i == 0) CHECK(at_wait_prep(ops, false, 20000));
    }
    CHECK(at_wait_prep(ops, false, 20000));
    CHECK(ops->attach_get(4900001) == e1 && ops->attach_get(4900002) == e2 && ops->attach_get(4000500) == a[500] && ops->attach_get(4950000 + 39999) == more[39999]);
    CHECK(at_scan_ok(ops) == (size_t)n + 2 + 40000);
    ops->attach_remove(e1);
    ops->attach_remove(e2);
    free(e1);
    free(e2);
    at_drop_all(ops, more, 40000);
    at_drop_all(ops, a, n);

    /* C: the table that is full of tombstones (a steady attach and eviction of the same number of zones) is made again outside the lock, at the same size */
    atomic_store(&g_pp_calls, 0);
    atomic_store(&g_pp_hold, false);
    db_store_test_prep_hook = prep_hold_hook;
    const uint32_t live = 40000;
    zdir_elem_t **ring = calloc(live, sizeof(*ring));
    for (uint32_t i = 0; i < live; i++) {
        ring[i] = at_new(6000000 + i);
        CHECK(at_put(ops, ring[i]));
    }
    CHECK(at_wait_prep(ops, false, 20000));
    const uint64_t slots2 = ops->counters(5), gr2 = ops->counters(6), bg2 = ops->counters(8);
    uint32_t next = 6000000 + live;
    zdir_elem_t *gone[4096];
    int ngone = 0;
    for (uint32_t k = 0; k < 600000; k++) {                                      /* (one out, one in: the live ones stay 40,000, the used slots grow with the tombstones) */
        const uint32_t slot = k % live;
        ops->attach_remove(ring[slot]);
        gone[ngone++] = ring[slot];                                              /* (freed after a grace period, as the registry frees an element: the thread that makes a table may be reading it) */
        ring[slot] = at_new(next++);
        CHECK(at_put(ops, ring[slot]));
        if (ngone == 4096) {
            (void)rcu_writer_wait_until_safe(rcu_writer_advance_epoch(), 5000);
            for (int g = 0; g < ngone; g++) free(gone[g]);
            ngone = 0;
        }
        if ((k & 1023) == 0) usleep(100);
    }
    (void)rcu_writer_wait_until_safe(rcu_writer_advance_epoch(), 5000);
    for (int g = 0; g < ngone; g++) free(gone[g]);
    CHECK(at_wait_prep(ops, false, 20000));
    const uint64_t gr3 = ops->counters(6) - gr2, bg3 = ops->counters(8) - bg2;
    printf("  tombstones: %llu table(s) made at %llu slots, %llu of them outside the lock; prepared growths started: %d\n", (unsigned long long)gr3, (unsigned long long)slots2, (unsigned long long)bg3, atomic_load(&g_pp_calls));
    CHECK(ops->counters(5) >= slots2);                                           /* (the size that 40,000 live elements get: four slots each; compaction itself keeps it) */
    CHECK(gr3 >= 1 && atomic_load(&g_pp_calls) >= 1 && bg3 >= (AT_SLOW ? 0 : 1));
    CHECK(at_scan_ok(ops) == live);
    at_drop_all(ops, ring, live);
    db_store_test_prep_hook = NULL;
}

static _Atomic bool g_at_stopped;
static void *at_stop_thread(void *arg) {
    (void)arg;
    db_store_stop();
    atomic_store(&g_at_stopped, true);
    return NULL;
}
/* D: the store stops while a table is being made: the stop waits for the thread, the table is not put in, and no growth is started after it */
static void at_stop_scenario(const dbdir_ops_t *ops) {
    zdir_elem_t **a;
    uint32_t n;
    atomic_store(&g_pp_hold, true);
    atomic_store(&g_pp_calls, 0);
    atomic_store(&g_at_stopped, false);
    db_store_test_prep_hook = prep_hold_hook;
    CHECK(at_fill_to_prep(ops, 8000000, &a, &n));
    for (int t = 0; t < 20000 && atomic_load(&g_pp_calls) == 0; t++) usleep(1000);
    CHECK(atomic_load(&g_pp_calls) == 1);
    const uint64_t bg = ops->counters(8);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, at_stop_thread, NULL) == 0);
    usleep(300000);
    CHECK(!atomic_load(&g_at_stopped) && ops->counters(9) == 1);                 /* (the stop is waiting for the thread that makes the table) */
    atomic_store(&g_pp_hold, false);
    pthread_join(th, NULL);
    CHECK(atomic_load(&g_at_stopped) && ops->counters(9) == 0);
    CHECK(ops->counters(8) == bg);                                               /* (the table was dropped: the store is stopping) */
    db_store_test_prep_hook = NULL;
    for (uint32_t i = 0; i < 60000; i++) {                                       /* (more elements than a growth is started for: none is) */
        zdir_elem_t *el = at_new(8500000 + i);
        CHECK(at_put(ops, el));
        ops->attach_remove(el);
        free(el);
    }
    CHECK(ops->counters(9) == 0 && ops->counters(8) == bg);
    at_drop_all(ops, a, n);
}

static int run_attab(const char *dir) {
    printf("[the attach table grows outside the registry's lock]\n");
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; store-threads 2; store-hot-list no; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled());
    const dbdir_ops_t *ops = dbdir();
    CHECK(ops != NULL);
    const uint64_t g0 = ops->counters(6), b0 = ops->counters(8), slots0 = ops->counters(5);
    g_at_el = calloc((size_t)AT_N + 1, sizeof(*g_at_el));
    pthread_t rt[3];
    atomic_store(&g_at_stop, false);
    for (int i = 0; i < 3; i++) CHECK(pthread_create(&rt[i], NULL, at_reader, (void *)(uintptr_t)(i + 1)) == 0);
    int64_t worst = 0;
    for (uint32_t i = 1; i <= AT_N && g_at_el; i++) {
        zdir_elem_t *el = calloc(1, sizeof(*el));
        el->zid = 1000000 + i;                                                  /* (a range that no store zone has: only the table is looked at) */
        g_at_el[i] = el;
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        const bool ok = ops->attach_reserve() && ops->attach_put(el);
        clock_gettime(CLOCK_MONOTONIC, &b);
        if (!ok) CHECK(false);
        const int64_t d = (int64_t)(b.tv_sec - a.tv_sec) * 1000000000ll + (b.tv_nsec - a.tv_nsec);
        if (d > worst) worst = d;
        if (i > 50 && (i - 50) % 7 == 0) ops->attach_remove(g_at_el[i - 50]);   /* (the ids that are multiples of 7 are put and taken out 50 puts later) */
        atomic_store_explicit(&g_at_hi, i, memory_order_release);
    }
    atomic_store(&g_at_stop, true);
    for (int i = 0; i < 3; i++) pthread_join(rt[i], NULL);
    /* the table: every element that was not taken out is there, and the others are not */
    uint32_t wrong = 0;
    rcu_aux_read_lock();
    for (uint32_t i = 1; i <= AT_N && g_at_el; i++) {
        const zdir_elem_t *e = ops->attach_get(1000000 + i);
        const bool want = !(i % 7 == 0 && i + 50 <= AT_N);
        if (want ? e != g_at_el[i] : e != NULL) wrong++;
    }
    rcu_aux_read_unlock();
    const uint64_t grows = ops->counters(6) - g0, prepared = ops->counters(8) - b0;
    printf("  %d elements, %llu table(s) made (%llu of them outside the lock), slots %llu -> %llu, longest put %.2f ms, %llu lookups\n", AT_N, (unsigned long long)grows, (unsigned long long)prepared,
           (unsigned long long)slots0, (unsigned long long)ops->counters(5), (double)worst / 1e6, (unsigned long long)atomic_load(&g_at_looks));
    /* (what a descheduled thread can change is the time, and how many of the growths were ready in time: neither is asserted here; the cases that matter are held by the hook below) */
    CHECK(at_wait_prep(ops, false, 20000));
    CHECK(wrong == 0);
    CHECK(atomic_load(&g_at_bad) == 0 && atomic_load(&g_at_looks) > 1000);
    CHECK(grows >= 5);
    for (uint32_t i = 1; i <= AT_N && g_at_el; i++) {                            /* (the table is emptied: nothing is freed that a reader could have) */
        if (!(i % 7 == 0 && i + 50 <= AT_N)) ops->attach_remove(g_at_el[i]);
    }
    (void)rcu_writer_wait_until_safe(rcu_writer_advance_epoch(), 5000);
    for (uint32_t i = 1; i <= AT_N && g_at_el; i++) free(g_at_el[i]);
    free(g_at_el);
    at_scenarios(ops);
    at_stop_scenario(ops);                                                       /* (this stops the store) */
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

/* ---------------------------------------------------------------- 0.7 fix 8: hot.list at the next start */
/* A process on the store that run_mode() left after its clean stop.  Phase 0 (store-hot-list yes, the default): the list is read, the zones are attached in its order in the background, a query for a
 * zone at the end of the list is attached at once (the queries come first), and a clean stop writes the list again.  Phase 1 (store-hot-list no): the list is not read, nothing is attached, and a
 * stop writes no list. */
static uint32_t g_hot_seen[8192];
static char g_hot_xkey[XFR_KEY_MAX + 1];                 /* the key of the copy that the list names (phases 0, 2, 4, 3) */
static int g_hot_xklen;
static uint32_t g_hot_xzid;
static _Atomic int g_hot_nseen;
static int g_hot_delay_us;
static _Atomic int g_hot_limit_at;                       /* the number of zones after which the hook puts the memory-limit on (0: never) */
static void hot_order_hook(uint32_t zid) {
    int i = atomic_fetch_add(&g_hot_nseen, 1);
    if (i < 8192) g_hot_seen[i] = zid;
    if (atomic_load(&g_hot_limit_at) && i + 1 == atomic_load(&g_hot_limit_at)) dbreg_cache_set_limit(1);      /* (every zone is above the high mark of a limit of one byte) */
    if (g_hot_delay_us) usleep((useconds_t)g_hot_delay_us);
}

extern void (*db_ingest_test_fetch_req_hook)(const char *zone);
static int run_hot(const char *dir, int phase) {
    printf("[hot.list: the next start, store-hot-list %s%s]\n", phase != 1 ? "yes" : "no", phase == 2 ? ", six threads of the list, and attach requests that always wait" : phase == 3 ? ", the high mark of memory-limit" : phase == 4 ? ", six threads of the list, and attach requests that wait and are not served" : "");
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads %d; %s }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir, phase >= 2 ? 8 : 2, phase == 1 ? "store-hot-list no;" : "");
    CHECK(parse_named_conf(conf, &cfg) == 0);
    CHECK(cfg.database.store_hot_list == (phase != 1));
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    park_register_worker(0, -1);
    memset(&g_wctx, 0, sizeof(g_wctx));
    g_query_bg_fetch = no_bg_fetch;
    g_query_bg_attach = no_bg_fetch;
    /* the list as the last stop wrote it, read from the file before the server starts */
    uint32_t *want = NULL;
    size_t nwant = 0;
    {
        int dfd = open(sdir, O_RDONLY | O_DIRECTORY);
        store_opts_t so;
        store_opts_default(&so);
        so.boot_id = 4242;
        store_t *s0 = NULL;
        CHECK(dfd >= 0 && store_open(dfd, &so, &s0) == 0 && s0);
        /* The list is made here, from the zones that the store holds (every stored zone, by id), and not left to what the stop of the earlier process wrote: that is the zones that happened to be in
         * memory then, and the cache manager's tests before it take a part of them out (a CI machine had fewer than 256).  Every phase starts from this list; a phase's own stop rewrites it. */
        /* 0.7 (secondary store 2.2, 13): a secondary's copy (the reserved view) is on the list too, as a zone id that the database used and the store gave to a copy later may be: the list never attaches it
         * as a zone of a database view (it is looked at and skipped) */
        {
            int xv = store_view_id(s0, KARIDNS_XFR_STORE_VIEW);
            if (xv < 0) xv = store_view_add(s0, KARIDNS_XFR_STORE_VIEW);
            g_hot_xklen = xfr_key_make("default", XFR_K_CONFIG, "xfr.test.", g_hot_xkey, sizeof(g_hot_xkey));
            zone_image_t *ximg = zone_img("xfr.test.", 1);
            xfr_state_t xs = { .kind = XFR_K_CONFIG, .identity = 1, .last_ok = 1 };
            store_meta_t xm;
            memset(&xm, 0, sizeof(xm));
            xm.flags = STORE_F_XFR;
            xm.serial = 1;
            xm.stamp_time = 1;
            xfr_state_encode(&xs, xm.digest);
            CHECK(s0 && xv >= 0 && ximg && g_hot_xklen > 0 && store_put(s0, (uint16_t)xv, g_hot_xkey, (size_t)g_hot_xklen, &xm, ximg, ximg->total_size, &g_hot_xzid) == 0);
            zone_image_free(ximg);
        }
        {
            uint32_t *ids = malloc((size_t)4096 * sizeof(*ids));
            size_t nid = 0;
            uint32_t cursor = 0;
            store_zone_t sz0;
            int ir;
            while (s0 && ids && nid < 4096 && (ir = store_iter(s0, &cursor, &sz0)) != 0) {
                if (ir > 0 && sz0.state == STORE_STATE_STORED && !(sz0.flags & (STORE_F_NONSTORE | STORE_F_XFR))) ids[nid++] = sz0.zid;
            }
            CHECK(nid >= 512);                                                    /* (the store holds about a thousand zones by now) */
            if (ids && nid < 4096) {                                              /* the copy is the first of the list (the last one is a zone of the database: the query test asks for it) */
                memmove(ids + 1, ids, nid * sizeof(*ids));
                ids[0] = g_hot_xzid;
                nid++;
            }
            CHECK(s0 && ids && store_hot_write(s0, ids, nid) == 0);
            free(ids);
        }
        CHECK(s0 && store_hot_read(s0, &want, &nwant) == 0 && nwant >= 512);
        if (s0) (void)store_close(s0);
        if (dfd >= 0) close(dfd);
    }
    CHECK(db_store_start(&cfg) && db_store_enabled());
    store_t *st = db_store_handle();
    db_store_counters_t c;
    db_store_counters(&c);
    if (phase == 1) {
        CHECK(c.hot_state == 4 && c.hot_listed == 0);                              /* (4: off) */
        db_store_hot_start();                                                   /* (nothing to start) */
        usleep(200000);
        db_store_counters(&c);
        CHECK(c.hot_attached == 0 && c.hot_skipped == 0 && dbdir()->attach_count() == 0);
        uint8_t before[64], after[64];
        char hp[700];
        snprintf(hp, sizeof(hp), "%s/hot.list", sdir);
        int fd = open(hp, O_RDONLY);
        CHECK(fd >= 0 && pread(fd, before, sizeof(before), 0) == (ssize_t)sizeof(before));
        if (fd >= 0) close(fd);
        db_store_stop();
        db_store_counters(&c);
        fd = open(hp, O_RDONLY);
        CHECK(fd >= 0 && pread(fd, after, sizeof(after), 0) == (ssize_t)sizeof(after) && memcmp(before, after, sizeof(after)) == 0 && c.hot_written == 0);      /* (no list was written) */
        if (fd >= 0) close(fd);
        free(want);
        printf("%d checks, %d failed\n", g_checks, g_failed);
        return g_failed ? 1 : 0;
    }
    CHECK(c.hot_listed == nwant && c.hot_state == 0 && dbdir()->attach_count() == 0);                   /* (read, not started: no zone is in memory) */
    if (phase >= 2) {
        /* 0.7 M4: the list has three quarters of the store threads, at most six (8 store threads here: 6), takes the zones in batches in the order of the list, registers a batch in one section of the registry's lock, never
         * waits for the queries, and stops at the high mark of memory-limit (phase 3: the limit comes while the list is being worked through) */
        CHECK(nwant >= 256);
        g_hot_delay_us = 150;                                                   /* (a zone takes 150 us to come: the batches of the threads overlap) */
        atomic_store(&g_hot_nseen, 0);
        atomic_store(&g_hot_limit_at, phase == 3 ? (int)(nwant / 4) : 0);
        atomic_store(&db_store_test_hot_pending, phase == 2);                          /* (phase 2: a query always waits for a store thread: the list gives it a moment before each batch and is not starved) */
        atomic_store(&db_store_test_hot_stuck, phase == 4);                            /* (phase 4: it waits and nothing is served: the list gives way once, then goes on) */
        atomic_store(&db_store_test_hot_naps, 0);
        const uint64_t grows0 = dbdir()->counters(6);
        db_store_test_hot_hook = hot_order_hook;
        db_store_hot_start();
        db_store_counters(&c);
        const uint64_t slots1 = dbdir()->counters(5), grows1 = dbdir()->counters(6);
        CHECK(slots1 >= 4 * nwant && grows1 == grows0 + 1);                          /* (the attach table is made for the zones of the list at the start: no doubling inside the registry's lock while they come) */
        CHECK(c.hot_threads == 6 && (c.hot_state == 1 || c.hot_state == 2 || c.hot_state == 3));
        for (int t = 0; t < 5000; t++) {
            db_store_counters(&c);
            if (c.hot_state != 1) break;
            usleep(4000);
        }
        db_store_counters(&c);
        printf("  hot: state %llu, attached %llu, skipped %llu of %zu zones by %llu thread(s), %llu zones a second, in memory %zu\n", (unsigned long long)c.hot_state, (unsigned long long)c.hot_attached,
               (unsigned long long)c.hot_skipped, nwant, (unsigned long long)c.hot_threads, (unsigned long long)c.hot_per_s, dbdir()->attach_count());
        const int nseen = atomic_load(&g_hot_nseen);
        /* the batches were taken in the order of the list: the j-th batch that was seen first is the j-th, give or take the threads that took one and were not scheduled yet */
        {
            bool first_ok = true;
            int distinct = 0;
            const size_t nb = (nwant + 31) / 32;
            bool *seen_b = calloc(nb, 1);
            for (int i = 0; i < nseen && i < 8192 && seen_b; i++) {
                size_t pos = 0;
                while (pos < nwant && want[pos] != g_hot_seen[i]) pos++;
                if (pos == nwant) {
                    first_ok = false;
                    break;
                }
                if (!seen_b[pos / 32]) {
                    seen_b[pos / 32] = true;
                    first_ok = first_ok && pos / 32 < (size_t)distinct + 6;
                    distinct++;
                }
            }
            free(seen_b);
            CHECK(first_ok);
        }
        const uint64_t naps = atomic_load(&db_store_test_hot_naps);
        const uint64_t nbatches = (nwant + 31) / 32;
        if (phase == 2) CHECK(naps >= 8 * nbatches);                                            /* (the whole moment, HOT_YIELD_US in naps of HOT_NAP_US, before every batch) */
        if (phase == 4) CHECK(naps >= nbatches && naps <= nbatches + 6);                        /* (one nap before every batch, and one for the thread that finds the end: nothing was served) */
        if (phase == 2 || phase == 4) {
            CHECK(c.hot_state == 2 && nseen == (int)nwant);                                      /* (2: done; every zone of the list was looked at once) */
            CHECK(c.hot_attached + c.hot_skipped == nwant && c.hot_attached >= nwant - 8 && c.hot_per_s > 0);
            CHECK(dbdir()->attach_count() + 8 >= nwant);                         /* (the list is every stored zone: a few of them are shadowed by the configuration and are registered but not in the table) */
            CHECK(dbdir()->counters(6) == grows1 && dbdir()->counters(5) == slots1);        /* (and it was not grown by them) */
            uint8_t out[1232];
            CHECK(ask_engine(&g_wctx, &g_cc, "www.wq5.test.", 1, out) > 12 && (out[3] & 0x0F) == 0);
        } else {
            dbreg_cache_set_limit(0);
            CHECK(c.hot_state == 3);                                                             /* (3: stopped at the high mark) */
            CHECK(nseen >= (int)(nwant / 4) && nseen <= (int)(nwant / 4) + 6 + 2);                   /* (the limit is looked at for every zone: each thread goes one zone past it at the most, and what was made is registered) */
            CHECK(c.hot_attached < nwant && dbdir()->attach_count() < nwant);
        }
        {
            zref_t zr;
            memset(&zr, 0, sizeof(zr));
            const int xv = store_view_id(st, KARIDNS_XFR_STORE_VIEW);
            CHECK(xv >= 0 && g_hot_xklen > 0);
            CHECK(!(dbdir()->find(xv, g_hot_xkey, (size_t)g_hot_xklen, &zr) && zr.el));          /* (the copy on the list was not attached as a zone) */
        }
        atomic_store(&db_store_test_hot_pending, false);
        atomic_store(&db_store_test_hot_stuck, false);
        db_store_test_hot_hook = NULL;
        db_store_stop();
        free(want);
        printf("%d checks, %d failed\n", g_checks, g_failed);
        return g_failed ? 1 : 0;
    }
    g_hot_delay_us = 3000;                                                      /* (a zone takes 3 ms to come: the list takes that long for each zone it has) */
    db_store_test_hot_hook = hot_order_hook;
    db_store_hot_start();
    /* the queries come first: a query for the zone at the end of the list is attached by its own request while the list is still being worked through */
    store_zone_t lz;
    char lname[300];
    store_read_lock();
    CHECK(store_zone_get(st, want[nwant - 1], &lz) == 0);
    store_read_unlock();
    snprintf(lname, sizeof(lname), "%s.", lz.name);
    for (int t = 0; t < 500 && atomic_load(&g_hot_nseen) < 2; t++) usleep(2000);
    CHECK(atomic_load(&g_hot_nseen) >= 2 && atomic_load(&g_hot_nseen) < (int)nwant - 1);        /* (it is running, and far from the end) */
    static wk_t wk;
    wk_init(&wk);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    wk_send(&wk, lname, 6);
    uint8_t got[1232];
    int glen = 0;
    CHECK(wk.w.n_tx == 1 || wk_wait_answer(&wk, got, &glen, 3000));              /* (the worker attached it itself, or a store thread did: not after the list) */
    clock_gettime(CLOCK_MONOTONIC, &t1);
    db_store_counters(&c);
    CHECK(c.hot_state == 1);                                                      /* (the list is not done) */
    CHECK((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < (long)(nwant * 3 / 2));
    wk_free(&wk);
    for (int t = 0; t < 2500; t++) {                                              /* (the list ends) */
        db_store_counters(&c);
        if (c.hot_state != 1) break;
        usleep(4000);
    }
    if (c.hot_state != 2 || atomic_load(&g_hot_nseen) != (int)nwant) printf("  hot: state %llu seen %d of %zu, attached %llu skipped %llu\n", (unsigned long long)c.hot_state, atomic_load(&g_hot_nseen), nwant, (unsigned long long)c.hot_attached, (unsigned long long)c.hot_skipped);
    printf("  hot: state %llu, attached %llu, skipped %llu of %zu zones, in memory %zu\n", (unsigned long long)c.hot_state, (unsigned long long)c.hot_attached, (unsigned long long)c.hot_skipped, nwant, dbdir()->attach_count());
    CHECK(c.hot_state == 2 && atomic_load(&g_hot_nseen) == (int)nwant);           /* (2: done) */
    bool inorder = true;
    for (size_t i = 0; i < nwant && i < 8192; i++) inorder = inorder && g_hot_seen[i] == want[i];
    CHECK(inorder);                                                              /* (in the order of the list) */
    CHECK(c.hot_attached + c.hot_skipped == nwant && c.hot_skipped >= 1);              /* (the zone that the query attached was in memory when the list came to it) */
    const size_t in_mem = dbdir()->attach_count();
    CHECK(in_mem + 8 >= nwant);                                                       /* (every zone of the list is in memory now, but the few that the configuration shadows, and the name servers' zones that an attach brings) */
    uint8_t out[1232];
    CHECK(ask_engine(&g_wctx, &g_cc, "www.wq5.test.", 1, out) > 12 && (out[3] & 0x0F) == 0);
    {
        zref_t zr;
        memset(&zr, 0, sizeof(zr));
        const int xv = store_view_id(st, KARIDNS_XFR_STORE_VIEW);
        CHECK(xv >= 0 && g_hot_xklen > 0);
        CHECK(!(dbdir()->find(xv, g_hot_xkey, (size_t)g_hot_xklen, &zr) && zr.el));              /* (the copy on the list was not attached as a zone: it is the skipped one besides the query's) */
        CHECK(c.hot_skipped >= 2);
    }
    db_store_test_hot_hook = NULL;
    db_store_stop();
    db_store_counters(&c);
    CHECK(c.hot_written == 2 && in_mem + 8 >= nwant);                                 /* (0.7 fix D: the two zones that a query was answered from, the one at the end of the list and wq5; the ones the list attached have none) */
    free(want);
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
/* 0.7 fix 8, the queries come before the fill: a manifest pass of PN entries, each of which takes 100 us (a hook), is being worked through when a worker asks for a zone of it.  The request is
 * made when the pass has given the thread up (after the page it was in), not when the whole pass is done: the number of entries the thread had done when it sent the request is the measure
 * (without the yield the thread read and handled every page it had before it went to the requests: all PN). */
extern void (*db_ingest_test_fetch_req_hook)(const char *zone);
static _Atomic int g_pent;                                         /* entries of the pass done */
static _Atomic int g_pent_at_req = -1;                             /* ... when the request for m0000.test was sent */
static _Atomic int g_pent_push = -1;                               /* ... when the worker asked */
static void pent_hook(void) {
    int n = atomic_fetch_add(&g_pent, 1) + 1;
    if (n == 1000 && atomic_load(&g_pent_push) < 0) {
        atomic_store(&g_pent_push, n);
        (void)park_fetch_request(0, "default", "m0000.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL);
    }
    usleep(100);
}
static void preq_hook(const char *zone) {
    if (strcmp(zone, "m0000.test.") == 0 && atomic_load(&g_pent_at_req) < 0) atomic_store(&g_pent_at_req, atomic_load(&g_pent));
}

extern int64_t g_ing_fetch_timeout_ms;                                 /* dns_db_ingest.c: 30 s, shortened where a test waits for it */
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
    CHECK(db_store_directory_wait() == (phase <= 1));                                 /* (0.7 fix 8: a store with no list of the zones waits for the first pass; one that has the cursor of an earlier run does not) */
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
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, (phase > 0 ? (phase == 1 ? (KDB_FEAT_STORE | KDB_FEAT_LOOKUP) : KDB_FEAT_STORE) : 0) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
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
        /* 0.7 (secondary store 2.2, 13): a server with a database block and secondaries: their copies are records of the reserved view of the same store (STORE_F_XFR), and none of the database's
         * walks sees them: the reconcile's scan (db_recon_scan(): not even a KNOWN copy is asked of the loader), the inventory, and the lookup of a name in a configured view */
        const int xv = xfr_store_vid();
        char xkey[XFR_KEY_MAX + 1], xkey2[XFR_KEY_MAX + 1];
        const int xkl = xfr_key_make("default", XFR_K_CONFIG, "sec.test.", xkey, sizeof(xkey)), xkl2 = xfr_key_make("default", XFR_K_CONFIG, "known.test.", xkey2, sizeof(xkey2));
        CHECK(xv >= 0 && xv == store_view_id(st, KARIDNS_XFR_STORE_VIEW) && xkl > 0 && xkl2 > 0);
        if (xv >= 0 && xkl > 0 && xkl2 > 0) {
            zone_image_t *ximg = zone_img("sec.test.", 3);
            xfr_state_t xs = { .kind = XFR_K_CONFIG, .identity = 1, .last_ok = 1 };
            store_meta_t xm;
            memset(&xm, 0, sizeof(xm));
            xm.flags = STORE_F_XFR;
            xm.serial = 3;
            xm.stamp_time = 1;
            xfr_state_encode(&xs, xm.digest);
            CHECK(ximg && store_put_ex(st, (uint16_t)xv, xkey, (size_t)xkl, &xm, ximg, ximg->total_size, STORE_PUT_NO_DEGRADE, NULL) == 0);
            zone_image_free(ximg);
            xm.serial = 4;                                                   /* a KNOWN copy (a scrub or a bad image made it so): the reconcile's scan asks the loader for KNOWN records */
            CHECK(store_set_known(st, (uint16_t)xv, xkey2, (size_t)xkl2, &xm, NULL) == 0);
            uint32_t cur = 0;
            db_scan_item_t it;
            int items = 0, rc;
            while ((rc = db_recon_scan(&cur, 64, &it)) != 0)
                if (rc == 1) items++;
            CHECK_MSG(items == 0, "db_recon_scan() gave %d item(s) of a store that holds only secondaries' copies", items);
            zref_t zr;
            memset(&zr, 0, sizeof(zr));
            const int dsid = store_view_id(st, "default");
            CHECK(dsid >= 0);
            CHECK(!dbdir()->find(dsid, "sec.test", 8, &zr) && !dbdir()->find(dsid, xkey, (size_t)xkl, &zr));      /* (the name of a copy is no name of a configured view, and its key is none) */
            CHECK(dbdir()->counters(0) == 0 && dbdir()->counters(1) == 0 && dbdir()->counters(2) == 0);      /* (no zone of the database: the copies are not counted with them) */
        }
        /* the loader that does not offer the protocol gets the inventory as before: INVENTORY_REQ is answered (an inventory of the store: empty) */
        kdb_enc_begin(&e, KDB_T_INVENTORY_REQ);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        bool end = false;
        uint64_t inv_n = 0;
        while (!end && ch_next(&mainc, &m, 5000)) {
            if (m.type == KDB_T_INVENTORY) inv_n += m.u.inventory.n_entries;
            end = m.type == KDB_T_INVENTORY_END;
        }
        CHECK(end);
        CHECK(inv_n == 0 && m.u.inventory_end.n_zones == 0);            /* (the copies are not in the inventory: an inventory with them would tell the loader of zones that it does not have) */
        CHECK(!ch_next(&fetchc, &m, 200));
        goto done;
    }
    uint64_t kn, sd;
    const int vid = store_view_id(st, "default");
    CHECK(vid >= 0);

    if (phase == 1) {
        CHECK(!ch_next(&fetchc, &m, 200));                               /* an empty store has nothing to ask for */

        /* -- A0. the lookup of a name (0.7, FETCH_REQ mode 2) while the first pass has not listed the zones: the loader (this test) answers on the fetch stream, which a pass does not hold up */
        {
            CHECK(db_store_view_pending(vid) && !db_store_view_pending(vid + 1) && !db_store_view_pending(-1));          /* (the view's list of zones is not complete) */
            CHECK(db_ingest_lookup_ready());
            const uint64_t zid_sid = 777000;
            /* a zone is found: recorded as a MANIFEST entry would (KNOWN, with its stamp), and the worker's query for the name is woken (not failed) */
            drain_wakes();
            CHECK(park_fetch_request(0, "default", "www.late.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_LOOKUP && strcmp(m.u.fetch_req.name, "www.late.test.") == 0 &&
                  m.u.fetch_req.priority == KDB_FETCH_PRIO_QUERY && m.u.fetch_req.source_id == 0 && !m.u.fetch_req.has_range);
            const uint64_t rid = m.u.fetch_req.request_id;
            CHECK(park_fetch_request(0, "default", "www.late.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));     /* (the same name again: one request on the stream) */
            CHECK(!ch_next(&fetchc, &m, 300));
            CHECK(lk_stats().same_name == 1 && lk_stats().in_flight == 1 && park_places_used() == 1);       /* (the duplicate took nothing: one place, for the request that is out) */
            kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
            kdb_enc_u64(&e, 1, rid + 1000); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);      /* (an answer of no request is discarded; the stream goes on) */
            kdb_enc_end(&e);
            ch_send(f[0], &e);
            kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
            kdb_enc_u64(&e, 1, rid); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 1);
            kdb_enc_i64(&e, 4, (int64_t)zid_sid); kdb_enc_name(&e, 5, "late.test."); kdb_enc_u8(&e, 6, KDB_ZK_PRIMARY); kdb_enc_u64(&e, 7, 5); kdb_enc_u64(&e, 8, 6); kdb_enc_u8(&e, 9, KDB_EF_STAMPED);
            kdb_enc_end(&e);
            ch_send(f[0], &e);
            CHECK(wake_for("www.late.test.", &k, 5000) && !k.failed && !k.retry);
            CHECK(places_are(0, 2000) && lk_stats().in_flight == 0);
            {
                store_zone_t lz;
                CHECK(zrec(st, "late.test", &lz) && lz.state == STORE_STATE_KNOWN && lz.source_id == (int64_t)zid_sid && lz.stamp_gen == 5 && lz.stamp_time == 6);
                zref_t zr;
                CHECK(zref_of("late.test.", &zr) && zr.entry == NULL && zr.zid != ZREF_NOZID && zr.zstate == ZREF_ST_KNOWN);      /* (the query is looked up again: the zone is there, to be read) */
                CHECK(db_recon_delete("default", (int64_t)zid_sid, NULL) == 1);       /* (not a zone of the pass that follows: the scan of the wanted bodies would ask for its body) */
            }
            /* a loader that announced no KDB_FEAT_LOOKUP_BODY is asked in mode 2 (above) and a body that it sends after the answer all the same is no part of the request (it ended with the answer): thrown away, and
             * the stream goes on.  Mode 3 is never sent to it. */
            {
                const uint64_t bad0 = lk_stats().bad_body;
                send_zone(f[0], &e, "late.test.", 3, rid, (int64_t)zid_sid);
                usleep(300000);
                CHECK(!in_memory("late.test.") && lk_stats().body_inline == 0 && lk_stats().bad_body == bad0);
            }
            /* no zone has the name: nothing is recorded; the query is woken, and answered as for any name that is not served */
            drain_wakes();
            CHECK(park_fetch_request(0, "default", "nothing.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_LOOKUP && strcmp(m.u.fetch_req.name, "nothing.test.") == 0);
            kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
            kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(f[0], &e);
            CHECK(wake_for("nothing.test.", &k, 5000) && !k.failed && !k.retry);
            CHECK(places_are(0, 2000) && lk_stats().in_flight == 0);
            {
                zref_t zr;
                CHECK(!zref_of("nothing.test.", &zr));
            }
            /* a loader that names a zone that does not enclose the name (or the root) is not believed: nothing is recorded, the query is woken */
            for (int bad = 0; bad < 2; bad++) {
                drain_wakes();
                CHECK(park_fetch_request(0, "default", "www.evil.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
                CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "www.evil.test.") == 0);
                kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 1);
                kdb_enc_i64(&e, 4, 888000 + bad); kdb_enc_name(&e, 5, bad ? "." : "other.test."); kdb_enc_u8(&e, 6, KDB_ZK_PRIMARY); kdb_enc_u64(&e, 7, 1); kdb_enc_u64(&e, 8, 1);
                kdb_enc_end(&e);
                ch_send(f[0], &e);
                CHECK(wake_for("www.evil.test.", &k, 5000) && k.failed);              /* (a loader that cannot be believed: the lookup failed, the queries are told "not ready") */
                CHECK(places_are(0, 2000) && lk_stats().in_flight == 0);
                store_zone_t lz;
                CHECK(!zrec(st, "other.test", &lz));
            }
            /* a database error (ZONE_FAILED with the request id) fails the lookup: the queries are told "not ready" (SERVFAIL + EDE 14, as for the fetch of a zone that fails), and nothing is recorded */
            drain_wakes();
            CHECK(park_fetch_request(0, "default", "x.fail.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "x.fail.test.") == 0);
            kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
            kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "x.fail.test."); kdb_enc_i64(&e, 3, 0); kdb_enc_str(&e, 4, "looking up the zone of a name: the database is busy"); kdb_enc_u64(&e, 5, m.u.fetch_req.request_id);
            kdb_enc_end(&e);
            ch_send(f[0], &e);
            CHECK(wake_for("x.fail.test.", &k, 5000) && k.failed);
            CHECK(places_are(0, 2000) && lk_stats().in_flight == 0);
            /* a name the stream cannot carry (a request of a worker is checked before it is sent: a name the loader's decoder refuses would close the stream) is woken without a request */
            drain_wakes();
            CHECK(park_fetch_request(0, "default", "No.Dot", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
            CHECK(wake_for("No.Dot", &k, 5000) && !k.failed && !ch_next(&fetchc, &m, 200));
            CHECK(places_are(0, 2000) && lk_stats().in_flight == 0);
            /* a view the configuration does not have: no request */
            drain_wakes();
            CHECK(park_fetch_request(0, "noview", "a.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
            usleep(300000);                                                                   /* (woken by the name of that view: wake_for() looks at "default" only) */
            CHECK(places_are(0, 2000) && !ch_next(&fetchc, &m, 200));
            /* a request that the loader does not answer ends as a failure of the lookup: the query is woken, the place is given back */
            drain_wakes();
            g_ing_fetch_timeout_ms = 300;
            CHECK(park_fetch_request(0, "default", "slow.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "slow.test.") == 0);
            CHECK(wake_for("slow.test.", &k, 12000) && k.failed);
            g_ing_fetch_timeout_ms = 30000;
            CHECK(places_are(0, 2000) && lk_stats().failed >= 1);
            /* the worker's side (udp_one(): lookup_wanted(), udp_park_lookup()): a query for a name of a zone the pass has not listed is parked for the lookup, not refused; the zone that is found is read as any zone
             * that the store knows without a body, and the query is answered from it */
            {
                static wk_t lw;
                wk_init(&lw);
                uint8_t lgot[1232];
                int llen = 0;
                drain_wakes();
                wk_send(&lw, "late2.test.", 6);                                             /* (SOA) */
                CHECK(lw.w.n_tx == 0 && lw.table.nwait == 1 && lw.table.nlook == 1 && places_are(1, 2000));
                CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_LOOKUP && strcmp(m.u.fetch_req.name, "late2.test.") == 0);
                kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 1);
                kdb_enc_i64(&e, 4, 777100); kdb_enc_name(&e, 5, "late2.test."); kdb_enc_u8(&e, 6, KDB_ZK_PRIMARY); kdb_enc_u64(&e, 7, 1); kdb_enc_u64(&e, 8, 1); kdb_enc_u8(&e, 9, KDB_EF_STAMPED);
                kdb_enc_end(&e);
                ch_send(f[0], &e);
                bool got_req = false;
                for (int t = 0; t < 2500 && !got_req; t++) {                                  /* (the wake-up: the worker looks the query up again and parks it for the zone that is known now) */
                    rcu_aux_read_lock();
                    park_service(&lw.w, -1);
                    rcu_aux_read_unlock();
                    got_req = ch_next(&fetchc, &m, 2);
                }
                CHECK(got_req && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_FULL && strcmp(m.u.fetch_req.name, "late2.test.") == 0 && m.u.fetch_req.source_id == 777100);
                send_zone(f[0], &e, "late2.test.", 3, m.u.fetch_req.request_id, 777100);
                CHECK(wk_wait_answer(&lw, lgot, &llen, 5000) && llen > 12 && (lgot[3] & 0x0F) == 0 && (lgot[2] & 0x04) != 0);        /* (NOERROR, authoritative) */
                CHECK(places_are(0, 2000) && lw.table.nwait == 0 && lw.table.nlook == 0);
                CHECK(db_recon_delete("default", 777100, NULL) == 1);
                /* no zone: the query is refused when the answer comes (the normal answer for a name that is not served) */
                wk_send(&lw, "nothing2.test.", 1);
                CHECK(lw.w.n_tx == 0 && lw.table.nwait == 1);
                CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_LOOKUP && strcmp(m.u.fetch_req.name, "nothing2.test.") == 0);
                kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
                kdb_enc_end(&e);
                ch_send(f[0], &e);
                CHECK(wk_wait_answer(&lw, lgot, &llen, 5000) && (lgot[3] & 0x0F) == 5);          /* (REFUSED) */
                CHECK(places_are(0, 2000) && lw.table.nwait == 0);
                /* the same name asked twice by one worker is one request (the second query joins the first), and a DS query asks for the parent of its name */
                wk_send(&lw, "dup.nothing2.test.", 1);
                wk_send(&lw, "dup.nothing2.test.", 1);
                CHECK(lw.w.n_tx == 0 && lw.table.nwait == 2 && lw.table.nlook == 2 && places_are(1, 2000));
                CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "dup.nothing2.test.") == 0);
                CHECK(!ch_next(&fetchc, &m, 200));
                kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
                kdb_enc_end(&e);
                ch_send(f[0], &e);
                CHECK(wk_wait_answer(&lw, lgot, &llen, 5000) && (lgot[3] & 0x0F) == 5);
                CHECK(wk_wait_answer(&lw, lgot, &llen, 5000) && (lgot[3] & 0x0F) == 5 && lw.table.nwait == 0);
                wk_send(&lw, "ds.nothing3.test.", 43);
                CHECK(lw.table.nwait == 1);
                CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "nothing3.test.") == 0);        /* (the zone of a DS is the parent's) */
                kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
                kdb_enc_end(&e);
                ch_send(f[0], &e);
                CHECK(wk_wait_answer(&lw, lgot, &llen, 5000) && (lgot[3] & 0x0F) == 5);
                /* many lookups at once (the old window of 32 is gone): none is refused for the lack of a place; the ones that get no place now wait for one (fetch-concurrency 16, the lookups may hold 12 of them) and
                 * the query is parked all the same, answered when its lookup is */
                {
                    enum { NLK = 40 };
                    drain_wakes();
                    for (int i = 0; i < NLK; i++) {
                        char nm[64];
                        snprintf(nm, sizeof(nm), "w%d.many.test.", i);
                        wk_send(&lw, nm, 1);
                    }
                    CHECK(lw.w.n_tx == 0 && lw.table.nwait == NLK && lw.table.nlook == NLK);
                    int got = 0;
                    uint64_t rids[NLK];
                    while (got < NLK && ch_next(&fetchc, &m, got < 12 ? 5000 : 300)) {
                        if (m.type != KDB_T_FETCH_REQ || m.u.fetch_req.mode != KDB_FETCH_LOOKUP) break;
                        rids[got++] = m.u.fetch_req.request_id;
                    }
                    printf("  (%d of %d lookups were sent at once; the others wait for a place)\n", got, NLK);
                    CHECK(got >= 4 && got <= 12);                                                    /* (a share of the places: not all, not none) */
                    CHECK(lk_stats().in_flight == (uint64_t)got && lk_stats().pending == (uint64_t)(NLK - got) && places_are((uint32_t)got, 2000));
                    for (int i = 0; i < got; i++) {                                                    /* (each answer frees its place at once; the next request goes out) */
                        kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                        kdb_enc_u64(&e, 1, rids[i]); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
                        kdb_enc_end(&e);
                        ch_send(f[0], &e);
                    }
                    int more = 0;
                    while (more < NLK - got && ch_next(&fetchc, &m, 3000) && m.type == KDB_T_FETCH_REQ) {      /* (the queue goes out as the places come back) */
                                                kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
                        kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
                        kdb_enc_end(&e);
                        ch_send(f[0], &e);
                        more++;
                    }
                    CHECK(got + more == NLK);
                    int refused = 0;
                    while (refused < NLK && wk_wait_answer(&lw, lgot, &llen, 5000) && (lgot[3] & 0x0F) == 5) refused++;
                    CHECK(refused == NLK && lw.table.nwait == 0 && lw.table.nlook == 0);                /* (REFUSED when the zone is not there, as for any name: never for the lack of a place) */
                    CHECK(places_are(0, 3000) && lk_stats().pending == 0 && lk_stats().in_flight == 0 && lk_stats().none >= (uint64_t)NLK);
                }
                park_free(&lw.table);
            }
        }

        /* -- A. the first fill: a pass.  BATCH_RESULT comes when the entries are recorded, the bodies follow.  A worker asks for a zone of the pass while it is being worked through (the hooks): the thread
         *       gives the stream up for the request after the page it is in, it does not finish the pass first */
        db_recon_test_entry_hook = pent_hook;
        db_ingest_test_fetch_req_hook = preq_hook;
        p_batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP, 0);
        full_pass(a[0], &e, 1, NULL, 77, true);
        p_batch_end(a[0], &e, 1, PN, 0);
        CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_applied == PN && m.u.batch_result.n_rejected == 0);
        db_recon_test_entry_hook = NULL;
        db_ingest_test_fetch_req_hook = NULL;
        CHECK(!db_store_directory_wait());                                              /* (the pass has ended: every zone is listed) */
        {                                                                               /* once the pass has ended an unknown name is refused at once: nothing is parked, no lookup is asked for */
            static wk_t lw2;
            wk_init(&lw2);
            uint8_t g2[1232];
            const uint64_t lk0 = lk_stats().asked;
            wk_send(&lw2, "after.nothing5.test.", 1);
            CHECK(lw2.w.n_tx == 1 && lw2.table.nwait == 0 && wk_get(&lw2, g2) > 12 && (g2[3] & 0x0F) == 5 && lk_stats().asked == lk0);
            park_free(&lw2.table);
        }
        {
            const int at = atomic_load(&g_pent_at_req), pushed = atomic_load(&g_pent_push);
            printf("  the request of a worker, made at entry %d of %d, was sent at entry %d\n", pushed, PN, at);
            CHECK(pushed == 1000 && at >= pushed && at < PN - 1500);                       /* (after the page it was in: 2048; not at the end of the pass: 5000) */
        }
        store_counts(st, &kn, &sd);
        CHECK(kn == PN && sd == 0);                                      /* (no body has come: the loader is not answering yet) */
        CHECK(cursor_is(st, 77));                                        /* (the cursor is kept once the entries are recorded) */
        {
            store_zone_t z;
            CHECK(zrec(st, "m0010.test", &z) && z.state == STORE_STATE_KNOWN && z.source_id == p_sid(10) && z.stamp_gen == 1 && z.stamp_time == 10);
            zref_t zr;
            CHECK(zref_of("m4000.test.", &zr) && zr.entry == NULL && zr.zid != ZREF_NOZID && zr.zstate == ZREF_ST_KNOWN);      /* (the name index is complete: the zone is known) */
        }
        /* -- A1. the queries come first, and the fill has a share of its own (0.7 fix 8): forty queries ask for zones of the pass; the loader answers the requests of the fill at once and the
         *        requests of the queries not at all.  The places of fetch-concurrency (16) are not all the queries': they have 12 at the most, and the fill goes on (before, it was held back while
         *        a query waited, and the loader saw the 8 requests it had had before the queries came and no more) */
        drain_wakes();
        {
            enum { NQ1 = 40 };
            typedef struct { char name[24]; uint64_t id; int64_t sid; uint8_t prio; } req1_t;
            static req1_t rq1[64];
            int nrq1 = 0, nq = 0, nb = 0, fill_asked = 0;
            for (int i = 0; i < NQ1; i++) {
                char zn[24];
                pn_name(zn, sizeof(zn), 2000 + i);
                CHECK(park_fetch_request(0, "default", zn, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            }
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            do {
                if (ch_next(&fetchc, &m, 20) && m.type == KDB_T_FETCH_REQ) {
                    const int zi = pn_index(m.u.fetch_req.name);
                    CHECK_MSG(zi >= 0 && zi < PN, "a request for %s (mode %d)", m.u.fetch_req.name, (int)m.u.fetch_req.mode);
                    if (m.u.fetch_req.priority == KDB_FETCH_PRIO_QUERY) {
                        if (nrq1 < 64) {
                            req1_t *q = &rq1[nrq1++];
                            snprintf(q->name, sizeof(q->name), "%s", m.u.fetch_req.name);
                            q->id = m.u.fetch_req.request_id;
                            q->sid = m.u.fetch_req.source_id;
                            q->prio = m.u.fetch_req.priority;
                        }
                        nq++;
                    } else {
                        nb++;
                        if (zi >= 0 && zi < PN) {
                            g_pasked[zi]++;
                            g_pprio[zi] = m.u.fetch_req.priority;
                            g_psid[zi] = m.u.fetch_req.source_id;
                            send_zone(f[0], &e, m.u.fetch_req.name, g_pserial[zi] ? g_pserial[zi] : 1, m.u.fetch_req.request_id, m.u.fetch_req.source_id);
                        }
                    }
                }
                clock_gettime(CLOCK_MONOTONIC, &t1);
            } while (nb < 200 && (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < 600);
            fill_asked = nb;
            printf("  40 queries waiting, none answered: %d requests of queries, %d of the fill in 600 ms\n", nq, fill_asked);
            CHECK(nq >= 4 && nq <= 12);                                                    /* (the queries have the places the fill's share leaves) */
            CHECK(fill_asked >= 100);                                                      /* (the fill went on: its fetches are answered and made again, whatever waits) */
            for (int i = 0; i < nrq1; i++) {                                                  /* (the queries are answered now) */
                const int zi = pn_index(rq1[i].name);
                CHECK(zi >= 0 && zi < PN);
                g_pasked[zi]++;
                g_pprio[zi] = rq1[i].prio;
                g_psid[zi] = rq1[i].sid;
                send_zone(f[0], &e, rq1[i].name, g_pserial[zi] ? g_pserial[zi] : 1, rq1[i].id, rq1[i].sid);
            }
        }
        /* a query for a zone that is known and has no body goes to the fetch queue (priority 0, with the domain id) and is answered */
        drain_wakes();
        CHECK(park_fetch_request(0, "default", "m4000.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
        int n = serve_fetches(&fetchc, f[0], &e, 1500, -1, -1);
        CHECK(n >= PN - 400);                                          /* (the 200 or so that A1 answered are not in the count) */
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
        CHECK(!in_memory("m0010.test.") || evict_zone("m0010.test."));   /* (0.7 M3: a body of the fill is not attached by itself; the zone whose stamp changes is out of memory: its NOTIFY is queued when the new body is installed, as for a summary before) */
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
        test_exit(g_failed ? 1 : 0);                                         /* (no clean stop: the next start recovers the store from its journal) */
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
    {
        /* the report of one zone asks the server whether it is in memory (store.zone.attached), and the scan of the wanted bodies is put back for a zone whose body could not be fetched */
        static char zr[STORE_STATUS_OUT_MAX];
        CHECK(store_status_format(zr, sizeof(zr), STORE_FMT_KV, "m0600.test") > 0 && strstr(zr, "store.zone.attached=") != NULL);
        db_recon_status_t fs;
        db_recon_status(&fs);
        CHECK(db_store_filling() == (fs.known_now > 0 && (fs.active || fs.in_flight > 0)));      /* (a first fill: zones without an image and a pass or the fetch of their bodies running) */
        db_recon_scan_retry(7);
        db_recon_scan_retry(0xF0000001u);
        /* a view that the store did not know when it was opened (the configuration was reloaded with a new view) is added by its first zone, and its identity is noted */
        db_recon_entry_t re;
        memset(&re, 0, sizeof(re));
        re.source_id = 900001;
        re.name = "newview.test.";
        re.kind = KDB_ZK_PRIMARY;
        re.stamped = true;
        re.gen = 1;
        re.time = 1;
        uint32_t zid = STORE_NONE;
        const int vr = db_recon_change("viewb", &re, &zid);
        CHECK(vr >= 0 && store_view_id(st, "viewb") >= 0);
    }
done:
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    test_exit(g_failed ? 1 : 0);
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
static _Atomic int g_dbs_jw_nospc;                                     /* 0.7: the journal ring's write meets ENOSPC while it is set */
static int dbs_jw_fault(uint64_t pos, uint64_t len) { (void)pos; (void)len; return atomic_load(&g_dbs_jw_nospc) ? ENOSPC : 0; }

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

typedef struct { char name[64]; uint64_t id; int64_t sid; } rq_t;
/* the FETCH_REQs that come within `ms` of silence */
/* The requests that the ingest thread makes of the loader, until it is quiet.  The first one is waited for `ms` (it may take a batch, a tick); once one has come the others follow within a few
 * milliseconds, so the quiet that ends the collection is a fifth of that (at least 300 ms) and not `ms` again: with the full time after every request the cases of this test spent 26 s of a
 * minute doing nothing.  KARIDNS_STORE_LONG=1 keeps the full time. */
static int rq_collect(ch_t *fc, rq_t *out, int max, int ms) {
    int n = 0;
    kdb_msg_t m;
    const char *lg = getenv("KARIDNS_STORE_LONG");
    const int quiet = lg && lg[0] == '1' ? ms : (ms / 5 < 300 ? 300 : ms / 5);
    int wait = ms;
    while (ch_next(fc, &m, wait)) {
        if (m.type == KDB_T_FETCH_REQ) wait = quiet;
        if (m.type != KDB_T_FETCH_REQ || n >= max) continue;
        snprintf(out[n].name, sizeof(out[n].name), "%s", m.u.fetch_req.name);
        out[n].id = m.u.fetch_req.request_id;
        out[n].sid = m.u.fetch_req.source_id;
        n++;
    }
    return n;
}

static bool wait_rec(store_t *st, const char *name, uint8_t state, uint32_t serial, uint64_t gen, bool stale, int ms);
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
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_STORE | KDB_FEAT_BATCH_STATUS | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
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

    /* -- 0.7 M3: the bodies of a first fill, which nobody waits for, are stored as the images they are: no entry is made, the registry does not change, and the counters say so.  The first query
     *    (db_store_attach_zone(): what a worker does) attaches the zone from its record. */
    {
        store_fill_t sf;
        CHECK(db_ingest_fill_stats(&sf));
        CHECK_MSG(sf.images >= (uint64_t)NF && sf.store_only >= (uint64_t)NF && sf.resident == 0 && sf.invalid == 0 && sf.image_bytes >= (uint64_t)NF * sizeof(zone_image_t) && sf.validate_ns > 0,
                  "store.fill: images %llu, store_only %llu, resident %llu, invalid %llu, bytes %llu", (unsigned long long)sf.images, (unsigned long long)sf.store_only, (unsigned long long)sf.resident,
                  (unsigned long long)sf.invalid, (unsigned long long)sf.image_bytes);
        CHECK(!in_memory("m0007.test.") && dbreg_lookup_entry("default", "m0007.test.") == NULL);
        db_store_attach_zone("default", "m0007.test.");
        for (int i = 0; i < 500 && !in_memory("m0007.test."); i++) usleep(10000);
        CHECK(in_memory("m0007.test.") && dbreg_lookup_entry("default", "m0007.test.") != NULL);
    }

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

    /* -- 0.7: the store cannot make a batch durable (its journal meets ENOSPC at the batch end): BATCH_RESULT says so in tag 7 (this loader has KDB_FEAT_BATCH_STATUS), the counter
     *    and the status show it; once the journal is written again the next batch is answered as recorded */
    {
      db_recon_status_t rs0, rs1;
      db_recon_status(&rs0);
      p_batch_begin(a[0], &e, 40, KDB_BATCH_AUTO, 0);
      fx_pass(a[0], &e, 40, NF, omit, 350, true);
      atomic_store(&g_dbs_jw_nospc, 1);
      store_test_jw_fault = dbs_jw_fault;
      p_batch_end(a[0], &e, 40, NF - 1, 0);
      CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.batch_id == 40 && m.u.batch_result.store_error == ENOSPC);
      db_recon_status(&rs1);
      CHECK(rs1.batch_store_errors == rs0.batch_store_errors + 1 && rs1.batch_store_last == -ENOSPC);
      atomic_store(&g_dbs_jw_nospc, 0);                                 /* the room comes back: the flusher writes the journal again */
      store_stats_t ss;
      for (int w = 0; w < 5000; w++) { store_stats(st, &ss); if (ss.journal_state == STORE_JOURNAL_OK) break; usleep(1000); }
      CHECK(ss.journal_state == STORE_JOURNAL_OK);
      store_test_jw_fault = NULL;
      p_batch_begin(a[0], &e, 41, KDB_BATCH_AUTO, 0);
      fx_pass(a[0], &e, 41, NF, omit, 360, true);
      p_batch_end(a[0], &e, 41, NF - 1, 0);
      CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.batch_id == 41 && m.u.batch_result.store_error == 0);
      CHECK(cursor_is(st, 360));
    }

    /* -- H1: the bit of a zone that the pass lists cannot be set (no memory): the same, nothing is swept */
    omit[1101] = true;
    db_store_test_bits_fail = 4;
    p_batch_begin(a[0], &e, 4, KDB_BATCH_AUTO, 0);
    fx_pass(a[0], &e, 4, NF, omit, 400, true);
    p_batch_end(a[0], &e, 4, NF - 2, 0);
    CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.n_deleted == 0);
    CHECK(zrec(st, "m1101.test", &z) && zones_now(st) == NF - 1 && cursor_is(st, 360));
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

    /* -- L11: the loader's estimate is a claim.  A first fill reserves what the loader announces (round 10: the whole estimate, so that a fill of 10M zones grows the index no more than once), up to what
     *    memory-limit can give the two indexes (a quarter of it at 43 bytes a zone) and the address space of the tables; a loader that claims four million zones with a limit that holds 1.5 million
     *    makes the store reserve about that, not four million records */
    {
        char why[200];
        store_stats_t s1;
        dbreg_cache_set_limit(1500000ull * 43 * 4);
        CHECK(db_recon_begin("default", 4000000, false, why, sizeof(why)));
        store_stats(st, &s1);
        CHECK(s1.zt_capacity >= 1400000 && s1.zt_capacity < 3000000);
        CHECK(s1.ix_slots >= 1400000 * 8 / 3 && s1.ix_slots < 3000000 * 8 / 3);
        db_recon_abort();
        dbreg_cache_set_limit(0);
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
    /* -- L13 (review of M3): the limits of the configuration on the store-only path.  The bodies of the first fill, which nobody waits for, go to the store as images; max-records, max-records-per-type,
     *    max-types-per-name and max-zone-ttl must refuse them there as they refuse a zone that is installed (dns_db_ingest.c job_execute(): zone_limits_gate_settings()).  Five new zones are listed; the
     *    loader sends a zone within the limits and four that break one limit each, and only the first is stored (the others stay known, without an image) */
    {
        static server_config_t cfgl;
        char confl[2048];
        snprintf(confl, sizeof(confl),
                 "options { max-records 8; max-records-per-type 3; max-types-per-name 4; max-zone-ttl 600; database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
                 "store-threads 2; }; };\n"
                 "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
        CHECK(parse_named_conf(confl, &cfgl) == 0);
        atomic_store_explicit(&g_config_db.active, &cfgl, memory_order_release);
        memset(omit, 0, sizeof(omit));
        p_batch_begin(a[0], &e, 13, KDB_BATCH_AUTO, 0);
        fx_pass(a[0], &e, 13, NF + 100 + 5, omit, 9000, false);                  /* (zones 1300..1304 are new; the others are unchanged or known already) */
        p_batch_end(a[0], &e, 13, NF + 100 + 5, 0);
        CHECK(p_result(&mainc, &m, 10000));
        static const char *const HD = "@ SOA ns1 host 1 3600 600 86400 300\n@ NS ns1\n";
        const char *const body[5] = {
            "www A 192.0.2.1\n",                                                                                      /* 3 records: within every limit */
            "a1 A 192.0.2.1\na2 A 192.0.2.2\na3 A 192.0.2.3\na4 A 192.0.2.4\na5 A 192.0.2.5\na6 A 192.0.2.6\na7 A 192.0.2.7\n",   /* 9 records: above max-records 8 */
            "x A 192.0.2.1\nx A 192.0.2.2\nx A 192.0.2.3\nx A 192.0.2.4\n",                                           /* 4 A RRs at one name: above max-records-per-type 3 */
            "t A 192.0.2.1\nt AAAA 2001:db8::1\nt TXT \"a\"\nt MX 10 ns1\nt HINFO \"a\" \"b\"\n",                      /* 5 types at one name: above max-types-per-name 4 */
            "www A 192.0.2.1\n",                                                                                      /* ($TTL 700 below: above max-zone-ttl 600) */
        };
        rq_t rq[200];
        const int nrq = rq_collect(&fetchc, rq, 200, 3000);
        CHECK(nrq >= 5);
        for (int i = 0; i < nrq; i++) {
            const int idx = pn_index(rq[i].name);
            if (idx >= NF + 100 && idx < NF + 105) {
                char apex[40], text[2000];
                snprintf(apex, sizeof(apex), "%s", rq[i].name);
                snprintf(text, sizeof(text), "$ORIGIN %s\n$TTL %d\n%s%s", apex, idx == NF + 104 ? 700 : 300, HD, body[idx - NF - 100]);
                zone_image_t *img = zi_from_text(apex, text);
                CHECK(img != NULL);
                if (!img) continue;
                zi_zone_msgs(&e, 0, apex, rq[i].sid, 1, img, rq[i].id, NULL, NULL, 0, 1);
                zone_image_free(img);
                ch_send(f[0], &e);
            } else {
                send_zone(f[0], &e, rq[i].name, g_pserial[idx >= 0 && idx < PN + 16 ? idx : 0] ? g_pserial[idx >= 0 && idx < PN + 16 ? idx : 0] : 1, rq[i].id, rq[i].sid);
            }
        }
        CHECK(wait_rec(st, "m1300.test", STORE_STATE_STORED, 1, 1, false, 5000));                                  /* (within the limits: stored) */
        usleep(500000);
        for (int k = 1; k < 5; k++) {
            char nm[40];
            snprintf(nm, sizeof(nm), "m%04d.test", NF + 100 + k);
            CHECK_MSG(zrec(st, nm, &z) && z.state == STORE_STATE_KNOWN, "%s is over a limit: its body was not stored (state %d)", nm, zrec(st, nm, &z) ? (int)z.state : -1);
        }
        /* a limit that was tightened after the image was stored: the attach checks the image against the limits as they are now (before: it attached unchecked, a zone over max-records served for ever).  The zone is set back
         * to known, to be read from the database again, where its body is refused with the reason */
        {
            static server_config_t cfgt;
            char conft[2048];
            snprintf(conft, sizeof(conft),
                     "options { max-records 2; database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
                     "store-threads 2; }; };\n"
                     "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
            CHECK(parse_named_conf(conft, &cfgt) == 0);
            atomic_store_explicit(&g_config_db.active, &cfgt, memory_order_release);
            char att[40] = "";                                                                                 /* (a zone of the first fill that is only in the store: its body went there as an image, no entry was made) */
            for (int i = 100; i < 400 && !att[0]; i++) {
                char cand[40];
                snprintf(cand, sizeof(cand), "m%04d.test.", i);
                if (stored_only(cand)) snprintf(att, sizeof(att), "%s", cand);
            }
            CHECK(att[0] != '\0');
            db_store_attach_zone("default", att);
            usleep(700000);
            { char nm_[40]; snprintf(nm_, sizeof(nm_), "%.*s", (int)strlen(att) - 1, att); CHECK_MSG(!in_memory(att) && zrec(st, nm_, &z) && z.state == STORE_STATE_KNOWN, "%s is over the tightened limit: not attached, set back to known", att); }
            (void)rq_collect(&fetchc, rq, 200, 500);                                       /* (the zone is asked for again: nobody answers here) */
        }
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        (void)serve_fetches(&fetchc, f[0], &e, 300, -1, -1);
    }

    store_test_write_fault = NULL;
    db_store_batch_end();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    test_exit(g_failed ? 1 : 0);
}

/* ---------------------------------------------------------------- phase 6: a fetched body is installed only for the stamp it was asked for */
/* ingest-threads 2.  The check "the record still has the stamp the request was made for" (job_execute()) is made before the install, which takes a long time; the ingest thread (a CHANGES or manifest
 * entry, a delete) does not wait for the builders.  The version that dbreg_commit() puts in the store gets the record's stamp, so before the fix an older body was installed under the newer stamp (the record
 * said "current" and nothing fetched the zone again), and a zone that was deleted in between was written back.  The test hook of db_store_commit_begin() runs the other writer in the window, in a thread of its
 * own, while two builders have a body each in hand: the newer stamp always wins, a zone that was deleted stays deleted, a body that was dropped is asked for again, and a writer that comes while the commit holds
 * the step waits for it.  The same for a zone the store cannot name (the root zone: a zone of the heap directory). */
enum { HK_UPSERT = 1, HK_DELETE, HK_INNER, HK_FAULT };
typedef struct {
    const char *zone;                   /* with the trailing dot */
    int act;
    int64_t sid;
    uint64_t gen, time;                 /* the stamp the other writer records */
    _Atomic bool used, mover_done, started, blocked_seen;
    pthread_t th;
} hk_t;
#define HK_MAX 8
static hk_t g_hk[HK_MAX];
static int g_hk_n;
static _Atomic int g_hk_arrived, g_hk_expect;
static _Atomic bool g_hk_timeout;

static void *hk_mover(void *arg) {
    hk_t *h = arg;
    if (h->act == HK_DELETE) {
        (void)db_recon_delete("default", h->sid, h->zone);
    } else {
        db_recon_entry_t re;
        memset(&re, 0, sizeof(re));
        re.source_id = h->sid;
        re.name = h->zone;
        re.kind = KDB_ZK_PRIMARY;
        re.stamped = true;
        re.gen = h->gen;
        re.time = h->time;
        uint32_t zid;
        (void)db_recon_change("default", &re, &zid);
    }
    atomic_store(&h->mover_done, true);
    return NULL;
}

static void hk_start(hk_t *h) {
    if (pthread_create(&h->th, NULL, hk_mover, h) == 0) atomic_store(&h->started, true);
}

static pthread_mutex_t g_hk_mu = PTHREAD_MUTEX_INITIALIZER;        /* (the table is set by the test thread and read by the builders: the socket between them is no synchronization TSan knows) */
static void race_hook(int where, const char *zone) {
    hk_t *h = NULL;
    pthread_mutex_lock(&g_hk_mu);
    for (int i = 0; i < g_hk_n && !h; i++)
        if (g_hk[i].zone && strcmp(g_hk[i].zone, zone) == 0 && !atomic_load(&g_hk[i].used)) {
            h = &g_hk[i];
            if (h->act != HK_INNER || where == 1) atomic_store(&h->used, true);          /* (this call takes the case; an inner one is taken inside the step) */
        }
    pthread_mutex_unlock(&g_hk_mu);
    if (!h) return;
    if (h->act == HK_FAULT) {                                            /* (S5 leftover c: the record of the zone cannot be read when the builder takes the step: a damaged cell) */
        if (where == 0) {
            atomic_store(&db_store_test_rec_fault_zone, h->zone);
            atomic_store(&h->mover_done, true);
        }
        return;
    }
    if (where == 0) {
        atomic_fetch_add(&g_hk_arrived, 1);                              /* (the writer is inside the window before it goes on) */
        for (int t = 0; t < 1000 && atomic_load(&g_hk_arrived) < atomic_load(&g_hk_expect); t++) usleep(10000);
        if (atomic_load(&g_hk_arrived) < atomic_load(&g_hk_expect)) atomic_store(&g_hk_timeout, true);
        if (h->act == HK_INNER) return;
        hk_start(h);                                                      /* (the other writer runs to its end before this builder goes on) */
        if (atomic_load(&h->started)) pthread_join(h->th, NULL);
    } else if (h->act == HK_INNER) {
        hk_start(h);                                                      /* (inside the step: the other writer has to wait for it) */
        usleep(250000);
        atomic_store(&h->blocked_seen, !atomic_load(&h->mover_done));
    }
}

static void hk_set(int n, int act, const char *zone, int64_t sid, uint64_t gen, uint64_t time) {
    pthread_mutex_lock(&g_hk_mu);
    hk_t *h = &g_hk[n];
    h->zone = zone;
    h->act = act;
    h->sid = sid;
    h->gen = gen;
    h->time = time;
    atomic_store(&h->used, false);
    atomic_store(&h->mover_done, false);
    atomic_store(&h->started, false);
    atomic_store(&h->blocked_seen, false);
    if (n + 1 > g_hk_n) g_hk_n = n + 1;
    pthread_mutex_unlock(&g_hk_mu);
}

static const rq_t *rq_find(const rq_t *r, int n, const char *name) {
    for (int i = 0; i < n; i++)
        if (strcmp(r[i].name, name) == 0) return &r[i];
    return NULL;
}

static void send_root_zone(int fd, kdb_enc_t *e, uint32_t serial, uint64_t req, int64_t sid) {
    zone_image_t *img = zi_zone(".", serial, NULL, NULL, 0);
    zi_zone_msgs(e, 0, ".", sid, serial, img, req, NULL, NULL, 0, (int)serial);
    zone_image_free(img);
    ch_send(fd, e);
}

static bool wait_rec(store_t *st, const char *name, uint8_t state, uint32_t serial, uint64_t gen, bool stale, int ms) {
    store_zone_t z;
    for (int t = 0; t < ms / 10; t++) {
        if (zrec(st, name, &z) && z.state == state && z.serial == serial && z.stamp_gen == gen && ((z.flags & STORE_F_STALE) != 0) == stale) return true;
        usleep(10000);
    }
    return false;
}

/* the record is written before the zone is registered (the put, then dbreg_commit()): a zone that is stored is in memory a moment later */
static bool wait_mem(const char *zone, int ms) {
    for (int t = 0; t < ms / 10; t++) {
        if (in_memory(zone)) return true;
        usleep(10000);
    }
    return false;
}

/* 0.7 M3: a body that nobody waits for goes to the store as it is, and the zone is in memory when the first query asks for it (what a worker does) */
static bool attach_mem(const char *zone, int ms) {
    db_store_attach_zone("default", zone);
    return wait_mem(zone, ms);
}

static int run_stamp_race(const char *dir) {
    printf("[the store protocol: a fetched body is installed only for the stamp it was asked for (phase 6)]\n");
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; ingest-threads 2; }; };\n"
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
    db_store_test_commit_hook = race_hook;                              /* (before the builders exist: the hook does nothing for a zone that has no case) */
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
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, (KDB_FEAT_STORE) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG && m.u.config.store_proto);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    store_zone_t z;
    rq_t rq[16];
    uint64_t bid = 1, cur = 100;
    const int ZA = 2000, ZB = 2001, ZC = 2002, ZD = 2003;
    char na[64], nb[64], nc[64], nd[64], ra[64], rb[64], rc[64], rd[64];
    pn_name(na, sizeof(na), ZA); pn_name(nb, sizeof(nb), ZB); pn_name(nc, sizeof(nc), ZC); pn_name(nd, sizeof(nd), ZD);       /* "m2000.test." ... */
    snprintf(ra, sizeof(ra), "m%04d.test", ZA); snprintf(rb, sizeof(rb), "m%04d.test", ZB); snprintf(rc, sizeof(rc), "m%04d.test", ZC); snprintf(rd, sizeof(rd), "m%04d.test", ZD);       /* (the names of the records: no dot) */
    pc_t c[4];

    /* -- zone C is in the store and in memory, with the stamp (1,10) */
    memset(c, 0, sizeof(c));
    c[0] = (pc_t){ .sid = p_sid(ZC), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  snprintf(c[0].name, sizeof(c[0].name), "%s", nc);
    p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
    p_changes(a[0], &e, bid, ++cur, true, c, 1);
    p_batch_end(a[0], &e, bid++, 1, 0);
    CHECK(p_result(&mainc, &m, 10000));
    CHECK(rq_collect(&fetchc, rq, 16, 1500) == 1 && rq_find(rq, 1, nc));
    send_zone(f[0], &e, nc, 1, rq[0].id, p_sid(ZC));
    CHECK(wait_rec(st, rc, STORE_STATE_STORED, 1, 1, false, 10000) && attach_mem(nc, 5000));

    /* -- round 1: two builders, each with a body in hand.  A: a new zone (no entry), the database changes it again in the window.  B: the database deletes it in the window. */
    memset(c, 0, sizeof(c));
    c[0] = (pc_t){ .sid = p_sid(ZA), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  snprintf(c[0].name, sizeof(c[0].name), "%s", na);
    c[1] = (pc_t){ .sid = p_sid(ZB), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  snprintf(c[1].name, sizeof(c[1].name), "%s", nb);
    p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
    p_changes(a[0], &e, bid, ++cur, true, c, 2);
    p_batch_end(a[0], &e, bid++, 2, 0);
    CHECK(p_result(&mainc, &m, 10000));
    int n = rq_collect(&fetchc, rq, 16, 1500);
    CHECK(n == 2 && rq_find(rq, n, na) && rq_find(rq, n, nb));
    hk_set(0, HK_UPSERT, na, p_sid(ZA), 2, 20);
    hk_set(1, HK_DELETE, nb, p_sid(ZB), 0, 0);
    atomic_store(&g_hk_arrived, 0);
    atomic_store(&g_hk_expect, 1);                                 /* (0.7 M3: with the store the thread that reads the stream installs the bodies, one after the other: one writer is in the window at a time) */
    const rq_t *qa = rq_find(rq, n, na), *qb = rq_find(rq, n, nb);
    if (qa && qb) {
        send_zone(f[0], &e, na, 1, qa->id, p_sid(ZA));
        send_zone(f[0], &e, nb, 1, qb->id, p_sid(ZB));
    }
    n = rq_collect(&fetchc, rq, 16, 3000);                               /* (A is asked for again, with the new stamp; B is gone and is not) */
    CHECK(n == 1 && rq_find(rq, n, na) && !rq_find(rq, n, nb));
    CHECK(!atomic_load(&g_hk_timeout) && atomic_load(&g_hk[0].mover_done) && atomic_load(&g_hk[1].mover_done));
    CHECK(zrec(st, ra, &z) && z.state == STORE_STATE_KNOWN && z.stamp_gen == 2 && z.stamp_time == 20);       /* (before: STORED, serial 1, under the stamp 2, not stale: the body of the stamp 1 was "current") */
    CHECK(!in_memory(na));
    CHECK(!zrec(st, rb, &z) && dbreg_lookup_entry("default", nb) == NULL);                                   /* (before: the deleted zone was written back) */
    qa = rq_find(rq, n, na);
    if (qa) send_zone(f[0], &e, na, 2, qa->id, p_sid(ZA));
    CHECK(wait_rec(st, ra, STORE_STATE_STORED, 2, 2, false, 10000) && attach_mem(na, 5000));
    CHECK(zrec(st, ra, &z) && z.stamp_time == 20);

    /* -- round 2: C is in memory (the body is installed into its entry in place).  The database changes it twice, the second time in the window: the store keeps the old image under the new stamp, marked stale,
     *    and the zone is asked for again.  D: the other writer comes while the commit holds the step, and waits for it (the record is stored under the stamp it was asked for, and then marked stale). */
    memset(c, 0, sizeof(c));
    c[0] = (pc_t){ .sid = p_sid(ZC), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 2, .time = 20 };  snprintf(c[0].name, sizeof(c[0].name), "%s", nc);
    c[1] = (pc_t){ .sid = p_sid(ZD), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 10 };  snprintf(c[1].name, sizeof(c[1].name), "%s", nd);
    p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
    p_changes(a[0], &e, bid, ++cur, true, c, 2);
    p_batch_end(a[0], &e, bid++, 2, 0);
    CHECK(p_result(&mainc, &m, 10000));
    n = rq_collect(&fetchc, rq, 16, 1500);
    CHECK(n == 2 && rq_find(rq, n, nc) && rq_find(rq, n, nd));
    hk_set(2, HK_UPSERT, nc, p_sid(ZC), 3, 30);
    hk_set(3, HK_INNER, nd, p_sid(ZD), 2, 20);
    atomic_store(&g_hk_arrived, 0);
    atomic_store(&g_hk_expect, 1);                                 /* (0.7 M3: with the store the thread that reads the stream installs the bodies, one after the other: one writer is in the window at a time) */
    const rq_t *qc = rq_find(rq, n, nc), *qd = rq_find(rq, n, nd);
    if (qc && qd) {
        send_zone(f[0], &e, nc, 2, qc->id, p_sid(ZC));
        send_zone(f[0], &e, nd, 1, qd->id, p_sid(ZD));
    }
    n = rq_collect(&fetchc, rq, 16, 3000);                               /* (C is asked for again with the stamp 3; D may be, when the other writer was done before the fetch ended) */
    CHECK(n >= 1 && n <= 2 && rq_find(rq, n, nc));
    CHECK(!atomic_load(&g_hk_timeout) && atomic_load(&g_hk[2].mover_done));
    CHECK(zrec(st, rc, &z) && z.state == STORE_STATE_STORED && z.serial == 1 && z.stamp_gen == 3 && z.stamp_time == 30 && (z.flags & STORE_F_STALE));       /* (before: serial 2, the body of the stamp 2, "current" under the stamp 3) */
    CHECK(in_memory(nc));
    CHECK(wait_rec(st, rd, STORE_STATE_STORED, 1, 2, true, 5000));                                            /* (D: put under the stamp 1, then the stamp 2 and stale; before: serial 1 under the stamp 2, not stale) */
    CHECK(atomic_load(&g_hk[3].blocked_seen));                                                               /* (the other writer had not finished when the builder left the step) */
    if (atomic_load(&g_hk[3].started)) pthread_join(g_hk[3].th, NULL);
    CHECK(atomic_load(&g_hk[3].mover_done));
    qc = rq_find(rq, n, nc);
    qd = rq_find(rq, n, nd);
    if (qc) send_zone(f[0], &e, nc, 3, qc->id, p_sid(ZC));
    CHECK(wait_rec(st, rc, STORE_STATE_STORED, 3, 3, false, 10000));
    if (!qd) {                                                           /* (D was not asked for again yet: a forced entry asks for it) */
        c[0] = (pc_t){ .sid = p_sid(ZD), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 2, .time = 20, .force = true };  snprintf(c[0].name, sizeof(c[0].name), "%s", nd);
        p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, bid, ++cur, true, c, 1);
        p_batch_end(a[0], &e, bid++, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        n = rq_collect(&fetchc, rq, 16, 1500);
        qd = rq_find(rq, n, nd);
        CHECK(qd != NULL);
    }
    if (qd) send_zone(f[0], &e, nd, 2, qd->id, p_sid(ZD));
    CHECK(wait_rec(st, rd, STORE_STATE_STORED, 2, 2, false, 10000));
    CHECK(zrec(st, rc, &z) && z.stamp_time == 30);

    /* -- round 3: a zone the store cannot name (the root zone) is a zone of the heap directory; its stamp is the entry's in the list of the Backend.  The same two cases. */
    {
        pc_t rc0[1];
        memset(rc0, 0, sizeof(rc0));
        rc0[0] = (pc_t){ .sid = 9100, .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 1, .time = 5 };  snprintf(rc0[0].name, sizeof(rc0[0].name), ".");
        p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, bid, ++cur, true, rc0, 1);
        p_batch_end(a[0], &e, bid++, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        n = rq_collect(&fetchc, rq, 16, 1500);
        CHECK(n == 1 && rq_find(rq, n, "."));
        hk_set(4, HK_UPSERT, ".", 9100, 2, 5);
        atomic_store(&g_hk_arrived, 0);
        atomic_store(&g_hk_expect, 1);
        if (n == 1) send_root_zone(f[0], &e, 1, rq[0].id, 9100);
        n = rq_collect(&fetchc, rq, 16, 3000);                           /* (the body of the stamp 1 is dropped; the zone is asked for again) */
        CHECK(n == 1 && rq_find(rq, n, "."));
        CHECK(atomic_load(&g_hk[4].mover_done) && dbreg_lookup_entry("default", ".") == NULL);       /* (before: the body was installed) */
        if (n == 1) send_root_zone(f[0], &e, 2, rq[0].id, 9100);
        int64_t sid;
        uint32_t sr = 0;
        bool have = false;
        for (int t = 0; t < 500 && !have; t++) { have = dbreg_zone_version("default", ".", &sid, &sr) && sr == 2; if (!have) usleep(10000); }
        CHECK(have && dbreg_lookup_entry("default", ".") != NULL);
        /* the database deletes the zone in the window: it stays deleted */
        rc0[0].gen = 3;
        p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
        p_changes(a[0], &e, bid, ++cur, true, rc0, 1);
        p_batch_end(a[0], &e, bid++, 1, 0);
        CHECK(p_result(&mainc, &m, 10000));
        n = rq_collect(&fetchc, rq, 16, 1500);
        CHECK(n == 1 && rq_find(rq, n, "."));
        hk_set(5, HK_DELETE, ".", 9100, 0, 0);
        atomic_store(&g_hk_arrived, 0);
        atomic_store(&g_hk_expect, 1);
        if (n == 1) send_root_zone(f[0], &e, 3, rq[0].id, 9100);
        n = rq_collect(&fetchc, rq, 16, 1500);
        CHECK(n == 0);
        CHECK(atomic_load(&g_hk[5].mover_done) && dbreg_lookup_entry("default", ".") == NULL);
        db_recon_status_t rs;
        db_recon_status(&rs);
        CHECK(rs.nonstore == 0);
    }

    /* -- round 2b (S5 leftover c): C is in memory and stored.  The database changes it (the stamp 4); when the builder takes the step the record cannot be read (a damaged cell: the answer of the store is
     *    "gone").  The body was installed into the zone in memory, so the zone's element was marked busy for the install, and no commit follows: the mark must go (before: it stayed, and the zone could never be
     *    taken out of memory again).  */
    memset(c, 0, sizeof(c));
    c[0] = (pc_t){ .sid = p_sid(ZC), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 4, .time = 40 };  snprintf(c[0].name, sizeof(c[0].name), "%s", nc);
    p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
    p_changes(a[0], &e, bid, ++cur, true, c, 1);
    p_batch_end(a[0], &e, bid++, 1, 0);
    CHECK(p_result(&mainc, &m, 10000));
    n = rq_collect(&fetchc, rq, 16, 1500);
    CHECK(n == 1 && rq_find(rq, n, nc));
    hk_set(6, HK_FAULT, nc, p_sid(ZC), 0, 0);
    qc = rq_find(rq, n, nc);
    if (qc) send_zone(f[0], &e, nc, 4, qc->id, p_sid(ZC));
    for (int t = 0; t < 500 && !atomic_load(&g_hk[6].used); t++) usleep(10000);
    CHECK(atomic_load(&g_hk[6].used));
    {
        bool unbusy = false;
        for (int t = 0; t < 300 && !unbusy; t++) {
            zref_t zr;
            unbusy = zref_of(nc, &zr) && zr.el && !(dbreg_test_flags("default", nc) & ZDIR_F_BUSY) && zr.entry && atomic_load(&zr.entry->serial) == 4;       /* (the body was installed in memory, and the mark is gone) */
            if (!unbusy) usleep(10000);
        }
        CHECK(unbusy);
    }
    atomic_store(&db_store_test_rec_fault_zone, NULL);

    /* -- round 2c (S5 leftover b): a body that is refused marks the store's record (it is not asked for again with this stamp) only when the record still has the stamp the body was asked for.  D: the database
     *    changes the zone again in the window (stamp 6): the refusal is not the newer version's, the record is not marked.  C: nothing moves: the record is marked. */
    memset(c, 0, sizeof(c));
    c[0] = (pc_t){ .sid = p_sid(ZD), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 5, .time = 50 };  snprintf(c[0].name, sizeof(c[0].name), "%s", nd);
    c[1] = (pc_t){ .sid = p_sid(ZC), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 7, .time = 70 };  snprintf(c[1].name, sizeof(c[1].name), "%s", nc);
    p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
    p_changes(a[0], &e, bid, ++cur, true, c, 2);
    p_batch_end(a[0], &e, bid++, 2, 0);
    CHECK(p_result(&mainc, &m, 10000));
    n = rq_collect(&fetchc, rq, 16, 1500);
    CHECK(n >= 2 && rq_find(rq, n, nc) && rq_find(rq, n, nd));
    hk_set(7, HK_UPSERT, nd, p_sid(ZD), 6, 60);
    atomic_store(&g_hk_arrived, 0);
    atomic_store(&g_hk_expect, 1);
    qc = rq_find(rq, n, nc);
    qd = rq_find(rq, n, nd);
    if (qd) send_bad_zone(f[0], &e, nd, 5, qd->id, p_sid(ZD));
    for (int t = 0; t < 500 && !atomic_load(&g_hk[7].mover_done); t++) usleep(10000);
    CHECK(atomic_load(&g_hk[7].mover_done));
    if (qc) send_bad_zone(f[0], &e, nc, 7, qc->id, p_sid(ZC));
    for (int t = 0; t < 500; t++) {
        char txt[200];
        if (dbreg_err_get("default", nc, 0xFFFFFFFFu, txt, sizeof(txt)) || (zrec(st, rc, &z) && (z.flags & STORE_F_REJECTED_NEW))) break;
        usleep(10000);
    }
    {
        char txt[200];
        usleep(200000);
        CHECK(zrec(st, rd, &z) && z.stamp_gen == 6 && z.stamp_time == 60 && !(z.flags & STORE_F_REJECTED_NEW));         /* (D: before: marked, and the stamp 6 was not asked for again) */
        CHECK(!dbreg_err_get_locked("default", nd, z.zid, txt, sizeof(txt)));                                                /* (and no text is kept for it: the record has another version now (L1)) */
        CHECK(zrec(st, rc, &z) && z.stamp_gen == 7 && (z.flags & STORE_F_REJECTED_NEW));                                     /* (C: the stamp is the one that was asked for) */
        CHECK(dbreg_err_get_locked("default", nc, z.zid, txt, sizeof(txt)) && strstr(txt, "SOA serial") != NULL);
    }
    n = rq_collect(&fetchc, rq, 16, 500);                                /* (what the background scan asked for meanwhile) */
    memset(c, 0, sizeof(c));                                             /* (D's body for the stamp 6 is asked for and sent, so that the zones are quiet for the next round) */
    c[0] = (pc_t){ .sid = p_sid(ZD), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 6, .time = 60, .force = true };  snprintf(c[0].name, sizeof(c[0].name), "%s", nd);
    p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
    p_changes(a[0], &e, bid, ++cur, true, c, 1);
    p_batch_end(a[0], &e, bid++, 1, 0);
    CHECK(p_result(&mainc, &m, 10000));
    n += rq_collect(&fetchc, rq + n, 16 - n, 1500);
    qd = rq_find(rq, n, nd);
    CHECK(qd != NULL);
    if (qd) send_zone(f[0], &e, nd, 6, qd->id, p_sid(ZD));
    CHECK(wait_rec(st, rd, STORE_STATE_STORED, 6, 6, false, 10000));
    n = rq_collect(&fetchc, rq, 16, 500);
    CHECK(n == 0 || (n == 1 && rq_find(rq, n, nc) == NULL));
    CHECK(!atomic_load(&g_hk_timeout));
    /* -- 0.7: this loader has no KDB_FEAT_BATCH_STATUS: a batch the store cannot make durable (its journal meets ENOSPC) is counted, but BATCH_RESULT has no tag 7
     *    (an older decoder would reject the unknown tag) */
    {
      db_recon_status_t rs0, rs1;
      db_recon_status(&rs0);
      atomic_store(&g_dbs_jw_nospc, 1);
      store_test_jw_fault = dbs_jw_fault;
      memset(c, 0, sizeof(c));
      c[0] = (pc_t){ .sid = p_sid(ZD), .op = KDB_CH_UPSERT, .has_name = true, .stamped = true, .gen = 8, .time = 80 };  snprintf(c[0].name, sizeof(c[0].name), "%s", nd);
      p_batch_begin(a[0], &e, bid, KDB_BATCH_AUTO, 0);
      p_changes(a[0], &e, bid, ++cur, true, c, 1);
      p_batch_end(a[0], &e, bid, 1, 0);
      CHECK(p_result(&mainc, &m, 10000) && m.u.batch_result.batch_id == bid && m.u.batch_result.store_error == 0);
      bid++;
      db_recon_status(&rs1);
      CHECK(rs1.batch_store_errors == rs0.batch_store_errors + 1 && rs1.batch_store_last == -ENOSPC);
      atomic_store(&g_dbs_jw_nospc, 0);
      store_stats_t ss;
      for (int w = 0; w < 5000; w++) { store_stats(st, &ss); if (ss.journal_state == STORE_JOURNAL_OK) break; usleep(1000); }
      CHECK(ss.journal_state == STORE_JOURNAL_OK);
      store_test_jw_fault = NULL;
    }
    gc_snapshot_wait_idle();                                             /* (the reclaim thread that the last delta started: joined, not left to the exit) */
    db_store_batch_end();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    test_exit(g_failed ? 1 : 0);
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
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
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
        zone_image_t *simg = zone_img(zn, 1);
        zi_zone_msgs(&e, 0, zn, 700 + i, 1, simg, 0, stext, NULL, 0, 9);
        zone_image_free(simg);
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
    test_exit(g_failed ? 1 : 0);
}

/* ---------------------------------------------------------------- S5: the light entry, the statistics of the zones that leave memory, eviction by samples, the attach table, the leftovers */
/* `test_db_store s5 [map|copy]` (its own process: the ingest thread and the store are process wide) */
void stats_collect_totals(zone_db_snapshot_t *snap, karidns_stats_total_t *t);        /* (dns_server_core.c, unit-test builds) */
extern void (*g_stats_walk_hook)(int attempt);                                         /* (dns_server_core.c: called after the walk of the zones in memory, before the check of the fold sequence) */
static const char *g_l3_zone;
static void l3_walk_hook(int attempt) {
    if (attempt == 0 && g_l3_zone) (void)dbreg_test_evict("default", g_l3_zone);           /* (a zone leaves memory after the walk has counted it) */
}

/* a sink that asks whether the registry's lock is free at every put and clear (a thread that takes it: it ends at once when the lock is free, and when this thread holds it, it ends after the call returns), and
 * does what the store's sink does */
static _Atomic int g_probe_calls, g_probe_held, g_probe_done;
static void *probe_thread(void *arg) {
    (void)arg;
    (void)dbreg_lookup_entry("default", "probe.test.");
    atomic_store(&g_probe_done, 1);
    return NULL;
}
static void probe_registry_lock(void) {
    atomic_store(&g_probe_done, 0);
    pthread_t t;
    if (pthread_create(&t, NULL, probe_thread, NULL) != 0) return;
    pthread_detach(t);
    bool free_lock = false;
    for (int i = 0; i < 40 && !free_lock; i++) {
        usleep(10000);
        free_lock = atomic_load(&g_probe_done) != 0;
    }
    atomic_fetch_add(&g_probe_calls, 1);
    if (!free_lock) atomic_fetch_add(&g_probe_held, 1);
}
static void probe_put(uint32_t zid, uint32_t tag, uint64_t stamp, const char *text) {
    probe_registry_lock();
    store_t *st = db_store_handle();
    if (st) (void)store_err_put(st, zid, tag, stamp, text);
}
static bool probe_get(uint32_t zid, uint32_t tag, uint64_t stamp, char *out, size_t cap) {
    store_t *st = db_store_handle();
    store_err_t se;
    if (!st || !cap || store_err_get(st, zid, &se) != 0 || se.tag != (tag & 0xFFFFFFu) || se.stamp_gen != stamp) return false;
    snprintf(out, cap, "%s", se.text);
    return true;
}
static void probe_clear(uint32_t zid) {
    probe_registry_lock();
    store_t *st = db_store_handle();
    if (st) (void)store_err_clear(st, zid);
}
static const dbreg_err_sink_t g_probe_sink = { probe_put, probe_get, probe_clear };

static int run_s5(const char *mode) {
    printf("[S5: the light entry, the counters of the zones that leave memory, eviction by samples, the attach table, rejected zones, the four leftovers: %s mode]\n", mode);
    char dir[] = "/tmp/test_db_store_s5.XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode %s; store-threads 2; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir, mode);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled() && dbdir() != NULL);
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
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    memset(&g_wctx, 0, sizeof(g_wctx));
    g_query_bg_fetch = no_bg_fetch;
    g_query_bg_attach = no_bg_fetch;
    store_t *st = db_store_handle();
    CHECK(st != NULL);
    dbreg_cache_test_pause(true);                                          /* (the manager's thread does not run rounds by itself: the test calls them) */

    enum { NZ = 900 };
    static char nm[NZ][24];
    batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP);
    for (int i = 0; i < NZ; i++) {
        snprintf(nm[i], sizeof(nm[i]), "s%04d.test.", i);
        send_zone(a[0], &e, nm[i], 1, 0, 5000 + i);
    }
    batch_end(a[0], &e, &mainc, 1, NZ, 0);
    for (int i = 0; i < 300 && dbdir()->attach_count() < (size_t)NZ; i++) usleep(50000);
    CHECK(dbdir()->attach_count() == (size_t)NZ);

    /* -- 1. the entry of an attached zone is the core alone, in a slot of the pool; the extension is made by what needs it */
    {
        zref_t zr;
        CHECK(zref_of(nm[1], &zr) && zr.entry != NULL);
        zone_db_entry_t *en = zr.entry;
        CHECK(en && en->light && en->pooled && en->block_bytes == 256 && zone_x(en) == NULL);
        zone_entry_pool_stats_t ps;
        zone_entry_pool_stats(&ps);
        CHECK(ps.used >= (uint64_t)NZ && ps.slabs >= 1 && ps.slot_bytes == 256);
        CHECK(sizeof(zone_db_entry_t) <= 224);
        printf("  entry: sizeof(zone_db_entry_t) %zu, slot %llu octets, %llu entries in %llu slab(s) of the pool\n", sizeof(zone_db_entry_t), (unsigned long long)ps.slot_bytes, (unsigned long long)ps.used,
               (unsigned long long)ps.slabs);
    }

    /* -- 2. the counters of a zone are the core's; what is folded when the zone leaves memory is in the totals of the view and in the table of the top zones */
    uint8_t out[1500];
    {
        for (int i = 0; i < 25; i++) CHECK(ask_engine(&g_wctx, &g_cc, nm[1], 6, out) > 12);
        for (int i = 0; i < 3; i++) (void)ask_engine(&g_wctx, &g_cc, "nx.s0001.test.", 1, out);        /* (NXDOMAIN) */
        zref_t zr;
        CHECK(zref_of(nm[1], &zr) && zr.entry);
        CHECK(zr.entry && zone_ctr_get(zr.entry, ZCTR_QUERIES) == 28 && zone_ctr_get(zr.entry, ZCTR_NXDOMAIN) == 3 && zone_ctr_get(zr.entry, ZCTR_NOERROR) == 25);
        uint64_t f0[ZCTR_N], f1[ZCTR_N], z0, z1;
        dbreg_fold_totals(f0, &z0);
        CHECK(f0[ZCTR_QUERIES] == 0 && z0 == 0);
        CHECK(evict_zone(nm[1]));
        dbreg_fold_totals(f1, &z1);
        CHECK(f1[ZCTR_QUERIES] == 28 && f1[ZCTR_NXDOMAIN] == 3 && f1[ZCTR_NOERROR] == 25 && z1 == 1);
        uint64_t fv[ZCTR_N], zv;
        CHECK(dbreg_fold_view_totals("default", fv, &zv) && fv[ZCTR_QUERIES] == 28 && zv == 1);
        CHECK(!dbreg_fold_view_totals("nosuch", fv, &zv) && fv[ZCTR_QUERIES] == 0);
        zone_fold_row_t rows[ZFOLD_TOPK];
        size_t nr = dbreg_fold_topk(rows, ZFOLD_TOPK);
        CHECK(nr == 1 && strcmp(rows[0].zone, nm[1]) == 0 && strcmp(rows[0].view, "default") == 0 && rows[0].c[ZCTR_QUERIES] == 28 && rows[0].detaches == 1);
        karidns_stats_total_t tot;
        rcu_aux_read_lock();
        zone_db_snapshot_t *sn = acquire_zone_snapshot();
        stats_collect_totals(sn, &tot);
        rcu_aux_read_unlock();
        CHECK(tot.queries_total == 28 && tot.responses_nxdomain == 3 && tot.responses_noerror == 25);       /* (the totals do not go back when the zone leaves memory: the alerts look at their change) */
        /* a zone with no queries leaves no row, and the zone that comes back counts from zero (its row is not listed while it is in memory) */
        CHECK(evict_zone(nm[2]));
        nr = dbreg_fold_topk(rows, ZFOLD_TOPK);
        CHECK(nr == 1);
        db_store_attach_zone("default", nm[1]);
        CHECK(zref_of(nm[1], &zr) && zr.entry && zone_ctr_get(zr.entry, ZCTR_QUERIES) == 0);
        nr = dbreg_fold_topk(rows, ZFOLD_TOPK);
        CHECK(nr == 0);
        for (int i = 0; i < 4; i++) (void)ask_engine(&g_wctx, &g_cc, nm[1], 6, out);
        CHECK(evict_zone(nm[1]));
        nr = dbreg_fold_topk(rows, ZFOLD_TOPK);
        CHECK(nr == 1 && rows[0].c[ZCTR_QUERIES] == 32 && rows[0].detaches == 2);                    /* (the stays are added) */
        dbreg_fold_totals(f1, &z1);
        CHECK(f1[ZCTR_QUERIES] == 32 && z1 == 3);
        /* the zone is deleted from the database: the row goes, the totals stay */
        db_store_attach_zone("default", nm[2]);
        db_store_attach_zone("default", nm[1]);
        CHECK(in_memory(nm[1]) && in_memory(nm[2]));
    }

    /* -- 2b. (L3) a zone that is taken out of memory while the totals are collected is counted once: the walk of the attach table has no lock, and the zone can be seen in the table after the folded totals were
     *    read (it was added again: the totals were doubled for it, and went back at the next call) */
    {
        zref_t zr;
        db_store_attach_zone("default", nm[3]);
        CHECK(zref_of(nm[3], &zr) && zr.entry);
        for (int i = 0; i < 12; i++) CHECK(ask_engine(&g_wctx, &g_cc, nm[3], 6, out) > 12);
        karidns_stats_total_t t0, t1;
        rcu_aux_read_lock();
        zone_db_snapshot_t *sn = acquire_zone_snapshot();
        stats_collect_totals(sn, &t0);
        CHECK(t0.queries_total >= 12);
        g_l3_zone = nm[3];
        g_stats_walk_hook = l3_walk_hook;
        stats_collect_totals(sn, &t1);                                                              /* (the hook takes the zone out after the walk) */
        g_stats_walk_hook = NULL;
        g_l3_zone = NULL;
        rcu_aux_read_unlock();
        CHECK(!in_memory(nm[3]));
        CHECK(t1.queries_total == t0.queries_total && t1.responses_noerror == t0.responses_noerror);                       /* (before: the zone's queries were in the walk and in the folded totals) */
        rcu_aux_read_lock();
        sn = acquire_zone_snapshot();
        stats_collect_totals(sn, &t1);
        rcu_aux_read_unlock();
        CHECK(t1.queries_total == t0.queries_total);
        wait_retired();
    }

    /* -- 3. eviction by samples: the registry is not walked; the cold zones go, the hot zone and the pinned zone stay; the attach table gets smaller after a mass detach */
    {
        zref_t zr;
        for (int i = 0; i < 60; i++) (void)ask_engine(&g_wctx, &g_cc, nm[100], 6, out);              /* (the hot zone) */
        CHECK(zref_of(nm[200], &zr) && zr.el);
        dbreg_test_pin("default", nm[200], true);                                                   /* (the pinned zone: counted in the pinned total like a zone whose settings pin it) */
        usleep(300000);                                                                             /* (older than the minimum residency) */
        const uint64_t res0 = resident_bytes();
        const uint64_t cap0 = dbdir()->counters(5);
        CHECK(res0 > 0 && cap0 >= 1024);
        dbreg_cache_stats_t cs0, cs1;
        dbreg_cache_stats(&cs0);
        dbreg_cache_set_limit(res0 * 55 / 100);
        dbreg_cache_test_pause(false);
        uint32_t taken = 0;
        for (int round = 0; round < 400 && dbdir()->attach_count() > (size_t)NZ / 2; round++) {
            taken += dbreg_cache_round();
            usleep(20000);
        }
        dbreg_cache_set_limit(0);
        dbreg_cache_test_pause(true);
        wait_retired();
        dbreg_cache_stats(&cs1);
        const size_t left = dbdir()->attach_count();
        printf("  samples: %u zones taken out by the manager, %zu of %d left, resident %llu -> %llu\n", taken, left, NZ, (unsigned long long)res0, (unsigned long long)resident_bytes());
        CHECK(taken >= 100 && left <= (size_t)NZ * 6 / 10 && left >= 20);
        CHECK(resident_bytes() < res0);
        CHECK(cs1.evictions >= cs0.evictions + taken && cs1.sampled >= cs0.sampled + taken);         /* (every one of them was found by a sample) */
        CHECK(in_memory(nm[100]));                                                                   /* (the hot zone: its priority is the highest of all) */
        CHECK(in_memory(nm[200]));                                                                   /* (the pinned zone) */
        CHECK(cs1.pinned_bytes > 0);                                                                 /* (counted when the zone was registered, not by a walk) */
        /* what is still attached is found, and what is not is answered from the store */
        CHECK(stored_only(nm[2]) || in_memory(nm[2]));
        dbreg_test_pin("default", nm[200], false);
        /* the attach table is smaller after a mass detach */
        const uint64_t grows = dbdir()->counters(6);
        (void)grows;
        const uint64_t cap1 = dbdir()->counters(5);
        for (int i = 0; i < NZ; i++)
            if (in_memory(nm[i])) (void)dbreg_test_evict("default", nm[i]);
        wait_retired();
        CHECK(dbdir()->attach_count() == 0);
        const uint64_t cap2 = dbdir()->counters(5);
        printf("  attach table: %llu slots with %d zones, %llu slots with none (%llu shrinks)\n", (unsigned long long)cap1, NZ, (unsigned long long)cap2, (unsigned long long)dbdir()->counters(7));
        CHECK(cap1 > 1024 && cap2 == 1024 && dbdir()->counters(7) >= 1);
    }

    /* -- 4. a rejected zone has no element: its text is in the ring, its record says so */
    {
        size_t nel0, rb0, ib0, nel1, rb1, ib1;
        CHECK(stored_only(nm[10]));
        dbreg_dir_bytes(&nel0, &rb0, &ib0);
        CHECK(dbreg_reject_ex("default", nm[10], 5010, "the body was refused: boom", true));
        dbreg_dir_bytes(&nel1, &rb1, &ib1);
        CHECK(nel1 == nel0);                                                                         /* (no registry element for the text) */
        dbdir_rec_t rec;
        CHECK(dbdir()->rec_get("default", nm[10], &rec) && (rec.flags & STORE_F_REJECTED_NEW));
        dbreg_info_t info[2];
        CHECK(dbreg_find_info("default", nm[10], info, 2) == 1 && info[0].last_result == DBREG_REJECTED && strcmp(info[0].error, "the body was refused: boom") == 0 && !info[0].has_entry);
        size_t total, rejected, shc, shk;
        dbreg_counts2(&total, &rejected, &shc, &shk);
        CHECK(rejected >= 1);
        char st_text[2000];
        size_t stl = db_ingest_status("s0010.test.", "default", st_text, sizeof(st_text));
        CHECK(stl > 0 && strstr(st_text, "status rejected") && strstr(st_text, "last error: the body was refused: boom"));
        /* the same, not marking the record (the stamp the body was asked for is not the record's any more): the record is not marked, and no text is kept for a version that the record does not have (L1) */
        CHECK(stored_only(nm[11]));
        CHECK(dbreg_reject_ex("default", nm[11], 5011, "refused", false));
        CHECK(dbdir()->rec_get("default", nm[11], &rec) && !(rec.flags & STORE_F_REJECTED_NEW));
        CHECK(!dbreg_err_get("default", nm[11], rec.zid, st_text, sizeof(st_text)));
        dbreg_err_note("default", nm[11], rec.zid, "refused");                                         /* (a text of the zone: the attach that follows forgets it) */
        CHECK(dbreg_err_get("default", nm[11], rec.zid, st_text, sizeof(st_text)) && strcmp(st_text, "refused") == 0);
        /* an attach that registers a version forgets the text */
        db_store_attach_zone("default", nm[11]);
        CHECK(in_memory(nm[11]) && !dbreg_err_get("default", nm[11], rec.zid, st_text, sizeof(st_text)));
        CHECK(dbreg_find_info("default", nm[11], info, 2) == 1 && info[0].last_result == DBREG_APPLIED && info[0].error[0] == '\0');
        dbreg_err_note("default", nm[10], rec.zid, NULL);
        /* (L1) a text is for a zone and for a version: the file ring keeps the tag of the zone's name and the stamp of the record with it, and answers for those only; the delete of the zone forgets it in both rings */
        {
            dbdir_rec_t r12, r13;
            char tx[300];
            store_err_t se;
            CHECK(stored_only(nm[12]) && stored_only(nm[13]));
            CHECK(dbdir()->rec_get("default", nm[12], &r12) && dbdir()->rec_get("default", nm[13], &r13));
            CHECK(store_set_stamp(st, r12.zid, 9, 90, 0, 0) == 0);
            CHECK(dbreg_reject_ex("default", nm[12], r12.source_id, "refused: stamped", true));
            CHECK(store_err_get(st, r12.zid, &se) == 0 && se.stamp_gen != 0 && strcmp(se.text, "refused: stamped") == 0);
            const uint64_t key = se.stamp_gen;
            CHECK(dbreg_err_forget("default", nm[12]));                                                                     /* (the ring in memory is empty: the file answers) */
            CHECK(dbreg_err_get_locked("default", nm[12], r12.zid, tx, sizeof(tx)) && strcmp(tx, "refused: stamped") == 0);
            CHECK(!dbreg_err_get_st("default", "another.test.", r12.zid, key, tx, sizeof(tx)));                             /* (the id of another zone now: the tag of the name does not match; before: its text was shown) */
            CHECK(!dbreg_err_get_st("default", nm[12], r12.zid, key + 1, tx, sizeof(tx)));                                    /* (another version) */
            CHECK(store_set_stamp(st, r12.zid, 10, 100, 0, 0) == 0);                                                          /* (the database has another version: the text is of the one before) */
            CHECK(!dbreg_err_get_locked("default", nm[12], r12.zid, tx, sizeof(tx)));
            CHECK(store_set_stamp(st, r12.zid, 9, 90, 0, 0) == 0);
            CHECK(dbreg_err_get_locked("default", nm[12], r12.zid, tx, sizeof(tx)) && strcmp(tx, "refused: stamped") == 0);
            dbreg_err_note_st("default", nm[12], r12.zid, key, "refused: stamped");                                          /* (both rings have it) */
            CHECK(dbreg_err_get_st("default", nm[12], r12.zid, key, tx, sizeof(tx)));
            CHECK(dbreg_delete("default", nm[12], r12.source_id) == 1);
            CHECK(!dbreg_err_get_st("default", nm[12], r12.zid, key, tx, sizeof(tx)));                                        /* (before: the text stayed, and showed under the zone that got the id) */
            CHECK(store_err_get(st, r12.zid, &se) == -ENOENT);
            /* (M1) the sink's put and clear are called with no lock of the registry held: the registry's lock is free in them (before: the commit forgot the text inside the lock) */
            atomic_store(&g_probe_calls, 0);
            atomic_store(&g_probe_held, 0);
            dbreg_err_set_sink(&g_probe_sink);
            dbreg_err_note_st("default", nm[13], r13.zid, 0, "text 13");
            CHECK(atomic_load(&g_probe_calls) == 1 && atomic_load(&g_probe_held) == 0);
            CHECK(store_err_get(st, r13.zid, &se) == 0);
            db_store_attach_zone("default", nm[13]);                                                                           /* (registers a version: the text is forgotten) */
            CHECK(in_memory(nm[13]));
            CHECK(atomic_load(&g_probe_calls) == 2 && atomic_load(&g_probe_held) == 0);
            CHECK(store_err_get(st, r13.zid, &se) == -ENOENT);
            CHECK(dbdir()->rec_get("default", nm[13], &r13) && dbreg_err_get_st("default", nm[13], r13.zid, 0, tx, sizeof(tx)) == false);
        }
        /* (L2) the pinned total counts a zone that a dynamic UPDATE or a rollback changed (it stays in memory until the database replaces it) with the bytes it has now, and follows it when it grows */
        {
            zref_t zr;
            db_store_attach_zone("default", nm[30]);
            CHECK(zref_of(nm[30], &zr) && zr.entry && !(zr.el->flags & ZDIR_F_PIN));
            zone_db_entry_t *en = zr.entry;
            const zone_version_t *cv = en ? atomic_load(&en->rcu.active) : NULL;
            const uint64_t zbytes = cv ? (cv->counted ? cv->bytes : 0) + atomic_load(&en->fixed_charged) : 0;
            CHECK(zbytes > 0);
            dbreg_cache_stats_t p0, p1, p2, p3;
            dbreg_cache_stats(&p0);
            atomic_store(&en->updated, true);                                                                                /* (what an UPDATE leaves) */
            dbreg_pin_changed(en);
            dbreg_cache_stats(&p1);
            CHECK(p1.pinned_bytes == p0.pinned_bytes + zbytes);
            atomic_fetch_add(&en->fixed_charged, 1000);                                                                      /* (the zone grew by 1000 bytes) */
            dbreg_pin_changed(en);
            dbreg_cache_stats(&p2);
            CHECK(p2.pinned_bytes == p0.pinned_bytes + zbytes + 1000);
            atomic_fetch_sub(&en->fixed_charged, 1000);
            atomic_store(&en->updated, false);                                                                               /* (the database's version replaced it) */
            dbreg_pin_changed(en);
            dbreg_cache_stats(&p3);
            CHECK(p3.pinned_bytes == p0.pinned_bytes);
            CHECK(dbreg_test_evict("default", nm[30]));                                                                      /* (and a zone that left memory is not counted) */
            wait_retired();
        }
    }

    /* -- 5. leftovers.  (c) a zone that the ingest marked busy and does not commit is not busy for ever; (d) an element of the attach table without its entry is "not in memory", not "no zone" */
    {
        zref_t zr;
        db_store_attach_zone("default", nm[20]);
        CHECK(zref_of(nm[20], &zr) && zr.el && zr.entry);
        zone_db_entry_t *be = dbreg_lookup_entry_busy("default", nm[20]);
        CHECK(be != NULL && (zr.el->flags & ZDIR_F_BUSY));
        CHECK(!dbreg_test_evict("default", nm[20]));                                                 /* (busy: not taken out) */
        dbreg_busy_clear("default", nm[20]);
        CHECK(!(zr.el->flags & ZDIR_F_BUSY));
        /* (d) */
        zone_db_entry_t *keep = zr.entry;
        atomic_store(&zr.el->entry, NULL);
        zref_t z2;
        CHECK(zref_of(nm[20], &z2));
        CHECK(z2.el == zr.el && z2.entry == NULL && z2.zid == zr.el->zid && zref_present(&z2) && !z2.busy);        /* (before: the lookup said "no such zone" and nothing waited) */
        rcu_aux_read_lock();
        zone_db_snapshot_t *sn = acquire_zone_snapshot();
        zref_t z3;
        zref_clear(&z3);
        zone_db_entry_t *fe2 = find_zone_for_query_zref(snapshot_find_view(sn, "default"), "www.s0020.test.", 1, &z3);
        rcu_aux_read_unlock();
        CHECK(fe2 == NULL && zref_present(&z3) && z3.el == zr.el);
        atomic_store(&zr.el->entry, keep);
        CHECK(in_memory(nm[20]));
        /* (a) a version the store cannot take: the zone is pinned in memory and stays pinned (zdir_elem_sync() of the same commit made the flags again) */
        zone_db_entry_t *ae = zr.entry;
        CHECK(ae != NULL);
        dbdir_rec_t rec;
        CHECK(dbdir()->rec_get("default", nm[20], &rec));
        g_fx_zid = STORE_NONE;                                                                       /* (the store passes no zone id for a put) */
        g_fx_op = "put";
        g_fx_err = -ENOSPC;
        store_test_write_fault = fx_fault;
        batch_begin(a[0], &e, 2, KDB_BATCH_DIFF);
        send_zone(a[0], &e, nm[20], 2, 0, 5020);
        batch_end(a[0], &e, &mainc, 2, 1, 0);
        g_fx_op = NULL;
        CHECK(zref_of(nm[20], &z2) && z2.entry && z2.el == zr.el && zdir_serial(z2.el) == 2);
        CHECK((zr.el->flags & ZDIR_F_PIN) != 0);                                                     /* (before: the sync of the same commit cleared it) */
        CHECK(!dbreg_test_evict("default", nm[20]));                                                 /* (pinned: it is the only copy of the new version) */
        batch_begin(a[0], &e, 3, KDB_BATCH_DIFF);                                                   /* the store takes the next version: no pin is needed any more */
        send_zone(a[0], &e, nm[20], 3, 0, 5020);
        batch_end(a[0], &e, &mainc, 3, 1, 0);
        CHECK(zref_of(nm[20], &z2) && z2.el && zdir_serial(z2.el) == 3 && !(z2.el->flags & ZDIR_F_PIN));
        store_test_write_fault = NULL;
    }
    gc_snapshot_wait_idle();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    char rm[700];
    snprintf(rm, sizeof(rm), "rm -rf %s", dir);
    (void)!system(rm);
    fflush(stdout);
    test_exit(g_failed ? 1 : 0);
}

/* ---------------------------------------------------------------- phase 7: the lookup with the body of the zone (0.7, FETCH_REQ mode 3, KDB_FEAT_LOOKUP_BODY) */
static void lk_found(int fd, kdb_enc_t *e, uint64_t rid, int64_t sid, const char *zone, uint64_t gen, uint64_t at) {
    kdb_enc_begin(e, KDB_T_LOOKUP_RESULT);
    kdb_enc_u64(e, 1, rid); kdb_enc_u16(e, 2, 0); kdb_enc_u8(e, 3, 1);
    kdb_enc_i64(e, 4, sid); kdb_enc_name(e, 5, zone); kdb_enc_u8(e, 6, KDB_ZK_PRIMARY); kdb_enc_u64(e, 7, gen); kdb_enc_u64(e, 8, at); kdb_enc_u8(e, 9, KDB_EF_STAMPED);
    kdb_enc_end(e);
    ch_send(fd, e);
}
static void lk_none(int fd, kdb_enc_t *e, uint64_t rid) {
    kdb_enc_begin(e, KDB_T_LOOKUP_RESULT);
    kdb_enc_u64(e, 1, rid); kdb_enc_u16(e, 2, 0); kdb_enc_u8(e, 3, 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}
/* the next request on the fetch stream must be the lookup of `name` with the body (mode 3): its id (0 when it is not) */
static uint64_t lk_next(ch_t *c, const char *name) {
    kdb_msg_t m;
    if (!ch_next(c, &m, 5000) || m.type != KDB_T_FETCH_REQ || m.u.fetch_req.mode != KDB_FETCH_LOOKUP_FULL || strcmp(m.u.fetch_req.name, name) != 0 || m.u.fetch_req.source_id != 0 || m.u.fetch_req.has_range) {
        CHECK_MSG(false, "the request of the lookup of %s", name);
        return 0;
    }
    return m.u.fetch_req.request_id;
}
/* what the supervisor does after a restart of the loader: one message on the control socket, the Backend's end of the stream and of the fetch stream as SCM_RIGHTS descriptors */
static void hand_over(int ctrl, int main_fd, int fetch_fd) {
    int fds[2] = { main_fd, fetch_fd };
    for (int i = 0; i < 2; i++) fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL, 0) | O_NONBLOCK);
    char byte = 'F';
    struct iovec iov = { &byte, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int) * 2)]; } u;
    memset(&u, 0, sizeof(u));
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = u.b;
    mh.msg_controllen = CMSG_SPACE(sizeof(int) * 2);
    struct cmsghdr *ch = CMSG_FIRSTHDR(&mh);
    ch->cmsg_level = SOL_SOCKET;
    ch->cmsg_type = SCM_RIGHTS;
    ch->cmsg_len = CMSG_LEN(sizeof(int) * 2);
    memcpy(CMSG_DATA(ch), fds, sizeof(int) * 2);
    CHECK(sendmsg(ctrl, &mh, 0) == 1);
    for (int i = 0; i < 2; i++) close(fds[i]);
}

/* a figure of the status text of the ingest thread (dbstatus): the field `name` of the line `line` */
static unsigned long long st_field(const char *line, const char *name) {
    char st[8192], key[48];
    if (db_ingest_status(NULL, NULL, st, sizeof(st)) == 0) return ~0ull;
    snprintf(key, sizeof(key), "\n%s: ", line);
    const char *l = strstr(st, key);
    if (!l) return ~0ull;
    snprintf(key, sizeof(key), " %s=", name);
    const char *eol = strchr(l + 1, '\n');
    const char *p = strstr(l, key);
    if (!p || (eol && p > eol)) return ~0ull;
    return strtoull(p + strlen(key), NULL, 10);
}

/* the configuration with the settings `dbextra` made active (store settings of this phase and the views as at its start), and waited for until the manager's thread has taken the rate and the limit in force */
static char g_lk_sdir[600];
static void lk_cfg(const char *dbextra, unsigned rate, uint64_t memory_limit) {
    static server_config_t pool[8];
    static int used;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; fetch-concurrency 8; park-timeout 1000; %s }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", g_lk_sdir, dbextra);
    server_config_t *c = &pool[used++ % 8];
    CHECK(parse_named_conf(conf, c) == 0);
    if (memory_limit) c->database.memory_limit = memory_limit;
    atomic_store_explicit(&g_config_db.active, c, memory_order_release);
    for (int i = 0; i < 300 && !(st_field("fetch", "rate") == rate && dbreg_cache_limit() == c->database.memory_limit); i++) usleep(20000);
    usleep(150000);
    CHECK(st_field("fetch", "rate") == rate && dbreg_cache_limit() == c->database.memory_limit);
}

/* the next request on the fetch stream, whatever its mode: it must be a lookup of `name` (mode 2 or 3) */
static uint64_t lk_next_mode(ch_t *c, const char *name, int mode) {
    kdb_msg_t m;
    if (!ch_next(c, &m, 5000) || m.type != KDB_T_FETCH_REQ || m.u.fetch_req.mode != mode || strcmp(m.u.fetch_req.name, name) != 0) {
        CHECK_MSG(false, "the request of the lookup of %s in mode %d", name, mode);
        return 0;
    }
    return m.u.fetch_req.request_id;
}

static bool lk_asked(const char *name) { return park_fetch_request(0, "default", name, KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP); }

static int run_lookup_body(const char *dir) {
    printf("[the lookup with the body of the zone: phase 7]\n");
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    snprintf(g_lk_sdir, sizeof(g_lk_sdir), "%s", sdir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; fetch-concurrency 8; park-timeout 1000; }; };\n"
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

    /* -- 0. before the loader's HELLO (the first second of a start: the list of the zones is unknown, the loader not up yet): a query for a name that no zone covers waits for the loader that is
     *       expected, it is not REFUSED; its lookup is made once the HELLO says the loader looks names up */
    CHECK(db_ingest_lookup_wanted() && !db_ingest_lookup_ready());
    drain_wakes();
    CHECK(lk_asked("www.early.test."));
    CHECK(!wake_for("www.early.test.", &k, 300) && lk_stats().refused == 0 && lk_stats().pending == 1);

    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_STORE | KDB_FEAT_LOOKUP | KDB_FEAT_LOOKUP_BODY | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG && m.u.config.store_proto);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    CHECK(db_ingest_lookup_ready());
    {
        const uint64_t r0 = lk_next(&fetchc, "www.early.test.");                          /* (the request that waited for the HELLO) */
        CHECK(r0 != 0);
        lk_none(f[0], &e, r0);
        CHECK(wake_for("www.early.test.", &k, 5000) && !k.failed && places_are(0, 2000) && lk_stats().none == 1 && lk_stats().refused == 0 && lk_stats().pending == 0);
    }
    usleep(300000);                                                                        /* (the manager's thread has taken fetch-concurrency 8 and park-timeout 1000 ms) */
    CHECK(!ch_next(&fetchc, &m, 200));
    const int vid = store_view_id(st, "default");
    CHECK(vid >= 0 && db_store_view_pending(vid));                                         /* (no pass has listed the zones: the lookups are what finds them) */
    uint32_t sr;
    int64_t sid;

    /* -- 1. the happy path: the answer names the zone, the body follows with the same request id.  The zone is answerable after one request: no second FETCH_REQ is made, the queries that wait for the name
     *       are woken when the body is installed (not at the answer), the place is held until then */
    drain_wakes();
    CHECK(lk_asked("www.late.test."));
    uint64_t rid = lk_next(&fetchc, "www.late.test.");
    CHECK(rid != 0 && places_are(1, 2000));
    lk_found(f[0], &e, rid, 777000, "late.test.", 5, 6);
    {
        store_zone_t lz;
        bool known = false;
        for (int t = 0; t < 500 && !known; t++) { known = zrec(st, "late.test", &lz) && lz.state == STORE_STATE_KNOWN; if (!known) usleep(10000); }
        CHECK(known && lz.source_id == 777000 && lz.stamp_gen == 5 && lz.stamp_time == 6);
    }
    CHECK(!wake_for("www.late.test.", &k, 200) && park_places_used() == 1 && lk_stats().in_flight == 1 && lk_stats().found == 1);       /* (the body has not come: the queries wait) */
    send_zone(f[0], &e, "late.test.", 3, rid, 777000);
    CHECK(wake_for("www.late.test.", &k, 5000) && !k.failed && !k.retry);
    CHECK(in_memory("late.test.") && dbreg_zone_version("default", "late.test.", &sid, &sr) && sid == 777000 && sr == 3);
    CHECK(places_are(0, 2000) && lk_stats().in_flight == 0 && lk_stats().body_inline == 1 && lk_stats().bad_body == 0);
    {
        store_zone_t lz;
        CHECK(zrec(st, "late.test", &lz) && lz.state == STORE_STATE_STORED && lz.stamp_gen == 5 && lz.stamp_time == 6);      /* (installed under the stamp the answer made) */
    }
    CHECK(!ch_next(&fetchc, &m, 300));                                                        /* (one round trip: no request for the zone followed) */

    /* -- 2. a name whose zone is known meanwhile is not asked for (another name of the zone found it): the queries are woken */
    drain_wakes();
    CHECK(lk_asked("mail.late.test."));
    CHECK(wake_for("mail.late.test.", &k, 5000) && !k.failed && !ch_next(&fetchc, &m, 200) && places_are(0, 1000) && lk_stats().covered == 1);

    /* -- 3. no zone: the place is free the moment the answer is here, and the queries are woken (the normal answer is REFUSED) */
    drain_wakes();
    CHECK(lk_asked("www.nothing.test."));
    rid = lk_next(&fetchc, "www.nothing.test.");
    CHECK(places_are(1, 2000));
    lk_none(f[0], &e, rid);
    CHECK(wake_for("www.nothing.test.", &k, 5000) && !k.failed && park_places_used() == 0 && lk_stats().none == 2);            /* (and the one of step 0) */

    /* -- 4. a loader that cannot be believed (the stream is hostile input).  Nothing it says is installed unless the answer announced it; the request goes on until the right body or the time is up. */
    {
        /* a body with no answer before it */
        const uint64_t bad0 = lk_stats().bad_body;
        drain_wakes();
        CHECK(lk_asked("w.body0.test."));
        rid = lk_next(&fetchc, "w.body0.test.");
        send_zone(f[0], &e, "body0.test.", 3, rid, 880000);
        for (int t = 0; t < 200 && lk_stats().bad_body == bad0; t++) usleep(5000);
        CHECK(lk_stats().bad_body == bad0 + 1 && !in_memory("body0.test.") && park_places_used() == 1);
        lk_none(f[0], &e, rid);
        CHECK(wake_for("w.body0.test.", &k, 5000) && places_are(0, 2000));
        /* a body for another zone than the answer named, and one for the zone with another source id: thrown away, the request waits for the right one */
        for (int kase = 0; kase < 2; kase++) {
            const char *qn = kase ? "w.body2.test." : "w.body1.test.", *zn = kase ? "body2.test." : "body1.test.";
            const int64_t zs = kase ? 880002 : 880001;
            const uint64_t b1 = lk_stats().bad_body;
            drain_wakes();
            CHECK(lk_asked(qn));
            rid = lk_next(&fetchc, qn);
            lk_found(f[0], &e, rid, zs, zn, 1, 1);
            if (kase) send_zone(f[0], &e, zn, 3, rid, zs + 100);                              /* (the zone, with another id) */
            else send_zone(f[0], &e, "other1.test.", 3, rid, zs);                            /* (another zone) */
            for (int t = 0; t < 200 && lk_stats().bad_body == b1; t++) usleep(5000);
            CHECK(lk_stats().bad_body == b1 + 1 && !in_memory("other1.test.") && !in_memory(zn) && park_places_used() == 1);
            CHECK(!wake_for(qn, &k, 100));
            send_zone(f[0], &e, zn, 3, rid, zs);                                              /* (the right one) */
            CHECK(wake_for(qn, &k, 5000) && !k.failed && in_memory(zn) && places_are(0, 2000));
        }
        /* two bodies for one request: the second is thrown away (the request is over when the first is installed) */
        drain_wakes();
        CHECK(lk_asked("w.body3.test."));
        rid = lk_next(&fetchc, "w.body3.test.");
        lk_found(f[0], &e, rid, 880003, "body3.test.", 1, 1);
        send_zone(f[0], &e, "body3.test.", 3, rid, 880003);
        send_zone(f[0], &e, "body3.test.", 4, rid, 880003);
        CHECK(wake_for("w.body3.test.", &k, 5000) && places_are(0, 2000));
        usleep(200000);
        CHECK(in_memory("body3.test.") && dbreg_zone_version("default", "body3.test.", &sid, &sr) && sr == 3);
        /* a second answer after the first: no part of the request; the body that follows the first is the one that counts */
        drain_wakes();
        CHECK(lk_asked("w.body4.test."));
        rid = lk_next(&fetchc, "w.body4.test.");
        lk_found(f[0], &e, rid, 880004, "body4.test.", 1, 1);
        lk_none(f[0], &e, rid);
        send_zone(f[0], &e, "body4.test.", 3, rid, 880004);
        CHECK(wake_for("w.body4.test.", &k, 5000) && in_memory("body4.test.") && places_are(0, 2000));
        /* an answer that names a zone that does not enclose the name: the request fails, and the body that follows is thrown away */
        drain_wakes();
        CHECK(lk_asked("w.evil.test."));
        rid = lk_next(&fetchc, "w.evil.test.");
        lk_found(f[0], &e, rid, 880005, "other5.test.", 1, 1);
        CHECK(wake_for("w.evil.test.", &k, 5000) && places_are(0, 2000));
        send_zone(f[0], &e, "other5.test.", 3, rid, 880005);
        usleep(200000);
        {
            store_zone_t lz;
            CHECK(!in_memory("other5.test.") && !zrec(st, "other5.test", &lz));
        }
        /* the body cannot be read: ZONE_FAILED with the request id and the zone's name; the queries are woken (not failed), the record stays (known) for the fetch that a query then asks for */
        drain_wakes();
        CHECK(lk_asked("w.knownz.test."));
        rid = lk_next(&fetchc, "w.knownz.test.");
        lk_found(f[0], &e, rid, 777999, "knownz.test.", 1, 1);
        kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "knownz.test."); kdb_enc_i64(&e, 3, 777999); kdb_enc_str(&e, 4, "reading the records: the database is busy"); kdb_enc_u64(&e, 5, rid);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
        CHECK(wake_for("w.knownz.test.", &k, 5000) && k.failed && k.ask == 0 && places_are(0, 2000));       /* (the lookup found the zone and the database could not give it: SERVFAIL + EDE 14 for the queries, not a silent drop at park-timeout) */
        {
            store_zone_t lz;
            CHECK(zrec(st, "knownz.test", &lz) && lz.state == STORE_STATE_KNOWN && !in_memory("knownz.test."));
        }
        /* the claim of a lookup is a key of its own: a lookup of the name "apex6.test." in flight does not hold the mark of the zone "apex6.test." (its fetch is not the duplicate of the lookup) */
        drain_wakes();
        CHECK(lk_asked("apex6.test."));
        rid = lk_next(&fetchc, "apex6.test.");
        CHECK(park_claim_held(park_lookup_claim_key("default", "apex6.test.")) && !park_claim_held(park_claim_key("default", "apex6.test.")));
        /* the name is the zone's apex and the body fails: the queries of the name are failed too (they share the key with the zone's) */
        lk_found(f[0], &e, rid, 880066, "apex6.test.", 1, 1);
        kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "apex6.test."); kdb_enc_i64(&e, 3, 880066); kdb_enc_str(&e, 4, "reading the records: the database is busy"); kdb_enc_u64(&e, 5, rid);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
        CHECK(wake_for("apex6.test.", &k, 5000) && k.failed && k.ask == 0 && places_are(0, 2000) && !park_claim_held(park_lookup_claim_key("default", "apex6.test.")));
        /* the loader says "busy" (KDB_FETCH_BUSY_REASON): overload, not a failure: the queries that wait are dropped (a wake with PARK_ASK_DROP: counted store.park.drop.queue / store.lookup.drop.queue at their workers), not
         * answered SERVFAIL.  Once for the lookup itself, once for the body of the zone that it found */
        drain_wakes();
        CHECK(lk_asked("w.busy1.test."));
        rid = lk_next(&fetchc, "w.busy1.test.");
        kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "w.busy1.test."); kdb_enc_i64(&e, 3, 880068); kdb_enc_str(&e, 4, KDB_FETCH_BUSY_REASON); kdb_enc_u64(&e, 5, rid);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
        CHECK(wake_for("w.busy1.test.", &k, 5000) && !k.failed && k.ask == PARK_ASK_DROP && places_are(0, 2000));
        drain_wakes();
        CHECK(lk_asked("w.busy2.test."));
        rid = lk_next(&fetchc, "w.busy2.test.");
        lk_found(f[0], &e, rid, 880067, "busy2.test.", 1, 1);
        kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "busy2.test."); kdb_enc_i64(&e, 3, 880067); kdb_enc_str(&e, 4, KDB_FETCH_BUSY_REASON); kdb_enc_u64(&e, 5, rid);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
        CHECK(wake_for("w.busy2.test.", &k, 5000) && !k.failed && k.ask == PARK_ASK_DROP && places_are(0, 2000));
        CHECK(db_recon_delete("default", 880067, NULL) == 1);                                    /* (the record of the zone that the lookup found stays known, and the fill would ask for its body some time later: it goes) */

    }

    /* -- 5. two names of one zone asked for at once: the first answer starts the fetch of the zone, the second finds it on its way (or in memory): its body is read through and thrown away, the zone is installed once,
     *       and both queries are woken */
    {
        drain_wakes();
        CHECK(lk_asked("a.skip.test.") && lk_asked("b.skip.test."));
        const uint64_t ra = lk_next(&fetchc, "a.skip.test."), rb = lk_next(&fetchc, "b.skip.test.");
        CHECK(places_are(2, 2000));
        lk_found(f[0], &e, ra, 990001, "skip.test.", 1, 1);
        lk_found(f[0], &e, rb, 990001, "skip.test.", 1, 1);
        CHECK(wake_for("b.skip.test.", &k, 5000) && !k.failed && !in_memory("skip.test."));        /* (not the body's: it is not read) */
        const uint64_t bad0 = lk_stats().bad_body;
        send_zone(f[0], &e, "skip.test.", 3, ra, 990001);
        CHECK(wake_for("a.skip.test.", &k, 5000) && in_memory("skip.test.") && places_are(1, 2000));
        send_zone(f[0], &e, "skip.test.", 4, rb, 990001);                                         /* (the loader sends it all the same) */
        CHECK(places_are(0, 5000) && lk_stats().bad_body == bad0 && dbreg_zone_version("default", "skip.test.", &sid, &sr) && sr == 3);
    }

    /* -- 6. the places: the lookups may take three quarters of fetch-concurrency (6 of 8); the rest of them wait in a queue of their own, a fetch of a zone is not held up by them, each answer frees its place at once
     *       and the next lookup goes, and a lookup that waits longer than park-timeout (1 s) is dropped and its queries woken */
    {
        drain_wakes();
        char nm[40];
        uint64_t qr[10];
        const uint64_t exp0 = lk_stats().expired;
        for (int i = 0; i < 10; i++) {
            snprintf(nm, sizeof(nm), "q%d.nz.test.", i);
            CHECK(lk_asked(nm));
        }
        for (int i = 0; i < 6; i++) {
            snprintf(nm, sizeof(nm), "q%d.nz.test.", i);
            qr[i] = lk_next(&fetchc, nm);
        }
        CHECK(!ch_next(&fetchc, &m, 300));                                                        /* (the share is used: the others wait) */
        CHECK(lk_stats().in_flight == 6 && lk_stats().pending == 4 && places_are(6, 2000));
        lk_none(f[0], &e, qr[0]);                                                                 /* (the answer "none" gives the place back, and the oldest that waited goes out) */
        qr[6] = lk_next(&fetchc, "q6.nz.test.");
        CHECK(lk_stats().in_flight == 6 && lk_stats().pending == 3 && park_places_used() == 6);
        CHECK(park_fetch_request(0, "default", "knownz.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));        /* (a zone that the store knows: the two places that are left are its) */
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_FULL && strcmp(m.u.fetch_req.name, "knownz.test.") == 0 && places_are(7, 2000));
        send_zone(f[0], &e, "knownz.test.", 3, m.u.fetch_req.request_id, 777999);
        CHECK(wake_for("knownz.test.", &k, 5000) && !k.failed && in_memory("knownz.test.") && places_are(6, 2000));
        for (int i = 7; i < 10; i++) {                                                            /* (the three that are left wait their park-timeout out: dropped, their queries woken, nothing is asked) */
            snprintf(nm, sizeof(nm), "q%d.nz.test.", i);
            CHECK(wake_for(nm, &k, 5000) && !k.failed && k.ask == PARK_ASK_DROP);                 /* (the queries are dropped, not woken to be refused) */
        }
        CHECK(lk_stats().expired == exp0 + 3 && lk_stats().pending == 0 && !ch_next(&fetchc, &m, 300));
        for (int i = 1; i <= 6; i++) lk_none(f[0], &e, qr[i]);
        CHECK(places_are(0, 3000) && lk_stats().in_flight == 0);
        /* the claim of a name that was dropped is free: it can be asked for again */
        CHECK(lk_asked("q7.nz.test."));
        rid = lk_next(&fetchc, "q7.nz.test.");
        lk_none(f[0], &e, rid);
        CHECK(places_are(0, 3000));
    }
    /* -- 7. the queue is full: the lookups that find it so are dropped (their queries get the key of a drop, nothing is answered), the claim of their name is free, `shed` counts them; the ones that wait in it
     *       are dropped when their time is up (`expired`) */
    {
        drain_wakes();
        char nm[40];
        uint64_t sr[6];
        const uint64_t shed0 = lk_stats().shed, exp0 = lk_stats().expired, rem0 = lk_stats().remembered, rel0 = lk_stats().remember_releases;
        atomic_store(&db_ingest_test_lq_max, 3);
        for (int i = 0; i < 12; i++) {
            snprintf(nm, sizeof(nm), "s%d.nz.test.", i);
            CHECK(lk_asked(nm));
        }
        for (int i = 0; i < 6; i++) {
            snprintf(nm, sizeof(nm), "s%d.nz.test.", i);
            sr[i] = lk_next(&fetchc, nm);
        }
        CHECK(!ch_next(&fetchc, &m, 300));
        CHECK(lk_stats().in_flight == 6 && lk_stats().pending == 3 && lk_stats().shed == shed0 + 3);
        for (int t = 0; t < 400 && lk_stats().remembered < rem0 + 3; t++) usleep(1000);            /* (the counter of the shed goes up before the name is remembered) */
        const int64_t t_shed = mono_ms();                                                       /* (the sheds are done; the check below looks at this moment, not after the waits: a slow runner may pass park-timeout) */
        for (int i = 9; i < 12; i++) {
            snprintf(nm, sizeof(nm), "s%d.nz.test.", i);
            CHECK(park_shed_held(park_lookup_claim_key("default", nm), t_shed));                  /* (a name that was shed is remembered: its worker asks no more for it) */
            CHECK(wake_for(nm, &k, 5000) && k.ask == PARK_ASK_DROP && !k.failed && !park_claim_held(park_lookup_claim_key("default", nm)));
        }
        CHECK(!shed_held_now("s0.nz.test.") && !shed_held_now("s8.nz.test."));                    /* (the ones that were asked for, or wait, are not) */
        for (int i = 6; i < 9; i++) {
            snprintf(nm, sizeof(nm), "s%d.nz.test.", i);
            CHECK(wake_for(nm, &k, 5000) && k.ask == PARK_ASK_DROP);
            CHECK(shed_held_now(nm));                                                             /* (and so are the ones whose time was up in the queue) */
        }
        CHECK(lk_stats().expired == exp0 + 3 && lk_stats().pending == 0 && !ch_next(&fetchc, &m, 200));
        CHECK(lk_stats().remembered == rem0 + 6);
        for (int i = 0; i < 6; i++) lk_none(f[0], &e, sr[i]);
        CHECK(places_are(0, 3000));
        /* the thread has caught up (no queue, places free): the names are forgotten, so that the next query for them asks again */
        for (int t = 0; t < 400 && shed_held_now("s7.nz.test."); t++) usleep(5000);
        CHECK(!shed_held_now("s7.nz.test.") && !shed_held_now("s6.nz.test.") && lk_stats().remember_releases >= rel0 + 1);
        atomic_store(&db_ingest_test_lq_max, 0);
    }

    /* -- 8. with a fetch-rate, and with the zones in memory above the hard line of memory-limit, the Backend asks mode 2 (no body: the rate counts the zones read for queries, and the fetches wait for room);
     *       the zone that the answer names is recorded as ever */
    {
        for (int kase = 0; kase < 2; kase++) {
            drain_wakes();
            if (kase == 0) {
                lk_cfg("fetch-rate 5;", 5, 0);
            } else {
                lk_cfg("memory-limit 1024g;", 0, 100000);
                zone_bytes_resident_add(ZBYTES_DB, 1000000);
                CHECK(dbreg_cache_over_limit());
            }
            const uint64_t body0 = lk_stats().body_inline;
            const char *qn = kase ? "w.limz.test." : "w.ratez.test.", *zn = kase ? "limz.test." : "ratez.test.";
            CHECK(lk_asked(qn));
            rid = lk_next_mode(&fetchc, qn, KDB_FETCH_LOOKUP);
            lk_found(f[0], &e, rid, kase ? 991001 : 991000, zn, 1, 1);
            CHECK(wake_for(qn, &k, 5000) && !k.failed && places_are(0, 2000) && lk_stats().body_inline == body0);        /* (a lookup, no body: the request is over at the answer) */
            CHECK(!ch_next(&fetchc, &m, 200));
            CHECK(db_recon_delete("default", kase ? 991001 : 991000, NULL) == 1);
            if (kase) zone_bytes_resident_add(ZBYTES_DB, -1000000);
            lk_cfg("", 0, 0);
            drain_wakes();
            CHECK(lk_asked("w.back.test."));                                                    /* (the settings are gone: mode 3 again) */
            rid = lk_next(&fetchc, "w.back.test.");
            lk_none(f[0], &e, rid);
            CHECK(wake_for("w.back.test.", &k, 5000) && places_are(0, 2000));
        }
    }

    /* -- 9. the loader is replaced while lookups wait for an answer (fetch_adopt()): a lookup that waits for the answer is asked again, in mode 2 until the new loader's HELLO says it has the body; one whose body is on its
     *       way is asked again as the fetch of its zone; one whose body was not wanted (LKS_SKIP) has nothing to wait for and is over */
    {
        drain_wakes();
        CHECK(lk_asked("r1.adopt.test."));
        const uint64_t r1 = lk_next(&fetchc, "r1.adopt.test.");
        CHECK(lk_asked("a.skip2.test.") && lk_asked("b.skip2.test."));
        const uint64_t ra = lk_next(&fetchc, "a.skip2.test."), rb = lk_next(&fetchc, "b.skip2.test.");
        lk_found(f[0], &e, ra, 990101, "skip2.test.", 1, 1);
        lk_found(f[0], &e, rb, 990101, "skip2.test.", 1, 1);
        CHECK(wake_for("b.skip2.test.", &k, 5000) && !k.failed && places_are(3, 2000));
        close(a[0]);                                                                               /* (the loader goes) */
        close(f[0]);
        for (int t = 0; t < 400 && db_ingest_lookup_ready(); t++) usleep(5000);
        CHECK(!db_ingest_lookup_ready());
        int a2[2], f2[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a2) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f2) == 0);
        hand_over(cs[0], a2[1], f2[1]);
        static ch_t mainc2, fetchc2;
        ch_init(&mainc2, a2[0], KDB_FROM_BACKEND);
        ch_init(&fetchc2, f2[0], KDB_FROM_BACKEND);
        CHECK(lk_next_mode(&fetchc2, "r1.adopt.test.", KDB_FETCH_LOOKUP) == r1);              /* (mode 3 asked again as mode 2: the new loader has not said it has the body) */
        CHECK(ch_next(&fetchc2, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.request_id == ra && m.u.fetch_req.mode == KDB_FETCH_FULL && strcmp(m.u.fetch_req.name, "skip2.test.") == 0 &&
              m.u.fetch_req.source_id == 990101);
        CHECK(!ch_next(&fetchc2, &m, 300));                                                    /* (the one that was to be read through is not asked again) */
        CHECK(wake_for("b.skip2.test.", &k, 5000) && !k.failed && places_are(2, 2000));        /* (it is over: its place is back, its queries woken once more) */
        kdb_enc_begin(&e, KDB_T_HELLO);
        kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader-2"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4243); kdb_enc_u32(&e, 5, (KDB_FEAT_STORE | KDB_FEAT_LOOKUP) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
        kdb_enc_end(&e);
        ch_send(a2[0], &e);
        CHECK(ch_next(&mainc2, &m, 5000) && m.type == KDB_T_CONFIG);
        send_zone(f2[0], &e, "skip2.test.", 3, ra, 990101);
        CHECK(wake_for("a.skip2.test.", &k, 5000) && in_memory("skip2.test.") && places_are(1, 2000));
        lk_none(f2[0], &e, r1);
        CHECK(wake_for("r1.adopt.test.", &k, 5000) && places_are(0, 2000));
        CHECK(db_ingest_lookup_ready());
        drain_wakes();
        CHECK(lk_asked("w.after.test."));                                                       /* (the new loader has no body bit: mode 2) */
        rid = lk_next_mode(&fetchc2, "w.after.test.", KDB_FETCH_LOOKUP);
        lk_none(f2[0], &e, rid);
        CHECK(wake_for("w.after.test.", &k, 5000) && places_are(0, 2000));
        close(a2[0]);                                                                              /* (the loader goes again) */
        close(f2[0]);
        for (int t = 0; t < 400 && db_ingest_lookup_ready(); t++) usleep(5000);
        CHECK(!db_ingest_lookup_ready());
        /* the loader is away: a query for a name that no stored zone covers still waits for a lookup (the pass is not over), and the lookup waits in the queue for the loader; when its time is up it is dropped (a wake
         * with PARK_ASK_DROP: nothing is answered), it is not woken as "no zone" (REFUSED) */
        CHECK(db_ingest_lookup_wanted());
        drain_wakes();
        CHECK(lk_asked("away1.test."));
        CHECK(wake_for("away1.test.", &k, 6000) && !k.failed && k.ask == PARK_ASK_DROP);
        CHECK(!park_claim_held(park_lookup_claim_key("default", "away1.test.")));
    }
    {
        const store_lookup_t ls = lk_stats();
        printf("  (lookups: asked %llu, found %llu, none %llu, failed %llu, body_inline %llu, bad_body %llu, covered %llu, expired %llu)\n", (unsigned long long)ls.asked, (unsigned long long)ls.found,
               (unsigned long long)ls.none, (unsigned long long)ls.failed, (unsigned long long)ls.body_inline, (unsigned long long)ls.bad_body, (unsigned long long)ls.covered, (unsigned long long)ls.expired);
        CHECK(ls.body_inline == 10 && ls.found == 14 && ls.in_flight == 0 && ls.pending == 0 && ls.shed == 4);
    }
    printf("%d checks, %d failed\n", g_checks, g_failed);
    fflush(stdout);
    test_exit(g_failed ? 1 : 0);
}

/* ---------------------------------------------------------------- 0.7 M2: the reconcile thread and the group commit (phase 8) */
/* Part A: the entries of a pass applied in groups (db_recon_entry_n()) are what the same entries applied one at a time (db_recon_entry()) are: the same result of every entry, the same records, the same
 * counters of the pass, the same sweep.  Two views of one store, one for each way; the entries are those of a manifest with all its traps (a name that two ids claim, an id that two names claim, secondary
 * zones, stamps that change, unstamped zones, a forced entry, the root zone and a name that is too long for the store). */
static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}
typedef struct { db_recon_entry_t e; char name[400]; } gr_t;
static void gr_make(gr_t *g, uint64_t K, unsigned pool) {
    uint64_t r = mix64(K * 0x9e3779b97f4a7c15ull + 4242);
    unsigned i = (unsigned)(r % pool);
    memset(g, 0, sizeof(*g));
    unsigned p = (unsigned)((r >> 20) % 1000);
    if (p < 8) snprintf(g->name, sizeof(g->name), ".");
    else if (p < 14) { memset(g->name, 'a', 300); g->name[300] = '.'; g->name[301] = '\0'; g->name[63] = '.'; g->name[127] = '.'; g->name[191] = '.'; }
    else snprintf(g->name, sizeof(g->name), "g%u.test.", i);
    g->e.name = g->name;
    g->e.source_id = (int64_t)(7000 + i);
    unsigned q = (unsigned)((r >> 32) % 100);
    if (q < 12) g->e.source_id = (int64_t)(7000 + (unsigned)((r >> 40) % pool));      /* another zone's id: a rename, or a name taken over */
    else if (q < 15) g->e.source_id = 0;
    g->e.kind = ((r >> 48) % 100) < 12 ? KDB_ZK_SECONDARY : KDB_ZK_PRIMARY;
    unsigned s = (unsigned)((r >> 52) % 10);
    g->e.stamped = s < 8;
    g->e.gen = (r >> 56) % 3;
    g->e.time = g->e.gen * 10;
    g->e.has_serial = !g->e.stamped && s == 8;
    g->e.serial = (uint32_t)(r >> 58);
    g->e.force = ((r >> 10) % 100) < 4;
}
static void recon_snapshot(store_t *st, int vid, char (*names)[130], int *nz, uint8_t *state, uint16_t *flags, uint64_t *gen, int64_t *sid, int cap) {
    uint32_t cur = 0;
    store_zone_t z;
    int n = 0;
    store_read_lock();
    while (store_iter(st, &cur, &z) > 0) {
        if (z.view != (uint16_t)vid || n >= cap) continue;
        snprintf(names[n], 130, "%.120s", z.name);
        state[n] = z.state; flags[n] = z.flags; gen[n] = z.stamp_gen ^ (z.stamp_time << 8); sid[n] = z.source_id;
        n++;
    }
    store_read_unlock();
    *nz = n;
}
static int g_sort_names_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* review of M2: the answer of a lookup (the ingest thread: db_recon_lookup()) that comes during a pass is newer than the page of the pass (the loader read the page some time before the reconcile thread
 * applies it, an answer when it is asked for): the entry of the pass leaves the record as the answer made it, and the sweep does not delete the zone that only the answer listed */
static bool lkv_record(store_t *st, int64_t sid, store_zone_t *z) {
    const int vid = store_view_id(st, "lkv");
    bool ok = false;
    store_read_lock();
    const uint32_t zid = vid >= 0 ? store_find_source(st, (uint16_t)vid, sid, (uint16_t)vid) : STORE_NONE;
    ok = zid != STORE_NONE && store_zone_get(st, zid, z) == 0;
    store_read_unlock();
    return ok;
}
static void recon_lookup_in_pass(store_t *st) {
    printf("  [A2: the answer of a lookup during a pass]\n");
    char why[200];
    db_recon_end_t o;
    db_recon_entry_t e[2];
    int res[2];
    uint32_t zid[2];
    memset(e, 0, sizeof(e));
    e[0].source_id = 6001; e[0].name = "p1.lk.test."; e[0].kind = KDB_ZK_PRIMARY; e[0].stamped = true; e[0].gen = 1; e[0].time = 10;
    e[1].source_id = 6002; e[1].name = "p2.lk.test."; e[1].kind = KDB_ZK_PRIMARY; e[1].stamped = true; e[1].gen = 1; e[1].time = 10;
    CHECK(db_recon_begin("lkv", 2, true, why, sizeof(why)));
    db_recon_entry_n(e, 2, res, zid);
    db_recon_end(true, 0, false, 0, NULL, 0, &o);
    CHECK(res[0] == DBR_NEW && res[1] == DBR_NEW && o.deleted == 0);
    /* the second pass: the answers of two lookups come first (p1 with a newer stamp, n1 a zone that the page does not list), then the page the loader read earlier: p1 with the old stamp and p2 */
    CHECK(db_recon_begin("lkv", 2, true, why, sizeof(why)));
    db_recon_entry_t a1 = e[0], n1;
    a1.gen = 5; a1.time = 50;
    memset(&n1, 0, sizeof(n1));
    n1.source_id = 6003; n1.name = "n1.lk.test."; n1.kind = KDB_ZK_PRIMARY; n1.stamped = true; n1.gen = 1; n1.time = 10;
    uint32_t lz = STORE_NONE;
    CHECK(db_recon_lookup("lkv", &a1, &lz) == DBR_CHANGED && lz != STORE_NONE);
    CHECK(db_recon_lookup("lkv", &n1, &lz) == DBR_NEW && lz != STORE_NONE);
    db_recon_entry_n(e, 2, res, zid);                                         /* (p1 with gen 1, p2 as before) */
    CHECK_MSG(res[0] == DBR_SAME && res[1] == DBR_PENDING, "the page after the answers: %d %d", res[0], res[1]);      /* (p1: the answer stays; p2: the same stamp, no body yet) */
    store_zone_t z;
    CHECK(lkv_record(st, 6001, &z) && z.stamp_gen == 5 && z.stamp_time == 50);        /* (the answer's stamp stays: the old page did not take it back) */
    db_recon_end(true, 0, false, 0, NULL, 0, &o);
    CHECK_MSG(o.deleted == 0 && o.unlisted == 0, "the sweep deleted %llu, unlisted %llu: the zone of the answer is not unlisted", (unsigned long long)o.deleted, (unsigned long long)o.unlisted);
    CHECK(lkv_record(st, 6003, &z) && lkv_record(st, 6001, &z) && lkv_record(st, 6002, &z));
    /* a pass that does not list the zone and has no answer for it: swept as ever */
    CHECK(db_recon_begin("lkv", 2, true, why, sizeof(why)));
    db_recon_entry_n(e, 2, res, zid);
    db_recon_end(true, 0, false, 0, NULL, 0, &o);
    CHECK_MSG(o.deleted == 1 && !lkv_record(st, 6003, &z), "the zone that no pass and no answer lists goes: deleted %llu", (unsigned long long)o.deleted);
}
static void recon_equivalence(store_t *st) {
    printf("  [A: entries in groups against entries one at a time]\n");
    const unsigned pool = 700;
    const int NR = 3;                                                    /* rounds: a first pass, then passes over what the first left (changes, renames, a sweep) */
    uint64_t K = 1;
    for (int round = 0; round < NR; round++) {
        const unsigned npass = round == 0 ? 2600 : 1800;
        gr_t *ent = malloc(sizeof(*ent) * npass);
        for (unsigned i = 0; i < npass; i++) gr_make(&ent[i], K++, pool);
        int *ra = malloc(sizeof(int) * npass), *rb = malloc(sizeof(int) * npass);
        uint32_t *za = malloc(sizeof(uint32_t) * npass), *zb = malloc(sizeof(uint32_t) * npass);
        char why[200];
        db_recon_status_t sa, sb;
        db_recon_end_t oa, ob;
        CHECK(db_recon_begin("grp", npass, true, why, sizeof(why)));
        unsigned off = 0;
        uint64_t rng = (uint64_t)round + 31;
        db_recon_entry_t *ee = malloc(sizeof(*ee) * npass);
        for (unsigned i = 0; i < npass; i++) ee[i] = ent[i].e;
        while (off < npass) {
            rng = mix64(rng);
            unsigned n = 1 + (unsigned)(rng % 190);
            if (n > npass - off) n = npass - off;
            db_recon_entry_n(ee + off, n, ra + off, za + off);
            off += n;
        }
        db_recon_end(true, 0, false, 0, NULL, 0, &oa);
        db_recon_status(&sa);
        CHECK(db_recon_begin("one", npass, true, why, sizeof(why)));
        for (unsigned i = 0; i < npass; i++) {
            zb[i] = STORE_NONE;
            rb[i] = db_recon_entry(&ee[i], &zb[i]);
        }
        db_recon_end(true, 0, false, 0, NULL, 0, &ob);
        db_recon_status(&sb);
        unsigned bad = 0;
        for (unsigned i = 0; i < npass; i++) {
            if (ra[i] != rb[i] || ((za[i] == STORE_NONE) != (zb[i] == STORE_NONE))) {
                if (bad++ < 5) printf("    entry %u (%s id %lld kind %d stamp %d/%llu): the group says %d, one at a time %d (zones %u / %u)\n", i, ent[i].name[0] == '.' ? "root" : ent[i].name, (long long)ee[i].source_id, ee[i].kind, ee[i].stamped, (unsigned long long)ee[i].gen, ra[i], rb[i], za[i], zb[i]);
            }
        }
        CHECK_MSG(bad == 0, "round %d: %u entries differ", round, bad);
        CHECK(sa.entries == sb.entries && sa.created == sb.created && sa.changed == sb.changed && sa.renamed == sb.renamed && sa.pending == sb.pending && sa.kept == sb.kept && sa.same == sb.same);
        CHECK(sa.entries == npass && sa.swept == sb.swept && sa.total == sb.total && sa.unlisted == sb.unlisted);
        CHECK(oa.swept == ob.swept && oa.held == ob.held && oa.failed == ob.failed && oa.total == ob.total && oa.unlisted == ob.unlisted && oa.deleted == ob.deleted);
        /* the zones of the two views at the end */
        const int va = store_view_id(st, "grp"), vb = store_view_id(st, "one");
        CHECK(va >= 0 && vb >= 0);
        enum { CAPZ = 2000 };
        static char na[CAPZ][130], nb[CAPZ][130];
        static uint8_t sta[CAPZ], stb[CAPZ];
        static uint16_t fa[CAPZ], fb[CAPZ];
        static uint64_t ga[CAPZ], gb[CAPZ];
        static int64_t ia[CAPZ], ib[CAPZ];
        int cna = 0, cnb = 0;
        recon_snapshot(st, va, na, &cna, sta, fa, ga, ia, CAPZ);
        recon_snapshot(st, vb, nb, &cnb, stb, fb, gb, ib, CAPZ);
        CHECK(cna == cnb && cna > 100);
        {                                                                    /* (the same names with the same records, by name) */
            char *pa[CAPZ], *pb[CAPZ];
            for (int i = 0; i < cna && i < CAPZ; i++) { pa[i] = na[i]; pb[i] = nb[i]; }
            qsort(pa, (size_t)cna, sizeof(char *), g_sort_names_cmp);
            qsort(pb, (size_t)cnb, sizeof(char *), g_sort_names_cmp);
            unsigned dn = 0;
            for (int i = 0; i < cna && i < cnb; i++) if (strcmp(pa[i], pb[i]) != 0) dn++;
            CHECK_MSG(dn == 0, "round %d: %u names differ between the views", round, dn);
            for (int i = 0; i < cna; i++) {
                int j = -1;
                for (int k = 0; k < cnb; k++) if (strcmp(na[i], nb[k]) == 0) { j = k; break; }
                if (j < 0 || sta[i] != stb[j] || fa[i] != fb[j] || ga[i] != gb[j] || ia[i] != ib[j]) { CHECK_MSG(false, "round %d: zone %s differs", round, na[i]); break; }
            }
        }
        printf("    round %d: %u entries: %llu new, %llu changed, %llu renamed, %llu pending, %llu kept, %llu same; the sweep %s (%llu of %llu), %d zones in each view\n", round, npass,
               (unsigned long long)sa.created, (unsigned long long)sa.changed, (unsigned long long)sa.renamed, (unsigned long long)sa.pending, (unsigned long long)sa.kept, (unsigned long long)sa.same,
               oa.swept ? "deleted" : "none", (unsigned long long)oa.deleted, (unsigned long long)oa.unlisted, cna);
        free(ent); free(ee); free(ra); free(rb); free(za); free(zb);
    }
    store_stats_t ss;
    store_read_lock();
    store_stats(st, &ss);
    store_read_unlock();
    CHECK(ss.group_records > 0 && ss.group_entries > ss.group_records);
    {
        store_check_report_t rep;
        CHECK(store_check(st, &rep) == 0);
    }
}

static void slow_entry(void) { usleep(1000); }
static bool st_text_has(const char *needle, int ms) {
    char *st = malloc(65536);
    bool found = false;
    for (int i = 0; i < ms / 10 && !found; i++) {
        if (db_ingest_status(NULL, NULL, st, 65536) > 0 && strstr(st, needle)) found = true;
        else usleep(10000);
    }
    free(st);
    return found;
}
static int64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void gm_zones(pz_t *z, int first, int n, int64_t sid_base, const char *tag) {
    for (int i = 0; i < n; i++) {
        memset(&z[i], 0, sizeof(z[i]));
        z[i].sid = sid_base + first + i;
        snprintf(z[i].name, sizeof(z[i].name), "%s%d.test.", tag, first + i);
        z[i].kind = KDB_ZK_PRIMARY;
        z[i].stamped = true;
        z[i].gen = 1;
        z[i].time = 10;
    }
}

static int run_recon_thread(const char *dir) {
    printf("[0.7 M2: the reconcile thread and the group commit (phase 8)]\n");
    signal(SIGPIPE, SIG_IGN);                                            /* (a stream that the Backend closed after a protocol error) */
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode map; "
             "store-threads 2; park-timeout 2000; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled());
    store_t *st = db_store_handle();
    CHECK(st != NULL);
    recon_equivalence(st);
    recon_lookup_in_pass(st);

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
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, (KDB_FEAT_STORE | KDB_FEAT_LOOKUP) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG && m.u.config.store_proto);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    db_recon_status_t rs;
    db_recon_status(&rs);
    CHECK(rs.recon_thread);                                              /* (the thread runs and reports) */

    /* -- B1. a pass of 3000 entries in two pages: the entries are recorded in groups, BATCH_RESULT has the counts */
    {
        static pz_t page[1500];
        db_recon_status_t r0;
        db_recon_status(&r0);
        p_batch_begin(a[0], &e, 1, KDB_BATCH_STARTUP, 0);
        p_manifest_begin(a[0], &e, 1, 3000, 5, true);
        gm_zones(page, 0, 1500, 3000000, "gm");
        p_manifest_page(a[0], &e, 1, 0, page, 1500);
        gm_zones(page, 1500, 1500, 3000000, "gm");
        p_manifest_page(a[0], &e, 1, 1, page, 1500);
        p_manifest_end(a[0], &e, 1, 3000, 0, 5, true);
        p_batch_end(a[0], &e, 1, 3000, 0);
        CHECK(p_result(&mainc, &m, 20000) && m.u.batch_result.n_applied == 3000 && m.u.batch_result.n_rejected == 0 && m.u.batch_result.n_unchanged == 0);
        uint64_t kn, sd;
        store_counts(st, &kn, &sd);
        store_stats_t ss;
        store_read_lock();
        store_stats(st, &ss);
        store_read_unlock();
        db_recon_status_t r1;
        db_recon_status(&r1);
        const uint64_t g0 = r0.rt_group_entries;
        CHECK(!db_store_directory_wait());                               /* (the pass has ended: BATCH_RESULT is answered after it) */
        CHECK_MSG(r1.passes == r0.passes + 1 && r1.created - 0 == 3000 && r1.entries == 3000, "the pass: %llu entries, %llu new", (unsigned long long)r1.entries, (unsigned long long)r1.created);
        CHECK_MSG(r1.rt_group_entries - g0 >= 2900 && r1.rt_group_records - r0.rt_group_records <= 3000 / STORE_GROUP_MAX + 6, "group commit: %llu entries in %llu records", (unsigned long long)(r1.rt_group_entries - g0), (unsigned long long)(r1.rt_group_records - r0.rt_group_records));
        CHECK(r1.rt_entries >= 3000 && r1.rt_pages >= 2 && r1.rt_queued == 0 && r1.recon_thread);
        CHECK(kn >= 3000);
        printf("    the pass: %llu entries in %llu group records\n", (unsigned long long)(r1.rt_group_entries - g0), (unsigned long long)(r1.rt_group_records - r0.rt_group_records));
        (void)serve_fetches(&fetchc, f[0], &e, 300, 0, 0);               /* (the fill asks for the bodies: none in this test) */
    }

    /* -- B2. a slow pass: the thread that reads the stream goes on serving the fetch stream (a lookup is on the fetch stream long before the pass ends: within 150 ms while the pass takes 600 ms; the bound is generous for a loaded host, the proof is that the request is there while 4 or more pages still wait and the pass is active), the pages wait in the ring (8 slots) and the loader's socket,
     *       and BATCH_RESULT is answered only when every entry is recorded: the counts are the whole pass's */
    {
        static pz_t page[10];
        uint64_t kn0, sd0, kn1, sd1;
        store_counts(st, &kn0, &sd0);
        db_recon_status_t r0;
        db_recon_status(&r0);                                              /* (the passes so far: the slow pass is the next one) */
        db_recon_test_entry_hook = slow_entry;                             /* (a millisecond for every entry: 600 entries, 600 ms) */
        p_batch_begin(a[0], &e, 2, KDB_BATCH_FULL, 0);
        p_manifest_begin(a[0], &e, 2, 600, 6, true);
        for (int pg = 0; pg < 60; pg++) {
            gm_zones(page, pg * 10, 10, 4000000, "gs");
            p_manifest_page(a[0], &e, 2, (uint32_t)pg, page, 10);
        }
        p_manifest_end(a[0], &e, 2, 600, 0, 6, true);
        p_batch_end(a[0], &e, 2, 600, 0);
        uint64_t maxq = 0;
        db_recon_status_t r;
        for (int i = 0; i < 100; i++) {
            db_recon_status(&r);
            if (r.rt_queued > maxq) maxq = r.rt_queued;
            if (r.rt_queued >= 4) break;
            usleep(2000);
        }
        CHECK_MSG(maxq >= 4, "pages wait for the thread (queued %llu)", (unsigned long long)maxq);
        drain_wakes();
        CHECK(db_ingest_lookup_ready());
        const int64_t t0 = now_us();
        CHECK(park_fetch_request(0, "default", "www.late8.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_LOOKUP));
        bool got_lookup = false;
        int n_fill = 0;
        while (!got_lookup && ch_next(&fetchc, &m, 2000)) {             /* (the fill may ask for bodies of the slow pass's zones first: those get "no body", as serve_fetches() does) */
            if (m.type != KDB_T_FETCH_REQ) continue;
            if (m.u.fetch_req.mode == KDB_FETCH_LOOKUP && strcmp(m.u.fetch_req.name, "www.late8.test.") == 0) { got_lookup = true; break; }
            kdb_enc_begin(&e, KDB_T_ZONE_FAILED);
            kdb_enc_u16(&e, 1, m.u.fetch_req.view); kdb_enc_name(&e, 2, m.u.fetch_req.name); kdb_enc_i64(&e, 3, m.u.fetch_req.source_id); kdb_enc_str(&e, 4, "no body in the test"); kdb_enc_u64(&e, 5, m.u.fetch_req.request_id);
            kdb_enc_end(&e);
            ch_send(f[0], &e);
            n_fill++;
        }
        CHECK_MSG(got_lookup, "the lookup request was not on the fetch stream (%d other requests)", n_fill);
        const int64_t dt = now_us() - t0;
        db_recon_status(&r);
        CHECK_MSG(r.active ? r.entries < 600 : r.passes == r0.passes, "the pass was over when the lookup request came (%llu entries, %llu passes, %llu before)", (unsigned long long)r.entries, (unsigned long long)r.passes, (unsigned long long)r0.passes);   /* (the request did not wait for the pass: the pass runs, or the thread has not begun it while its pages wait) */
        printf("    the request of a lookup was on the fetch stream %lld us after it was made, with %llu pages of the slow pass waiting\n", (long long)dt, (unsigned long long)maxq);
        CHECK_MSG(dt < 150000, "the lookup waited %lld us", (long long)dt);
        {
            kdb_enc_begin(&e, KDB_T_LOOKUP_RESULT);
            kdb_enc_u64(&e, 1, m.u.fetch_req.request_id); kdb_enc_u16(&e, 2, 0); kdb_enc_u8(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(f[0], &e);
        }
        CHECK(p_result(&mainc, &m, 30000) && m.u.batch_result.n_applied == 600 && m.u.batch_result.n_rejected == 0);
        store_counts(st, &kn1, &sd1);
        CHECK_MSG(kn1 - kn0 == 600, "BATCH_RESULT came with %llu of the 600 entries recorded", (unsigned long long)(kn1 - kn0));
        db_recon_status(&r);
        CHECK(!r.active && r.entries == 600 && r.rt_full_stops > 0 && r.rt_queued == 0);
        printf("    the stream thread stopped reading %llu times because the ring was full\n", (unsigned long long)r.rt_full_stops);
        db_recon_test_entry_hook = NULL;
        (void)serve_fetches(&fetchc, f[0], &e, 300, 0, 0);
    }

    /* -- B3. a loader that is hostile: a page that is not the next one ends the stream, the entries before it were recorded, the ones after it are not; the pass sweeps nothing */
    {
        static pz_t page[8];
        uint64_t kn0, sd0, kn1, sd1;
        store_counts(st, &kn0, &sd0);
        p_batch_begin(a[0], &e, 3, KDB_BATCH_FULL, 0);
        p_manifest_begin(a[0], &e, 3, 100, 7, true);
        gm_zones(page, 0, 8, 5000000, "gh");
        p_manifest_page(a[0], &e, 3, 0, page, 8);
        gm_zones(page, 8, 8, 5000000, "gh");
        p_manifest_page(a[0], &e, 3, 2, page, 8);                          /* (page 2 where page 1 is due) */
        gm_zones(page, 16, 8, 5000000, "gh");
        p_manifest_page(a[0], &e, 3, 1, page, 8);
        p_manifest_end(a[0], &e, 3, 24, 0, 7, true);
        p_batch_end(a[0], &e, 3, 24, 0);
        CHECK_MSG(st_text_has("last protocol error: MANIFEST: page 2, want 1", 5000), "the protocol error of the reconcile thread is logged and shown");
        CHECK(!ch_next(&mainc, &m, 300));                                    /* (the stream is closed: nothing answers) */
        for (int i = 0; i < 100; i++) { db_recon_status_t r; db_recon_status(&r); if (!r.active) break; usleep(10000); }
        store_counts(st, &kn1, &sd1);
        CHECK_MSG(kn1 - kn0 == 8, "the page before the bad one was recorded (%llu), none after it", (unsigned long long)(kn1 - kn0));
        db_recon_status_t r;
        db_recon_status(&r);
        CHECK(!r.active && r.swept == 0);                                    /* (the pass was cut off: nothing is swept) */
        store_zone_t z;
        CHECK(zrec(st, "gh3.test", &z));
        CHECK(!zrec(st, "gh9.test", &z) && !zrec(st, "gh17.test", &z));
    }

    /* -- C1. a new stream: a pass cut off in the middle (the stream is closed while pages wait in the ring), then a clean pass whose BATCH_RESULT has exactly its own counts (nothing of the stream that ended) */
    {
        int a2[2], f2[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a2) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f2) == 0);
        hand_over(cs[0], a2[1], f2[1]);
        close(a[0]);
        close(f[0]);
        a[0] = a2[0];
        f[0] = f2[0];
        ch_init(&mainc, a[0], KDB_FROM_BACKEND);
        ch_init(&fetchc, f[0], KDB_FROM_BACKEND);
        kdb_enc_begin(&e, KDB_T_HELLO);
        kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, (KDB_FEAT_STORE | KDB_FEAT_LOOKUP) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
        static pz_t page[10];
        uint64_t kn0, sd0, kn1, sd1;
        store_counts(st, &kn0, &sd0);
        db_recon_test_entry_hook = slow_entry;
        p_batch_begin(a[0], &e, 4, KDB_BATCH_FULL, 0);
        p_manifest_begin(a[0], &e, 4, 400, 8, true);
        for (int pg = 0; pg < 40; pg++) {
            gm_zones(page, pg * 10, 10, 6000000, "gc");
            p_manifest_page(a[0], &e, 4, (uint32_t)pg, page, 10);
        }
        usleep(40000);
        close(a[0]);                                                         /* the loader dies: some pages are recorded, some wait in the ring, the rest is in the socket */
        a[0] = -1;
        int waited = 0;
        db_recon_status_t r;
        for (; waited < 600; waited++) {
            db_recon_status(&r);
            if (!r.active && r.rt_queued == 0) break;
            usleep(10000);
        }
        db_recon_test_entry_hook = NULL;
        store_counts(st, &kn1, &sd1);
        CHECK_MSG(!r.active && r.rt_queued == 0, "the pass that was cut off is forgotten (active %d, queued %llu)", r.active, (unsigned long long)r.rt_queued);
        CHECK_MSG(kn1 - kn0 < 400 && r.swept == 0, "part of the pass was recorded (%llu of 400) and nothing swept", (unsigned long long)(kn1 - kn0));
        /* the supervisor starts a new loader */
        int a3[2], f3[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a3) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f3) == 0);
        hand_over(cs[0], a3[1], f3[1]);
        close(f[0]);
        a[0] = a3[0];
        f[0] = f3[0];
        ch_init(&mainc, a[0], KDB_FROM_BACKEND);
        ch_init(&fetchc, f[0], KDB_FROM_BACKEND);
        kdb_enc_begin(&e, KDB_T_HELLO);
        kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, (KDB_FEAT_STORE | KDB_FEAT_LOOKUP) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
        p_batch_begin(a[0], &e, 5, KDB_BATCH_FULL, 0);
        p_manifest_begin(a[0], &e, 5, 50, 9, true);
        gm_zones(page, 0, 10, 7000000, "gd");
        for (int pg = 0; pg < 5; pg++) {
            gm_zones(page, pg * 10, 10, 7000000, "gd");
            p_manifest_page(a[0], &e, 5, (uint32_t)pg, page, 10);
        }
        p_manifest_end(a[0], &e, 5, 50, 0, 9, true);
        p_batch_end(a[0], &e, 5, 50, 0);
        CHECK_MSG(p_result(&mainc, &m, 20000) && m.u.batch_result.n_applied == 50 && m.u.batch_result.n_unchanged == 0 && m.u.batch_result.n_rejected == 0 && m.u.batch_result.n_deleted == 0,
                  "the clean pass after the cut-off one: applied %u unchanged %u rejected %u deleted %u (the counts are its own)", m.u.batch_result.n_applied, m.u.batch_result.n_unchanged, m.u.batch_result.n_rejected, m.u.batch_result.n_deleted);
        /* a MANIFEST_END whose sum is not the sum of the pages ends the stream before the sweep (nothing is deleted) */
        p_batch_begin(a[0], &e, 6, KDB_BATCH_FULL, 0);
        p_manifest_begin(a[0], &e, 6, 10, 10, true);
        gm_zones(page, 0, 10, 7000000, "gd");
        p_manifest_page(a[0], &e, 6, 0, page, 10);
        p_manifest_end(a[0], &e, 6, 11, 0, 10, true);
        p_batch_end(a[0], &e, 6, 11, 0);
        CHECK_MSG(st_text_has("last protocol error: MANIFEST_END: n_entries differs from the entries of the pages", 5000), "a pass whose end has another sum ends the stream");
        for (int i = 0; i < 100; i++) { db_recon_status(&r); if (!r.active) break; usleep(10000); }
        store_zone_t z;
        CHECK(zrec(st, "gd49.test", &z));                                    /* (the sweep did not run: the zones the short pass did not list are still there) */
        CHECK(!r.active && r.swept == 0);
    }

    /* -- C2. the reconcile thread found a protocol error in a page and is idle again before the stream thread handles the next frame (the event that tells the stream thread is held off here): BATCH_END must not be
     *       handled (it would commit the pass), the stream is closed with the thread's reason, nothing after the bad page is recorded and no cursor is kept */
    {
        int a2[2], f2[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a2) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f2) == 0);
        hand_over(cs[0], a2[1], f2[1]);
        close(a[0]);
        close(f[0]);
        a[0] = a2[0];
        f[0] = f2[0];
        ch_init(&mainc, a[0], KDB_FROM_BACKEND);
        ch_init(&fetchc, f[0], KDB_FROM_BACKEND);
        kdb_enc_begin(&e, KDB_T_HELLO);
        kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, (KDB_FEAT_STORE | KDB_FEAT_LOOKUP) | KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
        CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
        static pz_t page[10];
        uint64_t kn0, sd0, kn1, sd1;
        store_counts(st, &kn0, &sd0);
        atomic_store(&db_ingest_test_recon_poll_off, true);
        p_batch_begin(a[0], &e, 8, KDB_BATCH_FULL, 0);
        p_manifest_begin(a[0], &e, 8, 20, 12, true);
        gm_zones(page, 0, 10, 9000000, "gf");
        p_manifest_page(a[0], &e, 8, 1, page, 10);                           /* (page 1 where page 0 is due: the thread fails it) */
        usleep(150000);                                                       /* (the thread has failed the page and is idle: nothing else is posted yet) */
        db_recon_status_t r2;
        db_recon_status(&r2);
        CHECK(r2.rt_queued == 0);
        p_manifest_end(a[0], &e, 8, 10, 0, 12, true);
        p_batch_end(a[0], &e, 8, 10, 0);
        CHECK_MSG(st_text_has("last protocol error: MANIFEST: page 1, want 0", 5000), "the stream thread took the thread's protocol error before it handled the next frame");
        CHECK(!ch_next(&mainc, &m, 300));                                    /* (no BATCH_RESULT: the pass was not committed) */
        atomic_store(&db_ingest_test_recon_poll_off, false);
        for (int i = 0; i < 100; i++) { db_recon_status(&r2); if (!r2.active) break; usleep(10000); }
        store_counts(st, &kn1, &sd1);
        CHECK_MSG(kn1 == kn0, "nothing of the bad pass was recorded (%llu)", (unsigned long long)(kn1 - kn0));
        CHECK(!r2.active && r2.swept == 0);
    }
    db_recon_status(&rs);
    printf("  (the reconcile thread: %llu entries in %llu pages)\n", (unsigned long long)rs.rt_entries, (unsigned long long)rs.rt_pages);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}


/* a part of the test in a process of its own: a part that ends without its "checks" line (a signal, an exit from a thread) says how it ended */
static int run_part(const char *cmd) {
    const int rc = system(cmd);
    if (rc == -1) printf("  [FAIL] %s: system() failed\n", cmd);
    else if (WIFSIGNALED(rc)) printf("  [FAIL] %s: killed by signal %d\n", cmd, WTERMSIG(rc));
    else if (WIFEXITED(rc) && WEXITSTATUS(rc) != 0) printf("  [FAIL] %s: exit status %d\n", cmd, WEXITSTATUS(rc));
    return rc;
}

static int proto_main(const char *self) {
    char dir[600];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/test_db_store_proto.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    int bad = 0;
    for (int phase = 0; phase < 9; phase++) {
        char cmd[900];
        snprintf(cmd, sizeof(cmd), "%s proto%d %s", self, phase, dir);
        if (run_part(cmd) != 0) bad++;
        if (phase == 0 || phase == 2 || phase == 3 || phase == 5 || phase == 6 || phase == 7) {                   /* (phase 0 is the legacy loader on an empty store, phase 3 the fixes of the review, phase 4 the settings: the next phases start on a new store; phase 5 follows phase 4 on its store) */
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
    /* KARIDNS_NO_DEFAULT_STORE=1 (the test hook of tests/lib_proc.sh): no store in the default directory, whether or not /var/db/karidns exists; a named store is opened */
    {
        printf("  KARIDNS_NO_DEFAULT_STORE=1\n");
        const char *old = getenv("KARIDNS_NO_DEFAULT_STORE");
        char *keep = old ? strdup(old) : NULL;
        setenv("KARIDNS_NO_DEFAULT_STORE", "1", 1);
        database_config_t d0;
        memset(&d0, 0, sizeof(d0));
        d0.enabled = true;
        bool dflt = false;
        CHECK(db_store_dir_of(&d0, &dflt) != NULL && dflt);
        CHECK(db_store_frontend_open(&d0, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() < 0 && strstr(msg, "KARIDNS_NO_DEFAULT_STORE=1") != NULL);
        CHECK(db_store_frontend_open(&db, root, run_uid, run_gid, msg, sizeof(msg)) && db_store_dir_fd() >= 0);   /* (as the loop above: as root the directory is the run user's) */
        db_store_frontend_close();
        if (keep) { setenv("KARIDNS_NO_DEFAULT_STORE", keep, 1); free(keep); } else unsetenv("KARIDNS_NO_DEFAULT_STORE");
    }
    char cmd[800];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", base);
    (void)!system(cmd);
    return 0;
}

/* ---------------------------------------------------------------- S5: what an attached zone costs in the heap */
/* `test_db_store heap [zones] [map|copy]`: install N small zones (they are attached at once), and read the allocator's byte count before and after: the Backend heap per attached zone
 * (the entry with its block, the version, the settings, the registry element, the attach table; the image bytes in COPY mode).  The numbers are printed; the checks are that every zone
 * is attached and that the figure is under a generous bound.  jemalloc only (FreeBSD). */
#ifdef __FreeBSD__
#include <malloc_np.h>
#include <sys/resource.h>
static uint64_t heap_allocated(void) {
    uint64_t epoch = 1;
    size_t l = sizeof(epoch);
    (void)mallctl("epoch", &epoch, &l, &epoch, l);
    size_t v = 0;
    l = sizeof(v);
    if (mallctl("stats.allocated", &v, &l, NULL, 0) != 0) return 0;
    return (uint64_t)v;
}
#else
static uint64_t heap_allocated(void) { return 0; }
#endif
static int run_heap(int nz, const char *mode) {
    printf("[heap per attached zone: %d zones, %s mode]\n", nz, mode);
    char dir[] = "/tmp/test_db_store_heap.XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char sdir[600];
    snprintf(sdir, sizeof(sdir), "%s/s", dir);
    static server_config_t cfg;
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; store-mode %s; store-threads 2; }; };\n"
             "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", sdir, mode);
    CHECK(parse_named_conf(conf, &cfg) == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    char msg[400];
    CHECK(db_store_frontend_open(&cfg.database, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg)) && db_store_dir_fd() >= 0);
    CHECK(db_store_start(&cfg) && db_store_enabled() && dbdir() != NULL);
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
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242); kdb_enc_u32(&e, 5, KDB_FEAT_IMAGE); kdb_enc_u32(&e, 6, ZONE_IMAGE_VERSION);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_DEBUG);
    usleep(200000);
    const uint64_t h0 = heap_allocated();
    const int per = 2500;
    for (int b = 0; b * per < nz; b++) {
        batch_begin(a[0], &e, (uint64_t)b + 1, b == 0 ? KDB_BATCH_STARTUP : KDB_BATCH_DIFF);
        int n = nz - b * per < per ? nz - b * per : per;
        for (int i = 0; i < n; i++) {
            char zn[32];
            snprintf(zn, sizeof(zn), "z%07d.test.", b * per + i);
            send_zone(a[0], &e, zn, 1, 0, 10000 + b * per + i);
        }
        batch_end(a[0], &e, &mainc, (uint64_t)b + 1, (uint32_t)n, 0);
    }
    for (int i = 0; i < 600 && dbdir()->attach_count() < (size_t)nz; i++) usleep(100000);
    usleep(500000);
    const size_t att = dbdir()->attach_count();
    const uint64_t h1 = heap_allocated();
    CHECK(att == (size_t)nz);
    printf("  attached %zu zones; sizeof(zone_db_entry_t) %zu, sizeof(zdir_elem_t) %zu, sizeof(zone_config_t) %zu, sizeof(zone_version_t) %zu, sizeof(zone_x_t) %zu\n", att, sizeof(zone_db_entry_t), sizeof(zdir_elem_t),
           sizeof(zone_config_t), sizeof(zone_version_t), sizeof(zone_x_t));
    if (h1 > h0 && att) printf("  heap: %llu -> %llu bytes allocated: %.1f bytes per attached zone\n", (unsigned long long)h0, (unsigned long long)h1, (double)(h1 - h0) / (double)att);
#ifdef __FreeBSD__
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) printf("  maxrss %ld KiB\n", ru.ru_maxrss);
#endif
    CHECK(h1 == 0 || att == 0 || (h1 - h0) / att < 4096);
    /* the zones taken out of memory and attached again from the store: in MAP mode the image is the mapped file (no heap), in COPY mode a buffer */
    for (int i = 0; i < nz; i++) {
        char zn[32];
        snprintf(zn, sizeof(zn), "z%07d.test.", i);
        CHECK(dbreg_test_evict("default", zn));
    }
    for (int i = 0; i < 6000 && (dbdir()->attach_count() > 0 || dbreg_evict_inflight() != 0); i++) { zone_retire_process(true); usleep(10000); }
    const uint64_t h2 = heap_allocated();
    CHECK(dbdir()->attach_count() == 0);
    for (int i = 0; i < nz; i++) {
        char zn[32];
        snprintf(zn, sizeof(zn), "z%07d.test.", i);
        db_store_attach_zone("default", zn);
    }
    for (int i = 0; i < 600 && dbdir()->attach_count() < (size_t)nz; i++) usleep(100000);
    usleep(500000);
    const uint64_t h3 = heap_allocated();
    CHECK(dbdir()->attach_count() == (size_t)nz);
    if (h3 > h2 && nz > 0) printf("  attached again from the store: %.1f bytes per attached zone (heap %llu -> %llu)\n", (double)(h3 - h2) / (double)nz, (unsigned long long)h2, (unsigned long long)h3);
    if (nz > 0) printf("  what memory-limit counts for an attached zone (resident bytes of the zone totals / zones): %llu\n", (unsigned long long)(resident_bytes() / (uint64_t)nz));
    printf("%d checks, %d failed\n", g_checks, g_failed);
    char rm[700];
    snprintf(rm, sizeof(rm), "rm -rf %s", dir);
    (void)!system(rm);
    fflush(stdout);
    test_exit(g_failed ? 1 : 0);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);                               /* (as the server does, dns_server_core.c: a write to a stream whose other end the test closed is EPIPE, not the end of the process; the parts inherit it) */
    zi_www_varies = 1;                                      /* (the www address of a zone follows its serial) */
    setvbuf(stdout, NULL, _IOLBF, 0);                       /* (a log that shows where the time goes, also through a pipe) */
    g_self = argv[0];
    if (argc > 3 && strcmp(argv[1], "hot") == 0) return run_hot(argv[2], atoi(argv[3]));
    if (argc > 2 && strcmp(argv[1], "attab") == 0) return run_attab(argv[2]);
    if (argc > 1 && strcmp(argv[1], "s5") == 0) return run_s5(argc > 2 ? argv[2] : "map");
    if (argc > 1 && strcmp(argv[1], "heap") == 0) return run_heap(argc > 2 ? atoi(argv[2]) : 100000, argc > 3 ? argv[3] : "map");
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] == '3') return run_fixes(argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] == '6') return run_stamp_race(argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] == '7') return run_lookup_body(argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] == '8') return run_recon_thread(argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && (argv[1][5] == '4' || argv[1][5] == '5')) return run_settings(argv[1][5] - '0', argv[2]);
    if (argc > 2 && strncmp(argv[1], "proto", 5) == 0 && argv[1][5] >= '0' && argv[1][5] <= '2') return run_proto(argv[1][5] - '0', argv[2]);
    if (argc > 1) return run_mode(strcmp(argv[1], "copy") == 0 ? "copy" : "map");
    if (lock_tests() != 0 || g_failed) { printf("%d checks, %d failed\n", g_checks, g_failed); return 1; }
    printf("lock file: %d checks\n", g_checks);
    /* the second mode is a second process: the ingest thread and the store are process wide */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s copy", argv[0]);
    int rc = run_part(cmd);
    int rc2 = run_mode("map");
    int rc3 = proto_main(argv[0]);
    snprintf(cmd, sizeof(cmd), "%s s5 map", argv[0]);
    int rc4 = run_part(cmd);
    snprintf(cmd, sizeof(cmd), "%s s5 copy", argv[0]);
    int rc5 = run_part(cmd);
    return (rc != 0 || rc2 != 0 || rc3 != 0 || rc4 != 0 || rc5 != 0) ? 1 : 0;
}

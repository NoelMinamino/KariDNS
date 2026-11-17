/*
 * fetch_backend.c - a stand-in for the Backend on both streams of karidns-dbloader (tests/run_db_fetch_test.sh; D1a milestone 2).
 *
 *   fetch_backend LOADER DBFILE ITEM...
 *
 * It starts LOADER with the two streams (`-s 3 --fetch-fd 4`), answers the handshake of the first stream the way the Backend does (CONFIG for one
 * view "default" that reads DBFILE with the SQLite3 driver, an empty INVENTORY, BATCH_RESULT for every batch) and, once the startup batch is
 * through, runs the ITEMs on the fetch stream in order:
 *   req:ID:ZONE:PRIO:MODE   send FETCH_REQ (request id ID, view 0, zone ZONE, priority 0..2, mode 0 zone / 1 summary)
 *   range:ID:ZONE:LO:HI     send FETCH_REQ with a range
 *   wait:N                  read until N answers (a whole zone or a ZONE_FAILED) have come
 *   begin:ID                read until the ZONE_BEGIN of request ID has come (the loader is busy with it; the stream is read byte by byte up to it, so the rest of the zone stays with the loader)
 *   hold:MS                 wait MS milliseconds without reading either stream
 *   sleep:MS                keep serving the streams for MS milliseconds
 *   garbage:fetch           write bytes that are not KDB1 on the fetch stream; then wait for the loader to close it
 *   badmain                 send a FETCH_REQ on the first stream (a protocol error there); then wait for the loader to end
 *   flood:N:ZONE            send N requests (ids 1000..) for ZONE at once, priority 1
 * Every answer is checked by the state machine of the fetch stream (kdb_sm_init_fetch()) and printed, in the order it arrives:
 *   ANS id=ID zone=NAME kind=primary|secondary|catalog summary=0|1 presigned=0|1 serial=N rr=N (the RRs of the zone image) data=N (the ZONE_IMAGE messages) timers=R,T,E|-
 *   FAILED id=ID reason=TEXT
 * and at the end `DONE answers=N loader=STATUS`.  A protocol error of the loader prints `PROTOCOL ERROR: ...` and ends with status 1.
 *
 * 0.7 WP7a, the store protocol (options before the items):
 *   --store                 CONFIG store_proto = 1: no INVENTORY; the first stream goes through the state machine of the Backend (kdb_sm_accept())
 *   --views=N               N views (a, b, c, ...) that share the source (CONFIG shared_source), for the view mapping of karidns_domain_views
 *   --cursor=V:CURSOR[:IDENT]   the cursor (and identity, text) the Backend gives view V in CONFIG; --cursor=state:FILE reads `STATE` lines of an earlier run
 *   --auto[=SEC]            auto reload on, poll interval SEC (default 1), coalesce 100 ms
 *   --postgresql=CONNINFO:SCHEMA   the PostgreSQL driver (DBFILE is then ignored)
 *   --log=FILE              every manifest / changes entry, one line each:  M view id name kind stamped gen time serial   /   C view op id name kind stamped force gen time serial
 *   --signer-wait=0         CONFIG signer_wait 0
 *   --fail-batch=N[:ERRNO]  answer the N-th BATCH_END (counted from 1) with BATCH_RESULT tag 7 = ERRNO (default ENOSPC): the store could not record the batch (0.7,
 *                           KDB_FEAT_BATCH_STATUS); only when the loader's HELLO offers the feature
 * More items:
 *   sh:COMMAND              run COMMAND (system()) while the loader runs: it changes the database
 *   batches:N               serve the streams until N batches have ended (BATCH_END seen) in all
 *   reload / reloadforce    RELOAD_REQ scope all (force 0 / 1);  reloadzone:VIEW:ZONE  scope one zone, force 1
 *   state                   print the cursor the Backend would keep for every view (the last MANIFEST_END / CHANGES with last = 1)
 * Printed (store protocol): HELLO features=N; BB kind=K req=R; MB view=V count=N cursor=C valid=B ident=TEXT flags=F; ME view=V n=N seen=N skipped=N cursor=C valid=B
 * complete=B ident=TEXT ok=B (ok: the ids of the pages were strictly ascending and their number is n); CH view=V cursor=C last=B up=N del=N; ZD view=V id=I name=NAME;
 * BE zones=N failed=N deleted=N; BR batch=N store_error=E (the BATCH_RESULT sent); STATE view=V cursor=C valid=B ident=TEXT; at the end RSS kb=N (the peak of the loader process) before DONE.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

#include "../../dns_db_stream.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

typedef struct {
    int fd;
    kdb_framer_t fr;
    uint8_t *body;
    bool eof;
} chan_t;

static chan_t g_main, g_fetch;
static kdb_sm_t g_fsm;
static kdb_enc_t g_enc;
static bool g_startup_done;
static unsigned g_answers;
static uint64_t g_begin_seen[64];
static unsigned g_nbegin;
static bool g_hold;                      /* "begin:" is waiting: the fetch stream is read byte by byte, and no further than the ZONE_BEGIN waited for */
static uint64_t g_hold_id;
static bool begin_seen(void *a);
static pid_t g_pid;
static bool g_child_gone;
static int g_child_status;
static const char *g_dbfile;
/* 0.7 WP7a: the store protocol */
#define MAXV 8
static bool g_store, g_auto, g_signer_wait = true;
static unsigned g_nviews = 1, g_auto_sec = 1;
static const char *g_pg_conninfo, *g_pg_schema;
static struct { bool has; uint64_t cursor; uint8_t ident[KDB_IDENT_MAX]; uint8_t ilen; } g_cfg_cur[MAXV];      /* what CONFIG says */
static struct { bool valid; uint64_t cursor; uint8_t ident[KDB_IDENT_MAX]; uint8_t ilen; } g_keep[MAXV];       /* what the Backend would keep */
static FILE *g_log;
static kdb_sm_t g_msm;
static unsigned g_batches;
static unsigned g_fail_batch, g_fail_errno = ENOSPC;   /* --fail-batch */
static uint32_t g_loader_feat;          /* HELLO features of the loader */
static uint64_t g_reqid = 100;
static struct { bool open; uint16_t view; uint64_t last_id, n, seen; bool ok; } g_man;

static void die(const char *m) {
    printf("ERROR: %s\n", m);
    fflush(stdout);
    if (g_pid > 0) kill(g_pid, SIGKILL);
    exit(2);
}

static void write_all(int fd, const uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w > 0) {
            p += w;
            n -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pf = { fd, POLLOUT, 0 };
            poll(&pf, 1, 100);
            continue;
        }
        return;                                       /* (the loader is gone: the checks below say so) */
    }
}

static void send_enc(int fd) {
    if (g_enc.err) die("cannot encode a message");
    write_all(fd, g_enc.buf, g_enc.len);
    kdb_enc_reset(&g_enc);
}

static void send_config(void) {
    kdb_enc_reset(&g_enc);
    kdb_enc_begin(&g_enc, KDB_T_CONFIG);
    kdb_enc_u64(&g_enc, 1, 1);
    kdb_enc_str(&g_enc, 2, g_pg_conninfo ? "postgresql" : "sqlite3");
    for (unsigned v = 0; v < g_nviews; v++) {
        char nm[8];
        snprintf(nm, sizeof(nm), "%c", 'a' + (int)v);
        kdb_enc_nest_begin(&g_enc, 4);
        kdb_enc_u16(&g_enc, 1, (uint16_t)v);
        kdb_enc_str(&g_enc, 2, g_nviews > 1 ? nm : "default");
        kdb_enc_str(&g_enc, 3, g_pg_conninfo ? g_pg_schema : g_dbfile);
        if (g_pg_conninfo) kdb_enc_str(&g_enc, 4, g_pg_conninfo);
        kdb_enc_u8(&g_enc, 5, g_auto ? 1 : 0);
        kdb_enc_u32(&g_enc, 6, g_auto ? g_auto_sec : 2);
        kdb_enc_u32(&g_enc, 7, g_auto ? 100 : 1000);
        kdb_enc_u64(&g_enc, 8, KDB_DEFAULT_MAX_ZONE_RECORDS);
        kdb_enc_u64(&g_enc, 9, KDB_DEFAULT_MAX_ZONE_BYTES);
        if (g_nviews > 1) kdb_enc_u8(&g_enc, 10, 1);
        if (g_cfg_cur[v].has) {
            kdb_enc_u64(&g_enc, 11, g_cfg_cur[v].cursor);
            kdb_enc_u8(&g_enc, 12, 1);
            kdb_enc_bytes(&g_enc, 13, g_cfg_cur[v].ident, g_cfg_cur[v].ilen);
        }
        kdb_enc_nest_end(&g_enc);
    }
    kdb_enc_u32(&g_enc, 5, 3600);
    kdb_enc_u8(&g_enc, 6, 25);
    kdb_enc_u32(&g_enc, 7, 1);
    if (!g_signer_wait) kdb_enc_u8(&g_enc, 9, 0);
    if (g_store) kdb_enc_u8(&g_enc, 10, 1);
    kdb_enc_end(&g_enc);
    send_enc(g_main.fd);
}

static void hexs(const uint8_t *p, size_t n, char *out) {      /* the identity is text for the SQLite3 loader; shown as it is when printable */
    size_t k = 0;
    for (size_t i = 0; i < n; i++) out[k++] = (p[i] >= 0x21 && p[i] < 0x7F) ? (char)p[i] : '?';
    out[k] = '\0';
}

static void keep_cursor(unsigned view, uint64_t cursor, bool valid, const uint8_t *ident, uint8_t ilen) {
    if (view >= MAXV) return;
    g_keep[view].valid = valid;
    g_keep[view].cursor = cursor;
    g_keep[view].ilen = ilen;
    memcpy(g_keep[view].ident, ident, ilen);
}

static void print_state(void) {
    for (unsigned v = 0; v < g_nviews; v++) {
        char id[KDB_IDENT_MAX + 1];
        hexs(g_keep[v].ident, g_keep[v].ilen, id);
        printf("STATE view=%u cursor=%llu valid=%d ident=%s\n", v, (unsigned long long)g_keep[v].cursor, g_keep[v].valid ? 1 : 0, id);
    }
}

static void store_msg(const kdb_msg_t *m) {
    char id[KDB_IDENT_MAX + 1];
    switch (m->type) {
    case KDB_T_BATCH_BEGIN:
        printf("BB kind=%u req=%llu\n", m->u.batch_begin.kind, (unsigned long long)m->u.batch_begin.request_id);
        break;
    case KDB_T_MANIFEST_BEGIN: {
        const kdb_manifest_begin_t *b = &m->u.manifest_begin;
        hexs(b->ident, b->ident_len, id);
        printf("MB view=%u count=%llu cursor=%llu valid=%d ident=%s flags=%u\n", b->view, (unsigned long long)b->count, (unsigned long long)b->cursor,
               b->cursor_valid ? 1 : 0, id, b->flags);
        memset(&g_man, 0, sizeof(g_man));
        g_man.open = true;
        g_man.view = b->view;
        g_man.ok = true;
        break;
    }
    case KDB_T_MANIFEST: {
        kdb_iter_t it;
        kdb_manifest_entry_t e;
        kdb_manifest_entries(m, &it);
        while (kdb_manifest_entries_next(&it, &e)) {
            if ((uint64_t)e.source_id <= g_man.last_id && g_man.n > 0) g_man.ok = false;      /* ids strictly ascending */
            g_man.last_id = (uint64_t)e.source_id;
            g_man.n++;
            if (g_log)
                fprintf(g_log, "M %u %lld %s %u %d %llu %llu %lld\n", m->u.manifest.view, (long long)e.source_id, e.name, e.kind, e.stamped ? 1 : 0,
                        (unsigned long long)e.stamp_gen, (unsigned long long)e.stamp_time, e.has_serial ? (long long)e.serial : -1ll);
        }
        g_man.seen += m->u.manifest.n_entries;
        printf("MP view=%u page=%u n=%u\n", m->u.manifest.view, m->u.manifest.page, m->u.manifest.n_entries);
        break;
    }
    case KDB_T_MANIFEST_END: {
        const kdb_manifest_end_t *e = &m->u.manifest_end;
        hexs(e->ident, e->ident_len, id);
        bool ok = g_man.ok && g_man.n == e->n_entries && g_man.seen == e->n_entries;
        printf("ME view=%u n=%llu seen=%llu skipped=%llu cursor=%llu valid=%d complete=%d ident=%s ok=%d\n", e->view, (unsigned long long)e->n_entries,
               (unsigned long long)g_man.seen, (unsigned long long)e->n_skipped, (unsigned long long)e->cursor, e->cursor_valid ? 1 : 0, e->complete ? 1 : 0,
               id, ok ? 1 : 0);
        if (e->complete) keep_cursor(e->view, e->cursor, e->cursor_valid, e->ident, e->ident_len);
        g_man.open = false;
        break;
    }
    case KDB_T_CHANGES: {
        const kdb_changes_t *c = &m->u.changes;
        kdb_iter_t it;
        kdb_changes_entry_t e;
        unsigned up = 0, del = 0;
        kdb_changes_entries(m, &it);
        while (kdb_changes_entries_next(&it, &e)) {
            if (e.op == KDB_CH_UPSERT) up++;
            else del++;
            if (g_log)
                fprintf(g_log, "C %u %s %lld %s %u %d %d %llu %llu %lld\n", c->view, e.op == KDB_CH_UPSERT ? "up" : "del", (long long)e.source_id,
                        e.has_name ? e.name : "-", e.kind, e.stamped ? 1 : 0, e.force ? 1 : 0, (unsigned long long)e.stamp_gen,
                        (unsigned long long)e.stamp_time, e.has_serial ? (long long)e.serial : -1ll);
        }
        printf("CH view=%u cursor=%llu last=%d up=%u del=%u\n", c->view, (unsigned long long)c->cursor, c->last ? 1 : 0, up, del);
        if (c->last) keep_cursor(c->view, c->cursor, true, c->ident, c->ident_len);
        break;
    }
    case KDB_T_ZONE_DELETE:
        printf("ZD view=%u id=%lld name=%s\n", m->u.zone_delete.view, (long long)m->u.zone_delete.source_id, m->u.zone_delete.name);
        break;
    case KDB_T_ZONE_FAILED:
        printf("ZF view=%u id=%lld name=%s\n", m->u.zone_failed.view, (long long)m->u.zone_failed.source_id, m->u.zone_failed.name);
        break;
    default:
        break;
    }
}

static void main_msg(const kdb_msg_t *m) {
    switch (m->type) {
    case KDB_T_HELLO:
        if (g_store) printf("HELLO features=%u\n", m->u.hello.features);
        g_loader_feat = m->u.hello.features;
        send_config();
        break;
    case KDB_T_INVENTORY_REQ:
        kdb_enc_reset(&g_enc);
        kdb_enc_begin(&g_enc, KDB_T_INVENTORY_END);
        kdb_enc_u64(&g_enc, 1, 0);
        kdb_enc_u64(&g_enc, 2, 0);
        kdb_enc_end(&g_enc);
        send_enc(g_main.fd);
        break;
    case KDB_T_BATCH_END:
        g_batches++;
        if (g_store) printf("BE zones=%u failed=%u deleted=%u\n", m->u.batch_end.n_zones, m->u.batch_end.n_failed, m->u.batch_end.n_deleted);
        kdb_enc_reset(&g_enc);
        kdb_enc_begin(&g_enc, KDB_T_BATCH_RESULT);
        kdb_enc_u64(&g_enc, 1, m->u.batch_end.batch_id);
        kdb_enc_u32(&g_enc, 3, m->u.batch_end.n_zones);
        kdb_enc_u32(&g_enc, 4, 0);
        kdb_enc_u32(&g_enc, 5, 0);
        kdb_enc_u32(&g_enc, 6, 0);
        const uint32_t serr = (g_fail_batch == g_batches && (g_loader_feat & KDB_FEAT_BATCH_STATUS)) ? g_fail_errno : 0;
        if (serr) kdb_enc_u32(&g_enc, 7, serr);
        kdb_enc_end(&g_enc);
        send_enc(g_main.fd);
        g_startup_done = true;
        if (g_store) printf("BR batch=%llu store_error=%u\n", (unsigned long long)m->u.batch_end.batch_id, serr);
        break;
    default:
        break;
    }
}

/* the answer being received on the fetch stream */
static struct {
    bool open;
    uint64_t id;
    char zone[DNS_NAME_TEXT_SIZE];
    uint8_t kind;
    bool summary, presigned;
    uint32_t serial;
    uint64_t rr;
    unsigned data;
    bool timers;
    uint32_t tr, tt, te;
} g_cur;

static void fetch_msg(const kdb_msg_t *m) {
    switch (m->type) {
    case KDB_T_ZONE_BEGIN: {
        const kdb_zone_begin_t *z = &m->u.zone_begin;
        memset(&g_cur, 0, sizeof(g_cur));
        g_cur.open = true;
        g_cur.id = z->request_id;
        snprintf(g_cur.zone, sizeof(g_cur.zone), "%s", z->name);
        g_cur.kind = z->zone_kind;
        g_cur.summary = (z->flags & KDB_ZF_SUMMARY) != 0;
        g_cur.presigned = (z->flags & KDB_ZF_PRESIGNED) != 0;
        g_cur.serial = z->serial;
        g_cur.rr = z->rr_count;
        g_cur.timers = z->has_soa_timers;
        g_cur.tr = z->soa_refresh;
        g_cur.tt = z->soa_retry;
        g_cur.te = z->soa_expire;
        g_begin_seen[g_nbegin++ % (sizeof(g_begin_seen) / sizeof(g_begin_seen[0]))] = z->request_id;      /* (the last 64) */
        break;
    }
    case KDB_T_ZONE_IMAGE:
        g_cur.data++;
        break;
    case KDB_T_ZONE_END: {
        char t[64] = "-";
        if (g_cur.timers) snprintf(t, sizeof(t), "%u,%u,%u", g_cur.tr, g_cur.tt, g_cur.te);
        printf("ANS id=%llu zone=%s kind=%s summary=%d presigned=%d serial=%u rr=%llu data=%u timers=%s\n", (unsigned long long)g_cur.id, g_cur.zone,
               g_cur.kind == KDB_ZK_PRIMARY ? "primary" : g_cur.kind == KDB_ZK_SECONDARY ? "secondary" : "catalog", g_cur.summary ? 1 : 0,
               g_cur.presigned ? 1 : 0, g_cur.serial, (unsigned long long)g_cur.rr, g_cur.data, t);
        g_cur.open = false;
        g_answers++;
        break;
    }
    case KDB_T_ZONE_FAILED: {
        char r[260];
        size_t n = m->u.zone_failed.reason.len < sizeof(r) - 1 ? m->u.zone_failed.reason.len : sizeof(r) - 1;
        memcpy(r, m->u.zone_failed.reason.p, n);
        r[n] = '\0';
        printf("FAILED id=%llu zone=%s reason=%s\n", (unsigned long long)m->u.zone_failed.request_id, m->u.zone_failed.name, r);
        g_answers++;
        break;
    }
    default:
        break;
    }
}

static void pump(chan_t *c, bool fetch) {
    uint8_t buf[65536];
    for (;;) {
        ssize_t n = read(c->fd, buf, (fetch && g_hold) ? 1 : sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) {
            c->eof = true;
            return;
        }
        if (kdb_framer_feed(&c->fr, buf, (size_t)n) != KDB_OK) {
            printf("PROTOCOL ERROR: %s\n", c->fr.reason);
            exit(1);
        }
        kdb_frame_t fr;
        for (;;) {
            kdb_rc_t rc = kdb_framer_next(&c->fr, &fr);
            if (rc == KDB_MORE) break;
            if (rc != KDB_OK) {
                printf("PROTOCOL ERROR: %s\n", c->fr.reason);
                exit(1);
            }
            kdb_msg_t m;
            if (fetch) {
                rc = kdb_sm_accept(&g_fsm, &fr, &m);
                if (rc != KDB_OK) {
                    printf("PROTOCOL ERROR: %s\n", g_fsm.reason);
                    exit(1);
                }
                fetch_msg(&m);
                if (g_hold && begin_seen(&g_hold_id)) return;      /* (the 1-byte reads leave nothing behind in the framer: the loader keeps what it still has to send, so the worker is busy) */
            } else {
                char why[KDB_REASON_LEN];
                if (g_store) {                                  /* the rules the Backend applies to the loader's stream */
                    if (kdb_sm_accept(&g_msm, &fr, &m) != KDB_OK) {
                        printf("PROTOCOL ERROR: %s\n", g_msm.reason);
                        exit(1);
                    }
                } else if (kdb_decode(&fr, 1, &m, why, sizeof(why)) != KDB_OK) {
                    printf("PROTOCOL ERROR: %s\n", why);
                    exit(1);
                }
                if (g_store && (m.type == KDB_T_BATCH_BEGIN || m.type == KDB_T_MANIFEST_BEGIN || m.type == KDB_T_MANIFEST || m.type == KDB_T_MANIFEST_END ||
                                m.type == KDB_T_CHANGES || m.type == KDB_T_ZONE_DELETE || m.type == KDB_T_ZONE_FAILED))
                    store_msg(&m);
                main_msg(&m);
            }
        }
    }
}

/* the resident size of the loader now (FreeBSD: kinfo_proc; elsewhere 0): ru_maxrss is sampled by the statistics clock and misses a pass of a few milliseconds */
static long g_rss_max_kb;
static void sample_rss(void) {
#ifdef __FreeBSD__
    if (g_pid <= 0 || g_child_gone) return;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)g_pid };
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0 && len == sizeof(kp)) {
        long kb = (long)kp.ki_rssize * (long)(getpagesize() / 1024);
        if (kb > g_rss_max_kb) g_rss_max_kb = kb;
    }
#endif
}

/* serve both streams for up to ms milliseconds, or until done() */
static void service(int ms, bool (*done)(void *), void *arg) {
    int64_t end = now_ms() + ms;
    for (;;) {
        if (done && done(arg)) return;
        int64_t left = end - now_ms();
        if (left <= 0) return;
        struct pollfd pf[2] = { { g_main.fd, POLLIN, 0 }, { g_fetch.fd, POLLIN, 0 } };
        poll(pf, 2, left > 20 ? 20 : (int)left);
        sample_rss();
        if (pf[0].revents & (POLLIN | POLLHUP)) pump(&g_main, false);
        if (g_fetch.fd >= 0 && (pf[1].revents & (POLLIN | POLLHUP))) pump(&g_fetch, true);
        if (!g_child_gone && waitpid(g_pid, &g_child_status, WNOHANG) == g_pid) g_child_gone = true;
        if (g_child_gone) return;
    }
}

static bool startup_done(void *a) { (void)a; return g_startup_done; }
static bool answers_reached(void *a) { return g_answers >= *(unsigned *)a; }
static bool begin_seen(void *a) {
    unsigned n = g_nbegin < 64 ? g_nbegin : 64;
    for (unsigned i = 0; i < n; i++)
        if (g_begin_seen[i] == *(uint64_t *)a) return true;
    return false;
}
static bool batches_reached(void *a) { return g_batches >= *(unsigned *)a; }
static bool fetch_eof(void *a) { (void)a; return g_fetch.eof; }
static bool child_gone(void *a) { (void)a; return g_child_gone; }

static void send_req(uint64_t id, const char *zone, int prio, int mode, const char *lo, const char *hi, int64_t source_id) {
    kdb_enc_reset(&g_enc);
    kdb_enc_begin(&g_enc, KDB_T_FETCH_REQ);
    kdb_enc_u64(&g_enc, 1, id);
    kdb_enc_u16(&g_enc, 2, 0);
    kdb_enc_name(&g_enc, 3, zone);
    kdb_enc_u8(&g_enc, 4, (uint8_t)prio);
    kdb_enc_u8(&g_enc, 5, (uint8_t)mode);
    if (lo) {
        kdb_enc_name(&g_enc, 6, lo);
        kdb_enc_name(&g_enc, 7, hi);
    }
    if (source_id) kdb_enc_i64(&g_enc, 8, source_id);
    kdb_enc_end(&g_enc);
    send_enc(g_fetch.fd);
}

static void send_reload(bool all, bool force, unsigned view, const char *zone) {
    kdb_enc_reset(&g_enc);
    kdb_enc_begin(&g_enc, KDB_T_RELOAD_REQ);
    kdb_enc_u64(&g_enc, 1, g_reqid++);
    kdb_enc_u8(&g_enc, 2, all ? 0 : 1);
    if (!all) {
        kdb_enc_u16(&g_enc, 3, (uint16_t)view);
        kdb_enc_name(&g_enc, 4, zone);
    }
    kdb_enc_u8(&g_enc, 5, force ? 1 : 0);
    kdb_enc_end(&g_enc);
    send_enc(g_main.fd);
}

static void chan_init(chan_t *c, int fd) {
    c->fd = fd;
    c->body = malloc(KDB_MAX_BODY);
    if (!c->body) die("out of memory");
    kdb_framer_init(&c->fr, KDB_FROM_LOADER, c->body, KDB_MAX_BODY);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int main(int argc, char **argv) {
    int a0 = 1;
    for (; a0 < argc && strncmp(argv[a0], "--", 2) == 0; a0++) {         /* options come first (the store protocol) */
        const char *o = argv[a0];
        if (strcmp(o, "--store") == 0) g_store = true;
        else if (strncmp(o, "--views=", 8) == 0) g_nviews = (unsigned)atoi(o + 8);
        else if (strncmp(o, "--auto", 6) == 0) { g_auto = true; if (o[6] == '=') g_auto_sec = (unsigned)atoi(o + 7); }
        else if (strcmp(o, "--signer-wait=0") == 0) g_signer_wait = false;
        else if (strncmp(o, "--fail-batch=", 13) == 0) {
            char *p = NULL;
            g_fail_batch = (unsigned)strtoul(o + 13, &p, 10);
            if (p && *p == ':') g_fail_errno = (unsigned)atoi(p + 1);
            if (g_fail_batch == 0 || g_fail_errno == 0) die("--fail-batch=N[:ERRNO], N and ERRNO from 1");
        }
        else if (strncmp(o, "--log=", 6) == 0) { g_log = fopen(o + 6, "w"); if (!g_log) die("cannot open the log file"); setvbuf(g_log, NULL, _IOFBF, 1 << 16); }
        else if (strncmp(o, "--postgresql=", 13) == 0) {
            char *c = strdup(o + 13), *sc = c ? strrchr(c, '|') : NULL;
            if (!sc) die("--postgresql=CONNINFO|SCHEMA");
            *sc = '\0';
            g_pg_conninfo = c;
            g_pg_schema = sc + 1;
        } else if (strncmp(o, "--cursor=", 9) == 0) {
            char *c = strdup(o + 9);
            if (strncmp(c, "state:", 6) == 0) {                      /* STATE lines of an earlier run: view=V cursor=C valid=B ident=TEXT */
                FILE *sf = fopen(c + 6, "r");
                if (!sf) die("cannot read the state file");
                char line[512];
                while (fgets(line, sizeof(line), sf)) {
                    unsigned v = 0, valid = 0;
                    unsigned long long cur = 0;
                    char id[KDB_IDENT_MAX + 1] = "";
                    int n = sscanf(line, "STATE view=%u cursor=%llu valid=%u ident=%64s", &v, &cur, &valid, id);
                    if (n >= 3 && v < MAXV && valid) {
                        g_cfg_cur[v].has = true;
                        g_cfg_cur[v].cursor = cur;
                        g_cfg_cur[v].ilen = (uint8_t)(n == 4 ? strlen(id) : 0);
                        memcpy(g_cfg_cur[v].ident, id, g_cfg_cur[v].ilen);
                    }
                }
                fclose(sf);
            } else {
                unsigned v = (unsigned)atoi(c);
                char *p = strchr(c, ':');
                if (!p || v >= MAXV) die("--cursor=V:CURSOR[:IDENT]");
                g_cfg_cur[v].has = true;
                g_cfg_cur[v].cursor = strtoull(p + 1, &p, 10);
                if (p && *p == ':') {
                    g_cfg_cur[v].ilen = (uint8_t)strlen(p + 1);
                    memcpy(g_cfg_cur[v].ident, p + 1, g_cfg_cur[v].ilen);
                }
            }
        } else {
            fprintf(stderr, "unknown option %s\n", o);
            return 2;
        }
    }
    if (g_nviews < 1 || g_nviews > MAXV) die("--views=N, 1 to 8");
    if (argc - a0 < 2) {
        fprintf(stderr, "usage: fetch_backend [OPTION...] LOADER DBFILE ITEM...\n");
        return 2;
    }
    const char *loader = argv[a0];
    g_dbfile = argv[a0 + 1];
    signal(SIGPIPE, SIG_IGN);
    int a[2], f[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, a) != 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, f) != 0) die("socketpair");
    g_pid = fork();
    if (g_pid < 0) die("fork");
    if (g_pid == 0) {
        int h1 = fcntl(a[1], F_DUPFD, 10), h2 = fcntl(f[1], F_DUPFD, 10);
        if (h1 < 0 || h2 < 0 || dup2(h1, 3) < 0 || dup2(h2, 4) < 0) _exit(127);
        closefrom(5);
        execl(loader, "karidns-dbloader", "-s", "3", "--fetch-fd", "4", (char *)NULL);
        _exit(127);
    }
    close(a[1]);
    close(f[1]);
    chan_init(&g_main, a[0]);
    chan_init(&g_fetch, f[0]);
    kdb_framer_init(&g_fetch.fr, KDB_FROM_LOADER, g_fetch.body, KDB_MAX_BODY);
    kdb_limits_t lim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, 1 };
    kdb_sm_init_fetch(&g_fsm, &lim);
    kdb_limits_t mlim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, g_nviews };
    kdb_sm_init(&g_msm, &mlim);
    kdb_enc_init(&g_enc);

    service(30000, startup_done, NULL);
    if (!g_startup_done) die("the loader did not finish its startup batch");
    printf("STARTUP done\n");
    fflush(stdout);

    for (int i = a0 + 2; i < argc; i++) {
        const char *it = argv[i];
        if (strncmp(it, "req:", 4) == 0 || strncmp(it, "range:", 6) == 0) {
            bool range = it[0] == 'r' && it[1] == 'a';
            char buf[512];
            snprintf(buf, sizeof(buf), "%s", it + (range ? 6 : 4));
            char *p[6] = { 0 };
            int n = 0;
            for (char *s = buf; s && n < 6;) {
                p[n++] = s;
                s = strchr(s, ':');
                if (s) *s++ = '\0';
            }
            if (range ? n != 4 : (n != 4 && n != 5)) die("bad req item");
            send_req(strtoull(p[0], NULL, 10), p[1], range ? 0 : atoi(p[2]), range ? 0 : atoi(p[3]), range ? p[2] : NULL, range ? p[3] : NULL,
                     !range && n == 5 ? strtoll(p[4], NULL, 10) : 0);
        } else if (strncmp(it, "wait:", 5) == 0) {
            unsigned want = (unsigned)atoi(it + 5);
            service(30000, answers_reached, &want);
            if (g_answers < want) die("timed out waiting for answers");
        } else if (strncmp(it, "begin:", 6) == 0) {
            uint64_t id = strtoull(it + 6, NULL, 10);
            g_hold = true;                                      /* the Backend must not read the zone on: a drained zone frees the worker, and the requests that follow would find it idle */
            g_hold_id = id;
            service(30000, begin_seen, &id);
            g_hold = false;
            if (!begin_seen(&id)) die("timed out waiting for a ZONE_BEGIN");
        } else if (strncmp(it, "sh:", 3) == 0) {
            fflush(stdout);
            if (system(it + 3) != 0) die("sh: item failed");
        } else if (strncmp(it, "batches:", 8) == 0) {
            unsigned want = (unsigned)atoi(it + 8);
            service(60000, batches_reached, &want);
            if (g_batches < want) die("timed out waiting for batches");
        } else if (strcmp(it, "reload") == 0 || strcmp(it, "reloadforce") == 0) {
            send_reload(true, it[6] == 'f', 0, NULL);
        } else if (strncmp(it, "reloadzone:", 11) == 0) {
            char buf[300];
            snprintf(buf, sizeof(buf), "%s", it + 11);
            char *z = strchr(buf, ':');
            if (!z) die("bad reloadzone item");
            *z++ = '\0';
            send_reload(false, true, (unsigned)atoi(buf), z);
        } else if (strcmp(it, "state") == 0) {
            print_state();
        } else if (strncmp(it, "hold:", 5) == 0) {
            usleep((useconds_t)atoi(it + 5) * 1000);            /* (no reading: the loader keeps the zone it is writing, its reader thread gets the time to queue the requests that were sent) */
        } else if (strncmp(it, "sleep:", 6) == 0) {
            service(atoi(it + 6), NULL, NULL);
        } else if (strcmp(it, "garbage:fetch") == 0) {
            static const uint8_t junk[] = "NOT KDB1 AT ALL, JUST BYTES THAT ARE NOT A FRAME";
            write_all(g_fetch.fd, junk, sizeof(junk));
            service(10000, fetch_eof, NULL);
            printf("FETCH %s\n", g_fetch.eof ? "closed" : "still open");
            service(10000, child_gone, NULL);                   /* (a loader whose fetch stream is gone ends, for the supervisor to start another) */
            printf("LOADER %s\n", g_child_gone ? "ended" : "still running");
        } else if (strcmp(it, "closefetch") == 0) {
            close(g_fetch.fd);                                  /* the Backend drops the fetch stream (loader protocol error, send buffer overflow, memory) */
            g_fetch.fd = -1;
            service(10000, child_gone, NULL);
            printf("LOADER %s\n", g_child_gone ? "ended" : "still running");
        } else if (strcmp(it, "badmain") == 0) {
            kdb_enc_reset(&g_enc);
            kdb_enc_begin(&g_enc, KDB_T_FETCH_REQ);
            kdb_enc_u64(&g_enc, 1, 1);
            kdb_enc_u16(&g_enc, 2, 0);
            kdb_enc_name(&g_enc, 3, "x.test.");
            kdb_enc_u8(&g_enc, 4, 0);
            kdb_enc_u8(&g_enc, 5, 0);
            kdb_enc_end(&g_enc);
            send_enc(g_main.fd);
            service(10000, child_gone, NULL);
            printf("LOADER %s\n", g_child_gone ? "ended" : "still running");
        } else if (strncmp(it, "flood:", 6) == 0) {
            char buf[300];
            snprintf(buf, sizeof(buf), "%s", it + 6);
            char *z = strchr(buf, ':');
            if (!z) die("bad flood item");
            *z++ = '\0';
            int n = atoi(buf);
            kdb_enc_reset(&g_enc);                              /* all the requests in one write: they reach the loader together */
            for (int k = 0; k < n; k++) {
                kdb_enc_begin(&g_enc, KDB_T_FETCH_REQ);
                kdb_enc_u64(&g_enc, 1, 1000 + (uint64_t)k);
                kdb_enc_u16(&g_enc, 2, 0);
                kdb_enc_name(&g_enc, 3, z);
                kdb_enc_u8(&g_enc, 4, 1);
                kdb_enc_u8(&g_enc, 5, 0);
                kdb_enc_end(&g_enc);
            }
            send_enc(g_fetch.fd);
        } else {
            die("unknown item");
        }
        fflush(stdout);
    }
    /* the end of the Backend: the first stream is closed first and the fetch stream only once the loader has gone.  Closed together, the loader may see the
     * fetch stream go before the first one and end with an error status ("the fetch stream is gone"), as it should for a fetch stream lost on its own */
    close(g_main.fd);
    int64_t end = now_ms() + 15000;
    while (!g_child_gone && now_ms() < end) {
        if (waitpid(g_pid, &g_child_status, WNOHANG) == g_pid) g_child_gone = true;
        else usleep(20000);
    }
    close(g_fetch.fd);
    if (!g_child_gone) {
        kill(g_pid, SIGKILL);
        waitpid(g_pid, &g_child_status, 0);
    }
    if (g_store) {
        struct rusage ru;
        long kb = g_rss_max_kb;
        if (getrusage(RUSAGE_CHILDREN, &ru) == 0 && (long)ru.ru_maxrss > kb) kb = (long)ru.ru_maxrss;
        printf("RSS kb=%ld\n", kb);
        print_state();
    }
    if (g_log) fclose(g_log);
    printf("DONE answers=%u loader=%d\n", g_answers, WIFEXITED(g_child_status) ? WEXITSTATUS(g_child_status) : 128 + WTERMSIG(g_child_status));
    return 0;
}

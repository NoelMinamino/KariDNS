/*
 * test_db_fetch.c - the Backend's side of the fetch stream (dns_db_ingest.c, dns_park.c; D1a milestone 2, design 6.1, 4.3).
 *
 * The real db ingest thread runs in this process (db_ingest_start()) with the three descriptors the supervisor hands it, and the test is the
 * loader on both streams.  A "worker" is the test thread itself: it registers its rings (park_register_worker()), pushes fetch requests with
 * park_fetch_request() as a worker that has parked a query does, and takes the wake keys the ingest thread sends back.
 * Nothing in the server makes a zone leave memory yet, so the test does it by hand: it takes the entry out of the directory's element
 * (the state of an evicted zone) and then asks for the zone.  Cases:
 *   - a request for a zone of a view that takes no database zones, and for a zone that is not in the registry, is answered at once (failed wake)
 *   - a request for a zone that is in memory wakes the worker without a message to the loader
 *   - a request for a zone that is not in memory becomes one FETCH_REQ (a second request for it in flight sends nothing), its answer
 *     (ZONE_BEGIN .. ZONE_DATA .. ZONE_END with the request id) installs the zone, makes it resident again and wakes the worker
 *   - a ZONE_FAILED wakes the worker with the failure; a summary updates the serial and the timers of an element that has no data
 *   - a zone nobody asked for is read and thrown away: no zone appears, the stream goes on
 *   - bytes that are not KDB1 close the fetch stream; a request then is failed at once; a new pair of descriptors over the control socket
 *     (a restarted loader) gets the requests that were not answered
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
#include <sys/uio.h>

#include "../dns_config_parser.h"
#include "../dns_db_ingest.h"
#include "../dns_db_stream.h"
#include "../dns_dynamic_update.h"
#include "../dns_park.h"
#include "../dns_server_internal.h"
#include "../dns_snapshot_rcu.h"
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
    bool eof;
} ch_t;

static void ch_init(ch_t *c, int fd, kdb_dir_t dir) {
    c->fd = fd;
    c->eof = false;
    kdb_framer_init(&c->fr, dir, c->body, sizeof(c->body));
}

/* the next message, waiting up to ms; false: none (or the end of the stream, c->eof) */
static bool ch_next(ch_t *c, kdb_msg_t *m, int ms) {
    for (;;) {
        kdb_frame_t fr;
        kdb_rc_t rc = kdb_framer_next(&c->fr, &fr);
        if (rc == KDB_OK) {
            char why[KDB_REASON_LEN];
            if (kdb_decode(&fr, KDB_VIEWS_ANY, m, why, sizeof(why)) != KDB_OK) {
                printf("  decode: %s\n", why);
                return false;
            }
            return true;
        }
        if (rc != KDB_MORE) return false;
        struct pollfd p = { c->fd, POLLIN, 0 };
        if (poll(&p, 1, ms) <= 0) return false;
        ssize_t n = read(c->fd, c->buf, sizeof(c->buf));
        if (n <= 0) {
            c->eof = true;
            return false;
        }
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

/* ---------------------------------------------------------------- zone data (uncompressed RRs, RFC 1035 3.2.1) */
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

/* ZONE_DATA of the zone `zone` (SOA, NS, A, SOA): four RRs */
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
            b[start] = 192; b[start + 1] = 0; b[start + 2] = 2; b[start + 3] = 80;
            l = 4;
        }
        put_u16(b + o + rp[0], (uint16_t)l);
        o = start + l;
    }
    return o;
}

static void send_zone(int fd, kdb_enc_t *e, uint16_t view, const char *zone, uint32_t serial, uint64_t req, int64_t sid) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (int)serial, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
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

/* a zone of a batch that names a profile (the PROFILE message is the caller's) */
static void send_zone_p(int fd, kdb_enc_t *e, uint16_t view, const char *zone, uint32_t serial, int64_t sid, const char *profile) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, (int)serial, sizeof(dig));
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, 0); kdb_enc_u64(e, 7, 4); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    if (profile) kdb_enc_str(e, 10, profile);
    kdb_enc_end(e);
    uint8_t msg[2048];
    size_t n = zone_message(msg, zone, serial);
    kdb_enc_raw_msg(e, KDB_T_ZONE_DATA, msg, n);
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, 4);
    kdb_enc_end(e);
    ch_send(fd, e);
}

static void send_summary(int fd, kdb_enc_t *e, uint16_t view, const char *zone, uint32_t serial, uint64_t req, int64_t sid) {
    uint8_t dig[KDB_DIGEST_LEN] = { 0 };
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, KDB_ZF_SUMMARY); kdb_enc_u64(e, 7, 0); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    kdb_enc_u64(e, 11, req); kdb_enc_u32(e, 12, 1111); kdb_enc_u32(e, 13, 222); kdb_enc_u32(e, 14, 33333);
    kdb_enc_end(e);
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}

/* D1a milestone 4: the summary of a zone of a batch (the directory entry: settings, serial, SOA timers; no data) */
static void send_dir_zone(int fd, kdb_enc_t *e, uint16_t view, const char *zone, uint32_t serial, int64_t sid, const char *settings) {
    uint8_t dig[KDB_DIGEST_LEN] = { 0 };
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, KDB_ZF_SUMMARY); kdb_enc_u64(e, 7, 0); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    if (settings) kdb_enc_str(e, 9, settings);
    kdb_enc_u32(e, 12, 4444); kdb_enc_u32(e, 13, 555); kdb_enc_u32(e, 14, 66666);
    kdb_enc_name(e, 15, "ns1.hosting.example."); kdb_enc_name(e, 16, "host.hosting.example."); kdb_enc_u32(e, 17, 300); kdb_enc_u32(e, 18, 900); kdb_enc_u32(e, 19, 3600);
    kdb_enc_bytes(e, 20, (const uint8_t *)"ns1.hosting.example.\nns2.hosting.example.", 41);
    kdb_enc_end(e);
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}

/* D1a step 6: the summary of a zone in a batch whose apex has an NS name inside the zone and one outside it, and glue for the name with the index `gidx` (0: inside the
 * zone, 1: outside, which the Backend does not accept: no apex).  The glue: an A record and an AAAA record. */
static void send_glue_zone(int fd, kdb_enc_t *e, uint16_t view, const char *zone, uint32_t serial, int64_t sid, uint8_t gidx) {
    uint8_t dig[KDB_DIGEST_LEN] = { 0 };
    char ns[300];
    snprintf(ns, sizeof(ns), "ns1.%s\nns2.hosting.example.", zone);
    uint8_t gl[32] = { gidx, 1, 0, 0, 0x0e, 0x10, 192, 0, 2, 53, gidx, 28, 0, 0, 0x02, 0x58, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 };
    kdb_enc_begin(e, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, sid); kdb_enc_u8(e, 4, KDB_ZK_PRIMARY);
    kdb_enc_u32(e, 5, serial); kdb_enc_u32(e, 6, KDB_ZF_SUMMARY); kdb_enc_u64(e, 7, 0); kdb_enc_bytes(e, 8, dig, sizeof(dig));
    kdb_enc_u32(e, 12, 4444); kdb_enc_u32(e, 13, 555); kdb_enc_u32(e, 14, 66666);
    char mn[300];
    snprintf(mn, sizeof(mn), "ns1.%s", zone);
    kdb_enc_name(e, 15, mn); kdb_enc_name(e, 16, "host.hosting.example."); kdb_enc_u32(e, 17, 300); kdb_enc_u32(e, 18, 900); kdb_enc_u32(e, 19, 3600);
    kdb_enc_bytes(e, 20, (const uint8_t *)ns, strlen(ns));
    kdb_enc_bytes(e, 21, gl, sizeof(gl));
    kdb_enc_end(e);
    kdb_enc_begin(e, KDB_T_ZONE_END);
    kdb_enc_u64(e, 1, 0);
    kdb_enc_end(e);
    ch_send(fd, e);
}

static void send_failed(int fd, kdb_enc_t *e, uint16_t view, const char *zone, uint64_t req) {
    kdb_enc_begin(e, KDB_T_ZONE_FAILED);
    kdb_enc_u16(e, 1, view); kdb_enc_name(e, 2, zone); kdb_enc_i64(e, 3, 0); kdb_enc_str(e, 4, "no such zone in the database"); kdb_enc_u64(e, 5, req);
    kdb_enc_end(e);
    ch_send(fd, e);
}

/* ---------------------------------------------------------------- the worker's side */
extern int64_t g_ing_fetch_timeout_ms;                                 /* dns_db_ingest.c: 30 s, shortened here */

static bool wake_next(park_key_t *k, int ms) {
    park_wake_ring_t *r = park_wake_ring(0);
    for (int i = 0; i < ms / 2; i++) {
        if (park_wake_pop(r, k)) return true;
        usleep(2000);
    }
    return false;
}

static zdir_elem_t *elem_of(const char *view, const char *zone) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    zdir_elem_t *e = zdir_find_exact(snapshot_find_view(s, view), zone);
    release_zone_snapshot(s);
    return e;
}

/* take the data of the zone out of memory, as an eviction will: the element stays in the directory, its entry is gone (kept by the test) */
static zone_db_entry_t *evict(const char *zone) {
    zdir_elem_t *e = elem_of("default", zone);
    CHECK(e != NULL);
    zone_db_entry_t *en = zdir_entry(e);
    atomic_store(&e->entry, NULL);
    atomic_store(&e->state, ZDIR_ST_ABSENT);
    return en;
}

/* what the supervisor does after a restart of the loader: one message on the control socket, the Backend's end of the stream and (fetch_fd >= 0)
 * of the fetch stream as SCM_RIGHTS descriptors */
static void hand_over(int ctrl, int main_fd, int fetch_fd) {
    int fds[2] = { main_fd, fetch_fd };
    int n = fetch_fd >= 0 ? 2 : 1;
    for (int i = 0; i < n; i++) fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL, 0) | O_NONBLOCK);
    char byte = 'F';
    struct iovec iov = { &byte, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int) * 2)]; } u;
    memset(&u, 0, sizeof(u));
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = u.b;
    mh.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)n);
    struct cmsghdr *ch = CMSG_FIRSTHDR(&mh);
    ch->cmsg_level = SOL_SOCKET;
    ch->cmsg_type = SCM_RIGHTS;
    ch->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)n);
    memcpy(CMSG_DATA(ch), fds, sizeof(int) * (size_t)n);
    CHECK(sendmsg(ctrl, &mh, 0) == 1);
    for (int i = 0; i < n; i++) close(fds[i]);
}

/* a zone transfer thread waiting for a zone (D1a step 7) */
typedef struct {
    zdir_elem_t *el;
    zone_db_entry_t *res;
    int64_t t0, t1;
} await_t;
static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void *await_thread(void *arg) {
    await_t *a = arg;
    a->t0 = mono_ms();
    a->res = db_ingest_xfr_await(a->el, "default");
    a->t1 = mono_ms();
    return NULL;
}
static uint16_t elem_flags(const char *zone) {
    dbreg_info_t inf;
    return dbreg_find_info("default", zone, &inf, 1) == 1 ? inf.flags : 0xFFFF;
}

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int main(void) {
    printf("[the Backend side of the fetch stream]\n");
    static server_config_t cfg;
    int prc = parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; }; };\n"
                               "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfg);
    CHECK(prc == 0);
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);

    int a[2], f[2], c[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0 && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, c) == 0);
    int ends[3] = { a[1], f[1], c[1] };
    for (int i = 0; i < 3; i++) fcntl(ends[i], F_SETFL, fcntl(ends[i], F_GETFL, 0) | O_NONBLOCK);
    park_register_worker(0, -1);
    CHECK(db_ingest_start(a[1], c[1], f[1]));

    static ch_t mainc, fetchc;
    ch_init(&mainc, a[0], KDB_FROM_BACKEND);
    ch_init(&fetchc, f[0], KDB_FROM_BACKEND);
    kdb_enc_t e;
    kdb_enc_init(&e);
    kdb_msg_t m;
    park_key_t k;

    /* the handshake of the first stream gives the Backend its table of views (CONFIG) */
    kdb_enc_begin(&e, KDB_T_HELLO);
    kdb_enc_u16(&e, 1, 1); kdb_enc_str(&e, 2, "test-loader"); kdb_enc_str(&e, 3, "sqlite3"); kdb_enc_u32(&e, 4, 4242);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    CHECK(ch_next(&mainc, &m, 5000) && m.type == KDB_T_CONFIG && m.u.config.n_views == 1);

    /* a zone in memory, installed from a batch of the first stream (r.test.), and a second one (s.test.) */
    kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
    kdb_enc_u64(&e, 1, 1); kdb_enc_u8(&e, 2, KDB_BATCH_STARTUP); kdb_enc_u64(&e, 3, 0);
    kdb_enc_end(&e);
    send_zone(a[0], &e, 0, "r.test.", 5, 0, 11);
    send_zone(a[0], &e, 0, "s.test.", 6, 0, 12);
    kdb_enc_begin(&e, KDB_T_BATCH_END);
    kdb_enc_u64(&e, 1, 1); kdb_enc_u32(&e, 2, 2); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
    kdb_enc_end(&e);
    ch_send(a[0], &e);
    int results = 0;
    while (ch_next(&mainc, &m, 5000) && m.type != KDB_T_BATCH_RESULT) results++;
    CHECK(results == 2 && m.type == KDB_T_BATCH_RESULT);
    CHECK(dbreg_lookup_entry("default", "r.test.") != NULL && dbreg_lookup_entry("default", "s.test.") != NULL);
    for (int i = 0; i < 100 && !elem_of("default", "r.test."); i++) usleep(50000);            /* (the view delta runs within a second) */
    CHECK(elem_of("default", "r.test.") != NULL && zdir_entry(elem_of("default", "r.test.")) != NULL);

    /* -- a full rebuild of the zone directory (a zone { } block is added to the configuration) keeps a zone that is out of memory in the index: it
     *    still parks, is fetched and answers (it used to leave the index, and so was REFUSED for good) */
    {
        CHECK(dbreg_test_evict("default", "s.test."));
        static server_config_t cfgX;
        CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; }; };\n"
                               "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; zone \"added.test\" { type master; }; };\n", &cfgX) == 0);
        rebuild_zone_db_from_config(&cfgX, false);
        zdir_elem_t *se = elem_of("default", "s.test.");
        CHECK(se != NULL && zdir_entry(se) == NULL && atomic_load(&se->state) == ZDIR_ST_ABSENT);
        /* D1a step 6: the zone that left memory has the apex of its image (the SOA question that comes next is answered from it, no fetch) */
        const zdir_apex_t *eap = se ? atomic_load(&se->apex) : NULL;
        CHECK(eap && eap->serial == 6 && eap->soa_ttl == 300 && eap->ns_ttl == 300 && eap->minimum == 300 && eap->refresh == 3600 && eap->retry == 600 && eap->expire == 86400);
        CHECK(eap && eap->n_ns == 1 && eap->mname_len == 12 && eap->rname_len == 13 && eap->ns_len == 12);
        CHECK(eap && memcmp(eap->data, "\3ns1\1s\4test\0\4host\1s\4test\0\3ns1\1s\4test\0", 12 + 13 + 12) == 0);
        CHECK(elem_of("default", "r.test.") != NULL && zdir_entry(elem_of("default", "r.test.")) != NULL);
        CHECK(park_fetch_request(0, "default", "s.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "s.test.") == 0);
        send_zone(f[0], &e, 0, "s.test.", 6, m.u.fetch_req.request_id, 12);
        CHECK(wake_next(&k, 5000) && strcmp(k.zone, "s.test.") == 0 && !k.failed);
        CHECK(zdir_entry(elem_of("default", "s.test.")) != NULL);
    }

    /* -- an eviction cannot overtake an install: from dbreg_lookup_entry_busy() to dbreg_commit() the zone is not taken out (the new version would
     *    be published into an entry that goes to the garbage); an UPDATE that waited for the lock of an entry that was taken out meanwhile does not
     *    change it (SERVFAIL); a zone changed by an UPDATE is not taken out; the byte totals never went below zero */
    {
        zone_db_entry_t *be = dbreg_lookup_entry_busy("default", "r.test.");
        CHECK(be != NULL && (elem_of("default", "r.test.")->flags & ZDIR_F_BUSY));
        CHECK(!dbreg_test_evict("default", "r.test."));
        bool shd = false;
        uint8_t dgr[32], dgs[32];                           /* (a copy: the element's own digest would be copied onto itself) */
        memcpy(dgr, elem_of("default", "r.test.")->digest, 32);
        memcpy(dgs, elem_of("default", "s.test.")->digest, 32);
        CHECK(dbreg_commit("default", "r.test.", be, false, 11, atomic_load(&be->serial), dgr, &shd) == 0);
        CHECK(!(elem_of("default", "r.test.")->flags & ZDIR_F_BUSY) && zdir_entry(elem_of("default", "r.test.")) == be);
        /* an install that fails (dbreg_reject) clears the mark as well; the zone keeps serving its last good version */
        zone_db_entry_t *se = dbreg_lookup_entry_busy("default", "s.test.");
        CHECK(se != NULL && (elem_of("default", "s.test.")->flags & ZDIR_F_BUSY));
        CHECK(dbreg_reject("default", "s.test.", 12, "install failed"));
        CHECK(!(elem_of("default", "s.test.")->flags & ZDIR_F_BUSY) && dbreg_lookup_entry("default", "s.test.") == se);
        CHECK(se && dbreg_commit("default", "s.test.", se, false, 12, atomic_load(&se->serial), dgs, &shd) == 0);   /* (clears the error) */
        if (se) atomic_store(&se->updated, true);                                    /* (what an UPDATE leaves) */
        CHECK(!dbreg_test_evict("default", "s.test."));
        if (se) atomic_store(&se->updated, false);
        /* UPDATE against an entry that was taken out while it waited for the lock: the snapshot keeps the entry alive meanwhile */
        zone_db_snapshot_t *hold = acquire_retained_zone_snapshot();
        zone_db_entry_t *ue = dbreg_lookup_entry("default", "r.test.");
        CHECK(ue != NULL && dbreg_test_evict("default", "r.test."));
        uint8_t upd[12];
        memset(upd, 0, sizeof(upd));
        upd[2] = 0x28;                                                 /* opcode UPDATE */
        CHECK(ue && handle_dynamic_update(upd, sizeof(upd), ue, "127.0.0.1", "<none>") == 2);
        release_zone_snapshot(hold);
        for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(50000);
        /* the zone comes back through the fetch stream as before */
        CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "r.test.") == 0);
        send_zone(f[0], &e, 0, "r.test.", 5, m.u.fetch_req.request_id, 11);
        CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && !k.failed);
        CHECK(zone_bytes_underflows() == 0);
    }

    /* ======================================================================================================================================
     * the cache manager (D1a step 5, design 8): memory-limit, GDSF, pins, cold zones, admission.  A second batch brings many zones; the limit is
     * then set (a configuration with memory-limit, which the manager's thread reads) and the manager takes zones out of memory.
     * ====================================================================================================================================== */
    {
        enum { NZ = 2500, NY = 400 };
        char nm[40];
        zone_bytes_t zb0, zb1;
        zone_bytes_get(ZBYTES_DB, &zb0);
        dbreg_cache_stats_t cs0;
        dbreg_cache_stats(&cs0);
        uint64_t ev_base = cs0.evictions;
        kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
        kdb_enc_u64(&e, 1, 2); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        kdb_enc_begin(&e, KDB_T_PROFILE);
        kdb_enc_str(&e, 1, "pinp"); kdb_enc_str(&e, 2, "cache pin;");
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        kdb_enc_begin(&e, KDB_T_PROFILE);
        kdb_enc_str(&e, 1, "ncp"); kdb_enc_str(&e, 2, "cache no-cache;");
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        send_zone_p(a[0], &e, 0, "pin.test.", 1, 900001, "pinp");
        send_zone_p(a[0], &e, 0, "nc.test.", 1, 900002, "ncp");
        for (int i = 0; i < NZ; i++) {
            snprintf(nm, sizeof(nm), "z%04d.test.", i);
            send_zone(a[0], &e, 0, nm, 1, 0, 1000 + i);
        }
        kdb_enc_begin(&e, KDB_T_BATCH_END);
        kdb_enc_u64(&e, 1, 2); kdb_enc_u32(&e, 2, NZ + 2); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        int nres = 0;
        while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT) nres++;
        CHECK(nres == NZ + 2 && m.type == KDB_T_BATCH_RESULT);
        for (int i = 0; i < 100 && !elem_of("default", "z2499.test."); i++) usleep(50000);
        zone_bytes_get(ZBYTES_DB, &zb1);
        uint64_t added = zb1.resident - zb0.resident;
        CHECK(added > 1000000 && dbreg_lookup_entry("default", "z0000.test.") != NULL && dbreg_lookup_entry("default", "pin.test.") != NULL &&
              dbreg_lookup_entry("default", "nc.test.") != NULL);              /* (no limit: every zone is in memory) */
        printf("  (%d zones add %llu bytes: %llu per zone)\n", NZ + 2, (unsigned long long)added, (unsigned long long)(added / (NZ + 2)));
        dbreg_cache_stats_t cs;
        dbreg_cache_stats(&cs);
        CHECK(cs.limit == 0 && cs.evictions == ev_base && cs.cold == 0);       /* (the hook evictions of the earlier blocks are not counted) */

        /* some zones are asked for (the counters of the entries, as the queries make them): the first ten very often, the next hundred a little */
        for (int i = 0; i < 110; i++) {
            snprintf(nm, sizeof(nm), "z%04d.test.", i);
            zone_db_entry_t *en = dbreg_lookup_entry("default", nm);
            CHECK(en != NULL);
            if (en) atomic_store(&en->observatory.queries_total, i < 10 ? 100000 : 40);
        }
        /* the limit: 60% of what is in memory.  The manager takes zones out until it is at 90% of the limit */
        static server_config_t cfgL;
        CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; }; };\n"
                               "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfgL) == 0);
        uint64_t limit = (zb1.resident + zb1.retired) / 10 * 6;
        cfgL.database.memory_limit = limit;
        atomic_store_explicit(&g_config_db.active, &cfgL, memory_order_release);
        bool settled = false;
        for (int i = 0; i < 400 && !settled; i++) {
            usleep(50000);
            dbreg_cache_stats(&cs);
            settled = cs.limit == limit && cs.evictions > 0 && cs.inflight == 0 && cs.resident + cs.retired <= limit;
        }
        CHECK(settled);
        dbreg_cache_stats(&cs);
        printf("  (limit %llu: resident %llu + retired %llu, %llu zones taken out in %llu rounds)\n", (unsigned long long)limit,
               (unsigned long long)cs.resident, (unsigned long long)cs.retired, (unsigned long long)cs.evictions, (unsigned long long)cs.rounds);
        CHECK(cs.evictions >= NZ / 4 && cs.resident + cs.retired <= limit && cs.resident + cs.retired >= limit / 10 * 8);   /* (not much more than needed) */
        int hot_in = 0, mid_in = 0, cold_in = 0;
        for (int i = 0; i < 10; i++) { snprintf(nm, sizeof(nm), "z%04d.test.", i); hot_in += dbreg_lookup_entry("default", nm) != NULL; }
        for (int i = 10; i < 110; i++) { snprintf(nm, sizeof(nm), "z%04d.test.", i); mid_in += dbreg_lookup_entry("default", nm) != NULL; }
        for (int i = 110; i < NZ; i++) { snprintf(nm, sizeof(nm), "z%04d.test.", i); cold_in += dbreg_lookup_entry("default", nm) != NULL; }
        printf("  (still in memory: %d of 10 hot, %d of 100 mid, %d of %d others)\n", hot_in, mid_in, cold_in, NZ - 110);
        CHECK(hot_in == 10 && mid_in == 100 && cold_in < NZ - 110);            /* the zones that are asked for stay; the others go first */
        CHECK(dbreg_lookup_entry("default", "pin.test.") != NULL);              /* pinned: never taken out */
        CHECK(dbreg_lookup_entry("default", "nc.test.") == NULL);               /* no-cache: out as soon as it is old enough */
        zdir_elem_t *ne = elem_of("default", "nc.test.");
        CHECK(ne != NULL && atomic_load(&ne->state) == ZDIR_ST_ABSENT && ne->serial == 1 && ne->digest != NULL);
        if (dbreg_lookup_entry("default", "r.test.")) CHECK(dbreg_test_evict("default", "r.test."));       /* (the test hook goes through the same eviction) */

        /* zones of a batch while the database zones are above the high mark are not built: cold (the directory has the serial and the digest) */
        dbreg_cache_test_pause(true);                                           /* (the manager does not run while the zones come) */
        kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
        kdb_enc_u64(&e, 1, 3); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        for (int i = 0; i < NY; i++) {
            snprintf(nm, sizeof(nm), "y%04d.test.", i);
            send_zone(a[0], &e, 0, nm, 1, 0, 50000 + i);
        }
        kdb_enc_begin(&e, KDB_T_BATCH_END);
        kdb_enc_u64(&e, 1, 3); kdb_enc_u32(&e, 2, NY); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        nres = 0;
        int n_notres = 0, n_applied = 0;
        while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT) {
            nres++;
            if (m.type == KDB_T_ZONE_RESULT) {
                n_notres += m.u.zone_result.status == KDB_ST_NOT_RESIDENT;
                n_applied += m.u.zone_result.status == KDB_ST_APPLIED;
            }
        }
        CHECK(nres == NY && m.type == KDB_T_BATCH_RESULT);
        for (int i = 0; i < 100 && !elem_of("default", "y0399.test."); i++) usleep(50000);
        dbreg_cache_stats(&cs);
        /* a body that was left out of memory is answered NOT_RESIDENT (the loader then knows the Backend has no data of the zone), the others APPLIED */
        CHECK(n_notres == (int)cs.cold && n_applied == NY - n_notres);
        CHECK(cs.cold > 0 && cs.cold < NY);                                      /* the first ones fitted under the high mark, the rest came cold */
        int ncold = 0, nin = 0;
        char coldzone[40] = "", firstcold[40] = "", coldz[8][40];
        for (int i = 0; i < NY; i++) {
            snprintf(nm, sizeof(nm), "y%04d.test.", i);
            zdir_elem_t *ye = elem_of("default", nm);
            if (!ye) continue;
            nin++;
            if (!zdir_entry(ye)) {
                if (ncold < 8) snprintf(coldz[ncold], sizeof(coldz[0]), "%s", nm);
                ncold++;
                CHECK(atomic_load(&ye->state) == ZDIR_ST_ABSENT && ye->serial == 1 && ye->digest != NULL);
                snprintf(coldzone, sizeof(coldzone), "%s", nm);
                if (!firstcold[0]) snprintf(firstcold, sizeof(firstcold), "%s", nm);
            }
        }
        CHECK(nin == NY && ncold == (int)cs.cold && coldzone[0]);                /* (every zone is in the index, the cold ones without data) */

        /* D1a review 6C: a zone out of memory whose fetch is on its way (LOADING) while the database changes.  The body is left out (NOT_RESIDENT); the summary of the
         * version the directory has now is applied, with its apex (APPLIED), and no SEND_BODY follows, which sent the body again, left out again, and so on until the
         * fetch ended (a full zone read and a diff for every turn).  The summary of another version is told to come whole, once. */
        CHECK(ncold >= 2 && strcmp(firstcold, coldzone) != 0);
        {
            /* (the zones the test took out meanwhile are freed by now: the limit is set to what is used, so that a body is left out again) */
            dbreg_cache_stats(&cs);
            static server_config_t cfgL;
            CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; }; };\n"
                                   "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfgL) == 0);
            cfgL.database.memory_limit = cs.resident + cs.retired + 1;
            atomic_store_explicit(&g_config_db.active, &cfgL, memory_order_release);
            usleep(1500000);
            int yi0 = 0;
            CHECK(sscanf(firstcold, "y%d", &yi0) == 1);
            CHECK(park_fetch_request(0, "default", firstcold, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, firstcold) == 0);
            const uint64_t ldreq = m.u.fetch_req.request_id;
            zdir_elem_t *le = elem_of("default", firstcold);
            CHECK(le && atomic_load(&le->state) == ZDIR_ST_LOADING && zdir_entry(le) == NULL);
            kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
            kdb_enc_u64(&e, 1, 9); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            send_zone(a[0], &e, 0, firstcold, 2, 0, 50000 + yi0);                  /* the body of the version 2 (the loader thought the zone was in memory) */
            send_dir_zone(a[0], &e, 0, firstcold, 2, 50000 + yi0, NULL);           /* ... its summary, the version the directory has now */
            send_dir_zone(a[0], &e, 0, firstcold, 3, 50000 + yi0, NULL);           /* ... and the summary of a version the directory does not have */
            kdb_enc_begin(&e, KDB_T_BATCH_END);
            kdb_enc_u64(&e, 1, 9); kdb_enc_u32(&e, 2, 3); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            int ldst[4] = { -1, -1, -1, -1 }, ldn = 0;
            while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT)
                if (m.type == KDB_T_ZONE_RESULT && ldn < 4) ldst[ldn++] = m.u.zone_result.status;
            printf("  (results: %d: %d %d %d; state %d)\n", ldn, ldst[0], ldst[1], ldst[2], (int)atomic_load(&le->state));
            CHECK(ldn == 3 && ldst[0] == KDB_ST_NOT_RESIDENT && ldst[1] == KDB_ST_APPLIED && ldst[2] == KDB_ST_SEND_BODY);
            CHECK(atomic_load(&le->state) == ZDIR_ST_LOADING && le->serial == 2);   /* (the fetch is still on its way; the directory has the version 2) */
            const zdir_apex_t *lap = atomic_load(&le->apex);
            CHECK(lap && lap->serial == 2 && lap->n_ns == 2);                       /* (the apex of the summary that was applied) */
            send_failed(f[0], &e, 0, firstcold, ldreq);                            /* the fetch ends */
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, firstcold) == 0 && k.failed);
            CHECK(atomic_load(&le->state) == ZDIR_ST_ABSENT);
        }

        /* D1a review 6C: a request for the zone and a request for its summary do not stand in for each other.  A summary in flight, then a query for the zone: the
         * zone is asked for as well; the zone in flight, then a summary for it: no second request (the apex of a zone that leaves memory is made from its image) */
        CHECK(ncold >= 4);
        {
            const char *zs = coldz[1], *zf = coldz[2];
            int ys = 0, yf = 0;
            CHECK(sscanf(zs, "y%d", &ys) == 1 && sscanf(zf, "y%d", &yf) == 1);
            CHECK(park_fetch_request(0, "default", zs, KDB_FETCH_PRIO_QUERY, KDB_FETCH_SUMMARY));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, zs) == 0 && m.u.fetch_req.mode == KDB_FETCH_SUMMARY);
            const uint64_t rs = m.u.fetch_req.request_id;
            CHECK(park_fetch_request(0, "default", zs, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, zs) == 0 && m.u.fetch_req.mode == KDB_FETCH_FULL);
            const uint64_t rf = m.u.fetch_req.request_id;
            CHECK(rf != rs);
            send_summary(f[0], &e, 0, zs, 1, rs, 50000 + ys);
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zs) == 0 && !k.failed);   /* (the query that asked for the summary) */
            send_zone(f[0], &e, 0, zs, 1, rf, 50000 + ys);
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zs) == 0 && !k.failed);
            CHECK(park_fetch_request(0, "default", zf, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, zf) == 0 && m.u.fetch_req.mode == KDB_FETCH_FULL);
            const uint64_t rf2 = m.u.fetch_req.request_id;
            CHECK(park_fetch_request(0, "default", zf, KDB_FETCH_PRIO_QUERY, KDB_FETCH_SUMMARY));
            CHECK(!ch_next(&fetchc, &m, 500));                                     /* (no second request) */
            send_zone(f[0], &e, 0, zf, 1, rf2, 50000 + yf);
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zf) == 0 && !k.failed);
        }

        /* D1a review 6C: a loader that sends nothing but summaries with a new serial (each replaces the apex block of the zone, and the old one is garbage) makes the
         * ingest thread publish when the bound is passed, not only when some other change comes: the pending count is back to 0 and no garbage is due */
        {
            const char *zg = coldz[3];
            const uint64_t gf0 = dbreg_garbage_forced();
            int yg = 0;
            CHECK(sscanf(zg, "y%d", &yg) == 1);
            kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
            kdb_enc_u64(&e, 1, 10); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            for (int i = 0; i < 1300; i++) send_dir_zone(a[0], &e, 0, zg, 100 + (uint32_t)i, 50000 + yg, NULL);
            kdb_enc_begin(&e, KDB_T_BATCH_END);
            kdb_enc_u64(&e, 1, 10); kdb_enc_u32(&e, 2, 1300); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            int ngr = 0;
            while (ch_next(&mainc, &m, 20000) && m.type != KDB_T_BATCH_RESULT) ngr++;
            CHECK(ngr == 1300 && m.type == KDB_T_BATCH_RESULT);
            CHECK(dbreg_garbage_forced() > gf0);                                   /* (the bound was passed: a publication was due) */
            for (int i = 0; i < 60 && (dbreg_pending_count() != 0 || dbreg_garbage_due()); i++) usleep(50000);
            CHECK(dbreg_pending_count() == 0 && !dbreg_garbage_due());
            CHECK(elem_of("default", zg) != NULL && elem_of("default", zg)->serial == 100 + 1299);
        }

        /* D1a review 6D: a fetch brings the version the loader read when the request was made.  The directory learns of a newer version meanwhile (the body of it
         * is left out of memory here): what the fetch brings is the older one, and is dropped, not installed; the requests that wait for it are woken (not failed)
         * and ask again */
        CHECK(ncold >= 8);
        {
            const char *zl = coldz[4];
            int yl = 0;
            CHECK(sscanf(zl, "y%d", &yl) == 1);
            CHECK(park_fetch_request(0, "default", zl, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, zl) == 0);
            const uint64_t rl = m.u.fetch_req.request_id;
            kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
            kdb_enc_u64(&e, 1, 11); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            send_zone(a[0], &e, 0, zl, 50, 0, 50000 + yl);                         /* the newer version (the loader says: NOT_RESIDENT) */
            kdb_enc_begin(&e, KDB_T_BATCH_END);
            kdb_enc_u64(&e, 1, 11); kdb_enc_u32(&e, 2, 1); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            int stl = -1;
            while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT)
                if (m.type == KDB_T_ZONE_RESULT) stl = m.u.zone_result.status;
            CHECK(stl == KDB_ST_NOT_RESIDENT);
            zdir_elem_t *le2 = elem_of("default", zl);
            CHECK(le2 && le2->serial == 50 && atomic_load(&le2->state) == ZDIR_ST_LOADING);
            send_zone(f[0], &e, 0, zl, 1, rl, 50000 + yl);                         /* the fetch brings the version 1 */
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zl) == 0 && !k.failed);
            CHECK(zdir_entry(le2) == NULL && le2->serial == 50 && atomic_load(&le2->state) == ZDIR_ST_ABSENT);       /* (not installed: the newer version stays) */
        }

        /* D1a review 6E: the body of the version 60 came first and was left out of memory (the directory has the version 60 now); the fetch that was on its way brings
         * that version: it is installed at the first try and nothing is asked for again */
        {
            const char *zc = coldz[7];
            int yc = 0;
            CHECK(sscanf(zc, "y%d", &yc) == 1);
            CHECK(park_fetch_request(0, "default", zc, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, zc) == 0);
            const uint64_t rc7 = m.u.fetch_req.request_id;
            kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
            kdb_enc_u64(&e, 1, 12); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            send_zone(a[0], &e, 0, zc, 60, 0, 50000 + yc);
            kdb_enc_begin(&e, KDB_T_BATCH_END);
            kdb_enc_u64(&e, 1, 12); kdb_enc_u32(&e, 2, 1); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT) {}
            zdir_elem_t *le3 = elem_of("default", zc);
            CHECK(le3 && le3->serial == 60 && zdir_entry(le3) == NULL);
            send_zone(f[0], &e, 0, zc, 60, rc7, 50000 + yc);
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zc) == 0 && !k.failed);
            CHECK(zdir_entry(le3) != NULL && le3->serial == 60);
            CHECK(!ch_next(&fetchc, &m, 300));                                      /* (no second request) */
        }

        /* D1a review 6D: with the zones in memory above the hard limit a request for a zone is shed ("not ready") and a request for a summary is not (it brings no data) */
        {
            dbreg_cache_stats(&cs);
            static server_config_t cfgH;
            CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; }; };\n"
                                   "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfgH) == 0);
            cfgH.database.memory_limit = cs.resident / 4;                             /* (the zones in memory are far above 110% of it) */
            atomic_store_explicit(&g_config_db.active, &cfgH, memory_order_release);
            usleep(1500000);
            const char *zx = coldz[5], *zy = coldz[6];
            int yy = 0;
            CHECK(sscanf(zy, "y%d", &yy) == 1);
            CHECK(park_fetch_request(0, "default", zx, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zx) == 0 && k.failed);          /* shed: the query gets "not ready" now */
            CHECK(!ch_next(&fetchc, &m, 300));
            CHECK(park_fetch_request(0, "default", zy, KDB_FETCH_PRIO_QUERY, KDB_FETCH_SUMMARY));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, zy) == 0 && m.u.fetch_req.mode == KDB_FETCH_SUMMARY);
            send_summary(f[0], &e, 0, zy, 1, m.u.fetch_req.request_id, 50000 + yy);
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, zy) == 0 && !k.failed);
        }

        /* a cold zone is fetched when a query needs it; loaded while the database zones are at the limit and asked for less than what the manager
         * took out last, it answers the waiting queries and is marked to go first */
        dbreg_cache_stats(&cs);
        limit = cs.resident + cs.retired + 1;
        static server_config_t cfgM;                                              /* (a configuration of its own: the manager's thread reads the active one) */
        CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; }; };\n"
                               "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfgM) == 0);
        cfgM.database.memory_limit = limit;                                       /* (0.95 limit < used <= limit: above the high mark, not over the limit) */
        atomic_store_explicit(&g_config_db.active, &cfgM, memory_order_release);
        usleep(1500000);                                                          /* (the manager's thread takes the new limit; it is paused) */
        dbreg_cache_test_set_victim_freq(1000);
        CHECK(park_fetch_request(0, "default", coldzone, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, coldzone) == 0);
        int yi = 0;
        CHECK(sscanf(coldzone, "y%d", &yi) == 1);
        send_zone(f[0], &e, 0, coldzone, 1, m.u.fetch_req.request_id, 50000 + yi);
        CHECK(wake_next(&k, 5000) && strcmp(k.zone, coldzone) == 0 && !k.failed);
        dbreg_cache_stats_t cs2;
        dbreg_cache_stats(&cs2);
        zdir_elem_t *fe = elem_of("default", coldzone);
        CHECK(zdir_entry(fe) != NULL && (fe->flags & ZDIR_F_EVICT_NEXT) && cs2.marked == cs.marked + 1);
        dbreg_cache_test_pause(false);
        bool gone = false;
        for (int i = 0; i < 300 && !gone; i++) { usleep(50000); gone = zdir_entry(fe) == NULL; }
        CHECK(gone);                                                              /* (after CACHE_MIN_RESIDENT_MS, whatever the pressure) */

        /* D1a milestone 4 (design 3.3, 6.3): with memory-limit the loader sends the summary of a zone it does not see in memory, also in a batch: the
         * directory learns the zone (serial, SOA timers, settings), no data is built.  A summary for a zone that has its data here changes nothing
         * (UNCHANGED); a pinned zone is read right after its summary (warm-up, priority "warm"). */
        {
            kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
            kdb_enc_u64(&e, 1, 4); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            send_dir_zone(a[0], &e, 0, "dir1.test.", 7, 60001, "allow-transfer { 192.0.2.1; };");
            send_dir_zone(a[0], &e, 0, "dirp.test.", 8, 60002, "cache pin;");
            CHECK(dbreg_lookup_entry("default", "pin.test.") != NULL);
            send_dir_zone(a[0], &e, 0, "pin.test.", 9, 900001, NULL);            /* (it has its data here, in another version: the loader is asked to send it whole) */
            send_dir_zone(a[0], &e, 0, "pin.test.", 1, 900001, NULL);            /* (... and in this version: nothing to do) */
            send_glue_zone(a[0], &e, 0, "glu.test.", 5, 60003, 0);                /* (the addresses of ns1.glu.test, inside the zone) */
            send_glue_zone(a[0], &e, 0, "glubad.test.", 5, 60004, 1);             /* (addresses for ns2.hosting.example: not accepted, no apex) */
            kdb_enc_begin(&e, KDB_T_BATCH_END);
            kdb_enc_u64(&e, 1, 4); kdb_enc_u32(&e, 2, 6); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
            kdb_enc_end(&e);
            ch_send(a[0], &e);
            int st_dir1 = -1, st_dirp = -1, st_pin = -1, st_pin2 = -1;
            while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT) {
                if (m.type != KDB_T_ZONE_RESULT) continue;
                if (strcmp(m.u.zone_result.name, "dir1.test.") == 0) st_dir1 = m.u.zone_result.status;
                else if (strcmp(m.u.zone_result.name, "dirp.test.") == 0) st_dirp = m.u.zone_result.status;
                else if (strcmp(m.u.zone_result.name, "pin.test.") == 0) { if (st_pin < 0) st_pin = m.u.zone_result.status; else st_pin2 = m.u.zone_result.status; }
            }
            CHECK(st_dir1 == KDB_ST_APPLIED && st_dirp == KDB_ST_APPLIED && st_pin == KDB_ST_SEND_BODY && st_pin2 == KDB_ST_UNCHANGED);
            for (int i = 0; i < 100 && !elem_of("default", "dirp.test."); i++) usleep(50000);
            zdir_elem_t *d1 = elem_of("default", "dir1.test.");
            CHECK(d1 != NULL && zdir_entry(d1) == NULL && atomic_load(&d1->state) == ZDIR_ST_ABSENT && d1->serial == 7);
            CHECK(d1 && d1->refresh == 4444 && d1->retry == 555 && d1->expire == 66666);
            /* D1a step 6: the apex of the summary is kept with the element (wire names, the TTLs, the serial it describes); the zone that has its data keeps none */
            const zdir_apex_t *dap = d1 ? atomic_load(&d1->apex) : NULL;
            CHECK(dap && dap->serial == 7 && dap->soa_ttl == 900 && dap->minimum == 300 && dap->ns_ttl == 3600 && dap->refresh == 4444 && dap->retry == 555 && dap->expire == 66666);
            CHECK(dap && dap->n_ns == 2 && dap->mname_len == 21 && dap->rname_len == 22 && dap->ns_len == 42);
            CHECK(dap && memcmp(dap->data, "\3ns1\7hosting\7example\0\4host\7hosting\7example\0\3ns1\7hosting\7example\0\3ns2\7hosting\7example\0", 21 + 22 + 42) == 0);
            CHECK(d1 && atomic_load(&d1->sh) != NULL && atomic_load(&d1->sh)->ext.allow_transfer_count == 1);
            CHECK(dap && dap->glue_len == 0);                                      /* (no glue was sent for dir1) */
            /* in-zone glue (tag 21): kept after the NS names, as sent (index, type, TTL, address); glue for a name outside the zone is no apex at all */
            for (int i = 0; i < 100 && !elem_of("default", "glubad.test."); i++) usleep(50000);
            const zdir_apex_t *gap = elem_of("default", "glu.test.") ? atomic_load(&elem_of("default", "glu.test.")->apex) : NULL;
            CHECK(gap && gap->n_ns == 2 && gap->glue_len == 10 + 22);
            CHECK(gap && memcmp(gap->data + gap->mname_len + gap->rname_len + gap->ns_len, (const uint8_t[]){ 0, 1, 0, 0, 0x0e, 0x10, 192, 0, 2, 53, 0, 28, 0, 0, 0x02, 0x58 }, 16) == 0);
            CHECK(elem_of("default", "glubad.test.") != NULL && atomic_load(&elem_of("default", "glubad.test.")->apex) == NULL);
            zdir_elem_t *pe2 = elem_of("default", "pin.test.");
            CHECK(pe2 != NULL && zdir_entry(pe2) != NULL && pe2->serial != 9);   /* (still the zone with its data) */
            CHECK(pe2 && atomic_load(&pe2->apex) == NULL);                        /* (the summary of a zone that has its data brought none to keep) */
            /* the pinned one: a warm-up request follows by itself */
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "dirp.test.") == 0 &&
                  m.u.fetch_req.priority == KDB_FETCH_PRIO_WARM && m.u.fetch_req.mode == KDB_FETCH_FULL);
            send_zone(f[0], &e, 0, "dirp.test.", 8, m.u.fetch_req.request_id, 60002);
            bool got = false;
            for (int i = 0; i < 100 && !got; i++) { usleep(50000); got = dbreg_lookup_entry("default", "dirp.test.") != NULL; }
            CHECK(got);
        }

        /* the limit is taken away: everything is as before (nothing is taken out, nothing comes cold) */
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        for (int i = 0; i < 60 && dbreg_cache_limit() != 0; i++) usleep(50000);
        for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(50000);
        CHECK(dbreg_cache_limit() == 0 && dbreg_evict_inflight() == 0);
        usleep(300000);
        dbreg_cache_stats(&cs);
        uint64_t ev_before = cs.evictions;
        usleep(500000);
        dbreg_cache_stats(&cs);
        CHECK(cs.evictions == ev_before);

        /* without memory-limit the Backend does not take a summary in a batch (the loader sends one only after CONFIG dir_only; a loader that does it
         * anyway is told the zone was rejected, and nothing is installed) */
        kdb_enc_begin(&e, KDB_T_BATCH_BEGIN);
        kdb_enc_u64(&e, 1, 5); kdb_enc_u8(&e, 2, KDB_BATCH_DIFF); kdb_enc_u64(&e, 3, 0);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        send_dir_zone(a[0], &e, 0, "dir2.test.", 3, 60003, NULL);
        kdb_enc_begin(&e, KDB_T_BATCH_END);
        kdb_enc_u64(&e, 1, 5); kdb_enc_u32(&e, 2, 1); kdb_enc_u32(&e, 3, 0); kdb_enc_u32(&e, 4, 0);
        kdb_enc_end(&e);
        ch_send(a[0], &e);
        int st_dir2 = -1;
        while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT)
            if (m.type == KDB_T_ZONE_RESULT && strcmp(m.u.zone_result.name, "dir2.test.") == 0) st_dir2 = m.u.zone_result.status;
        CHECK(st_dir2 == KDB_ST_REJECTED && elem_of("default", "dir2.test.") == NULL);

        /* fetch-rate: queries scattered over many zones that are out of memory make the loader read zones at most as fast as the bucket fills
         * (burst = one second of the rate); the others are told "not ready" at once, and the status says how many */
        static server_config_t cfgR;
        CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; fetch-rate 10; }; };\n"
                               "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfgR) == 0);
        CHECK(cfgR.database.fetch_rate == 10);
        atomic_store_explicit(&g_config_db.active, &cfgR, memory_order_release);
        usleep(2500000);                                                          /* (the manager's thread takes the rate; the bucket fills to its burst) */
        int asked = 0, got = 0, refused = 0;
        for (int i = 300; i < 2500 && asked < 60; i++) {
            snprintf(nm, sizeof(nm), "z%04d.test.", i);
            if (dbreg_lookup_entry("default", nm)) continue;                      /* (a zone out of memory) */
            CHECK(park_fetch_request(0, "default", nm, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            asked++;
        }
        CHECK(asked == 60);
        while (ch_next(&fetchc, &m, 700) && m.type == KDB_T_FETCH_REQ) {
            got++;
            send_failed(f[0], &e, 0, m.u.fetch_req.name, m.u.fetch_req.request_id);       /* (the loader cannot read it: nothing stays in flight) */
        }
        while (wake_next(&k, 300)) refused += k.failed ? 1 : 0;
        printf("  (fetch-rate 10: %d of %d requests reached the loader, %d queries woken with a failure)\n", got, asked, refused);
        CHECK(got >= 8 && got <= 16);                                             /* (10 in the bucket, and what fills it meanwhile) */
        CHECK(refused >= asked - 16);
        {
            char st[4096];
            size_t sl = db_ingest_status(NULL, NULL, st, sizeof(st));
            const char *p = sl ? strstr(st, "refused_by_rate=") : NULL;
            CHECK(p != NULL && strtoull(p + 16, NULL, 10) >= (unsigned long long)(asked - 16));
            CHECK(strstr(st, "fetch: rate=10/s") != NULL);
        }
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        usleep(1300000);                                                          /* (back to the default rate before the fetches that follow) */
        /* r.test. (the hook) and s.test. (asked for least) may be out of memory: the tests that follow start from the two being in memory */
        static const struct { const char *name; uint32_t serial; int64_t sid; } back[] = { { "r.test.", 5, 11 }, { "s.test.", 6, 12 } };
        for (int b = 0; b < 2; b++) {
            if (dbreg_lookup_entry("default", back[b].name)) continue;
            CHECK(park_fetch_request(0, "default", back[b].name, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
            CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
            send_zone(f[0], &e, 0, back[b].name, back[b].serial, m.u.fetch_req.request_id, back[b].sid);
            CHECK(wake_next(&k, 5000) && strcmp(k.zone, back[b].name) == 0 && !k.failed);
        }
        CHECK(dbreg_lookup_entry("default", "r.test.") != NULL && dbreg_lookup_entry("default", "s.test.") != NULL);
    }

    /* -- answered at once: a view that takes no database zones, a zone the registry does not know, a zone that is in memory */
    CHECK(park_fetch_request(0, "nosuchview", "z.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(wake_next(&k, 5000) && strcmp(k.view, "nosuchview") == 0 && k.failed);
    CHECK(park_fetch_request(0, "default", "ghost.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "ghost.test.") == 0 && k.failed);
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && !k.failed);
    CHECK(!ch_next(&fetchc, &m, 200));                                    /* nothing was asked of the loader */

    /* -- a zone that is not in memory: one FETCH_REQ, a second request for it sends nothing, the answer installs it and wakes */
    /* (evicted as the cache manager does it: the entry goes to the garbage of the snapshot the next delta retires, and is freed when that is drained;
     * its bytes are in the retired total and in "in flight" until then) */
    uint64_t ev0 = dbreg_evictions();
    zone_bytes_t zb0;
    zone_bytes_get(ZBYTES_DB, &zb0);
    CHECK(dbreg_test_evict("default", "r.test."));
    CHECK(dbreg_evictions() == ev0 + 1 && zdir_entry(elem_of("default", "r.test.")) == NULL &&
          atomic_load(&elem_of("default", "r.test.")->state) == ZDIR_ST_ABSENT);
    CHECK(!dbreg_test_evict("default", "r.test."));                       /* (nothing in memory to take out) */
    for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(50000);
    CHECK(dbreg_evict_inflight() == 0);                                   /* the delta was published, the snapshot drained, the entry freed */
    {
        zone_bytes_t zb1;
        zone_bytes_get(ZBYTES_DB, &zb1);
        CHECK(zb1.resident + zb1.retired <= zb0.resident + zb0.retired && zb1.resident < zb0.resident);   /* its bytes are gone from both totals */
    }
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_WARM, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    uint64_t id1 = m.u.fetch_req.request_id;
    CHECK(id1 != 0 && m.u.fetch_req.view == 0 && strcmp(m.u.fetch_req.name, "r.test.") == 0 && m.u.fetch_req.priority == KDB_FETCH_PRIO_WARM &&
          m.u.fetch_req.mode == KDB_FETCH_FULL && !m.u.fetch_req.has_range);
    CHECK(atomic_load(&elem_of("default", "r.test.")->state) == ZDIR_ST_LOADING);
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(!ch_next(&fetchc, &m, 300));                                     /* (in flight: no second message) */
    for (int i = 0; i < 100 && dbreg_pending_count() != 0; i++) usleep(50000);
    zone_db_snapshot_t *snap_before = atomic_load(&g_zone_db_active);
    CHECK(dbreg_pending_count() == 0);
    send_zone(f[0], &e, 0, "r.test.", 7, id1, 11);
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && !k.failed);
    /* the element is in the index already (only its data was out of memory): the install queues nothing and publishes no snapshot */
    usleep(300000);
    CHECK(dbreg_pending_count() == 0 && atomic_load(&g_zone_db_active) == snap_before);
    zone_db_entry_t *new_r = zdir_entry(elem_of("default", "r.test."));
    CHECK(new_r != NULL && atomic_load(&new_r->serial) == 7);
    CHECK(atomic_load(&elem_of("default", "r.test.")->state) == ZDIR_ST_RESIDENT);

    /* -- the loader says it cannot read the zone: the worker is told at once, the zone stays out of memory */
    evict("r.test.");
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    send_failed(f[0], &e, 0, "r.test.", m.u.fetch_req.request_id);
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && k.failed);
    CHECK(zdir_entry(elem_of("default", "r.test.")) == NULL && atomic_load(&elem_of("default", "r.test.")->state) == ZDIR_ST_ABSENT);

    /* -- a profile (settings text) comes before the zone on the fetch stream, which has its own profile table (that of the batches is not
     *    shared): the zone is installed with those settings */
    evict("r.test.");
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    uint64_t id_prof = m.u.fetch_req.request_id;
    kdb_enc_begin(&e, KDB_T_PROFILE);
    kdb_enc_str(&e, 1, "p1"); kdb_enc_str(&e, 2, "ixfr-history 7;");
    kdb_enc_end(&e);
    ch_send(f[0], &e);
    {
        uint8_t dig[KDB_DIGEST_LEN];
        memset(dig, 9, sizeof(dig));
        kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "r.test."); kdb_enc_i64(&e, 3, 11); kdb_enc_u8(&e, 4, KDB_ZK_PRIMARY);
        kdb_enc_u32(&e, 5, 8); kdb_enc_u32(&e, 6, 0); kdb_enc_u64(&e, 7, 4); kdb_enc_bytes(&e, 8, dig, sizeof(dig));
        kdb_enc_str(&e, 10, "p1"); kdb_enc_u64(&e, 11, id_prof);
        kdb_enc_end(&e);
        uint8_t msg[2048];
        size_t n = zone_message(msg, "r.test.", 8);
        kdb_enc_raw_msg(&e, KDB_T_ZONE_DATA, msg, n);
        kdb_enc_begin(&e, KDB_T_ZONE_END);
        kdb_enc_u64(&e, 1, 4);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
    }
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && !k.failed);
    CHECK(zdir_entry(elem_of("default", "r.test.")) != NULL && atomic_load(&zdir_entry(elem_of("default", "r.test."))->serial) == 8);
    /* a profile the fetch stream never sent is refused for its zone: the zone is not installed and the worker is told */
    evict("r.test.");
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    {
        uint8_t dig[KDB_DIGEST_LEN];
        memset(dig, 9, sizeof(dig));
        kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "r.test."); kdb_enc_i64(&e, 3, 11); kdb_enc_u8(&e, 4, KDB_ZK_PRIMARY);
        kdb_enc_u32(&e, 5, 9); kdb_enc_u32(&e, 6, 0); kdb_enc_u64(&e, 7, 4); kdb_enc_bytes(&e, 8, dig, sizeof(dig));
        kdb_enc_str(&e, 10, "p2"); kdb_enc_u64(&e, 11, m.u.fetch_req.request_id);
        kdb_enc_end(&e);
        uint8_t msg[2048];
        size_t n = zone_message(msg, "r.test.", 9);
        kdb_enc_raw_msg(&e, KDB_T_ZONE_DATA, msg, n);
        kdb_enc_begin(&e, KDB_T_ZONE_END);
        kdb_enc_u64(&e, 1, 4);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
    }
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && k.failed);
    CHECK(zdir_entry(elem_of("default", "r.test.")) == NULL);

    /* -- a zone nobody asked for (a request id that is not in flight, and a request that wanted a summary) is thrown away */
    send_zone(f[0], &e, 0, "u.test.", 3, 424242, 99);
    send_zone(f[0], &e, 0, "s.test.", 66, 7777, 12);
    CHECK(!wake_next(&k, 300));
    CHECK(dbreg_lookup_entry("default", "u.test.") == NULL);
    zone_db_entry_t *s_entry = dbreg_lookup_entry("default", "s.test.");
    CHECK(s_entry != NULL && atomic_load(&s_entry->serial) == 6);

    /* -- a summary: the element that has no data takes the serial and the SOA timers */
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.mode == KDB_FETCH_SUMMARY && m.u.fetch_req.priority == KDB_FETCH_PRIO_BACKGROUND);
    send_summary(f[0], &e, 0, "r.test.", 9, m.u.fetch_req.request_id, 11);
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && !k.failed);
    dbreg_info_t inf;
    CHECK(dbreg_find_info("default", "r.test.", &inf, 1) == 1 && !inf.has_entry && inf.serial == 9 && inf.refresh == 1111);
    CHECK(zdir_entry(elem_of("default", "r.test.")) == NULL);
    /* a full answer to a summary request is not what was asked: thrown away */
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_SUMMARY));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    uint64_t id_sum = m.u.fetch_req.request_id;
    send_zone(f[0], &e, 0, "r.test.", 10, id_sum, 11);
    CHECK(zdir_entry(elem_of("default", "r.test.")) == NULL);
    send_summary(f[0], &e, 0, "r.test.", 10, id_sum, 11);
    CHECK(wake_next(&k, 5000) && !k.failed);

    /* -- a summary whose timers are above 2147483647 stores the value a zone in memory has (parse_ttl_value rounds it down, RFC 8767 4) */
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    {
        uint8_t dig0[KDB_DIGEST_LEN] = { 0 };
        kdb_enc_begin(&e, KDB_T_ZONE_BEGIN);
        kdb_enc_u16(&e, 1, 0); kdb_enc_name(&e, 2, "r.test."); kdb_enc_i64(&e, 3, 11); kdb_enc_u8(&e, 4, KDB_ZK_PRIMARY);
        kdb_enc_u32(&e, 5, 12); kdb_enc_u32(&e, 6, KDB_ZF_SUMMARY); kdb_enc_u64(&e, 7, 0); kdb_enc_bytes(&e, 8, dig0, sizeof(dig0));
        kdb_enc_u64(&e, 11, m.u.fetch_req.request_id); kdb_enc_u32(&e, 12, 4000000000u); kdb_enc_u32(&e, 13, 3000000000u); kdb_enc_u32(&e, 14, 7);
        kdb_enc_end(&e);
        kdb_enc_begin(&e, KDB_T_ZONE_END);
        kdb_enc_u64(&e, 1, 0);
        kdb_enc_end(&e);
        ch_send(f[0], &e);
    }
    CHECK(wake_next(&k, 5000) && !k.failed);
    CHECK(dbreg_find_info("default", "r.test.", &inf, 1) == 1 && !inf.has_entry && inf.serial == 12 && inf.refresh == 2147483647u);
    CHECK(elem_of("default", "r.test.")->retry == 2147483647u && elem_of("default", "r.test.")->expire == 7);

    /* -- zone transfers of zones that are out of memory (D1a step 7, design 7, 12-6): db_ingest_xfr_await() asks for the zone through the slots of
     *    park_fetch_request_any() and returns the entry with the transfer counted in active_axfr.  A zone it brought is marked evict-next (and XFRLOAD)
     *    unless it is pinned, was changed by an UPDATE or is asked for more often than the zones the manager took out; queries drop the mark.  The
     *    manager (a limit far above the zones in memory: no pressure) takes a marked zone out as soon as the transfer has ended. */
    {
        static server_config_t cfgX;
        CHECK(parse_named_conf("options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; "
                               "transfer-fetch-timeout 1500; }; };\n"
                               "view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", &cfgX) == 0);
        CHECK(cfgX.database.transfer_fetch_timeout_ms == 1500);
        cfgX.database.memory_limit = 1ull << 40;
        atomic_store_explicit(&g_config_db.active, &cfgX, memory_order_release);
        usleep(1400000);                                                       /* (the manager's thread takes the limit and the timeout) */
        zdir_elem_t *xe = elem_of("default", "r.test.");
        CHECK(xe != NULL && zdir_entry(xe) == NULL);
        dbreg_cache_stats_t cs0, cs1;
        dbreg_cache_stats(&cs0);
        char st[4096];
        size_t sl = db_ingest_status(NULL, NULL, st, sizeof(st));
        CHECK(sl > 0 && strstr(st, "issued=") != NULL && strstr(st, "transfers of zones out of memory: waited=") != NULL && strstr(st, "timeout=1500ms") != NULL);

        /* a zone that is in memory: the transfer is counted at once and nothing is asked for */
        {
            zone_db_entry_t *sen = dbreg_lookup_entry("default", "s.test.");
            await_t A = { elem_of("default", "s.test."), NULL, 0, 0 };
            CHECK(sen != NULL && A.el != NULL);
            await_thread(&A);
            CHECK(A.res == sen && atomic_load(&sen->active_axfr) == 1 && A.t1 - A.t0 < 100);
            atomic_fetch_sub(&sen->active_axfr, 1);
            CHECK(!ch_next(&fetchc, &m, 100));
        }

        /* the zone is read, marked, held by the transfer, and taken out when the transfer ends */
        await_t A = { xe, NULL, 0, 0 };
        pthread_t th;
        CHECK(pthread_create(&th, NULL, await_thread, &A) == 0);
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && strcmp(m.u.fetch_req.name, "r.test.") == 0 && m.u.fetch_req.mode == KDB_FETCH_FULL &&
              m.u.fetch_req.priority == KDB_FETCH_PRIO_QUERY);
        send_zone(f[0], &e, 0, "r.test.", 12, m.u.fetch_req.request_id, 11);
        pthread_join(th, NULL);
        CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && !k.failed);
        CHECK(A.res != NULL && A.res == zdir_entry(xe) && atomic_load(&A.res->active_axfr) == 1 && atomic_load(&A.res->serial) == 12);
        CHECK((elem_flags("r.test.") & (ZDIR_F_EVICT_NEXT | ZDIR_F_XFRLOAD)) == (ZDIR_F_EVICT_NEXT | ZDIR_F_XFRLOAD));
        dbreg_cache_stats(&cs1);
        CHECK(cs1.xfr[DBREG_XFR_WAITED] == cs0.xfr[DBREG_XFR_WAITED] + 1 && cs1.xfr[DBREG_XFR_LOADED] == cs0.xfr[DBREG_XFR_LOADED] + 1 &&
              cs1.xfr_marked == cs0.xfr_marked + 1 && cs1.xfr[DBREG_XFR_FAILED] == cs0.xfr[DBREG_XFR_FAILED]);
        usleep(600000);                                                        /* (the manager sees the mark and a transfer that holds the zone) */
        CHECK(zdir_entry(xe) == A.res && !dbreg_test_evict("default", "r.test."));
        uint64_t ev0 = dbreg_evictions();
        atomic_fetch_sub(&A.res->active_axfr, 1);
        for (int i = 0; i < 100 && zdir_entry(xe) != NULL; i++) usleep(30000);
        CHECK(zdir_entry(xe) == NULL && dbreg_evictions() == ev0 + 1);         /* (taken out first: no pressure, nothing else to compare with) */
        CHECK(atomic_load(&xe->state) == ZDIR_ST_ABSENT);
        for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(50000);

        /* a zone that queries ask for more often than the zones taken out last is not marked */
        atomic_store(&xe->freq, 50);
        A.res = NULL;
        CHECK(pthread_create(&th, NULL, await_thread, &A) == 0);
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
        send_zone(f[0], &e, 0, "r.test.", 12, m.u.fetch_req.request_id, 11);
        pthread_join(th, NULL);
        CHECK(wake_next(&k, 5000) && !k.failed);
        CHECK(A.res != NULL && (elem_flags("r.test.") & (ZDIR_F_EVICT_NEXT | ZDIR_F_XFRLOAD)) == 0);
        dbreg_cache_stats(&cs1);
        CHECK(cs1.xfr_marked == cs0.xfr_marked + 1 && cs1.xfr[DBREG_XFR_LOADED] == cs0.xfr[DBREG_XFR_LOADED] + 2);
        atomic_fetch_sub(&A.res->active_axfr, 1);
        usleep(600000);
        CHECK(zdir_entry(xe) == A.res);                                         /* (it stays: GDSF only) */
        CHECK(dbreg_test_evict("default", "r.test."));
        atomic_store(&xe->freq, 0);
        for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(50000);

        /* queries that ask for the zone while the transfer runs drop the mark (the entry's query counter, as the cache manager sees it) */
        A.res = NULL;
        CHECK(pthread_create(&th, NULL, await_thread, &A) == 0);
        CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
        send_zone(f[0], &e, 0, "r.test.", 12, m.u.fetch_req.request_id, 11);
        pthread_join(th, NULL);
        CHECK(wake_next(&k, 5000) && !k.failed);
        CHECK(A.res != NULL && (elem_flags("r.test.") & ZDIR_F_XFRLOAD));
        atomic_store(&A.res->observatory.queries_total, 7);
        for (int i = 0; i < 100 && (elem_flags("r.test.") & (ZDIR_F_XFRLOAD | ZDIR_F_EVICT_NEXT)); i++) usleep(30000);
        CHECK((elem_flags("r.test.") & (ZDIR_F_XFRLOAD | ZDIR_F_EVICT_NEXT)) == 0);
        atomic_fetch_sub(&A.res->active_axfr, 1);
        usleep(700000);
        CHECK(zdir_entry(xe) == A.res);                                         /* (a zone the queries use is not taken out because a transfer read it) */
        CHECK(dbreg_test_evict("default", "r.test."));
        for (int i = 0; i < 200 && dbreg_evict_inflight() != 0; i++) usleep(50000);

        /* pinned, changed by an UPDATE: never marked */
        {
            zone_db_entry_t *pe = dbreg_lookup_entry("default", "pin.test.");
            CHECK(pe != NULL && (elem_flags("pin.test.") & ZDIR_F_PIN));
            dbreg_cache_stats(&cs1);
            uint64_t m0 = cs1.xfr_marked;
            dbreg_xfr_loaded("default", "pin.test.");
            zone_db_entry_t *se = dbreg_lookup_entry("default", "s.test.");
            CHECK(se != NULL);
            atomic_store(&se->updated, true);
            dbreg_xfr_loaded("default", "s.test.");
            atomic_store(&se->updated, false);
            dbreg_xfr_loaded("default", "ghost.test.");                         /* (no such zone) */
            dbreg_xfr_loaded("nosuchview", "s.test.");
            dbreg_cache_stats(&cs1);
            CHECK(cs1.xfr_marked == m0 && (elem_flags("pin.test.") & (ZDIR_F_EVICT_NEXT | ZDIR_F_XFRLOAD)) == 0 &&
                  (elem_flags("s.test.") & (ZDIR_F_EVICT_NEXT | ZDIR_F_XFRLOAD)) == 0);
        }

        /* the fetch fails (the loader cannot read the zone) and is asked for again until the time is up: nothing is left counted in active_axfr */
        {
            dbreg_cache_stats(&cs0);
            A.res = (zone_db_entry_t *)1;
            CHECK(pthread_create(&th, NULL, await_thread, &A) == 0);
            int asked = 0;
            while (ch_next(&fetchc, &m, 400) && m.type == KDB_T_FETCH_REQ) {
                asked++;
                send_failed(f[0], &e, 0, "r.test.", m.u.fetch_req.request_id);
            }
            pthread_join(th, NULL);
            while (wake_next(&k, 100)) CHECK(k.failed);
            printf("  (a transfer whose fetch fails: %d requests in %lld ms)\n", asked, (long long)(A.t1 - A.t0));
            CHECK(A.res == NULL && A.t1 - A.t0 >= 1400 && A.t1 - A.t0 < 3500 && asked >= 3);   /* (it asks again every 100 ms while nothing is on its way) */
            dbreg_cache_stats(&cs1);
            CHECK(cs1.xfr[DBREG_XFR_FAILED] == cs0.xfr[DBREG_XFR_FAILED] + 1 && cs1.xfr[DBREG_XFR_LOADED] == cs0.xfr[DBREG_XFR_LOADED]);
            CHECK(zdir_entry(xe) == NULL && atomic_load(&xe->state) == ZDIR_ST_ABSENT);
            /* a zone with no usable version (state ERROR): no time spent and no request */
            atomic_store(&xe->state, ZDIR_ST_ERROR);
            await_thread(&A);
            CHECK(A.res == NULL && A.t1 - A.t0 < 300 && !ch_next(&fetchc, &m, 200));
            atomic_store(&xe->state, ZDIR_ST_ABSENT);
        }
        {
            sl = db_ingest_status(NULL, NULL, st, sizeof(st));
            const char *p = sl ? strstr(st, "issued=") : NULL;
            CHECK(p != NULL && strtoull(p + 7, NULL, 10) > 0);
        }
        /* back to the configuration the tests that follow expect */
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        usleep(1300000);
    }

    /* -- a fetch the loader never answers is given up (the test shortens the 30 s): the workers are told it failed, the zone can be asked for
     *    again, and the answer that comes too late is thrown away */
    g_ing_fetch_timeout_ms = 150;
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    uint64_t id_late = m.u.fetch_req.request_id;
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && k.failed);
    g_ing_fetch_timeout_ms = 30000;
    CHECK(atomic_load(&elem_of("default", "r.test.")->state) == ZDIR_ST_ABSENT);
    send_zone(f[0], &e, 0, "r.test.", 13, id_late, 11);
    CHECK(!wake_next(&k, 300));
    CHECK(zdir_entry(elem_of("default", "r.test.")) == NULL);
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.request_id != id_late);
    send_failed(f[0], &e, 0, "r.test.", m.u.fetch_req.request_id);
    CHECK(wake_next(&k, 5000) && k.failed);

    /* -- a restarted loader: the supervisor hands over a new pair of streams; what was not answered is asked again */
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetchc, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    uint64_t id_open = m.u.fetch_req.request_id;
    int a2[2], f2[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a2) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f2) == 0);
    hand_over(c[0], a2[1], f2[1]);
    static ch_t fetch2;
    ch_init(&fetch2, f2[0], KDB_FROM_BACKEND);
    CHECK(ch_next(&fetch2, &m, 5000) && m.type == KDB_T_FETCH_REQ && m.u.fetch_req.request_id == id_open && strcmp(m.u.fetch_req.name, "r.test.") == 0);
    CHECK(ch_next(&fetchc, &m, 1000) == false && fetchc.eof);                 /* the old fetch stream was closed */
    send_failed(f2[0], &e, 0, "r.test.", id_open);
    CHECK(wake_next(&k, 5000) && k.failed);

    /* -- bytes that are not KDB1: the fetch stream is closed, a request after that is answered at once */
    static const uint8_t junk[] = "NOT KDB1, JUST BYTES.";
    CHECK(write(f2[0], junk, sizeof(junk)) == (ssize_t)sizeof(junk));
    CHECK(!ch_next(&fetch2, &m, 5000) && fetch2.eof);
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(wake_next(&k, 5000) && k.failed);
    CHECK(atomic_load(&elem_of("default", "r.test.")->state) == ZDIR_ST_ABSENT);        /* (a failed request leaves the zone to be asked again) */

    /* -- a loader that has no fetch stream (an older one): the requests in flight are failed at once, the old fetch stream is gone */
    int a3[2], f3[2], a4[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, a3) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, f3) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, a4) == 0);
    hand_over(c[0], a3[1], f3[1]);
    static ch_t fetch3;
    ch_init(&fetch3, f3[0], KDB_FROM_BACKEND);
    usleep(100000);
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(ch_next(&fetch3, &m, 5000) && m.type == KDB_T_FETCH_REQ);
    hand_over(c[0], a4[1], -1);
    CHECK(wake_next(&k, 5000) && strcmp(k.zone, "r.test.") == 0 && k.failed);
    CHECK(!ch_next(&fetch3, &m, 5000) && fetch3.eof);
    CHECK(park_fetch_request(0, "default", "r.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    CHECK(wake_next(&k, 5000) && k.failed);

    usleep(300000);
    gc_snapshot_wait_idle();                          /* (the cleanup threads of the retired snapshots are joined, as the manager does before it forks) */
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) return 1;
    printf("=== test_db_fetch: all checks passed ===\n");
    return 0;
}

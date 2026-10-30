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

    /* ======================================================================================================================================
     * the cache manager (D1a step 5, design 8): memory-limit, GDSF, pins, cold zones, admission.  A second batch brings many zones; the limit is
     * then set (a configuration with memory-limit, which the manager's thread reads) and the manager takes zones out of memory.
     * ====================================================================================================================================== */
    {
        enum { NZ = 2500, NY = 400 };
        char nm[40];
        zone_bytes_t zb0, zb1;
        zone_bytes_get(ZBYTES_DB, &zb0);
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
        CHECK(cs.limit == 0 && cs.evictions == 0 && cs.cold == 0);

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
        while (ch_next(&mainc, &m, 10000) && m.type != KDB_T_BATCH_RESULT) nres++;
        CHECK(nres == NY && m.type == KDB_T_BATCH_RESULT);
        for (int i = 0; i < 100 && !elem_of("default", "y0399.test."); i++) usleep(50000);
        dbreg_cache_stats(&cs);
        CHECK(cs.cold > 0 && cs.cold < NY);                                      /* the first ones fitted under the high mark, the rest came cold */
        int ncold = 0, nin = 0;
        char coldzone[40] = "";
        for (int i = 0; i < NY; i++) {
            snprintf(nm, sizeof(nm), "y%04d.test.", i);
            zdir_elem_t *ye = elem_of("default", nm);
            if (!ye) continue;
            nin++;
            if (!zdir_entry(ye)) {
                ncold++;
                CHECK(atomic_load(&ye->state) == ZDIR_ST_ABSENT && ye->serial == 1 && ye->digest != NULL);
                snprintf(coldzone, sizeof(coldzone), "%s", nm);
            }
        }
        CHECK(nin == NY && ncold == (int)cs.cold && coldzone[0]);                /* (every zone is in the index, the cold ones without data) */

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

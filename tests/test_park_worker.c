/*
 * test_park_worker.c - a worker parks a UDP query for a zone that is not in memory, and answers it later (dns_server_core.c: udp_one(),
 * park_service(); dns_park.c; D1a milestone 2, design 4.1 - 4.4).
 *
 * The directory of the view lists the zone park.test. but the test has taken its data out of memory (the entry of the element is NULL: the
 * state of an evicted zone; nothing in the server does that yet).  udp_one() is the code every UDP request runs through, park_service() the
 * code that starts a parked request again.  Checked:
 *   - a zone in memory is answered at once, as before (the first pass and the second one are the same function)
 *   - a query for the zone that is not in memory is parked, not answered; the first one asks for the zone (one request on the worker's fetch
 *     ring), a second one for the same zone asks for nothing
 *   - the zone is back and the ingest thread says so (a key on the wake ring): both queries are answered from the zone, once, on the socket
 *     they came in on, with their own IDs
 *   - the zone is still not there after a wake-up: the query is parked again, with the deadline it had
 *   - the time is up: SERVFAIL with Extended DNS Error 14 (RFC 8914 4.15), the question kept; so is a failed fetch (answered at once), a full
 *     park table, a request too big to park and a worker that has no park table
 *   - the request log and the dnstap query event of a parked request are written once (not again when it comes back)
 *   - 0.7 P-B, the gate: with memory-limit a first query for a zone out of memory marks the zone as claimed before it parks and asks (the request carries
 *     PARK_PRIO_CLAIMED); it is never refused for the lack of a place, a token or room (the ingest thread keeps the request waiting); the park table or the ring being
 *     full clears the mark; a zone that is LOADING, an ERROR zone and a server without memory-limit are not claimed
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/event.h>
#include <sys/ioctl.h>

#include "../dns_config_parser.h"
#include "../dns_db_stream.h"
#include "../dns_park.h"
#include "../dns_query_engine.h"
#include "../dns_server_internal.h"
#include "../dns_snapshot_rcu.h"
#include "../dns_utils.h"

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

void udp_one(udp_pass_t *w, udp_ipc_t *ipc_msg, uint8_t *req_buf, ssize_t payload_received);
void park_service(udp_pass_t *w, int kq);
extern _Atomic bool dns_core_test_lookup_force;

/* a query for www.park.test. A, with an OPT record when edns; id as given; padding: bytes of an EDNS padding option (RFC 7830) */
static size_t build_query(uint8_t *b, uint16_t id, bool edns, size_t padding) {
    memset(b, 0, 12);
    b[0] = (uint8_t)(id >> 8); b[1] = (uint8_t)id;
    b[2] = 0x01;                                   /* RD */
    b[5] = 1;                                      /* QDCOUNT */
    b[11] = edns ? 1 : 0;                          /* ARCOUNT */
    size_t o = 12;
    static const uint8_t qn[] = { 3, 'w', 'w', 'w', 4, 'p', 'a', 'r', 'k', 4, 't', 'e', 's', 't', 0 };
    memcpy(b + o, qn, sizeof(qn));
    o += sizeof(qn);
    b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1;     /* A IN */
    if (edns) {
        b[o++] = 0;                                /* root */
        b[o++] = 0; b[o++] = 41;                   /* OPT */
        b[o++] = 0x04; b[o++] = 0xD0;              /* UDP payload size 1232 */
        b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0;
        size_t rdlen = padding ? 4 + padding : 0;
        b[o++] = (uint8_t)(rdlen >> 8); b[o++] = (uint8_t)rdlen;
        if (padding) {
            b[o++] = 0; b[o++] = 12;               /* option code 12: padding */
            b[o++] = (uint8_t)(padding >> 8); b[o++] = (uint8_t)padding;
            memset(b + o, 0, padding);
            o += padding;
        }
    }
    return o;
}

/* a query for www.late.test. A (no zone of the test has it): the lookup path */
static size_t build_lk_query(uint8_t *b, uint16_t id) {
    memset(b, 0, 12);
    b[0] = (uint8_t)(id >> 8); b[1] = (uint8_t)id;
    b[2] = 0x01;
    b[5] = 1;
    static const uint8_t qn[] = { 3, 'w', 'w', 'w', 4, 'l', 'a', 't', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1 };
    memcpy(b + 12, qn, sizeof(qn));
    return 12 + sizeof(qn);
}

/* the same with an OPT record (EDNS0, RFC 6891: UDP size 1232): an error answer then carries an Extended DNS Error (RFC 8914) */
static size_t build_lk_query_edns(uint8_t *b, uint16_t id) {
    size_t o = build_lk_query(b, id);
    b[11] = 1;
    static const uint8_t opt[] = { 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 };
    memcpy(b + o, opt, sizeof(opt));
    return o + sizeof(opt);
}

/* a NOTIFY (opcode 4) or an UPDATE (opcode 5) for `name`: the zone / question section is "name SOA IN" (RFC 1996, RFC 2136 2.3) */
static size_t build_op(uint8_t *b, uint16_t id, int opcode, const char *name) {
    memset(b, 0, 12);
    b[0] = (uint8_t)(id >> 8); b[1] = (uint8_t)id;
    b[2] = (uint8_t)(opcode << 3);
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
    b[o++] = 0; b[o++] = 6; b[o++] = 0; b[o++] = 1;                       /* SOA IN */
    return o;
}

/* an IXFR question for park.test over UDP (RFC 1995 4.2) with the client's SOA (serial `serial`) in Authority; no_soa: leave it out (RFC 1995 3: FORMERR) */
static size_t build_ixfr(uint8_t *b, uint16_t id, uint32_t serial, bool no_soa) {
    memset(b, 0, 12);
    b[0] = (uint8_t)(id >> 8); b[1] = (uint8_t)id;
    b[5] = 1;
    b[9] = no_soa ? 0 : 1;
    b[11] = 1;                                     // an OPT record, so that an error carries the EDE
    size_t o = 12;
    static const uint8_t qn[] = { 4, 'p', 'a', 'r', 'k', 4, 't', 'e', 's', 't', 0 };
    memcpy(b + o, qn, sizeof(qn));
    o += sizeof(qn);
    b[o++] = 0; b[o++] = 251; b[o++] = 0; b[o++] = 1;
    if (!no_soa) {
    b[o++] = 0xC0; b[o++] = 12;
    b[o++] = 0; b[o++] = 6; b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0;
    static const uint8_t rd[] = { 2, 'n', 's', 0xC0, 12, 1, 'h', 0xC0, 12 };
    size_t rl = sizeof(rd) + 20;
    b[o++] = (uint8_t)(rl >> 8); b[o++] = (uint8_t)rl;
    memcpy(b + o, rd, sizeof(rd));
    o += sizeof(rd);
    b[o++] = (uint8_t)(serial >> 24); b[o++] = (uint8_t)(serial >> 16); b[o++] = (uint8_t)(serial >> 8); b[o++] = (uint8_t)serial;
    memset(b + o, 0, 16);
    o += 16;
    }
    static const uint8_t opt[] = { 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 };
    memcpy(b + o, opt, sizeof(opt));
    o += sizeof(opt);
    return o;
}

/* a query for `name` and `qtype` (no EDNS) */
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

/* the types of the RRs of a response, section by section (answer, authority, additional); returns how many */
static int rr_types(const uint8_t *m, size_t len, uint16_t t[3][8], int cnt[3]) {
    cnt[0] = cnt[1] = cnt[2] = 0;
    size_t o = 12;
    for (int q = (m[4] << 8) | m[5]; q > 0 && o < len; q--) {
        while (o < len && m[o] != 0) o += 1 + m[o];
        o += 5;
    }
    int counts[3] = { (m[6] << 8) | m[7], (m[8] << 8) | m[9], (m[10] << 8) | m[11] };
    for (int s = 0; s < 3; s++) {
        for (int r = 0; r < counts[s] && o + 11 <= len; r++) {
            size_t nl = 0;
            if (m[o] == 0) nl = 1;
            else if ((m[o] & 0xC0) == 0xC0) nl = 2;
            else { while (o + nl < len && m[o + nl] != 0) nl += 1 + m[o + nl]; nl++; }
            uint16_t type = (uint16_t)((m[o + nl] << 8) | m[o + nl + 1]);
            size_t rdlen = (size_t)((m[o + nl + 8] << 8) | m[o + nl + 9]);
            if (cnt[s] < 8) t[s][cnt[s]++] = type;
            o += nl + 10 + rdlen;
        }
    }
    return cnt[0] + cnt[1] + cnt[2];
}

static int g_bg_calls;
static char g_bg_view[64], g_bg_zone[256];
static void test_bg_hook(const char *view, const char *zone) {
    g_bg_calls++;
    snprintf(g_bg_view, sizeof(g_bg_view), "%s", view);
    snprintf(g_bg_zone, sizeof(g_bg_zone), "%s", zone);
}

static void mk_ipc(udp_ipc_t *i, int tag, size_t len) {
    memset(i, 0, sizeof(*i));
    i->sock_fd_idx = tag;
    i->addr_len = sizeof(struct sockaddr_in);
    i->payload_len = (uint16_t)len;
    i->client_addr.sin.sin_family = AF_INET;
    i->client_addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    i->client_addr.sin.sin_port = htons(40000 + (uint16_t)tag);
#if defined(__FreeBSD__) || defined(__APPLE__)
    i->client_addr.sin.sin_len = sizeof(struct sockaddr_in);
#endif
}

/* the answer the worker sent, read from the other end of the datagram socket: header fields, and the EDE info code (-1: none) */
typedef struct {
    bool got;
    int sock_idx;
    uint16_t id;
    int rcode, ancount;
    int ede;
    size_t len;
} ans_t;

static uint8_t g_raw[4096];                       /* the last answer read, as it came */
static size_t g_raw_len;

static ans_t read_answer(int fd) {
    ans_t a;
    memset(&a, 0, sizeof(a));
    a.ede = -1;
    uint8_t buf[sizeof(udp_ipc_t) + 4096];
    struct pollfd p = { fd, POLLIN, 0 };
    if (poll(&p, 1, 1000) <= 0) return a;
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < (ssize_t)sizeof(udp_ipc_t) + 12) return a;
    const udp_ipc_t *ipc = (const udp_ipc_t *)buf;
    const uint8_t *m = buf + sizeof(udp_ipc_t);
    size_t len = (size_t)n - sizeof(udp_ipc_t);
    a.got = true;
    a.sock_idx = ipc->sock_fd_idx;
    a.len = len;
    g_raw_len = len < sizeof(g_raw) ? len : sizeof(g_raw);
    memcpy(g_raw, m, g_raw_len);
    a.id = (uint16_t)((m[0] << 8) | m[1]);
    a.rcode = m[3] & 0x0F;
    a.ancount = (m[6] << 8) | m[7];
    int ar = (m[10] << 8) | m[11];
    size_t o = 12;
    for (int q = (m[4] << 8) | m[5]; q > 0 && o < len; q--) {          /* the question (names are not compressed there) */
        while (o < len && m[o] != 0) o += 1 + m[o];
        o += 5;
    }
    for (int r = a.ancount + ((m[8] << 8) | m[9]) + ar; r > 0 && o + 11 <= len; r--) {
        size_t nl = 0;
        if (m[o] == 0) nl = 1;
        else if ((m[o] & 0xC0) == 0xC0) nl = 2;
        else {
            while (o + nl < len && m[o + nl] != 0) nl += 1 + m[o + nl];
            nl++;
        }
        uint16_t type = (uint16_t)((m[o + nl] << 8) | m[o + nl + 1]);
        size_t rdlen = (size_t)((m[o + nl + 8] << 8) | m[o + nl + 9]);
        size_t rd = o + nl + 10;
        if (type == 41) {                                                /* OPT: look for the EDE option (code 15) */
            for (size_t k = rd; k + 4 <= rd + rdlen && k + 4 <= len;) {
                uint16_t code = (uint16_t)((m[k] << 8) | m[k + 1]), ol = (uint16_t)((m[k + 2] << 8) | m[k + 3]);
                if (code == 15 && ol >= 2) a.ede = (m[k + 4] << 8) | m[k + 5];
                k += 4 + ol;
            }
        }
        o = rd + rdlen;
    }
    return a;
}

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static zdir_elem_t *the_elem(void) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    zdir_elem_t *e = zdir_find_exact(snapshot_find_view(s, "default"), "park.test.");
    release_zone_snapshot(s);
    return e;
}

/* 0.7 work stealing, concurrently (run under ThreadSanitizer by test_park_worker-tsan): an owner and two thieves read one loopback UDP socket with the
 * steal protocol of dns_server_core.c (steal_owner_note(), steal_pick(), steal_may_sleep(), steal_thief_step(), the EVFILT_USER wake-up) while a sender
 * sends ST_N numbered datagrams.  Checked: every number is read exactly once (no loss, no duplicate), the thieves read some of them (the owner is
 * slow on purpose and starts only when ST_HEAD are queued, so it is behind: a thief that does nothing fails), nobody stays asleep while the owner is
 * behind (the run ends within its bound), and the shared state is race-free (TSan).  The datagrams are not DNS queries: the protocol is what is
 * tested here; worker_udp_steal() itself is tested above on real queries. */
#define ST_N 20000
#define ST_HEAD 100
#define ST_LEAD 200
#define ST_THIEVES 2
static int st_fd = -1;
static _Atomic uint8_t st_seen[ST_N];
static _Atomic int st_read_total, st_dups, st_bad, st_sent;
static _Atomic int st_read_by[1 + ST_THIEVES];
static _Atomic bool st_stop;
static int st_kq[1 + ST_THIEVES];

static int st_read_batch(int who) {
    uint8_t b[UDP_BATCH_SIZE][16];
    struct iovec iov[UDP_BATCH_SIZE];
    struct mmsghdr m[UDP_BATCH_SIZE];
    memset(m, 0, sizeof(m));
    for (int k = 0; k < UDP_BATCH_SIZE; k++) {
        iov[k].iov_base = b[k];
        iov[k].iov_len = sizeof(b[k]);
        m[k].msg_hdr.msg_iov = &iov[k];
        m[k].msg_hdr.msg_iovlen = 1;
    }
    const int n = recvmmsg(st_fd, m, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);
    for (int k = 0; k < n; k++) {
        uint32_t v;
        if (m[k].msg_len != sizeof(v)) { atomic_fetch_add(&st_bad, 1); continue; }
        memcpy(&v, b[k], sizeof(v));
        if (v >= ST_N) { atomic_fetch_add(&st_bad, 1); continue; }
        if (atomic_exchange(&st_seen[v], 1)) atomic_fetch_add(&st_dups, 1);
    }
    if (n > 0) {
        atomic_fetch_add(&st_read_total, n);
        atomic_fetch_add(&st_read_by[who], n);
    }
    return n > 0 ? n : 0;
}

static void *st_owner(void *arg) {
    (void)arg;
    while (atomic_load(&st_sent) < ST_HEAD && !atomic_load(&st_stop)) usleep(1000);   /* (behind from the start) */
    while (!atomic_load(&st_stop)) {
        struct pollfd p = { st_fd, POLLIN, 0 };
        if (poll(&p, 1, 10) != 1) continue;
        int full = 0;
        for (;;) {                                         /* worker_udp_rx(): batches until a short one; behind after the second full one */
            const int n = st_read_batch(0);
            usleep(1000);                                  /* (slow: the thieves have something to take) */
            if (n < UDP_BATCH_SIZE) break;
            (void)steal_owner_note(0, 0, ++full, false);
        }
        (void)steal_owner_note(0, 0, 0, true);
    }
    return NULL;
}

static void *st_thief(void *arg) {
    const int self = (int)(intptr_t)arg;
    steal_register(self, st_kq[self]);
    steal_thief_t t = { 0 };
    int mode = STEAL_BLOCK;
    while (!atomic_load(&st_stop)) {                      /* worker_thread_func(): the wait, the steal round, the next wait */
        struct kevent ev;
        struct timespec ts = { 0, mode == STEAL_WARM ? (long)STEAL_POLL_US * 1000L : 0L }, longest = { 0, 50000000L };
        const struct timespec *tp = &ts;
        if (mode == STEAL_BLOCK && steal_may_sleep(self)) tp = &longest;   /* ("asleep": bounded only so that the test cannot hang; the wake-up itself is checked one step at a time above) */
        (void)kevent(st_kq[self], NULL, 0, &ev, 1, tp);
        steal_awake(self);
        int a = -1, got = 0;
        const int v = steal_pick(self, &a);
        if (v == 0 && a == 0) got = st_read_batch(self);
        else if (v >= 0) atomic_fetch_add(&st_bad, 1);
        mode = steal_thief_step(&t, self, got);
    }
    return NULL;
}

static void test_steal_concurrent(void) {
    printf("[work stealing: an owner and %d thieves on one socket]\n", ST_THIEVES);
    const int saved_count = g_be_udp_count;
    g_be_udp_count = 1;
    steal_setup(1 + ST_THIEVES);
    int sc = socket(AF_INET, SOCK_DGRAM, 0);
    st_fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(st_fd >= 0 && sc >= 0);
    int rb = 1 << 20;
    setsockopt(st_fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
#if defined(__FreeBSD__) || defined(__APPLE__)
    a.sin_len = sizeof(a);
#endif
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    CHECK(bind(st_fd, (struct sockaddr *)&a, sizeof(a)) == 0 && getsockname(st_fd, (struct sockaddr *)&a, &al) == 0);
    for (int i = 0; i <= ST_THIEVES; i++) {
        st_kq[i] = kqueue();
        CHECK(st_kq[i] >= 0);
        struct kevent ev;
        EV_SET(&ev, STEAL_WAKE_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
        CHECK(kevent(st_kq[i], &ev, 1, NULL, 0, NULL) == 0);
    }
    pthread_t th[1 + ST_THIEVES];
    CHECK(pthread_create(&th[0], NULL, st_owner, NULL) == 0);
    for (int i = 1; i <= ST_THIEVES; i++) CHECK(pthread_create(&th[i], NULL, st_thief, (void *)(intptr_t)i) == 0);
    /* the sender: at most ST_LEAD ahead of the readers.  Loopback hands every datagram to the IP input queue of netisr first (net.route.netisr_maxqlen, 256
     * by default), which drops what does not fit: 4000 ahead lost about 400 of 20000 in 2 of 6 runs (pc101, 2026-11-27).  Below that queue nothing is
     * lost, so a missing datagram is the protocol's */
    for (uint32_t v = 0; v < ST_N; v++) {
        for (int t = 0; t < 30000 && (int)v - atomic_load(&st_read_total) >= ST_LEAD; t++) usleep(100);
        ssize_t s;
        while ((s = sendto(sc, &v, sizeof(v), 0, (struct sockaddr *)&a, sizeof(a))) < 0 && errno == ENOBUFS) usleep(100);
        CHECK(s == (ssize_t)sizeof(v));
        atomic_fetch_add(&st_sent, 1);
    }
    for (int t = 0; t < 60000 && atomic_load(&st_read_total) < ST_N; t++) usleep(1000);   /* (bounded: 60 s; TSan is slow) */
    atomic_store(&st_stop, true);
    for (int i = 1; i <= ST_THIEVES; i++) {
        struct kevent ev;
        EV_SET(&ev, STEAL_WAKE_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        (void)kevent(st_kq[i], &ev, 1, NULL, 0, NULL);
    }
    for (int i = 0; i <= ST_THIEVES; i++) pthread_join(th[i], NULL);
    int missing = 0;
    for (int v = 0; v < ST_N; v++) missing += !atomic_load(&st_seen[v]);
    const int stolen = atomic_load(&st_read_by[1]) + atomic_load(&st_read_by[2]);
    CHECK(atomic_load(&st_read_total) == ST_N && missing == 0 && atomic_load(&st_dups) == 0 && atomic_load(&st_bad) == 0);
    CHECK(stolen > 0);
    printf("  read %d of %d (owner %d, thieves %d + %d), missing %d, duplicates %d, bad %d\n", atomic_load(&st_read_total), ST_N,
           atomic_load(&st_read_by[0]), atomic_load(&st_read_by[1]), atomic_load(&st_read_by[2]), missing, atomic_load(&st_dups), atomic_load(&st_bad));
    int sa;
    CHECK(steal_pick(1, &sa) == -1);                       /* (the owner cleared its mark) */
    for (int i = 0; i <= ST_THIEVES; i++) close(st_kq[i]);
    close(st_fd);
    close(sc);
    steal_setup(0);
    g_be_udp_count = saved_count;
}

int main(void) {
    printf("[a worker parks a query for a zone that is not in memory]\n");
    char dir[] = "/tmp/karidns_parkw_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char zf[300], conf[1200];
    snprintf(zf, sizeof(zf), "%s/park.test.zone", dir);
    FILE *fp = fopen(zf, "w");
    CHECK(fp != NULL);
    fputs("$ORIGIN park.test.\n$TTL 300\n@ IN SOA ns.park.test. h.park.test. 1 7200 3600 1209600 300\n@ IN NS ns.park.test.\nns IN A 192.0.2.1\nwww IN A 192.0.2.80\n", fp);
    fclose(fp);
    snprintf(conf, sizeof(conf), "options { directory \"%s\"; };\n"
             "key \"k1\" { algorithm hmac-sha256; secret \"c2VjcmV0LWtleS1vbmUtMTIzNDU2Nzg5MDEyMzQ1Ng==\"; };\n"
             "view \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; }; };\n", dir, zf);
    static server_config_t cfg;
    CHECK(parse_named_conf(conf, &cfg) == 0);
    cfg.send_extended_errors = true;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    rebuild_zone_db_from_config(&cfg, false);
    zdir_elem_t *el = the_elem();
    CHECK(el != NULL && zdir_entry(el) != NULL);
    zone_db_entry_t *entry = zdir_entry(el);

    static worker_ctx_t wctx;
    memset(&wctx, 0, sizeof(wctx));
    static compress_ctx_t cc;
    memset(&cc, 0, sizeof(cc));
    int sk[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sk) == 0);
    int sndbuf = 1 << 20;
    setsockopt(sk[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(sk[1], SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));

    park_table_t table;
    CHECK(park_init(&table, 8));
    park_register_worker(0, -1);
    udp_pass_t w;
    memset(&w, 0, sizeof(w));
    w.ctx = &wctx;
    w.batch = &wctx.batch;
    w.cc = &cc;
    w.active_fd = sk[0];
    w.park = &table;
    w.worker_idx = 0;
    w.park_timeout_ms = 5000;
    udp_batch_ctx_t *batch = &wctx.batch;
    uint8_t *rx = batch->rx_buffers[0];

    #define SEND_QUERY(id, edns, pad) do { size_t ql_ = build_query(rx + sizeof(udp_ipc_t), (id), (edns), (pad)); \
        mk_ipc((udp_ipc_t *)rx, 7, ql_); w.n_tx = 0; udp_one(&w, (udp_ipc_t *)rx, rx + sizeof(udp_ipc_t), (ssize_t)ql_); } while (0)
    #define FLUSH() do { if (w.n_tx > 0) { for (int k_ = 0; k_ < w.n_tx; k_++) send(sk[0], batch->tx_buffers[k_], batch->tx_iov[k_].iov_len, 0); w.n_tx = 0; } } while (0)

    /* -- in memory: answered at once, nothing parked */
    SEND_QUERY(0x1001, true, 0);
    CHECK(w.n_tx == 1 && table.nwait == 0);
    FLUSH();
    ans_t a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x1001 && a.rcode == 0 && a.ancount == 1 && a.ede == -1);

    /* -- not in memory: parked.  The first query for the zone asks for it, the second asks for nothing */
    atomic_store(&el->entry, NULL);
    atomic_store(&el->state, ZDIR_ST_ABSENT);
    SEND_QUERY(0x2001, true, 0);
    CHECK(w.n_tx == 0 && table.nwait == 1);
    park_fetch_req_t q;
    CHECK(park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.view, "default") == 0 && strcmp(q.zone, "park.test.") == 0 &&
          q.prio == KDB_FETCH_PRIO_QUERY && q.mode == KDB_FETCH_FULL);
    SEND_QUERY(0x2002, true, 0);
    CHECK(w.n_tx == 0 && table.nwait == 2 && !park_fetch_pop(park_fetch_ring(0), &q));
    CHECK(!read_answer(sk[1]).got);                                    /* nothing was sent */

    /* -- the zone is back and the ingest thread says so: both are answered, on their socket, with their IDs */
    atomic_store(&el->entry, entry);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
    park_service(&w, -1);
    CHECK(table.nwait == 0 && table.nready == 0 && table.nfree == table.cap);
    ans_t a1 = read_answer(sk[1]), a2 = read_answer(sk[1]);
    CHECK(a1.got && a2.got && a1.sock_idx == 7 && a2.sock_idx == 7);
    CHECK((a1.id == 0x2001 && a2.id == 0x2002) || (a1.id == 0x2002 && a2.id == 0x2001));
    CHECK(a1.rcode == 0 && a1.ancount == 1 && a2.rcode == 0 && a2.ancount == 1);
    CHECK(!read_answer(sk[1]).got);                                    /* once */

    /* -- 0.7 B3 phase 2, udp-receive backend: the query comes in on the worker's own UDP socket (worker_udp_rx(): the header from msg_name and the
     *    address the socket is bound to, socket index 2), is answered on the pair to the router with that index and the client's address; one for the
     *    zone that is not in memory parks with them and its answer, after the wake-up, goes out the same way (the entry's pair, not the pass's) */
    {
        int us = socket(AF_INET, SOCK_DGRAM, 0), uc = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(us >= 0 && uc >= 0);
        struct sockaddr_in ua, ucl;
        memset(&ua, 0, sizeof(ua));
        ua.sin_family = AF_INET;
#if defined(__FreeBSD__) || defined(__APPLE__)
        ua.sin_len = sizeof(ua);
#endif
        ua.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ucl = ua;
        socklen_t sl = sizeof(ua);
        CHECK(bind(us, (struct sockaddr *)&ua, sizeof(ua)) == 0 && getsockname(us, (struct sockaddr *)&ua, &sl) == 0);
        sl = sizeof(ucl);
        CHECK(bind(uc, (struct sockaddr *)&ucl, sizeof(ucl)) == 0 && getsockname(uc, (struct sockaddr *)&ucl, &sl) == 0);
        fcntl(us, F_SETFL, fcntl(us, F_GETFL, 0) | O_NONBLOCK);
        g_be_udp_count = 3;
        g_be_udp_wild[2] = false;
        struct sockaddr_storage bss;
        memset(&bss, 0, sizeof(bss));
        memcpy(&bss, &ua, sizeof(ua));
        CHECK(router_src_from_sockaddr(&bss, &g_be_udp_src[2]));
        const uint64_t q0 = atomic_load(&wctx.query_count), r0 = ipcd_wrecv(0);
        const uint64_t short0 = ipcd_total(IPCD_WURX_SHORT), trunc0 = ipcd_total(IPCD_WURX_TRUNC);
        uint8_t qb[600];
        #define UDP_IN(id) do { size_t ql_ = build_query(qb, (id), true, 0); CHECK(sendto(uc, qb, ql_, 0, (struct sockaddr *)&ua, sizeof(ua)) == (ssize_t)ql_); \
            struct pollfd up_ = { us, POLLIN, 0 }; CHECK(poll(&up_, 1, 2000) == 1); } while (0)
        /* the raw answer on the router's pair: the header the router reads */
        #define RAW_ANSWER(hdr, id_out) do { uint8_t rb_[sizeof(udp_ipc_t) + 4096]; struct pollfd rp_ = { sk[1], POLLIN, 0 }; ssize_t rn_ = poll(&rp_, 1, 1000) == 1 ? \
            recv(sk[1], rb_, sizeof(rb_), 0) : -1; CHECK(rn_ > (ssize_t)sizeof(udp_ipc_t) + 12); memset(&(hdr), 0, sizeof(hdr)); (id_out) = 0; \
            if (rn_ > (ssize_t)sizeof(udp_ipc_t) + 12) { memcpy(&(hdr), rb_, sizeof(hdr)); (id_out) = (uint16_t)((rb_[sizeof(udp_ipc_t)] << 8) | rb_[sizeof(udp_ipc_t) + 1]); } } while (0)

        udp_ipc_t rh;
        uint16_t rid;
        UDP_IN(0x6101);                                              /* in memory: answered at once */
        CHECK(worker_udp_rx(&w, us, 2, sk[0]) == 1 && w.n_tx == 0 && table.nwait == 0);
        RAW_ANSWER(rh, rid);
        CHECK(rid == 0x6101 && rh.sock_fd_idx == 2 && rh.addr_len == sizeof(struct sockaddr_in) && rh.client_addr.sin.sin_port == ucl.sin_port &&
              rh.client_addr.sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        CHECK(rh.has_source_addr && rh.source_addr.sin.sin_family == AF_INET && rh.source_addr.sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

        atomic_store(&el->entry, NULL);                              /* not in memory: parked, nothing sent, the zone asked for */
        UDP_IN(0x6102);
        CHECK(worker_udp_rx(&w, us, 2, sk[0]) == 1 && table.nwait == 1);
        CHECK(park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "park.test.") == 0);
        CHECK(!read_answer(sk[1]).got);
        atomic_store(&el->entry, entry);
        CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
        w.active_fd = -1;                                            /* (the parked entry knows the pair; the pass's is not used) */
        park_service(&w, -1);
        w.active_fd = sk[0];
        CHECK(table.nwait == 0 && table.nready == 0);
        RAW_ANSWER(rh, rid);
        CHECK(rid == 0x6102 && rh.sock_fd_idx == 2 && rh.client_addr.sin.sin_port == ucl.sin_port && rh.has_source_addr &&
              rh.source_addr.sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        CHECK(!read_answer(sk[1]).got);                              /* once */

        /* a datagram shorter than a DNS header and one larger than the buffer (cut: MSG_TRUNC) are dropped and counted, never run */
        CHECK(sendto(uc, "short", 5, 0, (struct sockaddr *)&ua, sizeof(ua)) == 5);
        static uint8_t big[5000];
        memset(big, 0, sizeof(big));
        CHECK(sendto(uc, big, sizeof(big), 0, (struct sockaddr *)&ua, sizeof(ua)) == (ssize_t)sizeof(big));
        int runs = 0;
        for (int i = 0; i < 200 && (ipcd_total(IPCD_WURX_SHORT) < short0 + 1 || ipcd_total(IPCD_WURX_TRUNC) < trunc0 + 1); i++) {   /* (bounded: 2 s) */
            runs += worker_udp_rx(&w, us, 2, sk[0]);
            usleep(10000);
        }
        CHECK(runs == 0 && ipcd_total(IPCD_WURX_SHORT) == short0 + 1 && ipcd_total(IPCD_WURX_TRUNC) == trunc0 + 1);
        CHECK(!read_answer(sk[1]).got);
        CHECK(atomic_load(&wctx.query_count) == q0 + 2 && ipcd_wrecv(0) == r0 + 2);
        /* a socket index the Backend does not have reads nothing */
        UDP_IN(0x6103);
        CHECK(worker_udp_rx(&w, us, 3, sk[0]) == 0 && worker_udp_rx(&w, us, -1, sk[0]) == 0);
        CHECK(worker_udp_rx(&w, us, 2, sk[0]) == 1);
        RAW_ANSWER(rh, rid);
        CHECK(rid == 0x6103 && rh.sock_fd_idx == 2);

        /* -- 0.7 work stealing (planing_0.7.x_worker_steal.md): the socket `us` is worker 1's now; worker 0 (this pass, with the park table) is the
         *    thief.  A stolen batch is run as worker 0's own: its frames go on worker 0's pair (sk) with the listen address's index 2, so the router
         *    sends them on worker 0's socket of the same address (same address and port); stolen / lent count it; what is left stays for the owner */
        {
            int stk = kqueue();
            CHECK(stk >= 0);
            struct kevent kreg;
            EV_SET(&kreg, STEAL_WAKE_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);  /* (as worker_thread_func() registers it) */
            CHECK(kevent(stk, &kreg, 1, NULL, 0, NULL) == 0);
            g_be_udp_fds[1][2] = us;
            g_be_udp_fds[0][2] = -1;
            steal_setup(1);
            CHECK(!steal_on());                                      /* one worker: nobody to steal from */
            CHECK(steal_owner_note(1, 2, 2, false) == 0 && worker_udp_steal(&w, 1, 2, sk[0]) == 0);
            steal_setup(2);
            CHECK(steal_on());
            steal_register(0, stk);
            steal_register(-1, stk);
            steal_register(2, stk);                                  /* (no such worker: nothing) */
            #define QUEUE(n, id0) do { for (int i_ = 0; i_ < (n); i_++) { size_t ql_ = build_query(qb, (uint16_t)((id0) + i_), true, 0); \
                CHECK(sendto(uc, qb, ql_, 0, (struct sockaddr *)&ua, sizeof(ua)) == (ssize_t)ql_); } \
                int nr_ = 0; for (int t_ = 0; t_ < 400; t_++) { if (ioctl(us, FIONREAD, &nr_) == 0 && nr_ >= (n) * (int)ql_one) break; usleep(5000); } \
                CHECK(nr_ >= (n) * (int)ql_one); } while (0)
            const size_t ql_one = build_query(qb, 0, true, 0);
            /* the frames on the pair: how many, all with index 2 and this client; returns the number read */
            #define FRAMES(want) do { int nf_ = 0, bad_ = 0; uint8_t fb_[65536]; for (int t_ = 0; t_ < 100 && nf_ < (want); t_++) { \
                struct pollfd fp_ = { sk[1], POLLIN, 0 }; if (poll(&fp_, 1, 20) != 1) continue; ssize_t fn_ = recv(sk[1], fb_, sizeof(fb_), 0); \
                size_t fo_ = 0; const udp_ipc_t *fm_; while (fn_ > 0 && udp_ipc_frame_next(fb_, (size_t)fn_, &fo_, &fm_) == UDP_IPC_FRAME_OK) { nf_++; \
                if (fm_->sock_fd_idx != 2 || fm_->client_addr.sin.sin_port != ucl.sin_port) bad_++; } } \
                CHECK(nf_ == (want) && bad_ == 0); if (nf_ != (want) || bad_) printf("    frames %d (want %d), bad %d\n", nf_, (want), bad_); \
                CHECK(!read_answer(sk[1]).got); } while (0)

            const uint64_t s0 = steal_stolen(0), l1 = steal_lent(1), r0w = ipcd_wrecv(0), q0w = atomic_load(&wctx.query_count);
            QUEUE(40, 0x6200);
            CHECK(worker_udp_steal(&w, 1, 2, sk[0]) == UDP_BATCH_SIZE);      /* one batch, not the whole queue */
            CHECK(steal_stolen(0) == s0 + UDP_BATCH_SIZE && steal_lent(1) == l1 + UDP_BATCH_SIZE);
            CHECK(ipcd_wrecv(0) == r0w + UDP_BATCH_SIZE && atomic_load(&wctx.query_count) == q0w + UDP_BATCH_SIZE);
            FRAMES(UDP_BATCH_SIZE);
            CHECK(worker_udp_rx(&w, us, 2, sk[0]) == 40 - UDP_BATCH_SIZE);  /* the rest is still there for the owner */
            FRAMES(40 - UDP_BATCH_SIZE);
            CHECK(worker_udp_steal(&w, 1, 2, sk[0]) == 0);                  /* empty: nothing, nothing counted */
            CHECK(steal_stolen(0) == s0 + UDP_BATCH_SIZE);
            /* arguments the thief must not act on: itself, a worker or an address that does not exist, a socket it does not hold */
            CHECK(worker_udp_steal(&w, 0, 2, sk[0]) == 0 && worker_udp_steal(&w, 2, 2, sk[0]) == 0 && worker_udp_steal(&w, -1, 2, sk[0]) == 0);
            CHECK(worker_udp_steal(&w, 1, 3, sk[0]) == 0 && worker_udp_steal(&w, 1, -1, sk[0]) == 0);
            g_be_udp_fds[1][2] = -1;
            CHECK(worker_udp_steal(&w, 1, 2, sk[0]) == 0);
            g_be_udp_fds[1][2] = us;
            w.worker_idx = 5;                                                /* (a thief that is not a worker) */
            CHECK(worker_udp_steal(&w, 1, 2, sk[0]) == 0);
            w.worker_idx = 0;

            /* the owner's mark: one full batch is not "behind", the second in the same wake is; a short batch clears it; two addresses count once */
            int sa = -1;
            CHECK(steal_pick(0, &sa) == -1);
            CHECK(steal_owner_note(1, 2, 1, false) == 0 && steal_pick(0, &sa) == -1);
            CHECK(steal_owner_note(1, 2, 2, false) == 0 && steal_pick(0, &sa) == 1 && sa == 2);   /* (nobody sleeps: nobody woken) */
            CHECK(steal_owner_note(1, 2, 3, false) == 0 && steal_pick(1, &sa) == -1);            /* (set already; a worker never picks itself) */
            CHECK(steal_owner_note(1, 6, 2, false) == 0 && steal_pick(0, &sa) == 1 && sa == 2);
            CHECK(steal_owner_note(1, 2, 0, true) == 0 && steal_pick(0, &sa) == 1 && sa == 6);
            CHECK(steal_owner_note(1, 6, 0, true) == 0 && steal_pick(0, &sa) == -1);
            CHECK(steal_owner_note(1, 6, 0, true) == 0);                    /* (cleared already) */
            CHECK(steal_owner_note(1, -1, 2, false) == 0 && steal_owner_note(1, MAX_BIND_ADDRS, 2, false) == 0 && steal_owner_note(7, 2, 2, false) == 0);
            CHECK(steal_pick(-1, &sa) == -1 && steal_pick(2, &sa) == -1);

            /* the thief's waits: right away after a full batch, warm while a worker is busy and for STEAL_LINGER_POLLS looks after, then asleep */
            steal_thief_t th = { 0 };
            CHECK(steal_thief_step(&th, 0, 0) == STEAL_BLOCK);
            CHECK(steal_thief_step(&th, 0, UDP_BATCH_SIZE) == STEAL_NOW);
            for (int i = 0; i < STEAL_LINGER_POLLS; i++) CHECK(steal_thief_step(&th, 0, 3) == STEAL_WARM);
            CHECK(steal_thief_step(&th, 0, 0) == STEAL_BLOCK);
            CHECK(steal_owner_note(1, 2, 2, false) == 0);
            for (int i = 0; i < STEAL_LINGER_POLLS + 2; i++) CHECK(steal_thief_step(&th, 0, 0) == STEAL_WARM);   /* (busy: warm however long) */
            CHECK(steal_owner_note(1, 2, 0, true) == 0);

            /* sleeping and waking: a worker that sleeps is woken once, by EVFILT_USER on its kqueue, when another falls behind; one that went to sleep
             * while another was busy does not sleep (the order of the two stores and loads) */
            struct kevent kev;
            const struct timespec zero = { 0, 0 };
            CHECK(steal_may_sleep(0));                                       /* nothing busy: it may sleep (marked cold) */
            CHECK(steal_owner_note(1, 2, 2, false) == 1);                    /* worker 0 woken */
            CHECK(kevent(stk, NULL, 0, &kev, 1, &zero) == 1 && kev.filter == EVFILT_USER && kev.ident == STEAL_WAKE_IDENT);
            CHECK(kevent(stk, NULL, 0, &kev, 1, &zero) == 0);                /* once */
            CHECK(!steal_may_sleep(0));                                      /* busy now: stays awake */
            CHECK(steal_owner_note(1, 2, 0, true) == 0 && steal_owner_note(1, 2, 2, false) == 0);   /* (not cold: nobody woken) */
            CHECK(steal_owner_note(1, 2, 0, true) == 0);
            CHECK(steal_may_sleep(0));
            steal_awake(0);                                                  /* woken by its own socket: no longer cold */
            CHECK(steal_owner_note(1, 2, 2, false) == 0 && kevent(stk, NULL, 0, &kev, 1, &zero) == 0);
            CHECK(steal_owner_note(1, 2, 0, true) == 0);
            CHECK(steal_may_sleep(-1) && steal_may_sleep(2));                /* (not a worker: may sleep, nothing marked) */
            steal_awake(-1);
            steal_awake(1);                                                  /* (not cold: nothing to do) */
            /* ... and a full stolen batch wakes one more sleeper (the thieves grow with the backlog) */
            CHECK(steal_may_sleep(0));
            CHECK(steal_thief_step(&th, 1, UDP_BATCH_SIZE) == STEAL_NOW);
            CHECK(kevent(stk, NULL, 0, &kev, 1, &zero) == 1 && kev.ident == STEAL_WAKE_IDENT);

            /* the owner's own read loop marks it: 40 queued = 16 + 16 + 8; the second full batch wakes the sleeping worker 0, the short one clears it */
            w.worker_idx = 1;
            CHECK(steal_may_sleep(0));
            QUEUE(40, 0x6300);
            CHECK(worker_udp_rx(&w, us, 2, sk[0]) == 40);
            FRAMES(40);
            CHECK(kevent(stk, NULL, 0, &kev, 1, &zero) == 1 && kev.ident == STEAL_WAKE_IDENT);
            CHECK(steal_pick(0, &sa) == -1);                                 /* drained: not busy any more */
            QUEUE(20, 0x6400);                                               /* 16 + 4: one full batch only, not behind */
            CHECK(steal_may_sleep(0) && worker_udp_rx(&w, us, 2, sk[0]) == 20);
            FRAMES(20);
            CHECK(kevent(stk, NULL, 0, &kev, 1, &zero) == 0);
            steal_awake(0);
            w.worker_idx = 0;

            /* a stolen query for the zone that is not in memory parks in the thief's table, with the thief's pair; after the wake-up its answer goes out
             * the same way (the thief's pair, index 2) */
            atomic_store(&el->entry, NULL);
            QUEUE(1, 0x6501);
            CHECK(worker_udp_steal(&w, 1, 2, sk[0]) == 1 && table.nwait == 1);
            CHECK(park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "park.test.") == 0);
            CHECK(!read_answer(sk[1]).got);
            atomic_store(&el->entry, entry);
            CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
            w.active_fd = -1;
            park_service(&w, -1);
            w.active_fd = sk[0];
            CHECK(table.nwait == 0 && table.nready == 0);
            RAW_ANSWER(rh, rid);
            CHECK(rid == 0x6501 && rh.sock_fd_idx == 2 && rh.client_addr.sin.sin_port == ucl.sin_port);
            CHECK(!read_answer(sk[1]).got);
            #undef QUEUE
            #undef FRAMES
            g_be_udp_fds[1][2] = -1;
            steal_setup(0);
            close(stk);
        }

        #undef UDP_IN
        #undef RAW_ANSWER
        g_be_udp_count = 0;
        close(us);
        close(uc);
    }

    /* -- woken while the zone is still not there: parked again, with the deadline it had; nothing asked again while a fetch is on its way (LOADING) ... */
    atomic_store(&el->entry, NULL);
    SEND_QUERY(0x3001, true, 0);
    CHECK(table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q));
    int64_t d0 = park_next_deadline_ms(&table, 0);
    atomic_store(&el->state, ZDIR_ST_LOADING);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
    park_service(&w, -1);
    CHECK(table.nwait == 1 && !park_fetch_pop(park_fetch_ring(0), &q) && !read_answer(sk[1]).got);
    CHECK(park_next_deadline_ms(&table, 0) == d0);
    /* ... and asked again when nothing is on its way: the zone was taken out of memory again before the request could use it (the cache manager) */
    atomic_store(&el->state, ZDIR_ST_ABSENT);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
    park_service(&w, -1);
    CHECK(table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q) && !park_fetch_pop(park_fetch_ring(0), &q) && !read_answer(sk[1]).got);
    CHECK(park_next_deadline_ms(&table, 0) == d0);
    atomic_store(&el->entry, entry);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x3001 && a.rcode == 0 && a.ancount == 1 && table.nwait == 0);

    /* -- the time is up and the zone is not there: the query is dropped and counted (0.7: overload is never answered REFUSED or SERVFAIL for a zone the database may have) */
    atomic_store(&el->entry, NULL);
    w.park_timeout_ms = 5;
    SEND_QUERY(0x4001, true, 0);
    CHECK(table.nwait == 1);
    (void)park_fetch_pop(park_fetch_ring(0), &q);
    usleep(30000);
    const uint64_t zt0 = park_cnt_get(PARK_CNT_ZONE_TIMEOUT);
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(!a.got && table.nwait == 0 && table.nready == 0 && park_cnt_get(PARK_CNT_ZONE_TIMEOUT) == zt0 + 1);
    w.park_timeout_ms = 5000;

    /* -- a failed fetch: answered at once, with the same answer */
    SEND_QUERY(0x5001, true, 0);
    CHECK(table.nwait == 1);
    (void)park_fetch_pop(park_fetch_ring(0), &q);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", true));
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x5001 && a.rcode == 2 && a.ede == 14 && table.nwait == 0);
    /* ... without EDNS there is no OPT to carry the error: SERVFAIL alone */
    SEND_QUERY(0x5002, false, 0);
    (void)park_fetch_pop(park_fetch_ring(0), &q);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", true));
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x5002 && a.rcode == 2 && a.ede == -1);

    /* -- a lost wake-up (the ring overflowed): every parked query looks again */
    SEND_QUERY(0x5101, true, 0);
    (void)park_fetch_pop(park_fetch_ring(0), &q);
    atomic_store(&el->entry, entry);
    atomic_store(&park_wake_ring(0)->overflow, true);
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x5101 && a.rcode == 0 && a.ancount == 1);
    atomic_store(&el->entry, NULL);

    /* -- a request too big to park (more than PARK_UDP_MAX bytes) and a worker without a park table: "not ready" at once; a full table is overload: the query is dropped and counted */
    SEND_QUERY(0x6001, true, PARK_UDP_MAX);
    CHECK(w.n_tx == 1 && table.nwait == 0 && table.n_toobig == 1);
    FLUSH();
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x6001 && a.rcode == 2 && a.ede == 14);
    park_table_t tiny;
    CHECK(park_init(&tiny, 1));
    w.park = &tiny;
    SEND_QUERY(0x6002, true, 0);
    CHECK(tiny.nwait == 1 && w.n_tx == 0);
    SEND_QUERY(0x6003, true, 0);                                       /* the table is full */
    CHECK(w.n_tx == 0 && tiny.nwait == 1 && tiny.n_full == 1 && park_cnt_get(PARK_CNT_ZONE_ROOM) == 1);
    FLUSH();
    a = read_answer(sk[1]);
    CHECK(!a.got);
    w.park = NULL;
    SEND_QUERY(0x6004, true, 0);
    CHECK(w.n_tx == 1);
    FLUSH();
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x6004 && a.rcode == 2 && a.ede == 14);
    park_free(&tiny);

    /* -- the time is up, but the zone is there when the request is looked at again: it is answered from the zone, not "not ready" (the TCP
     *    path does the same) */
    w.park = &table;
    w.park_timeout_ms = 5;
    SEND_QUERY(0x7001, true, 0);
    CHECK(table.nwait == 1);
    (void)park_fetch_pop(park_fetch_ring(0), &q);
    usleep(30000);
    atomic_store(&el->entry, entry);                                   /* (no wake-up message: the deadline alone runs the request again) */
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x7001 && a.rcode == 0 && a.ancount == 1 && a.ede == -1 && table.nwait == 0);
    atomic_store(&el->entry, NULL);
    w.park_timeout_ms = 5000;

    /* -- 0.7, the by-name lookup of a name that no zone covers (the store's first pass has not listed every zone: forced here): the query parks and asks for the lookup (FETCH_REQ mode 2).  A wake that is not
     *    the answer (every query is woken after a wake ring that overflowed) parks it again for the lookup, with the deadline it had, and asks again; only the answer (a wake by the name), a failure or the
     *    park-timeout end it, with the normal answer (REFUSED for a name no zone has) */
    {
        atomic_store(&dns_core_test_lookup_force, true);
        const uint64_t tf0 = park_lookup_take_fails();
        while (park_fetch_pop(park_fetch_ring(0), &q)) {}                                          /* (what the tests before left in the ring) */
        #define SEND_LK(id) do { size_t ql_ = build_lk_query(rx + sizeof(udp_ipc_t), (id)); \
            mk_ipc((udp_ipc_t *)rx, 7, ql_); w.n_tx = 0; udp_one(&w, (udp_ipc_t *)rx, rx + sizeof(udp_ipc_t), (ssize_t)ql_); } while (0)
        SEND_LK(0x7101);
        CHECK(w.n_tx == 0 && table.nwait == 1 && table.nlook == 1);
        CHECK(park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "www.late.test.") == 0 && q.mode == KDB_FETCH_LOOKUP && !park_fetch_pop(park_fetch_ring(0), &q));
        const int64_t dl = park_next_deadline_ms(&table, 0);
        /* the spurious wake: parked again with the first deadline, the request is made again, nothing is answered */
        atomic_store(&park_wake_ring(0)->overflow, true);
        park_service(&w, -1);
        CHECK(table.nwait == 1 && table.nready == 0 && !read_answer(sk[1]).got && table.nlook == 1);
        CHECK(park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "www.late.test.") == 0 && q.mode == KDB_FETCH_LOOKUP);
        CHECK(park_next_deadline_ms(&table, 0) <= dl && park_next_deadline_ms(&table, 0) >= dl - 3);
        /* ... as often as it happens; and when the worker's ring to the ingest thread is full the request cannot be made: the query is parked all the same (it is not refused), the request is pending (PARK_PEND_LOOKUP)
         * and is made at a pass of the worker when the ring has room */
        while (park_fetch_push(park_fetch_ring(0), "default", "other.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY)) {}
        atomic_store(&park_wake_ring(0)->overflow, true);
        park_service(&w, -1);
        CHECK(table.nwait == 1 && table.nready == 0 && !read_answer(sk[1]).got && table.nunsent == 1 && table.e[park_pending_head(&table) - table.e].pend == PARK_PEND_LOOKUP && park_lookup_take_fails() == tf0 + 1);
        park_service(&w, -1);                                                                      /* (the ring is still full: it waits) */
        CHECK(table.nwait == 1 && table.nunsent == 1 && !read_answer(sk[1]).got);
        while (park_fetch_pop(park_fetch_ring(0), &q)) {}                                          /* (the ingest thread took them: there is room) */
        park_service(&w, -1);
        CHECK(table.nwait == 1 && table.nunsent == 0 && park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "www.late.test.") == 0 && q.mode == KDB_FETCH_LOOKUP && q.prio == KDB_FETCH_PRIO_QUERY &&
              !park_fetch_pop(park_fetch_ring(0), &q));
        /* the answer (a wake by the name): the query looks the name up again and, with no zone for it, is refused */
        CHECK(park_wake_push(park_wake_ring(0), "default", "www.late.test.", false));
        park_service(&w, -1);
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7101 && a.rcode == 5 && a.ancount == 0 && table.nwait == 0 && table.nready == 0 && table.nlook == 0);
        /* the same name asked for by a second query (the first one waits for it): one request, and the second only waits; the answer is for both */
        SEND_LK(0x7106);
        SEND_LK(0x7107);
        CHECK(table.nwait == 2 && table.nlook == 2 && park_fetch_pop(park_fetch_ring(0), &q) && !park_fetch_pop(park_fetch_ring(0), &q));
        CHECK(park_wake_push(park_wake_ring(0), "default", "www.late.test.", false));
        park_service(&w, -1);
        a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 5);
        a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 5 && table.nwait == 0 && table.nlook == 0);
        /* the entries that wait for a lookup may take three quarters of the park table: the query that finds no room is dropped (nothing is answered, counted), never refused; the others are answered when the lookup is */
        {
            park_table_t small;
            CHECK(park_init(&small, 8));
            w.park = &small;
            const uint64_t lr0 = park_cnt_get(PARK_CNT_LK_ROOM);
            for (int i = 0; i < 7; i++) SEND_LK(0x7110 + i);
            CHECK(small.nwait == 6 && small.nlook == 6 && w.n_tx == 0 && park_cnt_get(PARK_CNT_LK_ROOM) == lr0 + 1);
            while (park_fetch_pop(park_fetch_ring(0), &q)) {}
            CHECK(park_wake_push(park_wake_ring(0), "default", "www.late.test.", false));
            park_service(&w, -1);
            int refused = 0;
            for (int i = 0; i < 7; i++) {
                a = read_answer(sk[1]);
                if (a.got && a.rcode == 5) refused++;
            }
            CHECK(refused == 6 && small.nwait == 0 && small.nlook == 0);
            /* the ingest thread dropped the lookup (its queue was full, or it waited too long): the queries are dropped, counted; a zone's wait queue that is full drops the queries that wait for the zone */
            const uint64_t lq0 = park_cnt_get(PARK_CNT_LK_QUEUE), zq0 = park_cnt_get(PARK_CNT_ZONE_QUEUE);
            SEND_LK(0x7120);
            SEND_LK(0x7121);
            CHECK(small.nwait == 2);
            park_wake_queue_drop_one(0, "default", "www.late.test.");
            park_service(&w, -1);
            a = read_answer(sk[1]);
            CHECK(!a.got && small.nwait == 0 && small.nready == 0 && small.nlook == 0 && park_cnt_get(PARK_CNT_LK_QUEUE) == lq0 + 2);
            SEND_QUERY(0x7130, true, 0);
            CHECK(small.nwait == 1);
            while (park_fetch_pop(park_fetch_ring(0), &q)) {}
            park_wake_queue_drop_one(0, "default", "park.test.");
            park_service(&w, -1);
            a = read_answer(sk[1]);
            CHECK(!a.got && small.nwait == 0 && small.nready == 0 && park_cnt_get(PARK_CNT_ZONE_QUEUE) == zq0 + 1);
            park_claim_release("default", "park.test.");
            w.park = &table;
            park_free(&small);
        }
        /* the lookup failed (the database, the loader): SERVFAIL + EDE 14 at once, as the fetch of a zone that fails.  The query has an OPT record: the answer must carry the Extended DNS Error 14 (Not Ready, RFC 8914 4.15) */
        {
            size_t ql_ = build_lk_query_edns(rx + sizeof(udp_ipc_t), 0x7102);
            mk_ipc((udp_ipc_t *)rx, 7, ql_); w.n_tx = 0; udp_one(&w, (udp_ipc_t *)rx, rx + sizeof(udp_ipc_t), (ssize_t)ql_);
        }
        CHECK(table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q));
        CHECK(park_wake_push(park_wake_ring(0), "default", "www.late.test.", true));
        park_service(&w, -1);
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7102 && a.rcode == 2 && a.ancount == 0 && a.ede == 14 && table.nwait == 0 && table.nlook == 0 && park_cnt_get(PARK_CNT_LK_SERVFAIL) == 1);        /* (a failed lookup: SERVFAIL + EDE 14, as for a zone whose fetch failed) */
        /* the ingest thread shed the lookup of the name lately and remembers it (park_shed_remember()): a query for it is dropped at once with no request, counted; when the names are released (the ingest thread has caught
         * up) the next query asks again.  A name that is not remembered is asked for as before. */
        {
            struct timespec tn;
            clock_gettime(CLOCK_MONOTONIC, &tn);
            const int64_t t_ms = (int64_t)tn.tv_sec * 1000 + tn.tv_nsec / 1000000;
            const uint64_t rk0 = park_cnt_get(PARK_CNT_LK_REMEMBERED);
            park_shed_set_ttl(60000);
            park_shed_remember(park_lookup_claim_key("default", "www.late.test."), t_ms);
            SEND_LK(0x7140);
            CHECK(w.n_tx == 0 && table.nwait == 0 && table.nlook == 0 && !park_fetch_pop(park_fetch_ring(0), &q) && !read_answer(sk[1]).got && park_cnt_get(PARK_CNT_LK_REMEMBERED) == rk0 + 1);
            clock_gettime(CLOCK_MONOTONIC, &tn);                                                  /* (released: the next query for the name parks and asks) */
            park_shed_release((int64_t)tn.tv_sec * 1000 + tn.tv_nsec / 1000000);
            SEND_LK(0x7141);
            CHECK(w.n_tx == 0 && table.nwait == 1 && table.nlook == 1 && park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "www.late.test.") == 0 && q.mode == KDB_FETCH_LOOKUP &&
                  park_cnt_get(PARK_CNT_LK_REMEMBERED) == rk0 + 1);
            CHECK(park_wake_push(park_wake_ring(0), "default", "www.late.test.", false));
            park_service(&w, -1);
            a = read_answer(sk[1]);
            CHECK(a.got && a.id == 0x7141 && a.rcode == 5 && table.nwait == 0 && table.nlook == 0);
            park_shed_set_ttl(0);
        }
        /* the time is up: the answer of a query that has waited the park-timeout; and a wake of every query after the deadline does not park it again */
        w.park_timeout_ms = 5;
        const uint64_t lt0 = park_cnt_get(PARK_CNT_LK_TIMEOUT);
        SEND_LK(0x7103);
        CHECK(table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q));
        usleep(30000);
        park_service(&w, -1);
        a = read_answer(sk[1]);
        CHECK(!a.got && table.nwait == 0 && table.nlook == 0 && park_cnt_get(PARK_CNT_LK_TIMEOUT) == lt0 + 1);        /* (dropped, counted) */
        SEND_LK(0x7104);
        CHECK(table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q));
        usleep(30000);
        CHECK(park_wake_all(&table) == 1);                                                        /* (it is READY with its mark when the worker looks: the deadline has passed) */
        park_service(&w, -1);
        a = read_answer(sk[1]);
        CHECK(!a.got && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q) && park_cnt_get(PARK_CNT_LK_TIMEOUT) == lt0 + 2);
        w.park_timeout_ms = 5000;
        /* not wanted (the pass has ended: no force): refused at once, nothing parked or asked */
        atomic_store(&dns_core_test_lookup_force, false);
        SEND_LK(0x7105);
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7105 && a.rcode == 5);
        #undef SEND_LK
    }

    /* -- a caller that does not park (DoT, DoH: the engine looks the zone up itself): "not ready", not REFUSED */
    {
        uint8_t qb2[512], rb2[4096];
        size_t ql2 = build_query(qb2, 0x7401, true, 0);
        rcu_reader_enter(&wctx);
        zone_db_snapshot_t *sn = acquire_zone_snapshot();
        int rl2 = process_dns_query_cap(qb2, ql2, rb2, 1232, 0, "www.park.test.", 1, "127.0.0.1", &cc, false, NULL, sn);
        rcu_reader_exit(&wctx);
        CHECK(rl2 > 12 && rb2[0] == 0x74 && rb2[1] == 0x01 && (rb2[3] & 0x0F) == 2);
        bool found = false;                                                     /* the EDE option: code 15, a length, info code 14 */
        for (int i = 12; i + 6 <= rl2; i++) if (rb2[i] == 0 && rb2[i + 1] == 15 && rb2[i + 4] == 0 && rb2[i + 5] == 14) found = true;
        CHECK(found);
    }

    /* -- the request to fetch cannot be handed over (the ring is full): the query is not answered "not ready" for that; it stays parked, the request is marked pending and the
     *    worker makes it again, at every pass, until the ring has room (0.7: a full ring is never a SERVFAIL) */
    while (park_fetch_push(park_fetch_ring(0), "default", "other.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY)) {}
    SEND_QUERY(0x7101, true, 0);
    CHECK(w.n_tx == 0 && table.nwait == 1 && table.nunsent == 1 && !read_answer(sk[1]).got);
    park_service(&w, -1);                                                        /* (the ring is still full: it waits) */
    CHECK(w.n_tx == 0 && table.nwait == 1 && table.nunsent == 1 && !read_answer(sk[1]).got);
    while (park_fetch_pop(park_fetch_ring(0), &q)) {}                           /* (the ingest thread took them: there is room) */
    park_service(&w, -1);
    CHECK(table.nwait == 1 && table.nunsent == 0 && park_fetch_pop(park_fetch_ring(0), &q) && strcmp(q.zone, "park.test.") == 0 && q.prio == KDB_FETCH_PRIO_QUERY && !park_fetch_pop(park_fetch_ring(0), &q));
    (void)park_fail(&table, "default", "park.test.");                           /* (the fetch failed: the query is answered) */
    park_service(&w, -1);
    FLUSH();
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x7101 && a.rcode == 2 && a.ede == 14 && table.nwait == 0 && table.nfree == table.cap);

    /* -- a TSIG-signed request gets a signed "not ready" answer (RFC 8945 5.3: the key of the verified request, the request's MAC): the same
     *    handling as every other answer of the engine */
    {
        tsig_key_t *k1 = NULL;
        for (tsig_key_t *k = cfg.keys; k; k = k->next) if (strcmp(k->name, "k1") == 0) k1 = k;
        CHECK(k1 != NULL);
        w.park = NULL;
        uint8_t *qb = rx + sizeof(udp_ipc_t);
        size_t ql = build_query(qb, 0x7201, true, 0), sl = ql;
        CHECK(k1 && tsig_sign_packet(qb, &sl, 2000, k1, 0, NULL, NULL, NULL, 0, false) == 0);
        uint8_t req_copy[2048], req_mac[64], resp_mac[64];
        size_t req_mac_len = 0, resp_mac_len = 0;
        memcpy(req_copy, qb, sl);
        CHECK(k1 && tsig_verify_packet(req_copy, sl, k1, NULL, 0, NULL, 0, false, req_mac, &req_mac_len) == 0);
        mk_ipc((udp_ipc_t *)rx, 7, sl);
        w.n_tx = 0;
        udp_one(&w, (udp_ipc_t *)rx, qb, (ssize_t)sl);
        CHECK(w.n_tx == 1);
        FLUSH();
        uint8_t raw[sizeof(udp_ipc_t) + 4096];
        struct pollfd pf = { sk[1], POLLIN, 0 };
        ssize_t rn = poll(&pf, 1, 1000) > 0 ? recv(sk[1], raw, sizeof(raw), MSG_PEEK) : -1;
        CHECK(rn > (ssize_t)sizeof(udp_ipc_t) + 12);
        tsig_rr_t trr;
        const uint8_t *rm = raw + sizeof(udp_ipc_t);
        size_t rml = rn > (ssize_t)sizeof(udp_ipc_t) ? (size_t)rn - sizeof(udp_ipc_t) : 0;
        CHECK(rml > 0 && tsig_parse_rr(rm, rml, &trr) == 1 && strcasecmp(trr.key_name, "k1.") == 0);
        CHECK(rml > 0 && k1 && tsig_verify_packet(rm, rml, k1, req_mac, req_mac_len, NULL, 0, false, resp_mac, &resp_mac_len) == 0);
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7201 && a.rcode == 2 && a.ede == 14);
        /* a request with a wrong MAC is NOTAUTH, not "not ready" (the TSIG is checked first, RFC 8945 5.2) */
        sl = build_query(qb, 0x7202, true, 0);
        CHECK(k1 && tsig_sign_packet(qb, &sl, 2000, k1, 0, NULL, NULL, NULL, 0, false) == 0);
        qb[sl - 10] ^= 0x55;                                           /* (inside the MAC) */
        mk_ipc((udp_ipc_t *)rx, 7, sl);
        w.n_tx = 0;
        udp_one(&w, (udp_ipc_t *)rx, qb, (ssize_t)sl);
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7202 && a.rcode == 9);
        /* RFC 8945 5.3.2: BADTIME is answered NOTAUTH with a TSIG that IS signed (the server's time in Other Data); BADKEY is unsigned (MAC size
         * 0).  The same engine path decides for the "not ready" answer as for every other. */
        {
            tsig_sign_times_t tt = { (uint64_t)time(NULL) - 7200, 300 };      /* two hours ago: outside the fudge */
            sl = build_query(qb, 0x7203, true, 0);
            CHECK(k1 && tsig_sign_packet_ex(qb, &sl, 2000, k1, 0, NULL, NULL, NULL, 0, false, &tt) == 0);
            mk_ipc((udp_ipc_t *)rx, 7, sl);
            w.n_tx = 0;
            udp_one(&w, (udp_ipc_t *)rx, qb, (ssize_t)sl);
            FLUSH();
            struct pollfd pf2 = { sk[1], POLLIN, 0 };
            rn = poll(&pf2, 1, 1000) > 0 ? recv(sk[1], raw, sizeof(raw), MSG_PEEK) : -1;
            rm = raw + sizeof(udp_ipc_t);
            rml = rn > (ssize_t)sizeof(udp_ipc_t) ? (size_t)rn - sizeof(udp_ipc_t) : 0;
            CHECK(rml > 0 && tsig_parse_rr(rm, rml, &trr) == 1 && trr.error == 18 && trr.mac_size > 0 && trr.other_len == 6);
            a = read_answer(sk[1]);
            CHECK(a.got && a.id == 0x7203 && a.rcode == 9);
            /* BADKEY: a key the server does not have */
            tsig_key_t bad;
            memcpy(&bad, k1, sizeof(bad));
            bad.name = (char *)"nokey.";
            sl = build_query(qb, 0x7204, true, 0);
            CHECK(tsig_sign_packet(qb, &sl, 2000, &bad, 0, NULL, NULL, NULL, 0, false) == 0);
            mk_ipc((udp_ipc_t *)rx, 7, sl);
            w.n_tx = 0;
            udp_one(&w, (udp_ipc_t *)rx, qb, (ssize_t)sl);
            FLUSH();
            struct pollfd pf3 = { sk[1], POLLIN, 0 };
            rn = poll(&pf3, 1, 1000) > 0 ? recv(sk[1], raw, sizeof(raw), MSG_PEEK) : -1;
            rm = raw + sizeof(udp_ipc_t);
            rml = rn > (ssize_t)sizeof(udp_ipc_t) ? (size_t)rn - sizeof(udp_ipc_t) : 0;
            CHECK(rml > 0 && tsig_parse_rr(rm, rml, &trr) == 1 && trr.error == 17 && trr.mac_size == 0);
            a = read_answer(sk[1]);
            CHECK(a.got && a.id == 0x7204 && a.rcode == 9);
        }
    }

    /* -- the answer is counted by response rate limiting like any error answer: the same request again and again from one address is cut
     *    off (slip 0: dropped) */
    {
        static server_config_t cfg2;
        char conf2[1400];
        snprintf(conf2, sizeof(conf2), "options { directory \"%s\"; rate-limit { responses-per-second 1; errors-per-second 1; window 1; slip 0; }; };\n"
                 "view \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; }; };\n", dir, zf);
        CHECK(parse_named_conf(conf2, &cfg2) == 0);
        cfg2.send_extended_errors = true;
        atomic_store_explicit(&g_config_db.active, &cfg2, memory_order_release);
        int answered = 0;
        for (int i = 0; i < 12; i++) {
            SEND_QUERY(0x7300 + i, true, 0);
            answered += w.n_tx;
            FLUSH();
        }
        CHECK(answered >= 1 && answered < 12);
        while (read_answer(sk[1]).got) {}
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    }

    /* -- allow-query is evaluated BEFORE the query parks or the zone is asked for: a client that may not ask gets REFUSED + EDE 18 as for a zone
     *    in memory, occupies no entry of the park table, makes no fetch request and does not count for the zone's frequency; the same on the path
     *    that does not park (DoT, DoH: the engine looks the zone up itself); a client that may ask still parks */
    {
        static server_config_t cfg3, cfg4;
        char conf3[1600];
        w.park = &table;
        for (int k = 0; k < 2; k++) {
            snprintf(conf3, sizeof(conf3), "options { directory \"%s\"; allow-query { %s; }; };\n"
                     "view \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; }; };\n", dir,
                     k == 0 ? "192.0.2.99" : "127.0.0.1", zf);
            server_config_t *c = k == 0 ? &cfg3 : &cfg4;
            CHECK(parse_named_conf(conf3, c) == 0);
            c->send_extended_errors = true;
        }
        atomic_store_explicit(&g_config_db.active, &cfg3, memory_order_release);
        uint32_t f0 = atomic_load(&el->freq);
        SEND_QUERY(0x7501, true, 0);
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7501 && a.rcode == 5 && a.ede == 18);
        CHECK(atomic_load(&el->freq) == f0);
        uint8_t qb3[512], rb3[4096];
        size_t ql3 = build_query(qb3, 0x7502, true, 0);
        rcu_reader_enter(&wctx);
        zone_db_snapshot_t *sn3 = acquire_zone_snapshot();
        int rl3 = process_dns_query_cap(qb3, ql3, rb3, 1232, 0, "www.park.test.", 1, "127.0.0.1", &cc, false, NULL, sn3);
        rcu_reader_exit(&wctx);
        CHECK(rl3 > 12 && (rb3[3] & 0x0F) == 5);
        atomic_store_explicit(&g_config_db.active, &cfg4, memory_order_release);
        SEND_QUERY(0x7503, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q) && atomic_load(&el->freq) == f0 + 1);
        CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", true));
        park_service(&w, -1);
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7503 && a.rcode == 2 && a.ede == 14 && table.nwait == 0);
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    }

    /* -- NOTIFY and UPDATE for a zone that is out of memory (until the transfer / UPDATE step of D1 they neither park nor ask for the zone nor count
     *    for its frequency): NOTIFY is REFUSED as for a primary zone; UPDATE is checked (SOA question, the apex, allow-update from the settings
     *    kept in the element): REFUSED without allow-update, NOTAUTH for a name that is not the apex, SERVFAIL + EDE 14 where it may be made */
    {
        w.park = &table;
        uint32_t f1 = atomic_load(&el->freq);
        #define OPQ(id, opcode, name) do { size_t ql_ = build_op(rx + sizeof(udp_ipc_t), (id), (opcode), (name)); mk_ipc((udp_ipc_t *)rx, 7, ql_); \
            w.n_tx = 0; udp_one(&w, (udp_ipc_t *)rx, rx + sizeof(udp_ipc_t), (ssize_t)ql_); } while (0)
        OPQ(0x7601, 4, "park.test");
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7601 && a.rcode == 5);
        OPQ(0x7602, 5, "park.test");
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7602 && a.rcode == 5);                  /* (no allow-update: REFUSED) */
        static const char ust[] = "allow-update { 127.0.0.1; };";
        zone_ext_shared_t *ush = db_settings_parse(ust, strlen(ust), NULL, 0);
        CHECK(ush != NULL);
        atomic_store(&el->sh, ush);
        /* (a database zone's allow-update also needs the database's acl-ceiling to let the client in, dns_tsig_acl.c) */
        static server_config_t cfg5;
        char conf5[1600];
        snprintf(conf5, sizeof(conf5), "options { directory \"%s\"; database { driver sqlite3; database-file \"/x.db\"; acl-ceiling { 127.0.0.1; }; }; };\n"
                 "view \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; }; };\n", dir, zf);
        CHECK(parse_named_conf(conf5, &cfg5) == 0);
        cfg5.send_extended_errors = true;
        atomic_store_explicit(&g_config_db.active, &cfg5, memory_order_release);
        OPQ(0x7603, 5, "park.test");
        /* D1a milestone 4: an UPDATE that may be made waits for the zone like a query (parked, the zone is asked for) and is applied when it is there;
         * it does not count for the zone's frequency.  When the read fails it is answered SERVFAIL (the query has no OPT, so no EDE) */
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q) && atomic_load(&el->freq) == f1);
        CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", true));
        park_service(&w, -1);
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7603 && a.rcode == 2 && table.nwait == 0);
        OPQ(0x7604, 5, "x.park.test");
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7604 && a.rcode == 9);                  /* (not the apex: NOTAUTH) */
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        atomic_store(&el->sh, NULL);
        zone_ext_shared_unref(ush);
        CHECK(atomic_load(&el->freq) == f1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
    }

    /* -- D1a review 7c: an IXFR over UDP (RFC 1995 4.2) is a zone transfer question.  allow-transfer decides, for a zone in memory and for one that is out of memory:
     *    a client that may not transfer is REFUSED (EDE 18) without a fetch, a parked query or a count for the zone's frequency; one that may gets the one SOA from the
     *    summary (TC when it is behind) without the zone being read, byte for byte what the zone in memory answers; without a usable apex it waits for the zone like
     *    any query; a request without the client's SOA is FORMERR */
    {
        w.park = &table;
        uint32_t f2 = atomic_load(&el->freq);
        #define IXQ(id, serial, nosoa) do { size_t ql_ = build_ixfr(rx + sizeof(udp_ipc_t), (id), (serial), (nosoa)); mk_ipc((udp_ipc_t *)rx, 7, ql_); \
            w.n_tx = 0; udp_one(&w, (udp_ipc_t *)rx, rx + sizeof(udp_ipc_t), (ssize_t)ql_); } while (0)
        static server_config_t cfgD, cfgA;
        char confx[1600];
        snprintf(confx, sizeof(confx), "options { directory \"%s\"; };\nview \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; }; };\n", dir, zf);
        CHECK(parse_named_conf(confx, &cfgD) == 0);
        snprintf(confx, sizeof(confx), "options { directory \"%s\"; };\nview \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; allow-transfer { 127.0.0.1; }; }; };\n", dir, zf);
        CHECK(parse_named_conf(confx, &cfgA) == 0);
        cfgD.send_extended_errors = cfgA.send_extended_errors = true;
        /* the zone in memory, with and without allow-transfer: the answers to compare with */
        atomic_store(&el->entry, entry);
        atomic_store(&el->state, ZDIR_ST_RESIDENT);
        uint8_t res_up[4096], res_tc[4096];
        size_t res_up_len = 0, res_tc_len = 0;
        atomic_store_explicit(&g_config_db.active, &cfgD, memory_order_release);
        rebuild_zone_db_from_config(&cfgD, false);
        el = the_elem();
        entry = zdir_entry(el);
        IXQ(0x7801, 1, false); FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7801 && a.rcode == 5 && a.ede == 18 && a.ancount == 0);          /* (a zone in memory: REFUSED without allow-transfer) */
        atomic_store_explicit(&g_config_db.active, &cfgA, memory_order_release);
        rebuild_zone_db_from_config(&cfgA, false);
        el = the_elem();
        entry = zdir_entry(el);
        IXQ(0x7802, 1, false); FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 0 && a.ancount == 1 && !(g_raw[2] & 0x02));                   /* up to date: the one SOA, no TC */
        memcpy(res_up, g_raw, g_raw_len); res_up_len = g_raw_len;
        IXQ(0x7803, 0, false); FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 0 && a.ancount == 1 && (g_raw[2] & 0x02));                    /* behind: the one SOA and TC */
        memcpy(res_tc, g_raw, g_raw_len); res_tc_len = g_raw_len;
        IXQ(0x7804, 0, true); FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 1);                                                            /* (no SOA of the client: FORMERR) */
        /* the zone out of memory: the same, from the apex of its summary */
        uint8_t nm_wire[] = { 2, 'n', 's', 4, 'p', 'a', 'r', 'k', 4, 't', 'e', 's', 't', 0, 1, 'h', 4, 'p', 'a', 'r', 'k', 4, 't', 'e', 's', 't', 0 };
        zdir_apex_t *iap = calloc(1, sizeof(*iap) + sizeof(nm_wire) + 20);
        iap->serial = 1; iap->soa_ttl = 300; iap->refresh = 7200; iap->retry = 3600; iap->expire = 1209600; iap->minimum = 300; iap->ns_ttl = 300;
        iap->mname_len = 14; iap->rname_len = 13; iap->ns_len = 14; iap->n_ns = 1;
        memcpy(iap->data, nm_wire, 14 + 13);
        memcpy(iap->data + 27, nm_wire, 14);
        atomic_store(&el->serial, 1);
        atomic_store(&el->apex, iap);
        atomic_store(&el->entry, NULL);
        atomic_store(&el->state, ZDIR_ST_ABSENT);
        atomic_store_explicit(&g_config_db.active, &cfgD, memory_order_release);
        static const char tst[] = "";
        (void)tst;
        f2 = atomic_load(&el->freq);
        IXQ(0x7811, 1, false);
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7811 && a.rcode == 5 && a.ede == 18 && a.ancount == 0 && atomic_load(&el->freq) == f2);   /* (REFUSED: no allow-transfer, nothing parked or asked for) */
        /* allowed: the settings kept in the element (a database zone's allow-transfer needs the ceiling of the database block as well) */
        static const char ast[] = "allow-transfer { 127.0.0.1; };";
        zone_ext_shared_t *ash = db_settings_parse(ast, strlen(ast), NULL, 0);
        CHECK(ash != NULL);
        atomic_store(&el->sh, ash);
        static server_config_t cfgC;
        snprintf(confx, sizeof(confx), "options { directory \"%s\"; database { driver sqlite3; database-file \"/x.db\"; acl-ceiling { 127.0.0.1; }; }; };\n"
                 "view \"default\" { match-clients { any; }; zone \"park.test\" { type master; file \"%s\"; }; };\n", dir, zf);
        CHECK(parse_named_conf(confx, &cfgC) == 0);
        cfgC.send_extended_errors = true;
        atomic_store_explicit(&g_config_db.active, &cfgC, memory_order_release);
        IXQ(0x7802, 1, false);
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 0 && a.ancount == 1 && g_raw_len == res_up_len && memcmp(g_raw, res_up, res_up_len) == 0);        /* (the bytes of the zone in memory) */
        IXQ(0x7803, 0, false);
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 0 && a.ancount == 1 && (g_raw[2] & 0x02) && g_raw_len == res_tc_len && memcmp(g_raw, res_tc, res_tc_len) == 0);
        IXQ(0x7812, 9, false); FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 0 && a.ancount == 1 && !(g_raw[2] & 0x02) && table.nwait == 0);          /* (a client that is ahead: up to date) */
        IXQ(0x7804, 0, true); FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));        /* (no SOA of the client: FORMERR, nothing asked for) */
        /* the apex describes another version than the directory has: the zone is waited for (an allowed client) */
        atomic_store(&el->serial, 5);
        IXQ(0x7813, 1, false);
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q));
        CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", true));
        park_service(&w, -1);
        FLUSH(); a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7813 && a.rcode == 2 && table.nwait == 0);
        atomic_store(&el->serial, 1);
        atomic_store(&el->apex, NULL);
        free(iap);
        atomic_store(&el->sh, NULL);
        zone_ext_shared_unref(ash);
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        rebuild_zone_db_from_config(&cfg, false);
        el = the_elem();
        entry = zdir_entry(el);
        atomic_store(&el->entry, NULL);
        atomic_store(&el->state, ZDIR_ST_ABSENT);
        #undef IXQ
    }

    /* -- D1a step 8 (design 5): a CNAME chain and the glue of a name server lead into a zone of the view that is in the directory and not in memory.  The answer
     *    is what it is without it (the chain stops at the CNAME: RFC 1034 4.3.2; no glue: RFC 9471 3.2) and the zone is asked for in the background once, through
     *    the hook of the engine (no waiting, no I/O); a zone that is in memory (or not in the directory) asks for nothing; the chain is whole when the zone is back */
    {
        char xz[300], oz[300], confb[1800];
        snprintf(xz, sizeof(xz), "%s/x.test.zone", dir);
        snprintf(oz, sizeof(oz), "%s/other.test.zone", dir);
        FILE *fx = fopen(xz, "w");
        CHECK(fx != NULL);
        fputs("$ORIGIN x.test.\n$TTL 300\n@ IN SOA ns.x.test. h.x.test. 1 7200 3600 1209600 300\n@ IN NS ns1.other.test.\ncn IN CNAME h.other.test.\next IN CNAME h.unknown.example.\n", fx);
        fclose(fx);
        FILE *fo = fopen(oz, "w");
        CHECK(fo != NULL);
        fputs("$ORIGIN other.test.\n$TTL 300\n@ IN SOA ns1.other.test. h.other.test. 1 7200 3600 1209600 300\n@ IN NS ns1.other.test.\nns1 IN A 192.0.2.53\nh IN A 192.0.2.99\n", fo);
        fclose(fo);
        snprintf(confb, sizeof(confb), "options { directory \"%s\"; };\nview \"default\" { match-clients { any; }; zone \"x.test\" { type master; file \"%s\"; }; "
                 "zone \"other.test\" { type master; file \"%s\"; }; };\n", dir, xz, oz);
        static server_config_t cfgB;
        CHECK(parse_named_conf(confb, &cfgB) == 0);
        cfgB.send_extended_errors = true;
        atomic_store_explicit(&g_config_db.active, &cfgB, memory_order_release);
        rebuild_zone_db_from_config(&cfgB, false);
        zone_db_snapshot_t *snb = acquire_retained_zone_snapshot();
        zdir_elem_t *oel = zdir_find_exact(snapshot_find_view(snb, "default"), "other.test.");
        release_zone_snapshot(snb);
        CHECK(oel != NULL && zdir_entry(oel) != NULL);
        zone_db_entry_t *oentry = zdir_entry(oel);
        void (*old_hook)(const char *, const char *) = g_query_bg_fetch;
        g_query_bg_fetch = test_bg_hook;
        #define ASK(name, qt, out, outlen) do { uint8_t qb_[512]; size_t ql_ = build_q(qb_, 0x7901, (name), (qt)); \
            rcu_reader_enter(&wctx); zone_db_snapshot_t *sn_ = acquire_zone_snapshot(); \
            (outlen) = process_dns_query_cap(qb_, ql_, (out), 1232, 0, (name), (qt), "127.0.0.1", &cc, false, NULL, sn_); \
            rcu_reader_exit(&wctx); } while (0)
        uint8_t rb[4096];
        int rl;
        uint16_t ty[3][8];
        int cn[3];
        /* the zone is in memory: the whole chain, nothing asked for */
        g_bg_calls = 0;
        ASK("cn.x.test", 1, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(rl > 12 && cn[0] == 2 && ty[0][0] == 5 && ty[0][1] == 1 && g_bg_calls == 0);
        ASK("x.test", 2, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(cn[0] == 1 && ty[0][0] == 2 && cn[2] == 1 && ty[2][0] == 1 && g_bg_calls == 0);            /* (the NS with its glue from the sibling) */
        /* the zone is out of memory */
        atomic_store(&oel->entry, NULL);
        atomic_store(&oel->state, ZDIR_ST_ABSENT);
        ASK("cn.x.test", 1, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(rl > 12 && (rb[3] & 0x0F) == 0 && cn[0] == 1 && ty[0][0] == 5);                            /* the CNAME alone */
        CHECK(g_bg_calls == 1 && strcmp(g_bg_view, "default") == 0 && strcmp(g_bg_zone, "other.test.") == 0);
        ASK("x.test", 2, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(cn[0] == 1 && ty[0][0] == 2 && cn[2] == 0 && g_bg_calls == 2);                             /* the NS without its glue */
        ASK("ext.x.test", 1, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(cn[0] == 1 && ty[0][0] == 5 && g_bg_calls == 2);                                            /* (a chain out of every zone of the view asks for nothing) */
        /* a fetch is on its way (LOADING) or the zone has no usable version (ERROR): not asked for */
        atomic_store(&oel->state, ZDIR_ST_LOADING);
        ASK("cn.x.test", 1, rb, rl);
        atomic_store(&oel->state, ZDIR_ST_ERROR);
        ASK("cn.x.test", 1, rb, rl);
        CHECK(g_bg_calls == 2);
        /* the zone is back: the whole chain, the glue */
        atomic_store(&oel->state, ZDIR_ST_RESIDENT);
        atomic_store(&oel->entry, oentry);
        ASK("cn.x.test", 1, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(cn[0] == 2 && ty[0][0] == 5 && ty[0][1] == 1 && g_bg_calls == 2);
        ASK("x.test", 2, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(cn[0] == 1 && cn[2] == 1 && g_bg_calls == 2);
        /* without a hook (the engine on its own) the partial answer is the same and nothing is asked */
        atomic_store(&oel->entry, NULL);
        atomic_store(&oel->state, ZDIR_ST_ABSENT);
        g_query_bg_fetch = NULL;
        ASK("cn.x.test", 1, rb, rl);
        rr_types(rb, (size_t)rl, ty, cn);
        CHECK(cn[0] == 1 && g_bg_calls == 2);
        atomic_store(&oel->state, ZDIR_ST_RESIDENT);
        atomic_store(&oel->entry, oentry);
        g_query_bg_fetch = old_hook;
        #undef ASK
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        rebuild_zone_db_from_config(&cfg, false);
        el = the_elem();
        entry = zdir_entry(el);
        atomic_store(&el->entry, NULL);
        atomic_store(&el->state, ZDIR_ST_ABSENT);
        unlink(xz);
        unlink(oz);
    }

    /* -- 0.7 P-B: the worker's gate.  With memory-limit set (dbreg_cache_limit() != 0) a query that is the first for a zone that is out of memory marks the zone as claimed
     *    (fetch_gate(), the UDP path of udp_one()) and parks and asks with PARK_PRIO_CLAIMED.  It is never refused for fetch-concurrency, fetch-rate or the memory limit: the
     *    ingest thread keeps the request waiting.  Every way out of udp_park() that does not end in a request on the ring clears the mark. */
    {
        printf("[the gate of the worker]\n");
        park_stats_t g0, g1;
        #define RNOW() ({ struct timespec ts_; clock_gettime(CLOCK_MONOTONIC, &ts_); (int64_t)ts_.tv_sec * 1000 + ts_.tv_nsec / 1000000; })
        dbreg_cache_set_limit(1ull << 40);                                  /* (a limit that the zones in memory do not reach) */
        park_places_set_limit(2);
        park_rate_set(0);
        park_rate_reset();
        atomic_store(&el->entry, NULL);
        atomic_store(&el->state, ZDIR_ST_ABSENT);
        while (park_fetch_pop(park_fetch_ring(0), &q)) {}
        CHECK(park_places_used() == 0 && table.nwait == 0 && table.nfree == table.cap);
        const uint64_t key = park_claim_key("default", "park.test.");

        /* the first query marks the zone and asks with the claim; a second for the same zone asks for nothing; neither takes a place or a token (the ingest thread does) */
        park_stats_get(&g0);
        SEND_QUERY(0x9001, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_places_used() == 0 && park_claim_held(key));
        CHECK(park_fetch_pop(park_fetch_ring(0), &q) && (q.prio & PARK_PRIO_CLAIMED) && (q.prio & 0x7F) == KDB_FETCH_PRIO_QUERY && q.mode == KDB_FETCH_FULL);
        SEND_QUERY(0x9002, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 2 && park_places_used() == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        /* the ingest thread (the test) clears the claim mark when it is done with the request, and wakes the queries */
        park_claim_clear(key);
        CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", true));
        park_service(&w, -1);
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 2 && a.ede == 14);
        a = read_answer(sk[1]);
        CHECK(a.got && a.rcode == 2 && a.ede == 14 && table.nwait == 0 && park_places_used() == 0);
        park_stats_get(&g1);
        CHECK(g1.full == g0.full && g1.ring_dropped == g0.ring_dropped);

        /* every place is taken (by fetches in flight) and the bucket is empty: the query is not refused, it parks and asks as any other (the request waits in the ingest thread) */
        CHECK(park_place_take() && park_place_take() && !park_place_avail());
        park_rate_set(1);
        park_rate_reset();
        CHECK(park_rate_take(RNOW(), false));
        SEND_QUERY(0x9101, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_places_used() == 2 && park_claim_held(key));
        CHECK(park_fetch_pop(park_fetch_ring(0), &q) && (q.prio & PARK_PRIO_CLAIMED) && (q.prio & 0x7F) == KDB_FETCH_PRIO_QUERY);
        CHECK(!park_rate_check(RNOW(), false));                              /* (the bucket was not touched) */
        park_claim_clear(key);
        (void)park_fail(&table, "default", "park.test.");
        {
            /* (done list: no cursor) */
            park_entry_t *pe;
            while ((pe = park_next_done(&table))) park_release(&table, pe);
        }
        park_place_give();
        park_place_give();
        park_rate_set(0);
        park_rate_reset();

        /* the park table is full: the query is dropped and counted (true overload), the mark goes back */
        {
            udp_ipc_t fi;
            memset(&fi, 0, sizeof(fi));
            uint8_t fp[32];
            memset(fp, 0, sizeof(fp));
            char fz[32];
            for (uint32_t i = 0; i < table.cap; i++) {
                snprintf(fz, sizeof(fz), "filler%u.test.", i);
                CHECK(park_udp(&table, 1, 100000, "default", fz, sk[0], &fi, fp, 20) >= 0);
            }
            const uint64_t zr0 = park_cnt_get(PARK_CNT_ZONE_ROOM);
            SEND_QUERY(0x9201, true, 0);
            CHECK(w.n_tx == 0 && table.nfree == 0 && !park_fetch_pop(park_fetch_ring(0), &q) && park_places_used() == 0 && !park_claim_held(key) && park_cnt_get(PARK_CNT_ZONE_ROOM) == zr0 + 1);
            FLUSH();
            a = read_answer(sk[1]);
            CHECK(!a.got);                                          /* (dropped, counted) */
            for (uint32_t i = 0; i < table.cap; i++) {
                snprintf(fz, sizeof(fz), "filler%u.test.", i);
                (void)park_fail(&table, "default", fz);
            }
            /* (done list: no cursor) */
            park_entry_t *pe;
            while ((pe = park_next_done(&table))) park_release(&table, pe);
            CHECK(table.nfree == table.cap);
        }

        /* the ring to the ingest thread is full: the query stays parked with its request pending, and the claim mark stays with it (the request is made again, with the claim); the mark
         * is given up when the entry is dropped without the request having been made */
        while (park_fetch_push(park_fetch_ring(0), "default", "other.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY)) {}
        park_stats_get(&g0);
        SEND_QUERY(0x9301, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 1 && table.nunsent == 1 && park_places_used() == 0 && park_claim_held(key));
        park_stats_get(&g1);
        CHECK(g1.ring_dropped - g0.ring_dropped == 1);
        {
            park_entry_t *pe = park_pending_head(&table);
            CHECK(pe && pe->pend == PARK_PEND_FETCH && (pe->prio & PARK_PRIO_CLAIMED));
            park_release(&table, pe);                                           /* (the query is gone before the request was made: the mark goes with it) */
            CHECK(table.nunsent == 0 && table.nwait == 0 && !park_claim_held(key));
        }
        while (park_fetch_pop(park_fetch_ring(0), &q)) {}

        /* the zone is LOADING (a fetch is on its way): no claim, and the query parks and asks the old way (the request is a duplicate for the ingest thread, and
         * a zone that arrived meanwhile is woken: no wake-up is lost) */
        atomic_store(&el->state, ZDIR_ST_LOADING);
        SEND_QUERY(0x9501, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_places_used() == 0 && !park_claim_held(key));
        CHECK(park_fetch_pop(park_fetch_ring(0), &q) && !(q.prio & PARK_PRIO_CLAIMED) && q.prio == KDB_FETCH_PRIO_QUERY);
        (void)park_fail(&table, "default", "park.test.");
        {
            /* (done list: no cursor) */
            park_entry_t *pe;
            while ((pe = park_next_done(&table))) park_release(&table, pe);
        }
        atomic_store(&el->state, ZDIR_ST_ABSENT);

        /* no memory-limit: no claim at all (nothing is queued, the ingest thread's old way) */
        dbreg_cache_set_limit(0);
        SEND_QUERY(0x9601, true, 0);
        CHECK(w.n_tx == 0 && table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q) && !(q.prio & PARK_PRIO_CLAIMED) && !park_claim_held(key));
        (void)park_fail(&table, "default", "park.test.");
        {
            /* (done list: no cursor) */
            park_entry_t *pe;
            while ((pe = park_next_done(&table))) park_release(&table, pe);
        }

        /* fetch_gate() itself: the zone out of memory is ABSENT; the results */
        dbreg_cache_set_limit(1ull << 40);
        CHECK(fetch_gate("default", el) == FETCH_GATE_TAKEN && park_claim_held(key) && park_places_used() == 0);
        park_claim_release("default", el->name);
        CHECK(!park_claim_held(key));
        atomic_store(&el->state, ZDIR_ST_ERROR);
        CHECK(fetch_gate("default", el) == FETCH_GATE_ASK && !park_claim_held(key));   /* (ERROR: the ingest thread answers it) */
        atomic_store(&el->state, ZDIR_ST_ABSENT);
        /* (B2 M1) the zone is claimed: the next worker asks without a claim, whatever the places say (the pool is full: still not a refusal); the claim of another view is a claim
         * of another zone; when the claim is released the next worker takes it */
        CHECK(fetch_gate("default", el) == FETCH_GATE_TAKEN);
        CHECK(fetch_gate("default", el) == FETCH_GATE_ASK && fetch_gate("default", el) == FETCH_GATE_ASK);
        CHECK(park_place_take() && park_place_take());
        CHECK(fetch_gate("default", el) == FETCH_GATE_ASK);
        CHECK(fetch_gate("other", el) == FETCH_GATE_TAKEN);                  /* (a zone of another view is not claimed; the full pool is no reason to refuse) */
        park_place_give();
        park_place_give();
        park_claim_release("other", el->name);
        park_claim_release("default", el->name);
        CHECK(park_places_used() == 0 && !park_claim_held(key));

        /* the database zones are over the hard limit (the test adds bytes to the database total: 1,000,000 against a limit of 100,000): the query is not refused, it is claimed,
         * parks and asks (the ingest thread makes room); the old refusal is gone */
        {
            park_places_set_limit(2);
            zone_bytes_resident_add(ZBYTES_DB, 1000000);
            dbreg_cache_set_limit(100000);
            CHECK(dbreg_cache_over_limit());
            CHECK(fetch_gate("default", el) == FETCH_GATE_TAKEN && park_claim_held(key));
            park_claim_release("default", el->name);
            SEND_QUERY(0xA002, true, 0);                                    /* (parked, one request with the claim, no answer now) */
            CHECK(w.n_tx == 0 && table.nwait == 1 && park_places_used() == 0 && park_claim_held(key));
            CHECK(park_fetch_pop(park_fetch_ring(0), &q) && (q.prio & PARK_PRIO_CLAIMED) && (q.prio & 0x7F) == KDB_FETCH_PRIO_QUERY && q.mode == KDB_FETCH_FULL);
            /* the ingest thread could not make room before the deadline: the query times out like any parked query (dropped, counted) */
            park_claim_clear(key);
            CHECK(park_expire(&table, RNOW() + 100000) == 1);
            park_service(&w, -1);
            FLUSH();
            a = read_answer(sk[1]);
            CHECK(!a.got && table.nwait == 0 && table.nfree == table.cap && park_places_used() == 0);
            zone_bytes_resident_add(ZBYTES_DB, -1000000);
            park_places_set_limit(1);
        }

        dbreg_cache_set_limit(0);
        park_places_set_limit(INT32_MAX);
        park_rate_set(0);
        park_rate_reset();
        while (park_fetch_pop(park_fetch_ring(0), &q)) {}
        CHECK(table.nwait == 0 && table.nready == 0 && table.nfree == table.cap);
    }

    /* -- nothing is parked and nobody said anything: park_service() returns at once (and with a key in the ring it does look) */
    w.park = &table;
    CHECK(table.nwait == 0 && table.nready == 0);
    park_service(&w, -1);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false) && park_wake_pending(park_wake_ring(0)));
    park_service(&w, -1);
    CHECK(!park_wake_pending(park_wake_ring(0)));

    park_unregister_worker(0);
    park_free(&table);
    atomic_store(&el->entry, entry);
    unlink(zf);
    rmdir(dir);
    test_steal_concurrent();
    gc_snapshot_wait_idle();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) return 1;
    printf("=== test_park_worker: all checks passed ===\n");
    return 0;
}

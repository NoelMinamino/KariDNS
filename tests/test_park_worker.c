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
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
    for (int k = 0; k < UDP_BATCH_SIZE; k++) {                       /* as the worker thread sets its batch up */
        memset(&batch->tx_msgs[k], 0, sizeof(batch->tx_msgs[k]));
        batch->tx_msgs[k].msg_hdr.msg_iov = &batch->tx_iov[k];
        batch->tx_msgs[k].msg_hdr.msg_iovlen = 1;
    }
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

    /* -- woken while the zone is still not there: parked again, with the deadline it had; nothing asked again */
    atomic_store(&el->entry, NULL);
    SEND_QUERY(0x3001, true, 0);
    CHECK(table.nwait == 1 && park_fetch_pop(park_fetch_ring(0), &q));
    int64_t d0 = park_next_deadline_ms(&table, 0);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
    park_service(&w, -1);
    CHECK(table.nwait == 1 && !park_fetch_pop(park_fetch_ring(0), &q) && !read_answer(sk[1]).got);
    CHECK(park_next_deadline_ms(&table, 0) == d0);
    atomic_store(&el->entry, entry);
    CHECK(park_wake_push(park_wake_ring(0), "default", "park.test.", false));
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x3001 && a.rcode == 0 && a.ancount == 1 && table.nwait == 0);

    /* -- the time is up: SERVFAIL + EDE 14, the question kept */
    atomic_store(&el->entry, NULL);
    w.park_timeout_ms = 5;
    SEND_QUERY(0x4001, true, 0);
    CHECK(table.nwait == 1);
    (void)park_fetch_pop(park_fetch_ring(0), &q);
    usleep(30000);
    park_service(&w, -1);
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x4001 && a.rcode == 2 && a.ancount == 0 && a.ede == 14 && table.nwait == 0);
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

    /* -- a request too big to park (more than PARK_UDP_MAX bytes), a full table, a worker without a park table: "not ready" at once */
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
    CHECK(w.n_tx == 1 && tiny.nwait == 1 && tiny.n_full == 1);
    FLUSH();
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x6003 && a.rcode == 2 && a.ede == 14);
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

    /* -- the request to fetch cannot be handed over (the ring is full): "not ready" at once, nothing stays parked that nobody would wake */
    while (park_fetch_push(park_fetch_ring(0), "default", "other.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY)) {}
    SEND_QUERY(0x7101, true, 0);
    CHECK(w.n_tx == 1 && table.nwait == 0 && table.nfree == table.cap);
    FLUSH();
    a = read_answer(sk[1]);
    CHECK(a.got && a.id == 0x7101 && a.rcode == 2 && a.ede == 14);
    while (park_fetch_pop(park_fetch_ring(0), &q)) {}

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
        CHECK(w.n_tx == 1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7603 && a.rcode == 2);                  /* (allowed: SERVFAIL, nothing read; the query has no OPT, so no EDE) */
        OPQ(0x7604, 5, "x.park.test");
        FLUSH();
        a = read_answer(sk[1]);
        CHECK(a.got && a.id == 0x7604 && a.rcode == 9);                  /* (not the apex: NOTAUTH) */
        atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
        atomic_store(&el->sh, NULL);
        zone_ext_shared_unref(ush);
        CHECK(atomic_load(&el->freq) == f1 && table.nwait == 0 && !park_fetch_pop(park_fetch_ring(0), &q));
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
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) return 1;
    printf("=== test_park_worker: all checks passed ===\n");
    return 0;
}

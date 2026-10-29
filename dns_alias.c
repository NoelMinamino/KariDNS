/*
 * dns_alias.c - PowerDNS ALIAS expansion (beta design 3.6b, milestone B9a).  The design is in dns_alias.h.
 */
#include "dns_alias.h"
#include "dns_server_internal.h"
#include "dns_epoch_rcu.h"
#include "dns_zone_image.h"

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "dns_log.h"
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* milliseconds left until `deadline` (monotonic_ms()), 0 when it has passed */
static uint32_t remaining_ms(int64_t deadline) {
    int64_t d = deadline - monotonic_ms();
    return d > 0 ? (d > 0x7FFFFFFF ? 0x7FFFFFFFu : (uint32_t)d) : 0;
}

/* exactly len octets from fd within timeout_ms (poll + recv); the number read, short on timeout or error */
static ssize_t read_all_timeout(int fd, uint8_t *buf, size_t len, uint32_t timeout_ms) {
    int64_t deadline = monotonic_ms() + timeout_ms;
    size_t got = 0;
    while (got < len) {
        uint32_t rem = remaining_ms(deadline);
        if (rem == 0) break;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, (int)rem);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) break;
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

int64_t (*g_alias_now_hook)(void) = NULL;
alias_resolve_fn g_alias_resolve_hook = NULL;

static int64_t alias_now(void) {
    if (g_alias_now_hook) return g_alias_now_hook();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* configuration: which resolvers apply to a zone                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    const char *ip;
    int port;
} rs_ent_t;

static int rs_collect(const server_config_t *cfg, const zone_config_t *zcfg, bool db_zone, rs_ent_t *out) {
    const zone_ext_t *x = zext(zcfg);
    int n = 0;
    if (x->alias_resolvers_count > 0 && x->alias_resolvers) {
        for (int i = 0; i < x->alias_resolvers_count && n < ALIAS_MAX_RESOLVERS; i++) {
            out[n].ip = x->alias_resolvers[i].ip;
            out[n++].port = x->alias_resolvers[i].port;
        }
    } else if (cfg && cfg->alias_resolvers_count > 0 && cfg->alias_resolvers) {
        for (int i = 0; i < cfg->alias_resolvers_count && n < ALIAS_MAX_RESOLVERS; i++) {
            out[n].ip = cfg->alias_resolvers[i].ip;
            out[n++].port = cfg->alias_resolvers[i].port;
        }
    } else if (db_zone && cfg && cfg->database.enabled && cfg->database.alias_resolver_count > 0 && cfg->database.alias_resolver) {
        for (int i = 0; i < cfg->database.alias_resolver_count && n < ALIAS_MAX_RESOLVERS; i++) {
            out[n].ip = cfg->database.alias_resolver[i];
            out[n++].port = 53;
        }
    }
    int m = 0;                                  /* an entry without text cannot be used */
    for (int i = 0; i < n; i++)
        if (out[i].ip) out[m++] = out[i];
    return m;
}

static uint64_t fnv64(uint64_t h, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t rs_key(const rs_ent_t *e, int n) {
    if (n == 0) return 0;
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) {
        h = fnv64(h, e[i].ip, strlen(e[i].ip) + 1);
        h = fnv64(h, &e[i].port, sizeof(e[i].port));
    }
    return h ? h : 1;
}

uint64_t alias_resolvers_key(const server_config_t *cfg, const zone_config_t *zcfg, bool db_zone) {
    rs_ent_t e[ALIAS_MAX_RESOLVERS];
    return rs_key(e, rs_collect(cfg, zcfg, db_zone, e));
}

int alias_resolvers_fill(const server_config_t *cfg, const zone_config_t *zcfg, bool db_zone, alias_rset_t *out) {
    rs_ent_t e[ALIAS_MAX_RESOLVERS];
    int n = rs_collect(cfg, zcfg, db_zone, e);
    memset(out, 0, sizeof(*out));
    out->key = rs_key(e, n);
    for (int i = 0; i < n; i++) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&out->sa[out->n];
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&out->sa[out->n];
        int port = e[i].port > 0 && e[i].port <= 65535 ? e[i].port : 53;
        if (inet_pton(AF_INET, e[i].ip, &s4->sin_addr) == 1) {
            s4->sin_family = AF_INET;
            s4->sin_port = htons((uint16_t)port);
            out->sl[out->n++] = sizeof(*s4);
        } else if (inet_pton(AF_INET6, e[i].ip, &s6->sin6_addr) == 1) {
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons((uint16_t)port);
            out->sl[out->n++] = sizeof(*s6);
        } else {
            memset(&out->sa[out->n], 0, sizeof(out->sa[out->n]));
        }
    }
    return out->n;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* wire format helpers                                                                                             */
/* ------------------------------------------------------------------------------------------------------------- */

static inline uint8_t lc(uint8_t c) { return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c; }

/* One uncompressed name at the start of p[0..len): its length in *used (RFC 1035 section 3.1: labels up to 63, the name up to 255) */
static bool wire_name_valid(const uint8_t *p, size_t len, size_t *used) {
    size_t i = 0;
    for (;;) {
        if (i >= len) return false;
        uint8_t l = p[i++];
        if (l == 0) {
            *used = i;
            return i <= 255;
        }
        if (l > 63 || len - i < l) return false;
        i += l;
        if (i > 254) return false;
    }
}

bool alias_wire_lower(const uint8_t *rdata, size_t rdlen, uint8_t *out, size_t *outlen) {
    size_t used;
    if (!rdata || !wire_name_valid(rdata, rdlen, &used) || used != rdlen) return false;
    for (size_t i = 0; i < rdlen;) {              /* length octets are < 64 and stay as they are; label octets are folded */
        uint8_t l = rdata[i];
        out[i++] = l;
        for (uint8_t k = 0; k < l; k++, i++) out[i] = lc(rdata[i]);
    }
    *outlen = rdlen;
    return true;
}

/* The name at `off` of a message (compression allowed, RFC 1035 section 4.1.4) as a lower case uncompressed name.  A pointer must go
 * backwards (to a "prior occurrence"), which also ends every loop.  Returns the length, -1 on a malformed name; *next is the offset
 * after the name where it started. */
static int pkt_name(const uint8_t *pkt, size_t len, size_t off, uint8_t out[256], size_t *next) {
    size_t o = off, n = 0;
    bool jumped = false;
    for (;;) {
        if (o >= len) return -1;
        uint8_t l = pkt[o];
        if ((l & 0xC0) == 0xC0) {
            if (o + 1 >= len) return -1;
            size_t ptr = (size_t)((l & 0x3F) << 8) | pkt[o + 1];
            if (!jumped) {
                *next = o + 2;
                jumped = true;
            }
            if (ptr >= o) return -1;
            o = ptr;
            continue;
        }
        if (l & 0xC0) return -1;                  /* 01 and 10 label types are not valid (RFC 6891 section 7 retired the extended label) */
        o++;
        if (l == 0) {
            if (n + 1 > 255) return -1;
            out[n++] = 0;
            if (!jumped) *next = o;
            return (int)n;
        }
        if (o + l > len || n + 1 + l + 1 > 255) return -1;
        out[n++] = l;
        for (uint8_t i = 0; i < l; i++) out[n++] = lc(pkt[o + i]);
        o += l;
    }
}

size_t alias_build_query(uint8_t *buf, size_t cap, uint16_t id, const uint8_t *name, size_t nlen, uint16_t qtype) {
    if (nlen == 0 || nlen > 255 || cap < 12 + nlen + 4 + 11) return 0;
    size_t o = 0;
    buf[o++] = (uint8_t)(id >> 8);
    buf[o++] = (uint8_t)id;
    buf[o++] = 0x01;                              /* RD: the resolver recurses (PowerDNS asks the same) */
    buf[o++] = 0x00;
    buf[o++] = 0; buf[o++] = 1;                   /* QDCOUNT */
    buf[o++] = 0; buf[o++] = 0;
    buf[o++] = 0; buf[o++] = 0;
    buf[o++] = 0; buf[o++] = 1;                   /* ARCOUNT: the OPT RR */
    memcpy(buf + o, name, nlen);
    o += nlen;
    buf[o++] = (uint8_t)(qtype >> 8);
    buf[o++] = (uint8_t)qtype;
    buf[o++] = 0; buf[o++] = 1;                   /* IN */
    buf[o++] = 0;                                 /* OPT: root owner, TYPE 41, UDP payload 1232, no extended RCODE / flags (RFC 6891) */
    buf[o++] = 0; buf[o++] = 41;
    buf[o++] = 0x04; buf[o++] = 0xD0;
    buf[o++] = 0; buf[o++] = 0; buf[o++] = 0; buf[o++] = 0;
    buf[o++] = 0; buf[o++] = 0;
    return o;
}

/* walk one RR at *off: owner (lower case), type, class, ttl, RDATA offset and length.  false on a malformed RR or the end of the message */
typedef struct {
    uint8_t owner[256];
    int olen;
    uint16_t type, cls;
    uint32_t ttl;
    size_t rd_off, rdlen;
} rr_t;

static bool next_rr(const uint8_t *pkt, size_t len, size_t *off, rr_t *r) {
    size_t nx;
    r->olen = pkt_name(pkt, len, *off, r->owner, &nx);
    if (r->olen < 0 || nx + 10 > len) return false;
    r->type = (uint16_t)((pkt[nx] << 8) | pkt[nx + 1]);
    r->cls = (uint16_t)((pkt[nx + 2] << 8) | pkt[nx + 3]);
    r->ttl = ((uint32_t)pkt[nx + 4] << 24) | ((uint32_t)pkt[nx + 5] << 16) | ((uint32_t)pkt[nx + 6] << 8) | pkt[nx + 7];
    r->rdlen = (size_t)((pkt[nx + 8] << 8) | pkt[nx + 9]);
    r->rd_off = nx + 10;
    if (r->rd_off + r->rdlen > len) return false;
    *off = r->rd_off + r->rdlen;
    return true;
}

void alias_parse_response(const uint8_t *pkt, size_t len, uint16_t id, const uint8_t *name, size_t nlen, uint16_t qtype,
                          alias_parsed_t *out) {
    memset(out, 0, sizeof(*out));
    out->rc = -1;
    if (len < 12) return;
    if ((uint16_t)((pkt[0] << 8) | pkt[1]) != id || !(pkt[2] & 0x80) || ((pkt[2] >> 3) & 0x0F) != 0 ||
        (uint16_t)((pkt[4] << 8) | pkt[5]) != 1) {
        out->rc = -2;
        return;
    }
    /* the question must be ours (RFC 5452 section 9.1) */
    size_t off = 12, nx;
    uint8_t qn[256];
    int ql = pkt_name(pkt, len, off, qn, &nx);
    if (ql < 0 || nx + 4 > len || (size_t)ql != nlen || memcmp(qn, name, nlen) != 0 ||
        (uint16_t)((pkt[nx] << 8) | pkt[nx + 1]) != qtype || (uint16_t)((pkt[nx + 2] << 8) | pkt[nx + 3]) != 1) {
        out->rc = -2;
        return;
    }
    off = nx + 4;
    if (pkt[2] & 0x02) {                          /* TC: the caller asks again over TCP */
        out->truncated = true;
        return;
    }
    if ((pkt[3] & 0x0F) != 0) {
        out->rc = 1;
        return;
    }
    unsigned an = (unsigned)((pkt[6] << 8) | pkt[7]);
    if (an > 1024) return;
    size_t an_start = off;
    /* follow the CNAME chain from the target inside the answer (RFC 1034 section 3.6.2); at most ALIAS_MAX_CNAME hops */
    uint8_t cur[256];
    int curlen = (int)nlen;
    memcpy(cur, name, nlen);
    for (int hop = 0;; hop++) {
        bool moved = false;
        off = an_start;
        for (unsigned i = 0; i < an; i++) {
            rr_t r;
            if (!next_rr(pkt, len, &off, &r)) return;
            if (r.cls != 1 || r.type != 5 || r.olen != curlen || memcmp(r.owner, cur, (size_t)curlen) != 0) continue;
            uint8_t tgt[256];
            size_t tn;
            int tl = pkt_name(pkt, len, r.rd_off, tgt, &tn);
            if (tl < 0 || tn != r.rd_off + r.rdlen) return;
            if (hop >= ALIAS_MAX_CNAME) return;
            memcpy(cur, tgt, (size_t)tl);
            curlen = tl;
            moved = true;
            break;
        }
        if (!moved) break;
    }
    uint8_t want = qtype == 1 ? 4 : 16;
    uint32_t ttl = 0xFFFFFFFFu;
    off = an_start;
    for (unsigned i = 0; i < an; i++) {
        rr_t r;
        if (!next_rr(pkt, len, &off, &r)) return;
        if (r.cls != 1 || r.type != qtype || r.olen != curlen || memcmp(r.owner, cur, (size_t)curlen) != 0 || r.rdlen != want) continue;
        bool dup = false;
        for (unsigned k = 0; k < out->n; k++)
            if (memcmp(out->rd + (size_t)k * want, pkt + r.rd_off, want) == 0) dup = true;
        if (r.ttl < ttl) ttl = r.ttl;
        if (dup || out->n >= ALIAS_MAX_RR) continue;
        memcpy(out->rd + (size_t)out->n * want, pkt + r.rd_off, want);
        out->n++;
    }
    out->rdlen = want;
    if (out->n == 0) ttl = ALIAS_NEG_TTL;         /* NODATA (or a chain that ends without addresses) */
    if (ttl > 0x7FFFFFFF) ttl = 0x7FFFFFFF;       /* RFC 2181 section 8, RFC 8767 section 4 */
    out->ttl = ttl > ALIAS_MAX_TTL ? ALIAS_MAX_TTL : ttl;
    out->rc = 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the network: UDP, TCP when truncated, through the broker                                                        */
/* ------------------------------------------------------------------------------------------------------------- */

static uint8_t g_rbuf[65535];                     /* the one resolving thread's receive buffer */

static ssize_t tcp_query(const struct sockaddr_storage *sa, socklen_t sl, const uint8_t *q, size_t qlen, uint32_t timeout_ms,
                         uint8_t *resp, size_t cap) {
    tcp_sockopts_t copts = { .connect_timeout_ms = timeout_ms > 0 ? (int)timeout_ms : 1 };
    int64_t deadline = monotonic_ms() + timeout_ms;
    int fd = broker_connect_opts(sa->ss_family, SOCK_STREAM, (struct sockaddr *)(void *)sa, sl, &copts);
    if (fd < 0) return -1;
    uint8_t msg[2 + 512];
    if (qlen > 512) { close(fd); return -1; }
    msg[0] = (uint8_t)(qlen >> 8);
    msg[1] = (uint8_t)qlen;
    memcpy(msg + 2, q, qlen);
    if (send(fd, msg, qlen + 2, MSG_NOSIGNAL) != (ssize_t)(qlen + 2)) { close(fd); return -1; }
    uint8_t lp[2];
    uint32_t rem = remaining_ms(deadline);
    if (read_all_timeout(fd, lp, 2, rem) != 2) { close(fd); return -1; }
    size_t rl = (size_t)((lp[0] << 8) | lp[1]);
    if (rl < 12 || rl > cap) { close(fd); return -1; }
    rem = remaining_ms(deadline);
    ssize_t got = read_all_timeout(fd, resp, rl, rem);
    close(fd);
    return got == (ssize_t)rl ? got : -1;
}

/* One resolution of (name, qtype) at the resolvers of rs.  0 = a usable answer in *out, 1 = an answer but not a usable one (an RCODE
 * other than NOERROR, malformed), 2 = no resolver answered at all. */
static int net_resolve(const alias_rset_t *rs, const uint8_t *name, size_t nlen, uint16_t qtype, alias_parsed_t *out) {
    int64_t deadline = monotonic_ms() + ALIAS_RESOLVE_BUDGET_MS;
    bool any_answer = false;
    memset(out, 0, sizeof(*out));
    out->rc = -1;
    for (int i = 0; i < rs->n; i++) {
        uint32_t rem = remaining_ms(deadline);
        if (rem == 0) break;
        uint32_t share = rem / (uint32_t)(rs->n - i);
        if (share == 0) share = 1;
        const struct sockaddr_storage *sa = &rs->sa[i];
        uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
        uint8_t q[600];
        size_t ql = alias_build_query(q, sizeof(q), id, name, nlen, qtype);
        if (ql == 0) return 1;
        int fd = broker_connect(sa->ss_family, SOCK_DGRAM, (struct sockaddr *)(void *)sa, rs->sl[i]);
        if (fd < 0) continue;
        int64_t fwd_deadline = monotonic_ms() + share;
        ssize_t got = -1;
        alias_parsed_t p;
        memset(&p, 0, sizeof(p));
        p.rc = -2;
        if (send(fd, q, ql, MSG_NOSIGNAL) == (ssize_t)ql) {
            for (;;) {
                uint32_t wait_ms = remaining_ms(fwd_deadline);
                if (wait_ms == 0) break;
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                int pr = poll(&pfd, 1, (int)wait_ms);
                if (pr < 0 && errno == EINTR) continue;
                if (pr <= 0) break;
                ssize_t n = recv(fd, g_rbuf, sizeof(g_rbuf), 0);
                if (n < 0) break;                 /* ICMP unreachable and the like: the next resolver */
                alias_parse_response(g_rbuf, (size_t)n, id, name, nlen, qtype, &p);
                if (p.rc == -2) continue;         /* not the answer to this query: keep waiting (RFC 5452 section 9.1) */
                got = n;
                break;
            }
        }
        close(fd);
        if (got < 0) continue;
        any_answer = true;
        if (p.truncated) {
            ssize_t tg = tcp_query(sa, rs->sl[i], q, ql, remaining_ms(deadline), g_rbuf, sizeof(g_rbuf));
            if (tg < 0) continue;
            alias_parse_response(g_rbuf, (size_t)tg, id, name, nlen, qtype, &p);
        }
        if (p.rc == 0) {
            *out = p;
            return 0;
        }
    }
    return any_answer ? 1 : 2;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the published table                                                                                             */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    uint32_t nslots;
    uint32_t count;
} alias_tab_t;                                     /* followed by uint32_t slots[nslots] (byte offset of the entry from the table, 0 = empty) and the entries */

typedef struct {
    uint64_t key;
    int64_t fetched;
    uint32_t ttl;
    uint16_t qtype;
    uint8_t nlen, n, rdlen;
    uint8_t pad[3];
    /* name[nlen], then n * rdlen address octets, padded to 8 */
} alias_ent_t;

static _Atomic(alias_tab_t *) g_tab;

static inline uint64_t ent_hash(uint64_t key, uint16_t qtype, const uint8_t *name, size_t nlen) {
    uint64_t h = fnv64(1469598103934665603ULL, &key, sizeof(key));
    h = fnv64(h, &qtype, sizeof(qtype));
    return fnv64(h, name, nlen);
}

static inline const uint32_t *tab_slots(const alias_tab_t *t) { return (const uint32_t *)(const void *)(t + 1); }
static inline uint32_t *tab_slots_mut(alias_tab_t *t) { return (uint32_t *)(void *)(t + 1); }

bool alias_lookup(uint64_t key, const uint8_t *name, size_t nlen, uint16_t qtype, alias_answer_t *out) {
    const alias_tab_t *t = atomic_load_explicit(&g_tab, memory_order_acquire);
    if (!t || key == 0 || nlen == 0 || nlen > 255) return false;
    const uint8_t *base = (const uint8_t *)t;
    uint32_t mask = t->nslots - 1;
    for (uint32_t s = (uint32_t)ent_hash(key, qtype, name, nlen) & mask;; s = (s + 1) & mask) {
        uint32_t off = tab_slots(t)[s];
        if (off == 0) return false;
        const alias_ent_t *e = (const alias_ent_t *)(const void *)(base + off);
        if (e->key != key || e->qtype != qtype || e->nlen != nlen || memcmp((const uint8_t *)(e + 1), name, nlen) != 0) continue;
        int64_t age = alias_now() - e->fetched;
        if (age < 0) age = 0;
        int64_t validity = e->ttl > ALIAS_MIN_REFRESH ? (int64_t)e->ttl : ALIAS_MIN_REFRESH;
        if (age < validity) {
            out->ttl = age < (int64_t)e->ttl ? (uint32_t)((int64_t)e->ttl - age) : 0;
            out->stale = false;
        } else if (age < validity + ALIAS_STALE_MAX) {
            out->ttl = ALIAS_STALE_TTL;           /* RFC 8767 section 5: a short TTL for the data served past its time */
            out->stale = true;
        } else {
            return false;
        }
        out->n = e->n;
        out->rdlen = e->rdlen;
        out->rdata = (const uint8_t *)(e + 1) + ((e->nlen + 7u) & ~7u);
        return true;
    }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the jobs (the resolving thread only)                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    uint64_t key;
    int rset;
    uint16_t qtype;
    uint8_t nlen;
    uint8_t name[255];
    bool wanted;
    bool have;
    bool logged_fail;
    uint8_t n, rdlen;
    uint32_t ttl;
    int64_t fetched;
    int64_t next_try;
    uint32_t fails;
    uint8_t rd[ALIAS_MAX_RR * 16];
} job_t;

#define MAX_RSETS 64
static alias_rset_t g_rsets[MAX_RSETS];
static int64_t g_rset_dead[MAX_RSETS];
static int g_n_rsets;
static job_t **g_jobs;
static size_t g_njobs, g_jobs_cap;
static int32_t *g_jidx;                            /* open addressing over g_jobs: job index + 1, 0 = free */
static size_t g_jidx_size;
static size_t g_rot;                               /* rotating start of a pass (fairness) */
static bool g_changed;

static int rset_get(const alias_rset_t *rs) {
    for (int i = 0; i < g_n_rsets; i++)
        if (g_rsets[i].key == rs->key) return i;
    if (g_n_rsets >= MAX_RSETS) return -1;
    g_rsets[g_n_rsets] = *rs;
    g_rset_dead[g_n_rsets] = 0;
    return g_n_rsets++;
}

static bool jidx_rebuild(void) {
    size_t sz = 1024;
    while (sz < g_njobs * 2 + 16) sz <<= 1;
    int32_t *n = (int32_t *)calloc(sz, sizeof(*n));
    if (!n) return false;
    free(g_jidx);
    g_jidx = n;
    g_jidx_size = sz;
    for (size_t i = 0; i < g_njobs; i++) {
        size_t s = (size_t)ent_hash(g_jobs[i]->key, g_jobs[i]->qtype, g_jobs[i]->name, g_jobs[i]->nlen) & (sz - 1);
        while (g_jidx[s]) s = (s + 1) & (sz - 1);
        g_jidx[s] = (int32_t)i + 1;
    }
    return true;
}

static job_t *job_find(uint64_t key, uint16_t qtype, const uint8_t *name, size_t nlen) {
    if (!g_jidx) return NULL;
    for (size_t s = (size_t)ent_hash(key, qtype, name, nlen) & (g_jidx_size - 1); g_jidx[s]; s = (s + 1) & (g_jidx_size - 1)) {
        job_t *j = g_jobs[g_jidx[s] - 1];
        if (j->key == key && j->qtype == qtype && j->nlen == nlen && memcmp(j->name, name, nlen) == 0) return j;
    }
    return NULL;
}

/* marks (key, name, A and AAAA) as wanted, adding the jobs; false when the global cap is reached */
static bool want(int rset, const uint8_t *name, size_t nlen) {
    static const uint16_t types[2] = { 1, 28 };
    for (int t = 0; t < 2; t++) {
        job_t *j = job_find(g_rsets[rset].key, types[t], name, nlen);
        if (j) {
            j->wanted = true;
            continue;
        }
        if (g_njobs >= ALIAS_MAX_JOBS) return false;
        if (g_njobs == g_jobs_cap) {
            size_t nc = g_jobs_cap ? g_jobs_cap * 2 : 64;
            job_t **nj = (job_t **)realloc(g_jobs, nc * sizeof(*nj));
            if (!nj) return false;
            g_jobs = nj;
            g_jobs_cap = nc;
        }
        j = (job_t *)calloc(1, sizeof(*j));
        if (!j) return false;
        j->key = g_rsets[rset].key;
        j->rset = rset;
        j->qtype = types[t];
        j->nlen = (uint8_t)nlen;
        memcpy(j->name, name, nlen);
        j->wanted = true;
        g_jobs[g_njobs++] = j;
        if (!g_jidx || g_njobs * 2 + 16 > g_jidx_size) {
            if (!jidx_rebuild()) {
                g_njobs--;
                free(j);
                return false;
            }
        } else {
            size_t s = (size_t)ent_hash(j->key, j->qtype, j->name, j->nlen) & (g_jidx_size - 1);
            while (g_jidx[s]) s = (s + 1) & (g_jidx_size - 1);
            g_jidx[s] = (int32_t)g_njobs;
        }
    }
    return true;
}

static void sweep_unwanted(void) {
    size_t m = 0;
    for (size_t i = 0; i < g_njobs; i++) {
        if (g_jobs[i]->wanted) {
            g_jobs[m++] = g_jobs[i];
        } else {
            if (g_jobs[i]->have) g_changed = true;
            free(g_jobs[i]);
        }
    }
    if (m != g_njobs) {
        g_njobs = m;
        if (!jidx_rebuild()) {                       /* out of memory: start over at the next scan */
            for (size_t i = 0; i < g_njobs; i++) free(g_jobs[i]);
            g_njobs = 0;
            free(g_jidx);
            g_jidx = NULL;
            g_jidx_size = 0;
            g_changed = true;
        }
    }
}

static void name_text(const uint8_t *w, size_t n, char *out, size_t cap) {
    size_t o = 0, i = 0;
    while (i < n && w[i] && o + 6 < cap) {
        uint8_t l = w[i++];
        for (uint8_t k = 0; k < l && i < n && o + 6 < cap; k++, i++) {
            uint8_t c = w[i];
            if (c == '.' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
            else if (c < 0x21 || c > 0x7E) o += (size_t)snprintf(out + o, 5, "\\%03u", c);
            else out[o++] = (char)c;
        }
        out[o++] = '.';
    }
    if (o == 0) out[o++] = '.';
    out[o] = '\0';
}

static void log_job(const job_t *j, const char *what) {
    char t[300];
    name_text(j->name, j->nlen, t, sizeof(t));
    syslog(LOG_WARNING, "[Alias] %s: ALIAS target '%s' (%s)", what, t, j->qtype == 1 ? "A" : "AAAA");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* publishing                                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

static size_t ent_size(size_t nlen, size_t n, size_t rdlen) {
    return (sizeof(alias_ent_t) + (((nlen + 7) & ~(size_t)7) + n * rdlen) + 7) & ~(size_t)7;
}

static alias_tab_t *tab_build(void) {
    size_t usable = 0, bytes = 0;
    int64_t now = alias_now();
    for (size_t i = 0; i < g_njobs; i++) {
        const job_t *j = g_jobs[i];
        if (!j->have) continue;
        int64_t validity = j->ttl > ALIAS_MIN_REFRESH ? (int64_t)j->ttl : ALIAS_MIN_REFRESH;
        if (now - j->fetched >= validity + ALIAS_STALE_MAX) continue;
        usable++;
        bytes += ent_size(j->nlen, j->n, j->rdlen);
    }
    uint32_t nslots = 16;
    while (nslots < usable * 2 + 2) nslots <<= 1;
    size_t head = (sizeof(alias_tab_t) + (size_t)nslots * 4 + 7) & ~(size_t)7;
    uint8_t *mem = (uint8_t *)calloc(1, head + bytes);
    if (!mem) return NULL;
    alias_tab_t *t = (alias_tab_t *)(void *)mem;
    t->nslots = nslots;
    t->count = (uint32_t)usable;
    size_t o = head;
    for (size_t i = 0; i < g_njobs; i++) {
        const job_t *j = g_jobs[i];
        if (!j->have) continue;
        int64_t validity = j->ttl > ALIAS_MIN_REFRESH ? (int64_t)j->ttl : ALIAS_MIN_REFRESH;
        if (now - j->fetched >= validity + ALIAS_STALE_MAX) continue;
        alias_ent_t *e = (alias_ent_t *)(void *)(mem + o);
        e->key = j->key;
        e->fetched = j->fetched;
        e->ttl = j->ttl;
        e->qtype = j->qtype;
        e->nlen = j->nlen;
        e->n = j->n;
        e->rdlen = j->rdlen;
        memcpy((uint8_t *)(e + 1), j->name, j->nlen);
        memcpy((uint8_t *)(e + 1) + ((j->nlen + 7u) & ~7u), j->rd, (size_t)j->n * j->rdlen);
        uint32_t s = (uint32_t)ent_hash(j->key, j->qtype, j->name, j->nlen) & (nslots - 1);
        while (tab_slots_mut(t)[s]) s = (s + 1) & (nslots - 1);
        tab_slots_mut(t)[s] = (uint32_t)o;
        o += ent_size(j->nlen, j->n, j->rdlen);
    }
    return t;
}

static alias_tab_t *g_old_tab;                     /* waiting for its grace period */
static uint64_t g_old_epoch;

static void reap_old(bool wait) {
    if (!g_old_tab) return;
    if (wait ? rcu_writer_wait_until_safe(g_old_epoch, 5000) : rcu_writer_is_safe(g_old_epoch)) {
        free(g_old_tab);
        g_old_tab = NULL;
    }
}

static void publish(void) {
    alias_tab_t *t = tab_build();
    if (!t) {
        syslog(LOG_ERR, "[Alias] out of memory building the result table; the previous one stays in service");
        return;
    }
    reap_old(true);
    if (g_old_tab) { free(t); return; }            /* readers still hold the one before: publish at the next pass */
    alias_tab_t *prev = atomic_load_explicit(&g_tab, memory_order_relaxed);
    g_old_epoch = rcu_writer_publish(&g_tab, t);
    g_old_tab = prev;
    g_changed = false;
    reap_old(false);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the scheduler                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

static uint32_t retry_delay(uint32_t fails) {
    uint32_t d = ALIAS_RETRY_MIN;
    for (uint32_t i = 1; i < fails && d < ALIAS_RETRY_MAX; i++) d *= 2;
    return d > ALIAS_RETRY_MAX ? ALIAS_RETRY_MAX : d;
}

static void run_pass(void) {
    int64_t now = alias_now();
    int budget = ALIAS_QUERIES_PER_TICK;
    size_t n = g_njobs;
    for (size_t k = 0; k < n && budget > 0; k++) {
        job_t *j = g_jobs[(g_rot + k) % n];
        if (j->next_try > now) continue;
        if (g_rset_dead[j->rset] > now) {          /* the whole resolver set did not answer a moment ago */
            j->next_try = g_rset_dead[j->rset];
            continue;
        }
        budget--;
        alias_parsed_t p;
        int rc = g_alias_resolve_hook ? g_alias_resolve_hook(&g_rsets[j->rset], j->name, j->nlen, j->qtype, &p)
                                      : net_resolve(&g_rsets[j->rset], j->name, j->nlen, j->qtype, &p);
        now = alias_now();
        if (rc == 0 && p.rc == 0) {
            j->have = true;
            j->n = p.n;
            j->rdlen = p.rdlen;
            j->ttl = p.ttl;
            j->fetched = now;
            memcpy(j->rd, p.rd, (size_t)p.n * p.rdlen);
            j->fails = 0;
            uint32_t third = (uint32_t)((uint64_t)p.ttl * 2 / 3);
            j->next_try = now + (third > ALIAS_MIN_REFRESH ? third : ALIAS_MIN_REFRESH);
            if (j->logged_fail) {
                log_job(j, "resolved again");
                j->logged_fail = false;
            }
            g_changed = true;
        } else {
            j->fails++;
            j->next_try = now + retry_delay(j->fails);
            if (rc == 2) g_rset_dead[j->rset] = now + ALIAS_DEAD_SECS;
            if (!j->logged_fail) {
                log_job(j, j->have ? "cannot refresh, the last result is served for a while" : "cannot resolve, the name answers SERVFAIL");
                j->logged_fail = true;
            }
        }
    }
    if (n) g_rot = (g_rot + 1) % n;
    /* a result that ran out of its stale time leaves the table */
    for (size_t i = 0; i < g_njobs; i++) {
        job_t *j = g_jobs[i];
        if (!j->have) continue;
        int64_t validity = j->ttl > ALIAS_MIN_REFRESH ? (int64_t)j->ttl : ALIAS_MIN_REFRESH;
        if (now - j->fetched >= validity + ALIAS_STALE_MAX) {
            j->have = false;
            g_changed = true;
        }
    }
    if (g_changed) publish();
}

/* ------------------------------------------------------------------------------------------------------------- */
/* finding the targets                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static void scan_zones(void) {
    for (size_t i = 0; i < g_njobs; i++) g_jobs[i]->wanted = false;
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    if (cfg && snap && snap->views) {
        for (size_t v = 0; v < snap->view_count; v++) {
            view_snapshot_t *view = &snap->views[v];
            for (size_t zi = 0; zi < view->zone_count; zi++) {
                zone_db_entry_t *e = view->entries ? view->entries[zi] : NULL;
                if (!e || !view_owns_entry(view, e) || e->kind == ZONE_KIND_FORWARD || e->kind == ZONE_KIND_PROGRAM) continue;   /* a shared zone is scanned in its owner view */
                zone_version_t *ver = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
                const zone_image_t *img = ver ? ver->image : NULL;
                if (!img || !(img->flags & ZONE_IMAGE_F_ALIAS)) continue;
                const zone_config_t *zc = zone_entry_config(cfg, e);
                alias_rset_t rs;
                if (alias_resolvers_fill(cfg, zc, e->source == ZONE_SRC_DB, &rs) == 0) continue;
                int ri = rset_get(&rs);
                if (ri < 0) {
                    syslog(LOG_WARNING, "[Alias] more than %d different alias-resolver lists; zone '%s' is not expanded", MAX_RSETS, e->domain);
                    continue;
                }
                const zone_image_name_t *names = zone_image_names(img);
                const zone_image_rr_t *rrs = zone_image_rrs(img);
                int targets = 0;
                bool capped = false;
                for (uint32_t id = 0; id < img->n_names && !capped; id++) {
                    if (!(names[id].rr_count_flags & ZONE_IMAGE_NAME_ALIAS)) continue;
                    uint32_t k = names[id].first_rr, end = k + (names[id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
                    for (; k < end; k++) {
                        if (rrs[k].type != DNS_TYPE_PDNS_ALIAS || rrs[k].class_val != 1) continue;
                        if (++targets > ALIAS_MAX_TARGETS_PER_ZONE) { capped = true; break; }
                        uint8_t w[256];
                        size_t wl;
                        if (!alias_wire_lower(zone_image_rr_rdata(img, k), zone_image_rr_rdlen(img, k), w, &wl)) continue;
                        if (!want(ri, w, wl)) {
                            capped = true;
                            break;
                        }
                    }
                }
                if (capped) syslog(LOG_WARNING, "[Alias] zone '%s': more than %d ALIAS targets (or %d jobs in all); the rest answer SERVFAIL", e->domain,
                                   ALIAS_MAX_TARGETS_PER_ZONE, ALIAS_MAX_JOBS);
            }
        }
    }
    if (cfg) release_config_snapshot(cfg);
    rcu_aux_read_unlock();
    sweep_unwanted();
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the thread                                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

static _Atomic uint64_t g_dirty;
static pthread_t g_tid;
static bool g_started;

void alias_notify(void) { atomic_fetch_add_explicit(&g_dirty, 1, memory_order_relaxed); }

static void *alias_thread(void *arg) {
    (void)arg;
    uint64_t seen_dirty = (uint64_t)-1, seen_gen = (uint64_t)-1;
    const void *seen_snap = NULL;
    /* runs until the Backend ends with _exit(); nothing joins or stops it */
    for (;;) {
        uint64_t d = atomic_load_explicit(&g_dirty, memory_order_relaxed);
        uint64_t gen = 0;
        const void *sp;
        rcu_aux_read_lock();
        server_config_t *cfg = acquire_config_snapshot();
        if (cfg) {
            gen = cfg->generation;
            release_config_snapshot(cfg);
        }
        sp = acquire_zone_snapshot();
        rcu_aux_read_unlock();
        if (d != seen_dirty || gen != seen_gen || sp != seen_snap) {
            seen_dirty = d;
            seen_gen = gen;
            seen_snap = sp;
            scan_zones();
        }
        run_pass();
        reap_old(false);
        struct timespec ts = { 0, ALIAS_TICK_MS * 1000000L };
        nanosleep(&ts, NULL);
    }
}

bool alias_start(void) {
    if (g_started) return true;
    if (pthread_create(&g_tid, NULL, alias_thread, NULL) != 0) return false;
    g_started = true;
    return true;
}

static void free_jobs(void) {
    for (size_t i = 0; i < g_njobs; i++) free(g_jobs[i]);
    free(g_jobs);
    free(g_jidx);
    g_jobs = NULL;
    g_jidx = NULL;
    g_njobs = g_jobs_cap = g_jidx_size = 0;
    g_n_rsets = 0;
    memset(g_rset_dead, 0, sizeof(g_rset_dead));
    g_rot = 0;
    g_changed = false;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* tests                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

void alias_test_reset(void) {
    free_jobs();
    alias_tab_t *t = atomic_exchange_explicit(&g_tab, NULL, memory_order_acq_rel);
    free(t);
    free(g_old_tab);
    g_old_tab = NULL;
}

void alias_test_want(const alias_rset_t *rs, const uint8_t *name, size_t nlen) {
    int ri = rset_get(rs);
    if (ri >= 0) (void)want(ri, name, nlen);
}

void alias_test_pass(void) { run_pass(); }

size_t alias_test_job_count(void) { return g_njobs; }

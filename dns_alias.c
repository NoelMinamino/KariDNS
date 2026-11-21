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

/* How long a result of this TTL is kept as fresh data: the TTL, at least the refresh interval (a refresh is not tried sooner) */
static inline int64_t alias_validity(uint32_t ttl) { return ttl > ALIAS_MIN_REFRESH ? (int64_t)ttl : ALIAS_MIN_REFRESH; }

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

/* The key of a resolver set: the same members give the same key whatever their order or spelling ("::1" and "0::1"), so one set
 * does not make two jobs per target.  Each member is hashed on its binary address and port (the text when it is not an IP literal),
 * the hashes are sorted and folded. */
static uint64_t rs_key(const rs_ent_t *e, int n) {
    if (n == 0) return 0;
    uint64_t eh[ALIAS_MAX_RESOLVERS];
    for (int i = 0; i < n; i++) {
        uint8_t a[16];
        uint16_t port = (uint16_t)(e[i].port > 0 && e[i].port <= 65535 ? e[i].port : 53);   /* as alias_resolvers_fill() */
        uint64_t h = 1469598103934665603ULL;
        if (inet_pton(AF_INET, e[i].ip, a) == 1) {
            h = fnv64(h, "4", 1);
            h = fnv64(h, a, 4);
        } else if (inet_pton(AF_INET6, e[i].ip, a) == 1) {
            h = fnv64(h, "6", 1);
            h = fnv64(h, a, 16);
        } else {
            h = fnv64(h, e[i].ip, strlen(e[i].ip) + 1);
        }
        eh[i] = fnv64(h, &port, sizeof(port));
    }
    for (int i = 1; i < n; i++) {                 /* insertion sort: n <= ALIAS_MAX_RESOLVERS */
        uint64_t v = eh[i];
        int k = i;
        for (; k > 0 && eh[k - 1] > v; k--) eh[k] = eh[k - 1];
        eh[k] = v;
    }
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) h = fnv64(h, &eh[i], sizeof(eh[i]));
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

uint32_t alias_max_refresh(const server_config_t *cfg, const zone_config_t *zcfg, bool db_zone) {
    uint32_t v = zext(zcfg)->alias_max_refresh;
    if (v == 0 && cfg) v = cfg->alias_max_refresh;
    if (v == 0 && db_zone && cfg && cfg->database.enabled) v = cfg->database.alias_max_refresh;
    return v ? v : KARIDNS_ALIAS_MAX_REFRESH_DEFAULT;
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

#define EDNS_OPT_COOKIE 10                        /* RFC 7873 section 8 */

size_t alias_build_query(uint8_t *buf, size_t cap, uint16_t id, const uint8_t *name, size_t nlen, uint16_t qtype, const uint8_t *cc,
                         const uint8_t *sc, size_t sclen) {
    if (cc && sclen != 0 && (sclen < 8 || sclen > 32 || !sc)) return 0;   /* a server cookie is 8 to 32 octets (RFC 7873 section 4) */
    size_t optlen = cc ? 4 + 8 + sclen : 0;
    if (nlen == 0 || nlen > 255 || cap < 12 + nlen + 4 + 11 + optlen) return 0;
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
    buf[o++] = (uint8_t)(optlen >> 8);            /* RDLEN */
    buf[o++] = (uint8_t)optlen;
    if (cc) {
        /* RFC 7873 section 4: OPTION-CODE 10, the 8-octet client cookie, then the server cookie when one is known (section 5.1: every
         * request carries a COOKIE option; the longer form with the server cookie last received from this server) */
        buf[o++] = 0; buf[o++] = EDNS_OPT_COOKIE;
        buf[o++] = (uint8_t)((8 + sclen) >> 8);
        buf[o++] = (uint8_t)(8 + sclen);
        memcpy(buf + o, cc, 8);
        o += 8;
        if (sclen) memcpy(buf + o, sc, sclen);
        o += sclen;
    }
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

/* The options of the OPT RR (RFC 6891 section 6.1.2: {code, length, data} to the end of the RDATA): the COOKIE option against the client
 * cookie sent.  false = discard the response (RFC 7873 section 5.3: an illegal COOKIE length - valid are 8 and 16 to 40, section 5.2.2 -, an
 * incorrect client cookie; here also two COOKIE options or an option list that runs past the RDATA, where the cookie cannot be checked). */
static bool opt_cookie(const uint8_t *rd, size_t rdlen, const uint8_t *cc, alias_parsed_t *out) {
    size_t o = 0;
    bool seen = false;
    while (o < rdlen) {
        if (rdlen - o < 4) return false;
        uint16_t code = (uint16_t)((rd[o] << 8) | rd[o + 1]);
        size_t olen = (size_t)((rd[o + 2] << 8) | rd[o + 3]);
        o += 4;
        if (olen > rdlen - o) return false;
        if (code == EDNS_OPT_COOKIE) {
            if (seen) return false;
            seen = true;
            if (olen < 8 || (olen > 8 && olen < 16) || olen > 40) return false;
            if (memcmp(rd + o, cc, 8) != 0) return false;
            out->cookie = olen == 8 ? ALIAS_CK_CLIENT : ALIAS_CK_SERVER;
            out->sc_len = (uint8_t)(olen - 8);
            memcpy(out->sc, rd + o + 8, olen - 8);   /* opaque to the client (RFC 7873 section 4.2; RFC 9018 section 4 defines the server's own form) */
        }
        o += olen;
    }
    return true;
}

void alias_parse_response(const uint8_t *pkt, size_t len, uint16_t id, const uint8_t *name, size_t nlen, uint16_t qtype,
                          const uint8_t *cc, alias_parsed_t *out) {
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
    size_t an_start = off;
    unsigned an = (unsigned)((pkt[6] << 8) | pkt[7]);
    const unsigned an_ns = an + (unsigned)((pkt[8] << 8) | pkt[9]), total = an_ns + (unsigned)((pkt[10] << 8) | pkt[11]);
    const bool tc = (pkt[2] & 0x02) != 0;
    /* the OPT RR: at most one, owned by the root, in the additional section (RFC 6891 section 6.1.1); its TTL carries the upper 8 bits of
     * the RCODE (section 6.1.3).  Every RR is walked (each takes at least 11 octets, so the walk ends with the message).  A truncated
     * message may end inside an RR: the walk stops there (TCP is asked next; no COOKIE option was seen) */
    unsigned ext_rcode = 0;
    bool opt_seen = false;
    for (unsigned i = 0; i < total; i++) {
        rr_t r;
        if (!next_rr(pkt, len, &off, &r)) {
            if (tc) break;
            return;
        }
        if (r.type != 41) continue;
        if (i < an_ns || opt_seen || r.olen != 1) {
            if (tc) break;
            return;
        }
        opt_seen = true;
        ext_rcode = r.ttl >> 24;
        if (cc && !opt_cookie(pkt + r.rd_off, r.rdlen, cc, out)) {
            out->cookie = ALIAS_CK_NONE;
            out->sc_len = 0;
            out->rc = -2;                         /* RFC 7873 section 5.3: discarded; the real answer may still come */
            return;
        }
    }
    unsigned rcode = (ext_rcode << 4) | (pkt[3] & 0x0Fu);
    if (rcode == ALIAS_RCODE_BADCOOKIE) {         /* RFC 7873 section 5.3: the caller retries with the server cookie of this response */
        out->badcookie = true;
        out->rc = 1;
        return;
    }
    if (tc) {                                     /* TC: the caller asks again over TCP */
        out->truncated = true;
        return;
    }
    if (rcode != 0) {
        out->rc = 1;
        return;
    }
    if (an > 1024) return;
    /* follow the CNAME chain from the target inside the answer (RFC 1034 section 3.6.2); at most ALIAS_MAX_CNAME hops */
    uint8_t cur[256];
    int curlen = (int)nlen;
    memcpy(cur, name, nlen);
    uint32_t cname_ttl = 0xFFFFFFFFu;               /* minimum over the CNAMEs followed (RFC 2181 section 5.2: the answer must not outlive them) */
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
            if (r.ttl < cname_ttl) cname_ttl = r.ttl;
            memcpy(cur, tgt, (size_t)tl);
            curlen = tl;
            moved = true;
            break;
        }
        if (!moved) break;
    }
    uint8_t want = qtype == 1 ? 4 : 16;
    uint32_t ttl = cname_ttl;
    off = an_start;
    for (unsigned i = 0; i < an; i++) {
        rr_t r;
        if (!next_rr(pkt, len, &off, &r)) return;
        if (r.cls != 1 || r.type != qtype || r.olen != curlen || memcmp(r.owner, cur, (size_t)curlen) != 0 || r.rdlen != want) continue;
        bool dup = false;
        for (unsigned k = 0; k < out->n && !dup; k++)
            if (memcmp(out->rd + (size_t)k * want, pkt + r.rd_off, want) == 0) dup = true;
        if (r.ttl < ttl) ttl = r.ttl;
        if (dup || out->n >= ALIAS_MAX_RR) continue;
        memcpy(out->rd + (size_t)out->n * want, pkt + r.rd_off, want);
        out->n++;
    }
    out->rdlen = want;
    if (out->n == 0) ttl = ALIAS_NEG_TTL < cname_ttl ? ALIAS_NEG_TTL : cname_ttl;  /* NODATA (or a chain that ends without addresses) */
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

/* ---- DNS Cookies (RFC 7873) of the resolver addresses: the alias thread only ---- */
typedef struct {
    bool used;
    bool capable;                                 /* it sent a valid server cookie: its responses must carry one (RFC 7873 section 5.3) */
    uint8_t fam;                                  /* AF_INET / AF_INET6 */
    uint8_t addr[16];
    uint16_t port;
    uint8_t cc[8];                                /* the client cookie */
    uint8_t sc[32];                               /* the newest server cookie, sc_len octets (0 = none) */
    uint8_t sc_len;
    uint32_t fails;                               /* resolutions in a row without an accepted answer */
    int64_t cc_renew;                             /* alias_now() at which cc is replaced */
    int64_t last_ok;                              /* alias_now() of the last accepted answer */
    int64_t last_use;
} ck_t;
static ck_t g_ck[ALIAS_COOKIE_SLOTS];

static void ck_addr(const struct sockaddr_storage *sa, uint8_t *fam, uint8_t addr[16], uint16_t *port) {
    memset(addr, 0, 16);
    if (sa->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)(const void *)sa;
        *fam = AF_INET6;
        memcpy(addr, &s6->sin6_addr, 16);
        *port = s6->sin6_port;
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)(const void *)sa;
        *fam = AF_INET;
        memcpy(addr, &s4->sin_addr, 4);
        *port = s4->sin_port;
    }
}

static ck_t *ck_find(const struct sockaddr_storage *sa) {
    uint8_t fam, addr[16];
    uint16_t port;
    ck_addr(sa, &fam, addr, &port);
    for (int i = 0; i < ALIAS_COOKIE_SLOTS; i++)
        if (g_ck[i].used && g_ck[i].fam == fam && g_ck[i].port == port && memcmp(g_ck[i].addr, addr, 16) == 0) return &g_ck[i];
    return NULL;
}

/* the state of an address, made when it has none (a free slot, else the least recently used one); the client cookie is renewed when it is due */
static ck_t *ck_get(const struct sockaddr_storage *sa, int64_t now) {
    ck_t *c = ck_find(sa);
    if (!c) {
        c = &g_ck[0];
        for (int i = 0; i < ALIAS_COOKIE_SLOTS; i++) {
            if (!g_ck[i].used) { c = &g_ck[i]; break; }
            if (g_ck[i].last_use < c->last_use) c = &g_ck[i];
        }
        memset(c, 0, sizeof(*c));
        c->used = true;
        ck_addr(sa, &c->fam, c->addr, &c->port);
        c->cc_renew = INT64_MIN;
        c->last_ok = now;
    }
    c->last_use = now;
    if (now >= c->cc_renew) {
        /* RFC 7873 section 4.1: a client cookie of at least 64 bits of entropy, different per server address and changed periodically;
         * section 7.1: the default lifetime is one day, with a jitter of plus zero to minus at least 40 %.  RFC 9018 section 3: a random
         * value per server is one of the allowed ways.  The server cookie was made for the old client cookie (RFC 7873 section 4.2), so it
         * goes too; `capable` stays: the server still sends cookies.  Only between two resolutions: no query is outstanding (section 7.1) */
        arc4random_buf(c->cc, sizeof(c->cc));
        c->cc_renew = now + ALIAS_COOKIE_LIFETIME - (int64_t)arc4random_uniform(ALIAS_COOKIE_LIFETIME * 2 / 5 + 1);
        c->sc_len = 0;
    }
    return c;
}

static void ck_text(const ck_t *c, char *out, size_t cap) {
    char a[INET6_ADDRSTRLEN];
    if (!inet_ntop(c->fam, c->addr, a, sizeof(a))) strlcpy(a, "?", sizeof(a));
    snprintf(out, cap, c->fam == AF_INET6 ? "[%s]:%u" : "%s:%u", a, (unsigned)ntohs(c->port));
}

/* a response that passed the checks: keep the newest server cookie (RFC 7873 section 5.3: also from an error response) */
static void ck_learn(ck_t *c, const alias_parsed_t *p) {
    if (p->cookie != ALIAS_CK_SERVER) return;
    memcpy(c->sc, p->sc, p->sc_len);
    c->sc_len = p->sc_len;
    if (!c->capable) {
        c->capable = true;
        char t[64];
        ck_text(c, t, sizeof(t));
        syslog(LOG_NOTICE, "[Alias] resolver %s sends DNS cookies: from now on its answers without a valid cookie are ignored (RFC 7873 section 5.3)", t);
    }
}

/* the end of one resolution at this address: accepted = some response passed the checks */
static void ck_account(ck_t *c, bool accepted, int64_t now) {
    if (accepted) {
        c->fails = 0;
        c->last_ok = now;
        return;
    }
    if (!c->capable) return;
    c->fails++;
    if (c->fails >= ALIAS_COOKIE_FORGET_FAILS && now - c->last_ok >= ALIAS_COOKIE_FORGET_SECS) {
        /* a resolver that was replaced by one without cookies at the same address would never be heard again: after this many failed
         * resolutions over this long, answers without a cookie are taken again (and the mark comes back with the next server cookie) */
        c->capable = false;
        c->sc_len = 0;
        c->fails = 0;
        char t[64];
        ck_text(c, t, sizeof(t));
        syslog(LOG_WARNING, "[Alias] resolver %s gave no answer with a valid DNS cookie in %d resolutions over %lld s: answers without a cookie are accepted from it again",
               t, ALIAS_COOKIE_FORGET_FAILS, (long long)(now - c->last_ok));
    }
}

/* RFC 7873 section 5.3 beyond what alias_parse_response() checks: once the address sent a server cookie, a response without one (no COOKIE
 * option, or the client cookie alone) is discarded, as one the client expected a COOKIE option in */
static inline bool ck_acceptable(const ck_t *c, const alias_parsed_t *p) { return !c->capable || p->cookie == ALIAS_CK_SERVER; }

/* One exchange with one resolver: UDP, then TCP when truncated; once more after BADCOOKIE with the new server cookie (RFC 7873 section 5.3,
 * within the same time).  -1 = no accepted response, 0 = a usable answer in *p, 1 = an accepted response that is no usable answer.
 * *accepted is set when a response passed the checks. */
static int resolve_at(const struct sockaddr_storage *sa, socklen_t sl, ck_t *c, const uint8_t *name, size_t nlen, uint16_t qtype,
                      uint32_t share, int64_t deadline, uint32_t left, alias_parsed_t *p, bool *accepted) {
    int64_t at_deadline = monotonic_ms() + share;
    for (int attempt = 0; attempt < 2; attempt++) {
        uint8_t q[600];
        uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
        size_t ql = alias_build_query(q, sizeof(q), id, name, nlen, qtype, c->cc, c->sc, c->sc_len);
        if (ql == 0) return 1;
        int fd = broker_connect(sa->ss_family, SOCK_DGRAM, (struct sockaddr *)(void *)sa, sl);
        if (fd < 0) return -1;
        bool got = false;
        memset(p, 0, sizeof(*p));
        p->rc = -2;
        if (send(fd, q, ql, MSG_NOSIGNAL) == (ssize_t)ql) {
            for (;;) {
                uint32_t wait_ms = remaining_ms(at_deadline);
                if (wait_ms == 0) break;
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                int pr = poll(&pfd, 1, (int)wait_ms);
                if (pr < 0 && errno == EINTR) continue;
                if (pr <= 0) break;
                ssize_t n = recv(fd, g_rbuf, sizeof(g_rbuf), 0);
                if (n < 0) break;                 /* ICMP unreachable and the like: the next resolver */
                alias_parse_response(g_rbuf, (size_t)n, id, name, nlen, qtype, c->cc, p);
                /* not the answer to this query (RFC 5452 section 9.1), or a cookie that is wrong or missing (RFC 7873 section 5.3): keep waiting */
                if (p->rc == -2 || !ck_acceptable(c, p)) {
                    p->rc = -2;
                    continue;
                }
                got = true;
                break;
            }
        }
        close(fd);
        if (!got) return -1;
        *accepted = true;
        ck_learn(c, p);
        if (p->truncated) {
            /* TCP gets this resolver's share of what is left, not all of it: the resolvers after this one still need time */
            uint32_t tcp_ms = remaining_ms(deadline) / left;
            ssize_t tg = tcp_query(sa, sl, q, ql, tcp_ms, g_rbuf, sizeof(g_rbuf));
            if (tg < 0) return 1;
            /* a COOKIE option that is there must be right (s5.3); one that is missing is accepted over TCP, where an off-path forger
             * cannot answer (the three-way handshake) and some resolvers send no cookie */
            alias_parse_response(g_rbuf, (size_t)tg, id, name, nlen, qtype, c->cc, p);
            if (p->rc == -2) return 1;
            ck_learn(c, p);
        }
        if (p->badcookie && p->cookie == ALIAS_CK_SERVER && attempt == 0 && remaining_ms(at_deadline) > 0) continue;
        return p->rc == 0 ? 0 : 1;
    }
    return 1;
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
        ck_t *c = ck_get(&rs->sa[i], alias_now());
        bool accepted = false;
        alias_parsed_t p;
        int r = resolve_at(&rs->sa[i], rs->sl[i], c, name, nlen, qtype, share, deadline, (uint32_t)(rs->n - i), &p, &accepted);
        ck_account(c, accepted, alias_now());
        if (accepted) any_answer = true;
        if (r == 0) {
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
        int64_t validity = alias_validity(e->ttl);
        if (age < validity) {
            /* current data: the rest of the TTL, 0 while a TTL below ALIAS_MIN_REFRESH waits for its refresh (an upstream
             * TTL of 0 stays 0: the upstream asks not to cache it, and the refresh is due) */
            out->ttl = age < (int64_t)e->ttl ? (uint32_t)((int64_t)e->ttl - age) : 0;
            out->stale = false;
        } else if (age < validity + ALIAS_STALE_MAX) {
            /* the refreshes failed past the validity: stale data, served with a TTL greater than 0, RECOMMENDED 30 s
             * (RFC 8767 section 4) */
            out->ttl = ALIAS_STALE_TTL;
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
    uint32_t max_refresh;                          /* alias-max-refresh-time in force: the smallest of the zones that want the job */
    uint32_t scan_cap;                             /* the smallest value of the zones of the scan that is running (0 = none yet) */
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
    int slot = -1;
    for (int i = 0; i < g_n_rsets; i++) {
        if (g_rsets[i].key == rs->key) return i;
        if (g_rsets[i].key == 0 && slot < 0) slot = i;   /* released by reclaim_rsets() */
    }
    if (slot < 0) {
        if (g_n_rsets >= MAX_RSETS) return -1;
        slot = g_n_rsets++;
    }
    g_rsets[slot] = *rs;
    g_rset_dead[slot] = 0;
    return slot;
}

/* Releases the slots no job refers to any more (a resolver list that left the configuration), so that changing lists over the life of the
 * process does not use up MAX_RSETS.  A released slot has key 0; real keys are never 0. */
static void reclaim_rsets(void) {
    bool used[MAX_RSETS] = { false };
    for (size_t i = 0; i < g_njobs; i++) used[g_jobs[i]->rset] = true;
    for (int i = 0; i < g_n_rsets; i++)
        if (!used[i]) g_rsets[i].key = 0;
    while (g_n_rsets > 0 && g_rsets[g_n_rsets - 1].key == 0) g_n_rsets--;
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

/* the time from a fetch to the next refresh: two thirds of the TTL, at most alias-max-refresh-time, at least ALIAS_MIN_REFRESH */
static uint32_t refresh_interval(uint32_t ttl, uint32_t max_refresh) {
    uint32_t iv = (uint32_t)((uint64_t)ttl * 2 / 3);
    if (iv > max_refresh) iv = max_refresh;
    return iv > ALIAS_MIN_REFRESH ? iv : ALIAS_MIN_REFRESH;
}

/* marks (key, name, A and AAAA) as wanted by a zone with alias-max-refresh-time cap, adding the jobs; false when the global cap is reached.
 * A job several zones want takes the smallest of their values (scan_cap; apply_caps() puts it in force after the scan). */
static bool want(int rset, const uint8_t *name, size_t nlen, uint32_t cap) {
    static const uint16_t types[2] = { 1, 28 };
    if (cap == 0) cap = KARIDNS_ALIAS_MAX_REFRESH_DEFAULT;
    for (int t = 0; t < 2; t++) {
        job_t *j = job_find(g_rsets[rset].key, types[t], name, nlen);
        if (j) {
            if (j->scan_cap == 0 || cap < j->scan_cap) j->scan_cap = cap;
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
        j->max_refresh = j->scan_cap = cap;
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

/* after a scan: the smallest alias-max-refresh-time of the zones is in force.  A job whose next refresh is now later than its fetch plus
 * the new interval is refreshed at that time (a reconfiguration that lowers the value applies to the results already held); a job that
 * is failing keeps its retry time */
static void apply_caps(void) {
    for (size_t i = 0; i < g_njobs; i++) {
        job_t *j = g_jobs[i];
        if (j->scan_cap == 0 || j->scan_cap == j->max_refresh) continue;
        j->max_refresh = j->scan_cap;
        if (!j->have || j->fails != 0) continue;
        int64_t due = j->fetched + refresh_interval(j->ttl, j->max_refresh);
        if (j->next_try > due) j->next_try = due;
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
    char t[1100];                                  /* 255 wire octets, each at worst as "\DDD" */
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
        if (now - j->fetched >= alias_validity(j->ttl) + ALIAS_STALE_MAX) continue;
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
        if (now - j->fetched >= alias_validity(j->ttl) + ALIAS_STALE_MAX) continue;
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

/* wait: a short, quiet try (0.7; it waited up to 5 s, with the stall line, for a reader that stays in its section): the table is freed after
 * its grace period only, and while a reader holds it the next table is built at a later pass (publish()) */
#define ALIAS_REAP_TRY_MS 50
static void reap_old(bool wait) {
    if (!g_old_tab) return;
    if (wait ? rcu_writer_try_wait(g_old_epoch, ALIAS_REAP_TRY_MS) : rcu_writer_is_safe(g_old_epoch)) {
        free(g_old_tab);
        g_old_tab = NULL;
    }
}

static void publish(void) {
    reap_old(true);
    if (g_old_tab) return;                         /* readers still hold the one before: build and publish at the next pass (g_changed stays set) */
    alias_tab_t *t = tab_build();
    if (!t) {
        syslog(LOG_ERR, "[Alias] out of memory building the result table; the previous one stays in service");
        return;
    }
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
            /* a little jitter, so the jobs of a set that comes back do not all fire in the same tick */
            j->next_try = g_rset_dead[j->rset] + (int64_t)arc4random_uniform(ALIAS_DEAD_SECS / 2);
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
            j->next_try = now + refresh_interval(p.ttl, j->max_refresh);
            if (j->logged_fail) {
                log_job(j, "resolved again");
                j->logged_fail = false;
            }
            if (logev_wanted(LOGC_GENERAL, 2)) {      /* 0.7 M3, debug 2: when the next refresh is and why */
                char t[1100];
                name_text(j->name, j->nlen, t, sizeof(t));
                logev_post(LOGC_GENERAL, 2, NULL, 0, "[Alias] ALIAS target '%.200s' (%s): %d record(s), TTL %u; next refresh in %lld s (two thirds of the TTL, at most alias-max-refresh-time %u, at least %d)", t,
                           j->qtype == 1 ? "A" : "AAAA", (int)p.n, (unsigned)p.ttl, (long long)(j->next_try - now), (unsigned)j->max_refresh, ALIAS_MIN_REFRESH);
            }
            g_changed = true;
        } else {
            j->fails++;
            j->next_try = now + retry_delay(j->fails);
            if (logev_wanted(LOGC_GENERAL, 1)) {      /* 0.7 M3, debug 1: every failure, with the retry (the WARNING is said once per episode) */
                char t[1100];
                name_text(j->name, j->nlen, t, sizeof(t));
                logev_post(LOGC_GENERAL, 1, NULL, 0, "[Alias] ALIAS target '%.200s' (%s): %s (failure %u); next try in %lld s%s", t, j->qtype == 1 ? "A" : "AAAA",
                           rc == 2 ? "no resolver of the set answered" : rc != 0 ? "the query failed" : "the answer is an error", (unsigned)j->fails,
                           (long long)(j->next_try - now), rc == 2 ? ", the whole resolver set waits" : "");
            }
            if (rc == 2) g_rset_dead[j->rset] = now + ALIAS_DEAD_SECS;
            if (!j->logged_fail) {
                log_job(j, j->have ? "cannot refresh, the last result is served for a while" : "cannot resolve, the name answers SERVFAIL");
                j->logged_fail = true;
            }
        }
    }
    if (n) g_rot = (g_rot + 1) % n;
    if (budget == 0) {                              /* the per-tick limit was reached: say so when jobs are still due (at most every 5 minutes) */
        static int64_t last_note;
        if (last_note == 0 || now - last_note >= 300) {
            size_t due = 0;
            for (size_t i = 0; i < g_njobs; i++)
                if (g_jobs[i]->next_try <= now && g_rset_dead[g_jobs[i]->rset] <= now) due++;
            if (due) {
                last_note = now ? now : 1;
                syslog(LOG_WARNING, "[Alias] %zu ALIAS jobs are due but at most %d upstream queries per %d ms are sent; they are refreshed late",
                       due, ALIAS_QUERIES_PER_TICK, ALIAS_TICK_MS);
            }
        }
    }
    /* a result that ran out of its stale time leaves the table */
    for (size_t i = 0; i < g_njobs; i++) {
        job_t *j = g_jobs[i];
        if (!j->have) continue;
        if (now - j->fetched >= alias_validity(j->ttl) + ALIAS_STALE_MAX) {
            j->have = false;
            g_changed = true;
        }
    }
    if (g_changed) publish();
}

/* ------------------------------------------------------------------------------------------------------------- */
/* finding the targets                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

/* what scan_zones() has to tell the log: syslog() can block, so it is called after rcu_aux_read_unlock() and not inside the section
 * (which would hold up writers' grace periods).  The calloc()s of want() stay inside: they are small and at most ALIAS_MAX_JOBS. */
#define SCAN_NOTES_MAX 8
typedef struct {
    bool rsets;                                    /* true: too many resolver lists; false: too many targets */
    char zone[256];
} scan_note_t;

static void scan_zones(void) {
    scan_note_t notes[SCAN_NOTES_MAX];
    int n_notes = 0, n_lost = 0;
    for (size_t i = 0; i < g_njobs; i++) {
        g_jobs[i]->wanted = false;
        g_jobs[i]->scan_cap = 0;
    }
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    if (cfg && snap && snap->views) {
        for (size_t v = 0; v <= snap->view_count; v++) {
            const bool att = v == snap->view_count;       /* 0.7 S3: after the views' directories, the zones of the zone store that are in memory (the attach table: a zone that is not has no ALIAS targets to resolve) */
            if (att && !dbdir()) break;
            zdir_iter_t zit;
            size_t apos = 0;
            if (!att) zdir_iter_init(&zit, &snap->views[v]);
            int att_again = 0;
att_restart:;
            /* the attach table that grows while it is walked is another table: the position of the walk means nothing in it and zones are skipped (a zone whose ALIAS targets are not resolved until the next scan); a
             * walk that saw it change starts again (the work of a zone is the same the second time) */
            const uint64_t atid = att ? dbdir()->attach_tab_id() : 0;
            apos = 0;
            for (zdir_elem_t *zel; (zel = att ? dbdir()->attach_next(&apos) : zdir_iter_next(&zit));) {
                zone_db_entry_t *e = zdir_entry(zel);
                if (!e || !view_owns_elem(zel) || e->kind == ZONE_KIND_FORWARD || e->kind == ZONE_KIND_PROGRAM) continue;   /* a shared zone is scanned in its owner view */
                zone_version_t *ver = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
                const zone_image_t *img = ver ? ver->image : NULL;
                if (!img || !(img->flags & ZONE_IMAGE_F_ALIAS)) continue;
                const zone_config_t *zc = zone_entry_config(cfg, e);
                alias_rset_t rs;
                if (alias_resolvers_fill(cfg, zc, e->source == ZONE_SRC_DB, &rs) == 0) continue;
                const uint32_t cap = alias_max_refresh(cfg, zc, e->source == ZONE_SRC_DB);
                int ri = rset_get(&rs);
                if (ri < 0) {
                    if (n_notes < SCAN_NOTES_MAX) {
                        notes[n_notes].rsets = true;
                        strlcpy(notes[n_notes++].zone, e->domain, sizeof(notes[0].zone));
                    } else {
                        n_lost++;
                    }
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
                        if (!want(ri, w, wl, cap)) {
                            capped = true;
                            break;
                        }
                    }
                }
                if (capped) {
                    if (n_notes < SCAN_NOTES_MAX) {
                        notes[n_notes].rsets = false;
                        strlcpy(notes[n_notes++].zone, e->domain, sizeof(notes[0].zone));
                    } else {
                        n_lost++;
                    }
                }
            }
            if (att && dbdir()->attach_tab_id() != atid && ++att_again < 4) goto att_restart;
        }
    }
    if (cfg) release_config_snapshot(cfg);
    rcu_aux_read_unlock();
    sweep_unwanted();
    reclaim_rsets();
    apply_caps();
    for (int i = 0; i < n_notes; i++) {
        if (notes[i].rsets)
            syslog(LOG_WARNING, "[Alias] more than %d different alias-resolver lists; zone '%s' is not expanded", MAX_RSETS, notes[i].zone);
        else
            syslog(LOG_WARNING, "[Alias] zone '%s': more than %d ALIAS targets (or %d jobs in all); the rest answer SERVFAIL", notes[i].zone,
                   ALIAS_MAX_TARGETS_PER_ZONE, ALIAS_MAX_JOBS);
    }
    if (n_lost) syslog(LOG_WARNING, "[Alias] %d more zones hit the ALIAS limits (not listed)", n_lost);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the thread                                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

static _Atomic uint64_t g_dirty;
static _Atomic uint64_t g_scans;
static pthread_t g_tid;
static bool g_started;

/* The scan is driven by these notices and by the configuration generation, not by a change of the zone snapshot (0.7 B2): a snapshot changes for every
 * zone a database fetch brings in, and a million-zone warm-up scanned the whole directory over and over.  So whoever changes the set of zones that
 * the directory holds, or the version of a zone, tells us after the change is visible (zone_publish_ex(), the registry commit, the delta that
 * puts elements in or takes them out, the eviction, the rebuild of the snapshot) - release here, acquire in the thread: the scan sees the change. */
void alias_notify(void) { atomic_fetch_add_explicit(&g_dirty, 1, memory_order_release); }

uint64_t alias_scan_count(void) { return atomic_load_explicit(&g_scans, memory_order_relaxed); }

static void *alias_thread(void *arg) {
    (void)arg;
    uint64_t seen_dirty = (uint64_t)-1, seen_gen = (uint64_t)-1;
    /* runs until the Backend ends with _exit(); nothing joins or stops it */
    for (;;) {
        uint64_t d = atomic_load_explicit(&g_dirty, memory_order_acquire);
        uint64_t gen = 0;
        rcu_aux_read_lock();
        server_config_t *cfg = acquire_config_snapshot();
        if (cfg) {
            gen = cfg->generation;
            release_config_snapshot(cfg);
        }
        rcu_aux_read_unlock();
        if (d != seen_dirty || gen != seen_gen) {
            seen_dirty = d;
            seen_gen = gen;
            uint64_t n = atomic_fetch_add_explicit(&g_scans, 1, memory_order_relaxed) + 1;
            logev_post(LOGC_GENERAL, 2, NULL, 0, "[Alias] scanning the zones for ALIAS records (scan %llu; notices %llu, configuration generation %llu)", (unsigned long long)n,
                       (unsigned long long)d, (unsigned long long)gen);
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

/* tests: how many times alias_notify() was called (what the thread would turn into scans) */
uint64_t alias_test_notices(void) { return atomic_load_explicit(&g_dirty, memory_order_relaxed); }

void alias_test_reset(void) {
    free_jobs();
    alias_tab_t *t = atomic_exchange_explicit(&g_tab, NULL, memory_order_acq_rel);
    free(t);
    free(g_old_tab);
    g_old_tab = NULL;
    memset(g_ck, 0, sizeof(g_ck));
}

void alias_test_want(const alias_rset_t *rs, const uint8_t *name, size_t nlen, uint32_t max_refresh) {
    int ri = rset_get(rs);
    if (ri >= 0) (void)want(ri, name, nlen, max_refresh);
    apply_caps();
}

void alias_test_rescan(void) {
    for (size_t i = 0; i < g_njobs; i++) {
        g_jobs[i]->wanted = false;
        g_jobs[i]->scan_cap = 0;
    }
}

bool alias_test_cookie(const struct sockaddr_storage *sa, bool *capable, uint8_t cc[8], uint8_t *sc_len) {
    const ck_t *c = ck_find(sa);
    if (!c) return false;
    *capable = c->capable;
    memcpy(cc, c->cc, 8);
    *sc_len = c->sc_len;
    return true;
}

int64_t alias_test_next_try(const uint8_t *name, size_t nlen, uint16_t qtype) {
    for (size_t i = 0; i < g_njobs; i++)
        if (g_jobs[i]->qtype == qtype && g_jobs[i]->nlen == nlen && memcmp(g_jobs[i]->name, name, nlen) == 0) return g_jobs[i]->next_try;
    return -1;
}

void alias_test_pass(void) { run_pass(); }

size_t alias_test_job_count(void) { return g_njobs; }

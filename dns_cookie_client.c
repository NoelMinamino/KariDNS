/*
 * dns_cookie_client.c - the client side of DNS Cookies (RFC 7873) for the upstream queries (ALIAS resolvers, forwarders).  The design is
 * in dns_cookie_client.h.  Everything here works on caller buffers and the caller's table: no allocation, no I/O but syslog.
 */
#include "dns_cookie_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_log.h"

/* ------------------------------------------------------------------------------------------------------------- */
/* the option                                                                                                      */
/* ------------------------------------------------------------------------------------------------------------- */

size_t ckc_option_put(uint8_t *p, size_t cap, const uint8_t cc[8], const uint8_t *sc, size_t sclen) {
    if (sclen != 0 && (sclen < 8 || sclen > 32 || !sc)) return 0;   /* a server cookie is 8 to 32 octets (RFC 7873 section 4) */
    size_t olen = 4 + 8 + sclen;
    if (!cc || cap < olen) return 0;
    /* RFC 7873 section 4: OPTION-CODE 10, the 8-octet client cookie, then the server cookie when one is known (section 5.1: every
     * request carries a COOKIE option; the longer form with the server cookie last received from this server) */
    p[0] = 0;
    p[1] = CKC_OPT_COOKIE;
    p[2] = (uint8_t)((8 + sclen) >> 8);
    p[3] = (uint8_t)(8 + sclen);
    memcpy(p + 4, cc, 8);
    if (sclen) memcpy(p + 12, sc, sclen);
    return olen;
}

bool ckc_option_parse(const uint8_t *rd, size_t rdlen, const uint8_t cc[8], ckc_seen_t *out) {
    size_t o = 0;
    bool seen = false;
    while (o < rdlen) {
        if (rdlen - o < 4) return false;
        uint16_t code = (uint16_t)((rd[o] << 8) | rd[o + 1]);
        size_t olen = (size_t)((rd[o + 2] << 8) | rd[o + 3]);
        o += 4;
        if (olen > rdlen - o) return false;
        if (code == CKC_OPT_COOKIE) {
            /* RFC 7873 section 5.3 would use the first of several COOKIE options; two are discarded here: a forger cannot know the
             * client cookie, so the real server never needs a second one */
            if (seen) return false;
            seen = true;
            if (olen < 8 || (olen > 8 && olen < 16) || olen > 40) return false;
            if (memcmp(rd + o, cc, 8) != 0) return false;
            out->kind = olen == 8 ? CKC_CLIENT : CKC_SERVER;
            out->sc_len = (uint8_t)(olen - 8);
            memcpy(out->sc, rd + o + 8, olen - 8);   /* opaque to the client (RFC 7873 section 4.2; RFC 9018 section 4 defines the server's own form) */
        }
        o += olen;
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the state of the server addresses                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

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

ckc_entry_t *ckc_find(const ckc_table_t *t, const struct sockaddr_storage *sa) {
    uint8_t fam, addr[16];
    uint16_t port;
    ck_addr(sa, &fam, addr, &port);
    for (unsigned i = 0; i < t->n; i++) {
        ckc_entry_t *c = &t->slots[i];
        if (c->used && c->fam == fam && c->port == port && memcmp(c->addr, addr, 16) == 0) return c;
    }
    return NULL;
}

ckc_entry_t *ckc_get(ckc_table_t *t, const struct sockaddr_storage *sa, int64_t now) {
    ckc_entry_t *c = ckc_find(t, sa);
    if (!c) {
        c = &t->slots[0];
        for (unsigned i = 0; i < t->n; i++) {
            if (!t->slots[i].used) { c = &t->slots[i]; break; }
            if (t->slots[i].last_use < c->last_use) c = &t->slots[i];
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
         * goes too; `capable` stays: the server still sends cookies.  Only between two exchanges: no query is outstanding (section 7.1) */
        arc4random_buf(c->cc, sizeof(c->cc));
        c->cc_renew = now + CKC_LIFETIME - (int64_t)arc4random_uniform(CKC_LIFETIME * 2 / 5 + 1);
        c->sc_len = 0;
    }
    return c;
}

static void ck_text(const ckc_entry_t *c, char *out, size_t cap) {
    char a[INET6_ADDRSTRLEN];
    if (!inet_ntop(c->fam, c->addr, a, sizeof(a))) snprintf(a, sizeof(a), "?");
    snprintf(out, cap, c->fam == AF_INET6 ? "[%s]:%u" : "%s:%u", a, (unsigned)ntohs(c->port));
}

/* the process-wide mark of an address (nonzero) */
static uint64_t ck_key(const ckc_entry_t *c) {
    uint64_t h = 1469598103934665603ULL;
    const uint8_t parts[3] = { c->fam, (uint8_t)(c->port >> 8), (uint8_t)c->port };
    for (size_t i = 0; i < sizeof(parts); i++) h = (h ^ parts[i]) * 1099511628211ULL;
    for (size_t i = 0; i < 16; i++) h = (h ^ c->addr[i]) * 1099511628211ULL;
    return h | 1;
}

/* Whether this thread's change of the mark is the one to log.  Without marks (one thread) always.  With marks the slot of the address
 * holds its key while some thread has logged "sends DNS cookies": the first thread to set it logs, and the first to clear it.  An
 * address whose slot is taken by another one is logged by every thread (a hash collision costs repeated lines, never a lost one) */
static bool ck_mark(ckc_table_t *t, const ckc_entry_t *c, bool set) {
    if (!t->marks || t->nmarks == 0) return true;
    uint64_t k = ck_key(c);
    _Atomic uint64_t *slot = &t->marks[k % t->nmarks];
    uint64_t want = set ? 0 : k;
    if (atomic_compare_exchange_strong_explicit(slot, &want, set ? k : 0, memory_order_relaxed, memory_order_relaxed)) return true;
    return set && want != k;                      /* set: another address holds the slot; clear: someone else cleared it, or it was never ours */
}

bool ckc_expected(const ckc_table_t *t, const ckc_entry_t *c) {
    if (c->capable) return true;
    if (!t->marks || t->nmarks == 0) return false;
    uint64_t k = ck_key(c);
    return atomic_load_explicit(&t->marks[k % t->nmarks], memory_order_relaxed) == k;
}

bool ckc_learn(ckc_table_t *t, ckc_entry_t *c, uint8_t kind, const uint8_t *sc, uint8_t sc_len) {
    if (kind != CKC_SERVER || sc_len < 8 || sc_len > 32) return false;
    memcpy(c->sc, sc, sc_len);
    c->sc_len = sc_len;
    if (c->capable) return false;
    c->capable = true;
    if (!ck_mark(t, c, true)) return false;
    char a[64];
    ck_text(c, a, sizeof(a));
    syslog(LOG_NOTICE, "%s %s sends DNS cookies: from now on its answers without a valid cookie are ignored (RFC 7873 section 5.3)", t->who, a);
    return true;
}

bool ckc_account(ckc_table_t *t, ckc_entry_t *c, bool accepted, int64_t now) {
    if (accepted) {
        c->fails = 0;
        c->last_ok = now;
        return false;
    }
    if (!ckc_expected(t, c)) return false;
    c->fails++;
    if (c->fails >= CKC_FORGET_FAILS && now - c->last_ok >= CKC_FORGET_SECS) {
        /* a server that was replaced by one without cookies at the same address would never be heard again: after this many failed
         * exchanges over this long, answers without a cookie are taken again (and the mark comes back with the next server cookie) */
        c->capable = false;
        c->sc_len = 0;
        c->fails = 0;
        if (ck_mark(t, c, false)) {
            char a[64];
            ck_text(c, a, sizeof(a));
            syslog(LOG_WARNING, "%s %s gave no answer with a valid DNS cookie in %d %s over %lld s: answers without a cookie are accepted from it again",
                   t->who, a, CKC_FORGET_FAILS, t->unit, (long long)(now - c->last_ok));
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* whole messages                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

/* the offset after the (possibly compressed) name at off; 0 when it runs past len.  A pointer ends the name where it stands (RFC 1035
 * section 4.1.4), so nothing is followed and no loop is possible */
static size_t skip_name(const uint8_t *p, size_t len, size_t off) {
    for (;;) {
        if (off >= len) return 0;
        uint8_t l = p[off];
        if ((l & 0xC0) == 0xC0) return off + 2 <= len ? off + 2 : 0;
        if (l & 0xC0) return 0;                   /* 01 and 10 label types are not valid (RFC 6891 section 7 retired the extended label) */
        if (l == 0) return off + 1;
        off += 1 + (size_t)l;
    }
}

bool ckc_msg_scan(const uint8_t *pkt, size_t len, ckc_msg_t *m) {
    memset(m, 0, sizeof(*m));
    if (len < 12) return false;
    unsigned qd = (unsigned)((pkt[4] << 8) | pkt[5]);
    unsigned an_ns = (unsigned)((pkt[6] << 8) | pkt[7]) + (unsigned)((pkt[8] << 8) | pkt[9]);
    unsigned total = an_ns + (unsigned)((pkt[10] << 8) | pkt[11]);
    size_t off = 12;
    for (unsigned i = 0; i < qd; i++) {
        off = skip_name(pkt, len, off);
        if (off == 0 || off + 4 > len) return false;
        off += 4;
    }
    /* every RR takes at least 11 octets, so the walk ends with the message whatever the counts say */
    for (unsigned i = 0; i < total; i++) {
        size_t start = off;
        off = skip_name(pkt, len, off);
        if (off == 0 || off + 10 > len) return false;
        uint16_t type = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        size_t rdlen = (size_t)((pkt[off + 8] << 8) | pkt[off + 9]);
        size_t rd = off + 10;
        if (rdlen > len - rd) return false;
        if (type == 41) {
            /* RFC 6891 section 6.1.1: in the additional section, the owner is the root; section 6.1.2 / 6.1.3: CLASS and TTL */
            if (i < an_ns || off != start + 1 || pkt[start] != 0) return false;
            if (m->opt_count++ == 0) {
                m->opt_off = start;
                m->opt_end = rd + rdlen;
                m->rd_off = rd;
                m->rdlen = rdlen;
                m->ttl = ((uint32_t)pkt[off + 4] << 24) | ((uint32_t)pkt[off + 5] << 16) | ((uint32_t)pkt[off + 6] << 8) | pkt[off + 7];
            }
        } else if (i >= an_ns && (type == 250 || type == 24)) {
            m->has_sig = true;                    /* TSIG (RFC 8945) or SIG(0) (RFC 2931) */
        }
        off = rd + rdlen;
    }
    m->rr_end = off;
    return true;
}

int ckc_msg_check(const uint8_t *pkt, size_t len, const uint8_t cc[8], ckc_seen_t *out) {
    memset(out, 0, sizeof(*out));
    ckc_msg_t m;
    /* a message that cannot be walked (a truncated one may end inside an RR) shows no cookie: the caller decides whether that is enough */
    if (!ckc_msg_scan(pkt, len, &m) || m.opt_count == 0) return 0;
    if (m.opt_count > 1) return -1;               /* RFC 6891 section 6.1.1: one OPT RR; which one's cookie would count is not defined */
    out->opt = true;
    if (!ckc_option_parse(pkt + m.rd_off, m.rdlen, cc, out)) {
        memset(out, 0, sizeof(*out));
        return -1;                                /* RFC 7873 section 5.3: discarded; the real answer may still come */
    }
    unsigned rcode = ((m.ttl >> 24) << 4) | (pkt[3] & 0x0Fu);   /* RFC 6891 section 6.1.3: the upper 8 bits of the RCODE */
    out->badcookie = rcode == CKC_RCODE_BADCOOKIE;
    return 0;
}

size_t ckc_msg_rewrite(const uint8_t *in, size_t len, uint8_t *out, size_t cap, const uint8_t *opt, size_t optlen, int mode, bool *added) {
    if (added) *added = false;
    ckc_msg_t m;
    if (!ckc_msg_scan(in, len, &m) || m.has_sig || m.opt_count > 1) return 0;
    if (m.opt_count == 0) {
        if (mode != CKC_RW_SET) {
            if (len > cap) return 0;
            memcpy(out, in, len);
            return len;
        }
        uint16_t ar = (uint16_t)((in[10] << 8) | in[11]);
        if (ar == 0xFFFF || optlen > 0xFFFF || len + 11 + optlen > cap) return 0;
        /* the new OPT RR goes after the last RR, before whatever follows the RRs (copied as it was) */
        memcpy(out, in, m.rr_end);
        size_t o = m.rr_end;
        out[o++] = 0;                             /* root owner, TYPE 41, UDP payload 512, extended RCODE 0, version 0, no flags (RFC 6891 section 6.1.2) */
        out[o++] = 0; out[o++] = 41;
        out[o++] = 0x02; out[o++] = 0x00;
        out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;
        out[o++] = (uint8_t)(optlen >> 8);
        out[o++] = (uint8_t)optlen;
        if (optlen) memcpy(out + o, opt, optlen);
        o += optlen;
        memcpy(out + o, in + m.rr_end, len - m.rr_end);
        o += len - m.rr_end;
        ar++;
        out[10] = (uint8_t)(ar >> 8);
        out[11] = (uint8_t)ar;
        if (added) *added = true;
        return o;
    }
    if (mode == CKC_RW_DROP) {
        size_t n = len - (m.opt_end - m.opt_off);
        if (n > cap) return 0;
        memcpy(out, in, m.opt_off);
        memcpy(out + m.opt_off, in + m.opt_end, len - m.opt_end);
        uint16_t ar = (uint16_t)(((in[10] << 8) | in[11]) - 1);   /* the OPT RR is in the additional section: ARCOUNT >= 1 */
        out[10] = (uint8_t)(ar >> 8);
        out[11] = (uint8_t)ar;
        return n;
    }
    /* the options without COOKIE, then opt (RFC 6891 section 6.1.2: the order of the options does not matter) */
    if (m.rd_off > cap) return 0;
    memcpy(out, in, m.rd_off);
    size_t o = m.rd_off, p = m.rd_off, end = m.opt_end;
    while (p < end) {
        if (end - p < 4) return 0;
        uint16_t code = (uint16_t)((in[p] << 8) | in[p + 1]);
        size_t olen = (size_t)((in[p + 2] << 8) | in[p + 3]);
        if (olen > end - p - 4) return 0;
        if (code != CKC_OPT_COOKIE) {
            if (o + 4 + olen > cap) return 0;
            memcpy(out + o, in + p, 4 + olen);
            o += 4 + olen;
        }
        p += 4 + olen;
    }
    if (o + optlen > cap) return 0;
    if (optlen) memcpy(out + o, opt, optlen);
    o += optlen;
    size_t rdlen = o - m.rd_off;
    if (rdlen > 0xFFFF || o + (len - m.opt_end) > cap) return 0;
    out[m.rd_off - 2] = (uint8_t)(rdlen >> 8);
    out[m.rd_off - 1] = (uint8_t)rdlen;
    memcpy(out + o, in + m.opt_end, len - m.opt_end);
    return o + (len - m.opt_end);
}

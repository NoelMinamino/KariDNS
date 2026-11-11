#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "tapstat_core.h"
#include "dnstap_decode.h"
#include "../dns_siphash.h"

/* ====================================================================== */
/* Frame Streams reader                                                    */
/* Control frame: 4 zero bytes (escape), 4-byte length, then the payload: 4-byte control type and fields of 4-byte type,
 * 4-byte length, value (field 1 = content type).  Data frame: 4-byte length (not 0), then the payload.  All big-endian.
 * Types: ACCEPT 1, START 2, STOP 3, READY 4, FINISH 5 (the libfstrm control frame format, as sent by dns_dnstap.c). */

#define FS_ACCEPT 1U
#define FS_START  2U
#define FS_STOP   3U
#define FS_READY  4U
#define FS_FINISH 5U
#define FS_FIELD_CONTENT_TYPE 1U

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

void fstrm_reader_init(fstrm_reader_t *r, bool bidir) {
    memset(r, 0, sizeof(*r));
    r->bidir = bidir;
    r->state = FSTRM_ST_INIT;
}

void fstrm_reader_free(fstrm_reader_t *r) {
    free(r->buf);
    r->buf = NULL;
    r->buf_cap = 0;
}

/* appends a control frame (escape, length, type, optional content type) to r->reply */
static void fstrm_queue_control(fstrm_reader_t *r, uint32_t type, bool with_ct) {
    static const char ct[] = FSTRM_CTYPE_DNSTAP;
    size_t ctlen = sizeof(ct) - 1;
    uint32_t plen = 4 + (with_ct ? (uint32_t)(8 + ctlen) : 0);
    size_t need = 8 + plen;
    if (r->reply_len + need > sizeof(r->reply)) return; /* two replies at most per stream: cannot happen */
    uint8_t *p = r->reply + r->reply_len;
    wr32(p, 0);
    wr32(p + 4, plen);
    wr32(p + 8, type);
    if (with_ct) {
        wr32(p + 12, FS_FIELD_CONTENT_TYPE);
        wr32(p + 16, (uint32_t)ctlen);
        memcpy(p + 20, ct, ctlen);
    }
    r->reply_len += need;
}

/* One control frame of n >= 4 bytes.  0 = ok, 1 = stream finished, -1 = error. */
static int fstrm_control(fstrm_reader_t *r, const uint8_t *p, size_t n) {
    uint32_t type = rd32(p);
    bool has_ct = false, match = false;
    size_t off = 4;
    while (n - off >= 8) {
        uint32_t ft = rd32(p + off), fl = rd32(p + off + 4);
        off += 8;
        if (fl > n - off) return -1;
        if (ft == FS_FIELD_CONTENT_TYPE) {
            if (fl > FSTRM_MAX_CTYPE) return -1;
            has_ct = true;
            if (fl == sizeof(FSTRM_CTYPE_DNSTAP) - 1 && memcmp(p + off, FSTRM_CTYPE_DNSTAP, fl) == 0) match = true;
        }
        off += fl;
    }
    if (off != n) return -1; /* 1 to 7 bytes that are no field */

    switch (type) {
    case FS_READY:
        if (!r->bidir || r->state != FSTRM_ST_INIT) return -1;
        if (has_ct && !match) return -1; /* the sender offers other content types only: nothing to accept */
        fstrm_queue_control(r, FS_ACCEPT, match);
        r->state = FSTRM_ST_WAIT_START;
        return 0;
    case FS_START:
        if (r->state != (r->bidir ? FSTRM_ST_WAIT_START : FSTRM_ST_INIT)) return -1;
        if (has_ct && !match) return -1;
        r->state = FSTRM_ST_DATA;
        return 0;
    case FS_STOP:
        if (r->state != FSTRM_ST_DATA) return -1;
        if (r->bidir) fstrm_queue_control(r, FS_FINISH, false);
        r->state = FSTRM_ST_DONE;
        return 1;
    default: /* ACCEPT and FINISH go from the receiver to the sender; anything else is unknown */
        return -1;
    }
}

int fstrm_feed(fstrm_reader_t *r, const uint8_t *in, size_t len, fstrm_data_cb cb, void *ctx) {
    if (r->state == FSTRM_ST_ERROR) return -1;
    if (r->state == FSTRM_ST_DONE) return 1;
    for (;;) {
        const uint8_t *frame = NULL;
        if (r->phase == 0) {
            if (len == 0) break;
            size_t need = (r->hdr_have >= 4 && rd32(r->hdr) == 0) ? 8 : 4;
            size_t n = need - r->hdr_have;
            if (n > len) n = len;
            memcpy(r->hdr + r->hdr_have, in, n);
            r->hdr_have += n; in += n; len -= n;
            need = (r->hdr_have >= 4 && rd32(r->hdr) == 0) ? 8 : 4;
            if (r->hdr_have < need) continue;
            uint32_t first = rd32(r->hdr);
            r->control = (first == 0);
            r->plen = r->control ? rd32(r->hdr + 4) : first;
            r->hdr_have = 0;
            if (r->control ? (r->plen < 4 || r->plen > FSTRM_MAX_CONTROL) : r->plen > FSTRM_MAX_DATA_FRAME) {
                r->state = FSTRM_ST_ERROR;
                return -1;
            }
            r->have = 0;
            r->phase = 1;
        } else {
            if (len == 0) break;
            if (r->have == 0 && len >= r->plen) {
                frame = in; /* the whole frame is in this read: no copy */
                in += r->plen; len -= r->plen;
            } else {
                if (r->buf_cap < r->plen) {
                    uint8_t *nb = realloc(r->buf, r->plen);
                    if (!nb) { r->state = FSTRM_ST_ERROR; return -1; }
                    r->buf = nb;
                    r->buf_cap = r->plen;
                }
                size_t n = r->plen - r->have;
                if (n > len) n = len;
                memcpy(r->buf + r->have, in, n);
                r->have += (uint32_t)n; in += n; len -= n;
                if (r->have < r->plen) break;
                frame = r->buf;
            }
            r->phase = 0;
            if (r->control) {
                int rc = fstrm_control(r, frame, r->plen);
                if (rc < 0) { r->state = FSTRM_ST_ERROR; return -1; }
                if (rc > 0) return 1;
            } else {
                if (r->state != FSTRM_ST_DATA) { r->state = FSTRM_ST_ERROR; return -1; }
                cb(ctx, frame, r->plen);
            }
        }
    }
    return 0;
}

/* ====================================================================== */
/* names                                                                   */

/* "example.test" / "example.test." / "." to wire format, lower case.  No escapes: a zone name with a dot in a label is no use here. */
bool tapstat_name_to_wire(const char *name, uint8_t *out, size_t *out_len) {
    size_t pos = 0;
    if (!name || !*name) return false;
    if (strcmp(name, ".") == 0) { out[0] = 0; *out_len = 1; return true; }
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63 || pos + 1 + l + 1 > 255) return false;
        out[pos++] = (uint8_t)l;
        for (size_t i = 0; i < l; i++) {
            unsigned char c = (unsigned char)p[i];
            out[pos++] = (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
        }
        if (!dot) break;
        p = dot + 1;
    }
    out[pos++] = 0;
    *out_len = pos;
    return true;
}

/* wire name to text with the master-file escapes (\. \\ \DDD); the root is "."; false when the name is not well formed */
static bool wire_to_text(const uint8_t *w, size_t n, char *out, size_t cap) {
    size_t pos = 0, o = 0;
    if (n == 0) return false;
    if (n == 1 && w[0] == 0) { if (cap < 2) return false; out[0] = '.'; out[1] = 0; return true; }
    while (pos < n) {
        uint8_t l = w[pos++];
        if (l == 0) { out[o] = 0; return pos == n; }
        if (l > 63 || l > n - pos) return false;
        for (uint8_t i = 0; i < l; i++) {
            uint8_t c = w[pos++];
            char tmp[5];
            size_t tl;
            if (c == '.' || c == '\\') { tmp[0] = '\\'; tmp[1] = (char)c; tl = 2; }
            else if (c <= 0x20 || c >= 0x7f) {
                tmp[0] = '\\'; tmp[1] = (char)('0' + c / 100); tmp[2] = (char)('0' + (c / 10) % 10); tmp[3] = (char)('0' + c % 10); tl = 4;
            } else { tmp[0] = (char)c; tl = 1; }
            if (o + tl + 2 > cap) return false;
            memcpy(out + o, tmp, tl);
            o += tl;
        }
        if (o + 2 > cap) return false;
        out[o++] = '.';
    }
    return false; /* no root label */
}

const char *tapstat_qtype_name(uint16_t t, char *buf, size_t cap) {
    static const struct { uint16_t t; const char *n; } names[] = {
        {1, "A"}, {2, "NS"}, {5, "CNAME"}, {6, "SOA"}, {12, "PTR"}, {13, "HINFO"}, {15, "MX"}, {16, "TXT"}, {28, "AAAA"},
        {33, "SRV"}, {35, "NAPTR"}, {39, "DNAME"}, {41, "OPT"}, {43, "DS"}, {44, "SSHFP"}, {46, "RRSIG"}, {47, "NSEC"},
        {48, "DNSKEY"}, {50, "NSEC3"}, {51, "NSEC3PARAM"}, {52, "TLSA"}, {64, "SVCB"}, {65, "HTTPS"}, {251, "IXFR"},
        {252, "AXFR"}, {255, "ANY"}, {257, "CAA"}
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (names[i].t == t) return names[i].n;
    snprintf(buf, cap, "TYPE%u", (unsigned)t);
    return buf;
}

const char *tapstat_rcode_name(unsigned rc, char *buf, size_t cap) {
    static const char *names[] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
                                   "NXRRSET", "NOTAUTH", "NOTZONE" };
    if (rc < sizeof(names) / sizeof(names[0])) return names[rc];
    snprintf(buf, cap, "RCODE%u", rc);
    return buf;
}

/* ====================================================================== */
/* fixed-size top-K table: Space-Saving (Metwally, Agrawal, El Abbadi: "Efficient Computation of Frequent and Top-k
 * Elements in Data Streams", ICDT 2005).  At most `cap` keys are kept.  A key that is not kept replaces the kept key
 * with the smallest count and inherits that count (as the error bound), then counts its own event.  So for a kept key
 * the true count is in [count - err, count], and any key with a true count above total / cap is kept.
 * The smallest count is found with a min-heap over the entries (O(log cap) per event); lookup is an open-addressing
 * hash index with backward-shift deletion.  Nothing is allocated per event. */

typedef struct {
    uint64_t count;
    uint64_t err;       /* the count may be too high by up to this much */
    uint64_t hash;
    uint32_t hpos;      /* position in the heap */
    uint16_t klen;
    uint8_t key[];      /* keymax bytes */
} tent_t;

typedef struct {
    uint32_t cap;       /* keys kept at most */
    uint32_t used;
    uint32_t nslots;    /* power of two, at least 2 * cap */
    size_t keymax;
    size_t stride;
    uint8_t *ents;      /* cap * stride, zero pages until used */
    uint32_t *slots;    /* 0 = empty, else entry index + 1 */
    uint32_t *heap;     /* entry indices, a min-heap on count */
    uint64_t total;     /* events counted */
    uint64_t evictions; /* events whose key replaced another key */
} ttab_t;

static tent_t *tent(const ttab_t *t, uint32_t i) { return (tent_t *)(void *)(t->ents + (size_t)i * t->stride); }

static bool ttab_init(ttab_t *t, uint32_t cap, size_t keymax) {
    memset(t, 0, sizeof(*t));
    t->cap = cap;
    t->keymax = keymax;
    t->stride = (offsetof(tent_t, key) + keymax + 7) & ~(size_t)7;
    t->nslots = 16;
    while (t->nslots < 2U * cap) t->nslots <<= 1;
    t->ents = calloc(cap, t->stride);
    t->slots = calloc(t->nslots, sizeof(uint32_t));
    t->heap = calloc(cap, sizeof(uint32_t));
    return t->ents && t->slots && t->heap;
}

static void ttab_free(ttab_t *t) {
    free(t->ents);
    free(t->slots);
    free(t->heap);
    t->ents = NULL;
    t->slots = NULL;
    t->heap = NULL;
}

static void ttab_reset(ttab_t *t) {
    memset(t->slots, 0, (size_t)t->nslots * sizeof(uint32_t));
    t->used = 0;
    t->total = 0;
    t->evictions = 0;
}

static void heap_swap(ttab_t *t, uint32_t a, uint32_t b) {
    uint32_t x = t->heap[a], y = t->heap[b];
    t->heap[a] = y; t->heap[b] = x;
    tent(t, y)->hpos = a;
    tent(t, x)->hpos = b;
}

static void heap_down(ttab_t *t, uint32_t p) {
    for (;;) {
        uint32_t l = 2 * p + 1, r = l + 1, m = p;
        if (l < t->used && tent(t, t->heap[l])->count < tent(t, t->heap[m])->count) m = l;
        if (r < t->used && tent(t, t->heap[r])->count < tent(t, t->heap[m])->count) m = r;
        if (m == p) return;
        heap_swap(t, p, m);
        p = m;
    }
}

static void heap_up(ttab_t *t, uint32_t p) {
    while (p > 0) {
        uint32_t par = (p - 1) / 2;
        if (tent(t, t->heap[p])->count >= tent(t, t->heap[par])->count) return;
        heap_swap(t, p, par);
        p = par;
    }
}

/* removes the index slot i (backward-shift deletion: no tombstones) */
static void index_remove(ttab_t *t, uint32_t i) {
    uint32_t mask = t->nslots - 1, j = i;
    for (;;) {
        j = (j + 1) & mask;
        uint32_t v = t->slots[j];
        if (v == 0) break;
        uint32_t k = (uint32_t)tent(t, v - 1)->hash & mask; /* where v would like to be */
        if (i <= j ? (i < k && k <= j) : (i < k || k <= j)) continue; /* v is between i and j: it stays */
        t->slots[i] = v;
        i = j;
    }
    t->slots[i] = 0;
}

static void ttab_add(ttab_t *t, const uint8_t *key, size_t klen, const uint64_t hk[2]) {
    t->total++;
    if (klen > t->keymax) return; /* cannot happen: the keys are built to fit */
    uint64_t h = dns_siphash24(key, klen, hk);
    uint32_t mask = t->nslots - 1;
    uint32_t i = (uint32_t)h & mask;
    for (;;) {
        uint32_t v = t->slots[i];
        if (v == 0) break;
        tent_t *e = tent(t, v - 1);
        if (e->hash == h && e->klen == klen && (klen == 0 || memcmp(e->key, key, klen) == 0)) {
            e->count++;
            heap_down(t, e->hpos);
            return;
        }
        i = (i + 1) & mask;
    }
    uint32_t idx;
    if (t->used < t->cap) {
        idx = t->used++;
        t->heap[idx] = idx;
        tent(t, idx)->hpos = idx;
        tent(t, idx)->count = 0;
        tent(t, idx)->err = 0;
    } else { /* replace the key with the smallest count */
        idx = t->heap[0];
        tent_t *old = tent(t, idx);
        uint32_t j = (uint32_t)old->hash & mask;
        while (t->slots[j] != idx + 1) j = (j + 1) & mask;
        index_remove(t, j);
        i = (uint32_t)h & mask; /* the free slot of the new key: probe again, the index changed */
        while (t->slots[i] != 0) i = (i + 1) & mask;
        old->err = old->count;
        t->evictions++;
    }
    tent_t *e = tent(t, idx);
    e->hash = h;
    e->klen = (uint16_t)klen;
    if (klen) memcpy(e->key, key, klen);
    e->count++;
    t->slots[i] = idx + 1;
    if (e->err == 0 && e->count == 1) heap_up(t, e->hpos);
    else heap_down(t, e->hpos);
}

/* ====================================================================== */
/* aggregator                                                              */

typedef struct { uint8_t len; uint8_t wire[]; } zname_t;

struct tapstat {
    tapstat_opts_t o;
    ttab_t tab[TAPSTAT_DIMS];
    zname_t **zset;      /* open-addressing set of the -z names */
    uint32_t zslots;     /* power of two, 0 = none */
    size_t nzones;
    uint64_t frames, bad_frames, queries, responses, other_msgs, no_question, malformed;
};

static const size_t dim_keymax[TAPSTAT_DIMS] = { 255, 255, 2, 1, 17 };

tapstat_t *tapstat_new(const tapstat_opts_t *o) {
    if (!o || o->topk == 0 || o->topk > TAPSTAT_MAX_TOPK) return NULL;
    if (o->v4_prefix < 0 || o->v4_prefix > 32 || o->v6_prefix < 0 || o->v6_prefix > 128) return NULL;
    if (o->count_type != 1 && o->count_type != 2) return NULL;
    tapstat_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->o = *o;
    for (int d = 0; d < TAPSTAT_DIMS; d++) {
        /* the rcode and qtype tables never hold more than 16 / 65536 keys; the others get the whole -k */
        uint32_t cap = o->topk;
        if (d == TAPSTAT_D_RCODE && cap > 16) cap = 16;
        if (!ttab_init(&s->tab[d], cap, dim_keymax[d])) {
            for (int j = 0; j <= d; j++) ttab_free(&s->tab[j]);
            free(s);
            return NULL;
        }
    }
    return s;
}

void tapstat_free(tapstat_t *s) {
    if (!s) return;
    for (int d = 0; d < TAPSTAT_DIMS; d++) ttab_free(&s->tab[d]);
    for (uint32_t i = 0; i < s->zslots; i++) free(s->zset[i]);
    free(s->zset);
    free(s);
}

size_t tapstat_zone_count(const tapstat_t *s) { return s->nzones; }
uint64_t tapstat_frames(const tapstat_t *s) { return s->frames; }
uint64_t tapstat_bad_frames(const tapstat_t *s) { return s->bad_frames; }

static zname_t *zset_find(const tapstat_t *s, const uint8_t *w, size_t n) {
    if (s->zslots == 0 || n == 0 || n > 255) return NULL;
    uint32_t mask = s->zslots - 1;
    uint32_t i = (uint32_t)dns_siphash24(w, n, s->o.hash_key) & mask;
    while (s->zset[i]) {
        if (s->zset[i]->len == n && memcmp(s->zset[i]->wire, w, n) == 0) return s->zset[i];
        i = (i + 1) & mask;
    }
    return NULL;
}

static bool zset_insert(tapstat_t *s, zname_t *z) {
    if (s->nzones * 2 >= s->zslots) { /* grow: at most half full */
        uint32_t ns = s->zslots ? s->zslots * 2 : 64;
        zname_t **nz = calloc(ns, sizeof(*nz));
        if (!nz) return false;
        for (uint32_t i = 0; i < s->zslots; i++) {
            zname_t *e = s->zset[i];
            if (!e) continue;
            uint32_t j = (uint32_t)dns_siphash24(e->wire, e->len, s->o.hash_key) & (ns - 1);
            while (nz[j]) j = (j + 1) & (ns - 1);
            nz[j] = e;
        }
        free(s->zset);
        s->zset = nz;
        s->zslots = ns;
    }
    uint32_t j = (uint32_t)dns_siphash24(z->wire, z->len, s->o.hash_key) & (s->zslots - 1);
    while (s->zset[j]) j = (j + 1) & (s->zslots - 1);
    s->zset[j] = z;
    s->nzones++;
    return true;
}

bool tapstat_add_zone(tapstat_t *s, const char *name) {
    uint8_t w[256];
    size_t n = 0;
    if (!tapstat_name_to_wire(name, w, &n)) return false;
    if (zset_find(s, w, n)) return true; /* listed twice */
    zname_t *z = malloc(sizeof(*z) + n);
    if (!z) return false;
    z->len = (uint8_t)n;
    memcpy(z->wire, w, n);
    if (!zset_insert(s, z)) { free(z); return false; }
    return true;
}

void tapstat_reset(tapstat_t *s) {
    for (int d = 0; d < TAPSTAT_DIMS; d++) ttab_reset(&s->tab[d]);
    s->frames = s->bad_frames = s->queries = s->responses = s->other_msgs = s->no_question = s->malformed = 0;
}

static void client_key(const tapstat_t *s, const uint8_t *a, size_t alen, uint8_t key[17], size_t *klen) {
    int bits;
    if (alen == 16 && memcmp(a, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) { a += 12; alen = 4; } /* ::ffff:a.b.c.d */
    if (alen == 4) { key[0] = 4; bits = s->o.v4_prefix; }
    else { key[0] = 6; bits = s->o.v6_prefix; }
    for (size_t i = 0; i < alen; i++) {
        int rem = bits - (int)i * 8;
        uint8_t m = rem >= 8 ? 0xff : rem <= 0 ? 0x00 : (uint8_t)(0xff << (8 - rem));
        key[1 + i] = a[i] & m;
    }
    *klen = 1 + alen;
}

void tapstat_frame(tapstat_t *s, const uint8_t *frame, size_t len) {
    s->frames++;
    dnstap_msg_t m;
    if (!dnstap_decode_message(frame, len, &m)) { s->bad_frames++; return; }

    const uint8_t *w;
    size_t wl;
    if (m.message_type == 1) { /* AUTH_QUERY */
        s->queries++;
        w = m.query_msg ? m.query_msg : m.response_msg;
        wl = m.query_msg ? m.query_msg_len : m.response_msg_len;
    } else if (m.message_type == 2) { /* AUTH_RESPONSE */
        s->responses++;
        w = m.response_msg ? m.response_msg : m.query_msg;
        wl = m.response_msg ? m.response_msg_len : m.query_msg_len;
    } else {
        s->other_msgs++;
        return;
    }
    bool counted = ((int)m.message_type == s->o.count_type);
    if (!w || wl < 12) { s->bad_frames++; return; }

    if (m.message_type == 2) { /* RFC 1035 4.1.1: RCODE is the low four bits of the fourth header byte (no EDNS extension) */
        uint8_t rc = w[3] & 0x0f;
        ttab_add(&s->tab[TAPSTAT_D_RCODE], &rc, 1, s->o.hash_key);
    }
    if (!counted) return;

    if (m.has_query_addr && (m.query_addr_len == 4 || m.query_addr_len == 16)) {
        uint8_t key[17];
        size_t kl;
        client_key(s, m.query_addr, m.query_addr_len, key, &kl);
        ttab_add(&s->tab[TAPSTAT_D_CLIENT], key, kl, s->o.hash_key);
    }

    uint16_t qdcount = (uint16_t)(((unsigned)w[4] << 8) | w[5]);
    if (qdcount == 0) { s->no_question++; return; }

    /* the question: RFC 1035 4.1.2.  No compression in a question; a pointer or a length over 63 is malformed */
    uint8_t nm[255];
    size_t nlen = 0, pos = 12;
    uint8_t bound[128];  /* offsets in nm of the labels, the root label included */
    size_t nb = 0;
    for (;;) {
        if (pos >= wl) { s->malformed++; return; }
        uint8_t l = w[pos++];
        if (l > 63 || nb >= sizeof(bound) || nlen + 1 + l > sizeof(nm)) { s->malformed++; return; }
        bound[nb++] = (uint8_t)nlen;
        nm[nlen++] = l;
        if (l == 0) break;
        if (l > wl - pos) { s->malformed++; return; }
        for (uint8_t i = 0; i < l; i++) {
            uint8_t c = w[pos++];
            nm[nlen++] = (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
        }
    }
    if (wl - pos < 4) { s->malformed++; return; }
    uint8_t qt[2] = { w[pos], w[pos + 1] };

    /* zone: the longest listed suffix (the first label boundary that is in the set); without -z the zone the server
     * put in the message (query_zone, field 11); else "other" (an empty key) */
    const uint8_t *zk = (const uint8_t *)"";
    size_t zl = 0;
    if (s->nzones > 0) {
        for (size_t b = 0; b < nb; b++) {
            zname_t *z = zset_find(s, nm + bound[b], nlen - bound[b]);
            if (z) { zk = z->wire; zl = z->len; break; }
        }
    } else if (m.query_zone && m.query_zone_len > 0 && m.query_zone_len <= 255) {
        uint8_t zn[255];
        size_t p = 0, o = 0;
        bool ok = false;
        while (p < m.query_zone_len) {
            uint8_t l = m.query_zone[p++];
            if (l > 63 || l > m.query_zone_len - p) break;
            zn[o++] = l;
            if (l == 0) { ok = (p == m.query_zone_len); break; }
            for (uint8_t i = 0; i < l; i++) { uint8_t c = m.query_zone[p++]; zn[o++] = (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c; }
        }
        if (ok) { ttab_add(&s->tab[TAPSTAT_D_ZONE], zn, o, s->o.hash_key); zk = NULL; }
    }
    if (zk) ttab_add(&s->tab[TAPSTAT_D_ZONE], zk, zl, s->o.hash_key);

    ttab_add(&s->tab[TAPSTAT_D_QNAME], nm, nlen, s->o.hash_key);
    ttab_add(&s->tab[TAPSTAT_D_QTYPE], qt, 2, s->o.hash_key);
}

/* ====================================================================== */
/* output                                                                  */

static const char *const dim_name[TAPSTAT_DIMS] = { "zone", "qname", "qtype", "rcode", "client" };

static int ent_cmp(const void *a, const void *b) {
    const tent_t *x = *(const tent_t *const *)a, *y = *(const tent_t *const *)b;
    if (x->count != y->count) return x->count > y->count ? -1 : 1;
    size_t n = x->klen < y->klen ? x->klen : y->klen;
    int c = n ? memcmp(x->key, y->key, n) : 0;
    if (c) return c;
    return (int)x->klen - (int)y->klen;
}

/* the text of a key of dimension d */
static void key_text(const tapstat_t *s, int d, const tent_t *e, char *out, size_t cap) {
    char tmp[16];
    out[0] = 0;
    switch (d) {
    case TAPSTAT_D_ZONE:
        if (e->klen == 0) snprintf(out, cap, "other");
        else if (!wire_to_text(e->key, e->klen, out, cap)) snprintf(out, cap, "(invalid)");
        break;
    case TAPSTAT_D_QNAME:
        if (!wire_to_text(e->key, e->klen, out, cap)) snprintf(out, cap, "(invalid)");
        break;
    case TAPSTAT_D_QTYPE:
        snprintf(out, cap, "%s", tapstat_qtype_name((uint16_t)((e->key[0] << 8) | e->key[1]), tmp, sizeof(tmp)));
        break;
    case TAPSTAT_D_RCODE:
        snprintf(out, cap, "%s", tapstat_rcode_name(e->key[0], tmp, sizeof(tmp)));
        break;
    default: { /* client */
        char a[INET6_ADDRSTRLEN] = "?";
        if (e->key[0] == 4 && e->klen == 5) {
            inet_ntop(AF_INET, e->key + 1, a, sizeof(a));
            snprintf(out, cap, "%s/%d", a, s->o.v4_prefix);
        } else if (e->key[0] == 6 && e->klen == 17) {
            inet_ntop(AF_INET6, e->key + 1, a, sizeof(a));
            snprintf(out, cap, "%s/%d", a, s->o.v6_prefix);
        } else snprintf(out, cap, "(invalid)");
    }
    }
}

/* escape " \ and control characters for a JSON string or a Prometheus label value */
static void put_escaped(FILE *fp, const char *s, bool json) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { fputc('\\', fp); fputc(c, fp); }
        else if (c == '\n') fputs("\\n", fp);
        else if (c < 0x20 || c == 0x7f) { if (json) fprintf(fp, "\\u%04x", c); else fputc('?', fp); }
        else fputc(c, fp);
    }
}

static void iso_time(time_t t, char *out, size_t cap) {
    struct tm tmv;
    if (!gmtime_r(&t, &tmv) || strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) snprintf(out, cap, "?");
}

void tapstat_render(const tapstat_t *s, tapstat_format_t fmt, FILE *fp, time_t start, time_t end, double secs) {
    char t0[40], t1[40], text[1100];
    iso_time(start, t0, sizeof(t0));
    iso_time(end, t1, sizeof(t1));

    /* the kept entries of every dimension, most frequent first */
    const tent_t **sorted[TAPSTAT_DIMS] = { 0 };
    for (int d = 0; d < TAPSTAT_DIMS; d++) {
        const ttab_t *t = &s->tab[d];
        if (t->used == 0) continue;
        sorted[d] = malloc((size_t)t->used * sizeof(*sorted[d]));
        if (!sorted[d]) continue;
        for (uint32_t i = 0; i < t->used; i++) sorted[d][i] = (const tent_t *)(const void *)(t->ents + (size_t)i * t->stride);
        qsort(sorted[d], t->used, sizeof(*sorted[d]), ent_cmp);
    }

    if (fmt == TAPSTAT_TEXT) {
        fprintf(fp, "karidns-tapstat %s - %s (%.1f s)\n", t0, t1, secs);
        fprintf(fp, "frames %llu  bad %llu  queries %llu  responses %llu  other-messages %llu  no-question %llu  malformed %llu\n",
                (unsigned long long)s->frames, (unsigned long long)s->bad_frames, (unsigned long long)s->queries,
                (unsigned long long)s->responses, (unsigned long long)s->other_msgs, (unsigned long long)s->no_question,
                (unsigned long long)s->malformed);
        for (int d = 0; d < TAPSTAT_DIMS; d++) {
            const ttab_t *t = &s->tab[d];
            fprintf(fp, "%s: events %llu  keys %u  evictions %llu\n", dim_name[d], (unsigned long long)t->total, t->used,
                    (unsigned long long)t->evictions);
            uint32_t n = t->used;
            if (s->o.show && n > s->o.show) n = s->o.show;
            for (uint32_t i = 0; sorted[d] && i < n; i++) {
                key_text(s, d, sorted[d][i], text, sizeof(text));
                fprintf(fp, "  %10llu  %s", (unsigned long long)sorted[d][i]->count, text);
                if (sorted[d][i]->err) fprintf(fp, "  (may be over-counted by up to %llu)", (unsigned long long)sorted[d][i]->err);
                fputc('\n', fp);
            }
        }
    } else if (fmt == TAPSTAT_JSON) {
        fprintf(fp, "{\"start\":\"%s\",\"end\":\"%s\",\"seconds\":%.3f,\"frames\":%llu,\"bad_frames\":%llu,\"queries\":%llu,"
                    "\"responses\":%llu,\"other_messages\":%llu,\"no_question\":%llu,\"malformed\":%llu,\"dimensions\":{",
                t0, t1, secs, (unsigned long long)s->frames, (unsigned long long)s->bad_frames, (unsigned long long)s->queries,
                (unsigned long long)s->responses, (unsigned long long)s->other_msgs, (unsigned long long)s->no_question,
                (unsigned long long)s->malformed);
        for (int d = 0; d < TAPSTAT_DIMS; d++) {
            const ttab_t *t = &s->tab[d];
            fprintf(fp, "%s\"%s\":{\"events\":%llu,\"keys\":%u,\"evictions\":%llu,\"top\":[", d ? "," : "", dim_name[d],
                    (unsigned long long)t->total, t->used, (unsigned long long)t->evictions);
            uint32_t n = t->used;
            if (s->o.show && n > s->o.show) n = s->o.show;
            for (uint32_t i = 0; sorted[d] && i < n; i++) {
                key_text(s, d, sorted[d][i], text, sizeof(text));
                fprintf(fp, "%s{\"key\":\"", i ? "," : "");
                put_escaped(fp, text, true);
                fprintf(fp, "\",\"count\":%llu,\"error\":%llu}", (unsigned long long)sorted[d][i]->count, (unsigned long long)sorted[d][i]->err);
            }
            fputs("]}", fp);
        }
        fputs("}}\n", fp);
    } else {
        /* Prometheus text exposition format: gauges, because the interval is reset after every summary */
        fputs("# HELP karidns_tapstat_interval_seconds Length of the interval these values cover.\n"
              "# TYPE karidns_tapstat_interval_seconds gauge\n", fp);
        fprintf(fp, "karidns_tapstat_interval_seconds %.3f\n", secs);
        fputs("# HELP karidns_tapstat_last_summary_timestamp_seconds Unix time the interval ended.\n"
              "# TYPE karidns_tapstat_last_summary_timestamp_seconds gauge\n", fp);
        fprintf(fp, "karidns_tapstat_last_summary_timestamp_seconds %lld\n", (long long)end);
        fputs("# HELP karidns_tapstat_messages Frames of the interval by kind.\n# TYPE karidns_tapstat_messages gauge\n", fp);
        fprintf(fp, "karidns_tapstat_messages{kind=\"frames\"} %llu\n", (unsigned long long)s->frames);
        fprintf(fp, "karidns_tapstat_messages{kind=\"bad\"} %llu\n", (unsigned long long)s->bad_frames);
        fprintf(fp, "karidns_tapstat_messages{kind=\"query\"} %llu\n", (unsigned long long)s->queries);
        fprintf(fp, "karidns_tapstat_messages{kind=\"response\"} %llu\n", (unsigned long long)s->responses);
        fprintf(fp, "karidns_tapstat_messages{kind=\"other\"} %llu\n", (unsigned long long)s->other_msgs);
        fprintf(fp, "karidns_tapstat_messages{kind=\"no_question\"} %llu\n", (unsigned long long)s->no_question);
        fprintf(fp, "karidns_tapstat_messages{kind=\"malformed\"} %llu\n", (unsigned long long)s->malformed);
        fputs("# HELP karidns_tapstat_events Events counted per dimension in the interval, and those whose key replaced another key in the full table.\n"
              "# TYPE karidns_tapstat_events gauge\n", fp);
        for (int d = 0; d < TAPSTAT_DIMS; d++) {
            fprintf(fp, "karidns_tapstat_events{dimension=\"%s\",kind=\"total\"} %llu\n", dim_name[d], (unsigned long long)s->tab[d].total);
            fprintf(fp, "karidns_tapstat_events{dimension=\"%s\",kind=\"evictions\"} %llu\n", dim_name[d], (unsigned long long)s->tab[d].evictions);
        }
        fputs("# HELP karidns_tapstat_count Count of a key in the interval (the most frequent keys of each dimension).\n"
              "# TYPE karidns_tapstat_count gauge\n", fp);
        for (int d = 0; d < TAPSTAT_DIMS; d++) {
            const ttab_t *t = &s->tab[d];
            uint32_t n = t->used;
            if (s->o.show && n > s->o.show) n = s->o.show;
            for (uint32_t i = 0; sorted[d] && i < n; i++) {
                key_text(s, d, sorted[d][i], text, sizeof(text));
                fprintf(fp, "karidns_tapstat_count{dimension=\"%s\",key=\"", dim_name[d]);
                put_escaped(fp, text, false);
                fprintf(fp, "\"} %llu\n", (unsigned long long)sorted[d][i]->count);
            }
        }
        fputs("# HELP karidns_tapstat_count_error The count of a key may be too high by up to this much (Space-Saving error bound).\n"
              "# TYPE karidns_tapstat_count_error gauge\n", fp);
        for (int d = 0; d < TAPSTAT_DIMS; d++) {
            const ttab_t *t = &s->tab[d];
            uint32_t n = t->used;
            if (s->o.show && n > s->o.show) n = s->o.show;
            for (uint32_t i = 0; sorted[d] && i < n; i++) {
                if (!sorted[d][i]->err) continue;
                key_text(s, d, sorted[d][i], text, sizeof(text));
                fprintf(fp, "karidns_tapstat_count_error{dimension=\"%s\",key=\"", dim_name[d]);
                put_escaped(fp, text, false);
                fprintf(fp, "\"} %llu\n", (unsigned long long)sorted[d][i]->err);
            }
        }
    }
    for (int d = 0; d < TAPSTAT_DIMS; d++) free(sorted[d]);
}

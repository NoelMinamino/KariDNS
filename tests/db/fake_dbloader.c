/*
 * fake_dbloader.c - a stand-in for karidns-dbloader that speaks KDB1 wrongly (tests/run_db_loader_lifecycle_test.sh,
 * tests/run_db_hostile_loader_test.sh).
 *
 *   fake_dbloader -s FD MODE
 *
 * It sends a correct HELLO (version 1, driver sqlite3), reads the CONFIG, and then misbehaves.  Modes of the
 * lifecycle test (the stream is wrong; the Backend closes it):
 *   bad-magic  a message whose magic is not "KDB1"
 *   bad-order  ZONE_END without BATCH_BEGIN / ZONE_BEGIN (a message type that is not legal in the state)
 *   bad-view   BATCH_BEGIN followed by a ZONE_BEGIN naming a view index beyond the configured views
 *   silent     nothing more (the Backend must keep waiting without harm)
 * Modes of the hostile loader test (B4b), each one batch of ok1.test, <the bad zone bad.test>, ok2.test:
 *   good             no bad zone (the sanity run: both zones are installed)
 *   owner-outside    bad.test contains an A record with an owner outside the zone      -> zone rejected
 *   anc-short        ANCOUNT says 5 RRs, the message holds 3                            -> zone rejected
 *   garbage-rr       a valid frame whose DNS message is garbage after the header        -> zone rejected
 *   no-final-soa     SOA, A and no closing SOA                                          -> zone rejected
 *   two-soa          a second SOA with another serial in the middle                     -> zone rejected
 *   soa-subdomain    the first SOA belongs to sub.bad.test, not the apex                -> zone rejected
 *   trailing-rr      a record after the closing SOA                                     -> zone rejected
 *   later-message    a record in a second ZONE_DATA after the closing SOA               -> zone rejected
 *   secondary-kind   zone_kind secondary, rr_count 0, no settings (B7b: no masters)              -> zone rejected
 *   secondary-data   zone_kind secondary with rr_count 2 and ZONE_DATA                           -> protocol error
 *   secondary-flag   zone_kind secondary with the presigned flag                                 -> zone rejected
 *   secondary-host   secondary whose masters statement names a host name                         -> zone rejected
 *   secondary-prim   a primary zone whose settings name masters                                   -> zone rejected
 *   secondary-ok     secondary with masters { 127.0.0.1 port 1; } (the transfer fails, the zone is registered) -> applied
 *   catalog-ok       zone_kind catalog (a CONSUMER) with masters                                  -> applied
 *   ext-no-flag      a state record (CLASS 65302) in a zone without the extended flag    -> zone rejected
 *   ext-trusted      an ECS_TRUSTED record (settings only)                               -> zone rejected
 *   ext-bad-def      a malformed LOC_TAGDEF                                              -> zone rejected
 *   ext-bad-locdef   a malformed TINYDNS_LOCDEF                                          -> zone rejected
 *   ext-bad-wrap     a TINYDNS_WRAP shorter than its fixed part                          -> zone rejected
 *   ext-long-tag     a LOC_STATE tag of 70 octets                                        -> zone rejected
 *   ext-flag-bit     a reserved zone flag bit (16: bit 3 is the fetch summary since D1a)                                          -> protocol error
 *   ext-ok           state records and the extended + tinydns flags                      -> applied
 *   non-in-class     an RR of class CH                                                  -> zone rejected
 *   again            ok1.test twice in one batch (the second replaces the first)       -> both applied
 *   slow             ok1.test, a pause of 3 s, ok2.test: ok1.test must answer during the pause (the view delta runs
 *                    at least once a second, design 4.4)
 *   delete-unknown   ZONE_DELETE of a zone that is not registered                       -> "unchanged"
 *   huge-frame       a ZONE_DATA body of 70000 bytes                                    -> protocol error
 *   end-count        ZONE_END with another RR count than ZONE_BEGIN                     -> protocol error
 *   begin-count      ZONE_BEGIN declares 9 RRs, the data has 3                          -> protocol error
 *   zero-ancount     a ZONE_DATA message with ANCOUNT 0                                 -> protocol error
 *   opt-twice        ARCOUNT 1 in the second ZONE_DATA of a zone                        -> protocol error
 *   unknown-tag      ZONE_BEGIN with an unknown TLV tag                                 -> protocol error
 * Modes of the version 3 SOA set (B8t-2: SOA_SET, the apex SOA RRs as wrapped body RRs):
 *   soaset-ok        two SOAs (one with the location in), the frame is the reference SOA     -> applied
 *   soaset-serial    a body SOA with another serial than the frame                          -> zone rejected
 *   soaset-count     SOA_SET announces 3, the body has 2                                    -> zone rejected
 *   soaset-late      SOA_SET after a data record                                            -> zone rejected
 *   soaset-dup       two body SOAs for the same clients (both location in)                  -> zone rejected
 *   soaset-frame     the opening SOA is not the reference SOA (another refresh)             -> zone rejected
 * Modes of the settings part (B7a):
 *   settings-key     settings text naming a TSIG key karidns.conf does not define          -> zone rejected
 *   settings-include settings text with an include statement                               -> zone rejected
 *   settings-file    settings text with a file statement                                   -> zone rejected
 *   settings-slave   settings text with type / masters statements                          -> zone rejected
 *   settings-brace   settings text with a stray closing brace                              -> zone rejected
 *   profile-missing  ZONE_BEGIN names a profile that was not sent                          -> zone rejected
 *   profile-flood    270 PROFILE messages of 64000 bytes (more than the Backend keeps)    -> protocol error
 *   settings-ok      settings text and a profile the Backend accepts                       -> both applied
 * Then it waits until the Backend closes the stream and exits 0.  Hand-made bytes, no library: the encoder of
 * dns_db_stream.c would only make correct messages.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }

static size_t tlv(uint8_t *b, uint16_t tag, const void *v, uint16_t n) {
    put16(b, tag);
    put16(b + 2, n);
    memcpy(b + 4, v, n);
    return 4u + n;
}

static uint8_t g_buf[80000];

static void send_msg(int fd, const char *magic, uint16_t type, const uint8_t *body, size_t n) {
    memcpy(g_buf, magic, 4);
    put16(g_buf + 4, type);
    put16(g_buf + 6, 0);
    put32(g_buf + 8, (uint32_t)n);
    memcpy(g_buf + 12, body, n);
    size_t off = 0, len = 12 + n;
    while (off < len) {
        ssize_t w = write(fd, g_buf + off, len - off);
        if (w <= 0) exit(0);
        off += (size_t)w;
    }
}

/* ---------------------------------------------------------------- DNS message pieces */
typedef struct {
    uint8_t b[4096];
    size_t n;
    uint16_t an;
} dm_t;

static void dm_init(dm_t *m) {
    memset(m, 0, sizeof(*m));
    m->b[2] = 0x84;                          /* QR, AA */
    m->n = 12;
}

static size_t wname(uint8_t *p, const char *name) {
    size_t n = 0;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        p[n++] = (uint8_t)l;
        memcpy(p + n, s, l);
        n += l;
        if (!dot) break;
        s = dot + 1;
    }
    p[n++] = 0;
    return n;
}

static void dm_rr(dm_t *m, const char *owner, uint16_t type, uint16_t cls, const uint8_t *rd, size_t rdlen) {
    m->n += wname(m->b + m->n, owner);
    put16(m->b + m->n, type); m->n += 2;
    put16(m->b + m->n, cls); m->n += 2;
    put32(m->b + m->n, 300); m->n += 4;
    put16(m->b + m->n, (uint16_t)rdlen); m->n += 2;
    memcpy(m->b + m->n, rd, rdlen);
    m->n += rdlen;
    m->an++;
    put16(m->b + 6, m->an);
}

static void dm_soa_ex(dm_t *m, const char *zone, uint32_t serial, uint32_t refresh) {
    uint8_t rd[600];
    char mn[300], rn[300];
    snprintf(mn, sizeof(mn), "ns.%s", zone);
    snprintf(rn, sizeof(rn), "host.%s", zone);
    size_t n = wname(rd, mn);
    n += wname(rd + n, rn);
    put32(rd + n, serial); put32(rd + n + 4, refresh); put32(rd + n + 8, 600); put32(rd + n + 12, 86400);
    put32(rd + n + 16, 300);
    dm_rr(m, zone, 6, 1, rd, n + 20);
}

static void dm_soa(dm_t *m, const char *zone, uint32_t serial) { dm_soa_ex(m, zone, serial, 3600); }

/* B8t-2: a SOA of a SOA set: TYPE 65406 around the SOA, with the tinydns location loc ("" = none) */
static void dm_soa_set_member(dm_t *m, const char *zone, uint32_t serial, uint32_t refresh, const char *loc) {
    uint8_t rd[600], w[700];
    char mn[300], rn[300];
    snprintf(mn, sizeof(mn), "ns.%s", zone);
    snprintf(rn, sizeof(rn), "host.%s", zone);
    size_t n = wname(rd, mn);
    n += wname(rd + n, rn);
    put32(rd + n, serial); put32(rd + n + 4, refresh); put32(rd + n + 8, 600); put32(rd + n + 12, 86400);
    put32(rd + n + 16, 300);
    n += 20;
    memset(w, 0, sizeof(w));
    put16(w, 6); put16(w + 2, 1); put32(w + 4, 300);                 /* the original TYPE, CLASS, TTL */
    w[8] = (uint8_t)loc[0]; w[9] = loc[0] ? (uint8_t)loc[1] : 0;     /* the location, no time stamp */
    put16(w + 19, (uint16_t)n);
    memcpy(w + 21, rd, n);
    dm_rr(m, zone, 65406, 65302, w, 21 + n);
}

static void dm_a(dm_t *m, const char *owner, uint8_t last) {
    uint8_t rd[4] = { 192, 0, 2, last };
    dm_rr(m, owner, 1, 1, rd, 4);
}

static void dm_ns(dm_t *m, const char *owner, const char *target) {
    uint8_t rd[300];
    dm_rr(m, owner, 2, 1, rd, wname(rd, target));
}

/* ---------------------------------------------------------------- KDB1 pieces */
static uint64_t g_batch = 1;
static uint32_t g_nzones, g_ndel;

static void batch_begin(int fd) {
    uint8_t b[64], kind = 0, zero8[8] = { 0 };
    size_t n = 0;
    uint8_t id[8];
    put64(id, g_batch);
    n += tlv(b + n, 1, id, 8);
    n += tlv(b + n, 2, &kind, 1);
    n += tlv(b + n, 3, zero8, 8);
    send_msg(fd, "KDB1", 3, b, n);
}

static void batch_end(int fd, uint32_t deleted) {
    uint8_t b[64], id[8], v[4];
    size_t n = 0;
    put64(id, g_batch);
    n += tlv(b + n, 1, id, 8);
    put32(v, g_nzones); n += tlv(b + n, 2, v, 4);
    put32(v, 0); n += tlv(b + n, 3, v, 4);
    put32(v, deleted); n += tlv(b + n, 4, v, 4);
    send_msg(fd, "KDB1", 11, b, n);
}

static uint32_t g_zb_serial = 1;              /* the serial ZONE_BEGIN declares (the SOA serial of the zone) */

static void zone_begin_ex(int fd, const char *zone, uint8_t kind, uint32_t flags, uint64_t declared, uint16_t extra_tag,
                          const char *settings, const char *profile) {
    uint8_t b[1024], view[2] = { 0, 0 }, serial[4], fl[4], rrs[8], digest[32] = { 0 }, src[8] = { 0 };
    char canon[300];
    snprintf(canon, sizeof(canon), "%s.", zone);
    put32(serial, g_zb_serial);
    put32(fl, flags);
    put64(rrs, declared);
    put64(src, 100 + g_nzones);
    size_t n = 0;
    n += tlv(b + n, 1, view, 2);
    n += tlv(b + n, 2, canon, (uint16_t)strlen(canon));
    n += tlv(b + n, 3, src, 8);
    n += tlv(b + n, 4, &kind, 1);
    n += tlv(b + n, 5, serial, 4);
    n += tlv(b + n, 6, fl, 4);
    n += tlv(b + n, 7, rrs, 8);
    n += tlv(b + n, 8, digest, 32);
    if (settings) n += tlv(b + n, 9, settings, (uint16_t)strlen(settings));
    if (profile) n += tlv(b + n, 10, profile, (uint16_t)strlen(profile));
    if (extra_tag) n += tlv(b + n, extra_tag, "x", 1);
    send_msg(fd, "KDB1", 4, b, n);
}

static void zone_begin(int fd, const char *zone, uint8_t kind, uint32_t flags, uint64_t declared, uint16_t extra_tag) {
    zone_begin_ex(fd, zone, kind, flags, declared, extra_tag, NULL, NULL);
}

static void zone_data(int fd, const dm_t *m) { send_msg(fd, "KDB1", 5, m->b, m->n); }

static void zone_end(int fd, uint64_t count) {
    uint8_t b[16];
    put64(b + 4, count);
    put16(b, 1);
    put16(b + 2, 8);
    send_msg(fd, "KDB1", 6, b, 12);
    g_nzones++;
}

/* a correct zone: SOA, NS, 2 A, SOA */
static void good_zone(int fd, const char *zone, uint32_t serial) {
    dm_t m;
    char ns[300], h1[300], h2[300];
    snprintf(ns, sizeof(ns), "ns.%s", zone);
    snprintf(h1, sizeof(h1), "www.%s", zone);
    snprintf(h2, sizeof(h2), "mail.%s", zone);
    dm_init(&m);
    g_zb_serial = serial;
    dm_soa(&m, zone, serial);
    dm_ns(&m, zone, ns);
    dm_a(&m, ns, 1);
    dm_a(&m, h1, 10);
    dm_a(&m, h2, 25);
    dm_soa(&m, zone, serial);
    zone_begin(fd, zone, 0, 0, 6, 0);
    zone_data(fd, &m);
    zone_end(fd, 6);
}

/* the bad zone of a mode: bad.test */
static void bad_zone(int fd, const char *mode) {
    dm_t m;
    const char *z = "bad.test";
    dm_init(&m);
    g_zb_serial = 5;
    if (strcmp(mode, "owner-outside") == 0) {
        dm_soa(&m, z, 5); dm_a(&m, "host.other.test", 1); dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "anc-short") == 0) {
        dm_soa(&m, z, 5); dm_a(&m, "www.bad.test", 1); dm_soa(&m, z, 5);
        put16(m.b + 6, 5);
        zone_begin(fd, z, 0, 0, 5, 0); zone_data(fd, &m); zone_end(fd, 5);
    } else if (strcmp(mode, "garbage-rr") == 0) {
        m.b[7] = 3;
        for (size_t i = 12; i < 90; i++) m.b[i] = (uint8_t)(i * 37 + 11);
        m.n = 90;
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "no-final-soa") == 0) {
        dm_soa(&m, z, 5); dm_a(&m, "www.bad.test", 1);
        zone_begin(fd, z, 0, 0, 2, 0); zone_data(fd, &m); zone_end(fd, 2);
    } else if (strcmp(mode, "two-soa") == 0) {
        dm_soa(&m, z, 5); dm_soa(&m, z, 6); dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "soa-subdomain") == 0) {
        dm_soa(&m, "sub.bad.test", 5); dm_a(&m, "www.bad.test", 1); dm_soa(&m, "sub.bad.test", 5);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "trailing-rr") == 0) {
        dm_soa(&m, z, 5); dm_soa(&m, z, 5); dm_a(&m, "www.bad.test", 1);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "later-message") == 0) {
        dm_t m2;
        dm_soa(&m, z, 5); dm_soa(&m, z, 5);
        dm_init(&m2); dm_a(&m2, "www.bad.test", 1);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_data(fd, &m2); zone_end(fd, 3);
    } else if (strcmp(mode, "secondary-kind") == 0) {
        zone_begin(fd, z, 1, 0, 0, 0); zone_end(fd, 0);
    } else if (strcmp(mode, "secondary-data") == 0) {
        dm_soa(&m, z, 5); dm_soa(&m, z, 5);
        zone_begin_ex(fd, z, 1, 0, 2, 0, "masters { 192.0.2.1; };", NULL); zone_data(fd, &m); zone_end(fd, 2);
    } else if (strcmp(mode, "secondary-flag") == 0) {
        zone_begin_ex(fd, z, 1, 1, 0, 0, "masters { 192.0.2.1; };", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "secondary-host") == 0) {
        zone_begin_ex(fd, z, 1, 0, 0, 0, "masters { ns1.example.net; };", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "secondary-prim") == 0) {
        dm_soa(&m, z, 5); dm_a(&m, "www.bad.test", 1); dm_soa(&m, z, 5);
        zone_begin_ex(fd, z, 0, 0, 3, 0, "masters { 192.0.2.1; };", NULL); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "secondary-ok") == 0) {
        zone_begin_ex(fd, z, 1, 0, 0, 0, "masters { 127.0.0.1 port 1; 2001:db8::1; }; ixfr-history 3;", NULL); zone_end(fd, 0);
    } else if (strcmp(mode, "catalog-ok") == 0) {
        zone_begin_ex(fd, z, 2, 0, 0, 0, "masters { 127.0.0.1 port 1; };", NULL); zone_end(fd, 0);
    } else if (strncmp(mode, "ext-", 4) == 0) {                   /* B8: Extended AXFR records in the stream */
        uint8_t lan[3] = { 'l', 'a', 'n' }, tr[2] = { 1, 0 }, bad1[1] = { 'x' }, longtag[70];
        memset(longtag, 'a', sizeof(longtag));
        uint32_t flags = 2;                                       /* KDB_ZF_EXTENDED */
        uint64_t declared = 3;
        dm_soa(&m, z, 5);
        if (strcmp(mode, "ext-no-flag") == 0) {                   /* state record, flag 0 */
            dm_rr(&m, z, 65401, 65302, lan, 3); flags = 0;
        } else if (strcmp(mode, "ext-trusted") == 0) {            /* ECS_TRUSTED is not for the stream */
            dm_rr(&m, z, 65407, 65302, tr, 2);
        } else if (strcmp(mode, "ext-bad-def") == 0) {
            dm_rr(&m, z, 65403, 65302, bad1, 1);
        } else if (strcmp(mode, "ext-bad-locdef") == 0) {
            dm_rr(&m, z, 65405, 65302, bad1, 1);
        } else if (strcmp(mode, "ext-bad-wrap") == 0) {
            dm_rr(&m, "www.bad.test", 65406, 65302, bad1, 1); declared = 3;
        } else if (strcmp(mode, "ext-long-tag") == 0) {
            dm_rr(&m, z, 65401, 65302, longtag, sizeof(longtag));
        } else if (strcmp(mode, "ext-flag-bit") == 0) {           /* a reserved zone flag: protocol error */
            flags = 16; declared = 2;
        } else {                                                  /* ext-ok: the state records and the tinydns flag are accepted */
            dm_rr(&m, z, 65401, 65302, lan, 3); dm_a(&m, "www.bad.test", 1);
            dm_rr(&m, z, 65401, 65302, (const uint8_t *)"", 0);
            flags = 6; declared = 5;
        }
        dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, flags, declared, 0); zone_data(fd, &m); zone_end(fd, declared);
    } else if (strncmp(mode, "soaset-", 7) == 0) {                 /* B8t-2: the version 3 SOA set */
        const char *m2 = mode + 7;
        uint8_t locdef[7] = { 'i', 'n', 32, 127, 0, 0, 1 };
        uint8_t set_n[3] = { 1, 0, (uint8_t)(strcmp(m2, "count") == 0 ? 3 : 2) };
        uint64_t declared = 8;                                    /* frame, SOA_SET, locdef, 2 wrapped SOAs, NS, A, closing SOA */
        uint32_t fr = strcmp(m2, "frame") == 0 ? 1234 : 3600;     /* "frame": the opening SOA is not the reference SOA */
        dm_soa_ex(&m, z, 5, fr);
        if (strcmp(m2, "late") == 0) {                             /* SOA_SET after a data record */
            dm_a(&m, "www.bad.test", 1);
            declared++;
        }
        dm_rr(&m, z, 65409, 65302, set_n, 3);
        dm_rr(&m, z, 65405, 65302, locdef, 7);
        dm_soa_set_member(&m, z, 5, 3600, "in");
        dm_soa_set_member(&m, z, strcmp(m2, "serial") == 0 ? 6 : 5, 3600, strcmp(m2, "dup") == 0 ? "in" : "");
        dm_ns(&m, z, "ns.bad.test");
        dm_a(&m, "www.bad.test", 1);
        dm_soa_ex(&m, z, 5, fr);
        zone_begin(fd, z, 0, 6, declared, 0); zone_data(fd, &m); zone_end(fd, declared);
    } else if (strcmp(mode, "non-in-class") == 0) {
        uint8_t rd[4] = { 192, 0, 2, 1 };
        dm_soa(&m, z, 5); dm_rr(&m, "www.bad.test", 1, 3, rd, 4); dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "huge-frame") == 0) {
        static uint8_t big[70000];
        memset(big, 0, sizeof(big));
        big[2] = 0x84; put16(big + 6, 1);
        zone_begin(fd, z, 0, 0, 2, 0);
        send_msg(fd, "KDB1", 5, big, sizeof(big));
    } else if (strcmp(mode, "end-count") == 0) {
        dm_soa(&m, z, 5); dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, 0, 2, 0); zone_data(fd, &m); zone_end(fd, 7);
    } else if (strcmp(mode, "begin-count") == 0) {
        dm_soa(&m, z, 5); dm_a(&m, "www.bad.test", 1); dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, 0, 9, 0); zone_data(fd, &m); zone_end(fd, 9);
    } else if (strcmp(mode, "zero-ancount") == 0) {
        zone_begin(fd, z, 0, 0, 2, 0); zone_data(fd, &m);
    } else if (strcmp(mode, "opt-twice") == 0) {
        dm_t m2;
        dm_soa(&m, z, 5);
        dm_init(&m2); dm_a(&m2, "www.bad.test", 1);
        put16(m2.b + 10, 1);
        zone_begin(fd, z, 0, 0, 3, 0); zone_data(fd, &m); zone_data(fd, &m2);
    } else if (strcmp(mode, "unknown-tag") == 0) {
        dm_soa(&m, z, 5); dm_soa(&m, z, 5);
        zone_begin(fd, z, 0, 0, 2, 99);
    } else if (strcmp(mode, "settings-key") == 0 || strcmp(mode, "settings-include") == 0 || strcmp(mode, "settings-file") == 0 ||
               strcmp(mode, "settings-slave") == 0 || strcmp(mode, "settings-brace") == 0 || strcmp(mode, "profile-missing") == 0 ||
               strcmp(mode, "settings-ok") == 0) {
        const char *st = NULL, *pr = NULL;
        if (strcmp(mode, "settings-key") == 0) st = "allow-transfer { 127.0.0.1; key \"ghost\"; };";
        else if (strcmp(mode, "settings-include") == 0) st = "include \"/etc/passwd\"; allow-transfer { any; };";
        else if (strcmp(mode, "settings-file") == 0) st = "ixfr-history 2; file \"/etc/passwd\";";
        else if (strcmp(mode, "settings-slave") == 0) st = "type slave; masters { 192.0.2.1; };";
        else if (strcmp(mode, "settings-brace") == 0) st = "allow-transfer { 127.0.0.1; }; };";
        else if (strcmp(mode, "profile-missing") == 0) pr = "p1";
        else st = "allow-transfer { 127.0.0.1; }; ixfr-history 3;";
        dm_soa(&m, z, 5); dm_a(&m, "www.bad.test", 1); dm_soa(&m, z, 5);
        if (strcmp(mode, "settings-ok") == 0) {                   /* a profile first, then a zone that uses it and has own text */
            uint8_t pb[256];
            size_t pn = 0;
            pn += tlv(pb + pn, 1, "p1", 2);
            pn += tlv(pb + pn, 2, "notify-retries 2;", 17);
            send_msg(fd, "KDB1", 10, pb, pn);
            pr = "p1";
        }
        zone_begin_ex(fd, z, 0, 0, 3, 0, st, pr); zone_data(fd, &m); zone_end(fd, 3);
    } else if (strcmp(mode, "profile-flood") == 0) {
        static uint8_t pb[64100];
        static char text[64001];
        memset(text, '#', 64000);
        for (int i = 0; i < 270; i++) {
            char name[16];
            size_t pn = 0;
            snprintf(name, sizeof(name), "p%d", i);
            pn += tlv(pb + pn, 1, name, (uint16_t)strlen(name));
            pn += tlv(pb + pn, 2, text, 64000);
            send_msg(fd, "KDB1", 10, pb, pn);
        }
    } else if (strcmp(mode, "delete-unknown") == 0) {
        uint8_t b[128], view[2] = { 0, 0 }, src[8] = { 0 };
        size_t n = 0;
        put64(src, 4242);
        n += tlv(b + n, 1, view, 2);
        n += tlv(b + n, 2, "nothere.test.", 13);
        n += tlv(b + n, 3, src, 8);
        send_msg(fd, "KDB1", 9, b, n);
        g_ndel++;
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "-s") != 0) return 2;
    int fd = atoi(argv[2]);
    const char *mode = argc > 3 ? argv[3] : "bad-magic";
    uint8_t b[512];
    size_t n = 0;
    uint8_t v16[2] = { 0, 1 }, pid[4];
    put32(pid, (uint32_t)getpid());
    n += tlv(b + n, 1, v16, 2);
    n += tlv(b + n, 2, "fake", 4);
    n += tlv(b + n, 3, "sqlite3", 7);
    n += tlv(b + n, 4, pid, 4);
    send_msg(fd, "KDB1", 1, b, n);

    uint8_t rbuf[4096];                      /* the CONFIG */
    ssize_t r = read(fd, rbuf, sizeof(rbuf));
    (void)r;
    uint8_t one[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
    n = 0;
    if (strcmp(mode, "bad-magic") == 0) {
        send_msg(fd, "XXXX", 2, b, 0);
    } else if (strcmp(mode, "bad-order") == 0) {
        n += tlv(b + n, 1, one, 8);
        send_msg(fd, "KDB1", 6, b, n);       /* ZONE_END in READY */
    } else if (strcmp(mode, "bad-view") == 0) {
        uint8_t kind = 0, zero8[8] = { 0 };
        n += tlv(b + n, 1, one, 8);
        n += tlv(b + n, 2, &kind, 1);
        n += tlv(b + n, 3, zero8, 8);
        send_msg(fd, "KDB1", 3, b, n);       /* BATCH_BEGIN */
        uint8_t view[2] = { 0x12, 0x34 }, serial[4] = { 0, 0, 0, 1 }, flags[4] = { 0 }, rrs[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };
        uint8_t digest[32] = { 0 }, src[8] = { 0 }, zk = 0;
        n = 0;
        n += tlv(b + n, 1, view, 2);
        n += tlv(b + n, 2, "bad.test.", 9);
        n += tlv(b + n, 3, src, 8);
        n += tlv(b + n, 4, &zk, 1);
        n += tlv(b + n, 5, serial, 4);
        n += tlv(b + n, 6, flags, 4);
        n += tlv(b + n, 7, rrs, 8);
        n += tlv(b + n, 8, digest, 32);
        send_msg(fd, "KDB1", 4, b, n);       /* ZONE_BEGIN with view 0x1234 */
    } else if (strcmp(mode, "silent") != 0) {
        /* zone-level modes: one batch, ok1.test, the bad zone, ok2.test */
        batch_begin(fd);
        good_zone(fd, "ok1.test", 1);
        if (strcmp(mode, "slow") == 0) sleep(3);
        else if (strcmp(mode, "good") != 0) bad_zone(fd, mode);
        if (strcmp(mode, "again") == 0) good_zone(fd, "ok1.test", 2);
        good_zone(fd, "ok2.test", 1);
        batch_end(fd, g_ndel);
    }
    for (;;) {                                /* until the Backend closes the stream */
        ssize_t k = read(fd, rbuf, sizeof(rbuf));
        if (k == 0) return 0;
        if (k < 0) sleep(1);
    }
}

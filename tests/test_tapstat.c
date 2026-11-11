/* Unit test of karidns-tapstat's core (tools/tapstat_core.c) and of the shared dnstap decoder (tools/dnstap_decode.c):
 * the Frame Streams reader (handshake, every protocol error, frames split at every byte), the aggregator (zones, the
 * dimensions, prefixes, the full-table counter, malformed input) and the three output formats. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../tools/tapstat_core.h"
#include "../tools/dnstap_decode.h"

/* ---- builders ---- */

static size_t pb_varint(uint8_t *b, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) { b[n++] = (uint8_t)(v | 0x80); v >>= 7; }
    b[n++] = (uint8_t)v;
    return n;
}
static size_t pb_f_varint(uint8_t *b, unsigned fn, uint64_t v) { size_t n = pb_varint(b, (fn << 3) | 0); return n + pb_varint(b + n, v); }
static size_t pb_f_bytes(uint8_t *b, unsigned fn, const void *p, size_t l) {
    size_t n = pb_varint(b, (fn << 3) | 2);
    n += pb_varint(b + n, l);
    memcpy(b + n, p, l);
    return n + l;
}

/* DNS message: id 0x1234, QR/rcode, one question (unless qd == 0) */
static size_t mk_dns(uint8_t *b, bool resp, unsigned rcode, const char *labels_dot, unsigned qtype, unsigned qd) {
    memset(b, 0, 12);
    b[0] = 0x12; b[1] = 0x34;
    b[2] = resp ? 0x84 : 0x00;
    b[3] = (uint8_t)(rcode & 0x0f);
    b[5] = (uint8_t)qd;
    size_t n = 12;
    if (qd == 0) return n;
    uint8_t w[256];
    size_t wl = 0;
    if (labels_dot[0] == '.' && labels_dot[1] == 0) { w[0] = 0; wl = 1; }
    else {
        /* labels_dot is "a.b." built with the (non-lowering) copy of tapstat_name_to_wire; keep the case */
        const char *p = labels_dot;
        while (*p) {
            const char *d = strchr(p, '.');
            size_t l = d ? (size_t)(d - p) : strlen(p);
            w[wl++] = (uint8_t)l;
            memcpy(w + wl, p, l);
            wl += l;
            if (!d) break;
            p = d + 1;
        }
        w[wl++] = 0;
    }
    memcpy(b + n, w, wl); n += wl;
    b[n++] = (uint8_t)(qtype >> 8); b[n++] = (uint8_t)qtype; b[n++] = 0; b[n++] = 1;
    return n;
}

typedef struct {
    unsigned type;        /* message type */
    const uint8_t *addr; size_t addr_len;
    const uint8_t *wire; size_t wire_len;
    const uint8_t *zone; size_t zone_len;
} mf_t;

static size_t mk_frame(uint8_t *out, const mf_t *m) {
    uint8_t msg[8192];
    size_t n = 0;
    n += pb_f_varint(msg + n, 1, m->type);
    n += pb_f_varint(msg + n, 2, m->addr_len == 16 ? 2 : 1);
    n += pb_f_varint(msg + n, 3, 1);
    if (m->addr) n += pb_f_bytes(msg + n, 4, m->addr, m->addr_len);
    n += pb_f_varint(msg + n, 6, 5353);
    if (m->type == 1) n += pb_f_bytes(msg + n, 10, m->wire, m->wire_len);
    else n += pb_f_bytes(msg + n, 14, m->wire, m->wire_len);
    if (m->zone) n += pb_f_bytes(msg + n, 11, m->zone, m->zone_len);
    size_t o = 0;
    o += pb_f_bytes(out + o, 1, "id", 2);
    o += pb_f_varint(out + o, 15, 1);
    o += pb_f_bytes(out + o, 14, msg, n);
    return o;
}

static size_t frame_for(uint8_t *out, unsigned type, const uint8_t *addr, size_t addr_len, const char *name, unsigned qtype,
                        unsigned rcode, const uint8_t *zone, size_t zone_len) {
    uint8_t w[600];
    size_t wl = mk_dns(w, type == 2, rcode, name, qtype, 1);
    mf_t m = { type, addr, addr_len, w, wl, zone, zone_len };
    return mk_frame(out, &m);
}

static void be32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

static size_t ctl(uint8_t *out, uint32_t type, bool ct) {
    static const char c[] = "protobuf:dnstap.Dnstap";
    uint32_t pl = 4 + (ct ? 8 + 22 : 0);
    be32(out, 0); be32(out + 4, pl); be32(out + 8, type);
    if (ct) { be32(out + 12, 1); be32(out + 16, 22); memcpy(out + 20, c, 22); }
    return 8 + pl;
}

static size_t data_frame(uint8_t *out, const uint8_t *p, size_t l) { be32(out, (uint32_t)l); memcpy(out + 4, p, l); return 4 + l; }

/* ---- counters of the callback ---- */

static unsigned g_data;
static size_t g_last_len;
static void count_cb(void *ctx, const uint8_t *f, size_t l) { (void)ctx; (void)f; g_data++; g_last_len = l; }

static tapstat_t *mk(uint32_t topk, uint32_t show, int type) {
    tapstat_opts_t o = { .topk = topk, .show = show, .count_type = type, .v4_prefix = 24, .v6_prefix = 56, .hash_key = { 1, 2 } };
    tapstat_t *s = tapstat_new(&o);
    assert(s);
    return s;
}

static char *render(const tapstat_t *s, tapstat_format_t f) {
    char *buf = NULL;
    size_t sz = 0;
    FILE *fp = open_memstream(&buf, &sz);
    assert(fp);
    tapstat_render(s, f, fp, 1700000000, 1700000060, 60.0);
    fclose(fp);
    return buf;
}

static const uint8_t A4[4] = { 192, 0, 2, 77 };
static const uint8_t A4b[4] = { 192, 0, 2, 200 };
static const uint8_t A4c[4] = { 198, 51, 100, 5 };
static const uint8_t A6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33 };
static const uint8_t A4m6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 9 };

static void test_fstrm(void) {
    uint8_t stream[2048], tmp[256];
    size_t n = 0;
    n += ctl(stream + n, 4, true);   /* READY */
    n += ctl(stream + n, 2, true);   /* START */
    uint8_t fr[600];
    size_t fl = frame_for(fr, 2, A4, 4, "www.example.test.", 1, 0, NULL, 0);
    n += data_frame(stream + n, fr, fl);
    n += data_frame(stream + n, fr, fl);
    n += ctl(stream + n, 3, false);  /* STOP */

    /* whole stream in one read */
    fstrm_reader_t r;
    fstrm_reader_init(&r, true);
    g_data = 0;
    assert(fstrm_feed(&r, stream, n, count_cb, NULL) == 1);
    assert(g_data == 2 && g_last_len == fl);
    uint8_t exp[128];
    size_t el = ctl(exp, 1, true);
    el += ctl(exp + el, 5, false);
    assert(r.reply_len == el && memcmp(r.reply, exp, el) == 0); /* ACCEPT(content type) then FINISH */
    assert(r.state == FSTRM_ST_DONE);
    assert(fstrm_feed(&r, stream, n, count_cb, NULL) == 1); /* after STOP: ignored */
    fstrm_reader_free(&r);

    /* one byte at a time, and every split in two */
    fstrm_reader_init(&r, true);
    g_data = 0;
    for (size_t i = 0; i < n; i++) {
        int rc = fstrm_feed(&r, stream + i, 1, count_cb, NULL);
        assert(rc == (i == n - 1 ? 1 : 0));
    }
    assert(g_data == 2);
    fstrm_reader_free(&r);
    for (size_t cut = 1; cut < n; cut++) {
        fstrm_reader_init(&r, true);
        g_data = 0;
        assert(fstrm_feed(&r, stream, cut, count_cb, NULL) == 0);
        assert(fstrm_feed(&r, stream + cut, n - cut, count_cb, NULL) == 1);
        assert(g_data == 2);
        fstrm_reader_free(&r);
    }

    /* file mode: START ... STOP, no reply */
    n = 0;
    n += ctl(stream + n, 2, true);
    n += data_frame(stream + n, fr, fl);
    n += ctl(stream + n, 3, false);
    fstrm_reader_init(&r, false);
    g_data = 0;
    assert(fstrm_feed(&r, stream, n, count_cb, NULL) == 1 && g_data == 1 && r.reply_len == 0);
    fstrm_reader_free(&r);
    /* a file that is cut: no error, the frames before count */
    fstrm_reader_init(&r, false);
    g_data = 0;
    assert(fstrm_feed(&r, stream, n - 10, count_cb, NULL) == 0 && g_data == 1);
    fstrm_reader_free(&r);

    /* READY without content type: ACCEPT without; START without content type is fine */
    fstrm_reader_init(&r, true);
    n = ctl(stream, 4, false);
    n += ctl(stream + n, 2, false);
    assert(fstrm_feed(&r, stream, n, count_cb, NULL) == 0 && r.state == FSTRM_ST_DATA);
    el = ctl(exp, 1, false);
    assert(r.reply_len == el && memcmp(r.reply, exp, el) == 0);
    fstrm_reader_free(&r);

    /* READY with two content types, the second is ours; unknown field type is skipped */
    {
        uint8_t b[200];
        size_t o = 0;
        uint32_t pl = 4 + (8 + 3) + (8 + 4) + (8 + 22);
        be32(b, 0); be32(b + 4, pl); be32(b + 8, 4); o = 12;
        be32(b + o, 1); be32(b + o + 4, 3); memcpy(b + o + 8, "abc", 3); o += 11;
        be32(b + o, 99); be32(b + o + 4, 4); memcpy(b + o + 8, "xxxx", 4); o += 12;
        be32(b + o, 1); be32(b + o + 4, 22); memcpy(b + o + 8, "protobuf:dnstap.Dnstap", 22); o += 30;
        fstrm_reader_init(&r, true);
        assert(fstrm_feed(&r, b, o, count_cb, NULL) == 0 && r.reply_len > 0);
        fstrm_reader_free(&r);
    }

    /* errors */
    struct { const char *what; bool bidir; uint8_t b[400]; size_t l; } bad[16];
    int nb = 0;
#define BAD(w, bd) memset(&bad[nb], 0, sizeof(bad[nb])); bad[nb].what = w; bad[nb].bidir = bd; bad[nb].l = 0
    BAD("data before READY", true); bad[nb].l = data_frame(bad[nb].b, fr, 20); nb++;
    BAD("START before READY", true); bad[nb].l = ctl(bad[nb].b, 2, true); nb++;
    BAD("READY in file mode", false); bad[nb].l = ctl(bad[nb].b, 4, true); nb++;
    BAD("data before START", false); bad[nb].l = data_frame(bad[nb].b, fr, 20); nb++;
    BAD("STOP before START", false); bad[nb].l = ctl(bad[nb].b, 3, false); nb++;
    BAD("ACCEPT from the sender", true); bad[nb].l = ctl(bad[nb].b, 1, true); nb++;
    BAD("unknown control", true); bad[nb].l = ctl(bad[nb].b, 77, false); nb++;
    BAD("READY twice", true); bad[nb].l = ctl(bad[nb].b, 4, true); bad[nb].l += ctl(bad[nb].b + bad[nb].l, 4, true); nb++;
    BAD("control length 3", true); be32(bad[nb].b, 0); be32(bad[nb].b + 4, 3); bad[nb].l = 11; nb++;
    BAD("control length 513", true); be32(bad[nb].b, 0); be32(bad[nb].b + 4, 513); bad[nb].l = 8; nb++;
    BAD("data length over the cap", true); be32(bad[nb].b, FSTRM_MAX_DATA_FRAME + 1); bad[nb].l = 4; nb++;
    BAD("other content type", true); { ctl(bad[nb].b, 4, true); bad[nb].b[21] = 'X'; bad[nb].l = 42; } nb++;
    BAD("trailing bytes in control", true); { be32(bad[nb].b, 0); be32(bad[nb].b + 4, 6); be32(bad[nb].b + 8, 4); bad[nb].b[12] = 1; bad[nb].b[13] = 2; bad[nb].l = 14; } nb++;
    BAD("field longer than the frame", true); { be32(bad[nb].b, 0); be32(bad[nb].b + 4, 16); be32(bad[nb].b + 8, 4); be32(bad[nb].b + 12, 1); be32(bad[nb].b + 16, 99); bad[nb].l = 24; } nb++;
    BAD("content type longer than 256", true); { be32(bad[nb].b, 0); be32(bad[nb].b + 4, 312); be32(bad[nb].b + 8, 4); be32(bad[nb].b + 12, 1); be32(bad[nb].b + 16, 300); bad[nb].l = 320; } nb++;
#undef BAD
    for (int i = 0; i < nb; i++) {
        fstrm_reader_init(&r, bad[i].bidir);
        g_data = 0;
        int rc = fstrm_feed(&r, bad[i].b, bad[i].l, count_cb, NULL);
        if (rc != -1) { fprintf(stderr, "no error for: %s (rc %d)\n", bad[i].what, rc); abort(); }
        assert(g_data == 0);
        assert(fstrm_feed(&r, tmp, 1, count_cb, NULL) == -1); /* an error state stays */
        fstrm_reader_free(&r);
    }

    /* a data frame of the largest size, assembled from reads of 7 bytes */
    {
        uint8_t *big = malloc(4 + FSTRM_MAX_DATA_FRAME);
        assert(big);
        memset(big, 0x42, 4 + FSTRM_MAX_DATA_FRAME);
        be32(big, FSTRM_MAX_DATA_FRAME);
        fstrm_reader_init(&r, false);
        n = ctl(stream, 2, true);
        assert(fstrm_feed(&r, stream, n, count_cb, NULL) == 0);
        g_data = 0;
        for (size_t o = 0; o < 4 + FSTRM_MAX_DATA_FRAME; o += 7) {
            size_t c = 4 + FSTRM_MAX_DATA_FRAME - o < 7 ? 4 + FSTRM_MAX_DATA_FRAME - o : 7;
            assert(fstrm_feed(&r, big + o, c, count_cb, NULL) == 0);
        }
        assert(g_data == 1 && g_last_len == FSTRM_MAX_DATA_FRAME);
        fstrm_reader_free(&r);
        free(big);
    }
}

static void test_decoder(void) {
    uint8_t fr[700];
    size_t fl = frame_for(fr, 1, A4, 4, "a.example.test.", 28, 0, NULL, 0);
    dnstap_msg_t m;
    assert(dnstap_decode_message(fr, fl, &m));
    assert(m.message_type == 1 && m.socket_family == 1 && m.socket_protocol == 1 && m.has_query_addr && m.query_addr_len == 4);
    assert(m.query_port == 5353 && m.query_msg && m.query_msg_len > 12 && !m.response_msg);
    assert(!dnstap_decode_message(NULL, 0, &m));
    assert(!dnstap_decode_message(fr, 0, &m));
    assert(!dnstap_decode_message(fr, fl, NULL));
    for (size_t i = 0; i < fl; i++) (void)dnstap_decode_message(fr, i, &m); /* every truncation: no read out of bounds (ASan) */

    uint8_t junk[] = { 0x0b, 0x01, 0x00 };             /* wire type 3 (group) */
    assert(!dnstap_decode_message(junk, sizeof(junk), &m));
    uint8_t junk2[] = { 0x75 };                        /* field 14, wire type 5: fixed32 with no room */
    assert(!dnstap_decode_message(junk2, sizeof(junk2), &m));
    uint8_t junk3[] = { 0x71, 1, 2, 3, 4, 5, 6, 7, 8, 0x72, 0x00 }; /* field 14 wire type 1 (fixed64), then an empty message */
    assert(!dnstap_decode_message(junk3, sizeof(junk3), &m));
    uint8_t junk4[] = { 0x72, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }; /* length 2^64-1 */
    assert(!dnstap_decode_message(junk4, sizeof(junk4), &m));
    uint8_t junk5[] = { 0x72, 0x80 };                  /* varint that ends in the buffer */
    assert(!dnstap_decode_message(junk5, sizeof(junk5), &m));

    /* inside the message: an address of 17 bytes is ignored, fixed32 / fixed64 fields are skipped */
    uint8_t msg[200];
    size_t n = 0;
    uint8_t a17[17] = { 0 };
    n += pb_f_bytes(msg + n, 4, a17, 17);
    msg[n++] = (9 << 3) | 5; memset(msg + n, 0, 4); n += 4;
    msg[n++] = (15 << 3) | 1; memset(msg + n, 0, 8); n += 8;
    n += pb_f_varint(msg + n, 1, 2);
    n += pb_f_bytes(msg + n, 5, A4, 4);
    n += pb_f_varint(msg + n, 7, 53);
    uint8_t top[260];
    size_t t = pb_f_bytes(top, 14, msg, n);
    assert(dnstap_decode_message(top, t, &m));
    assert(!m.has_query_addr && m.has_response_addr && m.response_addr_len == 4 && m.response_port == 53 && m.message_type == 2);
    /* the replay wrappers still read the same */
    dnstap_frame_info_t fi;
    assert(!parse_dnstap_data_frame_full(top, t, &fi)); /* no DNS message in it */
    fl = frame_for(fr, 2, A4, 4, "a.example.test.", 1, 3, NULL, 0);
    assert(parse_dnstap_data_frame_full(fr, fl, &fi) && fi.has_wire && fi.message_type == 2 && fi.protocol == 17 && fi.client_addr[3] == 77 && fi.client_port == 5353);
    uint8_t dns[4096];
    size_t dl = 0;
    assert(!parse_dnstap_data_frame(fr, fl, dns, &dl));   /* a response message holds no query */
    fl = frame_for(fr, 1, A4, 4, "a.example.test.", 1, 0, NULL, 0);
    char tr[8];
    assert(parse_dnstap_data_frame_ex(fr, fl, dns, &dl, tr, sizeof(tr)) && strcmp(tr, "udp") == 0 && dl > 12);
}

static void test_aggregate(void) {
    uint8_t fr[800];
    size_t fl;
    tapstat_t *s = mk(100, 0, 2);
    assert(tapstat_add_zone(s, "Example.TEST"));
    assert(tapstat_add_zone(s, "sub.example.test."));
    assert(tapstat_add_zone(s, "example.test")); /* twice */
    assert(tapstat_zone_count(s) == 2);
    assert(!tapstat_add_zone(s, ""));
    assert(!tapstat_add_zone(s, "a..b"));
    assert(!tapstat_add_zone(s, "0123456789012345678901234567890123456789012345678901234567890123456.test"));
    assert(tapstat_add_zone(s, "."));
    assert(tapstat_zone_count(s) == 3);

    fl = frame_for(fr, 2, A4, 4, "WWW.Example.TEST.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A4b, 4, "www.example.test.", 28, 0, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A4c, 4, "x.sub.example.test.", 1, 3, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A6, 16, "nope.invalid.", 99, 5, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A4m6, 16, "sub.example.test.", 255, 2, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 1, A4, 4, "ignored.example.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl); /* a query: not counted for -t response */
    fl = frame_for(fr, 2, A4, 4, ".", 2, 0, NULL, 0); tapstat_frame(s, fr, fl);

    char *txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "frames 7  bad 0  queries 1  responses 6"));
    assert(strstr(txt, "2  www.example.test."));            /* case folded */
    assert(strstr(txt, "1  x.sub.example.test."));
    assert(!strstr(txt, "ignored.example.test."));
    assert(strstr(txt, "         2  example.test."));       /* zone: www + www */
    assert(strstr(txt, "         2  sub.example.test."));   /* x.sub and sub: the longest listed suffix */
    assert(strstr(txt, "         2  .\n"));                  /* the root zone: nope.invalid. and "." */
    assert(strstr(txt, "  A\n") && strstr(txt, "  AAAA\n") && strstr(txt, "  TYPE99\n") && strstr(txt, "  ANY\n") && strstr(txt, "  NS\n"));
    assert(strstr(txt, "NXDOMAIN") && strstr(txt, "REFUSED") && strstr(txt, "SERVFAIL") && strstr(txt, "NOERROR"));
    assert(strstr(txt, "192.0.2.0/24"));
    assert(strstr(txt, "198.51.100.0/24"));
    assert(strstr(txt, "2001:db8:12:3400::/56"));
    free(txt);
    char *js = render(s, TAPSTAT_JSON);
    assert(strstr(js, "\"frames\":7") && strstr(js, "\"seconds\":60.000") && strstr(js, "\"start\":\"2023-11-14T22:13:20Z\""));
    assert(strstr(js, "{\"key\":\"www.example.test.\",\"count\":2,\"error\":0}"));
    assert(js[strlen(js) - 1] == '\n' && strchr(js, '\n') == js + strlen(js) - 1); /* one line */
    free(js);
    char *pm = render(s, TAPSTAT_PROM);
    assert(strstr(pm, "# TYPE karidns_tapstat_count gauge"));
    assert(strstr(pm, "karidns_tapstat_count{dimension=\"qname\",key=\"www.example.test.\"} 2"));
    assert(strstr(pm, "karidns_tapstat_messages{kind=\"frames\"} 7"));
    assert(strstr(pm, "karidns_tapstat_last_summary_timestamp_seconds 1700000060"));
    free(pm);
    assert(tapstat_frames(s) == 7 && tapstat_bad_frames(s) == 0);

    tapstat_reset(s);
    assert(tapstat_frames(s) == 0);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "frames 0  bad 0") && strstr(txt, "zone: events 0  keys 0"));
    free(txt);
    fl = frame_for(fr, 2, A4, 4, "www.example.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    assert(tapstat_frames(s) == 1 && tapstat_zone_count(s) == 3); /* zones survive the reset */
    tapstat_free(s);

    /* -t query: the queries are counted for the name tables, responses only for rcode */
    s = mk(100, 0, 1);
    fl = frame_for(fr, 1, A4, 4, "q.example.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A4, 4, "r.example.test.", 1, 3, NULL, 0); tapstat_frame(s, fr, fl);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "q.example.test.") && !strstr(txt, "r.example.test.") && strstr(txt, "NXDOMAIN"));
    free(txt);
    tapstat_free(s);

    /* no -z: the zone the server put in the message; none = "other"; a bad one = "other" */
    s = mk(100, 0, 2);
    static const uint8_t qz[] = { 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0 };
    fl = frame_for(fr, 2, A4, 4, "w.example.test.", 1, 0, qz, sizeof(qz)); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A4, 4, "w.example.test.", 1, 5, NULL, 0); tapstat_frame(s, fr, fl);
    static const uint8_t qzbad[] = { 7, 'e', 'x' };
    fl = frame_for(fr, 2, A4, 4, "w.example.test.", 1, 5, qzbad, sizeof(qzbad)); tapstat_frame(s, fr, fl);
    static const uint8_t qzbad2[] = { 1, 'a', 0, 9 };
    fl = frame_for(fr, 2, A4, 4, "w.example.test.", 1, 5, qzbad2, sizeof(qzbad2)); tapstat_frame(s, fr, fl);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "         1  example.test.") && strstr(txt, "         3  other"));
    free(txt);
    tapstat_free(s);

    /* malformed input is counted, never read past the end */
    s = mk(100, 0, 2);
    uint8_t w[600];
    size_t wl;
    mf_t m;
    wl = mk_dns(w, true, 0, "a.test.", 1, 0);                       /* no question */
    m = (mf_t){ 2, A4, 4, w, wl, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);
    wl = mk_dns(w, true, 0, "a.test.", 1, 1);
    w[12] = 0xc0;                                                  /* compression pointer in the question */
    m = (mf_t){ 2, A4, 4, w, wl, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);
    wl = mk_dns(w, true, 0, "a.test.", 1, 1);
    w[12] = 64;                                                    /* label longer than 63 */
    m = (mf_t){ 2, A4, 4, w, wl, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);
    wl = mk_dns(w, true, 0, "a.test.", 1, 1);
    m = (mf_t){ 2, A4, 4, w, wl - 3, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);        /* no room for type and class */
    m = (mf_t){ 2, A4, 4, w, 13, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);            /* the name runs off the end */
    m = (mf_t){ 2, A4, 4, w, 5, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);             /* shorter than a header */
    m = (mf_t){ 2, NULL, 0, w, wl, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);          /* no client address: counted, no client */
    m = (mf_t){ 2, A4, 3, w, wl, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);            /* an address of 3 bytes */
    /* a name of 127 one-byte labels (254 bytes + root = 255 is the limit), and one label too many */
    {
        uint8_t big[400];
        memset(big, 0, 12);
        big[2] = 0x84; big[5] = 1;
        size_t o = 12;
        for (int i = 0; i < 127; i++) { big[o++] = 1; big[o++] = 'a'; }
        big[o++] = 0; big[o++] = 0; big[o++] = 1; big[o++] = 0; big[o++] = 1;
        m = (mf_t){ 2, A4, 4, big, o, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);      /* 255 bytes: fine */
        size_t o2 = 12;
        for (int i = 0; i < 128; i++) { big[o2++] = 1; big[o2++] = 'a'; }
        big[o2++] = 0; big[o2++] = 0; big[o2++] = 1; big[o2++] = 0; big[o2++] = 1;
        m = (mf_t){ 2, A4, 4, big, o2, NULL, 0 }; fl = mk_frame(fr, &m); tapstat_frame(s, fr, fl);     /* 257 bytes: malformed */
    }
    tapstat_frame(s, (const uint8_t *)"\x01\x02", 2);              /* not dnstap at all */
    tapstat_frame(s, (const uint8_t *)"", 0);
    { uint8_t o3[64]; size_t k = pb_f_varint(o3, 15, 1); (void)k; tapstat_frame(s, o3, k); }       /* no message */
    { mf_t mm = { 5, A4, 4, w, wl, NULL, 0 }; fl = mk_frame(fr, &mm); tapstat_frame(s, fr, fl); }  /* a message type that is neither */
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "no-question 1  malformed 5"));
    assert(strstr(txt, "other-messages 1"));
    assert(strstr(txt, "bad 4"));
    free(txt);
    tapstat_free(s);

    /* odd names: a dot in a label, a quote, a control byte, a backslash; JSON and Prometheus escape them */
    s = mk(100, 0, 2);
    {
        uint8_t o4[64];
        size_t k = 0;
        o4[k++] = 5; memcpy(o4 + k, "a.\"\\\x01", 5); k += 5; o4[k++] = 0;
        uint8_t w2[100];
        memset(w2, 0, 12); w2[2] = 0x84; w2[5] = 1;
        memcpy(w2 + 12, o4, k);
        w2[12 + k] = 0; w2[13 + k] = 1; w2[14 + k] = 0; w2[15 + k] = 1;
        mf_t mm = { 2, A4, 4, w2, 16 + k, NULL, 0 };
        fl = mk_frame(fr, &mm); tapstat_frame(s, fr, fl);
    }
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "a\\.\"\\\\\\001."));
    free(txt);
    js = render(s, TAPSTAT_JSON);
    assert(strstr(js, "\"key\":\"a\\\\.\\\"\\\\\\\\\\\\001.\""));
    free(js);
    pm = render(s, TAPSTAT_PROM);
    assert(strstr(pm, "key=\"a\\\\.\\\"\\\\\\\\\\\\001.\""));
    free(pm);
    tapstat_free(s);
}

/* the qname section of a text summary rendered with -n 0: "count name [(may be over-counted by up to E)]" per line */
typedef struct { char name[64]; unsigned long long count, err; } row_t;
static size_t parse_qname_rows(const char *txt, row_t *rows, size_t max, unsigned long long *events) {
    const char *p = strstr(txt, "qname: events ");
    assert(p);
    *events = strtoull(p + 14, NULL, 10);
    p = strchr(p, '\n') + 1;
    size_t n = 0;
    while (p[0] == ' ' && p[1] == ' ') {
        assert(n < max);
        char *end;
        rows[n].count = strtoull(p, &end, 10);
        while (*end == ' ') end++;
        size_t l = strcspn(end, " \n");
        assert(l < sizeof(rows[n].name));
        memcpy(rows[n].name, end, l);
        rows[n].name[l] = 0;
        end += l;
        rows[n].err = 0;
        const char *e = strstr(end, "up to ");
        const char *nl = strchr(end, '\n');
        if (e && e < nl) rows[n].err = strtoull(e + 6, NULL, 10);
        n++;
        p = nl + 1;
    }
    return n;
}

static void test_space_saving(void) {
    uint8_t fr[800];
    size_t fl;
    char name[32];

    /* a heavy key that arrives after the table is full replaces the smallest key, inherits its count as the error, and
     * outgrows the noise: it is the first entry */
    tapstat_t *s = mk(8, 3, 2);
    for (int i = 0; i < 40; i++) { /* 40 one-off names fill the table and keep evicting */
        snprintf(name, sizeof(name), "noise%d.test.", i);
        fl = frame_for(fr, 2, A4, 4, name, 1, 0, NULL, 0);
        tapstat_frame(s, fr, fl);
    }
    for (int i = 0; i < 60; i++) {
        fl = frame_for(fr, 2, A4, 4, "heavy.test.", 1, 0, NULL, 0);
        tapstat_frame(s, fr, fl);
        snprintf(name, sizeof(name), "more%d.test.", i);
        fl = frame_for(fr, 2, A4, 4, name, 1, 0, NULL, 0);
        tapstat_frame(s, fr, fl);
    }
    char *txt = render(s, TAPSTAT_TEXT);
    char *q = strstr(txt, "qname: events 160  keys 8  evictions ");
    assert(q);
    char *first = strchr(q, '\n') + 1;
    char *hv = strstr(first, "heavy.test.");
    assert(hv && hv < strchr(first, '\n'));
    char *js = render(s, TAPSTAT_JSON);
    assert(strstr(js, "\"evictions\":") && strstr(js, "\"error\":"));
    char *pm = render(s, TAPSTAT_PROM);
    assert(strstr(pm, "kind=\"evictions\"") && strstr(pm, "karidns_tapstat_count_error{dimension=\"qname\""));
    free(txt); free(js); free(pm);
    tapstat_free(s);

    /* the Space-Saving guarantees on a skewed stream over 300 names and a table of 40: the counts add up to the events,
     * every kept key has count - error <= true <= count, and every key with a true count above events / 40 is kept */
    enum { NAMES = 300, EVENTS = 20000, CAP = 40 };
    static unsigned long long truth[NAMES];
    s = mk(CAP, 0, 2);
    uint32_t r = 12345;
    for (int i = 0; i < EVENTS; i++) {
        r = r * 1103515245u + 12345u;
        uint32_t a = (r >> 8) % NAMES, b = (r >> 20) % NAMES;
        int k = (int)(a < b ? a : b); /* skewed to the low numbers */
        if (i % 3 == 0) k = (int)((r >> 4) % NAMES);
        truth[k]++;
        snprintf(name, sizeof(name), "k%d.test.", k);
        fl = frame_for(fr, 2, A4, 4, name, 1, 0, NULL, 0);
        tapstat_frame(s, fr, fl);
    }
    txt = render(s, TAPSTAT_TEXT);
    static row_t rows[CAP + 4];
    unsigned long long events = 0, sum = 0;
    size_t n = parse_qname_rows(txt, rows, CAP + 4, &events);
    assert(events == EVENTS && n == CAP);
    for (size_t i = 0; i < n; i++) {
        int k = atoi(rows[i].name + 1);
        sum += rows[i].count;
        assert(rows[i].count >= rows[i].err);
        assert(rows[i].count - rows[i].err <= truth[k] && truth[k] <= rows[i].count);
        if (i) assert(rows[i - 1].count >= rows[i].count);
    }
    assert(sum == EVENTS);
    for (int k = 0; k < NAMES; k++) {
        if (truth[k] <= EVENTS / CAP) continue;
        int found = 0;
        for (size_t i = 0; i < n; i++) if (atoi(rows[i].name + 1) == k) found = 1;
        assert(found);
    }
    free(txt);
    tapstat_reset(s); /* the heap and the index start clean after a reset */
    fl = frame_for(fr, 2, A4, 4, "again.test.", 1, 0, NULL, 0);
    tapstat_frame(s, fr, fl);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "qname: events 1  keys 1  evictions 0"));
    free(txt);
    tapstat_free(s);
}

static void test_tables(void) {
    uint8_t fr[800];
    size_t fl;
    char name[32];

    /* a full table keeps the first keys and counts the rest */
    tapstat_t *s = mk(3, 2, 2);
    for (int i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "n%d.test.", i % 5);
        fl = frame_for(fr, 2, A4, 4, name, 1, 0, NULL, 0);
        tapstat_frame(s, fr, fl);
    }
    char *txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "qname: events 10  keys 3  evictions "));  /* the keys of the second round replace kept ones */
    assert(!strstr(txt, "qname: events 10  keys 3  evictions 0"));
    free(txt);
    tapstat_free(s);

    /* many keys, small cap: the probing never loops on a full slot array */
    s = mk(64, 5, 2);
    for (int i = 0; i < 5000; i++) {
        snprintf(name, sizeof(name), "h%d.test.", i);
        fl = frame_for(fr, 2, A4, 4, name, 1, 0, NULL, 0);
        tapstat_frame(s, fr, fl);
    }
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "qname: events 5000  keys 64  evictions 4936"));
    free(txt);
    tapstat_free(s);

    /* the client prefix: IPv6 with other lengths, /0 and /32 */
    tapstat_opts_t o = { .topk = 10, .show = 0, .count_type = 2, .v4_prefix = 0, .v6_prefix = 61, .hash_key = { 3, 4 } };
    s = tapstat_new(&o);
    fl = frame_for(fr, 2, A4, 4, "a.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A6, 16, "a.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "0.0.0.0/0") && strstr(txt, "2001:db8:12:3450::/61"));
    free(txt);
    tapstat_free(s);
    o.v4_prefix = 32;
    s = tapstat_new(&o);
    fl = frame_for(fr, 2, A4, 4, "a.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "192.0.2.77/32"));
    free(txt);
    tapstat_free(s);

    /* bad options */
    tapstat_opts_t b = { .topk = 0, .count_type = 2, .v4_prefix = 24, .v6_prefix = 56 };
    assert(!tapstat_new(&b));
    b.topk = TAPSTAT_MAX_TOPK + 1; assert(!tapstat_new(&b));
    b.topk = 1; b.v4_prefix = 33; assert(!tapstat_new(&b));
    b.v4_prefix = 24; b.v6_prefix = 129; assert(!tapstat_new(&b));
    b.v6_prefix = 56; b.count_type = 3; assert(!tapstat_new(&b));
    assert(!tapstat_new(NULL));
    tapstat_free(NULL);

    /* many zones: the set grows and finds all of them */
    s = mk(10, 0, 2);
    for (int i = 0; i < 300; i++) {
        snprintf(name, sizeof(name), "z%d.test", i);
        assert(tapstat_add_zone(s, name));
    }
    assert(tapstat_zone_count(s) == 300);
    fl = frame_for(fr, 2, A4, 4, "www.z299.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    fl = frame_for(fr, 2, A4, 4, "www.z300.test.", 1, 0, NULL, 0); tapstat_frame(s, fr, fl);
    txt = render(s, TAPSTAT_TEXT);
    assert(strstr(txt, "         1  z299.test.") && strstr(txt, "         1  other"));
    free(txt);
    tapstat_free(s);
}

static void test_names(void) {
    char b[32];
    assert(strcmp(tapstat_qtype_name(1, b, sizeof(b)), "A") == 0);
    assert(strcmp(tapstat_qtype_name(65, b, sizeof(b)), "HTTPS") == 0);
    assert(strcmp(tapstat_qtype_name(60000, b, sizeof(b)), "TYPE60000") == 0);
    assert(strcmp(tapstat_rcode_name(0, b, sizeof(b)), "NOERROR") == 0);
    assert(strcmp(tapstat_rcode_name(10, b, sizeof(b)), "NOTZONE") == 0);
    assert(strcmp(tapstat_rcode_name(15, b, sizeof(b)), "RCODE15") == 0);
    uint8_t w[256];
    size_t l;
    assert(tapstat_name_to_wire(".", w, &l) && l == 1 && w[0] == 0);
    assert(tapstat_name_to_wire("A.B", w, &l) && l == 5 && w[1] == 'a' && w[3] == 'b');
    assert(tapstat_name_to_wire("a.b.", w, &l) && l == 5);
    assert(!tapstat_name_to_wire(NULL, w, &l));
    assert(!tapstat_name_to_wire(".a", w, &l));
    char long_name[300];
    memset(long_name, 'a', sizeof(long_name));
    for (int i = 50; i < 290; i += 50) long_name[i] = '.';
    long_name[299] = 0;
    assert(!tapstat_name_to_wire(long_name, w, &l)); /* over 255 bytes */
}

int main(void) {
    test_fstrm();
    test_decoder();
    test_aggregate();
    test_tables();
    test_space_saving();
    test_names();
    printf("test_tapstat: all passed\n");
    return 0;
}

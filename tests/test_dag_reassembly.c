/*
 * test_dag_reassembly.c - dag's pcap L4 extraction and TCP stream reassembly.
 *
 *   1. pcap_extract_l4(): frames are built byte by byte from the RFC 791 / 8200 / 793 / 768 layouts for every link
 *      type (Ethernet, 802.1Q, Linux SLL, raw IP, auto-detect). Link-layer padding/trailers, IP options, fragments,
 *      truncation at every length and unsupported protocols are covered.
 *   2. tcp_reasm_feed(): a deterministic pseudo-random model. A stream of length-prefixed DNS messages (RFC 7766)
 *      is cut into random segments and delivered in order, with duplicated / overlapping retransmissions, with
 *      bounded reordering, in both directions, over several interleaved streams and across sequence-number
 *      wraparound. Oracle: every message is delivered exactly once, byte-identical, in order.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/dag_pcap_l4.h"
#include "tools/dag_tcp_reassembly.h"

#define N(a) (sizeof(a) / sizeof((a)[0]))

/* ---------------------------------------------------------------- frame builders */
typedef struct { uint8_t b[2048]; size_t n; } frame_t;
static void f8(frame_t *f, uint8_t v) { f->b[f->n++] = v; }
static void f16(frame_t *f, uint16_t v) { f8(f, (uint8_t)(v >> 8)); f8(f, (uint8_t)v); }
static void f32(frame_t *f, uint32_t v) { f16(f, (uint16_t)(v >> 16)); f16(f, (uint16_t)v); }
static void fbytes(frame_t *f, const void *p, size_t l) { memcpy(f->b + f->n, p, l); f->n += l; }

static void eth(frame_t *f, uint16_t ethertype, bool vlan) {
    static const uint8_t macs[12] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    f->n = 0; fbytes(f, macs, 12);
    if (vlan) { f16(f, 0x8100); f16(f, 0x0064); }
    f16(f, ethertype);
}
static void ip4(frame_t *f, uint8_t proto, uint16_t total_len, uint16_t frag, int ihl_words, const uint8_t src[4], const uint8_t dst[4]) {
    f8(f, (uint8_t)(0x40 | ihl_words)); f8(f, 0); f16(f, total_len); f16(f, 0x1234); f16(f, frag);
    f8(f, 64); f8(f, proto); f16(f, 0); fbytes(f, src, 4); fbytes(f, dst, 4);
    for (int i = 5; i < ihl_words; i++) f32(f, 0x01010101);      /* NOP options */
}
static void ip6(frame_t *f, uint8_t next, uint16_t payload_len, const uint8_t src[16], const uint8_t dst[16]) {
    f32(f, 0x60000000); f16(f, payload_len); f8(f, next); f8(f, 64); fbytes(f, src, 16); fbytes(f, dst, 16);
}
static void udp(frame_t *f, uint16_t sp, uint16_t dp, uint16_t len, const uint8_t *pl, size_t pll) {
    f16(f, sp); f16(f, dp); f16(f, len); f16(f, 0); if (pll) fbytes(f, pl, pll);
}
static void tcp(frame_t *f, uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack, uint8_t flags, int hdr_words, const uint8_t *pl, size_t pll) {
    f16(f, sp); f16(f, dp); f32(f, seq); f32(f, ack); f8(f, (uint8_t)(hdr_words << 4)); f8(f, flags); f16(f, 8192); f16(f, 0); f16(f, 0);
    for (int i = 5; i < hdr_words; i++) f32(f, 0x01010101);
    if (pll) fbytes(f, pl, pll);
}

static const uint8_t A4[4] = { 192, 0, 2, 1 }, B4[4] = { 192, 0, 2, 2 };
static const uint8_t A6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const uint8_t B6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

static void test_extract_l4(void) {
    printf("[TEST] dag pcap: pcap_extract_l4 for every link type, padding, options, fragments, truncation...\n");
    frame_t f;
    pcap_l4_info_t o;
    static const uint8_t dns[] = { 0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    static const uint8_t body[] = "hello-dns";

    /* Ethernet + IPv4 + UDP */
    eth(&f, 0x0800, false); ip4(&f, 17, 20 + 8 + sizeof(dns), 0, 5, A4, B4); udp(&f, 5353, 53, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(f.b, f.n, 1, &o));
    assert(o.ip_version == 4 && o.l4_proto == 17 && o.src_port == 5353 && o.dst_port == 53);
    assert(!memcmp(o.src_addr, A4, 4) && !memcmp(o.dst_addr, B4, 4));
    assert(o.l4_payload_len == sizeof(dns) && !memcmp(o.l4_payload, dns, sizeof(dns)));
    frame_t g = f; memset(g.b + g.n, 0, 20); g.n += 20;                   /* padding after the datagram: UDP length wins */
    assert(pcap_extract_l4(g.b, g.n, 1, &o) && o.l4_payload_len == sizeof(dns));
    frame_t t = f; t.n -= 4;                                              /* snaplen-truncated capture */
    assert(pcap_extract_l4(t.b, t.n, 1, &o) && o.l4_payload_len == sizeof(dns) - 4);
    frame_t bad = f; bad.b[14 + 20 + 4] = 0; bad.b[14 + 20 + 5] = 3;     /* bogus UDP length < 8 */
    assert(pcap_extract_l4(bad.b, bad.n, 1, &o) && o.l4_payload_len == sizeof(dns));

    /* 802.1Q VLAN; IPv4 options (IHL 7) */
    eth(&f, 0x0800, true); ip4(&f, 17, 20 + 8 + sizeof(dns), 0, 5, A4, B4); udp(&f, 1, 2, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.src_port == 1 && o.dst_port == 2 && o.l4_payload_len == sizeof(dns));
    eth(&f, 0x0800, false); ip4(&f, 17, 28 + 8 + sizeof(dns), 0, 7, A4, B4); udp(&f, 7, 8, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.src_port == 7 && o.dst_port == 8 && o.l4_payload_len == sizeof(dns));

    /* IPv6 + UDP, with a trailer after the IPv6 payload */
    eth(&f, 0x86DD, false); ip6(&f, 17, 8 + sizeof(dns), A6, B6); udp(&f, 9, 10, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.ip_version == 6 && !memcmp(o.src_addr, A6, 16) && o.l4_payload_len == sizeof(dns));
    frame_t g6 = f; memset(g6.b + g6.n, 0xEE, 6); g6.n += 6;
    assert(pcap_extract_l4(g6.b, g6.n, 1, &o) && o.l4_payload_len == sizeof(dns));

    /* TCP fields and payload */
    eth(&f, 0x0800, false); ip4(&f, 6, 20 + 20 + sizeof(body), 0, 5, A4, B4); tcp(&f, 10000, 53, 0xFFFFFFF0u, 77, 0x18, 5, body, sizeof(body));
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.l4_proto == 6 && o.tcp_seq == 0xFFFFFFF0u && o.tcp_ack == 77 && o.tcp_flags == 0x18);
    assert(o.l4_payload_len == sizeof(body) && !memcmp(o.l4_payload, body, sizeof(body)));
    /* A pure ACK padded to the 60-byte Ethernet minimum carries NO payload. The padding used to be reported as 6
     * payload bytes and fed into the DNS stream. */
    eth(&f, 0x0800, false); ip4(&f, 6, 40, 0, 5, A4, B4); tcp(&f, 10000, 53, 1, 2, 0x10, 5, NULL, 0);
    while (f.n < 60) f8(&f, 0);
    assert(f.n == 60 && pcap_extract_l4(f.b, f.n, 1, &o) && o.tcp_flags == 0x10);
    assert(o.l4_payload_len == 0);
    /* TCP header options + an FCS-like trailer */
    eth(&f, 0x0800, false); ip4(&f, 6, 20 + 24 + sizeof(body), 0, 5, A4, B4); tcp(&f, 1, 2, 5, 6, 0x18, 6, body, sizeof(body)); f32(&f, 0xDEADBEEF);
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.l4_payload_len == sizeof(body) && !memcmp(o.l4_payload, body, sizeof(body)));
    /* TCP over IPv6 */
    eth(&f, 0x86DD, false); ip6(&f, 6, 20 + sizeof(body), A6, B6); tcp(&f, 3, 4, 9, 9, 0x18, 5, body, sizeof(body));
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.ip_version == 6 && o.l4_proto == 6 && o.l4_payload_len == sizeof(body));

    /* A non-first IPv4 fragment has no L4 header (its first bytes are payload of the original datagram): ignored.
     * A first fragment (MF set, offset 0) is parsed. */
    eth(&f, 0x0800, false); ip4(&f, 17, 20 + 8 + sizeof(dns), 0x00B9, 5, A4, B4); udp(&f, 1, 2, 8 + sizeof(dns), dns, sizeof(dns));
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    eth(&f, 0x0800, false); ip4(&f, 17, 20 + 8 + sizeof(dns), 0x2000, 5, A4, B4); udp(&f, 1, 2, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(f.b, f.n, 1, &o) && o.src_port == 1);

    /* raw IP (101, 12), auto-detection of IP / Ethernet for other link types, Linux cooked capture (113) */
    frame_t r; r.n = 0; ip4(&r, 17, 20 + 8 + sizeof(dns), 0, 5, A4, B4); udp(&r, 11, 12, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(r.b, r.n, 101, &o) && o.src_port == 11);
    assert(pcap_extract_l4(r.b, r.n, 12, &o) && o.src_port == 11);
    assert(pcap_extract_l4(r.b, r.n, 0, &o) && o.src_port == 11);
    eth(&f, 0x0800, false); ip4(&f, 17, 20 + 8 + sizeof(dns), 0, 5, A4, B4); udp(&f, 13, 14, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(f.b, f.n, 999, &o) && o.src_port == 13);
    frame_t s; s.n = 0; f16(&s, 0); f16(&s, 1); f16(&s, 6);
    { static const uint8_t z8[8] = { 0 }; fbytes(&s, z8, 8); }
    f16(&s, 0x0800); ip4(&s, 17, 20 + 8 + sizeof(dns), 0, 5, A4, B4); udp(&s, 15, 16, 8 + sizeof(dns), dns, sizeof(dns));
    assert(pcap_extract_l4(s.b, s.n, 113, &o) && o.src_port == 15 && o.l4_payload_len == sizeof(dns));
    s.b[14] = 0x08; s.b[15] = 0x06;                                       /* SLL protocol = ARP */
    assert(!pcap_extract_l4(s.b, s.n, 113, &o));

    /* frames that are not DNS carriers */
    eth(&f, 0x0806, false); for (int i = 0; i < 28; i++) f8(&f, 0);                  /* ARP */
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    eth(&f, 0x0800, false); ip4(&f, 1, 28, 0, 5, A4, B4); f32(&f, 0); f32(&f, 0);     /* ICMP */
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    eth(&f, 0x0800, false); ip4(&f, 17, 28, 0, 4, A4, B4);                            /* IHL < 5 */
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    eth(&f, 0x0800, false); ip4(&f, 6, 40, 0, 5, A4, B4); tcp(&f, 1, 2, 1, 1, 0x10, 5, NULL, 0); f.b[14 + 20 + 12] = 0x40;   /* data offset 4 words */
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    f.b[14 + 20 + 12] = 0xF0;                                             /* data offset beyond the frame */
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    eth(&f, 0x0800, false); ip4(&f, 6, 40, 0, 5, A4, B4); f.b[14] = 0x75;    /* IPv4 header claims IHL 21 words: beyond frame */
    for (int i = 0; i < 6; i++) f8(&f, 0);
    assert(!pcap_extract_l4(f.b, f.n, 1, &o));
    frame_t v; v.n = 0; f8(&v, 0x50); for (int i = 0; i < 30; i++) f8(&v, 0);        /* neither IPv4 nor IPv6 */
    assert(!pcap_extract_l4(v.b, v.n, 101, &o));
    assert(!pcap_extract_l4(NULL, 100, 1, &o) && !pcap_extract_l4(f.b, f.n, 1, NULL) && !pcap_extract_l4(f.b, 5, 1, &o));

    /* truncation at every length: never a fault; a positive verdict must point inside the captured bytes */
    frame_t seeds[6];
    eth(&seeds[0], 0x0800, false); ip4(&seeds[0], 17, 20 + 8 + sizeof(dns), 0, 5, A4, B4); udp(&seeds[0], 1, 2, 8 + sizeof(dns), dns, sizeof(dns));
    eth(&seeds[1], 0x0800, true);  ip4(&seeds[1], 6, 20 + 24 + sizeof(body), 0, 5, A4, B4); tcp(&seeds[1], 1, 2, 5, 6, 0x18, 6, body, sizeof(body));
    eth(&seeds[2], 0x86DD, false); ip6(&seeds[2], 17, 8 + sizeof(dns), A6, B6); udp(&seeds[2], 1, 2, 8 + sizeof(dns), dns, sizeof(dns));
    eth(&seeds[3], 0x86DD, false); ip6(&seeds[3], 6, 20 + sizeof(body), A6, B6); tcp(&seeds[3], 1, 2, 5, 6, 0x18, 5, body, sizeof(body));
    seeds[4] = s;
    seeds[5].n = 0; ip4(&seeds[5], 17, 28 + 8 + sizeof(dns), 0, 7, A4, B4); udp(&seeds[5], 1, 2, 8 + sizeof(dns), dns, sizeof(dns));
    static const uint32_t links[] = { 1, 1, 1, 1, 113, 101 };
    size_t truncs = 0;
    for (size_t k = 0; k < N(seeds); k++) {
        for (size_t cut = 0; cut <= seeds[k].n; cut++) {
            uint8_t *exact = malloc(cut ? cut : 1);
            memcpy(exact, seeds[k].b, cut);
            pcap_l4_info_t x;
            if (pcap_extract_l4(exact, cut, links[k], &x)) {
                assert(x.l4_payload >= exact && x.l4_payload + x.l4_payload_len <= exact + cut);
            }
            free(exact);
            truncs++;
        }
    }
    assert(truncs > 200);

    /* endpoint canonicalization is symmetric */
    uint8_t k1[32], k2[32]; uint16_t p1[2], p2[2]; int d1, d2;
    uint8_t a[16] = { 1 }, b[16] = { 2 };
    pcap_canonicalize_endpoints(a, 100, b, 200, k1, p1, &d1);
    pcap_canonicalize_endpoints(b, 200, a, 100, k2, p2, &d2);
    assert(!memcmp(k1, k2, 32) && p1[0] == p2[0] && p1[1] == p2[1] && d1 == 0 && d2 == 1);
    pcap_canonicalize_endpoints(a, 300, a, 200, k1, p1, &d1);              /* identical addresses: ports decide */
    pcap_canonicalize_endpoints(a, 200, a, 300, k2, p2, &d2);
    assert(p1[0] == 200 && p1[1] == 300 && p2[0] == 200 && p2[1] == 300 && d1 == 1 && d2 == 0);
    pcap_canonicalize_endpoints(a, 5, a, 5, k1, p1, NULL);                 /* same endpoint, no direction requested */
    printf("  -> pcap_extract_l4 passed (%zu truncated frames).\n", truncs);
}

/* ---------------------------------------------------------------- reassembly model */
static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(uint32_t n) {                                          /* deterministic xorshift64 */
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return n ? (uint32_t)(g_rng % n) : 0;
}

#define MAX_MSGS 40
typedef struct {
    uint8_t *bytes; size_t len;
    size_t nmsg; size_t moff[MAX_MSGS], mlen[MAX_MSGS];
} bytestream_t;

static void make_stream(bytestream_t *s, size_t nmsg, size_t max_msg) {
    s->len = 0; s->nmsg = nmsg;
    s->bytes = malloc(nmsg * (max_msg + 2));
    for (size_t i = 0; i < nmsg; i++) {
        size_t l = 12 + rnd((uint32_t)(max_msg - 12));
        s->moff[i] = s->len + 2; s->mlen[i] = l;
        s->bytes[s->len++] = (uint8_t)(l >> 8); s->bytes[s->len++] = (uint8_t)l;
        for (size_t k = 0; k < l; k++) s->bytes[s->len++] = (uint8_t)rnd(256);
    }
}

typedef struct { size_t off, len; } seg_t;
static size_t make_segments(size_t total, size_t max_seg, seg_t *out) {
    size_t n = 0, off = 0;
    while (off < total) {
        size_t l = 1 + rnd((uint32_t)max_seg);
        if (off + l > total) l = total - off;
        out[n].off = off; out[n].len = l; n++; off += l;
    }
    return n;
}

#define MAX_STREAMS 4
#define MAX_SEGS 4096
typedef struct {
    bytestream_t st[MAX_STREAMS][2];         /* [slot][direction] */
    size_t got[MAX_STREAMS][2];              /* messages delivered so far */
    bool mismatch;
    size_t total_cb;
} model_t;
static model_t g_m;

static void model_cb(void *ctx, uint32_t stream_id, int direction, const uint8_t *addr_key, const uint16_t *port_key,
                     const uint8_t *msg, size_t len) {
    (void)ctx; (void)stream_id; (void)addr_key;
    int slot = (port_key[0] == 53 ? port_key[1] : port_key[0]) - 10000;
    assert(slot >= 0 && slot < MAX_STREAMS && (direction == 0 || direction == 1));
    bytestream_t *s = &g_m.st[slot][direction];
    size_t i = g_m.got[slot][direction]++;
    g_m.total_cb++;
    if (i >= s->nmsg || len != s->mlen[i] || memcmp(msg, s->bytes + s->moff[i], len) != 0) g_m.mismatch = true;
}

/* direction 0 = client -> server (A4 < B4 so it canonicalizes to direction 0) */
static void feed(tcp_reasm_table_t *t, int slot, int dir, uint32_t isn, const bytestream_t *s, size_t off, size_t len, uint8_t flags) {
    pcap_l4_info_t l4;
    memset(&l4, 0, sizeof(l4));
    l4.ip_version = 4; l4.l4_proto = 6;
    const uint8_t *src = dir == 0 ? A4 : B4, *dst = dir == 0 ? B4 : A4;
    memcpy(l4.src_addr, src, 4); memcpy(l4.dst_addr, dst, 4);
    l4.src_port = dir == 0 ? (uint16_t)(10000 + slot) : 53;
    l4.dst_port = dir == 0 ? 53 : (uint16_t)(10000 + slot);
    l4.tcp_seq = isn + (uint32_t)off;
    l4.tcp_flags = flags;
    l4.l4_payload = s->bytes + off;
    l4.l4_payload_len = len;
    tcp_reasm_feed(t, &l4, model_cb, NULL);
}

static void model_reset(size_t nmsg, size_t max_msg, size_t nstreams, bool both_dirs) {
    for (size_t sl = 0; sl < MAX_STREAMS; sl++)
        for (int d = 0; d < 2; d++) { free(g_m.st[sl][d].bytes); g_m.st[sl][d].bytes = NULL; g_m.st[sl][d].nmsg = 0; g_m.got[sl][d] = 0; }
    g_m.mismatch = false; g_m.total_cb = 0;
    for (size_t sl = 0; sl < nstreams; sl++)
        for (int d = 0; d < (both_dirs ? 2 : 1); d++) make_stream(&g_m.st[sl][d], nmsg, max_msg);
}

static void model_verify(size_t nstreams, bool both_dirs, const char *what) {
    assert(!g_m.mismatch);
    for (size_t sl = 0; sl < nstreams; sl++)
        for (int d = 0; d < (both_dirs ? 2 : 1); d++)
            if (g_m.got[sl][d] != g_m.st[sl][d].nmsg) {
                fprintf(stderr, "%s: stream %zu dir %d delivered %zu of %zu messages\n", what, sl, d, g_m.got[sl][d], g_m.st[sl][d].nmsg);
                assert(0);
            }
}

/* mode: 0 in order, 1 + duplicates/overlaps, 2 bounded reordering, 3 both */
static void run_model(int mode, size_t nstreams, bool both_dirs, uint32_t isn_base, size_t max_seg, int trials) {
    static seg_t segs[MAX_STREAMS][2][MAX_SEGS];
    static size_t nseg[MAX_STREAMS][2], next_idx[MAX_STREAMS][2];
    static size_t order[MAX_STREAMS][2][MAX_SEGS];
    for (int trial = 0; trial < trials; trial++) {
        model_reset(6 + rnd(10), 300 + rnd(500), nstreams, both_dirs);
        tcp_reasm_table_t *t = tcp_reasm_create((uint32_t)nstreams + 1, 256 * 1024);
        assert(t);
        uint32_t isn[MAX_STREAMS][2];
        for (size_t sl = 0; sl < nstreams; sl++)
            for (int d = 0; d < (both_dirs ? 2 : 1); d++) {
                isn[sl][d] = isn_base ? isn_base + rnd(200) : rnd(1u << 30);
                nseg[sl][d] = make_segments(g_m.st[sl][d].len, max_seg, segs[sl][d]);
                assert(nseg[sl][d] < MAX_SEGS);
                for (size_t i = 0; i < nseg[sl][d]; i++) order[sl][d][i] = i;
                if (mode & 2) {                                              /* segment 0 first, then blocks of <= 5 shuffled */
                    for (size_t base = 1; base < nseg[sl][d]; base += 5) {
                        size_t blk = nseg[sl][d] - base < 5 ? nseg[sl][d] - base : 5;
                        for (size_t i = blk; i > 1; i--) {
                            size_t j = rnd((uint32_t)i);
                            size_t tmp = order[sl][d][base + i - 1]; order[sl][d][base + i - 1] = order[sl][d][base + j]; order[sl][d][base + j] = tmp;
                        }
                    }
                }
                next_idx[sl][d] = 0;
            }
        size_t remaining = 0;
        for (size_t sl = 0; sl < nstreams; sl++) for (int d = 0; d < (both_dirs ? 2 : 1); d++) remaining += nseg[sl][d];
        while (remaining) {
            size_t sl = rnd((uint32_t)nstreams);
            int d = both_dirs ? (int)rnd(2) : 0;
            if (next_idx[sl][d] >= nseg[sl][d]) continue;
            size_t idx = order[sl][d][next_idx[sl][d]++];
            seg_t sg = segs[sl][d][idx];
            feed(t, (int)sl, d, isn[sl][d], &g_m.st[sl][d], sg.off, sg.len, 0x18);
            remaining--;
            if ((mode & 1) && next_idx[sl][d] > 0 && rnd(4) == 0) {           /* exact retransmission of an earlier segment */
                size_t back = order[sl][d][rnd((uint32_t)next_idx[sl][d])];
                if (segs[sl][d][back].off <= sg.off + sg.len)
                    feed(t, (int)sl, d, isn[sl][d], &g_m.st[sl][d], segs[sl][d][back].off, segs[sl][d][back].len, 0x18);
            }
            if ((mode & 1) && rnd(5) == 0) {                                   /* overlapping retransmission spanning boundaries */
                size_t back = order[sl][d][rnd((uint32_t)next_idx[sl][d])];
                size_t start = segs[sl][d][back].off + rnd((uint32_t)segs[sl][d][back].len);
                size_t want = 1 + rnd((uint32_t)max_seg);
                if (start + want > g_m.st[sl][d].len) want = g_m.st[sl][d].len - start;
                if (want > 0 && start <= sg.off + sg.len)                      /* only bytes the sender has already sent */
                    feed(t, (int)sl, d, isn[sl][d], &g_m.st[sl][d], start, want > sg.off + sg.len - start ? sg.off + sg.len - start : want, 0x18);
            }
        }
        model_verify(nstreams, both_dirs, "model");
        tcp_reasm_destroy(t);
    }
}

static void test_reassembly_model(void) {
    printf("[TEST] dag reassembly: randomized segmentation / retransmission / reordering model...\n");
    run_model(0, 1, false, 0, 1200, 300);                 /* in-order, random cuts */
    run_model(0, 1, false, 0, 40, 200);                   /* tiny segments: messages spread over many segments */
    run_model(1, 1, false, 0, 900, 300);                  /* duplicates + overlapping retransmissions */
    run_model(2, 1, false, 0, 500, 300);                  /* bounded reordering */
    run_model(3, 1, true, 0, 700, 300);                   /* both, both directions */
    run_model(3, 3, true, 0, 600, 200);                   /* three interleaved streams, both directions */
    run_model(3, 2, true, 0xFFFFFF00u, 300, 300);         /* sequence numbers wrap within the stream */
    printf("  -> %zu messages delivered byte-exactly in order.\n", g_m.total_cb);
}

/* ---------------------------------------------------------------- limits, eviction, ignored input */
static void test_reassembly_limits(void) {
    printf("[TEST] dag reassembly: buffer cap, LRU eviction, ignored segments...\n");
    static const uint8_t dnsmsg[] = { 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    bytestream_t one = { .bytes = (uint8_t *)dnsmsg, .len = sizeof(dnsmsg), .nmsg = 1, .moff = { 2 }, .mlen = { 12 } };

    /* NULL / non-TCP / empty-payload segments are ignored */
    pcap_l4_info_t l4;
    memset(&l4, 0, sizeof(l4));
    tcp_reasm_feed(NULL, &l4, model_cb, NULL);
    tcp_reasm_table_t *t = tcp_reasm_create(2, 4096);
    tcp_reasm_feed(t, NULL, model_cb, NULL);
    l4.l4_proto = 17; l4.l4_payload = dnsmsg; l4.l4_payload_len = sizeof(dnsmsg);
    tcp_reasm_feed(t, &l4, model_cb, NULL);                                /* UDP */
    l4.l4_proto = 6; l4.l4_payload_len = 0;
    tcp_reasm_feed(t, &l4, model_cb, NULL);                                /* pure ACK / SYN / FIN */
    tcp_reasm_destroy(NULL);

    /* max_streams = 2, three streams: the least recently used one is evicted and a later segment on it starts afresh */
    model_reset(1, 20, 0, false);
    for (int sl = 0; sl < 3; sl++) {
        g_m.st[sl][0] = one; g_m.st[sl][0].bytes = malloc(sizeof(dnsmsg)); memcpy(g_m.st[sl][0].bytes, dnsmsg, sizeof(dnsmsg));
        g_m.st[sl][0].nmsg = 2; g_m.st[sl][0].moff[1] = 2; g_m.st[sl][0].mlen[1] = 12;   /* the same message is sent twice */
        g_m.got[sl][0] = 0;
    }
    for (int sl = 0; sl < 3; sl++) feed(t, sl, 0, 1000 + 7 * sl, &g_m.st[sl][0], 0, sizeof(dnsmsg), 0x18);
    assert(!g_m.mismatch && g_m.got[0][0] == 1 && g_m.got[1][0] == 1 && g_m.got[2][0] == 1);
    feed(t, 0, 0, 5000, &g_m.st[0][0], 0, sizeof(dnsmsg), 0x18);           /* stream 0 was evicted: new state, delivered again */
    assert(!g_m.mismatch && g_m.got[0][0] == 2);
    tcp_reasm_destroy(t);
    for (int sl = 0; sl < 3; sl++) { free(g_m.st[sl][0].bytes); g_m.st[sl][0].bytes = NULL; }

    /* per-direction buffer cap: a message that can not fit is dropped together with the stream; the table stays usable */
    static uint8_t big[600];
    big[0] = 0x02; big[1] = 0x00; for (int i = 2; i < 600; i++) big[i] = (uint8_t)i;      /* 512-byte message */
    bytestream_t bigs = { .bytes = big, .len = 514, .nmsg = 1, .moff = { 2 }, .mlen = { 512 } };
    t = tcp_reasm_create(4, 256);
    model_reset(1, 20, 0, false);
    g_m.st[0][0] = bigs; g_m.got[0][0] = 0;
    feed(t, 0, 0, 100, &bigs, 0, 200, 0x18);
    feed(t, 0, 0, 100, &bigs, 200, 314, 0x18);
    assert(g_m.got[0][0] == 0 && !g_m.mismatch);                           /* nothing delivered, no crash */
    g_m.st[1][0] = one; g_m.st[1][0].bytes = malloc(sizeof(dnsmsg)); memcpy(g_m.st[1][0].bytes, dnsmsg, sizeof(dnsmsg));
    feed(t, 1, 0, 900, &g_m.st[1][0], 0, sizeof(dnsmsg), 0x18);
    assert(g_m.got[1][0] == 1 && !g_m.mismatch);
    free(g_m.st[1][0].bytes); g_m.st[1][0].bytes = NULL;
    g_m.st[0][0].bytes = NULL;
    tcp_reasm_destroy(t);

    /* an out-of-order segment larger than the OOO slot (1500 bytes) is not stored; more than 8 pending OOO segments
     * overwrite a slot: neither may corrupt memory (ASan) or deliver a wrong message */
    t = tcp_reasm_create(2, 64 * 1024);
    model_reset(1, 20, 0, false);
    static uint8_t huge[4000];
    huge[0] = 0x0F; huge[1] = 0xA0 - 2; for (int i = 2; i < 4000; i++) huge[i] = (uint8_t)(i * 7);
    bytestream_t hs = { .bytes = huge, .len = 4000, .nmsg = 1, .moff = { 2 }, .mlen = { 3998 } };
    g_m.st[0][0] = hs; g_m.got[0][0] = 0;
    feed(t, 0, 0, 10, &hs, 0, 100, 0x18);
    feed(t, 0, 0, 10, &hs, 200, 2000, 0x18);                               /* too large for an OOO slot: ignored */
    for (int i = 0; i < 12; i++) feed(t, 0, 0, 10, &hs, 3000 + i * 50, 40, 0x18);   /* 12 disjoint OOO segments, 8 slots */
    feed(t, 0, 0, 10, &hs, 100, 1000, 0x18);                               /* fills part of the gap */
    assert(!g_m.mismatch);
    tcp_reasm_destroy(t);
    g_m.st[0][0].bytes = NULL;

    /* mid-stream capture: the first segment seen is not the first one; the missing head is prepended before any
     * message has been drained (dag can start capturing in the middle of a connection) */
    t = tcp_reasm_create(2, 64 * 1024);
    model_reset(1, 300, 1, false);
    bytestream_t *m = &g_m.st[0][0];
    feed(t, 0, 0, 77, m, 20, m->len - 20, 0x18);                           /* tail first (buffered, nothing decodable yet) */
    feed(t, 0, 0, 77, m, 0, 20, 0x18);                                     /* then the head */
    assert(!g_m.mismatch && g_m.got[0][0] == 1);
    tcp_reasm_destroy(t);
    model_reset(1, 20, 0, false);
    printf("  -> limits and eviction passed.\n");
}

/* ---------------------------------------------------------------- targeted state-machine paths */
static void custom_stream(bytestream_t *s, size_t nmsg, const size_t *lens) {
    s->len = 0; s->nmsg = nmsg;
    s->bytes = malloc(4096);
    for (size_t i = 0; i < nmsg; i++) {
        s->bytes[s->len++] = (uint8_t)(lens[i] >> 8); s->bytes[s->len++] = (uint8_t)lens[i];
        s->moff[i] = s->len; s->mlen[i] = lens[i];
        for (size_t k = 0; k < lens[i]; k++) s->bytes[s->len++] = (uint8_t)(0x30 + (k * 7 + i * 13) % 200);
    }
}

static void test_reassembly_paths(void) {
    printf("[TEST] dag reassembly: mid-stream capture, prepend, overlap and stale-retransmission paths...\n");
    tcp_reasm_table_t *t;
    bytestream_t *m;

    /* (a) capture starts in the middle of a message. The tail arrives first (its first two bytes read as a length
     *     prefix < 12, so nothing can be decoded), then the head arrives out of order, then the gap. Before any
     *     message has been drained the missing head is prepended. */
    static const size_t one_msg[] = { 400 };
    for (int order = 0; order < 2; order++) {
        model_reset(0, 0, 0, false);
        m = &g_m.st[0][0];
        custom_stream(m, 1, one_msg);
        m->bytes[300] = 0; m->bytes[301] = 0;                                 /* the tail starts with a "length" of 0 */
        t = tcp_reasm_create(2, 64 * 1024);
        feed(t, 0, 0, 5000, m, 300, m->len - 300, 0x18);                      /* tail: [300, 402) */
        if (order == 0) {
            feed(t, 0, 0, 5000, m, 0, 100, 0x18);                             /* head [0,100): not adjacent -> parked out of order */
            assert(g_m.got[0][0] == 0);
            feed(t, 0, 0, 5000, m, 100, 200, 0x18);                           /* middle: prepended, then the parked head merges */
        } else {
            feed(t, 0, 0, 5000, m, 100, 200, 0x18);                           /* adjacent: prepended directly */
            assert(g_m.got[0][0] == 0);
            feed(t, 0, 0, 5000, m, 0, 100, 0x18);
        }
        assert(!g_m.mismatch && g_m.got[0][0] == 1);
        tcp_reasm_destroy(t);
    }

    /* (a2) a 6000-byte message captured from the middle: prepending the head must grow the buffer past its initial 4 KiB */
    {
        static const size_t big_msg[] = { 6000 };
        model_reset(0, 0, 0, false);
        m = &g_m.st[0][0];
        m->bytes = malloc(8192);
        m->len = 0; m->nmsg = 1; m->moff[0] = 2; m->mlen[0] = 6000;
        m->bytes[m->len++] = (uint8_t)(big_msg[0] >> 8); m->bytes[m->len++] = (uint8_t)big_msg[0];
        for (size_t k = 0; k < big_msg[0]; k++) m->bytes[m->len++] = (uint8_t)(0x21 + (k * 11) % 90);
        m->bytes[3000] = 0; m->bytes[3001] = 0;
        t = tcp_reasm_create(2, 64 * 1024);
        feed(t, 0, 0, 40000, m, 3000, 3002, 0x18);            /* tail (3002 bytes, fits the 4096-byte buffer) */
        feed(t, 0, 0, 40000, m, 1500, 1500, 0x18);            /* prepend: 4502 bytes > 4096 -> realloc */
        assert(g_m.got[0][0] == 0);
        feed(t, 0, 0, 40000, m, 0, 1500, 0x18);
        assert(!g_m.mismatch && g_m.got[0][0] == 1);
        tcp_reasm_destroy(t);
    }

    /* (b) out-of-order segments that overlap each other, are fully redundant, or are stored twice */
    static const size_t lens_b[] = { 200, 300 };
    model_reset(0, 0, 0, false);
    m = &g_m.st[0][0];
    custom_stream(m, 2, lens_b);                                              /* 504 bytes */
    t = tcp_reasm_create(2, 64 * 1024);
    feed(t, 0, 0, 900, m, 0, 100, 0x18);                                      /* base */
    feed(t, 0, 0, 900, m, 200, 100, 0x18);                                    /* OOO [200,300) */
    feed(t, 0, 0, 900, m, 200, 100, 0x18);                                    /* the same OOO segment again (duplicate slot) */
    feed(t, 0, 0, 900, m, 150, 100, 0x18);                                    /* OOO [150,250) overlapping the previous one */
    feed(t, 0, 0, 900, m, 110, 30, 0x18);                                     /* OOO [110,140) that will become redundant */
    feed(t, 0, 0, 900, m, 100, 50, 0x18);                                     /* fills [100,150): everything parked is merged */
    assert(!g_m.mismatch && g_m.got[0][0] == 1);                              /* first message ends at 202 */
    feed(t, 0, 0, 900, m, 300, m->len - 300, 0x18);
    assert(!g_m.mismatch && g_m.got[0][0] == 2);
    tcp_reasm_destroy(t);

    /* (c) after a message was delivered: stale retransmissions are ignored, an overlapping one adds only its new tail */
    model_reset(0, 0, 0, false);
    m = &g_m.st[0][0];
    custom_stream(m, 2, lens_b);
    size_t first = 2 + lens_b[0];
    t = tcp_reasm_create(2, 64 * 1024);
    feed(t, 0, 0, 77, m, 0, first, 0x18);                                     /* message 1 delivered */
    assert(g_m.got[0][0] == 1);
    feed(t, 0, 0, 77, m, 0, 10, 0x18);                                        /* stale: entirely before the buffer */
    feed(t, 0, 0, 77, m, first, 50, 0x18);                                    /* start of message 2 */
    feed(t, 0, 0, 77, m, first - 30, 110, 0x18);                              /* starts in drained data, ends beyond next_seq */
    feed(t, 0, 0, 77, m, first + 60, 20, 0x18);                               /* out of order ahead ... */
    feed(t, 0, 0, 77, m, first - 5, 10, 0x18);                                /* stale again */
    feed(t, 0, 0, 77, m, first + 80, 10, 0x18);                               /* ... then in order: merges the parked one? (gap at 110..) */
    feed(t, 0, 0, 77, m, first + 50, m->len - first - 50, 0x18);              /* the rest */
    assert(!g_m.mismatch && g_m.got[0][0] == 2);
    /* an out-of-order segment that starts inside drained data and reaches beyond the buffer (stale + novel tail) */
    tcp_reasm_destroy(t);
    model_reset(0, 0, 0, false);
    printf("  -> targeted reassembly paths passed.\n");
}

int main(void) {
    printf("=== Starting dag pcap / TCP Reassembly Tests ===\n");
    test_extract_l4();
    test_reassembly_model();
    test_reassembly_limits();
    test_reassembly_paths();
    printf("=== All dag pcap / TCP Reassembly Tests PASSED ===\n");
    return 0;
}

/* dnsqps: Ethernet / ARP / IPv4 / IPv6 / UDP frames for the kernel-bypass paths (AF_XDP, netmap).  No I/O here: the functions build and read
 * byte strings, so they are tested on every OS.  Checksums: RFC 1071 (the Internet checksum); the UDP checksum over the IPv4 or IPv6 pseudo header
 * (RFC 768, RFC 8200 8.1); ARP: RFC 826; neighbor discovery: RFC 4861 (a solicited-node multicast address, hop limit 255).
 * Everything read from a frame is checked against the length first: the frames come from the network. */
#include "dnsqps.h"
#include <string.h>

uint32_t dq_csum_add(uint32_t sum, const uint8_t *p, size_t n) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (i < n) sum += (uint32_t)(p[i] << 8);
    return sum;
}

uint16_t dq_csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)sum;
}

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static unsigned get16(const uint8_t *p) { return (unsigned)((p[0] << 8) | p[1]); }

void dq_frame_tpl_init(dq_frame_tpl_t *t, const uint8_t smac[6], const uint8_t dmac[6], bool v6, const uint8_t *sip, const uint8_t *dip,
                       uint16_t sport, uint16_t dport) {
    memset(t, 0, sizeof *t);
    t->v6 = v6;
    memcpy(t->hdr, dmac, 6);
    memcpy(t->hdr + 6, smac, 6);
    uint8_t *ip = t->hdr + 14;
    if (!v6) {
        put16(t->hdr + 12, 0x0800);
        ip[0] = 0x45;
        ip[6] = 0x40;   /* DF; the identification stays 0 (RFC 6864: an atomic datagram) */
        ip[8] = 64;
        ip[9] = 17;
        memcpy(ip + 12, sip, 4);
        memcpy(ip + 16, dip, 4);
        t->hlen = 14 + 20 + 8;
        t->psum = dq_csum_add(dq_csum_add(0, sip, 4), dip, 4) + 17;
    } else {
        put16(t->hdr + 12, 0x86DD);
        ip[0] = 0x60;
        ip[6] = 17;
        ip[7] = 64;
        memcpy(ip + 8, sip, 16);
        memcpy(ip + 24, dip, 16);
        t->hlen = 14 + 40 + 8;
        t->psum = dq_csum_add(dq_csum_add(0, sip, 16), dip, 16) + 17;
    }
    put16(t->hdr + t->hlen - 8, sport);
    put16(t->hdr + t->hlen - 6, dport);
}

size_t dq_frame_build(const dq_frame_tpl_t *t, uint8_t *out, size_t cap, const uint8_t *payload, size_t plen) {
    size_t ulen = 8 + plen;
    if (plen > 65000 || cap < t->hlen + plen) return 0;
    memcpy(out, t->hdr, t->hlen);
    uint8_t *ip = out + 14, *udp = out + t->hlen - 8;
    if (!t->v6) {
        put16(ip + 2, (unsigned)(20 + ulen));
        put16(ip + 10, 0);
        put16(ip + 10, (unsigned)(uint16_t)~dq_csum_fold(dq_csum_add(0, ip, 20)));
    } else {
        put16(ip + 4, (unsigned)ulen);
    }
    put16(udp + 4, (unsigned)ulen);
    put16(udp + 6, 0);
    memcpy(udp + 8, payload, plen);
    uint16_t c = (uint16_t)~dq_csum_fold(dq_csum_add(t->psum + (uint32_t)ulen, udp, ulen));
    put16(udp + 6, c ? c : 0xFFFF);   /* RFC 768: a computed zero is sent as all ones */
    return t->hlen + plen;
}

/* a destination address is ours: all of it, or only the network bits of mask (a source prefix: -b ADDR/LEN) */
static bool ip_ours(const uint8_t *a, const uint8_t *ours, const uint8_t *mask, size_t n) {
    for (size_t i = 0; i < n; i++)
        if ((a[i] ^ ours[i]) & (mask ? mask[i] : 0xFF)) return false;
    return true;
}

int dq_frame_parse_udp(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, dq_udp_view_t *v) {
    return dq_frame_parse_udp_pfx(f, n, v6, our_ip, NULL, v);
}

int dq_frame_parse_udp_pfx(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, const uint8_t *mask, dq_udp_view_t *v) {
    if (n < 14) return -1;
    size_t off = 14;
    unsigned et = get16(f + 12);
    if (et == 0x8100) {   /* one VLAN tag */
        if (n < 18) return -1;
        et = get16(f + 16);
        off = 18;
    }
    const uint8_t *udp;
    size_t ulen;
    memset(v, 0, sizeof *v);
    if (!v6) {
        if (et != 0x0800 || n < off + 20) return -1;
        const uint8_t *ip = f + off;
        size_t ihl = (size_t)(ip[0] & 15) * 4, tot = get16(ip + 2);
        if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17) return -1;
        if ((ip[6] & 0x20) || (get16(ip + 6) & 0x1FFF)) return -1;   /* a fragment */
        if (tot < ihl + 8 || off + tot > n || !ip_ours(ip + 16, our_ip, mask, 4)) return -1;
        udp = ip + ihl;
        ulen = get16(udp + 4);
        if (ulen < 8 || ihl + ulen > tot) return -1;
        memcpy(v->sip, ip + 12, 4);
    } else {
        if (et != 0x86DD || n < off + 40 + 8) return -1;
        const uint8_t *ip = f + off;
        size_t pl = get16(ip + 4);
        if ((ip[0] >> 4) != 6 || ip[6] != 17 || pl < 8 || off + 40 + pl > n || !ip_ours(ip + 24, our_ip, mask, 16)) return -1;
        udp = ip + 40;
        ulen = get16(udp + 4);
        if (ulen < 8 || ulen > pl) return -1;
        memcpy(v->sip, ip + 8, 16);
    }
    v->v6 = v6;
    v->sport = (uint16_t)get16(udp);
    v->dport = (uint16_t)get16(udp + 2);
    v->payload = udp + 8;
    v->plen = (unsigned)(ulen - 8);
    memcpy(v->smac, f + 6, 6);
    return 0;
}

/* ---------------------------------------------------------------- patching a pre-built frame
 * RFC 1624 3, eqn. 3: HC' = ~(~HC + ~m + m') for a 16-bit word m of the data that becomes m'.  Every changed word adds ~m + m' to one accumulator (at most
 * 14 words of 17 bits: no overflow of 32 bits); one fold and one complement per checksum.  The IPv4 header checksum covers the source address only (the ID
 * stays 0, RFC 6864); IPv6 has no header checksum.  The UDP checksum covers the pseudo header (the source address, RFC 768; RFC 8200 8.1 for IPv6), the
 * source port, the DNS ID and the cookie.  RFC 768: a computed zero is sent as 0xFFFF; a stored 0xFFFF is the same value in ones' complement, so
 * ~HC = 0 starts the sum correctly, and eqn. 3 itself never produces 0xFFFF from a valid checksum. */
static uint32_t word_swap(uint8_t *p, unsigned neww) {   /* write the word, return ~old + new */
    unsigned old = get16(p);
    put16(p, neww);
    return (uint32_t)(uint16_t)~old + neww;
}

static uint16_t csum_update(unsigned hc, uint32_t acc) { return (uint16_t)~dq_csum_fold((uint32_t)(uint16_t)~hc + acc); }

int dq_frame_cap_check(size_t cap, const char *what, char *err, size_t errlen) {
    if (cap >= DQ_FRMAX) return 0;
    snprintf(err, errlen, "%s: buffers of %zu bytes are smaller than the largest query frame (%u bytes)", what, cap, (unsigned)DQ_FRMAX);
    return -1;
}

size_t dq_frame_emit(uint8_t *dst, size_t cap, const dq_fsend_t *s, bool v6, uint16_t sport) {
    unsigned hlen = v6 ? 62 : 42;
    if (cap < s->flen || s->flen < hlen + 12) return 0;
    memcpy(dst, s->frame, s->flen);
    uint8_t *ip = dst + 14, *udp = dst + hlen - 8;
    uint32_t acc = word_swap(udp, sport), ipacc = 0;
    acc += word_swap(dst + hlen, s->id);
    if (s->set_sip) {
        uint8_t *a = v6 ? ip + 8 : ip + 12;
        for (unsigned i = 0; i < (v6 ? 8u : 2u); i++) {
            uint32_t d = word_swap(a + 2 * i, (unsigned)((s->sip[2 * i] << 8) | s->sip[2 * i + 1]));
            acc += d;
            ipacc += d;
        }
        if (!v6) put16(ip + 10, csum_update(get16(ip + 10), ipacc));
    }
    if (s->cookie_off && (size_t)s->cookie_off + 8 <= s->flen && s->cookie_off >= hlen + 12) {
        /* the cookie is 8 octets at any offset of the message: the checksum adds up 16-bit words counted from the UDP header, so with an odd offset the
         * first and the last word hold one octet of the neighbours too; an odd last octet of the datagram counts as followed by a zero (RFC 768) */
        size_t u = (size_t)s->cookie_off - (hlen - 8), ulen = s->flen - (hlen - 8), start = u & ~(size_t)1, avail = ulen - start;
        uint8_t was[10] = { 0 }, now[10] = { 0 };
        if (avail > 10) avail = 10;
        memcpy(was, udp + start, avail);
        memcpy(now, was, sizeof now);
        memcpy(now + (u & 1), s->cookie, 8);
        memcpy(udp + start, now, avail);
        for (unsigned i = 0; i < 10; i += 2) acc += (uint32_t)(uint16_t)~get16(was + i) + get16(now + i);
    }
    uint16_t c = csum_update(get16(udp + 6), acc);
    put16(udp + 6, c ? c : 0xFFFF);
    return s->flen;
}

/* the checksums of a UDP frame that dq_frame_parse_udp() accepted are right (the raw reflector drops a frame whose checksum is wrong, as a host would) */
static bool frame_csums_ok(const uint8_t *f, bool v6, const dq_udp_view_t *v) {
    const uint8_t *udp = v->payload - 8, *ip = f + (get16(f + 12) == 0x8100 ? 18 : 14);
    size_t ulen = 8 + (size_t)v->plen;
    uint32_t s = 17 + (uint32_t)ulen;
    if (!v6) {
        if (dq_csum_fold(dq_csum_add(0, ip, (size_t)(udp - ip))) != 0xFFFF) return false;
        if (get16(udp + 6) == 0) return true;   /* RFC 768: no checksum */
        s = dq_csum_add(s, ip + 12, 8);
    } else {
        s = dq_csum_add(s, ip + 8, 32);
    }
    return dq_csum_fold(dq_csum_add(s, udp, ulen)) == 0xFFFF;
}

/* ---------------------------------------------------------------- ARP */
static size_t arp_frame(uint8_t *out, size_t cap, const uint8_t dmac[6], const uint8_t smac[6], unsigned op, const uint8_t sha[6], const uint8_t spa[4],
                        const uint8_t tha[6], const uint8_t tpa[4]) {
    if (cap < 60) return 0;
    memset(out, 0, 60);   /* padded to the minimum frame */
    memcpy(out, dmac, 6);
    memcpy(out + 6, smac, 6);
    put16(out + 12, 0x0806);
    uint8_t *a = out + 14;
    put16(a, 1);
    put16(a + 2, 0x0800);
    a[4] = 6;
    a[5] = 4;
    put16(a + 6, op);
    memcpy(a + 8, sha, 6);
    memcpy(a + 14, spa, 4);
    memcpy(a + 18, tha, 6);
    memcpy(a + 24, tpa, 4);
    return 60;
}

size_t dq_arp_request(uint8_t *out, size_t cap, const uint8_t smac[6], const uint8_t sip[4], const uint8_t tip[4]) {
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, zero[6] = { 0 };
    return arp_frame(out, cap, bcast, smac, 1, smac, sip, zero, tip);
}

static bool arp_parse(const uint8_t *f, size_t n, unsigned op, const uint8_t **sha, const uint8_t **spa, const uint8_t **tpa) {
    if (n < 42 || get16(f + 12) != 0x0806) return false;
    const uint8_t *a = f + 14;
    if (get16(a) != 1 || get16(a + 2) != 0x0800 || a[4] != 6 || a[5] != 4 || get16(a + 6) != op) return false;
    *sha = a + 8;
    *spa = a + 14;
    *tpa = a + 24;
    return true;
}

bool dq_arp_reply_parse(const uint8_t *f, size_t n, const uint8_t tip[4], uint8_t mac[6]) {
    const uint8_t *sha, *spa, *tpa;
    if (!arp_parse(f, n, 2, &sha, &spa, &tpa) || memcmp(spa, tip, 4) != 0) return false;
    memcpy(mac, sha, 6);
    return true;
}

/* ---------------------------------------------------------------- neighbor discovery */
size_t dq_nd_solicit(uint8_t *out, size_t cap, const uint8_t smac[6], const uint8_t sip[16], const uint8_t tip[16]) {
    if (cap < 14 + 40 + 32) return 0;
    uint8_t dst[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, tip[13], tip[14], tip[15] };   /* the solicited-node address (RFC 4291 2.7.1) */
    memset(out, 0, 14 + 40 + 32);
    out[0] = 0x33; out[1] = 0x33; out[2] = 0xff; out[3] = tip[13]; out[4] = tip[14]; out[5] = tip[15];
    memcpy(out + 6, smac, 6);
    put16(out + 12, 0x86DD);
    uint8_t *ip = out + 14;
    ip[0] = 0x60;
    put16(ip + 4, 32);
    ip[6] = 58;
    ip[7] = 255;
    memcpy(ip + 8, sip, 16);
    memcpy(ip + 24, dst, 16);
    uint8_t *ic = ip + 40;
    ic[0] = 135;
    memcpy(ic + 8, tip, 16);
    ic[24] = 1;   /* the source link-layer address option */
    ic[25] = 1;
    memcpy(ic + 26, smac, 6);
    uint32_t s = dq_csum_add(dq_csum_add(0, sip, 16), dst, 16) + 32 + 58;
    put16(ic + 2, (unsigned)(uint16_t)~dq_csum_fold(dq_csum_add(s, ic, 32)));
    return 14 + 40 + 32;
}

bool dq_nd_adv_parse(const uint8_t *f, size_t n, const uint8_t tip[16], uint8_t mac[6]) {
    if (n < 14 + 40 + 24 || get16(f + 12) != 0x86DD) return false;
    const uint8_t *ip = f + 14;
    size_t pl = get16(ip + 4);
    if ((ip[0] >> 4) != 6 || ip[6] != 58 || ip[7] != 255 || pl < 24 || 14 + 40 + pl > n) return false;
    const uint8_t *ic = ip + 40;
    if (ic[0] != 136 || ic[1] != 0 || memcmp(ic + 8, tip, 16) != 0) return false;
    memcpy(mac, f + 6, 6);   /* without the option: the sender of the frame */
    size_t o = 24;
    while (o + 2 <= pl) {
        size_t ol = (size_t)ic[o + 1] * 8;
        if (ol == 0 || o + ol > pl) break;
        if (ic[o] == 2 && ol == 8) { memcpy(mac, ic + o + 2, 6); break; }
        o += ol;
    }
    return true;
}

/* ---------------------------------------------------------------- the reflector of the raw test path */
size_t dq_frame_reflect(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, const uint8_t our_mac[6], uint16_t port, uint8_t *out, size_t cap) {
    const uint8_t *sha, *spa, *tpa;
    if (!v6 && arp_parse(f, n, 1, &sha, &spa, &tpa)) {
        if (memcmp(tpa, our_ip, 4) != 0) return 0;
        return arp_frame(out, cap, sha, our_mac, 2, our_mac, our_ip, sha, spa);
    }
    dq_udp_view_t v;
    if (dq_frame_parse_udp(f, n, v6, our_ip, &v) < 0 || v.dport != port || v.plen < 12 || v.plen > DQ_RXMAX || !frame_csums_ok(f, v6, &v)) return 0;
    uint8_t tmp[DQ_RXMAX];
    memcpy(tmp, v.payload, v.plen);
    tmp[2] |= 0x80;   /* QR */
    dq_frame_tpl_t t;
    dq_frame_tpl_init(&t, our_mac, v.smac, v6, our_ip, v.sip, port, v.sport);
    return dq_frame_build(&t, out, cap, tmp, v.plen);
}

/* ---------------------------------------------------------------- the next-hop MAC through the raw path itself */
int dq_raw_resolve_mac(const dq_rawif_t *r, dq_target_t *tg, char *err, size_t errlen) {
    if (tg->have_dst_mac) return 0;
    uint8_t fr[128];
    for (int attempt = 0; attempt < 5; attempt++) {
        size_t fl = tg->v6 ? dq_nd_solicit(fr, sizeof fr, tg->src_mac, tg->arp_ip, tg->hop_ip) : dq_arp_request(fr, sizeof fr, tg->src_mac, tg->arp_ip, tg->hop_ip);
        if (fl == 0 || r->tx(r->ctx, fr, (unsigned)fl) < 0) { snprintf(err, errlen, "cannot send the ARP / neighbor request"); return -1; }
        uint64_t deadline = dq_now_ns() + 400000000ull;
        while (dq_now_ns() < deadline) {
            const uint8_t *f;
            unsigned l;
            int g = r->rx(r->ctx, &f, &l, 50);
            if (g < 0) { snprintf(err, errlen, "cannot receive while resolving the next hop"); return -1; }
            if (g == 0) continue;
            if (tg->v6 ? dq_nd_adv_parse(f, l, tg->hop_ip, tg->dst_mac) : dq_arp_reply_parse(f, l, tg->hop_ip, tg->dst_mac)) {
                tg->have_dst_mac = true;
                return 0;
            }
        }
    }
    snprintf(err, errlen, "no ARP / neighbor answer from the next hop within 2 s: give --next-hop-mac (or --next-hop for a gateway)");
    return -1;
}

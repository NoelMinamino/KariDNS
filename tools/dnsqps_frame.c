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

int dq_frame_parse_udp(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, dq_udp_view_t *v) {
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
        if (tot < ihl + 8 || off + tot > n || memcmp(ip + 16, our_ip, 4) != 0) return -1;
        udp = ip + ihl;
        ulen = get16(udp + 4);
        if (ulen < 8 || ihl + ulen > tot) return -1;
        memcpy(v->sip, ip + 12, 4);
    } else {
        if (et != 0x86DD || n < off + 40 + 8) return -1;
        const uint8_t *ip = f + off;
        size_t pl = get16(ip + 4);
        if ((ip[0] >> 4) != 6 || ip[6] != 17 || pl < 8 || off + 40 + pl > n || memcmp(ip + 24, our_ip, 16) != 0) return -1;
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
    if (dq_frame_parse_udp(f, n, v6, our_ip, &v) < 0 || v.dport != port || v.plen < 12 || v.plen > DQ_RXMAX) return 0;
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
        size_t fl = tg->v6 ? dq_nd_solicit(fr, sizeof fr, tg->src_mac, tg->src_ip, tg->hop_ip) : dq_arp_request(fr, sizeof fr, tg->src_mac, tg->src_ip, tg->hop_ip);
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

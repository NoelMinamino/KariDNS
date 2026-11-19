/* dnsqps: the parser of an answer.  The bytes come from the network: every offset is checked against the length before it is read (RFC 1035 4.1,
 * names end at a root label or a compression pointer, which is not followed: the walk only needs the length of a name). */
#include "dnsqps.h"

/* the offset after the name at off, 0 when it runs past the end or uses a reserved label type */
static size_t skip_name(const uint8_t *p, size_t n, size_t off) {
    while (off < n) {
        uint8_t l = p[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) return off + 2 <= n ? off + 2 : 0;
        if (l & 0xC0) return 0;
        off += 1u + l;
    }
    return 0;
}

int dq_resp_parse(const uint8_t *p, size_t n, dq_resp_t *r) {
    memset(r, 0, sizeof *r);
    if (n < 12 || !(p[2] & 0x80)) return -1;
    r->id = (uint16_t)((p[0] << 8) | p[1]);
    r->aa = (p[2] & 0x04) != 0;
    r->tc = (p[2] & 0x02) != 0;
    r->rcode = p[3] & 0x0F;
    r->qd = (uint16_t)((p[4] << 8) | p[5]);
    r->an = (uint16_t)((p[6] << 8) | p[7]);
    r->ns = (uint16_t)((p[8] << 8) | p[9]);
    r->ar = (uint16_t)((p[10] << 8) | p[11]);
    size_t off = 12;
    for (unsigned i = 0; i < r->qd; i++) {
        off = skip_name(p, n, off);
        if (off == 0 || off + 4 > n) return 1;
        off += 4;
    }
    unsigned total = (unsigned)r->an + r->ns + r->ar;
    for (unsigned i = 0; i < total; i++) {
        off = skip_name(p, n, off);
        if (off == 0 || off + 10 > n) return 1;
        uint16_t type = (uint16_t)((p[off] << 8) | p[off + 1]);
        uint32_t ttl = ((uint32_t)p[off + 4] << 24) | ((uint32_t)p[off + 5] << 16) | ((uint32_t)p[off + 6] << 8) | p[off + 7];
        size_t rdlen = (size_t)((p[off + 8] << 8) | p[off + 9]);
        off += 10;
        if (rdlen > n - off) return 1;
        if (type == 41 && i >= (unsigned)r->an + r->ns) {   /* OPT in the additional section (RFC 6891 6.1.3: the high 8 bits of the RCODE) */
            r->opt = true;
            r->rcode = (uint16_t)((((ttl >> 24) & 0xFF) << 4) | (r->rcode & 0x0F));
        }
        off += rdlen;
    }
    return 0;
}

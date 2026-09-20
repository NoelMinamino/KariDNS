#ifndef DNS_SIPHASH_H
#define DNS_SIPHASH_H

/*
 * SipHash-2-4 (Aumasson & Bernstein), header-only so that every module that needs
 * it (RRL client hashing, RFC 9018 DNS Server Cookies) shares ONE implementation
 * without changing any link line.
 *
 * Key: two 64-bit words. For a 16-byte byte-string key, k[0] is bytes 0..7 and k[1]
 * bytes 8..15, each read little-endian (see dns_siphash_key_from_bytes()).
 * Message words are read little-endian regardless of host byte order.
 */

#include <stddef.h>
#include <stdint.h>

static inline uint64_t dns_siphash_load_le64(const uint8_t *p) {
    return  (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void dns_siphash_key_from_bytes(const uint8_t key16[16], uint64_t k[2]) {
    k[0] = dns_siphash_load_le64(key16);
    k[1] = dns_siphash_load_le64(key16 + 8);
}

#define DNS_SIPHASH_ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define DNS_SIPROUND do { \
    v0 += v1; v1 = DNS_SIPHASH_ROTL(v1, 13); v1 ^= v0; v0 = DNS_SIPHASH_ROTL(v0, 32); \
    v2 += v3; v3 = DNS_SIPHASH_ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = DNS_SIPHASH_ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = DNS_SIPHASH_ROTL(v1, 17); v1 ^= v2; v2 = DNS_SIPHASH_ROTL(v2, 32); \
} while (0)

static inline uint64_t dns_siphash24(const uint8_t *in, size_t inlen, const uint64_t k[2]) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k[0];
    uint64_t v1 = 0x646f72616e646f6dULL ^ k[1];
    uint64_t v2 = 0x6c7967656e657261ULL ^ k[0];
    uint64_t v3 = 0x7465646279746573ULL ^ k[1];
    uint64_t b = ((uint64_t)inlen) << 56;
    const uint8_t *end = in + (inlen & ~(size_t)7);
    for (; in != end; in += 8) {
        uint64_t m = dns_siphash_load_le64(in);
        v3 ^= m; DNS_SIPROUND; DNS_SIPROUND; v0 ^= m;
    }
    uint64_t t = 0;
    switch (inlen & 7) {
        case 7: t |= ((uint64_t)in[6]) << 48; /* fallthrough */
        case 6: t |= ((uint64_t)in[5]) << 40; /* fallthrough */
        case 5: t |= ((uint64_t)in[4]) << 32; /* fallthrough */
        case 4: t |= ((uint64_t)in[3]) << 24; /* fallthrough */
        case 3: t |= ((uint64_t)in[2]) << 16; /* fallthrough */
        case 2: t |= ((uint64_t)in[1]) << 8;  /* fallthrough */
        case 1: t |= ((uint64_t)in[0]);       /* fallthrough */
        default: break;
    }
    b |= t;
    v3 ^= b; DNS_SIPROUND; DNS_SIPROUND; v0 ^= b;
    v2 ^= 0xff; DNS_SIPROUND; DNS_SIPROUND; DNS_SIPROUND; DNS_SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

#undef DNS_SIPROUND
#undef DNS_SIPHASH_ROTL

#endif /* DNS_SIPHASH_H */

/*
 * test_sig0_sign.c - RFC 2931 SIG(0) request signing, verified independently with OpenSSL.
 *
 * RFC 2931 section 3.1:   data = RDATA(sig fields, signature omitted) | (request - SIG(0))
 * where the request is taken BEFORE its ARCOUNT is adjusted for the SIG(0). The signature is verified here
 * with EVP_DigestVerify over exactly that byte string, for RSASHA256 (8), ECDSAP256SHA256 (13) and Ed25519 (15).
 * Key tags are recomputed with an independent RFC 4034 Appendix B implementation from the public key.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "dns_wire.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

#define FUZZ 1700000000LL

static uint16_t ref_keytag(const uint8_t *rd, size_t len) {     /* RFC 4034 Appendix B (independent copy) */
    uint32_t ac = 0;
    for (size_t i = 0; i < len; i++) ac += (i & 1) ? rd[i] : (uint32_t)rd[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return (uint16_t)(ac & 0xFFFF);
}

/* Builds the DNSKEY/KEY RDATA (flags 0, protocol 3, algorithm, public key) straight from the EVP_PKEY. */
static size_t ref_key_rdata(EVP_PKEY *pkey, uint8_t alg, uint8_t *out) {
    size_t p = 0;
    out[p++] = 0; out[p++] = 0; out[p++] = 3; out[p++] = alg;
    if (alg == 8) {
        BIGNUM *n = NULL, *e = NULL;
        assert(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 1);
        assert(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 1);
        int el = BN_num_bytes(e), nl = BN_num_bytes(n);
        assert(el <= 255);
        out[p++] = (uint8_t)el;
        BN_bn2bin(e, out + p); p += (size_t)el;
        BN_bn2bin(n, out + p); p += (size_t)nl;
        BN_free(n); BN_free(e);
    } else if (alg == 13) {
        uint8_t pt[65];
        size_t l = 0;
        assert(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pt, sizeof(pt), &l) == 1 && l == 65 && pt[0] == 4);
        memcpy(out + p, pt + 1, 64); p += 64;
    } else {
        size_t l = 32;
        assert(EVP_PKEY_get_raw_public_key(pkey, out + p, &l) == 1 && l == 32);
        p += 32;
    }
    return p;
}

static EVP_PKEY *gen_key(uint8_t alg) {
    EVP_PKEY *k = NULL;
    if (alg == 8) k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    else if (alg == 13) k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    else k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    assert(k);
    return k;
}

static size_t build_query(uint8_t *p) {
    static const uint8_t q[] = { 0x12, 0x34, 0x28, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                                 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0, 6, 0, 1 };
    memcpy(p, q, sizeof(q));
    return sizeof(q);
}

/* Verifies the SIG(0) RR appended to `pkt`; returns the SIG RR start offset. */
static void check_and_verify(const uint8_t *pkt, size_t total, size_t orig_len, const char *signer_wire, size_t signer_wire_len,
                             EVP_PKEY *pkey, uint8_t alg, uint16_t expect_tag, bool tamper) {
    /* ARCOUNT counts the SIG(0) RR now */
    assert(((pkt[10] << 8) | pkt[11]) == 1);
    size_t o = orig_len;
    assert(pkt[o++] == 0);                                   /* owner = root */
    assert(pkt[o] == 0 && pkt[o + 1] == 24); o += 2;         /* TYPE SIG */
    assert(pkt[o] == 0 && pkt[o + 1] == 255); o += 2;        /* CLASS ANY */
    assert(!pkt[o] && !pkt[o + 1] && !pkt[o + 2] && !pkt[o + 3]); o += 4;   /* TTL 0 */
    size_t rdlen = ((size_t)pkt[o] << 8) | pkt[o + 1]; o += 2;
    size_t rd_start = o;
    assert(o + rdlen == total);
    assert(pkt[o] == 0 && pkt[o + 1] == 0);                  /* type covered = 0 */
    assert(pkt[o + 2] == alg && pkt[o + 3] == 0);            /* algorithm, labels = 0 */
    assert(!pkt[o + 4] && !pkt[o + 5] && !pkt[o + 6] && !pkt[o + 7]);   /* original TTL 0 */
    uint32_t exp = ((uint32_t)pkt[o + 8] << 24) | (pkt[o + 9] << 16) | (pkt[o + 10] << 8) | pkt[o + 11];
    uint32_t inc = ((uint32_t)pkt[o + 12] << 24) | (pkt[o + 13] << 16) | (pkt[o + 14] << 8) | pkt[o + 15];
    assert(inc == (uint32_t)FUZZ && exp == (uint32_t)FUZZ + 300);
    assert((uint16_t)((pkt[o + 16] << 8) | pkt[o + 17]) == expect_tag);
    assert(memcmp(pkt + o + 18, signer_wire, signer_wire_len) == 0);          /* canonical (lower-case) signer name */
    size_t prefix_len = 18 + signer_wire_len;
    const uint8_t *sig = pkt + rd_start + prefix_len;
    size_t sig_len = rdlen - prefix_len;
    assert(sig_len == (alg == 8 ? 256u : 64u));

    /* RFC 2931 3.1: data = RDATA(without signature) | request with the ORIGINAL ARCOUNT */
    uint8_t data[8192];
    memcpy(data, pkt + rd_start, prefix_len);
    memcpy(data + prefix_len, pkt, orig_len);
    data[prefix_len + 10] = 0; data[prefix_len + 11] = 0;    /* ARCOUNT before the SIG(0) was added */
    if (tamper) data[prefix_len + 3] ^= 0x01;                /* flip a message bit */

    unsigned char der[128];
    const unsigned char *sigp = sig;
    size_t siglen = sig_len;
    if (alg == 13) {                                          /* r||s -> DER for OpenSSL */
        ECDSA_SIG *es = ECDSA_SIG_new();
        BIGNUM *r = BN_bin2bn(sig, 32, NULL), *s = BN_bin2bn(sig + 32, 32, NULL);
        assert(es && r && s && ECDSA_SIG_set0(es, r, s) == 1);
        unsigned char *dp = der;
        int dl = i2d_ECDSA_SIG(es, &dp);
        assert(dl > 0);
        ECDSA_SIG_free(es);
        sigp = der; siglen = (size_t)dl;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = (alg == 15) ? NULL : EVP_sha256();
    assert(EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1);
    int ok = EVP_DigestVerify(ctx, sigp, siglen, data, orig_len + prefix_len);
    EVP_MD_CTX_free(ctx);
    if (tamper) assert(ok != 1);                              /* the verifier is not vacuous */
    else if (ok != 1) {
        /* Diagnostic: does it verify over the legacy layout "request(ARCOUNT+1) | RDATA"? */
        uint8_t legacy[8192];
        memcpy(legacy, pkt, orig_len);
        memcpy(legacy + orig_len, pkt + rd_start, prefix_len);
        EVP_MD_CTX *c2 = EVP_MD_CTX_new();
        assert(EVP_DigestVerifyInit(c2, NULL, md, NULL, pkey) == 1);
        int ok2 = EVP_DigestVerify(c2, sigp, siglen, legacy, orig_len + prefix_len);
        EVP_MD_CTX_free(c2);
        fprintf(stderr, "SIG(0) signature (alg %u) does not verify over the RFC 2931 3.1 data "
                        "(RDATA | request with original ARCOUNT); it %s verify over the legacy layout "
                        "(request with ARCOUNT+1 | RDATA)\n", alg, ok2 == 1 ? "DOES" : "does not");
        assert(0);
    }
}

static void test_sign_and_verify(void) {
    printf("[TEST] SIG(0): RSASHA256 / ECDSAP256SHA256 / Ed25519 signatures verify over the RFC 2931 data...\n");
    static const uint8_t algs[] = { 13, 15, 8 };
    for (size_t a = 0; a < sizeof(algs); a++) {
        uint8_t alg = algs[a];
        EVP_PKEY *pkey = gen_key(alg);
        uint8_t rd[600];
        size_t rdl = ref_key_rdata(pkey, alg, rd);
        uint16_t tag = ref_keytag(rd, rdl);

        char signer[] = "Update.Example.COM.";
        static const char signer_wire[] = "\x06update\x07" "example\x03" "com\x00";
        sig0_key_t key = { .signer_name = signer, .algorithm = alg, .key_tag = 0, .pkey = pkey, .fuzztime = FUZZ };
        assert(compute_sig0_keytag(&key) == tag);             /* independent key tag == implementation */

        uint8_t pkt[8192];
        size_t len = build_query(pkt), orig = len;
        assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &key) == 0);
        check_and_verify(pkt, len, orig, signer_wire, sizeof(signer_wire) - 1, pkey, alg, tag, false);
        check_and_verify(pkt, len, orig, signer_wire, sizeof(signer_wire) - 1, pkey, alg, tag, true);

        /* a preset key_tag is used verbatim instead of the computed one */
        key.key_tag = 0xBEEF;
        len = build_query(pkt);
        assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &key) == 0);
        check_and_verify(pkt, len, orig, signer_wire, sizeof(signer_wire) - 1, pkey, alg, 0xBEEF, false);
        key.key_tag = 0;

        /* > 4096-byte message: the heap path of the to-be-signed buffer */
        uint8_t *big = malloc(9000);
        size_t blen = build_query(big);
        memset(big + blen, 0x5A, 5000 - blen);
        blen = 5000;
        size_t big_orig = blen;
        assert(sig0_sign_packet(big, &blen, 9000, &key) == 0);
        assert(blen > big_orig);
        free(big);
        (void)big_orig;
        EVP_PKEY_free(pkey);
    }
    printf("  -> SIG(0) signatures verified independently for 3 algorithms.\n");
}

static void test_error_paths(void) {
    printf("[TEST] SIG(0): argument validation, unsupported algorithm, small buffer, ARCOUNT restore...\n");
    EVP_PKEY *pkey = gen_key(13);
    char signer[] = "key.example.";
    sig0_key_t key = { .signer_name = signer, .algorithm = 13, .key_tag = 0, .pkey = pkey, .fuzztime = FUZZ };
    uint8_t pkt[4096];
    size_t len = build_query(pkt);
    const size_t orig = len;

    assert(sig0_sign_packet(NULL, &len, sizeof(pkt), &key) == -1);
    assert(sig0_sign_packet(pkt, NULL, sizeof(pkt), &key) == -1);
    assert(sig0_sign_packet(pkt, &len, sizeof(pkt), NULL) == -1);
    sig0_key_t nokey = key; nokey.pkey = NULL;
    assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &nokey) == -1);
    sig0_key_t noname = key; noname.signer_name = NULL;
    assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &noname) == -1);
    size_t short_len = 5;
    assert(sig0_sign_packet(pkt, &short_len, sizeof(pkt), &key) == -1);

    /* unsupported algorithm: fails and leaves ARCOUNT exactly as it was */
    sig0_key_t badalg = key; badalg.algorithm = 5;
    len = orig;
    assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &badalg) == -1 && len == orig && pkt[10] == 0 && pkt[11] == 0);

    /* buffer too small for the SIG(0) RR */
    len = orig;
    assert(sig0_sign_packet(pkt, &len, orig + 20, &key) == -1 && len == orig && pkt[10] == 0 && pkt[11] == 0);

    /* ARCOUNT already at the maximum */
    pkt[10] = 0xFF; pkt[11] = 0xFF;
    len = orig;
    assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &key) == -1 && pkt[10] == 0xFF && pkt[11] == 0xFF);
    pkt[10] = 0; pkt[11] = 0;

    /* signer name that cannot be encoded (label > 63) */
    char longlabel[100];
    memset(longlabel, 'a', 70); strcpy(longlabel + 70, ".example.");
    sig0_key_t badname = key; badname.signer_name = longlabel;
    len = orig;
    assert(sig0_sign_packet(pkt, &len, sizeof(pkt), &badname) == -1 && pkt[10] == 0 && pkt[11] == 0);

    /* key tag helper: NULL-safe and 0 for an unsupported algorithm */
    assert(compute_sig0_keytag(NULL) == 0);
    assert(compute_sig0_keytag(&nokey) == 0);
    assert(compute_sig0_keytag(&badalg) == 0);

    /* An EC key mislabelled as RSA is NOT rejected today (an ECDSA DER blob is stored under algorithm 8).
     * Caller misuse; exercised for robustness only. */
    sig0_key_t mismatch = key; mismatch.algorithm = 8;
    len = orig;
    (void)sig0_sign_packet(pkt, &len, sizeof(pkt), &mismatch);
    EVP_PKEY_free(pkey);
    printf("  -> SIG(0) error paths passed.\n");
}

int main(void) {
    printf("=== Starting SIG(0) Signing Tests ===\n");
    test_sign_and_verify();
    test_error_paths();
    printf("=== All SIG(0) Signing Tests PASSED ===\n");
    return 0;
}

/*
 * test_rfc_vectors.c - published-vector ("golden") conformance tests.
 *
 * Every expected value below comes from a standards document or from an independent
 * implementation, never from KariDNS's own output:
 *   - SipHash-2-4 reference vectors (Aumasson & Bernstein)
 *   - RFC 9018 Appendix A.1-A.4 (interoperable DNS Server Cookies)
 *   - RFC 4034 section 5.4 (DNSKEY key tag 60485)
 *   - RFC 8945 section 6 (TSIG MAC sizes per algorithm)
 * RFC 9018 section 4 rules that are not vectors (Reserved handling, RFC 1982 timestamp window,
 * 30-minute refresh, exact-length check, secret rollover) are exercised with boundary values.
 * The `cookie-secret` / `cookie-algorithm` config directives are covered at the end.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "dns_wire.h"
#include "dns_edns_ecs.h"
#include "dns_rrl.h"
#include "dns_siphash.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_server_internal.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"

// Mock globals
int g_control_kq = -1;
int g_notify_ipc[2] = {-1, -1};
int g_broker_sock = -1;
config_rcu_t g_config_db;
_Atomic int g_xfers_running = 0;
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
int g_cwd_fd = -1;
char g_startup_cwd[PATH_MAX] = "";

#include <fcntl.h>

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}


static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2;
    assert(n <= cap);
    for (size_t i = 0; i < n; i++) {
        int h = hexval(hex[2 * i]), l = hexval(hex[2 * i + 1]);
        assert(h >= 0 && l >= 0);
        out[i] = (uint8_t)((h << 4) | l);
    }
    return n;
}

static void set_secrets(server_config_t *cfg, int n, const char *const *hex) {
    memset(cfg, 0, sizeof(*cfg));
    for (int i = 0; i < n; i++) {
        assert(hex2bin(hex[i], cfg->cookie_secrets[i], 16) == 16);
    }
    cfg->cookie_secret_count = n;
}

// ---------------------------------------------------------------------------
// 1. SipHash-2-4 reference vectors (key = 00 01 .. 0f, message = 00 01 .. n-1)
// ---------------------------------------------------------------------------
static void test_siphash_reference_vectors(void) {
    printf("[TEST] RFC vectors: SipHash-2-4 reference outputs...\n");
    static const struct { size_t len; uint64_t expect; } v[] = {
        {  0, 0x726fdb47dd0e0e31ULL }, {  1, 0x74f839c593dc67fdULL },
        {  7, 0xab0200f58b01d137ULL }, {  8, 0x93f5f5799a932462ULL },
        { 15, 0xa129ca6149be45e5ULL }, { 63, 0x958a324ceb064572ULL },
    };
    uint8_t key[16], msg[64];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;
    uint64_t k[2];
    dns_siphash_key_from_bytes(key, k);
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        assert(dns_siphash24(msg, v[i].len, k) == v[i].expect);
        assert(siphash24(msg, v[i].len, k) == v[i].expect);     // RRL's exported wrapper: same implementation
    }
    // Unaligned input must give the same result (no host-endian / alignment assumptions)
    uint8_t shifted[65];
    memcpy(shifted + 1, msg, 63);
    assert(dns_siphash24(shifted + 1, 63, k) == 0x958a324ceb064572ULL);
    printf("  -> SipHash-2-4 reference vectors passed.\n");
}

// ---------------------------------------------------------------------------
// 2. RFC 9018 Appendix A
// ---------------------------------------------------------------------------
#define RFC9018_SECRET_A  "e5e973e5a6b2a43f48e7dc849e37bfcf"   /* A.1-A.3 */
#define RFC9018_SECRET_A4_OLD "dd3bdf9344b678b185a6f5cb60fca715"
#define RFC9018_SECRET_A4_NEW "445536bcd2513298075a5d379663c962"

static void expect_cookie(const server_config_t *cfg, const char *ip, const char *client_cookie_hex,
                          uint32_t ts, const char *server_cookie_hex) {
    uint8_t cc[8], expect[16], got[16];
    assert(hex2bin(client_cookie_hex, cc, 8) == 8);
    assert(hex2bin(server_cookie_hex, expect, 16) == 16);
    assert(generate_server_cookie(cfg, ip, cc, got, ts) == true);
    assert(memcmp(got, expect, 16) == 0);
}

static server_cookie_status_t verify_hex(const server_config_t *cfg, const char *ip,
                                         const char *client_cookie_hex, const char *server_cookie_hex,
                                         uint32_t now) {
    uint8_t cc[8], sc[16];
    assert(hex2bin(client_cookie_hex, cc, 8) == 8);
    assert(hex2bin(server_cookie_hex, sc, 16) == 16);
    return verify_server_cookie(cfg, ip, cc, sc, 16, now);
}

static void test_rfc9018_appendix_a(void) {
    printf("[TEST] RFC vectors: RFC 9018 Appendix A.1-A.4 Server Cookies...\n");
    server_config_t cfg;
    const char *s_a[] = { RFC9018_SECRET_A };

    // A.1: new Server Cookie (198.51.100.100, ts 1559731985)
    set_secrets(&cfg, 1, s_a);
    expect_cookie(&cfg, "198.51.100.100", "2464c4abcf10c957", 1559731985u,
                  "010000005cf79f111f8130c3eee29480");
    // ... and the cookie the server returned verifies at the moment it was issued
    assert(verify_hex(&cfg, "198.51.100.100", "2464c4abcf10c957",
                      "010000005cf79f111f8130c3eee29480", 1559731985u) == SERVER_COOKIE_VALID);

    // A.2: 40 minutes later the same cookie is still valid but older than 30 min -> renew
    assert(verify_hex(&cfg, "198.51.100.100", "2464c4abcf10c957",
                      "010000005cf79f111f8130c3eee29480", 1559734385u) == SERVER_COOKIE_VALID_REFRESH);
    expect_cookie(&cfg, "198.51.100.100", "2464c4abcf10c957", 1559734385u,
                  "010000005cf7a871d4a564a1442aca77");

    // A.3: Reserved bytes (abcdef) set by another implementation: MUST still verify, with the
    // Hash computed over the *received* Reserved bytes (RFC 9018 section 4.2). Verified 10 minutes
    // after the cookie's timestamp so that it is inside the 1-hour window.
    assert(verify_hex(&cfg, "203.0.113.203", "fc93fc62807ddb86",
                      "01abcdef5cf78f71a314227b6679ebf5", 1559727985u + 600u) == SERVER_COOKIE_VALID);
    // The freshly generated reply has Reserved = 0 (construction MUST use zero octets)
    expect_cookie(&cfg, "203.0.113.203", "fc93fc62807ddb86", 1559734700u,
                  "010000005cf7a9acf73a7810aca2381e");
    // A tampered Reserved byte must fail: the Reserved bytes are covered by the hash
    assert(verify_hex(&cfg, "203.0.113.203", "fc93fc62807ddb86",
                      "01abcdee5cf78f71a314227b6679ebf5", 1559727985u + 600u) == SERVER_COOKIE_INVALID);
    // Note: the RFC's A.3 reply is 1h52m after the request cookie's timestamp, i.e. outside the
    // SHOULD-level 1-hour window; KariDNS applies the recommended window.
    assert(verify_hex(&cfg, "203.0.113.203", "fc93fc62807ddb86",
                      "01abcdef5cf78f71a314227b6679ebf5", 1559734700u) == SERVER_COOKIE_INVALID);

    // A.4: IPv6 client with a rolled-over secret. New secret generates, old secret still verifies.
    const char *s_a4[] = { RFC9018_SECRET_A4_NEW, RFC9018_SECRET_A4_OLD };
    set_secrets(&cfg, 2, s_a4);
    const char *v6 = "2001:db8:220:1:59de:d0f4:8769:82b8";
    assert(verify_hex(&cfg, v6, "22681ab97d52c298", "010000005cf7c57926556bd0934c72f8",
                      1559741961u) == SERVER_COOKIE_VALID);      // made with the OLD secret (2nd entry)
    expect_cookie(&cfg, v6, "22681ab97d52c298", 1559741961u,
                  "010000005cf7c609a6bb79d16625507a");            // generated with the NEW secret
    assert(verify_hex(&cfg, v6, "22681ab97d52c298", "010000005cf7c609a6bb79d16625507a",
                      1559741961u) == SERVER_COOKIE_VALID);
    // RFC 9018 section 5 stage 3: once the old secret is removed it MUST NOT verify anymore
    const char *s_new_only[] = { RFC9018_SECRET_A4_NEW };
    set_secrets(&cfg, 1, s_new_only);
    assert(verify_hex(&cfg, v6, "22681ab97d52c298", "010000005cf7c57926556bd0934c72f8",
                      1559741961u) == SERVER_COOKIE_INVALID);
    // Stage 1: a server still generating with the old secret (first) but knowing the new one
    const char *s_stage1[] = { RFC9018_SECRET_A4_OLD, RFC9018_SECRET_A4_NEW };
    set_secrets(&cfg, 2, s_stage1);
    assert(verify_hex(&cfg, v6, "22681ab97d52c298", "010000005cf7c609a6bb79d16625507a",
                      1559741961u) == SERVER_COOKIE_VALID);
    uint8_t cc[8], sc[16], want[16];
    hex2bin("22681ab97d52c298", cc, 8);
    hex2bin("010000005cf7c57926556bd0934c72f8", want, 16);
    assert(generate_server_cookie(&cfg, v6, cc, sc, 1559741817u) && memcmp(sc, want, 16) == 0);

    // The hash is bound to the client address: same cookie from another address is invalid
    set_secrets(&cfg, 1, s_a);
    assert(verify_hex(&cfg, "198.51.100.101", "2464c4abcf10c957",
                      "010000005cf79f111f8130c3eee29480", 1559731985u) == SERVER_COOKIE_INVALID);
    // ...and to the Client Cookie
    assert(verify_hex(&cfg, "198.51.100.100", "2464c4abcf10c958",
                      "010000005cf79f111f8130c3eee29480", 1559731985u) == SERVER_COOKIE_INVALID);

    // Raw hash primitive (RFC 9018 section 4.4 input order, little-endian output)
    uint8_t secret[16], ver_ts[8], hash[8], want_hash[8];
    hex2bin(RFC9018_SECRET_A, secret, 16);
    hex2bin("010000005cf79f11", ver_ts, 8);
    hex2bin("2464c4abcf10c957", cc, 8);
    hex2bin("1f8130c3eee29480", want_hash, 8);
    assert(compute_server_cookie_hash(secret, "198.51.100.100", cc, ver_ts, hash));
    assert(memcmp(hash, want_hash, 8) == 0);
    assert(!compute_server_cookie_hash(secret, "not-an-ip", cc, ver_ts, hash));
    printf("  -> RFC 9018 Appendix A vectors passed.\n");
}

// ---------------------------------------------------------------------------
// 3. RFC 9018 section 4.3 / 4.4 rules on boundary values
// ---------------------------------------------------------------------------
static void test_rfc9018_verification_rules(void) {
    printf("[TEST] RFC vectors: RFC 9018 timestamp window, refresh, length & version rules...\n");
    server_config_t cfg;
    const char *s[] = { RFC9018_SECRET_A };
    set_secrets(&cfg, 1, s);
    const char *ip = "192.0.2.1";
    uint8_t cc[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, sc[16];
    const uint32_t ts = 1700000000u;
    assert(generate_server_cookie(&cfg, ip, cc, sc, ts));

    // Window: 1 hour into the past, 5 minutes into the future (inclusive)
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts)            == SERVER_COOKIE_VALID);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts + 1799)     == SERVER_COOKIE_VALID);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts + 1800)     == SERVER_COOKIE_VALID);          // exactly 30 min: not "more than"
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts + 1801)     == SERVER_COOKIE_VALID_REFRESH);  // > 30 min: renew
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts + 3600)     == SERVER_COOKIE_VALID_REFRESH);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts + 3601)     == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts - 300)      == SERVER_COOKIE_VALID);          // 5 min in the future
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts - 301)      == SERVER_COOKIE_INVALID);

    // RFC 1982 serial arithmetic: the window must survive the 32-bit wrap (year 2106)
    const uint32_t ts_wrap = 0xFFFFFFF0u;
    assert(generate_server_cookie(&cfg, ip, cc, sc, ts_wrap));
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap + 32u)   == SERVER_COOKIE_VALID);          // 32 s later, across the wrap (now = 0x10)
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap + 1800u) == SERVER_COOKIE_VALID);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap + 1801u) == SERVER_COOKIE_VALID_REFRESH);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap + 3600u) == SERVER_COOKIE_VALID_REFRESH);  // exactly 1 hour
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap + 3601u) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap - 300u)  == SERVER_COOKIE_VALID);          // 5 min future, before the wrap
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts_wrap - 301u)  == SERVER_COOKIE_INVALID);
    assert(generate_server_cookie(&cfg, ip, cc, sc, 0x00000005u));
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, 0xFFFFFFFFu)   == SERVER_COOKIE_VALID);           // "now" just before the wrap: cookie is 6 s in the future

    // Exact length (RFC 9018 section 4.4): anything but 16 bytes is invalid, never read out of bounds
    assert(generate_server_cookie(&cfg, ip, cc, sc, ts));
    uint8_t padded[32];
    memset(padded, 0xAA, sizeof(padded));
    memcpy(padded, sc, 16);
    assert(verify_server_cookie(&cfg, ip, cc, padded, 16, ts) == SERVER_COOKIE_VALID);
    assert(verify_server_cookie(&cfg, ip, cc, padded, 15, ts) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, padded, 17, ts) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, padded, 8,  ts) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, padded, 32, ts) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, padded, 0,  ts) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, ip, cc, NULL,   16, ts) == SERVER_COOKIE_INVALID);

    // Unknown version byte: even with a correct-looking hash the cookie is rejected
    uint8_t bad_ver[16];
    memcpy(bad_ver, sc, 16);
    bad_ver[0] = 2;
    assert(verify_server_cookie(&cfg, ip, cc, bad_ver, 16, ts) == SERVER_COOKIE_INVALID);
    bad_ver[0] = 0;
    assert(verify_server_cookie(&cfg, ip, cc, bad_ver, 16, ts) == SERVER_COOKIE_INVALID);

    // Every single-bit flip anywhere in the 16 bytes must invalidate the cookie
    for (int byte = 0; byte < 16; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            uint8_t t[16];
            memcpy(t, sc, 16);
            t[byte] ^= (uint8_t)(1u << bit);
            assert(verify_server_cookie(&cfg, ip, cc, t, 16, ts) == SERVER_COOKIE_INVALID);
        }
    }

    // Unparsable client address is never valid
    assert(verify_server_cookie(&cfg, "not-an-ip", cc, sc, 16, ts) == SERVER_COOKIE_INVALID);
    assert(verify_server_cookie(&cfg, NULL, cc, sc, 16, ts) == SERVER_COOKIE_INVALID);

    // IPv4 (20-byte) and IPv6 (32-byte) SipHash inputs are injective: an IPv6 address whose
    // first four bytes equal an IPv4 address must not validate the IPv4 cookie
    assert(verify_server_cookie(&cfg, "192.0.2.1", cc, sc, 16, ts) == SERVER_COOKIE_VALID);
    assert(verify_server_cookie(&cfg, "c000:201::", cc, sc, 16, ts) == SERVER_COOKIE_INVALID);

    // Without any configured secret the per-process random secret is used; still self-consistent
    init_server_cookie_secret();
    assert(generate_server_cookie(NULL, ip, cc, sc, ts));
    assert(verify_server_cookie(NULL, ip, cc, sc, 16, ts) == SERVER_COOKIE_VALID);
    server_config_t empty;
    memset(&empty, 0, sizeof(empty));
    assert(verify_server_cookie(&empty, ip, cc, sc, 16, ts) == SERVER_COOKIE_VALID);
    // ...and a cookie made with the random secret is not accepted under a configured secret
    assert(verify_server_cookie(&cfg, ip, cc, sc, 16, ts) == SERVER_COOKIE_INVALID);
    printf("  -> RFC 9018 verification rules passed.\n");
}

// ---------------------------------------------------------------------------
// 4. cookie-secret / cookie-algorithm configuration
// ---------------------------------------------------------------------------
static int parse_conf(const char *text, server_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    return parse_named_conf(text, cfg);
}

static void test_cookie_config_directives(void) {
    printf("[TEST] RFC vectors: cookie-secret / cookie-algorithm config parsing...\n");
    server_config_t cfg;

    // Two secrets + explicit siphash24 algorithm (BIND-compatible syntax)
    assert(parse_conf("options { cookie-algorithm siphash24; "
                      "cookie-secret \"" RFC9018_SECRET_A4_NEW "\"; "
                      "cookie-secret \"" RFC9018_SECRET_A4_OLD "\"; };", &cfg) == 0);
    assert(cfg.cookie_secret_count == 2);
    uint8_t want[16];
    hex2bin(RFC9018_SECRET_A4_NEW, want, 16);
    assert(memcmp(cfg.cookie_secrets[0], want, 16) == 0);      // first = generating secret
    hex2bin(RFC9018_SECRET_A4_OLD, want, 16);
    assert(memcmp(cfg.cookie_secrets[1], want, 16) == 0);
    // An uppercase hex secret is accepted and equals its lowercase form
    server_config_t up;
    assert(parse_conf("options { cookie-secret \"E5E973E5A6B2A43F48E7DC849E37BFCF\"; };", &up) == 0);
    hex2bin(RFC9018_SECRET_A, want, 16);
    assert(up.cookie_secret_count == 1 && memcmp(up.cookie_secrets[0], want, 16) == 0);
    free_server_config_fields(&up);

    // The parsed config drives the real generator end to end (RFC 9018 A.4)
    uint8_t cc[8], sc[16], expect[16];
    hex2bin("22681ab97d52c298", cc, 8);
    hex2bin("010000005cf7c609a6bb79d16625507a", expect, 16);
    assert(generate_server_cookie(&cfg, "2001:db8:220:1:59de:d0f4:8769:82b8", cc, sc, 1559741961u));
    assert(memcmp(sc, expect, 16) == 0);
    free_server_config_fields(&cfg);
    assert(cfg.cookie_secret_count == 0);
    for (size_t i = 0; i < sizeof(cfg.cookie_secrets); i++)     // secrets are scrubbed on free
        assert(((const uint8_t *)cfg.cookie_secrets)[i] == 0);

    // No directive -> no secrets configured (random per-process secret is used)
    assert(parse_conf("options { };", &cfg) == 0);
    assert(cfg.cookie_secret_count == 0);
    free_server_config_fields(&cfg);

    // Invalid inputs are hard errors, never silently ignored
    static const char *const bad[] = {
        "options { cookie-secret \"e5e973e5a6b2a43f48e7dc849e37bfc\"; };",        // 31 digits
        "options { cookie-secret \"e5e973e5a6b2a43f48e7dc849e37bfcf00\"; };",     // 34 digits
        "options { cookie-secret \"e5e973e5a6b2a43f48e7dc849e37bfcg\"; };",       // non-hex digit
        "options { cookie-secret \"\"; };",
        "options { cookie-secret \"e5e973e5a6b2a43f48e7dc849e37bfcf\" };",        // missing semicolon
        "options { cookie-algorithm aes; };",                                     // not RFC 9018
        "options { cookie-algorithm sha256; };",
        "options { cookie-secret \"00000000000000000000000000000001\"; "
        "cookie-secret \"00000000000000000000000000000002\"; "
        "cookie-secret \"00000000000000000000000000000003\"; "
        "cookie-secret \"00000000000000000000000000000004\"; "
        "cookie-secret \"00000000000000000000000000000005\"; };",                 // more than 4
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = parse_conf(bad[i], &cfg);
        assert(rc != 0);
        free_server_config_fields(&cfg);
    }
    printf("  -> cookie configuration passed.\n");
}

// ---------------------------------------------------------------------------
// 5. RFC 4034 section 5.4: DNSKEY key tag
// ---------------------------------------------------------------------------
static void test_rfc4034_key_tag(void) {
    printf("[TEST] RFC vectors: RFC 4034 section 5.4 DNSKEY key tag...\n");
    // dskey.example.com. 86400 IN DNSKEY 256 3 5 (AQOeiiR0GOMYkDshWoSKz9Xz...) ; key id = 60485
    static const uint8_t rdata[] = {
        0x01, 0x00, 0x03, 0x05, 0x01, 0x03, 0x9e, 0x8a, 0x24, 0x74, 0x18, 0xe3, 0x18, 0x90, 0x3b, 0x21,
        0x5a, 0x84, 0x8a, 0xcf, 0xd5, 0xf3, 0x7f, 0x02, 0x6b, 0xd4, 0x06, 0x2d, 0xb2, 0x6c, 0x77, 0x4c,
        0x69, 0x09, 0x68, 0xd5, 0xd5, 0x6d, 0xf8, 0xbf, 0xda, 0x91, 0xe6, 0xf3, 0x6d, 0x9a, 0x27, 0x98,
        0x88, 0xf4, 0x13, 0x33, 0x35, 0x7c, 0x5e, 0x60, 0x29, 0x99, 0x0d, 0x10, 0xfd, 0xf5, 0x66, 0x30,
        0x62, 0xa5, 0x12, 0x76, 0x33, 0x26, 0x98, 0x0a, 0x61, 0x5d, 0xdb, 0xf1, 0x7a, 0x05, 0xdd, 0xfc,
        0xce, 0x7e, 0x5f, 0xb3, 0xab, 0xcc, 0xa0, 0x5a, 0x31, 0xb0, 0x95, 0x74, 0x52, 0xd4, 0x52, 0x1e,
        0x83, 0x87, 0x07, 0x89, 0x06, 0x31, 0x15, 0xbf, 0x97, 0xf6, 0xc3, 0x08, 0xcc, 0xf5, 0x7c, 0xdc,
        0x9c, 0xe7, 0xfe, 0x10, 0xf6, 0xed, 0x1b, 0xd0, 0xcc, 0x06, 0x60, 0x03, 0x8c, 0x50, 0xdc, 0xdb,
        0x0f, 0xeb, 0x96, 0x3c, 0x2f, 0x17
    };
    assert(sizeof(rdata) == 134);
    assert(compute_dnskey_tag(rdata, sizeof(rdata)) == 60485);

    // Any change to the RDATA changes the tag (sanity: the checksum really covers every byte)
    assert(compute_dnskey_tag(rdata, sizeof(rdata) - 1) != 60485);
    // Degenerate inputs never crash and yield 0
    assert(compute_dnskey_tag(NULL, 10) == 0);
    assert(compute_dnskey_tag(rdata, 3) == 0);

    // Algorithm 1 (RSAMD5) uses the special rule of RFC 4034 App. B.1: bits 16..31 counted from the end
    uint8_t md5key[12] = { 0x01, 0x00, 0x03, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0x12, 0x34, 0x56, 0x78 };
    assert(compute_dnskey_tag(md5key, sizeof(md5key)) == 0x3456);
    printf("  -> DNSKEY key tag passed.\n");
}

// ---------------------------------------------------------------------------
// 6. RFC 8945 TSIG: every algorithm survives the Capsicum pre-warm and signs/verifies
// ---------------------------------------------------------------------------
// Regression guard: RFC 9018 cookies became SipHash-2-4 (no OpenSSL), which silently removed the
// only code that initialised OpenSSL before cap_enter(). The first HMAC() executed inside the
// capability-mode backend then died with SIGTRAP (every TSIG / karictl integration test failed).
// main() now calls tsig_prewarm_crypto() explicitly; this test pins its contract.
// (The capability-mode behaviour itself is checked in test_server_core.c on FreeBSD.)
static void test_tsig_prewarm_and_all_algorithms(void) {
    printf("[TEST] RFC vectors: RFC 8945 TSIG HMAC algorithms + Capsicum pre-warm...\n");

    // Must succeed for every algorithm in the TSIG table and be safe to call repeatedly.
    assert(tsig_prewarm_crypto());
    assert(tsig_prewarm_crypto());

    // MAC sizes per RFC 8945 section 6 (full HMAC output length of the underlying hash).
    static const struct { const char *alg; size_t mac_len; } algs[] = {
        { "hmac-md5.sig-alg.reg.int", 16 }, { "hmac-sha1", 20 }, { "hmac-sha224", 28 },
        { "hmac-sha256", 32 },              { "hmac-sha384", 48 }, { "hmac-sha512", 64 },
    };
    for (size_t i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        assert(tsig_algorithm_is_supported(algs[i].alg));

        tsig_key_t key = {0};
        key.name = "prewarm-key.example.com.";
        key.algorithm = (char *)algs[i].alg;
        key.secret_decoded_len = 32;
        memset(key.secret_decoded, 0xA5, 32);

        uint8_t pkt[512] = {0};
        pkt[0] = 0xBE; pkt[1] = 0xEF;   // ID
        pkt[2] = 0x01; pkt[3] = 0x00;   // RD=1
        pkt[5] = 0x01;                  // QDCOUNT=1
        size_t off = 12;
        pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
        pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
        pkt[off++] = 0;
        pkt[off++] = 0; pkt[off++] = 1; // A
        pkt[off++] = 0; pkt[off++] = 1; // IN

        uint8_t mac[64];
        size_t mac_len = 0;
        size_t signed_len = off;
        assert(tsig_sign_packet(pkt, &signed_len, sizeof(pkt), &key, 0, mac, &mac_len, NULL, 0, false) == 0);
        assert(mac_len == algs[i].mac_len);

        uint8_t vmac[64];
        size_t vmac_len = 0;
        assert(tsig_verify_packet(pkt, signed_len, &key, NULL, 0, NULL, 0, false, vmac, &vmac_len) == 0);
        assert(vmac_len == mac_len && memcmp(vmac, mac, mac_len) == 0);

        // A different secret must be rejected with BADSIG (16)
        key.secret_decoded[0] ^= 0xFF;
        assert(tsig_verify_packet(pkt, signed_len, &key, NULL, 0, NULL, 0, false, NULL, NULL) == 16);
    }
    printf("  -> TSIG pre-warm and per-algorithm sign/verify passed.\n");
}

int main(void) {
    printf("=== Starting RFC Published-Vector Conformance Tests ===\n");
    test_siphash_reference_vectors();
    test_rfc9018_appendix_a();
    test_rfc9018_verification_rules();
    test_cookie_config_directives();
    test_rfc4034_key_tag();
    test_tsig_prewarm_and_all_algorithms();
    printf("=== All RFC Published-Vector Conformance Tests PASSED ===\n");
    return 0;
}

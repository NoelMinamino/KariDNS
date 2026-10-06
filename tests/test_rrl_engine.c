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

#include "dns_wire.h"
#include "dns_rrl.h"
#include "dns_cidr.h"
#include "dns_config_parser.h"

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

static void test_siphash_and_init(void) {
    printf("[TEST] RRL: SipHash-2-4 & rrl_init...\n");
    rrl_init();

    uint64_t key[2] = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL };
    uint8_t in[15] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

    uint64_t h1 = siphash24(in, sizeof(in), key);
    uint64_t h2 = siphash24(in, sizeof(in), key);
    assert(h1 == h2); // deterministic

    uint64_t h3 = siphash24(in, sizeof(in) - 1, key);
    assert(h1 != h3);

    printf("  -> siphash24 passed.\n");
}

static void test_get_rrl_class(void) {
    printf("[TEST] RRL: get_rrl_class response classification...\n");
    uint8_t pkt[64] = {0};

    // 1. Short packet (< 12 bytes)
    assert(get_rrl_class(pkt, 10) == RRL_RESP_ERROR);

    // 2. NOERROR with ANCOUNT=1 -> RRL_RESP_NOERROR
    pkt[3] = 0x00; // RCODE=0
    pkt[6] = 0x00; pkt[7] = 0x01; // ANCOUNT=1
    assert(get_rrl_class(pkt, 12) == RRL_RESP_NOERROR);

    // 3. NOERROR with ANCOUNT=0 -> RRL_RESP_NODATA
    pkt[6] = 0x00; pkt[7] = 0x00; // ANCOUNT=0
    assert(get_rrl_class(pkt, 12) == RRL_RESP_NODATA);

    // 4. NXDOMAIN (RCODE=3) -> RRL_RESP_NXDOMAIN
    pkt[3] = 0x03;
    assert(get_rrl_class(pkt, 12) == RRL_RESP_NXDOMAIN);

    // 5. SERVFAIL (RCODE=2) -> RRL_RESP_ERROR
    pkt[3] = 0x02;
    assert(get_rrl_class(pkt, 12) == RRL_RESP_ERROR);

    // 6. REFUSED (RCODE=5) -> RRL_RESP_ERROR
    pkt[3] = 0x05;
    assert(get_rrl_class(pkt, 12) == RRL_RESP_ERROR);

    printf("  -> get_rrl_class passed.\n");
}

static void test_rrl_rate_limiting_and_slip(void) {
    printf("[TEST] RRL: Token bucket rate limiting, /24 aggregation & SLIP...\n");
    rate_limit_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.configured = true;
    cfg.responses_per_second = 5;
    cfg.nodata_per_second = 5;
    cfg.nxdomains_per_second = 2;
    cfg.errors_per_second = 2;
    cfg.window_seconds = 1;
    cfg.slip = 2; // Every 2nd dropped packet gets SLIP (TC=1)

    struct sockaddr_in cli1, cli2;
    memset(&cli1, 0, sizeof(cli1));
    cli1.sin_family = AF_INET;
    cli1.sin_port = htons(12345);
    inet_pton(AF_INET, "192.0.2.10", &cli1.sin_addr);

    memset(&cli2, 0, sizeof(cli2));
    cli2.sin_family = AF_INET;
    cli2.sin_port = htons(54321);
    inet_pton(AF_INET, "192.0.2.99", &cli2.sin_addr); // Same /24 subnet!

    bool slip = false;

    // First 5 queries from cli1 should be allowed (burst limit = 5 * 1 = 5)
    for (int i = 0; i < 5; i++) {
        bool allow = rrl_check(&cli1, RRL_RESP_NOERROR, &cfg, &slip);
        assert(allow == true);
        assert(slip == false);
    }

    // 6th query from cli2 (same /24 subnet) should be rate limited!
    bool allow = rrl_check(&cli2, RRL_RESP_NOERROR, &cfg, &slip);
    assert(allow == false);
    // 1st dropped -> slip false (slip=2)
    assert(slip == false);

    // 7th query -> 2nd dropped -> slip true!
    allow = rrl_check(&cli1, RRL_RESP_NOERROR, &cfg, &slip);
    assert(allow == false);
    assert(slip == true);

    // Test IPv6 /56 subnet aggregation
    struct sockaddr_in6 cli6_a, cli6_b;
    memset(&cli6_a, 0, sizeof(cli6_a));
    cli6_a.sin6_family = AF_INET6;
    cli6_a.sin6_port = htons(1111);
    inet_pton(AF_INET6, "2001:db8:abcd:1200::1", &cli6_a.sin6_addr);

    memset(&cli6_b, 0, sizeof(cli6_b));
    cli6_b.sin6_family = AF_INET6;
    cli6_b.sin6_port = htons(2222);
    inet_pton(AF_INET6, "2001:db8:abcd:12ff::99", &cli6_b.sin6_addr); // Same /56

    for (int i = 0; i < 2; i++) {
        allow = rrl_check(&cli6_a, RRL_RESP_NXDOMAIN, &cfg, &slip);
        assert(allow == true);
    }
    // 3rd should be blocked (rate = 2)
    allow = rrl_check(&cli6_b, RRL_RESP_NXDOMAIN, &cfg, &slip);
    assert(allow == false);

    // Test exempt clients
    ip_port_t exempt;
    exempt.ip = "192.0.2.0/24";
    exempt.port = 0;
    cfg.exempt_clients = &exempt;
    cfg.exempt_clients_count = 1;

    allow = rrl_check(&cli1, RRL_RESP_NOERROR, &cfg, &slip);
    assert(allow == true); // Exempt!

    // Test exempt_clients_parsed
    cidr_entry_t parsed_exempt;
    memset(&parsed_exempt, 0, sizeof(parsed_exempt));
    assert(cidr_entry_parse(&parsed_exempt, "192.0.2.0/24"));
    cfg.exempt_clients_parsed = &parsed_exempt;
    cfg.exempt_clients = NULL;
    allow = rrl_check(&cli1, RRL_RESP_NOERROR, &cfg, &slip);
    assert(allow == true);

    // Test log_only mode
    cfg.exempt_clients_parsed = NULL;
    cfg.exempt_clients_count = 0;
    cfg.log_only = true;
    cfg.responses_per_second = 1;
    rrl_check(&cli1, RRL_RESP_NOERROR, &cfg, &slip);
    // In log_only mode, rate exceeded should still return true!
    allow = rrl_check(&cli1, RRL_RESP_NOERROR, &cfg, &slip);
    assert(allow == true);

    // Test NODATA and ERROR rate classes
    cfg.log_only = false;
    cfg.nodata_per_second = 1;
    cfg.errors_per_second = 1;
    cfg.window_seconds = 5000; // Trigger > 3600 clamp
    allow = rrl_check(&cli1, RRL_RESP_NODATA, &cfg, &slip);
    assert(allow == true);
    allow = rrl_check(&cli1, RRL_RESP_ERROR, &cfg, &slip);
    assert(allow == true);

    // NULL and unconfigured checks
    assert(rrl_check(NULL, RRL_RESP_NOERROR, &cfg, &slip) == true);
    assert(rrl_check(&cli1, RRL_RESP_NOERROR, NULL, &slip) == true);

    printf("  -> rate limiting & slip passed.\n");
}

static void test_rrl_client_exhaustion_and_shutdown(void) {
    printf("[TEST] RRL: rrl_is_client_exhausted & rrl_shutdown...\n");

    rate_limit_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.configured = true;
    cfg.responses_per_second = 2;
    cfg.window_seconds = 1;

    struct sockaddr_in cli;
    memset(&cli, 0, sizeof(cli));
    cli.sin_family = AF_INET;
    cli.sin_port = htons(12345);
    inet_pton(AF_INET, "198.51.100.22", &cli.sin_addr);

    // Initial state: not exhausted
    assert(rrl_is_client_exhausted(&cli, &cfg) == false);

    bool slip = false;
    rrl_check(&cli, RRL_RESP_NOERROR, &cfg, &slip);
    rrl_check(&cli, RRL_RESP_NOERROR, &cfg, &slip);
    rrl_check(&cli, RRL_RESP_NOERROR, &cfg, &slip); // Now dropped

    assert(rrl_is_client_exhausted(&cli, &cfg) == true);
    assert(rrl_is_client_exhausted(NULL, &cfg) == false);

    // Test exempt client in rrl_is_client_exhausted
    ip_port_t exempt;
    exempt.ip = "198.51.100.0/24";
    exempt.port = 0;
    cfg.exempt_clients = &exempt;
    cfg.exempt_clients_count = 1;
    assert(rrl_is_client_exhausted(&cli, &cfg) == false);

    cidr_entry_t parsed_exempt;
    memset(&parsed_exempt, 0, sizeof(parsed_exempt));
    assert(cidr_entry_parse(&parsed_exempt, "198.51.100.0/24"));
    cfg.exempt_clients_parsed = &parsed_exempt;
    cfg.exempt_clients = NULL;
    assert(rrl_is_client_exhausted(&cli, &cfg) == false);

    rate_limit_config_t uncfg;
    memset(&uncfg, 0, sizeof(uncfg));
    assert(rrl_is_client_exhausted(&cli, &uncfg) == false);

    // Test shutdown
    rrl_shutdown();

    printf("  -> rrl_is_client_exhausted & rrl_shutdown passed.\n");
}

/* ---------------------------------------------------------------------------
 * D-05: BIND-compatible keys (lib/dns/rrl.c make_key()) and prefix lengths.
 * Every case uses names of its own so that buckets of earlier cases do not interfere.
 * ------------------------------------------------------------------------- */
static size_t put_name(uint8_t *p, const char *name) {
    size_t n = 0;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t l = dot ? (size_t)(dot - name) : strlen(name);
        p[n++] = (uint8_t)l;
        memcpy(p + n, name, l);
        n += l;
        name += l;
        if (*name == '.') name++;
    }
    p[n++] = 0;
    return n;
}

/* response: question qname/A/IN; for a referral one NS RR owned by `ns_owner` in Authority */
static size_t mk_resp(uint8_t *b, uint8_t rcode, bool aa, uint16_t ancount, const char *qname, const char *ns_owner) {
    memset(b, 0, 512);
    b[2] = 0x80 | (aa ? 0x04 : 0);
    b[3] = rcode;
    b[5] = 1;
    b[7] = (uint8_t)ancount;
    size_t off = 12 + put_name(b + 12, qname);
    b[off + 1] = 1; b[off + 3] = 1;  /* A IN */
    off += 4;
    if (ns_owner) {
        b[9] = 1;                     /* NSCOUNT */
        off += put_name(b + off, ns_owner);
        b[off + 1] = 2; b[off + 3] = 1; /* NS IN */
        b[off + 7] = 60;               /* TTL */
        b[off + 9] = 2;                /* RDLENGTH */
        b[off + 10] = 0xC0; b[off + 11] = 12;
        off += 12;
    }
    return off;
}

static bool rrl_ok(const struct sockaddr *cli, const uint8_t *res, size_t len, const char *qname, uint16_t qtype,
                   const char *zone, bool wildcard, const rate_limit_config_t *cfg) {
    rrl_key_t key;
    char nb[DNS_NAME_TEXT_SIZE];
    rrl_make_key(&key, res, len, qname, qtype, 1, zone, wildcard, nb, sizeof(nb));
    bool slip;
    return rrl_check_key(cli, &key, cfg, &slip);
}

static void test_rrl_bind_keys(void) {
    printf("[TEST] RRL: BIND-compatible keys, prefix lengths, referrals / all-per-second (D-05)...\n");
    rate_limit_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.configured = true;
    cfg.responses_per_second = 1;   /* window 1 s -> one token per bucket */
    cfg.nodata_per_second = 1;
    cfg.nxdomains_per_second = 1;
    cfg.referrals_per_second = 1;
    cfg.errors_per_second = 1;
    cfg.window_seconds = 1;
    cfg.slip = 0;

    struct sockaddr_in a, b;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    b = a;
    inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
    inet_pton(AF_INET, "192.0.2.200", &b.sin_addr);
    const struct sockaddr *A = (const struct sockaddr *)&a, *B = (const struct sockaddr *)&b;
    uint8_t r[512];
    size_t n;

    /* NOERROR: the key is client /24 + QNAME + QTYPE */
    n = mk_resp(r, 0, true, 1, "k1.example.test", NULL);
    assert(rrl_ok(A, r, n, "k1.example.test", 1, "example.test", false, &cfg));
    assert(!rrl_ok(B, r, n, "k1.example.test", 1, "example.test", false, &cfg));   /* same /24 */
    n = mk_resp(r, 0, true, 1, "k2.example.test", NULL);
    assert(rrl_ok(A, r, n, "k2.example.test", 1, "example.test", false, &cfg));    /* other name */
    assert(rrl_ok(A, r, n, "k2.example.test", 28, "example.test", false, &cfg));   /* other type */
    assert(!rrl_ok(A, r, n, "K2.Example.TEST", 1, "example.test", false, &cfg));  /* names ignore case */

    /* ipv4-prefix-length 32: the two hosts are counted apart */
    cfg.ipv4_prefix_length = 32;
    cfg.ipv4_prefix_length_set = true;
    n = mk_resp(r, 0, true, 1, "k3.example.test", NULL);
    assert(rrl_ok(A, r, n, "k3.example.test", 1, "example.test", false, &cfg));
    assert(rrl_ok(B, r, n, "k3.example.test", 1, "example.test", false, &cfg));
    cfg.ipv4_prefix_length_set = false;

    /* NODATA: QNAME without QTYPE */
    n = mk_resp(r, 0, true, 0, "k4.example.test", NULL);
    assert(rrl_ok(A, r, n, "k4.example.test", 1, "example.test", false, &cfg));
    assert(!rrl_ok(A, r, n, "k4.example.test", 28, "example.test", false, &cfg));

    /* NXDOMAIN: the zone name, so random subdomains share one bucket */
    n = mk_resp(r, 3, true, 0, "rnd1.nx.example.test", NULL);
    assert(rrl_ok(A, r, n, "rnd1.nx.example.test", 1, "nx.example.test", false, &cfg));
    n = mk_resp(r, 3, true, 0, "rnd2.nx.example.test", NULL);
    assert(!rrl_ok(A, r, n, "rnd2.nx.example.test", 1, "nx.example.test", false, &cfg));

    /* wildcard answers: one "*.<zone>" bucket */
    n = mk_resp(r, 0, true, 1, "w1.wc.example.test", NULL);
    assert(rrl_ok(A, r, n, "w1.wc.example.test", 1, "wc.example.test", true, &cfg));
    n = mk_resp(r, 0, true, 1, "w2.wc.example.test", NULL);
    assert(!rrl_ok(A, r, n, "w2.wc.example.test", 1, "wc.example.test", true, &cfg));

    /* referral (AA=0, NS in Authority): the delegation point */
    n = mk_resp(r, 0, false, 0, "h1.child.example.test", "child.example.test");
    rrl_key_t key;
    char nb[DNS_NAME_TEXT_SIZE];
    rrl_make_key(&key, r, n, "h1.child.example.test", 1, 1, "example.test", false, nb, sizeof(nb));
    assert(key.cls == RRL_RESP_REFERRAL && key.name && strcmp(key.name, "child.example.test") == 0);
    assert(rrl_ok(A, r, n, "h1.child.example.test", 1, "example.test", false, &cfg));
    n = mk_resp(r, 0, false, 0, "h2.child.example.test", "child.example.test");
    assert(!rrl_ok(A, r, n, "h2.child.example.test", 1, "example.test", false, &cfg));

    /* errors: the client prefix only */
    struct sockaddr_in e;
    memset(&e, 0, sizeof(e));
    e.sin_family = AF_INET;
    inet_pton(AF_INET, "198.51.100.77", &e.sin_addr);
    n = mk_resp(r, 2, false, 0, "e1.example.test", NULL);
    assert(rrl_ok((struct sockaddr *)&e, r, n, "e1.example.test", 1, "example.test", false, &cfg));
    n = mk_resp(r, 5, false, 0, "e2.other.test", NULL);
    assert(!rrl_ok((struct sockaddr *)&e, r, n, "e2.other.test", 1, NULL, false, &cfg));

    /* all-per-second: every response of the client prefix, whatever the name */
    rate_limit_config_t all;
    memset(&all, 0, sizeof(all));
    all.configured = true;
    all.all_per_second = 2;
    all.window_seconds = 1;
    struct sockaddr_in c;
    memset(&c, 0, sizeof(c));
    c.sin_family = AF_INET;
    inet_pton(AF_INET, "203.0.113.9", &c.sin_addr);
    const struct sockaddr *C = (const struct sockaddr *)&c;
    n = mk_resp(r, 0, true, 1, "a1.example.test", NULL);
    assert(rrl_ok(C, r, n, "a1.example.test", 1, "example.test", false, &all));
    n = mk_resp(r, 0, true, 1, "a2.example.test", NULL);
    assert(rrl_ok(C, r, n, "a2.example.test", 1, "example.test", false, &all));
    n = mk_resp(r, 0, true, 1, "a3.example.test", NULL);
    assert(!rrl_ok(C, r, n, "a3.example.test", 1, "example.test", false, &all));
    rrl_key_t any = { .cls = RRL_RESP_NOERROR, .name = "a9.example.test", .qtype = 1, .qclass = 1 };
    assert(rrl_key_exhausted(C, &any, &all));   /* early-drop sees the empty all-per-second bucket */

    /* IPv6: /56 by default, ipv6-prefix-length 64 splits these two */
    struct sockaddr_in6 x, y;
    memset(&x, 0, sizeof(x));
    x.sin6_family = AF_INET6;
    y = x;
    inet_pton(AF_INET6, "2001:db8:0:1::1", &x.sin6_addr);
    inet_pton(AF_INET6, "2001:db8:0:ff::1", &y.sin6_addr);
    n = mk_resp(r, 0, true, 1, "v6a.example.test", NULL);
    assert(rrl_ok((struct sockaddr *)&x, r, n, "v6a.example.test", 1, "example.test", false, &cfg));
    assert(!rrl_ok((struct sockaddr *)&y, r, n, "v6a.example.test", 1, "example.test", false, &cfg));
    cfg.ipv6_prefix_length = 64;
    cfg.ipv6_prefix_length_set = true;
    n = mk_resp(r, 0, true, 1, "v6b.example.test", NULL);
    assert(rrl_ok((struct sockaddr *)&x, r, n, "v6b.example.test", 1, "example.test", false, &cfg));
    assert(rrl_ok((struct sockaddr *)&y, r, n, "v6b.example.test", 1, "example.test", false, &cfg));

    /* the referral class is detected from the header */
    n = mk_resp(r, 0, false, 0, "z.example.test", "example.test");
    assert(get_rrl_class(r, n) == RRL_RESP_REFERRAL);
    n = mk_resp(r, 0, true, 0, "z.example.test", "example.test");
    assert(get_rrl_class(r, n) == RRL_RESP_NODATA);   /* AA=1: NODATA with SOA */

    printf("  -> BIND-compatible keys passed.\n");
}

int main(void) {
    printf("=== Starting RRL Engine Unit Tests ===\n");
    test_siphash_and_init();
    test_get_rrl_class();
    test_rrl_rate_limiting_and_slip();
    test_rrl_client_exhaustion_and_shutdown();
    test_rrl_bind_keys();
    printf("=== All RRL Engine Unit Tests PASSED ===\n");
    return 0;
}


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

    rate_limit_config_t uncfg;
    memset(&uncfg, 0, sizeof(uncfg));
    assert(rrl_is_client_exhausted(&cli, &uncfg) == false);

    // Test shutdown
    rrl_shutdown();

    printf("  -> rrl_is_client_exhausted & rrl_shutdown passed.\n");
}

int main(void) {
    printf("=== Starting RRL Engine Unit Tests ===\n");
    test_siphash_and_init();
    test_get_rrl_class();
    test_rrl_rate_limiting_and_slip();
    test_rrl_client_exhaustion_and_shutdown();
    printf("=== All RRL Engine Unit Tests PASSED ===\n");
    return 0;
}

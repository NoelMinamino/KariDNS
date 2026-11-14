#include "../dns_cidr.h"
#include "../dns_config_parser.h"
#include "../dns_tsig_acl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// Stub for open_via_dir_cache when running unit tests outside full server
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg, ...) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
    } else { \
        fprintf(stderr, "[FAIL] Line %d: " msg "\n", __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

static void test_acl_parity(char **acl_list, int count, const char *client_ip) {
    bool legacy_res = check_acl(client_ip, acl_list, count);
    acl_entry_t *parsed = acl_list_parse(acl_list, count);
    bool new_res = check_acl_bin(client_ip, parsed, count);
    if (parsed) free(parsed);
    TEST_ASSERT(legacy_res == new_res,
        "ACL mismatch for client '%s': legacy=%d, new=%d",
        client_ip, legacy_res, new_res);
}

static void test_parity(const char *cidr_str, const char *client_ip) {
    bool legacy_res = match_cidr(client_ip, cidr_str);

    cidr_entry_t entry;
    bool parsed = cidr_entry_parse(&entry, cidr_str);
    bool new_res = false;
    if (parsed) {
        new_res = cidr_entry_match_str(&entry, client_ip);
    }

    TEST_ASSERT(legacy_res == new_res,
        "Mismatch for CIDR '%s' vs Client IP '%s': legacy=%d, new=%d (parsed=%d)",
        cidr_str, client_ip, legacy_res, new_res, parsed);
}

static void test_sockaddr_match(void) {
    cidr_entry_t entry_v4, entry_v6;
    TEST_ASSERT(cidr_entry_parse(&entry_v4, "192.168.1.0/24") == true, "parse 192.168.1.0/24");
    TEST_ASSERT(cidr_entry_parse(&entry_v6, "2001:db8::/32") == true, "parse 2001:db8::/32");

    struct sockaddr_storage sa4;
    memset(&sa4, 0, sizeof(sa4));
    struct sockaddr_in *sin = (struct sockaddr_in *)&sa4;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.100", &sin->sin_addr);

    TEST_ASSERT(cidr_entry_match_sockaddr(&entry_v4, &sa4) == true, "sockaddr_storage IPv4 in /24");
    TEST_ASSERT(cidr_entry_match_sockaddr(&entry_v6, &sa4) == false, "sockaddr_storage IPv4 in IPv6 /32");

    inet_pton(AF_INET, "192.168.2.1", &sin->sin_addr);
    TEST_ASSERT(cidr_entry_match_sockaddr(&entry_v4, &sa4) == false, "sockaddr_storage IPv4 out of /24");

    struct sockaddr_storage sa6;
    memset(&sa6, 0, sizeof(sa6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa6;
    sin6->sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:db8:1234::1", &sin6->sin6_addr);

    TEST_ASSERT(cidr_entry_match_sockaddr(&entry_v6, &sa6) == true, "sockaddr_storage IPv6 in /32");
    TEST_ASSERT(cidr_entry_match_sockaddr(&entry_v4, &sa6) == false, "sockaddr_storage IPv6 in IPv4 /24");

    inet_pton(AF_INET6, "2001:db9::1", &sin6->sin6_addr);
    TEST_ASSERT(cidr_entry_match_sockaddr(&entry_v6, &sa6) == false, "sockaddr_storage IPv6 out of /32");
}

static void test_ecs_family_mapping(void) {
    /*
     * RFC 7871 ECS Address Family:
     * 1 = IPv4, 2 = IPv6.
     * Host OS address family: AF_INET, AF_INET6.
     * Test mapping conversion: (ecs_family == 1) ? AF_INET : ((ecs_family == 2) ? AF_INET6 : -1)
     */
    cidr_entry_t entry4, entry6;
    TEST_ASSERT(cidr_entry_parse(&entry4, "10.20.30.0/24") == true, "parse 10.20.30.0/24");
    TEST_ASSERT(cidr_entry_parse(&entry6, "2001:db8:85a3::/48") == true, "parse 2001:db8:85a3::/48");

    /* Host OS constants verification */
    TEST_ASSERT(entry4.family == AF_INET, "entry4 family is AF_INET");
    TEST_ASSERT(entry6.family == AF_INET6, "entry6 family is AF_INET6");

    struct in_addr a4;
    inet_pton(AF_INET, "10.20.30.45", &a4);
    uint16_t ecs_family_v4 = 1; /* IANA Address Family 1 = IPv4 */
    int os_family_v4 = (ecs_family_v4 == 1) ? AF_INET : AF_INET6;
    TEST_ASSERT(cidr_entry_match(&entry4, os_family_v4, (const uint8_t *)&a4.s_addr) == true,
        "ECS family 1 -> AF_INET match");

    struct in6_addr a6;
    inet_pton(AF_INET6, "2001:db8:85a3::1", &a6);
    uint16_t ecs_family_v6 = 2; /* IANA Address Family 2 = IPv6 */
    int os_family_v6 = (ecs_family_v6 == 1) ? AF_INET : AF_INET6;
    TEST_ASSERT(cidr_entry_match(&entry6, os_family_v6, (const uint8_t *)&a6.s6_addr) == true,
        "ECS family 2 -> AF_INET6 match");

    /* Negative mismatch */
    inet_pton(AF_INET, "10.20.31.1", &a4);
    TEST_ASSERT(cidr_entry_match(&entry4, os_family_v4, (const uint8_t *)&a4.s_addr) == false,
        "ECS family 1 -> AF_INET mismatch");
}

int main(void) {
    printf("[*] Starting CIDR binary optimization test suite...\n");

    /* 1. "any" and "any;" */
    test_parity("any", "192.0.2.4");
    test_parity("any", "2001:db8::1");
    test_parity("any;", "192.0.2.4");
    test_parity("any;", "::1");

    /* 2. IPv4 Exact and Subnets */
    test_parity("192.168.1.0/24", "192.168.1.1");
    test_parity("192.168.1.0/24", "192.168.1.254");
    test_parity("192.168.1.0/24", "192.168.2.1");
    test_parity("10.0.0.0/8", "10.255.255.255");
    test_parity("10.0.0.0/8", "11.0.0.1");
    test_parity("0.0.0.0/0", "192.0.2.4");
    test_parity("0.0.0.0/0", "255.255.255.255");
    test_parity("192.0.2.1/32", "192.0.2.1");
    test_parity("192.0.2.1/32", "192.0.2.2");
    test_parity("192.0.2.1", "192.0.2.1");     /* Implicit /32 */
    test_parity("192.0.2.1", "192.0.2.2");
    test_parity("172.16.0.0/12", "172.31.255.255");
    test_parity("172.16.0.0/12", "172.32.0.1");
    test_parity("192.168.1.128/25", "192.168.1.130");
    test_parity("192.168.1.128/25", "192.168.1.50");

    /* 3. IPv6 Exact and Subnets */
    test_parity("2001:db8::/32", "2001:db8:1::1");
    test_parity("2001:db8::/32", "2001:db9::1");
    test_parity("2001:db8:abcd:0012::/64", "2001:db8:abcd:12::1");
    test_parity("2001:db8:abcd:0012::/64", "2001:db8:abcd:13::1");
    test_parity("::1/128", "::1");
    test_parity("::1/128", "::2");
    test_parity("::1", "::1");                 /* Implicit /128 */
    test_parity("::1", "::2");
    test_parity("::/0", "2001:db8::1");
    test_parity("::/0", "::1");
    test_parity("2001:db8::/35", "2001:db8:1800::1");
    test_parity("2001:db8::/35", "2001:db8:2000::1");

    /* 4. Cross family & Invalid */
    test_parity("192.168.1.0/24", "2001:db8::1");
    test_parity("2001:db8::/32", "192.168.1.1");
    test_parity("192.168.1.0/33", "192.168.1.1");
    test_parity("192.168.1.0/-1", "192.168.1.1");
    test_parity("192.168.1.0/abc", "192.168.1.1");
    test_parity("2001:db8::/129", "2001:db8::1");
    test_parity("invalid_ip/24", "192.168.1.1");

    /* 5. Sockaddr matching */
    test_sockaddr_match();

    /* 6. RFC 7871 ECS Address Family mapping */
    test_ecs_family_mapping();

    /* 7. ACL List with Allow / Deny rules */
    char *acl_sample1[] = { "!192.168.1.50", "192.168.1.0/24", "!2001:db8::1", "2001:db8::/32", "10.0.0.0/8" };
    test_acl_parity(acl_sample1, 5, "192.168.1.50"); /* Explicitly denied -> false */
    test_acl_parity(acl_sample1, 5, "192.168.1.51"); /* Allowed by /24 -> true */
    test_acl_parity(acl_sample1, 5, "2001:db8::1");   /* Explicitly denied -> false */
    test_acl_parity(acl_sample1, 5, "2001:db8::2");   /* Allowed by /32 -> true */
    test_acl_parity(acl_sample1, 5, "10.1.2.3");      /* Allowed by /8 -> true */
    test_acl_parity(acl_sample1, 5, "172.16.1.1");    /* Not in ACL -> false */

    /* 8. TSIG Key lookup by name */
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    tsig_key_t k1, k2;
    memset(&k1, 0, sizeof(k1));
    memset(&k2, 0, sizeof(k2));
    k1.name = "admin-key";
    k2.name = "transfer-key";
    k1.next = &k2;
    cfg.keys = &k1;

    TEST_ASSERT(find_tsig_key_by_name(&cfg, "admin-key") == &k1, "find admin-key exact");
    TEST_ASSERT(find_tsig_key_by_name(&cfg, "ADMIN-KEY") == &k1, "find admin-key case-insensitive");
    TEST_ASSERT(find_tsig_key_by_name(&cfg, "transfer-key") == &k2, "find transfer-key");
    TEST_ASSERT(find_tsig_key_by_name(&cfg, "nonexistent") == NULL, "find nonexistent");
    TEST_ASSERT(find_tsig_key_by_name(NULL, "admin-key") == NULL, "find NULL cfg");
    TEST_ASSERT(find_tsig_key_by_name(&cfg, NULL) == NULL, "find NULL key");
    TEST_ASSERT(find_tsig_key_by_name(&cfg, "") == NULL, "find empty key");

    /* 9. the prefix length is digits only (strtol alone would take leading space, '+' and '-'), in both parsers */
    {
        cidr_entry_t pe;
        TEST_ASSERT(cidr_entry_parse(&pe, "192.0.2.0/24") && pe.prefix == 24, "prefix 24");
        TEST_ASSERT(cidr_entry_parse(&pe, "192.0.2.0/024") && pe.prefix == 24, "leading zeros are digits");
        TEST_ASSERT(!cidr_entry_parse(&pe, "192.0.2.0/ 24"), "prefix with a leading space is refused");
        TEST_ASSERT(!cidr_entry_parse(&pe, "192.0.2.0/+24"), "prefix with a plus sign is refused");
        TEST_ASSERT(!cidr_entry_parse(&pe, "192.0.2.0/-1"), "negative prefix is refused");
        TEST_ASSERT(!cidr_entry_parse(&pe, "192.0.2.0/"), "empty prefix is refused");
        TEST_ASSERT(!cidr_entry_parse(&pe, "192.0.2.0/33"), "IPv4 prefix above 32 is refused");
        TEST_ASSERT(cidr_entry_parse(&pe, "2001:db8::/128") && pe.prefix == 128, "IPv6 /128");
        TEST_ASSERT(!cidr_entry_parse(&pe, "2001:db8::/129"), "IPv6 prefix above 128 is refused");
        TEST_ASSERT(!match_cidr("192.0.2.1", "192.0.2.0/ 24"), "match_cidr: prefix with a leading space matches nothing");
        TEST_ASSERT(!match_cidr("192.0.2.1", "192.0.2.0/+24"), "match_cidr: prefix with a plus sign matches nothing");
        TEST_ASSERT(match_cidr("192.0.2.1", "192.0.2.0/24"), "match_cidr: plain prefix still matches");
    }

    /* 10. a BADKEY / BADSIG answer reserves room for the TSIG RR it carries (the key name and algorithm of the request), though no key was found */
    {
        tsig_request_t tr;
        memset(&tr, 0, sizeof(tr));
        tr.status = TSIG_REQ_ERROR;
        tr.error = 17;
        snprintf(tr.key_name, sizeof(tr.key_name), "nokey.example.");
        snprintf(tr.alg_name, sizeof(tr.alg_name), "hmac-sha256.");
        size_t want = tsig_rr_wire_size("nokey.example.", "hmac-sha256.", 17);
        TEST_ASSERT(want > 0 && tsig_response_reserve(&tr) == want, "BADKEY without a key reserves the TSIG RR");
        tr.error = 16;
        want = tsig_rr_wire_size("nokey.example.", "hmac-sha256.", 16);
        TEST_ASSERT(tsig_response_reserve(&tr) == want, "BADSIG reserves from the request's names");
        tr.status = TSIG_REQ_NONE;
        TEST_ASSERT(tsig_response_reserve(&tr) == 0, "no TSIG: nothing reserved");
        tr.status = TSIG_REQ_VALID;
        TEST_ASSERT(tsig_response_reserve(&tr) == 0, "valid but no key object: nothing reserved");
    }

    /* 11. RFC 8945 section 5.3: a response whose TSIG does not fit becomes question + TSIG, TC=1, RCODE 0 -- also an error response (BADTIME, RCODE 9) */
    {
        static tsig_key_t tk;
        memset(&tk, 0, sizeof(tk));
        tk.name = "k.test.";
        tk.algorithm = "hmac-sha256";
        memset(tk.secret_decoded, 0x42, 32);
        tk.secret_decoded_len = 32;
        tsig_request_t tr;
        memset(&tr, 0, sizeof(tr));
        tr.status = TSIG_REQ_ERROR;
        tr.error = 18;                       /* BADTIME: signed with the request's key */
        tr.key = &tk;
        tr.time_signed = 1700000000;
        tr.fudge = 300;
        memset(tr.mac, 0x11, 32);   /* the verified MAC of the request (BADTIME keeps it) */
        tr.mac_len = 32;
        snprintf(tr.key_name, sizeof(tr.key_name), "k.test.");
        snprintf(tr.alg_name, sizeof(tr.alg_name), "hmac-sha256.");
        uint8_t res[512];
        memset(res, 0xAB, sizeof(res));
        memset(res, 0, 12);
        res[3] = 0x09;                       /* NOTAUTH */
        res[5] = 1;                          /* one question: a.test. A IN */
        res[7] = 1;                          /* and an answer that is long enough to push the TSIG out */
        static const uint8_t q[] = { 1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1 };
        memcpy(res + 12, q, sizeof(q));
        size_t q_end = 12 + sizeof(q);
        int n = tsig_finish_response(res, 300, 200, &tr);
        TEST_ASSERT(n > (int)q_end && n <= 200, "TSIG that does not fit: a response is still made (n=%d)", n);
        TEST_ASSERT(n > 0 && (res[2] & 0x02) != 0, "TC=1");
        TEST_ASSERT(n > 0 && (res[3] & 0x0F) == 0, "RCODE 0 (NOERROR) in the TC response (RFC 8945 5.3)");
        TEST_ASSERT(n > 0 && res[6] == 0 && res[7] == 0 && res[9] == 0 && res[11] == 1, "no answer, the TSIG RR in the additional section");
    }

    printf("[*] Results: %d / %d tests passed.\n", g_tests_passed, g_tests_run);
    if (g_tests_passed == g_tests_run) {
        printf("[OK] All CIDR tests passed successfully!\n");
        return 0;
    } else {
        printf("[FAIL] Some tests failed!\n");
        return 1;
    }
}

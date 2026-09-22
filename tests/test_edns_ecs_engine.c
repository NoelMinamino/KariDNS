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
#include "dns_edns_ecs.h"
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

static void test_cookie_generation(void) {
    printf("[TEST] EDNS/ECS: Cookie secret init & SipHash-2-4 generation...\n");
    init_server_cookie_secret();

    uint8_t client_cookie[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    uint8_t server_cookie1[16] = {0};
    uint8_t server_cookie2[16] = {0};
    uint32_t ts = 1700000000;

    // IPv4 Cookie
    bool ok = generate_server_cookie(NULL, "192.0.2.1", client_cookie, server_cookie1, ts);
    assert(ok == true);
    assert(server_cookie1[0] == 1); // version
    assert(server_cookie1[4] == ((ts >> 24) & 0xFF));
    assert(server_cookie1[7] == (ts & 0xFF));

    // Deterministic with same parameters
    ok = generate_server_cookie(NULL, "192.0.2.1", client_cookie, server_cookie2, ts);
    assert(ok == true);
    assert(memcmp(server_cookie1, server_cookie2, 16) == 0);

    // Different IP produces different cookie
    uint8_t server_cookie_diff[16] = {0};
    ok = generate_server_cookie(NULL, "192.0.2.2", client_cookie, server_cookie_diff, ts);
    assert(ok == true);
    assert(memcmp(server_cookie1 + 8, server_cookie_diff + 8, 8) != 0);

    // IPv6 Cookie
    uint8_t server_cookie_v6[16] = {0};
    ok = generate_server_cookie(NULL, "2001:db8::1", client_cookie, server_cookie_v6, ts);
    assert(ok == true);
    assert(server_cookie_v6[0] == 1);

    // Invalid IP
    uint8_t dummy_srv[16] = {0};
    ok = generate_server_cookie(NULL, "not-an-ip", client_cookie, dummy_srv, ts);
    assert(ok == false);

    printf("  -> Cookie generation passed.\n");
}

static void test_extended_dns_errors(void) {
    printf("[TEST] EDNS/ECS: Extended DNS Errors (EDE) counters and packing...\n");
    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));

    // 1. Not present or not enabled -> no EDE added
    add_ede(&edns, false, 18, "Prohibited");
    assert(edns.ede_count == 0);

    edns.present = true;
    add_ede(&edns, false, 18, "Prohibited");
    assert(edns.ede_count == 0);

    // 2. Add various EDE codes
    uint64_t proh_before = atomic_load(&g_ede_prohibited_total);
    uint64_t notauth_before = atomic_load(&g_ede_not_authoritative_total);
    uint64_t notsupp_before = atomic_load(&g_ede_not_supported_total);
    uint64_t other_before = atomic_load(&g_ede_other_total);

    add_ede(&edns, true, 18, "Blocked by policy");
    assert(edns.ede_count == 1);
    assert(edns.ede_list[0].code == 18);
    assert(strcmp(edns.ede_list[0].text, "Blocked by policy") == 0);
    assert(atomic_load(&g_ede_prohibited_total) == proh_before + 1);

    add_ede(&edns, true, 20, "Not Authoritative");
    assert(edns.ede_count == 2);
    assert(atomic_load(&g_ede_not_authoritative_total) == notauth_before + 1);

    add_ede(&edns, true, 21, "Not Supported");
    assert(edns.ede_count == 3);
    assert(atomic_load(&g_ede_not_supported_total) == notsupp_before + 1);

    add_ede(&edns, true, 0, "Other error");
    assert(edns.ede_count == 4);
    assert(atomic_load(&g_ede_other_total) == other_before + 1);

    // 3. Max EDE capacity
    for (int i = edns.ede_count; i < MAX_EDE_COUNT + 5; i++) {
        add_ede(&edns, true, 1, "test");
    }
    assert(edns.ede_count == MAX_EDE_COUNT);

    printf("  -> EDE passed.\n");
}

static void test_tag_def_pack_unpack(void) {
    printf("[TEST] EDNS/ECS: Tag definition packing and unpacking...\n");

    ecs_tag_def_t def;
    memset(&def, 0, sizeof(def));
    def.tag = "tokyo";
    def.cidr_count = 2;
    ecs_cidr_entry_t cidrs[2];
    cidrs[0].cidr = "192.0.2.0/24";
    cidrs[1].cidr = "2001:db8::/32";
    def.cidrs = cidrs;

    uint8_t buf[256];
    size_t packed_len = pack_tag_def_rdata(buf, sizeof(buf), &def);
    assert(packed_len > 0);

    // Small buffer test
    size_t small_len = pack_tag_def_rdata(buf, 5, &def);
    assert(small_len == 0);

    // Unpack
    ecs_tag_def_t *unpacked_defs = NULL;
    int unpacked_count = 0;
    bool ok = unpack_tag_def_rdata(buf, packed_len, &unpacked_defs, &unpacked_count);
    assert(ok == true);
    assert(unpacked_count == 1);
    assert(strcmp(unpacked_defs[0].tag, "tokyo") == 0);
    assert(unpacked_defs[0].cidr_count == 2);
    assert(strcmp(unpacked_defs[0].cidrs[0].cidr, "192.0.2.0/24") == 0);
    assert(strcmp(unpacked_defs[0].cidrs[1].cidr, "2001:db8::/32") == 0);
    assert(unpacked_defs[0].cidrs[0].parsed.valid == true);
    assert(unpacked_defs[0].cidrs[1].parsed.valid == true);

    // Cleanup
    for (int i = 0; i < unpacked_count; i++) {
        free(unpacked_defs[i].tag);
        for (int j = 0; j < unpacked_defs[i].cidr_count; j++) {
            free(unpacked_defs[i].cidrs[j].cidr);
        }
        free(unpacked_defs[i].cidrs);
    }
    free(unpacked_defs);

    // Unpack truncated / invalid
    unpacked_defs = NULL;
    unpacked_count = 0;
    assert(unpack_tag_def_rdata(NULL, 0, &unpacked_defs, &unpacked_count) == false);
    assert(unpack_tag_def_rdata(buf, 2, &unpacked_defs, &unpacked_count) == false);

    printf("  -> Tag def pack/unpack passed.\n");
}

static void test_trusted_resolvers_unpack(void) {
    printf("[TEST] EDNS/ECS: Trusted resolvers unpacking...\n");
    // Format: 1 byte count, followed by [1 byte len + string]
    uint8_t data[64];
    size_t off = 0;
    data[off++] = 2; // 2 resolvers
    const char *r1 = "192.0.2.53";
    data[off++] = (uint8_t)strlen(r1);
    memcpy(&data[off], r1, strlen(r1));
    off += strlen(r1);
    const char *r2 = "2001:db8::53";
    data[off++] = (uint8_t)strlen(r2);
    memcpy(&data[off], r2, strlen(r2));
    off += strlen(r2);

    char **resolvers = NULL;
    int count = 0;
    bool ok = unpack_trusted_resolvers_rdata(data, off, &resolvers, &count);
    assert(ok == true);
    assert(count == 2);
    assert(strcmp(resolvers[0], "192.0.2.53") == 0);
    assert(strcmp(resolvers[1], "2001:db8::53") == 0);

    for (int i = 0; i < count; i++) free(resolvers[i]);
    free(resolvers);

    printf("  -> Trusted resolvers unpack passed.\n");
}

static void test_tinydns_loc_and_wrap(void) {
    printf("[TEST] EDNS/ECS: tinydns location unpack & record wrap...\n");
    // 1. unpack_tinydns_loc_rdata
    // code[2], prefix_len, prefix[4]
    uint8_t loc_data[7] = { 'j', 'p', 3, 192, 0, 2, 0 };
    tinydns_location_entry_t *locs = NULL;
    int loc_count = 0;
    bool ok = unpack_tinydns_loc_rdata(loc_data, 6, &locs, &loc_count);
    assert(ok == true);
    assert(loc_count == 1);
    assert(locs[0].code[0] == 'j' && locs[0].code[1] == 'p');
    assert(locs[0].prefix_len == 3);
    assert(locs[0].prefix[0] == 192 && locs[0].prefix[1] == 0 && locs[0].prefix[2] == 2);
    free(locs);

    // 2. wrap_tinydns_record
    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.name = "www.example.com";
    rec.type = "A";
    rec.type_code = 1;
    rec.class_str = "IN";
    rec.class_val = 1;
    rec.ttl = "300";
    rec.ttl_value = 300;
    rec.rdata_count = 1;
    rec.rdata[0] = "192.0.2.1";
    rec.tinydns_loc[0] = 'u';
    rec.tinydns_loc[1] = 's';
    rec.tinydns_ttd = 1800000000;
    rec.tinydns_ttl_countdown = true;

    dns_record_t out_wrap;
    uint8_t wrap_buf[512];
    ok = wrap_tinydns_record(&rec, &out_wrap, wrap_buf, sizeof(wrap_buf));
    assert(ok == true);
    assert(out_wrap.type_code == DNS_TYPE_KARIDNS_TINYDNS_WRAP);
    assert(out_wrap.class_val == DNS_CLASS_KARIDNS_EXT);
    assert(out_wrap.generic_len >= 21 + 4);

    printf("  -> tinydns loc & wrap passed.\n");
}

static void test_ecs_resolution(void) {
    printf("[TEST] EDNS/ECS: resolve_ecs_subnet_tag & match_ecs_client_subnet...\n");

    ecs_tag_def_t tag_tokyo;
    memset(&tag_tokyo, 0, sizeof(tag_tokyo));
    tag_tokyo.tag = "tokyo";
    tag_tokyo.cidr_count = 1;
    ecs_cidr_entry_t cidr_tokyo;
    cidr_tokyo.cidr = "192.0.2.0/24";
    cidr_entry_parse(&cidr_tokyo.parsed, cidr_tokyo.cidr);
    tag_tokyo.cidrs = &cidr_tokyo;

    ecs_tag_def_t tag_osaka;
    memset(&tag_osaka, 0, sizeof(tag_osaka));
    tag_osaka.tag = "osaka";
    tag_osaka.cidr_count = 1;
    ecs_cidr_entry_t cidr_osaka;
    cidr_osaka.cidr = "198.51.100.0/24";
    cidr_entry_parse(&cidr_osaka.parsed, cidr_osaka.cidr);
    tag_osaka.cidrs = &cidr_osaka;

    ecs_tag_def_t tags[2] = { tag_tokyo, tag_osaka };

    zone_arena_t zone;
    memset(&zone, 0, sizeof(zone));
    zone.bind_ecs_tags = tags;
    zone.bind_ecs_tag_count = 2;

    uint8_t addr_match[4] = { 192, 0, 2, 45 };
    uint8_t out_scope = 0;
    const char *tag = resolve_ecs_subnet_tag(&zone, NULL, NULL, addr_match, 1 /* IPv4 */, &out_scope);
    assert(tag != NULL);
    assert(strcmp(tag, "tokyo") == 0);
    assert(out_scope == 24);

    uint8_t addr_nomatch[4] = { 10, 0, 0, 1 };
    tag = resolve_ecs_subnet_tag(&zone, NULL, NULL, addr_nomatch, 1, &out_scope);
    assert(tag == NULL);

    // Test resolve_bind_location_tag
    zone.bind_location_tags = tags;
    zone.bind_location_tag_count = 2;
    const char *loc_tag = resolve_bind_location_tag(&zone, NULL, NULL, "198.51.100.99");
    assert(loc_tag != NULL);
    assert(strcmp(loc_tag, "osaka") == 0);

    loc_tag = resolve_bind_location_tag(&zone, NULL, NULL, "10.0.0.1");
    assert(loc_tag == NULL);

    // Test tinydns_resolve_client_location
    tinydns_location_entry_t loc_entries[2];
    loc_entries[0].code[0] = 'j'; loc_entries[0].code[1] = 'p';
    loc_entries[0].prefix_len = 3;
    loc_entries[0].prefix[0] = 192; loc_entries[0].prefix[1] = 0; loc_entries[0].prefix[2] = 2;

    loc_entries[1].code[0] = 'u'; loc_entries[1].code[1] = 's';
    loc_entries[1].prefix_len = 0; // default /0

    zone.locations = loc_entries;
    zone.location_count = 2;

    char resolved_loc[2] = {0, 0};
    tinydns_resolve_client_location(&zone, "192.0.2.123", resolved_loc);
    assert(resolved_loc[0] == 'j' && resolved_loc[1] == 'p');

    tinydns_resolve_client_location(&zone, "1.2.3.4", resolved_loc);
    assert(resolved_loc[0] == 'u' && resolved_loc[1] == 's');

    printf("  -> ECS & location resolution passed.\n");
}

static void test_ecs_trusted_resolver_precedence(void) {
    printf("[TEST] EDNS/ECS: is_ecs_trusted_resolver source precedence (zone data > zone config > server config)...\n");

    char *srv_list[] = { (char *)"192.0.2.0/24" };
    char *zcfg_list[] = { (char *)"198.51.100.0/24" };
    char *zone_list[] = { (char *)"203.0.113.0/24" };

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zone_arena_t zone;
    memset(&zone, 0, sizeof(zone));

    // No source configured anywhere, or no client address: never trusted (fail closed).
    assert(!is_ecs_trusted_resolver(NULL, NULL, NULL, "192.0.2.7"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "192.0.2.7"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, NULL));

    // Server-level list, pre-parsed binary ACL.
    cfg.ecs_trusted_resolvers = srv_list;
    cfg.ecs_trusted_resolvers_count = 1;
    cfg.ecs_trusted_resolvers_parsed = acl_list_parse(srv_list, 1);
    assert(cfg.ecs_trusted_resolvers_parsed != NULL);
    assert(is_ecs_trusted_resolver(&zone, &cfg, NULL, "192.0.2.7"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, NULL, "198.51.100.1"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, NULL, "203.0.113.9"));

    // A zone-level list replaces (does not extend) the server-level list.
    zcfg.ecs_trusted_resolvers = zcfg_list;
    zcfg.ecs_trusted_resolvers_count = 1;
    zcfg.ecs_trusted_resolvers_parsed = acl_list_parse(zcfg_list, 1);
    assert(zcfg.ecs_trusted_resolvers_parsed != NULL);
    assert(is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "198.51.100.1"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "192.0.2.7"));

    // The list received via extended AXFR (stored in the zone data) wins over both.
    zone.bind_ecs_trusted_resolvers = zone_list;
    zone.bind_ecs_trusted_resolver_count = 1;
    zone.bind_ecs_trusted_resolvers_parsed = acl_list_parse(zone_list, 1);
    assert(zone.bind_ecs_trusted_resolvers_parsed != NULL);
    assert(is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "203.0.113.9"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "198.51.100.1"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "192.0.2.7"));

    // Without the pre-parsed form the textual lists are used, with the same precedence.
    free(zone.bind_ecs_trusted_resolvers_parsed); zone.bind_ecs_trusted_resolvers_parsed = NULL;
    free(zcfg.ecs_trusted_resolvers_parsed);      zcfg.ecs_trusted_resolvers_parsed = NULL;
    free(cfg.ecs_trusted_resolvers_parsed);       cfg.ecs_trusted_resolvers_parsed = NULL;
    assert(is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "203.0.113.9"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "198.51.100.1"));
    zone.bind_ecs_trusted_resolvers = NULL; zone.bind_ecs_trusted_resolver_count = 0;
    assert(is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "198.51.100.1"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "192.0.2.7"));
    zcfg.ecs_trusted_resolvers = NULL; zcfg.ecs_trusted_resolvers_count = 0;
    assert(is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "192.0.2.7"));
    assert(!is_ecs_trusted_resolver(&zone, &cfg, &zcfg, "198.51.100.1"));

    // ACL semantics: first match wins, `!` negates (BIND 9 address_match_list), IPv6 prefixes.
    char *neg[] = { (char *)"!192.0.2.7", (char *)"192.0.2.0/24", (char *)"2001:db8::/32" };
    cfg.ecs_trusted_resolvers = neg;
    cfg.ecs_trusted_resolvers_count = 3;
    cfg.ecs_trusted_resolvers_parsed = acl_list_parse(neg, 3);
    assert(cfg.ecs_trusted_resolvers_parsed != NULL);
    assert(!is_ecs_trusted_resolver(NULL, &cfg, NULL, "192.0.2.7"));    // negated entry matches first
    assert(is_ecs_trusted_resolver(NULL, &cfg, NULL, "192.0.2.8"));
    assert(is_ecs_trusted_resolver(NULL, &cfg, NULL, "2001:db8::1"));
    assert(!is_ecs_trusted_resolver(NULL, &cfg, NULL, "2001:db9::1"));
    free(cfg.ecs_trusted_resolvers_parsed);
    printf("  -> is_ecs_trusted_resolver precedence & ACL semantics passed.\n");
}

int main(void) {
    printf("=== Starting EDNS / ECS Engine Unit Tests ===\n");
    test_cookie_generation();
    test_extended_dns_errors();
    test_tag_def_pack_unpack();
    test_trusted_resolvers_unpack();
    test_tinydns_loc_and_wrap();
    test_ecs_resolution();
    test_ecs_trusted_resolver_precedence();
    printf("=== All EDNS / ECS Engine Unit Tests PASSED ===\n");
    return 0;
}

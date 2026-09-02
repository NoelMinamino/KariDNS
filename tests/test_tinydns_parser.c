#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include "../dns_wire.h"
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_utils.h"

#include <fcntl.h>
#include <unistd.h>

#define TTL_NS 259200UL
#define TTL_POSITIVE 86400UL
#define TTL_NEGATIVE 2560UL

// Stub for open_via_dir_cache when running unit tests outside full server
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static int test_count = 0;
static int pass_count = 0;

#define TEST_ASSERT(expr, msg) do { \
    test_count++; \
    if (expr) { \
        pass_count++; \
    } else { \
        printf("FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
    } \
} while(0)

/* ============================================================================
 * Test 1: 各種レコードの基本パース検証 (., &, +, =, -, @, ', ^, C, Z, :, %)
 * ============================================================================ */
static void test_basic_records(void) {
    printf("--- Test 1: Basic Records Parsing ---\n");

    const char *data =
        "# Comment line should be ignored\n"
        "\n" // empty line
        "-bad.example.com:1.2.3.4:300\n" // disabled line, skipped
        ".example.com:192.168.1.1:a:259200\n" // SOA + NS + A
        "&sub.example.com:192.168.1.2:ns1.sub:86400\n" // NS + A (x has dot)
        "+www.example.com:192.168.1.10:3600\n" // A
        "=mail.example.com:192.168.1.20:7200\n" // A + PTR
        "@example.com:192.168.1.30:mx1:10:1800\n" // MX + A
        "'txt.example.com:Hello\\040World:300\n" // TXT
        "^ptr.example.com:target.example.com:600\n" // PTR
        "Calias.example.com:www.example.com:1200\n" // CNAME
        "Zcustom.example.com:ns1.custom.example.com:admin.custom.example.com:2026090201:7200:3600:1209600:300:600\n" // Full SOA
        ":ssh.example.com:44:\\002\\001\\001\\012\\023\\045:3600\n" // Generic RR (SSHFP type 44)
        "%loc1:192.168\n"; // location directive (phase 1: ignored)

    char buf[4096];
    strncpy(buf, data, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    zone_arena_t arena;
    zone_arena_init(&arena);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .default_origin = "example.com.",
        .err_out = &err
    };

    int count = parse_tinydns_data(buf, strlen(buf), &arena, &ctx);
    TEST_ASSERT(count > 0, "parse_tinydns_data should succeed");
    printf("Parsed %d records into arena (count=%zu)\n", count, arena.count);

    // 検証: SOA for example.com.
    bool found_soa = false;
    bool found_ns = false;
    bool found_glue_a = false;
    bool found_www_a = false;
    bool found_mail_a = false;
    bool found_mx = false;
    bool found_txt = false;
    bool found_cname = false;

    for (size_t i = 0; i < arena.count; i++) {
        dns_record_t *r = &arena.records[i];
        if (r->type_code == 6 && strcmp(r->name, "example.com.") == 0) {
            found_soa = true;
            TEST_ASSERT(strcmp(r->rdata[0], "a.ns.example.com.") == 0, "SOA mname x expansion");
            TEST_ASSERT(strcmp(r->rdata[1], "hostmaster.example.com.") == 0, "SOA rname");
            TEST_ASSERT(r->ttl_value == TTL_NEGATIVE, "SOA TTL default");
        }
        if (r->type_code == 2 && strcmp(r->name, "example.com.") == 0) {
            found_ns = true;
            TEST_ASSERT(strcmp(r->rdata[0], "a.ns.example.com.") == 0, "NS target");
            TEST_ASSERT(r->ttl_value == 259200, "NS TTL");
        }
        if (r->type_code == 1 && strcmp(r->name, "a.ns.example.com.") == 0) {
            found_glue_a = true;
            TEST_ASSERT(strcmp(r->rdata[0], "192.168.1.1") == 0, "Glue A IP");
        }
        if (r->type_code == 1 && strcmp(r->name, "www.example.com.") == 0) {
            found_www_a = true;
            TEST_ASSERT(strcmp(r->rdata[0], "192.168.1.10") == 0, "www A IP");
            TEST_ASSERT(r->ttl_value == 3600, "www A TTL");
        }
        if (r->type_code == 1 && strcmp(r->name, "mail.example.com.") == 0) {
            found_mail_a = true;
            TEST_ASSERT(strcmp(r->rdata[0], "192.168.1.20") == 0, "mail A IP");
            TEST_ASSERT(r->ttl_value == 7200, "mail A TTL");
        }
        if (r->type_code == 15 && strcmp(r->name, "example.com.") == 0) {
            found_mx = true;
            TEST_ASSERT(strcmp(r->rdata[0], "10") == 0, "MX preference");
            TEST_ASSERT(strcmp(r->rdata[1], "mx1.mx.example.com.") == 0, "MX target x expansion");
            TEST_ASSERT(r->ttl_value == 1800, "MX TTL");
        }
        if (r->type_code == 16 && strcmp(r->name, "txt.example.com.") == 0) {
            found_txt = true;
            TEST_ASSERT(strcmp(r->rdata[0], "Hello World") == 0, "TXT octal escape \\040");
            TEST_ASSERT(r->ttl_value == 300, "TXT TTL");
        }
        if (r->type_code == 5 && strcmp(r->name, "alias.example.com.") == 0) {
            found_cname = true;
            TEST_ASSERT(strcmp(r->rdata[0], "www.example.com.") == 0, "CNAME target");
        }
    }

    TEST_ASSERT(found_soa, "Found SOA");
    TEST_ASSERT(found_ns, "Found NS");
    TEST_ASSERT(found_glue_a, "Found Glue A");
    TEST_ASSERT(found_www_a, "Found www A");
    TEST_ASSERT(found_mail_a, "Found mail A");
    TEST_ASSERT(found_mx, "Found MX");
    TEST_ASSERT(found_txt, "Found TXT");
    TEST_ASSERT(found_cname, "Found CNAME");

    zone_arena_destroy(&arena);
}

/* ============================================================================
 * Test 2: TXT 127バイトチャンク分割検証
 * ============================================================================ */
static void test_txt_127_byte_chunking(void) {
    printf("--- Test 2: TXT 127-byte Chunking ---\n");

    // 300バイトのテキスト文字列を作成 (127 + 127 + 46 = 300) -> 3 chunks
    char txt_line[600];
    strcpy(txt_line, "'longtxt.example.com:");
    size_t header_len = strlen(txt_line);
    for (int i = 0; i < 300; i++) {
        txt_line[header_len + i] = 'A' + (i % 26);
    }
    txt_line[header_len + 300] = '\0';
    strcat(txt_line, ":3600\n");

    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .default_origin = "example.com.", .err_out = &err };

    int count = parse_tinydns_data(txt_line, strlen(txt_line), &arena, &ctx);
    TEST_ASSERT(count == 1, "parse long TXT");
    TEST_ASSERT(arena.count == 1, "1 record in arena");

    dns_record_t *rec = &arena.records[0];
    TEST_ASSERT(rec->type_code == 16, "Record is TXT");
    TEST_ASSERT(rec->rdata_count == 3, "TXT split into exactly 3 chunks (127+127+46)");
    if (rec->rdata_count == 3) {
        TEST_ASSERT(strlen(rec->rdata[0]) == 127, "Chunk 0 is 127 bytes");
        TEST_ASSERT(strlen(rec->rdata[1]) == 127, "Chunk 1 is 127 bytes");
        TEST_ASSERT(strlen(rec->rdata[2]) == 46, "Chunk 2 is 46 bytes");
    }
    zone_arena_destroy(&arena);

    // 6096バイト超のTXTレコードが拒否されることを検証
    char *huge_txt = malloc(7000);
    if (huge_txt) {
        strcpy(huge_txt, "'overlong.example.com:");
        size_t hlen = strlen(huge_txt);
        for (int i = 0; i < 6200; i++) huge_txt[hlen + i] = 'X';
        huge_txt[hlen + 6200] = '\0';
        strcat(huge_txt, ":3600\n");

        zone_arena_t arena_huge;
        zone_arena_init(&arena_huge);
        parse_error_t err_huge = {0};
        parse_context_t ctx_huge = { .default_origin = "example.com.", .err_out = &err_huge };

        int res_huge = parse_tinydns_data(huge_txt, strlen(huge_txt), &arena_huge, &ctx_huge);
        TEST_ASSERT(res_huge < 0, "Oversized TXT (>6096 bytes) rejected with error");
        zone_arena_destroy(&arena_huge);
        free(huge_txt);
    }
}

/* ============================================================================
 * Test 3: 緩い IPv4 スキャナ検証 (オーバーフロー & ゴミ文字)
 * ============================================================================ */
static void test_loose_ip4_scan(void) {
    printf("--- Test 3: Loose IPv4 Scanning ---\n");

    // "256.0.0.1" -> (256 & 0xFF) = 0 -> "0.0.0.1"
    // "10.20.30.40garbage" -> "10.20.30.40"
    const char *data =
        "+overflow.example.com:256.0.0.1:300\n"
        "+garbage.example.com:10.20.30.40trailingstuff:300\n";

    char buf[512];
    strcpy(buf, data);

    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .default_origin = "example.com.", .err_out = &err };

    int count = parse_tinydns_data(buf, strlen(buf), &arena, &ctx);
    TEST_ASSERT(count == 2, "Loose IPv4 records parsed");

    for (size_t i = 0; i < arena.count; i++) {
        dns_record_t *r = &arena.records[i];
        if (strcmp(r->name, "overflow.example.com.") == 0) {
            TEST_ASSERT(strcmp(r->rdata[0], "0.0.0.1") == 0, "256 masked to 0");
        }
        if (strcmp(r->name, "garbage.example.com.") == 0) {
            TEST_ASSERT(strcmp(r->rdata[0], "10.20.30.40") == 0, "Trailing garbage ignored");
        }
    }

    zone_arena_destroy(&arena);
}

/* ============================================================================
 * Test 4: 汎用レコードの禁止タイプ拒否検証 (0, 2, 5, 6, 12, 15, 252)
 * ============================================================================ */
static void test_generic_record_prohibited_types(void) {
    printf("--- Test 4: Generic Record Prohibited Types ---\n");

    uint16_t bad_types[] = {0, 2, 5, 6, 12, 15, 252};
    for (size_t t = 0; t < sizeof(bad_types)/sizeof(bad_types[0]); t++) {
        char line[256];
        snprintf(line, sizeof(line), ":gen.example.com:%u:\\001\\002:3600\n", bad_types[t]);

        zone_arena_t arena;
        zone_arena_init(&arena);
        parse_error_t err = {0};
        parse_context_t ctx = { .default_origin = "example.com.", .err_out = &err };

        int res = parse_tinydns_data(line, strlen(line), &arena, &ctx);
        TEST_ASSERT(res < 0, "Prohibited generic RR type rejected");
        zone_arena_destroy(&arena);
    }

    // 許可されるタイプ (例: 28 = AAAA, 33 = SRV)
    const char *good_line = ":ipv6.example.com:28:\\040\\001\\015\\270\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001:3600\n";
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .default_origin = "example.com.", .err_out = &err };

    char good_buf[256];
    strcpy(good_buf, good_line);
    int res = parse_tinydns_data(good_buf, strlen(good_buf), &arena, &ctx);
    TEST_ASSERT(res == 1, "Valid generic AAAA record accepted");
    if (res == 1) {
        TEST_ASSERT(arena.records[0].type_code == 28, "Type code 28");
        TEST_ASSERT(arena.records[0].generic_len == 16, "Generic len 16");
        TEST_ASSERT(arena.records[0].generic_data != NULL, "Generic data not null");
    }
    zone_arena_destroy(&arena);
}

/* ============================================================================
 * Test 5: 正引き・逆引き混在および親子ゾーンの振り分け検証
 * ============================================================================ */
static void test_zone_filtering_and_parent_child(void) {
    printf("--- Test 5: Zone Filtering and Parent-Child Delegation ---\n");

    const char *shared_data =
        ".example.com:192.168.1.1:a:259200\n"
        "+host.example.com:192.168.1.10:3600\n"
        "+host.sub.example.com:192.168.1.20:3600\n"
        "=revhost.example.com:192.168.1.50:3600\n"; // A + PTR (50.1.168.192.in-addr.arpa.)

    const char *all_zones[] = {
        "example.com.",
        "sub.example.com.",
        "1.168.192.in-addr.arpa."
    };
    int all_zones_count = 3;

    // 1. 親ゾーン example.com. のパース
    {
        char buf[1024]; strcpy(buf, shared_data);
        zone_arena_t arena; zone_arena_init(&arena);
        parse_error_t err = {0};
        parse_context_t ctx = {
            .default_origin = "example.com.",
            .all_zone_names = all_zones,
            .all_zone_count = all_zones_count,
            .err_out = &err
        };
        int count = parse_tinydns_data(buf, strlen(buf), &arena, &ctx);
        TEST_ASSERT(count > 0, "Parent zone parsed");

        bool has_host_example = false;
        bool has_sub_host = false;
        bool has_ptr = false;

        for (size_t i = 0; i < arena.count; i++) {
            if (strcmp(arena.records[i].name, "host.example.com.") == 0) has_host_example = true;
            if (strcmp(arena.records[i].name, "host.sub.example.com.") == 0) has_sub_host = true;
            if (arena.records[i].type_code == 12) has_ptr = true;
        }

        TEST_ASSERT(has_host_example, "Parent zone has host.example.com.");
        TEST_ASSERT(!has_sub_host, "Parent zone DOES NOT have host.sub.example.com. (delegated to child)");
        TEST_ASSERT(!has_ptr, "Parent zone DOES NOT have in-addr.arpa PTR");
        zone_arena_destroy(&arena);
    }

    // 2. 子ゾーン sub.example.com. のパース
    {
        char buf[1024]; strcpy(buf, shared_data);
        zone_arena_t arena; zone_arena_init(&arena);
        parse_error_t err = {0};
        parse_context_t ctx = {
            .default_origin = "sub.example.com.",
            .all_zone_names = all_zones,
            .all_zone_count = all_zones_count,
            .err_out = &err
        };
        int count = parse_tinydns_data(buf, strlen(buf), &arena, &ctx);
        TEST_ASSERT(count == 1, "Child zone parsed exactly 1 record");

        if (count == 1) {
            TEST_ASSERT(strcmp(arena.records[0].name, "host.sub.example.com.") == 0, "Child zone owns host.sub.example.com.");
        }
        zone_arena_destroy(&arena);
    }

    // 3. 逆引きゾーン 1.168.192.in-addr.arpa. のパース
    {
        char buf[1024]; strcpy(buf, shared_data);
        zone_arena_t arena; zone_arena_init(&arena);
        parse_error_t err = {0};
        parse_context_t ctx = {
            .default_origin = "1.168.192.in-addr.arpa.",
            .all_zone_names = all_zones,
            .all_zone_count = all_zones_count,
            .err_out = &err
        };
        int count = parse_tinydns_data(buf, strlen(buf), &arena, &ctx);
        TEST_ASSERT(count == 1, "Reverse zone parsed exactly 1 PTR record");

        if (count == 1) {
            TEST_ASSERT(strcmp(arena.records[0].name, "50.1.168.192.in-addr.arpa.") == 0, "Reverse PTR name matched");
            TEST_ASSERT(strcmp(arena.records[0].rdata[0], "revhost.example.com.") == 0, "Reverse PTR target matched");
        }
        zone_arena_destroy(&arena);
    }
}

/* ============================================================================
 * Test 6: 設定パーサー (file-format tinydns;) 検証
 * ============================================================================ */
static void test_config_file_format(void) {
    printf("--- Test 6: Config Parser file-format ---\n");

    const char *conf =
        "options { port 5353; };\n"
        "zone \"example.com\" {\n"
        "    type master;\n"
        "    file \"example.tinydns\";\n"
        "    file-format tinydns;\n"
        "};\n"
        "zone \"bind.example\" {\n"
        "    type master;\n"
        "    file \"bind.zone\";\n"
        "    file-format bind;\n"
        "};\n";

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    int res = parse_named_conf(conf, &cfg);
    TEST_ASSERT(res == 0, "Config parsed successfully");

    zone_config_t *z1 = cfg.views ? cfg.views->zones : cfg.zones;
    TEST_ASSERT(z1 != NULL, "Zone 1 exists");
    if (z1) {
        TEST_ASSERT(strcmp(z1->domain, "example.com.") == 0, "Zone 1 domain");
        TEST_ASSERT(z1->file_format != NULL && strcmp(z1->file_format, "tinydns") == 0, "Zone 1 file-format is tinydns");
        
        zone_config_t *z2 = z1->next;
        TEST_ASSERT(z2 != NULL, "Zone 2 exists");
        if (z2) {
            TEST_ASSERT(strcmp(z2->domain, "bind.example.") == 0, "Zone 2 domain");
            TEST_ASSERT(z2->file_format != NULL && strcmp(z2->file_format, "bind") == 0, "Zone 2 file-format is bind");
        }
    }

    free_server_config_fields(&cfg);
}

int main(void) {
    printf("==================================================\n");
    printf(" Running KariDNS tinydns Parser Tests (djbdns 1.05)\n");
    printf("==================================================\n");

    test_basic_records();
    test_txt_127_byte_chunking();
    test_loose_ip4_scan();
    test_generic_record_prohibited_types();
    test_zone_filtering_and_parent_child();
    test_config_file_format();

    printf("==================================================\n");
    printf(" Test Results: %d / %d Passed\n", pass_count, test_count);
    printf("==================================================\n");

    return (pass_count == test_count) ? 0 : 1;
}

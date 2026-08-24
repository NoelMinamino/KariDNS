#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "../../dns_config_parser.h"
#include "../../dns_zone_parser.h"

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// Mock main so we can include dns_server_core.c directly
// and test its internal static/non-static functions
#define main karidns_main
#include "../../dns_server_core.c"
#undef main

static void test_mqtype_truncation(void) {
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "example.com.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    char zone_text[] = "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n"
                       "example.com. 3600 IN NS ns1.example.com.\n"
                       "example.com. 3600 IN A 192.0.2.1\n"
                       "example.com. 3600 IN TXT \"this is a very long txt record to trigger buffer overflow during mqtype response assembly 1234567890 1234567890\"\n"
                       "example.com. 3600 IN TXT \"another very long txt record for overflow testing 1234567890 1234567890 1234567890 1234567890\"\n";
    if (parse_zone_fast(zone_text, strlen(zone_text), &arena, &ctx) < 0) {
        zone_arena_destroy(&arena);
        return;
    }
    build_zone_index(&arena);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain));
    atomic_store_explicit(&db_entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = { &db_entry };
    char *any_acl[1] = { (char *)"any" };

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 1;
    view.match_clients = any_acl;
    view.match_clients_count = 1;

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.rfc10029_mqtype_enable = true;
    cfg.max_mqtypes = 4;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    // Build Query: example.com. IN A + EDNS MQTYPE (TXT)
    uint8_t req[512] = {0};
    req[0] = 0xAB; req[1] = 0xCD; // ID
    req[2] = 0x01; req[3] = 0x00; // RD=1
    req[4] = 0x00; req[5] = 0x01; // QDCOUNT=1
    req[10] = 0x00; req[11] = 0x01; // ARCOUNT=1 (OPT)

    size_t off = 12;
    const char *qname = "\x07" "example" "\x03" "com" "\x00";
    memcpy(&req[off], qname, 13);
    off += 13;
    req[off++] = 0x00; req[off++] = 0x01; // TYPE A
    req[off++] = 0x00; req[off++] = 0x01; // CLASS IN

    // OPT RR with MQTYPE-Query (TXT = 16)
    req[off++] = 0x00; // Root name
    req[off++] = 0x00; req[off++] = 0x29; // TYPE OPT (41)
    req[off++] = 0x10; req[off++] = 0x00; // UDP payload 4096
    req[off++] = 0x00; req[off++] = 0x00; req[off++] = 0x00; req[off++] = 0x00; // Extended RCODE / Flags
    req[off++] = 0x00; req[off++] = 0x06; // RDLEN = 6
    req[off++] = 0x00; req[off++] = 0x14; // OptCode 20 (MQTYPE-Query)
    req[off++] = 0x00; req[off++] = 0x02; // OptLen 2
    req[off++] = 0x00; req[off++] = 0x10; // QTYPE TXT (16)

    compress_ctx_t comp_ctx;
    compress_ctx_init_packet(&comp_ctx);

    // Test with buffer large enough for A record (~70 bytes) but not for large TXT records (~250 bytes)
    uint8_t res[512] = {0};
    size_t small_res_len = 100;
    rate_limit_config_t *rrl = NULL;
    int res_len = process_dns_query(req, off, res, small_res_len, "example.com.", 1,
                                     "127.0.0.1", &comp_ctx, false, &rrl, &snap);

    if (res_len > 0) {
        uint8_t rcode = res[3] & 0x0F;
        bool tc_set = (res[2] & 0x02) != 0;
        uint16_t ancount = (res[6] << 8) | res[7];

        if (rcode == 5 /* REFUSED */) {
            abort();
        }

        // RFC 10029 §3.4: MQTYPE failure MUST NOT trigger TC bit
        if (tc_set) {
            abort();
        }
        if (ancount == 0) {
            abort();
        }
    }

    zone_arena_destroy(&arena);
}

static void test_mqtype_qdcount0_formerr(void) {
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.rfc10029_mqtype_enable = true;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    // Build QDCOUNT=0 query with EDNS MQTYPE-Query (option-code 20)
    uint8_t req[512] = {0};
    req[0] = 0x12; req[1] = 0x34; // ID
    req[2] = 0x00; req[3] = 0x00; // Opcode=0, QDCOUNT=0
    req[4] = 0x00; req[5] = 0x00; // QDCOUNT=0
    req[10] = 0x00; req[11] = 0x01; // ARCOUNT=1 (OPT)

    size_t off = 12;
    // OPT RR with MQTYPE-Query (TXT = 16)
    req[off++] = 0x00; // Root name
    req[off++] = 0x00; req[off++] = 0x29; // TYPE OPT (41)
    req[off++] = 0x10; req[off++] = 0x00; // UDP payload 4096
    req[off++] = 0x00; req[off++] = 0x00; req[off++] = 0x00; req[off++] = 0x00; // Extended RCODE / Flags
    req[off++] = 0x00; req[off++] = 0x06; // RDLEN = 6
    req[off++] = 0x00; req[off++] = 0x14; // OptCode 20 (MQTYPE-Query)
    req[off++] = 0x00; req[off++] = 0x02; // OptLen 2
    req[off++] = 0x00; req[off++] = 0x10; // QTYPE TXT (16)

    uint8_t res[512] = {0};
    compress_ctx_t comp_ctx;
    compress_ctx_init_packet(&comp_ctx);
    rate_limit_config_t *rrl = NULL;

    int res_len = process_dns_query(req, off, res, sizeof(res), "", 0,
                                    "127.0.0.1", &comp_ctx, false, &rrl, NULL);
    if (res_len < 12) {
        abort(); // Failed to respond
    }
    uint8_t rcode = res[3] & 0x0F;
    if (rcode != 1) { // FORMERR (1)
        abort(); // Expected FORMERR for QDCOUNT=0 with MQTYPE-Query (RFC 10029 §3.3)
    }
}

static void test_resolve_name_servfail_rcode_clearing(void) {
    // 1. Test empty / uninitialized zone arena
    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain));

    zone_arena_t *empty_zone = NULL;
    zone_db_entry_t *db_entry_ptr = &db_entry;
    zone_arena_t **zone_ptr = &empty_zone;

    uint8_t res[512] = {0};
    res[3] = 0x83; // Pre-set RCODE=3 (NXDOMAIN)
    uint16_t offset = 12, ancount = 0, nscount = 0, arcount = 0;
    compress_ctx_t comp_ctx;
    compress_ctx_init_packet(&comp_ctx);

    uint16_t qtype = 1;
    resolve_name("example.com.", &qtype, 1,
                 &db_entry_ptr, zone_ptr, res,
                 sizeof(res), &offset, &comp_ctx,
                 &ancount, &nscount, &arcount,
                 false, false, 0, false, NULL, NULL);
    if ((res[3] & 0x0F) != 2) {
        // Must be exactly SERVFAIL (2), not (3 | 2 = 3)
        abort();
    }

    // 2. Test CNAME loop / chain exhaustion (> 16 hops)
    zone_arena_t loop_arena;
    memset(&loop_arena, 0, sizeof(loop_arena));
    zone_arena_init(&loop_arena);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "example.com.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    char loop_zone[] = "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n"
                       "example.com. 3600 IN NS ns1.example.com.\n"
                       "loop.example.com. 3600 IN CNAME loop.example.com.\n";
    if (parse_zone_fast(loop_zone, strlen(loop_zone), &loop_arena, &ctx) < 0) {
        zone_arena_destroy(&loop_arena);
        abort();
    }
    build_zone_index(&loop_arena);

    zone_arena_t *current_zone = &loop_arena;
    zone_ptr = &current_zone;

    memset(res, 0, sizeof(res));
    res[3] = 0x83; // Pre-set RCODE=3 (NXDOMAIN)
    offset = 12; ancount = 0; nscount = 0; arcount = 0;
    compress_ctx_init_packet(&comp_ctx);

    resolve_name("loop.example.com.", &qtype, 1,
                 &db_entry_ptr, zone_ptr, res,
                 sizeof(res), &offset, &comp_ctx,
                 &ancount, &nscount, &arcount,
                 false, false, 0, false, NULL, NULL);
    if ((res[3] & 0x0F) != 2) {
        // Must be exactly SERVFAIL (2) on CNAME loop exhaustion
        zone_arena_destroy(&loop_arena);
        abort();
    }
    zone_arena_destroy(&loop_arena);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static bool mqtype_trunc_tested = false;
    if (!mqtype_trunc_tested) {
        test_mqtype_truncation();
        test_mqtype_qdcount0_formerr();
        test_resolve_name_servfail_rcode_clearing();
        mqtype_trunc_tested = true;
    }

    if (size == 0) return 0;

    // We use the first byte to decide WHICH function to fuzz.
    // This allows a single fuzzer target to test multiple entry points
    // which is a standard libFuzzer pattern.
    uint8_t selector = data[0];
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;

    if (fuzz_size == 0) return 0;

    // Create a null-terminated text buffer for parsing functions
    char *text_buf = malloc(fuzz_size + 1);
    if (!text_buf) return 0;
    memcpy(text_buf, fuzz_data, fuzz_size);
    text_buf[fuzz_size] = '\0';

    if (selector % 3 == 0) {
        // 1. Fuzz parse_named_conf (Config file parser)
        server_config_t config;
        memset(&config, 0, sizeof(config));
        parse_named_conf(text_buf, &config);

        // Free the allocations made by parse_named_conf
        free_server_config_fields(&config);
    } 
    else if (selector % 3 == 1) {
        // 2. Fuzz parse_zone_fast (Zone file parser)
        zone_arena_t arena;
        memset(&arena, 0, sizeof(arena));
        arena.records_cap = 1024;
        arena.records = calloc(arena.records_cap, sizeof(dns_record_t));

        parse_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.default_origin = "fuzz.local.";

        // The parser operates in place on buf, so text_buf is modified
        parse_zone_fast(text_buf, fuzz_size, &arena, &ctx);

        // Free arena memory
        zone_arena_destroy(&arena);
    }
    else {
        // 3. Fuzz parse_xfr_packet (AXFR packet parser)
        zone_arena_t standby;
        memset(&standby, 0, sizeof(standby));
        standby.records_cap = 1024;
        standby.records = calloc(standby.records_cap, sizeof(dns_record_t));

        zone_arena_t active;
        memset(&active, 0, sizeof(active));

        axfr_session_t session;
        memset(&session, 0, sizeof(session));

        // Use original data for packet parsing (binary, not text_buf)
        parse_xfr_packet(fuzz_data, fuzz_size, &standby, &active, &session, "fuzz.local.");

        // Free standby and active arenas
        zone_arena_destroy(&standby);
        zone_arena_destroy(&active);
    }

    free(text_buf);
    return 0; // Fuzzer must return 0
}

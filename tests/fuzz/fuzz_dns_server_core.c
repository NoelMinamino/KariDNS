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

static zone_arena_t g_fuzz_arena;
static zone_db_entry_t g_fuzz_entry;
static zone_db_entry_t *g_fuzz_entries[1];
static char *g_fuzz_any_acl[1] = { (char *)"any" };
static view_snapshot_t g_fuzz_view;
static zone_db_snapshot_t g_fuzz_snap;
static server_config_t g_fuzz_cfg;
static bool g_fuzz_initialized = false;

static void init_fuzz_environment(void) {
    if (g_fuzz_initialized) return;

    memset(&g_fuzz_arena, 0, sizeof(g_fuzz_arena));
    zone_arena_init(&g_fuzz_arena);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "fuzz.local.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    char zone_text[] = "fuzz.local. 3600 IN SOA ns1.fuzz.local. admin.fuzz.local. 1 3600 1800 604800 86400\n"
                       "fuzz.local. 3600 IN NS ns1.fuzz.local.\n"
                       "fuzz.local. 3600 IN A 192.0.2.1\n"
                       "fuzz.local. 3600 IN AAAA 2001:db8::1\n"
                       "fuzz.local. 3600 IN TXT \"fuzz sample text\"\n"
                       "cname.fuzz.local. 3600 IN CNAME fuzz.local.\n"
                       "sub.fuzz.local. 3600 IN A 192.0.2.2\n";
    parse_zone_fast(zone_text, strlen(zone_text), &g_fuzz_arena, &ctx);
    build_zone_index(&g_fuzz_arena, true);

    memset(&g_fuzz_entry, 0, sizeof(g_fuzz_entry));
    strncpy(g_fuzz_entry.domain, "fuzz.local.", sizeof(g_fuzz_entry.domain) - 1);
    atomic_store_explicit(&g_fuzz_entry.rcu.active, &g_fuzz_arena, memory_order_release);

    g_fuzz_entries[0] = &g_fuzz_entry;

    memset(&g_fuzz_view, 0, sizeof(g_fuzz_view));
    g_fuzz_view.name = "default";
    g_fuzz_view.entries = g_fuzz_entries;
    g_fuzz_view.zone_count = 1;
    g_fuzz_view.match_clients = g_fuzz_any_acl;
    g_fuzz_view.match_clients_count = 1;

    memset(&g_fuzz_snap, 0, sizeof(g_fuzz_snap));
    g_fuzz_snap.views = &g_fuzz_view;
    g_fuzz_snap.view_count = 1;

    memset(&g_fuzz_cfg, 0, sizeof(g_fuzz_cfg));
    g_fuzz_cfg.rfc10029_mqtype_enable = true;
    g_fuzz_cfg.max_mqtypes = 4;
    atomic_store_explicit(&g_config_db.active, &g_fuzz_cfg, memory_order_release);

    g_fuzz_initialized = true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    init_fuzz_environment();

    // Use the first byte to decide WHICH function to fuzz.
    uint8_t selector = data[0];
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;

    if (fuzz_size == 0) return 0;

    // Create a null-terminated text buffer for parsing functions
    char *text_buf = malloc(fuzz_size + 1);
    if (!text_buf) return 0;
    memcpy(text_buf, fuzz_data, fuzz_size);
    text_buf[fuzz_size] = '\0';

    uint8_t branch = selector % 4;

    if (branch == 0) {
        // 1. Fuzz parse_named_conf (Config file parser)
        server_config_t config;
        memset(&config, 0, sizeof(config));
        parse_named_conf(text_buf, &config);
        free_server_config_fields(&config);
    } 
    else if (branch == 1) {
        // 2. Fuzz parse_zone_fast (Zone file parser)
        zone_arena_t arena;
        memset(&arena, 0, sizeof(arena));
        arena.records_cap = 1024;
        arena.records = calloc(arena.records_cap, sizeof(dns_record_t));

        parse_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.default_origin = "fuzz.local.";

        parse_zone_fast(text_buf, fuzz_size, &arena, &ctx);
        zone_arena_destroy(&arena);
    }
    else if (branch == 2) {
        // 3. Fuzz parse_xfr_packet (AXFR packet parser)
        zone_arena_t standby;
        memset(&standby, 0, sizeof(standby));
        standby.records_cap = 1024;
        standby.records = calloc(standby.records_cap, sizeof(dns_record_t));

        zone_arena_t active;
        memset(&active, 0, sizeof(active));

        axfr_session_t session;
        memset(&session, 0, sizeof(session));

        parse_xfr_packet(fuzz_data, fuzz_size, &standby, &active, &session, "fuzz.local.");

        zone_arena_destroy(&standby);
        zone_arena_destroy(&active);
    }
    else {
        // 4. Fuzz process_dns_query (Core Query Engine hot-path resolution)
        uint8_t res[4096];
        compress_ctx_t comp_ctx;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);

        char qname[256] = "";
        uint16_t qtype = 0;
        uint16_t qclass = 1;
        size_t qend = 0;
        parse_query_question_fast(fuzz_data, fuzz_size, qname, sizeof(qname), &qtype, &qclass, &qend);

        rate_limit_config_t *rrl = NULL;
        bool is_tcp = (selector & 0x80) != 0;
        process_dns_query(fuzz_data, fuzz_size, res, sizeof(res), qname, qtype,
                          "127.0.0.1", &comp_ctx, is_tcp, &rrl, &g_fuzz_snap);
    }

    free(text_buf);
    return 0;
}

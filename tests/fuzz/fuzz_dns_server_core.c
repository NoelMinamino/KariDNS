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
    /* parse_zone_fast() のレコードはこのバッファを指し続けるので static にする */
    static char zone_text[] = "fuzz.local. 3600 IN SOA ns1.fuzz.local. admin.fuzz.local. 1 3600 1800 604800 86400\n"
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
    /* TSIG key "k" (hmac-sha256): requests signed with it reach the MAC check and the error responses (RFC 8945 §5.2) */
    static tsig_key_t fuzz_key;
    memset(&fuzz_key, 0, sizeof(fuzz_key));
    fuzz_key.name = "k";
    fuzz_key.algorithm = "hmac-sha256";
    fuzz_key.secret_decoded_len = 32;
    memset(fuzz_key.secret_decoded, 0x6b, 32);
    g_fuzz_cfg.keys = &fuzz_key;
    atomic_store_explicit(&g_config_db.active, &g_fuzz_cfg, memory_order_release);

    g_fuzz_initialized = true;
}

/* NSEC3 index (R-34): every chain is sorted in hash order and is the chain found for its own RRs */
static void check_nsec3_index(zone_arena_t *arena) {
    for (size_t c = 0; c < arena->nsec3_chain_count; c++) {
        const nsec3_chain_t *ch = &arena->nsec3_chains[c];
        for (size_t i = 0; i < ch->count; i++) {
            const nsec3_index_entry_t *e = &ch->entries[i];
            if (zone_find_nsec3_chain(arena, e->rec) != ch) abort();
            if (i > 0) {
                const nsec3_index_entry_t *p = &ch->entries[i - 1];
                size_t n = p->hash_len < e->hash_len ? p->hash_len : e->hash_len;
                int d = strncasecmp(p->hash, e->hash, n);
                if (d > 0 || (d == 0 && p->hash_len > e->hash_len)) abort();
            }
        }
    }
}

/* R-31: the NSEC3 parameters chosen by build_zone_index() are a usable NSEC3PARAM (Flags 0, SHA-1, decodable salt of
 * at most 255 octets) with its own chain, and the decoded salt is that of the record */
static void check_nsec3_active(zone_arena_t *arena) {
    const nsec3_params_t *p = &arena->nsec3_active;
    if (!p->param) return;
    uint8_t flags, salt[255];
    if (p->param->type_code != 51 || p->algorithm != 1 || p->param->rdata_count < 4) abort();
    if (!parse_u8(p->param->rdata[1], &flags) || flags != 0) abort();
    if (p->chain != zone_find_nsec3_chain(arena, p->param)) abort();
    size_t n = hex_to_bytes(p->param->rdata[3], salt, sizeof(salt));
    if (n == (size_t)-1 || n != p->salt_len || memcmp(salt, p->salt, n) != 0) abort();
}

/* Phase 9: DO=1 queries against the fuzzed zone (answer sections, RRSIG attachment, NSEC/NSEC3 proofs, glue),
 * with a 512-octet and a 4096-octet EDNS buffer, for the apex, a missing name and the first owners of the zone. */
static void query_fuzzed_zone(zone_arena_t *arena) {
    atomic_store_explicit(&g_fuzz_entry.rcu.active, arena, memory_order_release);
    static const uint16_t types[] = { 255, 1, 43, 48, 15, 2 };
    const char *names[6] = { "fuzz.local.", "nx.fuzz.local.", "a.b.fuzz.local.", NULL, NULL, NULL };
    uint16_t own_type[6] = { 6, 1, 1, 0, 0, 0 };
    for (size_t i = 0, k = 3; i < arena->count && k < 6; i++)
        if (arena->records[i].name) { own_type[k] = arena->records[i].type_code; names[k++] = arena->records[i].name; }
    for (int n = 0; n < 6 && names[n]; n++) {
        for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
            uint16_t qt = t == 1 ? own_type[n] : types[t];
            uint8_t req[300], res[4096];
            memset(req, 0, 12);
            req[5] = 1;   // QDCOUNT
            req[11] = 1;  // ARCOUNT (OPT)
            long w = write_uncompressed_name(req, 12, 12 + 255, names[n]);
            if (w <= 0) continue;
            size_t off = 12 + (size_t)w;
            req[off++] = (uint8_t)(qt >> 8); req[off++] = (uint8_t)qt; req[off++] = 0; req[off++] = 1;
            uint16_t udp = (t & 1) ? 512 : 4096;
            const uint8_t opt[11] = { 0, 0, 41, (uint8_t)(udp >> 8), (uint8_t)udp, 0, 0, 0x80, 0, 0, 0 };  // DO=1
            memcpy(req + off, opt, sizeof(opt));
            off += sizeof(opt);
            char qname[DNS_NAME_TEXT_SIZE] = "";
            uint16_t qtype = 0, qclass = 1;
            size_t qend = 0;
            parse_query_question_fast(req, off, qname, sizeof(qname), &qtype, &qclass, &qend);
            compress_ctx_t comp_ctx;
            memset(&comp_ctx, 0, sizeof(comp_ctx));
            compress_ctx_init_packet(&comp_ctx);
            rate_limit_config_t *rrl = NULL;
            process_dns_query(req, off, res, sizeof(res), qname, qtype, "127.0.0.1", &comp_ctx, false, &rrl,
                              &g_fuzz_snap);
        }
    }
    atomic_store_explicit(&g_fuzz_entry.rcu.active, &g_fuzz_arena, memory_order_release);
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

        if (parse_zone_fast(text_buf, fuzz_size, &arena, &ctx) >= 0 && build_zone_index(&arena, true) == 0) {
            check_nsec3_index(&arena);
            check_nsec3_active(&arena);
            query_fuzzed_zone(&arena);
        }
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

        /* R-33: transferred NSEC3 RRs get text fields and enter the index like file-loaded ones */
        if (parse_xfr_packet(fuzz_data, fuzz_size, &standby, &active, &session, "fuzz.local.") == 0 &&
            build_zone_index(&standby, true) == 0)
            check_nsec3_index(&standby);

        zone_arena_destroy(&standby);
        zone_arena_destroy(&active);
    }
    else {
        // 4. Fuzz process_dns_query (Core Query Engine hot-path resolution)
        uint8_t res[4096];
        compress_ctx_t comp_ctx;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);

        char qname[DNS_NAME_TEXT_SIZE] = "";
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

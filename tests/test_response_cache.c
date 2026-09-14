#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_query_engine.h"
#include "dns_server_internal.h"

int g_control_kq = -1;
int g_notify_ipc[2] = {-1, -1};
int g_broker_sock = -1;
config_rcu_t g_config_db;
_Atomic int g_xfers_running = 0;
int g_worker_count = 0;
worker_ctx_t *g_worker_ctxs = NULL;
int g_cwd_fd = -1;
char g_startup_cwd[PATH_MAX] = "";

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

server_config_t *acquire_config_snapshot(void) { return NULL; }
void release_config_snapshot(server_config_t *snap) { (void)snap; }

int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len) {
    (void)family; (void)type; (void)addr; (void)addr_len; return -1;
}

ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len) {
    (void)fd; (void)buf; return len;
}

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out) {
    (void)fd; (void)ctx; (void)msg_out; (void)msg_len_out; return -1;
}

void submit_response_log(log_action_t action, const char *client_ip, int client_port,
                        const char *qname, uint16_t qclass, uint16_t qtype,
                        uint8_t rcode, bool has_edns, bool dnssec_ok) {
    (void)action; (void)client_ip; (void)client_port; (void)qname;
    (void)qclass; (void)qtype; (void)rcode; (void)has_edns; (void)dnssec_ok;
}

void dec_tcp_clients(void) {}
void inc_tcp_clients(void) {}

size_t resolve_ip_port_to_sockaddr(const char *ip, int port, struct sockaddr_storage *out) {
    (void)ip; (void)port; (void)out; return 0;
}

static void build_simple_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype) {
    memset(buf, 0, 512);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; // RD=1
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = 0;

    long wlen = write_uncompressed_name(buf, 12, 512, qname);
    assert(wlen > 0);
    size_t off = 12 + wlen;
    buf[off++] = (uint8_t)(qtype >> 8);
    buf[off++] = (uint8_t)(qtype & 0xFF);
    buf[off++] = 0x00;
    buf[off++] = 0x01; // IN class
    *out_len = off;
}

static void build_edns_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, bool dnssec_ok) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = dnssec_ok ? 0x80 : 0x00; // DO bit
    buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00; // RDLEN=0
    *out_len = off;
}

static void test_wire_cache_consistency(void) {
    printf("[TEST] Running wire cache byte-for-byte consistency test...\n");

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

    const char zone_text[] =
        "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026091401 7200 3600 1209600 3600\n"
        "example.com. 3600 IN NS ns1.example.com.\n"
        "example.com. 3600 IN NS ns2.example.com.\n"
        "example.com. 3600 IN MX 10 mail.example.com.\n"
        "example.com. 3600 IN TXT \"v=spf1 include:_spf.example.com ~all\"\n"
        "example.com. 3600 IN CAA 0 issue \"letsencrypt.org\"\n"
        "ns1.example.com. 3600 IN A 192.0.2.1\n"
        "ns2.example.com. 3600 IN AAAA 2001:db8::2\n"
        "mail.example.com. 3600 IN A 192.0.2.10\n"
        "mail.example.com. 3600 IN AAAA 2001:db8::10\n"
        "_sip._tcp.example.com. 3600 IN SRV 10 60 5060 bigbox.example.com.\n"
        "bigbox.example.com. 3600 IN A 192.0.2.20\n"
        "www.example.com. 3600 IN CNAME mail.example.com.\n"
        "*.wildcard.example.com. 3600 IN A 192.0.2.50\n"
        "1.2.0.192.in-addr.arpa. 3600 IN PTR ns1.example.com.\n";

    int parsed = parse_zone_fast((char *)zone_text, strlen(zone_text), &arena, &ctx);
    assert(parsed >= 0);
    assert(build_zone_index(&arena, true) == 0);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    build_zone_response_cache(&arena, &cfg, "example.com.");
    assert(arena.response_cache.bucket_count > 0);
    assert(arena.response_cache.entry_count > 0);
    printf("       Pre-rendered %zu response cache entries.\n", arena.response_cache.entry_count);

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

    struct {
        const char *qname;
        uint16_t qtype;
        const char *desc;
    } test_cases[] = {
        { "example.com.", 6, "SOA" },
        { "example.com.", 2, "NS" },
        { "example.com.", 15, "MX" },
        { "example.com.", 16, "TXT" },
        { "example.com.", 257, "CAA" },
        { "ns1.example.com.", 1, "A (apex NS glue)" },
        { "ns2.example.com.", 28, "AAAA (apex NS glue)" },
        { "mail.example.com.", 1, "A (MX target)" },
        { "mail.example.com.", 28, "AAAA (MX target)" },
        { "_sip._tcp.example.com.", 33, "SRV" },
        { "bigbox.example.com.", 1, "A" },
        { "www.example.com.", 1, "CNAME chasing to A" },
        { "1.2.0.192.in-addr.arpa.", 12, "PTR" },
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        uint8_t req[512], res_cached[4096], res_uncached[4096];
        size_t req_len = 0;
        build_simple_query(req, &req_len, (uint16_t)(0x1234 + i), test_cases[i].qname, test_cases[i].qtype);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);

        // 1. Cached run
        zone_db_entry_t *matched1 = NULL;
        int len_cached = process_dns_query_impl(req, req_len, res_cached, sizeof(res_cached),
                                               test_cases[i].qname, test_cases[i].qtype,
                                               "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len_cached > 0);

        // 2. Uncached run (temporarily clear buckets pointer)
        response_cache_entry_t **saved_buckets = arena.response_cache.buckets;
        arena.response_cache.buckets = NULL;

        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                 test_cases[i].qname, test_cases[i].qtype,
                                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len_uncached > 0);

        // Restore buckets pointer
        arena.response_cache.buckets = saved_buckets;

        // Byte-for-byte comparison
        assert(len_cached == len_uncached);
        assert(memcmp(res_cached, res_uncached, len_cached) == 0);

        if (strcmp(test_cases[i].qname, "example.com.") == 0 && test_cases[i].qtype == 6) {
            uint16_t ans_ptr = ((uint16_t)res_cached[req_len] << 8) | res_cached[req_len + 1];
            assert(ans_ptr == 0xC00C);
        }

        printf("  [PASS] %s (%s) matches uncached response byte-for-byte (length=%d bytes)\n",
               test_cases[i].qname, test_cases[i].desc, len_cached);
    }

    // Test 0x20 casing preservation
    {
        uint8_t req[512], res_cached[4096], res_uncached[4096];
        size_t req_len = 0;
        const char *mixed_qname = "MaIl.ExAmPlE.cOm.";
        build_simple_query(req, &req_len, 0x5678, mixed_qname, 1);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len_cached = process_dns_query_impl(req, req_len, res_cached, sizeof(res_cached),
                                               mixed_qname, 1,
                                               "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len_cached > 0);

        response_cache_entry_t **saved_buckets = arena.response_cache.buckets;
        arena.response_cache.buckets = NULL;
        compress_ctx_init_packet(&comp_ctx);
        int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                 mixed_qname, 1,
                                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        arena.response_cache.buckets = saved_buckets;

        assert(len_cached == len_uncached);
        assert(memcmp(res_cached, res_uncached, len_cached) == 0);
        printf("  [PASS] 0x20 mixed casing '%s' preserved and byte-identical\n", mixed_qname);
    }

    // Test Fallbacks
    // A. EDNS query fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_query(req, &req_len, 0x9999, "mail.example.com.", 1, false);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint16_t arcount = ((uint16_t)res[10] << 8) | res[11];
        assert(arcount >= 1); // OPT record present in additional section
        printf("  [PASS] EDNS query bypassed cache and assembled OPT record\n");
    }

    // B. Wildcard query fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_simple_query(req, &req_len, 0x9998, "sub.wildcard.example.com.", 1);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "sub.wildcard.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        uint16_t ancount = ((uint16_t)res[6] << 8) | res[7];
        assert(rcode == 0);
        assert(ancount == 1);
        printf("  [PASS] Wildcard query synthesized answer via dynamic fallback\n");
    }

    // C. NXDOMAIN query fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_simple_query(req, &req_len, 0x9997, "nonexistent.example.com.", 1);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "nonexistent.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        assert(rcode == 3); // NXDOMAIN
        printf("  [PASS] NXDOMAIN query returned RCODE 3 via dynamic fallback\n");
    }

    // D. NODATA query fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_simple_query(req, &req_len, 0x9996, "mail.example.com.", 16 /* TXT */);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 16,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        uint16_t ancount = ((uint16_t)res[6] << 8) | res[7];
        assert(rcode == 0); // NOERROR
        assert(ancount == 0); // NODATA
        printf("  [PASS] NODATA query returned NOERROR with ANCOUNT=0 via dynamic fallback\n");
    }

    zone_arena_destroy(&arena);
    printf("[SUCCESS] All wire cache tests passed!\n");
}

int main(void) {
    test_wire_cache_consistency();
    return 0;
}

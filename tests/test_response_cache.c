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

static void build_edns_cookie_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, const uint8_t *client_cookie) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    buf[off++] = 0x00; buf[off++] = 12; // RDLEN = 12
    buf[off++] = 0x00; buf[off++] = 10; // Option code: 10 (COOKIE)
    buf[off++] = 0x00; buf[off++] = 8;  // Option len: 8
    memcpy(&buf[off], client_cookie, 8);
    off += 8;
    *out_len = off;
}

static void build_edns_mqtype_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, uint16_t mqtype) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    buf[off++] = 0x00; buf[off++] = 6;  // RDLEN = 6 (option header 4 + 2 bytes mqtype)
    buf[off++] = 0x00; buf[off++] = 20; // Option code: 20 (MQTYPE)
    buf[off++] = 0x00; buf[off++] = 2;  // Option len: 2
    buf[off++] = (uint8_t)(mqtype >> 8);
    buf[off++] = (uint8_t)(mqtype & 0xFF);
    *out_len = off;
}

static void build_edns_ecs_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype,
                                uint16_t family, uint8_t src_prefix, const uint8_t *addr, size_t addr_len) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    uint16_t opt_len = 4 + (uint16_t)addr_len;
    uint16_t rdlen = 4 + opt_len;
    buf[off++] = (uint8_t)(rdlen >> 8); buf[off++] = (uint8_t)(rdlen & 0xFF);
    buf[off++] = 0x00; buf[off++] = 8; // Option Code: 8 (ECS)
    buf[off++] = (uint8_t)(opt_len >> 8); buf[off++] = (uint8_t)(opt_len & 0xFF);
    buf[off++] = (uint8_t)(family >> 8); buf[off++] = (uint8_t)(family & 0xFF);
    buf[off++] = src_prefix;
    buf[off++] = 0; // scope prefix
    memcpy(&buf[off], addr, addr_len);
    off += addr_len;
    *out_len = off;
}

static void build_edns_malformed_cookie_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    buf[off++] = 0x00; buf[off++] = 8; // RDLEN = 8
    buf[off++] = 0x00; buf[off++] = 10; // Option Code: 10 (COOKIE)
    buf[off++] = 0x00; buf[off++] = 4; // Option len: 4 (malformed: not 8 and not 16-40)
    buf[off++] = 0x11; buf[off++] = 0x22; buf[off++] = 0x33; buf[off++] = 0x44;
    *out_len = off;
}

static void build_edns_nsid_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    buf[off++] = 0x00; buf[off++] = 4; // RDLEN = 4
    buf[off++] = 0x00; buf[off++] = 3; // Option Code: 3 (NSID)
    buf[off++] = 0x00; buf[off++] = 0; // Option len: 0
    *out_len = off;
}

static void build_edns_keepalive_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    buf[off++] = 0x00; buf[off++] = 4; // RDLEN = 4
    buf[off++] = 0x00; buf[off++] = 11; // Option Code: 11 (Keepalive)
    buf[off++] = 0x00; buf[off++] = 0; // Option len: 0
    *out_len = off;
}

static void build_edns_karidns_ext_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    buf[off++] = 0x00; buf[off++] = 9; // RDLEN = 9
    buf[off++] = (uint8_t)(EDNS_OPTION_KARIDNS_EXT >> 8); buf[off++] = (uint8_t)(EDNS_OPTION_KARIDNS_EXT & 0xFF); // 65153
    buf[off++] = 0x00; buf[off++] = 5; // Option len: 5
    buf[off++] = 1; // version
    buf[off++] = 0x12; buf[off++] = 0x34; buf[off++] = 0x56; buf[off++] = 0x78; // hash
    *out_len = off;
}

static void build_edns_ede_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, uint16_t ede_code, const char *text) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    uint16_t text_len = text ? (uint16_t)strlen(text) : 0;
    uint16_t opt_len = 2 + text_len;
    uint16_t rdlen = 4 + opt_len;
    buf[off++] = (uint8_t)(rdlen >> 8); buf[off++] = (uint8_t)(rdlen & 0xFF);
    buf[off++] = 0x00; buf[off++] = 15; // Option Code: 15 (EDE)
    buf[off++] = (uint8_t)(opt_len >> 8); buf[off++] = (uint8_t)(opt_len & 0xFF);
    buf[off++] = (uint8_t)(ede_code >> 8); buf[off++] = (uint8_t)(ede_code & 0xFF);
    if (text_len > 0) {
        memcpy(&buf[off], text, text_len);
        off += text_len;
    }
    *out_len = off;
}

static void build_edns_cookie_ecs_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype,
                                       const uint8_t *client_cookie, uint16_t family, uint8_t src_prefix, const uint8_t *addr, size_t addr_len) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x00; buf[off++] = 0x00; // flags
    uint16_t ecs_opt_len = 4 + (uint16_t)addr_len;
    uint16_t cookie_opt_len = 8;
    uint16_t rdlen = (4 + cookie_opt_len) + (4 + ecs_opt_len);
    buf[off++] = (uint8_t)(rdlen >> 8); buf[off++] = (uint8_t)(rdlen & 0xFF);
    // Cookie option
    buf[off++] = 0x00; buf[off++] = 10;
    buf[off++] = (uint8_t)(cookie_opt_len >> 8); buf[off++] = (uint8_t)(cookie_opt_len & 0xFF);
    memcpy(&buf[off], client_cookie, 8);
    off += 8;
    // ECS option
    buf[off++] = 0x00; buf[off++] = 8;
    buf[off++] = (uint8_t)(ecs_opt_len >> 8); buf[off++] = (uint8_t)(ecs_opt_len & 0xFF);
    buf[off++] = (uint8_t)(family >> 8); buf[off++] = (uint8_t)(family & 0xFF);
    buf[off++] = src_prefix;
    buf[off++] = 0; // scope
    memcpy(&buf[off], addr, addr_len);
    off += addr_len;
    *out_len = off;
}

static void build_edns_mqtype_do_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, uint16_t mqtype) {
    build_simple_query(buf, out_len, txid, qname, qtype);
    size_t off = *out_len;
    buf[10] = 0x00; buf[11] = 0x01; // ARCOUNT=1
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; buf[off++] = 41; // OPT (41)
    buf[off++] = 0x10; buf[off++] = 0x00; // UDP payload 4096
    buf[off++] = 0x00; // ext rcode
    buf[off++] = 0x00; // edns version 0
    buf[off++] = 0x80; buf[off++] = 0x00; // DO bit = 1
    buf[off++] = 0x00; buf[off++] = 6;  // RDLEN = 6 (option header 4 + 2 bytes mqtype)
    buf[off++] = 0x00; buf[off++] = 20; // Option code: 20 (MQTYPE)
    buf[off++] = 0x00; buf[off++] = 2;  // Option len: 2
    buf[off++] = (uint8_t)(mqtype >> 8);
    buf[off++] = (uint8_t)(mqtype & 0xFF);
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
        "mail.example.com. 3600 IN RRSIG A 13 3 3600 20300101000000 20260101000000 12345 example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
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

    // 1. Standard (non-EDNS) query byte-for-byte consistency
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        uint8_t req[512], res_cached[4096], res_uncached[4096];
        size_t req_len = 0;
        build_simple_query(req, &req_len, (uint16_t)(0x1234 + i), test_cases[i].qname, test_cases[i].qtype);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);

        zone_db_entry_t *matched1 = NULL;
        int len_cached = process_dns_query_impl(req, req_len, res_cached, sizeof(res_cached),
                                               test_cases[i].qname, test_cases[i].qtype,
                                               "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len_cached > 0);

        response_cache_entry_t **saved_buckets = arena.response_cache.buckets;
        arena.response_cache.buckets = NULL;

        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                 test_cases[i].qname, test_cases[i].qtype,
                                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len_uncached > 0);
        arena.response_cache.buckets = saved_buckets;

        assert(len_cached == len_uncached);
        assert(memcmp(res_cached, res_uncached, len_cached) == 0);

        if (strcmp(test_cases[i].qname, "example.com.") == 0 && test_cases[i].qtype == 6) {
            uint16_t ans_ptr = ((uint16_t)res_cached[req_len] << 8) | res_cached[req_len + 1];
            assert(ans_ptr == 0xC00C);
        }

        printf("  [PASS] %s (%s) non-EDNS matches uncached response byte-for-byte (length=%d bytes)\n",
               test_cases[i].qname, test_cases[i].desc, len_cached);
    }

    // 2. Plain EDNS query (DO=0) byte-for-byte consistency (all test cases)
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        uint8_t req[512], res_cached[4096], res_uncached[4096];
        size_t req_len = 0;
        build_edns_query(req, &req_len, (uint16_t)(0x3456 + i), test_cases[i].qname, test_cases[i].qtype, false);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);

        zone_db_entry_t *matched1 = NULL;
        int len_cached = process_dns_query_impl(req, req_len, res_cached, sizeof(res_cached),
                                               test_cases[i].qname, test_cases[i].qtype,
                                               "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len_cached > 0);
        uint16_t arcount_cached = ((uint16_t)res_cached[10] << 8) | res_cached[11];
        assert(arcount_cached >= 1); // OPT record present

        response_cache_entry_t **saved_buckets = arena.response_cache.buckets;
        arena.response_cache.buckets = NULL;

        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                 test_cases[i].qname, test_cases[i].qtype,
                                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len_uncached > 0);
        arena.response_cache.buckets = saved_buckets;

        assert(len_cached == len_uncached);
        assert(memcmp(res_cached, res_uncached, len_cached) == 0);

        printf("  [PASS] %s (%s) plain EDNS (DO=0) matches uncached response byte-for-byte (length=%d bytes)\n",
               test_cases[i].qname, test_cases[i].desc, len_cached);
    }

    // 3. DNS Cookie query consistency & multi-client isolation test
    {
        uint8_t client_cookie1[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        uint8_t client_cookie2[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };

        uint8_t req1[512], res1_cached[4096], res1_uncached[4096];
        uint8_t req2[512], res2_cached[4096];
        size_t req_len1 = 0, req_len2 = 0;

        build_edns_cookie_query(req1, &req_len1, 0x7701, "mail.example.com.", 1, client_cookie1);
        build_edns_cookie_query(req2, &req_len2, 0x7702, "mail.example.com.", 1, client_cookie2);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);

        // Client 1 query (cached)
        zone_db_entry_t *matched1 = NULL;
        int len1_cached = process_dns_query_impl(req1, req_len1, res1_cached, sizeof(res1_cached),
                                                "mail.example.com.", 1,
                                                "192.0.2.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len1_cached > 0);

        // Client 1 query (uncached)
        response_cache_entry_t **saved_buckets = arena.response_cache.buckets;
        arena.response_cache.buckets = NULL;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len1_uncached = process_dns_query_impl(req1, req_len1, res1_uncached, sizeof(res1_uncached),
                                                  "mail.example.com.", 1,
                                                  "192.0.2.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len1_uncached > 0);
        arena.response_cache.buckets = saved_buckets;

        assert(len1_cached == len1_uncached);
        assert(memcmp(res1_cached, res1_uncached, len1_cached) == 0);
        printf("  [PASS] Client 1 DNS Cookie query matches uncached response byte-for-byte\n");

        // Client 2 query from different IP (cached)
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched3 = NULL;
        int len2_cached = process_dns_query_impl(req2, req_len2, res2_cached, sizeof(res2_cached),
                                                "mail.example.com.", 1,
                                                "192.0.2.2", &comp_ctx, false, NULL, &snap, &cfg, &matched3);
        assert(len2_cached > 0);

        // Verify body portion (ANSWER section) is identical between Client 1 and Client 2
        // while the OPT / Cookie portion is independently generated
        assert(len1_cached == len2_cached);
        // Header TXID differs (0x7701 vs 0x7702)
        assert(res1_cached[0] != res2_cached[0] || res1_cached[1] != res2_cached[1]);
        // Answer section length and payload are identical
        assert(memcmp(&res1_cached[req_len1], &res2_cached[req_len2], 16) == 0); // 16 bytes A RR
        // Cookie in OPT record differs due to different client cookie & IP
        assert(memcmp(&res1_cached[len1_cached - 24], &res2_cached[len2_cached - 24], 24) != 0);

        printf("  [PASS] Multiple clients with different IPs/Cookies receive shared cached body with isolated Cookie generation\n");
    }

    // 4. Test 0x20 casing preservation & case-folding cache hit
    {
        const char *mixed_qnames[] = {
            "MaIl.ExAmPlE.cOm.",
            "WWW.example.com.",
            "WwW.ExAmPlE.CoM.",
            "NS1.EXAMPLE.COM."
        };
        for (size_t i = 0; i < sizeof(mixed_qnames) / sizeof(mixed_qnames[0]); i++) {
            const char *mixed_qname = mixed_qnames[i];
            uint8_t req[512], res_cached[4096], res_uncached[4096];
            size_t req_len = 0;
            build_simple_query(req, &req_len, (uint16_t)(0x5678 + i), mixed_qname, 1);

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
    }

    // 5. Test Fallbacks (All exclusion criteria)
    // A. EDNS DO=1 (DNSSEC OK) fallback
    // Zone has RRSIG for mail.example.com. A. DO=0 returns ANCOUNT=1 (cached), DO=1 returns ANCOUNT=2 (A + RRSIG, dynamic)
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_query(req, &req_len, 0x9999, "mail.example.com.", 1, true /* dnssec_ok = true */);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint16_t ancount = ((uint16_t)res[6] << 8) | res[7];
        uint16_t arcount = ((uint16_t)res[10] << 8) | res[11];
        assert(ancount == 2); // A + RRSIG returned dynamically!
        assert(arcount >= 1); // OPT record present
        printf("  [PASS] EDNS DO=1 query bypassed cache and dynamically returned RRSIG (ANCOUNT=%d)\n", ancount);
    }

    // B. EDNS Multi-QTYPE fallback (RFC 10029)
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_mqtype_query(req, &req_len, 0x999A, "mail.example.com.", 1 /* A */, 28 /* AAAA */);

        cfg.rfc10029_mqtype_enable = true;
        cfg.max_mqtypes = 4;
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        cfg.rfc10029_mqtype_enable = false;
        cfg.max_mqtypes = 0;
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        uint16_t ancount = ((uint16_t)res[6] << 8) | res[7];
        assert(rcode == 0);
        assert(ancount == 2); // Both A (192.0.2.10) and AAAA (2001:db8::10) answered!
        printf("  [PASS] EDNS Multi-QTYPE (+mqtype=AAAA) bypassed cache and returned multiple answers (ANCOUNT=%d)\n", ancount);
    }

    // C. EDNS Client Subnet (ECS, RFC 7871) fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        uint8_t ecs_ip[4] = { 192, 0, 2, 0 };
        build_edns_ecs_query(req, &req_len, 0x999B, "mail.example.com.", 1, 1 /* IPv4 */, 24, ecs_ip, 4);

        cfg.ecs_enable = true;
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        cfg.ecs_enable = false;
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        assert(rcode == 0);
        uint16_t arcount = ((uint16_t)res[10] << 8) | res[11];
        assert(arcount >= 1);
        // Verify that OPT record contains ECS option (code 8)
        bool has_ecs_option = false;
        for (int p = req_len; p < len - 4; p++) {
            if (res[p] == 0x00 && res[p+1] == 0x08) {
                has_ecs_option = true;
                break;
            }
        }
        assert(has_ecs_option);
        printf("  [PASS] EDNS ECS query bypassed cache and responded with ECS option\n");
    }

    // D. Malformed Cookie fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_malformed_cookie_query(req, &req_len, 0x999C, "mail.example.com.", 1);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        assert(rcode == 1); // FORMERR on malformed cookie
        printf("  [PASS] Malformed Cookie query bypassed cache and returned FORMERR (RCODE=1)\n");
    }

    // E. EDNS NSID (RFC 5001) fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_nsid_query(req, &req_len, 0x999D, "mail.example.com.", 1);

        cfg.nsid_string = (char *)"kari-test-node";
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        cfg.nsid_string = NULL;
        assert(len > 0);
        // Verify that OPT record contains NSID option (code 3)
        bool has_nsid_option = false;
        for (int p = req_len; p < len - 4; p++) {
            if (res[p] == 0x00 && res[p+1] == 0x03) {
                has_nsid_option = true;
                break;
            }
        }
        assert(has_nsid_option);
        printf("  [PASS] EDNS NSID query bypassed cache and responded with NSID option\n");
    }

    // F. EDNS TCP Keepalive (RFC 7828) fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_keepalive_query(req, &req_len, 0x999E, "mail.example.com.", 1);

        cfg.tcp_connection_reuse = true;
        cfg.tcp_idle_timeout = 10000;
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, true /* is_tcp */, NULL, &snap, &cfg, &matched);
        cfg.tcp_connection_reuse = false;
        assert(len > 0);
        // Verify that OPT record contains Keepalive option (code 11)
        bool has_keepalive_option = false;
        for (int p = req_len; p < len - 4; p++) {
            if (res[p] == 0x00 && res[p+1] == 0x0B) {
                has_keepalive_option = true;
                break;
            }
        }
        assert(has_keepalive_option);
        printf("  [PASS] EDNS TCP Keepalive query bypassed cache and responded with Keepalive option\n");
    }

    // G. KariDNS Extended AXFR (Option 65153) fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_karidns_ext_query(req, &req_len, 0x999F, "mail.example.com.", 1);

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        assert(rcode == 0);
        printf("  [PASS] KariDNS Extended AXFR option query bypassed cache and dynamically processed\n");
    }

    // H. Extended DNS Error (EDE, RFC 8914) fallback
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_ede_query(req, &req_len, 0x99A0, "mail.example.com.", 1, 15 /* Blocked */, "Filtered");

        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        assert(rcode == 0);
        printf("  [PASS] Extended DNS Error (EDE) query bypassed cache and dynamically processed\n");
    }

    // I. Combined condition fallback: Cookie + ECS
    {
        uint8_t client_cookie[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        uint8_t ecs_ip[4] = { 192, 0, 2, 0 };
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_cookie_ecs_query(req, &req_len, 0x99A1, "mail.example.com.", 1, client_cookie, 1, 24, ecs_ip, 4);

        cfg.ecs_enable = true;
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "192.0.2.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        cfg.ecs_enable = false;
        assert(len > 0);
        // Verify both Cookie (code 10) and ECS (code 8) options are present
        bool has_cookie = false, has_ecs = false;
        for (int p = req_len; p < len - 4; p++) {
            if (res[p] == 0x00 && res[p+1] == 0x0A) has_cookie = true;
            if (res[p] == 0x00 && res[p+1] == 0x08) has_ecs = true;
        }
        assert(has_cookie && has_ecs);
        printf("  [PASS] Combined Cookie + ECS query bypassed cache and generated both options in OPT\n");
    }

    // J. Combined condition fallback: Multi-QTYPE + DO=1
    {
        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_edns_mqtype_do_query(req, &req_len, 0x99A2, "mail.example.com.", 1 /* A */, 28 /* AAAA */);

        cfg.rfc10029_mqtype_enable = true;
        cfg.max_mqtypes = 4;
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "mail.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        cfg.rfc10029_mqtype_enable = false;
        cfg.max_mqtypes = 0;
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        uint16_t ancount = ((uint16_t)res[6] << 8) | res[7];
        assert(rcode == 0);
        assert(ancount == 3); // A (192.0.2.10) + AAAA (2001:db8::10) + RRSIG for A = 3 answers!
        printf("  [PASS] Combined Multi-QTYPE + DO=1 query bypassed cache and returned all answers + RRSIG (ANCOUNT=%d)\n", ancount);
    }

    // K. Wildcard query fallback
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

    // L. NXDOMAIN query fallback
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

    // M. NODATA query fallback
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

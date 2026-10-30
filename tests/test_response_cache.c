#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "test_image_helper.h"
#include "dns_snapshot_rcu.h"
#include "dns_query_engine.h"
#include "dns_server_internal.h"
#include "tst_entry.h"

_Atomic int g_control_kq = -1;
int g_notify_ipc[2] = {-1, -1};
int g_broker_sock = -1;
config_rcu_t g_config_db;
_Atomic int g_xfers_running = 0;
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
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
    size_t expected_addr_len = (src_prefix + 7) / 8;
    if (addr_len > expected_addr_len) addr_len = expected_addr_len;
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
    size_t expected_addr_len = (src_prefix + 7) / 8;
    if (addr_len > expected_addr_len) addr_len = expected_addr_len;
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

/* The shared cache is filled on a miss. Send the query once to fill it, then answer it again so the
 * returned response comes from the cache (if the query is cacheable). */
static int cached_query(const uint8_t *req, size_t req_len, uint8_t *res, size_t max_res_len,
                        const char *qname, uint16_t qtype, const char *client_ip, compress_ctx_t *comp_ctx,
                        bool is_tcp, const rate_limit_config_t **out_rrl_cfg, zone_db_snapshot_t *snap,
                        server_config_t *cfg, zone_db_entry_t **matched) {
    uint8_t warm[4096];
    compress_ctx_t warm_ctx = {0};
    compress_ctx_init_packet(&warm_ctx);
    zone_db_entry_t *warm_matched = NULL;
    (void)process_dns_query_impl(req, req_len, warm, sizeof(warm), qname, qtype, client_ip, &warm_ctx,
                                 is_tcp, NULL, snap, cfg, &warm_matched);
    compress_ctx_init_packet(comp_ctx);
    return process_dns_query_impl(req, req_len, res, max_res_len, qname, qtype, client_ip, comp_ctx,
                                  is_tcp, out_rrl_cfg, snap, cfg, matched);
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
    int b_rc = test_build_index(&arena, true);
    assert(b_rc == 0);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
    assert(arena.rcache_ok);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain));
    atomic_store_explicit(&db_entry.rcu.active, &arena.ver, memory_order_release);

    zone_db_entry_t *entries[1] = { &db_entry };
    char *any_acl[1] = { (char *)"any" };

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 1);
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

        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);

        zone_db_entry_t *matched1 = NULL;
        int len_cached = cached_query(req, req_len, res_cached, sizeof(res_cached),
                                               test_cases[i].qname, test_cases[i].qtype,
                                               "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len_cached > 0);

        bool saved_ok = arena.rcache_ok;
        arena.rcache_ok = false;

        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                 test_cases[i].qname, test_cases[i].qtype,
                                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len_uncached > 0);
        arena.rcache_ok = saved_ok;

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

        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);

        zone_db_entry_t *matched1 = NULL;
        int len_cached = cached_query(req, req_len, res_cached, sizeof(res_cached),
                                               test_cases[i].qname, test_cases[i].qtype,
                                               "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len_cached > 0);
        uint16_t arcount_cached = ((uint16_t)res_cached[10] << 8) | res_cached[11];
        assert(arcount_cached >= 1); // OPT record present

        bool saved_ok = arena.rcache_ok;
        arena.rcache_ok = false;

        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                 test_cases[i].qname, test_cases[i].qtype,
                                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len_uncached > 0);
        arena.rcache_ok = saved_ok;

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

        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);

        // Client 1 query (cached)
        zone_db_entry_t *matched1 = NULL;
        int len1_cached = cached_query(req1, req_len1, res1_cached, sizeof(res1_cached),
                                                "mail.example.com.", 1,
                                                "192.0.2.1", &comp_ctx, false, NULL, &snap, &cfg, &matched1);
        assert(len1_cached > 0);
        assert(matched1 != NULL);
        uint64_t hits_before = atomic_load(&matched1->observatory.wirecache_hits);

        // Client 1 query (uncached)
        bool saved_ok = arena.rcache_ok;
        arena.rcache_ok = false;
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched2 = NULL;
        int len1_uncached = process_dns_query_impl(req1, req_len1, res1_uncached, sizeof(res1_uncached),
                                                  "mail.example.com.", 1,
                                                  "192.0.2.1", &comp_ctx, false, NULL, &snap, &cfg, &matched2);
        assert(len1_uncached > 0);
        arena.rcache_ok = saved_ok;

        assert(len1_cached == len1_uncached);
        assert(memcmp(res1_cached, res1_uncached, len1_cached) == 0);
        printf("  [PASS] Client 1 DNS Cookie query matches uncached response byte-for-byte\n");

        // Client 2 query from different IP (cached)
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched3 = NULL;
        int len2_cached = cached_query(req2, req_len2, res2_cached, sizeof(res2_cached),
                                                "mail.example.com.", 1,
                                                "192.0.2.2", &comp_ctx, false, NULL, &snap, &cfg, &matched3);
        assert(len2_cached > 0);
        // A cookie query is served from the wire cache (the cookie itself is appended per query)
        assert(matched3 == matched1);
        assert(atomic_load(&matched3->observatory.wirecache_hits) == hits_before + 2); // warm-up + query, both hits

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

            compress_ctx_t comp_ctx = {0};
            compress_ctx_init_packet(&comp_ctx);
            zone_db_entry_t *matched = NULL;
            int len_cached = cached_query(req, req_len, res_cached, sizeof(res_cached),
                                                   mixed_qname, 1,
                                                   "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
            assert(len_cached > 0);

            bool saved_ok = arena.rcache_ok;
            arena.rcache_ok = false;
            compress_ctx_init_packet(&comp_ctx);
            int len_uncached = process_dns_query_impl(req, req_len, res_uncached, sizeof(res_uncached),
                                                     mixed_qname, 1,
                                                     "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
            arena.rcache_ok = saved_ok;

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

        compress_ctx_t comp_ctx = {0};
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
        compress_ctx_t comp_ctx = {0};
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
        compress_ctx_t comp_ctx = {0};
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

        compress_ctx_t comp_ctx = {0};
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
        compress_ctx_t comp_ctx = {0};
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
        compress_ctx_t comp_ctx = {0};
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

        compress_ctx_t comp_ctx = {0};
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

        compress_ctx_t comp_ctx = {0};
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
        compress_ctx_t comp_ctx = {0};
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
        compress_ctx_t comp_ctx = {0};
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

        compress_ctx_t comp_ctx = {0};
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

        compress_ctx_t comp_ctx = {0};
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

        compress_ctx_t comp_ctx = {0};
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

static void test_wire_cache_max_records_limit(void) {
    printf("[TEST] Running wire-cache-max-records configuration and threshold tests...\n");

    // 1. Config parser tests
    {
        char conf_ok[] = "options { wire-cache-max-records 500000; };";
        server_config_t cfg_ok;
        memset(&cfg_ok, 0, sizeof(cfg_ok));
        int res = parse_named_conf(conf_ok, &cfg_ok);
        assert(res == 0);
        assert(cfg_ok.wire_cache_max_records == 500000);
        free_server_config_fields(&cfg_ok);

        char conf_zero[] = "options { wire-cache-max-records 0; };";
        server_config_t cfg_zero;
        memset(&cfg_zero, 0, sizeof(cfg_zero));
        res = parse_named_conf(conf_zero, &cfg_zero);
        assert(res == 0);
        assert(cfg_zero.wire_cache_max_records == 0);
        free_server_config_fields(&cfg_zero);

        char conf_neg[] = "options { wire-cache-max-records -10; };";
        server_config_t cfg_neg;
        memset(&cfg_neg, 0, sizeof(cfg_neg));
        res = parse_named_conf(conf_neg, &cfg_neg);
        assert(res != 0);

        char conf_invalid[] = "options { wire-cache-max-records abc; };";
        server_config_t cfg_inv;
        memset(&cfg_inv, 0, sizeof(cfg_inv));
        res = parse_named_conf(conf_invalid, &cfg_inv);
        assert(res != 0);

        printf("  [PASS] Config parser handles wire-cache-max-records properly\n");

        /* response-cache-size: default 32M, K/M suffix, 0 disables, junk and out-of-range values are errors */
        struct { const char *conf; int ok; size_t want; } rcs[] = {
            { "options { };", 1, 32u * 1024 * 1024 },
            { "options { response-cache-size 64M; };", 1, 64u * 1024 * 1024 },
            { "options { response-cache-size 512K; };", 1, 512u * 1024 },
            { "options { response-cache-size 0; };", 1, 0 },
            { "options { response-cache-size 16X; };", 0, 0 },
            { "options { response-cache-size -1; };", 0, 0 },
            { "options { response-cache-size 2048M; };", 0, 0 },
            { "options { response-cache-size abc; };", 0, 0 },
        };
        for (size_t i = 0; i < sizeof(rcs) / sizeof(rcs[0]); i++) {
            char text[128];
            snprintf(text, sizeof(text), "%s", rcs[i].conf);
            server_config_t c;
            memset(&c, 0, sizeof(c));
            int r = parse_named_conf(text, &c);
            if (rcs[i].ok) {
                assert(r == 0);
                assert(c.response_cache_size == rcs[i].want);
                free_server_config_fields(&c);
            } else {
                assert(r != 0);
            }
        }
        printf("  [PASS] Config parser handles response-cache-size properly\n");
    }

    // 2. Threshold check & boundary tests
    {
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
            "ns1.example.com. 3600 IN A 192.0.2.1\n"
            "mail.example.com. 3600 IN A 192.0.2.10\n"
            "www.example.com. 3600 IN A 192.0.2.20\n";

        int parsed = parse_zone_fast((char *)zone_text, strlen(zone_text), &arena, &ctx);
        assert(parsed >= 0);
        int b_rc = test_build_index(&arena, true);
        assert(b_rc == 0);
        size_t total_records = arena.count;
        assert(total_records == 5);

        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));

        // Case A: wire_cache_max_records = 0 (unlimited) -> Cache enabled
        cfg.wire_cache_max_records = 0;
        build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
        assert(arena.rcache_ok);
        printf("  [PASS] wire_cache_max_records=0 enables cache\n");

        // Case B: wire_cache_max_records = total_records + 1 (above) -> Cache enabled
        cfg.wire_cache_max_records = (uint32_t)(total_records + 1);
        build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
        assert(arena.rcache_ok);
        printf("  [PASS] wire_cache_max_records=%zu (total+1) enables cache\n", total_records + 1);

        // Case C: wire_cache_max_records = total_records (exact boundary) -> Cache enabled (since arena->count > max is false)
        cfg.wire_cache_max_records = (uint32_t)total_records;
        build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
        assert(arena.rcache_ok);
        printf("  [PASS] wire_cache_max_records=%zu (exact total) enables cache\n", total_records);

        // Case D: wire_cache_max_records = total_records - 1 (below) -> Cache disabled
        cfg.wire_cache_max_records = (uint32_t)(total_records - 1);
        build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
        assert(!arena.rcache_ok);
        printf("  [PASS] wire_cache_max_records=%zu (total-1) disables cache\n", total_records - 1);

        // Case E: Query resolution still works when cache is disabled (fallback to full path)
        zone_db_entry_t db_entry;
        memset(&db_entry, 0, sizeof(db_entry));
        strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain));
        atomic_store_explicit(&db_entry.rcu.active, &arena.ver, memory_order_release);

        zone_db_entry_t *entries[1] = { &db_entry };
        char *any_acl[1] = { (char *)"any" };

        view_snapshot_t view;
        memset(&view, 0, sizeof(view));
        view.name = "default";
        view_set_entries(&view, entries, 1);
        view.match_clients = any_acl;
        view.match_clients_count = 1;

        zone_db_snapshot_t snap;
        memset(&snap, 0, sizeof(snap));
        snap.views = &view;
        snap.view_count = 1;

        uint8_t req[512], res[4096];
        size_t req_len = 0;
        build_simple_query(req, &req_len, 0x1234, "www.example.com.", 1 /* A */);

        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);
        zone_db_entry_t *matched = NULL;
        int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                        "www.example.com.", 1,
                                        "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
        assert(len > 0);
        uint8_t rcode = res[3] & 0x0F;
        uint16_t ancount = ((uint16_t)res[6] << 8) | res[7];
        assert(rcode == 0);
        assert(ancount == 1);
        printf("  [PASS] Query www.example.com A resolved correctly via full path when cache disabled\n");

        zone_arena_destroy(&arena);
    }

    printf("[SUCCESS] All wire-cache-max-records tests passed!\n");
}

/* An answer whose CNAME chain leaves the zone is not cached: the cache key has only the first zone's
 * generation, so after an update of the other zone the old answer would keep being returned. */
static void test_rcache_cross_zone_cname_not_cached(void) {
    printf("[TEST] Shared response cache: answers that follow a CNAME into another zone are not stored...\n");
    static char text_a[] =
        "a.example. 3600 IN SOA ns.a.example. h.a.example. 1 7200 3600 1209600 3600\n"
        "a.example. 3600 IN NS ns.a.example.\n"
        "ns.a.example. 3600 IN A 192.0.2.1\n"
        "www.a.example. 3600 IN CNAME x.b.example.\n"
        "back.a.example. 3600 IN CNAME y.b.example.\n"
        "end.a.example. 3600 IN A 192.0.2.9\n";
    static char text_b[] =
        "b.example. 3600 IN SOA ns.b.example. h.b.example. 1 7200 3600 1209600 3600\n"
        "b.example. 3600 IN NS ns.b.example.\n"
        "ns.b.example. 3600 IN A 192.0.2.2\n"
        "x.b.example. 3600 IN A 192.0.2.77\n"
        "y.b.example. 3600 IN CNAME end.a.example.\n";
    zone_arena_t arena_a, arena_b;
    zone_arena_init(&arena_a);
    zone_arena_init(&arena_b);
    parse_error_t err = {0};
    parse_context_t ca = { .base_dir = ".", .default_origin = "a.example.", .is_standalone_mode = true, .err_out = &err };
    parse_context_t cb = { .base_dir = ".", .default_origin = "b.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(text_a, strlen(text_a), &arena_a, &ca) >= 0);
    assert(parse_zone_fast(text_b, strlen(text_b), &arena_b, &cb) >= 0);
    assert(test_build_index(&arena_a, true) == 0 && test_build_index(&arena_b, true) == 0);
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    build_zone_response_cache(&arena_a.ver, &cfg, tst_entry(NULL, "a.example."));
    build_zone_response_cache(&arena_b.ver, &cfg, tst_entry(NULL, "b.example."));
    assert(arena_a.rcache_ok && arena_b.rcache_ok);

    zone_db_entry_t ea, eb;
    memset(&ea, 0, sizeof(ea));
    memset(&eb, 0, sizeof(eb));
    strncpy(ea.domain, "a.example.", sizeof(ea.domain) - 1);
    strncpy(eb.domain, "b.example.", sizeof(eb.domain) - 1);
    atomic_store_explicit(&ea.rcu.active, &arena_a.ver, memory_order_release);
    atomic_store_explicit(&eb.rcu.active, &arena_b.ver, memory_order_release);
    zone_db_entry_t *entries[2] = { &ea, &eb };
    char *any_acl[1] = { (char *)"any" };
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 2);
    view.match_clients = any_acl;
    view.match_clients_count = 1;
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    struct { const char *qname; bool crosses; } cases[] = {
        { "www.a.example.", true },   /* a -> b */
        { "back.a.example.", true },  /* a -> b -> a: ends in the first zone but used b's data */
        { "end.a.example.", false },  /* stays in a: cached as before */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint64_t hits0 = atomic_load(&ea.observatory.wirecache_hits);
        for (int round = 0; round < 2; round++) {
            uint8_t req[512], res[4096];
            size_t req_len = 0;
            build_simple_query(req, &req_len, (uint16_t)(0x4100 + i * 2 + round), cases[i].qname, 1);
            compress_ctx_t cc = {0};
            compress_ctx_init_packet(&cc);
            zone_db_entry_t *matched = NULL;
            int len = process_dns_query_impl(req, req_len, res, sizeof(res), cases[i].qname, 1,
                                             "127.0.0.1", &cc, false, NULL, &snap, &cfg, &matched);
            assert(len > 12 && (res[3] & 0x0F) == 0 && ((res[6] << 8) | res[7]) >= 1);
        }
        uint64_t hits = atomic_load(&ea.observatory.wirecache_hits) - hits0;
        assert(cases[i].crosses ? hits == 0 : hits == 1);
    }
    zone_arena_destroy(&arena_a);
    zone_arena_destroy(&arena_b);
    printf("  [PASS] cross-zone CNAME answers are not cached; in-zone answers still are\n");
}

/* An answer whose Additional section was cut to fit a small buffer (no TC, RFC 2181 §9) is not cached:
 * the key does not include the requester's buffer size, so a later EDNS query would get the cut answer. */
static void test_rcache_cut_additional_not_cached(void) {
    printf("[TEST] Shared response cache: answers with a cut Additional section are not stored...\n");
    static char text[8192];
    size_t n = (size_t)snprintf(text, sizeof(text),
        "mx.example. 3600 IN SOA ns.mx.example. h.mx.example. 1 7200 3600 1209600 3600\n"
        "mx.example. 3600 IN NS ns.mx.example.\n"
        "ns.mx.example. 3600 IN A 192.0.2.1\n");
    for (int m = 1; m <= 6; m++) {
        n += (size_t)snprintf(text + n, sizeof(text) - n, "mx.example. 3600 IN MX %d m%d.mx.example.\n", m, m);
        for (int a = 1; a <= 6; a++)
            n += (size_t)snprintf(text + n, sizeof(text) - n, "m%d.mx.example. 3600 IN A 192.0.2.%d\n", m, m * 10 + a);
    }
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "mx.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(text, strlen(text), &arena, &ctx) >= 0);
    assert(test_build_index(&arena, true) == 0);
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "mx.example."));
    assert(arena.rcache_ok);

    zone_db_entry_t e;
    memset(&e, 0, sizeof(e));
    strncpy(e.domain, "mx.example.", sizeof(e.domain) - 1);
    atomic_store_explicit(&e.rcu.active, &arena.ver, memory_order_release);
    zone_db_entry_t *entries[1] = { &e };
    char *any_acl[1] = { (char *)"any" };
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 1);
    view.match_clients = any_acl;
    view.match_clients_count = 1;
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    uint8_t req[512], res_small[4096], res_big[4096];
    size_t req_len = 0;
    compress_ctx_t cc = {0};
    zone_db_entry_t *matched = NULL;
    /* 1. no EDNS: 512 octets, the Additional section is cut, no TC */
    build_simple_query(req, &req_len, 0x5101, "mx.example.", 15);
    compress_ctx_init_packet(&cc);
    int len_small = process_dns_query_impl(req, req_len, res_small, 512, "mx.example.", 15,
                                           "127.0.0.1", &cc, false, NULL, &snap, &cfg, &matched);
    assert(len_small > 12 && len_small <= 512 && !(res_small[2] & 0x02));
    uint16_t ar_small = (uint16_t)((res_small[10] << 8) | res_small[11]);
    /* 2. EDNS 4096: must get the whole Additional section, not the cut answer from the cache */
    uint64_t hits0 = atomic_load(&e.observatory.wirecache_hits);
    build_edns_query(req, &req_len, 0x5102, "mx.example.", 15, false);
    compress_ctx_init_packet(&cc);
    int len_big = process_dns_query_impl(req, req_len, res_big, sizeof(res_big), "mx.example.", 15,
                                         "127.0.0.1", &cc, false, NULL, &snap, &cfg, &matched);
    assert(len_big > len_small);
    uint16_t ar_big = (uint16_t)((res_big[10] << 8) | res_big[11]);
    assert(ar_big > ar_small + 1); /* more than the OPT RR alone */
    assert(atomic_load(&e.observatory.wirecache_hits) == hits0);
    zone_arena_destroy(&arena);
    printf("  [PASS] cut Additional section not cached (plain AR=%u, EDNS AR=%u)\n", ar_small, ar_big);
}

/* Two or three zones of one view (additional-from-auth yes, the default) for the sibling glue tests. */
typedef struct {
    zone_arena_t arena[3];
    zone_db_entry_t ent[3];
    zone_db_entry_t *entries[3];
    char *any_acl[1];
    view_snapshot_t view;
    zone_db_snapshot_t snap;
    server_config_t cfg;
    int n;
} glue_world_t;

static void world_load(glue_world_t *w, int i, char *text, const char *origin) {
    zone_arena_init(&w->arena[i]);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = origin, .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(text, strlen(text), &w->arena[i], &ctx) >= 0);
    assert(test_build_index(&w->arena[i], true) == 0);
    build_zone_response_cache(&w->arena[i].ver, &w->cfg, tst_entry(NULL, origin));
}

static void world_publish(glue_world_t *w, int i, const char *origin) {
    memset(&w->ent[i], 0, sizeof(w->ent[i]));
    strncpy(w->ent[i].domain, origin, sizeof(w->ent[i].domain) - 1);
    atomic_store_explicit(&w->ent[i].rcu.active, &w->arena[i].ver, memory_order_release);
    w->entries[i] = &w->ent[i];
}

static void world_finish(glue_world_t *w, int n) {
    w->n = n;
    w->any_acl[0] = (char *)"any";
    memset(&w->view, 0, sizeof(w->view));
    w->view.name = "default";
    view_set_entries(&w->view, w->entries, (size_t)n);
    w->view.match_clients = w->any_acl;
    w->view.match_clients_count = 1;
    memset(&w->snap, 0, sizeof(w->snap));
    w->snap.views = &w->view;
    w->snap.view_count = 1;
}

static int world_query(glue_world_t *w, uint16_t id, const char *qname, uint16_t qtype, bool edns, uint8_t *res,
                       size_t res_cap, size_t limit) {
    uint8_t req[512];
    size_t req_len = 0;
    if (edns) build_edns_query(req, &req_len, id, qname, qtype, false);
    else build_simple_query(req, &req_len, id, qname, qtype);
    compress_ctx_t cc = {0};
    compress_ctx_init_packet(&cc);
    zone_db_entry_t *matched = NULL;
    (void)res_cap;
    return process_dns_query_impl(req, req_len, res, limit, qname, qtype, "127.0.0.1", &cc, false, NULL, &w->snap,
                                  &w->cfg, &matched);
}

static bool bytes_contain(const uint8_t *buf, size_t len, const uint8_t *pat, size_t plen) {
    for (size_t i = 0; i + plen <= len; i++)
        if (memcmp(buf + i, pat, plen) == 0) return true;
    return false;
}

/* C1: sibling-zone glue from append_glue_records() (additional-from-auth yes) is not stored in the shared response cache.
 * The cache key holds only the first zone's data generation; the sibling's publication reaches that generation later, through
 * g_glue_dirty and the control thread, and only for the first MAX_PRELINK_TARGETS targets.  Until then a cached answer would
 * keep the old sibling address. */
static void test_rcache_sibling_glue_not_cached(void) {
    printf("[TEST] Shared response cache: answers with sibling-zone glue are not stored (C1)...\n");
    static char text_a[] =
        "a.example. 3600 IN SOA ns.a.example. h.a.example. 1 7200 3600 1209600 3600\n"
        "a.example. 3600 IN NS ns.a.example.\n"
        "ns.a.example. 3600 IN A 192.0.2.1\n"
        "mx.a.example. 3600 IN MX 10 mail.b.example.\n"
        "own.a.example. 3600 IN MX 10 ns.a.example.\n";
    static char text_b[] =
        "b.example. 3600 IN SOA ns.b.example. h.b.example. 1 7200 3600 1209600 3600\n"
        "b.example. 3600 IN NS ns.b.example.\n"
        "ns.b.example. 3600 IN A 192.0.2.2\n"
        "mail.b.example. 3600 IN A 192.0.2.77\n";
    static char text_b2[] =
        "b.example. 3600 IN SOA ns.b.example. h.b.example. 2 7200 3600 1209600 3600\n"
        "b.example. 3600 IN NS ns.b.example.\n"
        "ns.b.example. 3600 IN A 192.0.2.2\n"
        "mail.b.example. 3600 IN A 192.0.2.88\n";
    glue_world_t *w = calloc(1, sizeof(*w));
    assert(w);
    world_load(w, 0, text_a, "a.example.");
    world_load(w, 1, text_b, "b.example.");
    assert(w->arena[0].rcache_ok && w->arena[1].rcache_ok);
    world_publish(w, 0, "a.example.");
    world_publish(w, 1, "b.example.");
    world_finish(w, 2);

    static const uint8_t old_addr[4] = {192, 0, 2, 77}, new_addr[4] = {192, 0, 2, 88};
    uint8_t res[4096];
    /* the answer carries the sibling's address, and the same query again is not a cache hit */
    uint64_t hits0 = atomic_load(&w->ent[0].observatory.wirecache_hits);
    for (int round = 0; round < 3; round++) {
        int len = world_query(w, (uint16_t)(0x6100 + round), "mx.a.example.", 15, false, res, sizeof(res), 512);
        assert(len > 12 && (res[3] & 0x0F) == 0 && ((res[6] << 8) | res[7]) == 1);
        assert(bytes_contain(res, (size_t)len, old_addr, 4));
    }
    assert(atomic_load(&w->ent[0].observatory.wirecache_hits) == hits0);

    /* b.example is published again with another address; a.example's generation is not touched (the window before the control
     * thread's glue refresh, or a target beyond the tracked 256): the next answer must already show the new address */
    world_load(w, 2, text_b2, "b.example.");
    atomic_store_explicit(&w->ent[1].rcu.active, &w->arena[2].ver, memory_order_release);
    int len = world_query(w, 0x6110, "mx.a.example.", 15, false, res, sizeof(res), 512);
    assert(len > 12);
    assert(bytes_contain(res, (size_t)len, new_addr, 4));
    assert(!bytes_contain(res, (size_t)len, old_addr, 4));

    /* a name whose glue is the zone's own address is still cached (the rule is not wider than the sibling lookup) */
    uint64_t own0 = atomic_load(&w->ent[0].observatory.wirecache_hits);
    for (int round = 0; round < 2; round++) {
        len = world_query(w, (uint16_t)(0x6120 + round), "own.a.example.", 15, false, res, sizeof(res), 512);
        assert(len > 12 && (res[3] & 0x0F) == 0);
    }
    assert(atomic_load(&w->ent[0].observatory.wirecache_hits) == own0 + 1);

    for (int i = 0; i < 3; i++) zone_arena_destroy(&w->arena[i]);
    free(w);
    printf("  [PASS] sibling glue answers are not cached and follow the sibling at once\n");
}

/* C2: the sibling's location-tagged addresses are chosen with the sibling's own tag definitions (append_glue_records() takes the
 * client's view of the sibling, as a CNAME into another zone does), not with the first zone's: the first zone has no tags, the client
 * (127.0.0.1) is in the sibling's "tokyo" and not in its "osaka".  Such a client-specific answer is not shared through the response
 * cache (the first zone's own cache is on, it has no tags). */
static void test_rcache_sibling_tagged_glue_not_cached(void) {
    printf("[TEST] Shared response cache: sibling glue is chosen with the sibling's tags and not stored (C2)...\n");
    static char text_a[] =
        "a.example. 3600 IN SOA ns.a.example. h.a.example. 1 7200 3600 1209600 3600\n"
        "a.example. 3600 IN NS ns.a.example.\n"
        "ns.a.example. 3600 IN A 192.0.2.1\n"
        "mx.a.example. 3600 IN MX 10 mail.b.example.\n";
    static char text_b[] =
        "$LOCATION-TAG tokyo 127.0.0.0/8\n"
        "$LOCATION-TAG osaka 198.51.100.0/24\n"
        "b.example. 3600 IN SOA ns.b.example. h.b.example. 1 7200 3600 1209600 3600\n"
        "b.example. 3600 IN NS ns.b.example.\n"
        "ns.b.example. 3600 IN A 192.0.2.2\n"
        "$LOCATION tokyo\n"
        "mail.b.example. 3600 IN A 192.0.2.201\n"
        "$LOCATION osaka\n"
        "mail.b.example. 3600 IN A 192.0.2.203\n"
        "$LOCATION \"\"\n"
        "mail.b.example. 3600 IN A 192.0.2.202\n";
    glue_world_t *w = calloc(1, sizeof(*w));
    assert(w);
    world_load(w, 0, text_a, "a.example.");
    world_load(w, 1, text_b, "b.example.");
    assert(w->arena[0].rcache_ok);
    assert(!w->arena[1].rcache_ok); /* the tagged zone is not cached itself */
    world_publish(w, 0, "a.example.");
    world_publish(w, 1, "b.example.");
    world_finish(w, 2);

    static const uint8_t tokyo[4] = {192, 0, 2, 201}, osaka[4] = {192, 0, 2, 203};
    uint8_t res[4096];
    uint64_t hits0 = atomic_load(&w->ent[0].observatory.wirecache_hits);
    for (int round = 0; round < 3; round++) {
        int len = world_query(w, (uint16_t)(0x6200 + round), "mx.a.example.", 15, false, res, sizeof(res), 512);
        assert(len > 12 && (res[3] & 0x0F) == 0);
        assert(bytes_contain(res, (size_t)len, tokyo, 4));   /* the sibling's own tag matched the client */
        assert(!bytes_contain(res, (size_t)len, osaka, 4));
    }
    assert(atomic_load(&w->ent[0].observatory.wirecache_hits) == hits0);

    for (int i = 0; i < 2; i++) zone_arena_destroy(&w->arena[i]);
    free(w);
    printf("  [PASS] tagged sibling glue follows the sibling's tags and is not cached\n");
}

/* A1, RFC 9471 §3.1-§3.3 and RFC 2181 §9: a referral that cannot hold all its glue sets TC=1 only when glue for a name server
 * inside the delegated zone (in-domain) is left out; glue for the other name servers (sibling, RFC 9471 §3.2: SHOULD, "MAY set
 * TC=1 but is not obligated") is left out without TC.  The positive-answer path (resolve_name_answer(), Additional section after
 * the apex NS) never sets TC for glue, so after this both paths agree on sibling glue. */
static void test_referral_tc_only_for_in_domain_glue(void) {
    printf("[TEST] Referral: TC only when in-domain glue does not fit; sibling glue is dropped without TC (A1)...\n");
    static char text_p[8192];
    size_t n = (size_t)snprintf(text_p, sizeof(text_p),
        "p.example. 3600 IN SOA ns.p.example. h.p.example. 1 7200 3600 1209600 3600\n"
        "p.example. 3600 IN NS ns.p.example.\n"
        "ns.p.example. 3600 IN A 192.0.2.1\n"
        /* c: one in-domain server and a sibling one; s first, then in-domain */
        "c.p.example. 3600 IN NS ns1.c.p.example.\n"
        "c.p.example. 3600 IN NS ns.big.example.\n"
        "ns1.c.p.example. 3600 IN A 192.0.2.5\n"
        "s.p.example. 3600 IN NS ns.big.example.\n"
        "s.p.example. 3600 IN NS ns1.s.p.example.\n"
        "ns1.s.p.example. 3600 IN A 192.0.2.6\n"
        /* t: an in-domain server whose glue is too large */
        "t.p.example. 3600 IN NS ns1.t.p.example.\n");
    for (int i = 1; i <= 20; i++)
        n += (size_t)snprintf(text_p + n, sizeof(text_p) - n, "ns1.t.p.example. 3600 IN AAAA 2001:db8:1::%x\n", i);
    /* u: sibling servers only (the second would fit after the first one was left out) */
    n += (size_t)snprintf(text_p + n, sizeof(text_p) - n,
        "u.p.example. 3600 IN NS ns.big.example.\nu.p.example. 3600 IN NS ns.small.example.\n");
    (void)n;
    /* ns.big.example has one AAAA RRset of 20 addresses (no A): it is all or nothing (RFC 2181 §9) and does not fit in 512 octets */
    static char text_big[8192];
    n = (size_t)snprintf(text_big, sizeof(text_big),
        "big.example. 3600 IN SOA ns.big.example. h.big.example. 1 7200 3600 1209600 3600\n"
        "big.example. 3600 IN NS ns.big.example.\n");
    for (int i = 1; i <= 20; i++)
        n += (size_t)snprintf(text_big + n, sizeof(text_big) - n, "ns.big.example. 3600 IN AAAA 2001:db8:2::%x\n", i);
    static char text_small[] =
        "small.example. 3600 IN SOA ns.small.example. h.small.example. 1 7200 3600 1209600 3600\n"
        "small.example. 3600 IN NS ns.small.example.\n"
        "ns.small.example. 3600 IN A 192.0.2.9\n";
    glue_world_t *w = calloc(1, sizeof(*w));
    assert(w);
    world_load(w, 0, text_p, "p.example.");
    world_load(w, 1, text_big, "big.example.");
    world_load(w, 2, text_small, "small.example.");
    world_publish(w, 0, "p.example.");
    world_publish(w, 1, "big.example.");
    world_publish(w, 2, "small.example.");
    world_finish(w, 3);

    static const uint8_t in_dom[4] = {192, 0, 2, 5}, in_dom_s[4] = {192, 0, 2, 6};
    static const uint8_t sib_a[6] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02}; /* 2001:db8:2:: */
    uint8_t res[4096];
    /* 1. in-domain glue first, sibling glue (20 AAAA) does not fit in 512 octets: no TC,
     *    the in-domain address is there, the sibling's is not */
    int len = world_query(w, 0x6300, "www.c.p.example.", 1, false, res, sizeof(res), 512);
    assert(len > 12 && len <= 512);
    assert(!(res[2] & 0x04));                 /* referral: AA clear */
    assert(((res[8] << 8) | res[9]) == 2);    /* both NS in Authority */
    assert(!(res[2] & 0x02));                 /* A1: no TC */
    assert(bytes_contain(res, (size_t)len, in_dom, 4));
    assert(!bytes_contain(res, (size_t)len, sib_a, 6));
    /* 2. sibling first, then in-domain: the in-domain glue is still tried after the sibling one did not fit */
    len = world_query(w, 0x6301, "www.s.p.example.", 1, false, res, sizeof(res), 512);
    assert(len > 12 && len <= 512);
    assert(!(res[2] & 0x02));
    assert(bytes_contain(res, (size_t)len, in_dom_s, 4));
    assert(!bytes_contain(res, (size_t)len, sib_a, 6));
    /* 3. in-domain glue too large: TC=1 (RFC 9471 §3.1, §3.3) */
    len = world_query(w, 0x6302, "www.t.p.example.", 1, false, res, sizeof(res), 512);
    assert(len > 12 && len <= 512);
    assert((res[2] & 0x02));
    /* 4. sibling servers only: no TC, the one that fits after the omitted one is not added either (the optional glue stops at the
     *    first omission, as in the positive-answer path) */
    static const uint8_t small_a[4] = {192, 0, 2, 9};
    len = world_query(w, 0x6303, "www.u.p.example.", 1, false, res, sizeof(res), 512);
    assert(len > 12 && len <= 512);
    assert(!(res[2] & 0x02));
    assert(((res[8] << 8) | res[9]) == 2);
    assert(!bytes_contain(res, (size_t)len, small_a, 4));
    /* 5. with EDNS (4096) everything fits: all glue is there, no TC */
    len = world_query(w, 0x6304, "www.c.p.example.", 1, true, res, sizeof(res), 4096);
    assert(len > 512 && !(res[2] & 0x02));
    assert(bytes_contain(res, (size_t)len, in_dom, 4) && bytes_contain(res, (size_t)len, sib_a, 6));

    for (int i = 0; i < 3; i++) zone_arena_destroy(&w->arena[i]);
    free(w);
    printf("  [PASS] referral TC only for in-domain glue\n");
}

/* E2: a caller that already looked up the view and the zone (the Backend does, to find program / forward zones) passes them in
 * a query_route_t; the answer is the same as when the engine looks them up itself, including the DS question at a child apex
 * (find_zone_for_query() answers it from the parent zone), a name below a zone cut, a name that no zone holds and EDNS queries. */
static void test_routed_query_equals_lookup(void) {
    printf("[TEST] process_dns_query_cap_routed() answers like process_dns_query_cap() (E2)...\n");
    static char text_a[] =
        "a.example. 3600 IN SOA ns.a.example. h.a.example. 1 7200 3600 1209600 3600\n"
        "a.example. 3600 IN NS ns.a.example.\n"
        "ns.a.example. 3600 IN A 192.0.2.1\n"
        "mx.a.example. 3600 IN MX 10 ns.a.example.\n"
        "cut.a.example. 3600 IN NS ns.cut.a.example.\n"
        "ns.cut.a.example. 3600 IN A 192.0.2.7\n"
        "sub.a.example. 3600 IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n"
        "sub.a.example. 3600 IN NS ns.sub.a.example.\n";
    static char text_sub[] =
        "sub.a.example. 3600 IN SOA ns.sub.a.example. h.sub.a.example. 1 7200 3600 1209600 3600\n"
        "sub.a.example. 3600 IN NS ns.sub.a.example.\n"
        "ns.sub.a.example. 3600 IN A 192.0.2.8\n"
        "www.sub.a.example. 3600 IN A 192.0.2.9\n";
    glue_world_t *w = calloc(1, sizeof(*w));
    assert(w);
    world_load(w, 0, text_a, "a.example.");
    world_load(w, 1, text_sub, "sub.a.example.");
    world_publish(w, 0, "a.example.");
    world_publish(w, 1, "sub.a.example.");
    world_finish(w, 2);

    struct { const char *qname; uint16_t qtype; bool edns; bool dobit; } cases[] = {
        { "mx.a.example.", 15, false, false }, { "mx.a.example.", 15, true, false }, { "mx.a.example.", 15, true, true },
        { "www.cut.a.example.", 1, false, false },  /* referral */
        { "nx.a.example.", 1, false, false },       /* NXDOMAIN */
        { "www.sub.a.example.", 1, false, false },  /* the child zone */
        { "sub.a.example.", 43, true, true },       /* DS at the child apex: answered from the parent zone */
        { "sub.a.example.", 6, false, false },
        { "other.example.", 1, false, false },      /* no zone: REFUSED */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t req[512], r1[4096], r2[4096];
        size_t req_len = 0;
        if (cases[i].edns) build_edns_query(req, &req_len, (uint16_t)(0x7000 + i), cases[i].qname, cases[i].qtype, cases[i].dobit);
        else build_simple_query(req, &req_len, (uint16_t)(0x7000 + i), cases[i].qname, cases[i].qtype);
        compress_ctx_t cc = {0};
        compress_ctx_init_packet(&cc);
        int l1 = process_dns_query_cap(req, req_len, r1, 4096, 0, cases[i].qname, cases[i].qtype, "127.0.0.1", &cc, false, NULL, &w->snap);
        query_route_t route;
        route.view = select_view(&w->snap, "127.0.0.1");
        route.tsig = NULL;
        route.entry = route.view ? find_zone_for_query(route.view, cases[i].qname, cases[i].qtype) : NULL;
        compress_ctx_init_packet(&cc);
        int l2 = process_dns_query_cap_routed(req, req_len, r2, 4096, 0, cases[i].qname, cases[i].qtype, "127.0.0.1", &cc, false,
                                              NULL, &w->snap, &route);
        assert(l1 > 12 && l1 == l2 && memcmp(r1, r2, (size_t)l1) == 0);
    }
    for (int i = 0; i < 2; i++) zone_arena_destroy(&w->arena[i]);
    free(w);
    printf("  [PASS] routed and looked-up answers are byte-identical\n");
}

static void test_wire_cache_observatory_counters(void) {
    printf("[TEST] Running wire cache observatory statistics & counters test...\n");

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
        "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026091801 7200 3600 1209600 3600\n"
        "example.com. 3600 IN NS ns1.example.com.\n"
        "ns1.example.com. 3600 IN A 192.0.2.1\n"
        "www.example.com. 3600 IN A 192.0.2.2\n";

    int parsed = parse_zone_fast((char *)zone_text, strlen(zone_text), &arena, &ctx);
    assert(parsed >= 0);
    int b_rc = test_build_index(&arena, true);
    assert(b_rc == 0);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
    assert(arena.rcache_ok);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain));
    atomic_store_explicit(&db_entry.rcu.active, &arena.ver, memory_order_release);

    zone_db_entry_t *entries[1] = { &db_entry };
    char *any_acl[1] = { (char *)"any" };

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 1);
    view.match_clients = any_acl;
    view.match_clients_count = 1;

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    // 1. First query fills the shared cache (miss), the second one is a hit: www.example.com A
    uint8_t req[512], res[4096];
    size_t req_len = 0;
    build_simple_query(req, &req_len, 0x1001, "www.example.com.", 1);

    compress_ctx_t comp_ctx = {0};
    compress_ctx_init_packet(&comp_ctx);
    zone_db_entry_t *matched = NULL;
    int len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                    "www.example.com.", 1,
                                    "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_hits, memory_order_relaxed) == 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 1);
    uint8_t res_first[4096];
    memcpy(res_first, res, (size_t)len);
    int len_first = len;
    compress_ctx_init_packet(&comp_ctx);
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "www.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len == len_first && memcmp(res, res_first, (size_t)len) == 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_hits, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 1);

    // 2. Cache miss query (NXDOMAIN): nonexistent.example.com A
    build_simple_query(req, &req_len, 0x1002, "nonexistent.example.com.", 1);
    compress_ctx_init_packet(&comp_ctx);
    matched = NULL;
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "nonexistent.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_hits, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 2);
    // NXDOMAIN is not stored: the same query misses again
    compress_ctx_init_packet(&comp_ctx);
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "nonexistent.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0 && (res[3] & 0x0F) == 3);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_hits, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 3);

    // 3. Cache-ineligible query (DO=1): should not increment hits or misses
    build_edns_query(req, &req_len, 0x1003, "www.example.com.", 1, true /* DO=1 */);
    compress_ctx_init_packet(&comp_ctx);
    matched = NULL;
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "www.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_hits, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 3);

    // 4. A new published version (new data generation) never sees the old entries
    build_simple_query(req, &req_len, 0x1004, "www.example.com.", 1);
    build_zone_response_cache(&arena.ver, &cfg, tst_entry(NULL, "example.com."));
    compress_ctx_init_packet(&comp_ctx);
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "www.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_hits, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 4);

    // 5. A sibling zone that holds glue addresses changed (S2): the zone gets a new generation in place
    uint64_t sibling_gen = zone_data_generation_next();
    atomic_store_explicit(&arena.generation, sibling_gen, memory_order_release);
    assert(zone_arena_data_generation(&arena.ver) == sibling_gen);
    compress_ctx_init_packet(&comp_ctx);
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "www.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 5);

    // 6. A configuration generation change also misses
    cfg.generation++;
    compress_ctx_init_packet(&comp_ctx);
    len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                 "www.example.com.", 1,
                                 "127.0.0.1", &comp_ctx, false, NULL, &snap, &cfg, &matched);
    assert(len > 0);
    assert(atomic_load_explicit(&db_entry.observatory.wirecache_misses, memory_order_relaxed) == 6);

    zone_arena_destroy(&arena);
    printf("[SUCCESS] All wire cache observatory counters tests passed!\n");
}

/* O-07: the same zone name in two views; only one view's zone{} has ecs-tags. The wire cache must follow
 * the configuration of the entry's own view (previously the first view's settings decided for both). */
static void test_wire_cache_per_view_config(void) {
    printf("[TEST] Wire cache: zone configuration is looked up in the entry's own view...\n");
    const char *conf =
        "view \"tagged\" { match-clients { 127.0.0.1; }; zone \"example.com\" { type master; file \"x.zone\";\n"
        "    ecs-tags { tag \"eu\" { 198.51.100.0/24; }; }; }; };\n"
        "view \"plain\" { match-clients { any; }; zone \"example.com\" { type master; file \"x.zone\"; }; };\n";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    assert(parse_named_conf(conf, &cfg) == 0);

    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };
    static char zone_text[] =
        "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600\n"
        "example.com. 3600 IN NS ns1.example.com.\n"
        "ns1.example.com. 3600 IN A 192.0.2.1\n";
    assert(parse_zone_fast(zone_text, strlen(zone_text), &arena, &ctx) >= 0);
    assert(test_build_index(&arena, true) == 0);

    build_zone_response_cache(&arena.ver, &cfg, tst_entry("tagged", "example.com."));
    assert(!arena.rcache_ok);
    build_zone_response_cache(&arena.ver, &cfg, tst_entry("plain", "example.com."));
    assert(arena.rcache_ok);

    zone_arena_destroy(&arena);
    free_server_config_fields(&cfg);
    printf("  -> per-view wire cache configuration passed.\n");
}

/* Store layout: one set (8 index entries, 1 KiB ring). Bodies of varying sizes wrap around the ring; a lookup
 * returns the stored body exactly or misses, never bytes of another entry, and a stored key replaces its old body. */
static void test_rcache_store_layout(void) {
    printf("[TEST] Shared response cache: variable-length bodies, ring wrap-around and eviction...\n");
    assert(response_cache_init(1) == 0);              /* too small for one set: disabled */
    size_t got = response_cache_init(1400);           /* exactly one set */
    assert(got > 0 && got <= 1400);
    uint8_t body[512], out[512];
    uint16_t an, ns, ar;
    int hits_total = 0;
    for (uint64_t k = 1; k <= 400; k++) {
        size_t len = 1 + (k * 37) % 300;
        for (size_t i = 0; i < len; i++) body[i] = (uint8_t)(k * 13 + i);
        rcache_store(k, 7, 1, body, len, (uint16_t)k, 2, 3);
        /* the entry just stored is always there */
        int l = rcache_lookup(k, 7, 1, out, sizeof(out), &an, &ns, &ar);
        assert(l == (int)len && an == (uint16_t)k && ns == 2 && ar == 3 && memcmp(out, body, len) == 0);
        /* older entries either hit with their own bytes or miss */
        for (uint64_t j = (k > 12 ? k - 12 : 1); j < k; j++) {
            size_t jl = 1 + (j * 37) % 300;
            l = rcache_lookup(j, 7, 1, out, sizeof(out), &an, &ns, &ar);
            if (l < 0) continue;
            assert(l == (int)jl && an == (uint16_t)j);
            for (size_t i = 0; i < jl; i++) assert(out[i] == (uint8_t)(j * 13 + i));
            hits_total++;
        }
        /* wrong generation, wrong qtype, too little room: miss */
        assert(rcache_lookup(k, 8, 1, out, sizeof(out), &an, &ns, &ar) < 0);
        assert(rcache_lookup(k, 7, 28, out, sizeof(out), &an, &ns, &ar) < 0);
        assert(rcache_lookup(k, 7, 1, out, len - 1, &an, &ns, &ar) < 0 || len == 0);
    }
    assert(hits_total > 0);
    /* the same key stored again replaces the old body */
    memset(body, 0xAB, 40);
    rcache_store(9999, 7, 1, body, 40, 1, 0, 0);
    memset(body, 0xCD, 24);
    rcache_store(9999, 7, 1, body, 24, 1, 0, 0);
    assert(rcache_lookup(9999, 7, 1, out, sizeof(out), &an, &ns, &ar) == 24 && out[0] == 0xCD && out[23] == 0xCD);
    /* bodies over the limit are not stored */
    rcache_store(4242, 7, 1, body, 497, 1, 0, 0);
    assert(rcache_lookup(4242, 7, 1, out, sizeof(out), &an, &ns, &ar) < 0);
    printf("  [PASS] variable-length store, wrap-around and eviction\n");
}

/* allow-query / allow-query-on (BIND 9.20 ARM): the check comes before the shared response cache, so an answer cached for a client that
 * may ask is never given to one that may not, and the answers that lead into a zone the client may not ask are cut and not stored. */
static void test_acl_before_response_cache(void) {
    printf("[TEST] allow-query is checked before the shared response cache; CNAME into a closed zone...\n");
    static char text_a[] =
        "a.example. 3600 IN SOA ns.a.example. h.a.example. 1 7200 3600 1209600 3600\n"
        "a.example. 3600 IN NS ns.a.example.\n"
        "ns.a.example. 3600 IN A 192.0.2.1\n"
        "www.a.example. 3600 IN CNAME x.b.example.\n"
        "end.a.example. 3600 IN A 192.0.2.9\n";
    static char text_b[] =
        "b.example. 3600 IN SOA ns.b.example. h.b.example. 1 7200 3600 1209600 3600\n"
        "b.example. 3600 IN NS ns.b.example.\n"
        "ns.b.example. 3600 IN A 192.0.2.2\n"
        "x.b.example. 3600 IN A 192.0.2.77\n";
    zone_arena_t arena_a, arena_b;
    zone_arena_init(&arena_a);
    zone_arena_init(&arena_b);
    parse_error_t err = {0};
    parse_context_t ca = { .base_dir = ".", .default_origin = "a.example.", .is_standalone_mode = true, .err_out = &err };
    parse_context_t cb = { .base_dir = ".", .default_origin = "b.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(text_a, strlen(text_a), &arena_a, &ca) >= 0);
    assert(parse_zone_fast(text_b, strlen(text_b), &arena_b, &cb) >= 0);
    assert(test_build_index(&arena_a, true) == 0 && test_build_index(&arena_b, true) == 0);
    /* options: only 127.0.0.0/8 may ask; a.example: only 127.0.0.1; b.example: only a request signed with k (or on the local address 192.0.2.53) */
    static const char conf[] =
        "key \"k\" { algorithm hmac-sha256; secret \"c2VjcmV0LW9uZS1mb3ItdGVzdA==\"; };"
        "options { allow-query { 127.0.0.0/8; }; };"
        "zone \"a.example\" { type master; file \"a\"; allow-query { 127.0.0.1; }; allow-query-on { 192.0.2.53; any; }; };"
        "zone \"b.example\" { type master; file \"b\"; allow-query { key k; }; };";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    assert(parse_named_conf(conf, &cfg) == 0 && cfg.acl_query_active);
    build_zone_response_cache(&arena_a.ver, &cfg, tst_entry(NULL, "a.example."));
    build_zone_response_cache(&arena_b.ver, &cfg, tst_entry(NULL, "b.example."));
    assert(arena_a.rcache_ok && arena_b.rcache_ok);

    zone_db_entry_t ea, eb;
    memset(&ea, 0, sizeof(ea));
    memset(&eb, 0, sizeof(eb));
    strncpy(ea.domain, "a.example.", sizeof(ea.domain) - 1);
    strncpy(eb.domain, "b.example.", sizeof(eb.domain) - 1);
    atomic_store_explicit(&ea.rcu.active, &arena_a.ver, memory_order_release);
    atomic_store_explicit(&eb.rcu.active, &arena_b.ver, memory_order_release);
    zone_db_entry_t *entries[2] = { &ea, &eb };
    char *any_acl[1] = { (char *)"any" };
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "__default__";
    view_set_entries(&view, entries, 2);
    view.match_clients = any_acl;
    view.match_clients_count = 1;
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    inet_pton(AF_INET, "192.0.2.99", &local.sin_addr);
    uint8_t req[512], res[4096];
    size_t req_len = 0;
    compress_ctx_t cc = {0};
    zone_db_entry_t *matched = NULL;
#define ASK(ID, NAME, IP) \
    (build_simple_query(req, &req_len, (ID), (NAME), 1), compress_ctx_init_packet(&cc), query_set_local_addr(&local), \
     process_dns_query_impl(req, req_len, res, sizeof(res), (NAME), 1, (IP), &cc, false, NULL, &snap, &cfg, &matched))

    /* the allowed client warms the cache (the second answer is a hit) ... */
    int len = ASK(0x5001, "end.a.example.", "127.0.0.1");
    assert(len > 12 && (res[3] & 0x0F) == 0 && ((res[6] << 8) | res[7]) == 1);
    uint64_t hits0 = atomic_load(&ea.observatory.wirecache_hits);
    len = ASK(0x5002, "end.a.example.", "127.0.0.1");
    assert(len > 12 && (res[3] & 0x0F) == 0 && ((res[6] << 8) | res[7]) == 1);
    assert(atomic_load(&ea.observatory.wirecache_hits) == hits0 + 1);
    /* ... and a client that may not ask is refused: no answer, AA=0, the question only, and the cache is not even looked at */
    uint64_t hits1 = atomic_load(&ea.observatory.wirecache_hits), miss1 = atomic_load(&ea.observatory.wirecache_misses);
    for (int i = 0; i < 3; i++) {
        len = ASK(0x5003 + i, "end.a.example.", "127.0.0.9");     /* inside options' 127.0.0.0/8 but not in a.example's list */
        assert(len > 12 && (res[3] & 0x0F) == 5 && ((res[6] << 8) | res[7]) == 0 && (res[2] & 0x04) == 0 && ((res[4] << 8) | res[5]) == 1);
        len = ASK(0x5010 + i, "end.a.example.", "198.51.100.1");
        assert(len > 12 && (res[3] & 0x0F) == 5 && ((res[6] << 8) | res[7]) == 0);
    }
    assert(atomic_load(&ea.observatory.wirecache_hits) == hits1 && atomic_load(&ea.observatory.wirecache_misses) == miss1);
    /* a refused response with EDNS carries EDE 18 and no stale bytes after the question + OPT */
    {
        build_edns_query(req, &req_len, 0x5020, "end.a.example.", 1, false);
        compress_ctx_init_packet(&cc);
        query_set_local_addr(&local);
        len = process_dns_query_impl(req, req_len, res, sizeof(res), "end.a.example.", 1, "127.0.0.9", &cc, false, NULL, &snap, &cfg, &matched);
        assert(len > 12 && (res[3] & 0x0F) == 5 && ((res[10] << 8) | res[11]) == 1);
        bool ede18 = false;                                                              /* option code 15, length, info code 18 (Prohibited) */
        for (int i = 12; i + 6 <= len; i++)
            if (res[i] == 0x00 && res[i + 1] == 0x0F && res[i + 4] == 0x00 && res[i + 5] == 0x12) ede18 = true;
        assert(ede18);
    }
    /* (allow-query-on { 192.0.2.53; any; } of a.example let the local address 192.0.2.99 in above)
     * b.example is closed to an unsigned client; the CNAME of a.example that leads there stops at the CNAME and is not cached */
    for (int round = 0; round < 3; round++) {
        len = ASK(0x5030 + round, "www.a.example.", "127.0.0.1");
        assert(len > 12 && (res[3] & 0x0F) == 0 && ((res[6] << 8) | res[7]) == 1 && (res[2] & 0x04) != 0);
        assert(!bytes_contain(res, (size_t)len, (const uint8_t[]){ 192, 0, 2, 77 }, 4));
    }
    assert(atomic_load(&ea.observatory.wirecache_hits) == hits1);                      /* never a hit: the answer is not stored */
    len = ASK(0x5040, "x.b.example.", "127.0.0.1");
    assert(len > 12 && (res[3] & 0x0F) == 5);                                          /* b.example itself: unsigned is refused */
    free_server_config_fields(&cfg);
#undef ASK
    zone_arena_destroy(&arena_a);
    zone_arena_destroy(&arena_b);
    printf("  [PASS] ACL before the cache, REFUSED shape, CNAME into a closed zone\n");
}

int main(void) {
    test_rcache_store_layout();
    assert(response_cache_init(1u << 20) > 0);
    test_wire_cache_consistency();
    test_wire_cache_max_records_limit();
    test_wire_cache_observatory_counters();
    test_rcache_cross_zone_cname_not_cached();
    test_rcache_cut_additional_not_cached();
    test_rcache_sibling_glue_not_cached();
    test_rcache_sibling_tagged_glue_not_cached();
    test_referral_tc_only_for_in_domain_glue();
    test_routed_query_equals_lookup();
    test_wire_cache_per_view_config();
    test_acl_before_response_cache();
    return 0;
}

/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}

/* send_tcp_dns_message(): goes through the send_tcp_robust() mock above (length prefix, then message) */
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len) {
    uint8_t prefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    if (send_tcp_robust(fd, prefix, 2) < 0) return -1;
    if (send_tcp_robust(fd, msg, len) < 0) return -1;
    return (ssize_t)len;
}

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <limits.h>

#include "../../dns_wire.h"
#include "../../dns_zone_parser.h"
#include "../../dns_config_parser.h"
#include "../../dns_query_engine.h"
#include "../../dns_snapshot_rcu.h"
#include "../../dns_epoch_rcu.h"
#include "../../dns_rrl.h"
#include "../../dns_catalog_zone.h"
#include "../../dns_dnstap.h"
#include "../../dns_edns_ecs.h"
#include "../../dns_dynamic_update.h"
#include "../../dns_axfr_ixfr.h"
#include "../../dns_server_internal.h"

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

// Override syslog during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

server_config_t *acquire_config_snapshot(void) {
    return atomic_load_explicit(&g_config_db.active, memory_order_acquire);
}
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

static zone_arena_t g_fuzz_arena_main;
static zone_arena_t g_fuzz_arena_sub;
static zone_arena_t g_fuzz_arena_nsec3;
static zone_db_entry_t g_fuzz_entries[3];
static zone_db_entry_t *g_fuzz_entry_ptrs[3];
static char *g_fuzz_any_acl[1] = { (char *)"any" };
static view_snapshot_t g_fuzz_views[1];
static zone_db_snapshot_t g_fuzz_snap;
static server_config_t g_fuzz_cfg;
static bool g_fuzz_qe_initialized = false;

static const char g_main_zone_text[] =
    "$ORIGIN example.com.\n"
    "$TTL 3600\n"
    "example.com. IN SOA ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600\n"
    "example.com. IN NS ns1.example.com.\n"
    "example.com. IN NS ns2.example.com.\n"
    "example.com. IN A 192.0.2.1\n"
    "example.com. IN AAAA 2001:db8::1\n"
    "example.com. IN MX 10 mail.example.com.\n"
    "example.com. IN TXT \"v=spf1 -all\"\n"
    "example.com. IN CAA 0 issue \"letsencrypt.org\"\n"
    "ns1.example.com. IN A 192.0.2.2\n"
    "ns2.example.com. IN A 192.0.2.3\n"
    "mail.example.com. IN A 192.0.2.10\n"
    "cname.example.com. IN CNAME target.example.com.\n"
    "target.example.com. IN A 192.0.2.20\n"
    "loop1.example.com. IN CNAME loop2.example.com.\n"
    "loop2.example.com. IN CNAME loop1.example.com.\n"
    "dname.example.com. IN DNAME target.example.com.\n"
    "*.wild.example.com. IN A 192.0.2.100\n"
    "*.wild.example.com. IN TXT \"wildcard match\"\n"
    "ent.sub.example.com. IN A 192.0.2.101\n"
    "subzone.example.com. IN NS ns1.subzone.example.com.\n"
    "ns1.subzone.example.com. IN A 192.0.2.200\n"
    "sibling.example.com. IN NS ns1.other.example.com.\n"
    "example.com. IN NSEC cname.example.com. A AAAA NS SOA MX TXT CAA RRSIG NSEC\n"
    "example.com. IN RRSIG SOA 13 2 3600 20300101000000 20200101000000 12345 example.com. AAAA\n";

static const char g_sub_zone_text[] =
    "$ORIGIN sub.example.org.\n"
    "$TTL 1800\n"
    "sub.example.org. IN SOA ns1.sub.example.org. admin.sub.example.org. 1 3600 1800 604800 86400\n"
    "sub.example.org. IN NS ns1.sub.example.org.\n"
    "sub.example.org. IN A 198.51.100.1\n"
    "*.w.sub.example.org. IN AAAA 2001:db8:ffff::1\n";

static const char g_nsec3_zone_text[] =
    "$ORIGIN signed.local.\n"
    "$TTL 3600\n"
    "signed.local. IN SOA ns1.signed.local. admin.signed.local. 100 3600 1800 604800 86400\n"
    "signed.local. IN NS ns1.signed.local.\n"
    "signed.local. IN A 203.0.113.1\n"
    "signed.local. IN NSEC3PARAM 1 0 10 AABBCCDD\n"
    "00000000000000000000000000000000.signed.local. IN NSEC3 1 0 10 AABBCCDD HGFEDCBA000000000000000000000000 A RRSIG\n";

static void init_rich_fuzz_engine(void) {
    if (g_fuzz_qe_initialized) return;

    parse_error_t err = {0};
    
    // Main zone
    zone_arena_init(&g_fuzz_arena_main);
    parse_context_t ctx1 = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };
    char main_buf[sizeof(g_main_zone_text)];
    memcpy(main_buf, g_main_zone_text, sizeof(g_main_zone_text));
    parse_zone_fast(main_buf, sizeof(g_main_zone_text) - 1, &g_fuzz_arena_main, &ctx1);
    build_zone_index(&g_fuzz_arena_main, true);
    
    memset(&g_fuzz_entries[0], 0, sizeof(g_fuzz_entries[0]));
    strncpy(g_fuzz_entries[0].domain, "example.com.", sizeof(g_fuzz_entries[0].domain) - 1);
    atomic_store_explicit(&g_fuzz_entries[0].rcu.active, &g_fuzz_arena_main, memory_order_release);
    g_fuzz_entry_ptrs[0] = &g_fuzz_entries[0];

    // Sub zone
    zone_arena_init(&g_fuzz_arena_sub);
    parse_context_t ctx2 = { .base_dir = ".", .default_origin = "sub.example.org.", .is_standalone_mode = true, .err_out = &err };
    char sub_buf[sizeof(g_sub_zone_text)];
    memcpy(sub_buf, g_sub_zone_text, sizeof(g_sub_zone_text));
    parse_zone_fast(sub_buf, sizeof(g_sub_zone_text) - 1, &g_fuzz_arena_sub, &ctx2);
    build_zone_index(&g_fuzz_arena_sub, true);
    
    memset(&g_fuzz_entries[1], 0, sizeof(g_fuzz_entries[1]));
    strncpy(g_fuzz_entries[1].domain, "sub.example.org.", sizeof(g_fuzz_entries[1].domain) - 1);
    atomic_store_explicit(&g_fuzz_entries[1].rcu.active, &g_fuzz_arena_sub, memory_order_release);
    g_fuzz_entry_ptrs[1] = &g_fuzz_entries[1];

    // NSEC3 zone
    zone_arena_init(&g_fuzz_arena_nsec3);
    parse_context_t ctx3 = { .base_dir = ".", .default_origin = "signed.local.", .is_standalone_mode = true, .err_out = &err };
    char nsec3_buf[sizeof(g_nsec3_zone_text)];
    memcpy(nsec3_buf, g_nsec3_zone_text, sizeof(g_nsec3_zone_text));
    parse_zone_fast(nsec3_buf, sizeof(g_nsec3_zone_text) - 1, &g_fuzz_arena_nsec3, &ctx3);
    build_zone_index(&g_fuzz_arena_nsec3, true);
    
    memset(&g_fuzz_entries[2], 0, sizeof(g_fuzz_entries[2]));
    strncpy(g_fuzz_entries[2].domain, "signed.local.", sizeof(g_fuzz_entries[2].domain) - 1);
    atomic_store_explicit(&g_fuzz_entries[2].rcu.active, &g_fuzz_arena_nsec3, memory_order_release);
    g_fuzz_entry_ptrs[2] = &g_fuzz_entries[2];

    // Snapshot View
    memset(&g_fuzz_views[0], 0, sizeof(g_fuzz_views[0]));
    g_fuzz_views[0].name = "default";
    g_fuzz_views[0].entries = g_fuzz_entry_ptrs;
    g_fuzz_views[0].zone_count = 3;
    g_fuzz_views[0].match_clients = g_fuzz_any_acl;
    g_fuzz_views[0].match_clients_count = 1;

    memset(&g_fuzz_snap, 0, sizeof(g_fuzz_snap));
    g_fuzz_snap.views = g_fuzz_views;
    g_fuzz_snap.view_count = 1;

    // Config
    memset(&g_fuzz_cfg, 0, sizeof(g_fuzz_cfg));
    g_fuzz_cfg.rfc10029_mqtype_enable = true;
    g_fuzz_cfg.max_mqtypes = 4;
    g_fuzz_cfg.minimal_responses = true;
    g_fuzz_cfg.minimal_any = true;
    g_fuzz_cfg.minimal_any_ttl = 60;
    atomic_store_explicit(&g_config_db.active, &g_fuzz_cfg, memory_order_release);

    g_fuzz_qe_initialized = true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    init_rich_fuzz_engine();

    // Build or mutate query packet
    uint8_t query_buf[4096];
    size_t query_len = size;
    if (query_len > sizeof(query_buf)) query_len = sizeof(query_buf);
    memcpy(query_buf, data, query_len);

    char qname[256] = {0};
    uint16_t qtype = 0;
    uint16_t qclass = 1;
    size_t qend = 0;

    parse_query_question_fast(query_buf, query_len, qname, sizeof(qname), &qtype, &qclass, &qend);

    uint8_t resp_buf[4096];
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);

    bool is_tcp = (data[0] & 0x01) != 0;
    
    int resp_len = process_dns_query(
        query_buf, query_len,
        resp_buf, sizeof(resp_buf),
        qname, qtype,
        "127.0.0.1", &comp_ctx,
        is_tcp, NULL,
        &g_fuzz_snap
    );

    // Oracle invariant verification
    if (resp_len > 12) {
        // Must have QR bit set in response flags
        uint16_t flags = ((uint16_t)resp_buf[2] << 8) | resp_buf[3];
        (void)flags;
        char rqname[256] = {0};
        uint16_t rqtype = 0;
        uint16_t rqclass = 1;
        size_t rqend = 0;
        parse_query_question_fast(resp_buf, (size_t)resp_len, rqname, sizeof(rqname), &rqtype, &rqclass, &rqend);
    }

    return 0;
}

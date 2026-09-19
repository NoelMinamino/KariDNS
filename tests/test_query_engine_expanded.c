#define OPENSSL_SUPPRESS_DEPRECATED 1
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
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_query_engine.h"
#include "dns_server_internal.h"
#include "dns_axfr_ixfr.h"
#include "dns_dynamic_update.h"

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

static void build_dns_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, bool dnssec_ok) {
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; // RD=1
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = dnssec_ok ? 0x01 : 0x00; // ARCOUNT

    long wlen = write_uncompressed_name(buf, 12, 256, qname);
    assert(wlen > 0);
    size_t off = 12 + (size_t)wlen;
    buf[off++] = (uint8_t)(qtype >> 8);
    buf[off++] = (uint8_t)(qtype & 0xFF);
    buf[off++] = 0x00;
    buf[off++] = 0x01; // IN class

    if (dnssec_ok) {
        buf[off++] = 0x00; // Root
        buf[off++] = 0x00; buf[off++] = 41; // OPT
        buf[off++] = 0x10; buf[off++] = 0x00; // UDP 4096
        buf[off++] = 0x00; buf[off++] = 0x00;
        buf[off++] = 0x80; buf[off++] = 0x00; // DO=1
        buf[off++] = 0x00; buf[off++] = 0x00;
    }
    *out_len = off;
}

static void test_all_rr_types_and_resolution(void) {
    printf("[TEST] Query Engine: Comprehensive All-RR Types Resolution...\n");

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
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        "@       IN SOA   ns1.example.com. hostmaster.example.com. 2026091401 7200 3600 1209600 3600\n"
        "@       IN NS    ns1.example.com.\n"
        "@       IN NS    ns2.example.com.\n"
        "ns1     IN A     192.0.2.1\n"
        "ns2     IN AAAA  2001:db8::2\n"
        "@       IN MX    10 mail.example.com.\n"
        "mail    IN A     192.0.2.10\n"
        "@       IN TXT   \"v=spf1 -all\"\n"
        "@       IN CAA   0 issue \"letsencrypt.org\"\n"
        "ptr     IN PTR   target.example.com.\n"
        "_sip._tcp IN SRV 10 60 5060 srv.example.com.\n"
        "srv     IN A     192.0.2.30\n"
        "@       IN NAPTR 100 10 \"u\" \"sip+E2U\" \"!^.*$!sip:info@example.com!\" .\n"
        "ssh     IN SSHFP 1 1 123456789abcdef67890123456789abcdef67890\n"
        "_443._tcp IN TLSA 3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a132e9620a4036024c63f2ef95ab\n"
        "dsrec   IN DS    60485 5 1 2BB183437027340B64FEA36B73D5E8B9F2E48A96\n"
        "dkey    IN DNSKEY 256 3 5 AwEAAcd2abde240d7cd3ee6b4b28c54df034b97983a132e9620a4036024c63f2ef95ab==\n"
        "rrsigrec IN RRSIG A 13 2 3600 20300101000000 20260101000000 12345 example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "nsec1   IN NSEC  nsec2.example.com. A AAAA RRSIG NSEC\n"
        "nsec3rec IN NSEC3 1 0 10 aabbccdd 0123456789abcdef0123456789abcdef A RRSIG\n"
        "svc     IN SVCB  1 . alpn=h2\n"
        "https   IN HTTPS 1 . alpn=h2,h3\n"
        "apl     IN APL   1:192.0.2.0/24 !1:192.0.2.1/32\n"
        "loc     IN LOC   51 30 12.748 N 0 7 39.611 W 45.00m 1000.00m 1000.00m 10.00m\n"
        "zonemd  IN ZONEMD 2026091401 1 1 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n"
        "cname1  IN CNAME ns1.example.com.\n"
        "*.wild  IN A     192.0.2.77\n"
        "subdname IN DNAME dname-target.org.\n";

    int parsed = parse_zone_fast((char *)zone_text, strlen(zone_text), &arena, &ctx);
    assert(parsed >= 0);
    int b_res = build_zone_index(&arena, true);
    assert(b_res == 0);

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

    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);

    // Array of (QNAME, QTYPE, expected min ANCOUNT, expected RCODE)
    struct {
        const char *qname;
        uint16_t qtype;
        uint16_t min_ancount;
        uint8_t exp_rcode;
    } tests[] = {
        { "ns1.example.com.", 1 /* A */, 1, 0 },
        { "ns2.example.com.", 28 /* AAAA */, 1, 0 },
        { "example.com.", 2 /* NS */, 2, 0 },
        { "example.com.", 6 /* SOA */, 1, 0 },
        { "example.com.", 15 /* MX */, 1, 0 },
        { "example.com.", 16 /* TXT */, 1, 0 },
        { "example.com.", 257 /* CAA */, 1, 0 },
        { "ptr.example.com.", 12 /* PTR */, 1, 0 },
        { "_sip._tcp.example.com.", 33 /* SRV */, 1, 0 },
        { "example.com.", 35 /* NAPTR */, 1, 0 },
        { "ssh.example.com.", 44 /* SSHFP */, 1, 0 },
        { "_443._tcp.example.com.", 52 /* TLSA */, 1, 0 },
        { "dsrec.example.com.", 43 /* DS */, 1, 0 },
        { "dkey.example.com.", 48 /* DNSKEY */, 1, 0 },
        { "rrsigrec.example.com.", 46 /* RRSIG */, 1, 0 },
        { "nsec1.example.com.", 47 /* NSEC */, 1, 0 },
        { "nsec3rec.example.com.", 50 /* NSEC3 */, 1, 0 },
        { "svc.example.com.", 64 /* SVCB */, 1, 0 },
        { "https.example.com.", 65 /* HTTPS */, 1, 0 },
        { "apl.example.com.", 42 /* APL */, 1, 0 },
        { "loc.example.com.", 29 /* LOC */, 1, 0 },
        { "zonemd.example.com.", 63 /* ZONEMD */, 1, 0 },
        { "cname1.example.com.", 1 /* A via CNAME */, 1, 0 },
        // Wildcard
        { "foo.wild.example.com.", 1 /* A */, 1, 0 },
        { "bar.baz.wild.example.com.", 1 /* A */, 1, 0 },
        // DNAME synthesis
        { "test.subdname.example.com.", 1 /* A synthesized CNAME */, 1, 0 },
        // ANY query
        { "example.com.", 255 /* ANY */, 1, 0 },
        // NODATA (A query for TXT-only name or non-existent type)
        { "example.com.", 999 /* Non-existent TYPE */, 0, 0 },
        // NXDOMAIN
        { "nonexistent.example.com.", 1 /* A */, 0, 3 },
        // Non-existent zone -> REFUSED
        { "otherdomain.org.", 1 /* A */, 0, 5 }
    };

    uint8_t req[512], res[4096];
    size_t req_len = 0;

    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        build_dns_query(req, &req_len, (uint16_t)(i + 1), tests[i].qname, tests[i].qtype, false);
        compress_ctx_init_packet(&comp_ctx);

        rate_limit_config_t *rrl_out = NULL;
        zone_db_entry_t *matched_entry = NULL;
        int res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                             tests[i].qname, tests[i].qtype,
                                             "192.0.2.100", &comp_ctx,
                                             false, &rrl_out, &snap, &cfg, &matched_entry);
        assert(res_len >= DNS_HEADER_SIZE);
        uint8_t rcode = res[3] & 0x0F;
        uint16_t ancount = (res[6] << 8) | res[7];

        assert(rcode == tests[i].exp_rcode);
        if (tests[i].min_ancount > 0) {
            assert(ancount >= tests[i].min_ancount);
        }
    }

    zone_arena_destroy(&arena);
    printf("  -> All-RR types resolution passed.\n");
}

static void test_dnssec_negative_and_delegation_proofs(void) {
    printf("[TEST] Query Engine: DNSSEC NSEC/NSEC3 Negative Proofs & Insecure Delegation...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "sec.example.com.",
        .is_standalone_mode = true,
        .err_out = &err,
    };

    // DNSSEC NSEC-signed zone with delegation without DS
    const char zone_text[] =
        "$ORIGIN sec.example.com.\n"
        "$TTL 3600\n"
        "@       IN SOA   ns1.sec.example.com. hostmaster.sec.example.com. 2026091401 7200 3600 1209600 3600\n"
        "@       IN RRSIG SOA 13 3 3600 20300101000000 20260101000000 12345 sec.example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "@       IN NS    ns1.sec.example.com.\n"
        "@       IN RRSIG NS 13 3 3600 20300101000000 20260101000000 12345 sec.example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "ns1     IN A     192.0.2.5\n"
        "ns1     IN RRSIG A 13 4 3600 20300101000000 20260101000000 12345 sec.example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "@       IN NSEC  ns1.sec.example.com. SOA NS RRSIG NSEC\n"
        "@       IN RRSIG NSEC 13 3 3600 20300101000000 20260101000000 12345 sec.example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "ns1     IN NSEC  sub.sec.example.com. A RRSIG NSEC\n"
        "ns1     IN RRSIG NSEC 13 4 3600 20300101000000 20260101000000 12345 sec.example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "sub     IN NS    ns1.sub.sec.example.com.\n" // Delegation without DS
        "sub     IN NSEC  sec.example.com. NS RRSIG NSEC\n"
        "sub     IN RRSIG NSEC 13 4 3600 20300101000000 20260101000000 12345 sec.example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n";

    int parsed = parse_zone_fast((char *)zone_text, strlen(zone_text), &arena, &ctx);
    assert(parsed >= 0);
    int b_res = build_zone_index(&arena, true);
    assert(b_res == 0);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "sec.example.com.", sizeof(db_entry.domain));
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

    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));

    uint8_t req[512], res[4096];
    size_t req_len = 0;

    // 1. NXDOMAIN with DO=1 -> Authority section contains NSEC + RRSIG
    build_dns_query(req, &req_len, 0x8801, "nonexistent.sec.example.com.", 1 /* A */, true);
    compress_ctx_init_packet(&comp_ctx);
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched_entry = NULL;
    int res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                         "nonexistent.sec.example.com.", 1,
                                         "192.0.2.100", &comp_ctx,
                                         false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert((res[3] & 0x0F) == 3); // NXDOMAIN
    uint16_t nscount = (res[8] << 8) | res[9];
    assert(nscount > 0); // Authority section has SOA + NSEC + RRSIGs

    // 2. NODATA with DO=1 (AAAA query for ns1.sec.example.com which only has A)
    build_dns_query(req, &req_len, 0x8802, "ns1.sec.example.com.", 28 /* AAAA */, true);
    compress_ctx_init_packet(&comp_ctx);
    res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                     "ns1.sec.example.com.", 28,
                                     "192.0.2.100", &comp_ctx,
                                     false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert((res[3] & 0x0F) == 0); // NOERROR
    uint16_t ancount = (res[6] << 8) | res[7];
    assert(ancount == 0); // NODATA
    nscount = (res[8] << 8) | res[9];
    assert(nscount > 0); // NSEC proof present in Authority

    // 3. Delegation referral with DO=1 (host.sub.sec.example.com) -> Insecure Delegation DS proof
    build_dns_query(req, &req_len, 0x8803, "host.sub.sec.example.com.", 1 /* A */, true);
    compress_ctx_init_packet(&comp_ctx);
    res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                     "host.sub.sec.example.com.", 1,
                                     "192.0.2.100", &comp_ctx,
                                     false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert((res[2] & 0x04) == 0); // AA=0 (Referral)
    nscount = (res[8] << 8) | res[9];
    assert(nscount >= 1); // NS referral + NSEC DS denial proof

    zone_arena_destroy(&arena);
    printf("  -> DNSSEC Negative Proofs & Delegation passed.\n");
}

static void test_tinydns_timestamp_countdown(void) {
    printf("[TEST] Query Engine: tinydns Timestamp & Countdown TTL Resolution...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    arena.is_tinydns_format = true;

    arena.records = malloc(sizeof(dns_record_t) * 8);
    arena.records_cap = 8;
    arena.hash_size = 256;
    arena.hash_table = malloc(sizeof(int) * arena.hash_size);
    for (size_t i = 0; i < arena.hash_size; i++) arena.hash_table[i] = -1;

    // SOA
    dns_record_t soa; memset(&soa, 0, sizeof(soa));
    soa.name = arena_strdup(&arena, "tiny.example.");
    soa.type_code = 6; soa.ttl_value = 3600; soa.class_val = 1;
    soa.rdata_count = 7;
    soa.rdata[0] = arena_strdup(&arena, "a.ns.tiny.example.");
    soa.rdata[1] = arena_strdup(&arena, "hostmaster.tiny.example.");
    soa.rdata[2] = arena_strdup(&arena, "1");
    soa.rdata[3] = arena_strdup(&arena, "7200");
    soa.rdata[4] = arena_strdup(&arena, "3600");
    soa.rdata[5] = arena_strdup(&arena, "1209600");
    soa.rdata[6] = arena_strdup(&arena, "300");
    arena.records[arena.count++] = soa;

    time_t now = time(NULL);

    // Record 1: Past activation timestamp (active)
    dns_record_t r_past; memset(&r_past, 0, sizeof(r_past));
    r_past.name = arena_strdup(&arena, "past.tiny.example.");
    r_past.type_code = 1; r_past.class_val = 1;
    r_past.ttl_value = 300; r_past.rdata_count = 1;
    r_past.rdata[0] = arena_strdup(&arena, "192.0.2.11");
    r_past.tinydns_ttd = now - 1000; // Activated in past
    r_past.tinydns_ttl_countdown = false;
    arena.records[arena.count++] = r_past;

    // Record 2: Future activation timestamp (inactive)
    dns_record_t r_fut; memset(&r_fut, 0, sizeof(r_fut));
    r_fut.name = arena_strdup(&arena, "future.tiny.example.");
    r_fut.type_code = 1; r_fut.class_val = 1;
    r_fut.ttl_value = 300; r_fut.rdata_count = 1;
    r_fut.rdata[0] = arena_strdup(&arena, "192.0.2.22");
    r_fut.tinydns_ttd = now + 10000; // In future
    r_fut.tinydns_ttl_countdown = false;
    arena.records[arena.count++] = r_fut;

    // Record 3: Countdown TTL (expires in 60 seconds)
    dns_record_t r_cnt; memset(&r_cnt, 0, sizeof(r_cnt));
    r_cnt.name = arena_strdup(&arena, "countdown.tiny.example.");
    r_cnt.type_code = 1; r_cnt.class_val = 1;
    r_cnt.ttl_value = 300; r_cnt.rdata_count = 1;
    r_cnt.rdata[0] = arena_strdup(&arena, "192.0.2.33");
    r_cnt.tinydns_ttd = now + 60;
    r_cnt.tinydns_ttl_countdown = true;
    arena.records[arena.count++] = r_cnt;

    build_zone_index(&arena, true);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "tiny.example.", sizeof(db_entry.domain));
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
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));

    uint8_t req[512], res[4096];
    size_t req_len = 0;
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched_entry = NULL;

    // Query 1: Past activation record -> found (ancount=1)
    build_dns_query(req, &req_len, 0x9001, "past.tiny.example.", 1, false);
    compress_ctx_init_packet(&comp_ctx);
    int res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                         "past.tiny.example.", 1,
                                         "192.0.2.100", &comp_ctx,
                                         false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert((res[3] & 0x0F) == 0); // NOERROR
    assert(((res[6] << 8) | res[7]) == 1);

    // Query 2: Future activation record -> omitted (NXDOMAIN/NODATA)
    build_dns_query(req, &req_len, 0x9002, "future.tiny.example.", 1, false);
    compress_ctx_init_packet(&comp_ctx);
    res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                     "future.tiny.example.", 1,
                                     "192.0.2.100", &comp_ctx,
                                     false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert(((res[6] << 8) | res[7]) == 0); // Not returned

    // Query 3: Countdown record -> found with dynamically computed TTL
    build_dns_query(req, &req_len, 0x9003, "countdown.tiny.example.", 1, false);
    compress_ctx_init_packet(&comp_ctx);
    res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                     "countdown.tiny.example.", 1,
                                     "192.0.2.100", &comp_ctx,
                                     false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert(((res[6] << 8) | res[7]) == 1);

    zone_arena_destroy(&arena);
    printf("  -> tinydns timestamp countdown passed.\n");
}

static void test_mqtype_truncation(void) {
    printf("[TEST] Query Engine: MQTYPE EDNS option truncation handling...\n");
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
    int p_res = parse_zone_fast(zone_text, strlen(zone_text), &arena, &ctx);
    assert(p_res >= 0);
    int b_res = build_zone_index(&arena, true);
    assert(b_res == 0);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain) - 1);
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
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);

    uint8_t res[512] = {0};
    size_t small_res_len = 100;
    rate_limit_config_t *rrl = NULL;
    zone_db_entry_t *matched_entry = NULL;
    int res_len = process_dns_query_impl(req, off, res, small_res_len, "example.com.", 1,
                                         "127.0.0.1", &comp_ctx, false, &rrl, &snap, &cfg, &matched_entry);

    if (res_len > 0) {
        uint8_t rcode = res[3] & 0x0F;
        bool tc_set = (res[2] & 0x02) != 0;
        uint16_t ancount = (res[6] << 8) | res[7];

        assert(rcode != 5 /* REFUSED */);
        assert(!tc_set); // RFC 10029 §3.4: MQTYPE failure MUST NOT trigger TC bit
        assert(ancount >= 1);
    }

    zone_arena_destroy(&arena);
    printf("  -> MQTYPE truncation handling passed.\n");
}

static void test_mqtype_qdcount0_formerr(void) {
    printf("[TEST] Query Engine: MQTYPE QDCOUNT=0 FORMERR handling...\n");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.rfc10029_mqtype_enable = true;

    uint8_t req[512] = {0};
    req[0] = 0x12; req[1] = 0x34; // ID
    req[2] = 0x00; req[3] = 0x00; // Opcode=0, QDCOUNT=0
    req[4] = 0x00; req[5] = 0x00; // QDCOUNT=0
    req[10] = 0x00; req[11] = 0x01; // ARCOUNT=1 (OPT)

    size_t off = 12;
    req[off++] = 0x00; // Root name
    req[off++] = 0x00; req[off++] = 0x29; // TYPE OPT (41)
    req[off++] = 0x10; req[off++] = 0x00; // UDP payload 4096
    req[off++] = 0x00; req[off++] = 0x00; req[off++] = 0x00; req[off++] = 0x00;
    req[off++] = 0x00; req[off++] = 0x06; // RDLEN = 6
    req[off++] = 0x00; req[off++] = 0x14; // OptCode 20 (MQTYPE-Query)
    req[off++] = 0x00; req[off++] = 0x02; // OptLen 2
    req[off++] = 0x00; req[off++] = 0x10; // QTYPE TXT (16)

    uint8_t res[512] = {0};
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_entry_t *matched = NULL;

    int res_len = process_dns_query_impl(req, off, res, sizeof(res), "", 0,
                                         "127.0.0.1", &comp_ctx, false, &rrl, NULL, &cfg, &matched);
    assert(res_len >= 12);
    uint8_t rcode = res[3] & 0x0F;
    assert(rcode == 1); // FORMERR (1) per RFC 10029 §3.3
    printf("  -> MQTYPE QDCOUNT=0 FORMERR passed.\n");
}

static void test_resolve_name_servfail_rcode_clearing(void) {
    printf("[TEST] Query Engine: resolve_name() SERVFAIL and CNAME resolution...\n");
    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain) - 1);

    zone_arena_t *empty_zone = NULL;
    zone_db_entry_t *db_entry_ptr = &db_entry;
    zone_arena_t **zone_ptr = &empty_zone;

    uint8_t res[512] = {0};
    res[3] = 0x83; // Pre-set RCODE=3 (NXDOMAIN)
    uint16_t offset = 12, ancount = 0, nscount = 0, arcount = 0;
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);

    uint16_t qtype = 1;
    resolve_name("example.com.", 1, &qtype, 1,
                 &db_entry_ptr, zone_ptr, res,
                 sizeof(res), &offset, &comp_ctx,
                 &ancount, &nscount, &arcount,
                 false, false, 0, false, NULL, NULL,
                 "127.0.0.1", NULL, false, NULL, 0, 0, NULL);
    assert((res[3] & 0x0F) == 2); // Exactly SERVFAIL (2)

    // CNAME loop / chain test
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
    int p_res = parse_zone_fast(loop_zone, strlen(loop_zone), &loop_arena, &ctx);
    assert(p_res >= 0);
    int b_res = build_zone_index(&loop_arena, true);
    assert(b_res == 0);

    zone_arena_t *current_zone = &loop_arena;
    zone_ptr = &current_zone;

    memset(res, 0, sizeof(res));
    res[3] = 0x83; // Pre-set RCODE=3
    offset = 12; ancount = 0; nscount = 0; arcount = 0;
    compress_ctx_init_packet(&comp_ctx);

    resolve_name("loop.example.com.", 1, &qtype, 1,
                 &db_entry_ptr, zone_ptr, res,
                 sizeof(res), &offset, &comp_ctx,
                 &ancount, &nscount, &arcount,
                 false, false, 0, false, NULL, NULL,
                 "127.0.0.1", NULL, false, NULL, 0, 0, NULL);
    assert((res[3] & 0x0F) == 0 && ancount == 1);

    zone_arena_destroy(&loop_arena);
    printf("  -> resolve_name() SERVFAIL and CNAME resolution passed.\n");
}

static void test_response_section_order(void) {
    printf("[TEST] Query Engine: Response section ordering (Answer before Additional)...\n");
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
    char zone_text[] = "example.com. 1800 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 1800\n"
                       "example.com. 1800 IN NS ns1.example.com.\n"
                       "example.com. 1800 IN NS ns2.v6.example.com.\n"
                       "example.com. 1800 IN NS ns3.v6.example.com.\n"
                       "ns1.example.com. 1800 IN A 192.0.2.1\n"
                       "ns2.v6.example.com. 1800 IN AAAA 2001:db8:1::1\n"
                       "ns2.v6.example.com. 1800 IN A 192.0.2.2\n"
                       "ns3.v6.example.com. 1800 IN AAAA 2001:db8:2::1\n"
                       "ns3.v6.example.com. 1800 IN A 192.0.2.3\n";
    int p_res = parse_zone_fast(zone_text, strlen(zone_text), &arena, &ctx);
    assert(p_res >= 0);
    int b_res = build_zone_index(&arena, true);
    assert(b_res == 0);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strncpy(db_entry.domain, "example.com.", sizeof(db_entry.domain) - 1);
    atomic_store_explicit(&db_entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *db_entry_ptr = &db_entry;
    zone_arena_t *cur_zone = &arena;
    zone_arena_t **zone_ptr = &cur_zone;

    uint8_t res[1024];
    memset(res, 0, sizeof(res));
    uint16_t offset = 12;
    uint16_t ancount = 0, nscount = 0, arcount = 0;
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);

    uint16_t qtype = 2; // NS
    resolve_name("example.com.", 1, &qtype, 1,
                 &db_entry_ptr, zone_ptr, res,
                 sizeof(res), &offset, &comp_ctx,
                 &ancount, &nscount, &arcount,
                 false, false, 0, false, NULL, NULL,
                 "127.0.0.1", NULL, false, NULL, 0, 0, NULL);

    assert(ancount == 3 && nscount == 0 && arcount == 5);

    size_t parse_off = 12;
    for (int i = 0; i < ancount; i++) {
        dns_record_t rec;
        uint16_t rtype = 0;
        int pr_rc = parse_resource_record(res, offset, &parse_off, &arena, &rec, &rtype);
        assert(pr_rc >= 0);
        assert(rtype == 2); // Must be NS
    }

    for (int i = 0; i < arcount; i++) {
        dns_record_t rec;
        uint16_t rtype = 0;
        int pr_rc = parse_resource_record(res, offset, &parse_off, &arena, &rec, &rtype);
        assert(pr_rc >= 0);
        assert(rtype == 1 || rtype == 28); // Must be A or AAAA
    }

    zone_arena_destroy(&arena);
    printf("  -> Response section ordering passed.\n");
}

static void test_parse_query_question_fast_cases(void) {
    printf("[TEST] Wire: parse_query_question_fast() comprehensive tests...\n");

    char qname[256];
    uint16_t qtype = 0, qclass = 0;
    size_t qend = 0;

    // 1. Normal standard domain "www.example.com."
    uint8_t pkt1[64] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Header
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // QNAME
        0x00, 0x01, // QTYPE=A
        0x00, 0x01  // QCLASS=IN
    };
    bool ok = parse_query_question_fast(pkt1, 12 + 17 + 4, qname, sizeof(qname), &qtype, &qclass, &qend);
    assert(ok == true);
    assert(strcmp(qname, "www.example.com.") == 0);
    assert(qtype == 1);
    assert(qclass == 1);
    assert(qend == 12 + 17 + 4);

    // 2. Root domain "."
    uint8_t pkt2[64] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0, // Root QNAME
        0x00, 0x02, // QTYPE=NS
        0x00, 0x01  // QCLASS=IN
    };
    ok = parse_query_question_fast(pkt2, 12 + 1 + 4, qname, sizeof(qname), &qtype, &qclass, &qend);
    assert(ok == true);
    assert(strcmp(qname, ".") == 0);
    assert(qtype == 2);
    assert(qclass == 1);
    assert(qend == 12 + 1 + 4);

    // 3. Domain with escaped dot and backslash
    uint8_t pkt3[64] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4, 'a', '.', 'b', '\\', 3, 'c', 'o', 'm', 0,
        0x00, 0x10, // TXT
        0x00, 0x01
    };
    ok = parse_query_question_fast(pkt3, 12 + 10 + 4, qname, sizeof(qname), &qtype, &qclass, &qend);
    assert(ok == true);
    assert(strcmp(qname, "a\\.b\\\\.com.") == 0);
    assert(qtype == 16);

    // 4. Truncated / malformed packet (length < 12)
    ok = parse_query_question_fast(pkt1, 10, qname, sizeof(qname), &qtype, &qclass, &qend);
    assert(ok == false);

    // 5. Malformed label length exceeding packet bounds
    uint8_t pkt_bad[64] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        50, 'a', 'b', 'c' // claims 50 bytes, only 3 present
    };
    ok = parse_query_question_fast(pkt_bad, 16, qname, sizeof(qname), &qtype, &qclass, &qend);
    assert(ok == false);

    printf("  -> parse_query_question_fast() tests passed.\n");
}

static void test_cname_loop_and_max_depth(void) {
    printf("[TEST] Query Engine: CNAME loop & recursion limit (depth >= 16)...\n");

    zone_arena_t arena;
    zone_arena_init(&arena);
    arena.records = calloc(8, sizeof(dns_record_t));
    arena.records_cap = 8;

    // CNAME a.loop. -> b.loop.
    dns_record_t c1;
    memset(&c1, 0, sizeof(c1));
    c1.name = arena_strdup(&arena, "a.loop.example.");
    c1.type = arena_strdup(&arena, "CNAME");
    c1.type_code = 5;
    c1.ttl = arena_strdup(&arena, "300");
    c1.ttl_value = 300;
    c1.class_str = arena_strdup(&arena, "IN");
    c1.class_val = 1;
    c1.rdata_count = 1;
    c1.rdata[0] = arena_strdup(&arena, "b.loop.example.");
    arena.records[0] = c1;

    // CNAME b.loop. -> a.loop. (Circular loop)
    dns_record_t c2;
    memset(&c2, 0, sizeof(c2));
    c2.name = arena_strdup(&arena, "b.loop.example.");
    c2.type = arena_strdup(&arena, "CNAME");
    c2.type_code = 5;
    c2.ttl = arena_strdup(&arena, "300");
    c2.ttl_value = 300;
    c2.class_str = arena_strdup(&arena, "IN");
    c2.class_val = 1;
    c2.rdata_count = 1;
    c2.rdata[0] = arena_strdup(&arena, "a.loop.example.");
    arena.records[1] = c2;

    arena.count = 2;
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "loop.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 1;
    view.hash_table = hash_tbl;
    view.hash_size = 2;
    view.chain_next = chain_nxt;

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    uint8_t qbuf[512];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1122, "a.loop.example.", 1, false);

    uint8_t rbuf[4096];
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);

    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched_entry = NULL;

    int res_len = process_dns_query_impl(qbuf, qlen, rbuf, sizeof(rbuf),
                                         "a.loop.example.", 1,
                                         "127.0.0.1", &comp_ctx,
                                         false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= 12);
    uint8_t rcode = rbuf[3] & 0x0F;
    assert(rcode == 2 || rcode == 0); // SERVFAIL or terminated CNAME chain

    zone_arena_destroy(&arena);
    printf("  -> CNAME loop & recursion limit passed.\n");
}

static void test_prelink_zone_additional_glue_policies(void) {
    printf("[TEST] Snapshot RCU: prelink_zone_additional_glue policies...\n");

    zone_arena_t arena;
    zone_arena_init(&arena);
    arena.records = calloc(8, sizeof(dns_record_t));
    arena.records_cap = 8;

    // SOA
    dns_record_t soa;
    memset(&soa, 0, sizeof(soa));
    soa.name = arena_strdup(&arena, "glue.example.");
    soa.type = arena_strdup(&arena, "SOA");
    soa.type_code = 6;
    soa.ttl = arena_strdup(&arena, "3600");
    soa.ttl_value = 3600;
    soa.class_str = arena_strdup(&arena, "IN");
    soa.class_val = 1;
    soa.rdata_count = 3;
    soa.rdata[0] = arena_strdup(&arena, "ns1.glue.example.");
    soa.rdata[1] = arena_strdup(&arena, "hostmaster.glue.example.");
    soa.rdata[2] = arena_strdup(&arena, "1");
    arena.records[0] = soa;

    // NS record pointing to in-bailiwick ns1.glue.example.
    dns_record_t ns;
    memset(&ns, 0, sizeof(ns));
    ns.name = arena_strdup(&arena, "glue.example.");
    ns.type = arena_strdup(&arena, "NS");
    ns.type_code = 2;
    ns.ttl = arena_strdup(&arena, "3600");
    ns.ttl_value = 3600;
    ns.class_str = arena_strdup(&arena, "IN");
    ns.class_val = 1;
    ns.rdata_count = 1;
    ns.rdata[0] = arena_strdup(&arena, "ns1.glue.example.");
    arena.records[1] = ns;

    // MX record pointing to mail.glue.example.
    dns_record_t mx;
    memset(&mx, 0, sizeof(mx));
    mx.name = arena_strdup(&arena, "glue.example.");
    mx.type = arena_strdup(&arena, "MX");
    mx.type_code = 15;
    mx.ttl = arena_strdup(&arena, "3600");
    mx.ttl_value = 3600;
    mx.class_str = arena_strdup(&arena, "IN");
    mx.class_val = 1;
    mx.rdata_count = 2;
    mx.rdata[0] = arena_strdup(&arena, "10");
    mx.rdata[1] = arena_strdup(&arena, "mail.glue.example.");
    arena.records[2] = mx;

    // A records for ns1 and mail
    dns_record_t a1;
    memset(&a1, 0, sizeof(a1));
    a1.name = arena_strdup(&arena, "ns1.glue.example.");
    a1.type = arena_strdup(&arena, "A");
    a1.type_code = 1;
    a1.ttl = arena_strdup(&arena, "3600");
    a1.ttl_value = 3600;
    a1.class_str = arena_strdup(&arena, "IN");
    a1.class_val = 1;
    a1.rdata_count = 1;
    a1.rdata[0] = arena_strdup(&arena, "192.0.2.53");
    arena.records[3] = a1;

    dns_record_t a2;
    memset(&a2, 0, sizeof(a2));
    a2.name = arena_strdup(&arena, "mail.glue.example.");
    a2.type = arena_strdup(&arena, "A");
    a2.type_code = 1;
    a2.ttl = arena_strdup(&arena, "3600");
    a2.ttl_value = 3600;
    a2.class_str = arena_strdup(&arena, "IN");
    a2.class_val = 1;
    a2.rdata_count = 1;
    a2.rdata[0] = arena_strdup(&arena, "192.0.2.25");
    arena.records[4] = a2;

    arena.count = 5;
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "glue.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 1;
    view.hash_table = hash_tbl;
    view.hash_size = 2;
    view.chain_next = chain_nxt;

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    // 1. Policy NO
    prelink_zone_additional_glue(&arena, "glue.example.", &snap, &view, ADDITIONAL_AUTH_NO);
    assert(arena.prelinked_glue == NULL);

    // 2. Policy YES
    prelink_zone_additional_glue(&arena, "glue.example.", &snap, &view, ADDITIONAL_AUTH_YES);
    assert(arena.prelinked_glue != NULL);
    assert(arena.prelinked_glue_count >= 1);

    zone_arena_destroy(&arena);
    printf("  -> prelink_zone_additional_glue policies passed.\n");
}

// ----------------------------------------------------------------------------
// 11. NSEC3 Hashing, Interval Coverage & Tree Search Tests
// ----------------------------------------------------------------------------
static void test_nsec3_hashing_and_intervals(void) {
    printf("[TEST] Query Engine: NSEC3 canonical wire, SHA1 hashing & interval coverage...\n");

    // 1. name_to_canonical_wire
    uint8_t wire[256];
    size_t wlen = name_to_canonical_wire("WwW.ExAmPlE.CoM.", wire, sizeof(wire));
    assert(wlen == 17); // 1+3 + 1+7 + 1+3 + 1
    assert(wire[0] == 3 && memcmp(wire + 1, "www", 3) == 0);
    assert(wire[4] == 7 && memcmp(wire + 5, "example", 7) == 0);
    assert(wire[12] == 3 && memcmp(wire + 13, "com", 3) == 0);
    assert(wire[16] == 0); // Root label

    // Error conditions
    assert(name_to_canonical_wire(NULL, wire, sizeof(wire)) == 0);
    assert(name_to_canonical_wire("example.com.", wire, 2) == 0); // Buffer too small

    // 2. compute_nsec3_hash
    char b32_out[128];
    uint8_t salt[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    bool ok = compute_nsec3_hash("example.com.", 1 /* SHA-1 */, 10 /* iterations */,
                                salt, sizeof(salt), b32_out, sizeof(b32_out));
    assert(ok == true);
    assert(strlen(b32_out) > 0);

    // Unsupported algorithm
    assert(compute_nsec3_hash("example.com.", 2, 1, salt, sizeof(salt), b32_out, sizeof(b32_out)) == false);

    // 3. nsec3_covers_hash
    // Standard interval: owner="1000", next="3000"
    assert(nsec3_covers_hash("1000", "3000", "2000") == true);
    assert(nsec3_covers_hash("1000", "3000", "0500") == false);
    assert(nsec3_covers_hash("1000", "3000", "4000") == false);

    // Wrap-around interval: owner="8000", next="2000"
    assert(nsec3_covers_hash("8000", "2000", "9000") == true);
    assert(nsec3_covers_hash("8000", "2000", "1000") == true);
    assert(nsec3_covers_hash("8000", "2000", "5000") == false);

    // Single record (owner == next): covers all except owner
    assert(nsec3_covers_hash("5000", "5000", "1000") == true);
    assert(nsec3_covers_hash("5000", "5000", "5000") == false);

    // NULL edge cases
    assert(nsec3_covers_hash(NULL, "2000", "1000") == false);

    // 4. find_next_closer_name
    char closer[256];
    assert(find_next_closer_name("sub.host.example.com.", "example.com.", closer, sizeof(closer)) == true);
    assert(strcmp(closer, "host.example.com") == 0);

    assert(find_next_closer_name("host.example.com.", "example.com.", closer, sizeof(closer)) == true);
    assert(strcmp(closer, "host.example.com") == 0);

    // Negative find_next_closer_name
    assert(find_next_closer_name("example.com.", "example.com.", closer, sizeof(closer)) == false);
    assert(find_next_closer_name("other.org.", "example.com.", closer, sizeof(closer)) == false);

    // 5. NSEC3 matching & covering in zone arena
    zone_arena_t arena;
    zone_arena_init(&arena);
    arena.records = calloc(8, sizeof(dns_record_t));
    arena.records_cap = 8;

    dns_record_t nsec3_rec;
    memset(&nsec3_rec, 0, sizeof(nsec3_rec));
    nsec3_rec.name = arena_strdup(&arena, "00000000000000000000000000000000.example.com.");
    nsec3_rec.type = arena_strdup(&arena, "NSEC3");
    nsec3_rec.type_code = 50;
    nsec3_rec.ttl = arena_strdup(&arena, "3600");
    nsec3_rec.ttl_value = 3600;
    nsec3_rec.class_str = arena_strdup(&arena, "IN");
    nsec3_rec.class_val = 1;
    nsec3_rec.rdata_count = 6;
    nsec3_rec.rdata[0] = arena_strdup(&arena, "1"); // Hash algo SHA-1
    nsec3_rec.rdata[1] = arena_strdup(&arena, "0"); // Flags
    nsec3_rec.rdata[2] = arena_strdup(&arena, "1"); // Iterations
    nsec3_rec.rdata[3] = arena_strdup(&arena, "-"); // Salt
    nsec3_rec.rdata[4] = arena_strdup(&arena, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"); // Next hash
    nsec3_rec.rdata[5] = arena_strdup(&arena, "A"); // Type bitmap
    arena.records[0] = nsec3_rec;
    arena.count = 1;
    build_zone_index(&arena, true);

    dns_record_t *matched = find_matching_nsec3(&arena, "00000000000000000000000000000000", "example.com.");
    assert(matched != NULL);
    assert(matched->type_code == 50);

    dns_record_t *covering = find_covering_nsec3(&arena, "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM");
    assert(covering != NULL);

    // 6. attach_nsec3_record
    uint8_t res_buf[512];
    uint16_t offset = 12;
    compress_ctx_t comp_ctx;
    compress_ctx_init_packet(&comp_ctx);
    uint16_t nscount = 0;
    dns_record_t *attached[8] = {0};
    int attached_count = 0;

    bool attached_ok = attach_nsec3_record(&arena, matched, res_buf, sizeof(res_buf),
                                           &offset, &comp_ctx, &nscount,
                                           attached, &attached_count);
    assert(attached_ok == true);
    assert(nscount == 1);
    assert(attached_count == 1);

    zone_arena_destroy(&arena);
    printf("  -> NSEC3 hashing, interval coverage & tree search passed.\n");
}

// ----------------------------------------------------------------------------
// 12. Delegation Referral & RFC 4035 DS Query Exception Tests
// ----------------------------------------------------------------------------
static void test_delegation_referral_and_ds_handling(void) {
    printf("[TEST] Query Engine: Delegation NS referral & DS query handling...\n");

    zone_arena_t arena;
    zone_arena_init(&arena);
    arena.records = calloc(8, sizeof(dns_record_t));
    arena.records_cap = 8;

    // Apex SOA
    dns_record_t soa;
    memset(&soa, 0, sizeof(soa));
    soa.name = arena_strdup(&arena, "example.com.");
    soa.type = arena_strdup(&arena, "SOA");
    soa.type_code = 6;
    soa.ttl = arena_strdup(&arena, "3600");
    soa.ttl_value = 3600;
    soa.class_str = arena_strdup(&arena, "IN");
    soa.class_val = 1;
    soa.rdata_count = 3;
    soa.rdata[0] = arena_strdup(&arena, "ns1.example.com.");
    soa.rdata[1] = arena_strdup(&arena, "hostmaster.example.com.");
    soa.rdata[2] = arena_strdup(&arena, "1");
    arena.records[0] = soa;

    // Subdelegation NS: child.example.com. NS ns1.child.example.com.
    dns_record_t ns_del;
    memset(&ns_del, 0, sizeof(ns_del));
    ns_del.name = arena_strdup(&arena, "child.example.com.");
    ns_del.type = arena_strdup(&arena, "NS");
    ns_del.type_code = 2;
    ns_del.ttl = arena_strdup(&arena, "3600");
    ns_del.ttl_value = 3600;
    ns_del.class_str = arena_strdup(&arena, "IN");
    ns_del.class_val = 1;
    ns_del.rdata_count = 1;
    ns_del.rdata[0] = arena_strdup(&arena, "ns1.child.example.com.");
    arena.records[1] = ns_del;

    // Glue A: ns1.child.example.com. A 192.0.2.123
    dns_record_t glue;
    memset(&glue, 0, sizeof(glue));
    glue.name = arena_strdup(&arena, "ns1.child.example.com.");
    glue.type = arena_strdup(&arena, "A");
    glue.type_code = 1;
    glue.ttl = arena_strdup(&arena, "3600");
    glue.ttl_value = 3600;
    glue.class_str = arena_strdup(&arena, "IN");
    glue.class_val = 1;
    glue.rdata_count = 1;
    glue.rdata[0] = arena_strdup(&arena, "192.0.2.123");
    arena.records[2] = glue;

    arena.count = 3;
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 1;
    view.hash_table = hash_tbl;
    view.hash_size = 2;
    view.chain_next = chain_nxt;

    // 1. Regular query under delegated zone: www.child.example.com. -> Returns referral (delegation)
    uint8_t res[512] = {0};
    uint16_t offset = 12;
    compress_ctx_t comp_ctx;
    compress_ctx_init_packet(&comp_ctx);
    uint16_t nscount = 0;
    uint16_t arcount = 0;

    bool del_res = find_delegation(&arena, "www.child.example.com.", calc_fnv1a_str("www.child.example.com."),
                                   "example.com.", res, sizeof(res), &offset,
                                   &comp_ctx, &nscount, &arcount, false /* not DS */,
                                   NULL, NULL, NULL, ADDITIONAL_AUTH_YES, &view, false);
    assert(del_res == true);
    assert(nscount >= 1); // NS in authority section
    assert(arcount >= 1); // Glue A in additional section

    // 2. DS query directly at delegation point: child.example.com. DS -> Returns false (continues to auth lookup)
    offset = 12;
    compress_ctx_init_packet(&comp_ctx);
    nscount = 0;
    arcount = 0;
    del_res = find_delegation(&arena, "child.example.com.", calc_fnv1a_str("child.example.com."),
                              "example.com.", res, sizeof(res), &offset,
                              &comp_ctx, &nscount, &arcount, true /* is DS query */,
                              NULL, NULL, NULL, ADDITIONAL_AUTH_YES, &view, false);
    assert(del_res == false); // Must return false so DS is handled as authoritative answer/NODATA

    zone_arena_destroy(&arena);
    printf("  -> Delegation referral & DS query handling passed.\n");
}

// ----------------------------------------------------------------------------
// 13. Program Plugins & Forward Zone Helper Tests
// ----------------------------------------------------------------------------
static void test_program_plugins_and_forward_zone_helpers(void) {
    printf("[TEST] Query Engine: Program plugin & forward zone helpers...\n");

    // 1. compute_program_zone_fingerprint
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "dynamic.prog.";
    zcfg.type = "program";
    zcfg.program_path = "/usr/local/bin/test_plugin";
    zcfg.program_user = "bind";
    zcfg.program_timeout_ms = 1500;
    zcfg.program_max_failures = 3;
    const char *args[2] = {"--zone=dynamic.prog", "--debug"};
    zcfg.program_args = (char **)args;
    zcfg.program_args_count = 2;

    char fp[256];
    compute_program_zone_fingerprint(&zcfg, fp, sizeof(fp));
    assert(strstr(fp, "path=/usr/local/bin/test_plugin") != NULL);
    assert(strstr(fp, "user=bind") != NULL);
    assert(strstr(fp, "timeout=1500") != NULL);
    assert(strstr(fp, "--zone=dynamic.prog;") != NULL);

    // 2. build_synthetic_servfail
    uint8_t qpkt[512];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0xABCD, "broken.prog.", 1, false);

    uint8_t servfail_res[512];
    int sf_len = build_synthetic_servfail(qpkt, qlen, servfail_res, sizeof(servfail_res));
    assert(sf_len >= (int)DNS_HEADER_SIZE);
    assert(servfail_res[0] == 0xAB && servfail_res[1] == 0xCD); // Matching txid
    assert((servfail_res[2] & 0x80) != 0); // QR=1
    assert((servfail_res[3] & 0x0F) == 2);  // RCODE=2 (SERVFAIL)

    // 3. question_section_matches
    uint8_t resp_pkt[512];
    size_t rlen = 0;
    build_dns_query(resp_pkt, &rlen, 0xABCD, "BrOkEn.PrOg.", 1, false);
    assert(question_section_matches(resp_pkt, rlen, qpkt, qlen) == true); // Case-insensitive match

    // Mismatched QTYPE
    uint8_t resp_mismatch[512];
    size_t rlen2 = 0;
    build_dns_query(resp_mismatch, &rlen2, 0xABCD, "broken.prog.", 28 /* AAAA */, false);
    assert(question_section_matches(resp_mismatch, rlen2, qpkt, qlen) == false);

    // 4. write_all_timeout & read_all_timeout via pipe
    int pfd[2];
    int r_pipe = pipe(pfd);
    assert(r_pipe == 0);

    const char *test_msg = "KARIDNS_PIPE_TEST_MSG";
    ssize_t nw = write_all_timeout(pfd[1], (const uint8_t *)test_msg, strlen(test_msg), 1000);
    assert(nw == (ssize_t)strlen(test_msg));

    char rbuf[64] = {0};
    ssize_t nr = read_all_timeout(pfd[0], (uint8_t *)rbuf, strlen(test_msg), 1000);
    assert(nr == (ssize_t)strlen(test_msg));
    assert(strcmp(rbuf, test_msg) == 0);

    close(pfd[0]);
    close(pfd[1]);

    // 5. monotonic_ms & remaining_ms
    int64_t t1 = monotonic_ms();
    assert(t1 > 0);
    int64_t future_deadline = t1 + 500;
    assert(remaining_ms(future_deadline) > 0);
    int64_t past_deadline = t1 - 100;
    assert(remaining_ms(past_deadline) == 0);

    // 6. dispatch_to_program_zone with no plugin registered -> returns synthetic SERVFAIL
    uint8_t prog_res[512];
    int pr_len = dispatch_to_program_zone("unregistered.prog.", qpkt, qlen, prog_res, sizeof(prog_res), "127.0.0.1", false);
    assert(pr_len > 0);
    assert((prog_res[3] & 0x0F) == 2); // SERVFAIL

    // 7. dispatch_forward_zone with 0 forwarders -> returns synthetic SERVFAIL
    zone_config_t fwd_cfg;
    memset(&fwd_cfg, 0, sizeof(fwd_cfg));
    fwd_cfg.domain = "forward.example.";
    fwd_cfg.type = "forward";
    fwd_cfg.forwarders_count = 0;

    int fwd_len = dispatch_forward_zone(&fwd_cfg, qpkt, qlen, prog_res, sizeof(prog_res));
    assert(fwd_len > 0);
    assert((prog_res[3] & 0x0F) == 2); // SERVFAIL

    // 8. spawn_program_zone_plugins with no program zones
    server_config_t no_prog_cfg;
    memset(&no_prog_cfg, 0, sizeof(no_prog_cfg));
    spawn_program_zone_plugins(&no_prog_cfg);

    // 9. spawn_one_program_plugin with NULL path -> false
    zone_config_t null_prog_cfg;
    memset(&null_prog_cfg, 0, sizeof(null_prog_cfg));
    null_prog_cfg.domain = "null.prog.";
    program_plugin_t null_out;
    assert(spawn_one_program_plugin(&null_prog_cfg, &null_out) == false);

    // 10. nsec_covers_name & find_covering_nsec
    zone_arena_t nsec_arena;
    zone_arena_init(&nsec_arena);
    dns_record_t nsec1; memset(&nsec1, 0, sizeof(nsec1));
    nsec1.name = arena_strdup(&nsec_arena, "a.example.");
    nsec1.type_code = 47;
    nsec1.rdata_count = 1;
    nsec1.rdata[0] = arena_strdup(&nsec_arena, "m.example.");

    dns_record_t nsec2; memset(&nsec2, 0, sizeof(nsec2));
    nsec2.name = arena_strdup(&nsec_arena, "m.example.");
    nsec2.type_code = 47;
    nsec2.rdata_count = 1;
    nsec2.rdata[0] = arena_strdup(&nsec_arena, "a.example."); // wrap-around

    assert(nsec_covers_name(&nsec1, "b.example.") == true);
    assert(nsec_covers_name(&nsec1, "z.example.") == false);
    assert(nsec_covers_name(&nsec2, "z.example.") == true); // wrap-around covers z
    assert(nsec_covers_name(NULL, "b.example.") == false);

    nsec_arena.records = calloc(2, sizeof(dns_record_t));
    nsec_arena.records[0] = nsec1;
    nsec_arena.records[1] = nsec2;
    nsec_arena.count = 2;

    dns_record_t *cov = find_covering_nsec(&nsec_arena, "b.example.");
    assert(cov != NULL && strcmp(cov->name, "a.example.") == 0);

    dns_record_t *cov_wrap = find_covering_nsec(&nsec_arena, "z.example.");
    assert(cov_wrap != NULL && strcmp(cov_wrap->name, "m.example.") == 0);

    assert(find_covering_nsec(NULL, "b.example.") == NULL);
    assert(find_covering_nsec(&nsec_arena, NULL) == NULL);

    zone_arena_destroy(&nsec_arena);

    printf("  -> Program plugin & forward zone helpers passed.\n");
}

static void test_query_engine_helpers_and_edge_cases(void) {
    printf("[TEST] Query Engine: helper functions, checkpoints, glue & observatory...\n");

    // 1. restore_checkpoint
    resolve_checkpoint_t cp = { 123, 1, 2, 3 };
    uint16_t off = 999, an = 9, ns = 8, ar = 7;
    restore_checkpoint(&cp, &off, &an, &ns, &ar);
    assert(off == 123 && an == 1 && ns == 2 && ar == 3);

    // 2. tinydns_record_currently_valid
    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.ttl_value = 300;
    uint32_t eff_ttl = 0;
    time_t now = 1700000000;

    // Location mismatch / match
    rec.tinydns_loc[0] = 'u'; rec.tinydns_loc[1] = 's';
    assert(tinydns_record_currently_valid(&rec, now, "jp", NULL, NULL, &eff_ttl) == false);
    assert(tinydns_record_currently_valid(&rec, now, "us", NULL, NULL, &eff_ttl) == true);
    rec.tinydns_loc[0] = 0; rec.tinydns_loc[1] = 0;

    // ECS tag mismatch / match
    rec.ecs_subnet_tag = "tagA";
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == false);
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", "tagB", NULL, &eff_ttl) == false);
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", "tagA", NULL, &eff_ttl) == true);
    rec.ecs_subnet_tag = NULL;

    // BIND location tag mismatch / match
    rec.bind_location_tag = "locX";
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == false);
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, "locY", &eff_ttl) == false);
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, "locX", &eff_ttl) == true);
    rec.bind_location_tag = NULL;

    // Timestamp countdown: future activation (ttd >= now)
    rec.tinydns_ttd = now + 100;
    rec.tinydns_ttl_countdown = false;
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == false);

    // Timestamp countdown: past activation (ttd < now)
    rec.tinydns_ttd = now - 100;
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == true);
    assert(eff_ttl == 300);

    // Countdown TTL: expired
    rec.tinydns_ttl_countdown = true;
    rec.tinydns_ttd = now - 10;
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == false);

    // Countdown TTL: remaining < 2s clamped to 2s
    rec.tinydns_ttd = now + 1;
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == true);
    assert(eff_ttl == 2);

    // Countdown TTL: remaining > 3600s clamped to 3600s
    rec.tinydns_ttd = now + 5000;
    assert(tinydns_record_currently_valid(&rec, now, "\0\0", NULL, NULL, &eff_ttl) == true);
    assert(eff_ttl == 3600);

    // 3. collect_additional_rr_glue
    const char *glue_targets[16] = {0};
    int glue_count = 0;

    // Minimal responses flag disables collection
    collect_additional_rr_glue(&rec, glue_targets, &glue_count, true);
    assert(glue_count == 0);

    // MX record
    dns_record_t mx_rec;
    memset(&mx_rec, 0, sizeof(mx_rec));
    mx_rec.type_code = 15;
    mx_rec.rdata[0] = "10";
    mx_rec.rdata[1] = "mail.example.com.";
    mx_rec.rdata_count = 2;
    collect_additional_rr_glue(&mx_rec, glue_targets, &glue_count, false);
    assert(glue_count == 1);
    assert(strcmp(glue_targets[0], "mail.example.com.") == 0);

    // Duplicate MX target ignored
    collect_additional_rr_glue(&mx_rec, glue_targets, &glue_count, false);
    assert(glue_count == 1);

    // SRV record
    dns_record_t srv_rec;
    memset(&srv_rec, 0, sizeof(srv_rec));
    srv_rec.type_code = 33;
    srv_rec.rdata[0] = "0";
    srv_rec.rdata[1] = "5";
    srv_rec.rdata[2] = "5060";
    srv_rec.rdata[3] = "sip.example.com.";
    srv_rec.rdata_count = 4;
    collect_additional_rr_glue(&srv_rec, glue_targets, &glue_count, false);
    assert(glue_count == 2);
    assert(strcmp(glue_targets[1], "sip.example.com.") == 0);

    // NS record
    dns_record_t ns_rec;
    memset(&ns_rec, 0, sizeof(ns_rec));
    ns_rec.type_code = 2;
    ns_rec.rdata[0] = "ns1.example.com.";
    ns_rec.rdata_count = 1;
    collect_additional_rr_glue(&ns_rec, glue_targets, &glue_count, false);
    assert(glue_count == 3);

    // 4. append_glue_records NO-OP paths
    uint8_t dummy_res[512];
    uint16_t dummy_off = 0, dummy_ar = 0;
    compress_ctx_t comp;
    compress_ctx_init(&comp);
    assert(append_glue_records(NULL, "target.com.", "apex.com.", dummy_res, sizeof(dummy_res), &dummy_off, &comp, &dummy_ar, "\0\0", NULL, NULL, ADDITIONAL_AUTH_NO, NULL) == true);

    // 5. record_observatory_response
    zone_db_entry_t obs_entry;
    memset(&obs_entry, 0, sizeof(obs_entry));
    record_observatory_response(NULL, 0, 1);
    record_observatory_response(&obs_entry, 0, 1); // noerror
    assert(atomic_load_explicit(&obs_entry.observatory.responses_noerror, memory_order_relaxed) == 1);
    record_observatory_response(&obs_entry, 0, 0); // nodata
    assert(atomic_load_explicit(&obs_entry.observatory.responses_nodata, memory_order_relaxed) == 1);
    record_observatory_response(&obs_entry, 3, 0); // nxdomain
    assert(atomic_load_explicit(&obs_entry.observatory.responses_nxdomain, memory_order_relaxed) == 1);
    record_observatory_response(&obs_entry, 2, 0); // servfail
    assert(atomic_load_explicit(&obs_entry.observatory.responses_servfail, memory_order_relaxed) == 1);
    record_observatory_response(&obs_entry, 5, 0); // refused
    assert(atomic_load_explicit(&obs_entry.observatory.responses_refused, memory_order_relaxed) == 1);

    // 6. select_view
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.view_count = 2;
    view_snapshot_t views[2];
    memset(views, 0, sizeof(views));
    views[0].name = "internal";
    char *internal_cidr[1] = { "192.168.1.0/24" };
    views[0].match_clients = internal_cidr;
    views[0].match_clients_count = 1;

    views[1].name = "default";
    views[1].match_clients = NULL;
    views[1].match_clients_count = 0;
    snap.views = views;

    view_snapshot_t *sel1 = select_view(&snap, "192.168.1.50");
    assert(sel1 == &views[0]);

    view_snapshot_t *sel2 = select_view(&snap, "203.0.113.1");
    assert(sel2 == &views[1]);


    // 7. build_zone_response_cache
    zone_arena_t test_arena;
    zone_arena_init(&test_arena);
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.wire_cache_max_records = 100;
    build_zone_response_cache(&test_arena, &cfg, "example.com.");
    zone_arena_destroy(&test_arena);

    printf("  -> Query engine helpers & edge cases passed.\n");
}

int main(void) {
    printf("=== Starting Expanded Query Engine Unit Tests ===\n");
    test_all_rr_types_and_resolution();
    test_dnssec_negative_and_delegation_proofs();
    test_tinydns_timestamp_countdown();
    test_mqtype_truncation();
    test_mqtype_qdcount0_formerr();
    test_resolve_name_servfail_rcode_clearing();
    test_response_section_order();
    test_parse_query_question_fast_cases();
    test_cname_loop_and_max_depth();
    test_prelink_zone_additional_glue_policies();
    test_nsec3_hashing_and_intervals();
    test_delegation_referral_and_ds_handling();
    test_program_plugins_and_forward_zone_helpers();
    test_query_engine_helpers_and_edge_cases();
    printf("=== All Expanded Query Engine Unit Tests PASSED ===\n");
    return 0;
}



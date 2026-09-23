#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
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
#include "dns_dynamic_update.h"

// Prototypes for internal query engine functions under test
void restore_checkpoint(const resolve_checkpoint_t *cp, uint16_t *offset,
                        uint16_t *ancount, uint16_t *nscount, uint16_t *arcount);
bool nsec_covers_name(const dns_record_t *rec, const char *name);
dns_record_t *find_covering_nsec(zone_arena_t *zone, const char *name);
size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_out);
int64_t monotonic_ms(void);
uint32_t remaining_ms(int64_t deadline);
int build_synthetic_servfail(const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len);
ssize_t write_all_timeout(int fd, const uint8_t *buf, size_t len, uint32_t timeout_ms);
ssize_t read_all_timeout(int fd, uint8_t *buf, size_t len, uint32_t timeout_ms);
int dispatch_to_program_zone(const char *domain, const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len,
                             const char *client_ip, bool is_tcp);
bool question_section_matches(const uint8_t *resp, size_t resp_len,
                              const uint8_t *req, size_t req_len);
int dispatch_forward_zone(zone_config_t *zcfg, const uint8_t *req, size_t req_len,
                          uint8_t *res, size_t max_res_len);
size_t name_to_canonical_wire(const char *name, uint8_t *wire, size_t max_wire);
bool compute_nsec3_hash(const char *name, uint8_t algo, uint16_t iterations,
                        const uint8_t *salt, size_t salt_len,
                        char *out_b32, size_t out_b32_sz);
bool nsec3_covers_hash(const char *owner_hash, const char *next_hash, const char *target_hash);
dns_record_t *find_matching_nsec3(zone_arena_t *zone, const char *hash_b32, const char *apex);
dns_record_t *find_covering_nsec3(zone_arena_t *zone, const char *target_hash);
bool find_next_closer_name(const char *qname, const char *encloser, char *out, size_t out_sz);
bool attach_nsec3_record(zone_arena_t *zone, dns_record_t *rec,
                         uint8_t *res, size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *nscount,
                         dns_record_t **attached, int *attached_count);
bool name_exists_in_zone(zone_arena_t *zone, const char *name, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag);
const char *find_closest_encloser(zone_arena_t *zone, const char *qname, const char *zone_apex, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag);
program_plugin_t *find_program_plugin(const char *domain);
ssize_t forward_via_tcp(const struct sockaddr_storage *ss, size_t ss_len,
                        const uint8_t *query, size_t query_len,
                        uint8_t *resp_out, size_t resp_out_cap,
                        uint32_t timeout_ms);

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
    // The previous assertion here was only strlen(b32_out) > 0, which a wrong hash passes.
    // Check against the published RFC 5155 Appendix A vectors (SHA-1, 12 iterations, salt aabbccdd).
    static const struct { const char *name; const char *hash; } rfc5155_a[] = {
        { "example.",       "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" },
        { "a.example.",     "35mthgpgcu1qg68fab165klnsnk3dpvl" },
        { "ai.example.",    "gjeqe526plbf1g8mklp59enfd789njgi" },
        { "ns1.example.",   "2t7b4g4vsa5smi47k61mv5bv1a22bojr" },
        { "ns2.example.",   "q04jkcevqvmu85r014c7dkba38o0ji5r" },
        { "w.example.",     "k8udemvp1j2f7eg6jebps17vp3n8i58h" },
        { "*.w.example.",   "r53bq7cc2uvmubfu5ocmm6pers9tk9en" },
        { "x.w.example.",   "b4um86eghhds6nea196smvmlo4ors995" },
        { "y.w.example.",   "ji6neoaepv8b5o6k4ev33abha8ht9fgc" },
        { "x.y.w.example.", "2vptu5timamqttgl4luu9kg21e0aor3s" },
        { "xx.example.",    "t644ebqk9bibcna874givr6joj62mlhv" },
        // RFC 5155 Appendix B.1 (name error): next-closer and wildcard hashes
        { "c.x.w.example.",   "0va5bpr2ou0vk0lbqeeljri88laipsfh" },
        { "*.x.w.example.",   "92pqneegtaue7pjatc3l3qnk738c6v5m" },
    };
    for (size_t i = 0; i < sizeof(rfc5155_a) / sizeof(rfc5155_a[0]); i++) {
        memset(b32_out, 0, sizeof(b32_out));
        assert(compute_nsec3_hash(rfc5155_a[i].name, 1, 12, salt, sizeof(salt),
                                  b32_out, sizeof(b32_out)) == true);
        assert(strcasecmp(b32_out, rfc5155_a[i].hash) == 0);
    }
    // Owner-name case must not matter (RFC 5155 §5: canonical lower-case form is hashed)
    assert(compute_nsec3_hash("X.Y.W.EXAMPLE.", 1, 12, salt, sizeof(salt), b32_out, sizeof(b32_out)));
    assert(strcasecmp(b32_out, "2vptu5timamqttgl4luu9kg21e0aor3s") == 0);
    // Independently computed (SHA-1, no salt): iterations = 0, iterations = 1, and the root name
    assert(compute_nsec3_hash("example.com.", 1, 0, NULL, 0, b32_out, sizeof(b32_out)));
    assert(strcasecmp(b32_out, "onib9mgub9h0rml3cdf5bgrj59dkjhvk") == 0);
    assert(compute_nsec3_hash("EXAMPLE.COM.", 1, 1, NULL, 0, b32_out, sizeof(b32_out)));
    assert(strcasecmp(b32_out, "9vq38lj9qs6s1aruer131mbtsfnvek2p") == 0);
    assert(compute_nsec3_hash(".", 1, 0, NULL, 0, b32_out, sizeof(b32_out)));
    assert(strcasecmp(b32_out, "bekjp7dgpvsjukll47bk43i3urmq4u2f") == 0);
    // Characterization: an undersized output buffer never overflows and stays NUL-terminated.
    // (compute_nsec3_hash() currently still returns true with a *truncated* hash; callers must
    //  pass >= 33 bytes. Returning false here would be safer - see report.)
    {
        char guarded[8 + 16];
        memset(guarded, 0x5A, sizeof(guarded));
        assert(compute_nsec3_hash("example.", 1, 12, salt, sizeof(salt), guarded, 8));
        assert(strlen(guarded) == 7);
        assert(strncasecmp(guarded, "0p9mhav", 7) == 0);   // engine emits upper-case base32hex; RFC 4648 §7 is case-insensitive
        for (size_t i = 8; i < sizeof(guarded); i++) assert((unsigned char)guarded[i] == 0x5A);
    }

    // RFC 5155 Appendix B.1 proof structure, expressed with the real hashes:
    //   closest encloser x.w.example.  -> matched by owner b4um86eg...
    //   next closer c.x.w.example.     -> covered by 0p9mhave... -> 2t7b4g4v...
    //   wildcard *.x.w.example.        -> covered by 35mthgpg... -> b4um86eg...
    assert(nsec3_covers_hash("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
                             "0va5bpr2ou0vk0lbqeeljri88laipsfh") == true);
    assert(nsec3_covers_hash("35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995",
                             "92pqneegtaue7pjatc3l3qnk738c6v5m") == true);
    // ...and the closest encloser's own hash is an owner, not "covered" by its predecessor's interval
    assert(nsec3_covers_hash("35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995",
                             "b4um86eghhds6nea196smvmlo4ors995") == false);

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
// RFC 4592 §2.2.1 / §3.3.2 wildcard "golden" test.
// Unlike test_all_rr_types_and_resolution() (which only checks RCODE and
// ANCOUNT >= N), this parses the response and checks owner names, RDATA, the
// AA flag and section placement against the outcomes RFC 4592 prescribes.
// ----------------------------------------------------------------------------
typedef struct {
    char name[256];
    uint16_t type;
    uint32_t ttl;        // for OPT: extended RCODE | version | flags
    size_t rdoff, rdlen;
    int sect;            // 1 = ANSWER, 2 = AUTHORITY, 3 = ADDITIONAL
} gr_rr_t;

typedef struct {
    const uint8_t *msg;
    size_t len;
    uint8_t rcode;
    bool aa;
    uint16_t counts[3];
    gr_rr_t rr[64];
    int nrr;
} gr_resp_t;

// Decodes a (possibly compressed) name at `off`; returns offset after it in the
// original position, or 0 on malformed input. Output has a trailing dot, e.g. "host3.example."
static size_t gr_read_name(const uint8_t *m, size_t len, size_t off, char *out, size_t cap) {
    size_t o = 0, next = 0;
    int jumps = 0;
    bool jumped = false;
    while (1) {
        if (off >= len) return 0;
        uint8_t l = m[off];
        if ((l & 0xC0) == 0xC0) {
            if (off + 1 >= len || ++jumps > 16) return 0;
            if (!jumped) next = off + 2;
            jumped = true;
            off = (size_t)(((l & 0x3F) << 8) | m[off + 1]);
            continue;
        }
        if (l == 0) { if (!jumped) next = off + 1; break; }
        if ((l & 0xC0) != 0 || off + 1 + l > len || o + l + 2 > cap) return 0;
        memcpy(out + o, m + off + 1, l); o += l; out[o++] = '.';
        off += 1u + l;
    }
    if (o == 0) { out[o++] = '.'; }
    out[o] = '\0';
    return next;
}

static bool gr_parse(const uint8_t *m, size_t len, gr_resp_t *r) {
    memset(r, 0, sizeof(*r));
    if (len < 12) return false;
    r->msg = m; r->len = len;
    r->rcode = m[3] & 0x0F;
    r->aa = (m[2] & 0x04) != 0;
    uint16_t qd = (uint16_t)((m[4] << 8) | m[5]);
    r->counts[0] = (uint16_t)((m[6] << 8) | m[7]);
    r->counts[1] = (uint16_t)((m[8] << 8) | m[9]);
    r->counts[2] = (uint16_t)((m[10] << 8) | m[11]);
    size_t off = 12;
    char tmp[256];
    for (uint16_t i = 0; i < qd; i++) {
        off = gr_read_name(m, len, off, tmp, sizeof(tmp));
        if (!off || off + 4 > len) return false;
        off += 4;
    }
    for (int sect = 0; sect < 3; sect++) {
        for (uint16_t i = 0; i < r->counts[sect]; i++) {
            if (r->nrr >= 64) return false;
            gr_rr_t *rr = &r->rr[r->nrr++];
            off = gr_read_name(m, len, off, rr->name, sizeof(rr->name));
            if (!off || off + 10 > len) return false;
            rr->type = (uint16_t)((m[off] << 8) | m[off + 1]);
            rr->ttl = ((uint32_t)m[off + 4] << 24) | ((uint32_t)m[off + 5] << 16) |
                      ((uint32_t)m[off + 6] << 8) | m[off + 7];
            rr->rdlen = (size_t)((m[off + 8] << 8) | m[off + 9]);
            off += 10;
            if (off + rr->rdlen > len) return false;
            rr->rdoff = off;
            rr->sect = sect + 1;
            off += rr->rdlen;
        }
    }
    return true;
}

static int gr_count(const gr_resp_t *r, int sect, int type /* -1 = any */) {
    int n = 0;
    for (int i = 0; i < r->nrr; i++)
        if (r->rr[i].sect == sect && (type < 0 || r->rr[i].type == type)) n++;
    return n;
}

static const gr_rr_t *gr_first(const gr_resp_t *r, int sect, int type) {
    for (int i = 0; i < r->nrr; i++)
        if (r->rr[i].sect == sect && r->rr[i].type == type) return &r->rr[i];
    return NULL;
}

static struct {
    zone_arena_t arena;
    zone_db_entry_t entry;
    zone_db_entry_t *entries[1];
    char *acl[1];
    view_snapshot_t view;
    zone_db_snapshot_t snap;
    server_config_t cfg;
    uint8_t res[4096];
} g_gr;

static void gr_setup(const char *origin, const char *zone_text) {
    memset(&g_gr, 0, sizeof(g_gr));
    zone_arena_init(&g_gr.arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = origin,
                            .is_standalone_mode = true, .err_out = &err };
    // parse_zone_fast() keeps pointers into its input (zero-copy), so the text must
    // live as long as the arena: give it arena lifetime instead of free()ing it.
    char *buf = arena_strdup(&g_gr.arena, zone_text);
    assert(buf != NULL);
    assert(parse_zone_fast(buf, strlen(buf), &g_gr.arena, &ctx) >= 0);
    assert(build_zone_index(&g_gr.arena, true) == 0);
    strncpy(g_gr.entry.domain, origin, sizeof(g_gr.entry.domain) - 1);
    atomic_store_explicit(&g_gr.entry.rcu.active, &g_gr.arena, memory_order_release);
    g_gr.entries[0] = &g_gr.entry;
    g_gr.acl[0] = (char *)"any";
    g_gr.view.name = "default";
    g_gr.view.entries = g_gr.entries;
    g_gr.view.zone_count = 1;
    g_gr.view.match_clients = g_gr.acl;
    g_gr.view.match_clients_count = 1;
    g_gr.snap.views = &g_gr.view;
    g_gr.snap.view_count = 1;
}

static void gr_query_raw(const uint8_t *req, size_t req_len, const char *qname, uint16_t qtype,
                         const char *client_ip, bool is_tcp, gr_resp_t *out);

static void gr_query(const char *qname, uint16_t qtype, bool dnssec_ok, gr_resp_t *out) {
    uint8_t req[512];
    size_t req_len = 0;
    build_dns_query(req, &req_len, 0x4592, qname, qtype, dnssec_ok);
    gr_query_raw(req, req_len, qname, qtype, "192.0.2.100", false, out);
}

static void gr_query_raw(const uint8_t *req, size_t req_len, const char *qname, uint16_t qtype,
                         const char *client_ip, bool is_tcp, gr_resp_t *out) {
    compress_ctx_t comp;
    memset(&comp, 0, sizeof(comp));
    compress_ctx_init_packet(&comp);
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched = NULL;
    int n = process_dns_query_impl(req, req_len, g_gr.res, sizeof(g_gr.res), qname, qtype,
                                   client_ip, &comp, is_tcp, &rrl_out,
                                   &g_gr.snap, &g_gr.cfg, &matched);
    assert(n >= DNS_HEADER_SIZE);
    assert(gr_parse(g_gr.res, (size_t)n, out));
    assert(g_gr.res[0] == 0x45 && g_gr.res[1] == 0x92);   // ID echoed
}

static void gr_expect_txt(const gr_resp_t *r, const gr_rr_t *rr, const char *text) {
    assert(rr->rdlen == 1u + strlen(text));
    assert(r->msg[rr->rdoff] == strlen(text));
    assert(memcmp(r->msg + rr->rdoff + 1, text, strlen(text)) == 0);
}

static void test_rfc4592_wildcard_golden(void) {
    printf("[TEST] Query Engine: RFC 4592 §2.2.1 wildcard golden responses...\n");

    // Example zone from RFC 4592 §2.2.1 (SOA RDATA is left open by the RFC).
    gr_setup("example.",
        "$ORIGIN example.\n"
        "$TTL 3600\n"
        "@                   IN SOA  ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600\n"
        "@                   IN NS   ns.example.com.\n"
        "@                   IN NS   ns.example.net.\n"
        "*                   IN TXT  \"this is a wildcard\"\n"
        "*                   IN MX   10 host1.example.\n"
        "sub.*               IN TXT  \"this is not a wildcard\"\n"
        "host1               IN A    192.0.2.1\n"
        "_ssh._tcp.host1     IN SRV  0 0 80 host1.example.\n"
        "_ssh._tcp.host2     IN SRV  0 0 80 host2.example.\n"
        "subdel              IN NS   ns.example.com.\n"
        "subdel              IN NS   ns.example.net.\n");

    gr_resp_t r;
    const gr_rr_t *rr;

    // --- Synthesized from *.example. ---------------------------------------
    // host3.example. MX -> "host3.example. IN MX ..." (owner is the QNAME, not the wildcard)
    gr_query("host3.example.", 15, false, &r);
    assert(r.rcode == 0 && r.aa);
    assert(gr_count(&r, 1, -1) == 1);
    rr = gr_first(&r, 1, 15);
    assert(rr && strcasecmp(rr->name, "host3.example.") == 0);
    assert(rr->rdlen >= 3 && r.msg[rr->rdoff] == 0 && r.msg[rr->rdoff + 1] == 10);   // preference 10
    {
        char target[256];
        assert(gr_read_name(r.msg, r.len, rr->rdoff + 2, target, sizeof(target)) != 0);
        assert(strcasecmp(target, "host1.example.") == 0);
    }

    // host3.example. A -> NOERROR/NODATA: no A RRset at *.example.
    gr_query("host3.example.", 1, false, &r);
    assert(r.rcode == 0 && r.aa);
    assert(gr_count(&r, 1, -1) == 0);
    assert(gr_count(&r, 2, 6) == 1);                        // SOA in AUTHORITY (RFC 2308)

    // foo.bar.example. TXT -> synthesized although bar.example. does not exist
    gr_query("foo.bar.example.", 16, false, &r);
    assert(r.rcode == 0 && r.aa);
    assert(gr_count(&r, 1, -1) == 1);
    rr = gr_first(&r, 1, 16);
    assert(rr && strcasecmp(rr->name, "foo.bar.example.") == 0);
    gr_expect_txt(&r, rr, "this is a wildcard");

    // _telnet._tcp.host3.example. SRV -> closest encloser example., wildcard exists but has no SRV -> NODATA
    gr_query("_telnet._tcp.host3.example.", 33, false, &r);
    assert(r.rcode == 0 && r.aa);
    assert(gr_count(&r, 1, -1) == 0);
    assert(gr_count(&r, 2, 6) == 1);

    // --- Must NOT be synthesized from any wildcard -------------------------
    // host1.example. MX -> host1.example. exists (A only): NODATA, not the wildcard MX
    gr_query("host1.example.", 15, false, &r);
    assert(r.rcode == 0 && r.aa);
    assert(gr_count(&r, 1, -1) == 0);
    assert(gr_count(&r, 2, 6) == 1);

    // sub.*.example. MX -> the literal name exists (TXT only): NODATA
    gr_query("sub.*.example.", 15, false, &r);
    assert(r.rcode == 0 && r.aa);
    assert(gr_count(&r, 1, -1) == 0);
    // ...and its own TXT is returned literally, not the wildcard's TXT
    gr_query("sub.*.example.", 16, false, &r);
    assert(r.rcode == 0 && gr_count(&r, 1, -1) == 1);
    rr = gr_first(&r, 1, 16);
    assert(rr && strcasecmp(rr->name, "sub.*.example.") == 0);
    gr_expect_txt(&r, rr, "this is not a wildcard");

    // _telnet._tcp.host1.example. SRV -> _tcp.host1.example. exists (empty non-terminal): NXDOMAIN
    gr_query("_telnet._tcp.host1.example.", 33, false, &r);
    assert(r.rcode == 3 && r.aa);
    assert(gr_count(&r, 1, -1) == 0);
    assert(gr_count(&r, 2, 6) == 1);

    // §3.3.2 chart: _telnet._tcp.host2.example. and _dns._udp.host2.example. have no source of synthesis
    gr_query("_telnet._tcp.host2.example.", 33, false, &r);
    assert(r.rcode == 3 && gr_count(&r, 1, -1) == 0);
    gr_query("_dns._udp.host2.example.", 33, false, &r);
    assert(r.rcode == 3 && gr_count(&r, 1, -1) == 0);

    // ghost.*.example. MX / foobar.*.example. MX -> closest encloser is *.example. itself;
    // its source of synthesis (*.*.example.) does not exist -> NXDOMAIN
    gr_query("ghost.*.example.", 15, false, &r);
    assert(r.rcode == 3 && gr_count(&r, 1, -1) == 0);
    gr_query("foobar.*.example.", 15, false, &r);
    assert(r.rcode == 3 && gr_count(&r, 1, -1) == 0);

    // host.subdel.example. A -> below a zone cut: referral (NOERROR, AA=0, NS in AUTHORITY)
    gr_query("host.subdel.example.", 1, false, &r);
    assert(r.rcode == 0 && !r.aa);
    assert(gr_count(&r, 1, -1) == 0);
    assert(gr_count(&r, 2, 2) == 2);
    rr = gr_first(&r, 2, 2);
    assert(rr && strcasecmp(rr->name, "subdel.example.") == 0);

    zone_arena_destroy(&g_gr.arena);
    printf("  -> RFC 4592 wildcard golden responses passed.\n");
}


// ----------------------------------------------------------------------------
// RFC 9018 / RFC 7873 DNS Cookie behaviour of the query engine, end to end
// (EDNS COOKIE option in -> BADCOOKIE / refresh / echo decisions out).
// ----------------------------------------------------------------------------
static size_t gr_build_cookie_query(uint8_t *req, const char *qname, uint16_t qtype,
                                    const uint8_t *cookie, size_t cookie_len) {
    size_t o = 0;
    req[o++] = 0x45; req[o++] = 0x92;          // ID
    req[o++] = 0x01; req[o++] = 0x00;          // RD
    req[o++] = 0; req[o++] = 1;                // QDCOUNT
    req[o++] = 0; req[o++] = 0;                // ANCOUNT
    req[o++] = 0; req[o++] = 0;                // NSCOUNT
    req[o++] = 0; req[o++] = 1;                // ARCOUNT (OPT)
    for (const char *p = qname; *p; ) {        // QNAME
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0) break;
        req[o++] = (uint8_t)l; memcpy(req + o, p, l); o += l;
        p += l + (dot ? 1 : 0);
    }
    req[o++] = 0;
    req[o++] = (uint8_t)(qtype >> 8); req[o++] = (uint8_t)qtype;
    req[o++] = 0; req[o++] = 1;                // QCLASS IN
    req[o++] = 0;                              // OPT owner = root
    req[o++] = 0; req[o++] = 41;               // TYPE OPT
    req[o++] = 0x10; req[o++] = 0x00;          // UDP payload 4096
    req[o++] = 0; req[o++] = 0; req[o++] = 0; req[o++] = 0;   // ext RCODE / version / flags
    size_t rdlen = 4 + cookie_len;
    req[o++] = (uint8_t)(rdlen >> 8); req[o++] = (uint8_t)rdlen;
    req[o++] = 0; req[o++] = 10;               // option COOKIE
    req[o++] = (uint8_t)(cookie_len >> 8); req[o++] = (uint8_t)cookie_len;
    memcpy(req + o, cookie, cookie_len); o += cookie_len;
    return o;
}

// Returns pointer to the COOKIE option payload in the response's OPT RR (NULL if absent).
static const uint8_t *gr_find_cookie(const gr_resp_t *r, size_t *len_out, uint32_t *opt_ttl_out) {
    for (int i = 0; i < r->nrr; i++) {
        if (r->rr[i].sect != 3 || r->rr[i].type != 41) continue;
        if (opt_ttl_out) *opt_ttl_out = r->rr[i].ttl;
        size_t off = r->rr[i].rdoff, end = off + r->rr[i].rdlen;
        while (off + 4 <= end) {
            uint16_t code = (uint16_t)((r->msg[off] << 8) | r->msg[off + 1]);
            uint16_t len = (uint16_t)((r->msg[off + 2] << 8) | r->msg[off + 3]);
            if (off + 4 + len > end) return NULL;
            if (code == 10) { *len_out = len; return r->msg + off + 4; }
            off += 4 + (size_t)len;
        }
    }
    return NULL;
}

static void test_dns_cookie_engine_rfc9018(void) {
    printf("[TEST] Query Engine: RFC 9018 DNS Cookie handling (BADCOOKIE / refresh / echo)...\n");
    gr_setup("example.",
        "$ORIGIN example.\n$TTL 3600\n"
        "@ IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600\n"
        "@ IN NS ns.example.com.\n"
        "host1 IN A 192.0.2.1\n");
    // RFC 9018 Appendix A.1 secret, configured exactly like `cookie-secret` in named.conf
    static const uint8_t secret[16] = { 0xe5,0xe9,0x73,0xe5,0xa6,0xb2,0xa4,0x3f,
                                        0x48,0xe7,0xdc,0x84,0x9e,0x37,0xbf,0xcf };
    memcpy(g_gr.cfg.cookie_secrets[0], secret, 16);
    g_gr.cfg.cookie_secret_count = 1;

    const char *ip = "198.51.100.100";
    const uint8_t cc[8] = { 0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57 };
    const uint32_t now = (uint32_t)time(NULL);
    uint8_t req[512], opt[24], sc[16];
    gr_resp_t r;
    size_t clen;
    uint32_t opt_ttl;
    const uint8_t *ck;

    memcpy(opt, cc, 8);

    // 1. Client-only cookie -> NOERROR plus a fresh, valid Server Cookie bound to (client cookie, IP)
    size_t n = gr_build_cookie_query(req, "host1.example.", 1, opt, 8);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert(r.rcode == 0 && gr_count(&r, 1, 1) == 1);
    ck = gr_find_cookie(&r, &clen, &opt_ttl);
    assert(ck && clen == 24 && memcmp(ck, cc, 8) == 0);
    assert(verify_server_cookie(&g_gr.cfg, ip, cc, ck + 8, 16, (uint32_t)time(NULL)) == SERVER_COOKIE_VALID);
    assert(((opt_ttl >> 24) & 0xFF) == 0);                  // no BADCOOKIE extended RCODE

    // 2. Valid, fresh Server Cookie -> accepted and echoed unchanged (no needless rotation)
    assert(generate_server_cookie(&g_gr.cfg, ip, cc, sc, now - 10));
    memcpy(opt + 8, sc, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert(r.rcode == 0 && gr_count(&r, 1, 1) == 1);
    ck = gr_find_cookie(&r, &clen, &opt_ttl);
    assert(ck && clen == 24 && memcmp(ck + 8, sc, 16) == 0);

    // 3. Valid but older than 30 minutes -> accepted, and a NEW Server Cookie is returned (RFC 9018 4.3)
    assert(generate_server_cookie(&g_gr.cfg, ip, cc, sc, now - 2400));
    memcpy(opt + 8, sc, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert(r.rcode == 0 && gr_count(&r, 1, 1) == 1);
    ck = gr_find_cookie(&r, &clen, &opt_ttl);
    assert(ck && clen == 24 && memcmp(ck + 8, sc, 16) != 0);
    assert(verify_server_cookie(&g_gr.cfg, ip, cc, ck + 8, 16, (uint32_t)time(NULL)) == SERVER_COOKIE_VALID);

    // 4. Reserved bytes set by another implementation but hash valid (RFC 9018 4.2) -> accepted
    uint8_t rsv[16] = { 0x01, 0xab, 0xcd, 0xef };
    rsv[4] = (uint8_t)((now - 10) >> 24); rsv[5] = (uint8_t)((now - 10) >> 16);
    rsv[6] = (uint8_t)((now - 10) >> 8);  rsv[7] = (uint8_t)(now - 10);
    assert(compute_server_cookie_hash(secret, ip, cc, rsv, rsv + 8));
    memcpy(opt + 8, rsv, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert(r.rcode == 0);                                   // NOT BADCOOKIE
    ck = gr_find_cookie(&r, &clen, &opt_ttl);
    assert(ck && clen == 24 && ((opt_ttl >> 24) & 0xFF) == 0);

    // 5. Wrong hash over UDP -> BADCOOKIE (RCODE 23 = ext 1 | base 7) with a fresh cookie so the client can retry
    assert(generate_server_cookie(&g_gr.cfg, ip, cc, sc, now - 10));
    sc[15] ^= 0x01;
    memcpy(opt + 8, sc, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert((r.msg[3] & 0x0F) == 7);
    ck = gr_find_cookie(&r, &clen, &opt_ttl);
    assert(ck && clen == 24 && ((opt_ttl >> 24) & 0xFF) == 1);
    assert(verify_server_cookie(&g_gr.cfg, ip, cc, ck + 8, 16, (uint32_t)time(NULL)) == SERVER_COOKIE_VALID);
    assert(gr_count(&r, 1, -1) == 0);                       // no answer data is leaked on BADCOOKIE

    // 6. Same invalid cookie over TCP -> served normally (TCP already proves the source address)
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, true, &r);
    assert(r.rcode == 0 && gr_count(&r, 1, 1) == 1);

    // 7. Too old (> 1 hour) and cookie replayed from another client address -> BADCOOKIE
    assert(generate_server_cookie(&g_gr.cfg, ip, cc, sc, now - 3700));
    memcpy(opt + 8, sc, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert((r.msg[3] & 0x0F) == 7);
    assert(generate_server_cookie(&g_gr.cfg, ip, cc, sc, now - 10));
    memcpy(opt + 8, sc, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, "198.51.100.101", false, &r);
    assert((r.msg[3] & 0x0F) == 7);

    // 8. Secret rollover: a cookie made with the previous (2nd) secret is still accepted...
    static const uint8_t old_secret[16] = { 0xdd,0x3b,0xdf,0x93,0x44,0xb6,0x78,0xb1,
                                            0x85,0xa6,0xf5,0xcb,0x60,0xfc,0xa7,0x15 };
    server_config_t old_cfg;
    memset(&old_cfg, 0, sizeof(old_cfg));
    memcpy(old_cfg.cookie_secrets[0], old_secret, 16);
    old_cfg.cookie_secret_count = 1;
    assert(generate_server_cookie(&old_cfg, ip, cc, sc, now - 10));
    memcpy(g_gr.cfg.cookie_secrets[1], old_secret, 16);
    g_gr.cfg.cookie_secret_count = 2;
    memcpy(opt + 8, sc, 16);
    n = gr_build_cookie_query(req, "host1.example.", 1, opt, 24);
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert(r.rcode == 0);
    // ...and rejected once it is removed (stage 3)
    g_gr.cfg.cookie_secret_count = 1;
    gr_query_raw(req, n, "host1.example.", 1, ip, false, &r);
    assert((r.msg[3] & 0x0F) == 7);

    // 9. A query without a COOKIE option never gets one back
    uint8_t plain[512];
    size_t pn = 0;
    build_dns_query(plain, &pn, 0x4592, "host1.example.", 1, false);
    gr_query_raw(plain, pn, "host1.example.", 1, ip, false, &r);
    assert(r.rcode == 0 && gr_find_cookie(&r, &clen, &opt_ttl) == NULL);

    memset(&g_gr.cfg, 0, sizeof(g_gr.cfg));
    zone_arena_destroy(&g_gr.arena);
    printf("  -> RFC 9018 DNS Cookie engine handling passed.\n");
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

    // 8. name_to_canonical_wire
    uint8_t cwire[256];
    size_t cwire_len = name_to_canonical_wire("WWW.Example.COM.", cwire, sizeof(cwire));
    assert(cwire_len > 0);
    assert(cwire[0] == 3 && cwire[1] == 'w');
    assert(name_to_canonical_wire(NULL, cwire, sizeof(cwire)) == 0);

    // 9. compute_nsec3_hash
    char b32_hash[64];
    uint8_t salt[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    assert(compute_nsec3_hash("example.com.", 1, 1, salt, sizeof(salt), b32_hash, sizeof(b32_hash)) == true);
    assert(strlen(b32_hash) > 0);
    assert(compute_nsec3_hash("example.com.", 2 /* invalid algo */, 1, salt, sizeof(salt), b32_hash, sizeof(b32_hash)) == false);

    // 10. nsec3_covers_hash
    assert(nsec3_covers_hash("AAAA", "CCCC", "BBBB") == true);
    assert(nsec3_covers_hash("AAAA", "CCCC", "DDDD") == false);
    assert(nsec3_covers_hash("ZZZZ", "AAAA", "0000") == true); // Wrap-around inside
    assert(nsec3_covers_hash("ZZZZ", "AAAA", "YYYY") == false); // Wrap-around outside
    assert(nsec3_covers_hash(NULL, "CCCC", "BBBB") == false);

    // 11. find_next_closer_name
    char next_closer[256];
    assert(find_next_closer_name("sub.deep.example.com.", "example.com.", next_closer, sizeof(next_closer)) == true);
    assert(strcmp(next_closer, "deep.example.com") == 0);
    assert(find_next_closer_name("example.com.", "example.com.", next_closer, sizeof(next_closer)) == false);
    assert(find_next_closer_name(NULL, "example.com.", next_closer, sizeof(next_closer)) == false);

    // 12. name_exists_in_zone & find_closest_encloser
    assert(name_exists_in_zone(NULL, "example.com.", "\0\0", NULL, NULL) == false);
    assert(strcmp(find_closest_encloser(NULL, "sub.example.com.", "example.com.", "\0\0", NULL, NULL), "example.com.") == 0);

    // 13. find_matching_nsec3 & find_covering_nsec3 on empty arena
    zone_arena_t nsec3_arena;
    zone_arena_init(&nsec3_arena);
    assert(find_matching_nsec3(&nsec3_arena, "AAAA", "example.com.") == NULL);
    assert(find_covering_nsec3(&nsec3_arena, "AAAA") == NULL);
    dns_record_t *att[8];
    int att_count = 0;
    assert(attach_nsec3_record(&nsec3_arena, NULL, dummy_res, sizeof(dummy_res), &dummy_off, &comp, &dummy_ar, att, &att_count) == true);
    zone_arena_destroy(&nsec3_arena);

    // 14. find_program_plugin
    assert(find_program_plugin(NULL) == NULL);
    assert(find_program_plugin("unknown.domain.invalid.") == NULL);

    // 15. forward_via_tcp
    struct sockaddr_storage fwd_ss;
    memset(&fwd_ss, 0, sizeof(fwd_ss));
    fwd_ss.ss_family = AF_INET;
    uint8_t qpkt[12] = {0};
    uint8_t rpkt[512];
    assert(forward_via_tcp(&fwd_ss, sizeof(struct sockaddr_in), qpkt, sizeof(qpkt), rpkt, sizeof(rpkt), 100) == -1);

    // 16. restore_checkpoint
    resolve_checkpoint_t cp_extra = { 100, 1, 2, 3 };
    uint16_t roff = 0, ranc = 0, rnsc = 0, rarc = 0;
    restore_checkpoint(&cp_extra, &roff, &ranc, &rnsc, &rarc);
    assert(roff == 100 && ranc == 1 && rnsc == 2 && rarc == 3);

    // 17. nsec_covers_name & find_covering_nsec
    dns_record_t nsec_rec;
    memset(&nsec_rec, 0, sizeof(nsec_rec));
    nsec_rec.type_code = 47;
    nsec_rec.name = "a.example.com.";
    nsec_rec.rdata[0] = "c.example.com.";
    nsec_rec.rdata_count = 1;
    assert(nsec_covers_name(&nsec_rec, "b.example.com.") == true);
    assert(nsec_covers_name(&nsec_rec, "d.example.com.") == false);
    assert(nsec_covers_name(NULL, "b.example.com.") == false);

    zone_arena_t cov_arena;
    zone_arena_init(&cov_arena);
    assert(find_covering_nsec(&cov_arena, "b.example.com.") == NULL);
    zone_arena_destroy(&cov_arena);

    // 18. hex_to_bytes
    uint8_t hex_out[16];
    assert(hex_to_bytes("DEADBEEF", hex_out, sizeof(hex_out)) == 4);
    assert(hex_out[0] == 0xDE && hex_out[1] == 0xAD);
    assert(hex_to_bytes("-", hex_out, sizeof(hex_out)) == 0);
    assert(hex_to_bytes(NULL, hex_out, sizeof(hex_out)) == 0);

    // 19. monotonic_ms & remaining_ms
    int64_t now_m = monotonic_ms();
    assert(now_m > 0);
    assert(remaining_ms(now_m + 500) > 0);
    assert(remaining_ms(now_m - 500) == 0);

    // 20. build_synthetic_servfail
    uint8_t sf_res[512];
    int sf_len = build_synthetic_servfail(qpkt, sizeof(qpkt), sf_res, sizeof(sf_res));
    assert(sf_len >= 12);
    assert(build_synthetic_servfail(qpkt, sizeof(qpkt), sf_res, 6) == 0);
    assert(build_synthetic_servfail(qpkt, 6, sf_res, sizeof(sf_res)) == 0);

    // 21. write_all_timeout & read_all_timeout
    int sv_rw[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv_rw) == 0) {
        uint8_t send_b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t recv_b[8] = {0};
        assert(write_all_timeout(sv_rw[0], send_b, sizeof(send_b), 500) == (ssize_t)sizeof(send_b));
        assert(read_all_timeout(sv_rw[1], recv_b, sizeof(recv_b), 500) == (ssize_t)sizeof(recv_b));
        assert(memcmp(send_b, recv_b, sizeof(send_b)) == 0);
        close(sv_rw[0]);
        close(sv_rw[1]);
    }
    assert(write_all_timeout(-1, qpkt, sizeof(qpkt), 10) == -1);
    assert(read_all_timeout(-1, qpkt, sizeof(qpkt), 10) == -1);

    // 22. dispatch_to_program_zone & question_section_matches
    uint8_t valid_qpkt[256];
    size_t valid_qlen = 0;
    build_dns_query(valid_qpkt, &valid_qlen, 0x1234, "example.com.", 1, false);
    assert(question_section_matches(valid_qpkt, valid_qlen, valid_qpkt, valid_qlen) == true);
    assert(question_section_matches(qpkt, sizeof(qpkt), qpkt, sizeof(qpkt)) == false);
    assert(question_section_matches(NULL, 0, valid_qpkt, valid_qlen) == false);
    int pgm_res = dispatch_to_program_zone("invalid.zone.", valid_qpkt, valid_qlen, rpkt, sizeof(rpkt), "127.0.0.1", false);
    assert(pgm_res >= 12);
    assert((rpkt[3] & 0x0F) == 2); // SERVFAIL

    // 23. dispatch_forward_zone
    zone_config_t dummy_fwd;
    memset(&dummy_fwd, 0, sizeof(dummy_fwd));
    int fwd_res = dispatch_forward_zone(&dummy_fwd, valid_qpkt, valid_qlen, rpkt, sizeof(rpkt));
    assert(fwd_res >= 12);
    assert((rpkt[3] & 0x0F) == 2); // SERVFAIL

    printf("  -> Query engine helpers & edge cases passed.\n");
}

static void test_dname_synthesis_and_wildcard_proofs(void) {
    printf("[TEST] Query Engine: DNAME synthesis & wildcard resolution edge cases...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "dname.example.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    const char *zstr =
        "$ORIGIN dname.example.\n"
        "$TTL 300\n"
        "@ IN SOA ns1.dname.example. hostmaster.dname.example. 1 7200 3600 1209600 300\n"
        "@ IN NS ns1.dname.example.\n"
        "ns1 IN A 192.0.2.1\n"
        "sub IN DNAME target.example.net.\n"
        "*.wild IN A 192.0.2.99\n"
        "*.wild IN TXT \"wildcard text\"\n";

    char *zbuf = arena_strdup(&arena, zstr);
    int parsed = parse_zone_fast(zbuf, strlen(zbuf), &arena, &ctx);
    assert(parsed >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "dname.example.", sizeof(entry.domain));
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
    atomic_init(&snap.reader_count, 10);

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl_cfg = NULL;

    // 1. Query for host.sub.dname.example. -> synthesizes DNAME + CNAME target.example.net.
    uint8_t qbuf[512];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1122, "host.sub.dname.example.", 1, false);

    uint8_t rbuf[4096];
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "host.sub.dname.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 0); // NOERROR
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 1); // Contains DNAME and synthesized CNAME

    // 2. Query for a.b.wild.dname.example. -> Wildcard expansion
    compress_ctx_init(&comp_ctx);
    build_dns_query(qbuf, &qlen, 0x3344, "a.b.wild.dname.example.", 1, false);
    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "a.b.wild.dname.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 0); // NOERROR
    ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1); // 1 A record synthesized from wildcard

    // 3. Query for a.b.wild.dname.example. QTYPE=AAAA -> Wildcard No-Data
    compress_ctx_init(&comp_ctx);
    build_dns_query(qbuf, &qlen, 0x5566, "a.b.wild.dname.example.", 28, false);
    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "a.b.wild.dname.example.", 28, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 0); // NOERROR
    ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 0); // 0 answers (NODATA)
    uint16_t nscount = (rbuf[8] << 8) | rbuf[9];
    assert(nscount >= 1); // SOA in authority section

    zone_arena_destroy(&arena);
    printf("  -> DNAME synthesis & wildcard resolution passed.\n");
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
    test_rfc4592_wildcard_golden();
    test_dns_cookie_engine_rfc9018();
    test_delegation_referral_and_ds_handling();
    test_program_plugins_and_forward_zone_helpers();
    test_query_engine_helpers_and_edge_cases();
    test_dname_synthesis_and_wildcard_proofs();
    printf("=== All Expanded Query Engine Unit Tests PASSED ===\n");
    return 0;
}



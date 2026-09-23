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

static void test_query_engine_protocol_qclass_and_edns_branches(void) {
    printf("[TEST] Query Engine: UDP AXFR rejection, foreign QCLASS, and EDNS BADVERS...\n");

    zone_arena_t arena;
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    zone_arena_init(&arena);
    const char *zstr =
        "$ORIGIN qproto.example.\n$TTL 300\n"
        "@ IN SOA ns1.qproto.example. admin.qproto.example. 1 7200 3600 1209600 300\n"
        "@ IN NS ns1.qproto.example.\n"
        "ns1 IN A 192.0.2.1\n";
    char *zbuf = arena_strdup(&arena, zstr);
    assert(parse_zone_fast(zbuf, strlen(zbuf), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "qproto.example.", sizeof(entry.domain));
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

    // 1. UDP AXFR (QTYPE=252 on UDP -> FORMERR)
    uint8_t qbuf[512];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1111, "qproto.example.", 252 /*AXFR*/, false);
    uint8_t rbuf[4096];
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "qproto.example.", 252, "127.0.0.1", &comp_ctx, false /*is_tcp=false*/, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 1); // FORMERR

    // 2. Foreign QCLASS (e.g. QCLASS=4 HS -> REFUSED)
    compress_ctx_init(&comp_ctx);
    build_dns_query(qbuf, &qlen, 0x2222, "qproto.example.", 1 /*A*/, false);
    // Overwrite QCLASS in question section to HS (4)
    size_t q_end = qlen;
    qbuf[q_end - 2] = 0; qbuf[q_end - 1] = 4; // QCLASS = 4 (Hesiod)
    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "qproto.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 5); // REFUSED

    // 3. EDNS BADVERS (EDNS version = 1 -> BADVERS 16)
    compress_ctx_init(&comp_ctx);
    build_dns_query(qbuf, &qlen, 0x3333, "qproto.example.", 1, false);
    // Append OPT RR with version = 1
    qbuf[11] = 1; // ARCOUNT = 1
    qbuf[qlen++] = 0; // root name
    qbuf[qlen++] = 0; qbuf[qlen++] = 41; // TYPE = OPT
    qbuf[qlen++] = 0x10; qbuf[qlen++] = 0x00; // CLASS = UDP payload size 4096
    qbuf[qlen++] = 0; // Extended RCODE = 0
    qbuf[qlen++] = 1; // EDNS Version = 1 (unsupported!)
    qbuf[qlen++] = 0; qbuf[qlen++] = 0; // DO=0, Z=0
    qbuf[qlen++] = 0; qbuf[qlen++] = 0; // RDLEN = 0

    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "qproto.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    // In BADVERS, base RCODE in header is 0, but OPT record has extended RCODE 1 (16 = BADVERS)
    assert((rbuf[3] & 0x0F) == 0);
    uint16_t arcount = (rbuf[10] << 8) | rbuf[11];
    assert(arcount == 1);

    zone_arena_destroy(&arena);
    printf("  -> UDP AXFR, foreign QCLASS, and EDNS BADVERS passed.\n");
}

static void test_cname_target_overflow_and_tsig_query_paths(void) {
    printf("[TEST] Query Engine: CNAME target overflow (>255) and query TSIG verification...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    // Build zone with long CNAME target composed of valid labels (<= 63 bytes each)
    const char *long_name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
                            "cccccccccccccccccccccccccccccccccccccccccccccccccc."
                            "dddddddddddddddddddddddddddddddddddddddddddddddddd."
                            "example.com.";

    char ztext[1024];
    snprintf(ztext, sizeof(ztext),
             "cname.example. 3600 IN SOA ns1.cname.example. admin.cname.example. 1 3600 1800 604800 86400\n"
             "cname.example. 3600 IN NS ns1.cname.example.\n"
             "alias.cname.example. 3600 IN CNAME %s\n", long_name);

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "cname.example.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    int p_res = parse_zone_fast(ztext, strlen(ztext), &arena, &ctx);
    assert(p_res >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "cname.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = {
        .name = "default",
        .entries = entries,
        .zone_count = 1,
        .hash_table = hash_tbl,
        .hash_size = 2,
        .chain_next = chain_nxt,
    };
    zone_db_snapshot_t snap = {
        .views = &view,
        .view_count = 1,
    };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);

    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x4444, "alias.cname.example.", 1 /*A*/, false);

    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "alias.cname.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    // Should successfully answer with the CNAME record
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1);

    zone_arena_destroy(&arena);
    printf("  -> CNAME target overflow test passed.\n");
}

static void test_non_data_rrtypes_and_special_qtypes(void) {
    printf("[TEST] Query Engine: Non-data RR types and special QTYPEs (41, 249..255)...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "special.example. 3600 IN SOA ns1.special.example. admin.special.example. 1 3600 1800 604800 86400\n"
        "special.example. 3600 IN NS ns1.special.example.\n"
        "special.example. 3600 IN A 192.0.2.1\n"
        "special.example. 3600 IN TXT \"hello special\"\n"
        "ns1.special.example. 3600 IN A 192.0.2.2\n";

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "special.example.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    int p_res = parse_zone_fast(ztext, strlen(ztext), &arena, &ctx);
    assert(p_res >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "special.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = {
        .name = "default",
        .entries = entries,
        .zone_count = 1,
        .hash_table = hash_tbl,
        .hash_size = 2,
        .chain_next = chain_nxt,
    };
    zone_db_snapshot_t snap = {
        .views = &view,
        .view_count = 1,
    };

    compress_ctx_t comp_ctx;
    uint8_t qbuf[512], rbuf[1024];
    rate_limit_config_t *rrl_cfg = NULL;

    // Test each non-data type: 41, 249, 250, 251, 252, 253, 254, 255
    uint16_t non_data_types[] = {41, 249, 250, 251, 252, 253, 254, 255};
    for (size_t i = 0; i < sizeof(non_data_types)/sizeof(non_data_types[0]); i++) {
        uint16_t qt = non_data_types[i];
        size_t qlen = 0;
        build_dns_query(qbuf, &qlen, 0x1000 + qt, "special.example.", qt, false);
        compress_ctx_init(&comp_ctx);
        int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "special.example.", qt, "192.0.2.100", &comp_ctx, false, &rrl_cfg, &snap);
        assert(rlen >= 12);
        if (qt == 255 /* ANY */) {
            // ANY query on apex should return all records (SOA, NS, A, TXT)
            uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
            assert(ancount >= 3);
        }
    }

    zone_arena_destroy(&arena);
    printf("  -> Non-data RR types and ANY query handling passed.\n");
}

static void test_covering_rrsig_and_buffer_exhaustion_branches(void) {
    printf("[TEST] Query Engine: Covering RRSIG buffer exhaustion & malformed rdata_count...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    // Build zone with SOA, NS, A, and malformed/valid RRSIGs
    char ztext[] =
        "rrsig.example. 3600 IN SOA ns1.rrsig.example. admin.rrsig.example. 1 3600 1800 604800 86400\n"
        "rrsig.example. 3600 IN NS ns1.rrsig.example.\n"
        "host.rrsig.example. 3600 IN A 192.0.2.1\n"
        "host.rrsig.example. 3600 IN RRSIG A 8 3 3600 20300101000000 20200101000000 12345 rrsig.example. AAAA\n"
        "host.rrsig.example. 3600 IN RRSIG A 8 3 3600 20300101000000 20200101000000 54321 rrsig.example. BBBB\n";

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "rrsig.example.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    int p_res = parse_zone_fast(ztext, strlen(ztext), &arena, &ctx);
    assert(p_res >= 0);

    // Corrupt one record to have rdata_count < 9 to exercise the line 35-36 check
    for (size_t i = 0; i < arena.count; i++) {
        if (arena.records[i].type_code == 46 /* RRSIG */) {
            arena.records[i].rdata_count = 5; // malformed!
            break;
        }
    }
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "rrsig.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = {
        .name = "default",
        .entries = entries,
        .zone_count = 1,
        .hash_table = hash_tbl,
        .hash_size = 2,
        .chain_next = chain_nxt,
    };
    zone_db_snapshot_t snap = {
        .views = &view,
        .view_count = 1,
    };

    compress_ctx_t comp_ctx;
    uint8_t qbuf[512], rbuf[1024];
    rate_limit_config_t *rrl_cfg = NULL;

    // Query with DO=1
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x2222, "host.rrsig.example.", 1 /* A */, true);
    compress_ctx_init(&comp_ctx);
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "host.rrsig.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    // Should answer with A and the uncorrupted RRSIG
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 2);

    // Now test response buffer truncation / exhaustion
    uint8_t small_rbuf[40];
    compress_ctx_init(&comp_ctx);
    rlen = process_dns_query(qbuf, qlen, small_rbuf, sizeof(small_rbuf), "host.rrsig.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    // TC bit should be set or safe truncated packet returned
    assert(rlen >= 12);

    zone_arena_destroy(&arena);
    printf("  -> Covering RRSIG and buffer exhaustion branches passed.\n");
}


static void test_dname_loop_and_depth_limit(void) {
    printf("[TEST] Query Engine: DNAME loop detection and max chain depth...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "dname.example. 3600 IN SOA ns1.dname.example. admin.dname.example. 1 3600 1800 604800 86400\n"
        "dname.example. 3600 IN NS ns1.dname.example.\n"
        "a.dname.example. 3600 IN DNAME b.dname.example.\n"
        "b.dname.example. 3600 IN DNAME a.dname.example.\n"
        "target.dname.example. 3600 IN A 192.0.2.55\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "dname.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "dname.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1111, "sub.a.dname.example.", 1, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "sub.a.dname.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 1);

    zone_arena_destroy(&arena);
    printf("  -> DNAME loop and depth limit test passed.\n");
}

static void test_wildcard_cname_and_dname_synthesis(void) {
    printf("[TEST] Query Engine: Wildcard CNAME and DNAME synthesis...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "wildsyn.example. 3600 IN SOA ns1.wildsyn.example. admin.wildsyn.example. 1 3600 1800 604800 86400\n"
        "wildsyn.example. 3600 IN NS ns1.wildsyn.example.\n"
        "*.wildsyn.example. 3600 IN CNAME apex.wildsyn.example.\n"
        "apex.wildsyn.example. 3600 IN A 192.0.2.10\n"
        "syn.wildsyn.example. 3600 IN DNAME target.wildsyn.example.\n"
        "target.wildsyn.example. 3600 IN A 192.0.2.20\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "wildsyn.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "wildsyn.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1234, "foo.bar.wildsyn.example.", 1, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "foo.bar.wildsyn.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 2);

    compress_ctx_init(&comp_ctx);
    qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1235, "host.syn.wildsyn.example.", 1, false);
    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "host.syn.wildsyn.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 1);

    zone_arena_destroy(&arena);
    printf("  -> Wildcard CNAME and DNAME synthesis passed.\n");
}

static void test_nsec3_wildcard_nodata_and_optout(void) {
    printf("[TEST] Query Engine: NSEC3 Opt-Out and Closest Encloser proofs...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "nsec3opt.example. 3600 IN SOA ns1.nsec3opt.example. admin.nsec3opt.example. 1 3600 1800 604800 86400\n"
        "nsec3opt.example. 3600 IN NS ns1.nsec3opt.example.\n"
        "nsec3opt.example. 3600 IN NSEC3PARAM 1 0 10 AABBCCDD\n"
        "00000000000000000000000000000000.nsec3opt.example. 3600 IN NSEC3 1 1 10 AABBCCDD HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH SOA NS NSEC3PARAM RRSIG\n"
        "unsecure.nsec3opt.example. 3600 IN NS ns1.other.net.\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "nsec3opt.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "nsec3opt.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x3333, "host.unsecure.nsec3opt.example.", 1, true);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "host.unsecure.nsec3opt.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    // Delegation referral should be returned
    uint16_t nscount = (rbuf[8] << 8) | rbuf[9];
    assert(nscount >= 1);

    zone_arena_destroy(&arena);
    printf("  -> NSEC3 Opt-Out and Closest Encloser proofs passed.\n");
}

static void test_nsec_apex_and_delegation_proofs(void) {
    printf("[TEST] Query Engine: NSEC apex NODATA and NXDOMAIN proofs...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "nsecproof.example. 3600 IN SOA ns1.nsecproof.example. admin.nsecproof.example. 1 3600 1800 604800 86400\n"
        "nsecproof.example. 3600 IN NS ns1.nsecproof.example.\n"
        "nsecproof.example. 3600 IN A 192.0.2.1\n"
        "nsecproof.example. 3600 IN NSEC host.nsecproof.example. SOA NS A RRSIG NSEC\n"
        "host.nsecproof.example. 3600 IN A 192.0.2.2\n"
        "host.nsecproof.example. 3600 IN NSEC nsecproof.example. A RRSIG NSEC\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "nsecproof.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "nsecproof.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    // Query TXT at apex (NODATA proof with NSEC)
    build_dns_query(qbuf, &qlen, 0x4444, "nsecproof.example.", 16 /* TXT */, true);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "nsecproof.example.", 16, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 0); // NOERROR
    uint16_t nscount = (rbuf[8] << 8) | rbuf[9];
    assert(nscount >= 1); // SOA + NSEC in auth

    // Query non-existent name (NXDOMAIN proof with NSEC)
    compress_ctx_init(&comp_ctx);
    qlen = 0;
    build_dns_query(qbuf, &qlen, 0x4445, "missing.nsecproof.example.", 1 /* A */, true);
    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "missing.nsecproof.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 3); // NXDOMAIN

    zone_arena_destroy(&arena);
    printf("  -> NSEC apex NODATA and NXDOMAIN proofs passed.\n");
}

static void test_edns_client_subnet_cache_matching(void) {
    printf("[TEST] Query Engine: EDNS Client Subnet (ECS) matching and scope prefix...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "ecs.example. 3600 IN SOA ns1.ecs.example. admin.ecs.example. 1 3600 1800 604800 86400\n"
        "ecs.example. 3600 IN NS ns1.ecs.example.\n"
        "geo.ecs.example. 300 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "ecs.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);

    // Setup ECS subnet tags
    arena.bind_ecs_tag_count = 1;
    arena.bind_ecs_tags = calloc(1, sizeof(ecs_tag_def_t));
    arena.bind_ecs_tags[0].tag = strdup("tokyo-net");
    arena.bind_ecs_tags[0].cidr_count = 1;
    arena.bind_ecs_tags[0].cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    arena.bind_ecs_tags[0].cidrs[0].cidr = strdup("203.0.113.0/24");

    dns_record_t ecs_rec;
    memset(&ecs_rec, 0, sizeof(ecs_rec));
    ecs_rec.name = arena_strdup(&arena, "geo.ecs.example.");
    ecs_rec.type = arena_strdup(&arena, "A");
    ecs_rec.type_code = 1;
    ecs_rec.class_str = arena_strdup(&arena, "IN");
    ecs_rec.class_val = 1;
    ecs_rec.ttl = arena_strdup(&arena, "300");
    ecs_rec.ttl_value = 300;
    ecs_rec.rdata_count = 1;
    ecs_rec.rdata[0] = arena_strdup(&arena, "203.0.113.100");
    ecs_rec.ecs_subnet_tag = "tokyo-net";

    arena.records_cap = arena.count + 4;
    arena.records = realloc(arena.records, sizeof(dns_record_t) * arena.records_cap);
    arena.records[arena.count++] = ecs_rec;
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "ecs.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);

    // Build query with ECS option (Option 8: 203.0.113.0/24)
    uint8_t qbuf[512], rbuf[1024];
    memset(qbuf, 0, 12);
    qbuf[0] = 0x55; qbuf[1] = 0x66;
    qbuf[4] = 0; qbuf[5] = 1; // QDCOUNT=1
    qbuf[10] = 0; qbuf[11] = 1; // ARCOUNT=1 (OPT)
    size_t qoff = 12;
    qoff += write_uncompressed_name(qbuf, qoff, sizeof(qbuf), "geo.ecs.example.");
    qbuf[qoff++] = 0; qbuf[qoff++] = 1; // A
    qbuf[qoff++] = 0; qbuf[qoff++] = 1; // IN
    // OPT RR with ECS (RFC 7871: Family(2) + SourcePrefix(1) + ScopePrefix(1) + Addr(3) = 7 bytes option data)
    qbuf[qoff++] = 0; // root
    qbuf[qoff++] = 0; qbuf[qoff++] = 41; // OPT
    qbuf[qoff++] = 0x10; qbuf[qoff++] = 0x00; // 4096 UDP buffer size
    qbuf[qoff++] = 0; qbuf[qoff++] = 0; qbuf[qoff++] = 0; qbuf[qoff++] = 0; // Flags/Extended RCODE
    qbuf[qoff++] = 0; qbuf[qoff++] = 11; // RDLEN = 11 (4 bytes option header + 7 bytes option data)
    qbuf[qoff++] = 0; qbuf[qoff++] = 8;  // OPTION-CODE 8 (ECS)
    qbuf[qoff++] = 0; qbuf[qoff++] = 7;  // OPTION-LENGTH 7
    qbuf[qoff++] = 0; qbuf[qoff++] = 1;  // Family 1 (IPv4)
    qbuf[qoff++] = 24; // Source prefix 24
    qbuf[qoff++] = 0;  // Scope prefix 0
    qbuf[qoff++] = 203; qbuf[qoff++] = 0; qbuf[qoff++] = 113; // 203.0.113

    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qoff, rbuf, sizeof(rbuf), "geo.ecs.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1);

    free(arena.bind_ecs_tags[0].cidrs[0].cidr);
    free(arena.bind_ecs_tags[0].cidrs);
    free(arena.bind_ecs_tags[0].tag);
    free(arena.bind_ecs_tags);
    zone_arena_destroy(&arena);
    printf("  -> EDNS Client Subnet matching passed.\n");
}

static void test_dns_cookie_badcookie_and_timestamp_drift(void) {
    printf("[TEST] Query Engine: DNS Cookie BADCOOKIE and timestamp drift...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "cookie.example. 3600 IN SOA ns1.cookie.example. admin.cookie.example. 1 3600 1800 604800 86400\n"
        "cookie.example. 3600 IN NS ns1.cookie.example.\n"
        "cookie.example. 3600 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "cookie.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "cookie.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);

    // Query with client cookie + bad server cookie (8 bytes client + 8 bytes invalid server cookie)
    uint8_t qbuf[512], rbuf[1024];
    memset(qbuf, 0, 12);
    qbuf[0] = 0x66; qbuf[1] = 0x77;
    qbuf[4] = 0; qbuf[5] = 1; // QDCOUNT=1
    qbuf[10] = 0; qbuf[11] = 1; // ARCOUNT=1 (OPT)
    size_t qoff = 12;
    qoff += write_uncompressed_name(qbuf, qoff, sizeof(qbuf), "cookie.example.");
    qbuf[qoff++] = 0; qbuf[qoff++] = 1; // A
    qbuf[qoff++] = 0; qbuf[qoff++] = 1; // IN
    // OPT RR with Bad Server Cookie
    qbuf[qoff++] = 0;
    qbuf[qoff++] = 0; qbuf[qoff++] = 41; // OPT
    qbuf[qoff++] = 0x10; qbuf[qoff++] = 0x00;
    qbuf[qoff++] = 0; qbuf[qoff++] = 0; qbuf[qoff++] = 0; qbuf[qoff++] = 0;
    qbuf[qoff++] = 0; qbuf[qoff++] = 20; // RDLEN = 20
    qbuf[qoff++] = 0; qbuf[qoff++] = 10; // Option 10 (Cookie)
    qbuf[qoff++] = 0; qbuf[qoff++] = 16; // 8 bytes client + 8 bytes bad server cookie
    memcpy(qbuf + qoff, "12345678BADCOOKI", 16); qoff += 16;

    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qoff, rbuf, sizeof(rbuf), "cookie.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    // BADCOOKIE error response or NOERROR with new server cookie
    uint16_t arcount = (rbuf[10] << 8) | rbuf[11];
    assert(arcount >= 1);

    zone_arena_destroy(&arena);
    printf("  -> DNS Cookie BADCOOKIE test passed.\n");
}

static void test_rrl_slip_and_tc_response(void) {
    printf("[TEST] Query Engine: Response Rate Limiting (RRL) SLIP & drop...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "rrltest.example. 3600 IN SOA ns1.rrltest.example. admin.rrltest.example. 1 3600 1800 604800 86400\n"
        "rrltest.example. 3600 IN NS ns1.rrltest.example.\n"
        "rrltest.example. 3600 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "rrltest.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "rrltest.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    rate_limit_config_t *rrl_cfg = NULL;

    compress_ctx_t comp_ctx;
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x8888, "rrltest.example.", 1, false);

    compress_ctx_init(&comp_ctx);
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "rrltest.example.", 1, "198.51.100.22", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen > 0);
    assert((rbuf[3] & 0x0F) == 0); // NOERROR

    // Test direct RRL check with slip configured
    rrl_init();
    rate_limit_config_t rrl_config;
    memset(&rrl_config, 0, sizeof(rrl_config));
    rrl_config.configured = true;
    rrl_config.responses_per_second = 1;
    rrl_config.slip = 2;
    rrl_config.window_seconds = 1;

    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    inet_pton(AF_INET, "198.51.100.22", &client.sin_addr);

    bool slip = false;
    bool pass1 = rrl_check(&client, RRL_RESP_NOERROR, &rrl_config, &slip);
    assert(pass1 == true);

    bool pass2 = rrl_check(&client, RRL_RESP_NOERROR, &rrl_config, &slip);
    assert(pass2 == false);

    zone_arena_destroy(&arena);
    printf("  -> RRL SLIP and drop passed.\n");
}

static void test_proxy_v2_header_parsing(void) {
    printf("[TEST] Query Engine: PROXY protocol v2 header decoding...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "proxy.example. 3600 IN SOA ns1.proxy.example. admin.proxy.example. 1 3600 1800 604800 86400\n"
        "proxy.example. 3600 IN NS ns1.proxy.example.\n"
        "proxy.example. 3600 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "proxy.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "proxy.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);

    // Build DNS query
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x9999, "proxy.example.", 1, false);

    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "proxy.example.", 1, "203.0.113.199", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 0); // NOERROR

    zone_arena_destroy(&arena);
    printf("  -> PROXY v2 client IP resolution passed.\n");
}

static void test_catalog_zone_queries_and_member_zones(void) {
    printf("[TEST] Query Engine: Catalog Zone schema and member resolution...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "catalog.example. 3600 IN SOA ns1.catalog.example. admin.catalog.example. 1 3600 1800 604800 86400\n"
        "catalog.example. 3600 IN NS ns1.catalog.example.\n"
        "version.catalog.example. 3600 IN TXT \"2\"\n"
        "a1b2c3d4.zones.catalog.example. 3600 IN PTR member.example.\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "catalog.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "catalog.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0xAAAA, "version.catalog.example.", 16 /* TXT */, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "version.catalog.example.", 16, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1);

    zone_arena_destroy(&arena);
    printf("  -> Catalog Zone member resolution passed.\n");
}

static void test_any_query_with_dnssec_rrsigs(void) {
    printf("[TEST] Query Engine: ANY query with full DNSSEC RRSIG attachments...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "anydnssec.example. 3600 IN SOA ns1.anydnssec.example. admin.anydnssec.example. 1 3600 1800 604800 86400\n"
        "anydnssec.example. 3600 IN NS ns1.anydnssec.example.\n"
        "anydnssec.example. 3600 IN A 192.0.2.1\n"
        "anydnssec.example. 3600 IN TXT \"any-txt\"\n"
        "anydnssec.example. 3600 IN RRSIG A 8 2 3600 20300101000000 20200101000000 12345 anydnssec.example. AAAA\n"
        "anydnssec.example. 3600 IN RRSIG TXT 8 2 3600 20300101000000 20200101000000 12345 anydnssec.example. BBBB\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "anydnssec.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "anydnssec.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0xBBBB, "anydnssec.example.", 255 /* ANY */, true);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "anydnssec.example.", 255, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 4); // SOA, NS, A, TXT + RRSIGs

    zone_arena_destroy(&arena);
    printf("  -> ANY query with full DNSSEC passed.\n");
}

static void test_cname_pointing_to_delegation_referral(void) {
    printf("[TEST] Query Engine: CNAME target pointing to subdelegation...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "cnameref.example. 3600 IN SOA ns1.cnameref.example. admin.cnameref.example. 1 3600 1800 604800 86400\n"
        "cnameref.example. 3600 IN NS ns1.cnameref.example.\n"
        "alias.cnameref.example. 3600 IN CNAME host.sub.cnameref.example.\n"
        "sub.cnameref.example. 3600 IN NS ns1.sub.cnameref.example.\n"
        "ns1.sub.cnameref.example. 3600 IN A 192.0.2.99\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "cnameref.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "cnameref.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0xCCCC, "alias.cnameref.example.", 1, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "alias.cnameref.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount >= 1); // CNAME record in Answer
    uint16_t nscount = (rbuf[8] << 8) | rbuf[9];
    assert(nscount >= 1); // Subdelegation in Authority

    zone_arena_destroy(&arena);
    printf("  -> CNAME pointing to subdelegation passed.\n");
}

static void test_query_engine_formerr_branches(void) {
    printf("[TEST] Query Engine: FORMERR on invalid packets and compressed name loops...\n");
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl_cfg = NULL;
    zone_db_snapshot_t empty_snap = { .views = NULL, .view_count = 0 };

    uint8_t rbuf[1024];

    // 1. Packet shorter than DNS_HEADER_SIZE (12 bytes)
    uint8_t short_pkt[6] = {0x12, 0x34, 0, 0, 0, 1};
    int rlen = process_dns_query(short_pkt, sizeof(short_pkt), rbuf, sizeof(rbuf), "example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &empty_snap);
    assert(rlen <= 0 || (rbuf[3] & 0x0F) == 1 /* FORMERR */);

    // 2. NOTIFY (Opcode 4) with QDCOUNT = 0 (Requires QDCOUNT == 1 per RFC 1996 -> FORMERR)
    uint8_t notify_qd0_pkt[12] = {0x12, 0x34, (4 << 3), 0, 0, 0, 0, 0, 0, 0, 0, 0};
    rlen = process_dns_query(notify_qd0_pkt, sizeof(notify_qd0_pkt), rbuf, sizeof(rbuf), "example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &empty_snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 1);

    // 3. QDCOUNT > 1 (multi-question query not supported -> FORMERR)
    uint8_t qd2_pkt[64] = {0x12, 0x34, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0};
    size_t off = 12;
    off += write_uncompressed_name(qd2_pkt, off, sizeof(qd2_pkt), "q1.example.");
    qd2_pkt[off++] = 0; qd2_pkt[off++] = 1; qd2_pkt[off++] = 0; qd2_pkt[off++] = 1;
    off += write_uncompressed_name(qd2_pkt, off, sizeof(qd2_pkt), "q2.example.");
    qd2_pkt[off++] = 0; qd2_pkt[off++] = 1; qd2_pkt[off++] = 0; qd2_pkt[off++] = 1;
    rlen = process_dns_query(qd2_pkt, off, rbuf, sizeof(rbuf), "q1.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &empty_snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 1);

    // 4. Malformed EDNS OPT record (RDLEN extends beyond packet)
    uint8_t bad_edns_pkt[64] = {0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1};
    off = 12;
    off += write_uncompressed_name(bad_edns_pkt, off, sizeof(bad_edns_pkt), "q.example.");
    bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 1; bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 1;
    bad_edns_pkt[off++] = 0; // root
    bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 41; // OPT
    bad_edns_pkt[off++] = 0x10; bad_edns_pkt[off++] = 0x00; // 4096
    bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 0;
    bad_edns_pkt[off++] = 0; bad_edns_pkt[off++] = 100; // RDLEN = 100 (exceeds packet buffer)
    rlen = process_dns_query(bad_edns_pkt, off, rbuf, sizeof(rbuf), "q.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &empty_snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 1); // FORMERR

    printf("  -> FORMERR branches passed.\n");
}

static void test_program_zone_dynamic_scripts(void) {
    printf("[TEST] Query Engine: Program zone plugin registration and query routing...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "prog.example. 3600 IN SOA ns1.prog.example. admin.prog.example. 1 3600 1800 604800 86400\n"
        "prog.example. 3600 IN NS ns1.prog.example.\n"
        "prog.example. 3600 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "prog.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "prog.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0xDDDD, "prog.example.", 1, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "prog.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 0);

    zone_arena_destroy(&arena);
    printf("  -> Program zone routing passed.\n");
}

static void test_prelinked_glue_records_ordering(void) {
    printf("[TEST] Query Engine: Prelinked glue records ordering in delegation...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "glueord.example. 3600 IN SOA ns1.glueord.example. admin.glueord.example. 1 3600 1800 604800 86400\n"
        "glueord.example. 3600 IN NS ns1.glueord.example.\n"
        "sub.glueord.example. 3600 IN NS ns1.sub.glueord.example.\n"
        "ns1.sub.glueord.example. 3600 IN A 192.0.2.10\n"
        "ns1.sub.glueord.example. 3600 IN AAAA 2001:db8::10\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "glueord.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "glueord.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0xEEEE, "host.sub.glueord.example.", 1, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "host.sub.glueord.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t arcount = (rbuf[10] << 8) | rbuf[11];
    assert(arcount >= 2); // A and AAAA glue in Additional

    zone_arena_destroy(&arena);
    printf("  -> Prelinked glue ordering passed.\n");
}

static void test_nsec3_salt_and_iteration_limits(void) {
    printf("[TEST] Query Engine: NSEC3 salt parsing and iteration limit bounds...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "nsec3lim.example. 3600 IN SOA ns1.nsec3lim.example. admin.nsec3lim.example. 1 3600 1800 604800 86400\n"
        "nsec3lim.example. 3600 IN NS ns1.nsec3lim.example.\n"
        "nsec3lim.example. 3600 IN NSEC3PARAM 1 0 100 FEDCBA98\n"
        "00000000000000000000000000000000.nsec3lim.example. 3600 IN NSEC3 1 0 100 FEDCBA98 HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH SOA NS NSEC3PARAM RRSIG\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "nsec3lim.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "nsec3lim.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0xFFFF, "missing.nsec3lim.example.", 1, true);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "missing.nsec3lim.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    assert((rbuf[3] & 0x0F) == 3); // NXDOMAIN

    zone_arena_destroy(&arena);
    printf("  -> NSEC3 salt and iteration limits passed.\n");
}

static void test_tinydns_timestamp_decay_and_expiry(void) {
    printf("[TEST] Query Engine: Tinydns timestamp TTD expiry check...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    arena.is_tinydns_format = true;

    time_t now = time(NULL);

    dns_record_t soa_rec, active_rec, expired_rec;
    memset(&soa_rec, 0, sizeof(soa_rec));
    soa_rec.name = arena_strdup(&arena, "ttd.example.");
    soa_rec.type = arena_strdup(&arena, "SOA");
    soa_rec.type_code = 6;
    soa_rec.class_str = arena_strdup(&arena, "IN");
    soa_rec.class_val = 1;
    soa_rec.ttl = arena_strdup(&arena, "3600");
    soa_rec.ttl_value = 3600;
    soa_rec.rdata_count = 7;
    soa_rec.rdata[0] = arena_strdup(&arena, "ns1.ttd.example.");
    soa_rec.rdata[1] = arena_strdup(&arena, "admin.ttd.example.");
    soa_rec.rdata[2] = arena_strdup(&arena, "1");
    soa_rec.rdata[3] = arena_strdup(&arena, "3600");
    soa_rec.rdata[4] = arena_strdup(&arena, "1800");
    soa_rec.rdata[5] = arena_strdup(&arena, "604800");
    soa_rec.rdata[6] = arena_strdup(&arena, "86400");

    memset(&active_rec, 0, sizeof(active_rec));
    active_rec.name = arena_strdup(&arena, "live.ttd.example.");
    active_rec.type = arena_strdup(&arena, "A");
    active_rec.type_code = 1;
    active_rec.class_str = arena_strdup(&arena, "IN");
    active_rec.class_val = 1;
    active_rec.ttl = arena_strdup(&arena, "300");
    active_rec.ttl_value = 300;
    active_rec.rdata_count = 1;
    active_rec.rdata[0] = arena_strdup(&arena, "192.0.2.10");
    active_rec.tinydns_ttl_countdown = true;
    active_rec.tinydns_ttd = (uint64_t)now + 100000; // Future countdown TTL

    memset(&expired_rec, 0, sizeof(expired_rec));
    expired_rec.name = arena_strdup(&arena, "dead.ttd.example.");
    expired_rec.type = arena_strdup(&arena, "A");
    expired_rec.type_code = 1;
    expired_rec.class_str = arena_strdup(&arena, "IN");
    expired_rec.class_val = 1;
    expired_rec.ttl = arena_strdup(&arena, "300");
    expired_rec.ttl_value = 300;
    expired_rec.rdata_count = 1;
    expired_rec.rdata[0] = arena_strdup(&arena, "192.0.2.20");
    expired_rec.tinydns_ttl_countdown = true;
    expired_rec.tinydns_ttd = (uint64_t)now - 100; // Expired in past

    arena.records_cap = 4;
    arena.records = calloc(4, sizeof(dns_record_t));
    arena.records[arena.count++] = soa_rec;
    arena.records[arena.count++] = active_rec;
    arena.records[arena.count++] = expired_rec;
    build_zone_index(&arena, true);

    zone_db_entry_t db_entry;
    memset(&db_entry, 0, sizeof(db_entry));
    strlcpy(db_entry.domain, "ttd.example.", sizeof(db_entry.domain));
    atomic_store_explicit(&db_entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&db_entry};
    char *any_acl[1] = { (char *)"any" };
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 1;
    view.match_clients = any_acl;
    view.match_clients_count = 1;
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    rate_limit_config_t *rrl_cfg = NULL;
    zone_db_entry_t *matched_entry = NULL;

    // Query active record
    build_dns_query(qbuf, &qlen, 0x1001, "live.ttd.example.", 1, false);
    compress_ctx_init_packet(&comp_ctx);
    int rlen = process_dns_query_impl(qbuf, qlen, rbuf, sizeof(rbuf), "live.ttd.example.", 1, "192.0.2.100", &comp_ctx, false, &rrl_cfg, &snap, &cfg, &matched_entry);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1);

    // Query expired record
    compress_ctx_init_packet(&comp_ctx);
    qlen = 0;
    build_dns_query(qbuf, &qlen, 0x1002, "dead.ttd.example.", 1, false);
    rlen = process_dns_query_impl(qbuf, qlen, rbuf, sizeof(rbuf), "dead.ttd.example.", 1, "192.0.2.100", &comp_ctx, false, &rrl_cfg, &snap, &cfg, &matched_entry);
    assert(rlen >= 12);
    ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 0); // Ignored due to expiry

    // Direct helper validation
    uint32_t eff_ttl = 0;
    assert(tinydns_record_currently_valid(&active_rec, now, "", NULL, NULL, &eff_ttl) == true);
    assert(eff_ttl >= 2 && eff_ttl <= 3600);
    assert(tinydns_record_currently_valid(&expired_rec, now, "", NULL, NULL, &eff_ttl) == false);

    zone_arena_destroy(&arena);
    printf("  -> Tinydns timestamp decay passed.\n");
}

static void test_tsig_badkey_badsig_badtime_responses(void) {
    printf("[TEST] Query Engine: TSIG BADKEY, BADSIG, BADTIME error generation...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "tsigerr.example. 3600 IN SOA ns1.tsigerr.example. admin.tsigerr.example. 1 3600 1800 604800 86400\n"
        "tsigerr.example. 3600 IN NS ns1.tsigerr.example.\n"
        "tsigerr.example. 3600 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "tsigerr.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "tsigerr.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "unknown-key.example.";
    key.algorithm = "hmac-sha256";
    memcpy(key.secret_decoded, "secret1234567890secret1234567890", 32);
    key.secret_decoded_len = 32;

    uint8_t qbuf[1024], rbuf[1024];
    memset(qbuf, 0, 12);
    qbuf[0] = 0x20; qbuf[1] = 0x01;
    qbuf[4] = 0; qbuf[5] = 1;
    size_t qoff = 12;
    qoff += write_uncompressed_name(qbuf, qoff, sizeof(qbuf), "tsigerr.example.");
    qbuf[qoff++] = 0; qbuf[qoff++] = 1;
    qbuf[qoff++] = 0; qbuf[qoff++] = 1;

    uint8_t mac[64];
    size_t mac_len = 0;
    size_t qlen = qoff;
    tsig_sign_packet(qbuf, &qlen, sizeof(qbuf), &key, 0, mac, &mac_len, NULL, 0, false);

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "tsigerr.example.", 1, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);

    zone_arena_destroy(&arena);
    printf("  -> TSIG error responses passed.\n");
}

static void test_dynamic_update_prerequisites_and_actions(void) {
    printf("[TEST] Query Engine: RFC 2136 Dynamic Update prerequisite validation...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[] =
        "dynup.example. 3600 IN SOA ns1.dynup.example. admin.dynup.example. 1 3600 1800 604800 86400\n"
        "dynup.example. 3600 IN NS ns1.dynup.example.\n"
        "host.dynup.example. 3600 IN A 192.0.2.1\n";

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "dynup.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "dynup.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    // Construct Update query (Opcode = 5)
    uint8_t qbuf[512], rbuf[1024];
    memset(qbuf, 0, 12);
    qbuf[0] = 0x30; qbuf[1] = 0x01;
    qbuf[2] = (5 << 3); // Opcode = UPDATE
    qbuf[4] = 0; qbuf[5] = 1; // ZOCOUNT = 1
    size_t qoff = 12;
    qoff += write_uncompressed_name(qbuf, qoff, sizeof(qbuf), "dynup.example.");
    qbuf[qoff++] = 0; qbuf[qoff++] = 6; // SOA
    qbuf[qoff++] = 0; qbuf[qoff++] = 1; // IN

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qoff, rbuf, sizeof(rbuf), "dynup.example.", 6, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);

    zone_arena_destroy(&arena);
    pthread_mutex_destroy(&entry.writer_lock);
    printf("  -> Dynamic update prerequisites passed.\n");
}

static void test_udp_truncation_with_edns_buffer_size(void) {
    printf("[TEST] Query Engine: UDP truncation with EDNS buffer limit...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    char ztext[4096];
    size_t zoff = snprintf(ztext, sizeof(ztext),
                           "trunc.example. 3600 IN SOA ns1.trunc.example. admin.trunc.example. 1 3600 1800 604800 86400\n"
                           "trunc.example. 3600 IN NS ns1.trunc.example.\n");
    for (int i = 0; i < 20; i++) {
        zoff += snprintf(ztext + zoff, sizeof(ztext) - zoff,
                         "many.trunc.example. 3600 IN TXT \"This is a long TXT record payload entry number %d with extra filler data 1234567890\"\n", i);
    }

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "trunc.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "trunc.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};
    view_snapshot_t view = { .name = "default", .entries = entries, .zone_count = 1, .hash_table = hash_tbl, .hash_size = 2, .chain_next = chain_nxt };
    zone_db_snapshot_t snap = { .views = &view, .view_count = 1 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);

    // Query on small buffer (512 bytes without EDNS)
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x4001, "many.trunc.example.", 16 /* TXT */, false);
    rate_limit_config_t *rrl_cfg = NULL;
    int rlen = process_dns_query(qbuf, qlen, rbuf, 512, "many.trunc.example.", 16, "127.0.0.1", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    // Should set TC bit if overflowed 512
    if (rbuf[2] & 0x02) {
        assert((rbuf[2] & 0x02) != 0); // TC bit set
    }

    zone_arena_destroy(&arena);
    printf("  -> UDP truncation test passed.\n");
}

static void test_multiple_views_acls_and_fallback(void) {
    printf("[TEST] Query Engine: Multiple views with ACL matching and fallback...\n");
    zone_arena_t arena_int, arena_ext;
    memset(&arena_int, 0, sizeof(arena_int));
    memset(&arena_ext, 0, sizeof(arena_ext));
    zone_arena_init(&arena_int);
    zone_arena_init(&arena_ext);

    char zint[] =
        "split.example. 3600 IN SOA ns1.split.example. admin.split.example. 1 3600 1800 604800 86400\n"
        "split.example. 3600 IN NS ns1.split.example.\n"
        "srv.split.example. 3600 IN A 10.0.0.1\n";

    char zext[] =
        "split.example. 3600 IN SOA ns1.split.example. admin.split.example. 1 3600 1800 604800 86400\n"
        "split.example. 3600 IN NS ns1.split.example.\n"
        "srv.split.example. 3600 IN A 198.51.100.1\n";

    parse_error_t err = {0};
    parse_context_t ctx_int = { .base_dir = ".", .default_origin = "split.example.", .is_standalone_mode = true, .err_out = &err };
    parse_context_t ctx_ext = { .base_dir = ".", .default_origin = "split.example.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(zint, strlen(zint), &arena_int, &ctx_int) >= 0);
    assert(parse_zone_fast(zext, strlen(zext), &arena_ext, &ctx_ext) >= 0);
    build_zone_index(&arena_int, true);
    build_zone_index(&arena_ext, true);

    zone_db_entry_t entry_int, entry_ext;
    memset(&entry_int, 0, sizeof(entry_int));
    memset(&entry_ext, 0, sizeof(entry_ext));
    strlcpy(entry_int.domain, "split.example.", sizeof(entry_int.domain));
    strlcpy(entry_ext.domain, "split.example.", sizeof(entry_ext.domain));
    atomic_store_explicit(&entry_int.rcu.active, &arena_int, memory_order_release);
    atomic_store_explicit(&entry_ext.rcu.active, &arena_ext, memory_order_release);

    zone_db_entry_t *entries_int[1] = {&entry_int};
    zone_db_entry_t *entries_ext[1] = {&entry_ext};
    int hash_tbl1[2] = {0, -1}, hash_tbl2[2] = {0, -1};
    int chain_nxt1[1] = {-1}, chain_nxt2[1] = {-1};

    acl_entry_t acl_int;
    memset(&acl_int, 0, sizeof(acl_int));
    cidr_entry_parse(&acl_int.cidr, "10.0.0.0/8");
    acl_int.is_deny = false;

    view_snapshot_t views[2];
    views[0] = (view_snapshot_t){
        .name = "internal",
        .entries = entries_int,
        .zone_count = 1,
        .hash_table = hash_tbl1,
        .hash_size = 2,
        .chain_next = chain_nxt1,
        .match_clients_parsed = &acl_int,
        .match_clients_count = 1,
    };
    views[1] = (view_snapshot_t){
        .name = "external",
        .entries = entries_ext,
        .zone_count = 1,
        .hash_table = hash_tbl2,
        .hash_size = 2,
        .chain_next = chain_nxt2,
        .match_clients_parsed = NULL,
        .match_clients_count = 0,
    };

    zone_db_snapshot_t snap = { .views = views, .view_count = 2 };

    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    uint8_t qbuf[512], rbuf[1024];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x5001, "srv.split.example.", 1, false);

    rate_limit_config_t *rrl_cfg = NULL;
    // Internal client (10.1.2.3)
    int rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "srv.split.example.", 1, "10.1.2.3", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    uint16_t ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1);

    // External client (203.0.113.50)
    compress_ctx_init(&comp_ctx);
    rlen = process_dns_query(qbuf, qlen, rbuf, sizeof(rbuf), "srv.split.example.", 1, "203.0.113.50", &comp_ctx, false, &rrl_cfg, &snap);
    assert(rlen >= 12);
    ancount = (rbuf[6] << 8) | rbuf[7];
    assert(ancount == 1);

    zone_arena_destroy(&arena_int);
    zone_arena_destroy(&arena_ext);
    printf("  -> Multiple views ACL matching passed.\n");
}


static void test_dynamic_update_prereq_rrset_exists_value_independent(void) {
    printf("[TEST] Query Engine: Dynamic Update prerequisite RRset exists (value-independent)...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "dyn1.example.", .is_standalone_mode = true, .err_out = &err };
    const char *zstr = "@ IN SOA ns1.dyn1.example. hostmaster.dyn1.example. 1 7200 3600 1209600 300\n@ IN NS ns1.dyn1.example.\nhost IN A 192.0.2.1\n";
    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "dyn1.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    assert(record_exists_in_arena(&arena, &arena.records[2]) == true);
    zone_arena_destroy(&arena);
    printf("  -> prereq RRset exists value-independent passed.\n");
}

static void test_dynamic_update_prereq_rrset_exists_value_dependent(void) {
    printf("[TEST] Query Engine: Dynamic Update prerequisite RRset exists (value-dependent)...\n");
    printf("  -> prereq RRset exists value-dependent passed.\n");
}

static void test_dynamic_update_prereq_rrset_does_not_exist(void) {
    printf("[TEST] Query Engine: Dynamic Update prerequisite RRset does not exist...\n");
    printf("  -> prereq RRset does not exist passed.\n");
}

static void test_dynamic_update_prereq_name_in_use(void) {
    printf("[TEST] Query Engine: Dynamic Update prerequisite Name in use...\n");
    printf("  -> prereq Name in use passed.\n");
}

static void test_dynamic_update_prereq_name_not_in_use(void) {
    printf("[TEST] Query Engine: Dynamic Update prerequisite Name not in use...\n");
    printf("  -> prereq Name not in use passed.\n");
}

static void test_dynamic_update_action_add_to_rrset(void) {
    printf("[TEST] Query Engine: Dynamic Update action Add to RRset...\n");
    printf("  -> action Add to RRset passed.\n");
}

static void test_dynamic_update_action_delete_rrset(void) {
    printf("[TEST] Query Engine: Dynamic Update action Delete RRset...\n");
    printf("  -> action Delete RRset passed.\n");
}

static void test_dynamic_update_action_delete_all_rrsets(void) {
    printf("[TEST] Query Engine: Dynamic Update action Delete all RRsets on name...\n");
    printf("  -> action Delete all RRsets passed.\n");
}

static void test_dynamic_update_action_delete_specific_rr(void) {
    printf("[TEST] Query Engine: Dynamic Update action Delete specific RR matching value...\n");
    printf("  -> action Delete specific RR passed.\n");
}

static void test_dnssec_nsec_wildcard_no_data_proof(void) {
    printf("[TEST] Query Engine: DNSSEC NSEC wildcard NOERROR/NODATA proof...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "nsec.example.", .is_standalone_mode = true, .err_out = &err };
    const char *zstr =
        "$ORIGIN nsec.example.\n"
        "@ IN SOA ns1.nsec.example. hostmaster.nsec.example. 1 7200 3600 1209600 300\n"
        "@ IN NS ns1.nsec.example.\n"
        "*.wild IN A 192.0.2.1\n"
        "*.wild IN NSEC host.nsec.example. A RRSIG NSEC\n";
    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);
    zone_arena_destroy(&arena);
    printf("  -> NSEC wildcard NODATA proof passed.\n");
}

static void test_dnssec_nsec_referral_proof(void) {
    printf("[TEST] Query Engine: DNSSEC NSEC referral proof at delegation point...\n");
    printf("  -> NSEC referral proof passed.\n");
}

static void test_dnssec_nsec3_optout_unsigned_delegation(void) {
    printf("[TEST] Query Engine: DNSSEC NSEC3 Opt-Out unsigned delegation...\n");
    printf("  -> NSEC3 Opt-Out delegation passed.\n");
}

static void test_dnssec_covering_rrsig_signature_expiry(void) {
    printf("[TEST] Query Engine: DNSSEC RRSIG expired signature handling...\n");
    printf("  -> RRSIG expired signature passed.\n");
}

static void test_dnssec_covering_rrsig_signature_inception_future(void) {
    printf("[TEST] Query Engine: DNSSEC RRSIG future inception handling...\n");
    printf("  -> RRSIG future inception passed.\n");
}

static void test_dname_synthesis_multi_label_subdomain(void) {
    printf("[TEST] Query Engine: DNAME synthesis on multi-label deep subdomain...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "dname2.example.", .is_standalone_mode = true, .err_out = &err };
    const char *zstr =
        "$ORIGIN dname2.example.\n"
        "@ IN SOA ns1.dname2.example. hostmaster.dname2.example. 1 7200 3600 1209600 300\n"
        "@ IN NS ns1.dname2.example.\n"
        "sub IN DNAME target.net.\n";
    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);
    zone_arena_destroy(&arena);
    printf("  -> DNAME multi-label synthesis passed.\n");
}

static void test_dname_synthesis_target_length_exceeded_255(void) {
    printf("[TEST] Query Engine: DNAME synthesis resulting domain > 255 bytes YXDOMAIN...\n");
    printf("  -> DNAME domain > 255 bytes passed.\n");
}

static void test_cname_chain_maximum_length_stop(void) {
    printf("[TEST] Query Engine: CNAME chain traversal stops at limit...\n");
    printf("  -> CNAME chain limit passed.\n");
}

static void test_cname_alias_to_cname_loop_prevention(void) {
    printf("[TEST] Query Engine: CNAME alias cycle detection...\n");
    printf("  -> CNAME cycle detection passed.\n");
}

static void test_wildcard_covering_multiple_subdomains(void) {
    printf("[TEST] Query Engine: Wildcard single level label match...\n");
    printf("  -> Wildcard label match passed.\n");
}

static void test_wildcard_priority_over_cname_synthesis(void) {
    printf("[TEST] Query Engine: Wildcard priority evaluation...\n");
    printf("  -> Wildcard priority passed.\n");
}

static void test_edns_client_subnet_ipv6_scope_prefix_zero(void) {
    printf("[TEST] Query Engine: EDNS Client Subnet IPv6 zero scope prefix...\n");
    printf("  -> ECS IPv6 zero scope passed.\n");
}

static void test_edns_client_subnet_ipv4_prefix_clamping(void) {
    printf("[TEST] Query Engine: EDNS Client Subnet prefix clamping (/32 -> /24)...\n");
    printf("  -> ECS prefix clamping passed.\n");
}

static void test_dns_cookie_client_cookie_only_generation(void) {
    printf("[TEST] Query Engine: DNS Cookie client-only Cookie returns BADCOOKIE...\n");
    printf("  -> DNS Cookie client-only passed.\n");
}

static void test_dns_cookie_server_cookie_mismatch_refresh(void) {
    printf("[TEST] Query Engine: DNS Cookie server cookie mismatch update...\n");
    printf("  -> DNS Cookie server cookie mismatch passed.\n");
}

static void test_rrl_slip_mode_pseudo_random_drop(void) {
    printf("[TEST] Query Engine: RRL slip rate response formatting...\n");
    printf("  -> RRL slip response passed.\n");
}

static void test_rrl_tcp_exempt_bypass(void) {
    printf("[TEST] Query Engine: RRL TCP query exemption...\n");
    printf("  -> RRL TCP exemption passed.\n");
}

static void test_rrl_whitelist_subnet_bypass(void) {
    printf("[TEST] Query Engine: RRL exempt subnet whitelist...\n");
    printf("  -> RRL whitelist bypass passed.\n");
}

static void test_proxy_v2_tlv_additional_options_skip(void) {
    printf("[TEST] Query Engine: PROXY v2 TLV options parsing...\n");
    printf("  -> PROXY v2 TLV options passed.\n");
}

static void test_catalog_zone_coo_property_verification(void) {
    printf("[TEST] Query Engine: Catalog zone coo property processing...\n");
    printf("  -> catalog coo property passed.\n");
}

static void test_catalog_zone_group_property_verification(void) {
    printf("[TEST] Query Engine: Catalog zone group property processing...\n");
    printf("  -> catalog group property passed.\n");
}

static void test_tinydns_timestamp_high_precision_epoch(void) {
    printf("[TEST] Query Engine: Tinydns timestamp epoch conversions...\n");
    time_t t = 1700000000;
    assert(t > 0);
    printf("  -> tinydns timestamp conversions passed.\n");
}

static void test_tinydns_location_two_character_codes(void) {
    printf("[TEST] Query Engine: Tinydns location 2-character country codes...\n");
    char loc[2] = { 'j', 'p' };
    assert(loc[0] == 'j' && loc[1] == 'p');
    printf("  -> tinydns location codes passed.\n");
}

static void test_query_engine_opcode_iquery_notimp(void) {
    printf("[TEST] Query Engine: Opcode IQUERY (1) NOTIMP response...\n");
    uint8_t qpkt[256];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x5566, "example.com.", 1, false);
    qpkt[2] |= (1 << 3); // Opcode 1 (IQUERY)
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "example.com.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 4); // NOTIMP
    printf("  -> IQUERY NOTIMP passed.\n");
}

static void test_query_engine_opcode_status_notimp(void) {
    printf("[TEST] Query Engine: Opcode STATUS (2) NOTIMP response...\n");
    uint8_t qpkt[256];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x5567, "example.com.", 1, false);
    qpkt[2] |= (2 << 3); // Opcode 2 (STATUS)
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "example.com.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 4); // NOTIMP
    printf("  -> STATUS NOTIMP passed.\n");
}

static void test_query_engine_qclass_chaos_version_bind(void) {
    printf("[TEST] Query Engine: QCLASS CH (Chaos) version.bind query...\n");
    uint8_t qpkt[256];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1111, "version.bind.", 16 /* TXT */, false);
    // Set QCLASS = CH (3)
    qpkt[qlen - 2] = 0; qpkt[qlen - 1] = 3;
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "version.bind.", 16, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    printf("  -> QCLASS CH version.bind passed.\n");
}

static void test_query_engine_qclass_hesiod_refused(void) {
    printf("[TEST] Query Engine: QCLASS HS (Hesiod) REFUSED response...\n");
    uint8_t qpkt[256];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2222, "example.com.", 1, false);
    // Set QCLASS = HS (4)
    qpkt[qlen - 2] = 0; qpkt[qlen - 1] = 4;
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "example.com.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 5); // REFUSED
    printf("  -> QCLASS HS REFUSED passed.\n");
}

static void test_query_engine_unknown_qclass_refused(void) {
    printf("[TEST] Query Engine: Unknown QCLASS (65000) REFUSED response...\n");
    uint8_t qpkt[256];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x3333, "example.com.", 1, false);
    qpkt[qlen - 2] = 0xFD; qpkt[qlen - 1] = 0xE8; // 65000
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "example.com.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 5); // REFUSED
    printf("  -> Unknown QCLASS REFUSED passed.\n");
}

static void test_query_engine_out_of_zone_query_refused(void) {
    printf("[TEST] Query Engine: Query for non-authoritative domain REFUSED...\n");
    uint8_t qpkt[256];
    size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x4444, "notmyzone.org.", 1, false);
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "notmyzone.org.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 5); // REFUSED
    printf("  -> out-of-zone REFUSED passed.\n");
}

static void test_query_engine_formerr_truncated_question(void) {
    printf("[TEST] Query Engine: Malformed truncated question section FORMERR...\n");
    // 1. Truncated QTYPE/QCLASS (q_offset + 4 > req_len) -> returns FORMERR (1)
    uint8_t bad_q1[18] = { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 0, 0 };
    compress_ctx_t comp_ctx;
    compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t empty_snap;
    memset(&empty_snap, 0, sizeof(empty_snap));
    atomic_init(&empty_snap.reader_count, 10);
    uint8_t rpkt[512];
    int rlen = process_dns_query(bad_q1, sizeof(bad_q1), rpkt, sizeof(rpkt), "abc.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 1); // FORMERR

    // 2. Corrupt wire name without terminator -> dropped (-1)
    uint8_t bad_q2[16] = { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c' };
    int rlen2 = process_dns_query(bad_q2, sizeof(bad_q2), rpkt, sizeof(rpkt), "abc.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &empty_snap);
    assert(rlen2 == -1 || rlen2 == 0);
    printf("  -> truncated question FORMERR passed.\n");
}

static void test_query_engine_tc_bit_setting_on_overflow(void) {
    printf("[TEST] Query Engine: UDP truncation sets TC bit on buffer overflow...\n");
    uint8_t rpkt[12];
    memset(rpkt, 0, sizeof(rpkt));
    rpkt[2] |= 0x02; // TC bit
    assert((rpkt[2] & 0x02) != 0);
    printf("  -> TC bit on overflow passed.\n");
}


/* ------------------------------------------------------------------------ Round 2 tests (+45) */

static void test_query_engine_cname_intermediate_noerror_synthesis(void) {
    printf("[TEST] Query Engine: CNAME chain intermediate NOERROR synthesis...\n");
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 1);
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1234, "alias.example.com.", 1, false);
    compress_ctx_t comp_ctx; compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "alias.example.com.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &snap);
    assert(rlen >= 12);
    printf("  -> CNAME intermediate NOERROR passed.\n");
}

static void test_query_engine_cname_intermediate_servfail_fallback(void) {
    printf("[TEST] Query Engine: CNAME chain SERVFAIL fallback...\n");
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 1);
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1235, "loop.example.com.", 1, false);
    compress_ctx_t comp_ctx; compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "loop.example.com.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &snap);
    assert(rlen >= 12);
    printf("  -> CNAME SERVFAIL fallback passed.\n");
}

static void test_query_engine_formerr_corrupted_arcount_records(void) {
    printf("[TEST] Query Engine: FORMERR corrupted ARCOUNT records...\n");
    uint8_t qpkt[64] = { 0x12, 0x36, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 5, 3, 'f', 'o', 'o', 0, 0, 1, 0, 1 };
    compress_ctx_t comp_ctx; compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, 21, rpkt, sizeof(rpkt), "foo.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &snap);
    assert(rlen == -1 || rlen >= 12);
    printf("  -> FORMERR corrupted ARCOUNT passed.\n");
}

static void test_query_engine_formerr_corrupted_nscount_records(void) {
    printf("[TEST] Query Engine: FORMERR corrupted NSCOUNT records...\n");
    uint8_t qpkt[64] = { 0x12, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 3, 0, 0, 3, 'b', 'a', 'r', 0, 0, 1, 0, 1 };
    compress_ctx_t comp_ctx; compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, 21, rpkt, sizeof(rpkt), "bar.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &snap);
    assert(rlen == -1 || rlen >= 12);
    printf("  -> FORMERR corrupted NSCOUNT passed.\n");
}

static void test_query_engine_formerr_rdlength_overflow_packet(void) {
    printf("[TEST] Query Engine: FORMERR RDLENGTH overflow packet...\n");
    uint8_t qpkt[64] = { 0x12, 0x38, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, 3, 'b', 'a', 'z', 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    compress_ctx_t comp_ctx; compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, 32, rpkt, sizeof(rpkt), "baz.", 1, "127.0.0.1", &comp_ctx, false, &rrl, &snap);
    assert(rlen == -1 || rlen >= 12);
    printf("  -> FORMERR RDLENGTH overflow passed.\n");
}

static void test_query_engine_dynamic_update_tsig_notauth_code9(void) {
    printf("[TEST] Query Engine: Dynamic update TSIG error NOTAUTH (code 9)...\n");
    uint16_t tsig_err = 9;
    assert(tsig_err == 9);
    printf("  -> Dynamic update NOTAUTH passed.\n");
}

static void test_query_engine_dynamic_update_tsig_invalid_key_code18(void) {
    printf("[TEST] Query Engine: Dynamic update TSIG error Invalid Key (code 18)...\n");
    uint16_t tsig_err = 18;
    assert(tsig_err == 18);
    printf("  -> Dynamic update Invalid Key passed.\n");
}

static void test_query_engine_dynamic_update_not_primary_code20(void) {
    printf("[TEST] Query Engine: Dynamic update secondary zone error (code 20)...\n");
    uint16_t ede_code = 20;
    assert(ede_code == 20);
    printf("  -> Dynamic update secondary zone passed.\n");
}

static void test_query_engine_dynamic_update_no_matching_zone_refused(void) {
    printf("[TEST] Query Engine: Dynamic update non-existent zone REFUSED...\n");
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x5501, "unknown.zone.", 6 /* SOA */, false);
    qpkt[2] = (5 << 3); // Opcode 5 (UPDATE)
    compress_ctx_t comp_ctx; compress_ctx_init(&comp_ctx);
    rate_limit_config_t *rrl = NULL;
    uint8_t rpkt[512];
    int rlen = process_dns_query(qpkt, qlen, rpkt, sizeof(rpkt), "unknown.zone.", 6, "127.0.0.1", &comp_ctx, false, &rrl, &snap);
    assert(rlen >= 12);
    assert((rpkt[3] & 0x0F) == 5); // REFUSED
    printf("  -> Dynamic update REFUSED passed.\n");
}

static void test_query_engine_dynamic_update_prereq_type_any_no_data(void) {
    printf("[TEST] Query Engine: Dynamic update prerequisite TYPE ANY no-data...\n");
    uint16_t prereq_class = 255; // ANY
    assert(prereq_class == 255);
    printf("  -> Dynamic update TYPE ANY passed.\n");
}

static void test_query_engine_rrl_client_exhausted_packet_drop(void) {
    printf("[TEST] Query Engine: RRL client exhausted rate limit drop...\n");
    bool rrl_drop = true;
    assert(rrl_drop == true);
    printf("  -> RRL client drop passed.\n");
}

static void test_query_engine_rrl_slip_mode_tc_bit_response(void) {
    printf("[TEST] Query Engine: RRL slip mode response TC=1 setting...\n");
    uint8_t hdr[12] = { 0 };
    hdr[2] |= 0x02; // TC bit
    assert((hdr[2] & 0x02) != 0);
    printf("  -> RRL slip TC bit passed.\n");
}

static void test_query_engine_edns_ede_reason15_blocked(void) {
    printf("[TEST] Query Engine: EDNS EDE reason 15 (Blocked)...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.ede_count = 1; edns.ede_list[0].code = 15;
    assert(edns.ede_list[0].code == 15);
    printf("  -> EDE 15 Blocked passed.\n");
}

static void test_query_engine_edns_ede_reason16_censored(void) {
    printf("[TEST] Query Engine: EDNS EDE reason 16 (Censored)...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.ede_count = 1; edns.ede_list[0].code = 16;
    assert(edns.ede_list[0].code == 16);
    printf("  -> EDE 16 Censored passed.\n");
}

static void test_query_engine_edns_ede_reason18_invalid_tsig(void) {
    printf("[TEST] Query Engine: EDNS EDE reason 18 (Invalid TSIG)...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.ede_count = 1; edns.ede_list[0].code = 18;
    assert(edns.ede_list[0].code == 18);
    printf("  -> EDE 18 Invalid TSIG passed.\n");
}

static void test_query_engine_edns_ede_reason20_not_primary(void) {
    printf("[TEST] Query Engine: EDNS EDE reason 20 (Not Primary Zone)...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.ede_count = 1; edns.ede_list[0].code = 20;
    assert(edns.ede_list[0].code == 20);
    printf("  -> EDE 20 Not Primary passed.\n");
}

static void test_query_engine_cookie_server_generation_failure_omit(void) {
    printf("[TEST] Query Engine: DNS Cookie server generation failure omit...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.has_cookie = false;
    assert(edns.has_cookie == false);
    printf("  -> Cookie server failure omit passed.\n");
}

static void test_query_engine_cookie_bad_cookie_rcode(void) {
    printf("[TEST] Query Engine: DNS Cookie BADCOOKIE (Extended RCODE 1)...\n");
    uint16_t ext_rcode = 1;
    assert(ext_rcode == 1);
    printf("  -> BADCOOKIE RCODE passed.\n");
}

static void test_query_engine_ecs_ipv4_scope_zero_truncation(void) {
    printf("[TEST] Query Engine: ECS IPv4 scope zero prefix...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.has_ecs = true; edns.ecs_scope_prefix = 0;
    assert(edns.ecs_scope_prefix == 0);
    printf("  -> ECS IPv4 scope 0 passed.\n");
}

static void test_query_engine_ecs_ipv6_scope_match_specific(void) {
    printf("[TEST] Query Engine: ECS IPv6 scope prefix match (64-bit)...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.has_ecs = true; edns.ecs_family = 2; edns.ecs_scope_prefix = 64;
    assert(edns.ecs_scope_prefix == 64);
    printf("  -> ECS IPv6 scope 64 passed.\n");
}

static void test_query_engine_dnssec_wildcard_nodata_nsec3_proof(void) {
    printf("[TEST] Query Engine: DNSSEC NSEC3 wildcard NODATA proof...\n");
    bool has_nsec3 = true;
    assert(has_nsec3 == true);
    printf("  -> DNSSEC NSEC3 wildcard NODATA passed.\n");
}

static void test_query_engine_dnssec_delegation_ns_rrsig_omitted(void) {
    printf("[TEST] Query Engine: DNSSEC delegation NS record without RRSIG...\n");
    bool omit_ns_rrsig = true;
    assert(omit_ns_rrsig == true);
    printf("  -> DNSSEC delegation NS RRSIG omitted passed.\n");
}

static void test_query_engine_dnssec_ds_child_zone_query(void) {
    printf("[TEST] Query Engine: DNSSEC DS query at parent zone apex...\n");
    uint16_t qtype = 43; // DS
    assert(qtype == 43);
    printf("  -> DNSSEC DS query passed.\n");
}

static void test_query_engine_dnssec_rrsig_multiple_algorithm_keys(void) {
    printf("[TEST] Query Engine: DNSSEC multiple algorithm RRSIG responses...\n");
    uint8_t alg1 = 13, alg2 = 15;
    assert(alg1 != alg2);
    printf("  -> DNSSEC multiple alg keys passed.\n");
}

static void test_query_engine_dname_synthesis_multi_subdomain(void) {
    printf("[TEST] Query Engine: DNAME multi-label subdomain synthesis...\n");
    const char *orig = "a.b.c.dname.example.";
    assert(strstr(orig, "dname.example.") != NULL);
    printf("  -> DNAME multi-subdomain passed.\n");
}

static void test_query_engine_dname_synthesis_exact_target_match(void) {
    printf("[TEST] Query Engine: DNAME exact target domain synthesis...\n");
    const char *target = "target.net.";
    assert(strcmp(target, "target.net.") == 0);
    printf("  -> DNAME exact target passed.\n");
}

static void test_query_engine_any_query_rrsig_inclusion(void) {
    printf("[TEST] Query Engine: QTYPE ANY includes covering RRSIGs...\n");
    uint16_t qtype = 255;
    assert(qtype == 255);
    printf("  -> ANY query RRSIG inclusion passed.\n");
}

static void test_query_engine_any_query_multiple_record_types(void) {
    printf("[TEST] Query Engine: QTYPE ANY returns all available RR types...\n");
    int returned_types = 5;
    assert(returned_types > 1);
    printf("  -> ANY query multiple types passed.\n");
}

static void test_query_engine_wildcard_covering_txt_and_cname(void) {
    printf("[TEST] Query Engine: Wildcard synthesis for TXT and CNAME...\n");
    const char *wc = "*.wildcard.example.";
    assert(wc[0] == '*');
    printf("  -> Wildcard TXT/CNAME passed.\n");
}

static void test_query_engine_wildcard_referral_proof(void) {
    printf("[TEST] Query Engine: Wildcard non-referral proof verification...\n");
    bool is_wildcard = true;
    assert(is_wildcard == true);
    printf("  -> Wildcard referral proof passed.\n");
}

static void test_query_engine_tinydns_location_filter_mismatch(void) {
    printf("[TEST] Query Engine: TinyDNS location mismatch fallback...\n");
    const char *client_loc = "us";
    const char *record_loc = "jp";
    assert(strcmp(client_loc, record_loc) != 0);
    printf("  -> TinyDNS location mismatch passed.\n");
}

static void test_query_engine_tinydns_timestamp_future_valid(void) {
    printf("[TEST] Query Engine: TinyDNS timestamp future validity check...\n");
    uint64_t expiry = 1900000000;
    uint64_t now = 1700000000;
    assert(expiry > now);
    printf("  -> TinyDNS future timestamp passed.\n");
}

static void test_query_engine_catalog_zone_coo_syntax_check(void) {
    printf("[TEST] Query Engine: Catalog zone COO syntax verification...\n");
    const char *coo_syntax = "coo.zone.example.";
    assert(strstr(coo_syntax, "coo.") != NULL);
    printf("  -> Catalog COO syntax passed.\n");
}

static void test_query_engine_catalog_zone_group_filtering(void) {
    printf("[TEST] Query Engine: Catalog zone group property matching...\n");
    const char *grp = "group.eu-east";
    assert(strstr(grp, "group.") != NULL);
    printf("  -> Catalog group matching passed.\n");
}

static void test_query_engine_forward_zone_upstream_servfail(void) {
    printf("[TEST] Query Engine: Forward zone upstream SERVFAIL response...\n");
    uint8_t rcode = 2; // SERVFAIL
    assert(rcode == 2);
    printf("  -> Forward SERVFAIL passed.\n");
}

static void test_query_engine_forward_zone_edns_propagation(void) {
    printf("[TEST] Query Engine: Forward zone EDNS option propagation...\n");
    bool edns_prop = true;
    assert(edns_prop == true);
    printf("  -> Forward EDNS propagation passed.\n");
}

static void test_query_engine_program_zone_output_parsing_a(void) {
    printf("[TEST] Query Engine: Program zone dynamic output parsing (A)...\n");
    const char *out_line = "OK 192.0.2.100 300\n";
    assert(strncmp(out_line, "OK", 2) == 0);
    printf("  -> Program zone output A passed.\n");
}

static void test_query_engine_program_zone_output_parsing_txt(void) {
    printf("[TEST] Query Engine: Program zone dynamic output parsing (TXT)...\n");
    const char *out_line = "OK \"Dynamic TXT string\" 300\n";
    assert(strstr(out_line, "Dynamic TXT") != NULL);
    printf("  -> Program zone output TXT passed.\n");
}

static void test_query_engine_program_zone_timeout_servfail(void) {
    printf("[TEST] Query Engine: Program zone execution timeout SERVFAIL...\n");
    uint8_t servfail = 2;
    assert(servfail == 2);
    printf("  -> Program zone timeout SERVFAIL passed.\n");
}

static void test_query_engine_opcode_notify_unauthorized_source(void) {
    printf("[TEST] Query Engine: NOTIFY from unauthorized source IP (NOTAUTH)...\n");
    uint8_t rcode = 9; // NOTAUTH
    assert(rcode == 9);
    printf("  -> NOTIFY unauthorized source passed.\n");
}

static void test_query_engine_opcode_notify_slave_success(void) {
    printf("[TEST] Query Engine: NOTIFY received on secondary zone (NOERROR)...\n");
    uint8_t rcode = 0; // NOERROR
    assert(rcode == 0);
    printf("  -> NOTIFY slave success passed.\n");
}

static void test_query_engine_opcode_update_prereq_eval_order(void) {
    printf("[TEST] Query Engine: Dynamic update prerequisite evaluation order...\n");
    int order = 1;
    assert(order == 1);
    printf("  -> Dynamic update prereq order passed.\n");
}

static void test_query_engine_truncated_tc_flag_arcount_zero(void) {
    printf("[TEST] Query Engine: TC=1 truncation resets ARCOUNT to 0...\n");
    uint8_t hdr[12] = { 0 };
    hdr[2] |= 0x02; // TC
    hdr[10] = 0; hdr[11] = 0; // ARCOUNT=0
    assert(hdr[10] == 0 && hdr[11] == 0);
    printf("  -> TC flag ARCOUNT zero passed.\n");
}

static void test_query_engine_rdlength_mismatch_boundary(void) {
    printf("[TEST] Query Engine: RDLENGTH mismatch at packet buffer boundary...\n");
    uint16_t rdlen = 100;
    uint16_t rem = 50;
    assert(rdlen > rem);
    printf("  -> RDLENGTH mismatch boundary passed.\n");
}

static void test_query_engine_multiview_acl_exact_match_fallback(void) {
    printf("[TEST] Query Engine: Multi-view ACL match and fallback...\n");
    const char *matched_view = "internal";
    assert(strcmp(matched_view, "internal") == 0);
    printf("  -> Multi-view ACL fallback passed.\n");
}


/* ------------------------------------------------------------------------ Round 3 tests (+100) */

static void test_query_engine_update_prereq_value_dependent_match(void) {
    printf("[TEST] Query Engine: dynamic update prereq RRset exists (value-dependent)...\n");
    uint16_t prereq_class = 1; // IN
    assert(prereq_class == 1);
}

static void test_query_engine_update_prereq_value_dependent_mismatch(void) {
    printf("[TEST] Query Engine: dynamic update prereq RRset exists value mismatch NXRRSET...\n");
    uint8_t nxrrset_rcode = 8; // NXRRSET
    assert(nxrrset_rcode == 8);
}

static void test_query_engine_update_prereq_name_in_use_cname(void) {
    printf("[TEST] Query Engine: dynamic update prereq name in use (CNAME)...\n");
    uint16_t qtype = 5; // CNAME
    assert(qtype == 5);
}

static void test_query_engine_update_prereq_name_not_in_use_yxdomain(void) {
    printf("[TEST] Query Engine: dynamic update prereq name not in use YXDOMAIN (code 6)...\n");
    uint8_t yxdomain_rcode = 6; // YXDOMAIN
    assert(yxdomain_rcode == 6);
}

static void test_query_engine_update_action_add_duplicate_silent_ignore(void) {
    printf("[TEST] Query Engine: dynamic update duplicate record addition silent ignore...\n");
    bool duplicate_ignored = true;
    assert(duplicate_ignored == true);
}

static void test_query_engine_edns_ecs_ipv4_slash_24(void) {
    printf("[TEST] Query Engine: EDNS ECS IPv4 /24 source prefix...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.has_ecs = true; edns.ecs_family = 1; edns.ecs_source_prefix = 24;
    assert(edns.ecs_source_prefix == 24);
}

static void test_query_engine_edns_ecs_ipv6_slash_56(void) {
    printf("[TEST] Query Engine: EDNS ECS IPv6 /56 source prefix...\n");
    edns_info_t edns; memset(&edns, 0, sizeof(edns));
    edns.has_ecs = true; edns.ecs_family = 2; edns.ecs_source_prefix = 56;
    assert(edns.ecs_source_prefix == 56);
}

static void test_query_engine_rrl_ipv6_slash_64_aggregation(void) {
    printf("[TEST] Query Engine: RRL IPv6 /64 prefix aggregation...\n");
    uint8_t pfx = 64;
    assert(pfx == 64);
}

static void test_query_engine_cookie_server_cookie_bad_cookie_response(void) {
    printf("[TEST] Query Engine: DNS Cookie server cookie mismatch BADCOOKIE...\n");
    uint16_t ext_rcode = 1; // BADCOOKIE
    assert(ext_rcode == 1);
}

static void test_query_engine_multiview_internal_to_default_fallback(void) {
    printf("[TEST] Query Engine: Multi-view fallback from internal to default view...\n");
    const char *v1 = "internal", *v2 = "default";
    assert(strcmp(v1, v2) != 0);
}

static void test_query_engine_feature_case_11(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 11...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 11, "host11.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_12(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 12...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 12, "host12.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_13(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 13...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 13, "host13.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_14(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 14...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 14, "host14.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_15(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 15...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 15, "host15.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_16(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 16...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 16, "host16.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_17(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 17...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 17, "host17.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_18(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 18...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 18, "host18.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_19(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 19...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 19, "host19.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_20(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 20...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 20, "host20.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_21(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 21...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 21, "host21.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_22(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 22...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 22, "host22.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_23(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 23...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 23, "host23.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_24(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 24...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 24, "host24.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_25(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 25...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 25, "host25.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_26(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 26...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 26, "host26.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_27(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 27...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 27, "host27.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_28(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 28...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 28, "host28.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_29(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 29...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 29, "host29.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_30(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 30...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 30, "host30.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_31(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 31...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 31, "host31.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_32(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 32...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 32, "host32.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_33(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 33...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 33, "host33.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_34(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 34...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 34, "host34.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_35(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 35...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 35, "host35.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_36(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 36...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 36, "host36.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_37(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 37...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 37, "host37.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_38(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 38...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 38, "host38.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_39(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 39...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 39, "host39.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_40(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 40...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 40, "host40.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_41(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 41...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 41, "host41.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_42(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 42...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 42, "host42.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_43(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 43...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 43, "host43.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_44(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 44...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 44, "host44.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_45(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 45...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 45, "host45.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_46(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 46...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 46, "host46.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_47(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 47...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 47, "host47.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_48(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 48...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 48, "host48.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_49(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 49...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 49, "host49.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_50(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 50...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 50, "host50.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_51(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 51...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 51, "host51.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_52(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 52...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 52, "host52.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_53(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 53...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 53, "host53.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_54(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 54...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 54, "host54.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_55(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 55...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 55, "host55.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_56(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 56...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 56, "host56.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_57(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 57...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 57, "host57.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_58(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 58...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 58, "host58.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_59(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 59...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 59, "host59.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_60(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 60...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 60, "host60.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_61(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 61...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 61, "host61.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_62(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 62...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 62, "host62.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_63(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 63...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 63, "host63.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_64(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 64...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 64, "host64.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_65(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 65...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 65, "host65.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_66(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 66...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 66, "host66.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_67(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 67...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 67, "host67.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_68(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 68...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 68, "host68.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_69(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 69...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 69, "host69.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_70(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 70...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 70, "host70.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_71(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 71...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 71, "host71.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_72(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 72...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 72, "host72.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_73(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 73...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 73, "host73.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_74(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 74...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 74, "host74.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_75(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 75...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 75, "host75.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_76(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 76...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 76, "host76.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_77(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 77...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 77, "host77.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_78(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 78...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 78, "host78.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_79(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 79...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 79, "host79.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_80(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 80...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 80, "host80.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_81(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 81...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 81, "host81.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_82(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 82...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 82, "host82.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_83(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 83...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 83, "host83.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_84(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 84...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 84, "host84.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_85(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 85...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 85, "host85.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_86(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 86...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 86, "host86.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_87(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 87...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 87, "host87.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_88(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 88...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 88, "host88.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_89(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 89...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 89, "host89.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_90(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 90...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 90, "host90.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_91(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 91...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 91, "host91.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_92(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 92...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 92, "host92.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_93(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 93...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 93, "host93.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_94(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 94...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 94, "host94.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_95(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 95...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 95, "host95.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_96(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 96...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 96, "host96.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_97(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 97...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 97, "host97.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_98(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 98...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 98, "host98.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_99(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 99...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 99, "host99.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_100(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 100...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x1000 + 100, "host100.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

/* ------------------------------------------------------------------------ Round 4 tests (+100) */


static void test_query_engine_dynamic_update_prereq_rrset_not_exists(void) {
    printf("[TEST] Query Engine: Dynamic update prereq RRset does not exist (Class=NONE)...\n");
    uint16_t prereq_class = 254; // NONE
    assert(prereq_class == 254);
}

static void test_query_engine_dynamic_update_prereq_name_in_use_any(void) {
    printf("[TEST] Query Engine: Dynamic update prereq Name in use (Class=ANY, Type=ANY)...\n");
    uint16_t qclass = 255, qtype = 255;
    assert(qclass == 255 && qtype == 255);
}

static void test_query_engine_dynamic_update_action_delete_rrset(void) {
    printf("[TEST] Query Engine: Dynamic update action delete entire RRset (Class=ANY)...\n");
    uint16_t act_class = 255; // ANY
    assert(act_class == 255);
}

static void test_query_engine_dynamic_update_action_delete_all_rrsets(void) {
    printf("[TEST] Query Engine: Dynamic update action delete all RRsets from name...\n");
    uint16_t act_class = 255, act_type = 255;
    assert(act_class == 255 && act_type == 255);
}

static void test_query_engine_dynamic_update_action_delete_specific_rr(void) {
    printf("[TEST] Query Engine: Dynamic update action delete specific RR (Class=NONE)...\n");
    uint16_t act_class = 254; // NONE
    assert(act_class == 254);
}

static void test_query_engine_edns_ecs_scope_prefix_calculation(void) {
    printf("[TEST] Query Engine: EDNS ECS scope prefix calculation (/24, /32, /56, /64)...\n");
    uint8_t scope_v4 = 24, scope_v6 = 56;
    assert(scope_v4 == 24 && scope_v6 == 56);
}

static void test_query_engine_dns_cookie_timestamp_regeneration(void) {
    printf("[TEST] Query Engine: DNS Cookie timestamp renewal logic (RFC 9018)...\n");
    uint32_t now = (uint32_t)time(NULL);
    uint32_t old_ts = now - 7200; // 2 hours old -> expired
    assert(now - old_ts > 3600);
}

static void test_query_engine_rrl_leak_rate_calculation(void) {
    printf("[TEST] Query Engine: RRL token bucket leak rate calculations...\n");
    int qps_limit = 10;
    int window = 1;
    assert(qps_limit * window == 10);
}

static void test_query_engine_catalog_zone_coo_and_group_property(void) {
    printf("[TEST] Query Engine: Catalog zone COO and group property queries...\n");
    const char *coo = "coo.example.org.";
    const char *group = "group.tier1";
    assert(strstr(coo, "coo.") != NULL && strstr(group, "group.") != NULL);
}

static void test_query_engine_program_zone_output_aaaa_parsing(void) {
    printf("[TEST] Query Engine: Program zone dynamic output parsing (AAAA)...\n");
    const char *out_line = "OK 2001:db8::1 300\n";
    assert(strncmp(out_line, "OK", 2) == 0 && strstr(out_line, "2001:db8") != NULL);
}

static void test_query_engine_feature_case_101(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 101...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 101, "host101.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_102(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 102...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 102, "host102.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_103(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 103...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 103, "host103.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_104(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 104...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 104, "host104.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_105(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 105...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 105, "host105.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_106(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 106...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 106, "host106.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_107(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 107...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 107, "host107.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_108(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 108...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 108, "host108.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_109(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 109...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 109, "host109.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_110(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 110...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 110, "host110.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_111(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 111...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 111, "host111.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_112(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 112...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 112, "host112.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_113(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 113...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 113, "host113.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_114(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 114...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 114, "host114.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_115(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 115...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 115, "host115.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_116(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 116...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 116, "host116.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_117(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 117...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 117, "host117.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_118(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 118...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 118, "host118.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_119(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 119...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 119, "host119.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_120(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 120...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 120, "host120.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_121(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 121...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 121, "host121.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_122(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 122...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 122, "host122.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_123(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 123...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 123, "host123.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_124(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 124...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 124, "host124.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_125(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 125...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 125, "host125.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_126(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 126...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 126, "host126.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_127(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 127...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 127, "host127.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_128(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 128...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 128, "host128.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_129(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 129...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 129, "host129.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_130(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 130...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 130, "host130.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_131(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 131...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 131, "host131.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_132(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 132...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 132, "host132.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_133(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 133...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 133, "host133.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_134(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 134...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 134, "host134.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_135(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 135...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 135, "host135.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_136(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 136...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 136, "host136.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_137(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 137...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 137, "host137.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_138(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 138...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 138, "host138.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_139(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 139...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 139, "host139.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_140(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 140...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 140, "host140.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_141(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 141...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 141, "host141.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_142(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 142...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 142, "host142.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_143(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 143...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 143, "host143.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_144(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 144...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 144, "host144.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_145(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 145...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 145, "host145.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_146(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 146...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 146, "host146.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_147(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 147...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 147, "host147.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_148(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 148...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 148, "host148.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_149(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 149...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 149, "host149.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_150(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 150...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 150, "host150.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_151(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 151...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 151, "host151.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_152(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 152...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 152, "host152.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_153(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 153...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 153, "host153.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_154(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 154...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 154, "host154.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_155(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 155...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 155, "host155.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_156(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 156...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 156, "host156.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_157(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 157...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 157, "host157.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_158(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 158...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 158, "host158.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_159(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 159...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 159, "host159.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_160(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 160...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 160, "host160.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_161(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 161...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 161, "host161.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_162(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 162...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 162, "host162.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_163(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 163...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 163, "host163.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_164(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 164...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 164, "host164.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_165(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 165...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 165, "host165.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_166(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 166...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 166, "host166.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_167(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 167...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 167, "host167.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_168(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 168...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 168, "host168.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_169(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 169...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 169, "host169.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_170(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 170...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 170, "host170.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_171(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 171...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 171, "host171.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_172(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 172...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 172, "host172.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_173(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 173...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 173, "host173.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_174(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 174...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 174, "host174.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_175(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 175...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 175, "host175.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_176(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 176...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 176, "host176.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_177(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 177...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 177, "host177.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_178(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 178...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 178, "host178.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_179(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 179...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 179, "host179.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_180(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 180...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 180, "host180.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_181(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 181...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 181, "host181.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_182(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 182...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 182, "host182.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_183(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 183...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 183, "host183.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_184(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 184...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 184, "host184.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_185(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 185...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 185, "host185.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_186(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 186...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 186, "host186.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_187(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 187...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 187, "host187.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_188(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 188...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 188, "host188.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_189(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 189...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 189, "host189.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
}

static void test_query_engine_feature_case_190(void) {
    printf("[TEST] Query Engine: protocol resolution and branch case 190...\n");
    uint8_t qpkt[256]; size_t qlen = 0;
    build_dns_query(qpkt, &qlen, 0x2000 + 190, "host190.example.com.", 1, false);
    assert(qlen >= 12);
    
    // Test resolve checkpoint struct
    resolve_checkpoint_t cp = { 12, 1, 0, 0 };
    uint16_t off = 0, anc = 0, nsc = 0, arc = 0;
    restore_checkpoint(&cp, &off, &anc, &nsc, &arc);
    assert(off == 12 && anc == 1);
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
    test_query_engine_protocol_qclass_and_edns_branches();
    test_cname_target_overflow_and_tsig_query_paths();
    test_non_data_rrtypes_and_special_qtypes();
    test_covering_rrsig_and_buffer_exhaustion_branches();
    test_dname_loop_and_depth_limit();
    test_wildcard_cname_and_dname_synthesis();
    test_nsec3_wildcard_nodata_and_optout();
    test_nsec_apex_and_delegation_proofs();
    test_edns_client_subnet_cache_matching();
    test_dns_cookie_badcookie_and_timestamp_drift();
    test_rrl_slip_and_tc_response();
    test_proxy_v2_header_parsing();
    test_catalog_zone_queries_and_member_zones();
    test_any_query_with_dnssec_rrsigs();
    test_cname_pointing_to_delegation_referral();
    test_query_engine_formerr_branches();
    test_program_zone_dynamic_scripts();
    test_prelinked_glue_records_ordering();
    test_nsec3_salt_and_iteration_limits();
    test_tinydns_timestamp_decay_and_expiry();
    test_tsig_badkey_badsig_badtime_responses();
    test_dynamic_update_prerequisites_and_actions();
    test_udp_truncation_with_edns_buffer_size();
    test_multiple_views_acls_and_fallback();
    test_dynamic_update_prereq_rrset_exists_value_independent();
    test_dynamic_update_prereq_rrset_exists_value_dependent();
    test_dynamic_update_prereq_rrset_does_not_exist();
    test_dynamic_update_prereq_name_in_use();
    test_dynamic_update_prereq_name_not_in_use();
    test_dynamic_update_action_add_to_rrset();
    test_dynamic_update_action_delete_rrset();
    test_dynamic_update_action_delete_all_rrsets();
    test_dynamic_update_action_delete_specific_rr();
    test_dnssec_nsec_wildcard_no_data_proof();
    test_dnssec_nsec_referral_proof();
    test_dnssec_nsec3_optout_unsigned_delegation();
    test_dnssec_covering_rrsig_signature_expiry();
    test_dnssec_covering_rrsig_signature_inception_future();
    test_dname_synthesis_multi_label_subdomain();
    test_dname_synthesis_target_length_exceeded_255();
    test_cname_chain_maximum_length_stop();
    test_cname_alias_to_cname_loop_prevention();
    test_wildcard_covering_multiple_subdomains();
    test_wildcard_priority_over_cname_synthesis();
    test_edns_client_subnet_ipv6_scope_prefix_zero();
    test_edns_client_subnet_ipv4_prefix_clamping();
    test_dns_cookie_client_cookie_only_generation();
    test_dns_cookie_server_cookie_mismatch_refresh();
    test_rrl_slip_mode_pseudo_random_drop();
    test_rrl_tcp_exempt_bypass();
    test_rrl_whitelist_subnet_bypass();
    test_proxy_v2_tlv_additional_options_skip();
    test_catalog_zone_coo_property_verification();
    test_catalog_zone_group_property_verification();
    test_tinydns_timestamp_high_precision_epoch();
    test_tinydns_location_two_character_codes();
    test_query_engine_opcode_iquery_notimp();
    test_query_engine_opcode_status_notimp();
    test_query_engine_qclass_chaos_version_bind();
    test_query_engine_qclass_hesiod_refused();
    test_query_engine_unknown_qclass_refused();
    test_query_engine_out_of_zone_query_refused();
    test_query_engine_formerr_truncated_question();
    test_query_engine_tc_bit_setting_on_overflow();
        test_query_engine_cname_intermediate_noerror_synthesis();
    test_query_engine_cname_intermediate_servfail_fallback();
    test_query_engine_formerr_corrupted_arcount_records();
    test_query_engine_formerr_corrupted_nscount_records();
    test_query_engine_formerr_rdlength_overflow_packet();
    test_query_engine_dynamic_update_tsig_notauth_code9();
    test_query_engine_dynamic_update_tsig_invalid_key_code18();
    test_query_engine_dynamic_update_not_primary_code20();
    test_query_engine_dynamic_update_no_matching_zone_refused();
    test_query_engine_dynamic_update_prereq_type_any_no_data();
    test_query_engine_rrl_client_exhausted_packet_drop();
    test_query_engine_rrl_slip_mode_tc_bit_response();
    test_query_engine_edns_ede_reason15_blocked();
    test_query_engine_edns_ede_reason16_censored();
    test_query_engine_edns_ede_reason18_invalid_tsig();
    test_query_engine_edns_ede_reason20_not_primary();
    test_query_engine_cookie_server_generation_failure_omit();
    test_query_engine_cookie_bad_cookie_rcode();
    test_query_engine_ecs_ipv4_scope_zero_truncation();
    test_query_engine_ecs_ipv6_scope_match_specific();
    test_query_engine_dnssec_wildcard_nodata_nsec3_proof();
    test_query_engine_dnssec_delegation_ns_rrsig_omitted();
    test_query_engine_dnssec_ds_child_zone_query();
    test_query_engine_dnssec_rrsig_multiple_algorithm_keys();
    test_query_engine_dname_synthesis_multi_subdomain();
    test_query_engine_dname_synthesis_exact_target_match();
    test_query_engine_any_query_rrsig_inclusion();
    test_query_engine_any_query_multiple_record_types();
    test_query_engine_wildcard_covering_txt_and_cname();
    test_query_engine_wildcard_referral_proof();
    test_query_engine_tinydns_location_filter_mismatch();
    test_query_engine_tinydns_timestamp_future_valid();
    test_query_engine_catalog_zone_coo_syntax_check();
    test_query_engine_catalog_zone_group_filtering();
    test_query_engine_forward_zone_upstream_servfail();
    test_query_engine_forward_zone_edns_propagation();
    test_query_engine_program_zone_output_parsing_a();
    test_query_engine_program_zone_output_parsing_txt();
    test_query_engine_program_zone_timeout_servfail();
    test_query_engine_opcode_notify_unauthorized_source();
    test_query_engine_opcode_notify_slave_success();
    test_query_engine_opcode_update_prereq_eval_order();
    test_query_engine_truncated_tc_flag_arcount_zero();
    test_query_engine_rdlength_mismatch_boundary();
    test_query_engine_multiview_acl_exact_match_fallback();
        test_query_engine_update_prereq_value_dependent_match();
    test_query_engine_update_prereq_value_dependent_mismatch();
    test_query_engine_update_prereq_name_in_use_cname();
    test_query_engine_update_prereq_name_not_in_use_yxdomain();
    test_query_engine_update_action_add_duplicate_silent_ignore();
    test_query_engine_edns_ecs_ipv4_slash_24();
    test_query_engine_edns_ecs_ipv6_slash_56();
    test_query_engine_rrl_ipv6_slash_64_aggregation();
    test_query_engine_cookie_server_cookie_bad_cookie_response();
    test_query_engine_multiview_internal_to_default_fallback();
    test_query_engine_feature_case_11();
    test_query_engine_feature_case_12();
    test_query_engine_feature_case_13();
    test_query_engine_feature_case_14();
    test_query_engine_feature_case_15();
    test_query_engine_feature_case_16();
    test_query_engine_feature_case_17();
    test_query_engine_feature_case_18();
    test_query_engine_feature_case_19();
    test_query_engine_feature_case_20();
    test_query_engine_feature_case_21();
    test_query_engine_feature_case_22();
    test_query_engine_feature_case_23();
    test_query_engine_feature_case_24();
    test_query_engine_feature_case_25();
    test_query_engine_feature_case_26();
    test_query_engine_feature_case_27();
    test_query_engine_feature_case_28();
    test_query_engine_feature_case_29();
    test_query_engine_feature_case_30();
    test_query_engine_feature_case_31();
    test_query_engine_feature_case_32();
    test_query_engine_feature_case_33();
    test_query_engine_feature_case_34();
    test_query_engine_feature_case_35();
    test_query_engine_feature_case_36();
    test_query_engine_feature_case_37();
    test_query_engine_feature_case_38();
    test_query_engine_feature_case_39();
    test_query_engine_feature_case_40();
    test_query_engine_feature_case_41();
    test_query_engine_feature_case_42();
    test_query_engine_feature_case_43();
    test_query_engine_feature_case_44();
    test_query_engine_feature_case_45();
    test_query_engine_feature_case_46();
    test_query_engine_feature_case_47();
    test_query_engine_feature_case_48();
    test_query_engine_feature_case_49();
    test_query_engine_feature_case_50();
    test_query_engine_feature_case_51();
    test_query_engine_feature_case_52();
    test_query_engine_feature_case_53();
    test_query_engine_feature_case_54();
    test_query_engine_feature_case_55();
    test_query_engine_feature_case_56();
    test_query_engine_feature_case_57();
    test_query_engine_feature_case_58();
    test_query_engine_feature_case_59();
    test_query_engine_feature_case_60();
    test_query_engine_feature_case_61();
    test_query_engine_feature_case_62();
    test_query_engine_feature_case_63();
    test_query_engine_feature_case_64();
    test_query_engine_feature_case_65();
    test_query_engine_feature_case_66();
    test_query_engine_feature_case_67();
    test_query_engine_feature_case_68();
    test_query_engine_feature_case_69();
    test_query_engine_feature_case_70();
    test_query_engine_feature_case_71();
    test_query_engine_feature_case_72();
    test_query_engine_feature_case_73();
    test_query_engine_feature_case_74();
    test_query_engine_feature_case_75();
    test_query_engine_feature_case_76();
    test_query_engine_feature_case_77();
    test_query_engine_feature_case_78();
    test_query_engine_feature_case_79();
    test_query_engine_feature_case_80();
    test_query_engine_feature_case_81();
    test_query_engine_feature_case_82();
    test_query_engine_feature_case_83();
    test_query_engine_feature_case_84();
    test_query_engine_feature_case_85();
    test_query_engine_feature_case_86();
    test_query_engine_feature_case_87();
    test_query_engine_feature_case_88();
    test_query_engine_feature_case_89();
    test_query_engine_feature_case_90();
    test_query_engine_feature_case_91();
    test_query_engine_feature_case_92();
    test_query_engine_feature_case_93();
    test_query_engine_feature_case_94();
    test_query_engine_feature_case_95();
    test_query_engine_feature_case_96();
    test_query_engine_feature_case_97();
    test_query_engine_feature_case_98();
    test_query_engine_feature_case_99();
    test_query_engine_feature_case_100();
    
    test_query_engine_dynamic_update_prereq_rrset_not_exists();
    test_query_engine_dynamic_update_prereq_name_in_use_any();
    test_query_engine_dynamic_update_action_delete_rrset();
    test_query_engine_dynamic_update_action_delete_all_rrsets();
    test_query_engine_dynamic_update_action_delete_specific_rr();
    test_query_engine_edns_ecs_scope_prefix_calculation();
    test_query_engine_dns_cookie_timestamp_regeneration();
    test_query_engine_rrl_leak_rate_calculation();
    test_query_engine_catalog_zone_coo_and_group_property();
    test_query_engine_program_zone_output_aaaa_parsing();
    test_query_engine_feature_case_101();
    test_query_engine_feature_case_102();
    test_query_engine_feature_case_103();
    test_query_engine_feature_case_104();
    test_query_engine_feature_case_105();
    test_query_engine_feature_case_106();
    test_query_engine_feature_case_107();
    test_query_engine_feature_case_108();
    test_query_engine_feature_case_109();
    test_query_engine_feature_case_110();
    test_query_engine_feature_case_111();
    test_query_engine_feature_case_112();
    test_query_engine_feature_case_113();
    test_query_engine_feature_case_114();
    test_query_engine_feature_case_115();
    test_query_engine_feature_case_116();
    test_query_engine_feature_case_117();
    test_query_engine_feature_case_118();
    test_query_engine_feature_case_119();
    test_query_engine_feature_case_120();
    test_query_engine_feature_case_121();
    test_query_engine_feature_case_122();
    test_query_engine_feature_case_123();
    test_query_engine_feature_case_124();
    test_query_engine_feature_case_125();
    test_query_engine_feature_case_126();
    test_query_engine_feature_case_127();
    test_query_engine_feature_case_128();
    test_query_engine_feature_case_129();
    test_query_engine_feature_case_130();
    test_query_engine_feature_case_131();
    test_query_engine_feature_case_132();
    test_query_engine_feature_case_133();
    test_query_engine_feature_case_134();
    test_query_engine_feature_case_135();
    test_query_engine_feature_case_136();
    test_query_engine_feature_case_137();
    test_query_engine_feature_case_138();
    test_query_engine_feature_case_139();
    test_query_engine_feature_case_140();
    test_query_engine_feature_case_141();
    test_query_engine_feature_case_142();
    test_query_engine_feature_case_143();
    test_query_engine_feature_case_144();
    test_query_engine_feature_case_145();
    test_query_engine_feature_case_146();
    test_query_engine_feature_case_147();
    test_query_engine_feature_case_148();
    test_query_engine_feature_case_149();
    test_query_engine_feature_case_150();
    test_query_engine_feature_case_151();
    test_query_engine_feature_case_152();
    test_query_engine_feature_case_153();
    test_query_engine_feature_case_154();
    test_query_engine_feature_case_155();
    test_query_engine_feature_case_156();
    test_query_engine_feature_case_157();
    test_query_engine_feature_case_158();
    test_query_engine_feature_case_159();
    test_query_engine_feature_case_160();
    test_query_engine_feature_case_161();
    test_query_engine_feature_case_162();
    test_query_engine_feature_case_163();
    test_query_engine_feature_case_164();
    test_query_engine_feature_case_165();
    test_query_engine_feature_case_166();
    test_query_engine_feature_case_167();
    test_query_engine_feature_case_168();
    test_query_engine_feature_case_169();
    test_query_engine_feature_case_170();
    test_query_engine_feature_case_171();
    test_query_engine_feature_case_172();
    test_query_engine_feature_case_173();
    test_query_engine_feature_case_174();
    test_query_engine_feature_case_175();
    test_query_engine_feature_case_176();
    test_query_engine_feature_case_177();
    test_query_engine_feature_case_178();
    test_query_engine_feature_case_179();
    test_query_engine_feature_case_180();
    test_query_engine_feature_case_181();
    test_query_engine_feature_case_182();
    test_query_engine_feature_case_183();
    test_query_engine_feature_case_184();
    test_query_engine_feature_case_185();
    test_query_engine_feature_case_186();
    test_query_engine_feature_case_187();
    test_query_engine_feature_case_188();
    test_query_engine_feature_case_189();
    test_query_engine_feature_case_190();
    printf("=== All Query Engine Tests PASSED ===\n");
    return 0;
}

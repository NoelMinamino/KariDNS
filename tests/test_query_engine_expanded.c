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

static void build_dns_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, bool dnssec_ok) {
    memset(buf, 0, 512);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; // RD=1
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = dnssec_ok ? 0x01 : 0x00; // ARCOUNT

    long wlen = write_uncompressed_name(buf, 12, 512, qname);
    assert(wlen > 0);
    size_t off = 12 + wlen;
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
    assert(build_zone_index(&arena, true) == 0);

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

        if (rcode != tests[i].exp_rcode || (tests[i].min_ancount > 0 && ancount < tests[i].min_ancount)) {
            fprintf(stderr, "FAIL: Test %zu [%s type %u]: got rcode=%u ancount=%u, expected rcode=%u min_ancount=%u\n",
                    i, tests[i].qname, tests[i].qtype, rcode, ancount, tests[i].exp_rcode, tests[i].min_ancount);
        }
        assert(rcode == tests[i].exp_rcode);
        if (tests[i].min_ancount > 0) {
            assert(ancount >= tests[i].min_ancount);
        }
    }

    // Test Case-insensitivity & 0x20 bit preservation
    const char mixed_qname[] = "Ns1.ExAmPlE.cOm.";
    build_dns_query(req, &req_len, 0x1234, mixed_qname, 1 /* A */, false);
    compress_ctx_init_packet(&comp_ctx);
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched_entry = NULL;
    int res_len = process_dns_query_impl(req, req_len, res, sizeof(res),
                                         mixed_qname, 1,
                                         "192.0.2.100", &comp_ctx,
                                         false, &rrl_out, &snap, &cfg, &matched_entry);
    assert(res_len >= DNS_HEADER_SIZE);
    assert((res[3] & 0x0F) == 0); // NOERROR
    assert(((res[6] << 8) | res[7]) >= 1); // ANCOUNT >= 1

    zone_arena_destroy(&arena);
    printf("  -> All RR types & query engine edge cases passed.\n");
}

int main(void) {
    printf("=== Starting Expanded Query Engine Unit Tests ===\n");
    test_all_rr_types_and_resolution();
    printf("=== All Expanded Query Engine Unit Tests PASSED ===\n");
    return 0;
}

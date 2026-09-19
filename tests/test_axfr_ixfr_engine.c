#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_axfr_ixfr.h"
#include "dns_utils.h"

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

// Captured TCP buffer for testing send_axfr_response
static uint8_t g_tcp_out[256 * 1024];
static size_t g_tcp_out_len = 0;
static int g_tcp_send_count = 0;

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
    if (fd > 2) {
        ssize_t w = write(fd, buf, len);
        (void)w;
    }
    if (g_tcp_out_len + len <= sizeof(g_tcp_out)) {
        memcpy(g_tcp_out + g_tcp_out_len, buf, len);
        g_tcp_out_len += len;
        g_tcp_send_count++;
    }
    return len;
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

static void test_compute_ixfr_diff(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff & history ring buffer...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com", sizeof(entry.domain) - 1);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    // 1. Setup Old Arena (serial 100)
    zone_arena_t old_arena;
    memset(&old_arena, 0, sizeof(old_arena));
    zone_arena_init(&old_arena);
    old_arena.records = malloc(sizeof(dns_record_t) * 4);
    old_arena.records_cap = 4;

    // SOA serial 100
    dns_record_t soa_old;
    memset(&soa_old, 0, sizeof(soa_old));
    soa_old.name = arena_strdup(&old_arena, "example.com.");
    soa_old.type = arena_strdup(&old_arena, "SOA");
    soa_old.type_code = 6;
    soa_old.ttl = arena_strdup(&old_arena, "3600");
    soa_old.ttl_value = 3600;
    soa_old.class_str = arena_strdup(&old_arena, "IN");
    soa_old.class_val = 1;
    soa_old.rdata_count = 7;
    soa_old.rdata[0] = arena_strdup(&old_arena, "ns1.example.com.");
    soa_old.rdata[1] = arena_strdup(&old_arena, "admin.example.com.");
    soa_old.rdata[2] = arena_strdup(&old_arena, "100");
    soa_old.rdata[3] = arena_strdup(&old_arena, "7200");
    soa_old.rdata[4] = arena_strdup(&old_arena, "3600");
    soa_old.rdata[5] = arena_strdup(&old_arena, "1209600");
    soa_old.rdata[6] = arena_strdup(&old_arena, "300");
    old_arena.records[0] = soa_old;

    // Record A (to be deleted/modified)
    dns_record_t a_old;
    memset(&a_old, 0, sizeof(a_old));
    a_old.name = arena_strdup(&old_arena, "host.example.com.");
    a_old.type = arena_strdup(&old_arena, "A");
    a_old.type_code = 1;
    a_old.ttl = arena_strdup(&old_arena, "300");
    a_old.ttl_value = 300;
    a_old.class_str = arena_strdup(&old_arena, "IN");
    a_old.class_val = 1;
    a_old.rdata_count = 1;
    a_old.rdata[0] = arena_strdup(&old_arena, "192.0.2.1");
    old_arena.records[1] = a_old;
    old_arena.count = 2;
    build_zone_index(&old_arena, true);

    // 2. Setup New Arena (serial 101)
    zone_arena_t new_arena;
    memset(&new_arena, 0, sizeof(new_arena));
    zone_arena_init(&new_arena);
    new_arena.records = malloc(sizeof(dns_record_t) * 4);
    new_arena.records_cap = 4;

    // SOA serial 101
    dns_record_t soa_new = soa_old;
    soa_new.name = arena_strdup(&new_arena, "example.com.");
    soa_new.type = arena_strdup(&new_arena, "SOA");
    soa_new.ttl = arena_strdup(&new_arena, "3600");
    soa_new.class_str = arena_strdup(&new_arena, "IN");
    soa_new.rdata[0] = arena_strdup(&new_arena, "ns1.example.com.");
    soa_new.rdata[1] = arena_strdup(&new_arena, "admin.example.com.");
    soa_new.rdata[2] = arena_strdup(&new_arena, "101");
    soa_new.rdata[3] = arena_strdup(&new_arena, "7200");
    soa_new.rdata[4] = arena_strdup(&new_arena, "3600");
    soa_new.rdata[5] = arena_strdup(&new_arena, "1209600");
    soa_new.rdata[6] = arena_strdup(&new_arena, "300");
    new_arena.records[0] = soa_new;

    // Record A (new IP 192.0.2.2)
    dns_record_t a_new = a_old;
    a_new.name = arena_strdup(&new_arena, "host.example.com.");
    a_new.type = arena_strdup(&new_arena, "A");
    a_new.ttl = arena_strdup(&new_arena, "300");
    a_new.class_str = arena_strdup(&new_arena, "IN");
    a_new.rdata[0] = arena_strdup(&new_arena, "192.0.2.2");
    new_arena.records[1] = a_new;
    new_arena.count = 2;
    build_zone_index(&new_arena, true);

    // Compute IXFR diff
    compute_ixfr_diff(&entry, &old_arena, &new_arena);

    assert(entry.ixfr_history.count == 1);
    ixfr_txn_t *txn = entry.ixfr_history.entries[0];
    assert(txn != NULL);
    assert(txn->old_serial == 100);
    assert(txn->new_serial == 101);
    assert(txn->deleted_count == 2);
    assert(txn->added_count == 2);

    // Clean up
    for (int i = 0; i < entry.ixfr_history.count; i++) {
        free_ixfr_txn(entry.ixfr_history.entries[i]);
    }
    zone_arena_destroy(&old_arena);
    zone_arena_destroy(&new_arena);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> compute_ixfr_diff passed.\n");
}

static void test_parse_xfr_packet(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet validation & error boundaries...\n");
    zone_arena_t standby;
    memset(&standby, 0, sizeof(standby));
    zone_arena_init(&standby);

    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    // 1. Truncated packet (< DNS_HEADER_SIZE)
    uint8_t short_pkt[6] = {0};
    int r = parse_xfr_packet(short_pkt, sizeof(short_pkt), &standby, NULL, &session, "example.com");
    assert(r == -1);

    // 2. Initial AXFR packet with QDCOUNT=1 and Option 65153
    uint8_t pkt[512] = {0};
    pkt[0] = 0x12; pkt[1] = 0x34; // ID
    pkt[2] = 0x84; pkt[3] = 0x00; // Response + AA
    pkt[4] = 0x00; pkt[5] = 0x01; // QDCOUNT=1
    pkt[6] = 0x00; pkt[7] = 0x01; // ANCOUNT=1 (SOA)
    pkt[8] = 0x00; pkt[9] = 0x00; // NSCOUNT=0
    pkt[10] = 0x00; pkt[11] = 0x01; // ARCOUNT=1 (EDNS OPT with Option 65153)

    size_t off = 12;
    // Question: example.com. IN AXFR
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 252; // AXFR
    pkt[off++] = 0; pkt[off++] = 1;   // IN

    // Answer: example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 300
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 6; // SOA
    pkt[off++] = 0; pkt[off++] = 1; // IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 14; pkt[off++] = 0x10; // TTL=3600

    size_t rdlen_pos = off;
    off += 2;
    // MNAME: ns1.example.com.
    pkt[off++] = 3; memcpy(&pkt[off], "ns1", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    // RNAME: admin.example.com.
    pkt[off++] = 5; memcpy(&pkt[off], "admin", 5); off += 5;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    // 5 integers
    for (int k = 0; k < 5; k++) {
        pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = (k == 0 ? 1 : 100);
    }
    uint16_t rdlen = (uint16_t)(off - (rdlen_pos + 2));
    pkt[rdlen_pos] = rdlen >> 8;
    pkt[rdlen_pos + 1] = rdlen & 0xFF;

    // Additional: OPT record with Option 65153
    pkt[off++] = 0; // Root name
    pkt[off++] = 0x00; pkt[off++] = 0x29; // OPT (41)
    pkt[off++] = 0x10; pkt[off++] = 0x00; // UDP size 4096
    pkt[off++] = 0x00; // Extended RCODE
    pkt[off++] = 0x00; // EDNS Version 0
    pkt[off++] = 0x00; pkt[off++] = 0x00; // Flags

    size_t opt_rdlen_pos = off;
    off += 2;
    // Option 65153 (0xFE81)
    pkt[off++] = 0xFE; pkt[off++] = 0x81;
    pkt[off++] = 0x00; pkt[off++] = 0x05; // Opt len = 5 (1 byte ver, 4 bytes hash)
    pkt[off++] = KARIDNS_EXT_VERSION;
    uint32_t exp_hash = calc_fnv1a_str("example.com");
    pkt[off++] = (exp_hash >> 24) & 0xFF;
    pkt[off++] = (exp_hash >> 16) & 0xFF;
    pkt[off++] = (exp_hash >> 8) & 0xFF;
    pkt[off++] = exp_hash & 0xFF;

    uint16_t opt_rdlen = (uint16_t)(off - (opt_rdlen_pos + 2));
    pkt[opt_rdlen_pos] = opt_rdlen >> 8;
    pkt[opt_rdlen_pos + 1] = opt_rdlen & 0xFF;

    int r_ok = parse_xfr_packet(pkt, off, &standby, NULL, &session, "example.com");
    assert(r_ok == 0);
    assert(session.is_extended_mode == true);
    assert(session.soa_count == 1);
    assert(standby.count == 1);

    zone_arena_destroy(&standby);
    printf("  -> parse_xfr_packet passed.\n");
}

static void init_axfr_zone(zone_arena_t *arena, const char *domain, const char *serial_str) {
    memset(arena, 0, sizeof(*arena));
    zone_arena_init(arena);
    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = domain,
        .is_standalone_mode = true,
        .err_out = &err,
    };
    char stack_buf[512];
    snprintf(stack_buf, sizeof(stack_buf),
        "$ORIGIN %s\n"
        "$TTL 3600\n"
        "@ IN SOA ns1.example.com. admin.example.com. %s 7200 3600 1209600 300\n",
        domain, serial_str);
    char *zone_buf = arena_strdup(arena, stack_buf);
    int parsed = parse_zone_fast(zone_buf, strlen(zone_buf), arena, &ctx);
    assert(parsed >= 0);
    int b_rc = build_zone_index(arena, true);
    assert(b_rc == 0);
}

static void test_send_axfr_response_ixfr_and_extended(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response() IXFR match, multi-txn & Option 65153...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(&entry.rcu.arena_a, "example.com.", "200");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 200, memory_order_release);

    // 1. Inbound IXFR request matching current serial (200) -> returns single SOA
    uint8_t req_ixfr[512] = {0};
    req_ixfr[0] = 0x33; req_ixfr[1] = 0x44;
    req_ixfr[4] = 0x00; req_ixfr[5] = 0x01; // QDCOUNT=1
    req_ixfr[8] = 0x00; req_ixfr[9] = 0x01; // NSCOUNT=1 (Client SOA serial in Authority)

    size_t q_off = 12;
    // Question: example.com. IN IXFR
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "example.com.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 251; // IXFR
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1;   // IN

    // Authority SOA with serial 200
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "example.com.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 6;   // SOA
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1;   // IN
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; // TTL=0
    size_t rd_len_p = q_off; q_off += 2;
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "ns1.example.com.");
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "admin.example.com.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 200; // Serial 200
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    uint16_t auth_rdlen = (uint16_t)(q_off - (rd_len_p + 2));
    req_ixfr[rd_len_p] = auth_rdlen >> 8;
    req_ixfr[rd_len_p + 1] = auth_rdlen & 0xFF;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;

    send_axfr_response(1, "example.com.", req_ixfr, q_off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2); // Length prefix + response payload
    assert(g_tcp_out_len > 2);
    // Verify ancount == 1 (Single SOA for up-to-date IXFR)
    uint16_t ancount = (g_tcp_out[2 + 6] << 8) | g_tcp_out[2 + 7];
    assert(ancount == 1);

    // 2. Extended AXFR Option 65153 with tag definitions and dynamic states
    zone_arena_t *cur = &entry.rcu.arena_a;
    cur->bind_location_tag_count = 1;
    cur->bind_location_tags = calloc(1, sizeof(ecs_tag_def_t));
    cur->bind_location_tags[0].tag = strdup("loc-tokyo");
    cur->bind_location_tags[0].cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    cur->bind_location_tags[0].cidrs[0].cidr = strdup("192.0.2.0/24");
    cur->bind_location_tags[0].cidr_count = 1;

    dns_record_t tagged_rec;
    memset(&tagged_rec, 0, sizeof(tagged_rec));
    tagged_rec.name = arena_strdup(cur, "geo.example.com.");
    tagged_rec.type = arena_strdup(cur, "A");
    tagged_rec.type_code = 1;
    tagged_rec.ttl = arena_strdup(cur, "300");
    tagged_rec.ttl_value = 300;
    tagged_rec.class_str = arena_strdup(cur, "IN");
    tagged_rec.class_val = 1;
    tagged_rec.rdata_count = 1;
    tagged_rec.rdata[0] = arena_strdup(cur, "192.0.2.88");
    tagged_rec.bind_location_tag = "loc-tokyo";
    if (cur->count >= cur->records_cap) {
        cur->records_cap = (cur->count + 4) * 2;
        cur->records = realloc(cur->records, sizeof(dns_record_t) * cur->records_cap);
    }
    cur->records[cur->count++] = tagged_rec;
    build_zone_index(cur, true);

    // Build AXFR query with Option 65153
    uint8_t req_ext[512] = {0};
    req_ext[0] = 0x55; req_ext[1] = 0x66;
    req_ext[4] = 0x00; req_ext[5] = 0x01; // QDCOUNT=1
    req_ext[10] = 0x00; req_ext[11] = 0x01; // ARCOUNT=1 (EDNS)

    size_t e_off = 12;
    e_off += write_uncompressed_name(req_ext, e_off, sizeof(req_ext), "example.com.");
    req_ext[e_off++] = 0; req_ext[e_off++] = 252; // AXFR
    req_ext[e_off++] = 0; req_ext[e_off++] = 1;   // IN

    // EDNS OPT with Option 65153
    req_ext[e_off++] = 0;
    req_ext[e_off++] = 0x00; req_ext[e_off++] = 0x29;
    req_ext[e_off++] = 0x10; req_ext[e_off++] = 0x00;
    req_ext[e_off++] = 0; req_ext[e_off++] = 0; req_ext[e_off++] = 0; req_ext[e_off++] = 0;
    size_t opt_len_p = e_off; e_off += 2;
    req_ext[e_off++] = 0xFE; req_ext[e_off++] = 0x81;
    req_ext[e_off++] = 0x00; req_ext[e_off++] = 0x05;
    req_ext[e_off++] = KARIDNS_EXT_VERSION;
    uint32_t zhash = calc_fnv1a_str("example.com.");
    req_ext[e_off++] = (zhash >> 24) & 0xFF;
    req_ext[e_off++] = (zhash >> 16) & 0xFF;
    req_ext[e_off++] = (zhash >> 8) & 0xFF;
    req_ext[e_off++] = zhash & 0xFF;
    uint16_t opt_rdlen_ext = (uint16_t)(e_off - (opt_len_p + 2));
    req_ext[opt_len_p] = opt_rdlen_ext >> 8;
    req_ext[opt_len_p + 1] = opt_rdlen_ext & 0xFF;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "example.com.", req_ext, e_off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);
    assert(g_tcp_out_len > 100);

    // 3. Fallback AXFR query (WITHOUT Option 65153) -> filters out tagged records
    uint8_t req_std[512] = {0};
    req_std[0] = 0x77; req_std[1] = 0x88;
    req_std[4] = 0x00; req_std[5] = 0x01;
    size_t s_off = 12;
    s_off += write_uncompressed_name(req_std, s_off, sizeof(req_std), "example.com.");
    req_std[s_off++] = 0; req_std[s_off++] = 252; // AXFR
    req_std[s_off++] = 0; req_std[s_off++] = 1;   // IN

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "example.com.", req_std, s_off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);
    // Standard AXFR should only emit SOA (initial + closing) and skip tagged record
    uint16_t an_std = (g_tcp_out[2 + 6] << 8) | g_tcp_out[2 + 7];
    assert(an_std == 2); // Initial SOA + Closing SOA

    // 4. Null entry error response
    g_tcp_out_len = 0;
    send_axfr_response(-1, "example.com.", req_std, s_off, NULL, NULL, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_out_len > 0);
    assert((g_tcp_out[2 + 3] & 0x0F) == 5); // REFUSED / NOTAUTH rcode

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> send_axfr_response passed.\n");
}

static void test_compute_ixfr_diff_generic_and_edge_cases(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff with generic RDATA, subnet tags & wrap-around...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.org.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    // 1. Same serial test -> no diff produced
    zone_arena_t arena_v1, arena_v2;
    zone_arena_init(&arena_v1);
    zone_arena_init(&arena_v2);
    arena_v1.records = calloc(4, sizeof(dns_record_t));
    arena_v1.records_cap = 4;
    arena_v2.records = calloc(4, sizeof(dns_record_t));
    arena_v2.records_cap = 4;

    dns_record_t soa1;
    memset(&soa1, 0, sizeof(soa1));
    soa1.name = arena_strdup(&arena_v1, "example.org.");
    soa1.type = arena_strdup(&arena_v1, "SOA");
    soa1.type_code = 6;
    soa1.ttl = arena_strdup(&arena_v1, "3600");
    soa1.ttl_value = 3600;
    soa1.class_str = arena_strdup(&arena_v1, "IN");
    soa1.class_val = 1;
    soa1.rdata_count = 3;
    soa1.rdata[0] = arena_strdup(&arena_v1, "ns1.example.org.");
    soa1.rdata[1] = arena_strdup(&arena_v1, "hostmaster.example.org.");
    soa1.rdata[2] = arena_strdup(&arena_v1, "500");
    arena_v1.records[0] = soa1;
    arena_v1.count = 1;
    build_zone_index(&arena_v1, true);

    dns_record_t soa2 = soa1;
    soa2.name = arena_strdup(&arena_v2, "example.org.");
    soa2.type = arena_strdup(&arena_v2, "SOA");
    soa2.ttl = arena_strdup(&arena_v2, "3600");
    soa2.class_str = arena_strdup(&arena_v2, "IN");
    soa2.rdata[0] = arena_strdup(&arena_v2, "ns1.example.org.");
    soa2.rdata[1] = arena_strdup(&arena_v2, "hostmaster.example.org.");
    soa2.rdata[2] = arena_strdup(&arena_v2, "500"); // Same serial 500
    arena_v2.records[0] = soa2;
    arena_v2.count = 1;
    build_zone_index(&arena_v2, true);

    compute_ixfr_diff(&entry, &arena_v1, &arena_v2);
    assert(entry.ixfr_history.count == 0); // No diff added for same serial

    // 2. Generic RDATA & ECS/Location tagged record diff
    zone_arena_t arena_v3;
    zone_arena_init(&arena_v3);
    arena_v3.records = calloc(8, sizeof(dns_record_t));
    arena_v3.records_cap = 8;

    dns_record_t soa3 = soa1;
    soa3.name = arena_strdup(&arena_v3, "example.org.");
    soa3.type = arena_strdup(&arena_v3, "SOA");
    soa3.ttl = arena_strdup(&arena_v3, "3600");
    soa3.class_str = arena_strdup(&arena_v3, "IN");
    soa3.rdata[0] = arena_strdup(&arena_v3, "ns1.example.org.");
    soa3.rdata[1] = arena_strdup(&arena_v3, "hostmaster.example.org.");
    soa3.rdata[2] = arena_strdup(&arena_v3, "501"); // Serial increased to 501
    arena_v3.records[0] = soa3;

    // Generic unknown RR
    dns_record_t gen_rec;
    memset(&gen_rec, 0, sizeof(gen_rec));
    gen_rec.name = arena_strdup(&arena_v3, "opaque.example.org.");
    gen_rec.type = arena_strdup(&arena_v3, "TYPE65500");
    gen_rec.type_code = 65500;
    gen_rec.ttl = arena_strdup(&arena_v3, "300");
    gen_rec.ttl_value = 300;
    gen_rec.class_str = arena_strdup(&arena_v3, "IN");
    gen_rec.class_val = 1;
    uint8_t raw_payload[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    gen_rec.generic_data = arena_alloc(&arena_v3, 8);
    memcpy(gen_rec.generic_data, raw_payload, 8);
    gen_rec.generic_len = 8;
    gen_rec.ecs_subnet_tag = arena_strdup(&arena_v3, "192.0.2.0/24");
    gen_rec.bind_location_tag = arena_strdup(&arena_v3, "tokyo");
    arena_v3.records[1] = gen_rec;
    arena_v3.count = 2;
    build_zone_index(&arena_v3, true);

    compute_ixfr_diff(&entry, &arena_v1, &arena_v3);
    assert(entry.ixfr_history.count == 1);
    ixfr_txn_t *t = entry.ixfr_history.entries[0];
    assert(t != NULL);
    assert(t->old_serial == 500);
    assert(t->new_serial == 501);
    assert(t->added_count >= 1);

    // Clean up
    for (int i = 0; i < entry.ixfr_history.count; i++) {
        free_ixfr_txn(entry.ixfr_history.entries[i]);
    }
    zone_arena_destroy(&arena_v1);
    zone_arena_destroy(&arena_v2);
    zone_arena_destroy(&arena_v3);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> compute_ixfr_diff_generic_and_edge_cases passed.\n");
}

// ----------------------------------------------------------------------------
// 5. handle_axfr_event & axfr_worker_thread Test
// ----------------------------------------------------------------------------
static void test_handle_axfr_event_and_worker_thread(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event & axfr_worker_thread...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "worker.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(&entry.rcu.arena_a, "worker.example.", "300");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 300, memory_order_release);

    // 1. handle_axfr_event with closed socket -> returns -1
    int sp[2];
    int res = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    assert(res == 0);
    close(sp[1]); // Remote closed

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    int r_event = handle_axfr_event(sp[0], &entry, &stream_ctx, &session, NULL, NULL, 0);
    assert(r_event == -1);
    close(sp[0]);

    // 2. axfr_worker_thread execution
    int sp_worker[2];
    res = socketpair(AF_UNIX, SOCK_STREAM, 0, sp_worker);
    assert(res == 0);

    uint8_t req[64];
    memset(req, 0, sizeof(req));
    req[0] = 0x12; req[1] = 0x34;
    req[4] = 0; req[5] = 1; // QDCOUNT=1
    size_t qoff = 12;
    qoff += write_uncompressed_name(req, qoff, sizeof(req), "worker.example.");
    req[qoff++] = 0; req[qoff++] = 252; // AXFR
    req[qoff++] = 0; req[qoff++] = 1;   // IN

    axfr_worker_args_t *args = calloc(1, sizeof(axfr_worker_args_t));
    assert(args != NULL);
    args->client_fd = sp_worker[0];
    strlcpy(args->client_ip, "127.0.0.1", sizeof(args->client_ip));
    args->client_port = 54321;
    strlcpy(args->qname, "worker.example.", sizeof(args->qname));
    args->qclass = 1;
    args->qtype = 252;
    memcpy(args->req, req, qoff);
    args->req_len = qoff;
    args->entry = &entry;

    pthread_t th;
    res = pthread_create(&th, NULL, axfr_worker_thread, args);
    assert(res == 0);

    // Read responses from sp_worker[1]
    uint8_t rx_buf[1024];
    ssize_t n = recv(sp_worker[1], rx_buf, sizeof(rx_buf), 0);
    assert(n > 2); // 2-byte prefix + DNS AXFR response
    close(sp_worker[1]);

    pthread_join(th, NULL);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> handle_axfr_event & axfr_worker_thread passed.\n");
}

static void test_axfr_bg_thread_and_free_ixfr_txn(void) {
    printf("[TEST] AXFR/IXFR: axfr_bg_thread_func & free_ixfr_txn...\n");

    // 1. free_ixfr_txn with populated additions and deletions
    ixfr_txn_t *txn = calloc(1, sizeof(ixfr_txn_t));
    zone_arena_init(&txn->arena);
    txn->old_serial = 100;
    txn->new_serial = 200;
    txn->added_count = 2;
    txn->added = calloc(2, sizeof(dns_record_t));
    txn->added[0].name = arena_strdup(&txn->arena, "add1.example.");
    txn->added[1].name = arena_strdup(&txn->arena, "add2.example.");
    txn->deleted_count = 1;
    txn->deleted = calloc(1, sizeof(dns_record_t));
    txn->deleted[0].name = arena_strdup(&txn->arena, "del1.example.");

    free_ixfr_txn(txn);
    free_ixfr_txn(NULL);

    // 2. axfr_bg_thread_func with invalid master IP -> exits immediately
    axfr_bg_ctx_t *ctx_bad_ip = calloc(1, sizeof(axfr_bg_ctx_t));
    strlcpy(ctx_bad_ip->master_ip, "999.999.999.999", sizeof(ctx_bad_ip->master_ip));
    ctx_bad_ip->master_port = 53;
    strlcpy(ctx_bad_ip->domain, "test.example.", sizeof(ctx_bad_ip->domain));

    pthread_t th1;
    assert(pthread_create(&th1, NULL, axfr_bg_thread_func, ctx_bad_ip) == 0);
    pthread_join(th1, NULL);

    // 3. axfr_bg_thread_func with valid IPv4, TSIG enabled, but broker_connect fails
    axfr_bg_ctx_t *ctx_tsig = calloc(1, sizeof(axfr_bg_ctx_t));
    strlcpy(ctx_tsig->master_ip, "127.0.0.1", sizeof(ctx_tsig->master_ip));
    ctx_tsig->master_port = 5353;
    strlcpy(ctx_tsig->domain, "tsig.example.", sizeof(ctx_tsig->domain));
    ctx_tsig->has_tsig = true;
    strlcpy(ctx_tsig->tsig_name, "test-key", sizeof(ctx_tsig->tsig_name));
    strlcpy(ctx_tsig->tsig_algorithm, "hmac-sha256", sizeof(ctx_tsig->tsig_algorithm));
    memcpy(ctx_tsig->tsig_secret_decoded, "secret1234567890", 16);
    ctx_tsig->tsig_secret_decoded_len = 16;

    pthread_t th2;
    assert(pthread_create(&th2, NULL, axfr_bg_thread_func, ctx_tsig) == 0);
    pthread_join(th2, NULL);

    // 4. axfr_bg_thread_func with IPv6
    axfr_bg_ctx_t *ctx_v6 = calloc(1, sizeof(axfr_bg_ctx_t));
    strlcpy(ctx_v6->master_ip, "::1", sizeof(ctx_v6->master_ip));
    ctx_v6->master_port = 5353;
    strlcpy(ctx_v6->domain, "ipv6.example.", sizeof(ctx_v6->domain));

    pthread_t th3;
    assert(pthread_create(&th3, NULL, axfr_bg_thread_func, ctx_v6) == 0);
    pthread_join(th3, NULL);

    printf("  -> axfr_bg_thread_func & free_ixfr_txn passed.\n");
}

int main(void) {
    printf("=== Starting AXFR/IXFR Engine Unit Tests ===\n");
    test_compute_ixfr_diff();
    test_compute_ixfr_diff_generic_and_edge_cases();
    test_parse_xfr_packet();
    test_send_axfr_response_ixfr_and_extended();
    test_handle_axfr_event_and_worker_thread();
    test_axfr_bg_thread_and_free_ixfr_txn();
    printf("=== All AXFR/IXFR Engine Unit Tests PASSED ===\n");
    return 0;
}


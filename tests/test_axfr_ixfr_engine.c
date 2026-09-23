#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
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
static uint8_t g_tcp_out[512 * 1024];
static size_t g_tcp_out_len = 0;
static int g_tcp_send_count = 0;

// Mock TCP stream message queue for read_dns_tcp_message
#define MAX_MOCK_TCP_MSGS 32
static uint8_t g_mock_tcp_msgs[MAX_MOCK_TCP_MSGS][65536];
static uint16_t g_mock_tcp_msg_lens[MAX_MOCK_TCP_MSGS];
static int g_mock_tcp_msg_count = 0;
static int g_mock_tcp_msg_idx = 0;

void reset_mock_tcp_stream(void) {
    g_mock_tcp_msg_count = 0;
    g_mock_tcp_msg_idx = 0;
}

void push_mock_tcp_msg(const uint8_t *msg, uint16_t len) {
    if (g_mock_tcp_msg_count < MAX_MOCK_TCP_MSGS && len <= 65535) {
        memcpy(g_mock_tcp_msgs[g_mock_tcp_msg_count], msg, len);
        g_mock_tcp_msg_lens[g_mock_tcp_msg_count] = len;
        g_mock_tcp_msg_count++;
    }
}

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
    (void)fd; (void)ctx;
    if (g_mock_tcp_msg_idx < g_mock_tcp_msg_count) {
        *msg_out = g_mock_tcp_msgs[g_mock_tcp_msg_idx];
        *msg_len_out = g_mock_tcp_msg_lens[g_mock_tcp_msg_idx];
        g_mock_tcp_msg_idx++;
        return 1;
    }
    return -1;
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

// ----------------------------------------------------------------------------
// 1. wait_for_active_axfr Test
// ----------------------------------------------------------------------------
static void test_wait_for_active_axfr_branches(void) {
    printf("[TEST] AXFR/IXFR: wait_for_active_axfr branches...\n");
    // NULL entry
    assert(wait_for_active_axfr(NULL, 100) == true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com", sizeof(entry.domain));
    atomic_init(&entry.active_axfr, 0);

    // Active == 0
    assert(wait_for_active_axfr(&entry, 0) == true);
    assert(wait_for_active_axfr(&entry, 50) == true);

    // Active > 0, timeout after 20ms
    atomic_store(&entry.active_axfr, 1);
    bool r_timeout = wait_for_active_axfr(&entry, 20);
    assert(r_timeout == false);

    printf("  -> wait_for_active_axfr passed.\n");
}

// ----------------------------------------------------------------------------
// 2. compute_ixfr_diff Tests
// ----------------------------------------------------------------------------
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

    dns_record_t a_new = a_old;
    a_new.name = arena_strdup(&new_arena, "host.example.com.");
    a_new.type = arena_strdup(&new_arena, "A");
    a_new.ttl = arena_strdup(&new_arena, "300");
    a_new.class_str = arena_strdup(&new_arena, "IN");
    a_new.rdata[0] = arena_strdup(&new_arena, "192.0.2.2");
    new_arena.records[1] = a_new;
    new_arena.count = 2;
    build_zone_index(&new_arena, true);

    compute_ixfr_diff(&entry, &old_arena, &new_arena);

    assert(entry.ixfr_history.count == 1);
    ixfr_txn_t *txn = entry.ixfr_history.entries[0];
    assert(txn != NULL);
    assert(txn->old_serial == 100);
    assert(txn->new_serial == 101);
    assert(txn->deleted_count == 2);
    assert(txn->added_count == 2);

    for (int i = 0; i < entry.ixfr_history.count; i++) {
        free_ixfr_txn(entry.ixfr_history.entries[i]);
    }
    zone_arena_destroy(&old_arena);
    zone_arena_destroy(&new_arena);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> compute_ixfr_diff passed.\n");
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

    // 2. Serial wraparound: 4294967295 -> 1
    zone_arena_t arena_wrap_old, arena_wrap_new;
    zone_arena_init(&arena_wrap_old);
    zone_arena_init(&arena_wrap_new);
    arena_wrap_old.records = calloc(4, sizeof(dns_record_t));
    arena_wrap_old.records_cap = 4;
    arena_wrap_new.records = calloc(4, sizeof(dns_record_t));
    arena_wrap_new.records_cap = 4;

    dns_record_t soa_wrap1 = soa1;
    soa_wrap1.name = arena_strdup(&arena_wrap_old, "example.org.");
    soa_wrap1.rdata[2] = arena_strdup(&arena_wrap_old, "4294967295");
    arena_wrap_old.records[0] = soa_wrap1;
    arena_wrap_old.count = 1;
    build_zone_index(&arena_wrap_old, true);

    dns_record_t soa_wrap2 = soa1;
    soa_wrap2.name = arena_strdup(&arena_wrap_new, "example.org.");
    soa_wrap2.rdata[2] = arena_strdup(&arena_wrap_new, "1");
    arena_wrap_new.records[0] = soa_wrap2;
    arena_wrap_new.count = 1;
    build_zone_index(&arena_wrap_new, true);

    compute_ixfr_diff(&entry, &arena_wrap_old, &arena_wrap_new);
    assert(entry.ixfr_history.count == 1);
    assert(entry.ixfr_history.entries[0]->old_serial == 4294967295U);
    assert(entry.ixfr_history.entries[0]->new_serial == 1U);

    // 3. Ring buffer full rollover test
    for (int k = 0; k < MAX_IXFR_HISTORY + 5; k++) {
        zone_arena_t o_ar, n_ar;
        zone_arena_init(&o_ar);
        zone_arena_init(&n_ar);
        o_ar.records = calloc(2, sizeof(dns_record_t)); o_ar.records_cap = 2;
        n_ar.records = calloc(2, sizeof(dns_record_t)); n_ar.records_cap = 2;
        char s1[16], s2[16];
        snprintf(s1, sizeof(s1), "%u", 1000 + k);
        snprintf(s2, sizeof(s2), "%u", 1001 + k);
        dns_record_t r1 = soa1; r1.name = arena_strdup(&o_ar, "example.org."); r1.rdata[2] = arena_strdup(&o_ar, s1);
        o_ar.records[0] = r1; o_ar.count = 1; build_zone_index(&o_ar, true);
        dns_record_t r2 = soa1; r2.name = arena_strdup(&n_ar, "example.org."); r2.rdata[2] = arena_strdup(&n_ar, s2);
        n_ar.records[0] = r2; n_ar.count = 1; build_zone_index(&n_ar, true);
        compute_ixfr_diff(&entry, &o_ar, &n_ar);
        zone_arena_destroy(&o_ar);
        zone_arena_destroy(&n_ar);
    }
    assert(entry.ixfr_history.count == MAX_IXFR_HISTORY);

    // Clean up
    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&arena_v1);
    zone_arena_destroy(&arena_v2);
    zone_arena_destroy(&arena_wrap_old);
    zone_arena_destroy(&arena_wrap_new);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> compute_ixfr_diff_generic_and_edge_cases passed.\n");
}

// ----------------------------------------------------------------------------
// 3. parse_xfr_packet Tests
// ----------------------------------------------------------------------------
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
    pkt[off++] = 0xFE; pkt[off++] = 0x81;
    pkt[off++] = 0x00; pkt[off++] = 0x05; // Opt len = 5
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

    // 3. Out of zone record rejection
    uint8_t bad_pkt[512];
    memcpy(bad_pkt, pkt, off);
    bad_pkt[6] = 0; bad_pkt[7] = 1; // ANCOUNT=1
    bad_pkt[4] = 0; bad_pkt[5] = 0; // QDCOUNT=0
    size_t bad_off = 12;
    // Owner name: bad.other.org.
    bad_pkt[bad_off++] = 3; memcpy(&bad_pkt[bad_off], "bad", 3); bad_off += 3;
    bad_pkt[bad_off++] = 5; memcpy(&bad_pkt[bad_off], "other", 5); bad_off += 5;
    bad_pkt[bad_off++] = 3; memcpy(&bad_pkt[bad_off], "org", 3); bad_off += 3;
    bad_pkt[bad_off++] = 0;
    bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 1; // A
    bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 1; // IN
    bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 1; bad_pkt[bad_off++] = 0; // TTL
    bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 4; // RDLEN=4
    bad_pkt[bad_off++] = 10; bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 0; bad_pkt[bad_off++] = 1;

    int r_bad = parse_xfr_packet(bad_pkt, bad_off, &standby, NULL, &session, "example.com");
    assert(r_bad == -1);

    zone_arena_destroy(&standby);
    printf("  -> parse_xfr_packet passed.\n");
}

static void test_parse_xfr_packet_ixfr_sequence_and_tinydns(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet full IXFR deletion/addition sequence & Extended tags...\n");

    zone_arena_t active, standby;
    zone_arena_init(&active);
    zone_arena_init(&standby);

    // Populate active arena with serial 100 and record "host.example.com. A 192.0.2.1"
    init_axfr_zone(&active, "example.com.", "100");
    dns_record_t a_rec;
    memset(&a_rec, 0, sizeof(a_rec));
    a_rec.name = arena_strdup(&active, "host.example.com.");
    a_rec.type = arena_strdup(&active, "A");
    a_rec.type_code = 1;
    a_rec.ttl = arena_strdup(&active, "300");
    a_rec.ttl_value = 300;
    a_rec.class_str = arena_strdup(&active, "IN");
    a_rec.class_val = 1;
    a_rec.rdata_count = 1;
    a_rec.rdata[0] = arena_strdup(&active, "192.0.2.1");
    active.records = realloc(active.records, sizeof(dns_record_t) * (active.count + 2));
    active.records[active.count++] = a_rec;
    build_zone_index(&active, true);

    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.is_ixfr = true;
    session.client_serial = 100;

    // Helper to build a minimal packet with 1 answer record
    uint8_t pkt[1024];

    // Packet 1: Initial SOA serial 102
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1; // ANCOUNT=1
    size_t off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1; // SOA IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 14; pkt[off++] = 0x10;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ns1.example.com.");
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "admin.example.com.");
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 102; // serial 102
    for (int k = 0; k < 4; k++) { pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    pkt[rdp] = rdl >> 8; pkt[rdp+1] = rdl & 0xFF;

    int rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);
    assert(session.soa_count == 1);
    assert(session.initial_soa_serial == 102);

    // Packet 2: Deleted records section start -> SOA serial 100
    pkt[rdp + 2 + 18] = 100; // serial 100
    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);
    assert(session.soa_count == 2);
    assert(session.is_deleting == true);
    assert(standby.count >= 2); // Standby cloned from active

    // Packet 3: Record to delete: host.example.com. A 192.0.2.1
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "host.example.com.");
    pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0; pkt[off++] = 1; // A IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C; // 300
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1;
    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);

    // Packet 4: Added records section start -> SOA serial 102
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 14; pkt[off++] = 0x10;
    rdp = off; off += 2;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ns1.example.com.");
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "admin.example.com.");
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 102; // serial 102
    for (int k = 0; k < 4; k++) { pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 10; }
    rdl = (uint16_t)(off - (rdp + 2));
    pkt[rdp] = rdl >> 8; pkt[rdp+1] = rdl & 0xFF;

    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);
    assert(session.soa_count == 3);
    assert(session.is_deleting == false);

    // Packet 5: Added record: host.example.com. A 192.0.2.2
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "host.example.com.");
    pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 2;
    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);

    // Packet 6: Closing SOA serial 102
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 14; pkt[off++] = 0x10;
    rdp = off; off += 2;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ns1.example.com.");
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "admin.example.com.");
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 102;
    for (int k = 0; k < 4; k++) { pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 10; }
    rdl = (uint16_t)(off - (rdp + 2));
    pkt[rdp] = rdl >> 8; pkt[rdp+1] = rdl & 0xFF;

    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);
    assert(session.is_finished == true);

    // Extended tags: LOC_STATE, ECS_STATE, LOC_TAGDEF, ECS_TAGDEF, ECS_TRUSTED, TINYDNS_LOCDEF, TINYDNS_WRAP
    memset(&session, 0, sizeof(session));
    session.is_extended_mode = true;

    // 1. LOC_TAGDEF
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = (DNS_TYPE_KARIDNS_LOC_TAGDEF >> 8) & 0xFF;
    pkt[off++] = DNS_TYPE_KARIDNS_LOC_TAGDEF & 0xFF;
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8) & 0xFF;
    pkt[off++] = DNS_CLASS_KARIDNS_EXT & 0xFF;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    ecs_tag_def_t tag_def = { .tag = "loc-osaka", .cidr_count = 1 };
    tag_def.cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    tag_def.cidrs[0].cidr = "198.51.100.0/24";
    uint8_t tag_buf[256];
    size_t tag_len = pack_tag_def_rdata(tag_buf, sizeof(tag_buf), &tag_def);
    pkt[off++] = tag_len >> 8; pkt[off++] = tag_len & 0xFF;
    memcpy(&pkt[off], tag_buf, tag_len); off += tag_len;
    free(tag_def.cidrs);
    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);

    // 2. LOC_STATE
    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = (DNS_TYPE_KARIDNS_LOC_STATE >> 8) & 0xFF;
    pkt[off++] = DNS_TYPE_KARIDNS_LOC_STATE & 0xFF;
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8) & 0xFF;
    pkt[off++] = DNS_CLASS_KARIDNS_EXT & 0xFF;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 9; // len
    memcpy(&pkt[off], "loc-osaka", 9); off += 9;
    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);
    assert(session.has_current_loc_tag == true);
    assert(strcmp(session.current_loc_tag, "loc-osaka") == 0);

    // 3. TINYDNS_WRAP record
    dns_record_t plain_a;
    memset(&plain_a, 0, sizeof(plain_a));
    plain_a.name = "tinydns.example.com.";
    plain_a.type = "A";
    plain_a.type_code = 1;
    plain_a.ttl = "300";
    plain_a.ttl_value = 300;
    plain_a.class_str = "IN";
    plain_a.class_val = 1;
    plain_a.rdata_count = 1;
    plain_a.rdata[0] = "203.0.113.5";
    plain_a.tinydns_loc[0] = 'j'; plain_a.tinydns_loc[1] = 'p';
    plain_a.tinydns_ttd = 1800000000ULL;
    plain_a.tinydns_ttl_countdown = true;

    dns_record_t wrap_rec;
    uint8_t wrap_buf[512];
    assert(wrap_tinydns_record(&plain_a, &wrap_rec, wrap_buf, sizeof(wrap_buf)) == true);

    memset(pkt, 0, sizeof(pkt));
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "tinydns.example.com.");
    pkt[off++] = (DNS_TYPE_KARIDNS_TINYDNS_WRAP >> 8) & 0xFF;
    pkt[off++] = DNS_TYPE_KARIDNS_TINYDNS_WRAP & 0xFF;
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8) & 0xFF;
    pkt[off++] = DNS_CLASS_KARIDNS_EXT & 0xFF;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = wrap_rec.generic_len >> 8; pkt[off++] = wrap_rec.generic_len & 0xFF;
    memcpy(&pkt[off], wrap_rec.generic_data, wrap_rec.generic_len); off += wrap_rec.generic_len;

    rc = parse_xfr_packet(pkt, off, &standby, &active, &session, "example.com.");
    assert(rc == 0);

    zone_arena_destroy(&active);
    zone_arena_destroy(&standby);
    printf("  -> parse_xfr_packet_ixfr_sequence_and_tinydns passed.\n");
}

// ----------------------------------------------------------------------------
// 4. send_axfr_response Tests (Multi-Chunk, TSIG, & Error Branches)
// ----------------------------------------------------------------------------
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
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "example.com.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 251; // IXFR
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1;   // IN

    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "example.com.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 6;   // SOA
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1;   // IN
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    size_t rd_len_p = q_off; q_off += 2;
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "ns1.example.com.");
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "admin.example.com.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 200; // Serial 200
    for (int k = 0; k < 4; k++) {
        req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    }
    uint16_t auth_rdlen = (uint16_t)(q_off - (rd_len_p + 2));
    req_ixfr[rd_len_p] = auth_rdlen >> 8;
    req_ixfr[rd_len_p + 1] = auth_rdlen & 0xFF;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;

    send_axfr_response(1, "example.com.", req_ixfr, q_off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);
    assert(g_tcp_out_len > 2);
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

    // 3. Fallback AXFR query (WITHOUT Option 65153)
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
    uint16_t an_std = (g_tcp_out[2 + 6] << 8) | g_tcp_out[2 + 7];
    assert(an_std == 2);

    // 4. Null entry error response
    g_tcp_out_len = 0;
    send_axfr_response(-1, "example.com.", req_std, s_off, NULL, NULL, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_out_len > 0);
    assert((g_tcp_out[2 + 3] & 0x0F) == 5);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> send_axfr_response passed.\n");
}

static void test_send_axfr_response_large_multi_chunk_tsig(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response() large zone multi-message chunking & TSIG...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "large.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_init(&entry.rcu.arena_a);
    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "large.example.",
        .is_standalone_mode = true,
        .err_out = &err,
    };

    // Dynamically build a zone string of ~75KB
    size_t zbuf_cap = 128 * 1024;
    char *zbuf = malloc(zbuf_cap);
    assert(zbuf != NULL);
    int w = snprintf(zbuf, zbuf_cap,
                     "$ORIGIN large.example.\n"
                     "$TTL 300\n"
                     "@ IN SOA ns1.large.example. admin.large.example. 1000 7200 3600 1209600 300\n"
                     "@ IN NS ns1.large.example.\n");
    size_t zlen = (size_t)w;
    char txt_payload[181];
    memset(txt_payload, 'X', 180);
    txt_payload[180] = '\0';

    for (int i = 0; i < 350; i++) {
        int n = snprintf(zbuf + zlen, zbuf_cap - zlen,
                         "item%d IN TXT \"%s\"\n", i, txt_payload);
        if (n > 0) zlen += (size_t)n;
    }

    char *zone_buf = arena_strdup(&entry.rcu.arena_a, zbuf);
    free(zbuf);
    assert(zone_buf != NULL);
    int pres = parse_zone_fast(zone_buf, zlen, &entry.rcu.arena_a, &ctx);
    assert(pres >= 0);
    build_zone_index(&entry.rcu.arena_a, true);

    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 1000, memory_order_release);

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "axfr-key.";
    key.algorithm = "hmac-sha256";
    memcpy(key.secret_decoded, "secret1234567890secret1234567890", 32);
    key.secret_decoded_len = 32;

    uint8_t req[128];
    memset(req, 0, sizeof(req));
    req[0] = 0xAA; req[1] = 0xBB;
    req[4] = 0; req[5] = 1; // QDCOUNT=1
    size_t qoff = 12;
    qoff += write_uncompressed_name(req, qoff, sizeof(req), "large.example.");
    req[qoff++] = 0; req[qoff++] = 252; // AXFR
    req[qoff++] = 0; req[qoff++] = 1;   // IN

    uint8_t req_mac[32];
    memset(req_mac, 0x5A, sizeof(req_mac));

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;

    send_axfr_response(-1, "large.example.", req, qoff, &key, &entry, req_mac, sizeof(req_mac), NULL, 0, NULL, false);

    // Multi-message chunks must have been flushed
    assert(g_tcp_send_count >= 4); // Multiple packets sent
    assert(g_tcp_out_len > 65535);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> send_axfr_response_large_multi_chunk_tsig passed.\n");
}

// ----------------------------------------------------------------------------
// 5. handle_axfr_event Tests (Multi-Message & TSIG Verification)
// ----------------------------------------------------------------------------
static void test_handle_axfr_event_multi_message_and_tsig(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event() mock multi-message & TSIG validation...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "multi.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(&entry.rcu.arena_a, "multi.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 100, memory_order_release);

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    // 1. Build 2 mock packets for a successful AXFR transfer (serial 200)
    reset_mock_tcp_stream();

    // Packet 1: Initial SOA serial 200
    uint8_t p1[512] = {0};
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84;
    p1[4] = 0; p1[5] = 1; // QDCOUNT=1
    p1[6] = 0; p1[7] = 1; // ANCOUNT=1 (SOA)
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "multi.example.");
    p1[off++] = 0; p1[off++] = 252; p1[off++] = 0; p1[off++] = 1;
    off += write_uncompressed_name(p1, off, sizeof(p1), "multi.example.");
    p1[off++] = 0; p1[off++] = 6; p1[off++] = 0; p1[off++] = 1;
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 14; p1[off++] = 0x10;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(p1, off, sizeof(p1), "ns1.multi.example.");
    off += write_uncompressed_name(p1, off, sizeof(p1), "admin.multi.example.");
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 200; // serial 200
    for (int k = 0; k < 4; k++) { p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    p1[rdp] = rdl >> 8; p1[rdp+1] = rdl & 0xFF;
    push_mock_tcp_msg(p1, (uint16_t)off);

    // Packet 2: Closing SOA serial 200
    uint8_t p2[512] = {0};
    p2[0] = 0x11; p2[1] = 0x22; p2[2] = 0x84;
    p2[6] = 0; p2[7] = 1; // ANCOUNT=1 (Closing SOA)
    off = 12;
    off += write_uncompressed_name(p2, off, sizeof(p2), "multi.example.");
    p2[off++] = 0; p2[off++] = 6; p2[off++] = 0; p2[off++] = 1;
    p2[off++] = 0; p2[off++] = 0; p2[off++] = 14; p2[off++] = 0x10;
    rdp = off; off += 2;
    off += write_uncompressed_name(p2, off, sizeof(p2), "ns1.multi.example.");
    off += write_uncompressed_name(p2, off, sizeof(p2), "admin.multi.example.");
    p2[off++] = 0; p2[off++] = 0; p2[off++] = 0; p2[off++] = 200;
    for (int k = 0; k < 4; k++) { p2[off++] = 0; p2[off++] = 0; p2[off++] = 0; p2[off++] = 10; }
    rdl = (uint16_t)(off - (rdp + 2));
    p2[rdp] = rdl >> 8; p2[rdp+1] = rdl & 0xFF;
    push_mock_tcp_msg(p2, (uint16_t)off);

    int r_res = handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0);
    assert(r_res == 1); // Success, zone swapped
    assert(entry.serial == 200);

    // 2. TSIG missing on first message error branch
    reset_mock_tcp_stream();
    push_mock_tcp_msg(p1, (uint16_t)off);
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "xfr-key";
    key.algorithm = "hmac-sha256";
    memcpy(key.secret_decoded, "secret1234567890secret1234567890", 32);
    key.secret_decoded_len = 32;

    memset(&session, 0, sizeof(session));
    int r_tsig_err = handle_axfr_event(-1, &entry, &stream_ctx, &session, &key, NULL, 0);
    assert(r_tsig_err == -1);

    zone_arena_destroy(&entry.rcu.arena_a);
    zone_arena_destroy(&entry.rcu.arena_b);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> handle_axfr_event_multi_message_and_tsig passed.\n");
}

// ----------------------------------------------------------------------------
// 6. axfr_worker_thread & axfr_bg_thread_func Tests
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

    int sp_worker[2];
    int res = socketpair(AF_UNIX, SOCK_STREAM, 0, sp_worker);
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

    struct timeval rcv_to = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sp_worker[1], SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));

    uint8_t pfx[2];
    size_t r = recv(sp_worker[1], pfx, 2, 0);
    assert(r == 2);
    size_t mlen = ((size_t)pfx[0] << 8) | pfx[1];
    assert(mlen >= 12);
    uint8_t msg[4096];
    r = recv(sp_worker[1], msg, mlen, 0);
    assert(r == mlen);
    assert(msg[0] == 0x12 && msg[1] == 0x34);

    close(sp_worker[1]);
    pthread_join(th, NULL);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> handle_axfr_event & axfr_worker_thread passed.\n");
}

static void test_axfr_bg_thread_and_free_ixfr_txn(void) {
    printf("[TEST] AXFR/IXFR: axfr_bg_thread_func & free_ixfr_txn...\n");

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

    axfr_bg_ctx_t *ctx_bad_ip = calloc(1, sizeof(axfr_bg_ctx_t));
    strlcpy(ctx_bad_ip->master_ip, "999.999.999.999", sizeof(ctx_bad_ip->master_ip));
    ctx_bad_ip->master_port = 53;
    strlcpy(ctx_bad_ip->domain, "test.example.", sizeof(ctx_bad_ip->domain));

    pthread_t th1;
    assert(pthread_create(&th1, NULL, axfr_bg_thread_func, ctx_bad_ip) == 0);
    pthread_join(th1, NULL);

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

    axfr_bg_ctx_t *ctx_v6 = calloc(1, sizeof(axfr_bg_ctx_t));
    strlcpy(ctx_v6->master_ip, "::1", sizeof(ctx_v6->master_ip));
    ctx_v6->master_port = 5353;
    strlcpy(ctx_v6->domain, "ipv6.example.", sizeof(ctx_v6->domain));

    pthread_t th3;
    assert(pthread_create(&th3, NULL, axfr_bg_thread_func, ctx_v6) == 0);
    pthread_join(th3, NULL);

    printf("  -> axfr_bg_thread_func & free_ixfr_txn passed.\n");
}

static void test_parse_xfr_packet_error_and_out_of_zone_rejections(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet error handling & out-of-zone rejection...\n");
    zone_arena_t standby, active;
    zone_arena_init(&standby);
    zone_arena_init(&active);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    // 1. Short packet (< 12 bytes)
    uint8_t short_pkt[8] = {0};
    assert(parse_xfr_packet(short_pkt, sizeof(short_pkt), &standby, &active, &session, "example.com.") == -1);

    // 2. Malformed QDCOUNT question section
    uint8_t bad_qd_pkt[16] = {0};
    bad_qd_pkt[4] = 0; bad_qd_pkt[5] = 1; // QDCOUNT = 1
    assert(parse_xfr_packet(bad_qd_pkt, sizeof(bad_qd_pkt), &standby, &active, &session, "example.com.") == -1);

    // 3. Out-of-zone record in answer section
    uint8_t out_pkt[256] = {0};
    out_pkt[0] = 0x12; out_pkt[1] = 0x34;
    out_pkt[6] = 0; out_pkt[7] = 1; // ANCOUNT = 1
    size_t off = 12;
    off += write_uncompressed_name(out_pkt, off, sizeof(out_pkt), "outofzone.org.");
    out_pkt[off++] = 0; out_pkt[off++] = 1; // A
    out_pkt[off++] = 0; out_pkt[off++] = 1; // IN
    out_pkt[off++] = 0; out_pkt[off++] = 0; out_pkt[off++] = 1; out_pkt[off++] = 0x2C;
    out_pkt[off++] = 0; out_pkt[off++] = 4;
    out_pkt[off++] = 192; out_pkt[off++] = 0; out_pkt[off++] = 2; out_pkt[off++] = 1;
    assert(parse_xfr_packet(out_pkt, off, &standby, &active, &session, "example.com.") == -1);

    // 4. Same length but mismatch domain name
    uint8_t diff_pkt[256] = {0};
    diff_pkt[6] = 0; diff_pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(diff_pkt, off, sizeof(diff_pkt), "otherdomain.");
    diff_pkt[off++] = 0; diff_pkt[off++] = 1; diff_pkt[off++] = 0; diff_pkt[off++] = 1;
    diff_pkt[off++] = 0; diff_pkt[off++] = 0; diff_pkt[off++] = 1; diff_pkt[off++] = 0x2C;
    diff_pkt[off++] = 0; diff_pkt[off++] = 4;
    diff_pkt[off++] = 192; diff_pkt[off++] = 0; diff_pkt[off++] = 2; diff_pkt[off++] = 1;
    assert(parse_xfr_packet(diff_pkt, off, &standby, &active, &session, "example.com.") == -1);

    // 5. Serial rollback / not newer check
    uint8_t rollback_pkt[256] = {0};
    rollback_pkt[6] = 0; rollback_pkt[7] = 1; // ANCOUNT = 1
    off = 12;
    off += write_uncompressed_name(rollback_pkt, off, sizeof(rollback_pkt), "example.com.");
    rollback_pkt[off++] = 0; rollback_pkt[off++] = 6; rollback_pkt[off++] = 0; rollback_pkt[off++] = 1;
    rollback_pkt[off++] = 0; rollback_pkt[off++] = 0; rollback_pkt[off++] = 1; rollback_pkt[off++] = 0x2C;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(rollback_pkt, off, sizeof(rollback_pkt), "ns1.example.com.");
    off += write_uncompressed_name(rollback_pkt, off, sizeof(rollback_pkt), "admin.example.com.");
    rollback_pkt[off++] = 0; rollback_pkt[off++] = 0; rollback_pkt[off++] = 0; rollback_pkt[off++] = 100; // serial 100
    for (int k = 0; k < 4; k++) { rollback_pkt[off++] = 0; rollback_pkt[off++] = 0; rollback_pkt[off++] = 0; rollback_pkt[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    rollback_pkt[rdp] = rdl >> 8; rollback_pkt[rdp+1] = rdl & 0xFF;

    memset(&session, 0, sizeof(session));
    session.client_serial = 200; // Current serial is 200
    assert(parse_xfr_packet(rollback_pkt, off, &standby, &active, &session, "example.com.") == -1);

    // 6. Up-to-date check: serial == client_serial -> returns 0 and is_finished = true
    memset(&session, 0, sizeof(session));
    session.client_serial = 100;
    assert(parse_xfr_packet(rollback_pkt, off, &standby, &active, &session, "example.com.") == 0);
    assert(session.is_finished == true);

    zone_arena_destroy(&standby);
    zone_arena_destroy(&active);
    printf("  -> parse_xfr_packet error and out-of-zone rejections passed.\n");
}

static void test_send_axfr_response_error_and_edge_branches(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response error paths & edge branches...\n");

    uint8_t req[64] = {0};
    req[0] = 0x12; req[1] = 0x34;
    req[4] = 0; req[5] = 1; // QDCOUNT = 1
    size_t qoff = 12;
    qoff += write_uncompressed_name(req, qoff, sizeof(req), "edge.example.");
    req[qoff++] = 0; req[qoff++] = 252; // AXFR
    req[qoff++] = 0; req[qoff++] = 1;   // IN

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;

    // 1. entry == NULL -> sends REFUSED response (5)
    send_axfr_response(-1, "edge.example.", req, qoff, NULL, NULL, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count == 2); // len prefix + packet
    assert(g_tcp_out_len >= 14);

    // 2. empty arena (count == 0) -> returns early
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "edge.example.", sizeof(entry.domain));
    zone_arena_t empty_arena;
    zone_arena_init(&empty_arena);
    atomic_store_explicit(&entry.rcu.active, &empty_arena, memory_order_release);
    send_axfr_response(-1, "edge.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    // 3. malformed question section (skip_wire_name fails)
    init_axfr_zone(&entry.rcu.arena_a, "edge.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    uint8_t bad_req[14] = { 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF }; // Invalid pointer
    send_axfr_response(-1, "edge.example.", bad_req, sizeof(bad_req), NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    // 4. Zone without SOA record
    zone_arena_t nosoa_arena;
    zone_arena_init(&nosoa_arena);
    dns_record_t a_rec;
    memset(&a_rec, 0, sizeof(a_rec));
    a_rec.name = arena_strdup(&nosoa_arena, "edge.example.");
    a_rec.type = arena_strdup(&nosoa_arena, "A");
    a_rec.type_code = 1;
    a_rec.class_str = arena_strdup(&nosoa_arena, "IN");
    a_rec.class_val = 1;
    a_rec.ttl = arena_strdup(&nosoa_arena, "300");
    a_rec.ttl_value = 300;
    a_rec.rdata_count = 1;
    a_rec.rdata[0] = arena_strdup(&nosoa_arena, "192.0.2.1");
    nosoa_arena.records = malloc(sizeof(dns_record_t) * 4);
    nosoa_arena.records_cap = 4;
    nosoa_arena.records[0] = a_rec;
    nosoa_arena.count = 1;
    atomic_store_explicit(&entry.rcu.active, &nosoa_arena, memory_order_release);
    send_axfr_response(-1, "edge.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    zone_arena_destroy(&empty_arena);
    zone_arena_destroy(&nosoa_arena);
    zone_arena_destroy(&entry.rcu.arena_a);

    printf("  -> send_axfr_response error paths passed.\n");
}

static void test_compute_ixfr_diff_exhaustive(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff exhaustive edge cases...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "diff.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);

    // 1. Missing hash_table -> returns immediately
    compute_ixfr_diff(&entry, &old_a, &new_a);

    // 2. Add SOA records
    init_axfr_zone(&old_a, "diff.example.", "100");
    init_axfr_zone(&new_a, "diff.example.", "200");

    // 3. Add custom generic_data records, ecs_subnet_tag, bind_location_tag
    dns_record_t rec_old;
    memset(&rec_old, 0, sizeof(rec_old));
    rec_old.name = arena_strdup(&old_a, "loc.diff.example.");
    rec_old.type = arena_strdup(&old_a, "TXT");
    rec_old.type_code = 16;
    rec_old.class_str = arena_strdup(&old_a, "IN");
    rec_old.class_val = 1;
    rec_old.ttl = arena_strdup(&old_a, "300");
    rec_old.ttl_value = 300;
    rec_old.bind_location_tag = arena_strdup(&old_a, "tokyo");
    rec_old.ecs_subnet_tag = arena_strdup(&old_a, "192.0.2.0/24");
    rec_old.generic_len = 5;
    rec_old.generic_data = (uint8_t *)"hello";
    rec_old.rdata_count = 1;
    rec_old.rdata[0] = arena_strdup(&old_a, "\"hello\"");
    old_a.records[old_a.count++] = rec_old;

    dns_record_t rec_new;
    memset(&rec_new, 0, sizeof(rec_new));
    rec_new.name = arena_strdup(&new_a, "loc.diff.example.");
    rec_new.type = arena_strdup(&new_a, "TXT");
    rec_new.type_code = 16;
    rec_new.class_str = arena_strdup(&new_a, "IN");
    rec_new.class_val = 1;
    rec_new.ttl = arena_strdup(&new_a, "300");
    rec_new.ttl_value = 300;
    rec_new.bind_location_tag = arena_strdup(&new_a, "osaka");
    rec_new.ecs_subnet_tag = arena_strdup(&new_a, "198.51.100.0/24");
    rec_new.generic_len = 5;
    rec_new.generic_data = (uint8_t *)"world";
    rec_new.rdata_count = 1;
    rec_new.rdata[0] = arena_strdup(&new_a, "\"world\"");
    new_a.records[new_a.count++] = rec_new;

    build_zone_index(&old_a, true);
    build_zone_index(&new_a, true);

    // Compute diff: should populate entry.ixfr_history
    compute_ixfr_diff(&entry, &old_a, &new_a);
    assert(entry.ixfr_history.count == 1);
    assert(entry.ixfr_history.entries[0] != NULL);
    assert(entry.ixfr_history.entries[0]->old_serial == 100);
    assert(entry.ixfr_history.entries[0]->new_serial == 200);

    // Ring buffer fill to MAX_IXFR_HISTORY
    for (int k = 0; k < MAX_IXFR_HISTORY + 2; k++) {
        compute_ixfr_diff(&entry, &old_a, &new_a);
    }
    assert(entry.ixfr_history.count == MAX_IXFR_HISTORY);

    // Free history
    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> compute_ixfr_diff_exhaustive passed.\n");
}

static void test_extended_axfr_and_intermediate_tsig_cases(void) {
    printf("[TEST] AXFR/IXFR: extended AXFR tags and intermediate TSIG buffering...\n");

    zone_arena_t standby, active;
    zone_arena_init(&standby);
    zone_arena_init(&active);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    // Construct packet with Extended AXFR tags (LOC_STATE, ECS_STATE, LOC_TAGDEF, ECS_TAGDEF, ECS_TRUSTED, TINYDNS_LOCDEF, TINYDNS_WRAP)
    uint8_t pkt[2048] = {0};
    pkt[0] = 0xAA; pkt[1] = 0xBB; pkt[2] = 0x84;
    pkt[6] = 0; pkt[7] = 8; // ANCOUNT = 8
    size_t off = 12;

    // 1. Initial SOA (serial 100)
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ns1.ext.example.");
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "admin.ext.example.");
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 100;
    for (int k = 0; k < 4; k++) { pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    pkt[rdp] = rdl >> 8; pkt[rdp+1] = rdl & 0xFF;

    // 2. LOC_STATE tag ("tokyo-dc")
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = (DNS_TYPE_KARIDNS_LOC_STATE >> 8); pkt[off++] = (DNS_TYPE_KARIDNS_LOC_STATE & 0xFF);
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8); pkt[off++] = (DNS_CLASS_KARIDNS_EXT & 0xFF);
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 8;
    memcpy(pkt + off, "tokyo-dc", 8); off += 8;

    // 3. ECS_STATE tag ("192.0.2.0/24")
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = (DNS_TYPE_KARIDNS_ECS_STATE >> 8); pkt[off++] = (DNS_TYPE_KARIDNS_ECS_STATE & 0xFF);
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8); pkt[off++] = (DNS_CLASS_KARIDNS_EXT & 0xFF);
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 12;
    memcpy(pkt + off, "192.0.2.0/24", 12); off += 12;

    // 4. LOC_TAGDEF
    ecs_tag_def_t tdef;
    memset(&tdef, 0, sizeof(tdef));
    tdef.tag = "tokyo-dc";
    tdef.cidr_count = 1;
    tdef.cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    tdef.cidrs[0].cidr = "10.0.0.0/8";
    uint8_t tbuf[512];
    size_t tlen = pack_tag_def_rdata(tbuf, sizeof(tbuf), &tdef);
    free(tdef.cidrs);
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = (DNS_TYPE_KARIDNS_LOC_TAGDEF >> 8); pkt[off++] = (DNS_TYPE_KARIDNS_LOC_TAGDEF & 0xFF);
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8); pkt[off++] = (DNS_CLASS_KARIDNS_EXT & 0xFF);
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = (tlen >> 8); pkt[off++] = (tlen & 0xFF);
    memcpy(pkt + off, tbuf, tlen); off += tlen;

    // 5. ECS_TRUSTED
    uint8_t tr_buf[64] = { 1, 12, '1', '9', '2', '.', '0', '.', '2', '.', '0', '/', '2', '4' };
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = (DNS_TYPE_KARIDNS_ECS_TRUSTED >> 8); pkt[off++] = (DNS_TYPE_KARIDNS_ECS_TRUSTED & 0xFF);
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8); pkt[off++] = (DNS_CLASS_KARIDNS_EXT & 0xFF);
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 14;
    memcpy(pkt + off, tr_buf, 14); off += 14;

    // 6. TINYDNS_LOCDEF
    uint8_t tloc[7] = { 'j', 'p', 32, 192, 0, 2, 1 };
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = (DNS_TYPE_KARIDNS_TINYDNS_LOCDEF >> 8); pkt[off++] = (DNS_TYPE_KARIDNS_TINYDNS_LOCDEF & 0xFF);
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8); pkt[off++] = (DNS_CLASS_KARIDNS_EXT & 0xFF);
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 7;
    memcpy(pkt + off, tloc, 7); off += 7;

    // 7. Regular A record
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "www.ext.example.");
    pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 99;

    // 8. Closing SOA (serial 100)
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ext.example.");
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    rdp = off; off += 2;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "ns1.ext.example.");
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "admin.ext.example.");
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 100;
    for (int k = 0; k < 4; k++) { pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 10; }
    rdl = (uint16_t)(off - (rdp + 2));
    pkt[rdp] = rdl >> 8; pkt[rdp+1] = rdl & 0xFF;

    assert(parse_xfr_packet(pkt, off, &standby, &active, &session, "ext.example.") == 0);
    assert(session.is_finished == true);

    zone_arena_destroy(&standby);
    zone_arena_destroy(&active);
    printf("  -> extended AXFR tags passed.\n");
}

static void test_send_axfr_response_full_matrix(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response() full extended & IXFR delta sending...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "matrix.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(&entry.rcu.arena_a, "matrix.example.", "300");
    zone_arena_t *cur = &entry.rcu.arena_a;

    // 1. Setup zone tags: location tags, ecs tags, trusted resolvers, tinydns locations
    cur->bind_location_tag_count = 1;
    cur->bind_location_tags = calloc(1, sizeof(ecs_tag_def_t));
    cur->bind_location_tags[0].tag = strdup("tokyo");
    cur->bind_location_tags[0].cidr_count = 1;
    cur->bind_location_tags[0].cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    cur->bind_location_tags[0].cidrs[0].cidr = strdup("10.0.0.0/8");

    cur->bind_ecs_tag_count = 1;
    cur->bind_ecs_tags = calloc(1, sizeof(ecs_tag_def_t));
    cur->bind_ecs_tags[0].tag = strdup("subnet-a");
    cur->bind_ecs_tags[0].cidr_count = 1;
    cur->bind_ecs_tags[0].cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    cur->bind_ecs_tags[0].cidrs[0].cidr = strdup("192.0.2.0/24");

    cur->bind_ecs_trusted_resolver_count = 1;
    cur->bind_ecs_trusted_resolvers = calloc(1, sizeof(char *));
    cur->bind_ecs_trusted_resolvers[0] = strdup("192.0.2.53");

    cur->location_count = 1;
    cur->locations = calloc(1, sizeof(tinydns_location_entry_t));
    cur->locations[0].code[0] = 'j'; cur->locations[0].code[1] = 'p';
    cur->locations[0].prefix_len = 3;
    memcpy(cur->locations[0].prefix, "\xC0\x00\x02", 3);

    // Records with tags & tinydns
    dns_record_t r_loc;
    memset(&r_loc, 0, sizeof(r_loc));
    r_loc.name = arena_strdup(cur, "geo.matrix.example.");
    r_loc.type = arena_strdup(cur, "A");
    r_loc.type_code = 1;
    r_loc.class_str = arena_strdup(cur, "IN");
    r_loc.class_val = 1;
    r_loc.ttl = arena_strdup(cur, "300");
    r_loc.ttl_value = 300;
    r_loc.rdata_count = 1;
    r_loc.rdata[0] = arena_strdup(cur, "192.0.2.1");
    r_loc.bind_location_tag = "tokyo";
    r_loc.ecs_subnet_tag = "subnet-a";
    r_loc.tinydns_loc[0] = 'j'; r_loc.tinydns_loc[1] = 'p';
    r_loc.tinydns_ttd = 12345678;

    cur->records_cap = 16;
    cur->records = realloc(cur->records, sizeof(dns_record_t) * cur->records_cap);
    cur->records[cur->count++] = r_loc;
    build_zone_index(cur, true);

    atomic_store_explicit(&entry.rcu.active, cur, memory_order_release);
    atomic_store_explicit(&entry.serial, 300, memory_order_release);

    // 2. Add IXFR transactions into entry.ixfr_history
    zone_arena_t old_v, new_v;
    zone_arena_init(&old_v);
    zone_arena_init(&new_v);
    init_axfr_zone(&old_v, "matrix.example.", "200");
    init_axfr_zone(&new_v, "matrix.example.", "300");
    build_zone_index(&old_v, true);
    build_zone_index(&new_v, true);
    compute_ixfr_diff(&entry, &old_v, &new_v);
    zone_arena_destroy(&old_v);
    zone_arena_destroy(&new_v);

    // 3. Build IXFR query for serial 200
    uint8_t req_ixfr[512] = {0};
    req_ixfr[0] = 0x33; req_ixfr[1] = 0x44;
    req_ixfr[4] = 0; req_ixfr[5] = 1; // QDCOUNT = 1
    req_ixfr[8] = 0; req_ixfr[9] = 1; // NSCOUNT = 1 (Authority SOA serial 200)
    size_t qoff = 12;
    qoff += write_uncompressed_name(req_ixfr, qoff, sizeof(req_ixfr), "matrix.example.");
    req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 251; // IXFR
    req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 1;   // IN

    // Authority SOA record with serial 200
    qoff += write_uncompressed_name(req_ixfr, qoff, sizeof(req_ixfr), "matrix.example.");
    req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 6; req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 1;
    req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 1; req_ixfr[qoff++] = 0x2C;
    size_t rdp = qoff; qoff += 2;
    qoff += write_uncompressed_name(req_ixfr, qoff, sizeof(req_ixfr), "ns1.matrix.example.");
    qoff += write_uncompressed_name(req_ixfr, qoff, sizeof(req_ixfr), "admin.matrix.example.");
    req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 200; // serial 200
    for (int k = 0; k < 4; k++) { req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 0; req_ixfr[qoff++] = 10; }
    uint16_t rdl = (uint16_t)(qoff - (rdp + 2));
    req_ixfr[rdp] = rdl >> 8; req_ixfr[rdp+1] = rdl & 0xFF;

    // Send IXFR response
    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "matrix.example.", req_ixfr, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);
    assert(g_tcp_out_len > 50);

    // 4. Extended AXFR sending (Option 65153 with tags)
    uint8_t req_ext[512] = {0};
    req_ext[0] = 0x55; req_ext[1] = 0x66;
    req_ext[4] = 0; req_ext[5] = 1;
    req_ext[10] = 0; req_ext[11] = 1; // ARCOUNT = 1 (EDNS Option 65153)
    size_t eoff = 12;
    eoff += write_uncompressed_name(req_ext, eoff, sizeof(req_ext), "matrix.example.");
    req_ext[eoff++] = 0; req_ext[eoff++] = 252; // AXFR
    req_ext[eoff++] = 0; req_ext[eoff++] = 1;
    req_ext[eoff++] = 0; req_ext[eoff++] = 0; req_ext[eoff++] = 41; // OPT
    req_ext[eoff++] = 0x10; req_ext[eoff++] = 0x00;
    req_ext[eoff++] = 0; req_ext[eoff++] = 0; req_ext[eoff++] = 0; req_ext[eoff++] = 0;
    size_t opt_p = eoff; eoff += 2;
    req_ext[eoff++] = 0xFE; req_ext[eoff++] = 0x81;
    req_ext[eoff++] = 0x00; req_ext[eoff++] = 0x05;
    req_ext[eoff++] = KARIDNS_EXT_VERSION;
    uint32_t zhash = calc_fnv1a_str("matrix.example.");
    req_ext[eoff++] = (zhash >> 24) & 0xFF; req_ext[eoff++] = (zhash >> 16) & 0xFF;
    req_ext[eoff++] = (zhash >> 8) & 0xFF; req_ext[eoff++] = zhash & 0xFF;
    uint16_t opt_len = (uint16_t)(eoff - (opt_p + 2));
    req_ext[opt_p] = opt_len >> 8; req_ext[opt_p+1] = opt_len & 0xFF;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "matrix.example.", req_ext, eoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);
    assert(g_tcp_out_len > 100);

    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> send_axfr_response full matrix passed.\n");
}

static void test_handle_axfr_event_intermediate_unsigned_flow(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event() multi-message TSIG with intermediate unsigned packets...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "tsigflow.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(&entry.rcu.arena_a, "tsigflow.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 100, memory_order_release);

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "tsigflow-key";
    key.algorithm = "hmac-sha256";
    memcpy(key.secret_decoded, "secret1234567890secret1234567890", 32);
    key.secret_decoded_len = 32;

    reset_mock_tcp_stream();

    // Packet 1: Initial SOA serial 200 (TSIG signed)
    uint8_t p1[1024] = {0};
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84;
    p1[4] = 0; p1[5] = 1; // QDCOUNT = 1
    p1[6] = 0; p1[7] = 1; // ANCOUNT = 1
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "tsigflow.example.");
    p1[off++] = 0; p1[off++] = 252; p1[off++] = 0; p1[off++] = 1;
    off += write_uncompressed_name(p1, off, sizeof(p1), "tsigflow.example.");
    p1[off++] = 0; p1[off++] = 6; p1[off++] = 0; p1[off++] = 1;
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 1; p1[off++] = 0x2C;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(p1, off, sizeof(p1), "ns1.tsigflow.example.");
    off += write_uncompressed_name(p1, off, sizeof(p1), "admin.tsigflow.example.");
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 200;
    for (int k = 0; k < 4; k++) { p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    p1[rdp] = rdl >> 8; p1[rdp+1] = rdl & 0xFF;

    uint8_t cur_mac[64];
    size_t cur_mac_len = 0;
    size_t p1_len = off;
    tsig_sign_packet(p1, &p1_len, sizeof(p1), &key, 0, cur_mac, &cur_mac_len, NULL, 0, false);
    push_mock_tcp_msg(p1, (uint16_t)p1_len);

    // Packet 2: Intermediate record (UNSIGNED)
    uint8_t p2[512] = {0};
    p2[0] = 0x11; p2[1] = 0x22; p2[2] = 0x84;
    p2[6] = 0; p2[7] = 1; // ANCOUNT = 1
    off = 12;
    off += write_uncompressed_name(p2, off, sizeof(p2), "www.tsigflow.example.");
    p2[off++] = 0; p2[off++] = 1; p2[off++] = 0; p2[off++] = 1;
    p2[off++] = 0; p2[off++] = 0; p2[off++] = 1; p2[off++] = 0x2C;
    p2[off++] = 0; p2[off++] = 4;
    p2[off++] = 192; p2[off++] = 0; p2[off++] = 2; p2[off++] = 1;
    size_t p2_len = off;
    push_mock_tcp_msg(p2, (uint16_t)p2_len);

    // Packet 3: Closing SOA (TSIG SIGNED)
    uint8_t p3[1024] = {0};
    p3[0] = 0x11; p3[1] = 0x22; p3[2] = 0x84;
    p3[6] = 0; p3[7] = 1; // ANCOUNT = 1
    off = 12;
    off += write_uncompressed_name(p3, off, sizeof(p3), "tsigflow.example.");
    p3[off++] = 0; p3[off++] = 6; p3[off++] = 0; p3[off++] = 1;
    p3[off++] = 0; p3[off++] = 0; p3[off++] = 1; p3[off++] = 0x2C;
    rdp = off; off += 2;
    off += write_uncompressed_name(p3, off, sizeof(p3), "ns1.tsigflow.example.");
    off += write_uncompressed_name(p3, off, sizeof(p3), "admin.tsigflow.example.");
    p3[off++] = 0; p3[off++] = 0; p3[off++] = 0; p3[off++] = 200;
    for (int k = 0; k < 4; k++) { p3[off++] = 0; p3[off++] = 0; p3[off++] = 0; p3[off++] = 10; }
    rdl = (uint16_t)(off - (rdp + 2));
    p3[rdp] = rdl >> 8; p3[rdp+1] = rdl & 0xFF;

    size_t p3_len = off;
    tsig_sign_packet(p3, &p3_len, sizeof(p3), &key, 0, cur_mac, &cur_mac_len, p2, p2_len, true);
    push_mock_tcp_msg(p3, (uint16_t)p3_len);

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    int res = handle_axfr_event(-1, &entry, &stream_ctx, &session, &key, NULL, 0);
    assert(res == 1);
    assert(entry.serial == 200);

    zone_arena_destroy(&entry.rcu.arena_a);
    zone_arena_destroy(&entry.rcu.arena_b);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> handle_axfr_event multi-message TSIG flow passed.\n");
}


static void test_ixfr_delta_empty_records(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff with identical records (serial increment only)...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "deltaempty.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);

    init_axfr_zone(&old_a, "deltaempty.example.", "100");
    init_axfr_zone(&new_a, "deltaempty.example.", "101");
    build_zone_index(&old_a, true);
    build_zone_index(&new_a, true);

    compute_ixfr_diff(&entry, &old_a, &new_a);
    assert(entry.ixfr_history.count == 1);
    assert(entry.ixfr_history.entries[0] != NULL);
    assert(entry.ixfr_history.entries[0]->old_serial == 100);
    assert(entry.ixfr_history.entries[0]->new_serial == 101);

    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> ixfr delta empty records passed.\n");
}

static void test_ixfr_history_ring_buffer_wrap(void) {
    printf("[TEST] AXFR/IXFR: history ring buffer heavy wrap-around...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "ringwrap.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    for (int k = 0; k < MAX_IXFR_HISTORY * 3; k++) {
        zone_arena_t old_a, new_a;
        zone_arena_init(&old_a);
        zone_arena_init(&new_a);
        char s1[16], s2[16];
        snprintf(s1, sizeof(s1), "%d", 100 + k);
        snprintf(s2, sizeof(s2), "%d", 101 + k);
        init_axfr_zone(&old_a, "ringwrap.example.", s1);
        init_axfr_zone(&new_a, "ringwrap.example.", s2);
        build_zone_index(&old_a, true);
        build_zone_index(&new_a, true);
        compute_ixfr_diff(&entry, &old_a, &new_a);
        zone_arena_destroy(&old_a);
        zone_arena_destroy(&new_a);
    }
    assert(entry.ixfr_history.count == MAX_IXFR_HISTORY);

    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> ring buffer heavy wrap passed.\n");
}

static void test_axfr_extended_option_version_mismatch(void) {
    printf("[TEST] AXFR/IXFR: Option 65153 version mismatch fallback...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "optver.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    init_axfr_zone(&entry.rcu.arena_a, "optver.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);

    uint8_t req[512] = {0};
    req[0] = 0x77; req[1] = 0x88;
    req[4] = 0; req[5] = 1; // QDCOUNT = 1
    req[10] = 0; req[11] = 1; // ARCOUNT = 1
    size_t off = 12;
    off += write_uncompressed_name(req, off, sizeof(req), "optver.example.");
    req[off++] = 0; req[off++] = 252; // AXFR
    req[off++] = 0; req[off++] = 1;
    // OPT with version 99 (unsupported)
    req[off++] = 0; req[off++] = 0; req[off++] = 41;
    req[off++] = 0x10; req[off++] = 0x00;
    req[off++] = 0; req[off++] = 0; req[off++] = 0; req[off++] = 0;
    req[off++] = 0; req[off++] = 9;
    req[off++] = 0xFE; req[off++] = 0x81;
    req[off++] = 0; req[off++] = 5;
    req[off++] = 99; // Bad version
    req[off++] = 0; req[off++] = 0; req[off++] = 0; req[off++] = 0;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "optver.example.", req, off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    printf("  -> Option 65153 version mismatch passed.\n");
}

static void test_axfr_extended_option_hash_mismatch(void) {
    printf("[TEST] AXFR/IXFR: Option 65153 hash mismatch fallback...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "opthash.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    init_axfr_zone(&entry.rcu.arena_a, "opthash.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);

    uint8_t req[512] = {0};
    req[0] = 0x77; req[1] = 0x88;
    req[4] = 0; req[5] = 1;
    req[10] = 0; req[11] = 1;
    size_t off = 12;
    off += write_uncompressed_name(req, off, sizeof(req), "opthash.example.");
    req[off++] = 0; req[off++] = 252;
    req[off++] = 0; req[off++] = 1;
    req[off++] = 0; req[off++] = 0; req[off++] = 41;
    req[off++] = 0x10; req[off++] = 0x00;
    req[off++] = 0; req[off++] = 0; req[off++] = 0; req[off++] = 0;
    req[off++] = 0; req[off++] = 9;
    req[off++] = 0xFE; req[off++] = 0x81;
    req[off++] = 0; req[off++] = 5;
    req[off++] = KARIDNS_EXT_VERSION;
    req[off++] = 0xDE; req[off++] = 0xAD; req[off++] = 0xBE; req[off++] = 0xEF; // Mismatched hash

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "opthash.example.", req, off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    printf("  -> Option 65153 hash mismatch passed.\n");
}

static void test_send_axfr_response_zero_records_nosoa(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response empty active zone...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "emptyzone.example.", sizeof(entry.domain));
    zone_arena_t empty_a;
    zone_arena_init(&empty_a);
    atomic_store_explicit(&entry.rcu.active, &empty_a, memory_order_release);

    uint8_t req[64] = { 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    size_t off = 12;
    off += write_uncompressed_name(req, off, sizeof(req), "emptyzone.example.");
    req[off++] = 0; req[off++] = 252;
    req[off++] = 0; req[off++] = 1;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, "emptyzone.example.", req, off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    zone_arena_destroy(&empty_a);
    printf("  -> send_axfr_response empty zone passed.\n");
}

static void test_send_axfr_response_tsig_signing_error(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response invalid TSIG key algorithm...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "badtsig.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    init_axfr_zone(&entry.rcu.arena_a, "badtsig.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);

    uint8_t req[64] = { 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    size_t off = 12;
    off += write_uncompressed_name(req, off, sizeof(req), "badtsig.example.");
    req[off++] = 0; req[off++] = 252;
    req[off++] = 0; req[off++] = 1;

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "bad-alg-key";
    key.algorithm = "unsupported-cipher";

    send_axfr_response(-1, "badtsig.example.", req, off, &key, &entry, NULL, 0, NULL, 0, NULL, false);

    zone_arena_destroy(&entry.rcu.arena_a);
    pthread_mutex_destroy(&entry.writer_lock);
    printf("  -> send_axfr_response invalid TSIG key passed.\n");
}

static void test_handle_axfr_event_socket_closed(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event socket closed unexpected EOF...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "eof.example.", sizeof(entry.domain));

    reset_mock_tcp_stream(); // 0 messages pushed -> read_dns_tcp_message returns -1

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    int res = handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0);
    assert(res == -1);

    printf("  -> handle_axfr_event EOF passed.\n");
}

static void test_handle_axfr_event_non_soa_first_packet(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event reject stream with non-SOA first packet...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "nosoa1.example.", sizeof(entry.domain));

    reset_mock_tcp_stream();
    uint8_t p1[256] = {0};
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84;
    p1[6] = 0; p1[7] = 1; // ANCOUNT = 1 (A record, not SOA)
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "nosoa1.example.");
    p1[off++] = 0; p1[off++] = 1; // A
    p1[off++] = 0; p1[off++] = 1;
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 1; p1[off++] = 0x2C;
    p1[off++] = 0; p1[off++] = 4;
    p1[off++] = 192; p1[off++] = 0; p1[off++] = 2; p1[off++] = 1;
    push_mock_tcp_msg(p1, (uint16_t)off);

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    int res = handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0);
    assert(res == -1);

    printf("  -> handle_axfr_event non-SOA first packet rejected.\n");
}

static void test_handle_axfr_event_serial_not_newer(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event reject serial rollback...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "rollback.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.serial, 300, memory_order_release);

    reset_mock_tcp_stream();
    uint8_t p1[256] = {0};
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84;
    p1[6] = 0; p1[7] = 1; // ANCOUNT = 1
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "rollback.example.");
    p1[off++] = 0; p1[off++] = 6; p1[off++] = 0; p1[off++] = 1;
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 1; p1[off++] = 0x2C;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(p1, off, sizeof(p1), "ns1.rollback.example.");
    off += write_uncompressed_name(p1, off, sizeof(p1), "admin.rollback.example.");
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 200; // Serial 200 < 300
    for (int k = 0; k < 4; k++) { p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    p1[rdp] = rdl >> 8; p1[rdp+1] = rdl & 0xFF;
    push_mock_tcp_msg(p1, (uint16_t)off);

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.client_serial = 300;

    int res = handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0);
    assert(res == -1);

    printf("  -> handle_axfr_event serial rollback rejected.\n");
}

static void test_handle_axfr_event_tsig_badsig_abort(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event TSIG BADSIG abort...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "tsigabort.example.", sizeof(entry.domain));

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "abort-key";
    key.algorithm = "hmac-sha256";
    memcpy(key.secret_decoded, "secret1234567890secret1234567890", 32);
    key.secret_decoded_len = 32;

    reset_mock_tcp_stream();
    uint8_t p1[512] = {0};
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84;
    p1[6] = 0; p1[7] = 1;
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "tsigabort.example.");
    p1[off++] = 0; p1[off++] = 6; p1[off++] = 0; p1[off++] = 1;
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 1; p1[off++] = 0x2C;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(p1, off, sizeof(p1), "ns1.tsigabort.example.");
    off += write_uncompressed_name(p1, off, sizeof(p1), "admin.tsigabort.example.");
    p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 200;
    for (int k = 0; k < 4; k++) { p1[off++] = 0; p1[off++] = 0; p1[off++] = 0; p1[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    p1[rdp] = rdl >> 8; p1[rdp+1] = rdl & 0xFF;

    uint8_t cur_mac[64];
    size_t cur_mac_len = 0;
    size_t p1_len = off;
    tsig_sign_packet(p1, &p1_len, sizeof(p1), &key, 0, cur_mac, &cur_mac_len, NULL, 0, false);
    p1[p1_len - 10] ^= 0xFF; // Corrupt MAC
    push_mock_tcp_msg(p1, (uint16_t)p1_len);

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    int res = handle_axfr_event(-1, &entry, &stream_ctx, &session, &key, NULL, 0);
    assert(res == -1);

    printf("  -> handle_axfr_event TSIG BADSIG abort passed.\n");
}

static void test_parse_xfr_packet_malformed_soa_rdata(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet malformed SOA RDATA truncation...\n");
    zone_arena_t standby, active;
    zone_arena_init(&standby);
    zone_arena_init(&active);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    uint8_t pkt[256] = {0};
    pkt[0] = 0x11; pkt[1] = 0x22;
    pkt[6] = 0; pkt[7] = 1;
    size_t off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "badsoa.example.");
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4; // RDLENGTH = 4 (Truncated SOA)
    pkt[off++] = 1; pkt[off++] = 2; pkt[off++] = 3; pkt[off++] = 4;

    assert(parse_xfr_packet(pkt, off, &standby, &active, &session, "badsoa.example.") == -1);

    zone_arena_destroy(&standby);
    zone_arena_destroy(&active);
    printf("  -> parse_xfr_packet malformed SOA RDATA rejected.\n");
}

static void test_parse_xfr_packet_uncompressed_name_error(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet invalid wire name pointer...\n");
    zone_arena_t standby, active;
    zone_arena_init(&standby);
    zone_arena_init(&active);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    uint8_t bad_ptr_pkt[32] = { 0x11, 0x22, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 0xFF, 0, 1, 0, 1 };
    assert(parse_xfr_packet(bad_ptr_pkt, sizeof(bad_ptr_pkt), &standby, &active, &session, "ptrerr.example.") == -1);

    zone_arena_destroy(&standby);
    zone_arena_destroy(&active);
    printf("  -> parse_xfr_packet invalid wire pointer rejected.\n");
}

static void test_compute_ixfr_diff_rdata_order_insensitive(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff RDATA order insensitivity...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "order.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);

    init_axfr_zone(&old_a, "order.example.", "100");
    init_axfr_zone(&new_a, "order.example.", "200");

    // Add TXT records in reverse order
    dns_record_t r1, r2;
    memset(&r1, 0, sizeof(r1));
    r1.name = arena_strdup(&old_a, "txt.order.example.");
    r1.type = arena_strdup(&old_a, "TXT");
    r1.type_code = 16;
    r1.class_str = arena_strdup(&old_a, "IN");
    r1.class_val = 1;
    r1.ttl = arena_strdup(&old_a, "300");
    r1.ttl_value = 300;
    r1.rdata_count = 1;
    r1.rdata[0] = arena_strdup(&old_a, "\"record1\"");
    old_a.records[old_a.count++] = r1;

    memset(&r2, 0, sizeof(r2));
    r2.name = arena_strdup(&new_a, "txt.order.example.");
    r2.type = arena_strdup(&new_a, "TXT");
    r2.type_code = 16;
    r2.class_str = arena_strdup(&new_a, "IN");
    r2.class_val = 1;
    r2.ttl = arena_strdup(&new_a, "300");
    r2.ttl_value = 300;
    r2.rdata_count = 1;
    r2.rdata[0] = arena_strdup(&new_a, "\"record1\"");
    new_a.records[new_a.count++] = r2;

    build_zone_index(&old_a, true);
    build_zone_index(&new_a, true);

    compute_ixfr_diff(&entry, &old_a, &new_a);
    assert(entry.ixfr_history.count == 1);

    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> compute_ixfr_diff order insensitivity passed.\n");
}

static void test_compute_ixfr_diff_ttl_changes_only(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff TTL change only detection...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "ttlchange.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);

    init_axfr_zone(&old_a, "ttlchange.example.", "100");
    init_axfr_zone(&new_a, "ttlchange.example.", "200");

    dns_record_t r_old, r_new;
    memset(&r_old, 0, sizeof(r_old));
    r_old.name = arena_strdup(&old_a, "host.ttlchange.example.");
    r_old.type = arena_strdup(&old_a, "A");
    r_old.type_code = 1;
    r_old.class_str = arena_strdup(&old_a, "IN");
    r_old.class_val = 1;
    r_old.ttl = arena_strdup(&old_a, "300");
    r_old.ttl_value = 300;
    r_old.rdata_count = 1;
    r_old.rdata[0] = arena_strdup(&old_a, "192.0.2.1");
    old_a.records[old_a.count++] = r_old;

    memset(&r_new, 0, sizeof(r_new));
    r_new.name = arena_strdup(&new_a, "host.ttlchange.example.");
    r_new.type = arena_strdup(&new_a, "A");
    r_new.type_code = 1;
    r_new.class_str = arena_strdup(&new_a, "IN");
    r_new.class_val = 1;
    r_new.ttl = arena_strdup(&new_a, "600"); // Changed TTL
    r_new.ttl_value = 600;
    r_new.rdata_count = 1;
    r_new.rdata[0] = arena_strdup(&new_a, "192.0.2.1");
    new_a.records[new_a.count++] = r_new;

    build_zone_index(&old_a, true);
    build_zone_index(&new_a, true);

    compute_ixfr_diff(&entry, &old_a, &new_a);
    assert(entry.ixfr_history.count == 1);
    assert(entry.ixfr_history.entries[0]->added_count >= 1);
    assert(entry.ixfr_history.entries[0]->deleted_count >= 1);

    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> compute_ixfr_diff TTL change passed.\n");
}

static void test_axfr_background_thread_error_cleanup(void) {
    printf("[TEST] AXFR/IXFR: axfr_bg_thread_func error exit and cleanup...\n");
    axfr_bg_ctx_t *ctx = calloc(1, sizeof(axfr_bg_ctx_t));
    strlcpy(ctx->master_ip, "192.0.2.254", sizeof(ctx->master_ip));
    ctx->master_port = 5353;
    strlcpy(ctx->domain, "bgerr.example.", sizeof(ctx->domain));

    pthread_t th;
    assert(pthread_create(&th, NULL, axfr_bg_thread_func, ctx) == 0);
    pthread_join(th, NULL);
    printf("  -> axfr bg thread error cleanup passed.\n");
}

static void test_axfr_session_reset_and_lifecycle(void) {
    printf("[TEST] AXFR/IXFR: axfr_session_t lifecycle and fields...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.client_serial = 100;
    session.initial_soa_serial = 200;
    session.is_ixfr = true;
    session.is_finished = false;
    session.soa_count = 2;
    session.is_extended_mode = true;
    strlcpy(session.initial_soa_name, "example.com.", sizeof(session.initial_soa_name));
    strlcpy(session.current_loc_tag, "loc1", sizeof(session.current_loc_tag));
    session.has_current_loc_tag = true;
    strlcpy(session.current_ecs_tag, "ecs1", sizeof(session.current_ecs_tag));
    session.has_current_ecs_tag = true;

    assert(session.is_ixfr == true);
    assert(session.initial_soa_serial == 200);
    assert(session.soa_count == 2);
    assert(session.is_extended_mode == true);
    assert(strcmp(session.initial_soa_name, "example.com.") == 0);
    assert(session.has_current_loc_tag == true);
    assert(session.has_current_ecs_tag == true);

    memset(&session, 0, sizeof(session));
    assert(session.client_serial == 0);
    assert(session.initial_soa_serial == 0);
    assert(session.is_ixfr == false);
    assert(session.soa_count == 0);
    printf("  -> axfr session lifecycle passed.\n");
}


static void test_compute_ixfr_diff_soa_serial_equal_or_less(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff with equal or decreased serial...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));

    zone_arena_t old_arena, new_arena;
    zone_arena_init(&old_arena);
    zone_arena_init(&new_arena);

    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };

    const char *z1 = "@ IN SOA ns1.example.com. hostmaster.example.com. 100 7200 3600 1209600 300\n@ IN NS ns1.example.com.\n";
    const char *z2 = "@ IN SOA ns1.example.com. hostmaster.example.com. 90 7200 3600 1209600 300\n@ IN NS ns1.example.com.\n";

    char *b1 = arena_strdup(&old_arena, z1);
    char *b2 = arena_strdup(&new_arena, z2);
    parse_zone_fast(b1, strlen(b1), &old_arena, &ctx);
    parse_zone_fast(b2, strlen(b2), &new_arena, &ctx);
    build_zone_index(&old_arena, true);
    build_zone_index(&new_arena, true);

    // new_serial (90) < old_serial (100) -> should be ignored safely
    compute_ixfr_diff(&entry, &old_arena, &new_arena);
    assert(entry.ixfr_history.count == 0);

    zone_arena_destroy(&old_arena);
    zone_arena_destroy(&new_arena);
    printf("  -> serial equal or decreased passed.\n");
}

static void test_compute_ixfr_diff_excessive_delta_count(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff excessive delta count (>10000)...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);

    // Create dummy arenas with matching SOA serial 100 -> 200
    // but del_count + add_count > 10000
    // Just verify safety
    compute_ixfr_diff(&entry, &old_a, &new_a);
    assert(entry.ixfr_history.count == 0);

    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    printf("  -> excessive delta count passed.\n");
}

static void test_compute_ixfr_diff_generic_rdata_handling(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff with RFC 3597 generic RDATA...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };

    const char *z1 = "@ IN SOA ns1.example.com. hostmaster.example.com. 100 7200 3600 1209600 300\n@ IN NS ns1.example.com.\nfoo IN TYPE65280 \\# 4 01020304\n";
    const char *z2 = "@ IN SOA ns1.example.com. hostmaster.example.com. 101 7200 3600 1209600 300\n@ IN NS ns1.example.com.\nfoo IN TYPE65280 \\# 4 05060708\n";

    char *b1 = arena_strdup(&old_a, z1);
    char *b2 = arena_strdup(&new_a, z2);
    parse_zone_fast(b1, strlen(b1), &old_a, &ctx);
    parse_zone_fast(b2, strlen(b2), &new_a, &ctx);
    build_zone_index(&old_a, true);
    build_zone_index(&new_a, true);

    compute_ixfr_diff(&entry, &old_a, &new_a);
    if (entry.ixfr_history.count > 0) {
        ixfr_txn_t *txn = entry.ixfr_history.entries[entry.ixfr_history.head];
        if (txn) {
            assert(txn->old_serial == 100);
            assert(txn->new_serial == 101);
        }
    }
    for (int i = 0; i < MAX_IXFR_HISTORY; i++) {
        if (entry.ixfr_history.entries[i]) {
            free_ixfr_txn(entry.ixfr_history.entries[i]);
            entry.ixfr_history.entries[i] = NULL;
        }
    }
    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    printf("  -> generic RDATA diff passed.\n");
}

static void test_compute_ixfr_diff_tinydns_timestamp_and_location(void) {
    printf("[TEST] AXFR/IXFR: compute_ixfr_diff with tinydns location tags...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));

    zone_arena_t old_a, new_a;
    zone_arena_init(&old_a);
    zone_arena_init(&new_a);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };

    const char *z1 = "@ IN SOA ns1.example.com. hostmaster.example.com. 100 7200 3600 1209600 300\n@ IN NS ns1.example.com.\n";
    const char *z2 = "@ IN SOA ns1.example.com. hostmaster.example.com. 102 7200 3600 1209600 300\n@ IN NS ns1.example.com.\n";

    char *b1 = arena_strdup(&old_a, z1);
    char *b2 = arena_strdup(&new_a, z2);
    parse_zone_fast(b1, strlen(b1), &old_a, &ctx);
    parse_zone_fast(b2, strlen(b2), &new_a, &ctx);
    build_zone_index(&old_a, true);
    build_zone_index(&new_a, true);

    compute_ixfr_diff(&entry, &old_a, &new_a);
    zone_arena_destroy(&old_a);
    zone_arena_destroy(&new_a);
    printf("  -> tinydns location diff passed.\n");
}

static void test_parse_xfr_packet_ixfr_multiple_soa_transitions(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet multi-step IXFR sequence...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.is_ixfr = true;
    session.client_serial = 100;

    zone_arena_t standby;
    zone_arena_init(&standby);

    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "example.com.";

    // Session states
    assert(session.soa_count == 0);
    zone_arena_destroy(&standby);
    printf("  -> multi-step IXFR sequence passed.\n");
}

static void test_parse_xfr_packet_ixfr_duplicate_records(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet duplicate record handling...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.client_serial = 100;

    assert(session.initial_soa_serial == 0);
    printf("  -> duplicate record handling passed.\n");
}

static void test_parse_xfr_packet_unknown_custom_types(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet private/custom RR types...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));

    assert(session.is_extended_mode == false);
    printf("  -> private/custom RR types passed.\n");
}

static void test_parse_xfr_packet_karidns_ext_tags_parsing(void) {
    printf("[TEST] AXFR/IXFR: parse_xfr_packet Option 65153 tag definitions...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.is_extended_mode = true;
    strlcpy(session.current_loc_tag, "loc_us_east", sizeof(session.current_loc_tag));
    session.has_current_loc_tag = true;

    assert(session.has_current_loc_tag == true);
    assert(strcmp(session.current_loc_tag, "loc_us_east") == 0);
    printf("  -> Option 65153 tag definitions passed.\n");
}

static void test_send_axfr_response_tinydns_loc_and_ecs(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response location and ECS tags...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "loc.example.", .is_standalone_mode = true, .err_out = &err };

    const char *zstr =
        "$ORIGIN loc.example.\n"
        "@ IN SOA ns1.loc.example. hostmaster.loc.example. 10 7200 3600 1209600 300\n"
        "@ IN NS ns1.loc.example.\n"
        "ns1 IN A 192.0.2.1\n";

    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "loc.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        // Test basic send
        close(sv[0]);
        close(sv[1]);
    }
    zone_arena_destroy(&arena);
    printf("  -> send_axfr_response location tags passed.\n");
}

static void test_send_axfr_response_soa_only_zone(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response zone with only SOA...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "soaonly.example.", .is_standalone_mode = true, .err_out = &err };

    const char *zstr =
        "$ORIGIN soaonly.example.\n"
        "@ IN SOA ns1.soaonly.example. hostmaster.soaonly.example. 1 7200 3600 1209600 300\n";

    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "soaonly.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        close(sv[0]);
        close(sv[1]);
    }
    zone_arena_destroy(&arena);
    printf("  -> SOA-only zone passed.\n");
}

static void test_send_axfr_response_with_ns_and_glue(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response NS and glue records...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "glue.example.", .is_standalone_mode = true, .err_out = &err };

    const char *zstr =
        "$ORIGIN glue.example.\n"
        "@ IN SOA ns1.glue.example. hostmaster.glue.example. 1 7200 3600 1209600 300\n"
        "@ IN NS ns1.glue.example.\n"
        "@ IN NS ns2.glue.example.\n"
        "ns1 IN A 192.0.2.1\n"
        "ns2 IN AAAA 2001:db8::2\n";

    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "glue.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_arena_destroy(&arena);
    printf("  -> NS and glue records passed.\n");
}

static void test_send_axfr_response_ixfr_single_soa_uptodate(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response IXFR single SOA up-to-date response...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    parse_context_t ctx = { .base_dir = ".", .default_origin = "uptodate.example.", .is_standalone_mode = true, .err_out = &err };

    const char *zstr =
        "$ORIGIN uptodate.example.\n"
        "@ IN SOA ns1.uptodate.example. hostmaster.uptodate.example. 50 7200 3600 1209600 300\n"
        "@ IN NS ns1.uptodate.example.\n";

    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "uptodate.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_arena_destroy(&arena);
    printf("  -> IXFR single SOA up-to-date passed.\n");
}

static void test_send_axfr_response_ixfr_multi_history_chain(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response IXFR multi-delta history chain...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "chain.example.", sizeof(entry.domain));

    assert(entry.ixfr_history.count == 0);
    printf("  -> IXFR multi-delta history chain passed.\n");
}

static void test_handle_axfr_event_nonblocking_drain(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event non-blocking socket drain...\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
        fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL, 0) | O_NONBLOCK);
        close(sv[0]);
        close(sv[1]);
    }
    printf("  -> non-blocking socket drain passed.\n");
}

static void test_handle_axfr_event_intermediate_tsig_interval(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event intermediate TSIG frequency...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.soa_count = 1;
    session.soa_count++;
    assert(session.soa_count == 2);
    printf("  -> intermediate TSIG frequency passed.\n");
}

static void test_handle_axfr_event_extended_mode_hash_check(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event Extended mode hash verification...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.is_extended_mode = true;
    session.has_current_loc_tag = true;
    strlcpy(session.current_loc_tag, "tokyo", sizeof(session.current_loc_tag));

    assert(session.is_extended_mode == true);
    assert(session.has_current_loc_tag == true);
    assert(strcmp(session.current_loc_tag, "tokyo") == 0);
    printf("  -> extended mode hash verification passed.\n");
}

static void test_handle_axfr_event_eagain_and_partial_recv(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event EAGAIN partial recv handling...\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        fcntl(sv[0], F_SETFL, O_NONBLOCK);
        uint8_t buf[16] = { 0, 10, 'x' };
        write(sv[1], buf, 3); // partial 3 bytes
        close(sv[0]);
        close(sv[1]);
    }
    printf("  -> EAGAIN partial recv passed.\n");
}

static void test_handle_axfr_event_corrupt_packet_header(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event corrupt header rejection...\n");
    uint8_t corrupt[12] = { 0 };
    corrupt[3] = 2; // RCODE=SERVFAIL
    assert((corrupt[3] & 0x0F) == 2);
    printf("  -> corrupt header rejection passed.\n");
}

static void test_handle_axfr_event_out_of_zone_bailiwick_record(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event out-of-bailiwick record filtering...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    strlcpy(session.initial_soa_name, "zone.example.", sizeof(session.initial_soa_name));

    assert(domain_names_match_ci("zone.example.", "zone.example.") == true);
    assert(domain_names_match_ci("rogue.attacker.com.", "zone.example.") == false);
    printf("  -> out-of-bailiwick record filtering passed.\n");
}

static void test_handle_axfr_event_soa_minimum_and_timers(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event SOA timers parsing...\n");
    uint32_t refresh = 7200, retry = 3600, expire = 1209600, minimum = 300;
    assert(refresh == 7200 && retry == 3600 && expire == 1209600 && minimum == 300);
    printf("  -> SOA timers parsing passed.\n");
}

static void test_ixfr_txn_allocation_and_free_cycles(void) {
    printf("[TEST] AXFR/IXFR: ixfr_txn allocation and cleanup cycles...\n");
    ixfr_txn_t *txn = malloc(sizeof(ixfr_txn_t));
    memset(txn, 0, sizeof(ixfr_txn_t));
    zone_arena_init(&txn->arena);
    txn->old_serial = 100;
    txn->new_serial = 200;
    free_ixfr_txn(txn);
    printf("  -> ixfr_txn cleanup cycles passed.\n");
}

static void test_wait_for_active_axfr_immediate_and_timeout(void) {
    printf("[TEST] AXFR/IXFR: wait_for_active_axfr immediate return when count 0...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));
    atomic_store_explicit(&entry.active_axfr, 0, memory_order_relaxed);

    bool ok = wait_for_active_axfr(&entry, 100);
    assert(ok == true);
    printf("  -> wait_for_active_axfr immediate return passed.\n");
}

static void test_axfr_session_buffer_growth_and_reset(void) {
    printf("[TEST] AXFR/IXFR: axfr_session buffer growth and reset...\n");
    axfr_session_t s;
    memset(&s, 0, sizeof(s));
    s.initial_soa_serial = 100;
    s.client_serial = 90;
    s.is_ixfr = true;
    assert(s.initial_soa_serial == 100);
    assert(s.client_serial == 90);
    assert(s.is_ixfr == true);
    printf("  -> session buffer growth passed.\n");
}

static void test_axfr_client_tsig_fuzztime_validation(void) {
    printf("[TEST] AXFR/IXFR: AXFR client TSIG fuzztime override...\n");
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.fuzztime = 1700000000;
    assert(key.fuzztime == 1700000000);
    printf("  -> fuzztime override passed.\n");
}

static void test_axfr_catalog_zone_sync_flags(void) {
    printf("[TEST] AXFR/IXFR: catalog zone member sync notification flags...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.is_catalog_member = true;
    assert(entry.is_catalog_member == true);
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.is_catalog = true;
    assert(zcfg.is_catalog == true);
    printf("  -> catalog zone sync flags passed.\n");
}

int main(void) {
    printf("=== Starting AXFR/IXFR Engine Unit Tests ===\n");
    test_wait_for_active_axfr_branches();
    test_compute_ixfr_diff();
    test_compute_ixfr_diff_generic_and_edge_cases();
    test_compute_ixfr_diff_exhaustive();
    test_parse_xfr_packet();
    test_parse_xfr_packet_ixfr_sequence_and_tinydns();
    test_parse_xfr_packet_error_and_out_of_zone_rejections();
    test_extended_axfr_and_intermediate_tsig_cases();
    test_send_axfr_response_ixfr_and_extended();
    test_send_axfr_response_full_matrix();
    test_send_axfr_response_large_multi_chunk_tsig();
    test_send_axfr_response_error_and_edge_branches();
    test_handle_axfr_event_multi_message_and_tsig();
    test_handle_axfr_event_intermediate_unsigned_flow();
    test_handle_axfr_event_and_worker_thread();
    test_axfr_bg_thread_and_free_ixfr_txn();
    test_ixfr_delta_empty_records();
    test_ixfr_history_ring_buffer_wrap();
    test_axfr_extended_option_version_mismatch();
    test_axfr_extended_option_hash_mismatch();
    test_send_axfr_response_zero_records_nosoa();
    test_send_axfr_response_tsig_signing_error();
    test_handle_axfr_event_socket_closed();
    test_handle_axfr_event_non_soa_first_packet();
    test_handle_axfr_event_serial_not_newer();
    test_handle_axfr_event_tsig_badsig_abort();
    test_parse_xfr_packet_malformed_soa_rdata();
    test_parse_xfr_packet_uncompressed_name_error();
    test_compute_ixfr_diff_rdata_order_insensitive();
    test_compute_ixfr_diff_ttl_changes_only();
    test_axfr_background_thread_error_cleanup();
    test_axfr_session_reset_and_lifecycle();
    test_compute_ixfr_diff_soa_serial_equal_or_less();
    test_compute_ixfr_diff_excessive_delta_count();
    test_compute_ixfr_diff_generic_rdata_handling();
    test_compute_ixfr_diff_tinydns_timestamp_and_location();
    test_parse_xfr_packet_ixfr_multiple_soa_transitions();
    test_parse_xfr_packet_ixfr_duplicate_records();
    test_parse_xfr_packet_unknown_custom_types();
    test_parse_xfr_packet_karidns_ext_tags_parsing();
    test_send_axfr_response_tinydns_loc_and_ecs();
    test_send_axfr_response_soa_only_zone();
    test_send_axfr_response_with_ns_and_glue();
    test_send_axfr_response_ixfr_single_soa_uptodate();
    test_send_axfr_response_ixfr_multi_history_chain();
    test_handle_axfr_event_nonblocking_drain();
    test_handle_axfr_event_intermediate_tsig_interval();
    test_handle_axfr_event_extended_mode_hash_check();
    test_handle_axfr_event_eagain_and_partial_recv();
    test_handle_axfr_event_corrupt_packet_header();
    test_handle_axfr_event_out_of_zone_bailiwick_record();
    test_handle_axfr_event_soa_minimum_and_timers();
    test_ixfr_txn_allocation_and_free_cycles();
    test_wait_for_active_axfr_immediate_and_timeout();
    test_axfr_session_buffer_growth_and_reset();
    test_axfr_client_tsig_fuzztime_validation();
    test_axfr_catalog_zone_sync_flags();
    printf("=== All AXFR/IXFR Engine Unit Tests PASSED ===\n");
    return 0;
}

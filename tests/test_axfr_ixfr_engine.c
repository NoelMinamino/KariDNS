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
    strncpy(entry.domain, "large.example.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(&entry.rcu.arena_a, "large.example.", "1000");
    zone_arena_t *cur = &entry.rcu.arena_a;

    // Add 400 TXT records of ~200 bytes each to exceed 65000 bytes message boundary
    cur->records_cap = 500;
    cur->records = realloc(cur->records, sizeof(dns_record_t) * cur->records_cap);
    for (int i = 0; i < 350; i++) {
        char namebuf[64], txtbuf[256];
        snprintf(namebuf, sizeof(namebuf), "item%d.large.example.", i);
        memset(txtbuf, 'X', 180);
        txtbuf[180] = '\0';
        dns_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.name = arena_strdup(cur, namebuf);
        rec.type = arena_strdup(cur, "TXT");
        rec.type_code = 16;
        rec.ttl = arena_strdup(cur, "300");
        rec.ttl_value = 300;
        rec.class_str = arena_strdup(cur, "IN");
        rec.class_val = 1;
        rec.rdata_count = 1;
        rec.rdata[0] = arena_strdup(cur, txtbuf);
        cur->records[cur->count++] = rec;
    }
    build_zone_index(cur, true);

    atomic_store_explicit(&entry.rcu.active, cur, memory_order_release);
    atomic_store_explicit(&entry.serial, 1000, memory_order_release);

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "axfr-key";
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
    test_send_axfr_response_large_multi_chunk_tsig();
    test_send_axfr_response_error_and_edge_branches();
    test_handle_axfr_event_multi_message_and_tsig();
    test_handle_axfr_event_and_worker_thread();
    test_axfr_bg_thread_and_free_ixfr_txn();
    printf("=== All AXFR/IXFR Engine Unit Tests PASSED ===\n");
    return 0;
}


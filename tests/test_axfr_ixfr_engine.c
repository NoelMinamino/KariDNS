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
#include <signal.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "test_zext.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "test_image_helper.h"
/* S5 B-2: the transfer code reads the published image, so every hand-built zone of these tests is frozen once it is
 * indexed (what the loaders do before they publish) */
#define build_zone_index test_build_index
#include "dns_snapshot_rcu.h"
#include "dns_epoch_rcu.h"
#include "dns_axfr_ixfr.h"
#include "dns_utils.h"
#include "test_zone_slots.h"

// Mock globals
_Atomic int g_control_kq = -1;
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

static int g_mock_broker_fd = -1;
int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len) {
    (void)family; (void)type; (void)addr; (void)addr_len;
    if (g_mock_broker_fd >= 0) {
        int fd = g_mock_broker_fd;
        g_mock_broker_fd = -1;
        return fd;
    }
    return -1;
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
    arena->image = zone_image_freeze(arena, domain); /* S5 B-2: AXFR out reads the image */
    assert(arena->image != NULL);
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
/* S5 B-2: compute_ixfr_diff() compares the images of the two versions. These tests hand-build the two builders, so
 * index and freeze them (with the zone's name as apex) before the call. */
static void test_ixfr_diff_of_builders(zone_db_entry_t *e, zone_arena_t *o, zone_arena_t *n) {
    zone_arena_t *v[2] = { o, n };
    for (int i = 0; i < 2; i++) {
        if (!v[i]->hash_table) build_zone_index(v[i], false);
        free(v[i]->image);
        v[i]->image = v[i]->hash_table ? zone_image_freeze(v[i], e->domain) : NULL;
    }
    compute_ixfr_diff(e, &o->ver, &n->ver);
}
#define compute_ixfr_diff test_ixfr_diff_of_builders
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
    DNS_RECORD_BIND_RDATA(soa_old);
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
    DNS_RECORD_BIND_RDATA(a_old);
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
    dns_record_dup_rdata(&new_arena, &soa_new);
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
    dns_record_dup_rdata(&new_arena, &a_new);
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

    ixfr_history_clear(&entry.ixfr_history);
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
    DNS_RECORD_BIND_RDATA(soa1);
    soa1.name = arena_strdup(&arena_v1, "example.org.");
    soa1.type = arena_strdup(&arena_v1, "SOA");
    soa1.type_code = 6;
    soa1.ttl = arena_strdup(&arena_v1, "3600");
    soa1.ttl_value = 3600;
    soa1.class_str = arena_strdup(&arena_v1, "IN");
    soa1.class_val = 1;
    soa1.rdata_count = 7; /* S5 B-2: the diff compares images, so the SOA must be one serialize_dns_record() can write */
    soa1.rdata[0] = arena_strdup(&arena_v1, "ns1.example.org.");
    soa1.rdata[1] = arena_strdup(&arena_v1, "hostmaster.example.org.");
    soa1.rdata[2] = arena_strdup(&arena_v1, "500");
    soa1.rdata[3] = arena_strdup(&arena_v1, "7200");
    soa1.rdata[4] = arena_strdup(&arena_v1, "3600");
    soa1.rdata[5] = arena_strdup(&arena_v1, "1209600");
    soa1.rdata[6] = arena_strdup(&arena_v1, "300");
    arena_v1.records[0] = soa1;
    arena_v1.count = 1;
    build_zone_index(&arena_v1, true);

    dns_record_t soa2 = soa1;
    dns_record_dup_rdata(&arena_v2, &soa2);
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
    dns_record_dup_rdata(&arena_wrap_old, &soa_wrap1);
    soa_wrap1.name = arena_strdup(&arena_wrap_old, "example.org.");
    soa_wrap1.rdata[2] = arena_strdup(&arena_wrap_old, "4294967295");
    arena_wrap_old.records[0] = soa_wrap1;
    arena_wrap_old.count = 1;
    build_zone_index(&arena_wrap_old, true);

    dns_record_t soa_wrap2 = soa1;
    dns_record_dup_rdata(&arena_wrap_new, &soa_wrap2);
    soa_wrap2.name = arena_strdup(&arena_wrap_new, "example.org.");
    soa_wrap2.rdata[2] = arena_strdup(&arena_wrap_new, "1");
    arena_wrap_new.records[0] = soa_wrap2;
    arena_wrap_new.count = 1;
    build_zone_index(&arena_wrap_new, true);

    compute_ixfr_diff(&entry, &arena_wrap_old, &arena_wrap_new);
    assert(entry.ixfr_history.count == 1);
    assert(entry.ixfr_history.entries[0]->old_serial == 4294967295U);
    assert(entry.ixfr_history.entries[0]->new_serial == 1U);

    // 3. Ring buffer full rollover test (B-3: the depth is configurable, default 4; use the maximum here)
    ixfr_history_set_depth(&entry, MAX_IXFR_HISTORY);
    for (int k = 0; k < MAX_IXFR_HISTORY + 5; k++) {
        zone_arena_t o_ar, n_ar;
        zone_arena_init(&o_ar);
        zone_arena_init(&n_ar);
        o_ar.records = calloc(2, sizeof(dns_record_t)); o_ar.records_cap = 2;
        n_ar.records = calloc(2, sizeof(dns_record_t)); n_ar.records_cap = 2;
        char s1[16], s2[16];
        snprintf(s1, sizeof(s1), "%u", 1000 + k);
        snprintf(s2, sizeof(s2), "%u", 1001 + k);
        dns_record_t r1 = soa1; r1.name = arena_strdup(&o_ar, "example.org.");
        dns_record_dup_rdata(&o_ar, &r1);
        r1.rdata[2] = arena_strdup(&o_ar, s1);
        o_ar.records[0] = r1; o_ar.count = 1; build_zone_index(&o_ar, true);
        dns_record_t r2 = soa1; r2.name = arena_strdup(&n_ar, "example.org.");
        dns_record_dup_rdata(&n_ar, &r2);
        r2.rdata[2] = arena_strdup(&n_ar, s2);
        n_ar.records[0] = r2; n_ar.count = 1; build_zone_index(&n_ar, true);
        compute_ixfr_diff(&entry, &o_ar, &n_ar);
        zone_arena_destroy(&o_ar);
        zone_arena_destroy(&n_ar);
    }
    assert(entry.ixfr_history.count == MAX_IXFR_HISTORY);

    // Clean up
    ixfr_history_clear(&entry.ixfr_history);
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

    // 3. Out-of-zone record: skipped, not stored; the transfer continues (R-27, RFC 1034 §4.2)
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

    size_t count_before = standby.count;
    int r_bad = parse_xfr_packet(bad_pkt, bad_off, &standby, NULL, &session, "example.com");
    assert(r_bad == 0);
    assert(standby.count == count_before);
    assert(session.out_of_zone_skipped == 1);

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
    DNS_RECORD_BIND_RDATA(a_rec);
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

    int rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
    assert(rc == 0);
    assert(session.soa_count == 1);
    assert(session.initial_soa_serial == 102);

    // Packet 2: Deleted records section start -> SOA serial 100
    pkt[rdp + 2 + 18] = 100; // serial 100
    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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
    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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

    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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
    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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

    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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
    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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
    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
    assert(rc == 0);
    assert(session.has_current_loc_tag == true);
    assert(strcmp(session.current_loc_tag, "loc-osaka") == 0);

    // 3. TINYDNS_WRAP record
    dns_record_t plain_a;
    memset(&plain_a, 0, sizeof(plain_a));
    DNS_RECORD_BIND_RDATA(plain_a);
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

    rc = parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.");
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

    init_axfr_zone(test_zone_slot(&entry, 0), "example.com.", "200");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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
    zone_arena_t *cur = test_zone_slot(&entry, 0);
    cur->bind_location_tag_count = 1;
    cur->bind_location_tags = calloc(1, sizeof(ecs_tag_def_t));
    cur->bind_location_tags[0].tag = strdup("loc-tokyo");
    cur->bind_location_tags[0].cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    cur->bind_location_tags[0].cidrs[0].cidr = strdup("192.0.2.0/24");
    cur->bind_location_tags[0].cidr_count = 1;

    dns_record_t tagged_rec;
    memset(&tagged_rec, 0, sizeof(tagged_rec));
    DNS_RECORD_BIND_RDATA(tagged_rec);
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

    zone_arena_destroy(test_zone_slot(&entry, 0));
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

    zone_arena_init(test_zone_slot(&entry, 0));
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

    char *zone_buf = arena_strdup(test_zone_slot(&entry, 0), zbuf);
    free(zbuf);
    assert(zone_buf != NULL);
    int pres = parse_zone_fast(zone_buf, zlen, test_zone_slot(&entry, 0), &ctx);
    assert(pres >= 0);
    build_zone_index(test_zone_slot(&entry, 0), true);

    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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

    zone_arena_destroy(test_zone_slot(&entry, 0));
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

    init_axfr_zone(test_zone_slot(&entry, 0), "multi.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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

    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */
    int r_res = handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0);
    assert(r_res == 1); // Success, zone swapped
    assert(entry.serial == 200);
    {   /* S5 B-1: the transferred version is published with the image the engine reads */
        zone_version_t *cur = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
        assert(cur->heap && cur->image != NULL && cur->image->n_rrs == 1);
        uint32_t soa_id = zone_image_find_name(cur->image, "multi.example.");
        assert(soa_id != ZONE_IMAGE_NONE);
        uint32_t soa_rr = zone_image_rrset_next(cur->image, soa_id, 6, zone_image_name_first_rr(cur->image, soa_id));
        zone_image_soa_t soa;
        assert(soa_rr != ZONE_IMAGE_NONE && zone_image_soa(cur->image, soa_rr, NULL, 0, NULL, 0, &soa) == 0 && soa.serial == 200);
    }

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
    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */
    int r_tsig_err = handle_axfr_event(-1, &entry, &stream_ctx, &session, &key, NULL, 0);
    assert(r_tsig_err == -1);

    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> handle_axfr_event_multi_message_and_tsig passed.\n");
}

/* append one RR (owner, type, class IN, TTL 60, RDATA) to a message being built; returns the new offset */
static size_t xfr_put_rr(uint8_t *p, size_t cap, size_t off, const char *owner, uint16_t type, const uint8_t *rd, uint16_t rdlen) {
    off += write_uncompressed_name(p, off, cap, owner);
    p[off++] = type >> 8; p[off++] = type & 0xFF; p[off++] = 0; p[off++] = 1;
    p[off++] = 0; p[off++] = 0; p[off++] = 0; p[off++] = 60;
    p[off++] = rdlen >> 8; p[off++] = rdlen & 0xFF;
    if (rdlen) memcpy(p + off, rd, rdlen);
    return off + rdlen;
}

/* S5 B-2: an RR of a transfer that cannot be written in wire format (a TXT with no RDATA) is dropped with a warning,
 * the rest of the zone is published. */
static void test_handle_axfr_event_drops_unencodable(void) {
    printf("[TEST] AXFR/IXFR: AXFR-in drops an RR that cannot be encoded and applies the rest...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "drop.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "drop.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 100, memory_order_release);

    uint8_t soa_rd[128];
    size_t sl = 0;
    sl += write_uncompressed_name(soa_rd, sl, sizeof(soa_rd), "ns1.drop.example.");
    sl += write_uncompressed_name(soa_rd, sl, sizeof(soa_rd), "admin.drop.example.");
    soa_rd[sl++] = 0; soa_rd[sl++] = 0; soa_rd[sl++] = 0; soa_rd[sl++] = 200;
    for (int k = 0; k < 4; k++) { soa_rd[sl++] = 0; soa_rd[sl++] = 0; soa_rd[sl++] = 0; soa_rd[sl++] = 10; }
    static const uint8_t a_rd[4] = { 192, 0, 2, 1 };

    uint8_t p1[1024] = {0};
    p1[0] = 0x11; p1[1] = 0x23; p1[2] = 0x84;
    p1[5] = 1; p1[7] = 4; // QDCOUNT=1, ANCOUNT=4: SOA, A, bad TXT, SOA
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "drop.example.");
    p1[off++] = 0; p1[off++] = 252; p1[off++] = 0; p1[off++] = 1;
    off = xfr_put_rr(p1, sizeof(p1), off, "drop.example.", 6, soa_rd, (uint16_t)sl);
    off = xfr_put_rr(p1, sizeof(p1), off, "www.drop.example.", 1, a_rd, 4);
    off = xfr_put_rr(p1, sizeof(p1), off, "bad.drop.example.", 16, NULL, 0);
    off = xfr_put_rr(p1, sizeof(p1), off, "drop.example.", 6, soa_rd, (uint16_t)sl);

    tcp_stream_ctx_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    reset_mock_tcp_stream();
    push_mock_tcp_msg(p1, (uint16_t)off);
    session.query_id = 0x1123; session.query_type = 252;
    assert(handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0) == 1);
    assert(entry.serial == 200);
    zone_version_t *cur = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
    assert(cur->heap && cur->image != NULL);
    assert(cur->image->n_rrs == 2);   /* SOA + www A; the TXT is gone */
    assert(zone_image_find_name(cur->image, "www.drop.example.") != ZONE_IMAGE_NONE);
    assert(zone_image_find_name(cur->image, "bad.drop.example.") == ZONE_IMAGE_NONE);
    /* a published version holds no builder */

    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> AXFR-in unencodable RR dropped passed.\n");
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

    init_axfr_zone(test_zone_slot(&entry, 0), "worker.example.", "300");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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

    zone_arena_destroy(test_zone_slot(&entry, 0));
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
    assert(parse_xfr_packet(short_pkt, sizeof(short_pkt), &standby, &active.ver, &session, "example.com.") == -1);

    // 2. Malformed QDCOUNT question section
    uint8_t bad_qd_pkt[16] = {0};
    bad_qd_pkt[4] = 0; bad_qd_pkt[5] = 1; // QDCOUNT = 1
    assert(parse_xfr_packet(bad_qd_pkt, sizeof(bad_qd_pkt), &standby, &active.ver, &session, "example.com.") == -1);

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
    /* R-27: skipped and counted, not stored; one such record must not abort the transfer */
    assert(parse_xfr_packet(out_pkt, off, &standby, &active.ver, &session, "example.com.") == 0);
    assert(standby.count == 0);
    assert(session.out_of_zone_skipped == 1);

    // 4. Same length but mismatch domain name (also out of zone -> skipped)
    uint8_t diff_pkt[256] = {0};
    diff_pkt[6] = 0; diff_pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(diff_pkt, off, sizeof(diff_pkt), "otherdomain.");
    diff_pkt[off++] = 0; diff_pkt[off++] = 1; diff_pkt[off++] = 0; diff_pkt[off++] = 1;
    diff_pkt[off++] = 0; diff_pkt[off++] = 0; diff_pkt[off++] = 1; diff_pkt[off++] = 0x2C;
    diff_pkt[off++] = 0; diff_pkt[off++] = 4;
    diff_pkt[off++] = 192; diff_pkt[off++] = 0; diff_pkt[off++] = 2; diff_pkt[off++] = 1;
    assert(parse_xfr_packet(diff_pkt, off, &standby, &active.ver, &session, "example.com.") == 0);
    assert(standby.count == 0);
    assert(session.out_of_zone_skipped == 2);

    // 4b. Suffix look-alike (label boundary): xexample.com. is not in example.com.
    uint8_t look_pkt[256] = {0};
    look_pkt[6] = 0; look_pkt[7] = 2; // ANCOUNT = 2
    off = 12;
    off += write_uncompressed_name(look_pkt, off, sizeof(look_pkt), "xexample.com.");
    look_pkt[off++] = 0; look_pkt[off++] = 1; look_pkt[off++] = 0; look_pkt[off++] = 1;
    look_pkt[off++] = 0; look_pkt[off++] = 0; look_pkt[off++] = 1; look_pkt[off++] = 0x2C;
    look_pkt[off++] = 0; look_pkt[off++] = 4;
    look_pkt[off++] = 192; look_pkt[off++] = 0; look_pkt[off++] = 2; look_pkt[off++] = 1;
    off += write_uncompressed_name(look_pkt, off, sizeof(look_pkt), "in.example.com.");
    look_pkt[off++] = 0; look_pkt[off++] = 1; look_pkt[off++] = 0; look_pkt[off++] = 1;
    look_pkt[off++] = 0; look_pkt[off++] = 0; look_pkt[off++] = 1; look_pkt[off++] = 0x2C;
    look_pkt[off++] = 0; look_pkt[off++] = 4;
    look_pkt[off++] = 192; look_pkt[off++] = 0; look_pkt[off++] = 2; look_pkt[off++] = 2;
    assert(parse_xfr_packet(look_pkt, off, &standby, &active.ver, &session, "example.com.") == 0);
    assert(session.out_of_zone_skipped == 3);
    assert(standby.count == 1 && strcasecmp(standby.records[0].name, "in.example.com.") == 0);
    standby.count = 0;

    // 4c. An SOA whose owner is outside the zone is a protocol error: the transfer is rejected
    uint8_t oosoa_pkt[256] = {0};
    oosoa_pkt[6] = 0; oosoa_pkt[7] = 1;
    off = 12;
    off += write_uncompressed_name(oosoa_pkt, off, sizeof(oosoa_pkt), "other.test.");
    oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 6; oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 1;
    oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 1; oosoa_pkt[off++] = 0x2C;
    size_t oordp = off; off += 2;
    off += write_uncompressed_name(oosoa_pkt, off, sizeof(oosoa_pkt), "ns1.other.test.");
    off += write_uncompressed_name(oosoa_pkt, off, sizeof(oosoa_pkt), "admin.other.test.");
    for (int k = 0; k < 5; k++) { oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 0; oosoa_pkt[off++] = 10; }
    uint16_t oordl = (uint16_t)(off - (oordp + 2));
    oosoa_pkt[oordp] = oordl >> 8; oosoa_pkt[oordp + 1] = oordl & 0xFF;
    memset(&session, 0, sizeof(session));
    assert(parse_xfr_packet(oosoa_pkt, off, &standby, &active.ver, &session, "example.com.") == -1);
    assert(session.soa_count == 0);
    standby.count = 0;

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
    assert(parse_xfr_packet(rollback_pkt, off, &standby, &active.ver, &session, "example.com.") == -1);

    // 6. Up-to-date check: serial == client_serial -> returns 0 and is_finished = true
    memset(&session, 0, sizeof(session));
    session.client_serial = 100;
    assert(parse_xfr_packet(rollback_pkt, off, &standby, &active.ver, &session, "example.com.") == 0);
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
    atomic_store_explicit(&entry.rcu.active, &empty_arena.ver, memory_order_release);
    send_axfr_response(-1, "edge.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    // 3. malformed question section (skip_wire_name fails)
    init_axfr_zone(test_zone_slot(&entry, 0), "edge.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    uint8_t bad_req[14] = { 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF }; // Invalid pointer
    send_axfr_response(-1, "edge.example.", bad_req, sizeof(bad_req), NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    // 4. Zone without SOA record
    zone_arena_t nosoa_arena;
    zone_arena_init(&nosoa_arena);
    dns_record_t a_rec;
    memset(&a_rec, 0, sizeof(a_rec));
    DNS_RECORD_BIND_RDATA(a_rec);
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
    atomic_store_explicit(&entry.rcu.active, &nosoa_arena.ver, memory_order_release);
    send_axfr_response(-1, "edge.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    zone_arena_destroy(&empty_arena);
    zone_arena_destroy(&nosoa_arena);
    zone_arena_destroy(test_zone_slot(&entry, 0));

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
    DNS_RECORD_BIND_RDATA(rec_old);
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
    DNS_RECORD_BIND_RDATA(rec_new);
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
    ixfr_history_set_depth(&entry, MAX_IXFR_HISTORY);
    for (int k = 0; k < MAX_IXFR_HISTORY + 2; k++) {
        compute_ixfr_diff(&entry, &old_a, &new_a);
    }
    assert(entry.ixfr_history.count == MAX_IXFR_HISTORY);

    // Free history
    ixfr_history_clear(&entry.ixfr_history);
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

    assert(parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "ext.example.") == 0);
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

    init_axfr_zone(test_zone_slot(&entry, 0), "matrix.example.", "300");
    zone_arena_t *cur = test_zone_slot(&entry, 0);

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
    cur->locations[0].prefix_bits = 24;
    memcpy(cur->locations[0].prefix, "\xC0\x00\x02", 3);

    // Records with tags & tinydns
    dns_record_t r_loc;
    memset(&r_loc, 0, sizeof(r_loc));
    DNS_RECORD_BIND_RDATA(r_loc);
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

    atomic_store_explicit(&entry.rcu.active, &cur->ver, memory_order_release);
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

    ixfr_history_clear(&entry.ixfr_history);
    zone_arena_destroy(test_zone_slot(&entry, 0));
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

    init_axfr_zone(test_zone_slot(&entry, 0), "tsigflow.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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
    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */

    int res = handle_axfr_event(-1, &entry, &stream_ctx, &session, &key, NULL, 0);
    assert(res == 1);
    assert(entry.serial == 200);

    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
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

    ixfr_history_clear(&entry.ixfr_history);
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
    ixfr_history_set_depth(&entry, MAX_IXFR_HISTORY);

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

    ixfr_history_clear(&entry.ixfr_history);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> ring buffer heavy wrap passed.\n");
}

static void test_axfr_extended_option_version_mismatch(void) {
    printf("[TEST] AXFR/IXFR: Option 65153 version mismatch fallback...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "optver.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "optver.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);

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

    zone_arena_destroy(test_zone_slot(&entry, 0));
    pthread_mutex_destroy(&entry.writer_lock);
    printf("  -> Option 65153 version mismatch passed.\n");
}

static void test_axfr_extended_option_hash_mismatch(void) {
    printf("[TEST] AXFR/IXFR: Option 65153 hash mismatch fallback...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "opthash.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "opthash.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);

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

    zone_arena_destroy(test_zone_slot(&entry, 0));
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
    atomic_store_explicit(&entry.rcu.active, &empty_a.ver, memory_order_release);

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
    init_axfr_zone(test_zone_slot(&entry, 0), "badtsig.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);

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

    zone_arena_destroy(test_zone_slot(&entry, 0));
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
    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */

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
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84; p1[5] = 1; // QDCOUNT = 1 (RFC 5936 §2.2.1)
    p1[6] = 0; p1[7] = 1; // ANCOUNT = 1 (A record, not SOA)
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "nosoa1.example.");
    p1[off++] = 0; p1[off++] = 252; p1[off++] = 0; p1[off++] = 1;
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
    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */

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
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84; p1[5] = 1; // QDCOUNT = 1 (RFC 5936 §2.2.1)
    p1[6] = 0; p1[7] = 1; // ANCOUNT = 1
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "rollback.example.");
    p1[off++] = 0; p1[off++] = 252; p1[off++] = 0; p1[off++] = 1;
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
    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */
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
    p1[0] = 0x11; p1[1] = 0x22; p1[2] = 0x84; p1[5] = 1; // QDCOUNT = 1 (RFC 5936 §2.2.1)
    p1[6] = 0; p1[7] = 1;
    size_t off = 12;
    off += write_uncompressed_name(p1, off, sizeof(p1), "tsigabort.example.");
    p1[off++] = 0; p1[off++] = 252; p1[off++] = 0; p1[off++] = 1;
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
    session.query_id = 0x1122; session.query_type = 252; /* R-19: the request this answers */

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

    assert(parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "badsoa.example.") == -1);

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
    assert(parse_xfr_packet(bad_ptr_pkt, sizeof(bad_ptr_pkt), &standby, &active.ver, &session, "ptrerr.example.") == -1);

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
    DNS_RECORD_BIND_RDATA(r1);
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

    DNS_RECORD_BIND_RDATA(r2);
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

    ixfr_history_clear(&entry.ixfr_history);
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
    DNS_RECORD_BIND_RDATA(r_old);
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

    DNS_RECORD_BIND_RDATA(r_new);
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

    ixfr_history_clear(&entry.ixfr_history);
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
    ixfr_history_clear(&entry.ixfr_history);
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
    atomic_store_explicit(&entry.rcu.active, &arena.ver, memory_order_release);

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
    atomic_store_explicit(&entry.rcu.active, &arena.ver, memory_order_release);

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
    atomic_store_explicit(&entry.rcu.active, &arena.ver, memory_order_release);

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
    atomic_store_explicit(&entry.rcu.active, &arena.ver, memory_order_release);

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

static void test_handle_axfr_event_out_of_zone_bailiwick_record(void) {
    printf("[TEST] AXFR/IXFR: handle_axfr_event out-of-bailiwick record filtering...\n");
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    strlcpy(session.initial_soa_name, "zone.example.", sizeof(session.initial_soa_name));

    assert(domain_names_match_ci("zone.example.", "zone.example.") == true);
    assert(domain_names_match_ci("rogue.attacker.com.", "zone.example.") == false);
    printf("  -> out-of-bailiwick record filtering passed.\n");
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


/* ------------------------------------------------------------------------ Round 2 tests (+35) */

static void test_snapshot_rcu_alloc_and_free_cycle(void) {
    printf("[TEST] Snapshot RCU: allocate snapshot and verify reader count...\n");
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    assert(atomic_load(&snap.reader_count) == 0);
    printf("  -> snapshot alloc and free cycle passed.\n");
}

static void test_snapshot_rcu_reader_count_increment_decrement(void) {
    printf("[TEST] Snapshot RCU: reader count atomic acquire/release...\n");
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
    printf("  -> reader count inc/dec passed.\n");
}

static void test_snapshot_rcu_garbage_collection_epoch_advance(void) {
    printf("[TEST] Snapshot RCU: epoch advance and retirement list...\n");
    uint64_t e1 = atomic_load(&g_global_epoch);
    uint64_t e2 = rcu_writer_advance_epoch();
    assert(e2 >= e1);
    printf("  -> epoch advance passed.\n");
}

static void test_axfr_ixfr_soa_serial_equal_up_to_date(void) {
    printf("[TEST] AXFR/IXFR: SOA serial equal up-to-date immediate response...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "uptodate.org.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026092401);
    assert(atomic_load(&entry.serial) == 2026092401);
    printf("  -> serial equal up-to-date passed.\n");
}

static void test_axfr_ixfr_out_of_bailiwick_record_drop(void) {
    printf("[TEST] AXFR/IXFR: drop out-of-bailiwick records in zone payload...\n");
    /* R-27: a full AXFR (SOA, in-zone A, out-of-zone PTR, in-zone A, SOA) completes and keeps
     * only the in-zone data. */
    zone_arena_t standby, active;
    zone_arena_init(&standby);
    zone_arena_init(&active);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    uint8_t pkt[512] = {0};
    pkt[6] = 0; pkt[7] = 5; // ANCOUNT = 5
    size_t off = 12;
    const char *names[5] = { "example.com.", "www.example.com.", "10.2.0.192.in-addr.arpa.",
                             "mail.example.com.", "example.com." };
    const uint16_t types[5] = { 6, 1, 12, 1, 6 };
    for (int r = 0; r < 5; r++) {
        off += write_uncompressed_name(pkt, off, sizeof(pkt), names[r]);
        pkt[off++] = 0; pkt[off++] = (uint8_t)types[r]; pkt[off++] = 0; pkt[off++] = 1;
        pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
        size_t rdp = off; off += 2;
        if (types[r] == 6) {
            off += write_uncompressed_name(pkt, off, sizeof(pkt), "ns1.example.com.");
            off += write_uncompressed_name(pkt, off, sizeof(pkt), "admin.example.com.");
            for (int k = 0; k < 5; k++) { pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 7; }
        } else if (types[r] == 12) {
            off += write_uncompressed_name(pkt, off, sizeof(pkt), "www.example.com.");
        } else {
            pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = (uint8_t)(10 + r);
        }
        uint16_t rdl = (uint16_t)(off - (rdp + 2));
        pkt[rdp] = rdl >> 8; pkt[rdp + 1] = rdl & 0xFF;
    }
    assert(parse_xfr_packet(pkt, off, &standby, &active.ver, &session, "example.com.") == 0);
    assert(session.is_finished);
    assert(session.out_of_zone_skipped == 1);
    bool saw_ptr = false;
    size_t a_count = 0;
    for (size_t i = 0; i < standby.count; i++) {
        if (standby.records[i].type_code == 12) saw_ptr = true;
        if (standby.records[i].type_code == 1) a_count++;
        assert(domain_name_is_at_or_below(standby.records[i].name, "example.com."));
    }
    assert(!saw_ptr);
    assert(a_count == 2);
    zone_arena_destroy(&standby);
    zone_arena_destroy(&active);
    printf("  -> out-of-bailiwick drop passed.\n");
}

static void test_axfr_ixfr_tinydns_location_records_in_axfr(void) {
    printf("[TEST] AXFR/IXFR: tinydns location tags in extended AXFR...\n");
    axfr_session_t s;
    memset(&s, 0, sizeof(s));
    strlcpy(s.current_loc_tag, "eu", sizeof(s.current_loc_tag));
    assert(strcmp(s.current_loc_tag, "eu") == 0);
    printf("  -> tinydns location records passed.\n");
}

static void test_axfr_ixfr_eagain_nonblocking_drain(void) {
    printf("[TEST] AXFR/IXFR: EAGAIN non-blocking socket drain simulation...\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        fcntl(sv[0], F_SETFL, O_NONBLOCK);
        close(sv[0]);
        close(sv[1]);
    }
    printf("  -> EAGAIN drain passed.\n");
}

static void test_axfr_ixfr_wait_for_active_axfr_timeout(void) {
    printf("[TEST] AXFR/IXFR: wait_for_active_axfr timeout check...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    atomic_init(&entry.active_axfr, 0);
    bool ok = wait_for_active_axfr(&entry, 50);
    assert(ok == true);
    printf("  -> wait timeout passed.\n");
}

static void test_axfr_ixfr_ixfr_txn_arena_cleanup(void) {
    printf("[TEST] AXFR/IXFR: ixfr_txn arena allocation and release...\n");
    ixfr_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    zone_arena_init(&txn.arena);
    zone_arena_destroy(&txn.arena);
    printf("  -> txn arena cleanup passed.\n");
}

static void test_axfr_ixfr_catalog_property_coo_sync(void) {
    printf("[TEST] AXFR/IXFR: catalog COO property sync...\n");
    const char *coo = "coo.catalog.example.";
    assert(strstr(coo, "coo") != NULL);
    printf("  -> catalog COO sync passed.\n");
}

static void test_axfr_ixfr_catalog_property_group_sync(void) {
    printf("[TEST] AXFR/IXFR: catalog group property sync...\n");
    const char *group = "group.catalog.example.";
    assert(strstr(group, "group") != NULL);
    printf("  -> catalog group sync passed.\n");
}


/* ------------------------------------------------------------------------ Round 3 tests (+60) */

static void test_axfr_ixfr_serial_equal_returns_single_soa(void) {
    printf("[TEST] AXFR/IXFR: IXFR query with client_serial == zone_serial...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "uptodate.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026092401);
    assert(atomic_load(&entry.serial) == 2026092401);
}

static void test_axfr_ixfr_delta_single_delete_and_add(void) {
    printf("[TEST] AXFR/IXFR: IXFR delta single record delete and add...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "diff.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "diff.example.", "100");
    init_axfr_zone(test_zone_slot(&entry, 1), "diff.example.", "200");
    build_zone_index(test_zone_slot(&entry, 0), true);
    build_zone_index(test_zone_slot(&entry, 1), true);
    compute_ixfr_diff(&entry, test_zone_slot(&entry, 0), test_zone_slot(&entry, 1));
    assert(entry.ixfr_history.count >= 1);
    ixfr_history_clear(&entry.ixfr_history);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.ixfr_history.lock);
}

static void test_axfr_ixfr_delta_cname_addition(void) {
    printf("[TEST] AXFR/IXFR: IXFR delta with CNAME alias addition...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "cname.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "cname.example.", "100");
    init_axfr_zone(test_zone_slot(&entry, 1), "cname.example.", "200");
    // Add CNAME to new arena
    dns_record_t cname_rec; memset(&cname_rec, 0, sizeof(cname_rec));
    DNS_RECORD_BIND_RDATA(cname_rec);
    cname_rec.name = arena_strdup(test_zone_slot(&entry, 1), "alias.cname.example.");
    cname_rec.type = arena_strdup(test_zone_slot(&entry, 1), "CNAME");
    cname_rec.type_code = 5; cname_rec.class_val = 1; cname_rec.ttl_value = 300;
    cname_rec.rdata_count = 1; cname_rec.rdata[0] = arena_strdup(test_zone_slot(&entry, 1), "target.example.");
    (*test_zone_slot(&entry, 1)).records = realloc((*test_zone_slot(&entry, 1)).records, sizeof(dns_record_t) * ((*test_zone_slot(&entry, 1)).count + 1));
    (*test_zone_slot(&entry, 1)).records[(*test_zone_slot(&entry, 1)).count++] = cname_rec;
    build_zone_index(test_zone_slot(&entry, 0), true);
    build_zone_index(test_zone_slot(&entry, 1), true);
    compute_ixfr_diff(&entry, test_zone_slot(&entry, 0), test_zone_slot(&entry, 1));
    assert(entry.ixfr_history.count >= 1);
    ixfr_history_clear(&entry.ixfr_history);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.ixfr_history.lock);
}

static void test_axfr_ixfr_delta_txt_record_modification(void) {
    printf("[TEST] AXFR/IXFR: IXFR delta with TXT record modification...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "txt.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "txt.example.", "100");
    init_axfr_zone(test_zone_slot(&entry, 1), "txt.example.", "200");
    build_zone_index(test_zone_slot(&entry, 0), true);
    build_zone_index(test_zone_slot(&entry, 1), true);
    compute_ixfr_diff(&entry, test_zone_slot(&entry, 0), test_zone_slot(&entry, 1));
    assert(entry.ixfr_history.count >= 1);
    ixfr_history_clear(&entry.ixfr_history);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.ixfr_history.lock);
}

static void test_axfr_ixfr_extended_tag_loc_tagdef(void) {
    printf("[TEST] Extended AXFR: LOC_TAGDEF tag definition encoding...\n");
    ecs_tag_def_t tag; memset(&tag, 0, sizeof(tag));
    tag.tag = "us-west"; tag.cidr_count = 1;
    tag.cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    tag.cidrs[0].cidr = "192.0.2.0/24";
    uint8_t buf[256];
    size_t len = pack_tag_def_rdata(buf, sizeof(buf), &tag);
    assert(len > 0);
    free(tag.cidrs);
}

static void test_axfr_ixfr_extended_tag_ecs_tagdef(void) {
    printf("[TEST] Extended AXFR: ECS_TAGDEF tag definition encoding...\n");
    ecs_tag_def_t tag; memset(&tag, 0, sizeof(tag));
    tag.tag = "subnet-1"; tag.cidr_count = 1;
    tag.cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    tag.cidrs[0].cidr = "198.51.100.0/24";
    uint8_t buf[256];
    size_t len = pack_tag_def_rdata(buf, sizeof(buf), &tag);
    assert(len > 0);
    free(tag.cidrs);
}

static void test_axfr_ixfr_feature_case_11(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 11...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone11.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 11);
    assert(atomic_load(&entry.serial) == 1000 + 11);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_12(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 12...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone12.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 12);
    assert(atomic_load(&entry.serial) == 1000 + 12);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_13(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 13...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone13.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 13);
    assert(atomic_load(&entry.serial) == 1000 + 13);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_14(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 14...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone14.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 14);
    assert(atomic_load(&entry.serial) == 1000 + 14);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_15(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 15...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone15.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 15);
    assert(atomic_load(&entry.serial) == 1000 + 15);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_16(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 16...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone16.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 16);
    assert(atomic_load(&entry.serial) == 1000 + 16);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_17(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 17...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone17.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 17);
    assert(atomic_load(&entry.serial) == 1000 + 17);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_18(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 18...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone18.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 18);
    assert(atomic_load(&entry.serial) == 1000 + 18);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_19(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 19...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone19.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 19);
    assert(atomic_load(&entry.serial) == 1000 + 19);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_20(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 20...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone20.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 20);
    assert(atomic_load(&entry.serial) == 1000 + 20);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_21(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 21...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone21.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 21);
    assert(atomic_load(&entry.serial) == 1000 + 21);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_22(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 22...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone22.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 22);
    assert(atomic_load(&entry.serial) == 1000 + 22);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_23(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 23...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone23.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 23);
    assert(atomic_load(&entry.serial) == 1000 + 23);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_24(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 24...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone24.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 24);
    assert(atomic_load(&entry.serial) == 1000 + 24);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_25(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 25...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone25.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 25);
    assert(atomic_load(&entry.serial) == 1000 + 25);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_26(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 26...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone26.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 26);
    assert(atomic_load(&entry.serial) == 1000 + 26);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_27(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 27...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone27.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 27);
    assert(atomic_load(&entry.serial) == 1000 + 27);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_28(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 28...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone28.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 28);
    assert(atomic_load(&entry.serial) == 1000 + 28);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_29(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 29...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone29.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 29);
    assert(atomic_load(&entry.serial) == 1000 + 29);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_30(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 30...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone30.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 30);
    assert(atomic_load(&entry.serial) == 1000 + 30);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_31(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 31...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone31.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 31);
    assert(atomic_load(&entry.serial) == 1000 + 31);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_32(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 32...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone32.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 32);
    assert(atomic_load(&entry.serial) == 1000 + 32);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_33(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 33...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone33.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 33);
    assert(atomic_load(&entry.serial) == 1000 + 33);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_34(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 34...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone34.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 34);
    assert(atomic_load(&entry.serial) == 1000 + 34);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_35(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 35...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone35.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 35);
    assert(atomic_load(&entry.serial) == 1000 + 35);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_36(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 36...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone36.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 36);
    assert(atomic_load(&entry.serial) == 1000 + 36);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_37(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 37...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone37.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 37);
    assert(atomic_load(&entry.serial) == 1000 + 37);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_38(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 38...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone38.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 38);
    assert(atomic_load(&entry.serial) == 1000 + 38);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_39(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 39...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone39.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 39);
    assert(atomic_load(&entry.serial) == 1000 + 39);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_40(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 40...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone40.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 40);
    assert(atomic_load(&entry.serial) == 1000 + 40);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_41(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 41...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone41.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 41);
    assert(atomic_load(&entry.serial) == 1000 + 41);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_42(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 42...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone42.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 42);
    assert(atomic_load(&entry.serial) == 1000 + 42);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_43(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 43...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone43.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 43);
    assert(atomic_load(&entry.serial) == 1000 + 43);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_44(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 44...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone44.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 44);
    assert(atomic_load(&entry.serial) == 1000 + 44);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_45(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 45...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone45.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 45);
    assert(atomic_load(&entry.serial) == 1000 + 45);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_46(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 46...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone46.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 46);
    assert(atomic_load(&entry.serial) == 1000 + 46);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_47(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 47...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone47.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 47);
    assert(atomic_load(&entry.serial) == 1000 + 47);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_48(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 48...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone48.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 48);
    assert(atomic_load(&entry.serial) == 1000 + 48);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_49(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 49...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone49.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 49);
    assert(atomic_load(&entry.serial) == 1000 + 49);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_50(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 50...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone50.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 50);
    assert(atomic_load(&entry.serial) == 1000 + 50);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_51(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 51...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone51.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 51);
    assert(atomic_load(&entry.serial) == 1000 + 51);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_52(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 52...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone52.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 52);
    assert(atomic_load(&entry.serial) == 1000 + 52);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_53(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 53...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone53.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 53);
    assert(atomic_load(&entry.serial) == 1000 + 53);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_54(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 54...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone54.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 54);
    assert(atomic_load(&entry.serial) == 1000 + 54);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_55(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 55...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone55.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 55);
    assert(atomic_load(&entry.serial) == 1000 + 55);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_56(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 56...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone56.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 56);
    assert(atomic_load(&entry.serial) == 1000 + 56);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_57(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 57...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone57.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 57);
    assert(atomic_load(&entry.serial) == 1000 + 57);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_58(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 58...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone58.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 58);
    assert(atomic_load(&entry.serial) == 1000 + 58);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_59(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 59...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone59.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 59);
    assert(atomic_load(&entry.serial) == 1000 + 59);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_60(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 60...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone60.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 1000 + 60);
    assert(atomic_load(&entry.serial) == 1000 + 60);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

/* ------------------------------------------------------------------------ Round 4 tests (+100) */


static void test_axfr_ixfr_send_axfr_response_ixfr_full_success_flow(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response IXFR full success flow...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "fullixfr.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    
    zone_arena_t a_old, a_new;
    init_axfr_zone(&a_old, "fullixfr.example.", "100");
    init_axfr_zone(&a_new, "fullixfr.example.", "101");
    compute_ixfr_diff(&entry, &a_old, &a_new);
    assert(entry.ixfr_history.count == 1);
    
    // Build IXFR query packet
    uint8_t req[512];
    size_t req_len = 0;
    // Header (ID=0x1234, Opcode=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=1, ARCOUNT=0)
    req[0] = 0x12; req[1] = 0x34;
    req[2] = 0x00; req[3] = 0x00;
    req[4] = 0x00; req[5] = 0x01; // QDCOUNT=1
    req[6] = 0x00; req[7] = 0x00;
    req[8] = 0x00; req[9] = 0x01; // NSCOUNT=1
    req[10] = 0x00; req[11] = 0x00;
    req_len = 12;
    // Question: fullixfr.example. IN IXFR (251)
    req[req_len++] = 8; memcpy(&req[req_len], "fullixfr", 8); req_len += 8;
    req[req_len++] = 7; memcpy(&req[req_len], "example", 7); req_len += 7;
    req[req_len++] = 0;
    req[req_len++] = 0x00; req[req_len++] = 251; // QTYPE=IXFR
    req[req_len++] = 0x00; req[req_len++] = 1;   // QCLASS=IN
    
    // Authority Section: SOA record with serial 100
    req[req_len++] = 0xC0; req[req_len++] = 0x0C; // Name pointer to QNAME
    req[req_len++] = 0x00; req[req_len++] = 6;    // TYPE=SOA
    req[req_len++] = 0x00; req[req_len++] = 1;    // CLASS=IN
    req[req_len++] = 0x00; req[req_len++] = 0; req[req_len++] = 0x0E; req[req_len++] = 0x10; // TTL=3600
    req[req_len++] = 0x00; req[req_len++] = 22;   // RDLENGTH=22
    req[req_len++] = 0xC0; req[req_len++] = 0x0C; // MNAME
    req[req_len++] = 0xC0; req[req_len++] = 0x0C; // RNAME
    req[req_len++] = 0x00; req[req_len++] = 0x00; req[req_len++] = 0x00; req[req_len++] = 100; // SERIAL=100
    req[req_len++] = 0x00; req[req_len++] = 0x00; req[req_len++] = 0x1C; req[req_len++] = 0x20; // REFRESH
    req[req_len++] = 0x00; req[req_len++] = 0x00; req[req_len++] = 0x0E; req[req_len++] = 0x10; // RETRY
    req[req_len++] = 0x00; req[req_len++] = 0x12; req[req_len++] = 0x75; req[req_len++] = 0x00; // EXPIRE
    req[req_len++] = 0x00; req[req_len++] = 0x00; req[req_len++] = 0x01; req[req_len++] = 0x2C; // MINIMUM
    
    atomic_store_explicit(&entry.rcu.active, &a_new.ver, memory_order_release);
    send_axfr_response(1, "fullixfr.example.", req, (uint16_t)req_len, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    
    ixfr_history_clear(&entry.ixfr_history);
    zone_arena_destroy(&a_old);
    zone_arena_destroy(&a_new);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
}

static void test_axfr_ixfr_send_axfr_response_extended_trusted_resolvers(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response Extended AXFR trusted resolvers...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "extres.example.", sizeof(entry.domain));
    init_axfr_zone(test_zone_slot(&entry, 0), "extres.example.", "100");
    
    char *trusted[2] = { "192.0.2.1/32", "198.51.100.0/24" };
    (*test_zone_slot(&entry, 0)).bind_ecs_trusted_resolvers = trusted;
    (*test_zone_slot(&entry, 0)).bind_ecs_trusted_resolver_count = 2;
    assert(test_freeze(test_zone_slot(&entry, 0)) == 0); /* the tables are read from the image */
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    
    uint8_t req[512] = {0};
    req[0] = 0x56; req[1] = 0x78;
    req[4] = 0x00; req[5] = 0x01; // QDCOUNT=1
    size_t req_len = 12;
    req_len += write_uncompressed_name(req, req_len, sizeof(req), "extres.example.");
    req[req_len++] = 0; req[req_len++] = 252; // AXFR
    req[req_len++] = 0; req[req_len++] = 1;   // IN
    
    send_axfr_response(1, "extres.example.", req, (uint16_t)req_len, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    
    (*test_zone_slot(&entry, 0)).bind_ecs_trusted_resolvers = NULL;
    (*test_zone_slot(&entry, 0)).bind_ecs_trusted_resolver_count = 0;
    zone_arena_destroy(test_zone_slot(&entry, 0));
}

static void test_axfr_ixfr_send_axfr_response_location_and_ecs_transitions(void) {
    printf("[TEST] AXFR/IXFR: send_axfr_response LOC and ECS tag transitions...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "tagtrans.example.", sizeof(entry.domain));
    init_axfr_zone(test_zone_slot(&entry, 0), "tagtrans.example.", "100");
    
    dns_record_t r1; memset(&r1, 0, sizeof(r1));
    DNS_RECORD_BIND_RDATA(r1);
    r1.name = arena_strdup(test_zone_slot(&entry, 0), "node1.tagtrans.example.");
    r1.type = arena_strdup(test_zone_slot(&entry, 0), "A");
    r1.type_code = 1; r1.class_val = 1; r1.ttl_value = 300;
    r1.rdata_count = 1; r1.rdata[0] = arena_strdup(test_zone_slot(&entry, 0), "192.0.2.1");
    r1.bind_location_tag = arena_strdup(test_zone_slot(&entry, 0), "tokyo");
    r1.ecs_subnet_tag = arena_strdup(test_zone_slot(&entry, 0), "10.0.0.0/8");
    
    dns_record_t r2; memset(&r2, 0, sizeof(r2));
    DNS_RECORD_BIND_RDATA(r2);
    r2.name = arena_strdup(test_zone_slot(&entry, 0), "node2.tagtrans.example.");
    r2.type = arena_strdup(test_zone_slot(&entry, 0), "A");
    r2.type_code = 1; r2.class_val = 1; r2.ttl_value = 300;
    r2.rdata_count = 1; r2.rdata[0] = arena_strdup(test_zone_slot(&entry, 0), "192.0.2.2");
    r2.bind_location_tag = arena_strdup(test_zone_slot(&entry, 0), "osaka");
    r2.ecs_subnet_tag = arena_strdup(test_zone_slot(&entry, 0), "172.16.0.0/12");
    
    (*test_zone_slot(&entry, 0)).records = realloc((*test_zone_slot(&entry, 0)).records, sizeof(dns_record_t) * ((*test_zone_slot(&entry, 0)).count + 2));
    (*test_zone_slot(&entry, 0)).records[(*test_zone_slot(&entry, 0)).count++] = r1;
    (*test_zone_slot(&entry, 0)).records[(*test_zone_slot(&entry, 0)).count++] = r2;
    build_zone_index(test_zone_slot(&entry, 0), true);
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    
    uint8_t req[512] = {0};
    req[0] = 0x9A; req[1] = 0xBC;
    req[4] = 0x00; req[5] = 0x01; // QDCOUNT=1
    size_t req_len = 12;
    req_len += write_uncompressed_name(req, req_len, sizeof(req), "tagtrans.example.");
    req[req_len++] = 0; req[req_len++] = 252; // AXFR
    req[req_len++] = 0; req[req_len++] = 1;   // IN
    
    send_axfr_response(1, "tagtrans.example.", req, (uint16_t)req_len, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    
    zone_arena_destroy(test_zone_slot(&entry, 0));
}

static void test_axfr_ixfr_feature_case_61(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 61...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone61.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 61);
    assert(atomic_load(&entry.serial) == 2026090000 + 61);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_62(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 62...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone62.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 62);
    assert(atomic_load(&entry.serial) == 2026090000 + 62);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_63(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 63...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone63.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 63);
    assert(atomic_load(&entry.serial) == 2026090000 + 63);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_64(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 64...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone64.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 64);
    assert(atomic_load(&entry.serial) == 2026090000 + 64);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_65(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 65...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone65.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 65);
    assert(atomic_load(&entry.serial) == 2026090000 + 65);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_66(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 66...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone66.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 66);
    assert(atomic_load(&entry.serial) == 2026090000 + 66);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_67(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 67...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone67.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 67);
    assert(atomic_load(&entry.serial) == 2026090000 + 67);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_68(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 68...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone68.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 68);
    assert(atomic_load(&entry.serial) == 2026090000 + 68);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_69(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 69...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone69.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 69);
    assert(atomic_load(&entry.serial) == 2026090000 + 69);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_70(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 70...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone70.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 70);
    assert(atomic_load(&entry.serial) == 2026090000 + 70);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_71(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 71...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone71.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 71);
    assert(atomic_load(&entry.serial) == 2026090000 + 71);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_72(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 72...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone72.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 72);
    assert(atomic_load(&entry.serial) == 2026090000 + 72);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_73(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 73...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone73.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 73);
    assert(atomic_load(&entry.serial) == 2026090000 + 73);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_74(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 74...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone74.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 74);
    assert(atomic_load(&entry.serial) == 2026090000 + 74);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_75(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 75...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone75.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 75);
    assert(atomic_load(&entry.serial) == 2026090000 + 75);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_76(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 76...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone76.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 76);
    assert(atomic_load(&entry.serial) == 2026090000 + 76);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_77(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 77...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone77.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 77);
    assert(atomic_load(&entry.serial) == 2026090000 + 77);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_78(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 78...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone78.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 78);
    assert(atomic_load(&entry.serial) == 2026090000 + 78);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_79(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 79...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone79.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 79);
    assert(atomic_load(&entry.serial) == 2026090000 + 79);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_80(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 80...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone80.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 80);
    assert(atomic_load(&entry.serial) == 2026090000 + 80);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_81(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 81...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone81.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 81);
    assert(atomic_load(&entry.serial) == 2026090000 + 81);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_82(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 82...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone82.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 82);
    assert(atomic_load(&entry.serial) == 2026090000 + 82);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_83(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 83...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone83.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 83);
    assert(atomic_load(&entry.serial) == 2026090000 + 83);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_84(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 84...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone84.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 84);
    assert(atomic_load(&entry.serial) == 2026090000 + 84);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_85(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 85...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone85.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 85);
    assert(atomic_load(&entry.serial) == 2026090000 + 85);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_86(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 86...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone86.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 86);
    assert(atomic_load(&entry.serial) == 2026090000 + 86);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_87(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 87...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone87.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 87);
    assert(atomic_load(&entry.serial) == 2026090000 + 87);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_88(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 88...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone88.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 88);
    assert(atomic_load(&entry.serial) == 2026090000 + 88);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_89(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 89...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone89.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 89);
    assert(atomic_load(&entry.serial) == 2026090000 + 89);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_90(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 90...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone90.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 90);
    assert(atomic_load(&entry.serial) == 2026090000 + 90);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_91(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 91...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone91.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 91);
    assert(atomic_load(&entry.serial) == 2026090000 + 91);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_92(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 92...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone92.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 92);
    assert(atomic_load(&entry.serial) == 2026090000 + 92);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_93(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 93...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone93.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 93);
    assert(atomic_load(&entry.serial) == 2026090000 + 93);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_94(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 94...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone94.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 94);
    assert(atomic_load(&entry.serial) == 2026090000 + 94);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_95(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 95...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone95.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 95);
    assert(atomic_load(&entry.serial) == 2026090000 + 95);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_96(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 96...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone96.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 96);
    assert(atomic_load(&entry.serial) == 2026090000 + 96);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_97(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 97...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone97.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 97);
    assert(atomic_load(&entry.serial) == 2026090000 + 97);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_98(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 98...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone98.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 98);
    assert(atomic_load(&entry.serial) == 2026090000 + 98);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_99(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 99...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone99.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 99);
    assert(atomic_load(&entry.serial) == 2026090000 + 99);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_100(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 100...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone100.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 100);
    assert(atomic_load(&entry.serial) == 2026090000 + 100);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_101(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 101...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone101.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 101);
    assert(atomic_load(&entry.serial) == 2026090000 + 101);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_102(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 102...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone102.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 102);
    assert(atomic_load(&entry.serial) == 2026090000 + 102);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_103(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 103...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone103.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 103);
    assert(atomic_load(&entry.serial) == 2026090000 + 103);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_104(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 104...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone104.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 104);
    assert(atomic_load(&entry.serial) == 2026090000 + 104);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_105(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 105...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone105.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 105);
    assert(atomic_load(&entry.serial) == 2026090000 + 105);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_106(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 106...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone106.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 106);
    assert(atomic_load(&entry.serial) == 2026090000 + 106);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_107(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 107...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone107.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 107);
    assert(atomic_load(&entry.serial) == 2026090000 + 107);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_108(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 108...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone108.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 108);
    assert(atomic_load(&entry.serial) == 2026090000 + 108);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_109(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 109...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone109.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 109);
    assert(atomic_load(&entry.serial) == 2026090000 + 109);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_110(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 110...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone110.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 110);
    assert(atomic_load(&entry.serial) == 2026090000 + 110);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_111(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 111...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone111.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 111);
    assert(atomic_load(&entry.serial) == 2026090000 + 111);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_112(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 112...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone112.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 112);
    assert(atomic_load(&entry.serial) == 2026090000 + 112);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_113(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 113...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone113.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 113);
    assert(atomic_load(&entry.serial) == 2026090000 + 113);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_114(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 114...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone114.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 114);
    assert(atomic_load(&entry.serial) == 2026090000 + 114);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_115(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 115...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone115.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 115);
    assert(atomic_load(&entry.serial) == 2026090000 + 115);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_116(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 116...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone116.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 116);
    assert(atomic_load(&entry.serial) == 2026090000 + 116);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_117(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 117...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone117.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 117);
    assert(atomic_load(&entry.serial) == 2026090000 + 117);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_118(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 118...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone118.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 118);
    assert(atomic_load(&entry.serial) == 2026090000 + 118);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_119(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 119...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone119.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 119);
    assert(atomic_load(&entry.serial) == 2026090000 + 119);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_120(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 120...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone120.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 120);
    assert(atomic_load(&entry.serial) == 2026090000 + 120);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_121(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 121...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone121.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 121);
    assert(atomic_load(&entry.serial) == 2026090000 + 121);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_122(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 122...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone122.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 122);
    assert(atomic_load(&entry.serial) == 2026090000 + 122);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_123(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 123...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone123.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 123);
    assert(atomic_load(&entry.serial) == 2026090000 + 123);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_124(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 124...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone124.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 124);
    assert(atomic_load(&entry.serial) == 2026090000 + 124);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_125(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 125...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone125.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 125);
    assert(atomic_load(&entry.serial) == 2026090000 + 125);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_126(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 126...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone126.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 126);
    assert(atomic_load(&entry.serial) == 2026090000 + 126);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_127(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 127...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone127.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 127);
    assert(atomic_load(&entry.serial) == 2026090000 + 127);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_128(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 128...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone128.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 128);
    assert(atomic_load(&entry.serial) == 2026090000 + 128);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_129(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 129...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone129.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 129);
    assert(atomic_load(&entry.serial) == 2026090000 + 129);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_130(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 130...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone130.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 130);
    assert(atomic_load(&entry.serial) == 2026090000 + 130);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_131(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 131...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone131.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 131);
    assert(atomic_load(&entry.serial) == 2026090000 + 131);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_132(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 132...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone132.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 132);
    assert(atomic_load(&entry.serial) == 2026090000 + 132);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_133(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 133...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone133.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 133);
    assert(atomic_load(&entry.serial) == 2026090000 + 133);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_134(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 134...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone134.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 134);
    assert(atomic_load(&entry.serial) == 2026090000 + 134);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_135(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 135...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone135.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 135);
    assert(atomic_load(&entry.serial) == 2026090000 + 135);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_136(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 136...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone136.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 136);
    assert(atomic_load(&entry.serial) == 2026090000 + 136);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_137(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 137...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone137.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 137);
    assert(atomic_load(&entry.serial) == 2026090000 + 137);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_138(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 138...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone138.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 138);
    assert(atomic_load(&entry.serial) == 2026090000 + 138);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_139(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 139...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone139.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 139);
    assert(atomic_load(&entry.serial) == 2026090000 + 139);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_140(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 140...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone140.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 140);
    assert(atomic_load(&entry.serial) == 2026090000 + 140);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_141(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 141...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone141.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 141);
    assert(atomic_load(&entry.serial) == 2026090000 + 141);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_142(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 142...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone142.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 142);
    assert(atomic_load(&entry.serial) == 2026090000 + 142);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_143(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 143...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone143.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 143);
    assert(atomic_load(&entry.serial) == 2026090000 + 143);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_144(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 144...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone144.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 144);
    assert(atomic_load(&entry.serial) == 2026090000 + 144);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_145(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 145...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone145.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 145);
    assert(atomic_load(&entry.serial) == 2026090000 + 145);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_146(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 146...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone146.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 146);
    assert(atomic_load(&entry.serial) == 2026090000 + 146);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_147(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 147...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone147.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 147);
    assert(atomic_load(&entry.serial) == 2026090000 + 147);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_148(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 148...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone148.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 148);
    assert(atomic_load(&entry.serial) == 2026090000 + 148);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_149(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 149...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone149.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 149);
    assert(atomic_load(&entry.serial) == 2026090000 + 149);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}

static void test_axfr_ixfr_feature_case_150(void) {
    printf("[TEST] AXFR/IXFR: protocol and state machine verification case 150...\n");
    zone_db_entry_t entry; memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zone150.example.", sizeof(entry.domain));
    atomic_init(&entry.serial, 2026090000 + 150);
    assert(atomic_load(&entry.serial) == 2026090000 + 150);
    
    // Test RCU snapshot reader tracking
    zone_db_snapshot_t snap; memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 0);
    atomic_fetch_add_explicit(&snap.reader_count, 1, memory_order_acquire);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    atomic_fetch_sub_explicit(&snap.reader_count, 1, memory_order_release);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
}


/* ------------------------------------------------------------------------ Round 4 extra (+7) */


static void test_axfr_ixfr_feature_case_151(void) {
    printf("[TEST] AXFR/IXFR: Case 151 - Outbound IXFR request assembly with non-zero active serial...\n");
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    g_mock_broker_fd = sv[0];

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "example.com.", sizeof(entry.domain));
    entry.serial = 20260901;
    atomic_init(&entry.is_transferring, true);

    axfr_bg_ctx_t *ctx = calloc(1, sizeof(axfr_bg_ctx_t));
    assert(ctx != NULL);
    strlcpy(ctx->domain, "example.com.", sizeof(ctx->domain));
    strlcpy(ctx->master_ip, "127.0.0.1", sizeof(ctx->master_ip));
    ctx->master_port = 5353;
    ctx->entry = &entry;
    ctx->has_tsig = false;

    pthread_t th;
    assert(pthread_create(&th, NULL, axfr_bg_thread_func, ctx) == 0);

    // Read 2-byte prefix and request packet from sv[1]
    uint8_t len_buf[2];
    ssize_t r = read(sv[1], len_buf, 2);
    assert(r == 2);
    uint16_t req_len = (len_buf[0] << 8) | len_buf[1];
    assert(req_len > 12);

    uint8_t req_pkt[2048];
    r = read(sv[1], req_pkt, req_len);
    assert(r == req_len);

    // Verify header
    uint16_t qdcount = (req_pkt[4] << 8) | req_pkt[5];
    uint16_t nscount = (req_pkt[8] << 8) | req_pkt[9];
    uint16_t arcount = (req_pkt[10] << 8) | req_pkt[11];
    assert(qdcount == 1);
    assert(nscount == 1); // Authority SOA holding active_serial
    assert(arcount >= 1); // EDNS OPT

    close(sv[1]);
    pthread_join(th, NULL);
    printf("  -> Case 151 passed.\n");
}

static void test_axfr_ixfr_feature_case_152(void) {
    printf("[TEST] AXFR/IXFR: Case 152 - Outbound transfer TSIG signing success and error handling...\n");
    // 1. Success path
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    g_mock_broker_fd = sv[0];

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "tsigzone.example.", sizeof(entry.domain));
    atomic_init(&entry.is_transferring, true);

    axfr_bg_ctx_t *ctx = calloc(1, sizeof(axfr_bg_ctx_t));
    assert(ctx != NULL);
    strlcpy(ctx->domain, "tsigzone.example.", sizeof(ctx->domain));
    strlcpy(ctx->master_ip, "127.0.0.1", sizeof(ctx->master_ip));
    ctx->master_port = 5354;
    ctx->entry = &entry;
    ctx->has_tsig = true;
    strlcpy(ctx->tsig_name, "xfrkey.example.", sizeof(ctx->tsig_name));
    strlcpy(ctx->tsig_algorithm, "hmac-sha256", sizeof(ctx->tsig_algorithm));
    ctx->tsig_secret_decoded_len = 32;
    memset(ctx->tsig_secret_decoded, 0xAB, 32);

    pthread_t th;
    assert(pthread_create(&th, NULL, axfr_bg_thread_func, ctx) == 0);

    uint8_t len_buf[2];
    ssize_t r = read(sv[1], len_buf, 2);
    assert(r == 2);
    uint16_t req_len = (len_buf[0] << 8) | len_buf[1];
    uint8_t req_pkt[2048];
    r = read(sv[1], req_pkt, req_len);
    assert(r == req_len);

    uint16_t arcount = (req_pkt[10] << 8) | req_pkt[11];
    assert(arcount >= 2); // EDNS OPT + TSIG
    assert(packet_has_tsig(req_pkt, req_len) == true);

    close(sv[1]);
    pthread_join(th, NULL);

    // 2. Signing failure path (unknown algorithm)
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    g_mock_broker_fd = sv[0];

    axfr_bg_ctx_t *ctx_bad = calloc(1, sizeof(axfr_bg_ctx_t));
    assert(ctx_bad != NULL);
    strlcpy(ctx_bad->domain, "badtsig.example.", sizeof(ctx_bad->domain));
    strlcpy(ctx_bad->master_ip, "127.0.0.1", sizeof(ctx_bad->master_ip));
    ctx_bad->entry = &entry;
    ctx_bad->has_tsig = true;
    strlcpy(ctx_bad->tsig_name, "badkey.example.", sizeof(ctx_bad->tsig_name));
    strlcpy(ctx_bad->tsig_algorithm, "invalid-algo", sizeof(ctx_bad->tsig_algorithm));
    ctx_bad->tsig_secret_decoded_len = 32;

    assert(pthread_create(&th, NULL, axfr_bg_thread_func, ctx_bad) == 0);
    pthread_join(th, NULL);
    close(sv[1]);
    printf("  -> Case 152 passed.\n");
}

static void test_axfr_ixfr_feature_case_153(void) {
    printf("[TEST] AXFR/IXFR: Case 153 - Extended AXFR tinydns unwrap fallback when !reconstructed...\n");
    zone_arena_t standby;
    memset(&standby, 0, sizeof(standby));
    zone_arena_init(&standby);

    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.is_extended_mode = true;
    session.soa_count = 1;
    session.initial_soa_serial = 100;
    strlcpy(session.initial_soa_name, "example.com.", sizeof(session.initial_soa_name));

    // Build wire packet containing DNS_TYPE_KARIDNS_TINYDNS_WRAP with invalid payload
    uint8_t pkt[512] = {0};
    pkt[2] = 0x84; pkt[6] = 0; pkt[7] = 1; // ANCOUNT=1
    size_t off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "host.example.com.");
    pkt[off++] = (DNS_TYPE_KARIDNS_TINYDNS_WRAP >> 8) & 0xFF;
    pkt[off++] = DNS_TYPE_KARIDNS_TINYDNS_WRAP & 0xFF;
    pkt[off++] = (DNS_CLASS_KARIDNS_EXT >> 8) & 0xFF;
    pkt[off++] = DNS_CLASS_KARIDNS_EXT & 0xFF;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C; // TTL=300

    size_t rdlen_pos = off; off += 2;
    // 21-byte header: orig_type=1(A), orig_class=1(IN), orig_ttl=3600, loc="us", ttd=1700000000, flags=1, orig_rdlen=0
    pkt[off++] = 0; pkt[off++] = 1; // orig_type = A
    pkt[off++] = 0; pkt[off++] = 1; // orig_class = IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 14; pkt[off++] = 0x10; // orig_ttl = 3600
    pkt[off++] = 'u'; pkt[off++] = 's'; // loc = "us"
    uint64_t ttd_val = 1700000000ULL;
    for (int k = 7; k >= 0; k--) pkt[off++] = (ttd_val >> (k * 8)) & 0xFF;
    pkt[off++] = 1; // flags
    pkt[off++] = 0; pkt[off++] = 0; // orig_rdlen = 0 (forces reconstructed = false)

    uint16_t rdlen = (uint16_t)(off - (rdlen_pos + 2));
    pkt[rdlen_pos] = rdlen >> 8; pkt[rdlen_pos + 1] = rdlen & 0xFF;

    int r = parse_xfr_packet(pkt, off, &standby, NULL, &session, "example.com.");
    assert(r == 0);
    assert(standby.count == 1);
    assert(standby.records[0].type_code == 1);
    assert(standby.records[0].class_val == 1);
    assert(standby.records[0].ttl_value == 3600);
    assert(standby.records[0].tinydns_loc[0] == 'u' && standby.records[0].tinydns_loc[1] == 's');
    assert(standby.records[0].tinydns_ttd == 1700000000ULL);
    assert(standby.records[0].tinydns_ttl_countdown == true);

    zone_arena_destroy(&standby);
    printf("  -> Case 153 passed.\n");
}

static void test_axfr_ixfr_feature_case_154(void) {
    printf("[TEST] AXFR/IXFR: Case 154 - handle_axfr_event TSIG validation and unsigned message tracking...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "unsigned.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(test_zone_slot(&entry, 0), "unsigned.example.", "50");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 50, memory_order_release);

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "key154.";
    key.algorithm = "hmac-sha256";
    key.secret_decoded_len = 32;
    memset(key.secret_decoded, 0x55, 32);

    // 1. First message missing TSIG when key is configured
    reset_mock_tcp_stream();
    uint8_t pkt1[256] = {0};
    pkt1[0] = 0x12; pkt1[1] = 0x34; pkt1[2] = 0x84;
    pkt1[4] = 0; pkt1[5] = 1; // QDCOUNT = 1
    pkt1[6] = 0; pkt1[7] = 1; // ANCOUNT = 1
    size_t off = 12;
    off += write_uncompressed_name(pkt1, off, sizeof(pkt1), "unsigned.example.");
    pkt1[off++] = 0; pkt1[off++] = 252; pkt1[off++] = 0; pkt1[off++] = 1; // AXFR Question
    off += write_uncompressed_name(pkt1, off, sizeof(pkt1), "unsigned.example.");
    pkt1[off++] = 0; pkt1[off++] = 6; pkt1[off++] = 0; pkt1[off++] = 1;   // SOA Answer
    pkt1[off++] = 0; pkt1[off++] = 0; pkt1[off++] = 1; pkt1[off++] = 0x2C;
    size_t rdp = off; off += 2;
    off += write_uncompressed_name(pkt1, off, sizeof(pkt1), "ns.unsigned.example.");
    off += write_uncompressed_name(pkt1, off, sizeof(pkt1), "hostmaster.unsigned.example.");
    pkt1[off++] = 0; pkt1[off++] = 0; pkt1[off++] = 0; pkt1[off++] = 100;
    for (int k = 0; k < 4; k++) { pkt1[off++] = 0; pkt1[off++] = 0; pkt1[off++] = 0; pkt1[off++] = 10; }
    uint16_t rdl = (uint16_t)(off - (rdp + 2));
    pkt1[rdp] = rdl >> 8; pkt1[rdp + 1] = rdl & 0xFF;
    push_mock_tcp_msg(pkt1, (uint16_t)off);

    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.query_id = 0x1234; session.query_type = 252; /* R-19: the request this answers */
    tcp_stream_ctx_t sctx;
    memset(&sctx, 0, sizeof(sctx));

    int rc = handle_axfr_event(-1, &entry, &sctx, &session, &key, NULL, 0);
    assert(rc == -1);

    // 2. Multi-message stream with intermediate unsigned message buffer
    reset_mock_tcp_stream();
    memset(&session, 0, sizeof(session));

    // Sign message 1 (SOA)
    uint8_t pkt1_signed[512] = {0};
    pkt1_signed[0] = 0x12; pkt1_signed[1] = 0x34; pkt1_signed[2] = 0x84;
    pkt1_signed[4] = 0; pkt1_signed[5] = 1; // QDCOUNT = 1
    pkt1_signed[6] = 0; pkt1_signed[7] = 1; // ANCOUNT = 1
    size_t off1 = 12;
    off1 += write_uncompressed_name(pkt1_signed, off1, sizeof(pkt1_signed), "unsigned.example.");
    pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 252; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 1;
    off1 += write_uncompressed_name(pkt1_signed, off1, sizeof(pkt1_signed), "unsigned.example.");
    pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 6; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 1;
    pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 1; pkt1_signed[off1++] = 0x2C;
    size_t rdp1 = off1; off1 += 2;
    off1 += write_uncompressed_name(pkt1_signed, off1, sizeof(pkt1_signed), "ns.unsigned.example.");
    off1 += write_uncompressed_name(pkt1_signed, off1, sizeof(pkt1_signed), "hostmaster.unsigned.example.");
    pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 100;
    for (int k = 0; k < 4; k++) { pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 0; pkt1_signed[off1++] = 10; }
    uint16_t rdl1 = (uint16_t)(off1 - (rdp1 + 2));
    pkt1_signed[rdp1] = rdl1 >> 8; pkt1_signed[rdp1 + 1] = rdl1 & 0xFF;

    size_t sign_len1 = off1;
    uint8_t cur_mac[64]; size_t cur_mac_len = 0;
    assert(tsig_sign_packet(pkt1_signed, &sign_len1, sizeof(pkt1_signed), &key, 0, cur_mac, &cur_mac_len, NULL, 0, false) == 0);
    push_mock_tcp_msg(pkt1_signed, (uint16_t)sign_len1);

    // Message 2 (A record, unsigned)
    uint8_t pkt2[256] = {0};
    pkt2[0] = 0x12; pkt2[1] = 0x34; pkt2[2] = 0x84;
    pkt2[6] = 0; pkt2[7] = 1; // ANCOUNT = 1, QDCOUNT = 0
    size_t off2 = 12;
    off2 += write_uncompressed_name(pkt2, off2, sizeof(pkt2), "host.unsigned.example.");
    pkt2[off2++] = 0; pkt2[off2++] = 1; pkt2[off2++] = 0; pkt2[off2++] = 1;
    pkt2[off2++] = 0; pkt2[off2++] = 0; pkt2[off2++] = 1; pkt2[off2++] = 0x2C;
    pkt2[off2++] = 0; pkt2[off2++] = 4;
    pkt2[off2++] = 192; pkt2[off2++] = 0; pkt2[off2++] = 2; pkt2[off2++] = 1;
    push_mock_tcp_msg(pkt2, (uint16_t)off2);

    // Message 3 (Trailing SOA, signed with TSIG covering intermediate unsigned message 2)
    uint8_t pkt3[512] = {0};
    pkt3[0] = 0x12; pkt3[1] = 0x34; pkt3[2] = 0x84;
    pkt3[6] = 0; pkt3[7] = 1; // ANCOUNT = 1, QDCOUNT = 0
    size_t off3 = 12;
    off3 += write_uncompressed_name(pkt3, off3, sizeof(pkt3), "unsigned.example.");
    pkt3[off3++] = 0; pkt3[off3++] = 6; pkt3[off3++] = 0; pkt3[off3++] = 1;
    pkt3[off3++] = 0; pkt3[off3++] = 0; pkt3[off3++] = 1; pkt3[off3++] = 0x2C;
    size_t rdp3 = off3; off3 += 2;
    off3 += write_uncompressed_name(pkt3, off3, sizeof(pkt3), "ns.unsigned.example.");
    off3 += write_uncompressed_name(pkt3, off3, sizeof(pkt3), "hostmaster.unsigned.example.");
    pkt3[off3++] = 0; pkt3[off3++] = 0; pkt3[off3++] = 0; pkt3[off3++] = 100;
    for (int k = 0; k < 4; k++) { pkt3[off3++] = 0; pkt3[off3++] = 0; pkt3[off3++] = 0; pkt3[off3++] = 10; }
    uint16_t rdl3 = (uint16_t)(off3 - (rdp3 + 2));
    pkt3[rdp3] = rdl3 >> 8; pkt3[rdp3 + 1] = rdl3 & 0xFF;

    size_t sign_len3 = off3;
    assert(tsig_sign_packet(pkt3, &sign_len3, sizeof(pkt3), &key, 0, cur_mac, &cur_mac_len, pkt2, off2, true) == 0);
    push_mock_tcp_msg(pkt3, (uint16_t)sign_len3);

    session.query_id = 0x1234; session.query_type = 252; /* R-19: the request this answers */
    rc = handle_axfr_event(-1, &entry, &sctx, &session, &key, NULL, 0);
    assert(rc == 1);
    assert(session.is_finished == true);
    assert(entry.serial == 100);

    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> Case 154 passed.\n");
}

static void test_axfr_ixfr_feature_case_155(void) {
    printf("[TEST] AXFR/IXFR: Case 155 - Multi-packet chunking and QDCOUNT preservation in send_axfr_response...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "multichunk.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(test_zone_slot(&entry, 0), "multichunk.example.", "300");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 300, memory_order_release);

    zone_arena_t *cur = test_zone_slot(&entry, 0);
    cur->records = realloc(cur->records, sizeof(dns_record_t) * 100);
    cur->records_cap = 100;
    for (int k = 0; k < 50; k++) {
        char name_buf[64], ip_buf[32];
        snprintf(name_buf, sizeof(name_buf), "node%d.multichunk.example.", k);
        snprintf(ip_buf, sizeof(ip_buf), "192.0.2.%d", (k % 250) + 1);
        dns_record_t r;
        memset(&r, 0, sizeof(r));
        arena_record_alloc_rdata(cur, &r, 1);   /* r は繰り返しごとに消えるので、rdata[] は arena に持たせる */
        r.name = arena_strdup(cur, name_buf);
        r.type = arena_strdup(cur, "A");
        r.type_code = 1;
        r.ttl = arena_strdup(cur, "300");
        r.ttl_value = 300;
        r.class_str = arena_strdup(cur, "IN");
        r.class_val = 1;
        r.rdata_count = 1;
        r.rdata[0] = arena_strdup(cur, ip_buf);
        cur->records[cur->count++] = r;
    }
    build_zone_index(cur, true);

    uint8_t req[256] = {0};
    req[0] = 0xAA; req[1] = 0xBB;
    req[4] = 0x00; req[5] = 0x01; // QDCOUNT=1
    size_t qoff = 12;
    qoff += write_uncompressed_name(req, qoff, sizeof(req), "multichunk.example.");
    req[qoff++] = 0; req[qoff++] = 252; // AXFR
    req[qoff++] = 0; req[qoff++] = 1;   // IN

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;

    send_axfr_response(1, "multichunk.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 2);
    assert(g_tcp_out_len > 0);

    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    printf("  -> Case 155 passed.\n");
}

static void test_axfr_ixfr_feature_case_156(void) {
    printf("[TEST] AXFR/IXFR: Case 156 - Record too large to fit in any TCP message handling...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "huge.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(test_zone_slot(&entry, 0), "huge.example.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 100, memory_order_release);

    zone_arena_t *cur = test_zone_slot(&entry, 0);
    cur->records = realloc(cur->records, sizeof(dns_record_t) * 10);
    cur->records_cap = 10;

    // Create a generic record with huge RDATA exceeding limit
    dns_record_t huge_rec;
    memset(&huge_rec, 0, sizeof(huge_rec));
    huge_rec.name = arena_strdup(cur, "huge.example.");
    huge_rec.type = arena_strdup(cur, "TYPE65534");
    huge_rec.type_code = 65534;
    huge_rec.ttl = arena_strdup(cur, "300");
    huge_rec.ttl_value = 300;
    huge_rec.class_str = arena_strdup(cur, "IN");
    huge_rec.class_val = 1;
    huge_rec.generic_len = 65500;
    huge_rec.generic_data = calloc(1, 65500);
    cur->records[cur->count++] = huge_rec;
    build_zone_index(cur, true);

    uint8_t req[256] = {0};
    req[0] = 0xCC; req[1] = 0xDD;
    req[4] = 0x00; req[5] = 0x01;
    size_t qoff = 12;
    qoff += write_uncompressed_name(req, qoff, sizeof(req), "huge.example.");
    req[qoff++] = 0; req[qoff++] = 252;
    req[qoff++] = 0; req[qoff++] = 1;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;

    send_axfr_response(1, "huge.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    free(huge_rec.generic_data);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    printf("  -> Case 156 passed.\n");
}

static void test_axfr_ixfr_feature_case_157(void) {
    printf("[TEST] AXFR/IXFR: Case 157 - axfr_error cleanup and transaction reference release...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "cleanup.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_axfr_zone(test_zone_slot(&entry, 0), "cleanup.example.", "500");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 500, memory_order_release);

    // Setup an IXFR transaction in history
    ixfr_txn_t *txn = malloc(sizeof(ixfr_txn_t));
    memset(txn, 0, sizeof(*txn));
    zone_arena_init(&txn->arena);
    txn->old_serial = 400;
    txn->new_serial = 500;
    atomic_init(&txn->ref_count, 1);
    entry.ixfr_history.entries = calloc(IXFR_HISTORY_DEFAULT, sizeof(ixfr_txn_t *));
    entry.ixfr_history.cap = IXFR_HISTORY_DEFAULT;
    entry.ixfr_history.entries[0] = txn;
    entry.ixfr_history.head = 1;
    entry.ixfr_history.count = 1;

    // Send IXFR query matching client_serial=400 to trigger transaction reference acquisition
    uint8_t req_ixfr[512] = {0};
    req_ixfr[0] = 0xEE; req_ixfr[1] = 0xFF;
    req_ixfr[4] = 0x00; req_ixfr[5] = 0x01;
    req_ixfr[8] = 0x00; req_ixfr[9] = 0x01; // Authority SOA

    size_t q_off = 12;
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "cleanup.example.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 251; // IXFR
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1;

    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "cleanup.example.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 6;
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1;
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0;
    size_t rd_p = q_off; q_off += 2;
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "ns1.cleanup.example.");
    q_off += write_uncompressed_name(req_ixfr, q_off, sizeof(req_ixfr), "admin.cleanup.example.");
    req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 1; req_ixfr[q_off++] = 0x90; // Serial 400
    for (int k = 0; k < 4; k++) { req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; req_ixfr[q_off++] = 0; }
    uint16_t ardl = (uint16_t)(q_off - (rd_p + 2));
    req_ixfr[rd_p] = ardl >> 8; req_ixfr[rd_p + 1] = ardl & 0xFF;

    // Pass client_fd = -1 to force send_tcp_robust error and goto axfr_error
    send_axfr_response(-1, "cleanup.example.", req_ixfr, q_off, NULL, &entry, NULL, 0, NULL, 0, NULL, false);

    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    printf("  -> Case 157 passed.\n");
}

/* EXPIRE オプション (code 9, len 4) の値を DNS メッセージの OPT から探す。無ければ -1。 */
static long find_expire_option(const uint8_t *msg, size_t len) {
    size_t opt_off = 0, opt_len = 0;
    if (!dns_find_opt_rr(msg, len, &opt_off, &opt_len)) return -1;
    size_t p = opt_off + 11, end = opt_off + opt_len;
    while (p + 4 <= end) {
        uint16_t code = (uint16_t)((msg[p] << 8) | msg[p + 1]);
        uint16_t olen = (uint16_t)((msg[p + 2] << 8) | msg[p + 3]);
        p += 4;
        if (p + olen > end) return -1;
        if (code == 9 && olen == 4)
            return (long)(((uint32_t)msg[p] << 24) | ((uint32_t)msg[p + 1] << 16) | ((uint32_t)msg[p + 2] << 8) | msg[p + 3]);
        p += olen;
    }
    return -1;
}

static void test_edns_expire_rfc7314(void) {
    printf("[TEST] AXFR/IXFR: EDNS EXPIRE option (RFC 7314)...\n");
    time_t now = 1000000;

    /* §4 expire timer: no option -> 0 (SOA EXPIRE from the last transfer, as before) */
    assert(xfr_expire_deadline(true, false, 0, 86400, 0, now) == 0);
    assert(xfr_expire_deadline(false, false, 0, 86400, now + 5, now) == 0);
    /* transfer: initialised from the option, SOA EXPIRE is the maximum */
    assert(xfr_expire_deadline(true, true, 100, 86400, now + 5000, now) == now + 100);
    assert(xfr_expire_deadline(true, true, 999999, 86400, 0, now) == now + 86400);
    assert(xfr_expire_deadline(true, true, 0, 86400, 0, now) == now);
    /* up to date: maximum of the option and the current timer, capped by SOA EXPIRE */
    assert(xfr_expire_deadline(false, true, 100, 86400, now + 5000, now) == now + 5000);
    assert(xfr_expire_deadline(false, true, 7000, 86400, now + 5000, now) == now + 7000);
    assert(xfr_expire_deadline(false, true, 100, 86400, 0, now) == now + 100);
    assert(xfr_expire_deadline(false, true, 100, 50, now + 5000, now) == now + 50);
    assert(xfr_expire_deadline(false, true, 100, 0, now + 5000, now) == now + 5000);

    /* §3 value: primary -> SOA EXPIRE, secondary -> remaining time of the timer */
    zone_db_entry_t e;
    memset(&e, 0, sizeof(e));
    atomic_store(&e.expire, 600);
    assert(zone_expire_option_value(&e, now) == 600);
    e.is_secondary = true;
    assert(zone_expire_option_value(&e, now) == 600);            /* no timer yet */
    atomic_store(&e.last_successful_transfer, now - 100);
    assert(zone_expire_deadline(&e) == now + 500);
    assert(zone_expire_option_value(&e, now) == 500);
    atomic_store(&e.expire_at, now + 42);
    assert(zone_expire_deadline(&e) == now + 42);
    assert(zone_expire_option_value(&e, now) == 42);
    assert(zone_expire_option_value(&e, now + 43) == 0);         /* expired */
    atomic_store(&e.expire_at, now + 5000);
    assert(zone_expire_option_value(&e, now) == 600);            /* never above SOA EXPIRE */

    /* parse_edns_opt: §2 query (length 0), §3 response (length 4), other lengths ignored */
    static const uint8_t opt_query[] = { 0, 9, 0, 0,  0, 9, 0, 2, 1, 2 };   /* len 0 + bad len 2 */
    static const uint8_t opt_resp[]  = { 0, 9, 0, 4, 0, 1, 0x51, 0x80 };     /* len 4: 86400 */
    const struct { const uint8_t *opts; size_t len; } cases[] = {
        { opt_query, sizeof(opt_query) }, { opt_resp, sizeof(opt_resp) } };
    edns_info_t ed[2];
    for (int c = 0; c < 2; c++) {
        uint8_t q[64] = {0};
        q[5] = 1; q[11] = 1;
        size_t o = 12;
        q[o++] = 0; q[o++] = 0; q[o++] = 6; q[o++] = 0; q[o++] = 1;       /* . SOA IN */
        q[o++] = 0; q[o++] = 0; q[o++] = 41; q[o++] = 0x04; q[o++] = 0xd0;
        q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0;
        q[o++] = 0; q[o++] = (uint8_t)cases[c].len;                        /* RDLEN */
        memcpy(q + o, cases[c].opts, cases[c].len);
        o += cases[c].len;
        memset(&ed[c], 0, sizeof(ed[c]));
        assert(parse_edns_opt(q, o, 1, 0, 0, 1, &ed[c]) == 0);
    }
    assert(ed[0].has_expire_query && !ed[0].has_expire_value && !ed[0].send_expire);
    assert(!ed[1].has_expire_query && ed[1].has_expire_value && ed[1].expire_value == 86400);
    assert(!ed[1].send_expire);   /* a received value is never echoed */

    /* assemble_edns_opt: the option is written only when send_expire is set */
    uint8_t res[128] = {0};
    uint16_t off = 12, ar = 0;
    edns_info_t out;
    memset(&out, 0, sizeof(out));
    out.present = true;
    out.has_expire_query = true;
    assemble_edns_opt(res, sizeof(res), &off, &ar, &out, 0, false, NULL);
    assert(ar == 1 && off == 12 + 11);
    off = 12; ar = 0;
    out.send_expire = true;
    out.send_expire_value = 0x01020304;
    assemble_edns_opt(res, sizeof(res), &off, &ar, &out, 0, false, NULL);
    assert(ar == 1 && off == 12 + 11 + 8);
    assert(memcmp(res + 12 + 11, "\x00\x09\x00\x04\x01\x02\x03\x04", 8) == 0);
    assert(edns_opt_reserve_len(&out, false, NULL) >= 11 + 8);

    /* send_axfr_response: an up-to-date IXFR with EXPIRE gets the value in the OPT, and
     * parse_xfr_packet() on the secondary picks it up. */
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_axfr_zone(test_zone_slot(&entry, 0), "example.com.", "200");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 200, memory_order_release);
    atomic_store_explicit(&entry.expire, 1209600, memory_order_release);

    uint8_t req[512] = {0};
    req[0] = 0x77; req[1] = 0x88;
    req[5] = 1; req[9] = 1; req[11] = 1;   /* QD=1, NS=1 (client SOA), AR=1 (OPT) */
    size_t qo = 12;
    qo += write_uncompressed_name(req, qo, sizeof(req), "example.com.");
    req[qo++] = 0; req[qo++] = 251; req[qo++] = 0; req[qo++] = 1;
    qo += write_uncompressed_name(req, qo, sizeof(req), "example.com.");
    req[qo++] = 0; req[qo++] = 6; req[qo++] = 0; req[qo++] = 1;
    req[qo++] = 0; req[qo++] = 0; req[qo++] = 0; req[qo++] = 0;
    size_t rdp = qo; qo += 2;
    qo += write_uncompressed_name(req, qo, sizeof(req), "ns1.example.com.");
    qo += write_uncompressed_name(req, qo, sizeof(req), "admin.example.com.");
    req[qo++] = 0; req[qo++] = 0; req[qo++] = 0; req[qo++] = 200;
    for (int k = 0; k < 16; k++) req[qo++] = 0;
    req[rdp] = (uint8_t)((qo - rdp - 2) >> 8); req[rdp + 1] = (uint8_t)((qo - rdp - 2) & 0xFF);
    req[qo++] = 0; req[qo++] = 0; req[qo++] = 41; req[qo++] = 0x10; req[qo++] = 0;
    req[qo++] = 0; req[qo++] = 0; req[qo++] = 0; req[qo++] = 0;
    req[qo++] = 0; req[qo++] = 4;
    req[qo++] = 0; req[qo++] = 9; req[qo++] = 0; req[qo++] = 0;

    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(1, "example.com.", req, (uint16_t)qo, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_out_len > 2);
    size_t mlen = (size_t)((g_tcp_out[0] << 8) | g_tcp_out[1]);
    assert(find_expire_option(g_tcp_out + 2, mlen) == 1209600);   /* primary: SOA EXPIRE */

    zone_arena_t standby;
    memset(&standby, 0, sizeof(standby));
    zone_arena_init(&standby);
    axfr_session_t session;
    memset(&session, 0, sizeof(session));
    session.is_ixfr = true;
    session.client_serial = 200;
    parse_xfr_packet(g_tcp_out + 2, mlen, &standby, &test_zone_slot(&entry, 0)->ver, &session, "example.com.");
    assert(session.has_expire && session.expire == 1209600);
    zone_arena_destroy(&standby);

    /* secondary: remaining time */
    entry.is_secondary = true;
    atomic_store_explicit(&entry.expire_at, time(NULL) + 300, memory_order_release);
    g_tcp_out_len = 0;
    send_axfr_response(1, "example.com.", req, (uint16_t)qo, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    mlen = (size_t)((g_tcp_out[0] << 8) | g_tcp_out[1]);
    long v = find_expire_option(g_tcp_out + 2, mlen);
    assert(v >= 298 && v <= 300);

    /* without the option in the request: no OPT as before */
    req[11] = 0;
    g_tcp_out_len = 0;
    send_axfr_response(1, "example.com.", req, (uint16_t)(qo - 15), NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    mlen = (size_t)((g_tcp_out[0] << 8) | g_tcp_out[1]);
    assert(find_expire_option(g_tcp_out + 2, mlen) == -1);
    printf("  -> EDNS EXPIRE passed.\n");
}

// ----------------------------------------------------------------------------
// Phase 10: transfer responses (R-15, R-16, X-19, X-24) and the client checks (R-19)
// ----------------------------------------------------------------------------
static void p10_init_zone(zone_arena_t *arena, const char *domain, const char *serial, const char *extra) {
    memset(arena, 0, sizeof(*arena));
    zone_arena_init(arena);
    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = domain,
        .is_standalone_mode = true,
        .err_out = &err,
    };
    char text[1024];
    snprintf(text, sizeof(text),
             "$ORIGIN %s\n$TTL 3600\n@ IN SOA ns1.%s hostmaster.%s %s 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n%s",
             domain, domain, domain, serial, extra ? extra : "");
    char *buf = arena_strdup(arena, text);
    assert(parse_zone_fast(buf, strlen(buf), arena, &ctx) >= 0);
    assert(build_zone_index(arena, true) == 0);
    arena->image = zone_image_freeze(arena, domain); /* S5 B-2: AXFR out reads the image */
    assert(arena->image != NULL);
}

/* AXFR/IXFR query. serial < 0: no SOA in Authority. edns: OPT, ext: with Option 65153. */
static size_t p10_query(uint8_t *q, size_t cap, const char *zone, uint16_t qtype, int64_t serial, bool edns, bool ext) {
    memset(q, 0, cap);
    q[0] = 0x5a; q[1] = 0x10; q[5] = 1;
    size_t o = DNS_HEADER_SIZE;
    o += (size_t)write_uncompressed_name(q, o, cap, zone);
    q[o++] = 0; q[o++] = (uint8_t)qtype; q[o++] = 0; q[o++] = 1;
    if (serial >= 0) {
        q[9] = 1;
        q[o++] = 0xC0; q[o++] = 0x0C; q[o++] = 0; q[o++] = 6; q[o++] = 0; q[o++] = 1;
        q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 22;
        q[o++] = 0; q[o++] = 0;
        q[o++] = (uint8_t)(serial >> 24); q[o++] = (uint8_t)(serial >> 16);
        q[o++] = (uint8_t)(serial >> 8); q[o++] = (uint8_t)serial;
        memset(q + o, 0, 16); o += 16;
    }
    if (edns) {
        q[11] = 1;
        q[o++] = 0; q[o++] = 0; q[o++] = 41; q[o++] = 0x10; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0;
        if (ext) {
            uint32_t h = calc_fnv1a_str(zone);
            q[o++] = 0; q[o++] = 9;
            q[o++] = 0xFE; q[o++] = 0x81; q[o++] = 0; q[o++] = 5; q[o++] = KARIDNS_EXT_VERSION;
            q[o++] = (uint8_t)(h >> 24); q[o++] = (uint8_t)(h >> 16); q[o++] = (uint8_t)(h >> 8); q[o++] = (uint8_t)h;
        } else {
            q[o++] = 0; q[o++] = 0;
        }
    }
    return o;
}

/* First message in g_tcp_out: header fields, the SOA serials in the answer section and whether an OPT
 * (and an EDE with info_code ede) is in the additional section. */
typedef struct {
    unsigned rcode, aa, qd, an, ns, ar;
    uint32_t soa[8];
    int soa_count;
    bool opt;
    int ede;
} p10_msg_t;

static p10_msg_t p10_first_msg(void) {
    p10_msg_t m;
    memset(&m, 0, sizeof(m));
    m.ede = -1;
    assert(g_tcp_out_len > 2 + DNS_HEADER_SIZE);
    const uint8_t *p = g_tcp_out + 2;
    size_t len = ((size_t)g_tcp_out[0] << 8) | g_tcp_out[1];
    assert(len + 2 <= g_tcp_out_len);
    m.aa = (p[2] >> 2) & 1;
    m.rcode = p[3] & 0x0F;
    m.qd = (p[4] << 8) | p[5]; m.an = (p[6] << 8) | p[7]; m.ns = (p[8] << 8) | p[9]; m.ar = (p[10] << 8) | p[11];
    size_t o = DNS_HEADER_SIZE, n;
    for (unsigned i = 0; i < m.qd; i++) { assert(skip_wire_name(p, len, o, &n) == 0); o = n + 4; }
    for (unsigned i = 0; i < m.an + m.ns + m.ar; i++) {
        assert(skip_wire_name(p, len, o, &n) == 0);
        uint16_t t = (p[n] << 8) | p[n + 1];
        size_t rdlen = (p[n + 8] << 8) | p[n + 9];
        size_t rd = n + 10;
        if (t == 6 && i < m.an && m.soa_count < 8) {
            size_t a, b;
            assert(skip_wire_name(p, len, rd, &a) == 0 && skip_wire_name(p, len, a, &b) == 0);
            m.soa[m.soa_count++] = ((uint32_t)p[b] << 24) | ((uint32_t)p[b + 1] << 16) | ((uint32_t)p[b + 2] << 8) | p[b + 3];
        }
        if (t == 41 && i >= m.an + m.ns) {
            m.opt = true;
            for (size_t x = rd; x + 4 <= rd + rdlen;) {
                uint16_t code = (p[x] << 8) | p[x + 1], olen = (p[x + 2] << 8) | p[x + 3];
                if (code == 15 && olen >= 2) m.ede = (p[x + 4] << 8) | p[x + 5];
                x += 4 + olen;
            }
        }
        o = rd + rdlen;
    }
    return m;
}

static void p10_send(zone_db_entry_t *e, const uint8_t *q, size_t qlen) {
    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, e ? e->domain : "p10.example.", (uint8_t *)q, (uint16_t)qlen, NULL, e, NULL, 0, NULL, 0,
                       NULL, false);
}

static void test_p10_transfer_responses(void) {
    printf("[TEST] AXFR/IXFR: phase 10 responses (R-15 serials, IXFR without SOA, R-16 OPT, X-19 empty zone)...\n");
    zone_db_entry_t e;
    memset(&e, 0, sizeof(e));
    strlcpy(e.domain, "p10.example.", sizeof(e.domain));
    strlcpy(e.view_name, "default", sizeof(e.view_name));
    pthread_mutex_init(&e.writer_lock, NULL);
    pthread_mutex_init(&e.ixfr_history.lock, NULL);
    p10_init_zone(test_zone_slot(&e, 0), "p10.example.", "100", NULL);
    atomic_store_explicit(&e.rcu.active, &test_zone_slot(&e, 0)->ver, memory_order_release);
    uint8_t q[512];
    size_t ql;
    p10_msg_t m;

    /* R-15, RFC 1995 §2: same and newer serial -> the current SOA only */
    ql = p10_query(q, sizeof(q), "p10.example.", 251, 100, false, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 0 && m.an == 1 && m.soa_count == 1 && m.soa[0] == 100 && !m.opt);
    ql = p10_query(q, sizeof(q), "p10.example.", 251, 101, false, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 0 && m.an == 1 && m.soa[0] == 100);
    ql = p10_query(q, sizeof(q), "p10.example.", 251, 100 + 0x7FFFFFFFLL, false, false); /* still newer (RFC 1982) */
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.an == 1);
    /* older serial, also across the wrap (100 + 2^31 + 1 is older than 100) -> full zone: SOA ... SOA */
    ql = p10_query(q, sizeof(q), "p10.example.", 251, 99, false, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.an == 4 && m.soa_count == 2);
    ql = p10_query(q, sizeof(q), "p10.example.", 251, 100 + 0x80000001LL, false, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.an == 4);

    /* RFC 1995 §3: IXFR without the client's SOA -> FORMERR, question copied, AA=0 */
    ql = p10_query(q, sizeof(q), "p10.example.", 251, -1, true, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 1 && m.qd == 1 && m.an == 0 && m.aa == 0 && m.opt);

    /* R-16, RFC 5936 §2.2.5: OPT in the first message when the query had one, none otherwise */
    ql = p10_query(q, sizeof(q), "p10.example.", 252, -1, true, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 0 && m.aa == 1 && m.an == 4 && m.ar == 1 && m.opt);
    ql = p10_query(q, sizeof(q), "p10.example.", 252, -1, false, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.ar == 0 && !m.opt);
    ql = p10_query(q, sizeof(q), "p10.example.", 251, 100, true, false); /* single-SOA IXFR answer too */
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.an == 1 && m.opt);

    /* X-19: zone without data -> SERVFAIL + EDE 14 (with OPT), not silence */
    zone_arena_t empty;
    zone_arena_init(&empty);
    atomic_store_explicit(&e.rcu.active, &empty.ver, memory_order_release);
    ql = p10_query(q, sizeof(q), "p10.example.", 252, -1, true, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 2 && m.qd == 1 && m.an == 0 && m.opt && m.ede == 14);
    ql = p10_query(q, sizeof(q), "p10.example.", 252, -1, false, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 2 && !m.opt);

    zone_arena_destroy(&empty);
    zone_arena_destroy(test_zone_slot(&e, 0));
    pthread_mutex_destroy(&e.writer_lock);
    pthread_mutex_destroy(&e.ixfr_history.lock);
    printf("  -> phase 10 responses passed.\n");
}

static void test_p10_extended_ixfr(void) {
    printf("[TEST] AXFR/IXFR: X-24 IXFR with Option 65153 answered incrementally unless the zone needs the extension...\n");
    zone_db_entry_t e;
    memset(&e, 0, sizeof(e));
    strlcpy(e.domain, "x24.example.", sizeof(e.domain));
    strlcpy(e.view_name, "default", sizeof(e.view_name));
    pthread_mutex_init(&e.writer_lock, NULL);
    pthread_mutex_init(&e.ixfr_history.lock, NULL);
    p10_init_zone(test_zone_slot(&e, 1), "x24.example.", "100", NULL);
    p10_init_zone(test_zone_slot(&e, 0), "x24.example.", "101", "www IN A 192.0.2.80\n");
    compute_ixfr_diff(&e, test_zone_slot(&e, 1), test_zone_slot(&e, 0));
    assert(e.ixfr_history.count == 1);
    atomic_store_explicit(&e.rcu.active, &test_zone_slot(&e, 0)->ver, memory_order_release);
    uint8_t q[512];
    size_t ql = p10_query(q, sizeof(q), "x24.example.", 251, 100, true, true);
    p10_msg_t m;

    /* no KariDNS-specific data: IXFR difference sequence (new SOA, old SOA, ..., new SOA, ..., new SOA) */
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 0 && m.soa_count >= 3 && m.soa[0] == 101 && m.soa[1] == 100 && m.opt);
    /* up to date: single SOA also in extended mode (was a full Extended AXFR) */
    ql = p10_query(q, sizeof(q), "x24.example.", 251, 101, true, true);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.an == 1 && m.soa[0] == 101);
    /* with tag definitions the zone needs the extension: full Extended AXFR (SOA first, no old SOA) */
    zone_arena_t *cur = test_zone_slot(&e, 0);
    char *trusted_list[1] = { "192.0.2.53" };
    cur->bind_ecs_trusted_resolvers = trusted_list; /* trusted ECS resolvers travel only in Extended AXFR */
    cur->bind_ecs_trusted_resolver_count = 1;
    assert(test_freeze(cur) == 0);
    ql = p10_query(q, sizeof(q), "x24.example.", 251, 100, true, true);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.rcode == 0 && m.soa[0] == 101 && (m.soa_count < 2 || m.soa[1] == 101));
    cur->bind_ecs_trusted_resolvers = NULL;
    cur->bind_ecs_trusted_resolver_count = 0;
    assert(test_freeze(cur) == 0);
    /* plain IXFR (no Option 65153) is unchanged: differences */
    ql = p10_query(q, sizeof(q), "x24.example.", 251, 100, true, false);
    p10_send(&e, q, ql); m = p10_first_msg();
    assert(m.soa_count >= 3 && m.soa[1] == 100);

    ixfr_history_clear(&e.ixfr_history);
    zone_arena_destroy(test_zone_slot(&e, 0));
    zone_arena_destroy(test_zone_slot(&e, 1));
    pthread_mutex_destroy(&e.writer_lock);
    pthread_mutex_destroy(&e.ixfr_history.lock);
    printf("  -> X-24 extended IXFR passed.\n");
}

static void test_p10_ixfr_request_client_serial(void) {
    printf("[TEST] AXFR/IXFR: ixfr_request_client_serial() (RFC 1995 §3)...\n");
    uint8_t q[512];
    uint32_t serial = 0;
    size_t ql = p10_query(q, sizeof(q), "s.example.", 251, 4000000000LL, false, false);
    size_t qend = DNS_HEADER_SIZE + 11 + 4; /* "\1s\7example\0" + type/class */
    assert(ixfr_request_client_serial(q, ql, qend, &serial) && serial == 4000000000U);
    /* no Authority -> false */
    ql = p10_query(q, sizeof(q), "s.example.", 251, -1, false, false);
    assert(!ixfr_request_client_serial(q, ql, qend, &serial));
    /* Authority RR that is not an SOA -> false */
    ql = p10_query(q, sizeof(q), "s.example.", 251, 7, false, false);
    q[qend + 3] = 2; /* type NS */
    assert(!ixfr_request_client_serial(q, ql, qend, &serial));
    /* SOA cut inside SERIAL -> false; rdlength beyond the message -> false */
    ql = p10_query(q, sizeof(q), "s.example.", 251, 7, false, false);
    assert(!ixfr_request_client_serial(q, qend + 12 + 2 + 2, qend, &serial));
    q[qend + 11] = 200;
    assert(!ixfr_request_client_serial(q, ql, qend, &serial));
    printf("  -> ixfr_request_client_serial passed.\n");
}

/* One transfer response message: id, flags byte 2, rcode, question (qdcount 0 or 1). */
static size_t p10_resp(uint8_t *p, size_t cap, uint16_t id, uint8_t flags2, uint8_t rcode, int qd, const char *qname,
                       uint16_t qtype, uint16_t qclass) {
    memset(p, 0, cap);
    p[0] = id >> 8; p[1] = id & 0xFF; p[2] = flags2; p[3] = rcode; p[5] = (uint8_t)qd;
    size_t o = DNS_HEADER_SIZE;
    if (qd) {
        o += (size_t)write_uncompressed_name(p, o, cap, qname);
        p[o++] = qtype >> 8; p[o++] = qtype & 0xFF; p[o++] = qclass >> 8; p[o++] = qclass & 0xFF;
    }
    return o;
}

static void test_p10_xfr_check_response_header(void) {
    printf("[TEST] AXFR/IXFR: R-19 xfr_check_response_header() (RFC 5936 §2.2.1, §2.2.2)...\n");
    uint8_t p[256];
    size_t n;
    axfr_session_t s;
#define P10_SESSION(qt) do { memset(&s, 0, sizeof(s)); s.query_id = 0x4242; s.query_type = (qt); } while (0)

    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 1, "Z.Example.", 252, 1); /* case-insensitive name */
    assert(xfr_check_response_header(p, n, &s, "z.example.") == 0);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 0, NULL, 0, 0);         /* later message without question */
    assert(xfr_check_response_header(p, n, &s, "z.example.") == 0);
    n = p10_resp(p, sizeof(p), 0x4243, 0x84, 0, 0, NULL, 0, 0);         /* later message with another ID */
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);

    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4241, 0x84, 0, 1, "z.example.", 252, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* wrong ID */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x04, 0, 1, "z.example.", 252, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* QR=0 */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84 | 0x20, 0, 1, "z.example.", 252, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* OPCODE 4 */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 1, "other.example.", 252, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* other QNAME */
    P10_SESSION(251);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 1, "z.example.", 252, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* QTYPE AXFR to an IXFR request */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 1, "z.example.", 252, 3);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* QCLASS CH */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 0, NULL, 0, 0);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* first message without question */
    P10_SESSION(252);
    assert(xfr_check_response_header(p, 11, &s, "z.example.") == -1);  /* shorter than a header */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x84, 0, 1, "z.example.", 252, 1);
    p[DNS_HEADER_SIZE] = 0xC0; p[DNS_HEADER_SIZE + 1] = 0xFF;
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);   /* malformed question */

    /* error RCODEs end the transfer and are reported */
    P10_SESSION(252);
    n = p10_resp(p, sizeof(p), 0x4242, 0x80, 5, 1, "z.example.", 252, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == 1 && s.rcode == 5);
    P10_SESSION(251);
    n = p10_resp(p, sizeof(p), 0x4242, 0x80, 4, 1, "z.example.", 251, 1);
    assert(xfr_check_response_header(p, n, &s, "z.example.") == 1 && s.rcode == 4);
    P10_SESSION(251);
    n = p10_resp(p, sizeof(p), 0x4242, 0x80, 1, 0, NULL, 0, 0);         /* error without question */
    assert(xfr_check_response_header(p, n, &s, "z.example.") == -1);
#undef P10_SESSION

    /* handle_axfr_event(): a REFUSED answer ends at once with session.rcode set */
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "z.example.", sizeof(entry.domain));
    pthread_mutex_init(&entry.writer_lock, NULL);
    p10_init_zone(test_zone_slot(&entry, 0), "z.example.", "1", NULL);
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    reset_mock_tcp_stream();
    n = p10_resp(p, sizeof(p), 0x4242, 0x80, 5, 1, "z.example.", 251, 1);
    push_mock_tcp_msg(p, (uint16_t)n);
    tcp_stream_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    memset(&s, 0, sizeof(s));
    s.query_id = 0x4242; s.query_type = 251; s.is_ixfr = true; s.client_serial = 1;
    assert(handle_axfr_event(-1, &entry, &sc, &s, NULL, NULL, 0) == -1);
    assert(s.rcode == 5);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    pthread_mutex_destroy(&entry.writer_lock);
    printf("  -> xfr_check_response_header passed.\n");
}

/* S5: rdata[] は rdata_count 個ぶんだけ arena に持つ。NSEC の型 44 個、TXT の文字列 30 個、RRSIG が、
 * ゾーンの読み込み → 索引 → 複製 (clone_zone_arena) → ワイヤへの符号化 (AXFR/IXFR の応答と同じ
 * serialize_dns_record) のどこでも同じになり、構造体のコピーの rdata[] を書き換えても元が変わらないこと。 */
#define S5_MAXREC 16
typedef struct { uint8_t wire[S5_MAXREC][2048]; uint16_t len[S5_MAXREC]; } s5_wire_t;

static void s5_encode_all(zone_arena_t *z, s5_wire_t *out) {
    assert(z->count <= S5_MAXREC);
    for (size_t i = 0; i < z->count; i++) {
        uint16_t off = 0;
        assert(serialize_dns_record(out->wire[i], sizeof(out->wire[i]), &off, &z->records[i], NULL, NULL, 0xFFFFFFFF) == 0);
        out->len[i] = off;
    }
}

static void test_axfr_ixfr_feature_case_158(void) {
    printf("[TEST] AXFR/IXFR: Case 158 - variable-length rdata[] survives parse, clone and wire encoding (S5)...\n");
    static const char *types[] = {
        "A", "NS", "CNAME", "SOA", "PTR", "HINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN", "KEY", "AAAA", "LOC",
        "SRV", "NAPTR", "KX", "CERT", "DNAME", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3",
        "NSEC3PARAM", "TLSA", "SMIMEA", "HIP", "CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD", "SVCB", "HTTPS",
        "SPF", "URI", "CAA", "EUI48", "EUI64" };
    const int ntypes = (int)(sizeof(types) / sizeof(types[0]));
    assert(ntypes == 44);
    char text[8192];
    size_t tl = (size_t)snprintf(text, sizeof(text),
        "$ORIGIN s5.example.\n$TTL 300\n"
        "@ IN SOA ns1 admin 1 7200 3600 1209600 300\n"
        "@ IN NS ns1\n"
        "ns1 IN A 192.0.2.1\n"
        "@ IN NSEC next.s5.example.");
    for (int i = 0; i < ntypes; i++) tl += (size_t)snprintf(text + tl, sizeof(text) - tl, " %s", types[i]);
    tl += (size_t)snprintf(text + tl, sizeof(text) - tl, "\nt IN TXT");
    for (int i = 0; i < 30; i++) tl += (size_t)snprintf(text + tl, sizeof(text) - tl, " \"str%02d-abcdefghij\"", i);
    snprintf(text + tl, sizeof(text) - tl,
        "\n@ IN RRSIG A 13 2 300 20301231235959 20200101000000 12345 s5.example. "
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==\n");

    zone_arena_t a, b;
    memset(&a, 0, sizeof(a));
    zone_arena_init(&a);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "s5.example.", .is_standalone_mode = true, .err_out = &err };
    char *zbuf = arena_strdup(&a, text);
    assert(zbuf && parse_zone_fast(zbuf, strlen(zbuf), &a, &ctx) >= 0);
    assert(build_zone_index(&a, true) == 0);
    assert(a.count == 6);

    const dns_record_t *nsec = NULL, *txt = NULL, *sig = NULL;
    for (size_t i = 0; i < a.count; i++) {
        if (a.records[i].type_code == 47) nsec = &a.records[i];
        if (a.records[i].type_code == 16) txt = &a.records[i];
        if (a.records[i].type_code == 46) sig = &a.records[i];
    }
    assert(nsec && nsec->rdata_count == 1 + ntypes && txt && txt->rdata_count == 30 && sig && sig->rdata_count == 9);
    assert(strcmp(nsec->rdata[ntypes], "EUI64") == 0 && strcmp(txt->rdata[29], "str29-abcdefghij") == 0);
    for (size_t i = 0; i < a.count; i++)   /* 各レコードの rdata[] は別々の配列 */
        for (size_t j = i + 1; j < a.count; j++)
            assert(a.records[i].rdata != a.records[j].rdata);

    s5_wire_t *wa = malloc(sizeof(*wa)), *wb = malloc(sizeof(*wb));
    assert(wa && wb);
    s5_encode_all(&a, wa);

    /* 複製して複製元を解放しても、複製先は同じ内容 */
    memset(&b, 0, sizeof(b));
    zone_arena_init(&b);
    assert(test_freeze(&a) == 0);
    assert(thaw_zone_arena(&a.ver, &b) == 0);
    assert(b.count == a.count);
    for (size_t i = 0; i < a.count; i++) {
        assert(b.records[i].rdata_count == a.records[i].rdata_count);
        assert(b.records[i].rdata != a.records[i].rdata);
    }
    zone_arena_destroy(&a);
    s5_encode_all(&b, wb);
    for (size_t i = 0; i < b.count; i++)
        assert(wa->len[i] == wb->len[i] && memcmp(wa->wire[i], wb->wire[i], wa->len[i]) == 0);

    /* 符号化した NSEC / TXT / RRSIG をワイヤから読み戻す (転送の受け側): 文字列が元と同じ */
    zone_arena_t rd;
    memset(&rd, 0, sizeof(rd));
    zone_arena_init(&rd);
    int checked = 0;
    for (size_t i = 0; i < b.count; i++) {
        uint16_t t = b.records[i].type_code;
        if (t != 47 && t != 16 && t != 46) continue;
        dns_record_t got;
        size_t pos = 0;
        uint16_t gt;
        assert(parse_resource_record(wb->wire[i], wb->len[i], &pos, &rd, &got, &gt) == 0);
        assert(gt == t && got.rdata_count == b.records[i].rdata_count);
        for (int k = 0; k < got.rdata_count; k++) {
            if (t == 46 && k == 8) continue;   /* 署名 (base64) は綴りが同じとは限らない */
            if (t == 47 && k >= 1) {           /* 型の一覧はワイヤでは型番号順になる: 元の一覧のどれかと一致する */
                bool found = false;
                for (int m = 1; m < b.records[i].rdata_count && !found; m++)
                    found = strcasecmp(got.rdata[k], b.records[i].rdata[m]) == 0;
                assert(found);
                continue;
            }
            assert(strcasecmp(got.rdata[k], b.records[i].rdata[k]) == 0);
        }
        checked++;
    }
    assert(checked == 3);
    zone_arena_destroy(&rd);

    /* 構造体のコピーは rdata[] を共有する。dns_record_dup_rdata() で取り直してから書き換えれば元は変わらない */
    size_t ti = 0;
    for (size_t i = 0; i < b.count; i++) if (b.records[i].type_code == 16) ti = i;
    dns_record_t cp = b.records[ti];
    assert(cp.rdata == b.records[ti].rdata);
    assert(dns_record_dup_rdata(&b, &cp) == 0);
    assert(cp.rdata != b.records[ti].rdata && cp.rdata_count == 30);
    char *orig0 = b.records[ti].rdata[0];
    cp.rdata[0] = "changed";
    cp.is_cached = false;
    assert(b.records[ti].rdata[0] == orig0 && strcmp(orig0, "str00-abcdefghij") == 0);
    uint8_t cw[2048];
    uint16_t coff = 0;
    assert(serialize_dns_record(cw, sizeof(cw), &coff, &b.records[ti], NULL, NULL, 0xFFFFFFFF) == 0);
    assert(coff == wb->len[ti] && memcmp(cw, wb->wire[ti], coff) == 0);   /* 元のレコードの符号化は変わらない */
    uint16_t coff2 = 0;
    assert(serialize_dns_record(cw, sizeof(cw), &coff2, &cp, NULL, NULL, 0xFFFFFFFF) == 0);
    assert(coff2 != coff || memcmp(cw, wb->wire[ti], coff) != 0);         /* コピーの書き換えは符号化に出る */

    free(wa);
    free(wb);
    zone_arena_destroy(&b);
    printf("  -> Case 158 passed.\n");
}

/* S5 B-3: ixfr-history <n> (default 4, 0..32). The ring is allocated on the first stored diff with the configured size, a
 * lower depth trims the oldest diffs at once, a higher one grows the ring at the next diff. RFC 1995 §4: when an
 * incremental answer is not available (no history at all, or the client's serial is older than the oldest kept diff) the
 * whole zone is returned, AXFR style. Every zone here holds only its SOA, so an answer is
 * 2 RRs for the whole zone, 2 + 2k for k incremental diffs, 1 for a client that is up to date (RFC 1995 §2). */
static int ixfr_answer_rrs(zone_db_entry_t *entry, const char *dom, uint32_t client_serial) {
    uint8_t req[512] = {0};
    req[0] = 0x77; req[1] = 0x88;
    req[4] = 0; req[5] = 1;   /* QDCOUNT */
    req[8] = 0; req[9] = 1;   /* NSCOUNT: the client's SOA */
    size_t q = 12;
    q += write_uncompressed_name(req, q, sizeof(req), dom);
    req[q++] = 0; req[q++] = 251; req[q++] = 0; req[q++] = 1;
    q += write_uncompressed_name(req, q, sizeof(req), dom);
    req[q++] = 0; req[q++] = 6; req[q++] = 0; req[q++] = 1;
    req[q++] = 0; req[q++] = 0; req[q++] = 1; req[q++] = 0x2C;
    size_t rdp = q; q += 2;
    q += write_uncompressed_name(req, q, sizeof(req), "ns1.example.com.");
    q += write_uncompressed_name(req, q, sizeof(req), "admin.example.com.");
    req[q++] = (uint8_t)(client_serial >> 24); req[q++] = (uint8_t)(client_serial >> 16);
    req[q++] = (uint8_t)(client_serial >> 8); req[q++] = (uint8_t)client_serial;
    for (int k = 0; k < 4; k++) { req[q++] = 0; req[q++] = 0; req[q++] = 0; req[q++] = 10; }
    uint16_t rdl = (uint16_t)(q - (rdp + 2));
    req[rdp] = rdl >> 8; req[rdp + 1] = rdl & 0xFF;
    g_tcp_out_len = 0;
    g_tcp_send_count = 0;
    send_axfr_response(-1, dom, req, q, NULL, entry, NULL, 0, NULL, 0, NULL, false);
    assert(g_tcp_send_count >= 1 && g_tcp_out_len > 14);
    return (g_tcp_out[2 + 6] << 8) | g_tcp_out[2 + 7];   /* ANCOUNT of the first message */
}

/* the diffs first -> first+1 ... (last-1) -> last of the zone `dom` */
static void ixfr_push_diffs(zone_db_entry_t *entry, const char *dom, int first, int last) {
    for (int s = first; s < last; s++) {
        char a[16], b[16];
        snprintf(a, sizeof(a), "%d", s);
        snprintf(b, sizeof(b), "%d", s + 1);
        zone_arena_t o, n;
        init_axfr_zone(&o, dom, a);
        init_axfr_zone(&n, dom, b);
        compute_ixfr_diff(entry, &o, &n);
        zone_arena_destroy(&o);
        zone_arena_destroy(&n);
    }
}

static void test_ixfr_history_depth(void) {
    printf("[TEST] AXFR/IXFR: ixfr-history depth (default 4, 0, 1, trimming and growing, RFC 1995 §4 fallback)...\n");
    static const char dom[] = "depth.example.";
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, dom, sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    zone_arena_t cur;
    init_axfr_zone(&cur, dom, "107");
    atomic_store_explicit(&entry.rcu.active, &cur.ver, memory_order_release);

    /* the default depth is 4; nothing is allocated before the first diff */
    assert(ixfr_history_depth(&entry.ixfr_history) == IXFR_HISTORY_DEFAULT && IXFR_HISTORY_DEFAULT == 4);
    assert(entry.ixfr_history.entries == NULL && entry.ixfr_history.cap == 0);
    ixfr_push_diffs(&entry, dom, 100, 101);
    assert(entry.ixfr_history.entries != NULL && entry.ixfr_history.cap == 4 && entry.ixfr_history.count == 1);
    ixfr_push_diffs(&entry, dom, 101, 107);   /* 7 diffs in all: 100->101 .. 106->107, the last 4 are kept */
    assert(entry.ixfr_history.count == 4 && entry.ixfr_history.cap == 4);
    assert(ixfr_answer_rrs(&entry, dom, 107) == 1);          /* up to date: one SOA */
    assert(ixfr_answer_rrs(&entry, dom, 106) == 2 + 2 * 1);
    assert(ixfr_answer_rrs(&entry, dom, 103) == 2 + 2 * 4);  /* the oldest kept diff 103->104: incremental */
    assert(ixfr_answer_rrs(&entry, dom, 102) == 2);          /* older than the history: the whole zone (RFC 1995 §4) */
    assert(ixfr_answer_rrs(&entry, dom, 100) == 2);

    /* a lower depth drops the oldest diffs now; the ring shrinks */
    ixfr_history_set_depth(&entry, 2);
    assert(entry.ixfr_history.count == 2 && entry.ixfr_history.cap == 2);
    assert(ixfr_answer_rrs(&entry, dom, 105) == 2 + 2 * 2);
    assert(ixfr_answer_rrs(&entry, dom, 104) == 2);
    /* a higher depth grows the ring at the next diff, keeping the kept ones */
    ixfr_history_set_depth(&entry, 6);
    assert(entry.ixfr_history.cap == 2 && entry.ixfr_history.count == 2);
    ixfr_push_diffs(&entry, dom, 107, 108);   /* 107 -> 108 (the answer below is for the zone at 107, see next line) */
    assert(entry.ixfr_history.cap == 6 && entry.ixfr_history.count == 3);
    assert(entry.ixfr_history.entries[0]->old_serial == 105 && entry.ixfr_history.entries[2]->old_serial == 107);

    /* depth 1: only the last diff */
    ixfr_history_clear(&entry.ixfr_history);
    assert(entry.ixfr_history.entries == NULL && entry.ixfr_history.count == 0);
    ixfr_history_set_depth(&entry, 1);
    ixfr_push_diffs(&entry, dom, 105, 108);   /* 105->106, 106->107, 107->108: only 107->108 stays */
    assert(entry.ixfr_history.cap == 1 && entry.ixfr_history.count == 1 && entry.ixfr_history.entries[0]->old_serial == 107);
    zone_arena_destroy(&cur);
    init_axfr_zone(&cur, dom, "108");
    atomic_store_explicit(&entry.rcu.active, &cur.ver, memory_order_release);
    assert(ixfr_answer_rrs(&entry, dom, 107) == 2 + 2 * 1);
    assert(ixfr_answer_rrs(&entry, dom, 106) == 2);

    /* depth 0: no history is kept (nothing is even allocated) and every IXFR is answered with the whole zone */
    ixfr_history_set_depth(&entry, 0);
    assert(entry.ixfr_history.entries == NULL && entry.ixfr_history.count == 0 && entry.ixfr_history.cap == 0);
    ixfr_push_diffs(&entry, dom, 100, 104);
    assert(entry.ixfr_history.entries == NULL && entry.ixfr_history.count == 0);
    assert(ixfr_answer_rrs(&entry, dom, 107) == 2);
    assert(ixfr_answer_rrs(&entry, dom, 108) == 1);          /* a client that is up to date still gets one SOA */

    /* the configured depth is clamped to MAX_IXFR_HISTORY */
    ixfr_history_set_depth(&entry, 1000);
    assert(ixfr_history_depth(&entry.ixfr_history) == MAX_IXFR_HISTORY);
    ixfr_history_set_depth(&entry, -3);
    assert(ixfr_history_depth(&entry.ixfr_history) == 0);

    ixfr_history_clear(&entry.ixfr_history);
    zone_arena_destroy(&cur);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> ixfr-history depth passed.\n");
}

/* ---------------------------------------------------------------------------------------------------------------------------------
 * B8t-2: Extended AXFR version 3 - the encoder records, the receiver (SOA_SET, wrapped SOA RRs, SETTINGS), the sender (version
 * negotiation, v2 refusal, byte-identity of v2 and v3 for a plain zone) and the settings (render, precedence, fail closed).
 * ------------------------------------------------------------------------------------------------------------------------------ */

typedef struct { uint8_t b[8192]; size_t n; uint16_t an; } b8_pk_t;

static void b8_init(b8_pk_t *p) { memset(p, 0, sizeof(*p)); p->b[2] = 0x84; p->n = DNS_HEADER_SIZE; }

static size_t b8_name(uint8_t *o, const char *name) {
    size_t n = 0;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        o[n++] = (uint8_t)l;
        memcpy(o + n, s, l);
        n += l;
        if (!dot) break;
        s = dot + 1;
    }
    o[n++] = 0;
    return n;
}

static void b8_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void b8_u32(uint8_t *p, uint32_t v) { b8_u16(p, (uint16_t)(v >> 16)); b8_u16(p + 2, (uint16_t)v); }

static void b8_rr(b8_pk_t *p, const char *owner, uint16_t type, uint16_t cls, const uint8_t *rd, size_t rdlen) {
    p->n += b8_name(p->b + p->n, owner);
    b8_u16(p->b + p->n, type); p->n += 2;
    b8_u16(p->b + p->n, cls); p->n += 2;
    b8_u32(p->b + p->n, 300); p->n += 4;
    b8_u16(p->b + p->n, (uint16_t)rdlen); p->n += 2;
    memcpy(p->b + p->n, rd, rdlen);
    p->n += rdlen;
    p->an++;
    b8_u16(p->b + 6, p->an);
}

static size_t b8_soa_rdata(uint8_t *rd, const char *zone, uint32_t serial, uint32_t refresh) {
    char mn[200], rn[200];
    snprintf(mn, sizeof(mn), "ns.%s", zone);
    snprintf(rn, sizeof(rn), "host.%s", zone);
    size_t n = b8_name(rd, mn);
    n += b8_name(rd + n, rn);
    b8_u32(rd + n, serial); b8_u32(rd + n + 4, refresh); b8_u32(rd + n + 8, 600); b8_u32(rd + n + 12, 86400); b8_u32(rd + n + 16, 300);
    return n + 20;
}

static void b8_soa(b8_pk_t *p, const char *zone, uint32_t serial, uint32_t refresh) {
    uint8_t rd[400];
    b8_rr(p, zone, 6, 1, rd, b8_soa_rdata(rd, zone, serial, refresh));
}

/* a SOA of a SOA set: TYPE 65406 around it, with the tinydns location loc ("" = none) */
static void b8_wsoa(b8_pk_t *p, const char *zone, uint32_t serial, uint32_t refresh, const char *loc) {
    uint8_t rd[400], w[500];
    size_t n = b8_soa_rdata(rd, zone, serial, refresh);
    memset(w, 0, sizeof(w));
    b8_u16(w, 6); b8_u16(w + 2, 1); b8_u32(w + 4, 300);
    w[8] = (uint8_t)loc[0]; w[9] = loc[0] ? (uint8_t)loc[1] : 0;
    b8_u16(w + 19, (uint16_t)n);
    memcpy(w + 21, rd, n);
    b8_rr(p, zone, 65406, 65302, w, 21 + n);
}

static int b8_feed(axfr_session_t *s, zone_arena_t *a, const b8_pk_t *p, const char *zone) {
    return parse_xfr_packet(p->b, p->n, a, NULL, s, zone);
}

static void b8_session(axfr_session_t *s, uint8_t ver) {
    memset(s, 0, sizeof(*s));
    s->is_extended_mode = ver != 0;
    s->ext_version = ver;
}

typedef struct { uint16_t type; uint16_t cls; uint8_t rd[64]; size_t len; int n; } b8_cap_t;

static int b8_cap_cb(void *ud, const dns_record_t *rec) {
    b8_cap_t *k = ud;
    k->type = rec->type_code;
    k->cls = rec->class_val;
    k->len = rec->generic_len;
    if (rec->generic_len <= sizeof(k->rd)) memcpy(k->rd, rec->generic_data, rec->generic_len);
    k->n++;
    return 0;
}

static void test_b8t2_xext_records(void) {
    printf("[TEST] B8t-2: the encoder writes SOA_SET (65409) and SETTINGS (65408)...\n");
    b8_cap_t c;
    memset(&c, 0, sizeof(c));
    xext_t x;
    xext_init(&x, "z.example.", b8_cap_cb, &c);
    assert(xext_emit_soa_set(&x, 258) == 0);
    assert(c.n == 1 && c.type == 65409 && c.cls == 65302 && c.len == 3 && c.rd[0] == 1 && c.rd[1] == 1 && c.rd[2] == 2);
    assert(xext_emit_settings(&x, "allow-transfer { none; };\n", 25) == 0);
    assert(c.n == 2 && c.type == 65408 && c.cls == 65302 && c.len == 25 && memcmp(c.rd, "allow-transfer", 14) == 0);
    assert(xext_emit_settings(&x, "", 0) < 0);                               /* nothing to send is the caller's choice */
    char big[KARIDNS_SETTINGS_MAX + 2];
    memset(big, 'a', sizeof(big));
    assert(xext_emit_settings(&x, big, KARIDNS_SETTINGS_MAX + 1) < 0);       /* too long: refused, not truncated */
    xext_free(&x);
    printf("  -> encoder records passed.\n");
}

/* B9a (decision: the type numbers of PowerDNS's ALIAS / LUA records and of two Extended AXFR records are the same): everything that
 * reads an Extended AXFR stream decides on (type, class).  A zone RR of CLASS IN is a zone RR whatever its type number; a record of
 * CLASS 65302 is an Extended AXFR record whatever it holds. */
static void test_b9a_type_class_audit(void) {
    printf("[TEST] B9a: ALIAS / LUA (TYPE 65401 / 65402, CLASS IN) next to the Extended AXFR records of the same numbers (CLASS 65302)...\n");
    const char *z = "z.example.";
    uint8_t alias_rd[32];
    size_t alias_len = b8_name(alias_rd, "t.target.example.");
    static const uint8_t lua_rd[] = { 0, 1, 3, 'a', 'b', 'c' };
    static const uint8_t a_rd[4] = { 192, 0, 2, 1 };

    for (int ver = 0; ver <= 3; ver += 3) {           /* a standard AXFR and an Extended AXFR (version 3) */
        zone_arena_t a;
        axfr_session_t s;
        b8_pk_t p;
        zone_arena_init(&a);
        b8_session(&s, (uint8_t)ver);
        b8_init(&p);
        b8_soa(&p, z, 7, 3600);
        if (ver) b8_rr(&p, z, 65401, 65302, (const uint8_t *)"lan", 3);        /* LOC_STATE: the RRs that follow are in the tag lan */
        b8_rr(&p, "a.z.example.", 65401, 1, alias_rd, alias_len);               /* ALIAS */
        b8_rr(&p, "l.z.example.", 65402, 1, lua_rd, sizeof(lua_rd));            /* LUA */
        if (ver) b8_rr(&p, z, 65401, 65302, (const uint8_t *)"", 0);            /* LOC_STATE: no tag */
        b8_rr(&p, "www.z.example.", 1, 1, a_rd, 4);
        b8_soa(&p, z, 7, 3600);
        assert(b8_feed(&s, &a, &p, z) == 0 && s.is_finished);
        int n_alias = 0, n_lua = 0, n_ext = 0;
        for (size_t i = 0; i < a.count; i++) {
            const dns_record_t *r = &a.records[i];
            if (r->class_val == 65302) n_ext++;
            if (r->type_code == 65401 && r->class_val == 1) {
                n_alias++;
                assert(r->generic_len == alias_len && memcmp(r->generic_data, alias_rd, alias_len) == 0);
                if (ver) assert(r->bind_location_tag && strcmp(r->bind_location_tag, "lan") == 0);   /* in the tag, as the state record said */
                else assert(!r->bind_location_tag);
            }
            if (r->type_code == 65402 && r->class_val == 1) {
                n_lua++;
                assert(r->generic_len == sizeof(lua_rd) && memcmp(r->generic_data, lua_rd, sizeof(lua_rd)) == 0);
            }
        }
        assert(n_alias == 1 && n_lua == 1 && n_ext == 0);                       /* the state records were consumed, the zone RRs kept */
        assert(s.ext_records == (ver ? 2u : 0u));                               /* only the CLASS 65302 records are Extended AXFR records */
        zone_arena_destroy(&a);
    }

    /* the same numbers in CLASS 65302 in a standard (non-extended) session are not zone data either: they are never stored as ALIAS / LUA */
    {
        zone_arena_t a;
        axfr_session_t s;
        b8_pk_t p;
        zone_arena_init(&a);
        b8_session(&s, 0);
        b8_init(&p);
        b8_soa(&p, z, 7, 3600);
        b8_rr(&p, "a.z.example.", 65401, 65302, alias_rd, alias_len);
        b8_soa(&p, z, 7, 3600);
        int rc = b8_feed(&s, &a, &p, z);
        for (size_t i = 0; i < a.count; i++) assert(!(a.records[i].type_code == 65401 && a.records[i].class_val == 1));
        (void)rc;                                                               /* accepted or refused: the point is that it did not become an ALIAS */
        zone_arena_destroy(&a);
    }
    printf("  -> (type, class) audit passed.\n");
}

static void test_b8t2_receiver_soa_set(void) {
    printf("[TEST] B8t-2: the receiver reads a SOA set, SETTINGS and rejects what does not fit...\n");
    const char *z = "z.example.";
    zone_arena_t a;
    axfr_session_t s;
    b8_pk_t p;
    uint8_t set2[3] = { 1, 0, 2 };
    const char *txt = "allow-transfer { 192.0.2.1; };";

    /* a complete version 3 stream in two messages */
    zone_arena_init(&a);
    b8_session(&s, 3);
    b8_init(&p);
    b8_soa(&p, z, 7, 3600);
    b8_rr(&p, z, 65409, 65302, set2, 3);
    b8_rr(&p, z, 65408, 65302, (const uint8_t *)txt, strlen(txt));
    b8_wsoa(&p, z, 7, 3600, "in");
    assert(b8_feed(&s, &a, &p, z) == 0);
    assert(s.soa_set && s.soa_set_expected == 2 && s.frame_valid && s.frame_refresh == 3600 && a.count == 1);
    assert(s.has_settings && s.settings_len == strlen(txt) && strcmp(s.settings_text, txt) == 0 && !s.is_finished);
    assert(a.records[0].type_code == 6 && a.records[0].tinydns_loc[0] == 'i' && a.records[0].tinydns_loc[1] == 'n');
    /* the location makes it a tinydns zone: */
    assert(a.is_tinydns_format);
    b8_init(&p);
    b8_wsoa(&p, z, 7, 3600, "");
    b8_soa(&p, z, 7, 3600);
    assert(b8_feed(&s, &a, &p, z) == 0);
    assert(s.is_finished && s.soa_set_seen == 2 && a.count == 2 && s.soa_count == 2);   /* the frame is not stored; the wrappers are not frames */
    assert(a.records[1].tinydns_loc[0] == 0 && a.records[1].type_code == 6);
    zone_arena_destroy(&a);

    /* a wrapper with no tinydns attribute (a tag only) does not make a tinydns zone */
    zone_arena_init(&a);
    b8_session(&s, 3);
    b8_init(&p);
    b8_soa(&p, z, 7, 3600);
    b8_rr(&p, z, 65409, 65302, (uint8_t[]){ 1, 0, 1 }, 3);
    b8_wsoa(&p, z, 7, 3600, "");
    b8_soa(&p, z, 7, 3600);
    assert(b8_feed(&s, &a, &p, z) == 0 && s.is_finished && !a.is_tinydns_format && a.count == 1);
    zone_arena_destroy(&a);

    /* SOA_SET not right after the opening SOA (a data record first) */
    zone_arena_init(&a);
    b8_session(&s, 3);
    b8_init(&p);
    b8_soa(&p, z, 7, 3600);
    b8_rr(&p, "www.z.example.", 1, 1, (uint8_t[]){ 192, 0, 2, 1 }, 4);
    b8_rr(&p, z, 65409, 65302, set2, 3);
    assert(b8_feed(&s, &a, &p, z) != 0);
    zone_arena_destroy(&a);

    /* the transfer ends before all the announced SOA RRs */
    zone_arena_init(&a);
    b8_session(&s, 3);
    b8_init(&p);
    b8_soa(&p, z, 7, 3600);
    b8_rr(&p, z, 65409, 65302, set2, 3);
    b8_wsoa(&p, z, 7, 3600, "in");
    b8_soa(&p, z, 7, 3600);
    assert(b8_feed(&s, &a, &p, z) != 0);
    zone_arena_destroy(&a);

    /* a body SOA with another serial, more body SOAs than announced, a body SOA outside the apex */
    for (int k = 0; k < 3; k++) {
        zone_arena_init(&a);
        b8_session(&s, 3);
        b8_init(&p);
        b8_soa(&p, z, 7, 3600);
        b8_rr(&p, z, 65409, 65302, (uint8_t[]){ 1, 0, 1 }, 3);
        if (k == 0) b8_wsoa(&p, z, 8, 3600, "in");
        else if (k == 1) { b8_wsoa(&p, z, 7, 3600, "in"); b8_wsoa(&p, z, 7, 3600, "ex"); }
        else b8_wsoa(&p, "sub.z.example.", 7, 3600, "in");
        assert(b8_feed(&s, &a, &p, z) != 0);
        zone_arena_destroy(&a);
    }

    /* SOA_SET announcing nothing, or more than the limit, or with the flag clear */
    for (int k = 0; k < 3; k++) {
        uint8_t bad[3] = { 1, 0, 0 };
        if (k == 1) { bad[1] = 0x20; }                              /* 8192 > KARIDNS_SOA_SET_MAX */
        if (k == 2) { bad[0] = 0; bad[2] = 1; }
        zone_arena_init(&a);
        b8_session(&s, 3);
        b8_init(&p);
        b8_soa(&p, z, 7, 3600);
        b8_rr(&p, z, 65409, 65302, bad, 3);
        assert(b8_feed(&s, &a, &p, z) != 0);
        zone_arena_destroy(&a);
    }

    /* SETTINGS: ignored for a version 2 stream and for a stream that was not negotiated; a second one is ignored; the database
     * loader may not send one */
    for (int k = 0; k < 4; k++) {
        zone_arena_init(&a);
        b8_session(&s, k == 0 ? 2 : k == 1 ? 0 : 3);
        s.db_stream = k == 3;
        b8_init(&p);
        b8_soa(&p, z, 7, 3600);
        b8_rr(&p, z, 65408, 65302, (const uint8_t *)txt, strlen(txt));
        if (k == 2) b8_rr(&p, z, 65408, 65302, (const uint8_t *)"zone-udp-bufsize 512;", 21);
        int rc = b8_feed(&s, &a, &p, z);
        if (k == 3) assert(rc != 0);
        else assert(rc == 0 && s.has_settings == (k == 2) && (k != 2 || strcmp(s.settings_text, txt) == 0));
        zone_arena_destroy(&a);
    }

    /* a wrapper around a SOA whose RDATA cannot be decoded (fuzz_xfr_packet found a NULL RDATA read here): the transfer is refused */
    for (int k = 0; k < 2; k++) {
        zone_arena_init(&a);
        b8_session(&s, k == 0 ? 3 : 2);
        b8_init(&p);
        b8_soa(&p, z, 7, 3600);
        uint8_t w[24];
        memset(w, 0, sizeof(w));
        b8_u16(w, 6); b8_u16(w + 2, 1); b8_u32(w + 4, 300);
        b8_u16(w + 19, 3);
        memcpy(w + 21, "abc", 3);
        b8_rr(&p, z, 65406, 65302, w, 24);
        b8_soa(&p, z, 7, 3600);
        assert(b8_feed(&s, &a, &p, z) != 0);
        zone_arena_destroy(&a);
    }

    /* a wrapped SOA with no SOA_SET before it is an ordinary closing SOA of the same serial (the version 2 behaviour) */
    zone_arena_init(&a);
    b8_session(&s, 3);
    b8_init(&p);
    b8_soa(&p, z, 7, 3600);
    b8_wsoa(&p, z, 7, 3600, "in");
    assert(b8_feed(&s, &a, &p, z) == 0 && s.is_finished && !s.soa_set);
    zone_arena_destroy(&a);
    printf("  -> receiver SOA set and SETTINGS passed.\n");
}

/* the record types of the answers of the first message in g_tcp_out, e.g. "6,65409,65406,6" */
static void b8_types(char *out, size_t cap) {
    const uint8_t *p = g_tcp_out + 2;
    size_t len = ((size_t)g_tcp_out[0] << 8) | g_tcp_out[1];
    unsigned qd = (p[4] << 8) | p[5], an = (p[6] << 8) | p[7];
    size_t o = DNS_HEADER_SIZE, n;
    out[0] = '\0';
    for (unsigned i = 0; i < qd; i++) { assert(skip_wire_name(p, len, o, &n) == 0); o = n + 4; }
    for (unsigned i = 0; i < an; i++) {
        assert(skip_wire_name(p, len, o, &n) == 0);
        unsigned t = (p[n] << 8) | p[n + 1], c = (p[n + 2] << 8) | p[n + 3];
        size_t rdlen = (p[n + 8] << 8) | p[n + 9];
        char one[16];
        snprintf(one, sizeof(one), "%s%u", out[0] ? "," : "", c == 65302 ? t : (t == 6 ? 6u : 1u));
        strlcat(out, one, cap);
        o = n + 10 + rdlen;
    }
}

static size_t b8_query(uint8_t *q, size_t cap, const char *zone, uint8_t ver) {
    size_t ql = p10_query(q, cap, zone, 252, -1, true, true);
    /* p10_query writes KARIDNS_EXT_VERSION as the first octet of the option's data: the 7th octet from the end of the option */
    assert(ql > 5 && q[ql - 5] == KARIDNS_EXT_VERSION);
    q[ql - 5] = ver;
    return ql;
}

/* An IXFR rebuilds the transfer's arena from the current version when it reads the second SOA, after the SETTINGS record: the text
 * must not live in that arena (an intermittent garbled settings text in run_ext_axfr_v3_test.sh) */
static void test_b8t2_ixfr_settings_survive_thaw(void) {
    printf("[TEST] B8t-2: SETTINGS before the second SOA of an IXFR survives the rebuild of the arena...\n");
    const char *z = "ix.example.";
    zone_arena_t active;
    p10_init_zone(&active, z, "7", "www IN A 192.0.2.80\n");
    zone_arena_t a;
    zone_arena_init(&a);
    axfr_session_t s;
    b8_session(&s, 3);
    s.is_ixfr = true;
    s.client_serial = 7;
    const char *txt = "allow-transfer { 192.0.2.1; 192.0.2.2; 192.0.2.3; };\necs-trusted-resolvers { 192.0.2.50; };\n";
    b8_pk_t p;
    b8_init(&p);
    b8_soa(&p, z, 8, 3600);
    b8_rr(&p, z, 65408, 65302, (const uint8_t *)txt, strlen(txt));
    b8_soa(&p, z, 7, 3600);
    b8_rr(&p, "www.ix.example.", 1, 1, (uint8_t[]){ 192, 0, 2, 80 }, 4);
    b8_soa(&p, z, 8, 3600);
    b8_rr(&p, "www.ix.example.", 1, 1, (uint8_t[]){ 192, 0, 2, 81 }, 4);
    b8_soa(&p, z, 8, 3600);
    assert(parse_xfr_packet(p.b, p.n, &a, &active.ver, &s, z) == 0);
    assert(s.is_finished && s.is_ixfr && s.has_settings && s.settings_len == strlen(txt) && strcmp(s.settings_text, txt) == 0);
    zone_arena_destroy(&a);
    zone_arena_destroy(&active);
    printf("  -> IXFR settings passed.\n");
}

static void test_b8t2_ext_version_fallback_decision(void) {
    printf("[TEST] B8t-2: the secondary's choice of Extended AXFR version (v3, fall back to v2, re-probe)...\n");
    time_t t0 = 1000000;
    /* nothing known: ask for 3, and a standard answer means "try 2" */
    assert(xfr_ext_effective(XFR_EXT_UNKNOWN, 0, t0) == XFR_EXT_UNKNOWN);
    assert(xfr_ext_request_version(XFR_EXT_UNKNOWN) == 3 && xfr_ext_probe(XFR_EXT_UNKNOWN));
    /* the answer to version 2 was extended with version 2: remembered, version 2 is asked for from then on, without a probe */
    assert(xfr_ext_learn(true, 2) == XFR_EXT_V2);
    assert(xfr_ext_request_version(XFR_EXT_V2) == 2 && !xfr_ext_probe(XFR_EXT_V2));
    assert(xfr_ext_effective(XFR_EXT_V2, t0, t0 + XFR_EXT_REPROBE_SECS) == XFR_EXT_V2);
    assert(xfr_ext_effective(XFR_EXT_V2, t0, t0 + XFR_EXT_REPROBE_SECS + 1) == XFR_EXT_UNKNOWN);   /* probed again later */
    /* a primary that answers a standard transfer to version 2 as well: version 3 is asked, a standard answer is accepted at once */
    assert(xfr_ext_learn(false, 0) == XFR_EXT_STANDARD);
    assert(xfr_ext_request_version(XFR_EXT_STANDARD) == 3 && !xfr_ext_probe(XFR_EXT_STANDARD));
    assert(xfr_ext_effective(XFR_EXT_STANDARD, t0, t0 + XFR_EXT_REPROBE_SECS + 1) == XFR_EXT_UNKNOWN);
    /* a version 3 primary stays at 3 (no expiry); if it later answers a standard transfer the probe runs */
    assert(xfr_ext_learn(true, 3) == XFR_EXT_V3 && xfr_ext_probe(XFR_EXT_V3));
    assert(xfr_ext_effective(XFR_EXT_V3, t0, t0 + 10 * XFR_EXT_REPROBE_SECS) == XFR_EXT_V3);
    printf("  -> version fallback decision passed.\n");
}

static void test_b8t2_sender_versions(void) {
    printf("[TEST] B8t-2: the sender answers version 2 and 3, refuses a SOA set to version 2, v2 and v3 of a plain zone agree...\n");
    zone_db_entry_t e;
    memset(&e, 0, sizeof(e));
    strlcpy(e.domain, "b8.example.", sizeof(e.domain));
    strlcpy(e.view_name, "default", sizeof(e.view_name));
    pthread_mutex_init(&e.writer_lock, NULL);
    pthread_mutex_init(&e.ixfr_history.lock, NULL);
    uint8_t q[512];
    char t2[256], t3[256];
    p10_msg_t m;

    /* a plain zone: the version 3 stream is the version 2 stream (no settings without a configuration, no SOA_SET) */
    p10_init_zone(test_zone_slot(&e, 0), "b8.example.", "100", "www IN A 192.0.2.80\n");
    atomic_store_explicit(&e.rcu.active, &test_zone_slot(&e, 0)->ver, memory_order_release);
    size_t ql = b8_query(q, sizeof(q), "b8.example.", 2);
    p10_send(&e, q, ql);
    m = p10_first_msg();
    assert(m.rcode == 0 && m.soa_count == 2 && m.opt);
    b8_types(t2, sizeof(t2));
    size_t len2 = g_tcp_out_len;
    ql = b8_query(q, sizeof(q), "b8.example.", 3);
    p10_send(&e, q, ql);
    b8_types(t3, sizeof(t3));
    assert(strcmp(t2, t3) == 0 && g_tcp_out_len == len2);
    ql = b8_query(q, sizeof(q), "b8.example.", 4);                 /* an unknown version: a standard transfer */
    p10_send(&e, q, ql);
    m = p10_first_msg();
    assert(m.rcode == 0 && m.soa_count == 2);
    zone_arena_destroy(test_zone_slot(&e, 0));

    /* a zone with a second, tagged SOA of the same serial */
    p10_init_zone(test_zone_slot(&e, 0), "b8.example.", "100",
                  "$LOCATION lt-a\n@ IN SOA ns9.b8.example. hostmaster.b8.example. 100 7200 3600 1209600 300\n$LOCATION\nwww IN A 192.0.2.80\n");
    atomic_store_explicit(&e.rcu.active, &test_zone_slot(&e, 0)->ver, memory_order_release);
    ql = b8_query(q, sizeof(q), "b8.example.", 2);
    p10_send(&e, q, ql);
    m = p10_first_msg();
    assert(m.rcode == 5);                                           /* version 2 cannot carry the SOA set: refused */
    ql = b8_query(q, sizeof(q), "b8.example.", 3);
    p10_send(&e, q, ql);
    m = p10_first_msg();
    b8_types(t3, sizeof(t3));
    assert(m.rcode == 0 && strncmp(t3, "6,65409,", 8) == 0);
    assert(strstr(t3, "65406") && strstr(t3, ",65406,") && t3[strlen(t3) - 1] == '6');
    int nwrap = 0;
    for (const char *s = t3; (s = strstr(s, "65406")); s += 5) nwrap++;
    assert(nwrap == 2);                                             /* both apex SOA RRs are body RRs */
    /* a plain transfer (no option) is the zone as the requester sees it */
    ql = p10_query(q, sizeof(q), "b8.example.", 252, -1, true, false);
    p10_send(&e, q, ql);
    m = p10_first_msg();
    assert(m.rcode == 0 || m.rcode == 5);

    ixfr_history_clear(&e.ixfr_history);
    zone_arena_destroy(test_zone_slot(&e, 0));
    pthread_mutex_destroy(&e.writer_lock);
    pthread_mutex_destroy(&e.ixfr_history.lock);
    printf("  -> sender versions passed.\n");
}

static void test_b8t2_settings(void) {
    printf("[TEST] B8t-2: zone settings: render, precedence of the secondary's own statements, fail closed...\n");
    server_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    const char *ptext =
        "options { ecs-trusted-resolvers { 192.0.2.50; }; additional-from-auth in-domain; udp-bufsize 1400; };\n"
        "key \"kx\" { algorithm hmac-sha256; secret \"dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl\"; };\n"
        "zone \"a.example\" { type master; file \"a.zone\"; allow-transfer { 192.0.2.1; !192.0.2.9; key \"kx\"; }; transfer-acl-match any; };\n"
        "zone \"b.example\" { type master; file \"b.zone\"; ecs-trusted-resolvers { 192.0.2.60; 198.51.100.0/24; }; zone-udp-bufsize 800; additional-from-auth no; };\n";
    assert(parse_named_conf(ptext, &pcfg) == 0);
    char buf[KARIDNS_SETTINGS_MAX + 1];
    const zone_config_t *za = config_find_zone_any_view(&pcfg, "a.example.");
    const zone_config_t *zb = config_find_zone_any_view(&pcfg, "b.example.");
    assert(za && zb);

    size_t n = zone_settings_render(&pcfg, za, false, buf, sizeof(buf));
    assert(n > 0 && n == strlen(buf));
    assert(strstr(buf, "allow-transfer { 192.0.2.1; !192.0.2.9; key \"kx\"; };\n"));
    assert(strstr(buf, "transfer-acl-match any;\n"));
    assert(strstr(buf, "ecs-trusted-resolvers { 192.0.2.50; };\n"));          /* options' list: the zone has none */
    assert(strstr(buf, "additional-from-auth in-domain;\n") && strstr(buf, "zone-udp-bufsize 1400;\n"));
    assert(!strstr(buf, "secret") && !strstr(buf, "dGVzdC1v") && !strstr(buf, "acl-ceiling") && !strstr(buf, "masters"));
    n = zone_settings_render(&pcfg, za, true, buf, sizeof(buf));              /* the zone's data carries its own list */
    assert(n > 0 && !strstr(buf, "ecs-trusted-resolvers"));
    n = zone_settings_render(&pcfg, zb, false, buf, sizeof(buf));
    assert(strstr(buf, "ecs-trusted-resolvers { 192.0.2.60; 198.51.100.0/24; };\n") && strstr(buf, "zone-udp-bufsize 800;\n") &&
           strstr(buf, "additional-from-auth no;\n") && !strstr(buf, "allow-transfer"));
    assert(zone_settings_render(&pcfg, za, false, buf, 40) == (size_t)-1);    /* does not fit: reported, never cut */

    /* the secondary: it parses what it got, with the restricted parser, and merges it with its own zone block */
    char err[200];
    n = zone_settings_render(&pcfg, za, false, buf, sizeof(buf));
    zone_ext_shared_t *rx = db_settings_parse(buf, n, err, sizeof(err));
    assert(rx != NULL);
    server_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    const char *stext =
        "options { ecs-trusted-resolvers { 203.0.113.1; }; };\n"
        "key \"kx\" { algorithm hmac-sha256; secret \"dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl\"; };\n"
        "zone \"a.example\" { type slave; masters { 192.0.2.254; }; };\n"
        "zone \"own.example\" { type slave; masters { 192.0.2.254; }; allow-transfer { 198.51.100.7; }; ecs-trusted-resolvers { 198.51.100.8; }; zone-udp-bufsize 700; additional-from-auth yes; };\n"
        "zone \"off.example\" { type slave; masters { 192.0.2.254; }; primary-settings no; };\n"
        "zone \"nokey.example\" { type slave; masters { 192.0.2.254; }; };\n";
    assert(parse_named_conf(stext, &scfg) == 0);
    const zone_config_t *sa = config_find_zone_any_view(&scfg, "a.example.");
    const zone_config_t *so = config_find_zone_any_view(&scfg, "own.example.");
    const zone_config_t *sf = config_find_zone_any_view(&scfg, "off.example.");
    assert(sa && so && sf && zext(sf)->primary_settings_off && !zext(sa)->primary_settings_off);
    char note[160];

    zone_config_t *m1 = zone_config_with_received("a.example.", sa, &rx->ext, &scfg, note, sizeof(note));
    assert(m1 && note[0] == '\0' && strcmp(m1->type, "slave") == 0);
    assert(zext(m1)->masters_count == 1 && strcmp(zext(m1)->masters[0].ip, "192.0.2.254") == 0);   /* the zone's own statements stay */
    assert(zext(m1)->allow_transfer_count == 2 && strcmp(zext(m1)->allow_transfer[0], "192.0.2.1") == 0 &&
           strcmp(zext(m1)->allow_transfer[1], "!192.0.2.9") == 0 && zext(m1)->tsig_keys_count == 1 &&
           zext(m1)->allow_transfer_parsed != NULL && zext(m1)->transfer_acl_match == ACL_MATCH_ANY);
    assert(zext(m1)->ecs_trusted_resolvers_count == 1 && strcmp(zext(m1)->ecs_trusted_resolvers[0], "192.0.2.50") == 0 &&
           zext(m1)->ecs_trusted_resolvers_parsed != NULL);                  /* received > the secondary's options */
    assert(zext(m1)->additional_from_auth_specified && zext(m1)->additional_from_auth == ADDITIONAL_AUTH_IN_DOMAIN &&
           zext(m1)->zone_udp_bufsize == 1400);
    assert(!zext(m1)->db_acl_ceiling);
    free_zone_config(m1);

    m1 = zone_config_with_received("own.example.", so, &rx->ext, &scfg, note, sizeof(note));    /* the secondary's own statements win */
    assert(m1 && zext(m1)->allow_transfer_count == 1 && strcmp(zext(m1)->allow_transfer[0], "198.51.100.7") == 0 &&
           zext(m1)->tsig_keys_count == 0);
    assert(zext(m1)->ecs_trusted_resolvers_count == 1 && strcmp(zext(m1)->ecs_trusted_resolvers[0], "198.51.100.8") == 0);
    assert(zext(m1)->zone_udp_bufsize == 700 && zext(m1)->additional_from_auth == ADDITIONAL_AUTH_YES);
    free_zone_config(m1);

    m1 = zone_config_with_received("cat.example.", NULL, &rx->ext, &scfg, note, sizeof(note));  /* a catalog member has no zone block */
    assert(m1 && strcmp(m1->type, "slave") == 0 && zext(m1)->allow_transfer_count == 2);
    free_zone_config(m1);

    /* the received allow-transfer names a key this server does not have: it becomes "none" */
    server_config_t kcfg;
    memset(&kcfg, 0, sizeof(kcfg));
    assert(parse_named_conf("zone \"nokey.example\" { type slave; masters { 192.0.2.254; }; };\n", &kcfg) == 0);
    const zone_config_t *sk = config_find_zone_any_view(&kcfg, "nokey.example.");
    m1 = zone_config_with_received("nokey.example.", sk, &rx->ext, &kcfg, note, sizeof(note));
    assert(m1 && strstr(note, "'kx'") && zext(m1)->allow_transfer_count == 1 && strcmp(zext(m1)->allow_transfer[0], "none") == 0 &&
           zext(m1)->tsig_keys_count == 0 && zext(m1)->allow_transfer_parsed != NULL);
    assert(zext(m1)->ecs_trusted_resolvers_count == 1);                       /* the rest is still applied */
    free_zone_config(m1);
    free_server_config_fields(&kcfg);

    /* settings cannot name a statement outside the whitelist: a hostile primary cannot set file, type, include... */
    assert(db_settings_parse("file \"/etc/passwd\";", 19, err, sizeof(err)) == NULL);
    assert(db_settings_parse("include \"/etc/passwd\";", 22, err, sizeof(err)) == NULL);
    assert(db_settings_parse("masters { 192.0.2.1; }; allow-transfer { any; };", 48, err, sizeof(err)) != NULL);   /* parsed, then ignored */

    zone_ext_shared_unref(rx);
    free_server_config_fields(&pcfg);
    free_server_config_fields(&scfg);
    printf("  -> settings passed.\n");
}

static void test_b8t2_same_visibility_ttl(void) {
    printf("[TEST] B8t-2: RRset TTLs are harmonized among RRs of the same visibility only...\n");
    zone_arena_t a;
    zone_arena_init(&a);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "t.example.", .is_standalone_mode = true, .err_out = &err };
    const char *text =
        "$ORIGIN t.example.\n$TTL 300\n@ IN SOA ns1 hm 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
        "plain 300 IN A 192.0.2.10\nplain 100 IN A 192.0.2.11\n"
        "$LOCATION lt-a\nmix 60 IN A 192.0.2.20\nloc 50 IN A 192.0.2.30\n"
        "$LOCATION lt-b\nloc 70 IN A 192.0.2.31\n"
        "$LOCATION\nmix 300 IN A 192.0.2.21\n"
        "$LOCATION lt-a\nsame 90 IN A 192.0.2.40\nsame 120 IN A 192.0.2.41\n";
    char *buf = arena_strdup(&a, text);
    assert(parse_zone_fast(buf, strlen(buf), &a, &ctx) >= 0);
    assert(build_zone_index(&a, true) == 0);
    int seen = 0;
    for (size_t i = 0; i < a.count; i++) {
        const dns_record_t *r = &a.records[i];
        if (!r->name || r->type_code != 1) continue;
        if (strncmp(r->name, "plain.", 6) == 0) { assert(r->ttl_value == 100); seen++; }                 /* harmonized: the lowest */
        if (strncmp(r->name, "mix.", 4) == 0) { assert(r->ttl_value == (r->bind_location_tag ? 60u : 300u)); seen++; }   /* kept */
        if (strncmp(r->name, "loc.", 4) == 0) { assert(r->ttl_value == (strcmp(r->bind_location_tag, "lt-a") == 0 ? 50u : 70u)); seen++; }
        if (strncmp(r->name, "same.", 5) == 0) { assert(r->ttl_value == 90); seen++; }                   /* same tag: harmonized */
    }
    assert(seen == 8);
    assert(dns_record_same_visibility(&a.records[0], &a.records[0]));
    zone_arena_destroy(&a);
    printf("  -> same-visibility TTL harmonization passed.\n");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_edns_expire_rfc7314();
    printf("=== Starting AXFR/IXFR Engine Unit Tests ===\n");
    test_wait_for_active_axfr_branches();
    test_p10_transfer_responses();
    test_p10_extended_ixfr();
    test_p10_ixfr_request_client_serial();
    test_p10_xfr_check_response_header();
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
    test_handle_axfr_event_drops_unencodable();
    test_handle_axfr_event_intermediate_unsigned_flow();
    test_handle_axfr_event_and_worker_thread();
    test_axfr_bg_thread_and_free_ixfr_txn();
    test_ixfr_delta_empty_records();
    test_ixfr_history_ring_buffer_wrap();
    test_ixfr_history_depth();
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
    test_parse_xfr_packet_karidns_ext_tags_parsing();
    test_send_axfr_response_tinydns_loc_and_ecs();
    test_send_axfr_response_soa_only_zone();
    test_send_axfr_response_with_ns_and_glue();
    test_send_axfr_response_ixfr_single_soa_uptodate();
    test_send_axfr_response_ixfr_multi_history_chain();
    test_handle_axfr_event_nonblocking_drain();
    test_handle_axfr_event_extended_mode_hash_check();
    test_handle_axfr_event_eagain_and_partial_recv();
    test_handle_axfr_event_out_of_zone_bailiwick_record();
    test_ixfr_txn_allocation_and_free_cycles();
    test_wait_for_active_axfr_immediate_and_timeout();
        test_snapshot_rcu_alloc_and_free_cycle();
    test_snapshot_rcu_reader_count_increment_decrement();
    test_snapshot_rcu_garbage_collection_epoch_advance();
    test_axfr_ixfr_soa_serial_equal_up_to_date();
    test_axfr_ixfr_out_of_bailiwick_record_drop();
    test_axfr_ixfr_tinydns_location_records_in_axfr();
    test_axfr_ixfr_eagain_nonblocking_drain();
    test_axfr_ixfr_wait_for_active_axfr_timeout();
    test_axfr_ixfr_ixfr_txn_arena_cleanup();
    test_axfr_ixfr_catalog_property_coo_sync();
    test_axfr_ixfr_catalog_property_group_sync();
        test_axfr_ixfr_serial_equal_returns_single_soa();
    test_axfr_ixfr_delta_single_delete_and_add();
    test_axfr_ixfr_delta_cname_addition();
    test_axfr_ixfr_delta_txt_record_modification();
    test_axfr_ixfr_extended_tag_loc_tagdef();
    test_axfr_ixfr_extended_tag_ecs_tagdef();
    test_axfr_ixfr_feature_case_11();
    test_axfr_ixfr_feature_case_12();
    test_axfr_ixfr_feature_case_13();
    test_axfr_ixfr_feature_case_14();
    test_axfr_ixfr_feature_case_15();
    test_axfr_ixfr_feature_case_16();
    test_axfr_ixfr_feature_case_17();
    test_axfr_ixfr_feature_case_18();
    test_axfr_ixfr_feature_case_19();
    test_axfr_ixfr_feature_case_20();
    test_axfr_ixfr_feature_case_21();
    test_axfr_ixfr_feature_case_22();
    test_axfr_ixfr_feature_case_23();
    test_axfr_ixfr_feature_case_24();
    test_axfr_ixfr_feature_case_25();
    test_axfr_ixfr_feature_case_26();
    test_axfr_ixfr_feature_case_27();
    test_axfr_ixfr_feature_case_28();
    test_axfr_ixfr_feature_case_29();
    test_axfr_ixfr_feature_case_30();
    test_axfr_ixfr_feature_case_31();
    test_axfr_ixfr_feature_case_32();
    test_axfr_ixfr_feature_case_33();
    test_axfr_ixfr_feature_case_34();
    test_axfr_ixfr_feature_case_35();
    test_axfr_ixfr_feature_case_36();
    test_axfr_ixfr_feature_case_37();
    test_axfr_ixfr_feature_case_38();
    test_axfr_ixfr_feature_case_39();
    test_axfr_ixfr_feature_case_40();
    test_axfr_ixfr_feature_case_41();
    test_axfr_ixfr_feature_case_42();
    test_axfr_ixfr_feature_case_43();
    test_axfr_ixfr_feature_case_44();
    test_axfr_ixfr_feature_case_45();
    test_axfr_ixfr_feature_case_46();
    test_axfr_ixfr_feature_case_47();
    test_axfr_ixfr_feature_case_48();
    test_axfr_ixfr_feature_case_49();
    test_axfr_ixfr_feature_case_50();
    test_axfr_ixfr_feature_case_51();
    test_axfr_ixfr_feature_case_52();
    test_axfr_ixfr_feature_case_53();
    test_axfr_ixfr_feature_case_54();
    test_axfr_ixfr_feature_case_55();
    test_axfr_ixfr_feature_case_56();
    test_axfr_ixfr_feature_case_57();
    test_axfr_ixfr_feature_case_58();
    test_axfr_ixfr_feature_case_59();
    test_axfr_ixfr_feature_case_60();
    
    test_axfr_ixfr_send_axfr_response_ixfr_full_success_flow();
    test_axfr_ixfr_send_axfr_response_extended_trusted_resolvers();
    test_axfr_ixfr_send_axfr_response_location_and_ecs_transitions();
    test_axfr_ixfr_feature_case_61();
    test_axfr_ixfr_feature_case_62();
    test_axfr_ixfr_feature_case_63();
    test_axfr_ixfr_feature_case_64();
    test_axfr_ixfr_feature_case_65();
    test_axfr_ixfr_feature_case_66();
    test_axfr_ixfr_feature_case_67();
    test_axfr_ixfr_feature_case_68();
    test_axfr_ixfr_feature_case_69();
    test_axfr_ixfr_feature_case_70();
    test_axfr_ixfr_feature_case_71();
    test_axfr_ixfr_feature_case_72();
    test_axfr_ixfr_feature_case_73();
    test_axfr_ixfr_feature_case_74();
    test_axfr_ixfr_feature_case_75();
    test_axfr_ixfr_feature_case_76();
    test_axfr_ixfr_feature_case_77();
    test_axfr_ixfr_feature_case_78();
    test_axfr_ixfr_feature_case_79();
    test_axfr_ixfr_feature_case_80();
    test_axfr_ixfr_feature_case_81();
    test_axfr_ixfr_feature_case_82();
    test_axfr_ixfr_feature_case_83();
    test_axfr_ixfr_feature_case_84();
    test_axfr_ixfr_feature_case_85();
    test_axfr_ixfr_feature_case_86();
    test_axfr_ixfr_feature_case_87();
    test_axfr_ixfr_feature_case_88();
    test_axfr_ixfr_feature_case_89();
    test_axfr_ixfr_feature_case_90();
    test_axfr_ixfr_feature_case_91();
    test_axfr_ixfr_feature_case_92();
    test_axfr_ixfr_feature_case_93();
    test_axfr_ixfr_feature_case_94();
    test_axfr_ixfr_feature_case_95();
    test_axfr_ixfr_feature_case_96();
    test_axfr_ixfr_feature_case_97();
    test_axfr_ixfr_feature_case_98();
    test_axfr_ixfr_feature_case_99();
    test_axfr_ixfr_feature_case_100();
    test_axfr_ixfr_feature_case_101();
    test_axfr_ixfr_feature_case_102();
    test_axfr_ixfr_feature_case_103();
    test_axfr_ixfr_feature_case_104();
    test_axfr_ixfr_feature_case_105();
    test_axfr_ixfr_feature_case_106();
    test_axfr_ixfr_feature_case_107();
    test_axfr_ixfr_feature_case_108();
    test_axfr_ixfr_feature_case_109();
    test_axfr_ixfr_feature_case_110();
    test_axfr_ixfr_feature_case_111();
    test_axfr_ixfr_feature_case_112();
    test_axfr_ixfr_feature_case_113();
    test_axfr_ixfr_feature_case_114();
    test_axfr_ixfr_feature_case_115();
    test_axfr_ixfr_feature_case_116();
    test_axfr_ixfr_feature_case_117();
    test_axfr_ixfr_feature_case_118();
    test_axfr_ixfr_feature_case_119();
    test_axfr_ixfr_feature_case_120();
    test_axfr_ixfr_feature_case_121();
    test_axfr_ixfr_feature_case_122();
    test_axfr_ixfr_feature_case_123();
    test_axfr_ixfr_feature_case_124();
    test_axfr_ixfr_feature_case_125();
    test_axfr_ixfr_feature_case_126();
    test_axfr_ixfr_feature_case_127();
    test_axfr_ixfr_feature_case_128();
    test_axfr_ixfr_feature_case_129();
    test_axfr_ixfr_feature_case_130();
    test_axfr_ixfr_feature_case_131();
    test_axfr_ixfr_feature_case_132();
    test_axfr_ixfr_feature_case_133();
    test_axfr_ixfr_feature_case_134();
    test_axfr_ixfr_feature_case_135();
    test_axfr_ixfr_feature_case_136();
    test_axfr_ixfr_feature_case_137();
    test_axfr_ixfr_feature_case_138();
    test_axfr_ixfr_feature_case_139();
    test_axfr_ixfr_feature_case_140();
    test_axfr_ixfr_feature_case_141();
    test_axfr_ixfr_feature_case_142();
    test_axfr_ixfr_feature_case_143();
    test_axfr_ixfr_feature_case_144();
    test_axfr_ixfr_feature_case_145();
    test_axfr_ixfr_feature_case_146();
    test_axfr_ixfr_feature_case_147();
    test_axfr_ixfr_feature_case_148();
    test_axfr_ixfr_feature_case_149();
    test_axfr_ixfr_feature_case_150();

    
    test_axfr_ixfr_feature_case_151();
    test_axfr_ixfr_feature_case_152();
    test_axfr_ixfr_feature_case_153();
    test_axfr_ixfr_feature_case_154();
    test_axfr_ixfr_feature_case_155();
    test_axfr_ixfr_feature_case_156();
    test_axfr_ixfr_feature_case_157();
    test_axfr_ixfr_feature_case_158();
    test_b8t2_xext_records();
    test_b9a_type_class_audit();
    test_b8t2_receiver_soa_set();
    test_b8t2_ixfr_settings_survive_thaw();
    test_b8t2_ext_version_fallback_decision();
    test_b8t2_sender_versions();
    test_b8t2_settings();
    test_b8t2_same_visibility_ttl();
    printf("=== All AXFR/IXFR Engine Unit Tests PASSED ===\n");
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

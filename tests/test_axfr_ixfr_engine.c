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
    // Deleted list should have old SOA and old A
    assert(txn->deleted_count == 2);
    // Added list should have new SOA and new A
    assert(txn->added_count == 2);

    // Clean up
    for (int i = 0; i < entry.ixfr_history.count; i++) {
        free_ixfr_txn(entry.ixfr_history.entries[i]);
    }
    zone_arena_destroy(&old_arena);
    zone_arena_destroy(&new_arena);

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

    r = parse_xfr_packet(pkt, off, &standby, NULL, &session, "example.com");
    assert(r == 0);
    assert(session.is_extended_mode == true);
    assert(session.soa_count == 1);
    assert(standby.count == 1);

    zone_arena_destroy(&standby);
    printf("  -> parse_xfr_packet passed.\n");
}

static void test_wait_for_active_axfr(void) {
    printf("[TEST] AXFR/IXFR: wait_for_active_axfr...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    atomic_init(&entry.active_axfr, 0);

    bool ok = wait_for_active_axfr(&entry, 100);
    assert(ok == true);

    atomic_store(&entry.active_axfr, 1);
    // Timeout expected
    ok = wait_for_active_axfr(&entry, 20);
    assert(ok == false);

    atomic_store(&entry.active_axfr, 0);
    printf("  -> wait_for_active_axfr passed.\n");
}

int main(void) {
    printf("=== Starting AXFR / IXFR Engine Unit Tests ===\n");
    test_compute_ixfr_diff();
    test_parse_xfr_packet();
    test_wait_for_active_axfr();
    printf("=== All AXFR / IXFR Engine Unit Tests PASSED ===\n");
    return 0;
}

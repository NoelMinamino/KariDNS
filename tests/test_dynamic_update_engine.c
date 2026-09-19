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
#include <sys/socket.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_dynamic_update.h"
#include "dns_axfr_ixfr.h"
#include "dns_utils.h"

// Mock globals needed by server internal dependencies
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

static void test_bump_soa_serial(void) {
    printf("[TEST] Dynamic Update: bump_soa_serial_in_arena()...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    // NULL arena / NULL zone
    assert(bump_soa_serial_in_arena(NULL, "example.com.") == 0);
    assert(bump_soa_serial_in_arena(&arena, NULL) == 0);

    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.name = arena_strdup(&arena, "example.com.");
    rec.type = arena_strdup(&arena, "SOA");
    rec.type_code = 6;
    rec.class_str = arena_strdup(&arena, "IN");
    rec.class_val = 1;
    rec.ttl = arena_strdup(&arena, "3600");
    rec.ttl_value = 3600;
    rec.rdata_count = 7;
    rec.rdata[0] = arena_strdup(&arena, "ns1.example.com.");
    rec.rdata[1] = arena_strdup(&arena, "hostmaster.example.com.");
    rec.rdata[2] = arena_strdup(&arena, "2026010101");
    rec.rdata[3] = arena_strdup(&arena, "7200");
    rec.rdata[4] = arena_strdup(&arena, "3600");
    rec.rdata[5] = arena_strdup(&arena, "1209600");
    rec.rdata[6] = arena_strdup(&arena, "300");

    arena.records = malloc(sizeof(dns_record_t) * 4);
    arena.records_cap = 4;
    arena.records[0] = rec;
    arena.count = 1;

    // Normal bump
    uint32_t s1 = bump_soa_serial_in_arena(&arena, "EXAMPLE.COM.");
    assert(s1 == 2026010102);
    assert(strcmp(arena.records[0].rdata[2], "2026010102") == 0);

    // Bump again
    uint32_t s2 = bump_soa_serial_in_arena(&arena, "example.com.");
    assert(s2 == 2026010103);

    // Wrap-around bump (0xFFFFFFFF -> 1)
    arena.records[0].rdata[2] = arena_strdup(&arena, "4294967295");
    uint32_t s_wrap = bump_soa_serial_in_arena(&arena, "example.com.");
    assert(s_wrap == 1);
    assert(strcmp(arena.records[0].rdata[2], "1") == 0);

    // Non-existent zone name
    uint32_t s_none = bump_soa_serial_in_arena(&arena, "otherzone.com.");
    assert(s_none == 0);

    zone_arena_destroy(&arena);
    printf("  -> bump_soa_serial_in_arena passed.\n");
}

static void test_process_update_sections_records(void) {
    printf("[TEST] Dynamic Update: RFC 2136 Update section Add/Delete records...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    arena.hash_size = 256;
    arena.hash_table = malloc(sizeof(int) * arena.hash_size);
    for (size_t i = 0; i < arena.hash_size; i++) arena.hash_table[i] = -1;

    // Initial SOA record
    dns_record_t soa_rec;
    memset(&soa_rec, 0, sizeof(soa_rec));
    soa_rec.name = arena_strdup(&arena, "example.com.");
    soa_rec.type = arena_strdup(&arena, "SOA");
    soa_rec.type_code = 6;
    soa_rec.class_str = arena_strdup(&arena, "IN");
    soa_rec.class_val = 1;
    soa_rec.ttl = arena_strdup(&arena, "3600");
    soa_rec.ttl_value = 3600;
    soa_rec.rdata_count = 7;
    soa_rec.rdata[0] = arena_strdup(&arena, "ns1.example.com.");
    soa_rec.rdata[1] = arena_strdup(&arena, "hostmaster.example.com.");
    soa_rec.rdata[2] = arena_strdup(&arena, "100");
    soa_rec.rdata[3] = arena_strdup(&arena, "7200");
    soa_rec.rdata[4] = arena_strdup(&arena, "3600");
    soa_rec.rdata[5] = arena_strdup(&arena, "1209600");
    soa_rec.rdata[6] = arena_strdup(&arena, "300");

    arena.records = malloc(sizeof(dns_record_t) * 16);
    arena.records_cap = 16;
    arena.records[0] = soa_rec;
    arena.count = 1;
    build_zone_index(&arena, true);

    // Build UPDATE packet: ZOCOUNT=1 (example.com), PRCOUNT=0, UPCOUNT=1 (Add test.example.com A 192.0.2.99)
    uint8_t pkt[512] = {0};
    pkt[0] = 0xAA; pkt[1] = 0x55;
    pkt[2] = 0x28; // Opcode=5 (UPDATE)
    pkt[4] = 0x00; pkt[5] = 0x01; // ZOCOUNT=1
    pkt[8] = 0x00; pkt[9] = 0x01; // UPCOUNT=1

    size_t off = 12;
    // Zone: example.com. IN SOA
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 6; // SOA
    pkt[off++] = 0; pkt[off++] = 1; // IN

    // Update 1: Add test.example.com. 300 IN A 192.0.2.99
    pkt[off++] = 4; memcpy(&pkt[off], "test", 4); off += 4;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // TYPE=A
    pkt[off++] = 0; pkt[off++] = 1; // CLASS=IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C; // TTL=300
    pkt[off++] = 0; pkt[off++] = 4; // RDLEN=4
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 99;

    int prcount = 0, upcount = 0;
    int rcode = process_update_sections(pkt, off, "example.com.", &arena, &prcount, &upcount);
    assert(rcode == 0); // NOERROR
    assert(upcount == 1);
    assert(arena.count == 2);

    zone_arena_destroy(&arena);
    printf("  -> process_update_sections passed.\n");
}

static void init_sample_zone_arena(zone_arena_t *arena, const char *domain, const char *serial_str) {
    memset(arena, 0, sizeof(*arena));
    zone_arena_init(arena);
    arena->hash_size = 256;
    arena->hash_table = malloc(sizeof(int) * arena->hash_size);
    for (size_t i = 0; i < arena->hash_size; i++) arena->hash_table[i] = -1;

    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.name = arena_strdup(arena, domain);
    rec.type = arena_strdup(arena, "SOA");
    rec.type_code = 6;
    rec.class_str = arena_strdup(arena, "IN");
    rec.class_val = 1;
    rec.ttl = arena_strdup(arena, "3600");
    rec.ttl_value = 3600;
    rec.rdata_count = 7;
    rec.rdata[0] = arena_strdup(arena, "ns1.example.com.");
    rec.rdata[1] = arena_strdup(arena, "hostmaster.example.com.");
    rec.rdata[2] = arena_strdup(arena, serial_str);
    rec.rdata[3] = arena_strdup(arena, "7200");
    rec.rdata[4] = arena_strdup(arena, "3600");
    rec.rdata[5] = arena_strdup(arena, "1209600");
    rec.rdata[6] = arena_strdup(arena, "300");

    arena->records = malloc(sizeof(dns_record_t) * 16);
    arena->records_cap = 16;
    arena->records[0] = rec;
    arena->count = 1;
    build_zone_index(arena, true);
}

static void test_handle_dynamic_update_pipeline(void) {
    printf("[TEST] Dynamic Update: handle_dynamic_update() full pipeline...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_sample_zone_arena(&entry.rcu.arena_a, "example.com.", "1000");
    init_sample_zone_arena(&entry.rcu.arena_b, "example.com.", "1000");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 1000, memory_order_release);

    // 1. AXFR in progress -> Rejected with SERVFAIL (rcode 2)
    atomic_store_explicit(&entry.active_axfr, 1, memory_order_release);

    uint8_t pkt[512] = {0};
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[2] = 0x28; // UPDATE
    pkt[4] = 0x00; pkt[5] = 0x01; // ZOCOUNT=1
    pkt[8] = 0x00; pkt[9] = 0x01; // UPCOUNT=1
    size_t off = 12;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 6; // SOA
    pkt[off++] = 0; pkt[off++] = 1; // IN
    // Add www.example.com A 192.0.2.1
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // A
    pkt[off++] = 0; pkt[off++] = 1; // IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1;

    int r_axfr = handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "key-admin");
    assert(r_axfr == 2); // SERVFAIL due to active AXFR

    atomic_store_explicit(&entry.active_axfr, 0, memory_order_release);

    // 2. Normal Successful Update
    int r_success = handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "key-admin");
    assert(r_success == 0); // NOERROR
    assert(atomic_load_explicit(&entry.serial, memory_order_acquire) == 1001);
    assert(atomic_load_explicit(&entry.notify_now, memory_order_acquire) == true);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire) == &entry.rcu.arena_b);

    // Verify record in active arena (arena_b)
    zone_arena_t *z_cur = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
    assert(z_cur->count == 2);

    // 3. Update with PREREQ failure (e.g. NXDOMAIN on non-existent domain under RFC 2136 §3.2.1)
    uint8_t bad_pkt[512] = {0};
    bad_pkt[0] = 0x56; bad_pkt[1] = 0x78;
    bad_pkt[2] = 0x28; // UPDATE
    bad_pkt[4] = 0x00; bad_pkt[5] = 0x01; // ZOCOUNT=1
    bad_pkt[6] = 0x00; bad_pkt[7] = 0x01; // PRCOUNT=1
    size_t b_off = 12;
    // Zone
    bad_pkt[b_off++] = 7; memcpy(&bad_pkt[b_off], "example", 7); b_off += 7;
    bad_pkt[b_off++] = 3; memcpy(&bad_pkt[b_off], "com", 3); b_off += 3;
    bad_pkt[b_off++] = 0;
    bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 6;
    bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 1;
    // Prereq: Name is in use (ANY / ANY) for nonexistent.example.com -> NXDOMAIN (3)
    bad_pkt[b_off++] = 11; memcpy(&bad_pkt[b_off], "nonexistent", 11); b_off += 11;
    bad_pkt[b_off++] = 7; memcpy(&bad_pkt[b_off], "example", 7); b_off += 7;
    bad_pkt[b_off++] = 3; memcpy(&bad_pkt[b_off], "com", 3); b_off += 3;
    bad_pkt[b_off++] = 0;
    bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 255; // ANY
    bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 255; // ANY
    bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 0;
    bad_pkt[b_off++] = 0; bad_pkt[b_off++] = 0;

    int r_prereq = handle_dynamic_update(bad_pkt, b_off, &entry, "127.0.0.1", "key-admin");
    assert(r_prereq == 3); // NXDOMAIN (RFC 2136 rcode 3)

    // Clean up
    zone_arena_destroy(&entry.rcu.arena_a);
    zone_arena_destroy(&entry.rcu.arena_b);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> handle_dynamic_update pipeline passed.\n");
}

static void test_send_notify_to_all_comprehensive(void) {
    printf("[TEST] Dynamic Update: send_notify_to_all() comprehensive (IPv6, glue, sibling)...\n");

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) < 0) {
        perror("socketpair");
        return;
    }

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    view_config_t view_cfg;
    memset(&view_cfg, 0, sizeof(view_cfg));
    view_cfg.name = "default";

    zone_config_t zcfg1, zcfg2;
    memset(&zcfg1, 0, sizeof(zcfg1));
    zcfg1.domain = "example.com.";
    zcfg1.notify_source = "192.0.2.1";
    zcfg1.also_notify_count = 3;
    ip_port_t notifys[3];
    notifys[0].ip = "192.0.2.10";
    notifys[0].port = 53;
    notifys[1].ip = "2001:db8::10";
    notifys[1].port = 5353;
    notifys[2].ip = "invalid.ip"; // Invalid IP to test parse failure
    notifys[2].port = 53;
    zcfg1.also_notify = notifys;
    zcfg1.next = &zcfg2;

    memset(&zcfg2, 0, sizeof(zcfg2));
    zcfg2.domain = "sibling.com.";
    zcfg2.next = NULL;

    view_cfg.zones = &zcfg1;
    cfg.views = &view_cfg;

    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    zone_db_snapshot_t *snap = rebuild_zone_db_snapshot(&cfg, NULL, NULL, NULL, NULL, 0);
    assert(snap != NULL);

    zone_db_entry_t *z1 = snapshot_get_zone(snap, "example.com.");
    zone_db_entry_t *z2 = snapshot_get_zone(snap, "sibling.com.");
    assert(z1 && z2);

    init_sample_zone_arena(&z1->rcu.arena_a, "example.com.", "100");

    // Add NS records and glue in z1
    // NS 1: ns1.example.com (matches SOA MNAME -> excluded)
    // NS 2: ns2.example.com -> in-zone A and AAAA glue
    // NS 3: ns1.sibling.com -> sibling zone glue
    zone_arena_t *a1 = &z1->rcu.arena_a;
    dns_record_t *new_recs = realloc(a1->records, sizeof(dns_record_t) * 16);
    assert(new_recs);
    a1->records = new_recs;
    a1->records_cap = 16;

    // NS records
    dns_record_t r_ns1; memset(&r_ns1, 0, sizeof(r_ns1));
    r_ns1.name = arena_strdup(a1, "example.com.");
    r_ns1.type_code = 2; r_ns1.rdata_count = 1;
    r_ns1.rdata[0] = arena_strdup(a1, "ns1.example.com.");
    a1->records[a1->count++] = r_ns1;

    dns_record_t r_ns2; memset(&r_ns2, 0, sizeof(r_ns2));
    r_ns2.name = arena_strdup(a1, "example.com.");
    r_ns2.type_code = 2; r_ns2.rdata_count = 1;
    r_ns2.rdata[0] = arena_strdup(a1, "ns2.example.com.");
    a1->records[a1->count++] = r_ns2;

    dns_record_t r_ns3; memset(&r_ns3, 0, sizeof(r_ns3));
    r_ns3.name = arena_strdup(a1, "example.com.");
    r_ns3.type_code = 2; r_ns3.rdata_count = 1;
    r_ns3.rdata[0] = arena_strdup(a1, "ns1.sibling.com.");
    a1->records[a1->count++] = r_ns3;

    // In-zone A & AAAA glue for ns2.example.com
    dns_record_t r_g4; memset(&r_g4, 0, sizeof(r_g4));
    r_g4.name = arena_strdup(a1, "ns2.example.com.");
    r_g4.type_code = 1; r_g4.rdata_count = 1;
    r_g4.rdata[0] = arena_strdup(a1, "192.0.2.20");
    a1->records[a1->count++] = r_g4;

    dns_record_t r_g6; memset(&r_g6, 0, sizeof(r_g6));
    r_g6.name = arena_strdup(a1, "ns2.example.com.");
    r_g6.type_code = 28; r_g6.rdata_count = 1;
    r_g6.rdata[0] = arena_strdup(a1, "2001:db8::20");
    a1->records[a1->count++] = r_g6;

    build_zone_index(a1, true);
    atomic_store_explicit(&z1->rcu.active, a1, memory_order_release);

    // Sibling zone z2: sibling.com
    init_sample_zone_arena(&z2->rcu.arena_a, "sibling.com.", "100");
    zone_arena_t *a2 = &z2->rcu.arena_a;
    dns_record_t *new_recs2 = realloc(a2->records, sizeof(dns_record_t) * 16);
    assert(new_recs2);
    a2->records = new_recs2;
    a2->records_cap = 16;

    dns_record_t r_sib4; memset(&r_sib4, 0, sizeof(r_sib4));
    r_sib4.name = arena_strdup(a2, "ns1.sibling.com.");
    r_sib4.type_code = 1; r_sib4.rdata_count = 1;
    r_sib4.rdata[0] = arena_strdup(a2, "198.51.100.30");
    a2->records[a2->count++] = r_sib4;

    dns_record_t r_sib6; memset(&r_sib6, 0, sizeof(r_sib6));
    r_sib6.name = arena_strdup(a2, "ns1.sibling.com.");
    r_sib6.type_code = 28; r_sib6.rdata_count = 1;
    r_sib6.rdata[0] = arena_strdup(a2, "2001:db8:ffff::30");
    a2->records[a2->count++] = r_sib6;

    build_zone_index(a2, true);
    atomic_store_explicit(&z2->rcu.active, a2, memory_order_release);

    send_notify_to_all("example.com.", "default");

    // Count received NOTIFY packets from IPC
    int pkt_count = 0;
    while (1) {
        uint8_t buf[2048];
        ssize_t n = recv(g_notify_ipc[0], buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) break;
        pkt_count++;
        udp_ipc_t *ipc = (udp_ipc_t *)buf;
        assert(ipc->sock_fd_idx == -1);
        if (ipc->has_source_addr) {
            assert(ipc->source_addr.ss_family == AF_INET);
        }
    }

    assert(pkt_count >= 4); // IPv4 also-notify, IPv6 also-notify, in-zone A/AAAA glue, sibling A/AAAA glue
    assert(atomic_load_explicit(&z1->observatory.notify_sent, memory_order_acquire) > 0);

    close(g_notify_ipc[0]);
    close(g_notify_ipc[1]);
    g_notify_ipc[0] = -1;
    g_notify_ipc[1] = -1;
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);

    printf("  -> send_notify_to_all comprehensive passed.\n");
}

int main(void) {
    printf("=== Starting Dynamic Update Engine Unit Tests ===\n");
    test_bump_soa_serial();
    test_process_update_sections_records();
    test_handle_dynamic_update_pipeline();
    test_send_notify_to_all_comprehensive();
    printf("=== All Dynamic Update Engine Unit Tests PASSED ===\n");
    return 0;
}

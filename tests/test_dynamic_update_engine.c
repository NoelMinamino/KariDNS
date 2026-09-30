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
#include "dns_query_engine.h"
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

    update_result_t ur;
    int rcode = process_update_sections(pkt, off, "example.com.", &arena, &ur);
    assert(rcode == 0); // NOERROR
    assert(ur.upcount == 1);
    assert(ur.changed && !ur.soa_replaced);
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
        alignas(udp_ipc_t) uint8_t buf[2048];
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

static void test_process_update_sections_apex_ns_protection(void) {
    printf("[TEST] Dynamic Update: RFC 2136 §3.4.2.4 apex NS deletion protection via Class NONE...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    arena.hash_size = 256;
    arena.hash_table = malloc(sizeof(int) * arena.hash_size);
    for (size_t i = 0; i < arena.hash_size; i++) arena.hash_table[i] = -1;

    arena.records = malloc(sizeof(dns_record_t) * 16);
    arena.records_cap = 16;

    // SOA record
    dns_record_t soa;
    memset(&soa, 0, sizeof(soa));
    soa.name = arena_strdup(&arena, "example.com.");
    soa.type = arena_strdup(&arena, "SOA");
    soa.type_code = 6;
    soa.class_str = arena_strdup(&arena, "IN");
    soa.class_val = 1;
    soa.ttl = arena_strdup(&arena, "3600");
    soa.ttl_value = 3600;
    soa.rdata_count = 7;
    soa.rdata[0] = arena_strdup(&arena, "ns1.example.com.");
    soa.rdata[1] = arena_strdup(&arena, "hostmaster.example.com.");
    soa.rdata[2] = arena_strdup(&arena, "100");
    soa.rdata[3] = arena_strdup(&arena, "7200");
    soa.rdata[4] = arena_strdup(&arena, "3600");
    soa.rdata[5] = arena_strdup(&arena, "1209600");
    soa.rdata[6] = arena_strdup(&arena, "300");
    arena.records[arena.count++] = soa;

    // Only 1 apex NS record
    dns_record_t ns1;
    memset(&ns1, 0, sizeof(ns1));
    ns1.name = arena_strdup(&arena, "example.com.");
    ns1.type = arena_strdup(&arena, "NS");
    ns1.type_code = 2;
    ns1.class_str = arena_strdup(&arena, "IN");
    ns1.class_val = 1;
    ns1.ttl = arena_strdup(&arena, "3600");
    ns1.ttl_value = 3600;
    ns1.rdata_count = 1;
    ns1.rdata[0] = arena_strdup(&arena, "ns1.example.com.");
    arena.records[arena.count++] = ns1;

    build_zone_index(&arena, true);

    // Build UPDATE packet to delete ns1 via CLASS NONE (254)
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

    // Delete exact RR: example.com. 0 NONE NS ns1.example.com.
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 2;   // TYPE=NS
    pkt[off++] = 0; pkt[off++] = 254; // CLASS=NONE
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; // TTL=0
    size_t rdlen_pos = off;
    off += 2;
    size_t rdata_start = off;
    pkt[off++] = 3; memcpy(&pkt[off], "ns1", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    uint16_t rdlen = (uint16_t)(off - rdata_start);
    pkt[rdlen_pos] = (uint8_t)(rdlen >> 8);
    pkt[rdlen_pos + 1] = (uint8_t)(rdlen & 0xFF);

    update_result_t ur;
    int rcode = process_update_sections(pkt, off, "example.com.", &arena, &ur);
    // RFC 2136 §3.4.2.4: deleting the last apex NS is ignored (NOERROR), not refused
    assert(rcode == 0);
    assert(!ur.changed);
    assert(arena.count == 2);
    assert(arena.records[1].name != NULL && arena.records[1].type_code == 2); // NS record was NOT tombstoned

    // Now add a second apex NS record: ns2.example.com.
    dns_record_t ns2;
    memset(&ns2, 0, sizeof(ns2));
    ns2.name = arena_strdup(&arena, "example.com.");
    ns2.type = arena_strdup(&arena, "NS");
    ns2.type_code = 2;
    ns2.class_str = arena_strdup(&arena, "IN");
    ns2.class_val = 1;
    ns2.ttl = arena_strdup(&arena, "3600");
    ns2.ttl_value = 3600;
    ns2.rdata_count = 1;
    ns2.rdata[0] = arena_strdup(&arena, "ns2.example.com.");
    arena.records[arena.count++] = ns2;
    build_zone_index(&arena, true);

    // Now repeating the delete of ns1 must succeed (2 apex NS existed -> 1 remains)
    rcode = process_update_sections(pkt, off, "example.com.", &arena, &ur);
    assert(rcode == 0); // NOERROR
    assert(ur.changed);
    assert(arena.count == 2); // Compacted: SOA + ns2
    assert(arena.records[0].name != NULL && arena.records[0].type_code == 6); // SOA exists
    assert(arena.records[1].name != NULL && arena.records[1].type_code == 2); // ns2 remains
    assert(strcmp(arena.records[1].rdata[0], "ns2.example.com.") == 0);

    zone_arena_destroy(&arena);
    printf("  -> Apex NS deletion protection passed.\n");
}

static void test_update_multi_tsig_keys(void) {
    printf("[TEST] Dynamic Update: Multiple TSIG keys in allow-update authorization...\n");

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    tsig_key_t key1;
    memset(&key1, 0, sizeof(key1));
    key1.name = "key1.example.com.";
    key1.algorithm = "hmac-sha256";
    key1.secret_decoded_len = 32;
    memset(key1.secret_decoded, 0x11, 32);

    tsig_key_t key2;
    memset(&key2, 0, sizeof(key2));
    key2.name = "key2.example.com.";
    key2.algorithm = "hmac-sha256";
    key2.secret_decoded_len = 32;
    memset(key2.secret_decoded, 0x22, 32);

    key1.next = &key2;
    cfg.keys = &key1;

    char *allow_keys[2] = { "key1.example.com.", "key2.example.com." };
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "example.com.";
    zcfg.type = "master";
    zcfg.allow_update = allow_keys;
    zcfg.allow_update_count = 2;
    cfg.zones = &zcfg;

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_sample_zone_arena(&entry.rcu.arena_a, "example.com.", "100");
    init_sample_zone_arena(&entry.rcu.arena_b, "example.com.", "100");
    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 100, memory_order_release);

    zone_db_entry_t *entries[1] = { &entry };
    char *any_acl[1] = { "any" };

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

    // Construct UPDATE packet: ZOCOUNT=1 (example.com), UPCOUNT=1 (Add host.example.com A 192.0.2.77)
    uint8_t pkt[1024] = {0};
    pkt[0] = 0x55; pkt[1] = 0xAA;
    pkt[2] = 0x28; // UPDATE
    pkt[4] = 0x00; pkt[5] = 0x01; // ZOCOUNT=1
    pkt[8] = 0x00; pkt[9] = 0x01; // UPCOUNT=1

    size_t off = 12;
    // Zone: example.com. IN SOA
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 6; // SOA
    pkt[off++] = 0; pkt[off++] = 1; // IN

    // Update 1: Add host.example.com. 300 IN A 192.0.2.77
    pkt[off++] = 4; memcpy(&pkt[off], "host", 4); off += 4;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // A
    pkt[off++] = 0; pkt[off++] = 1; // IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C; // TTL=300
    pkt[off++] = 0; pkt[off++] = 4; // RDLEN=4
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 77;

    // Sign the update packet using key2 (the 2nd key in allow_update list!)
    uint8_t mac[64];
    size_t mac_len = 0;
    size_t signed_len = off;
    int sign_res = tsig_sign_packet(pkt, &signed_len, sizeof(pkt), &key2, 0, mac, &mac_len, NULL, 0, false);
    assert(sign_res == 0);

    // Now process via query engine
    uint8_t res[4096] = {0};
    compress_ctx_t comp_ctx = {0};
    zone_db_entry_t *matched_entry = NULL;
    int res_len = process_dns_query_impl(pkt, signed_len, res, sizeof(res), "example.com.", 6,
                                         "192.0.2.1", &comp_ctx, false, NULL, &snap, &cfg, &matched_entry);
    assert(res_len > 0);
    uint8_t rcode = res[3] & 0x0F;
    assert(rcode == 0); // MUST NOT be 9 (NOTAUTH)! Must succeed with NOERROR (0)

    zone_arena_destroy(&entry.rcu.arena_a);
    zone_arena_destroy(&entry.rcu.arena_b);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> Multiple TSIG keys in allow-update passed.\n");
}

static void test_dynamic_update_prerequisites_and_error_paths(void) {
    printf("[TEST] Dynamic Update: RFC 2136 Prerequisite and Error branches...\n");
    zone_arena_t arena;
    init_sample_zone_arena(&arena, "example.com.", "100");

    // Add an A record for www.example.com.
    dns_record_t a_rec;
    memset(&a_rec, 0, sizeof(a_rec));
    a_rec.name = arena_strdup(&arena, "www.example.com.");
    a_rec.type = arena_strdup(&arena, "A");
    a_rec.type_code = 1;
    a_rec.class_str = arena_strdup(&arena, "IN");
    a_rec.class_val = 1;
    a_rec.ttl = arena_strdup(&arena, "300");
    a_rec.ttl_value = 300;
    a_rec.rdata_count = 1;
    a_rec.rdata[0] = arena_strdup(&arena, "192.0.2.1");
    arena.records[arena.count++] = a_rec;
    build_zone_index(&arena, true);

    // 1. Short packet (< 12 bytes)
    uint8_t short_pkt[8] = {0};
    update_result_t ur;
    assert(process_update_sections(short_pkt, sizeof(short_pkt), "example.com.", &arena, &ur) == 1);

    // 2. ZOCOUNT != 1
    uint8_t pkt_zocnt[64] = {0};
    pkt_zocnt[2] = 0x28; // UPDATE
    pkt_zocnt[5] = 0;    // ZOCOUNT = 0
    assert(process_update_sections(pkt_zocnt, 12, "example.com.", &arena, &ur) == 1);

    // 3. Excessive count (> 1000)
    pkt_zocnt[5] = 1; // ZOCOUNT = 1
    pkt_zocnt[6] = 0x03; pkt_zocnt[7] = 0xF0; // PRCOUNT = 1008
    assert(process_update_sections(pkt_zocnt, 12, "example.com.", &arena, &ur) == 5); // REFUSED

    // Helper to build base header + zone section for example.com.
    #define BUILD_HEADER(buf, len_var, pr_cnt, up_cnt) do { \
        memset(buf, 0, sizeof(buf)); \
        buf[2] = 0x28; \
        buf[4] = 0; buf[5] = 1; /* ZOCOUNT = 1 */ \
        buf[6] = (uint8_t)((pr_cnt) >> 8); buf[7] = (uint8_t)((pr_cnt) & 0xFF); \
        buf[8] = (uint8_t)((up_cnt) >> 8); buf[9] = (uint8_t)((up_cnt) & 0xFF); \
        len_var = 12; \
        buf[len_var++] = 7; memcpy(&buf[len_var], "example", 7); len_var += 7; \
        buf[len_var++] = 3; memcpy(&buf[len_var], "com", 3); len_var += 3; \
        buf[len_var++] = 0; \
        buf[len_var++] = 0; buf[len_var++] = 6; /* SOA */ \
        buf[len_var++] = 0; buf[len_var++] = 1; /* IN */ \
    } while (0)

    uint8_t pkt[1024];
    size_t off = 0;

    // 4. Zone name mismatch -> NOTAUTH (9)
    BUILD_HEADER(pkt, off, 0, 0);
    assert(process_update_sections(pkt, off, "other.com.", &arena, &ur) == 9);

    // 5. Prereq: name out of zone -> NOTZONE (10)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "out", 3); off += 3;
    pkt[off++] = 3; memcpy(&pkt[off], "org", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 255; // ANY
    pkt[off++] = 0; pkt[off++] = 255; // ANY
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; // TTL=0
    pkt[off++] = 0; pkt[off++] = 0; // RDLEN=0
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 10);

    // 6. Prereq: CLASS=ANY (255), RDLEN != 0 -> FORMERR (1)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 255; // ANY
    pkt[off++] = 0; pkt[off++] = 255; // ANY
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 4; // RDLEN=4 (invalid for ANY)
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 1);

    // 7. Prereq: CLASS=ANY, TYPE=ANY, name not in zone DB -> NXDOMAIN (3)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 4; memcpy(&pkt[off], "none", 4); off += 4;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 255; // TYPE=ANY
    pkt[off++] = 0; pkt[off++] = 255; // CLASS=ANY
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 3); // NXDOMAIN

    // 8. Prereq: CLASS=ANY, TYPE=TXT (not present on www.example.com.) -> NXRRSET (8)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 16;  // TYPE=TXT
    pkt[off++] = 0; pkt[off++] = 255; // CLASS=ANY
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 8); // NXRRSET

    // 9. Prereq: CLASS=NONE (254), TYPE=ANY, name exists (www) -> YXDOMAIN (6)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 255; // TYPE=ANY
    pkt[off++] = 0; pkt[off++] = 254; // CLASS=NONE
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 6); // YXDOMAIN

    // 10. Prereq: CLASS=NONE (254), TYPE=A, RRset exists (www A) -> YXRRSET (7)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1;   // TYPE=A
    pkt[off++] = 0; pkt[off++] = 254; // CLASS=NONE
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 7); // YXRRSET

    // 11. Prereq: CLASS=IN, value-dependent exact match mismatch -> NXRRSET (8)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // TYPE=A
    pkt[off++] = 0; pkt[off++] = 1; // CLASS=IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 99; // 192.0.2.99 != 192.0.2.1
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 8); // NXRRSET

    // 12. Prereq: CLASS=IN, value-dependent exact match success -> NOERROR (0)
    BUILD_HEADER(pkt, off, 1, 0);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // TYPE=A
    pkt[off++] = 0; pkt[off++] = 1; // CLASS=IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1; // 192.0.2.1
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 0);

    // 13. Update: Delete SOA via CLASS=ANY -> ignored (RFC 2136 §3.4.2.3), NOERROR, SOA untouched
    BUILD_HEADER(pkt, off, 0, 1);
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 6;   // SOA
    pkt[off++] = 0; pkt[off++] = 255; // ANY
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 0);
    assert(!ur.changed);
    assert(arena.count == 2 && arena.records[0].type_code == 6 && arena.records[0].name != NULL);

    // 14. Update: Add meta type (OPT=41) via ADD -> FORMERR (1)
    BUILD_HEADER(pkt, off, 0, 1);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 41; // OPT
    pkt[off++] = 0; pkt[off++] = 1;  // IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 1);

    // 15. Update: Add RR with wrong class (CH=3) -> FORMERR (1)
    BUILD_HEADER(pkt, off, 0, 1);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // A
    pkt[off++] = 0; pkt[off++] = 3; // CH (wrong class)
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 5;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 1);

    // 16. Update: Add RR with owner out of zone -> NOTZONE (10, RFC 2136 §3.4.1.3)
    BUILD_HEADER(pkt, off, 0, 1);
    pkt[off++] = 3; memcpy(&pkt[off], "out", 3); off += 3;
    pkt[off++] = 3; memcpy(&pkt[off], "org", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 1; // A
    pkt[off++] = 0; pkt[off++] = 1; // IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 5;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 10);

    // 17. Update: Add CNAME where A already exists (www) -> CNAME ignored (RFC 2136 §3.4.2.2), NOERROR
    BUILD_HEADER(pkt, off, 0, 1);
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7;
    pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3;
    pkt[off++] = 0;
    pkt[off++] = 0; pkt[off++] = 5; // CNAME
    pkt[off++] = 0; pkt[off++] = 1; // IN
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 8;
    pkt[off++] = 6; memcpy(&pkt[off], "target", 6); off += 6;
    pkt[off++] = 0;
    assert(process_update_sections(pkt, off, "example.com.", &arena, &ur) == 0);
    assert(!ur.changed);
    assert(arena.count == 2 && arena.records[1].type_code == 1); // www A kept, no CNAME

    zone_arena_destroy(&arena);
    #undef BUILD_HEADER
    printf("  -> Dynamic Update prerequisite & error branches passed.\n");
}

/* ---------------------------------------------------------------------------
 * RFC 2136 §3.1-§3.4 semantics (R-01, R-11): helpers build UPDATE messages
 * against the zone below; every case starts from a freshly loaded zone.
 * ------------------------------------------------------------------------- */
#define UZ "upd.example."
static const char UPD_ZONE_TEXT[] =
    "$ORIGIN upd.example.\n$TTL 300\n"
    "@ IN SOA ns1 hostmaster 100 3600 600 86400 60\n"
    "@ IN NS ns1\n@ IN NS ns2\n@ IN TXT \"apex\"\n"
    "ns1 IN A 192.0.2.1\nns2 IN A 192.0.2.2\n"
    "www IN A 192.0.2.10\nwww IN A 192.0.2.11\n"
    "alias IN CNAME www\n"
    "wks IN WKS 192.0.2.5 TCP 25\n"
    "sub IN NS ns.sub\nns.sub IN A 192.0.2.53\n";

static void upd_load(zone_arena_t *a) {
    memset(a, 0, sizeof(*a));
    zone_arena_init(a);
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base_dir = ".";
    ctx.default_origin = UZ;
    ctx.is_standalone_mode = true;
    ctx.err_out = &err;
    char *b = arena_strdup(a, UPD_ZONE_TEXT); // the arena keeps pointers into the text
    assert(parse_zone_fast(b, strlen(b), a, &ctx) >= 0);
    assert(build_zone_index(a, true) == 0);
}

static int upd_count(const zone_arena_t *a, const char *name, uint16_t type) {
    int n = 0;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (r->name && r->type_code == type && strcasecmp(r->name, name) == 0) n++;
    }
    return n;
}

static const dns_record_t *upd_get(const zone_arena_t *a, const char *name, uint16_t type) {
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (r->name && r->type_code == type && strcasecmp(r->name, name) == 0) return r;
    }
    return NULL;
}

typedef struct {
    uint8_t b[2048];
    size_t len;
    uint16_t pr, up;
} upd_msg_t;

static void upd_begin_zone(upd_msg_t *m, const char *zone, uint16_t ztype, uint16_t zclass) {
    memset(m, 0, sizeof(*m));
    m->b[0] = 0x4b; m->b[1] = 0x44;
    m->b[2] = 0x28; // UPDATE
    m->b[5] = 1;    // ZOCOUNT
    m->len = 12;
    long w = write_uncompressed_name(m->b, m->len, sizeof(m->b), zone);
    assert(w > 0);
    m->len += (size_t)w;
    m->b[m->len++] = (uint8_t)(ztype >> 8); m->b[m->len++] = (uint8_t)ztype;
    m->b[m->len++] = (uint8_t)(zclass >> 8); m->b[m->len++] = (uint8_t)zclass;
}

static void upd_begin(upd_msg_t *m) { upd_begin_zone(m, UZ, 6, 1); }

static void upd_rr(upd_msg_t *m, bool prereq, const char *name, uint16_t type, uint16_t cls,
                   uint32_t ttl, const uint8_t *rd, uint16_t rdlen) {
    long w = write_uncompressed_name(m->b, m->len, sizeof(m->b), name);
    assert(w > 0);
    m->len += (size_t)w;
    uint8_t *p = m->b + m->len;
    p[0] = (uint8_t)(type >> 8); p[1] = (uint8_t)type;
    p[2] = (uint8_t)(cls >> 8); p[3] = (uint8_t)cls;
    p[4] = (uint8_t)(ttl >> 24); p[5] = (uint8_t)(ttl >> 16); p[6] = (uint8_t)(ttl >> 8); p[7] = (uint8_t)ttl;
    p[8] = (uint8_t)(rdlen >> 8); p[9] = (uint8_t)rdlen;
    m->len += 10;
    if (rdlen) memcpy(m->b + m->len, rd, rdlen);
    m->len += rdlen;
    if (prereq) {
        assert(m->up == 0); // prerequisites precede the update section
        m->pr++;
    } else {
        m->up++;
    }
    m->b[6] = (uint8_t)(m->pr >> 8); m->b[7] = (uint8_t)m->pr;
    m->b[8] = (uint8_t)(m->up >> 8); m->b[9] = (uint8_t)m->up;
}

/* A record 192.0.2.<last> */
static void upd_a(upd_msg_t *m, bool prereq, const char *name, uint16_t cls, uint32_t ttl, uint8_t last) {
    uint8_t rd[4] = { 192, 0, 2, last };
    upd_rr(m, prereq, name, 1, cls, ttl, rd, 4);
}

/* RR whose RDATA is one domain name (NS, CNAME, DNAME) */
static void upd_named(upd_msg_t *m, const char *name, uint16_t type, uint16_t cls, const char *target) {
    uint8_t rd[256];
    long w = write_uncompressed_name(rd, 0, sizeof(rd), target);
    assert(w > 0);
    upd_rr(m, false, name, type, cls, cls == 1 ? 300 : 0, rd, (uint16_t)w);
}

static void upd_soa(upd_msg_t *m, const char *name, uint16_t cls, uint32_t serial) {
    uint8_t rd[256];
    long w = write_uncompressed_name(rd, 0, sizeof(rd), "ns1." UZ);
    assert(w > 0);
    size_t n = (size_t)w;
    w = write_uncompressed_name(rd, n, sizeof(rd), "hostmaster." UZ);
    assert(w > 0);
    n += (size_t)w;
    uint32_t v[5] = { serial, 3600, 600, 86400, 60 };
    for (int i = 0; i < 5; i++) {
        rd[n++] = (uint8_t)(v[i] >> 24); rd[n++] = (uint8_t)(v[i] >> 16);
        rd[n++] = (uint8_t)(v[i] >> 8); rd[n++] = (uint8_t)v[i];
    }
    upd_rr(m, false, name, 6, cls, cls == 1 ? 300 : 0, rd, (uint16_t)n);
}

static int upd_run(zone_arena_t *a, const upd_msg_t *m, update_result_t *ur) {
    return process_update_sections(m->b, m->len, UZ, a, ur);
}

static void test_update_soa_rules(void) {
    printf("[TEST] Dynamic Update: SOA add replaces only with a newer serial (R-01, RFC 2136 §3.4.2.2)...\n");
    zone_arena_t z;
    upd_msg_t m;
    update_result_t ur;

    upd_load(&z);
    upd_begin(&m);
    upd_soa(&m, UZ, 1, 105);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed && ur.soa_replaced);
    assert(upd_count(&z, UZ, 6) == 1); // replaced, not appended (R-01)
    assert(strcmp(upd_get(&z, UZ, 6)->rdata[2], "105") == 0);
    zone_arena_destroy(&z);

    /* equal, lower, and RFC 1982 undefined (difference 2^31) serials are ignored */
    const uint32_t ignored[] = { 100, 99, 100u + 2147483648u };
    for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++) {
        upd_load(&z);
        upd_begin(&m);
        upd_soa(&m, UZ, 1, ignored[i]);
        assert(upd_run(&z, &m, &ur) == 0 && !ur.changed && !ur.soa_replaced);
        assert(upd_count(&z, UZ, 6) == 1);
        assert(strcmp(upd_get(&z, UZ, 6)->rdata[2], "100") == 0);
        zone_arena_destroy(&z);
    }

    /* serial arithmetic wraps (RFC 1982 §3.2): 100 + 2^31 - 1 is newer than 100 */
    upd_load(&z);
    upd_begin(&m);
    upd_soa(&m, UZ, 1, 100u + 2147483647u);
    assert(upd_run(&z, &m, &ur) == 0 && ur.soa_replaced);
    assert(strcmp(upd_get(&z, UZ, 6)->rdata[2], "2147483747") == 0);
    zone_arena_destroy(&z);

    /* SOA at a name that has no SOA (not the apex) is ignored */
    upd_load(&z);
    upd_begin(&m);
    upd_soa(&m, "www." UZ, 1, 105);
    assert(upd_run(&z, &m, &ur) == 0 && !ur.changed);
    assert(upd_count(&z, "www." UZ, 6) == 0);
    zone_arena_destroy(&z);

    /* class NONE SOA delete and class ANY SOA delete are ignored (§3.4.2.3, §3.4.2.4) */
    upd_load(&z);
    upd_begin(&m);
    upd_soa(&m, UZ, 254, 100);
    upd_rr(&m, false, UZ, 6, 255, 0, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 0 && !ur.changed);
    assert(upd_count(&z, UZ, 6) == 1);
    zone_arena_destroy(&z);
    printf("  -> SOA rules passed.\n");
}

static void test_update_cname_dname_rules(void) {
    printf("[TEST] Dynamic Update: CNAME/DNAME conflicts are ignored, singletons replaced (R-11 b)...\n");
    zone_arena_t z;
    upd_msg_t m;
    update_result_t ur;

    /* CNAME next to other data: ignored; the rest of the update is applied */
    upd_load(&z);
    upd_begin(&m);
    upd_named(&m, "www." UZ, 5, 1, "ns1." UZ);
    upd_a(&m, false, "new." UZ, 1, 300, 20);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "www." UZ, 5) == 0 && upd_count(&z, "www." UZ, 1) == 2);
    assert(upd_count(&z, "new." UZ, 1) == 1);
    zone_arena_destroy(&z);

    /* other data next to a CNAME: ignored */
    upd_load(&z);
    upd_begin(&m);
    upd_a(&m, false, "alias." UZ, 1, 300, 30);
    assert(upd_run(&z, &m, &ur) == 0 && !ur.changed);
    assert(upd_count(&z, "alias." UZ, 1) == 0 && upd_count(&z, "alias." UZ, 5) == 1);
    zone_arena_destroy(&z);

    /* CNAME replaces the CNAME */
    upd_load(&z);
    upd_begin(&m);
    upd_named(&m, "alias." UZ, 5, 1, "ns1." UZ);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "alias." UZ, 5) == 1);
    assert(strcasecmp(upd_get(&z, "alias." UZ, 5)->rdata[0], "ns1." UZ) == 0);
    zone_arena_destroy(&z);

    /* KEY may coexist with a CNAME (RFC 4035 §2.5) */
    upd_load(&z);
    upd_begin(&m);
    const uint8_t key_rd[] = { 0x02, 0x00, 3, 8, 0xAA, 0xBB, 0xCC, 0xDD };
    upd_rr(&m, false, "alias." UZ, 25, 1, 300, key_rd, sizeof(key_rd));
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "alias." UZ, 25) == 1 && upd_count(&z, "alias." UZ, 5) == 1);
    zone_arena_destroy(&z);

    /* DNAME coexists with other data, also at the apex (RFC 6672 §2.3); a second DNAME replaces it (§5.2) */
    upd_load(&z);
    upd_begin(&m);
    upd_named(&m, "www." UZ, 39, 1, "t1.example.");
    upd_named(&m, "www." UZ, 39, 1, "t2.example.");
    upd_named(&m, UZ, 39, 1, "t3.example.");
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "www." UZ, 39) == 1 && upd_count(&z, "www." UZ, 1) == 2);
    assert(strcasecmp(upd_get(&z, "www." UZ, 39)->rdata[0], "t2.example.") == 0);
    assert(upd_count(&z, UZ, 39) == 1 && upd_count(&z, UZ, 6) == 1);
    zone_arena_destroy(&z);

    /* DNAME next to a CNAME, and CNAME next to a DNAME: ignored (RFC 6672 §5.2) */
    upd_load(&z);
    upd_begin(&m);
    upd_named(&m, "alias." UZ, 39, 1, "t1.example.");
    upd_named(&m, "dn." UZ, 39, 1, "t1.example.");
    upd_named(&m, "dn." UZ, 5, 1, "www." UZ);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "alias." UZ, 39) == 0);
    assert(upd_count(&z, "dn." UZ, 39) == 1 && upd_count(&z, "dn." UZ, 5) == 0);
    zone_arena_destroy(&z);
    printf("  -> CNAME/DNAME rules passed.\n");
}

static void test_update_delete_rules(void) {
    printf("[TEST] Dynamic Update: apex SOA/NS deletes ignored, other deletes applied (R-11 c)...\n");
    zone_arena_t z;
    upd_msg_t m;
    update_result_t ur;

    /* ANY/ANY at the apex keeps SOA and NS, deletes the rest */
    upd_load(&z);
    upd_begin(&m);
    upd_rr(&m, false, UZ, 255, 255, 0, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, UZ, 6) == 1 && upd_count(&z, UZ, 2) == 2 && upd_count(&z, UZ, 16) == 0);
    zone_arena_destroy(&z);

    /* ANY/NS at the apex is ignored; ANY/NS at a delegation deletes it */
    upd_load(&z);
    upd_begin(&m);
    upd_rr(&m, false, UZ, 2, 255, 0, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 0 && !ur.changed);
    assert(upd_count(&z, UZ, 2) == 2);
    upd_begin(&m);
    upd_rr(&m, false, "sub." UZ, 2, 255, 0, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "sub." UZ, 2) == 0);
    zone_arena_destroy(&z);

    /* NONE/NS: a non-last apex NS is deleted, the last one is kept */
    upd_load(&z);
    upd_begin(&m);
    upd_named(&m, UZ, 2, 254, "ns2." UZ);
    upd_named(&m, UZ, 2, 254, "ns1." UZ);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, UZ, 2) == 1);
    assert(strcasecmp(upd_get(&z, UZ, 2)->rdata[0], "ns1." UZ) == 0);
    zone_arena_destroy(&z);

    /* ANY/ANY at a non-apex name deletes every RRset there; NONE deletes one RR */
    upd_load(&z);
    upd_begin(&m);
    upd_rr(&m, false, "alias." UZ, 255, 255, 0, NULL, 0);
    upd_a(&m, false, "www." UZ, 254, 0, 10);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "alias." UZ, 5) == 0);
    assert(upd_count(&z, "www." UZ, 1) == 1);
    assert(strcmp(upd_get(&z, "www." UZ, 1)->rdata[0], "192.0.2.11") == 0);
    zone_arena_destroy(&z);
    printf("  -> Delete rules passed.\n");
}

static void test_update_add_replace_rules(void) {
    printf("[TEST] Dynamic Update: duplicates replace the zone RR (RFC 2136 §3.4.2.2)...\n");
    zone_arena_t z;
    upd_msg_t m;
    update_result_t ur;

    /* the same RR with the same TTL: no change */
    upd_load(&z);
    upd_begin(&m);
    upd_a(&m, false, "www." UZ, 1, 300, 10);
    assert(upd_run(&z, &m, &ur) == 0 && !ur.changed);
    assert(upd_count(&z, "www." UZ, 1) == 2);
    zone_arena_destroy(&z);

    /* the same RDATA with another TTL replaces the RR (not appended) */
    upd_load(&z);
    upd_begin(&m);
    upd_a(&m, false, "ns1." UZ, 1, 900, 1);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "ns1." UZ, 1) == 1);
    assert(upd_get(&z, "ns1." UZ, 1)->ttl_value == 900);
    zone_arena_destroy(&z);

    /* WKS with the same address and protocol replaces the WKS RR */
    upd_load(&z);
    assert(upd_count(&z, "wks." UZ, 11) == 1);
    upd_begin(&m);
    uint8_t wks_rd[5 + 11] = { 192, 0, 2, 5, 6 };
    wks_rd[5 + 10] = 0x20; // port 82
    upd_rr(&m, false, "wks." UZ, 11, 1, 300, wks_rd, sizeof(wks_rd));
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "wks." UZ, 11) == 1);
    /* another protocol is a different RR */
    upd_begin(&m);
    wks_rd[4] = 17;
    upd_rr(&m, false, "wks." UZ, 11, 1, 300, wks_rd, sizeof(wks_rd));
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "wks." UZ, 11) == 2);
    zone_arena_destroy(&z);
    printf("  -> Add/replace rules passed.\n");
}

static void test_update_prescan_errors(void) {
    printf("[TEST] Dynamic Update: prescan NOTZONE/FORMERR before any change (R-11 a, e)...\n");
    zone_arena_t z;
    upd_msg_t m;
    update_result_t ur;
    upd_load(&z);
    size_t count = z.count;

    /* NOTZONE for add and delete; a valid RR before it is not applied */
    upd_begin(&m);
    upd_a(&m, false, "new." UZ, 1, 300, 20);
    upd_a(&m, false, "out.test.", 1, 300, 20);
    assert(upd_run(&z, &m, &ur) == 10);
    assert(upd_count(&z, "new." UZ, 1) == 0 && z.count == count);
    upd_begin(&m);
    upd_rr(&m, false, "out.test.", 255, 255, 0, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 10);
    upd_begin(&m);
    upd_a(&m, false, "out.test.", 254, 0, 20);
    assert(upd_run(&z, &m, &ur) == 10);

    /* class ANY: TTL, RDLENGTH, meta type other than ANY */
    upd_begin(&m);
    upd_rr(&m, false, "www." UZ, 1, 255, 1, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_a(&m, false, "www." UZ, 255, 0, 10);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_rr(&m, false, "www." UZ, 252, 255, 0, NULL, 0); // AXFR
    assert(upd_run(&z, &m, &ur) == 1);
    /* class NONE: TTL, TYPE ANY */
    upd_begin(&m);
    upd_a(&m, false, "www." UZ, 254, 1, 10);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_rr(&m, false, "www." UZ, 255, 254, 0, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 1);
    /* class ZCLASS: meta types; other classes */
    upd_begin(&m);
    upd_rr(&m, false, "www." UZ, 255, 1, 300, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_rr(&m, false, "www." UZ, 251, 1, 300, NULL, 0); // IXFR
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_a(&m, false, "www." UZ, 3, 300, 10); // CH
    assert(upd_run(&z, &m, &ur) == 1);
    assert(z.count == count);

    /* zone section: ZTYPE != SOA -> FORMERR; ZCLASS != IN -> NOTAUTH (§3.1.1) */
    upd_begin_zone(&m, UZ, 1, 1);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin_zone(&m, UZ, 6, 3);
    assert(upd_run(&z, &m, &ur) == 9);
    upd_begin_zone(&m, UZ, 6, 255);
    assert(upd_run(&z, &m, &ur) == 9);
    zone_arena_destroy(&z);
    printf("  -> Prescan errors passed.\n");
}

static void test_update_prerequisite_rules(void) {
    printf("[TEST] Dynamic Update: prerequisite TTL and RRset set equality (R-11 d, e)...\n");
    zone_arena_t z;
    upd_msg_t m;
    update_result_t ur;
    upd_load(&z);

    /* TTL must be 0 (§3.2.1-§3.2.3) */
    upd_begin(&m);
    upd_rr(&m, true, "www." UZ, 255, 255, 1, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_rr(&m, true, "nx." UZ, 255, 254, 1, NULL, 0);
    assert(upd_run(&z, &m, &ur) == 1);
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 300, 10);
    assert(upd_run(&z, &m, &ur) == 1);

    /* value-dependent: the zone RRset must equal the prerequisite RRset (§3.2.3) */
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 10); // subset
    assert(upd_run(&z, &m, &ur) == 8);
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 11);
    upd_a(&m, true, "www." UZ, 1, 0, 10); // equal, any order
    assert(upd_run(&z, &m, &ur) == 0 && !ur.changed);
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 10);
    upd_a(&m, true, "www." UZ, 1, 0, 11);
    upd_a(&m, true, "www." UZ, 1, 0, 12); // superset
    assert(upd_run(&z, &m, &ur) == 8);
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 10);
    upd_a(&m, true, "www." UZ, 1, 0, 10);
    upd_a(&m, true, "www." UZ, 1, 0, 11); // a set: duplicates do not matter
    assert(upd_run(&z, &m, &ur) == 0);
    /* two RRsets, interleaved */
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 10);
    upd_a(&m, true, "ns1." UZ, 1, 0, 1);
    upd_a(&m, true, "www." UZ, 1, 0, 11);
    assert(upd_run(&z, &m, &ur) == 0);
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 10);
    upd_a(&m, true, "ns1." UZ, 1, 0, 2);
    upd_a(&m, true, "www." UZ, 1, 0, 11);
    assert(upd_run(&z, &m, &ur) == 8);
    /* the prerequisites hold -> the update section is applied */
    upd_begin(&m);
    upd_a(&m, true, "www." UZ, 1, 0, 10);
    upd_a(&m, true, "www." UZ, 1, 0, 11);
    upd_a(&m, false, "www." UZ, 1, 300, 12);
    assert(upd_run(&z, &m, &ur) == 0 && ur.changed);
    assert(upd_count(&z, "www." UZ, 1) == 3);
    zone_arena_destroy(&z);
    printf("  -> Prerequisite rules passed.\n");
}

static void upd_entry_init(zone_db_entry_t *entry) {
    memset(entry, 0, sizeof(*entry));
    strlcpy(entry->domain, UZ, sizeof(entry->domain));
    strlcpy(entry->view_name, "default", sizeof(entry->view_name));
    pthread_mutex_init(&entry->writer_lock, NULL);
    pthread_mutex_init(&entry->ixfr_history.lock, NULL);
    upd_load(&entry->rcu.arena_a);
    upd_load(&entry->rcu.arena_b);
    atomic_store_explicit(&entry->rcu.active, &entry->rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry->serial, 100, memory_order_release);
}

static void upd_entry_destroy(zone_db_entry_t *entry) {
    zone_arena_destroy(&entry->rcu.arena_a);
    zone_arena_destroy(&entry->rcu.arena_b);
    pthread_mutex_destroy(&entry->writer_lock);
    pthread_mutex_destroy(&entry->ixfr_history.lock);
}

static void test_handle_dynamic_update_serial_rules(void) {
    printf("[TEST] Dynamic Update: serial after explicit SOA, no-change and failed updates (RFC 2136 §3.6)...\n");
    zone_db_entry_t entry;
    upd_entry_init(&entry);
    upd_msg_t m;

    /* prerequisites only: NOERROR, nothing published, serial unchanged, no NOTIFY */
    upd_begin(&m);
    upd_rr(&m, true, "www." UZ, 255, 255, 0, NULL, 0);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    assert(atomic_load(&entry.rcu.active) == &entry.rcu.arena_a);
    assert(atomic_load(&entry.serial) == 100);
    assert(!atomic_load(&entry.notify_now));

    /* only ignored RRs (CNAME next to data, older SOA): same */
    upd_begin(&m);
    upd_named(&m, "www." UZ, 5, 1, "ns1." UZ);
    upd_soa(&m, UZ, 1, 50);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    assert(atomic_load(&entry.rcu.active) == &entry.rcu.arena_a);
    assert(atomic_load(&entry.serial) == 100);

    /* explicit newer SOA together with other data: that serial, no automatic increment (R-01) */
    upd_begin(&m);
    upd_soa(&m, UZ, 1, 500);
    upd_a(&m, false, "new." UZ, 1, 300, 20);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    zone_arena_t *cur = atomic_load(&entry.rcu.active);
    assert(cur == &entry.rcu.arena_b);
    assert(atomic_load(&entry.serial) == 500);
    assert(upd_count(cur, UZ, 6) == 1 && strcmp(upd_get(cur, UZ, 6)->rdata[2], "500") == 0);
    assert(upd_count(cur, "new." UZ, 1) == 1);
    assert(atomic_load(&entry.notify_now));

    /* a change without SOA: the server increments the serial */
    upd_begin(&m);
    upd_a(&m, false, "new2." UZ, 1, 300, 21);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    cur = atomic_load(&entry.rcu.active);
    assert(atomic_load(&entry.serial) == 501);
    assert(strcmp(upd_get(cur, UZ, 6)->rdata[2], "501") == 0);

    /* an error after a valid RR: nothing applied (§3.4.2.1 / atomic update) */
    upd_begin(&m);
    upd_a(&m, false, "new3." UZ, 1, 300, 22);
    upd_rr(&m, false, "www." UZ, 1, 255, 5, NULL, 0); // class ANY with TTL != 0 -> FORMERR
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 1);
    assert(atomic_load(&entry.rcu.active) == cur);
    assert(upd_count(cur, "new3." UZ, 1) == 0);
    assert(atomic_load(&entry.serial) == 501);

    upd_entry_destroy(&entry);
    printf("  -> Serial rules passed.\n");
}

/* process_dns_query_impl(): zone section before permission (RFC 2136 §3.1.2), secondary -> REFUSED */
static int upd_query(const upd_msg_t *m, const char *zname, uint16_t ztype, const char *client,
                     zone_db_snapshot_t *snap, server_config_t *cfg, uint8_t *res, size_t res_cap) {
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    zone_db_entry_t *matched = NULL;
    return process_dns_query_impl(m->b, m->len, res, res_cap, zname, ztype, client, &comp_ctx, false,
                                  NULL, snap, cfg, &matched);
}

static bool upd_res_has_ede(const uint8_t *res, int len, uint16_t code) {
    for (int i = 12; i + 6 <= len; i++) {
        if (res[i] == 0 && res[i + 1] == 15 && ((res[i + 4] << 8) | res[i + 5]) == code) return true;
    }
    return false;
}

static void test_update_dispatch_zone_section(void) {
    printf("[TEST] Dynamic Update: zone section dispatch (NOTAUTH, FORMERR) and secondary REFUSED...\n");
    char *allow[1] = { "192.0.2.1" };
    zone_config_t sec_cfg;
    memset(&sec_cfg, 0, sizeof(sec_cfg));
    sec_cfg.domain = "sec.example.";
    sec_cfg.type = "slave";
    sec_cfg.allow_update = allow;
    sec_cfg.allow_update_count = 1;
    zone_config_t prim_cfg;
    memset(&prim_cfg, 0, sizeof(prim_cfg));
    prim_cfg.domain = UZ;
    prim_cfg.type = "master";
    prim_cfg.allow_update = allow;
    prim_cfg.allow_update_count = 1;
    prim_cfg.next = &sec_cfg;
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.zones = &prim_cfg;
    cfg.send_extended_errors = true;

    zone_db_entry_t prim;
    upd_entry_init(&prim);
    zone_db_entry_t sec;
    memset(&sec, 0, sizeof(sec));
    strlcpy(sec.domain, "sec.example.", sizeof(sec.domain));
    strlcpy(sec.view_name, "default", sizeof(sec.view_name));
    zone_arena_init(&sec.rcu.arena_a);
    atomic_store_explicit(&sec.rcu.active, &sec.rcu.arena_a, memory_order_release);

    zone_db_entry_t *entries[2] = { &prim, &sec };
    char *any_acl[1] = { "any" };
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 2;
    view.match_clients = any_acl;
    view.match_clients_count = 1;
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    uint8_t res[4096];
    upd_msg_t m;

    /* secondary: REFUSED + EDE 18 for an allowed and for a not allowed client (maintainer decision) */
    upd_begin_zone(&m, "sec.example.", 6, 1);
    upd_a(&m, false, "x.sec.example.", 1, 300, 9);
    const uint8_t opt[11] = { 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 }; // OPT, UDP 1232
    memcpy(m.b + m.len, opt, sizeof(opt));
    m.len += sizeof(opt);
    m.b[11] = 1; // ARCOUNT
    int len = upd_query(&m, "sec.example.", 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 5);
    assert(upd_res_has_ede(res, len, 18));
    len = upd_query(&m, "sec.example.", 6, "192.0.2.99", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 5);

    /* a name below a served zone, and a zone that is not served: NOTAUTH, also for an allowed client */
    upd_begin_zone(&m, "x." UZ, 6, 1);
    len = upd_query(&m, "x." UZ, 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 9);
    upd_begin_zone(&m, "other.test.", 6, 1);
    len = upd_query(&m, "other.test.", 6, "192.0.2.99", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 9);
    /* ZCLASS CH -> NOTAUTH; ZTYPE A -> FORMERR, before the permission check */
    upd_begin_zone(&m, UZ, 6, 3);
    len = upd_query(&m, UZ, 6, "192.0.2.99", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 9);
    upd_begin_zone(&m, UZ, 1, 1);
    len = upd_query(&m, UZ, 1, "192.0.2.99", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 1);

    /* primary: not allowed -> REFUSED; allowed -> NOERROR and applied */
    upd_begin(&m);
    upd_a(&m, false, "new." UZ, 1, 300, 20);
    len = upd_query(&m, UZ, 6, "192.0.2.99", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 5);
    len = upd_query(&m, UZ, 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    assert(len >= 12 && (res[3] & 0x0F) == 0);
    assert(upd_count(atomic_load(&prim.rcu.active), "new." UZ, 1) == 1);
    assert(atomic_load(&prim.serial) == 101);

    upd_entry_destroy(&prim);
    zone_arena_destroy(&sec.rcu.arena_a);
    printf("  -> Zone section dispatch passed.\n");
}

int main(void) {
    printf("=== Starting Dynamic Update Engine Unit Tests ===\n");
    test_bump_soa_serial();
    test_process_update_sections_records();
    test_process_update_sections_apex_ns_protection();
    test_dynamic_update_prerequisites_and_error_paths();
    test_handle_dynamic_update_pipeline();
    test_update_multi_tsig_keys();
    test_update_soa_rules();
    test_update_cname_dname_rules();
    test_update_delete_rules();
    test_update_add_replace_rules();
    test_update_prescan_errors();
    test_update_prerequisite_rules();
    test_handle_dynamic_update_serial_rules();
    test_update_dispatch_zone_section();
    test_send_notify_to_all_comprehensive();
    printf("=== All Dynamic Update Engine Unit Tests PASSED ===\n");
    return 0;
}


/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}

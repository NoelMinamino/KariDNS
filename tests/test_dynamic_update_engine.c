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
#include "dns_dynamic_update.h"
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

static void test_notify_construction_and_dedup(void) {
    printf("[TEST] Dynamic Update: NOTIFY target deduplication & wire construction...\n");
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) == 0);

    // Setup config with also-notify
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "example.com";
    zcfg.also_notify_count = 2;
    ip_port_t notifys[2];
    notifys[0].ip = "192.0.2.10";
    notifys[0].port = 53;
    // Duplicate entry (same IP + port) to test dedup
    notifys[1].ip = "192.0.2.10";
    notifys[1].port = 53;
    zcfg.also_notify = notifys;
    zcfg.next = NULL;

    cfg.zones = &zcfg;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    send_notify_to_all("example.com", NULL);

    // Intercept message from g_notify_ipc[0]
    uint8_t buf[2048];
    ssize_t n = recv(g_notify_ipc[0], buf, sizeof(buf), MSG_DONTWAIT);
    assert(n > 0);
    assert(n >= (ssize_t)sizeof(udp_ipc_t) + DNS_HEADER_SIZE);

    udp_ipc_t *ipc = (udp_ipc_t *)buf;
    assert(ipc->sock_fd_idx == -1); // Dynamic UDP / NOTIFY
    uint8_t *dns_payload = buf + sizeof(udp_ipc_t);
    uint8_t opcode = (dns_payload[2] >> 3) & 0x0F;
    assert(opcode == 4); // NOTIFY Opcode
    assert((dns_payload[2] & 0x04) != 0); // AA bit set

    // Verify only ONE packet was sent (deduped)
    ssize_t n2 = recv(g_notify_ipc[0], buf, sizeof(buf), MSG_DONTWAIT);
    assert(n2 < 0); // No second packet

    close(g_notify_ipc[0]);
    close(g_notify_ipc[1]);
    g_notify_ipc[0] = -1;
    g_notify_ipc[1] = -1;
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);

    printf("  -> NOTIFY deduplication & IPC passed.\n");
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

int main(void) {
    printf("=== Starting Dynamic Update Engine Unit Tests ===\n");
    test_bump_soa_serial();
    test_notify_construction_and_dedup();
    test_process_update_sections_records();
    printf("=== All Dynamic Update Engine Unit Tests PASSED ===\n");
    return 0;
}

#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdarg.h>
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
#include "test_zext.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "test_image_helper.h"
#include "dns_snapshot_rcu.h"
#include "dns_dynamic_update.h"
#include "dns_query_engine.h"
#include "dns_axfr_ixfr.h"
#include "dns_utils.h"
#include "test_zone_slots.h"

// Mock globals needed by server internal dependencies
_Atomic int g_control_kq = -1;
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
    if (getenv("NT_DEBUG")) { /* NT_DEBUG=1 ./test_dynamic_update_engine shows what the server would have logged */
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        fputc('\n', stderr);
        va_end(ap);
    }
}

server_config_t *acquire_config_snapshot(void) {
    return atomic_load_explicit(&g_config_db.active, memory_order_acquire);
}
void release_config_snapshot(server_config_t *snap) { (void)snap; }

/* NOTIFY over TCP: the broker mock hands out one end of a socketpair (when g_broker_on) and keeps the other for the test, which plays the peer */
#define PEERS_MAX 600
static _Atomic int g_peer_fd[PEERS_MAX];   /* -1 until the thread's connection exists */
static _Atomic int g_peer_n;               /* connections made so far */
static _Atomic int g_broker_on;
static tcp_sockopts_t g_peer_opts[PEERS_MAX];

static int mock_broker(int type, const tcp_sockopts_t *opts) {
    if (!atomic_load(&g_broker_on) || type != SOCK_STREAM) return -1;
    int idx = atomic_fetch_add(&g_peer_n, 1);
    int sv[2];
    if (idx >= PEERS_MAX || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    if (opts) g_peer_opts[idx] = *opts;
    else memset(&g_peer_opts[idx], 0, sizeof(g_peer_opts[idx]));
    atomic_store(&g_peer_fd[idx], sv[1]);
    return sv[0];
}

int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len) {
    (void)family; (void)addr; (void)addr_len;
    return mock_broker(type, NULL);
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
    DNS_RECORD_BIND_RDATA(rec);
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

    // X-17: the arena cannot allocate the new serial text -> 0 (failure), SOA unchanged
    size_t saved_pools = arena.data_pool_count, saved_idx = arena.current_pool_idx;
    arena.data_pool_count = 128;                    // arena_alloc() refuses a 129th pool
    arena.current_pool_idx = arena.current_pool_cap; // and the current pool is full
    assert(bump_soa_serial_in_arena(&arena, "example.com.") == 0);
    assert(strcmp(arena.records[0].rdata[2], "1") == 0);
    arena.data_pool_count = saved_pools;
    arena.current_pool_idx = saved_idx;

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
    DNS_RECORD_BIND_RDATA(soa_rec);
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
    assert(test_build_index(&arena, true) == 0);

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
    arena_record_alloc_rdata(arena, &rec, 7);   /* rec は関数を出ると消えるので、rdata[] は arena に持たせる */
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
    assert(test_build_index(arena, true) == 0);
}

static void test_handle_dynamic_update_pipeline(void) {
    printf("[TEST] Dynamic Update: handle_dynamic_update() full pipeline...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_sample_zone_arena(test_zone_slot(&entry, 0), "example.com.", "1000");
    init_sample_zone_arena(test_zone_slot(&entry, 1), "example.com.", "1000");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->heap); /* a new heap version was published */

    // Verify record in active arena (arena_b)
    zone_version_t *z_cur = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
    assert(z_cur->image != NULL); /* S5 B-2: only the image is published (a zone_version_t has no builder) */
    /* S5 B-1: the published version carries the image the engine reads, with the added RR in it */
    assert(z_cur->image != NULL && z_cur->image->n_rrs == 2);
    uint32_t www_id = zone_image_find_name(z_cur->image, "www.example.com.");
    assert(www_id != ZONE_IMAGE_NONE && zone_image_rrset_next(z_cur->image, www_id, 1, zone_image_name_first_rr(z_cur->image, www_id)) != ZONE_IMAGE_NONE);

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
    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);

    printf("  -> handle_dynamic_update pipeline passed.\n");
}

/* S5 B-2: an RR of an UPDATE that cannot be written in wire format (a TXT with no RDATA, RFC 1035 §3.3.14 wants at
 * least one character-string) is dropped with a warning and the rest of the UPDATE is applied. */
static void test_handle_dynamic_update_drops_unencodable(void) {
    printf("[TEST] Dynamic Update: an RR that cannot be encoded is dropped, the rest is applied...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_sample_zone_arena(test_zone_slot(&entry, 0), "example.com.", "1000");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 1000, memory_order_release);

    uint8_t pkt[512] = {0};
    pkt[0] = 0x12; pkt[1] = 0x35;
    pkt[2] = 0x28; // UPDATE
    pkt[5] = 1;    // ZOCOUNT=1
    pkt[9] = 2;    // UPCOUNT=2
    size_t off = 12;
    static const uint8_t zname[] = { 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0 };
    memcpy(&pkt[off], zname, sizeof(zname)); off += sizeof(zname);
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1; // SOA IN
    // 1. add www.example.com. A 192.0.2.7
    pkt[off++] = 3; memcpy(&pkt[off], "www", 3); off += 3;
    memcpy(&pkt[off], zname, sizeof(zname)); off += sizeof(zname);
    pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 4;
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 7;
    // 2. add bad.example.com. TXT with RDLENGTH 0
    pkt[off++] = 3; memcpy(&pkt[off], "bad", 3); off += 3;
    memcpy(&pkt[off], zname, sizeof(zname)); off += sizeof(zname);
    pkt[off++] = 0; pkt[off++] = 16; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C;
    pkt[off++] = 0; pkt[off++] = 0;

    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "key") == 0);
    assert(atomic_load_explicit(&entry.serial, memory_order_acquire) == 1001);
    zone_version_t *cur = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
    assert(cur != &test_zone_slot(&entry, 0)->ver && cur->heap && cur->image != NULL);
    assert(cur->image->n_rrs == 2);   /* SOA + www A: the TXT was dropped, the A applied */
    uint32_t id = zone_image_find_name(cur->image, "www.example.com.");
    assert(id != ZONE_IMAGE_NONE && zone_image_rrset_next(cur->image, id, 1, zone_image_name_first_rr(cur->image, id)) != ZONE_IMAGE_NONE);
    assert(zone_image_find_name(cur->image, "bad.example.com.") == ZONE_IMAGE_NONE);

    /* 3. an UPDATE whose only addition cannot be encoded changes nothing: no serial bump, nothing published
     * (RFC 2136 §3.6) */
    pkt[1] = 0x36;
    pkt[9] = 1; // UPCOUNT=1
    size_t off2 = 12 + sizeof(zname) + 4;
    pkt[off2++] = 3; memcpy(&pkt[off2], "bad", 3); off2 += 3;
    memcpy(&pkt[off2], zname, sizeof(zname)); off2 += sizeof(zname);
    pkt[off2++] = 0; pkt[off2++] = 16; pkt[off2++] = 0; pkt[off2++] = 1;
    pkt[off2++] = 0; pkt[off2++] = 0; pkt[off2++] = 1; pkt[off2++] = 0x2C;
    pkt[off2++] = 0; pkt[off2++] = 0;
    uint32_t serial_before = atomic_load_explicit(&entry.serial, memory_order_acquire);
    assert(handle_dynamic_update(pkt, off2, &entry, "127.0.0.1", "key") == 0);
    assert(atomic_load_explicit(&entry.serial, memory_order_acquire) == serial_before);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire) == cur);

    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> unencodable UPDATE RR dropped passed.\n");
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
    tzx(&zcfg1)->notify_source = "192.0.2.1";
    tzx(&zcfg1)->also_notify_count = 3;
    notify_target_t notifys[3];
    memset(notifys, 0, sizeof(notifys));
    notifys[0].ip = "192.0.2.10";
    notifys[0].port = 53;
    notifys[1].ip = "2001:db8::10";
    notifys[1].port = 5353;
    notifys[2].ip = "invalid.ip"; // Invalid IP to test parse failure
    notifys[2].port = 53;
    tzx(&zcfg1)->also_notify = notifys;
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

    init_sample_zone_arena(test_zone_slot(z1, 0), "example.com.", "100");

    // Add NS records and glue in z1
    // NS 1: ns1.example.com (matches SOA MNAME -> excluded)
    // NS 2: ns2.example.com -> in-zone A and AAAA glue
    // NS 3: ns1.sibling.com -> sibling zone glue
    zone_arena_t *a1 = test_zone_slot(z1, 0);
    dns_record_t *new_recs = realloc(a1->records, sizeof(dns_record_t) * 16);
    assert(new_recs);
    a1->records = new_recs;
    a1->records_cap = 16;

    // NS records
    dns_record_t r_ns1; memset(&r_ns1, 0, sizeof(r_ns1));
    DNS_RECORD_BIND_RDATA(r_ns1);
    r_ns1.name = arena_strdup(a1, "example.com.");
    r_ns1.type_code = 2; r_ns1.rdata_count = 1;
    r_ns1.rdata[0] = arena_strdup(a1, "ns1.example.com.");
    a1->records[a1->count++] = r_ns1;

    dns_record_t r_ns2; memset(&r_ns2, 0, sizeof(r_ns2));
    DNS_RECORD_BIND_RDATA(r_ns2);
    r_ns2.name = arena_strdup(a1, "example.com.");
    r_ns2.type_code = 2; r_ns2.rdata_count = 1;
    r_ns2.rdata[0] = arena_strdup(a1, "ns2.example.com.");
    a1->records[a1->count++] = r_ns2;

    dns_record_t r_ns3; memset(&r_ns3, 0, sizeof(r_ns3));
    DNS_RECORD_BIND_RDATA(r_ns3);
    r_ns3.name = arena_strdup(a1, "example.com.");
    r_ns3.type_code = 2; r_ns3.rdata_count = 1;
    r_ns3.rdata[0] = arena_strdup(a1, "ns1.sibling.com.");
    a1->records[a1->count++] = r_ns3;

    // In-zone A & AAAA glue for ns2.example.com
    dns_record_t r_g4; memset(&r_g4, 0, sizeof(r_g4));
    DNS_RECORD_BIND_RDATA(r_g4);
    r_g4.name = arena_strdup(a1, "ns2.example.com.");
    r_g4.type_code = 1; r_g4.rdata_count = 1;
    r_g4.rdata[0] = arena_strdup(a1, "192.0.2.20");
    a1->records[a1->count++] = r_g4;

    dns_record_t r_g6; memset(&r_g6, 0, sizeof(r_g6));
    DNS_RECORD_BIND_RDATA(r_g6);
    r_g6.name = arena_strdup(a1, "ns2.example.com.");
    r_g6.type_code = 28; r_g6.rdata_count = 1;
    r_g6.rdata[0] = arena_strdup(a1, "2001:db8::20");
    a1->records[a1->count++] = r_g6;

    assert(test_build_index(a1, true) == 0);
    atomic_store_explicit(&z1->rcu.active, &a1->ver, memory_order_release);

    // Sibling zone z2: sibling.com
    init_sample_zone_arena(test_zone_slot(z2, 0), "sibling.com.", "100");
    zone_arena_t *a2 = test_zone_slot(z2, 0);
    dns_record_t *new_recs2 = realloc(a2->records, sizeof(dns_record_t) * 16);
    assert(new_recs2);
    a2->records = new_recs2;
    a2->records_cap = 16;

    dns_record_t r_sib4; memset(&r_sib4, 0, sizeof(r_sib4));
    DNS_RECORD_BIND_RDATA(r_sib4);
    r_sib4.name = arena_strdup(a2, "ns1.sibling.com.");
    r_sib4.type_code = 1; r_sib4.rdata_count = 1;
    r_sib4.rdata[0] = arena_strdup(a2, "198.51.100.30");
    a2->records[a2->count++] = r_sib4;

    dns_record_t r_sib6; memset(&r_sib6, 0, sizeof(r_sib6));
    DNS_RECORD_BIND_RDATA(r_sib6);
    r_sib6.name = arena_strdup(a2, "ns1.sibling.com.");
    r_sib6.type_code = 28; r_sib6.rdata_count = 1;
    r_sib6.rdata[0] = arena_strdup(a2, "2001:db8:ffff::30");
    a2->records[a2->count++] = r_sib6;

    assert(test_build_index(a2, true) == 0);
    atomic_store_explicit(&z2->rcu.active, &a2->ver, memory_order_release);

    send_notify_to_all(z1);

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
    DNS_RECORD_BIND_RDATA(soa);
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
    DNS_RECORD_BIND_RDATA(ns1);
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

    assert(test_build_index(&arena, true) == 0);

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
    DNS_RECORD_BIND_RDATA(ns2);
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
    assert(test_build_index(&arena, true) == 0);

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
    tzx(&zcfg)->allow_update = allow_keys;
    tzx(&zcfg)->allow_update_count = 2;
    cfg.zones = &zcfg;

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    init_sample_zone_arena(test_zone_slot(&entry, 0), "example.com.", "100");
    init_sample_zone_arena(test_zone_slot(&entry, 1), "example.com.", "100");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
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

    zone_arena_destroy(test_zone_slot(&entry, 0));
    zone_arena_destroy(test_zone_slot(&entry, 1));
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
    DNS_RECORD_BIND_RDATA(a_rec);
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
    assert(test_build_index(&arena, true) == 0);

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
    assert(test_build_index(a, true) == 0);
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

/* S5 B-2: a published version has no builder, only its image */
static int upd_img_count(const zone_version_t *a, const char *name, uint16_t type) {
    uint32_t id = zone_image_find_name(a->image, name);
    int n = 0;
    if (id == ZONE_IMAGE_NONE) return 0;
    for (uint32_t k = zone_image_rrset_next(a->image, id, type, zone_image_name_first_rr(a->image, id)); k != ZONE_IMAGE_NONE;
         k = zone_image_rrset_next(a->image, id, type, k + 1))
        n++;
    return n;
}

static uint32_t upd_img_serial(const zone_version_t *a) {
    zone_image_soa_t nums;
    uint32_t rr = zone_image_apex_soa(a->image);
    assert(rr != ZONE_IMAGE_NONE && zone_image_soa(a->image, rr, NULL, 0, NULL, 0, &nums) == 0);
    return nums.serial;
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
    upd_load(test_zone_slot(entry, 0));
    upd_load(test_zone_slot(entry, 1));
    atomic_store_explicit(&entry->rcu.active, &test_zone_slot(entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry->serial, 100, memory_order_release);
}

static void upd_entry_destroy(zone_db_entry_t *entry) {
    zone_arena_destroy(test_zone_slot(entry, 0));
    zone_arena_destroy(test_zone_slot(entry, 1));
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
    assert(atomic_load(&entry.rcu.active) == &test_zone_slot(&entry, 0)->ver);
    assert(atomic_load(&entry.serial) == 100);
    assert(!atomic_load(&entry.notify_now));

    /* only ignored RRs (CNAME next to data, older SOA): same */
    upd_begin(&m);
    upd_named(&m, "www." UZ, 5, 1, "ns1." UZ);
    upd_soa(&m, UZ, 1, 50);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    assert(atomic_load(&entry.rcu.active) == &test_zone_slot(&entry, 0)->ver);
    assert(atomic_load(&entry.serial) == 100);

    /* explicit newer SOA together with other data: that serial, no automatic increment (R-01) */
    upd_begin(&m);
    upd_soa(&m, UZ, 1, 500);
    upd_a(&m, false, "new." UZ, 1, 300, 20);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    zone_version_t *cur = atomic_load(&entry.rcu.active);
    assert(cur->heap);
    assert(atomic_load(&entry.serial) == 500);
    assert(upd_img_count(cur, UZ, 6) == 1 && upd_img_serial(cur) == 500);
    assert(upd_img_count(cur, "new." UZ, 1) == 1);
    assert(atomic_load(&entry.notify_now));

    /* a change without SOA: the server increments the serial */
    upd_begin(&m);
    upd_a(&m, false, "new2." UZ, 1, 300, 21);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 0);
    cur = atomic_load(&entry.rcu.active);
    assert(atomic_load(&entry.serial) == 501);
    assert(upd_img_serial(cur) == 501);

    /* an error after a valid RR: nothing applied (§3.4.2.1 / atomic update) */
    upd_begin(&m);
    upd_a(&m, false, "new3." UZ, 1, 300, 22);
    upd_rr(&m, false, "www." UZ, 1, 255, 5, NULL, 0); // class ANY with TTL != 0 -> FORMERR
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 1);
    assert(atomic_load(&entry.rcu.active) == cur);
    assert(upd_img_count(cur, "new3." UZ, 1) == 0);
    assert(atomic_load(&entry.serial) == 501);

    /* X-17: the serial cannot be incremented (here no apex SOA in the copy: the spelling of the apex in the image
     * the copy is thawed from is changed; an arena allocation failure in bump_soa_serial_in_arena() takes the same
     * branch): SERVFAIL, nothing published, serial unchanged, no NOTIFY (RFC 2136 §3.6: a changed zone must get a
     * new serial). */
    char *apex_text = (char *)zone_image_name_text(cur->image, cur->image->apex_name); // the test changes the copy source
    char apex_first = apex_text[0];
    apex_text[0] = 'X';
    atomic_store(&entry.notify_now, false);
    upd_begin(&m);
    upd_a(&m, false, "new4." UZ, 1, 300, 23);
    assert(handle_dynamic_update(m.b, m.len, &entry, "192.0.2.1", "<none>") == 2);
    assert(atomic_load(&entry.rcu.active) == cur);
    assert(upd_img_count(cur, "new4." UZ, 1) == 0);
    assert(atomic_load(&entry.serial) == 501);
    assert(!atomic_load(&entry.notify_now));
    apex_text[0] = apex_first;

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
    tzx(&sec_cfg)->allow_update = allow;
    tzx(&sec_cfg)->allow_update_count = 1;
    zone_config_t prim_cfg;
    memset(&prim_cfg, 0, sizeof(prim_cfg));
    prim_cfg.domain = UZ;
    prim_cfg.type = "master";
    tzx(&prim_cfg)->allow_update = allow;
    tzx(&prim_cfg)->allow_update_count = 1;
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
    zone_arena_init(test_zone_slot(&sec, 0));
    atomic_store_explicit(&sec.rcu.active, &test_zone_slot(&sec, 0)->ver, memory_order_release);

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
    assert(upd_img_count(atomic_load(&prim.rcu.active), "new." UZ, 1) == 1);
    assert(atomic_load(&prim.serial) == 101);

    upd_entry_destroy(&prim);
    zone_arena_destroy(test_zone_slot(&sec, 0));
    printf("  -> Zone section dispatch passed.\n");
}

/* ---- R-30 / R-07 / R-08 / R-09 / R-20 / D-03 / X-18: TSIG outcome first, then authorization ---- */

static void tk_init(tsig_key_t *k, const char *name, uint8_t fill) {
    memset(k, 0, sizeof(*k));
    k->name = (char *)name;
    k->algorithm = "hmac-sha256";
    k->secret_decoded_len = 32;
    memset(k->secret_decoded, fill, 32);
}

/* sign m with key; returns the request MAC in mac/mac_len */
static void tk_sign(upd_msg_t *m, tsig_key_t *key, uint8_t *mac, size_t *mac_len) {
    size_t len = m->len;
    *mac_len = 0;
    assert(tsig_sign_packet(m->b, &len, sizeof(m->b), key, 0, mac, mac_len, NULL, 0, false) == 0);
    m->len = len;
}

/* the response's TSIG: owner, error, MAC size; and whether it verifies against the request MAC */
static void tk_expect(const uint8_t *res, int len, uint8_t rcode, const char *owner, uint16_t error,
                      uint16_t mac_size, tsig_key_t *verify_key, const uint8_t *req_mac, size_t req_mac_len) {
    assert(len >= 12);
    assert((res[3] & 0x0F) == rcode);
    tsig_rr_t rr;
    int pr = tsig_parse_rr(res, (size_t)len, &rr);
    if (!owner) {
        assert(pr == 0);    /* no TSIG RR at all */
        return;
    }
    assert(pr == 1);
    assert(strcasecmp(rr.key_name, owner) == 0);
    assert(strcasecmp(rr.alg_name, "hmac-sha256.") == 0);
    assert(rr.error == error);
    assert(rr.mac_size == mac_size);
    if (verify_key) {
        uint8_t m[64];
        size_t ml = 0;
        assert(tsig_verify_packet(res, (size_t)len, verify_key, req_mac, req_mac_len, NULL, 0, false, m, &ml) == 0);
    }
}

static void test_update_tsig_matrix(void) {
    printf("[TEST] Dynamic Update: TSIG errors and authorization (RFC 8945 §5.2-§5.3, RFC 2136 §3.3; R-30)...\n");
    tsig_key_t k1, k2, k3, k1_bad;
    tk_init(&k1, "k1", 0x11);
    tk_init(&k2, "K2", 0x22);            /* configured in upper case (D-03) */
    tk_init(&k3, "k3", 0x33);            /* not configured */
    tk_init(&k1_bad, "k1", 0x44);        /* right name, wrong secret */
    k1.next = &k2;

    char *allow_k1[1] = { "K1." };       /* D-03: key references compare as DNS names */
    char *allow_ip[1] = { "192.0.2.1" };
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = UZ;
    zc.type = "master";
    tzx(&zc)->allow_update = allow_k1;
    tzx(&zc)->allow_update_count = 1;
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.zones = &zc;
    cfg.keys = &k1;
    cfg.send_extended_errors = true;

    zone_db_entry_t prim;
    upd_entry_init(&prim);
    zone_db_entry_t *entries[1] = { &prim };
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

    uint8_t res[4096];
    uint8_t mac[64];
    size_t mac_len;
    upd_msg_t m;
    int len;
    const char *C = "192.0.2.99";

    /* allowed key: NOERROR, signed with k1 */
    upd_begin(&m); upd_a(&m, false, "t1." UZ, 1, 300, 31); tk_sign(&m, &k1, mac, &mac_len);
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 0, "k1.", 0, 32, &k1, mac, mac_len);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t1." UZ, 1) == 1);

    /* valid key that allow-update does not list: REFUSED, signed with that key (not k1), error 0 */
    upd_begin(&m); upd_a(&m, false, "t2." UZ, 1, 300, 32); tk_sign(&m, &k2, mac, &mac_len);
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 5, "k2.", 0, 32, &k2, mac, mac_len);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t2." UZ, 1) == 0);

    /* unknown key: NOTAUTH, BADKEY, unsigned, the request's key name echoed */
    upd_begin(&m); upd_a(&m, false, "t3." UZ, 1, 300, 33); tk_sign(&m, &k3, mac, &mac_len);
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 9, "k3.", 17, 0, NULL, NULL, 0);

    /* wrong secret: NOTAUTH, BADSIG, unsigned */
    upd_begin(&m); upd_a(&m, false, "t4." UZ, 1, 300, 34); tk_sign(&m, &k1_bad, mac, &mac_len);
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 9, "k1.", 16, 0, NULL, NULL, 0);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t4." UZ, 1) == 0);

    /* BADTIME (R-08): signed with k1, Time Signed and Fudge are the client's, Other Data = server time */
    k1.fuzztime = 1000000000;
    upd_begin(&m); upd_a(&m, false, "t5." UZ, 1, 300, 35); tk_sign(&m, &k1, mac, &mac_len);
    k1.fuzztime = 0;
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    {
        tsig_rr_t rr;
        assert(tsig_parse_rr(res, (size_t)len, &rr) == 1);
        assert(rr.time_signed == 1000000000 && rr.fudge == 300 && rr.other_len == 6);
        uint64_t srv = ((uint64_t)rr.other[0] << 40) | ((uint64_t)rr.other[1] << 32) | ((uint64_t)rr.other[2] << 24) |
                       ((uint64_t)rr.other[3] << 16) | ((uint64_t)rr.other[4] << 8) | rr.other[5];
        assert(srv + 5 >= (uint64_t)time(NULL) && srv <= (uint64_t)time(NULL));
        k1.fuzztime = 1000000000;     /* a client with the same clock verifies the response incl. the request MAC */
        tk_expect(res, len, 9, "k1.", 18, 32, &k1, mac, mac_len);
        k1.fuzztime = 0;
    }
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t5." UZ, 1) == 0);

    /* BADTRUNC: a MAC truncated to 16 octets (allowed by §5.2.2.1) is below the local policy (full length) */
    upd_begin(&m); upd_a(&m, false, "t6." UZ, 1, 300, 36); tk_sign(&m, &k1, mac, &mac_len);
    {
        tsig_rr_t rr;
        assert(tsig_parse_rr(m.b, m.len, &rr) == 1 && rr.mac_size == 32);
        size_t mac_at = (size_t)(rr.mac - m.b);
        memmove(m.b + mac_at + 16, m.b + mac_at + 32, m.len - (mac_at + 32));
        m.len -= 16;
        m.b[mac_at - 2] = 0; m.b[mac_at - 1] = 16;                     /* MAC Size */
        size_t rdlen_at = rr.rr_offset + 4 /* "k1." */ + 8;
        uint16_t rdlen = (uint16_t)(((m.b[rdlen_at] << 8) | m.b[rdlen_at + 1]) - 16);
        m.b[rdlen_at] = (uint8_t)(rdlen >> 8); m.b[rdlen_at + 1] = (uint8_t)rdlen;
    }
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 9, "k1.", 22, 32, &k1, mac, 16);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t6." UZ, 1) == 0);

    /* R-09: a MAC shorter than max(10, hash/2) is FORMERR, no TSIG in the response */
    upd_begin(&m); upd_a(&m, false, "t7." UZ, 1, 300, 37); tk_sign(&m, &k1, mac, &mac_len);
    {
        tsig_rr_t rr;
        assert(tsig_parse_rr(m.b, m.len, &rr) == 1);
        size_t mac_at = (size_t)(rr.mac - m.b);
        memmove(m.b + mac_at + 8, m.b + mac_at + 32, m.len - (mac_at + 32));
        m.len -= 24;
        m.b[mac_at - 1] = 8;
        size_t rdlen_at = rr.rr_offset + 4 + 8;
        uint16_t rdlen = (uint16_t)(((m.b[rdlen_at] << 8) | m.b[rdlen_at + 1]) - 24);
        m.b[rdlen_at] = (uint8_t)(rdlen >> 8); m.b[rdlen_at + 1] = (uint8_t)rdlen;
    }
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 1, NULL, 0, 0, NULL, NULL, 0);

    /* R-09: two TSIG RRs are FORMERR (they used to make the request count as unsigned) */
    upd_begin(&m); upd_a(&m, false, "t8." UZ, 1, 300, 38); tk_sign(&m, &k1, mac, &mac_len);
    tk_sign(&m, &k1, mac, &mac_len);
    len = upd_query(&m, UZ, 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 1, NULL, 0, 0, NULL, NULL, 0);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t8." UZ, 1) == 0);

    /* R-20: an Original ID that differs from the message ID is accepted (the digest uses it) */
    upd_begin(&m); upd_a(&m, false, "t9." UZ, 1, 300, 39); tk_sign(&m, &k1, mac, &mac_len);
    m.b[0] ^= 0x5A;
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 0, "k1.", 0, 32, &k1, mac, mac_len);
    assert(res[0] == m.b[0] && res[1] == m.b[1]);

    /* X-18: a zone-section error for a validly signed request is signed */
    upd_begin_zone(&m, "x." UZ, 6, 1); tk_sign(&m, &k1, mac, &mac_len);
    len = upd_query(&m, "x." UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 9, "k1.", 0, 32, &k1, mac, mac_len);

    /* zone without allow-update: REFUSED, signed with the request's key */
    tzx(&zc)->allow_update = NULL;
    tzx(&zc)->allow_update_count = 0;
    upd_begin(&m); upd_a(&m, false, "t10." UZ, 1, 300, 40); tk_sign(&m, &k1, mac, &mac_len);
    len = upd_query(&m, UZ, 6, C, &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 5, "k1.", 0, 32, &k1, mac, mac_len);

    /* address ACL: an allowed address with a valid (unlisted) key is accepted and signed, like BIND;
     * an unsigned request from that address stays accepted and unsigned */
    tzx(&zc)->allow_update = allow_ip;
    tzx(&zc)->allow_update_count = 1;
    upd_begin(&m); upd_a(&m, false, "t11." UZ, 1, 300, 41); tk_sign(&m, &k2, mac, &mac_len);
    len = upd_query(&m, UZ, 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 0, "k2.", 0, 32, &k2, mac, mac_len);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t11." UZ, 1) == 1);
    upd_begin(&m); upd_a(&m, false, "t12." UZ, 1, 300, 42);
    len = upd_query(&m, UZ, 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 0, NULL, 0, 0, NULL, NULL, 0);
    /* ... but a TSIG error is never overridden by the address (RFC 8945 §5.2) */
    upd_begin(&m); upd_a(&m, false, "t13." UZ, 1, 300, 43); tk_sign(&m, &k1_bad, mac, &mac_len);
    len = upd_query(&m, UZ, 6, "192.0.2.1", &snap, &cfg, res, sizeof(res));
    tk_expect(res, len, 9, "k1.", 16, 0, NULL, NULL, 0);
    assert(upd_img_count(atomic_load(&prim.rcu.active), "t13." UZ, 1) == 0);

    upd_entry_destroy(&prim);
    printf("  -> TSIG matrix passed.\n");
}

/* ---- NOTIFY over TCP (dns_dynamic_update.c): the exchange on a socketpair, and the whole path from send_notify_to_all() through the
 * (mock) connect broker.  The mock broker hands out one end of a socketpair and keeps the other for the test, which plays the peer. ---- */
#include <poll.h>

enum { PB_OK, PB_OK_SIGNED, PB_UNSIGNED, PB_BADSIG, PB_BADID, PB_CLOSE, PB_GARBLE, PB_SHORT, PB_BIGLEN, PB_HOLD };

static void peers_reset(void) {
    for (int i = 0; i < PEERS_MAX; i++) atomic_store(&g_peer_fd[i], -1);
    atomic_store(&g_peer_n, 0);
}

/* the connection number idx (waits for the thread to make it), or -1 */
static int peer_wait(int idx) {
    for (int i = 0; i < 3000; i++) {
        int fd = atomic_load(&g_peer_fd[idx]);
        if (fd >= 0) return fd;
        usleep(1000);
    }
    return -1;
}

static bool peer_read_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 3000) <= 0) return false;
        ssize_t k = recv(fd, buf + got, n - got, 0);
        if (k <= 0) return false;
        got += (size_t)k;
    }
    return true;
}

/* the answer to the NOTIFY req: QR set, no additional records; signed with key (the request MAC goes into the digest) when beh asks */
static size_t make_answer(const uint8_t *req, size_t rlen, int beh, tsig_key_t *key, tsig_key_t *wrong, uint8_t *out, size_t cap) {
    size_t q = DNS_HEADER_SIZE;
    while (q < rlen && req[q] != 0) q += 1 + req[q];
    q += 5;
    assert(q <= rlen && q <= cap);
    memcpy(out, req, q);
    out[2] |= 0x80;
    out[10] = out[11] = 0;
    if (beh == PB_BADID) out[1] ^= 1;
    if (beh == PB_OK_SIGNED || beh == PB_BADSIG) {
        uint8_t rmac[64];
        size_t rmac_len = 0;
        assert(tsig_verify_packet(req, rlen, key, NULL, 0, NULL, 0, false, rmac, &rmac_len) == 0);
        size_t olen = q;
        assert(tsig_sign_packet(out, &olen, cap, beh == PB_BADSIG ? wrong : key, 0, rmac, &rmac_len, NULL, 0, false) == 0);
        return olen;
    }
    return q;
}

/* play the peer of connection idx: read the framed NOTIFY, check it, answer by beh.  Returns the NOTIFY (without the prefix) in req. */
static size_t peer_serve(int idx, int beh, tsig_key_t *key, tsig_key_t *wrong, uint8_t *req, size_t req_cap) {
    int fd = peer_wait(idx);
    assert(fd >= 0);
    uint8_t lp[2];
    assert(peer_read_exact(fd, lp, 2));
    size_t rlen = ((size_t)lp[0] << 8) | lp[1];
    assert(rlen >= DNS_HEADER_SIZE && rlen <= req_cap);
    assert(peer_read_exact(fd, req, rlen));
    assert(((req[2] >> 3) & 0x0F) == 4 && req[5] == 1); /* opcode NOTIFY, one question */
    uint8_t out[2 + 1024];
    size_t alen = 0;
    switch (beh) {
    case PB_OK: case PB_OK_SIGNED: case PB_UNSIGNED: case PB_BADSIG: case PB_BADID:
        alen = make_answer(req, rlen, beh == PB_UNSIGNED ? PB_OK : beh, key, wrong, out + 2, sizeof(out) - 2);
        break;
    case PB_GARBLE: alen = 20; for (size_t i = 0; i < alen; i++) out[2 + i] = (uint8_t)(0x5A ^ i); break;
    case PB_SHORT: alen = 5; memset(out + 2, 'x', alen); break;
    case PB_BIGLEN: out[0] = 0xFF; out[1] = 0xFF; assert(send(fd, out, 2, MSG_NOSIGNAL) == 2); close(fd); return rlen;
    case PB_HOLD: return rlen; /* keep the connection open and say nothing: the caller closes it */
    default: break; /* PB_CLOSE */
    }
    if (alen) {
        out[0] = (uint8_t)(alen >> 8);
        out[1] = (uint8_t)(alen & 0xFF);
        assert(send(fd, out, 2 + alen, MSG_NOSIGNAL) == (ssize_t)(2 + alen));
    }
    close(fd);
    return rlen;
}

static void wait_idle(void) {
    for (int i = 0; i < 6000 && notify_tcp_in_flight() != 0; i++) usleep(1000);
    assert(notify_tcp_in_flight() == 0);
}

/* close the connections that threads have made and left unanswered, until no thread runs any more */
static void peers_close_until_idle(int *next) {
    for (int i = 0; i < 6000 && (notify_tcp_in_flight() != 0 || *next < atomic_load(&g_peer_n)); i++) {
        while (*next < atomic_load(&g_peer_n)) {
            int fd = atomic_load(&g_peer_fd[*next]);
            if (fd < 0) break;
            close(fd);
            atomic_store(&g_peer_fd[*next], -2);
            (*next)++;
        }
        usleep(1000);
    }
    assert(notify_tcp_in_flight() == 0);
}

typedef struct { int fd; uint8_t part[16]; size_t n; } rt_peer_t;
/* read the 42 octets of the request, send the first n octets of part, close */
static void *rt_peer_close(void *arg) {
    rt_peer_t *p = arg;
    uint8_t in[2 + 40];
    if (peer_read_exact(p->fd, in, sizeof(in)) && p->n) (void)!send(p->fd, p->part, p->n, MSG_NOSIGNAL);
    close(p->fd);
    return NULL;
}

static void test_notify_tcp_roundtrip(void) {
    printf("[TEST] NOTIFY over TCP: notify_tcp_roundtrip() on a socketpair (answer, short/huge length, close, stall)...\n");
    uint8_t msg[40];
    memset(msg, 0, sizeof(msg));
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
    uint8_t resp[64];
    size_t rl = 0;
    int sv[2];

    /* an answer of 30 octets: the request leaves with its length prefix */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    uint8_t ans[2 + 30];
    ans[0] = 0; ans[1] = 30;
    for (int i = 0; i < 30; i++) ans[2 + i] = (uint8_t)(0x80 + i);
    assert(send(sv[1], ans, sizeof(ans), 0) == (ssize_t)sizeof(ans));
    assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 2000) == NOTIFY_TCP_OK);
    assert(rl == 30 && resp[0] == 0x80 && resp[29] == 0x80 + 29);
    uint8_t got[2 + 40];
    assert(peer_read_exact(sv[1], got, sizeof(got)));
    assert(got[0] == 0 && got[1] == 40 && memcmp(got + 2, msg, 40) == 0);
    close(sv[0]); close(sv[1]);

    /* a length below a DNS header, one above the room we give it (a peer's number is not trusted), and the exact fit */
    static const uint16_t lens[3] = {5, 65, 0xFFFF};
    for (int k = 0; k < 3; k++) {
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        uint8_t lp[2] = {(uint8_t)(lens[k] >> 8), (uint8_t)(lens[k] & 0xFF)};
        assert(send(sv[1], lp, 2, 0) == 2);
        assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 2000) == NOTIFY_TCP_BAD_LENGTH);
        close(sv[0]); close(sv[1]);
    }
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    uint8_t fit[2 + 64];
    memset(fit, 7, sizeof(fit));
    fit[0] = 0; fit[1] = 64;
    assert(send(sv[1], fit, sizeof(fit), 0) == (ssize_t)sizeof(fit));
    assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 2000) == NOTIFY_TCP_OK && rl == 64);
    close(sv[0]); close(sv[1]);

    /* the peer reads the request and closes: before the length, in the middle of the length, in the middle of the message */
    for (int k = 0; k < 3; k++) {
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        rt_peer_t rp = {.fd = sv[1], .n = k == 0 ? 0 : k == 1 ? 1 : 12};
        rp.part[0] = 0; rp.part[1] = 30;
        pthread_t th;
        assert(pthread_create(&th, NULL, rt_peer_close, &rp) == 0);
        assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 2000) == NOTIFY_TCP_CLOSED);
        pthread_join(th, NULL);
        close(sv[0]);
    }

    /* the peer is gone before we write: EPIPE is an error, not a signal */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    close(sv[1]);
    assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 2000) == NOTIFY_TCP_IO);
    close(sv[0]);

    /* silence, and a message that does not fit the frame, are bounded */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    time_t t0 = time(NULL);
    assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 150) == NOTIFY_TCP_TIMEOUT);
    assert(time(NULL) - t0 <= 2);
    uint8_t big[2000];
    memset(big, 0, sizeof(big));
    assert(notify_tcp_roundtrip(sv[0], big, sizeof(big), resp, sizeof(resp), &rl, 150) == NOTIFY_TCP_IO);
    /* a peer that sends the length and then one octet a time is held to the whole timeout, not to each octet */
    uint8_t slow[2] = {0, 30};
    assert(send(sv[1], slow, 2, 0) == 2);
    t0 = time(NULL);
    assert(notify_tcp_roundtrip(sv[0], msg, sizeof(msg), resp, sizeof(resp), &rl, 200) == NOTIFY_TCP_TIMEOUT);
    assert(time(NULL) - t0 <= 2);
    close(sv[0]); close(sv[1]);
    printf("  -> notify_tcp_roundtrip passed.\n");
}

/* One zone with also-notify addresses, a `server 192.0.2.0/24 { tcp-only yes; }` statement and a TSIG key, published as the active
 * configuration and snapshot.  The notify mode is explicit (only the also-notify list), the rate is high so that notify-rate does not
 * hold anything back. */
#define NT_TARGETS 8
static server_config_t nt_cfg;
static view_config_t nt_view;
static zone_config_t nt_zone;
static notify_target_t nt_an[NT_TARGETS];
static server_stmt_t nt_srv;
static tsig_key_t nt_key, nt_wrong;
static xfr_source_t nt_xs[1];

static zone_db_entry_t *nt_setup(const char *const *targets, int n, bool tcp_only, bool signed_zone, int retries) {
    memset(&nt_cfg, 0, sizeof(nt_cfg));
    memset(&nt_view, 0, sizeof(nt_view));
    memset(&nt_zone, 0, sizeof(nt_zone));
    memset(nt_an, 0, sizeof(nt_an));
    memset(&nt_srv, 0, sizeof(nt_srv));
    memset(&nt_key, 0, sizeof(nt_key));
    memset(&nt_wrong, 0, sizeof(nt_wrong));
    nt_key.name = "tcpkey.example.";
    nt_key.algorithm = "hmac-sha256";
    nt_key.secret_decoded_len = 32;
    memset(nt_key.secret_decoded, 0x5C, 32);
    nt_wrong = nt_key;
    memset(nt_wrong.secret_decoded, 0x3D, 32);
    nt_cfg.keys = &nt_key;
    nt_cfg.notify_rate = 100000;
    nt_cfg.notify_rate_set = true;
    nt_cfg.notify_retry.retries = retries;
    nt_cfg.notify_retry.interval = 1;
    nt_cfg.notify_retry.backoff = NOTIFY_BACKOFF_FIXED;
    nt_view.name = "default";
    nt_zone.domain = "tcp.example.";
    tzx(&nt_zone)->notify_mode = NOTIFY_MODE_EXPLICIT;
    if (signed_zone) tzx(&nt_zone)->tsig_key = "tcpkey.example.";
    for (int i = 0; i < n; i++) {
        nt_an[i].ip = (char *)(uintptr_t)targets[i];
        nt_an[i].port = 53;
    }
    /* the first target has the `source` of its list (a NOTIFY source the server had at start-up) */
    nt_an[0].src_set[0] = 1;
    inet_pton(AF_INET, "192.0.2.77", nt_an[0].src[0]);
    memset(nt_xs, 0, sizeof(nt_xs));
    nt_xs[0].family = AF_INET;
    inet_pton(AF_INET, "192.0.2.77", nt_xs[0].addr);
    nt_xs[0].notify = true;
    nt_cfg.xfr_sources = nt_xs;
    nt_cfg.xfr_source_count = 1;
    config_set_startup_xfr_sources(&nt_cfg);
    tzx(&nt_zone)->also_notify = nt_an;
    tzx(&nt_zone)->also_notify_count = n;
    tzx(&nt_zone)->also_notify_set = true;
    if (tcp_only) {
        nt_srv.family = AF_INET;
        nt_srv.plen = 24;
        inet_pton(AF_INET, "192.0.2.0", nt_srv.addr);
        nt_srv.set = SV_B_TCP_ONLY;
        nt_srv.bools = SV_B_TCP_ONLY;
        nt_cfg.servers = &nt_srv;
    }
    nt_view.zones = &nt_zone;
    nt_cfg.views = &nt_view;
    atomic_store_explicit(&g_config_db.active, &nt_cfg, memory_order_release);
    zone_db_snapshot_t *snap = rebuild_zone_db_snapshot(&nt_cfg, NULL, NULL, NULL, NULL, 0);
    assert(snap != NULL);
    zone_db_entry_t *z = snapshot_get_zone(snap, "tcp.example.");
    assert(z);
    return z;
}

static void nt_teardown(void) { atomic_store_explicit(&g_config_db.active, NULL, memory_order_release); }

/* the datagrams that send_notify_to_all() put on the NOTIFY IPC (the UDP ones); each is stored in dg[] */
typedef struct { alignas(udp_ipc_t) uint8_t b[1200]; } nt_dgram_t;
static int nt_drain_ipc(nt_dgram_t *dg, size_t *lens, int max) {
    int n = 0;
    while (n < max) {
        ssize_t k = recv(g_notify_ipc[0], dg[n].b, sizeof(dg[n].b), MSG_DONTWAIT);
        if (k <= 0) break;
        lens[n++] = (size_t)k;
    }
    return n;
}

/* an earlier test may have left NOTIFYs in the pending table: send them all over TCP with a broker that cannot connect (the threads end at once) */
static void nt_drain_pending(void) {
    atomic_store(&g_broker_on, 0);
    for (int k = 1; k <= 20; k++) notify_retransmit_due(time(NULL) + 1000 * k);
    wait_idle();
    atomic_store(&g_broker_on, 1);
    peers_reset();
}

static void nt_ipc_open(void) { assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) == 0); }
static void nt_ipc_close(void) { close(g_notify_ipc[0]); close(g_notify_ipc[1]); g_notify_ipc[0] = g_notify_ipc[1] = -1; }

static void test_notify_tcp_flow(void) {
    printf("[TEST] NOTIFY over TCP: tcp-only server statement, source address, TSIG, UDP for the other targets...\n");
    nt_ipc_open();
    peers_reset();
    nt_drain_pending();

    /* 192.0.2.10 is covered by the tcp-only statement (TCP, signed by the zone's key, from the list's source 192.0.2.77); 198.51.100.7 is
     * not (one UDP datagram) */
    const char *t1[] = {"192.0.2.10", "198.51.100.7"};
    zone_db_entry_t *z = nt_setup(t1, 2, true, true, 0);
    send_notify_to_all(z);
    nt_dgram_t dg[4];
    size_t dl[4];
    assert(nt_drain_ipc(dg, dl, 4) == 1);                  /* only the uncovered target goes over UDP */
    uint8_t req[1024];
    size_t rl = peer_serve(0, PB_OK_SIGNED, &nt_key, &nt_wrong, req, sizeof(req));
    assert(req[11] == 1);                                  /* ARCOUNT 1: the TSIG */
    assert(tsig_verify_packet(req, rl, &nt_key, NULL, 0, NULL, 0, false, (uint8_t[64]){0}, &(size_t){0}) == 0);
    wait_idle();
    assert(atomic_load(&g_peer_n) == 1);                   /* one connection, no second attempt after an answer that verifies */
    assert(g_peer_opts[0].has_src == 1 && memcmp(g_peer_opts[0].src, nt_an[0].src[0], 4) == 0);
    assert(g_peer_opts[0].connect_timeout_ms > 0);
    notify_retransmit_due(time(NULL) + 100000);            /* the UDP target has no retries left: over TCP; the TCP one is gone from the table */
    assert(nt_drain_ipc(dg, dl, 4) == 0);
    peer_serve(1, PB_OK_SIGNED, &nt_key, &nt_wrong, req, sizeof(req));
    wait_idle();
    assert(atomic_load(&g_peer_n) == 2);
    nt_teardown();

    /* tcp-only without a key: unsigned over TCP, an unsigned answer is fine; an answer with rcode REFUSED is logged and ends it */
    peers_reset();
    const char *t2[] = {"192.0.2.20"};
    z = nt_setup(t2, 1, true, false, 0);
    send_notify_to_all(z);
    assert(nt_drain_ipc(dg, dl, 4) == 0);
    rl = peer_serve(0, PB_OK, &nt_key, &nt_wrong, req, sizeof(req));
    assert(req[11] == 0 && rl > DNS_HEADER_SIZE);
    wait_idle();
    nt_teardown();

    /* an NS host of the zone is reached the same way (the statement is looked up for every target); here: explicit mode keeps this test to
     * the list, so this checks that a second call to the same target replaces nothing and starts a new exchange */
    peers_reset();
    z = nt_setup(t2, 1, true, false, 0);
    send_notify_to_all(z);
    send_notify_to_all(z);
    peer_serve(0, PB_OK, &nt_key, &nt_wrong, req, sizeof(req));
    peer_serve(1, PB_OK, &nt_key, &nt_wrong, req, sizeof(req));
    wait_idle();
    nt_teardown();
    nt_ipc_close();
    printf("  -> NOTIFY over TCP flow passed.\n");
}

static void test_notify_tcp_failures(void) {
    printf("[TEST] NOTIFY over TCP: a peer that closes, garbles, answers wrongly or stalls (two attempts, then the end)...\n");
    nt_ipc_open();
    nt_drain_pending();
    static const int beh[] = {PB_CLOSE, PB_GARBLE, PB_SHORT, PB_BIGLEN, PB_BADID, PB_UNSIGNED, PB_BADSIG};
    for (size_t b = 0; b < sizeof(beh) / sizeof(beh[0]); b++) {
        peers_reset();
        const char *t[] = {"192.0.2.30"};
        zone_db_entry_t *z = nt_setup(t, 1, true, beh[b] == PB_UNSIGNED || beh[b] == PB_BADSIG, 0);
        send_notify_to_all(z);
        uint8_t req[1024];
        /* tcp-only: a failed attempt is made a second time (BIND notify_done() finds DNS_NOTIFY_TCP clear) */
        peer_serve(0, beh[b], &nt_key, &nt_wrong, req, sizeof(req));
        peer_serve(1, beh[b], &nt_key, &nt_wrong, req, sizeof(req));
        wait_idle();
        assert(atomic_load(&g_peer_n) == 2);
        nt_teardown();
    }
    /* a stalled peer holds its thread, not the control thread; closing the connection ends the attempt */
    peers_reset();
    const char *t[] = {"192.0.2.31"};
    zone_db_entry_t *z = nt_setup(t, 1, true, false, 0);
    send_notify_to_all(z);
    uint8_t req[1024];
    peer_serve(0, PB_HOLD, &nt_key, &nt_wrong, req, sizeof(req));
    assert(notify_tcp_in_flight() == 1);
    int next = 0;
    peers_close_until_idle(&next);
    nt_teardown();

    /* the broker cannot connect: both attempts fail without a connection */
    peers_reset();
    atomic_store(&g_broker_on, 0);
    z = nt_setup(t, 1, true, false, 0);
    send_notify_to_all(z);
    wait_idle();
    assert(atomic_load(&g_peer_n) == 0);
    atomic_store(&g_broker_on, 1);
    nt_teardown();
    nt_ipc_close();
    printf("  -> NOTIFY over TCP failures passed.\n");
}

/* the answer to a UDP datagram taken from the IPC (udp_ipc_t + NOTIFY), signed or not, from the address it was sent to */
static void nt_udp_answer(const uint8_t *dgram, size_t dlen, int beh) {
    const udp_ipc_t *ipc = (const udp_ipc_t *)dgram;
    const uint8_t *pkt = dgram + sizeof(udp_ipc_t);
    size_t plen = dlen - sizeof(udp_ipc_t);
    uint8_t out[1024];
    size_t alen = make_answer(pkt, plen, beh, &nt_key, &nt_wrong, out, sizeof(out));
    notify_handle_response(out, alen, (const struct sockaddr *)&ipc->client_addr);
}

static void test_notify_tcp_after_udp(void) {
    printf("[TEST] NOTIFY over TCP: after the UDP attempts, and after a UDP answer that fails TSIG verification...\n");
    nt_ipc_open();
    atomic_store(&g_broker_on, 1);
    nt_dgram_t dg[8];
    size_t dl[8];
    uint8_t req[1024];

    /* notify-retries 1: two datagrams, then one attempt over TCP (the UDP attempts are the operator's schedule) */
    nt_drain_pending();
    const char *t[] = {"198.51.100.40"};
    zone_db_entry_t *z = nt_setup(t, 1, false, false, 1);
    send_notify_to_all(z);
    assert(nt_drain_ipc(dg, dl, 8) == 1);
    notify_retransmit_due(time(NULL) + 2);                 /* the retransmission */
    assert(nt_drain_ipc(dg, dl, 8) == 1);
    assert(atomic_load(&g_peer_n) == 0);
    notify_retransmit_due(time(NULL) + 4);                 /* no answer after 2 messages: TCP */
    assert(nt_drain_ipc(dg, dl, 8) == 0);
    peer_serve(0, PB_OK, &nt_key, &nt_wrong, req, sizeof(req));
    wait_idle();
    notify_retransmit_due(time(NULL) + 100000);            /* nothing is left to send */
    assert(atomic_load(&g_peer_n) == 1 && notify_tcp_in_flight() == 0);
    nt_teardown();

    /* the TCP attempt after UDP is one attempt (not tcp-only's two) */
    peers_reset();
    z = nt_setup(t, 1, false, false, 0);
    send_notify_to_all(z);
    assert(nt_drain_ipc(dg, dl, 8) == 1);
    notify_retransmit_due(time(NULL) + 2);
    peer_serve(0, PB_CLOSE, &nt_key, &nt_wrong, req, sizeof(req));
    wait_idle();
    assert(atomic_load(&g_peer_n) == 1);
    nt_teardown();

    /* a UDP answer with a good TSIG ends it (nothing over TCP, nothing retransmitted); an answer with an error rcode too */
    peers_reset();
    z = nt_setup(t, 1, false, true, 3);
    send_notify_to_all(z);
    assert(nt_drain_ipc(dg, dl, 8) == 1);
    nt_udp_answer(dg[0].b, dl[0], PB_OK_SIGNED);
    notify_retransmit_due(time(NULL) + 100000);
    assert(nt_drain_ipc(dg, dl, 8) == 0 && atomic_load(&g_peer_n) == 0);
    nt_teardown();
    z = nt_setup(t, 1, false, false, 3);
    send_notify_to_all(z);
    assert(nt_drain_ipc(dg, dl, 8) == 1);
    {
        const udp_ipc_t *ipc = (const udp_ipc_t *)dg[0].b;
        uint8_t out[1024];
        size_t alen = make_answer(dg[0].b + sizeof(udp_ipc_t), dl[0] - sizeof(udp_ipc_t), PB_OK, NULL, NULL, out, sizeof(out));
        out[3] = 5; /* REFUSED */
        notify_handle_response(out, alen, (const struct sockaddr *)&ipc->client_addr);
        notify_handle_response(out, alen, (const struct sockaddr *)&ipc->client_addr); /* the entry is gone: ignored */
        notify_handle_response(out, 5, (const struct sockaddr *)&ipc->client_addr);     /* not a message */
    }
    notify_retransmit_due(time(NULL) + 100000);
    assert(nt_drain_ipc(dg, dl, 8) == 0 && atomic_load(&g_peer_n) == 0);
    nt_teardown();

    /* an unsigned or wrongly signed UDP answer to a signed NOTIFY: ignored, and the NOTIFY follows over TCP at once (BIND notify_done()) */
    static const int bad[] = {PB_UNSIGNED, PB_BADSIG};
    for (int b = 0; b < 2; b++) {
        peers_reset();
        z = nt_setup(t, 1, false, true, 5);
        send_notify_to_all(z);
        assert(nt_drain_ipc(dg, dl, 8) == 1);
        nt_udp_answer(dg[0].b, dl[0], bad[b]);
        notify_retransmit_due(time(NULL));                 /* the retry interval (60 s) is not waited for */
        assert(nt_drain_ipc(dg, dl, 8) == 0);              /* and no further datagram */
        peer_serve(0, PB_OK_SIGNED, &nt_key, &nt_wrong, req, sizeof(req));
        wait_idle();
        assert(atomic_load(&g_peer_n) == 1);
        /* a second bad answer to the same NOTIFY (late, over UDP) does not start another exchange */
        nt_udp_answer(dg[0].b, dl[0], bad[b]);
        notify_retransmit_due(time(NULL) + 100000);
        assert(atomic_load(&g_peer_n) == 1);
        nt_teardown();
    }
    nt_ipc_close();
    printf("  -> NOTIFY over TCP after UDP passed.\n");
}

static void test_notify_tcp_busy(void) {
    printf("[TEST] NOTIFY over TCP: a full set of exchanges in flight holds the next one back...\n");
    nt_ipc_open();
    nt_drain_pending();
    /* 64 targets of tcp-only whose peers say nothing, then one more */
    static char names[64][24];
    const char *many[64];
    for (int i = 0; i < 64; i++) {
        snprintf(names[i], sizeof(names[i]), "192.0.2.%d", 100 + i);
        many[i] = names[i];
    }
    /* nt_an has NT_TARGETS entries: use a larger list of our own */
    static notify_target_t big[64];
    memset(big, 0, sizeof(big));
    zone_db_entry_t *z = nt_setup(many, 2, true, false, 0);
    for (int i = 0; i < 64; i++) { big[i].ip = names[i]; big[i].port = 53; }
    tzx(&nt_zone)->also_notify = big;
    tzx(&nt_zone)->also_notify_count = 64;
    send_notify_to_all(z);
    for (int i = 0; i < 6000 && notify_tcp_in_flight() < 64; i++) usleep(1000);
    assert(notify_tcp_in_flight() == 64);
    tzx(&nt_zone)->also_notify = nt_an;
    tzx(&nt_zone)->also_notify_count = 1;
    nt_an[0].ip = (char *)(uintptr_t)"192.0.2.200";
    nt_an[0].port = 53;
    send_notify_to_all(z);                                 /* no room: held in the table */
    assert(notify_tcp_in_flight() == 64);
    int next = 0;
    for (int i = 0; i < 64; i++) assert(peer_wait(i) >= 0);
    notify_retransmit_due(time(NULL) + 1);                 /* still no room: held again */
    assert(notify_tcp_in_flight() == 64);
    peers_close_until_idle(&next);                         /* every exchange ends (two attempts each) */
    int before = atomic_load(&g_peer_n);
    notify_retransmit_due(time(NULL) + 2);                 /* the held one starts now */
    for (int i = 0; i < 3000 && atomic_load(&g_peer_n) == before; i++) usleep(1000);
    assert(atomic_load(&g_peer_n) > before);
    peers_close_until_idle(&next);
    nt_teardown();
    nt_ipc_close();
    printf("  -> NOTIFY over TCP busy passed.\n");
}

/* ---- BIND compatibility, batch 7: serial-update-method (BIND 9.20 lib/dns/update.c dns_update_soaserial()), and max-records,
 * max-records-per-type, max-zone-ttl for an UPDATE (lib/ns/update.c: "reducing TTL to the configured max-zone-ttl", DNS_R_TOOMANYRECORDS) ---- */
static void test_serial_update_methods(void) {
    printf("[TEST] Dynamic Update: serial-update-method and the zone size limits...\n");
    setenv("TZ", "UTC", 1);
    tzset();
    /* increment: +1, skipping 0 (RFC 1982) */
    assert(update_next_serial(5, SUM_INCREMENT, 0) == 6);
    assert(update_next_serial(0xFFFFFFFFu, SUM_INCREMENT, 0) == 1);
    /* unixtime: the clock when it is ahead of the serial, else serial + 1 */
    assert(update_next_serial(5, SUM_UNIXTIME, 1700000000) == 1700000000u);
    assert(update_next_serial(1700000000u, SUM_UNIXTIME, 1700000000) == 1700000001u);
    assert(update_next_serial(1700000500u, SUM_UNIXTIME, 1700000000) == 1700000501u);
    assert(update_next_serial(0xFFFFFFFFu, SUM_UNIXTIME, 1700000000) == 1700000000u);   /* RFC 1982: 1.7e9 is "after" 0xFFFFFFFF */
    /* date: YYYYMMDD00 of the local date when that is ahead, else serial + 1 (the 99 serials of a day) */
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = 2026 - 1900; tmv.tm_mon = 9; tmv.tm_mday = 29; tmv.tm_hour = 12;
    time_t now = timegm(&tmv);
    assert(update_next_serial(2026102800u, SUM_DATE, now) == 2026102900u);
    assert(update_next_serial(2026102900u, SUM_DATE, now) == 2026102901u);
    assert(update_next_serial(2026102950u, SUM_DATE, now) == 2026102951u);
    assert(update_next_serial(5, SUM_DATE, now) == 2026102900u);
    assert(update_next_serial(2026110100u, SUM_DATE, now) == 2026110101u);   /* a serial already in the future */

    /* the whole pipeline: a hand-built configuration whose options write the three limits and the method */
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_sample_zone_arena(test_zone_slot(&entry, 0), "example.com.", "1000");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 1000, memory_order_release);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    view_config_t view_cfg;
    memset(&view_cfg, 0, sizeof(view_cfg));
    view_cfg.name = "default";
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "example.com.";
    zcfg.type = "master";
    view_cfg.zones = &zcfg;
    cfg.views = &view_cfg;
    cfg.zv.set = ZV_MAX_RECORDS | ZV_MAX_ZONE_TTL | ZV_SERIAL_METHOD;
    cfg.zv.max_records = 2;
    cfg.zv.max_zone_ttl = 100;
    cfg.zv.serial_method = SUM_UNIXTIME;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    /* add <label>.example.com A 192.0.2.<last> with TTL ttl */
    #define ADD_A_PKT(pkt, off, label, last, ttl) do { \
        memset(pkt, 0, sizeof(pkt)); \
        pkt[0] = 0x12; pkt[1] = 0x34; pkt[2] = 0x28; pkt[5] = 1; pkt[9] = 1; \
        off = 12; \
        pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7; pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3; pkt[off++] = 0; \
        pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1; \
        pkt[off++] = (uint8_t)strlen(label); memcpy(&pkt[off], label, strlen(label)); off += strlen(label); \
        pkt[off++] = 7; memcpy(&pkt[off], "example", 7); off += 7; pkt[off++] = 3; memcpy(&pkt[off], "com", 3); off += 3; pkt[off++] = 0; \
        pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0; pkt[off++] = 1; \
        pkt[off++] = (uint8_t)((ttl) >> 24); pkt[off++] = (uint8_t)((ttl) >> 16); pkt[off++] = (uint8_t)((ttl) >> 8); pkt[off++] = (uint8_t)(ttl); \
        pkt[off++] = 0; pkt[off++] = 4; pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = (last); \
    } while (0)

    uint8_t pkt[512];
    size_t off;
    /* 1. www A with TTL 300: the zone becomes 2 records, the TTL is cut to max-zone-ttl, the serial follows the clock (unixtime) */
    ADD_A_PKT(pkt, off, "www", 1, 300u);
    time_t before = time(NULL);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "k") == 0);
    uint32_t s = atomic_load_explicit(&entry.serial, memory_order_acquire);
    assert(s >= (uint32_t)before && s <= (uint32_t)time(NULL));
    zone_version_t *cur = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
    assert(cur->image && cur->image->n_rrs == 2);
    uint32_t id = zone_image_find_name(cur->image, "www.example.com.");
    assert(id != ZONE_IMAGE_NONE);
    uint32_t rr = zone_image_rrset_next(cur->image, id, 1, zone_image_name_first_rr(cur->image, id));
    assert(rr != ZONE_IMAGE_NONE && zone_image_rr_ttl(cur->image, rr) == 100);

    /* 2. a third record would break max-records 2: SERVFAIL, nothing applied */
    ADD_A_PKT(pkt, off, "mail", 2, 60u);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "k") == 2);
    assert(atomic_load_explicit(&entry.serial, memory_order_acquire) == s);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->image->n_rrs == 2);

    /* 3. max-records-per-type 1: a second A at www is refused; max-types-per-name 1: a name with two types is refused */
    cfg.zv.set = ZV_MAX_PER_TYPE;
    cfg.zv.max_per_type = 1;
    cfg.zv.max_records = 0;
    ADD_A_PKT(pkt, off, "www", 3, 60u);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "k") == 2);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->image->n_rrs == 2);
    cfg.zv.set = ZV_MAX_TYPES_PER_NAME;
    cfg.zv.max_types_per_name = 1;
    ADD_A_PKT(pkt, off, "ns1", 4, 60u);    /* a new name with one type: fine (the apex has SOA only in this sample zone) */
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "k") == 0);
    #undef ADD_A_PKT

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> serial-update-method and the zone size limits passed.\n");
}

/* ---- update-policy through handle_dynamic_update() (BIND 9.20 lib/ns/update.c: a change that no rule grants makes the whole UPDATE REFUSED;
 * deleting every RRset of a name checks each type found there, ssu_checkall()) ---- */
static size_t upd_rr_pkt(uint8_t *pkt, const char *label, uint16_t cls, uint16_t type, uint32_t ttl, const uint8_t *rdata, size_t rdlen) {
    memset(pkt, 0, 512);
    pkt[0] = 0x12; pkt[1] = 0x77; pkt[2] = 0x28; pkt[5] = 1; pkt[9] = 1;
    size_t off = 12;
    static const uint8_t zname[] = { 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0 };
    memcpy(&pkt[off], zname, sizeof(zname)); off += sizeof(zname);
    pkt[off++] = 0; pkt[off++] = 6; pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = (uint8_t)strlen(label); memcpy(&pkt[off], label, strlen(label)); off += strlen(label);
    memcpy(&pkt[off], zname, sizeof(zname)); off += sizeof(zname);
    pkt[off++] = (uint8_t)(type >> 8); pkt[off++] = (uint8_t)type;
    pkt[off++] = (uint8_t)(cls >> 8); pkt[off++] = (uint8_t)cls;
    pkt[off++] = (uint8_t)(ttl >> 24); pkt[off++] = (uint8_t)(ttl >> 16); pkt[off++] = (uint8_t)(ttl >> 8); pkt[off++] = (uint8_t)ttl;
    pkt[off++] = (uint8_t)(rdlen >> 8); pkt[off++] = (uint8_t)rdlen;
    if (rdlen) { memcpy(&pkt[off], rdata, rdlen); off += rdlen; }
    return off;
}

static void test_update_policy_pipeline(void) {
    printf("[TEST] Dynamic Update: update-policy decides each change...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);
    init_sample_zone_arena(test_zone_slot(&entry, 0), "example.com.", "1000");
    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 1000, memory_order_release);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    view_config_t view_cfg;
    memset(&view_cfg, 0, sizeof(view_cfg));
    view_cfg.name = "default";
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "example.com.";
    zcfg.type = "master";
    update_policy_t *pol = calloc(1, sizeof(*pol));
    tzx(&zcfg)->upd_policy = pol;
    view_cfg.zones = &zcfg;
    cfg.views = &view_cfg;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);
    /* grant upd zonesub A TXT; */
    pol->count = 1;
    pol->rules[0].grant = true;
    pol->rules[0].mtype = UPD_SUBDOMAIN;
    snprintf(pol->rules[0].identity, sizeof(pol->rules[0].identity), "upd");
    snprintf(pol->rules[0].name, sizeof(pol->rules[0].name), "example.com.");
    pol->rules[0].ntypes = 2;
    pol->rules[0].types[0] = 1;
    pol->rules[0].types[1] = 16;

    uint8_t pkt[512];
    static const uint8_t a_rdata[4] = { 192, 0, 2, 1 };
    static const uint8_t txt_rdata[2] = { 1, 'x' };
    size_t off = upd_rr_pkt(pkt, "www", 1, 1, 300, a_rdata, 4);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "other") == 5);                 /* the key is not the identity of a rule */
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->image->n_rrs == 1);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 0);
    off = upd_rr_pkt(pkt, "www", 1, 16, 300, txt_rdata, 2);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 0);                   /* TXT is in the list */
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->image->n_rrs == 3);
    static const uint8_t mx_rdata[3] = { 0, 10, 0 };
    off = upd_rr_pkt(pkt, "www", 1, 15, 300, mx_rdata, 3);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 5);                   /* MX is not */
    /* delete every RRset of www: A and TXT are allowed -> done */
    pol->rules[0].ntypes = 1;                                                                    /* now only A */
    off = upd_rr_pkt(pkt, "www", 255, 255, 0, NULL, 0);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 5);                   /* TXT at www is not granted: nothing is deleted */
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->image->n_rrs == 3);
    pol->rules[0].ntypes = 2;
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 0);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire)->image->n_rrs == 1);
    /* deleting a name that has nothing: nothing to check */
    off = upd_rr_pkt(pkt, "nothing", 255, 255, 0, NULL, 0);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 0);
    /* an empty policy refuses everything */
    pol->count = 0;
    off = upd_rr_pkt(pkt, "www", 1, 1, 300, a_rdata, 4);
    assert(handle_dynamic_update(pkt, off, &entry, "127.0.0.1", "upd") == 5);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    free(pol);
    zone_arena_destroy(test_zone_slot(&entry, 0));
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    printf("  -> update-policy passed.\n");
}

int main(void) {
    printf("=== Starting Dynamic Update Engine Unit Tests ===\n");
    test_serial_update_methods();
    test_update_policy_pipeline();
    test_bump_soa_serial();
    test_process_update_sections_records();
    test_process_update_sections_apex_ns_protection();
    test_dynamic_update_prerequisites_and_error_paths();
    test_handle_dynamic_update_pipeline();
    test_handle_dynamic_update_drops_unencodable();
    test_update_multi_tsig_keys();
    test_update_soa_rules();
    test_update_cname_dname_rules();
    test_update_delete_rules();
    test_update_add_replace_rules();
    test_update_prescan_errors();
    test_update_prerequisite_rules();
    test_handle_dynamic_update_serial_rules();
    test_update_dispatch_zone_section();
    test_update_tsig_matrix();
    test_send_notify_to_all_comprehensive();
    test_notify_tcp_roundtrip();
    test_notify_tcp_flow();
    test_notify_tcp_failures();
    test_notify_tcp_after_udp();
    test_notify_tcp_busy();
    printf("=== All Dynamic Update Engine Unit Tests PASSED ===\n");
    return 0;
}


/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)family; (void)addr; (void)addr_len;
    return mock_broker(type, tcp_opts);
}

/* send_tcp_dns_message(): goes through the send_tcp_robust() mock above (length prefix, then message) */
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len) {
    uint8_t prefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    if (send_tcp_robust(fd, prefix, 2) < 0) return -1;
    if (send_tcp_robust(fd, msg, len) < 0) return -1;
    return (ssize_t)len;
}

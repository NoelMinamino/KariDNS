#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_priv_sandbox.h"
#include "dns_query_engine.h"
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

static void test_priv_sandbox_directory_caching(void) {
    printf("[TEST] Priv Sandbox: Directory FD caching & Capsicum ENOTCAPABLE...\n");

    char tmp_file[] = "/tmp/karidns_sandbox_test_XXXXXX";
    int fd = mkstemp(tmp_file);
    if (fd < 0) {
        // Fallback for environments without /tmp
        strcpy(tmp_file, "karidns_sandbox_test.tmp");
        fd = open(tmp_file, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    write(fd, "test", 4);
    close(fd);

    // 1. Stat via dir cache
    struct stat sb;
    int r_stat = stat_via_dir_cache(tmp_file, &sb);
    assert(r_stat == 0);
    assert(sb.st_size == 4);

    // 2. Open via dir cache (read-only)
    int r_fd = open_via_dir_cache(tmp_file, O_RDONLY, 0, false);
    assert(r_fd >= 0);
    char buf[16] = {0};
    read(r_fd, buf, 4);
    assert(memcmp(buf, "test", 4) == 0);
    close(r_fd);

    // 3. Socket rights limitation (should not crash or error)
    int sock_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_tcp >= 0) {
        limit_server_socket_rights(sock_tcp, true);  // listening
        limit_server_socket_rights(sock_tcp, false); // connected
        close(sock_tcp);
    }

    int sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_udp >= 0) {
        limit_server_socket_rights(sock_udp, false);
        close(sock_udp);
    }

    // 4. Capability mode rejection on uncached path
    atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);
    int r_encap = open_via_dir_cache("/nonexistent_dir_uncached/test.zone", O_RDONLY, 0, false);
    assert(r_encap < 0);
    assert(errno == ENOTCAPABLE || errno == ENOENT);
    atomic_store_explicit(&g_capsicum_enabled, false, memory_order_release);

    unlink(tmp_file);
    printf("  -> Priv Sandbox directory caching passed.\n");
}

static void test_snapshot_rcu_lifecycle_and_suffix_lookup(void) {
    printf("[TEST] Snapshot RCU: retain/release, zone creation & suffix hash lookup...\n");

    // 1. Zone DB Entry creation & destruction
    zone_db_entry_t *entry = create_new_zone_entry("example.com.", "default");
    assert(entry != NULL);
    assert(strcmp(entry->domain, "example.com.") == 0);
    assert(strcmp(entry->view_name, "default") == 0);

    // 2. Arena deep cloning & clearing
    zone_arena_t src, dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    zone_arena_init(&src);
    zone_arena_init(&dst);

    src.records = malloc(sizeof(dns_record_t) * 4);
    src.records_cap = 4;
    dns_record_t r1; memset(&r1, 0, sizeof(r1));
    r1.name = arena_strdup(&src, "host.example.com.");
    r1.type = arena_strdup(&src, "A");
    r1.type_code = 1;
    r1.class_str = arena_strdup(&src, "IN");
    r1.class_val = 1;
    r1.ttl_value = 300;
    r1.rdata_count = 1;
    r1.rdata[0] = arena_strdup(&src, "192.0.2.55");
    src.records[src.count++] = r1;

    clone_zone_arena(&src, &dst);
    assert(dst.count == 1);
    assert(strcmp(dst.records[0].name, "host.example.com.") == 0);
    assert(strcmp(dst.records[0].rdata[0], "192.0.2.55") == 0);

    zone_arena_clear_data_pools(&dst);
    zone_arena_destroy(&src);
    zone_arena_destroy(&dst);

    // 3. View suffix hash lookup
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    zone_db_entry_t *entries[1] = { entry };
    view.entries = entries;
    view.zone_count = 1;
    view.hash_size = 16;
    int hash_tbl[16];
    int chain_next[1] = { -1 };
    for (int i = 0; i < 16; i++) hash_tbl[i] = -1;
    hash_tbl[calc_fnv1a_str("example.com.") & 15] = 0;
    view.hash_table = hash_tbl;
    view.chain_next = chain_next;

    zone_db_entry_t *found = find_zone_in_view(&view, "sub.host.example.com.");
    assert(found == entry);

    zone_db_entry_t *not_found = find_zone_in_view(&view, "otherdomain.org.");
    assert(not_found == NULL);

    free_zone_db_entry(entry);
    printf("  -> Snapshot RCU lifecycle & suffix lookup passed.\n");
}

int main(void) {
    printf("=== Starting Sandbox & Snapshot RCU Engine Unit Tests ===\n");
    test_priv_sandbox_directory_caching();
    test_snapshot_rcu_lifecycle_and_suffix_lookup();
    printf("=== All Sandbox & Snapshot RCU Engine Unit Tests PASSED ===\n");
    return 0;
}

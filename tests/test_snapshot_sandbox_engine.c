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
#include <sys/wait.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_priv_sandbox.h"
#include "dns_query_engine.h"
#include "dns_axfr_ixfr.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"
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
        limit_client_socket_rights(sock_udp);
        close(sock_udp);
    }

    // 4. renameat via dir cache
    char tmp_file2[] = "/tmp/karidns_sandbox_test2_XXXXXX";
    int fd2 = mkstemp(tmp_file2);
    if (fd2 >= 0) {
        close(fd2);
        char tmp_file3[PATH_MAX];
        snprintf(tmp_file3, sizeof(tmp_file3), "%s_renamed", tmp_file2);
        int r_ren = renameat_via_dir_cache(tmp_file2, tmp_file3);
        assert(r_ren == 0);
        unlink(tmp_file3);
    }

    // 5. Capability mode rejection on uncached path
    atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);
    int r_encap = open_via_dir_cache("/nonexistent_dir_uncached/test.zone", O_RDONLY, 0, false);
    assert(r_encap < 0);
    assert(errno == ENOTCAPABLE || errno == ENOENT);
    atomic_store_explicit(&g_capsicum_enabled, false, memory_order_release);

    unlink(tmp_file);

    // 6. enter_capsicum_sandbox in child process (since Capsicum capability mode is irreversible)
    pid_t cap_pid = fork();
    if (cap_pid == 0) {
        enter_capsicum_sandbox();
        assert(atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire) == true);
        _exit(0);
    } else if (cap_pid > 0) {
        int st = 0;
        waitpid(cap_pid, &st, 0);
        assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
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

    // Add locations, tags, and trusted resolvers
    tinydns_location_entry_t loc1;
    memset(&loc1, 0, sizeof(loc1));
    loc1.code[0] = 'u'; loc1.code[1] = 's';
    loc1.prefix[0] = 192; loc1.prefix[1] = 0; loc1.prefix[2] = 2; loc1.prefix[3] = 0;
    loc1.prefix_len = 24;
    src.locations = malloc(sizeof(tinydns_location_entry_t));
    memcpy(src.locations, &loc1, sizeof(loc1));
    src.location_count = 1;

    ecs_tag_def_t b_loc;
    memset(&b_loc, 0, sizeof(b_loc));
    b_loc.tag = strdup("tokyo");
    b_loc.cidr_count = 1;
    b_loc.cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    b_loc.cidrs[0].cidr = strdup("192.0.2.0/24");
    src.bind_location_tags = malloc(sizeof(ecs_tag_def_t));
    memcpy(src.bind_location_tags, &b_loc, sizeof(b_loc));
    src.bind_location_tag_count = 1;

    ecs_tag_def_t b_ecs;
    memset(&b_ecs, 0, sizeof(b_ecs));
    b_ecs.tag = strdup("cloud");
    b_ecs.cidr_count = 1;
    b_ecs.cidrs = calloc(1, sizeof(ecs_cidr_entry_t));
    b_ecs.cidrs[0].cidr = strdup("198.51.100.0/24");
    src.bind_ecs_tags = malloc(sizeof(ecs_tag_def_t));
    memcpy(src.bind_ecs_tags, &b_ecs, sizeof(b_ecs));
    src.bind_ecs_tag_count = 1;

    src.bind_ecs_trusted_resolvers = malloc(sizeof(char *));
    src.bind_ecs_trusted_resolvers[0] = strdup("127.0.0.1/32");
    src.bind_ecs_trusted_resolver_count = 1;

    clone_zone_arena(&src, &dst);
    assert(dst.count == 1);
    assert(strcmp(dst.records[0].name, "host.example.com.") == 0);
    assert(strcmp(dst.records[0].rdata[0], "192.0.2.55") == 0);
    assert(dst.location_count == 1);
    assert(dst.bind_location_tag_count == 1);
    assert(dst.bind_ecs_tag_count == 1);
    assert(dst.bind_ecs_trusted_resolver_count == 1);

    // Test wait_for_readers on dst (reader_count = 0)
    wait_for_readers(&dst);

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

    // 4. abort_rebuild_snapshot
    zone_db_snapshot_t *mock_new_snap = calloc(1, sizeof(zone_db_snapshot_t));
    abort_rebuild_snapshot(mock_new_snap, "test_allocation_abort");
    abort_rebuild_snapshot(NULL, "test_null_abort");

    free_zone_db_entry(entry);
    printf("  -> Snapshot RCU lifecycle & suffix lookup passed.\n");
}

static void test_capsicum_sandbox_execution(void) {
    printf("[TEST] Priv Sandbox: enter_capsicum_sandbox in child process...\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            close(sv[0]);
            g_dnstap_sock = sv[1];
            g_bypass_cap_enter = false;
            enter_capsicum_sandbox();
            bool enabled = atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire);
            close(sv[1]);
            _exit(enabled ? 0 : 1);
        }
        close(sv[0]);
        close(sv[1]);
        int status = 0;
        waitpid(pid, &status, 0);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    // Also test in main test process (with bypass so exit can flush coverage profraw)
    g_bypass_cap_enter = true;
    enter_capsicum_sandbox();
    assert(atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire) == true);
    printf("  -> enter_capsicum_sandbox passed.\n");
}

int main(void) {
    printf("=== Starting Sandbox & Snapshot RCU Engine Unit Tests ===\n");
    test_priv_sandbox_directory_caching();
    test_snapshot_rcu_lifecycle_and_suffix_lookup();
    test_capsicum_sandbox_execution();
    printf("=== All Sandbox & Snapshot RCU Engine Unit Tests PASSED ===\n");
    return 0;
}


/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}

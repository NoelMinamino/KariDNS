#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#include "fi/kari_fi.h"
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_snapshot_rcu.h"
#include "../dns_epoch_rcu.h"
#include "../dns_priv_sandbox.h"

#include <limits.h>
#include "../dns_server_internal.h"
#include "../dns_query_engine.h"
#include "../dns_axfr_ixfr.h"

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

static void test_fi_snapshot_rebuild(void) {
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = (char *)"example.com.";
    zc.type = (char *)"master";
    zc.file = (char *)"example.com.zone";
    zc.next = NULL;

    view_config_t view_cfg;
    memset(&view_cfg, 0, sizeof(view_cfg));
    view_cfg.name = (char *)"default";
    view_cfg.zones = &zc;
    view_cfg.next = NULL;

    server_config_t config;
    memset(&config, 0, sizeof(config));
    config.views = &view_cfg;

    FI_SWEEP({
        zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(&config, NULL, NULL, NULL, NULL, 0);
        if (new_snap) {
            release_zone_snapshot(new_snap);
        }
    });

    zone_db_snapshot_t *active = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (active) {
        atomic_store_explicit(&g_zone_db_active, NULL, memory_order_release);
        free_zone_db_snapshot(active);
    }
}

int main(void) {
    printf("[*] Running test_fi_snapshot...\n");
    test_fi_snapshot_rebuild();
    printf("[+] test_fi_snapshot passed successfully.\n");
    return 0;
}

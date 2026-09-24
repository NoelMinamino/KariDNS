#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fi/kari_fi.h"
#include "../dns_wire.h"
#include "../dns_zone_parser.h"
#include "../dns_dynamic_update.h"
#include "../dns_catalog_zone.h"
#include "../dns_dnstap.h"
#include "../dns_edns_ecs.h"

#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../dns_server_internal.h"
#include "../dns_query_engine.h"
#include "../dns_snapshot_rcu.h"
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

static void test_fi_dynamic_update(void) {
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_init(&entry.rcu.arena_a);
    zone_arena_init(&entry.rcu.arena_b);

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };
    char zone_text[] = "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 100 3600 1800 604800 86400\n"
                       "example.com. 3600 IN NS ns1.example.com.\n";
    parse_zone_fast(zone_text, sizeof(zone_text) - 1, &entry.rcu.arena_a, &ctx);
    build_zone_index(&entry.rcu.arena_a, true);

    atomic_store_explicit(&entry.rcu.active, &entry.rcu.arena_a, memory_order_release);
    atomic_store_explicit(&entry.serial, 100, memory_order_release);

    uint8_t update_pkt[512];
    memset(update_pkt, 0, sizeof(update_pkt));
    update_pkt[0] = 0x12; update_pkt[1] = 0x34;
    update_pkt[2] = 0x28; // OPCODE=UPDATE (5)
    update_pkt[5] = 0x01; // ZOCOUNT=1
    memcpy(update_pkt + 12, "\x07example\x03com\x00\x00\x06\x00\x01", 17); // Zone SOA IN

    FI_SWEEP({
        handle_dynamic_update(update_pkt, 29, &entry, "127.0.0.1", "key-admin");
    });

    zone_arena_destroy(&entry.rcu.arena_a);
    zone_arena_destroy(&entry.rcu.arena_b);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
}

static void test_fi_dnstap_encoding(void) {
    uint8_t msg[64] = "DNS-QUERY-MESSAGE-PAYLOAD";
    dnstap_event_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.ts.tv_sec = 1700000000;
    meta.ts.tv_nsec = 500000;
    meta.message_type = 1; // AUTH_QUERY
    meta.protocol = IPPROTO_UDP;
    struct sockaddr_in *sin = (struct sockaddr_in *)&meta.client_addr;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(53535);
    inet_pton(AF_INET, "192.0.2.1", &sin->sin_addr);
    meta.client_addr_len = sizeof(struct sockaddr_in);

    FI_SWEEP({
        uint8_t frame_buf[512];
        dnstap_build_message(&meta, msg, sizeof(msg), frame_buf, sizeof(frame_buf));
    });
}

int main(void) {
    printf("[*] Running test_fi_misc...\n");
    test_fi_dynamic_update();
    test_fi_dnstap_encoding();
    printf("[+] test_fi_misc passed successfully.\n");
    return 0;
}

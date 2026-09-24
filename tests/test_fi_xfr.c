#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include "fi/kari_fi.h"
#include "../dns_wire.h"
#include "../dns_zone_parser.h"
#include "../dns_axfr_ixfr.h"
#include "../dns_dynamic_update.h"

#include <limits.h>
#include "../dns_server_internal.h"
#include "../dns_query_engine.h"
#include "../dns_snapshot_rcu.h"

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

static void test_fi_xfr_parsing(void) {
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[4] = 0x00; pkt[5] = 0x01; // QDCOUNT=1
    memcpy(pkt + 12, "\x07example\x03com\x00\x00\xFC\x00\x01", 17); // AXFR

    FI_SWEEP({
        zone_arena_t standby;
        memset(&standby, 0, sizeof(standby));
        standby.records_cap = 64;
        standby.records = calloc(standby.records_cap, sizeof(dns_record_t));

        zone_arena_t active;
        memset(&active, 0, sizeof(active));

        axfr_session_t session;
        memset(&session, 0, sizeof(session));

        parse_xfr_packet(pkt, 29, &standby, &active, &session, "example.com.");
        zone_arena_destroy(&standby);
        zone_arena_destroy(&active);
    });
}

static void test_fi_soa_serial_bump(void) {
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true, .err_out = &err };
    char zone_text[] = "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 100 3600 1800 604800 86400\n";
    parse_zone_fast(zone_text, sizeof(zone_text) - 1, &arena, &ctx);
    build_zone_index(&arena, true);

    FI_SWEEP({
        bump_soa_serial_in_arena(&arena, "example.com.");
    });

    zone_arena_destroy(&arena);
}

static void test_fi_axfr_send_and_recv(void) {
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "fixfr.example.", .is_standalone_mode = true, .err_out = &err };
    char zone_text[] = "fixfr.example. 3600 IN SOA ns1.fixfr.example. admin.fixfr.example. 100 3600 1800 604800 86400\n"
                       "fixfr.example. 3600 IN NS ns1.fixfr.example.\n"
                       "ns1.fixfr.example. 300 IN A 192.0.2.1\n";
    parse_zone_fast(zone_text, sizeof(zone_text) - 1, &arena, &ctx);
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "fixfr.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    uint8_t req[256] = {0};
    req[0] = 0x12; req[1] = 0x34;
    req[4] = 0; req[5] = 1;
    size_t qoff = 12;
    qoff += write_uncompressed_name(req, qoff, sizeof(req), "fixfr.example.");
    req[qoff++] = 0; req[qoff++] = 252; // AXFR
    req[qoff++] = 0; req[qoff++] = 1;

    FI_SWEEP_KIND(FI_SEND, {
        send_axfr_response(1, "fixfr.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    });

    FI_SWEEP_KIND(FI_WRITE, {
        send_axfr_response(1, "fixfr.example.", req, qoff, NULL, &entry, NULL, 0, NULL, 0, NULL, false);
    });

    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
    zone_arena_destroy(&arena);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("[*] Running test_fi_xfr...\n");
    test_fi_xfr_parsing();
    test_fi_soa_serial_bump();
    test_fi_axfr_send_and_recv();
    printf("[+] test_fi_xfr passed successfully.\n");
    return 0;
}

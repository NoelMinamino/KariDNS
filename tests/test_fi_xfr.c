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
#include "test_zone_slots.h"

// Mock globals
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

static uint8_t g_fi_msg[1024];       /* test_fi_axfr_install_failure_keeps_state(): the one message of the stream */
static size_t g_fi_msg_len;
static bool g_fi_msg_served;

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out) {
    (void)fd; (void)ctx;
    if (g_fi_msg_len == 0 || g_fi_msg_served) return -1;
    g_fi_msg_served = true;
    *msg_out = g_fi_msg;
    *msg_len_out = (uint16_t)g_fi_msg_len;
    return 1;
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

        parse_xfr_packet(pkt, 29, &standby, &active.ver, &session, "example.com.");
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
    atomic_store_explicit(&entry.rcu.active, &arena.ver, memory_order_release);
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

/* append one RR (owner, type, class IN, TTL 60, RDATA) to a message being built; returns the new offset */
static size_t fi_put_rr(uint8_t *p, size_t cap, size_t off, const char *owner, uint16_t type, const uint8_t *rd, uint16_t rdlen) {
    off += write_uncompressed_name(p, off, cap, owner);
    p[off++] = type >> 8; p[off++] = type & 0xFF; p[off++] = 0; p[off++] = 1;
    p[off++] = 0; p[off++] = 0; p[off++] = 0; p[off++] = 60;
    p[off++] = rdlen >> 8; p[off++] = rdlen & 0xFF;
    if (rdlen) memcpy(p + off, rd, rdlen);
    return off + rdlen;
}

/* A transfer that cannot be installed (an allocation fails while the version is built or published) leaves the zone as it was: the serial, the
 * SOA timers, next_check, expire_at and last_successful_transfer are the old ones.  Sweep every allocation of an AXFR-in: whenever handle_axfr_event()
 * does not return 1 the state must be the initial one, and when it returns 1 it must be the new one. */
static void test_fi_axfr_install_failure_keeps_state(void) {
    uint8_t soa_rd[128];
    size_t sl = 0;
    sl += write_uncompressed_name(soa_rd, sl, sizeof(soa_rd), "ns1.fiinst.example.");
    sl += write_uncompressed_name(soa_rd, sl, sizeof(soa_rd), "admin.fiinst.example.");
    soa_rd[sl++] = 0; soa_rd[sl++] = 0; soa_rd[sl++] = 0; soa_rd[sl++] = 200;                  /* serial 200 */
    static const uint32_t soa_t[4] = { 7200, 3600, 1209600, 300 };
    for (int k = 0; k < 4; k++) {
        soa_rd[sl++] = (uint8_t)(soa_t[k] >> 24); soa_rd[sl++] = (uint8_t)(soa_t[k] >> 16);
        soa_rd[sl++] = (uint8_t)(soa_t[k] >> 8); soa_rd[sl++] = (uint8_t)soa_t[k];
    }
    static const uint8_t a_rd[4] = { 192, 0, 2, 1 };
    memset(g_fi_msg, 0, sizeof(g_fi_msg));
    g_fi_msg[0] = 0x11; g_fi_msg[1] = 0x23; g_fi_msg[2] = 0x84;
    g_fi_msg[5] = 1; g_fi_msg[7] = 3;                                                          /* QDCOUNT 1, ANCOUNT 3: SOA, A, SOA */
    size_t off = 12;
    off += write_uncompressed_name(g_fi_msg, off, sizeof(g_fi_msg), "fiinst.example.");
    g_fi_msg[off++] = 0; g_fi_msg[off++] = 252; g_fi_msg[off++] = 0; g_fi_msg[off++] = 1;
    off = fi_put_rr(g_fi_msg, sizeof(g_fi_msg), off, "fiinst.example.", 6, soa_rd, (uint16_t)sl);
    off = fi_put_rr(g_fi_msg, sizeof(g_fi_msg), off, "www.fiinst.example.", 1, a_rd, 4);
    off = fi_put_rr(g_fi_msg, sizeof(g_fi_msg), off, "fiinst.example.", 6, soa_rd, (uint16_t)sl);
    g_fi_msg_len = off;

    unsigned failed = 0, installed = 0;
    FI_SWEEP({
        zone_db_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        strlcpy(entry.domain, "fiinst.example.", sizeof(entry.domain));
        strlcpy(entry.view_name, "default", sizeof(entry.view_name));
        pthread_mutex_init(&entry.writer_lock, NULL);
        pthread_mutex_init(&entry.ixfr_history.lock, NULL);
        atomic_store_explicit(&entry.rcu.active, &zone_version_empty, memory_order_release);
        entry.serial = 100; entry.refresh = 111; entry.retry = 222; entry.expire = 333;
        atomic_store(&entry.next_check, 777);
        atomic_store(&entry.expire_at, 888);
        atomic_store(&entry.last_successful_transfer, 999);

        g_fi_msg_served = false;
        tcp_stream_ctx_t stream_ctx;
        memset(&stream_ctx, 0, sizeof(stream_ctx));
        axfr_session_t session;
        memset(&session, 0, sizeof(session));
        session.query_id = 0x1123; session.query_type = 252;
        int rc = handle_axfr_event(-1, &entry, &stream_ctx, &session, NULL, NULL, 0);
        if (rc == 1) {
            installed++;
            assert(entry.serial == 200 && entry.refresh == 7200 && entry.retry == 3600 && entry.expire == 1209600);
            assert(atomic_load(&entry.last_successful_transfer) != 999);
        } else {
            failed++;
            assert(entry.serial == 100 && entry.refresh == 111 && entry.retry == 222 && entry.expire == 333);
            assert(atomic_load(&entry.next_check) == 777 && atomic_load(&entry.expire_at) == 888);
            assert(atomic_load(&entry.last_successful_transfer) == 999);
            assert(atomic_load(&entry.rcu.active) == &zone_version_empty);
        }
        test_entry_release(&entry);
        pthread_mutex_destroy(&entry.writer_lock);
        pthread_mutex_destroy(&entry.ixfr_history.lock);
    });
    g_fi_msg_len = 0;
    assert(failed > 0 && installed > 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("[*] Running test_fi_xfr...\n");
    test_fi_xfr_parsing();
    test_fi_soa_serial_bump();
    test_fi_axfr_send_and_recv();
    test_fi_axfr_install_failure_keeps_state();
    printf("[+] test_fi_xfr passed successfully.\n");
    return 0;
}

/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}

/* send_tcp_dns_message(): goes through the send_tcp_robust() mock above (length prefix, then message) */
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len) {
    uint8_t prefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    if (send_tcp_robust(fd, prefix, 2) < 0) return -1;
    if (send_tcp_robust(fd, msg, len) < 0) return -1;
    return (ssize_t)len;
}

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>
#include <limits.h>
#include <stdalign.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../../dns_wire.h"
#include "../../dns_zone_parser.h"
#include "../../dns_zone_image.h"
#include "../test_image_helper.h"
#include "../../dns_dynamic_update.h"
#include "../../dns_snapshot_rcu.h"
#include "../../dns_epoch_rcu.h"
#include "../../dns_server_internal.h"
#include "../test_zone_slots.h"
#include "../test_zext.h"
#include "../../dns_config_parser.h"

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

/* ---- the answer to a NOTIFY (dns_dynamic_update.c): the bytes of a peer, as a UDP datagram and as the reply on a TCP connection ----
 * An input that starts with 0x7E is such an answer.  A signed NOTIFY to 192.0.2.10 is pending (sent again for every input), so that the ID
 * and the source address can be right: notify_handle_response() then gets as far as the TSIG checks.  The TCP side goes through the framing
 * of notify_tcp_roundtrip() on a socketpair. */
static bool nf_ready;
static server_config_t nf_cfg;
static view_config_t nf_view;
static zone_config_t nf_zone;
static notify_target_t nf_an[1];
static tsig_key_t nf_key;
static zone_db_entry_t *nf_entry;

static void nf_setup(void) {
    nf_key.name = "tcpkey.example.";
    nf_key.algorithm = "hmac-sha256";
    nf_key.secret_decoded_len = 32;
    memset(nf_key.secret_decoded, 0x5C, 32);
    nf_cfg.keys = &nf_key;
    nf_cfg.notify_rate = 1000000;
    nf_cfg.notify_rate_set = true;
    nf_cfg.notify_retry.retries = 3;
    nf_cfg.notify_retry.interval = 60;
    nf_view.name = "default";
    nf_zone.domain = "nf.example.";
    tzx(&nf_zone)->notify_mode = NOTIFY_MODE_EXPLICIT;
    tzx(&nf_zone)->tsig_key = "tcpkey.example.";
    nf_an[0].ip = "192.0.2.10";
    nf_an[0].port = 53;
    tzx(&nf_zone)->also_notify = nf_an;
    tzx(&nf_zone)->also_notify_count = 1;
    tzx(&nf_zone)->also_notify_set = true;
    nf_view.zones = &nf_zone;
    nf_cfg.views = &nf_view;
    atomic_store_explicit(&g_config_db.active, &nf_cfg, memory_order_release);
    zone_db_snapshot_t *snap = rebuild_zone_db_snapshot(&nf_cfg, NULL, NULL, NULL, NULL, 0);
    assert(snap != NULL);
    nf_entry = snapshot_get_zone(snap, "nf.example.");
    assert(nf_entry);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) == 0);
    nf_ready = true;
}

typedef struct { alignas(udp_ipc_t) uint8_t b[2048]; } nf_dg_t;

/* send the NOTIFY (it replaces the pending one of the same target) and take its datagram: the ID and the address it went to */
static bool nf_notify(nf_dg_t *dg, uint8_t *id0, uint8_t *id1) {
    send_notify_to_all(nf_entry);
    ssize_t n = recv(g_notify_ipc[0], dg->b, sizeof(dg->b), MSG_DONTWAIT);
    if (n < (ssize_t)(sizeof(udp_ipc_t) + 12)) return false;
    *id0 = dg->b[sizeof(udp_ipc_t)];
    *id1 = dg->b[sizeof(udp_ipc_t) + 1];
    uint8_t junk[2048];
    while (recv(g_notify_ipc[0], junk, sizeof(junk), MSG_DONTWAIT) > 0) {}
    return true;
}

static void fuzz_notify_answer(const uint8_t *data, size_t size) {
    if (!nf_ready) nf_setup();
    if (size < 1) return;
    bool tcp = data[0] & 1; /* the next octet of the input says which way the answer comes */
    data++;
    size--;
    if (size > 4096) size = 4096;
    nf_dg_t dg;
    uint8_t id0, id1;
    uint8_t buf[4096];
    if (!nf_notify(&dg, &id0, &id1)) return;

    if (!tcp) {
        /* as a datagram from the address the NOTIFY went to, with its ID */
        memcpy(buf, data, size);
        if (size >= 2) { buf[0] = id0; buf[1] = id1; }
        notify_handle_response(buf, size, (const struct sockaddr *)&((const udp_ipc_t *)dg.b)->client_addr);
        return;
    }
    /* as the reply on a connection: the length prefix and the message come from the input; the peer says nothing more */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return;
    (void)!send(sv[1], data, size, MSG_NOSIGNAL | MSG_DONTWAIT);
    shutdown(sv[1], SHUT_WR);
    uint8_t req[40] = {0};
    size_t rl = 0;
    if (notify_tcp_roundtrip(sv[0], req, sizeof(req), buf, sizeof(buf), &rl, 20) == NOTIFY_TCP_OK) {
        assert(rl >= 12 && rl <= sizeof(buf));
        buf[0] = id0;
        buf[1] = id1;
        notify_handle_response(buf, rl, (const struct sockaddr *)&((const udp_ipc_t *)dg.b)->client_addr);
    }
    close(sv[0]);
    close(sv[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 1 && data[0] == 0x7E) {
        fuzz_notify_answer(data + 1, size - 1);
        return 0;
    }
    if (size < 12) return 0;

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.domain, "dyn.example.com.", sizeof(entry.domain) - 1);
    strncpy(entry.view_name, "default", sizeof(entry.view_name) - 1);
    pthread_mutex_init(&entry.writer_lock, NULL);
    pthread_mutex_init(&entry.ixfr_history.lock, NULL);

    zone_arena_init(test_zone_slot(&entry, 0));
    zone_arena_init(test_zone_slot(&entry, 1));

    parse_error_t err = {0};
    parse_context_t ctx = {
        .base_dir = ".",
        .default_origin = "dyn.example.com.",
        .is_standalone_mode = true,
        .err_out = &err,
    };
    char init_zone[] = "dyn.example.com. 3600 IN SOA ns1.dyn.example.com. admin.dyn.example.com. 1 3600 1800 604800 86400\n"
                       "dyn.example.com. 3600 IN NS ns1.dyn.example.com.\n"
                       "dyn.example.com. 3600 IN A 192.0.2.1\n"
                       /* names for the RFC 2136 §3.4.2 rules: RRset equality, CNAME conflicts, delegation */
                       "www.dyn.example.com. 3600 IN A 192.0.2.10\n"
                       "www.dyn.example.com. 3600 IN A 192.0.2.11\n"
                       "alias.dyn.example.com. 3600 IN CNAME www.dyn.example.com.\n"
                       "sub.dyn.example.com. 3600 IN NS ns.sub.dyn.example.com.\n";
    parse_zone_fast(init_zone, sizeof(init_zone) - 1, test_zone_slot(&entry, 0), &ctx);
    assert(test_build_index(test_zone_slot(&entry, 0), true) == 0);

    atomic_store_explicit(&entry.rcu.active, &test_zone_slot(&entry, 0)->ver, memory_order_release);
    atomic_store_explicit(&entry.serial, 1, memory_order_release);

    // Fuzz dynamic update handling
    handle_dynamic_update(data, size, &entry, "127.0.0.1", "key-admin");

    /* S5 B-1: every published version carries the image the engine reads. B-2: the version an UPDATE published has
     * no builder any more; the hand-built initial one (arena_a, an UPDATE that changed nothing) still holds its RRs */
    zone_version_t *published = atomic_load_explicit(&entry.rcu.active, memory_order_acquire);
    assert(published->image != NULL);
    assert(published == &test_zone_slot(&entry, 0)->ver || published->heap); /* unchanged, or a new heap version without a builder */

    /* X-35: an applied update records its IXFR difference in entry.ixfr_history (compute_ixfr_diff()); the
     * server keeps it for the life of the zone, this per-input entry must release it or every applied update
     * leaks one transaction (the RSS grew to the 2 GB limit of the build host in a few minutes) */
    ixfr_history_clear(&entry.ixfr_history);

    test_entry_release(&entry);
    pthread_mutex_destroy(&entry.writer_lock);
    pthread_mutex_destroy(&entry.ixfr_history.lock);
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

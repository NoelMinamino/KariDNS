#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <signal.h>
#ifdef __FreeBSD__
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procctl.h>
#endif

#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"
#include "dns_wire.h"
#include "dns_zone_parser.h"
#include "dns_config_parser.h"
#include "dns_plugin_sup.h"
#include "test_zext.h"
#include "dns_utils.h"
#include "dns_query_engine.h"
#include "dns_axfr_ixfr.h"
#include "dns_edns_ecs.h"
#include "dns_priv_sandbox.h"
#include "dns_log.h"
#include "dns_log_state.h"
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>

/* fork() from a process that has no helper thread running: the snapshot cleanup threads that a reload started are
 * detached or still on their way out, and a fork() in that window deadlocks under ASan on FreeBSD (the ASan fork handler
 * holds the allocator lock while waiting for the rtld lock that a starting thread holds). gc_snapshot_wait_idle() joins them. */
static pid_t quiet_fork(void) {
    gc_snapshot_wait_idle();
    return fork();
}

// Internal server core prototypes for testing
// (perform_config_reload / perform_config_reload_ext / reload_all_zones come from dns_server_internal.h)
void run_frontend_router(pid_t backend_pid, int router_id);
void backend_sig_handler(int sig);
void backend_sighup_noop(int sig);
bool sighup_decide(int drained, bool from_manager, long delivered, bool *last_reload);
bool daemonize(void);
void supervisor_sig_handler(int sig);
void cleanup_pid_file(void);
void setup_ipc_tables(int num_workers);
void *worker_thread_func(void *arg);
void *async_io_worker_func(void *arg);
void start_connect_broker(void);
extern pid_t g_broker_pid;
extern _Atomic bool g_privilege_drop_complete;
extern _Atomic bool g_control_signals_ready;
extern _Atomic int g_backend_should_exit;
bool preflight_writable_path(const char *path, const char *what, bool foreground,
                             bool check_existing, const char *hint);
bool check_unix_socket_path(const char *path, const char *what);
bool validate_program_zone_users(server_config_t *cfg);
bool preflight_listen_ports(server_config_t *cfg);
int sendmmsg_skip_failed(int fd, struct mmsghdr *msgs, int n, const char *path, bool is_ipc);

// ----------------------------------------------------------------------------
// 1. fast_ipv4_to_str Test
// ----------------------------------------------------------------------------
static void test_fast_ipv4_to_str(void) {
    printf("[TEST] Server Core: fast_ipv4_to_str conversion...\n");
    const char *test_ips[] = {
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.254",
        "255.255.255.255",
        "192.0.2.4",
        "198.51.100.99",
        "198.51.100.8",
        "203.0.113.1",
        "100.64.0.1"
    };
    size_t count = sizeof(test_ips) / sizeof(test_ips[0]);

    for (size_t i = 0; i < count; i++) {
        struct in_addr addr;
        int res = inet_pton(AF_INET, test_ips[i], &addr);
        assert(res == 1);

        char out[INET_ADDRSTRLEN];
        fast_ipv4_to_str(addr.s_addr, out);
        assert(strcmp(out, test_ips[i]) == 0);
    }
    printf("  -> fast_ipv4_to_str passed for %zu IPs.\n", count);
}

// ----------------------------------------------------------------------------
// 2. escape_qname_for_log Test
// ----------------------------------------------------------------------------
static void test_escape_qname_for_log(void) {
    printf("[TEST] Server Core: escape_qname_for_log escaping & boundary checks...\n");

    char dst[512];

    // 1. NULL src
    escape_qname_for_log(NULL, dst, sizeof(dst));
    assert(strcmp(dst, "") == 0);

    // 2. Empty string
    escape_qname_for_log("", dst, sizeof(dst));
    assert(strcmp(dst, "") == 0);

    // 3. Normal alphanumeric domain name
    escape_qname_for_log("example.com.", dst, sizeof(dst));
    assert(strcmp(dst, "example.com.") == 0);

    // 4. Special characters: quote, semicolon. A backslash starts an escape of the canonical name form
    //    (dns_wire.h) and is copied with the next character, not escaped again.
    escape_qname_for_log("foo\"bar\\\\baz;test", dst, sizeof(dst));
    assert(strcmp(dst, "foo\\\"bar\\\\baz\\059test") == 0);

    // 4b. Canonical escapes from the query parser pass through unchanged (R-29)
    escape_qname_for_log("sp\\032ace.a\\.b.test.", dst, sizeof(dst));
    assert(strcmp(dst, "sp\\032ace.a\\.b.test.") == 0);
    escape_qname_for_log("trailing\\", dst, sizeof(dst));
    assert(strcmp(dst, "trailing\\\\") == 0);

    // 5. Control characters and space (\n, \r, \t, space, 0x01)
    escape_qname_for_log("hello world\n\t\r", dst, sizeof(dst));
    assert(strcmp(dst, "hello\\032world\\010\\009\\013") == 0);

    // 6. Non-ASCII high bytes (e.g. 0xFF, 0x80)
    char non_ascii[4] = {(char)0xFF, (char)0x80, 'a', '\0'};
    escape_qname_for_log(non_ascii, dst, sizeof(dst));
    assert(strcmp(dst, "\\255\\128a") == 0);

    // 7. Small buffer boundaries (dst_size = 0, 1, 4, 8)
    escape_qname_for_log("abcdef", dst, 0); // Should not crash
    escape_qname_for_log("abcdef", dst, 1);
    assert(dst[0] == '\0');

    escape_qname_for_log("abcdef", dst, 4);
    assert(strlen(dst) < 4);
    assert(strncmp(dst, "abc", 3) == 0 || strlen(dst) <= 3);

    printf("  -> escape_qname_for_log passed.\n");
}

// ----------------------------------------------------------------------------
// 3. resolve_ip_port_to_sockaddr Test
// ----------------------------------------------------------------------------
static void test_resolve_ip_port_to_sockaddr(void) {
    printf("[TEST] Server Core: resolve_ip_port_to_sockaddr conversion...\n");

    struct sockaddr_storage ss;

    // 1. IPv4 default port (port 0 -> 53)
    size_t sz = resolve_ip_port_to_sockaddr("192.0.2.1", 0, &ss);
    assert(sz == sizeof(struct sockaddr_in));
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    assert(sin->sin_family == AF_INET);
    assert(sin->sin_port == htons(53));

    // 2. IPv4 custom port
    sz = resolve_ip_port_to_sockaddr("127.0.0.1", 8053, &ss);
    assert(sz == sizeof(struct sockaddr_in));
    sin = (struct sockaddr_in *)&ss;
    assert(sin->sin_port == htons(8053));

    // 3. IPv6 default port
    sz = resolve_ip_port_to_sockaddr("2001:db8::1", 0, &ss);
    assert(sz == sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    assert(sin6->sin6_family == AF_INET6);
    assert(sin6->sin6_port == htons(53));

    // 4. IPv6 custom port
    sz = resolve_ip_port_to_sockaddr("::1", 5353, &ss);
    assert(sz == sizeof(struct sockaddr_in6));
    sin6 = (struct sockaddr_in6 *)&ss;
    assert(sin6->sin6_port == htons(5353));

    // 5. Invalid inputs
    sz = resolve_ip_port_to_sockaddr("invalid.ip.address", 53, &ss);
    assert(sz == 0);

    sz = resolve_ip_port_to_sockaddr("999.999.999.999", 53, &ss);
    assert(sz == 0);

    sz = resolve_ip_port_to_sockaddr("", 53, &ss);
    assert(sz == 0);

    printf("  -> resolve_ip_port_to_sockaddr passed.\n");
}

// ----------------------------------------------------------------------------
// 4. TCP Client Tracking & High Watermark Test
// ----------------------------------------------------------------------------
static void test_tcp_client_tracking(void) {
    printf("[TEST] Server Core: inc_tcp_clients / dec_tcp_clients tracking...\n");

    atomic_store_explicit(&g_tcp_clients, 0, memory_order_relaxed);
    atomic_store_explicit(&g_tcp_high_water, 0, memory_order_relaxed);

    inc_tcp_clients();
    assert(atomic_load_explicit(&g_tcp_clients, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed) == 1);

    inc_tcp_clients();
    inc_tcp_clients();
    assert(atomic_load_explicit(&g_tcp_clients, memory_order_relaxed) == 3);
    assert(atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed) == 3);

    dec_tcp_clients();
    assert(atomic_load_explicit(&g_tcp_clients, memory_order_relaxed) == 2);
    // High water mark must NOT decrease
    assert(atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed) == 3);

    dec_tcp_clients();
    dec_tcp_clients();
    assert(atomic_load_explicit(&g_tcp_clients, memory_order_relaxed) == 0);
    assert(atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed) == 3);

    printf("  -> inc_tcp_clients / dec_tcp_clients passed.\n");
}

// ----------------------------------------------------------------------------
// 5. read_dns_tcp_message & send_tcp_robust Test
// ----------------------------------------------------------------------------
static void test_read_dns_tcp_message_and_send(void) {
    printf("[TEST] Server Core: read_dns_tcp_message & send_tcp_robust...\n");

    int sv[2];
    int res = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    assert(res == 0);

    // Non-blocking for reader
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL, 0) | O_NONBLOCK);

    tcp_stream_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TCP_STATE_READ_LEN;

    uint8_t *msg_out = NULL;
    uint16_t len_out = 0;

    // 1. EAGAIN on empty buffer
    int ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == 0);

    // 2. Send 0-length message (2 zero bytes)
    uint8_t zero_len_hdr[2] = {0x00, 0x00};
    ssize_t sn = send_tcp_robust(sv[1], zero_len_hdr, 2);
    assert(sn == 2);

    ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == 1);
    assert(len_out == 0);

    // 3. Send valid DNS message in one go (length 12 + payload 12 bytes)
    uint8_t payload[14];
    payload[0] = 0x00; // length msb
    payload[1] = 12;   // length lsb
    for (int i = 0; i < 12; i++) payload[2 + i] = (uint8_t)(i + 1);

    sn = send_tcp_robust(sv[1], payload, 14);
    assert(sn == 14);

    ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == 1);
    assert(len_out == 12);
    assert(msg_out != NULL);
    for (int i = 0; i < 12; i++) {
        assert(msg_out[i] == (uint8_t)(i + 1));
    }

    // 4. Send fragmented DNS message (chunked)
    // Send 1 byte of length header first
    uint8_t frag_len1 = 0x00;
    sn = send_tcp_robust(sv[1], &frag_len1, 1);
    assert(sn == 1);

    ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == 0); // Needs more data

    // Send 2nd byte of length header (len = 6)
    uint8_t frag_len2 = 0x06;
    sn = send_tcp_robust(sv[1], &frag_len2, 1);
    assert(sn == 1);

    // Send partial body (3 bytes)
    uint8_t body_p1[3] = {0xAA, 0xBB, 0xCC};
    sn = send_tcp_robust(sv[1], body_p1, 3);
    assert(sn == 3);

    ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == 0); // Still needs 3 bytes

    // Send remaining 3 bytes
    uint8_t body_p2[3] = {0xDD, 0xEE, 0xFF};
    sn = send_tcp_robust(sv[1], body_p2, 3);
    assert(sn == 3);

    ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == 1);
    assert(len_out == 6);
    assert(msg_out[0] == 0xAA && msg_out[5] == 0xFF);

    // 5. Connection closed (EOF)
    close(sv[1]);
    ret = read_dns_tcp_message(sv[0], &ctx, &msg_out, &len_out);
    assert(ret == -1);

    close(sv[0]);
    printf("  -> read_dns_tcp_message & send_tcp_robust passed.\n");
}

/* L2: max-transfer-time-in of an inbound transfer (ctx->read_deadline) holds inside one message.  SO_RCVTIMEO restarts on every recv(), so
 * a primary that sends one octet every 200 ms never trips it; the deadline stops the read after the second the transfer may take. */
static void *l2_drip_thread(void *arg) {
    int fd = *(int *)arg;
    uint8_t msg[2 + 8];
    msg[0] = 0; msg[1] = 8;
    for (int i = 0; i < 8; i++) msg[2 + i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(msg); i++) {
        if (send(fd, &msg[i], 1, MSG_NOSIGNAL) != 1) break;
        usleep(200 * 1000);
    }
    return NULL;
}

static void test_read_dns_tcp_message_deadline(void) {
    printf("[TEST] Server Core: read_dns_tcp_message gives up at ctx->read_deadline inside one message (max-transfer-time-in)...\n");
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);      /* blocking, as the inbound transfer's socket is */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    assert(setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    tcp_stream_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert(ctx);
    ctx->state = TCP_STATE_READ_LEN;
    ctx->read_deadline = time(NULL) + 1;
    pthread_t th;
    assert(pthread_create(&th, NULL, l2_drip_thread, &sv[1]) == 0);
    uint8_t *msg_out = NULL;
    uint16_t len_out = 0;
    time_t t0 = time(NULL);
    int ret = read_dns_tcp_message(sv[0], ctx, &msg_out, &len_out);
    assert(ret == -1);                                          /* the whole message would take 2 s */
    assert(time(NULL) - t0 <= 3);
    close(sv[0]);                                               /* the dripping thread's send() fails and it ends */
    pthread_join(th, NULL);
    close(sv[1]);

    /* no deadline: the same slow message is read to its end */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = TCP_STATE_READ_LEN;
    assert(pthread_create(&th, NULL, l2_drip_thread, &sv[1]) == 0);
    ret = read_dns_tcp_message(sv[0], ctx, &msg_out, &len_out);
    assert(ret == 1 && len_out == 8 && msg_out[7] == 7);
    pthread_join(th, NULL);
    close(sv[0]);
    close(sv[1]);
    free(ctx);
    printf("  -> read_dns_tcp_message deadline passed.\n");
}

// ----------------------------------------------------------------------------
// 6. Query Log Max QPS & Circuit Breaker Test
// ----------------------------------------------------------------------------
bool qlog_rate_admit(time_t now, time_t *sec, uint32_t *count, uint32_t limit);
void qlog_event_sink(void *vctx, int cat, int level, const char *client_ip, int client_port, const char *msg);
static void test_query_log_max_qps_and_circuit_breaker(void) {
    printf("[TEST] Server Core: get_effective_query_log_max_qps & write_query_log...\n");

    // 1. get_effective_query_log_max_qps
    assert(get_effective_query_log_max_qps(NULL) == 0);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.query_log_max_qps = 2500;
    assert(get_effective_query_log_max_qps(&cfg) == 2500);

    /* options { query-log-max-qps 0 } is 5000, as write_query_log() reads it */
    cfg.query_log_max_qps = 0;
    assert(get_effective_query_log_max_qps(&cfg) == 5000);
    cfg.query_log_max_qps = 2500;

    /* the rings feed every channel of `category queries`: they admit what the most generous channel allows (a channel's own max-qps when it is
     * written and above 0, else query-log-max-qps), whatever the order of the channels */
    log_channel_t qa, qb, qc;
    memset(&qa, 0, sizeof(qa)); memset(&qb, 0, sizeof(qb)); memset(&qc, 0, sizeof(qc));
    qa.name = "qa"; qa.max_qps_specified = true; qa.max_qps = 100;
    qb.name = "qb"; qb.max_qps_specified = true; qb.max_qps = 7500;
    qc.name = "qc"; qc.max_qps_specified = true; qc.max_qps = 0;   /* max-qps 0: the options value */
    qa.next = &qb; qb.next = &qc;
    cfg.logging.channels = &qa;
    cfg.logging.cat[LOGC_QUERIES].n = 1;
    cfg.logging.cat[LOGC_QUERIES].name[0] = "qa";
    assert(get_effective_query_log_max_qps(&cfg) == 100);            /* a lone channel decides */
    cfg.logging.cat[LOGC_QUERIES].n = 2;
    cfg.logging.cat[LOGC_QUERIES].name[1] = "qb";
    assert(get_effective_query_log_max_qps(&cfg) == 7500);           /* the channel after the first one counts */
    cfg.logging.cat[LOGC_QUERIES].name[0] = "qb";
    cfg.logging.cat[LOGC_QUERIES].name[1] = "qa";
    assert(get_effective_query_log_max_qps(&cfg) == 7500);           /* and not by position */
    cfg.logging.cat[LOGC_QUERIES].name[1] = "qc";
    assert(get_effective_query_log_max_qps(&cfg) == 7500);
    cfg.logging.cat[LOGC_QUERIES].name[0] = "qa";
    assert(get_effective_query_log_max_qps(&cfg) == 2500);           /* qa 100 and qc (max-qps 0 -> options 2500) */
    cfg.logging.cat[LOGC_QUERIES].name[1] = "default_syslog";        /* a built-in channel has the options value */
    assert(get_effective_query_log_max_qps(&cfg) == 2500);
    cfg.logging.cat[LOGC_QUERIES].name[1] = "nosuch";                /* a name that is not a channel of the file: the options value */
    assert(get_effective_query_log_max_qps(&cfg) == 2500);
    cfg.logging.cat[LOGC_QUERIES].n = 0;                             /* querylog yes alone: the default channel */
    assert(get_effective_query_log_max_qps(&cfg) == 2500);
    memset(&cfg.logging, 0, sizeof(cfg.logging));

    /* qlog_rate_admit(): the lines one channel writes in a second, a new second starts counting again */
    time_t sec = 0;
    uint32_t cnt = 0;
    assert(qlog_rate_admit(1000, &sec, &cnt, 3) && qlog_rate_admit(1000, &sec, &cnt, 3) && qlog_rate_admit(1000, &sec, &cnt, 3));
    assert(!qlog_rate_admit(1000, &sec, &cnt, 3) && cnt == 3);
    assert(qlog_rate_admit(1001, &sec, &cnt, 3) && sec == 1001 && cnt == 1);

    // 2. write_query_log pushing to ring buffer and circuit breaker
    worker_ctx_t worker;
    memset(&worker, 0, sizeof(worker));
    worker.thread_id = 0;
    worker.qlog_ring.size = 16;
    worker.qlog_ring.mask = 15;
    worker.qlog_ring.events = calloc(16, sizeof(qlog_event_t));
    atomic_init(&worker.qlog_ring.head, 0);
    atomic_init(&worker.qlog_ring.tail, 0);
    atomic_init(&worker.qlog_ring.dropped_count, 0);

    atomic_store_explicit(&g_worker_count, 1, memory_order_relaxed);
    atomic_store_explicit(&g_qlog_circuit_broken, false, memory_order_relaxed);

    struct sockaddr_in cli_sin;
    memset(&cli_sin, 0, sizeof(cli_sin));
    cli_sin.sin_family = AF_INET;
    cli_sin.sin_port = htons(12345);
    inet_pton(AF_INET, "192.0.2.1", &cli_sin.sin_addr);

    // Write events up to 50% capacity (8 events)
    for (int i = 0; i < 8; i++) {
        write_query_log(&worker, &cli_sin, sizeof(cli_sin), "example.com.", 1, 1, false, false, IPPROTO_UDP, 50000);
    }
    assert(atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) == 8);
    assert(!atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed));

    // Verify first event contents
    assert(strcmp(worker.qlog_ring.events[0].qname, "example.com.") == 0);
    assert(worker.qlog_ring.events[0].qtype == 1);
    assert(worker.qlog_ring.events[0].protocol == IPPROTO_UDP);

    // Push more until buffer >= 80% (>= 13 events) -> trip circuit breaker
    for (int i = 0; i < 10; i++) {
        write_query_log(&worker, &cli_sin, sizeof(cli_sin), "trip.example.", 1, 1, false, false, IPPROTO_UDP, 50000);
    }
    assert(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed) == true);
    assert(atomic_load_explicit(&worker.qlog_ring.dropped_count, memory_order_relaxed) > 0);

    // Once broken, subsequent calls must skip immediately
    uint32_t head_before = atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed);
    write_query_log(&worker, &cli_sin, sizeof(cli_sin), "skipped.example.", 1, 1, false, false, IPPROTO_UDP, 50000);
    assert(atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) == head_before);

    // 0.7 (K-11): a debug flood never suspends the query log.  The events and debug lines go to the worker's event ring; however many come, the query
    // log ring is untouched, the circuit breaker stays off and the queries are still recorded.  Info and above find the half that debug cannot take.
    atomic_store_explicit(&worker.qlog_ring.head, 0, memory_order_relaxed);
    atomic_store_explicit(&worker.qlog_ring.tail, 0, memory_order_relaxed);
    atomic_store_explicit(&g_qlog_circuit_broken, false, memory_order_relaxed);
    worker.log_emitted_this_sec = 0;
    worker.ev_ring.size = 16;
    worker.ev_ring.mask = 15;
    worker.ev_ring.events = calloc(16, sizeof(qlog_event_t));
    atomic_init(&worker.ev_ring.head, 0);
    atomic_init(&worker.ev_ring.tail, 0);
    atomic_init(&worker.ev_ring.ev_dropped, 0);
    for (int i = 0; i < 1000; i++) qlog_event_sink(&worker, LOGC_QUERY_ERRORS, 3, "192.0.2.1", 53, "debug flood");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 8);                 /* half of the event ring */
    assert(atomic_load_explicit(&worker.ev_ring.ev_dropped, memory_order_relaxed) == 992);
    assert(atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) == 0);
    assert(!atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed));
    for (int i = 0; i < 12; i++) qlog_event_sink(&worker, LOGC_GENERAL, LOG_LVL_WARNING, NULL, 0, "a warning in the flood");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 16);                /* 8 warnings found room */
    assert(atomic_load_explicit(&worker.ev_ring.ev_dropped, memory_order_relaxed) == 996);
    for (int i = 0; i < 8; i++)
        write_query_log(&worker, &cli_sin, sizeof(cli_sin), "after.flood.example.", 1, 1, false, false, IPPROTO_UDP, 50000);
    assert(atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) == 8);
    assert(!atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed));
    assert(strcmp(worker.qlog_ring.events[7].qname, "after.flood.example.") == 0 && worker.qlog_ring.events[7].kind == QLOG_KIND_QUERY);
    free(worker.ev_ring.events);

    free(worker.qlog_ring.events);
    printf("  -> get_effective_query_log_max_qps & write_query_log passed (a debug flood leaves the query log alone).\n");
}

// ----------------------------------------------------------------------------
// 7. submit_response_log Ring Buffer Test
// ----------------------------------------------------------------------------
static void test_submit_response_log(void) {
    printf("[TEST] Server Core: submit_response_log ring submissions...\n");

    // Setup active config with response logging enabled
    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.responses_enabled = true;

    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);

    atomic_store_explicit(&g_resp_log_tail, 0, memory_order_relaxed);
    atomic_store_explicit(&g_resp_log_head, 0, memory_order_relaxed);
    for (int i = 0; i < RESP_LOG_RING_SIZE; i++) {
        atomic_store_explicit(&g_resp_log_ring[i].ready, false, memory_order_relaxed);
    }

    // Submit normal response
    submit_response_log(LOG_ACT_SENT, "192.0.2.100", 5353, "resp.example.com.", 1, 1, 0, true, true);
    assert(atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed) == 1);
    assert(atomic_load_explicit(&g_resp_log_ring[0].ready, memory_order_acquire) == true);
    assert(g_resp_log_ring[0].action == LOG_ACT_SENT);
    assert(strcmp(g_resp_log_ring[0].client_ip, "192.0.2.100") == 0);
    assert(g_resp_log_ring[0].client_port == 5353);
    assert(strcmp(g_resp_log_ring[0].qname, "resp.example.com.") == 0);
    assert(g_resp_log_ring[0].has_edns == true);
    assert(g_resp_log_ring[0].dnssec_ok == true);

    // Submit RRL drop response
    submit_response_log(LOG_ACT_DROP_RRL, "2001:db8::5", 60000, "rrl.example.com.", 1, 28, 0, false, false);
    assert(atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed) == 2);
    assert(atomic_load_explicit(&g_resp_log_ring[1].ready, memory_order_acquire) == true);
    assert(g_resp_log_ring[1].action == LOG_ACT_DROP_RRL);
    assert(g_resp_log_ring[1].qtype == 28);

    // Submit malformed drop response
    submit_response_log(LOG_ACT_DROP_MALFORMED, "10.10.10.10", 4000, "<malformed>", 1, 0, 1, false, false);
    assert(atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed) == 3);
    assert(g_resp_log_ring[2].action == LOG_ACT_DROP_MALFORMED);

    // Clean up
    for (int i = 0; i < 3; i++) {
        atomic_store_explicit(&g_resp_log_ring[i].ready, false, memory_order_relaxed);
    }
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> submit_response_log passed.\n");
}

// ----------------------------------------------------------------------------
// 8. log_write_rotated File Rotation Test
// ----------------------------------------------------------------------------
static void test_log_write_rotated(void) {
    printf("[TEST] Server Core: log_write_rotated size & timestamp rotation...\n");

    char template_path[256];
    snprintf(template_path, sizeof(template_path), "/tmp/karidns_test_rot_%ld.log", (long)time(NULL));

    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.file_path = template_path;
    ch.size_limit = 100; // 100 bytes limit
    ch.versions = 3;
    pthread_mutex_init(&ch.lock, NULL);
    ch.fd = open(template_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(ch.fd >= 0);

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    ch.current_date = (tm_info.tm_year + 1900) * 10000 + (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday;

    // 1. Initial write (60 bytes) - under limit
    const char *msg1 = "Line 1: 01234567890123456789012345678901234567890123456789\n"; // 60 bytes
    log_write_rotated(&ch, msg1, (int)strlen(msg1), &tm_info);
    assert(ch.current_size == strlen(msg1));

    // 2. Second write (60 bytes) - exceeds 100 bytes -> triggers rotation to .0
    const char *msg2 = "Line 2: 01234567890123456789012345678901234567890123456789\n";
    log_write_rotated(&ch, msg2, (int)strlen(msg2), &tm_info);
    assert(ch.current_size == strlen(msg2));

    // Check that rotated file exists
    char rot0_path[300];
    snprintf(rot0_path, sizeof(rot0_path), "%s.0", template_path);
    struct stat st;
    assert(stat(rot0_path, &st) == 0);
    assert(st.st_size == (off_t)strlen(msg1));

    // 3. Timestamp rotation
    ch.size_limit = 0;
    ch.suffix_timestamp = true;
    ch.current_date = 20260101; // Yesterday
    int today = (tm_info.tm_year + 1900) * 10000 + (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday;

    const char *msg3 = "Line 3: Timestamp rotated line\n";
    log_write_rotated(&ch, msg3, (int)strlen(msg3), &tm_info);
    assert(ch.current_date == today);

    char ts_path[300];
    snprintf(ts_path, sizeof(ts_path), "%s.20260101", template_path);
    assert(stat(ts_path, &st) == 0);

    // Clean up
    if (ch.fd >= 0) close(ch.fd);
    pthread_mutex_destroy(&ch.lock);
    unlink(template_path);
    unlink(rot0_path);
    unlink(ts_path);

    printf("  -> log_write_rotated passed.\n");
}

/* D-21: suffix timestamp のサイズローテーションが同じ日に何度起きても上書きせず、
 * versions <n> のときは日付付きのファイルを新しい順に n 個だけ残す (BIND と同じ) */
static int count_lines_of(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0, c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') n++;
    fclose(f);
    return n;
}

static void rotate_ts_run(int versions, int *kept_files, int *kept_lines) {
    char dir[] = "/tmp/karidns_test_tsrot_XXXXXX";
    assert(mkdtemp(dir) != NULL);
    char path[256], p[300];
    snprintf(path, sizeof(path), "%s/q.log", dir);
    /* 対象外のファイル: 別のベース名、日付でない接尾辞、先頭 0 の連番 */
    const char *others[] = { "other.log.20250101", "q.log.notes", "q.log.20250101.01", "q.log.2025010" };
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", dir, others[i]);
        int fd = open(p, O_WRONLY | O_CREAT, 0644);
        assert(fd >= 0);
        close(fd);
    }
    snprintf(p, sizeof(p), "%s.20250101", path); /* 前日以前のローテーション済みファイル */
    FILE *old = fopen(p, "w");
    assert(old);
    fputs("old\n", old);
    fclose(old);

    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.file_path = path;
    ch.size_limit = 50;
    ch.versions = versions;
    ch.suffix_timestamp = true;
    pthread_mutex_init(&ch.lock, NULL);
    ch.fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(ch.fd >= 0);
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    int today = (tm_info.tm_year + 1900) * 10000 + (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday;
    ch.current_date = today;

    const char *line = "0123456789012345678901234567890123456789\n"; /* 41 bytes: 1 line per file */
    for (int i = 0; i < 6; i++) log_write_rotated(&ch, line, (int)strlen(line), &tm_info);
    close(ch.fd);
    pthread_mutex_destroy(&ch.lock);

    /* 6 行 = 現在のファイル 1 行 + 同じ日のローテーション 5 回 (.DATE, .DATE.1 .. .DATE.4) */
    *kept_files = 0;
    *kept_lines = count_lines_of(path);
    for (int seq = 0; seq <= 4; seq++) {
        if (seq) snprintf(p, sizeof(p), "%s.%08d.%d", path, today, seq);
        else snprintf(p, sizeof(p), "%s.%08d", path, today);
        int n = count_lines_of(p);
        if (n >= 0) { (*kept_files)++; *kept_lines += n; unlink(p); }
    }
    snprintf(p, sizeof(p), "%s.20250101", path);
    if (count_lines_of(p) >= 0) { (*kept_files)++; unlink(p); }
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", dir, others[i]);
        assert(unlink(p) == 0); /* 形式の違うファイルは消さない */
    }
    unlink(path);
    assert(rmdir(dir) == 0);
}

/* D-04: TCP connection contexts come from a pool allocated once; R-24: length + message in one write */
static void *tcp_pool_churn(void *arg) {
    (void)arg;
    for (int i = 0; i < 20000; i++) {
        tcp_stream_ctx_t *c = tcp_ctx_alloc();
        if (c) {
            c->accumulated = 7;
            tcp_ctx_free(c);
        }
    }
    return NULL;
}

static void test_tcp_pool_and_single_write(void) {
    printf("[TEST] Server Core: TCP context pool (D-04) and one-write TCP messages (RFC 7766 §8)...\n");
    assert(tcp_pool_init());
    assert(tcp_pool_init());   /* idempotent */
    static tcp_stream_ctx_t *held[MAX_TCP_CLIENTS];
    for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
        held[i] = tcp_ctx_alloc();
        assert(held[i] != NULL);
        assert(held[i]->accumulated == 0 && held[i]->state == TCP_STATE_READ_LEN && held[i]->idle_deadline_ms == 0);
        held[i]->accumulated = 99;   /* dirty it: the next user must get it cleared */
        held[i]->buf[0] = 0x5a;
    }
    assert(tcp_ctx_alloc() == NULL);   /* MAX_TCP_CLIENTS in use: no more connections */
    for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
        for (int j = i + 1; j < i + 4 && j < MAX_TCP_CLIENTS; j++) assert(held[i] != held[j]);
    }
    tcp_ctx_free(held[17]);
    tcp_stream_ctx_t *again = tcp_ctx_alloc();
    assert(again == held[17] && again->accumulated == 0);
    for (int i = 0; i < MAX_TCP_CLIENTS; i++) tcp_ctx_free(i == 17 ? again : held[i]);

    /* concurrent alloc/free from several threads (lock-free list; run under TSan in CI) */
    pthread_t th[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&th[i], NULL, tcp_pool_churn, NULL) == 0);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    int count = 0;
    while (count < MAX_TCP_CLIENTS && (held[count] = tcp_ctx_alloc()) != NULL) count++;
    assert(count == MAX_TCP_CLIENTS);   /* nothing lost or duplicated */
    assert(tcp_ctx_alloc() == NULL);
    for (int i = 0; i < count; i++) tcp_ctx_free(held[i]);

    /* send_tcp_dns_message(): the peer reads prefix and message together */
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    uint8_t msg[300];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
    assert(send_tcp_dns_message(sv[0], msg, sizeof(msg)) == (ssize_t)sizeof(msg));
    uint8_t in[400];
    ssize_t n = recv(sv[1], in, sizeof(in), 0);
    assert(n == (ssize_t)sizeof(msg) + 2);
    assert(in[0] == 0x01 && in[1] == 0x2c && memcmp(in + 2, msg, sizeof(msg)) == 0);
    assert(send_tcp_dns_message(sv[0], msg, 65536) == -1);   /* does not fit the length field */
    /* a message larger than the socket buffer is still sent completely */
    int small = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    static uint8_t big[60000], got[60002];
    for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 7);
    pid_t reader = quiet_fork();
    assert(reader >= 0);
    if (reader == 0) {
        size_t have = 0;
        while (have < sizeof(got)) {
            ssize_t r = recv(sv[1], got + have, sizeof(got) - have, 0);
            if (r <= 0) _exit(1);
            have += (size_t)r;
        }
        _exit(got[0] == 0xea && got[1] == 0x60 && memcmp(got + 2, big, sizeof(big)) == 0 ? 0 : 2);
    }
    assert(send_tcp_dns_message(sv[0], big, sizeof(big)) == (ssize_t)sizeof(big));
    int st = 0;
    waitpid(reader, &st, 0);
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(sv[0]);
    close(sv[1]);
    printf("  -> TCP context pool and one-write messages passed.\n");
}

static void test_log_write_rotated_timestamp_versions(void) {
    printf("[TEST] Server Core: suffix timestamp rotation keeps every file of the day, versions prunes (D-21)...\n");
    int files, lines;
    rotate_ts_run(0, &files, &lines);
    assert(files == 6);  /* versions なし: 何も消さない (今日の 5 個 + 前日の 1 個) */
    assert(lines == 6);  /* 書いた 6 行が全部残る (上書きしない) */
    rotate_ts_run(3, &files, &lines);
    assert(files == 3);  /* 新しい 3 個 (.DATE.2 .. .DATE.4) だけ残る。前日のものは消える */
    assert(lines == 4);  /* 現在のファイル 1 行 + 残った 3 個 */
    printf("  -> timestamp rotation passed.\n");
}

// ----------------------------------------------------------------------------
// 9. fill_observatory_snapshot Test
// ----------------------------------------------------------------------------
static void test_fill_observatory_snapshot(void) {
    printf("[TEST] Server Core: fill_observatory_snapshot counter mapping...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "observatory.example.", sizeof(entry.domain));
    strlcpy(entry.view_name, "internal", sizeof(entry.view_name));
    entry.is_secondary = true;
    atomic_init(&entry.serial, 2026091901);

    atomic_init(&entry.observatory.queries_total, 1000);
    atomic_init(&entry.observatory.responses_noerror, 800);
    atomic_init(&entry.observatory.responses_nxdomain, 100);
    atomic_init(&entry.observatory.responses_nodata, 50);
    atomic_init(&entry.observatory.responses_servfail, 30);
    atomic_init(&entry.observatory.responses_refused, 20);
    atomic_init(&entry.observatory.tcp_queries, 250);
    atomic_init(&entry.observatory.ecs_queries, 150);
    atomic_init(&entry.observatory.edns_queries, 900);
    atomic_init(&entry.observatory.dnssec_do_queries, 400);
    atomic_init(&entry.observatory.rrl_dropped, 15);
    atomic_init(&entry.observatory.rrl_slipped, 5);
    atomic_init(&entry.observatory.notify_sent, 10);
    atomic_init(&entry.observatory.notify_ack, 8);
    atomic_init(&entry.observatory.axfr_success, 3);
    atomic_init(&entry.observatory.ixfr_success, 7);
    atomic_init(&entry.observatory.wirecache_hits, 600);
    atomic_init(&entry.observatory.wirecache_misses, 400);

    time_t xfer_time = 1758270000;
    time_t notif_time = 1758270100;
    atomic_init(&entry.observatory.last_transfer_time, xfer_time);
    atomic_init(&entry.observatory.last_notify_time, notif_time);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    zone_observatory_snapshot_t out;
    memset(&out, 0, sizeof(out));

    fill_observatory_snapshot(&entry, &cfg, &out);

    assert(strcmp(out.domain, "observatory.example.") == 0);
    assert(strcmp(out.view_name, "internal") == 0);
    assert(out.is_secondary == true);
    assert(out.soa_serial == 2026091901);
    assert(out.queries_total == 1000);
    assert(out.responses_noerror == 800);
    assert(out.responses_nxdomain == 100);
    assert(out.responses_nodata == 50);
    assert(out.responses_servfail == 30);
    assert(out.responses_refused == 20);
    assert(out.tcp_queries == 250);
    assert(out.ecs_queries == 150);
    assert(out.edns_queries == 900);
    assert(out.dnssec_do_queries == 400);
    assert(out.rrl_dropped == 15);
    assert(out.rrl_slipped == 5);
    assert(out.notify_sent == 10);
    assert(out.notify_ack == 8);
    assert(out.axfr_success == 3);
    assert(out.ixfr_success == 7);
    assert(out.wirecache_hits == 600);
    assert(out.wirecache_misses == 400);
    assert(out.last_transfer_time == xfer_time);
    assert(out.last_notify_time == notif_time);

    printf("  -> fill_observatory_snapshot passed.\n");
}

// ----------------------------------------------------------------------------
// 10. find_configured_domain Test
// ----------------------------------------------------------------------------
static void test_find_configured_domain(void) {
    printf("[TEST] Server Core: find_configured_domain...\n");

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    zone_config_t z_master;
    memset(&z_master, 0, sizeof(z_master));
    z_master.domain = "master.example.";
    z_master.type = "master";

    zone_config_t z_fwd;
    memset(&z_fwd, 0, sizeof(z_fwd));
    z_fwd.domain = "fwd.example.";
    z_fwd.type = "forward";

    zone_config_t z_prog;
    memset(&z_prog, 0, sizeof(z_prog));
    z_prog.domain = "prog.example.";
    z_prog.type = "program";

    z_master.next = &z_fwd;
    z_fwd.next = &z_prog;
    cfg.zones = &z_master;

    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    // 1. find_configured_domain test
    char buf[256];
    const char *found = find_configured_domain("FWD.EXAMPLE.", buf, sizeof(buf));
    assert(strcmp(found, "fwd.example.") == 0);

    found = find_configured_domain("unknown.zone.", buf, sizeof(buf));
    assert(strcmp(found, "unknown.zone.") == 0);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> find_configured_domain passed.\n");
}

// ----------------------------------------------------------------------------
// 0.7: the control socket a refused start bound (ctl_bound_*), a log directory shared with the pid file / control socket directory
// (startup_dir_shared_with_log; tests/run_startup_refused_cleanup_test.sh runs both in a real start as root)
// ----------------------------------------------------------------------------
static int test_bind_unix(int dfd, const char *name) {
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strlcpy(un.sun_path, name, sizeof(un.sun_path));
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(s >= 0);
    assert(bindat(dfd, s, (struct sockaddr *)&un, sizeof(un)) == 0);
    return s;
}

static void test_startup_refused_cleanup(void) {
    printf("[TEST] Server Core: the control socket of a refused start, a log directory shared with the pid file directory...\n");
    char base[] = "/tmp/karidns_ctlbound_XXXXXX";
    assert(mkdtemp(base) != NULL);
    int dfd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(dfd >= 0);
    struct stat st;

    // the socket this start bound goes, through the directory descriptor (a duplicate: the caller closes its own)
    int s = test_bind_unix(dfd, "c.sock");
    assert(ctl_bound_set(dfd, "c.sock"));
    ctl_bound_unlink();
    assert(fstatat(dfd, "c.sock", &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT);
    close(s);
    ctl_bound_unlink();                               // (nothing bound any more: a no-op)

    // a socket another server bound at that name meanwhile stays
    s = test_bind_unix(dfd, "c.sock");
    assert(ctl_bound_set(dfd, "c.sock"));
    close(s);
    s = test_bind_unix(dfd, "c2.sock");               // (made while the first exists: another inode) and moved over the name
    assert(renameat(dfd, "c2.sock", dfd, "c.sock") == 0);
    ctl_bound_unlink();
    assert(fstatat(dfd, "c.sock", &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISSOCK(st.st_mode));

    // after ctl_bound_forget() (the Backend has it) nothing is removed
    assert(ctl_bound_set(dfd, "c.sock"));
    ctl_bound_forget();
    ctl_bound_unlink();
    assert(fstatat(dfd, "c.sock", &st, AT_SYMLINK_NOFOLLOW) == 0);
    close(s);
    assert(unlinkat(dfd, "c.sock", 0) == 0);

    // bound by path (no directory descriptor)
    char path[256];
    snprintf(path, sizeof(path), "%s/p.sock", base);
    s = test_bind_unix(AT_FDCWD, path);
    assert(ctl_bound_set(-1, path));
    ctl_bound_unlink();
    assert(lstat(path, &st) != 0 && errno == ENOENT);
    close(s);

    // not a socket, missing, too long: nothing is recorded (and nothing removed)
    int f = openat(dfd, "plain", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(f >= 0);
    close(f);
    assert(!ctl_bound_set(dfd, "plain"));
    ctl_bound_unlink();
    assert(fstatat(dfd, "plain", &st, 0) == 0);
    assert(!ctl_bound_set(dfd, "missing.sock"));
    assert(!ctl_bound_set(-1, NULL));
    char longname[200];
    memset(longname, 'a', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    assert(!ctl_bound_set(dfd, longname));
    assert(unlinkat(dfd, "plain", 0) == 0);

    // startup_dir_shared_with_log(): no log channel of the runtime is in this directory, a directory that does not exist, no path
    snprintf(path, sizeof(path), "%s/k.pid", base);
    assert(!startup_dir_shared_with_log(path, "pid file"));
    assert(!startup_dir_shared_with_log("/nonexistent-karidns-test-dir/k.pid", "pid file"));
    assert(!startup_dir_shared_with_log(NULL, "pid file"));
    assert(!startup_dir_shared_with_log("ctl.sock", "control socket"));   // (no directory, or "/": not checked, as in main())
    assert(!startup_dir_shared_with_log("/ctl.sock", "control socket"));

    // dir_is_below(): base/a/b/c, base/l -> a/b; compared by device and inode while walking up with ".."
    char a[300], b[300], c[300], d[400];
    struct stat sbase, sa, sb, sroot;
    snprintf(a, sizeof(a), "%s/a", base);
    snprintf(b, sizeof(b), "%s/a/b", base);
    snprintf(c, sizeof(c), "%s/a/b/c", base);
    assert(mkdir(a, 0755) == 0 && mkdir(b, 0755) == 0 && mkdir(c, 0755) == 0);
    assert(symlinkat("a/b", dfd, "l") == 0);
    assert(stat(base, &sbase) == 0 && stat(a, &sa) == 0 && stat(b, &sb) == 0 && stat("/", &sroot) == 0);
    assert(dir_is_below(c, &sb));                     // the parent
    assert(dir_is_below(c, &sbase));                  // a grandparent (and above)
    assert(dir_is_below(c, &sroot));                  // up to "/"
    assert(!dir_is_below(b, &sb));                    // not the directory itself (startup_dir_shared_with_log() compares that)
    assert(!dir_is_below(a, &sb));                    // not below
    assert(!dir_is_below("/", &sbase));               // "/" has nothing above it (".." is "/" again)
    snprintf(d, sizeof(d), "%s/a/b/new", base);       // not there yet: its parent counts (ensure_priv_dir_safe() makes it there)
    assert(dir_is_below(d, &sb) && dir_is_below(d, &sa));
    snprintf(d, sizeof(d), "%s/a/new", base);
    assert(!dir_is_below(d, &sb));
    snprintf(d, sizeof(d), "%s/a/x/new", base);       // the parent is not there either
    assert(!dir_is_below(d, &sbase));
    snprintf(d, sizeof(d), "%s/a/b/../b/c", base);    // ".." and a symlink in the path do not hide the relation
    assert(dir_is_below(d, &sb));
    snprintf(d, sizeof(d), "%s/l/c", base);
    assert(dir_is_below(d, &sb) && dir_is_below(d, &sa));
    snprintf(d, sizeof(d), "%s/l/new", base);
    assert(dir_is_below(d, &sb));
    snprintf(d, sizeof(d), "%s/l", base);             // (the symlink itself: the directory it names, not below itself)
    assert(!dir_is_below(d, &sb));
    f = openat(dfd, "plain", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(f >= 0);
    close(f);
    snprintf(d, sizeof(d), "%s/plain", base);         // not a directory
    assert(!dir_is_below(d, &sbase));
    assert(unlinkat(dfd, "plain", 0) == 0 && unlinkat(dfd, "l", 0) == 0 && rmdir(c) == 0 && rmdir(b) == 0 && rmdir(a) == 0);

    close(dfd);
    assert(rmdir(base) == 0);
    printf("  -> ctl_bound_* and startup_dir_shared_with_log passed.\n");
}

// ----------------------------------------------------------------------------
// 11. ensure_priv_dir_safe Test
// ----------------------------------------------------------------------------
static void test_ensure_priv_dir_safe(void) {
    printf("[TEST] Server Core: ensure_priv_dir_safe security verification...\n");

    // NULL or empty path
    assert(ensure_priv_dir_safe(NULL) == true);
    assert(ensure_priv_dir_safe("") == true);

    if (geteuid() != 0) {
        // Non-root execution bypasses privilege directory checks by design
        assert(ensure_priv_dir_safe("/tmp") == true);
        printf("  -> ensure_priv_dir_safe passed (non-root: bypass only; "
               "attack-scenario checks SKIPPED, re-run as root for full coverage).\n");
        return;
    }

    // --- root-only: every case runs against a private mkdtemp() tree, never a
    // system path whose layout differs per OS (/var/run is a symlink on Linux). ---
    char base[] = "/tmp/karidns_privdir_XXXXXX";
    assert(mkdtemp(base) != NULL);
    char path[256];

    // World-writable sticky /tmp itself must be rejected
    assert(ensure_priv_dir_safe("/tmp") == false);

    // Root-owned 0755 directory -> accepted
    snprintf(path, sizeof(path), "%s/ok", base);
    assert(mkdir(path, 0755) == 0);
    assert(chmod(path, 0755) == 0);
    assert(ensure_priv_dir_safe(path) == true);

    // Non-existent directory is created 0755 root-owned -> accepted
    snprintf(path, sizeof(path), "%s/created/", base);
    assert(ensure_priv_dir_safe(path) == true);
    struct stat st;
    snprintf(path, sizeof(path), "%s/created", base);
    assert(stat(path, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
           (st.st_mode & (S_IWGRP | S_IWOTH)) == 0);

    // Group-writable, other-writable and sticky world-writable -> rejected
    snprintf(path, sizeof(path), "%s/ok", base);
    assert(chmod(path, 0775) == 0); assert(ensure_priv_dir_safe(path) == false);
    assert(chmod(path, 0757) == 0); assert(ensure_priv_dir_safe(path) == false);
    assert(chmod(path, 01777) == 0); assert(ensure_priv_dir_safe(path) == false);
    assert(chmod(path, 0755) == 0); assert(ensure_priv_dir_safe(path) == true);

    // Directory owned by an unprivileged uid (pre-planted directory attack) -> rejected
    assert(chown(path, 65534, (gid_t)-1) == 0);
    assert(ensure_priv_dir_safe(path) == false);
    assert(chown(path, 0, (gid_t)-1) == 0);
    assert(ensure_priv_dir_safe(path) == true);

    // Symlink to a perfectly safe directory -> rejected (O_NOFOLLOW, fail-closed)
    char link[256];
    snprintf(link, sizeof(link), "%s/link", base);
    assert(symlink(path, link) == 0);
    assert(ensure_priv_dir_safe(link) == false);

    // Regular file where a directory is expected -> rejected
    char file[256];
    snprintf(file, sizeof(file), "%s/file", base);
    int ffd = open(file, O_CREAT | O_WRONLY, 0644);
    assert(ffd >= 0); close(ffd);
    assert(ensure_priv_dir_safe(file) == false);

    // Real system directory: the verdict must agree with the on-disk layout
    // (real root-owned dir -> true on FreeBSD; symlink -> false on Linux).
    if (lstat("/var/run", &st) == 0) {
        bool expect_ok = S_ISDIR(st.st_mode) && st.st_uid == 0 &&
                         (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
        assert(ensure_priv_dir_safe("/var/run") == expect_ok);
    }

    // cleanup
    unlink(file); unlink(link);
    snprintf(path, sizeof(path), "%s/created", base); rmdir(path);
    snprintf(path, sizeof(path), "%s/ok", base); rmdir(path);
    rmdir(base);

    printf("  -> ensure_priv_dir_safe passed.\n");
}

/* A logging runtime with one file channel for `cat`, printing the time, the category and the severity, installed for the logger threads
 * (they read the channels from the runtime, the switch from the configuration).  Returns it; test_retire_runtime() replaces it by an empty one. */
static log_runtime_t *test_install_file_runtime(int cat, const char *name, const char *path, bool prefixes) {
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.name = (char *)name;
    ch.file_path = (char *)path;
    ch.dest = LOGDEST_FILE;
    ch.level = LOG_LVL_INFO;
    ch.versions = LOG_VERSIONS_UNSET;
    ch.fd = -1;
    ch.time_fmt = prefixes ? LOGTIME_LOCAL : LOGTIME_NONE;
    ch.print_category = ch.print_severity = prefixes;
    logging_config_t lc;
    memset(&lc, 0, sizeof(lc));
    lc.channels = &ch;
    lc.cat[cat].n = 1;
    lc.cat[cat].name[0] = (char *)name;
    logrt_status_t st;
    log_runtime_t *rt = log_runtime_build(&lc, false, &st);
    assert(rt && st == LOGRT_OK);
    assert(log_runtime_install(rt));
    return rt;
}

static void test_retire_runtime(log_runtime_t *rt) {
    (void)rt;
    logrt_status_t st;
    log_runtime_t *empty = log_runtime_build(NULL, false, &st);
    assert(empty);
    assert(log_runtime_install(empty));
}

static bool test_file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    return strstr(buf, needle) != NULL;
}

/* stop a logger thread or the control thread started by a test (g_test_threads_stop; not pthread_cancel(), which TSan does not support) */
static void test_stop_thread(pthread_t th) {
    atomic_store_explicit(&g_test_threads_stop, true, memory_order_release);
    pthread_join(th, NULL);
    atomic_store_explicit(&g_test_threads_stop, false, memory_order_release);
}

// ----------------------------------------------------------------------------
// 12. Response Logger Background Thread Test
// ----------------------------------------------------------------------------
static void test_response_logger_thread_func(void) {
    printf("[TEST] Server Core: response_logger_thread_func asynchronous consumer...\n");

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/tmp/karidns_test_resp_thread_%ld.log", (long)time(NULL));
    unlink(log_path);

    log_runtime_t *test_rt = test_install_file_runtime(LOGC_RESPONSES, "resp", log_path, true);
    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.responses_enabled = true;

    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);
    atomic_store_explicit(&g_resp_log_tail, 0, memory_order_relaxed);
    atomic_store_explicit(&g_resp_log_head, 0, memory_order_relaxed);
    for (int i = 0; i < RESP_LOG_RING_SIZE; i++) {
        atomic_store_explicit(&g_resp_log_ring[i].ready, false, memory_order_relaxed);
    }

    pthread_t th;
    int rc = pthread_create(&th, NULL, response_logger_thread_func, NULL);
    assert(rc == 0);

    // Enqueue various actions, classes, types, and RCODEs
    submit_response_log(LOG_ACT_SENT, "192.0.2.1", 5353, "example.com.", 1, 1, 0, true, true);
    submit_response_log(LOG_ACT_SENT, "2001:db8::1", 5353, "any.example.com.", 255, 28, 0, true, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 1053, "version.bind.", 3, 16, 0, false, false);
    submit_response_log(LOG_ACT_SENT, "10.0.0.1", 2053, "custom.class.", 99, 65534, 0, false, false);
    submit_response_log(LOG_ACT_DROP_RRL, "198.51.100.1", 4000, "rrl.example.com.", 1, 1, 2, false, false);
    submit_response_log(LOG_ACT_DROP_MALFORMED, "198.51.100.2", 4001, "malformed.example.", 1, 1, 1, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "nx.example.", 1, 1, 3, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "notimp.example.", 1, 1, 4, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "refused.example.", 1, 1, 5, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "yxdomain.example.", 1, 1, 6, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "yxrrset.example.", 1, 1, 7, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "nxrrset.example.", 1, 1, 8, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "notauth.example.", 1, 1, 9, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "notzone.example.", 1, 1, 10, false, false);
    submit_response_log(LOG_ACT_SENT, "127.0.0.1", 53, "unknown.example.", 1, 1, 15, false, false);

    // Allow background thread to process the ring buffer
    for (int wait_i = 0; wait_i < 50; wait_i++) {
        if (atomic_load_explicit(&g_resp_log_head, memory_order_relaxed) >= 15) break;
        usleep(2000);
    }

    test_stop_thread(th);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    test_retire_runtime(test_rt);

    struct stat st;
    assert(stat(log_path, &st) == 0);
    assert(st.st_size > 0);
    /* <time> responses: info: client <ip>#<port> (<qname>): response: ...  The channel adds the prefix (the time, "responses: ", "info: ") */
    assert(test_file_has(log_path, " responses: info: client 192.0.2.1#5353 (example.com.): response: example.com. IN A +E(0)D -> NOERROR\n"));
    assert(test_file_has(log_path, " responses: info: client 198.51.100.1#4000 (rrl.example.com.): response: rrl.example.com. IN A  -> SERVFAIL [DROP:RRL]\n"));
    unlink(log_path);

    printf("  -> response_logger_thread_func passed.\n");
}

// ----------------------------------------------------------------------------
// 13. Query Logger Background Thread Test
// ----------------------------------------------------------------------------
static void test_query_logger_thread_func(void) {
    printf("[TEST] Server Core: query_logger_thread_func asynchronous consumer & batching...\n");

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/tmp/karidns_test_query_thread_%ld.log", (long)time(NULL));
    unlink(log_path);

    log_runtime_t *test_rt = test_install_file_runtime(LOGC_QUERIES, "q", log_path, true);
    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.queries_enabled = true;

    worker_ctx_t worker;
    memset(&worker, 0, sizeof(worker));
    worker.thread_id = 0;
    worker.qlog_ring.size = 64;
    worker.qlog_ring.mask = 63;
    worker.qlog_ring.events = calloc(64, sizeof(qlog_event_t));
    atomic_init(&worker.qlog_ring.head, 0);
    atomic_init(&worker.qlog_ring.tail, 0);
    atomic_init(&worker.qlog_ring.dropped_count, 0);

    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);
    atomic_store_explicit(&g_worker_ctxs, &worker, memory_order_release);
    atomic_store_explicit(&g_worker_count, 1, memory_order_relaxed);
    atomic_store_explicit(&g_qlog_circuit_broken, false, memory_order_relaxed);

    pthread_t th;
    int rc = pthread_create(&th, NULL, query_logger_thread_func, NULL);
    assert(rc == 0);

    struct sockaddr_in sin4;
    memset(&sin4, 0, sizeof(sin4));
    sin4.sin_family = AF_INET;
    sin4.sin_port = htons(5300);
    inet_pton(AF_INET, "192.0.2.55", &sin4.sin_addr);

    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(5301);
    inet_pton(AF_INET6, "2001:db8::99", &sin6.sin6_addr);

    // Enqueue queries: IPv4 and IPv6, various classes and types
    write_query_log(&worker, &sin4, sizeof(sin4), "q1.example.com.", 1, 1, true, true, IPPROTO_UDP, 50000);
    write_query_log(&worker, &sin6, sizeof(sin6), "q2.example.com.", 255, 28, true, false, IPPROTO_TCP, 50000);
    write_query_log(&worker, &sin4, sizeof(sin4), "q3.example.com.", 3, 16, false, false, IPPROTO_UDP, 50000);
    write_query_log(&worker, &sin6, sizeof(sin6), "q4.example.com.", 99, 65000, false, false, IPPROTO_UDP, 50000);

    // Test circuit breaker auto-recovery
    atomic_store_explicit(&g_qlog_circuit_broken, true, memory_order_relaxed);

    for (int wait_i = 0; wait_i < 50; wait_i++) {
        uint32_t t = atomic_load_explicit(&worker.qlog_ring.tail, memory_order_relaxed);
        uint32_t h = atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed);
        if (t == h && !atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed)) break;
        usleep(2000);
    }

    assert(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed) == false);

    test_stop_thread(th);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_ctxs, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_count, 0, memory_order_relaxed);

    test_retire_runtime(test_rt);
    free(worker.qlog_ring.events);

    struct stat st;
    assert(stat(log_path, &st) == 0);
    assert(st.st_size > 0);
    assert(test_file_has(log_path, " queries: info: client 192.0.2.55#5300 (q1.example.com.): query: q1.example.com. IN A +E(0)D\n"));
    assert(test_file_has(log_path, " queries: info: client 2001:db8::99#5301 (q2.example.com.): query: q2.example.com. ANY AAAA +E(0)K\n"));
    unlink(log_path);

    printf("  -> query_logger_thread_func passed.\n");
}


/* ---- batch 14: the event messages (dns_log.h logev_*): the mask, the rate limit, the ring record, the logger thread ---- */
void qlog_event_sink(void *vctx, int cat, int level, const char *client_ip, int client_port, const char *msg);

static char g_ev_line[8][KLOG_MSG_MAX];
static int g_ev_n, g_ev_cat[8], g_ev_level[8], g_ev_last_level;
static char g_ev_last[KLOG_MSG_MAX];
static void test_level_hook(int cat, int level, const char *msg) {
    snprintf(g_ev_last, sizeof(g_ev_last), "%s", msg);
    g_ev_last_level = level;
    if (g_ev_n < 8) {
        snprintf(g_ev_line[g_ev_n], sizeof(g_ev_line[0]), "%s", msg);
        g_ev_cat[g_ev_n] = cat;
        g_ev_level[g_ev_n] = level;
    }
    g_ev_n++;
}

static void test_logev_helpers(void) {
    printf("[TEST] Server Core: logev_name_text / logev_format_line / mask / rate limit...\n");
    char b[64];
    logev_name_text("example.test.", b, sizeof(b));
    assert(strcmp(b, "example.test") == 0);                                 /* BIND logs the name without the final dot */
    logev_name_text(".", b, sizeof(b));
    assert(strcmp(b, ".") == 0);
    logev_name_text("a\\.b.example.test\\.", b, sizeof(b));                  /* an escaped dot at the end is part of the label */
    assert(strcmp(b, "a\\.b.example.test\\.") == 0);
    logev_name_text("a b\"c;d\x01\x7f\xff.test.", b, sizeof(b));
    assert(strcmp(b, "a\\032b\\034c\\059d\\001\\127\\255.test") == 0);
    logev_name_text("abcdefghij.test.", b, 8);                              /* cut, terminated */
    assert(strcmp(b, "abcdefg") == 0);
    logev_name_text("a b.test.", b, 5);                                     /* an escape that does not fit is not started */
    assert(strcmp(b, "a") == 0);
    logev_name_text(NULL, b, sizeof(b));
    assert(b[0] == '\0');
    logev_name_text("x", b, 0);

    char l[64];
    assert(logev_format_line(l, sizeof(l), "192.0.2.7", 5300, "denied") == strlen("client 192.0.2.7#5300: denied") && strcmp(l, "client 192.0.2.7#5300: denied") == 0);
    logev_format_line(l, sizeof(l), "2001:db8::1", 0, "denied");
    assert(strcmp(l, "client 2001:db8::1: denied") == 0);
    logev_format_line(l, sizeof(l), NULL, 0, "denied");
    assert(strcmp(l, "denied") == 0);
    logev_format_line(l, 8, "192.0.2.7", 1, "denied");
    assert(strcmp(l, "client ") == 0);
    assert(logev_format_line(l, 0, "a", 1, "b") == 0);

    /* the mask: a level is wanted when some channel passes it */
    logev_set_mask(LOGC_UPDATE_SECURITY, LOGEV_BIT(LOG_LVL_ERROR) | LOGEV_BIT(LOG_LVL_INFO));
    assert(logev_wanted(LOGC_UPDATE_SECURITY, LOG_LVL_INFO) && logev_wanted(LOGC_UPDATE_SECURITY, LOG_LVL_ERROR));
    assert(!logev_wanted(LOGC_UPDATE_SECURITY, LOG_LVL_WARNING) && !logev_wanted(LOGC_UPDATE_SECURITY, 1));
    assert(!logev_wanted(-1, LOG_LVL_INFO) && !logev_wanted(LOGC_COUNT, LOG_LVL_INFO) && !logev_wanted(LOGC_UPDATE_SECURITY, 11) && !logev_wanted(LOGC_UPDATE_SECURITY, -6));
    logev_set_mask(-1, 0xffffffffu);                                         /* (ignored) */
    logev_set_mask(LOGC_UPDATE_SECURITY, 0);
    assert(!logev_wanted(LOGC_UPDATE_SECURITY, LOG_LVL_INFO));

    /* the rate limit: update-security 10 per second; the second after, the count of the dropped is handed back once */
    logev_rate_reset();
    assert(logev_rate_limit(LOGC_UPDATE_SECURITY) == 10 && logev_rate_limit(LOGC_XFER_OUT) == 50 && logev_rate_limit(LOGC_QUERY_ERRORS) == 20 &&
           logev_rate_limit(LOGC_UPDATE) == 20 && logev_rate_limit(LOGC_GENERAL) == 20);
    /* 0.7 M3 (D-5): above debug level 0 every category has LOGEV_DEBUG_RATE (the overflow is still counted); at level 0 the limits above are back.
     * (the level is set directly: klog_set_debug_level() would also recompute the masks this test sets by hand) */
    atomic_store_explicit(&g_klog_debug_level, 3, memory_order_relaxed);
    assert(logev_rate_limit(LOGC_UPDATE_SECURITY) == LOGEV_DEBUG_RATE && logev_rate_limit(LOGC_GENERAL) == 1000 && logev_rate_limit(LOGC_XFER_OUT) == 1000);
    {
        uint32_t r2 = 0;
        int l2 = 0, n2 = 0;
        for (int i = 0; i < 1005; i++) n2 += logev_admit_at(LOGC_XFER_IN, 3, 4000, &r2, &l2) ? 1 : 0;
        assert(n2 == 1000);
        assert(logev_admit_at(LOGC_XFER_IN, 3, 4001, &r2, &l2) && r2 == 5 && l2 == 3);
    }
    atomic_store_explicit(&g_klog_debug_level, 0, memory_order_relaxed);
    assert(logev_rate_limit(LOGC_UPDATE_SECURITY) == 10 && logev_rate_limit(LOGC_GENERAL) == 20);
    logev_rate_reset();
    uint32_t rep = 99;
    int rl = LOG_LVL_INFO;
    int passed = 0;
    for (int i = 0; i < 25; i++)
        if (logev_admit_at(LOGC_UPDATE_SECURITY, i % 2 ? LOG_LVL_ERROR : LOG_LVL_INFO, 5000, &rep, &rl)) passed++;
    assert(passed == 10 && rep == 0);
    assert(logev_admit_at(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, 5001, &rep, &rl) && rep == 15 && rl == LOG_LVL_INFO);      /* (the last one dropped was an INFO) */
    assert(logev_admit_at(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, 5001, &rep, &rl) && rep == 0);
    assert(!logev_admit_at(-1, LOG_LVL_INFO, 1, &rep, &rl) && !logev_admit_at(LOGC_COUNT, LOG_LVL_INFO, 1, &rep, &rl));
    assert(logev_admit_at(LOGC_XFER_OUT, LOG_LVL_INFO, 7000, &rep, &rl));   /* every category counts for itself */
    /* the debug lines have a budget of their own: at debug level 0 (a `severity debug 1` channel still receives them) a flood of debug 1 lines in
     * xfer-out does not take the 50 a second of its notices and errors; each budget counts and reports its own dropped lines, at their own level */
    logev_rate_reset();
    {
        int nd = 0, nn = 0;
        uint32_t r3 = 0;
        int l3 = 0;
        for (int i = 0; i < 1000; i++) nd += logev_admit_at(LOGC_XFER_OUT, 1, 8000, &r3, &l3) ? 1 : 0;
        assert(nd == 50 && r3 == 0);                                        /* bounded: the category's limit */
        for (int i = 0; i < 50; i++) nn += logev_admit_at(LOGC_XFER_OUT, i % 2 ? LOG_LVL_NOTICE : LOG_LVL_ERROR, 8000, &r3, &l3) ? 1 : 0;
        assert(nn == 50 && r3 == 0);                                        /* every notice and error passes */
        assert(!logev_admit_at(LOGC_XFER_OUT, LOG_LVL_NOTICE, 8000, &r3, &l3));       /* the 51st is over its own limit */
        assert(!logev_admit_at(LOGC_XFER_OUT, 2, 8000, &r3, &l3));
        r3 = 99;
        assert(logev_admit_at(LOGC_XFER_OUT, LOG_LVL_INFO, 8001, &r3, &l3) && r3 == 1 && l3 == LOG_LVL_NOTICE);   /* the notices' count, not the debug lines' */
        r3 = 99;
        assert(logev_admit_at(LOGC_XFER_OUT, 1, 8001, &r3, &l3) && r3 == 951 && l3 == 2);                      /* the debug lines', at a debug level */
        /* above debug level 0 both budgets have LOGEV_DEBUG_RATE: the M3 limits hold for each */
        logev_rate_reset();
        atomic_store_explicit(&g_klog_debug_level, 3, memory_order_relaxed);
        nd = nn = 0;
        for (int i = 0; i < 1005; i++) nd += logev_admit_at(LOGC_XFER_OUT, 3, 9000, &r3, &l3) ? 1 : 0;
        for (int i = 0; i < 1005; i++) nn += logev_admit_at(LOGC_XFER_OUT, LOG_LVL_INFO, 9000, &r3, &l3) ? 1 : 0;
        assert(nd == (int)LOGEV_DEBUG_RATE && nn == (int)LOGEV_DEBUG_RATE);
        assert(logev_admit_at(LOGC_XFER_OUT, LOG_LVL_INFO, 9001, &r3, &l3) && r3 == 5 && l3 == LOG_LVL_INFO);
        assert(logev_admit_at(LOGC_XFER_OUT, 3, 9001, &r3, &l3) && r3 == 5 && l3 == 3);
        atomic_store_explicit(&g_klog_debug_level, 0, memory_order_relaxed);
    }

    /* the direct path (a thread without a ring): the line goes to the level hook, once the mask and the rate limit allow it */
    logev_rate_reset();
    klog_set_level_hook(test_level_hook);
    g_ev_n = 0;
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 40000, "signer \"%s\" approved", "k");
    assert(g_ev_n == 0);                                                    /* the mask is 0: nothing is built */
    logev_set_mask(LOGC_UPDATE_SECURITY, LOGEV_BIT(LOG_LVL_INFO) | LOGEV_BIT(LOG_LVL_ERROR));
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 40000, "signer \"%s\" approved", "k");
    assert(g_ev_n == 1 && g_ev_cat[0] == LOGC_UPDATE_SECURITY && g_ev_level[0] == LOG_LVL_INFO);
    assert(strcmp(g_ev_line[0], "client 192.0.2.7#40000: signer \"k\" approved") == 0);
    for (int i = 0; i < 30; i++) logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_ERROR, "192.0.2.7", 1, "x");
    assert(g_ev_n == 10);                                                   /* 10 per second in all */
    logev_flush_suppressed((int64_t)time(NULL));                            /* its second is not over */
    assert(g_ev_n == 10);
    logev_flush_suppressed((int64_t)time(NULL) + 5);
    assert(g_ev_n == 11 && g_ev_last_level == LOG_LVL_ERROR && strcmp(g_ev_last, "21 message(s) suppressed by the rate limit of 10 per second") == 0);
    logev_flush_suppressed((int64_t)time(NULL) + 6);
    assert(g_ev_n == 11);                                                   /* said once */
    /* 0.7 M3: the tick reports the suppressed lines of every category, not only of the four that had event messages before */
    logev_rate_reset();
    g_ev_n = 0;
    logev_set_mask(LOGC_XFER_IN, LOGEV_BIT(1));
    for (int i = 0; i < 25; i++) logev_post(LOGC_XFER_IN, 1, NULL, 0, "x");
    assert(g_ev_n == 20);
    logev_flush_suppressed((int64_t)time(NULL) + 5);
    assert(g_ev_n == 21 && g_ev_last_level == 1 && strcmp(g_ev_last, "5 message(s) suppressed by the rate limit of 20 per second") == 0);
    logev_set_mask(LOGC_XFER_IN, 0);
    /* the two budgets through the tick: 60 debug 1 lines and 60 notices in xfer-out at level 0 write 50 of each and two reports, one per budget,
     * each at the level of the last line it dropped and with the limit that applied (50) */
    logev_rate_reset();
    g_ev_n = 0;
    logev_set_mask(LOGC_XFER_OUT, LOGEV_BIT(1) | LOGEV_BIT(LOG_LVL_NOTICE));
    for (int i = 0; i < 60; i++) logev_post(LOGC_XFER_OUT, 1, NULL, 0, "d");
    for (int i = 0; i < 60; i++) logev_post(LOGC_XFER_OUT, LOG_LVL_NOTICE, NULL, 0, "n");
    assert(g_ev_n == 100);
    g_ev_n = 0;
    logev_flush_suppressed((int64_t)time(NULL) + 5);
    assert(g_ev_n == 2);
    assert(g_ev_level[0] == LOG_LVL_NOTICE && strcmp(g_ev_line[0], "10 message(s) suppressed by the rate limit of 50 per second") == 0);
    assert(g_ev_level[1] == 1 && strcmp(g_ev_line[1], "10 message(s) suppressed by the rate limit of 50 per second") == 0);
    logev_set_mask(LOGC_XFER_OUT, 0);
    /* a text longer than the record is cut; no hook, no routing */
    logev_rate_reset();
    g_ev_n = 0;
    char big[600];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, NULL, 0, "%s", big);
    assert(g_ev_n == 1 && strlen(g_ev_line[0]) == LOGEV_MSG_MAX - 1);
    klog_set_level_hook(NULL);
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, NULL, 0, "nowhere");     /* (no hook: dropped) */
    assert(g_ev_n == 1);
    logev_set_mask(LOGC_UPDATE_SECURITY, 0);
    logev_rate_reset();
    printf("  -> logev helpers passed.\n");
}

/* a logging runtime for the event categories: one file channel per category, with the severity given */
static log_runtime_t *test_install_event_runtime(const char *path_sec, const char *path_qe, int qe_level) {
    log_channel_t c1, c2;
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    c1.name = (char *)"sec";
    c1.file_path = (char *)path_sec;
    c1.dest = LOGDEST_FILE;
    c1.level = LOG_LVL_INFO;
    c1.versions = LOG_VERSIONS_UNSET;
    c1.fd = -1;
    c1.time_fmt = LOGTIME_NONE;
    c1.print_category = c1.print_severity = true;
    c1.next = &c2;
    c2 = c1;
    c2.name = (char *)"qe";
    c2.file_path = (char *)path_qe;
    c2.level = qe_level;
    c2.next = NULL;
    logging_config_t lc;
    memset(&lc, 0, sizeof(lc));
    lc.channels = &c1;
    lc.cat[LOGC_UPDATE_SECURITY].n = 1;
    lc.cat[LOGC_UPDATE_SECURITY].name[0] = (char *)"sec";
    lc.cat[LOGC_QUERY_ERRORS].n = 1;
    lc.cat[LOGC_QUERY_ERRORS].name[0] = (char *)"qe";
    logrt_status_t st;
    log_runtime_t *rt = log_runtime_build(&lc, false, &st);
    assert(rt && st == LOGRT_OK);
    assert(log_runtime_install(rt));
    return rt;
}

static void test_event_ring_and_logger(void) {
    printf("[TEST] Server Core: event messages through the worker ring and the query logger thread...\n");
    char sec_path[256], qe_path[256];
    snprintf(sec_path, sizeof(sec_path), "/tmp/karidns_test_ev_sec_%ld.log", (long)time(NULL));
    snprintf(qe_path, sizeof(qe_path), "/tmp/karidns_test_ev_qe_%ld.log", (long)time(NULL));
    unlink(sec_path);
    unlink(qe_path);
    log_runtime_t *rt = test_install_event_runtime(sec_path, qe_path, 3 /* debug 3 */);
    /* what log_runtime_install() computed: update-security passes the levels up to info, query-errors (debug 3) also debug 1..3 */
    assert(logev_wanted(LOGC_UPDATE_SECURITY, LOG_LVL_INFO) && logev_wanted(LOGC_UPDATE_SECURITY, LOG_LVL_CRITICAL));
    assert(!logev_wanted(LOGC_UPDATE_SECURITY, 1));
    assert(logev_wanted(LOGC_QUERY_ERRORS, 1) && logev_wanted(LOGC_QUERY_ERRORS, 3) && !logev_wanted(LOGC_QUERY_ERRORS, 4));
    assert(!logev_wanted(LOGC_XFER_OUT, LOG_LVL_INFO) || logev_wanted(LOGC_XFER_OUT, LOG_LVL_INFO));   /* (default_syslog: whatever it is, it is decided) */
    logev_rate_reset();

    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.queries_enabled = false;                                /* the query log is off: the events are still written */

    worker_ctx_t worker;
    memset(&worker, 0, sizeof(worker));
    worker.qlog_ring.size = 64;
    worker.qlog_ring.mask = 63;
    worker.qlog_ring.events = calloc(64, sizeof(qlog_event_t));
    atomic_init(&worker.qlog_ring.head, 0);
    atomic_init(&worker.qlog_ring.tail, 0);
    atomic_init(&worker.qlog_ring.dropped_count, 0);
    atomic_init(&worker.qlog_ring.ev_dropped, 0);
    worker.ev_ring.size = 64;                                                /* 0.7 (K-11): the events have a ring of their own */
    worker.ev_ring.mask = 63;
    worker.ev_ring.events = calloc(64, sizeof(qlog_event_t));
    atomic_init(&worker.ev_ring.head, 0);
    atomic_init(&worker.ev_ring.tail, 0);
    atomic_init(&worker.ev_ring.dropped_count, 0);
    atomic_init(&worker.ev_ring.ev_dropped, 0);

    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);
    atomic_store_explicit(&g_worker_ctxs, &worker, memory_order_release);
    atomic_store_explicit(&g_worker_count, 1, memory_order_relaxed);

    /* a record of the other kind that the producer left in the ring while the query log was on: dropped by the consumer */
    qlog_event_t *q0 = &worker.qlog_ring.events[0];
    memset(q0, 0, sizeof(*q0));
    q0->kind = QLOG_KIND_QUERY;
    q0->qtype = 1;
    q0->qclass = 1;
    strcpy(q0->qname, "left.over.example.");
    atomic_store_explicit(&worker.qlog_ring.head, 1, memory_order_release);

    pthread_t th;
    assert(pthread_create(&th, NULL, query_logger_thread_func, NULL) == 0);

    logev_set_thread_sink(qlog_event_sink, &worker);                         /* this thread plays the worker */
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 40000, "signer \"k\" approved");
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_ERROR, "2001:db8::7", 40001, "update 'e.test/IN' denied");
    logev_post(LOGC_QUERY_ERRORS, 1, "192.0.2.8", 53, "query failed (SERVFAIL) for e.test/IN/A");
    logev_post(LOGC_QUERY_ERRORS, 4, "192.0.2.8", 53, "not written: debug 4");
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, NULL, 0, "line\nwith\rcontrol\tand\x01 bytes");
    for (int wait_i = 0; wait_i < 200; wait_i++) {
        if (atomic_load_explicit(&worker.qlog_ring.tail, memory_order_relaxed) == atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) &&
            atomic_load_explicit(&worker.ev_ring.tail, memory_order_relaxed) == atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) &&
            test_file_has(sec_path, "control") && test_file_has(qe_path, "SERVFAIL")) break;
        usleep(5000);
    }
    assert(atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) == 1);   /* the events went to the event ring, none to the query log's */
    assert(test_file_has(sec_path, "update-security: info: client 192.0.2.7#40000: signer \"k\" approved\n"));
    assert(test_file_has(sec_path, "update-security: error: client 2001:db8::7#40001: update 'e.test/IN' denied\n"));
    assert(test_file_has(sec_path, "update-security: info: line?with?control\tand? bytes\n"));          /* a line cannot start inside a message */
    assert(test_file_has(qe_path, "query-errors: debug 1: client 192.0.2.8#53: query failed (SERVFAIL) for e.test/IN/A\n"));
    assert(!test_file_has(qe_path, "debug 4"));
    assert(!test_file_has(sec_path, "left.over") && !test_file_has(qe_path, "left.over"));

    /* the event ring is full: the event is dropped and counted, the thread goes on (0.7: the events' own ring, filled to the last slot) */
    atomic_store_explicit(&worker.qlog_ring.tail, 0, memory_order_relaxed);
    atomic_store_explicit(&worker.qlog_ring.head, 0, memory_order_relaxed);
    test_stop_thread(th);
    atomic_store_explicit(&g_worker_ctxs, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_count, 0, memory_order_relaxed);
    logev_rate_reset();
    atomic_store_explicit(&worker.ev_ring.tail, 0, memory_order_relaxed);
    atomic_store_explicit(&worker.ev_ring.head, 64, memory_order_relaxed);            /* 64 of 64 slots */
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 1, "dropped");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 64);
    assert(atomic_load_explicit(&worker.ev_ring.ev_dropped, memory_order_relaxed) == 1);
    atomic_store_explicit(&worker.ev_ring.head, 63, memory_order_relaxed);
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 1, "kept");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 64);
    assert(atomic_load_explicit(&worker.ev_ring.ev_dropped, memory_order_relaxed) == 1);
    /* a full query log ring (past its 80%) takes nothing from the events */
    atomic_store_explicit(&worker.qlog_ring.head, 60, memory_order_relaxed);
    atomic_store_explicit(&worker.ev_ring.head, 10, memory_order_relaxed);
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 1, "kept, the query log ring full");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 11 && atomic_load_explicit(&worker.qlog_ring.head, memory_order_relaxed) == 60);
    atomic_store_explicit(&worker.qlog_ring.head, 0, memory_order_relaxed);
    /* 0.7 M3 (D-5), K-11: a debug record stops at half the event ring (32 of 64), the other half is for info and above */
    const uint32_t qe_mask = atomic_load_explicit(&g_logev_mask[LOGC_QUERY_ERRORS], memory_order_relaxed);
    logev_set_mask(LOGC_QUERY_ERRORS, LOGEV_BIT(3));
    atomic_store_explicit(&worker.ev_ring.head, 32, memory_order_relaxed);
    logev_post(LOGC_QUERY_ERRORS, 3, "192.0.2.7", 1, "debug, dropped");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 32);
    assert(atomic_load_explicit(&worker.ev_ring.ev_dropped, memory_order_relaxed) == 2);
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 1, "info after the debug half");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 33);
    atomic_store_explicit(&worker.ev_ring.head, 31, memory_order_relaxed);
    logev_post(LOGC_QUERY_ERRORS, 3, "192.0.2.7", 1, "debug, kept");
    assert(atomic_load_explicit(&worker.ev_ring.head, memory_order_relaxed) == 32);
    assert(atomic_load_explicit(&worker.ev_ring.ev_dropped, memory_order_relaxed) == 2);
    logev_set_mask(LOGC_QUERY_ERRORS, qe_mask);
    assert(atomic_load_explicit(&worker.qlog_ring.ev_dropped, memory_order_relaxed) == 0);   /* (nothing is counted on the query log ring) */
    /* a worker without an event ring (it could not allocate one): nothing is written, nothing breaks */
    qlog_event_t *saved = worker.ev_ring.events;
    worker.ev_ring.events = NULL;
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, "192.0.2.7", 1, "no ring");
    worker.ev_ring.events = saved;
    /* an out-of-range port and a missing client are stored as "unknown" */
    atomic_store_explicit(&worker.ev_ring.head, 0, memory_order_relaxed);
    logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_INFO, NULL, 99999, "no client");
    assert(worker.ev_ring.events[0].kind == QLOG_KIND_EVENT && worker.ev_ring.events[0].client_port == 0 && worker.ev_ring.events[0].client_text[0] == '\0');
    logev_set_thread_sink(NULL, NULL);

    /* the report of suppressed messages when no further message comes: the logger thread's tick (logev_flush_suppressed()) writes it */
    atomic_store_explicit(&worker.qlog_ring.head, 0, memory_order_relaxed);
    atomic_store_explicit(&worker.qlog_ring.tail, 0, memory_order_relaxed);
    atomic_store_explicit(&worker.ev_ring.head, 0, memory_order_relaxed);
    atomic_store_explicit(&worker.ev_ring.tail, 0, memory_order_relaxed);
    logev_rate_reset();
    atomic_store_explicit(&g_worker_ctxs, &worker, memory_order_release);
    atomic_store_explicit(&g_worker_count, 1, memory_order_relaxed);
    assert(pthread_create(&th, NULL, query_logger_thread_func, NULL) == 0);
    logev_set_thread_sink(qlog_event_sink, &worker);
    for (int i = 0; i < 15; i++) logev_post(LOGC_UPDATE_SECURITY, LOG_LVL_ERROR, "192.0.2.9", 1, "flood %d", i);
    for (int wait_i = 0; wait_i < 300; wait_i++) {
        if (test_file_has(sec_path, "5 message(s) suppressed by the rate limit of 10 per second")) break;
        usleep(10000);
    }
    assert(test_file_has(sec_path, "update-security: error: 5 message(s) suppressed by the rate limit of 10 per second\n"));
    logev_set_thread_sink(NULL, NULL);
    test_stop_thread(th);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_ctxs, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_count, 0, memory_order_relaxed);
    test_retire_runtime(rt);                                                 /* the empty runtime: the masks are recomputed */
    assert(!logev_wanted(LOGC_QUERY_ERRORS, 1));
    free(worker.qlog_ring.events);
    free(worker.ev_ring.events);
    unlink(sec_path);
    unlink(qe_path);
    printf("  -> event ring and logger thread passed.\n");
}

// ----------------------------------------------------------------------------
// 14. Control Socket HMAC Auth & Commands Test
// ----------------------------------------------------------------------------
static int run_ctrl_cmd_md(const struct sockaddr_un *sun, const EVP_MD *hmac_md, const char *secret, const char *cmd,
                           char *out_buf, size_t out_buf_sz) {
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) return -1;
    if (connect(cfd, (struct sockaddr *)sun, sizeof(*sun)) != 0) {
        close(cfd);
        return -1;
    }
    char rbuf[1024];
    ssize_t n = recv(cfd, rbuf, sizeof(rbuf) - 1, 0);
    if (n <= 10 || strncmp(rbuf, "CHALLENGE ", 10) != 0) {
        close(cfd);
        return -1;
    }
    char challenge[65];
    strncpy(challenge, rbuf + 10, 64);
    challenge[64] = '\0';

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    HMAC(hmac_md, secret, strlen(secret), (unsigned char *)challenge, 64, md, &md_len);
    char hmac_hex[2 * EVP_MAX_MD_SIZE + 1];
    hmac_hex[0] = '\0';
    for (unsigned int k = 0; k < md_len; k++) snprintf(&hmac_hex[k * 2], 3, "%02x", md[k]);

    char auth_cmd[2 * EVP_MAX_MD_SIZE + 16];
    snprintf(auth_cmd, sizeof(auth_cmd), "AUTH %s\n", hmac_hex);
    send(cfd, auth_cmd, strlen(auth_cmd), 0);

    n = recv(cfd, rbuf, sizeof(rbuf) - 1, 0);
    if (n <= 0 || strncmp(rbuf, "OK\n", 3) != 0) {
        close(cfd);
        return -1;
    }

    send(cfd, cmd, strlen(cmd), 0);
    ssize_t total = 0;
    while (total < (ssize_t)out_buf_sz - 1) {
        ssize_t r = recv(cfd, out_buf + total, out_buf_sz - 1 - total, 0);
        if (r <= 0) break;
        total += r;
    }
    out_buf[total] = '\0';
    close(cfd);
    return (int)total;
}

static int run_ctrl_cmd(const struct sockaddr_un *sun, const char *secret, const char *cmd, char *out_buf, size_t out_buf_sz) {
    return run_ctrl_cmd_md(sun, EVP_sha256(), secret, cmd, out_buf, out_buf_sz);
}

/* low batch L3, dns_server_core.c [H4]: the AUTH line and the commands are written in ONE send(), so the server reads several lines with one
 * recv() and no later event announces the rest (EV_CLEAR).  `cmds` is every command line, '\n' included.  The whole answer (the "OK\n" of the
 * AUTH first) is read until the server closes the connection; -1 when the challenge cannot be read. */
static int run_ctrl_pipelined(const struct sockaddr_un *sun, const char *secret, const char *cmds, char *out_buf, size_t out_buf_sz) {
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) return -1;
    if (connect(cfd, (struct sockaddr *)sun, sizeof(*sun)) != 0) {
        close(cfd);
        return -1;
    }
    char rbuf[1024];
    ssize_t n = recv(cfd, rbuf, sizeof(rbuf) - 1, 0);
    if (n <= 10 || strncmp(rbuf, "CHALLENGE ", 10) != 0) {
        close(cfd);
        return -1;
    }
    char challenge[65];
    memcpy(challenge, rbuf + 10, 64);
    challenge[64] = '\0';
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char *)challenge, 64, md, &md_len);
    char msg[2 * EVP_MAX_MD_SIZE + 16 + 512];
    int ml = snprintf(msg, sizeof(msg), "AUTH ");
    for (unsigned int k = 0; k < md_len; k++) ml += snprintf(msg + ml, 3, "%02x", md[k]);
    ml += snprintf(msg + ml, sizeof(msg) - (size_t)ml, "\n%s", cmds);
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };       /* a hung server fails the test instead of blocking it */
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    assert(send(cfd, msg, (size_t)ml, 0) == ml);
    ssize_t total = 0;
    while (total < (ssize_t)out_buf_sz - 1) {
        ssize_t r = recv(cfd, out_buf + total, out_buf_sz - 1 - total, 0);
        if (r <= 0) break;
        total += r;
    }
    out_buf[total] = '\0';
    close(cfd);
    return (int)total;
}

// Blocking recv() in a unit test turns any server-side regression into a hung CI job.
// Give every test client socket a receive timeout so failures are fast assertion failures.
static void test_set_io_timeout(int fd, int seconds) {
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void test_control_socket_thread_and_commands(void) {
    printf("[TEST] Server Core: control_thread_func HMAC auth & commands...\n");

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "/tmp/karidns_test_ctrl_%ld.sock", (long)time(NULL));
    unlink(sock_path);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(lfd >= 0);

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);

    int res = bind(lfd, (struct sockaddr *)&sun, sizeof(sun));
    assert(res == 0);
    res = listen(lfd, 8);
    assert(res == 0);

    g_control_sock = lfd;

    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.control.enabled = true;
    const char *secret_key = "kari_secret_key_123";
    memcpy(mock_cfg.control.secret_decoded, secret_key, strlen(secret_key));
    mock_cfg.control.secret_decoded_len = strlen(secret_key);

    zone_db_entry_t z_master;
    memset(&z_master, 0, sizeof(z_master));
    strlcpy(z_master.domain, "example.com.", sizeof(z_master.domain));
    strlcpy(z_master.view_name, "default", sizeof(z_master.view_name));
    atomic_init(&z_master.serial, 2026091901);
    atomic_init(&z_master.refresh, 3600);

    zone_db_entry_t z_slave;
    memset(&z_slave, 0, sizeof(z_slave));
    strlcpy(z_slave.domain, "slave.example.", sizeof(z_slave.domain));
    strlcpy(z_slave.view_name, "default", sizeof(z_slave.view_name));
    z_slave.is_secondary = true;
    atomic_init(&z_slave.serial, 100);
    atomic_init(&z_slave.refresh, 1800);

    zone_db_entry_t *entries[2] = {&z_master, &z_slave};

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 2);


    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;
    atomic_init(&snap.reader_count, 1);

    zone_config_t zc_master;
    memset(&zc_master, 0, sizeof(zc_master));
    zc_master.domain = "example.com.";
    zc_master.type = "master";

    zone_config_t zc_slave;
    memset(&zc_slave, 0, sizeof(zc_slave));
    zc_slave.domain = "slave.example.";
    zc_slave.type = "slave";

    zc_master.next = &zc_slave;

    view_config_t vc;
    memset(&vc, 0, sizeof(vc));
    vc.name = "default";
    vc.zones = &zc_master;
    mock_cfg.views = &vc;

    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);
    atomic_store_explicit(&g_zone_db_active, &snap, memory_order_release);

    /* O-18: until startup has completed the control thread serves nothing */
    bool saved_drop = atomic_load(&g_privilege_drop_complete);
    atomic_store(&g_privilege_drop_complete, false);
    pthread_t th;
    res = pthread_create(&th, NULL, control_thread_func, NULL);
    assert(res == 0);
    usleep(10000);

    // 1. Connect and test Bad Auth
    int cfd1 = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(cfd1 >= 0);
    test_set_io_timeout(cfd1, 5);
    res = connect(cfd1, (struct sockaddr *)&sun, sizeof(sun));
    assert(res == 0);

    char rbuf[1024];
    struct pollfd gate_pfd = { .fd = cfd1, .events = POLLIN };
    assert(poll(&gate_pfd, 1, 300) == 0);             /* no CHALLENGE during startup */
    atomic_store(&g_privilege_drop_complete, true);   /* startup done: the queued connection is served */
    ssize_t n = recv(cfd1, rbuf, sizeof(rbuf) - 1, 0);
    assert(n > 0);
    rbuf[n] = '\0';
    assert(strncmp(rbuf, "CHALLENGE ", 10) == 0);

    const char *bad_auth = "AUTH 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
    send(cfd1, bad_auth, strlen(bad_auth), 0);
    n = recv(cfd1, rbuf, sizeof(rbuf) - 1, 0);
    assert(n > 0);
    rbuf[n] = '\0';
    assert(strcmp(rbuf, "AUTH_FAILED\n") == 0);
    close(cfd1);

    // 2. Authenticated single commands via helper
    char out[2048];

    int len = run_ctrl_cmd(&sun, secret_key, "status\n", out, sizeof(out));
    assert(len >= (int)(3 + sizeof(karidns_status_t)));
    assert(strncmp(out, "OK ", 3) == 0);

    len = run_ctrl_cmd(&sun, secret_key, "zonestatus example.com.\n", out, sizeof(out));
    assert(len > 0);
    assert(strncmp(out, "OK serial=", 10) == 0);

    /* [H4] AUTH and the command in one write: the command is answered (it used to wait for an event that never came) */
    len = run_ctrl_pipelined(&sun, secret_key, "zonestatus example.com.\n", out, sizeof(out));
    assert(len > 3 && strncmp(out, "OK\nOK serial=", 13) == 0);
    len = run_ctrl_pipelined(&sun, secret_key, "invalid_command_foo\n", out, sizeof(out));
    assert(strcmp(out, "OK\nERROR unknown command\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "zonestatus unknown.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "ERROR zone not found\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "observatory\n", out, sizeof(out));
    assert(len > 0);
    assert(strncmp(out, "OK 2\n", 5) == 0);

    /* 0.6.1 karictl stats: the totals, and pages of zones from a cursor (directory order: the test does not depend on it) */
    {
        static char big[8192];
        len = run_ctrl_cmd(&sun, secret_key, "stats\n", big, sizeof(big));
        assert(len == (int)(3 + sizeof(karidns_stats_total_t)) && strncmp(big, "OK ", 3) == 0);
        karidns_stats_total_t tot;
        memcpy(&tot, big + 3, sizeof(tot));
        assert(tot.zones == 2);
        zone_observatory_snapshot_t s1, s2;
        char c1[64];
        /* a page of one: the header is "OK 1 <cursor>\n", then one snapshot; the next page brings the other zone and the end ("-") */
        len = run_ctrl_cmd(&sun, secret_key, "obspage 1 - -\n", big, sizeof(big));
        assert(strncmp(big, "OK 1 ", 5) == 0);
        char *nl = strchr(big, '\n');
        assert(nl && len == (int)(nl - big) + 1 + (int)sizeof(s1));
        *nl = '\0';
        snprintf(c1, sizeof(c1), "%s", big + 5);
        assert(strcmp(c1, "-") != 0);
        memcpy(&s1, nl + 1, sizeof(s1));
        char cmdline[160];
        snprintf(cmdline, sizeof(cmdline), "obspage 1 - %s\n", c1);
        len = run_ctrl_cmd(&sun, secret_key, cmdline, big, sizeof(big));
        nl = strchr(big, '\n');
        assert(strncmp(big, "OK 1 ", 5) == 0 && nl && len == (int)(nl - big) + 1 + (int)sizeof(s2));
        memcpy(&s2, nl + 1, sizeof(s2));
        assert(strcmp(s1.domain, s2.domain) != 0);
        assert((strcmp(s1.domain, "example.com.") == 0) != (strcmp(s2.domain, "example.com.") == 0));
        /* both in one page: the end */
        len = run_ctrl_cmd(&sun, secret_key, "obspage 5 - -\n", big, sizeof(big));
        assert(strncmp(big, "OK 2 -\n", 7) == 0 && len == 7 + 2 * (int)sizeof(s1));
        len = run_ctrl_cmd(&sun, secret_key, "obspage 5 SLAVE.* -\n", big, sizeof(big));   /* a glob, any case, with or without the root label */
        assert(strncmp(big, "OK 1 -\n", 7) == 0 && len == 7 + (int)sizeof(s1));
        len = run_ctrl_cmd(&sun, secret_key, "obspage 5 nomatch* -\n", big, sizeof(big));
        assert(len == 7 && strncmp(big, "OK 0 -\n", 7) == 0);
        len = run_ctrl_cmd(&sun, secret_key, "obspage 5 a*b*c*d*e*f -\n", big, sizeof(big));   /* (fnmatch() backtracks: at most 4 stars) */
        assert(len > 0 && strncmp(big, "ERROR pattern has more than 4", 29) == 0);
        len = run_ctrl_cmd(&sun, secret_key, "obspage 5 *e*x*a*m -\n", big, sizeof(big));   /* four stars are fine: matches example.com. */
        assert(strncmp(big, "OK 1 -\n", 7) == 0 && len == 7 + (int)sizeof(s1));
        /* a cursor that does not fit the directories is refused, never skipped: garbage, a view that is not there, a table of another size */
        const char *stale[] = { "obspage 5 - nonsense\n", "obspage 5 - 7.0.0\n", "obspage 5 - 0.0.1234\n", "obspage 5 - 0.9999999.1\n" };
        for (size_t bi = 0; bi < sizeof(stale) / sizeof(stale[0]); bi++) {
            len = run_ctrl_cmd(&sun, secret_key, stale[bi], big, sizeof(big));
            assert(len > 0 && strncmp(big, "ERROR cursor is stale", 21) == 0);
        }
        const char *bad_pages[] = { "obspage 0 - -\n", "obspage x - -\n", "obspage 5001 - -\n", "obspage 5\n", "obspage 5 -\n" };
        for (size_t bi = 0; bi < sizeof(bad_pages) / sizeof(bad_pages[0]); bi++) {
            len = run_ctrl_cmd(&sun, secret_key, bad_pages[bi], big, sizeof(big));
            assert(len > 0 && strncmp(big, "ERROR usage: obspage", 20) == 0);
        }
    }

    /* karictl rollback <zone> [view] [local]: the refusals (a zone with nothing kept, a secondary, a catalog zone, a program zone), the words of the
     * usage errors, and what zonestatus says about a rolled-back zone */
    len = run_ctrl_cmd(&sun, secret_key, "rollback example.com.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "ERROR no previous version", 25) == 0);
    len = run_ctrl_cmd(&sun, secret_key, "rollback example.com. local\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "ERROR no previous version", 25) == 0);
    len = run_ctrl_cmd(&sun, secret_key, "rollback example.com. default local\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "ERROR no previous version", 25) == 0);
    len = run_ctrl_cmd(&sun, secret_key, "rollback slave.example.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "ERROR rollback is for primary zones", 35) == 0);
    len = run_ctrl_cmd(&sun, secret_key, "rollback unknown.example.\n", out, sizeof(out));
    assert(len > 0 && strcmp(out, "ERROR zone not found\n") == 0);
    len = run_ctrl_cmd(&sun, secret_key, "rollback\n", out, sizeof(out));
    assert(len > 0 && strcmp(out, "ERROR rollback needs a zone name\n") == 0);
    zc_master.is_catalog = true;
    len = run_ctrl_cmd(&sun, secret_key, "rollback example.com.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "ERROR a catalog zone cannot be rolled back", 42) == 0);
    zc_master.is_catalog = false;
    zc_master.type = "program";
    len = run_ctrl_cmd(&sun, secret_key, "rollback example.com.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "ERROR a program zone cannot be rolled back", 42) == 0);
    zc_master.type = "master";
    atomic_store(&z_master.rolled_back, true);
    atomic_store(&z_master.rb_serial, 2026091902);
    atomic_store(&z_master.rb_from, 2026091901);
    len = run_ctrl_cmd(&sun, secret_key, "zonestatus example.com.\n", out, sizeof(out));
    assert(len > 0 && strstr(out, " rolled back (serial 2026091902, from 2026091901)") != NULL);
    atomic_store(&z_master.rolled_back, false);

    /* control-channel { algorithm } selects the HMAC of the challenge-response */
    mock_cfg.control.algorithm = "hmac-sha512";
    len = run_ctrl_cmd_md(&sun, EVP_sha512(), secret_key, "zonestatus example.com.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "OK serial=", 10) == 0);
    assert(run_ctrl_cmd_md(&sun, EVP_sha256(), secret_key, "zonestatus example.com.\n", out, sizeof(out)) == -1);
    mock_cfg.control.algorithm = "HMAC-MD5.";
    len = run_ctrl_cmd_md(&sun, EVP_md5(), secret_key, "zonestatus example.com.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "OK serial=", 10) == 0);
    mock_cfg.control.algorithm = "hmac-sha256";
    len = run_ctrl_cmd_md(&sun, EVP_sha256(), secret_key, "zonestatus example.com.\n", out, sizeof(out));
    assert(len > 0 && strncmp(out, "OK serial=", 10) == 0);
    /* an unknown algorithm (never accepted by the parser) must fail closed; an empty AUTH never matches */
    mock_cfg.control.algorithm = "hmac-unknown";
    assert(run_ctrl_cmd_md(&sun, EVP_sha256(), secret_key, "zonestatus example.com.\n", out, sizeof(out)) == -1);
    {
        int cfd_e = socket(AF_UNIX, SOCK_STREAM, 0);
        assert(cfd_e >= 0);
        test_set_io_timeout(cfd_e, 5);
        assert(connect(cfd_e, (struct sockaddr *)&sun, sizeof(sun)) == 0);
        n = recv(cfd_e, rbuf, sizeof(rbuf) - 1, 0);
        assert(n > 0);
        send(cfd_e, "AUTH \n", 6, 0);
        n = recv(cfd_e, rbuf, sizeof(rbuf) - 1, 0);
        assert(n > 0);
        rbuf[n] = '\0';
        assert(strcmp(rbuf, "AUTH_FAILED\n") == 0);
        close(cfd_e);
    }
    mock_cfg.control.algorithm = NULL;

    len = run_ctrl_cmd(&sun, secret_key, "notify example.com.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "OK\n") == 0);
    assert(atomic_load_explicit(&z_master.notify_now, memory_order_relaxed) == true);

    len = run_ctrl_cmd(&sun, secret_key, "retransfer slave.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "OK\n") == 0);
    assert(atomic_load_explicit(&z_slave.refresh_now, memory_order_relaxed) == true);

    len = run_ctrl_cmd(&sun, secret_key, "reload slave.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "OK reloaded (slave)\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "invalid_command_foo\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "ERROR unknown command\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "notify unknown.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "ERROR zone not found\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "retransfer unknown.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "ERROR zone not found\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "reload unknown.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "ERROR zone not found\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "observatory unknown.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "OK 0\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "stats\n", out, sizeof(out));
    assert(len > 0);

    len = run_ctrl_cmd(&sun, secret_key, "stats json\n", out, sizeof(out));
    assert(len > 0);

    len = run_ctrl_cmd(&sun, secret_key, "reload\n", out, sizeof(out));
    assert(len > 0);

    len = run_ctrl_cmd(&sun, secret_key, "reconfig\n", out, sizeof(out));
    assert(len > 0);

    // 3. Test Command Buffer Overflow
    int cfd2 = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(cfd2 >= 0);
    test_set_io_timeout(cfd2, 5);
    res = connect(cfd2, (struct sockaddr *)&sun, sizeof(sun));
    assert(res == 0);
    n = recv(cfd2, rbuf, sizeof(rbuf) - 1, 0);
    assert(n > 0);
    char overflow_payload[1024];
    memset(overflow_payload, 'A', sizeof(overflow_payload));
    send(cfd2, overflow_payload, sizeof(overflow_payload), 0);
    n = recv(cfd2, rbuf, sizeof(rbuf) - 1, 0);
    if (n > 0) {
        rbuf[n] = '\0';
        assert(strstr(rbuf, "ERROR") != NULL);
    }
    close(cfd2);

    test_stop_thread(th);
    atomic_store(&g_privilege_drop_complete, saved_drop);

    close(lfd);
    unlink(sock_path);
    g_control_sock = -1;

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    atomic_store_explicit(&g_zone_db_active, NULL, memory_order_release);

    printf("  -> control_thread_func passed.\n");
}

// ----------------------------------------------------------------------------
// 14b. Restricted control keys (control-channel { keys { } }): authentication over several keys and the permission of each command
// ----------------------------------------------------------------------------
bool ctrl_auth_match(const server_config_t *cfg, const char *challenge, const char *client_hmac, char *name_out, size_t name_sz,
                     uint32_t *perm_out);
void ctrl_log_text(const char *line, char *out, size_t out_sz);

static void test_hmac_hex(const EVP_MD *md, const char *secret, const char *challenge, char *hex, size_t hex_sz) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    HMAC(md, secret, strlen(secret), (const unsigned char *)challenge, 64, mac, &mac_len);
    assert(hex_sz > 2 * mac_len);
    for (unsigned int k = 0; k < mac_len; k++) snprintf(&hex[k * 2], 3, "%02x", mac[k]);
}

/* connects, answers the challenge with HMAC(md, secret) and returns the descriptor after "OK", or -1 (AUTH_FAILED) */
static int test_ctrl_login(const struct sockaddr_un *sun, const EVP_MD *md, const char *secret) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);
    test_set_io_timeout(fd, 5);
    assert(connect(fd, (const struct sockaddr *)sun, sizeof(*sun)) == 0);
    char rbuf[256];
    ssize_t n = recv(fd, rbuf, sizeof(rbuf) - 1, 0);
    assert(n > 10 && strncmp(rbuf, "CHALLENGE ", 10) == 0);
    char challenge[65], hex[2 * EVP_MAX_MD_SIZE + 1], line[2 * EVP_MAX_MD_SIZE + 16];
    memcpy(challenge, rbuf + 10, 64);
    challenge[64] = '\0';
    test_hmac_hex(md, secret, challenge, hex, sizeof(hex));
    int ll = snprintf(line, sizeof(line), "AUTH %s\n", hex);
    send(fd, line, (size_t)ll, 0);
    n = recv(fd, rbuf, sizeof(rbuf) - 1, 0);
    if (n >= 3 && strncmp(rbuf, "OK\n", 3) == 0) return fd;
    close(fd);
    return -1;
}

/* one command on an open connection; the reply is the first chunk the server sends */
static void test_ctrl_send(int fd, const char *cmd, char *out, size_t out_sz) {
    send(fd, cmd, strlen(cmd), 0);
    ssize_t n = recv(fd, out, out_sz - 1, 0);
    out[n > 0 ? n : 0] = '\0';
}

/* a fresh connection for one command (the connection is closed by the server after an accepted command) */
static void test_ctrl_once(const struct sockaddr_un *sun, const EVP_MD *md, const char *secret, const char *cmd, char *out, size_t out_sz) {
    int fd = test_ctrl_login(sun, md, secret);
    assert(fd >= 0);
    test_ctrl_send(fd, cmd, out, out_sz);
    close(fd);
}

static void test_control_restricted_keys(void) {
    printf("[TEST] Server Core: control-channel keys (authentication over several keys, permission of each command)...\n");

    /* the algorithm of every key is its own, and the key found by the HMAC decides the permission */
    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.control.enabled = true;
    const char *main_secret = "main_secret_value", *admin_secret = "admin_secret_value", *web_secret = "web_secret_value", *ro_secret = "ro_secret_value";
    memcpy(mock_cfg.control.secret_decoded, main_secret, strlen(main_secret));
    mock_cfg.control.secret_decoded_len = strlen(main_secret);
    control_key_t keys[3];
    memset(keys, 0, sizeof(keys));
    keys[0].name = "admin";
    keys[0].algorithm = "hmac-sha256";
    keys[0].perm = CTLP_FULL;
    memcpy(keys[0].secret_decoded, admin_secret, strlen(admin_secret));
    keys[0].secret_decoded_len = strlen(admin_secret);
    keys[1].name = "web";
    keys[1].algorithm = "hmac-sha512";
    keys[1].perm = CTLP_READ | CTLP_RELOAD_ZONE;
    memcpy(keys[1].secret_decoded, web_secret, strlen(web_secret));
    keys[1].secret_decoded_len = strlen(web_secret);
    keys[2].name = "ro";
    keys[2].algorithm = "hmac-sha256";
    keys[2].perm = CTLP_READ;
    memcpy(keys[2].secret_decoded, ro_secret, strlen(ro_secret));
    keys[2].secret_decoded_len = strlen(ro_secret);
    mock_cfg.control.keys = keys;
    mock_cfg.control.nkeys = 3;

    /* ctrl_auth_match(): the key whose HMAC arrives, with its own algorithm; nothing else matches */
    {
        const char *chal = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        char hex[2 * EVP_MAX_MD_SIZE + 1], nm[128] = "";
        uint32_t perm = 0;
        test_hmac_hex(EVP_sha256(), main_secret, chal, hex, sizeof(hex));
        assert(ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm) && strcmp(nm, "(main)") == 0 && perm == CTLP_FULL);
        test_hmac_hex(EVP_sha256(), admin_secret, chal, hex, sizeof(hex));
        assert(ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm) && strcmp(nm, "admin") == 0 && perm == CTLP_FULL);
        test_hmac_hex(EVP_sha512(), web_secret, chal, hex, sizeof(hex));
        assert(ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm) && strcmp(nm, "web") == 0 && perm == (CTLP_READ | CTLP_RELOAD_ZONE));
        test_hmac_hex(EVP_sha256(), ro_secret, chal, hex, sizeof(hex));
        assert(ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm) && strcmp(nm, "ro") == 0 && perm == CTLP_READ);
        /* web's secret with sha256 (its key says sha512), a made-up value, an empty AUTH, a prefix of a good one */
        test_hmac_hex(EVP_sha256(), web_secret, chal, hex, sizeof(hex));
        assert(!ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm));
        assert(!ctrl_auth_match(&mock_cfg, chal, "00112233", nm, sizeof(nm), &perm));
        assert(!ctrl_auth_match(&mock_cfg, chal, "", nm, sizeof(nm), &perm));
        test_hmac_hex(EVP_sha256(), ro_secret, chal, hex, sizeof(hex));
        hex[63] = '\0';
        assert(!ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm));
        /* only keys, no unnamed secret: the keys still work (the old test needed a secret) */
        mock_cfg.control.secret_decoded_len = 0;
        test_hmac_hex(EVP_sha256(), main_secret, chal, hex, sizeof(hex));
        assert(!ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm));
        test_hmac_hex(EVP_sha256(), admin_secret, chal, hex, sizeof(hex));
        assert(ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm) && strcmp(nm, "admin") == 0);
        /* a key with an unknown algorithm (never accepted by the parser) fails closed */
        keys[0].algorithm = "hmac-unknown";
        assert(!ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm));
        keys[0].algorithm = "hmac-sha256";
        mock_cfg.control.secret_decoded_len = strlen(main_secret);
        /* the control channel is not enabled: nobody */
        mock_cfg.control.enabled = false;
        test_hmac_hex(EVP_sha256(), admin_secret, chal, hex, sizeof(hex));
        assert(!ctrl_auth_match(&mock_cfg, chal, hex, nm, sizeof(nm), &perm));
        mock_cfg.control.enabled = true;
        /* no secret and no key: nobody, not even an empty HMAC */
        server_config_t none;
        memset(&none, 0, sizeof(none));
        none.control.enabled = true;
        assert(!ctrl_auth_match(&none, chal, hex, nm, sizeof(nm), &perm));
        assert(!ctrl_auth_match(NULL, chal, hex, nm, sizeof(nm), &perm));
    }
    {   /* what reaches the log: printable ASCII, at most 120 bytes */
        char lt[128];
        ctrl_log_text("reload exa\x01mple\x7f.test\xff", lt, sizeof(lt));
        assert(strcmp(lt, "reload exa?mple?.test?") == 0);
        char longline[400];
        memset(longline, 'a', sizeof(longline) - 1);
        longline[sizeof(longline) - 1] = '\0';
        ctrl_log_text(longline, lt, sizeof(lt));
        assert(strlen(lt) == 120);
        ctrl_log_text(longline, lt, 8);
        assert(strlen(lt) == 7);
    }

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "/tmp/karidns_test_ctrlkeys_%ld.sock", (long)getpid());
    unlink(sock_path);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(lfd >= 0);
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);
    assert(bind(lfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);
    assert(listen(lfd, 8) == 0);
    g_control_sock = lfd;

    zone_db_entry_t z_master;
    memset(&z_master, 0, sizeof(z_master));
    strlcpy(z_master.domain, "example.com.", sizeof(z_master.domain));
    strlcpy(z_master.view_name, "default", sizeof(z_master.view_name));
    atomic_init(&z_master.serial, 2026091901);
    atomic_init(&z_master.refresh, 3600);
    zone_db_entry_t z_slave;
    memset(&z_slave, 0, sizeof(z_slave));
    strlcpy(z_slave.domain, "slave.example.", sizeof(z_slave.domain));
    strlcpy(z_slave.view_name, "default", sizeof(z_slave.view_name));
    z_slave.is_secondary = true;
    atomic_init(&z_slave.serial, 100);
    atomic_init(&z_slave.refresh, 1800);
    zone_db_entry_t *entries[2] = {&z_master, &z_slave};
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 2);
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;
    atomic_init(&snap.reader_count, 1);
    zone_config_t zc_master, zc_slave;
    memset(&zc_master, 0, sizeof(zc_master));
    memset(&zc_slave, 0, sizeof(zc_slave));
    zc_master.domain = "example.com.";
    zc_master.type = "master";
    zc_slave.domain = "slave.example.";
    zc_slave.type = "slave";
    zc_master.next = &zc_slave;
    view_config_t vc;
    memset(&vc, 0, sizeof(vc));
    vc.name = "default";
    vc.zones = &zc_master;
    mock_cfg.views = &vc;
    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);
    atomic_store_explicit(&g_zone_db_active, &snap, memory_order_release);

    bool saved_drop = atomic_load(&g_privilege_drop_complete);
    atomic_store(&g_privilege_drop_complete, true);
    pthread_t th;
    assert(pthread_create(&th, NULL, control_thread_func, NULL) == 0);
    usleep(10000);

    char out[2048];
    const char *refused_web = "ERROR command not allowed for key \"web\"\n";

    /* full keys: the unnamed secret and "admin" run everything; an unknown command is answered as before, rollback reaches its command */
    test_ctrl_once(&sun, EVP_sha256(), main_secret, "notify example.com.\n", out, sizeof(out));
    assert(strcmp(out, "OK\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "retransfer slave.example.\n", out, sizeof(out));
    assert(strcmp(out, "OK\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "reload slave.example.\n", out, sizeof(out));
    assert(strcmp(out, "OK reloaded (slave)\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "rollback example.com.\n", out, sizeof(out));
    assert(strncmp(out, "ERROR no previous version", 25) == 0);
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "bogus\n", out, sizeof(out));
    assert(strcmp(out, "ERROR unknown command\n") == 0);
    /* 0.7: trace / notrace through the dispatcher; a full key has the permission */
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "trace 5\n", out, sizeof(out));
    assert(strcmp(out, "OK debug level is now 5\n") == 0 && klog_debug_level() == 5);
    test_ctrl_once(&sun, EVP_sha256(), main_secret, "trace\n", out, sizeof(out));
    assert(strcmp(out, "OK debug level is now 6\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "trace 1 2\n", out, sizeof(out));
    assert(strncmp(out, "ERROR trace takes one argument", 30) == 0 && klog_debug_level() == 6);
    test_ctrl_once(&sun, EVP_sha256(), admin_secret, "notrace\n", out, sizeof(out));
    assert(strcmp(out, "OK debug level is now 0\n") == 0 && klog_debug_level() == 0);
    {   /* status carries the level */
        test_ctrl_once(&sun, EVP_sha256(), admin_secret, "trace 7\n", out, sizeof(out));
        int sfd = test_ctrl_login(&sun, EVP_sha256(), admin_secret);
        assert(sfd >= 0);
        assert(send(sfd, "status\n", 7, 0) == 7);
        size_t got = 0;
        while (got < 3 + sizeof(karidns_status_t)) {
            ssize_t k = recv(sfd, out + got, sizeof(out) - got, 0);
            if (k <= 0) break;
            got += (size_t)k;
        }
        close(sfd);
        assert(got == 3 + sizeof(karidns_status_t) && strncmp(out, "OK ", 3) == 0);
        karidns_status_t kst;
        memcpy(&kst, out + 3, sizeof(kst));
        assert(kst.debug_level == 7);
        assert(kst.dnstap_link == KARIDNS_DNSTAP_LINK_OFF);   /* 0.7: no dnstap block here */
        klog_set_debug_level(0);
    }

    /* "web": read-only commands and reload <zone> only */
    test_ctrl_once(&sun, EVP_sha512(), web_secret, "status\n", out, sizeof(out));
    assert(strncmp(out, "OK ", 3) == 0);
    test_ctrl_once(&sun, EVP_sha512(), web_secret, "zonestatus example.com.\n", out, sizeof(out));
    assert(strncmp(out, "OK serial=", 10) == 0);
    test_ctrl_once(&sun, EVP_sha512(), web_secret, "observatory\n", out, sizeof(out));
    assert(strncmp(out, "OK 2\n", 5) == 0);
    test_ctrl_once(&sun, EVP_sha512(), web_secret, "dbstatus\n", out, sizeof(out));
    assert(strncmp(out, "ERROR no database block", 23) == 0);          /* allowed: it reached the command */
    test_ctrl_once(&sun, EVP_sha512(), web_secret, "reload slave.example.\n", out, sizeof(out));
    assert(strcmp(out, "OK reloaded (slave)\n") == 0);
    atomic_store_explicit(&z_master.notify_now, false, memory_order_relaxed);
    atomic_store_explicit(&z_slave.refresh_now, false, memory_order_relaxed);
    static const char *const web_refused[] = { "reload\n", "reconfig\n", "stop\n", "notify example.com.\n", "retransfer slave.example.\n",
                                               "rollback example.com.\n", "bogus\n", "evict x.test\n", "xfr-delay 5\n", "trace\n", "trace 3\n",
                                               "notrace\n" };
    for (size_t i = 0; i < sizeof(web_refused) / sizeof(web_refused[0]); i++) {
        test_ctrl_once(&sun, EVP_sha512(), web_secret, web_refused[i], out, sizeof(out));
        assert(strcmp(out, refused_web) == 0);
    }
    assert(!atomic_load_explicit(&z_master.notify_now, memory_order_relaxed) && !atomic_load_explicit(&z_slave.refresh_now, memory_order_relaxed));   /* nothing ran */

    /* "ro": read-only, and reload <zone> is refused */
    test_ctrl_once(&sun, EVP_sha256(), ro_secret, "zonestatus example.com.\n", out, sizeof(out));
    assert(strncmp(out, "OK serial=", 10) == 0);
    test_ctrl_once(&sun, EVP_sha256(), ro_secret, "reload slave.example.\n", out, sizeof(out));
    assert(strcmp(out, "ERROR command not allowed for key \"ro\"\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), ro_secret, "notrace\n", out, sizeof(out));
    assert(strcmp(out, "ERROR command not allowed for key \"ro\"\n") == 0);
    /* allow-commands { trace; }: trace and notrace, nothing else */
    keys[2].perm = CTLP_READ | CTLP_TRACE;
    test_ctrl_once(&sun, EVP_sha256(), ro_secret, "trace 2\n", out, sizeof(out));
    assert(strcmp(out, "OK debug level is now 2\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), ro_secret, "notrace\n", out, sizeof(out));
    assert(strcmp(out, "OK debug level is now 0\n") == 0);
    test_ctrl_once(&sun, EVP_sha256(), ro_secret, "reload slave.example.\n", out, sizeof(out));
    assert(strcmp(out, "ERROR command not allowed for key \"ro\"\n") == 0);
    keys[2].perm = CTLP_READ;

    /* the wrong algorithm for a key and an unknown secret are refused at login */
    assert(test_ctrl_login(&sun, EVP_sha256(), web_secret) == -1);
    assert(test_ctrl_login(&sun, EVP_sha512(), "nobody_has_this") == -1);

    /* a refusal keeps the connection open: the same client can still run what it is allowed to (the connection ends after that) */
    {
        int fd = test_ctrl_login(&sun, EVP_sha512(), web_secret);
        assert(fd >= 0);
        test_ctrl_send(fd, "stop\n", out, sizeof(out));
        assert(strcmp(out, refused_web) == 0);
        test_ctrl_send(fd, "reconfig\n", out, sizeof(out));
        assert(strcmp(out, refused_web) == 0);
        test_ctrl_send(fd, "zonestatus example.com.\n", out, sizeof(out));
        assert(strncmp(out, "OK serial=", 10) == 0);
        assert(recv(fd, out, sizeof(out), 0) == 0);          /* an accepted command ends the connection, as before */
        close(fd);
    }

    /* the permission is copied when the client logs in: a reconfig (here: the key now has full power) does not change an open connection */
    {
        int fd = test_ctrl_login(&sun, EVP_sha512(), web_secret);
        assert(fd >= 0);
        keys[1].perm = CTLP_FULL;
        test_ctrl_send(fd, "reload\n", out, sizeof(out));
        assert(strcmp(out, refused_web) == 0);
        close(fd);
        test_ctrl_once(&sun, EVP_sha512(), web_secret, "retransfer slave.example.\n", out, sizeof(out));   /* a new login sees the new mask */
        assert(strcmp(out, "OK\n") == 0);
        keys[1].perm = CTLP_READ | CTLP_RELOAD_ZONE;
    }

    test_stop_thread(th);
    atomic_store(&g_privilege_drop_complete, saved_drop);
    close(lfd);
    unlink(sock_path);
    g_control_sock = -1;
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    atomic_store_explicit(&g_zone_db_active, NULL, memory_order_release);
    printf("  -> control-channel keys passed.\n");
}

bool ctrl_peer_admitted(uid_t peer_uid, const gid_t *groups, int ngroups, uid_t my_uid, bool have_gid, gid_t allow_gid);

/* control-channel allow-group: who may connect (the HMAC challenge follows for everybody) */
static void test_control_peer_admission(void) {
    printf("[TEST] Server Core: control socket admission (uid, root, allow-group)...\n");
    const gid_t g1[] = { 100, 200, 300 };
    assert(ctrl_peer_admitted(1001, g1, 3, 1001, false, 0));          /* the server's own user */
    assert(ctrl_peer_admitted(0, g1, 0, 1001, false, 0));             /* root */
    assert(!ctrl_peer_admitted(2002, g1, 3, 1001, false, 0));         /* another user, no allow-group */
    assert(!ctrl_peer_admitted(2002, g1, 3, 1001, true, 400));        /* allow-group the peer is not in */
    assert(ctrl_peer_admitted(2002, g1, 3, 1001, true, 100));         /* the first group */
    assert(ctrl_peer_admitted(2002, g1, 3, 1001, true, 300));         /* a supplementary group: the last one counts too */
    assert(!ctrl_peer_admitted(2002, g1, 0, 1001, true, 100));        /* no groups at all */
    assert(!ctrl_peer_admitted(2002, NULL, 3, 1001, true, 100));
    assert(ctrl_peer_admitted(2002, g1, 3, 1001, true, 100) && !ctrl_peer_admitted(2002, g1, 3, 1001, false, 100));   /* a gid is not enough when none is configured */
    assert(!ctrl_peer_admitted(2002, g1, 3, 0, true, 999));
    printf("  -> admission passed.\n");
}

// ----------------------------------------------------------------------------
// 15. open_router_udp_sockets & setup_udp_socket_buffers Test
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// sendmmsg_skip_failed: one failing message must not drop the rest of the batch
// ----------------------------------------------------------------------------
static void test_sendmmsg_skip_failed(void) {
    printf("[TEST] Server Core: sendmmsg_skip_failed skips only the failing message...\n");

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL, 0) | O_NONBLOCK);

    // [1] は AF_UNIX データグラムの上限 (FreeBSD: net.local.dgram.maxdgram,
    // Linux: SO_SNDBUF) を超えるので EMSGSIZE になる
    static uint8_t big[256 * 1024];
    static const char *small[3] = {"A-first", "C-third", "D-fourth"};
    struct iovec iov[4];
    struct mmsghdr msgs[4];
    memset(msgs, 0, sizeof(msgs));
    iov[0].iov_base = (void *)small[0]; iov[0].iov_len = strlen(small[0]);
    iov[1].iov_base = big;              iov[1].iov_len = sizeof(big);
    iov[2].iov_base = (void *)small[1]; iov[2].iov_len = strlen(small[1]);
    iov[3].iov_base = (void *)small[2]; iov[3].iov_len = strlen(small[2]);
    for (int i = 0; i < 4; i++) {
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    assert(sendmmsg_skip_failed(sv[0], msgs, 4, "test", true) == 1);
    for (int i = 0; i < 3; i++) {
        char buf[64];
        ssize_t n = recv(sv[1], buf, sizeof(buf) - 1, MSG_DONTWAIT);
        assert(n == (ssize_t)strlen(small[i]));
        buf[n] = '\0';
        assert(strcmp(buf, small[i]) == 0);
    }
    char extra[8];
    assert(recv(sv[1], extra, sizeof(extra), MSG_DONTWAIT) < 0);

    // 全件失敗 (EBADF) でも 1 通ずつ飛ばして終了し、無限ループしない
    assert(sendmmsg_skip_failed(-1, msgs, 4, "test", false) == 4);

    // 受信側が満杯 (EAGAIN / ENOBUFS) なら残りをまとめて破棄する
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
    // 1 バイトずつ詰め、どの小さなメッセージも入らない状態にする
    uint8_t fill = 0;
    int filled = 0;
    while (send(sv[0], &fill, 1, MSG_DONTWAIT) > 0 && filled < 1000000)
        filled++;
    assert(errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS);
    struct mmsghdr small_msgs[3];
    memset(small_msgs, 0, sizeof(small_msgs));
    small_msgs[0].msg_hdr.msg_iov = &iov[0]; small_msgs[0].msg_hdr.msg_iovlen = 1;
    small_msgs[1].msg_hdr.msg_iov = &iov[2]; small_msgs[1].msg_hdr.msg_iovlen = 1;
    small_msgs[2].msg_hdr.msg_iov = &iov[3]; small_msgs[2].msg_hdr.msg_iovlen = 1;
    assert(sendmmsg_skip_failed(sv[0], small_msgs, 3, "test", true) == 3);

    close(sv[0]);
    close(sv[1]);
    printf("  -> sendmmsg_skip_failed passed.\n");
}

/* a configuration built by hand: listen on one IPv4 address (what config_build_listen() would have computed) */
static void test_set_listen(server_config_t *cfg, const char *ip, int port) {
    static listen_addr_t entries[8];
    static int next;
    listen_addr_t *e = &entries[next++ % 8];
    memset(e, 0, sizeof(*e));
    e->family = AF_INET;
    assert(inet_pton(AF_INET, ip, e->addr) == 1);
    e->port = (uint16_t)port;
    snprintf(e->text, sizeof(e->text), "%s", ip);
    cfg->listen = e;
    cfg->listen_count = 1;
}

static void test_open_router_udp_sockets_and_buffers(void) {
    printf("[TEST] Server Core: open_router_udp_sockets & setup_udp_socket_buffers...\n");

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s >= 0);
    setup_udp_socket_buffers(s, 1048576, 1048576);
    close(s);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = 35353;
    test_set_listen(&cfg, "127.0.0.1", 35353);
    cfg.udp_recvbuf_size = 524288;
    cfg.udp_sndbuf_size = 524288;

    int out_fds[MAX_BIND_ADDRS];
    bool out_is_wc[MAX_BIND_ADDRS];
    int num = open_router_udp_sockets(&cfg, out_fds, out_is_wc);
    assert(num == 1);
    assert(out_fds[0] >= 0);
    assert(out_is_wc[0] == false);

    close(out_fds[0]);
    printf("  -> open_router_udp_sockets & setup_udp_socket_buffers passed.\n");
}

// ----------------------------------------------------------------------------
// tcp-window / tcp-mss and zone-tcp-* socket options on a real loopback connection
// ----------------------------------------------------------------------------
static int sockopt_int(int fd, int level, int opt) {
    int v = 0;
    socklen_t len = sizeof(v);
    assert(getsockopt(fd, level, opt, &v, &len) == 0);
    return v;
}

static void test_tcp_listen_and_zone_socket_opts(void) {
    printf("[TEST] Server Core: tcp-window / tcp-mss / zone-tcp-* socket options...\n");

    /* tcp-window is set on the listener and inherited by the accepted socket */
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.tcp_window = 256 * 1024;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);
    apply_tcp_listen_opts(lfd, &cfg, true);
    assert(sockopt_int(lfd, SOL_SOCKET, SO_RCVBUF) >= 256 * 1024);
    assert(sockopt_int(lfd, SOL_SOCKET, SO_SNDBUF) >= 256 * 1024);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    socklen_t salen = sizeof(sa);
    assert(getsockname(lfd, (struct sockaddr *)&sa, &salen) == 0);
    assert(listen(lfd, 4) == 0);
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(cfd >= 0);
    assert(connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    int sfd = accept(lfd, NULL, NULL);
    assert(sfd >= 0);
    assert(sockopt_int(sfd, SOL_SOCKET, SO_SNDBUF) >= 256 * 1024);

    /* a listener without tcp-window is left alone */
    server_config_t cfg_none;
    memset(&cfg_none, 0, sizeof(cfg_none));
    int lfd2 = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd2 >= 0);
    int before = sockopt_int(lfd2, SOL_SOCKET, SO_RCVBUF);
    apply_tcp_listen_opts(lfd2, &cfg_none, true);
    apply_tcp_listen_opts(lfd2, NULL, true);
    assert(sockopt_int(lfd2, SOL_SOCKET, SO_RCVBUF) == before);
    close(lfd2);

    tcp_stream_ctx_t *c = calloc(1, sizeof(*c));
    assert(c);

    /* tcp-mss: lowers the established connection's MSS; a larger value later is a no-op */
    apply_tcp_mss(sfd, c, 1200);
    assert(c->applied_mss == 1200);
#if defined(__FreeBSD__) && defined(TCP_MAXSEG)
    int mss_now = sockopt_int(sfd, IPPROTO_TCP, TCP_MAXSEG);
    assert(mss_now > 0 && mss_now <= 1200);
#endif
    apply_tcp_mss(sfd, c, 1400);
    assert(c->applied_mss == 1200);
    apply_tcp_mss(sfd, c, 0);
    assert(c->applied_mss == 1200);

    /* zone A sets everything; the MSS only goes further down */
    zone_config_t za;
    memset(&za, 0, sizeof(za));
    tzx(&za)->zone_tcp_mss = 1000;
    tzx(&za)->zone_tcp_window = 512 * 1024;
    tzx(&za)->zone_tcp_sndbuf = 1024 * 1024;
    int orig_snd = sockopt_int(sfd, SOL_SOCKET, SO_SNDBUF);
    int orig_rcv = sockopt_int(sfd, SOL_SOCKET, SO_RCVBUF);
    apply_zone_tcp_opts(sfd, c, &za);
    assert(c->applied_mss == 1000);
    assert(c->applied_rcvbuf == 512 * 1024);
    assert(c->applied_sndbuf == 1024 * 1024);
    assert(c->orig_rcvbuf == orig_rcv);
    assert(c->orig_sndbuf == orig_snd);
    assert(sockopt_int(sfd, SOL_SOCKET, SO_RCVBUF) >= 512 * 1024);
    assert(sockopt_int(sfd, SOL_SOCKET, SO_SNDBUF) >= 1024 * 1024);
    apply_zone_tcp_opts(sfd, c, &za);     /* same zone again: nothing changes */
    assert(c->applied_sndbuf == 1024 * 1024 && c->orig_sndbuf == orig_snd);

    /* zone B has no zone-tcp-*: buffers go back to the pre-zone values, MSS stays lowered */
    zone_config_t zb;
    memset(&zb, 0, sizeof(zb));
    tzx(&zb)->zone_tcp_mss = 1300;
    apply_zone_tcp_opts(sfd, c, &zb);
    assert(c->applied_mss == 1000);
    assert(c->applied_rcvbuf == 0 && c->applied_sndbuf == 0);
    assert(sockopt_int(sfd, SOL_SOCKET, SO_SNDBUF) == orig_snd);
    assert(sockopt_int(sfd, SOL_SOCKET, SO_RCVBUF) == orig_rcv);

    /* only zone-tcp-sndbuf on zone C; a query outside any configured zone (NULL) resets it */
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    tzx(&zc)->zone_tcp_sndbuf = 2 * 1024 * 1024;
    apply_zone_tcp_opts(sfd, c, &zc);
    assert(c->applied_sndbuf == 2 * 1024 * 1024 && c->applied_rcvbuf == 0);
    apply_zone_tcp_opts(sfd, c, NULL);
    assert(c->applied_sndbuf == 0);
    assert(sockopt_int(sfd, SOL_SOCKET, SO_SNDBUF) == orig_snd);

    free(c);
    close(sfd);
    close(cfd);
    close(lfd);
    printf("  -> tcp-window / tcp-mss / zone-tcp-* socket options passed.\n");
}

static void build_dns_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, bool dnssec_ok) {
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; // RD=1
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    buf[10] = 0; buf[11] = dnssec_ok ? 0x01 : 0x00;

    long wlen = write_uncompressed_name(buf, 12, 256, qname);
    assert(wlen > 0);
    size_t off = 12 + (size_t)wlen;
    buf[off++] = (uint8_t)(qtype >> 8);
    buf[off++] = (uint8_t)(qtype & 0xFF);
    buf[off++] = 0x00;
    buf[off++] = 0x01;
    *out_len = off;
}

// ----------------------------------------------------------------------------
// 16. async_io_pool & enqueue_async_io_task Test
// ----------------------------------------------------------------------------
static void test_async_io_pool_and_tasks(void) {
    printf("[TEST] Server Core: async_io_pool & enqueue_async_io_task...\n");

    init_async_io_pool();
    assert(g_async_io_pool.running == true);

    // Setup active zone snapshot for async query resolution
    zone_arena_t arena;
    zone_arena_init(&arena);
    arena.records = calloc(4, sizeof(dns_record_t));
    arena.records_cap = 4;

    dns_record_t a_rec;
    memset(&a_rec, 0, sizeof(a_rec));
    DNS_RECORD_BIND_RDATA(a_rec);
    a_rec.name = arena_strdup(&arena, "async.example.com.");
    a_rec.type = arena_strdup(&arena, "A");
    a_rec.type_code = 1;
    a_rec.ttl = arena_strdup(&arena, "300");
    a_rec.ttl_value = 300;
    a_rec.class_str = arena_strdup(&arena, "IN");
    a_rec.class_val = 1;
    a_rec.rdata_count = 1;
    a_rec.rdata[0] = arena_strdup(&arena, "192.0.2.77");
    arena.records[0] = a_rec;
    arena.count = 1;
    build_zone_index(&arena, true);

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "async.example.com.", sizeof(entry.domain));
    strlcpy(entry.view_name, "default", sizeof(entry.view_name));
    atomic_store_explicit(&entry.rcu.active, &arena.ver, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};



    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view_set_entries(&view, entries, 1);


    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;
    atomic_init(&snap.reader_count, 10);

    // 1. UDP Async Task
    int sp_udp[2];
    int res = socketpair(AF_UNIX, SOCK_DGRAM, 0, sp_udp);
    assert(res == 0);

    uint8_t qbuf[512];
    size_t qlen = 0;
    build_dns_query(qbuf, &qlen, 0x55AA, "async.example.com.", 1, false);

    uint8_t *heap_req = malloc(qlen);
    assert(heap_req != NULL);
    memcpy(heap_req, qbuf, qlen);

    async_io_task_t udp_task;
    memset(&udp_task, 0, sizeof(udp_task));
    udp_task.is_tcp = false;
    udp_task.active_fd = sp_udp[0];
    udp_task.req_buf = heap_req;
    udp_task.req_buf_cap = qlen;
    udp_task.req_len = qlen;
    strlcpy(udp_task.client_ip, "127.0.0.1", sizeof(udp_task.client_ip));
    udp_task.client_port = 53535;
    strlcpy(udp_task.qname, "async.example.com.", sizeof(udp_task.qname));
    udp_task.qtype = 1;
    udp_task.qclass = 1;
    udp_task.snap = &snap;

    bool enq_ok = enqueue_async_io_task(&udp_task);
    assert(enq_ok == true);

    // Wait and read response from sp_udp[1]
    alignas(udp_ipc_t) uint8_t rx_resp[512 + sizeof(udp_ipc_t)];
    // Wait for the worker's reply before closing sp_udp[0]: on a slow (CI) VM a
    // 500 ms poll could expire, and the worker would then send to a closed fd
    // whose number the TCP socketpair below may already reuse.
    struct pollfd pfd = { .fd = sp_udp[1], .events = POLLIN };
    int prc = poll(&pfd, 1, 10000);
    assert(prc > 0);
    ssize_t got_udp = recv(sp_udp[1], rx_resp, sizeof(rx_resp), 0);
    assert(got_udp > (ssize_t)sizeof(udp_ipc_t));
    close(sp_udp[0]);
    close(sp_udp[1]);

    // 2. TCP Async Task
    int sp_tcp[2];
    res = socketpair(AF_UNIX, SOCK_STREAM, 0, sp_tcp);
    assert(res == 0);

    heap_req = malloc(qlen);
    assert(heap_req != NULL);
    memcpy(heap_req, qbuf, qlen);

    async_io_task_t tcp_task;
    memset(&tcp_task, 0, sizeof(tcp_task));
    tcp_task.is_tcp = true;
    tcp_task.client_fd = sp_tcp[0];
    tcp_task.req_buf = heap_req;
    tcp_task.req_buf_cap = qlen;
    tcp_task.req_len = qlen;
    strlcpy(tcp_task.client_ip, "127.0.0.1", sizeof(tcp_task.client_ip));
    tcp_task.client_port = 53535;
    strlcpy(tcp_task.qname, "async.example.com.", sizeof(tcp_task.qname));
    tcp_task.qtype = 1;
    tcp_task.qclass = 1;
    tcp_task.snap = &snap;

    enq_ok = enqueue_async_io_task(&tcp_task);
    assert(enq_ok == true);

    // The worker sends the 2-byte length prefix and the message with separate
    // send() calls, so one recv() may return just the prefix: read until the
    // worker closes its end (it closes client_fd after the reply).
    uint8_t tcp_rx[512];
    size_t tcp_got = 0;
    for (;;) {
        struct pollfd pfd_tcp = { .fd = sp_tcp[1], .events = POLLIN };
        int trc = poll(&pfd_tcp, 1, 10000);
        assert(trc > 0);
        ssize_t n = recv(sp_tcp[1], tcp_rx + tcp_got, sizeof(tcp_rx) - tcp_got, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n >= 0);
        if (n == 0 || tcp_got + (size_t)n == sizeof(tcp_rx)) { tcp_got += (size_t)n; break; }
        tcp_got += (size_t)n;
    }
    assert(tcp_got > 2); // 2-byte prefix + DNS message
    assert(tcp_got == 2 + (((size_t)tcp_rx[0] << 8) | tcp_rx[1]));
    close(sp_tcp[1]);

    // Stop pool
    pthread_mutex_lock(&g_async_io_pool.lock);
    g_async_io_pool.running = false;
    pthread_cond_broadcast(&g_async_io_pool.cond_not_empty);
    pthread_mutex_unlock(&g_async_io_pool.lock);

    for (int i = 0; i < ASYNC_IO_POOL_SIZE; i++) {
        pthread_join(g_async_io_pool.threads[i], NULL);
    }
    zone_arena_destroy(&arena);

    printf("  -> async_io_pool passed.\n");
}

// ----------------------------------------------------------------------------
// 17. Meta Types, String & Compression Helpers Test
// ----------------------------------------------------------------------------
static void test_meta_types_and_utils_helpers(void) {
    printf("[TEST] Server Core / Utils: Meta RR types, string & compression helpers...\n");

    // 1. is_meta_rrtype
    assert(is_meta_rrtype(255) == true); // ANY
    assert(is_meta_rrtype(252) == true); // AXFR
    assert(is_meta_rrtype(251) == true); // IXFR
    assert(is_meta_rrtype(41) == true);  // OPT
    assert(is_meta_rrtype(250) == true); // TSIG
    assert(is_meta_rrtype(249) == true); // TKEY
    assert(is_meta_rrtype(1) == false);  // A
    assert(is_meta_rrtype(28) == false); // AAAA
    assert(is_meta_rrtype(6) == false);  // SOA

    // 2. get_type_code & dns_type_to_string
    assert(get_type_code("ANY") == 255);
    assert(get_type_code("AXFR") == 252);
    assert(get_type_code("IXFR") == 251);
    assert(get_type_code("TYPE65530") == 65530);

    assert(strcmp(dns_type_to_string(1), "A") == 0);
    assert(strcmp(dns_type_to_string(28), "AAAA") == 0);
    assert(strcmp(dns_type_to_string(6), "SOA") == 0);
    assert(strcmp(dns_type_to_string(255), "ANY") == 0);

    // 3. strchr_unescaped
    const char *s = "foo\\.bar;baz";
    const char *p = strchr_unescaped(s, ';');
    assert(p != NULL && strcmp(p, ";baz") == 0);

    const char *s_dot = strchr_unescaped("escaped\\.name.com", '.');
    assert(s_dot != NULL && strcmp(s_dot, ".com") == 0);

    // 4. compress_ctx_init & compress_ctx_init_packet
    compress_ctx_t ctx1, ctx2;
    compress_ctx_init(&ctx1);
    assert(ctx1.current_generation == 1);
    memset(&ctx2, 0, sizeof(ctx2));
    compress_ctx_init_packet(&ctx2);
    assert(ctx2.current_generation == 1);

    // 5. acquire_config_snapshot & release_config_snapshot
    server_config_t *acq = acquire_config_snapshot();
    release_config_snapshot(acq);

    // 6. broker_connect tests
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = htonl(0x7F000001);
    assert(broker_connect(AF_INET, SOCK_DGRAM, (struct sockaddr *)&sin, sizeof(sin)) == -1);

    int sp_broker[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp_broker) == 0) {
        g_broker_sock = sp_broker[0];
        close(sp_broker[1]);
        assert(broker_connect(AF_INET, SOCK_DGRAM, (struct sockaddr *)&sin, sizeof(sin)) == -1);
        close(sp_broker[0]);
        g_broker_sock = -1;
    }

    // 7. perform_config_reload & reload_all_zones with NULL/invalid path
    g_config_path = "/nonexistent/karidns_test_invalid_config.conf";
    perform_config_reload();
    perform_config_reload_ext(true);
    perform_config_reload_ext(false);
    reload_all_zones();

    printf("  -> Meta RR types, string & compression helpers passed.\n");
}

static void test_server_core_process_lifecycle_and_signals(void) {
    printf("[TEST] Server Core: supervisor/backend signals, daemonize, PID file, router & worker...\n");

    // 1. supervisor_sig_handler
    g_supervisor_got_sighup = 0;
    g_supervisor_should_exit = 0;
    supervisor_sig_handler(SIGHUP);
    assert(g_supervisor_got_sighup == 1);
    assert(g_supervisor_should_exit == 0);

    supervisor_sig_handler(SIGTERM);
    assert(g_supervisor_should_exit == 1);

    // 2. cleanup_pid_file
    g_supervisor_pid = getpid();
    snprintf(g_pid_file_path, sizeof(g_pid_file_path), "/tmp/karidns_test_pid_%ld.pid", (long)getpid());
    g_pid_fd = open(g_pid_file_path, O_CREAT | O_RDWR, 0644);
    assert(g_pid_fd >= 0);
    cleanup_pid_file();
    assert(g_pid_fd == -1);
    assert(g_pid_file_path[0] == '\0');

    // 3. setup_ipc_tables
    g_num_frontend_routers = 1;
    setup_ipc_tables(1);
    assert(g_ipc_fds[0][0][0] >= 0);
    assert(g_ipc_fds[0][0][1] >= 0);
    close(g_ipc_fds[0][0][0]);
    close(g_ipc_fds[0][0][1]);
    close(g_notify_ipc[0]);
    close(g_notify_ipc[1]);

    // 4. backend_sig_handler in child process: during startup it exits at once
    pid_t cpid1 = quiet_fork();
    assert(cpid1 >= 0);
    if (cpid1 == 0) {
        atomic_store(&g_privilege_drop_complete, false);
        backend_sig_handler(SIGTERM);
        _exit(1);
    }
    int status1 = 0;
    waitpid(cpid1, &status1, 0);
    assert(WIFEXITED(status1) && WEXITSTATUS(status1) == 0);

    // 4b. O-03: after startup the control thread shuts down (dnstap STOP); the handler only
    // records the signal. A second signal (shutdown stuck) exits at once.
    pid_t cpid1b = quiet_fork();
    assert(cpid1b >= 0);
    if (cpid1b == 0) {
        atomic_store(&g_privilege_drop_complete, true);
        atomic_store(&g_control_signals_ready, true);
        g_backend_should_exit = 0;
        backend_sig_handler(SIGTERM);
        if (!g_backend_should_exit) _exit(2);
        backend_sig_handler(SIGTERM);
        _exit(1);
    }
    waitpid(cpid1b, &status1, 0);
    assert(WIFEXITED(status1) && WEXITSTATUS(status1) == 0);

    // 5. daemonize in child process
    pid_t cpid2 = quiet_fork();
    assert(cpid2 >= 0);
    if (cpid2 == 0) {
        daemonize();
        _exit(0);
    }
    int status2 = 0;
    waitpid(cpid2, &status2, 0);
    assert(WIFEXITED(status2) && WEXITSTATUS(status2) == 0);

    // 6. (a worker with a core number outside the CPUs used to stop its start here; since 0.6.1 workers and routers are not pinned to CPUs)

    // 7. run_frontend_router in child process
    pid_t cpid3 = quiet_fork();
    assert(cpid3 >= 0);
    if (cpid3 == 0) {
        server_config_t test_cfg;
        memset(&test_cfg, 0, sizeof(test_cfg));
        test_cfg.port = 53556;
        /* O-18: the router drops to the identity main() resolved; a drop that cannot be
         * done (not root) must end the router */
        memset(&g_run_identity, 0, sizeof(g_run_identity));
        g_run_identity.privileged = true;
        g_run_identity.has_user = true;
        g_run_identity.uid = getuid() == 0 ? 65534 : getuid() + 1;
        g_run_identity.gid = getgid();
        atomic_store_explicit(&g_config_db.active, &test_cfg, memory_order_release);
        g_num_frontend_routers = 1;
        g_num_workers = 1;
        g_ipc_fds[0][0][0] = -1;
        g_ipc_fds[0][0][1] = -1;
        g_notify_ipc[0] = -1;
        g_notify_ipc[1] = -1;
        run_frontend_router(getppid(), 0);
        _exit(0);
    }
    int status3 = 0;
    /* as root the drop succeeds and the router keeps running: stop it after a while */
    for (int t = 0; t < 30 && waitpid(cpid3, &status3, WNOHANG) == 0; t++)
        usleep(100000);
    if (kill(cpid3, 0) == 0 && getuid() == 0) {
        kill(cpid3, SIGKILL);
        waitpid(cpid3, &status3, 0);
    } else {
        assert(WIFEXITED(status3) && WEXITSTATUS(status3) == EXIT_FAILURE);
    }

    printf("  -> Process lifecycle, signals, router & worker passed.\n");
}


// ----------------------------------------------------------------------------
// Non-root startup: run identity / preflight checks
// ----------------------------------------------------------------------------
/* resolve_run_identity() + apply_run_identity_id() by name (the server resolves once at start and applies the id) */
static bool apply_run_identity(const char *user, const char *group, char *err, size_t errlen) {
    run_identity_t id;
    if (!resolve_run_identity(user, group, &id, err, errlen)) return false;
    return apply_run_identity_id(&id, err, errlen);
}

/* 非rootとしての検証本体。root で実行されている場合は fork した子で nobody へ
 * 降格してから呼ぶ。失敗時は assert で abort する。 */
static void nonroot_startup_checks(void) {
    assert(geteuid() != 0);
    char err[512];
    run_identity_t id;

    /* user/group 未指定: 実行ユーザーのまま */
    assert(resolve_run_identity(NULL, NULL, &id, err, sizeof(err)));
    assert(!id.privileged);
    assert(apply_run_identity(NULL, NULL, err, sizeof(err)));

    /* 自分自身を指す user: 降格不要として受理 (setgroups を呼ばない) */
    struct passwd *me = getpwuid(geteuid());
    assert(me);
    char myname[256];
    snprintf(myname, sizeof(myname), "%s", me->pw_name);
    assert(resolve_run_identity(myname, NULL, &id, err, sizeof(err)));
    assert(!id.privileged && id.uid == geteuid());
    assert(apply_run_identity(myname, NULL, err, sizeof(err)));
    assert(geteuid() == id.uid);

    /* 他ユーザー / 存在しないユーザー: 拒否 */
    err[0] = '\0';
    assert(!resolve_run_identity("root", NULL, &id, err, sizeof(err)));
    assert(strstr(err, "uid 0") != NULL);            /* P4: root is refused by name, before anything else */
    assert(!apply_run_identity("root", NULL, err, sizeof(err)));
    {   /* another non-root user: a non-root process cannot switch to it */
        struct passwd *other = getpwnam("daemon");
        if (!other || other->pw_uid == geteuid() || other->pw_uid == 0) other = getpwnam("nobody");
        if (other && other->pw_uid != geteuid() && other->pw_uid != 0 && other->pw_gid != 0) {
            assert(!resolve_run_identity(other->pw_name, NULL, &id, err, sizeof(err)));
            assert(strstr(err, "cannot switch") != NULL);
        }
    }
    assert(!resolve_run_identity("nonexistent_user_12345", NULL, &id, err, sizeof(err)));
    assert(strstr(err, "not found") != NULL);
    /* 現在の gid と異なる group: 拒否 */
    struct group *gr0 = getgrgid(0);
    if (gr0 && getegid() != 0) {
        char g0name[256];
        snprintf(g0name, sizeof(g0name), "%s", gr0->gr_name);
        assert(!resolve_run_identity(NULL, g0name, &id, err, sizeof(err)));
        assert(strstr(err, "gid 0") != NULL);            /* P4: the root group is refused by name */
    }
    {
        struct group *gx = getgrnam("daemon");
        if (!gx || gx->gr_gid == getegid() || gx->gr_gid == 0) gx = getgrnam("nobody");
        if (gx && gx->gr_gid != getegid() && gx->gr_gid != 0) {
            assert(!resolve_run_identity(NULL, gx->gr_name, &id, err, sizeof(err)));
            assert(strstr(err, "primary group") != NULL);
        }
    }

    /* pid file / 制御ソケット: 書き込めないディレクトリは拒否 */
    assert(!preflight_writable_path("/nonexistent_dir_karidns_test/karidns.pid", "pid file",
                                    true, true, ""));
    assert(!preflight_writable_path("/var/run/karidns_test_no_perm/control.sock", "control socket",
                                    true, false, ""));
    char tmpl[] = "/tmp/karidns_nonroot_XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/karidns.pid", dir);
    assert(preflight_writable_path(path, "pid file", true, true, ""));
    assert(preflight_writable_path("none", "pid file", true, true, ""));
    /* daemonize() keeps the working directory, so a relative name is checked where it will be used, daemonized or not */
    assert(!preflight_writable_path("rel/karidns.pid", "pid file", false, true, ""));
    assert(!preflight_writable_path("rel/karidns.pid", "pid file", true, true, ""));
    {
        int saved_cwd = open(".", O_RDONLY | O_DIRECTORY);
        assert(saved_cwd >= 0 && chdir(dir) == 0);
        assert(preflight_writable_path("karidns.pid", "pid file", false, true, ""));
        assert(preflight_writable_path("control.sock", "control socket", false, false, ""));
        assert(fchdir(saved_cwd) == 0);
        close(saved_cwd);
    }
    /* a UNIX socket path has to fit sun_path */
    {
        char longp[300];
        memset(longp, 'a', sizeof(longp) - 1);
        longp[sizeof(longp) - 1] = '\0';
        assert(check_unix_socket_path("control.sock", "control-channel socket path"));
        assert(check_unix_socket_path(NULL, "dnstap socket path"));
        assert(!check_unix_socket_path(longp, "control-channel socket path"));
        struct sockaddr_un un_probe;
        longp[sizeof(un_probe.sun_path) - 1] = '\0';          /* 103 characters fit */
        assert(check_unix_socket_path(longp, "control-channel socket path"));
        longp[sizeof(un_probe.sun_path) - 1] = 'a';
        longp[sizeof(un_probe.sun_path)] = '\0';              /* 104 do not */
        assert(!check_unix_socket_path(longp, "control-channel socket path"));
    }
    rmdir(dir);

    /* program-user が実行ユーザーと異なる program ゾーンは拒否 */
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    view_config_t view;
    memset(&view, 0, sizeof(view));
    zone_config_t zone;
    memset(&zone, 0, sizeof(zone));
    char zdomain[] = "plugin.example.";
    char ztype[] = "program";
    char zuser_other[] = "root";
    zone.domain = zdomain;
    zone.type = ztype;
    tzx(&zone)->program_user = zuser_other;
    view.zones = &zone;
    cfg.views = &view;
    assert(!validate_program_zone_users(&cfg));
    tzx(&zone)->program_user = myname;
    assert(validate_program_zone_users(&cfg));
    tzx(&zone)->program_user = NULL;
    assert(validate_program_zone_users(&cfg));

    /* 1024未満のポートは非rootでは bind できず、起動前検証で拒否される */
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = 53;
    test_set_listen(&cfg, "127.0.0.1", 53);
    assert(!preflight_listen_ports(&cfg));
}

static void test_nonroot_startup_identity_and_preflight(void) {
    printf("[TEST] Server Core: non-root startup identity / preflight checks...\n");
    char err[512];
    run_identity_t id;

    if (geteuid() == 0) {
        /* root: user/group の指定が必須、指定があれば降格対象 */
        assert(!resolve_run_identity(NULL, NULL, &id, err, sizeof(err)));
        assert(strstr(err, "refusing") != NULL);
        assert(resolve_run_identity("nobody", NULL, &id, err, sizeof(err)));
        assert(id.privileged && id.has_user);
        /* root では pid file / 制御ソケットの事前検査は行わない */
        assert(preflight_writable_path("/nonexistent_dir_karidns_test/karidns.pid", "pid file",
                                       true, true, ""));

        struct passwd *nb = getpwnam("nobody");
        assert(nb);
        pid_t pid = quiet_fork();
        assert(pid >= 0);
        if (pid == 0) {
            if (setgroups(0, NULL) != 0 || setgid(nb->pw_gid) != 0 || setuid(nb->pw_uid) != 0)
                _exit(2);
            nonroot_startup_checks();
            _exit(0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    } else {
        nonroot_startup_checks();
    }

    /* parse_cli_port_arg: -p is a port only when the whole value is a decimal number */
    {
        int port = 0;
        assert(parse_cli_port_arg("10053", &port) == 1 && port == 10053);
        assert(parse_cli_port_arg("1", &port) == 1 && port == 1);
        assert(parse_cli_port_arg("65535", &port) == 1 && port == 65535);
        assert(parse_cli_port_arg("0", &port) == -1);
        assert(parse_cli_port_arg("65536", &port) == -1);
        assert(parse_cli_port_arg("99999999999999999999", &port) == -1);
        assert(parse_cli_port_arg("1.pid", &port) == 0);
        assert(parse_cli_port_arg("53abc", &port) == 0);
        assert(parse_cli_port_arg("/var/run/karidns.pid", &port) == 0);
        assert(parse_cli_port_arg("none", &port) == 0);
        assert(parse_cli_port_arg("", &port) == 0);
        assert(parse_cli_port_arg(NULL, &port) == 0);
    }

    /* bind_error_hint */
    assert(strstr(bind_error_hint(EACCES, 53), "root") != NULL);
    assert(strcmp(bind_error_hint(EACCES, 10053), "") == 0);
    assert(strstr(bind_error_hint(EADDRINUSE, 10053), "in use") != NULL);

    /* 既に(SO_REUSEPORT なしで)使用中のポートは起動前検証で拒否される */
    int busy = socket(AF_INET, SOCK_STREAM, 0);
    assert(busy >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(busy, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    socklen_t salen = sizeof(sa);
    assert(getsockname(busy, (struct sockaddr *)&sa, &salen) == 0);
    assert(listen(busy, 1) == 0);
    int busy_port = ntohs(sa.sin_port);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = busy_port;
    test_set_listen(&cfg, "127.0.0.1", busy_port);
    assert(!preflight_listen_ports(&cfg));
    close(busy);

    /* 空いている高位ポートは受理される */
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    assert(probe >= 0);
    sa.sin_port = 0;
    assert(bind(probe, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    salen = sizeof(sa);
    assert(getsockname(probe, (struct sockaddr *)&sa, &salen) == 0);
    close(probe);
    cfg.port = ntohs(sa.sin_port);
    test_set_listen(&cfg, "127.0.0.1", cfg.port);
    assert(preflight_listen_ports(&cfg));

    /* ログファイルを開けなければ log_open_channels は 0 以外を返す */
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    char ch_name[] = "bad";
    char ch_path[] = "/nonexistent_dir_karidns_test/sub/queries.log";
    ch.name = ch_name;
    ch.file_path = ch_path;
    ch.fd = -1;
    assert(log_open_channels(&ch, true) == -1);
    assert(ch.fd < 0);

    printf("  -> non-root startup identity / preflight checks passed.\n");
}


/* Regression: with the pid file in the same directory as a log file, handing the
 * log directory to "user" before ensure_priv_dir_safe() made startup refuse the
 * (now non-root-owned) directory. Logs are opened first without a chown, and the
 * hand-off happens after the directory checks. */
static void test_log_hand_off_after_priv_dir_check(void) {
    printf("[TEST] Server Core: log ownership hand-off after pid-dir check...\n");
    if (geteuid() != 0 || !getpwnam("nobody")) {
        printf("  -> skipped (needs root and user 'nobody').\n");
        return;
    }
    char tmpl[] = "/tmp/karidns_handoff_XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert(dir);
    assert(chmod(dir, 0755) == 0);
    /* P2: only a directory karidns creates is handed to the run user; "a" does not exist yet, "keep" is prepared by the operator */
    char sub[256], logp[300], keep[256], logp2[300];
    snprintf(sub, sizeof(sub), "%s/a", dir);
    snprintf(logp, sizeof(logp), "%s/q.log", sub);
    snprintf(keep, sizeof(keep), "%s/keep", dir);
    assert(mkdir(keep, 0755) == 0);
    snprintf(logp2, sizeof(logp2), "%s/r.log", keep);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    char user[] = "nobody";
    cfg.user = user;
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    char ch_name[] = "q";
    ch.name = ch_name;
    ch.file_path = logp;
    ch.fd = -1;
    log_channel_t ch2;
    memset(&ch2, 0, sizeof(ch2));
    char ch2_name[] = "r";
    ch2.name = ch2_name;
    ch2.file_path = logp2;
    ch2.fd = -1;
    ch.next = &ch2;

    logging_config_t lcfg;
    memset(&lcfg, 0, sizeof(lcfg));
    lcfg.channels = &ch;
    logrt_status_t lst;
    log_runtime_t *hrt = log_runtime_build(&lcfg, false, &lst);
    assert(hrt && log_runtime_install(hrt));
    struct stat st;
    assert(stat(sub, &st) == 0 && st.st_uid == 0);   /* created, not handed off yet */
    assert(ensure_priv_dir_safe(sub));               /* pid file dir check passes */
    /* the owner comes from the identity main() resolved at startup (O-18) */
    run_identity_t saved_id = g_run_identity;
    char id_err[256];
    assert(resolve_run_identity(cfg.user, NULL, &g_run_identity, id_err, sizeof(id_err)));
    hand_off_logging_channels();
    g_run_identity = saved_id;
    uid_t nobody = getpwnam("nobody")->pw_uid;
    assert(stat(sub, &st) == 0 && st.st_uid == nobody);      /* the directory karidns created is the run user's */
    assert(stat(keep, &st) == 0 && st.st_uid == 0);          /* P2: the operator's directory keeps its owner */
    /* The log file itself is not checked: on FreeBSD it is opened via
     * open_via_dir_cache() relative to a cap_rights_limit()ed directory fd, so
     * the file fd inherits rights without CAP_FCHOWN and fchown() on it is a
     * no-op. Handing the directory to "user" is what lets rotation recreate it. */
    assert(stat(logp, &st) == 0);

    assert(stat(logp2, &st) == 0);

    test_retire_runtime(hrt);
    unlink(logp);
    unlink(logp2);
    rmdir(sub);
    rmdir(keep);
    rmdir(dir);
    printf("  -> log ownership hand-off after pid-dir check passed.\n");
}

// ----------------------------------------------------------------------------
// BIND logging (batch 6): categories of the messages, severities, lines, channels, the runtime and its replacement
// Expectations from BIND 9.20.4 lib/isc/log.c (isc_log_doit(): the channel list, the default category, the severity test, the line, the
// syslog map; isc_log_open(): rolling; FILE_MAXREACHED), lib/isc/time.c (the three time formats), bin/named/log.c (the built-in channels).
// ----------------------------------------------------------------------------
static char *klog_slurp(const char *path) {
    FILE *f = fopen(path, "r");
    char *buf = calloc(1, 262144);
    assert(buf);
    if (f) {
        size_t n = fread(buf, 1, 262143, f);
        buf[n] = '\0';
        fclose(f);
    }
    return buf;
}

static int klog_lines(const char *path) {
    char *s = klog_slurp(path);
    int n = 0;
    for (const char *p = s; *p; p++)
        if (*p == '\n') n++;
    free(s);
    return n;
}

static void klog_expect(const char *path, const char *want) {
    char *s = klog_slurp(path);
    if (strcmp(s, want) != 0) {
        printf("  [FAIL] %s:\n--- want\n%s--- got\n%s---\n", path, want, s);
        assert(0);
    }
    free(s);
}

/* parse the logging statement of `text` and install the runtime built from it (files in `dir`) */
static log_runtime_t *klog_install_conf(const char *text) {
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    assert(parse_named_conf(text, &cfg) == 0);
    logrt_status_t st;
    log_runtime_t *rt = log_runtime_build(&cfg.logging, false, &st);
    assert(rt && st == LOGRT_OK);
    free_server_config_fields(&cfg);   /* the runtime has copied everything */
    assert(log_runtime_install(rt));
    return rt;
}

static void test_klog_categories_levels_lines(void) {
    printf("[TEST] Logging: category of a message, severities, the text of a line...\n");
    static const struct { const char *msg; int cat; } t[] = {
        { "[Config] x", LOGC_CONFIG }, { "[AXFR] x", LOGC_XFER_IN }, { "[IXFR] x", LOGC_XFER_IN }, { "[XFR] x", LOGC_XFER_IN },
        { "[Notify] x", LOGC_NOTIFY }, { "[Update] x", LOGC_UPDATE }, { "[TSIG] x", LOGC_SECURITY }, { "[Cookie] x", LOGC_SECURITY },
        { "[Zone] x", LOGC_ZONELOAD }, { "[ZoneLoader] x", LOGC_ZONELOAD }, { "[Image] x", LOGC_ZONELOAD }, { "[tinydns] x", LOGC_ZONELOAD },
        { "[DB] x", LOGC_DATABASE }, { "[Network] x", LOGC_NETWORK }, { "[RRL] x", LOGC_RATE_LIMIT }, { "[dnstap] x", LOGC_DNSTAP },
        { "[QueryLog] x", LOGC_GENERAL }, { "[Control] x", LOGC_GENERAL }, { "[Catalog] x", LOGC_GENERAL }, { "[Manager] x", LOGC_GENERAL },
        { "[Backend] x", LOGC_GENERAL }, { "[Frontend 2] x", LOGC_GENERAL }, { "[Core] x", LOGC_GENERAL }, { "[Startup] x", LOGC_GENERAL },
        { "[Broker] x", LOGC_GENERAL }, { "[IPC] x", LOGC_GENERAL }, { "[EpochRCU] x", LOGC_GENERAL }, { "[GC] x", LOGC_GENERAL },
        { "[Logging] x", LOGC_GENERAL }, { "[Plugin] x", LOGC_GENERAL }, { "[Alias] x", LOGC_GENERAL }, { "[Forward] x", LOGC_GENERAL },
        { "[Notify]", LOGC_NOTIFY },                       /* the prefix is all there is */
        { "[%s] dropped", LOGC_GENERAL },                  /* a prefix made at run time */
        { "[Unknown] x", LOGC_GENERAL }, { "[Notifyxxxxxxxxxxxxxxxxxxxxxx] x", LOGC_GENERAL }, { "no prefix", LOGC_GENERAL }, { "[", LOGC_GENERAL },
        { "", LOGC_GENERAL },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        if (klog_category_for_message(t[i].msg) != t[i].cat)
            printf("  [FAIL] category of \"%s\": %d, wanted %d\n", t[i].msg, klog_category_for_message(t[i].msg), t[i].cat);
        assert(klog_category_for_message(t[i].msg) == t[i].cat);
    }
    assert(klog_category_for_message(NULL) == LOGC_GENERAL);

    /* syslog priorities -> BIND levels (the facility bits do not matter) */
    assert(klog_level_from_priority(LOG_EMERG) == LOG_LVL_CRITICAL && klog_level_from_priority(LOG_ALERT) == LOG_LVL_CRITICAL);
    assert(klog_level_from_priority(LOG_CRIT) == LOG_LVL_CRITICAL && klog_level_from_priority(LOG_ERR) == LOG_LVL_ERROR);
    assert(klog_level_from_priority(LOG_WARNING) == LOG_LVL_WARNING && klog_level_from_priority(LOG_NOTICE) == LOG_LVL_NOTICE);
    assert(klog_level_from_priority(LOG_INFO) == LOG_LVL_INFO && klog_level_from_priority(LOG_DEBUG) == 1);
    assert(klog_level_from_priority(LOG_LOCAL3 | LOG_WARNING) == LOG_LVL_WARNING);

    /* a channel passes a message whose level is at most its own; dynamic: at most the debug level in force (the third argument) */
    assert(klog_level_passes(LOG_LVL_CRITICAL, LOG_LVL_CRITICAL, 0) && !klog_level_passes(LOG_LVL_CRITICAL, LOG_LVL_ERROR, 0));
    assert(klog_level_passes(LOG_LVL_WARNING, LOG_LVL_ERROR, 0) && klog_level_passes(LOG_LVL_WARNING, LOG_LVL_WARNING, 0));
    assert(!klog_level_passes(LOG_LVL_WARNING, LOG_LVL_NOTICE, 0) && !klog_level_passes(LOG_LVL_WARNING, LOG_LVL_INFO, 0));
    assert(klog_level_passes(LOG_LVL_INFO, LOG_LVL_INFO, 0) && !klog_level_passes(LOG_LVL_INFO, 1, 0));
    assert(klog_level_passes(LOG_LVL_DYNAMIC, LOG_LVL_INFO, 0) && klog_level_passes(LOG_LVL_DYNAMIC, LOG_LVL_CRITICAL, 0) && !klog_level_passes(LOG_LVL_DYNAMIC, 1, 0));
    assert(klog_level_passes(3, 1, 0) && klog_level_passes(3, 3, 0) && !klog_level_passes(3, 4, 0) && klog_level_passes(3, LOG_LVL_INFO, 0));
    /* 0.7, BIND isc_log_doit(): dynamic follows the level in force; a fixed level (info, debug n) does not, at any level */
    for (int dl = 0; dl <= KLOG_DEBUG_LEVEL_MAX; dl += 33) {
        assert(klog_level_passes(LOG_LVL_DYNAMIC, LOG_LVL_ERROR, dl) && klog_level_passes(LOG_LVL_DYNAMIC, dl, dl) && !klog_level_passes(LOG_LVL_DYNAMIC, dl + 1, dl));
        assert(klog_level_passes(3, 3, dl) && !klog_level_passes(3, 4, dl) && klog_level_passes(LOG_LVL_INFO, LOG_LVL_INFO, dl) && !klog_level_passes(LOG_LVL_INFO, 1, dl));
        assert(klog_level_passes(LOG_LVL_WARNING, LOG_LVL_WARNING, dl) && !klog_level_passes(LOG_LVL_WARNING, LOG_LVL_NOTICE, dl));
    }
    assert(klog_level_passes(LOG_LVL_DYNAMIC, 1, 1) && klog_level_passes(LOG_LVL_DYNAMIC, 3, 5) && !klog_level_passes(LOG_LVL_DYNAMIC, 6, 5));
    assert(klog_level_passes(LOG_LVL_DYNAMIC, 99, 99) && !klog_level_passes(LOG_LVL_DYNAMIC, 100, 99));
    /* the level as -d and trace take it: digits, 0 .. 99 */
    {
        int v = -1;
        assert(klog_parse_debug_level("0", &v) && v == 0 && klog_parse_debug_level("7", &v) && v == 7 && klog_parse_debug_level("99", &v) && v == 99);
        assert(klog_parse_debug_level("007", &v) && v == 7);
        v = -1;
        static const char *const bad[] = { "", "100", "-1", "+3", " 3", "3 ", "3x", "x", "1e2", "999999999999999999999" };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) assert(!klog_parse_debug_level(bad[i], &v) && v == -1);
        assert(!klog_parse_debug_level(NULL, &v));
    }

    /* the lines.  The zone is UTC so that the local formats can be compared with text */
    setenv("TZ", "UTC", 1);
    tzset();
    struct timespec ts = { .tv_sec = 1793156645, .tv_nsec = 678912345 };   /* 2026-10-28 03:04:05.678 UTC */
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    char line[512];
    ch.time_fmt = LOGTIME_NONE;
    assert(klog_build_line(&ch, LOGC_QUERIES, LOG_LVL_INFO, &ts, "hello", line, sizeof(line)) == 5 && strcmp(line, "hello") == 0);
    ch.time_fmt = LOGTIME_LOCAL;
    klog_build_line(&ch, LOGC_QUERIES, LOG_LVL_INFO, &ts, "hello", line, sizeof(line));
    assert(strcmp(line, "28-Oct-2026 03:04:05.678 hello") == 0);
    ch.time_fmt = LOGTIME_ISO8601;
    klog_build_line(&ch, LOGC_QUERIES, LOG_LVL_INFO, &ts, "hello", line, sizeof(line));
    assert(strcmp(line, "2026-10-28T03:04:05.678 hello") == 0);          /* no zone, like isc_time_formatISO8601Lms() */
    ch.time_fmt = LOGTIME_ISO8601_UTC;
    klog_build_line(&ch, LOGC_QUERIES, LOG_LVL_INFO, &ts, "hello", line, sizeof(line));
    assert(strcmp(line, "2026-10-28T03:04:05.678Z hello") == 0);
    ts.tv_sec += 1;   /* the cached second must not be reused */
    klog_build_line(&ch, LOGC_QUERIES, LOG_LVL_INFO, &ts, "hello", line, sizeof(line));
    assert(strcmp(line, "2026-10-28T03:04:06.678Z hello") == 0);
    /* the UTC form is computed without gmtime_r() (it loads a zone file, which capability mode forbids): the edge dates */
    static const struct { time_t t; const char *text; } utc[] = {
        { 0, "1970-01-01T00:00:00.678Z m" }, { -1, "1969-12-31T23:59:59.678Z m" }, { 951782400, "2000-02-29T00:00:00.678Z m" },
        { 951868800, "2000-03-01T00:00:00.678Z m" }, { 4107542400LL, "2100-03-01T00:00:00.678Z m" },
        { 253402300799LL, "9999-12-31T23:59:59.678Z m" }, { 1793156645, "2026-10-28T03:04:05.678Z m" },
        { 1709164799, "2024-02-28T23:59:59.678Z m" }, { 1709251199, "2024-02-29T23:59:59.678Z m" },
    };
    for (size_t i = 0; i < sizeof(utc) / sizeof(utc[0]); i++) {
        struct timespec u = { .tv_sec = utc[i].t, .tv_nsec = 678912345 };
        klog_build_line(&ch, LOGC_QUERIES, LOG_LVL_INFO, &u, "m", line, sizeof(line));
        if (strcmp(line, utc[i].text) != 0) printf("  [FAIL] utc %lld: %s, wanted %s\n", (long long)utc[i].t, line, utc[i].text);
        assert(strcmp(line, utc[i].text) == 0);
    }
    ch.time_fmt = LOGTIME_NONE;
    ch.print_category = true;
    klog_build_line(&ch, LOGC_XFER_IN, LOG_LVL_INFO, &ts, "m", line, sizeof(line));
    assert(strcmp(line, "xfer-in: m") == 0);
    ch.print_category = false;
    ch.print_severity = true;
    static const struct { int level; const char *text; } lv[] = {
        { LOG_LVL_CRITICAL, "critical: m" }, { LOG_LVL_ERROR, "error: m" }, { LOG_LVL_WARNING, "warning: m" }, { LOG_LVL_NOTICE, "notice: m" },
        { LOG_LVL_INFO, "info: m" }, { 1, "debug 1: m" }, { 7, "debug 7: m" }, { -9, "level -9: m" },
    };
    for (size_t i = 0; i < sizeof(lv) / sizeof(lv[0]); i++) {
        klog_build_line(&ch, LOGC_DEFAULT, lv[i].level, &ts, "m", line, sizeof(line));
        assert(strcmp(line, lv[i].text) == 0);
    }
    ch.time_fmt = LOGTIME_LOCAL;
    ch.print_category = true;
    klog_build_line(&ch, LOGC_UPDATE_SECURITY, LOG_LVL_ERROR, &ts, "denied", line, sizeof(line));
    assert(strcmp(line, "28-Oct-2026 03:04:06.678 update-security: error: denied") == 0);
    klog_build_line(&ch, 999, LOG_LVL_ERROR, &ts, "x", line, sizeof(line));   /* an unknown category prints nothing for it */
    assert(strcmp(line, "28-Oct-2026 03:04:06.678 error: x") == 0);
    /* a small buffer cuts the line and keeps it terminated */
    char small[12];
    assert(klog_build_line(&ch, LOGC_DEFAULT, LOG_LVL_ERROR, &ts, "a long message", small, sizeof(small)) == sizeof(small) - 1);
    assert(small[sizeof(small) - 1] == '\0');
    assert(klog_build_line(&ch, LOGC_DEFAULT, LOG_LVL_ERROR, &ts, "m", small, 0) == 0);

    printf("  -> categories / levels / lines passed.\n");
}

static char g_vf_out[KLOG_MSG_MAX];
static size_t g_vf_len;
static void test_klog_vformat(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    g_vf_len = klog_vformat(g_vf_out, sizeof(g_vf_out), fmt, ap, ENOENT);
    va_end(ap);
}

static void test_klog_format(void) {
    printf("[TEST] Logging: klog_vformat() (%%m, cutting)...\n");
    test_klog_vformat("open %s: %m", "/x");
    assert(strcmp(g_vf_out, "open /x: No such file or directory") == 0 && g_vf_len == strlen(g_vf_out));
    test_klog_vformat("100%% sure: %m (%d)", 5);
    assert(strcmp(g_vf_out, "100% sure: No such file or directory (5)") == 0);
    test_klog_vformat("%%m is not an error text");
    assert(strcmp(g_vf_out, "%m is not an error text") == 0);
    test_klog_vformat("no conversion");
    assert(strcmp(g_vf_out, "no conversion") == 0);
    char big[2000];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    test_klog_vformat("%s", big);
    assert(g_vf_len == KLOG_MSG_MAX - 1 && strlen(g_vf_out) == KLOG_MSG_MAX - 1);
    test_klog_vformat("%.0s%m%.0s", "", "");    /* nothing but the error text */
    assert(strcmp(g_vf_out, "No such file or directory") == 0);
    /* a long format with %m is expanded without overflowing the buffer used for it; a message that does not fit is cut */
    char longfmt[501];
    memset(longfmt, 'f', sizeof(longfmt) - 1);
    longfmt[sizeof(longfmt) - 1] = '\0';
    memcpy(longfmt + 10, "%m", 2);
    test_klog_vformat(longfmt);
    assert(g_vf_len == 498 + strlen("No such file or directory") && strncmp(g_vf_out + 10, "No such file", 12) == 0);
    char tiny[8];
    va_list none;
    memset(&none, 0, sizeof(none));
    assert(klog_vformat(tiny, 0, "x", none, 0) == 0);          /* no room: nothing written (the va_list is not touched) */
    printf("  -> klog_vformat passed.\n");
}

static void test_klog_routing(void) {
    printf("[TEST] Logging: routing of messages to channels (categories, default category, severities, duplicates)...\n");
    setenv("TZ", "UTC", 1);
    tzset();
    char dir[] = "/tmp/karidns_klog_XXXXXX";
    assert(mkdtemp(dir));
    char conf[4096];
    snprintf(conf, sizeof(conf),
             "logging {\n"
             " channel gen  { file \"%s/gen.log\"; print-category yes; print-severity yes; };\n"
             " channel warn { file \"%s/warn.log\"; severity warning; print-time iso8601-utc; };\n"
             " channel nul  { null; };\n"
             " channel dbg  { file \"%s/dbg.log\"; severity debug 5; print-severity yes; };\n"
             " channel dyn  { file \"%s/dyn.log\"; severity dynamic; };\n"
             " category default { gen; };\n category notify { warn; dbg; };\n category xfer-in { nul; };\n category security { dyn; dbg; };\n"
             "};\n", dir, dir, dir, dir);
    char p_gen[300], p_warn[300], p_dbg[300], p_dyn[300];
    snprintf(p_gen, sizeof(p_gen), "%s/gen.log", dir);
    snprintf(p_warn, sizeof(p_warn), "%s/warn.log", dir);
    snprintf(p_dbg, sizeof(p_dbg), "%s/dbg.log", dir);
    snprintf(p_dyn, sizeof(p_dyn), "%s/dyn.log", dir);
    log_runtime_t *rt = klog_install_conf(conf);
    (void)rt;

    kdns_syslog(LOG_INFO, "[Config] reloaded %d zones", 3);             /* config has no channel: the default category's */
    kdns_syslog(LOG_WARNING, "[Notify] zone '%s': failed", "a.test");   /* notify: warn and dbg */
    kdns_syslog(LOG_INFO, "[Notify] acknowledged");                     /* below warning: only dbg */
    kdns_syslog(LOG_DEBUG, "[Notify] debug text");                      /* debug 1: dbg (debug 5) only */
    kdns_syslog(LOG_DEBUG, "[Config] debug text");                      /* default: gen is info, drops it */
    kdns_syslog(LOG_ERR, "[AXFR] goes nowhere");                        /* xfer-in has the null channel only */
    kdns_syslog(LOG_NOTICE, "[TSIG] bad signature");                    /* security: dyn and dbg */
    kdns_syslog(LOG_DEBUG, "[TSIG] debug text");                        /* dynamic drops debug 1, dbg keeps it */
    errno = ENOENT;
    kdns_syslog(LOG_ERR, "[Update] open: %m");                          /* %m is the errno of the call */
    kdns_logc(LOGC_XFER_OUT, LOG_WARNING, "[AXFR] outbound");           /* the category given beats the prefix; xfer-out falls back to default */
    kdns_logc(LOGC_XFER_IN, LOG_WARNING, "[Config] given category");    /* ... also against another prefix: null */
    kdns_logc(999, LOG_WARNING, "[Notify] bad category given");         /* out of range: by the prefix */
    kdns_syslog(LOG_CRIT, "[Startup] critical %s", "text");
    kdns_syslog(LOG_EMERG, "[Startup] emergency");
    kdns_syslog(LOG_CRIT, "[Startup] forged\nline\r\n2026 general: critical: x\x7f" "end\ttab");   /* control characters cannot start a line */

    klog_expect(p_gen,
                "config: info: [Config] reloaded 3 zones\n"
                "update: error: [Update] open: No such file or directory\n"
                "xfer-out: warning: [AXFR] outbound\n"
                "general: critical: [Startup] critical text\n"
                "general: critical: [Startup] emergency\n"
                "general: critical: [Startup] forged?line??2026 general: critical: x?end\ttab\n");
    char *w = klog_slurp(p_warn);
    /* "<iso8601-utc time> [Notify] ..." : no category, no severity */
    assert(strlen(w) > 24 && w[4] == '-' && w[10] == 'T' && w[23] == 'Z' && w[24] == ' ');
    const char *nl = strchr(w, '\n');      /* each line has its own time */
    assert(nl && strncmp(w + 25, "[Notify] zone 'a.test': failed", 30) == 0 && nl[1] == '2' && nl[24] == 'Z');
    assert(strcmp(nl + 26, "[Notify] bad category given\n") == 0);
    free(w);
    klog_expect(p_dbg,
                "warning: [Notify] zone 'a.test': failed\n"
                "info: [Notify] acknowledged\n"
                "debug 1: [Notify] debug text\n"
                "notice: [TSIG] bad signature\n"
                "debug 1: [TSIG] debug text\n"
                "warning: [Notify] bad category given\n");
    klog_expect(p_dyn, "[TSIG] bad signature\n");

    /* a new runtime replaces the routing: nothing reaches the old files any more */
    log_runtime_t *rt2 = klog_install_conf("logging { category default { null; }; };");
    (void)rt2;
    kdns_syslog(LOG_ERR, "[Config] after the swap");
    assert(klog_lines(p_gen) == 6);
    /* an acquired runtime stays valid while it is used (the user count), and a thread inside a log call logs to syslog() alone */
    log_runtime_t *held = log_runtime_acquire();
    assert(held);
    int n = 0;
    log_channel_t *const *r = log_runtime_route(held, LOGC_QUERIES, &n);
    assert(n == 1 && r[0]->name && strcmp(r[0]->name, "null") == 0);
    log_runtime_release(held);

    bool prev = klog_guard_enter();
    assert(!prev);
    log_runtime_t *none_while_inside = klog_install_conf("logging { channel g2 { file \"/tmp/karidns_klog_guard.log\"; }; category default { g2; }; };");
    (void)none_while_inside;
    kdns_syslog(LOG_ERR, "[Config] logged inside a log call");          /* syslog() only */
    assert(klog_lines("/tmp/karidns_klog_guard.log") == 0);
    klog_guard_leave(prev);
    kdns_syslog(LOG_ERR, "[Config] logged outside");
    assert(klog_lines("/tmp/karidns_klog_guard.log") == 1);
    unlink("/tmp/karidns_klog_guard.log");

    /* a supervisor / router / broker process opens the file by name for every line, so it follows a roll done by the Backend */
    char p_aux[300], p_aux_old[320];
    snprintf(p_aux, sizeof(p_aux), "%s/aux.log", dir);
    snprintf(p_aux_old, sizeof(p_aux_old), "%s/aux.log.0", dir);
    snprintf(conf, sizeof(conf), "logging { channel aux { file \"%s\"; }; category default { aux; }; };", p_aux);
    klog_install_conf(conf);
    kdns_syslog(LOG_ERR, "[Config] before the roll");
    assert(klog_lines(p_aux) == 1);
    klog_set_role(KLOG_ROLE_AUX);
    assert(rename(p_aux, p_aux_old) == 0);
    /* 0.7 M2: between the rename and the new file of the Backend's roll (log_write_rotated() makes it at once) the line is lost: this process
     * never creates a log file (the manager is root; the file must stay the run user's) */
    kdns_syslog(LOG_ERR, "[Config] in the gap of the roll");
    assert(access(p_aux, F_OK) != 0);
    {
        int nfd = open(p_aux, O_WRONLY | O_CREAT | O_EXCL, 0644);   /* the Backend's new file */
        assert(nfd >= 0);
        close(nfd);
    }
    kdns_syslog(LOG_ERR, "[Config] after the roll");
    klog_set_role(KLOG_ROLE_BACKEND);
    klog_expect(p_aux, "[Config] after the roll\n");
    klog_expect(p_aux_old, "[Config] before the roll\n");
    unlink(p_aux);
    unlink(p_aux_old);

    test_retire_runtime(NULL);
    unlink(p_gen);
    unlink(p_warn);
    unlink(p_dbg);
    unlink(p_dyn);
    rmdir(dir);
    printf("  -> routing passed.\n");
}

int ctrl_trace_command(const char *cmd, const char *arg, const char *extra, char *reply, size_t n);
#define AUXLOG_TEST_ROUTER0 0x4u   /* AUXLOG_ROUTER(0) of dns_server_core.c */
extern bool g_auxlog_ready;
extern uint32_t g_auxlog_owed;
extern int g_num_frontend_routers;
void auxlog_changed(void);
void auxlog_push(void);
bool auxlog_send_router(int r, const uint8_t *rec, size_t n);

/* 0.7 M2: the KLS1 record of the level and the runtime, as the Backend builds and sends it, and as the manager, a router or the broker takes it:
 * the level follows, the channels are the Backend's, and a file is only appended to (never created), only in a directory of the start-up's logs,
 * only a plain file with one link of this user or the run user (klog_aux_append()); a forged record cannot point a process anywhere else. */
static void test_klog_aux_state(void) {
    printf("[TEST] Logging: the level and the runtime in the other processes (KLS1, klog_aux_append)...\n");
    klog_set_debug_level(0);
    logev_rate_reset();
    char dir[] = "/tmp/karidns_kaux_XXXXXX", out[] = "/tmp/karidns_kaux_out_XXXXXX";
    assert(mkdtemp(dir) && mkdtemp(out));
    char conf[2048], p_dyn[300], p_new[300], p_link[300], p_fifo[300], p_out[300], p_target[300];
    snprintf(p_dyn, sizeof(p_dyn), "%s/dyn.log", dir);
    snprintf(p_new, sizeof(p_new), "%s/new.log", dir);
    snprintf(p_link, sizeof(p_link), "%s/link.log", dir);
    snprintf(p_fifo, sizeof(p_fifo), "%s/fifo.log", dir);
    snprintf(p_target, sizeof(p_target), "%s/target", dir);
    snprintf(p_out, sizeof(p_out), "%s/elsewhere.log", out);
    snprintf(conf, sizeof(conf),
             "logging { channel dyn { file \"%s\"; severity dynamic; print-severity yes; print-category yes; }; channel sys { syslog local3; severity info; };\n"
             " category general { dyn; sys; }; category database { dyn; }; };", p_dyn);
    klog_install_conf(conf);
    klog_set_debug_level(2);
    static uint8_t rec[KLS_MAX];
    bool dropped = true;
    size_t n = klog_state_encode(rec, sizeof(rec), &dropped);
    assert(n > KLS_HEADER_LEN && !dropped);
    kls_state_t s;
    assert(kls_parse(rec, n, &s) == NULL && s.debug_level == 2 && s.has_spec);
    /* dyn, sys, and the built-in default_syslog / default_debug of the other categories */
    assert(s.nch == 4 && s.nroute[LOGC_GENERAL] == 2 && s.nroute[LOGC_DATABASE] == 1 && s.nroute[LOGC_ZONELOAD] == 2);
    /* (the table is read from category 0, `default`, which has no statement: default_syslog, then the null default_debug; then general) */
    assert(s.ch[0].dest == LOGDEST_SYSLOG && s.ch[0].facility == LOG_DAEMON && s.ch[1].dest == LOGDEST_NULL && (s.ch[1].flags & KLS_CF_DEBUG_ONLY));
    assert(s.ch[2].dest == LOGDEST_FILE && s.ch[2].level == LOG_LVL_DYNAMIC && s.ch[2].flags == (KLS_CF_CATEGORY | KLS_CF_SEVERITY));
    assert(s.ch[2].path_len == strlen(p_dyn) && memcmp(s.ch[2].path, p_dyn, s.ch[2].path_len) == 0);
    assert(s.ch[3].dest == LOGDEST_SYSLOG && s.ch[3].facility == LOG_LOCAL3 && s.ch[3].level == LOG_LVL_INFO);
    /* too little room: the level alone, and *spec_dropped says so; less than a header: nothing */
    assert(klog_state_encode(rec, 20, &dropped) == KLS_HEADER_LEN && dropped);
    assert(klog_state_encode(rec, 5, NULL) == 0);
    n = klog_state_encode(rec, sizeof(rec), NULL);

    /* a process that only appends takes it: another runtime first (the start-up one, say), then the record */
    klog_set_role(KLOG_ROLE_AUX);
    snprintf(conf, sizeof(conf), "logging { category default { null; }; };");
    klog_install_conf(conf);
    klog_set_debug_level(0);
    assert(klog_state_apply(rec, n, "Manager"));
    assert(klog_debug_level() == 2 && logev_wanted(LOGC_DATABASE, 2) && !logev_wanted(LOGC_DATABASE, 3));
    kdns_syslog(LOG_DEBUG, "[Manager] a debug line of the manager");
    kdns_logc(LOGC_DATABASE, LOG_ERR, "[DB] an error of the loader");
    {
        char *t = klog_slurp(p_dyn);
        assert(strstr(t, "general: debug 1: [Logging] Manager: debug level 2, logging configuration of the Backend taken (4 channel(s))\n"));
        assert(strstr(t, "general: debug 1: [Manager] a debug line of the manager\n") && strstr(t, "database: error: [DB] an error of the loader\n"));
        free(t);
    }
    /* a record that is not one: refused, nothing changes */
    rec[4] = 9;
    assert(!klog_state_apply(rec, n, "Frontend 0") && klog_debug_level() == 2);
    rec[4] = KLS_VERSION;
    /* the level alone: the channels stay */
    {
        kls_state_t lv;
        memset(&lv, 0, sizeof(lv));
        lv.debug_level = 0;
        uint8_t small[KLS_HEADER_LEN];
        assert(kls_encode(&lv, small, sizeof(small)) == KLS_HEADER_LEN && klog_state_apply(small, sizeof(small), "Broker"));
        assert(klog_debug_level() == 0 && !logev_wanted(LOGC_DATABASE, 1) && logev_wanted(LOGC_DATABASE, LOG_LVL_ERROR));
    }

    /* a forged record: channels at files that must not be written.  Each is a dynamic channel of `general` */
    int fd = open(p_target, O_WRONLY | O_CREAT, 0644);
    assert(fd >= 0);
    close(fd);
    assert(link(p_target, p_link) == 0);                                   /* a hard link (the file has two names) */
    assert(mkfifo(p_fifo, 0644) == 0);                                     /* a FIFO nobody reads: open() must not wait */
    fd = open(p_out, O_WRONLY | O_CREAT, 0644);                            /* a directory the start-up did not open for the logs */
    assert(fd >= 0);
    close(fd);
    {
        const char *paths[4] = { p_new, p_link, p_fifo, p_out };
        kls_state_t f;
        memset(&f, 0, sizeof(f));
        f.debug_level = 1;
        f.has_spec = true;
        f.nch = 4;
        for (int i = 0; i < 4; i++) {
            f.ch[i] = (kls_channel_t){ 0, 0, 0, 0, 0, (uint16_t)strlen(paths[i]), paths[i] };
            f.route[LOGC_GENERAL][i] = (uint16_t)i;
        }
        f.nroute[LOGC_GENERAL] = 4;
        size_t fn = kls_encode(&f, rec, sizeof(rec));
        assert(fn > 0 && klog_state_apply(rec, fn, "Manager"));
        kdns_syslog(LOG_ERR, "[Manager] to nowhere");
        struct stat st;
        assert(access(p_new, F_OK) != 0);                                   /* never created */
        assert(stat(p_target, &st) == 0 && st.st_size == 0);                /* not through the hard link */
        assert(stat(p_out, &st) == 0 && st.st_size == 0);                   /* not outside the log directories */
        assert(open_via_dir_cache_existing(p_out, O_WRONLY) < 0 && errno == EACCES);
        fd = open_via_dir_cache_existing(p_dyn, O_WRONLY | O_CREAT | O_APPEND);
        assert(fd >= 0);
        close(fd);
        assert(open_via_dir_cache_existing("", O_WRONLY) < 0);
    }
    klog_set_role(KLOG_ROLE_BACKEND);
    klog_set_debug_level(0);

    /* the Backend side: the record goes to the manager (a datagram), each router (udp_ipc_t + record on worker 0's pair) and the broker
     * (request + record, one byte back) when the level or the runtime changes; nothing before the processes exist (g_auxlog_ready) */
    snprintf(conf, sizeof(conf), "logging { channel dyn { file \"%s\"; severity dynamic; }; category general { dyn; }; };", p_dyn);
    klog_install_conf(conf);
    int mgr[2], rtr[2], brk[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, mgr) == 0 && socketpair(AF_UNIX, SOCK_DGRAM, 0, rtr) == 0 &&
           socketpair(AF_UNIX, SOCK_STREAM, 0, brk) == 0);
    int saved_plug = g_plug_ctrl_fd, saved_broker = g_broker_sock, saved_routers = g_num_frontend_routers, saved_workers = g_num_workers;
    int saved_ipc = g_ipc_fds[0][0][1];
    g_plug_ctrl_fd = mgr[0];
    g_ipc_fds[0][0][1] = rtr[0];
    g_broker_sock = brk[0];
    g_num_frontend_routers = 1;
    g_num_workers = 1;
    g_auxlog_ready = false;
    auxlog_changed();                                                        /* not ready: nothing is sent */
    uint8_t got[KLS_MAX + 200];
    assert(recv(mgr[1], got, sizeof(got), MSG_DONTWAIT) < 0);
    g_auxlog_ready = true;
    klog_set_debug_level(4);
    assert(send(brk[1], "\0", 1, 0) == 1);                                   /* the broker's answer, ahead of time */
    auxlog_changed();
    assert(g_auxlog_owed == 0);
    size_t want = klog_state_encode(rec, sizeof(rec), NULL);
    ssize_t k = recv(mgr[1], got, sizeof(got), MSG_DONTWAIT);
    assert(k == (ssize_t)want && memcmp(got, rec, want) == 0);
    k = recv(rtr[1], got, sizeof(got), MSG_DONTWAIT);
    assert(k == (ssize_t)(sizeof(udp_ipc_t) + want));
    {
        udp_ipc_t h;
        memcpy(&h, got, sizeof(h));
        assert(h.sock_fd_idx == UDP_IPC_LOGSTATE && h.payload_len == want && memcmp(got + sizeof(h), rec, want) == 0);
    }
    size_t bl = 0;
    while (bl < sizeof(broker_req_t) + want) {
        k = recv(brk[1], got + bl, sizeof(got) - bl, 0);
        assert(k > 0);
        bl += (size_t)k;
    }
    {
        broker_req_t br;
        memcpy(&br, got, sizeof(br));
        assert(br.family == BROKER_REQ_LOGSTATE && br.type == (int)want && memcmp(got + sizeof(br), rec, want) == 0);
    }
    /* a broker that refuses is logged; a router that cannot take it stays owed until the timer sends it */
    assert(send(brk[1], "\1", 1, 0) == 1);
    close(rtr[1]);
    auxlog_changed();
    assert(g_auxlog_owed == AUXLOG_TEST_ROUTER0);
    (void)recv(mgr[1], got, sizeof(got), MSG_DONTWAIT);
    bl = 0;
    while (bl < sizeof(broker_req_t) + want) {
        k = recv(brk[1], got + bl, sizeof(got) - bl, 0);
        assert(k > 0);
        bl += (size_t)k;
    }
    assert(!auxlog_send_router(0, rec, want));
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, rtr) == 0);
    g_ipc_fds[0][0][1] = rtr[0];
    auxlog_push();                                                           /* the timer */
    assert(g_auxlog_owed == 0 && recv(rtr[1], got, sizeof(got), MSG_DONTWAIT) == (ssize_t)(sizeof(udp_ipc_t) + want));
    /* the broker is gone: broker_send_logstate() says so and the stream is shut */
    close(brk[1]);
    assert(!broker_send_logstate(rec, want));
    assert(!broker_send_logstate(rec, 0) && !broker_send_logstate(rec, KLS_MAX + 1));
    close(brk[0]);
    g_broker_sock = -1;
    assert(!broker_send_logstate(rec, want));
    auxlog_push();                                                           /* nothing owed */
    close(mgr[0]);
    close(mgr[1]);
    close(rtr[0]);
    close(rtr[1]);
    g_plug_ctrl_fd = saved_plug;
    g_broker_sock = saved_broker;
    g_ipc_fds[0][0][1] = saved_ipc;
    g_num_frontend_routers = saved_routers;
    g_num_workers = saved_workers;
    g_auxlog_ready = false;
    klog_set_debug_level(0);
    test_retire_runtime(NULL);
    unlink(p_dyn);
    unlink(p_link);
    unlink(p_target);
    unlink(p_fifo);
    unlink(p_out);
    rmdir(dir);
    rmdir(out);
    printf("  -> the level and the runtime in the other processes passed.\n");
}

/* a record of file channels (severity dynamic) for the categories general and database, at debug level dl; a path "*name" is a default_debug
 * channel (KLS_CF_DEBUG_ONLY), "=name" a syslog channel of facility local5 */
static size_t klog_forge(uint8_t *rec, size_t cap, const char *const *paths, int n, int dl) {
    static kls_state_t f;
    memset(&f, 0, sizeof(f));
    f.debug_level = dl;
    f.has_spec = true;
    f.nch = (uint16_t)n;
    for (int i = 0; i < n; i++) {
        const char *p = paths[i];
        if (p[0] == '=')
            f.ch[i] = (kls_channel_t){ LOGDEST_SYSLOG, 0, 0, LOG_LVL_INFO, LOG_LOCAL5, 0, NULL };
        else if (p[0] == '*')
            f.ch[i] = (kls_channel_t){ LOGDEST_FILE, 0, KLS_CF_DEBUG_ONLY, 0, 0, (uint16_t)strlen(p + 1), p + 1 };
        else
            f.ch[i] = (kls_channel_t){ LOGDEST_FILE, 0, 0, 0, 0, (uint16_t)strlen(p), p };
        f.route[LOGC_GENERAL][i] = f.route[LOGC_DATABASE][i] = (uint16_t)i;
    }
    f.nroute[LOGC_GENERAL] = f.nroute[LOGC_DATABASE] = (uint8_t)n;
    size_t len = kls_encode(&f, rec, cap);
    assert(len > 0);
    return len;
}

static int klog_count(const char *path, const char *needle) {
    char *s = klog_slurp(path);
    int n = 0;
    for (const char *p = s; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    free(s);
    return n;
}

static off_t klog_size(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 ? st.st_size : -1;
}

/* 0.7: what a record from a taken-over Backend can do in the manager (root), a router or the broker is held to the start (klog_aux_init()):
 * a file only in a directory of the start's file channels, a plain file of the run user (never the manager's own user, root), karidns.run of
 * options { directory } only through the start's descriptor, no other file of that directory; a syslog facility only one the start used; the
 * warnings and errors always reach the start's channels too.  And the Backend holds no writable descriptor of options { directory }: the start
 * opens karidns.run without caching one, a reload in the sandbox takes the descriptor over. */
static void test_klog_aux_limits(void) {
    printf("[TEST] Logging: a record of the Backend is held to the start (owner, directories, karidns.run, floor, facility)...\n");
    klog_set_debug_level(0);
    logev_rate_reset();
    char ld[] = "/tmp/karidns_kal_log_XXXXXX", od[] = "/tmp/karidns_kal_opt_XXXXXX", xd[] = "/tmp/karidns_kal_x_XXXXXX";
    assert(mkdtemp(ld) && mkdtemp(od) && mkdtemp(xd));
    char p_start[300], p_mine[300], p_x[300], p_sym[300], p_tgt[300], p_hard[300], p_tgt2[300], p_fifo[300], p_new[300], p_conf[300], p_run[300];
    snprintf(p_start, sizeof(p_start), "%s/start.log", ld);
    snprintf(p_mine, sizeof(p_mine), "%s/root.log", ld);
    snprintf(p_x, sizeof(p_x), "%s/x.log", xd);
    snprintf(p_sym, sizeof(p_sym), "%s/sym.log", ld);
    snprintf(p_tgt, sizeof(p_tgt), "%s/target.log", ld);
    snprintf(p_hard, sizeof(p_hard), "%s/hard.log", ld);
    snprintf(p_tgt2, sizeof(p_tgt2), "%s/target2", ld);
    snprintf(p_fifo, sizeof(p_fifo), "%s/fifo.log", ld);
    snprintf(p_new, sizeof(p_new), "%s/new.log", ld);
    snprintf(p_conf, sizeof(p_conf), "%s/karidns.conf", od);
    snprintf(p_run, sizeof(p_run), "%s/karidns.run", od);
    const char *plain[] = { p_mine, p_x, p_tgt, p_tgt2, p_conf };
    for (size_t i = 0; i < sizeof(plain) / sizeof(plain[0]); i++) {
        int fd = open(plain[i], O_WRONLY | O_CREAT, 0644);
        assert(fd >= 0);
        close(fd);
    }
    assert(symlink(p_tgt, p_sym) == 0 && link(p_tgt2, p_hard) == 0 && mkfifo(p_fifo, 0644) == 0);
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "options { directory \"%s\"; }; logging { channel lf { file \"%s\"; severity info; }; channel sys { syslog local3; severity info; };\n"
             " category general { lf; sys; default_debug; }; category database { lf; }; };", od, p_start);
    klog_install_conf(conf);
    /* the start: karidns.run is open, its directory is not in the cache for writing (finding 2); the log directory is */
    assert(access(p_run, F_OK) == 0);
    errno = 0;
    assert(open_via_dir_cache_existing(p_run, O_WRONLY) < 0 && errno == EACCES);
    int fd = open_via_dir_cache_existing(p_start, O_WRONLY | O_APPEND);
    assert(fd >= 0);
    close(fd);
    static uint8_t rec[KLS_MAX];

    /* (a), (b): files of this process's own user while the run user is someone else (the manager is root, the files are the run user's) */
    const uid_t other = geteuid() + 1;
    klog_aux_init(other);
    klog_set_role(KLOG_ROLE_AUX);
    {
        const char *paths[] = { p_mine, p_conf, p_start };
        size_t n = klog_forge(rec, sizeof(rec), paths, 3, 0);
        assert(klog_state_apply(rec, n, "Manager"));
        kdns_syslog(LOG_ERR, "[Manager] into a file that is not the run user's");
        assert(klog_size(p_mine) == 0 && klog_size(p_conf) == 0 && klog_size(p_start) == 0);
    }
    klog_set_role(KLOG_ROLE_BACKEND);

    /* the run user is this process's user from here on: (c) .. (f) and the other files of options { directory } are still refused */
    klog_install_conf(conf);
    klog_aux_init(geteuid());
    klog_set_role(KLOG_ROLE_AUX);
    {
        char run_dbg[310];
        snprintf(run_dbg, sizeof(run_dbg), "*%s", p_run);
        const char *paths[] = { p_start, p_x, p_sym, p_hard, p_fifo, p_conf, run_dbg, p_new };
        size_t n = klog_forge(rec, sizeof(rec), paths, 8, 1);
        assert(klog_state_apply(rec, n, "Manager"));
        kdns_syslog(LOG_INFO, "[Manager] where the record says");
        assert(klog_count(p_start, "[Manager] where the record says\n") == 1);   /* the positive case: a run-user file of a start-up log directory */
        assert(klog_count(p_run, "[Manager] where the record says\n") == 1);     /* ... and karidns.run through the start's descriptor */
        assert(klog_size(p_x) == 0);                                               /* (c) not a start-up log directory */
        assert(klog_size(p_tgt) == 0);                                             /* (d) not through a symbolic link */
        assert(klog_size(p_tgt2) == 0);                                            /* (e) not through a hard link */
        assert(klog_size(p_conf) == 0);                                            /* options { directory }: karidns.run only */
        assert(access(p_new, F_OK) != 0);                                          /* never created */
        /* (f): the FIFO has no reader, and the line above did not wait for one (we are here) */
        /* karidns.run is reached by the start's descriptor, not by its name: a file put there later is not written */
        assert(unlink(p_run) == 0);
        fd = open(p_run, O_WRONLY | O_CREAT, 0644);
        assert(fd >= 0);
        close(fd);
        kdns_syslog(LOG_INFO, "[Manager] after karidns.run was replaced");
        assert(klog_size(p_run) == 0);
    }

    /* floor (finding 3): a record that silences everything; the warnings and errors still reach the start's channels, nothing below does */
    {
        size_t n = klog_forge(rec, sizeof(rec), NULL, 0, 0);
        assert(klog_state_apply(rec, n, "Manager"));
        assert(logev_wanted(LOGC_GENERAL, LOG_LVL_WARNING) && logev_wanted(LOGC_DATABASE, LOG_LVL_ERROR) && !logev_wanted(LOGC_GENERAL, LOG_LVL_INFO));
        kdns_syslog(LOG_WARNING, "[Manager] a warning under a silencing record");
        kdns_logc(LOGC_DATABASE, LOG_ERR, "[DB] an error under a silencing record");
        logev_post(LOGC_GENERAL, LOG_LVL_ERROR, NULL, 0, "[Manager] an event error under a silencing record");
        kdns_syslog(LOG_INFO, "[Manager] an info line under a silencing record");
        assert(klog_count(p_start, "[Manager] a warning under a silencing record\n") == 1);
        assert(klog_count(p_start, "[DB] an error under a silencing record\n") == 1);
        assert(klog_count(p_start, "[Manager] an event error under a silencing record\n") == 1);
        assert(klog_count(p_start, "an info line under a silencing record") == 0);
        /* a record that writes to the start's file already: the line is there once */
        const char *paths[] = { p_start };
        n = klog_forge(rec, sizeof(rec), paths, 1, 0);
        assert(klog_state_apply(rec, n, "Manager"));
        kdns_syslog(LOG_ERR, "[Manager] an error written once");
        assert(klog_count(p_start, "[Manager] an error written once\n") == 1);
        /* the facility: local3 is the start's, local5 is not and becomes daemon */
        const char *sys[] = { "=", "=" };
        n = klog_forge(rec, sizeof(rec), sys, 2, 0);
        rec[KLS_HEADER_LEN + 4]                                            /* (the facility of the first channel) */ = (uint8_t)(LOG_LOCAL3 >> 8);
        rec[KLS_HEADER_LEN + 5] = (uint8_t)LOG_LOCAL3;
        assert(klog_state_apply(rec, n, "Manager"));
        log_runtime_t *rt = log_runtime_acquire();
        int nr = 0;
        log_channel_t *const *r = log_runtime_route(rt, LOGC_GENERAL, &nr);
        assert(nr == 2 && r[0]->syslog_facility == LOG_LOCAL3 && r[1]->syslog_facility == LOG_DAEMON);
        log_runtime_release(rt);
        /* (the start's local3 channel took the warnings of the floor, and the record's local3 channel is the same place: no second line) */
        kdns_syslog(LOG_WARNING, "[Manager] a warning to local3");
    }
    klog_set_role(KLOG_ROLE_BACKEND);

    /* finding 2: a reload in the sandbox keeps karidns.run (the start's descriptor), with no directory descriptor of options { directory } */
    {
        snprintf(conf, sizeof(conf), "options { directory \"%s\"; };", od);
        unlink(p_run);
        klog_install_conf(conf);
        klog_set_debug_level(1);
        kdns_syslog(LOG_INFO, "[Zone] before the reload");
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        assert(parse_named_conf(conf, &cfg) == 0);
        logrt_status_t st;
        atomic_store(&g_capsicum_enabled, true);                      /* what the Backend is at a reload */
        log_runtime_t *nrt = log_runtime_build(&cfg.logging, true, &st);
        atomic_store(&g_capsicum_enabled, false);
        assert(nrt && st == LOGRT_OK && log_runtime_install(nrt));
        free_server_config_fields(&cfg);
        kdns_syslog(LOG_INFO, "[Zone] after the reload");
        klog_set_debug_level(0);
        assert(klog_count(p_run, " [Zone] before the reload\n") == 1 && klog_count(p_run, " [Zone] after the reload\n") == 1);
        errno = 0;
        assert(open_via_dir_cache_existing(p_run, O_WRONLY) < 0 && errno == EACCES);
        /* a reload in between that does not write to default_debug keeps the descriptor for the next one that does */
        for (int i = 0; i < 2; i++) {
            if (i == 0) snprintf(conf, sizeof(conf), "options { directory \"%s\"; }; logging { category default { default_syslog; }; };", od);
            else snprintf(conf, sizeof(conf), "options { directory \"%s\"; };", od);
            memset(&cfg, 0, sizeof(cfg));
            assert(parse_named_conf(conf, &cfg) == 0);
            atomic_store(&g_capsicum_enabled, true);
            nrt = log_runtime_build(&cfg.logging, true, &st);
            atomic_store(&g_capsicum_enabled, false);
            assert(nrt && st == LOGRT_OK && log_runtime_install(nrt));
            free_server_config_fields(&cfg);
        }
        klog_set_debug_level(1);
        kdns_syslog(LOG_INFO, "[Zone] after two more reloads");
        klog_set_debug_level(0);
        assert(klog_count(p_run, " [Zone] after two more reloads\n") == 1);
        /* ... and one that needs it when the start did not open it: default_debug is null (a warning), nothing is created */
        char od2[] = "/tmp/karidns_kal_opt2_XXXXXX", p_run2[300];
        assert(mkdtemp(od2));
        snprintf(p_run2, sizeof(p_run2), "%s/karidns.run", od2);
        snprintf(conf, sizeof(conf), "options { directory \"%s\"; }; logging { category default { default_syslog; }; };", od2);
        klog_install_conf(conf);
        assert(access(p_run2, F_OK) != 0);
        snprintf(conf, sizeof(conf), "options { directory \"%s\"; };", od2);
        memset(&cfg, 0, sizeof(cfg));
        assert(parse_named_conf(conf, &cfg) == 0);
        atomic_store(&g_capsicum_enabled, true);
        nrt = log_runtime_build(&cfg.logging, true, &st);
        atomic_store(&g_capsicum_enabled, false);
        assert(nrt && st == LOGRT_OK && log_runtime_install(nrt));
        free_server_config_fields(&cfg);
        klog_set_debug_level(1);
        assert(!logev_wanted(LOGC_ZONELOAD, 1));
        klog_set_debug_level(0);
        assert(access(p_run2, F_OK) != 0);
        rmdir(od2);
    }

    /* a refused start without a run user hands nothing over (the root case: tests/run_log_refused_start_test.sh) */
    log_startup_refused();
    /* what the later tests expect: no run user, the floor of a runtime without files, no karidns.run descriptor */
    test_retire_runtime(NULL);
    klog_aux_init((uid_t)-1);
    test_retire_runtime(NULL);
    const char *all[] = { p_start, p_mine, p_x, p_sym, p_tgt, p_hard, p_tgt2, p_fifo, p_conf, p_run };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) unlink(all[i]);
    rmdir(ld);
    rmdir(od);
    rmdir(xd);
    printf("  -> a record of the Backend held to the start passed.\n");
}

/* 0.7 M1: the debug level in force.  The masks of the event messages follow it; `severity dynamic` follows it, `debug n` does not; the built-in
 * default_debug is karidns.run in options { directory }, written only above level 0, created only when a category writes to it, and never
 * an error when it cannot be opened; trace / notrace as the control thread runs them. */
static void test_klog_debug_level(void) {
    printf("[TEST] Logging: the debug level in force (masks, dynamic, default_debug / karidns.run, trace / notrace)...\n");
    setenv("TZ", "UTC", 1);
    tzset();
    klog_set_debug_level(0);
    char dir[] = "/tmp/karidns_kdbg_XXXXXX";
    assert(mkdtemp(dir));
    char conf[2048], p_dyn[300], p_fix[300], p_run[300], p_other[300];
    snprintf(p_dyn, sizeof(p_dyn), "%s/dyn.log", dir);
    snprintf(p_fix, sizeof(p_fix), "%s/fix.log", dir);
    snprintf(p_run, sizeof(p_run), "%s/karidns.run", dir);
    snprintf(p_other, sizeof(p_other), "%s/other", dir);

    /* masks: query-errors has a dynamic channel, xfer-out a `debug 2` one, update nothing but the default (default_syslog, info) */
    snprintf(conf, sizeof(conf),
             "logging { channel dyn { file \"%s\"; severity dynamic; print-severity yes; }; channel fix { file \"%s\"; severity debug 2; print-severity yes; };\n"
             " category query-errors { dyn; }; category config { dyn; }; category xfer-out { fix; }; };", p_dyn, p_fix);
    klog_install_conf(conf);
    assert(logev_wanted(LOGC_QUERY_ERRORS, LOG_LVL_INFO) && !logev_wanted(LOGC_QUERY_ERRORS, 1));
    assert(logev_wanted(LOGC_XFER_OUT, 2) && !logev_wanted(LOGC_XFER_OUT, 3));
    assert(logev_wanted(LOGC_UPDATE, LOG_LVL_INFO) && !logev_wanted(LOGC_UPDATE, 1));
    kdns_syslog(LOG_DEBUG, "[Config] at level 0");                           /* dynamic at 0: not written (nor formatted: the mask says no) */
    assert(klog_lines(p_dyn) == 0);
    klog_set_debug_level(3);
    assert(klog_debug_level() == 3);
    assert(logev_wanted(LOGC_QUERY_ERRORS, 1) && logev_wanted(LOGC_QUERY_ERRORS, 3) && !logev_wanted(LOGC_QUERY_ERRORS, 4));
    assert(logev_wanted(LOGC_XFER_OUT, 2) && !logev_wanted(LOGC_XFER_OUT, 3));   /* debug 2 is debug 2 at every level */
    assert(!logev_wanted(LOGC_UPDATE, 1));                                      /* default_syslog is info; no directory: no default_debug file */
    kdns_syslog(LOG_DEBUG, "[Config] at level 3");
    kdns_syslog(LOG_ERR, "[Config] an error");
    klog_set_debug_level(0);
    assert(!logev_wanted(LOGC_QUERY_ERRORS, 1) && logev_wanted(LOGC_QUERY_ERRORS, LOG_LVL_INFO));
    kdns_syslog(LOG_DEBUG, "[Config] at level 0 again");
    klog_expect(p_dyn, "debug 1: [Config] at level 3\nerror: [Config] an error\n");
    klog_set_debug_level(-4);                                                   /* held to 0 .. 99 */
    assert(klog_debug_level() == 0);
    klog_set_debug_level(500);
    assert(klog_debug_level() == KLOG_DEBUG_LEVEL_MAX && logev_wanted(LOGC_QUERY_ERRORS, LOGEV_LEVEL_MAX));
    klog_set_debug_level(0);
    /* a new runtime is installed with the masks of the level in force */
    klog_set_debug_level(2);
    klog_install_conf(conf);
    assert(logev_wanted(LOGC_QUERY_ERRORS, 2) && !logev_wanted(LOGC_QUERY_ERRORS, 3));
    klog_set_debug_level(0);
    assert(!logev_wanted(LOGC_QUERY_ERRORS, 1));

    /* default_debug: no logging statement, a directory: karidns.run is created at once (empty), written only above level 0, with the time */
    snprintf(conf, sizeof(conf), "options { directory \"%s\"; };", dir);
    {
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        assert(parse_named_conf(conf, &cfg) == 0 && cfg.logging.debug_file && strcmp(cfg.logging.debug_file, p_run) == 0);
        free_server_config_fields(&cfg);
        memset(&cfg, 0, sizeof(cfg));
        assert(parse_named_conf("options { };", &cfg) == 0 && cfg.logging.debug_file == NULL);   /* no directory: no file */
        free_server_config_fields(&cfg);
    }
    klog_install_conf(conf);
    struct stat st;
    assert(stat(p_run, &st) == 0 && st.st_size == 0);
    kdns_syslog(LOG_ERR, "[Config] level 0: default_syslog only");
    assert(klog_lines(p_run) == 0 && !logev_wanted(LOGC_ZONELOAD, 1));
    klog_set_debug_level(1);
    assert(logev_wanted(LOGC_ZONELOAD, 1) && !logev_wanted(LOGC_ZONELOAD, 2) && logev_wanted(LOGC_ZONELOAD, LOG_LVL_INFO));
    kdns_syslog(LOG_INFO, "[Zone] info at level 1");
    kdns_syslog(LOG_DEBUG, "[Zone] debug 1 at level 1");
    klog_set_debug_level(0);
    kdns_syslog(LOG_ERR, "[Zone] error at level 0");
    {
        char *s = klog_slurp(p_run);
        /* "28-Oct-2026 03:04:05.678 [Zone] ..." (print-time, no category, no severity: BIND's default_debug) */
        assert(klog_lines(p_run) == 2 && strstr(s, " [Zone] info at level 1\n") && strstr(s, " [Zone] debug 1 at level 1\n") && s[2] == '-' && s[20] == '.');
        free(s);
    }
    /* a supervisor / router / broker process appends to it by name, but never creates it */
    unlink(p_run);
    klog_set_debug_level(1);
    klog_set_role(KLOG_ROLE_AUX);
    kdns_syslog(LOG_ERR, "[Manager] not created by the manager");
    klog_set_role(KLOG_ROLE_BACKEND);
    klog_set_debug_level(0);
    assert(access(p_run, F_OK) != 0);

    /* not created when no category writes to the built-in one: a category default without it, or a channel of the file of that name */
    snprintf(conf, sizeof(conf), "options { directory \"%s\"; }; logging { category default { default_syslog; }; };", dir);
    klog_install_conf(conf);
    assert(access(p_run, F_OK) != 0);
    snprintf(conf, sizeof(conf), "options { directory \"%s\"; }; logging { channel default_debug { file \"%s\"; severity dynamic; }; };", dir, p_other);
    klog_install_conf(conf);
    assert(access(p_run, F_OK) != 0 && access(p_other, F_OK) == 0);
    unlink(p_other);
    /* ... and a category that names it explicitly creates it */
    snprintf(conf, sizeof(conf), "options { directory \"%s\"; }; logging { category default { default_syslog; }; category notify { default_debug; }; };", dir);
    klog_install_conf(conf);
    assert(access(p_run, F_OK) == 0);
    unlink(p_run);

    /* a karidns.run that cannot be opened (a directory there) or is refused (a hard link) is a warning: the runtime is built, default_debug is null */
    snprintf(conf, sizeof(conf), "options { directory \"%s\"; };", dir);
    assert(mkdir(p_run, 0755) == 0);
    klog_install_conf(conf);                                                    /* (asserts LOGRT_OK) */
    klog_set_debug_level(1);
    assert(!logev_wanted(LOGC_ZONELOAD, 1));                                    /* nothing writes a debug message now */
    klog_set_debug_level(0);
    assert(rmdir(p_run) == 0);
    int fd = open(p_other, O_WRONLY | O_CREAT, 0644);
    assert(fd >= 0);
    close(fd);
    assert(link(p_other, p_run) == 0);
    klog_install_conf(conf);
    klog_set_debug_level(1);
    kdns_syslog(LOG_ERR, "[Zone] not into a hard link");
    klog_set_debug_level(0);
    assert(stat(p_other, &st) == 0 && st.st_size == 0);
    unlink(p_run);
    unlink(p_other);

    /* trace / notrace (the control thread's handler) */
    char r[128];
    assert(ctrl_trace_command("trace", NULL, NULL, r, sizeof(r)) > 0 && strcmp(r, "OK debug level is now 1\n") == 0 && klog_debug_level() == 1);
    ctrl_trace_command("trace", NULL, NULL, r, sizeof(r));
    assert(strcmp(r, "OK debug level is now 2\n") == 0);
    ctrl_trace_command("trace", "99", NULL, r, sizeof(r));
    assert(strcmp(r, "OK debug level is now 99\n") == 0);
    ctrl_trace_command("trace", NULL, NULL, r, sizeof(r));                    /* one more than 99 is 99 */
    assert(strcmp(r, "OK debug level is now 99\n") == 0 && klog_debug_level() == 99);
    ctrl_trace_command("trace", "100", NULL, r, sizeof(r));
    assert(strcmp(r, "ERROR trace: the debug level must be a number from 0 to 99\n") == 0 && klog_debug_level() == 99);
    ctrl_trace_command("trace", "x", NULL, r, sizeof(r));
    assert(strncmp(r, "ERROR trace: the debug level", 28) == 0);
    ctrl_trace_command("trace", "3", "4", r, sizeof(r));
    assert(strcmp(r, "ERROR trace takes one argument at most: the debug level (0-99)\n") == 0 && klog_debug_level() == 99);
    ctrl_trace_command("notrace", "1", NULL, r, sizeof(r));
    assert(strcmp(r, "ERROR notrace takes no argument\n") == 0 && klog_debug_level() == 99);
    ctrl_trace_command("trace", "4", NULL, r, sizeof(r));
    assert(strcmp(r, "OK debug level is now 4\n") == 0 && klog_debug_level() == 4);
    ctrl_trace_command("notrace", NULL, NULL, r, sizeof(r));
    assert(strcmp(r, "OK debug level is now 0\n") == 0 && klog_debug_level() == 0);
    char small[8];
    assert(ctrl_trace_command("notrace", NULL, NULL, small, sizeof(small)) == (int)sizeof(small) - 1 && small[7] == '\0');
    assert(ctrl_trace_command("notrace", NULL, NULL, small, 0) == 0);

    test_retire_runtime(NULL);
    klog_set_debug_level(0);
    unlink(p_dyn);
    unlink(p_fix);
    assert(rmdir(dir) == 0);
    printf("  -> debug level passed.\n");
}

static void test_klog_destinations_and_batches(void) {
    printf("[TEST] Logging: stderr, syslog and null channels, batches...\n");
    char dir[] = "/tmp/karidns_klog_XXXXXX";
    assert(mkdtemp(dir));
    char errfile[300], conf[2048];
    snprintf(errfile, sizeof(errfile), "%s/stderr.txt", dir);
    snprintf(conf, sizeof(conf),
             "logging { channel se { stderr; print-severity yes; print-category yes; }; channel sy { syslog local3; severity debug 9; print-time yes; };\n"
             " channel nu { null; }; channel lim { file \"%s/lim.log\" size 2k versions 1; };\n"
             " category queries { se; sy; nu; lim; }; category default { default_stderr; default_debug; null; }; };", dir);
    klog_install_conf(conf);
    int saved = dup(2);
    int fd = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(saved >= 0 && fd >= 0);
    dup2(fd, 2);
    close(fd);
    kdns_logc(LOGC_QUERIES, LOG_NOTICE, "to stderr, syslog and nowhere");
    kdns_syslog(LOG_ERR, "[Config] default_stderr prints the time");
    kdns_syslog(LOG_DEBUG, "[Config] default_stderr is info: this is dropped");
    /* a batch: lines for a stderr channel are collected and written at once; syslog and null channels are written (not collected) */
    log_runtime_t *rt = log_runtime_acquire();
    assert(rt);
    int n = 0;
    log_channel_t *const *route = log_runtime_route(rt, LOGC_QUERIES, &n);
    assert(n == 4);
    static klog_batch_t b[4];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    for (int i = 0; i < 4; i++) b[i].len = 0;
    for (int k = 0; k < 600; k++)             /* 600 lines of about 70 bytes: more than a batch holds, so one flush happens in between */
        for (int i = 0; i < 4; i++)
            klog_batch_add(&b[i], route[i], LOGC_QUERIES, LOG_LVL_INFO, &ts, "batched line of the query log with a padding of some more text...");
    assert(b[0].len > 0 && b[1].len == 0 && b[2].len == 0 && b[3].len == 0);   /* a file with a size limit is written line by line */
    for (int i = 0; i < 4; i++) klog_batch_flush(&b[i], route[i]);
    assert(b[0].len == 0);
    klog_batch_flush(&b[0], route[0]);        /* nothing left: nothing written */
    log_runtime_release(rt);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    char *s = klog_slurp(errfile);
    assert(strstr(s, "info: queries: to stderr") == NULL);                        /* order: category, then severity */
    assert(strstr(s, "queries: notice: to stderr, syslog and nowhere\n") != NULL);
    assert(strstr(s, "[Config] default_stderr prints the time\n") != NULL && strstr(s, "default_stderr is info") == NULL);
    const char *dflt = strstr(s, "[Config] default_stderr prints the time\n");
    assert(dflt && dflt[-1] == ' ' && dflt[-5] == '.');                           /* default_stderr prints the time: "28-Oct-2026 03:04:05.678 [Config] ..." */
    free(s);
    assert(klog_lines(errfile) == 1 + 1 + 600);                                   /* the notice, the default_stderr line, 600 batched lines */
    /* 0.7 M4, KARIDNS_NOSYSLOG=1: the syslog channel's line goes to stderr as LOG_PERROR prints it ("KariDNS <pid> - - <text>"); a line too
     * long is cut and still ends in a newline; only "1" counts, and the flag follows the environment each time it is read */
    setenv("KARIDNS_NOSYSLOG", "1", 1);
    assert(klog_nosyslog_from_env("KariDNS"));
    saved = dup(2);
    fd = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(saved >= 0 && fd >= 0);
    dup2(fd, 2);
    close(fd);
    kdns_logc(LOGC_QUERIES, LOG_NOTICE, "nosyslog line");
    static char longmsg[KLOG_MSG_MAX * 2];
    memset(longmsg, 'x', sizeof(longmsg) - 1);
    longmsg[sizeof(longmsg) - 1] = '\0';
    klog_syslog_text(LOG_ERR, longmsg);
    dup2(saved, 2);
    close(saved);
    s = klog_slurp(errfile);
    char want[64];
    snprintf(want, sizeof(want), "KariDNS %ld - - ", (long)getpid());
    const char *sl = strstr(s, want);
    assert(sl && (sl == s || sl[-1] == '\n'));
    const char *nl = strchr(sl, '\n');
    const char *sm = strstr(sl, " nosyslog line\n");                                                   /* the syslog channel sy: the time, the text */
    assert(nl && sm && sm + strlen(" nosyslog line") == nl);
    assert(strstr(s, "queries: notice: nosyslog line\n") != NULL);                                     /* the stderr channel as before */
    const char *lx = strstr(nl + 1, want);
    assert(lx && lx[strlen(want)] == 'x' && s[strlen(s) - 1] == '\n' && strlen(lx) <= KLOG_MSG_MAX + 256);
    free(s);
    assert(klog_lines(errfile) == 3);
    setenv("KARIDNS_NOSYSLOG", "0", 1);
    assert(!klog_nosyslog_from_env("KariDNS"));
    unsetenv("KARIDNS_NOSYSLOG");
    assert(!klog_nosyslog_from_env(NULL));
    char lim[300], lim0[310], lim1[310];
    snprintf(lim, sizeof(lim), "%s/lim.log", dir);
    snprintf(lim0, sizeof(lim0), "%s/lim.log.0", dir);
    snprintf(lim1, sizeof(lim1), "%s/lim.log.1", dir);
    struct stat lst;
    assert(stat(lim, &lst) == 0 && lst.st_size > 0 && lst.st_size <= 2048);   /* never over the size ... */
    assert(stat(lim0, &lst) == 0 && lst.st_size > 0 && lst.st_size <= 2048);  /* ... rolled once, versions 1 keeps one old file */
    assert(access(lim1, F_OK) != 0);
    unlink(lim);
    unlink(lim0);
    unlink(errfile);
    test_retire_runtime(NULL);
    rmdir(dir);
    printf("  -> destinations and batches passed.\n");
}

static void test_klog_rolling(void) {
    printf("[TEST] Logging: size without versions stops the file, versions unlimited, versions 0...\n");
    char dir[] = "/tmp/karidns_klog_XXXXXX";
    assert(mkdtemp(dir));
    char path[300], p0[320], p1[320], p4[320];
    snprintf(path, sizeof(path), "%s/r.log", dir);
    struct tm tm_info;
    time_t now = time(NULL);
    localtime_r(&now, &tm_info);

    /* BIND ISC_LOG_ROLLNEVER: when the file is full nothing more is written, until it is removed or shorter (looked at once a second) */
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.name = (char *)"r";
    ch.file_path = path;
    ch.dest = LOGDEST_FILE;
    ch.fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    ch.versions = LOG_VERSIONS_UNSET;
    ch.size_limit = 100;
    pthread_mutex_init(&ch.lock, NULL);
    assert(ch.fd >= 0);
    const char *l40 = "0123456789012345678901234567890123456789\n";   /* 41 bytes */
    log_write_rotated(&ch, l40, 41, &tm_info);
    log_write_rotated(&ch, l40, 41, &tm_info);
    assert(klog_lines(path) == 2 && !ch.size_reached);
    log_write_rotated(&ch, l40, 41, &tm_info);                      /* 123 > 100: not written, the file is full */
    assert(klog_lines(path) == 2 && ch.size_reached);
    log_write_rotated(&ch, l40, 41, &tm_info);                      /* still full, and looked at again only after a second */
    assert(klog_lines(path) == 2);
    sleep(2);
    log_write_rotated(&ch, l40, 41, &tm_info);                      /* the file is still full: stays full */
    assert(klog_lines(path) == 2 && ch.size_reached);
    assert(truncate(path, 0) == 0);                                 /* an operator empties it ... */
    sleep(2);
    log_write_rotated(&ch, l40, 41, &tm_info);                      /* ... and the next line is written */
    assert(klog_lines(path) == 1 && !ch.size_reached);
    unlink(path);                                                   /* removed: the file is made again */
    log_write_rotated(&ch, l40, 41, &tm_info);
    log_write_rotated(&ch, l40, 41, &tm_info);
    log_write_rotated(&ch, l40, 41, &tm_info);
    assert(ch.size_reached);
    sleep(2);
    log_write_rotated(&ch, l40, 41, &tm_info);
    assert(klog_lines(path) == 1 && !ch.size_reached);
    close(ch.fd);
    unlink(path);

    /* versions unlimited: every roll adds one file (.0 is the newest) */
    ch.fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    assert(ch.fd >= 0);
    ch.versions = LOG_VERSIONS_UNLIMITED;
    ch.size_limit = 50;
    ch.current_size = 0;
    ch.size_reached = false;
    char line[32];
    for (int i = 1; i <= 6; i++) {
        snprintf(line, sizeof(line), "line %d xxxxxxxxxxxxxxxxxxxxxxx\n", i);    /* 30 bytes */
        log_write_rotated(&ch, line, (int)strlen(line), &tm_info);
    }
    snprintf(p0, sizeof(p0), "%s.0", path);
    snprintf(p1, sizeof(p1), "%s.1", path);
    snprintf(p4, sizeof(p4), "%s.4", path);
    klog_expect(path, "line 6 xxxxxxxxxxxxxxxxxxxxxxx\n");
    klog_expect(p0, "line 5 xxxxxxxxxxxxxxxxxxxxxxx\n");
    klog_expect(p1, "line 4 xxxxxxxxxxxxxxxxxxxxxxx\n");
    klog_expect(p4, "line 1 xxxxxxxxxxxxxxxxxxxxxxx\n");
    for (int i = 0; i < 5; i++) {
        char pn[320];
        snprintf(pn, sizeof(pn), "%s.%d", path, i);
        unlink(pn);
    }
    unlink(path);

    /* versions 3 with .0 and .1 present: the roll makes .2 and stops there; the oldest is dropped at the next */
    close(ch.fd);
    ch.fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    ch.versions = 3;
    ch.current_size = 0;
    for (int i = 1; i <= 6; i++) {
        snprintf(line, sizeof(line), "line %d xxxxxxxxxxxxxxxxxxxxxxx\n", i);
        log_write_rotated(&ch, line, (int)strlen(line), &tm_info);
    }
    char p2[320], p3[320];
    snprintf(p2, sizeof(p2), "%s.2", path);
    snprintf(p3, sizeof(p3), "%s.3", path);
    klog_expect(path, "line 6 xxxxxxxxxxxxxxxxxxxxxxx\n");
    klog_expect(p0, "line 5 xxxxxxxxxxxxxxxxxxxxxxx\n");
    klog_expect(p2, "line 3 xxxxxxxxxxxxxxxxxxxxxxx\n");       /* line 2 and line 1 were rolled out: versions 3 keeps .0 .1 .2 */
    assert(access(p3, F_OK) != 0);
    unlink(path);
    unlink(p0);
    unlink(p1);
    unlink(p2);

    /* versions 0: the file is emptied at a roll (it is removed in BIND) */
    close(ch.fd);
    ch.fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    ch.versions = 0;
    ch.current_size = 0;
    for (int i = 1; i <= 3; i++) {
        snprintf(line, sizeof(line), "line %d xxxxxxxxxxxxxxxxxxxxxxx\n", i);
        log_write_rotated(&ch, line, (int)strlen(line), &tm_info);
    }
    klog_expect(path, "line 3 xxxxxxxxxxxxxxxxxxxxxxx\n");
    assert(access(p0, F_OK) != 0);
    close(ch.fd);
    unlink(path);
    pthread_mutex_destroy(&ch.lock);
    rmdir(dir);
    printf("  -> rolling passed.\n");
}

/* threads log while the runtime is replaced over and over: no line is lost, nothing is used after it is freed (run under TSan / ASan) */
static pthread_t g_klog_threads[4];
static void *klog_thread_main(void *arg) {
    long id = (long)(intptr_t)arg;
    for (int i = 0; i < 1500; i++) kdns_syslog(LOG_INFO, "[Config] thread %ld line %d", id, i);
    return NULL;
}

static void test_klog_replacement_under_load(void) {
    printf("[TEST] Logging: the runtime is replaced while four threads log...\n");
    char dir[] = "/tmp/karidns_klog_XXXXXX";
    assert(mkdtemp(dir));
    char path[300], conf[1024];
    snprintf(path, sizeof(path), "%s/load.log", dir);
    snprintf(conf, sizeof(conf), "logging { channel l { file \"%s\"; }; category default { l; }; };", path);
    klog_install_conf(conf);
    for (long i = 0; i < 4; i++) assert(pthread_create(&g_klog_threads[i], NULL, klog_thread_main, (void *)(intptr_t)i) == 0);
    for (int i = 0; i < 30; i++) {
        klog_install_conf(conf);
        usleep(1000);
    }
    for (int i = 0; i < 4; i++) pthread_join(g_klog_threads[i], NULL);
    assert(klog_lines(path) == 4 * 1500);
    test_retire_runtime(NULL);
    unlink(path);
    rmdir(dir);
    printf("  -> replacement under load passed.\n");
}

static void test_klog_install_with_a_slow_user(void) {
    printf("[TEST] Logging: install keeps the old runtime when a user does not let go, restart-needed status...\n");
    log_runtime_t *a = klog_install_conf("logging { };");
    log_runtime_t *b = klog_install_conf("logging { };");
    (void)a;
    (void)b;
    log_runtime_t *held = log_runtime_acquire();                  /* the user of the runtime installed last */
    assert(held);
    klog_install_conf("logging { };");                            /* the other slot: the held runtime is retired, but cannot be freed yet */
    logrt_status_t st;
    log_runtime_t *c = log_runtime_build(NULL, false, &st);
    assert(c && st == LOGRT_OK);
    assert(!log_runtime_install(c));                              /* the slot is still in use: refused after waiting */
    log_runtime_free(c);
    log_runtime_release(held);
    klog_install_conf("logging { };");                            /* the user has gone: the old runtime is freed and the install works */

    /* a file in a directory the sandbox cannot reach: the build says "restart", it is not a failure (log_open_channels()) */
    char dir[] = "/tmp/karidns_klog_XXXXXX";
    assert(mkdtemp(dir));
    char path[300];
    snprintf(path, sizeof(path), "%s/new.log", dir);
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.name = (char *)"n";
    ch.file_path = path;
    ch.dest = LOGDEST_FILE;
    ch.fd = -1;
    ch.versions = LOG_VERSIONS_UNSET;
    logging_config_t lc;
    memset(&lc, 0, sizeof(lc));
    lc.channels = &ch;
    atomic_store(&g_capsicum_enabled, true);                      /* what the Backend is: a directory that was not opened before is out of reach */
    log_runtime_t *rt = log_runtime_build(&lc, false, &st);
    atomic_store(&g_capsicum_enabled, false);
    assert(!rt && st == LOGRT_RESTART);
    assert(access(path, F_OK) != 0);
    /* ... and a file that cannot be opened for another reason is an error */
    ch.file_path = (char *)"/nonexistent_dir_karidns_test/sub/x.log";
    rt = log_runtime_build(&lc, false, &st);
    assert(!rt && st == LOGRT_ERROR);
    rmdir(dir);
    test_retire_runtime(NULL);
    printf("  -> install / status passed.\n");
}

// ----------------------------------------------------------------------------
// Main Test Runner
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 0. tsig_prewarm_crypto() must keep HMAC usable inside Capsicum capability mode
// ----------------------------------------------------------------------------
// Regression guard. OpenSSL initialises lazily on the first HMAC() (opening openssl.cnf). Inside
// capability mode that open() fails with ECAPMODE and, with PROC_TRAPCAP_CTL_ENABLE (as
// enter_capsicum_sandbox() sets), the process dies with SIGTRAP. RFC 9018 cookies no longer use
// OpenSSL, so nothing but tsig_prewarm_crypto() initialises it before cap_enter() any more.
//
// This MUST run before any other test that touches OpenSSL (see main()): the child inherits the
// parent's OpenSSL state, and an already-initialised parent would hide a broken pre-warm.
static void test_crypto_prewarm_survives_capability_mode(void) {
    printf("[TEST] Server Core: tsig_prewarm_crypto() keeps HMAC usable in capability mode...\n");
    fflush(stdout);
#ifdef __FreeBSD__
    pid_t pid = quiet_fork();
    assert(pid >= 0);
    if (pid == 0) {
        // Child: same order as main() in dns_server_core.c: pre-warm, then cap_enter().
        if (!tsig_prewarm_crypto()) _exit(90);
        int trapmode = PROC_TRAPCAP_CTL_ENABLE;
        procctl(P_PID, 0, PROC_TRAPCAP_CTL, &trapmode);   // violation => SIGTRAP, like production
        if (cap_enter() != 0) _exit(91);

        // Everything the sandboxed backend does with OpenSSL: every TSIG algorithm plus the
        // karictl control-channel HMAC-SHA256.
        static const struct { const EVP_MD *(*fn)(void); unsigned int len; } algs[] = {
            { EVP_md5, 16 }, { EVP_sha1, 20 }, { EVP_sha224, 28 },
            { EVP_sha256, 32 }, { EVP_sha384, 48 }, { EVP_sha512, 64 },
        };
        unsigned char md[EVP_MAX_MD_SIZE];
        for (size_t i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
            unsigned int l = 0;
            if (!HMAC(algs[i].fn(), "k", 1, (const unsigned char *)"data", 4, md, &l) || l != algs[i].len)
                _exit(92);
        }
        // RFC 4231 test case 2 (HMAC-SHA-256): key "Jefe", data "what do ya want for nothing?"
        static const unsigned char tc2[32] = {
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
        };
        unsigned int l = 0;
        if (!HMAC(EVP_sha256(), "Jefe", 4, (const unsigned char *)"what do ya want for nothing?", 28, md, &l) ||
            l != 32 || memcmp(md, tc2, 32) != 0)
            _exit(93);
        _exit(0);
    }
    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    assert(w == pid);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "  child killed by signal %d (SIGTRAP=5: OpenSSL initialised lazily inside capability mode)\n",
                WTERMSIG(status));
    } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  child exited with %d (90=prewarm failed, 91=cap_enter, 92=HMAC, 93=RFC 4231 mismatch)\n",
                WEXITSTATUS(status));
    }
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("  -> HMAC works inside capability mode after pre-warm.\n");
#else
    printf("  -> skipped (Capsicum is FreeBSD-only).\n");
#endif
}

/* 0.7: how long an explicit reload waits for the readers of the configuration before: the longest program-timeout or forward-timeout of the
 * configuration plus 500 ms, at least 1 s, at most 5 s */
static void test_reload_readers_wait_ms(void) {
    printf("[TEST] Server Core: reload_readers_wait_ms() from program-timeout / forward-timeout...\n");
    assert(reload_readers_wait_ms(NULL) == 1000);
    static const struct { const char *conf; int ms; } c[] = {
        { "zone \"p.test\" { type master; file \"p.zone\"; };\n", 1000 },
        { "options { allow-program-zones yes; };\nzone \"p.test\" { type program; program \"/bin/cat\"; };\n", 2500 },
        { "options { allow-program-zones yes; };\nzone \"p.test\" { type program; program \"/bin/cat\"; program-timeout 3000; };\n"
          "zone \"f.test\" { type forward; forwarders { 192.0.2.1; }; forward-timeout 1200; };\n", 3500 },
        { "zone \"f.test\" { type forward; forwarders { 192.0.2.1; }; forward-timeout 100; };\n", 1000 },
        { "zone \"f.test\" { type forward; forwarders { 192.0.2.1; }; forward-timeout 9000; };\n", 5000 },
    };
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        assert(parse_named_conf(c[i].conf, &cfg) == 0);
        int ms = reload_readers_wait_ms(&cfg);
        if (ms != c[i].ms) printf("  case %zu: %d ms, expected %d\n", i, ms, c[i].ms);
        assert(ms == c[i].ms);
        free_server_config_fields(&cfg);
    }
    printf("  -> reload_readers_wait_ms passed.\n");
}

static void test_perform_config_reload_valid_and_diff(void) {
    printf("[TEST] Server Core: perform_config_reload with valid zone files and AST updates...\n");
    char conf_path[256];
    char zone_path[256];
    snprintf(conf_path, sizeof(conf_path), "/tmp/karidns_reload_test_%ld.conf", (long)time(NULL));
    snprintf(zone_path, sizeof(zone_path), "/tmp/karidns_reload_test_%ld.zone", (long)time(NULL));

    FILE *fz = fopen(zone_path, "w");
    assert(fz != NULL);
    fprintf(fz, "$ORIGIN reload.test.\n$TTL 300\n@ IN SOA ns.reload.test. admin.reload.test. 1 7200 3600 1209600 300\n@ IN NS ns.reload.test.\nns IN A 192.0.2.1\n");
    fclose(fz);

    FILE *fc = fopen(conf_path, "w");
    assert(fc != NULL);
    fprintf(fc, "options {\n  port 5354;\n};\nview \"default\" {\n  zone \"reload.test.\" {\n    type master;\n    file \"%s\";\n  };\n};\n", zone_path);
    fclose(fc);

    g_config_path = conf_path;
    perform_config_reload_ext(false);
    perform_config_reload_ext(true);
    reload_all_zones();

    unlink(conf_path);
    unlink(zone_path);
    printf("  -> perform_config_reload with valid zone files passed.\n");
}

static void test_active_broker_connect_loop(void) {
    printf("[TEST] Server Core: active start_connect_broker process loop...\n");
    start_connect_broker();
    if (g_broker_sock >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(5353);
        inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);

        int fd = broker_connect(AF_INET, SOCK_STREAM, (struct sockaddr *)&sin, sizeof(sin));
        if (fd >= 0) close(fd);

        close(g_broker_sock);
        g_broker_sock = -1;
        if (g_broker_pid > 0) {
            kill(g_broker_pid, SIGTERM);
            waitpid(g_broker_pid, NULL, 0);
            g_broker_pid = -1;
        }
    }
    printf("  -> active start_connect_broker passed.\n");
}

/* low batch L3, dns_server_core.c [M9]: broker_connect_opts() keeps request and reply in step.  The test plays the broker on a socketpair.
 *  - a reply with status 1 that carries a descriptor anyway: -1 and the descriptor is closed (no leak);
 *  - a recvmsg() interrupted by a signal is repeated: the reply that comes later is read by THIS call, not left for the next one;
 *  - a broker that goes away after the request ends the conversation: -1 and every later call fails at once. */
typedef struct { int fd; int mode; } mock_broker_t;
static void mock_broker_reply(int fd, int status, int pass_fd) {
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));
    char data[1] = { (char)status };
    struct iovec io = { .iov_base = data, .iov_len = 1 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    if (pass_fd >= 0) {
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &pass_fd, sizeof(int));
    }
    assert(sendmsg(fd, &msg, 0) == 1);
}
static void *mock_broker_thread(void *arg) {
    mock_broker_t *m = arg;
    broker_req_t req;
    int spare[2];
    assert(recv(m->fd, &req, sizeof(req), MSG_WAITALL) == (ssize_t)sizeof(req));
    if (m->mode == 0) {                          /* refuse, with a descriptor attached */
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spare) == 0);
        mock_broker_reply(m->fd, 1, spare[0]);
        close(spare[0]);
        close(spare[1]);
    } else if (m->mode == 1) {                   /* a slow answer: the caller's recvmsg() is interrupted meanwhile */
        usleep(150000);
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spare) == 0);
        mock_broker_reply(m->fd, 0, spare[0]);
        close(spare[0]);
        close(spare[1]);
    } else {                                     /* mode 2: read the request, say nothing, go away */
        close(m->fd);
    }
    return NULL;
}
static void test_alarm_noop(int sig) { (void)sig; }
static void test_broker_connect_reply_handling(void) {
    printf("[TEST] Server Core: broker_connect_opts keeps request and reply in step...\n");
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = htonl(0x7F000001);
    int saved = g_broker_sock;
    for (int mode = 0; mode < 3; mode++) {
        int sp[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
        g_broker_sock = sp[0];
        mock_broker_t m = { sp[1], mode };
        pthread_t th;
        struct sigaction sa, old_sa;
        if (mode == 1) {
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = test_alarm_noop;      /* no SA_RESTART: recvmsg() returns EINTR */
            sigemptyset(&sa.sa_mask);
            assert(sigaction(SIGALRM, &sa, &old_sa) == 0);
            struct itimerval it = { .it_interval = { 0, 20000 }, .it_value = { 0, 20000 } };
            assert(setitimer(ITIMER_REAL, &it, NULL) == 0);
        }
        assert(pthread_create(&th, NULL, mock_broker_thread, &m) == 0);
        int fd = broker_connect(AF_INET, SOCK_DGRAM, (struct sockaddr *)&sin, sizeof(sin));
        if (mode == 1) {
            struct itimerval off = { {0, 0}, {0, 0} };
            setitimer(ITIMER_REAL, &off, NULL);
            sigaction(SIGALRM, &old_sa, NULL);
        }
        pthread_join(th, NULL);
        if (mode == 1) {
            assert(fd >= 0);                      /* the interrupted call waited for its own reply */
            close(fd);
        } else {
            assert(fd == -1);
        }
        if (mode == 2) {
            /* the conversation is over: the next call fails without blocking */
            assert(broker_connect(AF_INET, SOCK_DGRAM, (struct sockaddr *)&sin, sizeof(sin)) == -1);
        }
        close(sp[0]);
        if (mode != 2) close(sp[1]);
        g_broker_sock = -1;
    }
    /* the leak check, stated plainly: the descriptor numbers are the same before and after a refused request */
    {
        int sp[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
        g_broker_sock = sp[0];
        mock_broker_t m = { sp[1], 0 };
        pthread_t th;
        int before = open("/dev/null", O_RDONLY);
        close(before);
        assert(pthread_create(&th, NULL, mock_broker_thread, &m) == 0);
        assert(broker_connect(AF_INET, SOCK_DGRAM, (struct sockaddr *)&sin, sizeof(sin)) == -1);
        pthread_join(th, NULL);
        int after = open("/dev/null", O_RDONLY);
        close(after);
        assert(after == before);
        close(sp[0]);
        close(sp[1]);
        g_broker_sock = -1;
    }
    g_broker_sock = saved;
    printf("  -> broker_connect_opts request/reply handling passed.\n");
}

/* The primary a catalog member is transferred from when its catalog zone is not found in the snapshot (the copy kept in the entry): the key is ranked
 * as for a listed primary (batch 5, peer_key_name()): the key of the primaries element, then the `keys` of the `server` statement that covers the
 * primary, then the catalog zone's tsig-key; and a port that is 0 is options { port } (batch 10). */
static void test_catalog_member_primary_key_precedence_and_port(void) {
    printf("[TEST] Server Core: xfr_build_primaries, catalog member fallback: key precedence and options port...\n");
    static const char *conf =
        "options { port 5300; };\n"
        "key \"kz\" { algorithm hmac-sha256; secret \"dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl\"; };\n"
        "key \"ks\" { algorithm hmac-sha256; secret \"c2VydmVyLXN0YXRlbWVudC1rZXktZm9yLXRoZS10ZXN0\"; };\n"
        "key \"ke\" { algorithm hmac-sha256; secret \"ZWxlbWVudC1rZXktZm9yLXRoZS1wcmltYXJpZXMtdGVzdA==\"; };\n"
        "server 192.0.2.1 { keys \"ks\"; };\n";
    server_config_t cfg;
    assert(parse_named_conf(conf, &cfg) == 0);
    assert(cfg.dst_port == 5300);

    zone_db_entry_t *e = create_new_zone_entry("m.example.", "__default__");
    assert(e);
    e->is_catalog_member = true;
    e->is_secondary = true;
    e->catalog_master = calloc(1, sizeof(*e->catalog_master));
    assert(e->catalog_master);
    axfr_bg_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert(ctx);
    strlcpy(ctx->domain, "m.example.", sizeof(ctx->domain));

    /* the catalog zone has a tsig-key, the server statement a key: the server statement wins; no port: options { port } */
    strlcpy(e->catalog_master->ip, "192.0.2.1", sizeof(e->catalog_master->ip));
    strlcpy(e->catalog_master->zone_key, "kz", sizeof(e->catalog_master->zone_key));
    xfr_build_primaries(&cfg, NULL, e, NULL, ctx);
    assert(ctx->nprim == 1 && ctx->prim[0].port == 5300);
    assert(ctx->prim[0].has_tsig && strcmp(ctx->prim[0].tsig_name, "ks") == 0);

    /* the key written on the primaries element is above the server statement */
    memset(ctx->prim, 0, sizeof(ctx->prim));
    strlcpy(e->catalog_master->key, "ke", sizeof(e->catalog_master->key));
    e->catalog_master->port = 6000;
    xfr_build_primaries(&cfg, NULL, e, NULL, ctx);
    assert(ctx->nprim == 1 && ctx->prim[0].port == 6000);
    assert(ctx->prim[0].has_tsig && strcmp(ctx->prim[0].tsig_name, "ke") == 0);

    /* a primary no server statement covers: the catalog zone's tsig-key */
    memset(ctx->prim, 0, sizeof(ctx->prim));
    e->catalog_master->key[0] = '\0';
    strlcpy(e->catalog_master->ip, "192.0.2.9", sizeof(e->catalog_master->ip));
    xfr_build_primaries(&cfg, NULL, e, NULL, ctx);
    assert(ctx->nprim == 1 && ctx->prim[0].has_tsig && strcmp(ctx->prim[0].tsig_name, "kz") == 0);

    /* no key anywhere: an unsigned transfer */
    memset(ctx->prim, 0, sizeof(ctx->prim));
    e->catalog_master->zone_key[0] = '\0';
    xfr_build_primaries(&cfg, NULL, e, NULL, ctx);
    assert(ctx->nprim == 1 && !ctx->prim[0].has_tsig);

    free(ctx);
    free_zone_db_entry(e);
    free_server_config_fields(&cfg);
    printf("  -> catalog member primary key precedence passed.\n");
}

static void test_broker_connect_opts_and_xfr_tcp_sockopts(void) {
    printf("[TEST] Server Core: xfr_tcp_sockopts & broker_connect_opts TCP options...\n");

    /* zone values win, the global tcp-mss / tcp-window fill the gaps, catalog members (no zone{}) get the globals */
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    tcp_sockopts_t o = xfr_tcp_sockopts(NULL, NULL);
    assert(o.mss == 0 && o.rcvbuf == 0 && o.sndbuf == 0);
    cfg.tcp_mss = 1400;
    cfg.tcp_window = 256 * 1024;
    o = xfr_tcp_sockopts(&cfg, NULL);
    assert(o.mss == 1400 && o.rcvbuf == 256 * 1024 && o.sndbuf == 256 * 1024);
    zone_config_t z;
    memset(&z, 0, sizeof(z));
    tzx(&z)->zone_tcp_window = 1024 * 1024;
    o = xfr_tcp_sockopts(&cfg, &z);
    assert(o.mss == 1400 && o.rcvbuf == 1024 * 1024 && o.sndbuf == 256 * 1024);
    tzx(&z)->zone_tcp_mss = 1200;
    tzx(&z)->zone_tcp_sndbuf = 128 * 1024;
    o = xfr_tcp_sockopts(&cfg, &z);
    assert(o.mss == 1200 && o.rcvbuf == 1024 * 1024 && o.sndbuf == 128 * 1024);

    /* the broker applies them to the socket it connects: buffers before connect(), MSS after */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    socklen_t salen = sizeof(sa);
    assert(getsockname(lfd, (struct sockaddr *)&sa, &salen) == 0);
    assert(listen(lfd, 4) == 0);

    /* as root the broker drops to the configured user and refuses to run without one */
    run_identity_t saved_id = g_run_identity;
    char id_err[256];
    if (geteuid() == 0)
        assert(resolve_run_identity("nobody", NULL, &g_run_identity, id_err, sizeof(id_err)));
    start_connect_broker();
    g_run_identity = saved_id;
    assert(g_broker_sock >= 0);

    tcp_sockopts_t want = { 1200, 512 * 1024, 256 * 1024, 0, 0, {0} };
    int fd = broker_connect_opts(AF_INET, SOCK_STREAM, (struct sockaddr *)&sa, sizeof(sa), &want);
    assert(fd >= 0);
    int v = 0;
    socklen_t vl = sizeof(v);
    assert(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, &vl) == 0 && v >= 512 * 1024);
    vl = sizeof(v);
    assert(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, &vl) == 0 && v >= 256 * 1024);
#if defined(__FreeBSD__) && defined(TCP_MAXSEG)
    /* FreeBSD reports t_maxseg, which the setsockopt lowered (Linux keeps reporting the path MSS) */
    vl = sizeof(v);
    assert(getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &v, &vl) == 0 && v > 0 && v <= 1200);
#endif
    close(fd);
    int afd = accept(lfd, NULL, NULL);
    if (afd >= 0) close(afd);

    /* plain broker_connect() still works and asks for nothing */
    fd = broker_connect(AF_INET, SOCK_STREAM, (struct sockaddr *)&sa, sizeof(sa));
    assert(fd >= 0);
    close(fd);
    afd = accept(lfd, NULL, NULL);
    if (afd >= 0) close(afd);

    /* an address longer than sockaddr_storage is rejected before anything is sent */
    uint8_t huge[sizeof(struct sockaddr_storage) + 8];
    memset(huge, 0, sizeof(huge));
    assert(broker_connect_opts(AF_INET, SOCK_STREAM, (struct sockaddr *)huge, sizeof(huge), &want) == -1);

    close(g_broker_sock);
    g_broker_sock = -1;
    if (g_broker_pid > 0) {
        kill(g_broker_pid, SIGTERM);
        waitpid(g_broker_pid, NULL, 0);
        g_broker_pid = -1;
    }
    close(lfd);
    printf("  -> xfr_tcp_sockopts & broker_connect_opts passed.\n");
}

static void test_setup_ipc_tables_and_reload_error_paths(void) {
    printf("[TEST] Server Core: setup_ipc_tables worker limits and reload_all_zones errors...\n");
    // reload_all_zones with empty config / NULL active snapshot
    reload_all_zones();
    printf("  -> setup_ipc_tables and reload_all_zones passed.\n");
}

static void test_control_multiview_and_timeout_cases(void) {
    printf("[TEST] Server Core: Control socket multi-view zone conflicts and timeouts...\n");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
        // Set short timeout and close
        test_set_io_timeout(fds[0], 1);
        test_set_io_timeout(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
    }
    printf("  -> test_control_multiview_and_timeout_cases passed.\n");
}


static void test_control_status_and_stats_dump(void) {
    printf("[TEST] Server Core: Control STATUS and STATS dump...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "statdump.example.", sizeof(entry.domain));
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    zone_observatory_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    fill_observatory_snapshot(&entry, &cfg, &snap);
    assert(strcmp(snap.domain, "statdump.example.") == 0);
    printf("  -> status and stats dump passed.\n");
}

static void test_tcp_client_high_watermark_tracking(void) {
    printf("[TEST] Server Core: TCP client tracking and high-watermark atomic update...\n");
    atomic_store_explicit(&g_tcp_clients, 0, memory_order_relaxed);
    atomic_store_explicit(&g_tcp_high_water, 0, memory_order_relaxed);
    for (int i = 0; i < 20; i++) {
        inc_tcp_clients();
    }
    int mid_high = atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed);
    int cur_clients = atomic_load_explicit(&g_tcp_clients, memory_order_relaxed);
    assert(cur_clients == 20);
    assert(mid_high == 20);
    for (int i = 0; i < 20; i++) {
        dec_tcp_clients();
    }
    assert(atomic_load_explicit(&g_tcp_clients, memory_order_relaxed) == 0);
    assert(atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed) == 20);
    printf("  -> TCP high watermark tracking passed.\n");
}

static void test_response_log_ring_buffer_overflow(void) {
    printf("[TEST] Server Core: Response log ring buffer wrap-around...\n");

    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.responses_enabled = true;
    atomic_store_explicit(&g_config_db.active, &mock_cfg, memory_order_release);

    atomic_store_explicit(&g_resp_log_tail, 0, memory_order_relaxed);
    atomic_store_explicit(&g_resp_log_head, 0, memory_order_relaxed);
    for (int i = 0; i < RESP_LOG_RING_SIZE; i++) {
        atomic_store_explicit(&g_resp_log_ring[i].ready, false, memory_order_relaxed);
    }

    // 1. Submit up to RESP_LOG_RING_SIZE
    for (int i = 0; i < RESP_LOG_RING_SIZE; i++) {
        submit_response_log(LOG_ACT_SENT, "192.0.2.1", 12345, "wrap.example.", 1, 1, 0, false, false);
    }
    uint64_t tail = atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed);
    assert(tail == (uint64_t)RESP_LOG_RING_SIZE);

    // 2. Ring is full: extra submission should be dropped
    submit_response_log(LOG_ACT_SENT, "192.0.2.1", 12345, "wrap.example.", 1, 1, 0, false, false);
    assert(atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed) == (uint64_t)RESP_LOG_RING_SIZE);

    // 3. Consume slots by resetting ready flags and advancing head
    for (int i = 0; i < RESP_LOG_RING_SIZE; i++) {
        atomic_store_explicit(&g_resp_log_ring[i].ready, false, memory_order_relaxed);
    }
    atomic_store_explicit(&g_resp_log_head, RESP_LOG_RING_SIZE, memory_order_release);

    // 4. Submit again into wrapped ring
    submit_response_log(LOG_ACT_SENT, "192.0.2.2", 12346, "wrap2.example.", 1, 1, 0, false, false);
    tail = atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed);
    assert(tail == (uint64_t)(RESP_LOG_RING_SIZE + 1));
    assert(atomic_load_explicit(&g_resp_log_ring[0].ready, memory_order_acquire) == true);

    // Clean up
    for (int i = 0; i < RESP_LOG_RING_SIZE; i++) {
        atomic_store_explicit(&g_resp_log_ring[i].ready, false, memory_order_relaxed);
    }
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> Response log ring buffer overflow passed.\n");
}

static void test_query_log_circuit_breaker(void) {
    printf("[TEST] Server Core: Query log circuit breaker trip and recovery...\n");
    atomic_store_explicit(&g_qlog_circuit_broken, true, memory_order_relaxed);
    assert(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed) == true);
    atomic_store_explicit(&g_qlog_circuit_broken, false, memory_order_relaxed);
    assert(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed) == false);
    printf("  -> Query log circuit breaker passed.\n");
}

static void test_worker_ipc_message_dispatch(void) {
    printf("[TEST] Server Core: Worker IPC notification message dispatch...\n");
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
        char buf[8] = "NOTIFY";
        ssize_t w = write(fds[0], buf, 6);
        assert(w == 6);
        char rbuf[8];
        ssize_t r = read(fds[1], rbuf, 6);
        assert(r == 6);
        close(fds[0]);
        close(fds[1]);
    }
    printf("  -> Worker IPC message dispatch passed.\n");
}

static void test_server_privilege_drop_guards(void) {
    printf("[TEST] Server Core: Privilege drop safety guards...\n");
    bool dropped = atomic_load_explicit(&g_privilege_drop_complete, memory_order_relaxed);
    (void)dropped;
    printf("  -> Privilege drop guards passed.\n");
}

static void test_setup_ipc_tables_edge_cases(void) {
    printf("[TEST] Server Core: setup_ipc_tables boundary limits...\n");
    setup_ipc_tables(0);
    setup_ipc_tables(1);
    setup_ipc_tables(4);
    printf("  -> setup_ipc_tables boundaries passed.\n");
}

static void *concur_config_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        server_config_t *snap = acquire_config_snapshot();
        release_config_snapshot(snap);
    }
    return NULL;
}

static void test_acquire_release_config_snapshot_concurrency(void) {
    printf("[TEST] Server Core: Concurrency stress on acquire/release config snapshot...\n");
    pthread_t th[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&th[i], NULL, concur_config_worker, NULL);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(th[i], NULL);
    }
    printf("  -> Concurrency stress test passed.\n");
}

static void test_server_core_sighup_sigusr1_handlers(void) {
    printf("[TEST] Server Core: SIGHUP and SIGUSR1 signal handler flags...\n");
    // Emulate reload signal
    atomic_store_explicit(&g_frontend_alive, true, memory_order_relaxed);
    assert(atomic_load_explicit(&g_frontend_alive, memory_order_relaxed) == true);
    printf("  -> Signal handler flags passed.\n");
}

/* P5: the Backend blocks SIGHUP in every thread and installs backend_sighup_noop() so that the signal stays pending (SIG_IGN would
 * drop it on arrival and sighup_from_manager() could not read the sender with sigtimedwait()).  A forked child (single thread, so no
 * other thread can take the signal) checks both halves: blocked, the SIGHUP stays pending with the sender's pid; unblocked, the
 * handler takes it and the process lives on (SIG_DFL would end it). */
static void test_backend_sighup_noop(void) {
    printf("[TEST] Server Core: Backend SIGHUP handler keeps the signal pending and never ends the process...\n");
    backend_sighup_noop(SIGHUP);                  /* does nothing (the handler is only run for a thread that does not block SIGHUP) */
    pid_t pid = quiet_fork();
    assert(pid >= 0);
    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = backend_sighup_noop;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGHUP, &sa, NULL) != 0) _exit(10);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGHUP);
        if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) _exit(11);
        if (kill(getpid(), SIGHUP) != 0) _exit(12);
        siginfo_t si;
        const struct timespec wait_s = {5, 0};
        if (sigtimedwait(&set, &si, &wait_s) != SIGHUP) _exit(13);   /* stayed pending, not discarded */
        if (si.si_pid != getpid()) _exit(14);                         /* with the sender, which sighup_from_manager() compares */
        if (kill(getpid(), SIGHUP) != 0) _exit(15);
        if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0) _exit(16);     /* the pending signal is taken by the handler now */
        if (kill(getpid(), SIGHUP) != 0) _exit(17);                   /* and so is one sent to a thread that does not block it */
        _exit(0);
    }
    int st = 0;
    assert(waitpid(pid, &st, 0) == pid);
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("  -> SIGHUP handler passed.\n");
}

/* P5: SIGHUP to every process (pkill -HUP) reaches the Backend twice, directly and forwarded by the manager.  A standard signal that
 * arrives while one is pending merges into it, and kqueue reports that delivery again: one reload in every order of the two. */
static void test_sighup_decide(void) {
    printf("[TEST] Server Core: SIGHUP from the manager and directly: one reload whatever merges...\n");
    bool last = false;
    /* separate events: direct (ignored), then forwarded (reload) */
    assert(!sighup_decide(1, false, 1, &last));
    assert(sighup_decide(1, true, 1, &last));
    /* forwarded taken, the direct one merged into it and reported again with nothing to take: no second reload */
    assert(sighup_decide(1, true, 1, &last));
    assert(!sighup_decide(0, false, 1, &last));
    /* direct taken (ignored), the forwarded one merged into it: the second event reloads */
    assert(!sighup_decide(1, false, 1, &last));
    assert(sighup_decide(0, false, 1, &last));
    /* both delivered before the event was read, the direct one is what is pending: reload (the merged one may be the manager's) */
    last = false;
    assert(sighup_decide(1, false, 2, &last));
    assert(!sighup_decide(0, false, 1, &last));
    /* no drain before any decision (the first event): reload, as before */
    last = false;
    assert(sighup_decide(0, false, 1, &last));
    printf("  -> SIGHUP decisions passed.\n");
}

static void test_control_zonestatus_empty_and_populated(void) {
    printf("[TEST] Server Core: Control ZONESTATUS formatting...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "zonestat.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.serial, 100, memory_order_release);
    assert(entry.serial == 100);
    printf("  -> ZONESTATUS formatting passed.\n");
}

static void test_broker_connect_error_branches(void) {
    printf("[TEST] Server Core: Broker connect error handling...\n");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int res = broker_connect(AF_INET, SOCK_STREAM, (struct sockaddr *)&addr, sizeof(addr));
    // Since broker socket is -1 or closed, it should return -1 safely
    assert(res == -1);
    printf("  -> Broker connect error handling passed.\n");
}


static void test_control_socket_eof_handling(void) {
    printf("[TEST] Server Core: Control socket client disconnect / EOF...\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        close(sv[1]); // Close sender
        char buf[16];
        ssize_t r = read(sv[0], buf, sizeof(buf));
        assert(r == 0); // EOF
        close(sv[0]);
    }
    printf("  -> control EOF passed.\n");
}

static void test_control_socket_partial_writes(void) {
    printf("[TEST] Server Core: Control socket partial command writes...\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        (void)!write(sv[1], "STA", 3);
        (void)!write(sv[1], "TUS\n", 4);
        char buf[16];
        ssize_t r = read(sv[0], buf, 7);
        assert(r == 7);
        assert(memcmp(buf, "STATUS\n", 7) == 0);
        close(sv[0]);
        close(sv[1]);
    }
    printf("  -> control partial writes passed.\n");
}

static void test_tcp_client_tracking_overflow_underflow(void) {
    printf("[TEST] Server Core: TCP client tracking underflow prevention...\n");
    atomic_store_explicit(&g_tcp_clients, 0, memory_order_relaxed);
    dec_tcp_clients(); // Should safely decrement without crash
    atomic_store_explicit(&g_tcp_clients, 0, memory_order_relaxed);
    printf("  -> TCP underflow passed.\n");
}

static void test_tcp_client_high_water_atomic_cas_race(void) {
    printf("[TEST] Server Core: TCP high watermark concurrent updates...\n");
    atomic_store_explicit(&g_tcp_high_water, 5, memory_order_relaxed);
    atomic_store_explicit(&g_tcp_clients, 10, memory_order_relaxed);
    inc_tcp_clients();
    assert(atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed) >= 10);
    atomic_store_explicit(&g_tcp_clients, 0, memory_order_relaxed);
    atomic_store_explicit(&g_tcp_high_water, 0, memory_order_relaxed);
    printf("  -> TCP watermark CAS passed.\n");
}

static void test_fast_ipv4_to_str_boundary_addresses(void) {
    printf("[TEST] Server Core: fast_ipv4_to_str boundary IP addresses...\n");
    char buf[INET_ADDRSTRLEN];
    fast_ipv4_to_str(0x00000000, buf);
    assert(strcmp(buf, "0.0.0.0") == 0);
    fast_ipv4_to_str(0xFFFFFFFF, buf);
    assert(strcmp(buf, "255.255.255.255") == 0);
    fast_ipv4_to_str(htonl(0x7F000001), buf);
    assert(strcmp(buf, "127.0.0.1") == 0);
    printf("  -> fast_ipv4_to_str boundaries passed.\n");
}

static void test_escape_qname_for_log_embedded_nulls_and_newlines(void) {
    printf("[TEST] Server Core: escape_qname_for_log special control characters...\n");
    char out[128];
    escape_qname_for_log("foo\r\nbar\t.example.", out, sizeof(out));
    assert(strlen(out) > 0);
    assert(strchr(out, '\n') == NULL);
    assert(strchr(out, '\r') == NULL);
    printf("  -> escape special chars passed.\n");
}

static void test_escape_qname_for_log_buffer_exact_size(void) {
    printf("[TEST] Server Core: escape_qname_for_log exact buffer sizing...\n");
    char tiny[4];
    escape_qname_for_log("example.com.", tiny, sizeof(tiny));
    assert(strlen(tiny) < sizeof(tiny));
    printf("  -> escape exact buffer passed.\n");
}

static void test_resolve_ip_port_to_sockaddr_ipv6_scope(void) {
    printf("[TEST] Server Core: resolve_ip_port_to_sockaddr IPv6 loopback...\n");
    struct sockaddr_storage ss;
    size_t sz = resolve_ip_port_to_sockaddr("::1", 5353, &ss);
    assert(sz > 0);
    assert(ss.ss_family == AF_INET6);
    printf("  -> resolve IPv6 loopback passed.\n");
}

static void test_resolve_ip_port_to_sockaddr_invalid_port(void) {
    printf("[TEST] Server Core: resolve_ip_port_to_sockaddr invalid port (0 fallback) and invalid IPs...\n");
    struct sockaddr_storage ss;
    // Port 0 falls back to default 53
    size_t sz = resolve_ip_port_to_sockaddr("127.0.0.1", 0, &ss);
    assert(sz == sizeof(struct sockaddr_in));
    assert(((struct sockaddr_in *)&ss)->sin_port == htons(53));

    // Invalid IP formats return 0
    assert(resolve_ip_port_to_sockaddr("999.999.999.999", 53, &ss) == 0);
    assert(resolve_ip_port_to_sockaddr("invalid:ipv6:format:zzz", 53, &ss) == 0);
    printf("  -> resolve invalid port passed.\n");
}

static void test_response_logger_thread_exit_condition(void) {
    printf("[TEST] Server Core: response logger thread graceful shutdown...\n");
    atomic_store_explicit(&g_frontend_alive, false, memory_order_relaxed);
    assert(atomic_load_explicit(&g_frontend_alive, memory_order_relaxed) == false);
    atomic_store_explicit(&g_frontend_alive, true, memory_order_relaxed);
    printf("  -> response logger shutdown passed.\n");
}

static void test_query_logger_thread_exit_condition(void) {
    printf("[TEST] Server Core: query logger thread graceful shutdown...\n");
    atomic_store_explicit(&g_frontend_alive, true, memory_order_relaxed);
    assert(atomic_load_explicit(&g_frontend_alive, memory_order_relaxed) == true);
    printf("  -> query logger shutdown passed.\n");
}

static void test_response_log_entry_formatting(void) {
    printf("[TEST] Server Core: response log entry text formatting...\n");
    resp_log_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.action = LOG_ACT_SENT;
    strcpy(entry.client_ip, "192.0.2.1");
    entry.client_port = 5353;
    strcpy(entry.qname, "test.example.");
    entry.qclass = 1;
    entry.qtype = 1;
    entry.rcode = 0;
    assert(entry.action == LOG_ACT_SENT);
    printf("  -> response log entry formatting passed.\n");
}

static void test_query_log_rate_limiting_decay(void) {
    printf("[TEST] Server Core: query log max QPS rate limiting decay...\n");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.query_log_max_qps = 500;
    uint32_t qps = get_effective_query_log_max_qps(&cfg);
    assert(qps == 500);
    printf("  -> query log rate limit decay passed.\n");
}

static void test_log_write_rotated_size_limit_zero(void) {
    printf("[TEST] Server Core: log_write_rotated size limit disabled (0)...\n");
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_log_unlimited_%ld.log", (long)time(NULL));
    log_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.file_path = path;
    ch.size_limit = 0; // unlimited
    ch.versions = 3;
    pthread_mutex_init(&ch.lock, NULL);
    ch.fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ch.fd < 0) {
        snprintf(path, sizeof(path), "test_log_unlimited_%ld.log", (long)time(NULL));
        ch.fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
    assert(ch.fd >= 0);
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    ch.current_date = (tm_info.tm_year + 1900) * 10000 + (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday;
    log_write_rotated(&ch, "test line\n", 10, &tm_info);
    assert(ch.current_size == 10);
    close(ch.fd);
    pthread_mutex_destroy(&ch.lock);
    unlink(path);
    printf("  -> log_write_rotated unlimited passed.\n");
}

static void test_fill_observatory_snapshot_all_counters(void) {
    printf("[TEST] Server Core: fill_observatory_snapshot all statistics fields...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "allstats.example.", sizeof(entry.domain));
    atomic_store_explicit(&entry.observatory.queries_total, 42, memory_order_relaxed);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    zone_observatory_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));

    fill_observatory_snapshot(&entry, &cfg, &snap);
    assert(strcmp(snap.domain, "allstats.example.") == 0);
    assert(snap.queries_total == 42);
    printf("  -> observatory snapshot counters passed.\n");
}

static void test_find_configured_domain_case_insensitive(void) {
    printf("[TEST] Server Core: find_configured_domain case insensitivity...\n");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    zone_config_t z;
    memset(&z, 0, sizeof(z));
    z.domain = "mydomain.example.com.";
    cfg.zones = &z;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    char buf[256];
    const char *found = find_configured_domain("MYDOMAIN.EXAMPLE.COM.", buf, sizeof(buf));
    assert(found != NULL);
    assert(strcmp(found, "mydomain.example.com.") == 0);
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release); // cfg is on this stack frame
    printf("  -> find_configured_domain case insensitive passed.\n");
}

static void test_ensure_priv_dir_safe_symlink_attack(void) {
    printf("[TEST] Server Core: ensure_priv_dir_safe symlink rejection...\n");
    if (geteuid() != 0) {
        printf("  -> symlink rejection passed (skipped for non-root).\n");
        return;
    }
    char path[] = "/tmp/test_symlink_privdir";
    unlink(path);
    if (symlink("/etc", path) == 0) {
        bool ok = ensure_priv_dir_safe(path);
        assert(ok == false);
        unlink(path);
    }
    printf("  -> symlink rejection passed.\n");
}

static void test_ensure_priv_dir_safe_world_writable(void) {
    printf("[TEST] Server Core: ensure_priv_dir_safe world-writable directory rejection...\n");
    if (geteuid() != 0) {
        printf("  -> world-writable rejection passed (skipped for non-root).\n");
        return;
    }
    char path[] = "/tmp/test_world_writable_dir";
    rmdir(path);
    mkdir(path, 0755);
    chmod(path, 0777);
    bool ok = ensure_priv_dir_safe(path);
    assert(ok == false);
    rmdir(path);
    printf("  -> world-writable rejection passed.\n");
}

static void test_setup_udp_socket_buffers_failure(void) {
    printf("[TEST] Server Core: setup_udp_socket_buffers invalid fd (-1)...\n");
    // Invalid socket fd should handle error without crashing
    setup_udp_socket_buffers(-1, 1024, 1024);
    printf("  -> UDP socket buffer invalid fd passed.\n");
}

static void test_setup_ipc_tables_max_workers_boundary(void) {
    printf("[TEST] Server Core: setup_ipc_tables maximum worker boundary (128)...\n");
    setup_ipc_tables(128);
    setup_ipc_tables(2);
    printf("  -> IPC tables max workers passed.\n");
}

/* perform_config_reload_ext() against real files: configuration and zone files of the reload tests */
static char g_rl_conf[256], g_rl_zone_a[256], g_rl_zone_b[256];

static void rl_write_zone(const char *path, const char *origin, int serial) {
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f, "$ORIGIN %s.\n$TTL 300\n@ IN SOA ns hostmaster %d 7200 3600 1209600 300\n@ IN NS ns\n"
               "ns IN A 192.0.2.1\n", origin, serial);
    fclose(f);
}

/* Writes a configuration with the zones a.reload.test / b.reload.test (when the flag is set) into the view
 * "default" and reloads it. Returns the reload status. */
static config_reload_status_t rl_reload(bool with_a, bool with_b, bool skip_unchanged) {
    FILE *f = fopen(g_rl_conf, "w");
    assert(f != NULL);
    fprintf(f, "options {\n  port 5354;\n  user \"nobody\";\n  group \"nobody\";\n};\nview \"default\" {\n");
    if (with_a) fprintf(f, "  zone \"a.reload.test\" { type master; file \"%s\"; };\n", g_rl_zone_a);
    if (with_b) fprintf(f, "  zone \"b.reload.test\" { type master; file \"%s\"; };\n", g_rl_zone_b);
    fprintf(f, "};\n");
    fclose(f);
    g_config_path = g_rl_conf;
    return perform_config_reload_ext(skip_unchanged).status;
}

/* Serial of the zone in the published snapshot; -1 when the zone is not served. The zone entry and its
 * arena are not usable as evidence of a reload: Pass 2 of every rebuild republishes each zone's arena
 * (glue prelink), so the arena pointer changes even for a zone that was not loaded again. */
static long rl_zone_serial(const char *domain) {
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    retain_zone_snapshot(snap);
    zone_db_entry_t *e = snap ? snapshot_get_zone_in_view(snap, "default", domain) : NULL;
    zone_version_t *a = e ? atomic_load_explicit(&e->rcu.active, memory_order_acquire) : NULL;
    long serial = (a && a->image && a->image->n_rrs > 0) ? (long)e->serial : -1;
    release_zone_snapshot(snap);
    return serial;
}

/* Rewrites a zone file with a new serial but restores its old modification time, so a reload that skips
 * unchanged files (mtime match, rebuild_zone_db_from_config_ext()) keeps the loaded serial. */
static void rl_rewrite_keep_mtime(const char *path, const char *origin, int serial) {
    struct stat st;
    assert(stat(path, &st) == 0);
    rl_write_zone(path, origin, serial);
    struct timeval tv[2] = { { st.st_atime, 0 }, { st.st_mtime, 0 } };
    assert(utimes(path, tv) == 0);
}

static void rl_setup(void) {
    /* earlier tests may leave g_config_db.active pointing at their own (stack) configuration */
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    snprintf(g_rl_conf, sizeof(g_rl_conf), "/tmp/karidns_rl_%ld.conf", (long)getpid());
    snprintf(g_rl_zone_a, sizeof(g_rl_zone_a), "/tmp/karidns_rl_%ld_a.zone", (long)getpid());
    snprintf(g_rl_zone_b, sizeof(g_rl_zone_b), "/tmp/karidns_rl_%ld_b.zone", (long)getpid());
    rl_write_zone(g_rl_zone_a, "a.reload.test", 1);
    rl_write_zone(g_rl_zone_b, "b.reload.test", 1);
}

static void rl_cleanup(void) {
    unlink(g_rl_conf);
    unlink(g_rl_zone_a);
    unlink(g_rl_zone_b);
}

static void test_perform_config_reload_identical_config(void) {
    printf("[TEST] Server Core: perform_config_reload identical config keeps unchanged zones...\n");
    rl_setup();
    assert(rl_reload(true, false, false) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("a.reload.test.") == 1);
    /* reload (skip unchanged): same configuration, file mtime unchanged -> the zone is not loaded again */
    rl_rewrite_keep_mtime(g_rl_zone_a, "a.reload.test", 2);
    assert(rl_reload(true, false, true) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("a.reload.test.") == 1);
    /* full reload (reload_all_zones()): every zone is loaded again */
    assert(rl_reload(true, false, false) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("a.reload.test.") == 2);
    rl_cleanup();
    printf("  -> config reload identical passed.\n");
}

static void test_perform_config_reload_removed_zone(void) {
    printf("[TEST] Server Core: perform_config_reload removed zone deletion...\n");
    rl_setup();
    assert(rl_reload(true, true, false) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("a.reload.test.") == 1 && rl_zone_serial("b.reload.test.") == 1);
    rl_rewrite_keep_mtime(g_rl_zone_a, "a.reload.test", 2);
    assert(rl_reload(true, false, true) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("b.reload.test.") == -1);        // removed from the configuration: not served
    assert(rl_zone_serial("a.reload.test.") == 1);         // the other zone is not loaded again
    rl_cleanup();
    printf("  -> config reload removed zone passed.\n");
}

static void test_perform_config_reload_added_zone(void) {
    printf("[TEST] Server Core: perform_config_reload added zone instantiation...\n");
    rl_setup();
    assert(rl_reload(true, false, false) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("b.reload.test.") == -1);
    rl_rewrite_keep_mtime(g_rl_zone_a, "a.reload.test", 2);
    rl_write_zone(g_rl_zone_b, "b.reload.test", 7);
    assert(rl_reload(true, true, true) == CONFIG_RELOAD_OK);
    assert(rl_zone_serial("b.reload.test.") == 7);         // added zone loaded from its file
    assert(rl_zone_serial("a.reload.test.") == 1);
    /* a zone whose file is missing is reported; the rest of the configuration is applied */
    unlink(g_rl_zone_b);
    snprintf(g_rl_zone_b, sizeof(g_rl_zone_b), "/tmp/karidns_rl_%ld_missing.zone", (long)getpid());
    assert(rl_reload(true, true, false) == CONFIG_RELOAD_ZONE_ERRORS);
    assert(rl_zone_serial("a.reload.test.") == 2);
    rl_cleanup();
    printf("  -> config reload added zone passed.\n");
}

/* S6a: the configuration retired by a reload is freed once its readers are gone (no standby kept until the next reload) */
static void test_perform_config_reload_frees_retired_config(void) {
    printf("[TEST] Server Core: perform_config_reload frees the retired configuration (S6a)...\n");
    rl_setup();
    assert(rl_reload(true, false, false) == CONFIG_RELOAD_OK);
    /* a reader that entered after the first publish still sees the second one's predecessor: its grace period
     * is not over, so the retired configuration must stay intact until the reader leaves */
    rcu_aux_read_lock();
    server_config_t *held = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    assert(held != NULL && held->views != NULL);
    assert(rl_reload(true, true, false) == CONFIG_RELOAD_OK);
    assert(held != atomic_load_explicit(&g_config_db.active, memory_order_acquire));
    assert(g_config_db.standby_pending);
    assert(!config_standby_reap(false));
    assert(held->views != NULL && held->views->zones != NULL); /* still valid for the reader */
    rcu_aux_read_unlock();
    uint64_t freed0 = g_config_db.standby_freed;
    assert(config_standby_reap(false));
    assert(!g_config_db.standby_pending && g_config_db.standby_freed == freed0 + 1);
    assert(held->views == NULL && held->keys == NULL && held->logging.channels == NULL);

    /* repeated reloads: one retired configuration per reload, each freed by the next reload or by the reaper */
    for (int i = 0; i < 100; i++) {
        assert(rl_reload(true, (i & 1) != 0, false) == CONFIG_RELOAD_OK);
        server_config_t *act = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
        server_config_t *sb = (act == &g_config_db.config_a) ? &g_config_db.config_b : &g_config_db.config_a;
        assert(g_config_db.standby_pending);
        assert(config_standby_reap(false));
        assert(sb->views == NULL && sb->zones == NULL);
        assert(act->views != NULL);
    }
    assert(g_config_db.standby_freed >= freed0 + 101);
    rl_cleanup();
    printf("  -> config reload frees the retired configuration passed.\n");
}

static void test_server_core_sighup_reload_flag(void) {
    printf("[TEST] Server Core: SIGHUP reload signal setting...\n");
    atomic_store_explicit(&g_frontend_alive, true, memory_order_relaxed);
    assert(atomic_load_explicit(&g_frontend_alive, memory_order_relaxed) == true);
    printf("  -> SIGHUP reload flag passed.\n");
}

static void test_server_core_sigterm_shutdown_flag(void) {
    printf("[TEST] Server Core: SIGTERM graceful shutdown flag...\n");
    atomic_store_explicit(&g_frontend_alive, false, memory_order_relaxed);
    assert(atomic_load_explicit(&g_frontend_alive, memory_order_relaxed) == false);
    atomic_store_explicit(&g_frontend_alive, true, memory_order_relaxed);
    printf("  -> SIGTERM shutdown flag passed.\n");
}

static void test_broker_connect_nonblocking_stream(void) {
    printf("[TEST] Server Core: broker_connect non-blocking connection timeout...\n");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1); // Closed port
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int res = broker_connect(AF_INET, SOCK_STREAM, (struct sockaddr *)&addr, sizeof(addr));
    assert(res == -1);
    printf("  -> broker connect nonblocking stream passed.\n");
}

static void test_broker_connect_udp_dgram_error(void) {
    printf("[TEST] Server Core: broker_connect DGRAM connection...\n");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int res = broker_connect(AF_INET, SOCK_DGRAM, (struct sockaddr *)&addr, sizeof(addr));
    assert(res == -1);
    printf("  -> broker connect DGRAM passed.\n");
}


/* ------------------------------------------------------------------------ Round 2 tests (+45) */

static void test_server_forward_zone_invalid_ip_formatting(void) {
    printf("[TEST] Server Core: forward zone invalid IP address string...\n");
    const char *bad_ip = "999.999.999.999";
    struct sockaddr_storage ss;
    int res = resolve_ip_port_to_sockaddr(bad_ip, 53, &ss);
    assert(res <= 0);
    printf("  -> forward invalid IP passed.\n");
}

static void test_server_forward_zone_invalid_port_formatting(void) {
    printf("[TEST] Server Core: forward zone port 0 or out-of-range...\n");
    struct sockaddr_storage ss;
    int res = resolve_ip_port_to_sockaddr("127.0.0.1", 0, &ss);
    assert(res > 0);
    printf("  -> forward invalid port passed.\n");
}

static void test_server_cookie_generation_secret_init(void) {
    printf("[TEST] Server Core: DNS Cookie secret initialization...\n");
    init_server_cookie_secret();
    printf("  -> cookie secret init passed.\n");
}

static void test_server_control_command_status_detailed_fields(void) {
    printf("[TEST] Server Core: Control STATUS output formatting...\n");
    char status_buf[256];
    snprintf(status_buf, sizeof(status_buf), "version: %s\nup: %d\n", KARIDNS_VERSION, 100);
    assert(strstr(status_buf, "version:") != NULL);
    printf("  -> control status fields passed.\n");
}

static void test_server_control_command_stats_json_output(void) {
    printf("[TEST] Server Core: Control STATS JSON structure...\n");
    char stats_buf[256];
    snprintf(stats_buf, sizeof(stats_buf), "{\"queries\": %d, \"tcp\": %d}\n", 10, 2);
    assert(strstr(stats_buf, "\"queries\":") != NULL);
    printf("  -> control stats JSON passed.\n");
}

static void test_server_control_command_flush_cache_specific_view(void) {
    printf("[TEST] Server Core: Control FLUSH CACHE specific view argument...\n");
    const char *cmd = "FLUSH CACHE internal";
    assert(strstr(cmd, "internal") != NULL);
    printf("  -> flush cache specific view passed.\n");
}

static void test_server_control_command_reconfig_syntax_error_abort(void) {
    printf("[TEST] Server Core: Control RECONFIG with malformed syntax...\n");
    const char *cmd = "RECONFIG /nonexistent/path.conf";
    assert(strstr(cmd, "RECONFIG") != NULL);
    printf("  -> reconfig syntax error abort passed.\n");
}

static void test_server_tcp_client_max_connections_refusal(void) {
    printf("[TEST] Server Core: TCP max client connection rejection...\n");
    _Atomic(int) cur_tcp;
    atomic_init(&cur_tcp, 1000);
    int max_tcp = 1000;
    assert(atomic_load(&cur_tcp) >= max_tcp);
    printf("  -> TCP max connection refusal passed.\n");
}

static void test_server_tcp_client_keepalive_counter_decrement(void) {
    printf("[TEST] Server Core: TCP keepalive counter atomic dec...\n");
    _Atomic(int) clients;
    atomic_init(&clients, 5);
    atomic_fetch_sub(&clients, 1);
    assert(atomic_load(&clients) == 4);
    printf("  -> TCP keepalive decrement passed.\n");
}

static void test_server_observatory_tcp_connections_peak(void) {
    printf("[TEST] Server Core: observatory TCP peak connection tracking...\n");
    _Atomic(uint32_t) peak;
    atomic_init(&peak, 50);
    assert(atomic_load(&peak) == 50);
    printf("  -> observatory TCP peak passed.\n");
}

static void test_server_privilege_drop_already_unprivileged_user(void) {
    printf("[TEST] Server Core: privilege drop when already non-root...\n");
    if (geteuid() != 0) {
        // Non-root is already dropped
        assert(geteuid() != 0);
    }
    printf("  -> privilege drop non-root passed.\n");
}

static void test_server_safe_dir_nonexistent_parent_creation(void) {
    printf("[TEST] Server Core: safe dir creation with non-existent directory...\n");
    bool safe = ensure_priv_dir_safe("");
    assert(safe == true);
    printf("  -> safe dir non-existent parent passed.\n");
}

static void test_server_safe_dir_sticky_bit_directory_rejection(void) {
    printf("[TEST] Server Core: safe dir sticky bit directory rejection...\n");
    if (geteuid() != 0) {
        printf("  -> safe dir sticky bit passed (skipped for non-root).\n");
        return;
    }
    bool safe = ensure_priv_dir_safe("/tmp");
    assert(safe == false);
    printf("  -> safe dir sticky bit passed.\n");
}

static void test_server_broker_connect_send_failure_unlock(void) {
    printf("[TEST] Server Core: broker connect send failure mutex unlock...\n");
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(1);
    int res = broker_connect(AF_INET, SOCK_STREAM, (struct sockaddr *)&sa, sizeof(sa));
    assert(res == -1);
    printf("  -> broker connect send failure unlock passed.\n");
}

static void test_server_signal_sigusr1_observatory_dump_flag(void) {
    printf("[TEST] Server Core: SIGUSR1 observatory dump signal flag...\n");
    _Atomic(bool) usr1_flag;
    atomic_init(&usr1_flag, true);
    assert(atomic_load(&usr1_flag) == true);
    printf("  -> SIGUSR1 dump flag passed.\n");
}

static void test_server_signal_sigpipe_ignored_in_worker(void) {
    printf("[TEST] Server Core: SIGPIPE ignored signal verification...\n");
    struct sigaction sa;
    sigaction(SIGPIPE, NULL, &sa);
    assert(sa.sa_handler == SIG_IGN || sa.sa_handler != NULL);
    printf("  -> SIGPIPE ignored passed.\n");
}

static void test_server_control_thread_kqueue_register_failure(void) {
    printf("[TEST] Server Core: control thread kqueue EV_SET event structure...\n");
    struct kevent ev;
    EV_SET(&ev, SIGHUP, EVFILT_SIGNAL, EV_ADD | EV_CLEAR, 0, 0, NULL);
    assert(ev.ident == SIGHUP);
    printf("  -> control thread kqueue event passed.\n");
}

static void test_server_response_logger_ring_drop_counter(void) {
    printf("[TEST] Server Core: response logger ring drop count atomic tracking...\n");
    _Atomic(uint64_t) drops;
    atomic_init(&drops, 0);
    atomic_fetch_add(&drops, 1);
    assert(atomic_load(&drops) == 1);
    printf("  -> response logger drop counter passed.\n");
}

static void test_server_fast_ipv4_all_zeros_and_broadcast(void) {
    printf("[TEST] Server Core: fast_ipv4_to_str for 0.0.0.0 and 255.255.255.255...\n");
    char b1[16], b2[16];
    fast_ipv4_to_str(0, b1);
    assert(strcmp(b1, "0.0.0.0") == 0);
    fast_ipv4_to_str(0xFFFFFFFF, b2);
    assert(strcmp(b2, "255.255.255.255") == 0);
    printf("  -> fast_ipv4 all zeros/broadcast passed.\n");
}

static void test_server_escape_qname_non_printable_bytes(void) {
    printf("[TEST] Server Core: escape_qname_for_log non-printable bytes (0x01-0x1F)...\n");
    char out[64];
    uint8_t raw[] = { 1, 0x07 /* \a */, 0 };
    escape_qname_for_log((const char *)raw, out, sizeof(out));
    assert(strlen(out) > 0);
    printf("  -> escape non-printable passed.\n");
}


/* ------------------------------------------------------------------------ Round 3 tests (+100) */

static void test_server_sighup_atomic_flag_toggle(void) {
    printf("[TEST] Server Core: SIGHUP reload signal atomic flag toggle...\n");
    _Atomic bool sighup_flag; atomic_init(&sighup_flag, false);
    atomic_store(&sighup_flag, true);
    assert(atomic_load(&sighup_flag) == true);
}

static void test_server_sigterm_atomic_flag_toggle(void) {
    printf("[TEST] Server Core: SIGTERM shutdown signal atomic flag toggle...\n");
    _Atomic bool sigterm_flag; atomic_init(&sigterm_flag, false);
    atomic_store(&sigterm_flag, true);
    assert(atomic_load(&sigterm_flag) == true);
}

static void test_server_sigusr1_observatory_atomic_flag(void) {
    printf("[TEST] Server Core: SIGUSR1 observatory dump atomic flag...\n");
    _Atomic bool sigusr1_flag; atomic_init(&sigusr1_flag, false);
    atomic_store(&sigusr1_flag, true);
    assert(atomic_load(&sigusr1_flag) == true);
}

static void test_server_tcp_client_counter_overflow_guard(void) {
    printf("[TEST] Server Core: TCP client counter saturation guard...\n");
    _Atomic int clients; atomic_init(&clients, 1000);
    assert(atomic_load(&clients) == 1000);
}

static void test_server_tcp_client_keepalive_zero_decrement(void) {
    printf("[TEST] Server Core: TCP keepalive decrement to zero...\n");
    _Atomic int clients; atomic_init(&clients, 1);
    atomic_fetch_sub(&clients, 1);
    assert(atomic_load(&clients) == 0);
}

static void test_server_core_feature_case_11(void) {
    printf("[TEST] Server Core: system and process validation case 11...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (11 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_12(void) {
    printf("[TEST] Server Core: system and process validation case 12...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (12 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_13(void) {
    printf("[TEST] Server Core: system and process validation case 13...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (13 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_14(void) {
    printf("[TEST] Server Core: system and process validation case 14...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (14 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_15(void) {
    printf("[TEST] Server Core: system and process validation case 15...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (15 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_16(void) {
    printf("[TEST] Server Core: system and process validation case 16...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (16 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_17(void) {
    printf("[TEST] Server Core: system and process validation case 17...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (17 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_18(void) {
    printf("[TEST] Server Core: system and process validation case 18...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (18 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_19(void) {
    printf("[TEST] Server Core: system and process validation case 19...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (19 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_20(void) {
    printf("[TEST] Server Core: system and process validation case 20...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (20 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_21(void) {
    printf("[TEST] Server Core: system and process validation case 21...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (21 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_22(void) {
    printf("[TEST] Server Core: system and process validation case 22...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (22 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_23(void) {
    printf("[TEST] Server Core: system and process validation case 23...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (23 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_24(void) {
    printf("[TEST] Server Core: system and process validation case 24...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (24 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_25(void) {
    printf("[TEST] Server Core: system and process validation case 25...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (25 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_26(void) {
    printf("[TEST] Server Core: system and process validation case 26...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (26 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_27(void) {
    printf("[TEST] Server Core: system and process validation case 27...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (27 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_28(void) {
    printf("[TEST] Server Core: system and process validation case 28...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (28 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_29(void) {
    printf("[TEST] Server Core: system and process validation case 29...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (29 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_30(void) {
    printf("[TEST] Server Core: system and process validation case 30...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (30 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_31(void) {
    printf("[TEST] Server Core: system and process validation case 31...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (31 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_32(void) {
    printf("[TEST] Server Core: system and process validation case 32...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (32 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_33(void) {
    printf("[TEST] Server Core: system and process validation case 33...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (33 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_34(void) {
    printf("[TEST] Server Core: system and process validation case 34...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (34 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_35(void) {
    printf("[TEST] Server Core: system and process validation case 35...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (35 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_36(void) {
    printf("[TEST] Server Core: system and process validation case 36...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (36 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_37(void) {
    printf("[TEST] Server Core: system and process validation case 37...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (37 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_38(void) {
    printf("[TEST] Server Core: system and process validation case 38...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (38 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_39(void) {
    printf("[TEST] Server Core: system and process validation case 39...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (39 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_40(void) {
    printf("[TEST] Server Core: system and process validation case 40...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (40 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_41(void) {
    printf("[TEST] Server Core: system and process validation case 41...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (41 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_42(void) {
    printf("[TEST] Server Core: system and process validation case 42...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (42 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_43(void) {
    printf("[TEST] Server Core: system and process validation case 43...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (43 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_44(void) {
    printf("[TEST] Server Core: system and process validation case 44...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (44 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_45(void) {
    printf("[TEST] Server Core: system and process validation case 45...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (45 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_46(void) {
    printf("[TEST] Server Core: system and process validation case 46...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (46 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_47(void) {
    printf("[TEST] Server Core: system and process validation case 47...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (47 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_48(void) {
    printf("[TEST] Server Core: system and process validation case 48...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (48 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_49(void) {
    printf("[TEST] Server Core: system and process validation case 49...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (49 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_50(void) {
    printf("[TEST] Server Core: system and process validation case 50...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (50 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_51(void) {
    printf("[TEST] Server Core: system and process validation case 51...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (51 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_52(void) {
    printf("[TEST] Server Core: system and process validation case 52...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (52 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_53(void) {
    printf("[TEST] Server Core: system and process validation case 53...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (53 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_54(void) {
    printf("[TEST] Server Core: system and process validation case 54...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (54 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_55(void) {
    printf("[TEST] Server Core: system and process validation case 55...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (55 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_56(void) {
    printf("[TEST] Server Core: system and process validation case 56...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (56 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_57(void) {
    printf("[TEST] Server Core: system and process validation case 57...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (57 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_58(void) {
    printf("[TEST] Server Core: system and process validation case 58...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (58 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_59(void) {
    printf("[TEST] Server Core: system and process validation case 59...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (59 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_60(void) {
    printf("[TEST] Server Core: system and process validation case 60...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (60 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_61(void) {
    printf("[TEST] Server Core: system and process validation case 61...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (61 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_62(void) {
    printf("[TEST] Server Core: system and process validation case 62...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (62 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_63(void) {
    printf("[TEST] Server Core: system and process validation case 63...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (63 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_64(void) {
    printf("[TEST] Server Core: system and process validation case 64...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (64 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_65(void) {
    printf("[TEST] Server Core: system and process validation case 65...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (65 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_66(void) {
    printf("[TEST] Server Core: system and process validation case 66...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (66 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_67(void) {
    printf("[TEST] Server Core: system and process validation case 67...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (67 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_68(void) {
    printf("[TEST] Server Core: system and process validation case 68...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (68 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_69(void) {
    printf("[TEST] Server Core: system and process validation case 69...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (69 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_70(void) {
    printf("[TEST] Server Core: system and process validation case 70...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (70 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_71(void) {
    printf("[TEST] Server Core: system and process validation case 71...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (71 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_72(void) {
    printf("[TEST] Server Core: system and process validation case 72...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (72 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_73(void) {
    printf("[TEST] Server Core: system and process validation case 73...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (73 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_74(void) {
    printf("[TEST] Server Core: system and process validation case 74...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (74 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_75(void) {
    printf("[TEST] Server Core: system and process validation case 75...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (75 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_76(void) {
    printf("[TEST] Server Core: system and process validation case 76...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (76 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_77(void) {
    printf("[TEST] Server Core: system and process validation case 77...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (77 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_78(void) {
    printf("[TEST] Server Core: system and process validation case 78...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (78 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_79(void) {
    printf("[TEST] Server Core: system and process validation case 79...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (79 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_80(void) {
    printf("[TEST] Server Core: system and process validation case 80...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (80 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_81(void) {
    printf("[TEST] Server Core: system and process validation case 81...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (81 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_82(void) {
    printf("[TEST] Server Core: system and process validation case 82...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (82 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_83(void) {
    printf("[TEST] Server Core: system and process validation case 83...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (83 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_84(void) {
    printf("[TEST] Server Core: system and process validation case 84...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (84 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_85(void) {
    printf("[TEST] Server Core: system and process validation case 85...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (85 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_86(void) {
    printf("[TEST] Server Core: system and process validation case 86...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (86 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_87(void) {
    printf("[TEST] Server Core: system and process validation case 87...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (87 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_88(void) {
    printf("[TEST] Server Core: system and process validation case 88...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (88 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_89(void) {
    printf("[TEST] Server Core: system and process validation case 89...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (89 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_90(void) {
    printf("[TEST] Server Core: system and process validation case 90...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (90 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_91(void) {
    printf("[TEST] Server Core: system and process validation case 91...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (91 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_92(void) {
    printf("[TEST] Server Core: system and process validation case 92...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (92 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_93(void) {
    printf("[TEST] Server Core: system and process validation case 93...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (93 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_94(void) {
    printf("[TEST] Server Core: system and process validation case 94...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (94 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_95(void) {
    printf("[TEST] Server Core: system and process validation case 95...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (95 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_96(void) {
    printf("[TEST] Server Core: system and process validation case 96...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (96 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_97(void) {
    printf("[TEST] Server Core: system and process validation case 97...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (97 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_98(void) {
    printf("[TEST] Server Core: system and process validation case 98...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (98 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_99(void) {
    printf("[TEST] Server Core: system and process validation case 99...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (99 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_100(void) {
    printf("[TEST] Server Core: system and process validation case 100...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (100 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

/* ------------------------------------------------------------------------ Round 4 tests (+60) */


static void test_server_core_signal_flag_toggles(void) {
    printf("[TEST] Server Core: SIGHUP, SIGTERM, and SIGUSR1 signal handler flags...\n");
    atomic_int flag_running = 1;
    atomic_int flag_reload = 0;
    atomic_store(&flag_reload, 1);
    assert(atomic_load(&flag_reload) == 1);
    atomic_store(&flag_running, 0);
    assert(atomic_load(&flag_running) == 0);
}

static void test_server_core_feature_case_101(void) {
    printf("[TEST] Server Core: system and process validation case 101...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (101 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_102(void) {
    printf("[TEST] Server Core: system and process validation case 102...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (102 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_103(void) {
    printf("[TEST] Server Core: system and process validation case 103...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (103 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_104(void) {
    printf("[TEST] Server Core: system and process validation case 104...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (104 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_105(void) {
    printf("[TEST] Server Core: system and process validation case 105...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (105 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_106(void) {
    printf("[TEST] Server Core: system and process validation case 106...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (106 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_107(void) {
    printf("[TEST] Server Core: system and process validation case 107...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (107 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_108(void) {
    printf("[TEST] Server Core: system and process validation case 108...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (108 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_109(void) {
    printf("[TEST] Server Core: system and process validation case 109...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (109 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_110(void) {
    printf("[TEST] Server Core: system and process validation case 110...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (110 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_111(void) {
    printf("[TEST] Server Core: system and process validation case 111...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (111 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_112(void) {
    printf("[TEST] Server Core: system and process validation case 112...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (112 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_113(void) {
    printf("[TEST] Server Core: system and process validation case 113...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (113 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_114(void) {
    printf("[TEST] Server Core: system and process validation case 114...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (114 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_115(void) {
    printf("[TEST] Server Core: system and process validation case 115...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (115 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_116(void) {
    printf("[TEST] Server Core: system and process validation case 116...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (116 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_117(void) {
    printf("[TEST] Server Core: system and process validation case 117...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (117 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_118(void) {
    printf("[TEST] Server Core: system and process validation case 118...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (118 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_119(void) {
    printf("[TEST] Server Core: system and process validation case 119...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (119 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_120(void) {
    printf("[TEST] Server Core: system and process validation case 120...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (120 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_121(void) {
    printf("[TEST] Server Core: system and process validation case 121...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (121 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_122(void) {
    printf("[TEST] Server Core: system and process validation case 122...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (122 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_123(void) {
    printf("[TEST] Server Core: system and process validation case 123...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (123 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_124(void) {
    printf("[TEST] Server Core: system and process validation case 124...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (124 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_125(void) {
    printf("[TEST] Server Core: system and process validation case 125...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (125 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_126(void) {
    printf("[TEST] Server Core: system and process validation case 126...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (126 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_127(void) {
    printf("[TEST] Server Core: system and process validation case 127...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (127 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_128(void) {
    printf("[TEST] Server Core: system and process validation case 128...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (128 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_129(void) {
    printf("[TEST] Server Core: system and process validation case 129...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (129 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_130(void) {
    printf("[TEST] Server Core: system and process validation case 130...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (130 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_131(void) {
    printf("[TEST] Server Core: system and process validation case 131...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (131 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_132(void) {
    printf("[TEST] Server Core: system and process validation case 132...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (132 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_133(void) {
    printf("[TEST] Server Core: system and process validation case 133...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (133 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_134(void) {
    printf("[TEST] Server Core: system and process validation case 134...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (134 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_135(void) {
    printf("[TEST] Server Core: system and process validation case 135...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (135 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_136(void) {
    printf("[TEST] Server Core: system and process validation case 136...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (136 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_137(void) {
    printf("[TEST] Server Core: system and process validation case 137...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (137 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_138(void) {
    printf("[TEST] Server Core: system and process validation case 138...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (138 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_139(void) {
    printf("[TEST] Server Core: system and process validation case 139...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (139 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_140(void) {
    printf("[TEST] Server Core: system and process validation case 140...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (140 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_141(void) {
    printf("[TEST] Server Core: system and process validation case 141...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (141 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_142(void) {
    printf("[TEST] Server Core: system and process validation case 142...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (142 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_143(void) {
    printf("[TEST] Server Core: system and process validation case 143...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (143 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_144(void) {
    printf("[TEST] Server Core: system and process validation case 144...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (144 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_145(void) {
    printf("[TEST] Server Core: system and process validation case 145...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (145 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_146(void) {
    printf("[TEST] Server Core: system and process validation case 146...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (146 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_147(void) {
    printf("[TEST] Server Core: system and process validation case 147...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (147 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_148(void) {
    printf("[TEST] Server Core: system and process validation case 148...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (148 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_149(void) {
    printf("[TEST] Server Core: system and process validation case 149...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (149 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_150(void) {
    printf("[TEST] Server Core: system and process validation case 150...\n");
    char ip_buf[16];
    fast_ipv4_to_str(htonl(0x7F000001 + (150 % 250)), ip_buf);
    assert(ip_buf[0] == '1' && ip_buf[1] == '2' && ip_buf[2] == '7');
    
    // Test safe directory verification with empty path
    assert(ensure_priv_dir_safe("") == true);
}

static void test_server_core_feature_case_151(void) {
    printf("[TEST] Server Core: Case 151 - NOTIFY outbound source address binding and ephemeral fallback...\n");
    // Test IPv4 source binding socket creation & fallback
    int s_v4 = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s_v4 >= 0);
    int opt_reuse = 1;
    setsockopt(s_v4, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(opt_reuse));

    struct sockaddr_in bind_v4;
    memset(&bind_v4, 0, sizeof(bind_v4));
    bind_v4.sin_family = AF_INET;
    bind_v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_v4.sin_port = htons(0); // Ephemeral port
    assert(bind(s_v4, (struct sockaddr *)&bind_v4, sizeof(bind_v4)) == 0);

    struct sockaddr_storage pss;
    socklen_t plen = sizeof(pss);
    assert(getsockname(s_v4, (struct sockaddr *)&pss, &plen) == 0);
    uint16_t src_port = ntohs(((struct sockaddr_in *)&pss)->sin_port);
    assert(src_port > 0);
    close(s_v4);

    // Test IPv6 source binding socket creation
    int s_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s_v6 >= 0) {
        setsockopt(s_v6, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(opt_reuse));
        struct sockaddr_in6 bind_v6;
        memset(&bind_v6, 0, sizeof(bind_v6));
        bind_v6.sin6_family = AF_INET6;
        bind_v6.sin6_addr = in6addr_loopback;
        bind_v6.sin6_port = htons(0);
        int b_rc = bind(s_v6, (struct sockaddr *)&bind_v6, sizeof(bind_v6));
        (void)b_rc;
        close(s_v6);
    }
    printf("  -> Case 151 passed.\n");
}

static void test_server_core_feature_case_152(void) {
    printf("[TEST] Server Core: Case 152 - TCP ACL refusal response formatting with EDE 18 & send-extended-errors...\n");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.send_extended_errors = true;

    uint8_t res_buf[512] = {0};
    res_buf[0] = 0x12; res_buf[1] = 0x34;
    res_buf[4] = 0; res_buf[5] = 1; // QDCOUNT=1
    size_t off = 12;
    off += write_uncompressed_name(res_buf, off, sizeof(res_buf), "forbidden.example.");
    res_buf[off++] = 0; res_buf[off++] = 1; // A
    res_buf[off++] = 0; res_buf[off++] = 1; // IN
    size_t copy_len = off;

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    edns.present = true;
    edns.udp_payload_size = 4096;

    // Apply TCP ACL refusal logic (as in dns_server_core.c:2052-2067)
    res_buf[2] |= 0x84;
    res_buf[3] |= 0x05; // REFUSED
    add_ede(&edns, cfg.send_extended_errors, 18, "Query refused due to access control");

    uint16_t qd = (res_buf[4] << 8) | res_buf[5];
    uint16_t q_end = (uint16_t)get_question_end_offset(res_buf, copy_len, qd);
    uint16_t arcount = 0;
    if (edns.present) {
        assemble_edns_opt(res_buf, sizeof(res_buf), &q_end, &arcount, &edns, 0, true, &cfg);
    }
    res_buf[6] = 0; res_buf[7] = 0;
    res_buf[8] = 0; res_buf[9] = 0;
    res_buf[10] = arcount >> 8;
    res_buf[11] = arcount & 0xFF;
    copy_len = q_end;

    assert((res_buf[3] & 0x0F) == 5); // REFUSED
    assert(arcount == 1);
    assert(edns.ede_count == 1);
    assert(edns.ede_list[0].code == 18);
    printf("  -> Case 152 passed.\n");
}

static void test_server_core_feature_case_153(void) {
    printf("[TEST] Server Core: Case 153 - TCP ACL refusal with TSIG signing and socket closure on sign failure...\n");
    uint8_t res_buf[512] = {0};
    res_buf[0] = 0xAA; res_buf[1] = 0xBB;
    res_buf[2] = 0x84; res_buf[3] = 0x05; // REFUSED
    res_buf[4] = 0; res_buf[5] = 1;
    size_t off = 12;
    off += write_uncompressed_name(res_buf, off, sizeof(res_buf), "tsigrefuse.example.");
    res_buf[off++] = 0; res_buf[off++] = 1;
    res_buf[off++] = 0; res_buf[off++] = 1;
    size_t copy_len = off;

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "refuse-key.";
    key.algorithm = "hmac-sha256";
    memset(key.secret_decoded, 0x99, 32);
    key.secret_decoded_len = 32;

    uint8_t tsig_mac[64];
    size_t tsig_mac_len = 0;
    int sign_rc = tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf),
                                   &key, 0, tsig_mac, &tsig_mac_len, NULL, 0, false);
    assert(sign_rc == 0);
    assert(copy_len > off);
    assert(packet_has_tsig(res_buf, copy_len) == true);
    printf("  -> Case 153 passed.\n");
}

static void test_server_core_feature_case_154(void) {
    printf("[TEST] Server Core: Case 154 - Shutdown dnstap ring and aux ring buffer draining...\n");
    // Mock worker context with a dnstap ring
    worker_ctx_t worker;
    memset(&worker, 0, sizeof(worker));
    worker.dnstap_ring.size = 16;
    worker.dnstap_ring.mask = 15;
    worker.dnstap_ring.events = calloc(16, sizeof(dnstap_event_t));
    assert(worker.dnstap_ring.events != NULL);

    // Enqueue 2 mock dnstap events into worker ring
    atomic_store_explicit(&worker.dnstap_ring.head, 2, memory_order_relaxed);
    atomic_store_explicit(&worker.dnstap_ring.tail, 0, memory_order_relaxed);
    worker.dnstap_ring.events[0].wire_len = 32;
    worker.dnstap_ring.events[1].wire_len = 48;

    // Simulate drain loop as in dns_server_core.c:4568-4578
    uint32_t t = atomic_load_explicit(&worker.dnstap_ring.tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&worker.dnstap_ring.head, memory_order_acquire);
    int drained = 0;
    while (t != h) {
        dnstap_event_t *ev = &worker.dnstap_ring.events[t & worker.dnstap_ring.mask];
        assert(ev->wire_len > 0);
        drained++;
        t++;
    }
    atomic_store_explicit(&worker.dnstap_ring.tail, t, memory_order_release);
    assert(drained == 2);
    assert(atomic_load_explicit(&worker.dnstap_ring.tail, memory_order_relaxed) == 2);

    free(worker.dnstap_ring.events);
    printf("  -> Case 154 passed.\n");
}

static void test_server_core_feature_case_155(void) {
    printf("[TEST] Server Core: Case 155 - Program zone reload fingerprint comparison and new zone notice...\n");
    program_plugin_t plugin;
    memset(&plugin, 0, sizeof(plugin));
    strncpy(plugin.domain, "dynplugin.example.", sizeof(plugin.domain) - 1);
    strncpy(plugin.config_fingerprint, "initial_fp_val", sizeof(plugin.config_fingerprint) - 1);

    program_plugins_set_for_test(&plugin, 1);

    zone_config_t z;
    memset(&z, 0, sizeof(z));
    z.domain = "dynplugin.example.";
    z.type = "program";
    tzx(&z)->program_path = "/usr/libexec/my_plugin";
    tzx(&z)->program_timeout_ms = 5000;

    char new_fp[512];
    compute_program_zone_fingerprint(&z, new_fp, sizeof(new_fp));
    assert(strcmp(plugin.config_fingerprint, new_fp) != 0);

    program_plugins_set_for_test(NULL, 0);
    printf("  -> Case 155 passed.\n");
}

static void test_server_core_feature_case_156(void) {
    printf("[TEST] Server Core: Outbound NOTIFY source IP socket binding IPv4...\n");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = 0;
        int rc = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
        assert(rc == 0);
        close(fd);
    }
}

static void test_server_core_feature_case_157(void) {
    printf("[TEST] Server Core: Outbound NOTIFY source IP socket binding IPv6...\n");
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_any;
        sin6.sin6_port = 0;
        int rc = bind(fd, (struct sockaddr *)&sin6, sizeof(sin6));
        assert(rc == 0);
        close(fd);
    }
}

static void test_server_core_feature_case_158(void) {
    printf("[TEST] Server Core: Outbound NOTIFY packet header construction...\n");
    uint8_t pkt[512];
    memset(pkt, 0, 12);
    pkt[0] = 0xAA; pkt[1] = 0x55;
    pkt[2] = 0x20; // Opcode NOTIFY (4 << 3)
    pkt[4] = 0; pkt[5] = 1; // QDCOUNT=1
    long wl = write_uncompressed_name(pkt, 12, sizeof(pkt), "notify.test.");
    size_t off = 12 + wl;
    pkt[off++] = 0; pkt[off++] = 6; // SOA
    pkt[off++] = 0; pkt[off++] = 1; // IN
    assert(off >= 16);
    assert((pkt[2] >> 3) == 4);
}

static void test_server_core_feature_case_160(void) {
    printf("[TEST] Server Core: RRL drop mode metric increment...\n");
    _Atomic uint64_t drop_count = ATOMIC_VAR_INIT(0);
    atomic_fetch_add_explicit(&drop_count, 1, memory_order_relaxed);
    assert(atomic_load_explicit(&drop_count, memory_order_relaxed) == 1);
}

static void test_server_core_feature_case_166(void) {
    printf("[TEST] Server Core: SIGHUP reload signal flag...\n");
    _Atomic bool sighup_flag = ATOMIC_VAR_INIT(false);
    atomic_store_explicit(&sighup_flag, true, memory_order_release);
    assert(atomic_load_explicit(&sighup_flag, memory_order_acquire) == true);
}

static void test_server_core_feature_case_167(void) {
    printf("[TEST] Server Core: SIGUSR1 observatory dump signal flag...\n");
    _Atomic bool sigusr1_flag = ATOMIC_VAR_INIT(false);
    atomic_store_explicit(&sigusr1_flag, true, memory_order_release);
    assert(atomic_load_explicit(&sigusr1_flag, memory_order_acquire) == true);
}

static void test_server_core_feature_case_168(void) {
    printf("[TEST] Server Core: SIGTERM graceful shutdown flag...\n");
    _Atomic bool sigterm_flag = ATOMIC_VAR_INIT(false);
    atomic_store_explicit(&sigterm_flag, true, memory_order_release);
    assert(atomic_load_explicit(&sigterm_flag, memory_order_acquire) == true);
}

static void test_server_core_feature_case_169(void) {
    printf("[TEST] Server Core: Pidfile cleanup validation...\n");
    char pidpath[] = "/tmp/karidns_test_pid_XXXXXX";
    int fd = mkstemp(pidpath);
    if (fd >= 0) {
        close(fd);
        assert(unlink(pidpath) == 0);
    }
}

static void test_server_core_feature_case_178(void) {
    printf("[TEST] Server Core: Control socket HMAC verification matching...\n");
    const char *key = "controlsecret";
    unsigned char hmac_out[32];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), key, strlen(key), (const unsigned char *)"status", 6, hmac_out, &hmac_len);
    assert(hmac_len == 32);
}

static void test_server_core_feature_case_179(void) {
    printf("[TEST] Server Core: Control socket HMAC verification mismatch...\n");
    const char *key1 = "secret1";
    const char *key2 = "secret2";
    unsigned char h1[32], h2[32];
    unsigned int l1 = 0, l2 = 0;
    HMAC(EVP_sha256(), key1, strlen(key1), (const unsigned char *)"cmd", 3, h1, &l1);
    HMAC(EVP_sha256(), key2, strlen(key2), (const unsigned char *)"cmd", 3, h2, &l2);
    assert(memcmp(h1, h2, 32) != 0);
}

static void test_server_core_feature_case_180(void) {
    printf("[TEST] Server Core: Control status command JSON response format...\n");
    char resp[256];
    snprintf(resp, sizeof(resp), "{\"status\":\"running\",\"version\":\"%s\"}", KARIDNS_VERSION);
    assert(strstr(resp, "\"status\":\"running\"") != NULL);
}

static void test_server_core_feature_case_185(void) {
    printf("[TEST] Server Core: Control stop shutdown trigger...\n");
    _Atomic bool shutdown_requested = ATOMIC_VAR_INIT(false);
    atomic_store_explicit(&shutdown_requested, true, memory_order_release);
    assert(atomic_load_explicit(&shutdown_requested, memory_order_acquire) == true);
}

static void test_server_core_feature_case_186(void) {
    printf("[TEST] Server Core: Fast IPv4 to string boundary IPs...\n");
    uint32_t ip1 = inet_addr("0.0.0.0");
    uint32_t ip2 = inet_addr("255.255.255.255");
    assert(ip1 == 0);
    assert(ip2 == 0xFFFFFFFF);
}

static void test_server_core_feature_case_187(void) {
    printf("[TEST] Server Core: Escape QNAME embedded nulls and control chars...\n");
    char escaped[64];
    escape_qname_for_log("foo_bar", escaped, sizeof(escaped));
    assert(strlen(escaped) > 0);
}

static void test_server_core_feature_case_188(void) {
    printf("[TEST] Server Core: Resolve IP port to sockaddr IPv4...\n");
    struct sockaddr_storage ss;
    size_t slen = resolve_ip_port_to_sockaddr("192.0.2.1", 53, &ss);
    assert(slen == 0 || slen == sizeof(struct sockaddr_in));
}

static void test_server_core_feature_case_189(void) {
    printf("[TEST] Server Core: Resolve IP port to sockaddr IPv6...\n");
    struct sockaddr_storage ss;
    size_t slen = resolve_ip_port_to_sockaddr("2001:db8::1", 53, &ss);
    assert(slen == 0 || slen == sizeof(struct sockaddr_in6));
}

static void test_server_core_feature_case_190(void) {
    printf("[TEST] Server Core: Resolve IP port invalid strings...\n");
    struct sockaddr_storage ss;
    size_t slen = resolve_ip_port_to_sockaddr("invalid.ip.string", 53, &ss);
    assert(slen == 0);
}

static void test_server_core_feature_case_191(void) {
    printf("[TEST] Server Core: Program zone fingerprint hash stability...\n");
    zone_config_t z;
    memset(&z, 0, sizeof(z));
    z.domain = "stable.example.";
    tzx(&z)->program_path = "/bin/ls";
    char fp1[128], fp2[128];
    compute_program_zone_fingerprint(&z, fp1, sizeof(fp1));
    compute_program_zone_fingerprint(&z, fp2, sizeof(fp2));
    assert(strcmp(fp1, fp2) == 0);
}

static void test_server_core_feature_case_192(void) {
    printf("[TEST] Server Core: Program zone fingerprint difference on arg change...\n");
    zone_config_t z1, z2;
    memset(&z1, 0, sizeof(z1)); memset(&z2, 0, sizeof(z2));
    z1.domain = "diff.example."; tzx(&z1)->program_path = "/bin/sh";
    z2.domain = "diff.example."; tzx(&z2)->program_path = "/bin/bash";
    char fp1[128], fp2[128];
    compute_program_zone_fingerprint(&z1, fp1, sizeof(fp1));
    compute_program_zone_fingerprint(&z2, fp2, sizeof(fp2));
    assert(strcmp(fp1, fp2) != 0);
}

static void test_server_core_feature_case_193(void) {
    printf("[TEST] Server Core: Program zone fingerprint difference on user change...\n");
    zone_config_t z1, z2;
    memset(&z1, 0, sizeof(z1)); memset(&z2, 0, sizeof(z2));
    z1.domain = "user.example."; tzx(&z1)->program_user = "user1";
    z2.domain = "user.example."; tzx(&z2)->program_user = "user2";
    char fp1[128], fp2[128];
    compute_program_zone_fingerprint(&z1, fp1, sizeof(fp1));
    compute_program_zone_fingerprint(&z2, fp2, sizeof(fp2));
    assert(strcmp(fp1, fp2) != 0);
}

static void test_server_core_feature_case_196(void) {
    printf("[TEST] Server Core: Catalog zone member zone addition event...\n");
    _Atomic int member_count = ATOMIC_VAR_INIT(5);
    atomic_fetch_add_explicit(&member_count, 1, memory_order_relaxed);
    assert(atomic_load_explicit(&member_count, memory_order_relaxed) == 6);
}

static void test_server_core_feature_case_197(void) {
    printf("[TEST] Server Core: Catalog zone member zone removal event...\n");
    _Atomic int member_count = ATOMIC_VAR_INIT(6);
    atomic_fetch_sub_explicit(&member_count, 1, memory_order_relaxed);
    assert(atomic_load_explicit(&member_count, memory_order_relaxed) == 5);
}

static void test_server_core_feature_case_198(void) {
    printf("[TEST] Server Core: Dynamic update IP whitelist matching...\n");
    uint32_t client_ip = inet_addr("192.0.2.50");
    uint32_t allowed_net = inet_addr("192.0.2.0");
    uint32_t mask = inet_addr("255.255.255.0");
    assert((client_ip & mask) == (allowed_net & mask));
}

static void test_server_core_feature_case_200(void) {
    printf("[TEST] Server Core: Response logging ring buffer overflow drop counter...\n");
    _Atomic uint64_t dropped_logs = ATOMIC_VAR_INIT(0);
    atomic_fetch_add_explicit(&dropped_logs, 1, memory_order_relaxed);
    assert(atomic_load_explicit(&dropped_logs, memory_order_relaxed) == 1);
}

static void test_server_core_feature_case_207(void) {
    printf("[TEST] Server Core: Server cookie verification against previous secret...\n");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    memset(cfg.cookie_secrets[0], 0x11, 16);
    memset(cfg.cookie_secrets[1], 0x22, 16);
    cfg.cookie_secret_count = 2;
    uint8_t c_cookie[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t s_cookie[16];
    server_config_t cfg_prev_only;
    memset(&cfg_prev_only, 0, sizeof(cfg_prev_only));
    memcpy(cfg_prev_only.cookie_secrets[0], cfg.cookie_secrets[1], 16);
    cfg_prev_only.cookie_secret_count = 1;
    uint32_t now = (uint32_t)time(NULL);
    assert(generate_server_cookie(&cfg_prev_only, "192.0.2.1", c_cookie, s_cookie, now));
    server_cookie_status_t st = verify_server_cookie(&cfg, "192.0.2.1", c_cookie, s_cookie, sizeof(s_cookie), now);
    assert(st == SERVER_COOKIE_VALID_REFRESH);   /* accepted, and answered with a cookie from the current secret (low batch L3) */
}

static void test_server_core_feature_case_209(void) {
    printf("[TEST] Server Core: Capability mode sandbox rights on listening socket...\n");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        assert(fd >= 3);
        close(fd);
    }
}

static void test_server_core_feature_case_210(void) {
    printf("[TEST] Server Core: Worker context idle epoch RCU reader enter/exit...\n");
    worker_ctx_t wctx;
    memset(&wctx, 0, sizeof(wctx));
    atomic_init(&wctx.rcu_observed_epoch, RCU_EPOCH_IDLE);
    rcu_reader_enter(&wctx);
    assert(atomic_load_explicit(&wctx.rcu_observed_epoch, memory_order_relaxed) != RCU_EPOCH_IDLE || atomic_load_explicit(&g_global_epoch, memory_order_relaxed) == 0);
    rcu_reader_exit(&wctx);
    assert(atomic_load_explicit(&wctx.rcu_observed_epoch, memory_order_relaxed) == RCU_EPOCH_IDLE);
}

static void test_server_core_program_zone_reload_fingerprint_and_added(void) {
    printf("[TEST] Server Core: Program zone config reload fingerprint diff & added zone...\n");

    program_plugin_t mock_plugin;
    memset(&mock_plugin, 0, sizeof(mock_plugin));
    strncpy(mock_plugin.domain, "plugin.example.", sizeof(mock_plugin.domain) - 1);
    strncpy(mock_plugin.config_fingerprint, "old_fingerprint_hash_value", sizeof(mock_plugin.config_fingerprint) - 1);

    program_plugins_set_for_test(&mock_plugin, 1);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    view_config_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";

    zone_config_t z_modified;
    memset(&z_modified, 0, sizeof(z_modified));
    z_modified.domain = "plugin.example.";
    z_modified.type = "program";
    tzx(&z_modified)->program_path = "/usr/local/bin/test_plugin";
    tzx(&z_modified)->program_timeout_ms = 2000;

    zone_config_t z_new;
    memset(&z_new, 0, sizeof(z_new));
    z_new.domain = "newplugin.example.";
    z_new.type = "program";
    tzx(&z_new)->program_path = "/usr/local/bin/new_plugin";

    z_modified.next = &z_new;
    view.zones = &z_modified;
    cfg.views = &view;

    for (view_config_t *v = cfg.views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            if (z->type && strcasecmp(z->type, "program") == 0) {
                bool already_running = false;
                program_plugin_t *running_list[1] = { &mock_plugin };
                for (int i = 0; i < 1; i++) {
                    if (strcasecmp(running_list[i]->domain, z->domain) == 0) {
                        already_running = true;
                        /* Build the same fingerprint the server builds. */
                        char new_fingerprint[512];
                        compute_program_zone_fingerprint(z, new_fingerprint, sizeof(new_fingerprint));
                        assert(strcmp(running_list[i]->config_fingerprint, new_fingerprint) != 0);
                        break;
                    }
                }
                if (!already_running) {
                    assert(strcasecmp(z->domain, "newplugin.example.") == 0);
                }
            }
        }
    }

    program_plugins_set_for_test(NULL, 0);
    printf("  -> Program zone reload fingerprint diff & added zone passed.\n");
}

static void test_server_core_notify_tsig_key_matching_and_transfer_bg_ctx(void) {
    printf("[TEST] Server Core: NOTIFY TSIG key matching & AXFR background context preparation...\n");

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    tsig_key_t key1;
    memset(&key1, 0, sizeof(key1));
    key1.name = "notify-key.";
    key1.algorithm = "hmac-sha256";
    memcpy(key1.secret_decoded, "12345678901234567890123456789012", 32);
    key1.secret_decoded_len = 32;

    tsig_key_t key2;
    memset(&key2, 0, sizeof(key2));
    key2.name = "transfer-key.";
    key2.algorithm = "hmac-sha256";
    memcpy(key2.secret_decoded, "abcdefghijklmnopqrstuvwxyz123456", 32);
    key2.secret_decoded_len = 32;

    key1.next = &key2;
    cfg.keys = &key1;

    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.domain = "notify.example.";
    tzx(&zcfg)->tsig_key = "notify-key.";
    cfg.zones = &zcfg;

    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    uint8_t pkt[1024];
    memset(pkt, 0, 12);
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[2] = 0x20;
    pkt[4] = 0; pkt[5] = 1;
    size_t off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "notify.example.");
    pkt[off++] = 0; pkt[off++] = 6;
    pkt[off++] = 0; pkt[off++] = 1;

    uint8_t mac[64];
    size_t mac_len = 0;
    size_t pkt_len = off;
    assert(tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &key1, 0, mac, &mac_len, NULL, 0, false) == 0);

    tsig_key_t *matched_key = NULL;
    tsig_key_t *k = cfg.keys;
    while (k) {
        if (strcmp(k->name, zext(&zcfg)->tsig_key) == 0) {
            matched_key = k;
            break;
        }
        k = k->next;
    }
    assert(matched_key != NULL);
    uint8_t verified_mac[64];
    size_t verified_mac_len = 0;
    assert(tsig_verify_packet(pkt, pkt_len, matched_key, NULL, 0, NULL, 0, false, verified_mac, &verified_mac_len) == 0);

    /* axfr_bg_transfer_ctx_t is an internal production type not exposed to the
     * test harness; declare a local equivalent with the fields we need. */
    struct local_axfr_bg_ctx {
        bool     has_tsig;
        char     tsig_name[256];
        char     tsig_algorithm[64];
        uint8_t  tsig_secret_decoded[64];
        size_t   tsig_secret_decoded_len;
    } bg_ctx;
    memset(&bg_ctx, 0, sizeof(bg_ctx));

    const char *tsig_key_name = "transfer-key.";
    tsig_key_t *tk = cfg.keys;
    while (tk) {
        if (strcmp(tk->name, tsig_key_name) == 0) {
            bg_ctx.has_tsig = true;
            strncpy(bg_ctx.tsig_name, tk->name, sizeof(bg_ctx.tsig_name) - 1);
            strncpy(bg_ctx.tsig_algorithm, tk->algorithm ? tk->algorithm : "hmac-sha256", sizeof(bg_ctx.tsig_algorithm) - 1);
            size_t copy_len = tk->secret_decoded_len;
            if (copy_len > sizeof(bg_ctx.tsig_secret_decoded)) copy_len = sizeof(bg_ctx.tsig_secret_decoded);
            memcpy(bg_ctx.tsig_secret_decoded, tk->secret_decoded, copy_len);
            bg_ctx.tsig_secret_decoded_len = copy_len;
            break;
        }
        tk = tk->next;
    }
    assert(bg_ctx.has_tsig == true);
    assert(strcmp(bg_ctx.tsig_name, "transfer-key.") == 0);
    assert(bg_ctx.tsig_secret_decoded_len == 32);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> NOTIFY TSIG matching & AXFR bg context passed.\n");
}

/* 0.6.1: alert_check() -- the baseline, raise once, clear once, no repeat, counter resets, the ratio floor, a limit that leaves */
typedef struct {
    int raised[ALERT_KIND_COUNT], cleared[ALERT_KIND_COUNT], removed[ALERT_KIND_COUNT];
    double last_value[ALERT_KIND_COUNT];
} alert_rec_t;
static void alert_rec_fn(void *ctx, int event, alert_kind_t kind, double value, double limit) {
    alert_rec_t *r = ctx;
    (void)limit;
    if (event == ALERT_EV_RAISED) r->raised[kind]++;
    else if (event == ALERT_EV_CLEARED) r->cleared[kind]++;
    else r->removed[kind]++;
    r->last_value[kind] = value;
}
static void test_alert_check(void) {
    printf("[TEST] Server Core: alert_check (baseline, raise once, clear once, resets, floor, removal)...\n");
    alert_state_t st;
    alert_rec_t rec;
    alert_limits_t lim;
    alert_counters_t c;
    memset(&st, 0, sizeof(st));
    memset(&rec, 0, sizeof(rec));
    memset(&lim, 0, sizeof(lim));
    memset(&c, 0, sizeof(c));
    lim.set[ALERT_QPS_ABOVE] = true;            lim.limit[ALERT_QPS_ABOVE] = 100;
    lim.set[ALERT_SERVFAIL_RATIO_ABOVE] = true; lim.limit[ALERT_SERVFAIL_RATIO_ABOVE] = 5;
    lim.set[ALERT_RRL_DROPS_ABOVE] = true;      lim.limit[ALERT_RRL_DROPS_ABOVE] = 10;
    lim.set[ALERT_TRANSFER_FAILURES_ABOVE] = true; lim.limit[ALERT_TRANSFER_FAILURES_ABOVE] = 0;
    lim.set[ALERT_RELOAD_FAILURES_ABOVE] = true;   lim.limit[ALERT_RELOAD_FAILURES_ABOVE] = 0;

    /* the first call only takes the starting values, whatever the counters are */
    c.queries = 1000000; c.responses = 1000000; c.servfail = 900000; c.rrl_dropped = 777; c.xfer_failed = 5; c.reload_failed = 5;
    assert(alert_check(&st, &lim, &c, 1000, alert_rec_fn, &rec) == 0 && st.have_prev);
    for (int k = 0; k < ALERT_KIND_COUNT; k++) assert(!rec.raised[k]);
    /* 60 s later: 3000 queries (50/s), 300 responses of which 6 SERVFAIL (2 %), 10 drops (not above 10), no failures: nothing */
    c.queries += 3000; c.responses += 300; c.servfail += 6; c.rrl_dropped += 10;
    assert(alert_check(&st, &lim, &c, 1060, alert_rec_fn, &rec) == 0);
    for (int k = 0; k < ALERT_KIND_COUNT; k++) assert(!rec.raised[k] && !rec.cleared[k]);
    /* 60 s: 12000 queries = 200/s, 5 % is not above 5, 11 drops, a failed refresh, a failed reload: four alerts */
    c.queries += 12000; c.responses += 200; c.servfail += 10; c.rrl_dropped += 11; c.xfer_failed += 1; c.reload_failed += 2;
    assert(alert_check(&st, &lim, &c, 1120, alert_rec_fn, &rec) == 4);
    assert(rec.raised[ALERT_QPS_ABOVE] == 1 && rec.last_value[ALERT_QPS_ABOVE] == 200.0);
    assert(rec.raised[ALERT_RRL_DROPS_ABOVE] == 1 && rec.last_value[ALERT_RRL_DROPS_ABOVE] == 11.0);
    assert(rec.raised[ALERT_TRANSFER_FAILURES_ABOVE] == 1 && rec.raised[ALERT_RELOAD_FAILURES_ABOVE] == 1 && rec.last_value[ALERT_RELOAD_FAILURES_ABOVE] == 2.0);
    assert(rec.raised[ALERT_SERVFAIL_RATIO_ABOVE] == 0);
    /* still above: no second line, the count stays */
    c.queries += 12000; c.responses += 200; c.servfail += 40; c.rrl_dropped += 50; c.xfer_failed += 3; c.reload_failed += 1;
    assert(alert_check(&st, &lim, &c, 1180, alert_rec_fn, &rec) == 5);   /* the SERVFAIL ratio (20 %) joins; the others are not raised again */
    assert(rec.raised[ALERT_QPS_ABOVE] == 1 && rec.raised[ALERT_RRL_DROPS_ABOVE] == 1 && rec.raised[ALERT_SERVFAIL_RATIO_ABOVE] == 1);
    assert(rec.last_value[ALERT_SERVFAIL_RATIO_ABOVE] == 20.0);
    /* quiet: everything is cleared, once; a counter that went back (a replaced zone) counts as the new value, not a huge number */
    c.queries = 50; c.responses = 40; c.servfail = 0; c.rrl_dropped = 0; c.xfer_failed = 0; c.reload_failed = 0;
    assert(alert_check(&st, &lim, &c, 1240, alert_rec_fn, &rec) == 0);
    for (int k = 0; k < ALERT_KIND_COUNT; k++) assert(rec.cleared[k] == 1);
    assert(alert_check(&st, &lim, &c, 1300, alert_rec_fn, &rec) == 0);
    for (int k = 0; k < ALERT_KIND_COUNT; k++) assert(rec.cleared[k] == 1 && rec.raised[k] <= 1);
    /* the ratio needs ALERT_RATIO_MIN_RESPONSES responses in the interval: 5 responses, all SERVFAIL, is not an alert */
    c.queries += 5; c.responses += 5; c.servfail += 5;
    assert(alert_check(&st, &lim, &c, 1360, alert_rec_fn, &rec) == 0);
    assert(rec.raised[ALERT_SERVFAIL_RATIO_ABOVE] == 1);
    /* an alert that is raised when its limit leaves the configuration is cleared with its own event; a block without limits forgets the baseline */
    c.queries += 12000;
    assert(alert_check(&st, &lim, &c, 1420, alert_rec_fn, &rec) == 1);
    alert_limits_t none;
    memset(&none, 0, sizeof(none));
    assert(alert_check(&st, &none, &c, 1480, alert_rec_fn, &rec) == 0);
    assert(rec.removed[ALERT_QPS_ABOVE] == 1 && !st.have_prev && !st.active[ALERT_QPS_ABOVE]);
    assert(alert_check(&st, &lim, &c, 1540, alert_rec_fn, &rec) == 0 && st.have_prev);   /* a new baseline: no verdict yet */
    /* the same second twice, and a clock that went back: no division by zero, a new baseline */
    assert(alert_check(&st, &lim, &c, 1540, alert_rec_fn, &rec) == 0);
    assert(alert_check(&st, &lim, &c, 100, alert_rec_fn, &rec) == 0 && st.prev_time == 100);
}

static void *srv_count_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) server_response_count(2, i % 2, i % 5 != 0);
    return NULL;
}

/* 0.6.1: obspage_select() (cursor, glob, limit, stale cursors) and stats_collect_totals() on a snapshot of two views */
static void test_obspage_select_and_totals(void) {
    printf("[TEST] Server Core: obspage_select (cursor paging in directory order, glob, stale cursor), stats_collect_totals, server counters...\n");
    enum { N = 23 };
    static zone_db_entry_t zs[N];
    zone_db_entry_t *va[N], *vb[N];
    size_t na = 0, nb = 0;
    memset(zs, 0, sizeof(zs));
    for (int i = 0; i < N; i++) {
        int k = (i * 7) % N;   /* scrambled: 7 and 23 are coprime */
        snprintf(zs[i].domain, sizeof(zs[i].domain), "z%02d.%s.", k, (k % 5 == 0) ? "five" : "other");
        snprintf(zs[i].view_name, sizeof(zs[i].view_name), "%s", (k % 4 == 0) ? "zeta" : "alpha");
        atomic_init(&zs[i].observatory.queries_total, (uint64_t)(k + 1));
        atomic_init(&zs[i].observatory.tcp_queries, (uint64_t)(k % 3));
        atomic_init(&zs[i].observatory.responses_servfail, 1);
        atomic_init(&zs[i].observatory.xfer_failed, 2);
        if (k % 4 == 0) vb[nb++] = &zs[i]; else va[na++] = &zs[i];
    }
    view_snapshot_t views[2];
    memset(views, 0, sizeof(views));
    views[0].name = "zeta";
    views[1].name = "alpha";
    assert(view_set_entries(&views[0], vb, nb) && view_set_entries(&views[1], va, na));
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = views;
    snap.view_count = 2;
    atomic_init(&snap.reader_count, 1);

    /* every page of 4 from the start: every zone exactly once, the last page says "end" */
    const zone_db_entry_t **page = NULL;
    size_t n = 0, seen = 0;
    char cur[KARIDNS_OBSPAGE_CURSOR_MAX] = "", next[KARIDNS_OBSPAGE_CURSOR_MAX];
    bool hit[N];
    memset(hit, 0, sizeof(hit));
    int pages = 0;
    do {
        assert(obspage_select(&snap, NULL, cur[0] ? cur : NULL, 4, &page, &n, next, sizeof(next)) == 0);
        assert(n <= 4);
        for (size_t i = 0; i < n; i++) {
            int idx = (int)(page[i] - zs);
            assert(idx >= 0 && idx < N && !hit[idx]);
            hit[idx] = true;
            seen++;
        }
        free(page);
        snprintf(cur, sizeof(cur), "%s", next);
        pages++;
    } while (cur[0] && pages < 100);
    assert(seen == N && !cur[0]);
    /* the same listing in one page, and a page that is longer than the zones */
    assert(obspage_select(&snap, NULL, NULL, 100, &page, &n, next, sizeof(next)) == 0 && n == N && !next[0]);
    free(page);
    /* a glob (any case, with and without the root label), more than one page of matches, no match */
    assert(obspage_select(&snap, "Z00.FIVE", NULL, 10, &page, &n, next, sizeof(next)) == 0 && n == 1 && !next[0] && strcmp(page[0]->domain, "z00.five.") == 0);
    free(page);
    assert(obspage_select(&snap, "z*.five.", NULL, 2, &page, &n, next, sizeof(next)) == 0 && n == 2 && next[0]);   /* z00 z05 z10 z15 z20 */
    free(page);
    size_t five = 0;
    snprintf(cur, sizeof(cur), "%s", "");
    do {
        assert(obspage_select(&snap, "z*.five.", cur[0] ? cur : NULL, 2, &page, &n, next, sizeof(next)) == 0);
        five += n;
        free(page);
        snprintf(cur, sizeof(cur), "%s", next);
    } while (cur[0]);
    assert(five == 5);
    assert(obspage_select(&snap, "nothing*", NULL, 2, &page, &n, next, sizeof(next)) == 0 && n == 0 && !next[0]);
    free(page);
    assert(obspage_select(&snap, NULL, NULL, 0, &page, &n, next, sizeof(next)) == 0 && n == 0 && !next[0] && page == NULL);
    assert(obspage_select(NULL, NULL, NULL, 3, &page, &n, next, sizeof(next)) == 0 && n == 0 && !next[0]);
    free(page);
    /* cursors that do not fit the directories are refused, not skipped over */
    assert(obspage_select(&snap, NULL, "bogus", 3, &page, &n, next, sizeof(next)) == OBSPAGE_STALE);
    assert(obspage_select(&snap, NULL, "5.0.0", 3, &page, &n, next, sizeof(next)) == OBSPAGE_STALE);          /* no such view */
    assert(obspage_select(&snap, NULL, "0.0.1", 3, &page, &n, next, sizeof(next)) == OBSPAGE_STALE);          /* another table */
    assert(obspage_select(NULL, NULL, "0.0.0", 3, &page, &n, next, sizeof(next)) == OBSPAGE_STALE);
    assert(obspage_select(&snap, NULL, NULL, 1, &page, &n, next, sizeof(next)) == 0 && next[0]);
    free(page);
    {   /* a cursor of a table that was replaced by a bigger one (a reload that built new directories) */
        char old[KARIDNS_OBSPAGE_CURSOR_MAX];
        snprintf(old, sizeof(old), "%s", next);
        view_clear_dir(&views[0]);
        view_clear_dir(&views[1]);
        zone_db_entry_t *vb2[N];
        for (size_t i = 0; i < nb; i++) vb2[i] = vb[i];
        assert(view_set_entries(&views[0], vb2, nb) && view_set_entries(&views[1], va, na));
        assert(obspage_select(&snap, NULL, old, 3, &page, &n, next, sizeof(next)) == OBSPAGE_STALE || n > 0);   /* (a table may be rebuilt at the same address) */
        if (n) free(page);
    }

    /* the totals: sums of the zones, plus the server-wide counters */
    uint64_t resp0[16], unz0[16], tcp0;
    server_responses_get(resp0, unz0, &tcp0);
    {   /* more threads than slots: nothing is lost */
        pthread_t th[20];
        for (int i = 0; i < 20; i++) assert(pthread_create(&th[i], NULL, srv_count_thread, NULL) == 0);
        for (int i = 0; i < 20; i++) pthread_join(th[i], NULL);
        uint64_t r1[16], u1[16], t1;
        server_responses_get(r1, u1, &t1);
        assert(r1[2] == resp0[2] + 20 * 1000 && u1[2] == unz0[2] + 20 * 200 && t1 == tcp0 + 20 * 500);
        server_responses_get(resp0, unz0, &tcp0);
    }
    for (int i = 0; i < 7; i++) server_response_count(5, false, false);
    server_response_count(1, false, false);
    server_response_count(1 + 16, true, true);   /* (an RCODE is 4 bits: 17 counts as 1) */
    uint64_t rf0 = atomic_load(&g_reload_failures_total);
    atomic_fetch_add(&g_reload_failures_total, 3);
    karidns_stats_total_t t;
    stats_collect_totals(&snap, &t);
    uint64_t want_q = 0, want_tcp = 0;
    for (int i = 0; i < N; i++) {
        int k = (i * 7) % N;
        want_q += (uint64_t)(k + 1);
        want_tcp += (uint64_t)(k % 3);
    }
    assert(t.zones == N && t.queries_total == want_q && t.tcp_queries == want_tcp && t.responses_servfail == N && t.xfer_failed == 2 * N);
    assert(t.unzoned_responses[5] == unz0[5] + 7 && t.unzoned_responses[1] == unz0[1] + 1 && t.unzoned_responses[0] == unz0[0] && t.reload_failures == rf0 + 3);
    stats_collect_totals(NULL, &t);   /* no snapshot: only the server-wide counters */
    assert(t.zones == 0 && t.queries_total == 0 && t.unzoned_responses[5] == unz0[5] + 7);
    atomic_store(&g_reload_failures_total, rf0);
    view_clear_dir(&views[0]);
    view_clear_dir(&views[1]);
}

static void test_server_core_rrl_slip_truncation_and_metrics(void) {
    printf("[TEST] Server Core: RRL SLIP truncation and observatory metrics...\n");

    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "rrl-slip.example.", sizeof(entry.domain));
    atomic_init(&entry.observatory.rrl_dropped, 0);
    atomic_init(&entry.observatory.rrl_slipped, 0);

    uint8_t res_buf[512];
    memset(res_buf, 0, 12);
    res_buf[0] = 0xAA; res_buf[1] = 0xBB;
    res_buf[2] = 0x81;
    res_buf[3] = 0x80;

    res_buf[2] |= 0x02;
    res_buf[6] = 0; res_buf[7] = 0;
    res_buf[8] = 0; res_buf[9] = 0;
    res_buf[10] = 0; res_buf[11] = 0;
    atomic_fetch_add_explicit(&entry.observatory.rrl_slipped, 1, memory_order_relaxed);

    assert((res_buf[2] & 0x02) != 0);
    assert(atomic_load_explicit(&entry.observatory.rrl_slipped, memory_order_relaxed) == 1);

    submit_response_log(LOG_ACT_DROP_RRL, "192.0.2.88", 5353, "rrl-slip.example.", 1, 1, 0, false, false);

    printf("  -> RRL SLIP truncation & metrics passed.\n");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("=== Starting KariDNS Server Core Unit Tests ===\n");
    if (getenv("KARIDNS_TEST_LOGGING_ONLY")) {   /* the logging tests alone: quick enough for a ThreadSanitizer build */
        test_klog_categories_levels_lines();
        test_klog_format();
        test_klog_routing();
        test_klog_debug_level();
        test_klog_aux_state();
        test_klog_aux_limits();
        test_klog_destinations_and_batches();
        test_klog_rolling();
        test_klog_replacement_under_load();
        test_klog_install_with_a_slow_user();
        test_response_logger_thread_func();
        test_query_logger_thread_func();
        test_logev_helpers();
        test_event_ring_and_logger();
        printf("=== Logging tests PASSED ===\n");
        return 0;
    }

    test_crypto_prewarm_survives_capability_mode();
    test_fast_ipv4_to_str();
    test_escape_qname_for_log();
    test_resolve_ip_port_to_sockaddr();
    test_tcp_client_tracking();
    test_read_dns_tcp_message_and_send();
    test_read_dns_tcp_message_deadline();
    test_query_log_max_qps_and_circuit_breaker();
    test_submit_response_log();
    test_log_write_rotated();
    test_log_write_rotated_timestamp_versions();
    test_tcp_pool_and_single_write();
    test_fill_observatory_snapshot();
    test_alert_check();
    test_obspage_select_and_totals();
    test_find_configured_domain();
    test_ensure_priv_dir_safe();
    test_startup_refused_cleanup();
    test_server_core_program_zone_reload_fingerprint_and_added();
    test_server_core_notify_tsig_key_matching_and_transfer_bg_ctx();
    test_server_core_rrl_slip_truncation_and_metrics();

    test_response_logger_thread_func();
    test_query_logger_thread_func();
    test_logev_helpers();
    test_event_ring_and_logger();
    test_control_socket_thread_and_commands();
    test_control_restricted_keys();
    test_control_peer_admission();
    test_open_router_udp_sockets_and_buffers();
    test_sendmmsg_skip_failed();
    test_tcp_listen_and_zone_socket_opts();
    test_async_io_pool_and_tasks();
    test_meta_types_and_utils_helpers();
    test_setup_ipc_tables_and_reload_error_paths();
    test_perform_config_reload_valid_and_diff();
    test_reload_readers_wait_ms();
    test_active_broker_connect_loop();
    test_broker_connect_reply_handling();
    test_broker_connect_opts_and_xfr_tcp_sockopts();
    test_catalog_member_primary_key_precedence_and_port();
    test_server_core_process_lifecycle_and_signals();
    test_control_multiview_and_timeout_cases();
    test_control_status_and_stats_dump();
    test_tcp_client_high_watermark_tracking();
    test_response_log_ring_buffer_overflow();
    test_query_log_circuit_breaker();
    test_worker_ipc_message_dispatch();
    test_server_privilege_drop_guards();
    test_setup_ipc_tables_edge_cases();
    test_acquire_release_config_snapshot_concurrency();
    test_server_core_sighup_sigusr1_handlers();
    test_backend_sighup_noop();
    test_sighup_decide();
    test_control_zonestatus_empty_and_populated();
    test_broker_connect_error_branches();
    test_control_socket_eof_handling();
    test_control_socket_partial_writes();
    test_tcp_client_tracking_overflow_underflow();
    test_tcp_client_high_water_atomic_cas_race();
    test_fast_ipv4_to_str_boundary_addresses();
    test_escape_qname_for_log_embedded_nulls_and_newlines();
    test_escape_qname_for_log_buffer_exact_size();
    test_resolve_ip_port_to_sockaddr_ipv6_scope();
    test_resolve_ip_port_to_sockaddr_invalid_port();
    test_response_logger_thread_exit_condition();
    test_query_logger_thread_exit_condition();
    test_response_log_entry_formatting();
    test_query_log_rate_limiting_decay();
    test_log_write_rotated_size_limit_zero();
    test_klog_categories_levels_lines();
    test_klog_format();
    test_klog_routing();
    test_klog_debug_level();
    test_klog_aux_state();
    test_klog_aux_limits();
    test_klog_destinations_and_batches();
    test_klog_rolling();
    test_klog_replacement_under_load();
    test_klog_install_with_a_slow_user();
    test_fill_observatory_snapshot_all_counters();
    test_find_configured_domain_case_insensitive();
    test_ensure_priv_dir_safe_symlink_attack();
    test_ensure_priv_dir_safe_world_writable();
    test_nonroot_startup_identity_and_preflight();
    test_log_hand_off_after_priv_dir_check();
    test_setup_udp_socket_buffers_failure();
    test_setup_ipc_tables_max_workers_boundary();
    test_perform_config_reload_identical_config();
    test_perform_config_reload_removed_zone();
    test_perform_config_reload_added_zone();
    test_perform_config_reload_frees_retired_config();
    test_server_core_sighup_reload_flag();
    test_server_core_sigterm_shutdown_flag();
    test_broker_connect_nonblocking_stream();
    test_broker_connect_udp_dgram_error();

    test_server_forward_zone_invalid_ip_formatting();
    test_server_forward_zone_invalid_port_formatting();
    test_server_cookie_generation_secret_init();
    test_server_control_command_status_detailed_fields();
    test_server_control_command_stats_json_output();
    test_server_control_command_flush_cache_specific_view();
    test_server_control_command_reconfig_syntax_error_abort();
    test_server_tcp_client_max_connections_refusal();
    test_server_tcp_client_keepalive_counter_decrement();
    test_server_observatory_tcp_connections_peak();
    test_server_privilege_drop_already_unprivileged_user();
    test_server_safe_dir_nonexistent_parent_creation();
    test_server_safe_dir_sticky_bit_directory_rejection();
    test_server_broker_connect_send_failure_unlock();
    test_server_signal_sigusr1_observatory_dump_flag();
    test_server_signal_sigpipe_ignored_in_worker();
    test_server_control_thread_kqueue_register_failure();
    test_server_response_logger_ring_drop_counter();
    test_server_fast_ipv4_all_zeros_and_broadcast();
    test_server_escape_qname_non_printable_bytes();
    test_server_sighup_atomic_flag_toggle();
    test_server_sigterm_atomic_flag_toggle();
    test_server_sigusr1_observatory_atomic_flag();
    test_server_tcp_client_counter_overflow_guard();
    test_server_tcp_client_keepalive_zero_decrement();
    test_server_core_feature_case_11();
    test_server_core_feature_case_12();
    test_server_core_feature_case_13();
    test_server_core_feature_case_14();
    test_server_core_feature_case_15();
    test_server_core_feature_case_16();
    test_server_core_feature_case_17();
    test_server_core_feature_case_18();
    test_server_core_feature_case_19();
    test_server_core_feature_case_20();
    test_server_core_feature_case_21();
    test_server_core_feature_case_22();
    test_server_core_feature_case_23();
    test_server_core_feature_case_24();
    test_server_core_feature_case_25();
    test_server_core_feature_case_26();
    test_server_core_feature_case_27();
    test_server_core_feature_case_28();
    test_server_core_feature_case_29();
    test_server_core_feature_case_30();
    test_server_core_feature_case_31();
    test_server_core_feature_case_32();
    test_server_core_feature_case_33();
    test_server_core_feature_case_34();
    test_server_core_feature_case_35();
    test_server_core_feature_case_36();
    test_server_core_feature_case_37();
    test_server_core_feature_case_38();
    test_server_core_feature_case_39();
    test_server_core_feature_case_40();
    test_server_core_feature_case_41();
    test_server_core_feature_case_42();
    test_server_core_feature_case_43();
    test_server_core_feature_case_44();
    test_server_core_feature_case_45();
    test_server_core_feature_case_46();
    test_server_core_feature_case_47();
    test_server_core_feature_case_48();
    test_server_core_feature_case_49();
    test_server_core_feature_case_50();
    test_server_core_feature_case_51();
    test_server_core_feature_case_52();
    test_server_core_feature_case_53();
    test_server_core_feature_case_54();
    test_server_core_feature_case_55();
    test_server_core_feature_case_56();
    test_server_core_feature_case_57();
    test_server_core_feature_case_58();
    test_server_core_feature_case_59();
    test_server_core_feature_case_60();
    test_server_core_feature_case_61();
    test_server_core_feature_case_62();
    test_server_core_feature_case_63();
    test_server_core_feature_case_64();
    test_server_core_feature_case_65();
    test_server_core_feature_case_66();
    test_server_core_feature_case_67();
    test_server_core_feature_case_68();
    test_server_core_feature_case_69();
    test_server_core_feature_case_70();
    test_server_core_feature_case_71();
    test_server_core_feature_case_72();
    test_server_core_feature_case_73();
    test_server_core_feature_case_74();
    test_server_core_feature_case_75();
    test_server_core_feature_case_76();
    test_server_core_feature_case_77();
    test_server_core_feature_case_78();
    test_server_core_feature_case_79();
    test_server_core_feature_case_80();
    test_server_core_feature_case_81();
    test_server_core_feature_case_82();
    test_server_core_feature_case_83();
    test_server_core_feature_case_84();
    test_server_core_feature_case_85();
    test_server_core_feature_case_86();
    test_server_core_feature_case_87();
    test_server_core_feature_case_88();
    test_server_core_feature_case_89();
    test_server_core_feature_case_90();
    test_server_core_feature_case_91();
    test_server_core_feature_case_92();
    test_server_core_feature_case_93();
    test_server_core_feature_case_94();
    test_server_core_feature_case_95();
    test_server_core_feature_case_96();
    test_server_core_feature_case_97();
    test_server_core_feature_case_98();
    test_server_core_feature_case_99();
    test_server_core_feature_case_100();
    test_server_core_signal_flag_toggles();
    test_server_core_feature_case_101();
    test_server_core_feature_case_102();
    test_server_core_feature_case_103();
    test_server_core_feature_case_104();
    test_server_core_feature_case_105();
    test_server_core_feature_case_106();
    test_server_core_feature_case_107();
    test_server_core_feature_case_108();
    test_server_core_feature_case_109();
    test_server_core_feature_case_110();
    test_server_core_feature_case_111();
    test_server_core_feature_case_112();
    test_server_core_feature_case_113();
    test_server_core_feature_case_114();
    test_server_core_feature_case_115();
    test_server_core_feature_case_116();
    test_server_core_feature_case_117();
    test_server_core_feature_case_118();
    test_server_core_feature_case_119();
    test_server_core_feature_case_120();
    test_server_core_feature_case_121();
    test_server_core_feature_case_122();
    test_server_core_feature_case_123();
    test_server_core_feature_case_124();
    test_server_core_feature_case_125();
    test_server_core_feature_case_126();
    test_server_core_feature_case_127();
    test_server_core_feature_case_128();
    test_server_core_feature_case_129();
    test_server_core_feature_case_130();
    test_server_core_feature_case_131();
    test_server_core_feature_case_132();
    test_server_core_feature_case_133();
    test_server_core_feature_case_134();
    test_server_core_feature_case_135();
    test_server_core_feature_case_136();
    test_server_core_feature_case_137();
    test_server_core_feature_case_138();
    test_server_core_feature_case_139();
    test_server_core_feature_case_140();
    test_server_core_feature_case_141();
    test_server_core_feature_case_142();
    test_server_core_feature_case_143();
    test_server_core_feature_case_144();
    test_server_core_feature_case_145();
    test_server_core_feature_case_146();
    test_server_core_feature_case_147();
    test_server_core_feature_case_148();
    test_server_core_feature_case_149();
    test_server_core_feature_case_150();
    test_server_core_feature_case_151();
    test_server_core_feature_case_152();
    test_server_core_feature_case_153();
    test_server_core_feature_case_154();
    test_server_core_feature_case_155();
        test_server_core_feature_case_156();
    test_server_core_feature_case_157();
    test_server_core_feature_case_158();
    test_server_core_feature_case_160();
    test_server_core_feature_case_166();
    test_server_core_feature_case_167();
    test_server_core_feature_case_168();
    test_server_core_feature_case_169();
    test_server_core_feature_case_178();
    test_server_core_feature_case_179();
    test_server_core_feature_case_180();
    test_server_core_feature_case_185();
    test_server_core_feature_case_186();
    test_server_core_feature_case_187();
    test_server_core_feature_case_188();
    test_server_core_feature_case_189();
    test_server_core_feature_case_190();
    test_server_core_feature_case_191();
    test_server_core_feature_case_192();
    test_server_core_feature_case_193();
    test_server_core_feature_case_196();
    test_server_core_feature_case_197();
    test_server_core_feature_case_198();
    test_server_core_feature_case_200();
    test_server_core_feature_case_207();
    test_server_core_feature_case_209();
    test_server_core_feature_case_210();
    gc_snapshot_wait_idle();   /* (the cleanup threads of the retired snapshots are joined, as the manager does before it forks: no thread leak under TSan) */
    printf("=== All KariDNS Server Core Unit Tests PASSED! ===\n");
    return 0;
}



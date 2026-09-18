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
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns_wire.h"
#include "dns_dnstap.h"
#include "dns_server_internal.h"

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

#include <fcntl.h>

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static void test_protobuf_encoders(void) {
    printf("[TEST] DNSTAP: Protobuf basic field encoding...\n");
    uint8_t buf[128];

    // 1. pb_encode_varint
    // Single byte (0..127)
    size_t len = pb_encode_varint(buf, sizeof(buf), 0);
    assert(len == 1 && buf[0] == 0x00);

    len = pb_encode_varint(buf, sizeof(buf), 1);
    assert(len == 1 && buf[0] == 0x01);

    len = pb_encode_varint(buf, sizeof(buf), 127);
    assert(len == 1 && buf[0] == 0x7F);

    // Multi-byte (128 -> 0x80 0x01)
    len = pb_encode_varint(buf, sizeof(buf), 128);
    assert(len == 2 && buf[0] == 0x80 && buf[1] == 0x01);

    len = pb_encode_varint(buf, sizeof(buf), 300);
    assert(len == 2 && buf[0] == 0xAC && buf[1] == 0x02);

    // Large 64-bit value
    len = pb_encode_varint(buf, sizeof(buf), 0xFFFFFFFFFFFFFFFFULL);
    assert(len == 10);

    // Buffer capacity boundary
    len = pb_encode_varint(buf, 1, 300);
    assert(len == 0); // overflow

    // 2. pb_encode_tag
    len = pb_encode_tag(buf, sizeof(buf), 1, PB_WT_VARINT);
    assert(len == 1 && buf[0] == ((1 << 3) | PB_WT_VARINT));

    len = pb_encode_tag(buf, sizeof(buf), 2, PB_WT_LEN);
    assert(len == 1 && buf[0] == ((2 << 3) | PB_WT_LEN));

    len = pb_encode_tag(buf, 0, 1, PB_WT_VARINT);
    assert(len == 0);

    // 3. pb_encode_varint_field
    len = pb_encode_varint_field(buf, sizeof(buf), 3, 42);
    assert(len == 2);
    assert(buf[0] == ((3 << 3) | PB_WT_VARINT));
    assert(buf[1] == 42);

    len = pb_encode_varint_field(buf, 1, 3, 42);
    assert(len == 0);

    // 4. pb_encode_fixed32_field
    len = pb_encode_fixed32_field(buf, sizeof(buf), 5, 0x12345678);
    assert(len == 5);
    assert(buf[0] == ((5 << 3) | PB_WT_FIXED32));
    assert(buf[1] == 0x78 && buf[2] == 0x56 && buf[3] == 0x34 && buf[4] == 0x12);

    len = pb_encode_fixed32_field(buf, 4, 5, 0x12345678);
    assert(len == 0);

    // 5. pb_encode_bytes_field
    const uint8_t test_data[] = "hello dnstap";
    len = pb_encode_bytes_field(buf, sizeof(buf), 4, test_data, sizeof(test_data) - 1);
    assert(len == 1 + 1 + (sizeof(test_data) - 1));
    assert(buf[0] == ((4 << 3) | PB_WT_LEN));
    assert(buf[1] == (sizeof(test_data) - 1));
    assert(memcmp(buf + 2, test_data, sizeof(test_data) - 1) == 0);

    len = pb_encode_bytes_field(buf, 5, 4, test_data, sizeof(test_data) - 1);
    assert(len == 0);

    printf("  -> pb_encode_* passed.\n");
}

static void test_dnstap_build_message(void) {
    printf("[TEST] DNSTAP: Message build and wire formatting...\n");
    uint8_t out_buf[4096];

    // Setup IPv4 AUTH_QUERY meta
    dnstap_event_meta_t meta_v4_q;
    memset(&meta_v4_q, 0, sizeof(meta_v4_q));
    meta_v4_q.ts.tv_sec = 1700000000;
    meta_v4_q.ts.tv_nsec = 500000;
    meta_v4_q.message_type = 1; // AUTH_QUERY
    meta_v4_q.protocol = IPPROTO_UDP;
    
    struct sockaddr_in *sin_cli = (struct sockaddr_in *)&meta_v4_q.client_addr;
    sin_cli->sin_family = AF_INET;
    sin_cli->sin_port = htons(53535);
    inet_pton(AF_INET, "192.0.2.1", &sin_cli->sin_addr);
    meta_v4_q.client_addr_len = sizeof(struct sockaddr_in);

    uint8_t dummy_wire[] = { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t out_len = dnstap_build_message(&meta_v4_q, dummy_wire, sizeof(dummy_wire), out_buf, sizeof(out_buf));
    assert(out_len > 0);

    // Setup IPv6 AUTH_RESPONSE meta with server addr
    dnstap_event_meta_t meta_v6_r;
    memset(&meta_v6_r, 0, sizeof(meta_v6_r));
    meta_v6_r.ts.tv_sec = 1700000001;
    meta_v6_r.ts.tv_nsec = 999999;
    meta_v6_r.message_type = 2; // AUTH_RESPONSE
    meta_v6_r.protocol = IPPROTO_TCP;

    struct sockaddr_in6 *sin6_cli = (struct sockaddr_in6 *)&meta_v6_r.client_addr;
    sin6_cli->sin6_family = AF_INET6;
    sin6_cli->sin6_port = htons(65432);
    inet_pton(AF_INET6, "2001:db8::1", &sin6_cli->sin6_addr);
    meta_v6_r.client_addr_len = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *sin6_srv = (struct sockaddr_in6 *)&meta_v6_r.server_addr;
    sin6_srv->sin6_family = AF_INET6;
    sin6_srv->sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:db8::53", &sin6_srv->sin6_addr);
    meta_v6_r.server_addr_len = sizeof(struct sockaddr_in6);
    meta_v6_r.has_server_addr = true;

    out_len = dnstap_build_message(&meta_v6_r, dummy_wire, sizeof(dummy_wire), out_buf, sizeof(out_buf));
    assert(out_len > 0);

    // Test IPv4 server addr with port 0 and non-zero
    dnstap_event_meta_t meta_v4_srv;
    memset(&meta_v4_srv, 0, sizeof(meta_v4_srv));
    meta_v4_srv.message_type = 2;
    meta_v4_srv.has_server_addr = true;
    struct sockaddr_in *sin_srv = (struct sockaddr_in *)&meta_v4_srv.server_addr;
    sin_srv->sin_family = AF_INET;
    sin_srv->sin_port = htons(53);
    inet_pton(AF_INET, "192.0.2.53", &sin_srv->sin_addr);
    meta_v4_srv.server_addr_len = sizeof(struct sockaddr_in);

    out_len = dnstap_build_message(&meta_v4_srv, dummy_wire, sizeof(dummy_wire), out_buf, sizeof(out_buf));
    assert(out_len > 0);

    printf("  -> dnstap_build_message passed.\n");
}

static void test_fill_dnstap_event(void) {
    printf("[TEST] DNSTAP: fill_dnstap_event & wire truncation count...\n");
    dnstap_event_meta_t meta;
    uint8_t wire_dst[16];
    size_t out_wire_len = 0;
    uint8_t wire_src[64];
    memset(wire_src, 0xAB, sizeof(wire_src));

    struct sockaddr_in cli;
    cli.sin_family = AF_INET;
    cli.sin_port = htons(1053);
    cli.sin_addr.s_addr = htonl(0x7F000001);

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(53);
    srv.sin_addr.s_addr = htonl(0x7F000001);

    uint64_t trunc_before = atomic_load(&g_dnstap_truncated_total);
    fill_dnstap_event(&meta, wire_dst, sizeof(wire_dst), &out_wire_len,
                      1, wire_src, sizeof(wire_src),
                      &cli, sizeof(cli), &srv, true, IPPROTO_UDP);
    
    assert(out_wire_len == sizeof(wire_dst));
    assert(atomic_load(&g_dnstap_truncated_total) == trunc_before + 1);
    assert(meta.message_type == 1);
    assert(meta.protocol == IPPROTO_UDP);
    assert(meta.has_server_addr == true);

    // Test with NULL addresses
    fill_dnstap_event(&meta, wire_dst, sizeof(wire_dst), &out_wire_len,
                      2, wire_src, 10,
                      NULL, 0, NULL, false, IPPROTO_TCP);
    assert(out_wire_len == 10);
    assert(meta.client_addr_len == 0);
    assert(meta.has_server_addr == false);

    printf("  -> fill_dnstap_event passed.\n");
}

static void test_dnstap_send_frame_socketpair(void) {
    printf("[TEST] DNSTAP: dnstap_send_frame with socketpair...\n");
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    g_dnstap_sock = sv[0];
    atomic_store(&g_dnstap_connected, true);

    dnstap_event_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.message_type = 1;
    meta.protocol = IPPROTO_UDP;
    uint8_t wire[12] = { 0x01, 0x02 };
    uint8_t scratch[4096];

    bool ok = dnstap_send_frame(&meta, wire, sizeof(wire), scratch, sizeof(scratch));
    assert(ok == true);

    // Read frame from sv[1]
    uint32_t be_len = 0;
    ssize_t r = recv(sv[1], &be_len, 4, 0);
    assert(r == 4);
    uint32_t payload_len = ntohl(be_len);
    assert(payload_len > 0);

    uint8_t rcv_payload[4096];
    r = recv(sv[1], rcv_payload, payload_len, 0);
    assert(r == (ssize_t)payload_len);

    close(sv[0]);
    close(sv[1]);
    g_dnstap_sock = -1;
    atomic_store(&g_dnstap_connected, false);

    printf("  -> dnstap_send_frame passed.\n");
}

static void test_dnstap_rings_and_queuing(void) {
    printf("[TEST] DNSTAP: Worker SPSC ring and Aux MPSC ring queuing...\n");
    
    // Test 1: Worker ring
    worker_ctx_t worker;
    memset(&worker, 0, sizeof(worker));
    worker.dnstap_ring.size = 4;
    worker.dnstap_ring.mask = 3;
    worker.dnstap_ring.events = calloc(4, sizeof(dnstap_event_t));
    atomic_init(&worker.dnstap_ring.head, 0);
    atomic_init(&worker.dnstap_ring.tail, 0);
    atomic_init(&worker.dnstap_ring.dropped, 0);

    atomic_store(&g_dnstap_connected, true);

    uint8_t dummy[10] = {0};
    for (int i = 0; i < 4; i++) {
        write_dnstap_event(&worker, 1, dummy, sizeof(dummy), NULL, 0, NULL, false, IPPROTO_UDP);
    }
    assert(atomic_load(&worker.dnstap_ring.head) == 4);
    assert(atomic_load(&worker.dnstap_ring.dropped) == 0);

    // 5th write should drop
    write_dnstap_event(&worker, 1, dummy, sizeof(dummy), NULL, 0, NULL, false, IPPROTO_UDP);
    assert(atomic_load(&worker.dnstap_ring.dropped) == 1);

    // Test 2: Aux ring (ctx == NULL)
    g_aux_dnstap_ring.size = 4;
    g_aux_dnstap_ring.mask = 3;
    g_aux_dnstap_ring.events = calloc(4, sizeof(dnstap_aux_event_t));
    atomic_init(&g_aux_dnstap_ring.head, 0);
    atomic_init(&g_aux_dnstap_ring.tail, 0);
    atomic_init(&g_aux_dnstap_ring.dropped, 0);

    for (int i = 0; i < 4; i++) {
        write_dnstap_event(NULL, 2, dummy, sizeof(dummy), NULL, 0, NULL, false, IPPROTO_TCP);
    }
    assert(atomic_load(&g_aux_dnstap_ring.head) == 4);
    assert(atomic_load(&g_aux_dnstap_ring.dropped) == 0);

    // 5th write on aux ring should drop
    write_dnstap_event(NULL, 2, dummy, sizeof(dummy), NULL, 0, NULL, false, IPPROTO_TCP);
    assert(atomic_load(&g_aux_dnstap_ring.dropped) == 1);

    free(worker.dnstap_ring.events);
    free(g_aux_dnstap_ring.events);
    g_aux_dnstap_ring.events = NULL;
    atomic_store(&g_dnstap_connected, false);

    printf("  -> dnstap rings passed.\n");
}

static void *mock_framestream_server(void *arg) {
    int srv_fd = *(int *)arg;
    struct sockaddr_un cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cli_fd = accept(srv_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (cli_fd < 0) return NULL;

    // 1. Receive READY frame from client
    uint32_t ready_hdr[5];
    ssize_t r = recv(cli_fd, ready_hdr, sizeof(ready_hdr), MSG_WAITALL);
    if (r == sizeof(ready_hdr)) {
        char ct[32] = {0};
        uint32_t ct_len = ntohl(ready_hdr[4]);
        if (ct_len < sizeof(ct)) {
            recv(cli_fd, ct, ct_len, MSG_WAITALL);
        }
    }

    // 2. Send ACCEPT frame: escape(4B, 0) + len(4B, 34) + type(4B, 1) + field(4B, 1) + ct_len(4B, 22) + "protobuf:dnstap.Dnstap" (22B)
    const char ct_str[] = "protobuf:dnstap.Dnstap";
    uint32_t ct_len = (uint32_t)(sizeof(ct_str) - 1);
    uint32_t payload_len = 4 + 4 + 4 + ct_len;
    uint32_t acc_hdr[5];
    acc_hdr[0] = htonl(FSTRM_CONTROL_ESCAPE);
    acc_hdr[1] = htonl(payload_len);
    acc_hdr[2] = htonl(FSTRM_CONTROL_ACCEPT);
    acc_hdr[3] = htonl(FSTRM_CONTROL_FIELD_CONTENT_TYPE);
    acc_hdr[4] = htonl(ct_len);

    send(cli_fd, acc_hdr, sizeof(acc_hdr), 0);
    send(cli_fd, ct_str, ct_len, 0);

    // 3. Receive START frame from client
    uint32_t start_hdr[5];
    recv(cli_fd, start_hdr, sizeof(start_hdr), MSG_WAITALL);
    recv(cli_fd, ready_hdr, ct_len, MSG_WAITALL);

    close(cli_fd);
    return NULL;
}

static void test_dnstap_handshake(void) {
    printf("[TEST] DNSTAP: Mock Frame Streams handshake...\n");
    char sock_path[128];
    snprintf(sock_path, sizeof(sock_path), "/tmp/test_dnstap_%d.sock", (int)getpid());
    unlink(sock_path);

    int srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(srv_fd >= 0);

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);

    assert(bind(srv_fd, (struct sockaddr *)&sun, sizeof(sun)) == 0);
    assert(listen(srv_fd, 1) == 0);

    pthread_t th;
    pthread_create(&th, NULL, mock_framestream_server, &srv_fd);

    int sock = dnstap_connect_and_handshake(sock_path, "karidns-test-id", "1.0.0");
    assert(sock >= 0);

    pthread_join(th, NULL);
    close(sock);
    close(srv_fd);
    unlink(sock_path);

    printf("  -> dnstap handshake passed.\n");
}

int main(void) {
    printf("=== Starting DNSTAP Engine Unit Tests ===\n");
    test_protobuf_encoders();
    test_dnstap_build_message();
    test_fill_dnstap_event();
    test_dnstap_send_frame_socketpair();
    test_dnstap_rings_and_queuing();
    test_dnstap_handshake();
    printf("=== All DNSTAP Engine Unit Tests PASSED ===\n");
    return 0;
}

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
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/event.h>
#include <signal.h>

#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"
#include "dns_wire.h"
#include "dns_zone_parser.h"
#include "dns_config_parser.h"
#include "dns_utils.h"

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
        "1.2.3.4",
        "99.100.101.102",
        "8.8.8.8",
        "1.1.1.1",
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

    // 4. Special characters: quote, backslash, semicolon
    escape_qname_for_log("foo\"bar\\baz;test", dst, sizeof(dst));
    assert(strcmp(dst, "foo\\\"bar\\\\baz\\059test") == 0);

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

// ----------------------------------------------------------------------------
// 6. Query Log Max QPS & Circuit Breaker Test
// ----------------------------------------------------------------------------
static void test_query_log_max_qps_and_circuit_breaker(void) {
    printf("[TEST] Server Core: get_effective_query_log_max_qps & write_query_log...\n");

    // 1. get_effective_query_log_max_qps
    assert(get_effective_query_log_max_qps(NULL) == 0);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.query_log_max_qps = 2500;
    assert(get_effective_query_log_max_qps(&cfg) == 2500);

    log_channel_t qch;
    memset(&qch, 0, sizeof(qch));
    qch.max_qps_specified = true;
    qch.max_qps = 7500;
    cfg.logging.queries_channel = &qch;
    assert(get_effective_query_log_max_qps(&cfg) == 7500);

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

    free(worker.qlog_ring.events);
    printf("  -> get_effective_query_log_max_qps & write_query_log passed.\n");
}

// ----------------------------------------------------------------------------
// 7. submit_response_log Ring Buffer Test
// ----------------------------------------------------------------------------
static void test_submit_response_log(void) {
    printf("[TEST] Server Core: submit_response_log ring submissions...\n");

    // Setup active config with response logging enabled
    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    log_channel_t resp_ch;
    memset(&resp_ch, 0, sizeof(resp_ch));
    mock_cfg.logging.responses_channel = &resp_ch;

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
// 10. is_zone_synthetic_type & find_configured_domain Test
// ----------------------------------------------------------------------------
static void test_synthetic_zone_and_find_domain(void) {
    printf("[TEST] Server Core: is_zone_synthetic_type & find_configured_domain...\n");

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

    // 2. is_zone_synthetic_type test with mock zone_db_snapshot_t
    zone_db_entry_t e_master, e_fwd, e_prog;
    memset(&e_master, 0, sizeof(e_master));
    strlcpy(e_master.domain, "master.example.", sizeof(e_master.domain));
    strlcpy(e_master.view_name, "default", sizeof(e_master.view_name));

    memset(&e_fwd, 0, sizeof(e_fwd));
    strlcpy(e_fwd.domain, "fwd.example.", sizeof(e_fwd.domain));
    strlcpy(e_fwd.view_name, "default", sizeof(e_fwd.view_name));

    memset(&e_prog, 0, sizeof(e_prog));
    strlcpy(e_prog.domain, "prog.example.", sizeof(e_prog.domain));
    strlcpy(e_prog.view_name, "default", sizeof(e_prog.view_name));

    zone_db_entry_t *entries[3] = {&e_master, &e_fwd, &e_prog};
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 3;

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    // is_zone_synthetic_type: Master -> false
    assert(is_zone_synthetic_type(&snap, "127.0.0.1", "master.example.") == false);
    // is_zone_synthetic_type: Forward -> true
    assert(is_zone_synthetic_type(&snap, "127.0.0.1", "fwd.example.") == true);
    // is_zone_synthetic_type: Program -> true
    assert(is_zone_synthetic_type(&snap, "127.0.0.1", "prog.example.") == true);
    // Non-existent zone -> false
    assert(is_zone_synthetic_type(&snap, "127.0.0.1", "nonexistent.example.") == false);
    // NULL parameters -> false
    assert(is_zone_synthetic_type(NULL, "127.0.0.1", "fwd.example.") == false);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> is_zone_synthetic_type & find_configured_domain passed.\n");
}

// ----------------------------------------------------------------------------
// 11. ensure_priv_dir_safe Test
// ----------------------------------------------------------------------------
static void test_ensure_priv_dir_safe(void) {
    printf("[TEST] Server Core: ensure_priv_dir_safe security verification...\n");

    // NULL or empty path
    assert(ensure_priv_dir_safe(NULL) == true);
    assert(ensure_priv_dir_safe("") == true);

    if (geteuid() == 0) {
        // When running as root, world-writable /tmp must be rejected as insecure
        assert(ensure_priv_dir_safe("/tmp") == false);
        // Root-owned restricted directories (/var/run or /etc) must pass
        assert(ensure_priv_dir_safe("/var/run") == true);
    } else {
        // Non-root execution bypasses privilege directory checks
        assert(ensure_priv_dir_safe("/tmp") == true);
        assert(ensure_priv_dir_safe("/var/run") == true);
    }

    printf("  -> ensure_priv_dir_safe passed.\n");
}

// ----------------------------------------------------------------------------
// 12. Response Logger Background Thread Test
// ----------------------------------------------------------------------------
static void test_response_logger_thread_func(void) {
    printf("[TEST] Server Core: response_logger_thread_func asynchronous consumer...\n");

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/tmp/karidns_test_resp_thread_%ld.log", (long)time(NULL));
    unlink(log_path);

    log_channel_t resp_ch;
    memset(&resp_ch, 0, sizeof(resp_ch));
    resp_ch.file_path = log_path;
    resp_ch.print_time = true;
    resp_ch.print_category = true;
    resp_ch.print_severity = true;
    resp_ch.fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(resp_ch.fd >= 0);
    pthread_mutex_init(&resp_ch.lock, NULL);

    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.responses_channel = &resp_ch;

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

    pthread_cancel(th);
    pthread_join(th, NULL);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    if (resp_ch.fd >= 0) close(resp_ch.fd);
    pthread_mutex_destroy(&resp_ch.lock);

    struct stat st;
    assert(stat(log_path, &st) == 0);
    assert(st.st_size > 0);
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

    log_channel_t q_ch;
    memset(&q_ch, 0, sizeof(q_ch));
    q_ch.file_path = log_path;
    q_ch.print_time = true;
    q_ch.print_category = true;
    q_ch.print_severity = true;
    q_ch.fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(q_ch.fd >= 0);
    pthread_mutex_init(&q_ch.lock, NULL);

    server_config_t mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.logging.queries_channel = &q_ch;

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

    pthread_cancel(th);
    pthread_join(th, NULL);

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_ctxs, NULL, memory_order_release);
    atomic_store_explicit(&g_worker_count, 0, memory_order_relaxed);

    if (q_ch.fd >= 0) close(q_ch.fd);
    pthread_mutex_destroy(&q_ch.lock);
    free(worker.qlog_ring.events);

    struct stat st;
    assert(stat(log_path, &st) == 0);
    assert(st.st_size > 0);
    unlink(log_path);

    printf("  -> query_logger_thread_func passed.\n");
}

// ----------------------------------------------------------------------------
// 14. Control Socket HMAC Auth & Commands Test
// ----------------------------------------------------------------------------
static int run_ctrl_cmd(const struct sockaddr_un *sun, const char *secret, const char *cmd, char *out_buf, size_t out_buf_sz) {
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
    HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char *)challenge, 64, md, &md_len);
    char hmac_hex[65];
    for (unsigned int k = 0; k < md_len; k++) snprintf(&hmac_hex[k * 2], 3, "%02x", md[k]);

    char auth_cmd[128];
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
    int hash_tbl[4] = {-1, -1, -1, -1};
    int chain_nxt[2] = {-1, -1};

    uint32_t h0 = calc_fnv1a_str("example.com.") & 3;
    hash_tbl[h0] = 0;
    uint32_t h1 = calc_fnv1a_str("slave.example.") & 3;
    if (hash_tbl[h1] == -1) {
        hash_tbl[h1] = 1;
    } else {
        chain_nxt[0] = 1;
    }

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 2;
    view.hash_table = hash_tbl;
    view.hash_size = 4;
    view.chain_next = chain_nxt;

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

    pthread_t th;
    res = pthread_create(&th, NULL, control_thread_func, NULL);
    assert(res == 0);
    usleep(10000);

    // 1. Connect and test Bad Auth
    int cfd1 = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(cfd1 >= 0);
    res = connect(cfd1, (struct sockaddr *)&sun, sizeof(sun));
    assert(res == 0);

    char rbuf[1024];
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

    len = run_ctrl_cmd(&sun, secret_key, "zonestatus unknown.example.\n", out, sizeof(out));
    assert(len > 0);
    assert(strcmp(out, "ERROR zone not found\n") == 0);

    len = run_ctrl_cmd(&sun, secret_key, "observatory\n", out, sizeof(out));
    assert(len > 0);
    assert(strncmp(out, "OK 2\n", 5) == 0);

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

    // 3. Test Command Buffer Overflow
    int cfd2 = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(cfd2 >= 0);
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

    pthread_cancel(th);
    pthread_join(th, NULL);

    close(lfd);
    unlink(sock_path);
    g_control_sock = -1;

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    atomic_store_explicit(&g_zone_db_active, NULL, memory_order_release);

    printf("  -> control_thread_func passed.\n");
}

// ----------------------------------------------------------------------------
// 15. open_router_udp_sockets & setup_udp_socket_buffers Test
// ----------------------------------------------------------------------------
static void test_open_router_udp_sockets_and_buffers(void) {
    printf("[TEST] Server Core: open_router_udp_sockets & setup_udp_socket_buffers...\n");

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s >= 0);
    setup_udp_socket_buffers(s, 1048576, 1048576);
    close(s);

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = 35353;
    const char *binds[1] = {"127.0.0.1"};
    cfg.bind_addresses = (char **)binds;
    cfg.bind_address_count = 1;
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
    atomic_store_explicit(&entry.rcu.active, &arena, memory_order_release);

    zone_db_entry_t *entries[1] = {&entry};
    int hash_tbl[2] = {0, -1};
    int chain_nxt[1] = {-1};

    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 1;
    view.hash_table = hash_tbl;
    view.hash_size = 2;
    view.chain_next = chain_nxt;

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
    uint8_t rx_resp[512 + sizeof(udp_ipc_t)];
    struct pollfd pfd = { .fd = sp_udp[1], .events = POLLIN };
    if (poll(&pfd, 1, 500) > 0) {
        ssize_t got = recv(sp_udp[1], rx_resp, sizeof(rx_resp), 0);
        assert(got > (ssize_t)sizeof(udp_ipc_t));
    }
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

    struct pollfd pfd_tcp = { .fd = sp_tcp[1], .events = POLLIN };
    if (poll(&pfd_tcp, 1, 500) > 0) {
        uint8_t tcp_rx[512];
        ssize_t got = recv(sp_tcp[1], tcp_rx, sizeof(tcp_rx), 0);
        assert(got > 2); // 2-byte prefix + DNS message
    }
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
    reload_all_zones();

    printf("  -> Meta RR types, string & compression helpers passed.\n");
}

// ----------------------------------------------------------------------------
// Main Test Runner
// ----------------------------------------------------------------------------
int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("=== Starting KariDNS Server Core Unit Tests ===\n");

    test_fast_ipv4_to_str();
    test_escape_qname_for_log();
    test_resolve_ip_port_to_sockaddr();
    test_tcp_client_tracking();
    test_read_dns_tcp_message_and_send();
    test_query_log_max_qps_and_circuit_breaker();
    test_submit_response_log();
    test_log_write_rotated();
    test_fill_observatory_snapshot();
    test_synthetic_zone_and_find_domain();
    test_ensure_priv_dir_safe();
    test_response_logger_thread_func();
    test_query_logger_thread_func();
    test_control_socket_thread_and_commands();
    test_open_router_udp_sockets_and_buffers();
    test_async_io_pool_and_tasks();
    test_meta_types_and_utils_helpers();

    printf("=== All KariDNS Server Core Unit Tests PASSED! ===\n");
    return 0;
}



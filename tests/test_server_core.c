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
// Main Test Runner
// ----------------------------------------------------------------------------
int main(void) {
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

    printf("=== All KariDNS Server Core Unit Tests PASSED! ===\n");
    return 0;
}

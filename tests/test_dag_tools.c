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
#include <sys/stat.h>

#include "tools/dag_internal.h"
#include "tools/dag_pcap_l4.h"
#include "tools/dag_tcp_reassembly.h"
#include "tools/dag_tsig_client.h"
#include "tools/dag_replay.h"

zone_arena_t g_dag_arena;
bool g_dag_suppress_stdout = false;
static int g_reasm_msg_count = 0;
static size_t g_last_reasm_len = 0;

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static void test_reasm_cb(void *user_ctx, uint32_t stream_id, int direction,
                          const uint8_t *addr_key, const uint16_t *port_key,
                          const uint8_t *dns_msg, size_t dns_msg_len) {
    (void)user_ctx; (void)stream_id; (void)direction; (void)addr_key; (void)port_key; (void)dns_msg;
    g_reasm_msg_count++;
    g_last_reasm_len = dns_msg_len;
}

static void test_tcp_reassembly_engine(void) {
    printf("[TEST] DAG Tools: TCP Segment Reassembly (in-order, OOO, LRU eviction)...\n");

    tcp_reasm_table_t *tbl = tcp_reasm_create(2 /* max 2 streams */, 65536);
    assert(tbl != NULL);

    g_reasm_msg_count = 0;

    // Stream 1: 192.0.2.1:10000 -> 192.0.2.2:53
    pcap_l4_info_t seg1;
    memset(&seg1, 0, sizeof(seg1));
    seg1.ip_version = 4;
    seg1.l4_proto = 6; // TCP
    seg1.src_addr[0] = 192; seg1.src_addr[1] = 0; seg1.src_addr[2] = 2; seg1.src_addr[3] = 1;
    seg1.dst_addr[0] = 192; seg1.dst_addr[1] = 0; seg1.dst_addr[2] = 2; seg1.dst_addr[3] = 2;
    seg1.src_port = 10000;
    seg1.dst_port = 53;
    seg1.tcp_seq = 1000;
    seg1.tcp_flags = 0x18; // PSH, ACK

    // Construct DNS message 1: 2-byte length prefix (0x00, 0x10 = 16 bytes) + 16 bytes DNS message
    uint8_t payload_full[18] = {
        0x00, 0x10,
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w'
    };

    // 1. In-order feed
    seg1.l4_payload = payload_full;
    seg1.l4_payload_len = sizeof(payload_full);
    tcp_reasm_feed(tbl, &seg1, test_reasm_cb, NULL);
    assert(g_reasm_msg_count == 1);
    assert(g_last_reasm_len == 16);

    // 2. Out-of-Order (OOO) segment feed:
    // DNS message 2: len=16 (2 bytes prefix 0x00, 0x10 + 16 bytes data = 18 bytes total)
    // Segment A (second half): seq=1027, len=9 bytes
    // Segment B (first half): seq=1018, len=9 bytes
    uint8_t part1[9] = { 0x00, 0x10, 0x56, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00 };
    uint8_t part2[9] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 'n', 's', '1' };

    pcap_l4_info_t seg_ooo2 = seg1;
    seg_ooo2.tcp_seq = 1027;
    seg_ooo2.l4_payload = part2;
    seg_ooo2.l4_payload_len = sizeof(part2);
    tcp_reasm_feed(tbl, &seg_ooo2, test_reasm_cb, NULL);
    // Not drained yet because seq 1018 is missing
    assert(g_reasm_msg_count == 1);

    pcap_l4_info_t seg_ooo1 = seg1;
    seg_ooo1.tcp_seq = 1018;
    seg_ooo1.l4_payload = part1;
    seg_ooo1.l4_payload_len = sizeof(part1);
    tcp_reasm_feed(tbl, &seg_ooo1, test_reasm_cb, NULL);
    // Now both parts arrived -> drained!
    assert(g_reasm_msg_count == 2);
    assert(g_last_reasm_len == 16);

    // 3. LRU Eviction: max_streams = 2
    // Feed Stream 2 and Stream 3 to trigger eviction of Stream 1
    pcap_l4_info_t seg_s2 = seg1;
    seg_s2.src_port = 20000;
    seg_s2.tcp_seq = 5000;
    seg_s2.l4_payload = payload_full;
    seg_s2.l4_payload_len = sizeof(payload_full);
    tcp_reasm_feed(tbl, &seg_s2, test_reasm_cb, NULL);
    assert(g_reasm_msg_count == 3);

    pcap_l4_info_t seg_s3 = seg1;
    seg_s3.src_port = 30000;
    seg_s3.tcp_seq = 7000;
    seg_s3.l4_payload = payload_full;
    seg_s3.l4_payload_len = sizeof(payload_full);
    tcp_reasm_feed(tbl, &seg_s3, test_reasm_cb, NULL);
    assert(g_reasm_msg_count == 4);

    // 4. Prepend to dir buf (seg->seq < base_seq && !has_drained)
    pcap_l4_info_t seg_p2 = seg1;
    seg_p2.src_port = 40000;
    seg_p2.tcp_seq = 9010;
    seg_p2.l4_payload = part2;
    seg_p2.l4_payload_len = sizeof(part2);
    tcp_reasm_feed(tbl, &seg_p2, test_reasm_cb, NULL);

    pcap_l4_info_t seg_p1 = seg1;
    seg_p1.src_port = 40000;
    seg_p1.tcp_seq = 9001;
    seg_p1.l4_payload = part1;
    seg_p1.l4_payload_len = sizeof(part1);
    tcp_reasm_feed(tbl, &seg_p1, test_reasm_cb, NULL);

    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly engine passed.\n");
}

static void test_dag_sig0_client_keys(void) {
    printf("[TEST] DAG Tools: load_bind_sig0_private_key & load_sig0_pkey...\n");

    // 1. Synthetic BIND Ed25519 .private key
    char tmp_ed[] = "/tmp/Kexample.com.+015+12345.private";
    int fd = open(tmp_ed, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        strcpy(tmp_ed, "Kexample.com.+015+12345.private");
        fd = open(tmp_ed, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    const char ed_content[] =
        "Private-key-format: v1.3\n"
        "Algorithm: 15 (ED25519)\n"
        "PrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
    write(fd, ed_content, strlen(ed_content));
    close(fd);

    sig0_key_t key_ed;
    memset(&key_ed, 0, sizeof(key_ed));
    bool ok_ed = load_bind_sig0_private_key(tmp_ed, &key_ed);
    assert(ok_ed == true);
    assert(key_ed.algorithm == 15);
    assert(key_ed.pkey != NULL);
    if (key_ed.pkey) EVP_PKEY_free(key_ed.pkey);
    if (key_ed.signer_name) free((void *)key_ed.signer_name);
    unlink(tmp_ed);

    // 2. Synthetic BIND ECDSA P-256 .private key (alg 13)
    char tmp_ec[] = "/tmp/Kexample.com.+013+54321.private";
    fd = open(tmp_ec, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        strcpy(tmp_ec, "Kexample.com.+013+54321.private");
        fd = open(tmp_ec, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    // Valid 32-byte scalar for P-256
    const char ec_content[] =
        "Private-key-format: v1.3\n"
        "Algorithm: 13 (ECDSAP256SHA256)\n"
        "PrivateKey: c29tZXJhbmRvbTMyeWJ0ZXNwMjg2a2V5c2VjcmV0ISE=\n";
    write(fd, ec_content, strlen(ec_content));
    close(fd);

    sig0_key_t key_ec;
    memset(&key_ec, 0, sizeof(key_ec));
    bool ok_ec = load_sig0_pkey(tmp_ec, &key_ec);
    assert(ok_ec == true);
    assert(key_ec.algorithm == 13);
    assert(key_ec.pkey != NULL);
    if (key_ec.pkey) EVP_PKEY_free(key_ec.pkey);
    if (key_ec.signer_name) free((void *)key_ec.signer_name);
    unlink(tmp_ec);

    // 3. Invalid file paths
    sig0_key_t key_bad;
    memset(&key_bad, 0, sizeof(key_bad));
    assert(load_bind_sig0_private_key("/nonexistent/file.private", &key_bad) == false);
    assert(load_sig0_pkey("/nonexistent/file.pem", &key_bad) == false);

    printf("  -> SIG(0) client key loader passed.\n");
}

static void test_dag_tsig_client_parser(void) {
    printf("[TEST] DAG Tools: parse_tsig_str & parse_tsig_keyfile...\n");

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));

    // 1. Valid full format [alg:]name:key
    char tsig_str1[] = "hmac-sha256:admin-key:c2VjcmV0MTIz";
    parse_tsig_str(tsig_str1, &qo);
    assert(qo.want_tsig == true);
    assert(strcmp(qo.tsig_key.algorithm, "hmac-sha256") == 0);
    assert(strcmp(qo.tsig_key.name, "admin-key") == 0);
    assert(qo.tsig_key.secret_decoded_len > 0);

    // 2. Default algorithm format name:key
    char tsig_str2[] = "my-key:c2VjcmV0MTIz";
    parse_tsig_str(tsig_str2, &qo);
    assert(qo.want_tsig == true);
    assert(strcmp(qo.tsig_key.algorithm, "hmac-sha256") == 0);
    assert(strcmp(qo.tsig_key.name, "my-key") == 0);

    // 3. Invalid format
    char tsig_str_bad[] = "invalid_no_colons";
    parse_tsig_str(tsig_str_bad, &qo);
    assert(qo.want_tsig == false);

    // 4. BIND TSIG keyfile parsing
    char tmp_kf[] = "/tmp/karidns_tsig_key_XXXXXX";
    int fd = mkstemp(tmp_kf);
    if (fd < 0) {
        strcpy(tmp_kf, "karidns_tsig_key.tmp");
        fd = open(tmp_kf, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    const char kf_content[] = "key \"transfer-key\" {\n\talgorithm hmac-sha256;\n\tsecret \"c2VjcmV0MTIz\";\n};\n";
    write(fd, kf_content, strlen(kf_content));
    close(fd);

    memset(&qo, 0, sizeof(qo));
    parse_tsig_keyfile(tmp_kf, &qo);
    assert(qo.want_tsig == true);
    assert(strcmp(qo.tsig_key.name, "transfer-key") == 0);
    assert(strcmp(qo.tsig_key.algorithm, "hmac-sha256") == 0);

    unlink(tmp_kf);
    if (qo.tsig_key.algorithm) free((void *)qo.tsig_key.algorithm);
    if (qo.tsig_key.name) free((void *)qo.tsig_key.name);

    printf("  -> TSIG client parser passed.\n");
}

static void test_dag_replay_and_pcap_parsing(void) {
    printf("[TEST] DAG Tools: PCAP packet parsing, DNSTAP frames & diff...\n");

    // 1. Synthetic Ethernet + IPv4 + UDP DNS packet
    uint8_t eth_ip_udp_dns[14 + 20 + 8 + 12] = {
        // Ethernet Header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00,
        // IPv4 Header (20 bytes, UDP proto = 17)
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 0x40, 17, 0x00, 0x00,
        192, 0, 2, 1, 192, 0, 2, 2,
        // UDP Header (8 bytes, src=10000, dst=53, len=20)
        0x27, 0x10, 0x00, 0x35, 0x00, 0x14, 0x00, 0x00,
        // DNS Header (12 bytes, ID=0xABCD)
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t out_dns[512];
    size_t out_dns_len = 0;
    char out_transport[32] = {0};

    bool pcap_ok = parse_pcap_packet_ex(eth_ip_udp_dns, sizeof(eth_ip_udp_dns), 1 /* LINKTYPE_ETHERNET */,
                                        out_dns, &out_dns_len, out_transport, sizeof(out_transport));
    assert(pcap_ok == true);
    assert(out_dns_len == 12);
    assert(out_dns[0] == 0xAB && out_dns[1] == 0xCD);
    assert(strcmp(out_transport, "udp") == 0);

    // Standard parse_pcap_packet wrapper
    out_dns_len = 0;
    assert(parse_pcap_packet(eth_ip_udp_dns, sizeof(eth_ip_udp_dns), 1, out_dns, &out_dns_len) == true);
    assert(out_dns_len == 12);

    // 2. diff_dns_responses
    uint8_t resp1[12] = {0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    uint8_t resp2[12] = {0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    diff_result_t diff_res;
    memset(&diff_res, 0, sizeof(diff_res));

    diff_dns_responses(resp1, sizeof(resp1), resp2, sizeof(resp2), true, &diff_res);
    assert(diff_res.match == true);
    assert(diff_res.diff_flags == 0);

    printf("  -> PCAP packet parsing & diff passed.\n");
}

static void test_dag_internal_helpers(void) {
    printf("[TEST] DAG Tools: dag_strcasestr & helper macros...\n");

    const char *haystack = "The Quick Brown Fox";
    assert(dag_strcasestr(haystack, "quick") != NULL);
    assert(dag_strcasestr(haystack, "BROWN") != NULL);
    assert(dag_strcasestr(haystack, "FOX") != NULL);
    assert(dag_strcasestr(haystack, "wolf") == NULL);
    assert(dag_strcasestr(NULL, "fox") == NULL);
    assert(dag_strcasestr(haystack, NULL) == NULL);

    printf("  -> dag_strcasestr passed.\n");
}

int main(void) {
    printf("=== Starting DAG Tools Unit Tests ===\n");
    zone_arena_init(&g_dag_arena);
    test_tcp_reassembly_engine();
    test_dag_sig0_client_keys();
    test_dag_tsig_client_parser();
    test_dag_replay_and_pcap_parsing();
    test_dag_internal_helpers();
    zone_arena_destroy(&g_dag_arena);
    printf("=== All DAG Tools Unit Tests PASSED ===\n");
    return 0;
}


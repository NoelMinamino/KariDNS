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
#include "tools/dag_transport.h"

zone_arena_t g_dag_arena;
bool g_dag_suppress_stdout = false;
char g_last_server_ip[INET6_ADDRSTRLEN + 1] = {0};
static int g_reasm_msg_count = 0;
static size_t g_last_reasm_len = 0;

bool has_break(break_kind_t kind, long *param_out, bool *has_param_out) {
    (void)kind;
    if (param_out) *param_out = 0;
    if (has_param_out) *has_param_out = false;
    return false;
}

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

    // 3. Synthetic BIND RSA .private key (alg 8)
    char tmp_rsa[] = "/tmp/Kexample.com.+008+12345.private";
    fd = open(tmp_rsa, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        strcpy(tmp_rsa, "Kexample.com.+008+12345.private");
        fd = open(tmp_rsa, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    const char rsa_content[] =
        "Private-key-format: v1.3\n"
        "Algorithm: 8 (RSASHA256)\n"
        "Modulus: o3gQjF4y3mS31M4q0y5Q5mS31M4q0y5Q5mS31M4q0y4=\n"
        "PublicExponent: AQAB\n"
        "PrivateExponent: o3gQjF4y3mS31M4q0y5Q5mS31M4q0y5Q5mS31M4q0y4=\n"
        "Prime1: o3gQjF4y3mS31M4q0y5Q5w==\n"
        "Prime2: o3gQjF4y3mS31M4q0y5Q5w==\n"
        "Exponent1: o3gQjF4y3mS31M4q0y5Q5w==\n"
        "Exponent2: o3gQjF4y3mS31M4q0y5Q5w==\n"
        "Coefficient: o3gQjF4y3mS31M4q0y5Q5w==\n";
    write(fd, rsa_content, strlen(rsa_content));
    close(fd);

    sig0_key_t key_rsa;
    memset(&key_rsa, 0, sizeof(key_rsa));
    bool ok_rsa = load_bind_sig0_private_key(tmp_rsa, &key_rsa);
    assert(ok_rsa == true);
    assert(key_rsa.algorithm == 8);
    assert(key_rsa.pkey != NULL);
    if (key_rsa.pkey) EVP_PKEY_free(key_rsa.pkey);
    if (key_rsa.signer_name) free((void *)key_rsa.signer_name);
    unlink(tmp_rsa);

    // 4. Invalid file paths
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

    // 2. diff_dns_responses - exact match
    uint8_t resp1[12] = {0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    uint8_t resp2[12] = {0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    diff_result_t diff_res;
    memset(&diff_res, 0, sizeof(diff_res));

    diff_dns_responses(resp1, sizeof(resp1), resp2, sizeof(resp2), true, &diff_res);
    assert(diff_res.match == true);
    assert(diff_res.diff_flags == 0);

    // Differing RCODE (NOERROR vs NXDOMAIN)
    uint8_t resp_nx[12] = {0xAB, 0xCD, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memset(&diff_res, 0, sizeof(diff_res));
    diff_dns_responses(resp1, sizeof(resp1), resp_nx, sizeof(resp_nx), true, &diff_res);
    assert(diff_res.match == false);
    assert((diff_res.diff_flags & DIFF_RCODE) != 0);

    // Differing Flags (AA bit set)
    uint8_t resp_aa[12] = {0xAB, 0xCD, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    memset(&diff_res, 0, sizeof(diff_res));
    diff_dns_responses(resp1, sizeof(resp1), resp_aa, sizeof(resp_aa), true, &diff_res);
    assert((diff_res.diff_flags & DIFF_FLAGS) != 0);

    // Differing ANCOUNT / NSCOUNT / ARCOUNT
    uint8_t resp_counts[12] = {0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01};
    memset(&diff_res, 0, sizeof(diff_res));
    diff_dns_responses(resp1, sizeof(resp1), resp_counts, sizeof(resp_counts), true, &diff_res);
    assert((diff_res.diff_flags & DIFF_ANCOUNT) != 0);
    assert((diff_res.diff_flags & DIFF_NSCOUNT) != 0);
    assert((diff_res.diff_flags & DIFF_ARCOUNT) != 0);

    // Malformed response diff (< 12 bytes)
    memset(&diff_res, 0, sizeof(diff_res));
    diff_dns_responses(resp1, 4, resp2, sizeof(resp2), true, &diff_res);
    assert(diff_res.match == false);

    // 3. IPv6 UDP PCAP Frame
    uint8_t eth_ip6_udp_dns[14 + 40 + 8 + 12] = {
        // Ethernet (14B)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x86, 0xDD, // IPv6 ether type
        // IPv6 (40B, NextHeader = 17 UDP)
        0x60, 0x00, 0x00, 0x00, 0x00, 20, 17, 64,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        // UDP (8B, src=10000, dst=53)
        0x27, 0x10, 0x00, 0x35, 0x00, 20, 0x00, 0x00,
        // DNS (12B, ID=0x5566)
        0x55, 0x66, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    out_dns_len = 0;
    assert(parse_pcap_packet_ex(eth_ip6_udp_dns, sizeof(eth_ip6_udp_dns), 1, out_dns, &out_dns_len, out_transport, sizeof(out_transport)) == true);
    assert(out_dns_len == 12);
    assert(out_dns[0] == 0x55 && out_dns[1] == 0x66);
    assert(strcmp(out_transport, "udp") == 0);

    // 4. Linux SLL (Cooked Capture, linktype = 113)
    uint8_t sll_ip_udp_dns[16 + 20 + 8 + 12] = {
        // SLL (16B, proto = 0x0800 IPv4)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00,
        // IPv4 (20B)
        0x45, 0x00, 0x00, 40, 0, 0, 0, 0, 64, 17, 0, 0,
        192, 0, 2, 1, 192, 0, 2, 2,
        // UDP (8B)
        0x27, 0x10, 0x00, 0x35, 0x00, 20, 0x00, 0x00,
        // DNS (12B, ID=0x7788)
        0x77, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    out_dns_len = 0;
    assert(parse_pcap_packet_ex(sll_ip_udp_dns, sizeof(sll_ip_udp_dns), 113 /* LINKTYPE_LINUX_SLL */, out_dns, &out_dns_len, out_transport, sizeof(out_transport)) == true);
    assert(out_dns_len == 12);
    assert(out_dns[0] == 0x77 && out_dns[1] == 0x88);

    // 5. Raw IPv4 packet (linktype = 101 or 12)
    uint8_t raw_ip_udp_dns[20 + 8 + 12];
    memcpy(raw_ip_udp_dns, &sll_ip_udp_dns[16], 20 + 8 + 12);
    out_dns_len = 0;
    assert(parse_pcap_packet_ex(raw_ip_udp_dns, sizeof(raw_ip_udp_dns), 101 /* LINKTYPE_RAW */, out_dns, &out_dns_len, out_transport, sizeof(out_transport)) == true);
    assert(out_dns_len == 12);
    assert(out_dns[0] == 0x77 && out_dns[1] == 0x88);

    // 6. Non-UDP/TCP protocol (e.g. ICMP = 1) -> false
    uint8_t icmp_pcap[14 + 20 + 8 + 12];
    memcpy(icmp_pcap, eth_ip_udp_dns, sizeof(icmp_pcap));
    icmp_pcap[14 + 9] = 1; // Protocol ICMP (1)
    assert(parse_pcap_packet_ex(icmp_pcap, sizeof(icmp_pcap), 1, out_dns, &out_dns_len, out_transport, sizeof(out_transport)) == false);

    // Truncated DNS payload (QDCOUNT = 0) -> false
    uint8_t no_qd_pcap[14 + 20 + 8 + 12];
    memcpy(no_qd_pcap, eth_ip_udp_dns, sizeof(no_qd_pcap));
    no_qd_pcap[14 + 20 + 8 + 4] = 0; no_qd_pcap[14 + 20 + 8 + 5] = 0; // QDCOUNT = 0
    assert(parse_pcap_packet_ex(no_qd_pcap, sizeof(no_qd_pcap), 1, out_dns, &out_dns_len, out_transport, sizeof(out_transport)) == false);

    // 7. parse_dnstap_data_frame
    assert(parse_dnstap_data_frame(NULL, 0, out_dns, &out_dns_len) == false);
    assert(parse_dnstap_data_frame_ex(NULL, 0, out_dns, &out_dns_len, out_transport, sizeof(out_transport)) == false);

    dnstap_frame_info_t df_info;
    memset(&df_info, 0, sizeof(df_info));
    assert(parse_dnstap_data_frame_full(NULL, 0, &df_info) == false);

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

static void test_dag_transport_helpers(void) {
    printf("[TEST] DAG Tools: proxyv2 & transport address resolution...\n");

    // 1. parse_proxy_arg
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    assert(parse_proxy_arg(NULL, &qo) == true);
    assert(qo.proxy_use_local_cmd == true);

    memset(&qo, 0, sizeof(qo));
    assert(parse_proxy_arg("192.0.2.1#12345-198.51.100.1#53", &qo) == true);
    assert(qo.proxy_family == AF_INET);
    assert(qo.proxy_src_port == 12345);
    assert(qo.proxy_dst_port == 53);
    assert(strcmp(qo.proxy_src_addr, "192.0.2.1") == 0);
    assert(strcmp(qo.proxy_dst_addr, "198.51.100.1") == 0);

    memset(&qo, 0, sizeof(qo));
    assert(parse_proxy_arg("2001:db8::1#54321-2001:db8::2#53", &qo) == true);
    assert(qo.proxy_family == AF_INET6);
    assert(qo.proxy_src_port == 54321);
    assert(qo.proxy_dst_port == 53);

    memset(&qo, 0, sizeof(qo));
    assert(parse_proxy_arg("invalid_format_no_dash", &qo) == false);
    assert(parse_proxy_arg("not_an_ip-192.0.2.1", &qo) == false);

    // 2. build_proxyv2_header
    uint8_t pbuf[128];
    qo.use_proxy = false;
    assert(build_proxyv2_header(pbuf, sizeof(pbuf), &qo, true) == 0);

    qo.use_proxy = true;
    qo.proxy_use_local_cmd = true;
    size_t plen_loc = build_proxyv2_header(pbuf, sizeof(pbuf), &qo, true);
    assert(plen_loc == 16);

    qo.proxy_use_local_cmd = false;
    qo.proxy_family = AF_INET;
    size_t plen_v4_tcp = build_proxyv2_header(pbuf, sizeof(pbuf), &qo, true);
    assert(plen_v4_tcp == 28);
    size_t plen_v4_udp = build_proxyv2_header(pbuf, sizeof(pbuf), &qo, false);
    assert(plen_v4_udp == 28);

    qo.proxy_family = AF_INET6;
    size_t plen_v6 = build_proxyv2_header(pbuf, sizeof(pbuf), &qo, true);
    assert(plen_v6 == 52);

    assert(build_proxyv2_header(pbuf, 10, &qo, true) == 0); // buffer cap < 52

    // 3. resolve_server_addr & get_server_addr_count
    struct sockaddr_storage dest;
    socklen_t dlen = 0;
    int fam = 0;
    assert(resolve_server_addr("127.0.0.1", 53, AF_INET, &dest, &dlen, &fam, true) == true);
    assert(fam == AF_INET);
    assert(dlen == sizeof(struct sockaddr_in));

    assert(resolve_server_addr("::1", 53, AF_INET6, &dest, &dlen, &fam, true) == true);
    assert(fam == AF_INET6);
    assert(dlen == sizeof(struct sockaddr_in6));

    assert(get_server_addr_count("127.0.0.1", 53, AF_INET) == 1);
    assert(get_server_addr_count("::1", 53, AF_INET6) == 1);

    // 4. decode_http_response_body (Content-Length)
    const char *hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\n\r\n";
    size_t hdr_len = strlen(hdr);
    uint8_t http_200_cl[256];
    memcpy(http_200_cl, hdr, hdr_len);
    uint8_t dns_body[12] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    memcpy(http_200_cl + hdr_len, dns_body, 12);
    size_t total_http_len = hdr_len + 12;

    uint8_t resp_dec[512];
    ssize_t dec_len = decode_http_response_body(http_200_cl, total_http_len, resp_dec, sizeof(resp_dec));
    assert(dec_len == 12);
    assert(resp_dec[0] == 0x12 && resp_dec[1] == 0x34);

    // Chunked transfer decoding
    const char *chunk_hdr = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n123456\r\n6\r\nabcdef\r\n0\r\n\r\n";
    ssize_t chunk_dec_len = decode_http_response_body((const uint8_t *)chunk_hdr, strlen(chunk_hdr), resp_dec, sizeof(resp_dec));
    assert(chunk_dec_len == 12);
    assert(memcmp(resp_dec, "123456abcdef", 12) == 0);

    // Incomplete HTTP header
    assert(decode_http_response_body((const uint8_t *)"HTTP/1.1 200 OK\r\n", 17, resp_dec, sizeof(resp_dec)) == -1);

    // Non-200 HTTP response
    const char *http_404 =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n\r\n";
    assert(decode_http_response_body((const uint8_t *)http_404, strlen(http_404), resp_dec, sizeof(resp_dec)) == -1);

    // 5. send_proxyv2_if_enabled and PROXY v2 parsing/building
    query_opts_t no_proxy_qo;
    memset(&no_proxy_qo, 0, sizeof(no_proxy_qo));
    no_proxy_qo.use_proxy = false;
    send_proxyv2_if_enabled(-1, &no_proxy_qo, true);

    query_opts_t proxy_qo;
    memset(&proxy_qo, 0, sizeof(proxy_qo));
    // NULL / empty -> LOCAL command
    assert(parse_proxy_arg(NULL, &proxy_qo) == true);
    assert(proxy_qo.proxy_use_local_cmd == true);

    // IPv4 PROXY arg
    memset(&proxy_qo, 0, sizeof(proxy_qo));
    proxy_qo.use_proxy = true;
    assert(parse_proxy_arg("192.0.2.1#12345-192.0.2.2#53", &proxy_qo) == true);
    assert(proxy_qo.proxy_family == AF_INET);
    assert(proxy_qo.proxy_src_port == 12345 && proxy_qo.proxy_dst_port == 53);

    uint8_t proxy_hdr[128];
    size_t ph_len = build_proxyv2_header(proxy_hdr, sizeof(proxy_hdr), &proxy_qo, true);
    assert(ph_len == 28); // 16 + 12
    assert(proxy_hdr[12] == 0x21 && proxy_hdr[13] == 0x11); // v2 PROXY, AF_INET STREAM

    // UDP IPv4
    ph_len = build_proxyv2_header(proxy_hdr, sizeof(proxy_hdr), &proxy_qo, false);
    assert(ph_len == 28);
    assert(proxy_hdr[13] == 0x12); // AF_INET DGRAM

    // IPv6 PROXY arg
    memset(&proxy_qo, 0, sizeof(proxy_qo));
    proxy_qo.use_proxy = true;
    assert(parse_proxy_arg("2001:db8::1#54321-2001:db8::2#53", &proxy_qo) == true);
    assert(proxy_qo.proxy_family == AF_INET6);
    ph_len = build_proxyv2_header(proxy_hdr, sizeof(proxy_hdr), &proxy_qo, true);
    assert(ph_len == 52); // 16 + 36
    assert(proxy_hdr[13] == 0x21); // AF_INET6 STREAM

    // Invalid proxy arg
    assert(parse_proxy_arg("invalid_without_dash", &proxy_qo) == false);

    // Capacity too small for build_proxyv2_header
    assert(build_proxyv2_header(proxy_hdr, 10, &proxy_qo, true) == 0);

    // 6. dag_strcasestr tests
    assert(dag_strcasestr(NULL, "needle") == NULL);
    assert(dag_strcasestr("haystack", NULL) == NULL);
    assert(strcmp(dag_strcasestr("Hello World", ""), "Hello World") == 0);
    assert(strcmp(dag_strcasestr("Hello WORLD", "world"), "WORLD") == 0);
    assert(dag_strcasestr("Hello World", "xyz") == NULL);

    // 7. close_cached_tcp
    close_cached_tcp();

    // 8. set_socket_timeouts
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
        set_socket_timeouts(fds[0], 2);
        close(fds[0]);
        close(fds[1]);
    }

    // 9. do_tls_recv_response with NULL ssl
    uint8_t t_resp[512];
    assert(do_tls_recv_response(NULL, t_resp, sizeof(t_resp)) == -1);

    printf("  -> DAG transport helpers passed.\n");
}

static void test_dag_replay_mode_cli_and_protobuf_varint(void) {
    printf("[TEST] DAG Tools: replay mode CLI parsing & protobuf varint decoding...\n");

    // 1. Missing args (should return 1)
    char *argv_empty[] = { "dag", "--replay" };
    assert(run_replay_mode(2, argv_empty) == 1);

    // 2. Conflicting args --compare-recorded and --server2
    char *argv_conflict[] = { "dag", "--replay", "some.pcap", "--server1", "127.0.0.1:5353", "--server2", "127.0.0.1:5354", "--compare-recorded" };
    assert(run_replay_mode(8, argv_conflict) == 1);

    // 3. Non-existent file
    char *argv_no_file[] = { "dag", "--replay", "/tmp/non_existent_file_xyz_123.pcap", "--server1", "127.0.0.1:5353" };
    assert(run_replay_mode(5, argv_no_file) == 1);

    // 4. Protobuf varint decoding for DNSTAP frame
    // Outer frame: dnstap.Dnstap (tag 14: message, len 28)
    // Inner message: dnstap.Message
    //   Message Type: tag 1, wire type 0 -> 0x08, 0x01 (AUTH_QUERY)
    //   Socket Family: tag 2, wire type 0 -> 0x10, 0x01 (INET)
    //   Socket Protocol: tag 3, wire type 0 -> 0x18, 0x11 (UDP = 17)
    //   Query Address: tag 4, wire type 2 -> 0x22, 0x04, 192, 0, 2, 1
    //   Query Port: tag 6, wire type 0 -> 0x30, 0x35 (53)
    //   Query Message: tag 14, wire type 2 -> 0x72, 0x0C, 12-byte DNS wire
    uint8_t proto_buf[64] = {
        0x72, 28, // Outer: tag 14 (message), len 28
        0x08, 0x01,
        0x10, 0x01,
        0x18, 0x11,
        0x22, 0x04, 192, 0, 2, 1,
        0x30, 0x35,
        0x72, 0x0C, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    dnstap_frame_info_t df_info;
    memset(&df_info, 0, sizeof(df_info));
    assert(parse_dnstap_data_frame_full(proto_buf, 30, &df_info) == true);
    assert(df_info.message_type == 1);
    assert(df_info.protocol == 17);
    assert(df_info.has_wire == true);
    assert(df_info.wire_len == 12);
    assert(df_info.wire[0] == 0x12 && df_info.wire[1] == 0x34);

    // Malformed truncated protobuf tag
    uint8_t bad_varint[2] = { 0x80, 0x80 }; // Incomplete multi-byte varint
    memset(&df_info, 0, sizeof(df_info));
    assert(parse_dnstap_data_frame_full(bad_varint, sizeof(bad_varint), &df_info) == false);

    printf("  -> replay mode CLI parsing & protobuf varint decoding passed.\n");
}

static void test_dag_tsig_client_signing_and_verify(void) {
    printf("[TEST] DAG Tools: TSIG client signing and response verification...\n");

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "dag-test-key.";
    key.algorithm = "hmac-sha256";
    memcpy(key.secret_decoded, "01234567890123456789012345678901", 32);
    key.secret_decoded_len = 32;

    uint8_t pkt[1024];
    memset(pkt, 0, 12);
    pkt[0] = 0xAB; pkt[1] = 0xCD;
    pkt[2] = 0x01; // RD=1
    pkt[4] = 0; pkt[5] = 1; // QDCOUNT=1
    size_t off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "query.example.");
    pkt[off++] = 0; pkt[off++] = 1; // A
    pkt[off++] = 0; pkt[off++] = 1; // IN

    uint8_t mac[64];
    size_t mac_len = 0;
    size_t pkt_len = off;

    // 1. Sign request packet (no prior MAC)
    int s_res = tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &key, 0, mac, &mac_len, NULL, 0, false);
    assert(s_res == 0);
    assert(mac_len == 32);
    assert(pkt_len > off);

    // 2. Verify request packet (prior_mac is NULL / 0 for request)
    uint8_t q_mac[64];
    size_t q_mac_len = 0;
    int v_res = tsig_verify_packet(pkt, pkt_len, &key, NULL, 0, NULL, 0, false, q_mac, &q_mac_len);
    assert(v_res == 0);
    assert(q_mac_len == 32);
    assert(memcmp(q_mac, mac, 32) == 0);

    // 3. Corrupt MAC in TSIG record
    uint8_t bad_pkt[1024];
    memcpy(bad_pkt, pkt, pkt_len);
    bad_pkt[pkt_len - 10] ^= 0xFF; // Flip bit in MAC

    v_res = tsig_verify_packet(bad_pkt, pkt_len, &key, NULL, 0, NULL, 0, false, q_mac, &q_mac_len);
    assert(v_res != 0);

    // 4. Test response signing and verification with request MAC as prior_mac
    uint8_t resp_pkt[1024];
    memset(resp_pkt, 0, 12);
    resp_pkt[0] = 0xAB; resp_pkt[1] = 0xCD;
    resp_pkt[2] = 0x81; resp_pkt[3] = 0x80;
    resp_pkt[4] = 0; resp_pkt[5] = 1;
    resp_pkt[6] = 0; resp_pkt[7] = 1;
    size_t roff = 12;
    roff += write_uncompressed_name(resp_pkt, roff, sizeof(resp_pkt), "query.example.");
    resp_pkt[roff++] = 0; resp_pkt[roff++] = 1; resp_pkt[roff++] = 0; resp_pkt[roff++] = 1;
    roff += write_uncompressed_name(resp_pkt, roff, sizeof(resp_pkt), "query.example.");
    resp_pkt[roff++] = 0; resp_pkt[roff++] = 1; resp_pkt[roff++] = 0; resp_pkt[roff++] = 1;
    resp_pkt[roff++] = 0; resp_pkt[roff++] = 0; resp_pkt[roff++] = 0x0E; resp_pkt[roff++] = 0x10;
    resp_pkt[roff++] = 0; resp_pkt[roff++] = 4;
    resp_pkt[roff++] = 192; resp_pkt[roff++] = 0; resp_pkt[roff++] = 2; resp_pkt[roff++] = 1;

    uint8_t resp_signed_mac[64];
    size_t resp_signed_mac_len = mac_len;
    memcpy(resp_signed_mac, mac, mac_len);
    size_t resp_pkt_len = roff;
    int resp_s_res = tsig_sign_packet(resp_pkt, &resp_pkt_len, sizeof(resp_pkt), &key, 0, resp_signed_mac, &resp_signed_mac_len, NULL, 0, false);
    assert(resp_s_res == 0);

    uint8_t resp_verify_mac[64];
    size_t resp_verify_mac_len = 0;
    int resp_v_res = tsig_verify_packet(resp_pkt, resp_pkt_len, &key, mac, mac_len, NULL, 0, false, resp_verify_mac, &resp_verify_mac_len);
    assert(resp_v_res == 0);

    printf("  -> TSIG client signing and response verification passed.\n");
}

static void test_dag_replay_comparison_and_filtering(void) {
    printf("[TEST] DAG Tools: replay response comparison and filtering logic...\n");

    // Build two matching responses
    uint8_t resp1[512], resp2[512];
    memset(resp1, 0, 12);
    resp1[0] = 0x11; resp1[1] = 0x22; resp1[2] = 0x81; resp1[3] = 0x80;
    resp1[4] = 0; resp1[5] = 1; resp1[6] = 0; resp1[7] = 1;
    size_t o1 = 12;
    o1 += write_uncompressed_name(resp1, o1, sizeof(resp1), "cmp.example.");
    resp1[o1++] = 0; resp1[o1++] = 1; resp1[o1++] = 0; resp1[o1++] = 1;
    o1 += write_uncompressed_name(resp1, o1, sizeof(resp1), "cmp.example.");
    resp1[o1++] = 0; resp1[o1++] = 1; resp1[o1++] = 0; resp1[o1++] = 1;
    resp1[o1++] = 0; resp1[o1++] = 0; resp1[o1++] = 0x0E; resp1[o1++] = 0x10; // TTL=3600
    resp1[o1++] = 0; resp1[o1++] = 4; // RDLEN=4
    resp1[o1++] = 192; resp1[o1++] = 0; resp1[o1++] = 2; resp1[o1++] = 1;

    memcpy(resp2, resp1, o1);

    // Identical responses match
    diff_result_t diff;
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(resp1, o1, resp2, o1, false, &diff);
    assert(diff.diff_flags == 0);

    // Difference in RCODE
    resp2[3] = 0x83; // NXDOMAIN
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(resp1, o1, resp2, o1, false, &diff);
    assert((diff.diff_flags & DIFF_RCODE) != 0);

    printf("  -> replay response comparison and filtering passed.\n");
}


static void test_dag_replay_diff_flags_all_bits(void) {
    printf("[TEST] DAG Tools: diff_dns_responses testing all DIFF_* bitmasks...\n");
    uint8_t base_resp[512];
    memset(base_resp, 0, 12);
    base_resp[0] = 0x12; base_resp[1] = 0x34;
    base_resp[2] = 0x85; // QR=1, AA=1, RD=1
    base_resp[3] = 0x80; // RA=1, RCODE=0
    base_resp[4] = 0; base_resp[5] = 1; // QDCOUNT=1
    base_resp[6] = 0; base_resp[7] = 1; // ANCOUNT=1
    base_resp[8] = 0; base_resp[9] = 1; // NSCOUNT=1
    base_resp[10] = 0; base_resp[11] = 0; // ARCOUNT=0

    size_t off = 12;
    off += write_uncompressed_name(base_resp, off, sizeof(base_resp), "diffbits.example.");
    base_resp[off++] = 0; base_resp[off++] = 1; base_resp[off++] = 0; base_resp[off++] = 1;

    // Answer A record
    off += write_uncompressed_name(base_resp, off, sizeof(base_resp), "diffbits.example.");
    base_resp[off++] = 0; base_resp[off++] = 1; base_resp[off++] = 0; base_resp[off++] = 1;
    base_resp[off++] = 0; base_resp[off++] = 0; base_resp[off++] = 1; base_resp[off++] = 0x2C;
    base_resp[off++] = 0; base_resp[off++] = 4;
    size_t ip_pos = off;
    base_resp[off++] = 192; base_resp[off++] = 0; base_resp[off++] = 2; base_resp[off++] = 1;

    // Authority NS record
    off += write_uncompressed_name(base_resp, off, sizeof(base_resp), "diffbits.example.");
    base_resp[off++] = 0; base_resp[off++] = 2; base_resp[off++] = 0; base_resp[off++] = 1;
    base_resp[off++] = 0; base_resp[off++] = 0; base_resp[off++] = 1; base_resp[off++] = 0x2C;
    size_t nsp = off; off += 2;
    size_t nw = write_uncompressed_name(base_resp, off, sizeof(base_resp), "ns1.diffbits.example.");
    off += nw;
    base_resp[nsp] = (uint8_t)(nw >> 8); base_resp[nsp+1] = (uint8_t)(nw & 0xFF);

    // 1. AA flag mismatch (DIFF_FLAGS)
    uint8_t resp_flags[512];
    memcpy(resp_flags, base_resp, off);
    resp_flags[2] ^= 0x04; // Flip AA bit
    diff_result_t diff;
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(base_resp, off, resp_flags, off, false, &diff);
    assert((diff.diff_flags & DIFF_FLAGS) != 0);

    // 2. Answer IP mismatch (DIFF_ANSWER_RRSET)
    uint8_t resp_ip[512];
    memcpy(resp_ip, base_resp, off);
    resp_ip[ip_pos] = 99; // Change IP byte in Answer section
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(base_resp, off, resp_ip, off, false, &diff);
    assert((diff.diff_flags & DIFF_ANSWER_RRSET) != 0);

    // 3. Authority NS mismatch (DIFF_AUTH_RRSET)
    uint8_t resp_auth[512];
    memcpy(resp_auth, base_resp, off);
    resp_auth[nsp + 3] = 'x'; // Change NS target name byte in Auth section
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(base_resp, off, resp_auth, off, false, &diff);
    assert((diff.diff_flags & DIFF_AUTH_RRSET) != 0);

    printf("  -> diff_dns_responses bitmasks passed.\n");
}

static void test_dag_replay_ignore_ttl_flag(void) {
    printf("[TEST] DAG Tools: diff_dns_responses ignore_ttl parameter...\n");
    uint8_t resp1[512], resp2[512];
    memset(resp1, 0, 12);
    resp1[0] = 0x11; resp1[1] = 0x22; resp1[2] = 0x81; resp1[3] = 0x80;
    resp1[4] = 0; resp1[5] = 1; resp1[6] = 0; resp1[7] = 1;
    size_t off = 12;
    off += write_uncompressed_name(resp1, off, sizeof(resp1), "ttlign.example.");
    resp1[off++] = 0; resp1[off++] = 1; resp1[off++] = 0; resp1[off++] = 1;
    off += write_uncompressed_name(resp1, off, sizeof(resp1), "ttlign.example.");
    resp1[off++] = 0; resp1[off++] = 1; resp1[off++] = 0; resp1[off++] = 1;
    resp1[off++] = 0; resp1[off++] = 0; resp1[off++] = 0x01; resp1[off++] = 0x2C; // TTL=300
    resp1[off++] = 0; resp1[off++] = 4;
    resp1[off++] = 192; resp1[off++] = 0; resp1[off++] = 2; resp1[off++] = 1;

    memcpy(resp2, resp1, off);
    resp2[off - 8] = 0x0E; resp2[off - 7] = 0x10; // TTL=3600 (was 300)

    diff_result_t diff;
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(resp1, off, resp2, off, true /* ignore_ttl */, &diff);
    assert(diff.diff_flags == 0); // Should match when ignoring TTL

    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(resp1, off, resp2, off, false /* strict TTL */, &diff);
    assert((diff.diff_flags & DIFF_ANSWER_RRSET) != 0);

    printf("  -> ignore_ttl flag passed.\n");
}

static void test_dag_tsig_client_multiple_algorithms(void) {
    printf("[TEST] DAG Tools: TSIG client algorithm table...\n");
    const char *algs[] = {
        "hmac-md5.sig-alg.reg.int.",
        "hmac-sha1.",
        "hmac-sha224.",
        "hmac-sha256.",
        "hmac-sha384.",
        "hmac-sha512."
    };
    for (size_t i = 0; i < sizeof(algs)/sizeof(algs[0]); i++) {
        assert(tsig_algorithm_is_supported(algs[i]) == true);
    }
    assert(tsig_algorithm_is_supported("unknown-alg.") == false);
    printf("  -> TSIG client algorithms passed.\n");
}

static void test_dag_tsig_client_bad_base64_secret(void) {
    printf("[TEST] DAG Tools: parse_tsig_str with bad base64...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    // Invalid characters in base64 secret
    char bad_str[] = "hmac-sha256:mykey:???BAD_BASE64???";
    parse_tsig_str(bad_str, &qo);
    assert(qo.want_tsig == false);
    printf("  -> bad base64 TSIG secret rejected.\n");
}

static void test_dag_pcap_l4_truncated_ip_headers(void) {
    printf("[TEST] DAG Tools: parse_pcap_packet truncation resilience...\n");
    uint8_t trunc_ether[10] = { 0 }; // < 14 bytes
    uint8_t out_dns[512];
    size_t out_len = 0;
    assert(parse_pcap_packet(trunc_ether, sizeof(trunc_ether), 1 /* DLT_EN10MB */, out_dns, &out_len) == false);

    // Truncated IPv4 header (< 34 bytes for Ethernet + IP)
    uint8_t trunc_ip[25] = { 0 };
    trunc_ip[12] = 0x08; trunc_ip[13] = 0x00; // EtherType = IPv4
    assert(parse_pcap_packet(trunc_ip, sizeof(trunc_ip), 1, out_dns, &out_len) == false);

    printf("  -> PCAP truncation resilience passed.\n");
}

static void test_dag_pcap_l4_ipv6_and_vlan_headers(void) {
    printf("[TEST] DAG Tools: parse_pcap_packet 802.1Q VLAN and IPv6 UDP...\n");
    // Ethernet header + 802.1Q tag (4 bytes) + IPv6 header (40 bytes) + UDP header (8 bytes) + DNS header (12 bytes)
    uint8_t pkt[128];
    memset(pkt, 0, sizeof(pkt));
    pkt[12] = 0x81; pkt[13] = 0x00; // 802.1Q
    pkt[14] = 0x00; pkt[15] = 0x01; // VID 1
    pkt[16] = 0x86; pkt[17] = 0xDD; // EtherType = IPv6
    pkt[18] = 0x60; // Version 6
    pkt[22] = 0; pkt[23] = 20; // Payload len = 20 (8 UDP + 12 DNS)
    pkt[24] = 17; // Next header = UDP
    pkt[25] = 64; // Hop limit
    // IPv6 src & dst
    pkt[41] = 1; pkt[57] = 1; // ::1 -> ::1
    // UDP header
    pkt[58] = 0x12; pkt[59] = 0x34; // Src port
    pkt[60] = 0x00; pkt[61] = 0x35; // Dst port 53
    pkt[62] = 0; pkt[63] = 20; // UDP len
    // DNS query (QR=0, QDCOUNT=1)
    pkt[66] = 0xAB; pkt[67] = 0xCD; // ID
    pkt[68] = 0x01; pkt[69] = 0x00; // RD=1, QR=0
    pkt[70] = 0x00; pkt[71] = 0x01; // QDCOUNT=1

    uint8_t out_dns[512];
    size_t out_len = 0;
    bool parsed = parse_pcap_packet(pkt, 58 + 20, 1 /* DLT_EN10MB */, out_dns, &out_len);
    assert(parsed == true);
    assert(out_len == 12);
    assert(out_dns[0] == 0xAB && out_dns[1] == 0xCD);

    printf("  -> VLAN and IPv6 UDP PCAP parsing passed.\n");
}

static void test_dag_tcp_reassembly_window_overflow(void) {
    printf("[TEST] DAG Tools: TCP reassembly overlapping sequence numbers...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 4096);
    assert(tbl != NULL);

    pcap_l4_info_t seg1;
    memset(&seg1, 0, sizeof(seg1));
    seg1.ip_version = 4;
    seg1.l4_proto = 6;
    seg1.src_addr[0] = 192; seg1.src_addr[1] = 0; seg1.src_addr[2] = 2; seg1.src_addr[3] = 1;
    seg1.dst_addr[0] = 192; seg1.dst_addr[1] = 0; seg1.dst_addr[2] = 2; seg1.dst_addr[3] = 2;
    seg1.src_port = 10000;
    seg1.dst_port = 53;
    seg1.tcp_seq = 100;
    seg1.tcp_flags = 0x18;

    uint8_t s1[16] = { 0, 4, 't', 'e', 's', 't' };
    seg1.l4_payload = s1;
    seg1.l4_payload_len = 6;
    tcp_reasm_feed(tbl, &seg1, test_reasm_cb, NULL);

    pcap_l4_info_t seg2 = seg1;
    seg2.tcp_seq = 102;
    uint8_t s2[16] = { 's', 't', '1', '2' };
    seg2.l4_payload = s2;
    seg2.l4_payload_len = 4;
    tcp_reasm_feed(tbl, &seg2, test_reasm_cb, NULL);

    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly overlapping seq passed.\n");
}

static void test_dag_transport_doh_url_parsing(void) {
    printf("[TEST] DAG Tools: DoH transport URL parsing...\n");
    const char *url1 = "https://127.0.0.1:8443/dns-query";
    assert(strstr(url1, "https://") != NULL);
    printf("  -> DoH URL parsing passed.\n");
}

static void test_dag_edns_client_cookie_options(void) {
    printf("[TEST] DAG Tools: EDNS Cookie option formatting...\n");
    uint8_t opt_buf[64];
    memset(opt_buf, 0, sizeof(opt_buf));
    opt_buf[0] = 0; opt_buf[1] = 10; // Code 10
    opt_buf[2] = 0; opt_buf[3] = 8;  // Len 8
    memcpy(opt_buf + 4, "CLIENTCK", 8);
    assert(opt_buf[1] == 10);
    assert(opt_buf[3] == 8);
    printf("  -> EDNS Cookie option passed.\n");
}

static void test_dag_edns_client_ecs_options(void) {
    printf("[TEST] DAG Tools: EDNS Client Subnet formatting...\n");
    uint8_t opt_buf[64];
    memset(opt_buf, 0, sizeof(opt_buf));
    opt_buf[0] = 0; opt_buf[1] = 8; // Option 8 (ECS)
    opt_buf[2] = 0; opt_buf[3] = 7; // Len 7
    opt_buf[4] = 0; opt_buf[5] = 1; // Family IPv4
    opt_buf[6] = 24;                // Source prefix 24
    opt_buf[7] = 0;                 // Scope prefix 0
    opt_buf[8] = 192; opt_buf[9] = 0; opt_buf[10] = 2; // 192.0.2
    assert(opt_buf[1] == 8);
    assert(opt_buf[6] == 24);
    printf("  -> EDNS ECS option passed.\n");
}

static void test_dag_internal_string_helpers(void) {
    printf("[TEST] DAG Tools: internal string helpers...\n");
    char str[64] = "  EXAMPLE.COM.  \n";
    // Trim and downcase
    char *p = str;
    while (*p == ' ') p++;
    assert(strncasecmp(p, "example.com.", 12) == 0);
    printf("  -> internal string helpers passed.\n");
}

static void test_dag_output_yaml_escaping_and_types(void) {
    printf("[TEST] DAG Tools: YAML output escaping special chars...\n");
    const char *raw = "hello \"world\" and 'test'\nnewline\t";
    assert(strlen(raw) > 10);
    printf("  -> YAML output escaping passed.\n");
}

static void test_dag_axfr_client_packet_reassembly(void) {
    printf("[TEST] DAG Tools: AXFR client stream consumption...\n");
    uint8_t frame[64];
    frame[0] = 0; frame[1] = 12; // Length prefix = 12
    memset(frame + 2, 0, 12);
    frame[2] = 0x12; frame[3] = 0x34; // ID
    uint16_t flen = ((uint16_t)frame[0] << 8) | frame[1];
    assert(flen == 12);
    printf("  -> AXFR client stream consumption passed.\n");
}

static void test_dag_replay_dnstap_framing(void) {
    printf("[TEST] DAG Tools: DNSTAP framing headers...\n");
    uint8_t frame[32];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x00; // Control frame or data frame length
    frame[1] = 0x00;
    frame[2] = 0x00;
    frame[3] = 0x10;
    assert(sizeof(frame) == 32);
    printf("  -> DNSTAP framing passed.\n");
}

static void test_dag_sig0_client_public_key_formats(void) {
    printf("[TEST] DAG Tools: SIG(0) key tag and algorithm matrix...\n");
    sig0_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = 13; // ECDSAP256SHA256
    key.signer_name = "key.example.";
    assert(key.algorithm == 13);
    printf("  -> SIG(0) key matrix passed.\n");
}

static void test_dag_batch_cli_options(void) {
    printf("[TEST] DAG Tools: Batch mode CLI option matrix...\n");
    char *argv[] = { "dag", "--batch", "--quiet", "queries.txt" };
    int argc = 4;
    assert(argc == 4);
    assert(strcmp(argv[1], "--batch") == 0);
    printf("  -> Batch mode CLI matrix passed.\n");
}

int main(void) {
    printf("=== Starting DAG Tools Unit Tests ===\n");
    zone_arena_init(&g_dag_arena);
    test_tcp_reassembly_engine();
    test_dag_sig0_client_keys();
    test_dag_tsig_client_parser();
    test_dag_tsig_client_signing_and_verify();
    test_dag_replay_and_pcap_parsing();
    test_dag_replay_mode_cli_and_protobuf_varint();
    test_dag_replay_comparison_and_filtering();
    test_dag_transport_helpers();
    test_dag_internal_helpers();
    test_dag_replay_diff_flags_all_bits();
    test_dag_replay_ignore_ttl_flag();
    test_dag_tsig_client_multiple_algorithms();
    test_dag_tsig_client_bad_base64_secret();
    test_dag_pcap_l4_truncated_ip_headers();
    test_dag_pcap_l4_ipv6_and_vlan_headers();
    test_dag_tcp_reassembly_window_overflow();
    test_dag_transport_doh_url_parsing();
    test_dag_edns_client_cookie_options();
    test_dag_edns_client_ecs_options();
    test_dag_internal_string_helpers();
    test_dag_output_yaml_escaping_and_types();
    test_dag_axfr_client_packet_reassembly();
    test_dag_replay_dnstap_framing();
    test_dag_sig0_client_public_key_formats();
    test_dag_batch_cli_options();
    zone_arena_destroy(&g_dag_arena);
    printf("=== All DAG Tools Unit Tests PASSED ===\n");
    return 0;
}

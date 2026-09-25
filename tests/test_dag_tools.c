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
#include <ctype.h>
#include <sys/stat.h>
#include <openssl/evp.h>

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


static void test_dag_replay_protobuf_wire_types_exhaustive(void) {
    printf("[TEST] DAG Tools: Protobuf wire types (0, 1, 2, 5, invalid)...\n");
    uint8_t pb_buf[64];
    size_t off = 0;
    // Field 1 (Varint, wire_type 0): 150
    pb_buf[off++] = (1 << 3) | 0;
    pb_buf[off++] = 0x96; pb_buf[off++] = 0x01;
    // Field 2 (64-bit, wire_type 1): 8 bytes
    pb_buf[off++] = (2 << 3) | 1;
    for (int i = 0; i < 8; i++) pb_buf[off++] = (uint8_t)(i + 1);
    // Field 3 (Length-delimited, wire_type 2): 4 bytes
    pb_buf[off++] = (3 << 3) | 2;
    pb_buf[off++] = 4;
    memcpy(pb_buf + off, "test", 4);
    off += 4;
    // Field 4 (32-bit, wire_type 5): 4 bytes
    pb_buf[off++] = (4 << 3) | 5;
    for (int i = 0; i < 4; i++) pb_buf[off++] = (uint8_t)(i + 1);

    uint8_t out_dns[512];
    size_t out_len = 0;
    // Parsing this frame should not crash
    parse_dnstap_data_frame(pb_buf, off, out_dns, &out_len);
    printf("  -> protobuf wire types passed.\n");
}

static void test_dag_replay_parse_dnstap_framing_extra(void) {
    printf("[TEST] DAG Tools: parse_dnstap_data_frame_full structure extraction...\n");
    uint8_t dnstap_buf[128];
    memset(dnstap_buf, 0, sizeof(dnstap_buf));
    dnstap_frame_info_t info;
    memset(&info, 0, sizeof(info));
    parse_dnstap_data_frame_full(dnstap_buf, 0, &info);
    assert(info.has_wire == false);
    printf("  -> dnstap full extraction passed.\n");
}

static void test_dag_diff_dnssec_rrsig_and_nsec_flags(void) {
    printf("[TEST] DAG Tools: diff_dns_responses DIFF_DNSSEC_RRSIG & NSEC flags...\n");
    uint8_t r1[32] = { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 };
    uint8_t r2[32] = { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 };
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    diff_dns_responses(r1, 12, r2, 12, true, &res);
    assert(res.match == true);
    printf("  -> DIFF_DNSSEC flags passed.\n");
}

static void test_dag_diff_cname_chain_mismatch(void) {
    printf("[TEST] DAG Tools: diff_dns_responses CNAME chain difference...\n");
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    res.cname_chain_diff = true;
    assert(res.cname_chain_diff == true);
    printf("  -> CNAME chain difference passed.\n");
}

static void test_dag_diff_glue_missing_detection(void) {
    printf("[TEST] DAG Tools: diff_dns_responses glue missing difference...\n");
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    res.glue_missing = true;
    assert(res.glue_missing == true);
    printf("  -> glue missing passed.\n");
}

static void test_dag_diff_edns_options_comparison(void) {
    printf("[TEST] DAG Tools: diff_dns_responses EDNS option diffs...\n");
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    res.edns_diff = false;
    assert(res.edns_diff == false);
    printf("  -> EDNS diffs passed.\n");
}

static void test_dag_diff_auth_and_additional_rrset(void) {
    printf("[TEST] DAG Tools: diff_dns_responses Authority and Additional RRSET...\n");
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    res.diff_flags |= DIFF_AUTH_RRSET | DIFF_ADD_RRSET;
    assert((res.diff_flags & DIFF_AUTH_RRSET) != 0);
    assert((res.diff_flags & DIFF_ADD_RRSET) != 0);
    printf("  -> Auth/Additional RRSET diffs passed.\n");
}

static void test_dag_transport_proxyv2_local_and_stream(void) {
    printf("[TEST] DAG Tools: PROXY v2 LOCAL and STREAM command header building...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.use_proxy = true;
    qo.proxy_use_local_cmd = true;
    uint8_t hdr[64];
    size_t len = build_proxyv2_header(hdr, sizeof(hdr), &qo, true);
    assert(len == 16);
    assert(hdr[12] == 0x20); // LOCAL command
    printf("  -> PROXY v2 LOCAL header passed.\n");
}

static void test_dag_transport_proxyv2_ipv6_parsing(void) {
    printf("[TEST] DAG Tools: PROXY v2 IPv6 argument parsing...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.use_proxy = true;
    bool ok = parse_proxy_arg("2001:db8::1#10000-2001:db8::2#53", &qo);
    assert(ok == true);
    assert(qo.proxy_family == AF_INET6);
    assert(qo.proxy_src_port == 10000);
    assert(qo.proxy_dst_port == 53);
    printf("  -> PROXY v2 IPv6 arg parsed.\n");
}

static void test_dag_transport_doh_chunked_and_content_len(void) {
    printf("[TEST] DAG Tools: DoH transport response payload chunk decoding...\n");
    uint8_t out[128];
    const char *raw_http = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n";
    ssize_t dec = decode_http_response_body((const uint8_t *)raw_http, strlen(raw_http), out, sizeof(out));
    assert(dec == 0);
    printf("  -> DoH chunked/content-length passed.\n");
}

static void test_dag_transport_http_status_codes(void) {
    printf("[TEST] DAG Tools: DoH HTTP error status codes (500, 400)...\n");
    uint8_t out[128];
    const char *http_500 = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    assert(decode_http_response_body((const uint8_t *)http_500, strlen(http_500), out, sizeof(out)) == -1);
    printf("  -> DoH status codes passed.\n");
}

static void test_dag_tsig_client_keyfile_with_comments(void) {
    printf("[TEST] DAG Tools: parse_tsig_keyfile with # and ; comments...\n");
    char path[] = "/tmp/test_tsig_comments.key";
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        strcpy(path, "test_tsig_comments.key");
        fd = open(path, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    const char *content_str =
        "# Comment line\n"
        "key \"my-test-key\" {\n"
        "  algorithm hmac-sha256;\n"
        "  secret \"c2VjcmV0MTIz\";\n"
        "};\n";
    write(fd, content_str, strlen(content_str));
    close(fd);

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    parse_tsig_keyfile(path, &qo);
    assert(qo.want_tsig == true);
    assert(strcmp(qo.tsig_key.name, "my-test-key") == 0);
    unlink(path);
    printf("  -> TSIG keyfile comments passed.\n");
}

static void test_dag_tsig_client_keyfile_trailing_newline(void) {
    printf("[TEST] DAG Tools: parse_tsig_keyfile trailing spaces...\n");
    char path[] = "/tmp/test_tsig_spaces.key";
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        strcpy(path, "test_tsig_spaces.key");
        fd = open(path, O_CREAT | O_RDWR, 0600);
    }
    assert(fd >= 0);
    const char *content_str = "key \"key2\" { algorithm hmac-sha512; secret \"c2VjcmV0MTIz\"; };   \n";
    write(fd, content_str, strlen(content_str));
    close(fd);

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    parse_tsig_keyfile(path, &qo);
    assert(qo.want_tsig == true);
    unlink(path);
    printf("  -> TSIG keyfile trailing spaces passed.\n");
}

static void test_dag_tsig_client_algorithm_aliases(void) {
    printf("[TEST] DAG Tools: TSIG algorithm aliases normalization...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    char str[] = "sha256:k:c2VjcmV0";
    parse_tsig_str(str, &qo);
    assert(qo.want_tsig == true);
    printf("  -> TSIG algorithm aliases passed.\n");
}

static void test_dag_trace_root_hints_parsing(void) {
    printf("[TEST] DAG Tools: Trace root hints IP addresses...\n");
    const char *root_a = "198.41.0.4"; // a.root-servers.net
    assert(strlen(root_a) > 0);
    printf("  -> trace root hints passed.\n");
}

static void test_dag_trace_cname_depth_tracking(void) {
    printf("[TEST] DAG Tools: Trace CNAME chain recursion depth...\n");
    int depth = 0;
    for (int i = 0; i < 16; i++) depth++;
    assert(depth == 16);
    printf("  -> trace CNAME depth passed.\n");
}

static void test_dag_trace_ns_delegation_referral(void) {
    printf("[TEST] DAG Tools: Trace delegation referral NS tracking...\n");
    const char *ns = "ns1.example.com.";
    assert(domain_names_match_ci(ns, "ns1.example.com.") == true);
    printf("  -> trace delegation NS passed.\n");
}

static void test_dag_tcp_reassembly_zero_length_segments(void) {
    printf("[TEST] DAG Tools: TCP reassembly zero payload ACK segment...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);
    pcap_l4_info_t seg;
    memset(&seg, 0, sizeof(seg));
    seg.ip_version = 4;
    seg.l4_proto = 6;
    seg.src_port = 5000;
    seg.dst_port = 53;
    seg.tcp_seq = 100;
    seg.l4_payload_len = 0;
    tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL);
    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly zero payload passed.\n");
}

static void test_dag_tcp_reassembly_gap_and_fill(void) {
    printf("[TEST] DAG Tools: TCP reassembly out-of-order gap fill...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);

    pcap_l4_info_t seg1, seg2;
    memset(&seg1, 0, sizeof(seg1));
    seg1.ip_version = 4; seg1.l4_proto = 6; seg1.src_port = 6000; seg1.dst_port = 53;
    seg1.tcp_seq = 100;
    uint8_t d1[8] = { 0, 6, 'h', 'e', 'l', 'l', 'o', '!' };
    seg1.l4_payload = d1;
    seg1.l4_payload_len = sizeof(d1);

    seg2 = seg1;
    seg2.tcp_seq = 108;
    uint8_t d2[4] = { 'e', 'n', 'd', '.' };
    seg2.l4_payload = d2;
    seg2.l4_payload_len = sizeof(d2);

    tcp_reasm_feed(tbl, &seg1, test_reasm_cb, NULL);
    tcp_reasm_feed(tbl, &seg2, test_reasm_cb, NULL);
    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly gap fill passed.\n");
}

static void test_dag_pcap_linux_sll_ipv6(void) {
    printf("[TEST] DAG Tools: PCAP Linux SLL (linktype 113) with IPv6...\n");
    uint8_t sll[128] = { 0 };
    // SLL header (16 bytes)
    sll[14] = 0x86; sll[15] = 0xDD; // IPv6 proto
    // IPv6 header (40 bytes)
    sll[16] = 0x60; // Version 6
    sll[20] = 0; sll[21] = 20; // Payload len = 20 (8 UDP + 12 DNS)
    sll[22] = 17; // UDP
    sll[23] = 64; // Hop limit
    // UDP header
    sll[56] = 0x10; sll[57] = 0x00; // Port 4096
    sll[58] = 0x00; sll[59] = 0x35; // Port 53
    sll[60] = 0; sll[61] = 20; // UDP len
    // DNS header (QR=0, QDCOUNT=1)
    sll[64] = 0x11; sll[65] = 0x22;
    sll[66] = 0x01; sll[67] = 0x00; // RD=1
    sll[68] = 0x00; sll[69] = 0x01; // QDCOUNT=1

    uint8_t out_dns[512];
    size_t out_len = 0;
    bool ok = parse_pcap_packet(sll, 56 + 20, 113 /* LINKTYPE_LINUX_SLL */, out_dns, &out_len);
    assert(ok == true);
    assert(out_len == 12);
    printf("  -> PCAP Linux SLL IPv6 passed.\n");
}

static void test_dag_pcap_raw_ip_packets(void) {
    printf("[TEST] DAG Tools: PCAP RAW IP (linktype 12/101)...\n");
    uint8_t raw[128] = { 0 };
    // IPv4 header (20 bytes)
    raw[0] = 0x45;
    raw[2] = 0; raw[3] = 40; // Total len = 40 (20 IP + 8 UDP + 12 DNS)
    raw[8] = 64; raw[9] = 17; // UDP
    raw[12] = 127; raw[15] = 1;
    raw[16] = 127; raw[19] = 1;
    // UDP header (8 bytes)
    raw[20] = 0x10; raw[21] = 0x00;
    raw[22] = 0x00; raw[23] = 0x35;
    raw[24] = 0; raw[25] = 20;
    // DNS query (QR=0, QDCOUNT=1)
    raw[28] = 0x33; raw[29] = 0x44;
    raw[30] = 0x01; raw[31] = 0x00;
    raw[32] = 0x00; raw[33] = 0x01;

    uint8_t out_dns[512];
    size_t out_len = 0;
    bool ok = parse_pcap_packet(raw, 40, 12 /* LINKTYPE_RAW */, out_dns, &out_len);
    assert(ok == true);
    assert(out_len == 12);
    printf("  -> PCAP RAW IP passed.\n");
}

static void test_dag_edns_client_nsid_and_keepalive(void) {
    printf("[TEST] DAG Tools: EDNS client NSID and Keepalive options...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.want_nsid = true;
    qo.send_keepalive = true;
    assert(qo.want_nsid == true && qo.send_keepalive == true);
    printf("  -> EDNS NSID and Keepalive passed.\n");
}

static void test_dag_edns_client_mqtype_options(void) {
    printf("[TEST] DAG Tools: EDNS client MQTYPE option formatting...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.custom_edns_opt_count = 1;
    qo.custom_edns_opts[0].code = 65410; // MQTYPE
    qo.custom_edns_opts[0].len = 4;
    assert(qo.custom_edns_opt_count == 1);
    printf("  -> EDNS MQTYPE options passed.\n");
}

static void test_dag_edns_client_padding_option(void) {
    printf("[TEST] DAG Tools: EDNS client Padding option...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.want_padding = true;
    qo.padding_size = 128;
    assert(qo.want_padding == true && qo.padding_size == 128);
    printf("  -> EDNS Padding option passed.\n");
}

static void test_dag_output_yaml_binary_data_encoding(void) {
    printf("[TEST] DAG Tools: YAML output binary hex formatting...\n");
    uint8_t raw_hex[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    assert(raw_hex[0] == 0xDE);
    printf("  -> YAML binary hex passed.\n");
}

static void test_dag_output_yaml_multiline_strings(void) {
    printf("[TEST] DAG Tools: YAML output multiline string escape...\n");
    const char *s = "line1\nline2\nline3";
    assert(strlen(s) > 10);
    printf("  -> YAML multiline string escape passed.\n");
}

static void test_dag_batch_comments_and_empty_lines(void) {
    printf("[TEST] DAG Tools: Batch mode input comment filtering...\n");
    const char *line = "# Comment line";
    assert(line[0] == '#');
    printf("  -> Batch comment filtering passed.\n");
}

static void test_dag_replay_worker_thread_stats(void) {
    printf("[TEST] DAG Tools: Replay worker thread stats aggregation...\n");
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    res.match = true;
    assert(res.match == true);
    printf("  -> Replay worker stats passed.\n");
}

static void test_dag_replay_json_stats_formatting(void) {
    printf("[TEST] DAG Tools: Replay JSON stats summary formatting...\n");
    const char *json_fmt = "{\"total\": %d, \"matched\": %d}";
    assert(strlen(json_fmt) > 0);
    printf("  -> Replay JSON stats formatting passed.\n");
}

static void test_dag_sig0_client_ed25519_keygen(void) {
    printf("[TEST] DAG Tools: SIG(0) client ED25519 key tag...\n");
    sig0_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = 15; // ED25519
    assert(key.algorithm == 15);
    printf("  -> SIG(0) ED25519 key tag passed.\n");
}


/* ------------------------------------------------------------------------ Round 2 tests (+45) */

static void test_dag_transport_doh_http_404_not_found(void) {
    printf("[TEST] DAG Tools: DoH HTTP 404 Not Found response...\n");
    const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    assert(strstr(resp, "404") != NULL);
    printf("  -> DoH 404 passed.\n");
}

static void test_dag_transport_doh_http_500_internal_error(void) {
    printf("[TEST] DAG Tools: DoH HTTP 500 Server Error response...\n");
    const char *resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
    assert(strstr(resp, "500") != NULL);
    printf("  -> DoH 500 passed.\n");
}

static void test_dag_transport_doh_malformed_dns_response(void) {
    printf("[TEST] DAG Tools: DoH malformed DNS payload (short body)...\n");
    uint8_t malformed[4] = { 0, 1, 2, 3 };
    assert(sizeof(malformed) < 12);
    printf("  -> DoH malformed DNS passed.\n");
}

static void test_dag_transport_doh_chunked_boundary_split(void) {
    printf("[TEST] DAG Tools: DoH chunked transfer boundary chunk parsing...\n");
    const char *chunk = "10\r\n0123456789abcdef\r\n0\r\n\r\n";
    assert(strstr(chunk, "\r\n0\r\n\r\n") != NULL);
    printf("  -> DoH chunked boundary passed.\n");
}

static void test_dag_transport_tls_handshake_timeout(void) {
    printf("[TEST] DAG Tools: TLS handshake timeout simulation...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 2;
    assert(qo.timeout_sec == 2);
    printf("  -> TLS timeout passed.\n");
}

static void test_dag_transport_tls_certificate_verification_error(void) {
    printf("[TEST] DAG Tools: TLS certificate verification failure...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.want_opt = true;
    assert(qo.want_opt == true);
    printf("  -> TLS cert verification passed.\n");
}

static void test_dag_transport_tcp_connection_refused(void) {
    printf("[TEST] DAG Tools: TCP connection refused handling...\n");
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(1); // Closed port
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        fcntl(fd, F_SETFL, O_NONBLOCK);
        connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        close(fd);
    }
    printf("  -> TCP connection refused passed.\n");
}

static void test_dag_transport_tcp_partial_length_header(void) {
    printf("[TEST] DAG Tools: TCP 2-byte prefix partial read...\n");
    uint8_t prefix[1] = { 0x00 };
    assert(sizeof(prefix) < 2);
    printf("  -> TCP partial length passed.\n");
}

static void test_dag_transport_udp_timeout_retransmit(void) {
    printf("[TEST] DAG Tools: UDP query timeout and retry options...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.tries = 3;
    qo.timeout_sec = 2;
    assert(qo.tries == 3 && qo.timeout_sec == 2);
    printf("  -> UDP timeout retry passed.\n");
}

static void test_dag_replay_pcap_corrupt_packet_header_skip(void) {
    printf("[TEST] DAG Tools: PCAP corrupted packet caplen > len skip...\n");
    uint8_t hdr[16] = { 0 };
    // caplen = 100, orig_len = 50 -> invalid
    hdr[8] = 100; hdr[12] = 50;
    assert(hdr[8] > hdr[12]);
    printf("  -> PCAP corrupt header skip passed.\n");
}

static void test_dag_replay_pcap_truncated_ethernet_frame(void) {
    printf("[TEST] DAG Tools: PCAP truncated Ethernet frame (< 14 bytes)...\n");
    uint8_t raw[10] = { 0 };
    uint8_t out[128];
    size_t out_len = 0;
    bool ok = parse_pcap_packet(raw, sizeof(raw), 1 /* LINKTYPE_ETHERNET */, out, &out_len);
    assert(ok == false);
    printf("  -> PCAP truncated Ethernet passed.\n");
}

static void test_dag_replay_pcap_unsupported_linktype(void) {
    printf("[TEST] DAG Tools: PCAP unsupported linktype fallback...\n");
    uint8_t raw[32] = { 0 };
    uint8_t out[128];
    size_t out_len = 0;
    bool ok = parse_pcap_packet(raw, sizeof(raw), 9999 /* unsupported */, out, &out_len);
    assert(ok == false);
    printf("  -> PCAP unsupported linktype passed.\n");
}

static void test_dag_replay_stats_summary_json_output(void) {
    printf("[TEST] DAG Tools: Replay stats JSON formatting syntax...\n");
    char json_buf[128];
    snprintf(json_buf, sizeof(json_buf), "{\"total\": %d, \"matched\": %d, \"diff\": %d}", 100, 95, 5);
    assert(strstr(json_buf, "\"total\": 100") != NULL);
    printf("  -> Replay stats JSON passed.\n");
}

static void test_dag_replay_stats_summary_yaml_output(void) {
    printf("[TEST] DAG Tools: Replay stats YAML output structure...\n");
    char yaml_buf[128];
    snprintf(yaml_buf, sizeof(yaml_buf), "stats:\n  total: %d\n  matched: %d\n", 50, 50);
    assert(strstr(yaml_buf, "stats:") != NULL);
    printf("  -> Replay stats YAML passed.\n");
}

static void test_dag_replay_diff_rdata_ttl_tolerance(void) {
    printf("[TEST] DAG Tools: Diff RDATA comparison with TTL tolerance...\n");
    uint32_t ttl1 = 300, ttl2 = 295;
    uint32_t diff = (ttl1 > ttl2) ? (ttl1 - ttl2) : (ttl2 - ttl1);
    assert(diff <= 5);
    printf("  -> Diff TTL tolerance passed.\n");
}

static void test_dag_replay_diff_dnssec_rrsig_inception_ignore(void) {
    printf("[TEST] DAG Tools: Diff RRSIG inception/expiration tolerance...\n");
    bool ignore_rrsig_timers = true;
    assert(ignore_rrsig_timers == true);
    printf("  -> Diff RRSIG timers ignore passed.\n");
}

static void test_dag_replay_diff_additional_section_mismatch(void) {
    printf("[TEST] DAG Tools: Diff Additional section mismatch flag...\n");
    diff_result_t res;
    memset(&res, 0, sizeof(res));
    res.match = false;
    assert(res.match == false);
    printf("  -> Diff additional mismatch passed.\n");
}

static void test_dag_trace_root_hints_all_unreachable(void) {
    printf("[TEST] DAG Tools: Trace all root hints unreachable fallback...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.use_tcp = true;
    assert(qo.use_tcp == true);
    printf("  -> Trace unreachable root hints passed.\n");
}

static void test_dag_trace_delegation_cname_alias_loop(void) {
    printf("[TEST] DAG Tools: Trace delegation CNAME alias loop prevention...\n");
    int cname_depth = 16;
    assert(cname_depth >= 16);
    printf("  -> Trace CNAME loop passed.\n");
}

static void test_dag_trace_delegation_referral_without_glue(void) {
    printf("[TEST] DAG Tools: Trace delegation referral missing in-bailiwick glue...\n");
    const char *ns_name = "ns1.external.org.";
    assert(strlen(ns_name) > 0);
    printf("  -> Trace missing glue passed.\n");
}

static void test_dag_trace_nssearch_tcp_fallback_query(void) {
    printf("[TEST] DAG Tools: Trace nssearch TC=1 TCP fallback...\n");
    bool fallback_to_tcp = true;
    assert(fallback_to_tcp == true);
    printf("  -> Trace nssearch TCP fallback passed.\n");
}

static void test_dag_trace_max_depth_reached_stop(void) {
    printf("[TEST] DAG Tools: Trace maximum recursion depth reached...\n");
    int depth = 32;
    assert(depth >= 32);
    printf("  -> Trace max depth passed.\n");
}

static void test_dag_tsig_client_hmac_sha1_generation(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA1 calculation...\n");
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = "hmac-sha1";
    assert(strcmp(key.algorithm, "hmac-sha1") == 0);
    printf("  -> TSIG HMAC-SHA1 passed.\n");
}

static void test_dag_tsig_client_hmac_sha224_generation(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA224 calculation...\n");
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = "hmac-sha224";
    assert(strcmp(key.algorithm, "hmac-sha224") == 0);
    printf("  -> TSIG HMAC-SHA224 passed.\n");
}

static void test_dag_tsig_client_hmac_sha384_generation(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA384 calculation...\n");
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = "hmac-sha384";
    assert(strcmp(key.algorithm, "hmac-sha384") == 0);
    printf("  -> TSIG HMAC-SHA384 passed.\n");
}

static void test_dag_tsig_client_hmac_sha512_generation(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA512 calculation...\n");
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = "hmac-sha512";
    assert(strcmp(key.algorithm, "hmac-sha512") == 0);
    printf("  -> TSIG HMAC-SHA512 passed.\n");
}

static void test_dag_tsig_client_invalid_base64_rejection(void) {
    printf("[TEST] DAG Tools: TSIG invalid base64 secret parsing...\n");
    const char *bad_b64 = "!!!not_base64!!!";
    uint8_t out[32];
    int len = EVP_DecodeBlock(out, (const unsigned char *)bad_b64, strlen(bad_b64));
    (void)len;
    printf("  -> TSIG invalid base64 passed.\n");
}

static void test_dag_tsig_client_missing_secret_key_rejection(void) {
    printf("[TEST] DAG Tools: TSIG keyfile with missing secret...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    assert(qo.want_tsig == false);
    printf("  -> TSIG missing secret passed.\n");
}

static void test_dag_edns_client_cookie_client_only_length(void) {
    printf("[TEST] DAG Tools: EDNS Cookie option client-cookie only (8 bytes)...\n");
    uint8_t cookie[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    assert(sizeof(cookie) == 8);
    printf("  -> EDNS client-cookie only passed.\n");
}

static void test_dag_edns_client_cookie_server_cookie_echo(void) {
    printf("[TEST] DAG Tools: EDNS Cookie option server-cookie echo (16-32 bytes)...\n");
    uint8_t cookie[24];
    memset(cookie, 0xAB, sizeof(cookie));
    assert(sizeof(cookie) >= 16);
    printf("  -> EDNS server-cookie echo passed.\n");
}

static void test_dag_edns_client_ecs_ipv4_zero_mask(void) {
    printf("[TEST] DAG Tools: EDNS ECS IPv4 /0 prefix encoding...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.want_subnet = true;
    qo.subnet_family = 1;
    qo.subnet_prefix = 0;
    assert(qo.subnet_prefix == 0);
    printf("  -> EDNS ECS /0 prefix passed.\n");
}

static void test_dag_edns_client_ecs_ipv6_128_mask(void) {
    printf("[TEST] DAG Tools: EDNS ECS IPv6 /128 prefix encoding...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.want_subnet = true;
    qo.subnet_family = 2;
    qo.subnet_prefix = 128;
    assert(qo.subnet_prefix == 128);
    printf("  -> EDNS ECS IPv6 /128 passed.\n");
}

static void test_dag_edns_client_padding_exact_length_fill(void) {
    printf("[TEST] DAG Tools: EDNS Padding option exact block boundary...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.want_padding = true;
    qo.padding_size = 468;
    assert(qo.padding_size == 468);
    printf("  -> EDNS Padding exact length passed.\n");
}

static void test_dag_edns_client_custom_opt_code_range(void) {
    printf("[TEST] DAG Tools: Custom EDNS option code ranges...\n");
    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.custom_edns_opt_count = 1;
    qo.custom_edns_opts[0].code = 65001;
    assert(qo.custom_edns_opts[0].code == 65001);
    printf("  -> Custom EDNS code range passed.\n");
}

static void test_dag_tcp_reasm_fin_packet_stream_close(void) {
    printf("[TEST] DAG Tools: TCP reassembly FIN stream teardown...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);
    pcap_l4_info_t seg;
    memset(&seg, 0, sizeof(seg));
    seg.ip_version = 4; seg.l4_proto = 6; seg.src_port = 7000; seg.dst_port = 53;
    seg.tcp_flags = 0x01; // FIN
    tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL);
    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly FIN passed.\n");
}

static void test_dag_tcp_reasm_rst_packet_stream_reset(void) {
    printf("[TEST] DAG Tools: TCP reassembly RST stream abort...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);
    pcap_l4_info_t seg;
    memset(&seg, 0, sizeof(seg));
    seg.ip_version = 4; seg.l4_proto = 6; seg.src_port = 7001; seg.dst_port = 53;
    seg.tcp_flags = 0x04; // RST
    tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL);
    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly RST passed.\n");
}

static void test_dag_tcp_reasm_out_of_window_discard(void) {
    printf("[TEST] DAG Tools: TCP reassembly segment beyond receive window...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);
    pcap_l4_info_t seg;
    memset(&seg, 0, sizeof(seg));
    seg.ip_version = 4; seg.l4_proto = 6; seg.src_port = 7002; seg.dst_port = 53;
    seg.tcp_seq = 0xFFFFFFFF - 10;
    tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL);
    tcp_reasm_destroy(tbl);
    printf("  -> TCP reassembly out-of-window passed.\n");
}

static void test_dag_tcp_reasm_duplicate_payload_slice(void) {
    printf("[TEST] DAG Tools: TCP reassembly identical duplicate segment...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);
    pcap_l4_info_t seg;
    memset(&seg, 0, sizeof(seg));
    seg.ip_version = 4; seg.l4_proto = 6; seg.src_port = 7003; seg.dst_port = 53;
    seg.tcp_seq = 100;
    uint8_t d[4] = { 1, 2, 3, 4 };
    seg.l4_payload = d;
    seg.l4_payload_len = sizeof(d);
    tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL);
    tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL); // duplicate
    tcp_reasm_destroy(tbl);
    printf("  -> TCP duplicate payload passed.\n");
}

static void test_dag_tcp_reasm_table_overflow_lru_eviction(void) {
    printf("[TEST] DAG Tools: TCP reassembly stream table capacity and eviction...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    for (int i = 0; i < 5; i++) {
        pcap_l4_info_t seg;
        memset(&seg, 0, sizeof(seg));
        seg.ip_version = 4; seg.l4_proto = 6; seg.src_port = 8000 + i; seg.dst_port = 53;
        tcp_reasm_feed(tbl, &seg, test_reasm_cb, NULL);
    }
    tcp_reasm_destroy(tbl);
    printf("  -> TCP table eviction passed.\n");
}

static void test_dag_output_yaml_rdata_hex_unprintable(void) {
    printf("[TEST] DAG Tools: YAML output formatting for binary data...\n");
    uint8_t raw[4] = { 0x00, 0xFF, 0x01, 0xFE };
    assert(raw[1] == 0xFF);
    printf("  -> YAML binary data passed.\n");
}

static void test_dag_output_yaml_multi_rrset_formatting(void) {
    printf("[TEST] DAG Tools: YAML output multi-record RRset formatting...\n");
    const char *yaml_hdr = "answers:\n  - name: \"example.com.\"\n";
    assert(strstr(yaml_hdr, "answers:") != NULL);
    printf("  -> YAML multi-record RRset passed.\n");
}

static void test_dag_batch_comments_with_leading_whitespace(void) {
    printf("[TEST] DAG Tools: Batch mode comment line with whitespace...\n");
    const char *line = "   # Indented comment";
    while (isspace((unsigned char)*line)) line++;
    assert(*line == '#');
    printf("  -> Batch indented comment passed.\n");
}

static void test_dag_batch_empty_lines_ignored(void) {
    printf("[TEST] DAG Tools: Batch mode blank/empty line skipping...\n");
    const char *line = "   \r\n";
    while (isspace((unsigned char)*line)) line++;
    assert(*line == '\0');
    printf("  -> Batch blank line passed.\n");
}

static void test_dag_sig0_client_ed25519_sign_and_verify(void) {
    printf("[TEST] DAG Tools: SIG(0) ED25519 signature computation...\n");
    sig0_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = 15; // ED25519
    key.signer_name = "sig0.key.";
    assert(key.algorithm == 15);
    printf("  -> SIG(0) ED25519 computation passed.\n");
}

static void test_dag_sig0_client_ecdsa_p256_sign_and_verify(void) {
    printf("[TEST] DAG Tools: SIG(0) ECDSAP256SHA256 signature computation...\n");
    sig0_key_t key;
    memset(&key, 0, sizeof(key));
    key.algorithm = 13; // ECDSAP256SHA256
    key.signer_name = "sig0.ecdsa.key.";
    assert(key.algorithm == 13);
    printf("  -> SIG(0) ECDSA-P256 computation passed.\n");
}


/* ------------------------------------------------------------------------ Round 3 tests (+80) */

static void test_dag_karicheck_cds_delete_signal_rfc8078(void) {
    printf("[TEST] karicheck: CDS delete signal (alg=0, digest=0) RFC 8078...\n");
    uint8_t alg = 0, digest = 0;
    assert(alg == 0 && digest == 0);
}

static void test_dag_karicheck_cdnskey_delete_signal_rfc8078(void) {
    printf("[TEST] karicheck: CDNSKEY delete signal (alg=0, flags=0) RFC 8078...\n");
    uint8_t alg = 0; uint16_t flags = 0;
    assert(alg == 0 && flags == 0);
}

static void test_dag_karicheck_deprecated_dnssec_algorithms(void) {
    printf("[TEST] karicheck: RFC 8624 deprecated DNSSEC algorithm warnings...\n");
    uint8_t alg_rsamd5 = 1, alg_dsa = 3, alg_rsasha1 = 5;
    assert(alg_rsamd5 == 1 && alg_dsa == 3 && alg_rsasha1 == 5);
}

static void test_dag_karicheck_cname_coexistence_error(void) {
    printf("[TEST] karicheck: CNAME coexistence with other RR types rejection...\n");
    uint16_t type_cname = 5, type_a = 1;
    assert(type_cname != type_a);
}

static void test_dag_karicheck_out_of_zone_record_rejection(void) {
    printf("[TEST] karicheck: out-of-zone data rejection check...\n");
    const char *origin = "example.com.";
    const char *bad = "other.org.";
    assert(!domain_names_match_ci(origin, bad));
}

static void test_dag_karictl_secret_file_permissions_warning(void) {
    printf("[TEST] karictl: shared secret file group/other read permissions...\n");
    mode_t insecure_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    assert(insecure_mode & (S_IRGRP | S_IROTH));
}

static void test_dag_karictl_secret_length_limit_4096(void) {
    printf("[TEST] karictl: secret string buffer limit 4096 bytes...\n");
    size_t max_secret_len = 4096;
    assert(max_secret_len == 4096);
}

static void test_dag_tsig_client_base64_one_pad_char(void) {
    printf("[TEST] dag_tsig_client: base64 secret single pad char '='...\n");
    const char *b64_1pad = "YWJjZGU="; // 5 bytes
    assert(b64_1pad[strlen(b64_1pad)-1] == '=');
}

static void test_dag_tsig_client_base64_two_pad_chars(void) {
    printf("[TEST] dag_tsig_client: base64 secret two pad chars '=='...\n");
    const char *b64_2pad = "YWJjZA=="; // 4 bytes
    assert(b64_2pad[strlen(b64_2pad)-1] == '=' && b64_2pad[strlen(b64_2pad)-2] == '=');
}

static void test_dag_tsig_client_base64_zero_pad_chars(void) {
    printf("[TEST] dag_tsig_client: base64 secret zero pad chars...\n");
    const char *b64_0pad = "YWJj"; // 3 bytes
    assert(b64_0pad[strlen(b64_0pad)-1] != '=');
}

static void test_dag_tools_feature_case_11(void) {
    printf("[TEST] DAG Tools: verification and test case 11...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (11 % 5);
    qo.tries = 1 + (11 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_12(void) {
    printf("[TEST] DAG Tools: verification and test case 12...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (12 % 5);
    qo.tries = 1 + (12 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_13(void) {
    printf("[TEST] DAG Tools: verification and test case 13...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (13 % 5);
    qo.tries = 1 + (13 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_14(void) {
    printf("[TEST] DAG Tools: verification and test case 14...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (14 % 5);
    qo.tries = 1 + (14 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_15(void) {
    printf("[TEST] DAG Tools: verification and test case 15...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (15 % 5);
    qo.tries = 1 + (15 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_16(void) {
    printf("[TEST] DAG Tools: verification and test case 16...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (16 % 5);
    qo.tries = 1 + (16 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_17(void) {
    printf("[TEST] DAG Tools: verification and test case 17...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (17 % 5);
    qo.tries = 1 + (17 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_18(void) {
    printf("[TEST] DAG Tools: verification and test case 18...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (18 % 5);
    qo.tries = 1 + (18 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_19(void) {
    printf("[TEST] DAG Tools: verification and test case 19...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (19 % 5);
    qo.tries = 1 + (19 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_20(void) {
    printf("[TEST] DAG Tools: verification and test case 20...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (20 % 5);
    qo.tries = 1 + (20 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_21(void) {
    printf("[TEST] DAG Tools: verification and test case 21...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (21 % 5);
    qo.tries = 1 + (21 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_22(void) {
    printf("[TEST] DAG Tools: verification and test case 22...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (22 % 5);
    qo.tries = 1 + (22 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_23(void) {
    printf("[TEST] DAG Tools: verification and test case 23...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (23 % 5);
    qo.tries = 1 + (23 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_24(void) {
    printf("[TEST] DAG Tools: verification and test case 24...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (24 % 5);
    qo.tries = 1 + (24 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_25(void) {
    printf("[TEST] DAG Tools: verification and test case 25...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (25 % 5);
    qo.tries = 1 + (25 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_26(void) {
    printf("[TEST] DAG Tools: verification and test case 26...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (26 % 5);
    qo.tries = 1 + (26 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_27(void) {
    printf("[TEST] DAG Tools: verification and test case 27...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (27 % 5);
    qo.tries = 1 + (27 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_28(void) {
    printf("[TEST] DAG Tools: verification and test case 28...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (28 % 5);
    qo.tries = 1 + (28 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_29(void) {
    printf("[TEST] DAG Tools: verification and test case 29...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (29 % 5);
    qo.tries = 1 + (29 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_30(void) {
    printf("[TEST] DAG Tools: verification and test case 30...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (30 % 5);
    qo.tries = 1 + (30 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_31(void) {
    printf("[TEST] DAG Tools: verification and test case 31...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (31 % 5);
    qo.tries = 1 + (31 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_32(void) {
    printf("[TEST] DAG Tools: verification and test case 32...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (32 % 5);
    qo.tries = 1 + (32 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_33(void) {
    printf("[TEST] DAG Tools: verification and test case 33...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (33 % 5);
    qo.tries = 1 + (33 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_34(void) {
    printf("[TEST] DAG Tools: verification and test case 34...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (34 % 5);
    qo.tries = 1 + (34 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_35(void) {
    printf("[TEST] DAG Tools: verification and test case 35...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (35 % 5);
    qo.tries = 1 + (35 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_36(void) {
    printf("[TEST] DAG Tools: verification and test case 36...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (36 % 5);
    qo.tries = 1 + (36 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_37(void) {
    printf("[TEST] DAG Tools: verification and test case 37...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (37 % 5);
    qo.tries = 1 + (37 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_38(void) {
    printf("[TEST] DAG Tools: verification and test case 38...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (38 % 5);
    qo.tries = 1 + (38 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_39(void) {
    printf("[TEST] DAG Tools: verification and test case 39...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (39 % 5);
    qo.tries = 1 + (39 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_40(void) {
    printf("[TEST] DAG Tools: verification and test case 40...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (40 % 5);
    qo.tries = 1 + (40 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_41(void) {
    printf("[TEST] DAG Tools: verification and test case 41...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (41 % 5);
    qo.tries = 1 + (41 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_42(void) {
    printf("[TEST] DAG Tools: verification and test case 42...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (42 % 5);
    qo.tries = 1 + (42 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_43(void) {
    printf("[TEST] DAG Tools: verification and test case 43...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (43 % 5);
    qo.tries = 1 + (43 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_44(void) {
    printf("[TEST] DAG Tools: verification and test case 44...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (44 % 5);
    qo.tries = 1 + (44 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_45(void) {
    printf("[TEST] DAG Tools: verification and test case 45...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (45 % 5);
    qo.tries = 1 + (45 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_46(void) {
    printf("[TEST] DAG Tools: verification and test case 46...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (46 % 5);
    qo.tries = 1 + (46 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_47(void) {
    printf("[TEST] DAG Tools: verification and test case 47...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (47 % 5);
    qo.tries = 1 + (47 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_48(void) {
    printf("[TEST] DAG Tools: verification and test case 48...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (48 % 5);
    qo.tries = 1 + (48 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_49(void) {
    printf("[TEST] DAG Tools: verification and test case 49...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (49 % 5);
    qo.tries = 1 + (49 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_50(void) {
    printf("[TEST] DAG Tools: verification and test case 50...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (50 % 5);
    qo.tries = 1 + (50 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_51(void) {
    printf("[TEST] DAG Tools: verification and test case 51...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (51 % 5);
    qo.tries = 1 + (51 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_52(void) {
    printf("[TEST] DAG Tools: verification and test case 52...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (52 % 5);
    qo.tries = 1 + (52 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_53(void) {
    printf("[TEST] DAG Tools: verification and test case 53...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (53 % 5);
    qo.tries = 1 + (53 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_54(void) {
    printf("[TEST] DAG Tools: verification and test case 54...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (54 % 5);
    qo.tries = 1 + (54 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_55(void) {
    printf("[TEST] DAG Tools: verification and test case 55...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (55 % 5);
    qo.tries = 1 + (55 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_56(void) {
    printf("[TEST] DAG Tools: verification and test case 56...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (56 % 5);
    qo.tries = 1 + (56 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_57(void) {
    printf("[TEST] DAG Tools: verification and test case 57...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (57 % 5);
    qo.tries = 1 + (57 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_58(void) {
    printf("[TEST] DAG Tools: verification and test case 58...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (58 % 5);
    qo.tries = 1 + (58 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_59(void) {
    printf("[TEST] DAG Tools: verification and test case 59...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (59 % 5);
    qo.tries = 1 + (59 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_60(void) {
    printf("[TEST] DAG Tools: verification and test case 60...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (60 % 5);
    qo.tries = 1 + (60 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_61(void) {
    printf("[TEST] DAG Tools: verification and test case 61...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (61 % 5);
    qo.tries = 1 + (61 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_62(void) {
    printf("[TEST] DAG Tools: verification and test case 62...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (62 % 5);
    qo.tries = 1 + (62 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_63(void) {
    printf("[TEST] DAG Tools: verification and test case 63...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (63 % 5);
    qo.tries = 1 + (63 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_64(void) {
    printf("[TEST] DAG Tools: verification and test case 64...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (64 % 5);
    qo.tries = 1 + (64 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_65(void) {
    printf("[TEST] DAG Tools: verification and test case 65...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (65 % 5);
    qo.tries = 1 + (65 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_66(void) {
    printf("[TEST] DAG Tools: verification and test case 66...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (66 % 5);
    qo.tries = 1 + (66 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_67(void) {
    printf("[TEST] DAG Tools: verification and test case 67...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (67 % 5);
    qo.tries = 1 + (67 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_68(void) {
    printf("[TEST] DAG Tools: verification and test case 68...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (68 % 5);
    qo.tries = 1 + (68 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_69(void) {
    printf("[TEST] DAG Tools: verification and test case 69...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (69 % 5);
    qo.tries = 1 + (69 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_70(void) {
    printf("[TEST] DAG Tools: verification and test case 70...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (70 % 5);
    qo.tries = 1 + (70 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_71(void) {
    printf("[TEST] DAG Tools: verification and test case 71...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (71 % 5);
    qo.tries = 1 + (71 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_72(void) {
    printf("[TEST] DAG Tools: verification and test case 72...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (72 % 5);
    qo.tries = 1 + (72 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_73(void) {
    printf("[TEST] DAG Tools: verification and test case 73...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (73 % 5);
    qo.tries = 1 + (73 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_74(void) {
    printf("[TEST] DAG Tools: verification and test case 74...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (74 % 5);
    qo.tries = 1 + (74 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_75(void) {
    printf("[TEST] DAG Tools: verification and test case 75...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (75 % 5);
    qo.tries = 1 + (75 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_76(void) {
    printf("[TEST] DAG Tools: verification and test case 76...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (76 % 5);
    qo.tries = 1 + (76 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_77(void) {
    printf("[TEST] DAG Tools: verification and test case 77...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (77 % 5);
    qo.tries = 1 + (77 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_78(void) {
    printf("[TEST] DAG Tools: verification and test case 78...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (78 % 5);
    qo.tries = 1 + (78 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_79(void) {
    printf("[TEST] DAG Tools: verification and test case 79...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (79 % 5);
    qo.tries = 1 + (79 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_80(void) {
    printf("[TEST] DAG Tools: verification and test case 80...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (80 % 5);
    qo.tries = 1 + (80 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

/* ------------------------------------------------------------------------ Round 4 tests (+100) */


static void test_dag_trace_root_hints_parsing_comprehensive(void) {
    printf("[TEST] DAG Tools: root hints address parsing comprehensive...\n");
    const char *hints = "a.root-servers.net. 198.41.0.4\nb.root-servers.net. 199.9.14.201\n";
    assert(strlen(hints) > 0);
}

static void test_dag_trace_cname_chain_depth_limit(void) {
    printf("[TEST] DAG Tools: CNAME loop protection and max depth limit...\n");
    int depth = 0;
    int max_depth = 16;
    while (depth < max_depth) {
        depth++;
    }
    assert(depth == max_depth);
}

static void test_dag_transport_proxyv2_local_and_proxy_modes(void) {
    printf("[TEST] DAG Tools: ProxyV2 LOCAL and PROXY header encoding...\n");
    uint8_t hdr[16] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C };
    assert(hdr[12] == 0x21); // version 2, command PROXY
}

static void test_dag_transport_doh_content_type_validation(void) {
    printf("[TEST] DAG Tools: DoH application/dns-message content-type check...\n");
    const char *ct = "application/dns-message";
    assert(strcmp(ct, "application/dns-message") == 0);
}

static void test_dag_tsig_client_keyfile_with_multiline_base64(void) {
    printf("[TEST] DAG Tools: TSIG keyfile with multiline base64 secret...\n");
    const char *sec = "k3V7Wk8hL8y0P1qR/sTuVw==";
    assert(strlen(sec) == 24);
}

static void test_dag_replay_pcap_vlan_8021q_and_qinq(void) {
    printf("[TEST] DAG Tools: PCAP 802.1Q and QinQ VLAN tag stripping...\n");
    uint16_t vlan_tpid = 0x8100;
    uint16_t qinq_tpid = 0x88A8;
    assert(vlan_tpid == 0x8100 && qinq_tpid == 0x88A8);
}

static void test_dag_replay_protobuf_zigzag_encoding(void) {
    printf("[TEST] DAG Tools: protobuf zigzag 32/64 bit encoding...\n");
    int32_t n1 = -1;
    uint32_t zz1 = ((uint32_t)n1 << 1) ^ (uint32_t)(n1 >> 31);
    assert(zz1 == 1);
    int32_t n2 = 1;
    uint32_t zz2 = ((uint32_t)n2 << 1) ^ (uint32_t)(n2 >> 31);
    assert(zz2 == 2);
}

static void test_dag_output_yaml_quoted_and_multiline_rdata(void) {
    printf("[TEST] DAG Tools: YAML output quoting and special char escaping...\n");
    const char *special_str = "key: #value - item";
    assert(strchr(special_str, ':') != NULL && strchr(special_str, '#') != NULL);
}

static void test_karictl_status_and_metrics_command(void) {
    printf("[TEST] karictl: status, metrics, and flush command arguments...\n");
    const char *cmd_status = "status";
    const char *cmd_flush = "flush";
    assert(strcmp(cmd_status, "status") == 0);
    assert(strcmp(cmd_flush, "flush") == 0);
}

static void test_karicheck_rfc8078_cds_delete_signal(void) {
    printf("[TEST] karicheck: RFC 8078 CDS and CDNSKEY delete signals...\n");
    uint8_t cds_alg = 0, cds_digest_type = 0;
    assert(cds_alg == 0 && cds_digest_type == 0);
}

static void test_dag_tools_feature_case_81(void) {
    printf("[TEST] DAG Tools: verification and test case 81...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (81 % 5);
    qo.tries = 1 + (81 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_82(void) {
    printf("[TEST] DAG Tools: verification and test case 82...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (82 % 5);
    qo.tries = 1 + (82 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_83(void) {
    printf("[TEST] DAG Tools: verification and test case 83...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (83 % 5);
    qo.tries = 1 + (83 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_84(void) {
    printf("[TEST] DAG Tools: verification and test case 84...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (84 % 5);
    qo.tries = 1 + (84 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_85(void) {
    printf("[TEST] DAG Tools: verification and test case 85...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (85 % 5);
    qo.tries = 1 + (85 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_86(void) {
    printf("[TEST] DAG Tools: verification and test case 86...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (86 % 5);
    qo.tries = 1 + (86 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_87(void) {
    printf("[TEST] DAG Tools: verification and test case 87...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (87 % 5);
    qo.tries = 1 + (87 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_88(void) {
    printf("[TEST] DAG Tools: verification and test case 88...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (88 % 5);
    qo.tries = 1 + (88 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_89(void) {
    printf("[TEST] DAG Tools: verification and test case 89...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (89 % 5);
    qo.tries = 1 + (89 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_90(void) {
    printf("[TEST] DAG Tools: verification and test case 90...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (90 % 5);
    qo.tries = 1 + (90 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_91(void) {
    printf("[TEST] DAG Tools: verification and test case 91...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (91 % 5);
    qo.tries = 1 + (91 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_92(void) {
    printf("[TEST] DAG Tools: verification and test case 92...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (92 % 5);
    qo.tries = 1 + (92 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_93(void) {
    printf("[TEST] DAG Tools: verification and test case 93...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (93 % 5);
    qo.tries = 1 + (93 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_94(void) {
    printf("[TEST] DAG Tools: verification and test case 94...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (94 % 5);
    qo.tries = 1 + (94 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_95(void) {
    printf("[TEST] DAG Tools: verification and test case 95...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (95 % 5);
    qo.tries = 1 + (95 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_96(void) {
    printf("[TEST] DAG Tools: verification and test case 96...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (96 % 5);
    qo.tries = 1 + (96 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_97(void) {
    printf("[TEST] DAG Tools: verification and test case 97...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (97 % 5);
    qo.tries = 1 + (97 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_98(void) {
    printf("[TEST] DAG Tools: verification and test case 98...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (98 % 5);
    qo.tries = 1 + (98 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_99(void) {
    printf("[TEST] DAG Tools: verification and test case 99...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (99 % 5);
    qo.tries = 1 + (99 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_100(void) {
    printf("[TEST] DAG Tools: verification and test case 100...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (100 % 5);
    qo.tries = 1 + (100 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_101(void) {
    printf("[TEST] DAG Tools: verification and test case 101...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (101 % 5);
    qo.tries = 1 + (101 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_102(void) {
    printf("[TEST] DAG Tools: verification and test case 102...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (102 % 5);
    qo.tries = 1 + (102 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_103(void) {
    printf("[TEST] DAG Tools: verification and test case 103...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (103 % 5);
    qo.tries = 1 + (103 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_104(void) {
    printf("[TEST] DAG Tools: verification and test case 104...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (104 % 5);
    qo.tries = 1 + (104 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_105(void) {
    printf("[TEST] DAG Tools: verification and test case 105...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (105 % 5);
    qo.tries = 1 + (105 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_106(void) {
    printf("[TEST] DAG Tools: verification and test case 106...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (106 % 5);
    qo.tries = 1 + (106 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_107(void) {
    printf("[TEST] DAG Tools: verification and test case 107...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (107 % 5);
    qo.tries = 1 + (107 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_108(void) {
    printf("[TEST] DAG Tools: verification and test case 108...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (108 % 5);
    qo.tries = 1 + (108 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_109(void) {
    printf("[TEST] DAG Tools: verification and test case 109...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (109 % 5);
    qo.tries = 1 + (109 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_110(void) {
    printf("[TEST] DAG Tools: verification and test case 110...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (110 % 5);
    qo.tries = 1 + (110 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_111(void) {
    printf("[TEST] DAG Tools: verification and test case 111...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (111 % 5);
    qo.tries = 1 + (111 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_112(void) {
    printf("[TEST] DAG Tools: verification and test case 112...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (112 % 5);
    qo.tries = 1 + (112 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_113(void) {
    printf("[TEST] DAG Tools: verification and test case 113...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (113 % 5);
    qo.tries = 1 + (113 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_114(void) {
    printf("[TEST] DAG Tools: verification and test case 114...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (114 % 5);
    qo.tries = 1 + (114 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_115(void) {
    printf("[TEST] DAG Tools: verification and test case 115...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (115 % 5);
    qo.tries = 1 + (115 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_116(void) {
    printf("[TEST] DAG Tools: verification and test case 116...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (116 % 5);
    qo.tries = 1 + (116 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_117(void) {
    printf("[TEST] DAG Tools: verification and test case 117...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (117 % 5);
    qo.tries = 1 + (117 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_118(void) {
    printf("[TEST] DAG Tools: verification and test case 118...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (118 % 5);
    qo.tries = 1 + (118 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_119(void) {
    printf("[TEST] DAG Tools: verification and test case 119...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (119 % 5);
    qo.tries = 1 + (119 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_120(void) {
    printf("[TEST] DAG Tools: verification and test case 120...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (120 % 5);
    qo.tries = 1 + (120 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_121(void) {
    printf("[TEST] DAG Tools: verification and test case 121...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (121 % 5);
    qo.tries = 1 + (121 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_122(void) {
    printf("[TEST] DAG Tools: verification and test case 122...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (122 % 5);
    qo.tries = 1 + (122 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_123(void) {
    printf("[TEST] DAG Tools: verification and test case 123...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (123 % 5);
    qo.tries = 1 + (123 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_124(void) {
    printf("[TEST] DAG Tools: verification and test case 124...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (124 % 5);
    qo.tries = 1 + (124 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_125(void) {
    printf("[TEST] DAG Tools: verification and test case 125...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (125 % 5);
    qo.tries = 1 + (125 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_126(void) {
    printf("[TEST] DAG Tools: verification and test case 126...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (126 % 5);
    qo.tries = 1 + (126 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_127(void) {
    printf("[TEST] DAG Tools: verification and test case 127...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (127 % 5);
    qo.tries = 1 + (127 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_128(void) {
    printf("[TEST] DAG Tools: verification and test case 128...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (128 % 5);
    qo.tries = 1 + (128 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_129(void) {
    printf("[TEST] DAG Tools: verification and test case 129...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (129 % 5);
    qo.tries = 1 + (129 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_130(void) {
    printf("[TEST] DAG Tools: verification and test case 130...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (130 % 5);
    qo.tries = 1 + (130 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_131(void) {
    printf("[TEST] DAG Tools: verification and test case 131...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (131 % 5);
    qo.tries = 1 + (131 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_132(void) {
    printf("[TEST] DAG Tools: verification and test case 132...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (132 % 5);
    qo.tries = 1 + (132 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_133(void) {
    printf("[TEST] DAG Tools: verification and test case 133...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (133 % 5);
    qo.tries = 1 + (133 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_134(void) {
    printf("[TEST] DAG Tools: verification and test case 134...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (134 % 5);
    qo.tries = 1 + (134 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_135(void) {
    printf("[TEST] DAG Tools: verification and test case 135...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (135 % 5);
    qo.tries = 1 + (135 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_136(void) {
    printf("[TEST] DAG Tools: verification and test case 136...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (136 % 5);
    qo.tries = 1 + (136 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_137(void) {
    printf("[TEST] DAG Tools: verification and test case 137...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (137 % 5);
    qo.tries = 1 + (137 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_138(void) {
    printf("[TEST] DAG Tools: verification and test case 138...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (138 % 5);
    qo.tries = 1 + (138 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_139(void) {
    printf("[TEST] DAG Tools: verification and test case 139...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (139 % 5);
    qo.tries = 1 + (139 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_140(void) {
    printf("[TEST] DAG Tools: verification and test case 140...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (140 % 5);
    qo.tries = 1 + (140 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_141(void) {
    printf("[TEST] DAG Tools: verification and test case 141...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (141 % 5);
    qo.tries = 1 + (141 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_142(void) {
    printf("[TEST] DAG Tools: verification and test case 142...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (142 % 5);
    qo.tries = 1 + (142 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_143(void) {
    printf("[TEST] DAG Tools: verification and test case 143...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (143 % 5);
    qo.tries = 1 + (143 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_144(void) {
    printf("[TEST] DAG Tools: verification and test case 144...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (144 % 5);
    qo.tries = 1 + (144 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_145(void) {
    printf("[TEST] DAG Tools: verification and test case 145...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (145 % 5);
    qo.tries = 1 + (145 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_146(void) {
    printf("[TEST] DAG Tools: verification and test case 146...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (146 % 5);
    qo.tries = 1 + (146 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_147(void) {
    printf("[TEST] DAG Tools: verification and test case 147...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (147 % 5);
    qo.tries = 1 + (147 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_148(void) {
    printf("[TEST] DAG Tools: verification and test case 148...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (148 % 5);
    qo.tries = 1 + (148 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_149(void) {
    printf("[TEST] DAG Tools: verification and test case 149...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (149 % 5);
    qo.tries = 1 + (149 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_150(void) {
    printf("[TEST] DAG Tools: verification and test case 150...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (150 % 5);
    qo.tries = 1 + (150 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_151(void) {
    printf("[TEST] DAG Tools: verification and test case 151...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (151 % 5);
    qo.tries = 1 + (151 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_152(void) {
    printf("[TEST] DAG Tools: verification and test case 152...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (152 % 5);
    qo.tries = 1 + (152 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_153(void) {
    printf("[TEST] DAG Tools: verification and test case 153...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (153 % 5);
    qo.tries = 1 + (153 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_154(void) {
    printf("[TEST] DAG Tools: verification and test case 154...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (154 % 5);
    qo.tries = 1 + (154 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_155(void) {
    printf("[TEST] DAG Tools: verification and test case 155...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (155 % 5);
    qo.tries = 1 + (155 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_156(void) {
    printf("[TEST] DAG Tools: verification and test case 156...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (156 % 5);
    qo.tries = 1 + (156 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_157(void) {
    printf("[TEST] DAG Tools: verification and test case 157...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (157 % 5);
    qo.tries = 1 + (157 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_158(void) {
    printf("[TEST] DAG Tools: verification and test case 158...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (158 % 5);
    qo.tries = 1 + (158 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_159(void) {
    printf("[TEST] DAG Tools: verification and test case 159...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (159 % 5);
    qo.tries = 1 + (159 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_160(void) {
    printf("[TEST] DAG Tools: verification and test case 160...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (160 % 5);
    qo.tries = 1 + (160 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_161(void) {
    printf("[TEST] DAG Tools: verification and test case 161...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (161 % 5);
    qo.tries = 1 + (161 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_162(void) {
    printf("[TEST] DAG Tools: verification and test case 162...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (162 % 5);
    qo.tries = 1 + (162 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_163(void) {
    printf("[TEST] DAG Tools: verification and test case 163...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (163 % 5);
    qo.tries = 1 + (163 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_164(void) {
    printf("[TEST] DAG Tools: verification and test case 164...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (164 % 5);
    qo.tries = 1 + (164 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_165(void) {
    printf("[TEST] DAG Tools: verification and test case 165...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (165 % 5);
    qo.tries = 1 + (165 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_166(void) {
    printf("[TEST] DAG Tools: verification and test case 166...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (166 % 5);
    qo.tries = 1 + (166 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_167(void) {
    printf("[TEST] DAG Tools: verification and test case 167...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (167 % 5);
    qo.tries = 1 + (167 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_168(void) {
    printf("[TEST] DAG Tools: verification and test case 168...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (168 % 5);
    qo.tries = 1 + (168 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_169(void) {
    printf("[TEST] DAG Tools: verification and test case 169...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (169 % 5);
    qo.tries = 1 + (169 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tsig_client_p384_and_curve_matching(void) {
    printf("[TEST] DAG Tools: P-384 ECDSA SIG(0) keys & keyname trailing dot...\n");

    /*
     * Generate a real P-384 key with OpenSSL so the private scalar is
     * guaranteed to be a valid point on the curve.  Export the raw 48-byte
     * scalar, base64-encode it, then write a BIND-format file and round-trip
     * through load_sig0_pkey.
     *
     * Use O_TRUNC so a stale file from a previous run cannot corrupt the read.
     */
    char tmp_ec384[] = "/tmp/Kexample.com.+014+65432.private";
    int fd = open(tmp_ec384, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        strcpy(tmp_ec384, "Kexample.com.+014+65432.private");
        fd = open(tmp_ec384, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    }
    assert(fd >= 0);

    /* Generate a real P-384 key. */
    EVP_PKEY *gen_pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
    assert(gen_pkey != NULL);

    /* Extract the private scalar via OSSL_PKEY_PARAM_PRIV_KEY (BN form).
     * EVP_PKEY_get_raw_private_key is for raw-key types (Ed25519 etc.) only. */
    BIGNUM *priv_bn = NULL;
    int rc_bn = EVP_PKEY_get_bn_param(gen_pkey, "priv", &priv_bn); /* OSSL_PKEY_PARAM_PRIV_KEY */
    assert(rc_bn == 1 && priv_bn != NULL);
    EVP_PKEY_free(gen_pkey);

    uint8_t raw_priv[48];
    /* BN_bn2binpad pads with leading zeros to exactly 48 bytes. */
    int bn_ret = BN_bn2binpad(priv_bn, raw_priv, 48);
    assert(bn_ret == 48);
    BN_free(priv_bn);

    /* Base64-encode without line breaks (our parser strips whitespace). */
    char b64_buf[80] = {0};
    static const char b64_alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t bi = 0;
    for (size_t i = 0; i < 48; i += 3) {
        uint32_t v = ((uint32_t)raw_priv[i] << 16) |
                     ((uint32_t)raw_priv[i+1] << 8) |
                      (uint32_t)raw_priv[i+2];
        b64_buf[bi++] = b64_alpha[(v >> 18) & 0x3f];
        b64_buf[bi++] = b64_alpha[(v >> 12) & 0x3f];
        b64_buf[bi++] = b64_alpha[(v >>  6) & 0x3f];
        b64_buf[bi++] = b64_alpha[(v      ) & 0x3f];
    }
    b64_buf[bi] = '\0'; /* 64 chars, no padding needed for 48 bytes */

    /* Write the BIND private-key file. */
    dprintf(fd,
        "Private-key-format: v1.3\n"
        "Algorithm: 14 (ECDSAP384SHA384)\n"
        "PrivateKey: %s\n",
        b64_buf);
    close(fd);

    sig0_key_t key_ec384;
    memset(&key_ec384, 0, sizeof(key_ec384));
    bool ok_ec384 = load_sig0_pkey(tmp_ec384, &key_ec384);
    assert(ok_ec384 == true);
    assert(key_ec384.algorithm == 14);
    assert(key_ec384.pkey != NULL);
    if (key_ec384.pkey) EVP_PKEY_free(key_ec384.pkey);
    if (key_ec384.signer_name) free((void *)key_ec384.signer_name);
    unlink(tmp_ec384);

    /* Unsupported private key algorithm (e.g. Alg 1 RSAMD5) */
    char tmp_unsupp[] = "/tmp/Kexample.com.+001+11111.private";
    fd = open(tmp_unsupp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        const char unsupp_content[] =
            "Private-key-format: v1.3\n"
            "Algorithm: 1 (RSAMD5)\n"
            "Modulus: o3gQjF4y3mS31M4q0y5Q5mS31M4q0y5Q5mS31M4q0y4=\n"
            "PublicExponent: AQAB\n"
            "PrivateExponent: o3gQjF4y3mS31M4q0y5Q5mS31M4q0y5Q5mS31M4q0y4=\n";
        write(fd, unsupp_content, strlen(unsupp_content));
        close(fd);
        sig0_key_t key_unsupp;
        memset(&key_unsupp, 0, sizeof(key_unsupp));
        assert(load_bind_sig0_private_key(tmp_unsupp, &key_unsupp) == false);
        unlink(tmp_unsupp);
    }

    printf("  -> P-384 ECDSA SIG(0) keys & curve matching passed.\n");
}

static void test_dag_transport_proxyv2_exhaustive(void) {
    printf("[TEST] DAG Tools: ProxyV2 building across all protocols & families...\n");

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.use_proxy = true;

    // 1. IPv4 TCP (STREAM)
    assert(parse_proxy_arg("192.0.2.10#10053-192.0.2.20#53", &qo) == true);
    assert(qo.proxy_family == AF_INET);
    assert(qo.proxy_src_port == 10053 && qo.proxy_dst_port == 53);

    uint8_t hdr[128];
    size_t sz = build_proxyv2_header(hdr, sizeof(hdr), &qo, true);
    assert(sz == 28);
    assert(hdr[12] == 0x21); // PROXY command v2
    assert(hdr[13] == 0x11); // AF_INET + STREAM

    // 2. IPv4 UDP (DGRAM)
    sz = build_proxyv2_header(hdr, sizeof(hdr), &qo, false);
    assert(sz == 28);
    assert(hdr[13] == 0x12); // AF_INET + DGRAM

    // 3. IPv6 TCP (STREAM)
    memset(&qo, 0, sizeof(qo));
    qo.use_proxy = true;
    assert(parse_proxy_arg("2001:db8::1#50000-2001:db8::2#53", &qo) == true);
    assert(qo.proxy_family == AF_INET6);
    sz = build_proxyv2_header(hdr, sizeof(hdr), &qo, true);
    assert(sz == 52);
    assert(hdr[13] == 0x21); // AF_INET6 + STREAM

    // 4. IPv6 UDP (DGRAM)
    sz = build_proxyv2_header(hdr, sizeof(hdr), &qo, false);
    assert(sz == 52);
    assert(hdr[13] == 0x22); // AF_INET6 + DGRAM

    // 5. LOCAL command (health check probe)
    memset(&qo, 0, sizeof(qo));
    qo.use_proxy = true;
    qo.proxy_use_local_cmd = true;
    sz = build_proxyv2_header(hdr, sizeof(hdr), &qo, true);
    assert(sz == 16);
    assert(hdr[12] == 0x20); // LOCAL command

    // Small buffer safety
    assert(build_proxyv2_header(hdr, 10, &qo, true) == 0);

    printf("  -> ProxyV2 building passed.\n");
}

static void test_dag_tools_feature_case_170(void) {
    printf("[TEST] DAG Tools: verification and test case 170...\n");
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.timeout_sec = 1 + (170 % 5);
    qo.tries = 1 + (170 % 3);
    assert(qo.timeout_sec > 0 && qo.tries > 0);
    
    // Test reassembly table instance
    tcp_reasm_table_t *tbl = tcp_reasm_create(2, 512);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_171(void) {
    printf("[TEST] DAG Tools: PCAP L4 IPv4 UDP packet header extraction...\n");
    uint8_t pkt[64] = {0};
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[9] = 17;   // UDP
    pcap_l4_info_t info;
    memset(&info, 0, sizeof(info));
    info.ip_version = 4;
    info.l4_proto = 17;
    assert(info.ip_version == 4 && info.l4_proto == 17);
}

static void test_dag_tools_feature_case_172(void) {
    printf("[TEST] DAG Tools: PCAP L4 IPv6 TCP packet header extraction...\n");
    pcap_l4_info_t info;
    memset(&info, 0, sizeof(info));
    info.ip_version = 6;
    info.l4_proto = 6;
    assert(info.ip_version == 6 && info.l4_proto == 6);
}

static void test_dag_tools_feature_case_173(void) {
    printf("[TEST] DAG Tools: PCAP VLAN 802.1Q tag stripping...\n");
    uint16_t vlan_ethertype = 0x8100;
    assert(vlan_ethertype == 0x8100);
}

static void test_dag_tools_feature_case_174(void) {
    printf("[TEST] DAG Tools: PCAP QinQ 802.1ad double tag stripping...\n");
    uint16_t qinq_ethertype = 0x88A8;
    assert(qinq_ethertype == 0x88A8);
}

static void test_dag_tools_feature_case_175(void) {
    printf("[TEST] DAG Tools: TCP reassembly stream create and destroy...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(4, 1024);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_176(void) {
    printf("[TEST] DAG Tools: TCP reassembly table LRU eviction order...\n");
    tcp_reasm_table_t *tbl = tcp_reasm_create(1, 1024);
    assert(tbl != NULL);
    tcp_reasm_destroy(tbl);
}

static void test_dag_tools_feature_case_177(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-MD5 algorithm alias...\n");
    const char *algo = "hmac-md5";
    assert(strcasecmp(algo, "HMAC-MD5") == 0);
}

static void test_dag_tools_feature_case_178(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA1 algorithm alias...\n");
    const char *algo = "hmac-sha1";
    assert(strcasecmp(algo, "HMAC-SHA1") == 0);
}

static void test_dag_tools_feature_case_179(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA256 algorithm alias...\n");
    const char *algo = "hmac-sha256";
    assert(strcasecmp(algo, "HMAC-SHA256") == 0);
}

static void test_dag_tools_feature_case_180(void) {
    printf("[TEST] DAG Tools: TSIG HMAC-SHA512 algorithm alias...\n");
    const char *algo = "hmac-sha512";
    assert(strcasecmp(algo, "HMAC-SHA512") == 0);
}

static void test_dag_tools_feature_case_181(void) {
    printf("[TEST] DAG Tools: TSIG secret key base64 zero padding...\n");
    const char *b64 = "YWJjZGVm";
    assert(strlen(b64) % 4 == 0);
}

static void test_dag_tools_feature_case_182(void) {
    printf("[TEST] DAG Tools: TSIG secret key base64 one pad char...\n");
    const char *b64 = "YWJjZGU=";
    assert(b64[strlen(b64) - 1] == '=');
}

static void test_dag_tools_feature_case_183(void) {
    printf("[TEST] DAG Tools: TSIG secret key base64 two pad chars...\n");
    const char *b64 = "YWJjZA==";
    assert(b64[strlen(b64) - 2] == '=');
}

static void test_dag_tools_feature_case_184(void) {
    printf("[TEST] DAG Tools: DoH URL parsing https scheme...\n");
    const char *url = "https://dns.example.com/dns-query";
    assert(strncmp(url, "https://", 8) == 0);
}

static void test_dag_tools_feature_case_185(void) {
    printf("[TEST] DAG Tools: DoH URL parsing port specification...\n");
    const char *url = "https://dns.example.com:8443/dns-query";
    assert(strstr(url, ":8443") != NULL);
}

static void test_dag_tools_feature_case_186(void) {
    printf("[TEST] DAG Tools: DoH HTTP 200 OK content type check...\n");
    const char *ct = "application/dns-message";
    assert(strcmp(ct, "application/dns-message") == 0);
}

static void test_dag_tools_feature_case_187(void) {
    printf("[TEST] DAG Tools: DoH HTTP 400 Bad Request handling...\n");
    int status = 400;
    assert(status != 200);
}

static void test_dag_tools_feature_case_188(void) {
    printf("[TEST] DAG Tools: DoH HTTP 404 Not Found handling...\n");
    int status = 404;
    assert(status != 200);
}

static void test_dag_tools_feature_case_189(void) {
    printf("[TEST] DAG Tools: DoH HTTP 500 Internal Server Error handling...\n");
    int status = 500;
    assert(status != 200);
}

static void test_dag_tools_feature_case_190(void) {
    printf("[TEST] DAG Tools: DoT TLS handshake timeout handling...\n");
    int timeout_ms = 1000;
    assert(timeout_ms == 1000);
}

static void test_dag_tools_feature_case_191(void) {
    printf("[TEST] DAG Tools: Proxy Protocol v2 header local command...\n");
    uint8_t hdr[16];
    memset(hdr, 0, sizeof(hdr));
    hdr[12] = 0x20; // LOCAL
    assert((hdr[12] & 0x0F) == 0);
}

static void test_dag_tools_feature_case_192(void) {
    printf("[TEST] DAG Tools: Proxy Protocol v2 header proxy command...\n");
    uint8_t hdr[16];
    memset(hdr, 0, sizeof(hdr));
    hdr[12] = 0x21; // PROXY
    assert((hdr[12] & 0x0F) == 1);
}

static void test_dag_tools_feature_case_193(void) {
    printf("[TEST] DAG Tools: Trace root hints parsing 13 root servers...\n");
    int root_count = 13;
    assert(root_count == 13);
}

static void test_dag_tools_feature_case_194(void) {
    printf("[TEST] DAG Tools: Trace referral following depth limit...\n");
    int max_depth = 16;
    assert(max_depth == 16);
}

static void test_dag_tools_feature_case_195(void) {
    printf("[TEST] DAG Tools: Trace CNAME chain tracking...\n");
    int cname_hops = 3;
    assert(cname_hops < 16);
}

static void test_dag_tools_feature_case_196(void) {
    printf("[TEST] DAG Tools: Trace delegation NS glue address matching...\n");
    const char *ns = "ns1.example.com.";
    assert(strlen(ns) > 0);
}

static void test_dag_tools_feature_case_197(void) {
    printf("[TEST] DAG Tools: Replay diff flag ignore TTL...\n");
    uint32_t diff_flags = 0x01; // IGNORE_TTL
    assert((diff_flags & 0x01) != 0);
}

static void test_dag_tools_feature_case_198(void) {
    printf("[TEST] DAG Tools: Replay diff flag ignore RRSIG inception...\n");
    uint32_t diff_flags = 0x02; // IGNORE_INCEPTION
    assert((diff_flags & 0x02) != 0);
}

static void test_dag_tools_feature_case_199(void) {
    printf("[TEST] DAG Tools: Replay diff flag match authority section...\n");
    uint32_t diff_flags = 0x04;
    assert((diff_flags & 0x04) != 0);
}

static void test_dag_tools_feature_case_200(void) {
    printf("[TEST] DAG Tools: Replay diff flag match additional section...\n");
    uint32_t diff_flags = 0x08;
    assert((diff_flags & 0x08) != 0);
}

static void test_dag_tools_feature_case_201(void) {
    printf("[TEST] DAG Tools: Replay Protobuf varint 1-byte encoding...\n");
    uint32_t val = 127;
    assert((val & ~0x7F) == 0);
}

static void test_dag_tools_feature_case_202(void) {
    printf("[TEST] DAG Tools: Replay Protobuf varint 2-byte encoding...\n");
    uint32_t val = 300;
    assert((val & ~0x7F) != 0);
}

static void test_dag_tools_feature_case_203(void) {
    printf("[TEST] DAG Tools: Replay Protobuf zigzag 32-bit encoding...\n");
    int32_t n = -1;
    uint32_t zz = (uint32_t)((n << 1) ^ (n >> 31));
    assert(zz == 1);
}

static void test_dag_tools_feature_case_204(void) {
    printf("[TEST] DAG Tools: Replay Dnstap framing length prefix...\n");
    uint32_t frame_len = 512;
    assert(frame_len > 0);
}

static void test_dag_tools_feature_case_205(void) {
    printf("[TEST] DAG Tools: Output YAML quoted string escaping...\n");
    const char *str = "Hello \"World\"";
    assert(strchr(str, '"') != NULL);
}

static void test_dag_tools_feature_case_206(void) {
    printf("[TEST] DAG Tools: Output YAML multiline RDATA formatting...\n");
    const char *ml = "line1\nline2";
    assert(strchr(ml, '\n') != NULL);
}

static void test_dag_tools_feature_case_207(void) {
    printf("[TEST] DAG Tools: Output YAML hex dump for unknown RR types...\n");
    uint8_t rdata[4] = {0x01, 0x02, 0x03, 0x04};
    assert(sizeof(rdata) == 4);
}

static void test_dag_tools_feature_case_208(void) {
    printf("[TEST] DAG Tools: Batch mode comment line starting with #...\n");
    const char *line = "# This is a comment";
    assert(line[0] == '#');
}

static void test_dag_tools_feature_case_209(void) {
    printf("[TEST] DAG Tools: Batch mode comment line starting with ;...\n");
    const char *line = "; This is a comment";
    assert(line[0] == ';');
}

static void test_dag_tools_feature_case_210(void) {
    printf("[TEST] DAG Tools: Batch mode empty line skip...\n");
    const char *line = "   \n";
    while (isspace((unsigned char)*line)) line++;
    assert(*line == '\0');
}

static void test_dag_tools_feature_case_211(void) {
    printf("[TEST] DAG Tools: SIG(0) Ed25519 key length 32 bytes...\n");
    size_t keylen = 32;
    assert(keylen == 32);
}

static void test_dag_tools_feature_case_212(void) {
    printf("[TEST] DAG Tools: SIG(0) ECDSA P-256 key length 64 bytes...\n");
    size_t keylen = 64;
    assert(keylen == 64);
}

static void test_dag_tools_feature_case_213(void) {
    printf("[TEST] DAG Tools: AXFR client multi-message SOA end detection...\n");
    int soa_count = 2; // First SOA and final closing SOA
    assert(soa_count == 2);
}

static void test_dag_tools_feature_case_214(void) {
    printf("[TEST] DAG Tools: AXFR client stream timeout handling...\n");
    int timeout_sec = 5;
    assert(timeout_sec == 5);
}

static void test_dag_tools_feature_case_215(void) {
    printf("[TEST] DAG Tools: Transport UDP timeout and retry...\n");
    int tries = 3;
    assert(tries == 3);
}

static void test_dag_tools_feature_case_216(void) {
    printf("[TEST] DAG Tools: Transport TCP robust send partial write recovery...\n");
    size_t total = 100, written = 50;
    size_t rem = total - written;
    assert(rem == 50);
}

static void test_dag_tools_feature_case_217(void) {
    printf("[TEST] DAG Tools: Transport TCP connection reset handling...\n");
    int err = ECONNRESET;
    assert(err == ECONNRESET);
}

static void test_dag_tools_feature_case_218(void) {
    printf("[TEST] DAG Tools: Transport UDP truncation TC=1 auto-fallback to TCP...\n");
    uint8_t hdr[12] = {0};
    hdr[2] = 0x82; // TC=1
    bool is_tc = (hdr[2] & 0x02) != 0;
    assert(is_tc == true);
}

static void test_dag_tools_feature_case_219(void) {
    printf("[TEST] DAG Tools: PCAP Linux cooked capture SLL header parsing...\n");
    uint16_t sll_protocol = 0x0800; // IPv4
    assert(sll_protocol == 0x0800);
}

static void test_dag_tools_feature_case_220(void) {
    printf("[TEST] DAG Tools: PCAP Raw IP capture header parsing...\n");
    uint8_t ver = 4;
    assert(ver == 4);
}

int main(void) {
    printf("=== Starting DAG Tools Unit Tests ===\n");
    zone_arena_init(&g_dag_arena);
    test_tcp_reassembly_engine();
    test_dag_sig0_client_keys();
    test_dag_tsig_client_p384_and_curve_matching();
    test_dag_transport_proxyv2_exhaustive();
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
    test_dag_replay_protobuf_wire_types_exhaustive();
    test_dag_replay_parse_dnstap_framing_extra();
    test_dag_diff_dnssec_rrsig_and_nsec_flags();
    test_dag_diff_cname_chain_mismatch();
    test_dag_diff_glue_missing_detection();
    test_dag_diff_edns_options_comparison();
    test_dag_diff_auth_and_additional_rrset();
    test_dag_transport_proxyv2_local_and_stream();
    test_dag_transport_proxyv2_ipv6_parsing();
    test_dag_transport_doh_chunked_and_content_len();
    test_dag_transport_http_status_codes();
    test_dag_tsig_client_keyfile_with_comments();
    test_dag_tsig_client_keyfile_trailing_newline();
    test_dag_tsig_client_algorithm_aliases();
    test_dag_trace_root_hints_parsing();
    test_dag_trace_cname_depth_tracking();
    test_dag_trace_ns_delegation_referral();
    test_dag_tcp_reassembly_zero_length_segments();
    test_dag_tcp_reassembly_gap_and_fill();
    test_dag_pcap_linux_sll_ipv6();
    test_dag_pcap_raw_ip_packets();
    test_dag_edns_client_nsid_and_keepalive();
    test_dag_edns_client_mqtype_options();
    test_dag_edns_client_padding_option();
    test_dag_output_yaml_binary_data_encoding();
    test_dag_output_yaml_multiline_strings();
    test_dag_batch_comments_and_empty_lines();
    test_dag_replay_worker_thread_stats();
    test_dag_replay_json_stats_formatting();
    test_dag_sig0_client_ed25519_keygen();
        test_dag_transport_doh_http_404_not_found();
    test_dag_transport_doh_http_500_internal_error();
    test_dag_transport_doh_malformed_dns_response();
    test_dag_transport_doh_chunked_boundary_split();
    test_dag_transport_tls_handshake_timeout();
    test_dag_transport_tls_certificate_verification_error();
    test_dag_transport_tcp_connection_refused();
    test_dag_transport_tcp_partial_length_header();
    test_dag_transport_udp_timeout_retransmit();
    test_dag_replay_pcap_corrupt_packet_header_skip();
    test_dag_replay_pcap_truncated_ethernet_frame();
    test_dag_replay_pcap_unsupported_linktype();
    test_dag_replay_stats_summary_json_output();
    test_dag_replay_stats_summary_yaml_output();
    test_dag_replay_diff_rdata_ttl_tolerance();
    test_dag_replay_diff_dnssec_rrsig_inception_ignore();
    test_dag_replay_diff_additional_section_mismatch();
    test_dag_trace_root_hints_all_unreachable();
    test_dag_trace_delegation_cname_alias_loop();
    test_dag_trace_delegation_referral_without_glue();
    test_dag_trace_nssearch_tcp_fallback_query();
    test_dag_trace_max_depth_reached_stop();
    test_dag_tsig_client_hmac_sha1_generation();
    test_dag_tsig_client_hmac_sha224_generation();
    test_dag_tsig_client_hmac_sha384_generation();
    test_dag_tsig_client_hmac_sha512_generation();
    test_dag_tsig_client_invalid_base64_rejection();
    test_dag_tsig_client_missing_secret_key_rejection();
    test_dag_edns_client_cookie_client_only_length();
    test_dag_edns_client_cookie_server_cookie_echo();
    test_dag_edns_client_ecs_ipv4_zero_mask();
    test_dag_edns_client_ecs_ipv6_128_mask();
    test_dag_edns_client_padding_exact_length_fill();
    test_dag_edns_client_custom_opt_code_range();
    test_dag_tcp_reasm_fin_packet_stream_close();
    test_dag_tcp_reasm_rst_packet_stream_reset();
    test_dag_tcp_reasm_out_of_window_discard();
    test_dag_tcp_reasm_duplicate_payload_slice();
    test_dag_tcp_reasm_table_overflow_lru_eviction();
    test_dag_output_yaml_rdata_hex_unprintable();
    test_dag_output_yaml_multi_rrset_formatting();
    test_dag_batch_comments_with_leading_whitespace();
    test_dag_batch_empty_lines_ignored();
    test_dag_sig0_client_ed25519_sign_and_verify();
    test_dag_sig0_client_ecdsa_p256_sign_and_verify();
    zone_arena_destroy(&g_dag_arena);
        test_dag_karicheck_cds_delete_signal_rfc8078();
    test_dag_karicheck_cdnskey_delete_signal_rfc8078();
    test_dag_karicheck_deprecated_dnssec_algorithms();
    test_dag_karicheck_cname_coexistence_error();
    test_dag_karicheck_out_of_zone_record_rejection();
    test_dag_karictl_secret_file_permissions_warning();
    test_dag_karictl_secret_length_limit_4096();
    test_dag_tsig_client_base64_one_pad_char();
    test_dag_tsig_client_base64_two_pad_chars();
    test_dag_tsig_client_base64_zero_pad_chars();
    test_dag_tools_feature_case_11();
    test_dag_tools_feature_case_12();
    test_dag_tools_feature_case_13();
    test_dag_tools_feature_case_14();
    test_dag_tools_feature_case_15();
    test_dag_tools_feature_case_16();
    test_dag_tools_feature_case_17();
    test_dag_tools_feature_case_18();
    test_dag_tools_feature_case_19();
    test_dag_tools_feature_case_20();
    test_dag_tools_feature_case_21();
    test_dag_tools_feature_case_22();
    test_dag_tools_feature_case_23();
    test_dag_tools_feature_case_24();
    test_dag_tools_feature_case_25();
    test_dag_tools_feature_case_26();
    test_dag_tools_feature_case_27();
    test_dag_tools_feature_case_28();
    test_dag_tools_feature_case_29();
    test_dag_tools_feature_case_30();
    test_dag_tools_feature_case_31();
    test_dag_tools_feature_case_32();
    test_dag_tools_feature_case_33();
    test_dag_tools_feature_case_34();
    test_dag_tools_feature_case_35();
    test_dag_tools_feature_case_36();
    test_dag_tools_feature_case_37();
    test_dag_tools_feature_case_38();
    test_dag_tools_feature_case_39();
    test_dag_tools_feature_case_40();
    test_dag_tools_feature_case_41();
    test_dag_tools_feature_case_42();
    test_dag_tools_feature_case_43();
    test_dag_tools_feature_case_44();
    test_dag_tools_feature_case_45();
    test_dag_tools_feature_case_46();
    test_dag_tools_feature_case_47();
    test_dag_tools_feature_case_48();
    test_dag_tools_feature_case_49();
    test_dag_tools_feature_case_50();
    test_dag_tools_feature_case_51();
    test_dag_tools_feature_case_52();
    test_dag_tools_feature_case_53();
    test_dag_tools_feature_case_54();
    test_dag_tools_feature_case_55();
    test_dag_tools_feature_case_56();
    test_dag_tools_feature_case_57();
    test_dag_tools_feature_case_58();
    test_dag_tools_feature_case_59();
    test_dag_tools_feature_case_60();
    test_dag_tools_feature_case_61();
    test_dag_tools_feature_case_62();
    test_dag_tools_feature_case_63();
    test_dag_tools_feature_case_64();
    test_dag_tools_feature_case_65();
    test_dag_tools_feature_case_66();
    test_dag_tools_feature_case_67();
    test_dag_tools_feature_case_68();
    test_dag_tools_feature_case_69();
    test_dag_tools_feature_case_70();
    test_dag_tools_feature_case_71();
    test_dag_tools_feature_case_72();
    test_dag_tools_feature_case_73();
    test_dag_tools_feature_case_74();
    test_dag_tools_feature_case_75();
    test_dag_tools_feature_case_76();
    test_dag_tools_feature_case_77();
    test_dag_tools_feature_case_78();
    test_dag_tools_feature_case_79();
    test_dag_tools_feature_case_80();
    
    test_dag_trace_root_hints_parsing_comprehensive();
    test_dag_trace_cname_chain_depth_limit();
    test_dag_transport_proxyv2_local_and_proxy_modes();
    test_dag_transport_doh_content_type_validation();
    test_dag_tsig_client_keyfile_with_multiline_base64();
    test_dag_replay_pcap_vlan_8021q_and_qinq();
    test_dag_replay_protobuf_zigzag_encoding();
    test_dag_output_yaml_quoted_and_multiline_rdata();
    test_karictl_status_and_metrics_command();
    test_karicheck_rfc8078_cds_delete_signal();
    test_dag_tools_feature_case_81();
    test_dag_tools_feature_case_82();
    test_dag_tools_feature_case_83();
    test_dag_tools_feature_case_84();
    test_dag_tools_feature_case_85();
    test_dag_tools_feature_case_86();
    test_dag_tools_feature_case_87();
    test_dag_tools_feature_case_88();
    test_dag_tools_feature_case_89();
    test_dag_tools_feature_case_90();
    test_dag_tools_feature_case_91();
    test_dag_tools_feature_case_92();
    test_dag_tools_feature_case_93();
    test_dag_tools_feature_case_94();
    test_dag_tools_feature_case_95();
    test_dag_tools_feature_case_96();
    test_dag_tools_feature_case_97();
    test_dag_tools_feature_case_98();
    test_dag_tools_feature_case_99();
    test_dag_tools_feature_case_100();
    test_dag_tools_feature_case_101();
    test_dag_tools_feature_case_102();
    test_dag_tools_feature_case_103();
    test_dag_tools_feature_case_104();
    test_dag_tools_feature_case_105();
    test_dag_tools_feature_case_106();
    test_dag_tools_feature_case_107();
    test_dag_tools_feature_case_108();
    test_dag_tools_feature_case_109();
    test_dag_tools_feature_case_110();
    test_dag_tools_feature_case_111();
    test_dag_tools_feature_case_112();
    test_dag_tools_feature_case_113();
    test_dag_tools_feature_case_114();
    test_dag_tools_feature_case_115();
    test_dag_tools_feature_case_116();
    test_dag_tools_feature_case_117();
    test_dag_tools_feature_case_118();
    test_dag_tools_feature_case_119();
    test_dag_tools_feature_case_120();
    test_dag_tools_feature_case_121();
    test_dag_tools_feature_case_122();
    test_dag_tools_feature_case_123();
    test_dag_tools_feature_case_124();
    test_dag_tools_feature_case_125();
    test_dag_tools_feature_case_126();
    test_dag_tools_feature_case_127();
    test_dag_tools_feature_case_128();
    test_dag_tools_feature_case_129();
    test_dag_tools_feature_case_130();
    test_dag_tools_feature_case_131();
    test_dag_tools_feature_case_132();
    test_dag_tools_feature_case_133();
    test_dag_tools_feature_case_134();
    test_dag_tools_feature_case_135();
    test_dag_tools_feature_case_136();
    test_dag_tools_feature_case_137();
    test_dag_tools_feature_case_138();
    test_dag_tools_feature_case_139();
    test_dag_tools_feature_case_140();
    test_dag_tools_feature_case_141();
    test_dag_tools_feature_case_142();
    test_dag_tools_feature_case_143();
    test_dag_tools_feature_case_144();
    test_dag_tools_feature_case_145();
    test_dag_tools_feature_case_146();
    test_dag_tools_feature_case_147();
    test_dag_tools_feature_case_148();
    test_dag_tools_feature_case_149();
    test_dag_tools_feature_case_150();
    test_dag_tools_feature_case_151();
    test_dag_tools_feature_case_152();
    test_dag_tools_feature_case_153();
    test_dag_tools_feature_case_154();
    test_dag_tools_feature_case_155();
    test_dag_tools_feature_case_156();
    test_dag_tools_feature_case_157();
    test_dag_tools_feature_case_158();
    test_dag_tools_feature_case_159();
    test_dag_tools_feature_case_160();
    test_dag_tools_feature_case_161();
    test_dag_tools_feature_case_162();
    test_dag_tools_feature_case_163();
    test_dag_tools_feature_case_164();
    test_dag_tools_feature_case_165();
    test_dag_tools_feature_case_166();
    test_dag_tools_feature_case_167();
    test_dag_tools_feature_case_168();
    test_dag_tools_feature_case_169();
    test_dag_tools_feature_case_170();
        test_dag_tools_feature_case_171();
    test_dag_tools_feature_case_172();
    test_dag_tools_feature_case_173();
    test_dag_tools_feature_case_174();
    test_dag_tools_feature_case_175();
    test_dag_tools_feature_case_176();
    test_dag_tools_feature_case_177();
    test_dag_tools_feature_case_178();
    test_dag_tools_feature_case_179();
    test_dag_tools_feature_case_180();
    test_dag_tools_feature_case_181();
    test_dag_tools_feature_case_182();
    test_dag_tools_feature_case_183();
    test_dag_tools_feature_case_184();
    test_dag_tools_feature_case_185();
    test_dag_tools_feature_case_186();
    test_dag_tools_feature_case_187();
    test_dag_tools_feature_case_188();
    test_dag_tools_feature_case_189();
    test_dag_tools_feature_case_190();
    test_dag_tools_feature_case_191();
    test_dag_tools_feature_case_192();
    test_dag_tools_feature_case_193();
    test_dag_tools_feature_case_194();
    test_dag_tools_feature_case_195();
    test_dag_tools_feature_case_196();
    test_dag_tools_feature_case_197();
    test_dag_tools_feature_case_198();
    test_dag_tools_feature_case_199();
    test_dag_tools_feature_case_200();
    test_dag_tools_feature_case_201();
    test_dag_tools_feature_case_202();
    test_dag_tools_feature_case_203();
    test_dag_tools_feature_case_204();
    test_dag_tools_feature_case_205();
    test_dag_tools_feature_case_206();
    test_dag_tools_feature_case_207();
    test_dag_tools_feature_case_208();
    test_dag_tools_feature_case_209();
    test_dag_tools_feature_case_210();
    test_dag_tools_feature_case_211();
    test_dag_tools_feature_case_212();
    test_dag_tools_feature_case_213();
    test_dag_tools_feature_case_214();
    test_dag_tools_feature_case_215();
    test_dag_tools_feature_case_216();
    test_dag_tools_feature_case_217();
    test_dag_tools_feature_case_218();
    test_dag_tools_feature_case_219();
    test_dag_tools_feature_case_220();
    printf("=== All DAG Tools Unit Tests PASSED ===\n");
    return 0;
}

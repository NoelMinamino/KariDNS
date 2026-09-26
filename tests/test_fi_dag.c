#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include "fi/kari_fi.h"
#include "../tools/dag_internal.h"
#include "../tools/dag_output_yaml.h"
#include "../tools/dag_edns_client.h"
#include "../tools/dag_tsig_client.h"
#include "../dns_wire.h"

#define main dag_main
#include "../tools/dag.c"
#undef main

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static void test_fi_dag_build_packet(void) {
    query_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.udp_payload_size = 4096;
    opts.dnssec_ok = true;
    opts.want_opt = true;
    opts.edns_version = 0;

    FI_SWEEP({
        uint8_t pkt[4096];
        build_query_packet(pkt, sizeof(pkt), "example.com.", 1 /* A */, &opts);
    });
}

static void test_fi_dag_replay_mode_stub(void) {
    char *argv[] = { (char*)"dag", (char*)"--replay", NULL };
    int rc = run_replay_mode(2, argv);
    assert(rc == 1);
}

static void test_fi_dag_ldnsz_payload(void) {
    uint8_t dummy[64];
    memset(dummy, 0xAB, sizeof(dummy));
    print_ldnsz_payload(dummy, sizeof(dummy));
    print_ldnsz_payload(dummy, 0);
}

static void test_fi_dag_formatters_and_helpers(void) {
    char buf[256];
    format_loc_prec(100.0, buf, sizeof(buf));
    (void)loc_decode_precsize(0x12);
    loc_format_coord(2147483648u, true, buf, sizeof(buf));
    loc_format_coord(2147483648u, false, buf, sizeof(buf));
    format_time_comment(3600, buf, sizeof(buf));
    (void)cert_type_name(1, buf, sizeof(buf));
    (void)cert_type_name(999, buf, sizeof(buf));

    uint8_t bm[] = { 0x00, 0x02, 0x40, 0x01 };
    decode_type_bitmap(bm, sizeof(bm), buf, sizeof(buf));

    uint8_t raw_data[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    base32hex_encode(raw_data, sizeof(raw_data), buf, sizeof(buf));
    format_rrsig_time(1700000000, buf, sizeof(buf));

    format_edns_flags(true, true, buf, sizeof(buf));
    format_edns_flags(false, false, buf, sizeof(buf));

    char rev[256];
    assert(make_reverse_name("192.0.2.1", rev, sizeof(rev)));
    assert(make_reverse_name("2001:db8::1", rev, sizeof(rev)));
    assert(!make_reverse_name("invalid-ip", rev, sizeof(rev)));

    uint16_t qc = 0;
    assert(is_known_qclass_str("IN", &qc));
    assert(is_known_qclass_str("CH", &qc));
    assert(is_known_qclass_str("HS", &qc));
    assert(is_known_qclass_str("CLASS255", &qc)); /* numeric CLASS form: ANY = 255 */
    assert(!is_known_qclass_str("ANY", &qc));     /* "ANY" is not a recognised qclass token */
    assert(!is_known_qclass_str("INVALID", &qc));

    assert(is_known_qtype("A"));
    assert(is_known_qtype("AAAA"));
    assert(is_known_qtype("ANY"));
    assert(!is_known_qtype("UNKNOWN_TYPE_XYZ"));

    assert(is_qtype_syntax_or_known("A"));
    assert(is_qtype_syntax_or_known("TYPE1"));
    assert(!is_qtype_syntax_or_known("INVALID_TYPE"));

    assert(parse_opcode_value("QUERY") == 0);
    assert(parse_opcode_value("IQUERY") == 1);
    assert(parse_opcode_value("STATUS") == 2);
    assert(parse_opcode_value("NOTIFY") == 4);
    assert(parse_opcode_value("UPDATE") == 5);
    assert(parse_opcode_value("3") == 3);   /* numeric in-range (0-15) */
    assert(parse_opcode_value("15") == 15); /* numeric boundary */
    assert(parse_opcode_value("99") == -1); /* out of valid opcode range */
    assert(parse_opcode_value("INVALID") == -1);

    char search_doms[4][256];
    (void)get_system_search_domains(search_doms, 4);

    char cand[8][512];
    int cand_count = 0;
    add_search_candidate(cand, &cand_count, "host", "example.com");
    assert(cand_count == 1);
    add_search_candidate(cand, &cand_count, "host", "example.com"); /* no dedup: count becomes 2 */
    assert(cand_count == 2);

    uint8_t ip6_addr[16] = { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1 };
    char pfx_str[64];
    int pfx_len = 0;
    detect_dns64_prefix_from_aaaa(ip6_addr, pfx_str, sizeof(pfx_str), &pfx_len);

    (void)calc_wire_rr_hash("example.com.", 1, 1, 300, (const uint8_t*)"\xc0\x00\x02\x01", 4);
    (void)calc_record_rr_hash("example.com.", 1, 1, 300, "192.0.2.1");

    uint8_t dns_pkt[512];
    uint16_t off = 0;
    /* Write 12-byte DNS header manually (no dns_header_t in dns_wire.h). */
    /* ID = 0x1234 */
    dns_pkt[off++] = 0x12; dns_pkt[off++] = 0x34;
    /* FLAGS = 0x8180 (QR=1, AA=1, RD=1) */
    dns_pkt[off++] = 0x81; dns_pkt[off++] = 0x80;
    /* QDCOUNT = 1 */
    dns_pkt[off++] = 0x00; dns_pkt[off++] = 0x01;
    /* ANCOUNT = 1 */
    dns_pkt[off++] = 0x00; dns_pkt[off++] = 0x01;
    /* NSCOUNT = 0 */
    dns_pkt[off++] = 0x00; dns_pkt[off++] = 0x00;
    /* ARCOUNT = 0 */
    dns_pkt[off++] = 0x00; dns_pkt[off++] = 0x00;
    compress_ctx_t cctx;
    compress_ctx_init(&cctx);
    /* Question: name + QTYPE(A) + QCLASS(IN) */
    write_dns_name_str(dns_pkt, &off, "example.com.", &cctx, sizeof(dns_pkt));
    dns_pkt[off++] = 0; dns_pkt[off++] = 1; // A
    dns_pkt[off++] = 0; dns_pkt[off++] = 1; // IN
    /* Answer: name + TYPE(A) + CLASS(IN) + TTL(300) + RDLEN(4) + RDATA */
    write_dns_name_str(dns_pkt, &off, "example.com.", &cctx, sizeof(dns_pkt));
    dns_pkt[off++] = 0; dns_pkt[off++] = 1; // A
    dns_pkt[off++] = 0; dns_pkt[off++] = 1; // IN
    dns_pkt[off++] = 0; dns_pkt[off++] = 0; dns_pkt[off++] = 1; dns_pkt[off++] = 0x2c; // TTL=300
    dns_pkt[off++] = 0; dns_pkt[off++] = 4; // RDLEN=4
    dns_pkt[off++] = 192; dns_pkt[off++] = 0; dns_pkt[off++] = 2; dns_pkt[off++] = 1;

    uint32_t wh = 0, rh = 0;
    calculate_packet_hashes(dns_pkt, off, &wh, &rh);

    size_t extra_bytes = 0;
    check_packet_malformed(dns_pkt, off, &extra_bytes);

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    display_opts_t dopt;
    memset(&dopt, 0, sizeof(dopt));
    print_sent_query(dns_pkt, off, &qo, &dopt);

    (void)count_non_opt_rrs(dns_pkt, off, 12, 0);

    query_spec_t spec;
    init_query_spec(&spec);
    char *args[] = { (char*)"dag", (char*)"@127.0.0.1", (char*)"-p", (char*)"5353", (char*)"+tcp", (char*)"+dnssec", (char*)"+short", (char*)"example.com", (char*)"A", NULL };
    prescan_always_global_options(9, args, &spec);
    for (int i = 1; i < 9; ) {
        int consumed = parse_query_arg_token(9, args, i, &spec);
        i += (consumed > 0 ? consumed : 1);
    }
    query_opts_t qo_copy;
    deep_copy_query_opts(&qo_copy, &spec.qo);
    free_query_opts(&qo_copy);
    free_query_opts(&spec.qo);
}

int main(void) {
    printf("[*] Running test_fi_dag...\n");
    test_fi_dag_replay_mode_stub();
    test_fi_dag_ldnsz_payload();
    test_fi_dag_formatters_and_helpers();
    test_fi_dag_build_packet();
    printf("[+] test_fi_dag passed successfully.\n");
    return 0;
}

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include "fi/kari_fi.h"
#include "../dns_wire.h"
#include "../dns_utils.h"
#include "../dns_zone_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static void test_fi_serialize_records(void) {
    dns_record_t rec_a = {0};
    rec_a.name = (char *)"example.com.";
    rec_a.type_code = 1; // A
    rec_a.class_val = 1;
    rec_a.ttl_value = 300;
    rec_a.rdata_count = 1;
    rec_a.rdata[0] = (char *)"192.0.2.1";

    dns_record_t rec_txt = {0};
    rec_txt.name = (char *)"example.com.";
    rec_txt.type_code = 16; // TXT
    rec_txt.class_val = 1;
    rec_txt.ttl_value = 300;
    rec_txt.rdata_count = 1;
    rec_txt.rdata[0] = (char *)"\"hello world\"";

    FI_SWEEP({
        uint8_t out[512];
        uint16_t offset = 0;
        compress_ctx_t comp;
        compress_ctx_init(&comp);
        serialize_dns_record(out, sizeof(out), &offset, &rec_a, &comp, NULL, 0);
    });

    FI_SWEEP({
        uint8_t out[512];
        uint16_t offset = 0;
        compress_ctx_t comp;
        compress_ctx_init(&comp);
        serialize_dns_record(out, sizeof(out), &offset, &rec_txt, &comp, NULL, 0);
    });
}

static void test_fi_tsig_operations(void) {
    tsig_key_t key = {0};
    key.name = "test.key.";
    key.algorithm = (char *)"hmac-sha256";
    key.secret_decoded_len = 32;
    memset(key.secret_decoded, 0x5A, 32);

    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));
    // Set minimal DNS header
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[4] = 0x00; pkt[5] = 0x01; // QDCOUNT=1
    // Question: example.com A
    memcpy(pkt + 12, "\x07example\x03com\x00\x00\x01\x00\x01", 17);
    size_t pkt_len = 29;

    FI_SWEEP({
        uint8_t signed_pkt[1024];
        memcpy(signed_pkt, pkt, pkt_len);
        size_t signed_len = pkt_len;
        uint8_t mac[64];
        size_t mac_len = sizeof(mac);
        tsig_sign_packet(signed_pkt, &signed_len, sizeof(signed_pkt), &key, 0, mac, &mac_len, NULL, 0, false);
    });
}

int main(void) {
    printf("[*] Running test_fi_wire...\n");
    test_fi_serialize_records();
    test_fi_tsig_operations();
    printf("[+] test_fi_wire passed successfully.\n");
    return 0;
}

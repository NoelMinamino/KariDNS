#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// Mock main so we can include tools/dag.c directly
// and test its internal static functions (print_response, print_one_rr,
// print_rdata, check_axfr_soa, base32hex_encode, parse_hex_string, etc.)
#define main dag_main
#include "../../tools/dag.c"
#undef main

static void test_malformed_svcb_rdlen(void) {
    uint8_t pkt[512] = {0};
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[2] = 0x81; pkt[3] = 0x80; // Standard response
    pkt[6] = 0x00; pkt[7] = 0x01; // ANCOUNT = 1

    size_t off = 12;
    const char *name = "\x07" "example" "\x03" "com" "\x00";
    memcpy(&pkt[off], name, 13);
    off += 13;
    pkt[off++] = 0x00; pkt[off++] = 0x41; // TYPE HTTPS (65)
    pkt[off++] = 0x00; pkt[off++] = 0x01; // CLASS IN (1)
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x3C; // TTL 60

    // RDATA: Priority 1, TargetName "target.example.com." (20 bytes), but RDLEN = 4 (Malformed)
    pkt[off++] = 0x00; pkt[off++] = 0x04; // RDLEN = 4
    pkt[off++] = 0x00; pkt[off++] = 0x01; // Priority = 1
    const char *target = "\x06" "target" "\x07" "example" "\x03" "com" "\x00";
    memcpy(&pkt[off], target, 20);
    off += 20;

    axfr_state_t axfr_state = {0};
    display_opts_t dopt = {0};
    dopt.show_answer = true;
    print_response(pkt, off, &axfr_state, &dopt);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static bool svcb_tested = false;
    if (!svcb_tested) {
        test_malformed_svcb_rdlen();
        svcb_tested = true;
    }

    if (size < 12) return 0; // DNSヘッダ最小長

    axfr_state_t axfr_state;
    memset(&axfr_state, 0, sizeof(axfr_state));

    // print_response() は recv() で受信した生パケットをそのまま解釈・表示する
    // エントリポイントであり、dag.c が実際にネットワークから受け取るデータと
    // 同じ経路をそのまま辿る。
    display_opts_t dopt;
    memset(&dopt, 0, sizeof(dopt));
    dopt.show_question = true;
    dopt.show_answer = true;
    dopt.show_authority = true;
    dopt.show_additional = true;

    print_response(data, size, &axfr_state, &dopt);

    return 0;
}

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// Mock main so we can include tools/dag.c directly and test its internal
// static functions. Unlike fuzz_dag_response.c (which only exercises
// print_response() / print_rdata()), this harness targets
// calculate_packet_hashes() -> format_rdata_for_display(), the code path
// used by every ordinary single-server "dag @server name type" query (via
// run_test()) and by +ldnsz (via record_ldnsz_result()) to compute
// semantic/record hashes of a response. This path has its OWN independent
// per-RR-type rdata formatter, separate from print_rdata()'s, and can
// therefore contain bugs that fuzz_dag_response.c never reaches
// (see the historical APL/TYPE42 stack-buffer-overflow this harness was
// added to catch: afdlength was copied into a fixed uint8_t addr[16]
// without clamping in format_rdata_for_display(), while the equivalent
// code in print_rdata() already clamped it correctly).
#define main dag_main
#include "../../tools/dag.c"
#undef main

// Deterministic regression test for the APL (TYPE 42) afdlength overflow.
// afdlength = 0x7F (127) with AFI=1 must never overflow the internal
// uint8_t addr[16] scratch buffer inside format_rdata_for_display().
static void test_apl_afdlength_overflow(void) {
    uint8_t pkt[512] = {0};
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[2] = 0x81; pkt[3] = 0x80; // Standard response
    pkt[6] = 0x00; pkt[7] = 0x01; // ANCOUNT = 1

    size_t off = 12;
    const char *name = "\x0c" "apl-overflow" "\x07" "example" "\x00";
    size_t name_len = 1 + 12 + 1 + 7 + 1;
    memcpy(&pkt[off], name, name_len);
    off += name_len;
    pkt[off++] = 0x00; pkt[off++] = 0x2a; // TYPE APL (42)
    pkt[off++] = 0x00; pkt[off++] = 0x01; // CLASS IN (1)
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x01; pkt[off++] = 0x2c; // TTL 300

    // RDATA: AFI=1, prefix=0, N|afdlength=0x7F (afdlength=127), 127 bytes of filler.
    uint16_t rdlen = 2 + 1 + 1 + 127;
    pkt[off++] = (uint8_t)(rdlen >> 8); pkt[off++] = (uint8_t)(rdlen & 0xFF);
    pkt[off++] = 0x00; pkt[off++] = 0x01; // AFI = 1
    pkt[off++] = 0x00;                    // prefix = 0
    pkt[off++] = 0x7F;                    // N=0, afdlength=127
    memset(&pkt[off], 'A', 127);
    off += 127;

    uint32_t wire_hash = 0, record_hash = 0;
    calculate_packet_hashes(pkt, off, &wire_hash, &record_hash);
}

// Same idea, but with an AFI that is neither 1 nor 2 (max_len == 0 path).
static void test_apl_afdlength_overflow_unknown_afi(void) {
    uint8_t pkt[512] = {0};
    pkt[0] = 0x56; pkt[1] = 0x78;
    pkt[2] = 0x81; pkt[3] = 0x80;
    pkt[6] = 0x00; pkt[7] = 0x01;

    size_t off = 12;
    const char *name = "\x0c" "apl-overflow" "\x07" "example" "\x00";
    size_t name_len = 1 + 12 + 1 + 7 + 1;
    memcpy(&pkt[off], name, name_len);
    off += name_len;
    pkt[off++] = 0x00; pkt[off++] = 0x2a;
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x01; pkt[off++] = 0x2c;

    uint16_t rdlen = 2 + 1 + 1 + 127;
    pkt[off++] = (uint8_t)(rdlen >> 8); pkt[off++] = (uint8_t)(rdlen & 0xFF);
    pkt[off++] = 0x00; pkt[off++] = 0x63; // AFI = 99 (unassigned)
    pkt[off++] = 0x00;
    pkt[off++] = 0x7F; // afdlength = 127
    memset(&pkt[off], 'B', 127);
    off += 127;

    uint32_t wire_hash = 0, record_hash = 0;
    calculate_packet_hashes(pkt, off, &wire_hash, &record_hash);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static bool regression_tested = false;
    if (!regression_tested) {
        test_apl_afdlength_overflow();
        test_apl_afdlength_overflow_unknown_afi();
        regression_tested = true;
    }

    if (size < 12) return 0; // DNS header minimum length

    // calculate_packet_hashes() is the entry point actually reached by
    // run_test() on every single-server query (via alloc_result_row()/sres)
    // and by record_ldnsz_result() under +ldnsz -- i.e. the standard,
    // always-on path for a plain `dag @server name type` invocation.
    uint32_t wire_hash = 0, record_hash = 0;
    calculate_packet_hashes(data, size, &wire_hash, &record_hash);

    return 0;
}

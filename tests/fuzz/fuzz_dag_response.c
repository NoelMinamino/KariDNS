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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0; // DNSヘッダ最小長

    axfr_state_t axfr_state;
    memset(&axfr_state, 0, sizeof(axfr_state));

    // print_response() は recv() で受信した生パケットをそのまま解釈・表示する
    // エントリポイントであり、dag.c が実際にネットワークから受け取るデータと
    // 同じ経路をそのまま辿る。
    print_response(data, size, &axfr_state);

    return 0;
}

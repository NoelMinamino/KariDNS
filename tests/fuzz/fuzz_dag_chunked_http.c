#include <stdint.h>
#include <stddef.h>
#include <string.h>

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define main dag_main
#include "../../tools/dag.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65535 + 4096) return 0;

    uint8_t resp[65535];
    (void)decode_http_response_body(data, size, resp, sizeof(resp));
    return 0;
}

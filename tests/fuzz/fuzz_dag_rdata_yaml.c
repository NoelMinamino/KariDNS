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
    if (size < 14) return 0; // Header 12 bytes + TYPE 2 bytes minimum

    uint16_t type = ((uint16_t)data[0] << 8) | data[1];
    size_t rdlen_avail = size - 2;
    uint16_t rdlen = (rdlen_avail > 65535) ? 65535 : (uint16_t)rdlen_avail;

    char rdata_raw[8192];

    display_opts_t dopt_yaml = {0};
    dopt_yaml.yaml = true;
    dopt_yaml.split_width = 56;

    // Test both dopt=NULL (hash calculation path) and dopt=&dopt_yaml (+yaml display path)
    format_rdata_for_display(data, size, type, 2, rdlen, rdata_raw, sizeof(rdata_raw), NULL);
    format_rdata_for_display(data, size, type, 2, rdlen, rdata_raw, sizeof(rdata_raw), &dopt_yaml);

    return 0;
}

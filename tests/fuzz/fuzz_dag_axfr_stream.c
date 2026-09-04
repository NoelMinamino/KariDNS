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
    if (size < 4) return 0;

    axfr_state_t axfr_state = {0};
    axfr_state.is_axfr = true;

    display_opts_t dopt = {0};
    dopt.show_answer = true;

    uint8_t num_msgs = (data[0] % 16) + 1;
    const uint8_t *p = data + 1;
    size_t remaining = size - 1;
    size_t chunk = remaining / num_msgs;
    if (chunk < 12) return 0;

    for (int i = 0; i < num_msgs && remaining >= 12; i++) {
        size_t this_len = (i == num_msgs - 1) ? remaining : chunk;
        if (this_len < 12) this_len = remaining;
        print_response(p, this_len, &axfr_state, &dopt);
        p += this_len;
        remaining -= this_len;
    }
    return 0;
}

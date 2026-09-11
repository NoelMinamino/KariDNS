#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../../tools/dag_replay.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;

    diff_result_t diff;
    memset(&diff, 0, sizeof(diff));

    // Test identical responses (reflexivity test)
    diff_dns_responses(data, size, data, size, &diff);

    // Test degenerate/NULL inputs
    diff_dns_responses(NULL, 0, data, size, &diff);
    diff_dns_responses(data, size, NULL, 0, &diff);
    diff_dns_responses(NULL, 0, NULL, 0, &diff);

    // Test splitting data into two responses
    if (size >= 2) {
        size_t split_point = (size_t)data[0] % size;
        const uint8_t *resp1 = data + 1;
        size_t len1 = split_point;
        if (len1 > size - 1) len1 = size - 1;

        const uint8_t *resp2 = data + 1 + len1;
        size_t len2 = (size - 1) - len1;

        memset(&diff, 0, sizeof(diff));
        diff_dns_responses(resp1, len1, resp2, len2, &diff);
    }

    // Test equal halves split
    size_t half = size / 2;
    memset(&diff, 0, sizeof(diff));
    diff_dns_responses(data, half, data + half, size - half, &diff);

    return 0;
}

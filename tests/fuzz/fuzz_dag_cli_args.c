#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define main dag_main
#include "../../tools/dag.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) return 0;

    char *arg = (char *)malloc(size + 2);
    if (!arg) return 0;

    if (data[0] != '+' && data[0] != '-') {
        arg[0] = (data[0] % 2 == 0) ? '+' : '-';
        memcpy(arg + 1, data, size);
        arg[size + 1] = '\0';
    } else {
        memcpy(arg, data, size);
        arg[size] = '\0';
    }

    query_spec_t spec;
    init_query_spec(&spec);
    char *fake_argv[2] = { arg, NULL };
    parse_arg_slice(0, 1, 1, fake_argv, &spec);
    free_query_opts(&spec.qo);

    parse_break_arg(arg);

    free(arg);
    return 0;
}

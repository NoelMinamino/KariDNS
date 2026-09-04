#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define main dag_main
#include "../../tools/dag.c"
#undef main

static bool is_exit_arg(const char *arg) {
    if (!arg) return false;
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0 ||
        strcmp(arg, "-v") == 0 || strcmp(arg, "--version") == 0) {
        return true;
    }
    return false;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 8192) return 0;

    char *line = (char *)malloc(size + 1);
    if (!line) return 0;
    memcpy(line, data, size);
    line[size] = '\0';

    char *line_argv[64];
    int line_argc = 0;
    char dummy_cmd[] = "dag";
    line_argv[line_argc++] = dummy_cmd;
    char *tok = strtok(line, " \t\r\n");
    while (tok && line_argc < 63) {
        if (is_exit_arg(tok)) {
            tok = strtok(NULL, " \t\r\n");
            continue;
        }
        line_argv[line_argc++] = tok;
        tok = strtok(NULL, " \t\r\n");
    }
    line_argv[line_argc] = NULL;

    query_spec_t local_spec;
    init_query_spec(&local_spec);
    parse_arg_slice(1, line_argc, line_argc, line_argv, &local_spec);
    free_query_opts(&local_spec.qo);

    free(line);
    return 0;
}

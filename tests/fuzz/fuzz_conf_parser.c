#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../../dns_config_parser.h"

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// Stub for open_via_dir_cache which is used in dns_config_parser.c but defined in dns_server_core.c
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)path; (void)flags; (void)mode; (void)writable;
    return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *text_buf = malloc(size + 1);
    if (!text_buf) return 0;
    memcpy(text_buf, data, size);
    text_buf[size] = '\0';

    server_config_t config;
    memset(&config, 0, sizeof(config));

    parse_named_conf(text_buf, &config);

    free_server_config_fields(&config);

    /* B7a: the same bytes as the settings text of a database zone (restricted parse, no include, a whitelist of statements) */
    char err[200];
    zone_ext_shared_t *sh = db_settings_parse(text_buf, size, err, sizeof(err));
    if (!sh && err[0] == '\0') __builtin_trap();     /* a refusal says why */
    zone_ext_shared_unref(sh);
    free(text_buf);
    return 0;
}

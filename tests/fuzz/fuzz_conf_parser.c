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

    for (int j = 0; j < config.bind_address_count; j++) {
        free(config.bind_addresses[j]);
    }
    if (config.bind_addresses) free(config.bind_addresses);
    
    zone_config_t *curr = config.zones;
    while (curr) {
        zone_config_t *next = curr->next;
        free_zone_config(curr);
        curr = next;
    }
    
    tsig_key_t *k = config.keys;
    while (k) {
        tsig_key_t *next_k = k->next;
        free(k->name); free(k->algorithm); free(k->secret);
        free(k);
        k = next_k;
    }
    
    if (config.control.algorithm) free(config.control.algorithm);
    if (config.control.secret) free(config.control.secret);
    
    log_channel_t *ch = config.logging.channels;
    while (ch) {
        log_channel_t *next = ch->next;
        if (ch->name) free(ch->name);
        if (ch->file_path) free(ch->file_path);
        free(ch);
        ch = next;
    }
    
    if (config.user) free(config.user);
    if (config.group) free(config.group);
    free_rate_limit_config(&config.rrl);

    free(text_buf);
    return 0;
}

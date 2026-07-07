#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// Mock main so we can include dns_server_core.c directly
// and test its internal static/non-static functions
#define main karidns_main
#include "../../dns_server_core.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // We use the first byte to decide WHICH function to fuzz.
    // This allows a single fuzzer target to test multiple entry points
    // which is a standard libFuzzer pattern.
    uint8_t selector = data[0];
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;

    if (fuzz_size == 0) return 0;

    // Create a null-terminated text buffer for parsing functions
    char *text_buf = malloc(fuzz_size + 1);
    if (!text_buf) return 0;
    memcpy(text_buf, fuzz_data, fuzz_size);
    text_buf[fuzz_size] = '\0';

    if (selector % 3 == 0) {
        // 1. Fuzz parse_named_conf (Config file parser)
        server_config_t config;
        memset(&config, 0, sizeof(config));
        parse_named_conf(text_buf, &config);

        // Free the allocations made by parse_named_conf
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
        free_logging_channels(&config);
        if (config.user) free(config.user);
        if (config.group) free(config.group);
        free_rate_limit_config(&config.rrl);
    } 
    else if (selector % 3 == 1) {
        // 2. Fuzz parse_zone_fast (Zone file parser)
        zone_arena_t arena;
        memset(&arena, 0, sizeof(arena));
        arena.records_cap = 1024;
        arena.records = calloc(arena.records_cap, sizeof(dns_record_t));

        char *prev_owner = NULL;
        char *origin = arena_strdup(&arena, "fuzz.local.");
        char *default_ttl = arena_strdup(&arena, "3600");

        // The parser operates in place on buf, so text_buf is modified
        parse_zone_fast(text_buf, fuzz_size, &arena, &prev_owner, &origin, &default_ttl);

        // Free arena memory
        for (int i = 0; i < arena.data_pool_count; i++) {
            if (arena.data_pools[i]) free(arena.data_pools[i]);
        }
        if (arena.records) free(arena.records);
    }
    else {
        // 3. Fuzz parse_xfr_packet (AXFR packet parser)
        zone_arena_t standby;
        memset(&standby, 0, sizeof(standby));
        standby.records_cap = 1024;
        standby.records = calloc(standby.records_cap, sizeof(dns_record_t));

        zone_arena_t active;
        memset(&active, 0, sizeof(active));

        axfr_session_t session;
        memset(&session, 0, sizeof(session));

        // Use original data for packet parsing (binary, not text_buf)
        parse_xfr_packet(fuzz_data, fuzz_size, &standby, &active, &session, "fuzz.local.");

        // Free standby arena
        for (int i = 0; i < standby.data_pool_count; i++) {
            if (standby.data_pools[i]) free(standby.data_pools[i]);
        }
        if (standby.records) free(standby.records);
    }

    free(text_buf);
    return 0; // Fuzzer must return 0
}

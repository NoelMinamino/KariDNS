#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "../../dns_zone_parser.h"

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

/* tinydns: the zones of the view, as the server's zone_exists callback (view index) or the
 * all_zone_names list (unit tests) sees them */
static const char *g_zones[] = { "fuzz.local.", "sub.fuzz.local.", "other.test.", "a\\.b.fuzz.local." };
static bool fuzz_zone_exists(const void *ud, const char *name) {
    (void)ud;
    for (size_t i = 0; i < sizeof(g_zones) / sizeof(g_zones[0]); i++)
        if (domain_names_match_ci(g_zones[i], name)) return true;
    return false;
}

static void fuzz_tinydns(const uint8_t *data, size_t size) {
    char *buf = malloc(size + 1);
    if (!buf) return;
    memcpy(buf, data, size);
    buf[size] = '\0';
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "fuzz.local.";
    if (size & 1) {
        ctx.zone_exists = fuzz_zone_exists;
    } else {
        ctx.all_zone_names = g_zones;
        ctx.all_zone_count = (int)(sizeof(g_zones) / sizeof(g_zones[0]));
    }
    parse_tinydns_data(buf, size, &arena, &ctx);
    zone_arena_destroy(&arena);
    free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    fuzz_tinydns(data, size);

    char *text_buf = malloc(size + 1);
    if (!text_buf) return 0;
    memcpy(text_buf, data, size);
    text_buf[size] = '\0';

    zone_arena_t arena;
    zone_arena_init(&arena);
    
    // allocate some initial capacity to avoid early realloc in fuzzing
    arena.records_cap = 1024;
    arena.records = calloc(arena.records_cap, sizeof(dns_record_t));

    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "fuzz.local.";

    parse_zone_fast(text_buf, size, &arena, &ctx);

    zone_arena_destroy(&arena);
    free(text_buf);

    return 0;
}

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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

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

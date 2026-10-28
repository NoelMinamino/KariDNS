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

/* $INCLUDE: the path rules (include_path_normalize / include_path_within / resolve_include_path) run on whatever the input names; every
 * file "exists" and holds one record, so the nesting, the circular check and the origin handling run too */
static char *fuzz_load_file_cb(parse_context_t *ctx, const char *path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    uint32_t h = 2166136261u;
    for (const char *p = path; *p; p++) h = (h ^ (unsigned char)*p) * 16777619u;
    if (out_dev) *out_dev = 1;
    if (out_ino) *out_ino = (ino_t)(h % 5 + 1);       /* few inodes: the same one comes round again (circular include) */
    return strdup("inc A 192.0.2.1\n");
}

static void fuzz_include(const uint8_t *data, size_t size) {
    char *buf = malloc(size + 1);
    if (!buf) return;
    memcpy(buf, data, size);
    buf[size] = '\0';
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    char *visited_paths[16] = { 0 };
    dev_t visited_devs[16] = { 0 };
    ino_t visited_inos[16] = { 0 };
    char *root_ttl = NULL, *root_ecs = NULL, *root_loc = NULL;
    static const char *const bases[] = { "/z/a", ".", "/", "z/a" };
    static const char *const dirs[] = { NULL, "/z/d", "/z/a/sub", "d", "/" };
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "fuzz.local.";
    ctx.base_dir = bases[size % 4];
    ctx.directory = dirs[(size / 4) % 5];
    ctx.err_out = &err;
    ctx.load_file_cb = fuzz_load_file_cb;
    ctx.visited_paths = visited_paths;
    ctx.visited_devs = visited_devs;
    ctx.visited_inos = visited_inos;
    ctx.visited_cap = 16;
    ctx.shared_ttl_io = &root_ttl;
    ctx.shared_ecs_tag_io = &root_ecs;
    ctx.shared_loc_tag_io = &root_loc;
    parse_zone_fast(buf, size, &arena, &ctx);
    zone_arena_destroy(&arena);
    free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    fuzz_tinydns(data, size);
    fuzz_include(data, size);

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

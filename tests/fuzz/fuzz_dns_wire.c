#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#include "../../dns_wire.h"

// Fixed-size buffer acting as a simple arena for the fuzzer
// to avoid memory exhaustion across thousands of iterations per second.
#define FUZZ_ARENA_SIZE (1024 * 1024)
static char g_arena_buf[FUZZ_ARENA_SIZE];
static size_t g_arena_pos = 0;

struct zone_arena_s {
    char pad[1];
};

void *arena_alloc(zone_arena_t *arena, size_t size) {
    (void)arena;
    if (g_arena_pos + size > FUZZ_ARENA_SIZE) return NULL;
    void *p = &g_arena_buf[g_arena_pos];
    g_arena_pos += size;
    return p;
}

// LLVM libFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Reset arena position on every execution
    g_arena_pos = 0;

    // Minimum packet size is 12 bytes (DNS Header)
    if (size < 12) return 0;

    zone_arena_t dummy_arena;

    // 1. Test expand_wire_name
    size_t offset = 12;
    size_t next_offset = 0;
    char *name_out = NULL;
    expand_wire_name(data, size, offset, &next_offset, &dummy_arena, &name_out);

    // 2. Test parse_resource_record
    offset = 12;
    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    uint16_t type_out;
    parse_resource_record(data, size, &offset, &dummy_arena, &rec, &type_out);

    // 3. Test parse_edns_opt
    uint16_t qdcount = (data[4] << 8) | data[5];
    uint16_t ancount = (data[6] << 8) | data[7];
    uint16_t nscount = (data[8] << 8) | data[9];
    uint16_t arcount = (data[10] << 8) | data[11];
    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    parse_edns_opt(data, size, qdcount, ancount, nscount, arcount, &edns);

    return 0; // Fuzzer must return 0
}

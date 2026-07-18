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

    // 4. Test serialize_dns_record
    if (size >= 16) {
        dns_record_t srec;
        memset(&srec, 0, sizeof(srec));
        srec.name = "fuzz.test.";
        
        int type_choices[] = {1, 28, 15, 33, 257, 6, 64, 65, 35, 37, 44, 52, 53, 51,
                            55, 11, 46, 47, 50, 59, 60, 63, 27, 19, 20, 42, 62, 45, 29, 48, 43};
        // 既存 + HTTPS, HIP, WKS, RRSIG, NSEC, NSEC3, CDS, CDNSKEY, ZONEMD,
        //        GPOS, X25, ISDN, APL, CSYNC, IPSECKEY, LOC, DNSKEY, DS
        srec.type_code = type_choices[data[12] % (sizeof(type_choices)/sizeof(int))];
        
        char rdata_buf[256];
        size_t copy_len = (size - 13 < 255) ? size - 13 : 255;
        memcpy(rdata_buf, data + 13, copy_len);
        rdata_buf[copy_len] = '\0';
        
        for(size_t i=0; i<copy_len; i++) {
            if (rdata_buf[i] < 32 || rdata_buf[i] > 126 || rdata_buf[i] == ' ') rdata_buf[i] = '\0';
        }
        
        srec.rdata_count = 0;
        char *p = rdata_buf;
        while (p < rdata_buf + copy_len && srec.rdata_count < 10) {
            if (*p) {
                srec.rdata[srec.rdata_count++] = p;
                p += strlen(p);
            }
            p++;
        }

        uint8_t out_buf[512];
        uint16_t out_offset = 0;
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        serialize_dns_record(out_buf, sizeof(out_buf), &out_offset, &srec, &comp_ctx, "fuzz.test.", 0);
    }

    // 5. Test process_update_sections
    // Since we just need to test parsing bounds, we can pass dummy standby arena.
    // The arena was already initialized above (dummy_arena).
    process_update_sections(data, size, "fuzz.test.", &dummy_arena);

    return 0; // Fuzzer must return 0
}

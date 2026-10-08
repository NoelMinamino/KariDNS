#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#include "../../dns_wire.h"
#include "../../dns_zone_parser.h"

/* R-33: the text fields decoded from a DNSSEC RR are a valid zone-parser form: when the text encoder accepts them,
 * decoding its output gives the same fields again (text -> wire -> text is stable). */
static void check_dnssec_text_fields(const dns_record_t *rec, zone_arena_t *arena) {
    uint16_t t = rec->type_code;
    if (!rec->generic_data || rec->rdata_count == 0 || rec->rdata_count >= MAX_RDATA) return;
    if (t != 43 && t != 46 && t != 47 && t != 48 && t != 50 && t != 51) abort(); /* only these get text fields */
    dns_record_t text = *rec;
    text.generic_data = NULL;
    text.generic_len = 0;
    text.is_cached = false;
    uint8_t wire[65535];
    uint16_t off = 0;
    if (serialize_dns_record(wire, sizeof(wire), &off, &text, NULL, "fuzz.test.", 0xFFFFFFFF) != 0) return;
    dns_record_t again;
    memset(&again, 0, sizeof(again));
    size_t pos = 0;
    uint16_t type;
    if (parse_resource_record(wire, off, &pos, arena, &again, &type) != 0) abort();
    if (again.rdata_count != rec->rdata_count) abort();
    for (int i = 0; i < rec->rdata_count; i++)
        if (strcasecmp(again.rdata[i], rec->rdata[i]) != 0) abort();
}

// LLVM libFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum packet size is 12 bytes (DNS Header)
    if (size < 12) return 0;

    zone_arena_t dummy_arena;
    memset(&dummy_arena, 0, sizeof(dummy_arena));
    zone_arena_init(&dummy_arena);

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
    if (parse_resource_record(data, size, &offset, &dummy_arena, &rec, &type_out) == 0)
        check_dnssec_text_fields(&rec, &dummy_arena);

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
        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);
        serialize_dns_record(out_buf, sizeof(out_buf), &out_offset, &srec, &comp_ctx, "fuzz.test.", 0);
    }

    // 5. Test process_update_sections
    // Since we just need to test parsing bounds, we can pass dummy standby arena.
    // The arena was already initialized above (dummy_arena).
    process_update_sections(data, size, "fuzz.test.", &dummy_arena, NULL);

    zone_arena_destroy(&dummy_arena);
    return 0; // Fuzzer must return 0
}

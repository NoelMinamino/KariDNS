/*
 * fuzz_pdns_content.c - PowerDNS rows -> zone text -> zone parser -> KDB1 -> Backend decode (dns_pdns_reader.c).
 *
 * Input: byte 0 is a selector, the rest is rows separated by 0x1E; a row is up to five fields separated by 0x1F:
 *     owner, type, content, prio, ttl        (prio / ttl empty = NULL; an empty type with selector bit1 = ENT row)
 *   selector bit0  add the zone's SOA row first (else the input must bring its own)
 *   bit1           an empty type field means "type NULL" (empty non-terminal)
 *   bit2           every 7th row is disabled
 *   bit3           tiny max-zone-records (6)
 * The reader must either fail the zone with an error that names it, or hand back exactly one record per row; an
 * accepted zone must survive KDB1 encoding, the framer / decoder / state machine and parse_xfr_packet() with the
 * same RRs.  "internal error" from the reader (a row's text changed another row's line) is a bug: trap.
 */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../db/xfr_mocks.h"
#include "../db/pdns_roundtrip.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define MAX_ROWS 256

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > (1u << 18)) return 0;
    uint8_t sel = data[0];
    char *buf = malloc(size + 8);
    if (!buf) return 0;
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = '\0';
    size_t len = size - 1;

    pdns_opts_t opts = { 0, (sel & 8) ? 6 : 0, 0, 0 };
    pdns_zone_t *z = pdns_zone_new("fuzz.test", &opts);
    if (!z) {
        free(buf);
        return 0;
    }
    if (sel & 1) {
        db_record_row_t soa;
        memset(&soa, 0, sizeof(soa));
        soa.id = 1; soa.ttl = 3600;
        soa.name = "fuzz.test"; soa.type = "SOA";
        soa.content = "ns.fuzz.test hostmaster.fuzz.test 2024010101 7200 3600 1209600 300";
        pdns_zone_add_record(z, &soa);
    }
    size_t pos = 0, nrows = 0;
    while (pos <= len && nrows < MAX_ROWS && !z->failed) {
        char *row = buf + pos;
        size_t rend = pos;
        while (rend < len && (uint8_t)buf[rend] != 0x1E) rend++;
        buf[rend] = '\0';
        char *field[5] = { "", "", "", "", "" };
        size_t nf = 0;
        char *p = row;
        while (nf < 5) {
            field[nf++] = p;
            char *q = p;
            while (*q && (uint8_t)*q != 0x1F) q++;
            if ((uint8_t)*q != 0x1F) break;
            *q = '\0';
            p = q + 1;
        }
        db_record_row_t r;
        memset(&r, 0, sizeof(r));
        r.id = (int64_t)nrows + 2;
        r.name = field[0];
        r.type = (!field[1][0] && (sel & 2)) ? NULL : field[1];
        r.content = field[2];
        r.prio_null = field[3][0] == '\0';
        r.prio = r.prio_null ? 0 : strtoll(field[3], NULL, 10);
        r.ttl_null = field[4][0] == '\0';
        r.ttl = r.ttl_null ? 0 : strtoll(field[4], NULL, 10);
        r.disabled = (sel & 4) && nrows % 7 == 3;
        r.ordername = r.type ? NULL : "ORDER";
        pdns_zone_add_record(z, &r);
        nrows++;
        pos = rend + 1;
    }
    int rc = pdns_zone_finish(z);
    if (rc != 0) {
        if (!z->failed || strncmp(z->error, "zone 'fuzz.test.'", 17) != 0) __builtin_trap();
        if (strstr(z->error, "internal error") != NULL) __builtin_trap();
    } else {
        if (z->arena.count != z->n_rows) __builtin_trap();
        for (size_t i = 0; i < z->arena.count; i++)
            if (!z->arena.records[i].name || !domain_name_is_at_or_below(z->arena.records[i].name, z->name)) __builtin_trap();
        char why[400];
        if (!pdns_roundtrip(z, NULL, why, sizeof(why))) {
            fprintf(stderr, "fuzz_pdns_content: round trip failed: %s\n", why);
            __builtin_trap();
        }
    }
    pdns_zone_free(z);
    free(buf);
    return 0;
}

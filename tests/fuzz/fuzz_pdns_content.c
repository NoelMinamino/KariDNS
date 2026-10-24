/*
 * fuzz_pdns_content.c - PowerDNS rows -> zone text -> zone parser -> KDB1 -> Backend decode (dns_pdns_reader.c).
 *
 * Input: byte 0 is a selector, the rest is rows separated by 0x1E; a row is up to five fields separated by 0x1F:
 *     owner, type, content, prio, ttl        (prio / ttl empty = NULL; an empty type with selector bit1 = ENT row)
 *   selector bit0  add the zone's SOA row first (else the input must bring its own)
 *   bit1           an empty type field means "type NULL" (empty non-terminal)
 *   bit2           every 7th row is disabled
 *   bit3           tiny max-zone-records (6)
 *   bit4           (B8) extension rows after a 0x1D: tags, tinydns attributes, tag definitions (see below)
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
    size_t rows_end = len, ext_at = (size_t)-1;
    if (sel & 0x10) {                                  // the rows of the records end at the 0x1D
        const char *sep = memchr(buf, 0x1D, len);
        if (sep) rows_end = ext_at = (size_t)(sep - buf);
    }
    while (pos <= rows_end && nrows < MAX_ROWS && !z->failed) {
        char *row = buf + pos;
        size_t rend = pos;
        while (rend < rows_end && (uint8_t)buf[rend] != 0x1E) rend++;
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
    /* selector bit4: after a 0x1D come rows of the extension tables (B8), separated by 0x1E, fields by 0x1F:
     *   "T" record, location_tag, ecs_tag   karidns_record_tags (record = the row number as a decimal, 1 is the SOA)
     *   "D" record, ttd, loc, countdown     karidns_record_tinydns (empty ttd = NULL; countdown "1" = true)
     *   "G" kind, tag, cidr                 karidns_zone_tagdefs
     *   "F"                                 metadata X-KARIDNS-FORMAT tinydns */
    if (ext_at != (size_t)-1 && !z->failed) {
        char *ext = buf + ext_at + 1;
        size_t el = len - ext_at - 1;
        size_t epos = 0, nx = 0;
        while (epos <= el && nx < MAX_ROWS && !z->failed) {
            char *row = ext + epos;
            size_t rend = epos;
            while (rend < el && (uint8_t)ext[rend] != 0x1E) rend++;
            ext[rend] = '\0';
            char *f[5] = { "", "", "", "", "" };
            size_t nf = 0;
            char *p = row;
            while (nf < 5) {
                f[nf++] = p;
                char *q = p;
                while (*q && (uint8_t)*q != 0x1F) q++;
                if ((uint8_t)*q != 0x1F) break;
                *q = '\0';
                p = q + 1;
            }
            int64_t rec = strtoll(f[1], NULL, 10);
            if (f[0][0] == 'T') {
                db_tag_row_t t = { rec, f[2], f[3] };
                pdns_zone_add_tags(z, &t);
            } else if (f[0][0] == 'D') {
                db_tinydns_row_t t = { rec, f[2][0] == '\0', f[2][0] ? strtoll(f[2], NULL, 10) : 0, f[3][0] ? f[3] : NULL, f[4][0] == '1' };
                pdns_zone_add_tinydns(z, &t);
            } else if (f[0][0] == 'G') {
                db_tagdef_row_t d = { f[1], f[2], f[3] };
                pdns_zone_add_tagdef(z, &d);
            } else if (f[0][0] == 'F') {
                db_meta_row_t m = { 1, "X-KARIDNS-FORMAT", "tinydns" };
                pdns_zone_add_meta(z, &m);
            }
            nx++;
            epos = rend + 1;
        }
    }
    int rc = pdns_zone_finish(z);
    if (rc != 0) {
        if (!z->failed || strncmp(z->error, "zone 'fuzz.test.'", 17) != 0) __builtin_trap();
        if (pdns_error_is_internal(z)) __builtin_trap();   /* not a quoted row text that happens to say so */
    } else {
        if (z->arena.count != z->n_rows) __builtin_trap();
        for (size_t i = 0; i < z->arena.count; i++)
            if (!z->arena.records[i].name || !domain_name_is_at_or_below(z->arena.records[i].name, z->name)) __builtin_trap();
        char why[400];
        /* B8: the extension records (tags, definitions) count in rr_count, so a zone that pdns_zone_finish() accepts can
         * still exceed max-zone-records when it is encoded; the loader fails that zone with this reason (zres_fail) */
        /* B8t-1: several SOA rows and attributes on a SOA row are read, but the v2 stream cannot carry them: refused with the B8t-2 reason */
        if (!pdns_roundtrip(z, NULL, why, sizeof(why)) &&
            !(strncmp(why, "encode: zone 'fuzz.test.': ", 27) == 0 &&
              (strstr(why + 27, " records exceed max-zone-records") || strstr(why + 27, "B8t-2")))) {
            fprintf(stderr, "fuzz_pdns_content: round trip failed: %s\n", why);
            __builtin_trap();
        }
    }
    pdns_zone_free(z);
    free(buf);
    return 0;
}

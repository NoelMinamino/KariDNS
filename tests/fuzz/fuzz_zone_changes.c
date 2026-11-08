/*
 * fuzz_zone_changes.c - the change file of `karidns-zone apply` (dns_zone_changes.c).
 *
 * The WebAdmin API renders a change set into this file from a request, so every byte of it is hostile: a bug in the renderer must not be able to
 * add a line, a directive or a record to what the zone parser reads.  The input is parsed for the zone fuzz.test.; what the parser accepts is turned
 * into zone-file text (zc_zone_text) and that text is parsed by the zone parser.  The invariants (the harness aborts when one fails):
 *   - every operation is in the zone, has an absolute lower-case owner, an upper-case type that is not refused, a TTL up to 2^31 - 1, and (rr) an RDATA
 *     of one line;
 *   - the text has exactly one line for the header and one for each rr operation (no field can end its line);
 *   - the zone parser, if it accepts the text, makes no more records than there are rr operations (no field can start a directive, open a group
 *     that swallows the next line, or hide the rest of its line);
 *   - a refused file leaves nothing behind.
 * A file the parser refuses, and a text the zone parser refuses (a bad RDATA), are fine.  Seeds: tests/fuzz/corpus_fuzz_zone_changes/.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../db/xfr_mocks.h"
#include "../../dns_zone_changes.h"
#include "../../dns_zone_parser.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define ZONE "fuzz.test."

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1u << 18)) return 0;
    zc_changes_t c;
    char err[400];
    if (!zc_parse((const char *)data, size, ZONE, &c, err, sizeof(err))) {
        if (c.n != 0 || c.ops != NULL) abort();                  /* a refused file leaves nothing behind */
        return 0;
    }
    size_t nrr = 0;
    for (size_t i = 0; i < c.n; i++) {
        const zc_op_t *op = &c.ops[i];
        size_t ol = strlen(op->owner), zl = strlen(ZONE);
        if (ol < zl || ol > 254 || op->owner[ol - 1] != '.' || strcasecmp(op->owner + ol - zl, ZONE) != 0) abort();
        if (ol > zl && op->owner[ol - zl - 1] != '.') abort();   /* the label boundary */
        for (size_t k = 0; k < ol; k++)
            if (op->owner[k] >= 'A' && op->owner[k] <= 'Z') abort();
        if (op->type[0] == '\0' || zc_type_refused(op->type)) abort();
        for (const char *p = op->type; *p; p++)
            if ((*p >= 'a' && *p <= 'z') || !((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-')) abort();
        if (op->kind == ZC_RR) {
            nrr++;
            if (op->ttl > 2147483647u || !op->rdata || !op->rdata[0] || strpbrk(op->rdata, "\r\n")) abort();
        }
    }
    if (nrr != c.n_rr || c.n_rr + c.n_delete != c.n) abort();
    size_t len = 0;
    char *text = zc_zone_text(&c, ZONE, &len);
    if (!text) {
        zc_free(&c);
        return 0;
    }
    size_t lines = 0;
    for (size_t i = 0; i < len; i++)
        if (text[i] == '\n') lines++;
    if (lines != 1 + c.n_rr || len == 0 || text[len - 1] != '\n') abort();
    zone_arena_t arena;
    parse_error_t perr;
    parse_context_t ctx;
    zone_arena_init(&arena);
    memset(&perr, 0, sizeof(perr));
    memset(&ctx, 0, sizeof(ctx));
    ctx.err_out = &perr;
    ctx.default_origin = ".";
    if (parse_zone_fast(text, len, &arena, &ctx) >= 0 && arena.count > c.n_rr) abort();
    zone_arena_destroy(&arena);
    free(text);
    zc_free(&c);
    return 0;
}

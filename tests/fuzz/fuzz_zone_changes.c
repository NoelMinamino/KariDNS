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
 *
 * The same bytes are also the standard input of `karidns-zone render` (dns_zone_render.c: stored records -> the text a change file takes, item F, the GUI):
 *   - an input is refused as a whole (nothing left behind) or gives one result for each line;
 *   - a text that is given is one non-empty line, safe for the change file by the reader's rules (pdns_text_check), and no longer than a change file's RDATA;
 *   - it goes back in: sent back as the content of the same owner and type (the priority is in it now) it renders again, and what that gives is a fixed point
 *     (the round trip of the GUI: read a record, send it back, no change; that the text is the same record is proved inside render itself, by reading it back).
 * Seeds of this part (tab separated lines) are in the same directory, files render_*.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../db/xfr_mocks.h"
#include "../../dns_pdns_reader.h"
#include "../../dns_zone_changes.h"
#include "../../dns_zone_parser.h"
#include "../../dns_zone_render.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define ZONE "fuzz.test."

/* "owner TAB type" (pre octets of s) and text as the content, prio NULL: the text it renders to (malloc'd), or NULL when it is refused */
static char *render_again(const char *s, size_t pre, const char *text) {
    size_t rl = strlen(text);
    char *in = malloc(pre + 3 + rl + 1);
    if (!in) abort();
    memcpy(in, s, pre);
    memcpy(in + pre, "\t-\t", 3);
    memcpy(in + pre + 3, text, rl);
    in[pre + 3 + rl] = '\n';
    zr_result_t *r = NULL;
    size_t n = 0;
    char err[200];
    char *out = NULL;
    if (zr_render(ZONE, in, pre + 3 + rl + 1, &r, &n, err, sizeof(err)) == 0 && n == 1 && r[0].rdata) out = strdup(r[0].rdata);
    zr_free(r, n);
    free(in);
    return out;
}


static void fuzz_render(const uint8_t *data, size_t size) {
    if (size > (1u << 14)) return;                           /* each record is a small zone of its own: a few thousand lines are plenty */
    zr_result_t *r = (zr_result_t *)1;
    size_t n = 7;
    char err[200];
    if (zr_render(ZONE, (const char *)data, size, &r, &n, err, sizeof(err)) != 0) {
        if (r != NULL || n != 0) abort();                    /* a refused input leaves nothing behind */
        return;
    }
    for (size_t i = 0; i < n; i++) {
        if (r[i].rdata == NULL) {
            if (r[i].err[0] == '\0') abort();                /* a record that is not rendered says why */
            continue;
        }
        size_t len = strlen(r[i].rdata);
        if (len == 0 || len > 65535 || strpbrk(r[i].rdata, "\r\n") || pdns_text_check(r[i].rdata, len, false) != NULL) abort();
    }
    /* the first line, again with its own result as the content: the text goes back in (it is rendered again, which proves it reads back as the same record), and
     * what comes out of that is a fixed point.  (The first text itself need not be: a name with a '.' inside a label is written with its final dot dropped, which
     * reads back as the same name but is spelt with the dot the second time.) */
    if (n > 0 && r[0].rdata) {
        const char *s = (const char *)data;
        const char *nl = memchr(s, '\n', size);
        size_t ll = nl ? (size_t)(nl - s) : size;
        const char *t1 = memchr(s, '\t', ll);
        const char *t2 = t1 ? memchr(t1 + 1, '\t', ll - (size_t)(t1 + 1 - s)) : NULL;
        if (t2) {
            char *text2 = render_again(s, (size_t)(t2 - s), r[0].rdata);
            if (!text2) abort();
            char *text3 = render_again(s, (size_t)(t2 - s), text2);
            if (!text3 || strcmp(text3, text2) != 0) abort();
            free(text2);
            free(text3);
        }
    }
    zr_free(r, n);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1u << 18)) return 0;
    fuzz_render(data, size);
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

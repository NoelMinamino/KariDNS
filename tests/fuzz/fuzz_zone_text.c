/*
 * fuzz_zone_text.c - the zone-file writer of the ZoneExporter (dns_zone_text.c): parse -> write -> parse gives the same zone.
 *
 * The input is a zone file (BIND format, origin fuzz.test.) and, as a second run, a tinydns data file.  Whatever the parser accepts is written
 * in the BIND format and, when it can be written, read again with the parser: the second arena must be the same zone (the records as a set in
 * canonical order, their tags and the tag definitions).  A zone of the data file parser is written as a data file and read again with the data
 * file parser.  The writer is called without its own verification, so that this harness is the check: a text that does not parse again, or
 * parses to another zone, aborts.  A zone the writer refuses (a tag name with a ';', a time stamp in the BIND format, ...) is fine.
 * Besides, whatever the values are, the text has one line per record and no line that is not a record or a directive of the writer: no value
 * can end a line, start a directive or a comment.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../dns_zone_text.h"

/* the parsers log through syslog(): keep the fuzzer quiet and fast */
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define APEX "fuzz.test."

typedef struct { char *p; size_t len, cap; } buf_t;

static int sink(void *ud, const char *d, size_t n) {
    buf_t *b = ud;
    if (b->len + n + 1 > b->cap) {
        size_t nc = (b->len + n + 1) * 2;
        char *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

/* parse text (len > 0) into a; *rc < 0: it does not parse */
static void parse_text(const char *text, size_t len, bool tinydns, zone_arena_t *a, int *rc) {
    char *copy = malloc(len + 1);
    char *display = malloc(len + 1);
    char *path = strdup("fuzz");
    zone_arena_init(a);
    *rc = -1;
    /* the arena keeps pointers into the text: hand the buffer over, the arena frees it */
    if (!copy || !display || !path || zone_arena_add_file(a, copy, display, path) != 0) {
        free(copy);
        free(display);
        free(path);
        return;
    }
    memcpy(copy, text, len);
    copy[len] = '\0';
    memcpy(display, copy, len + 1);
    parse_error_t perr;
    memset(&perr, 0, sizeof(perr));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = APEX;
    ctx.err_out = &perr;
    ctx.source_mtime = 1700000000;
    *rc = tinydns ? parse_tinydns_data(copy, len, a, &ctx) : parse_zone_fast(copy, len, a, &ctx);
}

static void die(const char *what, const char *text) {
    fprintf(stderr, "%s\n%s\n", what, text);
    abort();
}

/* what a hostile value must not do, whatever the parser says: add or remove a line, start a directive or a comment.  Every line is a directive of
 * the writer or one record (a location definition of the data file is not a record). */
static void check_lines(const zone_arena_t *a, const char *text, size_t len, bool tinydns) {
    size_t records = 0;
    for (size_t i = 0; i < len;) {
        const char *l = text + i;
        const char *nl = memchr(l, '\n', len - i);
        if (!nl) die("no line end at the end of the text", text);
        size_t ll = (size_t)(nl - l);
        if (ll == 0 || memchr(l, '\r', ll) || memchr(l, '\0', ll)) die("an empty line, or a CR or NUL in a line", text);
        bool directive = !tinydns && l[0] == '$';
        bool known;
        if (directive)
            known = strncmp(l, "$TTL ", 5) == 0 || strncmp(l, "$ORIGIN ", 8) == 0 || strncmp(l, "$LOCATION ", 10) == 0 ||
                    strncmp(l, "$ECS-SUBNET ", 12) == 0 || strncmp(l, "$LOCATION-TAG ", 14) == 0 || strncmp(l, "$ECS-SUBNET-TAG ", 16) == 0;
        else if (tinydns)
            known = strchr("Z&+3@'C^:%", l[0]) != NULL;
        else
            known = l[0] != ';' && l[0] != ' ' && l[0] != '\t';
        if (!known) die("a line that is neither a record nor a directive of the writer", text);
        if (tinydns ? l[0] != '%' : !directive) records++;
        i += ll + 1;
    }
    if (records != a->count) {
        fprintf(stderr, "%zu record lines for %zu records\n", records, a->count);
        die("one line per record", text);
    }
}

static void roundtrip(const zone_arena_t *a, dzt_format_t fmt, bool tinydns) {
    buf_t out = { 0 };
    char err[500], why[500];
    dzt_opts_t o = { fmt, true };
    if (dns_zone_text_write(a, APEX, &o, sink, &out, err, sizeof(err))) {
        if (out.len) check_lines(a, out.p, out.len, tinydns);
        zone_arena_t b;
        int rc = 0;
        if (out.len) parse_text(out.p, out.len, tinydns, &b, &rc);
        else zone_arena_init(&b);
        if (rc < 0) die("the text written does not parse again", out.p);
        if (!dns_zone_text_same_zone(a, &b, why, sizeof(why))) {
            fprintf(stderr, "the text written is another zone: %s\n", why);
            die("", out.p);
        }
        zone_arena_destroy(&b);
    }
    free(out.p);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;
    zone_arena_t a;
    int rc;

    parse_text((const char *)data, size, false, &a, &rc);
    if (rc >= 0) {
        zone_arena_drop_unencodable(&a, NULL, NULL);
        roundtrip(&a, DZT_BIND, false);
        zone_arena_drop_out_of_zone(&a, APEX, NULL, NULL);              /* the data file parser leaves them out */
        roundtrip(&a, DZT_TINYDNS, true);
    }
    zone_arena_destroy(&a);

    parse_text((const char *)data, size, true, &a, &rc);
    if (rc >= 0) {
        zone_arena_drop_unencodable(&a, NULL, NULL);
        roundtrip(&a, DZT_AUTO, true);
        roundtrip(&a, DZT_BIND, false);
    }
    zone_arena_destroy(&a);
    return 0;
}

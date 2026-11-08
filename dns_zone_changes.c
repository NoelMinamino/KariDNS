/*
 * dns_zone_changes.c - the change file of `karidns-zone apply` (dns_zone_changes.h).  Ordinary process code (malloc allowed); the server does not link it.
 * The text is hostile input (the WebAdmin renders it from a request; a bug in the renderer must not open a line injection): every field is checked here.
 */
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns_zone_changes.h"
#include "dns_pdns_reader.h"

#define ZC_MAX_RDATA 65535u

static void zc_err(char *err, size_t errlen, size_t line, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void zc_err(char *err, size_t errlen, size_t line, const char *fmt, ...) {
    char msg[300];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (line) snprintf(err, errlen, "line %zu: %s", line, msg);
    else snprintf(err, errlen, "%s", msg);
}

void zc_free(zc_changes_t *c) {
    for (size_t i = 0; i < c->n; i++) {
        free(c->ops[i].owner);
        free(c->ops[i].rdata);
    }
    free(c->ops);
    memset(c, 0, sizeof(*c));
}

/* the types of the signer (RFC 4034 sections 3, 4 and 5, RFC 5155, RFC 7344: the codes 46 47 48 50 51 59 60) and the meta types (RFC 6895 section 3.1: OPT 41, TKEY 249,
 * TSIG 250, IXFR 251, AXFR 252, MAILB 253, MAILA 254, ANY 255) */
bool zc_type_refused(const char *type) {
    static const char *const names[] = { "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY", "CDS", "CDNSKEY", "ANY", "AXFR", "IXFR", "OPT", "TSIG", "TKEY", "MAILA", "MAILB" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcmp(type, names[i]) == 0) return true;
    if (strncmp(type, "TYPE", 4) == 0 && type[4]) {
        unsigned long v = 0;
        for (const char *p = type + 4; *p; p++) {
            if (*p < '0' || *p > '9') return false;
            v = v * 10 + (unsigned long)(*p - '0');
            if (v > 65535) return false;
        }
        switch (v) {
        case 41: case 46: case 47: case 48: case 50: case 51: case 59: case 60: case 249: case 250: case 251: case 252: case 253: case 254: case 255: return true;
        default: return false;
        }
    }
    return false;
}

/* an owner: see dns_zone_changes.h.  out gets it in lower case (256 bytes).  NULL: fine, else why not */
static const char *zc_owner(const char *s, size_t n, const char *zone, char *out) {
    size_t zl = strlen(zone);
    if (n < 2) return "the owner is not an absolute name";
    if (s[n - 1] != '.') return "the owner is not an absolute name (no final dot)";
    if (n - 1 > 253) return "the owner is longer than 253 octets";
    size_t lab = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (lab == 0) return "the owner has an empty label";
            lab = 0;
        } else {
            if (!isalnum(c) && c != '_' && c != '*' && c != '-' && c != '/') return "the owner has a character a change file does not take (letters, digits, '_', '*', '-', '/' and '.')";
            if (++lab > 63) return "a label of the owner is longer than 63 octets";
        }
        out[i] = (char)tolower(c);
    }
    out[n] = '\0';
    if (pdns_text_check(out, n, true) != NULL) return "the owner is not safe in a zone file";
    if (!((n == zl && memcmp(out, zone, zl) == 0) || (n > zl && out[n - zl - 1] == '.' && memcmp(out + n - zl, zone, zl) == 0))) return "the owner is not in the zone";
    return NULL;
}

static const char *zc_type(const char *s, size_t n, char out[33]) {
    if (n == 0 || n > 32 || !isalpha((unsigned char)s[0])) return "not a record type name (letters, digits and '-', first a letter, 32 at most)";
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)s[i]) && s[i] != '-') return "not a record type name (letters, digits and '-', first a letter, 32 at most)";
        out[i] = (char)toupper((unsigned char)s[i]);
    }
    out[n] = '\0';
    if (zc_type_refused(out)) return "a change file does not write this type (DNSSEC types are the signer's, meta types are no data)";
    return NULL;
}

static const char *zc_ttl(const char *s, size_t n, uint32_t *ttl) {
    if (n == 0 || n > 10) return "the TTL is not a decimal number up to 2147483647";
    unsigned long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return "the TTL is not a decimal number up to 2147483647";
        v = v * 10 + (unsigned)(s[i] - '0');
    }
    if (v > 2147483647ull) return "the TTL is larger than 2147483647 (RFC 2181 section 8)";
    *ttl = (uint32_t)v;
    return NULL;
}

static bool zc_blank(char c) { return c == ' ' || c == '\t'; }

/* the next field of the line: skips blanks, sets *tok / *tl, moves *p behind it; false when the line has no more */
static bool zc_field(const char **p, const char *end, const char **tok, size_t *tl) {
    while (*p < end && zc_blank(**p)) (*p)++;
    if (*p >= end) return false;
    *tok = *p;
    while (*p < end && !zc_blank(**p)) (*p)++;
    *tl = (size_t)(*p - *tok);
    return true;
}

static bool zc_push(zc_changes_t *c, zc_op_t *op) {
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 64;
        zc_op_t *nv = realloc(c->ops, nc * sizeof(*nv));
        if (!nv) return false;
        c->ops = nv;
        c->cap = nc;
    }
    c->ops[c->n++] = *op;
    return true;
}

static int zc_cmp_key(const void *x, const void *y) {
    const zc_op_t *a = *(const zc_op_t *const *)x, *b = *(const zc_op_t *const *)y;
    int c = strcmp(a->owner, b->owner);
    if (c) return c;
    c = strcmp(a->type, b->type);
    if (c) return c;
    return a->kind != b->kind ? (a->kind == ZC_DELETE ? -1 : 1) : (a->line < b->line ? -1 : a->line > b->line);
}

bool zc_parse(const char *text, size_t len, const char *zone, zc_changes_t *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    if (memchr(text, '\0', len)) {
        zc_err(err, errlen, 0, "the change file contains a NUL byte");
        return false;
    }
    size_t line = 0;
    const char *p = text, *end = text + len;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        const char *le = eol ? eol : end;
        const char *next = eol ? eol + 1 : end;
        line++;
        if (le > p && le[-1] == '\r') le--;
        if ((size_t)(le - p) > ZC_MAX_LINE) {
            zc_err(err, errlen, line, "the line is longer than %u octets", ZC_MAX_LINE);
            goto bad;
        }
        const char *q = p, *tok;
        size_t tl;
        p = next;
        if (!zc_field(&q, le, &tok, &tl) || tok[0] == '#') continue;
        zc_op_t op;
        memset(&op, 0, sizeof(op));
        op.line = line;
        char owner[256];
        const char *why;
        if (tl == 2 && memcmp(tok, "rr", 2) == 0) op.kind = ZC_RR;
        else if (tl == 6 && memcmp(tok, "delete", 6) == 0) op.kind = ZC_DELETE;
        else {
            zc_err(err, errlen, line, "unknown operation (rr or delete)");
            goto bad;
        }
        if (!zc_field(&q, le, &tok, &tl)) {
            zc_err(err, errlen, line, "the owner is missing");
            goto bad;
        }
        if ((why = zc_owner(tok, tl, zone, owner)) != NULL) {
            zc_err(err, errlen, line, "%s", why);
            goto bad;
        }
        if (op.kind == ZC_RR) {
            if (!zc_field(&q, le, &tok, &tl)) {
                zc_err(err, errlen, line, "the TTL is missing");
                goto bad;
            }
            if ((why = zc_ttl(tok, tl, &op.ttl)) != NULL) {
                zc_err(err, errlen, line, "%s", why);
                goto bad;
            }
        }
        if (!zc_field(&q, le, &tok, &tl)) {
            zc_err(err, errlen, line, "the type is missing");
            goto bad;
        }
        if ((why = zc_type(tok, tl, op.type)) != NULL) {
            zc_err(err, errlen, line, "%s", why);
            goto bad;
        }
        if (op.kind == ZC_RR) {
            while (q < le && zc_blank(*q)) q++;
            const char *re = le;
            while (re > q && zc_blank(re[-1])) re--;
            size_t rl = (size_t)(re - q);
            if (rl == 0) {
                zc_err(err, errlen, line, "the RDATA is missing");
                goto bad;
            }
            if (rl > ZC_MAX_RDATA) {
                zc_err(err, errlen, line, "the RDATA is longer than %u octets", ZC_MAX_RDATA);
                goto bad;
            }
            if ((why = pdns_text_check(q, rl, false)) != NULL) {
                zc_err(err, errlen, line, "the RDATA is not safe in a zone file (%s)", why);
                goto bad;
            }
            if (!(op.rdata = malloc(rl + 1))) goto oom;
            memcpy(op.rdata, q, rl);
            op.rdata[rl] = '\0';
        } else if (zc_field(&q, le, &tok, &tl)) {
            zc_err(err, errlen, line, "a delete line takes an owner and a type and nothing more");
            goto bad;
        }
        if (out->n >= ZC_MAX_OPS) {
            zc_err(err, errlen, line, "more than %u operations", ZC_MAX_OPS);
            free(op.rdata);
            goto bad;
        }
        if (!(op.owner = strdup(owner))) {
            free(op.rdata);
            goto oom;
        }
        if (!zc_push(out, &op)) {
            free(op.owner);
            free(op.rdata);
            goto oom;
        }
        if (op.kind == ZC_RR) out->n_rr++;
        else out->n_delete++;
    }
    /* an RRset that is replaced and deleted in one change file is a mistake */
    if (out->n_rr && out->n_delete) {
        zc_op_t **idx = malloc(out->n * sizeof(*idx));
        if (!idx) goto oom;
        for (size_t i = 0; i < out->n; i++) idx[i] = &out->ops[i];
        qsort(idx, out->n, sizeof(*idx), zc_cmp_key);
        for (size_t i = 0; i + 1 < out->n; i++) {
            const zc_op_t *a = idx[i], *b = idx[i + 1];
            if (a->kind == ZC_DELETE && b->kind == ZC_RR && strcmp(a->owner, b->owner) == 0 && strcmp(a->type, b->type) == 0) {
                zc_err(err, errlen, a->line, "%s %s is deleted here and has rr lines (line %zu)", a->owner, a->type, b->line);
                free(idx);
                goto bad;
            }
        }
        free(idx);
    }
    return true;
oom:
    zc_err(err, errlen, 0, "out of memory");
bad:
    zc_free(out);
    return false;
}

char *zc_zone_text(const zc_changes_t *c, const char *zone, size_t *len) {
    size_t cap = 16 + strlen(zone);
    for (size_t i = 0; i < c->n; i++)
        if (c->ops[i].kind == ZC_RR) cap += strlen(c->ops[i].owner) + strlen(c->ops[i].type) + strlen(c->ops[i].rdata) + 24;
    char *buf = malloc(cap + 1);
    if (!buf) return NULL;
    size_t o = (size_t)snprintf(buf, cap, "$ORIGIN %s\n", zone);
    for (size_t i = 0; i < c->n; i++) {
        const zc_op_t *op = &c->ops[i];
        if (op->kind != ZC_RR) continue;
        o += (size_t)snprintf(buf + o, cap + 1 - o, "%s %u IN %s %s\n", op->owner, (unsigned)op->ttl, op->type, op->rdata);
    }
    *len = o;
    return buf;
}

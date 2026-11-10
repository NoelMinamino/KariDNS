/*
 * dns_zone_render.c - stored PowerDNS records as canonical presentation text (see dns_zone_render.h).
 *
 * One record = one small zone: a synthetic apex SOA (the reader wants one) and the record's row, read by the loader's reader (dns_pdns_reader.c: line
 * safety, the priority of MX and SRV, the zone parser) and written by dns_zone_text_rrset_lines() (RFC 4034 section 6.2 canonical form of the names,
 * quoted strings, RFC 3597 section 5 for generic RDATA).  The first two words of its line ("<ttl> <TYPE> ") are cut off: the caller has the TTL and the type.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns_pdns_reader.h"
#include "dns_zone_render.h"
#include "dns_zone_text.h"

/* the SOA the reader needs at the apex; the names are under .invalid (RFC 6761 section 6.4) and never leave this file */
#define ZR_SOA "ns.invalid. hostmaster.invalid. 1 3600 600 86400 300"

typedef struct {
    const char *owner, *type, *content;
    size_t owner_len, type_len, content_len;
    bool prio_null;
    int64_t prio;
} zr_line_t;

/* One line (no LF) -> its fields.  false: why. */
static bool zr_split(const char *s, size_t len, zr_line_t *l, const char **why) {
    const char *f[3];
    size_t fl[3];
    size_t pos = 0;
    for (int i = 0; i < 3; i++) {
        const char *tab = memchr(s + pos, '\t', len - pos);
        if (!tab) {
            *why = "the line has fewer than four fields (owner, type, prio, content)";
            return false;
        }
        f[i] = s + pos;
        fl[i] = (size_t)(tab - (s + pos));
        pos = (size_t)(tab - s) + 1;
    }
    l->owner = f[0];
    l->owner_len = fl[0];
    l->type = f[1];
    l->type_len = fl[1];
    l->content = s + pos;
    l->content_len = len - pos;
    if (l->owner_len == 0 || l->type_len == 0) {
        *why = "the owner or the type is empty";
        return false;
    }
    /* the prio: '-' alone is NULL, else an optional '-' and 1 to 18 digits */
    const char *p = f[2];
    size_t pl = fl[2];
    l->prio_null = pl == 1 && p[0] == '-';
    l->prio = 0;
    if (!l->prio_null) {
        bool neg = pl > 0 && p[0] == '-';
        size_t d = neg ? 1 : 0;
        if (pl - d < 1 || pl - d > 18) {
            *why = "the prio is not a number";
            return false;
        }
        for (; d < pl; d++) {
            if (p[d] < '0' || p[d] > '9') {
                *why = "the prio is not a number";
                return false;
            }
            l->prio = l->prio * 10 + (p[d] - '0');
        }
        if (neg) l->prio = -l->prio;
    }
    return true;
}

/* a copy of s[0..n) as a C string, or NULL */
static char *zr_dup(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

/* The reader's message is "zone 'x.test.' records.id 2: why": the zone and the number of the row are ours, not the caller's; what is left is why */
static void zr_reason(char *err, const char *msg) {
    const char *why = strstr(msg, "records.id ");
    why = why ? strstr(why, ": ") : NULL;
    snprintf(err, ZR_ERR_LEN, "%.200s", why ? why + 2 : msg);
}

/* One record through the loader's reader: the record as the zone parser makes it, inside a zone of its own (*pz, to be freed; *rec points into it).
 * 0, 1 (the reader refuses it: err says why) or -1 (out of memory) */
static int zr_read(const char *zone, const char *owner, const char *type, bool prio_null, int64_t prio, const char *content, pdns_zone_t **pz, const dns_record_t **rec,
                   char *err) {
    pdns_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.default_ttl = 3600;
    *pz = pdns_zone_new(zone, &opts);
    if (!*pz) return -1;
    const bool is_soa = strcasecmp(type, "SOA") == 0;
    if (!is_soa) {                                          /* a zone needs its SOA; ours is row 0 and has nothing to do with the record */
        db_record_row_t soa;
        memset(&soa, 0, sizeof(soa));
        soa.id = 1;
        soa.name = zone;
        soa.type = "SOA";
        soa.content = ZR_SOA;
        soa.ttl = 3600;
        if (pdns_zone_add_record(*pz, &soa) != 0) {
            zr_reason(err, (*pz)->error);
            return 1;
        }
    }
    db_record_row_t row;
    memset(&row, 0, sizeof(row));
    row.id = 2;
    row.name = owner;
    row.type = type;
    row.content = content;
    row.ttl = 3600;
    row.prio = prio;
    row.prio_null = prio_null;
    if (pdns_zone_add_record(*pz, &row) != 0 || pdns_zone_finish(*pz) != 0) {
        zr_reason(err, (*pz)->error);
        return 1;
    }
    const size_t idx = is_soa ? 0 : 1;
    if ((*pz)->n_rows != idx + 1 || (*pz)->arena.count != (*pz)->n_rows) {
        snprintf(err, ZR_ERR_LEN, "the loader's reader made %zu records of the row", (*pz)->arena.count);
        return 1;
    }
    *rec = &(*pz)->arena.records[idx];
    return 0;
}

/* One record -> its text (malloc'd), or NULL with err.  false only when memory ran out.
 * The text is only given when it is the record: it is read again (as a record with the priority in its content, which is how a change set will bring it back)
 * and must be the same type and the same canonical RDATA (RFC 4034 section 6.2).  The zone-file writer is the exporter's, whose verification does the same for
 * a whole zone; a text that does not survive this (a writer that escapes twice, say) is not offered, and the caller keeps the stored content. */
static bool zr_one(const char *zone, const zr_line_t *l, zr_result_t *res) {
    char *owner = zr_dup(l->owner, l->owner_len), *type = zr_dup(l->type, l->type_len), *content = zr_dup(l->content, l->content_len);
    pdns_zone_t *pz = NULL, *pz2 = NULL;
    char *lines = NULL, *text = NULL;
    uint8_t *wire = NULL;
    bool oom = false;
    if (!owner || !type || !content) {
        oom = true;
        goto out;
    }
    /* a NUL inside a field would end the C string early: the reader checks what it is given, so a field that has one is refused here */
    if (strlen(owner) != l->owner_len || strlen(type) != l->type_len || strlen(content) != l->content_len) {
        snprintf(res->err, sizeof(res->err), "the record has a NUL byte");
        goto out;
    }
    /* PowerDNS ALIAS and LUA (dns_pdns_reader.h, rule 3) are stored as a name or a script; their RFC 3597 form (TYPE65401 \# 8 ...) is not what a change set
     * takes under the name ALIAS, so there would be no text that goes back in: the caller keeps the stored content for them */
    if (strcasecmp(type, "ALIAS") == 0 || strcasecmp(type, "LUA") == 0) {
        snprintf(res->err, sizeof(res->err), "%s records are shown as stored, they have no other form", type);
        goto out;
    }
    const dns_record_t *rec = NULL, *rec2 = NULL;
    int rc = zr_read(zone, owner, type, l->prio_null, l->prio, content, &pz, &rec, res->err);
    if (rc != 0) {
        oom = rc < 0;
        goto out;
    }
    char err[ZR_ERR_LEN];
    err[0] = '\0';
    lines = dns_zone_text_rrset_lines(&rec, 1, err, sizeof(err));
    if (!lines) {
        snprintf(res->err, sizeof(res->err), "%s", err[0] ? err : "out of memory");
        goto out;
    }
    /* "<ttl> <TYPE> <rdata>": the rdata is what follows the second blank (a record always has some) */
    const char *sp = strchr(lines, ' ');
    sp = sp ? strchr(sp + 1, ' ') : NULL;
    if (!sp || !sp[1] || strpbrk(sp + 1, "\r\n")) {
        snprintf(res->err, sizeof(res->err), "the record has no text form");
        goto out;
    }
    text = strdup(sp + 1);
    if (!text) {
        oom = true;
        goto out;
    }
    rc = zr_read(zone, owner, type, true, 0, text, &pz2, &rec2, err);
    if (rc < 0) {
        oom = true;
        goto out;
    }
    if (rc > 0) {
        snprintf(res->err, sizeof(res->err), "the text form does not read back (%.150s), the record is shown as stored", err);
        goto out;
    }
    wire = malloc(2 * 65535u);
    if (!wire) {
        oom = true;
        goto out;
    }
    long w1 = dns_record_canonical_rdata(rec, wire, 65535), w2 = dns_record_canonical_rdata(rec2, wire + 65535, 65535);
    if (rec->type_code != rec2->type_code || w1 < 0 || w1 != w2 || memcmp(wire, wire + 65535, (size_t)w1) != 0) {
        snprintf(res->err, sizeof(res->err), "the text form reads back as another record, the record is shown as stored");
        goto out;
    }
    res->rdata = text;
    text = NULL;
out:
    free(wire);
    free(text);
    free(lines);
    pdns_zone_free(pz2);
    pdns_zone_free(pz);
    free(owner);
    free(type);
    free(content);
    return !oom;
}

void zr_free(zr_result_t *r, size_t n) {
    if (!r) return;
    for (size_t i = 0; i < n; i++) free(r[i].rdata);
    free(r);
}

int zr_render(const char *zone, const char *text, size_t len, zr_result_t **out, size_t *n, char *err, size_t errlen) {
    *out = NULL;
    *n = 0;
    size_t lines = 0;
    for (size_t i = 0; i < len; i++)
        if (text[i] == '\n') lines++;
    if (len > 0 && text[len - 1] != '\n') lines++;                  /* the last line may lack its LF */
    if (lines > ZR_MAX_RECORDS) {
        snprintf(err, errlen, "more than %u records", ZR_MAX_RECORDS);
        return -1;
    }
    char *zdup = zr_dup(zone, strlen(zone));
    zr_result_t *res = calloc(lines ? lines : 1, sizeof(*res));
    if (!zdup || !res) {
        free(zdup);
        free(res);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    size_t k = 0, pos = 0;
    while (pos < len) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t ll = nl ? (size_t)(nl - (text + pos)) : len - pos;
        zr_line_t l;
        const char *why = NULL;
        if (!zr_split(text + pos, ll, &l, &why)) {
            snprintf(err, errlen, "line %zu: %s", k + 1, why);
            goto fail;
        }
        if (!zr_one(zdup, &l, &res[k])) {
            snprintf(err, errlen, "out of memory");
            goto fail;
        }
        k++;
        pos += ll + 1;
    }
    free(zdup);
    *out = res;
    *n = k;
    return 0;
fail:
    free(zdup);
    zr_free(res, k + 1);
    return -1;
}

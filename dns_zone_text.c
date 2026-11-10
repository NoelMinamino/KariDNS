/*
 * dns_zone_text.c - a parsed zone -> zone file text (BIND format or tinydns data file); see dns_zone_text.h.
 * Ordinary process code (malloc allowed); every name, string and tag of the zone is untrusted.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "dns_zone_text.h"
#include "dns_zone_rows.h"
#include "dns_wire.h"
#include "dns_utils.h"

/* ------------------------------------------------------------------------------------------------------------- */
/* output buffer                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

#define DZT_FLUSH_AT 65536

typedef struct {
    char *p;
    size_t len, cap;
    bool oom;
    dzt_sink_t sink;            /* stream mode (no_verify): handed over whenever DZT_FLUSH_AT bytes are there */
    void *ud;
    bool stream;
    bool sink_failed;
} dzt_out_t;

static void out_add(dzt_out_t *o, const char *s, size_t n) {
    if (o->oom) return;
    if (o->len + n + 1 > o->cap) {
        size_t nc = o->cap ? o->cap : 4096;
        while (nc < o->len + n + 1) nc *= 2;
        char *np = realloc(o->p, nc);
        if (!np) {
            o->oom = true;
            return;
        }
        o->p = np;
        o->cap = nc;
    }
    memcpy(o->p + o->len, s, n);
    o->len += n;
    o->p[o->len] = '\0';
}
static void out_adds(dzt_out_t *o, const char *s) { out_add(o, s, strlen(s)); }
static void out_addc(dzt_out_t *o, char c) { out_add(o, &c, 1); }

static void out_addf(dzt_out_t *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void out_addf(dzt_out_t *o, const char *fmt, ...) {
    char tmp[64];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < sizeof(tmp)) out_add(o, tmp, (size_t)n);
    else o->oom = true;                    /* only short numbers are formatted here: never reached */
}

/* a line is complete: in stream mode hand the text over once enough has been made */
static void out_line_end(dzt_out_t *o) {
    if (!o->stream || o->len < DZT_FLUSH_AT || o->oom || o->sink_failed) return;
    if (o->sink(o->ud, o->p, o->len) != 0) o->sink_failed = true;
    o->len = 0;
    o->p[0] = '\0';
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the writer state                                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    const dns_record_t *r;
    size_t idx;                 /* position in the arena */
    size_t off;                 /* canonical RDATA in the pool */
    const uint8_t *rd;
    uint16_t rdlen;
} dzt_key_t;

typedef struct {
    const zone_arena_t *arena;
    char apex[DNS_NAME_TEXT_SIZE];      /* canonical absolute */
    size_t apex_len;
    bool apex_root;
    bool absolute_only;                 /* dns_zone_text_rrset_lines(): no origin at all, every name is written absolute (the root as ".", never "@") */
    dzt_out_t out;
    char *err;
    size_t errlen;
    dzt_key_t *keys;                    /* sorted */
    uint8_t *pool;
} dzt_t;

/* printable text of an untrusted string for a message */
static void show(const char *s, char *out, size_t cap) {
    size_t w = 0;
    for (; s && *s && w + 1 < cap; s++) out[w++] = (*s >= 0x20 && *s < 0x7F) ? *s : '?';
    out[w] = '\0';
}

static void fail_msg(char *err, size_t errlen, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void fail_msg(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* "record 12 (www.example.test. A): <why>" */
static void fail_rec(char *err, size_t errlen, const dzt_key_t *k, const char *why) {
    char own[80];
    show(k->r->name, own, sizeof(own));
    fail_msg(err, errlen, "record %zu (%s %s): %s", k->idx + 1, own, dns_type_to_string(k->r->type_code), why);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* canonical order (RFC 4034 section 6)                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static int cmp_str_null(const char *a, const char *b) {
    if (!a || !b) return (a != NULL) - (b != NULL);
    return strcmp(a, b);
}

static uint16_t class_of(const dns_record_t *r) { return r->class_val ? r->class_val : 1; }

static int key_cmp(const void *pa, const void *pb) {
    const dzt_key_t *a = pa, *b = pb;
    const dns_record_t *x = a->r, *y = b->r;
    int c = compare_canonical_name(x->name, y->name);                           /* RFC 4034 section 6.1 */
    if (c) return c;
    if (x->type_code != y->type_code) return x->type_code < y->type_code ? -1 : 1;
    if (class_of(x) != class_of(y)) return class_of(x) < class_of(y) ? -1 : 1;
    size_t n = a->rdlen < b->rdlen ? a->rdlen : b->rdlen;                       /* RFC 4034 section 6.3: RDATA as left-justified octets */
    if (n && (c = memcmp(a->rd, b->rd, n)) != 0) return c;
    if (a->rdlen != b->rdlen) return a->rdlen < b->rdlen ? -1 : 1;
    /* the rest only makes the order total, so two arenas holding the same records sort the same */
    if (x->ttl_value != y->ttl_value) return x->ttl_value < y->ttl_value ? -1 : 1;
    if ((c = cmp_str_null(x->bind_location_tag, y->bind_location_tag)) != 0) return c;
    if ((c = cmp_str_null(x->ecs_subnet_tag, y->ecs_subnet_tag)) != 0) return c;
    if (x->tinydns_ttd != y->tinydns_ttd) return x->tinydns_ttd < y->tinydns_ttd ? -1 : 1;
    if (x->tinydns_ttl_countdown != y->tinydns_ttl_countdown) return x->tinydns_ttl_countdown ? 1 : -1;
    if ((c = memcmp(x->tinydns_loc, y->tinydns_loc, 2)) != 0) return c;
    return strcmp(x->name, y->name);                                            /* the owner byte for byte, case included */
}

/* the records of an arena in canonical order, each with its canonical RDATA; NULL: *err says why (a record that cannot be encoded) */
static dzt_key_t *build_keys(const zone_arena_t *arena, uint8_t **pool_out, char *err, size_t errlen) {
    size_t n = arena->count;
    dzt_key_t *keys = calloc(n ? n : 1, sizeof(*keys));
    uint8_t *tmp = malloc(65535);
    uint8_t *pool = NULL;
    size_t plen = 0, pcap = 0;
    if (!keys || !tmp) {
        fail_msg(err, errlen, "out of memory");
        goto bad;
    }
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = &arena->records[i];
        dzt_key_t *k = &keys[i];
        k->r = r;
        k->idx = i;
        if (!r->name) {
            fail_msg(err, errlen, "record %zu: no owner name", i + 1);
            goto bad;
        }
        for (int j = 0; j < r->rdata_count; j++) {                  /* the encoder reads every field */
            if (!r->rdata || !r->rdata[j]) {
                fail_rec(err, errlen, k, "a missing RDATA field");
                goto bad;
            }
        }
        long rl = dns_record_canonical_rdata(r, tmp, 65535);
        if (rl < 0) {
            fail_rec(err, errlen, k, "the RDATA cannot be encoded");
            goto bad;
        }
        if (plen + (size_t)rl > pcap) {
            size_t nc = pcap ? pcap : 65536;
            while (nc < plen + (size_t)rl) nc *= 2;
            uint8_t *np = realloc(pool, nc);
            if (!np) {
                fail_msg(err, errlen, "out of memory");
                goto bad;
            }
            pool = np;
            pcap = nc;
        }
        if (rl) memcpy(pool + plen, tmp, (size_t)rl);
        k->off = plen;
        k->rdlen = (uint16_t)rl;
        plen += (size_t)rl;
    }
    for (size_t i = 0; i < n; i++) keys[i].rd = pool ? pool + keys[i].off : NULL;
    qsort(keys, n, sizeof(*keys), key_cmp);
    free(tmp);
    *pool_out = pool;
    return keys;
bad:
    free(tmp);
    free(pool);
    free(keys);
    return NULL;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* tokens of the BIND format                                                                                      */
/* ------------------------------------------------------------------------------------------------------------- */

/* A token with nothing in it that the zone-file lexer or the parser reads as something else: no blank, control character, quote,
 * backslash, ';' '(' ')' (RFC 1035 section 5.1), no '$' (directive) or '@' (the origin) and no brace (tag definitions). */
static bool plain_ok(const char *s, size_t n) {
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c >= 0x7F || strchr("\"\\;()$@{}", c)) return false;
    }
    return true;
}

/* the bytes of s inside quotes: \" \\ and \DDD (RFC 1035 section 5.1) for the rest that is not printable ASCII */
static void put_quoted_body(dzt_out_t *o, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            out_addc(o, '\\');
            out_addc(o, (char)c);
        } else if (c < 0x20 || c >= 0x7F) {
            out_addf(o, "\\%03u", (unsigned)c);
        } else {
            out_addc(o, (char)c);
        }
    }
}

static void put_quoted(dzt_out_t *o, const char *s) {
    out_addc(o, '"');
    put_quoted_body(o, s, strlen(s));
    out_addc(o, '"');
}

/* s as one token: bare when nothing in it needs care, else quoted (the parser unquotes and unescapes it) */
static void put_token(dzt_out_t *o, const char *s) {
    if (plain_ok(s, strlen(s))) out_adds(o, s);
    else put_quoted(o, s);
}

/* is the name in the canonical text form of dns_wire.h (so that it holds no blank, control character or unescaped special)? */
static bool name_canonical(const char *name) {
    char norm[DNS_NAME_TEXT_SIZE];
    size_t n = dns_name_normalize(name, norm, sizeof(norm));
    return n != (size_t)-1 && strcmp(norm, name) == 0;
}

/* 0: outside the zone, 1: the apex, 2: below it (*relen = the length of the part before the apex).  Only an exact match of the suffix is
 * relative, so reading the text gives the very same bytes back (the parser appends the $ORIGIN text). */
static int name_rel(const dzt_t *z, const char *name, size_t *relen) {
    size_t nl = strlen(name);
    if (z->absolute_only) return 0;
    if (z->apex_root) return (nl == 1 && name[0] == '.') ? 1 : 0;
    if (nl == z->apex_len && memcmp(name, z->apex, nl) == 0) return 1;
    if (nl > z->apex_len + 1 && memcmp(name + nl - z->apex_len, z->apex, z->apex_len) == 0) {
        size_t dot = nl - z->apex_len - 1;
        if (name[dot] == '.' && !dns_char_is_escaped(name, dot)) {
            *relen = dot;
            return 2;
        }
    }
    return 0;
}

/* a canonical name as a token of the zone file: "@", relative (inside the zone) or absolute, with ; " ( ) $ @ escaped again; false: not usable */
static bool put_name(dzt_t *z, const char *name) {
    size_t relen = 0;
    char tmp[DNS_NAME_TEXT_SIZE], tok[2 * DNS_NAME_TEXT_SIZE];
    if (!name_canonical(name)) return false;
    int k = name_rel(z, name, &relen);
    if (k == 1) {
        out_addc(&z->out, '@');
        return true;
    }
    const char *src = name;
    if (k == 2) {
        memcpy(tmp, name, relen);
        tmp[relen] = '\0';
        src = tmp;
    }
    size_t n = dns_name_zone_token(src, tok, sizeof(tok));
    if (n == (size_t)-1) return false;
    out_add(&z->out, tok, n);
    return true;
}

/* a name the parser keeps as typed (ZF_ABS): the absolute form, so that another server does not append the $ORIGIN to it */
static void put_abs_name(dzt_t *z, const char *name) {
    size_t n = strlen(name);
    char tmp[DNS_NAME_TEXT_SIZE + 2];
    if (n == 0 || name[n - 1] == '.' || n >= DNS_NAME_TEXT_SIZE) {
        put_token(&z->out, name);
        return;
    }
    memcpy(tmp, name, n);
    tmp[n] = '.';
    tmp[n + 1] = '\0';
    put_token(&z->out, tmp);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* tags and definitions                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

/* a tag name: 1-63 printable characters, none of those the lexer reads as something else; "none" and "default" clear a tag */
static bool tag_ok(const char *t) {
    size_t n = strlen(t);
    if (n == 0 || n > 63 || strcasecmp(t, "none") == 0 || strcasecmp(t, "default") == 0) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)t[i];
        if (c <= 0x20 || c >= 0x7F || strchr("\"\\;(){}$", c)) return false;
    }
    return true;
}

static bool cidr_ok(const char *c) {
    size_t n = strlen(c);
    if (n == 0 || n > 100) return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)c[i]) && c[i] != ':' && c[i] != '.' && c[i] != '/') return false;
    return true;
}

static bool put_tag_defs(dzt_t *z, const char *directive, const ecs_tag_def_t *defs, int n) {
    for (int i = 0; i < n; i++) {
        if (!defs[i].tag || !tag_ok(defs[i].tag) || defs[i].cidr_count <= 0) {
            char t[80];
            show(defs[i].tag, t, sizeof(t));
            fail_msg(z->err, z->errlen, "%s definition %d ('%s'): not a tag name, or no CIDR", directive, i + 1, t);
            return false;
        }
        out_addf(&z->out, "%s ", directive);
        out_adds(&z->out, defs[i].tag);
        for (int j = 0; j < defs[i].cidr_count; j++) {
            if (!defs[i].cidrs[j].cidr || !cidr_ok(defs[i].cidrs[j].cidr)) {
                char t[80];
                show(defs[i].tag, t, sizeof(t));
                fail_msg(z->err, z->errlen, "%s definition %d ('%s'): CIDR %d is not an address prefix", directive, i + 1, t, j + 1);
                return false;
            }
            out_addc(&z->out, ' ');
            out_adds(&z->out, defs[i].cidrs[j].cidr);
        }
        out_addc(&z->out, '\n');
        out_line_end(&z->out);
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* BIND format                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

static const char *type_token(uint16_t code, char *buf, size_t cap) {
    const char *t = dns_type_to_string(code);
    if (get_type_code(t) == code) return t;
    snprintf(buf, cap, "TYPE%u", (unsigned)code);
    return buf;
}

static void put_hex(dzt_out_t *o, const uint8_t *b, size_t n) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out_addc(o, d[b[i] >> 4]);
        out_addc(o, d[b[i] & 15]);
    }
}

/* the RDATA of a record; NULL, or why it cannot be written */
static const char *put_rdata(dzt_t *z, const dns_record_t *r) {
    dzt_out_t *o = &z->out;
    if (r->generic_data) {                                         /* RFC 3597 section 5 */
        out_addf(o, "\\# %u", (unsigned)r->generic_len);
        if (r->generic_len) {
            out_addc(o, ' ');
            put_hex(o, r->generic_data, r->generic_len);
        }
        return NULL;
    }
    if (r->rdata_count <= 0) return "no RDATA";
    int lead = zrows_blob_lead(r->type_code);
    for (int j = 0; j < r->rdata_count; j++) {
        if (j) out_addc(o, ' ');
        if (lead >= 0 && j == lead) {                              /* a split base64 / hex value: one token */
            bool plain = true;
            size_t total = 0;
            for (int m = j; m < r->rdata_count; m++) {
                size_t l = strlen(r->rdata[m]);
                total += l;
                if (l && !plain_ok(r->rdata[m], l)) plain = false;
            }
            if (!plain || total == 0) {
                out_addc(o, '"');
                for (int m = j; m < r->rdata_count; m++) put_quoted_body(o, r->rdata[m], strlen(r->rdata[m]));
                out_addc(o, '"');
            } else {
                for (int m = j; m < r->rdata_count; m++) out_adds(o, r->rdata[m]);
            }
            break;
        }
        unsigned ff = zrows_field_flags(r, j);
        if (ff & ZF_NAME) {
            if (!put_name(z, r->rdata[j])) return "a name in the RDATA is not in the canonical text form";
        } else if (ff & ZF_ABS) {
            put_abs_name(z, r->rdata[j]);
        } else if (ff & ZF_STRING) {
            put_quoted(o, r->rdata[j]);
        } else {
            put_token(o, r->rdata[j]);
        }
    }
    return NULL;
}

static bool same_tag(const char *a, const char *b) { return (a == NULL && b == NULL) || (a && b && strcmp(a, b) == 0); }

/* the numbers of an SOA as the zone-file parser takes them: a serial up to 4294967295, TTL-like times (the data file parser keeps larger ones) */
static bool soa_numbers_ok(const dns_record_t *r) {
    uint32_t v;
    if (r->type_code != 6 || r->rdata_count != 7 || r->generic_data) return true;
    if (!parse_soa_serial_strict(r->rdata[2], &v, NULL)) return false;
    for (int j = 3; j < 7; j++)
        if (!parse_ttl_strict(r->rdata[j], 0xFFFFFFFFu, &v)) return false;
    return true;
}

/* "$LOCATION tag" or "$LOCATION none" */
static void put_directive(dzt_out_t *o, const char *name, const char *tag) {
    out_adds(o, name);
    out_addc(o, ' ');
    out_adds(o, tag ? tag : "none");
    out_addc(o, '\n');
}

/* state of the $LOCATION / $ECS-SUBNET directives while the records are written */
typedef struct { const char *loc, *ecs; } dzt_tagstate_t;

static bool put_record_bind(dzt_t *z, const dzt_key_t *k, uint32_t def_ttl, dzt_tagstate_t *st) {
    const dns_record_t *r = k->r;
    dzt_out_t *o = &z->out;
    char tb[32];
    const char *why;
    if (r->tinydns_ttd || r->tinydns_loc[0] || r->tinydns_loc[1] || r->tinydns_ttl_countdown) {
        fail_rec(z->err, z->errlen, k, "has a tinydns time stamp or location code, which the BIND format cannot hold (write the zone as a tinydns data file)");
        return false;
    }
    if (!soa_numbers_ok(r)) {
        fail_rec(z->err, z->errlen, k, "the SOA serial or times are not numbers a zone file can hold");
        return false;
    }
    if ((r->bind_location_tag && !tag_ok(r->bind_location_tag)) || (r->ecs_subnet_tag && !tag_ok(r->ecs_subnet_tag))) {
        fail_rec(z->err, z->errlen, k, "its $LOCATION / $ECS-SUBNET tag is not a usable tag name");
        return false;
    }
    if (!same_tag(st->loc, r->bind_location_tag)) {
        put_directive(o, "$LOCATION", r->bind_location_tag);
        st->loc = r->bind_location_tag;
    }
    if (!same_tag(st->ecs, r->ecs_subnet_tag)) {
        put_directive(o, "$ECS-SUBNET", r->ecs_subnet_tag);
        st->ecs = r->ecs_subnet_tag;
    }
    if (!put_name(z, r->name)) {
        fail_rec(z->err, z->errlen, k, "the owner name is not in the canonical text form");
        return false;
    }
    out_addc(o, ' ');
    if (r->ttl_value != def_ttl) out_addf(o, "%u ", (unsigned)r->ttl_value);
    if (class_of(r) != 1) {
        char cb[24];
        out_adds(o, dns_class_text(class_of(r), cb, sizeof(cb)));
        out_addc(o, ' ');
    }
    out_adds(o, type_token(r->type_code, tb, sizeof(tb)));
    out_addc(o, ' ');
    if ((why = put_rdata(z, r)) != NULL) {
        fail_rec(z->err, z->errlen, k, why);
        return false;
    }
    out_addc(o, '\n');
    out_line_end(o);
    return true;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* the TTL most records have (the smallest of equally many): the $TTL, so that most lines need no TTL of their own */
static uint32_t pick_default_ttl(const dzt_key_t *keys, size_t n) {
    if (n == 0) return 3600;
    uint32_t *t = malloc(n * sizeof(*t));
    if (!t) return 3600;
    for (size_t i = 0; i < n; i++) t[i] = keys[i].r->ttl_value;
    qsort(t, n, sizeof(*t), cmp_u32);
    size_t best = 0, bestn = 0;
    for (size_t i = 0; i < n;) {
        size_t j = i;
        while (j < n && t[j] == t[i]) j++;
        if (j - i > bestn) {
            bestn = j - i;
            best = i;
        }
        i = j;
    }
    uint32_t v = t[best];
    free(t);
    return v;
}

static bool write_bind(dzt_t *z) {
    const zone_arena_t *a = z->arena;
    if (a->location_count > 0) {
        fail_msg(z->err, z->errlen, "the zone has tinydns location definitions (%% lines), which the BIND format cannot hold (write the zone as a tinydns data file)");
        return false;
    }
    char tok[2 * DNS_NAME_TEXT_SIZE];
    if (dns_name_zone_token(z->apex, tok, sizeof(tok)) == (size_t)-1) {
        fail_msg(z->err, z->errlen, "the zone name is not usable");
        return false;
    }
    uint32_t def_ttl = pick_default_ttl(z->keys, a->count);
    out_adds(&z->out, "$ORIGIN ");
    out_adds(&z->out, tok);
    out_addf(&z->out, "\n$TTL %u\n", (unsigned)def_ttl);
    if (!put_tag_defs(z, "$LOCATION-TAG", a->bind_location_tags, a->bind_location_tag_count) ||
        !put_tag_defs(z, "$ECS-SUBNET-TAG", a->bind_ecs_tags, a->bind_ecs_tag_count))
        return false;
    dzt_tagstate_t st = { NULL, NULL };
    for (size_t i = 0; i < a->count; i++)
        if (!put_record_bind(z, &z->keys[i], def_ttl, &st)) return false;
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* tinydns data file                                                                                              */
/* ------------------------------------------------------------------------------------------------------------- */

/* One byte of a tinydns field: printable characters as they are, except the field separator, the escape character and the blank; the rest
 * as \ooo (octal, three digits: dns_tinydns_parser.c reads at most three) */
static void td_byte(dzt_out_t *o, uint8_t b, bool in_name) {
    if (b > 0x20 && b < 0x7F && b != ':' && b != '\\' && !(in_name && b == '.')) out_addc(o, (char)b);
    else out_addf(o, "\\%03o", (unsigned)b);
}

/* a canonical name as the FQDN field (labels separated by dots, a dot at the end, the root as "."); false: not a name */
static bool td_name(dzt_out_t *o, const char *name) {
    uint8_t wire[256];
    if (!name_canonical(name)) return false;
    long w = write_uncompressed_name_ext(wire, 0, sizeof(wire), name, false);
    if (w <= 0) return false;
    if (wire[0] == 0) {
        out_addc(o, '.');
        return true;
    }
    for (size_t p = 0; p < (size_t)w && wire[p] != 0; p += 1 + wire[p]) {
        for (size_t i = 0; i < wire[p]; i++) td_byte(o, wire[p + 1 + i], true);
        out_addc(o, '.');
    }
    return true;
}

static void td_bytes(dzt_out_t *o, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) td_byte(o, b[i], false);
}

/* the wire RDATA of a record as written, names with the case they have (dns_record_canonical_rdata() lowers them) */
static long rdata_wire(const dns_record_t *r, uint8_t *buf, size_t cap) {
    uint16_t len = 0;
    if (cap > 65535) cap = 65535;
    if (serialize_dns_record(buf, cap, &len, r, NULL, ".", 0xFFFFFFFF) != 0) return -1;
    if (len < 11 || buf[0] != 0) return -1;
    size_t rdlen = ((size_t)buf[9] << 8) | buf[10];
    if (11 + rdlen != len) return -1;
    memmove(buf, buf + 11, rdlen);
    return (long)rdlen;
}

static bool all_digits(const char *s) {
    if (!*s) return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return false;
    return true;
}

/* the TXT strings are what the data file parser makes of the text: the bytes cut into pieces of 127 (an empty text is one empty string) */
static bool txt_is_tinydns_shaped(const dns_record_t *r) {
    if (r->rdata_count < 1 || r->rdata_count > MAX_RDATA) return false;
    size_t total = 0;
    for (int j = 0; j < r->rdata_count; j++) {
        size_t l = strlen(r->rdata[j]);
        if (l > 127 || (j + 1 < r->rdata_count && l != 127) || (l == 0 && r->rdata_count > 1)) return false;
        total += l;
    }
    return total <= (size_t)MAX_RDATA * 127;
}

/* ":<time stamp>:<location>" of every line; false (and why) for what the data file cannot say */
static const char *td_attrs(dzt_out_t *o, const dns_record_t *r) {
    bool has_ts = r->tinydns_ttd != 0 || r->tinydns_ttl_countdown;
    if (r->tinydns_ttd < 0) return "has a negative time stamp";
    if (has_ts && r->tinydns_ttl_countdown != (r->ttl_value == 0))
        return "has a time stamp that the data file cannot say (a countdown TTL is TTL 0 with a time stamp, and only that)";
    for (int i = 0; i < 2; i++) {
        unsigned char c = (unsigned char)r->tinydns_loc[i];
        if (c && (c <= 0x20 || c >= 0x7F || c == ':')) return "has a location code with a character the data file cannot hold";
    }
    if (r->tinydns_loc[0] == 0 && r->tinydns_loc[1] != 0) return "has a location code that does not start at the first character";
    out_addc(o, ':');
    if (has_ts) out_addf(o, "%016llx", (unsigned long long)(0x4000000000000000ULL + (uint64_t)r->tinydns_ttd));
    out_addc(o, ':');
    if (r->tinydns_loc[0]) out_addc(o, r->tinydns_loc[0]);
    if (r->tinydns_loc[1]) out_addc(o, r->tinydns_loc[1]);
    return NULL;
}

/* a text field of a record as a number of the data file (decimal digits only) */
static bool td_number(dzt_out_t *o, const char *s) {
    if (!all_digits(s) || strlen(s) > 10) return false;
    out_adds(o, s);
    return true;
}

/* one record as a line of the data file; NULL, or why it cannot be written */
static const char *put_record_td(dzt_t *z, const dns_record_t *r) {
    dzt_out_t *o = &z->out;
    uint8_t *wire = NULL;
    const char *why = NULL;
    uint16_t t = r->type_code;
    const char *bad = "the RDATA does not have the shape of its type";
    if (class_of(r) != 1) return "is not of class IN, the only class of a data file";
    if (r->bind_location_tag || r->ecs_subnet_tag) return "has a $LOCATION / $ECS-SUBNET tag, which a data file cannot hold";
    bool text = r->generic_data == NULL;
    if (text && t == 6 && r->rdata_count == 7) {                   /* Zfqdn:mname:rname:serial:refresh:retry:expire:minimum:ttl:ts:lo */
        out_addc(o, 'Z');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_addc(o, ':');
        if (!td_name(o, r->rdata[0])) return "a name in the RDATA is not usable";
        out_addc(o, ':');
        if (!td_name(o, r->rdata[1])) return "a name in the RDATA is not usable";
        out_addc(o, ':');
        uint32_t serial;
        if (!parse_soa_serial_strict(r->rdata[2], &serial, NULL)) return "the SOA serial is not a number up to 4294967295";
        out_addf(o, "%u", (unsigned)serial);
        for (int j = 3; j < 7; j++) out_addf(o, ":%u", (unsigned)parse_ttl_value(r->rdata[j]));
        out_addf(o, ":%u", (unsigned)r->ttl_value);
    } else if (text && t == 2 && r->rdata_count == 1) {            /* &fqdn:ip:x:ttl:ts:lo (x with a dot is the whole name) */
        out_addc(o, '&');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_addc(o, ':');
        out_addc(o, ':');
        if (!td_name(o, r->rdata[0])) return "a name in the RDATA is not usable";
        out_addf(o, ":%u", (unsigned)r->ttl_value);
    } else if (text && t == 1 && r->rdata_count == 1) {            /* +fqdn:ip:ttl:ts:lo */
        struct in_addr ia;
        char ip[INET_ADDRSTRLEN];
        if (inet_pton(AF_INET, r->rdata[0], &ia) != 1 || !inet_ntop(AF_INET, &ia, ip, sizeof(ip))) return "not an IPv4 address";
        out_addc(o, '+');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_addf(o, ":%s:%u", ip, (unsigned)r->ttl_value);
    } else if (text && t == 28 && r->rdata_count == 1) {           /* 3fqdn:ip6 as 32 hex digits:ttl:ts:lo */
        struct in6_addr ia;
        if (inet_pton(AF_INET6, r->rdata[0], &ia) != 1) return "not an IPv6 address";
        out_addc(o, '3');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_addc(o, ':');
        put_hex(o, ia.s6_addr, 16);
        out_addf(o, ":%u", (unsigned)r->ttl_value);
    } else if (text && t == 15 && r->rdata_count == 2) {           /* @fqdn:ip:x:distance:ttl:ts:lo */
        out_addc(o, '@');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_adds(o, "::");
        if (!td_name(o, r->rdata[1])) return "a name in the RDATA is not usable";
        out_addc(o, ':');
        if (!td_number(o, r->rdata[0])) return "the MX preference is not a plain number";
        out_addf(o, ":%u", (unsigned)r->ttl_value);
    } else if (text && (t == 5 || t == 12) && r->rdata_count == 1) {   /* Cfqdn:target:ttl:ts:lo  ^fqdn:target:ttl:ts:lo */
        out_addc(o, t == 5 ? 'C' : '^');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_addc(o, ':');
        if (!td_name(o, r->rdata[0])) return "a name in the RDATA is not usable";
        out_addf(o, ":%u", (unsigned)r->ttl_value);
    } else if (text && t == 16 && txt_is_tinydns_shaped(r)) {      /* 'fqdn:text:ttl:ts:lo */
        out_addc(o, '\'');
        if (!td_name(o, r->name)) return "the owner name is not usable";
        out_addc(o, ':');
        for (int j = 0; j < r->rdata_count; j++) td_bytes(o, (const uint8_t *)r->rdata[j], strlen(r->rdata[j]));
        out_addf(o, ":%u", (unsigned)r->ttl_value);
    } else {                                                       /* :fqdn:type:rdata:ttl:ts:lo */
        if (t == 0 || t == 2 || t == 5 || t == 6 || t == 12 || t == 15 || is_meta_rrtype(t))
            return (text && (t == 2 || t == 5 || t == 6 || t == 12 || t == 15)) ? bad : "has a type that a data file cannot hold";
        wire = malloc(65535);
        if (!wire) return "out of memory";
        long n = rdata_wire(r, wire, 65535);
        if (n < 0) {
            free(wire);
            return "the RDATA cannot be encoded";
        }
        out_addc(o, ':');
        if (!td_name(o, r->name)) {
            free(wire);
            return "the owner name is not usable";
        }
        out_addf(o, ":%u:", (unsigned)t);
        td_bytes(o, wire, (size_t)n);
        out_addf(o, ":%u", (unsigned)r->ttl_value);
        free(wire);
    }
    if ((why = td_attrs(o, r)) != NULL) return why;
    out_addc(o, '\n');
    out_line_end(o);
    return NULL;
}

static bool write_tinydns(dzt_t *z) {
    const zone_arena_t *a = z->arena;
    for (int i = 0; i < a->location_count; i++) {
        const tinydns_location_entry_t *l = &a->locations[i];
        for (int c = 0; c < 2; c++) {
            unsigned char ch = (unsigned char)l->code[c];
            if (ch && (ch <= 0x20 || ch >= 0x7F || ch == ':')) {
                fail_msg(z->err, z->errlen, "location definition %d: the code has a character the data file cannot hold", i + 1);
                return false;
            }
        }
        if (l->code[0] == 0 || l->prefix_bits > 32) {
            fail_msg(z->err, z->errlen, "location definition %d: no code, or a prefix length above 32", i + 1);
            return false;
        }
        out_addc(&z->out, '%');
        out_addc(&z->out, l->code[0]);
        if (l->code[1]) out_addc(&z->out, l->code[1]);
        out_addf(&z->out, ":%u.%u.%u.%u/%u\n", l->prefix[0], l->prefix[1], l->prefix[2], l->prefix[3], (unsigned)l->prefix_bits);
        out_line_end(&z->out);
    }
    if (a->bind_location_tag_count > 0 || a->bind_ecs_tag_count > 0) {
        fail_msg(z->err, z->errlen, "the zone has $LOCATION-TAG / $ECS-SUBNET-TAG definitions, which a data file cannot hold");
        return false;
    }
    for (size_t i = 0; i < a->count; i++) {
        const char *why = put_record_td(z, z->keys[i].r);
        if (why) {
            fail_rec(z->err, z->errlen, &z->keys[i], why);
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* comparing two zones                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static bool same_record(const dzt_key_t *a, const dzt_key_t *b) {
    const dns_record_t *x = a->r, *y = b->r;
    if (strcmp(x->name, y->name) != 0 || x->type_code != y->type_code || class_of(x) != class_of(y) || x->ttl_value != y->ttl_value)
        return false;
    /* the RDATA in canonical wire form, the tags and the tinydns attributes */
    return a->rdlen == b->rdlen && (a->rdlen == 0 || memcmp(a->rd, b->rd, a->rdlen) == 0) && same_tag(x->bind_location_tag, y->bind_location_tag) &&
           same_tag(x->ecs_subnet_tag, y->ecs_subnet_tag) && x->tinydns_ttd == y->tinydns_ttd &&
           x->tinydns_ttl_countdown == y->tinydns_ttl_countdown && memcmp(x->tinydns_loc, y->tinydns_loc, 2) == 0;
}

static bool same_defs(const ecs_tag_def_t *a, int na, const ecs_tag_def_t *b, int nb, const char *what, char *why, size_t whylen) {
    if (na != nb) {
        fail_msg(why, whylen, "%s: %d definitions, then %d", what, na, nb);
        return false;
    }
    for (int i = 0; i < na; i++) {
        bool same = a[i].cidr_count == b[i].cidr_count && strcmp(a[i].tag, b[i].tag) == 0;
        for (int j = 0; same && j < a[i].cidr_count; j++) same = strcmp(a[i].cidrs[j].cidr, b[i].cidrs[j].cidr) == 0;
        if (!same) {
            char t[80];
            show(a[i].tag, t, sizeof(t));
            fail_msg(why, whylen, "%s: definition %d ('%s') differs", what, i + 1, t);
            return false;
        }
    }
    return true;
}

bool dns_zone_text_same_zone(const zone_arena_t *a, const zone_arena_t *b, char *why, size_t whylen) {
    uint8_t *pa = NULL, *pb = NULL;
    dzt_key_t *ka = NULL, *kb = NULL;
    bool ok = false;
    if (a->count != b->count) {
        fail_msg(why, whylen, "%zu records, then %zu", a->count, b->count);
        return false;
    }
    if (!(ka = build_keys(a, &pa, why, whylen)) || !(kb = build_keys(b, &pb, why, whylen))) goto done;
    for (size_t i = 0; i < a->count; i++) {
        if (!same_record(&ka[i], &kb[i])) {
            char own[80];
            show(ka[i].r->name, own, sizeof(own));
            fail_msg(why, whylen, "record %zu (%s %s) differs from the one read back", ka[i].idx + 1, own, dns_type_to_string(ka[i].r->type_code));
            goto done;
        }
    }
    if (!same_defs(a->bind_location_tags, a->bind_location_tag_count, b->bind_location_tags, b->bind_location_tag_count,
                   "$LOCATION-TAG", why, whylen) ||
        !same_defs(a->bind_ecs_tags, a->bind_ecs_tag_count, b->bind_ecs_tags, b->bind_ecs_tag_count, "$ECS-SUBNET-TAG", why, whylen))
        goto done;
    bool same_locs = a->location_count == b->location_count;
    for (int i = 0; same_locs && i < a->location_count; i++)
        same_locs = memcmp(a->locations[i].code, b->locations[i].code, 2) == 0 && memcmp(a->locations[i].prefix, b->locations[i].prefix, 4) == 0 &&
                    a->locations[i].prefix_bits == b->locations[i].prefix_bits;
    if (!same_locs) {
        fail_msg(why, whylen, "the tinydns location definitions differ");
        goto done;
    }
    ok = true;
done:
    free(ka);
    free(kb);
    free(pa);
    free(pb);
    return ok;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the writer                                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

/* parse the text again and compare */
static bool verify_text(dzt_t *z, bool tinydns) {
    char why[300];
    bool ok = false;
    char *copy = malloc(z->out.len + 1);                          /* the parser cuts its buffer in place */
    zone_arena_t pa;
    parse_error_t perr;
    parse_context_t ctx;
    if (!copy) {
        fail_msg(z->err, z->errlen, "out of memory");
        return false;
    }
    if (z->out.len) memcpy(copy, z->out.p, z->out.len);
    copy[z->out.len] = '\0';
    zone_arena_init(&pa);
    memset(&perr, 0, sizeof(perr));
    memset(&ctx, 0, sizeof(ctx));
    ctx.err_out = &perr;
    ctx.default_origin = tinydns ? z->apex : ".";
    int rc = tinydns ? parse_tinydns_data(copy, z->out.len, &pa, &ctx) : parse_zone_fast(copy, z->out.len, &pa, &ctx);
    if (rc < 0) {
        fail_msg(z->err, z->errlen, "the text does not parse again (%s): it is not written", perr.error_message ? perr.error_message : "parse error");
    } else if (!dns_zone_text_same_zone(z->arena, &pa, why, sizeof(why))) {
        fail_msg(z->err, z->errlen, "the text does not read back as the same zone (%s): it is not written", why);
    } else {
        ok = true;
    }
    zone_arena_destroy(&pa);
    free(copy);
    return ok;
}

bool dns_zone_text_write(const zone_arena_t *arena, const char *apex, const dzt_opts_t *opts, dzt_sink_t sink, void *ud, char *err,
                         size_t errlen) {
    dzt_opts_t def = { DZT_AUTO, false };
    if (!opts) opts = &def;
    dzt_t z;
    memset(&z, 0, sizeof(z));
    z.arena = arena;
    z.err = err;
    z.errlen = errlen;
    bool ok = false;
    char norm[DNS_NAME_TEXT_SIZE];
    size_t n = apex ? dns_name_normalize(apex, norm, sizeof(norm)) : (size_t)-1;
    if (n == (size_t)-1 || n == 0) {
        fail_msg(err, errlen, "the zone name is not a domain name");
        return false;
    }
    if (norm[n - 1] != '.' || dns_char_is_escaped(norm, n - 1)) norm[n++] = '.';
    if (n + 1 > sizeof(z.apex)) {
        fail_msg(err, errlen, "the zone name is too long");
        return false;
    }
    memcpy(z.apex, norm, n);
    z.apex[n] = '\0';
    z.apex_len = n;
    z.apex_root = n == 1;
    bool tinydns = opts->format == DZT_TINYDNS || (opts->format == DZT_AUTO && arena->is_tinydns_format);
    z.out.sink = sink;
    z.out.ud = ud;
    z.out.stream = opts->no_verify;
    if (!(z.keys = build_keys(arena, &z.pool, err, errlen))) return false;
    if (tinydns ? !write_tinydns(&z) : !write_bind(&z)) goto done;
    if (z.out.oom) {
        fail_msg(err, errlen, "out of memory");
        goto done;
    }
    if (z.out.sink_failed) {
        fail_msg(err, errlen, "the output could not be written");
        goto done;
    }
    if (!opts->no_verify && !verify_text(&z, tinydns)) goto done;
    if (z.out.len && sink(ud, z.out.p, z.out.len) != 0) {
        fail_msg(err, errlen, "the output could not be written");
        goto done;
    }
    ok = true;
done:
    free(z.out.p);
    free(z.keys);
    free(z.pool);
    return ok;
}

static int file_sink(void *ud, const char *data, size_t len) { return fwrite(data, 1, len, (FILE *)ud) == len ? 0 : -1; }

bool dns_zone_text_write_file(const zone_arena_t *arena, const char *apex, const dzt_opts_t *opts, FILE *fp, char *err, size_t errlen) {
    return dns_zone_text_write(arena, apex, opts, file_sink, fp, err, errlen);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* one RRset as lines (karidns-zone apply: the delta of a change set, the rows of karidns_zone_version_rrsets)       */
/* ------------------------------------------------------------------------------------------------------------- */

static int rrset_key_cmp(const void *pa, const void *pb) {
    const dzt_key_t *a = pa, *b = pb;
    size_t n = a->rdlen < b->rdlen ? a->rdlen : b->rdlen;                       /* RFC 4034 section 6.3: RDATA as left-justified octets */
    int c = n ? memcmp(a->rd, b->rd, n) : 0;
    if (c) return c;
    if (a->rdlen != b->rdlen) return a->rdlen < b->rdlen ? -1 : 1;
    return a->r->ttl_value < b->r->ttl_value ? -1 : a->r->ttl_value > b->r->ttl_value;
}

char *dns_zone_text_rrset_lines(const dns_record_t *const *recs, size_t n, char *err, size_t errlen) {
    dzt_t z;
    memset(&z, 0, sizeof(z));
    z.err = err;
    z.errlen = errlen;
    snprintf(z.apex, sizeof(z.apex), ".");                 /* no zone to be relative to: every name is written absolute */
    z.apex_len = 1;
    z.apex_root = true;
    z.absolute_only = true;         /* the root name in an RDATA (a null MX, the replacement of a NAPTR) is ".": an "@" would be the origin of whatever zone the line is read for */
    dzt_key_t *keys = calloc(n ? n : 1, sizeof(*keys));
    uint8_t *tmp = malloc(65535), *pool = NULL;
    size_t plen = 0, pcap = 0;
    char *result = NULL;
    if (!keys || !tmp) {
        fail_msg(err, errlen, "out of memory");
        goto done;
    }
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = recs[i];
        dzt_key_t *k = &keys[i];
        k->r = r;
        k->idx = i;
        if (!r->name) {
            fail_msg(err, errlen, "record %zu: no owner name", i + 1);
            goto done;
        }
        for (int j = 0; j < r->rdata_count; j++)
            if (!r->rdata || !r->rdata[j]) {
                fail_rec(err, errlen, k, "a missing RDATA field");
                goto done;
            }
        long rl = dns_record_canonical_rdata(r, tmp, 65535);
        if (rl < 0) {
            fail_rec(err, errlen, k, "the RDATA cannot be encoded");
            goto done;
        }
        if (plen + (size_t)rl > pcap) {
            size_t nc = pcap ? pcap : 4096;
            while (nc < plen + (size_t)rl) nc *= 2;
            uint8_t *np = realloc(pool, nc);
            if (!np) {
                fail_msg(err, errlen, "out of memory");
                goto done;
            }
            pool = np;
            pcap = nc;
        }
        if (rl) memcpy(pool + plen, tmp, (size_t)rl);
        k->off = plen;
        k->rdlen = (uint16_t)rl;
        plen += (size_t)rl;
    }
    for (size_t i = 0; i < n; i++) keys[i].rd = pool ? pool + keys[i].off : NULL;
    qsort(keys, n, sizeof(*keys), rrset_key_cmp);
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = keys[i].r;
        char tb[32];
        const char *why;
        if (i) out_addc(&z.out, '\n');
        out_addf(&z.out, "%u ", (unsigned)r->ttl_value);
        out_adds(&z.out, type_token(r->type_code, tb, sizeof(tb)));
        out_addc(&z.out, ' ');
        if ((why = put_rdata(&z, r)) != NULL) {
            fail_rec(err, errlen, &keys[i], why);
            goto done;
        }
    }
    if (z.out.oom) {
        fail_msg(err, errlen, "out of memory");
        goto done;
    }
    result = z.out.p ? z.out.p : strdup("");
    z.out.p = NULL;
    if (!result) fail_msg(err, errlen, "out of memory");
done:
    free(z.out.p);
    free(keys);
    free(tmp);
    free(pool);
    return result;
}

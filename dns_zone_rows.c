/*
 * dns_zone_rows.c - zone file -> PowerDNS 5.1 schema rows (the row generation of the former tests/db/zone2sql.c; see dns_zone_rows.h).
 * Ordinary process code: the importer, zone2sql and the unit tests link it; the server does not.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>

#include "dns_zone_rows.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_zone_parser.h"
#include "dns_presigned.h"

/* ------------------------------------------------------------------------------------------------------------- */
/* reading the zone file                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

static char *zrows_read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n;
    while ((n = fread(buf + len, 1, cap - len - 1, f)) > 0) {
        len += n;
        if (cap - len < 2) {
            char *nb = realloc(buf, cap * 2);
            if (!nb) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = nb;
            cap *= 2;
        }
    }
    fclose(f);
    buf[len] = '\0';
    return buf;
}

static char *zrows_include_cb(parse_context_t *ctx, const char *path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (out_dev) *out_dev = st.st_dev;
    if (out_ino) *out_ino = st.st_ino;
    return zrows_read_file(path);
}

/* The text of a file or of standard input becomes the arena's file buffer (the parser works on it in place) and its pristine copy (for messages). */
static bool zrows_arena_text(zone_arena_t *arena, const char *text, size_t len, const char *shown, char *err, size_t errlen) {
    char *buf = malloc(len + 1), *display = malloc(len + 1), *path_copy = strdup(shown);
    if (!buf || !display || !path_copy) {
        free(buf);
        free(display);
        free(path_copy);
        snprintf(err, errlen, "out of memory");
        return false;
    }
    memcpy(buf, text, len);
    buf[len] = '\0';
    memcpy(display, text, len);
    display[len] = '\0';
    if (zone_arena_add_file(arena, buf, display, path_copy) != 0) {
        free(display);
        free(path_copy);
        free(buf);
        snprintf(err, errlen, "out of memory");
        return false;
    }
    return true;
}

/* The message of a failed parse: "file:line: reason" (the line is found in the pristine text of the file the parser was in). */
static void zrows_parse_error(const parse_error_t *perr, const zone_arena_t *arena, const char *shown, zrows_info_t *info, char *err, size_t errlen) {
    const char *reason = perr->error_message ? perr->error_message : "parse error";
    const char *file = shown;
    const char *buf = arena->file_buf_count > 0 ? arena->display_bufs[0] : NULL;
    if (perr->file_path)
        for (int i = 0; i < arena->file_buf_count; i++)
            if (arena->file_paths[i] && strcmp(arena->file_paths[i], perr->file_path) == 0) {
                file = perr->file_path;
                buf = arena->display_bufs[i];
                break;
            }
    int line = 1;
    if (buf) {
        size_t off = perr->error_offset, bl = strlen(buf);
        for (size_t i = 0; i < off && i < bl; i++)
            if (buf[i] == '\n') line++;
    }
    if (info) info->include_refused = strncmp(reason, "$INCLUDE is not available", 25) == 0;
    snprintf(err, errlen, "%s:%d: %s", file, line, reason);
}

static void zrows_report_ooz(const dns_record_t *rec, void *ud) {
    zrows_info_t *info = ud;
    if (info->out_of_zone++ == 0) snprintf(info->first_out_of_zone, sizeof(info->first_out_of_zone), "%s", rec->name ? rec->name : "");
}

/* what the importer warns about, from the parse context (karicheck's warnings) */
static void zrows_info_from_ctx(zrows_info_t *info, const parse_context_t *ctx) {
    if (!info) return;
    info->no_ttl = ctx->no_ttl_count;
    snprintf(info->no_ttl_owner, sizeof(info->no_ttl_owner), "%s", ctx->first_no_ttl_owner ? ctx->first_no_ttl_owner : "");
    snprintf(info->no_ttl_file, sizeof(info->no_ttl_file), "%s", ctx->first_no_ttl_file ? ctx->first_no_ttl_file : "");
    info->no_ttl_line = ctx->first_no_ttl_line;
    info->long_txt = ctx->long_txt_count;
    snprintf(info->long_txt_owner, sizeof(info->long_txt_owner), "%s", ctx->first_long_txt_owner ? ctx->first_long_txt_owner : "");
    snprintf(info->long_txt_file, sizeof(info->long_txt_file), "%s", ctx->first_long_txt_file ? ctx->first_long_txt_file : "");
    info->long_txt_line = ctx->first_long_txt_line;
    info->tinydns_out_of_zone = ctx->out_of_zone_count;
    snprintf(info->first_tinydns_out_of_zone, sizeof(info->first_tinydns_out_of_zone), "%s", ctx->first_out_of_zone ? ctx->first_out_of_zone : "");
}

bool zrows_load_zone_text(const char *text, size_t len, const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                          size_t apex_cap, zrows_info_t *info, char *err, size_t errlen) {
    zone_arena_init(arena);
    if (info) memset(info, 0, sizeof(*info));
    const char *shown = path ? path : "standard input";
    if (!zrows_arena_text(arena, text, len, shown, err, errlen)) return false;
    /* a file: $INCLUDE is read relative to its directory.  Standard input has none: no loader callback, so the parser refuses $INCLUDE. */
    char dirbuf[PATH_MAX];
    snprintf(dirbuf, sizeof(dirbuf), "%s", path ? path : ".");
    char *base_dir = strdup(path ? dirname(dirbuf) : ".");
    char *root_path = path ? realpath(path, NULL) : strdup("(standard input)");
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (!base_dir || !root_path || (path && stat(path, &st) != 0)) {
        free(base_dir);
        free(root_path);
        zone_arena_destroy(arena);
        snprintf(err, errlen, "cannot stat %s", shown);
        return false;
    }
    char *visited_paths[16];
    dev_t visited_devs[16];
    ino_t visited_inos[16];
    char *root_ttl = NULL, *root_ecs = NULL, *root_loc = NULL;
    parse_error_t perr = {0};
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base_dir = base_dir;
    ctx.default_origin = ".";
    ctx.is_standalone_mode = true;
    ctx.err_out = &perr;
    ctx.visited_paths = visited_paths;
    ctx.visited_devs = visited_devs;
    ctx.visited_inos = visited_inos;
    ctx.visited_count = 1;
    ctx.visited_cap = 16;
    ctx.load_file_cb = path ? zrows_include_cb : NULL;
    ctx.shared_ttl_io = &root_ttl;
    ctx.shared_ecs_tag_io = &root_ecs;
    ctx.shared_loc_tag_io = &root_loc;
    visited_paths[0] = root_path;
    visited_devs[0] = st.st_dev;
    visited_inos[0] = st.st_ino;

    char *parse_buf = arena->file_bufs[0];
    int rc = parse_zone_fast(parse_buf, strlen(parse_buf), arena, &ctx);
    free(base_dir);
    free(root_path);
    if (rc < 0) {
        zrows_parse_error(&perr, arena, shown, info, err, errlen);
        zone_arena_destroy(arena);
        return false;
    }
    zrows_info_from_ctx(info, &ctx);
    /* the zone is the owner of the first SOA */
    const char *apex = apex_override;
    for (size_t i = 0; !apex && i < arena->count; i++)
        if (arena->records[i].type_code == 6) apex = arena->records[i].name;
    if (!apex) {
        snprintf(err, errlen, "%s: no SOA record", shown);
        zone_arena_destroy(arena);
        return false;
    }
    snprintf(apex_out, apex_cap, "%s", apex);
    zone_arena_drop_out_of_zone(arena, apex_out, info ? zrows_report_ooz : NULL, info);
    zone_arena_drop_unencodable(arena, NULL, NULL);
    return true;
}

bool zrows_load_zone_file(const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                        size_t apex_cap, char *err, size_t errlen) {
    char *buf = zrows_read_file(path);
    if (!buf) {
        zone_arena_init(arena);
        snprintf(err, errlen, "cannot read %s", path);
        return false;
    }
    bool ok = zrows_load_zone_text(buf, strlen(buf), path, apex_override, arena, apex_out, apex_cap, NULL, err, errlen);
    free(buf);
    return ok;
}


/* ---- B8: tinydns data files ---- */
static bool zrows_tdns_parse(const char *text, size_t len, const char *shown, time_t mtime, const char *origin, const char *const *zones, int nzones,
                           zone_arena_t *arena, zrows_info_t *info, char *err, size_t errlen) {
    zone_arena_init(arena);
    if (!zrows_arena_text(arena, text, len, shown, err, errlen)) return false;
    parse_error_t perr = {0};
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = origin;
    ctx.err_out = &perr;
    ctx.source_mtime = mtime;
    ctx.all_zone_names = (const char **)zones;       /* the parser only reads the names */
    ctx.all_zone_count = nzones;
    char *parse_buf = arena->file_bufs[0];
    if (parse_tinydns_data(parse_buf, strlen(parse_buf), arena, &ctx) < 0) {
        zrows_parse_error(&perr, arena, shown, info, err, errlen);
        zone_arena_destroy(arena);
        return false;
    }
    zrows_info_from_ctx(info, &ctx);
    return true;
}

bool zrows_tinydns_apexes_text(const char *text, size_t len, const char *path, time_t mtime, char ***names, int *n, zrows_info_t *info, char *err,
                               size_t errlen) {
    zone_arena_t a;
    *names = NULL;
    *n = 0;
    const char *shown = path ? path : "standard input";
    if (!zrows_tdns_parse(text, len, shown, mtime, ".", NULL, 0, &a, info, err, errlen)) return false;
    char **v = calloc(a.count ? a.count : 1, sizeof(char *));
    if (!v) {
        zone_arena_destroy(&a);
        snprintf(err, errlen, "out of memory");
        return false;
    }
    int k = 0;
    for (size_t i = 0; i < a.count; i++) {
        if (a.records[i].type_code != 6) continue;
        bool dup = false;
        for (int j = 0; j < k; j++)
            if (strcasecmp(v[j], a.records[i].name) == 0) dup = true;
        if (!dup && !(v[k] = strdup(a.records[i].name))) {
            for (int j = 0; j < k; j++) free(v[j]);
            free(v);
            zone_arena_destroy(&a);
            snprintf(err, errlen, "out of memory");
            return false;
        }
        if (!dup) k++;
    }
    zone_arena_destroy(&a);
    if (k == 0) {
        free(v);
        snprintf(err, errlen, "%s: no SOA record (a . or Z line)", shown);
        return false;
    }
    *names = v;
    *n = k;
    return true;
}

bool zrows_load_tinydns_text(const char *text, size_t len, const char *path, time_t mtime, const char *apex_override, const char *const *zones, int nzones,
                             zone_arena_t *arena, char *apex_out, size_t apex_cap, zrows_info_t *info, char *err, size_t errlen) {
    char apex[DNS_NAME_TEXT_SIZE];
    if (info) memset(info, 0, sizeof(*info));
    if (apex_override) {
        snprintf(apex, sizeof(apex), "%s", apex_override);
    } else {
        char **names;
        int nn;
        if (!zrows_tinydns_apexes_text(text, len, path, mtime, &names, &nn, NULL, err, errlen)) return false;
        snprintf(apex, sizeof(apex), "%s", names[0]);
        for (int i = 0; i < nn; i++) free(names[i]);
        free(names);
    }
    size_t al = strlen(apex);
    if (al == 0 || apex[al - 1] != '.') {                    /* the data file parser wants the absolute form */
        if (al + 2 > sizeof(apex)) {
            snprintf(err, errlen, "zone name too long");
            return false;
        }
        apex[al] = '.';
        apex[al + 1] = '\0';
    }
    if (!zrows_tdns_parse(text, len, path ? path : "standard input", mtime, apex, zones, nzones, arena, info, err, errlen)) return false;
    snprintf(apex_out, apex_cap, "%s", apex);
    zone_arena_drop_out_of_zone(arena, apex_out, NULL, NULL);
    zone_arena_drop_unencodable(arena, NULL, NULL);
    return true;
}

/* the path versions: the file is read here (a file that cannot be read is "cannot read PATH") */
static char *zrows_read_with_mtime(const char *path, time_t *mtime, char *err, size_t errlen) {
    struct stat st;
    char *buf = zrows_read_file(path);
    if (!buf || stat(path, &st) != 0) {
        free(buf);
        snprintf(err, errlen, "cannot read %s", path);
        return NULL;
    }
    *mtime = st.st_mtime;
    return buf;
}

bool zrows_tinydns_apexes(const char *path, char ***names, int *n, char *err, size_t errlen) {
    time_t mt;
    *names = NULL;
    *n = 0;
    char *buf = zrows_read_with_mtime(path, &mt, err, errlen);
    if (!buf) return false;
    bool ok = zrows_tinydns_apexes_text(buf, strlen(buf), path, mt, names, n, NULL, err, errlen);
    free(buf);
    return ok;
}

bool zrows_load_tinydns_file(const char *path, const char *apex_override, const char *const *zones, int nzones, zone_arena_t *arena,
                           char *apex_out, size_t apex_cap, char *err, size_t errlen) {
    time_t mt;
    char *buf = zrows_read_with_mtime(path, &mt, err, errlen);
    if (!buf) {
        zone_arena_init(arena);
        return false;
    }
    bool ok = zrows_load_tinydns_text(buf, strlen(buf), path, mt, apex_override, zones, nzones, arena, apex_out, apex_cap, NULL, err, errlen);
    free(buf);
    return ok;
}

bool zrows_names_equal(const char *a, const char *b) {
    size_t na = strlen(a), nb = strlen(b);
    if (na > 1 && a[na - 1] == '.') na--;
    if (nb > 1 && b[nb - 1] == '.') nb--;
    return na == nb && strncasecmp(a, b, na) == 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* rows                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { char *p; size_t len, cap; bool oom; } dstr_t;

static void ds_add(dstr_t *d, const char *s, size_t n) {
    if (d->oom) return;
    if (d->len + n + 1 > d->cap) {
        size_t nc = d->cap ? d->cap : 64;
        while (nc < d->len + n + 1) nc *= 2;
        char *np = realloc(d->p, nc);
        if (!np) {
            d->oom = true;
            return;
        }
        d->p = np;
        d->cap = nc;
    }
    if (n) memcpy(d->p + d->len, s, n);
    d->len += n;
    d->p[d->len] = '\0';
}
static void ds_adds(dstr_t *d, const char *s) { ds_add(d, s, strlen(s)); }

/* absolute name -> PowerDNS form (no trailing dot; the root stays ".") */
static void ds_add_name(dstr_t *d, const char *n) {
    size_t len = strlen(n);
    size_t bare = dns_name_len_no_root(n, len);
    if (bare == 0) ds_adds(d, ".");
    else ds_add(d, n, bare);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the field table (dns_zone_rows.h): what each RDATA field of a parsed record is                                  */
/* ------------------------------------------------------------------------------------------------------------- */

/* The names PowerDNS 5.1 stores without the trailing dot (checked with pdnsutil load-zone on 5.1.4): NS CNAME PTR
 * DNAME, the MX and AFSDB target, the SRV target, both SOA names, both RP names and (B5: seen in a presigned zone
 * AXFRed into the database) the RRSIG signer.  It keeps the dot (as the zone file has the absolute name) in NAPTR,
 * SVCB / HTTPS, NSEC (next name), KX, LP and MINFO, so the same rule is applied here; the reader takes both.
 * The ZF_NAME rows are the zone parser's list of names it keeps escaped (dns_zone_parser.c, "A-1: Unescape fields"), the ZF_EXPAND-only
 * rows the names it unescapes first and then expands (IPSECKEY and AMTRELAY gateway / relay of type 3, SVCB / HTTPS target). */
#define ZF_REST 255
typedef struct { uint16_t type; uint8_t first, last; unsigned flags; } zrows_field_t;
static const zrows_field_t zrows_field_table[] = {
    { 2, 0, 0, ZF_NAME | ZF_EXPAND | ZF_NODOT },        /* NS */
    { 3, 0, 0, ZF_NAME | ZF_EXPAND },                   /* MD */
    { 4, 0, 0, ZF_NAME | ZF_EXPAND },                   /* MF */
    { 5, 0, 0, ZF_NAME | ZF_EXPAND | ZF_NODOT },        /* CNAME */
    { 6, 0, 1, ZF_NAME | ZF_EXPAND | ZF_NODOT },        /* SOA: MNAME RNAME */
    { 7, 0, 0, ZF_NAME | ZF_EXPAND },                   /* MB */
    { 8, 0, 0, ZF_NAME | ZF_EXPAND },                   /* MG */
    { 9, 0, 0, ZF_NAME | ZF_EXPAND },                   /* MR */
    { 12, 0, 0, ZF_NAME | ZF_EXPAND | ZF_NODOT },       /* PTR */
    { 14, 0, 1, ZF_NAME | ZF_EXPAND },                  /* MINFO */
    { 15, 1, 1, ZF_NAME | ZF_EXPAND | ZF_NODOT },       /* MX: EXCHANGE */
    { 17, 0, 1, ZF_NAME | ZF_EXPAND | ZF_NODOT },       /* RP */
    { 18, 1, 1, ZF_NAME | ZF_EXPAND | ZF_NODOT },       /* AFSDB */
    { 21, 1, 1, ZF_NAME | ZF_EXPAND },                  /* RT */
    { 23, 0, 0, ZF_NAME | ZF_EXPAND },                  /* NSAP-PTR */
    { 26, 1, 2, ZF_NAME | ZF_EXPAND },                  /* PX: MAP822 MAPX400 */
    { 30, 0, 0, ZF_NAME | ZF_EXPAND },                  /* NXT */
    { 33, 3, 3, ZF_NAME | ZF_EXPAND | ZF_NODOT },       /* SRV: target */
    { 35, 5, 5, ZF_NAME | ZF_EXPAND },                  /* NAPTR: replacement */
    { 36, 1, 1, ZF_NAME | ZF_EXPAND },                  /* KX */
    { 38, 2, 2, ZF_NAME | ZF_EXPAND },                  /* A6: prefix name (only with a prefix length above 0) */
    { 39, 0, 0, ZF_NAME | ZF_EXPAND | ZF_NODOT },       /* DNAME */
    { 45, 3, 3, ZF_EXPAND },                            /* IPSECKEY: gateway (only of gateway type 3) */
    { 24, 7, 7, ZF_ABS },                               /* SIG: signer (the parser expands no name here: a BIND file needs it absolute) */
    { 46, 7, 7, ZF_NODOT | ZF_ABS },                    /* RRSIG: signer (stored without the dot by AXFR-in, checked on 5.1.4, B5) */
    { 47, 0, 0, ZF_ABS },                               /* NSEC: next name */
    { 58, 0, 1, ZF_NAME | ZF_EXPAND },                  /* TALINK */
    { 64, 1, 1, ZF_EXPAND },                            /* SVCB: target (not "." ) */
    { 65, 1, 1, ZF_EXPAND },                            /* HTTPS: target (not "." ) */
    { 66, 3, 3, ZF_ABS },                               /* DSYNC: target */
    { 107, 1, 1, ZF_NAME | ZF_EXPAND },                 /* LP */
    { 260, 3, 3, ZF_EXPAND },                           /* AMTRELAY: relay (only of relay type 3) */
    /* character-strings */
    { 13, 0, ZF_REST, ZF_STRING },                      /* HINFO */
    { 16, 0, ZF_REST, ZF_STRING },                      /* TXT */
    { 19, 0, ZF_REST, ZF_STRING },                      /* X25 */
    { 20, 0, ZF_REST, ZF_STRING },                      /* ISDN */
    { 35, 2, 4, ZF_STRING },                            /* NAPTR: flags service regexp */
    { 56, 0, ZF_REST, ZF_STRING },                      /* NINFO */
    { 99, 0, ZF_REST, ZF_STRING },                      /* SPF */
    { 256, 2, 2, ZF_STRING },                           /* URI: target */
    { 257, 2, 2, ZF_STRING },                           /* CAA: value */
    { 258, 0, ZF_REST, ZF_STRING },                     /* AVC */
    { 259, 3, 3, ZF_STRING },                           /* DOA: media type */
    { 261, 0, ZF_REST, ZF_STRING },                     /* RESINFO */
    { 262, 0, ZF_REST, ZF_STRING },                     /* WALLET */
};

/* the gateway type of an IPSECKEY / the relay type of an AMTRELAY is 3 (a domain name): the test of the zone parser */
static bool zrows_type_is_3(const char *s) {
    uint8_t v;
    return parse_u8(s, &v) && v == 3;
}

unsigned zrows_field_flags(const dns_record_t *r, int j) {
    unsigned f = 0;
    for (size_t i = 0; i < sizeof(zrows_field_table) / sizeof(zrows_field_table[0]); i++) {
        const zrows_field_t *e = &zrows_field_table[i];
        if (e->type == r->type_code && j >= e->first && j <= e->last) f |= e->flags;
    }
    if (f & ZF_EXPAND) {                            /* the fields whose meaning depends on another field */
        switch (r->type_code) {
        case 38:                                    /* A6: the prefix name is there only for a prefix length above 0 */
            if ((uint8_t)atoi(r->rdata[0]) == 0) f &= ~(ZF_NAME | ZF_EXPAND);
            break;
        case 45:
            if (!zrows_type_is_3(r->rdata[1])) f &= ~ZF_EXPAND;
            break;
        case 260:
            if (!zrows_type_is_3(r->rdata[2])) f &= ~ZF_EXPAND;
            break;
        case 64: case 65:                           /* "." is the AliasMode root, not a name to expand */
            if (strcmp(r->rdata[1], ".") == 0) f &= ~ZF_EXPAND;
            break;
        default:
            break;
        }
    }
    return f;
}

/* number of leading fields before a base64 / hex blob that may be split (same table as the zone parser) */
int zrows_blob_lead(uint16_t type) {
    switch (type) {
    case 24: case 46: return 8;
    case 25: case 48: case 60: case 43: case 59: case 32768: case 32769: case 37: case 52: case 53: return 3;
    case 49: case 61: return 0;
    default: return -1;
    }
}

static void ds_add_quoted(dstr_t *d, const char *s) {
    ds_adds(d, "\"");
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            char b[3] = { '\\', (char)*p, 0 };
            ds_adds(d, b);
        } else if (*p < 0x20 || *p >= 0x7F) {
            char b[8];
            snprintf(b, sizeof(b), "\\%03u", *p);
            ds_adds(d, b);
        } else {
            char b[2] = { (char)*p, 0 };
            ds_adds(d, b);
        }
    }
    ds_adds(d, "\"");
}

/* content (and prio) of a record in PowerDNS form.  false: not representable (message in err) */
static bool record_content(const dns_record_t *r, dstr_t *out, long *prio, char *err, size_t errlen) {
    *prio = 0;
    /* B9a: PowerDNS's ALIAS and LUA rows (the zone parser keeps them as TYPE65401 / TYPE65402 of CLASS IN, the form PowerDNS transfers) */
    if (r->generic_data && (r->class_val == 1 || r->class_val == 0) && r->type_code == DNS_TYPE_PDNS_ALIAS) {
        char nm[DNS_NAME_TEXT_SIZE];
        size_t nx = 0;
        if (expand_wire_name_to_buffer(r->generic_data, r->generic_len, 0, &nx, nm, sizeof(nm)) < 0 || nx != r->generic_len) {
            snprintf(err, errlen, "ALIAS RDATA is not one name");
            return false;
        }
        ds_adds(out, nm);
        return true;
    }
    if (r->generic_data && (r->class_val == 1 || r->class_val == 0) && r->type_code == DNS_TYPE_PDNS_LUA) {
        if (r->generic_len < 3) {
            snprintf(err, errlen, "LUA RDATA is too short");
            return false;
        }
        ds_adds(out, dns_type_to_string((uint16_t)((r->generic_data[0] << 8) | r->generic_data[1])));
        for (unsigned p = 2; p < r->generic_len;) {
            unsigned l = r->generic_data[p++];
            if (r->generic_len - p < l) {
                snprintf(err, errlen, "LUA RDATA runs past its end");
                return false;
            }
            char tmp[256];
            memcpy(tmp, r->generic_data + p, l);
            tmp[l] = '\0';
            ds_adds(out, " ");
            ds_add_quoted(out, tmp);
            p += l;
        }
        return true;
    }
    if (r->generic_data) {       /* RFC 3597 form as written in the zone */
        char b[32];
        snprintf(b, sizeof(b), "\\# %u", (unsigned)r->generic_len);
        ds_adds(out, b);
        if (r->generic_len) ds_adds(out, " ");
        for (unsigned i = 0; i < r->generic_len; i++) {
            snprintf(b, sizeof(b), "%02x", r->generic_data[i]);
            ds_adds(out, b);
        }
        return !out->oom;
    }
    int from = 0;
    if (r->type_code == 15 || r->type_code == 33) {      /* MX, SRV: the priority is a column */
        if (r->rdata_count < 2) {
            snprintf(err, errlen, "%s record with too few fields", r->type ? r->type : "?");
            return false;
        }
        char *end;
        *prio = strtol(r->rdata[0], &end, 10);
        if (*end || end == r->rdata[0] || *prio < 0 || *prio > 65535) {
            snprintf(err, errlen, "bad priority '%.20s'", r->rdata[0]);
            return false;
        }
        from = 1;
    }
    if (r->type_code == 6 && r->rdata_count == 7) {      /* SOA: times as numbers (the file may say 1h) */
        ds_add_name(out, r->rdata[0]);
        ds_adds(out, " ");
        ds_add_name(out, r->rdata[1]);
        ds_adds(out, " ");
        ds_adds(out, r->rdata[2]);
        for (int j = 3; j < 7; j++) {
            char b[16];
            snprintf(b, sizeof(b), " %u", parse_ttl_value(r->rdata[j]));
            ds_adds(out, b);
        }
        return !out->oom;
    }
    int lead = zrows_blob_lead(r->type_code);
    for (int j = from; j < r->rdata_count; j++) {
        bool glue = lead >= 0 && j > lead;     /* a split blob is one token */
        if (j > from && !glue) ds_adds(out, " ");
        unsigned ff = zrows_field_flags(r, j);
        if (ff & ZF_NODOT) ds_add_name(out, r->rdata[j]);
        else if ((ff & ZF_STRING) || r->rdata[j][0] == '\0') ds_add_quoted(out, r->rdata[j]);   /* an empty token would vanish */
        else ds_adds(out, r->rdata[j]);
    }
    if (out->len == 0) {
        snprintf(err, errlen, "%s record without RDATA", r->type ? r->type : "?");
        return false;
    }
    return !out->oom;
}

static bool zrows_pool_dup(zrows_t *o, const char *s, const char **out);

static bool pool_add(zrows_t *o, char *s) {
    if (o->n_pool >= o->cap_pool) {
        size_t nc = o->cap_pool ? o->cap_pool * 2 : 64;
        char **np = realloc(o->pool, nc * sizeof(char *));
        if (!np) return false;
        o->pool = np;
        o->cap_pool = nc;
    }
    o->pool[o->n_pool++] = s;
    return true;
}

void zrows_free(zrows_t *r) {
    for (size_t i = 0; i < r->n_pool; i++) free(r->pool[i]);
    free(r->pool);
    free(r->rows);
    free(r->auth);
    free(r->nsec3param);
    free(r->tags);
    free(r->td);
    free(r->defs);
    memset(r, 0, sizeof(*r));
}

/* B5: the presigned layout (design 3.6, 8.2) is made by zrows_make_presigned() below, at the end of zrows_from_arena(). */

/* B8: the tag definitions ($LOCATION-TAG, $ECS-SUBNET-TAG) and the tinydns location definitions (% lines) of the zone, one row per CIDR */
static bool zrows_def_add(zrows_t *o, size_t *cap, const char *kind, const char *tag, const char *cidr) {
    if (o->ndefs >= *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        zrows_def_t *nd = realloc(o->defs, nc * sizeof(*nd));
        if (!nd) return false;
        o->defs = nd;
        *cap = nc;
    }
    zrows_def_t *d = &o->defs[o->ndefs];
    d->kind = kind;                                 /* a string literal */
    if (!zrows_pool_dup(o, tag, &d->tag) || !zrows_pool_dup(o, cidr, &d->cidr)) return false;
    o->ndefs++;
    return true;
}

static bool zrows_defs_from_arena(zrows_t *o, const zone_arena_t *a) {
    size_t cap = 0;
    for (int i = 0; i < a->bind_location_tag_count; i++)
        for (int j = 0; j < a->bind_location_tags[i].cidr_count; j++)
            if (!zrows_def_add(o, &cap, "location", a->bind_location_tags[i].tag, a->bind_location_tags[i].cidrs[j].cidr)) return false;
    for (int i = 0; i < a->bind_ecs_tag_count; i++)
        for (int j = 0; j < a->bind_ecs_tags[i].cidr_count; j++)
            if (!zrows_def_add(o, &cap, "ecs", a->bind_ecs_tags[i].tag, a->bind_ecs_tags[i].cidrs[j].cidr)) return false;
    for (int i = 0; i < a->location_count; i++) {
        const tinydns_location_entry_t *l = &a->locations[i];
        char code[3] = { l->code[0], l->code[1], '\0' }, cidr[24];
        snprintf(cidr, sizeof(cidr), "%u.%u.%u.%u/%u", l->prefix[0], l->prefix[1], l->prefix[2], l->prefix[3], l->prefix_bits);
        if (!zrows_def_add(o, &cap, "tinydns", code, cidr)) return false;
    }
    return true;
}

bool zrows_from_arena(zone_arena_t *arena, const char *apex, zrows_t *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    size_t al = dns_name_len_no_root(apex, strlen(apex));
    if (al == 0 || al >= sizeof(out->zone)) {
        snprintf(err, errlen, "bad zone name");
        return false;
    }
    for (size_t i = 0; i < al; i++) out->zone[i] = (char)tolower((unsigned char)apex[i]);
    out->zone[al] = '\0';
    out->rows = calloc(arena->count ? arena->count : 1, sizeof(db_record_row_t));
    if (!out->rows) {
        snprintf(err, errlen, "out of memory");
        return false;
    }
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        db_record_row_t *row = &out->rows[out->n];
        dstr_t name = {0}, content = {0};
        for (const char *p = r->name; *p; p++) {
            char c = (char)tolower((unsigned char)*p);
            ds_add(&name, &c, 1);
        }
        if (name.len > 0 && dns_name_len_no_root(name.p, name.len) != name.len) name.p[--name.len] = '\0';
        long prio = 0;
        char why[160] = "";
        if (name.oom || name.len == 0 || !record_content(r, &content, &prio, why, sizeof(why))) {
            free(name.p);
            free(content.p);
            snprintf(err, errlen, "record %zu (%.100s %s): %s", i + 1, r->name, r->type ? r->type : "?",
                     name.len == 0 ? "empty owner" : why);
            zrows_free(out);
            return false;
        }
        char *type = strdup((r->generic_data && (r->class_val == 1 || r->class_val == 0) && r->type_code == DNS_TYPE_PDNS_ALIAS) ? "ALIAS"
                                  : (r->generic_data && (r->class_val == 1 || r->class_val == 0) && r->type_code == DNS_TYPE_PDNS_LUA) ? "LUA"
                                  : get_type_str(r->type_code, arena));
        if (!type) {
            free(name.p);
            free(content.p);
            snprintf(err, errlen, "out of memory");
            zrows_free(out);
            return false;
        }
        if (!pool_add(out, name.p)) {
            free(name.p);
            free(content.p);
            free(type);
            snprintf(err, errlen, "out of memory");
            zrows_free(out);
            return false;
        }
        if (!pool_add(out, content.p)) {
            free(content.p);
            free(type);
            snprintf(err, errlen, "out of memory");
            zrows_free(out);
            return false;
        }
        if (!pool_add(out, type)) {
            free(type);
            snprintf(err, errlen, "out of memory");
            zrows_free(out);
            return false;
        }
        row->id = (int64_t)(out->n + 1);
        row->name = name.p;
        row->type = type;
        row->content = content.p;
        row->ttl = r->ttl_value;
        row->prio = prio;
        row->ttl_null = row->prio_null = row->disabled = false;
        if (r->type_code == 46 || r->type_code == 47 || r->type_code == 50) out->signed_zone = true;
        if (r->bind_location_tag || r->ecs_subnet_tag) {                // B8: karidns_record_tags
            if (!out->tags && !(out->tags = calloc(arena->count, sizeof(*out->tags)))) goto oom_ext;
            if ((r->bind_location_tag && !zrows_pool_dup(out, r->bind_location_tag, &out->tags[out->n].loc)) ||
                (r->ecs_subnet_tag && !zrows_pool_dup(out, r->ecs_subnet_tag, &out->tags[out->n].ecs)))
                goto oom_ext;
        }
        if (r->tinydns_ttd || r->tinydns_loc[0] || r->tinydns_loc[1]) {  // B8: karidns_record_tinydns
            if (!out->td && !(out->td = calloc(arena->count, sizeof(*out->td)))) goto oom_ext;
            zrows_td_t *t = &out->td[out->n];
            t->has = true;
            t->ttd = (int64_t)r->tinydns_ttd;
            t->countdown = r->tinydns_ttl_countdown;
            t->loc[0] = r->tinydns_loc[0];
            t->loc[1] = r->tinydns_loc[1];
        }
        out->n++;
    }
    out->tinydns = arena->is_tinydns_format;
    if (!zrows_defs_from_arena(out, arena)) goto oom_ext;
    if (!zrows_plain_signed && !zrows_make_presigned(out, err, errlen)) {
        zrows_free(out);
        return false;
    }
    return true;
oom_ext:
    snprintf(err, errlen, "out of memory");
    zrows_free(out);
    return false;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* presigned layout (design 3.6, 8.2): what PowerDNS 5.1.4 stores for a zone that is AXFRed with PRESIGNED=1         */
/* ------------------------------------------------------------------------------------------------------------- */

bool zrows_plain_signed = false;

static int zrows_cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

typedef struct { char **v; size_t n; } zrows_set_t;

static bool zrows_set_has(const zrows_set_t *s, const char *k) {
    return s->n && bsearch(&k, s->v, s->n, sizeof(char *), zrows_cmp_str) != NULL;
}

/* the sorted owner names of the rows of `type` (all rows if type is NULL); pointers into the rows, not owned */
static bool zrows_set_build(const zrows_t *o, const char *type, zrows_set_t *s) {
    s->n = 0;
    s->v = malloc((o->n ? o->n : 1) * sizeof(char *));
    if (!s->v) return false;
    for (size_t i = 0; i < o->n; i++)
        if (!type || (o->rows[i].type && strcmp(o->rows[i].type, type) == 0)) s->v[s->n++] = (char *)o->rows[i].name;
    qsort(s->v, s->n, sizeof(char *), zrows_cmp_str);
    return true;
}

/* strictly below a delegation point (RFC 1034 s4.2.1) */
static bool zrows_occluded(const zrows_t *o, const zrows_set_t *deleg, const char *name) {
    if (strcmp(name, o->zone) == 0) return false;
    for (const char *p = strchr(name, '.'); p; p = strchr(p + 1, '.')) {
        const char *anc = p + 1;
        if (strcmp(anc, o->zone) == 0) return false;
        if (zrows_set_has(deleg, anc)) return true;
    }
    return false;
}

/* PowerDNS' ordername of an NSEC zone: the labels below the apex, reversed, separated by a blank ("x.y.ent" -> "ent y x") */
static void zrows_nsec_ordername(const zrows_t *o, const char *name, char *out, size_t cap) {
    size_t nl = strlen(name), zl = strlen(o->zone);
    out[0] = '\0';
    if (nl <= zl) return;
    size_t end = nl - zl - 1, w = 0;
    while (end > 0 && w + 2 < cap) {
        size_t st = end;
        while (st > 0 && name[st - 1] != '.') st--;
        if (w) out[w++] = ' ';
        if (w + (end - st) + 1 >= cap) break;
        memcpy(out + w, name + st, end - st);
        w += end - st;
        end = st > 0 ? st - 1 : 0;
    }
    out[w] = '\0';
}

static bool zrows_pool_dup(zrows_t *o, const char *s, const char **out) {
    char *d = strdup(s);
    if (!d || !pool_add(o, d)) {
        free(d);
        return false;
    }
    *out = d;
    return true;
}

bool zrows_make_presigned(zrows_t *o, char *err, size_t errlen) {
    size_t n3 = 0, nsec = 0, rs3 = 0, rsn = 0, np_rows = 0;
    for (size_t i = 0; i < o->n; i++) {
        const char *ty = o->rows[i].type, *ct = o->rows[i].content;
        if (!ty) continue;
        if (strcmp(ty, "NSEC3") == 0) n3++;
        if (strcmp(ty, "NSEC3PARAM") == 0) np_rows++;
        if (strcmp(ty, "NSEC") == 0) nsec++;
        if (strcmp(ty, "RRSIG") == 0 && ct && strncasecmp(ct, "NSEC3 ", 6) == 0) rs3++;
        if (strcmp(ty, "RRSIG") == 0 && ct && strncasecmp(ct, "NSEC ", 5) == 0) rsn++;
    }
    /* only a zone PowerDNS could have stored as presigned: a complete chain (RRs and their signatures) of one kind */
    if (n3 && rs3 && np_rows && !nsec && !rsn) {
        /* NSEC3 */
    } else if (nsec && rsn && !n3 && !rs3 && !np_rows) {
        /* NSEC */
    } else {
        return true;                                     /* written as ordinary rows */
    }
    bool mode3 = n3 > 0;
    char meta[300] = "";
    presigned_n3param_t np;
    memset(&np, 0, sizeof(np));
    if (mode3) {
        /* NSEC3PARAM metadata "alg flags iterations salt": parameters of the NSEC3PARAM row, flags (Opt-Out) of the NSEC3 RRs */
        const char *param = NULL, *n3rr = NULL;
        for (size_t i = 0; i < o->n; i++) {
            if (!o->rows[i].type) continue;
            if (!param && strcmp(o->rows[i].type, "NSEC3PARAM") == 0) param = o->rows[i].content;
            if (!n3rr && strcmp(o->rows[i].type, "NSEC3") == 0) n3rr = o->rows[i].content;
        }
        unsigned a = 0, f = 0, it = 0, nf = 0;
        char salt[520] = "";
        if (!param || sscanf(param, "%u %u %u %519s", &a, &f, &it, salt) != 4 || !n3rr || sscanf(n3rr, "%u %u", &a, &nf) != 2) {
            snprintf(err, errlen, "zone '%s': NSEC3 records without a usable NSEC3PARAM record", o->zone);
            return false;
        }
        for (char *p = salt; *p; p++) *p = (char)tolower((unsigned char)*p);
        snprintf(meta, sizeof(meta), "%u %u %u %s", a, nf, it, salt);
        const char *why = "";
        if (!presigned_parse_n3param(meta, &np, &why)) {
            snprintf(err, errlen, "zone '%s': %s", o->zone, why);
            return false;
        }
    }
    zrows_set_t deleg = {0}, ds = {0}, all = {0}, ents = {0};
    db_record_row_t *nr = NULL;
    uint8_t *na = NULL;
    zrows_tag_t *ntag = NULL;
    zrows_td_t *ntd = NULL;
    size_t nn = 0, n_ents_out = 0;
    bool ok = false;
    char hash[33], rel[600], abs[DNS_NAME_TEXT_SIZE + 2];
    size_t ents_cap = o->n * 4 + 1;

    deleg.v = malloc((o->n ? o->n : 1) * sizeof(char *));          /* delegation points: NS below the apex */
    if (!deleg.v) goto oom;
    for (size_t i = 0; i < o->n; i++)
        if (o->rows[i].type && strcmp(o->rows[i].type, "NS") == 0 && strcmp(o->rows[i].name, o->zone) != 0)
            deleg.v[deleg.n++] = (char *)o->rows[i].name;
    qsort(deleg.v, deleg.n, sizeof(char *), zrows_cmp_str);
    if (!zrows_set_build(o, "DS", &ds) || !zrows_set_build(o, NULL, &all)) goto oom;
    /* ENTs: ancestors (below the apex) of the names that are not occluded and are no owner themselves */
    ents.v = malloc(ents_cap * sizeof(char *));
    if (!ents.v) goto oom;
    for (size_t i = 0; i < o->n; i++) {
        const char *nm = o->rows[i].name;
        if (zrows_occluded(o, &deleg, nm) || strcmp(nm, o->zone) == 0) continue;
        if (mode3 && o->rows[i].type && strcmp(o->rows[i].type, "RRSIG") == 0 && o->rows[i].content &&
            strncmp(o->rows[i].content, "NSEC3 ", 6) == 0)
            continue;                                           /* a hashed owner */
        for (const char *p = strchr(nm, '.'); p; p = strchr(p + 1, '.')) {
            const char *anc = p + 1;
            if (strcmp(anc, o->zone) == 0) break;
            if (zrows_set_has(&all, anc)) continue;
            if (ents.n < ents_cap) ents.v[ents.n++] = (char *)anc;
        }
    }
    qsort(ents.v, ents.n, sizeof(char *), zrows_cmp_str);
    {
        size_t w = 0;
        for (size_t i = 0; i < ents.n; i++)
            if (w == 0 || strcmp(ents.v[i], ents.v[w - 1]) != 0) ents.v[w++] = ents.v[i];
        ents.n = w;
    }

    nr = calloc(o->n + ents.n + 1, sizeof(*nr));
    na = calloc(o->n + ents.n + 1, 1);
    if (!nr || !na) goto oom;
    if (o->tags && !(ntag = calloc(o->n + ents.n + 1, sizeof(*ntag)))) goto oom;
    if (o->td && !(ntd = calloc(o->n + ents.n + 1, sizeof(*ntd)))) goto oom;
    for (size_t i = 0; i < o->n; i++) {
        db_record_row_t *r = &o->rows[i];
        const char *ty = r->type ? r->type : "";
        if (mode3 && (strcmp(ty, "NSEC3") == 0 || strcmp(ty, "NSEC3PARAM") == 0)) continue;
        if (!mode3 && strcmp(ty, "NSEC") == 0) continue;
        db_record_row_t *d = &nr[nn];
        *d = *r;
        if (o->tags) ntag[nn] = o->tags[i];                      // B8: the attributes stay with their row
        if (o->td) ntd[nn] = o->td[i];
        d->ordername = NULL;
        na[nn] = 1;
        bool is_rrsig = strcmp(ty, "RRSIG") == 0;
        bool occ = zrows_occluded(o, &deleg, r->name);
        bool is_deleg_ns = strcmp(ty, "NS") == 0 && strcmp(r->name, o->zone) != 0;
        if (occ || is_deleg_ns) na[nn] = 0;
        if (!is_rrsig && !occ) {
            if (mode3) {
                bool insecure = zrows_set_has(&deleg, r->name) && !zrows_set_has(&ds, r->name);
                if (!((np.flags & 1) && insecure)) {
                    snprintf(abs, sizeof(abs), "%s.", r->name);
                    if (!presigned_nsec3_hash(abs, &np, hash)) goto oom;
                    if (!zrows_pool_dup(o, hash, &d->ordername)) goto oom;
                }
            } else {
                zrows_nsec_ordername(o, r->name, rel, sizeof(rel));
                if (!zrows_pool_dup(o, rel, &d->ordername)) goto oom;
            }
        }
        nn++;
    }
    for (size_t i = 0; i < ents.n; i++) {                       /* empty non-terminals: type NULL */
        db_record_row_t *d = &nr[nn];
        if (!zrows_pool_dup(o, ents.v[i], &d->name)) goto oom;
        d->type = NULL;
        d->content = NULL;
        d->ttl_null = d->prio_null = true;
        na[nn] = 1;
        if (mode3) {
            snprintf(abs, sizeof(abs), "%s.", ents.v[i]);
            if (!presigned_nsec3_hash(abs, &np, hash)) goto oom;
            if (!zrows_pool_dup(o, hash, &d->ordername)) goto oom;
        }
        nn++;
        n_ents_out++;
    }
    (void)n_ents_out;
    for (size_t i = 0; i < nn; i++) nr[i].id = (int64_t)(i + 1);
    free(o->rows);
    o->rows = nr;
    nr = NULL;
    o->n = nn;
    free(o->auth);
    o->auth = na;
    na = NULL;
    if (o->tags) {
        free(o->tags);
        o->tags = ntag;
        ntag = NULL;
    }
    if (o->td) {
        free(o->td);
        o->td = ntd;
        ntd = NULL;
    }
    o->presigned = true;
    if (mode3) {
        o->nsec3param = strdup(meta);
        if (!o->nsec3param) goto oom;
    }
    ok = true;
    goto done;
oom:
    snprintf(err, errlen, "out of memory");
done:
    free(deleg.v);
    free(ds.v);
    free(all.v);
    free(ents.v);
    free(nr);
    free(na);
    free(ntag);
    free(ntd);
    return ok;
}


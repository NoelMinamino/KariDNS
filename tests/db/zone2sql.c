/*
 * zone2sql.c - zone file -> PowerDNS 5.1 schema rows / SQL (test importer, beta design 8.2).
 *
 *   zone2sql --dialect sqlite3|pgsql [--zone NAME] zonefile...     (SQL on stdout, one transaction per file)
 *
 * With -DZONE2SQL_LIB only the row generation is built (tests/test_pdns_reader.c links it).
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

#include "zone2sql.h"
#include "../../dns_wire.h"
#include "../../dns_utils.h"
#include "../../dns_zone_parser.h"

/* ------------------------------------------------------------------------------------------------------------- */
/* reading the zone file                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

static char *z2s_read_file(const char *path) {
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

static char *z2s_include_cb(parse_context_t *ctx, const char *path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (out_dev) *out_dev = st.st_dev;
    if (out_ino) *out_ino = st.st_ino;
    return z2s_read_file(path);
}

bool z2s_load_zone_file(const char *path, const char *apex_override, zone_arena_t *arena, char *apex_out,
                        size_t apex_cap, char *err, size_t errlen) {
    zone_arena_init(arena);
    char *buf = z2s_read_file(path);
    if (!buf) {
        snprintf(err, errlen, "cannot read %s", path);
        return false;
    }
    char *display = strdup(buf);
    char *path_copy = strdup(path);
    if (!display || !path_copy || zone_arena_add_file(arena, buf, display, path_copy) != 0) {
        free(display);
        free(path_copy);
        free(buf);
        snprintf(err, errlen, "out of memory");
        return false;
    }
    char dirbuf[PATH_MAX];
    snprintf(dirbuf, sizeof(dirbuf), "%s", path);
    char *base_dir = strdup(dirname(dirbuf));
    char *root_path = realpath(path, NULL);
    struct stat st;
    if (!base_dir || !root_path || stat(path, &st) != 0) {
        free(base_dir);
        free(root_path);
        zone_arena_destroy(arena);
        snprintf(err, errlen, "cannot stat %s", path);
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
    ctx.load_file_cb = z2s_include_cb;
    ctx.shared_ttl_io = &root_ttl;
    ctx.shared_ecs_tag_io = &root_ecs;
    ctx.shared_loc_tag_io = &root_loc;
    visited_paths[0] = root_path;
    visited_devs[0] = st.st_dev;
    visited_inos[0] = st.st_ino;

    int rc = parse_zone_fast(buf, strlen(buf), arena, &ctx);
    free(base_dir);
    free(root_path);
    if (rc < 0) {
        snprintf(err, errlen, "%s: %s", path, perr.error_message ? perr.error_message : "parse error");
        zone_arena_destroy(arena);
        return false;
    }
    /* the zone is the owner of the first SOA */
    const char *apex = apex_override;
    for (size_t i = 0; !apex && i < arena->count; i++)
        if (arena->records[i].type_code == 6) apex = arena->records[i].name;
    if (!apex) {
        snprintf(err, errlen, "%s: no SOA record", path);
        zone_arena_destroy(arena);
        return false;
    }
    snprintf(apex_out, apex_cap, "%s", apex);
    zone_arena_drop_out_of_zone(arena, apex_out, NULL, NULL);
    zone_arena_drop_unencodable(arena, NULL, NULL);
    return true;
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

/* The names PowerDNS 5.1 stores without the trailing dot (checked with pdnsutil load-zone on 5.1.4): NS CNAME PTR
 * DNAME, the MX and AFSDB target, the SRV target, both SOA names, both RP names.  It keeps the dot (as the zone file
 * has the absolute name) in NAPTR, SVCB / HTTPS, RRSIG (signer), NSEC (next name), KX, LP and MINFO, so the same rule
 * is applied here; the reader takes both. */
static bool is_name_field(const dns_record_t *r, int j) {
    switch (r->type_code) {
    case 2: case 5: case 12: case 39:
        return j == 0;
    case 15: case 18:
        return j == 1;
    case 6: case 17:
        return j == 0 || j == 1;
    case 33:
        return j == 3;
    default:
        return false;
    }
}

static bool is_string_field(uint16_t type, int j) {
    switch (type) {
    case 16: case 99: case 258: case 56: case 261: case 13: case 20: case 19:
        return true;
    case 35:
        return j >= 2 && j <= 4;
    case 257: case 256:
        return j == 2;
    case 259:                       /* DOA: media type */
        return j == 3;
    default:
        return false;
    }
}

/* number of leading fields before a base64 / hex blob that may be split (same table as the zone parser) */
static int blob_lead(uint16_t type) {
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
    int lead = blob_lead(r->type_code);
    for (int j = from; j < r->rdata_count; j++) {
        bool glue = lead >= 0 && j > lead;     /* a split blob is one token */
        if (j > from && !glue) ds_adds(out, " ");
        if (is_name_field(r, j)) ds_add_name(out, r->rdata[j]);
        else if (is_string_field(r->type_code, j) || r->rdata[j][0] == '\0') ds_add_quoted(out, r->rdata[j]);   /* an empty token would vanish */
        else ds_adds(out, r->rdata[j]);
    }
    if (out->len == 0) {
        snprintf(err, errlen, "%s record without RDATA", r->type ? r->type : "?");
        return false;
    }
    return !out->oom;
}

static bool pool_add(z2s_rows_t *o, char *s) {
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

void z2s_rows_free(z2s_rows_t *r) {
    for (size_t i = 0; i < r->n_pool; i++) free(r->pool[i]);
    free(r->pool);
    free(r->rows);
    memset(r, 0, sizeof(*r));
}

/* TODO(B5): presigned layout.  For a zone with NSEC3 records PowerDNS stores PRESIGNED=1 and NSEC3PARAM metadata,
 * no NSEC3 / NSEC3PARAM rows, RRSIG(NSEC3) rows at the hashed owners with ordername NULL, and the hash of every
 * other owner (and ENT) in ordername.  This hook is where that conversion goes; B2 only reports the situation. */
static void z2s_presigned_hook(z2s_rows_t *o) {
    if (o->signed_zone)
        fprintf(stderr, "zone2sql: note: zone '%s' has DNSSEC records; written as plain rows (presigned layout: B5)\n", o->zone);
}

bool z2s_rows_from_arena(zone_arena_t *arena, const char *apex, z2s_rows_t *out, char *err, size_t errlen) {
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
            z2s_rows_free(out);
            return false;
        }
        char *type = strdup(get_type_str(r->type_code, arena));
        if (!type) {
            free(name.p);
            free(content.p);
            snprintf(err, errlen, "out of memory");
            z2s_rows_free(out);
            return false;
        }
        if (!pool_add(out, name.p)) {
            free(name.p);
            free(content.p);
            free(type);
            snprintf(err, errlen, "out of memory");
            z2s_rows_free(out);
            return false;
        }
        if (!pool_add(out, content.p)) {
            free(content.p);
            free(type);
            snprintf(err, errlen, "out of memory");
            z2s_rows_free(out);
            return false;
        }
        if (!pool_add(out, type)) {
            free(type);
            snprintf(err, errlen, "out of memory");
            z2s_rows_free(out);
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
        out->n++;
    }
    z2s_presigned_hook(out);
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* SQL                                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static void sql_str(FILE *fp, const char *s) {
    fputc('\'', fp);
    for (; *s; s++) {
        if (*s == '\'') fputc('\'', fp);
        fputc(*s, fp);
    }
    fputc('\'', fp);
}

void z2s_print_sql(FILE *fp, z2s_dialect_t d, const z2s_rows_t *r) {
    const char *f = d == Z2S_PGSQL ? "false" : "0";
    const char *t = d == Z2S_PGSQL ? "true" : "1";
    if (d == Z2S_PGSQL) fputs("SET standard_conforming_strings = on;\n", fp);
    fputs("BEGIN;\n", fp);
    fputs("INSERT INTO domains (name, type) VALUES (", fp);
    sql_str(fp, r->zone);
    fputs(", 'NATIVE');\n", fp);
    for (size_t i = 0; i < r->n; i++) {
        const db_record_row_t *row = &r->rows[i];
        fputs("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES "
              "((SELECT id FROM domains WHERE name = ",
              fp);
        sql_str(fp, r->zone);
        fputs("), ", fp);
        sql_str(fp, row->name);
        fputs(", ", fp);
        sql_str(fp, row->type);
        fputs(", ", fp);
        sql_str(fp, row->content);
        fprintf(fp, ", %lld, %lld, %s, %s);\n", (long long)row->ttl, (long long)row->prio, f, t);
    }
    fputs("COMMIT;\n", fp);
}

#ifndef ZONE2SQL_LIB
int main(int argc, char **argv) {
    z2s_dialect_t dialect = Z2S_SQLITE3;
    const char *apex_override = NULL;
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        if (strcmp(argv[i], "--dialect") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "sqlite3") == 0) dialect = Z2S_SQLITE3;
            else if (strcmp(argv[i], "pgsql") == 0) dialect = Z2S_PGSQL;
            else {
                fprintf(stderr, "zone2sql: unknown dialect '%s' (sqlite3 or pgsql)\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--zone") == 0 && i + 1 < argc) {
            apex_override = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            goto usage;
        }
    }
    if (i >= argc) {
    usage:
        fprintf(stderr, "usage: zone2sql --dialect sqlite3|pgsql [--zone NAME.] zonefile...\n"
                        "  Writes SQL for the PowerDNS 5.1 schema (domains + records) to stdout, one transaction per file.\n"
                        "  Example: zone2sql --dialect sqlite3 tests/zones/example.com.zone | sqlite3 pdns.db\n");
        return 2;
    }
    int rc = 0;
    for (; i < argc; i++) {
        zone_arena_t arena;
        char apex[DNS_NAME_TEXT_SIZE], err[400];
        if (!z2s_load_zone_file(argv[i], apex_override, &arena, apex, sizeof(apex), err, sizeof(err))) {
            fprintf(stderr, "zone2sql: %s\n", err);
            rc = 1;
            continue;
        }
        z2s_rows_t rows;
        if (!z2s_rows_from_arena(&arena, apex, &rows, err, sizeof(err))) {
            fprintf(stderr, "zone2sql: %s: %s\n", argv[i], err);
            zone_arena_destroy(&arena);
            rc = 1;
            continue;
        }
        z2s_print_sql(stdout, dialect, &rows);
        z2s_rows_free(&rows);
        zone_arena_destroy(&arena);
    }
    return rc;
}
#endif

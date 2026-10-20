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
#include "../../dns_presigned.h"

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
 * DNAME, the MX and AFSDB target, the SRV target, both SOA names, both RP names and (B5: seen in a presigned zone
 * AXFRed into the database) the RRSIG signer.  It keeps the dot (as the zone file has the absolute name) in NAPTR,
 * SVCB / HTTPS, NSEC (next name), KX, LP and MINFO, so the same rule
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
    case 46:                        /* RRSIG signer: stored without the dot by AXFR-in (checked on 5.1.4, B5) */
        return j == 7;
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
    free(r->auth);
    free(r->nsec3param);
    memset(r, 0, sizeof(*r));
}

/* B5: the presigned layout (design 3.6, 8.2) is made by z2s_make_presigned() below, at the end of z2s_rows_from_arena(). */

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
    if (!z2s_plain_signed && !z2s_make_presigned(out, err, errlen)) {
        z2s_rows_free(out);
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* presigned layout (design 3.6, 8.2): what PowerDNS 5.1.4 stores for a zone that is AXFRed with PRESIGNED=1         */
/* ------------------------------------------------------------------------------------------------------------- */

bool z2s_plain_signed = false;

static int z2s_cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

typedef struct { char **v; size_t n; } z2s_set_t;

static bool z2s_set_has(const z2s_set_t *s, const char *k) {
    return s->n && bsearch(&k, s->v, s->n, sizeof(char *), z2s_cmp_str) != NULL;
}

/* the sorted owner names of the rows of `type` (all rows if type is NULL); pointers into the rows, not owned */
static bool z2s_set_build(const z2s_rows_t *o, const char *type, z2s_set_t *s) {
    s->n = 0;
    s->v = malloc((o->n ? o->n : 1) * sizeof(char *));
    if (!s->v) return false;
    for (size_t i = 0; i < o->n; i++)
        if (!type || (o->rows[i].type && strcmp(o->rows[i].type, type) == 0)) s->v[s->n++] = (char *)o->rows[i].name;
    qsort(s->v, s->n, sizeof(char *), z2s_cmp_str);
    return true;
}

/* strictly below a delegation point (RFC 1034 s4.2.1) */
static bool z2s_occluded(const z2s_rows_t *o, const z2s_set_t *deleg, const char *name) {
    if (strcmp(name, o->zone) == 0) return false;
    for (const char *p = strchr(name, '.'); p; p = strchr(p + 1, '.')) {
        const char *anc = p + 1;
        if (strcmp(anc, o->zone) == 0) return false;
        if (z2s_set_has(deleg, anc)) return true;
    }
    return false;
}

/* PowerDNS' ordername of an NSEC zone: the labels below the apex, reversed, separated by a blank ("x.y.ent" -> "ent y x") */
static void z2s_nsec_ordername(const z2s_rows_t *o, const char *name, char *out, size_t cap) {
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

static bool z2s_pool_dup(z2s_rows_t *o, const char *s, const char **out) {
    char *d = strdup(s);
    if (!d || !pool_add(o, d)) {
        free(d);
        return false;
    }
    *out = d;
    return true;
}

bool z2s_make_presigned(z2s_rows_t *o, char *err, size_t errlen) {
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
    z2s_set_t deleg = {0}, ds = {0}, all = {0}, ents = {0};
    db_record_row_t *nr = NULL;
    uint8_t *na = NULL;
    size_t nn = 0, n_ents_out = 0;
    bool ok = false;
    char hash[33], rel[600], abs[DNS_NAME_TEXT_SIZE + 2];
    size_t ents_cap = o->n * 4 + 1;

    deleg.v = malloc((o->n ? o->n : 1) * sizeof(char *));          /* delegation points: NS below the apex */
    if (!deleg.v) goto oom;
    for (size_t i = 0; i < o->n; i++)
        if (o->rows[i].type && strcmp(o->rows[i].type, "NS") == 0 && strcmp(o->rows[i].name, o->zone) != 0)
            deleg.v[deleg.n++] = (char *)o->rows[i].name;
    qsort(deleg.v, deleg.n, sizeof(char *), z2s_cmp_str);
    if (!z2s_set_build(o, "DS", &ds) || !z2s_set_build(o, NULL, &all)) goto oom;
    /* ENTs: ancestors (below the apex) of the names that are not occluded and are no owner themselves */
    ents.v = malloc(ents_cap * sizeof(char *));
    if (!ents.v) goto oom;
    for (size_t i = 0; i < o->n; i++) {
        const char *nm = o->rows[i].name;
        if (z2s_occluded(o, &deleg, nm) || strcmp(nm, o->zone) == 0) continue;
        if (mode3 && o->rows[i].type && strcmp(o->rows[i].type, "RRSIG") == 0 && o->rows[i].content &&
            strncmp(o->rows[i].content, "NSEC3 ", 6) == 0)
            continue;                                           /* a hashed owner */
        for (const char *p = strchr(nm, '.'); p; p = strchr(p + 1, '.')) {
            const char *anc = p + 1;
            if (strcmp(anc, o->zone) == 0) break;
            if (z2s_set_has(&all, anc)) continue;
            if (ents.n < ents_cap) ents.v[ents.n++] = (char *)anc;
        }
    }
    qsort(ents.v, ents.n, sizeof(char *), z2s_cmp_str);
    {
        size_t w = 0;
        for (size_t i = 0; i < ents.n; i++)
            if (w == 0 || strcmp(ents.v[i], ents.v[w - 1]) != 0) ents.v[w++] = ents.v[i];
        ents.n = w;
    }

    nr = calloc(o->n + ents.n + 1, sizeof(*nr));
    na = calloc(o->n + ents.n + 1, 1);
    if (!nr || !na) goto oom;
    for (size_t i = 0; i < o->n; i++) {
        db_record_row_t *r = &o->rows[i];
        const char *ty = r->type ? r->type : "";
        if (mode3 && (strcmp(ty, "NSEC3") == 0 || strcmp(ty, "NSEC3PARAM") == 0)) continue;
        if (!mode3 && strcmp(ty, "NSEC") == 0) continue;
        db_record_row_t *d = &nr[nn];
        *d = *r;
        d->ordername = NULL;
        na[nn] = 1;
        bool is_rrsig = strcmp(ty, "RRSIG") == 0;
        bool occ = z2s_occluded(o, &deleg, r->name);
        bool is_deleg_ns = strcmp(ty, "NS") == 0 && strcmp(r->name, o->zone) != 0;
        if (occ || is_deleg_ns) na[nn] = 0;
        if (!is_rrsig && !occ) {
            if (mode3) {
                bool insecure = z2s_set_has(&deleg, r->name) && !z2s_set_has(&ds, r->name);
                if (!((np.flags & 1) && insecure)) {
                    snprintf(abs, sizeof(abs), "%s.", r->name);
                    if (!presigned_nsec3_hash(abs, &np, hash)) goto oom;
                    if (!z2s_pool_dup(o, hash, &d->ordername)) goto oom;
                }
            } else {
                z2s_nsec_ordername(o, r->name, rel, sizeof(rel));
                if (!z2s_pool_dup(o, rel, &d->ordername)) goto oom;
            }
        }
        nn++;
    }
    for (size_t i = 0; i < ents.n; i++) {                       /* empty non-terminals: type NULL */
        db_record_row_t *d = &nr[nn];
        if (!z2s_pool_dup(o, ents.v[i], &d->name)) goto oom;
        d->type = NULL;
        d->content = NULL;
        d->ttl_null = d->prio_null = true;
        na[nn] = 1;
        if (mode3) {
            snprintf(abs, sizeof(abs), "%s.", ents.v[i]);
            if (!presigned_nsec3_hash(abs, &np, hash)) goto oom;
            if (!z2s_pool_dup(o, hash, &d->ordername)) goto oom;
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
    return ok;
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

static void sql_val(FILE *fp, const char *s) {
    if (s) sql_str(fp, s);
    else fputs("NULL", fp);
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
        fputs("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth, ordername) VALUES "
              "((SELECT id FROM domains WHERE name = ",
              fp);
        sql_str(fp, r->zone);
        fputs("), ", fp);
        sql_str(fp, row->name);
        fputs(", ", fp);
        sql_val(fp, row->type);
        fputs(", ", fp);
        sql_val(fp, row->content);
        fputs(", ", fp);
        if (row->ttl_null) fputs("NULL", fp);
        else fprintf(fp, "%lld", (long long)row->ttl);
        fputs(", ", fp);
        if (row->prio_null) fputs("NULL", fp);
        else fprintf(fp, "%lld", (long long)row->prio);
        fprintf(fp, ", %s, %s, ", f, (!r->auth || r->auth[i]) ? t : f);
        sql_val(fp, row->ordername);
        fputs(");\n", fp);
    }
    if (r->presigned) {
        fputs("INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = ", fp);
        sql_str(fp, r->zone);
        fputs("), 'PRESIGNED', '1');\n", fp);
    }
    if (r->nsec3param) {
        fputs("INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = ", fp);
        sql_str(fp, r->zone);
        fputs("), 'NSEC3PARAM', ", fp);
        sql_str(fp, r->nsec3param);
        fputs(");\n", fp);
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
        } else if (strcmp(argv[i], "--plain-signed") == 0) {
            z2s_plain_signed = true;
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
        fprintf(stderr, "usage: zone2sql --dialect sqlite3|pgsql [--zone NAME.] [--plain-signed] zonefile...\n"
                        "  Writes SQL for the PowerDNS 5.1 schema (domains + records) to stdout, one transaction per file.\n"
                        "  A zone that holds NSEC3 or NSEC records is written the way PowerDNS 5.1 stores a presigned zone (PRESIGNED\n"
                        "  metadata, NSEC3PARAM metadata, no NSEC3 / NSEC3PARAM / NSEC rows, ordername, ENT rows);\n"
                        "  --plain-signed writes the DNSSEC records as ordinary rows instead.\n"
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

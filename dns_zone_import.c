/*
 * dns_zone_import.c - the ZoneImporter of 0.6.0 (dns_zone_import.h): a zone file or tinydns data file into a PowerDNS 5.1 database.
 * Ordinary process code (malloc allowed); the server does not link it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "dns_zone_import.h"
#include "dns_zone_rows.h"
#include "dns_zone_export.h"
#include "dns_zone_lint.h"
#include "dns_wire.h"

#define ZI_STDIN_NAME "standard input"
#define ZI_STDIN_MAX ((size_t)64 << 20)             /* the limit of karicheck for a zone on standard input */

struct zi_s {
    zi_opts_t o;
    const db_driver_t *drv;
    db_conn_t *conn;
    db_schema_info_t si;
    char **types;                                   /* the types filter, upper case */
    size_t ntypes;
    char zone_type[16];                             /* upper case, "" = NATIVE */
    zmsg_t msg;
    int demoted;                                    /* findings of the zone checks that a partial file (merge, types) is not judged by */
};

/* ------------------------------------------------------------------------------------------------------------- */
/* options                                                                                                        */
/* ------------------------------------------------------------------------------------------------------------- */

#define ZI_ERR(z, code, file, ...) zmsg_emit(&(z)->msg, DIAG_ERROR, (code), (file), __VA_ARGS__)
#define ZI_WARN(z, code, file, ...) zmsg_emit(&(z)->msg, DIAG_WARNING, (code), (file), __VA_ARGS__)

/* a record type token as the database stores it: letters, digits, '-', first character a letter, at most 32 (dns_pdns_reader.h row rule 3) */
static bool zi_type_token_ok(const char *t) {
    size_t n = strlen(t);
    if (n == 0 || n > PDNS_MAX_TYPE_LEN || !isalpha((unsigned char)t[0])) return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)t[i]) && t[i] != '-') return false;
    return true;
}

static bool zi_view_ok(const char *v) {
    size_t n = strlen(v);
    if (n == 0 || n > 64) return false;                 /* karidns_domain_views.view_name is VARCHAR(64) */
    for (size_t i = 0; i < n; i++)
        if (!isgraph((unsigned char)v[i])) return false;
    return true;
}

static void zi_upper(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) dst[i] = (char)toupper((unsigned char)src[i]);
    dst[i] = '\0';
}

void zi_close(zi_t *z) {
    if (!z) return;
    if (z->conn) z->drv->close(z->conn);
    for (size_t i = 0; i < z->ntypes; i++) free(z->types[i]);
    free(z->types);
    free(z);
}

zi_t *zi_open(const zi_opts_t *o) {
    zmsg_t m = o->msg;
    if (!o->drv || !o->drv->open_write || !o->drv->w_begin) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPEN, NULL, "the database driver cannot write");
        return NULL;
    }
    for (size_t i = 0; i < o->ntypes; i++)
        if (!zi_type_token_ok(o->types[i])) {
            zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPTION, NULL, "'%.40s' is not a record type name (letters, digits and '-')", o->types[i]);
            return NULL;
        }
    if (o->view && !zi_view_ok(o->view)) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPTION, NULL, "the view name must be 1 to 64 printable characters without blanks");
        return NULL;
    }
    char ztype[16] = "";
    if (o->zone_type) {
        zi_upper(ztype, sizeof(ztype), o->zone_type);
        static const char *const ok[] = { "NATIVE", "MASTER", "SLAVE", "PRODUCER", "CONSUMER" };
        bool found = false;
        for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
            if (strcmp(ztype, ok[i]) == 0) found = true;
        if (!found) {
            zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPTION, NULL, "'%.20s' is not a zone type (NATIVE, MASTER, SLAVE, PRODUCER or CONSUMER)", o->zone_type);
            return NULL;
        }
    }
    zi_t *z = calloc(1, sizeof(*z));
    if (!z) {
        zmsg_emit(&m, DIAG_ERROR, DC_INTERNAL_OOM, NULL, "out of memory");
        return NULL;
    }
    z->o = *o;
    z->drv = o->drv;
    z->msg = o->msg;
    snprintf(z->zone_type, sizeof(z->zone_type), "%s", ztype);
    if (o->ntypes) {
        z->types = calloc(o->ntypes, sizeof(char *));
        for (size_t i = 0; z->types && i < o->ntypes; i++) {
            char up[PDNS_MAX_TYPE_LEN + 1];
            zi_upper(up, sizeof(up), o->types[i]);
            if (!(z->types[i] = strdup(up))) break;
            z->ntypes++;
        }
        if (!z->types || z->ntypes != o->ntypes) {
            zmsg_emit(&m, DIAG_ERROR, DC_INTERNAL_OOM, NULL, "out of memory");
            zi_close(z);
            return NULL;
        }
    }
    char err[DB_ERRLEN];
    if (z->drv->open_write(&z->conn, &o->src, err, sizeof(err)) != 0) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPEN, NULL, "%s", err);
        z->conn = NULL;
        zi_close(z);
        return NULL;
    }
    if (z->drv->w_set_audit && (o->audit_summary || o->audit_actor) && z->drv->w_set_audit(z->conn, o->audit_summary, o->audit_actor) != 0) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPEN, NULL, "%s", z->drv->errmsg(z->conn));
        zi_close(z);
        return NULL;
    }
    if (z->drv->check_schema(z->conn, &z->si) != 0) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_SCHEMA, NULL, "%s", z->drv->errmsg(z->conn));
        zi_close(z);
        return NULL;
    }
    if (o->view && !z->si.has_domain_views) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_SCHEMA, NULL, "a view was asked for but the database has no karidns_domain_views table (apply db/karidns_ext.*.sql)");
        zi_close(z);
        return NULL;
    }
    return z;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* input                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { char *text; size_t len; time_t mtime; const char *shown; bool from_file; } zi_text_t;     /* from_file: shown is a real path ( is read from its directory) */

static bool zi_read_fd(zi_t *z, int fd, size_t size_hint, size_t max, const char *shown, zi_text_t *t) {
    size_t cap = size_hint ? size_hint + 1 : 65536, len = 0;
    char *buf = malloc(cap + 1);
    if (!buf) {
        ZI_ERR(z, DC_INTERNAL_OOM, shown, "out of memory");
        return false;
    }
    for (;;) {
        if (len == cap) {
            if (max && cap >= max) {                  /* full, and there may be more: one more byte decides */
                char probe;
                ssize_t more;
                while ((more = read(fd, &probe, 1)) < 0 && errno == EINTR) {}
                if (more == 0) break;
                free(buf);
                ZI_ERR(z, DC_IO_STDIN_TOO_LARGE, shown, "The zone text on standard input is larger than %zu bytes", max);
                return false;
            }
            size_t nc = cap * 2;
            char *nb = realloc(buf, nc + 1);
            if (!nb) {
                free(buf);
                ZI_ERR(z, DC_INTERNAL_OOM, shown, "out of memory");
                return false;
            }
            buf = nb;
            cap = nc;
        }
        ssize_t got = read(fd, buf + len, cap - len);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) {
            int e = errno;
            free(buf);
            if (max) ZI_ERR(z, DC_IO_STDIN_READ, shown, "Could not read standard input: %s", strerror(e));
            else ZI_ERR(z, DC_IO_READ, shown, "Could not read %s: %s", shown, strerror(e));
            return false;
        }
        if (got == 0) break;
        len += (size_t)got;
    }
    buf[len] = '\0';
    t->text = buf;
    t->len = len;
    return true;
}

/* The text of the input: memory (copied), standard input ("-") or a regular file.  false: a message was given. */
static bool zi_get_text(zi_t *z, const zi_input_t *in, zi_text_t *t) {
    memset(t, 0, sizeof(*t));
    if (in->text) {
        t->shown = in->path ? in->path : ZI_STDIN_NAME;
        t->text = malloc(in->len + 1);
        if (!t->text) {
            ZI_ERR(z, DC_INTERNAL_OOM, t->shown, "out of memory");
            return false;
        }
        memcpy(t->text, in->text, in->len);
        t->text[in->len] = '\0';
        t->len = in->len;
        t->mtime = in->mtime;
    } else if (in->path && strcmp(in->path, "-") == 0) {
        t->shown = ZI_STDIN_NAME;
        if (!zi_read_fd(z, 0, 0, ZI_STDIN_MAX, t->shown, t)) return false;
        t->mtime = in->mtime;
    } else if (in->path) {
        t->shown = in->path;
        t->from_file = true;
        int fd = open(in->path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            ZI_ERR(z, DC_IO_OPEN, in->path, "Could not open %s: %s", in->path, strerror(errno));
            return false;
        }
        struct stat sb;
        if (fstat(fd, &sb) != 0) {
            ZI_ERR(z, DC_IO_STAT, in->path, "Could not examine %s: %s", in->path, strerror(errno));
            close(fd);
            return false;
        }
        if (!S_ISREG(sb.st_mode)) {
            ZI_ERR(z, DC_IO_NOT_REGULAR, in->path, "%s is not a regular file", in->path);
            close(fd);
            return false;
        }
        bool ok = zi_read_fd(z, fd, sb.st_size > 0 ? (size_t)sb.st_size : 0, 0, in->path, t);
        close(fd);
        if (!ok) return false;
        t->mtime = sb.st_mtime;
    } else {
        ZI_ERR(z, DC_USAGE_ARGS, NULL, "no zone file given");
        return false;
    }
    if (strlen(t->text) != t->len) {
        ZI_ERR(z, DC_IO_READ, t->shown, "%s contains a NUL byte", t->shown);
        free(t->text);
        t->text = NULL;
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the zone checks of karicheck                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static void zi_lint_sink(void *ud, char level, dns_diag_code_t code, const char *text) {
    zi_t *z = ud;
    /* A file that is only a part of the zone (merge, or limited to some types) may lack the SOA, the NS records or the glue of the zone: the rest of
     * the zone is in the database.  Those three findings are not printed and not counted (kc_error() counts after the sink returns). */
    if (level == 'E' && (z->o.mode == ZI_MERGE || z->ntypes > 0) && (code == DC_ZONE_SOA_MISSING || code == DC_ZONE_NS_MISSING || code == DC_ZONE_GLUE_MISSING)) {
        z->demoted++;
        return;
    }
    switch (level) {
    case 'E': zmsg_emit(&z->msg, DIAG_ERROR, code, NULL, "%s", text); break;
    case 'W': zmsg_emit(&z->msg, DIAG_WARNING, code, NULL, "%s", text); break;
    case 'I': zmsg_emit(&z->msg, DIAG_INFO, code, NULL, "%s", text); break;
    case 'D': zmsg_emit(&z->msg, ZMSG_DETAIL, DC_NONE, NULL, "%s", text); break;
    default: break;                                     /* 'O': a check that passed */
    }
}

/* the check-* severities and the tag definitions of the server configuration (zi_opts_t) */
static void zi_lint_policy(const zi_t *z, zone_lint_in_t *lin) {
    lin->chk = z->o.chk;
    lin->chk_names = z->o.chk_names;
    lin->ecs_tags = z->o.ecs_tags;
    lin->ecs_tag_count = z->o.n_ecs_tags;
    lin->loc_tags = z->o.loc_tags;
    lin->loc_tag_count = z->o.n_loc_tags;
}

/* `karicheck zone` on the parsed zone, in its order (tools/karicheck.c check_zone_run), without the options of a server configuration (every
 * check has the severity it has by default).  Fills rows from the raw arena first: the TTL harmonization of build_zone_index(true) must not
 * reach the rows (zone2sql and the loader's reader store the TTLs as written).  false: errors (or warnings with strict). */
static bool zi_check_zone(zi_t *z, zone_arena_t *arena, const char *apex, const char *shown, const char *raw_text, bool tinydns, const zrows_info_t *info,
                          zrows_t *rows, zi_result_t *res) {
    kc_tally_t t = {0};
    z->demoted = 0;
    t.sink = zi_lint_sink;
    t.sink_ud = z;
    if (arena->count == 0) {
        kc_error(&t, DC_ZONE_EMPTY, "No records found in zone '%s' (%s)\n", apex, shown);
        return false;
    }
    if (info->out_of_zone > 0)
        kc_warning(&t, DC_ZONE_OUT_OF_ZONE, "Zone '%s': %zu record(s) outside the zone are ignored (first: '%s')\n", apex, info->out_of_zone,
                   info->first_out_of_zone);
    if (info->tinydns_out_of_zone > 0)
        kc_warning(&t, DC_ZONE_TINYDNS_OUT_OF_ZONE, "Zone '%s': %zu tinydns record(s) belong to no zone of the data file and are ignored (first: '%s')\n", apex,
                   info->tinydns_out_of_zone, info->first_tinydns_out_of_zone);
    zone_lint_ttl(arena, "zone file", &t);
    if (info->no_ttl > 0 && !tinydns)
        kc_warning(&t, DC_ZONE_TTL_MISSING, "Zone '%s': %s:%zu: no TTL specified for '%s' (no $TTL, no earlier TTL, no SOA to take one from); %zu record(s) are served "
                   "with 3600; BIND rejects such a zone (\"no TTL specified\"). Add a $TTL line\n",
                   apex, info->no_ttl_file[0] ? info->no_ttl_file : shown, info->no_ttl_line, info->no_ttl_owner, info->no_ttl);
    if (info->long_txt > 0 && !tinydns)
        kc_warning(&t, DC_ZONE_STRING_LONG, "Zone '%s': %s:%zu: a character-string of more than 255 octets in '%s' (%zu record(s) in all); BIND rejects this. It is "
                   "served as 255-octet strings\n",
                   apex, info->long_txt_file[0] ? info->long_txt_file : shown, info->long_txt_line, info->long_txt_owner, info->long_txt);
    char err[400];
    if (!zrows_from_arena(arena, apex, rows, err, sizeof(err))) {
        ZI_ERR(z, DC_DB_IMPORT_ROWS, shown, "Zone '%s': %s", apex, err);
        return false;
    }
    if (build_zone_index(arena, true) != 0) {
        kc_error(&t, DC_INTERNAL_OOM, "Memory allocation failed during index build for '%s'\n", apex);
        return false;
    }
    parse_error_t perr = {0};
    if (validate_zone_dname(arena, &perr) < 0 || validate_zone_name_lengths(arena, &perr) < 0) {
        kc_error(&t, DC_ZONE_SYNTAX, "Zone '%s': %s\n", apex, perr.error_message ? perr.error_message : "invalid zone");
        return false;
    }
    char detail[400];
    if (validate_zone_pdns_types(arena, &perr, detail, sizeof(detail)) < 0) {
        kc_error(&t, DC_ZONE_PDNS_TYPES, "Zone '%s': %s (the server does not load this zone)\n", apex, detail);
        return false;
    }
    zone_lint_pdns_types(arena, apex, &t);
    zone_lint_in_t lin = {0};
    lin.domain = apex;
    lin.src = shown;
    lin.raw_text = raw_text;
    zi_lint_policy(z, &lin);
    zone_lint_records(arena, &lin, &t);
    res->warnings = (size_t)t.warnings;
    const int errors = t.errors - z->demoted;
    if (errors > 0) {
        ZI_ERR(z, DC_DB_IMPORT_CHECKS, shown, "Zone '%s': %d error(s) in the zone checks; nothing was written", apex, errors);
        return false;
    }
    if (z->o.strict && t.warnings > 0) {
        ZI_ERR(z, DC_DB_IMPORT_STRICT, shown, "Zone '%s': %d warning(s) in the zone checks and strict mode is on; nothing was written", apex, t.warnings);
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the rows of the database zone, and the difference to the rows of the file                                      */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    int64_t id;
    char *owner, *type, *content;                       /* owner: lower case, no final dot; type: upper case, "" for an empty non-terminal */
    int64_t ttl, prio;                                  /* -1 = NULL */
} dbrec_t;

typedef struct { dbrec_t *v; size_t n, cap; bool oom; } dbrecs_t;

/* the form of a name the comparisons use: ASCII lower case, one final dot dropped (the root stays "") */
static char *zi_canon(const char *s, bool upper) {
    size_t n = s ? strlen(s) : 0;
    if (!upper && n > 0 && s[n - 1] == '.') n--;
    char *o = malloc(n + 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = (char)(upper ? toupper((unsigned char)s[i]) : tolower((unsigned char)s[i]));
    o[n] = '\0';
    return o;
}

static int zi_cb_rec(void *ud, int64_t did, const db_record_row_t *r) {
    (void)did;
    dbrecs_t *a = ud;
    if (a->n == a->cap) {
        size_t nc = a->cap ? a->cap * 2 : 256;
        dbrec_t *nv = realloc(a->v, nc * sizeof(*nv));
        if (!nv) return a->oom = true;
        a->v = nv;
        a->cap = nc;
    }
    dbrec_t *d = &a->v[a->n];
    d->id = r->id;
    d->owner = zi_canon(r->name, false);
    d->type = zi_canon(r->type, true);
    d->content = strdup(r->content ? r->content : "");
    d->ttl = r->ttl_null ? -1 : r->ttl;
    d->prio = r->prio_null ? -1 : r->prio;
    if (!d->owner || !d->type || !d->content) {
        free(d->owner);
        free(d->type);
        free(d->content);
        return a->oom = true;
    }
    a->n++;
    return 0;
}

static void zi_recs_free(dbrecs_t *a) {
    for (size_t i = 0; i < a->n; i++) {
        free(a->v[i].owner);
        free(a->v[i].type);
        free(a->v[i].content);
    }
    free(a->v);
    memset(a, 0, sizeof(*a));
}

typedef struct { bool found, ambiguous; int64_t id; char *name, *type, *soa; const char *want; } zfind_t;

static int zi_cb_zone(void *ud, const db_zone_row_t *r) {
    zfind_t *f = ud;
    if (!r->name || !zrows_names_equal(r->name, f->want)) return 0;          /* the match is decided here, in C, not by an SQL collation */
    if (f->found) {
        if (r->id != f->id) f->ambiguous = true;
        return 0;
    }
    f->found = true;
    f->id = r->id;
    f->name = strdup(r->name);
    f->type = strdup(r->type ? r->type : "");
    f->soa = r->soa_content ? strdup(r->soa_content) : NULL;
    return 0;
}

/* one record as the comparisons and the report see it */
typedef struct { const char *owner, *type, *content; int64_t ttl, prio; } rrv_t;

static int zi_cmp_key(const rrv_t *a, const rrv_t *b) {
    int c = strcmp(a->owner, b->owner);
    return c ? c : strcmp(a->type, b->type);
}

static int zi_cmp_rrv(const void *x, const void *y) {
    const rrv_t *a = x, *b = y;
    int c = zi_cmp_key(a, b);
    if (c) return c;
    if (a->ttl != b->ttl) return a->ttl < b->ttl ? -1 : 1;
    if (a->prio != b->prio) return a->prio < b->prio ? -1 : 1;
    return strcmp(a->content, b->content);
}

typedef struct { char what; const char *owner, *type; } zi_item_t;

/* The RRsets of the rows a (deleted) against those of b (inserted): in a only '-', in b only '+', in both with other rows '~'. */
static bool zi_diff(rrv_t *a, size_t na, rrv_t *b, size_t nb, zi_item_t **out, size_t *nout, zi_result_t *res) {
    qsort(a, na, sizeof(*a), zi_cmp_rrv);
    qsort(b, nb, sizeof(*b), zi_cmp_rrv);
    zi_item_t *items = malloc((na + nb + 1) * sizeof(*items));
    if (!items) return false;
    size_t n = 0, i = 0, j = 0;
    while (i < na || j < nb) {
        int c = i >= na ? 1 : j >= nb ? -1 : zi_cmp_key(&a[i], &b[j]);
        size_t ie = i, je = j;
        if (c <= 0)
            while (ie < na && zi_cmp_key(&a[ie], &a[i]) == 0) ie++;
        if (c >= 0)
            while (je < nb && zi_cmp_key(&b[je], &b[j]) == 0) je++;
        if (c < 0) {
            items[n++] = (zi_item_t){ '-', a[i].owner, a[i].type };
            res->rrsets_deleted++;
        } else if (c > 0) {
            items[n++] = (zi_item_t){ '+', b[j].owner, b[j].type };
            res->rrsets_added++;
        } else {
            bool same = ie - i == je - j;
            for (size_t k = 0; same && k < ie - i; k++) same = zi_cmp_rrv(&a[i + k], &b[j + k]) == 0;
            if (!same) {
                items[n++] = (zi_item_t){ '~', b[j].owner, b[j].type };
                res->rrsets_replaced++;
            }
        }
        i = ie;
        j = je;
    }
    *out = items;
    *nout = n;
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the SOA serial                                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

/* RFC 1982 section 3.2: s1 > s2 in serial number arithmetic (SERIAL_BITS 32).  Two numbers 2^31 apart have no order. */
static bool zi_serial_gt(uint32_t s1, uint32_t s2) {
    return (s1 < s2 && s2 - s1 > 0x80000000u) || (s1 > s2 && s1 - s2 < 0x80000000u);
}

/* the content of an SOA row with the serial (its third field) replaced; NULL on out of memory or a content without that field */
static char *zi_soa_with_serial(const char *content, uint32_t serial) {
    const char *p = content;
    for (int f = 0; f < 2; f++) {
        while (*p == ' ' || *p == '\t') p++;
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    while (*p == ' ' || *p == '\t') p++;
    const char *start = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    if (start == p) return NULL;
    size_t pre = (size_t)(start - content), post = strlen(p);
    char *o = malloc(pre + 12 + post);
    if (!o) return NULL;
    memcpy(o, content, pre);
    int w = snprintf(o + pre, 12, "%u", (unsigned)serial);
    memcpy(o + pre + w, p, post + 1);
    return o;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* one zone into the database                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

static int zi_dbfail(zi_t *z, const char *what) {
    ZI_ERR(z, DC_DB_IMPORT_WRITE, NULL, "%s: %s; the transaction was rolled back and nothing was written", what, z->drv->errmsg(z->conn));
    return ZI_FAIL;
}

static bool zi_type_wanted(const zi_t *z, const char *type) {
    if (z->ntypes == 0) return true;
    if (!type || !*type) return false;                  /* an empty non-terminal has no type: a types filter never touches it */
    for (size_t i = 0; i < z->ntypes; i++)
        if (strcasecmp(z->types[i], type) == 0) return true;
    return false;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the read-back                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

static bool zi_primary_type(const char *t) { return t && (strcasecmp(t, "NATIVE") == 0 || strcasecmp(t, "MASTER") == 0); }

typedef struct {
    zi_t *z;
    const char *shown;
    bool partial;                                       /* the file was a part of the zone: the findings about the rest of it are new to the user */
    bool show;                                          /* the finding before a detail line was printed */
} zv_t;

static void zi_verify_sink(void *ud, char level, dns_diag_code_t code, const char *text) {
    zv_t *v = ud;
    switch (level) {
    case 'E':
        v->show = true;
        zmsg_emit(&v->z->msg, DIAG_ERROR, code, v->shown, "%s", text);
        break;
    case 'W':
        v->show = v->partial;
        if (v->show) zmsg_emit(&v->z->msg, DIAG_WARNING, code, v->shown, "%s", text);
        break;
    case 'D':
        if (v->show) zmsg_emit(&v->z->msg, ZMSG_DETAIL, DC_NONE, v->shown, "%s", text);
        break;
    default: break;                                     /* 'I', 'O' */
    }
}

/* The zone as the loader will read it: the rows just written (same transaction) go through the PowerDNS reader of karidns-dbloader (every row
 * checked, ALIAS beside A / AAAA, ALIAS in a signed zone, SOA rules, a presigned zone rebuilt), then the size limits of the server and the
 * checks of `karicheck db` (zone_lint_records with the check-* severities of the configuration).  An error refuses the import.  The warnings
 * of a whole zone are the ones the checks of the file gave already; of a part (merge, types) they are about the rest of the zone and are shown
 * (and fail in strict mode).  false: a message was given. */
static bool zi_verify(zi_t *z, const char *zone, int64_t did, const char *shown, bool partial, zi_result_t *res) {
    pdns_zone_t *pz = NULL;
    switch (zx_read_zone(z->drv, z->conn, z->si.has_ext, zone, did, &z->o.reader, &pz, NULL)) {
    case ZX_READ_OK: break;
    case ZX_READ_OOM:
        ZI_ERR(z, DC_INTERNAL_OOM, shown, "out of memory");
        return false;
    case ZX_READ_DB:
        zi_dbfail(z, "reading the zone back");
        return false;
    default:
        ZI_ERR(z, DC_DB_IMPORT_VERIFY, shown, "Zone '%s': the loader's reader refuses the rows just written: %s; the transaction was rolled back and nothing was written",
               zone, pz->error);
        pdns_zone_free(pz);
        return false;
    }
    bool ok = false;
    char lim_err[320];
    kc_tally_t t = {0};
    zv_t v = { z, shown, partial, false };
    t.sink = zi_verify_sink;
    t.sink_ud = &v;
    if (zone_arena_check_limits(&pz->arena, &z->o.limits, lim_err, sizeof(lim_err)) < 0) {
        ZI_ERR(z, DC_ZONE_LIMITS, shown, "Zone '%s': %s (the server does not load this zone); the transaction was rolled back and nothing was written", zone, lim_err);
        goto out;
    }
    if (partial) zone_lint_ttl(&pz->arena, "database", &t);
    zone_lint_in_t lin = {0};
    lin.domain = pz->name;
    lin.src = shown;
    zi_lint_policy(z, &lin);
    zone_lint_records(&pz->arena, &lin, &t);
    if (t.errors > 0) {
        ZI_ERR(z, DC_DB_IMPORT_VERIFY, shown, "Zone '%s': the zone as written has %d error(s) in the checks of `karicheck db`; the transaction was rolled back and nothing was "
               "written", zone, t.errors);
        goto out;
    }
    if (partial) {
        res->warnings += (size_t)t.warnings;
        if (z->o.strict && t.warnings > 0) {
            ZI_ERR(z, DC_DB_IMPORT_STRICT, shown, "Zone '%s': %d warning(s) in the checks of the zone as written and strict mode is on; nothing was written", zone, t.warnings);
            goto out;
        }
    }
    ok = true;
out:
    pdns_zone_free(pz);
    return ok;
}

static const char *const ZI_OWNED_META[3] = { "PRESIGNED", "NSEC3PARAM", "X-KARIDNS-FORMAT" };

/* Everything in the transaction.  Returns ZI_OK, ZI_FAIL or ZI_BUSY; the caller rolls back unless this committed (res->committed). */
static int zi_apply(zi_t *z, zrows_t *rows, const char *shown, zi_result_t *res) {
    const db_driver_t *d = z->drv;
    db_conn_t *c = z->conn;
    const bool filter = z->ntypes > 0;
    const bool whole = !filter;                         /* the metadata and the tag definitions belong to the import */
    int status = ZI_FAIL;
    dbrecs_t db = {0};
    zfind_t zf = {0};
    int64_t *del_ids = NULL;
    size_t ndel = 0, *ins = NULL, nins = 0;
    rrv_t *va = NULL, *vb = NULL;
    size_t nva = 0;
    zi_item_t *items = NULL;
    size_t nitems = 0;
    char **soa_new = NULL;                              /* SOA contents rewritten for --serial increment (owned here) */
    size_t nsoa_new = 0;
    bool in_tx = false;

    if ((rows->tags || rows->td || rows->ndefs) && !z->si.has_ext) {
        ZI_ERR(z, DC_DB_IMPORT_SCHEMA, shown, "Zone '%s' has tags, tinydns attributes or tag definitions, but the database has no karidns_record_tags / "
               "karidns_record_tinydns / karidns_zone_tagdefs tables (apply db/karidns_ext.*.sql)", rows->zone);
        goto out;
    }
    for (size_t i = 0; i < z->o.nfile_zones; i++)
        if (zrows_names_equal(z->o.file_zones[i], rows->zone)) {
            ZI_WARN(z, DC_DB_IMPORT_FILE_ZONE, shown, "Zone '%s' is also a file zone of the server configuration; the server serves the file zone, not the database zone",
                    rows->zone);
            break;
        }

    /* the rows to insert: the file's, limited by the types filter */
    ins = malloc((rows->n ? rows->n : 1) * sizeof(*ins));
    if (!ins) goto oom;
    for (size_t i = 0; i < rows->n; i++)
        if (zi_type_wanted(z, rows->rows[i].type)) ins[nins++] = i;

    int rc = d->w_begin(c, rows->zone);
    if (rc != 0) {
        if (rc == DB_ERR_RETRY) {
            ZI_ERR(z, DC_DB_IMPORT_BUSY, shown, "Zone '%s' is locked by another import or the database is busy: %s", rows->zone, d->errmsg(c));
            status = ZI_BUSY;
        } else {
            zi_dbfail(z, "begin");
        }
        goto out;
    }
    in_tx = true;

    zf.want = rows->zone;
    if ((rc = d->find_zone(c, rows->zone, zi_cb_zone, &zf)) != 0) {
        zi_dbfail(z, "finding the zone");
        goto out;
    }
    if (zf.ambiguous) {
        ZI_ERR(z, DC_DB_IMPORT_WRITE, shown, "More than one domains row is called '%s' (names that differ in case); nothing was written", rows->zone);
        goto out;
    }
    if (zf.found && d->scan_records(c, &zf.id, zi_cb_rec, &db) != 0) {
        zi_dbfail(z, "reading the records of the zone");
        goto out;
    }
    if (db.oom) goto oom;

    /* the SOA serial (RFC 1982) of a zone that exists and whose SOA is written */
    if (zf.found && zf.soa) {
        uint32_t s;
        if (pdns_soa_serial(zf.soa, &s)) {
            res->has_old_serial = true;
            res->old_serial = s;
        }
    }
    soa_new = calloc(nins ? nins : 1, sizeof(char *));
    if (!soa_new) goto oom;
    for (size_t k = 0; k < nins; k++) {
        db_record_row_t *r = &rows->rows[ins[k]];
        uint32_t s;
        if (!r->type || strcmp(r->type, "SOA") != 0 || strcmp(r->name, rows->zone) != 0 || !r->content || !pdns_soa_serial(r->content, &s)) continue;
        if (res->has_old_serial && z->o.serial == ZI_SERIAL_INCREMENT) {
            char *nc = zi_soa_with_serial(r->content, res->old_serial + 1u);
            if (!nc) goto oom;
            soa_new[nsoa_new++] = nc;
            r->content = nc;
            s = res->old_serial + 1u;
        }
        if (res->has_old_serial && z->o.serial == ZI_SERIAL_GROW && !zi_serial_gt(s, res->old_serial)) {
            ZI_ERR(z, DC_DB_IMPORT_SERIAL, shown, "Zone '%s': the SOA serial %u does not grow past the serial %u in the database (RFC 1982); raise it, or use "
                   "--serial increment (database serial + 1) or --serial keep (take the file's)", rows->zone, (unsigned)s, (unsigned)res->old_serial);
            goto out;
        }
        res->wrote_soa = true;
        res->new_serial = s;
    }

    vb = malloc((nins ? nins : 1) * sizeof(*vb));
    if (!vb) goto oom;
    for (size_t k = 0; k < nins; k++) {
        const db_record_row_t *r = &rows->rows[ins[k]];
        vb[k] = (rrv_t){ r->name, r->type ? r->type : "", r->content ? r->content : "", r->ttl_null ? -1 : r->ttl, r->prio_null ? -1 : r->prio };
    }

    /* what is deleted: replace = every record (or those of the types), merge = the RRsets of the file */
    const bool delete_all = zf.found && z->o.mode == ZI_REPLACE && whole;
    va = malloc((db.n ? db.n : 1) * sizeof(*va));
    del_ids = malloc((db.n ? db.n : 1) * sizeof(*del_ids));
    if (!va || !del_ids) goto oom;
    qsort(vb, nins, sizeof(*vb), zi_cmp_rrv);           /* by key for the merge lookup; the insert order is in ins[] */
    for (size_t i = 0; i < db.n; i++) {
        const dbrec_t *r = &db.v[i];
        bool del;
        if (z->o.mode == ZI_REPLACE) {
            del = zi_type_wanted(z, r->type);
        } else {
            rrv_t key = { r->owner, r->type, "", 0, 0 };
            del = zi_type_wanted(z, r->type);           /* nothing outside the types is touched */
            if (del) {
                size_t lo = 0, hi = nins;
                while (lo < hi) {
                    size_t mid = lo + (hi - lo) / 2;
                    if (zi_cmp_key(&vb[mid], &key) < 0) lo = mid + 1;
                    else hi = mid;
                }
                del = lo < nins && zi_cmp_key(&vb[lo], &key) == 0;
            }
        }
        if (!del) continue;
        va[nva] = (rrv_t){ r->owner, r->type, r->content, r->ttl, r->prio };
        del_ids[ndel++] = r->id;
        nva++;
    }
    res->records_deleted = ndel;
    res->records_inserted = nins;
    if (!zi_diff(va, nva, vb, nins, &items, &nitems, res)) goto oom;

    if (zf.found && whole && z->o.mode == ZI_REPLACE && !rows->presigned) {
        bool keys = false;
        if (d->w_zone_has_keys(c, zf.id, &keys) != 0) {
            zi_dbfail(z, "looking for cryptokeys");
            goto out;
        }
        if (keys)
            ZI_WARN(z, DC_DB_IMPORT_KEYS, shown, "Zone '%s' has cryptokeys, but the imported data is not presigned (no DNSSEC records), so karidns-dbloader will "
                    "refuse the zone (online signing is not supported)", rows->zone);
    }

    /* ---- writes ---- */
    int64_t did;
    if (zf.found) {
        did = zf.id;
        res->domain_id = did;
    } else {
        if (d->w_create_zone(c, rows->zone, z->zone_type[0] ? z->zone_type : NULL, &did) != 0) {
            zi_dbfail(z, "creating the zone");
            goto out;
        }
        res->domain_id = did;
        res->created = true;
    }
    if (zf.found && (delete_all ? d->w_delete_records(c, did, NULL, 0) : (ndel ? d->w_delete_records(c, did, del_ids, ndel) : 0)) != 0) {
        zi_dbfail(z, "deleting records");
        goto out;
    }
    if (whole && zf.found) {
        for (size_t m = 0; m < 3; m++) {
            bool declared = m == 0 ? rows->presigned : m == 1 ? rows->nsec3param != NULL : rows->tinydns;
            if ((z->o.mode == ZI_REPLACE || declared) && d->w_delete_meta(c, did, ZI_OWNED_META[m]) != 0) {
                zi_dbfail(z, "deleting metadata");
                goto out;
            }
        }
        if (z->si.has_ext) {
            if (z->o.mode == ZI_REPLACE) {
                if (d->w_delete_tagdefs(c, did, NULL, NULL) != 0) {
                    zi_dbfail(z, "deleting tag definitions");
                    goto out;
                }
            } else {
                for (size_t i = 0; i < rows->ndefs; i++) {
                    bool seen = false;
                    for (size_t j = 0; j < i && !seen; j++)
                        seen = strcmp(rows->defs[j].kind, rows->defs[i].kind) == 0 && strcasecmp(rows->defs[j].tag, rows->defs[i].tag) == 0;
                    if (!seen && d->w_delete_tagdefs(c, did, rows->defs[i].kind, rows->defs[i].tag) != 0) {
                        zi_dbfail(z, "deleting tag definitions");
                        goto out;
                    }
                }
            }
        }
    }
    for (size_t k = 0; k < nins; k++) {
        const size_t i = ins[k];
        int64_t rid;
        if (d->w_insert_record(c, did, &rows->rows[i], !rows->auth || rows->auth[i] != 0, &rid) != 0) {
            zi_dbfail(z, "inserting a record");
            goto out;
        }
        if (rows->tags && (rows->tags[i].loc || rows->tags[i].ecs) && d->w_insert_tags(c, rid, rows->tags[i].loc, rows->tags[i].ecs) != 0) {
            zi_dbfail(z, "inserting a record tag");
            goto out;
        }
        if (rows->td && rows->td[i].has &&
            d->w_insert_tinydns(c, rid, rows->td[i].ttd, rows->td[i].loc[0] ? rows->td[i].loc : NULL, rows->td[i].countdown) != 0) {
            zi_dbfail(z, "inserting tinydns attributes");
            goto out;
        }
    }
    if (whole) {
        for (size_t i = 0; i < rows->ndefs; i++)
            if (d->w_insert_tagdef(c, did, rows->defs[i].kind, rows->defs[i].tag, rows->defs[i].cidr) != 0) {
                zi_dbfail(z, "inserting a tag definition");
                goto out;
            }
        if ((rows->presigned && d->w_insert_meta(c, did, "PRESIGNED", "1") != 0) ||
            (rows->nsec3param && d->w_insert_meta(c, did, "NSEC3PARAM", rows->nsec3param) != 0) ||
            (rows->tinydns && d->w_insert_meta(c, did, "X-KARIDNS-FORMAT", "tinydns") != 0)) {
            zi_dbfail(z, "inserting metadata");
            goto out;
        }
    }
    if (z->o.view && d->w_set_view(c, did, z->o.view) != 0) {
        zi_dbfail(z, "putting the zone in the view");
        goto out;
    }
    if (z->o.reload) {
        if (z->si.has_reload_requests) {
            if (d->w_request_reload(c, rows->zone, false) != 0) {
                zi_dbfail(z, "adding a reload request");
                goto out;
            }
        } else {
            ZI_WARN(z, DC_DB_IMPORT_NO_RELOAD, shown, "A reload request was asked for, but the database has no karidns_reload_requests table (PostgreSQL, "
                    "db/karidns_ext.pgsql.sql); a running server notices the change through the change log");
        }
    }
    if (zf.found ? zi_primary_type(zf.type) : (!z->zone_type[0] || zi_primary_type(z->zone_type))) {
        if (!zi_verify(z, rows->zone, did, shown, !whole || z->o.mode == ZI_MERGE, res)) goto out;
    } else {
        ZI_WARN(z, DC_DB_IMPORT_NOT_PRIMARY, shown, "Zone '%s' has domains.type %s: the server does not serve the records of such a zone, so they were not checked", rows->zone,
                zf.found && zf.type[0] ? zf.type : z->zone_type);
    }
    if (z->o.dry_run) {
        status = ZI_OK;
    } else {
        in_tx = false;                                   /* commit ends the transaction whatever happens */
        if (d->w_commit(c) != 0) {
            zi_dbfail(z, "commit");
            goto out;
        }
        res->committed = true;
        status = ZI_OK;
    }
    if (z->o.report)
        for (size_t i = 0; i < nitems; i++) z->o.report(z->o.report_ud, items[i].what, items[i].owner, items[i].type[0] ? items[i].type : "ENT");
    char sn[80] = "";
    if (res->wrote_soa) {
        if (res->has_old_serial) snprintf(sn, sizeof(sn), ", SOA serial %u -> %u", (unsigned)res->old_serial, (unsigned)res->new_serial);
        else snprintf(sn, sizeof(sn), ", SOA serial %u", (unsigned)res->new_serial);
    }
    zmsg_emit(&z->msg, DIAG_INFO, z->o.dry_run ? DC_DB_IMPORT_DRY_RUN : DC_DB_IMPORT_DONE, shown,
              "Zone '%s'%s: %zu RRset(s) added, %zu replaced, %zu deleted (%zu record(s) written, %zu removed)%s%s", rows->zone, res->created ? " (new)" : "",
              res->rrsets_added, res->rrsets_replaced, res->rrsets_deleted, res->records_inserted, res->records_deleted, sn,
              z->o.dry_run ? "; dry run, nothing was written" : "");
    goto out;
oom:
    ZI_ERR(z, DC_INTERNAL_OOM, shown, "out of memory");
out:
    if (in_tx) d->w_rollback(c);                         /* a failed import, and a dry run: nothing stays */
    for (size_t i = 0; i < nsoa_new; i++) free(soa_new[i]);
    free(soa_new);
    free(items);
    free(vb);
    free(va);
    free(del_ids);
    free(ins);
    free(zf.name);
    free(zf.type);
    free(zf.soa);
    zi_recs_free(&db);
    return status;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* entry points                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

/* An arena that was loaded: check it, make the rows, write them.  The caller frees arena. */
static int zi_import_arena(zi_t *z, zone_arena_t *arena, const char *apex, const zi_text_t *t, bool tinydns, const zrows_info_t *info, zi_result_t *res) {
    zrows_t rows;
    memset(&rows, 0, sizeof(rows));
    memset(res, 0, sizeof(*res));
    int status = ZI_FAIL;
    if (zi_check_zone(z, arena, apex, t->shown, t->text, tinydns, info, &rows, res)) {
        snprintf(res->zone, sizeof(res->zone), "%s", rows.zone);
        res->dry_run = z->o.dry_run;
        status = zi_apply(z, &rows, t->shown, res);
    } else if (rows.zone[0]) {
        snprintf(res->zone, sizeof(res->zone), "%s", rows.zone);
    }
    zrows_free(&rows);
    return status;
}

/* the name the caller gave, in the zone parser's form: absolute with the final dot; false if it is not a zone name */
static bool zi_apex_name(const char *zone, char out[DNS_NAME_TEXT_SIZE]) {
    char canon[DNS_NAME_TEXT_SIZE];
    if (!pdns_canonical_zone_name(zone, canon)) return false;
    snprintf(out, DNS_NAME_TEXT_SIZE, "%s", canon);
    return true;
}

int zi_import_zone(zi_t *z, const zi_input_t *in, const char *zone, zi_result_t *res) {
    zi_result_t local;
    if (!res) res = &local;
    memset(res, 0, sizeof(*res));
    char want[DNS_NAME_TEXT_SIZE];
    if (zone && !zi_apex_name(zone, want)) {
        ZI_ERR(z, DC_DB_IMPORT_ZONE_NAME, NULL, "'%.100s' is not a valid zone name", zone);
        return ZI_FAIL;
    }
    zi_text_t t;
    if (!zi_get_text(z, in, &t)) return ZI_FAIL;
    zone_arena_t arena;
    char apex[DNS_NAME_TEXT_SIZE], err[600];
    zrows_info_t info;
    int status = ZI_FAIL;
    if (!zrows_load_zone_text(t.text, t.len, t.from_file ? t.shown : NULL, zone ? want : NULL, &arena, apex, sizeof(apex), &info, err,
                              sizeof(err))) {
        ZI_ERR(z, info.include_refused ? DC_ZONE_INCLUDE_STDIN : DC_ZONE_SYNTAX, t.shown, "%s",
               info.include_refused ? "$INCLUDE is refused in a zone read from standard input" : err);
    } else {
        status = zi_import_arena(z, &arena, apex, &t, false, &info, res);
        zone_arena_destroy(&arena);
    }
    free(t.text);
    return status;
}

int zi_import_tinydns(zi_t *z, const zi_input_t *in, const char *zone, zi_result_fn fn, void *ud) {
    char want[DNS_NAME_TEXT_SIZE];
    if (zone && !zi_apex_name(zone, want)) {
        ZI_ERR(z, DC_DB_IMPORT_ZONE_NAME, NULL, "'%.100s' is not a valid zone name", zone);
        return ZI_FAIL;
    }
    zi_text_t t;
    if (!zi_get_text(z, in, &t)) return ZI_FAIL;
    const char *path = t.from_file ? t.shown : NULL;
    char **names = NULL, err[600];
    int nn = 0, worst = ZI_OK;
    zrows_info_t info;
    memset(&info, 0, sizeof(info));
    if (!zrows_tinydns_apexes_text(t.text, t.len, path, t.mtime, &names, &nn, &info, err, sizeof(err))) {
        ZI_ERR(z, DC_ZONE_SYNTAX, t.shown, "%s", err);
        free(t.text);
        return ZI_FAIL;
    }
    bool any = false;
    for (int i = 0; i < nn; i++) {
        char canon[DNS_NAME_TEXT_SIZE];
        if (zone && !(zi_apex_name(names[i], canon) && zrows_names_equal(canon, want))) continue;
        any = true;
        zone_arena_t arena;
        char apex[DNS_NAME_TEXT_SIZE];
        zi_result_t res;
        memset(&res, 0, sizeof(res));
        int status = ZI_FAIL;
        if (!zrows_load_tinydns_text(t.text, t.len, path, t.mtime, names[i], (const char *const *)names, nn, &arena, apex, sizeof(apex), &info, err,
                                     sizeof(err))) {
            ZI_ERR(z, DC_ZONE_SYNTAX, t.shown, "%s", err);
        } else {
            status = zi_import_arena(z, &arena, apex, &t, true, &info, &res);
            zone_arena_destroy(&arena);
        }
        if (fn) fn(ud, &res, status);
        if (status > worst) worst = status;
    }
    if (!any) {
        ZI_ERR(z, DC_DB_IMPORT_ZONE_NAME, t.shown, "'%.100s' has no SOA (. or Z line) in %s", zone, t.shown);
        worst = ZI_FAIL;
    }
    for (int i = 0; i < nn; i++) free(names[i]);
    free(names);
    free(t.text);
    return worst;
}

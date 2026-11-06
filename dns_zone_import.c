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
    if (o->signer && (o->mode != ZI_REPLACE || o->ntypes > 0 || o->serial != ZI_SERIAL_GROW || o->view || o->zone_type)) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPTION, NULL, "a signer import takes no merge mode, types filter, serial rule, view or zone type");
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
    /* a signer import reads the zone and writes it as one snapshot (PostgreSQL: REPEATABLE READ), so that a change made in between is an error, not a lost update */
    if (o->signer && z->drv->w_set_snapshot && z->drv->w_set_snapshot(z->conn, true) != 0) {
        zmsg_emit(&m, DIAG_ERROR, DC_DB_IMPORT_OPEN, NULL, "%s", z->drv->errmsg(z->conn));
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
    char *ordername;                                    /* only when the collector has order set (signer mode); NULL = NULL */
    bool disabled;
} dbrec_t;

typedef struct { dbrec_t *v; size_t n, cap; bool oom; bool order; } dbrecs_t;

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
    d->disabled = r->disabled;
    d->ordername = a->order && r->ordername ? strdup(r->ordername) : NULL;
    if (!d->owner || !d->type || !d->content || (a->order && r->ordername && !d->ordername)) {
        free(d->owner);
        free(d->type);
        free(d->content);
        free(d->ordername);
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
        free(a->v[i].ordername);
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
static bool zi_verify(zi_t *z, const char *zone, int64_t did, const char *shown, bool partial, unsigned plain, zi_result_t *res) {
    pdns_zone_t *pz = NULL;
    switch (zx_read_zone_ex(z->drv, z->conn, z->si.has_ext, zone, did, &z->o.reader, plain, &pz, NULL)) {
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

static bool zi_managed_type(const char *t);

/* A zone that karidns-signer signs (metadata X-KARIDNS-SIGNER=1; item C): a normal import replaces its data and leaves the DNSSEC records and the metadata the
 * signer owns as they are.  The types: those of import --signer and CDS / CDNSKEY (a key rollover the signer announces). */
static bool zi_signer_kept(const char *t) { return t && (zi_managed_type(t) || strcasecmp(t, "CDS") == 0 || strcasecmp(t, "CDNSKEY") == 0); }

static int zi_cb_signer_meta(void *ud, const db_meta_row_t *m) {
    if (m->kind && m->content && strcasecmp(m->kind, "X-KARIDNS-SIGNER") == 0 && strcmp(m->content, "1") == 0) *(bool *)ud = true;
    return 0;
}

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
    bool szone = false;                                 /* the zone is signed by karidns-signer: its DNSSEC records and signer metadata stay */
    size_t nignored = 0;                                /* DNSSEC records of the input that a signer zone does not take */

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
    if (zf.found && d->scan_metadata(c, &zf.id, zi_cb_signer_meta, &szone) != 0) {
        zi_dbfail(z, "reading the metadata of the zone");
        goto out;
    }
    if (szone) {                                        /* the DNSSEC records of the input are the signer's business: ignored */
        size_t w = 0;
        for (size_t k = 0; k < nins; k++) {
            if (zi_signer_kept(rows->rows[ins[k]].type)) nignored++;
            else ins[w++] = ins[k];
        }
        nins = w;
    }

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
    const bool delete_all = zf.found && z->o.mode == ZI_REPLACE && whole && !szone;
    va = malloc((db.n ? db.n : 1) * sizeof(*va));
    del_ids = malloc((db.n ? db.n : 1) * sizeof(*del_ids));
    if (!va || !del_ids) goto oom;
    qsort(vb, nins, sizeof(*vb), zi_cmp_rrv);           /* by key for the merge lookup; the insert order is in ins[] */
    for (size_t i = 0; i < db.n; i++) {
        const dbrec_t *r = &db.v[i];
        bool del;
        if (szone && zi_signer_kept(r->type)) continue;
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

    if (zf.found && whole && z->o.mode == ZI_REPLACE && !rows->presigned && !szone) {
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
            if (szone && m < 2) continue;               /* PRESIGNED and NSEC3PARAM belong to the signer */
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
        if ((rows->presigned && !szone && d->w_insert_meta(c, did, "PRESIGNED", "1") != 0) ||
            (rows->nsec3param && !szone && d->w_insert_meta(c, did, "NSEC3PARAM", rows->nsec3param) != 0) ||
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
        if (!zi_verify(z, rows->zone, did, shown, !whole || z->o.mode == ZI_MERGE, szone ? ZX_PLAIN_DNSSEC | ZX_PLAIN_CDS : 0, res)) goto out;
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
    if (szone) {
        char ig[120] = "";
        if (nignored) snprintf(ig, sizeof(ig), "; %zu DNSSEC record(s) of the input were ignored", nignored);
        zmsg_emit(&z->msg, DIAG_INFO, DC_DB_IMPORT_SIGNER_ZONE, shown,
                  "Zone '%s' is signed by karidns-signer: its DNSSEC records and the metadata PRESIGNED and NSEC3PARAM were kept%s; the server serves the zone again after the next signing",
                  rows->zone, ig);
    }
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

/* ------------------------------------------------------------------------------------------------------------- */
/* import --signer                                                                                                */
/* ------------------------------------------------------------------------------------------------------------- */

/* the types the signer replaces (RFC 4034 3, RFC 5155 3 and 4; CDS and CDNSKEY, RFC 7344, are not the signer's here) */
static bool zi_managed_type(const char *t) {
    static const char *const k[] = { "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY" };
    if (!t) return false;
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (strcasecmp(t, k[i]) == 0) return true;
    return false;
}

/* days from 1970-01-01 to the civil date y-m-d (proleptic Gregorian calendar) */
static int64_t zi_days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153u * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* The Signature Expiration field of the content of an RRSIG row ("covered alg labels ttl expiration inception tag signer signature", RFC 4034 3.2):
 * seconds since the epoch as a decimal number, or YYYYMMDDHHmmSS in UTC.  The value is a 32 bit number of seconds modulo 2^32 (RFC 4034 3.1.5). */
static bool zi_rrsig_expire(const char *content, uint32_t *out) {
    const char *p = content;
    for (int f = 0; f < 4; f++) {
        while (*p == ' ' || *p == '\t') p++;
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    while (*p == ' ' || *p == '\t') p++;
    size_t n = 0;
    while (p[n] >= '0' && p[n] <= '9') n++;
    if (n == 0 || (p[n] && p[n] != ' ' && p[n] != '\t')) return false;
    if (n == 14) {
        unsigned f[6];
        static const unsigned len[6] = { 4, 2, 2, 2, 2, 2 };
        size_t o = 0;
        for (int i = 0; i < 6; i++) {
            f[i] = 0;
            for (unsigned j = 0; j < len[i]; j++) f[i] = f[i] * 10 + (unsigned)(p[o++] - '0');
        }
        if (f[1] < 1 || f[1] > 12 || f[2] < 1 || f[2] > 31 || f[3] > 23 || f[4] > 59 || f[5] > 60) return false;
        int64_t t = zi_days_from_civil(f[0], f[1], f[2]) * 86400 + (int64_t)f[3] * 3600 + (int64_t)f[4] * 60 + (int64_t)f[5];
        *out = (uint32_t)(uint64_t)t;                   /* modulo 2^32 */
        return true;
    }
    if (n > 10) return false;
    unsigned long long v = strtoull(p, NULL, 10);
    if (v > 0xFFFFFFFFull) return false;
    *out = (uint32_t)v;
    return true;
}

/* the time (seconds since the epoch) a 32 bit RRSIG time stands for: the one within 2^31 seconds of now */
static time_t zi_time_near(uint32_t t32, time_t now) {
    int64_t diff = (int64_t)t32 - (int64_t)(uint32_t)((uint64_t)now & 0xFFFFFFFFu);
    if (diff > 0x7FFFFFFFLL) diff -= 0x100000000LL;
    else if (diff < -0x80000000LL) diff += 0x100000000LL;
    return (time_t)((int64_t)now + diff);
}

/* ---- the zone as the signed file saw it: RRsets in canonical form (RFC 4034 6.2) ---- */

/* an RR as the comparison sees it: the record, its RDATA in the canonical form (not compressed, the names inside the RDATA of the types RFC 4034 6.2
 * lists in lower case; dns_record_canonical_rdata()), and the TTL of its RRset (the lowest of it: RFC 2181 5.2, what the server serves) */
typedef struct { const dns_record_t *r; size_t off; const uint8_t *rd; size_t rdlen; uint32_t ttl; } crr_t;
typedef struct { crr_t *v; size_t n; uint8_t *blob; const dns_record_t *soa; } crrs_t;

static int zi_cmp_str_null(const char *a, const char *b) {
    if (!a || !b) return (a != NULL) - (b != NULL);
    int c = strcasecmp(a, b);
    return c < 0 ? -1 : c > 0;
}

/* the RRset an RR belongs to: owner (without regard to case), type, class, and the visibility tags / tinydns attributes the server separates RRs by */
static int zi_cmp_crr_key(const crr_t *a, const crr_t *b) {
    int c = zi_cmp_str_null(a->r->name, b->r->name);
    if (c) return c;
    if (a->r->type_code != b->r->type_code) return a->r->type_code < b->r->type_code ? -1 : 1;
    const unsigned ca = a->r->class_val ? a->r->class_val : 1, cb = b->r->class_val ? b->r->class_val : 1;
    if (ca != cb) return ca < cb ? -1 : 1;
    if ((c = zi_cmp_str_null(a->r->bind_location_tag, b->r->bind_location_tag)) != 0) return c;
    if ((c = zi_cmp_str_null(a->r->ecs_subnet_tag, b->r->ecs_subnet_tag)) != 0) return c;
    if (a->r->tinydns_ttd != b->r->tinydns_ttd) return a->r->tinydns_ttd < b->r->tinydns_ttd ? -1 : 1;
    if (a->r->tinydns_ttl_countdown != b->r->tinydns_ttl_countdown) return a->r->tinydns_ttl_countdown ? 1 : -1;
    if ((c = memcmp(a->r->tinydns_loc, b->r->tinydns_loc, 2)) != 0) return c < 0 ? -1 : 1;
    return 0;
}

static int zi_cmp_crr(const void *x, const void *y) {
    const crr_t *a = x, *b = y;
    int c = zi_cmp_crr_key(a, b);
    if (c) return c;
    size_t m = a->rdlen < b->rdlen ? a->rdlen : b->rdlen;
    if (m && (c = memcmp(a->rd, b->rd, m)) != 0) return c < 0 ? -1 : 1;
    return a->rdlen == b->rdlen ? 0 : a->rdlen < b->rdlen ? -1 : 1;
}

static void zi_crrs_free(crrs_t *s) {
    free(s->v);
    free(s->blob);
    memset(s, 0, sizeof(*s));
}

/* The RRs of a zone arena that the signer leaves alone, sorted and made a set: every type but RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY and the SOA (which is
 * returned in ->soa); identical RRs are one; the TTL of each is the lowest of its RRset.  false: *why says why (out of memory, or an RDATA that has no
 * canonical form). */
static bool zi_crrs_from_arena(const zone_arena_t *a, crrs_t *out, char *why, size_t whylen) {
    memset(out, 0, sizeof(*out));
    uint8_t *tmp = malloc(65535);
    out->v = malloc((a->count ? a->count : 1) * sizeof(*out->v));
    if (!tmp || !out->v) {
        snprintf(why, whylen, "out of memory");
        free(tmp);
        zi_crrs_free(out);
        return false;
    }
    size_t bcap = 0, bn = 0;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (!r->name || r->type_code == 46 || r->type_code == 47 || r->type_code == 48 || r->type_code == 50 || r->type_code == 51) continue;
        if (r->type_code == 6) {
            if (!out->soa) out->soa = r;
            continue;
        }
        long l = dns_record_canonical_rdata(r, tmp, 65535);
        if (l < 0) {
            snprintf(why, whylen, "the RDATA of a %.20s record of '%.200s' has no canonical form", r->type ? r->type : "?", r->name);
            free(tmp);
            zi_crrs_free(out);
            return false;
        }
        if (bn + (size_t)l + 1 > bcap) {
            size_t nc = bcap ? bcap * 2 : 65536;
            while (nc < bn + (size_t)l + 1) nc *= 2;
            uint8_t *nb = realloc(out->blob, nc);
            if (!nb) {
                snprintf(why, whylen, "out of memory");
                free(tmp);
                zi_crrs_free(out);
                return false;
            }
            out->blob = nb;
            bcap = nc;
        }
        memcpy(out->blob + bn, tmp, (size_t)l);
        out->v[out->n++] = (crr_t){ r, bn, NULL, (size_t)l, r->ttl_value };
        bn += (size_t)l;
    }
    free(tmp);
    for (size_t i = 0; i < out->n; i++) out->v[i].rd = out->blob + out->v[i].off;
    qsort(out->v, out->n, sizeof(*out->v), zi_cmp_crr);
    size_t w = 0;
    for (size_t i = 0; i < out->n;) {
        size_t j = i, gs = w;
        uint32_t m = out->v[i].ttl;
        while (j + 1 < out->n && zi_cmp_crr_key(&out->v[i], &out->v[j + 1]) == 0) {
            j++;
            if (out->v[j].ttl < m) m = out->v[j].ttl;
        }
        for (size_t k = i; k <= j; k++) {
            if (w > gs && zi_cmp_crr(&out->v[w - 1], &out->v[k]) == 0) continue;           /* the same RR twice is one */
            out->v[w] = out->v[k];
            out->v[w].ttl = m;
            w++;
        }
        i = j + 1;
    }
    out->n = w;
    return true;
}

/* the RDATA of an SOA in canonical form with the serial set to 0, and the serial; -1 if it is not an SOA RDATA */
static long zi_soa_canon(const dns_record_t *r, uint8_t *buf, size_t cap, uint32_t *serial) {
    long l = dns_record_canonical_rdata(r, buf, cap);
    if (l < 0) return -1;
    size_t i = 0;
    for (int k = 0; k < 2; k++) {
        while (i < (size_t)l && buf[i]) i += (size_t)buf[i] + 1;
        i++;
    }
    if (i + 20 != (size_t)l) return -1;
    *serial = ((uint32_t)buf[i] << 24) | ((uint32_t)buf[i + 1] << 16) | ((uint32_t)buf[i + 2] << 8) | (uint32_t)buf[i + 3];
    memset(buf + i, 0, 4);
    return l;
}

/* an owner and type for a message */
static void zi_rr_name(const dns_record_t *r, char *owner, size_t ocap, char *type, size_t tcap) {
    snprintf(owner, ocap, "%.200s", r->name && r->name[0] && strcmp(r->name, ".") != 0 ? r->name : "(apex)");
    if (r->type && r->type[0]) snprintf(type, tcap, "%.20s", r->type);
    else snprintf(type, tcap, "TYPE%u", (unsigned)r->type_code);
}

/* The two sets must be equal, TTLs included.  0 when they are; else a message in why that names the first RRset that differs. */
static bool zi_crrs_equal(const crrs_t *dbr, const crrs_t *fir, char *why, size_t whylen) {
    size_t n = dbr->n > fir->n ? dbr->n : fir->n;
    for (size_t i = 0; i < n; i++) {
        const crr_t *a = i < dbr->n ? &dbr->v[i] : NULL, *b = i < fir->n ? &fir->v[i] : NULL;
        int c = !a ? 1 : !b ? -1 : zi_cmp_crr(a, b);
        if (c == 0 && a->ttl == b->ttl) continue;
        const crr_t *w = c == 0 ? a : c < 0 ? a : b;
        char o[220], t[32];
        zi_rr_name(w->r, o, sizeof(o), t, sizeof(t));
        if (c == 0) snprintf(why, whylen, "the TTL of '%s' %s is %u in the database and %u in the file", o, t, (unsigned)a->ttl, (unsigned)b->ttl);
        else snprintf(why, whylen, "'%s' %s %s", o, t, c < 0 ? "is in the database and not in the file" : "is in the file and not in the database");
        return false;
    }
    return true;
}

/* where the new ordername and auth of a record of the database come from: the file's row of the same owner and type */
typedef struct { const char *name, *type; size_t idx; } fmrow_t;
static int zi_cmp_fmrow(const void *x, const void *y) {
    const fmrow_t *a = x, *b = y;
    int c = strcasecmp(a->name, b->name);
    return c ? c : strcasecmp(a->type, b->type);
}

typedef struct { int64_t id; bool auth; } dbauth_t;
typedef struct { dbauth_t *v; size_t n, cap; bool oom; } dbauths_t;

static int zi_cb_auth(void *ud, int64_t id, bool auth) {
    dbauths_t *a = ud;
    if (a->n == a->cap) {
        size_t nc = a->cap ? a->cap * 2 : 256;
        dbauth_t *nv = realloc(a->v, nc * sizeof(*nv));
        if (!nv) return a->oom = true;
        a->v = nv;
        a->cap = nc;
    }
    a->v[a->n++] = (dbauth_t){ id, auth };
    return 0;
}

static int zi_cmp_auth_id(const void *k, const void *e) {
    const int64_t id = *(const int64_t *)k;
    const dbauth_t *a = e;
    return id < a->id ? -1 : id > a->id;
}

static bool zi_same_text(const char *a, const char *b) { return (a == NULL && b == NULL) || (a && b && strcmp(a, b) == 0); }

/* the status of a failed step of the signer's transaction: a concurrent change is "the zone changed" (the signer signs again), the rest a failure */
static int zi_sfail(zi_t *z, const char *what, int rc, const char *shown, const char *zone) {
    if (rc == DB_ERR_CONFLICT) {
        ZI_ERR(z, DC_DB_IMPORT_CHANGED, shown, "Zone '%s' changed while the signed file was being written (%s: %s); nothing was written; sign the zone again", zone, what,
               z->drv->errmsg(z->conn));
        return ZI_CHANGED;
    }
    return zi_dbfail(z, what);
}

#define ZI_SFAIL(what, rc) do { status = zi_sfail(z, (what), (rc), shown, rows->zone); goto out; } while (0)

/* Everything of a signer import in the transaction.  ZI_OK, ZI_FAIL, ZI_BUSY, ZI_CHANGED; the caller rolls back unless this committed.  farena: the parsed file. */
static int zi_apply_signer(zi_t *z, zrows_t *rows, const zone_arena_t *farena, const char *shown, zi_result_t *res) {
    const db_driver_t *d = z->drv;
    db_conn_t *c = z->conn;
    int status = ZI_FAIL;
    bool in_tx = false;
    dbrecs_t db = {0};
    db.order = true;
    dbauths_t au = {0};
    zfind_t zf = {0};
    fmrow_t *fm = NULL, *fe = NULL;                     /* the file's other records / empty non-terminals by owner and type, sorted */
    size_t nfm = 0, nfe = 0;
    size_t *fdn = NULL, nfdn = 0;                       /* the file's DNSSEC rows (indexes): written */
    int64_t *del_ids = NULL;
    size_t ndel = 0;
    size_t isoa_f = (size_t)-1;                         /* the file's apex SOA */
    const dbrec_t *soa_d = NULL;                        /* the database's apex SOA */
    size_t nsoa_d = 0;
    rrv_t *va = NULL, *vb = NULL;
    size_t nva = 0;
    zi_item_t *items = NULL;
    size_t nitems = 0;
    char *soa_new = NULL;
    bool have_exp = false;
    uint32_t exp_best = 0;
    uint64_t mark = 0;
    pdns_zone_t *pz = NULL;
    crrs_t dbr = {0}, fir = {0};
    db_order_t *ords = NULL;
    size_t nords = 0;
    db_ins_t *ins = NULL;
    char why[400];
    int rc;

    if (!rows->presigned) {
        ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s': the file is not a signed zone (it needs RRSIG records and a complete NSEC or NSEC3 chain); nothing was written", rows->zone);
        return ZI_FAIL;
    }
    /* the file's rows: DNSSEC records (written), the apex SOA, empty non-terminals and the others (where ordername and auth come from) */
    fm = malloc((rows->n ? rows->n : 1) * sizeof(*fm));
    fe = malloc((rows->n ? rows->n : 1) * sizeof(*fe));
    fdn = malloc((rows->n ? rows->n : 1) * sizeof(*fdn));
    if (!fm || !fe || !fdn) goto oom;
    for (size_t i = 0; i < rows->n; i++) {
        const db_record_row_t *r = &rows->rows[i];
        if (!r->type) {
            fe[nfe++] = (fmrow_t){ r->name, "", i };
        } else if (zi_managed_type(r->type)) {
            fdn[nfdn++] = i;
            if (strcasecmp(r->type, "RRSIG") == 0) {
                uint32_t e;
                if (!r->content || !zi_rrsig_expire(r->content, &e)) {
                    ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s': cannot read the expiration time of the RRSIG record of '%.100s'; nothing was written", rows->zone, r->name);
                    goto out;
                }
                if (!have_exp || zi_serial_gt(exp_best, e)) {
                    exp_best = e;
                    have_exp = true;
                }
            }
        } else if (strcasecmp(r->type, "SOA") == 0 && strcmp(r->name, rows->zone) == 0) {
            if (isoa_f != (size_t)-1) {
                ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s': the file has more than one SOA record at the apex; nothing was written", rows->zone);
                goto out;
            }
            isoa_f = i;
        } else {
            fm[nfm++] = (fmrow_t){ r->name, r->type, i };
        }
    }
    if (isoa_f == (size_t)-1 || !have_exp) {
        ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s': the file has %s; nothing was written", rows->zone, isoa_f == (size_t)-1 ? "no SOA record at the apex" : "no RRSIG record");
        goto out;
    }
    qsort(fm, nfm, sizeof(*fm), zi_cmp_fmrow);
    qsort(fe, nfe, sizeof(*fe), zi_cmp_fmrow);

    rc = d->w_begin(c, rows->zone);
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
    if ((rc = d->w_mark(c, &mark)) != 0) ZI_SFAIL("marking the change log", rc);
    zf.want = rows->zone;
    if (d->find_zone(c, rows->zone, zi_cb_zone, &zf) != 0) {
        zi_dbfail(z, "finding the zone");
        goto out;
    }
    if (zf.ambiguous) {
        ZI_ERR(z, DC_DB_IMPORT_WRITE, shown, "More than one domains row is called '%s' (names that differ in case); nothing was written", rows->zone);
        goto out;
    }
    if (!zf.found) {
        ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s' is not in the database: the signer signs a zone that exists; nothing was written", rows->zone);
        goto out;
    }
    if (!zi_primary_type(zf.type)) {
        ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s' has domains.type %s: only a primary zone (NATIVE or MASTER) is signed; nothing was written", rows->zone, zf.type);
        goto out;
    }
    res->domain_id = zf.id;
    if (d->scan_records(c, &zf.id, zi_cb_rec, &db) != 0) {
        zi_dbfail(z, "reading the records of the zone");
        goto out;
    }
    if (db.oom) goto oom;
    if (d->w_scan_auth(c, zf.id, zi_cb_auth, &au) != 0) {
        zi_dbfail(z, "reading the authoritative flags of the zone");
        goto out;
    }
    if (au.oom) goto oom;

    /* the database's rows: DNSSEC records (deleted: a disabled one too), the apex SOA, the others (their ordername and auth are set below) */
    del_ids = malloc((db.n ? db.n : 1) * sizeof(*del_ids));
    va = malloc((db.n ? db.n : 1) * sizeof(*va));
    ords = malloc((db.n ? db.n : 1) * sizeof(*ords));
    if (!del_ids || !va || !ords) goto oom;
    for (size_t i = 0; i < db.n; i++) {
        const dbrec_t *r = &db.v[i];
        if (zi_managed_type(r->type)) {
            del_ids[ndel++] = r->id;
            if (!r->disabled) va[nva++] = (rrv_t){ r->owner, r->type, r->content, r->ttl < 0 ? 0 : r->ttl, r->prio < 0 ? 0 : r->prio };
        } else if (!r->disabled && strcmp(r->type, "SOA") == 0 && strcmp(r->owner, rows->zone) == 0) {
            soa_d = r;
            nsoa_d++;
        }
    }
    if (nsoa_d != 1) {
        ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s' has %s SOA record at the apex in the database; nothing was written", rows->zone, nsoa_d ? "more than one" : "no");
        goto out;
    }

    /* The zone must be what the file was made from.  Both sides are read the way the server reads a zone (the zone parser for the file, the loader's reader for
     * the rows of the database, the DNSSEC records left out) and compared as sets of RRs in canonical form with the TTLs the server serves: how the text of a
     * row is spelled (case of names and hex, an uncompressed AAAA, quoting of a TXT) does not matter, a real change does. */
    switch (zx_read_zone_ex(d, c, z->si.has_ext, rows->zone, zf.id, &z->o.reader, ZX_PLAIN_DNSSEC, &pz, NULL)) {
    case ZX_READ_OK: break;
    case ZX_READ_OOM: goto oom;
    case ZX_READ_DB:
        zi_dbfail(z, "reading the zone");
        goto out;
    default:
        ZI_ERR(z, DC_DB_IMPORT_VERIFY, shown, "Zone '%s': the loader's reader refuses the rows of the zone in the database: %s; nothing was written", rows->zone, pz ? pz->error : "?");
        goto out;
    }
    if (!zi_crrs_from_arena(&pz->arena, &dbr, why, sizeof(why)) || !zi_crrs_from_arena(farena, &fir, why, sizeof(why))) {
        ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s': %s; nothing was written", rows->zone, why);
        goto out;
    }
    if (!zi_crrs_equal(&dbr, &fir, why, sizeof(why))) {
        ZI_ERR(z, DC_DB_IMPORT_CHANGED, shown, "Zone '%s' changed since the signed file was made (%s); nothing was written; sign the zone again", rows->zone, why);
        status = ZI_CHANGED;
        goto out;
    }
    /* the SOA: the same but for the serial, which grows (RFC 1982) */
    {
        uint8_t *ba = malloc(65535), *bb = malloc(65535);
        uint32_t s_old = 0, s_new = 0;
        long la = -1, lb = -1;
        if (!ba || !bb) {
            free(ba);
            free(bb);
            goto oom;
        }
        if (dbr.soa && fir.soa) {
            la = zi_soa_canon(dbr.soa, ba, 65535, &s_old);
            lb = zi_soa_canon(fir.soa, bb, 65535, &s_new);
        }
        bool same = la >= 0 && la == lb && memcmp(ba, bb, (size_t)la) == 0 && dbr.soa->ttl_value == fir.soa->ttl_value;
        free(ba);
        free(bb);
        if (!same) {
            ZI_ERR(z, DC_DB_IMPORT_CHANGED, shown, "Zone '%s' changed since the signed file was made (the SOA record differs by more than the serial); nothing was written; sign the zone again", rows->zone);
            status = ZI_CHANGED;
            goto out;
        }
        if (!zi_serial_gt(s_new, s_old)) {
            ZI_ERR(z, DC_DB_IMPORT_CHANGED, shown, "Zone '%s': the SOA serial %u of the signed file does not grow past the serial %u in the database (RFC 1982), so the zone changed since the file was made; "
                   "nothing was written; sign the zone again", rows->zone, (unsigned)s_new, (unsigned)s_old);
            status = ZI_CHANGED;
            goto out;
        }
        res->has_old_serial = true;
        res->old_serial = s_old;
        res->new_serial = s_new;
        res->wrote_soa = true;
        if (!(soa_new = zi_soa_with_serial(soa_d->content, s_new))) {
            ZI_ERR(z, DC_DB_IMPORT_SIGNER, shown, "Zone '%s': the SOA record in the database has no serial field to change; nothing was written", rows->zone);
            goto out;
        }
    }

    /* the RRsets of the DNSSEC records, for the report and the counts */
    vb = malloc((nfdn ? nfdn : 1) * sizeof(*vb));
    ins = malloc((nfdn ? nfdn : 1) * sizeof(*ins));
    if (!vb || !ins) goto oom;
    for (size_t k = 0; k < nfdn; k++) {
        const db_record_row_t *r = &rows->rows[fdn[k]];
        vb[k] = (rrv_t){ r->name, r->type, r->content ? r->content : "", r->ttl_null ? -1 : r->ttl, r->prio_null ? 0 : r->prio };
        ins[k] = (db_ins_t){ r, !rows->auth || rows->auth[fdn[k]] != 0 };
    }
    if (!zi_diff(va, nva, vb, nfdn, &items, &nitems, res)) goto oom;
    res->records_deleted = ndel;
    res->records_inserted = nfdn;
    res->has_expire = true;
    res->min_expire = zi_time_near(exp_best, z->o.now ? z->o.now : time(NULL));

    for (size_t i = 0; i < z->o.nfile_zones; i++)
        if (zrows_names_equal(z->o.file_zones[i], rows->zone)) {
            ZI_WARN(z, DC_DB_IMPORT_FILE_ZONE, shown, "Zone '%s' is also a file zone of the server configuration; the server serves the file zone, not the database zone", rows->zone);
            break;
        }

    /* ---- writes ---- */
    if (ndel && (rc = d->w_delete_dnssec(c, zf.id, del_ids, ndel)) != 0) ZI_SFAIL("deleting the DNSSEC records", rc);
    if (nfdn && (rc = d->w_insert_dnssec(c, zf.id, ins, nfdn)) != 0) ZI_SFAIL("inserting the DNSSEC records", rc);
    /* the apex SOA with its new serial, and the ordername and auth of the records that stay, as a presigned zone has them */
    if ((rc = d->w_update_record(c, zf.id, soa_d->id, soa_new, rows->rows[isoa_f].ordername, !rows->auth || rows->auth[isoa_f] != 0)) != 0) ZI_SFAIL("updating the SOA record", rc);
    res->rows_updated++;
    for (size_t i = 0; i < db.n; i++) {
        const dbrec_t *dr = &db.v[i];
        if (dr->disabled || zi_managed_type(dr->type) || dr == soa_d || (strcmp(dr->type, "SOA") == 0 && strcmp(dr->owner, rows->zone) == 0)) continue;
        /* an empty non-terminal the database holds (the loader derives the others): the ordername of its owner, and authoritative; every other record: the
         * file's row of the same owner and type (a record the file does not have, because the export leaves it out, is left as it is) */
        const bool ent = !dr->type[0];
        fmrow_t key = { dr->owner, ent ? "" : dr->type, 0 };
        const fmrow_t *hit = bsearch(&key, ent ? fe : fm, ent ? nfe : nfm, sizeof(*fm), zi_cmp_fmrow);
        if (!hit) continue;
        const db_record_row_t *fr = &rows->rows[hit->idx];
        const bool fauth = ent || !rows->auth || rows->auth[hit->idx] != 0;
        const dbauth_t *ca = bsearch(&dr->id, au.v, au.n, sizeof(*au.v), zi_cmp_auth_id);
        if (zi_same_text(fr->ordername, dr->ordername) && fauth == (ca ? ca->auth : true)) continue;
        ords[nords++] = (db_order_t){ dr->id, fr->ordername, fauth };
    }
    if (nords && (rc = d->w_update_orders(c, zf.id, ords, nords)) != 0) ZI_SFAIL("updating ordername and auth", rc);
    res->rows_updated += nords;

    /* the metadata the signer owns */
    if (d->w_delete_meta(c, zf.id, "PRESIGNED") != 0 || d->w_delete_meta(c, zf.id, "NSEC3PARAM") != 0 || d->w_delete_meta(c, zf.id, "X-KARIDNS-SIGNER") != 0) {
        zi_dbfail(z, "deleting metadata");
        goto out;
    }
    if (d->w_insert_meta(c, zf.id, "PRESIGNED", "1") != 0 || (rows->nsec3param && d->w_insert_meta(c, zf.id, "NSEC3PARAM", rows->nsec3param) != 0) ||
        d->w_insert_meta(c, zf.id, "X-KARIDNS-SIGNER", "1") != 0) {
        zi_dbfail(z, "inserting metadata");
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
    if (!zi_verify(z, rows->zone, zf.id, shown, false, 0, res)) goto out;
    if (d->w_write_id(c, mark, &res->write_id) != 0) {
        zi_dbfail(z, "reading the id of the write");
        goto out;
    }
    res->has_write_id = true;
    if (z->o.dry_run) {
        status = ZI_OK;
    } else {
        in_tx = false;                                  /* commit ends the transaction whatever happens */
        if ((rc = d->w_commit(c)) != 0) ZI_SFAIL("commit", rc);
        res->committed = true;
        status = ZI_OK;
    }
    if (z->o.report)
        for (size_t i = 0; i < nitems; i++) z->o.report(z->o.report_ud, items[i].what, items[i].owner, items[i].type);
    {
        char ex[40] = "";
        struct tm tmv;
        time_t et = res->min_expire;
        if (gmtime_r(&et, &tmv)) strftime(ex, sizeof(ex), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        zmsg_emit(&z->msg, DIAG_INFO, z->o.dry_run ? DC_DB_IMPORT_DRY_RUN : DC_DB_IMPORT_DONE, shown,
                  "Zone '%s' signed: SOA serial %u -> %u, %zu DNSSEC record(s) written, %zu removed, %zu record(s) updated (ordername, auth); the earliest RRSIG expires %s%s",
                  rows->zone, (unsigned)res->old_serial, (unsigned)res->new_serial, res->records_inserted, res->records_deleted, res->rows_updated, ex,
                  z->o.dry_run ? "; dry run, nothing was written" : "");
    }
    goto out;
oom:
    ZI_ERR(z, DC_INTERNAL_OOM, shown, "out of memory");
out:
    if (in_tx) d->w_rollback(c);
    pdns_zone_free(pz);
    zi_crrs_free(&dbr);
    zi_crrs_free(&fir);
    free(ins);
    free(ords);
    free(soa_new);
    free(items);
    free(vb);
    free(va);
    free(del_ids);
    free(fm);
    free(fe);
    free(fdn);
    free(au.v);
    free(zf.name);
    free(zf.type);
    free(zf.soa);
    zi_recs_free(&db);
    return status;
}

/* An arena that was loaded: check it, make the rows, write them.  The caller frees arena. */
static int zi_import_arena(zi_t *z, zone_arena_t *arena, const char *apex, const zi_text_t *t, bool tinydns, const zrows_info_t *info, zi_result_t *res) {
    zrows_t rows;
    memset(&rows, 0, sizeof(rows));
    memset(res, 0, sizeof(*res));
    int status = ZI_FAIL;
    if (zi_check_zone(z, arena, apex, t->shown, t->text, tinydns, info, &rows, res)) {
        snprintf(res->zone, sizeof(res->zone), "%s", rows.zone);
        res->dry_run = z->o.dry_run;
        status = z->o.signer ? zi_apply_signer(z, &rows, arena, t->shown, res) : zi_apply(z, &rows, t->shown, res);
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
    if (z->o.signer) {
        ZI_ERR(z, DC_DB_IMPORT_OPTION, NULL, "a signer import takes a zone file, not a tinydns data file");
        return ZI_FAIL;
    }
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

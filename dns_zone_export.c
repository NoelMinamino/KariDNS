/*
 * dns_zone_export.c - the ZoneExporter of 0.6.0 (dns_zone_export.h): a zone of a PowerDNS 5.1 database as zone-file text.
 * Ordinary process code (malloc allowed); the server does not link it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns_zone_export.h"
#include "dns_pdns_reader.h"
#include "dns_zone_rows.h"

struct zx_s {
    const db_driver_t *drv;
    db_conn_t *conn;
    db_schema_info_t si;
    zmsg_t msg;
    pdns_opts_t reader;                 /* what the loader's reader gets (zx_set_reader_opts) */
};

#define ZX_ERR(x, code, ...) zmsg_emit(&(x)->msg, DIAG_ERROR, (code), NULL, __VA_ARGS__)

zx_t *zx_open(const db_driver_t *drv, const db_source_t *src, const zmsg_t *msg) {
    zmsg_t m = msg ? *msg : (zmsg_t){ NULL, NULL };
    zx_t *x = calloc(1, sizeof(*x));
    if (!x) {
        zmsg_emit(&m, DIAG_ERROR, DC_INTERNAL_OOM, NULL, "out of memory");
        return NULL;
    }
    x->drv = drv;
    x->msg = m;
    char err[DB_ERRLEN];
    if (drv->open(&x->conn, src, err, sizeof(err)) != 0) {
        ZX_ERR(x, DC_DB_EXPORT_OPEN, "%s", err);
        free(x);
        return NULL;
    }
    if (drv->check_schema(x->conn, &x->si) != 0) {
        ZX_ERR(x, DC_DB_EXPORT_OPEN, "%s", drv->errmsg(x->conn));
        drv->close(x->conn);
        free(x);
        return NULL;
    }
    return x;
}

void zx_set_reader_opts(zx_t *x, const pdns_opts_t *o) { x->reader = *o; }

void zx_close(zx_t *x) {
    if (!x) return;
    x->drv->close(x->conn);
    free(x);
}

static bool zx_primary(const char *type) { return type && (strcasecmp(type, "NATIVE") == 0 || strcasecmp(type, "MASTER") == 0); }

/* ------------------------------------------------------------------------------------------------------------- */
/* views                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

/* the rows of karidns_domain_views as (domain id, is it the view asked for) */
typedef struct { int64_t id; bool mine; } vrow_t;
typedef struct { const char *view; vrow_t *v; size_t n, cap; bool oom; } vmap_t;

static int zx_cb_view(void *ud, int64_t did, const char *vn) {
    vmap_t *m = ud;
    if (m->n == m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 64;
        vrow_t *nv = realloc(m->v, nc * sizeof(*nv));
        if (!nv) return m->oom = true;
        m->v = nv;
        m->cap = nc;
    }
    m->v[m->n++] = (vrow_t){ did, strcasecmp(vn, m->view) == 0 };
    return 0;
}

/* Is the zone in the view?  A domain without any row is in every view; with rows, only in the views they name (the loader's rule, names
 * compared in C without case). */
static bool zx_in_view(const vmap_t *m, int64_t id) {
    bool any = false, mine = false;
    for (size_t i = 0; i < m->n; i++)
        if (m->v[i].id == id) {
            any = true;
            mine = mine || m->v[i].mine;
        }
    return !any || mine;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the list of zones                                                                                              */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { int64_t id; char *name; } zname_t;
typedef struct { zname_t *v; size_t n, cap; bool oom; } znames_t;

static int zx_cb_list(void *ud, const db_zone_row_t *r) {
    znames_t *l = ud;
    if (!r->name || !zx_primary(r->type)) return 0;
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 64;
        zname_t *nv = realloc(l->v, nc * sizeof(*nv));
        if (!nv) return l->oom = true;
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n].id = r->id;
    if (!(l->v[l->n].name = strdup(r->name))) return l->oom = true;
    l->n++;
    return 0;
}

static int zx_cmp_name(const void *a, const void *b) { return strcmp(((const zname_t *)a)->name, ((const zname_t *)b)->name); }

int zx_list_zones(zx_t *x, const char *view, zx_zone_fn fn, void *ud) {
    const db_driver_t *d = x->drv;
    znames_t l = {0};
    vmap_t vm = { view, NULL, 0, 0, false };
    int ret = -1;
    if (d->begin_snapshot(x->conn) != 0) {
        ZX_ERR(x, DC_DB_EXPORT_READ, "%s", d->errmsg(x->conn));
        return -1;
    }
    if (d->list_zones(x->conn, zx_cb_list, &l) != 0 || l.oom) {
        ZX_ERR(x, l.oom ? DC_INTERNAL_OOM : DC_DB_EXPORT_READ, "%s", l.oom ? "out of memory" : d->errmsg(x->conn));
        goto out;
    }
    if (view && x->si.has_domain_views && (d->scan_domain_views(x->conn, NULL, zx_cb_view, &vm) != 0 || vm.oom)) {
        ZX_ERR(x, vm.oom ? DC_INTERNAL_OOM : DC_DB_EXPORT_READ, "%s", vm.oom ? "out of memory" : d->errmsg(x->conn));
        goto out;
    }
    ret = 0;
out:
    d->end_snapshot(x->conn);
    if (ret == 0) {
        qsort(l.v, l.n, sizeof(*l.v), zx_cmp_name);
        for (size_t i = 0; i < l.n; i++)
            if ((!view || zx_in_view(&vm, l.v[i].id)) && fn(ud, l.v[i].name) != 0) break;
    }
    for (size_t i = 0; i < l.n; i++) free(l.v[i].name);
    free(l.v);
    free(vm.v);
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* one zone                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { const char *want; bool found, ambiguous; int64_t id; char *name, *type; } zfind_t;

static int zx_cb_zone(void *ud, const db_zone_row_t *r) {
    zfind_t *f = ud;
    if (!r->name || !zrows_names_equal(r->name, f->want)) return 0;       /* decided in C, not by an SQL collation */
    if (f->found) {
        if (r->id != f->id) f->ambiguous = true;
        return 0;
    }
    f->found = true;
    f->id = r->id;
    f->name = strdup(r->name);
    f->type = strdup(r->type ? r->type : "");
    return 0;
}

/* the rows of the zone into the reader; a bad row stops the scan (the reader keeps the reason).  plain: the DNSSEC records (and metadata) a signer
 * owns are left out, so the zone is read as the unsigned zone it holds (ZX_PLAIN_*) */
typedef struct { pdns_zone_t *z; unsigned plain; } zx_feed_t;

/* ZX_PLAIN_CHAIN: the chain types, and an RRSIG over them (the type an RRSIG row covers is the first word of its content) */
static bool zx_chain_type(const char *t) {
    return strcasecmp(t, "NSEC") == 0 || strcasecmp(t, "NSEC3") == 0 || strcasecmp(t, "NSEC3PARAM") == 0 || strcasecmp(t, "TYPE47") == 0 ||
           strcasecmp(t, "TYPE50") == 0 || strcasecmp(t, "TYPE51") == 0;
}

static bool zx_skip_type(unsigned plain, const db_record_row_t *r) {
    const char *t = r->type;
    if (!plain || !t) return false;
    if (plain == ZX_PLAIN_CHAIN) {
        if (strcasecmp(t, "RRSIG") != 0) return zx_chain_type(t);
        char w[16];
        size_t n = 0;
        const char *c = r->content ? r->content : "";
        while (*c == ' ') c++;
        while (c[n] && c[n] != ' ' && n < sizeof(w) - 1) {
            w[n] = c[n];
            n++;
        }
        w[n] = '\0';
        return zx_chain_type(w);
    }
    static const char *const dnssec[] = { "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY" };
    for (size_t i = 0; i < sizeof(dnssec) / sizeof(dnssec[0]); i++)
        if (strcasecmp(t, dnssec[i]) == 0) return true;
    return (plain & ZX_PLAIN_CDS) && (strcasecmp(t, "CDS") == 0 || strcasecmp(t, "CDNSKEY") == 0);
}

static int zx_cb_rec(void *ud, int64_t did, const db_record_row_t *r) {
    (void)did;
    zx_feed_t *f = ud;
    if (zx_skip_type(f->plain, r)) return 0;
    return pdns_zone_add_record(f->z, r) != 0;
}

static int zx_cb_meta(void *ud, const db_meta_row_t *m) {
    zx_feed_t *f = ud;
    if (f->plain && m->kind && (strcasecmp(m->kind, "PRESIGNED") == 0 || strcasecmp(m->kind, "NSEC3PARAM") == 0)) return 0;
    return pdns_zone_add_meta(f->z, m) != 0;
}
static int zx_cb_tags(void *ud, int64_t did, const db_tag_row_t *r) {
    (void)did;
    return pdns_zone_add_tags(ud, r) != 0;
}
static int zx_cb_tdns(void *ud, int64_t did, const db_tinydns_row_t *r) {
    (void)did;
    return pdns_zone_add_tinydns(ud, r) != 0;
}
static int zx_cb_defs(void *ud, int64_t did, const db_tagdef_row_t *r) {
    (void)did;
    return pdns_zone_add_tagdef(ud, r) != 0;
}

typedef struct { int64_t id; bool has; } keyq_t;
static int zx_cb_key(void *ud, int64_t did) {
    keyq_t *k = ud;
    if (did == k->id) k->has = true;
    return 0;
}

int zx_read_zone_ex(const db_driver_t *d, db_conn_t *c, bool has_ext, const char *name, int64_t id, const pdns_opts_t *opts, unsigned plain, pdns_zone_t **out,
                    bool *has_keys) {
    pdns_opts_t zero;
    memset(&zero, 0, sizeof(zero));
    *out = NULL;
    pdns_zone_t *z = pdns_zone_new(name, opts ? opts : &zero);
    if (!z) return ZX_READ_OOM;
    zx_feed_t feed = { z, plain };
    int rc = 0;
    if (!z->failed) rc = d->scan_records(c, &id, zx_cb_rec, &feed);
    if (rc == 0 && !z->failed) rc = d->scan_metadata(c, &id, zx_cb_meta, &feed);
    if (rc == 0 && !z->failed && has_ext) {
        db_ext_sink_t sk = { zx_cb_tags, zx_cb_tdns, zx_cb_defs, z };
        rc = d->scan_ext(c, &id, &sk);
    }
    keyq_t kq = { id, false };
    if (has_keys && rc == 0 && !z->failed) rc = d->zones_with_keys(c, zx_cb_key, &kq);
    if (has_keys) *has_keys = kq.has;
    if (rc != 0 && rc != DB_STOPPED) {
        pdns_zone_free(z);
        return ZX_READ_DB;
    }
    *out = z;
    if (z->failed || pdns_zone_finish(z) != 0) return ZX_READ_ZONE;
    return ZX_READ_OK;
}

int zx_read_zone(const db_driver_t *d, db_conn_t *c, bool has_ext, const char *name, int64_t id, const pdns_opts_t *opts, pdns_zone_t **out, bool *has_keys) {
    return zx_read_zone_ex(d, c, has_ext, name, id, opts, 0, out, has_keys);
}

int zx_export_zone_ex(zx_t *x, const char *zone, const char *view, const dzt_opts_t *fmt, dzt_sink_t sink, void *ud, unsigned plain) {
    const db_driver_t *d = x->drv;
    db_conn_t *c = x->conn;
    zfind_t zf = { zone, false, false, 0, NULL, NULL };
    pdns_zone_t *z = NULL;
    int ret = -1;
    if (d->begin_snapshot(c) != 0) {
        ZX_ERR(x, DC_DB_EXPORT_READ, "%s", d->errmsg(c));
        return -1;
    }
    if (d->find_zone(c, zone, zx_cb_zone, &zf) != 0) {
        ZX_ERR(x, DC_DB_EXPORT_READ, "%s", d->errmsg(c));
        goto out;
    }
    if (!zf.found || zf.ambiguous) {
        if (zf.ambiguous) ZX_ERR(x, DC_DB_EXPORT_READ, "More than one domains row is called '%s' (names that differ in case)", zone);
        else ZX_ERR(x, DC_DB_EXPORT_NOT_FOUND, "Zone '%s' is not in the database", zone);
        goto out;
    }
    if (view && x->si.has_domain_views) {
        vmap_t vm = { view, NULL, 0, 0, false };
        int rc = d->scan_domain_views(c, &zf.id, zx_cb_view, &vm);
        bool in = rc == 0 && !vm.oom && zx_in_view(&vm, zf.id);
        free(vm.v);
        if (rc != 0 || vm.oom) {
            ZX_ERR(x, DC_DB_EXPORT_READ, "%s", rc != 0 ? d->errmsg(c) : "out of memory");
            goto out;
        }
        if (!in) {
            ZX_ERR(x, DC_DB_EXPORT_NOT_FOUND, "Zone '%s' is not in the view '%s'", zone, view);
            goto out;
        }
    }
    if (!zx_primary(zf.type)) {
        ZX_ERR(x, DC_DB_EXPORT_ZONE_TYPE, "Zone '%s' has domains.type %s: only NATIVE and MASTER zones have records the server serves", zone,
               zf.type[0] ? zf.type : "NULL");
        goto out;
    }
    bool has_keys = false;
    switch (zx_read_zone_ex(d, c, x->si.has_ext, zf.name, zf.id, &x->reader, plain, &z, &has_keys)) {
    case ZX_READ_OK: break;
    case ZX_READ_OOM:
        ZX_ERR(x, DC_INTERNAL_OOM, "out of memory");
        goto out;
    case ZX_READ_DB:
        ZX_ERR(x, DC_DB_EXPORT_READ, "%s", d->errmsg(c));
        goto out;
    default:
        ZX_ERR(x, DC_DB_EXPORT_ZONE, "%s", z->error);
        goto out;
    }
    for (size_t i = 0; i < z->n_warnings; i++) zmsg_emit(&x->msg, DIAG_WARNING, DC_DB_EXPORT_WARNING, NULL, "%s", z->warnings[i]);
    if (has_keys && !plain && !(z->flags & PDNS_F_PRESIGNED)) {
        ZX_ERR(x, DC_DB_EXPORT_ZONE, "Zone '%s' has cryptokeys but no PRESIGNED=1 metadata (online signing is not supported): the server does not serve it", zone);
        goto out;
    }
    char err[600];
    if (!dns_zone_text_write(&z->arena, z->name, fmt, sink, ud, err, sizeof(err))) {
        ZX_ERR(x, DC_DB_EXPORT_WRITE, "Zone '%s': %s", zone, err);
        goto out;
    }
    ret = 0;
out:
    d->end_snapshot(c);
    pdns_zone_free(z);
    free(zf.name);
    free(zf.type);
    return ret;
}

int zx_export_zone(zx_t *x, const char *zone, const char *view, const dzt_opts_t *fmt, dzt_sink_t sink, void *ud) {
    return zx_export_zone_ex(x, zone, view, fmt, sink, ud, 0);
}

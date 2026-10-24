/*
 * karidns_dbloader.c - karidns-dbloader (beta design 1; milestone B3: the offline dump mode).
 *
 * Reads the PowerDNS 5.1 tables of one database through a driver (dns_db_driver.h), converts every zone with the
 * shared reader (dns_pdns_reader.h) and writes the KDB1 stream (dns_db_stream.h) the loader sends to the Backend:
 * HELLO, BATCH_BEGIN (startup), per zone ZONE_BEGIN / ZONE_DATA... / ZONE_END or ZONE_FAILED, BATCH_END.
 *
 *   karidns-dbloader --dump OUT --driver sqlite3 --database-file PATH [options]     (B3, this file)
 *   karidns-dbloader -s FD                                                          (B4a: stream mode)
 *
 * Ordinary process code like the tools (malloc and file I/O are fine, no Capsicum in beta); what it reads from the
 * database is untrusted and is validated by the reader.  What it writes is untrusted for the Backend.
 *
 * Bulk path (design 5.1): one snapshot; list_zones; scan_records over all zones in domain_id order feeding
 * pdns_zone_add_record() zone by zone; metadata and the cryptokeys existence list are read once before.  With --zone
 * only that zone is read (scan_records(domain_id)).  Zones are written in domains.id order, so two runs on the same
 * database give the same bytes (the HELLO of a dump carries pid 0 for that reason).
 *
 * Diff reload (stream mode, B6a, design 5.1): the loader keeps the inventory of what the Backend has (view, name,
 * source id, serial, digest, from the Backend's INVENTORY and its ZONE_RESULTs).  A load is one snapshot in which
 * list_zones and the change log (karidns_changes) are read; a zone is read and converted when it is new, when its serial
 * differs, when the change log lists it, when the Backend rejected its last version, or when everything is compared (the
 * first load of a loader process, a change of sources, an unusable change log).  A converted zone whose digest is the one
 * the Backend has is not sent.  Zones the Backend has and the database no longer lists get a ZONE_DELETE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "dns_db_driver.h"
#include "dns_db_stream.h"
#include "dns_pdns_reader.h"

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

enum { EXIT_OK = 0, EXIT_ZONES_FAILED = 1, EXIT_USAGE = 2, EXIT_ERROR = 3, EXIT_RETRY = 4 };

/* Messages.  Dump mode: stderr with the program prefix (the lines the dump tests expect).  Stream mode: syslog
 * (openlog() has LOG_PERROR, so a foreground server still shows them on stderr). */
static bool g_stream_mode;
static volatile sig_atomic_t g_stop;      /* SIGTERM / SIGINT in stream mode */
static void lg(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void lg(int prio, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (g_stream_mode) syslog(prio, "%s", msg);
    else fprintf(stderr, "karidns-dbloader: %s\n", msg);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* drivers compiled in                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static const db_driver_t *const k_drivers[] = {
#ifdef KARIDNS_DB_SQLITE3
    &db_driver_sqlite3,
#endif
#ifdef KARIDNS_DB_POSTGRESQL
    &db_driver_postgresql,
#endif
    NULL
};

static const db_driver_t *driver_find(const char *name) {
    for (size_t i = 0; k_drivers[i]; i++)
        if (strcmp(k_drivers[i]->name, name) == 0) return k_drivers[i];
    return NULL;
}

static void drivers_list(char *out, size_t cap) {
    out[0] = '\0';
    for (size_t i = 0; k_drivers[i]; i++) {
        size_t l = strlen(out);
        snprintf(out + l, cap - l, "%s%s", i ? ", " : "", k_drivers[i]->name);
    }
    if (!out[0]) snprintf(out, cap, "none");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* loader state                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    int64_t id;
    char *name;
    char *type;
    char *master;                     /* domains.master (SLAVE / CONSUMER: the masters), NULL if NULL */
    char *canon;                      /* stream mode: the canonical absolute name, NULL if the name is unusable */
    uint32_t serial;                  /* serial of the enabled apex SOA */
    bool has_serial;
    bool want;                        /* stream mode: read and convert this zone in this load */
    bool g_ok;                        /* stream mode: the Backend has a version of the zone it did not reject (digest gate) ... */
    int64_t g_source;                 /* ... with this source id, serial and digest (copied from the inventory by plan_diff(), */
    uint32_t g_serial;                /* so that the conversion threads never read the inventory) */
    uint8_t g_digest[KDB_DIGEST_LEN];
} zinfo_t;
typedef struct { int64_t domain_id; char *kind; char *content; } meta_t;
typedef struct { meta_t *v; size_t n, cap; bool oom; } mset_t;

/* ---- B8: the rows of karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs (design 3.7) ----
 * Copies, in scan order (domain_id ascending; within a domain the order of the table's scan).  A bulk load keeps the rows of every
 * zone (x->ext, read only while the conversion threads run); a one-zone read fills the worker's own set. */
typedef struct { int64_t domain_id, record_id; char *loc, *ecs; } xtag_t;
typedef struct { int64_t domain_id, record_id; bool ttd_null; int64_t ttd; char *loc; bool countdown; } xtd_t;
typedef struct { int64_t domain_id; char *kind, *tag, *cidr; } xdef_t;
typedef struct {
    xtag_t *tags; size_t nt, ct;
    xtd_t *td; size_t nd, cd;
    xdef_t *defs; size_t ng, cg;
    bool oom;
} eset_t;

static bool eset_grow(void **v, size_t *cap, size_t n, size_t esz) {
    if (n < *cap) return true;
    size_t nc = *cap ? *cap * 2 : 64;
    void *nv = realloc(*v, nc * esz);
    if (!nv) return false;
    *v = nv;
    *cap = nc;
    return true;
}

static char *dup_or_null(const char *s, bool *oom) {
    if (!s) return NULL;
    char *d = strdup(s);
    if (!d) *oom = true;
    return d;
}

static int eset_tags_cb(void *ud, int64_t did, const db_tag_row_t *r) {
    eset_t *e = ud;
    if (!eset_grow((void **)&e->tags, &e->ct, e->nt, sizeof(*e->tags))) return e->oom = true;
    xtag_t *t = &e->tags[e->nt];
    t->domain_id = did;
    t->record_id = r->record_id;
    t->loc = dup_or_null(r->location_tag, &e->oom);
    t->ecs = dup_or_null(r->ecs_tag, &e->oom);
    if (e->oom) {
        free(t->loc);
        free(t->ecs);
        return 1;
    }
    e->nt++;
    return 0;
}

static int eset_td_cb(void *ud, int64_t did, const db_tinydns_row_t *r) {
    eset_t *e = ud;
    if (!eset_grow((void **)&e->td, &e->cd, e->nd, sizeof(*e->td))) return e->oom = true;
    xtd_t *t = &e->td[e->nd];
    t->domain_id = did;
    t->record_id = r->record_id;
    t->ttd_null = r->ttd_null;
    t->ttd = r->ttd;
    t->countdown = r->countdown;
    t->loc = dup_or_null(r->loc, &e->oom);
    if (e->oom) return 1;
    e->nd++;
    return 0;
}

static int eset_def_cb(void *ud, int64_t did, const db_tagdef_row_t *r) {
    eset_t *e = ud;
    if (!eset_grow((void **)&e->defs, &e->cg, e->ng, sizeof(*e->defs))) return e->oom = true;
    xdef_t *t = &e->defs[e->ng];
    t->domain_id = did;
    t->kind = dup_or_null(r->kind, &e->oom);
    t->tag = dup_or_null(r->tag, &e->oom);
    t->cidr = dup_or_null(r->cidr, &e->oom);
    if (e->oom) {
        free(t->kind);
        free(t->tag);
        free(t->cidr);
        return 1;
    }
    e->ng++;
    return 0;
}

static void eset_reset(eset_t *e) {
    for (size_t i = 0; i < e->nt; i++) {
        free(e->tags[i].loc);
        free(e->tags[i].ecs);
    }
    for (size_t i = 0; i < e->nd; i++) free(e->td[i].loc);
    for (size_t i = 0; i < e->ng; i++) {
        free(e->defs[i].kind);
        free(e->defs[i].tag);
        free(e->defs[i].cidr);
    }
    e->nt = e->nd = e->ng = 0;
    e->oom = false;
}

static void eset_free(eset_t *e) {
    eset_reset(e);
    free(e->tags);
    free(e->td);
    free(e->defs);
    memset(e, 0, sizeof(*e));
}

/* read the rows of one domain (id) or of every domain (NULL) into e; the driver's return value */
static int eset_load(const db_driver_t *drv, db_conn_t *conn, const int64_t *id, eset_t *e) {
    db_ext_sink_t sink = { eset_tags_cb, eset_td_cb, eset_def_cb, e };
    return drv->scan_ext(conn, id, &sink);
}

/* first row of the vector with domain_id >= id */
#define ESET_LOWER(NAME, TYPE, FIELD)                                                                  \
    static size_t NAME(const TYPE *v, size_t n, int64_t id) {                                          \
        size_t lo = 0, hi = n;                                                                         \
        while (lo < hi) {                                                                              \
            size_t mid = lo + (hi - lo) / 2;                                                           \
            if (v[mid].domain_id < id) lo = mid + 1;                                                   \
            else hi = mid;                                                                             \
        }                                                                                              \
        return lo;                                                                                     \
    }
ESET_LOWER(eset_lower_tags, xtag_t, tags)
ESET_LOWER(eset_lower_td, xtd_t, td)
ESET_LOWER(eset_lower_defs, xdef_t, defs)

/* the rows of zone `id` into the reader; the reader checks them (a bad row fails the zone at pdns_zone_finish()) */
static void eset_feed(const eset_t *e, int64_t id, pdns_zone_t *z) {
    for (size_t i = eset_lower_tags(e->tags, e->nt, id); i < e->nt && e->tags[i].domain_id == id && !z->failed; i++) {
        db_tag_row_t r = { e->tags[i].record_id, e->tags[i].loc, e->tags[i].ecs };
        pdns_zone_add_tags(z, &r);
    }
    for (size_t i = eset_lower_td(e->td, e->nd, id); i < e->nd && e->td[i].domain_id == id && !z->failed; i++) {
        db_tinydns_row_t r = { e->td[i].record_id, e->td[i].ttd_null, e->td[i].ttd, e->td[i].loc, e->td[i].countdown };
        pdns_zone_add_tinydns(z, &r);
    }
    for (size_t i = eset_lower_defs(e->defs, e->ng, id); i < e->ng && e->defs[i].domain_id == id && !z->failed; i++) {
        db_tagdef_row_t r = { e->defs[i].kind, e->defs[i].tag, e->defs[i].cidr };
        pdns_zone_add_tagdef(z, &r);
    }
}


/* What the Backend has (stream mode): one entry per (view, zone name), filled from the Backend's INVENTORY and kept up
 * to date from its ZONE_RESULTs.  A version that was sent but not answered yet is "pending". */
typedef struct inv_ent {
    struct inv_ent *next;
    uint32_t hash;
    uint16_t vslot;                   /* index into lio.vnames: the view, by name (view indexes move when the views change) */
    bool known;                       /* the Backend has a version (source_id, serial, digest) */
    bool dirty;                       /* the last version offered was rejected / unreadable: offer the zone again */
    bool has_pend;
    uint32_t mark;                    /* generation of the diff that saw the zone in the database */
    int64_t source_id, p_source_id;
    uint32_t serial, p_serial;
    uint8_t digest[KDB_DIGEST_LEN], p_digest[KDB_DIGEST_LEN];
    char name[];
} inv_ent_t;

typedef struct { inv_ent_t **tab; size_t nb, count; } inv_t;

/* per source (view name): the change log position of the last complete load */
typedef struct { uint64_t seq; bool seq_valid; bool nolog_warned; } vstate_t;

typedef struct {
    const db_driver_t *drv;
    db_conn_t *conn;
    FILE *out;
    bool io_error;
    uint16_t view;
    pdns_opts_t opts;
    /* zone list */
    zinfo_t *zones;
    size_t nz, zcap;
    const char *only_name;            /* list only this zone (--zone, or a one-zone reload request) */
    /* bulk scan: the metadata of every zone (sorted by domain_id); the zones with cryptokeys */
    mset_t meta;
    int64_t *keys;
    size_t nk, kcap;
    bool has_ext;                     /* B8: the source has the extension tables (check_schema) */
    eset_t ext;                       /* B8: bulk scan: their rows for every zone (sorted by domain_id) */
    /* B6b: the zones to read (positions in zones[], ascending), the conversion threads, the view mapping */
    size_t *wl;
    size_t nwl;
    uint32_t nthreads;                /* loader-threads: 1..16 */
    const char *map_view;             /* non-NULL: keep only the zones karidns_domain_views maps to this view (D6) */
    bool map_logged;                  /* the mapping rows naming unknown views were logged in this batch */
    /* results */
    uint32_t n_zones, n_failed;       /* ZONE_END / ZONE_FAILED messages written */
    uint32_t n_unwritten;             /* failed zones whose name cannot be written to the stream */
    bool oom;
    kdb_enc_t enc;
    /* stream mode (-s FD, B4a); all zero in dump mode, so a ctx_t made by memset() is a dump context */
    struct lio *io;                   /* non-NULL: write to the socket (io->fd) instead of x->out */
    uint64_t batch_id;
    uint8_t batch_kind;
    uint64_t change_seq;
    bool batch_open;                  /* BATCH_BEGIN sent, BATCH_END not yet */
    /* diff reload (B6a) */
    uint64_t req_id;                  /* the RELOAD_REQ this batch answers, 0 = none (BATCH_BEGIN tag 4) */
    bool force;                       /* read and send the zone even when the Backend has this exact version */
    bool reconcile;                   /* compare every zone (digest) instead of trusting serials and the change log */
    uint16_t vslot;                   /* the view being read (lio.vnames) */
    int bulk_threshold;               /* percent of the zones of a source above which one bulk scan beats one query per zone */
    int64_t *chg;                     /* ids listed in the change log since the last load, sorted */
    size_t nchg, cchg;
    uint32_t n_unchanged;             /* zones not sent: serial and change log say nothing happened, or the digest is the same */
    uint32_t n_deleted;               /* ZONE_DELETE messages */
    uint32_t n_read;                  /* zones read and converted */
    char errtext[240];                /* the last database error (printable), for the ZONE_FAILED of a one-zone request */
    /* B7a: karidns_profiles of the source being read (loaded before the conversion threads start, read only while they
     * run) and the profiles already sent in the open batch (a PROFILE goes out once per batch and text) */
    struct lprof { char *name; char *text; const char *bad; } *profs;
    size_t nprofs, cprofs;
    bool prof_oom;
    struct psent { char name[256]; uint64_t hash; size_t len; } *psent;
    size_t npsent, cpsent;
} ctx_t;

static int stream_write(ctx_t *x, const uint8_t *msg, size_t len);

/* ------------------------------------------------------------------------------------------------------------- */
/* stream mode state: the Backend's CONFIG, the requests, the inventory                                           */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    uint16_t index;
    bool shared;                             /* the source is the global one: karidns_domain_views maps zones to this view (B6b) */
    char *name, *source, *conninfo;          /* source: the file (sqlite3) or schema (postgresql); NULL = driver default */
    uint8_t auto_reload;
    uint32_t poll_interval, coalesce_ms;
    uint64_t max_records, max_bytes;
} lview_t;

typedef struct {
    uint64_t generation;
    char driver[40], server_id[72];
    uint32_t default_ttl, loader_threads;
    int bulk_threshold;
    lview_t *views;
    size_t nviews;
} lcfg_t;

typedef struct { uint64_t id; uint16_t view; bool force; char zone[DNS_NAME_TEXT_SIZE]; } lreq_t;

#define LREQ_MAX 64
#define IDX_SLOTS 65536                      /* view indexes are u16 */

struct lio {
    int fd;
    kdb_framer_t fr;
    uint8_t *body;                           /* KDB_MAX_BODY */
    uint8_t rbuf[65536];
    bool eof, failed;
    lcfg_t cfg;                              /* in use by a load */
    bool have_cfg;
    lcfg_t newcfg;                           /* the latest CONFIG, adopted between two loads (a load walks cfg.views) */
    bool have_newcfg;
    bool inv_end;
    uint64_t inv_entries, inv_seq;
    lreq_t req[LREQ_MAX];
    size_t nreq;
    bool reload_all;                         /* a RELOAD_REQ scope all arrived (or the queue overflowed) */
    uint64_t all_req_id;                     /* the request id of the last scope all request, 0 = none */
    uint64_t batch_seq;
    uint64_t batches_ended, batch_results;   /* BATCH_ENDs sent / BATCH_RESULTs received: a load waits for the difference */
    uint64_t n_results, n_rejected, n_shadowed;   /* ZONE_RESULTs of the current batch */
    char first_reject[130];
    /* the inventory and the per-view state, by view name */
    inv_t inv;
    uint32_t gen;
    char **vnames;
    vstate_t *vst;
    size_t nvn, cvn;
    int32_t *idx_slot;                       /* view index -> slot of vnames, -1 = no such view in the current CONFIG */
};

static uint32_t name_hash(uint16_t vslot, const char *s) {
    uint32_t h = 2166136261u ^ vslot;
    for (; *s; s++) {
        h ^= (uint8_t)tolower((unsigned char)*s);
        h *= 16777619u;
    }
    return h;
}

static inv_ent_t *inv_find(inv_t *t, uint16_t vslot, const char *name) {
    if (!t->nb) return NULL;
    uint32_t h = name_hash(vslot, name);
    for (inv_ent_t *e = t->tab[h & (t->nb - 1)]; e; e = e->next)
        if (e->hash == h && e->vslot == vslot && strcasecmp(e->name, name) == 0) return e;
    return NULL;
}

/* the entry for (view, name), created empty (not known) if there is none; NULL on out of memory */
static inv_ent_t *inv_get(inv_t *t, uint16_t vslot, const char *name) {
    inv_ent_t *e = inv_find(t, vslot, name);
    if (e) return e;
    if (t->count >= t->nb) {
        size_t nnb = t->nb ? t->nb * 2 : 1024;
        inv_ent_t **nt = calloc(nnb, sizeof(*nt));
        if (!nt) return NULL;
        for (size_t i = 0; i < t->nb; i++) {
            inv_ent_t *p = t->tab[i];
            while (p) {
                inv_ent_t *nx = p->next;
                p->next = nt[p->hash & (nnb - 1)];
                nt[p->hash & (nnb - 1)] = p;
                p = nx;
            }
        }
        free(t->tab);
        t->tab = nt;
        t->nb = nnb;
    }
    size_t l = strlen(name);
    e = calloc(1, sizeof(*e) + l + 1);
    if (!e) return NULL;
    memcpy(e->name, name, l + 1);
    e->vslot = vslot;
    e->hash = name_hash(vslot, name);
    e->next = t->tab[e->hash & (t->nb - 1)];
    t->tab[e->hash & (t->nb - 1)] = e;
    t->count++;
    return e;
}

static void inv_del(inv_t *t, inv_ent_t *e) {
    inv_ent_t **pp = &t->tab[e->hash & (t->nb - 1)];
    while (*pp && *pp != e) pp = &(*pp)->next;
    if (*pp) {
        *pp = e->next;
        t->count--;
        free(e);
    }
}

static void inv_free(inv_t *t) {
    for (size_t i = 0; i < t->nb; i++) {
        inv_ent_t *e = t->tab[i];
        while (e) {
            inv_ent_t *nx = e->next;
            free(e);
            e = nx;
        }
    }
    free(t->tab);
    memset(t, 0, sizeof(*t));
}

/* slot of a view name in lio.vnames (appended when new); (uint16_t)-1 on out of memory.  The slot is stable for the
 * life of the process, so the inventory and the change log positions survive a CONFIG that renumbers the views. */
static int vslot_get(struct lio *io, const char *name) {
    for (size_t i = 0; i < io->nvn; i++)
        if (strcasecmp(io->vnames[i], name) == 0) return (int)i;
    if (io->nvn == io->cvn) {
        size_t nc = io->cvn ? io->cvn * 2 : 8;
        char **nn = realloc(io->vnames, nc * sizeof(*nn));
        if (!nn) return -1;
        io->vnames = nn;
        vstate_t *nv = realloc(io->vst, nc * sizeof(*nv));
        if (!nv) return -1;
        io->vst = nv;
        io->cvn = nc;
    }
    char *d = strdup(name);
    if (!d) return -1;
    io->vnames[io->nvn] = d;
    memset(&io->vst[io->nvn], 0, sizeof(vstate_t));
    return (int)io->nvn++;
}

static void io_free_views(struct lio *io) {
    for (size_t i = 0; i < io->nvn; i++) free(io->vnames[i]);
    free(io->vnames);
    free(io->vst);
    free(io->idx_slot);
    inv_free(&io->inv);
}

static int emit_file(void *ud, const uint8_t *msg, size_t len) {
    ctx_t *x = ud;
    if (x->io_error) return -1;
    if (x->io) {
        if (stream_write(x, msg, len) != 0) {
            x->io_error = true;
            return -1;
        }
        return 0;
    }
    if (fwrite(msg, 1, len, x->out) != len) {
        x->io_error = true;
        return -1;
    }
    return 0;
}

static int send_enc(ctx_t *x) {
    if (x->enc.err) return -1;
    int rc = emit_file(x, x->enc.buf, x->enc.len);
    kdb_enc_reset(&x->enc);
    return rc;
}

/* reasons go into a TLV `str`: printable ASCII, at most 255 bytes */
static void clean_reason(const char *in, char *out, size_t cap) {
    size_t k = 0;
    for (; in && *in && k < cap - 1 && k < 255; in++) out[k++] = (*in >= 0x20 && *in < 0x7F) ? *in : '?';
    out[k] = '\0';
}

/* ------------------------------------------------------------------------------------------------------------- */
/* collecting the lists                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

static bool names_equal(const char *a, const char *b);

static int zone_cb(void *ud, const db_zone_row_t *r) {
    ctx_t *x = ud;
    if (x->only_name && !(r->name && names_equal(r->name, x->only_name))) return 0;
    if (x->nz >= x->zcap) {
        size_t nc = x->zcap ? x->zcap * 2 : 256;
        zinfo_t *nzs = realloc(x->zones, nc * sizeof(*nzs));
        if (!nzs) return x->oom = true;
        x->zones = nzs;
        x->zcap = nc;
    }
    zinfo_t *z = &x->zones[x->nz];
    memset(z, 0, sizeof(*z));
    z->id = r->id;
    z->name = r->name ? strdup(r->name) : NULL;
    z->type = r->type ? strdup(r->type) : NULL;
    z->master = r->master ? strdup(r->master) : NULL;
    if ((r->name && !z->name) || (r->type && !z->type) || (r->master && !z->master)) {
        free(z->name);
        free(z->type);
        free(z->master);
        return x->oom = true;
    }
    if (x->io) {                                     /* stream mode: the diff needs the canonical name and the serial */
        char canon[DNS_NAME_TEXT_SIZE];
        if (pdns_canonical_zone_name(z->name, canon)) {
            z->canon = strdup(canon);
            if (!z->canon) {
                free(z->name);
                free(z->type);
                free(z->master);
                return x->oom = true;
            }
        }
        z->has_serial = r->soa_content && pdns_soa_serial(r->soa_content, &z->serial);
    }
    x->nz++;
    return x->only_name ? 1 : 0;                    /* one zone wanted: stop after it (names are unique) */
}

static int chg_cb(void *ud, const db_change_row_t *r) {
    ctx_t *x = ud;
    if (x->nchg >= x->cchg) {
        size_t nc = x->cchg ? x->cchg * 2 : 256;
        int64_t *n = realloc(x->chg, nc * sizeof(*n));
        if (!n) return x->oom = true;
        x->chg = n;
        x->cchg = nc;
    }
    x->chg[x->nchg++] = r->domain_id;
    return 0;
}

static int cmp_i64(const void *a, const void *b);

static bool chg_has(const ctx_t *x, int64_t id) {
    return x->nchg && bsearch(&id, x->chg, x->nchg, sizeof(int64_t), cmp_i64) != NULL;
}

static int meta_cb(void *ud, const db_meta_row_t *r) {
    mset_t *m = ud;
    if (m->n >= m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 256;
        meta_t *nms = realloc(m->v, nc * sizeof(*nms));
        if (!nms) return m->oom = true;
        m->v = nms;
        m->cap = nc;
    }
    meta_t *e = &m->v[m->n];
    e->domain_id = r->domain_id;
    e->kind = r->kind ? strdup(r->kind) : NULL;
    e->content = r->content ? strdup(r->content) : NULL;
    if ((r->kind && !e->kind) || (r->content && !e->content)) {
        free(e->kind);
        free(e->content);
        return m->oom = true;
    }
    m->n++;
    return 0;
}

/* forget the rows, keep the array */
static void mset_reset(mset_t *m) {
    for (size_t i = 0; i < m->n; i++) {
        free(m->v[i].kind);
        free(m->v[i].content);
    }
    m->n = 0;
    m->oom = false;
}

static void mset_free(mset_t *m) {
    mset_reset(m);
    free(m->v);
    memset(m, 0, sizeof(*m));
}

static int key_cb(void *ud, int64_t id) {
    ctx_t *x = ud;
    if (x->nk >= x->kcap) {
        size_t nc = x->kcap ? x->kcap * 2 : 64;
        int64_t *nk = realloc(x->keys, nc * sizeof(*nk));
        if (!nk) return x->oom = true;
        x->keys = nk;
        x->kcap = nc;
    }
    x->keys[x->nk++] = id;
    return 0;
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y;
}

static bool zone_has_keys(const ctx_t *x, int64_t id) {
    return x->nk && bsearch(&id, x->keys, x->nk, sizeof(int64_t), cmp_i64) != NULL;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* one zone                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

/* The ZONE_FAILED of a zone the loader cannot give the Backend (the Backend refuses any name but the canonical one: a
 * name that cannot be written as one is only reported on stderr / syslog). */
static int send_failed(ctx_t *x, const zinfo_t *zi, const char *reason) {
    char name[DNS_NAME_TEXT_SIZE], why[260], shown[210];
    clean_reason(zi->name ? zi->name : "(NULL)", shown, sizeof(shown));
    lg(LOG_ERR, "zone '%s' (domains.id %lld): %s", shown, (long long)zi->id, reason);
    if (!pdns_canonical_zone_name(zi->name, name)) {
        lg(LOG_ERR, "the zone name is not a valid domain name; not written to the stream");
        x->n_unwritten++;
        return 0;
    }
    if (x->io) {                    /* the Backend keeps its last good version; offer the zone again at the next load */
        inv_ent_t *e = inv_find(&x->io->inv, x->vslot, name);
        if (e && e->known) e->dirty = true;
    }
    x->n_failed++;
    clean_reason(reason, why, sizeof(why));
    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_FAILED) != 0 || kdb_enc_u16(&x->enc, 1, x->view) != 0 ||
        kdb_enc_name(&x->enc, 2, name) != 0 || kdb_enc_i64(&x->enc, 3, zi->id) != 0 || kdb_enc_str(&x->enc, 4, why) != 0 ||
        kdb_enc_end(&x->enc) != 0)
        return -1;
    return send_enc(x);
}

/* B7b: a SLAVE zone is a secondary (its masters are domains.master, its data comes by zone transfer, never from `records`); a
 * CONSUMER is a catalog consumer (the existing catalog secondary support: the member zones it lists are created and
 * transferred from the same masters).  Both are sent as ZONE_BEGIN without data (design 1.4); the Backend keeps the transferred
 * data in memory only.  0 = a zone with rows (NATIVE / MASTER). */
static uint8_t zone_sec_kind(const char *type) {
    if (type && strcasecmp(type, "SLAVE") == 0) return KDB_ZK_SECONDARY;
    if (type && strcasecmp(type, "CONSUMER") == 0) return KDB_ZK_CATALOG;
    return KDB_ZK_PRIMARY;
}

static const char *zone_type_reason(const char *type) {
    if (!type) return "domains.type is NULL";
    if (strcasecmp(type, "NATIVE") == 0 || strcasecmp(type, "MASTER") == 0) return NULL;
    if (strcasecmp(type, "SLAVE") == 0 || strcasecmp(type, "CONSUMER") == 0) return NULL;      /* B7b: see zone_sec_kind() */
    if (strcasecmp(type, "PRODUCER") == 0) return "catalog producer zones (type PRODUCER) are not loaded yet (later 0.6.x)";
    return "unsupported domains.type";
}

/* B6b: a zone is converted by a worker (the main thread when loader-threads is 1) into a zres_t, and committed to the
 * stream by the main thread, in zones[] order.  The worker never touches the inventory, the socket or the counters: it
 * reads the zone's own entry of zones[] (the Backend's version of it, copied by plan_diff()) and builds the ZONE_BEGIN /
 * ZONE_DATA / ZONE_END messages in memory, so a conversion that fails half way leaves nothing on the stream. */
static void io_pump(struct lio *io);

enum { ZR_UNCHANGED = 1, ZR_SENT, ZR_FAILED, ZR_FATAL };
typedef struct {
    uint8_t kind;
    uint8_t *buf;                     /* ZR_SENT: the messages */
    size_t len, cap;
    bool oom;
    uint32_t serial;                  /* ZR_SENT */
    uint8_t digest[KDB_DIGEST_LEN];
    char profile[256];                /* ZR_SENT: the profile the zone names ("" = none): commit_zone() sends its PROFILE first */
    char *reason;                     /* ZR_FAILED */
} zres_t;

static void zres_reset(zres_t *r) {
    r->kind = 0;
    r->profile[0] = '\0';
    r->len = 0;
    r->oom = false;
    free(r->reason);
    r->reason = NULL;
}

static void zres_free(zres_t *r) {
    free(r->buf);
    free(r->reason);
    memset(r, 0, sizeof(*r));
}

static int zres_emit(void *ud, const uint8_t *msg, size_t len) {
    zres_t *r = ud;
    if (len > r->cap - r->len) {
        size_t nc = r->cap ? r->cap : 4096;
        while (nc - r->len < len) nc *= 2;
        uint8_t *nb = realloc(r->buf, nc);
        if (!nb) {
            r->oom = true;
            return -1;
        }
        r->buf = nb;
        r->cap = nc;
    }
    memcpy(r->buf + r->len, msg, len);
    r->len += len;
    return 0;
}

static void zres_fail(zres_t *r, const char *reason) {
    r->len = 0;
    r->reason = strdup(reason);
    r->kind = r->reason ? ZR_FAILED : ZR_FATAL;
}

typedef struct wk {
    ctx_t *x;                         /* shared; read only while workers run */
    const db_driver_t *drv;
    db_conn_t *conn;
    const mset_t *bulk_meta;          /* bulk scan: the metadata of every zone; NULL = read them zone by zone into zmeta */
    mset_t zmeta;
    eset_t zext;                      /* B8: one-zone reads: the extension rows of the zone */
    size_t wi, wend;                  /* the next position of x->wl to finish, and the end of the task */
    pdns_zone_t *cur;
    bool cur_open;
    zres_t res;                       /* scratch for the zone being converted */
    bool oom, stop;
    int (*deliver)(struct wk *w, size_t pos, zres_t *r);   /* nonzero: stop */
    void *dud;
    char errtext[240];
} wk_t;

#define WZ(w, pos) (&(w)->x->zones[(w)->x->wl[pos]])

static void wk_free(wk_t *w) {
    if (w->cur_open && w->cur) pdns_zone_free(w->cur);
    w->cur = NULL;
    w->cur_open = false;
    mset_free(&w->zmeta);
    eset_free(&w->zext);
    zres_free(&w->res);
}

static void open_current(wk_t *w, const zinfo_t *zi) {
    if (w->cur_open) return;
    w->cur_open = true;
    w->cur = NULL;
    if (zi->name && !zone_type_reason(zi->type)) w->cur = pdns_zone_new(zi->name, &w->x->opts);
    if (zi->name && !zone_type_reason(zi->type) && !w->cur) w->oom = true;
}

/* ---- karidns_profiles (B7a, design 3.7, 1.4) ----
 * The loader does not interpret a profile: it checks that the text can travel (a PROFILE settings value is printable ASCII,
 * TAB and LF, at most 65,535 bytes) and sends it before the first zone of the batch that names it.  The Backend merges it
 * with the zone's own settings (the zone's statements replace the profile's) and parses the result in restricted mode. */
static int prof_cb(void *ud, const db_profile_row_t *r) {
    ctx_t *x = ud;
    if (x->nprofs >= x->cprofs) {
        size_t nc = x->cprofs ? x->cprofs * 2 : 16;
        struct lprof *np = realloc(x->profs, nc * sizeof(*np));
        if (!np) return x->prof_oom = true;
        x->profs = np;
        x->cprofs = nc;
    }
    struct lprof *p = &x->profs[x->nprofs];
    p->name = strdup(r->name);
    p->text = strdup(r->settings ? r->settings : "");
    p->bad = NULL;
    if (!p->name || !p->text) {
        free(p->name);
        free(p->text);
        return x->prof_oom = true;
    }
    size_t n = strlen(p->text);
    if (n > PDNS_MAX_SETTINGS) {
        p->bad = "its settings text is longer than 65535 bytes";
    } else {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)p->text[i];
            if ((c < 0x20 || c > 0x7E) && c != '\t' && c != '\n') {
                p->bad = "its settings text has a character other than printable ASCII, TAB and LF";
                break;
            }
        }
    }
    x->nprofs++;
    return 0;
}

static const struct lprof *lprof_find(const ctx_t *x, const char *name) {
    for (size_t i = 0; i < x->nprofs; i++)
        if (strcmp(x->profs[i].name, name) == 0) return &x->profs[i];
    return NULL;
}

static uint64_t text_hash(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* the PROFILE message of a zone about to be sent, unless the batch carried this name with this text already.  The Backend
 * keeps the latest text of a name, so two views that read different databases and use the same profile name each get
 * their own text in front of their zones.  0, or -1 (output error, memory). */
static int send_profile_for(ctx_t *x, const char *name) {
    const struct lprof *pf = lprof_find(x, name);
    if (!pf) return 0;
    size_t len = strlen(pf->text);
    uint64_t h = text_hash(pf->text, len);
    for (size_t i = 0; i < x->npsent; i++)
        if (strcmp(x->psent[i].name, name) == 0) {
            if (x->psent[i].hash == h && x->psent[i].len == len) return 0;
            x->psent[i].hash = h;
            x->psent[i].len = len;
            goto send;
        }
    if (x->npsent >= x->cpsent) {
        size_t nc = x->cpsent ? x->cpsent * 2 : 16;
        struct psent *np = realloc(x->psent, nc * sizeof(*np));
        if (!np) {
            x->oom = true;
            return -1;
        }
        x->psent = np;
        x->cpsent = nc;
    }
    snprintf(x->psent[x->npsent].name, sizeof(x->psent[0].name), "%s", name);
    x->psent[x->npsent].hash = h;
    x->psent[x->npsent].len = len;
    x->npsent++;
send:
    if (kdb_enc_begin(&x->enc, KDB_T_PROFILE) != 0 || kdb_enc_str(&x->enc, 1, name) != 0 ||
        kdb_enc_str(&x->enc, 2, pf->text) != 0 || kdb_enc_end(&x->enc) != 0)
        return -1;
    return send_enc(x);
}

/* the digest gate of pdns_zone_encode_kdb(): a zone whose converted stream has the digest the Backend already holds
 * (same source id, no pending rejection; copied into the zinfo by plan_diff) is not sent unless the request says force */
typedef struct { const ctx_t *x; const zinfo_t *zi; uint8_t digest[KDB_DIGEST_LEN]; } gate_t;

static int gate_cb(void *ud, uint32_t serial, const uint8_t digest[KDB_DIGEST_LEN]) {
    gate_t *g = ud;
    const zinfo_t *zi = g->zi;
    memcpy(g->digest, digest, KDB_DIGEST_LEN);          /* what ZONE_BEGIN will carry: the pending version of the entry */
    if (!g->x->io || g->x->force || !zi->canon) return 0;
    return zi->g_ok && zi->g_source == zi->id && zi->g_serial == serial && memcmp(zi->g_digest, digest, KDB_DIGEST_LEN) == 0;
}

/* index of the first metadata row with domain_id >= id (rows are sorted by domain_id) */
static size_t meta_lower(const mset_t *m, int64_t id) {
    size_t lo = 0, hi = m->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (m->v[mid].domain_id < id) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/* Convert the zone zi (its rows were added to w->cur) into w->res.  Never fails: a bad zone is a ZR_FAILED result. */
static void convert_zone(wk_t *w, const zinfo_t *zi) {
    ctx_t *x = w->x;
    zres_t *r = &w->res;
    zres_reset(r);
    open_current(w, zi);
    pdns_zone_t *z = w->cur;
    const char *tr = zone_type_reason(zi->type);
    const uint8_t skind = zone_sec_kind(zi->type);
    if (z && skind != KDB_ZK_PRIMARY && pdns_zone_set_secondary(z, skind, zi->master) != 0) w->oom = true;
    if (w->oom) {
        r->kind = ZR_FATAL;
    } else if (!zi->name) {
        zres_fail(r, "domains.name is NULL");
    } else if (tr) {
        zres_fail(r, tr);
    } else {
        /* metadata of this zone (sorted by domain_id) */
        const mset_t *m = w->bulk_meta ? w->bulk_meta : &w->zmeta;
        for (size_t mi = w->bulk_meta ? meta_lower(m, zi->id) : 0; !z->failed && mi < m->n && m->v[mi].domain_id == zi->id; mi++) {
            db_meta_row_t row = { zi->id, m->v[mi].kind, m->v[mi].content };
            pdns_zone_add_meta(z, &row);
        }
        if (skind == KDB_ZK_PRIMARY && x->has_ext) eset_feed(w->bulk_meta ? &x->ext : &w->zext, zi->id, z);      // B8: tags, tinydns attributes, tag definitions
        const char *why = NULL;
        if (pdns_zone_finish(z) != 0) {
            why = z->error;
        } else if (skind == KDB_ZK_PRIMARY && zone_has_keys(x, zi->id) && !(z->flags & PDNS_F_PRESIGNED)) {
            /* design 3.5: PowerDNS would sign the zone online, KariDNS serves pre-signed data only */
            why = "the zone has cryptokeys but no PRESIGNED=1 metadata (online signing is not supported)";
        }
        for (size_t i = 0; i < z->n_warnings; i++)
            lg(LOG_WARNING, "warning: %s", z->warnings[i]);
        /* B7a: the profile a zone names must be in karidns_profiles and fit the stream (design 3.7, 1.4) */
        const struct lprof *pf = NULL;
        char pwhy[200];
        if (!why && z->profile[0]) {
            pf = lprof_find(x, z->profile);
            if (!pf) {
                snprintf(pwhy, sizeof(pwhy), "the profile '%.64s' (X-KARIDNS-PROFILE) is not defined in karidns_profiles", z->profile);
                why = pwhy;
            } else if (pf->bad) {
                snprintf(pwhy, sizeof(pwhy), "the profile '%.64s' cannot be used: %s", z->profile, pf->bad);
                why = pwhy;
            }
        }
        if (why) {
            zres_fail(r, why);
        } else {
            gate_t g;
            memset(&g, 0, sizeof(g));
            g.x = x;
            g.zi = zi;
            pdns_kdb_params_t p = { x->view, zi->id, KDB_ZK_PRIMARY, NULL, gate_cb, &g, pf ? pf->text : NULL };
            char msg[PDNS_ERR_LEN + 100];
            int er = pdns_zone_encode_kdb(z, &p, zres_emit, r, msg, sizeof(msg));
            if (er == 0) {
                r->kind = ZR_SENT;
                r->serial = z->serial;
                snprintf(r->profile, sizeof(r->profile), "%s", z->profile);
                memcpy(r->digest, g.digest, KDB_DIGEST_LEN);
            } else if (er == 1) {
                r->kind = ZR_UNCHANGED;     /* converted, but the Backend has exactly this version */
            } else if (r->oom) {
                r->kind = ZR_FATAL;
            } else {
                zres_fail(r, msg);
            }
        }
    }
    pdns_zone_free(z);
    w->cur = NULL;
    w->cur_open = false;
}

static int send_simple_header(ctx_t *x);

/* Write the result of one zone to the stream (the main thread only; this is where the counters and the inventory are
 * touched).  0, or -1 on a fatal error (output, memory). */
static int commit_zone(ctx_t *x, const zinfo_t *zi, zres_t *r) {
    if (r->kind == ZR_FATAL) {
        x->oom = true;
        return -1;
    }
    if (send_simple_header(x) != 0) {
        x->io_error = true;
        return -1;
    }
    x->n_read++;
    switch (r->kind) {
    case ZR_UNCHANGED:
        x->n_unchanged++;
        return 0;
    case ZR_FAILED:
        return send_failed(x, zi, r->reason);
    default:                                   /* ZR_SENT */
        if (r->profile[0] && send_profile_for(x, r->profile) != 0) return -1;   /* B7a: the profile text comes first */
        if (emit_file(x, r->buf, r->len) != 0) return -1;
        x->n_zones++;
        if (x->io) {                           /* sent: what the Backend will have once it says "applied" */
            inv_ent_t *ie = inv_get(&x->io->inv, x->vslot, zi->canon);
            if (!ie) {
                x->oom = true;
                return -1;
            }
            ie->has_pend = true;
            ie->p_source_id = zi->id;
            ie->p_serial = r->serial;
            memcpy(ie->p_digest, r->digest, KDB_DIGEST_LEN);
        }
        return 0;
    }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the scan                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

/* convert and hand over the zone at w->wi; nonzero when the load must stop */
static int finish_pos(wk_t *w) {
    size_t pos = w->wi++;
    convert_zone(w, WZ(w, pos));
    if (w->deliver(w, pos, &w->res) != 0) {
        w->stop = true;
        return 1;
    }
    return 0;
}

static int rec_cb(void *ud, int64_t did, const db_record_row_t *row) {
    wk_t *w = ud;
    while (w->wi < w->wend && WZ(w, w->wi)->id < did) {
        if (finish_pos(w) != 0) return 1;
    }
    if (w->wi >= w->wend || WZ(w, w->wi)->id != did) return 0;      /* a row of a domain that is not wanted: ignored */
    open_current(w, WZ(w, w->wi));
    if (w->oom) {
        w->stop = true;
        return 1;
    }
    if (w->cur && !w->cur->failed && !zone_sec_kind(WZ(w, w->wi)->type)) pdns_zone_add_record(w->cur, row);   /* B7b: a SLAVE's rows are PowerDNS's copy of the transfer */
    return 0;
}

static int send_hello(ctx_t *x, const char *driver_list, uint32_t pid);
static int db_err_c(const db_driver_t *drv, db_conn_t *conn, char *errtext, size_t cap, int rc, const char *what);

enum { TK_FATAL = -1 };      /* a task returns 0, an EXIT_* status of a database error, or this */

/* Read and convert the wanted zones at positions a..b-1 of x->wl.  bulk: one scan of the records (all = the whole table,
 * otherwise the domain_id range of the zones), else one query per zone. */
static int run_task(wk_t *w, size_t a, size_t b, bool bulk, bool all) {
    const db_driver_t *drv = w->drv;
    int rc;
    w->wi = a;
    w->wend = b;
    if (bulk) {
        if (all) rc = drv->scan_records(w->conn, NULL, rec_cb, w);
        else rc = drv->scan_records_range(w->conn, WZ(w, a)->id, WZ(w, b - 1)->id, rec_cb, w);
        if (rc != 0 && rc != DB_STOPPED) return db_err_c(drv, w->conn, w->errtext, sizeof(w->errtext), rc, "reading records");
        if (rc == DB_STOPPED) {
            if (!w->stop) {
                lg(LOG_ERR, "internal error: the scan was stopped");
                snprintf(w->errtext, sizeof(w->errtext), "internal error: the scan was stopped");
                return EXIT_ERROR;
            }
            return TK_FATAL;
        }
        while (w->wi < w->wend)
            if (finish_pos(w) != 0) return TK_FATAL;
        return 0;
    }
    for (size_t pos = a; pos < b; pos++) {
        int64_t id = WZ(w, pos)->id;
        w->wi = pos;
        mset_reset(&w->zmeta);
        bool sec = zone_sec_kind(WZ(w, pos)->type) != KDB_ZK_PRIMARY;      /* B7b: no records are read for a secondary zone */
        eset_reset(&w->zext);
        if ((rc = drv->scan_metadata(w->conn, &id, meta_cb, &w->zmeta)) != 0 || (!sec && (rc = drv->scan_records(w->conn, &id, rec_cb, w)) != 0) ||
            (!sec && w->x->has_ext && (rc = eset_load(drv, w->conn, &id, &w->zext)) != 0)) {
            if (rc == DB_STOPPED) {
                if (w->zmeta.oom || w->zext.oom) w->oom = true;
                return TK_FATAL;
            }
            return db_err_c(drv, w->conn, w->errtext, sizeof(w->errtext), rc, "reading the zone");
        }
        if (finish_pos(w) != 0) return TK_FATAL;
    }
    return 0;
}

/* loader-threads 1 (or a single zone): the main thread converts and commits, zone by zone, on the connection of the view */
static int deliver_inline(wk_t *w, size_t pos, zres_t *r) {
    return commit_zone(w->x, WZ(w, pos), r);
}

/* ---- loader-threads N > 1 (design 1.5, D10) ----
 * N workers, each with its own connection and snapshot (later than the main thread's, so the change seq in BATCH_BEGIN
 * never runs ahead of what they read), take tasks of consecutive wanted zones from an atomic counter and convert them.
 * The results go through a window of slots indexed by the zone's position in x->wl; the main thread commits the slots in
 * position order, so the stream is the same as with one thread.  No mutex: the hand-over is the slot state (release /
 * acquire), the window base `emitted`, and a byte budget for results that wait out of order.  Waiting is by sched_yield
 * and short sleeps (the main thread also polls the socket, so the Backend's answers are read while it waits). */
#define POOL_BUDGET (256u << 20)         /* bytes of finished zones waiting for their turn (the next one in line is always taken) */
#define POOL_MAX 16

typedef struct { _Atomic int state; zres_t r; } zslot_t;       /* 0 empty, 1 full */

typedef struct pool {
    ctx_t *x;
    const db_source_t *src;
    bool bulk;
    size_t n_want, chunk, win;
    zslot_t *slots;
    _Atomic size_t next_task, emitted, buffered;
    _Atomic bool stop;
    _Atomic int failed;                  /* the first EXIT_* status of a worker, 0 = none */
    _Atomic bool oom;
    wk_t wk[POOL_MAX];
    char errtext[240];                   /* of the first failing worker (written once, under the CAS on `failed`) */
    pthread_t tid[POOL_MAX];
} pool_t;

static void nap(unsigned *spins) {
    if (++*spins < 32) {
        sched_yield();
    } else {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL);
    }
}

static void pool_fail(pool_t *p, wk_t *w, int status) {
    int none = 0;
    if (atomic_compare_exchange_strong(&p->failed, &none, status)) snprintf(p->errtext, sizeof(p->errtext), "%s", w->errtext);
    atomic_store(&p->stop, true);
}

static int deliver_slot(wk_t *w, size_t pos, zres_t *r) {
    pool_t *p = w->dud;
    unsigned spins = 0;
    for (;;) {                                                         /* the slot of pos is free once pos - win is committed */
        if (atomic_load_explicit(&p->stop, memory_order_acquire)) return -1;
        if (pos < atomic_load_explicit(&p->emitted, memory_order_acquire) + p->win) break;
        nap(&spins);
    }
    spins = 0;
    while (pos != atomic_load_explicit(&p->emitted, memory_order_acquire) &&
           atomic_load_explicit(&p->buffered, memory_order_relaxed) + r->len > POOL_BUDGET) {
        if (atomic_load_explicit(&p->stop, memory_order_acquire)) return -1;
        nap(&spins);
    }
    zslot_t *s = &p->slots[pos % p->win];
    zres_t t = s->r;                                                   /* swap, so both sides keep their buffers */
    s->r = *r;
    *r = t;
    atomic_fetch_add_explicit(&p->buffered, s->r.len, memory_order_relaxed);
    atomic_store_explicit(&s->state, 1, memory_order_release);
    return 0;
}

static void *worker_main(void *arg) {
    wk_t *w = arg;
    pool_t *p = w->dud;
    char err[DB_ERRLEN];
    int rc = w->drv->open(&w->conn, p->src, err, sizeof(err));
    if (rc != 0) {
        lg(LOG_ERR, "%s", err);
        clean_reason(err, w->errtext, sizeof(w->errtext));
        pool_fail(p, w, rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR);
        return NULL;
    }
    if ((rc = w->drv->begin_snapshot(w->conn)) != 0) {
        pool_fail(p, w, db_err_c(w->drv, w->conn, w->errtext, sizeof(w->errtext), rc, "snapshot"));
        w->drv->close(w->conn);
        w->conn = NULL;
        return NULL;
    }
    while (!atomic_load_explicit(&p->stop, memory_order_acquire)) {
        size_t t = atomic_fetch_add_explicit(&p->next_task, 1, memory_order_relaxed);
        size_t a = t * p->chunk;
        if (a >= p->n_want) break;
        size_t b = a + p->chunk < p->n_want ? a + p->chunk : p->n_want;
        int st = run_task(w, a, b, p->bulk, false);
        if (st == 0) continue;
        if (st == TK_FATAL) {
            if (w->oom) {
                atomic_store(&p->oom, true);
                snprintf(w->errtext, sizeof(w->errtext), "out of memory");
                pool_fail(p, w, EXIT_ERROR);
            }
            atomic_store(&p->stop, true);                              /* otherwise the main thread asked us to stop */
        } else {
            pool_fail(p, w, st);
        }
        break;
    }
    w->drv->end_snapshot(w->conn);
    w->drv->close(w->conn);
    w->conn = NULL;
    return NULL;
}

/* Wait for the next result while reading what the Backend sent.  0, or -1 when the load must stop. */
static int pool_wait(ctx_t *x, unsigned *spins) {
    if (g_stop) return -1;
    if (x->io) {
        struct pollfd pf = { x->io->fd, POLLIN, 0 };
        if (*spins > 32) {
            int r = poll(&pf, 1, 1);
            if (r > 0) io_pump(x->io);
        } else {
            nap(spins);
        }
        if (x->io->eof || x->io->failed) {
            errno = EPIPE;
            x->io_error = true;
            return -1;
        }
        ++*spins;
        return 0;
    }
    nap(spins);
    return 0;
}

static int run_pool(ctx_t *x, const db_source_t *src, bool bulk, size_t n_want, size_t nthr) {
    pool_t *p = calloc(1, sizeof(*p));
    if (!p) {
        x->oom = true;
        return TK_FATAL;
    }
    p->x = x;
    p->src = src;
    p->bulk = bulk;
    p->n_want = n_want;
    size_t cmax = bulk ? 128 : 32;
    p->chunk = n_want / (nthr * 4);
    if (p->chunk < 1) p->chunk = 1;
    if (p->chunk > cmax) p->chunk = cmax;
    p->win = nthr * p->chunk * 3 + 8;
    p->slots = calloc(p->win, sizeof(*p->slots));
    if (!p->slots) {
        free(p);
        x->oom = true;
        return TK_FATAL;
    }
    sigset_t all, old;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);                            /* workers take no signals: SIGTERM is for the main thread */
    size_t started = 0;
    for (size_t i = 0; i < nthr; i++) {
        wk_t *w = &p->wk[i];
        w->x = x;
        w->drv = x->drv;
        w->bulk_meta = bulk ? &x->meta : NULL;
        w->deliver = deliver_slot;
        w->dud = p;
        if (pthread_create(&p->tid[i], NULL, worker_main, w) != 0) break;
        started++;
    }
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    int result = 0;
    if (started == 0) {
        lg(LOG_ERR, "cannot start the loader threads: %s", strerror(errno));
        snprintf(x->errtext, sizeof(x->errtext), "cannot start the loader threads");
        result = EXIT_ERROR;
        atomic_store(&p->stop, true);
    }
    for (size_t pos = 0; started && pos < n_want; pos++) {
        zslot_t *s = &p->slots[pos % p->win];
        unsigned spins = 0;
        while (atomic_load_explicit(&s->state, memory_order_acquire) != 1) {
            if (atomic_load_explicit(&p->failed, memory_order_acquire) || pool_wait(x, &spins) != 0) goto drain;
        }
        int rc = commit_zone(x, &x->zones[x->wl[pos]], &s->r);
        atomic_fetch_sub_explicit(&p->buffered, s->r.len, memory_order_relaxed);
        s->r.len = 0;
        atomic_store_explicit(&s->state, 0, memory_order_relaxed);
        atomic_store_explicit(&p->emitted, pos + 1, memory_order_release);
        if (rc != 0) goto drain;
    }
drain:
    atomic_store(&p->stop, true);
    for (size_t i = 0; i < started; i++) pthread_join(p->tid[i], NULL);
    if (x->io_error || x->oom) {
        result = TK_FATAL;
    } else if (g_stop) {
        result = TK_FATAL;
    } else if (atomic_load(&p->failed)) {
        if (atomic_load(&p->oom)) x->oom = true;
        result = atomic_load(&p->failed);
        snprintf(x->errtext, sizeof(x->errtext), "%s", p->errtext);
        if (x->oom) result = TK_FATAL;
    }
    for (size_t i = 0; i < nthr; i++) wk_free(&p->wk[i]);
    for (size_t i = 0; i < p->win; i++) zres_free(&p->slots[i].r);
    free(p->slots);
    free(p);
    return result;
}

/* Convert the n_want wanted zones.  Returns 0, an EXIT_* status of a database error (x->errtext says what), or TK_FATAL. */
static int run_zones(ctx_t *x, const db_source_t *src, bool bulk, size_t n_want) {
    size_t nthr = x->nthreads < n_want ? x->nthreads : n_want;
    if (nthr > POOL_MAX) nthr = POOL_MAX;
    if (nthr > 1) return run_pool(x, src, bulk, n_want, nthr);
    wk_t w;
    memset(&w, 0, sizeof(w));
    w.x = x;
    w.drv = x->drv;
    w.conn = x->conn;
    w.bulk_meta = bulk ? &x->meta : NULL;
    w.deliver = deliver_inline;
    int st = run_task(&w, 0, n_want, bulk, true);
    if (w.oom) x->oom = true;
    if (st > 0) snprintf(x->errtext, sizeof(x->errtext), "%s", w.errtext);
    wk_free(&w);
    return st;
}

static int send_hello(ctx_t *x, const char *driver_list, uint32_t pid) {
    if (kdb_enc_begin(&x->enc, KDB_T_HELLO) != 0 || kdb_enc_u16(&x->enc, 1, KDB_VERSION) != 0 ||
        kdb_enc_str(&x->enc, 2, KARIDNS_VERSION) != 0 || kdb_enc_str(&x->enc, 3, driver_list) != 0 ||
        kdb_enc_u32(&x->enc, 4, pid) != 0 || kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
        return -1;
    return 0;
}

static int send_batch_begin(ctx_t *x, uint64_t id, uint8_t kind, uint64_t change_seq) {
    if (kdb_enc_begin(&x->enc, KDB_T_BATCH_BEGIN) != 0 || kdb_enc_u64(&x->enc, 1, id) != 0 ||
        kdb_enc_u8(&x->enc, 2, kind) != 0 || kdb_enc_u64(&x->enc, 3, change_seq) != 0 ||
        (x->req_id && kdb_enc_u64(&x->enc, 4, x->req_id) != 0) || kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
        return -1;
    return 0;
}

/* dump mode: HELLO and the one startup batch.  Stream mode: HELLO went out at the handshake; BATCH_BEGIN goes out
 * once, just before the first thing of the batch is sent (an error before that leaves nothing half sent). */
static int send_simple_header(ctx_t *x) {
    if (x->io) {
        if (x->batch_open) return 0;
        x->batch_open = true;
        x->npsent = 0;                         /* the Backend forgets the profiles at BATCH_BEGIN */
        return send_batch_begin(x, x->batch_id, x->batch_kind, x->change_seq);
    }
    if (x->batch_open) return 0;
    x->batch_open = true;
    x->npsent = 0;
    if (send_hello(x, x->drv->name, 0) != 0) return -1;
    return send_batch_begin(x, 1, KDB_BATCH_STARTUP, 0);
}

static int send_batch_end(ctx_t *x) {
    if (kdb_enc_begin(&x->enc, KDB_T_BATCH_END) != 0 || kdb_enc_u64(&x->enc, 1, x->io ? x->batch_id : 1) != 0 ||
        kdb_enc_u32(&x->enc, 2, x->n_zones) != 0 || kdb_enc_u32(&x->enc, 3, x->n_failed) != 0 ||
        kdb_enc_u32(&x->enc, 4, x->n_deleted) != 0 || kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
        return -1;
    return 0;
}

static bool names_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 1 && a[la - 1] == '.') la--;
    if (lb > 1 && b[lb - 1] == '.') lb--;
    return la == lb && strncasecmp(a, b, la) == 0;
}

static int db_err_c(const db_driver_t *drv, db_conn_t *conn, char *errtext, size_t cap, int rc, const char *what) {
    const char *m = conn ? drv->errmsg(conn) : "?";
    lg(LOG_ERR, "%s: %s", what, m);
    char shown[200];
    clean_reason(m, shown, sizeof(shown));
    snprintf(errtext, cap, "%s: %s", what, shown);
    return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
}

static int db_err(ctx_t *x, int rc, const char *what) {
    return db_err_c(x->drv, x->conn, x->errtext, sizeof(x->errtext), rc, what);
}

/* Forget the lists of the previous view (zones, metadata, keys).  The context keeps them after a run so that the owner
 * (main(), a test) can look at them; the next run starts empty. */
static void ctx_view_reset(ctx_t *x) {
    for (size_t i = 0; i < x->nz; i++) {
        free(x->zones[i].name);
        free(x->zones[i].type);
        free(x->zones[i].master);
        free(x->zones[i].canon);
    }
    free(x->zones);
    x->zones = NULL;
    x->nz = x->zcap = 0;
    mset_free(&x->meta);
    eset_free(&x->ext);
    x->has_ext = false;
    free(x->keys);
    x->keys = NULL;
    x->nk = x->kcap = 0;
    free(x->chg);
    x->chg = NULL;
    x->nchg = x->cchg = 0;
    free(x->wl);
    x->wl = NULL;
    x->nwl = 0;
    for (size_t i = 0; i < x->nprofs; i++) {
        free(x->profs[i].name);
        free(x->profs[i].text);
    }
    free(x->profs);
    x->profs = NULL;
    x->nprofs = x->cprofs = 0;
    x->prof_oom = false;
}

/* a zone the Backend has and the database no longer lists */
typedef struct { char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; } gone_t;

static int send_delete(ctx_t *x, const gone_t *g) {
    if (send_simple_header(x) != 0) return -1;
    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_DELETE) != 0 || kdb_enc_u16(&x->enc, 1, x->view) != 0 ||
        kdb_enc_name(&x->enc, 2, g->name) != 0 || kdb_enc_i64(&x->enc, 3, g->source_id) != 0 || kdb_enc_end(&x->enc) != 0)
        return -1;
    x->n_deleted++;
    return send_enc(x);
}

/* Stream mode, one source: which zones to read (zinfo.want) and which to delete.  Called inside the snapshot, after
 * list_zones.  compare_all: read every listed zone (the digest gate then decides what is sent). */
static int plan_diff(ctx_t *x, const db_schema_info_t *si, const char *only_zone, gone_t **gone_out, size_t *ngone_out,
                     bool *have_seq, uint64_t *new_seq) {
    struct lio *io = x->io;
    vstate_t *vs = &io->vst[x->vslot];
    bool compare_all = x->reconcile || x->force || only_zone != NULL;
    *have_seq = false;
    if (!only_zone) {
        if (si->has_changes) {
            uint64_t mx = 0;
            int cr = x->drv->changes_max ? x->drv->changes_max(x->conn, &mx) : DB_ERR_UNAVAILABLE;
            if (cr == 0) {
                *have_seq = true;
                *new_seq = mx;
                if (!vs->seq_valid) {
                    compare_all = true;
                } else if (mx < vs->seq) {
                    lg(LOG_NOTICE, "view '%s': the change log was reset (seq %llu < %llu); comparing every zone",
                       io->vnames[x->vslot], (unsigned long long)mx, (unsigned long long)vs->seq);
                    compare_all = true;
                } else if (mx > vs->seq) {
                    uint64_t last = 0;
                    bool gap = false;
                    cr = x->drv->changes_since(x->conn, vs->seq, chg_cb, x, &last, &gap);
                    if (x->oom) return -1;
                    if (cr != 0) {
                        lg(LOG_WARNING, "view '%s': cannot read the change log (%s); comparing every zone",
                           io->vnames[x->vslot], x->drv->errmsg(x->conn));
                        compare_all = true;
                    } else if (gap) {
                        lg(LOG_NOTICE, "view '%s': rows of the change log after seq %llu were pruned; comparing every zone",
                           io->vnames[x->vslot], (unsigned long long)vs->seq);
                        compare_all = true;
                    }
                }
            } else {
                lg(LOG_WARNING, "view '%s': cannot read the change log (%s); comparing every zone", io->vnames[x->vslot],
                   x->drv->errmsg(x->conn));
                compare_all = true;
            }
        } else if (!vs->nolog_warned) {
            vs->nolog_warned = true;
            lg(LOG_NOTICE, "view '%s': the database has no karidns_changes table; zones are compared by serial only (apply "
                           "db/karidns_ext.*.sql to notice edits that keep the serial; 'karictl reload <zone>' reads one zone)",
               io->vnames[x->vslot]);
        }
        if (x->nchg > 1) qsort(x->chg, x->nchg, sizeof(int64_t), cmp_i64);
    }
    uint32_t gen = ++io->gen;
    for (size_t i = 0; i < x->nz; i++) {
        zinfo_t *z = &x->zones[i];
        z->want = false;
        if (!z->canon) {
            z->want = compare_all;                 /* an unusable name is reported when everything is compared */
            continue;
        }
        inv_ent_t *e = inv_find(&io->inv, x->vslot, z->canon);
        if (e) e->mark = gen;
        z->g_ok = e && e->known && !e->dirty;
        if (z->g_ok) {
            z->g_source = e->source_id;
            z->g_serial = e->serial;
            memcpy(z->g_digest, e->digest, KDB_DIGEST_LEN);
        }
        bool changed = chg_has(x, z->id);
        if (zone_type_reason(z->type)) {
            z->want = compare_all || changed;      /* not loadable: reported again only when something happened to it */
        } else {
            /* B7b: a secondary zone has no SOA of its own to compare (what the Backend transferred is its business, and its inventory
             * serial is the 0 it was sent with); the change log, the digest and the source id decide */
            z->want = compare_all || changed || !e || !e->known || e->dirty || e->source_id != z->id ||
                      (!zone_sec_kind(z->type) && (!z->has_serial || z->serial != e->serial));
        }
    }
    /* what the Backend has and the database no longer lists */
    gone_t *gone = NULL;
    size_t ng = 0, cg = 0;
    char only_canon[DNS_NAME_TEXT_SIZE];
    bool have_only = only_zone && pdns_canonical_zone_name(only_zone, only_canon);
    for (size_t b = 0; b < io->inv.nb; b++) {
        for (inv_ent_t *e = io->inv.tab[b]; e; e = e->next) {
            if (e->vslot != x->vslot || e->mark == gen || !e->known) continue;
            if (only_zone && !(have_only && strcasecmp(e->name, only_canon) == 0)) continue;
            if (ng == cg) {
                size_t nc = cg ? cg * 2 : 16;
                gone_t *n = realloc(gone, nc * sizeof(*n));
                if (!n) {
                    free(gone);
                    return -1;
                }
                gone = n;
                cg = nc;
            }
            snprintf(gone[ng].name, sizeof(gone[ng].name), "%s", e->name);
            gone[ng].source_id = e->source_id;
            ng++;
        }
    }
    *gone_out = gone;
    *ngone_out = ng;
    return 0;
}

/* ---- karidns_domain_views (design 3.7, 7.1, D6) ----
 * A view that uses the global source takes the zones the mapping gives it.  A domain without any row goes to every such
 * view; a domain with rows goes to the views they name and to no other (a row that names a view this server does not have
 * for this source is logged and ignored, so a zone meant for another server's view is not served here by mistake).  The
 * names are compared in C, case-insensitively like view names everywhere else, never with an SQL collation. */
typedef struct {
    const ctx_t *x;
    int64_t *any, *mine, *known;          /* domain ids that have a row / a row for this view / a row for any view of this
                                             source (stream mode), ascending */
    size_t nany, cany, nmine, cmine, nknown, cknown;
    bool oom;
    char unk[3][64];                      /* names of views that are not views of this source (the first few) */
    size_t nunk;
    unsigned long unk_rows;
} mapctx_t;

static int push_id(int64_t **v, size_t *n, size_t *cap, int64_t id) {
    if (*n && (*v)[*n - 1] == id) return 0;                 /* the rows come in domain_id order */
    if (*n >= *cap) {
        size_t nc = *cap ? *cap * 2 : 256;
        int64_t *nv = realloc(*v, nc * sizeof(*nv));
        if (!nv) return -1;
        *v = nv;
        *cap = nc;
    }
    (*v)[(*n)++] = id;
    return 0;
}

static bool view_uses_shared_source(const struct lio *io, const char *name) {
    for (size_t i = 0; i < io->cfg.nviews; i++)
        if (io->cfg.views[i].shared && strcasecmp(io->cfg.views[i].name, name) == 0) return true;
    return false;
}

static int map_cb(void *ud, int64_t did, const char *vn) {
    mapctx_t *m = ud;
    if (push_id(&m->any, &m->nany, &m->cany, did) != 0) return m->oom = true;
    if (strcasecmp(vn, m->x->map_view) == 0) {
        if (push_id(&m->mine, &m->nmine, &m->cmine, did) != 0) return m->oom = true;
        if (push_id(&m->known, &m->nknown, &m->cknown, did) != 0) return m->oom = true;
    } else if (m->x->io && view_uses_shared_source(m->x->io, vn)) {
        if (push_id(&m->known, &m->nknown, &m->cknown, did) != 0) return m->oom = true;
    } else if (m->x->io) {
        m->unk_rows++;
        bool seen = false;
        for (size_t i = 0; i < m->nunk; i++)
            if (strcasecmp(m->unk[i], vn) == 0) seen = true;
        if (!seen && m->nunk < 3) clean_reason(vn, m->unk[m->nunk++], sizeof(m->unk[0]));
    }
    return 0;
}

/* Drop the zones of x->zones[] the mapping does not give to x->map_view.  0, or an EXIT_* status. */
static int apply_mapping(ctx_t *x, const db_schema_info_t *si) {
    if (!x->map_view || !si->has_domain_views || x->nz == 0) return 0;
    mapctx_t m;
    memset(&m, 0, sizeof(m));
    m.x = x;
    const int64_t *one = x->only_name ? &x->zones[0].id : NULL;      /* a one-zone list has the zone alone */
    int rc = x->drv->scan_domain_views(x->conn, one, map_cb, &m);
    int ret = 0;
    if (rc != 0) {
        ret = m.oom ? EXIT_ERROR : db_err(x, rc, "reading karidns_domain_views");
        if (m.oom) lg(LOG_ERR, "out of memory");
    } else {
        /* zones whose rows only name views that do not use this source are served by no view: say which (once per
         * batch, like the rows below; stream mode only, a dump does not know the other views) */
        size_t norphan = 0;
        char orphan[3][DNS_NAME_TEXT_SIZE];
        for (size_t i = 0; x->io && !x->map_logged && i < x->nz; i++) {
            int64_t id = x->zones[i].id;
            if (!(m.nany && bsearch(&id, m.any, m.nany, sizeof(int64_t), cmp_i64)) ||
                (m.nknown && bsearch(&id, m.known, m.nknown, sizeof(int64_t), cmp_i64)))
                continue;
            if (norphan < 3) clean_reason(x->zones[i].name ? x->zones[i].name : "?", orphan[norphan], sizeof(orphan[0]));
            norphan++;
        }
        size_t keep = 0;
        for (size_t i = 0; i < x->nz; i++) {
            int64_t id = x->zones[i].id;
            bool has_row = m.nany && bsearch(&id, m.any, m.nany, sizeof(int64_t), cmp_i64) != NULL;
            bool mine = m.nmine && bsearch(&id, m.mine, m.nmine, sizeof(int64_t), cmp_i64) != NULL;
            if (!has_row || mine) {
                if (keep != i) x->zones[keep] = x->zones[i];
                keep++;
            } else {
                free(x->zones[i].name);
                free(x->zones[i].type);
                free(x->zones[i].master);
                free(x->zones[i].canon);
            }
        }
        x->nz = keep;
        if (m.nunk && !x->map_logged) {
            x->map_logged = true;
            lg(LOG_WARNING, "karidns_domain_views: %lu row(s) name view(s) that do not use this database as their source (%s%s); "
                            "those rows are ignored, and a zone that only they map is served by no view",
               m.unk_rows, m.unk[0], m.nunk > 1 ? ", ..." : "");
            if (norphan)
                lg(LOG_WARNING, "karidns_domain_views: %zu zone(s) are mapped only to views that do not use this database as "
                                "their source and are served by no view: %s%s%s%s%s%s",
                   norphan, orphan[0], norphan > 1 ? ", " : "", norphan > 1 ? orphan[1] : "", norphan > 2 ? ", " : "",
                   norphan > 2 ? orphan[2] : "", norphan > 3 ? ", ..." : "");
        }
    }
    free(m.any);
    free(m.mine);
    free(m.known);
    return ret;
}

/* One source (one view): open, read the lists, then the records, writing the zones.  whole: the dump of a file,
 * with HELLO / BATCH_BEGIN before the first zone and BATCH_END after the last; otherwise (stream mode) the caller
 * owns the batch and calls this once per view.  Returns an exit status. */
static int run_view(ctx_t *x, const db_source_t *src, const char *only_zone, bool whole) {
    char err[DB_ERRLEN];
    ctx_view_reset(x);
    x->only_name = only_zone;
    int rc = x->drv->open(&x->conn, src, err, sizeof(err));
    if (rc != 0) {
        lg(LOG_ERR, "%s", err);
        clean_reason(err, x->errtext, sizeof(x->errtext));
        return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
    }
    int status = EXIT_OK;
    gone_t *gone = NULL;
    size_t ngone = 0;
    bool have_seq = false;
    uint64_t new_seq = 0;
    db_schema_info_t si;
    memset(&si, 0, sizeof(si));
    if ((rc = x->drv->check_schema(x->conn, &si)) != 0) {
        status = db_err(x, rc, "schema");
        goto out;
    }
    if ((rc = x->drv->begin_snapshot(x->conn)) != 0) {
        status = db_err(x, rc, "snapshot");
        goto out;
    }
    x->has_ext = si.has_ext && x->drv->scan_ext;
    rc = x->drv->list_zones(x->conn, zone_cb, x);
    if (rc == DB_STOPPED && x->only_name && x->nz == 1 && !x->oom) rc = 0;     /* the one zone was found */
    if (rc != 0) {
        status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading the zone list");
        if (x->oom) lg(LOG_ERR, "out of memory");
        goto out_snap;
    }
    if ((rc = apply_mapping(x, &si)) != 0) {
        status = rc;
        goto out_snap;
    }
    if (!x->io && only_zone && x->nz == 0) {
        lg(LOG_ERR, "zone '%.200s' is not in the database%s", only_zone, x->map_view ? " (or not mapped to this view)" : "");
        status = EXIT_ERROR;
        goto out_snap;
    }
    if (x->io) {
        if (plan_diff(x, &si, only_zone, &gone, &ngone, &have_seq, &new_seq) != 0) {
            lg(LOG_ERR, "out of memory");
            status = EXIT_ERROR;
            goto out_snap;
        }
        if (have_seq && new_seq > x->change_seq) x->change_seq = new_seq;   /* BATCH_BEGIN says how far the log was read */
    }
    /* the zones to read, in zones[] order; the others (the diff says nothing happened to them) are only counted */
    x->wl = malloc((x->nz ? x->nz : 1) * sizeof(*x->wl));
    if (!x->wl) {
        lg(LOG_ERR, "out of memory");
        status = EXIT_ERROR;
        goto out_snap;
    }
    for (size_t i = 0; i < x->nz; i++)
        if (!x->io || x->zones[i].want) x->wl[x->nwl++] = i;
    size_t n_want = x->nwl;
    if (x->io) x->n_unchanged += (uint32_t)(x->nz - n_want);
    if (!(x->io && n_want == 0 && ngone == 0)) {         /* otherwise: nothing to read, nothing to delete */
        /* bulk scan (every record of the source in domain_id order, the unwanted zones skipped) or one query per zone */
        bool bulk = !only_zone;
        if (x->io && only_zone == NULL)
            bulk = n_want > 0 && (uint64_t)n_want * 100 >= (uint64_t)x->nz * (uint64_t)(x->bulk_threshold >= 0 ? x->bulk_threshold : 25);
        if ((rc = x->drv->zones_with_keys(x->conn, key_cb, x)) != 0) {
            status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading metadata");
            if (x->oom) lg(LOG_ERR, "out of memory");
            goto out_snap;
        }
        qsort(x->keys, x->nk, sizeof(int64_t), cmp_i64);
        if (n_want > 0 && si.has_profiles && x->drv->scan_profiles) {                  /* B7a: the profiles, in this snapshot, before any zone is converted */
            rc = x->drv->scan_profiles(x->conn, prof_cb, x);
            if (rc != 0) {
                status = x->prof_oom ? EXIT_ERROR : db_err(x, rc, "reading karidns_profiles");
                if (x->prof_oom) lg(LOG_ERR, "out of memory");
                goto out_snap;
            }
        }
        if (bulk && n_want > 0) {
            if ((rc = x->drv->scan_metadata(x->conn, NULL, meta_cb, &x->meta)) != 0) {
                status = x->meta.oom ? EXIT_ERROR : db_err(x, rc, "reading metadata");
                if (x->meta.oom) lg(LOG_ERR, "out of memory");
                goto out_snap;
            }
            if (x->has_ext && (rc = eset_load(x->drv, x->conn, NULL, &x->ext)) != 0) {
                status = x->ext.oom ? EXIT_ERROR : db_err(x, rc, "reading the tags and tinydns attributes");
                if (x->ext.oom) lg(LOG_ERR, "out of memory");
                goto out_snap;
            }
        }
        if (!x->io || n_want > 0 || ngone > 0) {
            if (send_simple_header(x) != 0) {
                lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
                status = EXIT_ERROR;
                goto out_snap;
            }
        }
        int fatal = 0;
        if (n_want > 0) {
            int st = run_zones(x, src, bulk, n_want);
            if (st == TK_FATAL) {
                fatal = 1;
            } else if (st != 0) {
                status = st;
                goto out_snap;
            }
        }
        for (size_t i = 0; i < ngone && !fatal; i++)
            if (send_delete(x, &gone[i]) != 0) fatal = 1;
        if (fatal || x->io_error || x->oom) {
            if (x->oom) lg(LOG_ERR, "out of memory");
            else lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
            status = EXIT_ERROR;
            goto out_snap;
        }
        if (whole && send_batch_end(x) != 0) {
            lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
            status = EXIT_ERROR;
            goto out_snap;
        }
        if (x->n_failed || x->n_unwritten) status = EXIT_ZONES_FAILED;
    }
    if (x->io && have_seq && !only_zone) {                /* a complete load of this source: the log is read up to here */
        vstate_t *vs = &x->io->vst[x->vslot];
        vs->seq = new_seq;
        vs->seq_valid = true;
    }
out_snap:
    x->drv->end_snapshot(x->conn);
out:
    free(gone);
    x->drv->close(x->conn);
    x->conn = NULL;
    return status;
}

/* The whole dump.  Returns an exit status. */
static int run_dump(ctx_t *x, const db_source_t *src, const char *only_zone) {
    return run_view(x, src, only_zone, true);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* stream mode: -s FD, the long-running loader that karidns starts (beta design 1.2, 1.4, 1.5)                    */
/* ------------------------------------------------------------------------------------------------------------- */

static void on_term(int sig) { (void)sig; g_stop = 1; }

static void cfg_free(lcfg_t *c) {
    for (size_t i = 0; i < c->nviews; i++) {
        free(c->views[i].name);
        free(c->views[i].source);
        free(c->views[i].conninfo);
    }
    free(c->views);
    memset(c, 0, sizeof(*c));
}

static char *dup_kstr(kdb_str_t s) {
    if (!s.p) return NULL;
    char *r = malloc((size_t)s.len + 1);
    if (!r) return NULL;
    memcpy(r, s.p, s.len);
    r[s.len] = '\0';
    return r;
}

static int cfg_from_msg(const kdb_msg_t *m, lcfg_t *c) {
    memset(c, 0, sizeof(*c));
    c->generation = m->u.config.generation;
    snprintf(c->driver, sizeof(c->driver), "%.*s", (int)m->u.config.driver.len, m->u.config.driver.p);
    if (m->u.config.server_id.p)
        snprintf(c->server_id, sizeof(c->server_id), "%.*s", (int)m->u.config.server_id.len, m->u.config.server_id.p);
    c->default_ttl = m->u.config.default_ttl;
    c->loader_threads = m->u.config.loader_threads;
    c->bulk_threshold = m->u.config.bulk_threshold;
    c->views = calloc(m->u.config.n_views ? m->u.config.n_views : 1, sizeof(lview_t));
    if (!c->views) return -1;
    kdb_iter_t it;
    kdb_config_view_t v;
    kdb_config_views(m, &it);
    while (kdb_config_views_next(&it, &v) && c->nviews < m->u.config.n_views) {
        lview_t *d = &c->views[c->nviews++];
        d->index = v.index;
        d->shared = v.shared_source != 0;
        d->name = dup_kstr(v.name);
        d->source = dup_kstr(v.source);
        d->conninfo = dup_kstr(v.conninfo_file);
        d->auto_reload = v.auto_reload;
        d->poll_interval = v.poll_interval;
        d->coalesce_ms = v.coalesce_ms;
        d->max_records = v.max_zone_records;
        d->max_bytes = v.max_zone_bytes;
        if (!d->name || (v.source.p && !d->source) || (v.conninfo_file.p && !d->conninfo)) return -1;
    }
    return 0;
}

static bool streq_n(const char *a, const char *b) { return (a == NULL) == (b == NULL) && (!a || strcmp(a, b) == 0); }

/* Same sources and same conversion parameters: nothing to read again.  (Generation, auto-reload and the poll
 * settings change without a new read.) */
static bool cfg_load_equal(const lcfg_t *a, const lcfg_t *b) {
    if (strcmp(a->driver, b->driver) != 0 || a->default_ttl != b->default_ttl || a->nviews != b->nviews) return false;
    for (size_t i = 0; i < a->nviews; i++) {
        const lview_t *x = &a->views[i], *y = &b->views[i];
        if (x->index != y->index || x->shared != y->shared || strcmp(x->name, y->name) != 0 || !streq_n(x->source, y->source) ||
            !streq_n(x->conninfo, y->conninfo) || x->max_records != y->max_records || x->max_bytes != y->max_bytes)
            return false;
    }
    return true;
}

static void io_dispatch(struct lio *io, const kdb_frame_t *fr) {
    kdb_msg_t m;
    char why[KDB_REASON_LEN];
    kdb_rc_t rc = kdb_decode(fr, KDB_VIEWS_ANY, &m, why, sizeof(why));
    if (rc != KDB_OK) {
        lg(LOG_ERR, "protocol error from the Backend: %s", why);
        io->failed = true;
        return;
    }
    switch (m.type) {
    case KDB_T_CONFIG: {
        lcfg_t nc;
        if (cfg_from_msg(&m, &nc) != 0) {
            cfg_free(&nc);
            lg(LOG_ERR, "out of memory");
            io->failed = true;
            return;
        }
        cfg_free(&io->newcfg);
        io->newcfg = nc;
        io->have_newcfg = true;
        lg(LOG_INFO, "CONFIG generation %llu: driver %s, %zu view(s)", (unsigned long long)nc.generation, nc.driver,
           nc.nviews);
        break;
    }
    case KDB_T_INVENTORY: {
        kdb_iter_t it;
        kdb_inventory_entry_t e;
        kdb_inventory_entries(&m, &it);
        while (kdb_inventory_entries_next(&it, &e)) {
            io->inv_entries++;
            int slot = io->idx_slot ? io->idx_slot[e.view] : -1;
            if (slot < 0) continue;                  /* a view that is not in the current CONFIG */
            inv_ent_t *ie = inv_get(&io->inv, (uint16_t)slot, e.name);
            if (!ie) {
                lg(LOG_ERR, "out of memory");
                io->failed = true;
                return;
            }
            ie->known = true;
            ie->dirty = false;
            ie->has_pend = false;
            ie->source_id = e.source_id;
            ie->serial = e.serial;
            memcpy(ie->digest, e.digest, KDB_DIGEST_LEN);
        }
        break;
    }
    case KDB_T_INVENTORY_END:
        io->inv_end = true;
        io->inv_seq = m.u.inventory_end.last_change_seq;
        break;
    case KDB_T_ZONE_RESULT: {
        io->n_results++;
        int zslot = io->idx_slot ? io->idx_slot[m.u.zone_result.view] : -1;
        inv_ent_t *ie = zslot >= 0 ? inv_find(&io->inv, (uint16_t)zslot, m.u.zone_result.name) : NULL;
        if (ie) {
            switch (m.u.zone_result.status) {
            case KDB_ST_APPLIED:
            case KDB_ST_SHADOWED:                    /* the Backend has the version that was sent */
                if (ie->has_pend) {
                    ie->source_id = ie->p_source_id;
                    ie->serial = ie->p_serial;
                    memcpy(ie->digest, ie->p_digest, KDB_DIGEST_LEN);
                    ie->known = true;
                    ie->has_pend = false;
                }
                ie->dirty = false;
                break;
            case KDB_ST_REJECTED:                    /* its last version stays; offer the zone again at the next load */
                ie->has_pend = false;
                if (ie->known) ie->dirty = true;
                else inv_del(&io->inv, ie);
                break;
            default:                                 /* deleted (or unknown to the Backend): nothing to remember */
                inv_del(&io->inv, ie);
                break;
            }
        }
        if (m.u.zone_result.status == KDB_ST_REJECTED) {
            io->n_rejected++;
            if (!io->first_reject[0] && m.u.zone_result.reason.p)
                snprintf(io->first_reject, sizeof(io->first_reject), "%.*s", (int)m.u.zone_result.reason.len,
                         m.u.zone_result.reason.p);
            if (io->n_rejected <= 8)   /* the Backend logs every rejection too; a few here keep the story in one place */
                lg(LOG_WARNING, "the Backend rejected zone '%s' (view %u): %.*s", m.u.zone_result.name,
                   (unsigned)m.u.zone_result.view, (int)m.u.zone_result.reason.len,
                   m.u.zone_result.reason.p ? m.u.zone_result.reason.p : "");
        } else if (m.u.zone_result.status == KDB_ST_SHADOWED) {
            io->n_shadowed++;
            if (io->n_shadowed <= 8)
                lg(LOG_NOTICE, "zone '%s' (view %u) is hidden by a zone in karidns.conf", m.u.zone_result.name,
                   (unsigned)m.u.zone_result.view);
        }
        break;
    }
    case KDB_T_BATCH_RESULT:
        io->batch_results++;
        lg(LOG_INFO, "Backend result for batch %llu: %u applied, %u unchanged, %u rejected, %u deleted%s%s "
                     "(%llu zone result(s), %llu hidden by karidns.conf)",
           (unsigned long long)m.u.batch_result.batch_id, m.u.batch_result.n_applied, m.u.batch_result.n_unchanged,
           m.u.batch_result.n_rejected, m.u.batch_result.n_deleted, io->first_reject[0] ? "; first reason: " : "",
           io->first_reject, (unsigned long long)io->n_results, (unsigned long long)io->n_shadowed);
        break;
    case KDB_T_RELOAD_REQ:
        /* scope all: a diff of every source against the inventory; one zone: that zone (design 5.2).  The queue holds
         * LREQ_MAX requests (the Backend parks at most 32 clients); a request beyond it becomes a full diff. */
        if (m.u.reload_req.scope == 0 || io->nreq >= LREQ_MAX) {
            io->reload_all = true;
            io->all_req_id = m.u.reload_req.request_id;
        } else {
            lreq_t *r = &io->req[io->nreq++];
            r->id = m.u.reload_req.request_id;
            r->view = m.u.reload_req.view;
            r->force = m.u.reload_req.force != 0;
            snprintf(r->zone, sizeof(r->zone), "%s", m.u.reload_req.zone);
        }
        break;
    default:
        break;
    }
}

/* Read what is there and act on it.  Sets io->eof / io->failed. */
static void io_pump(struct lio *io) {
    for (;;) {
        ssize_t n = read(io->fd, io->rbuf, sizeof(io->rbuf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            lg(LOG_ERR, "cannot read the stream: %s", strerror(errno));
            io->failed = true;
            return;
        }
        if (n == 0) {
            io->eof = true;
            return;
        }
        if (kdb_framer_feed(&io->fr, io->rbuf, (size_t)n) != KDB_OK) {
            lg(LOG_ERR, "protocol error from the Backend: %s", io->fr.reason);
            io->failed = true;
            return;
        }
        kdb_frame_t fr;
        for (;;) {
            kdb_rc_t rc = kdb_framer_next(&io->fr, &fr);
            if (rc == KDB_MORE) break;
            if (rc != KDB_OK) {
                lg(LOG_ERR, "protocol error from the Backend: %s", io->fr.reason);
                io->failed = true;
                return;
            }
            io_dispatch(io, &fr);
            if (io->failed) return;
        }
    }
}

/* Write the whole buffer to the socket (short writes, EINTR).  While the socket is full, read what the Backend
 * sent: it answers every zone, and a Backend that cannot get rid of its answers must not be waited for. */
static int stream_write(ctx_t *x, const uint8_t *msg, size_t len) {
    struct lio *io = x->io;
    while (len > 0) {
        if (g_stop) {
            errno = EINTR;
            return -1;
        }
        ssize_t n = write(io->fd, msg, len);
        if (n > 0) {
            msg += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd p = { io->fd, POLLIN | POLLOUT, 0 };
            int r = poll(&p, 1, 1000);
            if (r < 0 && errno != EINTR) return -1;
            if (r > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR))) {
                io_pump(io);
                if (io->eof || io->failed) {
                    errno = EPIPE;
                    return -1;
                }
            }
            continue;
        }
        return -1;
    }
    return 0;
}

/* Wait until *flag is set.  0, or -1 when the loader is told to stop or the stream is gone. */
static int io_wait_for(struct lio *io, const bool *flag) {
    while (!*flag) {
        if (g_stop) return -1;
        if (io->eof || io->failed) return -1;
        struct pollfd p = { io->fd, POLLIN, 0 };
        int r = poll(&p, 1, 1000);
        if (r < 0 && errno != EINTR) return -1;
        if (r > 0) io_pump(io);
    }
    return 0;
}

static void drivers_csv(char *out, size_t cap) {
    out[0] = '\0';
    for (size_t i = 0; k_drivers[i]; i++) {
        size_t l = strlen(out);
        snprintf(out + l, cap - l, "%s%s", i ? "," : "", k_drivers[i]->name);
    }
}

/* Wait until every BATCH_END sent has been answered with a BATCH_RESULT: the inventory is only right after the Backend
 * has said what it did with the zones.  0, or -1 when the loader is told to stop or the stream is gone. */
static int io_wait_results(struct lio *io) {
    while (io->batch_results < io->batches_ended) {
        if (g_stop) return -1;
        if (io->eof || io->failed) return -1;
        struct pollfd p = { io->fd, POLLIN, 0 };
        int r = poll(&p, 1, 1000);
        if (r < 0 && errno != EINTR) return -1;
        if (r > 0) io_pump(io);
    }
    return 0;
}

/* view indexes -> slots of the inventory, for the CONFIG now in io->cfg.  false: out of memory */
static bool adopt_views(struct lio *io) {
    if (!io->idx_slot) {
        io->idx_slot = malloc(IDX_SLOTS * sizeof(int32_t));
        if (!io->idx_slot) return false;
    }
    for (size_t i = 0; i < IDX_SLOTS; i++) io->idx_slot[i] = -1;
    for (size_t i = 0; i < io->cfg.nviews; i++) {
        int s = vslot_get(io, io->cfg.views[i].name);
        if (s < 0) return false;
        io->idx_slot[io->cfg.views[i].index] = s;
    }
    return true;
}

static const char *batch_kind_name(uint8_t kind) {
    static const char *const n[] = { "startup", "full", "diff", "zone", "auto" };
    return kind < 5 ? n[kind] : "?";
}

/* ZONE_FAILED for a zone named in a one-zone request whose source could not be read: the request is answered with the
 * reason (the zone itself is not necessarily in the database) */
static int send_request_failure(ctx_t *x, uint16_t view, const char *zone, const char *reason) {
    char why[260];
    clean_reason(reason, why, sizeof(why));
    if (send_simple_header(x) != 0) return -1;
    x->n_failed++;
    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_FAILED) != 0 || kdb_enc_u16(&x->enc, 1, view) != 0 ||
        kdb_enc_name(&x->enc, 2, zone) != 0 || kdb_enc_i64(&x->enc, 3, 0) != 0 || kdb_enc_str(&x->enc, 4, why) != 0 ||
        kdb_enc_end(&x->enc) != 0)
        return -1;
    return send_enc(x);
}

/* One batch: the difference between the databases and the Backend's inventory, for every view (only_view >= 0: for that
 * view; only_zone: for that zone, read whatever its serial; req_id: the RELOAD_REQ the batch answers; force: send even
 * a version the Backend has; reconcile: read every zone and let the digest decide).  The batch is sent when something
 * is, or when it answers a request, or when it is the startup batch of a successful load.  0 = done, 1 = some view
 * could not be read (logged; the caller retries), -1 = fatal (stream, memory, stop). */
static int do_load(ctx_t *x, struct lio *io, uint8_t kind, int only_view, const char *only_zone, uint64_t req_id,
                   bool force, bool reconcile) {
    const lcfg_t *c = &io->cfg;
    const db_driver_t *drv = driver_find(c->driver);
    if (!drv) return -1;
    x->drv = drv;
    x->batch_id = ++io->batch_seq;
    x->batch_kind = kind;
    x->change_seq = 0;
    x->batch_open = false;
    x->req_id = req_id;
    x->force = force;
    x->reconcile = reconcile;
    x->bulk_threshold = c->bulk_threshold;
    x->nthreads = c->loader_threads >= 1 && c->loader_threads <= 16 ? c->loader_threads : 1;
    x->map_logged = false;
    x->n_zones = x->n_failed = x->n_unwritten = 0;
    x->n_unchanged = x->n_deleted = x->n_read = 0;
    io->n_results = io->n_rejected = io->n_shadowed = 0;
    io->first_reject[0] = '\0';
    int errs = 0;
    bool seen_view = false;
    bool sqlite = strcmp(drv->name, "sqlite3") == 0;
    for (size_t i = 0; i < c->nviews; i++) {
        const lview_t *v = &c->views[i];
        if (only_view >= 0 && v->index != only_view) continue;
        seen_view = true;
        int slot = vslot_get(io, v->name);
        if (slot < 0) {
            lg(LOG_ERR, "out of memory");
            return -1;
        }
        x->vslot = (uint16_t)slot;
        x->view = v->index;
        memset(&x->opts, 0, sizeof(x->opts));
        x->opts.default_ttl = c->default_ttl;
        x->opts.max_records = v->max_records;
        x->opts.max_zone_bytes = v->max_bytes;
        x->errtext[0] = '\0';
        x->map_view = v->shared ? v->name : NULL;      /* karidns_domain_views decides which zones of the shared source are this view's */
        db_source_t src = { drv->name, sqlite ? v->source : NULL, v->conninfo, sqlite ? NULL : v->source, 0 };
        int st = run_view(x, &src, only_zone, false);
        if (x->io_error || x->oom || g_stop) {
            ctx_view_reset(x);
            return -1;
        }
        if (st == EXIT_ERROR || st == EXIT_RETRY) {
            lg(LOG_ERR, "view '%s' could not be read", v->name);
            errs++;
            if (only_zone && send_request_failure(x, v->index, only_zone, x->errtext[0] ? x->errtext : "the database could not be read") != 0)
                x->io_error = true;
        }
    }
    ctx_view_reset(x);
    x->map_view = NULL;
    if (x->io_error) return -1;
    if (only_zone && !seen_view && send_request_failure(x, (uint16_t)only_view, only_zone, "the view takes no zones from the database") != 0)
        return -1;
    if (!x->batch_open && (req_id || (errs == 0 && (kind == KDB_BATCH_STARTUP || kind == KDB_BATCH_DIFF)))) {
        if (send_simple_header(x) != 0) {          /* an empty batch still tells the Backend the load is complete */
            lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
            return -1;
        }
    }
    if (x->batch_open) {
        x->batch_open = false;
        if (send_batch_end(x) != 0) {
            lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
            return -1;
        }
        io->batches_ended++;
        lg(LOG_INFO, "batch %llu (%s) sent: %u zone(s) read, %u sent, %u failed in the loader, %u deleted, %u unchanged%s",
           (unsigned long long)x->batch_id, batch_kind_name(kind), x->n_read, x->n_zones, x->n_failed, x->n_deleted,
           x->n_unchanged, req_id ? " (answers a request)" : "");
        if (io_wait_results(io) != 0) return -1;
    }
    return errs ? 1 : 0;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int run_stream(int fd) {
    struct lio *io = calloc(1, sizeof(*io));
    uint8_t *body = malloc(KDB_MAX_BODY);
    if (!io || !body) {
        lg(LOG_ERR, "out of memory");
        return EXIT_ERROR;
    }
    io->fd = fd;
    io->body = body;
    kdb_framer_init(&io->fr, KDB_FROM_BACKEND, body, KDB_MAX_BODY);
    ctx_t x;
    memset(&x, 0, sizeof(x));
    x.io = io;
    kdb_enc_init(&x.enc);
    int status = EXIT_OK;
    char drvs[128];
    drivers_csv(drvs, sizeof(drvs));

    /* HELLO -> CONFIG -> INVENTORY_REQ -> INVENTORY ... INVENTORY_END (design 1.4) */
    if (send_hello(&x, drvs, (uint32_t)getpid()) != 0) {
        status = g_stop ? EXIT_OK : EXIT_ERROR;
        goto done;
    }
    lg(LOG_INFO, "karidns-dbloader %s: HELLO sent (drivers: %s)", KARIDNS_VERSION, drvs);
    if (io_wait_for(io, &io->have_newcfg) != 0) goto stopped;
    cfg_free(&io->cfg);
    io->cfg = io->newcfg;
    memset(&io->newcfg, 0, sizeof(io->newcfg));
    io->have_cfg = true;
    io->have_newcfg = false;
    if (!adopt_views(io)) {
        lg(LOG_ERR, "out of memory");
        status = EXIT_ERROR;
        goto done;
    }
    if (!driver_find(io->cfg.driver)) {
        lg(LOG_ERR, "driver %s is not compiled into this loader (compiled in: %s)", io->cfg.driver, drvs);
        status = EXIT_ERROR;
        goto done;
    }
    if (kdb_enc_begin(&x.enc, KDB_T_INVENTORY_REQ) != 0 || kdb_enc_end(&x.enc) != 0 || send_enc(&x) != 0) goto stopped;
    if (io_wait_for(io, &io->inv_end) != 0) goto stopped;
    lg(LOG_INFO, "inventory received: %llu zone(s) at the Backend", (unsigned long long)io->inv_entries);

    bool startup_done = false, retry_pending = false;
    int64_t retry_at = 0;
    unsigned backoff = 1;
    bool need_load = true;                     /* the startup batch */
    bool reconcile = true;                     /* the first load compares every zone with the inventory (digest) */
    while (!g_stop) {
        if (io->failed) {
            status = EXIT_ERROR;
            goto done;
        }
        if (io->eof) goto stopped;
        if (io->have_newcfg) {                 /* a reload of karidns.conf: read again only if the sources changed */
            bool diff = !cfg_load_equal(&io->cfg, &io->newcfg);
            cfg_free(&io->cfg);
            io->cfg = io->newcfg;
            memset(&io->newcfg, 0, sizeof(io->newcfg));
            io->have_newcfg = false;
            if (!adopt_views(io)) {
                lg(LOG_ERR, "out of memory");
                status = EXIT_ERROR;
                goto done;
            }
            if (diff) {
                lg(LOG_NOTICE, "the database sources changed; comparing every zone with the Backend's");
                need_load = true;
                reconcile = true;
            }
        }
        uint64_t load_req = 0;
        if (io->reload_all) {                  /* karictl reload: a diff of every source (one-zone requests stay queued) */
            io->reload_all = false;
            load_req = io->all_req_id;
            io->all_req_id = 0;
            need_load = true;
        }
        if (retry_pending && now_ms() >= retry_at) {
            retry_pending = false;
            need_load = true;
        }
        if (need_load) {
            need_load = false;
            int rc = do_load(&x, io, startup_done ? KDB_BATCH_DIFF : KDB_BATCH_STARTUP, -1, NULL, load_req, false, reconcile);
            if (rc < 0) {
                if (g_stop) goto stopped;
                status = EXIT_ERROR;
                goto done;
            }
            if (rc == 0) {
                startup_done = true;
                reconcile = false;
                backoff = 1;
            } else {                           /* a database error: retry with backoff, do not crash (design 1.2) */
                retry_pending = true;
                retry_at = now_ms() + (int64_t)backoff * 1000;
                lg(LOG_WARNING, "retrying in %u s", backoff);
                if (backoff < 30) backoff *= 2;
            }
        }
        for (size_t i = 0; i < io->nreq && !g_stop; i++) {
            lreq_t r = io->req[i];
            if (do_load(&x, io, KDB_BATCH_ZONE, r.view, r.zone, r.id, r.force, false) < 0) {
                if (g_stop) goto stopped;
                status = EXIT_ERROR;
                goto done;
            }
        }
        io->nreq = 0;
        int timeout = 1000;
        if (retry_pending) {
            int64_t left = retry_at - now_ms();
            if (left < 0) left = 0;
            if (left < timeout) timeout = (int)left;
        }
        struct pollfd p = { io->fd, POLLIN, 0 };
        int r = poll(&p, 1, timeout);
        if (r < 0 && errno != EINTR) {
            lg(LOG_ERR, "poll: %s", strerror(errno));
            status = EXIT_ERROR;
            goto done;
        }
        if (r > 0) io_pump(io);
    }
stopped:
    if (g_stop) lg(LOG_NOTICE, "stopping on a signal");
    else if (io->eof) lg(LOG_NOTICE, "the Backend closed the stream; exiting");
    else if (io->failed) status = EXIT_ERROR;
done:
    ctx_view_reset(&x);
    kdb_enc_free(&x.enc);
    cfg_free(&io->cfg);
    cfg_free(&io->newcfg);
    io_free_views(io);
    free(body);
    free(io);
    return status;
}

static int stream_main(int fd) {
    /* Check the stream before anything opens a descriptor of its own: openlog(LOG_NDELAY) takes the lowest free
     * number, so with an unused fd the log socket itself would pass a later "is it a socket" test. The supervisor's
     * stream is a SOCK_STREAM socketpair (design 1.2); the log socket is a datagram socket. */
    struct stat st;
    int stype = 0;
    socklen_t slen = sizeof(stype);
    if (fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode) ||
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &stype, &slen) != 0 || stype != SOCK_STREAM) {
        fprintf(stderr, "karidns-dbloader: file descriptor %d is not a stream socket\n", fd);
        return EXIT_USAGE;
    }
    g_stream_mode = true;
    openlog("karidns-dbloader", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_term;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);          /* no SA_RESTART: a signal interrupts poll() / write() */
    sigaction(SIGINT, &sa, NULL);
    /* The supervisor starts us with these ignored, so that a "pkill -HUP karidns" cannot kill a loader that has not
     * got here yet.  Reload requests come from the Backend as RELOAD_REQ, never as a signal. */
    signal(SIGHUP, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
        lg(LOG_ERR, "cannot set the stream non-blocking: %s", strerror(errno));
        return EXIT_ERROR;
    }
    return run_stream(fd);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* command line                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static void usage(FILE *fp) {
    char drv[128];
    drivers_list(drv, sizeof(drv));
    fprintf(fp,
        "karidns-dbloader %s - reads PowerDNS 5.1 tables and writes the KDB1 zone stream of the KariDNS Backend\n"
        "\n"
        "usage:\n"
        "  karidns-dbloader --dump OUT --driver DRIVER --database-file PATH [options]\n"
        "  karidns-dbloader -s FD                    (stream mode; started by karidns, not by hand)\n"
        "  karidns-dbloader --drivers                (print the compiled-in drivers, one per line)\n"
        "\n"
        "Dump mode writes the stream exactly as the loader sends it to the Backend: HELLO, BATCH_BEGIN (startup), per\n"
        "zone ZONE_BEGIN / ZONE_DATA... / ZONE_END (or ZONE_FAILED with the reason), BATCH_END.  Zones come in\n"
        "domains.id order, so two runs on the same database write the same bytes (the HELLO carries pid 0).\n"
        "Stream mode (-s FD) is what karidns runs: FD is a socket to the Backend.  The loader sends HELLO, waits for the\n"
        "CONFIG of the Backend (databases, limits) and its inventory (the zones it has), then sends the startup batch: it\n"
        "reads every zone, and sends those the Backend does not have or has in another version (same digest = not sent).\n"
        "On RELOAD_REQ (karictl reload) it compares the databases with the inventory (new zones, other serial, zones listed\n"
        "in the change log table karidns_changes, zones the Backend refused; ZONE_DELETE for zones that left the database),\n"
        "or reads one zone (karictl reload ZONE [force]); a change of the configured sources compares everything again.\n"
        "It logs to syslog and ends when the Backend closes the stream or on SIGTERM / SIGINT; SIGHUP is ignored.\n"
        "\n"
        "options:\n"
        "  --dump OUT          write the stream to the file OUT (\"-\" = standard output)\n"
        "  --driver DRIVER     database driver; compiled in: %s\n"
        "  --database-file F   sqlite3: the database file; it must be in WAL mode.  The name is used byte for byte\n"
        "                      ('%%XX' is not decoded); a name starting with \"file:\" is refused (write ./file:...)\n"
        "  --view-index N      view index in ZONE_BEGIN / ZONE_FAILED (0..65535, default 0)\n"
        "  --zone NAME         dump only this zone (read with one query per zone instead of the bulk scan)\n"
        "  --default-ttl N     TTL for a records.ttl that is NULL (1..2147483647, default 3600)\n"
        "  --loader-threads N  1..16, default 1.  N workers, each with its own connection, read and convert disjoint sets of\n"
        "                      zones; the output is written in domains.id order whatever N is, so the bytes are the same\n"
        "  --map-view NAME     keep only the zones karidns_domain_views maps to the view NAME (a domain without a row is kept):\n"
        "                      what a view that uses the shared source of a server gets (docs/karidns.md)\n"
        "  --version           print the version\n"
        "  -h, --help          this text\n"
        "\n"
        "exit status:\n"
        "  0  every zone was written\n"
        "  1  the stream is complete but some zones went out as ZONE_FAILED (reason on stderr)\n"
        "  2  usage error (nothing was read)\n"
        "  3  error: database, schema, output or memory; the output file is removed\n"
        "  4  transient database error (busy); try again\n"
        "\n"
        "examples:\n"
        "  karidns-dbloader --dump /tmp/zones.kdb --driver sqlite3 --database-file /var/db/karidns/zones.sqlite3\n"
        "  karidns-dbloader --dump - --driver sqlite3 --database-file zones.sqlite3 --zone example.test | od -c | head\n"
        "  karidns-dbloader --dump /tmp/view1.kdb --driver sqlite3 --database-file view1.sqlite3 --view-index 1 --default-ttl 300\n",
        KARIDNS_VERSION, drv);
}

static bool parse_uint(const char *s, unsigned long min, unsigned long max, unsigned long *out) {
    char *end;
    if (!*s || *s == '-' || *s == '+') return false;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end || v < min || v > max) return false;
    *out = v;
    return true;
}

int main(int argc, char **argv) {
    static const struct option longopts[] = {
        { "dump", required_argument, NULL, 'd' },          { "driver", required_argument, NULL, 'D' },
        { "database-file", required_argument, NULL, 'f' }, { "conninfo-file", required_argument, NULL, 'c' },
        { "schema", required_argument, NULL, 'S' },        { "view-index", required_argument, NULL, 'v' },
        { "zone", required_argument, NULL, 'z' },          { "default-ttl", required_argument, NULL, 't' },
        { "loader-threads", required_argument, NULL, 'j' }, { "version", no_argument, NULL, 'V' },
        { "drivers", no_argument, NULL, 'L' },             { "map-view", required_argument, NULL, 'm' },
        { "help", no_argument, NULL, 'h' },                { NULL, 0, NULL, 0 }
    };
    const char *dump = NULL, *driver = NULL, *dbfile = NULL, *conninfo = NULL, *schema = NULL, *zone = NULL, *map_view = NULL;
    const char *stream_fd = NULL;
    unsigned long view = 0, ttl = 0, threads = 1, v;
    int ch;
    while ((ch = getopt_long(argc, argv, "hs:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'd': dump = optarg; break;
        case 'D': driver = optarg; break;
        case 'f': dbfile = optarg; break;
        case 'c': conninfo = optarg; break;
        case 'S': schema = optarg; break;
        case 's': stream_fd = optarg; break;
        case 'z': zone = optarg; break;
        case 'm': map_view = optarg; break;
        case 'v':
            if (!parse_uint(optarg, 0, 65535, &view)) {
                fprintf(stderr, "karidns-dbloader: --view-index must be 0..65535\n");
                return EXIT_USAGE;
            }
            break;
        case 't':
            if (!parse_uint(optarg, 1, PDNS_MAX_TTL, &ttl)) {
                fprintf(stderr, "karidns-dbloader: --default-ttl must be 1..%u\n", PDNS_MAX_TTL);
                return EXIT_USAGE;
            }
            break;
        case 'j':
            if (!parse_uint(optarg, 1, 16, &threads)) {
                fprintf(stderr, "karidns-dbloader: --loader-threads must be 1..16\n");
                return EXIT_USAGE;
            }
            break;
        case 'L':
            for (size_t i = 0; k_drivers[i]; i++) printf("%s\n", k_drivers[i]->name);
            return EXIT_OK;
        case 'V': printf("karidns-dbloader %s\n", KARIDNS_VERSION); return EXIT_OK;
        case 'h': usage(stdout); return EXIT_OK;
        default: usage(stderr); return EXIT_USAGE;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "karidns-dbloader: unexpected argument '%s'\n", argv[optind]);
        usage(stderr);
        return EXIT_USAGE;
    }
    if (stream_fd) {
        if (!parse_uint(stream_fd, 0, 1u << 20, &v)) {
            fprintf(stderr, "karidns-dbloader: -s needs a file descriptor number\n");
            return EXIT_USAGE;
        }
        if (dump || driver || dbfile || conninfo || schema || zone || map_view) {
            fprintf(stderr, "karidns-dbloader: -s cannot be combined with the dump options\n");
            return EXIT_USAGE;
        }
        return stream_main((int)v);
    }
    if (!dump || !driver) {
        fprintf(stderr, "karidns-dbloader: --dump and --driver are required\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    const db_driver_t *drv = driver_find(driver);
    if (!drv) {
        char list[128];
        drivers_list(list, sizeof(list));
        if (strcmp(driver, "postgresql") == 0 || strcmp(driver, "sqlite3") == 0)
            fprintf(stderr, "karidns-dbloader: driver %s is not available in this build (%s; compiled in: %s)\n", driver,
                    strcmp(driver, "postgresql") == 0 ? "the PostgreSQL driver comes with milestone B10" : "built without DB_DRIVERS=sqlite3",
                    list);
        else
            fprintf(stderr, "karidns-dbloader: unknown driver '%s' (compiled in: %s)\n", driver, list);
        return EXIT_USAGE;
    }
    if (strcmp(drv->name, "sqlite3") == 0 && !dbfile) {
        fprintf(stderr, "karidns-dbloader: driver sqlite3 needs --database-file\n");
        return EXIT_USAGE;
    }
    if (strcmp(drv->name, "sqlite3") == 0 && (conninfo || schema)) {
        fprintf(stderr, "karidns-dbloader: --conninfo-file and --schema are for the postgresql driver\n");
        return EXIT_USAGE;
    }

    ctx_t x;
    memset(&x, 0, sizeof(x));
    x.drv = drv;
    x.view = (uint16_t)view;
    x.opts.default_ttl = (uint32_t)ttl;
    x.nthreads = (uint32_t)threads;
    x.map_view = map_view;
    kdb_enc_init(&x.enc);
    bool to_stdout = strcmp(dump, "-") == 0;
    x.out = to_stdout ? stdout : fopen(dump, "wb");
    if (!x.out) {
        fprintf(stderr, "karidns-dbloader: cannot create %s: %s\n", dump, strerror(errno));
        return EXIT_ERROR;
    }
    db_source_t src = { drv->name, dbfile, conninfo, schema, 0 };
    int status = run_dump(&x, &src, zone);
    if (x.out && (fflush(x.out) != 0 || ferror(x.out)) && status < EXIT_ERROR) {
        fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
        status = EXIT_ERROR;
    }
    if (!to_stdout && fclose(x.out) != 0 && status < EXIT_ERROR) {
        fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
        status = EXIT_ERROR;
    }
    if (status >= EXIT_ERROR && !to_stdout) unlink(dump);
    ctx_view_reset(&x);
    kdb_enc_free(&x.enc);
    return status;
}

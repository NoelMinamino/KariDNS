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
#include <fcntl.h>
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

typedef struct { int64_t id; char *name; char *type; } zinfo_t;
typedef struct { int64_t domain_id; char *kind; char *content; } meta_t;

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
    /* metadata (sorted by domain_id) and zones with cryptokeys */
    meta_t *meta;
    size_t nm, mcap, mi;
    int64_t *keys;
    size_t nk, kcap;
    /* the zone being collected */
    size_t zi;
    pdns_zone_t *cur;
    bool cur_open;
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
} ctx_t;

static int stream_write(ctx_t *x, const uint8_t *msg, size_t len);

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

static int zone_cb(void *ud, const db_zone_row_t *r) {
    ctx_t *x = ud;
    if (x->nz >= x->zcap) {
        size_t nc = x->zcap ? x->zcap * 2 : 256;
        zinfo_t *nzs = realloc(x->zones, nc * sizeof(*nzs));
        if (!nzs) return x->oom = true;
        x->zones = nzs;
        x->zcap = nc;
    }
    zinfo_t *z = &x->zones[x->nz];
    z->id = r->id;
    z->name = r->name ? strdup(r->name) : NULL;
    z->type = r->type ? strdup(r->type) : NULL;
    if ((r->name && !z->name) || (r->type && !z->type)) {
        free(z->name);
        free(z->type);
        return x->oom = true;
    }
    x->nz++;
    return 0;
}

static int meta_cb(void *ud, const db_meta_row_t *r) {
    ctx_t *x = ud;
    if (x->nm >= x->mcap) {
        size_t nc = x->mcap ? x->mcap * 2 : 256;
        meta_t *nms = realloc(x->meta, nc * sizeof(*nms));
        if (!nms) return x->oom = true;
        x->meta = nms;
        x->mcap = nc;
    }
    meta_t *m = &x->meta[x->nm];
    m->domain_id = r->domain_id;
    m->kind = r->kind ? strdup(r->kind) : NULL;
    m->content = r->content ? strdup(r->content) : NULL;
    if ((r->kind && !m->kind) || (r->content && !m->content)) {
        free(m->kind);
        free(m->content);
        return x->oom = true;
    }
    x->nm++;
    return 0;
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

/* The canonical absolute name for a ZONE_FAILED message (the Backend refuses anything else).  false: the name
 * cannot be written as a zone name; the failure is then only reported on stderr. */
static bool canonical_name(const char *dbname, char out[DNS_NAME_TEXT_SIZE]) {
    if (!dbname) return false;
    pdns_zone_t *z = pdns_zone_new(dbname, NULL);
    if (!z) return false;
    bool ok = !z->failed;
    if (ok) snprintf(out, DNS_NAME_TEXT_SIZE, "%s", z->name);
    pdns_zone_free(z);
    return ok;
}

static int send_failed(ctx_t *x, const zinfo_t *zi, const char *reason) {
    char name[DNS_NAME_TEXT_SIZE], why[260], shown[210];
    clean_reason(zi->name ? zi->name : "(NULL)", shown, sizeof(shown));
    lg(LOG_ERR, "zone '%s' (domains.id %lld): %s", shown, (long long)zi->id, reason);
    if (!canonical_name(zi->name, name)) {
        lg(LOG_ERR, "the zone name is not a valid domain name; not written to the stream");
        x->n_unwritten++;
        return 0;
    }
    x->n_failed++;
    clean_reason(reason, why, sizeof(why));
    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_FAILED) != 0 || kdb_enc_u16(&x->enc, 1, x->view) != 0 ||
        kdb_enc_name(&x->enc, 2, name) != 0 || kdb_enc_i64(&x->enc, 3, zi->id) != 0 || kdb_enc_str(&x->enc, 4, why) != 0 ||
        kdb_enc_end(&x->enc) != 0)
        return -1;
    return send_enc(x);
}

typedef struct { ctx_t *x; bool started; } zemit_t;

static int zone_emit(void *ud, const uint8_t *msg, size_t len) {
    zemit_t *e = ud;
    e->started = true;
    return emit_file(e->x, msg, len);
}

static const char *zone_type_reason(const char *type) {
    if (!type) return "domains.type is NULL";
    if (strcasecmp(type, "NATIVE") == 0 || strcasecmp(type, "MASTER") == 0) return NULL;
    if (strcasecmp(type, "SLAVE") == 0 || strcasecmp(type, "CONSUMER") == 0)
        return "secondary zones (type SLAVE / CONSUMER) are not loaded yet (milestone B7)";
    if (strcasecmp(type, "PRODUCER") == 0) return "catalog producer zones (type PRODUCER) are not loaded yet (later 0.6.x)";
    return "unsupported domains.type";
}

static void open_current(ctx_t *x) {
    if (x->cur_open) return;
    x->cur_open = true;
    x->cur = NULL;
    const zinfo_t *zi = &x->zones[x->zi];
    if (zi->name && !zone_type_reason(zi->type)) x->cur = pdns_zone_new(zi->name, &x->opts);
    if (zi->name && !zone_type_reason(zi->type) && !x->cur) x->oom = true;
}

/* convert and write the zone x->zi; 0, or -1 on a fatal error (output, memory) */
static int finish_current(ctx_t *x) {
    open_current(x);
    const zinfo_t *zi = &x->zones[x->zi];
    pdns_zone_t *z = x->cur;
    int ret = 0;
    const char *tr = zone_type_reason(zi->type);
    char msg[PDNS_ERR_LEN + 100];

    if (x->oom) return -1;
    if (!zi->name) {
        ret = send_failed(x, zi, "domains.name is NULL");
    } else if (tr) {
        ret = send_failed(x, zi, tr);
    } else {
        /* metadata of this zone (sorted by domain_id) */
        while (x->mi < x->nm && x->meta[x->mi].domain_id < zi->id) x->mi++;
        for (; !z->failed && x->mi < x->nm && x->meta[x->mi].domain_id == zi->id; x->mi++) {
            db_meta_row_t m = { zi->id, x->meta[x->mi].kind, x->meta[x->mi].content };
            pdns_zone_add_meta(z, &m);
        }
        const char *why = NULL;
        if (pdns_zone_finish(z) != 0) {
            why = z->error;
        } else if (zone_has_keys(x, zi->id) && !(z->flags & PDNS_F_PRESIGNED)) {
            /* design 3.5: PowerDNS would sign the zone online, KariDNS serves pre-signed data only */
            why = "the zone has cryptokeys but no PRESIGNED=1 metadata (online signing is not supported)";
        }
        for (size_t i = 0; i < z->n_warnings; i++)
            lg(LOG_WARNING, "warning: %s", z->warnings[i]);
        if (why) {
            ret = send_failed(x, zi, why);
        } else {
            pdns_kdb_params_t p = { x->view, zi->id, KDB_ZK_PRIMARY, NULL };
            zemit_t e = { x, false };
            if (pdns_zone_encode_kdb(z, &p, zone_emit, &e, msg, sizeof(msg)) == 0) {
                x->n_zones++;
            } else if (x->io_error) {
                ret = -1;
            } else {
                if (e.started) {        /* cannot happen today (the refusals come before ZONE_BEGIN); be safe */
                    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_ABORT) != 0 || kdb_enc_str(&x->enc, 1, "encoding failed") != 0 ||
                        kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
                        ret = -1;
                }
                if (ret == 0) ret = send_failed(x, zi, msg);
            }
        }
    }
    pdns_zone_free(z);
    x->cur = NULL;
    x->cur_open = false;
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the scan                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static int rec_cb(void *ud, int64_t did, const db_record_row_t *row) {
    ctx_t *x = ud;
    while (x->zi < x->nz && x->zones[x->zi].id < did) {
        if (finish_current(x) != 0) return 1;
        x->zi++;
    }
    if (x->zi >= x->nz || x->zones[x->zi].id != did) return 0;      /* a row of a domain that is not listed: ignored */
    open_current(x);
    if (x->oom) return 1;
    if (x->cur && !x->cur->failed) pdns_zone_add_record(x->cur, row);
    return 0;
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
        kdb_enc_u8(&x->enc, 2, kind) != 0 || kdb_enc_u64(&x->enc, 3, change_seq) != 0 || kdb_enc_end(&x->enc) != 0 ||
        send_enc(x) != 0)
        return -1;
    return 0;
}

/* dump mode: HELLO and the one startup batch.  Stream mode: HELLO went out at the handshake; BATCH_BEGIN goes out
 * once, just before the first zone of the batch (an error before that leaves nothing half sent). */
static int send_simple_header(ctx_t *x) {
    if (x->io) {
        if (x->batch_open) return 0;
        x->batch_open = true;
        return send_batch_begin(x, x->batch_id, x->batch_kind, x->change_seq);
    }
    if (send_hello(x, x->drv->name, 0) != 0) return -1;
    return send_batch_begin(x, 1, KDB_BATCH_STARTUP, 0);
}

static int send_batch_end(ctx_t *x) {
    if (kdb_enc_begin(&x->enc, KDB_T_BATCH_END) != 0 || kdb_enc_u64(&x->enc, 1, x->io ? x->batch_id : 1) != 0 ||
        kdb_enc_u32(&x->enc, 2, x->n_zones) != 0 || kdb_enc_u32(&x->enc, 3, x->n_failed) != 0 ||
        kdb_enc_u32(&x->enc, 4, 0) != 0 || kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
        return -1;
    return 0;
}

static int names_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 1 && a[la - 1] == '.') la--;
    if (lb > 1 && b[lb - 1] == '.') lb--;
    return la == lb && strncasecmp(a, b, la) == 0;
}

static int db_err(ctx_t *x, int rc, const char *what) {
    lg(LOG_ERR, "%s: %s", what, x->conn ? x->drv->errmsg(x->conn) : "?");
    return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
}

/* Forget the lists of the previous view (zones, metadata, keys).  The context keeps them after a run so that the owner
 * (main(), a test) can look at them; the next run starts empty. */
static void ctx_view_reset(ctx_t *x) {
    if (x->cur_open && x->cur) pdns_zone_free(x->cur);
    x->cur = NULL;
    x->cur_open = false;
    for (size_t i = 0; i < x->nz; i++) {
        free(x->zones[i].name);
        free(x->zones[i].type);
    }
    free(x->zones);
    x->zones = NULL;
    x->nz = x->zcap = 0;
    for (size_t i = 0; i < x->nm; i++) {
        free(x->meta[i].kind);
        free(x->meta[i].content);
    }
    free(x->meta);
    x->meta = NULL;
    x->nm = x->mcap = x->mi = 0;
    free(x->keys);
    x->keys = NULL;
    x->nk = x->kcap = 0;
    x->zi = 0;
}

/* One source (one view): open, read the lists, then the records, writing the zones.  whole: the dump of a file,
 * with HELLO / BATCH_BEGIN before the first zone and BATCH_END after the last; otherwise (stream mode) the caller
 * owns the batch and calls this once per view.  Returns an exit status. */
static int run_view(ctx_t *x, const db_source_t *src, const char *only_zone, bool whole) {
    char err[DB_ERRLEN];
    ctx_view_reset(x);
    int rc = x->drv->open(&x->conn, src, err, sizeof(err));
    if (rc != 0) {
        lg(LOG_ERR, "%s", err);
        return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
    }
    int status = EXIT_OK;
    db_schema_info_t si;
    if ((rc = x->drv->check_schema(x->conn, &si)) != 0) {
        status = db_err(x, rc, "schema");
        goto out;
    }
    if ((rc = x->drv->begin_snapshot(x->conn)) != 0) {
        status = db_err(x, rc, "snapshot");
        goto out;
    }
    if ((rc = x->drv->list_zones(x->conn, zone_cb, x)) != 0) {
        status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading the zone list");
        if (x->oom) lg(LOG_ERR, "out of memory");
        goto out_snap;
    }
    if (only_zone) {        /* keep only that zone */
        size_t keep = 0;
        for (size_t i = 0; i < x->nz; i++) {
            if (x->zones[i].name && names_equal(x->zones[i].name, only_zone)) {
                if (keep != i) x->zones[keep] = x->zones[i];
                keep++;
            } else {
                free(x->zones[i].name);
                free(x->zones[i].type);
            }
        }
        x->nz = keep;
        if (!keep) {
            lg(LOG_ERR, "zone '%.200s' is not in the database", only_zone);
            status = EXIT_ERROR;
            goto out_snap;
        }
    }
    {
        const int64_t *sel = only_zone ? &x->zones[0].id : NULL;
        int64_t id0 = sel ? *sel : 0;
        if ((rc = x->drv->scan_metadata(x->conn, sel ? &id0 : NULL, meta_cb, x)) != 0 ||
            (rc = x->drv->zones_with_keys(x->conn, key_cb, x)) != 0) {
            status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading metadata");
            if (x->oom) lg(LOG_ERR, "out of memory");
            goto out_snap;
        }
        qsort(x->keys, x->nk, sizeof(int64_t), cmp_i64);

        if (send_simple_header(x) != 0) {
            lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
            status = EXIT_ERROR;
            goto out_snap;
        }
        rc = x->drv->scan_records(x->conn, sel ? &id0 : NULL, rec_cb, x);
        if (rc != 0 && rc != DB_STOPPED) {
            status = db_err(x, rc, "reading records");
            goto out_snap;
        }
        if (rc == DB_STOPPED && !x->io_error && !x->oom) {
            lg(LOG_ERR, "internal error: the scan was stopped");
            status = EXIT_ERROR;
            goto out_snap;
        }
        int fatal = rc == DB_STOPPED;
        while (!fatal && x->zi < x->nz) {
            if (finish_current(x) != 0) fatal = 1;
            x->zi++;
        }
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
out_snap:
    x->drv->end_snapshot(x->conn);
out:
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

typedef struct {
    uint16_t index;
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

typedef struct { uint64_t id; uint16_t view; char zone[DNS_NAME_TEXT_SIZE]; } lreq_t;

#define LREQ_MAX 64

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
    uint64_t inv_entries;
    lreq_t req[LREQ_MAX];
    size_t nreq;
    bool reload_all;
    uint64_t batch_seq;
    uint64_t n_results, n_rejected, n_shadowed;   /* ZONE_RESULTs of the current batch */
    char first_reject[130];
};

static volatile sig_atomic_t g_stop;
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
        if (x->index != y->index || strcmp(x->name, y->name) != 0 || !streq_n(x->source, y->source) ||
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
        while (kdb_inventory_entries_next(&it, &e)) io->inv_entries++;
        break;
    }
    case KDB_T_INVENTORY_END:
        io->inv_end = true;
        break;
    case KDB_T_ZONE_RESULT:
        io->n_results++;
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
    case KDB_T_BATCH_RESULT:
        lg(LOG_INFO, "Backend result for batch %llu: %u applied, %u unchanged, %u rejected, %u deleted%s%s "
                     "(%llu zone result(s), %llu hidden by karidns.conf)",
           (unsigned long long)m.u.batch_result.batch_id, m.u.batch_result.n_applied, m.u.batch_result.n_unchanged,
           m.u.batch_result.n_rejected, m.u.batch_result.n_deleted, io->first_reject[0] ? "; first reason: " : "",
           io->first_reject, (unsigned long long)io->n_results, (unsigned long long)io->n_shadowed);
        break;
    case KDB_T_RELOAD_REQ:
        /* scope all: send everything again (the diff against the Backend's inventory comes with B6) */
        if (m.u.reload_req.scope == 0 || io->nreq >= LREQ_MAX) {
            io->reload_all = true;
        } else {
            lreq_t *r = &io->req[io->nreq++];
            r->id = m.u.reload_req.request_id;
            r->view = m.u.reload_req.view;
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

/* One batch: the zones of every view (only_view >= 0: of that view; only_zone: of that zone).  0 = done, 1 = some
 * view could not be read (logged; the caller retries), -1 = fatal (stream, memory, stop). */
static int do_load(ctx_t *x, struct lio *io, uint8_t kind, int only_view, const char *only_zone) {
    const lcfg_t *c = &io->cfg;
    const db_driver_t *drv = driver_find(c->driver);
    if (!drv) return -1;
    x->drv = drv;
    x->batch_id = ++io->batch_seq;
    x->batch_kind = kind;
    x->change_seq = 0;
    x->batch_open = false;
    x->n_zones = x->n_failed = x->n_unwritten = 0;
    io->n_results = io->n_rejected = io->n_shadowed = 0;
    io->first_reject[0] = '\0';
    int errs = 0;
    bool sqlite = strcmp(drv->name, "sqlite3") == 0;
    for (size_t i = 0; i < c->nviews; i++) {
        const lview_t *v = &c->views[i];
        if (only_view >= 0 && v->index != only_view) continue;
        x->view = v->index;
        memset(&x->opts, 0, sizeof(x->opts));
        x->opts.default_ttl = c->default_ttl;
        x->opts.max_records = v->max_records;
        x->opts.max_zone_bytes = v->max_bytes;
        db_source_t src = { drv->name, sqlite ? v->source : NULL, v->conninfo, sqlite ? NULL : v->source, 0 };
        int st = run_view(x, &src, only_zone, false);
        if (x->io_error || x->oom || g_stop) {
            ctx_view_reset(x);
            return -1;
        }
        if (st == EXIT_ERROR || st == EXIT_RETRY) {
            lg(LOG_ERR, "view '%s' could not be read", v->name);
            errs++;
        }
    }
    ctx_view_reset(x);
    if (x->batch_open) {
        x->batch_open = false;
        if (send_batch_end(x) != 0) {
            lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
            return -1;
        }
        lg(LOG_INFO, "batch %llu sent: %u zone(s), %u failed in the loader", (unsigned long long)x->batch_id,
           x->n_zones, x->n_failed);
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
            if (diff) {
                lg(LOG_NOTICE, "the database sources changed; reading everything again");
                need_load = true;
            }
        }
        if (io->reload_all) {
            io->reload_all = false;
            io->nreq = 0;
            need_load = true;
        }
        if (retry_pending && now_ms() >= retry_at) {
            retry_pending = false;
            need_load = true;
        }
        if (need_load) {
            need_load = false;
            int rc = do_load(&x, io, startup_done ? KDB_BATCH_FULL : KDB_BATCH_STARTUP, -1, NULL);
            if (rc < 0) {
                if (g_stop) goto stopped;
                status = EXIT_ERROR;
                goto done;
            }
            if (rc == 0) {
                startup_done = true;
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
            if (do_load(&x, io, KDB_BATCH_ZONE, r.view, r.zone) < 0) {
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
        "CONFIG of the Backend (databases, limits), asks for the inventory, then sends one startup batch with every zone\n"
        "of every view, and again on RELOAD_REQ or when the configuration names other sources.  It logs to syslog and\n"
        "ends when the Backend closes the stream or on SIGTERM / SIGINT; SIGHUP is ignored.\n"
        "\n"
        "options:\n"
        "  --dump OUT          write the stream to the file OUT (\"-\" = standard output)\n"
        "  --driver DRIVER     database driver; compiled in: %s\n"
        "  --database-file F   sqlite3: the database file; it must be in WAL mode.  The name is used byte for byte\n"
        "                      ('%%XX' is not decoded); a name starting with \"file:\" is refused (write ./file:...)\n"
        "  --view-index N      view index in ZONE_BEGIN / ZONE_FAILED (0..65535, default 0)\n"
        "  --zone NAME         dump only this zone (read with one query per zone instead of the bulk scan)\n"
        "  --default-ttl N     TTL for a records.ttl that is NULL (1..2147483647, default 3600)\n"
        "  --loader-threads N  1..16, default 1.  Accepted; the dump runs on one thread (parallel workers: milestone B6)\n"
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
        { "drivers", no_argument, NULL, 'L' },
        { "help", no_argument, NULL, 'h' },                { NULL, 0, NULL, 0 }
    };
    const char *dump = NULL, *driver = NULL, *dbfile = NULL, *conninfo = NULL, *schema = NULL, *zone = NULL;
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
    (void)threads;
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
        if (dump || driver || dbfile || conninfo || schema || zone) {
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
    for (size_t i = 0; i < x.nz; i++) {
        free(x.zones[i].name);
        free(x.zones[i].type);
    }
    free(x.zones);
    for (size_t i = 0; i < x.nm; i++) {
        free(x.meta[i].kind);
        free(x.meta[i].content);
    }
    free(x.meta);
    free(x.keys);
    kdb_enc_free(&x.enc);
    return status;
}

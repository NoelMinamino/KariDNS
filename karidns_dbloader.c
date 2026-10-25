/*
 * karidns_dbloader.c - karidns-dbloader (beta design 1; milestone B3: the offline dump mode).
 *
 * Reads the PowerDNS 5.1 tables of one database through a driver (dns_db_driver.h), converts every zone with the
 * shared reader (dns_pdns_reader.h) and writes the KDB1 stream (dns_db_stream.h) the loader sends to the Backend:
 * HELLO, BATCH_BEGIN (startup), per zone ZONE_BEGIN / ZONE_DATA... / ZONE_END or ZONE_FAILED, BATCH_END.
 *
 *   karidns-dbloader --dump OUT --driver sqlite3 --database-file PATH [options]     (B3, this file)
 *   karidns-dbloader --dump OUT --driver postgresql --conninfo-file FILE [--schema NAME] [options]     (B10)
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
 *
 * Auto reload (B9, design 6): the same diff, started by the loader itself; see the block before run_stream().  B10: a driver
 * with a socket to wait on (PostgreSQL LISTEN, wait_fd()) wakes the main loop at once; the others are polled by timer.
 *
 * Multi-server operation (B11, release plan 4.8, PostgreSQL only): reload requests written to karidns_reload_requests by a
 * management tool make every server reload, and each loader writes the outcome to karidns_server_status; see the block
 * "multi-server reload requests" before auto_send_status().
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
#include <pwd.h>
#include <limits.h>

#include "dns_db_driver.h"
#include "dns_db_stream.h"
#include "dns_db_checkproto.h"
#include "dns_pdns_reader.h"
#include "dns_zone_lint.h"

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

enum { EXIT_OK = 0, EXIT_ZONES_FAILED = 1, EXIT_USAGE = 2, EXIT_ERROR = 3, EXIT_RETRY = 4 };

/* Messages.  Dump mode: stderr with the program prefix (the lines the dump tests expect).  Stream mode: syslog
 * (openlog() has LOG_PERROR, so a foreground server still shows them on stderr). */
static bool g_stream_mode;
static volatile sig_atomic_t g_stop;      /* SIGTERM / SIGINT in stream mode */

/* B12, --check: every message of the run is a line of the check protocol (dns_db_checkproto.h) on g_chk_out; g_chk_zone / g_chk_id say
 * which zone the findings are about ("" / 0: the source).  The run is single threaded. */
static FILE *g_chk_out;
static unsigned g_chk_errors, g_chk_warnings;
static char g_chk_zone[DNS_NAME_TEXT_SIZE + 16];
static int64_t g_chk_id;

/* one finding: level E W I O D, text of any bytes (cut at CHK_TEXT_MAX, escaped) */
static void chk_line(char level, const char *text) {
    char zone[4 * DNS_NAME_TEXT_SIZE + 4], body[4 * CHK_TEXT_MAX + 8];
    size_t tl = strlen(text);
    bool cut = false;
    if (level == 'E') g_chk_errors++;
    else if (level == 'W') g_chk_warnings++;
    chk_escape(g_chk_zone, strlen(g_chk_zone), zone, sizeof(zone), NULL);
    chk_escape(text, tl > CHK_TEXT_MAX ? CHK_TEXT_MAX : tl, body, sizeof(body), &cut);
    fprintf(g_chk_out, "%c\t%s\t%lld\t%s%s\n", level, zone, (long long)g_chk_id, body, tl > CHK_TEXT_MAX || cut ? "..." : "");
}

static void chk_linef(char level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void chk_linef(char level, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    chk_line(level, msg);
}

static void lg(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void lg(int prio, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (g_chk_out) chk_line(prio <= LOG_ERR ? 'E' : prio == LOG_WARNING ? 'W' : 'I', msg);
    else if (g_stream_mode) syslog(prio, "%s", msg);
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

/* per source (view name): the change log position of the last complete load, and (B9) the state of its auto reload */
#define AUTO_ERRLEN 160
typedef struct {
    uint64_t seq;
    bool seq_valid;
    bool nolog_warned;
    /* B9, auto reload: one persistent connection that only asks PRAGMA data_version (and the end of the change log);
     * the loads read through connections of their own.  Times are CLOCK_MONOTONIC milliseconds, 0 = not set. */
    const db_driver_t *pdrv;
    db_conn_t *pconn;
    bool has_changes;                    /* the database has karidns_changes (else: detection by data_version, zones compared by serial) */
    bool dv_valid;
    uint64_t dv;                         /* the last data_version seen */
    bool opened_once, nolog_auto_warned;
    bool need_full;                      /* the next auto load compares every zone (the database file was replaced) */
    int64_t next_poll, flush_at, open_retry_at;
    uint32_t pending;                    /* changes seen in the log, not applied yet */
    int64_t last_poll;                   /* wall clock seconds, 0 = never */
    char perr[AUTO_ERRLEN], lerr[AUTO_ERRLEN];   /* last poll error, last load error ("" = none) */
} vstate_t;

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
    /* B12, --check (read only, nothing is sent): the zone checks of `karicheck db`; all zero in the other modes */
    bool check;
    db_check_opts_t chk_opts;
    unsigned chk_zones;               /* zones read */
    char **chk_cat;                   /* domains.catalog of zones[i] (NULL if NULL) */
    size_t chk_ncat, chk_ccat;
    struct chk_map { int64_t did; char *view; } *chk_map;     /* the rows of karidns_domain_views, in domain_id order */
    size_t chk_nmap, chk_cmap;
    ecs_tag_def_t *chk_ecs, *chk_loc; /* names of the tag definitions of the server configuration (--ecs-tag / --location-tag): only .tag is set */
    int chk_necs, chk_nloc;
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

/* B11: the zones that failed in a load (the loader could not read or convert them, or the Backend rejected them), for the
 * failed_zones column of karidns_server_status.  Collected while fz.on; entries keep the view so that the load of several sources
 * can be split per source. */
#define FZ_MAX_ENT 256                       /* failures kept; more set `overflow` */
#define FZ_LINE 512
#define FZ_REPORT_LINES 64                   /* lines of failed_zones */
#define FZ_REPORT_BYTES 4096                 /* bytes of failed_zones (without the NUL) */
typedef struct { uint16_t view; char text[FZ_LINE]; } fz_ent_t;
typedef struct {
    bool on, overflow;
    unsigned n;
    fz_ent_t ent[FZ_MAX_ENT];
} fz_t;

/* B11: one watcher per source (schema) whose database has karidns_reload_requests; see the block before auto_send_status() */
#define RW_MAX 64                            /* sources watched */
#define RW_ZONES 64                          /* different zones of one coalesced request batch; more is a diff of the whole source */
#define RW_ERRLEN 160
#define RW_RETRY_MS 10000                    /* a status row that could not be written is tried again after this */
#define RW_ABSENT_MS 60000                   /* a source without the tables is looked at again after this */
#define RW_FD_BASE ((size_t)1 << 20)         /* pfs_slot values from here on are watchers (index = value - RW_FD_BASE) */
typedef struct {
    char *source, *conninfo;                 /* the key: the view's source (schema) and conninfo-file */
    uint16_t *views;                         /* indexes of the views that read this source (from the CONFIG) */
    size_t nv, cv;
    bool in_cfg;
    const db_driver_t *drv;
    db_conn_t *conn;
    bool absent;                             /* the source has no karidns_reload_requests (looked at again later) */
    bool seeded;                             /* `last` is valid */
    bool startup_seeded;                     /* `last` was taken before a load that follows: that load's outcome is reported */
    bool has_status;                         /* karidns_server_status exists */
    bool applied_ok;                         /* the outcome of the last reload that counted (every zone loaded) */
    uint64_t last;                           /* the highest generation applied */
    int64_t next_poll, flush_at, open_retry_at, report_retry_at;
    bool rep_pending;                        /* a status row is waiting to be written */
    uint64_t rep_gen;
    bool rep_ok;
    char *rep_text;                          /* FZ_REPORT_BYTES + 1 */
    char (*zbuf)[DNS_NAME_TEXT_SIZE];        /* RW_ZONES names of the request batch being built (allocated at the first request) */
    int64_t rep_time;                        /* wall clock seconds of the last status row written, 0 = never */
    bool listen_noted;
    char perr[RW_ERRLEN], rerr[RW_ERRLEN];   /* the last error reading requests / loading, and writing the status row ("" = none) */
} rw_t;

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
    struct pollfd *pfs;                      /* B10: poll set of the main loop: the stream, then the connections that notify (PostgreSQL LISTEN) */
    size_t *pfs_slot, cpfs;
    /* B11: multi-server reload requests */
    fz_t fz;
    rw_t rw[RW_MAX];
    size_t nrw;
    char sid[72], sid_why[100];              /* the server id the loader reports under; why it has none */
    bool sid_ok, sid_warned;
    bool status_dirty;                       /* an AUTO_STATUS is due (auto reload or reload request state changed) */
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
    for (size_t i = 0; i < io->nvn; i++) {
        if (io->vst[i].pconn) io->vst[i].pdrv->close(io->vst[i].pconn);
        free(io->vnames[i]);
    }
    free(io->vnames);
    free(io->vst);
    free(io->idx_slot);
    free(io->pfs);
    free(io->pfs_slot);
    io->pfs = NULL;
    io->pfs_slot = NULL;
    io->cpfs = 0;
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
/* B11: the zones that failed, for karidns_server_status.failed_zones                                            */
/* ------------------------------------------------------------------------------------------------------------- */

/* in[0..n) (up to a NUL) into out: printable ASCII as it is, every other byte (control characters, DEL, bytes >= 0x80: the column
 * is TEXT and must be valid in the database encoding, and a line must not contain a line end) as \DDD (decimal, like a DNS name).
 * At most cap - 1 bytes and an escape is never cut.  Returns the length. */
static size_t fz_escape(const char *in, size_t n, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < n && in[i] && cap > 0; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch >= 0x20 && ch < 0x7F) {
            if (o + 1 >= cap) break;
            out[o++] = (char)ch;
        } else {
            if (o + 4 >= cap) break;
            out[o++] = '\\';
            out[o++] = (char)('0' + ch / 100);
            out[o++] = (char)('0' + ch / 10 % 10);
            out[o++] = (char)('0' + ch % 10);
        }
    }
    if (cap > 0) out[o] = '\0';
    return o;
}

static void fz_reset(fz_t *f, bool on) {
    f->on = on;
    f->overflow = false;
    f->n = 0;
}

/* one failed zone of `view` (while collecting): the line is "name: reason", both escaped, the name cut at 255 bytes */
static void fz_add(fz_t *f, uint16_t view, const char *name, const char *reason, size_t rlen) {
    if (!f->on) return;
    if (f->n >= FZ_MAX_ENT) {
        f->overflow = true;
        return;
    }
    fz_ent_t *e = &f->ent[f->n++];
    e->view = view;
    size_t o = fz_escape(name ? name : "(NULL)", name ? strlen(name) : 6, e->text, 260);
    o += (size_t)snprintf(e->text + o, FZ_LINE - o, ": ");
    fz_escape(reason ? reason : "rejected", reason ? rlen : 8, e->text + o, FZ_LINE - o);
}

/* failed_zones of the views listed, into out (FZ_REPORT_BYTES + 1 bytes): their lines in the order they happened, at most
 * FZ_REPORT_LINES lines and FZ_REPORT_BYTES bytes, "... and N more" for the rest.  *ok = none of the views had a failure (and
 * nothing was dropped for want of room: then the text says so, as the view of the dropped one is not known). */
static void fz_report(const fz_t *f, const uint16_t *views, size_t nv, char *out, bool *ok) {
    size_t o = 0;
    unsigned lines = 0, sel = 0;
    out[0] = '\0';
    for (unsigned i = 0; i < f->n; i++) {
        bool mine = false;
        for (size_t k = 0; k < nv; k++)
            if (views[k] == f->ent[i].view) mine = true;
        if (!mine) continue;
        sel++;
        size_t l = strlen(f->ent[i].text);
        if (lines >= FZ_REPORT_LINES || o + (lines ? 1 : 0) + l > FZ_REPORT_BYTES - 40) continue;     /* 40 bytes: the "... and N more" line */
        if (lines) out[o++] = '\n';
        memcpy(out + o, f->ent[i].text, l);
        o += l;
        lines++;
    }
    out[o] = '\0';
    if (sel > lines) snprintf(out + o, FZ_REPORT_BYTES + 1 - o, "%s... and %u more", lines ? "\n" : "", sel - lines);
    else if (sel == 0 && f->overflow) snprintf(out, FZ_REPORT_BYTES + 1, "(more zones failed than are listed)");
    *ok = sel == 0 && !f->overflow;
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
    if (x->check) {                                  /* B12: domains.catalog, in step with zones[] */
        if (x->chk_ncat >= x->chk_ccat) {
            size_t nc = x->chk_ccat ? x->chk_ccat * 2 : 256;
            char **ncat = realloc(x->chk_cat, nc * sizeof(*ncat));
            if (!ncat) return x->oom = true;
            x->chk_cat = ncat;
            x->chk_ccat = nc;
        }
        x->chk_cat[x->chk_ncat] = r->catalog ? strdup(r->catalog) : NULL;
        if (r->catalog && !x->chk_cat[x->chk_ncat]) return x->oom = true;
        x->chk_ncat++;
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
    if (x->io) fz_add(&x->io->fz, x->view, zi->name, reason, reason ? strlen(reason) : 0);       /* B11: failed_zones (also a name the stream cannot carry) */
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

/* ---- B12, --check: what is said about a zone (design 7.2) ----
 * The conversion above is the production one; --check only adds what it says.  The reader's own messages and the zone checks of
 * karicheck (dns_zone_lint.c, the same code as `karicheck zone`) are lines of the check protocol. */

/* the reader prefixes its messages with "zone 'NAME' " or "zone 'NAME': "; the line already says which zone */
static const char *chk_strip_zone(const char *msg) {
    size_t n = strlen(g_chk_zone);
    if (n && strncmp(msg, "zone '", 6) == 0 && strncmp(msg + 6, g_chk_zone, n) == 0 && msg[6 + n] == '\'') {
        const char *p = msg + 7 + n;
        if (*p == ':') p++;
        while (*p == ' ') p++;
        return p;
    }
    return msg;
}

static void chk_sink(void *ud, char level, const char *text) {
    (void)ud;
    chk_line(level, text);
}

/* the first line of a zone: Z <zone> <id> <kind> <view>... (the views karidns_domain_views names, "*" = no row) */
static void chk_zone_begin(ctx_t *x, const zinfo_t *zi, const char *kind) {
    char canon[DNS_NAME_TEXT_SIZE], esc[4 * DNS_NAME_TEXT_SIZE + 4];
    bool ok = zi->name && pdns_canonical_zone_name(zi->name, canon);
    snprintf(g_chk_zone, sizeof(g_chk_zone), "%s", ok ? canon : (zi->name ? zi->name : ""));
    g_chk_id = zi->id;
    chk_escape(g_chk_zone, strlen(g_chk_zone), esc, sizeof(esc), NULL);
    fprintf(g_chk_out, "Z\t%s\t%lld\t%s", esc, (long long)zi->id, ok ? kind : "invalid");
    size_t lo = 0, hi = x->chk_nmap;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (x->chk_map[mid].did < zi->id) lo = mid + 1;
        else hi = mid;
    }
    unsigned n = 0;
    for (size_t i = lo; i < x->chk_nmap && x->chk_map[i].did == zi->id; i++, n++) {
        if (n >= 40) break;
        char v[4 * 256 + 4];
        chk_escape(x->chk_map[i].view, strlen(x->chk_map[i].view), v, sizeof(v), NULL);
        fprintf(g_chk_out, "\t%s", v);
    }
    if (n == 0) fprintf(g_chk_out, "\t*");
    fputc('\n', g_chk_out);
    if (n >= 40 && lo + 40 < x->chk_nmap && x->chk_map[lo + 40].did == zi->id)
        chk_linef('W', "karidns_domain_views has more than 40 rows for this zone; the rest are not checked");
}

/* after pdns_zone_finish(): the reader's warnings, the checks of `karicheck zone` on the parsed zone, the SOA serial, the settings text */
static void chk_zone_report(ctx_t *x, const zinfo_t *zi, pdns_zone_t *z, const struct lprof *pf) {
    for (size_t i = 0; i < z->n_warnings; i++) chk_line('W', chk_strip_zone(z->warnings[i]));
    if (z->warnings_dropped) chk_linef('W', "%zu more warning(s) were dropped", z->warnings_dropped);
    if (z->failed) return;
    if (z->zkind == KDB_ZK_PRIMARY && z->arena_ready) {
        kc_tally_t t = {0};
        t.sink = chk_sink;
        char src[40];
        snprintf(src, sizeof(src), "domains.id %lld", (long long)zi->id);
        zone_lint_ttl(&z->arena, "database", &t);
        zone_lint_pdns_types(&z->arena, z->name, &t);
        zone_lint_in_t in = {0};
        in.domain = z->name;
        in.src = src;
        in.ecs_tags = x->chk_ecs;
        in.ecs_tag_count = x->chk_necs;
        in.loc_tags = x->chk_loc;
        in.loc_tag_count = x->chk_nloc;
        zone_lint_records(&z->arena, &in, &t);
        if (z->serial == 0)
            chk_linef('W', "the SOA serial is 0; PowerDNS may compute the served serial (SOA-EDIT, auto-serial), but KariDNS uses the stored value as it is, "
                              "so secondaries and NOTIFY see serial 0");
    }
    if (z->settings[0] || pf) {          /* karicheck parses the text with the configuration (keys, acl-ceiling) */
        const char *ptext = pf ? pf->text : "";
        size_t zl = strlen(z->settings), pl = strlen(ptext);
        char *zt = malloc(4 * zl + 8), *pt = malloc(4 * pl + 8);
        char zn[4 * DNS_NAME_TEXT_SIZE + 4], pn[4 * 256 + 4];
        if (zt && pt) {
            chk_escape(g_chk_zone, strlen(g_chk_zone), zn, sizeof(zn), NULL);
            chk_escape(z->settings, zl, zt, 4 * zl + 8, NULL);
            chk_escape(pf ? pf->name : "", pf ? strlen(pf->name) : 0, pn, sizeof(pn), NULL);
            chk_escape(ptext, pl, pt, 4 * pl + 8, NULL);
            fprintf(g_chk_out, "S\t%s\t%lld\t%s\t%s\t%s\n", zn, (long long)zi->id, zt, pn, pt);
        } else {
            chk_linef('E', "out of memory");
        }
        free(zt);
        free(pt);
    }
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
    if (x->check) chk_zone_begin(x, zi, tr ? "other" : skind == KDB_ZK_SECONDARY ? "secondary" : skind == KDB_ZK_CATALOG ? "catalog" : "primary");
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
        if (!x->check)
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
        if (x->check) chk_zone_report(x, zi, z, pf && !pf->bad ? pf : NULL);        // B12: warnings, the zone checks of karicheck, the settings text
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
    if (g_stop) {                                      /* B13: SIGTERM / SIGINT: stop reading and converting at the next zone (the main thread sees g_stop and ends the load) */
        w->stop = true;
        return 1;
    }
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
    if (g_stop) {                                      /* B13: also inside a long scan, which converts nothing for the rows of unwanted zones */
        w->stop = true;
        return 1;
    }
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

/* --check: nothing is sent; the zones the production load would refuse are the errors (the converted stream is discarded) */
static int deliver_check(wk_t *w, size_t pos, zres_t *r) {
    ctx_t *x = w->x;
    (void)pos;
    x->chk_zones++;
    if (r->kind == ZR_FATAL) {
        x->oom = true;
        return -1;
    }
    if (r->kind == ZR_FAILED) chk_line('E', chk_strip_zone(r->reason));
    return 0;
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
    /* B11b: the driver learns which optional tables the source has (has_ext, ...) from check_schema(), as in run_view(); a worker
     * that skipped it read the zones one by one (bulk off) with scan_ext() failing "the ... tables do not exist" on a database that
     * has them, so a reload of two or more zones with loader-threads > 1 failed as a whole */
    db_schema_info_t si;
    memset(&si, 0, sizeof(si));
    if ((rc = w->drv->check_schema(w->conn, &si)) != 0) {
        pool_fail(p, w, db_err_c(w->drv, w->conn, w->errtext, sizeof(w->errtext), rc, "schema"));
        w->drv->close(w->conn);
        w->conn = NULL;
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
    w.deliver = x->check ? deliver_check : deliver_inline;
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
    for (size_t i = 0; i < x->chk_ncat; i++) free(x->chk_cat[i]);       /* B12 */
    free(x->chk_cat);
    x->chk_cat = NULL;
    x->chk_ncat = x->chk_ccat = 0;
    for (size_t i = 0; i < x->chk_nmap; i++) free(x->chk_map[i].view);
    free(x->chk_map);
    x->chk_map = NULL;
    x->chk_nmap = x->chk_cmap = 0;
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
                } else if (mx > vs->seq || x->drv->changes_unsettled) {      /* PostgreSQL: rows beyond the cursor may be visible */
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
            lg(LOG_NOTICE, "view '%s': the database has no usable karidns_changes table; zones are compared by serial only (apply "
                           "db/karidns_ext.*.sql, or on PostgreSQL db/karidns_ext_v1_to_v2.pgsql.sql, to notice edits that keep the "
                           "serial; 'karictl reload <zone>' reads one zone)",
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
    /* B13: a one-zone request asks the inventory for that one name (names are unique per view); the walk over every entry is only for a
     * full comparison */
    inv_ent_t *one = (only_zone && have_only) ? inv_find(&io->inv, x->vslot, only_canon) : NULL;
    for (size_t b = 0; b < (only_zone ? (one ? 1u : 0u) : io->inv.nb); b++) {
        for (inv_ent_t *e = only_zone ? one : io->inv.tab[b]; e; e = only_zone ? NULL : e->next) {
            if (e->vslot != x->vslot || e->mark == gen || !e->known) continue;
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
    /* B13: a one-zone request looks the zone up by name (index) instead of listing every zone of the source, so its cost does
     * not grow with the number of zones; a missing zone is the same empty result as before (nz == 0: a deletion in stream mode) */
    rc = x->only_name && x->drv->find_zone ? x->drv->find_zone(x->conn, x->only_name, zone_cb, x) : x->drv->list_zones(x->conn, zone_cb, x);
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
            if (g_stop && !x->io_error && !x->oom) {         /* B13: told to stop (the caller ends the load); nothing went wrong */
                status = EXIT_ERROR;
                goto out_snap;
            }
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
/* --check: `karicheck db` (B12, beta design 7.2)                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

/* The checks of one database, read only (the connection is query_only / READ ONLY, nothing is written, no status row, no LISTEN) and
 * through the same functions as the production load: the same driver calls and the same reader (convert_zone() above is the one the
 * production load runs), so a zone that --check accepts is a zone the loader sends, and the other way round.  The lines it writes are
 * the check protocol (dns_db_checkproto.h): karicheck prints them and applies the part that needs the configuration (settings text,
 * keys, acl-ceiling, views, the zones of karidns.conf).
 *
 * Rights: the process runs with the rights of whoever started it.  karicheck, when it is run as root, drops to loader-user /
 * loader-group before it executes this program (D-B12-1), so the check reads the source the way the loader of karidns does. */

static const char *chk_me(char *buf, size_t cap) {
    struct passwd *pw = getpwuid(geteuid());
    snprintf(buf, cap, "%s (uid %u)", pw ? pw->pw_name : "?", (unsigned)geteuid());
    return buf;
}

/* Can this user use `path`?  If not, say which file or directory lacks which permission.  rw: the file is opened for writing too
 * (SQLite opens a WAL database read-write because even a reader writes the -shm file). */
static bool chk_path_access(const char *what, const char *path, bool rw) {
    char me[160];
    struct stat st;
    if (stat(path, &st) != 0) {
        int e = errno;
        if (e == EACCES) {
            /* the directory (from the top) that cannot be searched: the first prefix that cannot be stat()ed is the one below it */
            char prefix[PATH_MAX];
            snprintf(prefix, sizeof(prefix), "%s", path);
            for (size_t i = 1; prefix[i]; i++) {
                if (prefix[i] != '/') continue;
                prefix[i] = '\0';
                struct stat ds;
                if (stat(prefix, &ds) != 0 || access(prefix, X_OK) != 0) {
                    if (stat(prefix, &ds) == 0)
                        chk_linef('E', "cannot reach %s '%s': the user %s has no search (x) permission on the directory '%s' (mode %04o, owner uid %u, group gid %u)",
                                  what, path, chk_me(me, sizeof(me)), prefix, (unsigned)(ds.st_mode & 07777), (unsigned)ds.st_uid, (unsigned)ds.st_gid);
                    else
                        chk_linef('E', "cannot reach %s '%s': the user %s cannot use the directory '%s' (%s)", what, path, chk_me(me, sizeof(me)), prefix,
                                  strerror(errno));
                    return false;
                }
                prefix[i] = '/';
            }
        }
        if (e == EACCES) chk_linef('E', "cannot reach %s '%s': permission denied for the user %s", what, path, chk_me(me, sizeof(me)));
        else chk_linef('E', "%s '%s': %s", what, path, strerror(e));
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        chk_linef('E', "%s '%s' is not a regular file", what, path);
        return false;
    }
    if (access(path, R_OK) != 0) {
        chk_linef('E', "%s '%s' is not readable by the user %s: it needs read permission (mode %04o, owner uid %u, group gid %u)", what, path,
                  chk_me(me, sizeof(me)), (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid, (unsigned)st.st_gid);
        return false;
    }
    if (strcmp(what, "conninfo-file") == 0) {          /* what the PostgreSQL driver demands before it reads the file (it may hold a password) */
        if (st.st_uid != geteuid()) {
            chk_linef('E', "%s '%s' is owned by uid %u; the loader refuses it unless it is owned by the user it runs as, %s", what, path, (unsigned)st.st_uid,
                      chk_me(me, sizeof(me)));
            return false;
        }
        if ((st.st_mode & 07777) != 0600 && (st.st_mode & 07777) != 0400) {
            chk_linef('E', "%s '%s' has mode %04o; the loader requires 0600 or 0400 (it may hold a password)", what, path, (unsigned)(st.st_mode & 07777));
            return false;
        }
    }
    if (rw && access(path, W_OK) != 0) {
        chk_linef('E', "%s '%s' is not writable by the user %s: SQLite needs write permission on the database file even for a reader in WAL mode "
                       "(mode %04o, owner uid %u, group gid %u)", what, path, chk_me(me, sizeof(me)), (unsigned)(st.st_mode & 07777),
                  (unsigned)st.st_uid, (unsigned)st.st_gid);
        return false;
    }
    if (rw) {                                           /* the -wal / -shm files live next to the database */
        char dir[PATH_MAX], shm[PATH_MAX + 8], wal[PATH_MAX + 8];
        snprintf(dir, sizeof(dir), "%s", path);
        char *s = strrchr(dir, '/');
        if (s) *(s == dir ? s + 1 : s) = '\0';
        else snprintf(dir, sizeof(dir), ".");
        snprintf(shm, sizeof(shm), "%s-shm", path);
        snprintf(wal, sizeof(wal), "%s-wal", path);
        if (access(dir, W_OK) != 0 && (access(shm, W_OK) != 0 || access(wal, W_OK) != 0)) {
            chk_linef('E', "the directory '%s' of the database file is not writable by the user %s, and '%s' / '%s' do not both exist and are writable: a reader "
                           "in WAL mode needs the -shm and -wal files (the directory needs write permission, or both files must exist and be writable)", dir,
                      chk_me(me, sizeof(me)), shm, wal);
            return false;
        }
    }
    return true;
}

static int chk_map_cb(void *ud, int64_t did, const char *vn) {
    ctx_t *x = ud;
    if (x->chk_nmap >= x->chk_cmap) {
        size_t nc = x->chk_cmap ? x->chk_cmap * 2 : 256;
        struct chk_map *nm = realloc(x->chk_map, nc * sizeof(*nm));
        if (!nm) return x->oom = true;
        x->chk_map = nm;
        x->chk_cmap = nc;
    }
    x->chk_map[x->chk_nmap].did = did;
    x->chk_map[x->chk_nmap].view = strdup(vn);
    if (!x->chk_map[x->chk_nmap].view) return x->oom = true;
    x->chk_nmap++;
    return 0;
}

static void chk_driver_sink(void *ud, char level, const char *text) {
    (void)ud;
    chk_line(level, text);
}

/* domains.catalog (PowerDNS catalog zones): the column names the PRODUCER zone a member belongs to.  KariDNS does not read it yet
 * (PRODUCER zones are refused above), so a name that is no PRODUCER zone of this database is only worth a warning. */
static void chk_catalogs(ctx_t *x) {
    struct { char name[DNS_NAME_TEXT_SIZE]; bool ok; } seen[64];
    size_t nseen = 0;
    for (size_t i = 0; i < x->nz && i < x->chk_ncat; i++) {
        const char *cat = x->chk_cat[i];
        if (!cat || !*cat) continue;
        bool ok = false, known = false;
        for (size_t k = 0; k < nseen && !known; k++)
            if (strcasecmp(seen[k].name, cat) == 0) {
                known = true;
                ok = seen[k].ok;
            }
        if (!known) {
            for (size_t j = 0; j < x->nz; j++)
                if (x->zones[j].name && names_equal(x->zones[j].name, cat) && x->zones[j].type && strcasecmp(x->zones[j].type, "PRODUCER") == 0) ok = true;
            if (nseen < sizeof(seen) / sizeof(seen[0]) && strlen(cat) < sizeof(seen[0].name)) {
                snprintf(seen[nseen].name, sizeof(seen[0].name), "%s", cat);
                seen[nseen++].ok = ok;
            }
        }
        if (ok) continue;
        char canon[DNS_NAME_TEXT_SIZE];
        snprintf(g_chk_zone, sizeof(g_chk_zone), "%s", x->zones[i].name && pdns_canonical_zone_name(x->zones[i].name, canon) ? canon : (x->zones[i].name ? x->zones[i].name : ""));
        g_chk_id = x->zones[i].id;
        chk_linef('W', "domains.catalog names '%.200s', which is not a PRODUCER zone of this database (KariDNS ignores the column; catalog producer zones are not loaded yet)", cat);
    }
    g_chk_zone[0] = '\0';
    g_chk_id = 0;
}

/* One source.  Returns an exit status: 0 nothing wrong, EXIT_ZONES_FAILED errors were found, EXIT_ERROR / EXIT_RETRY the source could not be read. */
static int run_check(ctx_t *x, const db_source_t *src) {
    char err[DB_ERRLEN];
    ctx_view_reset(x);
    g_chk_zone[0] = '\0';
    g_chk_id = 0;
    bool sqlite = strcmp(x->drv->name, "sqlite3") == 0;
    const char *file = sqlite ? src->database_file : src->conninfo_file;
    if (file && !chk_path_access(sqlite ? "database file" : "conninfo-file", file, sqlite)) return EXIT_ERROR;
    int rc = x->drv->open(&x->conn, src, err, sizeof(err));
    if (rc != 0) {
        chk_linef('E', "%s", err);
        return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
    }
    int status = EXIT_OK;
    db_schema_info_t si;
    memset(&si, 0, sizeof(si));
    unsigned e0 = g_chk_errors;
    if (x->drv->schema_findings && (rc = x->drv->schema_findings(x->conn, &x->chk_opts, chk_driver_sink, NULL)) != 0) {
        status = db_err(x, rc, "schema");
        goto out;
    }
    if ((rc = x->drv->check_schema(x->conn, &si)) != 0) {
        if (g_chk_errors == e0) status = db_err(x, rc, "schema");          /* schema_findings() said nothing, but the production check refuses */
        else status = EXIT_ZONES_FAILED;
        goto out;
    }
    if (g_chk_errors != e0) {                       /* the schema has errors (a privilege, say): reading would only repeat them */
        status = EXIT_ZONES_FAILED;
        goto out;
    }
    if ((rc = x->drv->begin_snapshot(x->conn)) != 0) {
        status = db_err(x, rc, "snapshot");
        goto out;
    }
    x->has_ext = si.has_ext && x->drv->scan_ext;
    rc = x->drv->list_zones(x->conn, zone_cb, x);
    if (rc != 0) {
        status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading the zone list");
        if (x->oom) lg(LOG_ERR, "out of memory");
        goto out_snap;
    }
    if (si.has_domain_views && x->nz > 0 && (rc = x->drv->scan_domain_views(x->conn, NULL, chk_map_cb, x)) != 0) {
        status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading karidns_domain_views");
        if (x->oom) lg(LOG_ERR, "out of memory");
        goto out_snap;
    }
    x->wl = malloc((x->nz ? x->nz : 1) * sizeof(*x->wl));
    if (!x->wl) {
        lg(LOG_ERR, "out of memory");
        status = EXIT_ERROR;
        goto out_snap;
    }
    for (size_t i = 0; i < x->nz; i++) x->wl[x->nwl++] = i;
    if (x->nz > 0) {
        if ((rc = x->drv->zones_with_keys(x->conn, key_cb, x)) != 0) {
            status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading metadata");
            if (x->oom) lg(LOG_ERR, "out of memory");
            goto out_snap;
        }
        qsort(x->keys, x->nk, sizeof(int64_t), cmp_i64);
        if (si.has_profiles && x->drv->scan_profiles && (rc = x->drv->scan_profiles(x->conn, prof_cb, x)) != 0) {
            status = x->prof_oom ? EXIT_ERROR : db_err(x, rc, "reading karidns_profiles");
            if (x->prof_oom) lg(LOG_ERR, "out of memory");
            goto out_snap;
        }
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
        int st = run_zones(x, src, true, x->nz);
        if (st == TK_FATAL) {
            if (x->oom) lg(LOG_ERR, "out of memory");
            status = EXIT_ERROR;
            goto out_snap;
        }
        if (st != 0) {
            status = st;
            goto out_snap;
        }
        chk_catalogs(x);
    }
    if (g_chk_errors != e0) status = EXIT_ZONES_FAILED;
out_snap:
    x->drv->end_snapshot(x->conn);
out:
    x->drv->close(x->conn);
    x->conn = NULL;
    return status;
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
            fz_add(&io->fz, m.u.zone_result.view, m.u.zone_result.name, m.u.zone_result.reason.p, m.u.zone_result.reason.len);
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

/* where the data of a view is: the file (sqlite3) or the schema (postgresql) in `source` */
static void view_source(const db_driver_t *drv, const lview_t *v, db_source_t *src) {
    bool sqlite = strcmp(drv->name, "sqlite3") == 0;
    src->driver = drv->name;
    src->database_file = sqlite ? v->source : NULL;
    src->conninfo_file = v->conninfo;
    src->schema = sqlite ? NULL : v->source;
    src->busy_timeout_ms = 0;
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
        db_source_t src;
        view_source(drv, v, &src);
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
        char vtxt[300] = "";                       /* an auto batch is made for one view: say which */
        if (kind == KDB_BATCH_AUTO) snprintf(vtxt, sizeof(vtxt), " (view '%.200s')", io->vnames[x->vslot]);
        lg(LOG_INFO, "batch %llu (%s) sent: %u zone(s) read, %u sent, %u failed in the loader, %u deleted, %u unchanged%s%s",
           (unsigned long long)x->batch_id, batch_kind_name(kind), x->n_read, x->n_zones, x->n_failed, x->n_deleted,
           x->n_unchanged, req_id ? " (answers a request)" : "", vtxt);
        if (io_wait_results(io) != 0) return -1;
    }
    return errs ? 1 : 0;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* auto reload (B9, design 6): `auto-reload yes;`                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */
/* Every poll-interval a view with auto reload asks its persistent connection for PRAGMA data_version.  When it changed,
 * the end of the change log decides whether a zone was touched (no new rows: nothing to do); the first change starts a
 * coalesce window, and when it ends one batch of kind auto is made by do_load() for that view: the same diff as a
 * `karictl reload` (change log since the last load, serials, digest gate, ZONE_DELETE for zones that left the database;
 * a gap in the log or a reset one compares every zone).  Without karidns_changes the batch compares serials only.
 * Everything runs in the main loop of the stream (no thread): a batch in progress is finished before the next poll, and
 * requests of the Backend wait in the queue until the loop comes round again.
 *
 * B10, PostgreSQL: poll_version() drains the LISTEN notifications of the persistent connection (and pings the server now and
 * then, so a dead connection fails the poll and is reopened with a catch-up check); the connection's socket (wait_fd()) is in
 * the poll set of the main loop, so a notification makes the view due at once instead of at the next poll-interval.  The
 * position in the change log is the driver's cursor (dns_db_driver.h changes_unsettled): changes_since() is called by every
 * batch, not only when the cursor grew, and the data_version style pre-check of auto_changed() is not used. */

static void auto_set_err(struct lio *io, uint16_t slot, bool load, const char *what, const char *msg) {
    vstate_t *vs = &io->vst[slot];
    char *dst = load ? vs->lerr : vs->perr;
    char shown[100], text[AUTO_ERRLEN];
    clean_reason(msg, shown, sizeof(shown));
    snprintf(text, sizeof(text), "%s: %s", what, shown);
    if (strcmp(dst, text) != 0) {                          /* log a condition once, not at every poll */
        snprintf(dst, AUTO_ERRLEN, "%s", text);
        lg(LOG_WARNING, "view '%s': auto reload: %s", io->vnames[slot], text);
    }
}

static uint64_t auto_poll_ms(const lview_t *v) { return (uint64_t)(v->poll_interval ? v->poll_interval : 1) * 1000u; }

static void auto_close(vstate_t *vs) {
    if (vs->pconn) vs->pdrv->close(vs->pconn);
    vs->pconn = NULL;
    vs->dv_valid = false;
}

/* auto reload is (now) off for this view: forget everything about it */
static void auto_off(vstate_t *vs) {
    auto_close(vs);
    vs->opened_once = false;
    vs->need_full = false;
    vs->next_poll = vs->flush_at = vs->open_retry_at = 0;
    vs->pending = 0;
    vs->last_poll = 0;
    vs->perr[0] = vs->lerr[0] = '\0';
}

/* a change was seen: the first one starts the coalesce window, which later ones do not extend */
static void auto_mark(vstate_t *vs, int64_t now, uint32_t coalesce_ms, uint32_t n) {
    if (!vs->flush_at) vs->flush_at = now + (int64_t)coalesce_ms;
    if (n > vs->pending) vs->pending = n;
}

/* open the persistent connection and take the baseline.  startup_pending: a load follows (the baseline is taken before it,
 * so that a commit during the load is seen by the next poll); otherwise changes may have been missed (auto reload was off,
 * the connection was lost): check, which costs one diff. */
static bool auto_open(struct lio *io, const lview_t *v, uint16_t slot, bool startup_pending) {
    vstate_t *vs = &io->vst[slot];
    const db_driver_t *drv = driver_find(io->cfg.driver);
    int64_t now = now_ms();
    vs->open_retry_at = now + (int64_t)auto_poll_ms(v);
    if (!drv || !drv->poll_version) {
        auto_set_err(io, slot, false, "cannot watch the database", "the driver has no change detector");
        return false;
    }
    db_source_t src;
    view_source(drv, v, &src);
    char err[DB_ERRLEN];
    db_conn_t *c = NULL;
    int rc = drv->open(&c, &src, err, sizeof(err));
    if (rc != 0) {
        auto_set_err(io, slot, false, "cannot open the database", err);
        return false;
    }
    db_schema_info_t si;
    memset(&si, 0, sizeof(si));
    uint64_t dv = 0;
    bool repl = false;
    if ((rc = drv->check_schema(c, &si)) != 0 || (rc = drv->poll_version(c, &dv, &repl)) != 0) {
        auto_set_err(io, slot, false, "cannot watch the database", drv->errmsg(c));
        drv->close(c);
        return false;
    }
    vs->pconn = c;
    vs->pdrv = drv;
    vs->has_changes = si.has_changes;
    vs->dv = dv;
    vs->dv_valid = true;
    vs->next_poll = now + (int64_t)auto_poll_ms(v);
    vs->perr[0] = '\0';
    if (!si.has_changes && !vs->nolog_auto_warned) {
        vs->nolog_auto_warned = true;
        if (strcmp(drv->name, "sqlite3") == 0)
            lg(LOG_WARNING, "view '%s': auto-reload is on but the database has no karidns_changes table; changes are noticed "
                            "(PRAGMA data_version) and zones are compared by serial only, so an edit that keeps the serial is not "
                            "picked up (apply db/karidns_ext.sqlite3.sql, or 'karictl reload <zone>')",
               io->vnames[slot]);
        else
            lg(LOG_WARNING, "view '%s': auto-reload is on but the database has no usable karidns_changes table (schema version 2); "
                            "nothing is notified without the triggers of db/karidns_ext.pgsql.sql, and zones are compared by serial "
                            "only (apply db/karidns_ext.pgsql.sql, or db/karidns_ext_v1_to_v2.pgsql.sql, or use 'karictl reload <zone>')",
               io->vnames[slot]);
    }
    if (!startup_pending) {                                 /* auto reload was just switched on, or the connection was lost: what */
        lg(LOG_INFO, "view '%s': auto reload %s; checking for changes", io->vnames[slot],   /* happened meanwhile is not known */
           vs->opened_once ? "reopened the database" : "is on");
        auto_mark(vs, now, v->coalesce_ms, 1);
    }
    vs->opened_once = true;
    return true;
}

/* top of the loop, before a load: views that have auto reload on get their connection (and baseline) first; views that
 * have it off, or left the configuration, lose theirs.  A change of karidns.conf takes effect here. */
static void auto_prepare(struct lio *io, bool load_follows) {
    int64_t now = now_ms();
    for (size_t s = 0; s < io->nvn; s++) {
        const lview_t *v = NULL;
        for (size_t i = 0; i < io->cfg.nviews; i++)
            if (strcasecmp(io->cfg.views[i].name, io->vnames[s]) == 0) v = &io->cfg.views[i];
        if (!v || !v->auto_reload) {
            if (io->vst[s].pconn || io->vst[s].opened_once || io->vst[s].flush_at) {
                lg(LOG_NOTICE, "view '%s': auto reload is off", io->vnames[s]);
                auto_off(&io->vst[s]);
            }
            continue;
        }
        if (!io->vst[s].pconn && now >= io->vst[s].open_retry_at) auto_open(io, v, (uint16_t)s, load_follows);
    }
}

/* the end of the change log decides whether the data_version change touched a zone */
static void auto_changed(vstate_t *vs, const lview_t *v, int64_t now) {
    uint32_t n = 1;
    if (vs->has_changes && vs->pdrv->changes_max && !vs->pdrv->changes_unsettled) {
        uint64_t mx = 0;
        if (vs->pdrv->changes_max(vs->pconn, &mx) == 0) {
            if (vs->seq_valid && mx == vs->seq) return;               /* nothing was logged since the last load */
            if (vs->seq_valid && mx > vs->seq) n = mx - vs->seq > UINT32_MAX ? UINT32_MAX : (uint32_t)(mx - vs->seq);
        }                                                              /* else: the log was reset or cannot be read: the load decides */
    }
    auto_mark(vs, now, v->coalesce_ms, n);
}

/* one view: poll when it is due, then make the batch when the coalesce window has ended.  0, or -1 (fatal: stream, stop) */
static int auto_view(ctx_t *x, struct lio *io, const lview_t *v, uint16_t slot, bool *dirty) {
    vstate_t *vs = &io->vst[slot];
    int64_t now = now_ms();
    uint64_t poll_ms = auto_poll_ms(v);
    if (!vs->pconn) {
        if (now >= vs->open_retry_at) {
            auto_open(io, v, slot, false);
            *dirty = true;
        }
    } else if (now >= vs->next_poll) {
        *dirty = true;
        vs->next_poll = now + (int64_t)poll_ms;
        vs->last_poll = (int64_t)time(NULL);
        uint64_t dv = 0;
        bool repl = false;
        int rc = vs->pdrv->poll_version(vs->pconn, &dv, &repl);
        if (rc != 0) {
            auto_set_err(io, slot, false, "poll failed", vs->pdrv->errmsg(vs->pconn));
            auto_close(vs);                                            /* reopened at the next due time, which then checks for changes */
            vs->open_retry_at = now + (int64_t)poll_ms;
        } else if (repl) {
            lg(LOG_NOTICE, "view '%s': the database file was replaced or removed; reopening and comparing every zone",
               io->vnames[slot]);
            vs->need_full = true;
            auto_close(vs);
            auto_mark(vs, now, v->coalesce_ms, 1);
            auto_open(io, v, slot, true);
        } else {
            vs->perr[0] = '\0';
            if (!vs->dv_valid || dv != vs->dv) {
                vs->dv = dv;
                vs->dv_valid = true;
                auto_changed(vs, v, now);
            }
        }
    }
    vs = &io->vst[slot];
    if (vs->flush_at && now_ms() >= vs->flush_at) {
        vs->flush_at = 0;
        int rc = do_load(x, io, KDB_BATCH_AUTO, v->index, NULL, 0, false, vs->need_full);
        if (rc < 0) return -1;
        vs = &io->vst[slot];
        *dirty = true;
        if (rc == 0) {
            vs->pending = 0;
            vs->need_full = false;
            vs->lerr[0] = '\0';
        } else {                                                       /* the database could not be read: try again at the next poll time */
            vs->flush_at = now_ms() + (int64_t)poll_ms;
            auto_set_err(io, slot, true, "cannot read the database", x->errtext[0] ? x->errtext : "the database could not be read");
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* multi-server reload requests (B11, release plan 4.8, design 3.7)                                               */
/* ------------------------------------------------------------------------------------------------------------- */
/* PostgreSQL only (a driver with watch_requests).  For every source (schema) whose database has karidns_reload_requests the
 * loader keeps one watcher: a connection of its own that LISTENs karidns_reload (its socket is in the poll set of the main loop)
 * and, every poll-interval, reads the requests with a generation above the last one it applied.  Whether auto reload is on or
 * not.  When the watcher is opened before a load (the startup load, or a load after a change of sources) the highest generation
 * counts as applied: that load covers it.  Requests that arrive together (the coalesce window) are one reload: a request for all
 * zones, a hole in the generations (pruned or rolled back requests), or more than RW_ZONES different zones makes it a diff of the
 * whole source, else the zones listed are reloaded; force is the OR of the requests.  The reload is the one of `karictl
 * reload` (do_load(), kinds diff / zone) for every view that reads the source.  When the BATCH_RESULTs are in, report_status()
 * writes the outcome (every zone loaded, or the zones that failed) to this server's row of karidns_server_status, in a
 * transaction of its own on the watcher's connection (never inside the read snapshot of a load).  The load that follows the
 * opening of a watcher is reported the same way.
 * Nothing here puts the loader into an error state (D-B11-5): a request that cannot be read, a source that cannot be loaded or a
 * status row that cannot be written is logged once (again when the text changes), shown by `karictl dbstatus` and retried; the
 * zones keep being served.  A request is only counted as applied after every view of the source was loaded. */

static const lview_t *rw_view(const struct lio *io, uint16_t index) {
    for (size_t i = 0; i < io->cfg.nviews; i++)
        if (io->cfg.views[i].index == index) return &io->cfg.views[i];
    return NULL;
}

static const lview_t *rw_view0(const struct lio *io, const rw_t *r) { return r->nv ? rw_view(io, r->views[0]) : NULL; }

static uint64_t rw_poll_ms(const struct lio *io, const rw_t *r) {
    const lview_t *v = rw_view0(io, r);
    return v ? auto_poll_ms(v) : 2000;
}

static void rw_set_err(struct lio *io, rw_t *r, bool report, const char *what, const char *msg) {
    char shown[100], text[RW_ERRLEN];
    clean_reason(msg, shown, sizeof(shown));
    snprintf(text, sizeof(text), "%s: %s", what, shown);
    char *dst = report ? r->rerr : r->perr;
    if (strcmp(dst, text) != 0) {                          /* log a condition once, not at every attempt */
        snprintf(dst, RW_ERRLEN, "%s", text);
        const lview_t *v = rw_view0(io, r);
        lg(LOG_WARNING, "view '%s': reload requests: %s", v ? v->name : "?", text);
        io->status_dirty = true;
    }
}

static void rw_close(rw_t *r) {
    if (r->conn) r->drv->close(r->conn);
    r->conn = NULL;
}

static void rw_free(rw_t *r) {
    rw_close(r);
    free(r->source);
    free(r->conninfo);
    free(r->views);
    free(r->rep_text);
    free(r->zbuf);
    memset(r, 0, sizeof(*r));
}

/* the server id: server-id of the database block, else the host name (D-B11-6); io->sid_ok is false when there is none that fits
 * the column (1..64 bytes), and io->sid_why says why */
static void sid_resolve(struct lio *io) {
    char h[256];
    const char *src = io->cfg.server_id, *why = NULL;
    if (!*src) {
        if (gethostname(h, sizeof(h)) != 0) h[0] = '\0';
        h[sizeof(h) - 1] = '\0';
        src = h;
        if (!*src) why = "no server-id is set and the host name is empty";
        else if (strlen(src) > 64) why = "no server-id is set and the host name is longer than 64 bytes";
    } else if (strlen(src) > 64) {
        why = "server-id is longer than 64 bytes";
    }
    if (why) {
        io->sid[0] = '\0';
        io->sid_ok = false;
        snprintf(io->sid_why, sizeof(io->sid_why), "%s", why);
        if (!io->sid_warned) {
            io->sid_warned = true;
            lg(LOG_WARNING, "%s: the outcome of reload requests is not written to karidns_server_status (set server-id in the database block)", why);
        }
        return;
    }
    snprintf(io->sid, sizeof(io->sid), "%s", src);
    io->sid_ok = true;
    io->sid_warned = false;
}

static rw_t *rw_find(struct lio *io, const char *source, const char *conninfo) {
    for (size_t i = 0; i < io->nrw; i++)
        if (streq_n(io->rw[i].source, source) && streq_n(io->rw[i].conninfo, conninfo)) return &io->rw[i];
    return NULL;
}

/* the watcher that serves view v (its source has the tables), or NULL */
static const rw_t *rw_for_view(const struct lio *io, const lview_t *v) {
    for (size_t i = 0; i < io->nrw; i++) {
        const rw_t *r = &io->rw[i];
        if (r->absent || !r->seeded) continue;
        for (size_t k = 0; k < r->nv; k++)
            if (r->views[k] == v->index) return r;
    }
    return NULL;
}

/* Open the connection, look for the tables, LISTEN, and take the position: the highest generation when a load follows
 * (startup_pending), else 0 (whatever the table holds is looked at: one diff, like auto reload that was just switched on); a
 * reopened watcher keeps its position and checks what came meanwhile. */
static bool rw_open(struct lio *io, rw_t *r, bool startup_pending) {
    int64_t now = now_ms();
    const lview_t *v = rw_view0(io, r);
    uint64_t poll_ms = rw_poll_ms(io, r);
    r->open_retry_at = now + (int64_t)poll_ms;
    if (!v) return false;
    db_source_t src;
    view_source(r->drv, v, &src);
    char err[DB_ERRLEN];
    db_conn_t *c = NULL;
    int rc = r->drv->open(&c, &src, err, sizeof(err));
    if (rc != 0) {
        rw_set_err(io, r, false, "cannot open the database", err);
        return false;
    }
    db_schema_info_t si;
    memset(&si, 0, sizeof(si));
    if ((rc = r->drv->check_schema(c, &si)) != 0) {
        rw_set_err(io, r, false, "cannot check the database", r->drv->errmsg(c));
        r->drv->close(c);
        return false;
    }
    if (!si.has_reload_requests) {                           /* the multi-server tables are optional */
        r->drv->close(c);
        r->absent = true;
        r->open_retry_at = now + RW_ABSENT_MS;
        return false;
    }
    r->absent = false;
    r->has_status = si.has_server_status;
    sid_resolve(io);
    if ((rc = r->drv->watch_requests(c)) == DB_ERR_RETRY) {
        rw_set_err(io, r, false, "cannot listen", r->drv->errmsg(c));
        r->drv->close(c);
        return false;
    }
    if (rc != 0 && !r->listen_noted) {                       /* a standby cannot LISTEN: the timer does it */
        r->listen_noted = true;
        lg(LOG_NOTICE, "view '%s': reload requests: cannot LISTEN karidns_reload (%s); the requests are read every %llu s", v->name,
           r->drv->errmsg(c), (unsigned long long)(poll_ms / 1000));
    }
    if (!r->seeded) {
        if (startup_pending) {
            uint64_t mx = 0;
            if ((rc = r->drv->requests_max(c, &mx)) != 0) {
                rw_set_err(io, r, false, "cannot read the requests", r->drv->errmsg(c));
                r->drv->close(c);
                return false;
            }
            r->last = mx;
            r->startup_seeded = true;
        } else {
            r->last = 0;
            r->flush_at = now;
        }
        r->seeded = true;
        r->applied_ok = true;
    } else {
        r->flush_at = now;                                   /* reopened: what was requested meanwhile */
    }
    r->conn = c;
    r->next_poll = now + (int64_t)poll_ms;
    r->perr[0] = '\0';
    io->status_dirty = true;
    lg(LOG_INFO, "view '%s': reload requests: watching karidns_reload_requests (generation %llu%s)", v->name, (unsigned long long)r->last,
       r->has_status ? "" : "; no karidns_server_status table, the outcome is not written");
    return true;
}

/* top of the loop: the watchers follow the CONFIG (one per source), and the ones that have no connection get one */
static void rw_prepare(struct lio *io, bool load_follows) {
    int64_t now = now_ms();
    for (size_t i = 0; i < io->nrw; i++) {
        io->rw[i].in_cfg = false;
        io->rw[i].nv = 0;
    }
    const db_driver_t *drv = driver_find(io->cfg.driver);
    for (size_t i = 0; drv && drv->watch_requests && i < io->cfg.nviews; i++) {
        const lview_t *v = &io->cfg.views[i];
        rw_t *r = rw_find(io, v->source, v->conninfo);
        if (!r) {
            if (io->nrw >= RW_MAX) {
                lg(LOG_WARNING, "view '%s': more than %d database sources: reload requests are not watched for it", v->name, RW_MAX);
                continue;
            }
            r = &io->rw[io->nrw];
            memset(r, 0, sizeof(*r));
            r->drv = drv;
            r->applied_ok = true;
            r->source = v->source ? strdup(v->source) : NULL;
            r->conninfo = v->conninfo ? strdup(v->conninfo) : NULL;
            if ((v->source && !r->source) || (v->conninfo && !r->conninfo)) {
                free(r->source);
                free(r->conninfo);
                lg(LOG_ERR, "out of memory");
                continue;
            }
            io->nrw++;
        }
        if (r->nv == r->cv) {
            size_t nc = r->cv ? r->cv * 2 : 4;
            uint16_t *nvw = realloc(r->views, nc * sizeof(*nvw));
            if (!nvw) continue;
            r->views = nvw;
            r->cv = nc;
        }
        r->views[r->nv++] = v->index;
        r->in_cfg = true;
    }
    for (size_t i = 0; i < io->nrw;) {                       /* sources that left the configuration */
        if (io->rw[i].in_cfg) {
            i++;
            continue;
        }
        rw_free(&io->rw[i]);
        memmove(&io->rw[i], &io->rw[i + 1], (io->nrw - i - 1) * sizeof(io->rw[0]));
        io->nrw--;
        memset(&io->rw[io->nrw], 0, sizeof(io->rw[0]));
    }
    for (size_t i = 0; i < io->nrw; i++)
        if (!io->rw[i].conn && now >= io->rw[i].open_retry_at) rw_open(io, &io->rw[i], load_follows);
}

/* write the status row waiting in r (a failure is shown and tried again after RW_RETRY_MS) */
static void rw_try_report(struct lio *io, rw_t *r) {
    if (!r->rep_pending || !r->conn) return;
    db_status_t st = { r->rep_gen, r->rep_ok, r->rep_text, io->sid };
    int rc = r->drv->report_status(r->conn, &st);
    int64_t now = now_ms();
    if (rc == 0) {
        r->rep_pending = false;
        r->rep_time = (int64_t)time(NULL);
        if (r->rerr[0]) {
            const lview_t *v = rw_view0(io, r);
            lg(LOG_NOTICE, "view '%s': reload requests: the status row is written again", v ? v->name : "?");
            r->rerr[0] = '\0';
        }
        io->status_dirty = true;
        return;
    }
    rw_set_err(io, r, true, "cannot write karidns_server_status", r->drv->errmsg(r->conn));
    r->report_retry_at = now + RW_RETRY_MS;
    if (rc == DB_ERR_RETRY) {                                /* the connection is gone: reopen (which also checks for new requests) */
        rw_close(r);
        r->open_retry_at = now + (int64_t)rw_poll_ms(io, r);
    }
}

/* the outcome of generation gen: remember it and write it */
static void rw_report(struct lio *io, rw_t *r, uint64_t gen, bool ok, const char *text) {
    r->applied_ok = ok;
    io->status_dirty = true;
    sid_resolve(io);
    if (!io->sid_ok) {                                       /* sid_resolve() has warned (once); dbstatus says why */
        r->rep_pending = false;
        snprintf(r->rerr, sizeof(r->rerr), "the status row is not written: %s", io->sid_why);
        return;
    }
    if (!r->has_status) {
        r->rep_pending = false;
        rw_set_err(io, r, true, "the status row is not written", "this database has no karidns_server_status table");
        return;
    }
    if (!r->rep_text && !(r->rep_text = malloc(FZ_REPORT_BYTES + 1))) {
        r->rep_pending = false;
        lg(LOG_ERR, "out of memory");
        return;
    }
    snprintf(r->rep_text, FZ_REPORT_BYTES + 1, "%s", text);
    r->rep_gen = gen;
    r->rep_ok = ok;
    r->rep_pending = true;
    rw_try_report(io, r);
}

/* a request batch under construction */
typedef struct {
    uint64_t rows;
    bool all, force;
    size_t nz;
    char (*zone)[DNS_NAME_TEXT_SIZE];                        /* RW_ZONES canonical names */
    unsigned nbad;
    char bad[4][260];                                        /* the first invalid zone names (printable) */
} rq_batch_t;

static int rq_row(void *ud, const db_reload_row_t *row) {
    rq_batch_t *b = ud;
    b->rows++;
    if (row->force) b->force = true;
    if (!row->zone) {
        b->all = true;
        return 0;
    }
    char canon[DNS_NAME_TEXT_SIZE];
    if (!pdns_canonical_zone_name(row->zone, canon)) {       /* untrusted text: never hand it to a one-zone load as it is */
        if (b->nbad < 4) clean_reason(row->zone, b->bad[b->nbad], sizeof(b->bad[0]));
        b->nbad++;
        return 0;
    }
    if (b->all) return 0;
    for (size_t i = 0; i < b->nz; i++)
        if (names_equal(b->zone[i], canon)) return 0;
    if (b->nz >= RW_ZONES) {
        b->all = true;
        return 0;
    }
    snprintf(b->zone[b->nz++], DNS_NAME_TEXT_SIZE, "%s", canon);
    return 0;
}

/* Read the requests above r->last; when there are some, reload and report.  0, or -1 (fatal: stream, memory, stop). */
static int rw_process(ctx_t *x, struct lio *io, rw_t *r) {
    int64_t now = now_ms();
    uint64_t poll_ms = rw_poll_ms(io, r);
    if (!r->zbuf && !(r->zbuf = calloc(RW_ZONES, DNS_NAME_TEXT_SIZE))) {
        lg(LOG_ERR, "out of memory");
        return -1;
    }
    rq_batch_t bs;
    memset(&bs, 0, sizeof(bs));
    bs.zone = r->zbuf;
    rq_batch_t *b = &bs;
    uint64_t maxg = r->last;
    bool gap = false;
    int rc = r->drv->reload_requests(r->conn, r->last, rq_row, b, &maxg, &gap);
    if (rc != 0) {
        rw_set_err(io, r, false, "cannot read the requests", r->drv->errmsg(r->conn));
        if (rc == DB_ERR_RETRY) {
            rw_close(r);
            r->open_retry_at = now + (int64_t)poll_ms;
        } else {
            r->flush_at = now + (int64_t)poll_ms;
        }
        goto out;
    }
    if (b->rows == 0) {
        r->perr[0] = '\0';
        goto out;
    }
    if (gap) b->all = true;                                  /* requests between were pruned or rolled back: do not guess */
    fz_reset(&io->fz, true);
    for (unsigned i = 0; i < b->nbad && i < 4; i++)
        fz_add(&io->fz, r->views[0], b->bad[i], "not a valid zone name; the request is ignored", 44);
    int fail = 0;
    for (size_t vi = 0; vi < r->nv && !fail && !g_stop; vi++) {
        int lrc = 0;
        if (b->all) {
            lrc = do_load(x, io, KDB_BATCH_DIFF, (int)r->views[vi], NULL, 0, b->force, false);
        } else {
            for (size_t zi = 0; zi < b->nz && lrc == 0; zi++)
                lrc = do_load(x, io, KDB_BATCH_ZONE, (int)r->views[vi], b->zone[zi], 0, b->force, false);
        }
        if (lrc < 0) {
            io->fz.on = false;
            return -1;
        }
        if (lrc > 0) fail = 1;
    }
    io->fz.on = false;
    if (g_stop) return -1;                                   /* told to stop between two loads: nothing is counted as applied */
    if (fail) {                                              /* the position stays: the same requests are read again */
        rw_set_err(io, r, false, "cannot read the database", x->errtext[0] ? x->errtext : "the database could not be read");
        r->flush_at = now_ms() + (int64_t)poll_ms;
        goto out;
    }
    r->last = maxg;
    r->perr[0] = '\0';
    char text[FZ_REPORT_BYTES + 1];
    bool ok;
    fz_report(&io->fz, r->views, r->nv, text, &ok);
    const lview_t *v0 = rw_view0(io, r);
    lg(LOG_INFO, "view '%s': reload request(s) up to generation %llu applied (%s%s%s)", v0 ? v0->name : "?", (unsigned long long)maxg,
       b->all ? "all zones" : "listed zones", b->force ? ", force" : "", ok ? "" : "; some zones failed");
    rw_report(io, r, maxg, ok, text);
out:
    return 0;
}

/* before a load: collect the failures when a watcher waits for the outcome of the load that follows its opening */
static void rw_collect_begin(struct lio *io) {
    bool any = false;
    for (size_t i = 0; i < io->nrw; i++)
        if (io->rw[i].startup_seeded) any = true;
    fz_reset(&io->fz, any);
}

/* after a successful load: report its outcome for the watchers that were opened before it */
static void rw_load_report(struct lio *io) {
    for (size_t i = 0; i < io->nrw; i++) {
        rw_t *r = &io->rw[i];
        if (!r->startup_seeded) continue;
        r->startup_seeded = false;
        if (!r->conn || r->last == 0) continue;              /* no request was ever made: there is nothing to say */
        char text[FZ_REPORT_BYTES + 1];
        bool ok;
        fz_report(&io->fz, r->views, r->nv, text, &ok);
        rw_report(io, r, r->last, ok, text);
    }
    io->fz.on = false;
}

/* a notification (or a dead connection) on the watcher's socket */
static void rw_ready(struct lio *io, size_t ri) {
    if (ri >= io->nrw || !io->rw[ri].conn) return;
    rw_t *r = &io->rw[ri];
    bool changed = false;
    int rc = r->drv->drain_notifications(r->conn, &changed);
    int64_t now = now_ms();
    const lview_t *v0 = rw_view0(io, r);
    if (rc != 0) {
        rw_set_err(io, r, false, "the connection was lost", r->drv->errmsg(r->conn));
        rw_close(r);
        r->open_retry_at = now + (int64_t)rw_poll_ms(io, r);
        return;
    }
    if (changed && !r->flush_at) r->flush_at = now + (v0 ? (int64_t)v0->coalesce_ms : 0);
}

/* the request step of the loop, after the startup batch: 0, or -1 (fatal) */
static int rw_run(ctx_t *x, struct lio *io) {
    if (io->have_newcfg) return 0;                           /* a CONFIG is waiting: adopt it first */
    for (size_t i = 0; i < io->nrw && !g_stop; i++) {
        rw_t *r = &io->rw[i];
        int64_t now = now_ms();
        if (!rw_view0(io, r)) continue;
        if (!r->conn) {
            if (now >= r->open_retry_at) rw_open(io, r, false);
        } else if (now >= r->next_poll) {                    /* the safety net: read the table even when no notification came */
            r->next_poll = now + (int64_t)rw_poll_ms(io, r);
            if (!r->flush_at) r->flush_at = now;
        }
        if (r->conn && r->flush_at && now_ms() >= r->flush_at) {
            r->flush_at = 0;
            if (rw_process(x, io, r) != 0) return -1;
        }
        if (r->conn && r->rep_pending && now_ms() >= r->report_retry_at) rw_try_report(io, r);
        if (io->eof || io->failed) return 0;
    }
    return 0;
}

/* AUTO_STATUS: what `karictl dbstatus` shows for each view that has auto reload on or whose source has reload requests */
static int auto_send_status(ctx_t *x, struct lio *io) {
    bool any = false;
    if (kdb_enc_begin(&x->enc, KDB_T_AUTO_STATUS) != 0) return -1;
    for (size_t i = 0; i < io->cfg.nviews; i++) {
        const lview_t *v = &io->cfg.views[i];
        const rw_t *r = rw_for_view(io, v);
        bool au = v->auto_reload != 0;
        if (!au && !r) continue;
        int slot = vslot_get(io, v->name);
        if (slot < 0) return -1;
        const vstate_t *vs = &io->vst[slot];
        const char *err = !au ? "" : vs->lerr[0] ? vs->lerr : vs->perr;
        any = true;
        if (kdb_enc_nest_begin(&x->enc, 1) != 0 || kdb_enc_u16(&x->enc, 1, v->index) != 0 ||
            kdb_enc_u64(&x->enc, 2, au ? (uint64_t)vs->last_poll : 0) != 0 ||
            kdb_enc_u64(&x->enc, 3, au && vs->seq_valid ? vs->seq : 0) != 0 || kdb_enc_u32(&x->enc, 4, au ? vs->pending : 0) != 0 ||
            (err[0] && kdb_enc_str(&x->enc, 5, err) != 0) ||
            kdb_enc_u8(&x->enc, 6, (uint8_t)((au ? KDB_AS_AUTO : 0) | (r ? KDB_AS_REQ : 0))) != 0)
            return -1;
        if (r) {
            const char *rerr = r->rerr[0] ? r->rerr : r->perr;
            if ((io->sid_ok && kdb_enc_str(&x->enc, 7, io->sid) != 0) || kdb_enc_u64(&x->enc, 8, r->last) != 0 ||
                kdb_enc_u8(&x->enc, 9, r->applied_ok ? 1 : 0) != 0 || (rerr[0] && kdb_enc_str(&x->enc, 10, rerr) != 0) ||
                kdb_enc_u64(&x->enc, 11, (uint64_t)r->rep_time) != 0)
                return -1;
        }
        if (kdb_enc_nest_end(&x->enc) != 0) return -1;
    }
    if (!any || kdb_enc_end(&x->enc) != 0) {
        kdb_enc_reset(&x->enc);
        return any ? -1 : 0;
    }
    return send_enc(x);
}

/* send the AUTO_STATUS when something it shows changed */
static int status_flush(ctx_t *x, struct lio *io) {
    if (!io->status_dirty || g_stop) return 0;
    io->status_dirty = false;
    if (auto_send_status(x, io) != 0) {
        lg(LOG_ERR, "cannot write the output: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* the auto reload step of the loop, after the startup batch: 0, or -1 (fatal) */
static int auto_run(ctx_t *x, struct lio *io) {
    bool dirty = false;
    if (io->have_newcfg) return 0;                                     /* a CONFIG is waiting: adopt it first (view indexes, settings) */
    for (size_t i = 0; i < io->cfg.nviews && !g_stop; i++) {
        const lview_t *v = &io->cfg.views[i];
        if (!v->auto_reload) continue;
        int slot = vslot_get(io, v->name);
        if (slot < 0) {
            lg(LOG_ERR, "out of memory");
            return -1;
        }
        if (auto_view(x, io, v, (uint16_t)slot, &dirty) != 0) return -1;
        if (io->eof || io->failed) return 0;                           /* the main loop ends */
    }
    if (dirty) io->status_dirty = true;                                 /* sent by status_flush() once the request step has run too */
    return 0;
}

/* milliseconds until the next poll / coalesce deadline / reopen of any view with auto reload on, at most `limit` */
static int auto_wait_ms(const struct lio *io, int limit) {
    int64_t now = now_ms();
    for (size_t i = 0; i < io->cfg.nviews; i++) {
        const lview_t *v = &io->cfg.views[i];
        if (!v->auto_reload) continue;
        for (size_t s = 0; s < io->nvn; s++) {
            if (strcasecmp(io->vnames[s], v->name) != 0) continue;
            const vstate_t *vs = &io->vst[s];
            int64_t t = vs->pconn ? vs->next_poll : vs->open_retry_at;
            if (vs->flush_at && vs->flush_at < t) t = vs->flush_at;
            int64_t left = t - now;
            if (left < 0) left = 0;
            if (left < limit) limit = (int)left;
        }
    }
    for (size_t i = 0; i < io->nrw; i++) {                           /* B11: the request watchers */
        const rw_t *r = &io->rw[i];
        int64_t t = r->conn ? r->next_poll : r->open_retry_at;
        if (r->conn && r->flush_at && r->flush_at < t) t = r->flush_at;
        if (r->conn && r->rep_pending && r->report_retry_at < t) t = r->report_retry_at;
        int64_t left = t - now;
        if (left < 0) left = 0;
        if (left < limit) limit = (int)left;
    }
    return limit;
}

/* B10: the poll set of the main loop, io->pfs[0..n): the stream to the Backend, then the connections of the views with auto
 * reload on whose driver notifies (PostgreSQL LISTEN; wait_fd() is -1 for SQLite3, which is polled by timer).  A readable
 * connection makes its view due at once.  Returns n, or 0 on out of memory. */
static size_t auto_fds(struct lio *io, bool watch) {
    if (io->cpfs < 1 + io->nvn + RW_MAX) {
        size_t nc = 1 + io->nvn + RW_MAX + 8;
        struct pollfd *np = realloc(io->pfs, nc * sizeof(*np));
        if (!np) return 0;
        io->pfs = np;
        size_t *ns = realloc(io->pfs_slot, nc * sizeof(*ns));
        if (!ns) return 0;
        io->pfs_slot = ns;
        io->cpfs = nc;
    }
    io->pfs[0].fd = io->fd;
    io->pfs[0].events = POLLIN;
    io->pfs[0].revents = 0;
    size_t n = 1;
    for (size_t s = 0; watch && s < io->nvn; s++) {
        vstate_t *vs = &io->vst[s];
        if (!vs->pconn || !vs->pdrv->wait_fd) continue;
        int wfd = vs->pdrv->wait_fd(vs->pconn);
        if (wfd < 0) continue;
        io->pfs[n].fd = wfd;
        io->pfs[n].events = POLLIN;
        io->pfs[n].revents = 0;
        io->pfs_slot[n] = s;
        n++;
    }
    for (size_t i = 0; watch && i < io->nrw; i++) {                  /* B11: the connections that LISTEN karidns_reload */
        rw_t *r = &io->rw[i];
        if (!r->conn || !r->drv->wait_fd) continue;
        int wfd = r->drv->wait_fd(r->conn);
        if (wfd < 0) continue;
        io->pfs[n].fd = wfd;
        io->pfs[n].events = POLLIN;
        io->pfs[n].revents = 0;
        io->pfs_slot[n] = RW_FD_BASE + i;
        n++;
    }
    return n;
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
                for (size_t s = 0; s < io->nvn; s++) auto_close(&io->vst[s]);     /* B9: reopened below, before the load */
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
        auto_prepare(io, need_load);
        rw_prepare(io, need_load);                  /* B11: before the load, so that the generation it covers is the one read here */
        if (need_load) {
            need_load = false;
            rw_collect_begin(io);
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
                rw_load_report(io);
            } else {
                io->fz.on = false;                           /* a database error: retry with backoff, do not crash (design 1.2) */
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
        if (startup_done && auto_run(&x, io) != 0) {
            if (g_stop) goto stopped;
            status = EXIT_ERROR;
            goto done;
        }
        if (startup_done && (rw_run(&x, io) != 0 || status_flush(&x, io) != 0)) {
            if (g_stop) goto stopped;
            status = EXIT_ERROR;
            goto done;
        }
        int timeout = 1000;
        if (retry_pending) {
            int64_t left = retry_at - now_ms();
            if (left < 0) left = 0;
            if (left < timeout) timeout = (int)left;
        }
        if (startup_done) timeout = auto_wait_ms(io, timeout);
        size_t npf = auto_fds(io, startup_done);
        if (npf == 0) {
            lg(LOG_ERR, "out of memory");
            status = EXIT_ERROR;
            goto done;
        }
        int r = poll(io->pfs, (nfds_t)npf, timeout);
        if (r < 0 && errno != EINTR) {
            lg(LOG_ERR, "poll: %s", strerror(errno));
            status = EXIT_ERROR;
            goto done;
        }
        if (r > 0) {
            for (size_t i = 1; i < npf; i++) {
                if (!io->pfs[i].revents) continue;
                if (io->pfs_slot[i] >= RW_FD_BASE) rw_ready(io, io->pfs_slot[i] - RW_FD_BASE);     /* B11: a reload request */
                else io->vst[io->pfs_slot[i]].next_poll = 0;      /* a notification (or a dead connection): look now */
            }
            if (io->pfs[0].revents) io_pump(io);
        }
    }
stopped:
    if (g_stop) lg(LOG_NOTICE, "stopping on a signal");
    else if (io->eof) lg(LOG_NOTICE, "the Backend closed the stream; exiting");
    else if (io->failed) status = EXIT_ERROR;
done:
    ctx_view_reset(&x);
    kdb_enc_free(&x.enc);
    for (size_t i = 0; i < io->nrw; i++) rw_free(&io->rw[i]);
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
        "  karidns-dbloader --dump OUT --driver postgresql --conninfo-file FILE [--schema NAME] [options]\n"
        "  karidns-dbloader -s FD                    (stream mode; started by karidns, not by hand)\n"
        "  karidns-dbloader --drivers                (print the compiled-in drivers, one per line)\n"
        "  karidns-dbloader --check --driver DRIVER --database-file PATH [options]       (read only; what `karicheck db` runs)\n"
        "  karidns-dbloader --check --driver postgresql --conninfo-file FILE [--schema NAME] [options]\n"
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
        "With auto-reload yes it also polls PRAGMA data_version of each database every poll-interval seconds and, a coalesce\n"
        "window after the first change, sends one batch of kind auto with the same comparison (docs/karidns.md).\n"
        "It logs to syslog and ends when the Backend closes the stream or on SIGTERM / SIGINT; SIGHUP is ignored.\n"
        "--check (what `karicheck db` runs) reads the same tables through the same code, sends nothing, writes nothing to the database,\n"
        "and prints what is wrong or odd as lines of the check protocol on standard output (dns_db_checkproto.h): the schema, every zone\n"
        "(the reader's errors with records.id, the zone checks of `karicheck zone`), the settings texts, the views a zone is mapped to.\n"
        "Run it as the user the loader runs as (karicheck does that for root); its output is meant to be read by karicheck.\n"
        "\n"
        "options:\n"
        "  --dump OUT          write the stream to the file OUT (\"-\" = standard output)\n"
        "  --driver DRIVER     database driver; compiled in: %s\n"
        "  --database-file F   sqlite3: the database file; it must be in WAL mode.  The name is used byte for byte\n"
        "                      ('%%XX' is not decoded); a name starting with \"file:\" is refused (write ./file:...)\n"
        "  --conninfo-file F   postgresql: the file holding the libpq connection string (owned by the user running the loader,\n"
        "                      mode 0600 or 0400; its content is never logged)\n"
        "  --schema NAME       postgresql: the schema that holds the tables (default: the search_path of the role)\n"
        "  --view-index N      view index in ZONE_BEGIN / ZONE_FAILED (0..65535, default 0)\n"
        "  --zone NAME         dump only this zone (read with one query per zone instead of the bulk scan)\n"
        "  --default-ttl N     TTL for a records.ttl that is NULL (1..2147483647, default 3600)\n"
        "  --loader-threads N  1..16, default 1.  N workers, each with its own connection, read and convert disjoint sets of\n"
        "                      zones; the output is written in domains.id order whatever N is, so the bytes are the same\n"
        "  --map-view NAME     keep only the zones karidns_domain_views maps to the view NAME (a domain without a row is kept):\n"
        "                      what a view that uses the shared source of a server gets (docs/karidns.md)\n"
        "  --check             check mode (see above); no --dump.  Exit status 0: nothing wrong, 1: errors found, 3 / 4 as below\n"
        "  --auto-reload       with --check: auto-reload is on, so the change log triggers are required\n"
        "  --server-id ID      with --check (postgresql): the server-id of the configuration\n"
        "  --ecs-tag NAME      with --check: a tag of options { ecs-tags }; repeatable (records may name it)\n"
        "  --location-tag NAME with --check: a tag of options { location-tags }; repeatable\n"
        "  --max-zone-records N, --max-zone-bytes N   with --check: the limits of the database block\n"
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
        "  karidns-dbloader --dump /tmp/view1.kdb --driver sqlite3 --database-file view1.sqlite3 --view-index 1 --default-ttl 300\n"
        "  karidns-dbloader --dump /tmp/zones.kdb --driver postgresql --conninfo-file /usr/local/etc/karidns/database.conf --schema pdns\n",
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
        { "check", no_argument, NULL, 1001 },              { "auto-reload", no_argument, NULL, 1002 },
        { "server-id", required_argument, NULL, 1003 },    { "ecs-tag", required_argument, NULL, 1004 },
        { "location-tag", required_argument, NULL, 1005 }, { "max-zone-records", required_argument, NULL, 1006 },
        { "max-zone-bytes", required_argument, NULL, 1007 },
        { "help", no_argument, NULL, 'h' },                { NULL, 0, NULL, 0 }
    };
    const char *dump = NULL, *driver = NULL, *dbfile = NULL, *conninfo = NULL, *schema = NULL, *zone = NULL, *map_view = NULL;
    const char *stream_fd = NULL;
    unsigned long view = 0, ttl = 0, threads = 1, v, max_records = 0, max_bytes = 0;
    bool check = false, chk_auto = false;                 // B12
    const char *chk_server_id = NULL;
    const char *chk_ecs[256], *chk_loc[256];
    int n_chk_ecs = 0, n_chk_loc = 0;
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
        case 1001: check = true; break;
        case 1002: chk_auto = true; break;
        case 1003: chk_server_id = optarg; break;
        case 1004:
        case 1005:
            if (ch == 1004 ? n_chk_ecs >= 256 : n_chk_loc >= 256) {
                fprintf(stderr, "karidns-dbloader: at most 256 --ecs-tag and 256 --location-tag\n");
                return EXIT_USAGE;
            }
            if (ch == 1004) chk_ecs[n_chk_ecs++] = optarg;
            else chk_loc[n_chk_loc++] = optarg;
            break;
        case 1006:
            if (!parse_uint(optarg, 2, 4294967295ul, &max_records)) {
                fprintf(stderr, "karidns-dbloader: --max-zone-records must be 2..4294967295\n");
                return EXIT_USAGE;
            }
            break;
        case 1007:
            if (!parse_uint(optarg, 65535, 1ul << 36, &max_bytes)) {
                fprintf(stderr, "karidns-dbloader: --max-zone-bytes must be 65535..68719476736\n");
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
        if (dump || driver || dbfile || conninfo || schema || zone || map_view || check) {
            fprintf(stderr, "karidns-dbloader: -s cannot be combined with the dump options\n");
            return EXIT_USAGE;
        }
        return stream_main((int)v);
    }
    if (check && (dump || zone || map_view)) {
        fprintf(stderr, "karidns-dbloader: --check cannot be combined with --dump, --zone or --map-view\n");
        return EXIT_USAGE;
    }
    if (!check && (chk_auto || chk_server_id || n_chk_ecs || n_chk_loc || max_records || max_bytes)) {
        fprintf(stderr, "karidns-dbloader: --auto-reload, --server-id, --ecs-tag, --location-tag, --max-zone-records and --max-zone-bytes are for --check\n");
        return EXIT_USAGE;
    }
    if ((!dump && !check) || !driver) {
        fprintf(stderr, "karidns-dbloader: --dump (or --check) and --driver are required\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    const db_driver_t *drv = driver_find(driver);
    if (!drv) {
        char list[128];
        drivers_list(list, sizeof(list));
        if (strcmp(driver, "postgresql") == 0 || strcmp(driver, "sqlite3") == 0)
            fprintf(stderr, "karidns-dbloader: driver %s is not available in this build (%s; compiled in: %s)\n", driver,
                    strcmp(driver, "postgresql") == 0 ? "built without DB_DRIVERS=postgresql" : "built without DB_DRIVERS=sqlite3",
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
    if (strcmp(drv->name, "postgresql") == 0 && !conninfo) {
        fprintf(stderr, "karidns-dbloader: driver postgresql needs --conninfo-file\n");
        return EXIT_USAGE;
    }
    if (strcmp(drv->name, "postgresql") == 0 && dbfile) {
        fprintf(stderr, "karidns-dbloader: --database-file is for the sqlite3 driver\n");
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
    if (check) {                       /* B12: one source, read only, the findings as lines of the check protocol on standard output */
        x.check = true;
        x.nthreads = 1;
        x.opts.max_records = max_records;
        x.opts.max_zone_bytes = max_bytes;
        x.chk_opts.auto_reload = chk_auto;
        x.chk_opts.server_id = chk_server_id;
        ecs_tag_def_t *tags = calloc((size_t)n_chk_ecs + (size_t)n_chk_loc + 1, sizeof(*tags));
        if (!tags) {
            fprintf(stderr, "karidns-dbloader: out of memory\n");
            return EXIT_ERROR;
        }
        for (int i = 0; i < n_chk_ecs; i++) tags[i].tag = (char *)chk_ecs[i];       /* the zone checks only compare the names */
        for (int i = 0; i < n_chk_loc; i++) tags[n_chk_ecs + i].tag = (char *)chk_loc[i];
        x.chk_ecs = tags;
        x.chk_necs = n_chk_ecs;
        x.chk_loc = tags + n_chk_ecs;
        x.chk_nloc = n_chk_loc;
        g_chk_out = stdout;
        setvbuf(stdout, NULL, _IOLBF, 0);
        db_source_t csrc = { drv->name, dbfile, conninfo, schema, 0 };
        int cst = run_check(&x, &csrc);
        fprintf(stdout, "R\t%u\t%u\t%u\n", x.chk_zones, g_chk_errors, g_chk_warnings);
        if (fflush(stdout) != 0 && cst < EXIT_ERROR) cst = EXIT_ERROR;
        ctx_view_reset(&x);
        kdb_enc_free(&x.enc);
        free(tags);
        return cst;
    }
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

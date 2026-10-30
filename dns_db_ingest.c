/*
 * dns_db_ingest.c - the db ingest thread of the Backend (see dns_db_ingest.h).
 *
 * The stream state is owned by one thread; the threads that touch it are the configuration trigger (an EVFILT_USER
 * event) and, with `ingest-threads` N > 1, N builder threads that parse and publish complete zones.  There is no
 * mutex of its own: builders get their job through an atomic slot and a per-builder kqueue, hand the result back on a
 * lock-free stack and an EVFILT_USER event, and share the DB zone registry under the existing
 * g_zone_db_rebuild_lock (dns_snapshot_rcu.c).  The configuration is read inside an RCU read section
 * (rcu_aux_read_lock) and copied.  Everything from the stream is untrusted: dns_db_stream.c validates it, a protocol
 * violation closes the stream (the loader then ends and the supervisor restarts it), a zone that fails its checks is
 * rejected alone and keeps its last good version.
 *
 * Allocation happens on the load path only (start, stream buffers, zones), never on the query path.
 */
#include "dns_db_ingest.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_log.h"
#include <time.h>
#include <unistd.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "dns_config_parser.h"
#include "dns_db_install.h"
#include "dns_db_stream.h"
#include "dns_epoch_rcu.h"
#include "dns_park.h"
#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"

_Static_assert(KARIDNS_DB_MAX_VIEWS == KDB_MAX_CONFIG_VIEWS, "the configuration check and the CONFIG message must agree");

#define ING_MAX_OUT (32u << 20)  /* queued answers the loader has not read: above this the loader is dropped */
#define ING_ZONES_LOGGED 16       /* zones logged one by one per connection */
#define ING_REJECTS_LOGGED 100    /* rejected zones logged one by one per batch */
#define ING_READ_ROUNDS 16
#define ING_EVT_CONFIG 1          /* EVFILT_USER idents of the main kqueue */
#define ING_EVT_RESULT 2
#define ING_EVT_REQ 3             /* karictl reload requests from the control thread (SPSC ring g_rq) */
#define ING_REQ_MAX 32            /* reload requests waiting for the loader's answer (the control thread parks as many clients) */
#define RQ_RING 64                /* both rings: more than ING_REQ_MAX, so a ring never fills while the bound holds */
#define ING_RETIRE_EVERY 1024     /* design 4.3: a blocking grace period every this many published zones */
#define ING_DELTA_MS 1000         /* design 4.4: new zones become visible at least this often */
#define ING_INV_CHUNK 400         /* INVENTORY entries per message */
#define ING_INV_QUEUE_LOW (256u << 10)
#define ING_MAX_BUILDERS 16
#define ING_RBUF 65536
#define ING_FLUSH_AT 16384        /* queued bytes that are written at once; the rest goes out after the event round */
#define ING_FETCH_MAX 256         /* fetches in flight (D1a): more is refused, the queries then wait for their own deadline */
/* a fetch the loader has not answered by then is given up (the queries have timed out long before); a variable for the unit test */
#define STATIC_TEST
STATIC_TEST int64_t g_ing_fetch_timeout_ms = 30000;
#define ING_FETCH_OUT_MAX (1u << 20)

typedef struct {
  uint64_t generation;
  char driver[40];
  uint32_t nviews;
  uint64_t max_zone_records, max_zone_bytes;
  uint32_t ingest_threads;
  bool auto_reload;
  uint32_t poll_interval, coalesce_ms;
  bool enabled;
} ing_cfg_t;

/* one zone on its way from ZONE_BEGIN to ZONE_RESULT */
typedef struct ing_job {
  struct ing_job *next;                  /* result stack */
  uint16_t view;
  char view_name[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
  int64_t source_id;
  uint32_t serial;
  uint64_t rr_count;
  uint8_t digest[KDB_DIGEST_LEN];
  db_zone_build_t *build;
  bool skip;                             /* decided at ZONE_BEGIN: the data is discarded, the zone is rejected */
  bool failed;                           /* a ZONE_DATA message was refused */
  uint8_t zkind;                          /* B7b: KDB_ZK_*; secondary (SLAVE) and catalog (CONSUMER) zones have no data: the masters are in the settings */
  zone_ext_shared_t *shared;             /* B7a: the interned settings of the zone (this job holds a reference), NULL = none */
  uint8_t *buf;                        /* ingest-threads > 1: the ZONE_DATA messages, [u32 length][bytes] each */
  size_t buf_len, buf_cap;
  uint8_t status;                        /* KDB_ST_* */
  int builder;                           /* index of the builder it was handed to */
  char reason[KDB_REASON_LEN];
  /* D1a, the fetch stream: the request the zone answers (0 = a zone of a batch), a summary (no data: what the directory keeps), a zone
   * nobody asked for (discarded; the loader may answer a request that was given up) */
  uint64_t fetch_id;
  bool summary, unsolicited, has_timers;
  uint32_t t_refresh, t_retry, t_expire;
} ing_job_t;

/* a fetch in flight: sent to the loader on the fetch stream, not answered yet */
typedef struct {
  bool active;
  uint64_t id;
  uint16_t view;                         /* the index in the CONFIG of the loader */
  uint8_t prio, mode;
  int64_t sent_ms;
  char view_name[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
} ing_freq_t;

typedef struct {
  pthread_t tid;
  int kq;
  _Atomic(ing_job_t *) slot;
} ing_builder_t;

/* B7a: the PROFILE messages of the batch (design 1.4): a zone names its profile in ZONE_BEGIN, the profile's text comes
 * before it.  A later PROFILE of the same name replaces the earlier one (two views may read different databases).  The
 * table is the stream thread's; a zone resolves its settings at ZONE_BEGIN, so builders never see it. */
#define ING_MAX_PROFILES 4096
#define ING_PROFILE_BYTES (16u << 20)  /* a hostile loader cannot make the Backend hold more than this */
typedef struct {
  char name[256];
  char *text;
  size_t len;
} ing_profile_t;

typedef struct {
  int kq, wait_kq, ctrl_fd, stream_fd;
  bool write_armed;
  uint8_t *body;               /* KDB_MAX_BODY */
  uint8_t *rbuf;               /* ING_RBUF */
  kdb_framer_t fr;
  kdb_sm_t sm;
  kdb_enc_t enc;
  uint8_t *out;                /* answers queued for the loader */
  size_t out_len, out_off, out_cap;
  bool hello_done, need_cleanup;
  /* view index -> name, as of the CONFIG last sent */
  char (*view_names)[KARIDNS_VIEW_NAME_MAX];
  uint8_t *view_db;            /* [index]: the view takes zones from the database (not "database none;") */
  uint32_t nview_names;
  /* the zone being received */
  ing_job_t *cur;
  uint32_t zones_logged;
  uint32_t rejects_logged;
  ing_profile_t *profiles;     /* of the current batch */
  size_t nprof, cprof, prof_bytes;
  /* batch */
  bool in_batch;
  uint64_t batch_id;
  uint8_t batch_kind;
  uint32_t b_applied, b_rejected, b_shadowed, b_deleted, b_failed;
  /* builders and work in flight */
  uint32_t nbuilders;          /* 0 = the stream thread builds */
  ing_builder_t builders[ING_MAX_BUILDERS];
  ing_job_t *flight[ING_MAX_BUILDERS];  /* the job each builder works on, until its result was taken (stream thread only) */
  _Atomic(ing_job_t *) res_head;
  uint32_t inflight;
  uint32_t since_retire;
  int64_t last_delta_ms;
  /* INVENTORY in progress */
  bool inv_active;
  dbreg_cursor_t inv_cur;
  uint64_t inv_sent;
  /* reload requests sent to the loader whose answer the control thread is waiting for (B6a, design 5.2) */
  struct {
    bool active;
    uint64_t id;
    uint16_t view;
    char view_name[KARIDNS_VIEW_NAME_MAX];
    char zone[DNS_NAME_TEXT_SIZE];
    int grp;                   /* >= 0: one view of a request that asks every view (grps[grp]) */
  } reqs[ING_REQ_MAX];
  /* B6b: `reload <zone>` without a view while several views take database zones: one RELOAD_REQ per view (ids with the
   * top bit set, so they cannot clash with the control thread's), one combined answer for the control thread */
  struct {
    bool active;
    uint64_t ctl_id;
    int pending;
    bool any_ok, any_bad;
    char zone[DNS_NAME_TEXT_SIZE];
    char text[200];
  } grps[ING_REQ_MAX];
  uint64_t sub_seq;
  int cur_req;                 /* the request the current batch answers (BATCH_BEGIN request_id), -1 = none */
  int req_outcome;             /* what the batch did to the requested zone: ROUT_* */
  uint32_t req_serial;
  char req_reason[KDB_REASON_LEN];
  /* D1a: the fetch stream, the second KDB1 stream (design 6.1).  Its own framer, state machine and output queue; the zones that come on it go
   * through the same jobs as the batch zones (job_execute()), with their own profile table (prof_swap()) and no ZONE_RESULT. */
  int fetch_fd;
  bool fwrite_armed;
  uint8_t *fbody;              /* KDB_MAX_BODY */
  kdb_framer_t ffr;
  kdb_sm_t fsm;
  kdb_enc_t fenc;
  uint8_t *fout;               /* FETCH_REQ messages not written yet */
  size_t fout_len, fout_off, fout_cap;
  ing_job_t *fcur;             /* the zone being received on the fetch stream */
  ing_profile_t *fprofiles;
  size_t fnprof, fcprof, fprof_bytes;
  uint64_t fseq;               /* request ids */
  uint32_t nfreq;
  ing_freq_t freq[ING_FETCH_MAX];
  uint32_t funsolicited;       /* zones nobody asked for, discarded (logged the first few) */
} ing_t;

enum { ROUT_NONE = 0, ROUT_APPLIED, ROUT_SHADOWED, ROUT_REJECTED, ROUT_FAILED, ROUT_DELETED };
static void answer_request(ing_t *g);
static void fetch_adopt(ing_t *g, int fd);
static void fetch_drop(ing_t *g);
static void fetch_fail_all(ing_t *g, const char *why);

static ing_t g_ing;
static _Atomic bool g_cfg_dirty;
static _Atomic int g_ing_kq = -1;
static _Atomic uint64_t g_last_change_seq;   /* what the last BATCH_BEGIN said (design 1.4, INVENTORY_END) */

/* ------------------------------------------------------------------------------------------------------------- */
/* karictl reload: control thread <-> ingest thread, two single-producer single-consumer rings (no mutex)         */
/* ------------------------------------------------------------------------------------------------------------- */

enum { RQ_ALL = 1, RQ_ZONE, RQ_CANCEL };
typedef struct {
  uint8_t type;
  bool force;
  uint64_t id;
  char view[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
} rq_item_t;

static rq_item_t g_rq[RQ_RING];              /* producer: the control thread; consumer: the ingest thread */
static _Atomic uint32_t g_rq_head, g_rq_tail;
static db_reload_result_t g_rs[RQ_RING];     /* producer: the ingest thread; consumer: the control thread */
static _Atomic uint32_t g_rs_head, g_rs_tail;
static uint64_t g_next_req_id;               /* control thread only */

/* ingest thread: queue an answer for the control thread and wake it */
static void post_result(uint64_t id, bool ok, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void post_result(uint64_t id, bool ok, const char *fmt, ...) {
  uint32_t t = atomic_load_explicit(&g_rs_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_rs_head, memory_order_acquire);
  if (t - h >= RQ_RING) {
    syslog(LOG_ERR, "[DB] the answer queue for the control thread is full; the answer to request %llu is dropped",
           (unsigned long long)id);
    return;
  }
  db_reload_result_t *r = &g_rs[t % RQ_RING];
  r->id = id;
  r->ok = ok;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(r->text, sizeof(r->text), fmt, ap);
  va_end(ap);
  atomic_store_explicit(&g_rs_tail, t + 1, memory_order_release);
  int ckq = atomic_load_explicit(&g_control_kq, memory_order_acquire);
  if (ckq >= 0) {
    struct kevent ev;
    EV_SET(&ev, DB_INGEST_CTL_EVENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(ckq, &ev, 1, NULL, 0, NULL);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* status for `karictl dbstatus`: written by the stream thread, read by the control thread                        */
/* ------------------------------------------------------------------------------------------------------------- */

#define ST_STR 200
static struct {
  _Atomic bool connected, ever_connected, batch_done;
  _Atomic uint32_t pid, b_applied, b_rejected, b_shadowed, b_deleted;
  _Atomic int64_t since;                                    /* connected since / disconnected since */
  _Atomic uint64_t tot_applied, tot_rejected, tot_shadowed, tot_deleted, tot_failed;
  _Atomic uint64_t tot_auto_batches;                        /* B9: batches of kind auto since the start */
  _Atomic uint64_t batch_id;
  _Atomic int batch_kind;
  _Atomic int64_t batch_time;
  _Atomic uint32_t seq;                                     /* seqlock of the strings (one writer) */
  _Atomic char err[ST_STR], ver[ST_STR];
  _Atomic int64_t err_time;
} g_st;

static void st_str_set(_Atomic char *dst, const char *src, size_t n) {
  size_t i = 0;
  for (; src && i + 1 < n && src[i]; i++) atomic_store_explicit(&dst[i], src[i], memory_order_relaxed);
  atomic_store_explicit(&dst[i], '\0', memory_order_relaxed);
}

static void st_str_get(const _Atomic char *src, char *dst, size_t n) {
  size_t i = 0;
  for (; i + 1 < n; i++) {
    char c = atomic_load_explicit(&src[i], memory_order_relaxed);
    dst[i] = c;
    if (!c) return;
  }
  dst[i] = '\0';
}

static void st_set_strings(const char *err, const char *ver) {
  uint32_t s = atomic_load_explicit(&g_st.seq, memory_order_relaxed);
  atomic_store_explicit(&g_st.seq, s + 1, memory_order_release);
  atomic_thread_fence(memory_order_seq_cst);
  if (err) {
    st_str_set(g_st.err, err, ST_STR);
    atomic_store_explicit(&g_st.err_time, (int64_t)time(NULL), memory_order_relaxed);
  }
  if (ver) st_str_set(g_st.ver, ver, ST_STR);
  atomic_store_explicit(&g_st.seq, s + 2, memory_order_release);
}

static void st_get_strings(char *err, size_t en, char *ver, size_t vn, int64_t *err_time) {
  for (int tries = 0; tries < 1000; tries++) {
    uint32_t s1 = atomic_load_explicit(&g_st.seq, memory_order_acquire);
    if (s1 & 1) continue;
    st_str_get(g_st.err, err, en);
    st_str_get(g_st.ver, ver, vn);
    *err_time = atomic_load_explicit(&g_st.err_time, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    if (atomic_load_explicit(&g_st.seq, memory_order_acquire) == s1) return;
  }
}

/* B9: what the loader reports about auto reload (AUTO_STATUS), per view index; written by the stream thread (one writer, a
 * seqlock per entry), read by the control thread for `karictl dbstatus`.  B11: the same entry carries the multi-server reload
 * request state of the view's source (the server id, the last request applied and whether it loaded every zone, the last error
 * of reading requests or writing the status row); as_data_t is the plain copy the two sides exchange. */
#define AS_ERR 120
#define AS_SID 68
typedef struct {
  int64_t last_poll;
  uint64_t applied_seq;
  uint32_t pending;
  char err[AS_ERR];
  unsigned flags;                    /* KDB_AS_AUTO: last_poll .. err are real; KDB_AS_REQ: the rest is real */
  char server_id[AS_SID];
  uint64_t req_generation;
  bool req_ok;
  char req_err[AS_ERR];
  int64_t req_time;
} as_data_t;

static struct as_ent {
  _Atomic uint32_t seq;
  _Atomic bool valid;
  _Atomic int64_t last_poll;
  _Atomic uint64_t applied_seq;
  _Atomic uint32_t pending;
  _Atomic char err[AS_ERR];
  _Atomic unsigned flags;
  _Atomic char server_id[AS_SID];
  _Atomic uint64_t req_generation;
  _Atomic bool req_ok;
  _Atomic char req_err[AS_ERR];
  _Atomic int64_t req_time;
} g_as[KARIDNS_DB_MAX_VIEWS];

/* printable ASCII only, whatever the loader sent */
static void as_put_str(_Atomic char *dst, size_t cap, const char *src, size_t n) {
  size_t i = 0;
  for (; src && i < n && i + 1 < cap; i++)
    atomic_store_explicit(&dst[i], (src[i] >= 0x20 && src[i] <= 0x7E) ? src[i] : '?', memory_order_relaxed);
  atomic_store_explicit(&dst[i], '\0', memory_order_relaxed);
}

static void as_set(struct as_ent *a, const as_data_t *d, const char *err, size_t errn, const char *sid, size_t sidn, const char *rerr, size_t rerrn) {
  uint32_t s = atomic_load_explicit(&a->seq, memory_order_relaxed);
  atomic_store_explicit(&a->seq, s + 1, memory_order_release);
  atomic_thread_fence(memory_order_seq_cst);
  atomic_store_explicit(&a->last_poll, d->last_poll, memory_order_relaxed);
  atomic_store_explicit(&a->applied_seq, d->applied_seq, memory_order_relaxed);
  atomic_store_explicit(&a->pending, d->pending, memory_order_relaxed);
  as_put_str(a->err, AS_ERR, err, errn);
  atomic_store_explicit(&a->flags, d->flags, memory_order_relaxed);
  as_put_str(a->server_id, AS_SID, sid, sidn);
  atomic_store_explicit(&a->req_generation, d->req_generation, memory_order_relaxed);
  atomic_store_explicit(&a->req_ok, d->req_ok, memory_order_relaxed);
  as_put_str(a->req_err, AS_ERR, rerr, rerrn);
  atomic_store_explicit(&a->req_time, d->req_time, memory_order_relaxed);
  atomic_store_explicit(&a->valid, true, memory_order_relaxed);
  atomic_store_explicit(&a->seq, s + 2, memory_order_release);
}

static bool as_get(struct as_ent *a, as_data_t *d) {
  for (int tries = 0; tries < 1000; tries++) {
    uint32_t s1 = atomic_load_explicit(&a->seq, memory_order_acquire);
    if (s1 & 1) continue;
    bool valid = atomic_load_explicit(&a->valid, memory_order_relaxed);
    d->last_poll = atomic_load_explicit(&a->last_poll, memory_order_relaxed);
    d->applied_seq = atomic_load_explicit(&a->applied_seq, memory_order_relaxed);
    d->pending = atomic_load_explicit(&a->pending, memory_order_relaxed);
    st_str_get(a->err, d->err, sizeof(d->err));
    d->flags = atomic_load_explicit(&a->flags, memory_order_relaxed);
    st_str_get(a->server_id, d->server_id, sizeof(d->server_id));
    d->req_generation = atomic_load_explicit(&a->req_generation, memory_order_relaxed);
    d->req_ok = atomic_load_explicit(&a->req_ok, memory_order_relaxed);
    st_str_get(a->req_err, d->req_err, sizeof(d->req_err));
    d->req_time = atomic_load_explicit(&a->req_time, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    if (atomic_load_explicit(&a->seq, memory_order_acquire) == s1) return valid;
  }
  return false;
}

static void as_reset(void) {                                /* a new loader: what the old one said is stale */
  for (size_t i = 0; i < KARIDNS_DB_MAX_VIEWS; i++) atomic_store_explicit(&g_as[i].valid, false, memory_order_relaxed);
}

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* rights                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

/* Design 1.3: the stream may be read, written and watched, nothing else (no fcntl, no shutdown, no sockopt). */
static void limit_stream_rights(int fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_READ, CAP_WRITE, CAP_EVENT);
  if (cap_rights_limit(fd, &r) != 0 && errno != ENOSYS)
    syslog(LOG_ERR, "[DB] cannot limit the rights of the loader stream: %s", strerror(errno));
}

static void limit_ctrl_rights(int fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_RECV, CAP_EVENT);
  if (cap_rights_limit(fd, &r) != 0 && errno != ENOSYS)
    syslog(LOG_ERR, "[DB] cannot limit the rights of the loader control socket: %s", strerror(errno));
}

/* ------------------------------------------------------------------------------------------------------------- */
/* configuration snapshot                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

static void fill_snap(const server_config_t *cfg, ing_cfg_t *c) {
  memset(c, 0, sizeof(*c));
  if (cfg && cfg->database.enabled) {
    c->enabled = true;
    c->generation = cfg->generation;
    snprintf(c->driver, sizeof(c->driver), "%s", cfg->database.driver ? cfg->database.driver : "");
    for (const view_config_t *v = cfg->views; v; v = v->next) c->nviews++;
    c->max_zone_records = cfg->database.max_zone_records;
    c->max_zone_bytes = cfg->database.max_zone_bytes;
    c->ingest_threads = cfg->database.ingest_threads;
    c->auto_reload = cfg->database.auto_reload;
    c->poll_interval = cfg->database.poll_interval;
    c->coalesce_ms = cfg->database.coalesce_ms;
  }
}

static void snapshot_cfg(ing_cfg_t *c) {
  rcu_aux_read_lock();
  fill_snap(acquire_config_snapshot(), c);
  rcu_aux_read_unlock();
}

/* Only printable ASCII goes into a TLV `str` (the loader refuses anything else): other bytes become '?'. */
static void enc_sane_str(kdb_enc_t *e, uint16_t tag, const char *s) {
  char buf[256];
  size_t n = 0;
  for (; s && *s && n < sizeof(buf) - 1; s++) buf[n++] = (*s >= 0x20 && *s <= 0x7E) ? *s : '?';
  buf[n] = '\0';
  kdb_enc_str(e, tag, buf);
}

static void sane_copy(char *dst, size_t cap, const char *s, size_t n) {
  size_t i = 0;
  for (; i + 1 < cap && i < n && s[i]; i++) dst[i] = (s[i] >= 0x20 && s[i] <= 0x7E) ? s[i] : '?';
  dst[i] = '\0';
}

/* CONFIG from the active configuration (design 1.4).  A view that takes no DB zones ("database none;") is left
 * out; the others carry their own source or, if they have none, the global one (the loader needs a path for every
 * view it reads; "absent = shared source" of the design is expressed by repeating the global path).  Views are
 * numbered by their position in the configuration; the names are remembered so that ZONE_BEGIN's index can be
 * turned into a view name.  false: no database block, or too many views. */
static bool build_config(ing_t *g, ing_cfg_t *snap) {
  bool ok = false;
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  if (cfg && cfg->database.enabled) {
    const database_config_t *db = &cfg->database;
    bool sqlite = db->driver && strcmp(db->driver, "sqlite3") == 0;
    fill_snap(cfg, snap);
    free(g->view_names);
    free(g->view_db);
    g->view_names = snap->nviews ? calloc(snap->nviews, sizeof(*g->view_names)) : NULL;
    g->view_db = snap->nviews ? calloc(snap->nviews, 1) : NULL;
    g->nview_names = g->view_names && g->view_db ? snap->nviews : 0;
    kdb_enc_reset(&g->enc);
    kdb_enc_begin(&g->enc, KDB_T_CONFIG);
    kdb_enc_u64(&g->enc, 1, cfg->generation);
    kdb_enc_str(&g->enc, 2, db->driver);
    if (db->server_id) enc_sane_str(&g->enc, 3, db->server_id);
    uint32_t idx = 0, listed = 0;
    for (const view_config_t *v = cfg->views; v; v = v->next, idx++) {
      if (g->view_names && idx < g->nview_names) snprintf(g->view_names[idx], sizeof(g->view_names[idx]), "%s", v->name ? v->name : "");
      if (v->database_none) continue;
      if (g->view_db && idx < g->nview_names) g->view_db[idx] = 1;
      const char *src = sqlite ? (v->database_file ? v->database_file : db->database_file)
                               : (v->database_schema ? v->database_schema : db->schema);
      if (listed >= KDB_MAX_CONFIG_VIEWS) break;
      listed++;
      kdb_enc_nest_begin(&g->enc, 4);
      kdb_enc_u16(&g->enc, 1, (uint16_t)idx);
      enc_sane_str(&g->enc, 2, v->name);
      if (src) kdb_enc_str(&g->enc, 3, src);
      if (!sqlite && db->conninfo_file) kdb_enc_str(&g->enc, 4, db->conninfo_file);
      kdb_enc_u8(&g->enc, 5, db->auto_reload ? 1 : 0);
      kdb_enc_u32(&g->enc, 6, db->poll_interval);
      kdb_enc_u32(&g->enc, 7, db->coalesce_ms);
      kdb_enc_u64(&g->enc, 8, db->max_zone_records);
      kdb_enc_u64(&g->enc, 9, db->max_zone_bytes);
      /* B6b (design 7.1): a view on the global source gets the zones karidns_domain_views maps to it */
      if (sqlite ? !v->database_file : !v->database_schema) kdb_enc_u8(&g->enc, 10, 1);
      kdb_enc_nest_end(&g->enc);
    }
    kdb_enc_u32(&g->enc, 5, db->default_ttl);
    kdb_enc_u8(&g->enc, 6, (uint8_t)db->bulk_threshold);
    kdb_enc_u32(&g->enc, 7, db->loader_threads);
    ok = kdb_enc_end(&g->enc) == 0 && idx <= 0xFFFF && (snap->nviews == 0 || (g->view_names && g->view_db));
  }
  rcu_aux_read_unlock();
  return ok;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* output queue                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static void drop_stream(ing_t *g);

static void arm_write(ing_t *g, bool on) {
  if (g->write_armed == on || g->stream_fd < 0) return;
  struct kevent ev;
  EV_SET(&ev, g->stream_fd, EVFILT_WRITE, on ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, &ev, 1, NULL, 0, NULL) == 0) g->write_armed = on;
}

static void out_flush(ing_t *g) {
  while (g->stream_fd >= 0 && g->out_off < g->out_len) {
    ssize_t n = write(g->stream_fd, g->out + g->out_off, g->out_len - g->out_off);
    if (n > 0) {
      g->out_off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      arm_write(g, true);
      return;
    }
    syslog(LOG_NOTICE, "[DB] loader disconnected (write: %s)", n < 0 ? strerror(errno) : "closed");
    drop_stream(g);
    return;
  }
  if (g->stream_fd >= 0) {
    g->out_len = g->out_off = 0;
    arm_write(g, false);
  }
}

/* queue the message built in g->enc and try to send it */
static void send_enc(ing_t *g) {
  if (g->enc.err) {
    syslog(LOG_ERR, "[DB] internal error: cannot encode a message for the loader; closing the stream");
    drop_stream(g);
    return;
  }
  if (g->stream_fd < 0) return;
  if (g->out_len - g->out_off + g->enc.len > ING_MAX_OUT) {
    syslog(LOG_ERR, "[DB] the loader does not read its answers (%zu bytes queued); closing the stream",
           g->out_len - g->out_off);
    drop_stream(g);
    return;
  }
  if (g->out_off > 0 && g->out_off == g->out_len) g->out_len = g->out_off = 0;
  if (g->out_len + g->enc.len > g->out_cap) {
    size_t nc = g->out_cap ? g->out_cap : 4096;
    while (nc < g->out_len + g->enc.len) nc *= 2;
    uint8_t *nb = realloc(g->out, nc);
    if (!nb) {
      syslog(LOG_ERR, "[DB] out of memory queueing an answer for the loader; closing the stream");
      drop_stream(g);
      return;
    }
    g->out = nb;
    g->out_cap = nc;
  }
  memcpy(g->out + g->out_len, g->enc.buf, g->enc.len);
  g->out_len += g->enc.len;
  kdb_enc_reset(&g->enc);
  /* many small answers (one ZONE_RESULT per zone) go out in one write: here when a chunk has gathered, otherwise at
   * the end of the event round in ingest_thread() */
  if (g->out_len - g->out_off >= ING_FLUSH_AT) out_flush(g);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* jobs                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

static void job_free(ing_job_t *j) {
  if (!j) return;
  db_zone_build_free(j->build);
  zone_ext_shared_unref(j->shared);
  free(j->buf);
  free(j);
}

static void job_reject(ing_job_t *j, const char *why) {
  j->status = KDB_ST_REJECTED;
  snprintf(j->reason, sizeof(j->reason), "%s", why);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* settings of DB zones (B7a, design 1.3, 3.5, 4.2)                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

/* do the ACL entries a..b overlap?  Two prefixes overlap when the shorter one contains the other's network. */
static bool cidr_overlap(const cidr_entry_t *a, const cidr_entry_t *b, bool *b_contains_a) {
  if (a->is_any || b->is_any) {
    *b_contains_a = b->is_any;
    return true;
  }
  if (!a->valid || !b->valid || a->family != b->family) return false;
  unsigned p = a->prefix < b->prefix ? a->prefix : b->prefix;
  for (unsigned i = 0; i < 16 && i * 8 < p; i++) {
    unsigned bits = p - i * 8;
    uint8_t m = bits >= 8 ? 0xFF : (uint8_t)(0xFF << (8 - bits));
    if ((a->addr[i] & m) != (b->addr[i] & m)) return false;
  }
  *b_contains_a = b->prefix <= a->prefix;
  return true;
}

/* How acl-ceiling cuts the ACLs of x: "<statement> <entry> <outside|narrowed by> the ceiling; ...".  Returns the length;
 * an empty text means nothing is cut.  Only address entries are judged here: whether a request is inside the ceiling also
 * depends on its key (dns_tsig_acl.c), but an address entry outside every ceiling address can only be used together with a
 * key the ceiling names. */
static size_t ceiling_notes(const server_config_t *cfg, const zone_ext_t *x, char *out, size_t cap) {
  size_t n = 0;
  if (cap) out[0] = '\0';
  bool have_acl = x->allow_transfer_count > 0 || x->tsig_keys_count > 0 || x->allow_update_count > 0;
  bool have_ecs = x->ecs_trusted_resolvers_count > 0;          /* B8: the trusted resolvers are bounded by the ceiling too */
  if (!have_acl && !have_ecs) return 0;
#define NOTE(...) do { if (n + 1 < cap) { int w_ = snprintf(out + n, cap - n, __VA_ARGS__); if (w_ > 0) n = (size_t)w_ < cap - n ? n + (size_t)w_ : cap - 1; } } while (0)
  if (!db_acl_ceiling_configured(cfg)) {
    if (have_acl) NOTE("no acl-ceiling is configured: these ACLs refuse everybody");
    if (have_ecs) NOTE("%sno acl-ceiling is configured: no resolver of ecs-trusted-resolvers is trusted", have_acl ? "; " : "");
    return n;
  }
  const database_config_t *d = &cfg->database;
  for (int pass = 0; pass < 3; pass++) {
    const char *what = pass == 0 ? "allow-transfer" : pass == 1 ? "allow-update" : "ecs-trusted-resolvers";
    char *const *list = pass == 0 ? x->allow_transfer : pass == 1 ? x->allow_update : x->ecs_trusted_resolvers;
    const acl_entry_t *parsed = pass == 0 ? x->allow_transfer_parsed : pass == 1 ? x->allow_update_parsed : x->ecs_trusted_resolvers_parsed;
    int count = pass == 0 ? x->allow_transfer_count : pass == 1 ? x->allow_update_count : x->ecs_trusted_resolvers_count;
    for (int i = 0; parsed && i < count; i++) {
      if (!parsed[i].cidr.valid || parsed[i].is_deny) continue;      /* a key name, none, or an exclusion */
      bool inside = false, overlaps = false;
      for (int k = 0; k < d->acl_ceiling_count && d->acl_ceiling_parsed; k++) {
        if (!d->acl_ceiling_parsed[k].cidr.valid || d->acl_ceiling_parsed[k].is_deny) continue;
        bool contains = false;
        if (cidr_overlap(&parsed[i].cidr, &d->acl_ceiling_parsed[k].cidr, &contains)) {
          overlaps = true;
          if (contains) inside = true;
        }
      }
      if (!inside)
        NOTE("%s %.64s %s; ", what, list[i], overlaps ? "is narrowed by acl-ceiling" : "lies outside acl-ceiling");
    }
  }
#undef NOTE
  return n;
}

/* Resolve the settings of a zone: the text of its profile followed by its own text, parsed in the restricted mode of the
 * configuration parser (statement by statement the zone overrides the profile: the loader sends both texts and the
 * Backend merges them, so a hostile loader cannot get a statement past the whitelist by the way it splits them).  The
 * result is interned: zones with the same texts share one parsed object.  Every TSIG key the settings name must exist in
 * karidns.conf now.  *out: a new reference (NULL = no settings at all).  false: the zone is rejected, why says why. */
static const ing_profile_t *find_profile(const ing_t *g, const char *name, size_t len) {
  for (size_t i = 0; i < g->nprof; i++)
    if (strlen(g->profiles[i].name) == len && memcmp(g->profiles[i].name, name, len) == 0) return &g->profiles[i];
  return NULL;
}

static _Atomic bool g_ceiling_warned;

static bool check_settings_against_config(const zone_ext_shared_t *sh, const char *zone, char *why, size_t whylen) {
  bool ok = true;
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  const char *missing = db_settings_missing_key(&sh->ext, cfg);
  if (missing) {
    char shown[72];
    sane_copy(shown, sizeof(shown), missing, strlen(missing));
    snprintf(why, whylen, "the settings name the TSIG key '%s', which is not defined in karidns.conf", shown);
    ok = false;
  } else if ((sh->ext.allow_transfer_count > 0 || sh->ext.tsig_keys_count > 0 || sh->ext.allow_update_count > 0 ||
              sh->ext.ecs_trusted_resolvers_count > 0) &&
             !db_acl_ceiling_configured(cfg) && !atomic_exchange_explicit(&g_ceiling_warned, true, memory_order_relaxed)) {
    syslog(LOG_WARNING, "[DB] zone '%s' has ACLs in its database settings, but options { database { acl-ceiling } } is not "
                        "configured: database ACLs refuse every client until it is (this is logged once)", zone);
  }
  rcu_aux_read_unlock();
  return ok;
}

static bool resolve_zone_settings(ing_t *g, ing_job_t *j, const kdb_zone_begin_t *zb) {
  const char *ztext = zb->settings.p ? zb->settings.p : "";
  size_t zlen = zb->settings.p ? zb->settings.len : 0;
  size_t pnlen = zb->profile.p ? zb->profile.len : 0;
  if (pnlen == 0 && zlen == 0) return true;               /* no metadata: the defaults, no ACLs */
  const ing_profile_t *prof = NULL;
  if (pnlen) {
    prof = find_profile(g, zb->profile.p, pnlen);
    if (!prof) {
      char shown[72];
      sane_copy(shown, sizeof(shown), zb->profile.p, pnlen);
      char msg[KDB_REASON_LEN];
      snprintf(msg, sizeof(msg), "the profile '%s' is not defined (karidns_profiles) or was not sent", shown);
      job_reject(j, msg);
      return false;
    }
  }
  const char *ptext = prof ? prof->text : "";
  size_t ptlen = prof ? prof->len : 0;
  /* what makes two settings the same: profile name, profile text, zone text */
  size_t klen = pnlen + 1 + ptlen + 1 + zlen;
  char *key = malloc(klen + 1);
  if (!key) {
    job_reject(j, "out of memory");
    return false;
  }
  memcpy(key, zb->profile.p ? zb->profile.p : "", pnlen);
  key[pnlen] = '\0';
  memcpy(key + pnlen + 1, ptext, ptlen);
  key[pnlen + 1 + ptlen] = '\0';
  memcpy(key + pnlen + 2 + ptlen, ztext, zlen);
  key[klen] = '\0';
  zone_ext_shared_t *sh = db_settings_find(key, klen);
  char err[200];
  if (!sh) {
    char *merged = malloc(ptlen + 1 + zlen + 1);
    if (!merged) {
      free(key);
      job_reject(j, "out of memory");
      return false;
    }
    memcpy(merged, ptext, ptlen);
    merged[ptlen] = '\n';
    memcpy(merged + ptlen + 1, ztext, zlen);
    /* each text must be complete on its own (a profile that opens a block it never closes would swallow the zone's
     * statements); then the two together, the zone's statements after the profile's */
    zone_ext_shared_t *t;
    char msg[KDB_REASON_LEN];
    bool bad = false;
    if (ptlen > 0 && zlen > 0) {
      if (!(t = db_settings_parse(ptext, ptlen, err, sizeof(err)))) {
        snprintf(msg, sizeof(msg), "profile text: %.150s", err);
        bad = true;
      } else {
        zone_ext_shared_unref(t);
        if (!(t = db_settings_parse(ztext, zlen, err, sizeof(err)))) {
          snprintf(msg, sizeof(msg), "zone settings: %.150s", err);
          bad = true;
        } else {
          zone_ext_shared_unref(t);
        }
      }
    }
    if (!bad && !(sh = db_settings_parse(merged, ptlen + 1 + zlen, err, sizeof(err)))) {
      snprintf(msg, sizeof(msg), "%s: %.150s", ptlen > 0 && zlen == 0 ? "profile text" : "settings", err);
      bad = true;
    }
    free(merged);
    if (bad) {
      free(key);
      job_reject(j, msg);
      return false;
    }
    sh->key = key;
    sh->key_len = klen;
    sh->hash = db_settings_hash(key, klen);
    if (pnlen) sane_copy(sh->profile, sizeof(sh->profile), zb->profile.p, pnlen);
    sh = db_settings_intern(sh);
    rcu_aux_read_lock();
    const server_config_t *ccfg = acquire_config_snapshot();
    char notes[400];
    if (db_acl_ceiling_configured(ccfg) && ceiling_notes(ccfg, &sh->ext, notes, sizeof(notes)) > 0)
      syslog(LOG_WARNING, "[DB] zone '%s' (first zone with these settings): %s", j->zone, notes);
    rcu_aux_read_unlock();
  } else {
    free(key);
  }
  char why[KDB_REASON_LEN];
  if (!check_settings_against_config(sh, j->zone, why, sizeof(why))) {
    zone_ext_shared_unref(sh);
    job_reject(j, why);
    return false;
  }
  j->shared = sh;
  return true;
}

/* the ixfr-history depth of the entry follows its settings (and options { ixfr-history }) */
static void apply_ixfr_depth(zone_db_entry_t *e, const zone_config_t *dc) {
  rcu_aux_read_lock();
  ixfr_history_set_depth(e, ixfr_history_effective(acquire_config_snapshot(), dc));
  rcu_aux_read_unlock();
}

/* A new entry for a DB zone (design 4.2): source DB, its settings block (interned settings or none).  zkind: a primary (its data
 * comes in ZONE_DATA), or (B7b) a secondary / catalog consumer, which the existing secondary machinery of the control thread
 * transfers from the masters in its settings (refresh timer, SOA retry and expire, NOTIFY, IXFR), like a configured one. */
static zone_db_entry_t *new_db_entry(const char *view, const char *zone, zone_ext_shared_t *shared, uint8_t zkind) {
  zone_db_entry_t *e = create_new_zone_entry(zone, view);
  if (!e) return NULL;
  zone_config_t *dc = db_zone_config_new_kind(zone, shared, zkind == KDB_ZK_PRIMARY ? 0 : zkind == KDB_ZK_SECONDARY ? 1 : 2);
  if (!dc) {
    free_zone_db_entry(e);
    return NULL;
  }
  e->source = ZONE_SRC_DB;
  e->kind = zkind == KDB_ZK_PRIMARY ? ZONE_KIND_PRIMARY : ZONE_KIND_SECONDARY;
  e->is_secondary = zkind != KDB_ZK_PRIMARY;
  atomic_store_explicit(&e->dbcfg, dc, memory_order_release);
  apply_ixfr_depth(e, dc);
  return e;
}

/* does the settings block of the entry already hold exactly these settings? */
static bool entry_has_settings(const zone_db_entry_t *e, const zone_ext_shared_t *sh) {
  const zone_config_t *c = atomic_load_explicit(&e->dbcfg, memory_order_acquire);
  if (!c) return false;
  return sh ? (c->ext_shared && c->ext == &sh->ext) : (c->ext == NULL);
}

/* B7b: ZONE_END of a secondary (SLAVE) or catalog consumer (CONSUMER) zone: there is no data.  The zone's entry is created, or its
 * settings are replaced (new masters or key: the zone is re-pointed and asked to refresh at once), and entered in the registry
 * with the serial and digest the loader sent (serial 0, the digest of the settings), which is what a restarted loader compares:
 * a zone that did not change is not sent again, so nothing is transferred again.  What the entry holds (the zone it transferred
 * from the masters) is not touched here, and it lives in memory only. */
static void job_execute_secondary(ing_job_t *j) {
  zone_db_entry_t *entry = dbreg_lookup_entry(j->view_name, j->zone);
  bool created = false;
  if (entry) {
    const zone_config_t *oc = atomic_load_explicit(&entry->dbcfg, memory_order_acquire);
    /* the zone was a primary, or a SLAVE became a CONSUMER (or back): a new entry replaces it */
    if (entry->source != ZONE_SRC_DB || !entry->is_secondary || !oc || oc->is_catalog != (j->zkind == KDB_ZK_CATALOG)) entry = NULL;
  }
  if (!entry) {
    entry = new_db_entry(j->view_name, j->zone, j->shared, j->zkind);
    if (!entry) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    created = true;
  } else if (!entry_has_settings(entry, j->shared)) {
    zone_config_t *nc = db_zone_config_new_kind(j->zone, j->shared, j->zkind == KDB_ZK_CATALOG ? 2 : 1);
    if (!nc) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    db_entry_set_config(entry, nc);
    apply_ixfr_depth(entry, nc);
    atomic_store_explicit(&entry->refresh_now, true, memory_order_release);      /* the masters or the key may have changed */
  }
  bool shadowed = false;
  if (dbreg_commit(j->view_name, j->zone, entry, created, j->source_id, j->serial, j->digest, &shadowed) != 0) {
    if (created) free_zone_db_entry(entry);
    job_reject(j, "out of memory registering the zone");
    goto rejected;
  }
  j->status = shadowed ? KDB_ST_SHADOWED : KDB_ST_APPLIED;
  return;
rejected:
  (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
}

/* ZONE_END work, on the stream thread (ingest-threads 1) or a builder: feed what was buffered, check, publish the
 * image into the entry, enter the zone in the registry.  Sets j->status / j->reason; the reply is the caller's. */
static void job_execute(ing_job_t *j) {
  if (j->skip) {                                         /* status and reason were set at ZONE_BEGIN */
    /* (a zone nobody asked for, or a fetch that was refused, is not a rejection of the zone: its last good version, if any, keeps serving) */
    if (j->view_name[0] && !j->unsolicited && !j->fetch_id) (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
    return;
  }
  if (j->summary) {                                      /* D1a: serial and SOA timers for the directory; nothing to install */
    j->status = dbreg_apply_summary(j->view_name, j->zone, j->source_id, j->serial, j->has_timers, j->t_refresh, j->t_retry, j->t_expire)
                    ? KDB_ST_APPLIED
                    : KDB_ST_UNCHANGED;
    return;
  }
  if (j->zkind != KDB_ZK_PRIMARY) {
    job_execute_secondary(j);
    return;
  }
  /* ingest-threads > 1: the messages were buffered by the stream thread */
  for (size_t off = 0; j->buf && !j->failed && off + 4 <= j->buf_len;) {
    uint32_t n;
    memcpy(&n, j->buf + off, 4);
    off += 4;
    if (db_zone_build_feed(j->build, j->buf + off, n, j->reason, sizeof(j->reason)) != 0) j->failed = true;
    off += n;
  }
  free(j->buf);
  j->buf = NULL;
  if (j->failed) {                                       /* j->reason says why */
    j->status = KDB_ST_REJECTED;
    goto rejected;
  }
  zone_db_entry_t *entry = dbreg_lookup_entry(j->view_name, j->zone);
  bool created = false;
  if (entry && entry->is_secondary) entry = NULL;          /* B7b: the zone was a SLAVE / CONSUMER; a new primary entry replaces it */
  if (!entry) {
    entry = new_db_entry(j->view_name, j->zone, j->shared, KDB_ZK_PRIMARY);
    if (!entry) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    created = true;
  }
  /* B7a: the settings that came with the data are in force while the data is installed (also-notify, the response cache
   * and the NOTIFY after the install read them); when the data is refused the previous settings are put back, so a zone
   * that keeps serving its last good version also keeps its last good settings */
  const zone_config_t *old_cfg = NULL, *new_cfg = NULL;
  uint64_t cfg_epoch = 0;
  if (!created && !entry_has_settings(entry, j->shared)) {
    zone_config_t *nc = db_zone_config_new(j->zone, j->shared);
    if (!nc) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    new_cfg = nc;
    old_cfg = db_entry_swap_config(entry, nc, &cfg_epoch);
    apply_ixfr_depth(entry, nc);
  }
  if (db_zone_build_install(j->build, entry, NULL, j->reason, sizeof(j->reason)) != 0) {
    if (created) {
      free_zone_db_entry(entry);                         /* never registered or published into a snapshot */
    } else if (new_cfg) {
      uint64_t e2;
      (void)db_entry_swap_config(entry, old_cfg, &e2);   /* take the previous settings back ... */
      db_entry_retire_config(entry, new_cfg, e2);        /* ... and retire the ones that were refused */
      if (old_cfg) apply_ixfr_depth(entry, old_cfg);
    }
    j->status = KDB_ST_REJECTED;
    goto rejected;
  }
  if (new_cfg) db_entry_retire_config(entry, old_cfg, cfg_epoch);
  bool shadowed = false;
  if (dbreg_commit(j->view_name, j->zone, entry, created, j->source_id, atomic_load(&entry->serial), j->digest,
                   &shadowed) != 0) {
    if (created) free_zone_db_entry(entry);
    job_reject(j, "out of memory registering the zone");
    goto rejected;
  }
  j->serial = atomic_load(&entry->serial);
  j->status = shadowed ? KDB_ST_SHADOWED : KDB_ST_APPLIED;
  db_zone_build_free(j->build);
  j->build = NULL;
  return;
rejected:
  (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
  db_zone_build_free(j->build);
  j->build = NULL;
}

static void *builder_thread(void *arg) {
  ing_builder_t *b = arg;
  ing_t *g = &g_ing;
  rcu_aux_thread_pin();
  struct kevent ev;
  burst_yield_t by = BURST_YIELD_INIT;
  for (;;) {
    if (kevent(b->kq, NULL, 0, &ev, 1, NULL) < 0) {
      if (errno == EINTR) continue;
      syslog(LOG_ERR, "[DB] a builder thread stops: kevent: %s", strerror(errno));
      return NULL;
    }
    ing_job_t *j = atomic_exchange_explicit(&b->slot, NULL, memory_order_acquire);
    if (!j) continue;
    burst_yield_check(&by);                /* a batch of a million zones: the pinned worker on this CPU gets its turns */
    job_execute(j);
    ing_job_t *h = atomic_load_explicit(&g->res_head, memory_order_relaxed);
    do {
      j->next = h;
    } while (!atomic_compare_exchange_weak_explicit(&g->res_head, &h, j, memory_order_release, memory_order_relaxed));
    struct kevent t;
    EV_SET(&t, ING_EVT_RESULT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(g->kq, &t, 1, NULL, 0, NULL);
    EV_SET(&t, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(g->wait_kq, &t, 1, NULL, 0, NULL);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* replies and bookkeeping (stream thread)                                                                        */
/* ------------------------------------------------------------------------------------------------------------- */

static void send_zone_result(ing_t *g, uint16_t view, const char *zone, uint8_t status, const char *reason) {
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_ZONE_RESULT) != 0 || kdb_enc_u16(&g->enc, 1, view) != 0 ||
      kdb_enc_name(&g->enc, 2, zone) != 0 || kdb_enc_u8(&g->enc, 3, status) != 0 ||
      (reason && reason[0] && (enc_sane_str(&g->enc, 4, reason), g->enc.err)) || kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

static void fetch_job_finish(ing_t *g, ing_job_t *j);

/* the answer of a finished job; the job is freed */
static void job_finish(ing_t *g, ing_job_t *j) {
  if (j->fetch_id) {                                     /* D1a: a zone of the fetch stream has no ZONE_RESULT, it wakes the queries that wait for it */
    fetch_job_finish(g, j);
    return;
  }
  switch (j->status) {
  case KDB_ST_APPLIED:
    g->b_applied++;
    atomic_fetch_add_explicit(&g_st.tot_applied, 1, memory_order_relaxed);
    g->since_retire++;
    if (g->zones_logged < ING_ZONES_LOGGED) {
      g->zones_logged++;
      syslog(LOG_INFO, "[DB] zone '%s' (view '%s'): installed, serial %u", j->zone, j->view_name, j->serial);
    }
    break;
  case KDB_ST_SHADOWED:
    g->b_shadowed++;
    atomic_fetch_add_explicit(&g_st.tot_shadowed, 1, memory_order_relaxed);
    g->since_retire++;
    {
      dbreg_info_t si;
      bool cat = dbreg_find_info(j->view_name, j->zone, &si, 1) > 0 && si.shadow_by == DBREG_SH_CATALOG;
      syslog(LOG_WARNING, "[DB] zone '%s' (view '%s'): loaded, but hidden by %s", j->zone, j->view_name,
             cat ? "a catalog member of the same name" : "the zone in karidns.conf");
    }
    break;
  default:
    g->b_rejected++;
    atomic_fetch_add_explicit(&g_st.tot_rejected, 1, memory_order_relaxed);
    if (g->rejects_logged < ING_REJECTS_LOGGED) {
      g->rejects_logged++;
      syslog(LOG_WARNING, "[DB] zone '%s' (view '%s') rejected: %s; the last good version, if any, keeps serving",
             j->zone, j->view_name, j->reason);
    }
    break;
  }
  if (g->cur_req >= 0 && g->reqs[g->cur_req].view == j->view && domain_names_match_ci(g->reqs[g->cur_req].zone, j->zone)) {
    g->req_outcome = j->status == KDB_ST_APPLIED ? ROUT_APPLIED : j->status == KDB_ST_SHADOWED ? ROUT_SHADOWED : ROUT_REJECTED;
    g->req_serial = j->serial;
    snprintf(g->req_reason, sizeof(g->req_reason), "%s", j->status == KDB_ST_REJECTED ? j->reason : "");
  }
  send_zone_result(g, j->view, j->zone, j->status, j->status == KDB_ST_REJECTED ? j->reason : NULL);
  job_free(j);
}

static void retire_if_due(ing_t *g, bool force) {
  if (g->since_retire >= ING_RETIRE_EVERY || force) {
    zone_retire_process(true);                           /* outside any read section; a grace period for the batch */
    g->since_retire = 0;
  }
}

static void apply_delta(ing_t *g) {
  if (dbreg_pending_count() == 0) return;
  (void)snapshot_apply_db_delta();
  g->last_delta_ms = now_ms();
}

/* publish new zones when a second has passed since the last time (design 4.4: the first DB zones appear early) */
static void maybe_apply_delta(ing_t *g) {
  if (dbreg_pending_count() > 0 && now_ms() - g->last_delta_ms >= ING_DELTA_MS) apply_delta(g);
}

static void drain_results(ing_t *g) {
  ing_job_t *list = atomic_exchange_explicit(&g->res_head, NULL, memory_order_acquire);
  while (list) {
    ing_job_t *j = list;
    list = j->next;
    g->inflight--;
    g->flight[j->builder] = NULL;
    job_finish(g, j);
  }
  retire_if_due(g, false);
  maybe_apply_delta(g);
}

/* block until a builder reports a result (or a second has passed) */
static void wait_for_result(ing_t *g) {
  struct kevent ev;
  struct timespec ts = { 1, 0 };
  (void)kevent(g->wait_kq, NULL, 0, &ev, 1, &ts);
  drain_results(g);
}

static void drain_all(ing_t *g) {
  drain_results(g);
  while (g->inflight > 0) wait_for_result(g);
}

/* Everything in flight is done and published, the new zones are visible and the old versions are being reclaimed */
static void sync_all(ing_t *g) {
  drain_all(g);
  apply_delta(g);
  retire_if_due(g, true);
}

static bool name_in_flight(ing_t *g, const ing_job_t *me) {
  /* in-flight zones of the same name must finish first: two builders would race on one registry record */
  for (uint32_t i = 0; i < g->nbuilders; i++) {
    const ing_job_t *j = g->flight[i];
    if (j && j->view == me->view && domain_names_match_ci(j->zone, me->zone)) return true;
  }
  return false;
}

/* hand a complete zone over (or build it here) */
static void job_submit(ing_t *g, ing_job_t *j) {
  if (g->nbuilders == 0 || j->skip) {
    job_execute(j);
    job_finish(g, j);
    retire_if_due(g, false);
    maybe_apply_delta(g);
    return;
  }
  for (;;) {
    int free_b = -1;
    for (uint32_t i = 0; i < g->nbuilders; i++) {
      if (!g->flight[i]) {
        free_b = (int)i;
        break;
      }
    }
    /* a finished job stays "same name in flight" until its result was taken */
    if (free_b >= 0 && !name_in_flight(g, j)) {
      ing_builder_t *b = &g->builders[free_b];
      j->builder = free_b;
      g->flight[free_b] = j;
      atomic_store_explicit(&b->slot, j, memory_order_release);
      g->inflight++;
      struct kevent t;
      EV_SET(&t, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
      (void)kevent(b->kq, &t, 1, NULL, 0, NULL);
      return;
    }
    wait_for_result(g);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* messages                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static void protocol_error(ing_t *g, const char *reason);

static void clear_profiles(ing_t *g) {
  for (size_t i = 0; i < g->nprof; i++) free(g->profiles[i].text);
  g->nprof = 0;
  g->prof_bytes = 0;
}

/* PROFILE (design 1.4): name and settings text, valid for the zones that follow in this batch.  The state machine has
 * checked the characters and the lengths; the Backend bounds what it holds (a hostile loader cannot make it keep more). */
enum { PROF_OK = 0, PROF_LIMIT, PROF_OOM };

static int profile_store(ing_t *g, const kdb_msg_t *m) {
  const kdb_profile_t *p = &m->u.profile;
  size_t i;
  for (i = 0; i < g->nprof; i++)
    if (strlen(g->profiles[i].name) == p->name.len && memcmp(g->profiles[i].name, p->name.p, p->name.len) == 0) break;
  size_t old = i < g->nprof ? g->profiles[i].len : 0;
  if (g->prof_bytes - old + p->settings.len > ING_PROFILE_BYTES || (i == g->nprof && g->nprof >= ING_MAX_PROFILES)) return PROF_LIMIT;
  char *copy = malloc(p->settings.len + 1);
  if (!copy) return PROF_OOM;
  memcpy(copy, p->settings.p, p->settings.len);
  copy[p->settings.len] = '\0';
  if (i == g->nprof) {
    if (g->nprof == g->cprof) {
      size_t nc = g->cprof ? g->cprof * 2 : 16;
      ing_profile_t *np = realloc(g->profiles, nc * sizeof(*np));
      if (!np) {
        free(copy);
        return PROF_OOM;
      }
      g->profiles = np;
      g->cprof = nc;
    }
    memcpy(g->profiles[i].name, p->name.p, p->name.len);
    g->profiles[i].name[p->name.len] = '\0';
    g->nprof++;
  } else {
    free(g->profiles[i].text);
    g->prof_bytes -= old;
  }
  g->profiles[i].text = copy;
  g->profiles[i].len = p->settings.len;
  g->prof_bytes += p->settings.len;
  return PROF_OK;
}

static void on_profile(ing_t *g, const kdb_msg_t *m) {
  int rc = profile_store(g, m);
  if (rc == PROF_LIMIT) {
    protocol_error(g, "PROFILE: more profile data in a batch than the Backend accepts");
  } else if (rc == PROF_OOM) {
    syslog(LOG_ERR, "[DB] out of memory; closing the stream");
    drop_stream(g);
  }
}

static void fail_requests(ing_t *g, const char *why) {
  for (int i = 0; i < ING_REQ_MAX; i++) {
    if (!g->reqs[i].active) continue;
    int grp = g->reqs[i].grp;
    if (grp < 0) {
      post_result(g->reqs[i].id, false, "zone %s (view %s): %s", g->reqs[i].zone, g->reqs[i].view_name, why);
    } else if (g->grps[grp].active) {          /* one answer for the group, under the id the control thread knows */
      post_result(g->grps[grp].ctl_id, false, "zone %s: %s", g->grps[grp].zone, why);
      g->grps[grp].active = false;
    }
    g->reqs[i].active = false;
  }
  g->cur_req = -1;
}

static void drop_stream(ing_t *g) {
  fail_requests(g, "the connection to the database loader was lost; the reload may or may not have been applied");
  if (g->stream_fd >= 0) close(g->stream_fd); /* the kqueue forgets the descriptor */
  g->stream_fd = -1;
  g->write_armed = false;
  g->out_len = g->out_off = 0;
  g->hello_done = false;
  g->inv_active = false;
  g->need_cleanup = true;                     /* zones in flight are finished by the main loop, not from here */
  kdb_enc_reset(&g->enc);
  if (atomic_exchange_explicit(&g_st.connected, false, memory_order_relaxed))
    atomic_store_explicit(&g_st.since, (int64_t)time(NULL), memory_order_relaxed);
}

/* the stream is gone (or replaced): throw away the partial zone, let the zones in flight finish, publish them */
static void cleanup_stream_state(ing_t *g) {
  g->need_cleanup = false;
  job_free(g->cur);
  g->cur = NULL;
  g->in_batch = false;
  clear_profiles(g);
  drain_all(g);
  apply_delta(g);
  retire_if_due(g, true);
}

static void send_config(ing_t *g, const char *why) {
  ing_cfg_t snap;
  if (!build_config(g, &snap)) {
    syslog(LOG_ERR, "[DB] cannot build CONFIG for the loader (no database block, or more than %d views); "
                    "closing the stream", KDB_MAX_CONFIG_VIEWS);
    drop_stream(g);
    return;
  }
  /* the state machine checks view indexes and limits against the configuration it was sent */
  g->sm.lim.view_count = snap.nviews;
  g->sm.lim.max_zone_records = snap.max_zone_records;
  g->sm.lim.max_zone_bytes = snap.max_zone_bytes;
  g->fsm.lim = g->sm.lim;                  /* the fetch stream's machine checks against the same configuration */
  syslog(LOG_INFO, "[DB] sent CONFIG generation %llu to the loader (%s): driver %s, %u view(s)",
         (unsigned long long)snap.generation, why, snap.driver, snap.nviews);
  send_enc(g);
}

/* does the comma separated list of the loader's drivers contain name? */
static bool driver_listed(const char *list, size_t len, const char *name) {
  size_t nl = strlen(name);
  size_t i = 0;
  while (i <= len) {
    size_t j = i;
    while (j < len && list[j] != ',') j++;
    if (j - i == nl && memcmp(list + i, name, nl) == 0) return true;
    i = j + 1;
  }
  return false;
}

static void on_hello(ing_t *g, const kdb_msg_t *m) {
  const kdb_hello_t *h = &m->u.hello;
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  syslog(LOG_INFO, "[DB] loader connected: pid %u, version %.*s, drivers %.*s", h->pid, (int)h->loader_version.len,
         h->loader_version.p, (int)h->driver.len, h->driver.p);
  if (!snap.enabled || !driver_listed(h->driver.p, h->driver.len, snap.driver)) {
    syslog(LOG_ERR, "[DB] driver %s is not available in the loader (it has: %.*s); closing the stream", snap.driver,
           (int)h->driver.len, h->driver.p);
    drop_stream(g);
    return;
  }
  char ver[ST_STR], drv[48];
  sane_copy(ver, sizeof(ver), h->loader_version.p, h->loader_version.len);
  sane_copy(drv, sizeof(drv), h->driver.p, h->driver.len);
  char line[ST_STR];
  snprintf(line, sizeof(line), "%s, drivers %s", ver, drv);
  st_set_strings(NULL, line);
  atomic_store_explicit(&g_st.pid, h->pid, memory_order_relaxed);
  atomic_store_explicit(&g_st.since, (int64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&g_st.ever_connected, true, memory_order_relaxed);
  atomic_store_explicit(&g_st.connected, true, memory_order_relaxed);
  as_reset();
  g->hello_done = true;
  send_config(g, "handshake");
}

/* ---- INVENTORY: the registry, a few hundred entries at a time so the output queue never holds all of it ---- */

typedef struct {
  ing_t *g;
  uint32_t n;
  bool bad;
} inv_ctx_t;

static bool inv_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  inv_ctx_t *c = ud;
  ing_t *g = c->g;
  if (!zdir_entry(z) || !z->digest) return true;              /* never applied: nothing the loader could skip */
  /* B6a: a zone whose last version was refused (or could not be read) is offered again by a loader that starts now: it
   * must not find the old version "up to date" and leave the error standing when the data are fixed */
  if (z->last_result == DBREG_REJECTED) return true;
  uint16_t idx = 0;
  bool found = false;
  for (uint32_t i = 0; i < g->nview_names; i++) {
    if (strcasecmp(g->view_names[i], view) == 0) {
      idx = (uint16_t)i;
      found = true;
      break;
    }
  }
  if (!found) return true;                               /* a view that left the configuration */
  if (c->n >= ING_INV_CHUNK) return false;
  if (kdb_enc_nest_begin(&g->enc, 1) != 0 || kdb_enc_u16(&g->enc, 1, idx) != 0 || kdb_enc_name(&g->enc, 2, z->name) != 0 ||
      kdb_enc_i64(&g->enc, 3, z->source_id) != 0 || kdb_enc_u32(&g->enc, 4, z->serial) != 0 ||
      kdb_enc_bytes(&g->enc, 5, z->digest, KDB_DIGEST_LEN) != 0 || kdb_enc_u8(&g->enc, 6, 1) != 0 || kdb_enc_nest_end(&g->enc) != 0) {
    c->bad = true;
    return false;
  }
  c->n++;
  return true;
}

static void pump_inventory(ing_t *g) {
  burst_yield_t by = BURST_YIELD_INIT;
  while (g->inv_active && g->stream_fd >= 0 && g->out_len - g->out_off < ING_INV_QUEUE_LOW) {
    burst_yield_check(&by);                /* a million zones are read in chunks; the pinned worker on this CPU gets its turns */
    inv_ctx_t c = { g, 0, false };
    kdb_enc_reset(&g->enc);
    if (kdb_enc_begin(&g->enc, KDB_T_INVENTORY) != 0) {
      send_enc(g);
      return;
    }
    bool done = dbreg_walk(&g->inv_cur, inv_cb, &c);
    if (c.bad || kdb_enc_end(&g->enc) != 0) {
      g->enc.err = true;
      send_enc(g);
      return;
    }
    if (c.n > 0) {
      g->inv_sent += c.n;
      send_enc(g);
    } else {
      kdb_enc_reset(&g->enc);
    }
    if (done) {
      g->inv_active = false;
      if (g->stream_fd < 0) return;
      kdb_enc_reset(&g->enc);
      if (kdb_enc_begin(&g->enc, KDB_T_INVENTORY_END) != 0 ||
          kdb_enc_u64(&g->enc, 1, atomic_load_explicit(&g_last_change_seq, memory_order_relaxed)) != 0 ||
          kdb_enc_u64(&g->enc, 2, g->inv_sent) != 0 || kdb_enc_end(&g->enc) != 0)
        g->enc.err = true;
      send_enc(g);
      syslog(LOG_INFO, "[DB] loader asked for the inventory: sent %llu zone(s)", (unsigned long long)g->inv_sent);
    }
  }
}

static void on_inventory_req(ing_t *g) {
  g->inv_active = true;
  memset(&g->inv_cur, 0, sizeof(g->inv_cur));
  g->inv_sent = 0;
  pump_inventory(g);
}

static const char *kind_name(int k) {
  static const char *const n[] = { "startup", "full", "diff", "zone", "auto" };
  return k >= 0 && k < 5 ? n[k] : "?";
}

static void on_batch_begin(ing_t *g, const kdb_msg_t *m) {
  drain_all(g);
  g->in_batch = true;
  g->batch_id = m->u.batch_begin.batch_id;
  g->batch_kind = m->u.batch_begin.kind;
  g->b_applied = g->b_rejected = g->b_shadowed = g->b_deleted = g->b_failed = 0;
  clear_profiles(g);                                     /* B7a: the profiles of the previous batch */
  g->rejects_logged = 0;
  if (m->u.batch_begin.change_seq != 0)                  /* a one-zone batch does not read the log */
    atomic_store_explicit(&g_last_change_seq, m->u.batch_begin.change_seq, memory_order_relaxed);
  g->cur_req = -1;
  g->req_outcome = ROUT_NONE;
  g->req_reason[0] = '\0';
  if (m->u.batch_begin.request_id != 0) {
    for (int i = 0; i < ING_REQ_MAX; i++)
      if (g->reqs[i].active && g->reqs[i].id == m->u.batch_begin.request_id) g->cur_req = i;
  }
  atomic_store_explicit(&g_st.batch_id, g->batch_id, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_kind, g->batch_kind, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_done, false, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_time, (int64_t)time(NULL), memory_order_relaxed);
  g->last_delta_ms = now_ms();
}

/* the job of a ZONE_BEGIN (either stream), with its settings resolved; NULL: out of memory */
static ing_job_t *job_from_begin(ing_t *g, const kdb_zone_begin_t *zb) {
  ing_job_t *j = calloc(1, sizeof(*j));
  if (!j) return NULL;
  j->view = zb->view;
  snprintf(j->zone, sizeof(j->zone), "%s", zb->name);
  j->source_id = zb->source_id;
  j->serial = zb->serial;
  j->rr_count = zb->rr_count;
  j->fetch_id = zb->request_id;
  memcpy(j->digest, zb->digest, KDB_DIGEST_LEN);
  if (zb->view < g->nview_names) snprintf(j->view_name, sizeof(j->view_name), "%s", g->view_names[zb->view]);
  if (j->view_name[0] == '\0') {
    j->skip = true;
    job_reject(j, "the view is not in the configuration");
  } else if (zb->flags & KDB_ZF_SUMMARY) {
    j->summary = true;                                   /* D1a: a primary's summary: no settings, no data (the state machine checked) */
    j->has_timers = zb->has_soa_timers;
    j->t_refresh = zb->soa_refresh;
    j->t_retry = zb->soa_retry;
    j->t_expire = zb->soa_expire;
  } else if (zb->zone_kind != KDB_ZK_PRIMARY && zb->flags != 0) {
    j->skip = true;                                      /* a SLAVE / CONSUMER has no data to describe */
    job_reject(j, "a secondary zone from the database carries no zone flags");
  } else if (!resolve_zone_settings(g, j, zb)) {
    j->skip = true;                                      /* job_reject() was called: the zone is rejected, its data skipped */
  } else if (zb->zone_kind != KDB_ZK_PRIMARY && (!j->shared || j->shared->ext.masters_count <= 0)) {
    j->skip = true;
    job_reject(j, "a secondary zone from the database needs masters in its settings");
  } else if (zb->zone_kind == KDB_ZK_PRIMARY && j->shared && j->shared->ext.masters_count > 0) {
    /* a profile shared with secondary zones may carry masters; a primary has nothing to transfer, and the NOTIFY check
     * (masters = who may notify) would otherwise treat it as a secondary */
    j->skip = true;
    job_reject(j, "the settings of a primary zone name masters (masters / primaries belong to SLAVE and CONSUMER zones)");
  } else if (zb->zone_kind != KDB_ZK_PRIMARY) {
    j->zkind = zb->zone_kind;                            /* no ZONE_DATA follows (the stream rules, dns_db_stream.c): ZONE_END runs it */
  } else {
    j->build = db_zone_build_new(j->zone, j->rr_count, zb->flags);
    if (j->build) db_zone_build_set_serial(j->build, zb->serial);
    if (!j->build) {
      j->skip = true;
      job_reject(j, "out of memory");
    }
  }
  return j;
}

static void on_zone_begin(ing_t *g, const kdb_msg_t *m) {
  ing_job_t *j = job_from_begin(g, &m->u.zone_begin);
  if (!j) {
    syslog(LOG_ERR, "[DB] out of memory; closing the stream");
    drop_stream(g);
    return;
  }
  g->cur = j;
}

/* ZONE_DATA of the zone j (either stream) */
static void job_feed(ing_t *g, ing_job_t *j, const kdb_msg_t *m) {
  if (!j || j->skip || j->failed) return;
  if (!j->build) {
    /* I6: ZONE_DATA for a job without a builder (a secondary zone, whose ZONE_BEGIN starts none, or an earlier failure):
     * the stream rules (dns_db_stream.c) refuse it before this point; fail the job rather than feed a NULL builder */
    j->failed = true;
    snprintf(j->reason, sizeof(j->reason), "zone data for a zone that takes none");
    return;
  }
  const kdb_zone_data_t *zd = &m->u.zone_data;
  if (g->nbuilders == 0) {
    if (db_zone_build_feed(j->build, zd->body, zd->len, j->reason, sizeof(j->reason)) != 0) j->failed = true;
    return;
  }
  size_t need = j->buf_len + 4 + zd->len;
  if (need > j->buf_cap) {
    size_t nc = j->buf_cap ? j->buf_cap : 65536;
    while (nc < need) nc *= 2;
    uint8_t *nb = realloc(j->buf, nc);
    if (!nb) {
      j->failed = true;
      snprintf(j->reason, sizeof(j->reason), "out of memory");
      return;
    }
    j->buf = nb;
    j->buf_cap = nc;
  }
  uint32_t n = zd->len;
  memcpy(j->buf + j->buf_len, &n, 4);
  memcpy(j->buf + j->buf_len + 4, zd->body, zd->len);
  j->buf_len = need;
}

static void on_zone_data(ing_t *g, const kdb_msg_t *m) { job_feed(g, g->cur, m); }

static void on_zone_end(ing_t *g) {
  ing_job_t *j = g->cur;
  g->cur = NULL;
  if (j) job_submit(g, j);
}

static void on_zone_failed(ing_t *g, const kdb_msg_t *m) {
  const kdb_zone_failed_t *zf = &m->u.zone_failed;
  char reason[KDB_REASON_LEN];
  sane_copy(reason, sizeof(reason), zf->reason.p, zf->reason.len);
  g->b_failed++;
  atomic_fetch_add_explicit(&g_st.tot_failed, 1, memory_order_relaxed);
  syslog(LOG_WARNING, "[DB] the loader could not read zone '%s' (view %u, id %lld): %s", zf->name,
         (unsigned)zf->view, (long long)zf->source_id, reason);
  if (zf->view < g->nview_names && g->view_names[zf->view][0]) {
    /* a zone of the same name in flight must be finished first (it would race on the record) */
    drain_all(g);
    (void)dbreg_reject(g->view_names[zf->view], zf->name, zf->source_id, reason);
  }
  if (g->cur_req >= 0 && g->reqs[g->cur_req].view == zf->view && domain_names_match_ci(g->reqs[g->cur_req].zone, zf->name)) {
    g->req_outcome = ROUT_FAILED;
    snprintf(g->req_reason, sizeof(g->req_reason), "%s", reason);
  }
}

static void on_zone_delete(ing_t *g, const kdb_msg_t *m) {
  const kdb_zone_delete_t *zd = &m->u.zone_delete;
  uint8_t st = KDB_ST_UNCHANGED;
  if (zd->view < g->nview_names && g->view_names[zd->view][0]) {
    drain_all(g);                                        /* a zone of the same name may be in flight */
    int r = dbreg_delete(g->view_names[zd->view], zd->name, zd->source_id);
    if (r > 0) {
      st = KDB_ST_DELETED;
      if (g->cur_req >= 0 && g->reqs[g->cur_req].view == zd->view && domain_names_match_ci(g->reqs[g->cur_req].zone, zd->name))
        g->req_outcome = ROUT_DELETED;
      g->b_deleted++;
      atomic_fetch_add_explicit(&g_st.tot_deleted, 1, memory_order_relaxed);
      syslog(LOG_INFO, "[DB] zone '%s' (view '%s') deleted", zd->name, g->view_names[zd->view]);
    } else if (r == 0) {
      syslog(LOG_NOTICE, "[DB] delete of zone '%s' (view %u, id %lld) ignored: not registered with that id",
             zd->name, (unsigned)zd->view, (long long)zd->source_id);
    }
  }
  send_zone_result(g, zd->view, zd->name, st, NULL);
}

static void on_batch_end(ing_t *g, const kdb_msg_t *m) {
  const kdb_batch_end_t *b = &m->u.batch_end;
  sync_all(g);
  atomic_store_explicit(&g_st.b_applied, g->b_applied, memory_order_relaxed);
  atomic_store_explicit(&g_st.b_rejected, g->b_rejected, memory_order_relaxed);
  atomic_store_explicit(&g_st.b_shadowed, g->b_shadowed, memory_order_relaxed);
  atomic_store_explicit(&g_st.b_deleted, g->b_deleted, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_time, (int64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_done, true, memory_order_relaxed);
  if (g->batch_kind == KDB_BATCH_AUTO) atomic_fetch_add_explicit(&g_st.tot_auto_batches, 1, memory_order_relaxed);
  syslog(LOG_INFO, "[DB] batch %llu complete: %u zone(s) received (%u installed, %u hidden by karidns.conf, %u rejected), "
                   "%u failed in the loader, %u deleted",
         (unsigned long long)b->batch_id, b->n_zones, g->b_applied, g->b_shadowed, g->b_rejected, b->n_failed,
         g->b_deleted);
  if (g->batch_kind == KDB_BATCH_STARTUP) {
    /* the loader may have sent nothing (a restarted loader finds the Backend up to date): count the registry */
    size_t total, rej, shc, shk;
    dbreg_counts2(&total, &rej, &shc, &shk);
    syslog(LOG_INFO, "[DB] initial load complete: %zu zone(s) served from the database", total);
  }
  answer_request(g);
  g->in_batch = false;
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_BATCH_RESULT) != 0 || kdb_enc_u64(&g->enc, 1, b->batch_id) != 0 ||
      kdb_enc_u32(&g->enc, 3, g->b_applied + g->b_shadowed) != 0 || kdb_enc_u32(&g->enc, 4, 0) != 0 ||
      kdb_enc_u32(&g->enc, 5, g->b_rejected) != 0 || kdb_enc_u32(&g->enc, 6, g->b_deleted) != 0 ||
      kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

/* B9: the loader's report on auto reload, one entry per view that has it on */
static void on_auto_status(const kdb_msg_t *m) {
  kdb_iter_t it;
  kdb_auto_status_entry_t e;
  kdb_auto_status_entries(m, &it);
  while (kdb_auto_status_entries_next(&it, &e)) {
    if (e.view >= KARIDNS_DB_MAX_VIEWS) continue;
    as_data_t d;
    memset(&d, 0, sizeof(d));
    d.last_poll = (int64_t)e.last_poll;
    d.applied_seq = e.applied_seq;
    d.pending = e.pending;
    d.flags = e.flags;
    d.req_generation = e.req_generation;
    d.req_ok = e.req_ok;
    d.req_time = (int64_t)e.req_time;
    as_set(&g_as[e.view], &d, e.error.p, e.error.len, e.server_id.p, e.server_id.len, e.req_error.p, e.req_error.len);
  }
}

static void handle_msg(ing_t *g, const kdb_msg_t *m) {
  switch (m->type) {
  case KDB_T_HELLO:
    on_hello(g, m);
    break;
  case KDB_T_INVENTORY_REQ:
    on_inventory_req(g);
    break;
  case KDB_T_BATCH_BEGIN:
    on_batch_begin(g, m);
    break;
  case KDB_T_ZONE_BEGIN:
    on_zone_begin(g, m);
    break;
  case KDB_T_ZONE_DATA:
    on_zone_data(g, m);
    break;
  case KDB_T_ZONE_END:
    on_zone_end(g);
    break;
  case KDB_T_ZONE_ABORT:
    job_free(g->cur);                                    /* the loader gave the zone up: no result */
    g->cur = NULL;
    break;
  case KDB_T_ZONE_FAILED:
    on_zone_failed(g, m);
    break;
  case KDB_T_ZONE_DELETE:
    on_zone_delete(g, m);
    break;
  case KDB_T_BATCH_END:
    on_batch_end(g, m);
    break;
  case KDB_T_PROFILE:
    on_profile(g, m);
    break;
  case KDB_T_AUTO_STATUS:
    on_auto_status(m);
    break;
  default:
    break;
  }
}

static void protocol_error(ing_t *g, const char *reason) {
  syslog(LOG_ERR, "[DB] protocol error from the loader: %s; closing the stream", reason);
  char line[ST_STR];
  snprintf(line, sizeof(line), "%s", reason);
  st_set_strings(line, NULL);
  drop_stream(g);
}

static void on_stream_readable(ing_t *g) {
  for (int round = 0; round < ING_READ_ROUNDS && g->stream_fd >= 0; round++) {
    ssize_t n = read(g->stream_fd, g->rbuf, ING_RBUF);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      syslog(LOG_NOTICE, "[DB] loader disconnected (read: %s)", strerror(errno));
      drop_stream(g);
      return;
    }
    if (n == 0) {
      syslog(LOG_NOTICE, "[DB] loader disconnected");
      drop_stream(g);
      return;
    }
    if (kdb_framer_feed(&g->fr, g->rbuf, (size_t)n) != KDB_OK) {
      protocol_error(g, g->fr.reason);
      return;
    }
    kdb_frame_t fr;
    for (;;) {
      kdb_rc_t rc = kdb_framer_next(&g->fr, &fr);
      if (rc == KDB_MORE) break;
      if (rc != KDB_OK) {
        protocol_error(g, g->fr.reason);
        return;
      }
      kdb_msg_t msg;
      rc = kdb_sm_accept(&g->sm, &fr, &msg);
      if (rc != KDB_OK) {
        /* the reason names the rule, never bytes of the stream */
        protocol_error(g, g->sm.reason);
        return;
      }
      handle_msg(g, &msg);
      if (g->stream_fd < 0) return;
    }
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* connections                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

static void adopt_stream(ing_t *g, int fd) {
  limit_stream_rights(fd); /* at once: a received descriptor has all the rights of the sender's end */
  if (g->stream_fd >= 0) {
    syslog(LOG_NOTICE, "[DB] a new loader stream replaces the old one");
    drop_stream(g);
  }
  if (g->need_cleanup) cleanup_stream_state(g);
  g->stream_fd = fd;
  struct kevent ev[2];
  EV_SET(&ev[0], fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, ev, 2, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader stream: %s", strerror(errno));
    drop_stream(g);
    return;
  }
  g->write_armed = false;
  g->out_len = g->out_off = 0;
  g->hello_done = false;
  g->zones_logged = 0;
  g->rejects_logged = 0;
  g->inv_active = false;
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  kdb_limits_t lim = { snap.max_zone_records ? snap.max_zone_records : KDB_DEFAULT_MAX_ZONE_RECORDS,
                       snap.max_zone_bytes ? snap.max_zone_bytes : KDB_DEFAULT_MAX_ZONE_BYTES,
                       snap.nviews ? snap.nviews : KDB_VIEWS_ANY };
  kdb_framer_init(&g->fr, KDB_FROM_LOADER, g->body, KDB_MAX_BODY);
  kdb_sm_init(&g->sm, &lim);
  kdb_enc_reset(&g->enc);
  syslog(LOG_INFO, "[DB] loader stream connected, waiting for HELLO");
}

static void on_ctrl_readable(ing_t *g) {
  for (;;) {
    char byte;
    struct iovec iov = { &byte, 1 };
    union {
      struct cmsghdr h;
      char buf[CMSG_SPACE(sizeof(int) * 4)];
    } u;
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof(u.buf);
    ssize_t n = recvmsg(g->ctrl_fd, &m, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      syslog(LOG_ERR, "[DB] recvmsg on the loader control socket: %s", strerror(errno));
      return;
    }
    if (n == 0) { /* the supervisor is gone: the server is going down; stop watching so the thread does not spin */
      syslog(LOG_NOTICE, "[DB] the loader control socket was closed by the supervisor");
      close(g->ctrl_fd);
      g->ctrl_fd = -1;
      return;
    }
    int got = -1, got_fetch = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
      if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
      size_t cnt = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      for (size_t i = 0; i < cnt; i++) {
        int fd;
        memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
        if (got < 0) got = fd;                  /* the first descriptor is the stream, the second (D1a) the fetch stream */
        else if (got_fetch < 0) got_fetch = fd;
        else close(fd);
      }
    }
    if (m.msg_flags & MSG_CTRUNC) syslog(LOG_ERR, "[DB] the loader control message was truncated");
    if (got >= 0) {
      adopt_stream(g, got);
      if (got_fetch >= 0) {
        fetch_adopt(g, got_fetch);
      } else {                                  /* a loader without the fetch stream: the old one is gone with the old loader */
        fetch_drop(g);
        fetch_fail_all(g, "the loader has no fetch stream");
      }
    }
  }
}

/* B7a: karidns.conf was reloaded.  The ceiling is evaluated for every request against the active configuration, and so is
 * the existence of a TSIG key (dns_tsig_acl.c: a database ACL that names a key the configuration no longer defines refuses
 * everybody), so nothing has to be republished and no data has to be read again; what is left to do is to say it: a line
 * per zone (the first few) and the counts in `karictl dbstatus`. */
typedef struct {
  const server_config_t *cfg;
  uint32_t zones, with_acl, missing, logged;
  uint32_t chunk;     /* zones seen in the current hold of the lock */
} reeval_ctx_t;

static _Atomic uint32_t g_settings_missing_keys;     /* zones with a missing key, as of the last reload (dbstatus) */

#define REEVAL_CHUNK 4096     /* zones per hold of the rebuild lock (about 1 ms); the walk sleeps between chunks */

static bool reeval_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  reeval_ctx_t *c = ud;
  if (++c->chunk > REEVAL_CHUNK) {     /* stop before this zone: the next chunk starts at it */
    c->chunk = 0;
    return false;
  }
  if (!zdir_entry(z)) return true;
  const zone_config_t *dc = atomic_load_explicit(&zdir_entry(z)->dbcfg, memory_order_acquire);
  if (!dc || !dc->ext_shared) return true;
  c->zones++;
  const zone_ext_t *x = dc->ext;
  if (x->allow_transfer_count > 0 || x->tsig_keys_count > 0 || x->allow_update_count > 0) c->with_acl++;
  const char *missing = db_settings_missing_key(x, c->cfg);
  if (missing) {
    c->missing++;
    if (c->logged < 20) {
      c->logged++;
      char shown[72];
      sane_copy(shown, sizeof(shown), missing, strlen(missing));
      syslog(LOG_WARNING, "[DB] zone '%s' (view '%s'): its settings name the TSIG key '%s', which karidns.conf no longer defines; "
                          "the ACL that names it refuses everybody until the key is back", z->name, view, shown);
    }
  }
  return true;
}

static void reeval_settings(ing_t *g) {
  (void)g;
  reeval_ctx_t c = { NULL, 0, 0, 0, 0, 0 };
  rcu_aux_read_lock();
  c.cfg = acquire_config_snapshot();
  dbreg_cursor_t cur;
  memset(&cur, 0, sizeof(cur));
  /* in chunks: a hold of the rebuild lock over a million zones (50 ms) would stall a reload or a delta that needs it, and
   * the ingest thread shares its CPU with a pinned worker (burst_yield()) */
  while (!dbreg_walk(&cur, reeval_cb, &c)) {
    struct timespec ts = { 0, BURST_YIELD_NS };
    nanosleep(&ts, NULL);
  }
  if (c.with_acl > 0 && !db_acl_ceiling_configured(c.cfg))
    syslog(LOG_WARNING, "[DB] %u zone(s) have ACLs in their database settings, but options { database { acl-ceiling } } is not "
                        "configured: they refuse every client", c.with_acl);
  rcu_aux_read_unlock();
  atomic_store_explicit(&g_settings_missing_keys, c.missing, memory_order_relaxed);
  if (c.zones > 0)
    syslog(LOG_INFO, "[DB] configuration reloaded: settings of %u database zone(s) checked against it (%u with ACLs, %u naming a "
                     "TSIG key that is not defined)", c.zones, c.with_acl, c.missing);
}

static void on_config_event(ing_t *g) {
  if (!atomic_exchange_explicit(&g_cfg_dirty, false, memory_order_acq_rel)) return;
  reeval_settings(g);
  if (g->stream_fd >= 0 && g->hello_done) send_config(g, "configuration reloaded");
  /* otherwise the CONFIG of the handshake reads the new configuration */
}

/* ---- karictl reload requests (control thread -> loader) and their answers ---- */

/* the zone name as the stream wants it: canonical, absolute */
static bool canon_zone(const char *in, char out[DNS_NAME_TEXT_SIZE]) {
  char norm[DNS_NAME_TEXT_SIZE];
  size_t nl = dns_name_normalize(in, norm, sizeof(norm) - 1);
  if (nl == (size_t)-1 || nl == 0) return false;
  if (dns_name_len_no_root(norm, nl) == nl) {
    norm[nl++] = '.';
    norm[nl] = '\0';
  }
  if (nl > 255) return false;
  snprintf(out, DNS_NAME_TEXT_SIZE, "%s", norm);
  return true;
}

static void send_reload_req(ing_t *g, uint64_t id, bool all, uint16_t view, const char *zone, bool force) {
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_RELOAD_REQ) != 0 || kdb_enc_u64(&g->enc, 1, id) != 0 ||
      kdb_enc_u8(&g->enc, 2, all ? 0 : 1) != 0 ||
      (!all && (kdb_enc_u16(&g->enc, 3, view) != 0 || kdb_enc_name(&g->enc, 4, zone) != 0)) ||
      kdb_enc_u8(&g->enc, 5, force ? 1 : 0) != 0 || kdb_enc_end(&g->enc) != 0)
    g->enc.err = true;
  send_enc(g);
}

static void on_config_event(ing_t *g);

/* B6b: one RELOAD_REQ per view that takes database zones; answer_request() combines the answers */
static void request_all_views(ing_t *g, const rq_item_t *it, const char *canon) {
  int need = 0, gi = -1, slots[ING_REQ_MAX], ns = 0;
  for (uint32_t v = 0; v < g->nview_names; v++)
    if (g->view_db && g->view_db[v]) need++;
  for (int i = 0; i < ING_REQ_MAX; i++) {
    if (gi < 0 && !g->grps[i].active) gi = i;
    if (!g->reqs[i].active && ns < need) slots[ns++] = i;
  }
  if (need == 0) {
    post_result(it->id, false, "no view takes zones from the database");
    return;
  }
  if (gi < 0 || ns < need) {
    post_result(it->id, false, "too many reload requests are waiting for the database loader");
    return;
  }
  g->grps[gi].active = true;
  g->grps[gi].ctl_id = it->id;
  g->grps[gi].pending = need;
  g->grps[gi].any_ok = g->grps[gi].any_bad = false;
  g->grps[gi].text[0] = '\0';
  snprintf(g->grps[gi].zone, sizeof(g->grps[gi].zone), "%s", canon);
  syslog(LOG_NOTICE, "[DB] reload of zone '%s' (all %d views that take database zones) requested (request %llu)%s", canon, need,
         (unsigned long long)it->id, it->force ? ", force" : "");
  int k = 0;
  for (uint32_t v = 0; v < g->nview_names; v++) {
    if (!g->view_db || !g->view_db[v]) continue;
    int slot = slots[k++];
    g->reqs[slot].active = true;
    g->reqs[slot].id = (1ULL << 63) | ++g->sub_seq;
    g->reqs[slot].grp = gi;
    g->reqs[slot].view = (uint16_t)v;
    snprintf(g->reqs[slot].view_name, sizeof(g->reqs[slot].view_name), "%s", g->view_names[v]);
    snprintf(g->reqs[slot].zone, sizeof(g->reqs[slot].zone), "%s", canon);
    send_reload_req(g, g->reqs[slot].id, false, (uint16_t)v, canon, it->force);
  }
}

static void process_requests(ing_t *g) {
  on_config_event(g);          /* a reload that changed the configuration sends CONFIG before the request */
  for (;;) {
    uint32_t h = atomic_load_explicit(&g_rq_head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&g_rq_tail, memory_order_acquire);
    if (h == t) break;
    rq_item_t it = g_rq[h % RQ_RING];
    atomic_store_explicit(&g_rq_head, h + 1, memory_order_release);
    bool ready = g->stream_fd >= 0 && g->hello_done;
    switch (it.type) {
    case RQ_ALL:
      if (ready) {
        send_reload_req(g, it.id, true, 0, NULL, false);
        syslog(LOG_NOTICE, "[DB] reload requested (request %llu): the loader compares every source with the zones served",
               (unsigned long long)it.id);
      } else {
        syslog(LOG_WARNING, "[DB] reload requested (request %llu), but the database loader is not connected",
               (unsigned long long)it.id);
      }
      break;
    case RQ_ZONE: {
      char canon[DNS_NAME_TEXT_SIZE];
      if (!canon_zone(it.zone, canon)) {
        post_result(it.id, false, "'%.100s' is not a valid zone name", it.zone);
        break;
      }
      if (!it.view[0]) { /* no view named, several take database zones: ask every one of them */
        if (!ready) {
          post_result(it.id, false, "the database loader is not connected (see 'karictl dbstatus')");
          break;
        }
        request_all_views(g, &it, canon);
        break;
      }
      int vi = -1;
      for (uint32_t i = 0; i < g->nview_names; i++)
        if (strcasecmp(g->view_names[i], it.view) == 0) vi = (int)i;
      if (vi < 0) {
        post_result(it.id, false, "view '%.60s' is not in the configuration", it.view);
        break;
      }
      if (!ready) {
        post_result(it.id, false, "the database loader is not connected (see 'karictl dbstatus')");
        break;
      }
      int slot = -1;
      for (int i = 0; i < ING_REQ_MAX && slot < 0; i++)
        if (!g->reqs[i].active) slot = i;
      if (slot < 0) {
        post_result(it.id, false, "too many reload requests are waiting for the database loader");
        break;
      }
      g->reqs[slot].active = true;
      g->reqs[slot].id = it.id;
      g->reqs[slot].grp = -1;
      g->reqs[slot].view = (uint16_t)vi;
      snprintf(g->reqs[slot].view_name, sizeof(g->reqs[slot].view_name), "%s", g->view_names[vi]);
      snprintf(g->reqs[slot].zone, sizeof(g->reqs[slot].zone), "%s", canon);
      syslog(LOG_NOTICE, "[DB] reload of zone '%s' (view '%s') requested (request %llu)%s", canon, g->view_names[vi],
             (unsigned long long)it.id, it.force ? ", force" : "");
      send_reload_req(g, it.id, false, (uint16_t)vi, canon, it.force);
      break;
    }
    case RQ_CANCEL:
      for (int i = 0; i < ING_REQ_MAX; i++)
        if (g->grps[i].active && g->grps[i].ctl_id == it.id) g->grps[i].active = false;
      for (int i = 0; i < ING_REQ_MAX; i++)
        if (g->reqs[i].active && (g->reqs[i].id == it.id || (g->reqs[i].grp >= 0 && !g->grps[g->reqs[i].grp].active))) {
          g->reqs[i].active = false;
          if (g->cur_req == i) g->cur_req = -1;
        }
      break;
    default:
      break;
    }
  }
}

/* What a finished request says about its zone in one view: the text after "zone Z (view V): " and whether it is good news.
 * *notfound: the loader sent nothing and the zone is not served (the zone is not in the database of this view). */
static void request_clause(ing_t *g, int i, char *out, size_t cap, bool *ok, bool *notfound) {
  const char *zone = g->reqs[i].zone, *view = g->reqs[i].view_name;
  dbreg_info_t info;
  int n = dbreg_find_info(view, zone, &info, 1);
  *ok = true;
  *notfound = false;
  switch (g->req_outcome) {
  case ROUT_APPLIED:
    snprintf(out, cap, "applied, serial %u", g->req_serial);
    break;
  case ROUT_SHADOWED:
    snprintf(out, cap, "loaded, serial %u, but hidden by %s", g->req_serial,
             n > 0 && info.shadow_by == DBREG_SH_CATALOG ? "a catalog member of the same name" : "the zone in karidns.conf");
    break;
  case ROUT_REJECTED:
    *ok = false;
    snprintf(out, cap, "rejected: %.100s; the last good version, if any, keeps serving", g->req_reason);
    break;
  case ROUT_FAILED:
    *ok = false;
    snprintf(out, cap, "failed: %.100s", g->req_reason);
    break;
  case ROUT_DELETED:
    snprintf(out, cap, "deleted (it is no longer in the database)");
    break;
  default: /* nothing was sent for the zone: the loader found it unchanged, or the database does not have it */
    if (n > 0 && info.has_entry) {
      snprintf(out, cap, "unchanged, serial %u%s", info.serial, info.shadowed ? " (hidden by another zone of the same name)" : "");
    } else {
      *ok = false;
      *notfound = true;
      snprintf(out, cap, "not in the database");
    }
    break;
  }
}

/* BATCH_END of a batch that answers a request: tell the control thread what became of the zone (design 5.2).  A request
 * that is one view of a group (B6b) only adds its part; the last part posts the combined answer. */
static void answer_request(ing_t *g) {
  if (g->cur_req < 0) return;
  int i = g->cur_req;
  g->cur_req = -1;
  if (!g->reqs[i].active) return;
  uint64_t id = g->reqs[i].id;
  const char *zone = g->reqs[i].zone, *view = g->reqs[i].view_name;
  int grp = g->reqs[i].grp;
  g->reqs[i].active = false;
  char clause[160];
  bool ok, notfound;
  request_clause(g, i, clause, sizeof(clause), &ok, &notfound);
  if (grp < 0) {
    if (notfound)
      post_result(id, false, "zone not found (it is not in the database of view %s)", view);
    else
      post_result(id, ok, "zone %s (view %s): %s", zone, view, clause);
    return;
  }
  size_t l = strlen(g->grps[grp].text);
  snprintf(g->grps[grp].text + l, sizeof(g->grps[grp].text) - l, "%sview %s: %s", l ? "; " : "", view, clause);
  if (ok) g->grps[grp].any_ok = true;
  if (!ok && !notfound) g->grps[grp].any_bad = true;
  if (--g->grps[grp].pending > 0) return;
  g->grps[grp].active = false;
  if (!g->grps[grp].any_ok && !g->grps[grp].any_bad)
    post_result(g->grps[grp].ctl_id, false, "zone not found (it is not in the database of any view that takes database zones)");
  else
    post_result(g->grps[grp].ctl_id, g->grps[grp].any_ok, "zone %s: %s", g->grps[grp].zone, g->grps[grp].text);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the fetch stream (D1a, design 6.1)                                                                             */
/* ------------------------------------------------------------------------------------------------------------- */
/* A worker that has parked a query for a zone whose data is not in memory pushes the request on its ring (dns_park.h) and triggers EVFILT_USER
 * PARK_FETCH_IDENT.  This thread turns the requests into FETCH_REQ messages on the second stream (one per zone in flight, the table below keeps
 * them), reads the loader's answers there (the state machine of the fetch stream, dns_db_stream.c), installs each zone through the same jobs as a
 * batch zone, and then tells every worker (park_wake_broadcast()): woken when the zone is in memory, answered at once when the fetch failed.
 * A zone nobody asked for is discarded as it is read: it takes no memory and counts against nothing.  The loader's answers are not ZONE_RESULTs:
 * the first stream's inventory is the batch's business. */

static void prof_swap(ing_t *g) {
  ing_profile_t *p = g->profiles;
  g->profiles = g->fprofiles;
  g->fprofiles = p;
  size_t t = g->nprof;
  g->nprof = g->fnprof;
  g->fnprof = t;
  t = g->cprof;
  g->cprof = g->fcprof;
  g->fcprof = t;
  t = g->prof_bytes;
  g->prof_bytes = g->fprof_bytes;
  g->fprof_bytes = t;
}

static void farm_write(ing_t *g, bool on) {
  if (g->fwrite_armed == on || g->fetch_fd < 0) return;
  struct kevent ev;
  EV_SET(&ev, g->fetch_fd, EVFILT_WRITE, on ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, &ev, 1, NULL, 0, NULL) == 0) g->fwrite_armed = on;
}

static void fetch_drop(ing_t *g) {
  if (g->fetch_fd >= 0) close(g->fetch_fd);              /* the kqueue forgets the descriptor */
  g->fetch_fd = -1;
  g->fwrite_armed = false;
  g->fout_len = g->fout_off = 0;
  job_free(g->fcur);
  g->fcur = NULL;
  prof_swap(g);
  clear_profiles(g);
  prof_swap(g);
  kdb_enc_reset(&g->fenc);
}

static void fetch_flush(ing_t *g) {
  while (g->fetch_fd >= 0 && g->fout_off < g->fout_len) {
    ssize_t n = write(g->fetch_fd, g->fout + g->fout_off, g->fout_len - g->fout_off);
    if (n > 0) {
      g->fout_off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      farm_write(g, true);
      return;
    }
    syslog(LOG_NOTICE, "[DB] loader fetch stream disconnected (write: %s)", n < 0 ? strerror(errno) : "closed");
    fetch_drop(g);
    return;
  }
  if (g->fetch_fd >= 0) {
    g->fout_len = g->fout_off = 0;
    farm_write(g, false);
  }
}

/* queue the message built in g->fenc.  false: nothing was queued (no stream, or the stream was dropped) */
static bool fetch_queue(ing_t *g) {
  if (g->fenc.err) {
    kdb_enc_reset(&g->fenc);
    return false;
  }
  if (g->fetch_fd < 0) {
    kdb_enc_reset(&g->fenc);
    return false;
  }
  if (g->fout_len - g->fout_off + g->fenc.len > ING_FETCH_OUT_MAX) {
    syslog(LOG_ERR, "[DB] the loader does not read its fetch requests; closing the fetch stream");
    fetch_drop(g);
    return false;
  }
  if (g->fout_off > 0 && g->fout_off == g->fout_len) g->fout_len = g->fout_off = 0;
  if (g->fout_len + g->fenc.len > g->fout_cap) {
    size_t nc = g->fout_cap ? g->fout_cap : 4096;
    while (nc < g->fout_len + g->fenc.len) nc *= 2;
    uint8_t *nb = realloc(g->fout, nc);
    if (!nb) {
      syslog(LOG_ERR, "[DB] out of memory queueing a fetch request; closing the fetch stream");
      fetch_drop(g);
      return false;
    }
    g->fout = nb;
    g->fout_cap = nc;
  }
  memcpy(g->fout + g->fout_len, g->fenc.buf, g->fenc.len);
  g->fout_len += g->fenc.len;
  kdb_enc_reset(&g->fenc);
  return true;
}

static bool fetch_send_req(ing_t *g, const ing_freq_t *r) {
  kdb_enc_reset(&g->fenc);
  if (kdb_enc_begin(&g->fenc, KDB_T_FETCH_REQ) != 0 || kdb_enc_u64(&g->fenc, 1, r->id) != 0 || kdb_enc_u16(&g->fenc, 2, r->view) != 0 ||
      kdb_enc_name(&g->fenc, 3, r->zone) != 0 || kdb_enc_u8(&g->fenc, 4, r->prio) != 0 || kdb_enc_u8(&g->fenc, 5, r->mode) != 0 ||
      kdb_enc_end(&g->fenc) != 0)
    g->fenc.err = true;
  return fetch_queue(g);
}

static ing_freq_t *fetch_find(ing_t *g, uint64_t id) {
  if (g->nfreq == 0 || id == 0) return NULL;
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && g->freq[i].id == id) return &g->freq[i];
  return NULL;
}

static ing_freq_t *fetch_find_zone(ing_t *g, uint16_t view, const char *zone) {
  if (g->nfreq == 0) return NULL;
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && g->freq[i].view == view && domain_names_match_ci(g->freq[i].zone, zone)) return &g->freq[i];
  return NULL;
}

/* the request is over.  ok: the zone (or its summary) was received and installed; else the queries that wait for it are answered at once. */
static void fetch_complete(ing_t *g, ing_freq_t *r, bool ok, const char *why) {
  ing_freq_t done = *r;
  r->active = false;
  g->nfreq--;
  dbreg_fetch_end(done.view_name, done.zone);
  if (!ok)
    syslog(LOG_WARNING, "[DB] fetch of zone '%s' (view '%s') failed: %s", done.zone, done.view_name, why && why[0] ? why : "no reason given");
  if (dbreg_pending_count() > 0) apply_delta(g);         /* a zone that was new to the index becomes visible before its queries are woken */
  park_wake_broadcast(done.view_name, done.zone, !ok);
}

static void fetch_job_finish(ing_t *g, ing_job_t *j) {
  if (!j->unsolicited) {
    ing_freq_t *r = fetch_find(g, j->fetch_id);
    bool ok = j->status != KDB_ST_REJECTED;
    if (ok && !j->summary) g->since_retire++;
    if (r) fetch_complete(g, r, ok, j->reason);
  }
  job_free(j);
}

static void fetch_fail_all(ing_t *g, const char *why) {
  if (g->nfreq == 0) return;
  for (uint32_t i = 0; i < ING_FETCH_MAX && g->nfreq > 0; i++)
    if (g->freq[i].active) fetch_complete(g, &g->freq[i], false, why);
}

static void fetch_expire(ing_t *g) {
  if (g->nfreq == 0) return;
  int64_t now = now_ms();
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && now - g->freq[i].sent_ms >= g_ing_fetch_timeout_ms)
      fetch_complete(g, &g->freq[i], false, "the loader did not answer in time");
}

/* the requests the workers have pushed since the last time */
static void fetch_issue(ing_t *g) {
  park_fetch_req_t q;
  while (park_fetch_next(&q)) {
    int vi = -1;
    for (uint32_t i = 0; i < g->nview_names; i++) {
      if (g->view_db && g->view_db[i] && strcasecmp(g->view_names[i], q.view) == 0) {
        vi = (int)i;
        break;
      }
    }
    if (vi < 0) {                                        /* a view that takes no zones from the database (or left): nothing to fetch */
      park_wake_broadcast(q.view, q.zone, true);
      continue;
    }
    ing_freq_t *r = fetch_find_zone(g, (uint16_t)vi, q.zone);
    if (r) continue;                                     /* in flight: its answer wakes this worker too */
    int st = dbreg_fetch_begin(g->view_names[vi], q.zone);
    if (st == DBREG_FETCH_BUSY) continue;
    if (st != DBREG_FETCH_STARTED) {                     /* in memory already (woken), or not a zone of the registry (answered at once) */
      park_wake_broadcast(q.view, q.zone, st == DBREG_FETCH_NONE);
      continue;
    }
    for (uint32_t i = 0; i < ING_FETCH_MAX && !r; i++)
      if (!g->freq[i].active) r = &g->freq[i];
    if (!r) {                                            /* too many in flight: the queries run into their deadlines */
      dbreg_fetch_end(g->view_names[vi], q.zone);
      park_wake_broadcast(q.view, q.zone, true);
      continue;
    }
    memset(r, 0, sizeof(*r));
    r->active = true;
    r->id = ++g->fseq;
    r->view = (uint16_t)vi;
    r->prio = q.prio < KDB_FETCH_PRIO_N ? q.prio : KDB_FETCH_PRIO_QUERY;
    r->mode = q.mode <= KDB_FETCH_SUMMARY ? q.mode : KDB_FETCH_FULL;
    r->sent_ms = now_ms();
    snprintf(r->view_name, sizeof(r->view_name), "%s", g->view_names[vi]);
    snprintf(r->zone, sizeof(r->zone), "%s", q.zone);
    g->nfreq++;
    if (!fetch_send_req(g, r)) fetch_complete(g, r, false, "the loader's fetch stream is not connected");
  }
  if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);
}

static void fetch_protocol_error(ing_t *g, const char *reason) {
  syslog(LOG_ERR, "[DB] protocol error from the loader on the fetch stream: %s; closing it", reason);
  fetch_drop(g);
}

static void fetch_discard(ing_t *g, const kdb_zone_begin_t *zb, const char *why) {
  g->funsolicited++;
  if (g->funsolicited <= 8)
    syslog(LOG_WARNING, "[DB] the loader sent a zone on the fetch stream that was not asked for (%s); discarded", why);
  (void)zb;
}

static void on_fetch_begin(ing_t *g, const kdb_zone_begin_t *zb) {
  ing_freq_t *r = fetch_find(g, zb->request_id);
  bool wanted = r && r->view == zb->view && domain_names_match_ci(r->zone, zb->name);
  if (wanted) {
    bool summary = (zb->flags & KDB_ZF_SUMMARY) != 0;
    /* a summary request is answered with a summary (a secondary zone has no data to leave out); a full request with the zone */
    wanted = r->mode == KDB_FETCH_SUMMARY ? (summary || zb->zone_kind != KDB_ZK_PRIMARY) : !summary;
  }
  if (!wanted) {                                         /* nobody asked: read it through the state machine and throw it away */
    ing_job_t *j = calloc(1, sizeof(*j));
    if (!j) {
      syslog(LOG_ERR, "[DB] out of memory; closing the fetch stream");
      fetch_drop(g);
      return;
    }
    j->skip = j->unsolicited = true;
    j->fetch_id = zb->request_id;
    fetch_discard(g, zb, r ? "it is not what the request wants" : "no such request");
    job_free(g->fcur);
    g->fcur = j;
    return;
  }
  prof_swap(g);
  ing_job_t *j = job_from_begin(g, zb);
  prof_swap(g);
  if (!j) {
    syslog(LOG_ERR, "[DB] out of memory; closing the fetch stream");
    fetch_drop(g);
    return;
  }
  job_free(g->fcur);
  g->fcur = j;
}

static void on_fetch_end(ing_t *g) {
  ing_job_t *j = g->fcur;
  g->fcur = NULL;
  if (!j) return;
  if (j->unsolicited) {
    job_free(j);
    return;
  }
  job_submit(g, j);                                      /* (job_finish() -> fetch_job_finish()) */
}

static void on_fetch_failed(ing_t *g, const kdb_zone_failed_t *zf) {
  ing_freq_t *r = fetch_find(g, zf->request_id);
  if (!r || r->view != zf->view || !domain_names_match_ci(r->zone, zf->name)) {
    fetch_discard(g, NULL, "a failure of no request");
    return;
  }
  char reason[KDB_REASON_LEN];
  sane_copy(reason, sizeof(reason), zf->reason.p, zf->reason.len);
  fetch_complete(g, r, false, reason);
}

static void handle_fetch_msg(ing_t *g, const kdb_msg_t *m) {
  switch (m->type) {
  case KDB_T_PROFILE: {
    prof_swap(g);
    int rc = profile_store(g, m);
    prof_swap(g);
    if (rc == PROF_LIMIT) fetch_protocol_error(g, "PROFILE: more profile data than the Backend accepts");
    else if (rc == PROF_OOM) {
      syslog(LOG_ERR, "[DB] out of memory; closing the fetch stream");
      fetch_drop(g);
    }
    break;
  }
  case KDB_T_ZONE_BEGIN:
    on_fetch_begin(g, &m->u.zone_begin);
    break;
  case KDB_T_ZONE_DATA:
    job_feed(g, g->fcur, m);
    break;
  case KDB_T_ZONE_END:
    on_fetch_end(g);
    break;
  case KDB_T_ZONE_ABORT: {
    ing_job_t *j = g->fcur;
    g->fcur = NULL;
    if (j && !j->unsolicited) {
      ing_freq_t *r = fetch_find(g, j->fetch_id);
      if (r) fetch_complete(g, r, false, "the loader gave the zone up");
    }
    job_free(j);
    break;
  }
  case KDB_T_ZONE_FAILED:
    on_fetch_failed(g, &m->u.zone_failed);
    break;
  default:
    break;
  }
}

static void on_fetch_readable(ing_t *g) {
  for (int round = 0; round < ING_READ_ROUNDS && g->fetch_fd >= 0; round++) {
    ssize_t n = read(g->fetch_fd, g->rbuf, ING_RBUF);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      syslog(LOG_NOTICE, "[DB] loader fetch stream disconnected (read: %s)", strerror(errno));
      fetch_drop(g);
      return;
    }
    if (n == 0) {
      syslog(LOG_NOTICE, "[DB] loader fetch stream disconnected");
      fetch_drop(g);
      return;
    }
    if (kdb_framer_feed(&g->ffr, g->rbuf, (size_t)n) != KDB_OK) {
      fetch_protocol_error(g, g->ffr.reason);
      return;
    }
    kdb_frame_t fr;
    for (;;) {
      kdb_rc_t rc = kdb_framer_next(&g->ffr, &fr);
      if (rc == KDB_MORE) break;
      if (rc != KDB_OK) {
        fetch_protocol_error(g, g->ffr.reason);
        return;
      }
      kdb_msg_t msg;
      rc = kdb_sm_accept(&g->fsm, &fr, &msg);
      if (rc != KDB_OK) {
        fetch_protocol_error(g, g->fsm.reason);            /* (the reason names the rule, never bytes of the stream) */
        return;
      }
      handle_fetch_msg(g, &msg);
      if (g->fetch_fd < 0) return;
    }
  }
}

static void fetch_adopt(ing_t *g, int fd) {
  limit_stream_rights(fd);
  if (g->fetch_fd >= 0) fetch_drop(g);
  g->fetch_fd = fd;
  struct kevent ev[2];
  EV_SET(&ev[0], fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, ev, 2, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader fetch stream: %s", strerror(errno));
    fetch_drop(g);
    return;
  }
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  kdb_limits_t lim = { snap.max_zone_records ? snap.max_zone_records : KDB_DEFAULT_MAX_ZONE_RECORDS,
                       snap.max_zone_bytes ? snap.max_zone_bytes : KDB_DEFAULT_MAX_ZONE_BYTES, snap.nviews ? snap.nviews : KDB_VIEWS_ANY };
  kdb_framer_init(&g->ffr, KDB_FROM_LOADER, g->fbody, KDB_MAX_BODY);
  kdb_sm_init_fetch(&g->fsm, &lim);
  kdb_enc_reset(&g->fenc);
  g->fout_len = g->fout_off = 0;
  syslog(LOG_INFO, "[DB] loader fetch stream connected");
  for (uint32_t i = 0; i < ING_FETCH_MAX && g->fetch_fd >= 0; i++)      /* what a restarted loader has not answered is asked again */
    if (g->freq[i].active) {
      g->freq[i].sent_ms = now_ms();
      (void)fetch_send_req(g, &g->freq[i]);
    }
  if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);
}

static void *ingest_thread(void *arg) {
  ing_t *g = arg;
  rcu_aux_thread_pin();
  struct kevent evs[8];
  for (;;) {
    struct timespec ts, *tp = NULL;
    int64_t wait_ms = -1;
    if (dbreg_pending_count() > 0) {                     /* new zones are waiting to become visible */
      wait_ms = g->last_delta_ms + ING_DELTA_MS - now_ms();
      if (wait_ms < 0) wait_ms = 0;
    }
    if (g->nfreq > 0) {                                  /* fetches in flight: look at their deadlines */
      int64_t tick = g_ing_fetch_timeout_ms / 10;
      if (tick > 1000) tick = 1000;
      if (tick < 10) tick = 10;
      if (wait_ms < 0 || wait_ms > tick) wait_ms = tick;
    }
    if (wait_ms >= 0) {
      ts.tv_sec = wait_ms / 1000;
      ts.tv_nsec = (wait_ms % 1000) * 1000000;
      tp = &ts;
    }
    int n = kevent(g->kq, NULL, 0, evs, 8, tp);
    if (n < 0) {
      if (errno == EINTR) continue;
      syslog(LOG_ERR, "[DB] the ingest thread stops: kevent: %s", strerror(errno));
      return NULL;
    }
    for (int i = 0; i < n; i++) {
      const struct kevent *e = &evs[i];
      if (e->filter == EVFILT_USER && e->ident == ING_EVT_RESULT) {
        drain_results(g);
      } else if (e->filter == EVFILT_USER && e->ident == ING_EVT_REQ) {
        process_requests(g);
      } else if (e->filter == EVFILT_USER && e->ident == PARK_FETCH_IDENT) {
        fetch_issue(g);                                  /* D1a: a worker parked a query for a zone that is not in memory */
      } else if (e->filter == EVFILT_USER) {
        on_config_event(g);
      } else if (g->ctrl_fd >= 0 && e->ident == (uintptr_t)g->ctrl_fd) {
        on_ctrl_readable(g);
      } else if (g->fetch_fd >= 0 && e->ident == (uintptr_t)g->fetch_fd) {
        if (e->filter == EVFILT_WRITE) fetch_flush(g);
        else on_fetch_readable(g);
      } else if (g->stream_fd >= 0 && e->ident == (uintptr_t)g->stream_fd) {
        if (e->filter == EVFILT_WRITE) out_flush(g);
        else on_stream_readable(g);
      }
      if (g->need_cleanup) cleanup_stream_state(g);
    }
    if (g->inv_active) pump_inventory(g);
    if (g->need_cleanup) cleanup_stream_state(g);
    maybe_apply_delta(g);
    fetch_expire(g);
    if (g->stream_fd >= 0 && g->out_off < g->out_len) out_flush(g);
    if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);
  }
}

bool db_ingest_start(int stream_fd, int ctrl_fd, int fetch_fd) {
  ing_t *g = &g_ing;
  memset(g, 0, sizeof(*g));
  g->stream_fd = -1;
  g->fetch_fd = -1;
  g->cur_req = -1;
  g->ctrl_fd = ctrl_fd;
  g->body = malloc(KDB_MAX_BODY);
  g->fbody = malloc(KDB_MAX_BODY);
  g->rbuf = malloc(ING_RBUF);
  kdb_enc_init(&g->enc);
  kdb_enc_init(&g->fenc);
  g->kq = kqueue();
  g->wait_kq = kqueue();
  if (!g->body || !g->fbody || !g->rbuf || g->kq < 0 || g->wait_kq < 0 || ctrl_fd < 0) {
    syslog(LOG_ERR, "[DB] cannot start the ingest thread: %s", g->kq < 0 ? strerror(errno) : "no control socket or memory");
    return false;
  }
  limit_ctrl_rights(ctrl_fd);
  struct kevent ev[5];
  EV_SET(&ev[0], ctrl_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], ING_EVT_CONFIG, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[2], ING_EVT_RESULT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[3], ING_EVT_REQ, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[4], PARK_FETCH_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);      /* D1a: a worker asks for a zone */
  if (kevent(g->kq, ev, 5, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader control socket: %s", strerror(errno));
    return false;
  }
  EV_SET(&ev[0], 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kevent(g->wait_kq, ev, 1, NULL, 0, NULL) != 0) return false;
  /* builder threads (design 1.5, D10): ingest-threads 1 = the stream thread builds */
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  uint32_t nthr = snap.ingest_threads;
  if (nthr > ING_MAX_BUILDERS) nthr = ING_MAX_BUILDERS;
  if (nthr > 1) {
    for (uint32_t i = 0; i < nthr; i++) {
      ing_builder_t *b = &g->builders[i];
      atomic_init(&b->slot, NULL);
      b->kq = kqueue();
      EV_SET(&ev[0], 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
      if (b->kq < 0 || kevent(b->kq, ev, 1, NULL, 0, NULL) != 0) {
        syslog(LOG_ERR, "[DB] cannot create a builder thread kqueue: %s", strerror(errno));
        return false;
      }
    }
    for (uint32_t i = 0; i < nthr; i++) {
      if (pthread_create(&g->builders[i].tid, NULL, builder_thread, &g->builders[i]) != 0) {
        syslog(LOG_ERR, "[DB] cannot create a builder thread");
        return false;
      }
      pthread_detach(g->builders[i].tid);
      g->nbuilders = i + 1;
    }
    syslog(LOG_INFO, "[DB] %u builder thread(s) for the zones of the database", g->nbuilders);
  }
  if (stream_fd >= 0) adopt_stream(g, stream_fd);
  if (fetch_fd >= 0) fetch_adopt(g, fetch_fd);
  park_fetch_set_notify(g->kq);
  pthread_t t;
  if (pthread_create(&t, NULL, ingest_thread, g) != 0) {
    syslog(LOG_ERR, "[DB] cannot create the ingest thread");
    return false;
  }
  pthread_detach(t);
  atomic_store_explicit(&g_ing_kq, g->kq, memory_order_release);
  return true;
}

bool db_ingest_enabled(void) {
  return atomic_load_explicit(&g_ing_kq, memory_order_acquire) >= 0;
}

uint64_t db_ingest_reload(bool all, const char *view, const char *zone, bool force) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return 0;
  uint32_t t = atomic_load_explicit(&g_rq_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_rq_head, memory_order_acquire);
  if (t - h >= RQ_RING) return 0;
  rq_item_t *it = &g_rq[t % RQ_RING];
  memset(it, 0, sizeof(*it));
  it->type = all ? RQ_ALL : RQ_ZONE;
  it->force = force;
  it->id = ++g_next_req_id;
  if (view) snprintf(it->view, sizeof(it->view), "%s", view);
  if (zone) snprintf(it->zone, sizeof(it->zone), "%s", zone);
  uint64_t id = it->id;
  atomic_store_explicit(&g_rq_tail, t + 1, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_REQ, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
  return id;
}

void db_ingest_reload_cancel(uint64_t id) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return;
  uint32_t t = atomic_load_explicit(&g_rq_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_rq_head, memory_order_acquire);
  if (t - h >= RQ_RING) return;                          /* the table entry then lives until its batch ends */
  rq_item_t *it = &g_rq[t % RQ_RING];
  memset(it, 0, sizeof(*it));
  it->type = RQ_CANCEL;
  it->id = id;
  atomic_store_explicit(&g_rq_tail, t + 1, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_REQ, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

bool db_ingest_reload_result(db_reload_result_t *out) {
  uint32_t h = atomic_load_explicit(&g_rs_head, memory_order_relaxed);
  uint32_t t = atomic_load_explicit(&g_rs_tail, memory_order_acquire);
  if (h == t) return false;
  *out = g_rs[h % RQ_RING];
  atomic_store_explicit(&g_rs_head, h + 1, memory_order_release);
  return true;
}

bool db_ingest_pick_view(const char *view_arg, char *out, size_t cap, char *err, size_t errlen) {
  bool ok = false;
  if (cap) out[0] = '\0';
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  if (!cfg || !cfg->database.enabled) {
    snprintf(err, errlen, "no database block is configured");
  } else {
    int n = 0;
    const view_config_t *only = NULL, *named = NULL;
    for (const view_config_t *v = cfg->views; v; v = v->next) {
      if (view_arg && v->name && strcasecmp(v->name, view_arg) == 0) named = v;
      if (v->database_none) continue;
      n++;
      only = v;
    }
    if (view_arg) {
      if (!named) snprintf(err, errlen, "view '%.60s' does not exist", view_arg);
      else if (named->database_none) snprintf(err, errlen, "view '%.60s' takes no zones from the database", view_arg);
      else ok = true, snprintf(out, cap, "%s", named->name);
    } else if (n == 1) {
      ok = true;
      snprintf(out, cap, "%s", only->name ? only->name : "");
    } else if (n == 0) {
      snprintf(err, errlen, "no view takes zones from the database");
    } else {
      ok = true;                 /* several views and none named: the caller asks every one of them (B6b) */
      out[0] = '\0';
    }
  }
  rcu_aux_read_unlock();
  return ok;
}

void db_ingest_config_changed(void) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return;
  atomic_store_explicit(&g_cfg_dirty, true, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_CONFIG, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* karictl dbstatus                                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

/* "YYYY-MM-DD HH:MM:SS UTC" without the C library's time functions: gmtime_r() and localtime_r() load a time zone file
 * on first use, which the Backend must not do in capability mode (CLAUDE.md Rule 2; it is a SIGTRAP).  The days are
 * converted with the civil-from-days algorithm (proleptic Gregorian calendar). */
static void fmt_time(int64_t t, char *buf, size_t n) {
  if (t <= 0) {
    snprintf(buf, n, "never");
    return;
  }
  int64_t days = t / 86400, rem = t % 86400;
  int64_t z = days + 719468;
  int64_t era = z / 146097;
  int64_t doe = z - era * 146097;
  int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = yoe + era * 400;
  int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  int64_t mp = (5 * doy + 2) / 153;
  int64_t d = doy - (153 * mp + 2) / 5 + 1;
  int64_t m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) y++;
  snprintf(buf, n, "%04lld-%02lld-%02lld %02lld:%02lld:%02lld UTC", (long long)y, (long long)m, (long long)d,
           (long long)(rem / 3600), (long long)(rem % 3600 / 60), (long long)(rem % 60));
}

typedef struct {
  const char *zone, *view;
  char *out;
  size_t cap, len;
  int matches;
  const server_config_t *cfg;   /* B7a: for the ceiling lines of one zone; valid inside the read section of db_ingest_status() */
} status_ctx_t;

static void st_append(status_ctx_t *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void st_append(status_ctx_t *c, const char *fmt, ...) {
  if (c->len + 1 >= c->cap) return;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(c->out + c->len, c->cap - c->len, fmt, ap);
  va_end(ap);
  if (n > 0) c->len = (size_t)n < c->cap - c->len ? c->len + (size_t)n : c->cap - 1;
}

static void st_list(status_ctx_t *c, const char *label, char *const *list, int n) {
  if (n <= 0) return;
  st_append(c, " %s", label);
  for (int i = 0; i < n && i < 8; i++) st_append(c, "%s%.64s", i ? ", " : " ", list[i] ? list[i] : "?");
  if (n > 8) st_append(c, ", ... (%d entries)", n);
}

/* B7b: a SLAVE / CONSUMER zone: where it transfers from and how far it got (its data is in memory only) */
static void secondary_status(status_ctx_t *c, const zone_db_entry_t *e, const zone_config_t *dc) {
  const zone_ext_t *x = dc->ext;
  st_append(c, "  type: %s, masters", dc->is_catalog ? "catalog consumer (CONSUMER)" : "secondary (SLAVE)");
  for (int i = 0; x && i < x->masters_count && i < 8; i++)
    st_append(c, "%s%.64s port %d", i ? ", " : " ", x->masters[i].ip ? x->masters[i].ip : "?", config_target_port(c->cfg, x->masters[i].port));
  if (x && x->masters_count > 8) st_append(c, ", ... (%d entries; only the first is used for transfers)", x->masters_count);
  if (x && x->tsig_key) st_append(c, ", TSIG key '%.64s'", x->tsig_key);
  st_append(c, "\n");
  time_t last = atomic_load_explicit(&e->last_successful_transfer, memory_order_acquire);
  char t[40];
  fmt_time((int64_t)last, t, sizeof(t));
  if (last > 0)
    st_append(c, "  transfer: last successful %s, serial %u (kept in memory only; a restart transfers it again)\n", t,
              (unsigned)atomic_load_explicit(&e->serial, memory_order_relaxed));
  else
    st_append(c, "  transfer: no transfer has succeeded yet (kept in memory only)\n");
  /* B8t-2: the settings the primary sent with the zone (Extended AXFR version 3); the statements of the zone's own metadata win */
  if (atomic_load_explicit(&e->rxcfg, memory_order_acquire))
    st_append(c, "  settings from the primary: in force (what the zone's own metadata sets wins over them)\n");
}

/* B7a: where the settings of a DB zone come from and what acl-ceiling makes of its ACLs */
static void settings_status(status_ctx_t *c, const zone_db_entry_t *e) {
  const zone_config_t *dc = atomic_load_explicit(&e->dbcfg, memory_order_acquire);
  if (dc && e->is_secondary) secondary_status(c, e, dc);
  if (!dc || !dc->ext_shared) {
    st_append(c, "  settings: none (the defaults; no ACLs, so transfers and updates are refused)\n");
    return;
  }
  const zone_ext_shared_t *sh = (const zone_ext_shared_t *)dc->ext;
  const zone_ext_t *x = dc->ext;
  if (sh->profile[0])
    st_append(c, "  settings: profile '%.64s' (statements in the zone's own metadata override the profile's)\n", sh->profile);
  else
    st_append(c, "  settings: the zone's own metadata\n");
  if (x->allow_transfer_count > 0 || x->tsig_keys_count > 0) {
    st_append(c, "  allow-transfer:");
    st_list(c, "addresses", x->allow_transfer, x->allow_transfer_count);
    st_list(c, "keys", x->tsig_keys, x->tsig_keys_count);
    st_append(c, " (match %s)\n", x->transfer_acl_match == ACL_MATCH_ANY ? "any" : "all");
  }
  if (x->allow_update_count > 0) {
    st_append(c, "  allow-update:");
    st_list(c, "entries", x->allow_update, x->allow_update_count);
    st_append(c, " (match %s)\n", x->update_acl_match == ACL_MATCH_ALL ? "all" : "any");
  }
  if (c->cfg) {
    char notes[400];
    if (ceiling_notes(c->cfg, x, notes, sizeof(notes)) > 0) st_append(c, "  acl-ceiling: %s\n", notes);
    const char *missing = db_settings_missing_key(x, c->cfg);
    if (missing)
      st_append(c, "  settings error: the TSIG key '%.64s' is not defined in karidns.conf; the ACL that names it refuses everybody\n",
                missing);
  }
}

static bool status_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  status_ctx_t *c = ud;
  if (c->view && strcasecmp(c->view, view) != 0) return true;
  if (!domain_names_match_ci(z->name, c->zone)) return true;
  c->matches++;
  const char *st = z->shadowed ? "shadowed" : (z->last_result == DBREG_REJECTED ? "rejected" : "applied");
  st_append(c, "zone %s view %s: source id %lld, serial %u, status %s", z->name, view, (long long)z->source_id,
            zdir_entry(z) ? (zdir_entry(z)->is_secondary ? atomic_load_explicit(&zdir_entry(z)->serial, memory_order_relaxed) : z->serial) : 0u, st);
  if (z->shadowed) st_append(c, z->shadow_by == DBREG_SH_CATALOG ? " (hidden by a catalog member)" : " (hidden by a zone in karidns.conf)");
  if (z->last_result == DBREG_REJECTED && zdir_entry(z)) st_append(c, " (serving the last good version, serial %u)", z->serial);
  if (!zdir_entry(z)) st_append(c, " (no version loaded)");
  if (z->error) st_append(c, ", last error: %s", z->error);
  st_append(c, "\n");
  if (zdir_entry(z)) settings_status(c, zdir_entry(z));
  return true;
}

size_t db_ingest_status(const char *zone, const char *view, char *out, size_t cap) {
  if (cap == 0) return 0;
  out[0] = '\0';
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  if (!snap.enabled) return 0;
  status_ctx_t c = { zone, view, out, cap, 0, 0, NULL };
  if (zone) {
    dbreg_cursor_t cur;
    memset(&cur, 0, sizeof(cur));
    rcu_aux_read_lock();                                 /* the entries' settings blocks are read */
    c.cfg = acquire_config_snapshot();
    (void)dbreg_walk(&cur, status_cb, &c);
    rcu_aux_read_unlock();
    if (c.matches == 0) st_append(&c, "zone %s: not in the database registry\n", zone);
    return c.len;
  }
  char err[ST_STR], ver[ST_STR], t1[40], t2[40], t3[40];
  int64_t err_time = 0;
  st_get_strings(err, sizeof(err), ver, sizeof(ver), &err_time);
  fmt_time(atomic_load(&g_st.since), t1, sizeof(t1));
  if (atomic_load(&g_st.connected))
    st_append(&c, "loader: connected since %s (pid %u, %s)\n", t1, atomic_load(&g_st.pid), ver);
  else if (atomic_load(&g_st.ever_connected))
    st_append(&c, "loader: not connected since %s (last pid %u)\n", t1, atomic_load(&g_st.pid));
  else
    st_append(&c, "loader: not connected yet\n");
  size_t total, rejected, sh_cfg, sh_cat;
  dbreg_counts2(&total, &rejected, &sh_cfg, &sh_cat);
  if (sh_cat == 0)
    st_append(&c, "zones: %zu in the registry (%zu served, %zu shadowed by karidns.conf), %zu with a rejected version\n",
              total, total - sh_cfg, sh_cfg, rejected);
  else
    st_append(&c, "zones: %zu in the registry (%zu served, %zu shadowed by karidns.conf, %zu hidden by catalog members), "
                  "%zu with a rejected version\n", total, total - sh_cfg - sh_cat, sh_cfg, sh_cat, rejected);
  {
    /* D1a (design 8.1): what the zone versions hold; "retired" = replaced, not freed yet (a reader or a transfer may still hold it) */
    zone_bytes_t zdb, zot;
    zone_bytes_get(ZBYTES_DB, &zdb);
    zone_bytes_get(ZBYTES_OTHER, &zot);
    st_append(&c, "zone versions and IXFR deltas: database zones %llu bytes resident + %llu retired; other zones %llu resident + %llu retired\n",
              (unsigned long long)zdb.resident, (unsigned long long)zdb.retired, (unsigned long long)zot.resident,
              (unsigned long long)zot.retired);
    size_t nel, rbytes, ibytes;
    dbreg_dir_bytes(&nel, &rbytes, &ibytes);
    st_append(&c, "zone directory: %zu elements, %zu bytes in the registry + %zu bytes in the indexes of the views (%zu bytes per zone)\n",
              nel, rbytes, ibytes, nel ? (rbytes + ibytes) / nel : (size_t)0);
  }
  fmt_time(atomic_load(&g_st.batch_time), t2, sizeof(t2));
  if (atomic_load(&g_st.batch_id) == 0)
    st_append(&c, "last batch: none yet\n");
  else
    st_append(&c, "last batch: id %llu, kind %s, %s %s: %u applied, %u rejected, %u shadowed, %u deleted\n",
              (unsigned long long)atomic_load(&g_st.batch_id), kind_name(atomic_load(&g_st.batch_kind)),
              atomic_load(&g_st.batch_done) ? "finished" : "started", t2, atomic_load(&g_st.b_applied),
              atomic_load(&g_st.b_rejected), atomic_load(&g_st.b_shadowed), atomic_load(&g_st.b_deleted));
  if (!snap.auto_reload) {
    st_append(&c, "auto reload: off\n");
  } else {
    st_append(&c, "auto reload: on (poll-interval %u s, coalesce %u ms), %llu auto batch(es) since start\n", snap.poll_interval,
              snap.coalesce_ms, (unsigned long long)atomic_load(&g_st.tot_auto_batches));
    rcu_aux_read_lock();
    const server_config_t *vcfg = acquire_config_snapshot();
    uint32_t vidx = 0;
    for (const view_config_t *v = vcfg ? vcfg->views : NULL; v; v = v->next, vidx++) {
      if (v->database_none) continue;
      as_data_t ad;
      char tp[40];
      if (vidx >= KARIDNS_DB_MAX_VIEWS || !as_get(&g_as[vidx], &ad) || !(ad.flags & KDB_AS_AUTO)) {
        st_append(&c, "  view %.64s: no report from the loader yet\n", v->name ? v->name : "?");
        continue;
      }
      fmt_time(ad.last_poll, tp, sizeof(tp));
      st_append(&c, "  view %.64s: last poll %s, applied change seq %llu, pending changes %u, last error: %s\n",
                v->name ? v->name : "?", tp, (unsigned long long)ad.applied_seq, ad.pending, ad.err[0] ? ad.err : "none");
    }
    rcu_aux_read_unlock();
  }
  /* B11: multi-server reload requests, one line per view whose source has the tables (the loader reports them whether or not
   * auto reload is on) */
  {
    rcu_aux_read_lock();
    const server_config_t *vcfg = acquire_config_snapshot();
    uint32_t vidx = 0;
    for (const view_config_t *v = vcfg ? vcfg->views : NULL; v; v = v->next, vidx++) {
      if (v->database_none || vidx >= KARIDNS_DB_MAX_VIEWS) continue;
      as_data_t rd;
      if (!as_get(&g_as[vidx], &rd) || !(rd.flags & KDB_AS_REQ)) continue;
      char tw[40];
      fmt_time(rd.req_time, tw, sizeof(tw));
      st_append(&c, "reload requests (view %.64s): server-id %s, last applied generation %llu, ok %s, status written %s, last error: %s\n",
                v->name ? v->name : "?", rd.server_id[0] ? rd.server_id : "(none)", (unsigned long long)rd.req_generation,
                rd.req_ok ? "yes" : "no", tw, rd.req_err[0] ? rd.req_err : "none");
    }
    rcu_aux_read_unlock();
  }
  st_append(&c, "since start: %llu applied, %llu rejected, %llu shadowed, %llu deleted, %llu failed in the loader\n",
            (unsigned long long)atomic_load(&g_st.tot_applied), (unsigned long long)atomic_load(&g_st.tot_rejected),
            (unsigned long long)atomic_load(&g_st.tot_shadowed), (unsigned long long)atomic_load(&g_st.tot_deleted),
            (unsigned long long)atomic_load(&g_st.tot_failed));
  st_append(&c, "settings: %zu distinct (shared between zones), %u zone(s) name a TSIG key that karidns.conf does not define\n",
            db_settings_count(), atomic_load_explicit(&g_settings_missing_keys, memory_order_relaxed));
  fmt_time(err_time, t3, sizeof(t3));
  if (err[0]) st_append(&c, "last protocol error: %s (%s)\n", err, t3);
  else st_append(&c, "last protocol error: none\n");
  return c.len;
}

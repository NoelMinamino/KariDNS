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
#include <syslog.h>
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

typedef struct {
  uint64_t generation;
  char driver[40];
  uint32_t nviews;
  uint64_t max_zone_records, max_zone_bytes;
  uint32_t ingest_threads;
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
  bool has_settings;
  uint8_t *buf;                          /* ingest-threads > 1: the ZONE_DATA messages, [u32 length][bytes] each */
  size_t buf_len, buf_cap;
  uint8_t status;                        /* KDB_ST_* */
  int builder;                           /* index of the builder it was handed to */
  char reason[KDB_REASON_LEN];
} ing_job_t;

typedef struct {
  pthread_t tid;
  int kq;
  _Atomic(ing_job_t *) slot;
} ing_builder_t;

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
  uint32_t settings_ignored;
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
} ing_t;

enum { ROUT_NONE = 0, ROUT_APPLIED, ROUT_SHADOWED, ROUT_REJECTED, ROUT_FAILED, ROUT_DELETED };
static void answer_request(ing_t *g);

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
  free(j->buf);
  free(j);
}

static void job_reject(ing_job_t *j, const char *why) {
  j->status = KDB_ST_REJECTED;
  snprintf(j->reason, sizeof(j->reason), "%s", why);
}

/* A new entry for a DB zone (design 4.2): source DB, a primary, its own settings block (B4b: the defaults) */
static zone_db_entry_t *new_db_entry(const char *view, const char *zone) {
  zone_db_entry_t *e = create_new_zone_entry(zone, view);
  if (!e) return NULL;
  zone_config_t *dc = db_zone_config_new(zone);
  if (!dc) {
    free_zone_db_entry(e);
    return NULL;
  }
  e->source = ZONE_SRC_DB;
  e->kind = ZONE_KIND_PRIMARY;
  e->is_secondary = false;
  atomic_store_explicit(&e->dbcfg, dc, memory_order_release);
  rcu_aux_read_lock();
  ixfr_history_set_depth(e, ixfr_history_effective(acquire_config_snapshot(), dc));
  rcu_aux_read_unlock();
  return e;
}

/* ZONE_END work, on the stream thread (ingest-threads 1) or a builder: feed what was buffered, check, publish the
 * image into the entry, enter the zone in the registry.  Sets j->status / j->reason; the reply is the caller's. */
static void job_execute(ing_job_t *j) {
  if (j->skip) {                                         /* status and reason were set at ZONE_BEGIN */
    if (j->view_name[0]) (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
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
  if (!entry) {
    entry = new_db_entry(j->view_name, j->zone);
    if (!entry) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    created = true;
  }
  if (db_zone_build_install(j->build, entry, NULL, j->reason, sizeof(j->reason)) != 0) {
    if (created) free_zone_db_entry(entry);              /* never registered or published into a snapshot */
    j->status = KDB_ST_REJECTED;
    goto rejected;
  }
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
  for (;;) {
    if (kevent(b->kq, NULL, 0, &ev, 1, NULL) < 0) {
      if (errno == EINTR) continue;
      syslog(LOG_ERR, "[DB] a builder thread stops: kevent: %s", strerror(errno));
      return NULL;
    }
    ing_job_t *j = atomic_exchange_explicit(&b->slot, NULL, memory_order_acquire);
    if (!j) continue;
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

/* the answer of a finished job; the job is freed */
static void job_finish(ing_t *g, ing_job_t *j) {
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
  if (j->has_settings) g->settings_ignored++;
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
  if (!z->entry) return true;                            /* never applied: nothing the loader could skip */
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
      kdb_enc_bytes(&g->enc, 5, z->digest, KDB_DIGEST_LEN) != 0 || kdb_enc_nest_end(&g->enc) != 0) {
    c->bad = true;
    return false;
  }
  c->n++;
  return true;
}

static void pump_inventory(ing_t *g) {
  while (g->inv_active && g->stream_fd >= 0 && g->out_len - g->out_off < ING_INV_QUEUE_LOW) {
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
  g->settings_ignored = 0;
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

static void on_zone_begin(ing_t *g, const kdb_msg_t *m) {
  const kdb_zone_begin_t *zb = &m->u.zone_begin;
  ing_job_t *j = calloc(1, sizeof(*j));
  if (!j) {
    syslog(LOG_ERR, "[DB] out of memory; closing the stream");
    drop_stream(g);
    return;
  }
  j->view = zb->view;
  snprintf(j->zone, sizeof(j->zone), "%s", zb->name);
  j->source_id = zb->source_id;
  j->serial = zb->serial;
  j->rr_count = zb->rr_count;
  memcpy(j->digest, zb->digest, KDB_DIGEST_LEN);
  j->has_settings = zb->settings.p != NULL && zb->settings.len > 0;
  if (j->has_settings && g->settings_ignored == 0)
    syslog(LOG_INFO, "[DB] zone '%s': the settings text is ignored (zone settings from the database come with B7); "
                     "the zone runs with the default settings", zb->name);
  if (zb->view < g->nview_names) snprintf(j->view_name, sizeof(j->view_name), "%s", g->view_names[zb->view]);
  if (j->view_name[0] == '\0') {
    j->skip = true;
    job_reject(j, "the view is not in the configuration");
  } else if (zb->zone_kind != KDB_ZK_PRIMARY) {
    j->skip = true;
    job_reject(j, "secondary and catalog zones from the database are not supported yet");
  } else if (zb->flags & KDB_ZF_EXTENDED) {
    j->skip = true;
    job_reject(j, "extended attributes (tags, tinydns) from the database are not supported yet");
  } else {
    j->build = db_zone_build_new(j->zone, j->rr_count);
    if (!j->build) {
      j->skip = true;
      job_reject(j, "out of memory");
    }
  }
  g->cur = j;
}

static void on_zone_data(ing_t *g, const kdb_msg_t *m) {
  ing_job_t *j = g->cur;
  if (!j || j->skip || j->failed) return;
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
  if (g->settings_ignored > 0)
    syslog(LOG_INFO, "[DB] %u zone(s) of the batch carried a settings text; it is ignored until B7", g->settings_ignored);
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
  default: /* PROFILE: counted by the state machine, used with B7 */
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
    int got = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
      if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
      size_t cnt = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      for (size_t i = 0; i < cnt; i++) {
        int fd;
        memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
        if (got < 0) got = fd;
        else close(fd); /* one stream per message */
      }
    }
    if (m.msg_flags & MSG_CTRUNC) syslog(LOG_ERR, "[DB] the loader control message was truncated");
    if (got >= 0) adopt_stream(g, got);
  }
}

static void on_config_event(ing_t *g) {
  if (!atomic_exchange_explicit(&g_cfg_dirty, false, memory_order_acq_rel)) return;
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

static void *ingest_thread(void *arg) {
  ing_t *g = arg;
  rcu_aux_thread_pin();
  struct kevent evs[8];
  for (;;) {
    struct timespec ts, *tp = NULL;
    if (dbreg_pending_count() > 0) {                     /* new zones are waiting to become visible */
      int64_t left = g->last_delta_ms + ING_DELTA_MS - now_ms();
      if (left < 0) left = 0;
      ts.tv_sec = left / 1000;
      ts.tv_nsec = (left % 1000) * 1000000;
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
      } else if (e->filter == EVFILT_USER) {
        on_config_event(g);
      } else if (g->ctrl_fd >= 0 && e->ident == (uintptr_t)g->ctrl_fd) {
        on_ctrl_readable(g);
      } else if (g->stream_fd >= 0 && e->ident == (uintptr_t)g->stream_fd) {
        if (e->filter == EVFILT_WRITE) out_flush(g);
        else on_stream_readable(g);
      }
      if (g->need_cleanup) cleanup_stream_state(g);
    }
    if (g->inv_active) pump_inventory(g);
    if (g->need_cleanup) cleanup_stream_state(g);
    maybe_apply_delta(g);
    if (g->stream_fd >= 0 && g->out_off < g->out_len) out_flush(g);
  }
}

bool db_ingest_start(int stream_fd, int ctrl_fd) {
  ing_t *g = &g_ing;
  memset(g, 0, sizeof(*g));
  g->stream_fd = -1;
  g->cur_req = -1;
  g->ctrl_fd = ctrl_fd;
  g->body = malloc(KDB_MAX_BODY);
  g->rbuf = malloc(ING_RBUF);
  kdb_enc_init(&g->enc);
  g->kq = kqueue();
  g->wait_kq = kqueue();
  if (!g->body || !g->rbuf || g->kq < 0 || g->wait_kq < 0 || ctrl_fd < 0) {
    syslog(LOG_ERR, "[DB] cannot start the ingest thread: %s", g->kq < 0 ? strerror(errno) : "no control socket or memory");
    return false;
  }
  limit_ctrl_rights(ctrl_fd);
  struct kevent ev[4];
  EV_SET(&ev[0], ctrl_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], ING_EVT_CONFIG, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[2], ING_EVT_RESULT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[3], ING_EVT_REQ, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kevent(g->kq, ev, 4, NULL, 0, NULL) != 0) {
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

static bool status_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  status_ctx_t *c = ud;
  if (c->view && strcasecmp(c->view, view) != 0) return true;
  if (!domain_names_match_ci(z->name, c->zone)) return true;
  c->matches++;
  const char *st = z->shadowed ? "shadowed" : (z->last_result == DBREG_REJECTED ? "rejected" : "applied");
  st_append(c, "zone %s view %s: source id %lld, serial %u, status %s", z->name, view, (long long)z->source_id,
            z->entry ? z->serial : 0u, st);
  if (z->shadowed) st_append(c, z->shadow_by == DBREG_SH_CATALOG ? " (hidden by a catalog member)" : " (hidden by a zone in karidns.conf)");
  if (z->last_result == DBREG_REJECTED && z->entry) st_append(c, " (serving the last good version, serial %u)", z->serial);
  if (!z->entry) st_append(c, " (no version loaded)");
  if (z->error) st_append(c, ", last error: %s", z->error);
  st_append(c, "\n");
  return true;
}

size_t db_ingest_status(const char *zone, const char *view, char *out, size_t cap) {
  if (cap == 0) return 0;
  out[0] = '\0';
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  if (!snap.enabled) return 0;
  status_ctx_t c = { zone, view, out, cap, 0, 0 };
  if (zone) {
    dbreg_cursor_t cur;
    memset(&cur, 0, sizeof(cur));
    (void)dbreg_walk(&cur, status_cb, &c);
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
  fmt_time(atomic_load(&g_st.batch_time), t2, sizeof(t2));
  if (atomic_load(&g_st.batch_id) == 0)
    st_append(&c, "last batch: none yet\n");
  else
    st_append(&c, "last batch: id %llu, kind %s, %s %s: %u applied, %u rejected, %u shadowed, %u deleted\n",
              (unsigned long long)atomic_load(&g_st.batch_id), kind_name(atomic_load(&g_st.batch_kind)),
              atomic_load(&g_st.batch_done) ? "finished" : "started", t2, atomic_load(&g_st.b_applied),
              atomic_load(&g_st.b_rejected), atomic_load(&g_st.b_shadowed), atomic_load(&g_st.b_deleted));
  st_append(&c, "since start: %llu applied, %llu rejected, %llu shadowed, %llu deleted, %llu failed in the loader\n",
            (unsigned long long)atomic_load(&g_st.tot_applied), (unsigned long long)atomic_load(&g_st.tot_rejected),
            (unsigned long long)atomic_load(&g_st.tot_shadowed), (unsigned long long)atomic_load(&g_st.tot_deleted),
            (unsigned long long)atomic_load(&g_st.tot_failed));
  fmt_time(err_time, t3, sizeof(t3));
  if (err[0]) st_append(&c, "last protocol error: %s (%s)\n", err, t3);
  else st_append(&c, "last protocol error: none\n");
  return c.len;
}

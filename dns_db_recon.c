/*
 * dns_db_recon.c - the reconcile thread of the Backend: the pages of a manifest pass are decoded and recorded here, off the thread that answers the fetches and the lookups (see dns_db_recon.h).
 */
#include "dns_db_recon.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/event.h>

#include "dns_config_parser.h"
#include "dns_db_store.h"
#include "dns_epoch_rcu.h"
#include "dns_log.h"
#include "dns_server_internal.h"
#include "dns_store_status.h"

enum { RTI_PAGE = 1, RTI_BEGIN, RTI_END };

typedef struct {
  uint8_t kind;
  uint64_t epoch;                    /* the stream the item came from (db_recon_abort_stream() counts them) */
  uint32_t view_count;
  /* BEGIN */
  uint64_t batch_id, count;
  uint16_t view;
  bool force;
  char vname[KARIDNS_VIEW_NAME_MAX];
  /* END */
  kdb_manifest_end_t end;
  /* PAGE */
  uint32_t len;
  uint8_t *body;                     /* KDB_MAX_BODY, allocated at the start */
} rt_item_t;

static struct {
  rt_item_t slot[DBRT_SLOTS];
  _Atomic uint64_t head, tail;       /* items consumed (a slot is free again) / posted; the slot of item n is n % DBRT_SLOTS */
  _Atomic uint64_t epoch, seen_epoch;
  int kq, notify_kq;
  uintptr_t notify_ident;
  bool started;
  /* a protocol error of the loader found here (the reason is written before err is set) */
  _Atomic bool err;
  _Atomic uint64_t err_epoch;
  _Atomic bool err_lock;             /* the error is written by this thread and taken by the stream thread: a spin lock held for the copy of the reason (the way of park_wake_push_ask()) */
  char err_why[KDB_REASON_LEN];
  /* what the entries became, since the ingest thread took them last */
  _Atomic uint32_t c_applied, c_unchanged, c_rejected, c_deleted;
  _Atomic uint64_t c_zones;
  _Atomic uint64_t t_applied, t_rejected, t_deleted;       /* the totals since the start (karictl dbstatus): never reset, so they may be read at any time */
  _Atomic bool c_wanted;
  /* the figures of the status (the thread's own window of a second) */
  _Atomic uint64_t st_busy_pct, st_eps, st_apply_ns, st_entries, st_pages, st_full;
  _Atomic uint64_t loop_cur_us, loop_prev_us, stream_cur_us, stream_prev_us;
  /* the thread's own state */
  kdb_man_t man;
  kdb_msg_t msg;
  bool skip, ch_failed, failed;      /* the pass is read and checked, not applied / an entry could not be recorded / a protocol error was found: the rest of the stream is dropped */
  uint32_t man_n;
  char vname[KARIDNS_VIEW_NAME_MAX];
  kdb_manifest_entry_t ents[DBRT_CHUNK];
  db_recon_entry_t re[DBRT_CHUNK];
  int res[DBRT_CHUNK];
  uint32_t zid[DBRT_CHUNK];
} RT;

static int64_t rt_mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000ll + ts.tv_nsec;
}

static void rt_trigger(int kq, uintptr_t ident) {
  struct kevent t;
  EV_SET(&t, ident, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &t, 1, NULL, 0, NULL);
}
static void rt_notify(void) { rt_trigger(RT.notify_kq, RT.notify_ident); }

/* ---- what an entry became (shared with the ingest thread's own CHANGES) ---- */

bool db_recon_note(dbrt_counts_t *c, int r, const char *zone, bool *unstorable_logged) {
  switch (r) {
  case DBR_NEW:
  case DBR_CHANGED:
  case DBR_RENAMED:
    c->applied++;
    c->tot_applied++;
    return true;
  case DBR_PENDING:
    c->applied++;
    return true;
  case DBR_SAME:
  case DBR_KEPT:
    c->unchanged++;
    return false;
  case DBR_UNSTORABLE:
    c->rejected++;
    c->tot_rejected++;
    if (!*unstorable_logged) {
      *unstorable_logged = true;
      syslog(LOG_WARNING, "[DB] zone '%s' cannot be served: the store and the zone directory key a name by at most 255 bytes of text (only escapes make a longer one), or the Backend is out of memory; the zone is not loaded", zone);
    }
    return false;
  default:
    c->rejected++;
    c->tot_rejected++;
    c->failed = true;
    return false;
  }
}

static void rt_publish(const dbrt_counts_t *c) {
  if (c->applied) atomic_fetch_add_explicit(&RT.c_applied, c->applied, memory_order_relaxed);
  if (c->unchanged) atomic_fetch_add_explicit(&RT.c_unchanged, c->unchanged, memory_order_relaxed);
  if (c->rejected) atomic_fetch_add_explicit(&RT.c_rejected, c->rejected, memory_order_relaxed);
  if (c->deleted) atomic_fetch_add_explicit(&RT.c_deleted, c->deleted, memory_order_relaxed);
  if (c->tot_applied) atomic_fetch_add_explicit(&RT.t_applied, c->tot_applied, memory_order_relaxed);
  if (c->tot_rejected) atomic_fetch_add_explicit(&RT.t_rejected, c->tot_rejected, memory_order_relaxed);
  if (c->tot_deleted) atomic_fetch_add_explicit(&RT.t_deleted, c->tot_deleted, memory_order_relaxed);
  if (c->zones) atomic_fetch_add_explicit(&RT.c_zones, c->zones, memory_order_relaxed);
  if (c->wanted) atomic_store_explicit(&RT.c_wanted, true, memory_order_release);
}

void db_recon_take(dbrt_counts_t *out) {
  memset(out, 0, sizeof(*out));
  out->applied = atomic_exchange_explicit(&RT.c_applied, 0, memory_order_relaxed);
  out->unchanged = atomic_exchange_explicit(&RT.c_unchanged, 0, memory_order_relaxed);
  out->rejected = atomic_exchange_explicit(&RT.c_rejected, 0, memory_order_relaxed);
  out->deleted = atomic_exchange_explicit(&RT.c_deleted, 0, memory_order_relaxed);
  out->zones = atomic_exchange_explicit(&RT.c_zones, 0, memory_order_relaxed);
}

bool db_recon_wanted_take(void) { return atomic_exchange_explicit(&RT.c_wanted, false, memory_order_acquire); }

void db_recon_totals(uint64_t *applied, uint64_t *rejected, uint64_t *deleted) {
  *applied = atomic_load_explicit(&RT.t_applied, memory_order_relaxed);
  *rejected = atomic_load_explicit(&RT.t_rejected, memory_order_relaxed);
  *deleted = atomic_load_explicit(&RT.t_deleted, memory_order_relaxed);
}

/* ---- the producer: the ingest thread ---- */

bool db_recon_room(void) {
  return atomic_load_explicit(&RT.tail, memory_order_relaxed) - atomic_load_explicit(&RT.head, memory_order_acquire) < DBRT_SLOTS;
}

bool db_recon_idle(void) {
  return atomic_load_explicit(&RT.head, memory_order_acquire) == atomic_load_explicit(&RT.tail, memory_order_relaxed) &&
         atomic_load_explicit(&RT.seen_epoch, memory_order_acquire) == atomic_load_explicit(&RT.epoch, memory_order_relaxed);
}

static rt_item_t *rt_claim(uint8_t kind, uint32_t view_count) {
  const uint64_t t = atomic_load_explicit(&RT.tail, memory_order_relaxed);
  rt_item_t *it = &RT.slot[t % DBRT_SLOTS];
  it->kind = kind;
  it->epoch = atomic_load_explicit(&RT.epoch, memory_order_relaxed);
  it->view_count = view_count;
  return it;
}
static void rt_post(void) {
  atomic_store_explicit(&RT.tail, atomic_load_explicit(&RT.tail, memory_order_relaxed) + 1, memory_order_release);
  rt_trigger(RT.kq, 1);
}

void db_recon_post_begin(uint64_t batch_id, uint16_t view, uint32_t view_count, const char *vname, uint64_t count, bool force) {
  rt_item_t *it = rt_claim(RTI_BEGIN, view_count);
  it->batch_id = batch_id;
  it->view = view;
  it->count = count;
  it->force = force;
  snprintf(it->vname, sizeof(it->vname), "%s", vname);
  rt_post();
}

void db_recon_post_page(const uint8_t *body, uint32_t len, uint32_t view_count) {
  rt_item_t *it = rt_claim(RTI_PAGE, view_count);
  it->len = len;
  memcpy(it->body, body, len);                             /* (len <= KDB_MAX_BODY: the framer's limit) */
  rt_post();
}

void db_recon_post_end(const kdb_manifest_end_t *e) {
  rt_item_t *it = rt_claim(RTI_END, 0);
  it->end = *e;
  rt_post();
}

void db_recon_abort_stream(void) {
  atomic_fetch_add_explicit(&RT.epoch, 1, memory_order_release);
  if (RT.started) rt_trigger(RT.kq, 1);
}

bool db_recon_error_take(char *why, size_t cap) {
  if (!atomic_load_explicit(&RT.err, memory_order_acquire)) return false;
  while (atomic_exchange_explicit(&RT.err_lock, true, memory_order_acquire)) {}
  /* (under the lock: rt_fail() of the stream that follows cannot be cleared by a stale clear made here, and the reason is not written while it is copied) */
  bool take = atomic_load_explicit(&RT.err, memory_order_relaxed);
  if (take && atomic_load_explicit(&RT.err_epoch, memory_order_relaxed) == atomic_load_explicit(&RT.epoch, memory_order_relaxed)) snprintf(why, cap, "%s", RT.err_why);
  else take = false;                                                              /* (none, or of a stream that is gone) */
  atomic_store_explicit(&RT.err, false, memory_order_relaxed);
  atomic_store_explicit(&RT.err_lock, false, memory_order_release);
  return take;
}

void db_recon_note_full(void) { atomic_fetch_add_explicit(&RT.st_full, 1, memory_order_relaxed); }

/* the longest of a kind in a window of ten seconds: win_start / cur are the one writer's (the ingest thread), the two figures that are read are atomics */
typedef struct { int64_t start; uint64_t cur; } rt_win_t;
static void rt_win_note(rt_win_t *w, _Atomic uint64_t *cur_out, _Atomic uint64_t *prev_out, int64_t ns) {
  const int64_t now = rt_mono_ns();
  if (w->start == 0) w->start = now;
  if (now - w->start >= 10000000000ll) {
    atomic_store_explicit(prev_out, w->cur, memory_order_relaxed);
    w->cur = 0;
    atomic_store_explicit(cur_out, 0, memory_order_relaxed);
    w->start = now;
  }
  const uint64_t us = (uint64_t)(ns / 1000);
  if (us > w->cur) {
    w->cur = us;
    atomic_store_explicit(cur_out, us, memory_order_relaxed);
  }
}
void db_recon_note_loop(int64_t ns) {
  static rt_win_t w;
  rt_win_note(&w, &RT.loop_cur_us, &RT.loop_prev_us, ns);
}
void db_recon_note_stream(int64_t ns) {
  static rt_win_t w;
  rt_win_note(&w, &RT.stream_cur_us, &RT.stream_prev_us, ns);
}

/* ---- the consumer ---- */

/* a protocol error of the loader: the reason is for the stream thread, which closes the stream; this thread drops the rest of what the stream sent */
static void rt_fail(const char *why, uint64_t epoch) {
  while (atomic_exchange_explicit(&RT.err_lock, true, memory_order_acquire)) {}
  snprintf(RT.err_why, sizeof(RT.err_why), "%s", why);
  atomic_store_explicit(&RT.err_epoch, epoch, memory_order_relaxed);               /* (the stream of the item that was bad, not the one that is current now: if that has ended meanwhile the error is stale and dropped, not the next stream's) */
  atomic_store_explicit(&RT.err, true, memory_order_release);
  atomic_store_explicit(&RT.err_lock, false, memory_order_release);
  RT.failed = true;
  rt_notify();
}

static void rt_begin(const rt_item_t *it) {
  RT.skip = true;
  RT.man_n = 0;
  RT.ch_failed = false;
  RT.vname[0] = '\0';
  kdb_man_begin(&RT.man, it->batch_id, it->view, it->view_count);
  if (!it->vname[0]) return;                                /* (the stream thread said so: the configuration has no such view) */
  char why[160];
  if (!db_recon_begin(it->vname, it->count, it->force, why, sizeof(why))) {
    syslog(LOG_ERR, "[DB] view '%s': the manifest pass cannot be applied: %s", it->vname, why);
    return;
  }
  RT.skip = false;
  snprintf(RT.vname, sizeof(RT.vname), "%s", it->vname);
  syslog(LOG_INFO, "[DB] view '%s': a manifest pass starts (the loader lists every zone of its source, about %llu)%s", it->vname, (unsigned long long)it->count,
         it->force ? "; asked for by the operator (karictl reload -force)" : "");
}

/* one page: decode and check, then the entries in groups; returns the nanoseconds the entries took to record (the apply) and their number */
static void rt_page(const rt_item_t *it, int64_t *apply_ns, uint64_t *entries) {
  kdb_frame_t fr = { KDB_T_MANIFEST, it->body, it->len };
  char why[KDB_REASON_LEN];
  kdb_rc_t rc = kdb_man_page(&RT.man, &fr, &RT.msg, why, sizeof(why));
  if (rc != KDB_OK) {
    rt_fail(why, it->epoch);
    return;
  }
  dbrt_counts_t c;
  memset(&c, 0, sizeof(c));
  c.zones = RT.msg.u.manifest.n_entries;
  if (RT.skip) {
    rt_publish(&c);
    return;
  }
  kdb_iter_t iter;
  burst_yield_t by = BURST_YIELD_INIT;
  bool unst = false;
  unsigned groups = 0;
  kdb_manifest_entries(&RT.msg, &iter);
  for (;;) {
    unsigned k = 0;
    while (k < DBRT_CHUNK && kdb_manifest_entries_next(&iter, &RT.ents[k])) {
      const kdb_manifest_entry_t *e = &RT.ents[k];
      db_recon_entry_t *re = &RT.re[k];
      memset(re, 0, sizeof(*re));
      re->source_id = e->source_id;
      re->name = e->name;
      re->kind = e->kind;
      re->stamped = e->stamped;
      re->gen = e->stamp_gen;
      re->time = e->stamp_time;
      re->has_serial = e->has_serial;
      re->serial = e->serial;
      k++;
    }
    if (k == 0) break;
    const int64_t t0 = rt_mono_ns();
    db_recon_entry_n(RT.re, k, RT.res, RT.zid);
    *apply_ns += rt_mono_ns() - t0;
    (void)db_store_journal_wait(2);                       /* (0.7: the journal at twice its limit: the pass waits for a checkpoint here, with no lock held) */
    *entries += k;
    for (unsigned i = 0; i < k; i++) c.wanted |= db_recon_note(&c, RT.res[i], RT.ents[i].name, &unst);
    RT.man_n += k;
    if ((++groups & 15) == 0) burst_yield_check(&by);       /* (a pass of ten million entries: the pinned worker on this CPU gets its turns) */
  }
  if (c.failed) RT.ch_failed = true;
  c.failed = false;
  rt_publish(&c);
}

static void rt_end(const rt_item_t *it) {
  const kdb_manifest_end_t *me = &it->end;
  char why[KDB_REASON_LEN];
  kdb_rc_t rc = kdb_man_end(&RT.man, me, why, sizeof(why));
  if (rc != KDB_OK) {
    rt_fail(why, it->epoch);
    return;
  }
  if (RT.skip) {
    RT.skip = false;
    return;
  }
  if (me->n_entries != RT.man_n) syslog(LOG_WARNING, "[DB] the manifest pass says %llu entries and the Backend saw %u", (unsigned long long)me->n_entries, RT.man_n);
  db_recon_end_t out;
  if (RT.ch_failed) syslog(LOG_ERR, "[DB] view '%s': an entry of the pass could not be recorded; the cursor is not kept, the next start lists the zones again", RT.vname);
  db_recon_end(me->complete, me->n_skipped, me->cursor_valid && !RT.ch_failed, me->cursor, me->ident_len ? me->ident : NULL, me->ident_len, &out);
  db_recon_status_t st;
  db_recon_status(&st);
  dbrt_counts_t c;
  memset(&c, 0, sizeof(c));
  c.deleted = (uint32_t)out.deleted;
  c.tot_deleted = out.deleted;
  rt_publish(&c);
  syslog(LOG_INFO, "[DB] view '%s': the manifest pass is over after %llu ms: %llu zone(s) listed (%llu new, %llu changed, %llu renamed, %llu already asked for, %llu unchanged, %llu refused with this "
                   "version), %llu not offered by the loader, %llu of the %llu zone(s) the Backend held for the view were not listed and %s",
         st.view, (unsigned long long)out.duration_ms, (unsigned long long)st.entries, (unsigned long long)st.created, (unsigned long long)st.changed, (unsigned long long)st.renamed,
         (unsigned long long)st.pending, (unsigned long long)st.same, (unsigned long long)st.kept, (unsigned long long)st.skipped, (unsigned long long)out.unlisted,
         (unsigned long long)out.total, out.held ? "NOT deleted (the mass-delete guard)" : out.failed ? "NOT all deleted (an entry of the pass could not be recorded, or a delete failed: see above)" : out.swept ? "deleted" : me->complete ? "none was" : "no sweep was made (the pass was not complete)");
  RT.ch_failed = false;
}

/* the stream that these items came from is gone: a pass that was open is forgotten (nothing is swept), the counts are not the next stream's */
static void rt_reset(void) {
  db_recon_abort();
  RT.skip = false;
  RT.ch_failed = false;
  RT.failed = false;
  RT.man_n = 0;
  dbrt_counts_t junk;
  db_recon_take(&junk);
  (void)db_recon_wanted_take();
}

static void rt_status(db_recon_status_t *o) {
  o->recon_thread = true;
  o->rt_busy_pct = atomic_load_explicit(&RT.st_busy_pct, memory_order_relaxed);
  o->rt_entries_per_s = atomic_load_explicit(&RT.st_eps, memory_order_relaxed);
  o->rt_queued = atomic_load_explicit(&RT.tail, memory_order_relaxed) - atomic_load_explicit(&RT.head, memory_order_relaxed);
  o->rt_apply_ns_per_entry = atomic_load_explicit(&RT.st_apply_ns, memory_order_relaxed);
  o->rt_entries = atomic_load_explicit(&RT.st_entries, memory_order_relaxed);
  o->rt_pages = atomic_load_explicit(&RT.st_pages, memory_order_relaxed);
  o->rt_full_stops = atomic_load_explicit(&RT.st_full, memory_order_relaxed);
  const uint64_t a = atomic_load_explicit(&RT.loop_cur_us, memory_order_relaxed), b = atomic_load_explicit(&RT.loop_prev_us, memory_order_relaxed);
  o->rt_loop_max_us = a > b ? a : b;
  const uint64_t c = atomic_load_explicit(&RT.stream_cur_us, memory_order_relaxed), d = atomic_load_explicit(&RT.stream_prev_us, memory_order_relaxed);
  o->rt_stream_max_us = c > d ? c : d;
}

static void *rt_main(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  uint64_t my_epoch = atomic_load_explicit(&RT.epoch, memory_order_acquire);
  int64_t win_start = rt_mono_ns(), busy_ns = 0, win_apply_ns = 0;
  uint64_t win_entries = 0;
  for (;;) {
    {                                                       /* the window of a second: the share of it the thread was busy, the entries a second, the time of an entry (closed here, in a pass of ten million entries too) */
      const int64_t now = rt_mono_ns();
      if (now - win_start >= 1000000000ll) {
        atomic_store_explicit(&RT.st_busy_pct, (uint64_t)(busy_ns * 100 / (now - win_start)), memory_order_relaxed);
        atomic_store_explicit(&RT.st_eps, (uint64_t)((double)win_entries * 1e9 / (double)(now - win_start)), memory_order_relaxed);
        if (win_entries) atomic_store_explicit(&RT.st_apply_ns, (uint64_t)(win_apply_ns / (int64_t)win_entries), memory_order_relaxed);
        win_start = now;
        busy_ns = win_apply_ns = 0;
        win_entries = 0;
      }
    }
    const uint64_t head = atomic_load_explicit(&RT.head, memory_order_relaxed);
    const uint64_t tail = atomic_load_explicit(&RT.tail, memory_order_acquire);
    uint64_t ep = atomic_load_explicit(&RT.epoch, memory_order_acquire);
    if (ep != my_epoch) {                                   /* a stream ended: the pass it had open, what it had in the ring */
      my_epoch = ep;
      rt_reset();
      atomic_store_explicit(&RT.seen_epoch, ep, memory_order_release);
      rt_notify();
    }
    if (head != tail) {
      rt_item_t *it = &RT.slot[head % DBRT_SLOTS];
      if (it->epoch != my_epoch) {                          /* (the epoch is counted before the items of the new stream are posted: an item that is not this one is older) */
        ep = atomic_load_explicit(&RT.epoch, memory_order_acquire);
        if (ep != my_epoch) continue;                       /* (the abort is made first) */
      }
      if (it->epoch == my_epoch && !RT.failed) {
        const int64_t t0 = rt_mono_ns();
        int64_t apply_ns = 0;
        uint64_t entries = 0;
        switch (it->kind) {
        case RTI_BEGIN:
          rt_begin(it);
          break;
        case RTI_PAGE:
          rt_page(it, &apply_ns, &entries);
          atomic_fetch_add_explicit(&RT.st_pages, 1, memory_order_relaxed);
          break;
        case RTI_END:
          rt_end(it);
          break;
        default:
          break;
        }
        busy_ns += rt_mono_ns() - t0;
        win_apply_ns += apply_ns;
        win_entries += entries;
        atomic_fetch_add_explicit(&RT.st_entries, entries, memory_order_relaxed);
      }
      atomic_store_explicit(&RT.head, head + 1, memory_order_release);
      rt_notify();                                          /* (a slot is free, the counts are there, the pass may be over) */
      continue;
    }
    struct timespec ts = { 1, 0 };
    struct kevent ev;
    if (kevent(RT.kq, NULL, 0, &ev, 1, &ts) < 0 && errno != EINTR) {
      struct timespec nap = { 0, 5000000L };                /* (the wait is broken: look at the ring every few ms instead) */
      nanosleep(&nap, NULL);
    }
  }
  return NULL;
}

bool db_recon_thread_start(int notify_kq, uintptr_t notify_ident) {
  if (RT.started) return true;
  for (unsigned i = 0; i < DBRT_SLOTS; i++) {
    RT.slot[i].body = malloc(KDB_MAX_BODY);
    if (!RT.slot[i].body) {
      syslog(LOG_ERR, "[DB] cannot start the reconcile thread: out of memory");
      return false;
    }
  }
  RT.kq = kqueue();
  struct kevent ev;
  EV_SET(&ev, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (RT.kq < 0 || kevent(RT.kq, &ev, 1, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot start the reconcile thread: kqueue: %s", strerror(errno));
    return false;
  }
  RT.notify_kq = notify_kq;
  RT.notify_ident = notify_ident;
  atomic_store_explicit(&RT.epoch, 0, memory_order_relaxed);
  pthread_t t;
  if (pthread_create(&t, NULL, rt_main, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot create the reconcile thread");
    return false;
  }
  pthread_detach(t);
  RT.started = true;
  db_recon_set_status_fn(rt_status);
  return true;
}

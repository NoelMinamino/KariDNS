/*
 * dns_park.c - parked queries and fetch requests (see dns_park.h).
 *
 * Everything on the query path is a bounded loop over preallocated memory: no malloc, no lock.  park_init() (worker start) is the only
 * allocation.  The tables are owned by one worker thread; the rings have one producer and one consumer, with release / acquire on
 * the indexes.
 */
#include "dns_park.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "dns_db_stream.h"

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

/* names are canonical (lower case, absolute) for the zone; a view name is compared as it is spelled in the configuration */
static bool key_fits(const char *view, const char *zone, size_t *vl, size_t *zl) {
  *vl = view ? strlen(view) : 0;
  *zl = zone ? strlen(zone) : 0;
  return *vl > 0 && *vl <= PARK_VIEW_MAX && *zl > 0 && *zl <= PARK_ZONE_MAX;
}

/* totals of all workers for park_stats_get(): bumped on the failure paths only (a full table, a deadline) */
static _Atomic uint64_t g_park_full, g_park_timeout;

/* ------------------------------------------------------------------ the table */
bool park_init(park_table_t *t, uint32_t cap) {
  memset(t, 0, sizeof(*t));
  if (cap == 0 || cap > (1u << 20)) return false;
  t->e = calloc(cap, sizeof(*t->e));                     /* zero pages are not memory until an entry is used */
  t->free_idx = malloc((size_t)cap * sizeof(*t->free_idx));
  if (!t->e || !t->free_idx) {
    free(t->e);
    free(t->free_idx);
    memset(t, 0, sizeof(*t));
    return false;
  }
  t->cap = cap;
  for (uint32_t i = 0; i < cap; i++) t->free_idx[i] = cap - 1 - i;      /* entry 0 is taken first */
  t->nfree = cap;
  t->min_deadline_ms = INT64_MAX;
  t->next_gen = 1;
  return true;
}

void park_free(park_table_t *t) {
  free(t->e);
  free(t->free_idx);
  memset(t, 0, sizeof(*t));
}

static park_entry_t *park_take(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, park_kind_t kind,
                               int32_t *idx_out) {
  size_t vl, zl;
  if (!t->e || !key_fits(view, zone, &vl, &zl)) return NULL;
  if (t->nfree == 0) {
    t->n_full++;
    atomic_fetch_add_explicit(&g_park_full, 1, memory_order_relaxed);
    return NULL;
  }
  uint32_t idx = t->free_idx[--t->nfree];
  park_entry_t *e = &t->e[idx];
  uint32_t gen = t->next_gen++;
  if (t->next_gen == 0) t->next_gen = 1;                 /* 0 is never a generation */
  memset(e, 0, offsetof(park_entry_t, u));               /* (the union is written by the caller) */
  e->state = PARK_WAIT;
  e->kind = (uint8_t)kind;
  e->zlen = (uint8_t)zl;
  e->vlen = (uint8_t)vl;
  e->gen = gen;
  e->deadline_ms = now_ms + (int64_t)timeout_ms;
  memcpy(e->view, view, vl + 1);
  memcpy(e->zone, zone, zl + 1);
  if (e->deadline_ms < t->min_deadline_ms) t->min_deadline_ms = e->deadline_ms;
  t->nwait++;
  t->n_parked++;
  *idx_out = (int32_t)idx;
  return e;
}

int32_t park_udp(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, int fd, const udp_ipc_t *ipc,
                 const uint8_t *payload, size_t len) {
  if (len > PARK_UDP_MAX) {
    t->n_toobig++;
    return -1;
  }
  int32_t idx;
  park_entry_t *e = park_take(t, now_ms, timeout_ms, view, zone, PARK_UDP, &idx);
  if (!e) return -1;
  e->udp_len = (uint16_t)len;
  e->u.udp.fd = fd;
  e->u.udp.ipc = *ipc;
  memcpy(e->u.udp.payload, payload, len);
  return idx;
}

int32_t park_tcp(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, int fd, uint32_t ctx_idx,
                 uint32_t ctx_gen) {
  int32_t idx;
  park_entry_t *e = park_take(t, now_ms, timeout_ms, view, zone, PARK_TCP, &idx);
  if (!e) return -1;
  e->u.tcp.fd = fd;
  e->u.tcp.ctx_idx = ctx_idx;
  e->u.tcp.ctx_gen = ctx_gen;
  return idx;
}

static bool entry_is(const park_entry_t *e, const char *view, size_t vl, const char *zone, size_t zl) {
  return e->vlen == vl && e->zlen == zl && memcmp(e->zone, zone, zl) == 0 && memcmp(e->view, view, vl) == 0;
}

bool park_has_wait(const park_table_t *t, const char *view, const char *zone) {
  size_t vl, zl;
  if (!t->e || t->nwait == 0 || !key_fits(view, zone, &vl, &zl)) return false;
  uint32_t seen = 0;
  for (uint32_t i = 0; i < t->cap && seen < t->nwait; i++) {
    const park_entry_t *e = &t->e[i];
    if (e->state != PARK_WAIT) continue;
    seen++;
    if (entry_is(e, view, vl, zone, zl)) return true;
  }
  return false;
}

park_entry_t *park_get(park_table_t *t, int32_t idx, uint32_t gen) {
  if (!t->e || idx < 0 || (uint32_t)idx >= t->cap) return NULL;
  park_entry_t *e = &t->e[idx];
  return e->state != PARK_FREE && e->gen == gen ? e : NULL;
}

uint32_t park_wake(park_table_t *t, const char *view, const char *zone) {
  size_t vl, zl;
  if (!t->e || t->nwait == 0 || !key_fits(view, zone, &vl, &zl)) return 0;
  uint32_t n = 0, seen = 0, waiting = t->nwait;         /* stop when every waiting entry was looked at */
  for (uint32_t i = 0; i < t->cap && seen < waiting; i++) {
    park_entry_t *e = &t->e[i];
    if (e->state != PARK_WAIT) continue;
    seen++;
    if (entry_is(e, view, vl, zone, zl)) {
      e->state = PARK_READY;
      t->nwait--;
      t->nready++;
      t->n_woken++;
      n++;
    }
  }
  return n;
}

uint32_t park_fail(park_table_t *t, const char *view, const char *zone) {
  size_t vl, zl;
  if (!t->e || t->nwait == 0 || !key_fits(view, zone, &vl, &zl)) return 0;
  uint32_t n = 0, seen = 0, waiting = t->nwait;
  for (uint32_t i = 0; i < t->cap && seen < waiting; i++) {
    park_entry_t *e = &t->e[i];
    if (e->state != PARK_WAIT) continue;
    seen++;
    if (entry_is(e, view, vl, zone, zl)) {
      e->state = PARK_TIMEOUT;
      t->nwait--;
      t->nready++;
      t->n_failed++;
      n++;
    }
  }
  return n;
}

uint32_t park_wake_all(park_table_t *t) {
  if (!t->e || t->nwait == 0) return 0;
  uint32_t n = 0;
  for (uint32_t i = 0; i < t->cap && t->nwait > 0; i++) {
    park_entry_t *e = &t->e[i];
    if (e->state != PARK_WAIT) continue;
    e->state = PARK_READY;
    t->nwait--;
    t->nready++;
    t->n_woken++;
    n++;
  }
  return n;
}

uint32_t park_expire(park_table_t *t, int64_t now_ms) {
  if (!t->e || t->nwait == 0 || now_ms < t->min_deadline_ms) return 0;
  uint32_t n = 0, waiting = 0;
  int64_t min = INT64_MAX;
  for (uint32_t i = 0; i < t->cap && waiting + n < t->nwait; i++) {
    park_entry_t *e = &t->e[i];
    if (e->state != PARK_WAIT) continue;
    if (e->deadline_ms <= now_ms) {
      e->state = PARK_TIMEOUT;
      n++;
    } else {
      waiting++;
      if (e->deadline_ms < min) min = e->deadline_ms;
    }
  }
  t->nwait -= n;
  t->nready += n;                                       /* (a TIMEOUT entry is "done" too: the worker answers it) */
  t->n_timeout += n;
  if (n) atomic_fetch_add_explicit(&g_park_timeout, n, memory_order_relaxed);
  t->min_deadline_ms = min;
  return n;
}

park_entry_t *park_next_done(park_table_t *t, uint32_t *cursor) {
  if (!t->e || t->nready == 0) return NULL;
  for (uint32_t i = *cursor; i < t->cap; i++) {
    park_entry_t *e = &t->e[i];
    if (e->state == PARK_READY || e->state == PARK_TIMEOUT) {
      *cursor = i + 1;
      return e;
    }
  }
  *cursor = t->cap;
  return NULL;
}

void park_release(park_table_t *t, park_entry_t *e) {
  if (!t->e || e < t->e || e >= t->e + t->cap || e->state == PARK_FREE) return;
  if (e->state == PARK_WAIT) {
    t->nwait--;
    if (t->nwait == 0) t->min_deadline_ms = INT64_MAX;
  } else {
    t->nready--;
  }
  e->state = PARK_FREE;
  t->free_idx[t->nfree++] = (uint32_t)(e - t->e);
}

bool park_cancel_tcp(park_table_t *t, uint32_t ctx_idx, uint32_t ctx_gen) {
  if (!t->e || t->nwait + t->nready == 0) return false;
  for (uint32_t i = 0; i < t->cap; i++) {
    park_entry_t *e = &t->e[i];
    if (e->state != PARK_FREE && e->kind == PARK_TCP && e->u.tcp.ctx_idx == ctx_idx && e->u.tcp.ctx_gen == ctx_gen) {
      park_release(t, e);
      t->n_cancelled++;
      return true;
    }
  }
  return false;
}

int64_t park_next_deadline_ms(const park_table_t *t, int64_t now_ms) {
  if (!t->e || t->nwait == 0) return -1;
  int64_t d = t->min_deadline_ms - now_ms;
  return d < 0 ? 0 : d;
}

/* ------------------------------------------------------------------ rings */
static bool key_set(park_key_t *k, const char *view, const char *zone, bool failed) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return false;
  k->failed = failed;
  k->vlen = (uint8_t)vl;
  k->zlen = (uint8_t)zl;
  memcpy(k->view, view, vl + 1);
  memcpy(k->zone, zone, zl + 1);
  return true;
}

bool park_wake_push(park_wake_ring_t *r, const char *view, const char *zone, bool failed) {
  uint32_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
  if (head - tail >= PARK_WAKE_RING || !key_set(&r->k[head % PARK_WAKE_RING], view, zone, failed)) {
    atomic_store_explicit(&r->overflow, true, memory_order_release);
    atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
    return false;
  }
  atomic_store_explicit(&r->head, head + 1, memory_order_release);
  return true;
}

bool park_wake_pop(park_wake_ring_t *r, park_key_t *out) {
  uint32_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
  uint32_t head = atomic_load_explicit(&r->head, memory_order_acquire);
  if (tail == head) return false;
  *out = r->k[tail % PARK_WAKE_RING];
  atomic_store_explicit(&r->tail, tail + 1, memory_order_release);
  return true;
}

bool park_wake_pending(const park_wake_ring_t *r) {
  return atomic_load_explicit(&r->head, memory_order_acquire) != atomic_load_explicit(&r->tail, memory_order_relaxed) ||
         atomic_load_explicit(&r->overflow, memory_order_relaxed);
}

bool park_wake_take_overflow(park_wake_ring_t *r) {
  return atomic_exchange_explicit(&r->overflow, false, memory_order_acq_rel);
}

bool park_fetch_push(park_fetch_ring_t *r, const char *view, const char *zone, uint8_t prio, uint8_t mode) {
  size_t vl, zl;
  uint32_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
  if (!key_fits(view, zone, &vl, &zl) || head - tail >= PARK_FETCH_RING) {
    atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
    return false;
  }
  park_fetch_req_t *q = &r->q[head % PARK_FETCH_RING];
  q->prio = prio;
  q->mode = mode;
  q->vlen = (uint8_t)vl;
  q->zlen = (uint8_t)zl;
  memcpy(q->view, view, vl + 1);
  memcpy(q->zone, zone, zl + 1);
  atomic_store_explicit(&r->head, head + 1, memory_order_release);
  return true;
}

bool park_fetch_pop(park_fetch_ring_t *r, park_fetch_req_t *out) {
  uint32_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
  uint32_t head = atomic_load_explicit(&r->head, memory_order_acquire);
  if (tail == head) return false;
  *out = r->q[tail % PARK_FETCH_RING];
  atomic_store_explicit(&r->tail, tail + 1, memory_order_release);
  return true;
}

/* ------------------------------------------------------------------ the workers' rings */
static park_wake_ring_t g_wake[PARK_MAX_WORKERS];
static park_fetch_ring_t g_fetch[PARK_MAX_WORKERS];
static _Atomic int g_wkq[PARK_MAX_WORKERS];              /* the worker's kqueue, -1 = no notification */
static _Atomic bool g_wreg[PARK_MAX_WORKERS];
static _Atomic int g_ingest_kq = -1;
static _Atomic uint32_t g_fetch_rr;
static _Atomic int g_wmax;                               /* the highest worker whose ring was used, plus one: the ingest thread looks at these rings only (park_fetch_pending) */
static _Atomic bool g_ingest_asleep;                     /* the ingest thread is about to wait for events, or waits (see "the sleep protocol") */
static _Atomic uint64_t g_wtrig[(PARK_MAX_WORKERS + 63) / 64];   /* the workers that were given a key and are not triggered yet (park_wake_flush) */
/* The requests of threads that are not workers (the transfer threads): a few slots that any number of threads may fill.  A slot is free (0), being
 * filled by the thread that took it with a compare-and-swap (1) or ready for the ingest thread (2); the ingest thread empties ready slots.  No lock. */
#define PARK_XFR_SLOTS 16
static park_fetch_req_t g_xfr_q[PARK_XFR_SLOTS];
static _Atomic uint8_t g_xfr_st[PARK_XFR_SLOTS];

static void wmax_raise(int w) {
  int cur = atomic_load_explicit(&g_wmax, memory_order_relaxed);
  while (cur < w + 1 && !atomic_compare_exchange_weak_explicit(&g_wmax, &cur, w + 1, memory_order_relaxed, memory_order_relaxed)) {}
}

void park_register_worker(int w, int kq) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return;
  wmax_raise(w);
  atomic_store_explicit(&g_wkq[w], kq, memory_order_relaxed);
  atomic_store_explicit(&g_wreg[w], true, memory_order_release);
}

void park_unregister_worker(int w) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return;
  atomic_store_explicit(&g_wreg[w], false, memory_order_release);
}

park_wake_ring_t *park_wake_ring(int w) { return (w >= 0 && w < PARK_MAX_WORKERS) ? &g_wake[w] : NULL; }
park_fetch_ring_t *park_fetch_ring(int w) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return NULL;
  wmax_raise(w);                                         /* (whoever gets the ring may push into it: the ingest thread has to look there) */
  return &g_fetch[w];
}

#ifdef __FreeBSD__
static void trigger(int kq, unsigned ident) {
  if (kq < 0) return;
  struct kevent t;
  EV_SET(&t, ident, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &t, 1, NULL, 0, NULL);
}
#else
static void trigger(int kq, unsigned ident) { (void)kq; (void)ident; }
#endif

/* The key goes into the ring now; the kqueue of the worker is triggered by park_wake_flush(), once however many keys came (the ring is what the worker reads: a
 * key is there before its trigger is). */
void park_wake_queue_one(int w, const char *view, const char *zone, bool failed) {
  if (w < 0 || w >= PARK_MAX_WORKERS || !atomic_load_explicit(&g_wreg[w], memory_order_acquire)) return;
  (void)park_wake_push(&g_wake[w], view, zone, failed);          /* (a full ring: the overflow flag wakes everything) */
  atomic_fetch_or_explicit(&g_wtrig[w / 64], 1ull << (w % 64), memory_order_release);
}

void park_wake_queue_all(const char *view, const char *zone, bool failed) {
  for (int w = 0; w < PARK_MAX_WORKERS; w++) park_wake_queue_one(w, view, zone, failed);
}

void park_wake_flush(void) {
  for (int i = 0; i < (int)(sizeof(g_wtrig) / sizeof(g_wtrig[0])); i++) {
    uint64_t m = atomic_exchange_explicit(&g_wtrig[i], 0, memory_order_acq_rel);
    while (m) {
      int w = i * 64 + __builtin_ctzll(m);
      m &= m - 1;
      trigger(atomic_load_explicit(&g_wkq[w], memory_order_relaxed), PARK_WAKE_IDENT);
    }
  }
}

void park_wake_broadcast(const char *view, const char *zone, bool failed) {
  park_wake_queue_all(view, zone, failed);
  park_wake_flush();
}

/* ------------------------------------------------------------------ places and tokens (B2 W5, 0.7 P-B; the idea is in dns_park.h) */
static _Atomic int32_t g_places;
static _Atomic int32_t g_places_lim = INT32_MAX;         /* until the ingest thread sets fetch-concurrency */

void park_places_set_limit(uint32_t limit) { atomic_store_explicit(&g_places_lim, limit > (uint32_t)INT32_MAX ? INT32_MAX : (int32_t)limit, memory_order_relaxed); }

uint32_t park_places_used(void) {
  int32_t v = atomic_load_explicit(&g_places, memory_order_relaxed);
  return v < 0 ? 0 : (uint32_t)v;
}

bool park_place_avail(void) { return atomic_load_explicit(&g_places, memory_order_relaxed) < atomic_load_explicit(&g_places_lim, memory_order_relaxed); }

/* a compare-and-swap loop, not an add that is undone: the count never goes above the limit, not even for a moment (a taker that sees it full leaves at once) */
bool park_place_take(void) {
  int32_t lim = atomic_load_explicit(&g_places_lim, memory_order_relaxed);
  int32_t c = atomic_load_explicit(&g_places, memory_order_relaxed);
  while (c < lim) {
    if (atomic_compare_exchange_weak_explicit(&g_places, &c, c + 1, memory_order_acq_rel, memory_order_relaxed)) return true;
  }
  return false;
}

void park_place_give(void) {
  int32_t c = atomic_load_explicit(&g_places, memory_order_relaxed);
  while (c > 0) {                                        /* (a place given back twice must not make room for one more fetch) */
    if (atomic_compare_exchange_weak_explicit(&g_places, &c, c - 1, memory_order_acq_rel, memory_order_relaxed)) return;
  }
}

/* The fetch-rate bucket: one 64-bit word, the tokens in thousandths in the low half and the time (ms, the low 32 bits of CLOCK_MONOTONIC) of the last change in the
 * high half.  The fill is computed from the time that has passed when a thread reads the word (rate thousandths a millisecond, at most one second of the rate);
 * a take writes the word with a compare-and-swap, a take that finds too few tokens writes nothing (a flood against an empty bucket is reads only).  0 is a bucket
 * that was never used: full.  With no rate (0, fetch-rate unlimited) the word is never touched: a take is one relaxed load. */
#define PARK_RATE_MAX 4000000u                           /* (rate x 1000 must fit 32 bits) */
#define PARK_RATE_BEHIND_MS 0x100000u                    /* (about 17 minutes) how far behind the stamp a caller's clock may be and still count as "no time has passed" */
static _Atomic uint32_t g_rate;
static _Atomic uint64_t g_rate_st;

void park_rate_set(uint32_t per_s) { atomic_store_explicit(&g_rate, per_s > PARK_RATE_MAX ? PARK_RATE_MAX : per_s, memory_order_relaxed); }
void park_rate_reset(void) { atomic_store_explicit(&g_rate_st, 0, memory_order_relaxed); }

static uint32_t rate_level(uint64_t st, uint32_t rate, int64_t now_ms, uint32_t *stamp) {
  uint32_t cap = rate * 1000u, now32 = (uint32_t)now_ms;
  if (now32 == 0) now32 = 1;
  if (st == 0) {
    *stamp = now32;
    return cap;
  }
  uint32_t tok = (uint32_t)st, old = (uint32_t)(st >> 32), d = now32 - old;
  /* A caller whose clock reading is behind the stamp (another thread read the clock later and wrote it; a thread that was preempted between its clock read and here)
   * has had nothing pass: d = 0, and the stamp stays where it is.  Behind by anything up to PARK_RATE_BEHIND_MS counts (it was 256 ms: a thread that lost the CPU for more
   * than that made d wrap to ~2^32, the bucket refilled to full and the stamp moved back).  Further behind is a stamp that is old (a bucket idle for weeks, the 32 bits
   * of the clock having wrapped since): that is forward, a full bucket. */
  if ((uint32_t)(old - now32) < PARK_RATE_BEHIND_MS) d = 0;
  *stamp = d ? now32 : old;
  uint64_t t = (uint64_t)tok + (uint64_t)d * rate;
  return t > cap ? cap : (uint32_t)t;
}

static uint32_t rate_need(uint32_t rate, bool half) { return half && rate * 500u > 1000u ? rate * 500u : 1000u; }

bool park_rate_take(int64_t now_ms, bool half) {
  uint32_t rate = atomic_load_explicit(&g_rate, memory_order_relaxed);
  if (!rate) return true;
  uint32_t need = rate_need(rate, half);
  uint64_t st = atomic_load_explicit(&g_rate_st, memory_order_relaxed);
  for (;;) {
    uint32_t stamp, lvl = rate_level(st, rate, now_ms, &stamp);
    if (lvl < need) return false;
    uint64_t ns = ((uint64_t)stamp << 32) | (lvl - 1000u);
    if (atomic_compare_exchange_weak_explicit(&g_rate_st, &st, ns, memory_order_acq_rel, memory_order_relaxed)) return true;
  }
}

bool park_rate_check(int64_t now_ms, bool half) {
  uint32_t rate = atomic_load_explicit(&g_rate, memory_order_relaxed);
  if (!rate) return true;
  uint32_t stamp;
  return rate_level(atomic_load_explicit(&g_rate_st, memory_order_relaxed), rate, now_ms, &stamp) >= rate_need(rate, half);
}

uint32_t park_rate_level(int64_t now_ms) {
  uint32_t rate = atomic_load_explicit(&g_rate, memory_order_relaxed), stamp;
  return rate ? rate_level(atomic_load_explicit(&g_rate_st, memory_order_relaxed), rate, now_ms, &stamp) : 0;
}

void park_rate_give(void) {
  uint32_t rate = atomic_load_explicit(&g_rate, memory_order_relaxed);
  uint64_t st = atomic_load_explicit(&g_rate_st, memory_order_relaxed);
  if (!rate) return;
  for (;;) {
    if (st == 0) return;                                 /* never used: full */
    uint64_t cap = (uint64_t)rate * 1000u, t = (uint64_t)(uint32_t)st + 1000u;
    if (t > cap) t = cap;
    if (t <= (uint32_t)st) return;
    uint64_t ns = (st & 0xFFFFFFFF00000000ull) | t;
    if (atomic_compare_exchange_weak_explicit(&g_rate_st, &st, ns, memory_order_acq_rel, memory_order_relaxed)) return;
  }
}

/* ---- the claims: one request for a zone that is out of memory, the others wait for its answer (B2 M1, 0.7 P-B) ----
 * The zone is not LOADING until the ingest thread has popped a request (and, with the wait queue, until it has a place and a token for it), so every worker that looks at the
 * zone meanwhile sees it ABSENT.  The mark says "a request with a claim for this zone is on its way or waits in the ingest thread's queue": the first worker sets it, the others
 * park and ask without a claim (the ingest thread drops the request while the mark is up, and the one fetch wakes them all, or fails them all), and the ingest thread clears
 * the mark when the request became a fetch, was dropped (park-timeout) or refused (the queue was full, the view is gone, the zone is in memory or not there), or the worker
 * that set it when the request could not be made.  Every mark was set with a claim that is on its way to exactly one of those, so none stays.
 * The marks are a table of hashes of (view, zone), a few slots apart from where the hash points.  A request that waits in the queue keeps its mark, so there can be as many
 * marks as the queue is long (ING_WQ_MAX, 8192) plus the fetches in flight: 32768 slots keep the table at most a third full.  A collision between two zones, or a window
 * with no free slot, costs the gate (a worker that is told the zone is claimed asks without a claim, which the ingest thread still handles as before), never an answer.  Two marks for one zone (two workers that raced, or a slot that was freed between their two looks) are both cleared by the one
 * clear: a duplicate claim that the ingest thread drops. */
#define PARK_CLAIM_SLOTS 32768u                          /* (a power of two; 256 KB) */
#define PARK_CLAIM_WIN 8u
static _Atomic uint64_t g_claim[PARK_CLAIM_SLOTS];       /* 0: free */

static uint64_t name_key(const char *view, const char *zone) {
  uint64_t h = 1469598103934665603ULL;
  for (const char *p = view; *p; p++) h = (h ^ (uint8_t)*p) * 1099511628211ULL;
  h = (h ^ 0xFF) * 1099511628211ULL;
  for (const char *p = zone; *p; p++) h = (h ^ (uint8_t)(*p | 0x20)) * 1099511628211ULL;
  return h | 1;                                          /* (never 0, the free slot) */
}

uint64_t park_claim_key(const char *view, const char *zone) { return name_key(view, zone); }

static size_t claim_slot(uint64_t key, unsigned j) { return (size_t)(((key >> 8) + j) & (PARK_CLAIM_SLOTS - 1u)); }

bool park_claim_held(uint64_t key) {
  for (unsigned j = 0; j < PARK_CLAIM_WIN; j++)
    if (atomic_load_explicit(&g_claim[claim_slot(key, j)], memory_order_acquire) == key) return true;
  return false;
}

bool park_claim_mark(uint64_t key) {
  for (unsigned j = 0; j < PARK_CLAIM_WIN; j++) {
    _Atomic uint64_t *s = &g_claim[claim_slot(key, j)];
    uint64_t v = atomic_load_explicit(s, memory_order_acquire);
    if (v == key) return false;
    if (v == 0 && atomic_compare_exchange_strong_explicit(s, &v, key, memory_order_acq_rel, memory_order_acquire)) return true;
    if (v == key) return false;                          /* (another worker took the slot between the load and the swap, for this very zone) */
  }
  return true;                                           /* no free slot in reach: the claim stands, without a mark */
}

void park_claim_clear(uint64_t key) {
  for (unsigned j = 0; j < PARK_CLAIM_WIN; j++) {
    _Atomic uint64_t *s = &g_claim[claim_slot(key, j)];
    uint64_t v = key;
    (void)atomic_compare_exchange_strong_explicit(s, &v, 0, memory_order_acq_rel, memory_order_relaxed);
  }
}

void park_claim_release(const char *view, const char *zone) { park_claim_clear(name_key(view, zone)); }

void park_stats_get(park_stats_t *out) {
  out->full = atomic_load_explicit(&g_park_full, memory_order_relaxed);
  out->timeout = atomic_load_explicit(&g_park_timeout, memory_order_relaxed);
  out->ring_dropped = 0;
  for (int w = 0; w < PARK_MAX_WORKERS; w++) {
    out->ring_dropped += atomic_load_explicit(&g_fetch[w].dropped, memory_order_relaxed);
  }
}

void park_fetch_set_notify(int kq) { atomic_store_explicit(&g_ingest_kq, kq, memory_order_relaxed); }

/* The sleep protocol.  The ingest thread waits for events in kevent() with a timeout; a worker that has pushed a request must wake it, but a trigger is a system
 * call (27% of the workers' time at 200k queries a second) and the thread is awake most of the time while there is work.  So a worker triggers only when the thread
 * may be asleep, which the thread says with g_ingest_asleep:
 *     worker:  push the request (the ring's head, release);  fence(seq_cst);  if (g_ingest_asleep) trigger.
 *     ingest:  g_ingest_asleep = true;  fence(seq_cst);  if (a request is pending) { g_ingest_asleep = false; do not wait }  else wait;  g_ingest_asleep = false.
 * With the two fences either the worker sees the flag (and triggers: the event is there when the thread waits, or wakes it) or the thread sees the request (and does
 * not wait): the case in which the worker sees no flag and the thread sees no request cannot happen, so no request is left in a ring while the thread sleeps.
 * A worker that sees the flag while the thread is already awake makes one trigger too many, which costs the thread one pass.  The thread looks for requests after
 * every wait, not only when the event is the trigger (the requests that came while it was awake had no trigger). */
static void trigger_ingest(void) {
  atomic_thread_fence(memory_order_seq_cst);
  if (atomic_load_explicit(&g_ingest_asleep, memory_order_relaxed)) trigger(atomic_load_explicit(&g_ingest_kq, memory_order_relaxed), PARK_FETCH_IDENT);
}

bool park_fetch_pending(void) {
  int wm = atomic_load_explicit(&g_wmax, memory_order_relaxed);
  for (int w = 0; w < wm; w++)
    if (atomic_load_explicit(&g_fetch[w].head, memory_order_acquire) != atomic_load_explicit(&g_fetch[w].tail, memory_order_relaxed)) return true;
  for (int k = 0; k < PARK_XFR_SLOTS; k++)
    if (atomic_load_explicit(&g_xfr_st[k], memory_order_acquire) == 2) return true;
  return false;
}

bool park_fetch_sleep_prepare(void) {
  atomic_store_explicit(&g_ingest_asleep, true, memory_order_relaxed);
  atomic_thread_fence(memory_order_seq_cst);
  if (!park_fetch_pending()) return false;
  atomic_store_explicit(&g_ingest_asleep, false, memory_order_relaxed);
  return true;
}

void park_fetch_sleep_done(void) { atomic_store_explicit(&g_ingest_asleep, false, memory_order_relaxed); }

bool park_fetch_request(int w, const char *view, const char *zone, uint8_t prio, uint8_t mode) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return false;
  wmax_raise(w);
  if (!park_fetch_push(&g_fetch[w], view, zone, prio, mode)) return false;
  trigger_ingest();
  return true;
}

/* (the slots are declared above, with the sleep protocol that looks at them) */
bool park_fetch_request_any(const char *view, const char *zone, uint8_t prio, uint8_t mode) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return false;
  for (int i = 0; i < PARK_XFR_SLOTS; i++) {
    uint8_t free_st = 0;
    if (!atomic_compare_exchange_strong_explicit(&g_xfr_st[i], &free_st, 1, memory_order_acquire, memory_order_relaxed)) continue;
    park_fetch_req_t *q = &g_xfr_q[i];
    q->prio = prio;
    q->mode = mode;
    q->vlen = (uint8_t)vl;
    q->zlen = (uint8_t)zl;
    memcpy(q->view, view, vl + 1);
    memcpy(q->zone, zone, zl + 1);
    atomic_store_explicit(&g_xfr_st[i], 2, memory_order_release);
    trigger_ingest();
    return true;
  }
  return false;
}

/* The requests the query path makes in the background (a CNAME or the glue of an NS host leads into a zone that is not in memory): one request for a zone in
 * PARK_BG_MS, remembered in a small table of hashes (a collision lets a request through; a request that could not be queued is not remembered), through the slots above.
 * The ingest thread still decides: no request while the fetch of the zone is on its way, none above the memory limit, the rate of fetches with the half of the
 * bucket kept for the queries (dns_db_ingest.c). */
#define PARK_BG_SLOTS 4096
#define PARK_BG_MS 5000
static _Atomic uint64_t g_bg_key[PARK_BG_SLOTS];
static _Atomic int64_t g_bg_at[PARK_BG_SLOTS];

void park_bg_fetch(const char *view, const char *zone) {
  uint64_t h = name_key(view, zone);
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t now = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  size_t i = (size_t)(h % PARK_BG_SLOTS);
  if (atomic_load_explicit(&g_bg_key[i], memory_order_relaxed) == h && now - atomic_load_explicit(&g_bg_at[i], memory_order_relaxed) < PARK_BG_MS) return;
  /* the slot is stamped after the request is queued: a request that found no free slot of the transfer threads is not remembered as made (the next query for the
   * zone makes it again), and a different zone that hashed to the same slot is asked for, not held back */
  if (!park_fetch_request_any(view, zone, KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_FULL)) return;
  atomic_store_explicit(&g_bg_at[i], now, memory_order_relaxed);
  atomic_store_explicit(&g_bg_key[i], h, memory_order_relaxed);
}

bool park_fetch_next(park_fetch_req_t *out) {
  /* the workers' rings and the slots of the transfer threads take turns: the slots are one more source in the round robin, so that workers whose rings are always
   * full do not starve a transfer (which would run into its time-out) */
  uint32_t start = atomic_fetch_add_explicit(&g_fetch_rr, 1, memory_order_relaxed);
  int wm = atomic_load_explicit(&g_wmax, memory_order_relaxed);          /* (only the rings that were ever used: 128 rings are 128 cache lines when the answer is "none") */
  for (int i = 0; i <= wm; i++) {
    int w = (int)((start + (uint32_t)i) % (uint32_t)(wm + 1));
    if (w == wm) {
      for (int k = 0; k < PARK_XFR_SLOTS; k++) {
        if (atomic_load_explicit(&g_xfr_st[k], memory_order_acquire) != 2) continue;
        *out = g_xfr_q[k];
        atomic_store_explicit(&g_xfr_st[k], 0, memory_order_release);
        out->claimed = false;
        out->worker = -1;
        return true;
      }
    } else if (park_fetch_pop(&g_fetch[w], out)) {
      out->claimed = (out->prio & PARK_PRIO_CLAIMED) != 0;
      out->prio &= (uint8_t)~PARK_PRIO_CLAIMED;
      out->worker = (int16_t)w;
      return true;
    }
  }
  return false;
}

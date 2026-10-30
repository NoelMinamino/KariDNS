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

void park_register_worker(int w, int kq) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return;
  atomic_store_explicit(&g_wkq[w], kq, memory_order_relaxed);
  atomic_store_explicit(&g_wreg[w], true, memory_order_release);
}

void park_unregister_worker(int w) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return;
  atomic_store_explicit(&g_wreg[w], false, memory_order_release);
}

park_wake_ring_t *park_wake_ring(int w) { return (w >= 0 && w < PARK_MAX_WORKERS) ? &g_wake[w] : NULL; }
park_fetch_ring_t *park_fetch_ring(int w) { return (w >= 0 && w < PARK_MAX_WORKERS) ? &g_fetch[w] : NULL; }

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

void park_wake_broadcast(const char *view, const char *zone, bool failed) {
  for (int w = 0; w < PARK_MAX_WORKERS; w++) {
    if (!atomic_load_explicit(&g_wreg[w], memory_order_acquire)) continue;
    (void)park_wake_push(&g_wake[w], view, zone, failed);        /* (a full ring: the overflow flag wakes everything) */
    trigger(atomic_load_explicit(&g_wkq[w], memory_order_relaxed), PARK_WAKE_IDENT);
  }
}

void park_fetch_set_notify(int kq) { atomic_store_explicit(&g_ingest_kq, kq, memory_order_relaxed); }

bool park_fetch_request(int w, const char *view, const char *zone, uint8_t prio, uint8_t mode) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return false;
  if (!park_fetch_push(&g_fetch[w], view, zone, prio, mode)) return false;
  trigger(atomic_load_explicit(&g_ingest_kq, memory_order_relaxed), PARK_FETCH_IDENT);
  return true;
}

bool park_fetch_next(park_fetch_req_t *out) {
  uint32_t start = atomic_fetch_add_explicit(&g_fetch_rr, 1, memory_order_relaxed);
  for (int i = 0; i < PARK_MAX_WORKERS; i++) {
    int w = (int)((start + (uint32_t)i) % PARK_MAX_WORKERS);
    if (park_fetch_pop(&g_fetch[w], out)) return true;
  }
  return false;
}

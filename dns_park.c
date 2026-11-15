/*
 * dns_park.c - parked queries and fetch requests (see dns_park.h).
 *
 * Everything on the query path is a bounded operation on preallocated memory: no malloc, no lock.  park_init() (worker start) is the only
 * allocation.  The tables are owned by one worker thread; the rings have one producer (or a few that take turns) and one consumer, with release / acquire on
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

static uint64_t name_key(const char *view, const char *zone) {
  uint64_t h = 1469598103934665603ULL;
  for (const char *p = view; *p; p++) h = (h ^ (uint8_t)*p) * 1099511628211ULL;
  h = (h ^ 0xFF) * 1099511628211ULL;
  for (const char *p = zone; *p; p++) h = (h ^ (uint8_t)(*p | 0x20)) * 1099511628211ULL;
  return h | 1;                                          /* (never 0, the free slot of the claims) */
}

uint64_t park_name_key(const char *view, const char *zone) { return name_key(view, zone); }

/* ------------------------------------------------------------------ the table */
/* The links of an entry are index + 1 (0: none), so that zeroed memory is an empty list.  An entry is in at most one list of each kind:
 *   the hash chain (bucket[key & bmask]) and the wheel slot: while it WAITs;
 *   the done list: while it is READY or TIMEOUT;
 *   the pending list: while it WAITs and its request has not been made. */
#define ENT(t, ref) (&(t)->e[(ref) - 1u])
#define REF(t, e) ((uint32_t)((e) - (t)->e) + 1u)

static size_t blk_need_max(void) { return (((size_t)PARK_ZONE_MAX + PARK_VIEW_MAX + 2 + 7) & ~(size_t)7) + sizeof(udp_ipc_t) + PARK_UDP_MAX; }

bool park_init(park_table_t *t, uint32_t cap) {
  memset(t, 0, sizeof(*t));
  if (cap == 0 || cap > (1u << 20)) return false;
  uint32_t nbig = cap / 8 < 16 ? (cap < 16 ? cap : 16) : cap / 8;
  uint32_t nb = 16;
  while (nb < cap * 2) nb <<= 1;
  t->e = calloc(cap, sizeof(*t->e));                     /* zero pages are not memory until an entry is used */
  t->free_idx = malloc((size_t)cap * sizeof(*t->free_idx));
  t->bucket = calloc(nb, sizeof(*t->bucket));
  t->wheel = calloc(PARK_WHEEL, sizeof(*t->wheel));
  t->wbits = calloc(PARK_WHEEL / 64, sizeof(*t->wbits));
  t->bsize[0] = PARK_BLK_SMALL;
  t->bsize[1] = (uint32_t)blk_need_max();
  t->blk[0] = calloc(cap, t->bsize[0]);
  t->blk[1] = calloc(nbig, t->bsize[1]);
  t->bfree[0] = malloc((size_t)cap * sizeof(uint32_t));
  t->bfree[1] = malloc((size_t)nbig * sizeof(uint32_t));
  if (!t->e || !t->free_idx || !t->bucket || !t->wheel || !t->wbits || !t->blk[0] || !t->blk[1] || !t->bfree[0] || !t->bfree[1]) {
    park_free(t);
    return false;
  }
  t->cap = cap;
  t->bmask = nb - 1;
  for (uint32_t i = 0; i < cap; i++) {                   /* entry 0 is taken first */
    t->free_idx[i] = cap - 1 - i;
    t->bfree[0][i] = cap - 1 - i;
  }
  for (uint32_t i = 0; i < nbig; i++) t->bfree[1][i] = nbig - 1 - i;
  t->nfree = cap;
  t->bnfree[0] = cap;
  t->bnfree[1] = nbig;
  t->next_gen = 1;
  return true;
}

void park_free(park_table_t *t) {
  free(t->e);
  free(t->free_idx);
  free(t->bucket);
  free(t->wheel);
  free(t->wbits);
  free(t->blk[0]);
  free(t->blk[1]);
  free(t->bfree[0]);
  free(t->bfree[1]);
  memset(t, 0, sizeof(*t));
}

static void hash_add(park_table_t *t, park_entry_t *e) {
  uint32_t *b = &t->bucket[e->key & t->bmask];
  e->hnext = *b;
  *b = REF(t, e);
}

static void hash_remove(park_table_t *t, park_entry_t *e) {
  uint32_t *p = &t->bucket[e->key & t->bmask];
  const uint32_t me = REF(t, e);
  while (*p && *p != me) p = &ENT(t, *p)->hnext;
  if (*p == me) *p = e->hnext;
  e->hnext = 0;
}

static void wheel_add(park_table_t *t, park_entry_t *e) {
  int64_t d = e->deadline_ms < t->wcur_ms ? t->wcur_ms : e->deadline_ms;       /* (a deadline that is past is looked at with the next tick) */
  uint32_t s = (uint32_t)((uint64_t)d & (PARK_WHEEL - 1));
  const uint32_t me = REF(t, e);
  e->wslot = (uint16_t)s;
  e->wprev = 0;
  e->wnext = t->wheel[s];
  if (e->wnext) ENT(t, e->wnext)->wprev = me;
  t->wheel[s] = me;
  t->wbits[s >> 6] |= 1ull << (s & 63);
}

static void wheel_remove(park_table_t *t, park_entry_t *e) {
  const uint32_t s = e->wslot;
  if (e->wprev) ENT(t, e->wprev)->wnext = e->wnext;
  else t->wheel[s] = e->wnext;
  if (e->wnext) ENT(t, e->wnext)->wprev = e->wprev;
  if (t->wheel[s] == 0) t->wbits[s >> 6] &= ~(1ull << (s & 63));
  e->wprev = e->wnext = 0;
}

static void done_add(park_table_t *t, park_entry_t *e) {
  const uint32_t me = REF(t, e);
  e->dnext = 0;
  e->dprev = t->dtail;
  if (t->dtail) ENT(t, t->dtail)->dnext = me;
  else t->dhead = me;
  t->dtail = me;
}

static void done_remove(park_table_t *t, park_entry_t *e) {
  if (e->dprev) ENT(t, e->dprev)->dnext = e->dnext;
  else t->dhead = e->dnext;
  if (e->dnext) ENT(t, e->dnext)->dprev = e->dprev;
  else t->dtail = e->dprev;
  e->dprev = e->dnext = 0;
}

static void unsent_add(park_table_t *t, park_entry_t *e) {
  const uint32_t me = REF(t, e);
  e->unext = 0;
  e->uprev = t->utail;
  if (t->utail) ENT(t, t->utail)->unext = me;
  else t->uhead = me;
  t->utail = me;
  e->ulinked = 1;
  t->nunsent++;
}

static void unsent_remove(park_table_t *t, park_entry_t *e) {
  if (!e->ulinked) return;
  if (e->uprev) ENT(t, e->uprev)->unext = e->unext;
  else t->uhead = e->unext;
  if (e->unext) ENT(t, e->unext)->uprev = e->uprev;
  else t->utail = e->uprev;
  e->uprev = e->unext = 0;
  e->ulinked = 0;
  t->nunsent--;
}

/* a WAIT entry leaves the indexes that only waiting entries are in (the hash, the wheel, the pending list); its state is the caller's */
static void wait_leave(park_table_t *t, park_entry_t *e) {
  hash_remove(t, e);
  wheel_remove(t, e);
  unsent_remove(t, e);
}

static void done_enter(park_table_t *t, park_entry_t *e, park_state_t st) {
  e->state = (uint8_t)st;
  t->nwait--;
  t->nready++;
  done_add(t, e);
}

static park_entry_t *park_take(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, park_kind_t kind, size_t req_len,
                               int32_t *idx_out) {
  size_t vl, zl;
  if (!t->e || !key_fits(view, zone, &vl, &zl)) return NULL;
  const size_t names = (zl + vl + 2 + 7) & ~(size_t)7;
  const size_t need = kind == PARK_UDP ? names + sizeof(udp_ipc_t) + req_len : zl + vl + 2;
  const int cls = need <= PARK_BLK_SMALL ? 0 : 1;
  if (t->nfree == 0 || t->bnfree[cls] == 0) {
    t->n_full++;
    atomic_fetch_add_explicit(&g_park_full, 1, memory_order_relaxed);
    return NULL;
  }
  uint32_t idx = t->free_idx[--t->nfree];
  uint32_t bi = t->bfree[cls][--t->bnfree[cls]];
  park_entry_t *e = &t->e[idx];
  uint32_t gen = t->next_gen++;
  if (t->next_gen == 0) t->next_gen = 1;                 /* 0 is never a generation */
  memset(e, 0, sizeof(*e));
  e->state = PARK_WAIT;
  e->kind = (uint8_t)kind;
  e->zlen = (uint8_t)zl;
  e->vlen = (uint8_t)vl;
  e->gen = gen;
  e->blk = ((uint32_t)cls << 31) | bi;
  e->deadline_ms = now_ms + (int64_t)timeout_ms;
  e->key = name_key(view, zone);
  e->pl = t->blk[cls] + (size_t)bi * t->bsize[cls];
  memcpy(e->pl, zone, zl + 1);
  memcpy(e->pl + zl + 1, view, vl + 1);
  if (t->nwait == 0) t->wcur_ms = now_ms;                /* (nothing is in the wheel: it starts at this tick) */
  hash_add(t, e);
  wheel_add(t, e);
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
  park_entry_t *e = park_take(t, now_ms, timeout_ms, view, zone, PARK_UDP, len, &idx);
  if (!e) return -1;
  e->udp_len = (uint16_t)len;
  e->fd = fd;
  uint8_t *ip = (uint8_t *)(uintptr_t)park_entry_ipc(e);
  memcpy(ip, ipc, sizeof(*ipc));
  memcpy(ip + sizeof(*ipc), payload, len);
  return idx;
}

int32_t park_tcp(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, int fd, uint32_t ctx_idx,
                 uint32_t ctx_gen) {
  int32_t idx;
  park_entry_t *e = park_take(t, now_ms, timeout_ms, view, zone, PARK_TCP, 0, &idx);
  if (!e) return -1;
  e->fd = fd;
  e->ctx_idx = ctx_idx;
  e->ctx_gen = ctx_gen;
  return idx;
}

bool park_has_wait(const park_table_t *t, const char *view, const char *zone) {
  size_t vl, zl;
  if (!t->e || t->nwait == 0 || !key_fits(view, zone, &vl, &zl)) return false;
  const uint64_t key = name_key(view, zone);
  for (uint32_t r = t->bucket[key & t->bmask]; r; r = ENT(t, r)->hnext)
    if (ENT(t, r)->key == key) return true;
  return false;
}

park_entry_t *park_get(park_table_t *t, int32_t idx, uint32_t gen) {
  if (!t->e || idx < 0 || (uint32_t)idx >= t->cap) return NULL;
  park_entry_t *e = &t->e[idx];
  return e->state != PARK_FREE && e->gen == gen ? e : NULL;
}

uint32_t park_wake_key(park_table_t *t, uint64_t key) {
  if (!t->e || t->nwait == 0) return 0;
  uint32_t n = 0;
  uint32_t *p = &t->bucket[key & t->bmask];
  while (*p) {
    park_entry_t *e = ENT(t, *p);
    if (e->key != key) {
      p = &e->hnext;
      continue;
    }
    *p = e->hnext;                                       /* (off the chain here: the others of the wait_leave() are not in the way) */
    e->hnext = 0;
    wheel_remove(t, e);
    unsent_remove(t, e);
    done_enter(t, e, PARK_READY);
    t->n_woken++;
    n++;
  }
  return n;
}

uint32_t park_wake(park_table_t *t, const char *view, const char *zone) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return 0;
  return park_wake_key(t, name_key(view, zone));
}

uint32_t park_fail_key(park_table_t *t, uint64_t key) {
  if (!t->e || t->nwait == 0) return 0;
  uint32_t n = 0;
  uint32_t *p = &t->bucket[key & t->bmask];
  while (*p) {
    park_entry_t *e = ENT(t, *p);
    if (e->key != key) {
      p = &e->hnext;
      continue;
    }
    *p = e->hnext;
    e->hnext = 0;
    wheel_remove(t, e);
    unsent_remove(t, e);
    done_enter(t, e, PARK_TIMEOUT);
    t->n_failed++;
    n++;
  }
  return n;
}

uint32_t park_fail(park_table_t *t, const char *view, const char *zone) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return 0;
  return park_fail_key(t, name_key(view, zone));
}

uint32_t park_retry_key(park_table_t *t, uint64_t key, int64_t new_deadline_ms) {
  if (!t->e || t->nwait == 0) return 0;
  uint32_t n = 0;
  for (uint32_t r = t->bucket[key & t->bmask]; r; r = ENT(t, r)->hnext) {
    park_entry_t *e = ENT(t, r);
    if (e->key != key) continue;
    if (new_deadline_ms > e->deadline_ms) {
      wheel_remove(t, e);
      e->deadline_ms = new_deadline_ms;
      wheel_add(t, e);
    }
    e->attach = 0;                                       /* (it waits for a fetch now: its time is not an attach's) */
    n++;
  }
  return n;
}

uint32_t park_retry(park_table_t *t, const char *view, const char *zone, int64_t new_deadline_ms) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return 0;
  return park_retry_key(t, name_key(view, zone), new_deadline_ms);
}

void park_mark_attach(park_table_t *t, int32_t idx, int64_t now_ns, int64_t full_deadline_ms) {
  if (!t->e || idx < 0 || (uint32_t)idx >= t->cap || t->e[idx].state != PARK_WAIT) return;
  t->e[idx].attach = 1;
  t->e[idx].t_park_ns = now_ns;
  t->e[idx].full_ms = full_deadline_ms;
}

uint32_t park_wake_all(park_table_t *t) {
  if (!t->e || t->nwait == 0) return 0;
  uint32_t n = 0;
  for (uint32_t b = 0; b <= t->bmask && t->nwait > 0; b++) {
    while (t->bucket[b]) {
      park_entry_t *e = ENT(t, t->bucket[b]);
      t->bucket[b] = e->hnext;
      e->hnext = 0;
      wheel_remove(t, e);
      unsent_remove(t, e);
      done_enter(t, e, PARK_READY);
      t->n_woken++;
      n++;
    }
  }
  return n;
}

static void wheel_slot_expire(park_table_t *t, uint32_t s, int64_t now_ms, uint32_t *n) {
  uint32_t r = t->wheel[s];
  while (r) {
    park_entry_t *e = ENT(t, r);
    const uint32_t next = e->wnext;
    if (e->deadline_ms <= now_ms) {
      if (e->attach && e->full_ms > now_ms) {
        /* the attach deadline passed with the request still queued (the store threads are behind slow reads): the query goes on waiting for the rest of its park-timeout, as
         * a query that waits for a fetch does; whoever finishes the zone wakes it, or the retry key of an attach that fails (park_retry()) */
        wheel_remove(t, e);
        e->deadline_ms = e->full_ms;
        wheel_add(t, e);
      } else {
        wait_leave(t, e);
        done_enter(t, e, PARK_TIMEOUT);
        (*n)++;
      }
    }
    r = next;
  }
}

uint32_t park_expire(park_table_t *t, int64_t now_ms) {
  if (!t->e) return 0;
  if (t->nwait == 0) {
    if (now_ms + 1 > t->wcur_ms) t->wcur_ms = now_ms + 1;
    return 0;
  }
  uint32_t n = 0;
  int64_t steps = now_ms - t->wcur_ms + 1;
  if (steps > PARK_WHEEL) steps = PARK_WHEEL;            /* (a longer gap: every slot once) */
  for (int64_t i = 0; i < steps; i++) wheel_slot_expire(t, (uint32_t)((uint64_t)(t->wcur_ms + i) & (PARK_WHEEL - 1)), now_ms, &n);
  if (now_ms + 1 > t->wcur_ms) t->wcur_ms = now_ms + 1;
  t->n_timeout += n;
  if (n) atomic_fetch_add_explicit(&g_park_timeout, n, memory_order_relaxed);
  return n;
}

park_entry_t *park_next_done(park_table_t *t) {
  if (!t->e || t->dhead == 0) return NULL;
  return ENT(t, t->dhead);
}

/* A pending request that is dropped with its entry (a cancelled connection, an answer sent) is taken over by another query of the same worker that waits for the zone: that one
 * is what the zone's other waiters rely on.  With no other, the marks that the request held are given up. */
static void pend_abandon(park_table_t *t, park_entry_t *e) {
  park_entry_t *other = NULL;
  for (uint32_t r = t->bucket[e->key & t->bmask]; r && !other; r = ENT(t, r)->hnext)
    if (ENT(t, r)->key == e->key && ENT(t, r) != e) other = ENT(t, r);
  if (other) {
    if (other->pend == PARK_PEND_NONE) park_pending_set(t, other, (park_pend_t)e->pend, e->preq, e->prio);
    return;
  }
  if (e->pend == PARK_PEND_FETCH && (e->prio & PARK_PRIO_CLAIMED)) park_claim_release(park_entry_view(e), park_entry_zone(e));
  else if (e->pend == PARK_PEND_ATTACH_ZID) (void)park_att_leave((uint16_t)(e->preq >> 32), (uint32_t)e->preq, (int)e->prio);       /* (prio: the worker that waits) */
}

void park_release(park_table_t *t, park_entry_t *e) {
  if (!t->e || e < t->e || e >= t->e + t->cap || e->state == PARK_FREE) return;
  if (e->pend) pend_abandon(t, e);
  if (e->state == PARK_WAIT) {
    wait_leave(t, e);
    t->nwait--;
  } else {
    done_remove(t, e);
    t->nready--;
  }
  const uint32_t cls = e->blk >> 31, bi = e->blk & 0x7FFFFFFFu;
  t->bfree[cls][t->bnfree[cls]++] = bi;
  e->state = PARK_FREE;
  e->pend = PARK_PEND_NONE;
  t->free_idx[t->nfree++] = (uint32_t)(e - t->e);
}

bool park_cancel_tcp(park_table_t *t, int32_t idx, uint32_t gen) {
  park_entry_t *e = park_get(t, idx, gen);
  if (!e || e->kind != PARK_TCP) return false;
  park_release(t, e);
  t->n_cancelled++;
  return true;
}

int64_t park_next_deadline_ms(const park_table_t *t, int64_t now_ms) {
  if (!t->e || t->nwait == 0) return -1;
  const uint32_t s0 = (uint32_t)((uint64_t)t->wcur_ms & (PARK_WHEEL - 1));
  const uint32_t nw = PARK_WHEEL / 64;
  for (uint32_t k = 0; k <= nw; k++) {                   /* from the slot of the current tick round the wheel to the first slot that holds an entry */
    const uint32_t wi = ((s0 >> 6) + k) % nw;
    uint64_t w = t->wbits[wi];
    if (k == 0) w &= ~0ull << (s0 & 63);
    else if (k == nw) w &= (s0 & 63) ? ~(~0ull << (s0 & 63)) : 0;
    if (!w) continue;
    const uint32_t s = wi * 64 + (uint32_t)__builtin_ctzll(w);
    const int64_t dist = (int64_t)((s - s0) & (PARK_WHEEL - 1));
    const int64_t d = t->wcur_ms + dist - now_ms;
    return d < 0 ? 0 : d;
  }
  return 0;
}

void park_pending_set(park_table_t *t, park_entry_t *e, park_pend_t kind, uint64_t preq, uint8_t prio) {
  if (!t->e || e->state != PARK_WAIT) return;
  e->pend = (uint8_t)kind;
  e->preq = preq;
  e->prio = prio;
  if (!e->ulinked) unsent_add(t, e);
}

park_entry_t *park_pending_head(park_table_t *t) {
  if (!t->e || t->uhead == 0) return NULL;
  return ENT(t, t->uhead);
}

void park_pending_done(park_table_t *t, park_entry_t *e) {
  unsent_remove(t, e);
  e->pend = PARK_PEND_NONE;
}

/* ------------------------------------------------------------------ rings */
static bool key_set(park_key_t *k, uint64_t key, bool failed, bool retry, bool fetch) {
  k->key = key;
  k->failed = failed;
  k->retry = retry;
  k->fetch = fetch;
  return true;
}

/* (0.7 store S2: the ingest thread and the store threads both produce keys, so the producers take turns: a spin lock held for the copy of one key) */
bool park_wake_push_key(park_wake_ring_t *r, uint64_t key, bool failed, bool retry, bool fetch) {
  while (atomic_exchange_explicit(&r->plock, true, memory_order_acquire)) {}
  uint32_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
  bool ok = true;
  if (head - tail >= PARK_WAKE_RING) {
    atomic_store_explicit(&r->overflow, true, memory_order_release);
    atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
    ok = false;
  } else {
    (void)key_set(&r->k[head % PARK_WAKE_RING], key, failed, retry, fetch);
    atomic_store_explicit(&r->head, head + 1, memory_order_release);
  }
  atomic_store_explicit(&r->plock, false, memory_order_release);
  return ok;
}

bool park_wake_push_ex(park_wake_ring_t *r, const char *view, const char *zone, bool failed, bool retry) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) {                 /* (no key to send: the consumer looks at everything) */
    atomic_store_explicit(&r->overflow, true, memory_order_release);
    atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
    return false;
  }
  return park_wake_push_key(r, name_key(view, zone), failed, retry, false);
}

bool park_wake_push(park_wake_ring_t *r, const char *view, const char *zone, bool failed) {
  return park_wake_push_ex(r, view, zone, failed, false);
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
static void wake_key_one(int w, uint64_t key, bool failed, bool retry, bool fetch) {
  if (w < 0 || w >= PARK_MAX_WORKERS || !atomic_load_explicit(&g_wreg[w], memory_order_acquire)) return;
  (void)park_wake_push_key(&g_wake[w], key, failed, retry, fetch);          /* (a full ring: the overflow flag wakes everything) */
  atomic_fetch_or_explicit(&g_wtrig[w / 64], 1ull << (w % 64), memory_order_release);
}

void park_wake_queue_one(int w, const char *view, const char *zone, bool failed) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return;
  wake_key_one(w, name_key(view, zone), failed, false, false);
}

void park_wake_queue_all(const char *view, const char *zone, bool failed) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return;
  const uint64_t key = name_key(view, zone);
  for (int w = 0; w < PARK_MAX_WORKERS; w++) wake_key_one(w, key, failed, false, false);
}

/* the workers of the set: workers 0..30 by their bit, bit 31 every worker from 31 up (a set that park_att_take() returns has the bits 15..31 all set for a worker of 15 and up) */
static void wake_set(uint32_t workers, uint64_t key, bool failed, bool retry, bool fetch) {
  if (workers == PARK_ATT_ALL) {
    for (int w = 0; w < PARK_MAX_WORKERS; w++) wake_key_one(w, key, failed, retry, fetch);
    return;
  }
  for (uint32_t m = workers & 0x7FFFFFFFu; m; m &= m - 1) wake_key_one(__builtin_ctz(m), key, failed, retry, fetch);
  if (workers & 0x80000000u) {
    const int wm = atomic_load_explicit(&g_wmax, memory_order_relaxed);
    for (int w = 31; w < wm; w++) wake_key_one(w, key, failed, retry, fetch);
  }
}

void park_wake_queue_mask(const char *view, const char *zone, uint32_t workers, bool failed) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return;
  wake_set(workers, name_key(view, zone), failed, false, false);
}

void park_wake_queue_retry(const char *view, const char *zone, uint32_t workers, bool fetch) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return;
  wake_set(workers, name_key(view, zone), false, true, fetch);
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

/* ------------------------------------------------------------------ ATTACH requests (0.7 store; the idea is in dns_park.h) */
/* One request is a zone of the store: the view's id (16 bits), the zone's (32), a priority (8), in one word.  The ring has one producer (its worker) and any number of
 * consumers (the store threads): a consumer reads the slot and moves the tail with a compare-and-swap; when it loses the race the word it read is dropped, and a producer
 * cannot have overwritten a slot before the tail went past it. */
typedef struct {
  _Atomic uint64_t q[PARK_ATTACH_RING];
  _Atomic uint32_t head, tail;
} att_ring_t;
static att_ring_t g_attach[PARK_MAX_WORKERS];
static _Atomic int g_attach_kq = -1;
static _Atomic int g_attach_asleep;                      /* the store threads that are about to wait for events, or wait */
static _Atomic uint32_t g_attach_rr;
static _Atomic int g_attach_wmax;                        /* the highest worker that asked, plus one */

void park_attach_set_notify(int kq) { atomic_store_explicit(&g_attach_kq, kq, memory_order_relaxed); }

static void trigger_attach(void) {
  atomic_thread_fence(memory_order_seq_cst);
  if (atomic_load_explicit(&g_attach_asleep, memory_order_relaxed) > 0) trigger(atomic_load_explicit(&g_attach_kq, memory_order_relaxed), PARK_ATTACH_IDENT);
}

bool park_attach_zid(int w, uint16_t sview, uint32_t zid) {
  if (w < 0 || w >= PARK_MAX_WORKERS) return false;
  att_ring_t *r = &g_attach[w];
  int cur = atomic_load_explicit(&g_attach_wmax, memory_order_relaxed);
  while (cur < w + 1 && !atomic_compare_exchange_weak_explicit(&g_attach_wmax, &cur, w + 1, memory_order_relaxed, memory_order_relaxed)) {}
  uint32_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
  if (head - tail >= PARK_ATTACH_RING) return false;                     /* (full: the query stays parked and the worker asks again) */
  atomic_store_explicit(&r->q[head % PARK_ATTACH_RING], ((uint64_t)sview << 32) | zid, memory_order_relaxed);
  atomic_store_explicit(&r->head, head + 1, memory_order_release);
  trigger_attach();
  return true;
}

/* 0.7 store S3: attach requests of threads that are not parked-query workers (the engine's background attach for a CNAME or glue that leads into a stored zone, a DoT / DoH thread),
 * and of a worker that cannot name the zone's id (the cell was being written): a few slots, as the transfer threads' fetch slots, taken by compare-and-swap */
#define PARK_ATTACH_ANY_SLOTS 16
static park_fetch_req_t g_att_q[PARK_ATTACH_ANY_SLOTS];
static _Atomic uint8_t g_att_st[PARK_ATTACH_ANY_SLOTS];

static bool attach_request_any(const char *view, const char *zone, uint8_t prio) {
  size_t vl, zl;
  if (!key_fits(view, zone, &vl, &zl)) return false;
  for (int i = 0; i < PARK_ATTACH_ANY_SLOTS; i++) {
    uint8_t free_st = 0;
    if (!atomic_compare_exchange_strong_explicit(&g_att_st[i], &free_st, 1, memory_order_acquire, memory_order_relaxed)) continue;
    park_fetch_req_t *q = &g_att_q[i];
    memset(q, 0, sizeof(*q));
    q->vlen = (uint8_t)vl;
    q->zlen = (uint8_t)zl;
    memcpy(q->view, view, vl + 1);
    memcpy(q->zone, zone, zl + 1);
    q->prio = prio;
    atomic_store_explicit(&g_att_st[i], 2, memory_order_release);
    trigger_attach();
    return true;
  }
  return false;
}

bool park_attach_request_any(const char *view, const char *zone) { return attach_request_any(view, zone, 0); }
bool park_attach_request_bg(const char *view, const char *zone) { return attach_request_any(view, zone, 2); }

bool park_attach_pending(void) {
  for (int k = 0; k < PARK_ATTACH_ANY_SLOTS; k++)
    if (atomic_load_explicit(&g_att_st[k], memory_order_acquire) == 2) return true;
  int wm = atomic_load_explicit(&g_attach_wmax, memory_order_relaxed);
  for (int w = 0; w < wm; w++)
    if (atomic_load_explicit(&g_attach[w].head, memory_order_acquire) != atomic_load_explicit(&g_attach[w].tail, memory_order_relaxed)) return true;
  return false;
}

bool park_attach_sleep_prepare(void) {
  atomic_fetch_add_explicit(&g_attach_asleep, 1, memory_order_relaxed);
  atomic_thread_fence(memory_order_seq_cst);
  if (!park_attach_pending()) return false;
  atomic_fetch_sub_explicit(&g_attach_asleep, 1, memory_order_relaxed);
  return true;
}

void park_attach_sleep_done(void) { atomic_fetch_sub_explicit(&g_attach_asleep, 1, memory_order_relaxed); }

static bool att_ring_pop(att_ring_t *r, uint16_t *sview, uint32_t *zid) {
  for (;;) {
    uint32_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
    uint32_t head = atomic_load_explicit(&r->head, memory_order_acquire);
    if (tail == head) return false;
    uint64_t v = atomic_load_explicit(&r->q[tail % PARK_ATTACH_RING], memory_order_relaxed);
    if (atomic_compare_exchange_weak_explicit(&r->tail, &tail, tail + 1, memory_order_acq_rel, memory_order_relaxed)) {
      *sview = (uint16_t)(v >> 32);
      *zid = (uint32_t)v;
      return true;
    }
  }
}

bool park_attach_next(park_attach_req_t *out) {
  bool got = false;
  for (int k = 0; k < PARK_ATTACH_ANY_SLOTS && !got; k++) {
    uint8_t ready = 2;
    if (atomic_load_explicit(&g_att_st[k], memory_order_relaxed) != 2 || !atomic_compare_exchange_strong_explicit(&g_att_st[k], &ready, 3, memory_order_acquire, memory_order_relaxed)) continue;
    const park_fetch_req_t *q = &g_att_q[k];
    out->by_name = true;
    out->prio = q->prio;
    out->worker = -1;
    out->sview = 0;
    out->zid = 0;
    memcpy(out->view, q->view, (size_t)q->vlen + 1);
    memcpy(out->zone, q->zone, (size_t)q->zlen + 1);
    atomic_store_explicit(&g_att_st[k], 0, memory_order_release);
    got = true;
  }
  int wm = atomic_load_explicit(&g_attach_wmax, memory_order_relaxed);
  uint32_t start = got || wm == 0 ? 0 : atomic_fetch_add_explicit(&g_attach_rr, 1, memory_order_relaxed);
  for (int i = 0; i < wm && !got; i++) {
    int w = (int)((start + (uint32_t)i) % (uint32_t)wm);
    uint16_t sv;
    uint32_t zid;
    if (att_ring_pop(&g_attach[w], &sv, &zid)) {
      out->by_name = false;
      out->prio = 0;
      out->worker = (int16_t)w;
      out->sview = sv;
      out->zid = zid;
      got = true;
    }
  }
  if (got && park_attach_pending()) trigger_attach();    /* (another store thread may be asleep while more wait) */
  return got;
}

/* ---- the attach claims: one request for a stored zone across the workers (see dns_park.h) ----
 * A slot is one word: the zone (view id and zone id, which are the exact name of the claim: no hash is compared, so a claim is never taken for another zone's), the set of the workers
 * that wait for it (bits 0..14 one worker each, bit 15 every worker from 15 up) and a bit that says that the request is in a ring.  Everything is a compare-and-swap on that one
 * word, so a worker that joins and the store thread that takes the claim cannot miss each other: a join that came before the take is in the set it returns, one that came after finds no
 * claim and makes the request itself.  A claim is made for the few thousand zones that wait at one time; 131072 slots (1 MB of address space) keep the table sparse. */
#define ACL_SLOTS 131072u
#define ACL_WIN 8u
#define ACL_SET 0xFFFFu
#define ACL_REQ 0x10000ull
#define ACL_ID(sv, zid) (((uint64_t)(zid) << 32) | ((uint64_t)((sv) & 0xFFu) << 24) | (1ull << 23))      /* (bit 23 is set in every id: an id is never 0, the free slot) */
#define ACL_IDMASK 0xFFFFFFFFFF800000ull
static _Atomic uint64_t g_aclaim[ACL_SLOTS];             /* 0: free */

static size_t acl_slot(uint64_t id, unsigned j) {
  uint64_t x = id * 0x9E3779B97F4A7C15ull;
  return (size_t)(((x >> 40) + j) & (ACL_SLOTS - 1u));
}

static uint64_t acl_bit(int w) { return 1ull << (w < 15 ? (w < 0 ? 0 : w) : 15); }
static uint32_t acl_to_set(uint64_t v) {                 /* the set of a slot as a set of workers: workers 0..14, and every worker from 15 up (the bits 15..31 of a 32 bit set) */
  uint32_t s = (uint32_t)(v & 0x7FFFu);
  if (v & 0x8000u) s |= 0xFFFF8000u;
  return s;
}

int park_att_claim(uint16_t sview, uint32_t zid, int w) {
  const uint64_t id = ACL_ID(sview, zid), bit = acl_bit(w);
  for (;;) {
    int free_j = -1;
    for (unsigned j = 0; j < ACL_WIN; j++) {
      _Atomic uint64_t *s = &g_aclaim[acl_slot(id, j)];
      uint64_t v = atomic_load_explicit(s, memory_order_acquire);
      if (v == 0) {
        if (free_j < 0) free_j = (int)j;
        continue;
      }
      if ((v & ACL_IDMASK) != id) continue;
      while ((v & ACL_IDMASK) == id) {                   /* the zone's claim: this worker joins */
        if (v & bit) return (v & ACL_REQ) ? 0 : 2;       /* (it was in the set already: its first query asked) */
        if (atomic_compare_exchange_weak_explicit(s, &v, v | bit, memory_order_acq_rel, memory_order_acquire)) return (v & ACL_REQ) ? 0 : 2;
      }
      free_j = -2;                                       /* (the claim was taken while we looked: start again) */
      break;
    }
    if (free_j == -2) continue;
    if (free_j < 0) return -1;                           /* no room for a mark: the caller asks without one */
    _Atomic uint64_t *s = &g_aclaim[acl_slot(id, (unsigned)free_j)];
    uint64_t z = 0;
    if (atomic_compare_exchange_strong_explicit(s, &z, id | bit, memory_order_acq_rel, memory_order_acquire)) return 1;
    /* the slot was taken between the look and the swap: look again (it may be this zone's claim) */
  }
}

/* the request of the claim is in a ring: a worker that joins now does not have to make one */
void park_att_requested(uint16_t sview, uint32_t zid) {
  const uint64_t id = ACL_ID(sview, zid);
  for (unsigned j = 0; j < ACL_WIN; j++) {
    _Atomic uint64_t *s = &g_aclaim[acl_slot(id, j)];
    uint64_t v = atomic_load_explicit(s, memory_order_acquire);
    while (v != 0 && (v & ACL_IDMASK) == id) {
      if (atomic_compare_exchange_weak_explicit(s, &v, v | ACL_REQ, memory_order_acq_rel, memory_order_acquire)) return;
    }
  }
}

uint32_t park_att_take(uint16_t sview, uint32_t zid) {
  const uint64_t id = ACL_ID(sview, zid);
  for (unsigned j = 0; j < ACL_WIN; j++) {
    _Atomic uint64_t *s = &g_aclaim[acl_slot(id, j)];
    uint64_t v = atomic_load_explicit(s, memory_order_acquire);
    while (v != 0 && (v & ACL_IDMASK) == id) {
      if (atomic_compare_exchange_weak_explicit(s, &v, 0, memory_order_acq_rel, memory_order_acquire)) return acl_to_set(v);
    }
  }
  return PARK_ATT_ALL;                                   /* no claim (a request without one, or a duplicate that came after the first was done): whoever waits is woken */
}

/* the worker no longer waits for the zone (its last query for it was answered or dropped without the zone): its bit goes, and the claim with it when nobody is left */
bool park_att_leave(uint16_t sview, uint32_t zid, int w) {
  const uint64_t id = ACL_ID(sview, zid), bit = acl_bit(w);
  for (unsigned j = 0; j < ACL_WIN; j++) {
    _Atomic uint64_t *s = &g_aclaim[acl_slot(id, j)];
    uint64_t v = atomic_load_explicit(s, memory_order_acquire);
    while (v != 0 && (v & ACL_IDMASK) == id) {
      uint64_t nv = v & ~bit;
      if (!(nv & ACL_SET)) nv = 0;
      if (atomic_compare_exchange_weak_explicit(s, &v, nv, memory_order_acq_rel, memory_order_acquire)) return true;
    }
  }
  return false;
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

/* the same one-per-PARK_BG_MS rule for the background attach of a stored zone */
void park_bg_attach(const char *view, const char *zone) {
  uint64_t h = name_key(view, zone) ^ 0x9E3779B97F4A7C15ull;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t now = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  size_t i = (size_t)(h % PARK_BG_SLOTS);
  if (atomic_load_explicit(&g_bg_key[i], memory_order_relaxed) == h && now - atomic_load_explicit(&g_bg_at[i], memory_order_relaxed) < PARK_BG_MS) return;
  if (!park_attach_request_bg(view, zone)) return;
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

#define OPENSSL_SUPPRESS_DEPRECATED 1
#define STATIC_TEST
#include "dns_snapshot_rcu.h"
#include "dns_dynamic_update.h"
#include "dns_server_internal.h"
#include "dns_catalog_zone.h"
#include "dns_edns_ecs.h"
#include "dns_axfr_ixfr.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_tsig_acl.h"
#include "dns_query_engine.h"
#include "dns_alias.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include "dns_log.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

pthread_mutex_t g_zone_db_rebuild_lock = PTHREAD_MUTEX_INITIALIZER;

// Protected by g_zone_db_rebuild_lock
pending_coo_t *g_pending_coo = NULL;
int g_pending_coo_count = 0;
int g_pending_coo_capacity = 0;

_Atomic(zone_db_snapshot_t *) g_zone_db_active = ATOMIC_VAR_INIT(NULL);
_Atomic uint32_t g_zone_notify_pending = ATOMIC_VAR_INIT(0);

zone_db_snapshot_t *acquire_zone_snapshot(void) {
  return atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
}

void retain_zone_snapshot(zone_db_snapshot_t *snap) {
  if (snap) {
    atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
  }
}

/* worker_ctx_t を持たないスレッド用。load から参照獲得までを読み取り区間で守る。
 * 区間の外で load すると、retain する前に GC スレッドが epoch 待ちと
 * reader_count == 0 の確認を通り抜けて解放できてしまう。*/
zone_db_snapshot_t *acquire_retained_zone_snapshot(void) {
  rcu_aux_read_lock();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  retain_zone_snapshot(snap);
  rcu_aux_read_unlock();
  return snap;
}

void release_zone_snapshot(zone_db_snapshot_t *snap) {
  if (snap) {
    int old = atomic_load_explicit(&snap->reader_count, memory_order_relaxed);
    while (old > 0) {
      if (atomic_compare_exchange_weak_explicit(&snap->reader_count, &old, old - 1,
                                                memory_order_release, memory_order_relaxed)) {
        break;
      }
    }
  }
}

zone_config_t *find_zone_config_in_view(server_config_t *cfg,
                                        const char *view_name,
                                        const char *domain) {
  if (!cfg || !domain) return NULL;
  if (cfg->views) {
    for (view_config_t *v = cfg->views; v; v = v->next) {
      if (view_name && view_name[0] != '\0' && strcasecmp(v->name, view_name) != 0) continue;
      zone_config_t *z = view_find_zone_config(v, domain);
      if (z) return z;
      /* a zone this view shares with an earlier one (zone { in-view }): the zone that holds the data, the owner's.  The ACLs of the shared
       * zone are looked up with the view's name (dns_tsig_acl.c), so the caller gets the data settings here. */
      zone_config_t *stub = view_find_in_view(v, domain);
      if (stub) return stub->ext->iv->target;
      if (view_name && view_name[0] != '\0') return NULL;
    }
  } else {
    for (zone_config_t *z = cfg->zones; z; z = z->next) {
      if (domain_names_match_ci(z->domain, domain)) return z;
    }
  }
  return NULL;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* The zone directory (D1a): the index of a view, its elements, and what is thrown away when they change         */
/* ------------------------------------------------------------------------------------------------------------- */

/* the name of a zone without its trailing dot(s): the key of the index.  "." and "" are the root zone (length 0). */
static size_t zone_key_len(const char *name) {
  size_t len = strlen(name), bare;
  while ((bare = dns_name_len_no_root(name, len)) != len) len = bare;
  return len;
}

/* the hash of a zone name in the index (and in the registry): FNV-1a of the name without its trailing dot(s), case folded.  What
 * a lookup by a suffix of a query name (calc_fnv1a_strn(cursor, remaining)) computes for the same zone. */
static inline uint32_t zdir_name_hash(const char *name) {
  return calc_fnv1a_strn(name, zone_key_len(name));
}

static void zone_entry_unref(zone_db_entry_t *e);

/* a removed slot: readers walk over it; a real element is never at this address */
static zdir_elem_t zdir_tomb_obj;
#define ZDIR_TOMB (&zdir_tomb_obj)
#define ZDIR_F_GARB 0x8000u      /* the element is on a garbage list (set by garb_elem()): it is put there once */
/* an element that leaves the index goes to the garbage when only the index and the old snapshots know it: a directory-owned one, or a registry one that left the registry */
static inline bool zdir_goes_to_garbage(const zdir_elem_t *e) { return (e->kind & ZDIR_K_OWNED) || (e->flags & ZDIR_F_DELETED); }
#define ZDIR_MIN_CAP 64u

static zdir_tab_t *zdir_tab_new(size_t cap) {
  zdir_tab_t *t = calloc(1, sizeof(*t) + cap * sizeof(_Atomic(zdir_elem_t *)));    /* NULL pointers are all-zero bits */
  if (!t) return NULL;
  t->cap = cap;
  t->mask = cap - 1;
  return t;
}

/* the element with this key in the table (hash = calc_fnv1a_strn(key, klen)); no lock: slots are read with acquire, an element is
 * written before it is put in a slot */
static zdir_elem_t *zdir_tab_find(const zdir_tab_t *t, uint32_t hash, const char *key, size_t klen) {
  size_t i = hash & t->mask;
  for (;;) {
    zdir_elem_t *s = atomic_load_explicit(&t->slot[i], memory_order_acquire);
    if (!s) return NULL;
    if (s != ZDIR_TOMB && s->hash == hash && s->klen == klen && strncasecmp(s->name, key, klen) == 0) return s;
    i = (i + 1) & t->mask;
  }
}

static inline const zdir_tab_t *zdir_tab_of(const view_snapshot_t *view) {
  return (view && view->dir) ? atomic_load_explicit(&view->dir->tab, memory_order_acquire) : NULL;
}

static zdir_t *zdir_new(void) {
  zdir_t *d = calloc(1, sizeof(*d));
  if (d) atomic_init(&d->refs, 1);
  return d;
}

static void zdir_ref(zdir_t *d) {
  atomic_fetch_add_explicit(&d->refs, 1, memory_order_relaxed);
}

/* give back one reference of an entry that the directory kept; the last one frees the entry */
static void zdir_entry_unref(zone_db_entry_t *en) {
  if (atomic_fetch_sub_explicit(&en->snapshot_refs, 1, memory_order_acq_rel) == 1) {
    syslog(LOG_INFO, "[GC] Freeing deleted zone '%s'", en->domain);
    free_zone_db_entry(en);
  }
}

/* A directory-owned element: what it holds of its entry is released with it (unless the entry is borrowed). */
static void zdir_elem_release(zdir_elem_t *e) {
  zone_db_entry_t *en = atomic_load_explicit(&e->entry, memory_order_relaxed);
  if (en && !(e->kind & ZDIR_K_BORROWED)) zdir_entry_unref(en);
  free(e->error);
  free(e->digest);
  zone_ext_shared_unref(atomic_load_explicit(&e->sh, memory_order_relaxed));
  free(e);
}

/* the last view that listed the directory is gone: nobody can reach it, and the elements it owns go with it (the registry's and
 * the ones that were taken out earlier are not in its table or are not its to free). */
static void zdir_unref(zdir_t *d) {
  if (!d || atomic_fetch_sub_explicit(&d->refs, 1, memory_order_acq_rel) != 1) return;
  zdir_tab_t *t = atomic_load_explicit(&d->tab, memory_order_relaxed);
  burst_yield_t by = BURST_YIELD_INIT;
  for (size_t i = 0; t && i < t->cap; i++) {
    zdir_elem_t *e = atomic_load_explicit(&t->slot[i], memory_order_relaxed);
    if (!e || e == ZDIR_TOMB) continue;
    burst_yield(&by);
    if (e->kind & ZDIR_K_OWNED) {
      if (e->flags & ZDIR_F_GARB) continue;
      zdir_elem_release(e);
    }
  }
  free(t);
  free(atomic_load_explicit(&d->tick, memory_order_relaxed));
  free(d);
}

/* ---- the garbage lists: under g_zone_db_rebuild_lock.  g_garb collects what is taken out between two publications; the
 * publication hands it to the snapshot it retires (gc_retire_locked()). ---- */
static zdir_garbage_t g_garb;

static void garb_elem(zdir_garbage_t *g, zdir_elem_t *e) {
  if (e->flags & ZDIR_F_GARB) return;
  e->flags |= ZDIR_F_GARB;
  e->next = g->elems;
  g->elems = e;
}

static void garb_free(zdir_garbage_t *g) {
  burst_yield_t by = BURST_YIELD_INIT;
  for (zdir_elem_t *e = g->elems, *nx; e; e = nx) {
    nx = e->next;
    burst_yield(&by);
    zdir_elem_release(e);
  }
  for (zdir_tab_t *t = g->tabs, *nx; t; t = nx) {
    nx = t->gnext;
    free(t);
  }
  for (zdir_tick_t *t = g->ticks, *nx; t; t = nx) {
    nx = t->gnext;
    free(t);
  }
  for (zdir_gent_t *n = g->ents, *nx; n; n = nx) {
    nx = n->next;
    if (n->entry) zdir_entry_unref(n->entry);
    zone_ext_shared_unref(n->sh_old);
    free(n);
  }
  memset(g, 0, sizeof(*g));
}

/* ---- the snapshots that were retired and are not drained yet, oldest first.  What a snapshot keeps in its garbage list is freed
 * when it and every older snapshot have been drained: a reader that holds an older snapshot (a transfer, a control command) can
 * have got a pointer to it from the shared directory. ---- */
static pthread_mutex_t g_gc_lock = PTHREAD_MUTEX_INITIALIZER;
static zone_db_snapshot_t *g_gc_head, *g_gc_tail;
static _Atomic unsigned g_gc_unstarted;       /* queued snapshots that have no cleanup thread yet (a thread could not be started) */

/* old is replaced by the snapshot that was just published (the rebuild lock is held): it takes the garbage so far and joins the queue */
static void gc_retire_locked(zone_db_snapshot_t *old) {
  old->garb = g_garb;
  memset(&g_garb, 0, sizeof(g_garb));
  old->gc_next = NULL;
  pthread_mutex_lock(&g_gc_lock);
  old->gc_queued = true;
  old->gc_started = false;
  atomic_fetch_add_explicit(&g_gc_unstarted, 1, memory_order_relaxed);
  if (g_gc_tail) g_gc_tail->gc_next = old;
  else g_gc_head = old;
  g_gc_tail = old;
  pthread_mutex_unlock(&g_gc_lock);
}

/* the views of a snapshot that nobody reads any more are released; then, in the order of retirement, the snapshots that are
 * drained are freed with their garbage.  snap may be freed here. */
static void gc_drained(zone_db_snapshot_t *snap) {
  zone_db_snapshot_t *done = NULL, **tail = &done;
  pthread_mutex_lock(&g_gc_lock);
  snap->gc_drained = true;
  while (g_gc_head && g_gc_head->gc_drained) {
    zone_db_snapshot_t *s = g_gc_head;
    g_gc_head = s->gc_next;
    if (!g_gc_head) g_gc_tail = NULL;
    s->gc_next = NULL;
    *tail = s;
    tail = &s->gc_next;
  }
  pthread_mutex_unlock(&g_gc_lock);
  while (done) {
    zone_db_snapshot_t *s = done;
    done = s->gc_next;
    garb_free(&s->garb);
    free(s);
  }
  if (gc_has_unstarted()) gc_start_pending();      /* a thread that could not be started earlier: try again now that one has ended */
}

/* ---- writers: change the index of a directory in place (g_zone_db_rebuild_lock held) ---- */

/* room for `extra` more elements without a rebuild of the table (the load factor stays at or below one half, tombstones counted);
 * otherwise the elements move to a new table, which replaces the old one for new readers; the old one is garbage.  false: out of memory. */
static bool zdir_reserve(zdir_t *d, size_t extra) {
  zdir_tab_t *old = atomic_load_explicit(&d->tab, memory_order_relaxed);
  if (old && (d->used + extra) * 2 <= old->cap) return true;
  size_t live = atomic_load_explicit(&d->live, memory_order_relaxed) + extra, cap = ZDIR_MIN_CAP;
  while (cap < live * 2) cap <<= 1;
  zdir_tab_t *nt = zdir_tab_new(cap);
  if (!nt) return false;
  size_t n = 0;
  burst_yield_t by = BURST_YIELD_INIT;
  for (size_t i = 0; old && i < old->cap; i++) {
    zdir_elem_t *e = atomic_load_explicit(&old->slot[i], memory_order_relaxed);
    if (!e || e == ZDIR_TOMB) continue;
    burst_yield(&by);
    size_t j = e->hash & nt->mask;
    while (atomic_load_explicit(&nt->slot[j], memory_order_relaxed)) j = (j + 1) & nt->mask;
    atomic_store_explicit(&nt->slot[j], e, memory_order_relaxed);
    n++;
  }
  atomic_store_explicit(&d->tab, nt, memory_order_release);
  if (old) {
    old->gnext = g_garb.tabs;
    g_garb.tabs = old;
  }
  d->used = n;
  return true;
}

static void zdir_count_flags(zdir_t *d, const zdir_elem_t *e, int delta) {
  if (e->kind & ZDIR_K_STATIC) atomic_fetch_add_explicit(&d->n_static, (size_t)(ptrdiff_t)delta, memory_order_relaxed);
  if (e->kind & ZDIR_K_SHARED) atomic_fetch_add_explicit(&d->n_shared, (size_t)(ptrdiff_t)delta, memory_order_relaxed);
  atomic_fetch_add_explicit(&d->live, (size_t)(ptrdiff_t)delta, memory_order_relaxed);
}

/* put e in the index (zdir_reserve() was called for it).  An element with the same name is replaced by it, in one store, so a reader sees
 * the old or the new; the replaced one is returned (NULL: none).  e itself already there: nothing happens. */
static zdir_elem_t *zdir_insert(zdir_t *d, zdir_elem_t *e) {
  zdir_tab_t *t = atomic_load_explicit(&d->tab, memory_order_relaxed);
  size_t i = e->hash & t->mask, tomb = (size_t)-1;
  for (;;) {
    zdir_elem_t *s = atomic_load_explicit(&t->slot[i], memory_order_relaxed);
    if (!s) break;
    if (s == ZDIR_TOMB) {
      if (tomb == (size_t)-1) tomb = i;
    } else if (s == e) {
      return NULL;
    } else if (s->hash == e->hash && s->klen == e->klen && strncasecmp(s->name, e->name, e->klen) == 0) {
      atomic_store_explicit(&t->slot[i], e, memory_order_release);
      zdir_count_flags(d, s, -1);
      zdir_count_flags(d, e, 1);
      return s;
    }
    i = (i + 1) & t->mask;
  }
  if (tomb != (size_t)-1) {
    i = tomb;
  } else {
    d->used++;
  }
  atomic_store_explicit(&t->slot[i], e, memory_order_release);
  zdir_count_flags(d, e, 1);
  return NULL;
}

/* take e out of the index (it stays valid for the readers that have it).  false: it was not in it. */
static bool zdir_remove(zdir_t *d, zdir_elem_t *e) {
  zdir_tab_t *t = atomic_load_explicit(&d->tab, memory_order_relaxed);
  if (!t) return false;
  size_t i = e->hash & t->mask;
  for (;;) {
    zdir_elem_t *s = atomic_load_explicit(&t->slot[i], memory_order_relaxed);
    if (!s) return false;
    if (s == e) {
      atomic_store_explicit(&t->slot[i], ZDIR_TOMB, memory_order_release);
      zdir_count_flags(d, e, -1);
      return true;
    }
    i = (i + 1) & t->mask;
  }
}

/* the element of this name in the directory of a writer (the lookup of a reader, for a directory instead of a view) */
static zdir_elem_t *zdir_lookup(const zdir_t *d, const char *name) {
  const zdir_tab_t *t = d ? atomic_load_explicit(&d->tab, memory_order_acquire) : NULL;
  if (!t) return NULL;
  size_t klen = zone_key_len(name);
  return zdir_tab_find(t, calc_fnv1a_strn(name, klen), name, klen);
}

static inline bool zdir_ticks(const zdir_elem_t *e) {
  return (e->flags & ZDIR_F_TICK) && !(e->kind & ZDIR_K_SHARED);
}

static int cmp_ptr(const void *a, const void *b) {
  const void *x = *(const void *const *)a, *y = *(const void *const *)b;
  return x < y ? -1 : x > y;
}

static bool ptr_in_sorted(zdir_elem_t *const *arr, size_t n, const zdir_elem_t *p) {
  size_t lo = 0, hi = n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (arr[mid] == p) return true;
    if (arr[mid] < p) lo = mid + 1;
    else hi = mid;
  }
  return false;
}

/* The tick list of a directory after a change: the ticking elements of the old list (or, without one, of the table) minus the elements
 * of rem (sorted) plus the ticking ones of add.  *out: the new list, NULL when nothing ticks any more.  false: out of memory. */
static bool zdir_tick_make(const zdir_t *d, bool from_table, zdir_elem_t *const *rem, size_t nrem, zdir_elem_t *const *add, size_t nadd,
                           zdir_tick_t **out) {
  const zdir_tick_t *ot = atomic_load_explicit(&d->tick, memory_order_relaxed);
  const zdir_tab_t *tab = atomic_load_explicit(&d->tab, memory_order_relaxed);
  size_t cap = nadd + (from_table ? 0 : (ot ? ot->n : 0));
  for (size_t i = 0; from_table && tab && i < tab->cap; i++) {      /* (one pass to size the list: not a pointer per slot of the index) */
    zdir_elem_t *e = atomic_load_explicit(&tab->slot[i], memory_order_relaxed);
    if (e && e != ZDIR_TOMB && zdir_ticks(e)) cap++;
  }
  *out = NULL;
  zdir_tick_t *nt = malloc(sizeof(*nt) + (cap ? cap : 1) * sizeof(zdir_elem_t *));
  if (!nt) return false;
  nt->gnext = NULL;
  size_t n = 0;
  if (from_table) {
    for (size_t i = 0; tab && i < tab->cap; i++) {
      zdir_elem_t *e = atomic_load_explicit(&tab->slot[i], memory_order_relaxed);
      if (e && e != ZDIR_TOMB && zdir_ticks(e) && !(nrem && ptr_in_sorted(rem, nrem, e))) nt->e[n++] = e;
    }
  } else {
    for (size_t i = 0; ot && i < ot->n; i++)
      if (!(nrem && ptr_in_sorted(rem, nrem, ot->e[i]))) nt->e[n++] = ot->e[i];
  }
  for (size_t i = 0; i < nadd; i++)
    if (zdir_ticks(add[i])) nt->e[n++] = add[i];
  /* a list made from the index is in the order of the configuration (zone { } blocks, catalog members), then the others: refreshes start in
   * this order, and transfers-per-ns lets only some of them run at once (the slot order of the index would make it depend on the names' hashes) */
  if (from_table && n > 1) qsort(nt->e, n, sizeof(nt->e[0]), zdir_listing_cmp);
  nt->n = n;
  if (n == 0 && !ot) {
    free(nt);
    return true;
  }
  *out = nt;
  return true;
}

/* publish a tick list made by zdir_tick_make() (NULL: the list is empty now); the old one is garbage */
static void zdir_tick_publish(zdir_t *d, zdir_tick_t *nt) {
  zdir_tick_t *ot = atomic_load_explicit(&d->tick, memory_order_relaxed);
  atomic_store_explicit(&d->tick, nt, memory_order_release);
  if (ot) {
    ot->gnext = g_garb.ticks;
    g_garb.ticks = ot;
  }
}

/* ---- readers ---- */

void zdir_iter_init(zdir_iter_t *it, const view_snapshot_t *view) {
  it->tab = zdir_tab_of(view);
  it->i = 0;
}

zdir_elem_t *zdir_iter_next(zdir_iter_t *it) {
  while (it->tab && it->i < it->tab->cap) {
    zdir_elem_t *e = atomic_load_explicit(&it->tab->slot[it->i++], memory_order_acquire);
    if (e && e != ZDIR_TOMB) return e;
  }
  return NULL;
}

int zdir_listing_cmp(const void *a, const void *b) {
  const zdir_elem_t *x = *(zdir_elem_t *const *)a, *y = *(zdir_elem_t *const *)b;
  bool xo = (x->kind & ZDIR_K_OWNED) != 0, yo = (y->kind & ZDIR_K_OWNED) != 0;
  if (xo != yo) return xo ? -1 : 1;
  if (!xo || x->source_id == y->source_id) return 0;
  return x->source_id < y->source_id ? -1 : 1;
}

size_t zdir_iter_slots(const zdir_iter_t *it) {
  return it->tab ? it->tab->cap : 0;
}

zdir_elem_t *zdir_iter_at(const zdir_iter_t *it, size_t i) {
  if (!it->tab || i >= it->tab->cap) return NULL;
  zdir_elem_t *e = atomic_load_explicit(&it->tab->slot[i], memory_order_acquire);
  return e == ZDIR_TOMB ? NULL : e;
}

zdir_elem_t *const *zdir_tick_list(const view_snapshot_t *view, size_t *n) {
  const zdir_tick_t *t = (view && view->dir) ? atomic_load_explicit(&view->dir->tick, memory_order_acquire) : NULL;
  *n = t ? t->n : 0;
  return t ? t->e : NULL;
}

/* A zone's name, entry and flags in a directory-owned element.  The element takes over one reference of `entry` (unless `borrowed`).
 * order: the position of the zone in the listing of the view.  NULL: out of memory (the caller still owns the reference). */
static zdir_elem_t *zdir_elem_new_owned(zone_db_entry_t *entry, uint8_t kind, int64_t order) {
  size_t l = strlen(entry->domain);
  zdir_elem_t *e = calloc(1, sizeof(*e) + l + 1);
  if (!e) return NULL;
  memcpy(e->name, entry->domain, l + 1);
  e->klen = (uint8_t)zone_key_len(e->name);
  e->hash = zdir_name_hash(e->name);
  e->source_id = order;
  atomic_init(&e->state, ZDIR_ST_RESIDENT);
  e->kind = (uint8_t)(kind | ZDIR_K_OWNED);
  e->flags = (uint16_t)(zone_entry_ticks(entry) ? ZDIR_F_TICK : 0);
  atomic_init(&e->entry, entry);
  return e;
}

bool view_set_entries(view_snapshot_t *view, zone_db_entry_t *const *entries, size_t n) {
  view_clear_dir(view);
  zdir_t *d = zdir_new();
  if (!d) return false;
  pthread_mutex_lock(&g_zone_db_rebuild_lock);
  bool ok = zdir_reserve(d, n);
  for (size_t i = 0; ok && i < n; i++) {
    if (!entries[i]) continue;
    zdir_elem_t *e = zdir_elem_new_owned(entries[i], ZDIR_K_BORROWED, (int64_t)i);
    if (!e) {
      ok = false;
      break;
    }
    zdir_elem_t *dup = zdir_insert(d, e);      /* (a name listed twice: the later entry wins) */
    if (dup) free(dup);                        /* (borrowed entry, nothing else to give back) */
  }
  pthread_mutex_unlock(&g_zone_db_rebuild_lock);
  if (ok) {
    zdir_tick_t *tk = NULL;
    ok = zdir_tick_make(d, true, NULL, 0, NULL, 0, &tk);
    atomic_store_explicit(&d->tick, tk, memory_order_release);
  }
  if (!ok) {
    zdir_unref(d);
    return false;
  }
  view->dir = d;
  return true;
}

void view_clear_dir(view_snapshot_t *view) {
  zdir_unref(view->dir);
  view->dir = NULL;
}

// view 内で apex が domain と一致するゾーンを返す (最長一致ではなく完全一致)。
zdir_elem_t *zdir_find_exact(const view_snapshot_t *view, const char *domain) {
  const zdir_tab_t *t = domain ? zdir_tab_of(view) : NULL;
  if (!t) return NULL;
  size_t klen = zone_key_len(domain);
  return zdir_tab_find(t, calc_fnv1a_strn(domain, klen), domain, klen);
}

zone_db_entry_t *find_zone_exact_in_view(view_snapshot_t *view, const char *domain) {
  return zdir_entry(zdir_find_exact(view, domain));
}


view_snapshot_t *snapshot_find_view(zone_db_snapshot_t *snap, const char *view_name) {
  if (!snap || !snap->views || !view_name) return NULL;
  for (size_t v = 0; v < snap->view_count; v++) {
    if (snap->views[v].name && strcasecmp(snap->views[v].name, view_name) == 0) {
      return &snap->views[v];
    }
  }
  return NULL;
}

// 同じゾーン名が複数の view にあり得るので、ゾーン単位の処理は必ず view を指定して引く (R-26)。
zone_db_entry_t *snapshot_get_zone_in_view(zone_db_snapshot_t *snap, const char *view_name,
                                           const char *domain) {
  return find_zone_exact_in_view(snapshot_find_view(snap, view_name), domain);
}

// domainに一致するゾーンを、view_nameが指定されていればそのview内だけを、
// NULLなら全view横断で検索する。戻り値は一致したview数(0/1/2以上)。
// 1件のみ一致した場合にresultへ結果を格納する。
int lookup_zone_across_views(zone_db_snapshot_t *snap, server_config_t *cfg,
                             const char *domain, const char *view_name,
                             zone_lookup_result_t *result) {
  if (!cfg || !domain || !result) return 0;
  int matches = 0;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    if (view_name && v->name && strcasecmp(v->name, view_name) != 0) continue;
    zone_config_t *zcfg = view_find_zone_config(v, domain);
    const char *ename = v->name;
    if (!zcfg && view_name) {
      /* a view that was named and shares the zone with an earlier one (zone { in-view }): the command is for the zone of the owner view.
       * Without a view name the owner view alone counts, so a shared zone is one match. */
      zone_config_t *stub = view_find_in_view(v, domain);
      if (stub) {
        zcfg = stub->ext->iv->target;
        ename = stub->ext->iv->view;
      }
    }
    if (!zcfg) continue;

    zone_db_entry_t *entry = ename ? snapshot_get_zone_in_view(snap, ename, domain) : NULL;
    matches++;
    if (matches == 1) {
      result->entry = entry;
      result->zcfg = zcfg;
      result->view_name = ename;
    }
  }
  return matches;
}

// 全 view を横断して最初に一致したゾーンを返す。どの view のエントリかを区別できないため、
// サーバーのコードでは使わないこと (単体テスト用)。view ごとの処理は snapshot_get_zone_in_view()。
zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain) {
  if (!snap || !domain || !snap->views) return NULL;
  for (size_t v = 0; v < snap->view_count; v++) {
    zone_db_entry_t *e = find_zone_exact_in_view(&snap->views[v], domain);
    if (e) return e;
  }
  return NULL;
}
/* The zone that holds qname: the longest suffix of the name that is a zone of the view (the root zone last).  O-08: the label
 * boundary is an unescaped '.' only ("a\.example.test" is not under "example.test").  Names are canonical (dns_wire.h), so the
 * comparison with a zone name ignores the case. */
zdir_elem_t *zdir_find_suffix(const view_snapshot_t *view, const char *qname) {
  const zdir_tab_t *t = qname ? zdir_tab_of(view) : NULL;
  if (!t) return NULL;
  size_t q_len = zone_key_len(qname);
  const char *cursor = qname;
  size_t remaining = q_len;
  while (remaining > 0) {
    zdir_elem_t *hit = zdir_tab_find(t, calc_fnv1a_strn(cursor, remaining), cursor, remaining);
    if (hit) return hit;
    // 次のラベル境界まで進める (末尾のルートの '.' は remaining の外)
    const char *dot = strchr_unescaped(cursor, '.');
    if (!dot || (size_t)(dot - cursor) >= remaining) break;
    remaining -= (size_t)(dot - cursor) + 1;
    cursor = dot + 1;
  }
  // ルートゾーン（"." または空文字列）へのフォールバック
  return zdir_tab_find(t, calc_fnv1a_strn("", 0), "", 0);
}

zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname) {
  return zdir_entry(zdir_find_suffix(view, qname));
}

/* R-32: RFC 4035 §3.1.4.1 / §3.1.5: DS は委任点の親側にしか無い権威データで、子ゾーンは DS を持たない。
 * QTYPE DS の QNAME が見つかったゾーンの頂点そのものなら、親の名前 (最初のラベルを除いた名前、1 ラベルなら
 * ルート) で探し直し、あればそのゾーンから答える (DS、または親の SOA と NSEC/NSEC3 による NODATA。親がさらに
 * 上で委任していれば参照応答)。親を持たないとき、または親が forward ゾーン (権威データを持たない) のときは
 * 子の頂点から権威のある NODATA を返す (§3.1.4.1 がこの場合に定める応答)。QUERY 以外は qtype に 0 を渡す。 */
zone_db_entry_t *find_zone_for_query_ex(view_snapshot_t *view, const char *qname, uint16_t qtype, zdir_elem_t **elem_out) {
  zdir_elem_t *el = zdir_find_suffix(view, qname);
  zone_db_entry_t *entry = zdir_entry(el);
  if (elem_out) *elem_out = el;
  if (qtype != 43 || !entry || !domain_names_match_ci(entry->domain, qname)) return entry;
  size_t q_len = zone_key_len(qname);
  if (q_len == 0) return entry; // ルート自身の DS は親を持たない
  const char *dot = strchr_unescaped(qname, '.');
  const char *parent = (dot && (size_t)(dot - qname) < q_len) ? dot + 1 : ".";
  zdir_elem_t *pel = zdir_find_suffix(view, parent);
  zone_db_entry_t *p = zdir_entry(pel);
  if (pel && !p) {                       /* the parent is in the directory and not in memory: the answer comes from it, so it is the zone to wait for */
    if (elem_out) *elem_out = pel;
    return NULL;
  }
  if (!p || p == entry || p->kind == ZONE_KIND_FORWARD) return entry;
  if (elem_out) *elem_out = pel;
  return p;
}

zone_db_entry_t *find_zone_for_query(view_snapshot_t *view, const char *qname, uint16_t qtype) {
  return find_zone_for_query_ex(view, qname, qtype, NULL);
}

zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name) {
  zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
  if (!z) return NULL;
  atomic_init(&z->active_axfr, 0);
  atomic_init(&z->snapshot_refs, 1);
  z->id = zone_entry_next_id();

  size_t dlen = domain ? strlen(domain) : 0;
  if (dlen > 0 && dns_name_len_no_root(domain, dlen) == dlen && dlen + 1 < sizeof(z->domain)) {
    memcpy(z->domain, domain, dlen);
    z->domain[dlen] = '.';
    z->domain[dlen + 1] = '\0';
  } else {
    strncpy(z->domain, domain ? domain : "", sizeof(z->domain) - 1);
    z->domain[sizeof(z->domain) - 1] = '\0';
  }
  strncpy(z->view_name, view_name ? view_name : "", sizeof(z->view_name) - 1);
  z->view_name[sizeof(z->view_name) - 1] = '\0';
  pthread_mutex_init(&z->writer_lock, NULL);
  pthread_mutex_init(&z->ixfr_history.lock, NULL);
  atomic_init(&z->rcu.active, &zone_version_empty);
  return z;
}

static void zone_bytes_retired_add(int cls, int64_t delta);
/* D1a step 5: bytes of zones that were evicted and whose entries are not freed yet (they are in the retired total until then) */
static _Atomic int64_t g_evict_inflight;

void free_zone_db_entry(zone_db_entry_t *entry) {
  if (!entry) return;
  if (entry->groups) {
    for (int i = 0; i < entry->group_count; i++) {
      free(entry->groups[i]);
    }
    free(entry->groups);
  }
  wait_for_active_axfr(entry, 0);
  pthread_mutex_destroy(&entry->writer_lock);
  pthread_mutex_destroy(&entry->ixfr_history.lock);
  ixfr_history_clear(&entry->ixfr_history);
  zone_version_t *active = atomic_load_explicit(&entry->rcu.active, memory_order_relaxed);
  if (active && active->counted) zone_bytes_resident_add(zone_bytes_class(entry), -(int64_t)active->bytes);   /* (8.1) */
  if (entry->evicted_bytes) {                       /* evicted: the active version was moved to the retired total when it left memory */
    zone_bytes_retired_add(zone_bytes_class(entry), -(int64_t)entry->evicted_bytes);
    atomic_fetch_sub_explicit(&g_evict_inflight, (int64_t)entry->evicted_bytes, memory_order_relaxed);
  }
  zone_version_free(active);
  /* a DB zone's settings (the entry owns the current block; replaced ones go through zone_retire_object()) */
  free_zone_config((zone_config_t *)atomic_load_explicit(&entry->dbcfg, memory_order_relaxed));
  free_zone_config((zone_config_t *)atomic_load_explicit(&entry->rxcfg, memory_order_relaxed));      /* B8t-2 */
  zone_ext_shared_unref(entry->rx_sh);
  /* the member ids of a catalog zone belong to its entry (a rebuild only copies the pointers while it runs) */
  if (entry->catalog_members) free_catalog_member_ids(entry->catalog_members, entry->catalog_member_count);
  free(entry->catalog_master);
  free(entry->catalog_member_unique_id);
  free(entry->owning_catalog_domain);
  free(entry);
}

/* The views of a snapshot are released; the directories go with the last snapshot that lists them.  A snapshot that was retired
 * (gc_retire_locked()) is not freed here: it is marked drained, and freed with its garbage when the older snapshots are drained
 * too (gc_drained()).  One that was never published (an aborted rebuild, a unit test's) is freed at once. */
void free_zone_db_snapshot(zone_db_snapshot_t *snap) {
  if (!snap) return;
  if (snap->views) {
    for (size_t v = 0; v < snap->view_count; v++) {
      view_snapshot_t *vs = &snap->views[v];
      free(vs->name);
      vs->name = NULL;
      if (vs->match_clients) {
        for (int i = 0; i < vs->match_clients_count; i++) {
          if (vs->match_clients[i]) free(vs->match_clients[i]);
        }
        free(vs->match_clients);
        vs->match_clients = NULL;
      }
      free(vs->match_clients_parsed);
      vs->match_clients_parsed = NULL;
      aml_unref(vs->match_aml);   /* NULL is fine */
      vs->match_aml = NULL;
      zdir_unref(vs->dir);
      vs->dir = NULL;
    }
    free(snap->views);
    snap->views = NULL;
  }
  if (snap->gc_queued) {
    gc_drained(snap);
    return;
  }
  garb_free(&snap->garb);
  free(snap);
}

/* GC threads that were started and have not finished.  The process manager forks the Backend, the routers and the
 * database loader; a fork while one of these threads still runs leaves a multi-threaded parent behind, and the child
 * (which only copies the forking thread) must not start threads of its own then (ThreadSanitizer refuses: "starting new
 * threads after multi-threaded fork").  gc_snapshot_wait_idle() lets the manager fork from a single thread. */
static _Atomic unsigned g_gc_live;
/* A thread that has counted itself out is still on its way out of the C library (and of ThreadSanitizer's bookkeeping),
 * and a fork in that window is a fork from a multi-threaded process.  So in the manager, before the Backend exists, the
 * cleanup threads are joinable and gc_snapshot_wait_idle() joins them.  The Backend turns this off (gc_snapshot_detach_only):
 * it creates a thread per retired snapshot for the life of the process and never joins. */
#define GC_TRACK_MAX 64
static bool g_gc_track = true;
static pthread_t g_gc_tids[GC_TRACK_MAX];
static unsigned g_gc_ntids;

void gc_snapshot_detach_only(void) {
  g_gc_track = false;
  g_gc_ntids = 0;                 /* the ids belong to the manager's threads, which the Backend does not have */
}

void gc_snapshot_wait_idle(void) {
  for (unsigned i = 0; i < g_gc_ntids; i++) pthread_join(g_gc_tids[i], NULL);
  g_gc_ntids = 0;
  for (int i = 0; atomic_load_explicit(&g_gc_live, memory_order_acquire) != 0; i++) {
    if (i == 30000) {    /* 30 s: a reader that never leaves; the fork goes on, the threads stay */
      syslog(LOG_WARNING, "[Manager] snapshot cleanup threads are still running; forking anyway");
      return;
    }
    struct timespec ts = { 0, 1000000 };
    nanosleep(&ts, NULL);
  }
}

/* start the cleanup of a retired snapshot; false when no thread could be started (the snapshot is then kept) */
static bool gc_snapshot_start(zone_db_snapshot_t *snap) {
  pthread_t gc_tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  bool track = g_gc_track && g_gc_ntids < GC_TRACK_MAX;      /* the manager: one thread creates and joins */
  if (!track) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  atomic_fetch_add_explicit(&g_gc_live, 1, memory_order_relaxed);
  bool ok = pthread_create(&gc_tid, &attr, gc_snapshot_thread, snap) == 0;
  if (!ok) atomic_fetch_sub_explicit(&g_gc_live, 1, memory_order_release);
  else if (track) g_gc_tids[g_gc_ntids++] = gc_tid;
  pthread_attr_destroy(&attr);
  return ok;
}

/* Start the cleanup thread of every queued snapshot that has none.  A snapshot whose thread could not be started stays queued, and
 * the garbage of every later snapshot waits behind it (the release is in order), so whoever publishes a snapshot, every cleanup thread
 * that ends and the control thread's tick try again.  One failure ends a round (no spinning on a full thread table). */
static pthread_mutex_t g_gc_start_lock = PTHREAD_MUTEX_INITIALIZER;

void gc_start_pending(void) {
  pthread_mutex_lock(&g_gc_start_lock);
  for (;;) {
    zone_db_snapshot_t *s = NULL;
    pthread_mutex_lock(&g_gc_lock);
    for (zone_db_snapshot_t *q = g_gc_head; q && !s; q = q->gc_next)
      if (!q->gc_started) {
        q->gc_started = true;                 /* (claimed: it cannot be drained, and so not freed, before its thread has run) */
        s = q;
      }
    pthread_mutex_unlock(&g_gc_lock);
    if (!s) break;
    if (!gc_snapshot_start(s)) {
      pthread_mutex_lock(&g_gc_lock);
      s->gc_started = false;
      pthread_mutex_unlock(&g_gc_lock);
      syslog(LOG_ERR, "[Core] cannot start the snapshot cleanup thread; the old snapshot and the garbage queued behind it are kept until the next try");
      break;
    }
    atomic_fetch_sub_explicit(&g_gc_unstarted, 1, memory_order_relaxed);
  }
  pthread_mutex_unlock(&g_gc_start_lock);
}

bool gc_has_unstarted(void) {
  return atomic_load_explicit(&g_gc_unstarted, memory_order_relaxed) != 0;
}

size_t zdir_gc_queued(void) {
  size_t n = 0;
  pthread_mutex_lock(&g_gc_lock);
  for (const zone_db_snapshot_t *q = g_gc_head; q; q = q->gc_next) n++;
  pthread_mutex_unlock(&g_gc_lock);
  return n;
}

void *gc_snapshot_thread(void *arg) {
  zone_db_snapshot_t *snap = (zone_db_snapshot_t *)arg;
  if (!snap) return NULL;
  // タイムアウトしても解放しない (まだ読んでいるリーダーがいる)。待機関数が停滞を syslog に出す。
  while (!rcu_writer_wait_until_safe(snap->retire_epoch, 60000)) {
  }
  int retries = 0;
  useconds_t sleep_time = 1;
  while (atomic_load_explicit(&snap->reader_count, memory_order_acquire) > 0) {
    rcu_exponential_backoff(&retries, &sleep_time);
    /* 期限は設けない (参照を持つ読み手がいる限り解放できない) が、長引いたら記録する (wait_until_safe と同じ間隔) */
    if (sleep_time >= 100000 && (retries % 10) == 0)
      syslog(LOG_WARNING, "[GC] snapshot %p still has %d reader(s) after %d waits; not freed yet", (void *)snap,
             (int)atomic_load_explicit(&snap->reader_count, memory_order_relaxed), retries);
  }
  free_zone_db_snapshot(snap);
  atomic_fetch_sub_explicit(&g_gc_live, 1, memory_order_release);
  return NULL;
}

static char *server_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
    int fd = open_via_dir_cache(rel_path, O_RDONLY | O_NOFOLLOW, 0, false);
    if (fd < 0) {
        return NULL;
    }
    
    if (out_dev || out_ino) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (out_dev) *out_dev = st.st_dev;
            if (out_ino) *out_ino = st.st_ino;
        } else {
            close(fd);
            return NULL; // fstat failed, fail-closed
        }
    }

    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0 || len > KARIDNS_MAX_CONFIG_FILE_SIZE) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_len = fread(buf, 1, len, f);
    buf[read_len] = '\0';
    fclose(f);
    return buf;
}

#define MAX_PRELINK_TARGETS 256 /* the image's NAME_GLUE flag uses the same number (IMG_MAX_PRELINK_TARGETS) */

/* 公開の通し番号 (zone_publish が増やす)。兄弟ゾーンを調べた時点と、兄弟ゾーンの公開の前後を比べる */
static _Atomic uint64_t g_publish_counter;

/* グルーの対象名 (src の NS/MX/SRV の対象) について、view で引けるゾーンを調べる。自分以外の
 * ゾーン (または無し) になる名前を、そのゾーンの id (無ければ 0) とともに targets / ids に入れ、
 * 見つかった兄弟ゾーンに glue_provider の印を付ける。読み取り区間の中で呼ぶ。 */
static void glue_lookup_siblings(const char *zone_domain, view_snapshot_t *view, const char **targets,
                                 uint64_t *ids, int count) {
  for (int k = 0; k < count; k++) {
    zone_db_entry_t *s = view ? find_zone_in_view(view, targets[k]) : NULL;
    if (s && domain_names_match_ci(s->domain, zone_domain)) s = NULL;
    if (s) atomic_store_explicit(&s->glue_provider, true, memory_order_relaxed);
    ids[k] = s ? s->id : 0;
  }
}

/* 公開前の版 (zone_image_freeze() の後) に、兄弟ゾーンのグルーの追跡情報を作る。Additional のグルーの
 * 実体はイメージにある (自分のアドレスは NAME_GLUE の印、兄弟のアドレスは応答のたびに兄弟から引く:
 * append_glue_records の 3.)。ここで作るのは、NS/MX/SRV の対象名のうち兄弟ゾーンにありうるものと、そのとき引けた
 * 兄弟の id だけ (S2: 兄弟が変わったらこのゾーンの応答の版を上げる)。兄弟ゾーンを引くので、呼び出し側は
 * 読み取り区間に入れる。対象名は先頭の MAX_PRELINK_TARGETS 個 (ファイルの順、重複を除く) で、additional-from-auth yes
 * のときだけ追跡する。 */
void zone_glue_track_build(zone_version_t *ver, const char *zone_domain, view_snapshot_t *view,
                           additional_from_auth_t policy) {
  if (!ver) return;
  if (ver->glue) ver->bytes -= ver->glue->bytes;     /* (the block the version had) */
  free(ver->glue);
  ver->glue = NULL;
  const zone_image_t *img = ver->image;
  if (!img || img->n_rrs == 0 || !zone_domain || policy != ADDITIONAL_AUTH_YES) return;

  char tmp[DNS_NAME_TEXT_SIZE];
  char *pool = NULL;
  size_t pool_len = 0, pool_cap = 0;
  uint32_t offs[MAX_PRELINK_TARGETS];
  int n = 0;
  for (uint32_t seq = 0; seq < img->n_rrs && n < MAX_PRELINK_TARGETS; seq++) {
    uint32_t k = zone_image_seq_rr(img, seq);
    uint16_t t = zone_image_rr_type(img, k);
    if (t != 2 && t != 15 && t != 33) continue;
    if (zone_image_rrs(img)[k].flags & ZONE_IMAGE_RR_RAW) continue; /* 生の RDATA に対象名の文字列は無い */
    if (zone_image_rr_target(img, k, tmp, sizeof(tmp)) != 0 || tmp[0] == '\0') continue;
    bool dup = false;
    for (int j = 0; j < n && !dup; j++) dup = domain_names_match_ci(pool + offs[j], tmp);
    if (dup) continue;
    size_t l = strlen(tmp) + 1;
    if (pool_len + l > pool_cap) {
      size_t nc = pool_cap ? pool_cap * 2 : 256;
      while (nc < pool_len + l) nc *= 2;
      char *np = realloc(pool, nc);
      if (!np) { free(pool); return; }
      pool = np;
      pool_cap = nc;
    }
    memcpy(pool + pool_len, tmp, l);
    offs[n++] = (uint32_t)pool_len;
    pool_len += l;
  }
  if (n > 0) {
    size_t head = (sizeof(zone_glue_t) + 7) & ~(size_t)7;
    size_t gbytes = head + (size_t)n * sizeof(uint64_t) + (size_t)n * sizeof(char *) + pool_len;
    zone_glue_t *g = malloc(gbytes);
    if (g) {
      g->bytes = gbytes;
      g->built_at = atomic_load_explicit(&g_publish_counter, memory_order_seq_cst);
      g->count = n;
      g->ids = (uint64_t *)(void *)((char *)g + head);
      g->targets = (const char **)(void *)(g->ids + n);
      char *strs = (char *)(g->targets + n);
      memcpy(strs, pool, pool_len);
      for (int k = 0; k < n; k++) g->targets[k] = strs + offs[k];
      glue_lookup_siblings(zone_domain, view, g->targets, g->ids, n);
      ver->glue = g;
      ver->bytes += gbytes;                              /* D1a (8.1): the glue is part of what the version holds */
    }
  }
  free(pool);
}

/* ---- S2: 解放待ちの版、公開、兄弟ゾーンの変更の反映 ----
 * S5 B-3: 公開した版は 1 つずつ malloc した zone_version_t で、書き込みは新しい版を作って公開する (standby の再利用は無い)。
 * 公開で退いた版は解放待ちに積み、猶予期間の後で制御スレッド (またはまとめて読み込む再構築) が解放する。
 * 積むのは複数のスレッド (制御、転送、UPDATE のワーカー) なので lock-free のスタックにし、
 * 取り出しはスタック全体を交換して行う。 */
typedef struct zone_retire_s {
  struct zone_retire_s *next;
  zone_db_entry_t *entry; /* 参照を 1 つ持つ */
  zone_version_t *ver;    /* 公開で退いた版。NULL なら obj / free_fn の項目 (zone_retire_object()) */
  void *obj;              /* ver が NULL のときに free_fn で解放する物 (ゾーン単位の設定など) */
  void (*free_fn)(void *);
  uint64_t epoch;
} zone_retire_t;

static _Atomic(zone_retire_t *) g_zone_retire_head;
static _Atomic uint64_t g_zone_entry_id;
static _Atomic bool g_glue_dirty;

uint64_t zone_entry_next_id(void) {
  return atomic_fetch_add_explicit(&g_zone_entry_id, 1, memory_order_relaxed) + 1;
}

/* ---- D1a (design 8.1): what the published zone versions hold, in bytes.  A version records its size when it is frozen
 * (zone_version_new(): the version and its image; zone_glue_track_build(): the glue block), an IXFR difference when it is stored.  The
 * totals are per kind of zone (database zones, the others) and cover what the zones serve now (resident: the active versions and the
 * IXFR histories) and what was replaced but is not freed yet (retired: the versions on the retire stack, which a reader or a transfer
 * can still hold).  Nothing limits them yet; karictl status / dbstatus show them. ---- */
static _Atomic int64_t g_zbytes_resident[ZBYTES_CLASSES], g_zbytes_retired[ZBYTES_CLASSES];

int zone_bytes_class(const zone_db_entry_t *e) {
  return e->source == ZONE_SRC_DB ? ZBYTES_DB : ZBYTES_OTHER;
}

void zone_bytes_resident_add(int cls, int64_t delta) {
  atomic_fetch_add_explicit(&g_zbytes_resident[cls], delta, memory_order_relaxed);
}

static void zone_bytes_retired_add(int cls, int64_t delta) {
  atomic_fetch_add_explicit(&g_zbytes_retired[cls], delta, memory_order_relaxed);
}

void zone_bytes_get(int cls, zone_bytes_t *out) {
  int64_t r = atomic_load_explicit(&g_zbytes_resident[cls], memory_order_relaxed);
  int64_t t = atomic_load_explicit(&g_zbytes_retired[cls], memory_order_relaxed);
  out->resident = r > 0 ? (uint64_t)r : 0;
  out->retired = t > 0 ? (uint64_t)t : 0;
}

static void zone_retire_push(zone_retire_t *r) {
  zone_retire_t *h = atomic_load_explicit(&g_zone_retire_head, memory_order_relaxed);
  do {
    r->next = h;
  } while (!atomic_compare_exchange_weak_explicit(&g_zone_retire_head, &h, r, memory_order_release,
                                                  memory_order_relaxed));
}

static void zone_entry_unref(zone_db_entry_t *e) {
  if (atomic_fetch_sub_explicit(&e->snapshot_refs, 1, memory_order_acq_rel) == 1) free_zone_db_entry(e);
}

/* 解放待ちを処理する。wait なら最も新しい世代まで猶予期間を待つ (再構築の途中でまとめて解放する)。
 * 読み取り区間の外から呼ぶこと。まだ解放できないもの (読み手、転送中、writer が使用中) は積み直す。 */
void zone_retire_process(bool wait) {
  zone_retire_t *list = atomic_exchange_explicit(&g_zone_retire_head, NULL, memory_order_acquire);
  if (!list) return;
  uint64_t max_epoch = 0;
  for (zone_retire_t *r = list; r; r = r->next) {
    if (r->epoch > max_epoch) max_epoch = r->epoch;
  }
  bool all_safe = wait ? rcu_writer_wait_until_safe(max_epoch, 60000) : rcu_writer_is_safe(max_epoch);
  while (list) {
    zone_retire_t *r = list;
    list = r->next;
    zone_db_entry_t *e = r->entry;
    if (!all_safe && !rcu_writer_is_safe(r->epoch)) {
      zone_retire_push(r);
      continue;
    }
    /* 送信中の AXFR と受信中の転送は、開始時の版を読み取り区間の外で使い続ける */
    if (atomic_load_explicit(&e->active_axfr, memory_order_acquire) > 0 ||
        atomic_load_explicit(&e->is_transferring, memory_order_acquire)) {
      zone_retire_push(r);
      continue;
    }
    if (r->ver) {
      zone_bytes_retired_add(zone_bytes_class(e), -(int64_t)r->ver->bytes);     /* freed now: no longer retired */
      zone_version_free(r->ver);
    } else {
      r->free_fn(r->obj);
    }
    zone_entry_unref(e);
    free(r);
  }
}

/* entry に属する物 obj を、世代 epoch の猶予期間が過ぎ、かつ entry が AXFR の送信中でも転送の受信中でもなくなってから
 * free_fn(obj) で解放する (退いた版と同じ解放待ちの積み方、同じ条件)。epoch は obj を読み手から外した公開 (rcu_writer_publish()) が
 * 返した世代。積むのは複数のスレッドから呼べる。成功すると entry の参照を 1 つ持ち、解放のときに手放す。
 * 戻り値 true なら以後の解放は zone_retire_process() が行う。false は積めなかった (メモリ不足) ことを示し、
 * obj は呼び出し側に残る (解放も参照も行っていない)。 */
bool zone_retire_object(zone_db_entry_t *entry, void *obj, void (*free_fn)(void *), uint64_t epoch) {
  if (!entry || !obj || !free_fn) return false;
  zone_retire_t *r = calloc(1, sizeof(*r));
  if (!r) return false;
  atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_relaxed);
  r->entry = entry;
  r->obj = obj;
  r->free_fn = free_fn;
  r->epoch = epoch;
  zone_retire_push(r);
  return true;
}

/* next を公開する。entry->writer_lock を持って呼ぶ (S2)。退いた版は解放待ちに積む (S5 B-3: 版は heap のものだけ。
 * 空の版とテストが自分で持つ版は積まない)。他のゾーンのグルーに使われているゾーン、または初めて公開するゾーン
 * なら、制御スレッドに依存するゾーンの応答の版の更新を頼む。 */
void zone_publish(zone_db_entry_t *entry, zone_version_t *next) {
  zone_version_t *old = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  /* B9a: a version with ALIAS RRs appears, changes or goes: the resolver thread looks for the targets again.  Read before the publish: the old version is retired by it. */
  bool alias_touch = (next && next->image && (next->image->flags & ZONE_IMAGE_F_ALIAS)) || (old && old->image && (old->image->flags & ZONE_IMAGE_F_ALIAS));
  bool first = atomic_load_explicit(&entry->publish_order, memory_order_relaxed) == 0;
  uint64_t epoch = rcu_writer_publish(&entry->rcu.active, next);
  atomic_store_explicit(&entry->publish_order,
                        atomic_fetch_add_explicit(&g_publish_counter, 1, memory_order_seq_cst) + 1,
                        memory_order_seq_cst);
  int zb = zone_bytes_class(entry);
  if (next && next->heap && !next->counted) {            /* D1a (8.1): the new version is resident ... */
    next->counted = true;
    zone_bytes_resident_add(zb, (int64_t)next->bytes);
  }
  if (old != next && old->counted) {                     /* ... and the one it replaced is not (retired, if it is kept) */
    old->counted = false;
    zone_bytes_resident_add(zb, -(int64_t)old->bytes);
  }
  if (old != next && old->heap) {
    zone_retire_t *r = calloc(1, sizeof(*r));
    if (r) {
      atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_relaxed);
      r->entry = entry;
      r->ver = old;
      r->epoch = epoch;
      zone_bytes_retired_add(zb, (int64_t)old->bytes);   /* until zone_retire_process() frees it */
      zone_retire_push(r);
    } else if (!atomic_load_explicit(&entry->active_axfr, memory_order_acquire) &&
               !atomic_load_explicit(&entry->is_transferring, memory_order_acquire) &&
               rcu_writer_wait_until_safe_in_reader(epoch, 60000)) {
      zone_version_free(old); /* 積めないときは、ここで猶予期間を待って解放する */
    } else {
      zone_bytes_retired_add(zb, (int64_t)old->bytes);   /* leaked: it stays counted */
      syslog(LOG_ERR, "[Zone] zone '%s': out of memory retiring the previous version; it is leaked", entry->domain);
    }
  }
  if (first || atomic_load_explicit(&entry->glue_provider, memory_order_relaxed))
    atomic_store_explicit(&g_glue_dirty, true, memory_order_release);
  if (alias_touch)
    alias_notify();
}

typedef struct {
  zone_db_entry_t *entry;
  view_snapshot_t *view;
} glue_todo_t;

/* 兄弟ゾーンが変わった (公開された、追加・削除された) ゾーンの応答の版を上げる。兄弟のアドレスは
 * 応答のたびに兄弟から引くので、データは作り直さない。共有の応答キャッシュに残る古い応答を引かせない
 * ためだけに版を上げ、兄弟の id と調べた時点を記録し直す (メモリは確保しない)。
 * 制御スレッドから (起動時はメインスレッドから)、読み取り区間の外で呼ぶ。glue->ids と
 * glue->built_at を公開後に書くのはこの関数だけ。force でなければ、グルーに関わる公開があったときだけ調べる。 */
void zone_glue_refresh_dependents(bool force) {
  if (!atomic_exchange_explicit(&g_glue_dirty, false, memory_order_acq_rel) && !force) return;
  zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
  if (!snap) return;
  glue_todo_t *todo = NULL;
  size_t n = 0, cap = 0;
  bool oom = false;
  burst_yield_t by = BURST_YIELD_INIT;
  for (size_t v = 0; v < snap->view_count && !oom; v++) {
    view_snapshot_t *view = &snap->views[v];
    rcu_aux_read_lock();
    zdir_iter_t zit;
    zdir_iter_init(&zit, view);
    for (zdir_elem_t *zel; (zel = zdir_iter_next(&zit));) {
      zone_db_entry_t *e = zdir_entry(zel);
      if (!e || !view_owns_elem(zel)) continue;   /* a zone shared from another view is looked at in its own view */
      burst_yield(&by);
      zone_version_t *a = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
      zone_glue_t *g = a ? a->glue : NULL;
      if (!g) continue;
      bool need = false;
      for (int k = 0; k < g->count && !need; k++) {
        zone_db_entry_t *s = find_zone_in_view(view, g->targets[k]);
        if (s && domain_names_match_ci(s->domain, e->domain)) s = NULL;
        need = (s ? s->id : 0) != g->ids[k] ||
               (s && atomic_load_explicit(&s->publish_order, memory_order_seq_cst) > g->built_at);
      }
      if (!need) continue;
      if (n == cap) {
        size_t ncap = cap ? cap * 2 : 64;
        glue_todo_t *t = realloc(todo, ncap * sizeof(*t));
        if (!t) {
          oom = true;
          break;
        }
        todo = t;
        cap = ncap;
      }
      todo[n].entry = e;
      todo[n].view = view;
      n++;
    }
    rcu_aux_read_unlock();
  }
  if (oom) atomic_store_explicit(&g_glue_dirty, true, memory_order_release); /* 次の周期でやり直す */
  for (size_t i = 0; i < n; i++) {
    zone_db_entry_t *e = todo[i].entry;
    /* writer は公開の前に glue を作る。その途中の arena は active ではないが、公開と
     * 入れ違わないように writer_lock の下で active を読み直す */
    pthread_mutex_lock(&e->writer_lock);
    zone_version_t *a = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
    if (a && a->glue) {
      a->glue->built_at = atomic_load_explicit(&g_publish_counter, memory_order_seq_cst);
      rcu_aux_read_lock();
      glue_lookup_siblings(e->domain, todo[i].view, a->glue->targets, a->glue->ids, a->glue->count);
      rcu_aux_read_unlock();
      atomic_store_explicit(&a->generation, zone_data_generation_next(), memory_order_release);
    }
    pthread_mutex_unlock(&e->writer_lock);
  }
  free(todo);
  release_zone_snapshot(snap);
}

/* ゾーン外レコードのログ。1回の読み込みで出す行数を制限し、残りは件数だけにする。 */
#define OUT_OF_ZONE_LOG_MAX 10
typedef struct {
  const char *zone;
  size_t logged;
} out_of_zone_log_t;

static void log_out_of_zone_record(const dns_record_t *rec, void *ud) {
  out_of_zone_log_t *l = ud;
  if (l->logged >= OUT_OF_ZONE_LOG_MAX) return;
  l->logged++;
  syslog(LOG_WARNING, "[Zone] zone '%s': ignoring out-of-zone data '%s' %s", l->zone,
         rec->name ? rec->name : "", rec->type ? rec->type : "");
}

static void log_unencodable_record(const dns_record_t *rec, void *ud) {
  out_of_zone_log_t *l = ud;
  if (l->logged >= OUT_OF_ZONE_LOG_MAX) return;
  l->logged++;
  syslog(LOG_WARNING, "[Zone] zone '%s': ignoring record '%s' %s: its RDATA cannot be encoded "
         "(karicheck shows the reason)", l->zone, rec->name ? rec->name : "", rec->type ? rec->type : "");
}

/* X-32, S5 B-2: 書けないレコードを 1 件ずつ除き (警告は 1 回に OUT_OF_ZONE_LOG_MAX 行まで、残りは件数)、残りで続ける。
 * ゾーンファイルの読み込みも、AXFR/IXFR で受けたゾーンも、UPDATE を当てたゾーンも同じ扱い (公開するイメージには
 * serialize_dns_record() で書けないレコードを入れられない)。build_zone_index() の前に呼ぶ。除いた件数を返す。 */
size_t zone_drop_unencodable_logged(zone_arena_t *a, const char *zone, const char *from) {
  out_of_zone_log_t bad = { zone, 0 };
  size_t bad_count = zone_arena_drop_unencodable(a, log_unencodable_record, &bad);
  if (bad_count > 0)
    syslog(LOG_WARNING, "[Zone] zone '%s': ignored %zu record(s) that cannot be encoded from %s", zone, bad_count, from);
  return bad_count;
}

/* Does the configuration of the view have a zone of this name: a zone { } block, or a zone it shares with an earlier view (zone { in-view }) */
static bool view_cfg_has(const view_config_t *v, const char *name) {
  return view_find_zone_config(v, name) != NULL || view_find_in_view(v, name) != NULL;
}

/* parse_context_t.zone_exists: name が view (ud) のゾーンの頂点か */
static bool view_has_zone(const void *ud, const char *name) {
  return view_cfg_has((const view_config_t *)ud, name);
}

reload_result_t reload_master_zone(zone_db_entry_t *entry, zone_config_t *zcfg) {
  if (!entry || !zcfg || !zcfg->file) return RELOAD_ERR_FILE_READ;
  const char *file = zcfg->file;
  struct stat root_st;
  char *buf = read_entire_file_stat(file, &root_st);
  dev_t root_dev = root_st.st_dev;
  ino_t root_ino = root_st.st_ino;
  if (!buf) {
    syslog(LOG_ERR, "[Zone] Failed to read file '%s' for zone '%s'.", file, entry->domain);
    return RELOAD_ERR_FILE_READ;
  }
  pthread_mutex_lock(&entry->writer_lock);
  if (!wait_for_active_axfr(entry, 5000)) {
    syslog(LOG_WARNING, "[Zone] Reload of zone '%s' postponed: active AXFR in progress (timeout 5s).", entry->domain);
    free(buf);
    pthread_mutex_unlock(&entry->writer_lock);
    return RELOAD_ERR_BUSY;
  }
  zone_version_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  /* S5 B-3: the zone is built in a builder of its own (freed on every way out) and published as a new version */
  zone_arena_t z_builder;
  zone_arena_t *z_standby = &z_builder;
  zone_arena_init(z_standby);
  /* R-21: 読み込み済みのゾーンの版が変わったら NOTIFY を送る (起動時の最初の読み込みでは送らない) */
  bool was_loaded = z_active->image && z_active->image->n_rrs > 0;
  uint32_t old_serial = entry->serial, old_refresh = entry->refresh, old_retry = entry->retry, old_expire = entry->expire;

  /* S4: 小さいゾーンに 64 KiB の最初のプールを持たせない。プールの使用量 (レコードのワイヤー形式の
   * 前処理など) はゾーンファイルの 0.6-1.2 倍ほど。足りなければ半分の大きさで足す (arena_alloc) */
  size_t pool_cap = (size_t)root_st.st_size + 256;
  if (pool_cap < 1024) pool_cap = 1024;
  if (pool_cap > 64 * 1024) pool_cap = 64 * 1024;
  z_standby->first_pool_cap = pool_cap;
  char *root_file_path = strdup(file);
  if (!root_file_path || zone_arena_add_file(z_standby, buf, NULL, root_file_path) != 0) {
    free(root_file_path);
    free(buf);
    zone_arena_destroy(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Out of memory reloading zone '%s'", entry->domain);
    return RELOAD_ERR_PARSE;
  }

  char *root_ttl = NULL;
  char *root_ecs_tag = NULL;
  char *root_loc_tag = NULL;
  char *visited_paths[16];
  dev_t visited_devs[16];
  ino_t visited_inos[16];
  
  char abs_file[PATH_MAX];
  if (file[0] != '/' && g_startup_cwd[0] != '\0') {
      snprintf(abs_file, sizeof(abs_file), "%s/%s", g_startup_cwd, file);
  } else {
      snprintf(abs_file, sizeof(abs_file), "%s", file);
  }
  
  char *root_path = strdup(abs_file);

  parse_error_t parse_err = {0};
  parse_context_t ctx = {0};
  ctx.default_origin = entry->domain;
  ctx.base_dir = get_base_dir(root_path);
  if (!ctx.base_dir) {
      syslog(LOG_ERR, "[ZoneLoader] Out of memory allocating base_dir for zone '%s'", entry->domain);
      free(root_path);
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      return RELOAD_ERR_PARSE;
  }
  ctx.is_standalone_mode = false;
  ctx.load_file_cb = server_load_file_cb;
  ctx.shared_ttl_io = &root_ttl;
  ctx.shared_ecs_tag_io = &root_ecs_tag;
  ctx.shared_loc_tag_io = &root_loc_tag;
  ctx.visited_paths = visited_paths;
  ctx.visited_devs = visited_devs;
  ctx.visited_inos = visited_inos;
  ctx.visited_cap = 16;
  ctx.visited_count = 1;
  ctx.visited_paths[0] = root_path;
  ctx.visited_devs[0] = root_dev;
  ctx.visited_inos[0] = root_ino;
  ctx.err_out = &parse_err;
  ctx.source_mtime = root_st.st_mtime; // X-13: tinydns の SOA serial。パーサはパスを stat しない

  server_config_t *active_cfg = acquire_config_snapshot();
  /* options { directory }: a relative $INCLUDE is read from it, and the tree below it is one of the two ranges an $INCLUDE may lie in
   * (the other is the directory of the zone file).  Both were opened at startup; they are registered as roots so that a directory
   * below them that a reload brings in can still be opened in capability mode. */
  char dir_abs[PATH_MAX];
  if (active_cfg && active_cfg->directory && active_cfg->directory[0]) {
      if (active_cfg->directory[0] != '/' && g_startup_cwd[0] != '\0')
          snprintf(dir_abs, sizeof(dir_abs), "%s/%s", g_startup_cwd, active_cfg->directory);
      else
          snprintf(dir_abs, sizeof(dir_abs), "%s", active_cfg->directory);
      ctx.directory = dir_abs;
      (void)dir_fd_cache_add_root(dir_abs);
  }
  (void)dir_fd_cache_add_root(ctx.base_dir);
  // 親子ゾーンの振り分けに使うのは、このゾーンと同じ view のゾーンだけ (R-26)。
  // 別の view にしか無い子ゾーンの名前で、この view のレコードを落とさない。
  view_config_t *own_view = NULL;
  if (active_cfg) {
      for (view_config_t *v = active_cfg->views; v; v = v->next) {
          if (v->name && strcasecmp(v->name, entry->view_name) == 0) { own_view = v; break; }
      }
  }
  /* view の全ゾーン名の配列をゾーンごとに作ると、読み込み全体がゾーン数の 2 乗になる。
   * tinydns パーサには view の索引を引かせる (O-11 と同じく、view の全ゾーンが対象)。 */
  if (own_view) {
      ctx.zone_exists = view_has_zone;
      ctx.zone_exists_ud = own_view;
  }

  int count;
  if (zext(zcfg)->file_format && strcasecmp(zext(zcfg)->file_format, "tinydns") == 0) {
      count = parse_tinydns_data(buf, strlen(buf), z_standby, &ctx);
  } else {
      count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
  }
  zone_limits_t limits;   /* max-records, max-records-per-type, max-types-per-name, max-zone-ttl (batch 7) */
  zone_limits_effective(active_cfg, zcfg, entry->view_name, &limits);
  release_config_snapshot(active_cfg);
  free((void*)ctx.base_dir);
  free(root_path);

  if (count >= 0 && ctx.no_ttl_count > 0)
      syslog(LOG_WARNING, "[Zone] zone '%s' (%s): %s:%zu: no TTL specified for '%s' (no $TTL, no earlier TTL, no SOA to take one from); "
             "%zu record(s) are served with 3600; BIND rejects such a zone", entry->domain, file,
             ctx.first_no_ttl_file ? ctx.first_no_ttl_file : file, ctx.first_no_ttl_line,
             ctx.first_no_ttl_owner ? ctx.first_no_ttl_owner : "", ctx.no_ttl_count);
  if (count < 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      if (parse_err.error_message) {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s': %s (offset=%zu, file=%s)",
                 entry->domain, file, parse_err.error_message,
                 parse_err.error_offset,
                 parse_err.file_path ? parse_err.file_path : file);
      } else {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s'", entry->domain, file);
      }
      return RELOAD_ERR_PARSE;
  }

  // R-27: ゾーン外のデータは読み込まない (BIND と同じく警告して無視する)
  out_of_zone_log_t ooz = { entry->domain, 0 };
  size_t ooz_count = zone_arena_drop_out_of_zone(z_standby, entry->domain, log_out_of_zone_record, &ooz);
  if (ooz_count > 0) {
      syslog(LOG_WARNING, "[Zone] zone '%s': ignored %zu out-of-zone record(s) from '%s'",
             entry->domain, ooz_count, file);
  }
  if (ctx.out_of_zone_count > 0) {
      syslog(LOG_WARNING, "[Zone] zone '%s': ignored %zu tinydns record(s) that belong to no configured zone "
             "in view '%s' (first: '%s') in '%s'", entry->domain, ctx.out_of_zone_count, entry->view_name,
             ctx.first_out_of_zone ? ctx.first_out_of_zone : "", file);
  }
  /* X-32: 書けないレコードはその 1 件だけ警告して除く (応答や AXFR で他のレコードを巻き込まない) */
  {
      char from[PATH_MAX + 8];
      snprintf(from, sizeof(from), "'%s'", file);
      zone_drop_unencodable_logged(z_standby, entry->domain, from);
  }

  zone_arena_shrink_records(z_standby);
  if (build_zone_index(z_standby, true) != 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after reload for '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_dname(z_standby, &parse_err) < 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] DNAME validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_name_lengths(z_standby, &parse_err) < 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Name length validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  /* batch 7: max-records, max-records-per-type, max-types-per-name, max-zone-ttl.  BIND fails the load of a zone that breaks one of them
   * (lib/dns/zone.c, master.c); the version in service stays. */
  {
      char lim_err[320];
      if (zone_arena_check_limits(z_standby, &limits, lim_err, sizeof(lim_err)) < 0) {
          zone_arena_destroy(z_standby);
          pthread_mutex_unlock(&entry->writer_lock);
          syslog(LOG_ERR, "[Zone] zone '%s' not loaded from '%s': %s", entry->domain, file, lim_err);
          return RELOAD_ERR_PARSE;
      }
  }
  /* B8t-1: the zone-wide values (serial, refresh, retry, expire) come from the reference SOA (the SOA without location, time stamp
   * or tag if there is one, else the first). All SOA RRs of the zone must have the same serial; a zone that breaks this is not
   * loaded, the version in service stays. */
  bool has_soa = false;
  {
      char soa_err[320];
      if (zone_arena_check_soa_set(z_standby, entry->domain, soa_err, sizeof(soa_err)) < 0) {
          zone_arena_destroy(z_standby);
          pthread_mutex_unlock(&entry->writer_lock);
          syslog(LOG_ERR, "[Zone] zone '%s' not loaded from '%s': %s", entry->domain, file, soa_err);
          return RELOAD_ERR_PARSE;
      }
      const dns_record_t *ref = zone_arena_reference_soa(z_standby, entry->domain);
      if (ref) {
          has_soa = true;
          entry->serial = strtoul(ref->rdata[2], NULL, 10);
          entry->refresh = parse_ttl_value(ref->rdata[3]);
          entry->retry = parse_ttl_value(ref->rdata[4]);
          entry->expire = parse_ttl_value(ref->rdata[5]);
      }
  }
  if (!has_soa) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Missing SOA reloading zone '%s' from '%s'", entry->domain, file);
      return RELOAD_ERR_MISSING_SOA;
  }

  /* S5 B-1: 応答を作る側が読むイメージ。公開の直前に 1 回だけ作る (クエリの経路では作らない) */
  z_standby->image = zone_image_freeze(z_standby, entry->domain);
  if (!z_standby->image) {
      /* a zone that is not published keeps its serial and timers (the values above were taken from the new file) */
      entry->serial = old_serial; entry->refresh = old_refresh; entry->retry = old_retry; entry->expire = old_expire;
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Failed to build the zone image after reload for '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }

  /* S5 B-2: 公開するのはイメージだけ。レコード・プール・索引・ゾーンファイルの本文はここで解放する。
   * S5 B-3: イメージは新しい版 (zone_version_t) に移る */
  zone_arena_free_builder(z_standby);
  zone_version_t *z_next = zone_version_new(z_standby);
  zone_arena_destroy(z_standby);
  if (!z_next) {
      entry->serial = old_serial; entry->refresh = old_refresh; entry->retry = old_retry; entry->expire = old_expire;
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Out of memory publishing the reloaded zone '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }

  // グルーの追跡は他ゾーンの active arena を読むので、読み取り区間で他の writer の再利用から守る
  rcu_aux_read_lock();
  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  server_config_t *active_cfg_prelink = acquire_config_snapshot();
  additional_from_auth_t policy = (zcfg && zext(zcfg)->additional_from_auth_specified)
                                      ? zext(zcfg)->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  zone_glue_track_build(z_next, entry->domain, snapshot_find_view(cur_snap, entry->view_name), policy);
  build_zone_response_cache(z_next, active_cfg_prelink, entry);
  release_config_snapshot(active_cfg_prelink);
  rcu_aux_read_unlock();

  compute_ixfr_diff(entry, z_active, z_next);
  zone_publish(entry, z_next);
  struct stat st_loaded;
  if (stat_via_dir_cache(file, &st_loaded) == 0) {
    entry->last_loaded_mtime = st_loaded.st_mtime;
    entry->last_loaded_size = st_loaded.st_size;
    if (entry->is_secondary) {
      atomic_store_explicit(&entry->last_successful_transfer, (time_t)st_loaded.st_mtime, memory_order_release);
    }
  }
  pthread_mutex_unlock(&entry->writer_lock);
  syslog(LOG_NOTICE, "[Zone] Reload successful for '%s'", entry->domain);
  // RFC 1996 §4.5: プライマリのゾーンが変わったらセカンダリへ通知する
  if (was_loaded && !entry->is_secondary && entry->serial != old_serial) notify_request_send(entry);
  return RELOAD_OK;
}

STATIC_TEST void abort_rebuild_snapshot(zone_db_snapshot_t *new_snap, const char *reason) {
    syslog(LOG_ERR, "[Core] Memory allocation failed during snapshot rebuild (%s), aborting", reason);
    if (new_snap) {
        free_zone_db_snapshot(new_snap);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

/* R-28, RFC 9432 §5.4: カタログメンバーの同一性は (メンバーゾーン名, メンバーノードのラベル) だけで決まる。
 * group (§4.3.2) は設定の選び分けにしか使わないので比較に含めない。ht/chain/hsize は
 * calc_catalog_member_hash() で作ったハッシュ表 (作れなかったときは NULL で線形探索)。 */
static int catalog_member_index(const catalog_member_id_t *list, int count, const int *ht, const int *chain,
                                size_t hsize, const char *domain, const char *unique_id) {
    if (ht && chain) {
        size_t idx = calc_catalog_member_hash(domain, unique_id) & (hsize - 1);
        for (int j = ht[idx]; j != -1; j = chain[j]) {
            if (strcasecmp(domain, list[j].domain) == 0 && strcmp(unique_id, list[j].unique_id) == 0) return j;
        }
        return -1;
    }
    for (int j = 0; j < count; j++) {
        if (strcasecmp(domain, list[j].domain) == 0 && strcmp(unique_id, list[j].unique_id) == 0) return j;
    }
    return -1;
}

/* catalog_member_index() 用のハッシュ表を作る。作れなければ *ht / *chain は NULL のまま
 * (catalog_member_index() は線形探索になる)。呼び出し側が free() する。 */
static void catalog_member_hash_build(const catalog_member_id_t *list, int count,
                                      int **ht, int **chain, size_t *hsize) {
    *ht = NULL;
    *chain = NULL;
    *hsize = 0;
    if (!list || count <= 0) return;
    size_t p = 256;
    while (p < (size_t)count * 2) p <<= 1;
    int *t = malloc(p * sizeof(int));
    int *c = malloc((size_t)count * sizeof(int));
    if (!t || !c) {
        free(t);
        free(c);
        return;
    }
    for (size_t k = 0; k < p; k++) t[k] = -1;
    for (int j = 0; j < count; j++) {
        size_t idx = calc_catalog_member_hash(list[j].domain, list[j].unique_id) & (p - 1);
        c[j] = t[idx];
        t[idx] = j;
    }
    *ht = t;
    *chain = c;
    *hsize = p;
}

static bool catalog_groups_equal(const catalog_member_id_t *a, const catalog_member_id_t *b) {
    if (a->group_count != b->group_count) return false;
    for (int k = 0; k < a->group_count; k++) {
        if (strcmp(a->groups[k], b->groups[k]) != 0) return false;
    }
    return true;
}

/* メンバーのゾーンエントリの group をその場で置き換える (エントリと転送の状態はそのまま)。
 * entry->groups を読むのは解放だけで、書き手はスナップショットを作り直すこのスレッドだけ。 */
static void catalog_entry_set_groups(zone_db_entry_t *entry, const catalog_member_id_t *m) {
    if (entry->groups) {
        for (int g = 0; g < entry->group_count; g++) free(entry->groups[g]);
        free(entry->groups);
        entry->groups = NULL;
    }
    entry->group_count = 0;
    if (m->group_count <= 0) return;
    entry->groups = calloc(m->group_count, sizeof(char *));
    if (!entry->groups) return;
    for (int g = 0; g < m->group_count; g++) {
        entry->groups[g] = strdup(m->groups[g]);
        if (!entry->groups[g]) break;
        entry->group_count = g + 1;
    }
}
/* ------------------------------------------------------------------------------------------------------------- */
/* DB zone registry and view delta (beta design 4.2, 4.4, 4.5; D1a: the registry's elements are the directory's)  */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    char name[KARIDNS_VIEW_NAME_MAX];
    zdir_elem_t **tab;                  /* hash chains by zdir_name_hash(), nb is a power of two */
    size_t nb, count;
    zdir_elem_t **adds;                 /* elements that should enter the index (ZDIR_F_QUEUED) */
    size_t n_adds, cap_adds;
    zdir_elem_t **removes;              /* elements that left the registry and should leave the index (ZDIR_F_DELETED) */
    size_t n_removes, cap_removes;
    zdir_gent_t *repl;                  /* entries that a new entry replaced (they carry the registry's reference); the element stayed */
    size_t n_repl;
} dbreg_view_t;

#define DBREG_QUEUE_KEEP 1024   /* a queue that grew beyond this many slots is given back when it is empty again */

/* all of it is protected by g_zone_db_rebuild_lock */
static dbreg_view_t *g_dbreg_views;
static size_t g_dbreg_nviews, g_dbreg_capviews, g_dbreg_hint;
static _Atomic size_t g_dbreg_pending;
/* the registry was dropped under the snapshot (dbreg_reset(), unit tests): the next full rebuild must read the registry */
static bool g_dbreg_force_full;

static dbreg_view_t *dbreg_view_get(const char *name, bool create) {
    size_t n = g_dbreg_nviews;
    if (n && g_dbreg_hint < n && strcasecmp(g_dbreg_views[g_dbreg_hint].name, name) == 0)
        return &g_dbreg_views[g_dbreg_hint];
    for (size_t i = 0; i < n; i++) {
        if (strcasecmp(g_dbreg_views[i].name, name) == 0) {
            g_dbreg_hint = i;
            return &g_dbreg_views[i];
        }
    }
    if (!create) return NULL;
    if (n == g_dbreg_capviews) {
        size_t nc = n ? n * 2 : 4;
        dbreg_view_t *nv = realloc(g_dbreg_views, nc * sizeof(*nv));
        if (!nv) return NULL;
        g_dbreg_views = nv;
        g_dbreg_capviews = nc;
    }
    dbreg_view_t *v = &g_dbreg_views[n];
    memset(v, 0, sizeof(*v));
    snprintf(v->name, sizeof(v->name), "%s", name);
    g_dbreg_nviews = n + 1;
    g_dbreg_hint = n;
    return v;
}

static dbreg_zone_t *dbreg_find(const dbreg_view_t *rv, const char *name, uint32_t h) {
    if (!rv->nb) return NULL;
    for (dbreg_zone_t *z = rv->tab[h & (rv->nb - 1)]; z; z = z->next) {
        if (z->hash == h && domain_names_match_ci(z->name, name)) return z;
    }
    return NULL;
}

static dbreg_zone_t *dbreg_add(dbreg_view_t *rv, const char *name, uint32_t h) {
    if (rv->count >= rv->nb) {
        size_t nnb = rv->nb ? rv->nb * 2 : 64;
        dbreg_zone_t **nt = calloc(nnb, sizeof(*nt));
        if (!nt) return NULL;
        for (size_t i = 0; i < rv->nb; i++) {
            dbreg_zone_t *z = rv->tab[i];
            while (z) {
                dbreg_zone_t *nx = z->next;
                size_t b = z->hash & (nnb - 1);
                z->next = nt[b];
                nt[b] = z;
                z = nx;
            }
        }
        free(rv->tab);
        rv->tab = nt;
        rv->nb = nnb;
    }
    size_t l = strlen(name);
    if (l > 255) return NULL;                   /* (klen is a byte; a name has at most 255 characters in text form) */
    dbreg_zone_t *z = calloc(1, sizeof(*z) + l + 1);
    if (!z) return NULL;
    memcpy(z->name, name, l + 1);
    z->hash = h;
    z->klen = (uint8_t)zone_key_len(name);
    atomic_init(&z->state, ZDIR_ST_ABSENT);
    size_t b = h & (rv->nb - 1);
    z->next = rv->tab[b];
    rv->tab[b] = z;
    rv->count++;
    return z;
}

static void dbreg_unlink(dbreg_view_t *rv, dbreg_zone_t *z) {
    dbreg_zone_t **pp = &rv->tab[z->hash & (rv->nb - 1)];
    while (*pp && *pp != z) pp = &(*pp)->next;
    if (*pp) *pp = z->next;
    rv->count--;
}

static bool dbreg_queue_reserve(zdir_elem_t ***arr, size_t n, size_t *cap) {
    if (n < *cap) return true;
    size_t nc = *cap ? *cap * 2 : 16;
    zdir_elem_t **na = realloc(*arr, nc * sizeof(**arr));
    if (!na) return false;
    *arr = na;
    *cap = nc;
    return true;
}

/* does a zone of the configuration hide a DB zone of this name in this view? (D-PRIO: file, program, forward and
 * secondary zones all come from zone {} statements) */
static bool dbreg_config_shadows(const char *view, const char *name) {
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    bool sh = cfg && find_zone_config_in_view(cfg, view, name) != NULL;
    release_config_snapshot(cfg);
    rcu_aux_read_unlock();
    return sh;
}

static void dbreg_set_error(dbreg_zone_t *z, const char *reason) {
    free(z->error);
    z->error = reason ? strdup(reason) : NULL;
}

/* the directory of a view in the active snapshot (the active snapshot is stable while the lock is held: only lock holders replace it) */
static zdir_t *dbreg_active_dir_locked(const char *view) {
    zone_db_snapshot_t *snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    view_snapshot_t *vs = snapshot_find_view(snap, view);
    return vs ? vs->dir : NULL;
}

/* D17-1: a catalog member with the name of a DB zone wins over it on every path */
static bool dbreg_catalog_member_locked(const char *view, const char *name) {
    zone_db_entry_t *e = zdir_entry(zdir_lookup(dbreg_active_dir_locked(view), name));
    return e && e->is_catalog_member;
}

/* what the directory keeps of a zone that the entry says: state, the flags of the image, the SOA timers */
static void zdir_elem_sync(zdir_elem_t *z, zone_db_entry_t *entry) {
    zone_version_t *v = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
    const zone_image_t *img = v ? v->image : NULL;
    uint16_t f = (uint16_t)(z->flags & ~(ZDIR_F_PRESIGNED | ZDIR_F_ALIAS | ZDIR_F_WILDCARD | ZDIR_F_TICK));
    if (img) {
        if (img->flags & ZONE_IMAGE_F_ALIAS) f |= ZDIR_F_ALIAS;
        if (img->flags & ZONE_IMAGE_F_WILDCARD) f |= ZDIR_F_WILDCARD;
        if (img->n_nsec > 0 || img->n_n3chains > 0) f |= ZDIR_F_PRESIGNED;
    }
    if (zone_entry_ticks(entry)) f |= ZDIR_F_TICK;
    z->flags = f;
    atomic_store_explicit(&z->state, ZDIR_ST_RESIDENT, memory_order_release);
    z->refresh = atomic_load_explicit(&entry->refresh, memory_order_relaxed);
    z->retry = atomic_load_explicit(&entry->retry, memory_order_relaxed);
    z->expire = atomic_load_explicit(&entry->expire, memory_order_relaxed);
}

int dbreg_commit(const char *view, const char *name, zone_db_entry_t *entry, bool created, int64_t source_id,
                 uint32_t serial, const uint8_t digest[32], bool *shadowed) {
    bool sh_cfg = dbreg_config_shadows(view, name);
    int rc = -1;
    zdir_gent_t *gent = NULL;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    bool sh_cat = !sh_cfg && dbreg_catalog_member_locked(view, name);
    bool sh = sh_cfg || sh_cat;
    dbreg_view_t *rv = dbreg_view_get(view, true);
    if (!rv) goto out;
    uint32_t h = zdir_name_hash(name);
    dbreg_zone_t *z = dbreg_find(rv, name, h);
    bool fresh = false;
    if (!z) {
        if (!(z = dbreg_add(rv, name, h))) goto out;
        fresh = true;
    }
    zone_db_entry_t *cur = zdir_entry(z);
    bool replace = created && cur && cur != entry;                  /* a new entry replaces the one registered earlier */
    bool in_index = created && !fresh && zdir_lookup(dbreg_active_dir_locked(view), z->name) == z;
    bool queue_add = created && !sh && !in_index && !(z->flags & ZDIR_F_QUEUED);
    uint8_t *new_digest = NULL;                                     /* the block of the digest: a zone that has none gets one */
    if ((replace && !(gent = malloc(sizeof(*gent)))) || (queue_add && !dbreg_queue_reserve(&rv->adds, rv->n_adds, &rv->cap_adds)) ||
        (!z->digest && !(new_digest = malloc(32)))) {
        if (fresh) {
            dbreg_unlink(rv, z);
            free(z);
        }
        goto out;
    }
    if (new_digest) z->digest = new_digest;
    if (replace) {
        /* The element stays in the index and now points to the new entry (one store: a reader sees the old or the new one); the old
         * entry's reference is given back when the readers that may have it are gone, and the delta looks at it (a catalog consumer
         * that is replaced takes its members with it). */
        gent->entry = cur;
        gent->sh_old = NULL;
        gent->served = in_index;
        gent->next = rv->repl;
        rv->repl = gent;
        size_t w = in_index ? 2 : 1;                       /* (counted as the removal of the old entry and the addition of the new one, as in the queues before D1a) */
        rv->n_repl += w;
        gent = NULL;
        atomic_fetch_add_explicit(&g_dbreg_pending, w, memory_order_relaxed);
    }
    if (created) atomic_store_explicit(&z->entry, entry, memory_order_release);   /* the initial reference of the entry is the registry's */
    if (queue_add) {
        rv->adds[rv->n_adds++] = z;
        z->flags |= ZDIR_F_QUEUED;
        atomic_fetch_add_explicit(&g_dbreg_pending, 1, memory_order_relaxed);
    }
    z->source_id = source_id;
    z->serial = serial;
    memcpy(z->digest, digest, 32);
    z->last_result = DBREG_APPLIED;
    z->shadowed = sh;
    z->shadow_by = sh_cfg ? DBREG_SH_CONFIG : sh_cat ? DBREG_SH_CATALOG : DBREG_SH_NONE;
    zdir_elem_sync(z, entry);
    dbreg_set_error(z, NULL);
    rc = 0;
out:
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    free(gent);
    if (shadowed) *shadowed = sh;
    return rc;
}

/* D17-1 helpers for the catalog delta (the lock is held): the DB zone of this name is now hidden by a catalog member / is
 * hidden by one and is a candidate to come back */
static void dbreg_hide_by_catalog_locked(const char *view, const char *name) {
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, name, zdir_name_hash(name)) : NULL;
    if (z && zdir_entry(z) && !z->shadowed) {
        z->shadowed = true;
        z->shadow_by = DBREG_SH_CATALOG;
        syslog(LOG_WARNING, "[DB] zone %s from the DB is hidden by a catalog member of the same name (view '%s')", z->name, view);
    }
}

static dbreg_zone_t *dbreg_catalog_hidden_zone_locked(const char *view, const char *name) {
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, name, zdir_name_hash(name)) : NULL;
    return z && zdir_entry(z) && z->shadowed && z->shadow_by == DBREG_SH_CATALOG ? z : NULL;
}

zone_db_entry_t *dbreg_lookup_entry(const char *view, const char *name) {
    zone_db_entry_t *e = NULL;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    if (rv) {
        dbreg_zone_t *z = dbreg_find(rv, name, zdir_name_hash(name));
        if (z) e = zdir_entry(z);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return e;
}

bool dbreg_reject(const char *view, const char *name, int64_t source_id, const char *reason) {
    bool ok = false;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, true);
    if (rv) {
        uint32_t h = zdir_name_hash(name);
        dbreg_zone_t *z = dbreg_find(rv, name, h);
        if (!z) z = dbreg_add(rv, name, h);
        if (z) {
            if (!zdir_entry(z)) {
                z->source_id = source_id;
                atomic_store_explicit(&z->state, ZDIR_ST_ERROR, memory_order_release);
            }
            z->last_result = DBREG_REJECTED;
            dbreg_set_error(z, reason);
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return ok;
}

/* ---- D1a milestone 2: a fetch of a zone that is in the directory and not in memory (the ingest thread asks the loader for it) ---- */
int dbreg_fetch_begin(const char *view, const char *zone) {
    int rc = DBREG_FETCH_NONE;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, zone, zdir_name_hash(zone)) : NULL;
    if (z && !(z->flags & ZDIR_F_DELETED)) {
        if (zdir_entry(z)) {
            rc = DBREG_FETCH_RESIDENT;
        } else if (atomic_load_explicit(&z->state, memory_order_relaxed) == ZDIR_ST_LOADING) {
            rc = DBREG_FETCH_BUSY;
        } else {
            atomic_store_explicit(&z->state, ZDIR_ST_LOADING, memory_order_release);
            rc = DBREG_FETCH_STARTED;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return rc;
}

void dbreg_fetch_end(const char *view, const char *zone) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, zone, zdir_name_hash(zone)) : NULL;
    if (z && !zdir_entry(z) && atomic_load_explicit(&z->state, memory_order_relaxed) == ZDIR_ST_LOADING)
        atomic_store_explicit(&z->state, ZDIR_ST_ABSENT, memory_order_release);
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

bool dbreg_apply_summary(const char *view, const char *zone, int64_t source_id, uint32_t serial, bool has_timers, uint32_t refresh,
                         uint32_t retry, uint32_t expire) {
    bool applied = false;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, zone, zdir_name_hash(zone)) : NULL;
    if (z && !(z->flags & ZDIR_F_DELETED) && !zdir_entry(z) && z->source_id == source_id) {     /* (a zone in memory is the newer truth) */
        z->serial = serial;
        if (has_timers) {
            /* the same values a zone in memory has: the zone parser takes 0..4294967295 for these fields and parse_ttl_value() (what the
             * install of the data stores) rounds a value with the top bit set down to 2147483647 (RFC 8767 4) */
            z->refresh = refresh > 2147483647u ? 2147483647u : refresh;
            z->retry = retry > 2147483647u ? 2147483647u : retry;
            z->expire = expire > 2147483647u ? 2147483647u : expire;
        }
        z->last_result = DBREG_APPLIED;
        applied = true;
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return applied;
}

/* ---- D1a step 5: the data of a DB zone leaves memory (design 8.2) ---- */
static _Atomic uint64_t g_evictions;
static _Atomic(void (*)(void)) g_pending_notify;
void dbreg_set_pending_notify(void (*cb)(void)) { atomic_store_explicit(&g_pending_notify, cb, memory_order_release); }

/* Take the data of z out of memory; the element stays in the directory (state ABSENT, entry NULL), its digest, serial and SOA timers stay.  The
 * lock is held.  Returns the bytes the zone's version held (at least 1), or 0: the zone cannot be evicted now (not a primary DB zone of its own
 * view, pinned, not in the index yet, a transfer is reading it, its writer lock is busy).
 * The entry is not freed here: a reader of the index may hold it, and so may a control command with a retained snapshot.  Its reference goes
 * with the replaced-entry list (rv->repl) to the garbage of the snapshot that the next delta retires, and is given back when that snapshot is
 * drained, exactly as a replaced entry's is.  Until then the version's bytes are in the retired total (not the resident one), and in g_evict_inflight. */
static __attribute__((unused)) uint64_t dbreg_evict_locked(dbreg_view_t *rv, dbreg_zone_t *z) {   /* (the cache manager of the next commit uses it; so does the test hook) */
    zone_db_entry_t *e = zdir_entry(z);
    if (!e || e->source != ZONE_SRC_DB || e->is_secondary || e->is_catalog_member || e->catalog_member_count > 0 || z->shadowed ||
        (z->kind & (ZDIR_K_SHARED | ZDIR_K_STATIC | ZDIR_K_BORROWED)) || (z->flags & (ZDIR_F_PIN | ZDIR_F_DELETED | ZDIR_F_GARB)) ||
        atomic_load_explicit(&z->state, memory_order_relaxed) != ZDIR_ST_RESIDENT || e->evicted_bytes)
        return 0;
    if (zdir_lookup(dbreg_active_dir_locked(rv->name), z->name) != z) return 0;
    if (atomic_load_explicit(&e->active_axfr, memory_order_acquire) > 0 || atomic_load_explicit(&e->is_transferring, memory_order_acquire)) return 0;
    /* more than the registry's reference: a zone { in-view } of another view shares the entry (it would go on serving it), or an object of the entry
     * waits on the retire stack; not now */
    if (atomic_load_explicit(&e->snapshot_refs, memory_order_acquire) != 1) return 0;
    zdir_gent_t *gent = malloc(sizeof(*gent));
    if (!gent) return 0;
    if (pthread_mutex_trylock(&e->writer_lock) != 0) {         /* an UPDATE, a transfer or a settings change is working on it */
        free(gent);
        return 0;
    }
    zone_version_t *a = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
    uint64_t bytes = (a && a->counted) ? a->bytes : 0;
    /* the settings the zone's allow-query is read from while its data is out (zdir_elem_t.sh) */
    const zone_config_t *dc = atomic_load_explicit(&e->dbcfg, memory_order_acquire);
    zone_ext_shared_t *nsh = (dc && dc->ext_shared) ? (zone_ext_shared_t *)dc->ext : NULL;
    zone_ext_shared_t *osh = atomic_load_explicit(&z->sh, memory_order_relaxed);
    gent->sh_old = NULL;
    if (nsh != osh) {
        if (nsh) zone_ext_shared_ref(nsh);
        atomic_store_explicit(&z->sh, nsh, memory_order_release);
        gent->sh_old = osh;
    }
    atomic_store_explicit(&z->entry, NULL, memory_order_release);
    atomic_store_explicit(&z->state, ZDIR_ST_ABSENT, memory_order_release);
    if (bytes) {
        a->counted = false;
        zone_bytes_resident_add(ZBYTES_DB, -(int64_t)bytes);
        zone_bytes_retired_add(ZBYTES_DB, (int64_t)bytes);
        e->evicted_bytes = bytes;
        atomic_fetch_add_explicit(&g_evict_inflight, (int64_t)bytes, memory_order_relaxed);
    } else {
        e->evicted_bytes = 0;
    }
    gent->entry = e;
    gent->served = false;
    gent->next = rv->repl;
    rv->repl = gent;
    rv->n_repl++;
    atomic_fetch_add_explicit(&g_dbreg_pending, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_evictions, 1, memory_order_relaxed);
    pthread_mutex_unlock(&e->writer_lock);
    void (*notify)(void) = atomic_load_explicit(&g_pending_notify, memory_order_acquire);
    if (notify) notify();                              /* the ingest thread publishes the delta (and so retires the entry) */
    return bytes ? bytes : 1;
}

uint64_t dbreg_evictions(void) { return atomic_load_explicit(&g_evictions, memory_order_relaxed); }
uint64_t dbreg_evict_inflight(void) {
    int64_t v = atomic_load_explicit(&g_evict_inflight, memory_order_relaxed);
    return v > 0 ? (uint64_t)v : 0;
}

#if defined(KARIDNS_TEST_EVICT) || defined(KARIDNS_UNIT_TEST)
/* TEST ONLY (not in a production build): evict one DB zone by name, as the cache manager does, whatever the memory limit says.  Deterministic tests
 * use it to put a zone out of memory (the state of an evicted zone: in the directory, no data); the data comes back through the fetch stream. */
bool dbreg_test_evict(const char *view, const char *name) {
    bool ok = false;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, name, zdir_name_hash(name)) : NULL;
    if (z && dbreg_evict_locked(rv, z)) ok = true;
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return ok;
}
#endif

int dbreg_delete(const char *view, const char *name, int64_t source_id) {
    int rc = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, name, zdir_name_hash(name)) : NULL;
    if (z && z->source_id == source_id) {
        /* An element that is in the index, or waits in the queue of additions, leaves the index with the next delta; any other
         * one only older snapshots can have (a rebuild hid it): it goes to the garbage at once.  Never freed here: the readers of
         * an older snapshot can have found it in the shared directory. */
        zdir_t *d = dbreg_active_dir_locked(view);
        bool defer = (z->flags & ZDIR_F_QUEUED) || zdir_lookup(d, z->name) == z;
        if (defer && !dbreg_queue_reserve(&rv->removes, rv->n_removes, &rv->cap_removes)) {
            rc = -1;
        } else {
            dbreg_unlink(rv, z);
            z->flags |= ZDIR_F_DELETED;
            if (defer) {
                rv->removes[rv->n_removes++] = z;
                atomic_fetch_add_explicit(&g_dbreg_pending, 1, memory_order_relaxed);
            } else {
                garb_elem(&g_garb, z);
            }
            rc = 1;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return rc;
}

size_t dbreg_pending_count(void) {
    return atomic_load_explicit(&g_dbreg_pending, memory_order_relaxed);
}

/* the queues of a view are done with (applied to the index, or no longer needed because a rebuild read the registry): the deleted
 * elements and the replaced entries go to the garbage, the waiting ones are not waiting any more; the lock is held */
static void dbreg_pending_drop_view_locked(dbreg_view_t *rv) {
    for (size_t i = 0; i < rv->n_adds; i++) rv->adds[i]->flags &= (uint16_t)~ZDIR_F_QUEUED;
    for (size_t i = 0; i < rv->n_removes; i++) garb_elem(&g_garb, rv->removes[i]);
    for (zdir_gent_t *n = rv->repl, *nx; n; n = nx) {
        nx = n->next;
        n->next = g_garb.ents;
        g_garb.ents = n;
    }
    atomic_fetch_sub_explicit(&g_dbreg_pending, rv->n_adds + rv->n_removes + rv->n_repl, memory_order_relaxed);
    rv->n_adds = rv->n_removes = rv->n_repl = 0;
    rv->repl = NULL;
    /* the queues of a start (a million additions) are not kept: the directory costs memory per zone, not per zone that ever waited */
    if (rv->cap_adds > DBREG_QUEUE_KEEP) {
        free(rv->adds);
        rv->adds = NULL;
        rv->cap_adds = 0;
    }
    if (rv->cap_removes > DBREG_QUEUE_KEEP) {
        free(rv->removes);
        rv->removes = NULL;
        rv->cap_removes = 0;
    }
}

static void dbreg_pending_drop_locked(void) {
    for (size_t v = 0; v < g_dbreg_nviews; v++) dbreg_pending_drop_view_locked(&g_dbreg_views[v]);
}

/* the queues of the views the configuration no longer has (a reused snapshot keeps the queues of its views); the lock is held */
static void dbreg_pending_drop_gone_locked(const server_config_t *cfg) {
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        dbreg_view_t *rv = &g_dbreg_views[v];
        bool have = false;
        for (const view_config_t *vc = cfg->views; vc && !have; vc = vc->next) have = vc->name && strcasecmp(vc->name, rv->name) == 0;
        if (!have) dbreg_pending_drop_view_locked(rv);
    }
}

/* The registry's elements of one view that the new configuration does not hide (beta design 4.5); the lock is held.
 * vc: the view of the new configuration, old_view: the same view of the snapshot being replaced (a catalog member of
 * the same name hides a DB zone too).  *out: a malloc'ed array of the elements.  Updates the
 * shadowed flags and logs the changes.  (size_t)-1: out of memory. */
static size_t dbreg_collect_view_locked(const view_config_t *vc, view_snapshot_t *old_view, const catalog_member_id_t *vm,
                                        int vm_count, const int *vm_ht, const int *vm_chain, size_t vm_hsize,
                                        zdir_elem_t ***out) {
    *out = NULL;
    dbreg_view_t *rv = vc->name ? dbreg_view_get(vc->name, false) : NULL;
    if (!rv || rv->count == 0) return 0;
    zdir_elem_t **list = malloc(rv->count * sizeof(*list));
    if (!list) return (size_t)-1;
    size_t n = 0;
    burst_yield_t by = BURST_YIELD_INIT;
    for (size_t b = 0; b < rv->nb; b++) {
        for (dbreg_zone_t *z = rv->tab[b]; z; z = z->next) {
            if (!zdir_entry(z)) continue;
            burst_yield(&by);
            bool by_cfg = view_cfg_has(vc, z->name);
            bool by_cat = false;
            if (!by_cfg && old_view) {
                zdir_elem_t *oel = zdir_find_exact(old_view, z->name);
                zone_db_entry_t *o = oel != z ? zdir_entry(oel) : NULL;
                /* a catalog member hides it only if the rebuild keeps that member (it is still valid) */
                by_cat = o && o->is_catalog_member &&
                         catalog_member_index(vm, vm_count, vm_ht, vm_chain, vm_hsize, o->domain, zone_entry_catalog_uid(o)) >= 0;
            }
            bool sh = by_cfg || by_cat;
            if (sh && !z->shadowed)
                syslog(LOG_WARNING, "[DB] zone %s from the DB is shadowed by the %s (view '%s')", z->name,
                       by_cfg ? "zone in karidns.conf" : "catalog member of the same name", vc->name);
            else if (!sh && z->shadowed)
                syslog(LOG_NOTICE, "[DB] zone %s (view '%s') is served from the DB again: the %s is gone", z->name, vc->name,
                       z->shadow_by == DBREG_SH_CATALOG ? "catalog member" : "zone in karidns.conf");
            z->shadowed = sh;
            z->shadow_by = by_cfg ? DBREG_SH_CONFIG : by_cat ? DBREG_SH_CATALOG : DBREG_SH_NONE;
            if (!sh) list[n++] = z;
        }
    }
    *out = list;
    return n;
}

/* The match-clients of a view snapshot from a list of names (the view's configuration, or the view of the snapshot being
 * replaced): copies of the names and the parsed ACL.  aml: the list as written; only one with a `key` element is kept (a reference,
 * select_view_req() evaluates it with the TSIG key of the request; the names are empty for it).  false: out of memory (what was allocated
 * stays for free_zone_db_snapshot() to release). */
static bool view_set_match_clients(view_snapshot_t *vs, char *const *names, int count, aml_t *aml) {
    vs->match_clients_count = count;
    vs->match_clients = NULL;
    vs->match_clients_parsed = NULL;
    vs->match_aml = (aml && aml->has_key) ? aml_ref(aml) : NULL;
    if (count <= 0) return true;
    vs->match_clients = calloc(count, sizeof(char *));
    if (!vs->match_clients) return false;
    for (int i = 0; i < count; i++) {
        if (names[i] && !(vs->match_clients[i] = strdup(names[i]))) return false;
    }
    vs->match_clients_parsed = acl_list_parse(vs->match_clients, vs->match_clients_count);
    return true;
}

/* A snapshot that has the views and settings of `old` and shares its directories (what a delta, or a catalog change, publishes after
 * it changed them in place).  NULL: out of memory. */
static zone_db_snapshot_t *snap_clone_locked(const zone_db_snapshot_t *old) {
    zone_db_snapshot_t *ns = calloc(1, sizeof(*ns));
    if (!ns) return NULL;
    if (old->view_count) ns->views = calloc(old->view_count, sizeof(view_snapshot_t));
    if (old->view_count && !ns->views) {
        free(ns);
        return NULL;
    }
    ns->view_count = old->view_count;
    ns->ixfr_history = old->ixfr_history;
    atomic_init(&ns->reader_count, 0);
    bool ok = true;
    for (size_t v = 0; v < old->view_count; v++) {
        const view_snapshot_t *ov = &old->views[v];
        view_snapshot_t *vs = &ns->views[v];
        vs->name = strdup(ov->name ? ov->name : "");
        ok = ok && vs->name != NULL && view_set_match_clients(vs, ov->match_clients, ov->match_clients_count, ov->match_aml);
        if (ov->dir) {
            zdir_ref(ov->dir);
            vs->dir = ov->dir;
        }
    }
    if (!ok) {
        free_zone_db_snapshot(ns);
        return NULL;
    }
    return ns;
}

/* ---- the change of one directory, planned before anything is changed, so that an out-of-memory leaves it as it was ---- */
typedef struct {
    zdir_t *dir;
    zdir_elem_t **rem;                 /* to take out of the index (sorted by address once the plan is made) */
    size_t nrem, caprem;
    zdir_elem_t **add;                  /* to put in; an element of the same name is replaced */
    size_t nadd, capadd;
    zdir_elem_t **unhide;               /* the registry elements among `add` that come back (their hidden state ends with the change) */
    size_t nunhide, capunhide;
    size_t repl_changes;                /* the replaced entries that were served: each counts as a removal and an addition */
    zdir_tick_t *tick;                  /* the new tick list */
    bool tick_set;
    bool full_tick;                     /* build the tick list from the index, not from the old list (an entry was replaced) */
    /* what is put in force with the change and not before (a plan that fails changes nothing) */
    zone_db_entry_t **gone;             /* the entries of catalog consumers that leave: their CoO intentions are dropped */
    size_t ngone;
    struct dplan_hide { zdir_elem_t *z; uint8_t by; } *hide;   /* registry elements that an element already in the index hides (D17-1, D-PRIO) */
    size_t nhide, caphide;
    const char *vname;                  /* the view (for the log) */
} dplan_t;

static void dplan_free(dplan_t *p) {
    free(p->rem);
    free(p->add);
    free(p->unhide);
    free(p->tick);
    free(p->gone);
    free(p->hide);
}

/* ZDIR_K_OWNED elements that leave the index are garbage; so are the deleted registry ones.  The hidden ones are still the registry's. */
static void dplan_apply(dplan_t *p) {
    zdir_t *d = p->dir;
    /* B7b: a catalog consumer that leaves takes its CoO intentions with it */
    for (size_t i = 0; i < p->ngone; i++) {
        int q = 0;
        while (q < g_pending_coo_count) {
            if (strcasecmp(g_pending_coo[q].old_catalog, p->gone[i]->domain) == 0) {
                g_pending_coo[q] = g_pending_coo[g_pending_coo_count - 1];
                g_pending_coo_count--;
            } else {
                q++;
            }
        }
    }
    for (size_t i = 0; i < p->nhide; i++) {
        bool cat = p->hide[i].by == DBREG_SH_CATALOG;
        p->hide[i].z->shadowed = true;                    /* (a zone of karidns.conf that is there wins too: D-PRIO) */
        p->hide[i].z->shadow_by = p->hide[i].by;
        syslog(LOG_WARNING, "[DB] zone %s from the DB is hidden by a %s of the same name (view '%s')", p->hide[i].z->name,
               cat ? "catalog member" : "zone in karidns.conf", p->vname ? p->vname : "");
    }
    for (size_t i = 0; i < p->nunhide; i++) {
        p->unhide[i]->shadowed = false;
        p->unhide[i]->shadow_by = DBREG_SH_NONE;
    }
    for (size_t i = 0; i < p->nadd; i++) {
        zdir_elem_t *old = zdir_insert(d, p->add[i]);
        if (old && zdir_goes_to_garbage(old)) garb_elem(&g_garb, old);
    }
    for (size_t i = 0; i < p->nrem; i++) {
        (void)zdir_remove(d, p->rem[i]);
        if (zdir_goes_to_garbage(p->rem[i])) garb_elem(&g_garb, p->rem[i]);
    }
    if (p->tick_set) zdir_tick_publish(d, p->tick);
    p->tick = NULL;
}

/* The tick list and the room in the index of a plan whose rem / add are final.  false: out of memory. */
static bool dplan_finish(dplan_t *p) {
    if (p->nrem > 1) qsort(p->rem, p->nrem, sizeof(*p->rem), cmp_ptr);
    bool changed = p->full_tick;
    for (size_t i = 0; i < p->nrem && !changed; i++) changed = zdir_ticks(p->rem[i]);
    for (size_t i = 0; i < p->nadd && !changed; i++) changed = zdir_ticks(p->add[i]);
    /* The list that can fail first, then the room: a failure of the second leaves the old table and the old list.  (A plan of a later
     * view that fails after this one's table grew leaves a bigger table with the same elements, and it has room for the retry: the
     * retry does not build it again.) */
    if (changed) {
        if (!zdir_tick_make(p->dir, p->full_tick, p->rem, p->nrem, p->add, p->nadd, &p->tick)) return false;
        p->tick_set = true;
    }
    return zdir_reserve(p->dir, p->nadd);
}

static bool dplan_hide_push(dplan_t *p, zdir_elem_t *z, uint8_t by) {
    if (p->nhide == p->caphide) {
        size_t nc = p->caphide ? p->caphide * 2 : 8;
        struct dplan_hide *nh = realloc(p->hide, nc * sizeof(*nh));
        if (!nh) return false;
        p->hide = nh;
        p->caphide = nc;
    }
    p->hide[p->nhide].z = z;
    p->hide[p->nhide].by = by;
    p->nhide++;
    return true;
}

static bool dplan_push(zdir_elem_t ***a, size_t *n, size_t *cap, zdir_elem_t *e) {
    if (!dbreg_queue_reserve(a, *n, cap)) return false;
    (*a)[(*n)++] = e;
    return true;
}

/* The consumers of the catalog zones that leave (their entries have members): the members they created leave with them, and the DB
 * zone that a member hid comes back (unless the name is taken meanwhile).  false: out of memory. */
static bool dplan_drop_members(dplan_t *p, const char *vname, zone_db_entry_t *const *gone, size_t ngone) {
    zdir_iter_t it = { atomic_load_explicit(&p->dir->tab, memory_order_relaxed), 0 };
    burst_yield_t by = BURST_YIELD_INIT;
    for (zdir_elem_t *e; (e = zdir_iter_next(&it));) {
        zone_db_entry_t *en = zdir_entry(e);
        burst_yield(&by);
        if (!en || !en->is_catalog_member) continue;
        bool owned = false;
        for (size_t j = 0; j < ngone && !owned; j++)
            owned = strcasecmp(zone_entry_catalog_owner(en), gone[j]->domain) == 0;
        if (!owned) continue;
        syslog(LOG_INFO, "[Catalog] Removed member '%s': its catalog zone '%s' left the database", en->domain, zone_entry_catalog_owner(en));
        if (!dplan_push(&p->rem, &p->nrem, &p->caprem, e)) return false;
        /* D17-1: a DB zone of this name that the member hid comes back (unless the name is taken meanwhile) */
        dbreg_zone_t *hz = dbreg_catalog_hidden_zone_locked(vname, en->domain);
        if (hz && hz != e) {
            if (!dplan_push(&p->add, &p->nadd, &p->capadd, hz) || !dplan_push(&p->unhide, &p->nunhide, &p->capunhide, hz)) return false;
            syslog(LOG_NOTICE, "[DB] zone %s (view '%s') is served from the DB again: the catalog member is gone", hz->name, vname);
        }
    }
    return true;
}

/* The plan for the queued changes of one view.  false: out of memory.  Nothing is changed by it: what has to be put in force with the
 * change (the CoO intentions of a consumer that leaves, the DB zones that an element of the index hides) is recorded in the plan. */
static bool dplan_db(dplan_t *p, dbreg_view_t *rv, const char *vname) {
    zdir_t *d = p->dir;
    p->vname = vname;
    p->gone = malloc((rv->n_removes + rv->n_repl + 1) * sizeof(*p->gone));   /* entries that leave: for the catalog consumers among them */
    if (!p->gone) return false;
    zone_db_entry_t **gone = p->gone;
    bool ok = true;
    /* removals that are in the index */
    for (size_t i = 0; ok && i < rv->n_removes; i++) {
        zdir_elem_t *r = rv->removes[i];
        if (zdir_lookup(d, r->name) != r) continue;
        ok = dplan_push(&p->rem, &p->nrem, &p->caprem, r);
        zone_db_entry_t *en = zdir_entry(r);
        if (en && en->catalog_member_count > 0) gone[p->ngone++] = en;
    }
    for (const zdir_gent_t *n = rv->repl; ok && n; n = n->next) {
        if (n->served) {
            p->full_tick = true;                            /* a kind of zone may have changed with the entry */
            p->repl_changes += 2;
        }
        if (n->served && n->entry->catalog_member_count > 0) gone[p->ngone++] = n->entry;
    }
    /* B7b: a catalog consumer that leaves (its row was deleted or it became another kind of zone) takes the member zones it
     * created with it, as a configured catalog zone's members go at the next reconfiguration */
    if (ok && p->ngone > 0) ok = dplan_drop_members(p, vname, gone, p->ngone);
    if (ok && p->nrem > 1) qsort(p->rem, p->nrem, sizeof(*p->rem), cmp_ptr);
    /* additions that are still wanted and not in the index yet */
    for (size_t i = 0; ok && i < rv->n_adds; i++) {
        zdir_elem_t *a = rv->adds[i];
        if ((a->flags & ZDIR_F_DELETED) || !zdir_entry(a) || a->shadowed || dbreg_find(rv, a->name, a->hash) != a) continue;
        zdir_elem_t *ex = zdir_lookup(d, a->name);
        if (ex == a) continue;
        if (ex && !(p->nrem && ptr_in_sorted(p->rem, p->nrem, ex))) {
            zone_db_entry_t *xe = zdir_entry(ex);
            bool cat = xe && xe->is_catalog_member;          /* D17-1: the catalog member that is there wins; so does a zone of karidns.conf (D-PRIO) */
            ok = dplan_hide_push(p, a, cat ? DBREG_SH_CATALOG : DBREG_SH_CONFIG);
            continue;
        }
        ok = dplan_push(&p->add, &p->nadd, &p->capadd, a);
    }
    return ok && dplan_finish(p);
}

int snapshot_apply_db_delta(void) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    if (atomic_load_explicit(&g_dbreg_pending, memory_order_relaxed) == 0) {
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        return 0;
    }
    zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (!old_snap) {                              /* no snapshot yet: the first full rebuild reads the registry */
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        return 0;
    }
    zone_db_snapshot_t *ns = snap_clone_locked(old_snap);
    dplan_t *plans = ns ? calloc(old_snap->view_count ? old_snap->view_count : 1, sizeof(*plans)) : NULL;
    bool ok = plans != NULL;
    for (size_t v = 0; ok && v < old_snap->view_count; v++) {
        view_snapshot_t *vs = &ns->views[v];
        dbreg_view_t *rv = dbreg_view_get(vs->name, false);
        if (!rv || (!rv->n_removes && !rv->n_adds && !rv->n_repl)) continue;
        dplan_t *p = &plans[v];
        if (!vs->dir && !(vs->dir = zdir_new())) {      /* a view that had no zones (the new snapshot's reference of the directory) */
            ok = false;
            break;
        }
        p->dir = vs->dir;
        ok = dplan_db(p, rv, vs->name);
    }
    if (!ok) {
        for (size_t v = 0; plans && v < old_snap->view_count; v++) dplan_free(&plans[v]);
        free(plans);
        free_zone_db_snapshot(ns);
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        syslog(LOG_ERR, "[DB] out of memory publishing the zone changes; they are kept for the next try");
        return -1;
    }
    /* nothing can fail from here on */
    int changes = 0;
    for (size_t v = 0; v < old_snap->view_count; v++) {
        dplan_t *p = &plans[v];
        if (!p->dir) continue;
        dbreg_view_t *rv = dbreg_view_get(ns->views[v].name, false);
        /* a zone that leaves publishes nothing, so the zones whose glue came from it are told here: their cached
         * responses would keep the addresses of a zone that is gone (zone_glue_refresh_dependents() of the tick) */
        if (rv->n_removes > 0 || p->nrem > 0) atomic_store_explicit(&g_glue_dirty, true, memory_order_release);
        changes += (int)(p->nrem + p->nadd + p->repl_changes);
        dplan_apply(p);
        dplan_free(p);
    }
    free(plans);
    uint64_t retire_epoch = rcu_writer_publish(&g_zone_db_active, ns);
    old_snap->retire_epoch = retire_epoch;
    dbreg_pending_drop_locked();
    gc_retire_locked(old_snap);
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);

    gc_start_pending();
    return changes;
}

bool dbreg_walk(dbreg_cursor_t *cur, dbreg_walk_cb cb, void *ud) {
    bool done = true;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    while (done && cur->view < g_dbreg_nviews) {
        const dbreg_view_t *rv = &g_dbreg_views[cur->view];
        while (done && cur->bucket < rv->nb) {
            size_t i = 0;
            for (const dbreg_zone_t *z = rv->tab[cur->bucket]; z; z = z->next, i++) {
                if (i < cur->skip) continue;
                if (!cb(ud, rv->name, z)) {
                    cur->skip = i;
                    done = false;
                    break;
                }
            }
            if (done) {
                cur->bucket++;
                cur->skip = 0;
            }
        }
        if (done) {
            cur->view++;
            cur->bucket = 0;
            cur->skip = 0;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return done;
}

/* What the directory costs (D1a, design 3.1): the registry's elements (header, name, error text) and its hash tables, and the index tables of
 * the views of the active snapshot (and their tick lists), in bytes as requested from malloc.  The entries and their images are not in it. */
void dbreg_dir_bytes(size_t *elements, size_t *registry_bytes, size_t *index_bytes) {
    size_t n = 0, rb = 0, ib = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        const dbreg_view_t *rv = &g_dbreg_views[v];
        rb += rv->nb * sizeof(*rv->tab) + rv->cap_adds * sizeof(*rv->adds) + rv->cap_removes * sizeof(*rv->removes);
        for (size_t b = 0; b < rv->nb; b++) {
            for (const dbreg_zone_t *z = rv->tab[b]; z; z = z->next) {
                n++;
                rb += sizeof(*z) + strlen(z->name) + 1 + (z->error ? strlen(z->error) + 1 : 0) + (z->digest ? 32 : 0);
            }
        }
    }
    zone_db_snapshot_t *snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    for (size_t v = 0; snap && v < snap->view_count; v++) {
        const zdir_t *d = snap->views[v].dir;
        if (!d) continue;
        const zdir_tab_t *t = atomic_load_explicit(&d->tab, memory_order_relaxed);
        const zdir_tick_t *tk = atomic_load_explicit(&d->tick, memory_order_relaxed);
        ib += sizeof(*d) + (t ? sizeof(*t) + t->cap * sizeof(t->slot[0]) : 0) + (tk ? sizeof(*tk) + tk->n * sizeof(tk->e[0]) : 0);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    if (elements) *elements = n;
    if (registry_bytes) *registry_bytes = rb;
    if (index_bytes) *index_bytes = ib;
}

void dbreg_counts(size_t *total, size_t *rejected, size_t *shadowed) {
    size_t t = 0, r = 0, s = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        const dbreg_view_t *rv = &g_dbreg_views[v];
        for (size_t b = 0; b < rv->nb; b++) {
            for (const dbreg_zone_t *z = rv->tab[b]; z; z = z->next) {
                if (zdir_entry(z)) t++;
                if (z->last_result == DBREG_REJECTED) r++;
                if (zdir_entry(z) && z->shadowed) s++;
            }
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    if (total) *total = t;
    if (rejected) *rejected = r;
    if (shadowed) *shadowed = s;
}

void dbreg_counts2(size_t *total, size_t *rejected, size_t *shadowed_config, size_t *shadowed_catalog) {
    size_t t = 0, r = 0, sc = 0, sk = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        const dbreg_view_t *rv = &g_dbreg_views[v];
        for (size_t b = 0; b < rv->nb; b++) {
            for (const dbreg_zone_t *z = rv->tab[b]; z; z = z->next) {
                if (zdir_entry(z)) t++;
                if (z->last_result == DBREG_REJECTED) r++;
                if (zdir_entry(z) && z->shadowed) {
                    if (z->shadow_by == DBREG_SH_CATALOG) sk++;
                    else sc++;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    if (total) *total = t;
    if (rejected) *rejected = r;
    if (shadowed_config) *shadowed_config = sc;
    if (shadowed_catalog) *shadowed_catalog = sk;
}

int dbreg_find_info(const char *view, const char *name, dbreg_info_t *out, int max) {
    int n = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        const dbreg_view_t *rv = &g_dbreg_views[v];
        if (view && strcasecmp(rv->name, view) != 0) continue;
        const dbreg_zone_t *z = dbreg_find(rv, name, zdir_name_hash(name));
        if (!z) continue;
        if (n < max) {
            dbreg_info_t *o = &out[n];
            memset(o, 0, sizeof(*o));
            snprintf(o->view, sizeof(o->view), "%s", rv->name);
            o->source_id = z->source_id;
            o->has_entry = zdir_entry(z) != NULL;
            if (zdir_entry(z)) {
                o->serial = atomic_load_explicit(&zdir_entry(z)->serial, memory_order_relaxed);
                o->refresh = atomic_load_explicit(&zdir_entry(z)->refresh, memory_order_relaxed);
            } else if (z->last_result == DBREG_APPLIED) {     /* no data in memory: what the directory kept (a summary, D1a) */
                o->serial = z->serial;
                o->refresh = z->refresh;
            }
            o->shadowed = z->shadowed;
            o->shadow_by = z->shadow_by;
            o->last_result = z->last_result;
            if (z->error) snprintf(o->error, sizeof(o->error), "%s", z->error);
        }
        n++;
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return n;
}

zone_db_entry_t *dbreg_snapshot_entry(zone_db_snapshot_t *snap, const char *view, const char *name) {
    dbreg_zone_t *want = NULL;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, name, zdir_name_hash(name)) : NULL;
    if (z && zdir_entry(z) && !z->shadowed) want = z;
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    if (!want) return NULL;
    zdir_elem_t *e = zdir_find_exact(snapshot_find_view(snap, view), name);
    return e == want ? zdir_entry(e) : NULL;       /* (want is only compared) */
}

/* unit tests, fuzzers: forget every record.  The elements may be in the index of the snapshot that is active (and in its tick list), and
 * they hold the entries it serves: they leave the index (so a delta that shares the directory does not keep pointers to them) and go to
 * the garbage, which the next snapshot to be retired frees when its readers are gone.  (If the new tick list cannot be allocated the
 * old one stays: this is not a production path.) */
void dbreg_reset(void) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    g_dbreg_force_full = true;
    dbreg_pending_drop_locked();
    zone_db_snapshot_t *active = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        dbreg_view_t *rv = &g_dbreg_views[v];
        view_snapshot_t *vs = snapshot_find_view(active, rv->name);
        zdir_t *d = vs ? vs->dir : NULL;
        for (size_t b = 0; b < rv->nb; b++) {
            dbreg_zone_t *z = rv->tab[b];
            while (z) {
                dbreg_zone_t *nx = z->next;
                if (d) (void)zdir_remove(d, z);
                garb_elem(&g_garb, z);
                z = nx;
            }
        }
        zdir_tick_t *tk = NULL;
        if (d && zdir_tick_make(d, true, NULL, 0, NULL, 0, &tk)) zdir_tick_publish(d, tk);
        free(rv->tab);
        free(rv->adds);
        free(rv->removes);
    }
    free(g_dbreg_views);
    g_dbreg_views = NULL;
    g_dbreg_nviews = g_dbreg_capviews = g_dbreg_hint = 0;
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

zone_config_t *db_zone_config_new(const char *domain, zone_ext_shared_t *shared) {
    return db_zone_config_new_kind(domain, shared, 0);
}

/* kind: 0 primary (type master), 1 secondary (type slave: the masters and the key are in the settings), 2 catalog consumer (type
 * slave and catalog-zone, as a configured catalog zone; the members it lists are created by the catalog code) */
zone_config_t *db_zone_config_new_kind(const char *domain, zone_ext_shared_t *shared, int kind) {
    zone_config_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->domain = strdup(domain);
    c->type = strdup(kind == 0 ? "master" : "slave");
    c->is_catalog = kind == 2;
    if (!c->domain || !c->type) {
        free_zone_config(c);
        return NULL;
    }
    if (shared) {                                   /* interned settings: this zone holds one reference */
        c->ext = &zone_ext_shared_ref(shared)->ext;
        c->ext_shared = true;
        if (shared->ext.zone_tcp_mss > 0 || shared->ext.zone_tcp_window > 0 || shared->ext.zone_tcp_sndbuf > 0)
            atomic_store_explicit(&g_db_zone_tcp_opts, true, memory_order_relaxed);
    }
    return c;
}

static void free_zone_config_cb(void *p) {
    free_zone_config(p);
}

const zone_config_t *db_entry_swap_config(zone_db_entry_t *entry, const zone_config_t *cfg, uint64_t *epoch) {
    /* one writer per entry (the ingest thread working on the zone) */
    const zone_config_t *old = atomic_load_explicit(&entry->dbcfg, memory_order_relaxed);
    *epoch = rcu_writer_publish(&entry->dbcfg, cfg);
    return old;
}

void db_entry_retire_config(zone_db_entry_t *entry, const zone_config_t *old, uint64_t epoch) {
    if (old && !zone_retire_object(entry, (void *)old, free_zone_config_cb, epoch))
        syslog(LOG_ERR, "[DB] zone '%s': out of memory retiring the previous settings; they are leaked", entry->domain);
}

void db_entry_set_config(zone_db_entry_t *entry, const zone_config_t *cfg) {
    uint64_t epoch;
    const zone_config_t *old = db_entry_swap_config(entry, cfg, &epoch);
    db_entry_retire_config(entry, old, epoch);
}

/* ---- settings received from the primary (B8t-2, Extended AXFR v3) ----
 * The writers are the transfer thread that applied a transfer, and the control thread (zone_rx_settings_refresh()); both hold
 * entry->writer_lock while they change rx_sh / rx_base / rx_gen / rx_note and publish rxcfg. */
static void rx_merge_locked(zone_db_entry_t *entry, server_config_t *cfg) {
    const zone_config_t *base = entry->source == ZONE_SRC_DB ? atomic_load_explicit(&entry->dbcfg, memory_order_acquire)
                                                              : find_zone_config_in_view(cfg, entry->view_name, entry->domain);
    zone_config_t *nc = NULL;
    entry->rx_note[0] = '\0';
    if (entry->rx_sh && !(base && zext(base)->primary_settings_off)) {
        nc = zone_config_with_received_in_view(entry->domain, entry->view_name, base, &entry->rx_sh->ext, cfg, entry->rx_note, sizeof(entry->rx_note));
        if (!nc) syslog(LOG_ERR, "[AXFR] zone '%s': out of memory applying the settings received from the primary; they are not in force", entry->domain);
    }
    entry->rx_base = base;
    entry->rx_gen = cfg->generation;
    const zone_config_t *old = atomic_load_explicit(&entry->rxcfg, memory_order_relaxed);
    if (!old && !nc) return;
    uint64_t epoch = rcu_writer_publish(&entry->rxcfg, nc);
    if (old && !zone_retire_object(entry, (void *)old, free_zone_config_cb, epoch))
        syslog(LOG_ERR, "[AXFR] zone '%s': out of memory retiring the previous received settings; they are leaked", entry->domain);
}

zone_ext_shared_t *zone_rx_settings_parse(const char *zone, const char *text, size_t len) {
    if (!text || len == 0) return NULL;
    char err[200];
    zone_ext_shared_t *sh = db_settings_parse(text, len, err, sizeof(err));
    if (!sh) {
        syslog(LOG_WARNING, "[AXFR] zone '%s': the settings received from the primary are not accepted (%s); the zone keeps its own settings",
               zone, err);
        return NULL;
    }
    sh->ext.db_acl_ceiling = false;      /* the ceiling is a rule for the settings of the secondary's own database zones */
    return sh;
}

zone_ext_shared_t *zone_rx_settings_apply_locked(zone_db_entry_t *entry, zone_ext_shared_t *sh) {
    zone_ext_shared_t *old = entry->rx_sh;
    entry->rx_sh = sh;
    atomic_store_explicit(&entry->rx_present, sh != NULL, memory_order_relaxed);
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    if (cfg) {
        rx_merge_locked(entry, cfg);
        release_config_snapshot(cfg);
    }
    rcu_aux_read_unlock();
    if (sh && entry->rx_note[0])
        syslog(LOG_WARNING, "[AXFR] zone '%s': settings received from the primary: %s", entry->domain, entry->rx_note);
    return old;
}

void zone_rx_settings_refresh(zone_db_entry_t *entry, server_config_t *cfg) {
    if (!cfg || !atomic_load_explicit(&entry->rx_present, memory_order_relaxed)) return;
    if (pthread_mutex_trylock(&entry->writer_lock) != 0) return;      /* a transfer is installing: next tick */
    if (!entry->rx_sh) {
        pthread_mutex_unlock(&entry->writer_lock);
        return;
    }
    rcu_aux_read_lock();
    const zone_config_t *base = entry->source == ZONE_SRC_DB ? atomic_load_explicit(&entry->dbcfg, memory_order_acquire)
                                                              : find_zone_config_in_view(cfg, entry->view_name, entry->domain);
    if (entry->rx_gen != cfg->generation || entry->rx_base != base) rx_merge_locked(entry, cfg);
    rcu_aux_read_unlock();
    pthread_mutex_unlock(&entry->writer_lock);
}

bool zone_rx_settings_status(zone_db_entry_t *entry, char *note, size_t cap) {
    bool on = atomic_load_explicit(&entry->rxcfg, memory_order_acquire) != NULL;
    if (note && cap) {
        note[0] = '\0';
        if (on && pthread_mutex_trylock(&entry->writer_lock) == 0) {
            snprintf(note, cap, "%s", entry->rx_note);
            pthread_mutex_unlock(&entry->writer_lock);
        }
    }
    return on;
}

/* ---- interned settings of DB zones (B7a, beta design 4.2) ----
 * Zones whose settings text (profile name + profile text + zone text) is the same share one parsed zone_ext_t.  The table
 * is a writer-side structure under g_zone_db_rebuild_lock (the ingest thread and its builders; queries never touch it).
 * It holds one reference of every object; an object nobody else holds (refs == 1) is dropped when the table has grown by
 * half since the last sweep.  A zone's reference is released when its zone_config_t is freed (the S2 retire stack for a
 * replaced block, the entry's free for the last one), so an object lives until the last reader has left. */
_Atomic bool g_db_zone_tcp_opts;

static zone_ext_shared_t **g_dbset_tab;
static size_t g_dbset_nb, g_dbset_count, g_dbset_sweep_at = 256;

uint64_t db_settings_hash(const char *key, size_t len) {
    uint64_t h = 1469598103934665603ULL;           /* FNV-1a, 64 bit */
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)key[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static zone_ext_shared_t *dbset_find_locked(uint64_t hash, const char *key, size_t len) {
    if (!g_dbset_nb) return NULL;
    for (zone_ext_shared_t *s = g_dbset_tab[hash & (g_dbset_nb - 1)]; s; s = s->next)
        if (s->hash == hash && s->key_len == len && memcmp(s->key, key, len) == 0) return s;
    return NULL;
}

zone_ext_shared_t *db_settings_find(const char *key, size_t len) {
    uint64_t h = db_settings_hash(key, len);
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    zone_ext_shared_t *s = dbset_find_locked(h, key, len);
    if (s) zone_ext_shared_ref(s);
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return s;
}

static void dbset_sweep_locked(void) {
    size_t kept = 0;
    for (size_t b = 0; b < g_dbset_nb; b++) {
        zone_ext_shared_t **pp = &g_dbset_tab[b];
        while (*pp) {
            zone_ext_shared_t *s = *pp;
            if (atomic_load_explicit(&s->refs, memory_order_acquire) == 1) {       /* only the table holds it */
                *pp = s->next;
                zone_ext_shared_unref(s);
            } else {
                kept++;
                pp = &s->next;
            }
        }
    }
    g_dbset_count = kept;
    g_dbset_sweep_at = kept * 2 > 256 ? kept * 2 : 256;
}

zone_ext_shared_t *db_settings_intern(zone_ext_shared_t *fresh) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    zone_ext_shared_t *s = dbset_find_locked(fresh->hash, fresh->key, fresh->key_len);
    if (s) {                                        /* another thread was first: use its object */
        zone_ext_shared_ref(s);
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        zone_ext_shared_unref(fresh);
        return s;
    }
    if (g_dbset_count >= g_dbset_sweep_at) dbset_sweep_locked();
    if (g_dbset_count >= g_dbset_nb) {
        size_t nnb = g_dbset_nb ? g_dbset_nb * 2 : 256;
        zone_ext_shared_t **nt = calloc(nnb, sizeof(*nt));
        if (nt) {
            for (size_t b = 0; b < g_dbset_nb; b++) {
                zone_ext_shared_t *p = g_dbset_tab[b];
                while (p) {
                    zone_ext_shared_t *nx = p->next;
                    p->next = nt[p->hash & (nnb - 1)];
                    nt[p->hash & (nnb - 1)] = p;
                    p = nx;
                }
            }
            free(g_dbset_tab);
            g_dbset_tab = nt;
            g_dbset_nb = nnb;
        }
    }
    if (g_dbset_nb) {                               /* (out of memory growing: the object is simply not shared) */
        zone_ext_shared_ref(fresh);                 /* the table's reference */
        fresh->next = g_dbset_tab[fresh->hash & (g_dbset_nb - 1)];
        g_dbset_tab[fresh->hash & (g_dbset_nb - 1)] = fresh;
        g_dbset_count++;
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return fresh;
}

size_t db_settings_count(void) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    size_t n = g_dbset_count;
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return n;
}

void db_settings_reset(void) {                      /* unit tests: drop the table's references */
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    for (size_t b = 0; b < g_dbset_nb; b++) {
        zone_ext_shared_t *s = g_dbset_tab[b];
        while (s) {
            zone_ext_shared_t *nx = s->next;
            zone_ext_shared_unref(s);
            s = nx;
        }
    }
    free(g_dbset_tab);
    g_dbset_tab = NULL;
    g_dbset_nb = g_dbset_count = 0;
    g_dbset_sweep_at = 256;
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

/* Did the last full-configuration rebuild change the entry set of a view (zones added, removed or recreated)?  The
 * glue of dependents is then looked at again (rebuild_zone_db_from_config_ext()); a reload that reused every view did
 * not, and publications set g_glue_dirty by themselves. */
static bool g_rebuild_sets_changed = true;

/* The reload fast path (zone-change latency): can the view of the new configuration take over the old view as it is?
 * Yes when every zone { } of the view is an entry of the old view of the same name and kind that is neither a DB zone
 * nor a catalog member, their number is the old view's number of such entries (so none was removed), and no catalog
 * zone stopped being one (its members would have to go).  Then nothing hides or uncovers a DB zone (D-PRIO: a zone { }
 * shadows a DB zone of its name, a catalog member hides one as well), every catalog member stays valid, and the entries,
 * the hash tables and the tick list of the old view are what the new view would be built to.  A reload at 1,000,000 DB
 * zones used to walk them four times (the registry, the ixfr depth, both hash tables, the glue): 2.3 s; this is 30 ms. */
static bool view_reusable(const view_config_t *v, view_snapshot_t *old_view, zone_db_snapshot_t *old_snap) {
    if (!old_view || !old_view->dir) return false;
    size_t n = 0;
    for (zone_config_t *z = v->zones; z; z = z->next, n++) {
        zdir_elem_t *oe = z->domain ? zdir_find_exact(old_view, z->domain) : NULL;
        zone_db_entry_t *old = zdir_entry(oe);
        /* (an entry shared from another view is not this zone { }'s: the name was an in-view zone before) */
        if (!old || !view_owns_elem(oe) || old->source == ZONE_SRC_DB || old->is_catalog_member ||
            old->kind != zone_kind_from_type(z->type)) return false;
        if (old->catalog_member_count > 0 && !z->is_catalog) return false;
    }
    if (n != zdir_count_static(old_view)) return false;
    /* the zones shared with earlier views (zone { in-view }) must be the same entries of the same owner views, and no other */
    size_t ns = 0;
    for (zone_config_t *s = v->in_view_zones; s; s = s->next, ns++) {
        const zone_inview_t *iv = s->ext->iv;
        zdir_elem_t *oe = zdir_find_exact(old_view, s->domain);
        zone_db_entry_t *old = zdir_entry(oe);
        if (!old || view_owns_elem(oe) || strcasecmp(old->view_name, iv->view) != 0) return false;
        if (find_zone_exact_in_view(snapshot_find_view(old_snap, iv->view), s->domain) != old) return false;
    }
    return ns == zdir_count_shared(old_view);
}

static bool snapshot_views_reusable(zone_db_snapshot_t *old_snap, server_config_t *cfg) {
    if (g_dbreg_force_full || !old_snap || !old_snap->views) return false;
    for (view_config_t *v = cfg->views; v; v = v->next) {
        if (!v->name || !view_reusable(v, snapshot_find_view(old_snap, v->name), old_snap)) return false;
    }
    return true;
}

/* The view as a copy of the old view (view_reusable() holds): the directory is shared with the old snapshot (O(1): nothing is copied or
 * hashed), the match-clients come from the new configuration.  The ixfr-history depth follows the new configuration: for the zone { }
 * blocks always (cheap), for every entry when options { ixfr-history } changed.  false: out of memory (free_zone_db_snapshot()
 * releases what was allocated). */
static bool view_copy_from_old(view_snapshot_t *vs, const view_config_t *v, const view_snapshot_t *ov, server_config_t *cfg,
                               bool depth_all) {
    vs->name = strdup(v->name ? v->name : "");
    if (!vs->name || !view_set_match_clients(vs, v->match_clients, v->match_clients_count, v->acl.match)) return false;
    zdir_ref(ov->dir);
    vs->dir = ov->dir;
    burst_yield_t by = BURST_YIELD_INIT;
    rcu_aux_read_lock();       /* B7a: a DB zone's settings block can be replaced (and freed after a grace period) meanwhile */
    for (zone_config_t *z = v->zones; z; z = z->next) {                 /* as the full rebuild sets it for a reused entry */
        zone_db_entry_t *e = find_zone_exact_in_view(vs, z->domain);
        if (e) ixfr_history_set_depth(e, ixfr_history_effective(cfg, z));
    }
    if (depth_all) {                                                    /* options { ixfr-history } changed: the DB zones and members too */
        zdir_iter_t it;
        zdir_iter_init(&it, vs);
        for (zdir_elem_t *el; (el = zdir_iter_next(&it));) {
            zone_db_entry_t *e = zdir_entry(el);
            if (!e) continue;
            burst_yield(&by);
            if (e->source == ZONE_SRC_DB) ixfr_history_set_depth(e, ixfr_history_effective(cfg, zone_entry_config(cfg, e)));
            else if (e->is_catalog_member) ixfr_history_set_depth(e, ixfr_history_effective(cfg, NULL));
        }
    }
    rcu_aux_read_unlock();
    return true;
}

/* The zones view cv shares with earlier views (zone { in-view "owner"; }, BIND bin/named/server.c configure_zone() dns_view_addzone()): the entry of
 * the owner view is put into vs as well, in an element of its own that holds a reference of the entry (the directory releases one per view it is
 * in).  entry->view_name stays the owner's, so zone_entry_config() finds the owner's zone { }.  Called after the owner's directory is built.  A zone
 * whose owner entry does not exist (it could not be allocated) is left out.  false: out of memory. */
static bool view_append_shared(zone_db_snapshot_t *snap, view_snapshot_t *vs, const view_config_t *cv) {
    size_t ns = 0;
    for (const zone_config_t *s = cv->in_view_zones; s; s = s->next) ns++;
    if (!zdir_reserve(vs->dir, ns)) return false;
    int64_t order = (int64_t)atomic_load_explicit(&vs->dir->live, memory_order_relaxed);
    for (const zone_config_t *s = cv->in_view_zones; s; s = s->next) {
        view_snapshot_t *tvs = snapshot_find_view(snap, s->ext->iv->view);
        zone_db_entry_t *e = tvs ? find_zone_exact_in_view(tvs, s->domain) : NULL;
        if (!e) {
            syslog(LOG_ERR, "[Core] zone '%s' of view '%s' is shared from view '%s', which has no such zone entry; it is not served in this view",
                   s->domain, vs->name, s->ext->iv->view);
            continue;
        }
        atomic_fetch_add_explicit(&e->snapshot_refs, 1, memory_order_release);
        zdir_elem_t *se = zdir_elem_new_owned(e, ZDIR_K_SHARED, order++);
        if (!se) {
            atomic_fetch_sub_explicit(&e->snapshot_refs, 1, memory_order_release);   /* (the owner's reference keeps it) */
            return false;
        }
        zdir_elem_t *old = zdir_insert(vs->dir, se);
        if (old && (old->kind & ZDIR_K_OWNED)) zdir_elem_release(old);     /* (not published yet: nobody else has it) */
    }
    return true;
}

/* the tick list of a directory that was just built (nobody reads it yet).  false: out of memory */
static bool zdir_tick_init(zdir_t *d) {
    zdir_tick_t *tk = NULL;
    if (!zdir_tick_make(d, true, NULL, 0, NULL, 0, &tk)) return false;
    atomic_store_explicit(&d->tick, tk, memory_order_release);
    return true;
}

/* ---- the changes a catalog delta makes besides the directory: recorded while the delta is planned, put in force when nothing can fail any
 * more (an out-of-memory in the plan leaves the DB registry, the members' owners and groups and the CoO intentions as they were) ---- */
enum { CAT_OP_HIDE, CAT_OP_GROUPS, CAT_OP_BOOKKEEP, CAT_OP_OWNER };
typedef struct {
    int kind;
    zone_db_entry_t *entry;     /* HIDE: unused; GROUPS, OWNER: the member's entry; BOOKKEEP: the entry of the catalog the member leaves */
    catalog_member_id_t m;      /* HIDE: m.domain; GROUPS: the member with its new groups (the strings stay with the member list); BOOKKEEP: m.unique_id, m.domain */
    char *owner;                /* OWNER: the new owning catalog (malloc, taken over when applied) */
    bool log;                   /* GROUPS: say so in the log (a change of the groups alone) */
} cat_op_t;
typedef struct {
    cat_op_t *v;
    size_t n, cap;
    bool oom;
} cat_ops_t;

static cat_op_t *cat_op_add(cat_ops_t *o, int kind, zone_db_entry_t *entry) {
    if (o->n == o->cap) {
        size_t nc = o->cap ? o->cap * 2 : 8;
        cat_op_t *nv = realloc(o->v, nc * sizeof(*nv));
        if (!nv) {
            o->oom = true;
            return NULL;
        }
        o->v = nv;
        o->cap = nc;
    }
    cat_op_t *op = &o->v[o->n++];
    memset(op, 0, sizeof(*op));
    op->kind = kind;
    op->entry = entry;
    return op;
}

static void cat_ops_free(cat_ops_t *o) {
    for (size_t i = 0; i < o->n; i++) free(o->v[i].owner);
    free(o->v);
    memset(o, 0, sizeof(*o));
}

static void cat_ops_apply(cat_ops_t *o, const char *view_name) {
    for (size_t i = 0; i < o->n; i++) {
        cat_op_t *op = &o->v[i];
        switch (op->kind) {
        case CAT_OP_HIDE:
            dbreg_hide_by_catalog_locked(view_name, op->m.domain);
            break;
        case CAT_OP_GROUPS:
            catalog_entry_set_groups(op->entry, &op->m);
            if (op->log)
                syslog(LOG_INFO, "[Catalog] Updated group property of member '%s' (unique-id: %s)", op->entry->domain, op->m.unique_id);
            break;
        case CAT_OP_BOOKKEEP:
            remove_member_from_catalog_bookkeeping(op->entry, op->m.unique_id, op->m.domain);
            break;
        default:   /* CAT_OP_OWNER */
            free(op->entry->owning_catalog_domain);
            op->entry->owning_catalog_domain = op->owner;
            op->owner = NULL;
            break;
        }
    }
}

/* The CoO intentions of the catalog `catalog` ($OLDCATZ): the earlier ones are dropped and `add` (n of them) put in */
static void cat_coo_apply(const char *catalog, const pending_coo_t *add, size_t n) {
    int p = 0;
    while (p < g_pending_coo_count) {
        if (strcasecmp(g_pending_coo[p].old_catalog, catalog) == 0) {
            if (p < g_pending_coo_count - 1) g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
            g_pending_coo_count--;
        } else {
            p++;
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (g_pending_coo_count >= g_pending_coo_capacity) {
            size_t old_cap = g_pending_coo_capacity;
            size_t new_cap = old_cap == 0 ? 16 : old_cap * 2;
            pending_coo_t *tmp = realloc(g_pending_coo, new_cap * sizeof(pending_coo_t));
            if (!tmp) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for g_pending_coo (domain=%s); skipping CoO tracking for this member", add[i].domain);
                continue;
            }
            g_pending_coo = tmp;
            g_pending_coo_capacity = new_cap;
            memset(&g_pending_coo[old_cap], 0, (new_cap - old_cap) * sizeof(pending_coo_t));
        }
        g_pending_coo[g_pending_coo_count++] = add[i];
    }
}

zone_db_snapshot_t *rebuild_zone_db_snapshot(
    server_config_t *active_config,
    const char *catalog_view_name,
    zone_db_entry_t *catalog_entry_to_update,
    const zone_config_t *catalog_cfg,
    catalog_member_id_t *new_desired_members, int new_desired_count) 
{
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    zone_db_snapshot_t *new_snap = calloc(1, sizeof(zone_db_snapshot_t));
    if (!new_snap) {
        abort_rebuild_snapshot(NULL, "new_snap");
        return NULL;
    }
    
    bool reused = false;
    burst_yield_t by = BURST_YIELD_INIT;
    if (active_config && snapshot_views_reusable(old_snap, active_config)) {
        /* MODE: Full Config Reload, no zone set changed: the views are copies of the old ones (O(views), not O(zones)) */
        int view_count = 0;
        for (view_config_t *v = active_config->views; v; v = v->next) view_count++;
        new_snap->view_count = view_count;
        new_snap->ixfr_history = active_config->ixfr_history;
        new_snap->views = view_count > 0 ? calloc(view_count, sizeof(view_snapshot_t)) : NULL;
        if (view_count > 0 && !new_snap->views) {
            abort_rebuild_snapshot(new_snap, "new_snap->views");
            return NULL;
        }
        atomic_init(&new_snap->reader_count, 0);
        int vidx = 0;
        for (view_config_t *v = active_config->views; v; v = v->next, vidx++) {
            if (!view_copy_from_old(&new_snap->views[vidx], v, snapshot_find_view(old_snap, v->name), active_config,
                                    old_snap->ixfr_history != active_config->ixfr_history)) {
                abort_rebuild_snapshot(new_snap, "view copy");
                return NULL;
            }
        }
        dbreg_pending_drop_gone_locked(active_config);
        reused = true;
        g_rebuild_sets_changed = false;
    } else if (active_config) {
        // MODE: Full Config Reload
        g_rebuild_sets_changed = true;
        g_dbreg_force_full = false;
        new_snap->ixfr_history = active_config->ixfr_history;
        
        int max_valid_members = 0;
        if (old_snap && old_snap->views) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                zdir_iter_t it;
                zdir_iter_init(&it, &old_snap->views[v]);
                for (zdir_elem_t *el; (el = zdir_iter_next(&it));) {
                    zone_db_entry_t *entry = zdir_entry(el);
                    if (!entry || !view_owns_elem(el)) continue;
                    burst_yield(&by);
                    if (entry->catalog_member_count > 0) {
                        max_valid_members += entry->catalog_member_count;
                    }
                }
            }
        }
        catalog_member_id_t *valid_members = max_valid_members > 0 ? calloc(max_valid_members, sizeof(catalog_member_id_t)) : NULL;
        if (max_valid_members > 0 && !valid_members) {
            abort_rebuild_snapshot(new_snap, "valid_members");
            return NULL;
        }
        int valid_member_count = 0;
        
        if (old_snap && old_snap->views) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                zdir_iter_t it;
                zdir_iter_init(&it, &old_snap->views[v]);
                for (zdir_elem_t *el; (el = zdir_iter_next(&it));) {
                    zone_db_entry_t *entry = zdir_entry(el);
                    if (!entry || !view_owns_elem(el)) continue;
                    burst_yield(&by);
                    if (entry->catalog_member_count > 0) {
                        const zone_config_t *zcfg = zone_entry_config(active_config, entry);
                        if (zcfg && zcfg->is_catalog) {
                            for (int k = 0; k < entry->catalog_member_count; k++) {
                                valid_members[valid_member_count++] = entry->catalog_members[k];
                            }
                        } else {
                            free_catalog_member_ids(entry->catalog_members, entry->catalog_member_count);
                            entry->catalog_members = NULL;
                            entry->catalog_member_count = 0;
                            
                            int p = 0;
                            while (p < g_pending_coo_count) {
                                if (strcasecmp(g_pending_coo[p].old_catalog, entry->domain) == 0) {
                                    if (p < g_pending_coo_count - 1) {
                                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                                    }
                                    g_pending_coo_count--;
                                } else {
                                    p++;
                                }
                            }
                        }
                    }
                }
            }
        }

        /* 旧メンバーが有効かは (名前, unique-id) のハッシュで引く (メンバー数の 2 乗にしない) */
        int *vm_ht = NULL, *vm_chain = NULL;
        size_t vm_hsize = 0;
        catalog_member_hash_build(valid_members, valid_member_count, &vm_ht, &vm_chain, &vm_hsize);

        int view_count = 0;
        for (view_config_t *v = active_config->views; v; v = v->next) view_count++;
        
        new_snap->view_count = view_count;
        if (view_count > 0) {
            new_snap->views = calloc(view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "new_snap->views");
                return NULL;
            }
        }
        atomic_init(&new_snap->reader_count, 0);

        int vidx = 0;
        for (view_config_t *v = active_config->views; v; v = v->next, vidx++) {
            view_snapshot_t *vs = &new_snap->views[vidx];
            vs->name = v->name ? strdup(v->name) : strdup("");
            if (!vs->name) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "vs->name");
                return NULL;
            }
            if (!view_set_match_clients(vs, v->match_clients, v->match_clients_count, v->acl.match)) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "vs->match_clients");
                return NULL;
            }

            int static_count = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) static_count++;

            /* 同じ名前の旧 view。ゾーンごとの照合はその view の索引と設定の索引で行う
             * (旧エントリを線形に探すと reload がゾーン数の 2 乗になる) */
            view_snapshot_t *old_view = (old_snap && v->name) ? snapshot_find_view(old_snap, v->name) : NULL;

            if (!(vs->dir = zdir_new())) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "vs->dir");
                return NULL;
            }

            /* the members of the catalog zones that stay, which no zone { } of this view replaces (the old view's elements: a zone shared from
             * another view is not one of them) */
            zdir_elem_t **member_els = NULL;
            size_t dynamic_count = 0, member_cap = 0;
            bool member_oom = false;
            zdir_iter_t oit;
            zdir_iter_init(&oit, old_view);
            for (zdir_elem_t *oel; (oel = zdir_iter_next(&oit));) {
                zone_db_entry_t *entry = zdir_entry(oel);
                burst_yield(&by);
                if (entry && view_owns_elem(oel) && entry->is_catalog_member &&
                    catalog_member_index(valid_members, valid_member_count, vm_ht, vm_chain, vm_hsize,
                                         entry->domain, zone_entry_catalog_uid(entry)) >= 0 &&
                    !view_cfg_has(v, entry->domain)) {
                    if (!dplan_push(&member_els, &dynamic_count, &member_cap, oel)) {
                        member_oom = true;
                        break;
                    }
                }
            }

            /* DB zones (beta design 4.5): the registry's elements of this view that no configured zone hides */
            zdir_elem_t **db_list = NULL;
            size_t db_n = member_oom ? (size_t)-1 : dbreg_collect_view_locked(v, old_view, valid_members, valid_member_count, vm_ht, vm_chain, vm_hsize, &db_list);
            if (db_n == (size_t)-1 || !zdir_reserve(vs->dir, static_count + dynamic_count + db_n)) {
                free(db_list);
                free(member_els);
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "db_list");
                return NULL;
            }

            int64_t order = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) {
                zone_db_entry_t *entry = NULL;
                zdir_elem_t *old_el = (old_view && z->domain) ? zdir_find_exact(old_view, z->domain) : NULL;
                zone_db_entry_t *old = zdir_entry(old_el);
                if (old && !view_owns_elem(old_el)) old = NULL;   /* it was a zone shared from another view (zone { in-view }): this one is new */
                if (old) {
                    /* O-13: type が変わったゾーンと、静的ゾーンで上書きされたカタログ
                     * メンバーは再利用しない。is_secondary や EXPIRE、転送の状態は
                     * エントリ作成時に決まるので、新しいエントリを作る (旧エントリは
                     * 削除されたゾーンと同じく旧スナップショットとともに解放される)。*/
                    if (old->kind == zone_kind_from_type(z->type) && !old->is_catalog_member && old->source != ZONE_SRC_DB) {
                        entry = old;
                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                        /* B-3: ixfr-history may have changed; a lower depth drops the oldest diffs now */
                        ixfr_history_set_depth(entry, ixfr_history_effective(active_config, z));
                    } else {
                        syslog(LOG_NOTICE, "[Core] zone '%s' in view '%s' changed type or replaces a catalog member; recreating the zone entry",
                               z->domain, v->name ? v->name : "");
                    }
                }
                if (!entry) {
                    entry = create_new_zone_entry(z->domain, v->name);
                    if (entry) {
                        ixfr_history_set_depth(entry, ixfr_history_effective(active_config, z));
                        entry->kind = zone_kind_from_type(z->type);
                        entry->is_secondary = (entry->kind == ZONE_KIND_SECONDARY);
                    }
                    if (entry && z->file) {
                        reload_master_zone(entry, z);
                    }
                }
                zdir_elem_t *el = entry ? zdir_elem_new_owned(entry, ZDIR_K_STATIC, order++) : NULL;
                if (!el) {
                    if (entry) zone_entry_unref(entry);       /* (the directory's reference of a reused entry, or a new entry's only one) */
                    syslog(LOG_ERR, "[Core] Failed to allocate memory for zone '%s' in view '%s', skipping this zone this reload cycle",
                           z->domain ? z->domain : "unknown", v->name ? v->name : "unknown");
                    continue;
                }
                zdir_elem_t *dup = zdir_insert(vs->dir, el);
                if (dup && (dup->kind & ZDIR_K_OWNED)) zdir_elem_release(dup);
            }

            /* 有効なカタログメンバーのうち、静的な zone{} で上書きされていないものを引き継ぐ */
            for (size_t k = 0; k < dynamic_count; k++) {
                zone_db_entry_t *entry = zdir_entry(member_els[k]);
                atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                ixfr_history_set_depth(entry, ixfr_history_effective(active_config, NULL));
                zdir_elem_t *el = zdir_elem_new_owned(entry, 0, order++);
                if (!el) {
                    syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s', dropping it this reload cycle", entry->domain);
                    zone_entry_unref(entry);
                    continue;
                }
                zdir_elem_t *dup = zdir_insert(vs->dir, el);
                if (dup && (dup->kind & ZDIR_K_OWNED)) zdir_elem_release(dup);
            }
            free(member_els);
            rcu_aux_read_lock();       /* B7a: a DB zone's settings block can be replaced (and freed after a grace period) meanwhile */
            for (size_t k = 0; k < db_n; k++) {
                burst_yield(&by);
                zone_db_entry_t *dbe = zdir_entry(db_list[k]);
                ixfr_history_set_depth(dbe, ixfr_history_effective(active_config, zone_entry_config(active_config, dbe)));
                (void)zdir_insert(vs->dir, db_list[k]);      /* (a name that a zone { } or a member has is not in the list) */
            }
            rcu_aux_read_unlock();
            free(db_list);
        }
        { free(valid_members); free(vm_ht); free(vm_chain); }

    } else {
        // MODE: Catalog Delta Update
        if (!catalog_entry_to_update) {
            abort_rebuild_snapshot(new_snap, "null catalog_entry_to_update");
            return NULL;
        }
        if (old_snap) new_snap->ixfr_history = old_snap->ixfr_history;
        
        // Step A: the CoO intentions of this catalog (acting as $OLDCATZ) are made here and put in force with the rest of the change (cat_coo_apply()):
        // nothing is changed while the change can still fail
        pending_coo_t *coo_new = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(pending_coo_t));
        size_t coo_new_n = 0;
        cat_ops_t cops;
        memset(&cops, 0, sizeof(cops));
        if (!coo_new) {
            abort_rebuild_snapshot(new_snap, "catalog CoO intentions");
            return NULL;
        }
        for (int i = 0; i < new_desired_count; i++) {
            if (strlen(new_desired_members[i].coo_target) > 0) {
                pending_coo_t *c = &coo_new[coo_new_n++];
                strncpy(c->domain, new_desired_members[i].domain, sizeof(c->domain) - 1);
                strncpy(c->old_catalog, catalog_entry_to_update->domain, sizeof(c->old_catalog) - 1);
                strncpy(c->new_catalog, new_desired_members[i].coo_target, sizeof(c->new_catalog) - 1);
            }
        }

        int added_count = 0;
        int removed_count = 0;
        catalog_member_id_t *added_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *removed_members = calloc(catalog_entry_to_update->catalog_member_count > 0 ? catalog_entry_to_update->catalog_member_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *coo_evicted_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        if (!added_members || !removed_members || !coo_evicted_members) {
            if (added_members) free(added_members);
            if (removed_members) free(removed_members);
            if (coo_evicted_members) free(coo_evicted_members);
            free(coo_new);
            abort_rebuild_snapshot(new_snap, "catalog member allocations");
            return NULL;
        }
        int coo_evicted_count = 0;

        int filtered_count = 0;
        view_snapshot_t *target_view = NULL;
        if (old_snap && old_snap->views) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                if (old_snap->views[v].name && catalog_view_name &&
                    strcasecmp(old_snap->views[v].name, catalog_view_name) == 0) {
                    target_view = &old_snap->views[v];
                    break;
                }
            }
        }

        // Ephemeral hash table for catalog_entry_to_update->catalog_members
        int *cur_hash_table = NULL;
        int *cur_chain_next = NULL;
        size_t cur_hash_size = 0;
        int cur_count = catalog_entry_to_update->catalog_member_count;
        catalog_member_hash_build(catalog_entry_to_update->catalog_members, cur_count,
                                  &cur_hash_table, &cur_chain_next, &cur_hash_size);

        for (int i = 0; i < new_desired_count; i++) {
            int cur_idx = catalog_member_index(catalog_entry_to_update->catalog_members, cur_count,
                                               cur_hash_table, cur_chain_next, cur_hash_size,
                                               new_desired_members[i].domain, new_desired_members[i].unique_id);
            bool found = cur_idx >= 0;
            if (found && target_view &&
                !catalog_groups_equal(&new_desired_members[i], &catalog_entry_to_update->catalog_members[cur_idx])) {
                /* R-28: group だけの変更はメンバーの削除と追加にしない (RFC 9432 §4.3.2, §5.4) */
                zone_db_entry_t *existing = find_catalog_parent_in_snapshot(target_view, new_desired_members[i].domain);
                if (existing && existing->is_catalog_member &&
                    strcasecmp(zone_entry_catalog_owner(existing), catalog_entry_to_update->domain) == 0) {
                    cat_op_t *op = cat_op_add(&cops, CAT_OP_GROUPS, existing);
                    if (op) {
                        op->m = new_desired_members[i];
                        op->log = true;
                    }
                }
            }

            bool member_accepted = true;
            bool needs_creation = true;

            if (!found) {
                if (target_view) {
                    zone_db_entry_t *existing = find_catalog_parent_in_snapshot(target_view, new_desired_members[i].domain);
                    if (existing && existing->source == ZONE_SRC_DB) {
                        /* D17-1: the catalog member wins on every path (a full reconfiguration does too, beta design 4.5).
                         * The DB zone stays in the registry, hidden, and comes back when the member goes away. */
                        syslog(LOG_WARNING, "[Catalog] Zone '%s' generated member '%s' which has the name of a zone from the database; "
                               "the catalog member wins and the database zone is hidden",
                               catalog_entry_to_update->domain, new_desired_members[i].domain);
                        cat_op_t *op = cat_op_add(&cops, CAT_OP_HIDE, existing);
                        if (op) snprintf(op->m.domain, sizeof(op->m.domain), "%s", new_desired_members[i].domain);
                    } else if (existing && existing->is_catalog_member) {
                        if (strcasecmp(zone_entry_catalog_owner(existing), catalog_entry_to_update->domain) != 0) {
                            bool valid_coo = false;
                            for (int p = 0; p < g_pending_coo_count; p++) {
                                if (strcasecmp(g_pending_coo[p].domain, new_desired_members[i].domain) == 0 &&
                                    strcasecmp(g_pending_coo[p].old_catalog, zone_entry_catalog_owner(existing)) == 0 &&
                                    strcasecmp(g_pending_coo[p].new_catalog, catalog_entry_to_update->domain) == 0) {
                                    valid_coo = true; break;
                                }
                            }
                            if (valid_coo) {
                                zone_db_entry_t *old_catalog_entry = find_catalog_parent_in_snapshot(target_view, zone_entry_catalog_owner(existing));
                                if (old_catalog_entry) {
                                    cat_op_t *op = cat_op_add(&cops, CAT_OP_BOOKKEEP, old_catalog_entry);
                                    if (op) {
                                        snprintf(op->m.unique_id, sizeof(op->m.unique_id), "%s", zone_entry_catalog_uid(existing));
                                        snprintf(op->m.domain, sizeof(op->m.domain), "%s", new_desired_members[i].domain);
                                    }
                                }
                                if (strcmp(zone_entry_catalog_uid(existing), new_desired_members[i].unique_id) == 0) {
                                    // Retain state
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: retained state for '%s' (unique-id: %s), owner %s -> %s",
                                           existing->domain, zone_entry_catalog_uid(existing), zone_entry_catalog_owner(existing), catalog_entry_to_update->domain);
                                    cat_op_t *oop = cat_op_add(&cops, CAT_OP_OWNER, existing);
                                    if (oop && !(oop->owner = strdup(catalog_entry_to_update->domain))) cops.oom = true;
                                    cat_op_t *gop = cat_op_add(&cops, CAT_OP_GROUPS, existing);
                                    if (gop) gop->m = new_desired_members[i];
                                    needs_creation = false;
                                } else {
                                    // State reset
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: evicted old state for '%s' (old unique-id: %s, new unique-id: %s)",
                                           existing->domain, zone_entry_catalog_uid(existing), new_desired_members[i].unique_id);
                                    strncpy(coo_evicted_members[coo_evicted_count].unique_id, zone_entry_catalog_uid(existing), sizeof(coo_evicted_members[coo_evicted_count].unique_id) - 1);
                                    strncpy(coo_evicted_members[coo_evicted_count].domain, existing->domain, sizeof(coo_evicted_members[coo_evicted_count].domain) - 1);
                                    coo_evicted_count++;
                                }
                            } else {
                                syslog(LOG_WARNING, "[Catalog] Name collision for '%s' between '%s' and '%s'. Ignoring.", 
                                       new_desired_members[i].domain, zone_entry_catalog_owner(existing), catalog_entry_to_update->domain);
                                member_accepted = false;
                            }
                        }
                    }
                }
            } else {
                needs_creation = false; // Already existed exactly in our catalog
            }

            if (member_accepted) {
                if (filtered_count != i) {
                    new_desired_members[filtered_count] = new_desired_members[i];
                }
                filtered_count++;
                if (needs_creation) {
                    added_members[added_count++] = new_desired_members[i];
                }
            } else {
                if (new_desired_members[i].groups) {
                    for (int g = 0; g < new_desired_members[i].group_count; g++) {
                        free(new_desired_members[i].groups[g]);
                    }
                    free(new_desired_members[i].groups);
                }
            }
        }
        if (cur_hash_table) free(cur_hash_table);
        if (cur_chain_next) free(cur_chain_next);
        new_desired_count = filtered_count;
        if (cops.oom) {                                 /* the record of the changes could not be kept: nothing was changed yet */
            free(added_members); free(removed_members); free(coo_evicted_members);
            free(coo_new);
            cat_ops_free(&cops);
            abort_rebuild_snapshot(new_snap, "catalog changes");
            return NULL;
        }

        // Ephemeral hash table for new_desired_members
        int *des_hash_table = NULL;
        int *des_chain_next = NULL;
        size_t des_hash_size = 0;
        catalog_member_hash_build(new_desired_members, new_desired_count,
                                  &des_hash_table, &des_chain_next, &des_hash_size);

        for (int i = 0; i < catalog_entry_to_update->catalog_member_count; i++) {
            bool found = catalog_member_index(new_desired_members, new_desired_count,
                                              des_hash_table, des_chain_next, des_hash_size,
                                              catalog_entry_to_update->catalog_members[i].domain,
                                              catalog_entry_to_update->catalog_members[i].unique_id) >= 0;
            if (!found) {
                removed_members[removed_count++] = catalog_entry_to_update->catalog_members[i];
            }
        }
        if (des_hash_table) free(des_hash_table);
        if (des_chain_next) free(des_chain_next);

        zone_db_entry_t **new_entries = calloc(added_count > 0 ? added_count : 1, sizeof(zone_db_entry_t*));
        if (!new_entries) {
            free(added_members); free(removed_members); free(coo_evicted_members);
            free(coo_new);
            cat_ops_free(&cops);
            abort_rebuild_snapshot(new_snap, "catalog new_entries");
            return NULL;
        }
        int actual_added_count = 0;
        /* The new members are entries with their initial reference until the plan below wraps them in elements of the catalog view's
         * directory; an error before that frees them directly (free_zone_db_entry()). */
        for (int i = 0; i < added_count; i++) {
            zone_db_entry_t *entry = create_new_zone_entry(added_members[i].domain, catalog_view_name);
            if (!entry) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s' owned by %s, skipping",
                       added_members[i].domain, catalog_entry_to_update->domain);
                continue;
            }
            ixfr_history_set_depth(entry, ixfr_history_effective(active_config, NULL));
            entry->owning_catalog_domain = strdup(catalog_entry_to_update->domain);
            entry->catalog_member_unique_id = strdup(added_members[i].unique_id);
            if (!entry->owning_catalog_domain || !entry->catalog_member_unique_id) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s' owned by %s, skipping",
                       added_members[i].domain, catalog_entry_to_update->domain);
                free_zone_db_entry(entry);
                continue;
            }
            syslog(LOG_INFO, "[Catalog] Added new member '%s' (unique-id: %s) owned by %s", added_members[i].domain, added_members[i].unique_id, catalog_entry_to_update->domain);
            entry->is_catalog_member = true;
            entry->source = ZONE_SRC_CATALOG;
            entry->kind = ZONE_KIND_SECONDARY;
            entry->is_secondary = true;
            if (added_members[i].group_count > 0) {
                entry->groups = calloc(added_members[i].group_count, sizeof(char*));
                if (entry->groups) {
                    entry->group_count = added_members[i].group_count;
                    for (int g = 0; g < added_members[i].group_count; g++) {
                        entry->groups[g] = strdup(added_members[i].groups[g]);
                    }
                }
            }
            bool has_master = catalog_cfg && zext(catalog_cfg)->masters_count > 0 && zext(catalog_cfg)->masters[0].ip != NULL;
            /* the key written on the first primaries element and the zone's tsig-key are kept apart: xfr_build_primaries() ranks them with the key of
             * the server statement that covers the primary (peer_key_name(): element, server statement, zone) */
            const char *elem_key = has_master ? zext(catalog_cfg)->masters[0].key : NULL;
            const char *zone_key = catalog_cfg ? zext(catalog_cfg)->tsig_key : NULL;
            if (elem_key && !elem_key[0]) elem_key = NULL;
            if (zone_key && !zone_key[0]) zone_key = NULL;
            if (has_master || zone_key) {
                entry->catalog_master = calloc(1, sizeof(*entry->catalog_master));
                if (entry->catalog_master && has_master) {
                    strncpy(entry->catalog_master->ip, zext(catalog_cfg)->masters[0].ip, sizeof(entry->catalog_master->ip) - 1);
                    entry->catalog_master->port = zext(catalog_cfg)->masters[0].port;
                }
                if (entry->catalog_master && elem_key)
                    strncpy(entry->catalog_master->key, elem_key, sizeof(entry->catalog_master->key) - 1);
                if (entry->catalog_master && zone_key)
                    strncpy(entry->catalog_master->zone_key, zone_key, sizeof(entry->catalog_master->zone_key) - 1);
            }
            atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
            new_entries[actual_added_count++] = entry;
        }
        added_count = actual_added_count;

        /* D1a: the new snapshot lists the same directories as the old one.  The catalog view's directory is changed in place (the
         * removed and evicted members leave, the new ones come in, the DB zones that a new member hides are replaced by it and those
         * that a removed member hid come back): the work is proportional to the members that change, whatever the number of zones.
         * Everything that can fail is done before the first change. */
        free(new_snap);
        new_snap = old_snap ? snap_clone_locked(old_snap) : calloc(1, sizeof(*new_snap));
        view_snapshot_t *cvs = (new_snap && catalog_view_name) ? snapshot_find_view(new_snap, catalog_view_name) : NULL;
        zdir_t *cdir = cvs ? cvs->dir : NULL;
        int total_deleted = removed_count + coo_evicted_count;
        dplan_t pl;
        memset(&pl, 0, sizeof(pl));
        zdir_elem_t **new_els = calloc(added_count > 0 ? added_count : 1, sizeof(*new_els));
        size_t nels = 0;
        bool plan_ok = new_snap != NULL && new_els != NULL;
        if (plan_ok && !old_snap) atomic_init(&new_snap->reader_count, 0);
        if (plan_ok && cdir) {
            pl.dir = cdir;
            int64_t order = (int64_t)atomic_load_explicit(&cdir->live, memory_order_relaxed);
            for (int i = 0; plan_ok && i < added_count; i++) {
                zdir_elem_t *el = zdir_elem_new_owned(new_entries[i], 0, order++);
                if (!el) {
                    plan_ok = false;
                    break;
                }
                new_els[nels++] = el;                                         /* (the element has the entry's reference now) */
                plan_ok = dplan_push(&pl.add, &pl.nadd, &pl.capadd, el);
                /* the element of the same name that the member replaces (a DB zone that it hides) also leaves the tick list: it stays in the
                 * registry, hidden */
                zdir_elem_t *ex = plan_ok ? zdir_lookup(cdir, el->name) : NULL;
                if (ex && (ex->kind & ZDIR_K_STATIC))
                    syslog(LOG_WARNING, "[Catalog] member '%s' of '%s' replaces the zone of the same name in a zone { } block of view '%s': the member is served, "
                           "the configured zone is not (it is not listed or ticked either) until the next reconfiguration", el->name, catalog_entry_to_update->domain,
                           catalog_view_name ? catalog_view_name : "");
                if (ex) plan_ok = dplan_push(&pl.rem, &pl.nrem, &pl.caprem, ex);
            }
            for (int j = 0; plan_ok && j < total_deleted; j++) {
                const catalog_member_id_t *del = (j < removed_count) ? &removed_members[j] : &coo_evicted_members[j - removed_count];
                zdir_elem_t *ex = zdir_lookup(cdir, del->domain);
                zone_db_entry_t *en = zdir_entry(ex);
                if (en && en->is_catalog_member && strcmp(zone_entry_catalog_uid(en), del->unique_id) == 0)
                    plan_ok = dplan_push(&pl.rem, &pl.nrem, &pl.caprem, ex);
            }
            if (plan_ok && pl.nrem > 1) qsort(pl.rem, pl.nrem, sizeof(*pl.rem), cmp_ptr);
            /* D17-1: a catalog member that left uncovers the DB zone of its name, unless another entry has the name */
            for (int j = 0; plan_ok && j < removed_count; j++) {
                dbreg_zone_t *hz = dbreg_catalog_hidden_zone_locked(catalog_view_name, removed_members[j].domain);
                if (!hz) continue;
                zdir_elem_t *ex = zdir_lookup(cdir, hz->name);
                bool taken = ex && !(pl.nrem && ptr_in_sorted(pl.rem, pl.nrem, ex));
                for (size_t k = 0; k < nels && !taken; k++) taken = domain_names_match_ci(new_els[k]->name, hz->name);
                if (taken) continue;
                plan_ok = dplan_push(&pl.add, &pl.nadd, &pl.capadd, hz) && dplan_push(&pl.unhide, &pl.nunhide, &pl.capunhide, hz);
                if (plan_ok)
                    syslog(LOG_NOTICE, "[DB] zone %s (view '%s') is served from the DB again: the catalog member is gone", hz->name,
                           catalog_view_name);
            }
            plan_ok = plan_ok && dplan_finish(&pl);
        }
        if (!plan_ok) {                                 /* nothing was changed */
            dplan_free(&pl);
            for (size_t k = 0; k < nels; k++) zdir_elem_release(new_els[k]);
            for (int k = (int)nels; k < actual_added_count; k++) free_zone_db_entry(new_entries[k]);
            free(new_els);
            free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
            free(coo_new);
            cat_ops_free(&cops);
            abort_rebuild_snapshot(new_snap, "catalog plan");
            return NULL;
        }
        /* nothing can fail from here on: the CoO intentions, the hidden DB zones, the owners and groups of the members */
        cat_coo_apply(catalog_entry_to_update->domain, coo_new, coo_new_n);
        cat_ops_apply(&cops, catalog_view_name ? catalog_view_name : "");
        free(coo_new);
        cat_ops_free(&cops);
        if (cdir) {
            if (added_count > 0 || total_deleted > 0) {
                g_rebuild_sets_changed = true;                /* a reload looks at the glue of dependents again */
                /* the tick does the same for a delta outside a reload: a member that left published nothing */
                if (total_deleted > 0) atomic_store_explicit(&g_glue_dirty, true, memory_order_release);
            }
            dplan_apply(&pl);
            dplan_free(&pl);
        } else {
            /* the catalog's view has no directory to put the members in: they are dropped (the old code had no view for them either) */
            for (int k = 0; k < actual_added_count; k++) free_zone_db_entry(new_entries[k]);
        }
        free(new_els);

        free(added_members);
        free(removed_members);
        free(coo_evicted_members);
        free(new_entries);

        if (catalog_entry_to_update) {
            // handled above
            if (catalog_entry_to_update->catalog_members) free_catalog_member_ids(catalog_entry_to_update->catalog_members, catalog_entry_to_update->catalog_member_count);
            catalog_entry_to_update->catalog_members = new_desired_members;
            catalog_entry_to_update->catalog_member_count = new_desired_count;
        }
    }

    /* in view order, so that a view that shares a zone finds the owner's entry in an earlier view whose directory is done; the tick
     * lists of the directories that were just built (the other modes share the old directories, tick lists included) */
    const view_config_t *cv = active_config ? active_config->views : NULL;
    for (size_t v = 0; active_config && !reused && v < new_snap->view_count; v++, cv = cv ? cv->next : NULL) {
        view_snapshot_t *vs = &new_snap->views[v];
        if (cv && cv->in_view_zones && !view_append_shared(new_snap, vs, cv)) {
            abort_rebuild_snapshot(new_snap, "shared entries");
            return NULL;
        }
        if (!zdir_tick_init(vs->dir)) {
            syslog(LOG_ERR, "[Core] Tick list allocation failed for view '%s', aborting snapshot rebuild", vs->name ? vs->name : "unknown");
            abort_rebuild_snapshot(new_snap, "tick list");
            return NULL;
        }
    }

    /* the registry is the source of truth: what the ingest threads queued for the old snapshot is in (or out of) this
     * one already (full configuration mode); the catalog delta copies the old entries, so its queue stays valid */
    /* (a reused view copied the old entries, so what the ingest thread queued for them stays valid, as in the catalog delta;
     * dbreg_pending_drop_gone_locked() dropped the queues of the views that left the configuration) */
    if (active_config && !reused) dbreg_pending_drop_locked();
    uint64_t retire_epoch = rcu_writer_publish(&g_zone_db_active, new_snap);
    if (old_snap) {
        old_snap->retire_epoch = retire_epoch;
        gc_retire_locked(old_snap);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);

    if (old_snap) gc_start_pending();

    return new_snap;
}

int rebuild_zone_db_from_config(server_config_t *config, bool skip_unchanged) {
    return rebuild_zone_db_from_config_ext(config, skip_unchanged, NULL, 0);
}

/* 戻り値: 読み込みに失敗したプライマリゾーンの数 (D-13)。スナップショットを作れなければ -1。
 * failed が NULL でなければ、失敗したゾーン名を ", " 区切りで入れる (入りきらなければ "..." で終える) */
int rebuild_zone_db_from_config_ext(server_config_t *config, bool skip_unchanged, char *failed, size_t failed_sz) {
    int nfailed = 0;
    if (failed && failed_sz > 0) failed[0] = '\0';
    /* 新しいエントリはスナップショットを作るときに読み込む。読み込めたものを下で 2 度読まない */
    uint64_t first_new_id = atomic_load_explicit(&g_zone_entry_id, memory_order_relaxed);
    zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(config, NULL, NULL, NULL, NULL, 0);
    if (!new_snap) {
        syslog(LOG_ERR, "[Core] Failed to rebuild zone DB snapshot from config due to allocation failure. Reload aborted.");
        return -1;
    }

    size_t since_retire = 0;
    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
            if (snap) {
                zone_db_entry_t *entry = snapshot_get_zone_in_view(snap, v->name, z->domain);
                if (entry && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                    struct stat st;
                    if (entry->id > first_new_id && atomic_load_explicit(&entry->publish_order, memory_order_seq_cst) != 0) {
                        /* この再構築で作って読み込み済み */
                    } else if (skip_unchanged && stat_via_dir_cache(z->file, &st) == 0 && entry->last_loaded_mtime != 0 &&
                               st.st_mtime == entry->last_loaded_mtime && st.st_size == entry->last_loaded_size) {
                        /* reconfig only: a full reload reads every zone file again (it also drops dynamic updates, RFC 2136
                         * changes are not written back) */
                        syslog(LOG_INFO, "[Config] zone '%s' file unchanged (mtime match), skipping reload", z->domain);
                    } else if (reload_master_zone(entry, z) != RELOAD_OK) {
                        nfailed++;
                        if (failed && failed_sz > 0) {
                            size_t used = strlen(failed);
                            int w = snprintf(failed + used, failed_sz - used, "%s%s", used ? ", " : "", z->domain);
                            if (w < 0 || (size_t)w >= failed_sz - used) {
                                /* 入りきらない: 末尾を "..." にする */
                                if (failed_sz >= 4) memcpy(failed + failed_sz - 4, "...", 4);
                            }
                        }
                    } else if (++since_retire >= 1024) {
                        /* S2: 古い版をまとめて解放する (全ゾーンの 2 版分を同時に持たない) */
                        zone_retire_process(true);
                        since_retire = 0;
                    }
                }
                release_zone_snapshot(snap);
            }
        }
    }

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            if (z->is_catalog && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
                if (snap) {
                    zone_db_entry_t *entry = snapshot_get_zone_in_view(snap, v->name, z->domain);
                    if (entry) {
                        catalog_process_membership(entry, z, v->name);
                    }
                    release_zone_snapshot(snap);
                }
            }
        }
    }

    /* S2: 兄弟ゾーンのアドレスを使うグルーを作り直す。以前は全ゾーンの arena を複製して prelink し
     * 直していた (Pass 2)。今は兄弟ゾーンが後から読み込まれた・変わった・増減したゾーンだけ、
     * グルーだけを差し替える。ゾーンの増減は公開を伴わないので、増減があった再構築の後は必ず調べる
     * (旧 view をそのまま引き継いだ reload は増減がなく、公開は g_glue_dirty を立てる)。 */
    zone_glue_refresh_dependents(g_rebuild_sets_changed);
    zone_retire_process(true);
    return nfailed;
}

void zone_arena_clear_data_pools(zone_arena_t *arena) {
  if (!arena) return;
  free(arena->image);
  arena->image = NULL;
  free(arena->glue);
  arena->glue = NULL;
  for (int i = 0; i < arena->data_pool_count; i++) {
    if (arena->data_pools[i]) {
      free(arena->data_pools[i]);
      arena->data_pools[i] = NULL;
    }
  }
  zone_arena_free_sorted_indexes(arena);
  if (arena->locations) {
    free(arena->locations);
    arena->locations = NULL;
    arena->location_count = 0;
  }
  if (arena->bind_location_tags) {
    free_ecs_tags_array(arena->bind_location_tags, arena->bind_location_tag_count);
    arena->bind_location_tags = NULL;
    arena->bind_location_tag_count = 0;
  }
  if (arena->bind_ecs_tags) {
    free_ecs_tags_array(arena->bind_ecs_tags, arena->bind_ecs_tag_count);
    arena->bind_ecs_tags = NULL;
    arena->bind_ecs_tag_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < arena->bind_ecs_trusted_resolver_count; i++) {
      free(arena->bind_ecs_trusted_resolvers[i]);
    }
    free(arena->bind_ecs_trusted_resolvers);
    arena->bind_ecs_trusted_resolvers = NULL;
    arena->bind_ecs_trusted_resolver_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers_parsed) {
    free(arena->bind_ecs_trusted_resolvers_parsed);
    arena->bind_ecs_trusted_resolvers_parsed = NULL;
  }
  arena->rcache_ok = false;
  atomic_store_explicit(&arena->generation, 0, memory_order_relaxed);
  arena->count = 0;
  arena->data_pool_count = 0;
  arena->pool_bytes = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
}

/* S5 B-2: 公開済みのイメージ src->image から dst に builder を作る (UPDATE と IXFR で、公開済みのゾーンに差分を当てる前の
 * 複製の代わり)。dst は空にしてからイメージを zone_image_thaw() する: レコードはファイルの順、索引も作ってある。
 * 0 = 成功。失敗したら dst は空にする。 */
int thaw_zone_arena(const zone_version_t *src, zone_arena_t *dst) {
  zone_arena_clear_data_pools(dst);
  if (!src || !src->image) return -1;
  if (zone_image_thaw(src->image, dst) != 0) {
    zone_arena_clear_data_pools(dst);
    return -1;
  }
  return 0;
}

/*
 * dns_xfr_store.c - the secondaries keep what they transferred in the zone store (0.7; see dns_xfr_store.h and planing_0.7.x_secondary_store.md).
 */
#include "dns_xfr_store.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "dns_catalog_zone.h"
#include "dns_db_ingest.h"
#include "dns_db_store.h"
#include "dns_epoch_rcu.h"
#include "dns_log.h"
#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"
#include "dns_utils.h"
#include "dns_zone_image.h"
#include "dns_zone_parser.h"

#define XFR_RESTORE_NET_MS   30000      /* R2': no progress of the restore thread for this long while entries wait: the tick gives up on them */
/* TEST ONLY (karidns-evict and the coverage build, make evict; -DKARIDNS_TEST_EVICT, never a production build): the knobs of tests/run_secondary_store_test.sh, read from the environment
 * once at the core start.  Not in the release binary: it does not read these variables, and a server that is started with them set does nothing different. */
#define XFR_SLICE_ZONES      64         /* W11: the restore works in slices (it is not the ticker) */
#define XFR_EVENTS_PER_MIN   20         /* D9: per-zone event lines a minute at most; the rest go into the next summary */
#define XFR_SUMMARY_ABOVE    20         /* D9: more expired zones than this: one summary line instead of the per-zone hourly lines */
#define XFR_HOURLY_S         3600

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void progress_stamp(void) { atomic_store_explicit(&g_xfr_restore_progress_ms, mono_ms(), memory_order_release); }

/* the zone ids of the reserved view: a bitmap (zone ids are dense), maintained by the puts and deletes of this module; built by one store_iter() at the start (W7) */
typedef struct { uint64_t *w; size_t nw; } zbits_t;

static struct {
  _Atomic(store_t *) st;
  _Atomic int vid;
  pthread_t thr;
  bool thr_started;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  uint64_t req_gen, done_gen;
  bool stop, first_done, quarantined, created;
  int64_t t0_ms;
  pthread_mutex_t zmu;
  zbits_t zs;
  _Atomic bool zs_built;
#ifdef KARIDNS_TEST_EVICT
  /* the test knobs (KARIDNS_TEST_XFR_PUT_FAIL: the next n appends of an image find no room (test_append_fault()); KARIDNS_TEST_XFR_RX_CAP: the cap on received settings texts; _KILL_BEFORE_PUT: the zone ('1' = any) whose put is preceded by a SIGKILL; _STALE_LOG_INTERVAL: the seconds between
   * the still-expired lines; _RESTORE_HOLD_MS: the restore thread waits this long before its first pass, without progress; _RESTORE_NET_MS: the safety net's 30 s) */
  _Atomic long put_fail;
  char kill_zone[256];
  unsigned log_interval;
  unsigned hold_ms, net_ms;
#endif
  _Atomic int64_t nospc_logged_ms, unstorable_logged;
  _Atomic int64_t unbulk_logged_ms;                   /* 0.7: the last line about a write put off for the end of an unlogged fill (xs_unbulk()) */
  _Atomic bool retry_want;                            /* ... a write was put off: the restore thread makes a pass once the end is on disk */
  _Atomic uint64_t put_off;                           /* the writes put off so */
  /* the start's figures */
  _Atomic uint64_t s_restored, s_expired, s_file, s_none;
  /* counters */
  _Atomic uint64_t puts, puts_uptodate, put_nospc, put_errors, state_writes, state_stale, state_skipped, orphans_deleted, unstorable;
  _Atomic uint64_t restored, restored_expired, file_won, restore_bad, restore_identity, restore_ms, restore_timeouts, gc_deleted;
  /* D9 */
  _Atomic uint64_t stale_capped, expire_events, expired_zones;
  /* P3 (R3): the restore jobs of the `d` copies the start gave the ingest thread, the ones that ran; dbj_hold: one could not be given (the `d` copies are kept this run) */
  _Atomic uint64_t dbj_posted, dbj_done;
  _Atomic bool dbj_hold;
  /* P4 (R1): restores that put the settings of the primary in force again; restores whose settings were not kept, or are not in settings.dat any more (the whole zone is asked for) */
  _Atomic uint64_t rx_restored, rx_lost;
  /* the expired zones of the tick's last walk: answered from stale data, answered SERVFAIL (karictl status) */
  _Atomic uint64_t expired_stale, expired_servfail;
  /* #203 review (R2'): the time the item the restore thread works on may take beyond the 30 s (a big image is read and checked in one step) */
  _Atomic int64_t item_allow_ms;
} X = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .zmu = PTHREAD_MUTEX_INITIALIZER, .vid = -1 };

#ifdef KARIDNS_UNIT_TEST
void (*_Atomic xfr_store_test_restore_hook)(zone_db_entry_t *e);
void xfr_store_test_item_allow(int64_t ms) { atomic_store_explicit(&X.item_allow_ms, ms, memory_order_relaxed); }
#endif

int xfr_store_vid(void) { return atomic_load_explicit(&X.vid, memory_order_acquire); }
bool xfr_store_active(void) { return atomic_load_explicit(&g_xfr_store_mode, memory_order_acquire) == XFRM_ACTIVE; }

/* 2.2: two configured views whose names have one tag (CRC-32C of the lowercased name) would share keys: the later one's zones are not persisted (a WARNING at the check).  The set holds a
 * 64-bit hash of each such view's lowercased name (0 = empty slot); the transfer and restore threads read it without a lock, the check (the restore thread's pass) is its only writer. */
#define XFR_NOKEY_MAX 64
static _Atomic uint64_t g_nokey[XFR_NOKEY_MAX];
static uint64_t view_hash(const char *v) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (const char *p = v ? v : ""; *p; p++) { h ^= (uint8_t)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p); h *= 0x100000001b3ull; }
  return h ? h : 1;
}
static bool view_nokey(const char *view) {
  const uint64_t h = view_hash(view);
  for (int i = 0; i < XFR_NOKEY_MAX; i++)
    if (atomic_load_explicit(&g_nokey[i], memory_order_acquire) == h) return true;
  return false;
}

int xfr_store_config_check(const server_config_t *cfg) {
  uint64_t want[XFR_NOKEY_MAX];
  int nw = 0;
  for (const view_config_t *v = cfg ? cfg->views : NULL; v; v = v->next) {
    if (!v->name) continue;
    const uint32_t tag = xfr_view_tag(v->name);
    for (const view_config_t *u = cfg->views; u != v; u = u->next) {      /* (an earlier view of the same tag keeps the key; this one does not) */
      if (!u->name || xfr_view_tag(u->name) != tag || strcasecmp(u->name, v->name) == 0) continue;
      const uint64_t h = view_hash(v->name);
      bool dup = false;
      for (int i = 0; i < nw; i++) dup = dup || want[i] == h;
      if (dup) break;
      if (nw == XFR_NOKEY_MAX) {
        syslog(LOG_ERR, "[Store] more than %d views share a store tag with an earlier view: the copies of the secondary zones of view '%s' are not told apart by the key (their identity still keeps them from being used by the wrong zone)", XFR_NOKEY_MAX, v->name);
        break;
      }
      if (!view_nokey(v->name))
        syslog(LOG_WARNING, "[Store] the views '%s' and '%s' map to the same store tag %08x (CRC-32C of the view name): the secondary zones of view '%s' are kept in memory only; rename one of the views", u->name, v->name, tag, v->name);
      want[nw++] = h;
      break;
    }
  }
  /* the new set is made visible before the old one is taken away (a reader never sees a view that stays flagged as clear) */
  for (int i = 0; i < nw; i++) {
    bool in = false;
    int freei = -1;
    for (int j = 0; j < XFR_NOKEY_MAX; j++) {
      const uint64_t g = atomic_load_explicit(&g_nokey[j], memory_order_relaxed);
      if (g == want[i]) in = true;
      if (g == 0 && freei < 0) freei = j;
    }
    if (!in && freei >= 0) atomic_store_explicit(&g_nokey[freei], want[i], memory_order_release);
  }
  for (int j = 0; j < XFR_NOKEY_MAX; j++) {
    const uint64_t g = atomic_load_explicit(&g_nokey[j], memory_order_relaxed);
    bool keep = false;
    for (int i = 0; i < nw; i++) keep = keep || want[i] == g;
    if (g && !keep) atomic_store_explicit(&g_nokey[j], 0, memory_order_release);
  }
  return nw;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* text helpers (no time zone data: the Backend is in capability mode)                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static void fmt_utc(time_t t, char *out, size_t cap) {
  if (t <= 0) {
    snprintf(out, cap, "never");
    return;
  }
  int64_t days = (int64_t)t / 86400, secs = (int64_t)t % 86400;
  /* civil from days (H. Hinnant's algorithm): no gmtime(), which may look for a zoneinfo file */
  int64_t z = days + 719468, era = (z >= 0 ? z : z - 146096) / 146097;
  int64_t doe = z - era * 146097, yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = yoe + era * 400, doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
  int64_t d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) y++;
  snprintf(out, cap, "%04lld-%02lld-%02lldT%02lld:%02lld:%02lldZ", (long long)y, (long long)m, (long long)d, (long long)(secs / 3600), (long long)(secs / 60 % 60),
           (long long)(secs % 60));
}
static void fmt_dur(int64_t s, char *out, size_t cap) {
  if (s < 0) s = 0;
  if (s >= 86400) snprintf(out, cap, "%lldd%lldh", (long long)(s / 86400), (long long)(s % 86400 / 3600));
  else if (s >= 3600) snprintf(out, cap, "%lldh%lldm", (long long)(s / 3600), (long long)(s % 3600 / 60));
  else if (s >= 60) snprintf(out, cap, "%lldm%llds", (long long)(s / 60), (long long)(s % 60));
  else snprintf(out, cap, "%llds", (long long)s);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the zone id set                                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

static void zs_add(uint32_t zid) {
  if (zid == STORE_NONE) return;
  pthread_mutex_lock(&X.zmu);
  const size_t w = zid / 64;
  if (w >= X.zs.nw) {
    size_t nw = X.zs.nw ? X.zs.nw : 16;
    while (nw <= w) nw *= 2;
    uint64_t *n = realloc(X.zs.w, nw * sizeof(*n));
    if (!n) {                                         /* (no memory: the GC does not know the copy; a later start's scan finds it) */
      pthread_mutex_unlock(&X.zmu);
      return;
    }
    memset(n + X.zs.nw, 0, (nw - X.zs.nw) * sizeof(*n));
    X.zs.w = n;
    X.zs.nw = nw;
  }
  X.zs.w[w] |= 1ull << (zid % 64);
  pthread_mutex_unlock(&X.zmu);
}
static void zs_del(uint32_t zid) {
  if (zid == STORE_NONE) return;
  pthread_mutex_lock(&X.zmu);
  if (zid / 64 < X.zs.nw) X.zs.w[zid / 64] &= ~(1ull << (zid % 64));
  pthread_mutex_unlock(&X.zmu);
}
/* a copy of the set (the GC walks it without the mutex) */
static bool zs_copy(zbits_t *out) {
  pthread_mutex_lock(&X.zmu);
  out->nw = X.zs.nw;
  out->w = out->nw ? malloc(out->nw * sizeof(uint64_t)) : NULL;
  if (out->w) memcpy(out->w, X.zs.w, out->nw * sizeof(uint64_t));
  pthread_mutex_unlock(&X.zmu);
  return out->nw == 0 || out->w != NULL;
}

/* the only full scan (W7): the records of the reserved view, by zone id, in chunks (the read section is left between them) */
static void zs_build(store_t *st, uint16_t vid) {
  uint32_t cur = 0;
  for (;;) {
    store_zone_t z;
    int n = 0, r = 1;
    store_read_lock();
    while (n < 4096 && (r = store_iter(st, &cur, &z)) != 0) {
      if (r == 1 && z.view == vid) zs_add(z.zid);
      n++;
    }
    store_read_unlock();
    progress_stamp();
    if (r == 0) break;
  }
  atomic_store_explicit(&X.zs_built, true, memory_order_release);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* what a secondary entry is to the store                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
  int kind;
  char key[XFR_KEY_MAX + 1];
  int klen;
  uint64_t identity;
  uint32_t primaries;
  bool has_file;
  xfr_eff_t eff;
  uint32_t view_tag;
  bool db;                                            /* a database secondary or catalog consumer (kind 4 / 5, P3) */
  uint32_t settings;                                  /* ... the id of its settings in settings.dat (2.1: the record's settings), set by the writes after a refresh, outside the read section */
} xinfo_t;

static void note_unstorable(const zone_db_entry_t *e, const char *why) {
  atomic_fetch_add_explicit(&X.unstorable, 1, memory_order_relaxed);
  if (!atomic_exchange_explicit(&X.unstorable_logged, 1, memory_order_relaxed))
    syslog(LOG_NOTICE, "[Store] secondary zone '%s' (view '%s') is not kept in the zone store: %s (it is kept in memory only, as before; xfr.unstorable)", e->domain, zone_vname(e), why);
}

/* The key, the identity and the primaries digest of the entry, from the configuration in force.  Inside an RCU read section (the configuration and the snapshot are
 * read).  false: not a zone this module stores (no name the store can hold; a database secondary whose domains.id is not known yet). */
static bool entry_info(zone_db_entry_t *e, const server_config_t *cfg, zone_db_snapshot_t *snap, xinfo_t *xi) {
  memset(xi, 0, sizeof(*xi));
  if (!e || !e->is_secondary) return false;
  const char *view = zone_vname(e);
  if (view_nokey(view)) return false;                  /* (2.2: the view's tag is another view's: not persisted; the WARNING is the config check's) */
  if (e->source == ZONE_SRC_DB) {
    /* P3 (3.3): a database secondary (SLAVE, kind 4) or catalog consumer (CONSUMER, kind 5).  Its kind is the one of its own settings block (dbcfg; the received settings of B8t-2 do not make a
     * zone a catalog), its identity has the domains.id of its row (R1: the record's source id stays 0), its primaries are those the transfer asks (zone_entry_config(): dbcfg, or rxcfg) */
    const zone_config_t *dc = atomic_load_explicit(&e->dbcfg, memory_order_acquire);
    const zone_x_t *dx = zone_x(e);
    const int64_t sid = dx ? atomic_load_explicit(&((zone_x_t *)dx)->xfr_db_sid, memory_order_acquire) : 0;
    if (!dc || sid == 0) return false;                 /* (an entry the ingest thread has not given its domain id: not stored until it has, the next refresh) */
    if (!db_store_name_ok(e->domain)) {                /* (W12: the root zone and the names the store cannot name in a database view live in the heap directory only, un_apply()) */
      note_unstorable(e, "the zone store cannot name it in a database view");
      return false;
    }
    const zone_config_t *tcfg = zone_entry_config((server_config_t *)cfg, e);
    xi->db = true;
    xi->kind = dc->is_catalog ? XFR_K_DB_CONSUMER : XFR_K_DB_SLAVE;
    xi->view_tag = xfr_view_tag(view);
    uint32_t pd = 0;
    if (tcfg) {
      const zone_ext_t *x = zext(tcfg);
      for (int i = 0; i < x->masters_count; i++)
        if (x->masters[i].ip) pd = xfr_primaries_add(pd, x->masters[i].ip, x->masters[i].port, x->masters[i].key);
      pd = xfr_primaries_add(pd, "", 0, x->tsig_key);
    }
    xi->primaries = pd;
    xfr_opts_effective(cfg, tcfg, view, &xi->eff);
    xi->identity = xfr_identity(xi->kind, e->domain, view, NULL, sid);
    xi->klen = xfr_key_make(view, xi->kind, e->domain, xi->key, sizeof(xi->key));
    if (xi->klen < 0) {
      note_unstorable(e, "its name is longer than 245 octets");
      return false;
    }
    return true;
  }
  const zone_config_t *zcfg = e->is_catalog_member ? NULL : zone_entry_config((server_config_t *)cfg, e);
  xi->kind = e->is_catalog_member ? XFR_K_MEMBER : (zcfg && zcfg->is_catalog) ? XFR_K_CATALOG : XFR_K_CONFIG;
  xi->has_file = zcfg && zcfg->file;
  xi->view_tag = xfr_view_tag(view);
  /* the primaries the transfer asks (xfr_build_primaries(): a member takes its catalog zone's) */
  const zone_config_t *mcfg = zcfg;
  if (e->is_catalog_member) {
    const char *owner = zone_xr(e)->owning_catalog_domain;
    view_snapshot_t *vs = owner && snap ? snapshot_find_view(snap, view) : NULL;
    zone_db_entry_t *cat = vs ? find_zone_in_view(vs, owner) : NULL;
    const zone_config_t *cc = cat ? zone_entry_config((server_config_t *)cfg, cat) : NULL;
    if (cc && zext(cc)->masters_count > 0) mcfg = cc;
  }
  uint32_t pd = 0;
  if (mcfg) {
    const zone_ext_t *x = zext(mcfg);
    for (int i = 0; i < x->masters_count; i++)
      if (x->masters[i].ip) pd = xfr_primaries_add(pd, x->masters[i].ip, x->masters[i].port, x->masters[i].key);
    pd = xfr_primaries_add(pd, "", 0, x->tsig_key);
  } else if (zone_xr(e)->catalog_master) {
    const catalog_master_t *cm = zone_xr(e)->catalog_master;
    pd = xfr_primaries_add(pd, cm->ip, cm->port, cm->key);
    pd = xfr_primaries_add(pd, "", 0, cm->zone_key);
  }
  xi->primaries = pd;
  xfr_opts_effective(cfg, mcfg, view, &xi->eff);
  xi->identity = xfr_identity(xi->kind, e->domain, view, zone_entry_catalog_uid(e), 0);
  xi->klen = xfr_key_make(view, xi->kind, e->domain, xi->key, sizeof(xi->key));
  if (xi->klen < 0) {
    note_unstorable(e, "its name is longer than 245 octets");
    return false;
  }
  return true;
}

/* the same with the section and the snapshots taken here */
static bool entry_info_now(zone_db_entry_t *e, xinfo_t *xi) {
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  const bool ok = entry_info(e, cfg, snap, xi);
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  return ok;
}

/* M6: is the entry still the one the snapshot has for its view and zone?  A database secondary: the one the registry has (it is registered before the snapshot shows it; 3.1) */
static bool entry_current(zone_db_entry_t *e) {
  if (e->source == ZONE_SRC_DB) return dbreg_lookup_entry(zone_vname(e), e->domain) == e;     /* (compared, never dereferenced) */
  rcu_aux_read_lock();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  view_snapshot_t *vs = snap ? snapshot_find_view(snap, zone_vname(e)) : NULL;
  const bool cur = vs && find_zone_exact_in_view(vs, e->domain) == e;
  rcu_aux_read_unlock();
  return cur;
}

static int rec_get(store_t *st, uint16_t vid, const xinfo_t *xi, store_zone_t *z) {
  store_read_lock();
  const uint32_t zid = store_find(st, vid, xi->key, (size_t)xi->klen);
  const int r = zid == STORE_NONE ? -ENOENT : store_zone_get(st, zid, z);
  store_read_unlock();
  return r;
}

/* 0.7: a write of a copy is made durable as any other (the journal).  During an unlogged first fill of the store (store_bulk_begin(), which a configuration with secondaries does not begin) or before
 * its end is on disk, a copy written would be acknowledged and lost to the last bulk checkpoint on a crash: the write is put off (-EAGAIN), the end of the fill is asked for (the store's checkpoint
 * thread makes it; this thread does not wait), and the restore thread makes a pass once it is on disk (restore_thread(): the refreshes put off are written then, pass_run()).  The zone in memory
 * is served all the while; only its copy waits.  One line a minute at most. */
static int xs_unbulk(store_t *st) {
  if (!store_bulk_pending(st)) return 0;
  (void)store_bulk_end(st, 0);
  atomic_fetch_add_explicit(&X.put_off, 1, memory_order_relaxed);
  if (!atomic_exchange_explicit(&X.retry_want, true, memory_order_acq_rel)) {       /* (the restore thread looks at it every second from now; X.mu is never held around a store write) */
    pthread_mutex_lock(&X.mu);
    pthread_cond_broadcast(&X.cv);
    pthread_mutex_unlock(&X.mu);
  }
  const int64_t now = mono_ms(), last = atomic_load_explicit(&X.unbulk_logged_ms, memory_order_relaxed);
  if (now - last >= 60000 && atomic_compare_exchange_strong_explicit(&X.unbulk_logged_ms, &(int64_t){ last }, now, memory_order_relaxed, memory_order_relaxed))
    syslog(LOG_NOTICE, "[Store] the copies of secondary zones are stored once the end of the unlogged fill of the store is on disk (%" PRIu64 " write(s) put off so far); the zones are served meanwhile",
           atomic_load_explicit(&X.put_off, memory_order_relaxed));
  return -EAGAIN;
}

static void rec_delete(store_t *st, uint16_t vid, const char *key, size_t klen, uint32_t zid) {
  if (xs_unbulk(st) < 0) return;
  if (store_delete_name(st, vid, key, klen) == 0) zs_del(zid);
}

static uint16_t img_flags(const zone_image_t *img) {
  uint16_t f = STORE_F_XFR;
  if (img->flags & ZONE_IMAGE_F_ALIAS) f |= STORE_F_ALIAS;
  if (img->flags & ZONE_IMAGE_F_WILDCARD) f |= STORE_F_WILDCARD;
  if (img->n_nsec > 0 || img->n_n3chains > 0) f |= STORE_F_PRESIGNED;
  return f;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the writes at the end of a refresh (3.1)                                                                        */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
  zone_version_t *v;
  uint32_t serial;
  time_t last_ok, expire_at;
  uint8_t origin;
  bool rx;
  zone_ext_shared_t *rxsh;                            /* P4 (R1): the settings the primary sent (a reference; NULL: none) */
} pin_t;

/* R2 (D5): settings the primary sent are in force for the zone (rxcfg; with primary-settings no they are kept aside and not used: nothing is lost by not persisting them) */
static bool rx_in_force(const zone_db_entry_t *e) {
  const zone_x_t *x = zone_x(e);
  /* (xfr_axfr_once: the settings of this copy are still lost, as the restore found it, until the whole transfer it asks for has come: a state write meanwhile keeps the bit) */
  return x && (atomic_load_explicit(&x->rxcfg, memory_order_acquire) != NULL || atomic_load_explicit(&x->xfr_axfr_once, memory_order_relaxed));
}

/* the values of a state write, under the writer lock (rx_sh belongs to the writers) */
static void collect_locked(zone_db_entry_t *e, pin_t *p) {
  p->serial = atomic_load_explicit(&e->serial, memory_order_relaxed);
  p->last_ok = atomic_load_explicit(&e->last_successful_transfer, memory_order_relaxed);
  p->expire_at = atomic_load_explicit(&e->expire_at, memory_order_relaxed);
  p->origin = e->xfr_origin;
  p->rx = rx_in_force(e);
  const zone_x_t *x = zone_x(e);
  p->rxsh = x && x->rx_sh ? zone_ext_shared_ref(x->rx_sh) : NULL;
}

/* P4 (R1, D5): the id in settings.dat of the settings the primary sent (written once per text; outside every lock and read section: it may append to the file); 0: none, or not kept */
static uint32_t rx_id_of(const pin_t *p) { return p->rxsh ? db_store_rx_settings_id(p->rxsh) : 0; }

/* Values under the writer lock into locals; the version pinned with xfr_refs inside a read section (as dir_put_locked() does); both are left before the store is called (2.5) */
static bool pin_active(zone_db_entry_t *e, pin_t *p) {
  memset(p, 0, sizeof(*p));
  pthread_mutex_lock(&e->writer_lock);
  rcu_aux_read_lock();
  zone_version_t *v = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
  collect_locked(e, p);
  if (v && v->image && v->image->n_rrs > 0) {
    zone_image_soa_t nums;
    const uint32_t soa = zone_image_apex_soa(v->image);
    if (soa != ZONE_IMAGE_NONE && zone_image_soa(v->image, soa, NULL, 0, NULL, 0, &nums) == 0 && nums.serial == p->serial) {
      atomic_fetch_add_explicit(&v->xfr_refs, 1, memory_order_acq_rel);
      p->v = v;
    }
  }
  rcu_aux_read_unlock();
  pthread_mutex_unlock(&e->writer_lock);
  return p->v != NULL;
}
static void pin_release(pin_t *p) {
  if (p->v) atomic_fetch_sub_explicit(&p->v->xfr_refs, 1, memory_order_acq_rel);
  p->v = NULL;
  zone_ext_shared_unref(p->rxsh);
  p->rxsh = NULL;
}

/* rx_id: the id of the primary's settings in settings.dat (R1); settings in force that have none are lost at a restart (R2: the state says so, the restore asks for the whole zone) */
static void state_of(const xinfo_t *xi, const pin_t *p, uint32_t rx_id, time_t attempt_at, xfr_state_t *s) {
  memset(s, 0, sizeof(*s));
  s->kind = (uint8_t)xi->kind;
  s->identity = xi->identity;
  s->primaries = xi->primaries;
  xfr_state_set_times(s, p->last_ok, p->expire_at);
  if (p->origin == XFR_ORIGIN_FILE || p->origin == XFR_ORIGIN_STORE_FILE) s->flags |= XFR_SF_FROM_FILE;
  s->rx_settings = rx_id;
  if (p->rx && !rx_id) s->flags |= XFR_SF_RX_LOST;
  s->last_attempt = attempt_at <= 0 ? 0 : attempt_at > (time_t)UINT32_MAX ? UINT32_MAX : (uint32_t)attempt_at;
}

/* the whole image of the active version, with the state (NO_DEGRADE: no room keeps the old copy, M1) */
static int put_image(store_t *st, uint16_t vid, zone_db_entry_t *e, const xinfo_t *xi, time_t attempt_at) {
  pin_t p;
  {
    const int ur = xs_unbulk(st);
    if (ur < 0) return ur;
  }
  if (!pin_active(e, &p)) {
    pin_release(&p);
    return -ENOENT;
  }
  if (p.last_ok <= 0) p.last_ok = attempt_at;           /* (a version from a file without mtime: the refresh just confirmed it) */
  xfr_state_t s;
  state_of(xi, &p, rx_id_of(&p), attempt_at, &s);
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.flags = img_flags(p.v->image);
  m.serial = p.serial;
  m.settings = xi->settings;                            /* (P3, 2.1: a database secondary names its settings, so that the restore needs no loader; else 0) */
  m.stamp_time = (uint64_t)time(NULL);                  /* the save time of these bytes (D7) */
  xfr_state_encode(&s, m.digest);
#ifdef KARIDNS_TEST_EVICT
  if (X.kill_zone[0] && (strcmp(X.kill_zone, "1") == 0 || strcasecmp(X.kill_zone, e->domain) == 0)) {
    syslog(LOG_WARNING, "[Store] KARIDNS_TEST_XFR_KILL_BEFORE_PUT: the process is killed between the install of '%s' (serial %u) and its put", e->domain, p.serial);
    kill(getpid(), SIGKILL);
  }
#endif
  int r;
  if ((uint64_t)p.v->image->total_size > 0x7fffffffu) r = -EFBIG;
  else {
    uint32_t zid = STORE_NONE;
    r = store_put_ex(st, vid, xi->key, (size_t)xi->klen, &m, p.v->image, p.v->image->total_size, STORE_PUT_NO_DEGRADE, &zid);
    if (r == 0) zs_add(zid);
  }
  pin_release(&p);
  if (r == 0) {
    atomic_fetch_add_explicit(&X.puts, 1, memory_order_relaxed);
  } else if (r == -ENOSPC || r == -EDQUOT) {
    atomic_fetch_add_explicit(&X.put_nospc, 1, memory_order_relaxed);
    const int64_t now = mono_ms(), last = atomic_load_explicit(&X.nospc_logged_ms, memory_order_relaxed);
    if (last == 0 || now - last >= 60000) {
      atomic_store_explicit(&X.nospc_logged_ms, now, memory_order_relaxed);
      syslog(LOG_WARNING, "[Store] no room for the copy of secondary zone '%s' (view '%s'): the copy stored before (if any) and its state are kept, the next refresh stores it again "
                          "(xfr.put_nospc; after a restart in this state the zone may expire earlier than it would have)", e->domain, zone_vname(e));
    }
  } else if (r == -EFBIG) {
    atomic_fetch_add_explicit(&X.unstorable, 1, memory_order_relaxed);
    syslog(LOG_WARNING, "[Store] the copy of secondary zone '%s' is over 2 GiB and is not stored (xfr.unstorable)", e->domain);
  } else {
    atomic_fetch_add_explicit(&X.put_errors, 1, memory_order_relaxed);
    syslog(LOG_ERR, "[Store] the copy of secondary zone '%s' (view '%s') could not be stored: %s (xfr.put_errors)", e->domain, zone_vname(e), strerror(-r));
  }
  return r;
}

static int put_state(store_t *st, uint16_t vid, const xinfo_t *xi, uint32_t expect_serial, const xfr_state_t *s) {
  uint8_t dg[STORE_DIGEST_LEN];
  xfr_state_encode(s, dg);
  {
    const int ur = xs_unbulk(st);
    if (ur < 0) return ur;
  }
  const int r = store_set_digest(st, vid, xi->key, (size_t)xi->klen, expect_serial, xi->settings, dg, STORE_F_XFR, 0);
  if (r == 0) atomic_fetch_add_explicit(&X.state_writes, 1, memory_order_relaxed);
  else if (r == -ESTALE || r == -ENOENT) atomic_fetch_add_explicit(&X.state_stale, 1, memory_order_relaxed);       /* (replaced or gone meanwhile: the next outcome writes again) */
  else atomic_fetch_add_explicit(&X.put_errors, 1, memory_order_relaxed);
  return r;
}

static void after_refresh_pinned(store_t *st, uint16_t vid16, zone_db_entry_t *e, int outcome, time_t attempt_at);
static void after_refresh(zone_db_entry_t *e, int outcome, time_t attempt_at) {
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  if (!st || vid < 0 || !e) return;
  rcu_aux_thread_pin();                              /* (pin_active() enters a read section with the writer lock held: the slot is taken first, as xfr_attempt() does for the install) */
  after_refresh_pinned(st, (uint16_t)vid, e, outcome, attempt_at);
  rcu_aux_thread_unpin();
}

static void after_refresh_pinned(store_t *st, uint16_t vid16, zone_db_entry_t *e, int outcome, time_t attempt_at) {
  const int vid = vid16;
  xinfo_t xi;
  if (!entry_info_now(e, &xi)) return;
  if (xi.db) xi.settings = db_store_settings_id_of(e);  /* (P3: may append the text to settings.dat once; outside any read section, no lock held) */
  if (outcome != XFR_OUT_NONE && store_bulk_pending(st)) {              /* (0.7: put off until the end of the unlogged fill is on disk, xs_unbulk(); the restore thread's pass writes it) */
    zone_x_t *const x = zone_x_need(e);                                  /* (a secondary has its extension from the start; no memory: the write waits for the next refresh) */
    if (x) {
      atomic_store_explicit(&x->xfr_store_retry_at, attempt_at, memory_order_relaxed);
      atomic_store_explicit(&x->xfr_store_retry, outcome, memory_order_release);
    }
    (void)xs_unbulk(st);
    return;
  }
  store_zone_t z;
  const bool have = rec_get(st, (uint16_t)vid, &xi, &z) == 0;
  bool wrote = false;
  if (outcome == XFR_OUT_TRANSFERRED) {
    wrote = put_image(st, (uint16_t)vid, e, &xi, attempt_at) == 0;
  } else if (outcome == XFR_OUT_UPTODATE) {
    const uint32_t serial = atomic_load_explicit(&e->serial, memory_order_acquire);
    /* (a record of this key that is of another zone or kind, or whose state cannot be read, is not written over with this zone's state: it is put whole, 2.3 identity) */
    xfr_state_t old;
    const bool mine = have && xfr_state_decode(z.digest, sizeof(z.digest), &old) == 0 && old.kind == xi.kind && old.identity == xi.identity;
    if (mine && xfr_uptodate_action(have, z.state, z.flags, z.serial, serial) == XFR_UP_STATE) {
      pin_t p;
      memset(&p, 0, sizeof(p));
      pthread_mutex_lock(&e->writer_lock);
      collect_locked(e, &p);
      pthread_mutex_unlock(&e->writer_lock);
      xfr_state_t s;
      state_of(&xi, &p, rx_id_of(&p), attempt_at, &s);
      pin_release(&p);
      wrote = put_state(st, (uint16_t)vid, &xi, p.serial, &s) == 0;
    } else {
      /* M2: no record, a KNOWN one (a scrub, the cleaner, a bad image at the restore), another serial (a put that found no room), a zone from `file` never transferred, a GC race:
       * the whole active image */
      wrote = put_image(st, (uint16_t)vid, e, &xi, attempt_at) == 0;
      if (wrote) atomic_fetch_add_explicit(&X.puts_uptodate, 1, memory_order_relaxed);
    }
  } else if (outcome == XFR_OUT_FAILED && have && (z.flags & STORE_F_XFR)) {
    /* the attempt time and the failure bit; the stored last-ok and deadline stay as they were (2.3: a failure never moves the expire clock on disk) */
    xfr_state_t old, upd;
    if (xfr_state_decode(z.digest, sizeof(z.digest), &old) == 0 && old.kind == xi.kind && old.identity == xi.identity) {
      upd = old;
      upd.flags |= XFR_SF_FAILED;
      upd.last_attempt = attempt_at > 0 ? (uint32_t)attempt_at : 0;
      /* (P3: a database secondary whose settings changed writes the new id even when nothing else did) */
      if (z.settings == xi.settings && xfr_failure_skip(&old, &upd, time(NULL), atomic_load_explicit(&e->retry, memory_order_relaxed)))
        atomic_fetch_add_explicit(&X.state_skipped, 1, memory_order_relaxed);
      else
        wrote = put_state(st, (uint16_t)vid, &xi, z.serial, &upd) == 0;
    }
  }
  if (wrote) {
    (void)store_journal_wait(st, 4);                 /* (the journal bound, as the ingest thread: no lock is held here) */
    if (!entry_current(e)) {                         /* M6: the entry left while this was written (a reconfiguration, a catalog change): no orphan */
      store_zone_t nz;
      if (rec_get(st, (uint16_t)vid, &xi, &nz) == 0) {
        xfr_state_t ns;
        /* (another entry of the same key may own the record now: only a record of this entry's identity goes) */
        if (xfr_state_decode(nz.digest, sizeof(nz.digest), &ns) == 0 && ns.identity == xi.identity) {
          rec_delete(st, (uint16_t)vid, xi.key, (size_t)xi.klen, nz.zid);
          atomic_fetch_add_explicit(&X.orphans_deleted, 1, memory_order_relaxed);
        }
      }
    }
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the restore (4.3)                                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

enum { RS_OFF = 0, RS_NOT_PENDING, RS_NONE, RS_IDENTITY, RS_BAD, RS_FILE_WON, RS_HAS_VERSION, RS_RESTORED, RS_NOINFO, RS_MEMORY };

static void make_known(store_t *st, uint16_t vid, const xinfo_t *xi, const store_zone_t *z) {
  if (xs_unbulk(st) < 0) return;
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.flags = z->flags;
  m.serial = z->serial;
  m.settings = z->settings;
  m.stamp_gen = z->stamp_gen;
  m.stamp_time = z->stamp_time;
  memcpy(m.digest, z->digest, STORE_DIGEST_LEN);
  (void)store_set_known(st, vid, xi->key, (size_t)xi->klen, &m, NULL);
}

static void log_expired(zone_db_entry_t *e, time_t deadline, time_t last_ok, bool serving, bool restart) {
  char a[40], b[40];
  fmt_utc(deadline, a, sizeof(a));
  fmt_utc(last_ok, b, sizeof(b));
  kdns_logc(LOGC_GENERAL, LOG_WARNING, "[Zone] secondary-expired: expired zone '%s' view '%s' expired %sat %s, last successful refresh %s; %s", e->domain, zone_vname(e),
            restart ? "while stopped " : "", a, b, serving ? "serving stale data (serve-stale, RFC 8767, EDE 3)" : "answering SERVFAIL (EDE 24)");
}

/* #203 review (design 2.5): a state write of the restore (the KNOWN marking of a copy that cannot be used) is made only by the holder of the entry's is_transferring, so that it cannot
 * interleave with the write at the end of a refresh (one that runs after the safety net gave up on the entry).  When a refresh holds it, the restore leaves the record alone: that
 * refresh writes the record, and the scrub of the store finds a damaged image that is still there.  Deletes need no CAS (a delete wins, 2.5). */
static void make_known_cas(zone_db_entry_t *e, store_t *st, uint16_t vid, const xinfo_t *xi, const store_zone_t *z) {
  bool idle = false;
  if (!atomic_compare_exchange_strong_explicit(&e->is_transferring, &idle, true, memory_order_acq_rel, memory_order_relaxed)) return;
  make_known(st, vid, xi, z);
  atomic_store_explicit(&e->is_transferring, false, memory_order_release);
}

static int restore_do(zone_db_entry_t *e, bool own) {
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vidi = xfr_store_vid();
  if (!st || vidi < 0) return RS_OFF;
  const uint16_t vid = (uint16_t)vidi;
  xinfo_t xi;
  if (!entry_info_now(e, &xi)) return RS_NOINFO;
  /* step 1: the record; every decision from store_zone_get()'s values (M3) */
  store_zone_t z;
  if (rec_get(st, vid, &xi, &z) != 0 || z.state != STORE_STATE_STORED || !(z.flags & STORE_F_XFR)) {
    atomic_fetch_add_explicit(&X.s_none, 1, memory_order_relaxed);
    return RS_NONE;
  }
  /* step 2: the identity (another zone of this key: a tag collision, a view renamed, a member with a new unique-id, RFC 9432 §5.4 / §5.6) */
  xfr_state_t s;
  if (xfr_state_decode(z.digest, sizeof(z.digest), &s) != 0 || s.kind != xi.kind || s.identity != xi.identity) {
    rec_delete(st, vid, xi.key, (size_t)xi.klen, z.zid);
    atomic_fetch_add_explicit(&X.restore_identity, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&X.s_none, 1, memory_order_relaxed);
    syslog(LOG_INFO, "[Store] the stored copy of secondary zone '%s' (view '%s') is of another zone (the view, the kind or the catalog member's unique-id changed): it is deleted, the zone starts without it",
           e->domain, zone_vname(e));
    return RS_IDENTITY;
  }
  /* step 3: the image, read and checked as an attach checks it; a heap copy (W8: MAP would pin its segment for ever, COPY's buffer is the store's).  #203 review (R2'): this is one
   * step of the restore thread however big the image is: the safety net gives it the time to read and check it at 10 MB/s on top of its 30 s */
  if (own) {
    atomic_store_explicit(&X.item_allow_ms, (int64_t)(z.img_len / 10000u), memory_order_relaxed);
    progress_stamp();
  }
  store_img_t img;
  store_read_lock();
  int r = store_image_read(st, z.zid, &img);
  store_read_unlock();
  bool ok = r == 0;
  zone_image_soa_t nums;
  memset(&nums, 0, sizeof(nums));
  char why[96] = "";
  if (ok) {
    const zone_image_t *zi = img.data;
    ok = img.len >= sizeof(zone_image_t) && ((uintptr_t)img.data & 7u) == 0 && zi->magic == ZONE_IMAGE_MAGIC && zi->version == ZONE_IMAGE_VERSION && zi->total_size == img.len &&
         zone_image_validate(img.data, img.len, why, sizeof(why)) == 0;
    if (ok) {
      const uint32_t apex = zone_image_find_name(zi, e->domain), soa = zone_image_apex_soa(zi);
      ok = apex != ZONE_IMAGE_NONE && apex == zi->apex_name && soa != ZONE_IMAGE_NONE && zone_image_soa(zi, soa, NULL, 0, NULL, 0, &nums) == 0 && nums.serial == z.serial;
      if (!ok) snprintf(why, sizeof(why), "not the image of the zone, or another serial");
    }
    /* review 2026-11-23 D-L5 / D-L6: as the attach of a stored database zone does (dns_db_store.c attach_build()), the copy is looked at as an image that
     * arrives now: the rules of the zone and of every source (zone_image_check_policy(); an image an older build wrote, or one stored before a rule was
     * made), then the limits of the configuration as they are now (max-records & co., zone_limits_gate_image(): a limit tightened since the transfer).  A
     * copy that fails is not used: the next refresh transfers the zone, which the transfer then checks the same way */
    if (ok) {
      const zone_image_policy_t pol = { e->domain, z.serial, UINT64_MAX, 0, 0, 0, true, (zi->flags & ZONE_IMAGE_F_TINYDNS) != 0, true };
      ok = zone_image_check_policy(img.data, img.len, &pol, why, sizeof(why)) == 0;
    }
    if (ok && zone_limits_gate_image(e, zi, "the restore of the stored copy") != 0) {      /* (logged by it) */
      ok = false;
      snprintf(why, sizeof(why), "over a limit of the configuration");
    }
  } else {
    snprintf(why, sizeof(why), "%s", r == -EBADMSG ? "the checksum is wrong" : strerror(-r));
  }
  void *copy = NULL;
  if (ok) {
    copy = malloc(img.len);
    if (copy) memcpy(copy, img.data, img.len);
  }
  const size_t ilen = r == 0 ? img.len : 0;
  if (r == 0) store_img_release(st, &img);
  if (!ok) {
    make_known_cas(e, st, vid, &xi, &z);             /* (the next refresh stores the zone again: the up-to-date rule puts the image) */
    atomic_fetch_add_explicit(&X.restore_bad, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&X.s_none, 1, memory_order_relaxed);
    syslog(LOG_WARNING, "[Store] the secondary's stored copy of '%s' (view '%s') cannot be used (%s); it is stored again by the next refresh", e->domain, zone_vname(e), why);
    return RS_BAD;
  }
  if (!copy) return RS_MEMORY;
  zone_version_t *ver = zone_version_new_ext((zone_image_t *)copy, dns_alloc_size(copy, ilen), NULL, NULL);
  if (!ver) {
    free(copy);
    return RS_MEMORY;
  }
  /* P4 (R1, D5): the settings the primary sent with this copy, read back from settings.dat (hostile: checked and parsed again; file I/O, so before the writer lock).  A copy whose
   * settings were not kept (R2: XFR_SF_RX_LOST), or whose id names no usable text, asks for the whole zone at its first refresh */
  zone_ext_shared_t *rxsh = s.rx_settings ? db_store_rx_settings_get(s.rx_settings) : NULL;
  const bool rx_lost = (s.flags & XFR_SF_RX_LOST) || (s.rx_settings && !rxsh);
  /* steps 4 and 5: under the writer lock, the install rule (4.1): no version, or the version of the `file` that the copy beats (D7); never over a transferred version */
  const time_t now = time(NULL);
  pthread_mutex_lock(&e->writer_lock);
  zone_version_t *cur = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
  if (cur && (!cur->image || cur->image->n_rrs == 0)) cur = NULL;     /* (the empty version of a secondary that has nothing yet) */
  if (cur) {
    const bool file_ver = e->xfr_origin == XFR_ORIGIN_FILE;
    const bool file_wins = file_ver && xfr_file_wins(zone_xr(e)->last_loaded_mtime, atomic_load_explicit(&e->serial, memory_order_relaxed), z.stamp_time, z.serial);
    if (!file_ver || file_wins) {
      pthread_mutex_unlock(&e->writer_lock);
      zone_ext_shared_unref(rxsh);
      zone_version_free(ver);
      if (file_wins) {
        atomic_fetch_add_explicit(&X.file_won, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&X.s_file, 1, memory_order_relaxed);
        syslog(LOG_INFO, "[Store] secondary zone '%s' (view '%s'): its file is newer than the stored copy and has a greater serial (%u > %u): the file is served, the copy is replaced by the next refresh",
               e->domain, zone_vname(e), atomic_load_explicit(&e->serial, memory_order_relaxed), z.serial);
        return RS_FILE_WON;
      }
      return RS_HAS_VERSION;
    }
  }
  uint32_t rf = nums.refresh, rt = nums.retry, ex = nums.expire;
  xfr_clamp_timers(&xi.eff, nums.refresh, nums.retry, nums.expire, &rf, &rt, &ex);
  xfr_times_t tm;
  xfr_state_times(&s, ex, now, &tm);
  atomic_store_explicit(&e->serial, z.serial, memory_order_relaxed);
  atomic_store_explicit(&e->refresh, rf, memory_order_relaxed);
  atomic_store_explicit(&e->retry, rt, memory_order_relaxed);
  atomic_store_explicit(&e->expire, ex, memory_order_relaxed);
  atomic_store_explicit(&e->last_successful_transfer, tm.last_ok, memory_order_release);
  atomic_store_explicit(&e->expire_at, tm.expire_at, memory_order_release);
  e->xfr_origin = (s.flags & XFR_SF_FROM_FILE) ? XFR_ORIGIN_STORE_FILE : XFR_ORIGIN_STORE;
  /* design 4.3 step 5: no difference is computed against the version it replaces (NULL, not `cur`): that version is the `file`'s, and a file -> store difference is no history of
   * the zone (RFC 1995 §4: the IXFR sequences are changes the primary made), it costs compute_ixfr_diff() under the writer lock, and when the stored serial is the lower one (the
   * D7 case: a retransfer to a lower serial) it would put a reversed difference into the history.  The first IXFR a downstream secondary asks of this serial gets the whole zone.
   * (No NOTIFY: the downstream secondaries have this serial, or ask for it at their refresh.)
   * The settings of the primary are in force before the data is installed, as a transfer puts them (handle_axfr_event(): the glue and the response cache of the version read them). */
  zone_ext_shared_t *rxold = rxsh ? zone_rx_settings_apply_locked(e, rxsh) : NULL;
  zone_install_version(e, ver, NULL, false);
  const time_t deadline = zone_expire_deadline(e);
  atomic_store_explicit(&e->next_check, xfr_restore_next_check(&s, rt, deadline, now), memory_order_release);
  pthread_mutex_unlock(&e->writer_lock);
  zone_ext_shared_unref(rxold);                       /* (no settings before a restore installs: NULL; or the object itself when there was no memory to keep it) */
  if (rxsh) atomic_fetch_add_explicit(&X.rx_restored, 1, memory_order_relaxed);
  if (tm.clamped)
    syslog(LOG_WARNING, "[Store] secondary zone '%s' (view '%s'): the times of the stored copy are ahead of the clock (the clock went back?): taken as now in memory, not written back",
           e->domain, zone_vname(e));
  /* step 6: other primaries than when the copy was written: the data is kept, refreshed at once */
  if (s.primaries != xi.primaries) {
    atomic_store_explicit(&e->refresh_now, true, memory_order_release);
    syslog(LOG_INFO, "[Store] secondary zone '%s' (view '%s'): the primaries changed since the copy was stored; the copy is served and the zone is refreshed now", e->domain, zone_vname(e));
  }
  zone_x_t *x = zone_x_need(e);
  if (rx_lost && x) atomic_store_explicit(&x->xfr_axfr_once, true, memory_order_relaxed);
  if (rx_lost) atomic_fetch_add_explicit(&X.rx_lost, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&X.restored, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&X.s_restored, 1, memory_order_relaxed);
  if (deadline > 0 && now > deadline) {
    atomic_fetch_add_explicit(&X.restored_expired, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&X.s_expired, 1, memory_order_relaxed);
    /* no line from this thread (D9: the per-zone event lines are at most XFR_EVENTS_PER_MIN a minute, the rest go into the summary; event_ok() belongs to the control thread's tick):
     * the tick sees the expired zone when this thread clears the pending bit and says `expired while stopped` through its own limit */
    if (x) x->exp_stopped = true;
  }
  /* 7: a catalog zone's members come from its restored version (on this thread, not in a hook); they are made restore-pending and restored by the next pass */
  if (xi.kind == XFR_K_CATALOG) {
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    const zone_config_t *zcfg = zone_entry_config((server_config_t *)cfg, e);
    if (zcfg && zcfg->is_catalog) catalog_process_membership(e, zcfg, zone_vname(e));
    release_config_snapshot(cfg);
    rcu_aux_read_unlock();
  }
  return RS_RESTORED;
}

static int restore_one(zone_db_entry_t *e) {
  if (!atomic_load_explicit(&e->restore_pending, memory_order_acquire)) return RS_NOT_PENDING;
#ifdef KARIDNS_UNIT_TEST
  void (*h)(zone_db_entry_t *) = atomic_load_explicit(&xfr_store_test_restore_hook, memory_order_acquire);
  if (h) h(e);
#endif
  if (!atomic_load_explicit(&e->restore_pending, memory_order_acquire)) return RS_NOT_PENDING;   /* (the tick's safety net gave up on it meanwhile: the zone refreshes without its copy) */
  const int r = restore_do(e, true);
  (void)zone_restore_pending_clear(e);              /* R2: every way out clears it */
  atomic_store_explicit(&X.item_allow_ms, 0, memory_order_relaxed);
  progress_stamp();
  return r;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the pass: the pending entries, then the diff GC (5)                                                             */
/* ------------------------------------------------------------------------------------------------------------- */

/* a small open-addressing set of 64-bit hashes (the keys of the current secondaries) */
typedef struct { uint64_t *h; size_t cap, n; } hset_t;
static uint64_t key_hash(const char *k, size_t n) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)k[i]; h *= 0x100000001b3ull; }
  return h ? h : 1;
}
static bool hset_add(hset_t *s, uint64_t h) {
  if ((s->n + 1) * 2 > s->cap) {
    size_t nc = s->cap ? s->cap * 2 : 256;
    uint64_t *nh = calloc(nc, sizeof(*nh));
    if (!nh) return false;
    for (size_t i = 0; i < s->cap; i++) {
      if (!s->h[i]) continue;
      size_t j = s->h[i] & (nc - 1);
      while (nh[j]) j = (j + 1) & (nc - 1);
      nh[j] = s->h[i];
    }
    free(s->h);
    s->h = nh;
    s->cap = nc;
  }
  size_t j = h & (s->cap - 1);
  while (s->h[j]) {
    if (s->h[j] == h) return true;
    j = (j + 1) & (s->cap - 1);
  }
  s->h[j] = h;
  s->n++;
  return true;
}
static bool hset_has(const hset_t *s, uint64_t h) {
  if (!s->cap) return false;
  size_t j = h & (s->cap - 1);
  while (s->h[j]) {
    if (s->h[j] == h) return true;
    j = (j + 1) & (s->cap - 1);
  }
  return false;
}

/* ---- P3: the database secondaries (3.3, 4.4, 5) ---- */

/* the database views of the configuration, by store tag (a view whose tag is an earlier view's is left out: its zones are not persisted, 2.2) */
#define XFR_DBV_MAX XFR_NOKEY_MAX
typedef struct { uint32_t tag; char name[KARIDNS_VIEW_NAME_MAX]; } dbv_t;
typedef struct { dbv_t v[XFR_DBV_MAX]; int n; bool db; } dbvs_t;
static void dbvs_of(const server_config_t *cfg, dbvs_t *o) {
  o->n = 0;
  o->db = cfg && cfg->database.enabled;
  for (const view_config_t *v = o->db ? cfg->views : NULL; v && o->n < XFR_DBV_MAX; v = v->next) {
    if (v->database_none || !v->name || view_nokey(v->name)) continue;
    o->v[o->n].tag = xfr_view_tag(v->name);
    snprintf(o->v[o->n].name, sizeof(o->v[o->n].name), "%s", v->name);
    o->n++;
  }
}
static const char *dbvs_find(const dbvs_t *o, uint32_t tag) {
  for (int i = 0; i < o->n; i++)
    if (o->v[i].tag == tag) return o->v[i].name;
  return NULL;
}

/* R3: the copies of the database secondaries are exempt from the GC until every restore job of the start (4.4) has run on the ingest thread */
static bool db_gc_open(void) {
  return !atomic_load_explicit(&X.dbj_hold, memory_order_acquire) &&
         atomic_load_explicit(&X.dbj_done, memory_order_acquire) >= atomic_load_explicit(&X.dbj_posted, memory_order_acquire);
}

/* Is the `d` copy (tag, zone, state) of a zone of the database?  It is when the registry has a database secondary of its identity (the same kind and domains.id), or, when the registry has
 * no zone of the name (the loader has not sent it yet: its restore waits for the loader, 4.4), when the reconcile's record of the zone names the copy's domains.id.  A view that is no
 * database view any more, another zone of the name (a primary, another kind or row), or neither: no */
static bool db_copy_current(const dbvs_t *dv, uint32_t tag, const char *zone, const xfr_state_t *s) {
  const char *view = dbvs_find(dv, tag);
  bool cat = false;
  int64_t sid = 0;
  if (!view) return false;
  if (dbreg_db_secondary_of(view, zone, &cat, &sid)) return xfr_identity(cat ? XFR_K_DB_CONSUMER : XFR_K_DB_SLAVE, zone, view, NULL, sid) == s->identity;
  if (dbreg_lookup_entry(view, zone)) return false;
  return db_store_nonstore_sid(view, zone, &sid) && xfr_identity(s->kind, zone, view, NULL, sid) == s->identity;
}

/* one record goes (the GC) */
static bool gc_delete(store_t *st, uint16_t vid, const char *name, size_t kl, uint32_t zid) {
  if (xs_unbulk(st) != 0 || store_delete_name(st, vid, name, kl) != 0) return false;
  zs_del(zid);
  return true;
}

/* consok: the keys of the database catalog consumers that are registered and have refreshed since the start; exempt gets the view tag (+ 1) of every other consumer whose copy is found */
static uint64_t gc_run(store_t *st, uint16_t vid, const hset_t *cur, hset_t *exempt, const hset_t *consok, bool cur_ok, const dbvs_t *dv) {
  if (!cur_ok || !atomic_load_explicit(&X.zs_built, memory_order_acquire)) return 0;      /* (a set that could not be made completely deletes nothing) */
  zbits_t b;
  if (!zs_copy(&b)) return 0;
  uint64_t deleted = 0;
  /* (P3: the members' copies are judged after the walk: a database catalog consumer whose own copy is seen in it and that has not refreshed (not restored yet: its restore job, or the
   * loader, makes it later) keeps its view's members, M6 per view.  Before P3 a member of a database consumer lost its copy at the first pass of a start, when no consumer existed yet) */
  typedef struct { uint32_t zid, tag; } gcm_t;
  gcm_t *mem = NULL;
  size_t nm = 0, mcap = 0;
  for (size_t w = 0; w < b.nw; w++) {
    for (uint64_t bits = b.w[w]; bits; bits &= bits - 1) {
      const uint32_t zid = (uint32_t)(w * 64 + (size_t)__builtin_ctzll(bits));
      store_zone_t z;
      store_read_lock();
      const int gr = store_zone_get(st, zid, &z);
      store_read_unlock();
      if (gr != 0 || z.view != vid || z.state == STORE_STATE_FREE) {
        if (gr != -EBADMSG) zs_del(zid);              /* (the id is another view's now, or free) */
        continue;
      }
      const size_t kl = strlen(z.name);
      if (hset_has(cur, key_hash(z.name, kl))) continue;
      uint32_t tag = 0;
      char kc = 0, zone[STORE_NAME_MAX + 2];
      if (xfr_key_parse(z.name, kl, &tag, &kc, zone, sizeof(zone)) != 0) continue;      /* (not a key of this module: left alone) */
      xfr_state_t s;
      const bool sok = xfr_state_decode(z.digest, sizeof(z.digest), &s) == 0;
      /* P3 (5, R3): a `d` copy goes when no database secondary of its identity is registered, once every restore job of the start has run (a copy whose restore has not run yet is kept) */
      if (sok && s.kind == XFR_K_DB_CONSUMER && kc == 'd' && !hset_has(consok, key_hash(z.name, kl)) && !hset_add(exempt, (uint64_t)tag + 1)) {
        free(mem);                                    /* (no memory for the exemption: nothing more is deleted this pass) */
        free(b.w);
        return deleted;
      }
      if (sok && (s.kind == XFR_K_DB_SLAVE || s.kind == XFR_K_DB_CONSUMER) && (kc != 'd' || !db_gc_open() || db_copy_current(dv, tag, zone, &s))) continue;
      if (sok && s.kind == XFR_K_MEMBER) {
        if (nm == mcap) {
          const size_t nc = mcap ? mcap * 2 : 64;
          gcm_t *nmem = realloc(mem, nc * sizeof(*nmem));
          if (!nmem) continue;                        /* (no memory: the member is kept) */
          mem = nmem;
          mcap = nc;
        }
        mem[nm++] = (gcm_t){ zid, tag };
        continue;
      }
      if (gc_delete(st, vid, z.name, kl, zid)) deleted++;
      progress_stamp();
    }
  }
  free(b.w);
  for (size_t i = 0; i < nm; i++) {
    if (hset_has(exempt, (uint64_t)mem[i].tag + 1)) continue;                             /* (M6: a catalog of that view has not refreshed since the start) */
    store_zone_t z;
    store_read_lock();
    const int gr = store_zone_get(st, mem[i].zid, &z);
    store_read_unlock();
    if (gr != 0 || z.view != vid || z.state == STORE_STATE_FREE || hset_has(cur, key_hash(z.name, strlen(z.name)))) continue;     /* (it changed meanwhile: the next pass) */
    if (gc_delete(st, vid, z.name, strlen(z.name), mem[i].zid)) deleted++;
    progress_stamp();
  }
  free(mem);
  if (deleted) atomic_fetch_add_explicit(&X.gc_deleted, deleted, memory_order_relaxed);
  return deleted;
}

static uint64_t pass_run(void) {
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  if (!st || vid < 0) return 0;
  zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
  if (!snap) return 0;
  zone_db_entry_t **pend = NULL, **retry = NULL;
  size_t np = 0, cap = 0, nr = 0, rcap = 0;
  hset_t cur = { 0 }, exempt = { 0 }, consok = { 0 };
  bool cur_ok = true;
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  (void)xfr_store_config_check(cfg);                  /* (2.2: first, so that the keys of this pass are the ones of the configuration in force) */
  dbvs_t *dv = calloc(1, sizeof(*dv));                 /* (P3: the database views of this configuration, for the GC of the `d` copies) */
  if (dv) dbvs_of(cfg, dv);
  else cur_ok = false;
  for (size_t v = 0; v < snap->view_count; v++) {
    size_t count = 0;
    zdir_elem_t *const *list = zdir_tick_list(&snap->views[v], &count);
    for (size_t i = 0; i < count; i++) {
      zone_db_entry_t *e = zdir_entry(list[i]);
      if (!e || !view_owns_elem(list[i])) continue;
      if (e->source == ZONE_SRC_DB) {
        /* (a database catalog consumer that has not refreshed keeps its members' copies too: M6 per view) */
        const zone_config_t *dz = zone_entry_config((server_config_t *)cfg, e);
        if (dz && dz->is_catalog && !atomic_load_explicit(&zone_xr(e)->xfr_refreshed, memory_order_acquire)) cur_ok = hset_add(&exempt, (uint64_t)xfr_view_tag(zone_vname(e)) + 1) && cur_ok;
        else if (dz && dz->is_catalog) {               /* (a consumer that refreshed: its copy, which the walk of the GC sees, does not hold its view's members) */
          char ck[XFR_KEY_MAX + 1];
          const int cl = xfr_key_make(zone_vname(e), XFR_K_DB_CONSUMER, e->domain, ck, sizeof(ck));
          if (cl > 0) cur_ok = hset_add(&consok, key_hash(ck, (size_t)cl)) && cur_ok;
        }
        /* (P3: its own copy is judged by the registry in the GC, db_copy_current(); a write of it that was put off is retried below) */
      } else {
        xinfo_t xi;
        /* (an entry with no key, a name too long or a view whose tag collides, is not in the set; its pending bit is cleared by the restore like any other: RS_NOINFO) */
        if (entry_info(e, cfg, snap, &xi)) {
          cur_ok = hset_add(&cur, key_hash(xi.key, (size_t)xi.klen)) && cur_ok;
          if (xi.kind == XFR_K_CATALOG && !atomic_load_explicit(&zone_xr(e)->xfr_refreshed, memory_order_acquire))
            cur_ok = hset_add(&exempt, (uint64_t)xi.view_tag + 1) && cur_ok;
        }
      }
      if (atomic_load_explicit(&zone_xr(e)->xfr_store_retry, memory_order_acquire) != 0) {     /* (0.7: a store write that waited for the end of an unlogged fill) */
        if (nr == rcap) {
          size_t nc = rcap ? rcap * 2 : 16;
          zone_db_entry_t **n = realloc(retry, nc * sizeof(*n));
          if (n) { retry = n; rcap = nc; }
        }
        if (nr < rcap) retry[nr++] = e;
      }
      if (atomic_load_explicit(&e->restore_pending, memory_order_acquire)) {
        if (np == cap) {
          size_t nc = cap ? cap * 2 : 64;
          zone_db_entry_t **n = realloc(pend, nc * sizeof(*n));
          if (!n) { cur_ok = false; continue; }
          pend = n;
          cap = nc;
        }
        pend[np++] = e;
      }
    }
  }
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  /* the entries stay valid while the snapshot is retained */
  for (size_t i = 0; i < np; i++) {
    (void)restore_one(pend[i]);
    if ((i + 1) % XFR_SLICE_ZONES == 0) sched_yield();
    if (atomic_load_explicit(&X.st, memory_order_acquire) == NULL) break;
  }
  free(pend);
  for (size_t i = 0; i < nr; i++) {                   /* (the writes put off for the end of an unlogged fill: made now, as at the end of their refresh; one that is put off again is flagged again) */
    zone_db_entry_t *e = retry[i];
    zone_x_t *const x = zone_x(e);
    const int outcome = x ? atomic_exchange_explicit(&x->xfr_store_retry, 0, memory_order_acq_rel) : 0;
    if (outcome != 0) after_refresh_pinned(st, (uint16_t)vid, e, outcome, atomic_load_explicit(&x->xfr_store_retry_at, memory_order_relaxed));
  }
  free(retry);
  const uint64_t del = dv ? gc_run(st, (uint16_t)vid, &cur, &exempt, &consok, cur_ok, dv) : 0;
  free(consok.h);
  free(dv);
  free(cur.h);
  free(exempt.h);
  release_zone_snapshot(snap);
  return del;
}

static void db_start_scan(store_t *st, uint16_t vid);
static void *restore_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  if (st && vid >= 0) zs_build(st, (uint16_t)vid);
  if (st && vid >= 0) db_start_scan(st, (uint16_t)vid);     /* (P3, 4.4: the copies of the database secondaries, restored by jobs of the ingest thread) */
#ifdef KARIDNS_TEST_EVICT
  /* (the thread is stalled with entries pending, and makes no progress: the tick's skip of pending entries and the 30 s safety net are tested with it) */
  for (unsigned waited = 0; X.hold_ms && waited < X.hold_ms && !X.stop; waited += 50) usleep(50000);
#endif
  pthread_mutex_lock(&X.mu);
  while (!X.stop) {
    if (X.req_gen == X.done_gen && atomic_load_explicit(&X.retry_want, memory_order_acquire)) {
      /* (0.7: writes were put off for the end of an unlogged fill: a pass once it is on disk, looked at every second) */
      if (st && !store_bulk_pending(st)) {
        atomic_store_explicit(&X.retry_want, false, memory_order_relaxed);
        X.req_gen++;
        continue;
      }
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += 1;
      (void)pthread_cond_timedwait(&X.cv, &X.mu, &ts);
      continue;
    }
    if (X.req_gen == X.done_gen) {
      pthread_cond_wait(&X.cv, &X.mu);
      continue;
    }
    const uint64_t g = X.req_gen;
    pthread_mutex_unlock(&X.mu);
    progress_stamp();
    (void)pass_run();
    pthread_mutex_lock(&X.mu);
    X.done_gen = g;
    if (!X.first_done) {
      X.first_done = true;
      const int64_t ms = mono_ms() - X.t0_ms;
      atomic_store_explicit(&X.restore_ms, (uint64_t)(ms > 0 ? ms : 0), memory_order_relaxed);
      syslog(LOG_NOTICE, "[Store] secondaries: %" PRIu64 " restored (%" PRIu64 " expired while stopped), %" PRIu64 " kept the file, %" PRIu64 " without a copy, %lld ms",
             atomic_load(&X.s_restored), atomic_load(&X.s_expired), atomic_load(&X.s_file), atomic_load(&X.s_none), (long long)ms);
    }
    pthread_cond_broadcast(&X.cv);
  }
  pthread_mutex_unlock(&X.mu);
  return NULL;
}

/* M4 d: the hook of a rebuild only asks for a pass */
static void ask_pass(void) {
  pthread_mutex_lock(&X.mu);
  /* (R2': the new pending entries are counted from now, not from the thread's last step; but only when the thread has done every pass asked so far: a thread stalled inside a pass is
   * not hidden by rebuilds that keep coming, #203 review) */
  if (X.req_gen == X.done_gen) progress_stamp();
  X.req_gen++;
  pthread_cond_broadcast(&X.cv);
  pthread_mutex_unlock(&X.mu);
}

/* P3: a database secondary left the registry (dbreg_delete(), a replacing entry): a pass, whose GC deletes its copy (5).  The hook only asks; the pass is shared by the hooks that come meanwhile */
static void db_gone(void) {
  pthread_mutex_lock(&X.mu);
  X.req_gen++;
  pthread_cond_broadcast(&X.cv);
  pthread_mutex_unlock(&X.mu);
}

static const xfr_store_ops_t g_ops = { .after_refresh = after_refresh, .rebuilt = ask_pass, .db_gone = db_gone };

/* ------------------------------------------------------------------------------------------------------------- */
/* P3: the database secondaries (4.4: their copies are restored by jobs of the ingest thread, without the loader)  */
/* ------------------------------------------------------------------------------------------------------------- */

/* The restore thread's start: every stored `d` copy of the reserved view gets a restore job on the ingest thread (dns_db_ingest.c), which makes the zone's entry from the copy when the reconcile's
 * record of the zone (its domains.id) agrees with the copy's identity; the jobs and job_execute_secondary() run on that one thread, so a zone never gets two entries (M4 c).  A copy of a view that is
 * no database view any more (the database block or the view was removed) has no zone it could be restored into: it is deleted.  A KNOWN copy (its image was found damaged) is not restored: the
 * loader's job makes the entry and its refresh stores the copy again. */
static void db_start_scan(store_t *st, uint16_t vid) {
  zbits_t b;
  dbvs_t *dv = calloc(1, sizeof(*dv));
  if (!dv || !zs_copy(&b)) {
    free(dv);
    atomic_store_explicit(&X.dbj_hold, true, memory_order_release);       /* (no memory: the `d` copies are not restored and stay exempt from the GC for this run) */
    return;
  }
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  dbvs_of(cfg, dv);
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  uint64_t posted = 0, dropped = 0;
  for (size_t w = 0; w < b.nw; w++) {
    for (uint64_t bits = b.w[w]; bits; bits &= bits - 1) {
      const uint32_t zid = (uint32_t)(w * 64 + (size_t)__builtin_ctzll(bits));
      store_zone_t z;
      store_read_lock();
      const int gr = store_zone_get(st, zid, &z);
      store_read_unlock();
      if (gr != 0 || z.view != vid || z.state != STORE_STATE_STORED || !(z.flags & STORE_F_XFR)) continue;
      const size_t kl = strlen(z.name);
      uint32_t tag = 0;
      char kc = 0, zone[STORE_NAME_MAX + 2];
      xfr_state_t s;
      if (xfr_key_parse(z.name, kl, &tag, &kc, zone, sizeof(zone)) != 0 || kc != 'd' || xfr_state_decode(z.digest, sizeof(z.digest), &s) != 0 ||
          (s.kind != XFR_K_DB_SLAVE && s.kind != XFR_K_DB_CONSUMER))
        continue;
      const char *view = dbvs_find(dv, tag);
      if (!view) {
        rec_delete(st, vid, z.name, kl, zid);
        atomic_fetch_add_explicit(&X.gc_deleted, 1, memory_order_relaxed);
        dropped++;
        continue;
      }
      atomic_fetch_add_explicit(&X.dbj_posted, 1, memory_order_acq_rel);
      if (!db_ingest_xfr_restore_post(view, zone)) {
        atomic_fetch_sub_explicit(&X.dbj_posted, 1, memory_order_acq_rel);
        atomic_store_explicit(&X.dbj_hold, true, memory_order_release);   /* (no memory for the job: the copy waits for the loader's job, and no `d` copy is deleted this run) */
      } else {
        posted++;
      }
      progress_stamp();
    }
  }
  free(b.w);
  free(dv);
  if (posted || dropped)
    syslog(LOG_INFO, "[Store] secondaries: %" PRIu64 " stored copy(ies) of database secondaries are restored by the ingest thread, %" PRIu64 " of a view that takes no database zones deleted",
           posted, dropped);
}

void xfr_store_db_job_done(void) {
  const uint64_t d = atomic_fetch_add_explicit(&X.dbj_done, 1, memory_order_acq_rel) + 1;
  if (d >= atomic_load_explicit(&X.dbj_posted, memory_order_acquire)) db_gone();   /* (the last one: the GC may judge the `d` copies now, R3) */
}

/* the `d` copy of (view, zone): STORED, of this module, its state readable and of a database kind */
bool xfr_store_db_copy(const char *view, const char *zone, int *kind, uint32_t *settings, uint64_t *identity) {
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  char k[XFR_KEY_MAX + 1];
  const int kl = xfr_key_make(view, XFR_K_DB_SLAVE, zone, k, sizeof(k));
  if (!st || vid < 0 || kl < 0) return false;
  store_zone_t z;
  store_read_lock();
  const uint32_t zid = store_find(st, (uint16_t)vid, k, (size_t)kl);
  const bool got = zid != STORE_NONE && store_zone_get(st, zid, &z) == 0;
  store_read_unlock();
  xfr_state_t s;
  if (!got || z.state != STORE_STATE_STORED || !(z.flags & STORE_F_XFR) || xfr_state_decode(z.digest, sizeof(z.digest), &s) != 0 ||
      (s.kind != XFR_K_DB_SLAVE && s.kind != XFR_K_DB_CONSUMER))
    return false;
  *kind = s.kind;
  *settings = z.settings;
  *identity = s.identity;
  return true;
}

/* the `d` copy of (view, zone) is of no zone any more (4.4: the row was deleted, renamed or purged while the server was stopped): deleted when it is still the copy of that identity */
void xfr_store_db_copy_drop(const char *view, const char *zone, uint64_t identity) {
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  char k[XFR_KEY_MAX + 1];
  const int kl = xfr_key_make(view, XFR_K_DB_SLAVE, zone, k, sizeof(k));
  if (!st || vid < 0 || kl < 0) return;
  store_zone_t z;
  store_read_lock();
  const uint32_t zid = store_find(st, (uint16_t)vid, k, (size_t)kl);
  const bool got = zid != STORE_NONE && store_zone_get(st, zid, &z) == 0;
  store_read_unlock();
  xfr_state_t s;
  if (!got || xfr_state_decode(z.digest, sizeof(z.digest), &s) != 0 || s.identity != identity) return;
  rec_delete(st, (uint16_t)vid, k, (size_t)kl, z.zid);
  atomic_fetch_add_explicit(&X.restore_identity, 1, memory_order_relaxed);
  syslog(LOG_INFO, "[Store] the stored copy of database secondary zone '%s' (view '%s') is of no zone of the database now (the row was deleted, renamed or purged while the server was stopped): it is deleted",
         zone, view);
}

/* 4.4 / 3.3: the copy restored into a database secondary's new entry, before the ingest thread registers it (no tick, no transfer and no query can reach the entry yet, so it needs no
 * restore_pending).  The caller is the ingest thread (pinned in the auxiliary RCU, holding no lock); xfr_db_sid of the entry is set.  true: the copy is installed */
bool xfr_store_db_restore(zone_db_entry_t *e) {
  if (!e || e->source != ZONE_SRC_DB || !e->is_secondary || !xfr_store_active()) return false;
  return restore_do(e, false) == RS_RESTORED;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the core                                                                                                        */
/* ------------------------------------------------------------------------------------------------------------- */

void xfr_store_want(bool on) { atomic_store_explicit(&g_xfr_store_mode, on ? XFRM_WANTED : XFRM_OFF, memory_order_release); }

/* every pending bit of the current snapshot is cleared (no restore will run for them) */
static uint64_t clear_all_pending(void) {
  uint64_t n = 0;
  zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
  if (!snap) return 0;
  rcu_aux_read_lock();
  for (size_t v = 0; v < snap->view_count; v++) {
    size_t count = 0;
    zdir_elem_t *const *list = zdir_tick_list(&snap->views[v], &count);
    for (size_t i = 0; i < count; i++) {
      zone_db_entry_t *e = zdir_entry(list[i]);
      if (e && zone_restore_pending_clear(e)) n++;
    }
  }
  rcu_aux_read_unlock();
  release_zone_snapshot(snap);
  return n;
}

void xfr_store_core_off(void) {
  atomic_store_explicit(&g_xfr_store_mode, XFRM_OFF, memory_order_release);
  (void)clear_all_pending();
}

#ifdef KARIDNS_TEST_EVICT
/* KARIDNS_TEST_XFR_PUT_FAIL: the next n appends of an image record find the disk full inside the store (store_put_ex() runs: its cleaner pass, its retry and NO_DEGRADE are what is tested,
 * #203 review; before, the knob returned -ENOSPC without calling the store).  The server of this test has no database: every image record it appends is a secondary's copy */
static int test_append_fault(uint64_t reclen) {
  (void)reclen;
  long pf = atomic_load_explicit(&X.put_fail, memory_order_relaxed);
  while (pf > 0 && !atomic_compare_exchange_weak_explicit(&X.put_fail, &pf, pf - 1, memory_order_relaxed, memory_order_relaxed)) {}
  return pf > 0 ? -ENOSPC : 0;
}
static void read_test_knobs(void) {
  const char *pf = getenv("KARIDNS_TEST_XFR_PUT_FAIL");
  atomic_store_explicit(&X.put_fail, pf ? strtol(pf, NULL, 10) : 0, memory_order_relaxed);
  if (pf) store_test_append_fault = test_append_fault;
  const char *rc = getenv("KARIDNS_TEST_XFR_RX_CAP");      /* (the cap on the settings received from primaries in settings.dat, R1: 0 keeps none, the R2 way) */
  if (rc && *rc) db_store_test_rx_cap_ids = strtoll(rc, NULL, 10);
  const char *kz = getenv("KARIDNS_TEST_XFR_KILL_BEFORE_PUT");
  snprintf(X.kill_zone, sizeof(X.kill_zone), "%s", kz ? kz : "");
  const char *li = getenv("KARIDNS_TEST_STALE_LOG_INTERVAL");
  X.log_interval = li ? (unsigned)strtoul(li, NULL, 10) : 0;
  const char *hm = getenv("KARIDNS_TEST_XFR_RESTORE_HOLD_MS");
  X.hold_ms = hm ? (unsigned)strtoul(hm, NULL, 10) : 0;
  const char *nm = getenv("KARIDNS_TEST_XFR_RESTORE_NET_MS");
  X.net_ms = nm ? (unsigned)strtoul(nm, NULL, 10) : 0;
}
#define read_test_knobs_call() read_test_knobs()
#else
#define read_test_knobs_call() ((void)0)
#endif

bool xfr_store_core_start(store_t *st, bool quarantined, bool created) {
  read_test_knobs_call();
  if (!st) {
    xfr_store_core_off();
    return false;
  }
  int vid = store_view_id(st, KARIDNS_XFR_STORE_VIEW);
  if (vid < 0) vid = store_view_add(st, KARIDNS_XFR_STORE_VIEW);     /* (D8: at the core start, before the views of the database) */
  if (vid < 0) {
    syslog(LOG_ERR, "[Store] no room for the view '%s' of the secondaries' copies in the store (%d views at most): the secondaries are kept in memory only (xfr.unstorable)",
           KARIDNS_XFR_STORE_VIEW, STORE_MAX_VIEWS);
    atomic_fetch_add_explicit(&X.unstorable, 1, memory_order_relaxed);
    xfr_store_core_off();
    return false;
  }
  atomic_store_explicit(&X.st, st, memory_order_release);
  atomic_store_explicit(&X.vid, vid, memory_order_release);
  X.quarantined = quarantined;
  X.created = created;
  X.t0_ms = mono_ms();
  X.stop = false;
  X.req_gen = 1;                                      /* (the start pass) */
  X.done_gen = 0;
  progress_stamp();                                   /* R2': the time the open took is not counted */
  if (pthread_create(&X.thr, NULL, restore_thread, NULL) != 0) {
    syslog(LOG_ERR, "[Store] the restore thread of the secondaries' copies cannot be started; the secondaries are kept in memory only");
    atomic_store_explicit(&X.st, NULL, memory_order_release);
    atomic_store_explicit(&X.vid, -1, memory_order_release);
    xfr_store_core_off();
    return false;
  }
  X.thr_started = true;
  const uint64_t pend = atomic_load_explicit(&g_xfr_pending, memory_order_relaxed);
  if (quarantined && pend > 0)
    syslog(LOG_ERR, "[Store] secondaries: the store was quarantined: %" PRIu64 " secondary zone(s) start without their copy (and their expire clock: counted from the file or the first transfer)", pend);
  else if (created && pend > 0)
    syslog(LOG_NOTICE, "[Store] secondaries: the store was created new: %" PRIu64 " secondary zone(s) start without a copy; their copies are stored by the first refreshes", pend);
  atomic_store_explicit(&g_xfr_ops, &g_ops, memory_order_release);
  atomic_store_explicit(&g_xfr_store_mode, XFRM_ACTIVE, memory_order_release);
  return true;
}

void xfr_store_wait_start(unsigned budget_ms) {
  if (!X.thr_started) return;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += budget_ms / 1000;
  ts.tv_nsec += (long)(budget_ms % 1000) * 1000000L;
  if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
  pthread_mutex_lock(&X.mu);
  /* (the first pass restores the catalog zones and makes their members, and every snapshot rebuild that makes entries asks for another pass: the members' copies are restored by those.
   * Done is every asked pass done, req_gen == done_gen, not only the first, so that the members answer too when the workers start; a reconfiguration that comes meanwhile is waited for
   * inside the budget as well) */
  while (!(X.first_done && X.req_gen == X.done_gen) && !X.stop)
    if (pthread_cond_timedwait(&X.cv, &X.mu, &ts) != 0) break;
  const bool done = X.first_done && X.req_gen == X.done_gen;
  pthread_mutex_unlock(&X.mu);
  if (!done)
    syslog(LOG_NOTICE, "[Store] secondaries: the restore of the stored copies takes longer than %u ms; it goes on in the background (the zones that wait answer from their file, or not yet)", budget_ms);
}

void xfr_store_stop(void) {
  atomic_store_explicit(&g_xfr_ops, NULL, memory_order_release);
  if (!X.thr_started) return;
  pthread_mutex_lock(&X.mu);
  X.stop = true;
  pthread_cond_broadcast(&X.cv);
  pthread_mutex_unlock(&X.mu);
  pthread_join(X.thr, NULL);
  X.thr_started = false;
  atomic_store_explicit(&g_xfr_store_mode, XFRM_OFF, memory_order_release);
}

bool xfr_restore_stuck(void) {
  if (atomic_load_explicit(&g_xfr_pending, memory_order_relaxed) == 0) return false;
  const int64_t p = atomic_load_explicit(&g_xfr_restore_progress_ms, memory_order_acquire);
  const int64_t allow = atomic_load_explicit(&X.item_allow_ms, memory_order_relaxed);   /* (the item in work: a big image) */
#ifdef KARIDNS_TEST_EVICT
  if (X.net_ms) return mono_ms() - p > (int64_t)X.net_ms + allow;
#endif
  return mono_ms() - p > XFR_RESTORE_NET_MS + allow;
}

void xfr_restore_note_timeouts(uint64_t n) {
  if (!n) return;
  atomic_fetch_add_explicit(&X.restore_timeouts, n, memory_order_relaxed);
  syslog(LOG_ERR, "[Store] the restore of the stored secondaries made no progress for 30 s; %" PRIu64 " zone(s) refresh without their stored copy (xfr.restore_timeouts)", n);
  progress_stamp();
}

/* ------------------------------------------------------------------------------------------------------------- */
/* zonestatus, counters                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

size_t xfr_store_zonestatus(zone_db_entry_t *e, const server_config_t *cfg, char *out, size_t cap) {
  if (!e || !cap || !e->is_secondary) return 0;
  size_t o = 0;
#define APP(...) do { int n_ = snprintf(out + o, cap - o, __VA_ARGS__); if (n_ > 0) o = (size_t)n_ >= cap - o ? cap - 1 : o + (size_t)n_; } while (0)
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  if (atomic_load_explicit(&e->restore_pending, memory_order_acquire)) {
    APP("Store: restore pending\n");
  } else if (!st || vid < 0) {
    APP("Store: off\n");
  } else {
    xinfo_t xi;
    store_zone_t z;
    char ts[40];
    if (view_nokey(zone_vname(e))) APP("Store: not kept (the view's name has the store tag of another view: see the log)\n");
    else if (!entry_info_now(e, &xi)) APP("Store: not kept (the name is too long)\n");
    else if (rec_get(st, (uint16_t)vid, &xi, &z) != 0 || z.state != STORE_STATE_STORED) APP("Store: no copy\n");
    else {
      fmt_utc((time_t)z.stamp_time, ts, sizeof(ts));
      /* P4 (R1): whether the settings the primary sent are kept with the copy (settings.dat), or a restart asks for the whole zone to get them again (R2) */
      xfr_state_t rs;
      const bool sok = xfr_state_decode(z.digest, sizeof(z.digest), &rs) == 0;
      const char *rx = !sok ? "" : rs.rx_settings ? ", the settings of the primary kept" : (rs.flags & XFR_SF_RX_LOST) ? ", the settings of the primary not kept (a restart asks for the whole zone)" : "";
      APP("Store: copy serial %u, %u bytes, saved %s%s\n", z.serial, z.img_len, ts, rx);
    }
  }
  char a[40], b[40], c[40];
  xfr_state_t s;
  bool failed = false;
  time_t attempt = 0;
  if (st && vid >= 0) {
    xinfo_t xi;
    store_zone_t z;
    if (entry_info_now(e, &xi) && rec_get(st, (uint16_t)vid, &xi, &z) == 0 && xfr_state_decode(z.digest, sizeof(z.digest), &s) == 0) {
      failed = (s.flags & XFR_SF_FAILED) != 0;
      attempt = (time_t)s.last_attempt;
    }
  }
  const time_t last_ok = atomic_load_explicit(&e->last_successful_transfer, memory_order_acquire);
  const time_t deadline = zone_expire_deadline(e);
  fmt_utc(last_ok, a, sizeof(a));
  fmt_utc(attempt, b, sizeof(b));
  fmt_utc(deadline, c, sizeof(c));
  APP("Last-refresh: %s  Last-attempt: %s%s  Expires: %s\n", a, b, failed ? " (failed)" : "", c);
  const time_t now = time(NULL);
  if (deadline > 0 && now > deadline) {
    const zone_config_t *zc = e->is_catalog_member ? NULL : zone_entry_config((server_config_t *)cfg, e);
    const uint32_t lim = zone_secondary_stale_max(cfg, zc, zone_vname(e));
    char d[32], l[32];
    fmt_dur(now - deadline, d, sizeof(d));
    if (zone_expired_serves_stale(cfg, zc, zone_vname(e), deadline, now)) {
      APP("Expired: since %s (%s), serving stale data (serve-stale)\n", c, d);
    } else {
      fmt_dur(lim, l, sizeof(l));
      if (cfg && cfg->serve_stale && lim) APP("Expired: since %s (%s), answering SERVFAIL (secondary-stale-max %s reached)\n", c, d, l);
      else APP("Expired: since %s (%s), answering SERVFAIL (serve-stale no)\n", c, d);
    }
  }
#undef APP
  return o;
}

void xfr_store_expired(uint64_t *expired, uint64_t *stale, uint64_t *servfail) {
  *expired = atomic_load_explicit(&X.expired_zones, memory_order_relaxed);
  *stale = atomic_load_explicit(&X.expired_stale, memory_order_relaxed);
  *servfail = atomic_load_explicit(&X.expired_servfail, memory_order_relaxed);
}

void xfr_store_counters(xfr_store_counters_t *o) {
  memset(o, 0, sizeof(*o));
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  o->vid = vid;
  if (st && vid >= 0 && vid < STORE_MAX_VIEWS) {
    store_stats_t ss;
    store_stats(st, &ss);
    o->records = ss.views[vid].known + ss.views[vid].stored;
    o->image_bytes = ss.views[vid].image_bytes;
  }
  o->puts = atomic_load(&X.puts);
  o->puts_uptodate = atomic_load(&X.puts_uptodate);
  o->put_nospc = atomic_load(&X.put_nospc);
  o->put_errors = atomic_load(&X.put_errors);
  o->state_writes = atomic_load(&X.state_writes);
  o->state_stale = atomic_load(&X.state_stale);
  o->state_skipped = atomic_load(&X.state_skipped);
  o->orphans_deleted = atomic_load(&X.orphans_deleted);
  o->unstorable = atomic_load(&X.unstorable);
  o->restored = atomic_load(&X.restored);
  o->restored_expired = atomic_load(&X.restored_expired);
  o->file_won = atomic_load(&X.file_won);
  o->restore_bad = atomic_load(&X.restore_bad);
  o->restore_identity = atomic_load(&X.restore_identity);
  o->restore_pending = atomic_load(&g_xfr_pending);
  o->restore_ms = atomic_load(&X.restore_ms);
  o->restore_timeouts = atomic_load(&X.restore_timeouts);
  o->gc_deleted = atomic_load(&X.gc_deleted);
  o->stale_capped = atomic_load(&X.stale_capped);
  o->expired_zones = atomic_load(&X.expired_zones);
  o->expired_stale = atomic_load(&X.expired_stale);
  o->expired_servfail = atomic_load(&X.expired_servfail);
  o->stale_answers = atomic_load(&g_secondary_stale_answers);
  o->expire_events = atomic_load(&X.expire_events);
  db_store_rx_stats(&o->rx_texts, &o->rx_bytes, &o->rx_capped);
  o->rx_restored = atomic_load(&X.rx_restored);
  o->rx_lost = atomic_load(&X.rx_lost);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* D9: the expired secondaries (the control thread's tick)                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

#define XFR_HOURLY_PICK 20
static struct {
  uint64_t expired, stale, servfail;
  time_t oldest_since;
  char oldest_zone[256], oldest_view[64];
  zone_db_entry_t *hourly[XFR_HOURLY_PICK];
  bool hourly_serving[XFR_HOURLY_PICK];
  uint32_t hourly_lim[XFR_HOURLY_PICK];
  unsigned nhourly;
  time_t ev_window;
  unsigned ev_count;
  uint64_t suppressed;
  time_t summary_at;
} E;

#ifdef KARIDNS_TEST_EVICT
static unsigned hourly_s(void) { return X.log_interval ? X.log_interval : XFR_HOURLY_S; }
#else
static unsigned hourly_s(void) { return XFR_HOURLY_S; }
#endif

/* the per-zone events (expired, stale-limit, refreshed): at most XFR_EVENTS_PER_MIN a minute, the rest counted for the summary */
static bool event_ok(time_t now) {
  if (now - E.ev_window >= 60) {
    E.ev_window = now;
    E.ev_count = 0;
  }
  if (E.ev_count >= XFR_EVENTS_PER_MIN) {
    E.suppressed++;
    return false;
  }
  E.ev_count++;
  return true;
}

void xfr_expiry_begin(time_t now) {
  (void)now;
  E.expired = E.stale = E.servfail = 0;
  E.oldest_since = 0;
  E.nhourly = 0;
}

void xfr_expiry_entry(zone_db_entry_t *e, const server_config_t *cfg, time_t now) {
  const time_t deadline = zone_expire_deadline(e);
  const bool expired = deadline > 0 && now > deadline;
  zone_x_t *x = expired ? zone_x_need(e) : zone_x(e);
  if (!x) return;
  if (!expired) {
    if (x->exp_state != 0) {                          /* the first successful refresh after it was expired */
      if (event_ok(now)) {
        char d[32];
        fmt_dur(now - x->exp_since, d, sizeof(d));
        kdns_logc(LOGC_GENERAL, LOG_NOTICE, "[Zone] secondary-expired: refreshed zone '%s' view '%s' serving again, serial %u, was expired for %s", e->domain, zone_vname(e),
                  atomic_load_explicit(&e->serial, memory_order_relaxed), d);
      }
      x->exp_state = 0;
      x->exp_since = 0;
    }
    x->exp_stopped = false;
    return;
  }
  const zone_config_t *zc = e->is_catalog_member ? NULL : zone_entry_config((server_config_t *)cfg, e);
  const uint32_t lim = zone_secondary_stale_max(cfg, zc, zone_vname(e));
  const bool serving = zone_expired_serves_stale(cfg, zc, zone_vname(e), deadline, now);
  E.expired++;
  if (serving) E.stale++;
  else E.servfail++;
  if (!E.oldest_since || deadline < E.oldest_since) {
    E.oldest_since = deadline;
    snprintf(E.oldest_zone, sizeof(E.oldest_zone), "%s", e->domain);
    snprintf(E.oldest_view, sizeof(E.oldest_view), "%s", zone_vname(e));
  }
  if (x->exp_state == 0) {
    const bool stopped = x->exp_stopped;                /* (it was expired when the restore installed it: `expired while stopped`) */
    x->exp_stopped = false;
    x->exp_state = 1;
    x->exp_since = deadline;
    atomic_store_explicit(&x->last_stale_log_time, now, memory_order_release);
    atomic_fetch_add_explicit(&X.expire_events, 1, memory_order_relaxed);
    if (event_ok(now)) log_expired(e, deadline, atomic_load_explicit(&e->last_successful_transfer, memory_order_acquire), serving, stopped);
  }
  if (lim && cfg && cfg->serve_stale && !serving && x->exp_state != 2) {
    x->exp_state = 2;
    atomic_fetch_add_explicit(&X.stale_capped, 1, memory_order_relaxed);
    if (event_ok(now)) {
      char d[32], l[32];
      fmt_dur(now - deadline, d, sizeof(d));
      fmt_dur(lim, l, sizeof(l));
      kdns_logc(LOGC_GENERAL, LOG_ERR, "[Zone] secondary-expired: stale-limit zone '%s' view '%s' expired for %s, secondary-stale-max %s reached: answering SERVFAIL (EDE 24) from now on",
                e->domain, zone_vname(e), d, l);
    }
  }
  const time_t last = atomic_load_explicit(&x->last_stale_log_time, memory_order_acquire);
  if (now - last >= (time_t)hourly_s() && E.nhourly < XFR_HOURLY_PICK) {
    E.hourly[E.nhourly] = e;
    E.hourly_serving[E.nhourly] = serving;
    E.hourly_lim[E.nhourly] = serving && lim ? lim : 0;
    E.nhourly++;
  }
}

void xfr_expiry_end(time_t now) {
  atomic_store_explicit(&X.expired_zones, E.expired, memory_order_relaxed);
  atomic_store_explicit(&X.expired_stale, E.stale, memory_order_relaxed);
  atomic_store_explicit(&X.expired_servfail, E.servfail, memory_order_relaxed);
  const bool many = E.expired > XFR_SUMMARY_ABOVE;
  if (many || (E.suppressed > 0 && (!E.summary_at || now - E.summary_at >= (time_t)hourly_s()))) {
    if (E.summary_at && now - E.summary_at < (time_t)hourly_s()) return;
    E.summary_at = now;
    char ts[40], sup[64] = "";
    fmt_utc(E.oldest_since, ts, sizeof(ts));
    if (E.suppressed) snprintf(sup, sizeof(sup), "; %" PRIu64 " event line(s) suppressed", E.suppressed);
    kdns_logc(LOGC_GENERAL, LOG_WARNING, "[Zone] secondary-expired: summary: %" PRIu64 " zone(s) expired (%" PRIu64 " serving stale, %" PRIu64 " SERVFAIL), oldest '%s' view '%s' since %s%s",
              E.expired, E.stale, E.servfail, E.expired ? E.oldest_zone : "-", E.expired ? E.oldest_view : "-", ts, sup);
    E.suppressed = 0;
    for (unsigned i = 0; i < E.nhourly; i++) {      /* (the summary stands for the hourly lines: their clocks start again) */
      zone_x_t *x = zone_x(E.hourly[i]);
      if (x) atomic_store_explicit(&x->last_stale_log_time, now, memory_order_release);
    }
    return;
  }
  for (unsigned i = 0; i < E.nhourly; i++) {
    zone_db_entry_t *e = E.hourly[i];
    zone_x_t *x = zone_x(e);
    if (!x) continue;
    char d[32], l[48] = "";
    fmt_dur(now - x->exp_since, d, sizeof(d));
    if (E.hourly_lim[i]) {
      char ld[32];
      const int64_t left = (int64_t)E.hourly_lim[i] - (int64_t)(now - x->exp_since);
      fmt_dur(left, ld, sizeof(ld));
      snprintf(l, sizeof(l), ", stale limit in %s", ld);
    }
    kdns_logc(LOGC_GENERAL, LOG_WARNING, "[Zone] secondary-expired: still-expired zone '%s' view '%s' expired for %s; %s%s", e->domain, zone_vname(e), d,
              E.hourly_serving[i] ? "serving stale data" : "answering SERVFAIL", l);
    atomic_store_explicit(&x->last_stale_log_time, now, memory_order_release);
  }
}

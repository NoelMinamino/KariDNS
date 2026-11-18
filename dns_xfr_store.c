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
#include "dns_epoch_rcu.h"
#include "dns_log.h"
#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"
#include "dns_utils.h"
#include "dns_zone_image.h"
#include "dns_zone_parser.h"

#define XFR_RESTORE_NET_MS   30000      /* R2': no progress of the restore thread for this long while entries wait: the tick gives up on them */
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
  /* the test knobs of the integration tests (read once at the core start; tests/run_secondary_store_test.sh) */
  _Atomic long put_fail;
  char kill_zone[256];
  unsigned log_interval;
  _Atomic int64_t nospc_logged_ms, unstorable_logged;
  /* the start's figures */
  _Atomic uint64_t s_restored, s_expired, s_file, s_none;
  /* counters */
  _Atomic uint64_t puts, puts_uptodate, put_nospc, put_errors, state_writes, state_stale, state_skipped, orphans_deleted, unstorable;
  _Atomic uint64_t restored, restored_expired, file_won, restore_bad, restore_identity, restore_ms, restore_timeouts, gc_deleted;
  /* D9 */
  _Atomic uint64_t stale_capped, expire_events, expired_zones;
} X = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .zmu = PTHREAD_MUTEX_INITIALIZER, .vid = -1 };

#ifdef KARIDNS_UNIT_TEST
void (*_Atomic xfr_store_test_restore_hook)(zone_db_entry_t *e);
#endif

int xfr_store_vid(void) { return atomic_load_explicit(&X.vid, memory_order_acquire); }
bool xfr_store_active(void) { return atomic_load_explicit(&g_xfr_store_mode, memory_order_acquire) == XFRM_ACTIVE; }

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
} xinfo_t;

/* The key, the identity and the primaries digest of the entry, from the configuration in force.  Inside an RCU read section (the configuration and the snapshot are
 * read).  false: not a zone this module stores (a database secondary: P3; no name the store can hold). */
static bool entry_info(zone_db_entry_t *e, const server_config_t *cfg, zone_db_snapshot_t *snap, xinfo_t *xi) {
  memset(xi, 0, sizeof(*xi));
  if (!e || !e->is_secondary || e->source == ZONE_SRC_DB) return false;
  const char *view = zone_vname(e);
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
    atomic_fetch_add_explicit(&X.unstorable, 1, memory_order_relaxed);
    if (!atomic_exchange_explicit(&X.unstorable_logged, 1, memory_order_relaxed))
      syslog(LOG_NOTICE, "[Store] secondary zone '%s' (view '%s') is not kept in the zone store: its name is longer than %d octets (it is kept in memory only, as before; xfr.unstorable)",
             e->domain, view, XFR_KEY_ZONE_MAX);
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

/* M6: is the entry still the one the snapshot has for its view and zone? */
static bool entry_current(zone_db_entry_t *e) {
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

static void rec_delete(store_t *st, uint16_t vid, const char *key, size_t klen, uint32_t zid) {
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
} pin_t;

/* R2 (D5): settings the primary sent are in force for the zone (rxcfg; with primary-settings no they are kept aside and not used: nothing is lost by not persisting them) */
static bool rx_in_force(const zone_db_entry_t *e) {
  const zone_x_t *x = zone_x(e);
  return x && atomic_load_explicit(&x->rxcfg, memory_order_acquire) != NULL;
}

/* Values under the writer lock into locals; the version pinned with xfr_refs inside a read section (as dir_put_locked() does); both are left before the store is called (2.5) */
static bool pin_active(zone_db_entry_t *e, pin_t *p) {
  memset(p, 0, sizeof(*p));
  pthread_mutex_lock(&e->writer_lock);
  rcu_aux_read_lock();
  zone_version_t *v = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
  p->serial = atomic_load_explicit(&e->serial, memory_order_relaxed);
  p->last_ok = atomic_load_explicit(&e->last_successful_transfer, memory_order_relaxed);
  p->expire_at = atomic_load_explicit(&e->expire_at, memory_order_relaxed);
  p->origin = e->xfr_origin;
  p->rx = rx_in_force(e);
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
}

static void state_of(const xinfo_t *xi, const pin_t *p, time_t attempt_at, xfr_state_t *s) {
  memset(s, 0, sizeof(*s));
  s->kind = (uint8_t)xi->kind;
  s->identity = xi->identity;
  s->primaries = xi->primaries;
  xfr_state_set_times(s, p->last_ok, p->expire_at);
  if (p->origin == XFR_ORIGIN_FILE || p->origin == XFR_ORIGIN_STORE_FILE) s->flags |= XFR_SF_FROM_FILE;
  if (p->rx) s->flags |= XFR_SF_RX_LOST;
  s->last_attempt = attempt_at <= 0 ? 0 : attempt_at > (time_t)UINT32_MAX ? UINT32_MAX : (uint32_t)attempt_at;
}

/* the whole image of the active version, with the state (NO_DEGRADE: no room keeps the old copy, M1) */
static int put_image(store_t *st, uint16_t vid, zone_db_entry_t *e, const xinfo_t *xi, time_t attempt_at) {
  pin_t p;
  if (!pin_active(e, &p)) return -ENOENT;
  if (p.last_ok <= 0) p.last_ok = attempt_at;           /* (a version from a file without mtime: the refresh just confirmed it) */
  xfr_state_t s;
  state_of(xi, &p, attempt_at, &s);
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.flags = img_flags(p.v->image);
  m.serial = p.serial;
  m.stamp_time = (uint64_t)time(NULL);                  /* the save time of these bytes (D7) */
  xfr_state_encode(&s, m.digest);
  if (X.kill_zone[0] && (strcmp(X.kill_zone, "1") == 0 || strcasecmp(X.kill_zone, e->domain) == 0)) {
    syslog(LOG_WARNING, "[Store] KARIDNS_TEST_XFR_KILL_BEFORE_PUT: the process is killed between the install of '%s' (serial %u) and its put", e->domain, p.serial);
    kill(getpid(), SIGKILL);
  }
  int r;
  long pf = atomic_load_explicit(&X.put_fail, memory_order_relaxed);
  if (pf > 0 && atomic_compare_exchange_strong_explicit(&X.put_fail, &pf, pf - 1, memory_order_relaxed, memory_order_relaxed)) r = -ENOSPC;   /* (KARIDNS_TEST_XFR_PUT_FAIL) */
  else if ((uint64_t)p.v->image->total_size > 0x7fffffffu) r = -EFBIG;
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
  const int r = store_set_digest(st, vid, xi->key, (size_t)xi->klen, expect_serial, 0, dg, STORE_F_XFR, 0);
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
  store_zone_t z;
  const bool have = rec_get(st, (uint16_t)vid, &xi, &z) == 0;
  bool wrote = false;
  if (outcome == XFR_OUT_TRANSFERRED) {
    wrote = put_image(st, (uint16_t)vid, e, &xi, attempt_at) == 0;
  } else if (outcome == XFR_OUT_UPTODATE) {
    const uint32_t serial = atomic_load_explicit(&e->serial, memory_order_acquire);
    if (xfr_uptodate_action(have, have ? z.state : 0, have ? z.flags : 0, have ? z.serial : 0, serial) == XFR_UP_STATE) {
      pin_t p;
      memset(&p, 0, sizeof(p));
      pthread_mutex_lock(&e->writer_lock);
      p.serial = atomic_load_explicit(&e->serial, memory_order_relaxed);
      p.last_ok = atomic_load_explicit(&e->last_successful_transfer, memory_order_relaxed);
      p.expire_at = atomic_load_explicit(&e->expire_at, memory_order_relaxed);
      p.origin = e->xfr_origin;
      p.rx = rx_in_force(e);
      pthread_mutex_unlock(&e->writer_lock);
      xfr_state_t s;
      state_of(&xi, &p, attempt_at, &s);
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
      if (xfr_failure_skip(&old, &upd, time(NULL), atomic_load_explicit(&e->retry, memory_order_relaxed)))
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

static int restore_do(zone_db_entry_t *e) {
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
  /* step 3: the image, read and checked as an attach checks it; a heap copy (W8: MAP would pin its segment for ever, COPY's buffer is the store's) */
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
    make_known(st, vid, &xi, &z);                    /* (the next refresh stores the zone again: the up-to-date rule puts the image) */
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
  zone_install_version(e, ver, cur, false);          /* (no NOTIFY: the downstream secondaries have this serial, or ask for it at their refresh) */
  const time_t deadline = zone_expire_deadline(e);
  atomic_store_explicit(&e->next_check, xfr_restore_next_check(&s, rt, deadline, now), memory_order_release);
  pthread_mutex_unlock(&e->writer_lock);
  if (tm.clamped)
    syslog(LOG_WARNING, "[Store] secondary zone '%s' (view '%s'): the times of the stored copy are ahead of the clock (the clock went back?): taken as now in memory, not written back",
           e->domain, zone_vname(e));
  /* step 6: other primaries than when the copy was written: the data is kept, refreshed at once */
  if (s.primaries != xi.primaries) {
    atomic_store_explicit(&e->refresh_now, true, memory_order_release);
    syslog(LOG_INFO, "[Store] secondary zone '%s' (view '%s'): the primaries changed since the copy was stored; the copy is served and the zone is refreshed now", e->domain, zone_vname(e));
  }
  zone_x_t *x = zone_x_need(e);
  if ((s.flags & XFR_SF_RX_LOST) && x) atomic_store_explicit(&x->xfr_axfr_once, true, memory_order_relaxed);
  atomic_fetch_add_explicit(&X.restored, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&X.s_restored, 1, memory_order_relaxed);
  if (deadline > 0 && now > deadline) {
    atomic_fetch_add_explicit(&X.restored_expired, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&X.s_expired, 1, memory_order_relaxed);
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    const bool serving = zone_expired_serves_stale(cfg, e->is_catalog_member ? NULL : zone_entry_config((server_config_t *)cfg, e), zone_vname(e), deadline, now);
    release_config_snapshot(cfg);
    rcu_aux_read_unlock();
    if (x) {                                          /* (the tick does not say `expired` again for it: the restore did) */
      x->exp_state = 1;
      x->exp_since = deadline;
      atomic_store_explicit(&x->last_stale_log_time, now, memory_order_release);
    }
    atomic_fetch_add_explicit(&X.expire_events, 1, memory_order_relaxed);
    log_expired(e, deadline, tm.last_ok, serving, true);
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
  const int r = restore_do(e);
  (void)zone_restore_pending_clear(e);              /* R2: every way out clears it */
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

static uint64_t gc_run(store_t *st, uint16_t vid, const hset_t *cur, const hset_t *exempt, bool cur_ok) {
  if (!cur_ok || !atomic_load_explicit(&X.zs_built, memory_order_acquire)) return 0;      /* (a set that could not be made completely deletes nothing) */
  zbits_t b;
  if (!zs_copy(&b)) return 0;
  uint64_t deleted = 0;
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
      if (sok && (s.kind == XFR_K_DB_SLAVE || s.kind == XFR_K_DB_CONSUMER)) continue;      /* (R3: the database secondaries are P3's: never deleted here) */
      if (sok && s.kind == XFR_K_MEMBER && hset_has(exempt, (uint64_t)tag + 1)) continue;   /* (M6: a catalog of that view has not refreshed since the start) */
      if (store_delete_name(st, vid, z.name, kl) == 0) {
        zs_del(zid);
        deleted++;
      }
      progress_stamp();
    }
  }
  free(b.w);
  if (deleted) atomic_fetch_add_explicit(&X.gc_deleted, deleted, memory_order_relaxed);
  return deleted;
}

static uint64_t pass_run(void) {
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  if (!st || vid < 0) return 0;
  zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
  if (!snap) return 0;
  zone_db_entry_t **pend = NULL;
  size_t np = 0, cap = 0;
  hset_t cur = { 0 }, exempt = { 0 };
  bool cur_ok = true;
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
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
        continue;
      }
      xinfo_t xi;
      if (!entry_info(e, cfg, snap, &xi)) continue;
      cur_ok = hset_add(&cur, key_hash(xi.key, (size_t)xi.klen)) && cur_ok;
      if (xi.kind == XFR_K_CATALOG && !atomic_load_explicit(&zone_xr(e)->xfr_refreshed, memory_order_acquire))
        cur_ok = hset_add(&exempt, (uint64_t)xi.view_tag + 1) && cur_ok;
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
  const uint64_t del = gc_run(st, (uint16_t)vid, &cur, &exempt, cur_ok);
  free(cur.h);
  free(exempt.h);
  release_zone_snapshot(snap);
  return del;
}

static void *restore_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  store_t *st = atomic_load_explicit(&X.st, memory_order_acquire);
  const int vid = xfr_store_vid();
  if (st && vid >= 0) zs_build(st, (uint16_t)vid);
  pthread_mutex_lock(&X.mu);
  while (!X.stop) {
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
  progress_stamp();                                   /* (R2': the new pending entries are counted from now, not from the thread's last step) */
  pthread_mutex_lock(&X.mu);
  X.req_gen++;
  pthread_cond_broadcast(&X.cv);
  pthread_mutex_unlock(&X.mu);
}

static const xfr_store_ops_t g_ops = { .after_refresh = after_refresh, .rebuilt = ask_pass };

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

static void read_test_knobs(void) {
  const char *pf = getenv("KARIDNS_TEST_XFR_PUT_FAIL");
  atomic_store_explicit(&X.put_fail, pf ? strtol(pf, NULL, 10) : 0, memory_order_relaxed);
  const char *kz = getenv("KARIDNS_TEST_XFR_KILL_BEFORE_PUT");
  snprintf(X.kill_zone, sizeof(X.kill_zone), "%s", kz ? kz : "");
  const char *li = getenv("KARIDNS_TEST_STALE_LOG_INTERVAL");
  X.log_interval = li ? (unsigned)strtoul(li, NULL, 10) : 0;
}

bool xfr_store_core_start(store_t *st, bool quarantined, bool created) {
  read_test_knobs();
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
  while (!X.first_done && !X.stop)
    if (pthread_cond_timedwait(&X.cv, &X.mu, &ts) != 0) break;
  const bool done = X.first_done;
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
  return mono_ms() - p > XFR_RESTORE_NET_MS;
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
  } else if (!st || vid < 0 || e->source == ZONE_SRC_DB) {
    APP("Store: off\n");
  } else {
    xinfo_t xi;
    store_zone_t z;
    char ts[40];
    if (!entry_info_now(e, &xi)) APP("Store: not kept (the name is too long)\n");
    else if (rec_get(st, (uint16_t)vid, &xi, &z) != 0 || z.state != STORE_STATE_STORED) APP("Store: no copy\n");
    else {
      fmt_utc((time_t)z.stamp_time, ts, sizeof(ts));
      APP("Store: copy serial %u, %u bytes, saved %s\n", z.serial, z.img_len, ts);
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
  o->stale_answers = atomic_load(&g_secondary_stale_answers);
  o->expire_events = atomic_load(&X.expire_events);
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

static unsigned hourly_s(void) { return X.log_interval ? X.log_interval : XFR_HOURLY_S; }

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
    x->exp_state = 1;
    x->exp_since = deadline;
    atomic_store_explicit(&x->last_stale_log_time, now, memory_order_release);
    atomic_fetch_add_explicit(&X.expire_events, 1, memory_order_relaxed);
    if (event_ok(now)) log_expired(e, deadline, atomic_load_explicit(&e->last_successful_transfer, memory_order_acquire), serving, false);
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

#ifdef KARIDNS_UNIT_TEST
int xfr_store_test_restore_one(zone_db_entry_t *e) { return restore_one(e); }
uint64_t xfr_store_test_pass(void) { return pass_run(); }
void xfr_store_test_reset_counters(void) {
  atomic_store(&X.puts, 0); atomic_store(&X.puts_uptodate, 0); atomic_store(&X.put_nospc, 0); atomic_store(&X.put_errors, 0);
  atomic_store(&X.state_writes, 0); atomic_store(&X.state_stale, 0); atomic_store(&X.state_skipped, 0); atomic_store(&X.orphans_deleted, 0);
  atomic_store(&X.restored, 0); atomic_store(&X.restored_expired, 0); atomic_store(&X.file_won, 0); atomic_store(&X.restore_bad, 0);
  atomic_store(&X.restore_identity, 0); atomic_store(&X.gc_deleted, 0); atomic_store(&X.restore_timeouts, 0);
}
#endif

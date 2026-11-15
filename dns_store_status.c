/*
 * dns_store_status.c - the counters and the report of `karictl store` (header: dns_store_status.h; design section 9).
 *
 * The report is built as a list of (key, value) entries first and written three ways from it, so that the text, the JSON object and the
 * key=value lines can not drift apart.  The keys are an interface (docs/karictl.md); the text form groups them by the first two parts of the
 * key and leaves the histogram buckets out.
 */
#include "dns_store_status.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* counters                                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------------------------ */

#define NSHARD 8
typedef struct {
  _Atomic uint64_t attaches, failed[STORE_ATT_CAUSES], detaches, det_by[STORE_DET_REASONS], cold[STORE_COLD_PATHS];
  _Atomic uint64_t ah[STORE_STATUS_HIST_BUCKETS], ch[STORE_STATUS_HIST_BUCKETS];
  _Atomic uint64_t amax, cmax;
} shard_t;
static shard_t g_sh[NSHARD] __attribute__((aligned(64)));
static _Atomic unsigned g_next_shard;
static _Thread_local int t_shard = -1;

static shard_t *my_shard(void) {
  if (t_shard < 0) t_shard = (int)(atomic_fetch_add_explicit(&g_next_shard, 1, memory_order_relaxed) % NSHARD);
  return &g_sh[t_shard];
}
static inline void inc(_Atomic uint64_t *c) { atomic_fetch_add_explicit(c, 1, memory_order_relaxed); }
static void max_to(_Atomic uint64_t *m, uint64_t v) {
  uint64_t cur = atomic_load_explicit(m, memory_order_relaxed);
  while (v > cur && !atomic_compare_exchange_weak_explicit(m, &cur, v, memory_order_relaxed, memory_order_relaxed)) {}
}
static unsigned bucket_of(uint64_t ns) {
  uint64_t us = (ns + 999) / 1000;
  if (us <= 1) return 0;
  unsigned b = 64u - (unsigned)__builtin_clzll(us - 1);
  return b >= STORE_STATUS_HIST_BUCKETS - 1 ? STORE_STATUS_HIST_BUCKETS - 1 : b;
}

void store_status_note_attach(uint64_t ns, int cause) {
  shard_t *s = my_shard();
  if (cause != STORE_ATT_OK) {
    inc(&s->failed[cause > 0 && cause < STORE_ATT_CAUSES ? cause : STORE_ATT_ERR_OTHER]);
    return;
  }
  inc(&s->attaches);
  inc(&s->ah[bucket_of(ns)]);
  max_to(&s->amax, ns);
}
void store_status_note_detach_why(int reason) {
  shard_t *s = my_shard();
  inc(&s->detaches);
  inc(&s->det_by[reason > 0 && reason < STORE_DET_REASONS ? reason : STORE_DET_OTHER]);
}
void store_status_note_detach(void) { store_status_note_detach_why(STORE_DET_OTHER); }
void store_status_note_cold(uint64_t ns, int path) {
  if (path < 0 || path >= STORE_COLD_PATHS) return;
  shard_t *s = my_shard();
  inc(&s->cold[path]);
  if (path == STORE_COLD_ATTACH) {
    inc(&s->ch[bucket_of(ns)]);
    max_to(&s->cmax, ns);
  }
}

void store_status_snapshot(store_attach_stats_t *o) {
  memset(o, 0, sizeof(*o));
  for (int i = 0; i < NSHARD; i++) {
    shard_t *s = &g_sh[i];
    o->attaches += atomic_load_explicit(&s->attaches, memory_order_relaxed);
    o->detaches += atomic_load_explicit(&s->detaches, memory_order_relaxed);
    for (int k = 0; k < STORE_ATT_CAUSES; k++) o->attach_failed[k] += atomic_load_explicit(&s->failed[k], memory_order_relaxed);
    for (int k = 0; k < STORE_DET_REASONS; k++) o->detach_by[k] += atomic_load_explicit(&s->det_by[k], memory_order_relaxed);
    for (int k = 0; k < STORE_COLD_PATHS; k++) o->cold[k] += atomic_load_explicit(&s->cold[k], memory_order_relaxed);
    for (int k = 0; k < STORE_STATUS_HIST_BUCKETS; k++) {
      o->attach_hist[k] += atomic_load_explicit(&s->ah[k], memory_order_relaxed);
      o->cold_hist[k] += atomic_load_explicit(&s->ch[k], memory_order_relaxed);
    }
    uint64_t a = atomic_load_explicit(&s->amax, memory_order_relaxed), c = atomic_load_explicit(&s->cmax, memory_order_relaxed);
    if (a > o->attach_max_ns) o->attach_max_ns = a;
    if (c > o->cold_max_ns) o->cold_max_ns = c;
  }
}

void store_status_reset(void) {
  for (int i = 0; i < NSHARD; i++) memset((void *)&g_sh[i], 0, sizeof(g_sh[i]));
}

uint64_t store_status_hist_pct(const uint64_t *hist, unsigned p, uint64_t max_ns) {
  uint64_t total = 0;
  for (int i = 0; i < STORE_STATUS_HIST_BUCKETS; i++) total += hist[i];
  if (total == 0) return 0;
  if (p > 100) p = 100;
  uint64_t want = (total * p + 99) / 100, cum = 0;
  if (want == 0) want = 1;
  for (int i = 0; i < STORE_STATUS_HIST_BUCKETS; i++) {
    cum += hist[i];
    if (cum >= want) return i == STORE_STATUS_HIST_BUCKETS - 1 ? (max_ns + 999) / 1000 : (uint64_t)1 << i;
  }
  return (max_ns + 999) / 1000;
}

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* what the server tells us                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------------------------ */

static _Atomic(store_t *) g_store;
static bool (*_Atomic g_mem_fn)(ma_est_t *);
static bool (*_Atomic g_att_fn)(uint32_t);
static uint64_t (*_Atomic g_att_count_fn)(void);
static bool (*_Atomic g_recon_fn)(store_recon_t *);

void store_status_bind(store_t *s) { atomic_store_explicit(&g_store, s, memory_order_release); }
void store_status_set_memory_fn(bool (*fn)(ma_est_t *out)) { atomic_store_explicit(&g_mem_fn, fn, memory_order_release); }
void store_status_set_attached_fn(bool (*fn)(uint32_t zid)) { atomic_store_explicit(&g_att_fn, fn, memory_order_release); }
void store_status_set_attached_count_fn(uint64_t (*fn)(void)) { atomic_store_explicit(&g_att_count_fn, fn, memory_order_release); }
void store_status_set_recon_fn(bool (*fn)(store_recon_t *out)) { atomic_store_explicit(&g_recon_fn, fn, memory_order_release); }

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* the entry list                                                                                                                 */
/* ------------------------------------------------------------------------------------------------------------------------------ */

enum { E_U = 0, E_S = 1 };
typedef struct {
  char key[56];
  uint8_t type;
  bool notext;                 /* left out of the text form (histogram buckets) */
  uint64_t u;
  char s[104];
} ent_t;
#define MAX_ENT 640
typedef struct {
  ent_t *e;
  unsigned n;
  bool ov;
} list_t;

static void add_u(list_t *l, bool notext, const char *key, uint64_t v) {
  if (l->n >= MAX_ENT) { l->ov = true; return; }
  ent_t *e = &l->e[l->n++];
  snprintf(e->key, sizeof(e->key), "%s", key);
  e->type = E_U;
  e->notext = notext;
  e->u = v;
  e->s[0] = '\0';
}
static void add_s(list_t *l, const char *key, const char *v) {
  if (l->n >= MAX_ENT) { l->ov = true; return; }
  ent_t *e = &l->e[l->n++];
  snprintf(e->key, sizeof(e->key), "%s", key);
  e->type = E_S;
  e->notext = false;
  e->u = 0;
  snprintf(e->s, sizeof(e->s), "%s", v);
}
#define U(k, v) add_u(l, false, (k), (uint64_t)(v))

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* the three writers                                                                                                              */
/* ------------------------------------------------------------------------------------------------------------------------------ */

typedef struct {
  char *p;
  size_t cap, len;
  bool ov;
} sb_t;
static void sb_put(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_put(sb_t *b, const char *fmt, ...) {
  if (b->ov) return;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= b->cap - b->len) { b->ov = true; return; }
  b->len += (size_t)n;
}
static void sb_json_str(sb_t *b, const char *s) {
  sb_put(b, "\"");
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') sb_put(b, "\\%c", c);
    else if (c < 0x20 || c == 0x7f) sb_put(b, "\\u%04x", c);
    else sb_put(b, "%c", c);
  }
  sb_put(b, "\"");
}
static void sb_kv_str(sb_t *b, const char *s) {
  bool plain = *s != '\0';
  for (const char *q = s; *q; q++)
    if (*q == ' ' || *q == '"' || *q == '\\' || *q == '=' || *q == '\'' || (unsigned char)*q < 0x20) plain = false;
  if (plain) { sb_put(b, "%s", s); return; }
  sb_put(b, "\"");
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') sb_put(b, "\\%c", c);
    else if (c < 0x20) sb_put(b, "?");
    else sb_put(b, "%c", c);
  }
  sb_put(b, "\"");
}

static void write_json(sb_t *b, const list_t *l) {
  sb_put(b, "{");
  for (unsigned i = 0; i < l->n; i++) {
    const ent_t *e = &l->e[i];
    sb_put(b, "%s\"%s\":", i ? "," : "", e->key);
    if (e->type == E_U) sb_put(b, "%" PRIu64, e->u);
    else sb_json_str(b, e->s);
  }
  sb_put(b, "}\n");
}
static void write_kv(sb_t *b, const list_t *l) {
  for (unsigned i = 0; i < l->n; i++) {
    const ent_t *e = &l->e[i];
    sb_put(b, "%s=", e->key);
    if (e->type == E_U) sb_put(b, "%" PRIu64, e->u);
    else sb_kv_str(b, e->s);
    sb_put(b, "\n");
  }
}
/* "store.attach.fail.io": section "attach", label "fail.io"; "store.state": section "store", label "state"; "schema": no section */
static void split_key(const char *key, char *sec, size_t secn, const char **label) {
  const char *d1 = strchr(key, '.');
  if (!d1) { snprintf(sec, secn, "%s", ""); *label = key; return; }
  const char *rest = d1 + 1;
  const char *d2 = strchr(rest, '.');
  if (!d2) { snprintf(sec, secn, "store"); *label = rest; return; }
  snprintf(sec, secn, "%.*s", (int)(d2 - rest), rest);
  *label = d2 + 1;
}
static void human(char *buf, size_t n, uint64_t v) {
  static const char *unit[] = { "B", "KB", "MB", "GB", "TB" };
  double d = (double)v;
  int u = 0;
  while (d >= 1024.0 && u < 4) { d /= 1024.0; u++; }
  if (u == 0) snprintf(buf, n, "%" PRIu64 " B", v);
  else snprintf(buf, n, "%.1f %s", d, unit[u]);
}
static void write_text(sb_t *b, const list_t *l) {
  char last[40] = "\x01";
  for (unsigned i = 0; i < l->n; i++) {
    const ent_t *e = &l->e[i];
    if (e->notext) continue;
    char sec[40];
    const char *label;
    split_key(e->key, sec, sizeof(sec), &label);
    if (strcmp(sec, last) != 0) {
      if (sec[0]) sb_put(b, "%s%s:\n", last[0] == '\x01' ? "" : "\n", sec);
      snprintf(last, sizeof(last), "%s", sec);
    }
    const char *ind = sec[0] ? "  " : "";
    if (e->type == E_S) { sb_put(b, "%s%s = %s\n", ind, label, e->s); continue; }
    size_t ll = strlen(label);
    if (ll >= 5 && strcmp(label + ll - 5, "bytes") == 0 && e->u >= 1024) {
      char h[32];
      human(h, sizeof(h), e->u);
      sb_put(b, "%s%s = %" PRIu64 " (%s)\n", ind, label, e->u, h);
    } else {
      sb_put(b, "%s%s = %" PRIu64 "\n", ind, label, e->u);
    }
  }
}

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* the page-cache sample                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------------------------ */

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static struct {
  const store_t *s;
  int64_t at;
  uint64_t sampled, resident;
  int err;
  bool have;
} g_samp;
static pthread_mutex_t g_samp_mu = PTHREAD_MUTEX_INITIALIZER;

static void page_sample(const store_t *s, uint64_t *sampled, uint64_t *resident, int *err, int64_t *age_ms) {
  int64_t now = mono_ms();
  pthread_mutex_lock(&g_samp_mu);
  if (!g_samp.have || g_samp.s != s || now - g_samp.at >= STORE_STATUS_SAMPLE_TTL_MS || now < g_samp.at) {
    g_samp.err = store_resident_sample(s, STORE_STATUS_SAMPLE_PAGES, (uint64_t)now * 2654435761u + 1, &g_samp.sampled, &g_samp.resident);
    g_samp.s = s;
    g_samp.at = now;
    g_samp.have = true;
  }
  *sampled = g_samp.sampled;
  *resident = g_samp.resident;
  *err = g_samp.err;
  *age_ms = now - g_samp.at;
  pthread_mutex_unlock(&g_samp_mu);
}

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* the entries                                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------------------------ */

static void hex(char *out, const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", p[i]);   /* (callers pass a buffer of 2n + 1) */
}

static void add_hist(list_t *l, const char *prefix, const uint64_t *h) {
  char k[56];
  for (int i = 0; i < STORE_STATUS_HIST_BUCKETS - 1; i++) {
    snprintf(k, sizeof(k), "%s.hist.le_%" PRIu64 "us", prefix, (uint64_t)1 << i);
    add_u(l, true, k, h[i]);
  }
  snprintf(k, sizeof(k), "%s.hist.more", prefix);
  add_u(l, true, k, h[STORE_STATUS_HIST_BUCKETS - 1]);
}

static void add_attach(list_t *l, const store_attach_stats_t *a) {
  uint64_t failed = 0;
  for (int i = 1; i < STORE_ATT_CAUSES; i++) failed += a->attach_failed[i];
  U("store.attach.count", a->attaches);
  U("store.attach.failed", failed);
  U("store.attach.fail.checksum", a->attach_failed[STORE_ATT_ERR_CHECKSUM]);
  U("store.attach.fail.record", a->attach_failed[STORE_ATT_ERR_RECORD]);
  U("store.attach.fail.invalid", a->attach_failed[STORE_ATT_ERR_INVALID]);
  U("store.attach.fail.io", a->attach_failed[STORE_ATT_ERR_IO]);
  U("store.attach.fail.memory", a->attach_failed[STORE_ATT_ERR_MEMORY]);
  U("store.attach.fail.other", a->attach_failed[STORE_ATT_ERR_OTHER]);
  U("store.attach.p50_us", store_status_hist_pct(a->attach_hist, 50, a->attach_max_ns));
  U("store.attach.p90_us", store_status_hist_pct(a->attach_hist, 90, a->attach_max_ns));
  U("store.attach.p99_us", store_status_hist_pct(a->attach_hist, 99, a->attach_max_ns));
  U("store.attach.max_us", (a->attach_max_ns + 999) / 1000);
  add_hist(l, "store.attach", a->attach_hist);
  U("store.detach.count", a->detaches);
  U("store.detach.limit", a->detach_by[STORE_DET_LIMIT]);
  U("store.detach.room", a->detach_by[STORE_DET_ROOM]);
  U("store.detach.operator", a->detach_by[STORE_DET_OPERATOR]);
  U("store.detach.other", a->detach_by[STORE_DET_OTHER]);
  U("store.cold.attach", a->cold[STORE_COLD_ATTACH]);
  U("store.cold.fetch", a->cold[STORE_COLD_FETCH]);
  U("store.cold.timeout", a->cold[STORE_COLD_TIMEOUT]);
  U("store.cold.p50_us", store_status_hist_pct(a->cold_hist, 50, a->cold_max_ns));
  U("store.cold.p90_us", store_status_hist_pct(a->cold_hist, 90, a->cold_max_ns));
  U("store.cold.p99_us", store_status_hist_pct(a->cold_hist, 99, a->cold_max_ns));
  U("store.cold.max_us", (a->cold_max_ns + 999) / 1000);
  add_hist(l, "store.cold", a->cold_hist);
}

static void add_memory(list_t *l) {
  bool (*fn)(ma_est_t *) = atomic_load_explicit(&g_mem_fn, memory_order_acquire);
  ma_est_t m;
  memset(&m, 0, sizeof(m));
  bool have = fn && fn(&m);
  U("store.memory.available", have ? 1 : 0);
  if (!have) return;
  static const char *basis[] = { "assumed", "resident", "records" };
  U("store.memory.zones", m.zones);
  U("store.memory.records", m.records);
  add_s(l, "store.memory.basis", m.basis >= 0 && m.basis <= MA_BASIS_RECORDS ? basis[m.basis] : "assumed");
  U("store.memory.counted_all_bytes", m.counted_all);
  U("store.memory.avg_zone_bytes", m.avg_zone);
  U("store.memory.backend_all_bytes", m.backend_all);
  U("store.memory.loader_all_bytes", m.loader_all);
  U("store.memory.directory_bytes", m.directory);
  U("store.memory.recommended_limit_bytes", m.recommended);
  U("store.memory.working_min_bytes", m.working_min);
  U("store.memory.fit_min_bytes", m.fit_min);
  U("store.memory.limit_bytes", m.limit);
  U("store.memory.fit_pct", m.fit_pct);
  U("store.memory.backend_limit_bytes", m.backend_limit);
  U("store.memory.loader_limit_bytes", m.loader_limit);
  add_s(l, "store.memory.level", ma_level_name(m.level));
}

/* 0.7 WP7b: the reconcile with the loader: the pass (entries, wanted bodies, fetched, swept, the guard) and what the background fetch has done since the start */
static void add_recon(list_t *l) {
  bool (*fn)(store_recon_t *) = atomic_load_explicit(&g_recon_fn, memory_order_acquire);
  store_recon_t *r = fn ? malloc(sizeof(*r)) : NULL;
  if (!r || !fn(r)) {
    free(r);
    U("store.recon.available", 0);
    return;
  }
  U("store.recon.available", 1);
  U("store.recon.pass.active", r->active ? 1 : 0);
  add_s(l, "store.recon.pass.view", r->view);
  U("store.recon.pass.started_unix", r->started_unix);
  U("store.recon.pass.duration_ms", r->duration_ms);
  U("store.recon.pass.estimate", r->estimate);
  U("store.recon.pass.entries", r->entries);
  U("store.recon.pass.created", r->created);
  U("store.recon.pass.changed", r->changed);
  U("store.recon.pass.renamed", r->renamed);
  U("store.recon.pass.same", r->same);
  U("store.recon.pass.pending", r->pending);
  U("store.recon.pass.kept", r->kept);
  U("store.recon.pass.skipped", r->skipped);
  U("store.recon.sweep.total", r->total);
  U("store.recon.sweep.unlisted", r->unlisted);
  U("store.recon.sweep.deleted", r->swept);
  U("store.recon.passes", r->passes);
  U("store.recon.wanted", r->wanted);
  U("store.zones.nonstore", r->nonstore);
  U("store.recon.bodies.known", r->known_now);
  U("store.recon.bodies.fetched", r->fetched);
  U("store.recon.bodies.failed", r->fetch_failed);
  U("store.recon.bodies.in_flight", r->in_flight);
  U("store.recon.changes.upserts", r->change_upserts);
  U("store.recon.changes.deletes", r->change_deletes);
  U("store.recon.cursors_kept", r->cursors);
  U("store.recon.guard.held_views", r->guard_views);
  if (r->guard_views) {
    add_s(l, "store.recon.guard.view", r->guard_view);
    U("store.recon.guard.unlisted", r->guard_unlisted);
    U("store.recon.guard.total", r->guard_total);
    U("store.recon.guard.since_unix", r->guard_unix);
    add_s(l, "store.recon.guard.release", "karictl reload -force");
  }
  free(r);
}

static void add_store(list_t *l, const store_t *s, const store_attach_stats_t *a) {
  store_stats_t *st = malloc(sizeof(*st));
  if (!st) { l->ov = true; return; }
  store_stats(s, st);
  char buf[40];
  add_s(l, "store.state", (st->state & STORE_ST_DEGRADED_NOSPC) ? "degraded" : "ok");
  U("store.state_bits", st->state);
  U("store.format", st->format);
  add_s(l, "store.mode", st->mode == STORE_MODE_COPY ? "copy" : "map");
  add_s(l, "store.fstype", st->fstype);
  hex(buf, st->uuid, 16);
  add_s(l, "store.uuid", buf);
  U("store.clean_flag", st->clean_flag ? 1 : 0);

  uint64_t attached = a->attaches > a->detaches ? a->attaches - a->detaches : 0;
  uint64_t (*acf)(void) = atomic_load_explicit(&g_att_count_fn, memory_order_acquire);
  if (acf) attached = acf();                       /* 0.7 S3: the zones in memory are counted by the attach table (an install puts a zone in memory too, not only an attach) */
  uint64_t image_bytes = 0;
  for (uint32_t v = 0; v < st->nviews && v < STORE_MAX_VIEWS; v++) image_bytes += st->views[v].image_bytes;
  U("store.zones.known", st->zones_known);
  U("store.zones.stored", st->zones_stored);
  U("store.zones.attached", attached);
  U("store.zones.rejected", st->zones_rejected);
  U("store.zones.free", st->zones_free);
  U("store.zones.image_bytes", image_bytes);
  U("store.views.count", st->nviews);
  for (uint32_t v = 0; v < st->nviews && v < STORE_MAX_VIEWS; v++) {
    char k[56];
    snprintf(k, sizeof(k), "store.view.%u.name", v);
    add_s(l, k, st->views[v].name);
    snprintf(k, sizeof(k), "store.view.%u.known", v);
    U(k, st->views[v].known);
    snprintf(k, sizeof(k), "store.view.%u.stored", v);
    U(k, st->views[v].stored);
    snprintf(k, sizeof(k), "store.view.%u.rejected", v);
    U(k, st->views[v].rejected);
    snprintf(k, sizeof(k), "store.view.%u.image_bytes", v);
    U(k, st->views[v].image_bytes);
  }
  U("store.tables.zt_records", st->zt_records);
  U("store.tables.zt_capacity", st->zt_capacity);
  U("store.tables.nx_used_bytes", st->nx_used);
  U("store.tables.nx_dead_bytes", st->nx_dead);
  U("store.tables.ix_gen", st->ix_gen);
  U("store.tables.ix_slots", st->ix_slots);
  U("store.tables.ix_used", st->ix_used);
  U("store.tables.ix_live", st->ix_live);
  U("store.tables.sx_gen", st->sx_gen);
  U("store.tables.sx_slots", st->sx_slots);
  U("store.tables.sx_used", st->sx_used);
  U("store.tables.sx_live", st->sx_live);
  U("store.segments.count", st->seg_count);
  U("store.segments.used_bytes", st->seg_used_bytes);
  U("store.segments.live_bytes", st->seg_live_bytes);
  U("store.segments.dead_pct", st->seg_used_bytes > st->seg_live_bytes ? (st->seg_used_bytes - st->seg_live_bytes) * 100 / st->seg_used_bytes : 0);
  U("store.journal.lsn", st->lsn);
  U("store.journal.checkpoint_lsn", st->ckpt_lsn);
  U("store.journal.committed_lsn", st->committed_lsn);
  U("store.journal.bytes", st->journal_bytes);
  U("store.journal.gen", st->journal_gen);
  U("store.checkpoint.count", st->checkpoints);
  U("store.checkpoint.last_unix", st->last_checkpoint_unix);
  U("store.checkpoint.last_us", st->last_checkpoint_us);
  U("store.writes.commits", st->commits);
  U("store.writes.puts", st->puts);
  U("store.writes.replaces", st->replaces);
  U("store.writes.deletes", st->deletes);
  U("store.writes.growths", st->growths);
  U("store.writes.errors", st->write_errors);
  const store_recovery_t *r = &st->recovery;
  U("store.recovery.created", r->created);
  U("store.recovery.was_clean", r->was_clean);
  U("store.recovery.used_older_super", r->used_older_super);
  U("store.recovery.rebuilt", r->rebuilt);
  U("store.recovery.journals_read", r->journals_read);
  U("store.recovery.records_replayed", r->records_replayed);
  U("store.recovery.journal_torn", r->journal_torn);
  U("store.recovery.rebuilt_zones", r->rebuilt_zones);
  U("store.recovery.dropped_zones", r->dropped_zones);
  U("store.recovery.open_us", r->open_us);

  /* the second-level cache */
  if (st->mode == STORE_MODE_MAP) {
    uint64_t sampled, resident;
    int err;
    int64_t age;
    page_sample(s, &sampled, &resident, &err, &age);
    add_s(l, "store.cache.kind", "page");
    if (err == 0) {
      U("store.cache.page.available", 1);
      U("store.cache.page.sampled_pages", sampled);
      U("store.cache.page.resident_pages", resident);
      U("store.cache.page.resident_pct", sampled ? resident * 100 / sampled : 0);
      U("store.cache.page.sample_age_ms", age);
    } else {
      char m[100];
      snprintf(m, sizeof(m), "n/a: mincore() fails here (%.60s)", strerror(err < 0 ? -err : err));
      U("store.cache.page.available", 0);
      add_s(l, "store.cache.page.note", m);
    }
  } else if (strcmp(st->fstype, "zfs") == 0) {
    add_s(l, "store.cache.kind", "arc");
    add_s(l, "store.cache.note", "see karictl (ARC kstats)");
  } else {
    add_s(l, "store.cache.kind", "copy");
  }
}

/* "name" or "name view": one index lookup, no attach */
static int add_zone(list_t *l, const store_t *s, const char *spec, char *err, size_t errn) {
  char name[STORE_NAME_MAX + 2], view[STORE_VIEW_NAME_MAX + 2] = "";
  int n = sscanf(spec, "%256s %64s", name, view);
  if (n < 1) { snprintf(err, errn, "ERROR zone name missing\n"); return -1; }
  size_t nl = strlen(name);
  while (nl > 1 && name[nl - 1] == '.') name[--nl] = '\0';
  if (nl > STORE_NAME_MAX) { snprintf(err, errn, "ERROR zone not found\n"); return -1; }
  store_stats_t *st = malloc(sizeof(*st));
  if (!st) { snprintf(err, errn, "ERROR out of memory\n"); return -1; }
  store_stats(s, st);
  uint32_t nviews = st->nviews;
  free(st);
  uint32_t zid = STORE_NONE;
  int hits = 0;
  uint16_t hv = 0;
  store_read_lock();
  if (view[0]) {
    int v = store_view_id(s, view);
    if (v >= 0 && (zid = store_find(s, (uint16_t)v, name, nl)) != STORE_NONE) { hits = 1; hv = (uint16_t)v; }
  } else {
    for (uint32_t v = 0; v < nviews; v++) {
      uint32_t z = store_find(s, (uint16_t)v, name, nl);
      if (z != STORE_NONE) { if (!hits) { zid = z; hv = (uint16_t)v; } hits++; }
    }
  }
  store_zone_t zz;
  int r = hits ? store_zone_get(s, zid, &zz) : -ENOENT;
  store_read_unlock();
  if (hits == 0 || r == -ENOENT) { snprintf(err, errn, "ERROR zone not found\n"); return -1; }
  if (hits > 1) { snprintf(err, errn, "ERROR zone exists in several views; give the view\n"); return -1; }
  if (r < 0) { snprintf(err, errn, "ERROR zone record is damaged (%s)\n", strerror(-r)); return -1; }
  const char *vn = store_view_name(s, hv);
  char buf[2 * STORE_DIGEST_LEN + 1];
  add_s(l, "store.zone.name", zz.name);
  add_s(l, "store.zone.view", vn ? vn : "");
  U("store.zone.zid", zz.zid);
  add_s(l, "store.zone.state", zz.state == STORE_STATE_STORED ? "stored" : "known");
  U("store.zone.serial", zz.serial);
  U("store.zone.flags", zz.flags);
  U("store.zone.source", zz.source);
  U("store.zone.source_id", zz.source_id > 0 ? zz.source_id : 0);
  U("store.zone.stamp_gen", zz.stamp_gen);
  U("store.zone.stamp_time", zz.stamp_time);
  U("store.zone.settings", zz.settings);
  U("store.zone.image_bytes", zz.img_len);
  if (zz.state == STORE_STATE_STORED) {
    U("store.zone.segment", zz.loc >> 36);
    U("store.zone.offset", (zz.loc & ((1ull << 36) - 1)) * 64);
  }
  hex(buf, zz.digest, STORE_DIGEST_LEN);
  add_s(l, "store.zone.digest", buf);
  bool (*af)(uint32_t) = atomic_load_explicit(&g_att_fn, memory_order_acquire);
  if (af) U("store.zone.attached", af(zz.zid) ? 1 : 0);
  return 0;
}

size_t store_status_format(char *out, size_t cap, int fmt, const char *zone) {
  if (!out || cap < 64) return 0;
  const store_t *s = atomic_load_explicit(&g_store, memory_order_acquire);
  list_t l = { 0 };
  l.e = malloc(sizeof(ent_t) * MAX_ENT);
  if (!l.e) { return (size_t)snprintf(out, cap, "ERROR out of memory\n"); }
  store_attach_stats_t *a = malloc(sizeof(*a));
  if (!a) { free(l.e); return (size_t)snprintf(out, cap, "ERROR out of memory\n"); }
  store_status_snapshot(a);
  struct timespec rt;
  clock_gettime(CLOCK_REALTIME, &rt);

  add_u(&l, false, "schema", STORE_STATUS_SCHEMA);
  add_u(&l, false, "store.time.mono_ms", (uint64_t)mono_ms());
  add_u(&l, false, "store.time.unix", (uint64_t)rt.tv_sec);
  if (zone && *zone) {
    if (!s) { free(a); free(l.e); return (size_t)snprintf(out, cap, "ERROR store not configured\n"); }
    char err[96];
    if (add_zone(&l, s, zone, err, sizeof(err)) < 0) { free(a); free(l.e); return (size_t)snprintf(out, cap, "%s", err); }
  } else {
    if (s) add_store(&l, s, a);
    else add_s(&l, "store.state", "none");
    add_attach(&l, a);
    add_memory(&l);
    add_recon(&l);
  }
  sb_t b = { out, cap, 0, false };
  if (fmt == STORE_FMT_JSON) write_json(&b, &l);
  else if (fmt == STORE_FMT_KV) write_kv(&b, &l);
  else write_text(&b, &l);
  if (l.ov || b.ov) {
    b.len = 0;
    b.ov = false;
    if (fmt == STORE_FMT_JSON) sb_put(&b, "{\"schema\":%d,\"error\":\"output too large\"}\n", STORE_STATUS_SCHEMA);
    else sb_put(&b, "ERROR output too large\n");
  }
  free(a);
  free(l.e);
  out[b.len] = '\0';
  return b.len;
}

size_t store_status_control(const char *arg, const char *rest, char *out, size_t cap) {
  char line[640];
  snprintf(line, sizeof(line), "%s %s", arg ? arg : "", rest ? rest : "");
  int fmt = STORE_FMT_TEXT;
  char zone[STORE_NAME_MAX + STORE_VIEW_NAME_MAX + 8] = "";
  bool want_zone = false;
  char *save = NULL;
  for (char *w = strtok_r(line, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) {
    if (want_zone) {                                   /* everything after `zone` is the name and an optional view */
      size_t zl = strlen(zone);
      if (zl + strlen(w) + 2 >= sizeof(zone)) return (size_t)snprintf(out, cap, "ERROR zone name too long\n");
      snprintf(zone + zl, sizeof(zone) - zl, "%s%s", zl ? " " : "", w);
    } else if (strcmp(w, "-j") == 0) fmt = STORE_FMT_JSON;
    else if (strcmp(w, "-k") == 0) fmt = STORE_FMT_KV;
    else if (strcmp(w, "zone") == 0) want_zone = true;
    else return (size_t)snprintf(out, cap, "ERROR usage: store [-j | -k] [zone <name> [view]]\n");
  }
  if (want_zone && !zone[0]) return (size_t)snprintf(out, cap, "ERROR zone name missing\n");
  return store_status_format(out, cap, fmt, want_zone ? zone : NULL);
}

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
  _Atomic uint64_t af[STORE_STATUS_FINE_BUCKETS], cf[STORE_STATUS_FINE_BUCKETS];
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
/* the fine buckets: 0 .. 7 us one each; from 8 us on, the power of two e (2^e <= us) and the three bits below its top bit: bucket (e - 2) x 8 + those bits, up to e = 23 */
unsigned store_status_fine_bucket(uint64_t ns) { return store_fine_bucket_us((ns + 999) / 1000); }    /* (the scheme is the store's: store_fine_bucket_us()) */
uint64_t store_status_fine_upper_us(unsigned i) {
  if (i >= STORE_STATUS_FINE_BUCKETS - 1) return UINT64_MAX;
  if (i < 8) return i;
  const unsigned e = i / 8 + 2, m = i % 8;
  return ((uint64_t)(9 + m) << (e - 3)) - 1;
}

void store_status_note_attach(uint64_t ns, int cause) {
  shard_t *s = my_shard();
  if (cause != STORE_ATT_OK) {
    inc(&s->failed[cause > 0 && cause < STORE_ATT_CAUSES ? cause : STORE_ATT_ERR_OTHER]);
    return;
  }
  inc(&s->attaches);
  inc(&s->ah[bucket_of(ns)]);
  inc(&s->af[store_status_fine_bucket(ns)]);
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
    inc(&s->cf[store_status_fine_bucket(ns)]);
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
    for (int k = 0; k < STORE_STATUS_FINE_BUCKETS; k++) {
      o->attach_fine[k] += atomic_load_explicit(&s->af[k], memory_order_relaxed);
      o->cold_fine[k] += atomic_load_explicit(&s->cf[k], memory_order_relaxed);
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
uint64_t store_status_fine_pct(const uint64_t *fine, unsigned permille, uint64_t max_ns) {
  uint64_t total = 0;
  for (int i = 0; i < STORE_STATUS_FINE_BUCKETS; i++) total += fine[i];
  if (total == 0) return 0;
  if (permille > 1000) permille = 1000;
  uint64_t want = (total * permille + 999) / 1000, cum = 0;
  if (want == 0) want = 1;
  const uint64_t mx = (max_ns + 999) / 1000;
  for (unsigned i = 0; i < STORE_STATUS_FINE_BUCKETS; i++) {
    cum += fine[i];
    if (cum < want) continue;
    const uint64_t up = store_status_fine_upper_us(i);
    return up < mx ? up : mx;
  }
  return mx;
}

/* ------------------------------------------------------------------------------------------------------------------------------ */
/* what the server tells us                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------------------------ */

static _Atomic(store_t *) g_store;
static bool (*_Atomic g_mem_fn)(ma_est_t *);
static bool (*_Atomic g_att_fn)(uint32_t);
static uint64_t (*_Atomic g_att_count_fn)(void);
static bool (*_Atomic g_recon_fn)(store_recon_t *);
static bool (*_Atomic g_extra_fn)(store_extra_t *);
static bool (*_Atomic g_lookup_fn)(store_lookup_t *);
static bool (*_Atomic g_fill_fn)(store_fill_t *);

void store_status_bind(store_t *s) { atomic_store_explicit(&g_store, s, memory_order_release); }
void store_status_set_memory_fn(bool (*fn)(ma_est_t *out)) { atomic_store_explicit(&g_mem_fn, fn, memory_order_release); }
void store_status_set_attached_fn(bool (*fn)(uint32_t zid)) { atomic_store_explicit(&g_att_fn, fn, memory_order_release); }
static _Atomic(void (*)(uint16_t, uint32_t, const char *, const char *, store_zdetail_t *)) g_zd_fn;
void store_status_set_zdetail_fn(void (*fn)(uint16_t sview, uint32_t zid, const char *view, const char *name, store_zdetail_t *out)) { atomic_store_explicit(&g_zd_fn, fn, memory_order_release); }
void store_status_set_attached_count_fn(uint64_t (*fn)(void)) { atomic_store_explicit(&g_att_count_fn, fn, memory_order_release); }
void store_status_set_extra_fn(bool (*fn)(store_extra_t *out)) { atomic_store_explicit(&g_extra_fn, fn, memory_order_release); }
void store_status_set_recon_fn(bool (*fn)(store_recon_t *out)) { atomic_store_explicit(&g_recon_fn, fn, memory_order_release); }
void store_status_set_lookup_fn(bool (*fn)(store_lookup_t *out)) { atomic_store_explicit(&g_lookup_fn, fn, memory_order_release); }
void store_status_set_fill_fn(bool (*fn)(store_fill_t *out)) { atomic_store_explicit(&g_fill_fn, fn, memory_order_release); }
static bool (*_Atomic g_xfr_fn)(store_xfr_t *);
void store_status_set_xfr_fn(bool (*fn)(store_xfr_t *out)) { atomic_store_explicit(&g_xfr_fn, fn, memory_order_release); }

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
#define MAX_ENT 900
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
  U("store.attach.p50_us", store_status_fine_pct(a->attach_fine, 500, a->attach_max_ns));
  U("store.attach.p90_us", store_status_fine_pct(a->attach_fine, 900, a->attach_max_ns));
  U("store.attach.p99_us", store_status_fine_pct(a->attach_fine, 990, a->attach_max_ns));
  U("store.attach.p999_us", store_status_fine_pct(a->attach_fine, 999, a->attach_max_ns));
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
  U("store.cold.p50_us", store_status_fine_pct(a->cold_fine, 500, a->cold_max_ns));
  U("store.cold.p90_us", store_status_fine_pct(a->cold_fine, 900, a->cold_max_ns));
  U("store.cold.p99_us", store_status_fine_pct(a->cold_fine, 990, a->cold_max_ns));
  U("store.cold.p999_us", store_status_fine_pct(a->cold_fine, 999, a->cold_max_ns));
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
  static const char *basis[] = { "assumed", "resident", "records", "store" };
  U("store.memory.zones", m.zones);
  U("store.memory.records", m.records);
  add_s(l, "store.memory.basis", m.basis >= 0 && m.basis <= MA_BASIS_STORE ? basis[m.basis] : "assumed");
  U("store.memory.counted_all_bytes", m.counted_all);
  U("store.memory.avg_zone_bytes", m.avg_zone);
  U("store.memory.backend_all_bytes", m.backend_all);
  U("store.memory.loader_all_bytes", m.loader_all);
  U("store.memory.directory_bytes", m.directory);
  U("store.memory.tables_bytes", m.tables);
  U("store.memory.mapped_bytes", m.mapped);
  U("store.memory.copy_mode", m.copy_mode ? 1 : 0);
  U("store.memory.recommended_limit_bytes", m.recommended);
  U("store.memory.working_min_bytes", m.working_min);
  U("store.memory.fit_min_bytes", m.fit_min);
  U("store.memory.limit_bytes", m.limit);
  U("store.memory.fit_pct", m.fit_pct);
  U("store.memory.backend_limit_bytes", m.backend_limit);
  U("store.memory.loader_limit_bytes", m.loader_limit);
  add_s(l, "store.memory.level", ma_level_name(m.level));
}

/* 0.7: the copies of the secondaries (the `secondaries:` block of the text form is the xfr section) */
static void add_xfr(list_t *l) {
  bool (*fn)(store_xfr_t *) = atomic_load_explicit(&g_xfr_fn, memory_order_acquire);
  store_xfr_t x;
  if (!fn || !fn(&x)) return;
  add_s(l, "xfr.view", x.vid >= 0 ? "_karidns-xfr" : "none");
  U("xfr.records", x.records);
  U("xfr.image_bytes", x.image_bytes);
  U("xfr.puts", x.puts);
  U("xfr.puts_uptodate", x.puts_uptodate);
  U("xfr.put_nospc", x.put_nospc);
  U("xfr.put_errors", x.put_errors);
  U("xfr.state_writes", x.state_writes);
  U("xfr.state_stale", x.state_stale);
  U("xfr.state_skipped", x.state_skipped);
  U("xfr.orphans_deleted", x.orphans_deleted);
  U("xfr.unstorable", x.unstorable);
  U("xfr.restored", x.restored);
  U("xfr.restored_expired", x.restored_expired);
  U("xfr.file_won", x.file_won);
  U("xfr.restore_bad", x.restore_bad);
  U("xfr.restore_identity", x.restore_identity);
  U("xfr.restore_pending", x.restore_pending);
  U("xfr.restore_ms", x.restore_ms);
  U("xfr.restore_timeouts", x.restore_timeouts);
  U("xfr.gc_deleted", x.gc_deleted);
  U("xfr.stale_capped", x.stale_capped);
  U("xfr.rx_texts", x.rx_texts);
  U("xfr.rx_bytes", x.rx_bytes);
  U("xfr.rx_capped", x.rx_capped);
  U("xfr.rx_restored", x.rx_restored);
  U("xfr.rx_lost", x.rx_lost);
  U("secondary.expired_zones", x.expired_zones);
  U("secondary.expired_stale", x.expired_stale);
  U("secondary.expired_servfail", x.expired_servfail);
  U("secondary.stale_answers", x.stale_answers);
  U("secondary.expire_events", x.expire_events);
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
  U("store.recon.thread", r->recon_thread ? 1 : 0);
  if (r->recon_thread) {
    U("store.recon.busy_pct", r->rt_busy_pct);
    U("store.recon.entries_per_s", r->rt_entries_per_s);
    U("store.recon.queued", r->rt_queued);
    U("store.recon.apply_ns_per_entry", r->rt_apply_ns_per_entry);
    U("store.recon.thread_entries", r->rt_entries);
    U("store.recon.thread_pages", r->rt_pages);
    U("store.recon.ring_full_stops", r->rt_full_stops);
  }
  U("store.recon.group_records", r->rt_group_records);
  U("store.recon.group_entries", r->rt_group_entries);
  U("store.ingest.loop_max_us", r->rt_loop_max_us);
  U("store.ingest.stream_max_us", r->rt_stream_max_us);
  U("store.lock.records_holds", r->rec_holds);
  U("store.lock.records_holds_slow", r->rec_holds_slow);
  U("store.lock.records_hold_max_us", r->rec_hold_max_us);
  U("store.lock.records_hold_p999_us", store_status_fine_pct(r->rec_hold_fine, 999, r->rec_hold_max_us * 1000));
  U("store.recon.settle_errors", r->settle_errors);
  U("store.recon.batch_store_errors", r->batch_store_errors);
  U("store.recon.batch_store_last_error", r->batch_store_last < 0 ? -r->batch_store_last : 0);
  U("store.lock.records_wait_max_us", r->rec_wait_max_us);
  U("store.recon.signer.held", r->signer_held);
  U("store.recon.signer.held_in_memory", r->signer_held_mem);
  U("store.recon.signer.unsigned", r->signer_unsigned);
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

/* 0.7 M3: the zone images (the figures are the ingest thread's or a builder's, dns_db_ingest.c) */
static void add_fill(list_t *l) {
  bool (*fn)(store_fill_t *) = atomic_load_explicit(&g_fill_fn, memory_order_acquire);
  store_fill_t f;
  if (!fn || !fn(&f)) return;
  U("store.fill.images", f.images);
  U("store.fill.image_bytes", f.image_bytes);
  U("store.fill.validate_ns", f.validate_ns);
  U("store.fill.validate_ns_per_image", f.images ? f.validate_ns / f.images : 0);
  U("store.fill.invalid", f.invalid);
  U("store.fill.store_only", f.store_only);
  U("store.fill.resident", f.resident);
}

/* 0.7: the by-name lookups of the first start (the figures are the ingest thread's, dns_db_ingest.c) */
static void add_lookup(list_t *l) {
  bool (*fn)(store_lookup_t *) = atomic_load_explicit(&g_lookup_fn, memory_order_acquire);
  store_lookup_t *k = fn ? malloc(sizeof(*k)) : NULL;
  if (!k || !fn(k)) {
    free(k);
    U("store.lookup.available", 0);
    return;
  }
  U("store.lookup.available", 1);
  U("store.lookup.ready", k->ready ? 1 : 0);
  U("store.lookup.asked", k->asked);
  U("store.lookup.found", k->found);
  U("store.lookup.none", k->none);
  U("store.lookup.failed", k->failed);
  U("store.lookup.pending", k->pending);
  U("store.lookup.pending_peak", k->peak);
  U("store.lookup.in_flight", k->in_flight);
  U("store.lookup.take_fail", k->take_fail);
  U("store.lookup.body_inline", k->body_inline);
  U("store.lookup.bad_body", k->bad_body);
  U("store.lookup.refused", k->refused);
  U("store.lookup.same_name", k->same_name);
  U("store.lookup.covered", k->covered);
  U("store.lookup.shed", k->shed);
  U("store.lookup.expired", k->expired);
  U("store.lookup.drop.room", k->drop_lk_room);
  U("store.lookup.drop.timeout", k->drop_lk_timeout);
  U("store.lookup.drop.queue", k->drop_lk_queue);
  U("store.lookup.servfail", k->servfail);
  U("store.lookup.remembered", k->remembered);
  U("store.lookup.reask_suppressed", k->reask_suppressed);
  U("store.lookup.remember_releases", k->remember_releases);
  U("store.lookup.drain.passes", k->drain_passes);
  U("store.lookup.drain.cut", k->drain_cut);
  U("store.lookup.drain.pass_max", k->drain_pass_max);
  U("store.lookup.drain.pass_max_us", (k->drain_pass_max_ns + 999) / 1000);
  U("store.park.drop.room", k->drop_zone_room);
  U("store.park.drop.timeout", k->drop_zone_timeout);
  U("store.park.drop.queue", k->drop_zone_queue);
  U("store.lookup.rtt.p50_us", store_status_hist_pct(k->hist, 50, k->max_ns));
  U("store.lookup.rtt.p99_us", store_status_hist_pct(k->hist, 99, k->max_ns));
  U("store.lookup.rtt.max_us", (k->max_ns + 999) / 1000);
  add_hist(l, "store.lookup.rtt", k->hist);
  free(k);
}

/* the server's own tables: the attach table, the pool of entries (design 4.2: a zone in memory costs one slot), the folded counters and the texts in memory (6.1, 6.7) */
static void add_extra(list_t *l) {
  bool (*fn)(store_extra_t *) = atomic_load_explicit(&g_extra_fn, memory_order_acquire);
  store_extra_t x;
  memset(&x, 0, sizeof(x));
  if (!fn || !fn(&x)) { U("store.entries.available", 0); return; }
  U("store.entries.available", 1);
  U("store.entries.pool_used", x.pool_used);
  U("store.entries.pool_slabs", x.pool_slabs);
  U("store.entries.pool_slab_bytes", x.pool_slab_bytes);
  U("store.entries.pool_slot_bytes", x.pool_slot_bytes);
  U("store.entries.pool_free_slots", x.pool_free_slots);
  U("store.entries.attach_table_slots", x.attach_slots);
  U("store.entries.attach_table_grows", x.attach_grows);
  U("store.entries.attach_table_shrinks", x.attach_shrinks);
  U("store.fold.zones", x.folded);
  U("store.fold.rows", x.fold_rows);
  U("store.fold.replaced", x.fold_replaced);
  U("store.errors.memory_texts", x.err_texts);
  U("store.errors.memory_noted", x.err_noted);
  U("store.errors.memory_pushed_out", x.err_dropped);
  U("store.detach.sampled", x.sampled_detaches);
  U("store.attach.build_ns_per_zone", x.build_n ? x.build_ns / x.build_n : 0);
  U("store.attach.worker.ok", x.wa_ok);
  U("store.attach.worker.mean_us", x.wa_ok ? x.wa_ns / x.wa_ok / 1000 : 0);
  U("store.attach.worker.not_resident", x.wa_cold);
  U("store.attach.worker.over_limit", x.wa_over);
  U("store.attach.worker.claimed", x.wa_claim);
  U("store.attach.worker.failed", x.wa_fail);
  U("store.attach.worker.declined", x.wa_decline);
  U("store.attach.worker.full", x.wa_full);
  U("store.attach.worker.registered", x.wa_adopted);
  U("store.attach.worker.dropped", x.wa_lost);
  {
    static const char *const hs[] = { "none", "attaching", "done", "high-mark", "off" };
    add_s(l, "store.hot.state", x.hot_state < 5 ? hs[x.hot_state] : "none");
  }
  U("store.hot.listed", x.hot_listed);
  U("store.hot.attached", x.hot_attached);
  U("store.hot.skipped", x.hot_skipped);
  U("store.hot.written_at_stop", x.hot_written);
  U("store.hot.threads", x.hot_threads);
  U("store.hot.attached_per_s", x.hot_per_s);
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
  U("store.segments.free_numbers", st->seg_free_numbers);
  U("store.segments.draining", st->seg_draining);
  U("store.segments.pinned", st->seg_pinned);
  U("store.journal.lsn", st->lsn);
  U("store.journal.checkpoint_lsn", st->ckpt_lsn);
  U("store.journal.committed_lsn", st->committed_lsn);
  U("store.journal.bytes", st->journal_bytes);
  U("store.journal.gen", st->journal_gen);
  U("store.journal.max_bytes", st->journal_max_bytes);
  U("store.journal.bound_bytes", st->journal_bound_bytes);
  U("store.journal.peak_bytes", st->journal_peak_bytes);
  U("store.journal.limit_waits", st->journal_limit_waits);
  U("store.journal.limit_wait_us", st->journal_limit_wait_us);
  U("store.journal.limit_wait_max_us", st->journal_limit_wait_max_us);
  U("store.journal.boost", st->journal_boost);
  U("store.journal.boosts", st->journal_boosts);
  U("store.journal.bytes_written", st->journal_bytes_written);
  U("store.bulk.active", st->bulk_active);                                       /* 0.7: the unlogged bulk fill of an empty store */
  U("store.bulk.fills", st->bulk_fills);
  U("store.bulk.resumed", st->bulk_resumed);
  U("store.bulk.recoveries", st->bulk_recoveries);
  U("store.bulk.recovered_known", st->recovery.bulk_known);
  U("store.bulk.checkpoints", st->bulk_checkpoints);
  U("store.bulk.unlogged_records", st->bulk_unlogged_records);
  U("store.bulk.since_unix", st->bulk_since_unix);
  U("store.bulk.ended_unix", st->bulk_ended_unix);
  U("store.bulk.next_checkpoint_bytes", st->bulk_next_bytes);
  U("store.bulk.end_pending", st->bulk_end_pending);
  U("store.bulk.cut", st->bulk_cut);
  U("store.writes.names_refused", st->names_refused);
  U("store.reserve.zones", st->reserve_zones);
  U("store.reserve.zones_used", st->reserve_zones_used);
  U("store.reserve.nx_bytes", st->reserve_nx_bytes);
  U("store.reserve.nx_used", st->reserve_nx_used);
  U("store.reserve.refused", st->reserve_refused);
  U("store.index.waits", st->index_waits);
  U("store.index.wait_us", st->index_wait_us);
  U("store.index.wait_max_us", st->index_wait_max_us);
  U("store.index.wait_giveups", st->index_wait_giveups);
  U("store.journal.commit_switches", st->journal_commit_switches);
  {                                                                              /* 0.7: the journal ring (the record is written after the writer mutex) */
    static const char *const jst[] = { "ok", "nospace", "failed" };
    add_s(l, "store.journal.state", jst[st->journal_state < 0 || st->journal_state > 2 ? 2 : st->journal_state]);
  }
  U("store.journal.error", st->journal_error);
  U("store.journal.failed_at_unix", st->journal_failed_unix);
  U("store.journal.ring_bytes", st->ring_bytes);
  U("store.journal.ring_unwritten_bytes", st->ring_unwritten_bytes);
  U("store.journal.ring_peak_bytes", st->ring_peak_bytes);
  U("store.journal.ring_waits", st->ring_waits);
  U("store.journal.ring_wait_max_us", st->ring_wait_max_us);
  U("store.journal.ring_full_in_lock", st->ring_full_in_lock);
  U("store.journal.leader_writes", st->leader_writes);
  U("store.journal.bytes_per_write", st->leader_writes ? st->leader_bytes / st->leader_writes : 0);
  U("store.journal.write_max_us", st->leader_write_max_us);
  U("store.journal.retries", st->leader_retries);
  U("store.journal.ck_waits", st->checkpoint_journal_waits);
  U("store.journal.defer_busy", st->defer_busy);
  U("store.writes.prewrites", st->image_prewrites);
  U("store.writes.prewrite_misses", st->image_prewrite_misses);
  U("store.ahead.allocs", st->ahead_allocs);
  U("store.ahead.alloc_us", st->ahead_alloc_us);
  U("store.ahead.alloc_max_us", st->ahead_alloc_max_us);
  U("store.ahead.thread_max_us", st->ahead_thread_max_us);
  U("store.ahead.errors", st->ahead_errors);
  U("store.ahead.busy_kicks", st->ahead_busy_kicks);
  U("store.ahead.unallocated_growths", st->ahead_unallocated_growths);
  U("store.segment.precreated", st->segment_precreated);
  U("store.segment.inline_creates", st->segment_inline_creates);
  U("store.segment.precreate_errors", st->segment_precreate_errors);
  U("store.segment.precreate_us", st->segment_precreate_us);
  U("store.segment.precreate_max_us", st->segment_precreate_max_us);
  U("store.segment.inline_create_max_us", st->segment_inline_create_max_us);
  U("store.segment.precreate_ready", st->segment_ready);
  U("store.checkpoint.count", st->checkpoints);
  U("store.checkpoint.last_unix", st->last_checkpoint_unix);
  U("store.checkpoint.last_us", st->last_checkpoint_us);
  U("store.checkpoint.max_us", st->checkpoint_max_us);
  U("store.checkpoint.cancelled", st->checkpoints_cancelled);
  U("store.checkpoint.table_bytes", st->checkpoint_table_bytes);
  U("store.checkpoint.table_last_bytes", st->checkpoint_table_last_bytes);
  U("store.checkpoint.paced_us", st->checkpoint_paced_us);
  U("store.tables.private_bytes", st->table_private_bytes);
  U("store.writes.commits", st->commits);
  U("store.writes.puts", st->puts);
  U("store.writes.replaces", st->replaces);
  U("store.writes.deletes", st->deletes);
  U("store.writes.growths", st->growths);
  U("store.writes.errors", st->write_errors);
  U("store.writes.growths_background", st->growths_background);
  U("store.lock.writer_holds", st->lock_holds);
  U("store.lock.writer_holds_slow", st->lock_holds_slow);
  U("store.lock.writer_hold_max_us", st->lock_hold_max_us);
  U("store.lock.writer_hold_p50_us", store_status_fine_pct(st->lock_hold_fine, 500, st->lock_hold_max_us * 1000));
  U("store.lock.writer_hold_p99_us", store_status_fine_pct(st->lock_hold_fine, 990, st->lock_hold_max_us * 1000));
  U("store.lock.writer_hold_p999_us", store_status_fine_pct(st->lock_hold_fine, 999, st->lock_hold_max_us * 1000));
  add_s(l, "store.lock.writer_hold_max_site", st->lock_hold_max_site ? st->lock_hold_max_site : "-");
  for (uint32_t i = 0; i < st->lock_nsites && i < STORE_LOCK_SITES; i++) {          /* 0.7: the holds of 1 ms or more by function */
    const store_lock_site_t *w = &st->lock_sites[i];
    char k[56];
    snprintf(k, sizeof(k), "store.lock.site.%.24s.slow", w->site);
    U(k, w->slow);
    snprintf(k, sizeof(k), "store.lock.site.%.24s.over_10ms", w->site);
    U(k, w->over_10ms);
    snprintf(k, sizeof(k), "store.lock.site.%.24s.over_100ms", w->site);
    U(k, w->over_100ms);
    snprintf(k, sizeof(k), "store.lock.site.%.24s.slow_us", w->site);
    U(k, w->slow_us);
    snprintf(k, sizeof(k), "store.lock.site.%.24s.max_us", w->site);
    U(k, w->max_us);
  }
  U("store.flusher", st->flusher ? 1 : 0);
  /* 0.7 WP9: the cleaner (design 3.2) */
  U("store.compact.runs", st->compact_runs);
  U("store.compact.moved_records", st->compact_moved_records);
  U("store.compact.moved_bytes", st->compact_moved_bytes);
  U("store.compact.segments_freed", st->compact_segs_freed);
  U("store.compact.bad_records", st->compact_bad_records);
  U("store.compact.pinned_skips", st->compact_pinned_skips);
  U("store.compact.incomplete", st->compact_incomplete);
  U("store.compact.last_unix", st->compact_last_unix);
  U("store.compact.rate_bytes", st->compact_rate == UINT64_MAX ? 0 : st->compact_rate);
  U("store.compact.candidates", st->compact_candidates);
  U("store.compact.dead_bytes", st->compact_dead_bytes);
  U("store.compact.nx_reclaims", st->nx_reclaims);
  U("store.compact.nx_reclaimed_bytes", st->nx_reclaimed_bytes);
  /* the file system, the free space and what happens when it runs out (design 3.5) */
  static const char *const lvl[] = { "ok", "low", "degraded" };
  add_s(l, "store.space.level", lvl[st->space_level > 2 ? 2 : st->space_level]);
  U("store.space.fs_total_bytes", st->fs_total_bytes);
  U("store.space.fs_free_bytes", st->fs_free_bytes);
  U("store.space.checked_unix", st->fs_checked_unix);
  U("store.space.reserve_bytes", st->reserve_bytes);
  add_u(l, false, "store.space.estimate_bytes", st->space_estimate_bytes < 0 ? 0 : (uint64_t)st->space_estimate_bytes);
  U("store.space.reprobe_in_lock", st->space_reprobe_in_lock);
  U("store.space.store_bytes", st->store_bytes);
  U("store.space.growth_bytes_per_hour", st->growth_bytes_per_hour);
  U("store.space.full_in_hours", st->full_in_hours);
  U("store.space.degraded_puts", st->degraded_puts);
  U("store.space.enospc_events", st->enospc_events);
  U("store.space.degraded_since_unix", st->degraded_since_unix);
  U("store.fs.blksize", st->fs_blksize);
  U("store.fs.recordsize_warning", st->fs_recordsize_warn ? 1 : 0);
  /* the scrub (design 2.4) */
  U("store.scrub.interval_s", st->scrub_interval_s == UINT32_MAX ? 0 : st->scrub_interval_s);
  U("store.scrub.running", st->scrub_running ? 1 : 0);
  U("store.scrub.progress_pct", st->scrub_progress_pct);
  U("store.scrub.passes", st->scrub_passes);
  U("store.scrub.last_start_unix", st->scrub_last_start_unix);
  U("store.scrub.last_end_unix", st->scrub_last_end_unix);
  U("store.scrub.zones_checked", st->scrub_zones_checked);
  U("store.scrub.bytes_checked", st->scrub_bytes_checked);
  U("store.scrub.bad_images", st->scrub_bad_images);
  U("store.scrub.bad_cells", st->scrub_bad_cells);
  U("store.scrub.bad_index", st->scrub_bad_index);
  U("store.scrub.io_errors", st->scrub_io_errors);
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
  U("store.open.ix_read_us", st->ix_read_us);
  U("store.open.zt_readahead_us", st->zt_readahead_us);
  U("store.open.zt_readahead_done", st->zt_readahead_done ? 1 : 0);
  U("store.errors.total", st->err_total);

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
  void (*zf)(uint16_t, uint32_t, const char *, const char *, store_zdetail_t *) = atomic_load_explicit(&g_zd_fn, memory_order_acquire);
  if (zf) {
    store_zdetail_t d;
    memset(&d, 0, sizeof(d));
    d.elem_state = -1;
    zf(hv, zz.zid, vn ? vn : "", zz.name, &d);
    U("store.zone.elem", d.elem ? 1 : 0);
    U("store.zone.resident", d.resident ? 1 : 0);
    U("store.zone.staged", d.staged ? 1 : 0);
    add_s(l, "store.zone.elem_state", d.elem_state == 1 ? "resident" : d.elem_state == 2 ? "loading" : d.elem_state == 3 ? "error" : d.elem_state == 0 ? "absent" : "none");
    U("store.zone.att_claim", d.att_claim ? 1 : 0);
    U("store.zone.att_claim_req", d.att_req ? 1 : 0);
    U("store.zone.att_claim_workers", d.att_set);
    U("store.zone.fetch_claim", d.fetch_claim ? 1 : 0);
  }
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
    add_extra(&l);
    add_xfr(&l);
    add_recon(&l);
    add_lookup(&l);
    add_fill(&l);
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

size_t store_status_op(const char *arg, const char *rest, char *out, size_t cap) {
  store_t *s = atomic_load_explicit(&g_store, memory_order_acquire);
  if (!s) return (size_t)snprintf(out, cap, "ERROR store not configured\n");
  char line[160];
  snprintf(line, sizeof(line), "%s %s", arg ? arg : "", rest ? rest : "");
  char w1[32] = "", w2[32] = "", w3[32] = "";
  int n = sscanf(line, "%31s %31s %31s", w1, w2, w3);
  store_stats_t *st = malloc(sizeof(*st));
  if (!st) return (size_t)snprintf(out, cap, "ERROR out of memory\n");
  size_t len;
  if (n == 1 && strcmp(w1, "compact") == 0) {
    store_compact_request(s);
    store_stats(s, st);
    len = (size_t)snprintf(out, cap, "OK the cleaner runs at full speed until no segment is dead enough (%u segment(s) are now, %" PRIu64 " dead bytes); the empty segments are removed at the end; karictl store: store.compact.*\n",
                           st->compact_candidates, st->compact_dead_bytes);
  } else if (n == 1 && strcmp(w1, "checkpoint") == 0) {
    int r = store_checkpoint(s);
    store_stats(s, st);
    if (r < 0) len = (size_t)snprintf(out, cap, "ERROR the checkpoint failed: %s\n", strerror(-r));
    else len = (size_t)snprintf(out, cap, "OK checkpoint %" PRIu64 " done in %" PRIu64 " us\n", st->checkpoints, st->last_checkpoint_us);
  } else if (n == 2 && strcmp(w1, "scrub") == 0 && strcmp(w2, "start") == 0) {
    store_scrub_start(s);
    len = (size_t)snprintf(out, cap, "OK the scrub runs (karictl store: store.scrub.*)\n");
  } else if (n == 2 && strcmp(w1, "scrub") == 0 && strcmp(w2, "stop") == 0) {
    store_scrub_stop(s);
    len = (size_t)snprintf(out, cap, "OK the scrub is stopped\n");
  } else {
    len = (size_t)snprintf(out, cap, "ERROR usage: store compact | checkpoint | scrub start | scrub stop\n");
  }
  (void)w3;
  free(st);
  return len < cap ? len : cap ? cap - 1 : 0;
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

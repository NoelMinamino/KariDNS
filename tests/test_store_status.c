/*
 * test_store_status.c - the counters and the report of `karictl store` (dns_store_status.c, 0.7 WP5).
 *
 * Cases: the histogram buckets and percentiles; the notes from several threads add up; no store bound (state=none) in the three formats,
 * with and without the memory figures; a store with three zones in two views and fake attach notes: the JSON is one valid object (a strict
 * checker below), the key=value lines and the text carry the same figures, every key of the documented interface is there, the numbers
 * are the ones the store and the notes gave, the output is bounded (32 views); the page-cache sample in MAP mode (a number, or "n/a" with
 * the reason when mincore() is not allowed) and the ZFS / COPY note; `zone <name> [view]` (found, other case, trailing dot, no such zone,
 * ambiguous without a view, a KNOWN zone); store_status_control's arguments; a buffer that is too small.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../dns_store.h"
#include "../dns_store_status.h"
#include "../dns_epoch_rcu.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* dns_epoch_rcu.c needs the worker table and the logger of the server; this test has no workers and ignores the log lines */
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);
void kdns_syslog(int prio, const char *fmt, ...) {
  (void)prio;
  (void)fmt;
}

static int g_checks, g_failed;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); fflush(stdout); } } while (0)
#define CHECK_EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); g_checks++; if (_a != _b) { g_failed++; \
    printf("  [FAIL] %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b); fflush(stdout); } } while (0)

static void rm_rf(const char *path) {
  struct stat st;
  if (lstat(path, &st) != 0) return;
  if (S_ISDIR(st.st_mode)) {
    DIR *d = opendir(path);
    if (d) {
      struct dirent *de;
      while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char sub[1024];
        snprintf(sub, sizeof(sub), "%s/%s", path, de->d_name);
        rm_rf(sub);
      }
      closedir(d);
    }
    rmdir(path);
  } else {
    unlink(path);
  }
}

/* ---- a strict checker for the one JSON object: flat, keys of [a-z0-9._], values numbers (integers) or strings.  Stores the pairs. ---- */
#define MAXKV 800
typedef struct { char key[80]; bool is_str; unsigned long long num; char str[160]; } kv_t;
static kv_t g_kv[MAXKV];
static int g_nkv;

static const kv_t *kv_get(const char *key) {
  for (int i = 0; i < g_nkv; i++) if (strcmp(g_kv[i].key, key) == 0) return &g_kv[i];
  return NULL;
}
static unsigned long long kv_num(const char *key) {
  const kv_t *k = kv_get(key);
  if (!k || k->is_str) { printf("  (missing or not a number: %s)\n", key); g_failed++; return 0; }
  return k->num;
}
static const char *kv_str(const char *key) {
  const kv_t *k = kv_get(key);
  if (!k || !k->is_str) { printf("  (missing or not a string: %s)\n", key); g_failed++; return ""; }
  return k->str;
}

/* returns true when the text is exactly one valid object followed by a newline */
static bool parse_json(const char *p) {
  g_nkv = 0;
  if (*p++ != '{') return false;
  if (*p == '}') return p[1] == '\n' && p[2] == '\0';
  for (;;) {
    if (*p++ != '"') return false;
    kv_t *kv = &g_kv[g_nkv];
    size_t n = 0;
    while (*p && *p != '"') {
      if (!(islower((unsigned char)*p) || isdigit((unsigned char)*p) || *p == '.' || *p == '_')) return false;
      if (n + 1 >= sizeof(kv->key)) return false;
      kv->key[n++] = *p++;
    }
    kv->key[n] = '\0';
    if (*p++ != '"' || *p++ != ':') return false;
    if (kv_get(kv->key)) return false;                         /* a key twice */
    if (*p == '"') {
      p++;
      kv->is_str = true;
      n = 0;
      while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20) return false;
        if (c == '\\') {
          p++;
          if (*p == '"' || *p == '\\' || *p == '/') c = (unsigned char)*p++;
          else if (*p == 'u') { p += 5; c = '?'; }
          else return false;
        } else p++;
        if (n + 1 >= sizeof(kv->str)) return false;
        kv->str[n++] = (char)c;
      }
      if (*p++ != '"') return false;
      kv->str[n] = '\0';
    } else {
      if (!isdigit((unsigned char)*p)) return false;
      if (*p == '0' && isdigit((unsigned char)p[1])) return false;   /* no leading zeros */
      char *end;
      kv->is_str = false;
      kv->num = strtoull(p, &end, 10);
      p = end;
    }
    if (++g_nkv >= MAXKV) return false;
    if (*p == ',') { p++; continue; }
    if (*p == '}') return p[1] == '\n' && p[2] == '\0';
    return false;
  }
}

/* the key=value form: every line key=value, same pairs as the JSON */
static bool kv_matches_json(const char *kvtext) {
  int lines = 0;
  const char *p = kvtext;
  while (*p) {
    const char *nl = strchr(p, '\n');
    if (!nl) return false;
    char line[400];
    size_t len = (size_t)(nl - p);
    if (len >= sizeof(line)) return false;
    memcpy(line, p, len);
    line[len] = '\0';
    char *eq = strchr(line, '=');
    if (!eq) return false;
    *eq = '\0';
    const kv_t *k = kv_get(line);
    if (!k) { printf("  (kv key not in json: %s)\n", line); return false; }
    if (!k->is_str) { if (strtoull(eq + 1, NULL, 10) != k->num && strcmp(line, "store.time.mono_ms") && strcmp(line, "store.time.unix")
                                 && strcmp(line, "store.cache.page.sample_age_ms") && strncmp(line, "store.open.", 11) && strcmp(line, "store.space.checked_unix")) {      /* (the read-ahead thread may end between the two calls) */ printf("  (kv value differs: %s)\n", line); return false; } }
    lines++;
    p = nl + 1;
  }
  return lines == g_nkv;
}

static bool extra_fn(store_extra_t *x) {
  memset(x, 0, sizeof(*x));
  x->pool_used = 7; x->pool_slabs = 1; x->pool_slab_bytes = 2u << 20; x->pool_slot_bytes = 256; x->pool_free_slots = 100;
  x->attach_slots = 2048; x->attach_grows = 3; x->attach_shrinks = 1;
  x->folded = 11; x->fold_rows = 5; x->fold_replaced = 2; x->err_texts = 4; x->err_noted = 9; x->err_dropped = 1; x->sampled_detaches = 6;
  x->wa_ok = 100; x->wa_cold = 7; x->wa_over = 2; x->wa_claim = 3; x->wa_fail = 4; x->wa_decline = 5; x->wa_full = 6; x->wa_adopted = 98; x->wa_lost = 2; x->wa_ns = 1500000;
  x->hot_state = 2; x->hot_listed = 1000; x->hot_attached = 990; x->hot_skipped = 10; x->hot_written = 1234; x->hot_threads = 6; x->hot_per_s = 123456;
  return true;
}
static bool g_mem_ok = true;
static bool mem_fn(ma_est_t *e) {
  if (!g_mem_ok) return false;
  ma_in_t in;
  memset(&in, 0, sizeof(in));
  in.zones = 1000;
  ma_estimate(&in, e);
  return true;
}
static bool att_fn(uint32_t zid) { return zid == 0; }

static const char *REQUIRED[] = {
  "schema", "store.time.mono_ms", "store.time.unix", "store.state", "store.state_bits", "store.format", "store.mode", "store.fstype",
  "store.uuid", "store.clean_flag", "store.zones.known", "store.zones.stored", "store.zones.attached", "store.zones.rejected",
  "store.zones.free", "store.zones.image_bytes", "store.views.count", "store.view.0.name", "store.view.0.stored", "store.tables.zt_records",
  "store.tables.ix_slots", "store.segments.count", "store.segments.used_bytes", "store.segments.live_bytes", "store.segments.dead_pct",
  "store.journal.lsn", "store.checkpoint.count", "store.writes.puts", "store.writes.errors", "store.recovery.created", "store.recovery.open_us",
  "store.writes.growths_background", "store.flusher", "store.lock.writer_holds", "store.lock.writer_holds_slow", "store.lock.writer_hold_max_us", "store.lock.writer_hold_max_site",     /* (0.7 fix A; the site: 0.7 leftovers) */
  "store.journal.bound_bytes", "store.journal.peak_bytes", "store.journal.limit_waits", "store.journal.limit_wait_us", "store.journal.limit_wait_max_us",
  "store.checkpoint.max_us", "store.checkpoint.cancelled",                                                                                  /* (0.7: the journal bound) */
  "store.cache.kind", "store.attach.count", "store.attach.failed", "store.attach.fail.checksum", "store.attach.fail.record",
  "store.attach.fail.invalid", "store.attach.fail.io", "store.attach.fail.memory", "store.attach.fail.other", "store.attach.p50_us",
  "store.attach.p90_us", "store.attach.p99_us", "store.attach.max_us", "store.attach.hist.le_1us", "store.attach.hist.le_8388608us",
  "store.attach.hist.more", "store.detach.count", "store.detach.limit", "store.detach.room", "store.detach.operator", "store.detach.other",
  "store.cold.attach", "store.cold.fetch", "store.cold.timeout", "store.cold.p50_us", "store.cold.p90_us", "store.cold.p99_us",
  "store.cold.max_us", "store.cold.hist.le_1us", "store.cold.hist.more", "store.memory.available",
  NULL
};

/* ---- cases ---- */

static void test_hist(void) {
  printf("[histogram]\n");
  store_status_reset();
  store_attach_stats_t a;
  store_status_note_attach(500, 0);            /* <= 1 us */
  store_status_note_attach(1000, 0);           /* 1 us: bucket 0 */
  store_status_note_attach(1001, 0);           /* 2 us: bucket 1 */
  store_status_note_attach(3000, 0);           /* 3 us: bucket 2 (<= 4) */
  store_status_note_attach(8388608ull * 1000, 0);        /* 2^23 us: bucket 23 */
  store_status_note_attach(8388609ull * 1000, 0);        /* more */
  store_status_snapshot(&a);
  CHECK_EQ(a.attaches, 6);
  CHECK_EQ(a.attach_hist[0], 2);
  CHECK_EQ(a.attach_hist[1], 1);
  CHECK_EQ(a.attach_hist[2], 1);
  CHECK_EQ(a.attach_hist[23], 1);
  CHECK_EQ(a.attach_hist[24], 1);
  CHECK_EQ(a.attach_max_ns, 8388609ull * 1000);
  CHECK_EQ(store_status_hist_pct(a.attach_hist, 50, a.attach_max_ns), 2);       /* the 3rd of 6 lies in bucket 1 (<= 2 us) */
  CHECK_EQ(store_status_hist_pct(a.attach_hist, 100, a.attach_max_ns), 8388609);/* the last bucket answers with the maximum */
  CHECK_EQ(store_status_hist_pct(a.cold_hist, 99, 0), 0);                       /* empty histogram */
  /* 0.7: the fine histogram of the percentiles (an eighth of a power of two) */
  CHECK_EQ(store_status_fine_bucket(0), 0);
  CHECK_EQ(store_status_fine_bucket(7000), 7);
  CHECK_EQ(store_status_fine_bucket(8000), 8);                                  /* 8 us: e = 3, exact */
  CHECK_EQ(store_status_fine_bucket(15000), 15);
  CHECK_EQ(store_status_fine_bucket(16000), 16);                                /* 16 and 17 us share a bucket */
  CHECK_EQ(store_status_fine_bucket(17000), 16);
  CHECK_EQ(store_status_fine_bucket(18000), 17);
  CHECK_EQ(store_status_fine_bucket(20001), store_status_fine_bucket(20480));   /* 20.001 ms rounds up to 21 us ... */
  CHECK_EQ(store_status_fine_upper_us(store_status_fine_bucket(20000 * 1000ull)), 20479);   /* 20 ms: the bucket 18432 .. 20479 us */
  CHECK_EQ(store_status_fine_upper_us(store_status_fine_bucket(33000 * 1000ull)), 36863);   /* 33 ms: 32768 .. 36863 us (the coarse bucket was 32768 .. 65536) */
  CHECK_EQ(store_status_fine_bucket(16777215ull * 1000), 175);                  /* 2^24 - 1 us: the last bucket of a value */
  CHECK_EQ(store_status_fine_upper_us(175), 16777215);
  CHECK_EQ(store_status_fine_bucket(16777216ull * 1000), STORE_STATUS_FINE_BUCKETS - 1);
  CHECK(store_status_fine_upper_us(STORE_STATUS_FINE_BUCKETS - 1) == UINT64_MAX);
  for (unsigned i = 1; i + 1 < STORE_STATUS_FINE_BUCKETS; i++) {               /* the buckets are adjacent, each at most an eighth of its lower bound wide (from 8 us on) */
    const uint64_t lo = store_status_fine_upper_us(i - 1) + 1, hi = store_status_fine_upper_us(i);
    if (store_status_fine_bucket(lo * 1000) != i || store_status_fine_bucket(hi * 1000) != i || (lo >= 8 && (hi - lo + 1) * 8 > lo)) { printf("  (fine bucket %u: %llu .. %llu)\n", i, (unsigned long long)lo, (unsigned long long)hi); g_failed++; break; }
  }
  CHECK_EQ(a.attach_fine[0], 0);                                                /* 0.5 and 1 us round up to 1 us (bucket 1), 1.001 us to 2, 3 us is bucket 3 */
  CHECK_EQ(a.attach_fine[1], 2);
  CHECK_EQ(a.attach_fine[2], 1);
  CHECK_EQ(a.attach_fine[3], 1);
  CHECK_EQ(a.attach_fine[STORE_STATUS_FINE_BUCKETS - 1], 0);                    /* 2^23 + 1 us is below 2^24 */
  CHECK_EQ(store_status_fine_pct(a.attach_fine, 500, a.attach_max_ns), 2);      /* the 3rd of 6: 1.001 us -> 2 us */
  CHECK_EQ(store_status_fine_pct(a.attach_fine, 1000, a.attach_max_ns), 8388609);   /* the maximum caps the bucket's bound */
  CHECK_EQ(store_status_fine_pct(a.attach_fine, 2000, a.attach_max_ns), 8388609);   /* (above 1000: 1000) */
  CHECK_EQ(store_status_fine_pct(a.cold_fine, 990, 0), 0);                      /* empty */
  {
    uint64_t f[STORE_STATUS_FINE_BUCKETS];
    memset(f, 0, sizeof(f));
    f[store_status_fine_bucket(1000000)] = 989;                                 /* 989 at 1 ms, 10 at 19 ms, 1 at 40 ms: p99 is the 990th */
    f[store_status_fine_bucket(19000000)] = 10;
    f[store_status_fine_bucket(40000000)] = 1;
    CHECK_EQ(store_status_fine_pct(f, 500, 40000000), 1023);
    CHECK_EQ(store_status_fine_pct(f, 990, 40000000), 20479);
    CHECK_EQ(store_status_fine_pct(f, 999, 40000000), 20479);
    CHECK_EQ(store_status_fine_pct(f, 1000, 40000000), 40000);                  /* (the bucket 38912 .. 40959 us, capped by the maximum) */
    CHECK_EQ(store_status_fine_pct(f, 0, 40000000), 1023);                      /* (at least the first) */
  }
  store_status_note_attach(0, STORE_ATT_ERR_CHECKSUM);
  store_status_note_attach(0, STORE_ATT_ERR_IO);
  store_status_note_attach(0, 99);                                              /* out of range: "other" */
  store_status_note_detach();
  store_status_note_detach_why(STORE_DET_LIMIT);
  store_status_note_detach_why(-5);
  store_status_note_cold(2000, STORE_COLD_ATTACH);
  store_status_note_cold(0, STORE_COLD_FETCH);
  store_status_note_cold(0, STORE_COLD_TIMEOUT);
  store_status_note_cold(0, 17);                                                /* ignored */
  store_status_snapshot(&a);
  CHECK_EQ(a.attach_failed[STORE_ATT_ERR_CHECKSUM], 1);
  CHECK_EQ(a.attach_failed[STORE_ATT_ERR_IO], 1);
  CHECK_EQ(a.attach_failed[STORE_ATT_ERR_OTHER], 1);
  CHECK_EQ(a.attaches, 6);                                                      /* failures are not attaches */
  CHECK_EQ(a.detaches, 3);
  CHECK_EQ(a.detach_by[STORE_DET_LIMIT], 1);
  CHECK_EQ(a.detach_by[STORE_DET_OTHER], 2);
  CHECK_EQ(a.cold[STORE_COLD_ATTACH], 1);
  CHECK_EQ(a.cold[STORE_COLD_FETCH], 1);
  CHECK_EQ(a.cold[STORE_COLD_TIMEOUT], 1);
  CHECK_EQ(a.cold_hist[1], 1);
  CHECK_EQ(a.cold_fine[2], 1);
}

static void *note_thread(void *arg) {
  (void)arg;
  for (int i = 0; i < 20000; i++) {
    store_status_note_attach(1500, 0);
    store_status_note_cold(1500, STORE_COLD_ATTACH);
    store_status_note_detach_why(STORE_DET_ROOM);
  }
  return NULL;
}
static void test_threads(void) {
  printf("[notes from 8 threads]\n");
  store_status_reset();
  pthread_t t[8];
  for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, note_thread, NULL);
  for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
  store_attach_stats_t a;
  store_status_snapshot(&a);
  CHECK_EQ(a.attaches, 160000);
  CHECK_EQ(a.cold[STORE_COLD_ATTACH], 160000);
  CHECK_EQ(a.detach_by[STORE_DET_ROOM], 160000);
  CHECK_EQ(a.attach_hist[1], 160000);
  CHECK_EQ(a.attach_fine[2], 160000);
  CHECK_EQ(a.cold_fine[2], 160000);
}

static bool g_recon_guard;
/* 0.7: the lookups of the first start (store.lookup.*) */
static bool lookup_fn(store_lookup_t *o) {
  memset(o, 0, sizeof(*o));
  o->ready = true;
  o->asked = 90; o->found = 40; o->none = 45; o->failed = 2; o->pending = 3; o->peak = 17; o->in_flight = 5; o->take_fail = 6; o->body_inline = 38; o->bad_body = 1; o->refused = 4;
  o->same_name = 7; o->covered = 8; o->shed = 9; o->expired = 10;
  o->drop_lk_room = 11; o->drop_lk_timeout = 12; o->drop_lk_queue = 13; o->servfail = 14; o->drop_zone_room = 15; o->drop_zone_timeout = 16; o->drop_zone_queue = 17;
  o->remembered = 18; o->reask_suppressed = 19; o->remember_releases = 20; o->drain_passes = 21; o->drain_cut = 22; o->drain_pass_max = 23; o->drain_pass_max_ns = 24001;
  o->hist[10] = 90;                                                   /* (<= 1024 us) */
  o->max_ns = 1000000;
  return true;
}

static bool recon_fn(store_recon_t *o) {
  memset(o, 0, sizeof(*o));
  snprintf(o->view, sizeof(o->view), "default");
  o->entries = 5000; o->created = 4000; o->same = 900; o->changed = 100; o->estimate = 5000;
  o->fetched = 77; o->in_flight = 3; o->passes = 2; o->wanted = 4100; o->known_now = 5;
  o->nonstore = 3;
  if (g_recon_guard) {
    o->guard_views = 1;
    snprintf(o->guard_view, sizeof(o->guard_view), "default");
    o->guard_unlisted = 1600; o->guard_total = 4800; o->guard_unix = 1700000000;
  }
  return true;
}

static void test_none(void) {
  printf("[no store bound: state=none]\n");
  store_status_reset();
  store_status_bind(NULL);
  g_mem_ok = true;
  store_status_set_memory_fn(mem_fn);
  char *buf = malloc(STORE_STATUS_OUT_MAX);
  size_t n = store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(n > 0 && n == strlen(buf));
  CHECK(parse_json(buf));
  CHECK(strcmp(kv_str("store.state"), "none") == 0);
  CHECK_EQ(kv_num("schema"), STORE_STATUS_SCHEMA);
  CHECK_EQ(kv_num("store.memory.available"), 1);
  CHECK_EQ(kv_num("store.memory.zones"), 1000);
  CHECK(kv_get("store.memory.recommended_limit_bytes") != NULL);
  CHECK(kv_get("store.memory.level") != NULL);
  CHECK(kv_get("store.zones.stored") == NULL);                       /* the store keys are absent without a store */
  CHECK_EQ(kv_num("store.attach.count"), 0);
  char *kv = malloc(STORE_STATUS_OUT_MAX);
  store_status_format(kv, STORE_STATUS_OUT_MAX, STORE_FMT_KV, NULL);
  CHECK(kv_matches_json(kv));
  CHECK(strstr(kv, "store.state=none\n") != NULL);
  char *tx = malloc(STORE_STATUS_OUT_MAX);
  store_status_format(tx, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, NULL);
  CHECK(strstr(tx, "store:\n  state = none\n") != NULL || strstr(tx, "state = none") != NULL);
  CHECK(strstr(tx, "memory:") != NULL);
  CHECK(strstr(tx, "hist") == NULL);                                  /* buckets are left out of the text */
  g_mem_ok = false;                                                   /* no figures: available = 0 and nothing else */
  store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(buf));
  CHECK_EQ(kv_num("store.memory.available"), 0);
  CHECK(kv_get("store.memory.zones") == NULL);
  g_mem_ok = true;
  size_t z = store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, "example.com");
  CHECK(strcmp(buf, "ERROR store not configured\n") == 0 && z == strlen(buf));
  /* 0.7 WP7b: the reconcile section (store.recon.*): not there without a function, the pass and the mass-delete guard with one */
  store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(buf));
  CHECK_EQ(kv_num("store.recon.available"), 0);
  CHECK(kv_get("store.recon.pass.entries") == NULL);
  store_status_set_recon_fn(recon_fn);
  g_recon_guard = false;
  store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(buf));
  CHECK_EQ(kv_num("store.recon.available"), 1);
  CHECK_EQ(kv_num("store.recon.pass.entries"), 5000);
  CHECK_EQ(kv_num("store.recon.pass.created"), 4000);
  CHECK_EQ(kv_num("store.zones.nonstore"), 3);
  CHECK_EQ(kv_num("store.recon.bodies.fetched"), 77);
  CHECK_EQ(kv_num("store.recon.guard.held_views"), 0);
  CHECK(kv_get("store.recon.guard.unlisted") == NULL);                /* (the guard keys are there only while it holds) */
  CHECK(strcmp(kv_str("store.recon.pass.view"), "default") == 0);
  g_recon_guard = true;
  store_status_format(kv, STORE_STATUS_OUT_MAX, STORE_FMT_KV, NULL);
  CHECK(strstr(kv, "store.recon.guard.held_views=1\n") != NULL && strstr(kv, "store.recon.guard.unlisted=1600\n") != NULL && strstr(kv, "store.recon.guard.total=4800\n") != NULL);
  CHECK(strstr(kv, "store.recon.guard.release=\"karictl reload -force\"\n") != NULL && strstr(kv, "store.recon.guard.view=default\n") != NULL);
  store_status_format(tx, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, NULL);
  CHECK(strstr(tx, "recon") != NULL);
  store_status_set_recon_fn(NULL);
  /* 0.7: the lookups of the first start (store.lookup.*): not there without a function, every figure and the time to the answer with one */
  store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(buf));
  CHECK_EQ(kv_num("store.lookup.available"), 0);
  CHECK(kv_get("store.lookup.asked") == NULL);
  store_status_set_lookup_fn(lookup_fn);
  store_status_format(buf, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(buf));
  CHECK_EQ(kv_num("store.lookup.available"), 1);
  CHECK_EQ(kv_num("store.lookup.ready"), 1);
  CHECK_EQ(kv_num("store.lookup.asked"), 90);
  CHECK_EQ(kv_num("store.lookup.found"), 40);
  CHECK_EQ(kv_num("store.lookup.none"), 45);
  CHECK_EQ(kv_num("store.lookup.failed"), 2);
  CHECK_EQ(kv_num("store.lookup.pending"), 3);
  CHECK_EQ(kv_num("store.lookup.pending_peak"), 17);
  CHECK_EQ(kv_num("store.lookup.in_flight"), 5);
  CHECK_EQ(kv_num("store.lookup.take_fail"), 6);
  CHECK_EQ(kv_num("store.lookup.body_inline"), 38);
  CHECK_EQ(kv_num("store.lookup.bad_body"), 1);
  CHECK_EQ(kv_num("store.lookup.refused"), 4);
  CHECK_EQ(kv_num("store.lookup.same_name"), 7);
  CHECK_EQ(kv_num("store.lookup.covered"), 8);
  CHECK_EQ(kv_num("store.lookup.shed"), 9);
  CHECK_EQ(kv_num("store.lookup.expired"), 10);
  CHECK_EQ(kv_num("store.lookup.drop.room"), 11);
  CHECK_EQ(kv_num("store.lookup.drop.timeout"), 12);
  CHECK_EQ(kv_num("store.lookup.drop.queue"), 13);
  CHECK_EQ(kv_num("store.lookup.servfail"), 14);
  CHECK_EQ(kv_num("store.lookup.remembered"), 18);
  CHECK_EQ(kv_num("store.lookup.reask_suppressed"), 19);
  CHECK_EQ(kv_num("store.lookup.remember_releases"), 20);
  CHECK_EQ(kv_num("store.lookup.drain.passes"), 21);
  CHECK_EQ(kv_num("store.lookup.drain.cut"), 22);
  CHECK_EQ(kv_num("store.lookup.drain.pass_max"), 23);
  CHECK_EQ(kv_num("store.lookup.drain.pass_max_us"), 25);
  CHECK_EQ(kv_num("store.park.drop.room"), 15);
  CHECK_EQ(kv_num("store.park.drop.timeout"), 16);
  CHECK_EQ(kv_num("store.park.drop.queue"), 17);
  CHECK_EQ(kv_num("store.lookup.rtt.p50_us"), 1024);
  CHECK_EQ(kv_num("store.lookup.rtt.p99_us"), 1024);
  CHECK_EQ(kv_num("store.lookup.rtt.max_us"), 1000);
  CHECK_EQ(kv_num("store.lookup.rtt.hist.le_1024us"), 90);
  store_status_format(kv, STORE_STATUS_OUT_MAX, STORE_FMT_KV, NULL);
  CHECK(kv_matches_json(kv) && strstr(kv, "store.lookup.body_inline=38\n") != NULL);
  store_status_format(tx, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, NULL);
  CHECK(strstr(tx, "lookup") != NULL && strstr(tx, "le_1024us") == NULL);
  store_status_set_lookup_fn(NULL);
  free(buf); free(kv); free(tx);
}

static void put_zone(store_t *s, uint16_t view, const char *name, uint32_t serial) {
  uint8_t img[200];
  memset(img, (int)serial & 0xff, sizeof(img));
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.serial = serial;
  m.stamp_gen = 7;
  m.source_id = 100 + serial;
  m.digest[0] = 0xab;
  CHECK_EQ(store_put(s, view, name, strlen(name), &m, img, sizeof(img), NULL), 0);
}

static void test_store(int mode, const char *base) {
  printf("[store, mode %s]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  char path[600];
  snprintf(path, sizeof(path), "%s/st.%d", base, mode);
  rm_rf(path);
  CHECK_EQ(mkdir(path, 0700), 0);
  int dfd = open(path, O_RDONLY | O_DIRECTORY);
  store_opts_t o;
  store_opts_default(&o);
  o.create = true;
  o.seg_size = 1u << 20;
  o.mode = mode;
  o.boot_id = 42;
  o.hash_seed[0] = 1;
  o.hash_seed[1] = 2;
  store_t *s = NULL;
  CHECK_EQ(store_open(dfd, &o, &s), 0);
  if (!s) { close(dfd); return; }
  CHECK_EQ(store_view_add(s, "default"), 0);
  CHECK_EQ(store_view_add(s, "external"), 1);
  put_zone(s, 0, "example.com", 11);
  put_zone(s, 0, "example.org", 12);
  put_zone(s, 1, "example.com", 13);
  store_meta_t km;
  memset(&km, 0, sizeof(km));
  km.serial = 5;
  CHECK_EQ(store_set_known(s, 0, "known.test", 10, &km, NULL), 0);
  CHECK_EQ(store_commit(s), 0);

  store_status_reset();
  store_status_bind(s);
  g_mem_ok = true;
  store_status_set_memory_fn(mem_fn);
  store_status_set_attached_fn(att_fn);
  store_status_note_attach(1500, 0);
  store_status_note_attach(900000, 0);
  store_status_note_attach(0, STORE_ATT_ERR_CHECKSUM);
  store_status_note_detach_why(STORE_DET_LIMIT);
  store_test_hold(s, "site_a", 2000);                    /* 0.7: the holds of 1 ms or more by function (store.lock.site.*) */
  store_test_hold(s, "site_a", 15000);
  store_test_hold(s, "site_b", 150000);
  store_test_hold(s, "site_c", 0);                       /* (under 1 ms: not counted) */
  store_status_note_cold(3000, STORE_COLD_ATTACH);
  store_status_note_cold(0, STORE_COLD_FETCH);

  char *js = malloc(STORE_STATUS_OUT_MAX), *kv = malloc(STORE_STATUS_OUT_MAX), *tx = malloc(STORE_STATUS_OUT_MAX);
  size_t nj = store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(nj > 0 && nj == strlen(js) && nj < STORE_STATUS_OUT_MAX);
  CHECK(parse_json(js));
  for (const char **k = REQUIRED; *k; k++) if (!kv_get(*k)) { printf("  (missing key %s)\n", *k); g_failed++; }
  CHECK(strcmp(kv_str("store.state"), "ok") == 0);
  CHECK(strcmp(kv_str("store.mode"), mode == STORE_MODE_MAP ? "map" : "copy") == 0);
  CHECK_EQ(kv_num("store.zones.stored"), 3);
  CHECK_EQ(kv_num("store.zones.known"), 1);              /* known = zones without an image */
  CHECK_EQ(kv_num("store.zones.attached"), 1);           /* 2 attaches - 1 detach */
  CHECK_EQ(kv_num("store.views.count"), 2);
  CHECK(strcmp(kv_str("store.view.0.name"), "default") == 0);
  CHECK(strcmp(kv_str("store.view.1.name"), "external") == 0);
  CHECK_EQ(kv_num("store.view.0.stored"), 2);
  CHECK_EQ(kv_num("store.view.1.stored"), 1);
  CHECK(kv_num("store.zones.image_bytes") >= 3 * 200);
  CHECK_EQ(kv_num("store.attach.count"), 2);
  CHECK_EQ(kv_num("store.attach.failed"), 1);
  CHECK_EQ(kv_num("store.attach.fail.checksum"), 1);
  CHECK_EQ(kv_num("store.attach.p50_us"), 2);            /* 1.5 us lies in the bucket <= 2 us */
  CHECK_EQ(kv_num("store.attach.max_us"), 900);
  CHECK_EQ(kv_num("store.attach.hist.le_2us"), 1);
  CHECK_EQ(kv_num("store.detach.limit"), 1);
  CHECK_EQ(kv_num("store.cold.attach"), 1);
  CHECK_EQ(kv_num("store.cold.fetch"), 1);
  CHECK_EQ(kv_num("store.cold.p99_us"), 3);              /* (the fine buckets: 3 us exactly; the coarse bucket said <= 4) */
  CHECK_EQ(kv_num("store.cold.p999_us"), 3);
  CHECK_EQ(kv_num("store.attach.p999_us"), 900);
  CHECK_EQ(kv_num("store.writes.puts"), 4);              /* (store_set_known counts as a put) */
  CHECK_EQ(kv_num("store.lock.site.site_a.slow"), 2);
  CHECK_EQ(kv_num("store.lock.site.site_a.over_10ms"), 1);
  CHECK_EQ(kv_num("store.lock.site.site_a.over_100ms"), 0);
  CHECK(kv_num("store.lock.site.site_a.slow_us") >= 17000 && kv_num("store.lock.site.site_a.slow_us") < 100000);
  CHECK(kv_num("store.lock.site.site_a.max_us") >= 15000 && kv_num("store.lock.site.site_a.max_us") < 100000);
  CHECK_EQ(kv_num("store.lock.site.site_b.over_100ms"), 1);
  CHECK(kv_num("store.lock.site.site_b.max_us") >= 150000);
  CHECK(kv_num("store.lock.writer_hold_max_us") >= 150000);
  CHECK(strcmp(kv_str("store.lock.writer_hold_max_site"), "site_b") == 0);
  CHECK(kv_get("store.lock.site.site_c.slow") == NULL);
  /* 0.7 WP9: the cleaner, the space, the scrub, the open: the keys are there, a store that has done nothing of it says so */
  static const char *const WP9[] = { "store.compact.runs", "store.compact.moved_records", "store.compact.moved_bytes", "store.compact.segments_freed", "store.compact.bad_records",
                                     "store.compact.pinned_skips", "store.compact.incomplete", "store.compact.last_unix", "store.compact.rate_bytes", "store.compact.candidates",
                                     "store.compact.dead_bytes", "store.compact.nx_reclaims", "store.compact.nx_reclaimed_bytes", "store.space.fs_total_bytes", "store.space.fs_free_bytes",
                                     "store.space.checked_unix", "store.space.reserve_bytes", "store.space.store_bytes", "store.space.growth_bytes_per_hour", "store.space.full_in_hours",
                                     "store.space.degraded_puts", "store.space.enospc_events", "store.space.degraded_since_unix", "store.fs.blksize", "store.fs.recordsize_warning",
                                     "store.scrub.interval_s", "store.scrub.running", "store.scrub.progress_pct", "store.scrub.passes", "store.scrub.last_start_unix",
                                     "store.scrub.last_end_unix", "store.scrub.zones_checked", "store.scrub.bytes_checked", "store.scrub.bad_images", "store.scrub.bad_cells",
                                     "store.scrub.bad_index", "store.scrub.io_errors", "store.segments.free_numbers", "store.segments.draining", "store.segments.pinned",
                                     "store.journal.max_bytes", "store.open.ix_read_us", "store.open.zt_readahead_us", "store.open.zt_readahead_done", "store.errors.total", NULL };
  for (const char *const *k = WP9; *k; k++) if (!kv_get(*k)) { printf("  (missing key %s)\n", *k); g_failed++; }
  CHECK(strcmp(kv_str("store.space.level"), "ok") == 0);
  CHECK_EQ(kv_num("store.compact.runs"), 0);
  CHECK_EQ(kv_num("store.space.degraded_puts"), 0);
  CHECK_EQ(kv_num("store.scrub.passes"), 0);
  CHECK_EQ(kv_num("store.journal.max_bytes"), 100u << 20);
  CHECK(kv_num("store.space.reserve_bytes") >= (256u << 10));
  CHECK(kv_num("store.space.fs_total_bytes") > 0);       /* (the free space was read at the open) */
  CHECK(kv_num("store.space.store_bytes") > 0);
  CHECK(kv_num("store.compact.rate_bytes") == (16u << 20));
  CHECK_EQ(kv_num("store.entries.available"), 0);                  /* (the server has not told the figures of its tables) */
  store_status_set_extra_fn(extra_fn);
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(js));
  CHECK_EQ(kv_num("store.entries.available"), 1);
  CHECK_EQ(kv_num("store.entries.pool_used"), 7);
  CHECK_EQ(kv_num("store.entries.pool_slot_bytes"), 256);
  CHECK_EQ(kv_num("store.entries.attach_table_slots"), 2048);
  CHECK_EQ(kv_num("store.entries.attach_table_grows"), 3);
  CHECK_EQ(kv_num("store.entries.attach_table_shrinks"), 1);
  CHECK_EQ(kv_num("store.fold.zones"), 11);
  CHECK_EQ(kv_num("store.fold.rows"), 5);
  CHECK_EQ(kv_num("store.fold.replaced"), 2);
  CHECK_EQ(kv_num("store.errors.memory_texts"), 4);
  CHECK_EQ(kv_num("store.errors.memory_pushed_out"), 1);
  CHECK_EQ(kv_num("store.detach.sampled"), 6);
  CHECK_EQ(kv_num("store.attach.worker.ok"), 100);
  CHECK_EQ(kv_num("store.attach.worker.mean_us"), 15);                  /* (1,500,000 ns over 100 attaches) */
  CHECK_EQ(kv_num("store.attach.worker.not_resident"), 7);
  CHECK_EQ(kv_num("store.attach.worker.over_limit"), 2);
  CHECK_EQ(kv_num("store.attach.worker.claimed"), 3);
  CHECK_EQ(kv_num("store.attach.worker.failed"), 4);
  CHECK_EQ(kv_num("store.attach.worker.declined"), 5);
  CHECK_EQ(kv_num("store.attach.worker.full"), 6);
  CHECK_EQ(kv_num("store.attach.worker.registered"), 98);
  CHECK_EQ(kv_num("store.attach.worker.dropped"), 2);
  CHECK(strcmp(kv_str("store.hot.state"), "done") == 0);
  CHECK_EQ(kv_num("store.hot.listed"), 1000);
  CHECK_EQ(kv_num("store.hot.attached"), 990);
  CHECK_EQ(kv_num("store.hot.skipped"), 10);
  CHECK_EQ(kv_num("store.hot.written_at_stop"), 1234);
  CHECK_EQ(kv_num("store.hot.threads"), 6);
  CHECK_EQ(kv_num("store.hot.attached_per_s"), 123456);
  store_status_set_extra_fn(NULL);
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(js));
  CHECK_EQ(strlen(kv_str("store.uuid")), 32);
  CHECK_EQ(kv_num("store.memory.available"), 1);
  if (mode == STORE_MODE_MAP) {
    CHECK(strcmp(kv_str("store.cache.kind"), "page") == 0);
    if (kv_num("store.cache.page.available")) {
      CHECK(kv_num("store.cache.page.sampled_pages") > 0 || kv_num("store.cache.page.sampled_pages") == 0);
      CHECK(kv_num("store.cache.page.resident_pages") <= kv_num("store.cache.page.sampled_pages"));
      CHECK(kv_num("store.cache.page.resident_pct") <= 100);
    } else {
      CHECK(strncmp(kv_str("store.cache.page.note"), "n/a", 3) == 0);
    }
  } else {
    CHECK(strcmp(kv_str("store.cache.kind"), "copy") == 0 || strcmp(kv_str("store.cache.kind"), "arc") == 0);
  }

  store_status_format(kv, STORE_STATUS_OUT_MAX, STORE_FMT_KV, NULL);
  CHECK(kv_matches_json(kv));                            /* (mono time and sample age may differ between the calls: not compared) */
  CHECK(strstr(kv, "store.zones.stored=3\n") != NULL);
  CHECK(strstr(kv, "store.state=ok\n") != NULL);
  store_status_format(tx, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, NULL);
  CHECK(strstr(tx, "zones:\n  known = 1\n  stored = 3\n") != NULL);
  CHECK(strstr(tx, "attach:\n  count = 2\n") != NULL);
  CHECK(strstr(tx, "  state = ok\n") != NULL);
  CHECK(strstr(tx, "hist") == NULL);
  CHECK(strstr(tx, "(") != NULL);                        /* a byte count has its human form */
  CHECK(strchr(tx, '\0') - tx < 8192);

  {                                                      /* the control command that changes the store: `storeop` */
    char op[512];
    store_status_op("compact", NULL, op, sizeof(op));
    CHECK(strncmp(op, "OK", 2) == 0);
    store_status_op("checkpoint", NULL, op, sizeof(op));
    CHECK(strncmp(op, "OK checkpoint", 13) == 0);
    store_status_op("scrub", "start", op, sizeof(op));
    CHECK(strncmp(op, "OK", 2) == 0);
    store_status_op("scrub", "stop", op, sizeof(op));
    CHECK(strncmp(op, "OK", 2) == 0);
    store_status_op("scrub", NULL, op, sizeof(op));
    CHECK(strncmp(op, "ERROR usage", 11) == 0);
    store_status_op("bogus", "x", op, sizeof(op));
    CHECK(strncmp(op, "ERROR usage", 11) == 0);
    store_status_op(NULL, NULL, op, sizeof(op));
    CHECK(strncmp(op, "ERROR usage", 11) == 0);
  }
  /* the same call twice reads nothing away: counters are not reset by reading */
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  CHECK(parse_json(js));
  CHECK_EQ(kv_num("store.attach.count"), 2);

  /* zone <name> [view] */
  size_t nz = store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, "example.org");
  CHECK(nz > 0 && parse_json(js));
  CHECK(strcmp(kv_str("store.zone.name"), "example.org") == 0);
  CHECK(strcmp(kv_str("store.zone.view"), "default") == 0);
  CHECK(strcmp(kv_str("store.zone.state"), "stored") == 0);
  CHECK_EQ(kv_num("store.zone.serial"), 12);
  CHECK_EQ(kv_num("store.zone.source_id"), 112);
  CHECK_EQ(kv_num("store.zone.stamp_gen"), 7);
  CHECK_EQ(kv_num("store.zone.image_bytes"), 200);
  CHECK(strncmp(kv_str("store.zone.digest"), "ab", 2) == 0 && strlen(kv_str("store.zone.digest")) == 64);
  CHECK(kv_get("store.zone.segment") != NULL && kv_num("store.zone.offset") > 0);
  CHECK(kv_get("store.zones.stored") == NULL);                       /* the zone form is only the zone */
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, "EXAMPLE.ORG.");
  CHECK(parse_json(js) && strcmp(kv_str("store.zone.name"), "example.org") == 0);          /* case and a trailing dot */
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, "example.com external");
  CHECK(parse_json(js));
  CHECK_EQ(kv_num("store.zone.serial"), 13);
  CHECK(strcmp(kv_str("store.zone.view"), "external") == 0);
  CHECK_EQ(kv_num("store.zone.attached"), kv_num("store.zone.zid") == 0 ? 1 : 0);
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, "known.test");
  CHECK(parse_json(js) && strcmp(kv_str("store.zone.state"), "known") == 0 && kv_get("store.zone.segment") == NULL);
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, "example.com");
  CHECK(strcmp(js, "ERROR zone exists in several views; give the view\n") == 0);
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, "example.com nosuchview");
  CHECK(strcmp(js, "ERROR zone not found\n") == 0);
  store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, "nosuch.test");
  CHECK(strcmp(js, "ERROR zone not found\n") == 0);
  store_status_format(tx, STORE_STATUS_OUT_MAX, STORE_FMT_TEXT, "example.org");
  CHECK(strstr(tx, "zone:\n  name = example.org\n") != NULL);

  /* the control command's words */
  store_status_control("-j", "zone example.org", js, STORE_STATUS_OUT_MAX);
  CHECK(parse_json(js) && strcmp(kv_str("store.zone.name"), "example.org") == 0);
  store_status_control("-k", NULL, kv, STORE_STATUS_OUT_MAX);
  CHECK(strstr(kv, "store.zones.stored=3\n") != NULL);
  store_status_control("zone", "example.com external", tx, STORE_STATUS_OUT_MAX);
  CHECK(strstr(tx, "serial = 13") != NULL);
  store_status_control(NULL, NULL, tx, STORE_STATUS_OUT_MAX);
  CHECK(strstr(tx, "zones:\n") != NULL);
  store_status_control("-x", NULL, tx, STORE_STATUS_OUT_MAX);
  CHECK(strncmp(tx, "ERROR usage:", 12) == 0);
  store_status_control("zone", NULL, tx, STORE_STATUS_OUT_MAX);
  CHECK(strcmp(tx, "ERROR zone name missing\n") == 0);

  /* a buffer that is too small: JSON stays a valid object, the others say so */
  char small[200];
  size_t ns = store_status_format(small, sizeof(small), STORE_FMT_JSON, NULL);
  CHECK(ns == strlen(small) && parse_json(small) && strcmp(kv_str("error"), "output too large") == 0);
  ns = store_status_format(small, sizeof(small), STORE_FMT_KV, NULL);
  CHECK(strcmp(small, "ERROR output too large\n") == 0);
  CHECK_EQ(store_status_format(small, 10, STORE_FMT_JSON, NULL), 0);

  store_status_bind(NULL);
  free(js); free(kv); free(tx);
  CHECK_EQ(store_close(s), 0);
  close(dfd);
  rm_rf(path);
}

/* 32 views: the longest reply stays below the limit that the callers' buffers have */
static void test_bounded(const char *base) {
  printf("[bounded output, 32 views]\n");
  char path[600];
  snprintf(path, sizeof(path), "%s/stb", base);
  rm_rf(path);
  CHECK_EQ(mkdir(path, 0700), 0);
  int dfd = open(path, O_RDONLY | O_DIRECTORY);
  store_opts_t o;
  store_opts_default(&o);
  o.create = true;
  o.seg_size = 1u << 20;
  o.mode = STORE_MODE_MAP;
  o.boot_id = 42;
  store_t *s = NULL;
  CHECK_EQ(store_open(dfd, &o, &s), 0);
  if (!s) { close(dfd); return; }
  for (int v = 0; v < STORE_MAX_VIEWS; v++) {
    char vn[64];
    snprintf(vn, sizeof(vn), "view-with-a-rather-long-name-number-%02d-xxxxxxxxxxxxxxxxxxxxxxx", v);
    CHECK_EQ(store_view_add(s, vn), v);
    put_zone(s, (uint16_t)v, "example.com", 1);
  }
  store_status_reset();
  for (int i = 0; i < 100; i++) { store_status_note_attach((uint64_t)i * 1000003u, 0); store_status_note_cold((uint64_t)i * 77777u, STORE_COLD_ATTACH); }
  static char sites[STORE_LOCK_SITES + 4][32];               /* (more functions than slots, with names of the longest kept length: the first STORE_LOCK_SITES are kept) */
  for (int i = 0; i < STORE_LOCK_SITES + 4; i++) {
    snprintf(sites[i], sizeof(sites[i]), "a_function_name_%02d_long_enough", i);
    store_test_hold(s, sites[i], 1000000 + (uint64_t)i);
  }
  store_status_bind(s);
  store_status_set_memory_fn(mem_fn);
  char *js = malloc(STORE_STATUS_OUT_MAX);
  size_t n = store_status_format(js, STORE_STATUS_OUT_MAX, STORE_FMT_JSON, NULL);
  printf("  JSON with 32 views: %zu bytes\n", n);
  CHECK(n > 0 && n < STORE_STATUS_OUT_MAX * 3 / 4);
  CHECK(parse_json(js));
  CHECK_EQ(kv_num("store.views.count"), 32);
  CHECK_EQ(kv_num("store.view.31.stored"), 1);
  CHECK_EQ(kv_num("store.lock.site.a_function_name_00_long_.slow"), 1);   /* (cut at 24 characters) */
  CHECK(kv_get("store.lock.site.a_function_name_27_long_.slow") == NULL);
  {                                                                       /* (every slot is taken: some by the store's own holds of the open on a slow host, the rest by the test's) */
    int nsite = 0;
    for (int i = 0; i < g_nkv; i++) nsite += strncmp(g_kv[i].key, "store.lock.site.", 16) == 0 && strstr(g_kv[i].key, ".over_100ms") != NULL;
    printf("  %d keys, %d functions with slow holds\n", g_nkv, nsite);
    CHECK_EQ(nsite, STORE_LOCK_SITES);
    CHECK(g_nkv < MAXKV);
  }
  CHECK(kv_get("error") == NULL);
  store_status_bind(NULL);
  free(js);
  CHECK_EQ(store_close(s), 0);
  close(dfd);
  rm_rf(path);
}

int main(void) {
  char base[512];
  const char *td = getenv("KARIDNS_STORE_TESTDIR");
  snprintf(base, sizeof(base), "%s/test_store_status.%d", td ? td : ".", (int)getpid());
  rm_rf(base);
  if (mkdir(base, 0700) != 0) { perror("mkdir"); return 2; }
  printf("test_store_status: base %s\n", base);
  test_hist();
  test_threads();
  test_none();
  test_store(STORE_MODE_MAP, base);
  test_store(STORE_MODE_COPY, base);
  test_bounded(base);
  rm_rf(base);
  printf("test_store_status: %d checks, %d failed\n", g_checks, g_failed);
  return g_failed ? 1 : 0;
}

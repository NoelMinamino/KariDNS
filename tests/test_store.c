/*
 * test_store.c - the zone store (dns_store.c, 0.7 WP1).
 *
 * Cases: the primitives (CRC-32C vector, SipHash against the project's SipHash-2-4, checksum64), put / find / replace / delete,
 * case-insensitive lookups, long names (nx), views, the source index, cursors, iteration, MAP and COPY mode, 100k zones (1M with
 * KARIDNS_STORE_BIG=1), group commit policies, journal rotation, generation growth while eight readers look up (the TSan case),
 * damage (image checksum, zt cell, name, both superblock copies, a torn journal tail, a foreign file), repair, quarantine,
 * a disk-full simulation (RLIMIT_FSIZE), and the kill -9 loop: a child process does mutations against one store and is killed at a random
 * moment or at a random internal crash point, the parent reopens the store and compares it to the model of the child's operations:
 * the state has to be the state after n operations for some n between the last acknowledged commit and the last operation begun.
 *
 * Environment: KARIDNS_STORE_TESTDIR (where the stores are made, default "."), KARIDNS_STORE_BIG=1 (1M zones),
 * KARIDNS_STORE_KILL_ITERS (kill -9 iterations, default 200).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../dns_store.h"
#include "../dns_epoch_rcu.h"
#include "../dns_siphash.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if defined(__SANITIZE_THREAD__) || __has_feature(thread_sanitizer)
#define UNDER_TSAN 1
#else
#define UNDER_TSAN 0
#endif
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
#define UNDER_ASAN 1
#else
#define UNDER_ASAN 0
#endif

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

static char g_base[512];

/* ------------------------------------------------------------------------------------------------------------------ */
/* helpers                                                                                                              */
/* ------------------------------------------------------------------------------------------------------------------ */

static uint64_t mix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}
static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static uint64_t now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

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

/* a fresh empty directory under the base; returns its path (static per call slot) and opens dirfd */
typedef struct { char path[600]; int fd; } tdir_t;
static int g_dir_seq;
static void tdir_new(tdir_t *d, const char *tag) {
  snprintf(d->path, sizeof(d->path), "%s/%s.%d", g_base, tag, g_dir_seq++);
  rm_rf(d->path);
  if (mkdir(d->path, 0700) != 0) { perror("mkdir"); exit(2); }
  d->fd = open(d->path, O_RDONLY | O_DIRECTORY);
  if (d->fd < 0) { perror("open dir"); exit(2); }
}
static void tdir_free(tdir_t *d) {
  if (d->fd >= 0) close(d->fd);
  rm_rf(d->path);
  d->fd = -1;
}
static void fpath(const tdir_t *d, const char *name, char *out, size_t n) { snprintf(out, n, "%s/%s", d->path, name); }

static void small_opts(store_opts_t *o) {
  store_opts_default(o);
  o->create = true;
  o->seg_size = 1u << 20;
  o->mode = STORE_MODE_MAP;
  o->boot_id = 42;
  o->hash_seed[0] = 0x0123456789abcdefull;
  o->hash_seed[1] = 0xfedcba9876543210ull;
  o->sync_policy = STORE_SYNC_BATCH;
}

/* the newest journal file of a store directory whose size is more than min_size (0: none).  A commit switches the file (0.7): the generations run into the hundreds, and the old ones are
 * deleted, so the directory is read, not a range of numbers */
static uint32_t jrn_newest_gen(const char *dir, off_t min_size) {
  DIR *dp = opendir(dir);
  if (!dp) return 0;
  uint32_t best = 0;
  struct dirent *de;
  while ((de = readdir(dp)) != NULL) {
    unsigned g;
    char tail;
    if (sscanf(de->d_name, "jrn.%u%c", &g, &tail) != 1 || g <= best) continue;
    char p[1024];
    struct stat sb;
    snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
    if (stat(p, &sb) == 0 && sb.st_size > min_size) best = g;
  }
  closedir(dp);
  return best;
}

/* ---- names and images: deterministic functions of (i, version) ---- */

static void name_of(uint32_t i, char *buf, size_t n) {
  if (i % 7 == 3) snprintf(buf, n, "z%07u.long-label-that-pushes-the-name-over-34-octets.example.test", i);
  else snprintf(buf, n, "z%07u.example.test", i);
}
static size_t img_len(uint32_t i, uint64_t ver) { return 96 + (size_t)(mix64(((uint64_t)i << 20) ^ ver) % 1100); }
static void img_fill(uint8_t *b, size_t n, uint32_t i, uint64_t ver) {
  memset(b, 0, 16);
  memcpy(b, &i, 4);
  memcpy(b + 8, &ver, 8);
  uint64_t x = mix64(((uint64_t)i << 32) ^ ver);
  for (size_t k = 16; k < n; k++) {
    if ((k & 7) == 0) x = mix64(x);
    b[k] = (uint8_t)(x >> ((k & 7) * 8));
  }
}
/* does b hold the image of zone i in some version?  returns false when not; *ver receives the version */
static bool img_ok(const uint8_t *b, size_t n, uint32_t i, uint64_t *ver) {
  if (n < 16) return false;
  uint32_t ii;
  uint64_t v;
  memcpy(&ii, b, 4);
  memcpy(&v, b + 8, 8);
  if (ii != i || img_len(i, v) != n) return false;
  uint8_t *ref = malloc(n);
  if (!ref) return false;
  img_fill(ref, n, i, v);
  bool ok = memcmp(ref, b, n) == 0;
  free(ref);
  if (ok && ver) *ver = v;
  return ok;
}

static store_meta_t meta_of(uint32_t i, uint64_t ver) {
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.source_id = (int64_t)i + 1;
  m.source = (uint16_t)(i % 4);
  m.flags = (uint16_t)((ver >> 3) & 0x2f);
  m.serial = (uint32_t)ver;
  m.settings = i % 100;
  m.stamp_gen = ver;
  m.stamp_time = ver * 3;
  for (int k = 0; k < STORE_DIGEST_LEN; k++) m.digest[k] = (uint8_t)(ver + (uint64_t)k);
  return m;
}
static int put_i(store_t *s, uint16_t view, uint32_t i, uint64_t ver, uint32_t *zid) {
  char nm[160];
  name_of(i, nm, sizeof(nm));
  size_t n = img_len(i, ver);
  uint8_t *img = malloc(n);
  img_fill(img, n, i, ver);
  store_meta_t m = meta_of(i, ver);
  int r = store_put(s, view, nm, strlen(nm), &m, img, n, zid);
  free(img);
  return r;
}
static uint32_t find_i(store_t *s, uint16_t view, uint32_t i) {
  char nm[160];
  name_of(i, nm, sizeof(nm));
  store_read_lock();
  uint32_t z = store_find(s, view, nm, strlen(nm));
  store_read_unlock();
  return z;
}
/* verify zone i is stored in the version ver (ver == UINT64_MAX: any version) */
static bool g_verbose;
static bool verify_i(store_t *s, uint16_t view, uint32_t i, uint64_t ver) {
  store_read_lock();
  char nm[160];
  name_of(i, nm, sizeof(nm));
  uint32_t z = store_find(s, view, nm, strlen(nm));
  bool ok = false;
  const char *why = "not found";
  if (z != STORE_NONE) {
    store_zone_t zi;
    store_img_t im;
    int r1 = store_zone_get(s, z, &zi), r2 = -1;
    why = "zone_get";
    if (r1 == 0 && strcmp(zi.name, nm) == 0 && zi.state == STORE_STATE_STORED && (r2 = store_image_read(s, z, &im)) == 0) {
      uint64_t v = 0;
      ok = img_ok(im.data, im.len, i, &v) && (ver == UINT64_MAX || v == ver) && zi.serial == (uint32_t)v && zi.stamp_gen == v &&
           ((uintptr_t)im.data % STORE_IMAGE_ALIGN) == 0 && im.serial == (uint32_t)v && zi.view == view;
      if (!ok) {
        why = "content / fields";
        if (g_verbose) { uint32_t ii; uint64_t vv; memcpy(&ii, im.data, 4); memcpy(&vv, (const uint8_t *)im.data + 8, 8); uint8_t *ref = malloc(im.len); img_fill(ref, im.len, i, ver == UINT64_MAX ? vv : ver); size_t d = 0; while (d < im.len && ref[d] == ((const uint8_t *)im.data)[d]) d++; printf("    ii=%u vv=%llu img_len(i,vv)=%zu len=%zu first diff at %zu\n", ii, (unsigned long long)vv, img_len(i, vv), im.len, d); free(ref); }
        if (g_verbose) printf("    img_ok %d v=%llu want=%llu serial %u/%u stamp %llu aligned %d imserial %u view %u/%u len %zu\n", (int)img_ok(im.data, im.len, i, NULL), (unsigned long long)v, (unsigned long long)ver, zi.serial, (uint32_t)v, (unsigned long long)zi.stamp_gen, (int)(((uintptr_t)im.data % STORE_IMAGE_ALIGN) == 0), im.serial, zi.view, view, im.len);
      }
      store_img_release(s, &im);
    } else if (r1 == 0) {
      why = r2 < 0 ? "image_read" : "name / state";
    }
  }
  if (!ok && g_verbose) printf("    verify_i(%u): %s (zone %s)\n", i, why, z == STORE_NONE ? "not found" : "found");
  store_read_unlock();
  return ok;
}

static void check_consistent(store_t *s, const char *what) {
  store_check_report_t rep;
  int r = store_check(s, &rep);
  if (r != 0) printf("  store_check (%s): %" PRIu64 " errors, first: %s\n", what, rep.errors, rep.first_error);
  CHECK_EQ(r, 0);
}

static int write_at(const char *path, off_t off, const void *buf, size_t n) {
  int fd = open(path, O_RDWR);
  if (fd < 0) return -1;
  ssize_t w = pwrite(fd, buf, n, off);
  close(fd);
  return w == (ssize_t)n ? 0 : -1;
}
static int read_at(const char *path, off_t off, void *buf, size_t n) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  ssize_t w = pread(fd, buf, n, off);
  close(fd);
  return w == (ssize_t)n ? 0 : -1;
}
static void flip_byte(const char *path, off_t off) {
  uint8_t b;
  if (read_at(path, off, &b, 1) != 0) { CHECK(0); return; }
  b ^= 0x5a;
  CHECK_EQ(write_at(path, off, &b, 1), 0);
}
/* a byte of a table changes in the store's memory (the tables are private memory: the file is the checkpoint's copy) */
static void mem_flip(store_t *s, int which, uint64_t off) {
  uint64_t w = store_test_peek(s, which, off & ~7ull);
  w ^= 0x5aull << (8 * (off & 7));
  store_test_poke(s, which, off & ~7ull, w);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* cases                                                                                                                */
/* ------------------------------------------------------------------------------------------------------------------ */

static void test_primitives(void) {
  printf("[primitives]\n");
  CHECK_EQ(store_test_crc32c(0, "123456789", 9), 0xE3069283u);          /* the CRC-32C check value */
  CHECK_EQ(store_test_crc32c(store_test_crc32c(0, "12345", 5), "6789", 4), 0xE3069283u);
  uint8_t zero[32] = { 0 };
  CHECK_EQ(store_test_crc32c(0, zero, 32), 0x8A9136AAu);                /* 32 zero bytes (RFC 3720 B.4) */
  /* the SipHash round function against the project's SipHash-2-4; the store itself uses 1-3 */
  uint8_t key[16], msg[80];
  for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
  for (int i = 0; i < 80; i++) msg[i] = (uint8_t)(i * 7 + 3);
  uint64_t k[2];
  dns_siphash_key_from_bytes(key, k);
  for (size_t len = 0; len <= 80; len++)
    CHECK(store_test_siphash(2, 4, key, msg, len) == dns_siphash24(msg, len, k));
  CHECK(store_test_siphash(1, 3, key, msg, 20) != store_test_siphash(2, 4, key, msg, 20));
  CHECK(store_test_siphash(1, 3, key, msg, 20) != store_test_siphash(1, 3, key, msg, 21));
  /* checksum64: every single bit flip of a 101-byte buffer changes it; length matters */
  uint8_t buf[101];
  for (int i = 0; i < 101; i++) buf[i] = (uint8_t)(i * 31 + 5);
  uint64_t base = store_test_sum64(buf, sizeof(buf));
  int same = 0;
  for (int bit = 0; bit < 101 * 8; bit++) {
    buf[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    if (store_test_sum64(buf, sizeof(buf)) == base) same++;
    buf[bit / 8] ^= (uint8_t)(1u << (bit % 8));
  }
  CHECK_EQ(same, 0);
  CHECK(store_test_sum64(buf, 100) != base);
  CHECK(store_test_sum64(buf, 0) != store_test_sum64(buf, 1));
  CHECK_EQ(store_name_labels("", 0), 0);
  CHECK_EQ(store_name_labels("com", 3), 1);
  CHECK_EQ(store_name_labels("a.b.example.test", 16), 4);
  CHECK_EQ(store_name_labels("a\\.b.test", 9), 2);
}

static void test_basic(int mode) {
  printf("[basic, mode %s]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "basic");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.mode, mode);
  CHECK(st.recovery.created);
  CHECK_EQ(st.zones_stored, 0);
  CHECK_EQ(store_view_id(s, "default"), -ENOENT);
  int v0 = store_view_add(s, "default"), v1 = store_view_add(s, "external");
  CHECK_EQ(v0, 0);
  CHECK_EQ(v1, 1);
  CHECK_EQ(store_view_add(s, "default"), 0);                            /* idempotent */
  CHECK_EQ(store_view_id(s, "external"), 1);
  CHECK(strcmp(store_view_name(s, 1), "external") == 0);
  CHECK(store_view_name(s, 5) == NULL);

  /* put / find / case / replace / delete */
  uint32_t z0 = STORE_NONE, z1 = STORE_NONE;
  CHECK_EQ(put_i(s, 0, 1, 100, &z0), 0);
  CHECK_EQ(put_i(s, 1, 1, 101, &z1), 0);                                /* the same name in another view */
  CHECK(z0 != STORE_NONE && z1 != STORE_NONE && z0 != z1);
  CHECK_EQ(find_i(s, 0, 1), z0);
  CHECK_EQ(find_i(s, 1, 1), z1);
  CHECK_EQ(find_i(s, 0, 2), STORE_NONE);
  store_read_lock();
  CHECK_EQ(store_find(s, 0, "Z0000001.EXAMPLE.Test", 21), z0);          /* case-insensitive */
  CHECK_EQ(store_find(s, 0, "z0000001.example.tes", 20), STORE_NONE);
  CHECK_EQ(store_find(s, 0, "z0000001.example.testt", 22), STORE_NONE);
  store_zone_t zi;
  CHECK_EQ(store_zone_get(s, z0, &zi), 0);
  CHECK(strcmp(zi.name, "z0000001.example.test") == 0);
  CHECK_EQ(zi.state, STORE_STATE_STORED);
  CHECK_EQ(zi.serial, 100);
  CHECK_EQ(zi.source_id, 2);
  CHECK_EQ(zi.source, 1);
  CHECK_EQ(zi.settings, 1);
  CHECK_EQ(zi.stamp_gen, 100);
  CHECK_EQ(zi.stamp_time, 300);
  CHECK_EQ(zi.digest[0], 100);
  CHECK_EQ(zi.img_len, img_len(1, 100));
  CHECK_EQ(zi.view, 0);
  CHECK(zi.loc != 0);
  CHECK_EQ(store_zone_get(s, 99999, &zi), -ENOENT);
  CHECK_EQ(store_find_source(s, 1, 2, 0), z0);
  CHECK_EQ(store_find_source(s, 1, 2, 1), z1);
  CHECK_EQ(store_find_source(s, 1, 3, 0), STORE_NONE);
  CHECK_EQ(store_find_source(s, 2, 2, 0), STORE_NONE);
  store_read_unlock();
  CHECK(verify_i(s, 0, 1, 100));
  CHECK(verify_i(s, 1, 1, 101));

  uint32_t zr;
  CHECK_EQ(put_i(s, 0, 1, 200, &zr), 0);                                /* replace: same zid */
  CHECK_EQ(zr, z0);
  CHECK(verify_i(s, 0, 1, 200));
  store_stats(s, &st);
  CHECK_EQ(st.zones_stored, 2);
  CHECK_EQ(st.replaces, 1);
  CHECK(st.seg_live_bytes < st.seg_used_bytes);                          /* the replaced record is dead */
  store_read_lock();
  store_img_t im;
  CHECK_EQ(store_image_read(s, z0, &im), 0);
  CHECK(im.prev_loc != 0);                                              /* the version before is chained */
  store_img_release(s, &im);
  store_read_unlock();

  /* long names through nx, 255 octets, the empty name, bad arguments */
  char longn[256];
  memset(longn, 'a', sizeof(longn));
  for (int k = 63; k < 255; k += 64) longn[k] = '.';
  store_meta_t m = meta_of(7, 7);
  m.source_id = 0;
  uint8_t img[200];
  img_fill(img, sizeof(img), 7, 7);
  uint32_t zl = STORE_NONE, ze = STORE_NONE;
  CHECK_EQ(store_put(s, 0, longn, 255, &m, img, sizeof(img), &zl), 0);
  CHECK_EQ(store_put(s, 0, longn, 256, &m, img, sizeof(img), NULL), -EINVAL);
  CHECK_EQ(store_put(s, 0, "", 0, &m, img, sizeof(img), &ze), 0);       /* the root */
  CHECK_EQ(store_put(s, 9, "x", 1, &m, img, sizeof(img), NULL), -EINVAL);      /* no such view */
  CHECK_EQ(store_put(s, 0, "x", 1, &m, img, 0, NULL), -EINVAL);
  store_read_lock();
  CHECK_EQ(store_find(s, 0, longn, 255), zl);
  longn[100] = 'A';                                                       /* case folding inside nx */
  CHECK_EQ(store_find(s, 0, longn, 255), zl);
  longn[254] = 'b';
  CHECK_EQ(store_find(s, 0, longn, 255), STORE_NONE);
  CHECK_EQ(store_find(s, 0, "", 0), ze);
  CHECK_EQ(store_zone_get(s, zl, &zi), 0);
  CHECK_EQ(zi.klen, 255);
  CHECK_EQ(zi.name[0], 'a');
  CHECK_EQ(zi.name[63], '.');
  store_read_unlock();
  store_stats(s, &st);
  CHECK(st.nx_used >= 255);

  /* KNOWN: no image; a stored image is released */
  uint32_t zk;
  m = meta_of(1, 300);
  CHECK_EQ(store_set_known(s, 0, "z0000001.example.test", 21, &m, &zk), 0);
  CHECK_EQ(zk, z0);
  store_read_lock();
  CHECK_EQ(store_zone_get(s, z0, &zi), 0);
  CHECK_EQ(zi.state, STORE_STATE_KNOWN);
  CHECK_EQ(zi.img_len, 0);
  CHECK_EQ(store_image_read(s, z0, &im), -ENOENT);
  store_read_unlock();
  CHECK_EQ(store_set_flags(s, z0, STORE_F_NOTIFY_DUE | STORE_F_REJECTED_NEW, 0), 0);
  store_stats(s, &st);
  CHECK_EQ(st.zones_known, 1);
  CHECK_EQ(st.zones_rejected, 1);
  CHECK_EQ(st.views[0].rejected, 1);
  CHECK_EQ(store_set_flags(s, z0, 0, STORE_F_REJECTED_NEW), 0);
  store_stats(s, &st);
  CHECK_EQ(st.zones_rejected, 0);
  CHECK_EQ(store_set_flags(s, 5000, 1, 0), -ENOENT);
  /* 0.7 WP7b: the stamp and the flags in one write (the reconcile's "the database has another version"): the zone keeps its state, serial and digest */
  CHECK_EQ(store_set_stamp(s, z0, 7, 70, STORE_F_STALE | STORE_F_REJECTED_NEW, 0), 0);
  store_read_lock();
  CHECK_EQ(store_zone_get(s, z0, &zi), 0);
  CHECK_EQ(zi.stamp_gen, 7);
  CHECK_EQ(zi.stamp_time, 70);
  CHECK_EQ(zi.state, STORE_STATE_KNOWN);
  CHECK_EQ(zi.flags & (STORE_F_STALE | STORE_F_REJECTED_NEW), STORE_F_STALE | STORE_F_REJECTED_NEW);
  store_read_unlock();
  store_stats(s, &st);
  CHECK_EQ(st.zones_rejected, 1);
  CHECK_EQ(st.views[0].rejected, 1);
  CHECK_EQ(store_set_stamp(s, z0, 8, 80, 0, STORE_F_STALE | STORE_F_REJECTED_NEW), 0);
  store_read_lock();
  CHECK_EQ(store_zone_get(s, z0, &zi), 0);
  CHECK_EQ(zi.stamp_gen, 8);
  CHECK_EQ(zi.flags & (STORE_F_STALE | STORE_F_REJECTED_NEW), 0);
  store_read_unlock();
  store_stats(s, &st);
  CHECK_EQ(st.zones_rejected, 0);
  CHECK_EQ(store_set_stamp(s, 5000, 1, 1, 0, 0), -ENOENT);
  check_consistent(s, "basic 1");

  /* the source key belongs to one zone */
  m = meta_of(50, 5);
  m.source_id = 2;                                                       /* z0 owns (source 1, id 2, view 0): source = 50 % 4 = 2, so use 1 */
  m.source = 1;
  CHECK_EQ(store_put(s, 0, "other.example.test", 18, &m, img, sizeof(img), NULL), -EEXIST);
  m.source_id = 777;
  uint32_t zo;
  CHECK_EQ(store_put(s, 0, "other.example.test", 18, &m, img, sizeof(img), &zo), 0);
  CHECK_EQ(store_find_source(s, 1, 777, 0), zo);
  m.source_id = 778;                                                     /* the same zone gets another source id */
  CHECK_EQ(store_put(s, 0, "other.example.test", 18, &m, img, sizeof(img), NULL), 0);
  CHECK_EQ(store_find_source(s, 1, 777, 0), STORE_NONE);
  CHECK_EQ(store_find_source(s, 1, 778, 0), zo);
  m.source_id = 0;
  CHECK_EQ(store_put(s, 0, "other.example.test", 18, &m, img, sizeof(img), NULL), 0);
  CHECK_EQ(store_find_source(s, 1, 778, 0), STORE_NONE);

  /* delete: by zid and by name; the zid is recycled */
  CHECK_EQ(store_delete(s, zo), 0);
  CHECK_EQ(store_delete(s, zo), -ENOENT);
  CHECK_EQ(find_i(s, 0, 1), z0);
  CHECK_EQ(store_delete_name(s, 1, "z0000001.example.test", 21), 0);
  CHECK_EQ(store_delete_name(s, 1, "z0000001.example.test", 21), -ENOENT);
  CHECK_EQ(find_i(s, 1, 1), STORE_NONE);
  uint32_t zn;
  CHECK_EQ(put_i(s, 1, 2, 5, &zn), 0);
  CHECK_EQ(zn, z1);                                                      /* LIFO reuse of the freed zid */
  check_consistent(s, "basic 2");

  /* depth counters */
  CHECK(store_view_depth_count(s, 0, 3) >= 1);
  CHECK(store_view_depth_max(s, 0) >= 4);
  CHECK_EQ(store_view_depth_count(s, 31, 3), 0);

  /* iteration by zid */
  uint32_t cur = 0, cnt = 0;
  int ir;
  while ((ir = store_iter(s, &cur, &zi)) == 1) cnt++;
  CHECK_EQ(ir, 0);
  store_stats(s, &st);
  CHECK_EQ(cnt, st.zones_known + st.zones_stored);

  /* cursors and identities */
  bool valid = true;
  uint64_t cv = 0;
  uint8_t ident[STORE_IDENT_MAX];
  size_t il = 0;
  CHECK_EQ(store_get_cursor(s, 3, &valid, &cv, ident, &il), 0);
  CHECK(!valid);
  CHECK_EQ(store_set_cursor(s, 3, 12345, "db-ident-1", 10), 0);
  CHECK_EQ(store_get_cursor(s, 3, &valid, &cv, ident, &il), 0);
  CHECK(valid && cv == 12345 && il == 10 && memcmp(ident, "db-ident-1", 10) == 0);
  CHECK_EQ(store_set_cursor(s, 99, 1, NULL, 0), -EINVAL);
  CHECK_EQ(store_set_cursor(s, 3, 1, NULL, STORE_IDENT_MAX + 1), -EINVAL);

  /* clean close and reopen: everything is there, nothing to replay */
  CHECK_EQ(store_close(s), 0);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &st);
    CHECK(st.recovery.was_clean);
    CHECK(!st.recovery.created);
    CHECK_EQ(st.recovery.records_replayed, 0);
    CHECK(!st.recovery.rebuilt);
    CHECK(verify_i(s, 0, 1, UINT64_MAX) == false);                       /* z1 is KNOWN now */
    CHECK(verify_i(s, 1, 2, 5));
    CHECK_EQ(store_view_id(s, "external"), 1);
    CHECK_EQ(store_get_cursor(s, 3, &valid, &cv, ident, &il), 0);
    CHECK(valid && cv == 12345 && il == 10);
    uint32_t zz = find_i(s, 0, 1);
    CHECK(zz != STORE_NONE);
    check_consistent(s, "basic reopen");
    store_seg_info_t si;
    CHECK_EQ(store_seg_info(s, 1, &si), 0);
    CHECK(si.used > 64 && si.live <= si.used);
    CHECK_EQ(store_seg_info(s, 77, &si), -ENOENT);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* 100k zones (1M with KARIDNS_STORE_BIG=1) */
static void test_scale(uint32_t n, bool reserve, int mode) {
  printf("[scale %u zones%s, %s]\n", n, reserve ? " (reserved)" : "", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "scale");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.seg_size = 8u << 20;
  o.sync_policy = STORE_SYNC_NONE;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  uint64_t t0 = now_ms();
  CHECK_EQ(store_view_add(s, "default"), 0);
  if (reserve) CHECK_EQ(store_reserve(s, n), 0);
  store_stats_t st;
  store_stats(s, &st);
  uint64_t g0 = st.growths;
  bool ok = true;
  for (uint32_t i = 0; i < n && ok; i++) ok = put_i(s, 0, i, 1, NULL) == 0;
  CHECK(ok);
  uint64_t t1 = now_ms();
  store_stats(s, &st);
  CHECK_EQ(st.zones_stored, n);
  if (reserve) CHECK_EQ(st.growths, g0);
  else CHECK(st.growths >= 1);
  printf("  put %u: %" PRIu64 " ms (%.1f us/zone), growths %" PRIu64 ", ix %" PRIu64 " slots, journal checkpoints %" PRIu64 ", segments %u\n", n,
         t1 - t0, n ? 1000.0 * (double)(t1 - t0) / n : 0.0, st.growths, st.ix_slots, st.checkpoints, st.seg_count);
  /* every zone is found, in lower and upper case */
  int miss = 0;
  store_read_lock();
  for (uint32_t i = 0; i < n; i++) {
    char nm[160];
    name_of(i, nm, sizeof(nm));
    size_t l = strlen(nm);
    uint32_t z = store_find(s, 0, nm, l);
    for (size_t k = 0; k < l; k++) if (nm[k] >= 'a' && nm[k] <= 'z' && (k & 1)) nm[k] = (char)(nm[k] - 32);
    if (z == STORE_NONE || store_find(s, 0, nm, l) != z) miss++;
    if (i % 4999 == 0) { store_read_unlock(); store_read_lock(); }
  }
  store_read_unlock();
  CHECK_EQ(miss, 0);
  uint64_t t2 = now_ms();
  printf("  find (2x) %u: %" PRIu64 " ms (%.0f ns per lookup)\n", n, t2 - t1, n ? 1e6 * (double)(t2 - t1) / (2.0 * n) : 0.0);
  /* misses */
  store_read_lock();
  int false_hits = 0;
  for (uint32_t i = 0; i < 20000; i++) {
    char nm[80];
    snprintf(nm, sizeof(nm), "nonexistent-%u.example.test", i);
    if (store_find(s, 0, nm, strlen(nm)) != STORE_NONE) false_hits++;
  }
  store_read_unlock();
  CHECK_EQ(false_hits, 0);
  /* replace 10 %, delete 10 %, put them back differently */
  for (uint32_t i = 0; i < n; i += 10) CHECK_EQ(put_i(s, 0, i, 2, NULL), 0);
  for (uint32_t i = 5; i < n; i += 10) {
    char nm[160];
    name_of(i, nm, sizeof(nm));
    CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);
  }
  store_stats(s, &st);
  CHECK_EQ(st.zones_stored, n - (n + 4) / 10);
  int bad = 0;
  for (uint32_t i = 0; i < n; i += 97) {
    uint32_t z = find_i(s, 0, i);
    if (i % 10 == 5) { if (z != STORE_NONE) bad++; }
    else if (!verify_i(s, 0, i, i % 10 == 0 ? 2 : 1)) bad++;
  }
  CHECK_EQ(bad, 0);
  for (uint32_t i = 5; i < n; i += 10) CHECK_EQ(put_i(s, 0, i, 3, NULL), 0);
  store_stats(s, &st);
  CHECK_EQ(st.zones_stored, n);
  /* a restart in between (clean) and a full check */
  CHECK_EQ(store_close(s), 0);
  uint64_t t3 = now_ms();
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &st);
    printf("  clean open: %" PRIu64 " us, check follows\n", st.recovery.open_us);
    CHECK_EQ(st.zones_stored, n);
    CHECK(verify_i(s, 0, n / 2, UINT64_MAX));
    uint64_t t4 = now_ms();
    check_consistent(s, "scale");
    printf("  full check %" PRIu64 " ms (close %" PRIu64 " ms)\n", now_ms() - t4, t4 - t3);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* group commit policy, journal rotation, bounded size */
static void test_commit_and_rotation(void) {
  printf("[commit policy, checkpoint, journal rotation]\n");
  tdir_t d;
  tdir_new(&d, "rot");
  store_opts_t o;
  small_opts(&o);
  o.journal_max_bytes = 200000;
  o.sync_policy = STORE_SYNC_BATCH;
  o.sync_interval_ms = 300;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_stats_t st;
  CHECK_EQ(put_i(s, 0, 1, 1, NULL), 0);
  store_stats(s, &st);
  CHECK(st.committed_lsn < st.lsn);                                      /* not yet synced: a group */
  CHECK_EQ(store_commit(s), 0);
  store_stats(s, &st);
  CHECK_EQ(st.committed_lsn, st.lsn);
  CHECK_EQ(put_i(s, 0, 2, 1, NULL), 0);
  store_stats(s, &st);
  CHECK(st.committed_lsn < st.lsn);
  usleep(450 * 1000);
  CHECK_EQ(store_tick(s), 0);                                            /* the time-driven commit */
  store_stats(s, &st);
  CHECK_EQ(st.committed_lsn, st.lsn);
  /* with the flusher the journal is cut by size in the background: while the writers go on it may grow past the bound by what they write during one checkpoint (how
   * long that is depends on the disk); when they stop it is cut back below the bound */
  uint64_t maxj = 0;
  for (uint32_t i = 0; i < 6000; i++) {
    CHECK_EQ(put_i(s, 0, i % 500, 10 + i, NULL), 0);
    store_stats(s, &st);
    if (st.journal_bytes > maxj) maxj = st.journal_bytes;
  }
  for (int w = 0; w < 3000; w++) {
    store_stats(s, &st);
    if (st.journal_bytes < 200000) break;
    usleep(10000);
  }
  printf("  with the flusher the journal grew to %" PRIu64 " bytes at most (bound %u), %" PRIu64 " bytes when the writes ended\n", maxj, 200000u, st.journal_bytes);
  CHECK(st.journal_bytes < 200000);
  CHECK(st.flusher);
  CHECK_EQ(store_close(s), 0);
  /* the journal stays bounded: many mutations, the journal is rotated by size.  Without the flusher the writer makes the checkpoint after its call: the bound holds after every call */
  atomic_store(&store_test_no_flusher, true);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  atomic_store(&store_test_no_flusher, false);
  if (!s) { tdir_free(&d); return; }
  store_stats(s, &st);
  CHECK(!st.flusher);
  uint64_t cp0 = st.checkpoints;
  maxj = 0;
  for (uint32_t i = 0; i < 6000; i++) {
    CHECK_EQ(put_i(s, 0, i % 500, 10 + i, NULL), 0);
    store_stats(s, &st);
    if (st.journal_bytes > maxj) maxj = st.journal_bytes;
  }
  store_stats(s, &st);
  CHECK(st.checkpoints > cp0 + 3);
  CHECK(maxj < 200000 + 4096);
  CHECK_EQ(st.ckpt_lsn <= st.lsn, 1);
  char p[700];
  struct stat sb;
  fpath(&d, "jrn.1", p, sizeof(p));
  CHECK(stat(p, &sb) != 0);                                              /* old journals are removed */
  snprintf(p, sizeof(p), "%s/jrn.%u", d.path, st.journal_gen);
  CHECK(stat(p, &sb) == 0 && (uint64_t)sb.st_size == st.journal_bytes);
  CHECK_EQ(store_checkpoint(s), 0);
  store_stats(s, &st);
  CHECK_EQ(st.ckpt_lsn, st.lsn);
  CHECK(st.last_checkpoint_unix > 0);
  check_consistent(s, "rotation");
  CHECK_EQ(store_close(s), 0);
  /* STORE_SYNC_EVERY: every call is durable when it returns */
  o.sync_policy = STORE_SYNC_EVERY;
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK_EQ(put_i(s, 0, 7, 99, NULL), 0);
    store_stats(s, &st);
    CHECK_EQ(st.committed_lsn, st.lsn);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* growth by churn: tombstones are cleaned by a rebuild, the index stays small */
static void test_churn(void) {
  printf("[churn]\n");
  tdir_t d;
  tdir_new(&d, "churn");
  store_opts_t o;
  small_opts(&o);
  o.sync_policy = STORE_SYNC_NONE;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 300; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  for (uint32_t round = 0; round < 40; round++) {
    for (uint32_t i = 0; i < 300; i++) {
      char nm[160];
      uint32_t k = 100000 + round * 300 + i;
      name_of(k, nm, sizeof(nm));
      store_meta_t m = meta_of(k, 1);
      uint8_t img[120];
      img_fill(img, sizeof(img), k, 1);
      CHECK_EQ(store_put(s, 0, nm, strlen(nm), &m, img, sizeof(img), NULL), 0);
      CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);
    }
  }
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.zones_stored, 300);
  CHECK(st.ix_slots <= 4096 * 2);                                        /* tombstones did not make it grow without bound */
  CHECK(st.ix_used * 2 <= st.ix_slots);
  CHECK(st.growths >= 1);
  CHECK(st.zt_records <= 1000);                                          /* zids are recycled */
  check_consistent(s, "churn");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* ---- concurrent readers while the writer grows the index ---- */

#define NSTABLE 1500
#define NVOL 4000
typedef struct {
  store_t *s;
  _Atomic int stop;
  _Atomic long errors;
  _Atomic long errk[16];
  _Atomic uint64_t lookups;
  _Atomic uint64_t latest[NSTABLE];       /* newest version the writer has completed */
} conc_t;
typedef struct { conc_t *c; int id; } rarg_t;
#define ERRK(k) do { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[(k)], 1); } while (0)

/* KARIDNS_STORE_LONG=1: the soak variants of the cases below (the default run is the one CI runs, a minute; the long one is for a local soak) */
static bool store_long(void) {
  const char *v = getenv("KARIDNS_STORE_LONG");
  return v && v[0] == '1';
}

static void *reader_main(void *arg) {
  rarg_t *a = arg;
  conc_t *c = a->c;
  store_t *s = c->s;
  const bool soak = store_long();
  uint64_t rounds = 0;
  uint64_t seen[NSTABLE];
  memset(seen, 0, sizeof(seen));
  uint64_t rng = (uint64_t)a->id * 7919 + 1;
  uint8_t *copy = malloc(2048);
  while (!atomic_load(&c->stop)) {
    /* the default run lets the readers give way now and then: eight threads that never stop make every step of the one writer (a grace period, a growth of the index) wait for a CPU, and the
     * case takes minutes on a host with few of them; what is looked at (a lookup against a growth, a replace, a delete) is the same */
    if (!soak && (++rounds & 63) == 0) sched_yield();
    rng = mix64(rng);
    uint32_t i;
    bool stable = (rng & 3) != 0;
    char nm[160];
    if (stable) i = (uint32_t)((rng >> 8) % NSTABLE);
    else i = NSTABLE + (uint32_t)((rng >> 8) % NVOL);
    name_of(i, nm, sizeof(nm));
    size_t l = strlen(nm);
    if ((rng >> 40) & 1) for (size_t k = 0; k < l; k++) if (nm[k] >= 'a' && nm[k] <= 'z') nm[k] = (char)(nm[k] - 32);
    store_read_lock();
    uint32_t z = store_find(s, 0, nm, l);
    atomic_fetch_add_explicit(&c->lookups, 1, memory_order_relaxed);
    if (stable) {
      if (z == STORE_NONE) { ERRK(0); store_read_unlock(); continue; }
      store_zone_t zi;
      int r = store_zone_get(s, z, &zi);
      char lc[160];
      name_of(i, lc, sizeof(lc));
      if (r != 0 || strcmp(zi.name, lc) != 0 || zi.state != STORE_STATE_STORED) ERRK(1);
      store_img_t im;
      r = store_image_read(s, z, &im);
      if (r != 0) ERRK(2);
      else {
        uint64_t v;
        if (!img_ok(im.data, im.len, i, &v)) ERRK(3);
        else {
          if (v < seen[i]) ERRK(4);               /* versions never go back */
          seen[i] = v;
        }
        memcpy(copy, im.data, im.len < 2048 ? im.len : 2048);
        store_img_release(s, &im);
      }
    } else if (z != STORE_NONE) {
      store_zone_t zi;
      int r = store_zone_get(s, z, &zi);
      if (r == 0) {
        store_img_t im;
        if (store_image_read(s, z, &im) == 0) {
          uint64_t v;
          char lc[160];
          name_of(i, lc, sizeof(lc));
          /* the zid may have been recycled for another name between the two calls: then the name differs */
          if (strcmp(zi.name, lc) == 0 && !img_ok(im.data, im.len, i, &v)) {
            /* the same zid can also have been reused for another zone between zone_get and image_read */
            uint32_t other;
            memcpy(&other, im.data, 4);
            if (other == i) ERRK(5);
          }
          store_img_release(s, &im);
        }
      } else if (r != -ENOENT) ERRK(6);
    }
    store_read_unlock();
    /* a miss must stay a miss */
    char nm2[80];
    snprintf(nm2, sizeof(nm2), "never-%d-%u.example.test", a->id, (unsigned)(rng & 0xff));
    store_read_lock();
    if (store_find(s, 0, nm2, strlen(nm2)) != STORE_NONE) ERRK(7);
    store_read_unlock();
  }
  free(copy);
  return NULL;
}

static void test_concurrent(int mode) {
  printf("[8 readers + 1 writer, generation growth, %s]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "conc");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.sync_policy = STORE_SYNC_NONE;
  o.journal_max_bytes = 4u << 20;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  static conc_t c;
  memset(&c, 0, sizeof(c));
  c.s = s;
  for (uint32_t i = 0; i < NSTABLE; i++) { CHECK_EQ(put_i(s, 0, i, 1, NULL), 0); atomic_store(&c.latest[i], 1); }
  store_stats_t st0, st1;
  store_stats(s, &st0);
  pthread_t th[8];
  rarg_t ra[8];
  for (int t = 0; t < 8; t++) { ra[t].c = &c; ra[t].id = t; pthread_create(&th[t], NULL, reader_main, &ra[t]); }
  uint32_t wops = UNDER_TSAN ? 12000 : 40000;
  if (UNDER_ASAN) wops = 25000;
  uint64_t rng = 99;
  bool vol[NVOL];
  memset(vol, 0, sizeof(vol));
  for (uint32_t k = 0; k < wops; k++) {
    rng = mix64(rng);
    uint32_t sel = (uint32_t)(rng % 100);
    if (sel < 30) {
      uint32_t i = (uint32_t)((rng >> 8) % NSTABLE);
      uint64_t v = atomic_load(&c.latest[i]) + 1;
      CHECK_EQ(put_i(s, 0, i, v, NULL), 0);
      atomic_store(&c.latest[i], v);
    } else if (sel < 75) {
      uint32_t j = (uint32_t)((rng >> 8) % NVOL);
      if (!vol[j]) { CHECK_EQ(put_i(s, 0, NSTABLE + j, k + 1, NULL), 0); vol[j] = true; }
      else if ((rng >> 50) & 1) { CHECK_EQ(put_i(s, 0, NSTABLE + j, k + 1, NULL), 0); }
      else {
        char nm[160];
        name_of(NSTABLE + j, nm, sizeof(nm));
        CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);
        vol[j] = false;
      }
    } else if (sel < 85) {
      uint32_t j = (uint32_t)((rng >> 8) % NVOL);
      if (vol[j]) {
        char nm[160];
        name_of(NSTABLE + j, nm, sizeof(nm));
        store_meta_t m = meta_of(NSTABLE + j, k);
        CHECK_EQ(store_set_known(s, 0, nm, strlen(nm), &m, NULL), 0);
        vol[j] = true;
      }
    }
    if (k % 3000 == 2999) { CHECK_EQ(store_checkpoint(s), 0); }
    if (k % 500 == 499) { CHECK_EQ(store_commit(s), 0); }
  }
  atomic_store(&c.stop, 1);
  for (int t = 0; t < 8; t++) pthread_join(th[t], NULL);
  store_stats(s, &st1);
  printf("  %" PRIu64 " lookups by 8 readers, %" PRIu64 " growths during the run, ix slots %" PRIu64 ", errors %ld\n", atomic_load(&c.lookups),
         st1.growths - st0.growths, st1.ix_slots, atomic_load(&c.errors));
  if (atomic_load(&c.errors)) { for (int k = 0; k < 16; k++) if (atomic_load(&c.errk[k])) printf("    error kind %d: %ld\n", k, atomic_load(&c.errk[k])); }
  CHECK_EQ(atomic_load(&c.errors), 0);
  CHECK(st1.growths > st0.growths);
  CHECK(atomic_load(&c.lookups) > 1000);
  check_consistent(s, "concurrent");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* ---- damage ---- */

#define ZT_HDR 16384
static void test_damage_cells(void) {
  printf("[damage: image checksum, zt cell, name, sx]\n");
  tdir_t d;
  tdir_new(&d, "dmg");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  uint32_t za = STORE_NONE, zb = STORE_NONE, zc = STORE_NONE, zdd = STORE_NONE;
  for (uint32_t i = 0; i < 50; i++) CHECK_EQ(put_i(s, 0, i, 1, i == 10 ? &za : i == 11 ? &zb : i == 12 ? &zc : i == 13 ? &zdd : NULL), 0);
  CHECK_EQ(store_commit(s), 0);
  store_zone_t zi;
  store_img_t im;
  CHECK_EQ(store_zone_get(s, za, &zi), 0);
  /* an image byte flips in the segment file: the checksum catches it, the zt cell is fine */
  uint32_t sn = (uint32_t)(zi.loc >> 36);
  uint64_t off = (zi.loc & ((1ull << 36) - 1)) * 64;
  char p[700], nm[32];
  snprintf(nm, sizeof(nm), "seg.%u", sn);
  fpath(&d, nm, p, sizeof(p));
  flip_byte(p, (off_t)(off + 64 + 32 + 10));
  store_read_lock();
  CHECK_EQ(store_image_read(s, za, &im), -EBADMSG);
  CHECK(store_image_read(s, zb, &im) == 0);
  store_img_release(s, &im);
  store_read_unlock();
  CHECK(!verify_i(s, 0, 10, 1));
  CHECK(verify_i(s, 0, 11, 1));
  /* the caller sets the zone back to KNOWN: that is the way out */
  store_meta_t m = meta_of(10, 1);
  char n10[160];
  name_of(10, n10, sizeof(n10));
  CHECK_EQ(store_set_known(s, 0, n10, strlen(n10), &m, NULL), 0);
  CHECK_EQ(put_i(s, 0, 10, 2, NULL), 0);
  CHECK(verify_i(s, 0, 10, 2));
  /* the header of the record is damaged: magic */
  CHECK_EQ(store_zone_get(s, zb, &zi), 0);
  sn = (uint32_t)(zi.loc >> 36);
  off = (zi.loc & ((1ull << 36) - 1)) * 64;
  snprintf(nm, sizeof(nm), "seg.%u", sn);
  fpath(&d, nm, p, sizeof(p));
  flip_byte(p, (off_t)off);
  store_read_lock();
  CHECK_EQ(store_image_read(s, zb, &im), -EBADMSG);
  store_read_unlock();
  CHECK_EQ(put_i(s, 0, 11, 2, NULL), 0);
  /* a damaged zt cell (a byte of img_len): the zone is invisible to zone_get / iteration / image_read, no crash */
  fpath(&d, "zt.1", p, sizeof(p));
  mem_flip(s, 0, (uint64_t)zc * 64 + 9);
  store_read_lock();
  CHECK_EQ(store_zone_get(s, zc, &zi), -EBADMSG);
  CHECK_EQ(store_image_read(s, zc, &im), -EBADMSG);
  CHECK(store_find(s, 0, "z0000012.example.test", 21) == zc);          /* the name still matches ... */
  CHECK_EQ(store_zone_get(s, zc, &zi), -EBADMSG);                       /* ... but the cell cannot be used */
  uint32_t cur = 0, seen_bad = 0, seen_ok = 0;
  int r;
  while ((r = store_iter(s, &cur, &zi)) != 0) { if (r < 0) { seen_bad++; CHECK_EQ(zi.zid, zc); } else seen_ok++; }
  store_read_unlock();
  CHECK_EQ(seen_bad, 1);
  CHECK_EQ(seen_ok, 49);
  CHECK_EQ(put_i(s, 0, 12, 5, NULL), -EBADMSG);                         /* cannot be replaced either */
  CHECK_EQ(store_delete(s, zc), -EBADMSG);
  /* a damaged name byte: invisible by name */
  mem_flip(s, 0, (uint64_t)zdd * 64 + 30 + 3);
  store_read_lock();
  CHECK_EQ(store_find(s, 0, "z0000013.example.test", 21), STORE_NONE);
  CHECK_EQ(store_zone_get(s, zdd, &zi), -EBADMSG);
  store_read_unlock();
  store_check_report_t rep;
  CHECK(store_check(s, &rep) != 0);                                     /* the full check sees the damage */
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

static void test_repair(void) {
  printf("[repair and rebuild]\n");
  tdir_t d;
  tdir_new(&d, "repair");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  uint32_t zc = STORE_NONE, zd = STORE_NONE;
  for (uint32_t i = 0; i < 300; i++) CHECK_EQ(put_i(s, 0, i, 1, i == 12 ? &zc : i == 13 ? &zd : NULL), 0);
  for (uint32_t i = 100; i < 120; i++) { char nm[160]; name_of(i, nm, sizeof(nm)); CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0); }
  char p[700];
  fpath(&d, "zt.1", p, sizeof(p));
  mem_flip(s, 0, (uint64_t)zc * 64 + 9);                 /* damaged cell */
  mem_flip(s, 0, (uint64_t)zd * 64 + 31);                /* damaged name -> CRC */
  store_check_report_t rep;
  CHECK(store_check(s, &rep) != 0);
  CHECK(rep.errors >= 2);
  CHECK_EQ(store_repair(s), 0);
  check_consistent(s, "after repair");
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.zones_stored, 300 - 20 - 2);
  CHECK(st.state & STORE_ST_REPAIRED);
  CHECK_EQ(find_i(s, 0, 12), STORE_NONE);
  CHECK_EQ(find_i(s, 0, 13), STORE_NONE);
  CHECK(verify_i(s, 0, 14, 1));
  CHECK_EQ(put_i(s, 0, 12, 2, NULL), 0);                                 /* fetched again */
  CHECK(verify_i(s, 0, 12, 2));
  CHECK_EQ(store_close(s), 0);
  /* force_rebuild at open */
  o.create = false;
  o.force_rebuild = true;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &st);
    CHECK(st.recovery.rebuilt);
    CHECK_EQ(st.zones_stored, 300 - 20 - 1);
    check_consistent(s, "force_rebuild");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

static int read_u64_at(const char *path, off_t off, uint64_t *v) { return read_at(path, off, v, 8); }

static void test_superblock_damage(void) {
  printf("[damage: superblock copies, torn journal, foreign file, quarantine]\n");
  tdir_t d;
  tdir_new(&d, "sb");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_view_add(s, "other");
  for (uint32_t i = 0; i < 400; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  CHECK_EQ(store_set_cursor(s, 1, 77, "x", 1), 0);
  CHECK_EQ(store_close(s), 0);

  char pa[700], pb[700];
  fpath(&d, "super.a", pa, sizeof(pa));
  fpath(&d, "super.b", pb, sizeof(pb));
  uint64_t sa = 0, sbq = 0;
  CHECK_EQ(read_u64_at(pa, 16, &sa), 0);
  CHECK_EQ(read_u64_at(pb, 16, &sbq), 0);
  const char *newer = sa > sbq ? pa : pb, *older = sa > sbq ? pb : pa;
  /* 1. the NEWER copy is damaged: the older one plus the longer journal chain give the same store */
  flip_byte(newer, 100);
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(st.recovery.used_older_super);
    CHECK(st.recovery.records_replayed > 400);
    CHECK_EQ(st.zones_stored, 400);
    CHECK(verify_i(s, 0, 399, 1));
    bool valid;
    uint64_t cv;
    CHECK_EQ(store_get_cursor(s, 1, &valid, &cv, NULL, NULL), 0);
    CHECK(valid && cv == 77);
    CHECK_EQ(store_view_id(s, "other"), 1);
    check_consistent(s, "older superblock");
    for (uint32_t i = 400; i < 450; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    CHECK_EQ(store_close(s), 0);
  }
  /* 2. the OLDER copy is damaged: no loss */
  uint64_t s1 = 0, s2 = 0;
  CHECK_EQ(read_u64_at(pa, 16, &s1), 0);
  CHECK_EQ(read_u64_at(pb, 16, &s2), 0);
  older = s1 < s2 ? pa : pb;
  flip_byte(older, 5000);
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.zones_stored, 450);
    check_consistent(s, "older damaged");
    CHECK_EQ(store_close(s), 0);
  }
  /* 3. a torn journal tail after an unclean stop (a child that does not close the store) */
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_t *c = NULL;
    if (store_open(d.fd, &o, &c) != 0) _exit(3);
    /* (no growth and no checkpoint after the puts: the index is made big enough and the checkpoint the growth asks for is made first, so the last record is the last one of the newest journal) */
    if (store_reserve(c, 2000) != 0 || store_checkpoint(c) != 0) _exit(5);
    for (uint32_t i = 450; i < 700; i++) if (put_i(c, 0, i, 1, NULL) != 0) _exit(4);
    _exit(0);                                                            /* no close, no commit */
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  /* find the newest journal and cut it in the middle of a record */
  char jp[700];
  uint32_t best = 0;
  best = jrn_newest_gen(d.path, 64);                                    /* (not the next journal, made ahead and empty, nor one with a header only) */
  snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, best);
  struct stat jst;
  CHECK_EQ(stat(jp, &jst), 0);
  CHECK(jst.st_size > 1000);
  CHECK_EQ(truncate(jp, jst.st_size - 37), 0);                           /* the last record is torn: its cells landed, its journal record did not */
  o.boot_id = 43;                                                        /* a lost journal tail is what a power loss looks like: another boot */
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(!st.recovery.was_clean);
    CHECK(st.recovery.journal_torn);
    CHECK(st.recovery.rebuilt);                                          /* the cells are ahead of the journal: derived tables are rebuilt */
    CHECK_EQ(st.zones_stored, 699);                                      /* the zone of the lost record is not in the rebuilt tables: its cell lies beyond the
                                                                          * high-water mark that the journal gave */
    if (g_verbose) for (uint32_t i = 0; i < 700; i++) if (find_i(s, 0, i) == STORE_NONE) printf("    missing zone %u\n", i);
    CHECK(verify_i(s, 0, 698, 1));
    CHECK_EQ(find_i(s, 0, 699), STORE_NONE);
    check_consistent(s, "torn journal");
    CHECK_EQ(store_close(s), 0);
  }
  /* 4. a foreign / truncated table file: the store cannot be opened (both copies name it), then the quarantine path */
  fpath(&d, "zt.1", jp, sizeof(jp));
  CHECK_EQ(truncate(jp, 100), 0);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), -EBADMSG);
  CHECK(s == NULL);
  int moved = store_quarantine(d.fd);
  CHECK(moved >= 6);
  o.create = true;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(st.recovery.created);
    CHECK_EQ(st.zones_stored, 0);
    CHECK_EQ(store_close(s), 0);
  }
  /* 5. both superblock copies damaged */
  fpath(&d, "super.a", pa, sizeof(pa));
  fpath(&d, "super.b", pb, sizeof(pb));
  flip_byte(pa, 200);
  flip_byte(pb, 200);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), -EBADMSG);
  /* 6. nothing there, create not set */
  tdir_t e;
  tdir_new(&e, "none");
  CHECK_EQ(store_open(e.fd, &o, &s), -ENOENT);
  tdir_free(&e);
  tdir_free(&d);
}

/* ---- the kill -9 loop ---- */

#define KNZ 1500
typedef struct { uint8_t exists, known; uint16_t flags; uint64_t ver; } mz_t;
typedef struct { mz_t z[KNZ]; bool cursor_valid; uint64_t cursor; } model_t;

enum { OP_PUT, OP_DEL, OP_KNOWN, OP_FLAGS, OP_CURSOR, OP_CKPT, OP_NONE, OP_COMPACT, OP_SCRUB, OP_KNOWN_N };
static int g_kill_mode;                  /* 1: the cleaner, the nx pass and the scrub are operations of the loop too (they change no zone); 2: groups of zones made known in one call (store_set_known_n(): all or none of a group is there) */
static int op_kind(uint64_t K, uint32_t *i) {
  uint64_t r = mix64(K * 0x9e3779b97f4a7c15ull + 12345);
  *i = (uint32_t)((r >> 16) % KNZ);
  uint32_t p = (uint32_t)(r % 100);
  if (g_kill_mode == 2) {
    if (p < 25) return OP_PUT;
    if (p < 35) return OP_DEL;
    if (p < 75) return OP_KNOWN_N;
    if (p < 82) return OP_KNOWN;
    if (p < 90) return OP_FLAGS;
    if (p < 95) return OP_CURSOR;
    if (p < 97) return OP_CKPT;
    return OP_NONE;
  }
  if (g_kill_mode == 1) {
    if (p < 40) return OP_PUT;
    if (p < 52) return OP_DEL;
    if (p < 58) return OP_KNOWN;
    if (p < 64) return OP_FLAGS;
    if (p < 67) return OP_CURSOR;
    if (p < 69) return OP_CKPT;
    if (p < 95) return OP_COMPACT;
    if (p < 98) return OP_SCRUB;
    return OP_NONE;
  }
  if (p < 58) return OP_PUT;
  if (p < 72) return OP_DEL;
  if (p < 82) return OP_KNOWN;
  if (p < 91) return OP_FLAGS;
  if (p < 96) return OP_CURSOR;
  if (p < 98) return OP_CKPT;
  return OP_NONE;
}
static uint16_t op_flags(uint64_t K) { return (uint16_t)((mix64(K) >> 7) & 0x3f); }
/* the zones of a group of OP_KNOWN_N: 2 to 10 of the same view, one of them twice now and then */
static unsigned kn_group(uint64_t K, uint32_t i, uint32_t *idx) {
  unsigned g = 2 + (unsigned)((mix64(K ^ 0x55) >> 9) % 9);
  for (unsigned j = 0; j < g; j++) idx[j] = (i + 2 * 5 * j) % KNZ;
  if (K % 3 == 0) idx[g - 1] = idx[0];
  return g;
}

static int store_do_op(store_t *s, uint64_t K) {
  uint32_t i;
  int k = op_kind(K, &i);
  uint16_t view = (uint16_t)(i & 1);
  char nm[160];
  name_of(i, nm, sizeof(nm));
  store_meta_t m = meta_of(i, K);
  m.flags = op_flags(K);
  switch (k) {
  case OP_PUT: {
    size_t n = img_len(i, K);
    uint8_t *img = malloc(n);
    img_fill(img, n, i, K);
    int r = store_put(s, view, nm, strlen(nm), &m, img, n, NULL);
    free(img);
    return r;
  }
  case OP_DEL: { int r = store_delete_name(s, view, nm, strlen(nm)); return r == -ENOENT ? 0 : r; }
  case OP_KNOWN: return store_set_known(s, view, nm, strlen(nm), &m, NULL);
  case OP_KNOWN_N: {
    uint32_t idx[16];
    unsigned g = kn_group(K, i, idx);
    char names[16][160];
    store_meta_t metas[16];
    store_known_t in[16];
    int res[16];
    for (unsigned j = 0; j < g; j++) {
      name_of(idx[j], names[j], sizeof(names[j]));
      metas[j] = meta_of(idx[j], K);
      metas[j].flags = op_flags(K);
      in[j].name = names[j];
      in[j].len = strlen(names[j]);
      in[j].meta = &metas[j];
    }
    int r = store_set_known_n(s, view, in, g, res, NULL);
    for (unsigned j = 0; j < g && r == 0; j++) if (res[j] != 0) r = res[j];
    return r;
  }
  case OP_FLAGS: {
    uint32_t z = find_i(s, view, i);
    if (z == STORE_NONE) return 0;
    uint16_t f = op_flags(K);
    return store_set_flags(s, z, f, (uint16_t)(0x3f & ~f));
  }
  case OP_CURSOR: return store_set_cursor(s, 3, K, &K, 8);
  case OP_CKPT: return store_checkpoint(s);
  case OP_COMPACT: return store_compact(s, (uint64_t)(32u + (K & 7) * 16) << 10, (K & 1) != 0, NULL);
  case OP_SCRUB: return store_scrub_run(s, NULL);
  default: return 0;
  }
}
/* parts: how many entries of a group (OP_KNOWN_N) are applied (UINT32_MAX: all; the other operations are whole) */
static void model_do_op_part(model_t *m, uint64_t K, unsigned parts) {
  uint32_t i;
  int k = op_kind(K, &i);
  mz_t *z = &m->z[i];
  switch (k) {
  case OP_PUT: z->exists = 1; z->known = 0; z->ver = K; z->flags = op_flags(K); break;
  case OP_DEL: memset(z, 0, sizeof(*z)); break;
  case OP_KNOWN: z->exists = 1; z->known = 1; z->ver = K; z->flags = op_flags(K); break;
  case OP_KNOWN_N: {
    uint32_t idx[16];
    unsigned g = kn_group(K, i, idx);
    for (unsigned j = 0; j < g && j < parts; j++) { mz_t *y = &m->z[idx[j]]; y->exists = 1; y->known = 1; y->ver = K; y->flags = op_flags(K); }
    break;
  }
  case OP_FLAGS: if (z->exists) z->flags = op_flags(K); break;
  case OP_CURSOR: m->cursor_valid = true; m->cursor = K; break;
  default: break;
  }
}
static void model_do_op(model_t *m, uint64_t K) { model_do_op_part(m, K, UINT32_MAX); }
/* the entries of operation K (a group: its size; otherwise 1) */
static unsigned model_op_parts(uint64_t K) {
  uint32_t i, idx[16];
  return op_kind(K, &i) == OP_KNOWN_N ? kn_group(K, i, idx) : 1;
}
/* compare the store with the model; verbose = print the first difference */
static bool model_matches(store_t *s, const model_t *m, bool verbose) {
  uint64_t cnt = 0;
  store_read_lock();
  for (uint32_t i = 0; i < KNZ; i++) {
    const mz_t *z = &m->z[i];
    uint16_t view = (uint16_t)(i & 1);
    char nm[160];
    name_of(i, nm, sizeof(nm));
    uint32_t zid = store_find(s, view, nm, strlen(nm));
    if (!z->exists) {
      if (zid != STORE_NONE) { if (verbose) printf("    zone %u exists but should not\n", i); store_read_unlock(); return false; }
      continue;
    }
    cnt++;
    store_zone_t zi;
    if (zid == STORE_NONE || store_zone_get(s, zid, &zi) != 0) { if (verbose) printf("    zone %u missing\n", i); store_read_unlock(); return false; }
    bool ok = zi.state == (z->known ? STORE_STATE_KNOWN : STORE_STATE_STORED) && zi.serial == (uint32_t)z->ver && zi.stamp_gen == z->ver &&
              zi.flags == z->flags && zi.source_id == (int64_t)i + 1 && store_find_source(s, (uint16_t)(i % 4), (int64_t)i + 1, view) == zid;
    if (ok && !z->known) {
      store_img_t im;
      uint64_t v;
      ok = store_image_read(s, zid, &im) == 0;
      if (ok) { ok = img_ok(im.data, im.len, i, &v) && v == z->ver; store_img_release(s, &im); }
    }
    if (!ok) { if (verbose) printf("    zone %u differs (state %d ver %" PRIu64 " vs %" PRIu64 " flags %x vs %x)\n", i, zi.state, zi.stamp_gen, z->ver, zi.flags, z->flags); store_read_unlock(); return false; }
  }
  store_read_unlock();
  store_stats_t st;
  store_stats(s, &st);
  if (st.zones_known + st.zones_stored != cnt) { if (verbose) printf("    count %" PRIu64 " vs %" PRIu64 "\n", st.zones_known + st.zones_stored, cnt); return false; }
  bool valid;
  uint64_t cv;
  uint8_t id[STORE_IDENT_MAX];
  size_t il;
  store_get_cursor(s, 3, &valid, &cv, id, &il);
  if (valid != m->cursor_valid || (valid && (cv != m->cursor || il != 8 || memcmp(id, &cv, 8) != 0))) { if (verbose) printf("    cursor\n"); return false; }
  return true;
}
/* adopt what the store holds as the model (after a repair path that lost the prefix property) */
static bool model_from_store(store_t *s, model_t *m) {
  memset(m, 0, sizeof(*m));
  store_read_lock();
  for (uint32_t i = 0; i < KNZ; i++) {
    uint16_t view = (uint16_t)(i & 1);
    char nm[160];
    name_of(i, nm, sizeof(nm));
    uint32_t zid = store_find(s, view, nm, strlen(nm));
    if (zid == STORE_NONE) continue;
    store_zone_t zi;
    if (store_zone_get(s, zid, &zi) != 0) continue;
    m->z[i].exists = 1;
    m->z[i].known = zi.state == STORE_STATE_KNOWN;
    m->z[i].ver = zi.stamp_gen;
    m->z[i].flags = zi.flags;
  }
  store_read_unlock();
  bool valid;
  uint64_t cv;
  store_get_cursor(s, 3, &valid, &cv, NULL, NULL);
  m->cursor_valid = valid;
  m->cursor = cv;
  return true;
}

typedef struct { _Atomic uint64_t begun, done, acked, dcur; } shm_t;      /* dcur: mode 6, the cursor of source 7 that a deferring thread's commit made durable */

/* modes 3 and 4 of the kill loop (0.7 fix A): a step of a checkpoint that runs outside the writer mutex (3: a thread checkpoints all the time, the flush of the tables is made slow) or of a
 * growth of the index built outside it (4: the build waits before it takes the mutex, so that the writers' changes pile up in its log) is reached while the operations go on, and the child is
 * killed at the n-th time one step is reached (g_hk_step: 1..5 a checkpoint step (5: between two runs of its write of the tables), 11..13 a growth step (13: after a round of its catch-up with no lock); 0: not by a hook) */
static _Atomic int g_hk_step, g_hk_n;
static void hk_kill(int step) {
  if (atomic_load(&g_hk_step) == step && atomic_fetch_sub(&g_hk_n, 1) == 1) kill(getpid(), SIGKILL);
}
static void hk_ckpt(int step) {
  if (step == 2 || step == 5) usleep(300);           /* (5: the writers change pages while the checkpoint copies them) */
  hk_kill(step);
}
static void hk_regrow(int step) {
  if (step == 1) usleep(3000);
  if (step == 3) usleep(500);                         /* (3: after a round of the catch-up with no lock: the writers log more meanwhile) */
  hk_kill(10 + step);
}
static void hk_commit(int step) { hk_kill(20 + step); }
/* mode 6 (0.7, the journal ring): the leader's rounds are slowed now and then and killed at their steps (31: a round begins, 32: a span was written); a second thread makes
 * no-op calls (they wait for the records before them) and deferred ones with a settle; the main thread's calls are acknowledged when they return (rule A): after kill -9 every
 * call that returned is there */
static void hk_jw(store_t *s, int step) {
  (void)s;
  if (step == 1 && (mix64(now_us()) & 7) == 0) usleep((useconds_t)(mix64(now_us() ^ 0x77) % 400));
  hk_kill(30 + step);
}
static _Atomic bool g_noop_stop;
static void *noop_main(void *arg) {
  store_t *s = arg;
  uint64_t k = 0;
  while (!atomic_load(&g_noop_stop)) {
    k++;
    const bool df = (k & 15) == 0 && store_defer(s, true) == 0;
    for (int j = 0; j < 8; j++) {
      const uint32_t z = (uint32_t)(mix64(k * 131 + (uint64_t)j) % 64);
      const int r = store_set_flags(s, z, 0, 0);                         /* (no change: no record of its own; it waits for those it came after) */
      if (r != 0 && r != -ENOENT) _exit(16);
    }
    if (df) { if (store_settle(s) != 0) _exit(17); (void)store_defer(s, false); }
    usleep(200);
  }
  return NULL;
}
/* mode 6: a thread whose calls do not wait (the ingest thread's way): cursors of source 7, a commit every eight of them (the batch end), whose value is then durable */
static shm_t *g_kshm;
static void *dwriter_main(void *arg) {
  store_t *s = arg;
  bool v = false;
  uint64_t k = 0;
  (void)store_get_cursor(s, 7, &v, &k, NULL, NULL);
  if (store_defer(s, true) != 0) _exit(18);
  while (!atomic_load(&g_noop_stop)) {
    k++;
    if (store_set_cursor(s, 7, k, "d", 1) != 0) _exit(19);
    if ((k & 7) == 0) {
      if (store_commit(s) != 0) _exit(20);
      atomic_store(&g_kshm->dcur, k);
    }
    usleep(300);
  }
  return NULL;
}
static void *ckthr_main(void *arg) {
  store_t *s = arg;
  for (;;) {
    (void)store_checkpoint(s);
    usleep(300);
  }
  return NULL;
}

static void child_main(const char *path, shm_t *shm, uint64_t K0, uint64_t count, uint64_t boot, long countdown) {
  int fd = open(path, O_RDONLY | O_DIRECTORY);
  if (fd < 0) _exit(10);
  store_opts_t o;
  small_opts(&o);
  o.create = false;
  o.boot_id = boot;
  o.seg_size = 256u << 10;
  o.journal_max_bytes = 96u << 10;
  o.sync_policy = STORE_SYNC_BATCH;
  o.sync_interval_ms = 5;
  o.checkpoint_interval_ms = 20;
  o.scrub_interval_s = UINT32_MAX;
  if (g_kill_mode == 1) { o.compact_rate = UINT64_MAX; o.nx_reclaim_min = 256; }
  store_test_crash_countdown = countdown;
  if (g_kill_mode == 3) atomic_store(&store_test_ckpt_hook, hk_ckpt);
  if (g_kill_mode == 4) {
    atomic_store(&store_test_regrow_hook, hk_regrow);
    atomic_store(&store_test_rg_tail, 0);             /* (every logged change is made in the rounds with no lock, but what the writers add during the last one) */
  }
  if (g_kill_mode == 5) atomic_store(&store_test_commit_hook, hk_commit);
  if (g_kill_mode == 6) store_test_jw_hook = hk_jw;
  store_t *s = NULL;
  if (store_open(fd, &o, &s) != 0) _exit(11);
  if (g_kill_mode == 6) {
    pthread_t th;
    g_kshm = shm;
    if (pthread_create(&th, NULL, noop_main, s) != 0 || pthread_create(&th, NULL, ckthr_main, s) != 0 || pthread_create(&th, NULL, dwriter_main, s) != 0) _exit(15);
  }
  if (g_kill_mode == 3) {
    pthread_t th;
    if (pthread_create(&th, NULL, ckthr_main, s) != 0) _exit(14);
    pthread_detach(th);
  }
  for (uint64_t K = K0; K < K0 + count; K++) {
    atomic_store(&shm->begun, K + 1);
    if (store_do_op(s, K) != 0) _exit(12);
    atomic_store(&shm->done, K + 1);
    if (g_kill_mode == 6) atomic_store(&shm->acked, K + 1);               /* (rule A: returned = in the kernel, no commit needed for kill -9) */
    if ((K & 7) == 7) {
      if (store_commit(s) != 0) _exit(13);
      atomic_store(&shm->acked, K + 1);
    }
  }
  _exit(0);                                                              /* leaves the store unclean, like a crash */
}

static void test_kill_loop(int iters, int mode) {
  g_kill_mode = mode;
  printf("[kill -9 loop%s: %d iterations]\n", mode == 1 ? " with the cleaner, the nx pass and the scrub" : mode == 2 ? " with groups of zones made known in one record (store_set_known_n)" :
         mode == 3 ? " with a thread that checkpoints all the time (a fuzzy checkpoint killed at its steps)" : mode == 4 ? " with growths of the index built outside the mutex (killed at their steps)" :
         mode == 5 ? " with commits that switch the journal file (killed at their steps)" : mode == 6 ? " with the journal ring (a call is there once it returned; the leader killed at its steps)" : "", iters);
  int hk_kills = 0;
  tdir_t d;
  tdir_new(&d, "kill");
  shm_t *shm = mmap(NULL, sizeof(*shm), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  CHECK(shm != MAP_FAILED);
  if (shm == MAP_FAILED) { tdir_free(&d); return; }
  model_t *model = calloc(1, sizeof(*model)), *tmp = calloc(1, sizeof(*tmp)), *tmp2 = calloc(1, sizeof(*tmp2)), *tmp3 = calloc(1, sizeof(*tmp3));
  uint64_t K0 = 0, boot = 42, rng = 20261114;
  int fresh = 0, crashed = 0, countdown_hits = 0, tampered = 0, older = 0, torn = 0, exact = 0, replayed_total = 0, lost_ops = 0, with_free = 0, part_groups = 0, gen_rebuilds = 0;
  uint32_t max_segs = 0;
  for (int it = 0; it < iters; it++) {
    if (it % (mode == 4 ? 2 : 25) == 0) {                             /* (mode 4: a new store often, so that the index grows from its smallest size again) */
      /* a new store: the first iterations grow the index through several generations */
      tdir_free(&d);
      tdir_new(&d, "kill");
      store_opts_t o;
      small_opts(&o);
      o.boot_id = boot;
      o.scrub_interval_s = UINT32_MAX;
      if (mode == 1) o.seg_size = 64u << 10;                           /* (the cleaner needs segments that are not the open one: the segment size is that of the store's creation) */
      store_t *s = NULL;
      if (store_open(d.fd, &o, &s) != 0) { CHECK(0); break; }
      store_view_add(s, "v0");
      store_view_add(s, "v1");
      store_close(s);
      memset(model, 0, sizeof(*model));
      fresh++;
    }
    rng = mix64(rng);
    bool use_countdown = (rng & 1) != 0;
    long cd = use_countdown ? 1 + (long)((rng >> 8) % 24000) : 0;
    atomic_store(&g_hk_step, 0);
    if (mode >= 3 && use_countdown && ((rng >> 5) & 1)) {             /* (half of the planned kills at a step of the new code instead of a crash point) */
      atomic_store(&g_hk_step, mode == 3 ? 1 + (int)((rng >> 8) % 5) : mode == 4 ? 11 + (int)((rng >> 8) % 3) : mode == 6 ? 31 + (int)((rng >> 8) % 2) : 21 + (int)((rng >> 8) % 3));
      atomic_store(&g_hk_n, 1 + (int)((rng >> 12) % (mode == 3 ? 12 : mode == 4 ? 2 : mode == 6 ? 300 : 40)));
      cd = 0;
      hk_kills++;
    }
    uint64_t count = 700 + (rng >> 40) % 400;
    atomic_store(&shm->begun, K0);
    atomic_store(&shm->done, K0);
    atomic_store(&shm->acked, K0);
    atomic_store(&shm->dcur, 0);
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) { CHECK(0); break; }
    if (pid == 0) child_main(d.path, shm, K0, count, boot, cd);
    if (!use_countdown) {
      usleep((useconds_t)((rng >> 20) % 60000));
      kill(pid, SIGKILL);
    }
    int stt = 0;
    waitpid(pid, &stt, 0);
    bool killed = WIFSIGNALED(stt);
    if (WIFEXITED(stt) && WEXITSTATUS(stt) != 0) { printf("  child failed with %d at iteration %d\n", WEXITSTATUS(stt), it); CHECK(0); break; }
    if (killed) crashed++;
    if (killed && use_countdown) countdown_hits++;
    uint64_t acked = atomic_load(&shm->acked), begun = atomic_load(&shm->begun), done = atomic_load(&shm->done);
    if (begun < K0) begun = K0;
    if (acked < K0) acked = K0;

    /* power-loss variant: lose the tail of the newest journal and come back with another boot id */
    bool tamper = (it % 7 == 6);
    if (tamper) {
      uint32_t best = 0;
      char jp[700];
      best = jrn_newest_gen(d.path, 64);                                /* (not the next journal, made ahead and empty, nor one with a header only) */
      snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, best);
      struct stat jst;
      if (best && stat(jp, &jst) == 0 && jst.st_size > 200) {
        off_t cut = 64 + (off_t)((rng >> 12) % (uint64_t)(jst.st_size - 64));
        CHECK_EQ(truncate(jp, cut), 0);
        boot++;
        tampered++;
      } else tamper = false;
    }
    store_opts_t o;
    small_opts(&o);
    o.create = false;
    o.boot_id = boot;
    o.seg_size = 256u << 10;
    o.scrub_interval_s = UINT32_MAX;
    store_t *s = NULL;
    int r = store_open(d.fd, &o, &s);
    if (r != 0) { printf("  iteration %d: open failed %d\n", it, r); CHECK(0); break; }
    if (mode == 6 && !tamper && atomic_load(&shm->dcur)) {                          /* (the deferred thread's commit: its cursor is durable after kill -9; the power-loss variant cuts durable bytes, as for acked) */
      bool v = false;
      uint64_t c7 = 0;
      CHECK(store_get_cursor(s, 7, &v, &c7, NULL, NULL) == 0 && v && c7 >= atomic_load(&shm->dcur));
    }
    store_stats_t st;
    store_stats(s, &st);
    if (st.recovery.used_older_super) older++;
    if (st.recovery.journal_torn) torn++;
    if (st.seg_free_numbers) with_free++;                              /* (segments were cleaned and removed before this open) */
    if (st.seg_count > max_segs) max_segs = st.seg_count;
    replayed_total += (int)st.recovery.records_replayed;
    store_check_report_t rep;
    int cr = store_check(s, &rep);
    if (cr != 0) { printf("  iteration %d: store_check: %s\n", it, rep.first_error); CHECK(0); store_close(s); break; }
    if (tamper) {
      CHECK(st.recovery.rebuilt || st.recovery.was_clean);
      model_from_store(s, model);
      K0 = begun;                                                       /* absolute ops: the generator needs no state */
    } else {
      CHECK(!st.recovery.rebuilt || st.recovery.gen_replays > 0);        /* (a kill between a growth of the index and the next checkpoint: the new generation's file holds nothing yet, the open rebuilds the derived tables) */
      if (st.recovery.gen_replays) gen_rebuilds++;
      /* the state must be the model after n ops, acked <= n <= begun, or (mode 2) after n ops and the first entries of op n: store_set_known_n() writes a group as more than one record
       * when an entry needs the index (or a table) to grow first, or names a zone pending in the group, and a kill between those records keeps the first ones (each record is whole or
       * not there; the call is not one unit, see dns_store.h) */
      memcpy(tmp, model, sizeof(*tmp));
      for (uint64_t K = K0; K < acked; K++) model_do_op(tmp, K);
      uint64_t found = UINT64_MAX;
      unsigned found_part = 0;
      for (uint64_t n = acked; n <= begun && found == UINT64_MAX; n++) {
        if (model_matches(s, tmp, false)) { found = n; break; }
        if (n == begun) break;
        const unsigned np = model_op_parts(n);
        if (np > 1) memcpy(tmp3, tmp, sizeof(*tmp3));
        model_do_op(tmp, n);
        for (unsigned j = 1; j < np && found == UINT64_MAX; j++) {
          memcpy(tmp2, tmp3, sizeof(*tmp2));
          model_do_op_part(tmp2, n, j);
          if (memcmp(tmp2, tmp, sizeof(*tmp2)) == 0) continue;          /* (the rest of the group changes nothing: a zone of the group twice) */
          if (model_matches(s, tmp2, false)) { found = n; found_part = j; }
        }
      }
      if (found_part) part_groups++;
      if (found == UINT64_MAX) {
        printf("  iteration %d: no prefix matches (K0=%" PRIu64 " acked=%" PRIu64 " done=%" PRIu64 " begun=%" PRIu64 ", killed=%d, countdown=%ld)\n", it, K0, acked, done, begun, killed, cd);
        /* print the difference against the model at 'begun' and at 'acked' */
        memcpy(tmp, model, sizeof(*tmp));
        for (uint64_t K = K0; K < acked; K++) model_do_op(tmp, K);
        model_matches(s, tmp, true);
        CHECK(0);
        store_close(s);
        break;
      }
      CHECK(found >= acked && found <= begun);
      if (found == begun || found == done) exact++;
      lost_ops += (int)(begun - found);
      /* rebuild the model at `found` */
      memcpy(tmp, model, sizeof(*tmp));
      for (uint64_t K = K0; K < found; K++) model_do_op(tmp, K);
      if (found_part) model_do_op_part(tmp, found, found_part);        /* (the next child runs op `found` again, whole: its entries are absolute values) */
      memcpy(model, tmp, sizeof(*model));
      K0 = found;
    }
    /* the store must be usable: a few more writes through the normal path, then a clean close */
    CHECK_EQ(put_i(s, 0, KNZ + 5, 1, NULL) + put_i(s, 1, KNZ + 6, 1, NULL), 0);
    CHECK_EQ(store_delete_name(s, 0, "z0001505.example.test", 21), 0);
    CHECK_EQ(store_delete_name(s, 1, "z0001506.example.test", 21), 0);
    CHECK_EQ(store_close(s), 0);
  }
  printf("  %d stores, %d children killed (%d at a crash point), %d journal tails cut (rebuild path), %d older-superblock opens, %d torn tails,\n"
         "  %d replayed records in total, %d exact-end matches, %d begun-but-lost operations; %d opens found removed segments (%u segment numbers at the most)\n",
         fresh, crashed, countdown_hits, tampered, older, torn, replayed_total, exact, lost_ops, with_free, max_segs);
  if (mode >= 3) printf("  %d kills planned at a step of a %s\n", hk_kills, mode == 3 ? "checkpoint" : mode == 4 ? "growth" : mode == 6 ? "leader of the journal ring" : "commit that switches the journal file");
  if (gen_rebuilds) printf("  %d recoveries rebuilt the derived tables after a growth of the index that no checkpoint had written\n", gen_rebuilds);
  if (mode == 2) printf("  %d recoveries found a group of entries applied in part (a kill between the records of one call)\n", part_groups);
  atomic_store(&g_hk_step, 0);
  free(model);
  free(tmp);
  free(tmp2);
  free(tmp3);
  munmap(shm, sizeof(*shm));
  tdir_free(&d);
  g_kill_mode = 0;
}

/* disk full: RLIMIT_FSIZE makes appends and journal writes fail with EFBIG */
static void test_disk_full(void) {
  printf("[disk full (RLIMIT_FSIZE), writes refused]\n");
  tdir_t d;
  tdir_new(&d, "full");
  store_opts_t o;
  small_opts(&o);
  o.create = true;
  o.no_degrade = true;
  CHECK_EQ(1, 1);
  {
    store_t *s = NULL;
    o.mode = STORE_MODE_COPY;
    o.seg_size = 8u << 20;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); return; }
    store_view_add(s, "default");
    store_close(s);
  }
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    signal(SIGXFSZ, SIG_IGN);
    store_opts_t c = o;
    c.create = false;
    c.sync_policy = STORE_SYNC_NONE;
    store_t *s = NULL;
    if (store_open(d.fd, &c, &s) != 0) _exit(20);
    struct rlimit rl = { 1500u << 10, RLIM_INFINITY };                       /* no file may grow beyond 1.5 MB */
    if (setrlimit(RLIMIT_FSIZE, &rl) != 0) _exit(21);
    uint32_t okn = 0, fails = 0;
    int firstfail = 0;
    static bool stored[4000];
    for (uint32_t i = 0; i < 4000; i++) {
      int r = put_i(s, 0, i, 1, NULL);
      if (r == 0) { okn++; stored[i] = true; }
      else { fails++; if (!firstfail) firstfail = r; if (r != -EFBIG && r != -ENOSPC) _exit(22); }
    }
    if (okn == 0 || fails == 0) _exit(23);
    store_stats_t st;
    store_stats(s, &st);
    if (!(st.state & STORE_ST_DEGRADED_NOSPC) || st.write_errors == 0) _exit(24);
    /* the zones that were stored are all readable, and the store is consistent */
    for (uint32_t i = 0; i < 4000; i++) if (stored[i] && !verify_i(s, 0, i, 1)) _exit(25);
    store_check_report_t rep;
    if (store_check(s, &rep) != 0) _exit(26);
    if (st.zones_stored != okn) _exit(27);
    /* reads keep working; deletes (journal only) may work or fail, not corrupt */
    (void)store_delete_name(s, 0, "z0000000.example.test", 21);
    rl.rlim_cur = RLIM_INFINITY;
    setrlimit(RLIMIT_FSIZE, &rl);
    { int pr = put_i(s, 0, 99999, 1, NULL); if (pr != 0) { printf("    put after the limit: %d\n", pr); fflush(stdout); _exit(28); } }                       /* space is back: the next write succeeds and clears the flag */
    store_stats(s, &st);
    if (st.state & STORE_ST_DEGRADED_NOSPC) _exit(29);
    if (store_check(s, &rep) != 0) _exit(30);
    printf("  %u stored before the limit, %u refused (first: %d)\n", okn, fails, firstfail);
    fflush(stdout);
    _exit(store_close(s) == 0 ? 0 : 31);
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt));
  CHECK_EQ(WEXITSTATUS(stt), 0);
  store_t *s = NULL;
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    check_consistent(s, "after disk full");
    CHECK(verify_i(s, 0, 99999, 1));
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* the cursor and view table survive an unclean stop through the journal */
static void test_unclean_small(void) {
  printf("[unclean stop: views, cursors, flags through the journal]\n");
  tdir_t d;
  tdir_new(&d, "unclean");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  CHECK_EQ(store_close(s), 0);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_opts_t c = o;
    c.create = false;
    store_t *x = NULL;
    if (store_open(d.fd, &c, &x) != 0) _exit(2);
    if (store_view_add(x, "alpha") != 0 || store_view_add(x, "beta") != 1) _exit(3);
    if (store_set_cursor(x, 5, 4242, "ident", 5) != 0) _exit(4);
    uint32_t z;
    if (put_i(x, 1, 5, 9, &z) != 0) _exit(5);
    if (store_set_flags(x, z, STORE_F_NOTIFY_DUE, 0) != 0) _exit(6);
    _exit(0);
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(!st.recovery.was_clean);
    CHECK_EQ(st.recovery.records_replayed, 5);
    CHECK_EQ(st.nviews, 2);
    CHECK_EQ(store_view_id(s, "beta"), 1);
    bool valid;
    uint64_t cv;
    uint8_t id[STORE_IDENT_MAX];
    size_t il;
    CHECK_EQ(store_get_cursor(s, 5, &valid, &cv, id, &il), 0);
    CHECK(valid && cv == 4242 && il == 5 && memcmp(id, "ident", 5) == 0);
    CHECK(verify_i(s, 1, 5, 9));
    store_read_lock();
    store_zone_t zi;
    CHECK_EQ(store_zone_get(s, find_i(s, 1, 5), &zi), 0);
    CHECK_EQ(zi.flags & STORE_F_NOTIFY_DUE, STORE_F_NOTIFY_DUE);
    store_read_unlock();
    check_consistent(s, "unclean small");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

static void test_views_full(void) {
  printf("[view table full]\n");
  tdir_t d;
  tdir_new(&d, "views");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  for (int i = 0; i < STORE_MAX_VIEWS; i++) {
    char nm[32];
    snprintf(nm, sizeof(nm), "view%d", i);
    CHECK_EQ(store_view_add(s, nm), i);
  }
  CHECK_EQ(store_view_add(s, "one-too-many"), -ENOSPC);
  CHECK_EQ(store_view_add(s, ""), -EINVAL);
  CHECK_EQ(put_i(s, 31, 1, 1, NULL), 0);
  CHECK(verify_i(s, 31, 1, 1));
  check_consistent(s, "32 views");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* the review of S1 + S2: hostile superblock and journal, visibility of a new record, reuse of a zone id, growth, clean stop  */
/* ------------------------------------------------------------------------------------------------------------------ */

/* the layout of the superblock (sb_t of dns_store.c): the offsets of the fields that a forged copy changes */
enum {
  SB_BYTES = 65536, SBO_SEQ = 16, SBO_CRC = 60, SBO_JRN_GEN = 96, SBO_IX_GEN = 100, SBO_NVIEWS = 108, SBO_ZT_CAP = 112, SBO_IX_SLOTS = 120,
  SBO_SX_SLOTS = 128, SBO_SEG_SIZE = 136, SBO_NX_CAP = 144, SBO_RSV = 152, SBO_VIEWS = 208, SBO_SRC = 2256, SBO_V = 7376
};
/* counter slots (V_* of dns_store.c) */
enum { VI_HWM = 0, VI_FREE_HEAD = 1, VI_FREE_COUNT = 2, VI_NX_USED = 3, VI_NSEGS = 9, VI_CUR_SEG = 10, VI_IMG_BYTES = 14, VI_SEG1_USED = 32 + 256 + 2048 + 2 };

/* change `n` bytes at `off` of a superblock copy and make its CRC right again: a forged copy that the CRC does not catch */
static void sb_forge(const char *path, size_t off, const void *val, size_t n) {
  uint8_t *b = malloc(SB_BYTES);
  if (!b || read_at(path, 0, b, SB_BYTES) != 0) { CHECK(0); free(b); return; }
  memcpy(b + off, val, n);
  memset(b + SBO_CRC, 0, 4);
  uint32_t crc = store_test_crc32c(0, b, SB_BYTES);
  memcpy(b + SBO_CRC, &crc, 4);
  CHECK_EQ(write_at(path, 0, b, SB_BYTES), 0);
  free(b);
}
static void sb_forge_u64(const char *path, size_t off, uint64_t v) { sb_forge(path, off, &v, 8); }
static void sb_forge_u32(const char *path, size_t off, uint32_t v) { sb_forge(path, off, &v, 4); }

/* M2: a field of the superblock that is used as a size, a count or an index is bounded before it is used.  A copy that is wrong that way is not taken (the other
 * copy is, and the journal chain that goes with it); both wrong: -EBADMSG (the caller quarantines).  ASan has to stay quiet. */
static void test_forged_superblock(void) {
  printf("[forged superblock copies (CRC right, a field wrong)]\n");
  struct { const char *what; size_t off; uint64_t val; int n; } cases[] = {
    { "ix slots 2^62", SBO_IX_SLOTS, 1ull << 62, 8 },
    { "ix slots 2^61 (the size computation wraps to 0)", SBO_IX_SLOTS, 1ull << 61, 8 },
    { "ix slots 2^61 + 1 (wraps to 8)", SBO_IX_SLOTS, (1ull << 61) + 1, 8 },
    { "sx slots all ones", SBO_SX_SLOTS, ~0ull, 8 },
    { "sx slots 0", SBO_SX_SLOTS, 0, 8 },
    { "ix generation 0", SBO_IX_GEN, 0, 4 },
    { "journal generation 0", SBO_JRN_GEN, 0, 4 },
    { "segment size 0", SBO_SEG_SIZE, 0, 8 },
    { "segment size 2^60", SBO_SEG_SIZE, 1ull << 60, 8 },
    { "zt capacity 2^60", SBO_ZT_CAP, 1ull << 60, 8 },
    { "nx capacity all ones", SBO_NX_CAP, ~0ull, 8 },
    { "views count 33", SBO_NVIEWS, 33, 4 },
    { "identity length 4 GiB", SBO_SRC + 3 * 80 + 12, 0xffffffffu, 4 },
    { "current segment 2^31", SBO_V + 8 * VI_CUR_SEG, 0x7fffffffull, 8 },
    { "segment count 5000", SBO_V + 8 * VI_NSEGS, 5000, 8 },
    { "segment 1 used 2^60", SBO_V + 8 * VI_SEG1_USED, 1ull << 60, 8 },
    { "high-water mark beyond the table", SBO_V + 8 * VI_HWM, 1ull << 40, 8 },
    { "free list head beyond the table", SBO_V + 8 * VI_FREE_HEAD, 0x12345678ull, 8 },
    { "name bytes used 2^45", SBO_V + 8 * VI_NX_USED, 1ull << 45, 8 },
    { "a counter of 2^64 - 1", SBO_V + 8 * VI_IMG_BYTES, ~0ull, 8 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    tdir_t d;
    tdir_new(&d, "forge");
    store_opts_t o;
    small_opts(&o);
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); continue; }
    store_view_add(s, "default");
    for (uint32_t i = 0; i < 50; i++) put_i(s, 0, i, 1, NULL);
    CHECK_EQ(store_set_cursor(s, 3, 9, "ident", 5), 0);
    CHECK_EQ(store_close(s), 0);
    char pa[700], pb[700];
    fpath(&d, "super.a", pa, sizeof(pa));
    fpath(&d, "super.b", pb, sizeof(pb));
    uint64_t sa = 0, sbq = 0;
    CHECK_EQ(read_u64_at(pa, SBO_SEQ, &sa), 0);
    CHECK_EQ(read_u64_at(pb, SBO_SEQ, &sbq), 0);
    const char *newer = sa > sbq ? pa : pb;
    if (cases[c].n == 4) sb_forge_u32(newer, cases[c].off, (uint32_t)cases[c].val); else sb_forge_u64(newer, cases[c].off, cases[c].val);
    o.create = false;
    int r = store_open(d.fd, &o, &s);
    if (r != 0 || !s) {
      printf("  [FAIL] %s: the older copy was not taken (open %d)\n", cases[c].what, r);
      g_failed++;
    } else {
      store_stats_t st;
      store_stats(s, &st);
      if (!st.recovery.used_older_super) { printf("  [FAIL] %s: the forged copy was taken\n", cases[c].what); g_failed++; }
      CHECK_EQ(st.zones_stored, 50);
      CHECK(verify_i(s, 0, 49, 1));
      bool valid;
      uint64_t cv;
      uint8_t id[STORE_IDENT_MAX];
      size_t il;
      CHECK_EQ(store_get_cursor(s, 3, &valid, &cv, id, &il), 0);
      CHECK(valid && cv == 9 && il == 5);
      check_consistent(s, cases[c].what);
      CHECK_EQ(put_i(s, 0, 500, 1, NULL), 0);
      CHECK_EQ(store_close(s), 0);
    }
    /* both copies the same wrong: nothing to open */
    for (int k = 0; k < 2; k++) {
      const char *p = k ? pb : pa;
      if (cases[c].n == 4) sb_forge_u32(p, cases[c].off, (uint32_t)cases[c].val); else sb_forge_u64(p, cases[c].off, cases[c].val);
    }
    s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), -EBADMSG);
    CHECK(s == NULL);
    tdir_free(&d);
  }
  /* the name of a view without its terminating zero (a forged copy; the older one has it) */
  {
    tdir_t d;
    tdir_new(&d, "forge");
    store_opts_t o;
    small_opts(&o);
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    store_view_add(s, "default");
    CHECK_EQ(put_i(s, 0, 1, 1, NULL), 0);
    CHECK_EQ(store_close(s), 0);
    char pa[700], pb[700];
    fpath(&d, "super.a", pa, sizeof(pa));
    fpath(&d, "super.b", pb, sizeof(pb));
    uint64_t sa = 0, sbq = 0;
    CHECK_EQ(read_u64_at(pa, SBO_SEQ, &sa), 0);
    CHECK_EQ(read_u64_at(pb, SBO_SEQ, &sbq), 0);
    uint8_t name[64];
    memset(name, 'A', sizeof(name));
    sb_forge(sa > sbq ? pa : pb, SBO_VIEWS, name, sizeof(name));
    o.create = false;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (s) {
      store_stats_t st;
      store_stats(s, &st);
      CHECK(st.recovery.used_older_super);
      CHECK_EQ(strlen(st.views[0].name), 7);
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* the control: a field that nothing reads (the reserved words) forged the same way is no reason to refuse the copy */
  {
    tdir_t d;
    tdir_new(&d, "forge");
    store_opts_t o;
    small_opts(&o);
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    CHECK_EQ(store_close(s), 0);
    char pa[700], pb[700];
    fpath(&d, "super.a", pa, sizeof(pa));
    fpath(&d, "super.b", pb, sizeof(pb));
    sb_forge_u64(pa, SBO_RSV, 5);
    sb_forge_u64(pb, SBO_RSV, 5);
    o.create = false;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (s) CHECK_EQ(store_close(s), 0);
    tdir_free(&d);
  }
}

/* a journal record that the CRC passes: ops are built by hand */
typedef struct { uint8_t b[2048]; size_t n; uint32_t nops; } fj_t;
static void fj_op(fj_t *j, uint16_t type, const void *pay, size_t pl) {
  size_t padded = (pl + 7) & ~(size_t)7;
  memset(j->b + j->n, 0, 8 + padded);
  memcpy(j->b + j->n, &type, 2);
  uint32_t l = (uint32_t)padded;
  memcpy(j->b + j->n + 4, &l, 4);
  memcpy(j->b + j->n + 8, pay, pl);
  j->n += 8 + padded;
  j->nops++;
}
static void fj_v(fj_t *j, uint32_t fid, uint64_t val) {
  uint8_t p[24];
  memset(p, 0, sizeof(p));
  uint32_t n = 1;
  memcpy(p, &n, 4);
  memcpy(p + 8, &fid, 4);
  memcpy(p + 16, &val, 8);
  fj_op(j, 5, p, sizeof(p));
}
/* append the record (24 byte header + ops) to the journal file `path` as the record with sequence number lsn */
static void fj_append(const char *path, fj_t *j, uint64_t lsn) {
  uint8_t *rec = malloc(24 + j->n);
  if (!rec) { CHECK(0); return; }
  uint32_t magic = 0x4a52454bu, len = (uint32_t)(24 + j->n), crc = 0, nops = j->nops;
  memcpy(rec, &magic, 4);
  memcpy(rec + 4, &len, 4);
  memcpy(rec + 8, &crc, 4);
  memcpy(rec + 12, &nops, 4);
  memcpy(rec + 16, &lsn, 8);
  memcpy(rec + 24, j->b, j->n);
  crc = store_test_crc32c(0, rec, len);
  memcpy(rec + 8, &crc, 4);
  struct stat st;
  if (stat(path, &st) != 0) { CHECK(0); free(rec); return; }
  CHECK_EQ(write_at(path, st.st_size, rec, len), 0);
  free(rec);
}

/* M2: journal records that carry values which are used as indexes or sizes; the record is valid (CRC, sequence), its content is not.  The replay refuses the values,
 * asks for the rebuild, and the store goes on as it was. */
static void test_forged_journal(void) {
  printf("[forged journal records]\n");
  struct { const char *what; int kind; } cases[] = {
    { "current segment", 0 }, { "segment used", 1 }, { "generation switch with 2^62 slots", 2 }, { "generation switch to a file that is not there", 3 },
    { "a view id of 77", 4 }, { "a source of 99 and an identity of 200 bytes", 5 }, { "free list head, high-water mark, segment count", 6 } };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    tdir_t d;
    tdir_new(&d, "forgej");
    store_opts_t o;
    small_opts(&o);
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); continue; }
    store_view_add(s, "default");
    for (uint32_t i = 0; i < 20; i++) put_i(s, 0, i, 1, NULL);
    store_stats_t st0;
    store_stats(s, &st0);
    CHECK_EQ(store_close(s), 0);
    char jp[700];
    uint32_t best = 0;
    best = jrn_newest_gen(d.path, -1);
    snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, best);
    fj_t j;
    memset(&j, 0, sizeof(j));
    switch (cases[c].kind) {
    case 0: fj_v(&j, VI_CUR_SEG, 99999); break;
    case 1: fj_v(&j, VI_SEG1_USED, 1ull << 60); break;
    case 2: { uint8_t p[16]; uint32_t w = 0, g = 7; uint64_t ns = 1ull << 62; memcpy(p, &w, 4); memcpy(p + 4, &g, 4); memcpy(p + 8, &ns, 8); fj_op(&j, 8, p, 16); break; }
    case 3: { uint8_t p[16]; uint32_t w = 1, g = 9; uint64_t ns = 4096; memcpy(p, &w, 4); memcpy(p + 4, &g, 4); memcpy(p + 8, &ns, 8); fj_op(&j, 8, p, 16); break; }
    case 4: { uint8_t p[8 + 64]; memset(p, 0, sizeof(p)); uint32_t id = 77; memcpy(p, &id, 4); memcpy(p + 8, "evil", 4); fj_op(&j, 6, p, sizeof(p)); break; }
    case 5: { uint8_t p[24 + 64]; memset(p, 0xaa, sizeof(p)); uint32_t src = 99, valid = 1, il = 200; uint64_t cur = 5; memcpy(p, &src, 4); memcpy(p + 4, &valid, 4); memcpy(p + 8, &cur, 8); memcpy(p + 16, &il, 4); fj_op(&j, 7, p, sizeof(p)); break; }
    case 6: fj_v(&j, VI_FREE_HEAD, 0x7ffffff0ull); fj_v(&j, VI_HWM, 1ull << 40); fj_v(&j, VI_NSEGS, 4000); break;
    }
    fj_append(jp, &j, st0.lsn + 1);
    o.create = false;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (s) {
      store_stats_t st;
      store_stats(s, &st);
      CHECK_EQ(st.recovery.records_replayed, 1);
      CHECK(st.recovery.rebuilt);                                        /* (the values were refused: the open asked for the rebuild) */
      CHECK_EQ(st.zones_stored, 20);
      CHECK(st.seg_count <= 4);
      CHECK_EQ(st.nviews, 1);
      CHECK(verify_i(s, 0, 19, 1));
      check_consistent(s, cases[c].what);
      CHECK_EQ(put_i(s, 0, 200, 1, NULL), 0);
      CHECK(verify_i(s, 0, 200, 1));
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
}

/* L5: the head of the free list names a zone that is alive (a forged counter array, CRC right): it is not taken for a free cell, the list is dropped */
static void test_free_list_head(void) {
  printf("[a free list head that is not a free cell]\n");
  tdir_t d;
  tdir_new(&d, "freehead");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 30; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  uint32_t live = find_i(s, 0, 5);
  CHECK(live != STORE_NONE);
  CHECK_EQ(store_close(s), 0);
  char pa[700], pb[700];
  fpath(&d, "super.a", pa, sizeof(pa));
  fpath(&d, "super.b", pb, sizeof(pb));
  for (int k = 0; k < 2; k++) {
    sb_forge_u64(k ? pb : pa, SBO_V + 8 * VI_FREE_HEAD, live);
    sb_forge_u64(k ? pb : pa, SBO_V + 8 * VI_FREE_COUNT, 3);
  }
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    uint32_t z = STORE_NONE;
    CHECK_EQ(put_i(s, 0, 100, 1, &z), 0);
    CHECK(z != live);                                                    /* (it was taken for a free cell and overwritten before) */
    CHECK(verify_i(s, 0, 5, 1));
    CHECK(verify_i(s, 0, 100, 1));
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.zones_free, 0);
    CHECK_EQ(st.zones_stored, 31);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* L1: a reader that finds a zone sees its image, also in the moment before the counters of the record are applied (a new segment, the used bytes of the segment) */
static store_t *g_vis_store;
static uint32_t g_vis_i;
static int g_vis_calls, g_vis_bad;
static void vis_hook(store_t *s) {
  if (s != g_vis_store || g_vis_i == UINT32_MAX) return;
  char nm[160];
  name_of(g_vis_i, nm, sizeof(nm));
  g_vis_calls++;
  store_read_lock();
  uint32_t z = store_find(s, 0, nm, strlen(nm));
  store_img_t im;
  store_zone_t zi;
  if (z == STORE_NONE || store_zone_get(s, z, &zi) != 0 || store_image_read(s, z, &im) != 0) {
    g_vis_bad++;
  } else {
    uint64_t v;
    if (!img_ok(im.data, im.len, g_vis_i, &v)) g_vis_bad++;
    store_img_release(s, &im);
  }
  store_read_unlock();
}
static void test_visibility(void) {
  printf("[a new record is readable before its counters are applied]\n");
  for (int mode = STORE_MODE_MAP; mode <= STORE_MODE_COPY; mode++) {
    tdir_t d;
    tdir_new(&d, "vis");
    store_opts_t o;
    small_opts(&o);
    o.mode = mode;
    o.seg_size = 65536;                                                  /* (a new segment every ~90 records) */
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); continue; }
    store_view_add(s, "default");
    g_vis_store = s;
    g_vis_calls = g_vis_bad = 0;
    store_test_before_counters = vis_hook;
    for (uint32_t i = 0; i < 400; i++) {
      g_vis_i = i;
      CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
      g_vis_i = UINT32_MAX;
    }
    store_test_before_counters = NULL;
    store_stats_t st;
    store_stats(s, &st);
    CHECK(st.seg_count >= 4);
    CHECK_EQ(g_vis_calls, 400);
    CHECK_EQ(g_vis_bad, 0);
    CHECK_EQ(store_close(s), 0);
    tdir_free(&d);
  }
}

/* 0.7 S3 (WP6): a query worker never sleeps for the store.  A cell whose sequence counter is odd (a writer in the middle of it, or one that a crash left so) is waited for by a thread that
 * may sleep (yield, sleep, give up after 500 ms) and by a thread that may not (store_reader_nosleep(): a bounded spin, then the lookup finds nothing and says "busy"). */
static void test_reader_nosleep(void) {
  printf("[a reader that must not sleep gives up on a cell that is being written]\n");
  tdir_t d;
  tdir_new(&d, "nosleep");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 10; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  char nm[160];
  name_of(4, nm, sizeof(nm));
  uint32_t z = find_i(s, 0, 4);
  CHECK(z != STORE_NONE);
  /* the candidates of the index: the zone id, not verified */
  uint32_t cand[4];
  unsigned nc = store_find_cand(s, 0, nm, strlen(nm), cand, 4);
  CHECK(nc >= 1 && cand[0] == z);
  CHECK(store_zid_is(s, z, 0, nm, strlen(nm)));
  CHECK(!store_zid_is(s, z, 1, nm, strlen(nm)));                        /* (another view) */
  /* the sequence counter of the zc cell (bytes 60..63) is made odd */
  const uint64_t w7 = store_test_peek(s, 1, (uint64_t)z * 64 + 56) & 0xffffffffull;
  store_test_poke(s, 1, (uint64_t)z * 64 + 56, w7 | (1ull << 32));
  store_reader_nosleep(true);
  (void)store_reader_busy_take();
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  store_read_lock();
  uint32_t r = store_find(s, 0, nm, strlen(nm));
  store_zone_t zz;
  int gr = store_zone_get(s, z, &zz);
  bool is = store_zid_is(s, z, 0, nm, strlen(nm));
  store_read_unlock();
  clock_gettime(CLOCK_MONOTONIC, &t1);
  const long us = (long)((t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000L);
  CHECK_EQ(r, STORE_NONE);
  CHECK(gr == -EBADMSG && !is);
  CHECK(store_reader_busy_take());                                      /* (the lookup says it gave up) */
  CHECK(!store_reader_busy_take());                                     /* (and the flag is taken) */
  CHECK(us < 100000);                                                   /* (three looks: a spin each, not the 500 ms of a thread that may wait) */
  printf("  three lookups of the cell that is being written: %ld us in all\n", us);
  /* the writer is done: the same calls see the zone */
  store_test_poke(s, 1, (uint64_t)z * 64 + 56, w7);
  store_read_lock();
  CHECK_EQ(store_find(s, 0, nm, strlen(nm)), z);
  CHECK_EQ(store_zone_get(s, z, &zz), 0);
  store_read_unlock();
  CHECK(!store_reader_busy_take());
  store_reader_nosleep(false);
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* L6: a zone id that a delete frees is not reused while a reader that could have found the zone is still in its read section */
static void test_reuse_after_grace(void) {
  printf("[a zone id is reused after the grace period]\n");
  tdir_t d;
  tdir_new(&d, "reuse");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 10; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  uint32_t a = find_i(s, 0, 4);
  /* no reader: the next zone takes the cell at once */
  CHECK_EQ(store_delete(s, a), 0);
  uint32_t z0 = STORE_NONE;
  CHECK_EQ(put_i(s, 0, 20, 1, &z0), 0);
  CHECK_EQ(z0, a);
  /* a reader in its section: the cell stays out of reach until it is done */
  store_read_lock();
  CHECK_EQ(store_delete(s, z0), 0);
  uint32_t z1 = STORE_NONE, z2 = STORE_NONE;
  CHECK_EQ(put_i(s, 0, 21, 1, &z1), 0);
  CHECK(z1 != z0);
  CHECK_EQ(put_i(s, 0, 22, 1, &z2), 0);
  CHECK(z2 != z0 && z2 != z1);
  store_read_unlock();
  uint32_t z3 = STORE_NONE;
  CHECK_EQ(put_i(s, 0, 23, 1, &z3), 0);
  CHECK_EQ(z3, z0);                                                      /* the reader is gone: the cell is free to use */
  check_consistent(s, "reuse");
  CHECK(verify_i(s, 0, 21, 1) && verify_i(s, 0, 22, 1) && verify_i(s, 0, 23, 1));
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* L4: the sync after the journal record of a generation switch fails: the journal names the new generation, so the live index is the new one too (and a replay of
 * what was left gives the same store) */
/* 0.7 fix A: a growth no longer syncs inside the writer's call; the checkpoint that follows it does, without the mutex.  When that sync fails the growth stays (its record is in the
 * journal and the memory follows it), the error is counted, the journal before the switch is kept open and synced by the next checkpoint, and nothing is lost: the next open (no close)
 * names the same generation and every zone.  Without a flusher thread the writer makes the due checkpoint after its call: deterministic here. */
static void test_growth_sync_fails(void) {
  printf("[an index growth whose checkpoint sync fails]\n");
  tdir_t d;
  tdir_new(&d, "growfail");
  store_opts_t o;
  small_opts(&o);
  o.sync_policy = STORE_SYNC_NONE;
  o.checkpoint_interval_ms = UINT32_MAX;
  int pfd[2];
  CHECK_EQ(pipe(pfd), 0);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    atomic_store(&store_test_no_flusher, true);
    store_t *c = NULL;
    if (store_open(d.fd, &o, &c) != 0) _exit(2);
    store_view_add(c, "default");
    int rc = 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < 5000; i++) {
      store_test_fail_commit = 1;                                        /* (every checkpoint after a growth fails its sync: the superblocks stay, the journal chain grows) */
      rc = put_i(c, 0, i, 1, NULL);
      store_test_fail_commit = 0;
      if (rc != 0) break;
      n++;
    }
    /* a growth of the index that a put started is built on a thread of its own (no flusher does not stop that) and may put its generation in after the last put: wait for it, or the
     * generation read here is older than the one its journal record names (store_reserve() waits for a build that runs, and with 0 zones does nothing else) */
    if (store_reserve(c, 0) != 0) _exit(4);
    store_stats_t st;
    store_stats(c, &st);
    uint64_t out[6] = { (uint64_t)(int64_t)rc, st.ix_gen, st.zones_stored, n, st.write_errors, st.growths };
    if (write(pfd[1], out, sizeof(out)) != (ssize_t)sizeof(out)) _exit(3);
    _exit(0);                                                            /* no close: what the journal holds is what the next open has */
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  uint64_t got[6] = { 0, 0, 0, 0, 0, 0 };
  CHECK(read(pfd[0], got, sizeof(got)) == (ssize_t)sizeof(got));
  close(pfd[0]);
  close(pfd[1]);
  printf("  %" PRIu64 " puts, %" PRIu64 " growths, %" PRIu64 " failed syncs, index generation %" PRIu64 "\n", got[3], got[5], got[4], got[1]);
  CHECK_EQ((int64_t)got[0], 0);                                          /* (no put was refused: the sync is not the writer's) */
  CHECK_EQ(got[3], 5000);
  CHECK(got[1] >= 2);                                                    /* (... and the live index is a new generation) */
  CHECK(got[4] > 0);                                                     /* (the failures were counted) */
  o.create = false;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(st.recovery.gen_replays > 0 && st.recovery.rebuilt);          /* (no checkpoint wrote the new generations: the open rebuilt the derived tables from zt) */
    CHECK(st.ix_gen > got[1]);
    CHECK_EQ(st.zones_stored, got[2]);
    check_consistent(s, "growth sync");
    for (uint32_t i = 0; i < got[3]; i += 97) CHECK(verify_i(s, 0, i, 1));
    CHECK_EQ(put_i(s, 0, 9000, 1, NULL), 0);
    CHECK_EQ(store_close(s), 0);
  }
  /* with the flusher: its commit fails in the background (counted, tried again after a pause), the writer's call does not see it; the next commit makes everything durable */
  o.sync_policy = STORE_SYNC_BATCH;
  o.sync_interval_ms = 20;
  s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    const uint64_t e0 = st.write_errors;
    store_test_fail_commit = 1;
    CHECK_EQ(put_i(s, 0, 9001, 1, NULL), 0);
    for (int w = 0; w < 3000; w++) { store_stats(s, &st); if (st.write_errors > e0) break; usleep(1000); }
    CHECK(st.write_errors > e0);                                         /* (the flusher's commit failed) */
    CHECK(st.committed_lsn < st.lsn);
    CHECK_EQ(store_commit(s), 0);
    store_stats(s, &st);
    CHECK_EQ(st.committed_lsn, st.lsn);
    CHECK(verify_i(s, 0, 9001, 1));
    CHECK_EQ(store_close(s), 0);
  }
  store_test_fail_commit = 0;
  tdir_free(&d);
}

/* A growth built outside the mutex is put in after a clean checkpoint was made meanwhile (the stop of a server that a straggler follows): its record is a change after the clean flag,
 * so the flag is cleared on disk first, as for any writer (the open after a reboot then rebuilds, as after every unclean stop). */
static store_t *g_cg_store;
static _Atomic int g_cg_done, g_cg_want, g_cg_idle;
static void cg_hook(int step) {
  if (step == 1 && atomic_load(&g_cg_done) == 0) {
    atomic_store(&g_cg_want, 1);                                         /* (the writer stops first: no put may clear the flag before the growth's record) */
    for (int w = 0; w < 5000 && !atomic_load(&g_cg_idle); w++) usleep(1000);
    atomic_store(&g_cg_done, store_checkpoint_clean(g_cg_store) == 0 ? 1 : -1);
  }
}
static void test_clean_then_growth(void) {
  printf("[a growth built outside the mutex after a clean checkpoint]\n");
  tdir_t d;
  tdir_new(&d, "cleangrow");
  store_opts_t o;
  small_opts(&o);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_t *s = NULL;
    if (store_open(d.fd, &o, &s) != 0) _exit(2);
    store_view_add(s, "default");
    g_cg_store = s;
    atomic_store(&store_test_regrow_hook, cg_hook);
    uint32_t i = 0;
    while (!atomic_load(&g_cg_want) && i < 20000) {                    /* (until a build begins and its hook asks for the clean checkpoint) */
      if (put_i(s, 0, i++, 1, NULL) != 0) _exit(3);
      usleep(200);
    }
    atomic_store(&g_cg_idle, 1);
    for (int w = 0; w < 10000 && atomic_load(&g_cg_done) == 0; w++) usleep(1000);
    if (atomic_load(&g_cg_done) != 1) _exit(4);
    store_stats_t st;
    store_stats(s, &st);
    for (int w = 0; w < 5000 && st.growths_background == 0; w++) { usleep(1000); store_stats(s, &st); }
    if (st.growths_background == 0) _exit(5);
    if (st.clean_flag) _exit(6);                                         /* (the growth's record cleared the flag on disk) */
    atomic_store(&store_test_regrow_hook, NULL);
    _exit(i > 255 ? 0 : 7);                                              /* no close */
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  if (WIFEXITED(stt) && WEXITSTATUS(stt) != 0) printf("  child exit %d\n", WEXITSTATUS(stt));
  if (WIFSIGNALED(stt)) printf("  child killed by signal %d\n", WTERMSIG(stt));
  o.create = false;
  o.boot_id = 77;                                                        /* (the host was rebooted) */
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(!st.recovery.was_clean);
    CHECK(st.recovery.rebuilt);
    check_consistent(s, "clean then growth");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* 0.7 fix A: no writer waits for the disk inside the writer mutex.  A checkpoint whose flush of the tables is made slow (400 ms in the hook) and a growth of the index whose build is made
 * slow before it takes the mutex: puts, groups, deletes, stamp changes and store_commit() all go on meanwhile and each one is quick; afterwards the checkpoint names its position, the new index
 * holds every change made during the build, and a reopen (after kill -9) has all of it. */
static _Atomic int g_slow_step;          /* the hook of that step sleeps (ckpt 1..4, growth 11..12) */
static _Atomic bool g_in_slow;
static void slow_at(int step) {
  if (step != atomic_load(&g_slow_step)) return;
  atomic_store(&g_in_slow, true);
  usleep(400000);
  atomic_store(&g_in_slow, false);
  atomic_store(&g_slow_step, 0);
}
static void slow_ckpt(int step) { slow_at(step); }
static void slow_regrow(int step) { slow_at(10 + step); }
static void *ckpt_call(void *arg) {
  (void)store_checkpoint(arg);
  return NULL;
}
static int put_src(store_t *s, uint32_t i, uint64_t ver, int64_t src) {      /* zone i with another source id (a renamed domain id) */
  char nm[160];
  name_of(i, nm, sizeof(nm));
  size_t n = img_len(i, ver);
  uint8_t *img = malloc(n);
  img_fill(img, n, i, ver);
  store_meta_t m = meta_of(i, ver);
  m.source_id = src;
  int r = store_put(s, 0, nm, strlen(nm), &m, img, n, NULL);
  free(img);
  return r;
}
static void test_no_wait_in_lock(int mode) {
  printf("[no wait for the disk inside the writer mutex: a slow checkpoint flush, a slow growth build (%s)]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "nowait");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  int pfd[2];
  CHECK_EQ(pipe(pfd), 0);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_t *s = NULL;
    if (store_open(d.fd, &o, &s) != 0) _exit(2);
    store_view_add(s, "default");
    for (uint32_t i = 0; i < 300; i++) if (put_i(s, 0, i, 1, NULL) != 0) _exit(3);
    uint64_t out[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    /* 1. a checkpoint that is slow in its flush (step 2) */
    atomic_store(&store_test_ckpt_hook, slow_ckpt);
    atomic_store(&g_slow_step, 2);
    pthread_t th;
    if (pthread_create(&th, NULL, ckpt_call, s) != 0) _exit(4);
    for (int w = 0; w < 2000 && !atomic_load(&g_in_slow); w++) usleep(1000);
    if (!atomic_load(&g_in_slow)) _exit(5);
    store_stats_t st;
    store_stats(s, &st);
    const uint64_t ck_before = st.checkpoints;
    uint64_t worst = 0, ops = 0;
    for (uint32_t i = 0; i < 300 && atomic_load(&g_in_slow); i++) {
      uint64_t t0 = now_us();
      if (put_i(s, 0, i, 2, NULL) != 0) _exit(6);
      if (i % 50 == 49 && store_commit(s) != 0) _exit(7);              /* (the baton is free while the tables are flushed) */
      uint64_t dt = now_us() - t0;
      if (dt > worst) worst = dt;
      ops++;
    }
    const bool still = atomic_load(&g_in_slow);
    pthread_join(th, NULL);
    store_stats(s, &st);
    out[0] = worst;
    out[1] = ops;
    out[2] = still;
    out[3] = st.checkpoints > ck_before && st.ckpt_lsn < st.lsn;          /* (the checkpoint ended at its position: the puts made during its flush come after it) */
    atomic_store(&store_test_ckpt_hook, NULL);
    /* 2. a growth whose build waits (step 1) before it takes the mutex: new zones until the build begins, then changes of every kind during the wait */
    atomic_store(&store_test_regrow_hook, slow_regrow);
    atomic_store(&g_slow_step, 11);
    store_stats(s, &st);
    const uint64_t bg0 = st.growths_background, g0 = st.growths;
    uint32_t next = 300;
    while (!atomic_load(&g_in_slow) && next < 90000) {
      if (put_i(s, 0, next, 1, NULL) != 0) _exit(8);
      next++;
      store_stats(s, &st);
      if (st.ix_used * 8 > st.ix_slots * 3) usleep(2000);             /* (the build began: give it the time to reach its wait before the old index is half full) */
    }
    if (!atomic_load(&g_in_slow)) _exit(9);
    store_stats(s, &st);
    const uint64_t room = (st.ix_slots / 2 - st.ix_used) / 3;          /* (stay below one half of the old index: no growth inside the mutex) */
    worst = 0;
    ops = 0;
    for (uint64_t k = 0; k < room && atomic_load(&g_in_slow); k++) {
      uint64_t t0 = now_us();
      int r = 0;
      switch (k % 4) {
      case 0: r = put_i(s, 0, next++, 1, NULL); break;                                  /* a new zone */
      case 1: { char nm[160]; name_of((uint32_t)(k % 300), nm, sizeof(nm)); r = store_delete_name(s, 0, nm, strlen(nm)); if (r == -ENOENT) r = 0; break; }   /* a zone goes */
      case 2: r = put_src(s, 100000 + (uint32_t)k, 1, 0); break;                        /* a new zone without a source id */
      default: r = put_src(s, 100000 + (uint32_t)k - 1, 3, 900000 + (int64_t)k); break;  /* ... gets a source id */
      }
      if (r != 0) _exit(10);
      uint64_t dt = now_us() - t0;
      if (dt > worst) worst = dt;
      ops++;
    }
    for (int w = 0; w < 5000 && atomic_load(&g_slow_step) != 0; w++) usleep(1000);
    for (int w = 0; w < 5000; w++) { store_stats(s, &st); if (st.growths_background > bg0) break; usleep(1000); }
    out[4] = worst;
    out[5] = ops;
    out[6] = st.growths_background > bg0 && st.growths == g0 + (st.growths_background - bg0);
    atomic_store(&store_test_regrow_hook, NULL);
    /* every zone is where the model says: by name and by source id */
    bool ok = true;
    for (uint64_t k = 0; k < room && ok; k++) {
      const uint32_t i = (uint32_t)(k % 300);
      if (k % 4 == 1) ok = find_i(s, 0, i) == STORE_NONE;
      if (ok && k % 4 == 3) {
        const uint32_t z = find_i(s, 0, 100000 + (uint32_t)k - 1);
        ok = z != STORE_NONE && store_find_source(s, (uint16_t)((100000 + k - 1) % 4), 900000 + (int64_t)k, 0) == z;
      }
      if (ok && k % 4 == 2) ok = find_i(s, 0, 100000 + (uint32_t)k) != STORE_NONE;
    }
    for (uint32_t i = 300; i < next && ok; i++) ok = find_i(s, 0, i) != STORE_NONE;
    store_check_report_t rep;
    out[7] = ok && store_check(s, &rep) == 0;
    if (!out[7] && store_check(s, &rep) != 0) printf("  store_check: %s\n", rep.first_error);
    out[7] |= (uint64_t)next << 8;
    if (write(pfd[1], out, sizeof(out)) != (ssize_t)sizeof(out)) _exit(11);
    _exit(0);                                                            /* no close: the journal has it all */
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  if (!WIFEXITED(stt) || WEXITSTATUS(stt) != 0) printf("  child exit %d\n", WIFEXITED(stt) ? WEXITSTATUS(stt) : -1);
  uint64_t got[8] = { 0 };
  CHECK(read(pfd[0], got, sizeof(got)) == (ssize_t)sizeof(got));
  close(pfd[0]);
  close(pfd[1]);
  printf("  checkpoint flush held 400 ms: %" PRIu64 " writer calls meanwhile, the slowest %" PRIu64 " us; growth build held 400 ms: %" PRIu64 " calls, the slowest %" PRIu64 " us\n", got[1], got[0], got[5], got[4]);
  CHECK(got[1] > 0 && got[5] > 0);
  CHECK(got[2] == 1);                                                    /* (the calls ended while the flush still slept) */
  CHECK(got[0] < 100000);
  CHECK(got[4] < 100000);
  CHECK(got[3] == 1);
  CHECK(got[6] == 1);                                                    /* (the build was put in: no growth inside the mutex) */
  CHECK((got[7] & 0xff) == 1);
  const uint32_t next = (uint32_t)(got[7] >> 8);
  o.create = false;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(!st.recovery.rebuilt || st.recovery.gen_replays > 0);          /* (the growth was put in after the last checkpoint: its file holds nothing, the open rebuilt the derived tables) */
    check_consistent(s, "no wait, reopen");
    for (uint32_t i = 300; i < next; i += 7) CHECK(find_i(s, 0, i) != STORE_NONE);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* 0.7: the bound of the journal and a close during a fuzzy checkpoint.  A checkpoint whose flush is made slow (1 s in the hook, as a disk slower than the writes) while one writer puts
 * zones as fast as it can: the journal goes past journal_max_bytes (the checkpoint in progress cannot cut it) but never past 2 x journal_max_bytes plus one call; the call that reaches
 * the bound waits at its end, with the writer mutex released (its longest hold stays short), until the checkpoint is done; the next call cuts the journal; one WARNING.  Then a close
 * while a fuzzy checkpoint sleeps in its flush leaves that checkpoint (logged) instead of finishing it, and the reopen finds the clean state with every zone. */
static void log_cb(void *ctx, int level, const char *msg);
static int log_count(int level, const char *needle);
static void log_clear(void);
static _Atomic int g_jb_step, g_jb_ms;
static _Atomic bool g_jb_in, g_jb_entered;
static void jb_hook(int step) {
  if (step != atomic_load(&g_jb_step)) return;
  atomic_store(&g_jb_step, 0);
  atomic_store(&g_jb_in, true);
  atomic_store(&g_jb_entered, true);
  usleep((useconds_t)atomic_load(&g_jb_ms) * 1000u);
  atomic_store(&g_jb_in, false);
}
/* 0.7: a commit switches the journal file (the writers append to a file that no sync holds).  The files of the chain are deleted once neither superblock names them, also when there are
 * hundreds; a file a checkpoint left before it deleted the old ones is found by the next open and deleted; what was written is there after a reopen */
static unsigned jrn_count(const char *dir) {
  DIR *dp = opendir(dir);
  if (!dp) return 0;
  unsigned n = 0;
  struct dirent *de;
  while ((de = readdir(dp)) != NULL) n += strncmp(de->d_name, "jrn.", 4) == 0;
  closedir(dp);
  return n;
}
static void pw_delete_hook(store_t *s) {                     /* (between the record written ahead and the mutex: the zone goes) */
  char nm[160];
  name_of(5, nm, sizeof(nm));
  (void)store_delete_name(s, 0, nm, strlen(nm));
}
/* ---- 0.7: the tables in private memory, written by the checkpoint ---- */
static _Atomic bool g_pt_stop;
static _Atomic uint32_t g_pt_k;
static void pt_hook(int step) {
  if (step == 5) usleep(200);                                            /* (between two runs of the write of the tables: the writer changes pages meanwhile) */
}
static void *pt_writer(void *arg) {
  store_t *s = arg;
  for (uint32_t k = 0; !atomic_load(&g_pt_stop); k++) {
    if (put_i(s, 0, k % 400, 2 + k / 400, NULL) != 0) break;
    atomic_store(&g_pt_k, k + 1);
  }
  return NULL;
}
static void test_private_tables(void) {
  printf("[the tables in private memory: the checkpoint writes the changed pages]\n");
  tdir_t d;
  tdir_new(&d, "priv");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 400; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  store_stats_t st;
  store_stats(s, &st);
  CHECK(st.table_private_bytes > 0);
  CHECK_EQ(store_reserve(s, 0), 0);                                     /* (a growth of the index built outside the mutex may still be on its way: its generation would come after the checkpoint) */
  CHECK_EQ(store_checkpoint_clean(s), 0);
  CHECK(store_test_files_match(s));                                      /* (the writers were out: the files are the memory) */
  store_stats(s, &st);
  CHECK(st.checkpoint_table_bytes > 0 && st.checkpoint_table_last_bytes > 0);
  /* fuzzy checkpoints while a writer changes the pages they copy: a clean checkpoint after them leaves the files equal to the memory (no page that changed was lost) */
  atomic_store(&store_test_ckpt_hook, pt_hook);
  atomic_store(&g_pt_stop, false);
  pthread_t th;
  CHECK_EQ(pthread_create(&th, NULL, pt_writer, s), 0);
  for (int j = 0; j < 30; j++) CHECK_EQ(store_checkpoint(s), 0);
  atomic_store(&g_pt_stop, true);
  pthread_join(th, NULL);
  atomic_store(&store_test_ckpt_hook, NULL);
  const uint32_t K = atomic_load(&g_pt_k);
  CHECK(K > 0);
  CHECK_EQ(store_reserve(s, 0), 0);
  CHECK_EQ(store_checkpoint_clean(s), 0);
  CHECK(store_test_files_match(s));
  /* a write of the tables fails: the checkpoint gives its pages back and the next one writes them */
  CHECK_EQ(put_i(s, 0, 7, 99, NULL), 0);
  store_test_fail_ckwrite = 1;
  CHECK(store_checkpoint(s) < 0);
  store_test_fail_ckwrite = 0;
  CHECK(!store_test_files_match(s));
  CHECK_EQ(store_checkpoint(s), 0);
  CHECK(store_test_files_match(s));
  store_stats(s, &st);
  printf("  %u puts during 30 checkpoints, %" PRIu64 " private bytes, %" PRIu64 " bytes written by checkpoints\n", K, st.table_private_bytes, st.checkpoint_table_bytes);
  CHECK_EQ(store_close(s), 0);
  /* the open: no page is private before a writer changes one */
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &st);
    CHECK_EQ(st.table_private_bytes, 0);
    for (uint32_t i = 0; i < 400; i++) {
      uint32_t last = UINT32_MAX;                                        /* (the last put of zone i by the writer) */
      for (uint32_t k = i; k < K; k += 400) last = k;
      CHECK(verify_i(s, 0, i, i == 7 ? 99 : last == UINT32_MAX ? 1 : 2 + last / 400));
    }
    check_consistent(s, "private tables");
    CHECK_EQ(put_i(s, 0, 500, 1, NULL), 0);
    store_stats(s, &st);
    CHECK(st.table_private_bytes > 0);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

static void test_commit_switch(void) {
  printf("[a commit switches the journal file; the old files go]\n");
  tdir_t d;
  tdir_new(&d, "jsw");
  store_opts_t o;
  small_opts(&o);
  o.sync_interval_ms = 2;
  o.journal_max_bytes = 64u << 10;
  o.checkpoint_interval_ms = 50;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  unsigned most = 0;
  for (uint32_t i = 0; i < 3000; i++) {
    CHECK_EQ(put_i(s, 0, i % 700, 1 + i / 700, NULL), 0);
    if ((i & 15) == 15) { CHECK_EQ(store_commit(s), 0); usleep(500); }
    if ((i & 255) == 0) { const unsigned c = jrn_count(d.path); if (c > most) most = c; }
  }
  store_stats_t st;
  store_stats(s, &st);
  printf("  %" PRIu64 " commits switched the file, %" PRIu64 " checkpoints, at most %u journal files, journal %" PRIu64 " bytes\n", st.journal_commit_switches, st.checkpoints, most,
         st.journal_bytes);
  CHECK(st.journal_commit_switches >= 20);
  CHECK(st.checkpoints >= 2);
  CHECK(st.journal_bytes <= 2 * o.journal_max_bytes + 4096);   /* (the size is the chain's since the checkpoint, every file of it) */
  printf("  %" PRIu64 " image records written before the writer mutex, %" PRIu64 " written again\n", st.image_prewrites, st.image_prewrite_misses);
  CHECK(st.image_prewrites >= 2000);                            /* (every put of a zone that is there: 3000 puts of 700 zones) */
  CHECK_EQ(store_checkpoint(s), 0);
  CHECK_EQ(store_checkpoint(s), 0);                              /* (nothing written between the two: no commit switches) */
  CHECK(jrn_count(d.path) <= 4);                                 /* (the chains of the two superblocks and the file made ahead) */
  store_stats(s, &st);
  const uint32_t gen = st.journal_gen;
  CHECK_EQ(store_close(s), 0);
  /* a file of an old chain that a crash left (the checkpoint had not deleted it yet) */
  char p[700];
  snprintf(p, sizeof(p), "%s/jrn.%u", d.path, gen > 40 ? gen - 40 : 1);
  int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  CHECK(fd >= 0 && write(fd, "junk", 4) == 4);
  if (fd >= 0) close(fd);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  struct stat sb;
  CHECK(gen <= 40 || stat(p, &sb) != 0);                         /* (the open's checkpoint deleted it) */
  bool all = true;
  for (uint32_t i = 0; i < 700; i++) all = all && verify_i(s, 0, i, 1 + (2999 - ((2999 - i) % 700)) / 700);
  CHECK(all);
  /* the zone is deleted between the record written ahead and the change: the change makes the zone again and writes its record inside the mutex */
  store_stats(s, &st);
  const uint64_t miss0 = st.image_prewrite_misses;
  atomic_store(&store_test_prewrite_hook, pw_delete_hook);
  CHECK_EQ(put_i(s, 0, 5, 99, NULL), 0);
  atomic_store(&store_test_prewrite_hook, NULL);
  store_stats(s, &st);
  CHECK_EQ(st.image_prewrite_misses, miss0 + 1);
  CHECK(verify_i(s, 0, 5, 99));
  CHECK_EQ(store_close(s), 0);
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK(verify_i(s, 0, 5, 99) && verify_i(s, 0, 6, 1 + (2999 - ((2999 - 6) % 700)) / 700));
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* 0.7: a growth built outside the mutex catches up with its log in rounds with no lock, and makes only the rest inside it.  The changes come at the two places where they can: before
 * the first round (the build was waiting) and during a round (the hook after the first round writes more); with no tail every logged change but the last round's is made with no
 * lock (two rounds), with the built-in tail (4096) the few changes are all made inside the mutex (no round).  Either way the new index holds every change, before and after a reopen. */
static store_t *g_gc_store;
static _Atomic int g_gc_rounds, g_gc_go, g_gc_idle, g_gc_bad;
static _Atomic uint32_t g_gc_next;
static int gc_delete(store_t *s, uint32_t i) {
  char nm[160];
  name_of(i, nm, sizeof(nm));
  return store_delete_name(s, 0, nm, strlen(nm));
}
static void gc_hook(int step) {
  store_t *s = g_gc_store;
  if (step == 1) {
    atomic_store(&g_gc_go, 1);                                            /* (the main thread stops writing: the changes of the test are the hook's alone) */
    for (int w = 0; w < 5000 && !atomic_load(&g_gc_idle); w++) usleep(1000);
    for (int k = 0; k < 40; k++) if (put_i(s, 0, atomic_fetch_add(&g_gc_next, 1), 1, NULL) != 0) atomic_store(&g_gc_bad, 1);
    if (gc_delete(s, 5) != 0 || put_src(s, 6, 3, 777) != 0) atomic_store(&g_gc_bad, 2);
  } else if (step == 3 && atomic_fetch_add(&g_gc_rounds, 1) == 0) {     /* (logged while the build catches up: the next round or the rest inside the mutex makes them) */
    for (int k = 0; k < 10; k++) if (put_i(s, 0, atomic_fetch_add(&g_gc_next, 1), 1, NULL) != 0) atomic_store(&g_gc_bad, 3);
    if (gc_delete(s, 7) != 0 || put_src(s, 8, 3, 778) != 0) atomic_store(&g_gc_bad, 4);
  }
}
static bool gc_model_ok(store_t *s, uint32_t next, bool round_writes) {      /* (round_writes: the hook after the first round made its changes) */
  for (uint32_t i = 0; i < next; i++) {
    const bool gone = i == 5 || (round_writes && i == 7);
    if (gone ? find_i(s, 0, i) != STORE_NONE : !verify_i(s, 0, i, i == 6 || (round_writes && i == 8) ? 3 : 1)) { printf("  zone %u not as the model says\n", i); return false; }
  }
  return store_find_source(s, 6 % 4, 777, 0) == find_i(s, 0, 6) && store_find_source(s, 6 % 4, 7, 0) == STORE_NONE &&
         (round_writes ? store_find_source(s, 8 % 4, 778, 0) == find_i(s, 0, 8) && store_find_source(s, 7 % 4, 8, 0) == STORE_NONE
                       : store_find_source(s, 8 % 4, 9, 0) == find_i(s, 0, 8));
}
static void test_growth_catchup(void) {
  printf("[a growth built outside the mutex catches up with its log in rounds with no lock]\n");
  for (int run = 0; run < 2; run++) {
    tdir_t d;
    tdir_new(&d, "gcatch");
    store_opts_t o;
    small_opts(&o);
    o.checkpoint_interval_ms = UINT32_MAX;
    o.scrub_interval_s = UINT32_MAX;
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); return; }
    CHECK_EQ(store_view_add(s, "default"), 0);
    g_gc_store = s;
    atomic_store(&g_gc_rounds, 0);
    atomic_store(&g_gc_go, 0);
    atomic_store(&g_gc_idle, 0);
    atomic_store(&g_gc_bad, 0);
    atomic_store(&g_gc_next, 0);
    atomic_store(&store_test_rg_tail, run == 0 ? 0 : -1);
    atomic_store(&store_test_regrow_hook, gc_hook);
    store_stats_t st;
    while (!atomic_load(&g_gc_go) && atomic_load(&g_gc_next) < 5000) {
      CHECK_EQ(put_i(s, 0, atomic_fetch_add(&g_gc_next, 1), 1, NULL), 0);
      store_stats(s, &st);
      if (st.ix_used * 8 > st.ix_slots * 3) usleep(2000);               /* (the build began: it reaches its hook long before the old index is half full) */
    }
    atomic_store(&g_gc_idle, 1);
    store_stats(s, &st);
    for (int w = 0; w < 5000 && st.growths_background == 0; w++) { usleep(1000); store_stats(s, &st); }
    atomic_store(&store_test_regrow_hook, NULL);
    atomic_store(&store_test_rg_tail, -1);
    CHECK_EQ(st.growths_background, 1);
    CHECK_EQ(st.growths, st.growths_background);
    CHECK_EQ(atomic_load(&g_gc_bad), 0);
    CHECK_EQ(atomic_load(&g_gc_rounds), run == 0 ? 2 : 0);
    const uint32_t next = atomic_load(&g_gc_next);
    CHECK(next > 300);
    CHECK(gc_model_ok(s, next, run == 0));
    check_consistent(s, "after the catch-up");
    CHECK_EQ(store_close(s), 0);
    o.create = false;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (s) {
      CHECK(gc_model_ok(s, next, run == 0));
      check_consistent(s, "reopened after the catch-up");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
}

/* 0.7: a retired index generation is released (munmap, close) after the writer mutex is given up, not inside it (20 to 60 ms holds at 10M zones) */
static _Atomic int g_rf_n, g_rf_locked;
static void rf_hook(store_t *s) {
  atomic_fetch_add(&g_rf_n, 1);
  if (!store_test_writer_free(s)) atomic_fetch_add(&g_rf_locked, 1);
}
static void test_retire_after_unlock(void) {
  printf("[a retired index generation is released after the writer mutex]\n");
  tdir_t d;
  tdir_new(&d, "rfree");
  store_opts_t o;
  small_opts(&o);
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  atomic_store(&store_test_no_flusher, true);                            /* (no other thread takes the mutex while the hook looks at it) */
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK_EQ(store_view_add(s, "default"), 0);
    atomic_store(&g_rf_n, 0);
    atomic_store(&g_rf_locked, 0);
    store_test_retire_free = rf_hook;
    store_stats_t st;
    uint32_t i = 0;
    for (store_stats(s, &st); st.growths == 0 && i < 5000; i++) { CHECK_EQ(put_i(s, 0, i, 1, NULL), 0); store_stats(s, &st); }
    for (int w = 0; w < 5000 && st.growths_background != st.growths; w++) { usleep(1000); store_stats(s, &st); }    /* (a build on its thread: it has ended) */
    for (uint32_t k = 0; k < 50 && atomic_load(&g_rf_n) == 0; k++) { CHECK_EQ(put_i(s, 0, i++, 1, NULL), 0); usleep(1000); }
    store_test_retire_free = NULL;
    CHECK(st.growths >= 1);
    CHECK(atomic_load(&g_rf_n) >= 1);
    CHECK_EQ(atomic_load(&g_rf_locked), 0);
    check_consistent(s, "after the release");
    CHECK_EQ(store_close(s), 0);
  }
  atomic_store(&store_test_no_flusher, false);
  tdir_free(&d);
}

/* 0.7 round 10: the growth of the index at a first fill.
 * (1) a reserve (store_reserve()) whose build is dropped by another writer's growth inside the mutex is made again, not counted as made (round 9: the first fill of 10M zones went
 *     through 17 growths);
 * (2) the bulk producer waits for a running build past 7/16 of the index (store_index_wait()) with no lock held, instead of filling the old index to one half and growing it inside the
 *     mutex; below 7/16 it does not wait; a build that does not end is given up on once (the bound), and the next build is waited for again. */
static _Atomic int g_ix_state, g_ix_hits, g_ix_ret;
static void ix_hook(int step) {                                          /* the first build to be built holds at its step 1 (the bigger index is built, nothing put in) until state 2 */
  if (step != 1 || atomic_fetch_add(&g_ix_hits, 1) != 0) return;
  atomic_store(&g_ix_state, 1);
  while (atomic_load(&g_ix_state) != 2) usleep(500);
}
static void *ix_reserve_thread(void *arg) { atomic_store(&g_ix_ret, store_reserve(arg, 50000)); return NULL; }
static void test_reserve_survives_growth(void) {
  printf("[a reserve whose build another writer's growth drops is made again]\n");
  tdir_t d;
  tdir_new(&d, "rsvgrow");
  store_opts_t o;
  small_opts(&o);
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  CHECK_EQ(store_view_add(s, "default"), 0);
  atomic_store(&g_ix_state, 0);
  atomic_store(&g_ix_hits, 0);
  atomic_store(&g_ix_ret, -1);
  atomic_store(&store_test_regrow_hook, ix_hook);
  pthread_t th;
  CHECK_EQ(pthread_create(&th, NULL, ix_reserve_thread, s), 0);
  for (int w = 0; w < 5000 && atomic_load(&g_ix_state) != 1; w++) usleep(1000);
  CHECK_EQ(atomic_load(&g_ix_state), 1);                                 /* (the reserve's build is made and waits: no other build can begin) */
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.ix_slots, 1024);
  uint32_t n = 0;
  for (store_stats(s, &st); st.growths == 0 && n < 5000; n++) { CHECK_EQ(put_i(s, 0, n, 1, NULL), 0); store_stats(s, &st); }
  CHECK_EQ(st.growths, 1);                                               /* (the index filled up to one half: the growth inside the mutex dropped the reserve's build) */
  CHECK_EQ(st.growths_background, 0);
  atomic_store(&g_ix_state, 2);
  pthread_join(th, NULL);
  atomic_store(&store_test_regrow_hook, NULL);
  CHECK_EQ(atomic_load(&g_ix_ret), 0);
  CHECK_EQ(atomic_load(&g_ix_hits), 2);                                  /* (it was built again) */
  store_stats(s, &st);
  CHECK(st.ix_slots >= 50000 * 8 / 3 + 16);                              /* (the reserve is there: round 9 left the index at the size of the growth inside the mutex) */
  CHECK(st.sx_slots >= 50000 * 8 / 3 + 16);
  CHECK_EQ(st.growths_background, 1);
  CHECK_EQ(st.growths, 2);
  for (uint32_t i = 0; i < n; i++) CHECK(verify_i(s, 0, i, 1));
  check_consistent(s, "after the reserve made again");
  /* the store is big enough now: more zones than the first fill had grow nothing */
  for (uint32_t i = n; i < 30000; i++) if (put_i(s, 0, i, 1, NULL) != 0) { CHECK(false); break; }
  store_stats(s, &st);
  CHECK_EQ(st.growths, 2);
  CHECK_EQ(store_reserve(s, 50000), 0);                                  /* (a reserve that is there needs no build) */
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

static void *ix_wait_thread(void *arg) { atomic_store(&g_ix_ret, (int)(store_index_wait(arg) ? 1 : 2)); return NULL; }
static void test_index_wait(void) {
  printf("[the producer waits for the build of the next index past 7/16 of the index instead of growing it inside the mutex]\n");
  for (int run = 0; run < 2; run++) {                                    /* run 1: the wait is bounded, the build ends later */
    tdir_t d;
    tdir_new(&d, "ixwait");
    store_opts_t o;
    small_opts(&o);
    o.checkpoint_interval_ms = UINT32_MAX;
    o.scrub_interval_s = UINT32_MAX;
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); return; }
    CHECK_EQ(store_view_add(s, "default"), 0);
    CHECK_EQ(store_index_wait(s), 0);                                    /* (no build) */
    atomic_store(&g_ix_state, 0);
    atomic_store(&g_ix_hits, 0);
    atomic_store(&g_ix_ret, 0);
    atomic_store(&store_test_regrow_hook, ix_hook);
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.ix_slots, 1024);
    uint32_t n = 0;
    for (; n < 384; n++) CHECK_EQ(put_i(s, 0, n, 1, NULL), 0);          /* (3/8: 384 entries in use, the 385th starts the build) */
    CHECK_EQ(put_i(s, 0, n++, 1, NULL), 0);
    for (int w = 0; w < 5000 && atomic_load(&g_ix_state) != 1; w++) usleep(1000);
    CHECK_EQ(atomic_load(&g_ix_state), 1);                               /* (the build is made and waits) */
    for (; n < 448; n++) CHECK_EQ(put_i(s, 0, n, 1, NULL), 0);          /* (7/16: 448 entries) */
    CHECK_EQ(store_index_wait(s), 0);                                    /* (a build runs, the index is not past 7/16: no wait) */
    CHECK_EQ(put_i(s, 0, n++, 1, NULL), 0);                             /* (the 449th entry) */
    if (run == 1) atomic_store(&store_test_rg_wait_ms, 100);
    atomic_store(&g_ix_ret, 0);
    pthread_t th;
    CHECK_EQ(pthread_create(&th, NULL, ix_wait_thread, s), 0);
    if (run == 0) {
      usleep(100000);
      CHECK_EQ(atomic_load(&g_ix_ret), 0);                               /* (it waits) */
      CHECK_EQ(put_i(s, 0, n++, 1, NULL), 0);                           /* (the writer mutex is free: a write goes through, and a lookup) */
      CHECK(find_i(s, 0, 3) != STORE_NONE);
      CHECK_EQ(atomic_load(&g_ix_ret), 0);
      atomic_store(&g_ix_state, 2);                                      /* (the build goes on: it is not dropped) */
      pthread_join(th, NULL);
      CHECK_EQ(atomic_load(&g_ix_ret), 1);
      for (int w = 0; w < 5000; w++) { store_stats(s, &st); if (st.growths_background == 1) break; usleep(1000); }
      CHECK_EQ(st.growths_background, 1);
      CHECK_EQ(st.growths, 1);                                           /* (no growth inside the mutex) */
      CHECK_EQ(st.index_waits, 1);
      CHECK(st.index_wait_us >= 100000);
      CHECK_EQ(st.index_wait_giveups, 0);
      CHECK(st.ix_slots > 1024);
    } else {
      pthread_join(th, NULL);                                            /* (the bound: 100 ms, the build is still held) */
      CHECK_EQ(atomic_load(&g_ix_ret), 1);
      store_stats(s, &st);
      CHECK_EQ(st.index_waits, 1);
      CHECK_EQ(st.index_wait_giveups, 1);
      CHECK(st.index_wait_max_us >= 100000 && st.index_wait_max_us < 5000000);
      CHECK_EQ(store_index_wait(s), 0);                                  /* (given up on: no second wait for this build) */
      CHECK_EQ(put_i(s, 0, n++, 1, NULL), 0);
      CHECK_EQ(store_index_wait(s), 0);
      atomic_store(&g_ix_state, 2);
      for (int w = 0; w < 5000; w++) { store_stats(s, &st); if (st.growths_background == 1) break; usleep(1000); }
      CHECK_EQ(st.growths_background, 1);
      CHECK_EQ(st.growths, 1);
      CHECK_EQ(st.index_waits, 1);
      atomic_store(&store_test_rg_wait_ms, -1);
    }
    atomic_store(&store_test_regrow_hook, NULL);
    for (uint32_t i = 0; i < n; i++) CHECK(verify_i(s, 0, i, 1));
    check_consistent(s, "after the wait");
    CHECK_EQ(store_close(s), 0);
    tdir_free(&d);
  }
}

/* 0.7 round 12: the first fill (the manifest pass of a store that reserved its index) raises the size at which a checkpoint is forced, and the bound of the journal, to 4 x journal_max_bytes while
 * the free space allows (store_journal_boost()); the end of the fill brings it back and the journal that grew is cut at once, not at the next write.  A small disk keeps the normal size, and a disk
 * that fills during the fill takes the raise back.  A crash during the fill replays the larger journal and loses nothing.  journal_max_bytes is 256 KiB here: the raise needs 128 times that
 * free (32 MiB), more than the floor that the writes need (jr_floor(): 8 MiB and what a checkpoint may still allocate), so that "small" can still take records. */
#define JBO_MAX (256u << 10)
#define JBO_BIG (1ll << 40)
#define JBO_SMALL (24ll << 20)
static _Atomic int64_t g_jbo_free;
static int64_t jbo_fs_free(void) { return atomic_load(&g_jbo_free); }
/* puts (new versions of the zones 0..149, from put k0 on) until the journal holds `bytes` or a checkpoint cut it (*cut); returns the number of the next put */
static uint32_t jbo_fill(store_t *s, uint32_t k0, uint64_t bytes, bool *cut) {
  store_stats_t st;
  store_stats(s, &st);
  const uint64_t c0 = st.checkpoints;
  uint32_t k = k0;
  *cut = false;
  while (k < k0 + 60000) {
    if (put_i(s, 0, k % 150, 1 + k / 150, NULL) != 0) { CHECK(!"put"); break; }
    k++;
    (void)store_journal_wait(s, 2);                                      /* (as the reconcile thread does between its groups) */
    store_stats(s, &st);
    if (st.checkpoints > c0) { *cut = true; break; }
    if (st.journal_bytes >= bytes) break;
  }
  return k;
}
static bool jbo_verify(store_t *s, uint32_t k) {                         /* every zone in the version of its last put among the first k */
  bool ok = true;
  for (uint32_t i = 0; i < 150; i++) {
    uint64_t ver = 0;
    for (uint32_t j = i; j < k; j += 150) ver = 1 + j / 150;
    if (ver && !verify_i(s, 0, i, ver)) ok = false;
  }
  return ok;
}
static void test_journal_boost(void) {
  printf("[a bulk fill raises the size at which a checkpoint is forced and the bound of the journal; its end brings them back and cuts the journal]\n");
  tdir_t d;
  tdir_new(&d, "jboost");
  store_opts_t o;
  small_opts(&o);
  o.journal_max_bytes = JBO_MAX;
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  log_clear();
  atomic_store(&g_jbo_free, JBO_BIG);
  store_test_fs_free = jbo_fs_free;
  atomic_store(&store_test_jr_floor, (int64_t)(8ll << 20));                /* (the floor of a UFS store: a copy-on-write file system adds 16 MiB, more than "small" leaves) */
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { store_test_fs_free = NULL; atomic_store(&store_test_jr_floor, -1); tdir_free(&d); return; }
  CHECK_EQ(store_view_add(s, "default"), 0);
  CHECK_EQ(store_reserve(s, 3000), 0);                                   /* (no growth of the index during the test: a growth asks for a checkpoint) */
  CHECK_EQ(store_checkpoint(s), 0);
  store_stats_t st;
  store_stats(s, &st);
  const uint64_t base = st.checkpoints;
  CHECK(st.flusher);
  CHECK_EQ(st.journal_max_bytes, JBO_MAX);
  CHECK_EQ(st.journal_bound_bytes, 2 * JBO_MAX);
  CHECK_EQ(st.journal_boost, 0);
  CHECK_EQ(st.journal_boosts, 0);
  store_journal_boost(NULL, true);                                       /* (no store: nothing) */
  store_journal_boost(s, false);                                         /* (not raised: nothing, no log) */
  CHECK_EQ(log_count(-1, "bulk fill"), 0);
  /* 1. raised: 4 x, the bound 2 x that; the journal passes 2 x the normal size, the bound of the normal one, with no checkpoint and no wait; a checkpoint is forced at the raised size */
  store_journal_boost(s, true);
  store_journal_boost(s, true);                                          /* (idempotent: one raise, one log line) */
  store_stats(s, &st);
  CHECK_EQ(st.journal_max_bytes, 4 * JBO_MAX);
  CHECK_EQ(st.journal_bound_bytes, 8 * JBO_MAX);
  CHECK_EQ(st.journal_boost, 1);
  CHECK_EQ(st.journal_boosts, 1);
  CHECK_EQ(log_count(6, "a bulk fill begins: a checkpoint is forced at 1024 KiB of journal"), 1);
  bool cut = false;
  uint32_t k = jbo_fill(s, 0, 5 * JBO_MAX / 2, &cut);
  store_stats(s, &st);
  CHECK(!cut);
  CHECK(st.journal_bytes >= 5 * JBO_MAX / 2);                            /* (past 2 x the normal size: with the normal one the writes would have waited here) */
  CHECK_EQ(st.checkpoints, base);
  CHECK_EQ(st.journal_limit_waits, 0);
  k = jbo_fill(s, k, 8 * JBO_MAX, &cut);                                 /* (on to the raised size: the writer that reaches it begins the checkpoint) */
  store_stats(s, &st);
  CHECK(cut);
  CHECK(st.journal_peak_bytes >= 4 * JBO_MAX && st.journal_peak_bytes <= 8 * JBO_MAX + 4096);
  for (int w = 0; w < 3000 && st.checkpoints < base + 1; w++) { usleep(1000); store_stats(s, &st); }
  CHECK(st.checkpoints >= base + 1);
  for (int w = 0; w < 20000 && st.journal_bytes >= 3 * JBO_MAX / 2; w++) { usleep(1000); store_stats(s, &st); }   /* (a slow checkpoint (ZFS, ASan) let the writes of step 1 run on past 4 x: the next one cuts them) */
  /* 2. the end of the fill: the journal is between the two sizes, the checkpoint that cuts it is made at once (the flusher is woken), the sizes are the normal ones */
  k = jbo_fill(s, k, 3 * JBO_MAX / 2, &cut);
  store_stats(s, &st);
  CHECK(!cut);
  CHECK(st.journal_bytes >= 3 * JBO_MAX / 2 && st.journal_bytes < 4 * JBO_MAX);
  const uint64_t c1 = st.checkpoints;
  log_clear();
  const uint64_t t0 = now_ms();
  store_journal_boost(s, false);
  store_stats(s, &st);
  CHECK_EQ(st.journal_max_bytes, JBO_MAX);
  CHECK_EQ(st.journal_bound_bytes, 2 * JBO_MAX);
  CHECK_EQ(st.journal_boost, 0);
  CHECK_EQ(st.journal_boosts, 1);
  CHECK_EQ(log_count(6, "the bulk fill is over: a checkpoint is forced at 256 KiB of journal again"), 1);
  for (int w = 0; w < 5000 && (st.checkpoints == c1 || st.journal_bytes >= JBO_MAX); w++) { usleep(1000); store_stats(s, &st); }
  printf("  the journal of %u KiB was cut %" PRIu64 " ms after the end of the fill\n", (unsigned)(3 * JBO_MAX / 2 >> 10), now_ms() - t0);
  CHECK(st.checkpoints > c1);
  CHECK(st.journal_bytes < JBO_MAX);
  store_journal_boost(s, false);                                         /* (idempotent) */
  CHECK_EQ(log_count(6, "the bulk fill is over"), 1);
  /* 3. a small disk keeps the normal size (the raise is asked for, and logged as not in force); the checkpoint is forced at 256 KiB */
  atomic_store(&g_jbo_free, JBO_SMALL);
  CHECK_EQ(store_checkpoint(s), 0);                                      /* (the probe) */
  log_clear();
  store_journal_boost(s, true);
  store_stats(s, &st);
  CHECK_EQ(st.journal_boost, 1);
  CHECK_EQ(st.journal_boosts, 2);
  CHECK_EQ(st.journal_max_bytes, JBO_MAX);                               /* (not in force) */
  CHECK_EQ(log_count(6, "the free space is too small"), 1);
  k = jbo_fill(s, k, 3 * JBO_MAX, &cut);
  CHECK(cut);
  /* 4. the disk has room again: the raise is in force; the disk fills up: the raise is taken back by itself (the next checkpoint probes) */
  atomic_store(&g_jbo_free, JBO_BIG);
  CHECK_EQ(store_checkpoint(s), 0);
  store_stats(s, &st);
  CHECK_EQ(st.journal_max_bytes, 4 * JBO_MAX);
  CHECK_EQ(st.journal_bound_bytes, 8 * JBO_MAX);
  atomic_store(&g_jbo_free, JBO_SMALL);
  CHECK_EQ(store_checkpoint(s), 0);
  store_stats(s, &st);
  CHECK_EQ(st.journal_max_bytes, JBO_MAX);
  CHECK_EQ(st.journal_boost, 1);                                         /* (still asked for) */
  store_journal_boost(s, false);
  store_stats(s, &st);
  CHECK_EQ(st.journal_boost, 0);
  CHECK(jbo_verify(s, k));
  check_consistent(s, "journal boost");
  CHECK_EQ(store_close(s), 0);
  store_test_fs_free = NULL;
  atomic_store(&store_test_jr_floor, -1);
  tdir_free(&d);
}

/* a crash (the process ends with no close) while the fill holds the larger bound: the journal that grew past the normal size is replayed, in full, and every zone is there */
static void test_journal_boost_crash(void) {
  printf("[a crash during the bulk fill replays the larger journal and loses nothing]\n");
  tdir_t d;
  tdir_new(&d, "jboostc");
  store_opts_t o;
  small_opts(&o);
  o.journal_max_bytes = JBO_MAX;
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  atomic_store(&g_jbo_free, JBO_BIG);
  store_test_fs_free = jbo_fs_free;
  int pp[2];
  CHECK_EQ(pipe(pp), 0);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_t *x = NULL;
    if (store_open(d.fd, &o, &x) != 0) _exit(2);
    if (store_view_add(x, "default") != 0 || store_reserve(x, 3000) != 0 || store_checkpoint(x) != 0) _exit(3);
    store_stats_t cs;
    store_stats(x, &cs);
    const uint64_t base = cs.checkpoints;
    store_journal_boost(x, true);
    bool cut = true;
    const uint32_t k = jbo_fill(x, 0, 3 * JBO_MAX, &cut);
    store_stats(x, &cs);
    if (cut || cs.journal_bytes < 3 * JBO_MAX || cs.checkpoints != base) _exit(4);   /* (three times the size at which the normal bound forces a checkpoint, and none was made) */
    if (store_commit(x) != 0) _exit(5);
    if (write(pp[1], &k, sizeof(k)) != (ssize_t)sizeof(k)) _exit(6);
    _exit(0);                                                            /* (no close: the state a crash leaves) */
  }
  uint32_t k = 0;
  CHECK(read(pp[0], &k, sizeof(k)) == (ssize_t)sizeof(k));
  close(pp[0]);
  close(pp[1]);
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  if (!(WIFEXITED(stt) && WEXITSTATUS(stt) == 0)) printf("  (the child ended with status %d)\n", WIFEXITED(stt) ? WEXITSTATUS(stt) : -1);
  o.create = false;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK(!st.recovery.was_clean);
    CHECK(!st.recovery.rebuilt);
    printf("  %u puts, %" PRIu64 " records replayed, the open took %" PRIu64 " us\n", k, st.recovery.records_replayed, st.recovery.open_us);
    CHECK(st.recovery.records_replayed >= k);                            /* (the journal was not cut: every put since the checkpoint is a record) */
    CHECK_EQ(st.journal_boost, 0);                                       /* (the flag is the fill's, not the store's: the next process starts at the normal size) */
    CHECK_EQ(st.journal_max_bytes, JBO_MAX);
    CHECK(jbo_verify(s, k));
    check_consistent(s, "journal boost crash");
    CHECK_EQ(store_close(s), 0);
  }
  store_test_fs_free = NULL;
  tdir_free(&d);
}

static void test_journal_bound(int mode) {
  printf("[the journal stays below 2 x journal_max_bytes while a checkpoint is slow; a close leaves a fuzzy checkpoint (%s)]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "jbound");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.journal_max_bytes = 64u << 10;
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  log_clear();
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.journal_bound_bytes, 2 * o.journal_max_bytes);
  CHECK(st.flusher);
  /* 1. the first fuzzy checkpoint (begun by the put that fills the journal) sleeps 1 s in its flush */
  atomic_store(&g_jb_entered, false);
  atomic_store(&g_jb_ms, 1000);
  atomic_store(&g_jb_step, 2);
  atomic_store(&store_test_ckpt_hook, jb_hook);
  uint64_t peak = 0;
  uint32_t i = 0;
  bool cut = false;
  for (; i < 100000 && !cut; i++) {
    if (put_i(s, 0, i, 1, NULL) != 0) { CHECK(!"put"); break; }
    (void)store_journal_wait(s, 2);                                     /* (as the reconcile thread does between its groups) */
    store_stats(s, &st);
    if (st.journal_bytes > peak) peak = st.journal_bytes;
    cut = atomic_load(&g_jb_entered) && !atomic_load(&g_jb_in) && st.journal_limit_waits > 0 && st.journal_bytes < o.journal_max_bytes;   /* (waited, the flush ended, the next checkpoint cut it) */
  }
  store_stats(s, &st);
  printf("  %u puts; journal peak %" PRIu64 " bytes (bound %" PRIu64 "), %" PRIu64 " wait(s), the longest %" PRIu64 " us; writer mutex held at most %" PRIu64 " us\n", i, st.journal_peak_bytes,
         st.journal_bound_bytes, st.journal_limit_waits, st.journal_limit_wait_max_us, st.lock_hold_max_us);
  CHECK(cut);
  CHECK(peak >= o.journal_max_bytes);                                     /* (the slow checkpoint did not cut it) */
  CHECK(st.journal_peak_bytes >= peak && st.journal_peak_bytes <= st.journal_bound_bytes + 4096);   /* (one put is far less than 4 KiB of records) */
  CHECK(st.journal_limit_waits >= 1);
  CHECK(st.journal_limit_wait_max_us > 0 && st.journal_limit_wait_us >= st.journal_limit_wait_max_us);
  CHECK(st.lock_hold_max_us < 500000);                                    /* (the wait is outside the writer mutex; the hook slept 1 s) */
  CHECK(st.lock_hold_max_site != NULL && st.lock_hold_max_site[0] != 0);              /* (the function of the longest hold is named: store.lock.writer_hold_max_site) */
  CHECK(st.checkpoint_max_us >= 900000);                                  /* (the slow one) */
  CHECK_EQ(log_count(4, "2 x journal_max_bytes"), 1);                   /* (at most one a minute) */
  CHECK_EQ(store_close(s), 0);
  /* 2. a close while a fuzzy checkpoint sleeps in its flush (the hook returns after 1 s; the flush then stops before its first piece).  A journal limit that is far away and a
   * checkpoint by the interval: no put waits, the close comes while the flusher's checkpoint is in the hook */
  o.create = false;
  o.journal_max_bytes = 64u << 20;
  o.checkpoint_interval_ms = 100;
  s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { atomic_store(&store_test_ckpt_hook, NULL); tdir_free(&d); return; }
  for (uint32_t k = 0; k < 500; k++, i++)
    if (put_i(s, 0, i, 1, NULL) != 0) { CHECK(!"put 2"); break; }
  atomic_store(&g_jb_entered, false);
  atomic_store(&g_jb_step, 2);
  for (int w = 0; w < 5000 && !atomic_load(&g_jb_entered); w++) usleep(1000);
  CHECK(atomic_load(&g_jb_in));
  const uint32_t n = i;
  log_clear();
  CHECK_EQ(store_close(s), 0);
  atomic_store(&store_test_ckpt_hook, NULL);
  CHECK_EQ(log_count(6, "was left for the clean checkpoint that follows"), 1);
  s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &st);
    CHECK(st.recovery.was_clean);
    CHECK_EQ(st.recovery.records_replayed, 0);
    CHECK(!st.recovery.rebuilt);
    for (uint32_t k = 0; k < n; k += 13) CHECK(find_i(s, 0, k) != STORE_NONE);
    CHECK(find_i(s, 0, n - 1) != STORE_NONE);
    check_consistent(s, "journal bound, reopen");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* M4: a clean checkpoint says "clean" on disk without closing the store: the next open reads no journal and, after a reboot, does not rebuild; a change after it clears the
 * flag first (so the next open after a reboot rebuilds, as after any unclean stop) */
static void test_clean_checkpoint(void) {
  printf("[a clean checkpoint without close]\n");
  tdir_t d;
  tdir_new(&d, "clean");
  store_opts_t o;
  small_opts(&o);
  for (int round = 0; round < 2; round++) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
      store_opts_t c = o;
      store_t *x = NULL;
      if (store_open(d.fd, &c, &x) != 0) _exit(2);
      if (round == 0) {
        store_view_add(x, "default");
        for (uint32_t i = 0; i < 100; i++) if (put_i(x, 0, i, 1, NULL) != 0) _exit(3);
      }
      if (store_checkpoint_clean(x) != 0) _exit(4);
      if (round == 1 && put_i(x, 0, 500, 1, NULL) != 0) _exit(5);       /* a straggler after the clean checkpoint */
      _exit(0);
    }
    int stt = 0;
    waitpid(pid, &stt, 0);
    CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
    o.create = false;
    o.boot_id = 100 + (uint64_t)round;                                   /* (the host was rebooted) */
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) continue;
    store_stats_t st;
    store_stats(s, &st);
    if (round == 0) {
      CHECK(st.recovery.was_clean);                                      /* the stop that did not close is clean */
      CHECK_EQ(st.recovery.records_replayed, 0);
      CHECK(!st.recovery.rebuilt);
      CHECK_EQ(st.zones_stored, 100);
    } else {
      CHECK(!st.recovery.was_clean);                                     /* the put after the checkpoint cleared the flag: unclean, another boot: the tables are rebuilt */
      CHECK(st.recovery.rebuilt);
      CHECK_EQ(st.zones_stored, 101);
      CHECK(verify_i(s, 0, 500, 1));
    }
    check_consistent(s, "clean checkpoint");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* ------------------------------------------------------------------------------------------------------------------ */

/* 0.7 review fixes (S3+S4): store_stats() reads the index generation, so it is a reader (L1); the NONSTORE records have a counter of their own (L8); a writer that fails changes nothing (the hook the
 * Backend's tests use to fail a write) */
static bool g_stats_in_section;
static void in_stats_hook(void) {
  /* a thread in a read section holds the grace period of what is retired after it started: an epoch that is advanced now is not safe yet.  Outside a section it is. */
  uint64_t ep = rcu_writer_advance_epoch();
  g_stats_in_section = !rcu_writer_is_safe(ep);
}

static int fault_enospc_set_stamp(const char *op, uint32_t zid) {
  (void)zid;
  return strcmp(op, "set_stamp") == 0 ? -ENOSPC : 0;
}

static void test_review_fixes(void) {
  printf("[store_stats() is a reader; the NONSTORE counter; a failed writer changes nothing]\n");
  tdir_t d;
  tdir_new(&d, "review");
  store_opts_t o;
  small_opts(&o);
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 6; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  /* L1 */
  store_stats_t ss;
  g_stats_in_section = false;
  store_test_in_stats = in_stats_hook;
  store_stats(s, &ss);
  store_test_in_stats = NULL;
  CHECK(g_stats_in_section);
  /* L8: records that make the memory of a zone of the heap directory (a secondary, a catalog consumer) are counted apart; known + stored still count them */
  uint32_t z1 = STORE_NONE, z2 = STORE_NONE;
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.flags = STORE_F_NONSTORE;
  m.source = 0;
  CHECK_EQ(store_set_known(s, 0, "ns1.sec.test", 12, &m, &z1), 0);
  CHECK_EQ(store_set_known(s, 0, "ns2.sec.test", 12, &m, &z2), 0);
  store_stats(s, &ss);
  CHECK_EQ(ss.zones_nonstore, 2);
  CHECK_EQ(ss.zones_known, 2);
  CHECK_EQ(ss.zones_stored, 6);
  check_consistent(s, "nonstore 2");
  CHECK_EQ(store_set_flags(s, z1, 0, STORE_F_NONSTORE), 0);                 /* (a secondary that became a primary's record: the counter follows the flag) */
  store_stats(s, &ss);
  CHECK_EQ(ss.zones_nonstore, 1);
  CHECK_EQ(store_set_flags(s, z1, STORE_F_NONSTORE, 0), 0);
  CHECK_EQ(store_delete(s, z2), 0);
  store_stats(s, &ss);
  CHECK_EQ(ss.zones_nonstore, 1);
  check_consistent(s, "nonstore 1");
  /* the counter is in the journal and the superblock: a reopen without a clean stop (the journal is replayed) and with one (the superblock) says the same */
  CHECK_EQ(store_close(s), 0);
  s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &ss);
    CHECK_EQ(ss.zones_nonstore, 1);
    check_consistent(s, "nonstore reopen");
    /* a writer that fails changes nothing and says why; the others work */
    uint32_t z = find_i(s, 0, 3);
    store_zone_t before, after;
    CHECK_EQ(store_zone_get(s, z, &before), 0);
    store_test_write_fault = fault_enospc_set_stamp;
    CHECK_EQ(store_set_stamp(s, z, 77, 88, STORE_F_STALE, 0), -ENOSPC);
    CHECK_EQ(store_set_flags(s, z, STORE_F_STALE, 0), 0);
    store_test_write_fault = NULL;
    CHECK_EQ(store_zone_get(s, z, &after), 0);
    CHECK(after.stamp_gen == before.stamp_gen && after.stamp_time == before.stamp_time && (after.flags & STORE_F_STALE));
    check_consistent(s, "fault");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* ================================================================================================================== */
/* 0.7 WP9 (S6): the cleaner, disk full, the scrub, nx, the open                                                        */
/* ================================================================================================================== */

/* the log lines of the store, kept */
typedef struct { int level; char msg[512]; } logline_t;
static logline_t g_logs[256];
static int g_nlogs;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;
static void log_cb(void *ctx, int level, const char *msg) {
  (void)ctx;
  pthread_mutex_lock(&g_log_mu);
  if (g_nlogs < 256) { g_logs[g_nlogs].level = level; snprintf(g_logs[g_nlogs].msg, sizeof(g_logs[g_nlogs].msg), "%s", msg); g_nlogs++; }
  pthread_mutex_unlock(&g_log_mu);
}
static int log_count(int level, const char *needle) {
  int n = 0;
  pthread_mutex_lock(&g_log_mu);
  for (int i = 0; i < g_nlogs; i++) if ((level < 0 || g_logs[i].level == level) && strstr(g_logs[i].msg, needle)) n++;
  pthread_mutex_unlock(&g_log_mu);
  return n;
}
static void log_clear(void) {
  pthread_mutex_lock(&g_log_mu);
  g_nlogs = 0;
  pthread_mutex_unlock(&g_log_mu);
}

static int count_files(const tdir_t *d, const char *prefix) {
  int n = 0;
  DIR *dp = opendir(d->path);
  if (!dp) return -1;
  struct dirent *de;
  while ((de = readdir(dp)) != NULL) if (strncmp(de->d_name, prefix, strlen(prefix)) == 0) n++;
  closedir(dp);
  return n;
}
static bool file_exists(const tdir_t *d, const char *name) {
  char p[700];
  struct stat st;
  fpath(d, name, p, sizeof(p));
  return stat(p, &st) == 0;
}
/* what the directory occupies on disk (blocks), the base of the "disk" the space tests make up */
static const char *g_fake_dir;
static int64_t g_fake_cap;
static int64_t dir_usage(const char *path) {
  int64_t used = 0;
  DIR *dp = opendir(path);
  if (!dp) return 0;
  struct dirent *de;
  while ((de = readdir(dp)) != NULL) {
    if (de->d_name[0] == '.') continue;
    char p[1100];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", path, de->d_name);
    if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) used += (int64_t)st.st_size;      /* (the logical size: on ZFS st_blocks lags behind the writes until the transaction group is synced, and compression shrinks it; the sparse files of the store have a constant size that the base cancels) */
  }
  closedir(dp);
  return used;
}
static int64_t fake_fs_free(void) {
  int64_t f = g_fake_cap - dir_usage(g_fake_dir);
  return f < 0 ? 0 : f;
}

static void cmp_zone_fields(const store_zone_t *a, const store_zone_t *b, const char *what) {
  bool ok = a->zid == b->zid && a->state == b->state && a->klen == b->klen && a->view == b->view && a->flags == b->flags && a->source == b->source && a->img_len == b->img_len &&
            a->serial == b->serial && a->settings == b->settings && a->source_id == b->source_id && a->stamp_gen == b->stamp_gen && a->stamp_time == b->stamp_time &&
            memcmp(a->digest, b->digest, STORE_DIGEST_LEN) == 0 && strcmp(a->name, b->name) == 0;
  if (!ok) printf("  zone %s: fields differ (%s)\n", a->name, what);
  CHECK(ok);
}

/* a store with `n` zones, most of them replaced a few times and some deleted: the early segments are mostly dead.  ver[i] = the version a zone has now (0 = deleted). */
static void fill_dead(store_t *s, uint32_t n, uint64_t *ver) {
  for (uint32_t i = 0; i < n; i++) { CHECK_EQ(put_i(s, 0, i, 1, NULL), 0); ver[i] = 1; }
  for (uint32_t i = 0; i < n; i++) if (i % 3 != 0) { CHECK_EQ(put_i(s, 0, i, 2, NULL), 0); ver[i] = 2; }
  for (uint32_t i = 0; i < n; i++) if (i % 5 != 0) { CHECK_EQ(put_i(s, 0, i, 3, NULL), 0); ver[i] = 3; }
  for (uint32_t i = 0; i < n; i++) {
    if (i % 11 == 0) { char nm[160]; name_of(i, nm, sizeof(nm)); CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0); ver[i] = 0; }
  }
}

typedef struct { store_zone_t z; uint8_t *img; size_t len; } snap_t;
static snap_t *snapshot_zones(store_t *s, uint32_t n, const uint64_t *ver) {
  snap_t *sn = calloc(n, sizeof(*sn));
  for (uint32_t i = 0; i < n; i++) {
    if (!ver[i]) continue;
    store_read_lock();
    uint32_t z = find_i(s, 0, i);
    store_img_t im;
    if (z != STORE_NONE && store_zone_get(s, z, &sn[i].z) == 0 && sn[i].z.state == STORE_STATE_STORED && store_image_read(s, z, &im) == 0) {
      sn[i].img = malloc(im.len);
      memcpy(sn[i].img, im.data, im.len);
      sn[i].len = im.len;
      store_img_release(s, &im);
    } else CHECK(0);
    store_read_unlock();
  }
  return sn;
}
/* every zone as it was: same zone id, same fields (not the place), same image bytes */
static void verify_snapshot(store_t *s, uint32_t n, const uint64_t *ver, const snap_t *sn, const char *what) {
  for (uint32_t i = 0; i < n; i++) {
    store_read_lock();
    uint32_t z = find_i(s, 0, i);
    if (!ver[i]) { CHECK_EQ(z, STORE_NONE); store_read_unlock(); continue; }
    store_zone_t zi;
    store_img_t im;
    CHECK(z == sn[i].z.zid);
    if (z != STORE_NONE && store_zone_get(s, z, &zi) == 0) {
      store_zone_t a = zi, b = sn[i].z;
      a.loc = b.loc = 0;
      cmp_zone_fields(&a, &b, what);
      if (store_image_read(s, z, &im) == 0) {
        CHECK(im.len == sn[i].len && memcmp(im.data, sn[i].img, im.len) == 0);
        store_img_release(s, &im);
      } else { printf("  zone %u: no image (%s)\n", i, what); CHECK(0); }
    } else { printf("  zone %u missing (%s)\n", i, what); CHECK(0); }
    store_read_unlock();
  }
}
static void free_snapshot(snap_t *sn, uint32_t n) {
  for (uint32_t i = 0; i < n; i++) free(sn[i].img);
  free(sn);
}

static void test_compact(int mode) {
  printf("[cleaner: %s mode]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "compact");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.seg_size = 64u << 10;
  o.compact_rate = UINT64_MAX;
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  enum { N = 500 };
  uint64_t ver[N];
  memset(ver, 0, sizeof(ver));
  fill_dead(s, N, ver);
  CHECK_EQ(store_commit(s), 0);
  store_stats_t st0, st1, st2;
  store_stats(s, &st0);
  int files0 = count_files(&d, "seg.");
  uint64_t dead0 = st0.seg_used_bytes - st0.seg_live_bytes;
  CHECK(st0.compact_candidates >= 3);
  CHECK(st0.compact_dead_bytes > st0.seg_used_bytes / 2);
  snap_t *sn = snapshot_zones(s, N, ver);
  store_compact_report_t rep, tot;
  memset(&tot, 0, sizeof(tot));
  for (int k = 0; k < 40; k++) {
    CHECK_EQ(store_compact(s, 0, true, &rep), 0);
    tot.moved_records += rep.moved_records;
    tot.moved_bytes += rep.moved_bytes;
    tot.segs_freed += rep.segs_freed;
    tot.bad_records += rep.bad_records;
    if (!rep.moved_records && !rep.segs_freed) break;
  }
  store_stats(s, &st1);
  int files1 = count_files(&d, "seg.");
  printf("  %" PRIu64 " records (%" PRIu64 " bytes) moved, %u segments freed: %d -> %d segment files, dead %" PRIu64 " -> %" PRIu64 " of %" PRIu64 " -> %" PRIu64 " bytes\n", tot.moved_records,
         tot.moved_bytes, tot.segs_freed, files0, files1, dead0, st1.seg_used_bytes - st1.seg_live_bytes, st0.seg_used_bytes, st1.seg_used_bytes);
  CHECK(tot.moved_records > 0);
  CHECK(tot.segs_freed >= 2);
  CHECK_EQ(tot.bad_records, 0);
  CHECK(files1 < files0);
  CHECK(st1.seg_used_bytes < st0.seg_used_bytes);
  CHECK((st1.seg_used_bytes - st1.seg_live_bytes) * 100 / st1.seg_used_bytes < dead0 * 100 / st0.seg_used_bytes);
  CHECK_EQ(st1.seg_live_bytes, st0.seg_live_bytes);                         /* what was live is live: moved, not changed */
  CHECK_EQ(st1.zones_stored, st0.zones_stored);
  CHECK(st1.compact_segs_freed == tot.segs_freed && st1.compact_moved_records == tot.moved_records);
  CHECK_EQ(st1.seg_draining, 0);
  CHECK(st1.seg_free_numbers >= 1);
  verify_snapshot(s, N, ver, sn, "after the cleaner");
  check_consistent(s, "after the cleaner");
  /* the freed segment numbers are used again: new zones do not raise the number of segments */
  for (uint32_t i = N; i < N + 150; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  store_stats(s, &st2);
  CHECK(st2.seg_count <= st1.seg_count);
  check_consistent(s, "numbers reused");
  CHECK_EQ(store_close(s), 0);
  /* a clean reopen, then a reopen of a store that was not closed */
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    verify_snapshot(s, N, ver, sn, "after a reopen");
    check_consistent(s, "reopen");
    store_stats(s, &st2);
    CHECK(!st2.recovery.rebuilt);
    CHECK_EQ(store_close(s), 0);
  }
  free_snapshot(sn, N);
  tdir_free(&d);
}

/* an image that an attached zone holds (MAP mode) pins its segment: the segment is not cleaned, not removed; one that is pinned after the cleaner has emptied it is not removed either */
static store_t *g_pin_store;
static store_img_t g_pin_img;
static uint32_t g_pin_seg, g_pin_zone;
static bool g_pin_taken;
static void pin_hook(store_t *s, uint32_t victim) {
  if (g_pin_taken) return;
  uint32_t cur = 0;
  store_zone_t zi;
  int r;
  store_read_lock();
  while ((r = store_iter(s, &cur, &zi)) != 0) {
    if (r < 0 || zi.state != STORE_STATE_STORED || (uint32_t)(zi.loc >> 36) != victim) continue;
    if (store_image_read(s, zi.zid, &g_pin_img) == 0) { g_pin_taken = true; g_pin_seg = victim; g_pin_zone = zi.zid; break; }
  }
  store_read_unlock();
}
static void test_compact_pinned(void) {
  printf("[cleaner: a segment that an attached image points into (MAP)]\n");
  tdir_t d;
  tdir_new(&d, "pin");
  store_opts_t o;
  small_opts(&o);
  o.mode = STORE_MODE_MAP;
  o.seg_size = 64u << 10;
  o.compact_rate = UINT64_MAX;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  enum { N = 400 };
  uint64_t ver[N];
  memset(ver, 0, sizeof(ver));
  fill_dead(s, N, ver);
  CHECK_EQ(store_commit(s), 0);
  snap_t *sn = snapshot_zones(s, N, ver);
  /* 1. zone 15 is held: it is never replaced (15 % 3 == 0 and % 5 == 0), so its record lies in the first segment, which is almost all dead.  That segment is not cleaned while it is held. */
  uint32_t z15 = find_i(s, 0, 15);
  store_zone_t zi;
  CHECK_EQ(store_zone_get(s, z15, &zi), 0);
  uint32_t seg15 = (uint32_t)(zi.loc >> 36);
  store_read_lock();
  store_img_t held;
  CHECK_EQ(store_image_read(s, z15, &held), 0);
  store_read_unlock();
  store_stats_t st;
  store_stats(s, &st);
  CHECK(st.seg_pinned >= 1);
  CHECK(st.compact_candidates >= 2);
  char nm[32];
  snprintf(nm, sizeof(nm), "seg.%u", seg15);
  for (int k = 0; k < 10; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
  CHECK(file_exists(&d, nm));
  CHECK_EQ(store_zone_get(s, z15, &zi), 0);
  CHECK_EQ((uint32_t)(zi.loc >> 36), seg15);                              /* not moved: its segment is pinned */
  CHECK(held.len == sn[15].len && memcmp(held.data, sn[15].img, held.len) == 0);
  verify_snapshot(s, N, ver, sn, "while a segment is pinned");
  check_consistent(s, "pinned");
  store_stats(s, &st);
  uint64_t freed_pinned = st.compact_segs_freed;
  store_img_release(s, &held);
  for (int k = 0; k < 10; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
  store_stats(s, &st);
  CHECK(st.compact_segs_freed > freed_pinned);
  CHECK_EQ(store_zone_get(s, z15, &zi), 0);
  CHECK((uint32_t)(zi.loc >> 36) != seg15);                               /* cleaned and removed once it was let go */
  verify_snapshot(s, N, ver, sn, "after the pin ended");
  /* 2. the image is taken while the cleaner works on the segment: the segment is empty afterwards, and stays until the image is released */
  for (uint32_t i = 0; i < N; i++) if (ver[i]) { CHECK_EQ(put_i(s, 0, i, 9, NULL), 0); ver[i] = 9; }       /* (everything is dead again: the next segments are mostly dead) */
  for (uint32_t i = 0; i < N; i++) if (ver[i] && i % 4 != 0) { CHECK_EQ(put_i(s, 0, i, 10, NULL), 0); ver[i] = 10; }
  free_snapshot(sn, N);
  sn = snapshot_zones(s, N, ver);
  g_pin_taken = false;
  g_pin_store = s;
  store_test_cleaner_step = pin_hook;
  store_stats(s, &st);
  uint64_t freed0 = st.compact_segs_freed;
  CHECK_EQ(store_compact(s, 0, true, NULL), 0);
  store_test_cleaner_step = NULL;
  CHECK(g_pin_taken);
  if (g_pin_taken) {
    char pn[32];
    snprintf(pn, sizeof(pn), "seg.%u", g_pin_seg);
    store_stats(s, &st);
    CHECK(st.compact_moved_records > 0);
    for (int k = 0; k < 5; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
    CHECK(file_exists(&d, pn));                                          /* emptied, and still there: the image is held */
    store_stats(s, &st);
    CHECK(st.seg_draining >= 1);
    CHECK(st.seg_pinned >= 1);
    CHECK(st.compact_pinned_skips >= 1);
    uint64_t freed_before_release = st.compact_segs_freed;
    uint32_t zz = g_pin_zone;
    const uint8_t *before = g_pin_img.data;
    CHECK(((uintptr_t)before % STORE_IMAGE_ALIGN) == 0);
    store_zone_t cz;
    CHECK_EQ(store_zone_get(s, zz, &cz), 0);
    CHECK((uint32_t)(cz.loc >> 36) != g_pin_seg);                         /* the zone itself is at another place now */
    uint64_t v = 0;
    CHECK(img_ok(g_pin_img.data, g_pin_img.len, (uint32_t)(((const uint32_t *)g_pin_img.data)[0]), &v));     /* the held bytes are intact */
    store_img_release(s, &g_pin_img);
    for (int k = 0; k < 5; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
    store_stats(s, &st);
    CHECK(st.compact_segs_freed > freed_before_release);
    CHECK(st.compact_segs_freed > freed0);
    CHECK_EQ(st.seg_draining, 0);
  }
  verify_snapshot(s, N, ver, sn, "after the pinned segment was removed");
  check_consistent(s, "pinned 2");
  free_snapshot(sn, N);
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* a store whose zones are all replaced again and again has one big open segment that is almost all dead: it is closed and cleaned (a segment of 8 MiB, 200 zones, 150 rounds) */
static void test_compact_open_segment(void) {
  printf("[cleaner: the open segment is the dead one]\n");
  tdir_t d;
  tdir_new(&d, "copen");
  store_opts_t o;
  small_opts(&o);
  o.seg_size = 8u << 20;
  o.compact_rate = UINT64_MAX;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (int round = 1; round <= 60; round++)
    for (uint32_t i = 0; i < 200; i++) CHECK_EQ(put_i(s, 0, i, (uint64_t)round, NULL), 0);
  store_stats_t st;
  store_stats(s, &st);
  CHECK(st.seg_count == 2 || st.seg_count == 1);
  uint64_t used0 = st.seg_used_bytes;
  CHECK(st.seg_used_bytes > 4u << 20);
  for (int k = 0; k < 4; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
  store_stats(s, &st);
  printf("  segments used %" PRIu64 " -> %" PRIu64 " bytes, live %" PRIu64 ", freed %" PRIu64 "\n", used0, st.seg_used_bytes, st.seg_live_bytes, st.compact_segs_freed);
  CHECK(st.seg_used_bytes < used0 / 4);
  CHECK(st.compact_segs_freed >= 1);
  for (uint32_t i = 0; i < 200; i++) CHECK(verify_i(s, 0, i, 60));
  check_consistent(s, "open segment cleaned");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* the tick does it by itself, at a rate */
static void test_compact_tick(void) {
  printf("[cleaner: by itself from the tick]\n");
  tdir_t d;
  tdir_new(&d, "ctick");
  store_opts_t o;
  small_opts(&o);
  o.seg_size = 64u << 10;
  o.scrub_interval_s = UINT32_MAX;
  o.checkpoint_interval_ms = 10;
  o.compact_rate = 256u << 10;                                          /* 256 KiB a second */
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  enum { N = 400 };
  uint64_t ver[N];
  memset(ver, 0, sizeof(ver));
  fill_dead(s, N, ver);
  store_stats_t st;
  store_stats(s, &st);
  uint64_t freed0 = st.compact_segs_freed, used0 = st.seg_used_bytes;
  uint64_t t0 = now_ms();
  while (now_ms() - t0 < 15000) {
    CHECK_EQ(store_tick(s), 0);
    store_stats(s, &st);
    if (st.compact_segs_freed >= freed0 + 3 && st.seg_draining == 0 && st.compact_candidates == 0) break;
    usleep(20000);
  }
  store_stats(s, &st);
  printf("  %" PRIu64 " segments freed in %" PRIu64 " ms by the tick, %" PRIu64 " bytes moved, used %" PRIu64 " -> %" PRIu64 "\n", st.compact_segs_freed - freed0, now_ms() - t0, st.compact_moved_bytes,
         used0, st.seg_used_bytes);
  CHECK(st.compact_segs_freed >= freed0 + 3);
  CHECK(st.seg_used_bytes < used0);
  for (uint32_t i = 0; i < N; i++) if (ver[i]) CHECK(verify_i(s, 0, i, ver[i]));
  check_consistent(s, "tick");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* long names: the space of deleted zones comes back */
static void test_nx_reclaim(void) {
  printf("[nx: the names of deleted zones are given back]\n");
  tdir_t d;
  tdir_new(&d, "nx");
  store_opts_t o;
  small_opts(&o);
  o.nx_reclaim_min = 4096;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  enum { N = 600 };
  uint32_t idx[N];
  for (uint32_t k = 0; k < N; k++) { idx[k] = 3 + 7 * k; CHECK_EQ(put_i(s, 0, idx[k], 1, NULL), 0); }       /* (every i % 7 == 3 has a name of 68 octets) */
  store_stats_t st0, st1;
  store_stats(s, &st0);
  CHECK_EQ(st0.nx_dead, 0);
  CHECK(st0.nx_used >= N * 60);
  for (uint32_t k = 0; k < N; k++) {
    if (k % 4 == 0) continue;
    char nm[160];
    name_of(idx[k], nm, sizeof(nm));
    CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);
  }
  store_stats(s, &st0);
  CHECK(st0.nx_dead * 2 > st0.nx_used);
  store_compact_report_t rep;
  CHECK_EQ(store_compact(s, 0, false, &rep), 0);
  store_stats(s, &st1);
  printf("  nx %" PRIu64 " used / %" PRIu64 " dead -> %" PRIu64 " / %" PRIu64 " (%" PRIu64 " bytes given back)\n", st0.nx_used, st0.nx_dead, st1.nx_used, st1.nx_dead, rep.nx_reclaimed);
  CHECK_EQ(st1.nx_dead, 0);
  CHECK_EQ(rep.nx_reclaimed, st0.nx_dead);
  CHECK_EQ(st1.nx_used, st0.nx_used - st0.nx_dead);
  CHECK_EQ(st1.nx_reclaims, 1);
  store_read_lock();
  for (uint32_t k = 0; k < N; k++) {
    if (k % 4 != 0) { CHECK_EQ(find_i(s, 0, idx[k]), STORE_NONE); continue; }
    uint32_t z = find_i(s, 0, idx[k]);
    store_zone_t zi;
    char nm[160];
    name_of(idx[k], nm, sizeof(nm));
    CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && strcmp(zi.name, nm) == 0);
  }
  store_read_unlock();
  for (uint32_t k = 0; k < N; k += 4) CHECK(verify_i(s, 0, idx[k], 1));
  check_consistent(s, "nx reclaimed");
  /* new long names go after the live ones; a reopen and a rebuild see the same */
  for (uint32_t k = 0; k < 50; k++) CHECK_EQ(put_i(s, 0, 3 + 7 * (N + k), 1, NULL), 0);
  check_consistent(s, "nx after new names");
  CHECK_EQ(store_close(s), 0);
  o.create = false;
  o.force_rebuild = true;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    for (uint32_t k = 0; k < N; k += 4) CHECK(verify_i(s, 0, idx[k], 1));
    check_consistent(s, "nx rebuilt");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* ---- the cleaner and eight readers, writers, attach / detach cycles (the TSan case) ---- */

typedef struct {
  store_t *s;
  _Atomic int stop;
  _Atomic long lookups, held, errors;
  _Atomic long errk[8];
  uint32_t n;
  int mode;
} cc_t;
static void *cc_reader(void *arg) {
  cc_t *c = arg;
  uint64_t rng = 0x1234567ull + (uint64_t)(uintptr_t)&rng;
  store_img_t held[4];
  uint32_t held_i[4];
  int nheld = 0;
  while (!atomic_load(&c->stop)) {
    rng = mix64(rng);
    uint32_t i = (uint32_t)(rng % c->n);
    store_read_lock();
    char nm[160];
    name_of(i, nm, sizeof(nm));
    uint32_t z = store_find(c->s, 0, nm, strlen(nm));
    if (z != STORE_NONE) {
      store_zone_t zi;
      int r = store_zone_get(c->s, z, &zi);
      if (r == 0) {
        if (strcmp(zi.name, nm) != 0 && zi.zid == z) { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[0], 1); }      /* (the zone id may have been reused for another zone: then find() would not have found it) */
        if (zi.state == STORE_STATE_STORED) {
          store_img_t im;
          r = store_image_read(c->s, z, &im);
          if (r == 0) {
            uint64_t v;
            if (!img_ok(im.data, im.len, i, &v)) { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[1], 1); }
            if (c->mode == STORE_MODE_MAP && (rng >> 40) % 8 == 0 && nheld < 4) { held[nheld] = im; held_i[nheld++] = i; atomic_fetch_add(&c->held, 1); }
            else store_img_release(c->s, &im);
          } else if (r == -EBADMSG) { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[2], 1); }
        }
      } else if (r == -EBADMSG) { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[3], 1); }
    }
    atomic_fetch_add(&c->lookups, 1);
    store_read_unlock();
    if ((rng >> 33) % 8 == 0) sched_yield();
    if (nheld && (rng >> 20) % 4 == 0) {              /* detach: the held image is still what it was, and is let go */
      nheld--;
      uint64_t v;
      if (!img_ok(held[nheld].data, held[nheld].len, held_i[nheld], &v)) { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[4], 1); }
      store_img_release(c->s, &held[nheld]);
    }
  }
  while (nheld--) store_img_release(c->s, &held[nheld]);
  return NULL;
}
static void *cc_cleaner(void *arg) {
  cc_t *c = arg;
  while (!atomic_load(&c->stop)) {
    if (store_compact(c->s, 64u << 10, true, NULL) != 0) { atomic_fetch_add(&c->errors, 1); atomic_fetch_add(&c->errk[5], 1); }
    (void)store_tick(c->s);
    usleep(2000);
  }
  return NULL;
}
static void test_compact_conc(int mode) {
  printf("[cleaner + readers + a writer + attach / detach, %s]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "cconc");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.seg_size = 64u << 10;
  o.compact_rate = UINT64_MAX;
  o.nx_reclaim_min = 2048;
  o.scrub_interval_s = UINT32_MAX;
  o.sync_policy = STORE_SYNC_NONE;
  o.checkpoint_interval_ms = 50;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  enum { N = 400 };
  static uint64_t ver[N];
  memset(ver, 0, sizeof(ver));
  for (uint32_t i = 0; i < N; i++) { CHECK_EQ(put_i(s, 0, i, 1, NULL), 0); ver[i] = 1; }
  cc_t c;
  memset(&c, 0, sizeof(c));
  c.s = s;
  c.n = N;
  c.mode = mode;
  pthread_t rt[4], ct;
  for (int t = 0; t < 4; t++) pthread_create(&rt[t], NULL, cc_reader, &c);
  pthread_create(&ct, NULL, cc_cleaner, &c);
  uint64_t t0 = now_ms(), rng = 77, k = 0, wops = UNDER_TSAN ? 4000 : 8000;
  while ((k < wops || now_ms() - t0 < 1500) && now_ms() - t0 < 90000) {          /* (a number of writes, not a time: on a loaded host the readers would starve the writer) */
    rng = mix64(rng);
    uint32_t i = (uint32_t)((rng >> 8) % N);
    uint32_t sel = (uint32_t)(rng % 100);
    k++;
    if (sel < 70) { CHECK_EQ(put_i(s, 0, i, k + 1, NULL), 0); ver[i] = k + 1; }
    else if (sel < 85) {
      char nm[160];
      name_of(i, nm, sizeof(nm));
      CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), ver[i] ? 0 : -ENOENT);
      ver[i] = 0;
    } else if (sel < 92) {
      char nm[160];
      name_of(i, nm, sizeof(nm));
      store_meta_t m = meta_of(i, k + 1);
      CHECK_EQ(store_set_known(s, 0, nm, strlen(nm), &m, NULL), 0);
      ver[i] = k + 1;                                                       /* (known: no image) */
    } else {
      (void)store_commit(s);
    }
  }
  atomic_store(&c.stop, 1);
  for (int t = 0; t < 4; t++) pthread_join(rt[t], NULL);
  pthread_join(ct, NULL);
  store_stats_t st;
  store_stats(s, &st);
  printf("  %ld lookups, %ld images held, %" PRIu64 " writes, cleaner: %" PRIu64 " records moved, %" PRIu64 " segments freed, nx %" PRIu64 " reclaims; errors %ld\n", atomic_load(&c.lookups),
         atomic_load(&c.held), k, st.compact_moved_records, st.compact_segs_freed, st.nx_reclaims, atomic_load(&c.errors));
  for (int e = 0; e < 8; e++) if (atomic_load(&c.errk[e])) printf("    error kind %d: %ld\n", e, atomic_load(&c.errk[e]));
  CHECK_EQ(atomic_load(&c.errors), 0);
  CHECK(st.compact_moved_records > 0);
  CHECK(st.compact_segs_freed > 0);
  CHECK(atomic_load(&c.lookups) > 1000);
  for (int e = 0; e < 5; e++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
  check_consistent(s, "cleaner under load");
  /* the writer's model is the truth (versions as written; a KNOWN zone was last written by set_known) */
  for (uint32_t i = 0; i < N; i++) {
    uint32_t z = find_i(s, 0, i);
    if (!ver[i]) { CHECK_EQ(z, STORE_NONE); continue; }
    store_zone_t zi;
    store_read_lock();
    CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.stamp_gen == ver[i]);
    if (z != STORE_NONE && zi.state == STORE_STATE_STORED) CHECK(verify_i(s, 0, i, ver[i]));
    store_read_unlock();
  }
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* ---- free space: the cleaner makes room, then the KNOWN fallback ---- */

static void test_space(int mode) {
  printf("[space: the reserve, the cleaner in a hurry, the fallback without an image, the way back (%s)]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "space");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.seg_size = 64u << 10;
  o.compact_rate = UINT64_MAX;
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  o.checkpoint_interval_ms = UINT32_MAX;
  o.journal_max_bytes = 64u << 10;                                      /* (the journal is part of what the disk holds: it is cut often) */
  log_clear();
  store_t *s = NULL;
  atomic_store(&store_test_no_flusher, true);                            /* (the free space is measured at the checkpoints: made by the writer after its call, in the order of the puts, not by the flusher at its own time) */
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  atomic_store(&store_test_no_flusher, false);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_checkpoint(s);
  int64_t base = dir_usage(d.path);
  g_fake_dir = d.path;
  g_fake_cap = base + (1800u << 10);
  store_test_fs_free = fake_fs_free;
  atomic_store(&store_test_jr_floor, 0);                                 /* (0.7: the journal's own floor, jr_floor(), is tested in test_jr_space(); here the thresholds of the reserve alone) */
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.reserve_bytes, 256u << 10);
  /* 1. every round replaces every zone: 300 zones of about 800 bytes, 240 KB a round; the "disk" holds 1800 KB less the reserve.  The cleaner makes the room each time, nothing is refused. */
  enum { M = 300 };
  uint64_t v = 0;
  for (int round = 1; round <= 30; round++) {
    for (uint32_t i = 0; i < M; i++) {
      v = (uint64_t)round;
      int r = put_i(s, 0, i, v, NULL);
      if (r != 0) { printf("  round %d zone %u: put %d\n", round, i, r); CHECK_EQ(r, 0); round = 99; break; }
    }
  }
  store_stats(s, &st);
  printf("  30 rounds of %d zones: %" PRIu64 " segments freed, %" PRIu64 " bytes moved, degraded puts %" PRIu64 ", ENOSPC events %" PRIu64 ", free now %" PRIu64 "\n", M, st.compact_segs_freed, st.compact_moved_bytes,
         st.degraded_puts, st.enospc_events, st.fs_free_bytes);
  CHECK(st.compact_segs_freed >= 5);
  CHECK_EQ(st.degraded_puts, 0);
  CHECK(st.enospc_events > 0);
  CHECK(!(st.state & STORE_ST_DEGRADED_NOSPC));
  CHECK(st.space_level < 2);                                             /* (not degraded; "low" is what the free space was at the last checkpoint, which runs on the flusher now: about 400 KB of 1800 KB free is low) */
  for (uint32_t i = 0; i < M; i++) CHECK(verify_i(s, 0, i, 30));
  check_consistent(s, "space 1");
  CHECK_EQ(log_count(3, "no room"), 0);
  /* 2. distinct zones: nothing to clean, the disk fills up: the zones are kept without an image (the put succeeds), the ERROR is said once */
  log_clear();
  uint32_t first_known = 0;
  uint32_t nz = 0;
  for (uint32_t i = 1000; i < 1000 + 3000; i++) {
    CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    nz++;
    store_zone_t zi;
    store_read_lock();
    uint32_t z = find_i(s, 0, i);
    if (z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.state == STORE_STATE_KNOWN && !first_known) first_known = i;
    store_read_unlock();
    if (first_known && i > first_known + 40) break;
  }
  store_stats(s, &st);
  printf("  the first zone kept without an image: %u (after %u puts); degraded puts %" PRIu64 ", free %" PRIu64 " of reserve %" PRIu64 "\n", first_known, nz, st.degraded_puts, st.fs_free_bytes, st.reserve_bytes);
  CHECK(first_known != 0);
  CHECK(st.degraded_puts >= 20);
  CHECK(st.state & STORE_ST_DEGRADED_NOSPC);
  CHECK_EQ(st.space_level, 2);
  CHECK(st.degraded_since_unix != 0);
  CHECK_EQ(log_count(3, "no room for zone images"), 1);                    /* once a minute */
  /* the zones before it are stored and served; every zone after it has its record (name, version), without an image or, when room came back meanwhile, with its image whole.  (Room
   * can come back between two puts: the journal files that a checkpoint cut are deleted, and the estimate of the free space is read again after a second or a megabyte, so on a
   * slow machine a later zone may fit again: what must not happen is a record with a wrong version or an image that is not the zone's.) */
  for (uint32_t i = 1000; i < first_known; i++) CHECK(verify_i(s, 0, i, 1));
  unsigned after_known = 0;
  for (uint32_t i = first_known; i < first_known + 40; i++) {
    store_zone_t zi;
    uint32_t z = find_i(s, 0, i);
    const bool rec = z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.serial == 1 && zi.stamp_gen == 1;
    CHECK(rec && ((zi.state == STORE_STATE_KNOWN && zi.img_len == 0) || (zi.state == STORE_STATE_STORED && verify_i(s, 0, i, 1))));
    after_known += rec && zi.state == STORE_STATE_KNOWN;
  }
  CHECK(after_known >= 20);                                               /* (most of them: the disk stays full) */
  /* a changed zone that is stored loses its image (its old record is released) and gets the new version as a record */
  store_stats_t before;
  store_stats(s, &before);
  CHECK_EQ(put_i(s, 0, 1005, 7, NULL), 0);
  {
    store_zone_t zi;
    uint32_t z = find_i(s, 0, 1005);
    CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.state == STORE_STATE_KNOWN && zi.stamp_gen == 7 && zi.serial == 7);
  }
  store_stats(s, &st);
  CHECK(st.seg_live_bytes < before.seg_live_bytes);
  check_consistent(s, "space 2");
  /* the recorded versions survive a restart */
  CHECK_EQ(store_close(s), 0);
  store_test_fs_free = NULL;
  o.create = false;
  atomic_store(&store_test_no_flusher, true);
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  atomic_store(&store_test_no_flusher, false);
  if (!s) { tdir_free(&d); return; }
  g_fake_cap = dir_usage(d.path) + (int64_t)(256u << 10) / 2;           /* (the reopen starts a new journal, so the files are smaller now: the "disk" is made full again, half of the reserve free) */
  store_test_fs_free = fake_fs_free;
  check_consistent(s, "space reopen");
  {
    store_zone_t zi;
    uint32_t z = find_i(s, 0, first_known);
    CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.state == STORE_STATE_KNOWN);
  }
  /* the disk is still full: the first put of the new session is kept without an image (the checkpoint reads the free space; the new store would otherwise believe what it read at its open) */
  CHECK_EQ(store_checkpoint(s), 0);
  CHECK_EQ(put_i(s, 0, 5000, 1, NULL), 0);
  store_stats(s, &st);
  CHECK_EQ(st.degraded_puts, 1);
  CHECK(st.state & STORE_ST_DEGRADED_NOSPC);
  /* 3. the way back: zones are deleted (the room comes from the cleaner), then a zone is stored again and the state ends */
  log_clear();
  unsigned ndel = 0;
  for (uint32_t i = 1000; i < first_known; i++) {
    if (i % 4 == 0) continue;
    char nm[160];
    name_of(i, nm, sizeof(nm));
    CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);
    if (++ndel % 100 == 0) CHECK_EQ(store_checkpoint(s), 0);            /* (0.7: a delete's record needs room on the full disk too, and the journal is checked against the free
                                                                         * space before the record is taken: the checkpoints cut the journal files, as the flusher's would) */
  }
  for (int k = 0; k < 6; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
  CHECK_EQ(put_i(s, 0, first_known, 2, NULL), 0);
  store_stats(s, &st);
  CHECK(verify_i(s, 0, first_known, 2));
  CHECK(!(st.state & STORE_ST_DEGRADED_NOSPC));
  CHECK_EQ(st.space_level, 0);
  CHECK(log_count(6, "there is room again") >= 1);
  CHECK_EQ(st.degraded_since_unix, 0);
  check_consistent(s, "space 3");
  store_test_fs_free = NULL;
  atomic_store(&store_test_jr_floor, -1);
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

static _Atomic int g_fault_left;
static int fault_append(uint64_t reclen) {
  (void)reclen;
  return atomic_fetch_sub(&g_fault_left, 1) > 0 ? -ENOSPC : 0;
}
static void test_append_fault(void) {
  printf("[space: an append that fails at the write]\n");
  tdir_t d;
  tdir_new(&d, "afault");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  log_clear();
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  /* the write fails twice (the put and its retry after the cleaner): the zone is kept without an image */
  atomic_store(&g_fault_left, 2);
  store_test_append_fault = fault_append;
  CHECK_EQ(put_i(s, 0, 5, 2, NULL), 0);
  store_test_append_fault = NULL;
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.degraded_puts, 1);
  CHECK(st.state & STORE_ST_DEGRADED_NOSPC);
  store_zone_t zi;
  uint32_t z = find_i(s, 0, 5);
  CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.state == STORE_STATE_KNOWN && zi.stamp_gen == 2);
  CHECK(verify_i(s, 0, 6, 1));
  /* a delete or a flag does not end it; an image that is stored does */
  CHECK_EQ(store_set_flags(s, z, STORE_F_NOTIFY_DUE, 0), 0);
  store_stats(s, &st);
  CHECK(st.state & STORE_ST_DEGRADED_NOSPC);
  CHECK_EQ(put_i(s, 0, 5, 3, NULL), 0);
  store_stats(s, &st);
  CHECK(!(st.state & STORE_ST_DEGRADED_NOSPC));
  CHECK(verify_i(s, 0, 5, 3));
  /* one failure only: the cleaner has nothing to free, the retry works (the cleaner is tried again after a second) */
  usleep(1100000);
  atomic_store(&g_fault_left, 1);
  store_test_append_fault = fault_append;
  CHECK_EQ(put_i(s, 0, 7, 2, NULL), 0);
  store_test_append_fault = NULL;
  CHECK(verify_i(s, 0, 7, 2));
  store_stats(s, &st);
  CHECK_EQ(st.degraded_puts, 1);
  check_consistent(s, "append fault");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* 0.7 (planing_0.7.x_secondary_store.md 2.4): store_put_ex(STORE_PUT_NO_DEGRADE) and store_set_digest() */
static int fault_set_digest(const char *op, uint32_t zid) {
  (void)zid;
  return strcmp(op, "set_digest") == 0 ? -EIO : 0;
}
static int put_ex_i(store_t *s, uint16_t view, uint32_t i, uint64_t ver, unsigned fl, uint32_t *zid) {
  char nm[160];
  name_of(i, nm, sizeof(nm));
  size_t n = img_len(i, ver);
  uint8_t *img = malloc(n);
  img_fill(img, n, i, ver);
  store_meta_t m = meta_of(i, ver);
  m.source_id = 0;
  int r = store_put_ex(s, view, nm, strlen(nm), &m, img, n, fl, zid);
  free(img);
  return r;
}
static void test_xfr_writers(void) {
  printf("[0.7 secondaries: store_put_ex(NO_DEGRADE) keeps the old record on a full disk; store_set_digest() by name, serial-checked]\n");
  tdir_t d;
  tdir_new(&d, "xfrw");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  log_clear();
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_ex_i(s, 0, i, 1, STORE_PUT_NO_DEGRADE, NULL), 0);
  store_stats_t st0, st;
  store_stats(s, &st0);
  /* 1. the disk fills up between the free-space check and the write, twice (the put and its retry after the cleaner): -ENOSPC, the old record and its image stay, not degraded */
  atomic_store(&g_fault_left, 2);
  store_test_append_fault = fault_append;
  CHECK_EQ(put_ex_i(s, 0, 5, 2, STORE_PUT_NO_DEGRADE, NULL), -ENOSPC);
  store_test_append_fault = NULL;
  store_stats(s, &st);
  CHECK_EQ(st.degraded_puts, st0.degraded_puts);
  CHECK(st.enospc_events > st0.enospc_events);
  CHECK(st.space_level < 2);
  CHECK(!(st.state & STORE_ST_DEGRADED_NOSPC) || st.degraded_since_unix == 0);
  CHECK(verify_i(s, 0, 5, 1));
  CHECK_EQ(st.zones_stored, 20);
  /* a new zone that does not fit is not made at all */
  usleep(1100000);                                                          /* (the cleaner is tried again after a second) */
  atomic_store(&g_fault_left, 2);
  store_test_append_fault = fault_append;
  CHECK_EQ(put_ex_i(s, 0, 50, 1, STORE_PUT_NO_DEGRADE, NULL), -ENOSPC);
  store_test_append_fault = NULL;
  CHECK(find_i(s, 0, 50) == STORE_NONE);
  check_consistent(s, "put_ex nospc");
  /* the same fault without the flag: the old behaviour (KNOWN, degraded) */
  usleep(1100000);
  atomic_store(&g_fault_left, 2);
  store_test_append_fault = fault_append;
  CHECK_EQ(put_ex_i(s, 0, 6, 2, 0, NULL), 0);
  store_test_append_fault = NULL;
  store_stats(s, &st);
  CHECK_EQ(st.degraded_puts, st0.degraded_puts + 1);
  CHECK_EQ(put_ex_i(s, 0, 6, 3, STORE_PUT_NO_DEGRADE, NULL), 0);         /* (room again: stored, the state ends) */
  CHECK(verify_i(s, 0, 6, 3));
  /* 2. store_set_digest(): digest, settings and flags change; the image, the stamp, the state stay */
  char nm[160];
  name_of(7, nm, sizeof(nm));
  uint8_t dg[STORE_DIGEST_LEN];
  for (int k = 0; k < STORE_DIGEST_LEN; k++) dg[k] = (uint8_t)(0xA0 + k);
  store_zone_t b, a;
  uint32_t z7 = find_i(s, 0, 7);
  CHECK_EQ(store_zone_get(s, z7, &b), 0);
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), b.serial, 4242, dg, STORE_F_XFR, 0), 0);
  CHECK_EQ(store_zone_get(s, z7, &a), 0);
  CHECK(memcmp(a.digest, dg, STORE_DIGEST_LEN) == 0 && a.settings == 4242 && (a.flags & STORE_F_XFR) && a.stamp_gen == b.stamp_gen && a.stamp_time == b.stamp_time && a.loc == b.loc &&
        a.state == STORE_STATE_STORED);
  CHECK(verify_i(s, 0, 7, 1));
  /* the name is folded */
  char up[160];
  snprintf(up, sizeof(up), "%s", nm);
  for (char *p = up; *p; p++) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
  dg[0] = 0x11;
  CHECK_EQ(store_set_digest(s, 0, up, strlen(up), b.serial, 4242, dg, 0, STORE_F_XFR), 0);
  CHECK_EQ(store_zone_get(s, z7, &a), 0);
  CHECK(a.digest[0] == 0x11 && !(a.flags & STORE_F_XFR));
  /* another serial: -ESTALE, nothing changed; no such zone: -ENOENT; a fault: nothing changed */
  dg[0] = 0x22;
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), b.serial + 1, 1, dg, 0, 0), -ESTALE);
  CHECK_EQ(store_set_digest(s, 0, "nosuch.example.test", 19, 1, 1, dg, 0, 0), -ENOENT);
  CHECK_EQ(store_set_digest(s, 3, nm, strlen(nm), 1, 1, dg, 0, 0), -EINVAL);
  store_test_write_fault = fault_set_digest;
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), b.serial, 1, dg, 0, 0), -EIO);
  store_test_write_fault = NULL;
  CHECK_EQ(store_zone_get(s, z7, &a), 0);
  CHECK(a.digest[0] == 0x11 && a.settings == 4242);
  /* the REJECTED_NEW counter follows the flags it sets */
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), b.serial, 4242, dg, STORE_F_REJECTED_NEW, 0), 0);
  store_stats(s, &st);
  CHECK_EQ(st.zones_rejected, 1);
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), b.serial, 4242, dg, 0, STORE_F_REJECTED_NEW), 0);
  check_consistent(s, "set_digest");
  /* 3. M3: a zone id kept from a lookup, the zone deleted, the id given to another zone: a set_digest by the old name finds nothing and does not touch the other zone */
  uint32_t z9 = find_i(s, 0, 9);
  CHECK_EQ(store_delete(s, z9), 0);
  for (int k = 0; k < 200 && find_i(s, 0, 9) == STORE_NONE; k++) {          /* (the id comes back after the grace period of the delete) */
    uint32_t nz = STORE_NONE;
    CHECK_EQ(put_ex_i(s, 0, 300 + (uint32_t)k, 1, 0, &nz), 0);
    if (nz == z9) break;
    usleep(1000);
  }
  store_zone_t o9;
  const bool reused = store_zone_get(s, z9, &o9) == 0 && o9.state != STORE_STATE_FREE;
  CHECK(reused);
  name_of(9, nm, sizeof(nm));
  dg[0] = 0x33;
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), 1, 7, dg, STORE_F_XFR, 0), -ENOENT);
  store_zone_t o9b;
  CHECK_EQ(store_zone_get(s, z9, &o9b), 0);
  CHECK(reused && memcmp(o9b.digest, o9.digest, STORE_DIGEST_LEN) == 0 && o9b.settings == o9.settings && o9b.flags == o9.flags);
  /* 4. replay: the digest is in the journal (a reopen without a clean stop) */
  name_of(7, nm, sizeof(nm));
  dg[0] = 0x44;
  CHECK_EQ(store_set_digest(s, 0, nm, strlen(nm), b.serial, 99, dg, STORE_F_XFR, 0), 0);
  CHECK_EQ(store_commit(s), 0);
  check_consistent(s, "set_digest 2");
  CHECK_EQ(store_close(s), 0);
  s = NULL;
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK_EQ(store_zone_get(s, find_i(s, 0, 7), &a), 0);
    CHECK(a.digest[0] == 0x44 && a.settings == 99 && (a.flags & STORE_F_XFR));
    CHECK(verify_i(s, 0, 7, 1));
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
  /* 5. kill -9 at every crash point of a store_set_digest() and a store_put_ex(): after the replay the record is the old one or the new one, whole */
  int runs = 0, olds = 0, news = 0, bad = 0;
  for (int which = 0; which < 2; which++) {
    for (long c = 1; c < 200 && !bad; c++) {
      tdir_t kd;
      tdir_new(&kd, "xfrk");
      store_opts_t ko;
      small_opts(&ko);
      ko.sync_policy = STORE_SYNC_EVERY;
      fflush(stdout);
      pid_t pid = fork();
      if (pid == 0) {
        store_t *ks = NULL;
        if (store_open(kd.fd, &ko, &ks) != 0) _exit(3);
        store_view_add(ks, "default");
        if (put_ex_i(ks, 0, 1, 1, STORE_PUT_NO_DEGRADE, NULL) != 0) _exit(4);
        char kn[160];
        name_of(1, kn, sizeof(kn));
        uint8_t kdg[STORE_DIGEST_LEN];
        memset(kdg, 0x5A, sizeof(kdg));
        store_test_crash_countdown = c;
        int r = which == 0 ? store_set_digest(ks, 0, kn, strlen(kn), 1, 77, kdg, STORE_F_XFR, 0) : put_ex_i(ks, 0, 1, 2, STORE_PUT_NO_DEGRADE, NULL);
        store_test_crash_countdown = 0;
        _exit(r == 0 ? 0 : 5);
      }
      int stt = 0;
      waitpid(pid, &stt, 0);
      const bool killed = WIFSIGNALED(stt);
      if (!killed) CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
      ko.create = false;
      store_t *ks = NULL;
      CHECK_EQ(store_open(kd.fd, &ko, &ks), 0);
      if (ks) {
        store_zone_t kz;
        const uint32_t z = find_i(ks, 0, 1);
        const bool got = z != STORE_NONE && store_zone_get(ks, z, &kz) == 0;
        if (!got) bad++;
        else if (which == 0) {
          const bool isnew = kz.digest[0] == 0x5A && kz.settings == 77 && (kz.flags & STORE_F_XFR);
          const bool isold = kz.digest[0] == (uint8_t)1 && kz.settings == 1 % 100 && !(kz.flags & STORE_F_XFR);
          if (!(isnew || isold) || !verify_i(ks, 0, 1, 1)) bad++;
          if (isnew) news++; else olds++;
        } else {
          if (verify_i(ks, 0, 1, 2)) news++;
          else if (verify_i(ks, 0, 1, 1)) olds++;
          else bad++;
        }
        check_consistent(ks, "xfr kill");
        CHECK_EQ(store_close(ks), 0);
      }
      tdir_free(&kd);
      runs++;
      if (!killed) break;
    }
  }
  printf("  kill -9 at each crash point (set_digest, put_ex): %d runs, %d old, %d new\n", runs, olds, news);
  CHECK_EQ(bad, 0);
  CHECK(olds > 0 && news > 0);
}

/* a file system that really is small: KARIDNS_STORE_SMALLFS names a directory on one (a quota dataset, a tmpfs of a few megabytes) */
static void test_smallfs(const char *base) {
  printf("[space: a real small file system (%s)]\n", base);
  tdir_t d;
  snprintf(d.path, sizeof(d.path), "%s/smallfs.%d", base, (int)getpid());
  rm_rf(d.path);
  if (mkdir(d.path, 0700) != 0) { perror("mkdir smallfs"); CHECK(0); return; }
  d.fd = open(d.path, O_RDONLY | O_DIRECTORY);
  store_opts_t o;
  small_opts(&o);
  o.mode = STORE_MODE_AUTO;                                               /* (copy on ZFS) */
  o.seg_size = (uint64_t)(getenv("KARIDNS_STORE_SMALLFS_SEG") ? atoi(getenv("KARIDNS_STORE_SMALLFS_SEG")) : 1) << 20;       /* (MiB: the reserve is half of it) */
  o.compact_rate = UINT64_MAX;
  o.scrub_interval_s = UINT32_MAX;
  o.log = log_cb;
  o.checkpoint_interval_ms = 3000;
  log_clear();
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_stats_t st;
  store_stats(s, &st);
  printf("  file system: %s, %" PRIu64 " bytes, %" PRIu64 " free, mode %s, reserve %" PRIu64 "\n", st.fstype, st.fs_total_bytes, st.fs_free_bytes, st.mode == STORE_MODE_MAP ? "map" : "copy", st.reserve_bytes);
  /* replace the same zones again and again: the cleaner keeps up (the disk is a few times the zones) */
  enum { M = 1500 };
  uint64_t round_fail = 0;
  for (int round = 1; round <= (getenv("KARIDNS_STORE_SMALLFS_ROUNDS") ? atoi(getenv("KARIDNS_STORE_SMALLFS_ROUNDS")) : 40); round++)
    for (uint32_t i = 0; i < M; i++) {
      int r = put_i(s, 0, i, (uint64_t)round, NULL);
      if (r != 0) round_fail++;
    }
  store_stats(s, &st);
  printf("  rounds: %" PRIu64 " puts refused, %" PRIu64 " ENOSPC events, %" PRIu64 " degraded, %" PRIu64 " segments freed, free %" PRIu64 "\n", round_fail, st.enospc_events, st.degraded_puts, st.compact_segs_freed,
         st.fs_free_bytes);
  CHECK_EQ(round_fail, 0);
  CHECK_EQ(st.degraded_puts, 0);                                          /* the cleaner makes the room: nothing is kept without an image */
  CHECK(st.compact_segs_freed >= 1);
  /* distinct zones until the disk is full */
  uint32_t i = 100000, first_known = 0;
  for (; i < 100000 + 200000; i++) {
    int r = put_i(s, 0, i, 1, NULL);
    if (r != 0) { printf("  put of a new zone: %d\n", r); break; }
    store_stats(s, &st);
    if (st.degraded_puts >= 20) break;
    if ((i & 1023) == 0) { store_stats(s, &st); if (st.degraded_puts && !first_known) first_known = i; if (g_verbose) printf("    %u zones, free %" PRIu64 ", degraded %" PRIu64 "\n", i - 100000, st.fs_free_bytes, st.degraded_puts); }
  }
  store_stats(s, &st);
  printf("  full after %u distinct zones: degraded puts %" PRIu64 ", ENOSPC %" PRIu64 ", free %" PRIu64 ", state %s, store %" PRIu64 " bytes\n", i - 100000, st.degraded_puts, st.enospc_events, st.fs_free_bytes,
         st.space_level == 2 ? "degraded" : "ok", st.store_bytes);
  CHECK(st.degraded_puts >= 20);
  CHECK(st.state & STORE_ST_DEGRADED_NOSPC);
  CHECK(log_count(3, "no room for zone images") >= 1);
  /* still consistent, still serving; delete half, clean, store again */
  check_consistent(s, "smallfs full");
  uint32_t last = i;
  for (uint32_t k = 100000; k < last; k += 2) {
    char nm[160];
    name_of(k, nm, sizeof(nm));
    (void)store_delete_name(s, 0, nm, strlen(nm));
  }
  bool back = false;
  for (int tries = 0; tries < 60 && !back; tries++) {         /* (a file system gives the space of a removed file back after a moment: ZFS at the end of its transaction group) */
    for (int k = 0; k < 4; k++) CHECK_EQ(store_compact(s, 0, true, NULL), 0);
    int r = put_i(s, 0, 4000000, 1 + (uint64_t)tries, NULL);
    CHECK_EQ(r, 0);
    back = verify_i(s, 0, 4000000, 1 + (uint64_t)tries);
    if (!back) usleep(500000);
  }
  CHECK(back);
  store_stats(s, &st);
  CHECK(!(st.state & STORE_ST_DEGRADED_NOSPC));
  printf("  after deleting half and cleaning: free %" PRIu64 ", state ok, %" PRIu64 " segments freed in all\n", st.fs_free_bytes, st.compact_segs_freed);
  check_consistent(s, "smallfs back");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* ---- the scrub ---- */

static int scrub_validate(const void *img, size_t len, char *why, size_t n) {
  uint32_t i;
  if (len < 4) return -1;
  memcpy(&i, img, 4);
  if (i == 7) { snprintf(why, n, "zone 7 is refused by the test"); return -1; }
  return 0;
}
static void test_scrub(int mode) {
  printf("[scrub: damaged image, structure check, damaged cell, index that does not lead to its zone (%s)]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t d;
  tdir_new(&d, "scrub");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.scrub_interval_s = UINT32_MAX;
  o.validate = scrub_validate;
  o.log = log_cb;
  log_clear();
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  enum { N = 120 };
  for (uint32_t i = 0; i < N; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  CHECK_EQ(store_commit(s), 0);
  store_scrub_report_t rep;
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(rep.zones, N);
  CHECK_EQ(rep.bad_cells, 0);
  CHECK_EQ(rep.bad_index, 0);
  CHECK_EQ(rep.images, N);                                              /* every zone is read */
  CHECK_EQ(rep.bad_images, 1);                                          /* zone 7: the structure check of the test refuses it */
  {
    store_zone_t zi;
    uint32_t z = find_i(s, 0, 7);
    CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.state == STORE_STATE_KNOWN && zi.stamp_gen == 1 && zi.serial == 1 && zi.source_id == 8);
  }
  CHECK_EQ(log_count(4, "zone '"), 1);
  /* a byte of an image flips */
  store_zone_t zi;
  uint32_t za = find_i(s, 0, 20);
  CHECK_EQ(store_zone_get(s, za, &zi), 0);
  char p[700], nm[32];
  snprintf(nm, sizeof(nm), "seg.%u", (unsigned)(zi.loc >> 36));
  fpath(&d, nm, p, sizeof(p));
  flip_byte(p, (off_t)((zi.loc & ((1ull << 36) - 1)) * 64 + 64 + 32 + 21));
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(rep.bad_images, 1);                                          /* (zone 7 is a KNOWN zone now: no image to refuse) -> only zone 20 */
  CHECK_EQ(find_i(s, 0, 20) != STORE_NONE, 1);
  CHECK(store_zone_get(s, find_i(s, 0, 20), &zi) == 0 && zi.state == STORE_STATE_KNOWN);
  CHECK(verify_i(s, 0, 21, 1));
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.scrub_passes, 2);
  CHECK_EQ(st.scrub_bad_images, 2);
  check_consistent(s, "scrub images");
  /* a damaged cell: the repair at the end of the pass drops the zone */
  uint32_t zc = find_i(s, 0, 30);
  fpath(&d, "zt.1", p, sizeof(p));
  mem_flip(s, 0, (uint64_t)zc * 64 + 9);
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(rep.bad_cells, 1);
  CHECK(rep.repaired);
  CHECK_EQ(find_i(s, 0, 30), STORE_NONE);
  CHECK(verify_i(s, 0, 31, 1));
  check_consistent(s, "scrub cell");
  /* an index entry that does not lead to its zone: the slot is a tombstone (the zone cannot be found by name) */
  store_stats(s, &st);
  uint32_t zx = find_i(s, 0, 40);
  bool hit = false;
  for (uint64_t k = 0; k < st.ix_slots && !hit; k++) {
    uint64_t v = store_test_peek(s, 3, k * 8);
    if ((uint32_t)v == zx) { store_test_poke(s, 3, k * 8, v | 0xffffffffull); hit = true; }
  }
  CHECK(hit);
  CHECK_EQ(find_i(s, 0, 40), STORE_NONE);
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(rep.bad_index, 1);
  CHECK(rep.repaired);
  CHECK(find_i(s, 0, 40) == zx);
  check_consistent(s, "scrub index");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

static void test_scrub_tick(void) {
  printf("[scrub: started by the interval, at a rate]\n");
  tdir_t d;
  tdir_new(&d, "scrubt");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = 1;
  o.scrub_rate = 128u << 10;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  const uint32_t N = store_long() ? 1500 : 800;                          /* (the rate is a bucket of 128 KiB a second: 800 zones are 4 s, enough for "not over in a moment" below) */
  for (uint32_t i = 0; i < N; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);          /* about a megabyte of images: 8 s at 128 KiB a second */
  store_stats_t st;
  uint64_t t0 = now_ms();
  bool saw_running = false;
  while (now_ms() - t0 < 30000) {
    (void)store_tick(s);
    store_stats(s, &st);
    if (st.scrub_running && st.scrub_progress_pct > 0 && st.scrub_progress_pct < 100) saw_running = true;
    if (st.scrub_passes >= 1) break;
    usleep(100000);
  }
  uint64_t took = now_ms() - t0;
  printf("  the first pass started after the interval and ended after %" PRIu64 " ms (%" PRIu64 " zones, %" PRIu64 " bytes read)\n", took, st.scrub_zones_checked, st.scrub_bytes_checked);
  CHECK(st.scrub_passes >= 1);
  CHECK(saw_running);
  CHECK(took >= 3000);                                                    /* the rate: a megabyte at 128 KiB a second is not over in a moment */
  CHECK_EQ(st.scrub_zones_checked, N);
  CHECK_EQ(st.scrub_bad_images + st.scrub_bad_cells + st.scrub_bad_index, 0);
  CHECK(st.scrub_last_end_unix >= st.scrub_last_start_unix && st.scrub_last_start_unix > 0);
  CHECK_EQ(store_close(s), 0);
  /* the time of the last pass is in the superblock: a reopen does not scrub at once */
  o.scrub_interval_s = 3600;
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    for (int k = 0; k < 5; k++) { (void)store_tick(s); usleep(20000); }
    store_stats(s, &st);
    CHECK_EQ(st.scrub_passes, 0);
    CHECK(!st.scrub_running);
    store_scrub_start(s);
    store_stats(s, &st);
    CHECK(st.scrub_running);
    store_scrub_stop(s);
    store_stats(s, &st);
    CHECK(!st.scrub_running);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* ---- ZFS: the record size of the dataset (the test is run by the integration test on datasets of 128K and 16K) ---- */

static void test_zfs_dir(const char *base, bool expect_warn, const char *what) {
  printf("[ZFS record size: %s (%s)]\n", what, base);
  tdir_t d;
  snprintf(d.path, sizeof(d.path), "%s/zfsrs.%d", base, (int)getpid());
  rm_rf(d.path);
  if (mkdir(d.path, 0700) != 0) { perror("mkdir"); CHECK(0); return; }
  d.fd = open(d.path, O_RDONLY | O_DIRECTORY);
  store_opts_t o;
  small_opts(&o);
  o.mode = STORE_MODE_AUTO;
  o.log = log_cb;
  o.scrub_interval_s = UINT32_MAX;
  log_clear();
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 50; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  store_stats_t st;
  store_stats(s, &st);
  printf("  file system %s, st_blksize %u, mode %s, warning %d\n", st.fstype, st.fs_blksize, st.mode == STORE_MODE_COPY ? "copy" : "map", (int)st.fs_recordsize_warn);
  CHECK(strcmp(st.fstype, "zfs") == 0);
  CHECK_EQ(st.mode, STORE_MODE_COPY);                                     /* auto: COPY on ZFS */
  CHECK_EQ((int)st.fs_recordsize_warn, expect_warn ? 1 : 0);
  CHECK_EQ(log_count(4, "record size"), expect_warn ? 1 : 0);
  if (expect_warn) CHECK(log_count(4, "recordsize=16K") == 1 && st.fs_blksize > 32768);
  else CHECK(st.fs_blksize <= 32768);
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* ---- the open: ix before the first answer, zt in the background; the journal cap ---- */

static _Atomic int g_ra_cnt;
static void ra_count_page(void) { atomic_fetch_add(&g_ra_cnt, 1); }

static void test_open_defaults(void) {
  printf("[open: the defaults, ix read before the answer, zt read-ahead]\n");
  tdir_t d;
  tdir_new(&d, "opendef");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 3000; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.journal_max_bytes, 100u << 20);                             /* the cap: about a second of replay */
  CHECK_EQ(store_close(s), 0);
  o.create = false;
  atomic_store(&g_ra_cnt, 0);
  store_test_ra_page = ra_count_page;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    for (int k = 0; k < 500 && (store_stats(s, &st), !st.zt_readahead_done); k++) usleep(2000);
    CHECK(st.zt_readahead_done);
    store_test_ra_page = NULL;
    CHECK(atomic_load(&g_ra_cnt) >= 2 * (3000 * 64) / 4096);                 /* (the read-ahead touches the pages of zc as it does those of zt) */
    printf("  open %" PRIu64 " us (ix read %" PRIu64 " us), zt read ahead %" PRIu64 " us\n", st.recovery.open_us, st.ix_read_us, st.zt_readahead_us);
    CHECK(verify_i(s, 0, 100, 1));
    CHECK_EQ(store_close(s), 0);                                           /* (joins the thread) */
  }
  o.no_readahead = true;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats(s, &st);
    CHECK(st.zt_readahead_done);
    CHECK_EQ(st.zt_readahead_us, 0);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* ---- err.ring and the NOTIFY-due scan ---- */

typedef struct { store_t *s; _Atomic int stop; _Atomic long bad; } errc_t;
static void *err_writer(void *a) {
  errc_t *c = a;
  char t[64];
  for (uint32_t k = 0; k < 20000; k++) { snprintf(t, sizeof(t), "text %u", k); store_err_put(c->s, k % 50, 0, k, t); }
  atomic_store(&c->stop, 1);
  return NULL;
}
static void *err_reader(void *a) {
  errc_t *c = a;
  while (!atomic_load(&c->stop)) {
    for (uint32_t z = 0; z < 50; z++) {
      store_err_t e;
      if (store_err_get(c->s, z, &e) == 0) {
        unsigned k = 0;
        if (e.zid != z || sscanf(e.text, "text %u", &k) != 1 || k % 50 != z || e.stamp_gen != k) atomic_fetch_add(&c->bad, 1);
      }
    }
  }
  return NULL;
}
static void test_err_ring(void) {
  printf("[err.ring and the NOTIFY-due scan]\n");
  tdir_t d;
  tdir_new(&d, "errring");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_err_t e;
  CHECK_EQ(store_err_get(s, 7, &e), -ENOENT);
  CHECK_EQ(store_err_put(s, 7, 0, 11, "the body of zone 7 was refused: a record is not valid"), 0);
  CHECK_EQ(store_err_put(s, 8, 0, 12, "another"), 0);
  CHECK_EQ(store_err_put(s, 7, 0, 13, "newer text for 7"), 0);
  CHECK_EQ(store_err_get(s, 7, &e), 0);
  CHECK(e.zid == 7 && e.stamp_gen == 13 && strcmp(e.text, "newer text for 7") == 0 && e.seq == 3 && e.time > 1000000000ull);
  CHECK_EQ(store_err_get(s, 8, &e), 0);
  CHECK(e.stamp_gen == 12 && strcmp(e.text, "another") == 0);
  char longt[400];
  memset(longt, 'x', sizeof(longt) - 1);
  longt[sizeof(longt) - 1] = 0;
  CHECK_EQ(store_err_put(s, 9, 0, 1, longt), 0);
  CHECK_EQ(store_err_get(s, 9, &e), 0);
  CHECK_EQ(strlen(e.text), STORE_ERR_TEXT - 1);                          /* cut, NUL-terminated */
  CHECK_EQ(store_err_total(s), 4);
  store_stats_t st;
  store_stats(s, &st);
  CHECK_EQ(st.err_total, 4);
  /* the ring wraps: after 70000 more texts the first ones are gone, the last 65536 are there */
  for (uint32_t k = 0; k < 70000; k++) { char t[40]; snprintf(t, sizeof(t), "w%u", k); CHECK_EQ(store_err_put(s, 1000 + k % 7, 0, k, t), 0); }
  CHECK_EQ(store_err_get(s, 8, &e), -ENOENT);
  CHECK_EQ(store_err_get(s, 1000 + 69999 % 7, &e), 0);
  CHECK(e.stamp_gen == 69999);
  CHECK_EQ(store_err_total(s), 70004);
  /* clear: the text of the zone is gone; a zone that has none costs no entry */
  uint64_t before_clear = store_err_total(s);
  CHECK_EQ(store_err_clear(s, 424242), 0);
  CHECK_EQ(store_err_total(s), before_clear);
  CHECK_EQ(store_err_put(s, 31, 0, 1, "text of 31"), 0);
  CHECK_EQ(store_err_get(s, 31, &e), 0);
  CHECK_EQ(store_err_clear(s, 31), 0);
  CHECK_EQ(store_err_get(s, 31, &e), -ENOENT);
  CHECK_EQ(store_err_put(s, 31, 0, 2, "again"), 0);
  CHECK_EQ(store_err_get(s, 31, &e), 0);
  CHECK(strcmp(e.text, "again") == 0 && e.stamp_gen == 2);
  CHECK_EQ(store_err_put(s, 32, 0, 3, "text of 32, cleared after the restart"), 0);
  CHECK_EQ(store_close(s), 0);
  /* it survives a clean close and an open */
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK(store_err_total(s) >= 70004);
    CHECK_EQ(store_err_get(s, 1000, &e), 0);
    CHECK_EQ(store_err_get(s, 32, &e), 0);
    CHECK_EQ(store_err_clear(s, 32), 0);                                  /* (the bitmap of zones with texts is made again at the open) */
    CHECK_EQ(store_err_get(s, 32, &e), -ENOENT);
    CHECK_EQ(store_err_put(s, 5, 0, 5, "after the reopen"), 0);
    CHECK_EQ(store_err_get(s, 5, &e), 0);
    CHECK(e.seq > 70005);
    /* a writer and readers at once (TSan); the zone ids the readers look at have no text of the earlier steps (a lookup is not slow any more: the readers see them at once) */
    CHECK_EQ(store_err_clear(s, 5), 0);
    CHECK_EQ(store_err_clear(s, 31), 0);
    errc_t c;
    memset(&c, 0, sizeof(c));
    c.s = s;
    pthread_t wt, rt[3];
    for (int i = 0; i < 3; i++) pthread_create(&rt[i], NULL, err_reader, &c);
    pthread_create(&wt, NULL, err_writer, &c);
    pthread_join(wt, NULL);
    for (int i = 0; i < 3; i++) pthread_join(rt[i], NULL);
    CHECK_EQ(atomic_load(&c.bad), 0);
    CHECK_EQ(store_close(s), 0);
  }
  /* a ring file that is not ours is made empty, not trusted */
  {
    char p[700];
    fpath(&d, "err.ring", p, sizeof(p));
    flip_byte(p, 3);
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (s) {
      CHECK_EQ(store_err_total(s), 0);
      CHECK_EQ(store_err_get(s, 5, &e), -ENOENT);
      CHECK_EQ(store_close(s), 0);
    }
  }
  /* NOTIFY due: a flag of zt, found by a scan, journaled (kill -9 keeps it) */
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    uint32_t zid[40];
    for (uint32_t i = 0; i < 40; i++) CHECK_EQ(put_i(s, 0, i, 1, &zid[i]), 0);
    for (uint32_t i = 0; i < 40; i += 5) CHECK_EQ(store_set_flags(s, zid[i], STORE_F_NOTIFY_DUE, 0), 0);
    uint32_t cur = 0, n = 0;
    store_zone_t zi;
    store_read_lock();
    while (store_flag_next(s, &cur, STORE_F_NOTIFY_DUE, &zi) == 1) { CHECK(zi.zid == zid[(n * 5)]); n++; }
    store_read_unlock();
    CHECK_EQ(n, 8);
    CHECK_EQ(store_set_flags(s, zid[10], 0, STORE_F_NOTIFY_DUE), 0);
    cur = 0;
    n = 0;
    store_read_lock();
    while (store_flag_next(s, &cur, STORE_F_NOTIFY_DUE, &zi) == 1) n++;
    store_read_unlock();
    CHECK_EQ(n, 7);
    CHECK_EQ(store_close(s), 0);
  }
  /* after an unclean stop */
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_opts_t c = o;
    store_t *x = NULL;
    if (store_open(d.fd, &c, &x) != 0) _exit(2);
    store_zone_t z2;
    uint32_t cur = 0, k = 0;
    store_read_lock();
    if (store_flag_next(x, &cur, STORE_F_NOTIFY_DUE, &z2) == 1) k = z2.zid;
    store_read_unlock();
    if (k == 0 && cur == 0) _exit(3);
    if (store_set_flags(x, k, 0, STORE_F_NOTIFY_DUE) != 0) _exit(4);
    _exit(0);
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    uint32_t cur = 0, n = 0;
    store_zone_t zi;
    store_read_lock();
    while (store_flag_next(s, &cur, STORE_F_NOTIFY_DUE, &zi) == 1) n++;
    store_read_unlock();
    CHECK_EQ(n, 6);                                                      /* 7, one cleared by the child that was killed without a close: the journal had it */
    check_consistent(s, "notify flag");
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* the clean open at a size: KARIDNS_STORE_OPENBENCH=<zones> (10M zones of 1.2 KB need 14 GB and some minutes) */
static void test_open_bench(uint64_t n) {
  printf("[open at %" PRIu64 " zones]\n", n);
  tdir_t d;
  tdir_new(&d, "openbench");
  store_opts_t o;
  small_opts(&o);
  o.seg_size = 256u << 20;
  o.scrub_interval_s = UINT32_MAX;
  o.expected_zones = n;
  o.max_zones = (uint32_t)(n + n / 8 + 1000);
  o.sync_policy = STORE_SYNC_NONE;
  o.journal_max_bytes = 256u << 20;
  o.checkpoint_interval_ms = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  uint64_t t0 = now_ms();
  uint8_t *img = malloc(1200);
  for (uint64_t i = 0; i < n; i++) {
    char nm[64];
    int nl = snprintf(nm, sizeof(nm), "z%09" PRIu64 ".example.test", i);
    store_meta_t m = meta_of((uint32_t)(i & 0xffffffffu), 1);
    m.source_id = (int64_t)i + 1;
    img_fill(img, 1100, (uint32_t)(i & 0xffffffffu), 1);
    if (store_put(s, 0, nm, (size_t)nl, &m, img, 1100, NULL) != 0) { CHECK(0); break; }
    if (i % 1000000 == 999999) { printf("  %" PRIu64 " zones in %" PRIu64 " s\n", i + 1, (now_ms() - t0) / 1000); fflush(stdout); }
  }
  free(img);
  printf("  filled in %" PRIu64 " s\n", (now_ms() - t0) / 1000);
  CHECK_EQ(store_close(s), 0);
  /* a cold cache: KARIDNS_STORE_OPENBENCH_EVICT=<GiB> writes a file that long (and removes it), which pushes the store out of the page cache (posix_fadvise does not on UFS) */
  if (getenv("KARIDNS_STORE_OPENBENCH_EVICT")) {
    uint64_t gib = strtoull(getenv("KARIDNS_STORE_OPENBENCH_EVICT"), NULL, 10);
    char ep[700];
    fpath(&d, "evict.bin", ep, sizeof(ep));
    int efd = open(ep, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    uint8_t *eb = malloc(1u << 20);
    if (efd >= 0 && eb) {
      for (size_t k = 0; k < (1u << 20); k += 8) { uint64_t x = mix64(k + 1); memcpy(eb + k, &x, 8); }
      uint64_t te = now_ms();
      for (uint64_t k = 0; k < gib * 1024; k++) { eb[0] = (uint8_t)k; if (write(efd, eb, 1u << 20) != (ssize_t)(1u << 20)) break; }
      fsync(efd);
      close(efd);
      printf("  %" PRIu64 " GiB written to push the store out of the page cache (%" PRIu64 " s)\n", gib, (now_ms() - te) / 1000);
    }
    free(eb);
    unlink(ep);
  }
  o.create = false;
  o.expected_zones = 0;
  for (int pass = 0; pass < 2; pass++) {
    uint64_t t1 = now_ms();
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    uint64_t opened = now_ms() - t1;
    if (!s) break;
    store_stats_t st;
    store_stats(s, &st);
    printf("  clean open (%s cache): %" PRIu64 " ms to the answer (open_us %" PRIu64 ", of it ix read %" PRIu64 " us)", pass ? "warm" : "first", opened, st.recovery.open_us, st.ix_read_us);
    for (int k = 0; k < 20000 && (store_stats(s, &st), !st.zt_readahead_done); k++) usleep(1000);
    printf(", zt read-ahead %" PRIu64 " ms in the background\n", st.zt_readahead_us / 1000);
    char nm[64];
    snprintf(nm, sizeof(nm), "z%09" PRIu64 ".example.test", n / 2);
    store_read_lock();
    CHECK(store_find(s, 0, nm, strlen(nm)) != STORE_NONE);
    store_read_unlock();
    CHECK_EQ(store_close(s), 0);
  }
  /* an unclean stop: a child opens the store, puts a zone and dies without closing; the open that follows replays the journal */
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_t *c = NULL;
    store_opts_t co = o;
    co.no_readahead = true;
    if (store_open(d.fd, &co, &c) != 0) _exit(3);
    for (uint32_t i = 0; i < 1000; i++) if (put_i(c, 0, 900000000u + i, 1, NULL) != 0) _exit(4);
    _exit(0);
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  uint64_t t2 = now_ms();
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    printf("  open after an unclean stop: %" PRIu64 " ms (replayed %" PRIu64 " records, rebuilt %d)\n", now_ms() - t2, st.recovery.records_replayed, (int)st.recovery.rebuilt);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* ---- the review of S5 + S6 (2026-11-15): the err.ring lookup is not a scan (M1), a text has the tag of its zone and a delete forgets it (L1), a zone of a damaged image is told to its owner (M2),
 *      the close waits for the read-ahead (L4) ---- */

static double mono_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void test_err_index(void) {
  printf("[err.ring: a lookup is a table, not a scan; the tag and the stamp of a text; a delete forgets the text]\n");
  tdir_t d;
  tdir_new(&d, "errix");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  o.no_readahead = true;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  store_err_t e;
  CHECK_EQ(store_err_put(s, 40, 0xABCDEF, 77, "tagged"), 0);
  CHECK_EQ(store_err_put(s, 41, 0x1FFFFFF, 78, "the tag has 24 bits"), 0);
  CHECK_EQ(store_err_get(s, 40, &e), 0);
  CHECK(e.tag == 0xABCDEF && e.stamp_gen == 77 && strcmp(e.text, "tagged") == 0);
  CHECK_EQ(store_err_get(s, 41, &e), 0);
  CHECK(e.tag == 0xFFFFFF);
  /* a ring of distinct zone ids that has wrapped: the lookups of zone ids that have no text, and of the oldest and the newest ones, are not scans (before: 65536 entries read for every miss) */
  enum { N = 70000 };
  for (uint32_t k = 0; k < N; k++) CHECK_EQ(store_err_put(s, 100000 + k, k & 0xFFFFFF, k, "x"), 0);
  double t0 = mono_s();
  long bad = 0;
  for (uint32_t i = 0; i < 20000; i++)
    if (store_err_get(s, 5000000 + i, &e) != -ENOENT) bad++;
  for (uint32_t k = N - 2000; k < N; k++)
    if (store_err_get(s, 100000 + k, &e) != 0 || e.stamp_gen != k || e.tag != (k & 0xFFFFFF)) bad++;
  double dt = mono_s() - t0;
  CHECK_EQ(bad, 0);
  printf("  22000 lookups: %.3f s\n", dt);
  CHECK(dt < 1.0);
  CHECK_EQ(store_err_get(s, 100000 + (N - 65536) - 1, &e), -ENOENT);                       /* (the ring wrapped over it) */
  CHECK_EQ(store_err_get(s, 100000 + (N - 65536), &e), 0);
  CHECK_EQ(store_err_get(s, 40, &e), -ENOENT);
  /* one zone id with many texts: the newest, and the others are not hidden by the chain */
  for (uint32_t k = 0; k < 3000; k++) { char t[32]; snprintf(t, sizeof(t), "t%u", k); CHECK_EQ(store_err_put(s, 7, 7, 900000 + k, t), 0); }
  CHECK_EQ(store_err_get(s, 7, &e), 0);
  CHECK(e.stamp_gen == 902999 && strcmp(e.text, "t2999") == 0);
  CHECK_EQ(store_err_get(s, 100000 + N - 1, &e), 0);
  /* a delete of the zone forgets its text: the id is reused, and the text must not show under the next zone that gets it */
  uint32_t zid = STORE_NONE, zid2 = STORE_NONE;
  CHECK_EQ(put_i(s, 0, 1, 1, &zid), 0);
  CHECK_EQ(store_err_put(s, zid, 5, 1, "the body of the zone was refused"), 0);
  CHECK_EQ(store_err_get(s, zid, &e), 0);
  CHECK_EQ(store_delete(s, zid), 0);
  CHECK_EQ(store_err_get(s, zid, &e), -ENOENT);                                            /* (before: the text stayed for the zone that got the id) */
  CHECK_EQ(put_i(s, 0, 2, 1, &zid2), 0);
  CHECK_EQ(store_err_get(s, zid2, &e), -ENOENT);
  CHECK_EQ(store_err_put(s, zid2, 6, 2, "text of the second zone"), 0);
  char nm[160];
  name_of(2, nm, sizeof(nm));
  CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);                                    /* (the other way to delete) */
  CHECK_EQ(store_err_get(s, zid2, &e), -ENOENT);
  CHECK_EQ(store_close(s), 0);
  /* the cleared state is in the file: the open makes the table from the ring, newest entry first wins */
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK_EQ(store_err_get(s, zid, &e), -ENOENT);
    CHECK_EQ(store_err_get(s, zid2, &e), -ENOENT);
    CHECK_EQ(store_err_get(s, 7, &e), 0);
    CHECK(e.stamp_gen == 902999 && e.tag == 7);
    CHECK_EQ(store_err_get(s, 100000 + N - 1, &e), 0);
    CHECK(e.stamp_gen == N - 1);
    CHECK_EQ(store_err_get(s, 100000 + (N - 65536) - 1, &e), -ENOENT);
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

static int g_bad_calls, g_bad_tries_ret;
static uint32_t g_bad_zid[64];
static store_t *g_bad_store;
static int bad_image_hook(uint32_t zid, void *ud) {
  (void)ud;
  if (g_bad_calls < 64) g_bad_zid[g_bad_calls] = zid;
  g_bad_calls++;
  (void)store_commit(g_bad_store);                      /* (the writer mutex: nothing of the store is held when the hook is called, or this would never return) */
  return g_bad_tries_ret > 0 ? (g_bad_tries_ret--, 1) : 0;
}

static void test_bad_image_hook(void) {
  printf("[a damaged image is told to the owner by the tick, with no lock held: the scrub and the cleaner]\n");
  tdir_t d;
  tdir_new(&d, "badimg");
  store_opts_t o;
  small_opts(&o);
  o.mode = STORE_MODE_MAP;
  o.scrub_interval_s = UINT32_MAX;
  o.no_readahead = true;
  o.bad_image = bad_image_hook;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  g_bad_store = s;
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 40; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  CHECK_EQ(store_commit(s), 0);
  store_zone_t zi;
  uint32_t za = find_i(s, 0, 20);
  CHECK_EQ(store_zone_get(s, za, &zi), 0);
  char p[700], nm[32];
  snprintf(nm, sizeof(nm), "seg.%u", (unsigned)(zi.loc >> 36));
  fpath(&d, nm, p, sizeof(p));
  flip_byte(p, (off_t)((zi.loc & ((1ull << 36) - 1)) * 64 + 64 + 32 + 21));
  g_bad_calls = 0;
  g_bad_tries_ret = 1;                                                     /* (the owner says "not now" once: the tick asks again) */
  store_scrub_report_t rep;
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(rep.bad_images, 1);
  CHECK_EQ(g_bad_calls, 1);
  CHECK(g_bad_zid[0] == za);
  CHECK(store_zone_get(s, za, &zi) == 0 && zi.state == STORE_STATE_KNOWN);
  CHECK_EQ(store_tick(s), 0);
  CHECK_EQ(g_bad_calls, 2);                                                /* (asked again) */
  CHECK(g_bad_zid[1] == za);
  CHECK_EQ(store_tick(s), 0);
  CHECK_EQ(g_bad_calls, 2);                                                /* (done: not asked again) */
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(g_bad_calls, 2);                                                /* (a KNOWN zone has no image to find damaged) */
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);

  /* the cleaner: a record that fails its checksum when it is moved makes the zone KNOWN, and the owner is told */
  tdir_new(&d, "badimgc");
  small_opts(&o);
  o.mode = STORE_MODE_MAP;
  o.seg_size = 64u << 10;
  o.compact_rate = UINT64_MAX;
  o.scrub_interval_s = UINT32_MAX;
  o.no_readahead = true;
  o.bad_image = bad_image_hook;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  g_bad_store = s;
  store_view_add(s, "default");
  enum { N = 500 };
  uint64_t ver[N];
  memset(ver, 0, sizeof(ver));
  fill_dead(s, N, ver);
  CHECK_EQ(store_commit(s), 0);
  uint32_t damaged[64], nd = 0;
  for (uint32_t i = 0; i < N && nd < 20; i++) {
    if (!ver[i] || i % 7 != 1) continue;
    uint32_t z = find_i(s, 0, i);
    if (z == STORE_NONE || store_zone_get(s, z, &zi) != 0 || zi.state != STORE_STATE_STORED) continue;
    snprintf(nm, sizeof(nm), "seg.%u", (unsigned)(zi.loc >> 36));
    fpath(&d, nm, p, sizeof(p));
    flip_byte(p, (off_t)((zi.loc & ((1ull << 36) - 1)) * 64 + 64 + 32 + 21));
    damaged[nd++] = z;
  }
  CHECK(nd >= 10);
  g_bad_calls = 0;
  g_bad_tries_ret = 0;
  store_compact_report_t crep, ctot;
  memset(&ctot, 0, sizeof(ctot));
  for (int k = 0; k < 40; k++) {
    CHECK_EQ(store_compact(s, 0, true, &crep), 0);
    ctot.bad_records += crep.bad_records;
    if (!crep.moved_records && !crep.segs_freed && !crep.bad_records) break;
  }
  CHECK(ctot.bad_records > 0);
  CHECK_EQ(g_bad_calls, (int)ctot.bad_records);                            /* (each zone the cleaner found damaged was handed over, once) */
  bool all_listed = true;
  for (int c = 0; c < g_bad_calls && c < 64; c++) {
    bool in = false;
    for (uint32_t k = 0; k < nd; k++) in = in || damaged[k] == g_bad_zid[c];
    all_listed = all_listed && in && store_zone_get(s, g_bad_zid[c], &zi) == 0 && zi.state == STORE_STATE_KNOWN;
  }
  CHECK(all_listed);
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

static _Atomic int g_ra_calls;
static void ra_slow_page(void) {
  atomic_fetch_add(&g_ra_calls, 1);
  usleep(300000);
}
static void test_readahead_close(void) {
  printf("[the close waits for the read-ahead thread, however slow a page is]\n");
  tdir_t d;
  tdir_new(&d, "ra");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  o.no_readahead = true;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  for (uint32_t i = 0; i < 1600; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);          /* (a table of 25 pages) */
  CHECK_EQ(store_close(s), 0);
  o.create = false;
  o.no_readahead = false;
  atomic_store(&g_ra_calls, 0);
  store_test_ra_page = ra_slow_page;                                                  /* (a page that waits for the disk: 0.3 s each, 25 of them) */
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    usleep(100000);
    double t0 = mono_s();
    CHECK_EQ(store_close(s), 0);                                                       /* (before: gave up after 5 s with the thread still running over the unmapped table; the stop flag was looked at every 1 MiB) */
    double dt = mono_s() - t0;
    const int at_close = atomic_load(&g_ra_calls);
    usleep(1000000);
    CHECK_EQ(atomic_load(&g_ra_calls), at_close);                                      /* (the thread is gone when the close returns) */
    printf("  close %.2f s, %d pages read\n", dt, at_close);
    CHECK(dt < 2.0 && at_close >= 1 && at_close < 25);
  }
  store_test_ra_page = NULL;
  tdir_free(&d);
}

/* ---- 0.7 fix 7 / 8: store_image_resident() and hot.list ---- */

/* mincore() says "resident" for a page that was written through a descriptor and has not been touched through the mapping only on file systems whose pages are the VM object's (UFS).  ZFS keeps them in the ARC: the
 * answer is "no" for them until they are touched, and the server uses COPY mode there (store-mode auto).  The checks that say "yes" are made where the file system can say it; those that say "no" always. */
static bool fs_reports_written_pages(const tdir_t *d) {
  struct statfs sfs;
  return fstatfs(d->fd, &sfs) != 0 || strcmp(sfs.f_fstypename, "zfs") != 0;
}

static bool resident_of(store_t *s, uint32_t zid) {
  store_zone_t z;
  store_read_lock();
  bool ok = store_zone_get(s, zid, &z) == 0 && store_image_resident(s, &z);
  store_read_unlock();
  return ok;
}

static void test_resident(int mode) {
  printf("[store_image_resident: %s mode]\n", mode == STORE_MODE_MAP ? "map" : "copy");
  tdir_t d;
  tdir_new(&d, "resident");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  uint32_t zid[40];
  for (uint32_t i = 0; i < 40; i++) CHECK_EQ(put_i(s, 0, i, 1, &zid[i]), 0);
  /* a record that was written is in the page cache (and its segment is open) in MAP mode; COPY mode never says yes (a read with pread can block) */
  const bool yes_ok = fs_reports_written_pages(&d);
  if (yes_ok || mode != STORE_MODE_MAP)
    for (uint32_t i = 0; i < 40; i += 7) CHECK_EQ(resident_of(s, zid[i]), mode == STORE_MODE_MAP);
  /* a zone with no image (known), and a zone id that is free, are not resident */
  {
    char nm[160];
    uint32_t kz = STORE_NONE;
    name_of(1, nm, sizeof(nm));
    store_meta_t m = meta_of(1, 2);
    CHECK_EQ(store_set_known(s, 0, nm, strlen(nm), &m, &kz), 0);
    CHECK(kz == zid[1]);
  }
  CHECK(!resident_of(s, zid[1]));
  {
    store_zone_t z;
    store_read_lock();
    CHECK_EQ(store_zone_get(s, zid[2], &z), 0);
    store_zone_t bad = z;
    bad.loc = 0;
    CHECK(!store_image_resident(s, &bad));                               /* (no record) */
    bad = z;
    bad.loc = (z.loc & ((1ull << 36) - 1)) | (7ull << 36);              /* (a segment that does not exist) */
    CHECK(!store_image_resident(s, &bad));
    bad = z;
    bad.loc = (z.loc & ((1ull << 36) - 1));                              /* (segment 0) */
    CHECK(!store_image_resident(s, &bad));
    bad = z;
    bad.img_len = 4u << 20;                                              /* (a record of many pages, or past the mapping) */
    CHECK(!store_image_resident(s, &bad));
    store_read_unlock();
  }
  CHECK_EQ(store_close(s), 0);
  /* after a reopen no segment is open: the answer is no until something (here the image read) opens it; then it is yes in MAP mode */
  o.create = false;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    CHECK(!resident_of(s, zid[2]));                                      /* (no segment is open yet) */
    store_open_segments(s);
    if (yes_ok || mode != STORE_MODE_MAP) CHECK_EQ(resident_of(s, zid[2]), mode == STORE_MODE_MAP);             /* (opened: the pages written before the close are in the page cache) */
    store_img_t im;
    store_read_lock();
    CHECK_EQ(store_image_read(s, zid[2], &im), 0);
    store_img_release(s, &im);
    store_read_unlock();
    if (yes_ok || mode != STORE_MODE_MAP) CHECK_EQ(resident_of(s, zid[2]), mode == STORE_MODE_MAP);
    if (mode == STORE_MODE_MAP) {
      /* the pages leave the page cache (as far as the system lets a test make it): the answer follows, whichever it is, and never crashes */
      store_zone_t z;
      store_read_lock();
      CHECK_EQ(store_zone_get(s, zid[2], &z), 0);
      store_read_unlock();
      char sp[700];
      fpath(&d, "seg.1", sp, sizeof(sp));
      int fd = open(sp, O_RDWR);
      if (fd >= 0) {
        (void)fsync(fd);
        (void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        close(fd);
      }
      (void)resident_of(s, zid[2]);
    }
    CHECK_EQ(store_close(s), 0);
  }
  tdir_free(&d);
}

/* 0.7 (Round 6): COPY mode reads a record through the reading thread's buffer (store_image_read()): images of a size that fits the first buffer, one that makes it grow, and one past the
 * largest buffer (read into its own buffer directly) read back the same, with the buffer and without it (store_test_rbuf_off), and from a thread that ends (its buffer is freed: ASan) */
typedef struct {
  store_t *s;
  const uint32_t *zid;
  const size_t *len;
  int n, bad;
} rbuf_arg_t;
static int rbuf_read_all(store_t *s, const uint32_t *zid, const size_t *len, int n) {
  int bad = 0;
  for (int k = 0; k < n; k++) {
    store_img_t im;
    store_read_lock();
    const int r = store_image_read(s, zid[k], &im);
    store_read_unlock();
    if (r != 0) {
      bad++;
      continue;
    }
    const uint8_t *p = im.data;
    bool same = im.len == len[k];
    for (size_t o = 0; same && o < len[k]; o++) same = p[o] == (uint8_t)(o * 7u + (size_t)k);
    bad += !same;
    store_img_release(s, &im);
  }
  return bad;
}
static void *rbuf_thread(void *arg) {
  rbuf_arg_t *a = arg;
  a->bad = rbuf_read_all(a->s, a->zid, a->len, a->n);
  return NULL;
}
static void test_rbuf(void) {
  printf("[COPY reads through the thread's buffer]\n");
  tdir_t d;
  tdir_new(&d, "rbuf");
  store_opts_t o;
  small_opts(&o);
  o.mode = STORE_MODE_COPY;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (!s) { tdir_free(&d); return; }
  store_view_add(s, "default");
  const size_t len[4] = { 1000, 100000, 300000, 1500000 };      /* (fits 64 KiB; grows it to 128 KiB; grows it again; past 1 MiB: direct) */
  uint32_t zid[4];
  for (int k = 0; k < 4; k++) {
    uint8_t *img = malloc(len[k]);
    for (size_t x = 0; x < len[k]; x++) img[x] = (uint8_t)(x * 7u + (size_t)k);
    char nm[32];
    snprintf(nm, sizeof(nm), "rbuf%d.example", k);
    store_meta_t m = meta_of((uint32_t)k, 1);
    CHECK_EQ(store_put(s, 0, nm, strlen(nm), &m, img, len[k], &zid[k]), 0);
    free(img);
  }
  CHECK_EQ(store_commit(s), 0);
  CHECK_EQ(rbuf_read_all(s, zid, len, 4), 0);
  CHECK_EQ(rbuf_read_all(s, zid, len, 4), 0);                    /* (the buffer reused) */
  atomic_store(&store_test_rbuf_off, 1);
  CHECK_EQ(rbuf_read_all(s, zid, len, 4), 0);
  atomic_store(&store_test_rbuf_off, 0);
  rbuf_arg_t a = { s, zid, len, 4, -1 };
  pthread_t th;
  CHECK_EQ(pthread_create(&th, NULL, rbuf_thread, &a), 0);
  pthread_join(th, NULL);
  CHECK_EQ(a.bad, 0);
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

static void test_hot_list(void) {
  printf("[hot.list: write, read, and what is not trusted]\n");
  tdir_t d, d2;
  tdir_new(&d, "hot");
  tdir_new(&d2, "hot2");
  store_opts_t o;
  small_opts(&o);
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = NULL, *s2 = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  CHECK_EQ(store_open(d2.fd, &o, &s2), 0);
  if (!s || !s2) { tdir_free(&d); tdir_free(&d2); return; }
  uint32_t *ids = NULL;
  size_t n = 99;
  CHECK_EQ(store_hot_read(s, &ids, &n), -ENOENT);                       /* (no file: a first start) */
  CHECK(ids == NULL && n == 0);
  CHECK_EQ(store_hot_write(s, NULL, 0), 0);                             /* (an empty list is a list) */
  CHECK_EQ(store_hot_read(s, &ids, &n), 0);
  CHECK(ids == NULL && n == 0);
  enum { N = 5000 };
  uint32_t *w = malloc(N * sizeof(*w));
  for (uint32_t i = 0; i < N; i++) w[i] = (i * 2654435761u) % 1000003u;
  CHECK_EQ(store_hot_write(s, w, N), 0);
  CHECK_EQ(store_hot_read(s, &ids, &n), 0);
  CHECK(n == N && ids && memcmp(ids, w, N * sizeof(*w)) == 0);           /* (the order is the list's) */
  free(ids);
  ids = NULL;
  CHECK_EQ(store_hot_write(s, w, 3), 0);                                /* (a shorter list replaces it: the file is cut) */
  CHECK_EQ(store_hot_read(s, &ids, &n), 0);
  CHECK(n == 3 && ids && memcmp(ids, w, 3 * sizeof(*w)) == 0);
  free(ids);
  ids = NULL;
  CHECK_EQ(store_hot_write(s, w, STORE_HOT_MAX + 1), -EINVAL);
  CHECK_EQ(store_hot_write(s, NULL, 1), -EINVAL);
  CHECK_EQ(store_hot_write(NULL, w, 1), -EINVAL);
  CHECK_EQ(store_hot_write(s, w, N), 0);
  char hp[700], hp2[700];
  fpath(&d, "hot.list", hp, sizeof(hp));
  fpath(&d2, "hot.list", hp2, sizeof(hp2));
  /* the list of another store (another uuid) is not trusted */
  {
    uint8_t buf[48 + N * 4];
    CHECK_EQ(read_at(hp, 0, buf, sizeof(buf)), 0);
    int fd = open(hp2, O_RDWR | O_CREAT, 0600);
    CHECK(fd >= 0 && write(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf));
    if (fd >= 0) close(fd);
    CHECK_EQ(store_hot_read(s2, &ids, &n), -EBADMSG);
    CHECK(ids == NULL && n == 0);
  }
  /* a byte of the header, of the ids, a file that is too short or too long, an unfinished write (the header is written last): none is trusted */
  const off_t spots[] = { 0, 9, 20, 30, 40, 48, 48 + 4000 };
  for (size_t k = 0; k < sizeof(spots) / sizeof(spots[0]); k++) {
    flip_byte(hp, spots[k]);
    CHECK_EQ(store_hot_read(s, &ids, &n), -EBADMSG);
    CHECK(ids == NULL && n == 0);
    flip_byte(hp, spots[k]);                                            /* (back) */
    CHECK_EQ(store_hot_read(s, &ids, &n), 0);
    free(ids);
    ids = NULL;
  }
  CHECK_EQ(truncate(hp, 48 + 100), 0);
  CHECK_EQ(store_hot_read(s, &ids, &n), -EBADMSG);
  CHECK_EQ(truncate(hp, 20), 0);
  CHECK_EQ(store_hot_read(s, &ids, &n), -EBADMSG);
  CHECK_EQ(store_hot_write(s, w, N), 0);
  {
    uint8_t zero[48];
    memset(zero, 0, sizeof(zero));
    CHECK_EQ(write_at(hp, 0, zero, sizeof(zero)), 0);                   /* (the state of a write that did not finish) */
    CHECK_EQ(store_hot_read(s, &ids, &n), -EBADMSG);
  }
  free(w);
  CHECK_EQ(store_close(s), 0);
  CHECK_EQ(store_close(s2), 0);
  tdir_free(&d);
  tdir_free(&d2);
}

/* ---- 0.7 M2: group commit (store_set_known_n()) ---- */

/* an entry of a group: a name and the meta of zone i, with some of the traps of a manifest pass (a source id that another zone owns, none, a source number that changed) */
typedef struct { char nm[200]; store_meta_t m; } gk_t;
static void gk_make(gk_t *e, uint64_t K, uint32_t npool) {
  uint64_t r = mix64(K * 0x9e3779b97f4a7c15ull + 777);
  uint32_t i = (uint32_t)(r % npool);
  name_of(i, e->nm, sizeof(e->nm));
  e->m = meta_of(i, K);
  uint32_t p = (uint32_t)((r >> 20) % 100);
  if (p < 7) e->m.source_id = (int64_t)((r >> 32) % npool) + 1;          /* an id that another zone owns: a rename (-EEXIST), or the zone's own */
  else if (p < 10) e->m.source_id = 0;
  else if (p < 13) e->m.source = (uint16_t)((e->m.source + 1) % 4);
  e->m.flags = (uint16_t)((r >> 40) & 0x3f);
}

/* the same zone table: the records by zone id (names, states, flags, stamps, sources) and the counters of the views */
static bool same_tables(store_t *a, store_t *b, const char *what) {
  bool ok = true;
  uint32_t ca = 0, cb = 0;
  store_zone_t za, zb;
  store_read_lock();
  for (;;) {
    int ra = store_iter(a, &ca, &za), rb = store_iter(b, &cb, &zb);
    if (ra != rb) { printf("    %s: the tables end at different zones\n", what); ok = false; break; }
    if (ra <= 0) break;
    if (za.zid != zb.zid || za.view != zb.view || strcmp(za.name, zb.name) != 0 || za.state != zb.state || za.flags != zb.flags || za.serial != zb.serial || za.settings != zb.settings ||
        za.stamp_gen != zb.stamp_gen || za.stamp_time != zb.stamp_time || za.source_id != zb.source_id || za.source != zb.source || memcmp(za.digest, zb.digest, STORE_DIGEST_LEN) != 0) {
      printf("    %s: zone %u (%s) differs\n", what, za.zid, za.name);
      ok = false;
      break;
    }
    if (store_find(a, za.view, za.name, strlen(za.name)) != store_find(b, zb.view, zb.name, strlen(zb.name)) ||
        (za.source_id && store_find_source(a, za.source, za.source_id, za.view) != store_find_source(b, zb.source, zb.source_id, zb.view))) {
      printf("    %s: the indexes lead to different zones for %s\n", what, za.name);
      ok = false;
      break;
    }
  }
  store_read_unlock();
  store_stats_t sa, sb;
  store_stats(a, &sa);
  store_stats(b, &sb);
  if (sa.zones_known != sb.zones_known || sa.zones_stored != sb.zones_stored || sa.zones_rejected != sb.zones_rejected || sa.zones_nonstore != sb.zones_nonstore || sa.zones_free != sb.zones_free ||
      sa.zt_records != sb.zt_records || sa.nx_used != sb.nx_used || sa.ix_live != sb.ix_live || sa.sx_live != sb.sx_live || sa.nviews != sb.nviews) {
    printf("    %s: the counters differ: known %" PRIu64 "/%" PRIu64 " stored %" PRIu64 "/%" PRIu64 " free %" PRIu64 "/%" PRIu64 " hwm %" PRIu64 "/%" PRIu64 " ix_live %" PRIu64 "/%" PRIu64 " sx_live %" PRIu64 "/%" PRIu64 "\n",
           what, sa.zones_known, sb.zones_known, sa.zones_stored, sb.zones_stored, sa.zones_free, sb.zones_free, sa.zt_records, sb.zt_records, sa.ix_live, sb.ix_live, sa.sx_live, sb.sx_live);
    ok = false;
  }
  for (uint32_t v = 0; v < sa.nviews && v < STORE_MAX_VIEWS; v++)
    if (sa.views[v].known != sb.views[v].known || sa.views[v].stored != sb.views[v].stored || sa.views[v].rejected != sb.views[v].rejected) { printf("    %s: the counters of view %u differ\n", what, v); ok = false; }
  for (unsigned labels = 1; labels < 8; labels++)
    for (uint16_t v = 0; v < 2; v++)
      if (store_view_depth_count(a, v, labels) != store_view_depth_count(b, v, labels)) { printf("    %s: the depth counters differ (view %u, %u labels)\n", what, v, labels); ok = false; }
  return ok;
}

static void test_group_commit(int mode) {
  printf("[group commit: store_set_known_n() against store_set_known(), %s]\n", mode == STORE_MODE_MAP ? "MAP" : "COPY");
  tdir_t da, db;
  tdir_new(&da, "gca");
  tdir_new(&db, "gcb");
  store_opts_t o;
  small_opts(&o);
  o.mode = mode;
  o.scrub_interval_s = UINT32_MAX;
  store_t *a = NULL, *b = NULL;
  atomic_store(&store_test_no_flusher, true);                            /* (the journal sizes are compared below: the checkpoints by size are made by the writer after its call, at the same points in both stores) */
  CHECK_EQ(store_open(da.fd, &o, &a), 0);
  CHECK_EQ(store_open(db.fd, &o, &b), 0);
  atomic_store(&store_test_no_flusher, false);
  if (!a || !b) { tdir_free(&da); tdir_free(&db); return; }
  store_view_add(a, "v0"); store_view_add(a, "v1");
  store_view_add(b, "v0"); store_view_add(b, "v1");
  /* the same start: stored zones (their images), some deleted (a free list) */
  for (uint32_t i = 0; i < 160; i++) { CHECK_EQ(put_i(a, (uint16_t)(i & 1), i, 1, NULL), 0); CHECK_EQ(put_i(b, (uint16_t)(i & 1), i, 1, NULL), 0); }
  for (uint32_t i = 0; i < 160; i += 5) {
    char nm[160];
    name_of(i, nm, sizeof(nm));
    CHECK_EQ(store_delete_name(a, (uint16_t)(i & 1), nm, strlen(nm)), 0);
    CHECK_EQ(store_delete_name(b, (uint16_t)(i & 1), nm, strlen(nm)), 0);
  }
  const uint32_t pool = 420;                                   /* (more names than zones: new, replaced, a name taken over) */
  uint64_t K = 100, groups = 0, entries = 0, errs = 0, ok_n = 0;
  uint64_t rng = 99;
  gk_t *e = malloc(sizeof(*e) * 200);
  store_known_t in[200];
  int res[200];
  uint32_t zb[200];
  while (entries < 6000) {
    rng = mix64(rng);
    unsigned n = 1 + (unsigned)(rng % 150);                    /* (above 64: the call splits it) */
    uint16_t view = (uint16_t)((rng >> 33) & 1);
    for (unsigned j = 0; j < n; j++) {
      gk_make(&e[j], K++, pool);
      if (((rng >> (8 + j % 20)) & 7) == 0 && j > 0) e[j] = e[j - 1 - (unsigned)((rng >> 50) % j)];      /* the same name, or the same source id, twice in a call */
      in[j].name = e[j].nm;
      in[j].len = strlen(e[j].nm);
      in[j].meta = &e[j].m;
    }
    CHECK_EQ(store_set_known_n(b, view, in, n, res, zb), 0);
    for (unsigned j = 0; j < n; j++) {
      uint32_t za = STORE_NONE;
      int ra = store_set_known(a, view, e[j].nm, strlen(e[j].nm), &e[j].m, &za);
      if (ra != res[j] || (ra == 0 && za != zb[j])) { printf("    group %" PRIu64 " entry %u: %d / zone %u, the group says %d / zone %u; name %s source %u id %lld view %u\n", groups, j, ra, za, res[j], zb[j], e[j].nm, e[j].m.source, (long long)e[j].m.source_id, view);
        for (unsigned q = 0; q < j; q++) if (e[q].m.source_id == e[j].m.source_id || strcmp(e[q].nm, e[j].nm) == 0) printf("      earlier entry %u: name %s source %u id %lld  (res %d)\n", q, e[q].nm, e[q].m.source, (long long)e[q].m.source_id, res[q]);
        CHECK(0); }
      if (ra < 0) errs++; else ok_n++;
    }
    groups++;
    entries += n;
  }
  printf("  %" PRIu64 " groups, %" PRIu64 " entries: %" PRIu64 " recorded, %" PRIu64 " refused (the source id of another zone)\n", groups, entries, ok_n, errs);
  CHECK(errs > 50 && ok_n > 3000);
  CHECK(same_tables(a, b, "after the calls"));
  check_consistent(a, "per entry");
  check_consistent(b, "group");
  store_stats_t sa, sb;
  store_stats(a, &sa);
  store_stats(b, &sb);
  CHECK(sb.group_records > 0 && sb.group_records < sb.group_entries && sb.group_entries >= ok_n);
  CHECK(sb.lsn < sa.lsn / 4);                                                      /* (a record a group, not one an entry; the sizes of the current journal files do not compare: a checkpoint after a growth cuts them when it is due) */
  printf("  journal: %" PRIu64 " records / %" PRIu64 " bytes for the group, %" PRIu64 " / %" PRIu64 " one entry at a time (%" PRIu64 " group records for %" PRIu64 " entries)\n",
         sb.lsn, sb.journal_bytes, sa.lsn, sa.journal_bytes, sb.group_records, sb.group_entries);
  /* the group store, closed and opened again, is the same tables */
  CHECK_EQ(store_close(b), 0);
  o.create = false;
  CHECK_EQ(store_open(db.fd, &o, &b), 0);
  if (b) {
    CHECK(same_tables(a, b, "after a clean restart"));
    CHECK_EQ(store_close(b), 0);
  }
  CHECK_EQ(store_close(a), 0);
  free(e);
  tdir_free(&da);
  tdir_free(&db);

  /* an entry that fails does not take the others with it: a name that is too long, a source number that does not exist, a view the store does not have, no name, bad arguments */
  store_opts_t o2;
  small_opts(&o2);
  o2.mode = mode;
  tdir_t dc;
  tdir_new(&dc, "gcc");
  store_t *c = NULL;
  CHECK_EQ(store_open(dc.fd, &o2, &c), 0);
  if (c) {
    store_view_add(c, "v0");
    gk_t g3[5];
    store_known_t i3[5];
    int r3[5];
    uint32_t z3[5];
    for (unsigned j = 0; j < 5; j++) { gk_make(&g3[j], 5000 + j * 11, 1000); i3[j].name = g3[j].nm; i3[j].len = strlen(g3[j].nm); i3[j].meta = &g3[j].m; }
    char longname[300];
    memset(longname, 'a', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    i3[2].name = longname;
    i3[2].len = strlen(longname);                                              /* (over 255 octets) */
    g3[3].m.source = 99;                                                       /* (no such source number) */
    CHECK_EQ(store_set_known_n(c, 0, i3, 5, r3, z3), 0);
    CHECK_EQ(r3[0], 0); CHECK_EQ(r3[1], 0); CHECK_EQ(r3[2], -EINVAL); CHECK_EQ(r3[3], -EINVAL); CHECK_EQ(r3[4], 0);
    CHECK(z3[2] == STORE_NONE && z3[3] == STORE_NONE && z3[0] != STORE_NONE && z3[4] != STORE_NONE);
    CHECK_EQ(store_set_known_n(c, 7, i3, 1, r3, z3), 0);                       /* (a view the store does not have: the entry is refused) */
    CHECK_EQ(r3[0], -EINVAL);
    CHECK_EQ(store_set_known_n(c, 0, i3, 0, r3, z3), -EINVAL);                 /* (nothing to do is a call that is wrong) */
    CHECK_EQ(store_set_known_n(c, 0, i3, 1, NULL, z3), -EINVAL);
    CHECK_EQ(store_set_known_n(NULL, 0, i3, 1, r3, z3), -EINVAL);
    i3[1].name = NULL;
    CHECK_EQ(store_set_known_n(c, 0, i3 + 1, 1, r3, NULL), 0);                 /* (no zid wanted; an entry without a name is refused) */
    CHECK_EQ(r3[0], -EINVAL);
    check_consistent(c, "failures");
    CHECK_EQ(store_close(c), 0);
  }
  tdir_free(&dc);
}

/* the record of a group is the record of a single call: one entry per call, in both ways, writes the same journal bytes (the format did not change), and a group is one record that a torn tail drops whole */
static int jrn_newest(const tdir_t *d, char *jp, size_t n) {
  uint32_t best = 0;
  best = jrn_newest_gen(d->path, 64);                                   /* (not the next journal, made ahead and empty, nor one with a header only) */
  snprintf(jp, n, "%s/jrn.%u", d->path, best);
  return best != 0;
}
static bool file_tail_equal(const char *p, const char *q, off_t from) {
  struct stat sp, sq;
  if (stat(p, &sp) != 0 || stat(q, &sq) != 0 || sp.st_size != sq.st_size) return false;
  size_t n = (size_t)(sp.st_size - from);
  uint8_t *x = malloc(n), *y = malloc(n);
  bool ok = x && y && read_at(p, from, x, n) == 0 && read_at(q, from, y, n) == 0 && memcmp(x, y, n) == 0;
  free(x);
  free(y);
  return ok;
}

static void gj_hold_build(int step) { if (step == 1) usleep(5000000); }       /* (a build of the index outside the mutex does not end while the group is written) */
static void test_group_journal(void) {
  printf("[group commit: the journal record, a torn record, kill -9]\n");
  /* 1. a group of one is the record of store_set_known() */
  {
    tdir_t da, db;
    tdir_new(&da, "gja");
    tdir_new(&db, "gjb");
    store_opts_t o;
    small_opts(&o);
    store_t *a = NULL, *b = NULL;
    CHECK_EQ(store_open(da.fd, &o, &a), 0);
    CHECK_EQ(store_open(db.fd, &o, &b), 0);
    if (a && b) {
      store_view_add(a, "v0"); store_view_add(b, "v0");
      for (uint32_t i = 0; i < 40; i++) {
        gk_t g;
        gk_make(&g, 300 + i, 90);
        store_known_t in = { g.nm, strlen(g.nm), &g.m };
        int r;
        (void)store_set_known(a, 0, g.nm, strlen(g.nm), &g.m, NULL);
        CHECK_EQ(store_set_known_n(b, 0, &in, 1, &r, NULL), 0);
      }
      store_stats_t sa, sb;
      store_stats(a, &sa);
      store_stats(b, &sb);
      CHECK_EQ(sa.lsn, sb.lsn);
      char pa[700], pb[700];
      CHECK(jrn_newest(&da, pa, sizeof(pa)) && jrn_newest(&db, pb, sizeof(pb)));
      CHECK(file_tail_equal(pa, pb, 4096));                                       /* (past the file header of the journal: the records) */
      CHECK(same_tables(a, b, "groups of one"));
      store_close(a);
      store_close(b);
    }
    tdir_free(&da);
    tdir_free(&db);
  }
  /* 2. kill -9 after a group (no close): the replay applies the whole record; a torn tail (the power fails in the write) drops the whole group, none of its zones is there, the zones before it are */
  for (int torn = 0; torn < 2; torn++) {
    tdir_t d;
    tdir_new(&d, "gjk");
    store_opts_t o;
    small_opts(&o);
    store_t *s = NULL;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (!s) { tdir_free(&d); continue; }
    store_view_add(s, "v0");
    store_close(s);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
      store_t *c = NULL;
      if (store_open(d.fd, &o, &c) != 0) _exit(3);
      for (uint32_t i = 0; i < 10; i++) { store_meta_t m = meta_of(i, 1); char nm[160]; name_of(i, nm, sizeof(nm)); if (store_set_known(c, 0, nm, strlen(nm), &m, NULL) != 0) _exit(4); }
      gk_t g[STORE_GROUP_MAX];                                                 /* (a full group: one record) */
      store_known_t in[STORE_GROUP_MAX];
      int r[STORE_GROUP_MAX];
      for (unsigned j = 0; j < STORE_GROUP_MAX; j++) {
        name_of(100 + j, g[j].nm, sizeof(g[j].nm));
        g[j].m = meta_of(100 + j, 1);
        in[j].name = g[j].nm; in[j].len = strlen(g[j].nm); in[j].meta = &g[j].m;
      }
      if (store_set_known_n(c, 0, in, STORE_GROUP_MAX, r, NULL) != 0) _exit(5);
      for (unsigned j = 0; j < STORE_GROUP_MAX; j++) if (r[j] != 0) _exit(6);
      _exit(0);                                                               /* no close, no commit: the record is in the kernel */
    }
    int stt = 0;
    waitpid(pid, &stt, 0);
    CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
    char jp[700];
    CHECK(jrn_newest(&d, jp, sizeof(jp)));
    struct stat jst;
    CHECK_EQ(stat(jp, &jst), 0);
    if (torn) {
      CHECK_EQ(truncate(jp, jst.st_size - 29), 0);                            /* the last record is the group: it is cut in the middle of its last op */
      o.boot_id = 43;                                                         /* (a lost tail is a power loss: another boot, the tables are rebuilt from zt, which has the cells of the group ahead of the journal) */
    }
    o.create = false;
    CHECK_EQ(store_open(d.fd, &o, &s), 0);
    if (s) {
      store_stats_t st;
      store_stats(s, &st);
      int found = 0;
      for (uint32_t j = 0; j < STORE_GROUP_MAX; j++) { char nm[160]; name_of(100 + j, nm, sizeof(nm)); store_read_lock(); if (store_find(s, 0, nm, strlen(nm)) != STORE_NONE) found++; store_read_unlock(); }
      if (torn) {
        CHECK(st.recovery.journal_torn);
        for (uint32_t i = 0; i < 10; i++) { char nm[160]; name_of(i, nm, sizeof(nm)); store_read_lock(); CHECK(store_find(s, 0, nm, strlen(nm)) != STORE_NONE); store_read_unlock(); }
        CHECK_EQ(found, 0);                                                   /* none of the group: it was one record */
        CHECK_EQ(st.zones_known, 10);
      } else {
        CHECK(!st.recovery.rebuilt);
        CHECK(st.recovery.records_replayed >= 11);                            /* (the ten singles and the group) */
        CHECK_EQ(found, STORE_GROUP_MAX);
        CHECK_EQ(st.zones_known, 10 + STORE_GROUP_MAX);
      }
      check_consistent(s, torn ? "torn group" : "replayed group");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* 3. a group that the index growth splits: the entries past one half of the index wait for the growth (the build outside the mutex is held back here), so the call (64 entries) writes the first
   * entries as records of up to STORE_GROUP_MAX, the growth as the next, the rest after it.  kill -9 at every crash point of the call: after the replay the group's zones are a prefix of the entries in the
   * order of the call (each record whole or not there), and some kills keep only the first record (the call is not one unit: what the kill -9 loop's model allows) */
  {
    int parts = 0, whole = 0, none = 0, bad = 0, runs = 0;
    for (long c = 1; c < 400 && !bad; c++) {
      tdir_t d;
      tdir_new(&d, "gjs");
      store_opts_t o;
      small_opts(&o);
      o.sync_policy = STORE_SYNC_NONE;
      o.checkpoint_interval_ms = UINT32_MAX;
      fflush(stdout);
      pid_t pid = fork();
      if (pid == 0) {
        atomic_store(&store_test_no_flusher, true);
        atomic_store(&store_test_regrow_hook, gj_hold_build);
        store_t *s = NULL;
        if (store_open(d.fd, &o, &s) != 0) _exit(3);
        store_view_add(s, "v0");
        for (uint32_t i = 0; i < 500; i++) { store_meta_t m = meta_of(i, 1); char nm[160]; name_of(i, nm, sizeof(nm)); if (store_set_known(s, 0, nm, strlen(nm), &m, NULL) != 0) _exit(4); }
        gk_t g[64];
        store_known_t in[64];
        int r[64];
        for (unsigned j = 0; j < 64; j++) {
          name_of(1000 + j, g[j].nm, sizeof(g[j].nm));
          g[j].m = meta_of(1000 + j, 1);
          in[j].name = g[j].nm; in[j].len = strlen(g[j].nm); in[j].meta = &g[j].m;
        }
        store_test_crash_countdown = c;
        if (store_set_known_n(s, 0, in, 64, r, NULL) != 0) _exit(5);
        store_test_crash_countdown = 0;
        for (unsigned j = 0; j < 64; j++) if (r[j] != 0) _exit(6);
        _exit(0);
      }
      int stt = 0;
      waitpid(pid, &stt, 0);
      const bool killed = WIFSIGNALED(stt);
      if (!killed) CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
      o.create = false;
      store_t *s = NULL;
      CHECK_EQ(store_open(d.fd, &o, &s), 0);
      if (s) {
        unsigned found = 0;
        bool prefix = true;
        store_read_lock();
        for (unsigned j = 0; j < 64; j++) {
          char nm[160];
          name_of(1000 + j, nm, sizeof(nm));
          const bool there = store_find(s, 0, nm, strlen(nm)) != STORE_NONE;
          if (there && found != j) prefix = false;
          if (there) found++;
        }
        store_read_unlock();
        store_stats_t st;
        store_stats(s, &st);
        if (!prefix || st.zones_known != 500 + found || (st.recovery.rebuilt && !st.recovery.gen_replays)) {
          bad++;
          printf("  crash point %ld: found %u (prefix %d), %" PRIu64 " known, rebuilt %d, generation switches replayed %u\n", c, found, (int)prefix, st.zones_known, (int)st.recovery.rebuilt, st.recovery.gen_replays);
        }
        if (found == 64) whole++;
        else if (found == 0) none++;
        else parts++;
        check_consistent(s, "split group");
        CHECK_EQ(store_close(s), 0);
      }
      tdir_free(&d);
      runs++;
      if (!killed) break;                                                     /* (the countdown is past the call's crash points) */
    }
    printf("  a group split by the index growth, killed at each of %d crash points: %d whole, %d none, %d in part (a prefix)\n", runs, whole, none, parts);
    CHECK_EQ(bad, 0);
    CHECK(whole > 0 && none > 0);                                         /* (0.7: the records of a call are written after it, in one span: a kill keeps them all or none, but across a switch of the journal file) */
  }
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* 0.7: the journal ring (the record is written after the writer mutex; planning planing_0.7.x_store_journal_offlock.md, 4.2)            */
/* ------------------------------------------------------------------------------------------------------------------ */

/* the leader's hook: while g_jh_hold is set, a leader that begins a round waits there (its records are applied and not in the kernel: the window the ring opens); a kill at
 * the n-th time a step is reached (1: a round begins, 2: a span was written) */
static _Atomic int g_jh_hold, g_jh_in, g_jh_kill_step, g_jh_kill_n, g_jh_sleep_us;
static void jh_hook(store_t *s, int step) {
  (void)s;
  if (atomic_load(&g_jh_kill_step) == step && atomic_fetch_sub(&g_jh_kill_n, 1) == 1) kill(getpid(), SIGKILL);
  if (step == 1 && atomic_load(&g_jh_sleep_us)) usleep((useconds_t)(mix64(now_us()) % (uint64_t)atomic_load(&g_jh_sleep_us)));
  if (step != 1 || !atomic_load(&g_jh_hold)) return;
  atomic_store(&g_jh_in, 1);
  while (atomic_load(&g_jh_hold)) usleep(300);
  atomic_store(&g_jh_in, 0);
}
static bool jh_wait_in(void) {
  for (int w = 0; w < 5000 && !atomic_load(&g_jh_in); w++) usleep(1000);
  return atomic_load(&g_jh_in) != 0;
}
/* the leader's write fails g_jf_n times (-1: every time) with g_jf_err */
static _Atomic int g_jf_n, g_jf_err;
static int jf_fault(uint64_t pos, uint64_t len) {
  (void)pos;
  (void)len;
  const int n = atomic_load(&g_jf_n);
  if (n == 0) return 0;
  if (n > 0) atomic_fetch_sub(&g_jf_n, 1);
  return atomic_load(&g_jf_err);
}
static void jr_hooks_off(void) {
  store_test_jw_hook = NULL;
  store_test_jw_fault = NULL;
  atomic_store(&g_jh_hold, 0);
  atomic_store(&g_jh_kill_step, 0);
  atomic_store(&g_jh_sleep_us, 0);
  atomic_store(&g_jf_n, 0);
}
/* a call on a thread of its own */
typedef struct jr_call { int (*fn)(struct jr_call *); store_t *s; uint32_t a; uint64_t b; int r; _Atomic int done, flag; pthread_t th; } jr_call_t;
static void *jr_call_main(void *arg) {
  jr_call_t *c = arg;
  c->r = c->fn(c);
  atomic_store(&c->done, 1);
  return NULL;
}
static bool jr_start(jr_call_t *c) { atomic_store(&c->done, 0); return pthread_create(&c->th, NULL, jr_call_main, c) == 0; }
static int jc_put(jr_call_t *c) { return put_i(c->s, 0, c->a, c->b, NULL); }
static int jc_noop(jr_call_t *c) { return store_set_flags(c->s, c->a, 0, 0); }
static int jc_flag(jr_call_t *c) { return store_set_flags(c->s, c->a, STORE_F_REJECTED_NEW, 0); }
static int jc_commit(jr_call_t *c) { return store_commit(c->s); }
static int jc_ckpt(jr_call_t *c) { return store_checkpoint(c->s); }
static int jc_close(jr_call_t *c) { return store_close(c->s); }
static int jc_jwait(jr_call_t *c) { (void)store_journal_wait(c->s, 1); return 0; }
static int jc_fill(jr_call_t *c) {                                        /* (b zones from a, deferred, then a settle) */
  int r = store_defer(c->s, true);
  for (uint64_t k = 0; k < c->b && r == 0; k++) r = put_i(c->s, 0, c->a + (uint32_t)k, 1, NULL);
  if (r == 0) r = store_settle(c->s);
  (void)store_defer(c->s, false);
  return r;
}
static int jc_defer_nosettle(jr_call_t *c) {                               /* (the bytes are left to the flusher and to whoever waits next) */
  int r = store_defer(c->s, true);
  if (r == 0) r = put_i(c->s, 0, c->a, 1, NULL);
  (void)store_defer(c->s, false);
  return r;
}
static store_t *jr_open_o(tdir_t *d, bool create, uint64_t boot, store_opts_t *o) {
  store_t *s = NULL;
  o->create = create;
  o->boot_id = boot;
  if (store_open(d->fd, o, &s) != 0) return NULL;
  if (create) store_view_add(s, "default");
  return s;
}
static store_t *jr_open(tdir_t *d, bool create, uint64_t boot) {
  store_opts_t o;
  small_opts(&o);
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  return jr_open_o(d, create, boot, &o);
}

/* (A, B2; 4.2 tests 2 and 4) A call returns only after the ring is written up to its unlock: its own record, and every record it planned on.  A no-op call of another thread made
 * after a record was applied (and before it is written) waits for it; store_commit() waits for a held leader; readers see the record before it is written; after the commit the
 * state survives a power loss (another boot id: the rebuild path). */
static void test_jr_ack(void) {
  printf("[journal ring: a call returns after its bytes and the bytes it planned on are written; a commit waits for a held leader]\n");
  tdir_t d;
  tdir_new(&d, "jrack");
  store_t *s = jr_open(&d, true, 42);
  CHECK(s != NULL);
  if (!s) { tdir_free(&d); return; }
  for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  const uint32_t z5 = find_i(s, 0, 5);
  store_test_jw_hook = jh_hook;
  atomic_store(&g_jh_hold, 1);
  jr_call_t a = { .fn = jc_put, .s = s, .a = 100, .b = 1 }, b = { .fn = jc_noop, .s = s, .a = z5 }, c = { .fn = jc_commit, .s = s };
  CHECK(jr_start(&a));
  CHECK(jh_wait_in());                                                     /* (the put is applied: its leader waits in the hook) */
  CHECK(find_i(s, 0, 100) != STORE_NONE);                                  /* (readers see it before it is written) */
  store_stats_t st;
  store_stats(s, &st);
  CHECK(st.ring_unwritten_bytes > 0);
  CHECK(jr_start(&b));
  CHECK(jr_start(&c));
  usleep(100000);
  CHECK(!atomic_load(&a.done) && !atomic_load(&b.done) && !atomic_load(&c.done));    /* (the no-op call and the commit wait for the record they came after) */
  atomic_store(&g_jh_hold, 0);
  pthread_join(a.th, NULL);
  pthread_join(b.th, NULL);
  pthread_join(c.th, NULL);
  CHECK_EQ(a.r, 0);
  CHECK_EQ(b.r, 0);
  CHECK_EQ(c.r, 0);
  store_stats(s, &st);
  CHECK_EQ(st.ring_unwritten_bytes, 0);
  CHECK(st.leader_writes > 0 && st.committed_lsn == st.lsn);
  jr_hooks_off();
  CHECK_EQ(store_close(s), 0);
  /* a commit made while its leader was held, then a crash with another boot (a power loss): the open rebuilds and the committed zones are there */
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    store_t *c = jr_open(&d, false, 42);
    if (!c) _exit(2);
    store_test_jw_hook = jh_hook;
    atomic_store(&g_jh_hold, 1);
    jr_call_t p = { .fn = jc_put, .s = c, .a = 500, .b = 1 }, cm = { .fn = jc_commit, .s = c };
    if (!jr_start(&p) || !jh_wait_in() || !jr_start(&cm)) _exit(3);
    usleep(50000);
    if (atomic_load(&cm.done)) _exit(4);                                   /* (the commit waits for the held write) */
    atomic_store(&g_jh_hold, 0);
    pthread_join(p.th, NULL);
    pthread_join(cm.th, NULL);
    if (p.r != 0 || cm.r != 0) _exit(5);
    kill(getpid(), SIGKILL);
    _exit(6);
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFSIGNALED(stt));
  store_t *s2 = jr_open(&d, false, 77);                                    /* (another boot: the rebuild path, after the commit's sync) */
  CHECK(s2 != NULL);
  if (s2) {
    store_stats_t st2;
    store_stats(s2, &st2);
    CHECK(st2.recovery.rebuilt);
    CHECK(verify_i(s2, 0, 500, 1) && verify_i(s2, 0, 100, 1));
    for (uint32_t i = 0; i < 20; i++) CHECK(verify_i(s2, 0, i, 1));
    check_consistent(s2, "ack reopen");
    CHECK_EQ(store_close(s2), 0);
  }
  tdir_free(&d);
}

/* (4.2 test 3) kill -9 right after a call returned, for every writer's way out of the mutex: with no flusher (no background leader writes behind the call), the change is
 * there after the reopen, and the replay is exact (same boot, no rebuild but after an index growth's OP_GEN). */
enum { JK_PUT, JK_KNOWN, JK_KNOWN_N, JK_DELETE, JK_DELETE_NAME, JK_FLAGS, JK_STAMP, JK_CURSOR, JK_VIEW, JK_RESERVE, JK_COMPACT, JK_REPAIR, JK_TICK, JK_SCRUB, JK_NX, JK_N };
static const char *const jk_names[JK_N] = { "store_put", "store_set_known", "store_set_known_n", "store_delete", "store_delete_name", "store_set_flags", "store_set_stamp",
                                             "store_set_cursor", "store_view_add", "store_reserve", "store_compact", "store_repair", "store_tick (cleaner, segment removal)",
                                             "store_scrub_run", "store_compact (the nx pass)" };
static store_opts_t jk_opts(void) {
  store_opts_t o;
  small_opts(&o);
  o.seg_size = 64u << 10;                                                  /* (several segments: the cleaner and the removal have work) */
  o.compact_rate = UINT64_MAX;
  o.nx_reclaim_min = 1;
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  return o;
}
/* the parent's part before the call (acknowledged, closed): what the call then changes */
static void jk_prep(store_t *s, int k) {
  if (k == JK_COMPACT || k == JK_TICK)
    for (uint32_t i = 0; i < 120; i++) { char nm[160]; name_of(i, nm, sizeof(nm)); (void)store_delete_name(s, 0, nm, strlen(nm)); }    /* (dead segments) */
  if (k == JK_NX)
    for (uint32_t i = 3; i < 200; i += 7) { char nm[160]; name_of(i, nm, sizeof(nm)); (void)store_delete_name(s, 0, nm, strlen(nm)); }  /* (holes in nx: long names gone) */
}
static int jk_call(store_t *s, int k) {
  char nm[160];
  store_meta_t m;
  switch (k) {
  case JK_PUT: return put_i(s, 0, 200, 3, NULL);
  case JK_KNOWN: name_of(201, nm, sizeof(nm)); m = meta_of(201, 1); return store_set_known(s, 0, nm, strlen(nm), &m, NULL);
  case JK_KNOWN_N: {
    char n4[4][160];
    store_meta_t m4[4];
    store_known_t in[4];
    int res[4];
    for (int j = 0; j < 4; j++) { name_of(202 + (uint32_t)j, n4[j], sizeof(n4[j])); m4[j] = meta_of(202 + (uint32_t)j, 1); in[j].name = n4[j]; in[j].len = strlen(n4[j]); in[j].meta = &m4[j]; }
    int r = store_set_known_n(s, 0, in, 4, res, NULL);
    for (int j = 0; j < 4 && r == 0; j++) r = res[j];
    return r;
  }
  case JK_DELETE: return store_delete(s, find_i(s, 0, 130));
  case JK_DELETE_NAME: name_of(131, nm, sizeof(nm)); return store_delete_name(s, 0, nm, strlen(nm));
  case JK_FLAGS: return store_set_flags(s, find_i(s, 0, 136), STORE_F_REJECTED_NEW, 0);
  case JK_STAMP: return store_set_stamp(s, find_i(s, 0, 137), 99, 990, 0, 0);
  case JK_CURSOR: return store_set_cursor(s, 1, 1234, "id", 2);
  case JK_VIEW: return store_view_add(s, "v9") >= 0 ? 0 : -1;
  case JK_RESERVE: return store_reserve(s, 5000);
  case JK_COMPACT: return store_compact(s, 0, true, NULL);
  case JK_REPAIR: mem_flip(s, 0, (uint64_t)find_i(s, 0, 138) * 64 + 24); return store_repair(s);    /* (a damaged cell: the repair drops the zone) */
  case JK_TICK: {
    int r = store_tick(s);                                                 /* (the cleaner and the marking of the empty segments) */
    if (r == 0) r = store_checkpoint(s);
    if (r == 0) r = store_tick(s);                                         /* (their removal) */
    return r;
  }
  case JK_SCRUB: {
    store_zone_t zi;
    if (store_zone_get(s, find_i(s, 0, 139), &zi) != 0) return -1;
    char p[64];
    snprintf(p, sizeof(p), "seg.%u", (unsigned)(zi.loc >> 36));
    const int fd = openat(store_test_dirfd_of(s), p, O_RDWR);
    if (fd < 0) return -1;
    uint8_t b;
    const off_t off = (off_t)((zi.loc & ((1ull << 36) - 1)) * 64 + 64 + 32 + 21);
    if (pread(fd, &b, 1, off) != 1) { close(fd); return -1; }
    b ^= 0x5a;
    if (pwrite(fd, &b, 1, off) != 1) { close(fd); return -1; }
    close(fd);
    return store_scrub_run(s, NULL);                                       /* (the damaged image: the zone becomes KNOWN, a record) */
  }
  default: return store_compact(s, 0, false, NULL);                         /* JK_NX: the nx pass moves the names down */
  }
}
static bool jk_check(store_t *s, int k, const store_stats_t *before) {
  store_zone_t zi;
  store_stats_t st;
  store_stats(s, &st);
  switch (k) {
  case JK_PUT: return verify_i(s, 0, 200, 3);
  case JK_KNOWN: return find_i(s, 0, 201) != STORE_NONE;
  case JK_KNOWN_N: for (uint32_t j = 0; j < 4; j++) if (find_i(s, 0, 202 + j) == STORE_NONE) return false; return true;
  case JK_DELETE: return find_i(s, 0, 130) == STORE_NONE;
  case JK_DELETE_NAME: return find_i(s, 0, 131) == STORE_NONE;
  case JK_FLAGS: return store_zone_get(s, find_i(s, 0, 136), &zi) == 0 && (zi.flags & STORE_F_REJECTED_NEW);
  case JK_STAMP: return store_zone_get(s, find_i(s, 0, 137), &zi) == 0 && zi.stamp_gen == 99;
  case JK_CURSOR: { bool v = false; uint64_t cur = 0; return store_get_cursor(s, 1, &v, &cur, NULL, NULL) == 0 && v && cur == 1234; }
  case JK_VIEW: return store_view_id(s, "v9") >= 0;
  case JK_RESERVE: return st.ix_slots >= 5000 || st.recovery.gen_replays > 0;   /* (its OP_GEN record: replayed, the open rebuilt the index at its own size) */
  case JK_COMPACT: case JK_TICK: return st.seg_free_numbers > before->seg_free_numbers;    /* (segments were removed by records that survived) */
  case JK_REPAIR: return find_i(s, 0, 138) == STORE_NONE;                 /* (the repair dropped the damaged zone; its checkpoint is on disk) */
  case JK_SCRUB: return store_zone_get(s, find_i(s, 0, 139), &zi) == 0 && zi.state == STORE_STATE_KNOWN;
  default: return st.nx_dead < before->nx_dead;                           /* JK_NX: the holes are gone */
  }
}
static void test_jr_kill_after_return(void) {
  printf("[journal ring: kill -9 right after each writer call returned: the change is there]\n");
  for (int k = 0; k < JK_N; k++) {
    tdir_t d;
    tdir_new(&d, "jrkr");
    store_opts_t o = jk_opts();
    store_t *s = jr_open_o(&d, true, 42, &o);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); continue; }
    for (uint32_t i = 0; i < 200; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    jk_prep(s, k);
    CHECK_EQ(store_close(s), 0);
    s = jr_open_o(&d, false, 42, &o);
    store_stats_t before;
    memset(&before, 0, sizeof(before));
    if (s) { store_stats(s, &before); CHECK_EQ(store_close(s), 0); }
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
      atomic_store(&store_test_no_flusher, true);
      store_t *c = jr_open_o(&d, false, 42, &o);
      if (!c) _exit(2);
      if (jk_call(c, k) != 0) _exit(3);
      kill(getpid(), SIGKILL);
      _exit(4);
    }
    int stt = 0;
    waitpid(pid, &stt, 0);
    if (!WIFSIGNALED(stt)) printf("  %s: the child ended with %d\n", jk_names[k], WIFEXITED(stt) ? WEXITSTATUS(stt) : -1);
    CHECK(WIFSIGNALED(stt));
    s = jr_open_o(&d, false, 42, &o);
    CHECK(s != NULL);
    if (s) {
      store_stats_t st;
      store_stats(s, &st);
      const bool ok = jk_check(s, k, &before);
      if (!ok) printf("  %s: the change is not there after kill -9\n", jk_names[k]);
      CHECK(ok);
      CHECK(!st.recovery.rebuilt || st.recovery.gen_replays > 0 || k == JK_REPAIR);
      check_consistent(s, jk_names[k]);
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
}

/* (4.2 tests 5, 6, 16, 18 and the no-flusher case of 4.1) the write of the journal fails: ENOSPC -> nospace (only the flusher, or the tick without one, writes again; every other
 * wait and every new record fails at once; the stop gets through), EIO -> three tries, then failed (no records, no table page, no clean checkpoint; the reopen replays the
 * written prefix); a write that fails once is written again whole (the state stays ok). */
static void test_jr_states(bool flusher) {
  printf("[journal ring: ENOSPC (nospace, the retry), EIO (failed), a transient error (%s)]\n", flusher ? "flusher" : "no flusher");
  /* 1. ENOSPC: the retry passes when the room comes back */
  {
    tdir_t d;
    tdir_new(&d, "jrnospc");
    atomic_store(&store_test_no_flusher, !flusher);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_no_flusher, false);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    store_test_jw_fault = jf_fault;
    atomic_store(&g_jf_err, ENOSPC);
    atomic_store(&g_jf_n, -1);
    CHECK_EQ(put_i(s, 0, 100, 1, NULL), -ENOSPC);                          /* (its own leader met the error: the outcome is unknown, the record is applied) */
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.journal_state, STORE_JOURNAL_NOSPACE);
    uint64_t t0 = now_us();
    CHECK_EQ(put_i(s, 0, 101, 1, NULL), -ENOSPC);                          /* (at once: no wait at the admission) */
    CHECK(find_i(s, 0, 101) == STORE_NONE);
    CHECK_EQ(store_commit(s), -ENOSPC);
    CHECK(store_checkpoint(s) < 0);
    CHECK(now_us() - t0 < 2000000);
    atomic_store(&g_jf_n, 0);                                              /* the room comes back */
    for (int w = 0; w < 5000; w++) {
      if (!flusher) (void)store_tick(s);
      store_stats(s, &st);
      if (st.journal_state == STORE_JOURNAL_OK) break;
      usleep(1000);
    }
    CHECK_EQ(st.journal_state, STORE_JOURNAL_OK);
    CHECK_EQ(st.ring_unwritten_bytes, 0);
    CHECK_EQ(put_i(s, 0, 102, 1, NULL), 0);
    CHECK_EQ(store_commit(s), 0);
    check_consistent(s, "nospace, back");
    jr_hooks_off();
    CHECK_EQ(store_close(s), 0);
    s = jr_open(&d, false, 42);
    CHECK(s != NULL);
    if (s) {
      CHECK(verify_i(s, 0, 100, 1) && verify_i(s, 0, 102, 1));            /* (the record of the call that got -ENOSPC was written by the retry) */
      check_consistent(s, "nospace reopen");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* 2. ENOSPC that lasts: the stop gets through (no clean checkpoint), the reopen replays the written prefix */
  {
    tdir_t d;
    tdir_new(&d, "jrnospc2");
    atomic_store(&store_test_no_flusher, !flusher);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_no_flusher, false);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    store_test_jw_fault = jf_fault;
    atomic_store(&g_jf_err, ENOSPC);
    atomic_store(&g_jf_n, -1);
    CHECK_EQ(put_i(s, 0, 100, 1, NULL), -ENOSPC);
    uint64_t t0 = now_us();
    CHECK(store_close(s) != 0 || true);                                    /* (the clean checkpoint cannot be made: logged) */
    CHECK(now_us() - t0 < 5000000);
    jr_hooks_off();
    s = jr_open(&d, false, 42);
    CHECK(s != NULL);
    if (s) {
      store_stats_t st;
      store_stats(s, &st);
      CHECK(!st.recovery.rebuilt);
      CHECK(find_i(s, 0, 100) == STORE_NONE);                              /* (never written) */
      for (uint32_t i = 0; i < 20; i++) CHECK(verify_i(s, 0, i, 1));
      check_consistent(s, "nospace stop");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* 3. EIO: failed; the writers that take the mutex themselves get -EIO too; no clean checkpoint; the reopen replays the written prefix */
  {
    tdir_t d;
    tdir_new(&d, "jreio");
    atomic_store(&store_test_no_flusher, !flusher);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_no_flusher, false);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    log_clear();
    store_test_jw_fault = jf_fault;
    atomic_store(&g_jf_err, EIO);
    atomic_store(&g_jf_n, -1);
    CHECK_EQ(put_i(s, 0, 100, 1, NULL), -EIO);
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.journal_state, STORE_JOURNAL_FAILED);
    CHECK_EQ(st.journal_error, EIO);
    CHECK(st.journal_failed_unix != 0 && st.leader_retries >= 3);
    CHECK_EQ(put_i(s, 0, 101, 1, NULL), -EIO);
    CHECK(store_compact(s, 0, true, NULL) < 0);
    CHECK(store_repair(s) < 0);
    CHECK(store_reserve(s, 50000) < 0);
    CHECK(store_checkpoint(s) < 0);
    CHECK_EQ(store_commit(s), -EIO);
    CHECK(store_close(s) != 0 || true);
    jr_hooks_off();
    s = jr_open(&d, false, 42);
    CHECK(s != NULL);
    if (s) {
      store_stats(s, &st);
      CHECK(!st.recovery.rebuilt);
      CHECK(find_i(s, 0, 100) == STORE_NONE);
      for (uint32_t i = 0; i < 20; i++) CHECK(verify_i(s, 0, i, 1));
      check_consistent(s, "failed reopen");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* 4. one failed write (a span that is written again whole): the state stays ok */
  {
    tdir_t d;
    tdir_new(&d, "jrretry");
    store_t *s = jr_open(&d, true, 42);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    store_test_jw_fault = jf_fault;
    atomic_store(&g_jf_err, EIO);
    atomic_store(&g_jf_n, 1);
    for (uint32_t i = 0; i < 20; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.journal_state, STORE_JOURNAL_OK);
    CHECK(st.leader_retries >= 1);
    jr_hooks_off();
    CHECK_EQ(store_close(s), 0);
    s = jr_open(&d, false, 42);
    if (s) {
      for (uint32_t i = 0; i < 20; i++) CHECK(verify_i(s, 0, i, 1));
      check_consistent(s, "retry reopen");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
}

/* (4.2 test 9, rule T, and its negative control) A checkpoint copies a page while a record that changed it is applied and not written (its leader is held): with rule T the
 * copy waits (store.journal.ck_waits), and a kill -9 there leaves the table files as the journal says; without it (store_test_no_rule_t) the copied page reaches the file with the
 * change of a record the journal does not hold, and the reopen finds the counters wrong: the test sees the bug the rule prevents. */
static _Atomic int g_rt_at, g_rt_go;
static void rt_ckpt_hook(int step) {
  if (step != 2) return;
  atomic_store(&g_rt_at, 1);
  while (!atomic_load(&g_rt_go)) usleep(300);
}
static int jc_del(jr_call_t *c) { char nm[160]; name_of(c->a, nm, sizeof(nm)); return store_delete_name(c->s, 0, nm, strlen(nm)); }
/* the record > P of each variant: 0 zt (the flags of zone 63), 1 ix (zone 5 deleted: its name slot), 2 sx (a new zone with a source id and a long name: its source slot, its
 * name slot, its cell and its name in nx), 3 nx (zone 10, a long name, deleted: the name's bytes become dead in nx).  (A change of a zone's source id alone keeps every structure
 * consistent when all its pages are copied: no check can tell it from a call that was applied, so the variant is a new zone.) */
static const char *const rt_names[4] = { "zt", "ix", "sx", "nx" };
static bool jr_rule_t_run(bool rule, int variant) {
  tdir_t d;
  tdir_new(&d, rule ? "jrrt" : "jrrt0");
  store_t *s = jr_open(&d, true, 42);
  if (!s) { tdir_free(&d); return false; }
  for (uint32_t i = 0; i < 64; i++) (void)put_i(s, 0, i, 1, NULL);        /* (zone ids 0..63: the first page of zt) */
  (void)store_checkpoint(s);
  (void)store_close(s);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    atomic_store(&store_test_no_flusher, true);                            /* (no background leader: the record stays unwritten while its own leader is held) */
    store_t *c = jr_open(&d, false, 42);
    if (!c) _exit(2);
    if (put_i(c, 0, 62, 2, NULL) != 0) _exit(3);                          /* (the first page of zt is dirty for the next checkpoint) */
    for (uint32_t k = 0; k < 60; k++) if (put_i(c, 0, 300 + k * 7, 1, NULL) != 0) _exit(3);       /* (and the pages of ix, sx and nx: new zones, long names) */
    atomic_store(&store_test_no_rule_t, !rule);
    atomic_store(&store_test_ckpt_hook, rt_ckpt_hook);
    jr_call_t ck = { .fn = jc_ckpt, .s = c };
    if (!jr_start(&ck)) _exit(4);
    for (int w = 0; w < 5000 && !atomic_load(&g_rt_at); w++) usleep(1000);
    store_test_jw_hook = jh_hook;
    atomic_store(&g_jh_hold, 1);
    jr_call_t fl = { .fn = jc_flag, .s = c, .a = find_i(c, 0, 63) };       /* (a record > P that changes zone 63: same page, last written before the previous checkpoint) */
    if (variant == 1) fl = (jr_call_t){ .fn = jc_del, .s = c, .a = 5 };
    if (variant == 2) fl = (jr_call_t){ .fn = jc_put, .s = c, .a = 2003, .b = 1 };     /* (a new zone: its name and source slots, its cell) */
    if (variant == 3) fl = (jr_call_t){ .fn = jc_del, .s = c, .a = 10 };
    if (!jr_start(&fl)) _exit(5);
    if (!jh_wait_in()) _exit(6);
    atomic_store(&g_rt_go, 1);                                             /* the checkpoint copies the page now */
    store_stats_t st;
    for (int w = 0; w < 3000; w++) { store_stats(c, &st); if (st.checkpoint_journal_waits > 0) break; usleep(1000); }
    if (!rule) usleep(300000);                                             /* (without the rule the page is written: give it the time) */
    kill(getpid(), SIGKILL);
    _exit(7);
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFSIGNALED(stt));
  s = jr_open(&d, false, 42);
  bool consistent = false;
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    store_check_report_t rep;
    store_zone_t zi;
    bool absent = true;                                                   /* (R's record was never written: its change must not be there) */
    if (variant == 0) absent = store_zone_get(s, find_i(s, 0, 63), &zi) == 0 && !(zi.flags & STORE_F_REJECTED_NEW);
    if (variant == 1) absent = find_i(s, 0, 5) != STORE_NONE;
    if (variant == 2) absent = find_i(s, 0, 2003) == STORE_NONE && store_find_source(s, 2003 % 4, 2004, 0) == STORE_NONE;
    if (variant == 3) absent = find_i(s, 0, 10) != STORE_NONE;
    consistent = store_check(s, &rep) == 0 && !st.recovery.rebuilt && absent;
    if (!consistent && rule) printf("  rule T on (%s): store_check: %s\n", rt_names[variant], rep.first_error);
    store_close(s);
  }
  tdir_free(&d);
  return consistent;
}
static void test_jr_rule_t(void) {
  printf("[journal ring: rule T, a checkpoint's copy waits for the journal; and without it the files get ahead of the journal (negative control)]\n");
  for (int v = 0; v < 4; v++) {
    CHECK(jr_rule_t_run(true, v));
    const bool without = jr_rule_t_run(false, v);
    printf("  %s: the rule kept the files exact; without it the reopen %s\n", rt_names[v], without ? "found nothing wrong (the negative control did not show the bug)" : "found the files ahead of the journal");
    CHECK(!without);
  }
}

/* (4.2 tests 1, 7, 8, 11) switches with only a header; a small ring: records across its wrap, the ring full (the admission and the drain inside the mutex), a record too big
 * for it; the close and store_journal_wait() while the leader is held */
static void test_jr_ring(void) {
  printf("[journal ring: header-only switches, a small ring (wrap, full, too big), the close and the journal bound while the leader is held]\n");
  /* 1. header-only switches */
  {
    tdir_t d;
    tdir_new(&d, "jrhdr");
    store_t *s = jr_open(&d, true, 42);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    CHECK_EQ(store_checkpoint(s), 0);
    CHECK_EQ(store_checkpoint(s), 0);
    CHECK_EQ(store_checkpoint_clean(s), 0);
    CHECK_EQ(store_checkpoint_clean(s), 0);
    store_test_jw_hook = jh_hook;                                          /* a checkpoint whose only bytes are the header of its file: it waits for them */
    atomic_store(&g_jh_hold, 1);
    jr_call_t ck = { .fn = jc_ckpt, .s = s };
    CHECK(jr_start(&ck));
    CHECK(jh_wait_in());
    usleep(50000);
    CHECK(!atomic_load(&ck.done));
    atomic_store(&g_jh_hold, 0);
    pthread_join(ck.th, NULL);
    CHECK_EQ(ck.r, 0);
    jr_hooks_off();
    CHECK_EQ(store_close(s), 0);
    s = jr_open(&d, false, 42);
    CHECK(s != NULL);
    if (s) { check_consistent(s, "header-only"); CHECK_EQ(store_close(s), 0); }
    /* kill -9 at the leader's steps while checkpoints switch the journal */
    for (int step = 1; step <= 2; step++)
      for (int n = 1; n <= 4; n++) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
          store_t *c = jr_open(&d, false, 42);
          if (!c) _exit(2);
          store_test_jw_hook = jh_hook;
          atomic_store(&g_jh_kill_n, n);
          atomic_store(&g_jh_kill_step, step);
          for (int k = 0; k < 8; k++) { (void)store_checkpoint(c); (void)put_i(c, 0, (uint32_t)(300 + k), 1, NULL); }
          kill(getpid(), SIGKILL);
          _exit(3);
        }
        waitpid(pid, NULL, 0);
        s = jr_open(&d, false, 42);
        CHECK(s != NULL);
        if (s) {
          store_stats_t st;
          store_stats(s, &st);
          CHECK(!st.recovery.rebuilt);
          check_consistent(s, "kill at a header");
          CHECK_EQ(store_close(s), 0);
        }
      }
    tdir_free(&d);
  }
  /* 2. a small ring */
  {
    tdir_t d;
    tdir_new(&d, "jrsmall");
    atomic_store(&store_test_jr_cap, 64u << 10);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_jr_cap, 0);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    for (uint32_t i = 0; i < 2000; i++) CHECK_EQ(put_i(s, 0, i % 500, 1 + i / 500, NULL), 0);    /* (about 1.5 MB of records through 64 KiB: many wraps) */
    store_stats_t st;
    store_stats(s, &st);
    CHECK(st.leader_bytes > (256u << 10));
    /* the ring full while the leader is held: the next writers wait before the mutex (admission), then inside it (drain) */
    store_test_jw_hook = jh_hook;
    atomic_store(&g_jh_hold, 1);
    jr_call_t a = { .fn = jc_put, .s = s, .a = 600, .b = 1 }, fill = { .fn = jc_fill, .s = s, .a = 601, .b = 200 };
    CHECK(jr_start(&a));
    CHECK(jh_wait_in());
    store_stats(s, &st);
    const uint64_t rw0 = st.ring_waits;
    CHECK(jr_start(&fill));
    for (int w = 0; w < 5000; w++) { store_stats(s, &st); if (st.ring_waits > rw0) break; usleep(1000); }
    CHECK(st.ring_waits > rw0 && !atomic_load(&fill.done));                /* (the ring is full of deferred records: the next call waits before the mutex) */
    atomic_store(&g_jh_hold, 0);
    pthread_join(a.th, NULL);
    pthread_join(fill.th, NULL);
    CHECK_EQ(fill.r, 0);
    jr_hooks_off();
    store_stats(s, &st);
    CHECK(st.ring_waits + st.ring_full_in_lock > 0);
    CHECK(st.ring_peak_bytes <= (64u << 10));
    /* a record bigger than half the ring is refused before anything is applied */
    {
      char n32[32][160];
      store_meta_t m32[32];
      store_known_t in[32];
      int res[32];
      for (int j = 0; j < 32; j++) { name_of(3000 + (uint32_t)j * 7 + 3, n32[j], sizeof(n32[j])); m32[j] = meta_of(3000 + (uint32_t)j * 7 + 3, 1); in[j].name = n32[j]; in[j].len = strlen(n32[j]); in[j].meta = &m32[j]; }
      CHECK_EQ(store_set_known_n(s, 0, in, 32, res, NULL), 0);
      int bad = 0;
      for (int j = 0; j < 32; j++) bad += res[j] != 0;
      CHECK_EQ(bad, 0);                                                    /* (32 long names fit: about 12 KB) */
    }
    check_consistent(s, "small ring");
    CHECK_EQ(store_close(s), 0);
    s = jr_open(&d, false, 42);
    if (s) {
      for (uint32_t i = 0; i < 500; i++) CHECK(verify_i(s, 0, i, 4));
      for (uint32_t k = 0; k < 201; k++) if (!verify_i(s, 0, 600 + k, 1)) { printf("  small ring: zone %u (found %d)\n", 600 + k, (int)(find_i(s, 0, 600 + k) != STORE_NONE)); CHECK(0); break; }
      check_consistent(s, "small ring reopen");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* 3. the close and store_journal_wait() while the leader is held: both wait for it, neither deadlocks */
  {
    tdir_t d;
    tdir_new(&d, "jrclose");
    store_opts_t o;
    small_opts(&o);
    o.scrub_interval_s = UINT32_MAX;
    o.journal_max_bytes = 16u << 10;
    store_t *s = jr_open_o(&d, true, 42, &o);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    for (uint32_t i = 0; i < 300; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    store_test_jw_hook = jh_hook;
    atomic_store(&g_jh_hold, 1);
    jr_call_t a = { .fn = jc_put, .s = s, .a = 900, .b = 1 }, jw = { .fn = jc_jwait, .s = s };
    CHECK(jr_start(&a));
    CHECK(jh_wait_in());
    CHECK(jr_start(&jw));
    usleep(100000);
    atomic_store(&g_jh_hold, 0);
    for (int w = 0; w < 10000 && !(atomic_load(&jw.done) && atomic_load(&a.done)); w++) usleep(1000);
    CHECK(atomic_load(&jw.done) && atomic_load(&a.done));
    pthread_join(a.th, NULL);
    pthread_join(jw.th, NULL);
    atomic_store(&g_jh_hold, 1);
    jr_call_t b = { .fn = jc_defer_nosettle, .s = s, .a = 901 };           /* (a deferred call: it returns at once, the flusher leads its write and is held in the hook) */
    CHECK(jr_start(&b));
    pthread_join(b.th, NULL);
    CHECK_EQ(b.r, 0);
    CHECK(jh_wait_in());
    jr_call_t cl = { .fn = jc_close, .s = s };
    CHECK(jr_start(&cl));
    usleep(100000);
    CHECK(!atomic_load(&cl.done));                                         /* (the close drains the ring: it waits for the held write) */
    atomic_store(&g_jh_hold, 0);
    pthread_join(cl.th, NULL);
    CHECK_EQ(cl.r, 0);
    jr_hooks_off();
    s = jr_open(&d, false, 42);
    if (s) {
      CHECK(verify_i(s, 0, 900, 1) && verify_i(s, 0, 901, 1));
      check_consistent(s, "close while held");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
}

/* (4.2 tests 13, 15, 17) the journal's floor on the free space: images are refused below the reserve + jr_floor() (the degraded mode records zones), records below jr_floor()
 * (-ENOSPC before anything is applied); a refusal that more room ends passes at once (the probe again); a checkpoint of an overwrite on UFS does not raise the floor; the probe is
 * made by the writers while the flusher is held in a commit. */
static _Atomic int g_jr_probes;
static int64_t g_jr_free;
static int64_t jr_fs_free(void) { atomic_fetch_add(&g_jr_probes, 1); return g_jr_free; }
static int64_t jr_fs_total(void) { return 64ll << 20; }               /* (64 MiB: the floor is capped at 8 MiB, the slack) */
static _Atomic int g_cm_hold;
static void jr_commit_hold(int step) { if (step == 2) while (atomic_load(&g_cm_hold)) usleep(500); }
static void test_jr_space(void) {
  printf("[journal ring: the journal's floor on the free space, the probe outside the mutex]\n");
  tdir_t d;
  tdir_new(&d, "jrspace");
  store_t *s = jr_open(&d, true, 42);
  CHECK(s != NULL);
  if (!s) { tdir_free(&d); return; }
  store_stats_t st;
  store_stats(s, &st);
  const uint64_t floor = 8ull << 20, reserve = st.reserve_bytes;
  store_test_fs_total = jr_fs_total;
  store_test_fs_free = jr_fs_free;
  g_jr_free = (int64_t)(reserve + floor + (4u << 20));
  usleep(1100000);                                                         /* (the next call probes: a second since the last) */
  CHECK_EQ(put_i(s, 0, 1, 1, NULL), 0);
  CHECK(verify_i(s, 0, 1, 1));
  g_jr_free = (int64_t)(floor + (256u << 10));                             /* below the reserve + floor: images refused, the zone is kept without one */
  usleep(1100000);
  CHECK_EQ(put_i(s, 0, 2, 1, NULL), 0);
  store_zone_t zi;
  CHECK(store_zone_get(s, find_i(s, 0, 2), &zi) == 0 && zi.state == STORE_STATE_KNOWN);
  g_jr_free = 64u << 10;                                                   /* below the floor: no record */
  usleep(1100000);
  CHECK_EQ(put_i(s, 0, 3, 1, NULL), -ENOSPC);
  CHECK(find_i(s, 0, 3) == STORE_NONE);                                    /* (refused before the apply) */
  store_stats(s, &st);
  CHECK_EQ(st.journal_state, STORE_JOURNAL_OK);
  usleep(150000);                                                          /* (the probe inside the mutex is made at most every 100 ms) */
  g_jr_free = 1ll << 34;                                                   /* more room: the refusal probes again and the call passes at once */
  CHECK_EQ(put_i(s, 0, 4, 1, NULL), 0);
  CHECK(verify_i(s, 0, 4, 1));
  /* a checkpoint that overwrites (no growth) on a file system that is not copy-on-write takes no room: the floor does not move, the images are stored */
  if (strcmp(st.fstype, "zfs") != 0) {
    for (uint32_t i = 10; i < 600; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    CHECK_EQ(store_checkpoint(s), 0);
    for (uint32_t i = 10; i < 600; i++) CHECK_EQ(put_i(s, 0, i, 2, NULL), 0);       /* (every page dirty again: an overwrite of what the files hold) */
    g_jr_free = (int64_t)(reserve + floor + (512u << 10));                 /* (less than the dirty pages) */
    usleep(1100000);
    CHECK_EQ(store_checkpoint(s), 0);
    store_stats(s, &st);
    const uint64_t deg0 = st.degraded_puts;
    CHECK_EQ(put_i(s, 0, 700, 1, NULL), 0);
    store_stats(s, &st);
    CHECK_EQ(st.degraded_puts, deg0);
    CHECK(verify_i(s, 0, 700, 1));
  }
  /* the probe while the flusher is held in a commit */
  g_jr_free = 1ll << 34;
  atomic_store(&store_test_commit_hook, jr_commit_hold);
  atomic_store(&g_cm_hold, 1);
  usleep(300000);                                                          /* (the flusher's next commit stops in the hook) */
  const int p0 = atomic_load(&g_jr_probes);
  for (int k = 0; k < 30; k++) { CHECK_EQ(put_i(s, 0, (uint32_t)(800 + k), 1, NULL), 0); usleep(50000); }
  CHECK(atomic_load(&g_jr_probes) > p0);
  atomic_store(&g_cm_hold, 0);
  atomic_store(&store_test_commit_hook, NULL);
  store_test_fs_free = NULL;
  store_test_fs_total = NULL;
  check_consistent(s, "space");
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* (4.2 tests 10, 19) two stores in one process (the deferral of a thread is per store), STORE_SYNC_EVERY, the deferral without a flusher (refused), the slots (taken, freed by
 * store_defer(false) before a thread ends) */
static int jc_defer_put(jr_call_t *c) {
  int r = store_defer(c->s, true);
  if (r != 0) return r;
  r = put_i(c->s, 0, c->a, 1, NULL);
  if (r == 0) r = store_settle(c->s);
  (void)store_defer(c->s, false);
  return r;
}
static int jc_defer_hold(jr_call_t *c) {                                   /* (takes a slot and keeps it until c->flag is cleared) */
  int r = store_defer(c->s, true);
  atomic_store(&c->done, 2);
  while (atomic_load(&c->flag)) usleep(500);
  (void)store_defer(c->s, false);
  return r;
}
static void test_jr_multi(void) {
  printf("[journal ring: two stores, deferral per store and its slots, STORE_SYNC_EVERY, no flusher]\n");
  tdir_t da, db;
  tdir_new(&da, "jrma");
  tdir_new(&db, "jrmb");
  store_t *a = jr_open(&da, true, 42), *b = jr_open(&db, true, 42);
  CHECK(a && b);
  if (!a || !b) { if (a) store_close(a); if (b) store_close(b); tdir_free(&da); tdir_free(&db); return; }
  /* a thread that defers on a: its call on b waits (the leader of b is held: the call does not return before it) */
  CHECK_EQ(store_defer(a, true), 0);
  CHECK_EQ(put_i(a, 0, 1, 1, NULL), 0);
  store_test_jw_hook = jh_hook;
  atomic_store(&g_jh_hold, 1);
  jr_call_t hb = { .fn = jc_put, .s = b, .a = 2, .b = 1 };
  CHECK(jr_start(&hb));
  CHECK(jh_wait_in());
  jr_call_t nb = { .fn = jc_put, .s = b, .a = 3, .b = 1 };
  CHECK(jr_start(&nb));
  usleep(50000);
  CHECK(!atomic_load(&nb.done));
  atomic_store(&g_jh_hold, 0);
  pthread_join(hb.th, NULL);
  pthread_join(nb.th, NULL);
  jr_hooks_off();
  CHECK_EQ(store_settle(a), 0);
  CHECK_EQ(store_defer(a, false), 0);
  /* the slots: 32 threads hold one, one more gets -EBUSY (counted); one that leaves frees its slot */
  jr_call_t hold[32];
  for (int k = 0; k < 32; k++) {
    hold[k] = (jr_call_t){ .fn = jc_defer_hold, .s = a };
    atomic_store(&hold[k].flag, 1);
    CHECK(jr_start(&hold[k]));
    for (int w = 0; w < 2000 && atomic_load(&hold[k].done) != 2; w++) usleep(500);
  }
  CHECK_EQ(store_defer(a, true), -EBUSY);
  atomic_store(&hold[0].flag, 0);
  pthread_join(hold[0].th, NULL);
  CHECK_EQ(hold[0].r, 0);
  jr_call_t dp = { .fn = jc_defer_put, .s = a, .a = 10 };
  CHECK(jr_start(&dp));
  pthread_join(dp.th, NULL);
  CHECK_EQ(dp.r, 0);
  for (int k = 1; k < 32; k++) { atomic_store(&hold[k].flag, 0); pthread_join(hold[k].th, NULL); }
  CHECK(verify_i(a, 0, 10, 1));
  CHECK_EQ(store_close(a), 0);
  CHECK_EQ(store_close(b), 0);
  tdir_free(&da);
  tdir_free(&db);
  /* no flusher: deferral is refused (no background leader), the calls wait */
  {
    tdir_t d;
    tdir_new(&d, "jrnf");
    atomic_store(&store_test_no_flusher, true);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_no_flusher, false);
    if (s) {
      CHECK_EQ(store_defer(s, true), -EAGAIN);
      CHECK_EQ(put_i(s, 0, 1, 1, NULL), 0);
      store_stats_t st;
      store_stats(s, &st);
      CHECK_EQ(st.ring_unwritten_bytes, 0);
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* STORE_SYNC_EVERY: a call returns after its record and its sync; a power loss keeps it */
  {
    tdir_t d;
    tdir_new(&d, "jrevery");
    store_opts_t o;
    small_opts(&o);
    o.sync_policy = STORE_SYNC_EVERY;
    o.checkpoint_interval_ms = UINT32_MAX;
    o.scrub_interval_s = UINT32_MAX;
    store_t *s = jr_open_o(&d, true, 42, &o);
    if (s) {
      for (uint32_t i = 0; i < 30; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
      store_stats_t st;
      store_stats(s, &st);
      CHECK_EQ(st.committed_lsn, st.lsn);
      CHECK_EQ(store_close(s), 0);
      s = jr_open_o(&d, false, 77, &o);
      if (s) { for (uint32_t i = 0; i < 30; i++) CHECK(verify_i(s, 0, i, 1)); check_consistent(s, "every"); CHECK_EQ(store_close(s), 0); }
    }
    tdir_free(&d);
  }
}

/* (4.2 test 7, the rest) the extents of the ring all in use: the next writer waits before the mutex; a record that takes exactly the room that is left is reserved without a wait,
 * and the next one waits for the leader */
static uint64_t jr_unwritten(store_t *s) { store_stats_t st; store_stats(s, &st); return st.ring_unwritten_bytes; }
/* a zone made known whose name is exactly len bytes (labels of at most 63) */
static int jr_known_len(store_t *s, uint32_t id, size_t len) {
  char nm[300];
  int n = snprintf(nm, sizeof(nm), "k%06u", id);
  const int r = (int)len - n - 5, k = (r + 60) / 61;                     /* (the bytes of the labels and their dots before ".test") */
  for (int i = 0; i < k; i++) {
    const int lab = (r - k) / k + (i < (r - k) % k ? 1 : 0);
    nm[n++] = '.';
    memset(nm + n, 'a', (size_t)lab);
    n += lab;
  }
  memcpy(nm + n, ".test", 6);
  n += 5;
  if ((size_t)n != len) return -EINVAL;
  store_meta_t m = meta_of(900000 + id, 1);
  return store_set_known(s, 0, nm, len, &m, NULL);
}
static int jr_group(store_t *s, uint32_t base) {                           /* (32 zones with long names of one length: the record has the same size for every base) */
  char nm[32][160];
  store_meta_t m[32];
  store_known_t in[32];
  int res[32];
  for (int j = 0; j < 32; j++) { const uint32_t i = base + (uint32_t)j * 7; name_of(i, nm[j], sizeof(nm[j])); m[j] = meta_of(i, 1); in[j].name = nm[j]; in[j].len = strlen(nm[j]); in[j].meta = &m[j]; }
  int r = store_set_known_n(s, 0, in, 32, res, NULL);
  for (int j = 0; j < 32 && r == 0; j++) r = res[j];
  return r;
}
static void test_jr_edges(void) {
  printf("[journal ring: the extents all in use; a record that fits the room exactly]\n");
  /* 1. the extents: four at the most (test knob); the leader is held, a commit switches the journal (its wait holds one more extent): the next writer waits before the mutex */
  {
    tdir_t d;
    tdir_new(&d, "jrext");
    atomic_store(&store_test_jx_cap, 4);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_jx_cap, 0);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    for (uint32_t i = 0; i < 10; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
    CHECK_EQ(store_commit(s), 0);                                          /* (a commit makes the next journal file ahead: the next commit switches to it) */
    CHECK_EQ(put_i(s, 0, 11, 1, NULL), 0);
    store_stats_t st;
    store_stats(s, &st);
    const uint64_t sw0 = st.journal_commit_switches, w0 = st.ring_waits;
    store_test_jw_hook = jh_hook;
    atomic_store(&g_jh_hold, 1);
    jr_call_t a = { .fn = jc_put, .s = s, .a = 100, .b = 1 }, c = { .fn = jc_commit, .s = s }, b = { .fn = jc_put, .s = s, .a = 101, .b = 1 };
    CHECK(jr_start(&a));
    CHECK(jh_wait_in());
    CHECK(jr_start(&c));
    for (int w = 0; w < 3000; w++) { store_stats(s, &st); if (st.journal_commit_switches > sw0) break; usleep(1000); }
    CHECK(st.journal_commit_switches > sw0);                               /* (the commit switched: a second extent waits behind the held write) */
    CHECK(jr_start(&b));
    usleep(100000);
    store_stats(s, &st);
    CHECK(!atomic_load(&b.done) && st.ring_waits > w0);                    /* (no room among the extents: the writer waits before the mutex) */
    atomic_store(&g_jh_hold, 0);
    pthread_join(a.th, NULL);
    pthread_join(c.th, NULL);
    pthread_join(b.th, NULL);
    CHECK(a.r == 0 && c.r == 0 && b.r == 0);
    jr_hooks_off();
    check_consistent(s, "extents");
    CHECK_EQ(store_close(s), 0);
    s = jr_open(&d, false, 42);
    if (s) { CHECK(verify_i(s, 0, 100, 1) && verify_i(s, 0, 101, 1)); check_consistent(s, "extents reopen"); CHECK_EQ(store_close(s), 0); }
    tdir_free(&d);
  }
  /* 2. the exact fit: a 32 KiB ring (the admission's margin is an eighth of it), the leader held; deferred calls fill it until exactly the size of a group record is left (the last
   * ones are zones made known with names of a chosen length: their records grow by 8 bytes for 8 more bytes of name), the group is reserved with no wait and fills the ring, the
   * next call waits for the leader */
  {
    tdir_t d;
    tdir_new(&d, "jrexact");
    const uint64_t cap = 32u << 10;
    atomic_store(&store_test_jr_cap, cap);
    store_t *s = jr_open(&d, true, 42);
    atomic_store(&store_test_jr_cap, 0);
    CHECK(s != NULL);
    if (!s) { tdir_free(&d); return; }
    store_test_jw_hook = jh_hook;
    atomic_store(&g_jh_hold, 1);
    jr_call_t a = { .fn = jc_put, .s = s, .a = 1, .b = 1 };
    CHECK(jr_start(&a));
    CHECK(jh_wait_in());
    CHECK_EQ(store_defer(s, true), 0);                                     /* (this thread's calls do not wait: the ring fills while the leader is held) */
    uint64_t u = jr_unwritten(s);
    CHECK_EQ(jr_group(s, 1003), 0);                                        /* the size of a group record */
    const uint64_t L = jr_unwritten(s) - u;
    if (!(L >= cap / 8 && L <= cap / 4)) printf("  the group record is %llu bytes\n", (unsigned long long)L);
    CHECK(L >= cap / 8 && L <= cap / 4);
    uint32_t id = 0;
    u = jr_unwritten(s);
    CHECK_EQ(jr_known_len(s, id++, 80), 0);
    const uint64_t r80 = jr_unwritten(s) - u;
    u = jr_unwritten(s);
    CHECK_EQ(jr_known_len(s, id++, 88), 0);
    const uint64_t r88 = jr_unwritten(s) - u;
    if (r88 - r80 != 8) printf("  name records: %llu, %llu bytes\n", (unsigned long long)r80, (unsigned long long)r88);
    CHECK(r88 - r80 == 8);
    uint32_t z = 10;
    /* name records of 40 .. 248 bytes: sizes ra .. ra + rw (8 more for 8 more bytes) */
    const uint64_t ra = r80 - 40, rw = 208;
    while (cap - jr_unwritten(s) > L + 6 * (ra + rw) + 1500) CHECK_EQ(put_i(s, 0, z++, 1, NULL), 0);
    uint64_t x = cap - jr_unwritten(s) - L;                                /* (what must be taken before the group: k name records of sizes in [ra, ra + rw]) */
    const uint64_t k = (x + ra + rw - 1) / (ra + rw);
    CHECK(k >= 1 && k * ra <= x && x <= k * (ra + rw) && (x & 7) == 0);
    uint64_t rem = x - k * ra;
    for (uint64_t j = 0; j < k; j++) {
      const uint64_t extra = rem > rw ? rw : rem;
      rem -= extra;
      CHECK_EQ(jr_known_len(s, id++, (size_t)(40 + extra)), 0);
    }
    CHECK_EQ(cap - jr_unwritten(s), L);                                    /* exactly the group's room is left */
    store_stats_t st;
    store_stats(s, &st);
    const uint64_t w0 = st.ring_waits, f0 = st.ring_full_in_lock;
    CHECK_EQ(jr_group(s, 3003), 0);                                        /* it fits: no wait */
    store_stats(s, &st);
    CHECK_EQ(st.ring_unwritten_bytes, cap);
    CHECK(st.ring_waits == w0 && st.ring_full_in_lock == f0);
    (void)store_defer(s, false);
    jr_call_t b = { .fn = jc_put, .s = s, .a = 5000, .b = 1 };
    CHECK(jr_start(&b));
    usleep(100000);
    CHECK(!atomic_load(&b.done));                                          /* (the ring is full: the next call waits for the leader) */
    atomic_store(&g_jh_hold, 0);
    pthread_join(a.th, NULL);
    pthread_join(b.th, NULL);
    CHECK(a.r == 0 && b.r == 0);
    jr_hooks_off();
    check_consistent(s, "exact fit");
    CHECK_EQ(store_close(s), 0);
    s = jr_open(&d, false, 42);
    if (s) {
      CHECK(find_i(s, 0, 3003) != STORE_NONE && verify_i(s, 0, 5000, 1));
      check_consistent(s, "exact fit reopen");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
}

/* (4.2 test 17, the estimate) the free space the store reckons with is the file system's less what the ring holds and has not written yet */
static void test_jr_estimate(void) {
  printf("[journal ring: the estimate of the free space is statfs less the ring's unwritten bytes]\n");
  tdir_t d;
  tdir_new(&d, "jrest");
  store_t *s = jr_open(&d, true, 42);
  CHECK(s != NULL);
  if (!s) { tdir_free(&d); return; }
  store_test_fs_total = jr_fs_total;
  store_test_fs_free = jr_fs_free;
  g_jr_free = 1ll << 33;
  store_test_jw_hook = jh_hook;
  atomic_store(&g_jh_hold, 1);
  jr_call_t a = { .fn = jc_put, .s = s, .a = 1, .b = 1 };
  CHECK(jr_start(&a));
  CHECK(jh_wait_in());
  CHECK_EQ(store_defer(s, true), 0);
  for (uint32_t i = 10; i < 40; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  store_test_probe(s);
  store_stats_t st;
  store_stats(s, &st);
  CHECK(st.ring_unwritten_bytes > 0);
  CHECK_EQ(st.space_estimate_bytes, (int64_t)((1ull << 33) - st.ring_unwritten_bytes));
  (void)store_defer(s, false);
  atomic_store(&g_jh_hold, 0);
  pthread_join(a.th, NULL);
  jr_hooks_off();
  CHECK_EQ(store_commit(s), 0);
  store_test_probe(s);
  store_stats(s, &st);
  CHECK_EQ(st.space_estimate_bytes, (int64_t)(1ull << 33));                /* (all written: statfs itself) */
  store_test_fs_free = NULL;
  store_test_fs_total = NULL;
  CHECK_EQ(store_close(s), 0);
  tdir_free(&d);
}

/* (4.2 test 18) a write that put half of its span in the file and failed is written again whole at the same offset: the journal file is byte for byte that of a store that did the
 * same calls with no fault */
static void test_jr_partial(void) {
  printf("[journal ring: a span half written, then written again whole: the journal file is the same bytes]\n");
  tdir_t da, db;
  tdir_new(&da, "jrpa");
  tdir_new(&db, "jrpb");
  atomic_store(&store_test_no_flusher, true);                              /* (no commit switches the journal on its own time: both stores have one file of records) */
  store_t *a = jr_open(&da, true, 42), *b = jr_open(&db, true, 42);
  atomic_store(&store_test_no_flusher, false);
  CHECK(a && b);
  if (!a || !b) { if (a) store_close(a); if (b) store_close(b); tdir_free(&da); tdir_free(&db); return; }
  for (uint32_t i = 0; i < 50; i++) CHECK_EQ(put_i(b, 0, i, 1, NULL), 0);
  store_test_jw_fault = jf_fault;
  for (uint32_t i = 0; i < 50; i++) {
    if (i == 20) { atomic_store(&g_jf_err, -1); atomic_store(&g_jf_n, 1); }     /* (the span of zone 20's record: half reaches the file, the write fails, the retry writes it all) */
    CHECK_EQ(put_i(a, 0, i, 1, NULL), 0);
  }
  jr_hooks_off();
  store_stats_t st;
  store_stats(a, &st);
  CHECK(st.leader_retries >= 1 && st.journal_state == STORE_JOURNAL_OK);
  CHECK_EQ(store_commit(a), 0);
  CHECK_EQ(store_commit(b), 0);
  char pa[700], pb[700];
  CHECK(jrn_newest(&da, pa, sizeof(pa)) && jrn_newest(&db, pb, sizeof(pb)));
  CHECK(file_tail_equal(pa, pb, 64));                                      /* (past the file header, which holds the store's uuid) */
  CHECK_EQ(store_close(a), 0);
  CHECK_EQ(store_close(b), 0);
  tdir_free(&da);
  tdir_free(&db);
}

/* (review defect 1) the flusher does not spin in JW_NOSPACE (it retries at most every 20 ms) nor in JW_FAILED (once a second), while records wait for a commit that is not made */
static void test_jr_flusher_states(void) {
  printf("[journal ring: the flusher's loop in the states nospace and failed]\n");
  tdir_t d;
  tdir_new(&d, "jrfl");
  store_t *s = jr_open(&d, true, 42);
  CHECK(s != NULL);
  if (!s) { tdir_free(&d); return; }
  for (uint32_t i = 0; i < 10; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  store_test_jw_fault = jf_fault;
  atomic_store(&g_jf_err, ENOSPC);
  atomic_store(&g_jf_n, -1);
  CHECK_EQ(put_i(s, 0, 100, 1, NULL), -ENOSPC);
  uint64_t l0 = atomic_load(&store_test_fl_loops);
  usleep(500000);
  uint64_t l1 = atomic_load(&store_test_fl_loops);
  printf("  nospace: %llu rounds of the flusher in 0.5 s\n", (unsigned long long)(l1 - l0));
  CHECK(l1 - l0 <= 60);
  atomic_store(&g_jf_err, EIO);                                            /* (the retry meets EIO: three tries, then failed) */
  store_stats_t st;
  for (int w = 0; w < 5000; w++) { store_stats(s, &st); if (st.journal_state == STORE_JOURNAL_FAILED) break; usleep(1000); }
  CHECK_EQ(st.journal_state, STORE_JOURNAL_FAILED);
  l0 = atomic_load(&store_test_fl_loops);
  usleep(1500000);
  l1 = atomic_load(&store_test_fl_loops);
  printf("  failed: %llu rounds of the flusher in 1.5 s\n", (unsigned long long)(l1 - l0));
  CHECK(l1 - l0 <= 4);
  jr_hooks_off();
  (void)store_close(s);
  tdir_free(&d);
}

/* (review defect 2, N8) a segment whose removal record is in the ring when the journal cannot be written keeps its file, marked; once the journal is written again a later pass
 * removes the file */
static void test_jr_seg_pending(void) {
  printf("[journal ring: a segment's file waits for its record, then goes]\n");
  tdir_t d;
  tdir_new(&d, "jrsegp");
  store_opts_t o;
  small_opts(&o);
  o.seg_size = 64u << 10;
  o.compact_rate = UINT64_MAX;
  o.compact_min_dead_pct = 100;                                            /* (no victim for the cleaner: only the removal of the empty segment) */
  o.checkpoint_interval_ms = UINT32_MAX;
  o.scrub_interval_s = UINT32_MAX;
  store_t *s = jr_open_o(&d, true, 42, &o);
  CHECK(s != NULL);
  if (!s) { tdir_free(&d); return; }
  for (uint32_t i = 0; i < 200; i++) CHECK_EQ(put_i(s, 0, i, 1, NULL), 0);
  for (uint32_t i = 0; i < 120; i++) { char nm[160]; name_of(i, nm, sizeof(nm)); CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0); }   /* (the first segment holds only dead records) */
  char p1[700];
  fpath(&d, "seg.1", p1, sizeof(p1));
  struct stat sb;
  CHECK_EQ(stat(p1, &sb), 0);
  CHECK_EQ(store_tick(s), 0);                                              /* (the segment is draining) */
  CHECK_EQ(store_checkpoint(s), 0);                                        /* (a checkpoint after the drain: it may go now) */
  store_stats_t st;
  store_stats(s, &st);
  const uint64_t fr0 = st.compact_segs_freed;
  store_test_jw_fault = jf_fault;
  atomic_store(&g_jf_err, ENOSPC);
  atomic_store(&g_jf_n, -1);
  (void)store_tick(s);                                                     /* the removal's record is reserved; its write meets ENOSPC: the file stays */
  store_stats(s, &st);
  CHECK_EQ(st.journal_state, STORE_JOURNAL_NOSPACE);
  CHECK_EQ(stat(p1, &sb), 0);
  CHECK_EQ(st.compact_segs_freed, fr0);
  atomic_store(&g_jf_n, 0);                                                /* the room comes back: the flusher's retry writes the record */
  for (int w = 0; w < 5000; w++) { store_stats(s, &st); if (st.journal_state == STORE_JOURNAL_OK) break; usleep(1000); }
  CHECK_EQ(st.journal_state, STORE_JOURNAL_OK);
  jr_hooks_off();
  (void)store_tick(s);                                                     /* a later pass: the file goes */
  store_stats(s, &st);
  CHECK(stat(p1, &sb) != 0 || st.compact_segs_freed > fr0);
  CHECK(st.compact_segs_freed > fr0);
  for (uint32_t i = 120; i < 200; i++) CHECK(verify_i(s, 0, i, 1));
  check_consistent(s, "segment pending");
  CHECK_EQ(store_close(s), 0);
  s = jr_open_o(&d, false, 42, &o);
  if (s) { for (uint32_t i = 120; i < 200; i++) CHECK(verify_i(s, 0, i, 1)); check_consistent(s, "segment pending reopen"); CHECK_EQ(store_close(s), 0); }
  tdir_free(&d);
}

/* (review: test_jr_multi) a thread that defers on store a waits for its call on store b; (4.2 test 19) after the flusher stopped (the first step of a close) a deferring thread's
 * calls wait */
typedef struct { store_t *a, *b; _Atomic int done; int r; pthread_t th; } jr_two_t;
static void *jr_two_main(void *arg) {
  jr_two_t *t = arg;
  int r = store_defer(t->a, true);
  if (r == 0) r = put_i(t->a, 0, 50, 1, NULL);                             /* (on a: no wait) */
  if (r == 0) r = put_i(t->b, 0, 51, 1, NULL);                             /* (on b: it waits for its record) */
  (void)store_settle(t->a);
  (void)store_defer(t->a, false);
  t->r = r;
  atomic_store(&t->done, 1);
  return NULL;
}
static int jc_defer_one(jr_call_t *c) {
  int r = store_defer(c->s, true);
  atomic_store(&c->flag, r == 0 ? 1 : -1);
  while (atomic_load(&c->flag) == 1) usleep(300);                          /* (the test stops the flusher meanwhile) */
  if (r == 0) r = put_i(c->s, 0, c->a, 1, NULL);
  (void)store_defer(c->s, false);
  return r;
}
static void test_jr_defer_more(void) {
  printf("[journal ring: deferral is per store; it ends with the flusher]\n");
  tdir_t da, db;
  tdir_new(&da, "jrda");
  tdir_new(&db, "jrdb");
  store_t *a = jr_open(&da, true, 42), *b = jr_open(&db, true, 42);
  CHECK(a && b);
  if (!a || !b) { if (a) store_close(a); if (b) store_close(b); tdir_free(&da); tdir_free(&db); return; }
  store_test_jw_hook = jh_hook;
  atomic_store(&g_jh_hold, 1);
  jr_call_t hb = { .fn = jc_put, .s = b, .a = 2, .b = 1 };
  CHECK(jr_start(&hb));
  CHECK(jh_wait_in());                                                     /* (b's leader is held) */
  jr_two_t t = { .a = a, .b = b };
  CHECK_EQ(pthread_create(&t.th, NULL, jr_two_main, &t), 0);
  usleep(150000);
  CHECK(!atomic_load(&t.done));                                            /* (deferring on a does not defer on b) */
  atomic_store(&g_jh_hold, 0);
  pthread_join(hb.th, NULL);
  pthread_join(t.th, NULL);
  CHECK_EQ(t.r, 0);
  CHECK(verify_i(a, 0, 50, 1) && verify_i(b, 0, 51, 1));
  /* deferral ends with the flusher */
  jr_call_t x = { .fn = jc_defer_one, .s = a, .a = 60 };
  CHECK(jr_start(&x));
  for (int w = 0; w < 3000 && atomic_load(&x.flag) == 0; w++) usleep(1000);
  CHECK_EQ(atomic_load(&x.flag), 1);
  store_test_stop_flusher(a);
  atomic_store(&g_jh_hold, 1);
  jr_call_t ha = { .fn = jc_put, .s = a, .a = 61, .b = 1 };
  CHECK(jr_start(&ha));
  CHECK(jh_wait_in());
  atomic_store(&x.flag, 2);                                                /* (its put now: the flusher is gone, the call waits for the held leader) */
  usleep(150000);
  CHECK(!atomic_load(&x.done));
  atomic_store(&g_jh_hold, 0);
  pthread_join(ha.th, NULL);
  pthread_join(x.th, NULL);
  CHECK_EQ(x.r, 0);
  store_stats_t st;
  store_stats(a, &st);
  CHECK(!st.flusher && st.ring_unwritten_bytes == 0);
  jr_hooks_off();
  CHECK_EQ(store_close(a), 0);
  CHECK_EQ(store_close(b), 0);
  tdir_free(&da);
  tdir_free(&db);
}

/* (review: test_group_journal) a group of 64 entries is two records; spans of 200 bytes cut them; kill -9 after each span: after the replay the group's zones are a prefix of the
 * entries (the records that are whole), and some kills keep the first record only */
static void test_jr_group_torn(void) {
  printf("[journal ring: a group whose records are cut by the spans of the write, kill -9 after each span]\n");
  int parts = 0, whole = 0, none = 0, bad = 0;
  for (int n = 1; n < 400 && !bad; n++) {
    tdir_t d;
    tdir_new(&d, "jrgt");
    store_t *s = jr_open(&d, true, 42);
    if (!s) { tdir_free(&d); break; }
    for (uint32_t i = 0; i < 100; i++) (void)put_i(s, 0, i, 1, NULL);
    (void)store_close(s);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
      atomic_store(&store_test_no_flusher, true);
      store_t *c = jr_open(&d, false, 42);
      if (!c) _exit(2);
      gk_t g[64];
      store_known_t in[64];
      int r[64];
      for (unsigned j = 0; j < 64; j++) { name_of(1000 + j, g[j].nm, sizeof(g[j].nm)); g[j].m = meta_of(1000 + j, 1); in[j].name = g[j].nm; in[j].len = strlen(g[j].nm); in[j].meta = &g[j].m; }
      atomic_store(&store_test_jw_run, 200);
      store_test_jw_hook = jh_hook;
      atomic_store(&g_jh_kill_n, n);
      atomic_store(&g_jh_kill_step, 2);
      if (store_set_known_n(c, 0, in, 64, r, NULL) != 0) _exit(3);
      _exit(0);                                                            /* (past the last span) */
    }
    int stt = 0;
    waitpid(pid, &stt, 0);
    const bool killed = WIFSIGNALED(stt);
    s = jr_open(&d, false, 42);
    if (s) {
      unsigned found = 0;
      bool prefix = true;
      for (uint32_t j = 0; j < 64; j++) {
        const bool f = find_i(s, 0, 1000 + j) != STORE_NONE;
        if (f && found != j) prefix = false;
        if (f) found++;
      }
      if (!prefix) { bad++; printf("  span %d: the group's zones are not a prefix\n", n); }
      if (found == 64) whole++; else if (found == 0) none++; else parts++;
      store_check_report_t rep;
      if (store_check(s, &rep) != 0) { bad++; printf("  span %d: store_check: %s\n", n, rep.first_error); }
      store_close(s);
    }
    tdir_free(&d);
    if (!killed) break;
  }
  printf("  %d whole, %d none, %d in part (a prefix)\n", whole, none, parts);
  CHECK_EQ(bad, 0);
  CHECK(parts > 0 && whole > 0 && none > 0);
}

int main(void) {
  const char *base = getenv("KARIDNS_STORE_TESTDIR");
  snprintf(g_base, sizeof(g_base), "%s/store_test.%d", base && *base ? base : ".", (int)getpid());
  rm_rf(g_base);
  if (mkdir(g_base, 0700) != 0) { perror("mkdir base"); return 2; }
  bool big = getenv("KARIDNS_STORE_BIG") && getenv("KARIDNS_STORE_BIG")[0] == '1';
  int iters = store_long() ? 200 : 75;                    /* (every 25 iterations the loop starts on a new store: three stores of kills in the default run) */
  if (getenv("KARIDNS_STORE_KILL_ITERS")) iters = atoi(getenv("KARIDNS_STORE_KILL_ITERS"));
  if (UNDER_TSAN && !getenv("KARIDNS_STORE_KILL_ITERS")) iters = 25;
  uint32_t n = UNDER_ASAN || UNDER_TSAN ? 100000 : 100000;
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("test_store: base %s\n", g_base);

  g_verbose = getenv("KARIDNS_STORE_VERBOSE") != NULL;
  const char *cases = getenv("KARIDNS_STORE_CASES");      /* comma-less filter: run only the cases whose tag occurs in it */
#define WANT(tag) (!cases || strstr(cases, tag))
  if (WANT("prim")) test_primitives();
  if (WANT("basic")) { test_basic(STORE_MODE_MAP); test_basic(STORE_MODE_COPY); }
  if (WANT("views")) test_views_full();
  if (WANT("commit")) test_commit_and_rotation();
  if (WANT("churn")) test_churn();
  if (WANT("unclean")) test_unclean_small();
  if (WANT("scale")) {
    test_scale(n, false, STORE_MODE_MAP);
    test_scale(n / 4, true, STORE_MODE_COPY);
    if (big) test_scale(1000000, true, STORE_MODE_MAP);
  }
  if (WANT("scalecopy")) { test_scale(n / 4, false, STORE_MODE_COPY); test_scale(n / 4, true, STORE_MODE_MAP); }
  if (WANT("damage")) test_damage_cells();
  if (WANT("repair")) test_repair();
  if (WANT("super")) test_superblock_damage();
  if (WANT("forge")) { test_forged_superblock(); test_forged_journal(); test_free_list_head(); }
  if (WANT("vis")) test_visibility();
  if (WANT("reuse")) test_reuse_after_grace();
  if (WANT("nosleep")) test_reader_nosleep();
  if (WANT("review")) test_review_fixes();
  if (WANT("growfail")) test_growth_sync_fails();
  if (WANT("cleanck")) { test_clean_checkpoint(); test_clean_then_growth(); }
  if (WANT("full")) test_disk_full();
  if (WANT("compact")) { test_compact(STORE_MODE_MAP); test_compact(STORE_MODE_COPY); test_compact_pinned(); test_compact_tick(); test_compact_open_segment(); test_nx_reclaim(); }
  if (WANT("space")) { test_space(STORE_MODE_MAP); test_space(STORE_MODE_COPY); test_append_fault(); }
  if (WANT("xfrw")) test_xfr_writers();
  if (WANT("scrub")) { test_scrub(STORE_MODE_MAP); test_scrub(STORE_MODE_COPY); test_scrub_tick(); }
  if (WANT("opendef")) test_open_defaults();
  if (WANT("errring")) { test_err_ring(); test_err_index(); }
  if (WANT("badimg")) test_bad_image_hook();
  if (WANT("raclose")) test_readahead_close();
  if (WANT("resident")) { test_resident(STORE_MODE_MAP); test_resident(STORE_MODE_COPY); test_hot_list(); }
  if (WANT("rbuf")) test_rbuf();
  if (WANT("smallfs") && getenv("KARIDNS_STORE_SMALLFS")) test_smallfs(getenv("KARIDNS_STORE_SMALLFS"));
  if (WANT("zfs") && getenv("KARIDNS_STORE_ZFS_128K")) test_zfs_dir(getenv("KARIDNS_STORE_ZFS_128K"), true, "128K dataset");
  if (WANT("zfs") && getenv("KARIDNS_STORE_ZFS_16K")) test_zfs_dir(getenv("KARIDNS_STORE_ZFS_16K"), false, "16K dataset");
  if (WANT("openbench") && getenv("KARIDNS_STORE_OPENBENCH")) test_open_bench(strtoull(getenv("KARIDNS_STORE_OPENBENCH"), NULL, 10));
  if (WANT("group")) { test_group_commit(STORE_MODE_MAP); test_group_commit(STORE_MODE_COPY); test_group_journal(); }
  if (WANT("kill")) test_kill_loop(iters, 0);
  if (WANT("kgrp")) test_kill_loop(UNDER_TSAN ? 25 : 50, 2);
  if (WANT("nowait")) { test_no_wait_in_lock(STORE_MODE_MAP); test_no_wait_in_lock(STORE_MODE_COPY); test_growth_catchup(); test_retire_after_unlock(); }
  if (WANT("ixwait")) { test_reserve_survives_growth(); test_index_wait(); }
  if (WANT("jbound")) { test_journal_bound(STORE_MODE_MAP); test_journal_bound(STORE_MODE_COPY); }
  if (WANT("jboost")) { test_journal_boost(); test_journal_boost_crash(); }
  if (WANT("kfz")) test_kill_loop(UNDER_TSAN ? 25 : 50, 3);
  if (WANT("kgrow")) test_kill_loop(UNDER_TSAN ? 20 : 50, 4);
  if (WANT("kjsw")) { test_kill_loop(UNDER_TSAN ? 20 : 50, 5); test_commit_switch(); }
  if (WANT("kjr")) test_kill_loop(UNDER_TSAN ? 20 : 60, 6);
  if (WANT("jring")) { test_jr_ack(); test_jr_kill_after_return(); test_jr_states(true); test_jr_states(false); test_jr_rule_t(); test_jr_ring(); test_jr_space(); test_jr_multi(); test_jr_edges(); test_jr_estimate(); test_jr_partial(); test_jr_flusher_states(); test_jr_seg_pending(); test_jr_defer_more(); test_jr_group_torn(); }
  if (WANT("priv")) test_private_tables();
  if (WANT("clk")) {
    int citers = getenv("KARIDNS_STORE_KILLC_ITERS") ? atoi(getenv("KARIDNS_STORE_KILLC_ITERS")) : (UNDER_TSAN ? 25 : store_long() ? 100 : 50);
    test_kill_loop(citers, 1);
  }
  if (WANT("cconc")) { test_compact_conc(STORE_MODE_MAP); test_compact_conc(STORE_MODE_COPY); }
  if (WANT("conc")) { test_concurrent(STORE_MODE_MAP); test_concurrent(STORE_MODE_COPY); }
#undef WANT

  rm_rf(g_base);
  printf("\ntest_store: %d checks, %d failed\n", g_checks, g_failed);
  return g_failed ? 1 : 0;
}

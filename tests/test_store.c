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
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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
  /* the journal stays bounded: many mutations, the journal is rotated by size */
  uint64_t cp0 = st.checkpoints;
  uint64_t maxj = 0;
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

static void *reader_main(void *arg) {
  rarg_t *a = arg;
  conc_t *c = a->c;
  store_t *s = c->s;
  uint64_t seen[NSTABLE];
  memset(seen, 0, sizeof(seen));
  uint64_t rng = (uint64_t)a->id * 7919 + 1;
  uint8_t *copy = malloc(2048);
  while (!atomic_load(&c->stop)) {
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
  flip_byte(p, (off_t)(ZT_HDR + (uint64_t)zc * 64 + 9));
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
  flip_byte(p, (off_t)(ZT_HDR + (uint64_t)zdd * 64 + 30 + 3));
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
  flip_byte(p, (off_t)(ZT_HDR + (uint64_t)zc * 64 + 9));                 /* damaged cell */
  flip_byte(p, (off_t)(ZT_HDR + (uint64_t)zd * 64 + 31));                /* damaged name -> CRC */
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
    for (uint32_t i = 450; i < 700; i++) if (put_i(c, 0, i, 1, NULL) != 0) _exit(4);
    _exit(0);                                                            /* no close, no commit */
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  /* find the newest journal and cut it in the middle of a record */
  char jp[700];
  uint32_t best = 0;
  for (uint32_t g = 1; g < 100; g++) { struct stat sbuf; snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, g); if (stat(jp, &sbuf) == 0) best = g; }
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

enum { OP_PUT, OP_DEL, OP_KNOWN, OP_FLAGS, OP_CURSOR, OP_CKPT, OP_NONE };
static int op_kind(uint64_t K, uint32_t *i) {
  uint64_t r = mix64(K * 0x9e3779b97f4a7c15ull + 12345);
  *i = (uint32_t)((r >> 16) % KNZ);
  uint32_t p = (uint32_t)(r % 100);
  if (p < 58) return OP_PUT;
  if (p < 72) return OP_DEL;
  if (p < 82) return OP_KNOWN;
  if (p < 91) return OP_FLAGS;
  if (p < 96) return OP_CURSOR;
  if (p < 98) return OP_CKPT;
  return OP_NONE;
}
static uint16_t op_flags(uint64_t K) { return (uint16_t)((mix64(K) >> 7) & 0x3f); }

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
  case OP_FLAGS: {
    uint32_t z = find_i(s, view, i);
    if (z == STORE_NONE) return 0;
    uint16_t f = op_flags(K);
    return store_set_flags(s, z, f, (uint16_t)(0x3f & ~f));
  }
  case OP_CURSOR: return store_set_cursor(s, 3, K, &K, 8);
  case OP_CKPT: return store_checkpoint(s);
  default: return 0;
  }
}
static void model_do_op(model_t *m, uint64_t K) {
  uint32_t i;
  int k = op_kind(K, &i);
  mz_t *z = &m->z[i];
  switch (k) {
  case OP_PUT: z->exists = 1; z->known = 0; z->ver = K; z->flags = op_flags(K); break;
  case OP_DEL: memset(z, 0, sizeof(*z)); break;
  case OP_KNOWN: z->exists = 1; z->known = 1; z->ver = K; z->flags = op_flags(K); break;
  case OP_FLAGS: if (z->exists) z->flags = op_flags(K); break;
  case OP_CURSOR: m->cursor_valid = true; m->cursor = K; break;
  default: break;
  }
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

typedef struct { _Atomic uint64_t begun, done, acked; } shm_t;

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
  store_test_crash_countdown = countdown;
  store_t *s = NULL;
  if (store_open(fd, &o, &s) != 0) _exit(11);
  for (uint64_t K = K0; K < K0 + count; K++) {
    atomic_store(&shm->begun, K + 1);
    if (store_do_op(s, K) != 0) _exit(12);
    atomic_store(&shm->done, K + 1);
    if ((K & 7) == 7) {
      if (store_commit(s) != 0) _exit(13);
      atomic_store(&shm->acked, K + 1);
    }
  }
  _exit(0);                                                              /* leaves the store unclean, like a crash */
}

static void test_kill_loop(int iters) {
  printf("[kill -9 loop: %d iterations]\n", iters);
  tdir_t d;
  tdir_new(&d, "kill");
  shm_t *shm = mmap(NULL, sizeof(*shm), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  CHECK(shm != MAP_FAILED);
  if (shm == MAP_FAILED) { tdir_free(&d); return; }
  model_t *model = calloc(1, sizeof(*model)), *tmp = calloc(1, sizeof(*tmp));
  uint64_t K0 = 0, boot = 42, rng = 20261114;
  int fresh = 0, crashed = 0, countdown_hits = 0, tampered = 0, older = 0, torn = 0, exact = 0, replayed_total = 0, lost_ops = 0;
  for (int it = 0; it < iters; it++) {
    if (it % 25 == 0) {
      /* a new store: the first iterations grow the index through several generations */
      tdir_free(&d);
      tdir_new(&d, "kill");
      store_opts_t o;
      small_opts(&o);
      o.boot_id = boot;
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
    uint64_t count = 700 + (rng >> 40) % 400;
    atomic_store(&shm->begun, K0);
    atomic_store(&shm->done, K0);
    atomic_store(&shm->acked, K0);
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
      for (uint32_t g = 1; g < 400; g++) { struct stat sbuf; snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, g); if (stat(jp, &sbuf) == 0) best = g; }
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
    store_t *s = NULL;
    int r = store_open(d.fd, &o, &s);
    if (r != 0) { printf("  iteration %d: open failed %d\n", it, r); CHECK(0); break; }
    store_stats_t st;
    store_stats(s, &st);
    if (st.recovery.used_older_super) older++;
    if (st.recovery.journal_torn) torn++;
    replayed_total += (int)st.recovery.records_replayed;
    store_check_report_t rep;
    int cr = store_check(s, &rep);
    if (cr != 0) { printf("  iteration %d: store_check: %s\n", it, rep.first_error); CHECK(0); store_close(s); break; }
    if (tamper) {
      CHECK(st.recovery.rebuilt || st.recovery.was_clean);
      model_from_store(s, model);
      K0 = begun;                                                       /* absolute ops: the generator needs no state */
    } else {
      CHECK(!st.recovery.rebuilt);
      /* the state must be the model after n ops, acked <= n <= begun */
      memcpy(tmp, model, sizeof(*tmp));
      for (uint64_t K = K0; K < acked; K++) model_do_op(tmp, K);
      uint64_t found = UINT64_MAX;
      for (uint64_t n = acked; n <= begun && found == UINT64_MAX; n++) {
        if (model_matches(s, tmp, false)) found = n;
        else if (n < begun) model_do_op(tmp, n);
      }
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
         "  %d replayed records in total, %d exact-end matches, %d begun-but-lost operations\n",
         fresh, crashed, countdown_hits, tampered, older, torn, replayed_total, exact, lost_ops);
  free(model);
  free(tmp);
  munmap(shm, sizeof(*shm));
  tdir_free(&d);
}

/* disk full: RLIMIT_FSIZE makes appends and journal writes fail with EFBIG */
static void test_disk_full(void) {
  printf("[disk full (RLIMIT_FSIZE)]\n");
  tdir_t d;
  tdir_new(&d, "full");
  store_opts_t o;
  small_opts(&o);
  o.create = true;
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
    for (uint32_t g = 1; g < 100; g++) { struct stat sb; snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, g); if (stat(jp, &sb) == 0) best = g; }
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
static void test_growth_sync_fails(void) {
  printf("[an index growth whose sync fails]\n");
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
    store_t *c = NULL;
    if (store_open(d.fd, &o, &c) != 0) _exit(2);
    store_view_add(c, "default");
    int rc = 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < 5000; i++) {
      store_test_fail_commit = 1;
      rc = put_i(c, 0, i, 1, NULL);
      store_test_fail_commit = 0;
      if (rc != 0) break;
      n++;
    }
    store_stats_t st;
    store_stats(c, &st);
    uint64_t out[4] = { (uint64_t)(int64_t)rc, st.ix_gen, st.zones_stored, n };
    if (write(pfd[1], out, sizeof(out)) != (ssize_t)sizeof(out)) _exit(3);
    _exit(0);                                                            /* no close: what the journal holds is what the next open has */
  }
  int stt = 0;
  waitpid(pid, &stt, 0);
  CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
  uint64_t got[4] = { 0, 0, 0, 0 };
  CHECK(read(pfd[0], got, sizeof(got)) == (ssize_t)sizeof(got));
  close(pfd[0]);
  close(pfd[1]);
  CHECK_EQ((int64_t)got[0], -EIO);                                       /* (the put that wanted room was refused) */
  CHECK(got[1] >= 2);                                                    /* (... and the live index is the new generation) */
  o.create = false;
  store_t *s = NULL;
  CHECK_EQ(store_open(d.fd, &o, &s), 0);
  if (s) {
    store_stats_t st;
    store_stats(s, &st);
    CHECK_EQ(st.ix_gen, got[1]);                                         /* the journal and the memory of the process that was killed name the same generation */
    CHECK_EQ(st.zones_stored, got[2]);
    CHECK(!st.recovery.rebuilt);
    check_consistent(s, "growth sync");
    for (uint32_t i = 0; i < got[3]; i += 97) CHECK(verify_i(s, 0, i, 1));
    CHECK_EQ(put_i(s, 0, 9000, 1, NULL), 0);
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

int main(void) {
  const char *base = getenv("KARIDNS_STORE_TESTDIR");
  snprintf(g_base, sizeof(g_base), "%s/store_test.%d", base && *base ? base : ".", (int)getpid());
  rm_rf(g_base);
  if (mkdir(g_base, 0700) != 0) { perror("mkdir base"); return 2; }
  bool big = getenv("KARIDNS_STORE_BIG") && getenv("KARIDNS_STORE_BIG")[0] == '1';
  int iters = 200;
  if (getenv("KARIDNS_STORE_KILL_ITERS")) iters = atoi(getenv("KARIDNS_STORE_KILL_ITERS"));
  if (UNDER_TSAN && !getenv("KARIDNS_STORE_KILL_ITERS")) iters = 40;
  uint32_t n = UNDER_ASAN || UNDER_TSAN ? 100000 : 100000;
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
  if (WANT("growfail")) test_growth_sync_fails();
  if (WANT("cleanck")) test_clean_checkpoint();
  if (WANT("full")) test_disk_full();
  if (WANT("kill")) test_kill_loop(iters);
  if (WANT("conc")) { test_concurrent(STORE_MODE_MAP); test_concurrent(STORE_MODE_COPY); }
#undef WANT

  rm_rf(g_base);
  printf("\ntest_store: %d checks, %d failed\n", g_checks, g_failed);
  return g_failed ? 1 : 0;
}

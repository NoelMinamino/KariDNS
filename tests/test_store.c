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
  for (uint32_t g = 1; g < 100; g++) { struct stat sbuf; snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, g); if (stat(jp, &sbuf) == 0 && sbuf.st_size > 64) best = g; }   /* (not the next journal, made ahead and empty) */
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

typedef struct { _Atomic uint64_t begun, done, acked; } shm_t;

/* modes 3 and 4 of the kill loop (0.7 fix A): a step of a checkpoint that runs outside the writer mutex (3: a thread checkpoints all the time, the flush of the tables is made slow) or of a
 * growth of the index built outside it (4: the build waits before it takes the mutex, so that the writers' changes pile up in its log) is reached while the operations go on, and the child is
 * killed at the n-th time one step is reached (g_hk_step: 1..4 a checkpoint step, 11..12 a growth step; 0: not by a hook) */
static _Atomic int g_hk_step, g_hk_n;
static void hk_kill(int step) {
  if (atomic_load(&g_hk_step) == step && atomic_fetch_sub(&g_hk_n, 1) == 1) kill(getpid(), SIGKILL);
}
static void hk_ckpt(int step) {
  if (step == 2) usleep(300);
  hk_kill(step);
}
static void hk_regrow(int step) {
  if (step == 1) usleep(3000);
  hk_kill(10 + step);
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
  if (g_kill_mode == 4) atomic_store(&store_test_regrow_hook, hk_regrow);
  store_t *s = NULL;
  if (store_open(fd, &o, &s) != 0) _exit(11);
  if (g_kill_mode == 3) {
    pthread_t th;
    if (pthread_create(&th, NULL, ckthr_main, s) != 0) _exit(14);
    pthread_detach(th);
  }
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

static void test_kill_loop(int iters, int mode) {
  g_kill_mode = mode;
  printf("[kill -9 loop%s: %d iterations]\n", mode == 1 ? " with the cleaner, the nx pass and the scrub" : mode == 2 ? " with groups of zones made known in one record (store_set_known_n)" :
         mode == 3 ? " with a thread that checkpoints all the time (a fuzzy checkpoint killed at its steps)" : mode == 4 ? " with growths of the index built outside the mutex (killed at their steps)" : "", iters);
  int hk_kills = 0;
  tdir_t d;
  tdir_new(&d, "kill");
  shm_t *shm = mmap(NULL, sizeof(*shm), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  CHECK(shm != MAP_FAILED);
  if (shm == MAP_FAILED) { tdir_free(&d); return; }
  model_t *model = calloc(1, sizeof(*model)), *tmp = calloc(1, sizeof(*tmp)), *tmp2 = calloc(1, sizeof(*tmp2)), *tmp3 = calloc(1, sizeof(*tmp3));
  uint64_t K0 = 0, boot = 42, rng = 20261114;
  int fresh = 0, crashed = 0, countdown_hits = 0, tampered = 0, older = 0, torn = 0, exact = 0, replayed_total = 0, lost_ops = 0, with_free = 0, part_groups = 0;
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
      atomic_store(&g_hk_step, mode == 3 ? 1 + (int)((rng >> 8) % 4) : 11 + (int)((rng >> 8) % 2));
      atomic_store(&g_hk_n, 1 + (int)((rng >> 12) % (mode == 3 ? 12 : 2)));
      cd = 0;
      hk_kills++;
    }
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
      for (uint32_t g = 1; g < 400; g++) { struct stat sbuf; snprintf(jp, sizeof(jp), "%s/jrn.%u", d.path, g); if (stat(jp, &sbuf) == 0 && sbuf.st_size > 64) best = g; }   /* (not the next journal, made ahead and empty) */
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
      CHECK(!st.recovery.rebuilt);
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
  if (mode >= 3) printf("  %d kills planned at a step of a %s\n", hk_kills, mode == 3 ? "checkpoint" : "growth");
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
  int fd = openat(d.fd, "zc.1", O_RDWR);
  CHECK(fd >= 0);
  uint32_t odd = 1, even = 0;
  CHECK(fd >= 0 && pwrite(fd, &odd, 4, (off_t)16384 + (off_t)z * 64 + 60) == 4);
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
  CHECK(fd >= 0 && pwrite(fd, &even, 4, (off_t)16384 + (off_t)z * 64 + 60) == 4);
  store_read_lock();
  CHECK_EQ(store_find(s, 0, nm, strlen(nm)), z);
  CHECK_EQ(store_zone_get(s, z, &zz), 0);
  store_read_unlock();
  CHECK(!store_reader_busy_take());
  store_reader_nosleep(false);
  if (fd >= 0) close(fd);
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
    CHECK_EQ(st.ix_gen, got[1]);                                         /* the journal and the memory of the process that was killed name the same generation */
    CHECK_EQ(st.zones_stored, got[2]);
    CHECK(!st.recovery.rebuilt);
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
    CHECK(!st.recovery.rebuilt);
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
  /* the zones before it are stored and served; the zones after it have their record (name, version) without an image */
  for (uint32_t i = 1000; i < first_known; i++) CHECK(verify_i(s, 0, i, 1));
  for (uint32_t i = first_known; i < first_known + 40; i++) {
    store_zone_t zi;
    uint32_t z = find_i(s, 0, i);
    CHECK(z != STORE_NONE && store_zone_get(s, z, &zi) == 0 && zi.state == STORE_STATE_KNOWN && zi.img_len == 0 && zi.serial == 1 && zi.stamp_gen == 1);
  }
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
  for (uint32_t i = 1000; i < first_known; i++) {
    if (i % 4 == 0) continue;
    char nm[160];
    name_of(i, nm, sizeof(nm));
    CHECK_EQ(store_delete_name(s, 0, nm, strlen(nm)), 0);
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
  flip_byte(p, (off_t)(ZT_HDR + (uint64_t)zc * 64 + 9));
  CHECK_EQ(store_scrub_run(s, &rep), 0);
  CHECK_EQ(rep.bad_cells, 1);
  CHECK(rep.repaired);
  CHECK_EQ(find_i(s, 0, 30), STORE_NONE);
  CHECK(verify_i(s, 0, 31, 1));
  check_consistent(s, "scrub cell");
  /* an index entry that does not lead to its zone: the slot is a tombstone (the zone cannot be found by name) */
  store_stats(s, &st);
  snprintf(nm, sizeof(nm), "ix.%u", st.ix_gen);
  fpath(&d, nm, p, sizeof(p));
  uint32_t zx = find_i(s, 0, 40);
  int fd = open(p, O_RDWR);
  CHECK(fd >= 0);
  bool hit = false;
  for (uint64_t k = 0; fd >= 0 && k < st.ix_slots && !hit; k++) {
    uint64_t v;
    if (pread(fd, &v, 8, (off_t)(ZT_HDR + k * 8)) != 8) break;
    if ((uint32_t)v == zx) { v |= 0xffffffffull; hit = pwrite(fd, &v, 8, (off_t)(ZT_HDR + k * 8)) == 8; }
  }
  if (fd >= 0) close(fd);
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
  for (uint32_t g = 1; g < 100; g++) { struct stat sbuf; snprintf(jp, n, "%s/jrn.%u", d->path, g); if (stat(jp, &sbuf) == 0 && sbuf.st_size > 64) best = g; }   /* (not the next journal, made ahead and empty) */
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
      gk_t g[64];
      store_known_t in[64];
      int r[64];
      for (unsigned j = 0; j < 64; j++) {
        name_of(100 + j, g[j].nm, sizeof(g[j].nm));
        g[j].m = meta_of(100 + j, 1);
        in[j].name = g[j].nm; in[j].len = strlen(g[j].nm); in[j].meta = &g[j].m;
      }
      if (store_set_known_n(c, 0, in, 64, r, NULL) != 0) _exit(5);
      for (unsigned j = 0; j < 64; j++) if (r[j] != 0) _exit(6);
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
      for (uint32_t j = 0; j < 64; j++) { char nm[160]; name_of(100 + j, nm, sizeof(nm)); store_read_lock(); if (store_find(s, 0, nm, strlen(nm)) != STORE_NONE) found++; store_read_unlock(); }
      if (torn) {
        CHECK(st.recovery.journal_torn);
        for (uint32_t i = 0; i < 10; i++) { char nm[160]; name_of(i, nm, sizeof(nm)); store_read_lock(); CHECK(store_find(s, 0, nm, strlen(nm)) != STORE_NONE); store_read_unlock(); }
        CHECK_EQ(found, 0);                                                   /* none of the group: it was one record */
        CHECK_EQ(st.zones_known, 10);
      } else {
        CHECK(!st.recovery.rebuilt);
        CHECK(st.recovery.records_replayed >= 11);                            /* (the ten singles and the group) */
        CHECK_EQ(found, 64);
        CHECK_EQ(st.zones_known, 74);
      }
      check_consistent(s, torn ? "torn group" : "replayed group");
      CHECK_EQ(store_close(s), 0);
    }
    tdir_free(&d);
  }
  /* 3. a group that the index growth splits: the entries past one half of the index wait for the growth (the build outside the mutex is held back here), so the call writes the first
   * entries as one record, the growth as the next, the rest as a third.  kill -9 at every crash point of the call: after the replay the group's zones are a prefix of the entries in the
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
        if (!prefix || st.zones_known != 500 + found || st.recovery.rebuilt) bad++;
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
    CHECK(parts > 0);
    CHECK(whole > 0 && none > 0);
  }
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
  if (WANT("scrub")) { test_scrub(STORE_MODE_MAP); test_scrub(STORE_MODE_COPY); test_scrub_tick(); }
  if (WANT("opendef")) test_open_defaults();
  if (WANT("errring")) { test_err_ring(); test_err_index(); }
  if (WANT("badimg")) test_bad_image_hook();
  if (WANT("raclose")) test_readahead_close();
  if (WANT("resident")) { test_resident(STORE_MODE_MAP); test_resident(STORE_MODE_COPY); test_hot_list(); }
  if (WANT("smallfs") && getenv("KARIDNS_STORE_SMALLFS")) test_smallfs(getenv("KARIDNS_STORE_SMALLFS"));
  if (WANT("zfs") && getenv("KARIDNS_STORE_ZFS_128K")) test_zfs_dir(getenv("KARIDNS_STORE_ZFS_128K"), true, "128K dataset");
  if (WANT("zfs") && getenv("KARIDNS_STORE_ZFS_16K")) test_zfs_dir(getenv("KARIDNS_STORE_ZFS_16K"), false, "16K dataset");
  if (WANT("openbench") && getenv("KARIDNS_STORE_OPENBENCH")) test_open_bench(strtoull(getenv("KARIDNS_STORE_OPENBENCH"), NULL, 10));
  if (WANT("group")) { test_group_commit(STORE_MODE_MAP); test_group_commit(STORE_MODE_COPY); test_group_journal(); }
  if (WANT("kill")) test_kill_loop(iters, 0);
  if (WANT("kgrp")) test_kill_loop(UNDER_TSAN ? 25 : 50, 2);
  if (WANT("nowait")) { test_no_wait_in_lock(STORE_MODE_MAP); test_no_wait_in_lock(STORE_MODE_COPY); }
  if (WANT("jbound")) { test_journal_bound(STORE_MODE_MAP); test_journal_bound(STORE_MODE_COPY); }
  if (WANT("kfz")) test_kill_loop(UNDER_TSAN ? 25 : 50, 3);
  if (WANT("kgrow")) test_kill_loop(UNDER_TSAN ? 20 : 50, 4);
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

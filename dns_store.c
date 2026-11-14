/*
 * dns_store.c - the zone store (see dns_store.h for the interface and the rules for callers).
 *
 * ======================================================================================================================
 * THE REDO JOURNAL (user decision D5, design 3.4 adapted)
 * ======================================================================================================================
 *
 * What is mapped and what is logged.  zt, zc, nx (grow in place), ix, sx (replaced by a new generation file) and the
 * superblock's counters (the flat array v[]: free list, high-water mark, per-view / per-segment counters, ...) are changed
 * *in place* through shared mappings.  Segments are append-only and are not logged: their bytes are written first.
 *
 * One writer call = one journal record.  The call plans the whole change (reads the current cells, decides every new cell
 * value) without writing a cell, builds the record, and then
 *     1. appends the segment record, if there is an image (pwritev; bytes the journal record is going to point at),
 *     2. write()s the journal record (header with LSN and CRC-32C, then typed ops that carry *full cell values*),
 *     3. applies the ops to the mapped cells in the order that is safe for lock-free readers (name bytes, zone record,
 *        index slot last for an insert; index tombstone first for a delete; counters at the end).
 * A journal record is thus in the kernel before the first cell changes: kill -9 at any point leaves either nothing of the
 * call (killed before 2 finished) or the whole record, and the replay applies it again (idempotent: ops are absolute values
 * "cell X = V", never deltas; counters are logged as absolute values too).
 *
 * Durability / group commit.  fdatasync is not issued per call: store_commit() (a batch end), the policy
 * (sync_interval_ms, default 100 ms, evaluated at each writer call and in store_tick()), a checkpoint and close do
 *     fdatasync(segments written since the last commit)   -- an image is durable before ...
 *     fdatasync(journal)                                  -- ... the record that points at it
 * so after power loss the journal prefix that was synced is complete and only points at durable images.
 *
 * Checkpoint (store_checkpoint(), by the journal size limit, by checkpoint_interval_ms, at close, after recovery).
 *     commit; msync + fdatasync every mapped file; create the next journal file; write the *other* superblock copy (seq+1,
 *     checkpoint LSN = last LSN, names the journal gen and the ix / sx generations, counters, views, cursors, CRC-32C);
 *     fdatasync it; delete journals / generations that neither superblock copy names any more.  The older copy plus the
 *     journals it names stays valid, so a damaged newer copy costs nothing: the open uses the older one and replays the
 *     longer journal chain.  Growth of ix / sx (a new generation file, built from a sequential pass over zt) is a checkpoint
 *     barrier: the new file is complete and flushed, an OP_GEN record bridges the journal chain, and no later record refers to
 *     the old generation.
 *
 * Recovery at open.  Take the newer valid superblock copy whose files check out against fstat sizes; read the journal files
 * from the gen it names (and the ones after, while their base LSN continues); apply every record with LSN > checkpoint LSN
 * in order; stop at the first record that is torn, CRC-bad or out of sequence (kill -9 in the middle of a write).  Then a
 * new checkpoint starts the session (the clean flag is cleared durably before the first modification).  Same boot after
 * kill -9: this is exact, the page cache kept every cell, cost = replay (about 1 s per 3M records).
 * Power loss / OS crash (different boot id, no clean flag): mapped pages may have reached the disk *ahead of* the journal
 * (the kernel flushes dirty pages on its own schedule), so after the replay the derived tables are rebuilt by one sequential
 * pass over zt (drop records with a bad CRC or impossible fields, drop duplicate names, rebuild ix, sx, the free list,
 * counters, live bytes); an image whose bytes did not reach the disk fails its checksum at the first read and the zone goes
 * back to KNOWN in the caller (design 3.4 item 4).  The rebuild is also the repair path whenever the replay meets something
 * it cannot apply.
 *
 * Bounded size: a checkpoint is forced when the journal reaches journal_max_bytes (default 64 MiB), so the journal never grows
 * without limit and the replay after a crash is bounded.
 *
 * Disk full: a failed append / write / extension returns -ENOSPC (or -EFBIG) *before* any cell changed; the store stays
 * consistent and readable, STORE_ST_DEGRADED_NOSPC is set until the next success.
 *
 * Deliberate limits of this first cut (WP1): compaction of segments, the scrub and store-copy-max are WP9; a long name's bytes in
 * nx are never reclaimed (counted in nx_dead); ix / sx growth runs under the writer mutex (readers continue on the old
 * generation; a 10M-zone rebuild blocks the writer for seconds, once per 1.5x growth, or never after store_reserve()).
 *
 * Journal ops (typed, each a TLV {u16 type, u16 0, u32 payload length}):
 *   ZREC zid + zt[64] + zc[64] | NX offset + bytes | IX / SX count x {slot, value} | V count x {field id, value}
 *   VIEW id + name | SRC source + cursor + identity | GEN which, generation, slots
 */

#include "dns_store.h"
#include "dns_epoch_rcu.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "dns_store: the on-disk format is little endian (zt / zc cells are read as host words)"
#endif

/* ------------------------------------------------------------------------------------------------------------------ */
/* constants and on-disk layouts                                                                                        */
/* ------------------------------------------------------------------------------------------------------------------ */

#define ST_SB_SIZE      65536u
#define ST_HDR_PAGE     16384u            /* file header page of every table file (data starts here) */
#define ST_REC          64u
#define ST_RHDR         64u               /* segment record header */
#define ST_SEGHDR       64u               /* segment file header; the first record is at 64 */
#define ST_LOC_SHIFT    36
#define ST_LOC_MASK     ((1ull << ST_LOC_SHIFT) - 1)
#define ST_NAME_INL     34u               /* name bytes inside zt */
#define ST_IX_MIN       1024u
#define ST_JHDR         64u
#define ST_JREC_HDR     24u
#define ST_MAGIC_REC    0x31474553u       /* "SEG1" */
#define ST_MAGIC_JREC   0x4a52454bu       /* "KERJ" */
#define ST_CHUNK        (1u << 20)        /* growth granule of mapped tables */
#define ST_MAXV         STORE_MAX_VIEWS
#define ST_MAXSRC       STORE_MAX_SOURCES
#define ST_MAXSEG       STORE_MAX_SEGS
#define ST_IX_MAX_SLOTS (1ull << 36)      /* more than the 2^32 zone ids can fill (3 slots per zone); keeps every size computation far from a wrap */
#define ST_SEG_MAX      (1ull << 42)      /* what a record location can address: 36 bits of 64 B units */
#define ST_V_MAX        (1ull << 56)      /* no counter of the superblock is above this */

/* flat counter array v[] (superblock + journal "V" ops) */
enum {
  V_HWM = 0, V_FREE_HEAD, V_FREE_COUNT, V_NX_USED, V_NX_DEAD, V_IX_USED, V_IX_LIVE, V_SX_USED, V_SX_LIVE,
  V_NSEGS, V_CUR_SEG, V_KNOWN, V_STORED, V_REJECTED, V_IMG_BYTES,
  V_GLOBAL_END = 32
};
#define V_VIEW(view, k)   (32u + (view) * 8u + (k))             /* k: 0 known, 1 stored, 2 rejected, 3 image bytes */
#define V_DEPTH(view, d)  (32u + 256u + (view) * 64u + (d))
#define V_SEG(n, k)       (32u + 256u + 2048u + 2u * (n) + (k))  /* k: 0 used, 1 live */
#define ST_NV             4400u

/* journal op types */
enum { OP_ZREC = 1, OP_NX, OP_IX, OP_SX, OP_V, OP_VIEW, OP_SRC, OP_GEN, OP_REBUILD };

/* file kinds */
enum { FK_ZT = 1, FK_ZC, FK_NX, FK_IX, FK_SX, FK_SEG, FK_JRN };

typedef struct {
  char     magic[8];
  uint32_t version;
  uint32_t kind;
  uint8_t  uuid[16];
  uint32_t gen;
  uint32_t recsz;
  uint64_t a;                 /* ix / sx: slots; journal: base LSN */
  uint64_t rsv;
  uint32_t crc;
  uint32_t pad;
} fhdr_t;
_Static_assert(sizeof(fhdr_t) == 64, "fhdr_t");

typedef struct {
  uint32_t magic, reclen, zid;
  uint16_t view, kind;
  uint32_t flags, serial, settings, img_len;
  uint64_t stamp_gen, prev_loc, checksum;
  uint16_t klen;
  uint8_t  pad[6];
} rhdr_t;
_Static_assert(sizeof(rhdr_t) == 64, "rhdr_t");

typedef struct {
  uint32_t magic, len, crc, nops;
  uint64_t lsn;
} jrec_t;
_Static_assert(sizeof(jrec_t) == 24, "jrec_t");

typedef struct {
  uint64_t cursor;
  uint32_t valid, identlen;
  uint8_t  ident[STORE_IDENT_MAX];
} srcent_t;

typedef union {
  struct {
    char     magic[8];
    uint32_t version, size;
    uint64_t seq;
    uint8_t  uuid[16];
    uint64_t hk0, hk1;
    uint32_t flags, crc;
    uint64_t boot_id, ckpt_lsn, ckpt_time, ckpt_us;
    uint32_t jrn_gen, ix_gen, sx_gen, nviews;
    uint64_t zt_cap, ix_slots, sx_slots, seg_size, nx_cap;
    uint64_t rsv[7];
    char     views[ST_MAXV][STORE_VIEW_NAME_MAX + 1];
    srcent_t src[ST_MAXSRC];
    uint64_t v[ST_NV];
  } f;
  uint8_t raw[ST_SB_SIZE];
} sb_t;
_Static_assert(sizeof(sb_t) == ST_SB_SIZE, "superblock size");
#define SBF_CLEAN 1u

/* 64 B cells as eight host (little endian) words */
typedef struct { uint64_t w[8]; } r64_t;

typedef struct {
  uint64_t loc;
  uint32_t img_len, serial, settings, crc;
  uint16_t view, flags;
  uint8_t  state, klen;
  uint8_t  name[ST_NAME_INL];
} zt_t;
typedef struct {
  int64_t  source_id;
  uint64_t stamp_gen, stamp_time;
  uint8_t  digest[STORE_DIGEST_LEN];
  uint16_t source;
} zc_t;

/* ------------------------------------------------------------------------------------------------------------------ */
/* run-time structures                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------------ */

typedef struct {                       /* a table that grows in place inside a reserved address range */
  int      fd;
  uint8_t *base;
  size_t   reserve;                    /* bytes of address space */
  _Atomic uint64_t mapped;             /* data bytes mapped (multiple of the page size) */
} mtab_t;

typedef struct ixgen {                 /* one generation of ix or sx */
  int      fd;
  uint32_t gen;
  uint64_t nslots;
  _Atomic uint64_t *slots;
  size_t   maplen;
} ixgen_t;

typedef struct seg {
  int      fd;
  uint32_t num;
  uint8_t *map;                        /* MAP mode: whole file, read only */
  size_t   maplen;
  _Atomic int refs;
} seg_t;

typedef struct retire {
  uint64_t epoch;
  ixgen_t *g;
  struct retire *next;
} retire_t;

#define JB_MAXV 96
typedef struct {
  uint8_t *p;
  size_t   len, cap;
  uint32_t nops;
  unsigned nv;
  struct { uint32_t fid; uint64_t val; } vs[JB_MAXV];
} jb_t;

struct store {
  int dirfd;
  store_opts_t o;
  int mode;
  char fstype[16];
  size_t pagesz;
  uint64_t seg_size;
  pthread_mutex_t wlock;
  pthread_mutex_t seg_mu;

  uint8_t uuid[16];
  uint64_t hk0, hk1;
  uint64_t sb_seq;
  int sb_fd[2];
  int sb_next;                          /* slot to write at the next checkpoint */
  _Atomic uint32_t jrn_gen;
  uint32_t ix_gen, sx_gen;              /* current */
  uint32_t slot_jrn[2], slot_ix[2], slot_sx[2];
  uint64_t boot_id;
  uint64_t free_epoch;                  /* writer: the retire epoch of the newest cell that was put on the free list (a cell is reused after its grace period) */
  _Atomic uint64_t ckpt_lsn, ckpt_time, ckpt_us;
  _Atomic bool clean_on_disk;
  _Atomic uint64_t v[ST_NV];
  char views[ST_MAXV][STORE_VIEW_NAME_MAX + 1];
  _Atomic uint32_t nviews;
  srcent_t src[ST_MAXSRC];
  sb_t *sbbuf;

  mtab_t zt, zc, nx;
  _Atomic uint64_t nx_avail;
  _Atomic(ixgen_t *) ix;
  _Atomic(ixgen_t *) sx;
  _Atomic(seg_t *) segs[ST_MAXSEG + 1];
  uint8_t seg_dirty[ST_MAXSEG + 1];

  int jfd;
  _Atomic uint64_t jbytes;
  _Atomic uint64_t lsn, committed_lsn;
  uint64_t uncommitted;
  bool dir_dirty;
  uint64_t last_sync_ms, last_ckpt_ms;
  jb_t jb;
  retire_t *rq_head, *rq_tail;

  _Atomic uint64_t n_puts, n_replaces, n_deletes, n_growths, n_checkpoints, n_commits, n_write_errors;
  _Atomic uint32_t state;
  store_recovery_t rec;
};

/* ------------------------------------------------------------------------------------------------------------------ */
/* test hooks                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

#ifdef KARIDNS_UNIT_TEST
long store_test_crash_countdown = 0;
void (*store_test_before_counters)(store_t *s) = NULL;
long store_test_fail_commit = 0;
static void st_crash_point(void) {
  long c = store_test_crash_countdown;
  if (c > 0 && --c == 0) kill(getpid(), SIGKILL);
  store_test_crash_countdown = c;
}
#define CRASH_POINT() st_crash_point()
#else
#define CRASH_POINT() ((void)0)
#endif

/* ------------------------------------------------------------------------------------------------------------------ */
/* small helpers: time, logging, CRC-32C, checksum64, SipHash-1-3                                                        */
/* ------------------------------------------------------------------------------------------------------------------ */

static uint64_t st_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static uint64_t st_now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void st_log(const store_t *s, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void st_log(const store_t *s, int level, const char *fmt, ...) {
  if (!s->o.log) return;
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  s->o.log(s->o.log_ctx, level, buf);
}

/* CRC-32C (Castagnoli, reflected polynomial 0x82F63B78), slicing by 8; tables built once */
static uint32_t st_crc_tab[8][256];
static pthread_once_t st_crc_once = PTHREAD_ONCE_INIT;
static void st_crc_init(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1u) ? (c >> 1) ^ 0x82F63B78u : (c >> 1);
    st_crc_tab[0][i] = c;
  }
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = st_crc_tab[0][i];
    for (int t = 1; t < 8; t++) {
      c = st_crc_tab[0][c & 0xff] ^ (c >> 8);
      st_crc_tab[t][i] = c;
    }
  }
}
static uint32_t st_crc32c(uint32_t crc, const void *buf, size_t n) {
  const uint8_t *p = buf;
  crc = ~crc;
  while (n >= 8) {
    uint64_t w;
    memcpy(&w, p, 8);
    uint32_t lo = (uint32_t)w ^ crc, hi = (uint32_t)(w >> 32);
    crc = st_crc_tab[7][lo & 0xff] ^ st_crc_tab[6][(lo >> 8) & 0xff] ^ st_crc_tab[5][(lo >> 16) & 0xff] ^
          st_crc_tab[4][lo >> 24] ^ st_crc_tab[3][hi & 0xff] ^ st_crc_tab[2][(hi >> 8) & 0xff] ^
          st_crc_tab[1][(hi >> 16) & 0xff] ^ st_crc_tab[0][hi >> 24];
    p += 8;
    n -= 8;
  }
  while (n--) crc = st_crc_tab[0][(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return ~crc;
}

/* checksum64: four multiply-rotate lanes over 32-byte blocks, then the tail, then an avalanche.  `seed` chains calls (the
 * result of one part is the seed of the next), so header, name and image need no copy into one buffer. */
static inline uint64_t st_rotl(uint64_t x, unsigned b) { return (x << b) | (x >> (64 - b)); }
static uint64_t st_sum64(const void *buf, size_t n, uint64_t seed) {
  static const uint64_t K1 = 0x9E3779B97F4A7C15ull, K2 = 0xD6E8FEB86659FD93ull, K3 = 0xA0761D6478BD642Full,
                        K4 = 0xE7037ED1A0B428DBull;
  const uint8_t *p = buf;
  uint64_t a = seed ^ K1, b = seed + K2, c = seed ^ K3, d = seed + K4;
  size_t left = n;
  while (left >= 32) {
    uint64_t w0, w1, w2, w3;
    memcpy(&w0, p, 8); memcpy(&w1, p + 8, 8); memcpy(&w2, p + 16, 8); memcpy(&w3, p + 24, 8);
    a = st_rotl(a ^ (w0 * K2), 31) * K1;
    b = st_rotl(b ^ (w1 * K3), 29) * K2;
    c = st_rotl(c ^ (w2 * K4), 27) * K3;
    d = st_rotl(d ^ (w3 * K1), 25) * K4;
    p += 32;
    left -= 32;
  }
  uint64_t h = st_rotl(a, 3) + st_rotl(b, 11) + st_rotl(c, 19) + st_rotl(d, 27) + (uint64_t)n * K1;
  while (left >= 8) {
    uint64_t w;
    memcpy(&w, p, 8);
    h = st_rotl(h ^ (w * K3), 23) * K2 + K4;
    p += 8;
    left -= 8;
  }
  uint64_t t = 0;
  for (size_t i = 0; i < left; i++) t |= (uint64_t)p[i] << (8 * i);
  if (left) h = st_rotl(h ^ (t * K2), 17) * K1;
  h ^= h >> 32; h *= K3; h ^= h >> 29; h *= K4; h ^= h >> 32;
  return h;
}

/* SipHash-c-d (Aumasson / Bernstein, "SipHash: a fast short-input PRF", 2012), written from the paper; the store uses c = 1,
 * d = 3 (design D10).  Message words little endian. */
#define SIP_ROUND do { \
    v0 += v1; v1 = st_rotl(v1, 13); v1 ^= v0; v0 = st_rotl(v0, 32); \
    v2 += v3; v3 = st_rotl(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = st_rotl(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = st_rotl(v1, 17); v1 ^= v2; v2 = st_rotl(v2, 32); \
  } while (0)
static inline uint64_t st_siphash(unsigned c, unsigned d, uint64_t k0, uint64_t k1, const uint8_t *in, size_t len) {
  uint64_t v0 = 0x736f6d6570736575ull ^ k0, v1 = 0x646f72616e646f6dull ^ k1;
  uint64_t v2 = 0x6c7967656e657261ull ^ k0, v3 = 0x7465646279746573ull ^ k1;
  size_t full = len & ~(size_t)7;
  for (size_t i = 0; i < full; i += 8) {
    uint64_t m;
    memcpy(&m, in + i, 8);
    v3 ^= m;
    for (unsigned r = 0; r < c; r++) SIP_ROUND;
    v0 ^= m;
  }
  uint64_t b = (uint64_t)len << 56;
  for (size_t i = 0; i < (len & 7); i++) b |= (uint64_t)in[full + i] << (8 * i);
  v3 ^= b;
  for (unsigned r = 0; r < c; r++) SIP_ROUND;
  v0 ^= b;
  v2 ^= 0xff;
  for (unsigned r = 0; r < d; r++) SIP_ROUND;
  return v0 ^ v1 ^ v2 ^ v3;
}

#ifdef KARIDNS_UNIT_TEST
uint64_t store_test_siphash(unsigned c, unsigned d, const uint8_t key[16], const uint8_t *in, size_t len) {
  uint64_t k0, k1;
  memcpy(&k0, key, 8);
  memcpy(&k1, key + 8, 8);
  return st_siphash(c, d, k0, k1, in, len);
}
uint32_t store_test_crc32c(uint32_t crc, const void *p, size_t n) {
  pthread_once(&st_crc_once, st_crc_init);
  return st_crc32c(crc, p, n);
}
uint64_t store_test_sum64(const void *p, size_t n) { return st_sum64(p, n, 0); }
#endif

static inline uint8_t st_lc(uint8_t c) { return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c; }
static inline size_t st_pad16(size_t n) { return (n + 15) & ~(size_t)15; }
static inline uint64_t st_reclen(size_t klen, size_t ilen) { return ((uint64_t)ST_RHDR + st_pad16(klen) + ilen + 63) & ~63ull; }

/* hash of (view, name): the name is folded already */
static inline uint64_t st_hash_name(const store_t *s, uint16_t view, const uint8_t *fn, size_t len) {
  uint8_t b[2 + 256];
  b[0] = (uint8_t)view;
  b[1] = (uint8_t)(view >> 8);
  memcpy(b + 2, fn, len);
  return st_siphash(1, 3, s->hk0, s->hk1, b, len + 2);
}
static inline uint64_t st_hash_src(const store_t *s, uint16_t source, uint16_t view, int64_t dom) {
  uint8_t b[12];
  b[0] = (uint8_t)source; b[1] = (uint8_t)(source >> 8);
  b[2] = (uint8_t)view;   b[3] = (uint8_t)(view >> 8);
  memcpy(b + 4, &dom, 8);
  return st_siphash(1, 3, s->hk0 ^ 0x5851f42d4c957f2dull, s->hk1, b, 12);
}
static inline uint32_t st_tag(uint64_t h) { uint32_t t = (uint32_t)h; return t ? t : 1u; }
static inline uint64_t st_pos(uint64_t h, uint64_t n) { return (uint64_t)(((unsigned __int128)h * n) >> 64); }
static inline uint64_t st_slotval(uint32_t tag, uint32_t zid) { return ((uint64_t)tag << 32) | zid; }

static void st_random(void *buf, size_t n) {
#if defined(__FreeBSD__) || defined(__APPLE__)
  arc4random_buf(buf, n);
#else
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  size_t got = 0;
  if (fd >= 0) {
    while (got < n) {
      ssize_t r = read(fd, (uint8_t *)buf + got, n - got);
      if (r <= 0) break;
      got += (size_t)r;
    }
    close(fd);
  }
  for (; got < n; got++) ((uint8_t *)buf)[got] = (uint8_t)(rand() >> 3);
#endif
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* cells: zt / zc records                                                                                               */
/* ------------------------------------------------------------------------------------------------------------------ */

static inline void r64_load(const void *p, r64_t *r) {
  const _Atomic uint64_t *a = p;
  r->w[3] = atomic_load_explicit(&a[3], memory_order_acquire);
  for (int i = 0; i < 8; i++)
    if (i != 3) r->w[i] = atomic_load_explicit(&a[i], memory_order_relaxed);
}

static void zt_pack(const zt_t *z, r64_t *r) {
  uint8_t *b = (uint8_t *)r->w;
  memset(b, 0, 64);
  memcpy(b + 0, &z->loc, 8);
  memcpy(b + 8, &z->img_len, 4);
  memcpy(b + 12, &z->serial, 4);
  memcpy(b + 16, &z->settings, 4);
  memcpy(b + 20, &z->crc, 4);
  memcpy(b + 24, &z->view, 2);
  memcpy(b + 26, &z->flags, 2);
  b[28] = z->state;
  b[29] = z->klen;
  memcpy(b + 30, z->name, ST_NAME_INL);
}
static void zt_unpack(const r64_t *r, zt_t *z) {
  const uint8_t *b = (const uint8_t *)r->w;
  memcpy(&z->loc, b + 0, 8);
  memcpy(&z->img_len, b + 8, 4);
  memcpy(&z->serial, b + 12, 4);
  memcpy(&z->settings, b + 16, 4);
  memcpy(&z->crc, b + 20, 4);
  memcpy(&z->view, b + 24, 2);
  memcpy(&z->flags, b + 26, 2);
  z->state = b[28];
  z->klen = b[29];
  memcpy(z->name, b + 30, ST_NAME_INL);
}
static void zc_pack(const zc_t *c, r64_t *r) {
  uint8_t *b = (uint8_t *)r->w;
  memset(b, 0, 64);
  memcpy(b + 0, &c->source_id, 8);
  memcpy(b + 8, &c->stamp_gen, 8);
  memcpy(b + 16, &c->stamp_time, 8);
  memcpy(b + 24, c->digest, STORE_DIGEST_LEN);
  memcpy(b + 56, &c->source, 2);
}
static void zc_unpack(const r64_t *r, zc_t *c) {
  const uint8_t *b = (const uint8_t *)r->w;
  memcpy(&c->source_id, b + 0, 8);
  memcpy(&c->stamp_gen, b + 8, 8);
  memcpy(&c->stamp_time, b + 16, 8);
  memcpy(c->digest, b + 24, STORE_DIGEST_LEN);
  memcpy(&c->source, b + 56, 2);
}
/* CRC-32C over the zt cell (its crc field as zero) and the zc cell */
static uint32_t zrec_crc(const r64_t *zt, const r64_t *zc) {
  r64_t t = *zt, c = *zc;
  memset((uint8_t *)t.w + 20, 0, 4);
  memset((uint8_t *)c.w + 60, 0, 4);         /* the sequence counter of the cell is not part of its content */
  return st_crc32c(st_crc32c(0, &t, 64), &c, 64);
}
/* complete a zt cell for storing: set its crc field */
static void zrec_seal(r64_t *zt, const r64_t *zc) {
  uint32_t c = zrec_crc(zt, zc);
  memcpy((uint8_t *)zt->w + 20, &c, 4);
}
static inline uint32_t zrec_stored_crc(const r64_t *zt) {
  uint32_t c;
  memcpy(&c, (const uint8_t *)zt->w + 20, 4);
  return c;
}

/* How long a reader waits for a cell that is being written (odd sequence counter) or changed under its copy.  A writer that is descheduled in the middle of a cell (a host
 * under load) makes readers wait, not fail: spin, yield, then sleep in short steps; only after ST_SEQ_GIVEUP_US the cell is taken for damaged (a counter that a crash left odd is
 * repaired by the replay or the rebuild, so this bound is for a forged one). */
#define ST_SEQ_GIVEUP_US 500000u
typedef struct { unsigned n; uint64_t t0; } seqwait_t;
static bool seq_wait(seqwait_t *w) {
  if (w->n++ < 16) return true;
  if (w->n < 256) {
    sched_yield();
    return true;
  }
  if (w->n == 256) w->t0 = st_now_us();
  else if (st_now_us() - w->t0 > ST_SEQ_GIVEUP_US) return false;
  struct timespec ts = { 0, 50000 };
  nanosleep(&ts, NULL);
  return true;
}

#define VG(s, i)    atomic_load_explicit(&(s)->v[(i)], memory_order_relaxed)
#define VS(s, i, x) atomic_store_explicit(&(s)->v[(i)], (x), memory_order_relaxed)

static inline const _Atomic uint64_t *zt_cell(const store_t *s, uint32_t z) { return (const _Atomic uint64_t *)(s->zt.base + (size_t)z * ST_REC); }
static inline const _Atomic uint64_t *zc_cell(const store_t *s, uint32_t z) { return (const _Atomic uint64_t *)(s->zc.base + (size_t)z * ST_REC); }
static inline uint64_t st_zt_cap(const store_t *s) { return atomic_load_explicit(&s->zt.mapped, memory_order_acquire) / ST_REC; }
static inline uint64_t st_zc_cap(const store_t *s) { return atomic_load_explicit(&s->zc.mapped, memory_order_acquire) / ST_REC; }

/* Write the zt and zc cells of one zone in place.  Readers are lock-free, so the cell pair is a seqlock: the sequence counter lives in
 * the top half of the last word of the zc cell (bytes 60..63; not part of the CRC).  The writer makes it odd, writes the words, and
 * makes it even again; a reader that sees an odd counter, or two different ones around its copy, tries again.  A CRC mismatch under a
 * stable even counter therefore means a damaged cell, not a write in flight (a writer that is preempted in the middle of a cell only
 * makes readers wait, never fail early).  An odd counter left behind by a crash is repaired by the replay (the record is rewritten) or
 * by the rebuild. */
static void zrec_write(const store_t *s, uint32_t z, const r64_t *zt, const r64_t *zc) {
  _Atomic uint64_t *tc = (_Atomic uint64_t *)zt_cell(s, z), *cc = (_Atomic uint64_t *)zc_cell(s, z);
  uint32_t seq = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32);
  uint32_t odd = seq | 1u, even = odd + 1u;
  uint64_t low7 = zc->w[7] & 0xffffffffu;
  atomic_store_explicit(&cc[7], low7 | ((uint64_t)odd << 32), memory_order_relaxed);
  atomic_thread_fence(memory_order_release);
  for (int i = 0; i < 7; i++) atomic_store_explicit(&cc[i], zc->w[i], memory_order_relaxed);
  for (int i = 0; i < 8; i++)
    if (i != 3) atomic_store_explicit(&tc[i], zt->w[i], memory_order_relaxed);
  atomic_store_explicit(&tc[3], zt->w[3], memory_order_release);
  atomic_store_explicit(&cc[7], low7 | ((uint64_t)even << 32), memory_order_release);
}

static int zrec_read_cells(const store_t *s, uint32_t z, r64_t *zt, r64_t *zc) {
  r64_load(zt_cell(s, z), zt);
  r64_load(zc_cell(s, z), zc);
  zc->w[7] &= 0xffffffffu;                      /* the sequence counter is not content */
  return zrec_crc(zt, zc) == zrec_stored_crc(zt) ? 0 : -EBADMSG;
}
/* Reader: a consistent copy of the zt and zc cells of z (see zrec_write).  -ENOENT: z is beyond the files; -EBADMSG: the CRC does not
 * match (a damaged cell) or the cell stays in the middle of a write for longer than a crashed or very slow writer can explain. */
static int zrec_read(const store_t *s, uint32_t z, r64_t *zt, r64_t *zc) {
  if ((uint64_t)z >= st_zt_cap(s) || (uint64_t)z >= st_zc_cap(s)) return -ENOENT;
  const _Atomic uint64_t *cc = zc_cell(s, z);
  seqwait_t sw = { 0, 0 };
  for (;;) {
    uint32_t s1 = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_acquire) >> 32);
    if (s1 & 1u) {
      if (!seq_wait(&sw)) break;
      continue;
    }
    r64_load(zt_cell(s, z), zt);
    r64_load(cc, zc);
    atomic_thread_fence(memory_order_acquire);
    uint32_t s2 = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32);
    if (s1 != s2) { if (!seq_wait(&sw)) break; continue; }
    zc->w[7] &= 0xffffffffu;
    return zrec_crc(zt, zc) == zrec_stored_crc(zt) ? 0 : -EBADMSG;
  }
  return -EBADMSG;
}
/* Writer (holds the writer mutex, so no cell is changing): the same without the sequence protocol */
static int zrec_read_locked(const store_t *s, uint32_t z, r64_t *zt, r64_t *zc) {
  if ((uint64_t)z >= st_zt_cap(s) || (uint64_t)z >= st_zc_cap(s)) return -ENOENT;
  return zrec_read_cells(s, z, zt, zc);
}

/* the state byte of a zt cell without a CRC check (FREE cells and cells never written are state 0) */
static inline uint8_t zt_state_fast(const store_t *s, uint32_t z) {
  uint64_t w3 = atomic_load_explicit(&zt_cell(s, z)[3], memory_order_acquire);
  return (uint8_t)(w3 >> 32);
}

/* Is `val` a value that slot `fid` of the counter array can have?  The superblock and the journal are checked by a CRC only, which a damaged file does not
 * pass but a forged one does, so every value that is used as an index, a position or a size is bounded before it is taken in (needs zt and nx opened:
 * their reserves are the limits of zone ids and name offsets). */
static bool v_value_ok(const store_t *s, uint32_t fid, uint64_t val) {
  if (fid >= ST_NV) return false;
  uint64_t zmax = (uint64_t)s->zt.reserve / ST_REC;
  switch (fid) {
  case V_HWM:
  case V_FREE_COUNT: return val <= zmax;
  case V_FREE_HEAD: return val == STORE_NONE || val < zmax;
  case V_NX_USED: return val <= (uint64_t)s->nx.reserve;
  case V_NSEGS:
  case V_CUR_SEG: return val <= ST_MAXSEG;
  default: break;
  }
  if (fid >= V_SEG(0, 0) && fid < V_SEG(ST_MAXSEG + 1, 0)) return val <= ST_SEG_MAX;
  return val <= ST_V_MAX;
}

/* the full name of a zone from its zt cell (inline part, or nx); false when the cell points outside nx */
static bool zt_fullname(const store_t *s, const zt_t *z, uint8_t *out) {
  if (z->klen <= ST_NAME_INL) {
    memcpy(out, z->name, z->klen);
    return true;
  }
  uint64_t off;
  memcpy(&off, z->name, 8);
  uint64_t avail = atomic_load_explicit(&s->nx_avail, memory_order_acquire);
  if (off > avail || (uint64_t)z->klen > avail - off) return false;
  memcpy(out, s->nx.base + off, z->klen);
  return true;
}

/* does the zt cell of z hold (view, name)?  fn is folded.  Hot path of every lookup: no CRC, only word loads.  The words are read under the
 * cell's sequence counter (see zrec_write): a cell that is being rewritten (a delete turns it into a FREE cell, a reuse writes another name) is
 * never compared half old, half new. */
static bool st_name_eq(const store_t *s, uint32_t z, uint16_t view, const uint8_t *fn, size_t len) {
  if ((uint64_t)z >= st_zt_cap(s) || (uint64_t)z >= st_zc_cap(s)) return false;
  const _Atomic uint64_t *c = zt_cell(s, z), *cc = zc_cell(s, z);
  seqwait_t sw = { 0, 0 };
  for (;;) {
    uint32_t s1 = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_acquire) >> 32);
    if (s1 & 1u) {
      if (!seq_wait(&sw)) break;
      continue;
    }
    uint64_t w3 = atomic_load_explicit(&c[3], memory_order_acquire);
    uint8_t state = (uint8_t)(w3 >> 32), klen = (uint8_t)(w3 >> 40);
    if (state == STORE_STATE_FREE || (uint16_t)w3 != view || klen != len) {
      atomic_thread_fence(memory_order_acquire);
      if (s1 != (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32)) { if (!seq_wait(&sw)) break; continue; }
      return false;
    }
    uint8_t nb[ST_NAME_INL + 2];   /* name bytes 0..1 are in w3, 2..33 in w4..w7 */
    nb[0] = (uint8_t)(w3 >> 48);
    nb[1] = (uint8_t)(w3 >> 56);
    for (int i = 0; i < 4; i++) {
      uint64_t w = atomic_load_explicit(&c[4 + i], memory_order_relaxed);
      memcpy(nb + 2 + 8 * i, &w, 8);
    }
    atomic_thread_fence(memory_order_acquire);
    if (s1 != (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32)) { if (!seq_wait(&sw)) break; continue; }
    if (len <= ST_NAME_INL) return memcmp(nb, fn, len) == 0;
    uint64_t off;
    memcpy(&off, nb, 8);
    if (memcmp(nb + 8, fn, ST_NAME_INL - 8) != 0) return false;
    uint64_t avail = atomic_load_explicit(&s->nx_avail, memory_order_acquire);
    if (off > avail || (uint64_t)len > avail - off) return false;
    return memcmp(s->nx.base + off, fn, len) == 0;
  }
  return false;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* files                                                                                                                */
/* ------------------------------------------------------------------------------------------------------------------ */

#ifdef MAP_NOCORE
#define ST_NOCORE MAP_NOCORE      /* the store is not part of a core dump */
#else
#define ST_NOCORE 0
#endif

#ifdef O_RESOLVE_BENEATH
#define ST_OBENEATH O_RESOLVE_BENEATH
#else
#define ST_OBENEATH 0
#endif

static int st_openat(const store_t *s, const char *name, int flags) {
  int fd = openat(s->dirfd, name, flags | O_CLOEXEC | ST_OBENEATH, 0600);
  return fd < 0 ? -errno : fd;
}

static int st_pwrite_all(int fd, const void *buf, size_t n, off_t off) {
  const uint8_t *p = buf;
  while (n) {
    ssize_t w = pwrite(fd, p, n, off);
    if (w < 0) {
      if (errno == EINTR) continue;
      return -errno;
    }
    if (w == 0) return -EIO;
    p += w; n -= (size_t)w; off += w;
  }
  return 0;
}
static int st_pread_all(int fd, void *buf, size_t n, off_t off) {
  uint8_t *p = buf;
  while (n) {
    ssize_t r = pread(fd, p, n, off);
    if (r < 0) {
      if (errno == EINTR) continue;
      return -errno;
    }
    if (r == 0) return -EIO;
    p += r; n -= (size_t)r; off += r;
  }
  return 0;
}

/* extend a file to `size` bytes, really allocating the blocks where the file system can (ENOSPC now, not SIGBUS on a mapped
 * store later); file systems without posix_fallocate get a sparse ftruncate */
static int st_extend(int fd, off_t from, off_t size) {
  if (size <= from) return 0;
  int r = posix_fallocate(fd, from, size - from);
  if (r == 0) return 0;
  if (r == ENOSPC || r == EFBIG || r == EDQUOT || r == EIO) return -r;
  if (ftruncate(fd, size) != 0) return -errno;
  return 0;
}

static void fhdr_make(const store_t *s, fhdr_t *h, uint32_t kind, uint32_t gen, uint32_t recsz, uint64_t a) {
  memset(h, 0, sizeof(*h));
  memcpy(h->magic, "KARIFILE", 8);
  h->version = STORE_FORMAT_VERSION;
  h->kind = kind;
  memcpy(h->uuid, s->uuid, 16);
  h->gen = gen;
  h->recsz = recsz;
  h->a = a;
  h->crc = st_crc32c(0, h, sizeof(*h));
}
static bool fhdr_ok(const store_t *s, const fhdr_t *in, uint32_t kind, uint32_t gen) {
  fhdr_t h = *in;
  h.crc = 0;
  return memcmp(in->magic, "KARIFILE", 8) == 0 && in->version == STORE_FORMAT_VERSION && in->kind == kind &&
         in->gen == gen && memcmp(in->uuid, s->uuid, 16) == 0 && in->crc == st_crc32c(0, &h, sizeof(h));
}
/* ---- growable mapped table (zt, zc, nx) ---- */

static int mtab_map_tail(mtab_t *t, uint64_t from, uint64_t to) {
  void *p = mmap(t->base + from, (size_t)(to - from), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | ST_NOCORE, t->fd,
                 (off_t)(ST_HDR_PAGE + from));
  return p == MAP_FAILED ? -errno : 0;
}
static int mtab_open(store_t *s, mtab_t *t, const char *name, uint32_t kind, uint32_t recsz, size_t reserve, bool create) {
  memset(t, 0, sizeof(*t));
  t->fd = -1;
  int fd = st_openat(s, name, O_RDWR | (create ? (O_CREAT | O_TRUNC) : 0));
  if (fd < 0) return fd;
  t->fd = fd;
  fhdr_t h;
  if (create) {
    fhdr_make(s, &h, kind, 1, recsz, 0);
    uint8_t *page = calloc(1, ST_HDR_PAGE);
    if (!page) return -ENOMEM;
    memcpy(page, &h, sizeof(h));
    int r = st_pwrite_all(fd, page, ST_HDR_PAGE, 0);
    free(page);
    if (r < 0) return r;
  } else {
    int r = st_pread_all(fd, &h, sizeof(h), 0);
    if (r < 0 || !fhdr_ok(s, &h, kind, 1)) return -EBADMSG;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) return -errno;
  if (st.st_size < (off_t)ST_HDR_PAGE) return -EBADMSG;
  uint64_t data = ((uint64_t)st.st_size - ST_HDR_PAGE) & ~((uint64_t)s->pagesz - 1);
  if (data > reserve) return -EFBIG;
  void *base = mmap(NULL, reserve, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if (base == MAP_FAILED) return -errno;
  t->base = base;
  t->reserve = reserve;
  if (data) {
    int r = mtab_map_tail(t, 0, data);
    if (r < 0) return r;
  }
  atomic_store_explicit(&t->mapped, data, memory_order_release);
  return 0;
}
static void mtab_close(mtab_t *t) {
  if (t->base) munmap(t->base, t->reserve);
  if (t->fd >= 0) close(t->fd);
  memset(t, 0, sizeof(*t));
  t->fd = -1;
}
/* grow the data area to at least `need` bytes (never shrinks); the address of existing data does not change */
static int mtab_grow(store_t *s, mtab_t *t, uint64_t need) {
  uint64_t cur = atomic_load_explicit(&t->mapped, memory_order_relaxed);
  if (need <= cur) return 0;
  if (need > t->reserve) return -EFBIG;
  uint64_t want = need;
  if (cur + cur / 4 > want) want = cur + cur / 4;
  if (cur + ST_CHUNK > want) want = cur + ST_CHUNK;
  want = (want + ST_CHUNK - 1) & ~(uint64_t)(ST_CHUNK - 1);
  if (want > t->reserve) want = t->reserve & ~(uint64_t)(s->pagesz - 1);
  int r = st_extend(t->fd, (off_t)(ST_HDR_PAGE + cur), (off_t)(ST_HDR_PAGE + want));
  if (r < 0) return r;
  r = mtab_map_tail(t, cur, want);
  if (r < 0) return r;
  atomic_store_explicit(&t->mapped, want, memory_order_release);
  return 0;
}
static int mtab_sync(mtab_t *t) {
  uint64_t m = atomic_load_explicit(&t->mapped, memory_order_relaxed);
  if (m && msync(t->base, (size_t)m, MS_SYNC) != 0) return -errno;
  if (fdatasync(t->fd) != 0) return -errno;
  return 0;
}

/* ---- index generation files (ix, sx) ---- */

static void st_name_ix(char *buf, size_t n, const char *base, uint32_t gen) { snprintf(buf, n, "%s.%u", base, gen); }

static void ixgen_free(ixgen_t *g) {
  if (!g) return;
  if (g->slots) munmap((void *)g->slots, g->maplen);
  if (g->fd >= 0) close(g->fd);
  free(g);
}
static int ixgen_map(const store_t *s, ixgen_t *g) {
  g->maplen = (size_t)((g->nslots * 8 + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1));
  int fl = MAP_SHARED | ST_NOCORE;
#if defined(MAP_ALIGNED_SUPER)
  if (g->maplen >= (2u << 20)) fl |= MAP_ALIGNED_SUPER;
#endif
  void *p = mmap(NULL, g->maplen, PROT_READ | PROT_WRITE, fl, g->fd, (off_t)ST_HDR_PAGE);
  if (p == MAP_FAILED) return -errno;
  g->slots = p;
  return 0;
}
/* create generation file `gen` of kind (FK_IX / FK_SX) with n empty slots */
static int ixgen_create(store_t *s, uint32_t kind, uint32_t gen, uint64_t nslots, ixgen_t **out) {
  char name[32];
  st_name_ix(name, sizeof(name), kind == FK_IX ? "ix" : "sx", gen);
  ixgen_t *g = calloc(1, sizeof(*g));
  if (!g) return -ENOMEM;
  g->fd = -1;
  g->gen = gen;
  g->nslots = nslots;
  int fd = st_openat(s, name, O_RDWR | O_CREAT | O_TRUNC);
  if (fd < 0) { free(g); return fd; }
  g->fd = fd;
  fhdr_t h;
  fhdr_make(s, &h, kind, gen, 8, nslots);
  uint8_t *page = calloc(1, ST_HDR_PAGE);
  if (!page) { ixgen_free(g); return -ENOMEM; }
  memcpy(page, &h, sizeof(h));
  int r = st_pwrite_all(fd, page, ST_HDR_PAGE, 0);
  free(page);
  if (r == 0) r = st_extend(fd, ST_HDR_PAGE, (off_t)(ST_HDR_PAGE + ((nslots * 8 + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1))));
  if (r == 0) r = ixgen_map(s, g);
  if (r < 0) { ixgen_free(g); return r; }
  s->dir_dirty = true;
  *out = g;
  return 0;
}
static int ixgen_open(store_t *s, uint32_t kind, uint32_t gen, uint64_t nslots, ixgen_t **out) {
  if (nslots == 0 || nslots > ST_IX_MAX_SLOTS || gen == 0) return -EBADMSG;      /* (before any size is computed from it: a forged count would wrap those) */
  char name[32];
  st_name_ix(name, sizeof(name), kind == FK_IX ? "ix" : "sx", gen);
  ixgen_t *g = calloc(1, sizeof(*g));
  if (!g) return -ENOMEM;
  g->fd = -1;
  g->gen = gen;
  g->nslots = nslots;
  int fd = st_openat(s, name, O_RDWR);
  if (fd < 0) { free(g); return fd; }
  g->fd = fd;
  fhdr_t h;
  struct stat st;
  int r = st_pread_all(fd, &h, sizeof(h), 0);
  if (r < 0 || !fhdr_ok(s, &h, kind, gen) || h.a != nslots || fstat(fd, &st) != 0 || st.st_size < 0 ||
      (uint64_t)st.st_size < ST_HDR_PAGE + nslots * 8) {
    ixgen_free(g);
    return -EBADMSG;
  }
  r = ixgen_map(s, g);
  if (r < 0) { ixgen_free(g); return r; }
  *out = g;
  return 0;
}

static void retire_add(store_t *s, ixgen_t *g) {
  retire_t *r = calloc(1, sizeof(*r));
  if (!r) return;   /* leak the mapping rather than free it under a reader */
  r->g = g;
  r->epoch = rcu_writer_advance_epoch();
  if (s->rq_tail) s->rq_tail->next = r; else s->rq_head = r;
  s->rq_tail = r;
}
static void retire_run(store_t *s, bool force) {
  while (s->rq_head && (force || rcu_writer_is_safe(s->rq_head->epoch))) {
    retire_t *r = s->rq_head;
    s->rq_head = r->next;
    if (!s->rq_head) s->rq_tail = NULL;
    ixgen_free(r->g);
    free(r);
  }
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* index probing                                                                                                        */
/* ------------------------------------------------------------------------------------------------------------------ */

static uint32_t ix_lookup(const store_t *s, const ixgen_t *g, uint16_t view, const uint8_t *fn, size_t len, uint64_t h) {
  uint32_t tag = st_tag(h);
  uint64_t n = g->nslots, pos = st_pos(h, n);
  for (uint64_t i = 0; i < n; i++) {
    uint64_t v = atomic_load_explicit(&g->slots[pos], memory_order_acquire);
    if (v == 0) return STORE_NONE;
    uint32_t z = (uint32_t)v;
    if (z != STORE_NONE && (uint32_t)(v >> 32) == tag && st_name_eq(s, z, view, fn, len)) return z;
    if (++pos == n) pos = 0;
  }
  return STORE_NONE;
}
/* position of the slot that holds zid z for hash h; UINT64_MAX when there is none */
static uint64_t slot_find_zid(const ixgen_t *g, uint64_t h, uint32_t z) {
  uint32_t tag = st_tag(h);
  uint64_t n = g->nslots, pos = st_pos(h, n);
  for (uint64_t i = 0; i < n; i++) {
    uint64_t v = atomic_load_explicit(&g->slots[pos], memory_order_relaxed);
    if (v == 0) return UINT64_MAX;
    if ((uint32_t)v == z && (uint32_t)(v >> 32) == tag) return pos;
    if (++pos == n) pos = 0;
  }
  return UINT64_MAX;
}
/* position for an insert: the first tombstone on the way, else the first empty slot; *was_empty tells which */
static uint64_t slot_find_insert(const ixgen_t *g, uint64_t h, bool *was_empty) {
  uint64_t n = g->nslots, pos = st_pos(h, n), tomb = UINT64_MAX;
  for (uint64_t i = 0; i < n; i++) {
    uint64_t v = atomic_load_explicit(&g->slots[pos], memory_order_relaxed);
    if (v == 0) {
      if (tomb != UINT64_MAX) { *was_empty = false; return tomb; }
      *was_empty = true;
      return pos;
    }
    if ((uint32_t)v == STORE_NONE && tomb == UINT64_MAX) tomb = pos;
    if (++pos == n) pos = 0;
  }
  *was_empty = false;
  return tomb;
}
static bool sx_match(const store_t *s, uint32_t z, uint16_t source, uint16_t view, int64_t dom) {
  if ((uint64_t)z >= st_zt_cap(s) || (uint64_t)z >= st_zc_cap(s)) return false;
  const _Atomic uint64_t *c = zc_cell(s, z);
  seqwait_t sw = { 0, 0 };
  for (;;) {                /* (under the sequence counter of the cell, as st_name_eq()) */
    uint64_t w7 = atomic_load_explicit(&c[7], memory_order_acquire);
    if ((uint32_t)(w7 >> 32) & 1u) {
      if (!seq_wait(&sw)) break;
      continue;
    }
    uint64_t w3 = atomic_load_explicit(&zt_cell(s, z)[3], memory_order_acquire);
    uint64_t w0 = atomic_load_explicit(&c[0], memory_order_relaxed);
    atomic_thread_fence(memory_order_acquire);
    if ((uint32_t)(w7 >> 32) != (uint32_t)(atomic_load_explicit(&c[7], memory_order_relaxed) >> 32)) { if (!seq_wait(&sw)) break; continue; }
    return (uint8_t)(w3 >> 32) != STORE_STATE_FREE && (uint16_t)w3 == view && (int64_t)w0 == dom && (uint16_t)w7 == source;
  }
  return false;
}
static uint32_t sx_lookup(const store_t *s, const ixgen_t *g, uint16_t source, uint16_t view, int64_t dom, uint64_t h) {
  uint32_t tag = st_tag(h);
  uint64_t n = g->nslots, pos = st_pos(h, n);
  for (uint64_t i = 0; i < n; i++) {
    uint64_t v = atomic_load_explicit(&g->slots[pos], memory_order_acquire);
    if (v == 0) return STORE_NONE;
    uint32_t z = (uint32_t)v;
    if (z != STORE_NONE && (uint32_t)(v >> 32) == tag && sx_match(s, z, source, view, dom)) return z;
    if (++pos == n) pos = 0;
  }
  return STORE_NONE;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* segments                                                                                                             */
/* ------------------------------------------------------------------------------------------------------------------ */

static void seg_free(seg_t *g) {
  if (!g) return;
  if (g->map) munmap(g->map, g->maplen);
  if (g->fd >= 0) close(g->fd);
  free(g);
}

/* the descriptor of segment n; opens it on first use (the only reader-side mutex: first touch of a segment) */
static seg_t *seg_get(store_t *s, uint32_t n) {
  if (n == 0 || n > ST_MAXSEG) return NULL;
  seg_t *g = atomic_load_explicit(&s->segs[n], memory_order_acquire);
  if (g) return g;
  pthread_mutex_lock(&s->seg_mu);
  g = atomic_load_explicit(&s->segs[n], memory_order_relaxed);
  if (!g) {
    char name[32];
    snprintf(name, sizeof(name), "seg.%u", n);
    int fd = st_openat(s, name, O_RDWR);
    if (fd >= 0) {
      fhdr_t h;
      struct stat st;
      if (st_pread_all(fd, &h, sizeof(h), 0) == 0 && fhdr_ok(s, &h, FK_SEG, n) && fstat(fd, &st) == 0) {
        g = calloc(1, sizeof(*g));
        if (g) {
          g->fd = fd;
          g->num = n;
          if (s->mode == STORE_MODE_MAP) {
            g->maplen = (size_t)st.st_size;
            void *p = g->maplen ? mmap(NULL, g->maplen, PROT_READ, MAP_SHARED | ST_NOCORE, fd, 0) : MAP_FAILED;
            if (p == MAP_FAILED) { free(g); g = NULL; } else g->map = p;
          }
          if (g) atomic_store_explicit(&s->segs[n], g, memory_order_release);
        }
      }
      if (!g) close(fd);
    }
  }
  pthread_mutex_unlock(&s->seg_mu);
  return g;
}
/* writer: create segment n with room for at least `cap` bytes */
static int seg_create(store_t *s, uint32_t n, uint64_t cap) {
  char name[32];
  snprintf(name, sizeof(name), "seg.%u", n);
  int fd = st_openat(s, name, O_RDWR | O_CREAT | O_TRUNC);
  if (fd < 0) return fd;
  fhdr_t h;
  fhdr_make(s, &h, FK_SEG, n, ST_REC, 0);
  uint8_t page[ST_SEGHDR];
  memcpy(page, &h, sizeof(h));
  int r = st_pwrite_all(fd, page, ST_SEGHDR, 0);
  if (r == 0 && s->mode == STORE_MODE_MAP) {
    /* MAP: the file has its full size from the start (sparse), so the one read-only mapping never has to grow */
    uint64_t sz = (cap + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1);
    if (ftruncate(fd, (off_t)sz) != 0) r = -errno;
  }
  if (r < 0) { close(fd); return r; }
  s->dir_dirty = true;
  seg_t *old = atomic_load_explicit(&s->segs[n], memory_order_relaxed);
  if (old) { atomic_store_explicit(&s->segs[n], NULL, memory_order_release); seg_free(old); }
  close(fd);
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* journal builder                                                                                                      */
/* ------------------------------------------------------------------------------------------------------------------ */

static void jb_reset(jb_t *j) {
  j->len = ST_JREC_HDR;
  j->nops = 0;
  j->nv = 0;
}
static uint8_t *jb_op(jb_t *j, uint16_t type, size_t paylen) {
  paylen = (paylen + 7) & ~(size_t)7;
  size_t need = j->len + 8 + paylen;
  if (need > j->cap) {
    size_t nc = j->cap ? j->cap : 4096;
    while (nc < need) nc *= 2;
    uint8_t *np = realloc(j->p, nc);
    if (!np) return NULL;
    j->p = np;
    j->cap = nc;
  }
  uint8_t *t = j->p + j->len;
  memset(t, 0, 8 + paylen);
  memcpy(t, &type, 2);
  uint32_t l = (uint32_t)paylen;
  memcpy(t + 4, &l, 4);
  j->len = need;
  j->nops++;
  return t + 8;
}
static int jb_vset(jb_t *j, uint32_t fid, uint64_t val) {
  for (unsigned i = 0; i < j->nv; i++)
    if (j->vs[i].fid == fid) { j->vs[i].val = val; return 0; }
  if (j->nv >= JB_MAXV) return -ENOMEM;
  j->vs[j->nv].fid = fid;
  j->vs[j->nv].val = val;
  j->nv++;
  return 0;
}
static uint64_t jb_vget(const store_t *s, const jb_t *j, uint32_t fid) {
  for (unsigned i = 0; i < j->nv; i++)
    if (j->vs[i].fid == fid) return j->vs[i].val;
  return VG(s, fid);
}
static int jb_vadd(const store_t *s, jb_t *j, uint32_t fid, int64_t delta) {
  uint64_t cur = jb_vget(s, j, fid);
  uint64_t nv = delta < 0 ? (cur >= (uint64_t)-delta ? cur - (uint64_t)-delta : 0) : cur + (uint64_t)delta;
  return jb_vset(j, fid, nv);
}
static int jb_flush_v(jb_t *j) {
  if (!j->nv) return 0;
  uint8_t *p = jb_op(j, OP_V, 8 + (size_t)j->nv * 16);
  if (!p) return -ENOMEM;
  uint32_t n = j->nv;
  memcpy(p, &n, 4);
  for (unsigned i = 0; i < j->nv; i++) {
    memcpy(p + 8 + i * 16, &j->vs[i].fid, 4);
    memcpy(p + 8 + i * 16 + 8, &j->vs[i].val, 8);
  }
  j->nv = 0;
  return 0;
}
static int jb_zrec(jb_t *j, uint32_t z, const r64_t *zt, const r64_t *zc) {
  uint8_t *p = jb_op(j, OP_ZREC, 8 + 128);
  if (!p) return -ENOMEM;
  memcpy(p, &z, 4);
  memcpy(p + 8, zt, 64);
  memcpy(p + 72, zc, 64);
  return 0;
}
static int jb_slot(jb_t *j, uint16_t type, uint64_t pos, uint64_t val) {
  uint8_t *p = jb_op(j, type, 8 + 16);
  if (!p) return -ENOMEM;
  uint32_t n = 1;
  memcpy(p, &n, 4);
  memcpy(p + 8, &pos, 8);
  memcpy(p + 16, &val, 8);
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* apply: the one place that changes cells (live and replay)                                                            */
/* ------------------------------------------------------------------------------------------------------------------ */

static int ensure_zt_cap(store_t *s, uint64_t nrec) {
  uint64_t need = nrec * ST_REC;
  int r = mtab_grow(s, &s->zt, need);
  if (r < 0) return r;
  return mtab_grow(s, &s->zc, need);
}
static int ensure_nx_cap(store_t *s, uint64_t bytes) { return mtab_grow(s, &s->nx, bytes); }

static int switch_gen(store_t *s, uint32_t which, uint32_t gen, uint64_t nslots) {
  ixgen_t *g = NULL;
  int r = ixgen_open(s, which == 0 ? FK_IX : FK_SX, gen, nslots, &g);
  if (r < 0) return r;
  _Atomic(ixgen_t *) *slot = which == 0 ? &s->ix : &s->sx;
  ixgen_t *old = atomic_exchange_explicit(slot, g, memory_order_acq_rel);
  if (which == 0) s->ix_gen = gen; else s->sx_gen = gen;
  if (old) retire_add(s, old);
  return 0;
}

/* Apply one record's ops.  Returns 0, or -EINVAL when an op does not fit the store (a replay then asks for a rebuild). */
static int apply_ops(store_t *s, const uint8_t *ops, size_t len) {
  size_t off = 0;
  int bad = 0;
  while (off + 8 <= len) {
    uint16_t type;
    uint32_t pl;
    memcpy(&type, ops + off, 2);
    memcpy(&pl, ops + off + 4, 4);
    const uint8_t *p = ops + off + 8;
    if ((size_t)pl > len - off - 8) return -EINVAL;
    off += 8 + (size_t)pl;
    switch (type) {
    case OP_ZREC: {
      uint32_t z;
      if (pl < 136) { bad = -EINVAL; break; }
      memcpy(&z, p, 4);
      if ((uint64_t)z >= s->zt.reserve / ST_REC || ensure_zt_cap(s, (uint64_t)z + 1) < 0) { bad = -EINVAL; break; }
      r64_t zt, zc;
      memcpy(&zt, p + 8, 64);
      memcpy(&zc, p + 72, 64);
      zrec_write(s, z, &zt, &zc);
      break;
    }
    case OP_NX: {
      uint64_t o;
      uint32_t n;
      if (pl < 16) { bad = -EINVAL; break; }
      memcpy(&o, p, 8);
      memcpy(&n, p + 8, 4);
      if ((uint64_t)n + 16 > pl || o > s->nx.reserve || n > s->nx.reserve - o || ensure_nx_cap(s, o + n) < 0) { bad = -EINVAL; break; }
      memcpy(s->nx.base + o, p + 16, n);
      uint64_t cur = atomic_load_explicit(&s->nx_avail, memory_order_relaxed);
      if (o + n > cur) atomic_store_explicit(&s->nx_avail, o + n, memory_order_release);
      break;
    }
    case OP_IX:
    case OP_SX: {
      uint32_t n;
      if (pl < 8) { bad = -EINVAL; break; }
      memcpy(&n, p, 4);
      if ((uint64_t)n * 16 + 8 > pl) { bad = -EINVAL; break; }
      ixgen_t *g = atomic_load_explicit(type == OP_IX ? &s->ix : &s->sx, memory_order_relaxed);
      for (uint32_t i = 0; i < n; i++) {
        uint64_t pos, val;
        memcpy(&pos, p + 8 + i * 16, 8);
        memcpy(&val, p + 16 + i * 16, 8);
        if (!g || pos >= g->nslots) { bad = -EINVAL; continue; }
        atomic_store_explicit(&g->slots[pos], val, memory_order_release);
      }
      break;
    }
    case OP_V: {
#ifdef KARIDNS_UNIT_TEST
      if (store_test_before_counters) store_test_before_counters(s);
#endif
      uint32_t n;
      if (pl < 8) { bad = -EINVAL; break; }
      memcpy(&n, p, 4);
      if ((uint64_t)n * 16 + 8 > pl) { bad = -EINVAL; break; }
      for (uint32_t i = 0; i < n; i++) {
        uint32_t fid;
        uint64_t val;
        memcpy(&fid, p + 8 + i * 16, 4);
        memcpy(&val, p + 8 + i * 16 + 8, 8);
        if (!v_value_ok(s, fid, val)) { bad = -EINVAL; continue; }       /* (the value is used as an index or a size: not taken in) */
        VS(s, fid, val);
      }
      break;
    }
    case OP_VIEW: {
      uint32_t id;
      if (pl < 8 + STORE_VIEW_NAME_MAX + 1) { bad = -EINVAL; break; }
      memcpy(&id, p, 4);
      if (id >= ST_MAXV) { bad = -EINVAL; break; }
      memcpy(s->views[id], p + 8, STORE_VIEW_NAME_MAX + 1);
      s->views[id][STORE_VIEW_NAME_MAX] = 0;
      if (atomic_load_explicit(&s->nviews, memory_order_relaxed) < id + 1)
        atomic_store_explicit(&s->nviews, id + 1, memory_order_release);
      break;
    }
    case OP_SRC: {
      uint32_t src, valid, il;
      uint64_t cur;
      if (pl < 24 + STORE_IDENT_MAX) { bad = -EINVAL; break; }
      memcpy(&src, p, 4);
      memcpy(&valid, p + 4, 4);
      memcpy(&cur, p + 8, 8);
      memcpy(&il, p + 16, 4);
      if (src >= ST_MAXSRC || il > STORE_IDENT_MAX) { bad = -EINVAL; break; }
      s->src[src].valid = valid;
      s->src[src].cursor = cur;
      s->src[src].identlen = il;
      memcpy(s->src[src].ident, p + 24, STORE_IDENT_MAX);
      break;
    }
    case OP_GEN: {
      uint32_t which, gen;
      uint64_t ns;
      if (pl < 16) { bad = -EINVAL; break; }
      memcpy(&which, p, 4);
      memcpy(&gen, p + 4, 4);
      memcpy(&ns, p + 8, 8);
      if (which > 1 || switch_gen(s, which, gen, ns) < 0) bad = -EINVAL;
      break;
    }
    case OP_REBUILD:
      /* a marker that store_repair() logs before it changes a cell: a replay that finds it (the repair did not reach its checkpoint) has the derived tables rebuilt */
      bad = -EINVAL;
      break;
    default:
      bad = -EINVAL;
      break;
    }
    CRASH_POINT();
  }
  return bad;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* journal file: append, commit                                                                                         */
/* ------------------------------------------------------------------------------------------------------------------ */

static int journal_open_new(store_t *s, uint32_t gen, uint64_t base_lsn) {
  char name[32];
  st_name_ix(name, sizeof(name), "jrn", gen);
  int fd = st_openat(s, name, O_RDWR | O_CREAT | O_TRUNC);
  if (fd < 0) return fd;
  fhdr_t h;
  fhdr_make(s, &h, FK_JRN, gen, 8, base_lsn);
  uint8_t page[ST_JHDR];
  memset(page, 0, sizeof(page));
  memcpy(page, &h, sizeof(h));
  int r = st_pwrite_all(fd, page, ST_JHDR, 0);
  if (r == 0 && fdatasync(fd) != 0) r = -errno;
  if (r < 0) { close(fd); return r; }
  s->dir_dirty = true;
  if (s->jfd >= 0) close(s->jfd);
  s->jfd = fd;
  s->jbytes = ST_JHDR;
  s->jrn_gen = gen;
  return 0;
}

static int checkpoint_locked(store_t *s, bool clean);

/* finish the builder's record (counters last), give it its LSN and CRC, write it.  The cells are not touched. */
static int journal_append(store_t *s) {
  jb_t *j = &s->jb;
  int r = jb_flush_v(j);
  if (r < 0) return r;
  /* the last checkpoint on disk says "clean stop" (store_checkpoint_clean()) and this is a change after it: the flag is cleared durably first, as the open does
   * (a record after a clean flag would not make the next open after a power loss rebuild the tables) */
  if (s->clean_on_disk && (r = checkpoint_locked(s, false)) < 0) return r;
  jrec_t h;
  h.magic = ST_MAGIC_JREC;
  h.len = (uint32_t)j->len;
  h.crc = 0;
  h.nops = j->nops;
  h.lsn = s->lsn + 1;
  memcpy(j->p, &h, sizeof(h));
  uint32_t crc = st_crc32c(0, j->p, j->len);
  memcpy(j->p + 8, &crc, 4);
  CRASH_POINT();
  r = st_pwrite_all(s->jfd, j->p, j->len, (off_t)s->jbytes);
  if (r < 0) return r;
  s->jbytes += j->len;
  s->lsn = h.lsn;
  s->uncommitted++;
  CRASH_POINT();
  return 0;
}

/* log the built record, then apply its ops */
static int journal_commit_apply(store_t *s) {
  int r = journal_append(s);
  if (r < 0) return r;
  r = apply_ops(s, s->jb.p + ST_JREC_HDR, s->jb.len - ST_JREC_HDR);
  CRASH_POINT();
  return r;
}

static int commit_locked(store_t *s) {
#ifdef KARIDNS_UNIT_TEST
  if (store_test_fail_commit > 0 && --store_test_fail_commit == 0) return -EIO;
#endif
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS);
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  for (uint32_t n = 1; n <= nsegs; n++) {
    if (!s->seg_dirty[n]) continue;
    seg_t *g = atomic_load_explicit(&s->segs[n], memory_order_relaxed);
    if (g && fdatasync(g->fd) != 0) return -errno;
    s->seg_dirty[n] = 0;
  }
  CRASH_POINT();
  /* new files (segments, journals) are in the directory before a journal record that refers to them is durable */
  if (s->dir_dirty) {
    if (fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) return -errno;
    s->dir_dirty = false;
  }
  if (s->jfd >= 0 && fdatasync(s->jfd) != 0) return -errno;
  s->committed_lsn = s->lsn;
  s->uncommitted = 0;
  s->last_sync_ms = st_now_ms();
  s->n_commits++;
  CRASH_POINT();
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* superblock                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

static const char *const st_sb_names[2] = { "super.a", "super.b" };

static void sb_fill(store_t *s, sb_t *b, bool clean, uint64_t seq, uint32_t jrn_gen) {
  memset(b, 0, sizeof(*b));
  memcpy(b->f.magic, "KARISTOR", 8);
  b->f.version = STORE_FORMAT_VERSION;
  b->f.size = ST_SB_SIZE;
  b->f.seq = seq;
  memcpy(b->f.uuid, s->uuid, 16);
  b->f.hk0 = s->hk0;
  b->f.hk1 = s->hk1;
  b->f.flags = clean ? SBF_CLEAN : 0;
  b->f.boot_id = s->boot_id;
  b->f.ckpt_lsn = s->lsn;
  b->f.ckpt_time = (uint64_t)time(NULL);
  b->f.ckpt_us = s->ckpt_us;
  b->f.jrn_gen = jrn_gen;
  b->f.ix_gen = s->ix_gen;
  b->f.sx_gen = s->sx_gen;
  b->f.nviews = atomic_load_explicit(&s->nviews, memory_order_relaxed);
  b->f.zt_cap = st_zt_cap(s);
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  b->f.ix_slots = ix ? ix->nslots : 0;
  b->f.sx_slots = sx ? sx->nslots : 0;
  b->f.seg_size = s->seg_size;
  b->f.nx_cap = atomic_load_explicit(&s->nx.mapped, memory_order_relaxed);
  memcpy(b->f.views, s->views, sizeof(s->views));
  memcpy(b->f.src, s->src, sizeof(s->src));
  for (uint32_t i = 0; i < ST_NV; i++) b->f.v[i] = VG(s, i);
  b->f.crc = 0;
  b->f.crc = st_crc32c(0, b, sizeof(*b));
}
/* The fields of a superblock copy that are used as sizes, counts or indexes, against hard limits (the CRC is no protection against a forged copy).  The
 * values that need the open files (zt, nx) are checked in adopt_sb(). */
static bool sb_fields_ok(const sb_t *b) {
  if (b->f.nviews > ST_MAXV || b->f.seq == 0) return false;
  if (b->f.seg_size < 65536 || b->f.seg_size > ST_SEG_MAX) return false;
  if (b->f.jrn_gen == 0 || b->f.ix_gen == 0 || b->f.sx_gen == 0) return false;
  if (b->f.ix_slots == 0 || b->f.ix_slots > ST_IX_MAX_SLOTS || b->f.sx_slots == 0 || b->f.sx_slots > ST_IX_MAX_SLOTS) return false;
  if (b->f.zt_cap > 0xFFFFFFFFull || b->f.nx_cap > (1ull << 40)) return false;
  for (uint32_t i = 0; i < b->f.nviews; i++)
    if (!memchr(b->f.views[i], 0, sizeof(b->f.views[i]))) return false;          /* (a view name is a string) */
  for (uint32_t i = 0; i < ST_MAXSRC; i++)
    if (b->f.src[i].identlen > STORE_IDENT_MAX) return false;
  return true;
}
/* read and check one copy; 0 = ok, -ENOENT = no file, -EBADMSG = damaged */
static int sb_read(store_t *s, int slot, sb_t *b) {
  int fd = s->sb_fd[slot];
  if (fd < 0) return -ENOENT;
  struct stat st;
  if (fstat(fd, &st) != 0) return -errno;
  if (st.st_size == 0) return -ENOENT;
  if ((size_t)st.st_size != ST_SB_SIZE || st_pread_all(fd, b, sizeof(*b), 0) < 0) return -EBADMSG;
  uint32_t crc = b->f.crc;
  b->f.crc = 0;
  uint32_t calc = st_crc32c(0, b, sizeof(*b));
  b->f.crc = crc;
  if (memcmp(b->f.magic, "KARISTOR", 8) != 0 || b->f.version != STORE_FORMAT_VERSION || b->f.size != ST_SB_SIZE || crc != calc)
    return -EBADMSG;
  if (!sb_fields_ok(b)) return -EBADMSG;
  return 0;
}
static int sb_write(store_t *s, bool clean, uint32_t jrn_gen) {
  int slot = s->sb_next;
  sb_fill(s, s->sbbuf, clean, s->sb_seq + 1, jrn_gen);
  int r = st_pwrite_all(s->sb_fd[slot], s->sbbuf, ST_SB_SIZE, 0);
  if (r == 0 && fdatasync(s->sb_fd[slot]) != 0) r = -errno;
  if (r < 0) return r;
  s->sb_seq++;
  s->slot_jrn[slot] = jrn_gen;
  s->slot_ix[slot] = s->ix_gen;
  s->slot_sx[slot] = s->sx_gen;
  s->sb_next = slot ^ 1;
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* checkpoint                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

static void unlink_old_gens(store_t *s) {
  struct { const char *base; uint32_t a, b; } k[3] = {
    { "jrn", s->slot_jrn[0], s->slot_jrn[1] }, { "ix", s->slot_ix[0], s->slot_ix[1] }, { "sx", s->slot_sx[0], s->slot_sx[1] } };
  for (int i = 0; i < 3; i++) {
    uint32_t lo = k[i].a < k[i].b ? k[i].a : k[i].b;
    for (uint32_t g = lo; g > 1 && lo - g < 8; ) {
      g--;
      char name[32];
      st_name_ix(name, sizeof(name), k[i].base, g);
      if (unlinkat(s->dirfd, name, 0) == 0) s->dir_dirty = true;
    }
  }
}

static int checkpoint_locked(store_t *s, bool clean) {
  uint64_t t0 = st_now_us();
  int r = commit_locked(s);
  if (r < 0) return r;
  mtab_t *tabs[3] = { &s->zt, &s->zc, &s->nx };
  for (int i = 0; i < 3 && r == 0; i++) r = mtab_sync(tabs[i]);
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  if (r == 0 && ix && msync((void *)ix->slots, ix->maplen, MS_SYNC) != 0) r = -errno;
  if (r == 0 && ix && fdatasync(ix->fd) != 0) r = -errno;
  if (r == 0 && sx && msync((void *)sx->slots, sx->maplen, MS_SYNC) != 0) r = -errno;
  if (r == 0 && sx && fdatasync(sx->fd) != 0) r = -errno;
  if (r < 0) return r;
  CRASH_POINT();
  /* the next journal first (its base LSN continues the chain), then the superblock that names it */
  uint32_t ngen = s->jrn_gen + 1;
  r = journal_open_new(s, ngen, s->lsn + 1);
  if (r < 0) return r;
  CRASH_POINT();
  if (s->dir_dirty) {
    if (fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) return -errno;
    s->dir_dirty = false;
  }
  s->ckpt_us = st_now_us() - t0;
  r = sb_write(s, clean, ngen);
  if (r < 0) return r;
  CRASH_POINT();
  s->ckpt_lsn = s->lsn;
  s->ckpt_time = (uint64_t)time(NULL);
  s->last_ckpt_ms = st_now_ms();
  s->clean_on_disk = clean;
  s->n_checkpoints++;
  unlink_old_gens(s);
  retire_run(s, false);
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* index (re)build: growth and repair                                                                                   */
/* ------------------------------------------------------------------------------------------------------------------ */

static int ix_raw_insert(ixgen_t *g, uint64_t h, uint32_t z) {
  uint64_t n = g->nslots, pos = st_pos(h, n);
  for (uint64_t i = 0; i < n; i++) {
    if (atomic_load_explicit(&g->slots[pos], memory_order_relaxed) == 0) {
      atomic_store_explicit(&g->slots[pos], st_slotval(st_tag(h), z), memory_order_relaxed);
      return 0;
    }
    if (++pos == n) pos = 0;
  }
  return -ENOSPC;
}
static uint64_t ix_slots_for(uint64_t live) {
  uint64_t n = live * 3 + 16;
  return n < ST_IX_MIN ? ST_IX_MIN : n;
}

static int index_publish(store_t *s, uint32_t which, ixgen_t *g) {
  _Atomic(ixgen_t *) *slot = which == 0 ? &s->ix : &s->sx;
  ixgen_t *old = atomic_exchange_explicit(slot, g, memory_order_acq_rel);
  if (which == 0) s->ix_gen = g->gen; else s->sx_gen = g->gen;
  if (old) retire_add(s, old);
  return 0;
}

/* Replace ix and / or sx (a non-zero slot count) by new generations built from a pass over zt; a checkpoint barrier.
 * Under the writer mutex; readers continue on the old generation. */
static int index_regrow(store_t *s, uint64_t ix_slots, uint64_t sx_slots) {
  uint64_t hwm = VG(s, V_HWM);
  ixgen_t *nix = NULL, *nsx = NULL;
  uint64_t live_ix = 0, live_sx = 0;
  int r = 0;
  if (ix_slots && (r = ixgen_create(s, FK_IX, s->ix_gen + 1, ix_slots, &nix)) < 0) return r;
  if (sx_slots && (r = ixgen_create(s, FK_SX, s->sx_gen + 1, sx_slots, &nsx)) < 0) { ixgen_free(nix); return r; }
  for (uint64_t z = 0; z < hwm && r == 0; z++) {
    r64_t rt, rc;
    if (zt_state_fast(s, (uint32_t)z) == STORE_STATE_FREE) continue;
    if (zrec_read_locked(s, (uint32_t)z, &rt, &rc) < 0) continue;     /* damaged: stays invisible */
    zt_t t;
    zc_t c;
    zt_unpack(&rt, &t);
    zc_unpack(&rc, &c);
    if (nix) {
      uint8_t fn[256];
      if (!zt_fullname(s, &t, fn)) continue;
      if (ix_raw_insert(nix, st_hash_name(s, t.view, fn, t.klen), (uint32_t)z) < 0) { r = -ENOSPC; break; }
      live_ix++;
    }
    if (nsx && c.source_id != 0) {
      if (ix_raw_insert(nsx, st_hash_src(s, c.source, t.view, c.source_id), (uint32_t)z) < 0) { r = -ENOSPC; break; }
      live_sx++;
    }
  }
  if (r == 0 && nix) r = (msync((void *)nix->slots, nix->maplen, MS_SYNC) != 0 || fdatasync(nix->fd) != 0) ? -errno : 0;
  if (r == 0 && nsx) r = (msync((void *)nsx->slots, nsx->maplen, MS_SYNC) != 0 || fdatasync(nsx->fd) != 0) ? -errno : 0;
  if (r < 0) { ixgen_free(nix); ixgen_free(nsx); return r; }
  CRASH_POINT();
  /* the bridge in the journal chain: GEN ops and the counters of the new tables */
  jb_reset(&s->jb);
  if (nix) {
    uint8_t *p = jb_op(&s->jb, OP_GEN, 16);
    uint32_t w = 0, g = nix->gen;
    if (!p) r = -ENOMEM; else { memcpy(p, &w, 4); memcpy(p + 4, &g, 4); memcpy(p + 8, &nix->nslots, 8); }
    jb_vset(&s->jb, V_IX_USED, live_ix);
    jb_vset(&s->jb, V_IX_LIVE, live_ix);
  }
  if (r == 0 && nsx) {
    uint8_t *p = jb_op(&s->jb, OP_GEN, 16);
    uint32_t w = 1, g = nsx->gen;
    if (!p) r = -ENOMEM; else { memcpy(p, &w, 4); memcpy(p + 4, &g, 4); memcpy(p + 8, &nsx->nslots, 8); }
    jb_vset(&s->jb, V_SX_USED, live_sx);
    jb_vset(&s->jb, V_SX_LIVE, live_sx);
  }
  if (r == 0) r = journal_append(s);
  if (r < 0) { ixgen_free(nix); ixgen_free(nsx); return r; }       /* (nothing is logged: the old generations stay, the new files are garbage that the next growth overwrites) */
  /* The record is in the journal now, so the memory follows it whatever the sync says: a replay switches to the new generations, and so does this process.  A failed
   * sync is reported (the growth, and the write that wanted room, fail) but does not leave the index on the old generation while the journal names the new one. */
  const int rc_sync = commit_locked(s);
  /* the journal now names the new generations; publish them (the files stay open: apply_ops would only reopen them) */
  if (nix) {
    index_publish(s, 0, nix);
    VS(s, V_IX_USED, live_ix);
    VS(s, V_IX_LIVE, live_ix);
  }
  if (nsx) {
    index_publish(s, 1, nsx);
    VS(s, V_SX_USED, live_sx);
    VS(s, V_SX_LIVE, live_sx);
  }
  s->n_growths++;
  CRASH_POINT();
  if (rc_sync < 0) return rc_sync;
  return checkpoint_locked(s, false);
}

static int ix_make_room(store_t *s, bool need_sx) {
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  uint64_t nix = 0, nsx = 0;
  if ((VG(s, V_IX_USED) + 1) * 2 > ix->nslots) nix = ix_slots_for(VG(s, V_IX_LIVE) + 1);
  if (need_sx && (VG(s, V_SX_USED) + 1) * 2 > sx->nslots) nsx = ix_slots_for(VG(s, V_SX_LIVE) + 1);
  if (!nix && !nsx) return 0;
  return index_regrow(s, nix, nsx);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* writer: put / set_known / delete / flags / views / cursors                                                          */
/* ------------------------------------------------------------------------------------------------------------------ */

static unsigned name_labels(const uint8_t *n, size_t len) {
  if (len == 0) return 0;
  unsigned c = 1;
  for (size_t i = 0; i < len; i++) {
    if (n[i] == '\\' && i + 1 < len) i++;
    else if (n[i] == '.') c++;
  }
  return c;
}
static inline unsigned depth_bucket(unsigned labels) { return labels > 63 ? 63 : labels; }

static void note_error(store_t *s, int r) {
  if (r == -ENOSPC || r == -EFBIG || r == -EDQUOT) atomic_fetch_or(&s->state, STORE_ST_DEGRADED_NOSPC);
  if (r < 0) s->n_write_errors++;
}
static void note_ok(store_t *s) { atomic_fetch_and(&s->state, ~(uint32_t)STORE_ST_DEGRADED_NOSPC); }

/* time- and size-driven commit / checkpoint after a writer call */
static int post_write(store_t *s) {
  int r = 0;
  uint64_t now = st_now_ms();
  if (s->o.sync_policy == STORE_SYNC_EVERY) r = commit_locked(s);
  else if (s->o.sync_policy == STORE_SYNC_BATCH && s->uncommitted && now - s->last_sync_ms >= s->o.sync_interval_ms) r = commit_locked(s);
  if (r == 0) {
    if (s->jbytes >= s->o.journal_max_bytes) r = checkpoint_locked(s, false);
    else if (s->o.checkpoint_interval_ms != UINT32_MAX && s->lsn > s->ckpt_lsn && now - s->last_ckpt_ms >= s->o.checkpoint_interval_ms)
      r = checkpoint_locked(s, false);
  }
  retire_run(s, false);
  if (r < 0) note_error(s, r);
  return r;
}

/* append an image record to the open segment (creating the next one when it does not fit); plans the counters.
 * *loc receives the location. */
static int seg_append(store_t *s, uint32_t zid, uint16_t view, const uint8_t *fn, size_t klen, const store_meta_t *m,
                      const void *image, size_t ilen, uint64_t prev_loc, uint64_t *loc, uint64_t *rlen_out) {
  jb_t *j = &s->jb;
  uint64_t rlen = st_reclen(klen, ilen);
  uint32_t cur = (uint32_t)jb_vget(s, j, V_CUR_SEG);
  uint64_t used = cur ? jb_vget(s, j, V_SEG(cur, 0)) : 0;
  if (cur == 0 || used + rlen > s->seg_size) {
    uint32_t n = (uint32_t)jb_vget(s, j, V_NSEGS) + 1;
    if (n > ST_MAXSEG) return -ENOSPC;
    uint64_t cap = s->seg_size;
    if (ST_SEGHDR + rlen > cap) cap = ST_SEGHDR + rlen;
    int r = seg_create(s, n, cap);
    if (r < 0) return r;
    if ((r = jb_vset(j, V_NSEGS, n)) < 0 || (r = jb_vset(j, V_CUR_SEG, n)) < 0 || (r = jb_vset(j, V_SEG(n, 0), ST_SEGHDR)) < 0 ||
        (r = jb_vset(j, V_SEG(n, 1), 0)) < 0)
      return r;
    cur = n;
    used = ST_SEGHDR;
  }
  seg_t *g = seg_get(s, cur);
  if (!g) return -EIO;
  rhdr_t h;
  memset(&h, 0, sizeof(h));
  h.magic = ST_MAGIC_REC;
  h.reclen = (uint32_t)rlen;
  h.zid = zid;
  h.view = view;
  h.kind = 0;
  h.flags = m->flags;
  h.serial = m->serial;
  h.settings = m->settings;
  h.img_len = (uint32_t)ilen;
  h.stamp_gen = m->stamp_gen;
  h.prev_loc = prev_loc;
  h.klen = (uint16_t)klen;
  uint8_t namepad[256 + 16];
  size_t np = st_pad16(klen);
  memset(namepad, 0, np);
  memcpy(namepad, fn, klen);
  uint8_t tail[64] = { 0 };
  size_t tl = (size_t)(rlen - ST_RHDR - np - ilen);
  uint64_t sum = st_sum64(&h, sizeof(h), 0);
  sum = st_sum64(namepad, np, sum);
  sum = st_sum64(image, ilen, sum);
  h.checksum = sum;
  struct iovec iov[4] = { { &h, sizeof(h) }, { namepad, np }, { (void *)image, ilen }, { tail, tl } };
  size_t total = sizeof(h) + np + ilen + tl;
  off_t off = (off_t)used;
  size_t done = 0;
  CRASH_POINT();
  while (done < total) {
    struct iovec v[4];
    int nv = 0;
    size_t skip = done;
    for (int i = 0; i < 4; i++) {
      if (skip >= iov[i].iov_len) { skip -= iov[i].iov_len; continue; }
      v[nv].iov_base = (uint8_t *)iov[i].iov_base + skip;
      v[nv].iov_len = iov[i].iov_len - skip;
      skip = 0;
      nv++;
    }
    ssize_t w = pwritev(g->fd, v, nv, off + (off_t)done);
    if (w < 0) {
      if (errno == EINTR) continue;
      return -errno;
    }
    if (w == 0) return -EIO;
    done += (size_t)w;
  }
  CRASH_POINT();
  s->seg_dirty[cur] = 1;
  *loc = ((uint64_t)cur << ST_LOC_SHIFT) | (used / 64);
  *rlen_out = rlen;
  int r = jb_vset(j, V_SEG(cur, 0), used + rlen);
  if (r == 0) r = jb_vset(j, V_SEG(cur, 1), jb_vget(s, j, V_SEG(cur, 1)) + rlen);
  return r;
}

/* counters for a zone leaving / entering a state: sign = -1 or +1 */
static int count_zone(store_t *s, uint16_t view, uint8_t state, uint16_t flags, uint64_t rlen, int sign) {
  jb_t *j = &s->jb;
  int r;
  int64_t d = sign;
  if (state == STORE_STATE_KNOWN) {
    if ((r = jb_vadd(s, j, V_KNOWN, d)) < 0 || (r = jb_vadd(s, j, V_VIEW(view, 0), d)) < 0) return r;
  } else if (state == STORE_STATE_STORED) {
    if ((r = jb_vadd(s, j, V_STORED, d)) < 0 || (r = jb_vadd(s, j, V_VIEW(view, 1), d)) < 0) return r;
    if ((r = jb_vadd(s, j, V_IMG_BYTES, d * (int64_t)rlen)) < 0 || (r = jb_vadd(s, j, V_VIEW(view, 3), d * (int64_t)rlen)) < 0) return r;
  }
  if (flags & STORE_F_REJECTED_NEW) {
    if ((r = jb_vadd(s, j, V_REJECTED, d)) < 0 || (r = jb_vadd(s, j, V_VIEW(view, 2), d)) < 0) return r;
  }
  return 0;
}
static int release_old_record(store_t *s, const zt_t *old) {
  if (old->state != STORE_STATE_STORED || old->loc == 0) return 0;
  uint32_t sn = (uint32_t)(old->loc >> ST_LOC_SHIFT);
  if (sn == 0 || sn > ST_MAXSEG) return 0;
  return jb_vadd(s, &s->jb, V_SEG(sn, 1), -(int64_t)st_reclen(old->klen, old->img_len));
}

static int put_locked(store_t *s, uint16_t view, const char *name, size_t nlen, const store_meta_t *m, const void *image,
                      size_t ilen, uint8_t state, uint32_t *zid_out) {
  jb_t *j = &s->jb;
  uint8_t fn[256];
  for (size_t i = 0; i < nlen; i++) fn[i] = st_lc((uint8_t)name[i]);
  uint64_t h = st_hash_name(s, view, fn, nlen);
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
  uint32_t z = ix_lookup(s, ix, view, fn, nlen, h);
  bool exists = z != STORE_NONE;
  r64_t ort, orc;
  zt_t ot;
  zc_t oc;
  memset(&ot, 0, sizeof(ot));
  memset(&oc, 0, sizeof(oc));
  if (exists) {
    int rr = zrec_read_locked(s, z, &ort, &orc);
    if (rr < 0) return rr;
    zt_unpack(&ort, &ot);
    zc_unpack(&orc, &oc);
  }
  /* conflict of the source key: another zone owns (source, domain id, view) */
  uint64_t sxh = 0;
  if (m->source_id != 0) {
    sxh = st_hash_src(s, m->source, view, m->source_id);
    uint32_t o = sx_lookup(s, atomic_load_explicit(&s->sx, memory_order_relaxed), m->source, view, m->source_id, sxh);
    if (o != STORE_NONE && o != z) return -EEXIST;
  }
  bool sx_new = m->source_id != 0 && (!exists || oc.source_id != m->source_id || oc.source != m->source);
  bool sx_old = exists && oc.source_id != 0 && (m->source_id != oc.source_id || m->source != oc.source);
  /* room: zid, nx, index slots */
  if (!exists) {
    int r = ix_make_room(s, sx_new);
    if (r < 0) return r;
    ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
  } else if (sx_new) {
    int r = ix_make_room(s, true);
    if (r < 0) return r;
  }
  jb_reset(j);
  int r;
  uint64_t loc = 0, rlen = 0;
  uint32_t nz = z;
  if (!exists) {
    uint64_t fh = jb_vget(s, j, V_FREE_HEAD);
    bool from_free = false;
    /* a zone id comes back only after the grace period of the delete that freed it: a reader that found the zone by the index before the delete may still be
     * looking at its cell (design 3.4).  Until then the table grows and the list keeps the cell. */
    if (fh != STORE_NONE && fh < st_zt_cap(s) && rcu_writer_is_safe(s->free_epoch)) {
      r64_t fr, fc;
      zt_t ft;
      memset(&ft, 0, sizeof(ft));
      bool usable = fh < jb_vget(s, j, V_HWM) && zrec_read_locked(s, (uint32_t)fh, &fr, &fc) == 0;
      if (usable) zt_unpack(&fr, &ft);
      if (usable && ft.state == STORE_STATE_FREE) {
        nz = (uint32_t)fh;
        from_free = true;
        if ((r = jb_vset(j, V_FREE_HEAD, ft.loc & 0xffffffffu)) < 0 || (r = jb_vadd(s, j, V_FREE_COUNT, -1)) < 0) return r;
      } else {                /* a damaged cell, or one that is not FREE, on the free list: drop the list (store_repair finds the cells again) and grow */
        if ((r = jb_vset(j, V_FREE_HEAD, STORE_NONE)) < 0 || (r = jb_vset(j, V_FREE_COUNT, 0)) < 0) return r;
      }
    } else if (fh != STORE_NONE && fh >= st_zt_cap(s)) {
      if ((r = jb_vset(j, V_FREE_HEAD, STORE_NONE)) < 0 || (r = jb_vset(j, V_FREE_COUNT, 0)) < 0) return r;
    }
    if (!from_free) {
      uint64_t hwm = jb_vget(s, j, V_HWM);
      if (hwm >= 0xFFFFFFFEu) return -ENOSPC;
      if ((r = ensure_zt_cap(s, hwm + 1)) < 0) return r;
      nz = (uint32_t)hwm;
      if ((r = jb_vset(j, V_HWM, hwm + 1)) < 0) return r;
    }
  }
  if (state == STORE_STATE_STORED) {
    r = seg_append(s, nz, view, fn, nlen, m, image, ilen, exists && ot.state == STORE_STATE_STORED ? ot.loc : 0, &loc, &rlen);
    if (r < 0) return r;
  }
  /* the new zt / zc cells */
  zt_t nt;
  zc_t nc;
  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  nt.loc = loc;
  nt.img_len = state == STORE_STATE_STORED ? (uint32_t)ilen : 0;
  nt.serial = m->serial;
  nt.settings = m->settings;
  nt.view = view;
  nt.flags = m->flags;
  nt.state = state;
  nt.klen = (uint8_t)nlen;
  nc.source_id = m->source_id;
  nc.stamp_gen = m->stamp_gen;
  nc.stamp_time = m->stamp_time;
  memcpy(nc.digest, m->digest, STORE_DIGEST_LEN);
  nc.source = m->source;
  if (exists) {
    memcpy(nt.name, ot.name, ST_NAME_INL);
  } else if (nlen <= ST_NAME_INL) {
    memcpy(nt.name, fn, nlen);
  } else {
    uint64_t off = jb_vget(s, j, V_NX_USED);
    if (off + nlen > s->nx.reserve) return -EFBIG;
    if ((r = ensure_nx_cap(s, off + nlen)) < 0) return r;
    uint8_t *p = jb_op(j, OP_NX, 16 + nlen);
    if (!p) return -ENOMEM;
    uint32_t nl = (uint32_t)nlen;
    memcpy(p, &off, 8);
    memcpy(p + 8, &nl, 4);
    memcpy(p + 16, fn, nlen);
    memcpy(nt.name, &off, 8);
    memcpy(nt.name + 8, fn, ST_NAME_INL - 8);
    if ((r = jb_vset(j, V_NX_USED, off + nlen)) < 0) return r;
  }
  r64_t nrt, nrc;
  zc_pack(&nc, &nrc);
  zt_pack(&nt, &nrt);
  zrec_seal(&nrt, &nrc);
  if ((r = jb_zrec(j, nz, &nrt, &nrc)) < 0) return r;
  /* counters */
  if (exists) {
    if ((r = release_old_record(s, &ot)) < 0) return r;
    if ((r = count_zone(s, ot.view, ot.state, ot.flags, st_reclen(ot.klen, ot.img_len), -1)) < 0) return r;
  } else {
    unsigned d = depth_bucket(name_labels(fn, nlen));
    if ((r = jb_vadd(s, j, V_DEPTH(view, d), 1)) < 0) return r;
  }
  if ((r = count_zone(s, view, state, m->flags, rlen, +1)) < 0) return r;
  /* source index */
  if (sx_old || sx_new) {
    ixgen_t *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
    if (sx_old) {
      uint64_t oh = st_hash_src(s, oc.source, view, oc.source_id);
      uint64_t pos = slot_find_zid(sx, oh, z);
      if (pos != UINT64_MAX) {
        if ((r = jb_slot(j, OP_SX, pos, st_slotval(st_tag(oh), STORE_NONE))) < 0) return r;
        if ((r = jb_vadd(s, j, V_SX_LIVE, -1)) < 0) return r;
      }
    }
    if (sx_new) {
      bool was_empty;
      uint64_t pos = slot_find_insert(sx, sxh, &was_empty);
      if (pos == UINT64_MAX) return -ENOSPC;
      if ((r = jb_slot(j, OP_SX, pos, st_slotval(st_tag(sxh), nz))) < 0) return r;
      if ((r = jb_vadd(s, j, V_SX_LIVE, 1)) < 0) return r;
      if (was_empty && (r = jb_vadd(s, j, V_SX_USED, 1)) < 0) return r;
    }
  }
  /* name index last: it publishes a new zone */
  if (!exists) {
    bool was_empty;
    uint64_t pos = slot_find_insert(ix, h, &was_empty);
    if (pos == UINT64_MAX) return -ENOSPC;
    if ((r = jb_slot(j, OP_IX, pos, st_slotval(st_tag(h), nz))) < 0) return r;
    if ((r = jb_vadd(s, j, V_IX_LIVE, 1)) < 0) return r;
    if (was_empty && (r = jb_vadd(s, j, V_IX_USED, 1)) < 0) return r;
  }
  r = journal_commit_apply(s);
  if (r < 0) return r;
  if (exists) s->n_replaces++; else s->n_puts++;
  if (zid_out) *zid_out = nz;
  return 0;
}

static int check_name_args(const store_t *s, uint16_t view, size_t nlen, const store_meta_t *m) {
  if (nlen > STORE_NAME_MAX || view >= atomic_load_explicit(&s->nviews, memory_order_relaxed)) return -EINVAL;
  if (m->source >= ST_MAXSRC) return -EINVAL;
  return 0;
}

int store_put(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, const void *image,
              size_t image_len, uint32_t *zid) {
  if (!s || !name || !meta || !image || image_len == 0 || image_len > 0x7fffffffu) return -EINVAL;
  int r = check_name_args(s, view, len, meta);
  if (r < 0) return r;
  pthread_mutex_lock(&s->wlock);
  r = put_locked(s, view, name, len, meta, image, image_len, STORE_STATE_STORED, zid);
  if (r < 0) note_error(s, r); else { note_ok(s); r = post_write(s); }
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_set_known(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, uint32_t *zid) {
  if (!s || !name || !meta) return -EINVAL;
  int r = check_name_args(s, view, len, meta);
  if (r < 0) return r;
  pthread_mutex_lock(&s->wlock);
  r = put_locked(s, view, name, len, meta, NULL, 0, STORE_STATE_KNOWN, zid);
  if (r < 0) note_error(s, r); else { note_ok(s); r = post_write(s); }
  pthread_mutex_unlock(&s->wlock);
  return r;
}

static int delete_locked(store_t *s, uint32_t z) {
  jb_t *j = &s->jb;
  if ((uint64_t)z >= st_zt_cap(s)) return -ENOENT;
  r64_t rt, rc;
  if (zt_state_fast(s, z) == STORE_STATE_FREE) return -ENOENT;
  int rr = zrec_read_locked(s, z, &rt, &rc);
  if (rr < 0) return rr;     /* a damaged cell cannot be trusted for the counters; the rebuild drops it */
  zt_t t;
  zc_t c;
  zt_unpack(&rt, &t);
  zc_unpack(&rc, &c);
  uint8_t fn[256];
  if (t.state == STORE_STATE_FREE) return -ENOENT;
  jb_reset(j);
  int r;
  bool named = zt_fullname(s, &t, fn);
  if (named) {
    ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
    uint64_t h = st_hash_name(s, t.view, fn, t.klen);
    uint64_t pos = slot_find_zid(ix, h, z);
    if (pos != UINT64_MAX) {
      if ((r = jb_slot(j, OP_IX, pos, st_slotval(st_tag(h), STORE_NONE))) < 0) return r;
      if ((r = jb_vadd(s, j, V_IX_LIVE, -1)) < 0) return r;
    }
  }
  if (c.source_id != 0) {
    ixgen_t *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
    uint64_t oh = st_hash_src(s, c.source, t.view, c.source_id);
    uint64_t pos = slot_find_zid(sx, oh, z);
    if (pos != UINT64_MAX) {
      if ((r = jb_slot(j, OP_SX, pos, st_slotval(st_tag(oh), STORE_NONE))) < 0) return r;
      if ((r = jb_vadd(s, j, V_SX_LIVE, -1)) < 0) return r;
    }
  }
  /* the cell becomes FREE and the head of the free list */
  zt_t ft;
  zc_t fc;
  memset(&ft, 0, sizeof(ft));
  memset(&fc, 0, sizeof(fc));
  ft.loc = jb_vget(s, j, V_FREE_HEAD) & 0xffffffffu;
  ft.state = STORE_STATE_FREE;
  r64_t frt, frc;
  zc_pack(&fc, &frc);
  zt_pack(&ft, &frt);
  zrec_seal(&frt, &frc);
  if ((r = jb_zrec(j, z, &frt, &frc)) < 0) return r;
  if ((r = jb_vset(j, V_FREE_HEAD, z)) < 0 || (r = jb_vadd(s, j, V_FREE_COUNT, 1)) < 0) return r;
  if ((r = release_old_record(s, &t)) < 0) return r;
  if ((r = count_zone(s, t.view, t.state, t.flags, st_reclen(t.klen, t.img_len), -1)) < 0) return r;
  if (named && (r = jb_vadd(s, j, V_DEPTH(t.view, depth_bucket(name_labels(fn, t.klen))), -1)) < 0) return r;
  if (t.klen > ST_NAME_INL && (r = jb_vadd(s, j, V_NX_DEAD, t.klen)) < 0) return r;
  r = journal_commit_apply(s);
  if (r == 0) {
    s->n_deletes++;
    s->free_epoch = rcu_writer_advance_epoch();      /* (the cell is reused when no reader that could have found it is left: put_locked) */
  }
  return r;
}

int store_delete(store_t *s, uint32_t zid) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = delete_locked(s, zid);
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_delete_name(store_t *s, uint16_t view, const char *name, size_t len) {
  if (!s || !name || len > STORE_NAME_MAX) return -EINVAL;
  uint8_t fn[256];
  for (size_t i = 0; i < len; i++) fn[i] = st_lc((uint8_t)name[i]);
  pthread_mutex_lock(&s->wlock);
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
  uint32_t z = ix_lookup(s, ix, view, fn, len, st_hash_name(s, view, fn, len));
  int r = z == STORE_NONE ? -ENOENT : delete_locked(s, z);
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  pthread_mutex_unlock(&s->wlock);
  return r;
}

int store_set_flags(store_t *s, uint32_t zid, uint16_t set, uint16_t clear) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r;
  r64_t rt, rc;
  if ((uint64_t)zid >= st_zt_cap(s) || zt_state_fast(s, zid) == STORE_STATE_FREE) r = -ENOENT;
  else if ((r = zrec_read_locked(s, zid, &rt, &rc)) == 0) {
    zt_t t;
    zt_unpack(&rt, &t);
    uint16_t nf = (uint16_t)((t.flags | set) & ~clear);
    if (nf != t.flags) {
      jb_t *j = &s->jb;
      jb_reset(j);
      int64_t dr = ((nf & STORE_F_REJECTED_NEW) ? 1 : 0) - ((t.flags & STORE_F_REJECTED_NEW) ? 1 : 0);
      t.flags = nf;
      zt_pack(&t, &rt);
      zrec_seal(&rt, &rc);
      if ((r = jb_zrec(j, zid, &rt, &rc)) == 0 && dr != 0) {
        r = jb_vadd(s, j, V_REJECTED, dr);
        if (r == 0) r = jb_vadd(s, j, V_VIEW(t.view, 2), dr);
      }
      if (r == 0) r = journal_commit_apply(s);
    }
  }
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  pthread_mutex_unlock(&s->wlock);
  return r;
}

int store_view_add(store_t *s, const char *name) {
  if (!s || !name || !*name || strlen(name) > STORE_VIEW_NAME_MAX) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r;
  uint32_t n = atomic_load_explicit(&s->nviews, memory_order_relaxed);
  for (uint32_t i = 0; i < n; i++)
    if (strcmp(s->views[i], name) == 0) { pthread_mutex_unlock(&s->wlock); return (int)i; }
  if (n >= ST_MAXV) { pthread_mutex_unlock(&s->wlock); return -ENOSPC; }
  jb_reset(&s->jb);
  uint8_t *p = jb_op(&s->jb, OP_VIEW, 8 + STORE_VIEW_NAME_MAX + 1);
  if (!p) { pthread_mutex_unlock(&s->wlock); return -ENOMEM; }
  memcpy(p, &n, 4);
  memcpy(p + 8, name, strlen(name));
  r = journal_commit_apply(s);
  if (r < 0) note_error(s, r); else { note_ok(s); r = post_write(s); if (r == 0) r = (int)n; }
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_view_id(const store_t *s, const char *name) {
  if (!s || !name) return -ENOENT;
  uint32_t n = atomic_load_explicit(&s->nviews, memory_order_acquire);
  for (uint32_t i = 0; i < n; i++)
    if (strcmp(s->views[i], name) == 0) return (int)i;
  return -ENOENT;
}
const char *store_view_name(const store_t *s, int view) {
  if (!s || view < 0 || (uint32_t)view >= atomic_load_explicit(&s->nviews, memory_order_acquire)) return NULL;
  return s->views[view];
}

int store_set_cursor(store_t *s, uint16_t source, uint64_t cursor, const void *ident, size_t ident_len) {
  if (!s || source >= ST_MAXSRC || ident_len > STORE_IDENT_MAX || (ident_len && !ident)) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  jb_reset(&s->jb);
  uint8_t *p = jb_op(&s->jb, OP_SRC, 24 + STORE_IDENT_MAX);
  int r = 0;
  if (!p) r = -ENOMEM;
  else {
    uint32_t src = source, valid = 1, il = (uint32_t)ident_len;
    memcpy(p, &src, 4);
    memcpy(p + 4, &valid, 4);
    memcpy(p + 8, &cursor, 8);
    memcpy(p + 16, &il, 4);
    if (ident_len) memcpy(p + 24, ident, ident_len);
    r = journal_commit_apply(s);
  }
  if (r < 0) note_error(s, r); else { note_ok(s); r = post_write(s); }
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_get_cursor(store_t *s, uint16_t source, bool *valid, uint64_t *cursor, void *ident, size_t *ident_len) {
  if (!s || source >= ST_MAXSRC) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  const srcent_t *e = &s->src[source];
  if (valid) *valid = e->valid != 0;
  if (cursor) *cursor = e->cursor;
  if (ident) memcpy(ident, e->ident, e->identlen);
  if (ident_len) *ident_len = e->identlen;
  pthread_mutex_unlock(&s->wlock);
  return 0;
}

int store_reserve(store_t *s, uint64_t zones) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = ensure_zt_cap(s, zones + 1);
  if (r == 0) {
    ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
    uint64_t want = zones * 22 / 10 + 16;
    uint64_t nix = want > ix->nslots ? want : 0, nsx = want > sx->nslots ? want : 0;
    if (nix || nsx) r = index_regrow(s, nix, nsx);
  }
  if (r < 0) note_error(s, r);
  pthread_mutex_unlock(&s->wlock);
  return r;
}

int store_commit(store_t *s) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = commit_locked(s);
  if (r < 0) note_error(s, r);
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_tick(store_t *s) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = post_write(s);
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_checkpoint(store_t *s) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = checkpoint_locked(s, false);
  if (r < 0) note_error(s, r);
  pthread_mutex_unlock(&s->wlock);
  return r;
}
int store_checkpoint_clean(store_t *s) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = checkpoint_locked(s, true);
  if (r < 0) note_error(s, r);
  pthread_mutex_unlock(&s->wlock);
  return r;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* readers                                                                                                              */
/* ------------------------------------------------------------------------------------------------------------------ */

void store_read_lock(void) { rcu_aux_read_lock(); }
void store_read_unlock(void) { rcu_aux_read_unlock(); }

uint32_t store_find(const store_t *s, uint16_t view, const char *name, size_t len) {
  if (len > STORE_NAME_MAX) return STORE_NONE;
  uint8_t fn[256];
  for (size_t i = 0; i < len; i++) fn[i] = st_lc((uint8_t)name[i]);
  const ixgen_t *g = atomic_load_explicit(&s->ix, memory_order_acquire);
  return ix_lookup(s, g, view, fn, len, st_hash_name(s, view, fn, len));
}
uint32_t store_find_source(const store_t *s, uint16_t source, int64_t domain_id, uint16_t view) {
  const ixgen_t *g = atomic_load_explicit(&s->sx, memory_order_acquire);
  return sx_lookup(s, g, source, view, domain_id, st_hash_src(s, source, view, domain_id));
}

static void zone_fill(const store_t *s, uint32_t z, const zt_t *t, const zc_t *c, store_zone_t *out, bool *name_ok) {
  memset(out, 0, sizeof(*out));
  out->zid = z;
  out->state = t->state;
  out->klen = t->klen;
  out->view = t->view;
  out->flags = t->flags;
  out->source = c->source;
  out->img_len = t->img_len;
  out->serial = t->serial;
  out->settings = t->settings;
  out->loc = t->loc;
  out->source_id = c->source_id;
  out->stamp_gen = c->stamp_gen;
  out->stamp_time = c->stamp_time;
  memcpy(out->digest, c->digest, STORE_DIGEST_LEN);
  uint8_t fn[256];
  bool ok = zt_fullname(s, t, fn);
  if (ok) memcpy(out->name, fn, t->klen);
  out->name[t->klen] = 0;
  if (name_ok) *name_ok = ok;
}

int store_zone_get(const store_t *s, uint32_t zid, store_zone_t *out) {
  r64_t rt, rc;
  if ((uint64_t)zid >= st_zt_cap(s) || zt_state_fast(s, zid) == STORE_STATE_FREE) return -ENOENT;
  int r = zrec_read(s, zid, &rt, &rc);
  if (r < 0) return r;
  zt_t t;
  zc_t c;
  zt_unpack(&rt, &t);
  zc_unpack(&rc, &c);
  if (t.state == STORE_STATE_FREE) return -ENOENT;
  if (t.state > STORE_STATE_STORED) return -EBADMSG;
  bool ok;
  zone_fill(s, zid, &t, &c, out, &ok);
  return ok ? 0 : -EBADMSG;
}

int store_iter(const store_t *s, uint32_t *cursor, store_zone_t *out) {
  uint64_t hwm = VG(s, V_HWM), cap = st_zt_cap(s);
  if (hwm > cap) hwm = cap;
  while (*cursor < hwm) {
    uint32_t z = (*cursor)++;
    if (zt_state_fast(s, z) == STORE_STATE_FREE) continue;
    int r = store_zone_get(s, z, out);
    if (r == -ENOENT) continue;
    if (r < 0) { memset(out, 0, sizeof(*out)); out->zid = z; return r; }
    return 1;
  }
  return 0;
}

int store_image_read(const store_t *cs, uint32_t zid, store_img_t *img) {
  store_t *s = (store_t *)cs;      /* seg_get opens a segment on first use (internal mutex) */
  memset(img, 0, sizeof(*img));
  if ((uint64_t)zid >= st_zt_cap(s) || zt_state_fast(s, zid) == STORE_STATE_FREE) return -ENOENT;
  r64_t rt, rc;
  int r = zrec_read(s, zid, &rt, &rc);
  if (r < 0) return r;
  zt_t t;
  zt_unpack(&rt, &t);
  if (t.state != STORE_STATE_STORED) return -ENOENT;
  uint32_t sn = (uint32_t)(t.loc >> ST_LOC_SHIFT);
  uint64_t off = (t.loc & ST_LOC_MASK) * 64;
  uint64_t rlen = st_reclen(t.klen, t.img_len);
  /* The record is bounded by the segment file, not by the counters of the superblock array: a journal record applies the zone's cell before its counters (a
   * reader that sees the new location must not find "beyond the used bytes"), and the record's bytes were written before the cell was. */
  if (sn == 0 || sn > ST_MAXSEG || off < ST_SEGHDR || off + rlen > ST_SEG_MAX) return -EBADMSG;
  seg_t *g = seg_get(s, sn);
  if (!g) return -EBADMSG;
  const uint8_t *rec;
  uint8_t *copy = NULL;
  if (s->mode == STORE_MODE_MAP) {
    if (off + rlen > g->maplen) return -EBADMSG;
    rec = g->map + off;
  } else {
    if (rlen > (1u << 20)) {            /* (before a big buffer is made: img_len is a field of a cell; a record of a megabyte or less is bounded by the read itself, without a system call for each read) */
      struct stat fst;
      if (fstat(g->fd, &fst) != 0 || fst.st_size < 0 || off + rlen > (uint64_t)fst.st_size) return -EBADMSG;
    }
    copy = malloc((size_t)rlen);
    if (!copy) return -ENOMEM;
    r = st_pread_all(g->fd, copy, (size_t)rlen, (off_t)off);
    if (r < 0) { free(copy); return r == -EIO ? -EBADMSG : r; }
    rec = copy;
  }
  rhdr_t h;
  memcpy(&h, rec, sizeof(h));
  size_t np = st_pad16(t.klen);
  r = -EBADMSG;
  if (h.magic != ST_MAGIC_REC || h.reclen != rlen || h.zid != zid || h.view != t.view || h.klen != t.klen || h.img_len != t.img_len ||
      h.kind != 0)
    goto bad;
  uint64_t want = h.checksum;
  h.checksum = 0;
  uint64_t sum = st_sum64(&h, sizeof(h), 0);
  sum = st_sum64(rec + ST_RHDR, np, sum);
  sum = st_sum64(rec + ST_RHDR + np, t.img_len, sum);
  if (sum != want) goto bad;
  img->data = rec + ST_RHDR + np;
  img->len = t.img_len;
  img->zid = zid;
  img->view = h.view;
  img->kind = h.kind;
  img->flags = h.flags;
  img->serial = h.serial;
  img->settings = h.settings;
  img->stamp_gen = h.stamp_gen;
  img->prev_loc = h.prev_loc;
  img->loc = t.loc;
  img->checksum = want;
  img->seg_ = sn;
  if (copy) img->priv_ = copy;
  else atomic_fetch_add_explicit(&g->refs, 1, memory_order_relaxed);
  return 0;
bad:
  free(copy);
  return -EBADMSG;
}
void store_img_release(const store_t *s, store_img_t *img) {
  if (!img || !img->data) return;
  if (img->priv_) free(img->priv_);
  else if (img->seg_) {
    seg_t *g = atomic_load_explicit(&((store_t *)s)->segs[img->seg_], memory_order_acquire);
    if (g) atomic_fetch_sub_explicit(&g->refs, 1, memory_order_relaxed);
  }
  memset(img, 0, sizeof(*img));
}

unsigned store_name_labels(const char *name, size_t len) { return name_labels((const uint8_t *)name, len); }
uint64_t store_view_depth_count(const store_t *s, uint16_t view, unsigned labels) {
  if (view >= ST_MAXV) return 0;
  return VG(s, V_DEPTH(view, depth_bucket(labels)));
}
unsigned store_view_depth_max(const store_t *s, uint16_t view) {
  if (view >= ST_MAXV) return 0;
  for (unsigned d = 63; d > 0; d--)
    if (VG(s, V_DEPTH(view, d))) return d;
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* statistics and the full check                                                                                        */
/* ------------------------------------------------------------------------------------------------------------------ */

void store_opts_default(store_opts_t *o) {
  memset(o, 0, sizeof(*o));
  o->mode = STORE_MODE_AUTO;
  o->sync_policy = STORE_SYNC_BATCH;
}

void store_stats(const store_t *s, store_stats_t *o) {
  memset(o, 0, sizeof(*o));
  o->format = STORE_FORMAT_VERSION;
  o->mode = s->mode;
  memcpy(o->fstype, s->fstype, sizeof(o->fstype));
  memcpy(o->uuid, s->uuid, 16);
  o->state = atomic_load_explicit(&s->state, memory_order_relaxed);
  o->clean_flag = s->clean_on_disk;
  o->zones_known = VG(s, V_KNOWN);
  o->zones_stored = VG(s, V_STORED);
  o->zones_rejected = VG(s, V_REJECTED);
  o->zones_free = VG(s, V_FREE_COUNT);
  o->zt_records = VG(s, V_HWM);
  o->zt_capacity = st_zt_cap(s);
  o->nx_used = VG(s, V_NX_USED);
  o->nx_dead = VG(s, V_NX_DEAD);
  const ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_acquire), *sx = atomic_load_explicit(&s->sx, memory_order_acquire);
  if (ix) { o->ix_gen = ix->gen; o->ix_slots = ix->nslots; }
  if (sx) { o->sx_gen = sx->gen; o->sx_slots = sx->nslots; }
  o->ix_used = VG(s, V_IX_USED);
  o->ix_live = VG(s, V_IX_LIVE);
  o->sx_used = VG(s, V_SX_USED);
  o->sx_live = VG(s, V_SX_LIVE);
  o->seg_count = (uint32_t)VG(s, V_NSEGS);
  for (uint32_t n = 1; n <= o->seg_count && n <= ST_MAXSEG; n++) {
    o->seg_used_bytes += VG(s, V_SEG(n, 0)) - ST_SEGHDR;
    o->seg_live_bytes += VG(s, V_SEG(n, 1));
  }
  o->lsn = s->lsn;
  o->ckpt_lsn = s->ckpt_lsn;
  o->committed_lsn = s->committed_lsn;
  o->journal_bytes = s->jbytes;
  o->journal_gen = s->jrn_gen;
  o->checkpoints = s->n_checkpoints;
  o->last_checkpoint_unix = s->ckpt_time;
  o->last_checkpoint_us = s->ckpt_us;
  o->commits = s->n_commits;
  o->puts = s->n_puts;
  o->replaces = s->n_replaces;
  o->deletes = s->n_deletes;
  o->growths = s->n_growths;
  o->write_errors = s->n_write_errors;
  o->recovery = s->rec;
  o->nviews = atomic_load_explicit(&s->nviews, memory_order_acquire);
  for (uint32_t i = 0; i < o->nviews; i++) {
    memcpy(o->views[i].name, s->views[i], sizeof(o->views[i].name));
    o->views[i].known = VG(s, V_VIEW(i, 0));
    o->views[i].stored = VG(s, V_VIEW(i, 1));
    o->views[i].rejected = VG(s, V_VIEW(i, 2));
    o->views[i].image_bytes = VG(s, V_VIEW(i, 3));
  }
}

int store_seg_info(const store_t *s, uint32_t num, store_seg_info_t *o) {
  if (num == 0 || num > VG(s, V_NSEGS) || num > ST_MAXSEG) return -ENOENT;
  o->num = num;
  o->used = VG(s, V_SEG(num, 0));
  o->live = VG(s, V_SEG(num, 1));
  o->file_size = 0;
  seg_t *g = seg_get((store_t *)s, num);
  struct stat st;
  if (g && fstat(g->fd, &st) == 0) o->file_size = (uint64_t)st.st_size;
  return 0;
}

/* Page-cache residency estimate (design 9.1): mincore() on up to `pages` random pages of the appended part of the segments.  Only
 * MAP mode has mappings to ask about.  Bounded by `pages`; no lock (the segments stay mapped until close, like every reader). */
int store_resident_sample(const store_t *cs, unsigned pages, uint64_t seed, uint64_t *sampled, uint64_t *resident) {
  store_t *s = (store_t *)cs;
  *sampled = *resident = 0;
  if (s->mode != STORE_MODE_MAP) return -ENOTSUP;
  uint32_t nseg = (uint32_t)VG(s, V_NSEGS);
  if (nseg > ST_MAXSEG) nseg = ST_MAXSEG;
  uint64_t total = 0;
  for (uint32_t n = 1; n <= nseg; n++) total += VG(s, V_SEG(n, 0)) / s->pagesz;
  if (total == 0 || pages == 0) return 0;
  uint64_t x = seed ? seed : 0x9E3779B97F4A7C15ull;
  for (unsigned i = 0; i < pages; i++) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;                   /* xorshift64 */
    uint64_t pick = x % total;
    for (uint32_t n = 1; n <= nseg; n++) {
      uint64_t np = VG(s, V_SEG(n, 0)) / s->pagesz;
      if (pick >= np) { pick -= np; continue; }
      seg_t *g = seg_get(s, n);
      if (!g || !g->map || (pick + 1) * s->pagesz > g->maplen) break;
      char vec = 0;
      if (mincore(g->map + pick * s->pagesz, s->pagesz, &vec) != 0) return *sampled ? 0 : -errno;
      (*sampled)++;
      if (vec & 1) (*resident)++;
      break;
    }
  }
  return 0;
}

#define CHK_FAIL(...) do { rep->errors++; if (!rep->first_error[0]) snprintf(rep->first_error, sizeof(rep->first_error), __VA_ARGS__); } while (0)

int store_check(store_t *s, store_check_report_t *rep) {
  memset(rep, 0, sizeof(*rep));
  pthread_mutex_lock(&s->wlock);
  uint64_t hwm = VG(s, V_HWM), known = 0, stored = 0, rej = 0, bytes = 0, nfree = 0, live_ix = 0, live_sx = 0, nxlive = 0;
  uint64_t vk[ST_MAXV][4];
  memset(vk, 0, sizeof(vk));
  uint64_t seglive[ST_MAXSEG + 1];
  memset(seglive, 0, sizeof(seglive));
  uint64_t depth[ST_MAXV][64];
  memset(depth, 0, sizeof(depth));
  uint32_t nviews = atomic_load_explicit(&s->nviews, memory_order_relaxed);
  if (hwm > st_zt_cap(s)) { CHK_FAIL("hwm %" PRIu64 " beyond zt capacity", hwm); hwm = st_zt_cap(s); }
  for (uint64_t z = 0; z < hwm; z++) {
    r64_t rt, rc;
    if (zrec_read_locked(s, (uint32_t)z, &rt, &rc) < 0) { CHK_FAIL("zone %" PRIu64 ": record CRC", z); continue; }
    zt_t t;
    zc_t c;
    zt_unpack(&rt, &t);
    zc_unpack(&rc, &c);
    if (t.state == STORE_STATE_FREE) { nfree++; continue; }
    rep->zones++;
    if (t.state > STORE_STATE_STORED || t.view >= nviews) { CHK_FAIL("zone %" PRIu64 ": state/view", z); continue; }
    uint8_t fn[256];
    if (!zt_fullname(s, &t, fn)) { CHK_FAIL("zone %" PRIu64 ": name outside nx", z); continue; }
    if (t.klen > ST_NAME_INL) nxlive += t.klen;
    const ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
    if (ix_lookup(s, ix, t.view, fn, t.klen, st_hash_name(s, t.view, fn, t.klen)) != (uint32_t)z) CHK_FAIL("zone %" PRIu64 ": not reachable by name (or duplicate)", z);
    else live_ix++;
    if (c.source_id != 0) {
      const ixgen_t *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
      if (sx_lookup(s, sx, c.source, t.view, c.source_id, st_hash_src(s, c.source, t.view, c.source_id)) != (uint32_t)z) CHK_FAIL("zone %" PRIu64 ": not reachable by source", z);
      else live_sx++;
    }
    depth[t.view][depth_bucket(name_labels(fn, t.klen))]++;
    if (t.state == STORE_STATE_KNOWN) { known++; vk[t.view][0]++; if (t.loc != 0 || t.img_len != 0) CHK_FAIL("zone %" PRIu64 ": KNOWN with an image", z); }
    else {
      stored++; vk[t.view][1]++;
      uint64_t rl = st_reclen(t.klen, t.img_len);
      bytes += rl; vk[t.view][3] += rl;
      uint32_t sn = (uint32_t)(t.loc >> ST_LOC_SHIFT);
      if (sn == 0 || sn > ST_MAXSEG) CHK_FAIL("zone %" PRIu64 ": loc segment", z);
      else seglive[sn] += rl;
      store_img_t im;
      int r = store_image_read(s, (uint32_t)z, &im);
      if (r < 0) CHK_FAIL("zone %" PRIu64 ": image read %d", z, r);
      else store_img_release(s, &im);
    }
    if (t.flags & STORE_F_REJECTED_NEW) { rej++; vk[t.view][2]++; }
  }
  /* free list */
  uint64_t fz = VG(s, V_FREE_HEAD), steps = 0;
  while (fz != STORE_NONE && steps <= hwm) {
    r64_t rt, rc;
    if (fz >= hwm || zrec_read_locked(s, (uint32_t)fz, &rt, &rc) < 0) { CHK_FAIL("free list: bad link %" PRIu64, fz); break; }
    zt_t t;
    zt_unpack(&rt, &t);
    if (t.state != STORE_STATE_FREE) { CHK_FAIL("free list: zone %" PRIu64 " not free", fz); break; }
    fz = t.loc & 0xffffffffu;
    steps++;
  }
  if (steps != VG(s, V_FREE_COUNT) || steps != nfree) CHK_FAIL("free list %" PRIu64 " links, counter %" PRIu64 ", %" PRIu64 " free cells", steps, VG(s, V_FREE_COUNT), nfree);
  if (known != VG(s, V_KNOWN) || stored != VG(s, V_STORED) || rej != VG(s, V_REJECTED) || bytes != VG(s, V_IMG_BYTES))
    CHK_FAIL("totals: known %" PRIu64 "/%" PRIu64 " stored %" PRIu64 "/%" PRIu64 " rejected %" PRIu64 "/%" PRIu64 " bytes %" PRIu64 "/%" PRIu64,
             known, VG(s, V_KNOWN), stored, VG(s, V_STORED), rej, VG(s, V_REJECTED), bytes, VG(s, V_IMG_BYTES));
  for (uint32_t v = 0; v < nviews; v++) {
    for (int k = 0; k < 4; k++)
      if (vk[v][k] != VG(s, V_VIEW(v, (unsigned)k))) CHK_FAIL("view %u counter %d: %" PRIu64 " vs %" PRIu64, v, k, vk[v][k], VG(s, V_VIEW(v, (unsigned)k)));
    for (unsigned d = 0; d < 64; d++)
      if (depth[v][d] != VG(s, V_DEPTH(v, d))) { CHK_FAIL("view %u depth %u: %" PRIu64 " vs %" PRIu64, v, d, depth[v][d], VG(s, V_DEPTH(v, d))); break; }
  }
  if (live_ix != VG(s, V_IX_LIVE)) CHK_FAIL("ix live %" PRIu64 " vs counter %" PRIu64, live_ix, VG(s, V_IX_LIVE));
  if (live_sx != VG(s, V_SX_LIVE)) CHK_FAIL("sx live %" PRIu64 " vs counter %" PRIu64, live_sx, VG(s, V_SX_LIVE));
  if (VG(s, V_NX_USED) < nxlive || VG(s, V_NX_USED) - nxlive != VG(s, V_NX_DEAD)) CHK_FAIL("nx used %" PRIu64 " live %" PRIu64 " dead %" PRIu64, VG(s, V_NX_USED), nxlive, VG(s, V_NX_DEAD));
  for (uint32_t n = 1; n <= VG(s, V_NSEGS) && n <= ST_MAXSEG; n++)
    if (seglive[n] != VG(s, V_SEG(n, 1))) { CHK_FAIL("segment %u live %" PRIu64 " vs %" PRIu64, n, seglive[n], VG(s, V_SEG(n, 1))); break; }
  const ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  if ((VG(s, V_IX_USED)) * 2 > ix->nslots + 1 || VG(s, V_IX_USED) < VG(s, V_IX_LIVE)) CHK_FAIL("ix used %" PRIu64 " slots %" PRIu64, VG(s, V_IX_USED), ix->nslots);
  if (VG(s, V_SX_USED) < VG(s, V_SX_LIVE) || VG(s, V_SX_USED) * 2 > sx->nslots + 1) CHK_FAIL("sx used %" PRIu64 " slots %" PRIu64, VG(s, V_SX_USED), sx->nslots);
  pthread_mutex_unlock(&s->wlock);
  return rep->errors ? -EBADMSG : 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* repair: rebuild the derived tables from zt                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

/* the counters are recomputed into a private array and stored at the end, so that readers (and a concurrent store_stats) never see a half-done recount */
#define NG(i)    (nv[(i)])
#define NS(i, x) (nv[(i)] = (x))
static int rebuild_locked(store_t *s) {
  uint64_t *nv = malloc(ST_NV * sizeof(*nv));
  if (!nv) return -ENOMEM;
  for (uint32_t i = 0; i < ST_NV; i++) nv[i] = VG(s, i);
  uint64_t hwm = NG(V_HWM), cap = st_zt_cap(s);
  if (hwm > cap) hwm = cap;
  uint32_t nviews = atomic_load_explicit(&s->nviews, memory_order_relaxed);
  ixgen_t *nix = NULL, *nsx = NULL;
  uint64_t slots = ix_slots_for(hwm);
  int r = ixgen_create(s, FK_IX, s->ix_gen + 1, slots, &nix);
  if (r == 0) r = ixgen_create(s, FK_SX, s->sx_gen + 1, slots, &nsx);
  if (r < 0) { ixgen_free(nix); free(nv); return r; }
  /* counters are recomputed: clear everything except the segment tables, which are recomputed below too */
  uint64_t nsegs = NG(V_NSEGS), cur_seg = NG(V_CUR_SEG), nx_used = NG(V_NX_USED);
  uint64_t seg_used[ST_MAXSEG + 1];
  for (uint32_t n = 1; n <= ST_MAXSEG; n++) seg_used[n] = NG(V_SEG(n, 0));
  for (uint32_t i = 0; i < ST_NV; i++) NS(i, 0);
  NS(V_NSEGS, nsegs);
  NS(V_CUR_SEG, cur_seg);
  NS(V_NX_USED, nx_used);
  NS(V_HWM, hwm);
  for (uint32_t n = 1; n <= nsegs && n <= ST_MAXSEG; n++) NS(V_SEG(n, 0), seg_used[n]);
  uint64_t nxlive = 0, live_ix = 0, live_sx = 0;
  for (uint64_t z = 0; z < hwm; z++) {
    r64_t rt, rc;
    s->rec.rebuilt_zones++;
    uint8_t st0 = zt_state_fast(s, (uint32_t)z);
    bool ok = false;
    zt_t t;
    zc_t c;
    uint8_t fn[256];
    if (st0 == STORE_STATE_FREE) continue;       /* free cells are linked below (a free cell with a bad CRC is rewritten there) */
    if (zrec_read_locked(s, (uint32_t)z, &rt, &rc) == 0) {
      if ((uint32_t)(atomic_load_explicit(&zc_cell(s, (uint32_t)z)[7], memory_order_relaxed) >> 32) & 1u)
        zrec_write(s, (uint32_t)z, &rt, &rc);       /* an odd counter left by a crash in the middle of a cell */
      zt_unpack(&rt, &t);
      zc_unpack(&rc, &c);
      ok = (t.state == STORE_STATE_KNOWN || t.state == STORE_STATE_STORED) && t.view < nviews && zt_fullname(s, &t, fn);
      if (ok && t.state == STORE_STATE_STORED) {
        uint32_t sn = (uint32_t)(t.loc >> ST_LOC_SHIFT);
        uint64_t off = (t.loc & ST_LOC_MASK) * 64, rl = st_reclen(t.klen, t.img_len);
        ok = sn >= 1 && sn <= nsegs && sn <= ST_MAXSEG && off >= ST_SEGHDR && off + rl <= NG(V_SEG(sn, 0));
      } else if (ok) {
        ok = t.loc == 0 && t.img_len == 0;
      }
    }
    if (ok) {
      uint64_t h = st_hash_name(s, t.view, fn, t.klen);
      if (ix_lookup(s, nix, t.view, fn, t.klen, h) != STORE_NONE) ok = false;         /* duplicate name */
      if (ok && c.source_id != 0 &&
          sx_lookup(s, nsx, c.source, t.view, c.source_id, st_hash_src(s, c.source, t.view, c.source_id)) != STORE_NONE)
        ok = false;                                                                    /* duplicate source key */
      if (ok && ix_raw_insert(nix, h, (uint32_t)z) < 0) ok = false;
      if (ok) {
        live_ix++;
        if (c.source_id != 0) {
          ix_raw_insert(nsx, st_hash_src(s, c.source, t.view, c.source_id), (uint32_t)z);
          live_sx++;
        }
        if (t.klen > ST_NAME_INL) nxlive += t.klen;
        if (t.state == STORE_STATE_KNOWN) { NS(V_KNOWN, NG(V_KNOWN) + 1); NS(V_VIEW(t.view, 0), NG(V_VIEW(t.view, 0)) + 1); }
        else {
          uint64_t rl = st_reclen(t.klen, t.img_len);
          NS(V_STORED, NG(V_STORED) + 1);
          NS(V_VIEW(t.view, 1), NG(V_VIEW(t.view, 1)) + 1);
          NS(V_IMG_BYTES, NG(V_IMG_BYTES) + rl);
          NS(V_VIEW(t.view, 3), NG(V_VIEW(t.view, 3)) + rl);
          uint32_t sn = (uint32_t)(t.loc >> ST_LOC_SHIFT);
          NS(V_SEG(sn, 1), NG(V_SEG(sn, 1)) + rl);
        }
        if (t.flags & STORE_F_REJECTED_NEW) { NS(V_REJECTED, NG(V_REJECTED) + 1); NS(V_VIEW(t.view, 2), NG(V_VIEW(t.view, 2)) + 1); }
        uint32_t d = V_DEPTH(t.view, depth_bucket(name_labels(fn, t.klen)));
        NS(d, NG(d) + 1);
      }
    }
    if (!ok) {              /* drop: the cell becomes FREE (linked below) */
      zt_t ft;
      zc_t fc;
      memset(&ft, 0, sizeof(ft));
      memset(&fc, 0, sizeof(fc));
      r64_t frt, frc;
      zc_pack(&fc, &frc);
      zt_pack(&ft, &frt);
      zrec_seal(&frt, &frc);
      zrec_write(s, (uint32_t)z, &frt, &frc);
      s->rec.dropped_zones++;
    }
  }
  /* free list: descending pass so that the head is the lowest zid */
  uint64_t head = STORE_NONE, nfree = 0;
  for (uint64_t z = hwm; z-- > 0; ) {
    if (zt_state_fast(s, (uint32_t)z) != STORE_STATE_FREE) continue;
    zt_t ft;
    zc_t fc;
    memset(&ft, 0, sizeof(ft));
    memset(&fc, 0, sizeof(fc));
    ft.loc = head;
    ft.state = STORE_STATE_FREE;
    r64_t frt, frc;
    zc_pack(&fc, &frc);
    zt_pack(&ft, &frt);
    zrec_seal(&frt, &frc);
    zrec_write(s, (uint32_t)z, &frt, &frc);
    head = z;
    nfree++;
  }
  NS(V_FREE_HEAD, head);
  NS(V_FREE_COUNT, nfree);
  NS(V_IX_USED, live_ix);
  NS(V_IX_LIVE, live_ix);
  NS(V_SX_USED, live_sx);
  NS(V_SX_LIVE, live_sx);
  NS(V_NX_DEAD, nx_used >= nxlive ? nx_used - nxlive : 0);
  /* the segment counters of segments no record uses stay 0 live; V_SEG(n, 0) were restored above */
  if (msync((void *)nix->slots, nix->maplen, MS_SYNC) != 0 || msync((void *)nsx->slots, nsx->maplen, MS_SYNC) != 0) r = -errno;
  if (r == 0 && (fdatasync(nix->fd) != 0 || fdatasync(nsx->fd) != 0)) r = -errno;
  if (r < 0) { ixgen_free(nix); ixgen_free(nsx); free(nv); return r; }
  for (uint32_t i = 0; i < ST_NV; i++) VS(s, i, nv[i]);
  free(nv);
  index_publish(s, 0, nix);
  index_publish(s, 1, nsx);
  s->free_epoch = rcu_writer_advance_epoch();         /* (cells that were dropped are reused after the readers of the old tables are gone) */
  s->rec.rebuilt = true;
  atomic_fetch_or(&s->state, STORE_ST_REPAIRED);
  return 0;
}
#undef NG
#undef NS

int store_repair(store_t *s) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  /* the rebuild changes cells, tables and counters that no journal record describes, and is only complete with its checkpoint: a marker in the journal first, so
   * that a crash (or a failed checkpoint and a later crash) in between makes the open rebuild again instead of trusting half of it */
  jb_reset(&s->jb);
  int r = jb_op(&s->jb, OP_REBUILD, 8) ? journal_append(s) : -ENOMEM;
  if (r == 0) r = rebuild_locked(s);
  if (r == 0) r = checkpoint_locked(s, false);
  if (r < 0) note_error(s, r);
  pthread_mutex_unlock(&s->wlock);
  return r;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* open / recovery / close                                                                                              */
/* ------------------------------------------------------------------------------------------------------------------ */

static uint64_t st_boot_id(void) {
#if defined(__FreeBSD__)
  struct timeval tv;
  size_t l = sizeof(tv);
  if (sysctlbyname("kern.boottime", &tv, &l, NULL, 0) == 0 && l == sizeof(tv)) return (uint64_t)tv.tv_sec ? (uint64_t)tv.tv_sec : 1;
#endif
  return 0;
}

static void files_close(store_t *s) {
  mtab_close(&s->zt);
  mtab_close(&s->zc);
  mtab_close(&s->nx);
  ixgen_free(atomic_exchange(&s->ix, NULL));
  ixgen_free(atomic_exchange(&s->sx, NULL));
  for (uint32_t n = 1; n <= ST_MAXSEG; n++) {
    seg_t *g = atomic_exchange(&s->segs[n], NULL);
    seg_free(g);
  }
  if (s->jfd >= 0) { close(s->jfd); s->jfd = -1; }
}

/* Adopt the state of superblock copy b: open and check the table files.  On failure the files are closed again. */
static int adopt_sb(store_t *s, const sb_t *b) {
  memcpy(s->uuid, b->f.uuid, 16);
  s->hk0 = b->f.hk0;
  s->hk1 = b->f.hk1;
  s->seg_size = b->f.seg_size;
  size_t zres = (size_t)(s->o.max_zones ? s->o.max_zones : (1u << 25)) * ST_REC;
  if (b->f.zt_cap * ST_REC > zres) zres = (size_t)(b->f.zt_cap * 2 * ST_REC);
  size_t nres = s->o.nx_max ? (size_t)s->o.nx_max : (size_t)1 << 30;
  if (b->f.nx_cap > nres) nres = (size_t)b->f.nx_cap * 2;
  int r = mtab_open(s, &s->zt, "zt.1", FK_ZT, 64, zres, false);
  if (r == 0) r = mtab_open(s, &s->zc, "zc.1", FK_ZC, 64, zres, false);
  if (r == 0) r = mtab_open(s, &s->nx, "nx.1", FK_NX, 1, nres, false);
  if (r < 0) goto fail;
  if (atomic_load(&s->zt.mapped) < b->f.zt_cap * ST_REC || atomic_load(&s->zc.mapped) < b->f.zt_cap * ST_REC ||
      atomic_load(&s->nx.mapped) < b->f.nx_cap || b->f.v[V_HWM] > b->f.zt_cap || b->f.v[V_NX_USED] > b->f.nx_cap) { r = -EBADMSG; goto fail; }
  /* every counter is bounded before it is taken in (the segment counters are array indexes and file offsets, the free list head a zone id) */
  for (uint32_t i = 0; i < ST_NV; i++)
    if (!v_value_ok(s, i, b->f.v[i])) { r = -EBADMSG; goto fail; }
  if (b->f.v[V_CUR_SEG] > b->f.v[V_NSEGS]) { r = -EBADMSG; goto fail; }
  for (uint32_t n = 1; n <= b->f.v[V_NSEGS]; n++)
    if (b->f.v[V_SEG(n, 0)] < ST_SEGHDR) { r = -EBADMSG; goto fail; }
  ixgen_t *ix = NULL, *sx = NULL;
  if ((r = ixgen_open(s, FK_IX, b->f.ix_gen, b->f.ix_slots, &ix)) < 0) goto fail;
  if ((r = ixgen_open(s, FK_SX, b->f.sx_gen, b->f.sx_slots, &sx)) < 0) { ixgen_free(ix); goto fail; }
  atomic_store(&s->ix, ix);
  atomic_store(&s->sx, sx);
  s->ix_gen = b->f.ix_gen;
  s->sx_gen = b->f.sx_gen;
  for (uint32_t i = 0; i < ST_NV; i++) VS(s, i, b->f.v[i]);
  memcpy(s->views, b->f.views, sizeof(s->views));
  for (uint32_t i = 0; i < ST_MAXV; i++) s->views[i][STORE_VIEW_NAME_MAX] = 0;
  atomic_store(&s->nviews, b->f.nviews);
  memcpy(s->src, b->f.src, sizeof(s->src));
  atomic_store(&s->nx_avail, b->f.v[V_NX_USED]);
  s->lsn = b->f.ckpt_lsn;
  s->ckpt_lsn = b->f.ckpt_lsn;
  s->ckpt_time = b->f.ckpt_time;
  s->ckpt_us = b->f.ckpt_us;
  s->jrn_gen = b->f.jrn_gen;
  return 0;
fail:
  files_close(s);
  return r < 0 ? r : -EBADMSG;
}

/* replay the journal chain that starts at the gen the adopted superblock names */
static int journal_replay(store_t *s, uint32_t first_gen, bool *anomaly) {
  uint64_t expected = s->ckpt_lsn + 1;
  s->rec.replay_from_lsn = expected;
  uint32_t gen = first_gen, last_gen = first_gen;
  for (;; gen++) {
    char name[32];
    st_name_ix(name, sizeof(name), "jrn", gen);
    int fd = st_openat(s, name, O_RDONLY);
    if (fd < 0) break;
    struct stat st;
    fhdr_t h;
    bool torn = false;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < ST_JHDR || st_pread_all(fd, &h, sizeof(h), 0) < 0 || !fhdr_ok(s, &h, FK_JRN, gen)) {
      close(fd);      /* a journal file without a valid header holds nothing (created and not yet written) */
      break;
    }
    s->rec.journals_read++;
    last_gen = gen;
    size_t size = (size_t)st.st_size;
    uint8_t *m = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { close(fd); *anomaly = true; break; }
    size_t off = ST_JHDR;
    if (h.a > expected) torn = true;       /* a gap before this file: the chain is broken */
    while (!torn && off + ST_JREC_HDR <= size) {
      jrec_t r;
      memcpy(&r, m + off, sizeof(r));
      if (r.magic != ST_MAGIC_JREC || r.len < ST_JREC_HDR || (r.len & 7) || r.len > size - off) { torn = true; break; }
      uint32_t crc = r.crc;
      uint8_t tmp[ST_JREC_HDR];
      memcpy(tmp, m + off, ST_JREC_HDR);
      memset(tmp + 8, 0, 4);
      uint32_t calc = st_crc32c(st_crc32c(0, tmp, ST_JREC_HDR), m + off + ST_JREC_HDR, r.len - ST_JREC_HDR);
      if (calc != crc) { torn = true; break; }
      if (r.lsn < expected) { off += r.len; continue; }          /* already in the checkpoint */
      if (r.lsn != expected) { torn = true; break; }
      if (apply_ops(s, m + off + ST_JREC_HDR, r.len - ST_JREC_HDR) < 0) *anomaly = true;
      expected++;
      s->rec.records_replayed++;
      off += r.len;
    }
    if (!torn && off < size) torn = true;            /* trailing bytes that are not a record */
    munmap(m, size);
    close(fd);
    if (torn) { s->rec.journal_torn = true; break; }
  }
  s->rec.replay_to_lsn = expected - 1;
  s->lsn = expected - 1;
  s->jrn_gen = last_gen;      /* the new journal will be last_gen + 1 */
  return 0;
}

static int create_store(store_t *s) {
  st_random(s->uuid, 16);
  if (s->o.hash_seed[0] || s->o.hash_seed[1]) { s->hk0 = s->o.hash_seed[0]; s->hk1 = s->o.hash_seed[1]; }
  else st_random(&s->hk0, 16);
  s->seg_size = s->seg_size ? s->seg_size : (256ull << 20);
  size_t zres = (size_t)(s->o.max_zones ? s->o.max_zones : (1u << 25)) * ST_REC;
  size_t nres = s->o.nx_max ? (size_t)s->o.nx_max : (size_t)1 << 30;
  int r = mtab_open(s, &s->zt, "zt.1", FK_ZT, 64, zres, true);
  if (r == 0) r = mtab_open(s, &s->zc, "zc.1", FK_ZC, 64, zres, true);
  if (r == 0) r = mtab_open(s, &s->nx, "nx.1", FK_NX, 1, nres, true);
  uint64_t zones = s->o.expected_zones;
  if (r == 0) r = ensure_zt_cap(s, zones + 1);
  if (r == 0) r = ensure_nx_cap(s, 1);
  ixgen_t *ix = NULL, *sx = NULL;
  uint64_t slots = zones ? zones * 22 / 10 + 16 : ST_IX_MIN;
  if (slots < ST_IX_MIN) slots = ST_IX_MIN;
  if (r == 0) r = ixgen_create(s, FK_IX, 1, slots, &ix);
  if (r == 0) r = ixgen_create(s, FK_SX, 1, slots, &sx);
  if (r < 0) { ixgen_free(ix); return r; }
  atomic_store(&s->ix, ix);
  atomic_store(&s->sx, sx);
  s->ix_gen = s->sx_gen = 1;
  VS(s, V_FREE_HEAD, STORE_NONE);
  atomic_store(&s->nx_avail, 0);
  s->lsn = 0;
  s->ckpt_lsn = 0;
  s->jrn_gen = 0;
  /* two superblock copies so that either one can be the "older" one from the start */
  s->sb_next = 0;
  r = journal_open_new(s, 1, 1);
  if (r == 0) r = sb_write(s, false, 1);
  if (r == 0) r = sb_write(s, false, 1);
  return r;
}

int store_open(int dirfd, const store_opts_t *opts, store_t **out) {
  uint64_t t0 = st_now_us();
  if (!out) return -EINVAL;
  *out = NULL;
  pthread_once(&st_crc_once, st_crc_init);
  store_t *s = calloc(1, sizeof(*s));
  if (!s) return -ENOMEM;
  s->dirfd = dirfd;
  if (opts) s->o = *opts; else store_opts_default(&s->o);
  if (s->o.sync_interval_ms == 0) s->o.sync_interval_ms = 100;
  if (s->o.checkpoint_interval_ms == 0) s->o.checkpoint_interval_ms = 30000;
  if (s->o.journal_max_bytes == 0) s->o.journal_max_bytes = 64ull << 20;
  s->seg_size = s->o.seg_size ? s->o.seg_size : (256ull << 20);
  if (s->seg_size < 65536) s->seg_size = 65536;
  s->pagesz = (size_t)sysconf(_SC_PAGESIZE);
  if (s->pagesz == 0 || s->pagesz > ST_HDR_PAGE) { free(s); return -EINVAL; }
  pthread_mutex_init(&s->wlock, NULL);
  pthread_mutex_init(&s->seg_mu, NULL);
  s->jfd = -1;
  s->sb_fd[0] = s->sb_fd[1] = -1;
  s->zt.fd = s->zc.fd = s->nx.fd = -1;
  s->sbbuf = calloc(1, sizeof(sb_t));
  s->jb.p = malloc(4096);
  s->jb.cap = s->jb.p ? 4096 : 0;
  sb_t *cand[2] = { NULL, NULL };
  int r = 0;
  if (!s->sbbuf || !s->jb.p) { r = -ENOMEM; goto fail; }
  strcpy(s->fstype, "unknown");
#if defined(__FreeBSD__)
  struct statfs sfs;
  if (fstatfs(dirfd, &sfs) == 0) snprintf(s->fstype, sizeof(s->fstype), "%s", sfs.f_fstypename);
#endif
  s->mode = s->o.mode;
  if (s->mode != STORE_MODE_MAP && s->mode != STORE_MODE_COPY) s->mode = strcmp(s->fstype, "zfs") == 0 ? STORE_MODE_COPY : STORE_MODE_MAP;
  s->boot_id = s->o.boot_id ? s->o.boot_id : st_boot_id();

  for (int i = 0; i < 2; i++) {
    int fd = st_openat(s, st_sb_names[i], O_RDWR | (s->o.create ? O_CREAT : 0));
    if (fd < 0 && fd != -ENOENT) { r = fd; goto fail; }
    s->sb_fd[i] = fd < 0 ? -1 : fd;
  }
  cand[0] = calloc(1, sizeof(sb_t));
  cand[1] = calloc(1, sizeof(sb_t));
  if (!cand[0] || !cand[1]) { r = -ENOMEM; goto fail; }
  int rc[2];
  for (int i = 0; i < 2; i++) rc[i] = sb_read(s, i, cand[i]);

  if (rc[0] == -ENOENT && rc[1] == -ENOENT) {
    /* nothing there: create (the superblock files exist already, empty, when create is set) */
    if (!s->o.create) { r = -ENOENT; goto fail; }
    r = create_store(s);
    if (r < 0) goto fail;
    s->rec.created = true;
    s->rec.was_clean = true;
  } else {
    /* the newest valid copy whose table files check out; the other one when that fails */
    int order[2] = { 0, 1 };
    if (rc[0] != 0 || (rc[1] == 0 && cand[1]->f.seq > cand[0]->f.seq)) { order[0] = 1; order[1] = 0; }
    int used = -1;
    r = -EBADMSG;
    for (int k = 0; k < 2 && used < 0; k++) {
      int i = order[k];
      if (rc[i] != 0) continue;
      r = adopt_sb(s, cand[i]);
      if (r == 0) used = i;
    }
    if (used < 0) {
      st_log(s, 3, "store: no usable superblock copy (%d, %d)", rc[0], rc[1]);
      r = -EBADMSG;
      goto fail;
    }
    int other = 1 - used;
    /* "older" = the newest valid copy was not the one we could use */
    s->rec.used_older_super = (rc[other] == -EBADMSG) || (rc[other] == 0 && cand[other]->f.seq > cand[used]->f.seq);
    s->rec.was_clean = (cand[used]->f.flags & SBF_CLEAN) != 0;
    s->sb_seq = cand[used]->f.seq;
    if (rc[other] == 0 && cand[other]->f.seq > s->sb_seq) s->sb_seq = cand[other]->f.seq;
    s->sb_next = other;            /* the copy we did not adopt (damaged or older) is overwritten next */
    for (int i = 0; i < 2; i++) {
      const sb_t *c = rc[i] == 0 ? cand[i] : cand[used];
      s->slot_jrn[i] = c->f.jrn_gen;
      s->slot_ix[i] = c->f.ix_gen;
      s->slot_sx[i] = c->f.sx_gen;
    }
    uint64_t was_boot = cand[used]->f.boot_id;
    bool unclean = !s->rec.was_clean;
    bool anomaly = false;
    r = journal_replay(s, cand[used]->f.jrn_gen, &anomaly);
    if (r < 0) goto fail;
    /* same boot after an unclean stop: the page cache kept every cell and the replay is exact; another or an unknown boot (power
     * loss, OS crash): cells may be ahead of the journal, so the derived tables are rebuilt */
    bool rebuild = s->o.force_rebuild || anomaly || (unclean && (s->boot_id == 0 || was_boot == 0 || was_boot != s->boot_id));
    if (rebuild) {
      pthread_mutex_lock(&s->wlock);
      r = rebuild_locked(s);
      pthread_mutex_unlock(&s->wlock);
      if (r < 0) goto fail;
    }
  }
  free(cand[0]);
  free(cand[1]);
  cand[0] = cand[1] = NULL;
  /* start the session: a new journal and a superblock with the clean flag cleared and this boot id, durable before the first
   * modification */
  pthread_mutex_lock(&s->wlock);
  r = checkpoint_locked(s, false);
  pthread_mutex_unlock(&s->wlock);
  if (r < 0) goto fail;
  s->clean_on_disk = false;
  s->last_sync_ms = s->last_ckpt_ms = st_now_ms();
  s->rec.open_us = st_now_us() - t0;
  if (s->rec.records_replayed || s->rec.rebuilt || s->rec.used_older_super)
    st_log(s, 4, "store: recovered: %" PRIu64 " journal records, rebuilt=%d, older superblock=%d", s->rec.records_replayed,
           s->rec.rebuilt, s->rec.used_older_super);
  *out = s;
  return 0;
fail:
  free(cand[0]);
  free(cand[1]);
  files_close(s);
  for (int i = 0; i < 2; i++) if (s->sb_fd[i] >= 0) close(s->sb_fd[i]);
  pthread_mutex_destroy(&s->wlock);
  pthread_mutex_destroy(&s->seg_mu);
  free(s->sbbuf);
  free(s->jb.p);
  free(s);
  return r < 0 ? r : -EIO;
}

int store_close(store_t *s) {
  if (!s) return -EINVAL;
  pthread_mutex_lock(&s->wlock);
  int r = checkpoint_locked(s, true);
  if (r < 0) st_log(s, 3, "store: clean checkpoint at close failed: %d", r);
  /* wait (bounded) for readers of retired generations; the caller has stopped them */
  uint64_t e = rcu_writer_advance_epoch();
  rcu_writer_wait_until_safe(e, 2000);
  retire_run(s, true);
  files_close(s);
  for (int i = 0; i < 2; i++) if (s->sb_fd[i] >= 0) close(s->sb_fd[i]);
  pthread_mutex_unlock(&s->wlock);
  pthread_mutex_destroy(&s->wlock);
  pthread_mutex_destroy(&s->seg_mu);
  free(s->sbbuf);
  free(s->jb.p);
  free(s);
  return r;
}

int store_quarantine(int dirfd) {
  char dir[32];
  int n;
  for (n = 1; n < 1000; n++) {
    snprintf(dir, sizeof(dir), "aside.%d", n);
    if (mkdirat(dirfd, dir, 0700) == 0) break;
    if (errno != EEXIST) return -errno;
  }
  if (n >= 1000) return -EEXIST;
  int dup = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dup < 0) return -errno;
  DIR *d = fdopendir(dup);
  if (!d) { int e = errno; close(dup); return -e; }
  struct dirent *de;
  int moved = 0, r = 0;
  /* collect first: renaming while reading a directory may skip entries */
  char (*names)[64] = NULL;
  size_t cnt = 0, cap = 0;
  while ((de = readdir(d)) != NULL) {
    static const char *const pre[] = { "super.", "zt.", "zc.", "nx.", "ix.", "sx.", "seg.", "jrn." };
    bool match = false;
    for (size_t i = 0; i < sizeof(pre) / sizeof(pre[0]); i++)
      if (strncmp(de->d_name, pre[i], strlen(pre[i])) == 0) match = true;
    if (!match || strlen(de->d_name) >= 64) continue;
    if (cnt == cap) {
      cap = cap ? cap * 2 : 64;
      char (*nn)[64] = realloc(names, cap * sizeof(*names));
      if (!nn) { r = -ENOMEM; break; }
      names = nn;
    }
    strcpy(names[cnt++], de->d_name);
  }
  closedir(d);
  for (size_t i = 0; i < cnt && r == 0; i++) {
    char to[128];
    snprintf(to, sizeof(to), "%s/%s", dir, names[i]);
    if (renameat(dirfd, names[i], dirfd, to) != 0) r = -errno; else moved++;
  }
  free(names);
  return r < 0 ? r : moved;
}

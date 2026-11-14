#ifndef DNS_STORE_H
#define DNS_STORE_H

/*
 * dns_store - the zone store of KariDNS 0.7 (design: planning/planing_0.7.x_store_10m_design.md; this is WP1 of the schedule).
 *
 * The store is a directory of files (the Frontend opens it and hands the directory fd to the Backend; everything below is
 * `openat`, `pread`, `pwrite`, `mmap` on files beneath that fd):
 *   super.a / super.b   the superblock, two copies written alternately (newer valid one wins)
 *   zt.1 zc.1 nx.1      zone table (64 B per zone, hot part), zone table (64 B, cold part), long names; grow in place
 *   ix.<g>  sx.<g>      name index (view, name) -> zid and source index (source, domain id, view) -> zid; a new generation
 *                       file replaces them when they have to grow
 *   seg.<n>             image segments: append-only records (64 B header + name + image), checksummed
 *   jrn.<g>             the redo journal (see the long comment at the top of dns_store.c)
 *
 * What a caller has to know:
 *
 *  Threads.  One writer thread at a time (every writer function takes the store's writer mutex, so a second thread is safe but
 *  serialised); any number of lock-free readers.  Reader functions (store_find, store_find_source, store_zone_get,
 *  store_image_read, store_iter) must be called inside an RCU read section of the project's epoch RCU (dns_epoch_rcu.h):
 *    - a worker thread is already in one while it handles a query (rcu_reader_enter / rcu_reader_exit with its worker_ctx_t);
 *    - any other thread (store threads, the control thread, tests) brackets the calls with store_read_lock() / store_read_unlock()
 *      (rcu_aux_read_lock / rcu_aux_read_unlock: they nest).
 *  The read section protects the index generation that a lookup walks: when a generation is replaced the old mapping is
 *  retired through rcu_writer_advance_epoch() and unmapped by the writer once rcu_writer_is_safe() says no reader can still be
 *  inside it (checked at every writer call and at close).  Do not call a writer function from inside a read section and wait
 *  for the grace period there.  store_close() waits (bounded) for the readers; stop them before closing.
 *  An image returned by store_image_read() in MAP mode points into the mapped segment; it stays valid until
 *  store_img_release() (a reference count on the segment), also after the read section ended.
 *
 *  Return values.  Functions return 0 / a count on success and a negative errno on failure (-EINVAL, -ENOENT, -EEXIST, -ENOSPC,
 *  -EFBIG, -EIO, -EBADMSG for damaged data).  Lookup functions
 *  return STORE_NONE when there is nothing.
 *
 *  Names.  A name is the canonical text of the registry key: lower case, no trailing dot, 0..255 octets.  The store folds ASCII
 *  A-Z to a-z on every call (a query name may come in mixed case) and keeps the folded form.  The zone id (zid, u32) is dense and
 *  recycled: a zid is only meaningful while the zone exists; store_zone_get() returns the name, so a caller that kept a zid
 *  over a delete can tell that it was reused.
 *
 *  Capsicum.  Everything is done through the directory fd: openat (O_CREAT, O_TRUNC; O_RESOLVE_BENEATH when available), pread, pwrite,
 *  pwritev, mmap (rw shared for the tables, ro for segments), msync, fsync, fdatasync, ftruncate, posix_fallocate, fstat, fstatfs,
 *  unlinkat; renameat and mkdirat (and readdir) only in store_quarantine(), which the Frontend runs before it hands the fd over.
 *  So the rights to limit the fd to: CAP_LOOKUP, CAP_CREATE, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_MMAP_RW, CAP_FSYNC, CAP_FTRUNCATE,
 *  CAP_FALLOCATE, CAP_FSTAT, CAP_FSTATFS, CAP_UNLINKAT.  The boot id (opts.boot_id) must be passed in: sysctl is not available there.
 *
 *  Durability.  A writer call is applied and visible to readers when it returns.  It is recoverable after kill -9 at once; it
 *  is durable against power loss after the next commit: store_commit() (a "batch end"), the periodic commit of the policy in
 *  store_opts_t (every sync_interval_ms, evaluated at each writer call and by store_tick()), or a checkpoint.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define STORE_NONE            0xFFFFFFFFu   /* "no zone" for zids */
#define STORE_FORMAT_VERSION  1u
#define STORE_MAX_VIEWS       32            /* store view ids 0..31 */
#define STORE_VIEW_NAME_MAX   63
#define STORE_MAX_SOURCES     64            /* source ids 0..63 (cursor table) */
#define STORE_IDENT_MAX       64            /* database identity bytes kept with a cursor */
#define STORE_NAME_MAX        255
#define STORE_DIGEST_LEN      32
#define STORE_MAX_SEGS        1024
#define STORE_IMAGE_ALIGN     16            /* image data (MAP or COPY) is aligned to this */

/* zone states (zt.state) */
enum { STORE_STATE_FREE = 0, STORE_STATE_KNOWN = 1, STORE_STATE_STORED = 2 };

/* zt.flags (the store keeps them for the caller; it counts only REJECTED_NEW) */
#define STORE_F_PRESIGNED     0x0001u
#define STORE_F_ALIAS         0x0002u
#define STORE_F_WILDCARD      0x0004u
#define STORE_F_NOTIFY_DUE    0x0008u
#define STORE_F_REJECTED_NEW  0x0010u
#define STORE_F_UPDATED_PIN   0x0020u

/* access mode of the images */
enum { STORE_MODE_AUTO = 0, STORE_MODE_MAP = 1, STORE_MODE_COPY = 2 };
/* journal sync policy */
enum {
  STORE_SYNC_BATCH = 0,   /* default: fdatasync at store_commit() and at least every sync_interval_ms */
  STORE_SYNC_EVERY = 1,   /* every writer call is committed before it returns */
  STORE_SYNC_NONE  = 2    /* only checkpoints and close sync (bulk loads, tests) */
};

/* store_stats_t.state bits */
#define STORE_ST_DEGRADED_NOSPC 0x1u  /* the last write failed with ENOSPC / EFBIG; cleared by the next success */
#define STORE_ST_REPAIRED       0x2u  /* the last open had to rebuild the derived tables */

typedef struct store store_t;

typedef struct store_opts {
  int      mode;                  /* STORE_MODE_AUTO (fstatfs f_fstypename "zfs" -> COPY, else MAP), MAP or COPY */
  bool     create;                /* create the store when the directory holds none */
  uint32_t max_zones;             /* address space reserved for zt / zc (records); 0 = 1<<25.  Not a limit of the files. */
  uint64_t nx_max;                /* address space reserved for nx (bytes); 0 = 1 GiB */
  uint64_t seg_size;              /* nominal segment size (bytes); 0 = 256 MiB; the minimum is 64 KiB (tests) */
  uint64_t expected_zones;        /* pre-size the tables (first fill); 0 = grow on demand */
  int      sync_policy;           /* STORE_SYNC_* */
  uint32_t sync_interval_ms;      /* STORE_SYNC_BATCH: longest time a writer call stays uncommitted; 0 = 100 */
  uint32_t checkpoint_interval_ms;/* 0 = 30000 (D6); UINT32_MAX = only by journal size and explicit calls */
  uint64_t journal_max_bytes;     /* a checkpoint is forced when the journal reaches this size; 0 = 64 MiB */
  uint64_t boot_id;               /* identifies this boot of the host (kern.boottime seconds); 0 = look it up, and if that is
                                   * not possible assume the worst.  After an unclean stop under a different boot id the open
                                   * rebuilds the derived tables after the replay (page cache lost -> pages may be ahead of the
                                   * journal); under the same boot id the journal replay alone is exact. */
  uint64_t hash_seed[2];          /* both 0 = random (created stores only); tests pin it */
  bool     force_rebuild;         /* rebuild ix / sx / free list / counters at open (tests, repair) */
  void   (*log)(void *ctx, int level, const char *msg);  /* optional: 3 = error, 4 = warning, 6 = info */
  void    *log_ctx;
} store_opts_t;

/* defaults of every field above (mode AUTO, create false, ...) */
void store_opts_default(store_opts_t *o);

/* What the open found and did. */
typedef struct store_recovery {
  bool     created;               /* a new store was made */
  bool     was_clean;             /* the previous session ended with store_close() */
  bool     used_older_super;      /* the newer superblock copy was damaged */
  bool     rebuilt;               /* derived tables were rebuilt (see store_opts_t.boot_id) */
  uint32_t journals_read;         /* journal files read */
  uint64_t records_replayed;      /* journal records applied (LSN after the checkpoint) */
  uint64_t replay_from_lsn;
  uint64_t replay_to_lsn;
  bool     journal_torn;          /* the replay stopped at a torn or CRC-bad record (normal after kill -9 mid-write) */
  uint64_t rebuilt_zones;         /* zone records seen by the rebuild */
  uint64_t dropped_zones;         /* ... of which dropped (CRC, bounds, duplicate name) */
  uint64_t open_us;               /* time of the whole open */
} store_recovery_t;

/* Zone metadata the caller supplies (everything the store keeps besides the name and the image). */
typedef struct store_meta {
  int64_t  source_id;             /* domain id in the source database; 0 = none (not in the source index) */
  uint16_t source;                /* source number 0..STORE_MAX_SOURCES-1 */
  uint16_t flags;                 /* STORE_F_* */
  uint32_t serial;                /* SOA serial of the stored version */
  uint32_t settings;              /* id of the interned settings text */
  uint64_t stamp_gen;             /* version stamp (design 5.2) */
  uint64_t stamp_time;
  uint8_t  digest[STORE_DIGEST_LEN];
} store_meta_t;

/* zt + zc of one zone (store_zone_get / store_iter) */
typedef struct store_zone {
  uint32_t zid;
  uint8_t  state;                 /* STORE_STATE_* */
  uint8_t  klen;
  uint16_t view;
  uint16_t flags;
  uint16_t source;
  uint32_t img_len;               /* bytes of the image (0 for KNOWN) */
  uint32_t serial;
  uint32_t settings;
  uint64_t loc;                   /* image record: segment << 36 | byte offset / 64; 0 for KNOWN */
  int64_t  source_id;
  uint64_t stamp_gen;
  uint64_t stamp_time;
  uint8_t  digest[STORE_DIGEST_LEN];
  char     name[STORE_NAME_MAX + 1];  /* NUL-terminated */
} store_zone_t;

/* One image read (store_image_read).  Fields from the 64 B record header; data/len are the image. */
typedef struct store_img {
  const void *data;               /* STORE_IMAGE_ALIGN-aligned; MAP: inside the mapped segment (read only); COPY: heap copy */
  size_t   len;
  uint32_t zid;
  uint16_t view;
  uint16_t kind;                  /* 0 = zone image */
  uint32_t flags;
  uint32_t serial;
  uint32_t settings;
  uint64_t stamp_gen;
  uint64_t prev_loc;              /* the record of the version before (0 = none); IXFR history later */
  uint64_t loc;
  uint64_t checksum;              /* checksum64 that was verified */
  void    *priv_;                 /* private: reference to release */
  uint32_t seg_;
} store_img_t;

typedef struct store_view_stats {
  char     name[STORE_VIEW_NAME_MAX + 1];
  uint64_t known, stored, rejected;
  uint64_t image_bytes;           /* record bytes of the stored images of this view */
} store_view_stats_t;

/* Design section 9.1; every figure is a counter kept at the change, store_stats() is O(views). */
typedef struct store_stats {
  uint32_t format;
  int      mode;                  /* STORE_MODE_MAP / COPY (resolved) */
  char     fstype[16];
  uint8_t  uuid[16];
  uint32_t state;                 /* STORE_ST_* */
  bool     clean_flag;            /* the newest superblock on disk says "clean stop"; false during a running session (the open clears it durably) */
  uint64_t zones_known, zones_stored, zones_rejected, zones_free;
  uint64_t zt_records;            /* high-water mark: records in use incl. free ones */
  uint64_t zt_capacity;           /* records the files can hold now */
  uint64_t nx_used, nx_dead;
  uint32_t ix_gen, sx_gen;
  uint64_t ix_slots, ix_used, ix_live, sx_slots, sx_used, sx_live;
  uint32_t seg_count;
  uint64_t seg_used_bytes;        /* bytes appended to all segments */
  uint64_t seg_live_bytes;        /* ... of which records still referenced */
  uint64_t lsn, ckpt_lsn, committed_lsn;
  uint64_t journal_bytes;         /* size of the current journal */
  uint32_t journal_gen;
  uint64_t checkpoints, last_checkpoint_unix, last_checkpoint_us;
  uint64_t commits;
  uint64_t puts, replaces, deletes, growths;
  uint64_t write_errors;
  store_recovery_t recovery;
  uint32_t nviews;
  store_view_stats_t views[STORE_MAX_VIEWS];
} store_stats_t;

typedef struct store_seg_info {
  uint32_t num;
  uint64_t used, live, file_size; /* appended bytes, referenced bytes */
} store_seg_info_t;

typedef struct store_check_report {
  uint64_t zones;                 /* non-free records seen */
  uint64_t errors;                /* inconsistencies found (0 = consistent) */
  char     first_error[160];
} store_check_report_t;

/* ---- open / close ---- */

/* Open (or create, opts->create) the store in the directory dirfd.  dirfd stays owned by the caller (it must outlive the store).
 * Recovery from the journal happens here; the result is in store_stats().recovery.  -EBADMSG: both superblock copies are
 * damaged or the store is of another format (see store_quarantine()). */
int  store_open(int dirfd, const store_opts_t *opts, store_t **out);
/* Clean stop: commit, checkpoint with the clean flag, close.  Waits (bounded) for readers of retired generations. */
int  store_close(store_t *s);
/* Move every file of a store that cannot be opened into a new sub-directory "aside.<n>" of dirfd (the caller then creates a new
 * store and fills it from the database, design 2.4). */
int  store_quarantine(int dirfd);

/* ---- views ---- */
/* id of the view named name, or -ENOENT.  Lock-free. */
int  store_view_id(const store_t *s, const char *name);
/* id of the view, created when it does not exist yet (writer; journaled).  -ENOSPC when STORE_MAX_VIEWS are in use. */
int  store_view_add(store_t *s, const char *name);
/* name of view id (NULL when none); valid until store_close. */
const char *store_view_name(const store_t *s, int view);

/* ---- lookup: lock-free, inside an RCU read section (see top) ---- */
void     store_read_lock(void);     /* for threads that are not workers; nests */
void     store_read_unlock(void);
/* zid of (view, name) or STORE_NONE.  Case-insensitive; the name is verified against zt / nx, so a damaged index entry makes a
 * zone invisible, never wrong. */
uint32_t store_find(const store_t *s, uint16_t view, const char *name, size_t len);
/* The query path's two-step lookup (0.7 S3).  store_find_cand(): the zids whose index slot has the tag of (view, name), in probe order, at most `max`, NOT verified against the
 * zone table (the name must be folded: lower case); usually 0 or 1.  The caller verifies a candidate against what it holds (the name of an attached zone's element in the heap) or,
 * for a zone that is not in memory, with store_zid_is() (the zone table's name, under the cell's sequence counter).  A damaged slot makes a zone invisible, never wrong. */
unsigned store_find_cand(const store_t *s, uint16_t view, const char *fname, size_t len, uint32_t *zids, unsigned max);
bool     store_zid_is(const store_t *s, uint32_t zid, uint16_t view, const char *name, size_t len);
/* A thread that must never yield or sleep (a query worker) calls store_reader_nosleep(true) once: the readers of this file then spin a bounded time on a cell that is being
 * written and give up (the lookup finds nothing, store_zone_get() says -EBADMSG) instead of yielding and sleeping up to 500 ms.  store_reader_busy_take() says (and clears) that
 * this thread gave up since the last call: the answer of the lookup is then "not known now", and the caller takes the slow path (parks the query for a store thread, which does
 * not mind sleeping) rather than treating the zone as absent or damaged. */
void     store_reader_nosleep(bool on);
bool     store_reader_busy_take(void);
/* zid by (source, domain id, view) from the source index, or STORE_NONE */
uint32_t store_find_source(const store_t *s, uint16_t source, int64_t domain_id, uint16_t view);
/* zt + zc fields of a zone.  0, -ENOENT (free / out of range), -EBADMSG (CRC of the record wrong: a damaged zone; a
 * record that is being replaced is read again until it is consistent). */
int      store_zone_get(const store_t *s, uint32_t zid, store_zone_t *out);
/* Read the image of a STORED zone and verify its checksum64 (and the header against zt).  -ENOENT: not stored; -EBADMSG: damaged
 * (the caller sets the zone back to KNOWN and fetches it again).  Release with store_img_release(). */
int      store_image_read(const store_t *s, uint32_t zid, store_img_t *img);
void     store_img_release(const store_t *s, store_img_t *img);
/* Iterate by zid (design D13).  *cursor starts at 0.  Returns 1 and fills *out with the next non-free zone and advances the
 * cursor; 0 at the end; -EBADMSG for a damaged record (out->zid says which, the cursor has advanced past it). */
int      store_iter(const store_t *s, uint32_t *cursor, store_zone_t *out);
/* number of labels of a canonical name (the depth key of the "depth skip"), escapes (\.) respected */
unsigned store_name_labels(const char *name, size_t len);
/* zones of the view whose name has exactly `labels` labels (labels >= 63 share the last bucket) and the deepest label count with
 * zones (0 = none): the suffix walk of the query path starts there. */
uint64_t store_view_depth_count(const store_t *s, uint16_t view, unsigned labels);
unsigned store_view_depth_max(const store_t *s, uint16_t view);

/* ---- writer (one thread; every call takes the writer mutex) ---- */
/* Insert or replace the zone (view, name) with a STORED image: append the record to the open segment, then one journal record
 * covers zt / zc / nx / ix / sx / counters, then the cells are written (readers see the zone atomically through the index slot,
 * or through the record CRC for a replace).  *zid (optional) receives the zone id.
 * -EEXIST: meta->source_id of another zone has the same (source, domain id, view) (rename: delete the old zone first). */
int  store_put(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta,
               const void *image, size_t image_len, uint32_t *zid);
/* The zone exists with name and stamp but without an image (state KNOWN); a stored image of the zone is released. */
int  store_set_known(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, uint32_t *zid);
int  store_delete(store_t *s, uint32_t zid);
int  store_delete_name(store_t *s, uint16_t view, const char *name, size_t len);
/* change zt.flags (set, then clear bits) without touching the image (NOTIFY_DUE, REJECTED_NEW, ...) */
int  store_set_flags(store_t *s, uint32_t zid, uint16_t set, uint16_t clear);
/* change-log cursor and database identity of a source (kept in the superblock; durable with the next commit) */
int  store_set_cursor(store_t *s, uint16_t source, uint64_t cursor, const void *ident, size_t ident_len);
/* valid = false: no cursor was ever stored.  ident (STORE_IDENT_MAX bytes) / *ident_len optional. */
int  store_get_cursor(store_t *s, uint16_t source, bool *valid, uint64_t *cursor, void *ident, size_t *ident_len);
/* announce the number of zones of a first fill: sizes zt / zc / ix / sx once (a checkpoint barrier) */
int  store_reserve(store_t *s, uint64_t zones);
/* group commit point: fdatasync the segments written and the journal.  After it every writer call made before is durable. */
int  store_commit(store_t *s);
/* the time-driven part: commits when the policy says so and checkpoints when checkpoint_interval_ms has passed.  Call about once
 * per second from the writer thread (writer calls do the same check). */
int  store_tick(store_t *s);
/* flush the files, write the other superblock copy with the checkpoint LSN, start a new journal, remove what no superblock
 * names any more (design 3.4 with a journal) */
int  store_checkpoint(store_t *s);
/* The same, with the clean flag: what store_close() does, but the store stays open and usable (a server that stops while its workers may still look).  The next
 * writer call clears the flag again, durably, before it changes anything. */
int  store_checkpoint_clean(store_t *s);
/* Rebuild the derived tables (ix, sx, free list, counters, live bytes) from one sequential pass over zt and drop cells that are
 * damaged (CRC, impossible fields, an image location outside its segment) or duplicate a name or a source key, then checkpoint.
 * Heavy (O(zones), blocks the writer; readers continue on the old tables).  This is what the open does after a power loss,
 * and what a scrub calls: a zone whose zt cell is damaged is invisible and cannot be changed (-EBADMSG) until it is dropped
 * here; the caller then fetches it again.  (An image that fails its checksum is different: its zt cell is fine, and
 * store_set_known() releases it.) */
int  store_repair(store_t *s);

/* ---- statistics, verification ---- */
void store_stats(const store_t *s, store_stats_t *out);                 /* O(views), no lock */
int  store_seg_info(const store_t *s, uint32_t num, store_seg_info_t *out);  /* num 1..seg_count */
/* Page-cache residency estimate: mincore() on up to `pages` random pages of the appended part of the segments (MAP mode; -ENOTSUP in
 * COPY mode, -errno when mincore() is refused, e.g. in a sandbox).  *sampled pages looked at, *resident of them in memory.  Bounded, no lock. */
int  store_resident_sample(const store_t *s, unsigned pages, uint64_t seed, uint64_t *sampled, uint64_t *resident);
/* Full consistency check (O(zones), takes the writer mutex): every record valid, every zone reachable through ix / sx, counters
 * and live bytes equal the recount, the free list intact, no duplicate names.  For tests, `karictl store verify`, the scrub. */
int  store_check(store_t *s, store_check_report_t *rep);

/* ---- test support (only compiled into unit-test builds, -DKARIDNS_UNIT_TEST) ---- */
#ifdef KARIDNS_UNIT_TEST
/* SIGKILL the process at the n-th crash point (0 = off); the points lie between every step of a write sequence */
extern long store_test_crash_countdown;
/* called by the writer between the ops of a journal record that publish a zone (cells, indexes) and the counters op of the same record: the window in which a reader can see a new zone before the counters of its segment (0 = off) */
extern void (*store_test_before_counters)(store_t *s);
/* commit_locked() fails with -EIO at the n-th call (0 = off): a failed fdatasync */
extern long store_test_fail_commit;
uint64_t store_test_siphash(unsigned c, unsigned d, const uint8_t key[16], const uint8_t *in, size_t len);
uint32_t store_test_crc32c(uint32_t crc, const void *p, size_t n);
uint64_t store_test_sum64(const void *p, size_t n);
/* path of a store file (for damage tests), written into buf */
#endif

#endif /* DNS_STORE_H */

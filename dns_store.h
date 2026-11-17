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
 *  serialised); any number of lock-free readers.  No writer call waits for the disk inside the mutex (0.7 fix A): the fdatasync of the
 *  journal and the segments (the commit), the msync of the tables (the checkpoint) and the build of a bigger index run outside it, on the
 *  store's flusher thread and on a thread of its own for a growth (both started by the store; see the comment at the top of dns_store.c).  Reader functions (store_find, store_find_source, store_zone_get,
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
 *  pwritev, mmap (rw shared for the tables, ro for segments), msync, madvise, mincore, fsync, fdatasync, ftruncate, posix_fallocate, fstat, fstatfs,
 *  unlinkat (the cleaner removes segments, the open removes old generations); renameat and mkdirat (and readdir) only in store_quarantine(), which the Frontend runs before it hands the fd over.
 *  The store starts a detached thread for the zt read-ahead after the open, the flusher thread (commits and checkpoints) and, while an index
 *  grows, a detached thread that builds the bigger index; store_close() waits for all of them.
 *  So the rights to limit the fd to: CAP_LOOKUP, CAP_CREATE, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_MMAP_RW, CAP_FSYNC, CAP_FTRUNCATE,
 *  CAP_FALLOCATE, CAP_FSTAT, CAP_FSTATFS, CAP_UNLINKAT.  The boot id (opts.boot_id) must be passed in: sysctl is not available there.
 *
 *  Durability.  A writer call is applied and visible to readers when it returns.  It is recoverable after kill -9 at once; it
 *  is durable against power loss after the next commit: store_commit() (a "batch end"), the periodic commit of the policy in
 *  store_opts_t (every sync_interval_ms, made by the flusher thread), or a checkpoint.  A commit that fails in the background is
 *  counted (write_errors, STORE_ST_DEGRADED_NOSPC for a full disk) and tried again; store_commit() and STORE_SYNC_EVERY return its error.
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
#define STORE_F_NONSTORE      0x0040u   /* 0.7 WP7b: a secondary or catalog zone of the database: the record only remembers the zone for the reconcile (it is a heap zone, never stored, never found by a query) */
#define STORE_F_STALE         0x0080u   /* 0.7 WP7b: the database has another version of the zone than the image (the record's stamp is the wanted one): the body is fetched in the background; the image keeps serving meanwhile */

/* access mode of the images */
enum { STORE_MODE_AUTO = 0, STORE_MODE_MAP = 1, STORE_MODE_COPY = 2 };
/* journal sync policy */
enum {
  STORE_SYNC_BATCH = 0,   /* default: fdatasync at store_commit() and at least every sync_interval_ms */
  STORE_SYNC_EVERY = 1,   /* every writer call is committed before it returns */
  STORE_SYNC_NONE  = 2    /* only checkpoints and close sync (bulk loads, tests) */
};

/* store_stats_t.state bits */
#define STORE_ST_DEGRADED_NOSPC 0x1u  /* no room: the last write failed with ENOSPC / EFBIG / EDQUOT, or the store is degraded (new and changed zones are kept as records without an image, see store_put()); cleared by the next write that works, in the degraded state by the next image that is stored */
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
  uint64_t journal_max_bytes;     /* a checkpoint is forced when the journal reaches this size; 0 = 100 MiB (a replay of that is about a second) */
  uint64_t boot_id;               /* identifies this boot of the host (kern.boottime seconds); 0 = look it up, and if that is
                                   * not possible assume the worst.  After an unclean stop under a different boot id the open
                                   * rebuilds the derived tables after the replay (page cache lost -> pages may be ahead of the
                                   * journal); under the same boot id the journal replay alone is exact. */
  uint64_t hash_seed[2];          /* both 0 = random (created stores only); tests pin it */
  bool     force_rebuild;         /* rebuild ix / sx / free list / counters at open (tests, repair) */
  void   (*log)(void *ctx, int level, const char *msg);  /* optional: 3 = error, 4 = warning, 6 = info */
  void    *log_ctx;
  /* 0.7 WP9 (S6): the cleaner, the disk-full behaviour, the scrub.  Every field is "0 = the default". */
  bool     no_degrade;            /* a write that finds no room is refused (-ENOSPC) instead of being kept as a record without an image (KNOWN): tests */
  uint64_t reserve_bytes;         /* free bytes of the file system that only the cleaner may use: ordinary appends refuse (ENOSPC) below this; 0 = seg_size / 2, at least 256 KiB, at most 128 MiB */
  uint64_t compact_rate;          /* bytes per second the cleaner moves (a token bucket); 0 = 16 MiB; UINT64_MAX = no limit */
  uint32_t compact_min_dead_pct;  /* a segment is cleaned when at least this share of it is dead; 0 = 50 */
  uint64_t nx_reclaim_min;        /* dead bytes of long names that make the space worth reclaiming (and at least half of nx); 0 = 4 MiB */
  uint32_t scrub_interval_s;      /* seconds between the starts of two scrubs; 0 = a week, UINT32_MAX = never (karictl can still start one) */
  uint64_t scrub_rate;            /* bytes per second the scrub reads; 0 = 16 MiB */
  /* the structure check of an image (zone_image_validate()); the scrub calls it for every image it reads.  NULL = the checksum only. */
  int    (*validate)(const void *image, size_t len, char *why, size_t whylen);
  bool     no_readahead;          /* do not start the thread that reads zt into memory after the open (tests) */
  /* The scrub and the cleaner make the zone of a damaged image KNOWN in the store; a zone that is attached in memory (MAP mode: its image is the mapped pages) keeps serving them.  The zone id is
   * queued under the writer mutex and handed to this function by the tick (and at the end of a scrub pass or a compact call) with no lock of the store held: ud is bad_image_ctx.  It returns 0 (done, or
   * nothing to do) or 1 (not now: asked again at the next tick, a bounded number of times).  NULL: nothing is queued. */
  int    (*bad_image)(uint32_t zid, void *ud);
  void    *bad_image_ctx;
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
  uint32_t gen_replays;           /* index generations (OP_GEN) the replay switched to: their files hold what a checkpoint wrote, so the derived tables were rebuilt (0.7, private tables) */
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
  uint32_t seq;                   /* the sequence word of the cell pair at the read (store_zone_unchanged()); 0 when the zone was not read by store_zone_get() */
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
  uint64_t zones_known, zones_stored, zones_rejected, zones_nonstore, zones_free;   /* zones_nonstore: the records with STORE_F_NONSTORE (a subset of known + stored) */
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
  uint64_t group_records, group_entries;   /* 0.7 M2: journal records written by store_set_known_n() and the entries they carried (one record per group) */
  uint64_t write_errors;
  store_recovery_t recovery;
  uint32_t nviews;
  store_view_stats_t views[STORE_MAX_VIEWS];
  /* ---- 0.7 WP9 ---- */
  uint64_t journal_max_bytes;     /* the size at which a checkpoint is forced */
  uint32_t seg_free_numbers;      /* numbers of segments that were cleaned and removed (they are used again) */
  uint32_t seg_draining;          /* segments with no live record that wait for a checkpoint, a grace period, the end of the references */
  uint32_t seg_pinned;            /* segments that an attached zone's image (MAP mode) points into: not cleaned, not removed */
  /* the cleaner */
  uint64_t compact_runs, compact_moved_records, compact_moved_bytes, compact_segs_freed, compact_bad_records, compact_pinned_skips, compact_incomplete;
  uint64_t compact_last_unix;
  uint64_t compact_rate;          /* bytes per second, UINT64_MAX = no limit */
  uint32_t compact_candidates;    /* segments that are dead enough to be cleaned now (not the open one) */
  uint64_t compact_dead_bytes;    /* dead bytes of all segments but the open one: what the cleaner could win */
  uint64_t nx_reclaims, nx_reclaimed_bytes;
  /* disk space (the file system of the store, measured at every checkpoint and every second while the store is busy) */
  uint64_t fs_total_bytes, fs_free_bytes, fs_checked_unix;
  uint64_t reserve_bytes;
  uint32_t fs_blksize;            /* st_blksize of the table file: on ZFS the dataset's recordsize */
  bool     fs_recordsize_warn;    /* ZFS with a record size above 32 KiB */
  uint32_t space_level;           /* 0 = ok, 1 = low (a WARNING was said), 2 = degraded: new images are not stored */
  uint64_t store_bytes;           /* what the store occupies: segments, tables, indexes, journal */
  uint64_t growth_bytes_per_hour; /* the growth of the last hour (0 = not known or shrinking) */
  uint64_t full_in_hours;         /* at that growth the file system is full in this many hours (0 = not known) */
  uint64_t degraded_puts, enospc_events, degraded_since_unix;
  /* the scrub */
  uint32_t scrub_interval_s;      /* UINT32_MAX = never */
  bool     scrub_running;
  uint32_t scrub_progress_pct;
  uint64_t scrub_passes, scrub_last_start_unix, scrub_last_end_unix, scrub_zones_checked, scrub_bytes_checked;
  uint64_t scrub_bad_images, scrub_bad_cells, scrub_bad_index, scrub_io_errors;
  /* the open */
  uint64_t ix_read_us;            /* the read of ix before the first answer */
  uint64_t zt_readahead_us;       /* the read-ahead of zt in the background (0 while it runs) */
  bool     zt_readahead_done;
  uint64_t err_total;             /* texts put into err.ring since it was made */
  /* ---- 0.7 fix A: no I/O inside the writer mutex ---- */
  uint64_t lock_holds;            /* holds of the writer mutex since the open */
  uint64_t lock_holds_slow;       /* ... of 1 ms or more */
  uint64_t lock_hold_max_us;      /* the longest one */
  const char *lock_hold_max_site;  /* the function that held it (a static string; NULL: no hold yet) */
  uint64_t growths_background;    /* index growths that were built outside the mutex (the others: in it, when the index filled up before the build ended) */
  bool     flusher;               /* the flusher thread runs (false: the writers make the due commits and checkpoints themselves, after the mutex) */
  /* ---- 0.7: the flush of a checkpoint converges; the bound of the journal ---- */
  uint64_t checkpoint_max_us;     /* the longest checkpoint since the open */
  uint64_t checkpoints_cancelled; /* fuzzy checkpoints that a close left (its clean checkpoint flushed everything instead) */
  uint64_t journal_peak_bytes;    /* the largest size a journal file reached since the open */
  uint64_t journal_bound_bytes;   /* the bound: 2 x journal_max_bytes (the writers wait at it for the checkpoint in progress) */
  uint64_t journal_limit_waits;   /* writer calls that waited at their end for a checkpoint because the journal was at the bound */
  uint64_t journal_limit_wait_us, journal_limit_wait_max_us;   /* the total and the longest of those waits */
  uint64_t journal_commit_switches; /* the journal file switched by a commit (0.7: the writers append to a file that no sync holds) */
  uint64_t image_prewrites;         /* image records store_put() wrote before the writer mutex and the change took (0.7) */
  uint64_t image_prewrite_misses;   /* ... that the change wrote again inside the mutex (the zone, its record or the open segment changed in between) */
  /* ---- 0.7: the tables in private memory, written by the checkpoint ---- */
  uint64_t table_private_bytes;     /* pages of zt, zc, nx, ix, sx that the writers changed since the open: private memory of the process (counted in memory-limit) */
  uint64_t checkpoint_table_bytes;  /* bytes of the tables that checkpoints wrote since the open */
  uint64_t checkpoint_table_last_bytes; /* ... the last one */
} store_stats_t;

/* What one store_compact() did. */
typedef struct store_compact_report {
  uint64_t moved_records, moved_bytes;
  uint32_t segs_emptied;          /* segments that have no live record now */
  uint32_t segs_freed;            /* segments removed (their files are gone) */
  uint64_t nx_reclaimed;          /* bytes of nx given back */
  uint32_t bad_records;           /* live records that failed their checksum: the zone became KNOWN */
} store_compact_report_t;

/* What one scrub pass found. */
typedef struct store_scrub_report {
  uint64_t zones, images, bytes;
  uint64_t bad_images;            /* checksum or structure: the zone became KNOWN */
  uint64_t bad_cells;             /* the table record is damaged: dropped by the repair at the end of the pass */
  uint64_t bad_index;             /* a zone that its index entry does not lead to: the repair rebuilt the indexes */
  uint64_t io_errors;
  bool     repaired;
} store_scrub_report_t;

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
bool     store_reader_nosleep(bool on);          /* the mode before the call */
bool     store_reader_busy_take(void);
/* zid by (source, domain id, view) from the source index, or STORE_NONE */
uint32_t store_find_source(const store_t *s, uint16_t source, int64_t domain_id, uint16_t view);
/* zt + zc fields of a zone.  0, -ENOENT (free / out of range), -EBADMSG (CRC of the record wrong: a damaged zone; a
 * record that is being replaced is read again until it is consistent). */
int      store_zone_get(const store_t *s, uint32_t zid, store_zone_t *out);
/* Has the zone's cell pair stayed as store_zone_get() read it (z->seq)?  Every write of the cells (a put, a delete, a state change, a rename) advances the sequence word, so true means that
 * the zone id still holds the record that was read, with the name, the version, the digest and the location.  It reads one word of the cell that the read touched a moment ago (no search in the
 * name index, no CRC): a caller that holds a lock can ask this where it would have read the record again.  false: changed, being written, or not a zone. */
bool     store_zone_unchanged(const store_t *s, uint32_t zid, uint32_t seq);
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
 * -EEXIST: meta->source_id of another zone has the same (source, domain id, view) (rename: delete the old zone first).
 * No room for the image (the free space is below opts.reserve_bytes, or the write fails with ENOSPC / EFBIG / EDQUOT): the cleaner runs at once and the put is tried again; if that
 * does not help the store is degraded (design 3.5) and, unless opts.no_degrade, the zone is stored as in store_set_known(): its record with the new stamp and no image (the old
 * image is released) and the call returns 0.  The caller sees the state with store_zone_get() (STORE_STATE_KNOWN); it is stored again by the next put when room is back.
 * -ENOSPC is returned when even the record cannot be made (a table that cannot grow), and with opts.no_degrade. */
int  store_put(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta,
               const void *image, size_t image_len, uint32_t *zid);
/* The zone exists with name and stamp but without an image (state KNOWN); a stored image of the zone is released. */
int  store_set_known(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, uint32_t *zid);
/* 0.7 M2, group commit: n entries of one view as n calls of store_set_known(), in order, but the journal record, the writer mutex and the commit decision are one per group of up to 64 entries.  res[i] is
 * what the call for entry i would have returned (0, or -errno: that entry is not recorded, the others are), zid[i] (optional) its zone id.  Every op of the record is a full cell value (the journal format is
 * the one of a single call), so after kill -9 the group is there whole or not at all (one CRC), and a replay needs nothing new.  An entry that has the name or the source id of one pending in the group, or
 * that needs a table to grow, ends the group first: the effect is that of the calls one after the other (the slot a pending entry claimed in the name index is probed past).  The return value is 0, or -EINVAL for bad arguments. */
typedef struct { const char *name; size_t len; const store_meta_t *meta; } store_known_t;
int  store_set_known_n(store_t *s, uint16_t view, const store_known_t *in, size_t n, int *res, uint32_t *zid);
int  store_delete(store_t *s, uint32_t zid);
int  store_delete_name(store_t *s, uint16_t view, const char *name, size_t len);
/* change zt.flags (set, then clear bits) without touching the image (NOTIFY_DUE, REJECTED_NEW, ...) */
int  store_set_flags(store_t *s, uint32_t zid, uint16_t set, uint16_t clear);
/* the stamp (zc) and the flags of a zone in one write: 0.7 WP7b, the reconcile records which version of the zone the database has */
int  store_set_stamp(store_t *s, uint32_t zid, uint64_t gen, uint64_t time, uint16_t set, uint16_t clear);
/* change-log cursor and database identity of a source (kept in the superblock; durable with the next commit) */
int  store_set_cursor(store_t *s, uint16_t source, uint64_t cursor, const void *ident, size_t ident_len);
/* valid = false: no cursor was ever stored.  ident (STORE_IDENT_MAX bytes) / *ident_len optional. */
int  store_get_cursor(store_t *s, uint16_t source, bool *valid, uint64_t *cursor, void *ident, size_t *ident_len);
/* announce the number of zones of a first fill: sizes zt / zc / ix / sx once (a checkpoint barrier) */
int  store_reserve(store_t *s, uint64_t zones);
/* group commit point: fdatasync the segments written and the journal.  After it every writer call made before is durable.  It waits for the disk without the writer mutex
 * (writers go on meanwhile); concurrent callers share one sync. */
int  store_commit(store_t *s);
/* 0.7: the bound of the journal.  A writer that holds no lock of its own (the caller's locks: a thread that waits for one of them would wait with it) calls this between its writes:
 * while the journal is at factor x journal_max_bytes or more, it wakes the flusher and waits until the journal was switched or a checkpoint ended (one that failed too), and returns
 * the microseconds it waited (0: no wait).  The bulk writer (the reconcile thread of a pass) uses 2, the thread that also answers lookups 4: the journal stays below 2 x
 * journal_max_bytes while the disk keeps up with the checkpoints, and below 4 x in any case (store.journal.limit_waits counts the waits).  The store's own calls never wait for it. */
uint64_t store_journal_wait(store_t *s, unsigned factor);
/* the time-driven part: the commit and the checkpoint that are due (the flusher thread makes them by itself; without it the tick does), and (0.7 WP9) the work of the
 * background: the cleaner (at opts.compact_rate), the removal of the segments it emptied, the nx pass, the free-space check, the scrub (at opts.scrub_rate).  Call about once per
 * second from the store's thread, which is not inside a read section; a call takes up to about 300 ms when there is work. */
int  store_tick(store_t *s);
/* start a new journal, flush the files, write the other superblock copy with the checkpoint LSN, remove what no superblock names any more (design 3.4 with a journal).
 * The flush runs without the writer mutex (a fuzzy checkpoint: see the top of dns_store.c); the call returns when the superblock is on disk. */
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

/* ---- 0.7 WP9: the cleaner, the scrub (design 3.2, 2.4) ---- */
/* The cleaner moves the live records of the segments that are mostly dead into the open segment (the journal makes each move one record: a crash leaves the old or the new location,
 * never both, never none) and then removes the empty segments.  It runs by itself from store_tick() (low priority, a bounded rate: opts.compact_rate); this call runs it now.
 * It also gives back the space of long names that were deleted (nx).  A segment is removed only when (a) a checkpoint after the last move is on disk, (b) every reader that could
 * still hold the old location has left its read section, and (c) no image that was read from it is held (MAP mode: store_img_release() not called yet): the segment is "pinned"
 * until then; in COPY mode nothing points into a segment.
 * max_bytes: stop after that many bytes were moved (0 = no limit).  finish: also make the checkpoint and remove the segments that are empty now (otherwise that happens at the
 * next checkpoint and tick).  Returns 0 or a negative errno; *rep (optional) says what happened. */
int  store_compact(store_t *s, uint64_t max_bytes, bool finish, store_compact_report_t *rep);
/* The scrub (design 2.4): every zone record is read; table record (CRC), index reachability, and for a stored zone the image (checksum, and opts.validate's structure check).
 * A bad image makes its zone KNOWN, so that it is read from the database again; damaged table records and index entries that do not lead to their zone are repaired
 * by store_repair() at the end of the pass.  store_scrub_run() does a whole pass now (no rate limit; blocks); the tick starts one by itself every opts.scrub_interval_s and runs it
 * in slices at opts.scrub_rate.  start / stop: for the operator (karictl store scrub). */
int  store_scrub_run(store_t *s, store_scrub_report_t *rep);
/* The operator's "clean now" (karictl store compact): the tick runs the cleaner without its rate limit until no segment is dead enough, then makes the checkpoint and removes the empty
 * segments.  Returns at once. */
void store_compact_request(store_t *s);
void store_scrub_start(store_t *s);
void store_scrub_stop(store_t *s);

/* ---- 0.7 S6: the error ring and the NOTIFY-due scan (design 6.6, 6.7) ---- */
/* `err.ring`: the last STORE_ERR_ENTRIES texts of zones that were refused or failed (rejection of a body, a failed install, ...), a fixed file of 14 MB (sparse until it is used) that
 * is written in place and wrapped; it is not journaled (a crash may lose the last entries) and it never holds the Backend's heap.  An entry says which zone id, which version stamp,
 * when, and why.  A zone id is reused after a delete: the caller checks the name (store_zone_get()) and the stamp before it shows a text.  Any thread may put and get. */
#define STORE_ERR_ENTRIES 65536u
#define STORE_ERR_TEXT    192            /* bytes of a text, the NUL included; longer texts are cut */
typedef struct store_err {
  uint64_t seq;                          /* 1, 2, 3 ... in the order they were put */
  uint32_t zid;
  uint32_t tag;                          /* 24 bits the caller chose (a hash of the zone's name): a zone id is reused after a delete, and the caller compares the tag before it shows the text */
  uint64_t stamp_gen;
  uint64_t time;                         /* unix time */
  char     text[STORE_ERR_TEXT];
} store_err_t;
int  store_err_put(store_t *s, uint32_t zid, uint32_t tag, uint64_t stamp_gen, const char *text);
/* the newest entry of the zone id that is still in the ring: 0, or -ENOENT (none, or it was overwritten).  O(1): a table of the zone ids that have an entry (made from the ring at the open), no scan;
 * the ring's own mutex is the only lock it takes, so the caller may hold any other.  A delete of the zone id forgets its text (store_delete()). */
int  store_err_get(const store_t *s, uint32_t zid, store_err_t *out);
/* forget the zone's text (a version of the zone was registered): a later store_err_get() of the zone id says -ENOENT until a new text is put (a record with an empty text hides the older ones) */
int  store_err_clear(store_t *s, uint32_t zid);
/* how many entries were ever put (the ring holds the last STORE_ERR_ENTRIES of them) */
uint64_t store_err_total(const store_t *s);
/* Next zone (by zid, from *cursor, which starts at 0) that has `flag` set in zt.flags, e.g. STORE_F_NOTIFY_DUE: 1 and *out filled, 0 at the end, -EBADMSG for a damaged record as
 * store_iter().  The flag itself is set and cleared with store_set_flags() (journaled: a NOTIFY that was due at a crash is due after the restart). */
int  store_flag_next(const store_t *s, uint32_t *cursor, uint16_t flag, store_zone_t *out);

/* ---- statistics, verification ---- */
void store_stats(const store_t *s, store_stats_t *out);                 /* O(views), no lock */
int  store_seg_info(const store_t *s, uint32_t num, store_seg_info_t *out);  /* num 1..seg_count */
/* Page-cache residency estimate: mincore() on up to `pages` random pages of the appended part of the segments (MAP mode; -ENOTSUP in
 * COPY mode, -errno when mincore() is refused, e.g. in a sandbox).  *sampled pages looked at, *resident of them in memory.  Bounded, no lock. */
int  store_resident_sample(const store_t *s, unsigned pages, uint64_t seed, uint64_t *sampled, uint64_t *resident);
/* 0.7 fix 7: are all pages of the stored image of this record in the page cache (mincore() on the record's range)?  MAP mode only; false in COPY mode, for a segment that is not open, or when the
 * record is too big to look at.  No lock, no open, no read: a worker may call it. */
bool store_image_resident(const store_t *s, const store_zone_t *z);
/* 0.7 fix 7: open (map) every segment now; store_image_resident() says no for a segment that is not open */
void store_open_segments(const store_t *s);
/* 0.7 fix 8: hot.list.  store_hot_write(): the zone ids (the most used first, at most STORE_HOT_MAX) are written to hot.list of the store's directory (not trusted by a reader until complete).
 * store_hot_read(): the list of this store (the uuid must be its own, the checksums right), malloc'ed, *n may be 0; -ENOENT when there is none, -EBADMSG when it is not trusted. */
#define STORE_HOT_MAX (4u << 20)
int  store_hot_write(store_t *s, const uint32_t *zids, size_t n);
int  store_hot_read(const store_t *s, uint32_t **zids, size_t *n);
/* Full consistency check (O(zones), takes the writer mutex): every record valid, every zone reachable through ix / sx, counters
 * and live bytes equal the recount, the free list intact, no duplicate names.  For tests, `karictl store verify`, the scrub. */
int  store_check(store_t *s, store_check_report_t *rep);

/* ---- test support ---- */
/* in every build (0 / NULL = off): called by a checkpoint after each of its steps outside the writer mutex (1: the journal was switched, 2: the journal before the switch is durable,
 * 3: the tables are written, 4: the superblock is written, 5: after each run of table pages written), and by a growth of the index built outside the mutex (1: the bigger index is built, 2: it was put in); tests make a step slow, or kill the process there */
extern void (*_Atomic store_test_ckpt_hook)(int step);
extern void (*_Atomic store_test_regrow_hook)(int step);
/* ... and by a commit (0.7): 1: the journal was switched to the file made ahead (writer mutex held), 2: the file before is synced (not closed yet), 3: the next file is made ahead */
extern void (*_Atomic store_test_commit_hook)(int step);
/* ... and by store_put() after it wrote the record before the writer mutex (no lock held but the writers of images'): a test changes the zone there */
extern void (*_Atomic store_test_prewrite_hook)(store_t *s);
/* the stores opened while this is set start no flusher thread (the writers make the due commits and checkpoints after the mutex) */
extern _Atomic bool store_test_no_flusher;
#ifdef KARIDNS_UNIT_TEST
/* SIGKILL the process at the n-th crash point (0 = off); the points lie between every step of a write sequence (in every thread of the store) */
extern _Atomic long store_test_crash_countdown;
/* called by the writer between the ops of a journal record that publish a zone (cells, indexes) and the counters op of the same record: the window in which a reader can see a new zone before the counters of its segment (0 = off) */
extern void (*store_test_before_counters)(store_t *s);
/* a commit fails with -EIO at the n-th one (0 = off): a failed fdatasync */
extern _Atomic long store_test_fail_commit;
/* the n-th write of a run of table pages by a checkpoint fails with -EIO (0 = off) */
extern _Atomic long store_test_fail_ckwrite;
/* the bytes of the table files (zt, zc, nx, the current ix and sx) equal the memory of the store: true after a checkpoint with the writers kept out (store_checkpoint_clean()) */
bool store_test_files_match(store_t *s);
/* a word (byte offset off, a multiple of 8) of the memory of a table: 0 zt, 1 zc, 2 nx, 3 the current ix, 4 the current sx (the tables are private memory since 0.7: a test that damages a cell
 * does it here, not in the file); poke marks it for the next checkpoint */
uint64_t store_test_peek(store_t *s, int which, uint64_t off);
void store_test_poke(store_t *s, int which, uint64_t off, uint64_t v);
/* a writer (store_put, store_set_known, store_delete, store_set_flags, store_set_stamp, store_set_cursor; `op` is its name without the store_ prefix) returns the errno this returns (not 0) before it changes anything: a full disk, an I/O error (NULL = off) */
extern int (*store_test_write_fault)(const char *op, uint32_t zid);
/* called by store_stats() after it has read the index generation (the window in which a writer may retire it) */
extern void (*store_test_in_stats)(void);
/* the free bytes of the store's file system, as the test wants them (a negative value = ask the file system) */
extern int64_t (*store_test_fs_free)(void);
/* an append of an image record fails with the errno this returns (not 0) before it writes anything: the disk fills up between the free-space check and the write */
extern int (*store_test_append_fault)(uint64_t reclen);
/* called at the start of every slice of the cleaner (writer mutex held) with the segment it is emptying: a test takes a reference of an image there (store_image_read does not need the mutex) */
extern void (*store_test_cleaner_step)(store_t *s, uint32_t victim);
/* called by the read-ahead thread before every page it reads (NULL = off): a test makes the read-ahead slow, and shows that store_close() waits for it */
extern void (*store_test_ra_page)(void);
uint64_t store_test_siphash(unsigned c, unsigned d, const uint8_t key[16], const uint8_t *in, size_t len);
uint32_t store_test_crc32c(uint32_t crc, const void *p, size_t n);
uint64_t store_test_sum64(const void *p, size_t n);
/* path of a store file (for damage tests), written into buf */
#endif

#endif /* DNS_STORE_H */

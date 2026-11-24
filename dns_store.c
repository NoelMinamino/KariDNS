/*
 * dns_store.c - the zone store (see dns_store.h for the interface and the rules for callers).
 *
 * ======================================================================================================================
 * THE REDO JOURNAL (user decision D5, design 3.4 adapted)
 * ======================================================================================================================
 *
 * What is mapped and what is logged.  zt, zc, nx (grow in place), ix, sx (replaced by a new generation file) and the
 * superblock's counters (the flat array v[]: free list, high-water mark, per-view / per-segment counters, ...) are changed
 * *in place* in memory (the tables: private memory, written to their files by the checkpoint, see "The tables in private memory" below).  Segments are append-only and are not logged:
 * their bytes are written first.
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
 * The group record (0.7 M2, store_set_known_n()).  One call may carry up to STORE_GROUP_MAX (32; 64 before the writer-hold fixes of 0.7) entries (the first fill: the manifest pass lists millions of zones, and a record, a write() and a mutex round per zone
 * was most of the cost).  The record is the same record: the ops of the entries one after the other (NX, ZREC, SX, IX per entry, in the order a lock-free reader is safe with), then ONE OP_V
 * with the counters as absolute values at the end of the group.  No new op, no new version of the format: an older server replays it as it replays any record, and a newer one replays an older
 * journal as before.  The group is the unit of the CRC, so a record that is torn (kill -9 or power loss in the write) is dropped whole at the replay: none of its entries is there, and the loader's
 * cursor, which is made durable only after the entries it covers, has not passed them.  The entries of a group are planned against the state before the group (no cell is written until the record is
 * in the kernel), so a group never holds two entries that touch one name or one source id, and the slots an entry has claimed in the index are skipped by the entries after it (see kn_chunk_t).
 *
 * Durability / group commit.  fsync is not issued per call: store_commit() (a batch end), the policy
 * (sync_interval_ms, default 100 ms), a checkpoint and close do
 *     fsync(segments written since the last commit)   -- an image is durable before ...
 *     fsync(journal)                                  -- ... the record that points at it
 * so after power loss the journal prefix that was synced is complete and only points at durable images.
 *
 * fsync(), never fdatasync() (0.7, measured on FreeBSD 15.1 UFS with soft updates, in a bhyve guest with the power cut by bhyvectl --destroy): fdatasync() of a file that grew by an append,
 * or of a new file whose only write was its first, is not durable there, fsync() is (planning: 2026-11-19_first_fill_ab/vps, fdtest).  With fdatasync the superblocks of a store that was cut
 * within 30 s of its first start were 0 bytes (the whole store lost), the tail of the journal was lost, and thousands of changed zones were damaged.  fsync() costs the same on ZFS (the ZIL
 * is written for both).  A new file is durable only with its directory entry: the directory is fsynced after files are created (dir_dirty, create_store(), a checkpoint).
 *
 * No I/O wait inside the writer mutex (0.7 fix A).  At 10M zones a checkpoint's msync of the tables took 1.5 to 25 s and a growth of the index
 * 6 s, all of it inside the writer mutex, and the threads that wait for the mutex hold the record mutex of the Backend meanwhile.  Now:
 *   - A commit takes, under the mutex, the LSN it covers, the segments marked dirty (the marks are cleared) and the journal's fd; it syncs them
 *     with the mutex released, then publishes committed_lsn.  Commits are serialised by the "I/O baton" (io_busy, a flag under bg_mu that is
 *     taken without the writer mutex, or tried with it: never waited for while it is held), so a later commit never publishes past an earlier
 *     one's segments.  A failed sync marks the segments dirty again.  The periodic commit is the flusher thread's; STORE_SYNC_EVERY syncs after
 *     the mutex is released, before the call returns; store_commit() waits for a commit that covers its LSN.
 *   - A checkpoint is fuzzy: under the mutex only its position P (= the last LSN), a copy of the superblock as of P, and the switch to the next
 *     journal file (pre-created, so the switch is a 64-byte pwrite of its header) are taken.  Then, with the mutex released, the journal up to P
 *     and the segments are synced (the baton is given back after this), the tables are written and the superblock (checkpoint LSN P, the
 *     journal after the switch) is written.  Writers go on meanwhile, so the written tables hold every effect of the records <= P and maybe some
 *     of the records > P.  That is what a replay from P is made for: every op is an absolute value ("cell X = V", "slot = value", "counter =
 *     value", the bytes of a name), so a location that a record > P wrote ends with the value of the last such record whatever it held before,
 *     and a location that no record > P wrote holds its value of P (a checkpoint only writes pages that the records before it changed); the
 *     counters of the superblock are those of P, and every record after P carries the absolute value of every counter it changes.  Same boot
 *     (kill -9): the page cache holds every page the checkpoints wrote, the replay is exact.  Power loss: pages of records > P that are not in the
 *     durable journal may be on disk (a checkpoint's copy is taken after P); the open rebuilds the derived tables then, as before (a
 *     cell whose bytes are damaged fails its CRC and is dropped by the rebuild: the zone is fetched again; a pair is never torn by the copy, ck_write_cells()).
 *     One checkpoint at a time (ck_busy); the ix / sx generations and segments it writes or syncs are kept from being freed by io_hold.  A close
 *     leaves a fuzzy checkpoint between two runs of its write (its clean checkpoint writes everything), and the journal is bounded by
 *     2 x journal_max_bytes: the bulk writer waits between its calls, with no lock held, while the journal is at that bound (store_journal_wait()).
 *   - A checkpoint with the clean flag (store_checkpoint_clean(), close), the first one of an open and the one of a repair keep the writers out
 *     for the whole time: the clean flag must name a state that no record follows.  A writer that finds the clean flag on disk writes a
 *     superblock without it first (nothing changed since: no flush), outside any hold of the writer mutex that it cannot give up.
 *   - A growth of ix / sx is built outside the mutex (see rg_* below), and its OP_GEN record is written under the mutex once the bigger index
 *     is up to date.
 *   - No append inside the mutex meets a sync of its file (0.7, the 10M first fill): on UFS kern_fsync() holds the file's vnode lock for the whole sync, and the append of a
 *     record (pwrite() of the journal) or of an image (into the open segment) waited for it, 0.1 to 1.4 s under load.  A commit switches the journal to the next file and syncs
 *     the one before (st_commit_ex()); a fuzzy checkpoint gets the file its superblock names synced the same way; store_put() writes the image before the mutex (st_prewrite()).
 *     What is left in the mutex: the pwrite() of a record still meets the file system's own back-pressure (UFS runningbufspace, the ZFS write throttle).
 *   - No store into a table meets the write of its page (0.7, the tables in private memory, below).
 *   - No allocation of the file system is waited for by the commit thread or inside the writer mutex (0.7 round 15): the blocks ahead of the tables are allocated by a thread of its own (fl_tab_main()), and
 *     the file of the next segment is made by another (seg_pre_make(), with the argument that its directory entry is durable before a record names it), seg_place() only takes it.
 *
 * The tables in private memory (0.7).  With shared mappings of the table files a store into a page of zt / zc / nx / ix / sx (apply_ops(), inside the mutex) waited while the kernel
 * wrote that page out (a checkpoint's msync, the syncer: vm_fault_busy_sleep, holds of up to 2.7 s at 10M zones), and the earlier msync(MS_SYNC) held a table's vnode lock for its
 * whole flush (a growth's posix_fallocate() waited for it: holds of 10 to 24 s).  Now nothing but a checkpoint writes the table files, and never from the pages the writers use:
 *   - The data a file holds at the open is mapped MAP_PRIVATE (a page is read from the file at its first touch and stays shared with the page cache until a writer changes it, then
 *     the process has its own copy); a growth maps anonymous memory; a generation made in this session (a growth of ix / sx, a rebuild) is anonymous memory.
 *   - The writers mark the pages they change (dmap_t, one bit per page, under the mutex).  The begin of a checkpoint (under the mutex) takes the bitmaps of P and gives the writers
 *     empty ones; then, with no lock, each run of marked pages is copied with word loads into a buffer and pwrite()n to the file, the file is extended to the size of P and
 *     synced (ck_write_tab(); zt and zc in lockstep, run by run over the same cells, and every cell pair under its sequence counter: ck_write_cells()).  The page cache page that the kernel
 *     writes out is never the page a writer stores into.  A checkpoint that fails or is left gives its pages back.
 *     The granule is the page: a larger one would write pages still shared with the page cache, and a writer's first store into one (a copy-on-write fault) would wait for it.
 *   - The copy is taken after P while the writers go on: what it holds of records > P is made right by the replay from P, as for the fuzzy flush above; a page that no record
 *     between the last two begins changed was written by the checkpoint before (one at a time) with its value of P.
 *   - A replayed OP_GEN: the new generation's file holds what a checkpoint wrote, nothing when none followed the growth, so the open rebuilds the derived tables then (gen_replays).
 *   - The private pages (dmap_t.priv: written since the open) are memory the kernel cannot drop: store.tables.private_bytes, counted in memory-limit by the Backend.
 *
 * Checkpoint (store_checkpoint(), by the journal size limit, by checkpoint_interval_ms, at close, after recovery).
 *     switch to the next journal file; commit up to P; write + fsync the changed pages of every table; fsync the new journal and the directory;
 *     write the *other* superblock copy (seq+1, checkpoint LSN = P, names the new journal gen and the ix / sx generations of P, counters,
 *     views, cursors, CRC-32C); fsync it; delete journals / generations that neither superblock copy names any more.  The older copy plus
 *     the journals it names stays valid, so a damaged newer copy costs nothing: the open uses the older one and replays the longer journal
 *     chain.  Growth of ix / sx (a new generation file) is bridged by an OP_GEN record in the journal chain: a replay from a checkpoint before
 *     it applies the records before it to the old generation and switches to the new one; since the tables are private memory (0.7) that file may
 *     hold nothing yet, and the open rebuilds the derived tables.
 *
 * Recovery at open.  Take the newer valid superblock copy whose files check out against fstat sizes; read the journal files
 * from the gen it names (and the ones after, while their base LSN continues); apply every record with LSN > checkpoint LSN
 * in order; stop at the first record that is torn, CRC-bad or out of sequence (kill -9 in the middle of a write).  Then a
 * new checkpoint starts the session (the clean flag is cleared durably before the first modification).  Same boot after
 * kill -9: this is exact, the page cache kept every page the checkpoints wrote, cost = replay (about 1 s per 3M records).
 * Power loss / OS crash (different boot id, no clean flag): table pages may have reached the disk *ahead of* the journal
 * (a checkpoint's copy is taken after its position), so after the replay the derived tables are rebuilt by one sequential
 * pass over zt (drop records with a bad CRC or impossible fields, drop duplicate names, rebuild ix, sx, the free list,
 * counters, live bytes); an image whose bytes did not reach the disk fails its checksum at the first read and the zone goes
 * back to KNOWN in the caller (design 3.4 item 4).  The rebuild is also the repair path whenever the replay meets something
 * it cannot apply.
 *
 * Bounded size: a checkpoint is forced when the journal reaches journal_max_bytes (default 100 MiB: a replay of that is about a second
 * warm), so the journal never grows without limit and the replay after a crash is bounded (by that and what is written while one
 * checkpoint flushes: the writer that finds the journal full switches it at once when no other checkpoint runs; and never by more than twice
 * the limit while the callers wait in store_journal_wait()).  While a first fill runs the limit is 4 x as much when the free space allows (jmax(), store_journal_boost()).
 *
 * ======================================================================================================================
 * 0.7 WP9 (S6): the cleaner, disk full, the scrub, nx
 * ======================================================================================================================
 *
 * The cleaner (design 3.2).  A segment whose records are mostly dead (replaced or deleted zones) is cleaned: its live records are copied,
 * byte for byte, to the open segment and each zone's zt cell gets the new location.  One move = one journal record (the appended bytes
 * are written and, at the commit, fsynced before the record is; the record carries the whole new cell and the counters), so after
 * kill -9 or a power loss a zone's record is either at the old or at the new place, never missing and never in two places that the
 * zone's cell names.  The old segment is removed only when
 *     (a) it has no live record left (the counters say so), and it is not the open segment,
 *     (b) a checkpoint that follows the last journal record of the move is on disk (a replay never starts before it, so it cannot want the file),
 *     (c) the grace period of the readers has passed (a reader that read the old location before the move is done), and
 *     (d) no image that was read from it is held (MAP mode: the reference count of the segment; an attached zone's image points into it).
 * Removing = a journal record that zeroes the segment's counters ("used = 0" is what a free segment number is: the number is used again by
 * the next new segment), then unlinkat().  A crash between the two leaves a file nobody names (the next creation truncates it), or a
 * segment with counters and no file (removed again by the next tick).  COPY mode (the ZFS default) has no pointers into segments, so (c) is
 * all there is.  The cleaner works on one segment at a time, from the one with the least live share, at most opts.compact_rate bytes a second, and takes
 * the writer mutex per record (so the writers interleave).  A live record that fails its checksum is not copied: its zone becomes KNOWN.
 *
 * Space.  The file system's free bytes are read (fstatfs) at every checkpoint, after every megabyte appended and once a second while
 * writes happen.  Ordinary appends refuse (-ENOSPC) when fewer than opts.reserve_bytes are free: that room is the cleaner's (it needs the
 * live bytes of a segment to free the whole segment; the design's "one empty segment in reserve").  An append that fails (the reserve, or
 * a real ENOSPC / EFBIG / EDQUOT) runs the cleaner at once and tries again; if that does not help the store is degraded (design 3.5):
 * store_put() keeps the zone's new stamp as a record without an image (KNOWN: its old image is released) and returns 0, and the server answers
 * the zone from memory / the database as it does for any zone that has no image; ERROR once a minute names the numbers; a successful append
 * (the space came back) ends it.  A zone that needs a new table record when the tables cannot grow is refused (-ENOSPC) and the caller does
 * not advance its cursor.  At every checkpoint a WARNING says when the file system is getting full: the store's size against the free space,
 * and the time to full at the growth of the last hour.
 *
 * nx.  The names of zones longer than ST_NAME_INL are kept in nx, appended; a deleted zone leaves a hole (nx_dead).  When the holes are
 * more than half of nx the names are moved down in place, in the order of their offsets, under the writer mutex: each move is one journal
 * op (new offset, the bytes, the whole new cell) that is applied under the cell's sequence counter, so a reader of that zone retries
 * and never sees half a name; the bytes of nx are only touched through 64-bit words (relaxed atomics) for the same reason.
 *
 * The scrub (design 2.4).  Every zone record is read: the cell (CRC), the way ix / sx lead to it, and for a stored zone the image
 * (checksum64, then opts.validate: zone_image_validate()).  A bad image: the zone becomes KNOWN.  A bad cell or an index that does not lead to its
 * zone: store_repair() at the end of the pass.  A pass starts every opts.scrub_interval_s (the time of the last one is in the superblock)
 * and runs in slices at opts.scrub_rate.
 *
 * Start (design 7).  The open reads ix once from the beginning (the first lookup does not wait for the disk), then a thread reads zt in the
 * background; both times are in the statistics.  On ZFS the open reads st_blksize of a table file (the dataset's recordsize) and warns above 32 KiB.
 *
 * Deliberate limits: store-copy-max (a big zone mapped instead of copied in COPY mode) is not done; an index that fills up to one half before
 * its build outside the mutex ended is grown inside it (as before 0.7 fix A); store_repair() and the nx pass block the writer (rarely: only
 * when more than half of nx is dead).
 *
 * ======================================================================================================================
 * THE BULK FILL (0.7, planing_0.7.x_first_fill_writes.md)
 * ======================================================================================================================
 *
 * The first fill of an empty store is read from the database, which stays the source of every zone: a fill that a crash cuts off can be read again.  Its journal (5 GB at 10M zones), the
 * checkpoints that cut it (every 100 MiB, each rewriting the reserved index) and the fsyncs of its commits (on ZFS each one writes its data twice, through the ZIL) were most of what the fill wrote
 * to the device; only the images must reach it.  So the fill of a store that holds no zone record is unlogged:
 *   B  begin (store_bulk_begin(), db_recon_begin() when it reserves for a store with no zone record and no segment bytes, and the configuration has no secondary whose copy the store keeps): a checkpoint with the writers kept out makes a superblock with SBF_BULK durable, then the flag is
 *      set in memory (it is set before the checkpoint, under the writer mutex: no writer runs until that superblock is on disk).  The reserve of the tables and the index comes after it, so its
 *      generation is not written by this checkpoint.  This superblock is "the start of the fill": exact, with its ix / sx.
 *   U  while BULK: every writer (the reconcile, the ingest of bodies, a secondary's transfer, store_repair(), a growth's publish) plans and applies its ops and marks its pages as before, but
 *      journal_reserve_locked() writes no record and gives no LSN.  So nothing is committed (committed_lsn stays at the LSN of the begin), no journal file is switched by a commit, the journal does not
 *      grow (no checkpoint by its size, store_journal_wait() never waits) and checkpoint_interval_ms is not looked at (ckpt_due()).  The segments are appended as before; they are synced by the
 *      checkpoints.  The cleaner, the removal of empty segments, the nx pass and the scrub do not run until the end is on disk (st_bulk_busy(): maintenance(); store_compact() and store_scrub_run() say -EBUSY), nor the emergency cleaning
 *      of a full disk: the store was empty (no segment bytes either), nothing is dead; a segment removed then would be one the cells of the on-disk bulk checkpoint still name.  The readers are
 *      unchanged: the tables in memory are the truth.  A writer that is not the fill (a secondary's copy, dns_xfr_store.c) asks for the end and puts its write off until the end is on disk (the restore thread makes it then).
 *   C  bulk checkpoints (store_bulk_phase(BODY / PASSED): none while a pass runs): a fuzzy checkpoint begun while BULK (ck_begin_locked(), ck.bulk) when the segments doubled since the last one and
 *      grew by at least opts.bulk_ckpt_bytes (4 GiB), or when opts.bulk_ckpt_interval_ms (15 min) passed and they grew (bulk_due()).  Its steps are those of any fuzzy checkpoint: the commit of its
 *      position P syncs the segments marked dirty and the directory (the files of new segments are in it before a superblock names them), zt and zc are copied as of P (and later; pair by pair under the cells' sequence counters, ck_write_cells(), so no pair is torn), nx by the nx rule
 *      (ck_nx_widen()); ix and sx are not written (their pages stay marked; a generation made during the fill is written whole at its end).  Its superblock says SBF_BULK | SBF_BULK_CK: the open
 *      does not read ix / sx from it (adopt_sb()) and rebuilds them from zt.  P names no record: the counters, views and cursors are those of the begin (under the mutex), the tables those of the copy.
 *   K  a crash during the fill (the open finds SBF_BULK without the clean flag): nothing is replayed (journal_skip(): the chain is passed over so that the next journal file is a new one; the records
 *      made after the end of the fill and before its checkpoint was on disk are lost with it); the derived tables are rebuilt with the bulk rules (rebuild_locked(RB_BULK); also after the
 *      superblock of the start: a bulk checkpoint that did not reach its superblock may have written pages of the tables, which no replay makes right): a cell that is damaged fails its CRC and is dropped (the copy never tears a pair); a STORED cell whose image is past the durable end of its segment (the counters of the superblock: the segments were synced to at least
 *      there before the tables) becomes KNOWN with its name, source id and stamp, so that it is fetched again rather than lost; a long name is taken only when it is the one whose start the cell holds and it has no zero byte, which no writer stores (st_name_text_ok(), check_name_args()).
 *      Segment files past the counters are files nobody names (the next creation of the number truncates them).  The caller drops the loader's cursors of its views (a bulk checkpoint may hold a
 *      cursor whose zones a dropped cell had): the next pass lists every zone again; SBF_BULK_CUT keeps that on disk until the caller did it (store_bulk_cut_done(), also across a start with no
 *      database block).  The open's own checkpoint says BULK again, so the rest of the fill stays unlogged.  The WARNING says when the
 *      store is back to and how many zones it holds.
 *   S  a clean stop (store_close(), store_checkpoint_clean()) during the fill writes a full clean checkpoint that keeps SBF_BULK (and SBF_BULK_PASSED): the state is exact, the next open needs no
 *      rebuild and goes on with the fill.  The first writer after a clean checkpoint clears the flag on disk before its first unlogged change (wr_lock()), as for a logged one: a clean flag after
 *      which an unlogged change was made would make the open trust tables that do not hold it.
 *   E  the end (store_bulk_end(), the caller's ticker after the passes of every view ended complete, when no body is in flight and the scan of the wanted bodies went idle: bulk_end_check()): the flag
 *      goes under the writer mutex and bulk_end_pending is set, so every later
 *      record is logged with an LSN after P; then one ordinary fuzzy checkpoint at P: every unlogged change is before P and its copy is taken after it, which is the rule of every fuzzy checkpoint
 *      (records after P are replayed onto it); it writes every page marked since the last full write, ix / sx included (taken from the writers' maps, which no bulk checkpoint took), and its
 *      superblock has no SBF_BULK (ck_finish() clears bulk_end_pending).  The checkpoint thread makes it (ckpt_due() is true while the end is pending, after a failure or with no room for it once its back-off is over, 1 s doubling up to 5 min, in st_ckpt(); the
 *      caller's thread does not wait for it).  Until it is on disk a crash is a crash of the fill (K): the commits acknowledged since the end are lost with it, the cost of decision 1 of the plan.
 * What relied on the journal, and what the fill does there:
 *   - OP_GEN (a growth of ix / sx): written unlogged; the generations are not durable during the fill (C), the superblock of the next bulk checkpoint marks them for the rebuild.
 *   - OP_SRC (the loader's cursors): applied in memory, durable in the superblock of the next checkpoint (as of its begin, with the tables copied after it), dropped by the caller after a crash (K).
 *   - OP_REBUILD (store_repair()'s marker): unlogged; the repair ends with a checkpoint with the writers kept out, which is exact; a crash before it goes back to the last checkpoint (K).
 *   - the clean flag on disk and unclean_now_locked(): as before (S); the superblock it writes keeps SBF_BULK (it follows a full checkpoint: ix / sx are valid).
 *   - jr_floor() and the space guard: no room for the journal is needed (jr_space_locked() is not asked); the appends keep their check (the reserve and the floor of a running checkpoint).
 *   - degradation on ENOSPC: the same rules (put_stored_locked(): the zone is KNOWN), without the emergency cleaning.
 *   - the replay at open: none after a cut-off fill (K), the usual one after a clean stop during it (the journal holds nothing after a clean checkpoint).
 *   - the segment made ahead (rule F / N4 of seg_pre_make()): no journal record names a segment during the fill; the directory entry is synced by the commit of the checkpoint whose superblock
 *     first counts the segment.  seg_free_lsn <= committed_lsn: the cleaner does not free numbers during the fill, and the numbers freed before it were durable at its begin (B is a checkpoint).
 *   - retire_run(): by io_hold and the grace period, not by the journal: unchanged.
 *   - the cleaner's (b) ("a checkpoint after the last record of the move is on disk"): LSNs do not move during the fill, so it would hold at once; the cleaner does not run (U).
 *   - store_journal_boost() is the fallback for a pass over a store that is not empty: the caller does not raise it for a bulk fill (it has no journal).
 *   - the nx rule (ck_nx_widen()) is kept by every fuzzy checkpoint, not only by bulk ones: after a power loss the cells past the durable journal are rebuilt from the tables too (rebuild_locked(RB_OPEN)).
 *
 * Journal ops (typed, each a TLV {u16 type, u16 0, u32 payload length}):
 *   ZREC zid + zt[64] + zc[64] | NX offset + bytes | IX / SX count x {slot, value} | V count x {field id, value}
 *   VIEW id + name | SRC source + cursor + identity | GEN which, generation, slots | NXMOVE zid, new offset, name bytes, zt[64], zc[64]
 */

#include "dns_store.h"
#include "dns_epoch_rcu.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
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
#define ST_NAME_MAX_B   256u              /* a name buffer */
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
#define ST_CL_CHUNK     (1u << 20)        /* the cleaner and the scrub read segments in pieces of this size (COPY mode) */
#define ST_CL_SLICE_MS  200u              /* the longest the cleaner keeps working in one tick */
#define ST_SCRUB_SLICE_MS 100u
#define ST_GRING        128               /* samples of the store's size (one a minute): the growth of the last hours */

/* flat counter array v[] (superblock + journal "V" ops) */
enum {
  V_HWM = 0, V_FREE_HEAD, V_FREE_COUNT, V_NX_USED, V_NX_DEAD, V_IX_USED, V_IX_LIVE, V_SX_USED, V_SX_LIVE,
  V_NSEGS, V_CUR_SEG, V_KNOWN, V_STORED, V_REJECTED, V_IMG_BYTES, V_NONSTORE,
  V_GLOBAL_END = 32
};
#define V_VIEW(view, k)   (32u + (view) * 8u + (k))             /* k: 0 known, 1 stored, 2 rejected, 3 image bytes */
#define V_DEPTH(view, d)  (32u + 256u + (view) * 64u + (d))
#define V_SEG(n, k)       (32u + 256u + 2048u + 2u * (n) + (k))  /* k: 0 used, 1 live */
#define ST_NV             4400u

/* journal op types */
enum { OP_ZREC = 1, OP_NX, OP_IX, OP_SX, OP_V, OP_VIEW, OP_SRC, OP_GEN, OP_REBUILD, OP_NXMOVE };

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
#define SBF_BULK 2u                       /* a bulk fill is going on: the journal holds nothing of it (THE BULK FILL) */
#define SBF_BULK_CK 4u                    /* a bulk checkpoint: a fuzzy copy without a journal and without ix / sx: the open rebuilds the derived tables */
#define SBF_BULK_PASSED 8u                /* the passes of the bulk fill ended complete (store_bulk_phase()) */
#define SBF_BULK_CUT 16u                  /* a bulk fill was cut off and the caller has not dropped the loader's cursors yet (store_bulk_cut()): kept with or without SBF_BULK */
#define ST_BULK_BYTES (4ull << 30)        /* the segments grew by at least this much since the last bulk checkpoint (and doubled) */
#define ST_BULK_IVL_MS 900000u            /* ... or this long passed since it */

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

/* The pages of a table that the writers changed (0.7, private tables: see "The tables in private memory" at the top).  Owned by the writer mutex (the build of a generation outside
 * it writes a generation that is written whole, `all`).  dirty: pages changed since the begin of the last checkpoint, which takes the bitmap; priv: pages changed since the open, the
 * private copies that store.tables.private_bytes counts (acct, the store's counter: a generation retired by the readers' grace period subtracts its own when it is freed). */
typedef struct {
  uint64_t *dirty, *priv;
  uint64_t npages, npriv;
  bool all;                            /* every page is to be written: a generation made in this session, until the begin of its first checkpoint */
  uint8_t shift;                       /* log2 of the page size */
  _Atomic uint64_t *acct;
} dmap_t;

typedef struct {                       /* a table that grows in place inside a reserved address range */
  int      fd;
  dmap_t   d;
  uint8_t *base;
  size_t   reserve;                    /* bytes of address space */
  _Atomic uint64_t mapped;             /* data bytes mapped (multiple of the page size) */
  _Atomic uint64_t extended;           /* data bytes the file is known to hold (allocated): a growth up to it is a mapping only (0.7 fix A: the flusher extends ahead, outside the writer mutex) */
  _Atomic bool no_alloc;               /* posix_fallocate() is not there (ZFS): nothing is allocated ahead */
} mtab_t;

typedef struct ixgen {                 /* one generation of ix or sx */
  int      fd;
  dmap_t   d;
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

/* A helper thread of the flusher (0.7, round 15): it waits on its own mutex and condition, which nobody holds across I/O, so the thread that asks (the commit thread, a writer inside the writer
 * mutex) never waits for the disk.  kick: work was asked for (coalesced); busy: the thread is in a round now (a kick that finds it set is counted: store.ahead.busy_kicks). */
typedef struct {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  bool kick, stop, busy;
} ahead_t;
enum { PRE_NONE = 0, PRE_BUSY, PRE_READY, PRE_STALE };    /* the segment made ahead (store_t.pre_state); STALE: made for a number that is not the lowest free one any more, the thread removes it */

typedef struct {                                      /* the holds of the writer mutex of 1 ms or more by one function (store.lock.site.*) */
  _Atomic(const char *) site;
  _Atomic uint64_t slow, over10, over100, slow_us, max_us;
} st_wl_site_t;
typedef struct retire {
  uint64_t epoch;
  ixgen_t *g;
  seg_t *sg;                           /* a segment that was removed: closed and unmapped after the grace period */
  struct retire *next;
} retire_t;

/* the journal ring (0.7) */
#define JR_CAP_DEF (64ull << 20)                 /* bytes of records that may wait for their write (D4: fixed; counted in memory-limit with the tables) */
#define JX_CAP 256u                              /* extents (one per journal file that has unwritten bytes) */
#define JW_RUN (4u << 20)                        /* the longest span one pwrite writes */
#define JR_ADMIT (1u << 20)                      /* a writer waits before the mutex while less than this is free in the ring */
#define JR_SLACK (8ull << 20)                    /* jr_floor(): spans in flight, a header, a probe interval of small records */
#define JR_ZFS_SLACK (16ull << 20)               /* jr_floor() on a copy-on-write file system: statfs lags behind the open transaction group */
#define ST_DEFER_SLOTS 32                        /* threads that defer at one time (the ingest and reconcile threads for good, one more inside the records lock at a time) */
enum { JW_OK = 0, JW_NOSPACE = 1, JW_FAILED = 2 };
typedef struct { uint64_t pos, foff; int fd; } jr_ext_t;    /* the ring's bytes from pos (to the next extent's pos) go to fd at foff.. */

#define JB_MAXV 96
/* An index change of a record, kept for a growth that is being built outside the mutex (rg_*): which index (0 ix, 1 sx), put or take out, the
 * hash and the zone id.  The bigger index is brought up to date with these, in their order, before it is put in. */
typedef struct { uint64_t h; uint32_t z; uint8_t which, ins; uint16_t pad; } rgent_t;
#define RG_LOG_MAX (8u << 20)                 /* index changes kept for one build (128 MiB): more drops it */
#define RG_CH_SHIFT 16                        /* the log is kept in chunks of 2^16 entries (1 MiB) */
#define RG_CH (1u << RG_CH_SHIFT)
#define RG_NCH (RG_LOG_MAX / RG_CH)
#define JB_MAXPL 208                      /* index ops of one record: three for each entry of a group of KN_MAX (STORE_GROUP_MAX, 32), with room */
typedef struct {
  uint8_t *p;
  size_t   len, cap;
  uint32_t nops;
  unsigned nv;
  struct { uint32_t fid; uint64_t val; } vs[JB_MAXV];
  unsigned npl;                           /* the index changes of the record (rgent_t), always noted: a growth may start while a group is being planned */
  rgent_t  pl[JB_MAXPL];
} jb_t;

struct store {
  int dirfd;
  store_opts_t o;
  int mode;
  char fstype[16];
  size_t pagesz;
  uint8_t pgshift;                      /* log2 of pagesz */
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
  _Atomic uint8_t seg_dirty[ST_MAXSEG + 1];           /* set by the writer after an append, cleared by the commit that takes the segment (and set again when its sync fails) */

  int jfd;
  uint64_t joff;                                      /* (the mutex) where the next record goes in the file jfd */
  _Atomic uint64_t jbytes;                            /* the bytes of the journal since the last checkpoint's switch (every file of the chain since: journal_max_bytes is about the replay) */
  _Atomic bool jboost;                                /* a bulk fill is going on (store_journal_boost()): the bound of the journal is JBOOST x journal_max_bytes while the free space allows (jmax()) */
  _Atomic uint64_t n_jboost;                          /* the times the bound was asked to be raised (0 -> 1) */
  /* ---- 0.7: the unlogged bulk fill (THE BULK FILL at the top; written under the writer mutex, read by the flusher) ---- */
  _Atomic bool bulk;                                  /* the writers append no journal record (store_bulk_begin() .. store_bulk_end()) */
  _Atomic bool bulk_body;                             /* no pass runs: bulk checkpoints may be made (bulk_due()) */
  _Atomic bool bulk_passed;                           /* a pass of the fill ended complete (SBF_BULK_PASSED) */
  _Atomic uint64_t bulk_base;                         /* the segment bytes at the begin of the last bulk checkpoint (or of the fill) */
  _Atomic uint64_t bulk_last_ms;                      /* ... and its time */
  _Atomic bool bulk_end_pending;                      /* the fill is over and no superblock without SBF_BULK is on disk yet (cleared by ck_finish()) */
  _Atomic bool bulk_cut;                              /* SBF_BULK_CUT */
  _Atomic uint64_t bulk_end_backoff_ms, bulk_end_next_ms;   /* the back-off of the checkpoint that ends a fill (st_ckpt()): 0 = none, try now */
  _Atomic int bulk_end_state;                         /* ... 0 trying, 1 it failed, 2 no room (the log line is said at a change) */
  _Atomic uint64_t n_bulk_fills, n_bulk_ckpts, n_bulk_unlogged, bulk_since, bulk_ended;
  _Atomic uint64_t lsn, committed_lsn;
  _Atomic bool dir_dirty;
  _Atomic uint64_t last_sync_ms, last_ckpt_ms;
  jb_t jb;
  /* ---- 0.7: the journal ring (the record is written after the writer mutex; see "The journal ring" at journal_reserve_locked()) ----
   * Positions are byte counters of the ring (monotonic); the ring's bytes are the journal files' bytes, extent by extent.  jr_head and the extents are written under
   * the writer mutex; jr_pub / jx_pub publish them (release); jr_tail (every byte below it is in the kernel) and jx_done are the leader's (jw_leader under jw_mu). */
  uint8_t *jr_buf;
  uint64_t jr_cap;
  uint64_t jr_head;                                   /* (wlock) bytes reserved */
  _Atomic uint64_t jr_pub, jr_tail;
  jr_ext_t jx[JX_CAP];
  uint32_t jx_cap;                                    /* the extents that may be in use: JX_CAP (fewer in a test, store_test_jx_cap) */
  uint64_t jx_head;                                   /* (wlock) extents begun */
  _Atomic uint64_t jx_pub, jx_done;                   /* extents published; the index of the extent jr_tail is in (the ones before it are all written: their slots may be reused) */
  pthread_mutex_t jw_mu;                              /* the leader flag and its waiters; order: wlock -> jw_mu, never jw_mu -> wlock */
  pthread_cond_t jw_cv;
  bool jw_leader;
  _Atomic int jw_state;                               /* JW_OK, JW_NOSPACE (a write met ENOSPC: only the flusher's jw_retry() writes; every other wait fails at once), JW_FAILED */
  uint64_t jold_end;                                  /* (the baton) the position up to which jold's bytes go (rule F: it is synced and closed only after jr_tail passes it) */
  _Atomic uint64_t n_jw_writes, n_jw_bytes, jw_write_max_us, jr_peak, n_jr_waits, jr_wait_max_us, n_jr_inlock, n_ck_twaits, n_jw_retries, jw_fail_unix;
  _Atomic int jw_last_err;
  uint64_t jr_warn_ms;                                /* (jw_mu) the last WARNING / ERROR about the journal ring's state */
  _Atomic uintptr_t df_tid[ST_DEFER_SLOTS];           /* threads whose calls do not wait for their journal bytes (store_defer()) ... */
  _Atomic uint64_t df_pos[ST_DEFER_SLOTS];            /* ... and the highest position their calls left (store_settle()) */
  _Atomic bool df_off;                                /* deferral ends with the flusher (bg_stop_join()): no background leader is left */
  _Atomic bool jw_kick;                               /* a deferred call asked the flusher to write the ring (one wake-up per round, wr_ack()) */
  _Atomic uint64_t n_df_busy;                         /* store_defer() found no free slot */
  _Atomic bool bg_stop_a;                             /* bg_stop for the waits outside bg_mu (the flusher's lead of the ring) */
  _Atomic bool cow;                                   /* the file system allocates on every write (ZFS): a checkpoint's overwrites take space too */
  _Atomic uint64_t ck_left;                           /* the bytes the running checkpoint may still allocate (jr_floor()) */
  retire_t *rq_head, *rq_tail;
  retire_t *rq_free;                                  /* (the mutex) what retire_run() took off the queue: freed by wr_unlock_raw() after the unlock (an munmap of a generation is 20 to 60 ms at 10M zones) */

  /* ---- 0.7 fix A: the I/O outside the writer mutex (see the top of the file) ----
   * Lock order: wlock, then bg_mu (innermost; nothing is waited for while it is held, except on bg_cv).  io_busy (the I/O baton: one commit at a
   * time) and ck_busy (one checkpoint at a time) are flags under bg_mu: a thread that holds the writer mutex only tries them (ck_try_locked()). */
  pthread_mutex_t bg_mu;
  pthread_cond_t bg_cv;
  bool io_busy, ck_busy, ck_handoff, bg_stop, bg_kick, fl_on;
  pthread_t fl_thr, fl_thr2;
  /* 0.7 round 15: what the commit thread and the writers must not wait for.  ah_tab: the blocks of the next growth of zt, zc and nx (tables_ahead(): a posix_fallocate() waited 0.5 to 11 s on UFS, and the commit
   * thread, which is also the background leader of the journal ring, stood in it).  ah_seg: the next segment file made ahead of its use (seg_pre_make(): seg_create() inside the writer mutex held it for
   * 0.4 to 0.9 s).  Both are started and stopped with the flusher (bg_start(), bg_stop_join()). */
  pthread_t fl_thr3, fl_thr4;
  ahead_t ah_tab, ah_seg;
  _Atomic uint64_t n_ah_allocs, n_ah_us, n_ah_max_us, n_ah_errors, n_ah_busy_kicks, n_ah_unahead, n_ah_thread_max_us;   /* store.ahead.*: posix_fallocate() calls of mtab_ahead() (any caller), their total and longest time, those that failed, kicks that found the thread busy, growths that found their blocks not allocated yet */
  /* The segment made ahead (seg_pre_*): pre_mu protects pre_state (its writes), pre_n and pre_g.  PRE_NONE -> PRE_BUSY (the thread, with the writer mutex held, picks the number: pre_n) -> PRE_READY (the file is made, the descriptor is in pre_g) -> PRE_NONE
   * (seg_place() took it under the writer mutex), or READY -> STALE (seg_place() found it made for a number that is not the next one) -> NONE (the thread removed the file; a close does the same).  Order: wlock, then pre_mu; nothing is waited for under pre_mu. */
  pthread_mutex_t pre_mu;
  _Atomic int pre_state;                              /* (writes under pre_mu; the thread peeks without it) */
  uint32_t pre_n;
  seg_t *pre_g;
  uint32_t pre_asked;                                 /* (the mutex) the segment for which the writer last asked the thread for the next one (once per segment) */
  uint64_t seg_free_lsn[ST_MAXSEG + 1];               /* (the mutex) the LSN of the record that freed the number of a removed segment (the number is made ahead only once that record is durable) */
  _Atomic uint64_t n_seg_pre, n_seg_inline, n_seg_pre_err, n_seg_pre_us, n_seg_pre_max_us, n_seg_inline_max_us;   /* store.segment.*: files taken from ahead, files made inside the writer mutex, failures of the thread, its longest creation, the longest creation inside the mutex */
  _Atomic bool ck_want;                               /* a checkpoint is wanted soon (after a growth: the old generation can go when the superblocks name the new one) */
  _Atomic bool ck_cancel;                             /* a clean checkpoint comes (store_checkpoint_clean(), store_close()): the write of a fuzzy checkpoint's tables ends between two runs (ck_write_tab()) */
  _Atomic uint64_t ckpt_max_us, n_ckpt_cancel;        /* the longest checkpoint; fuzzy checkpoints left for a clean one (a stop, a close) */
  /* the bound of the journal (store_journal_wait()): the largest size it reached, the calls that waited for a checkpoint, the longest and the total wait; under
   * bg_mu: ck_ends (checkpoints that ended, also the failed ones: bg_release()), jw_warn_ms (the last WARNING) */
  _Atomic uint64_t jpeak, jw_n, jw_max_us, jw_us;
  uint64_t ck_ends, jw_warn_ms;
  _Atomic int io_hold;                                /* commits and checkpoints whose I/O uses segment descriptors and index generations: retire_run() frees none meanwhile */
  int jold;                                           /* (baton) the journal before a switch whose sync failed: synced by the next commit, then closed */
  int jnext_fd;                                       /* (the baton) the next journal file, created ahead of the switch (ck_precreate()); jnext_gen its generation */
  uint32_t jrn_gone;                                  /* (ck_busy) the journal files below this generation are deleted (unlink_old_gens()) */
  uint32_t jrn_synced;                                /* (the baton) every journal file up to this generation is synced (with its header) */
  _Atomic uint64_t n_jswitch;                         /* switches of the journal file by a commit (store.journal.commit_switches) */
  pthread_mutex_t ap_mu;                              /* the writers of image records (store_put(), the cleaner): ap_mu before the writer mutex */
  const struct prew *prew;                            /* (the mutex) the record store_put() wrote before the mutex, for its put_locked() */
  _Atomic uint64_t n_prew, n_prew_miss;               /* records written before the mutex that the change took; those it wrote again (store.writes.prewrites, .prewrite_misses) */
  uint32_t jnext_gen;
  struct {                                            /* (ck_busy) the checkpoint being made */
    uint64_t lsn, t0, tw0;                            /* tw0: when the write of the tables began (ck_pace()) */
    uint64_t epos;                                    /* the ring position after its switch: the old file's records and the new file's header are below it (rule F) */
    bool clean, dir;
    bool bulk;                                        /* a bulk checkpoint: no ix / sx, the superblock says SBF_BULK_CK */
    uint64_t bulk_seg;                                /* ... the segment bytes at its begin */
    int oldfd, newfd;
    uint32_t gen;                                     /* the journal file the superblock names (newfd until a commit switches the journal on) */
    ixgen_t *ix, *sx;
    uint32_t nseg;
    seg_t *seg[ST_MAXSEG];
    struct { uint64_t *dirty; uint64_t npages, bytes; bool all, cow; uint64_t grow; } t[5];   /* zt, zc, nx, ix, sx as of P: the pages to write (taken from the writers), the bytes of P;
                                                       * cow: every write allocates (ZFS, a sparse file); grow: the bytes past what the file holds (allocated by this checkpoint) */
  } ck;
  uint8_t *ck_buf;                                    /* (ck_busy) the copy of a run of pages that the checkpoint writes */
  _Atomic uint64_t priv_bytes;                        /* the private pages of the tables (store.tables.private_bytes) */
  _Atomic uint64_t n_ck_bytes, ck_last_bytes;         /* bytes of the tables written by checkpoints: all, the last one */
  _Atomic uint64_t n_ck_paced_us;                     /* the time fuzzy checkpoints gave way to the writers (ck_pace()) */
  struct { uint32_t nseg; seg_t *seg[ST_MAXSEG]; } cm;   /* (baton) the segments of the commit being made */
  /* growth of ix / sx outside the mutex (rg_*; wlock, except the flags the build thread reads) */
  bool rg_active, rg_bad;
  bool rg_noalloc;                                     /* the running build is a reserve (store_reserve()): its files get their size and no blocks when they are made */
  _Atomic bool rg_cancel, rg_stop;
  _Atomic int rg_live;                                /* build threads that may still touch the store: a count, not a flag (a build clears rg_active under the mutex before its thread ends, so
                                                       * the next one can start while the last is still on its way out; with a flag the first one's end let store_close() free the store under the second) */
  _Atomic bool rg_press;                              /* a build runs and the index is past RG_PRESS (7/16) of its slots: store_index_wait() waits while it is set (set by ix_make_room(), cleared when the build ends or the wait gave up) */
  _Atomic bool rg_nowait;                             /* a wait gave up on this build: no more waits for it (cleared when the next build begins) */
  _Atomic uint64_t iw_n, iw_us, iw_max_us, iw_giveups;   /* the waits of store_index_wait(): their number, total and longest time, and those that gave up */
  uint64_t tabgen, rg_tabgen;                         /* tabgen: +1 at every change of a generation; a build made against another one is dropped */
  uint32_t ix_gen_next, sx_gen_next;                  /* the number of the next generation file (a dropped build does not reuse its number) */
  uint64_t rg_hwm, rg_nix, rg_nsx;
  uint32_t rg_ixgen, rg_sxgen;
  rgent_t *rg_ch[RG_NCH];                             /* the build's log of index changes, in chunks that never move (the build reads the part before rg_n with no lock while the writers append) */
  _Atomic size_t rg_n;                                /* (written under the mutex, after the entries it covers: release) */
  _Atomic uint64_t n_growths_bg;
  /* holds of the writer mutex */
  uint64_t wl_t0;
  const char *wl_site;                                /* (the mutex) the function that took it */
  _Atomic uintptr_t wl_owner;                         /* the thread that holds it (0: none): store_test_writer_free() */
  _Atomic uint64_t wl_n, wl_slow, wl_max_us;
  _Atomic uint64_t wl_fine[STORE_FINE_BUCKETS];       /* 0.7: every hold, for the percentiles (store.lock.writer_hold_p999_us) */
  _Atomic(const char *) wl_max_site;                  /* the function of the longest hold (store.lock.writer_hold_max_site) */
  st_wl_site_t wl_sites[STORE_LOCK_SITES];             /* 0.7: the holds of 1 ms or more by function (the first STORE_LOCK_SITES functions that had one; written under the mutex) */
  uint64_t wl_log_ms;                                 /* (the mutex) the last log line of a hold of a second or more */

  _Atomic uint64_t n_puts, n_replaces, n_deletes, n_growths, n_checkpoints, n_commits, n_write_errors;
  _Atomic uint64_t n_group_records, n_group_entries;      /* 0.7 M2: journal records of a group commit (store_set_known_n()) and the entries they carried */
  _Atomic uint64_t n_names_refused;                       /* 0.7: writer calls refused for a zero byte in the name (check_name_args()) */
  _Atomic uint64_t n_resv_refused;                        /* 0.7: writes refused because zt / zc or nx reached its reserved address space (reserve_hit()) */
  uint64_t last_resv_ms, last_resv_warn_ms;               /* (the log lines of the two, under the writer mutex) */
  uint32_t resv_zones;                                    /* the zones the address space of zt and zc was reserved for at the open */
  bool resv_from_opt;                                     /* ... and whether `store-max-zones` (max_zones) said so, or the RAM */
  _Atomic uint32_t state;
  store_recovery_t rec;

  /* ---- 0.7 WP9 ---- */
  uint64_t reserve_bytes;
  uint8_t  seg_draining[ST_MAXSEG + 1];            /* writer: the segment has no live record; drain_lsn / drain_epoch say when */
  uint64_t seg_drain_lsn[ST_MAXSEG + 1], seg_drain_epoch[ST_MAXSEG + 1];
  uint64_t seg_skip_until[ST_MAXSEG + 1];          /* writer: the cleaner could not empty this segment (a damaged record): not again before this time (ms) */
  uint64_t seg_dead_seen[ST_MAXSEG + 1], seg_dead_ms[ST_MAXSEG + 1];   /* writer: the dead bytes of a segment when the background cleaner last looked, and when they last changed (cl_settle_scan_locked()) */
  uint32_t cl_seg;                                 /* writer: the segment the cleaner is emptying, and the offset it has scanned to */
  uint64_t cl_off;
  uint8_t *cl_buf;                                 /* COPY mode: a piece of the segment being scanned */
  uint64_t cl_buf_off;
  size_t   cl_buf_len, cl_buf_cap;
  bool     in_cleaner;                             /* writer: appends may use the reserve */
  double   cl_tokens;                              /* bytes the cleaner may still move now */
  uint64_t cl_tokens_ms;
  _Atomic uint64_t c_runs, c_moved_recs, c_moved_bytes, c_segs_freed, c_bad, c_pinned, c_incomplete, c_last_unix, c_nx_runs, c_nx_bytes;
  _Atomic uint32_t c_draining, c_pinned_now;
  _Atomic bool c_forced;                           /* the operator asked for the cleaner at full speed (store_compact_request) */
  uint64_t emerg_block_until;                      /* the last emergency cleaning freed nothing: not again before this time (ms) */
  /* space */
  _Atomic int64_t avail_est;                       /* free bytes of the file system as of the last probe less every byte reserved since (records, images, a checkpoint's allocating writes); < 0 = unknown */
  _Atomic uint64_t probe_bytes, last_probe_ms;    /* (atomics: the probe is made outside the writer mutex, st_probe_stale()) */
  _Atomic uint64_t n_reprobe_lock;                 /* probes made inside the writer mutex to confirm a refusal (store.space.reprobe_in_lock) */
  _Atomic uint64_t fs_total, fs_avail, fs_checked_unix;
  _Atomic uint32_t fs_blksize, fs_rec_warn;
  uint32_t align_rs;                               /* 0.7 attach-align: COPY mode on ZFS, the record size the images are placed in (seg_align_pos()); 0 = not aligned */
  _Atomic uint64_t n_align_pads, n_align_pad_bytes;   /* records placed at the next record boundary, and the bytes skipped for them (store.segment.align_pads, .align_pad_bytes) */
  _Atomic uint32_t space_level;
  _Atomic bool degraded;                           /* a write went to the KNOWN fallback and no image was stored since */
  uint64_t last_err_ms, last_warn_ms, nospc_since;
  _Atomic uint64_t n_degraded, n_enospc, degraded_since;
  struct { uint64_t ms, bytes; } gring[ST_GRING];
  unsigned gcount, ghead;
  uint64_t last_gsample_ms;
  _Atomic uint64_t store_bytes, growth_bph, full_in_h;
  /* scrub */
  pthread_mutex_t sc_mu;
  bool     sc_running, sc_need_repair;
  uint32_t sc_cursor;
  uint64_t sc_start_ms, sc_tokens_ms;
  double   sc_tokens;
  _Atomic uint64_t sc_last_start, sc_last_end, sc_passes, sc_zones, sc_bytes, sc_bad_img, sc_bad_cell, sc_bad_idx, sc_io;
  _Atomic uint32_t sc_pct, sc_running_a;
  uint64_t sc_p_zones, sc_p_images, sc_p_bytes, sc_p_bad_img, sc_p_bad_cell, sc_p_bad_idx, sc_p_io;       /* the pass that runs */
  _Atomic uint64_t sc_last_done;                   /* unix time the last pass ended (superblock) */
  /* err.ring */
  int      err_fd;
  uint8_t *err_map;
  size_t   err_len;
  pthread_mutex_t err_mu;
  uint32_t *err_ix;                               /* ERR_IX_N buckets: the ring slot + 1 of the newest entry of the zone ids that hash there (0: none); err_mu */
  uint32_t *err_nx;                               /* per ring slot: the next slot + 1 in its bucket (a bucket has one entry per zone id) */
  /* a damaged image was found (the scrub, the cleaner): the zone ids wait here for the hook of the owner (opts.bad_image), which the tick calls with no store lock held */
  pthread_mutex_t bad_mu;
  struct bad_n { struct bad_n *next; uint32_t zid; uint16_t tries; } *bad_head, *bad_tail;
  uint64_t bad_lost;                              /* notices that could not be queued (no memory) */
  /* open */
  pthread_t ra_thr;
  bool     ra_started;
  _Atomic bool ra_stop, ra_done;
  _Atomic uint64_t ra_ix_us, ra_zt_us;
};

/* ------------------------------------------------------------------------------------------------------------------ */
/* test hooks                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

void (*_Atomic store_test_ckpt_hook)(int step);
void (*_Atomic store_test_regrow_hook)(int step);
void (*_Atomic store_test_commit_hook)(int step);
void (*_Atomic store_test_prewrite_hook)(store_t *s);
_Atomic bool store_test_no_flusher;
_Atomic uint32_t store_test_align_rs;
static void st_hook(void (*_Atomic *h)(int), int step) {
  void (*f)(int) = atomic_load_explicit(h, memory_order_acquire);
  if (f) f(step);
}

#ifdef KARIDNS_UNIT_TEST
_Atomic long store_test_crash_countdown = 0;
void (*store_test_before_counters)(store_t *s) = NULL;
_Atomic long store_test_fail_commit = 0;
_Atomic long store_test_fail_ckwrite = 0;
_Atomic long store_test_fail_map = 0;      /* the n-th reservation of address space of a table fails with ENOMEM (a limit of address space, ulimit -v) */
/* a writer function of the store (its name: "put", "set_known", "delete", "set_flags", "set_stamp", "set_cursor") fails before it changes anything with the errno this returns (0: no failure) */
int (*store_test_write_fault)(const char *op, uint32_t zid) = NULL;
void (*store_test_in_stats)(void) = NULL;
int64_t (*store_test_fs_free)(void) = NULL;
void (*store_test_cleaner_step)(store_t *s, uint32_t victim) = NULL;
/* the blocks ahead and the segment ahead (0.7 round 15): called with no lock held by mtab_ahead() before its posix_fallocate() (site 1), by the segment thread before it makes the file (2), and by seg_create() inside the writer mutex before it makes one (3); a test makes the disk slow there */
void (*_Atomic store_test_ahead_hook)(store_t *s, int site);
#define AHEAD_HOOK(s, site) do { void (*h_)(store_t *, int) = atomic_load_explicit(&store_test_ahead_hook, memory_order_acquire); if (h_) h_((s), (site)); } while (0)
#define ST_FAULT(op, zid) do { int fe_ = store_test_write_fault ? store_test_write_fault((op), (zid)) : 0; if (fe_) return fe_; } while (0)
/* ... the same for an entry of a group (store_set_known_n()): the entry fails with the errno, the others go on */
#define ST_FAULT_RES(op, zid, res) do { int fe_ = store_test_write_fault ? store_test_write_fault((op), (zid)) : 0; if (fe_) (res) = fe_; } while (0)
static void st_crash_point(void) {
  long c = atomic_load_explicit(&store_test_crash_countdown, memory_order_relaxed);
  while (c > 0 && !atomic_compare_exchange_weak_explicit(&store_test_crash_countdown, &c, c - 1, memory_order_relaxed, memory_order_relaxed)) {}
  if (c == 1) kill(getpid(), SIGKILL);
}
/* the n-th commit fails (store_test_fail_commit), the n-th write of table pages (store_test_fail_ckwrite) */
static bool st_fail_nth(_Atomic long *n) {
  long c = atomic_load_explicit(n, memory_order_relaxed);
  while (c > 0 && !atomic_compare_exchange_weak_explicit(n, &c, c - 1, memory_order_relaxed, memory_order_relaxed)) {}
  return c == 1;
}
#define CRASH_POINT() st_crash_point()
#define FAIL_COMMIT() st_fail_nth(&store_test_fail_commit)
#define FAIL_CKWRITE() st_fail_nth(&store_test_fail_ckwrite)
#define FAIL_MAP() st_fail_nth(&store_test_fail_map)
#else
#define CRASH_POINT() ((void)0)
#define FAIL_COMMIT() false
#define FAIL_CKWRITE() false
#define FAIL_MAP() false
#define AHEAD_HOOK(s, site) ((void)0)
#define ST_FAULT(op, zid) ((void)0)
#define ST_FAULT_RES(op, zid, res) ((void)0)
#endif
#if defined(KARIDNS_UNIT_TEST) || defined(KARIDNS_TEST_EVICT)
int (*store_test_append_fault)(uint64_t reclen) = NULL;   /* (also in the server's test build, karidns-evict: dns_store.h) */
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
  char buf[512];
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
#define ST_SEQ_SPIN_NOSLEEP 200u          /* a thread that must never sleep (a query worker): the number of looks at a cell that is being written, then it gives up */
typedef struct { unsigned n; uint64_t t0; } seqwait_t;
static _Thread_local bool t_st_nosleep;   /* store_reader_nosleep() */
static _Thread_local bool t_st_busy;      /* a lookup of this thread gave up on a cell that was being written (store_reader_busy_take()) */
bool store_reader_nosleep(bool on) {
  bool was = t_st_nosleep;
  t_st_nosleep = on;
  t_st_busy = false;
  return was;
}
bool store_reader_busy_take(void) {
  bool b = t_st_busy;
  t_st_busy = false;
  return b;
}
static bool seq_wait(seqwait_t *w) {
  if (t_st_nosleep) {                     /* a query worker never yields or sleeps here: a bounded spin, then "not now" (the caller falls back to the slow path) */
    if (w->n++ < ST_SEQ_SPIN_NOSLEEP) return true;
    t_st_busy = true;
    return false;
  }
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

/* a bulk fill runs, or its end is not on disk yet: the on-disk state is a bulk checkpoint (or the start of the fill), which names segments and cells that no journal can bring back, so the cleaner,
 * the removal of segments, the nx pass and the scrub stay off (THE BULK FILL, U and E) */
static inline bool st_bulk_busy(const store_t *s) {
  return atomic_load_explicit(&s->bulk, memory_order_relaxed) || atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed);
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
static void nx_write(store_t *s, uint64_t off, const uint8_t *src, size_t len);
static void dm_mark(dmap_t *d, uint64_t off, uint64_t len);
/* The same, and (nxlen != 0) the bytes of the zone's long name are written to nx inside the odd window: the nx pass moves a name and the cell that says where it is as one step. */
/* MEMORY ORDER (rule T of the journal ring, see journal_reserve_locked()): every store here is a C11 atomic word store, and it is made after the release fence of the
 * reservation of the record it belongs to.  A checkpoint copies the tables with atomic word loads and an acquire fence and then reads jr_pub: a plain store here, or a store made
 * before that fence, would let a table file get ahead of the kernel's journal after a kill -9 without any test on x86 or under TSan showing it. */
static void zrec_write_nx(store_t *s, uint32_t z, const r64_t *zt, const r64_t *zc, uint64_t nxoff, const uint8_t *nxb, size_t nxlen) {
  _Atomic uint64_t *tc = (_Atomic uint64_t *)zt_cell(s, z), *cc = (_Atomic uint64_t *)zc_cell(s, z);
  dm_mark(&s->zt.d, (uint64_t)z * ST_REC, ST_REC);
  dm_mark(&s->zc.d, (uint64_t)z * ST_REC, ST_REC);
  uint32_t seq = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32);
  uint32_t odd = seq | 1u, even = odd + 1u;
  uint64_t low7 = zc->w[7] & 0xffffffffu;
  atomic_store_explicit(&cc[7], low7 | ((uint64_t)odd << 32), memory_order_relaxed);
  atomic_thread_fence(memory_order_release);
  if (nxlen) nx_write(s, nxoff, nxb, nxlen);
  for (int i = 0; i < 7; i++) atomic_store_explicit(&cc[i], zc->w[i], memory_order_relaxed);
  for (int i = 0; i < 8; i++)
    if (i != 3) atomic_store_explicit(&tc[i], zt->w[i], memory_order_relaxed);
  atomic_store_explicit(&tc[3], zt->w[3], memory_order_release);
  atomic_store_explicit(&cc[7], low7 | ((uint64_t)even << 32), memory_order_release);
}
static void zrec_write(store_t *s, uint32_t z, const r64_t *zt, const r64_t *zc) { zrec_write_nx(s, z, zt, zc, 0, NULL, 0); }

static int zrec_read_cells(const store_t *s, uint32_t z, r64_t *zt, r64_t *zc) {
  r64_load(zt_cell(s, z), zt);
  r64_load(zc_cell(s, z), zc);
  zc->w[7] &= 0xffffffffu;                      /* the sequence counter is not content */
  return zrec_crc(zt, zc) == zrec_stored_crc(zt) ? 0 : -EBADMSG;
}
/* Reader: a consistent copy of the zt and zc cells of z (see zrec_write).  -ENOENT: z is beyond the files; -EBADMSG: the CRC does not
 * match (a damaged cell) or the cell stays in the middle of a write for longer than a crashed or very slow writer can explain. */
static int zrec_read_seq(const store_t *s, uint32_t z, r64_t *zt, r64_t *zc, uint32_t *seq_out) {
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
    if (seq_out) *seq_out = s1;
    return zrec_crc(zt, zc) == zrec_stored_crc(zt) ? 0 : -EBADMSG;
  }
  return -EBADMSG;
}
static int zrec_read(const store_t *s, uint32_t z, r64_t *zt, r64_t *zc) { return zrec_read_seq(s, z, zt, zc, NULL); }
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

/* nx is read and written in 64-bit words (relaxed atomics): the nx pass (WP9) rewrites names in place while readers look at them, and a reader whose copy was disturbed
 * throws it away (the sequence counter of the zone's cell, see zrec_write()); word accesses make that a race the C memory model allows (and TSan accepts), not a data race.
 * A name's bytes are not word aligned; the writer reads and writes whole words, so the neighbours' bytes in a shared word are written back unchanged. */
static void nx_read(const store_t *s, uint64_t off, uint8_t *dst, size_t len) {
  const _Atomic uint64_t *w = (const _Atomic uint64_t *)(s->nx.base + (off & ~7ull));
  size_t skip = (size_t)(off & 7u), i = 0;
  while (i < len) {
    uint64_t v = atomic_load_explicit(w++, memory_order_relaxed);
    const uint8_t *b = (const uint8_t *)&v;
    size_t n = 8 - skip;
    if (n > len - i) n = len - i;
    memcpy(dst + i, b + skip, n);
    i += n;
    skip = 0;
  }
}
/* (rule T: atomic word stores only, after the record's fence; see zrec_write_nx()) */
static void nx_write(store_t *s, uint64_t off, const uint8_t *src, size_t len) {
  _Atomic uint64_t *w = (_Atomic uint64_t *)(s->nx.base + (off & ~7ull));
  size_t skip = (size_t)(off & 7u), i = 0;
  dm_mark(&s->nx.d, off, len);
  while (i < len) {
    size_t n = 8 - skip;
    if (n > len - i) n = len - i;
    uint64_t v = 0;
    if (n < 8) v = atomic_load_explicit(w, memory_order_relaxed);
    memcpy((uint8_t *)&v + skip, src + i, n);
    atomic_store_explicit(w++, v, memory_order_relaxed);
    i += n;
    skip = 0;
  }
}

/* the full name of a zone from its zt cell (inline part, or nx); false when the cell points outside nx.  A reader that is not the writer checks the cell's sequence counter
 * afterwards (store_zone_get()): the bytes of nx may have been moved under it. */
static bool zt_fullname(const store_t *s, const zt_t *z, uint8_t *out) {
  if (z->klen <= ST_NAME_INL) {
    memcpy(out, z->name, z->klen);
    return true;
  }
  uint64_t off;
  memcpy(&off, z->name, 8);
  uint64_t avail = atomic_load_explicit(&s->nx_avail, memory_order_acquire);
  if (off > avail || (uint64_t)z->klen > avail - off) return false;
  nx_read(s, off, out, z->klen);
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
    uint8_t xb[ST_NAME_MAX_B];
    nx_read(s, off, xb, len);
    atomic_thread_fence(memory_order_acquire);
    if (s1 != (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32)) { if (!seq_wait(&sw)) break; continue; }       /* (the nx pass moved the name while it was read) */
    return memcmp(xb, fn, len) == 0;
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

/* mincore() only sees the pages that this process has mapped: a page that is in the page cache and has not been touched through the mapping reads as not resident (measured on FreeBSD 15.1, UFS: 96 pages of
 * 2,560 after a write, after a read, and after another process had touched them all).  MAP_PREFAULT_READ maps the pages that are in the page cache when the segment is mapped (no read of the disk), so
 * that store_image_resident() tells the truth about them; a page that comes into the cache later is mapped by its first touch, and until then the worker leaves its zone to a store thread. */
#ifdef MAP_PREFAULT_READ
#define ST_PREFAULT MAP_PREFAULT_READ
#else
#define ST_PREFAULT 0
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
/* ---- the pages the writers changed (dmap_t) ---- */

static void dm_init(store_t *s, dmap_t *d) {
  d->shift = s->pgshift;
  d->acct = &s->priv_bytes;
}
/* the bitmaps cover npages pages (they never shrink); -ENOMEM leaves them as they were (a size that was reached stays) */
static int dm_resize(dmap_t *d, uint64_t npages) {
  if (npages <= d->npages) return 0;
  const size_t ow = (size_t)((d->npages + 63) / 64), nw = (size_t)((npages + 63) / 64);
  if (nw > ow) {
    uint64_t *a = realloc(d->dirty, nw * sizeof(*a));
    if (!a) return -ENOMEM;
    memset(a + ow, 0, (nw - ow) * sizeof(*a));
    d->dirty = a;
    uint64_t *b = realloc(d->priv, nw * sizeof(*b));
    if (!b) return -ENOMEM;
    memset(b + ow, 0, (nw - ow) * sizeof(*b));
    d->priv = b;
  }
  d->npages = npages;
  return 0;
}
static void dm_free(dmap_t *d) {
  if (d->acct && d->npriv) atomic_fetch_sub_explicit(d->acct, d->npriv << d->shift, memory_order_relaxed);
  free(d->dirty);
  free(d->priv);
  d->dirty = d->priv = NULL;
  d->npages = d->npriv = 0;
}
/* a generation made in this session (anonymous memory): every page is private, and the first checkpoint that names it writes all of it */
static void dm_set_all(dmap_t *d) {
  const size_t nw = (size_t)((d->npages + 63) / 64);
  if (nw) memset(d->priv, 0xff, nw * sizeof(*d->priv));
  atomic_fetch_add_explicit(d->acct, (d->npages - d->npriv) << d->shift, memory_order_relaxed);
  d->npriv = d->npages;
  d->all = true;
}
/* bytes [off, off + len) of the table were changed (writer mutex) */
static void dm_mark(dmap_t *d, uint64_t off, uint64_t len) {
  if (!len) return;
  for (uint64_t p = off >> d->shift, e = (off + len - 1) >> d->shift; p <= e && p < d->npages; p++) {
    const uint64_t b = 1ull << (p & 63);
    d->dirty[p >> 6] |= b;
    if (!(d->priv[p >> 6] & b)) {
      d->priv[p >> 6] |= b;
      d->npriv++;
      atomic_fetch_add_explicit(d->acct, 1ull << d->shift, memory_order_relaxed);
    }
  }
}

/* ---- growable table (zt, zc, nx) ----
 * The data the file held at the open is mapped MAP_PRIVATE (a page is read from the file at its first touch and stays shared with the page cache until a writer changes it); a growth maps
 * anonymous memory.  Nothing but a checkpoint writes the file (ck_io_tables()). */

static int mtab_map_tail(mtab_t *t, uint64_t from, uint64_t to, bool file) {
  void *p = mmap(t->base + from, (size_t)(to - from), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | ST_NOCORE | (file ? 0 : MAP_ANON), file ? t->fd : -1,
                 file ? (off_t)(ST_HDR_PAGE + from) : 0);
  return p == MAP_FAILED ? -errno : 0;
}
static int mtab_open(store_t *s, mtab_t *t, const char *name, uint32_t kind, uint32_t recsz, size_t reserve, bool create) {
  memset(t, 0, sizeof(*t));
  t->fd = -1;
  dm_init(s, &t->d);
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
  void *base = FAIL_MAP() ? (errno = ENOMEM, MAP_FAILED) : mmap(NULL, reserve, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if (base == MAP_FAILED) return -errno;
  t->base = base;
  t->reserve = reserve;
  if (dm_resize(&t->d, data >> s->pgshift) < 0) return -ENOMEM;
  if (data) {
    int r = mtab_map_tail(t, 0, data, true);
    if (r < 0) return r;
  }
  atomic_store_explicit(&t->extended, data, memory_order_relaxed);
  atomic_store_explicit(&t->mapped, data, memory_order_release);
  return 0;
}
static void mtab_close(mtab_t *t) {
  if (t->base) munmap(t->base, t->reserve);
  if (t->fd >= 0) close(t->fd);
  dm_free(&t->d);
  memset(t, 0, sizeof(*t));
  t->fd = -1;
}
/* the size a growth from cur to at least need makes (a quarter more, at least a chunk, in whole chunks) */
static uint64_t mtab_want(const store_t *s, const mtab_t *t, uint64_t cur, uint64_t need) {
  uint64_t want = need;
  if (cur + cur / 4 > want) want = cur + cur / 4;
  if (cur + ST_CHUNK > want) want = cur + ST_CHUNK;
  want = (want + ST_CHUNK - 1) & ~(uint64_t)(ST_CHUNK - 1);
  if (want > t->reserve) want = t->reserve & ~(uint64_t)(s->pagesz - 1);
  return want;
}
static void mtab_note_extended(mtab_t *t, uint64_t to) {
  uint64_t c = atomic_load_explicit(&t->extended, memory_order_relaxed);
  while (to > c && !atomic_compare_exchange_weak_explicit(&t->extended, &c, to, memory_order_release, memory_order_relaxed)) {}
}
static bool st_no_fallocate(int r) { return r == EINVAL || r == EOPNOTSUPP || r == ENODEV; }
static void fs_probe(store_t *s);
static void space_used(store_t *s, uint64_t n);
static bool rl_ok(uint64_t *last, uint64_t every_ms);
/* A table is as large as the address space reserved for it at the open (mtab_open(): the mapping is never moved, readers hold its base).  A write that needs more is refused with -ENOMEM
 * (not -EFBIG / -ENOSPC: it is no disk-full state, nothing is made KNOWN and the cleaner does not run); the zone stays where it is (the database, or the secondary's refresh) and the next
 * start reserves twice what the files hold (open_tables()), or what `store-max-zones` says. */
static int reserve_hit(store_t *s, const mtab_t *t, uint64_t need) {
  atomic_fetch_add_explicit(&s->n_resv_refused, 1, memory_order_relaxed);
  if (rl_ok(&s->last_resv_ms, 60000))
    st_log(s, 3, "store: the %s is full: it needs %" PRIu64 " bytes and %" PRIu64 " are reserved (room for %u zones, %s); zones that need more are not stored and are served from the database; "
                 "raise `store-max-zones` in the database block and restart (the next start reserves at least twice what the files hold)",
           t == &s->nx ? "table of long names" : "table of zones", need, (uint64_t)t->reserve, (unsigned)s->resv_zones, s->resv_from_opt ? "set by store-max-zones" : "derived from the RAM");
  return -ENOMEM;
}
/* grow the data area to at least `need` bytes (never shrinks); the address of existing data does not change.  The new pages are anonymous memory, and no operation on the file is made
 * here (inside the writer mutex): UFS's posix_fallocate() syncs the file's vnode and waits for the lock that a checkpoint's fsync() of the table holds (holds of seconds).  The
 * room is checked against the free space (fs_probe(): a full disk is -ENOSPC now, not a checkpoint that cannot write); the flusher allocates the blocks ahead
 * (mtab_ahead()) and the checkpoint extends the file to the size of its position (ck_write_tab()). */
static int mtab_grow(store_t *s, mtab_t *t, uint64_t need) {
  uint64_t cur = atomic_load_explicit(&t->mapped, memory_order_relaxed);
  if (need <= cur) return 0;
  if (need > t->reserve) return reserve_hit(s, t, need);
  const uint64_t want = mtab_want(s, t, cur, need), ext = atomic_load_explicit(&t->extended, memory_order_acquire);
  if (ext < want) {                                   /* (the blocks are the flusher's and the checkpoint's to allocate: here only the room is checked; the reserve of the cleaner may be used, as an allocation could) */
    const uint64_t n = want - (ext > cur ? ext : cur);
    atomic_fetch_add_explicit(&s->n_ah_unahead, 1, memory_order_relaxed);         /* (the thread of the blocks ahead has not got there: the checkpoint allocates them, ck_write_tab()) */
    fs_probe(s);
    const int64_t est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
    if (est >= 0 && (uint64_t)est < n) return -ENOSPC;
    space_used(s, n);
  }
  if (dm_resize(&t->d, want >> s->pgshift) < 0) return -ENOMEM;
  int r = mtab_map_tail(t, cur, want, false);
  if (r < 0) return r;
  atomic_store_explicit(&t->mapped, want, memory_order_release);
  return 0;
}
/* Outside the writer mutex (the flusher, store_reserve()): allocate the blocks of the next growth of the table when what is in use (`used` bytes) is near the end of what is mapped, or
 * those of a growth to `need` (store_reserve()), so that the growth inside the mutex is a mapping (posix_fallocate() of a quarter of zt at millions of zones is seconds on UFS).  A growth
 * inside the mutex at the same time allocates the same range: both are the same allocation. */
static void mtab_ahead(store_t *s, mtab_t *t, uint64_t used, uint64_t need) {
  const uint64_t cur = atomic_load_explicit(&t->mapped, memory_order_acquire);
  if (need <= cur) {
    if (used + used / 8 + ST_CHUNK / 2 < cur) return;         /* (not near the end yet) */
    need = cur + 1;
  }
  if (need > t->reserve || atomic_load_explicit(&t->no_alloc, memory_order_relaxed)) return;
  const uint64_t want = mtab_want(s, t, cur, need), have = atomic_load_explicit(&t->extended, memory_order_acquire);
  if (have >= want) return;
  const uint64_t from = have > cur ? have : cur;
  /* posix_fallocate() only: it never makes a file shorter */
  const uint64_t t0 = st_now_us();
  AHEAD_HOOK(s, 1);
  const int r = posix_fallocate(t->fd, (off_t)(ST_HDR_PAGE + from), (off_t)(want - from));
  const uint64_t us = st_now_us() - t0;
  atomic_fetch_add_explicit(&s->n_ah_allocs, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->n_ah_us, us, memory_order_relaxed);
  uint64_t mx = atomic_load_explicit(&s->n_ah_max_us, memory_order_relaxed);
  while (us > mx && !atomic_compare_exchange_weak_explicit(&s->n_ah_max_us, &mx, us, memory_order_relaxed, memory_order_relaxed)) {}
  if (r == 0) mtab_note_extended(t, want);
  else if (st_no_fallocate(r)) atomic_store_explicit(&t->no_alloc, true, memory_order_relaxed);
  else atomic_fetch_add_explicit(&s->n_ah_errors, 1, memory_order_relaxed);        /* (ENOSPC, EIO: nothing is done here, as before: the checkpoint that extends the file meets the same error and the state handling is its, ck_write_tab()) */
}

/* ---- index generation files (ix, sx) ---- */

static void st_name_ix(char *buf, size_t n, const char *base, uint32_t gen) { snprintf(buf, n, "%s.%u", base, gen); }

static void ixgen_free(ixgen_t *g) {
  if (!g) return;
  if (g->slots) munmap((void *)g->slots, g->maplen);
  if (g->fd >= 0) close(g->fd);
  dm_free(&g->d);
  free(g);
}
/* an opened generation: MAP_PRIVATE of its file; a made one (anon): anonymous memory, every page written by the first checkpoint that names it */
static int ixgen_map(store_t *s, ixgen_t *g, bool anon) {
  g->maplen = (size_t)((g->nslots * 8 + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1));
  int fl = MAP_PRIVATE | ST_NOCORE | (anon ? MAP_ANON : 0);
#if defined(MAP_ALIGNED_SUPER)
  if (g->maplen >= (2u << 20)) fl |= MAP_ALIGNED_SUPER;
#endif
  dm_init(s, &g->d);
  if (dm_resize(&g->d, g->maplen >> s->pgshift) < 0) return -ENOMEM;
  void *p = mmap(NULL, g->maplen, PROT_READ | PROT_WRITE, fl, anon ? -1 : g->fd, anon ? 0 : (off_t)ST_HDR_PAGE);
  if (p == MAP_FAILED) return -errno;
  g->slots = p;
  if (anon) dm_set_all(&g->d);
  return 0;
}
/* create generation file `gen` of kind (FK_IX / FK_SX) with n empty slots */
static int ixgen_create(store_t *s, uint32_t kind, uint32_t gen, uint64_t nslots, bool alloc, ixgen_t **out) {
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
  const off_t fsize = (off_t)(ST_HDR_PAGE + ((nslots * 8 + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1)));
  if (r == 0) r = alloc ? st_extend(fd, ST_HDR_PAGE, fsize) : ftruncate(fd, fsize) == 0 ? 0 : -errno;    /* (not alloc, for the generation of a reserve: the file has its size, with no blocks; the checkpoint that names it writes every page.  The allocation of 400 MB on UFS stalls the files that other writers make meanwhile: a growth inside the mutex of the first zones, 425 ms) */
  if (r == 0) r = ixgen_map(s, g, true);
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
  r = ixgen_map(s, g, false);
  if (r < 0) { ixgen_free(g); return r; }
  *out = g;
  return 0;
}

static void seg_free(seg_t *g);
static void retire_add(store_t *s, ixgen_t *g) {
  retire_t *r = calloc(1, sizeof(*r));
  if (!r) return;   /* leak the mapping rather than free it under a reader */
  r->g = g;
  r->epoch = rcu_writer_advance_epoch();
  if (s->rq_tail) s->rq_tail->next = r; else s->rq_head = r;
  s->rq_tail = r;
}
/* a segment that was removed: its descriptor (fd, mapping) is freed when the readers that could have looked at it are gone */
static void retire_add_seg(store_t *s, seg_t *g) {
  retire_t *r = calloc(1, sizeof(*r));
  if (!r) return;
  r->sg = g;
  r->epoch = rcu_writer_advance_epoch();
  if (s->rq_tail) s->rq_tail->next = r; else s->rq_head = r;
  s->rq_tail = r;
}
/* (writer mutex held) the generations and segments whose grace period has passed leave the queue; their memory and descriptors are released by wr_unlock_raw() after the unlock: no
 * reader can reach them (grace period) and no commit or checkpoint uses them (io_hold was 0 under the mutex; the ones that start later take the current generations and segments) */
static void retire_run(store_t *s, bool force) {
  if (!force && atomic_load_explicit(&s->io_hold, memory_order_acquire) > 0) return;      /* (a commit or a checkpoint syncs a segment or a generation outside the mutex) */
  while (s->rq_head && (force || rcu_writer_is_safe(s->rq_head->epoch))) {
    retire_t *r = s->rq_head;
    s->rq_head = r->next;
    if (!s->rq_head) s->rq_tail = NULL;
    r->next = s->rq_free;
    s->rq_free = r;
  }
}
#ifdef KARIDNS_UNIT_TEST
void (*store_test_retire_free)(store_t *s) = NULL;
#endif
static void retire_free(store_t *s, retire_t *r) {
  (void)s;
  while (r) {
    retire_t *n = r->next;
#ifdef KARIDNS_UNIT_TEST
    if (store_test_retire_free) store_test_retire_free(s);
#endif
    ixgen_free(r->g);
    if (r->sg) seg_free(r->sg);
    free(r);
    r = n;
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
/* position for an insert: the first tombstone on the way, else the first empty slot; *was_empty tells which.  taken[ntaken]: slots that entries of a group commit (store_set_known_n()) have
 * claimed and not written yet: they count as occupied, as they would be after the record of the entry before (NULL, 0: none) */
static uint64_t slot_find_insert(const ixgen_t *g, uint64_t h, bool *was_empty, const uint64_t *taken, unsigned ntaken) {
  uint64_t n = g->nslots, pos = st_pos(h, n), tomb = UINT64_MAX;
  for (uint64_t i = 0; i < n; i++) {
    uint64_t v = atomic_load_explicit(&g->slots[pos], memory_order_relaxed);
    bool claimed = false;
    for (unsigned k = 0; k < ntaken && !claimed; k++) claimed = taken[k] == pos;
    if (claimed) {
      if (++pos == n) pos = 0;
      continue;
    }
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

/* the descriptor of an open segment file of `size` bytes (MAP mode: mapped read only, the whole file); NULL when it cannot be mapped (the caller closes fd) */
static seg_t *seg_wrap(const store_t *s, int fd, uint32_t n, size_t size) {
  seg_t *g = calloc(1, sizeof(*g));
  if (!g) return NULL;
  g->fd = fd;
  g->num = n;
  if (s->mode == STORE_MODE_MAP) {
    g->maplen = size;
    void *p = g->maplen ? mmap(NULL, g->maplen, PROT_READ, MAP_SHARED | ST_NOCORE | ST_PREFAULT, fd, 0) : MAP_FAILED;
    if (p == MAP_FAILED) { free(g); return NULL; }
    g->map = p;
  }
  return g;
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
        g = seg_wrap(s, fd, n, (size_t)st.st_size);
        if (g) atomic_store_explicit(&s->segs[n], g, memory_order_release);
      }
      if (!g) close(fd);
    }
  }
  pthread_mutex_unlock(&s->seg_mu);
  return g;
}
/* Make the file of segment n with room for at least `cap` bytes (the header; MAP mode: its full size, sparse); the open descriptor, or -errno.  The directory entry is not made durable here: the
 * caller sets dir_dirty (the next commit syncs the directory before the journal that names the file, commit_sync()). */
static int seg_file_new(store_t *s, uint32_t n, uint64_t cap) {
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
  return fd;
}
/* writer (the mutex held): create segment n with room for at least `cap` bytes, when none was made ahead (seg_pre_take()); the time it takes is inside the mutex: store.segment.inline_creates */
static int seg_create(store_t *s, uint32_t n, uint64_t cap) {
  s->seg_draining[n] = 0;                              /* (a removal that waited for the journal (3) does not unlink the new file: N8) */
  const uint64_t t0 = st_now_us();
  AHEAD_HOOK(s, 3);
  const int fd = seg_file_new(s, n, cap);
  if (fd < 0) return fd;
  s->dir_dirty = true;
  seg_t *old = atomic_load_explicit(&s->segs[n], memory_order_relaxed);
  if (old) { atomic_store_explicit(&s->segs[n], NULL, memory_order_release); retire_add_seg(s, old); }       /* (a reader or a commit may still hold it) */
  close(fd);
  const uint64_t us = st_now_us() - t0;
  atomic_fetch_add_explicit(&s->n_seg_inline, 1, memory_order_relaxed);
  if (us > atomic_load_explicit(&s->n_seg_inline_max_us, memory_order_relaxed)) atomic_store_explicit(&s->n_seg_inline_max_us, us, memory_order_relaxed);       /* (the writer mutex: one writer) */
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* journal builder                                                                                                      */
/* ------------------------------------------------------------------------------------------------------------------ */

static void jb_reset(jb_t *j) {
  j->len = ST_JREC_HDR;
  j->nops = 0;
  j->nv = 0;
  j->npl = 0;
}
/* note an index change of the record (rgent_t); -ENOMEM when the record has too many (it is cut: a group is written first) */
static int jb_pl(jb_t *j, uint8_t which, bool ins, uint64_t h, uint32_t z) {
  if (j->npl >= JB_MAXPL) return -ENOMEM;
  rgent_t *e = &j->pl[j->npl++];
  e->h = h;
  e->z = z;
  e->which = which;
  e->ins = ins ? 1 : 0;
  e->pad = 0;
  return 0;
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
  s->tabgen++;
  if (old) retire_add(s, old);
  return 0;
}

/* Apply one record's ops.  Returns 0, or -EINVAL when an op does not fit the store (a replay then asks for a rebuild).
 * MEMORY ORDER (rule T): called after journal_reserve_locked() made its release fence (or at the open, with no checkpoint running).  Every store into a table that a checkpoint
 * copies is an atomic word store (zrec_write(), nx_write(), the slots of OP_IX / OP_SX below): keep it so; see "The journal ring". */
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
      nx_write(s, o, p + 16, n);
      uint64_t cur = atomic_load_explicit(&s->nx_avail, memory_order_relaxed);
      if (o + n > cur) atomic_store_explicit(&s->nx_avail, o + n, memory_order_release);
      break;
    }
    case OP_NXMOVE: {            /* the nx pass: a long name moves to a new offset, with the cell that names the offset */
      uint32_t z, kl;
      uint64_t o;
      if (pl < 16 + 128) { bad = -EINVAL; break; }
      memcpy(&z, p, 4);
      memcpy(&kl, p + 4, 4);
      memcpy(&o, p + 8, 8);
      if (kl <= ST_NAME_INL || kl > STORE_NAME_MAX || (uint64_t)kl + 16 + 128 > pl || (uint64_t)z >= s->zt.reserve / ST_REC || o > s->nx.reserve ||
          kl > s->nx.reserve - o || ensure_zt_cap(s, (uint64_t)z + 1) < 0 || ensure_nx_cap(s, o + kl) < 0) { bad = -EINVAL; break; }
      r64_t zt, zc;
      memcpy(&zt, p + 16, 64);
      memcpy(&zc, p + 80, 64);
      zrec_write_nx(s, z, &zt, &zc, o, p + 144, kl);
      uint64_t cur = atomic_load_explicit(&s->nx_avail, memory_order_relaxed);
      if (o + kl > cur) atomic_store_explicit(&s->nx_avail, o + kl, memory_order_release);
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
        dm_mark(&g->d, pos * 8, 8);
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
      /* Only a replay meets this op (the growth writes it without applying it: rg_publish_locked()).  The file of the new generation holds what a checkpoint wrote to it, and nothing
       * when none followed the growth before the stop (the tables are private memory): the generation is switched to, so that the ops after it fit, and the open rebuilds the derived
       * tables from zt (-EINVAL: the anomaly) */
      if (which <= 1 && switch_gen(s, which, gen, ns) == 0) s->rec.gen_replays++;
      bad = -EINVAL;
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

/* create (or empty) journal file `gen`: the next checkpoint switches to it (journal_switch_locked() writes its header).  A file with no header ends the chain that a replay reads. */
static int journal_create(store_t *s, uint32_t gen) {
  char name[32];
  st_name_ix(name, sizeof(name), "jrn", gen);
  int fd = st_openat(s, name, O_RDWR | O_CREAT | O_TRUNC);
  if (fd < 0) return fd;
  s->dir_dirty = true;
  return fd;
}

/* ---- the journal ring (0.7: the record is written after the writer mutex) ----
 *
 * Under the writer mutex a writer plans its record, gives it its LSN and its place (journal_reserve_locked()): the bytes are copied into the ring at jr_head, a byte position that
 * also says where they go (the extent the position is in: a journal file and its offset), and the ops are applied.  After the mutex, the first thread that needs the ring written
 * up to some position is the leader (jw_wait()): it pwrite()s every byte published when it starts, in order, one span (the bytes of one extent, at most JW_RUN) per call; the others
 * wait, or lead the next round.  The flusher leads for the threads that do not wait (store_defer()).  A switch of the journal file begins an extent whose first bytes are the new
 * file's header, so the header is in the kernel before any record of its file, and nothing after an unwritten header is written.  The rules that make this exact (planning
 * planing_0.7.x_store_journal_offlock.md):
 *   T  (tables never ahead of the kernel's journal, N1): a checkpoint pwrite()s a copied run of table pages only after jr_tail has passed the jr_pub it reads after the copy
 *      (ck_write_tab()).  The pairing: a writer publishes jr_pub, then atomic_thread_fence(release), then its apply stores; the checkpoint copies, atomic_thread_fence(acquire),
 *      then reads jr_pub.  If the copy read a word that an apply wrote, the fences synchronize and the jr_pub it reads covers that record (C11 7.17.4).
 *      THIS NEEDS EVERY STORE INTO A TABLE THAT A CHECKPOINT COPIES TO BE AN ATOMIC WORD STORE MADE AFTER THE FENCE OF ITS RECORD (apply_ops(), zrec_write(), nx_write()): a
 *      plain store, or one made before the fence, breaks it silently (TSan does not model fences fully and x86 is TSO: no test on the build hosts would show it).
 *   A  (acknowledged = in the kernel, N3): a writer call returns only after jr_tail passed jr_head as it was at the call's unlock (wr_done(), wr_ack()): its own records and
 *      every record it planned on; a thread that defers (store_defer()) is acknowledged by a later wait (store_settle(), a commit).
 *   F  (fd lifetime): a journal fd is synced and closed only after jr_tail passed the last byte that goes to it (the commit and the checkpoint wait for the position taken
 *      under the mutex after their switch; jold keeps jold_end).
 *   N2 the kernel's journal is the ring's byte stream up to jr_tail, file by file, plus at most a torn span: every prefix is a consistent state, journal_replay() is unchanged.
 *   N4 images are in the kernel before the record that points at them is reserved (st_prewrite(), the append in put_locked()); N5 a commit syncs only written bytes.
 * A write that fails: ENOSPC -> JW_NOSPACE (the flusher's jw_retry() rewrites the span until it passes; every other wait and every new record gets -ENOSPC at once, so nobody
 * waits with a lock while the disk is full); another error -> three tries, then JW_FAILED (no more records, no table page, no clean checkpoint; a restart replays the written
 * prefix).  The span is rewritten whole at the same offset: its bytes do not change in the ring. */

#ifdef KARIDNS_UNIT_TEST
int (*_Atomic store_test_jw_fault)(uint64_t pos, uint64_t len) = NULL;
void (*_Atomic store_test_jw_hook)(store_t *s, int step) = NULL;
_Atomic bool store_test_no_rule_t = false;
_Atomic uint64_t store_test_jr_cap = 0;
_Atomic uint32_t store_test_jx_cap = 0;
_Atomic uint64_t store_test_fl_loops = 0;
void (*_Atomic store_test_fl_ckpt_hook)(int step) = NULL;
_Atomic uint32_t store_test_jw_run = 0;
void store_test_probe(store_t *s) { fs_probe(s); }
static void bg_stop_join(store_t *s);
void store_test_stop_flusher(store_t *s) { bg_stop_join(s); }
int store_test_dirfd_of(store_t *s) { return s->dirfd; }
_Atomic int64_t store_test_jr_floor = -1;
int64_t (*_Atomic store_test_fs_total)(void) = NULL;
static int jw_fault_now(uint64_t p, uint64_t n) { int (*f)(uint64_t, uint64_t) = atomic_load(&store_test_jw_fault); return f ? f(p, n) : 0; }
static void jw_hook_now(store_t *s, int k) { void (*f)(store_t *, int) = atomic_load(&store_test_jw_hook); if (f) f(s, k); }
#define JW_FAULT(p, n) jw_fault_now((p), (n))
#define JW_HOOK(s, k) jw_hook_now((s), (k))
#define RULE_T_OFF() atomic_load_explicit(&store_test_no_rule_t, memory_order_relaxed)
#else
#define RULE_T_OFF() false
#define JW_FAULT(p, n) 0
#define JW_HOOK(s, k) ((void)0)
#endif

static int st_pwritev_all(int fd, const struct iovec *iov, int niov, uint64_t rlen, off_t off);
static void fs_probe(store_t *s);
static void space_used(store_t *s, uint64_t n);
static inline bool is_nospc_err(int r) { return r == -ENOSPC || r == -EFBIG || r == -EDQUOT; }

/* the bytes [p, p + n) of the ring to fd at foff (two pieces at the wrap); the whole span or an error (a short write is continued by st_pwritev_all()) */
static int jr_write_span(store_t *s, int fd, uint64_t foff, uint64_t p, uint64_t n) {
  const int f = JW_FAULT(p, n);
  if (f > 0) return -f;
  uint64_t len = f < 0 ? n / 2 : n;                    /* (f < 0, the tests: half of the span reaches the file, then the write fails) */
  const uint64_t o = p % s->jr_cap, a = s->jr_cap - o < len ? s->jr_cap - o : len;
  struct iovec v[2] = { { s->jr_buf + o, (size_t)a }, { s->jr_buf, (size_t)(len - a) } };
  const int r = len ? st_pwritev_all(fd, v, a < len ? 2 : 1, len, (off_t)foff) : 0;
  return f < 0 ? -EIO : r;
}

/* One round of the leader (jw_leader held, no lock): every byte published when it starts.  jr_tail moves to the end of each span written whole; an error stops the round with
 * jr_tail at the start of the span that failed (the retry writes all of it again). */
static int jw_round(store_t *s) {
  const uint64_t end = atomic_load_explicit(&s->jr_pub, memory_order_acquire), xn = atomic_load_explicit(&s->jx_pub, memory_order_acquire);
  uint64_t p = atomic_load_explicit(&s->jr_tail, memory_order_relaxed), k = atomic_load_explicit(&s->jx_done, memory_order_relaxed);
  int r = 0;
  JW_HOOK(s, 1);
  while (p < end && r == 0) {
    while (k + 1 < xn && s->jx[(k + 1) % JX_CAP].pos <= p) k++;
    const jr_ext_t *e = &s->jx[k % JX_CAP];
    uint64_t stop = end;
    if (k + 1 < xn && s->jx[(k + 1) % JX_CAP].pos < stop) stop = s->jx[(k + 1) % JX_CAP].pos;
    uint64_t run = JW_RUN;
#ifdef KARIDNS_UNIT_TEST
    if (atomic_load_explicit(&store_test_jw_run, memory_order_relaxed)) run = atomic_load_explicit(&store_test_jw_run, memory_order_relaxed);
#endif
    const uint64_t n = stop - p > run ? run : stop - p;
    const uint64_t t0 = st_now_us();
    r = jr_write_span(s, e->fd, e->foff + (p - e->pos), p, n);
    if (r < 0) break;
    const uint64_t us = st_now_us() - t0;
    if (us > atomic_load_explicit(&s->jw_write_max_us, memory_order_relaxed)) atomic_store_explicit(&s->jw_write_max_us, us, memory_order_relaxed);   /* (the leader: one writer) */
    atomic_fetch_add_explicit(&s->n_jw_writes, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->n_jw_bytes, n, memory_order_relaxed);
    p += n;
    CRASH_POINT();
    atomic_store_explicit(&s->jr_tail, p, memory_order_release);
    JW_HOOK(s, 2);
  }
  while (k + 1 < xn && s->jx[(k + 1) % JX_CAP].pos <= p) k++;
  atomic_store_explicit(&s->jx_done, k, memory_order_release);           /* (the extents before k are written: their slots may be used again) */
  return r;
}

static void jw_log_state(store_t *s, int st, int err);
/* After a failed round (jw_leader held, no lock): ENOSPC -> JW_NOSPACE at once (jw_retry() is the flusher's); another error: the round again, three times 100 ms apart, then
 * JW_FAILED.  0: a retry passed. */
static int jw_after_error(store_t *s, int r) {
  for (int k = 0; k < 3 && r < 0 && !is_nospc_err(r); k++) {
    usleep(100000);
    atomic_fetch_add_explicit(&s->n_jw_retries, 1, memory_order_relaxed);
    r = jw_round(s);
  }
  if (r == 0) return 0;
  const int st = is_nospc_err(r) ? JW_NOSPACE : JW_FAILED;
  atomic_store_explicit(&s->jw_last_err, -r, memory_order_relaxed);
  if (st == JW_FAILED) { atomic_store_explicit(&s->jw_fail_unix, (uint64_t)time(NULL), memory_order_relaxed); }
  atomic_store_explicit(&s->jw_state, st, memory_order_release);
  jw_log_state(s, st, -r);
  return r;
}

/* Wait until the ring is written up to pos (no lock but the writer mutex in jw_drain_locked(), the order wlock -> jw_mu): 0; -ENOSPC in JW_NOSPACE and -EIO in JW_FAILED at
 * once (the outcome of the bytes is unknown: they may be written later by jw_retry(), or never); -ECANCELED when *cancel is set (a checkpoint that a stop leaves). */
static int jw_wait(store_t *s, uint64_t pos, const _Atomic bool *cancel) {
  if (atomic_load_explicit(&s->jr_tail, memory_order_acquire) >= pos) return 0;
  int r = 0;
  pthread_mutex_lock(&s->jw_mu);
  while (atomic_load_explicit(&s->jr_tail, memory_order_acquire) < pos) {
    const int st = atomic_load_explicit(&s->jw_state, memory_order_acquire);
    if (st == JW_FAILED) { r = -EIO; break; }
    if (st == JW_NOSPACE) { r = -ENOSPC; break; }
    if (cancel && atomic_load_explicit(cancel, memory_order_relaxed)) { r = -ECANCELED; break; }
    if (s->jw_leader) {
      if (!cancel) pthread_cond_wait(&s->jw_cv, &s->jw_mu);
      else {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_nsec += 20000000;
        if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
        pthread_cond_timedwait(&s->jw_cv, &s->jw_mu, &ts);
      }
      continue;
    }
    s->jw_leader = true;
    pthread_mutex_unlock(&s->jw_mu);
    int w = jw_round(s);
    if (w < 0) w = jw_after_error(s, w);
    pthread_mutex_lock(&s->jw_mu);
    s->jw_leader = false;
    pthread_cond_broadcast(&s->jw_cv);
  }
  pthread_mutex_unlock(&s->jw_mu);
  return r;
}
/* everything reserved is written (writer mutex held: nothing more is reserved meanwhile) */
static int jw_drain_locked(store_t *s) { return jw_wait(s, s->jr_head, NULL); }

/* JW_NOSPACE: one try to write what waits (the flusher, or the tick without one); the state ends when it passes.  An error other than ENOSPC goes the way of jw_after_error(). */
static void jw_retry(store_t *s) {
  if (atomic_load_explicit(&s->jw_state, memory_order_acquire) != JW_NOSPACE) return;
  pthread_mutex_lock(&s->jw_mu);
  if (s->jw_leader) { pthread_mutex_unlock(&s->jw_mu); return; }
  s->jw_leader = true;
  pthread_mutex_unlock(&s->jw_mu);
  atomic_fetch_add_explicit(&s->n_jw_retries, 1, memory_order_relaxed);
  int r = jw_round(s);
  if (r < 0 && !is_nospc_err(r)) r = jw_after_error(s, r);   /* (another error: the three tries of jw_after_error(), in JW_NOSPACE, then JW_FAILED) */
  pthread_mutex_lock(&s->jw_mu);
  if (r == 0) {
    atomic_store_explicit(&s->jw_state, JW_OK, memory_order_release);
    atomic_store_explicit(&s->jw_last_err, 0, memory_order_relaxed);
    s->jr_warn_ms = 0;                                  /* (the next trouble is said at once) */
  }
  s->jw_leader = false;
  pthread_cond_broadcast(&s->jw_cv);
  pthread_mutex_unlock(&s->jw_mu);
  if (r == 0) st_log(s, 5, "store: the journal is written again (the file system has room)");
  else jw_log_state(s, atomic_load_explicit(&s->jw_state, memory_order_relaxed), -r);
}
/* the state's log line: at the change, then at most once a minute (the flusher calls it while the state lasts) */
static void jw_log_state(store_t *s, int st, int err) {
  if (st == JW_OK) return;
  pthread_mutex_lock(&s->jw_mu);
  const uint64_t now = st_now_ms();
  const bool say = s->jr_warn_ms == 0 || now - s->jr_warn_ms >= 60000u;
  if (say) s->jr_warn_ms = now ? now : 1;
  pthread_mutex_unlock(&s->jw_mu);
  if (!say) return;
  const uint64_t wait = atomic_load_explicit(&s->jr_pub, memory_order_relaxed) - atomic_load_explicit(&s->jr_tail, memory_order_relaxed);
  if (st == JW_NOSPACE)
    st_log(s, 4, "store: the journal cannot be written: no space (%d); %" PRIu64 " bytes wait, new records are refused until there is room (store.journal.state=nospace)", err, wait);
  else
    st_log(s, 3, "store: the journal failed (%d) at position %" PRIu64 "; the store takes no writes, %" PRIu64 " bytes are lost; restart the server (store.journal.state=failed)", err,
           atomic_load_explicit(&s->jr_tail, memory_order_relaxed), wait);
}

/* ---- deferral (store_defer()): the threads whose calls do not wait for their bytes ---- */
static int df_slot(const store_t *s) {
  const uintptr_t me = (uintptr_t)pthread_self();
  for (int i = 0; i < ST_DEFER_SLOTS; i++)
    if (atomic_load_explicit(&s->df_tid[i], memory_order_acquire) == me) return i;
  return -1;
}
/* (a lock-free read: only the thread itself sets or clears its slot) */
static int deferred_slot(const store_t *s) {
  if (!s->fl_on || atomic_load_explicit(&s->df_off, memory_order_relaxed)) return -1;
  return df_slot(s);
}
int store_defer(store_t *s, bool on) {
  if (!s) return -EINVAL;
  const int i = df_slot(s);
  if (!on) {
    if (i < 0) return 0;
    atomic_store_explicit(&s->df_pos[i], 0, memory_order_relaxed);
    atomic_store_explicit(&s->df_tid[i], 0, memory_order_release);
    return 0;
  }
  if (i >= 0) return 0;
  if (!s->fl_on || atomic_load_explicit(&s->df_off, memory_order_relaxed)) return -EAGAIN;     /* (no background leader: the calls wait) */
  for (int k = 0; k < ST_DEFER_SLOTS; k++) {
    uintptr_t z = 0;
    if (atomic_compare_exchange_strong_explicit(&s->df_tid[k], &z, (uintptr_t)pthread_self(), memory_order_acq_rel, memory_order_relaxed)) {
      atomic_store_explicit(&s->df_pos[k], 0, memory_order_relaxed);
      return 0;
    }
  }
  atomic_fetch_add_explicit(&s->n_df_busy, 1, memory_order_relaxed);   /* (the calls wait then: counted, store.journal.defer_busy) */
  return -EBUSY;
}
int store_settle(store_t *s) {
  if (!s) return -EINVAL;
  const int i = df_slot(s);
  if (i < 0) return 0;
  return jw_wait(s, atomic_load_explicit(&s->df_pos[i], memory_order_relaxed), NULL);
}
static void bg_signal(store_t *s);
/* The acknowledgement of a writer call (rule A, no lock held): the ring is written up to t, the position at the call's unlock.  A deferring thread only notes t (its settle or
 * a commit waits) and wakes the flusher, the background leader, when nobody writes. */
static int wr_ack(store_t *s, int r, uint64_t t) {
  const int i = deferred_slot(s);
  if (i >= 0) {
    uint64_t c = atomic_load_explicit(&s->df_pos[i], memory_order_relaxed);
    if (t > c) atomic_store_explicit(&s->df_pos[i], t, memory_order_relaxed);
    if (atomic_load_explicit(&s->jr_tail, memory_order_acquire) < t && !atomic_exchange_explicit(&s->jw_kick, true, memory_order_acq_rel)) bg_signal(s);
    return r;
  }
  const int w = jw_wait(s, t, NULL);
  return r >= 0 && w < 0 ? w : r;
}

/* ---- space for the journal (2.7.1 of the plan) ---- */
/* What must stay free below the estimate for a record to be taken: what the running checkpoint may still allocate (ck_left: its taken pages on a copy-on-write file system,
 * the tables' growth otherwise), a slack, and on ZFS the lag of statfs; at most an eighth of the file system (a small one stays usable). */
static uint64_t jr_floor(const store_t *s) {
#ifdef KARIDNS_UNIT_TEST
  if (atomic_load_explicit(&store_test_jr_floor, memory_order_relaxed) >= 0) return (uint64_t)atomic_load_explicit(&store_test_jr_floor, memory_order_relaxed);
#endif
  uint64_t f = atomic_load_explicit(&s->ck_left, memory_order_relaxed) + JR_SLACK + (atomic_load_explicit(&s->cow, memory_order_relaxed) ? JR_ZFS_SLACK : 0);
  const uint64_t total = atomic_load_explicit(&s->fs_total, memory_order_relaxed);
  if (total && f > total / 8) f = total / 8;
  return f;
}

/* The journal goes on in file jrn_gen + 1, whose records start at base_lsn: an extent of the ring begins with the file's header (written by the leader before any record of the
 * file: N2), and the file before stays open in *oldfd for the sync of its last records, which the caller makes only after jr_tail passed the position after the switch (rule F).
 * Writer mutex and the baton held (a checkpoint, or a commit: st_commit()).  The file was made ahead (jnext_fd) when it could be.  ck: a checkpoint's switch (the size of the journal
 * starts again); else a commit's, which only switches to a file made ahead (1: none).  No I/O here but journal_create() when nothing was made ahead (a checkpoint's switch only). */
static int jr_room_locked(store_t *s, uint64_t n, unsigned exts);
static int journal_switch_locked(store_t *s, uint64_t base_lsn, int *oldfd, bool ck) {
  const uint32_t gen = s->jrn_gen + 1;
  if (!(s->jnext_fd >= 0 && s->jnext_gen == gen) && !ck) return 1;
  int r = jr_room_locked(s, ST_JHDR, 1);
  if (r < 0) return r;
  int fd = -1;
  if (s->jnext_fd >= 0 && s->jnext_gen == gen) {
    fd = s->jnext_fd;
    s->jnext_fd = -1;
  } else {
    if (s->jnext_fd >= 0) { close(s->jnext_fd); s->jnext_fd = -1; }
    if ((fd = journal_create(s, gen)) < 0) return fd;
  }
  fhdr_t h;
  fhdr_make(s, &h, FK_JRN, gen, 8, base_lsn);
  uint8_t page[ST_JHDR];
  memset(page, 0, sizeof(page));
  memcpy(page, &h, sizeof(h));
  jr_ext_t *e = &s->jx[s->jx_head % JX_CAP];          /* (jr_room_locked() made sure the slot is free) */
  e->pos = s->jr_head;
  e->foff = 0;
  e->fd = fd;
  s->jx_head++;
  atomic_store_explicit(&s->jx_pub, s->jx_head, memory_order_release);   /* (before jr_pub passes its first byte: the leader finds the extent of every byte it reads) */
  const uint64_t o = s->jr_head % s->jr_cap, a = s->jr_cap - o < ST_JHDR ? s->jr_cap - o : ST_JHDR;
  memcpy(s->jr_buf + o, page, (size_t)a);
  if (a < ST_JHDR) memcpy(s->jr_buf, page + a, (size_t)(ST_JHDR - a));
  s->jr_head += ST_JHDR;
  atomic_store_explicit(&s->jr_pub, s->jr_head, memory_order_release);
  *oldfd = s->jfd;
  s->jfd = fd;
  s->joff = ST_JHDR;
  s->jbytes = ck ? ST_JHDR : s->jbytes + ST_JHDR;
  s->jrn_gen = gen;
  return 0;
}

static void space_checkpoint(store_t *s);
static bool ck_try_locked(store_t *s);
static void bg_release(store_t *s, bool io, bool ck);
static int unclean_now_locked(store_t *s);
static void rg_note_locked(store_t *s, const jb_t *j);
static int wr_lock_at(store_t *s, const char *site);
static int wr_unlock_w(store_t *s);
#define wr_lock(s) wr_lock_at((s), __func__)

/* Room in the ring for n bytes and exts new extents (writer mutex held).  When there is none (a stall longer than the ring: the admission before the mutex keeps this rare) the
 * ring is drained here, inside the mutex: the old behaviour, counted (store.journal.ring_full_in_lock).  -ENOSPC / -EIO in the states that take no record. */
static int jr_room_locked(store_t *s, uint64_t n, unsigned exts) {
  if (n > s->jr_cap / 2) return -EFBIG;                /* (no record is near this: 64 MiB; a test ring is smaller than its records only by mistake) */
  for (;;) {
    const int st = atomic_load_explicit(&s->jw_state, memory_order_acquire);
    if (st == JW_FAILED) return -EIO;
    if (st == JW_NOSPACE) return -ENOSPC;
    if (s->jx_head == 0 && exts == 0) return -EIO;     /* (no journal file yet: the open switches to one before any record) */
    const uint64_t tail = atomic_load_explicit(&s->jr_tail, memory_order_acquire), xd = atomic_load_explicit(&s->jx_done, memory_order_acquire);
    if (s->jr_head + n - tail <= s->jr_cap && s->jx_head - xd + exts < s->jx_cap) return 0;
    atomic_fetch_add_explicit(&s->n_jr_inlock, 1, memory_order_relaxed);
    const int r = jw_drain_locked(s);
    if (r < 0) return r;
  }
}

/* The journal's room on the file system (writer mutex held, before anything is applied): the estimate less jr_floor().  Refused: the file system is probed again here (only
 * when it is nearly full) before -ENOSPC. */
/* The probe again inside the mutex (the deviation from the plan's "unlock, probe, retry", planning 10.4): only when the estimate says that the call does not fit, i.e. the
 * file system is within the call's size of the threshold or below it (nearly full), and at most once every 100 ms; counted (store.space.reprobe_in_lock).  Elsewhere the probe is
 * made before the mutex (st_probe_stale()).  The emergency cleaning keeps its own probe. */
static void st_reprobe_locked(store_t *s) {
  if (st_now_ms() - atomic_load_explicit(&s->last_probe_ms, memory_order_relaxed) < 100) return;
  atomic_fetch_add_explicit(&s->n_reprobe_lock, 1, memory_order_relaxed);
  fs_probe(s);
}
static int jr_space_locked(store_t *s, uint64_t n) {
  if (s->in_cleaner) { space_used(s, n); return 0; }   /* (the cleaner's records make room: not refused, as its appends are not; planning 10.4) */
  int64_t est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  if (est >= 0 && (uint64_t)est < n + jr_floor(s)) {
    st_reprobe_locked(s);
    est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
    if (est >= 0 && (uint64_t)est < n + jr_floor(s)) return -ENOSPC;
  }
  space_used(s, n);
  return 0;
}

/* Finish the builder's record (counters last), give it its LSN and CRC, and reserve its place: the bytes go into the ring (the leader writes them after the mutex).  The cells
 * are not touched; the caller applies the ops after this returns (and after the release fence of rule T, made here). */
static int journal_reserve_locked(store_t *s) {
  jb_t *j = &s->jb;
  const int st = atomic_load_explicit(&s->jw_state, memory_order_acquire);
  if (st == JW_FAILED) return -EIO;                    /* (every writer, also those that take the mutex with wr_lock_raw(): nothing more is planned on a journal that failed) */
  if (st == JW_NOSPACE) return -ENOSPC;
  int r = jb_flush_v(j);
  if (r < 0) return r;
  /* the last checkpoint on disk says "clean stop" (store_checkpoint_clean()) and this is a change after it: the flag is cleared durably first, as the open does
   * (a record after a clean flag would not make the next open after a power loss rebuild the tables).  Every writer clears it before it plans a record (wr_lock()):
   * this is the guard for a path that did not. */
  if (s->clean_on_disk) {
    if (!ck_try_locked(s)) return -EAGAIN;
    r = unclean_now_locked(s);
    bg_release(s, true, true);
    if (r < 0) return r;
  }
  if (atomic_load_explicit(&s->bulk, memory_order_relaxed)) {
    /* a bulk fill (THE BULK FILL): the record is not written.  The ops are applied as they are (the caller does it), the pages are marked; no LSN is given (nothing is replayed after a
     * crash: the open goes back to the last bulk checkpoint and rebuilds), so commits, the journal's size and rule T have nothing to do with it */
    atomic_fetch_add_explicit(&s->n_bulk_unlogged, 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_release);
    CRASH_POINT();
    return 0;
  }
  if ((r = jr_space_locked(s, j->len)) < 0) return r;
  if ((r = jr_room_locked(s, j->len, 0)) < 0) {                                       /* (nothing was taken: the estimate gets the bytes back) */
    int64_t c = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
    while (c >= 0 && !atomic_compare_exchange_weak_explicit(&s->avail_est, &c, c + (int64_t)j->len, memory_order_relaxed, memory_order_relaxed)) {}
    return r;
  }
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
  const uint64_t o = s->jr_head % s->jr_cap, a = s->jr_cap - o < j->len ? s->jr_cap - o : j->len;
  memcpy(s->jr_buf + o, j->p, (size_t)a);
  if (a < j->len) memcpy(s->jr_buf, j->p + a, (size_t)(j->len - a));
  s->jr_head += j->len;
  atomic_store_explicit(&s->jr_pub, s->jr_head, memory_order_release);
  s->joff += j->len;
  s->jbytes += j->len;
  if (s->jbytes > atomic_load_explicit(&s->jpeak, memory_order_relaxed)) atomic_store_explicit(&s->jpeak, s->jbytes, memory_order_relaxed);
  const uint64_t unw = s->jr_head - atomic_load_explicit(&s->jr_tail, memory_order_relaxed);
  if (unw > atomic_load_explicit(&s->jr_peak, memory_order_relaxed)) atomic_store_explicit(&s->jr_peak, unw, memory_order_relaxed);
  atomic_store_explicit(&s->lsn, h.lsn, memory_order_relaxed);
  atomic_thread_fence(memory_order_release);           /* rule T: every apply store of this record comes after this fence (and after jr_pub) */
  CRASH_POINT();
  return 0;
}
/* (the record is reserved; a caller that only logs, rg_publish_locked() and store_repair()'s marker, uses this name) */
static int journal_append(store_t *s) { return journal_reserve_locked(s); }

/* log the built record, then apply its ops (and keep its index changes for a growth being built outside the mutex).  The record is in the ring, maybe not in the kernel yet:
 * the tables are private memory, and rule T keeps the table files from getting ahead of the kernel's journal. */
static int journal_commit_apply(store_t *s) {
  int r = journal_reserve_locked(s);
  if (r < 0) return r;
  rg_note_locked(s, &s->jb);
  r = apply_ops(s, s->jb.p + ST_JREC_HDR, s->jb.len - ST_JREC_HDR);
  CRASH_POINT();
  return r;
}


/* ---- the writer mutex: every hold is timed (store.lock.*) ---- */

/* (the site of a hold is the function that took the mutex: wr_lock_raw(), wr_lock() and wr_lock_ck() are macros that pass __func__; the longest hold names it, and a hold of a second
 * or more is logged with it, at most once a minute) */
/* a hold of 1 ms or more, by its function (writer mutex held: the only writer of the table; a reader sees a slot's site before its counts) */
/* the bucket of a time in whole us: 0 .. 7 one each; from 8 us on, the power of two e (2^e <= us) and the three bits below its top bit: (e - 2) x 8 + those bits, up to e = 23 */
unsigned store_fine_bucket_us(uint64_t us) {
  if (us < 8) return (unsigned)us;
  const unsigned e = 63u - (unsigned)__builtin_clzll(us);
  if (e > 23) return STORE_FINE_BUCKETS - 1;
  return (e - 2) * 8u + (unsigned)((us >> (e - 3)) & 7u);
}
static void wl_site_note(store_t *s, const char *site, uint64_t h) {
  for (unsigned i = 0; i < STORE_LOCK_SITES; i++) {
    st_wl_site_t *w = &s->wl_sites[i];
    const char *at = atomic_load_explicit(&w->site, memory_order_relaxed);
    if (!at) atomic_store_explicit(&w->site, at = site, memory_order_release);
    if (at != site) continue;
    atomic_fetch_add_explicit(&w->slow, 1, memory_order_relaxed);
    if (h >= 10000) atomic_fetch_add_explicit(&w->over10, 1, memory_order_relaxed);
    if (h >= 100000) atomic_fetch_add_explicit(&w->over100, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&w->slow_us, h, memory_order_relaxed);
    if (h > atomic_load_explicit(&w->max_us, memory_order_relaxed)) atomic_store_explicit(&w->max_us, h, memory_order_relaxed);
    return;
  }
}
static void wr_lock_raw_at(store_t *s, const char *site) {
  pthread_mutex_lock(&s->wlock);
  s->wl_t0 = st_now_us();
  s->wl_site = site;
  atomic_store_explicit(&s->wl_owner, (uintptr_t)pthread_self(), memory_order_relaxed);
}
#define wr_lock_raw(s) wr_lock_raw_at((s), __func__)
static void wr_unlock_raw(store_t *s) {
  const uint64_t h = st_now_us() - s->wl_t0;
  const char *site = s->wl_site;
  atomic_fetch_add_explicit(&s->wl_n, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->wl_fine[store_fine_bucket_us(h)], 1, memory_order_relaxed);
  if (h >= 1000) atomic_fetch_add_explicit(&s->wl_slow, 1, memory_order_relaxed);
  if (h > atomic_load_explicit(&s->wl_max_us, memory_order_relaxed)) {       /* (every writer of the two holds the mutex) */
    atomic_store_explicit(&s->wl_max_us, h, memory_order_relaxed);
    atomic_store_explicit(&s->wl_max_site, site, memory_order_relaxed);
  }
  if (h >= 1000) wl_site_note(s, site, h);
  bool say = false;
  if (h >= 1000000u) {
    const uint64_t now = st_now_ms();
    say = s->wl_log_ms == 0 || now - s->wl_log_ms >= 60000u;
    if (say) s->wl_log_ms = now ? now : 1;
  }
  retire_t *const rf = s->rq_free;                    /* (retire_run(): released with the mutex given up) */
  s->rq_free = NULL;
  atomic_store_explicit(&s->wl_owner, 0, memory_order_relaxed);
  pthread_mutex_unlock(&s->wlock);
  retire_free(s, rf);
  if (say) st_log(s, 4, "store: the writer mutex was held for %" PRIu64 " ms by %s (store.lock.writer_hold_max_us)", h / 1000u, site);
}

/* ---- the I/O baton (io_busy: one commit at a time) and the checkpoint flag (ck_busy), under bg_mu ----
 * A thread that does not hold the writer mutex waits for them; one that holds it only tries (ck_try_locked()): the holder of a flag may be waiting for the writer mutex. */

static void bg_signal(store_t *s) {
  pthread_mutex_lock(&s->bg_mu);
  s->bg_kick = true;
  pthread_cond_broadcast(&s->bg_cv);
  pthread_mutex_unlock(&s->bg_mu);
}
/* ---- the helper threads that do the allocations ahead (ahead_t, see store_t): the thread that asks never waits for the disk ---- */
static void ahead_init(ahead_t *a) {
  pthread_condattr_t ca;
  pthread_mutex_init(&a->mu, NULL);
  pthread_condattr_init(&ca);
  pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
  pthread_cond_init(&a->cv, &ca);
  pthread_condattr_destroy(&ca);
  a->kick = a->stop = a->busy = false;
}
static void ahead_destroy(ahead_t *a) {
  pthread_mutex_destroy(&a->mu);
  pthread_cond_destroy(&a->cv);
}
/* ask for a round (coalesced with one that is waiting); busy_kicks (NULL: not counted) counts the asks that find the thread still in the round before: the work lags behind its askers */
static void ahead_kick(ahead_t *a, _Atomic uint64_t *busy_kicks) {
  pthread_mutex_lock(&a->mu);
  if (a->busy && busy_kicks) atomic_fetch_add_explicit(busy_kicks, 1, memory_order_relaxed);
  a->kick = true;
  pthread_cond_signal(&a->cv);
  pthread_mutex_unlock(&a->mu);
}
static void ahead_stop(ahead_t *a) {
  pthread_mutex_lock(&a->mu);
  a->stop = true;
  pthread_cond_signal(&a->cv);
  pthread_mutex_unlock(&a->mu);
}
/* the thread: wait up to `ms` for a kick; false when it has to end.  The round that follows is "busy" until the next call. */
static bool ahead_wait(ahead_t *a, uint64_t ms, bool *kicked) {
  pthread_mutex_lock(&a->mu);
  a->busy = false;
  if (!a->kick && !a->stop) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += (time_t)(ms / 1000u);
    ts.tv_nsec += (long)(ms % 1000u) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    (void)pthread_cond_timedwait(&a->cv, &a->mu, &ts);
  }
  if (kicked) *kicked = a->kick;
  a->kick = false;
  const bool run = !a->stop;
  a->busy = run;
  pthread_mutex_unlock(&a->mu);
  return run;
}
static void baton_take(store_t *s) {
  pthread_mutex_lock(&s->bg_mu);
  while (s->io_busy) pthread_cond_wait(&s->bg_cv, &s->bg_mu);
  s->io_busy = true;
  pthread_mutex_unlock(&s->bg_mu);
}
/* both: a checkpoint (it takes the baton for its first part) */
static void ck_acquire(store_t *s) {
  pthread_mutex_lock(&s->bg_mu);
  while (s->io_busy || s->ck_busy) pthread_cond_wait(&s->bg_cv, &s->bg_mu);
  s->io_busy = s->ck_busy = true;
  pthread_mutex_unlock(&s->bg_mu);
}
static bool ck_try_locked(store_t *s) {
  pthread_mutex_lock(&s->bg_mu);
  const bool ok = !s->io_busy && !s->ck_busy;
  if (ok) s->io_busy = s->ck_busy = true;
  pthread_mutex_unlock(&s->bg_mu);
  return ok;
}
static void bg_release(store_t *s, bool io, bool ck) {
  pthread_mutex_lock(&s->bg_mu);
  if (io) s->io_busy = false;
  if (ck) { s->ck_busy = false; s->ck_ends++; }
  pthread_cond_broadcast(&s->bg_cv);
  pthread_mutex_unlock(&s->bg_mu);
}

/* ---- commit ---- */

/* What a commit covers (writer mutex held): the LSN, the segments written since the last commit (their marks are cleared; io_hold keeps the descriptors), whether the directory has new entries.
 * The journal's fd does not change while the baton is held (a switch needs it). */
static uint32_t commit_capture_locked(store_t *s, seg_t **seg, bool *dir) {
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS), k = 0;
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  for (uint32_t n = 1; n <= nsegs; n++) {
    if (!atomic_exchange_explicit(&s->seg_dirty[n], 0, memory_order_relaxed)) continue;
    seg_t *g = atomic_load_explicit(&s->segs[n], memory_order_relaxed);
    if (g) seg[k++] = g;
  }
  *dir = atomic_exchange_explicit(&s->dir_dirty, false, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->io_hold, 1, memory_order_acq_rel);
  return k;
}

/* The sync of a commit (the baton held; no lock): the segments (an image is durable before the record that points at it), the directory (new files are in it before a record that refers
 * to them is durable), a journal file before a switch whose sync had failed, the journal file fd.  Then committed_lsn = target.  A failure marks the segments and the directory dirty again. */
/* the segments and the directory that a commit took are dirty again (its sync failed, or it did not sync: the journal before its position is not written) */
static void commit_unmark(store_t *s, seg_t *const *seg, uint32_t nseg, bool dir) {
  for (uint32_t k = 0; k < nseg; k++) atomic_store_explicit(&s->seg_dirty[seg[k]->num], 1, memory_order_relaxed);
  if (dir) atomic_store_explicit(&s->dir_dirty, true, memory_order_relaxed);
}
static int commit_sync(store_t *s, uint64_t target, seg_t *const *seg, uint32_t nseg, bool dir, int fd) {
  int r = FAIL_COMMIT() ? -EIO : 0;
  for (uint32_t k = 0; k < nseg && r == 0; k++)
    if (fsync(seg[k]->fd) != 0) r = -errno;
  CRASH_POINT();
  if (r == 0 && dir && fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) r = -errno;
  if (r == 0 && s->jold >= 0) {                      /* (rule F: the callers waited for a position past jold_end) */
    if (fsync(s->jold) != 0) r = -errno;
    else { close(s->jold); s->jold = -1; }
  }
  if (r == 0 && fd >= 0 && fsync(fd) != 0) r = -errno;
  if (r < 0) {
    commit_unmark(s, seg, nseg, dir);
    return r;
  }
  if (target > atomic_load_explicit(&s->committed_lsn, memory_order_relaxed)) atomic_store_explicit(&s->committed_lsn, target, memory_order_release);
  atomic_store_explicit(&s->last_sync_ms, st_now_ms(), memory_order_relaxed);
  atomic_fetch_add_explicit(&s->n_commits, 1, memory_order_relaxed);
  CRASH_POINT();
  return 0;
}

static void note_error(store_t *s, int r);
static void ck_precreate(store_t *s);
/* a journal whose sync failed (the baton held): its bytes are written (rule F), then it is synced and closed */
static int jold_sync(store_t *s) {
  if (s->jold < 0) return 0;
  int r = jw_wait(s, s->jold_end, NULL);
  if (r == 0 && fsync(s->jold) != 0) r = -errno;
  if (r == 0) { close(s->jold); s->jold = -1; }
  return r;
}

/* does a commit switch the journal file?  With the flusher and STORE_SYNC_BATCH (the server): the records of a commit are synced in the file they are in while the writers append to
 * the next one.  (UFS: kern_fsync() holds the file's vnode lock for the whole sync, and an append to that file, inside the writer mutex, waited for it: 0.1 to 0.9 s at 10M zones under
 * load.)  Not after a failed sync (jold is kept: the next commit syncs it first) and not for a file that holds no record.  STORE_SYNC_EVERY syncs every call: its writer waits for the
 * sync anyway, and a file a call would be too many. */
static bool commit_switches(const store_t *s) {
  return s->fl_on && s->o.sync_policy == STORE_SYNC_BATCH && s->jold < 0 && s->joff > ST_JHDR;
}

/* Make every record up to `target` durable (no lock held).  Callers that come together share one sync: the second finds its LSN covered.  The journal goes on in the file made ahead
 * (commit_switches()), the one with the records up to the target is synced and closed, and the next file is made ahead while the baton is held (ck_precreate()).
 * need_gen (not 0): the journal file of that generation is to be durable (a fuzzy checkpoint's, before its superblock names it: ck_io_super()); when it is the one the writers append to,
 * the commit switches the journal on even with no record in it (if it can), so that the sync is of a file that nobody appends to. */
static int st_commit_ex(store_t *s, uint64_t target, uint32_t need_gen) {
  if (!need_gen && atomic_load_explicit(&s->committed_lsn, memory_order_acquire) >= target) return 0;
  baton_take(s);
  int r = 0;
  if (need_gen ? s->jrn_synced < need_gen : atomic_load_explicit(&s->committed_lsn, memory_order_acquire) < target) {
    wr_lock_raw(s);
    const uint64_t t = s->lsn;
    const uint32_t gen = s->jrn_gen;                  /* (the file the sync below is of: the one before a switch, or the current one) */
    int oldfd = -1;
    const bool sw = need_gen ? s->jold < 0 && gen == need_gen : commit_switches(s);
    if (sw && journal_switch_locked(s, t + 1, &oldfd, false) == 0) {
      atomic_fetch_add_explicit(&s->n_jswitch, 1, memory_order_relaxed);
      CRASH_POINT();
      st_hook(&store_test_commit_hook, 1);
    } else {
      oldfd = -1;
    }
    bool dir;
    const uint32_t n = commit_capture_locked(s, s->cm.seg, &dir);
    const int fd = oldfd >= 0 ? oldfd : s->jfd;
    const uint64_t E = s->jr_head;                    /* (rule F, N5: the records <= t, the old file's last bytes and the new file's header are below it) */
    wr_unlock_raw(s);
    r = jw_wait(s, E, need_gen ? &s->ck_cancel : &s->bg_stop_a);   /* (-ENOSPC / -EIO at once in the states that write nothing; -ECANCELED at a stop: no sync of bytes that are not written) */
    if (r < 0) commit_unmark(s, s->cm.seg, n, dir);
    else r = commit_sync(s, t, s->cm.seg, n, dir, fd);
    if (r == 0 && gen > s->jrn_synced) s->jrn_synced = gen;     /* (a kept jold, an older file, was synced first by commit_sync()) */
    if (oldfd >= 0) {
      st_hook(&store_test_commit_hook, 2);
      if (r == 0) close(oldfd);
      else { s->jold = oldfd; s->jold_end = E; }    /* (jold was free: commit_switches(); rule F: its bytes end at E) */
    }
    atomic_fetch_sub_explicit(&s->io_hold, 1, memory_order_acq_rel);
  }
  if (s->fl_on && s->o.sync_policy == STORE_SYNC_BATCH) {
    ck_precreate(s);
    st_hook(&store_test_commit_hook, 3);
  }
  bg_release(s, true, false);
  if (r < 0) note_error(s, r);
  return r;
}
static int st_commit(store_t *s, uint64_t target) { return st_commit_ex(s, target, 0); }

/* ------------------------------------------------------------------------------------------------------------------ */
/* superblock                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

static const char *const st_sb_names[2] = { "super.a", "super.b" };

/* (bulk_ck: a bulk checkpoint's superblock: its ix / sx are not written; the flags of the bulk fill come from the store) */
static void sb_fill(store_t *s, sb_t *b, bool clean, uint64_t seq, uint32_t jrn_gen, bool bulk_ck) {
  memset(b, 0, sizeof(*b));
  memcpy(b->f.magic, "KARISTOR", 8);
  b->f.version = STORE_FORMAT_VERSION;
  b->f.size = ST_SB_SIZE;
  b->f.seq = seq;
  memcpy(b->f.uuid, s->uuid, 16);
  b->f.hk0 = s->hk0;
  b->f.hk1 = s->hk1;
  b->f.flags = clean ? SBF_CLEAN : 0;
  if (atomic_load_explicit(&s->bulk, memory_order_relaxed))
    b->f.flags |= SBF_BULK | (bulk_ck ? SBF_BULK_CK : 0) | (atomic_load_explicit(&s->bulk_passed, memory_order_relaxed) ? SBF_BULK_PASSED : 0);
  if (atomic_load_explicit(&s->bulk_cut, memory_order_relaxed)) b->f.flags |= SBF_BULK_CUT;
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
  b->f.rsv[0] = atomic_load_explicit(&s->sc_last_done, memory_order_relaxed);      /* the end of the last scrub pass (unix time) */
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
/* write the superblock copy in s->sbbuf (sb_fill()) to the slot that is next, and sync it (ck_busy: the superblock is the checkpoint's) */
static int sb_store(store_t *s) {
  const int slot = s->sb_next;
  int r = st_pwrite_all(s->sb_fd[slot], s->sbbuf, ST_SB_SIZE, 0);
  if (r == 0 && fsync(s->sb_fd[slot]) != 0) r = -errno;
  if (r < 0) return r;
  s->sb_seq = s->sbbuf->f.seq;
  s->slot_jrn[slot] = s->sbbuf->f.jrn_gen;
  s->slot_ix[slot] = s->sbbuf->f.ix_gen;            /* (the generations of the copy: a fuzzy checkpoint names those of its position) */
  s->slot_sx[slot] = s->sbbuf->f.sx_gen;
  s->sb_next = slot ^ 1;
  return 0;
}
static int sb_write(store_t *s, bool clean, uint32_t jrn_gen) {
  sb_fill(s, s->sbbuf, clean, s->sb_seq + 1, jrn_gen, false);
  return sb_store(s);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* checkpoint                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

static void unlink_old_gens(store_t *s) {
  struct { const char *base; uint32_t a, b; } k[3] = {
    { "jrn", s->slot_jrn[0], s->slot_jrn[1] }, { "ix", s->slot_ix[0], s->slot_ix[1] }, { "sx", s->slot_sx[0], s->slot_sx[1] } };
  for (int i = 0; i < 3; i++) {
    uint32_t lo = k[i].a < k[i].b ? k[i].a : k[i].b;
    if (i == 0) {                                     /* the journal: every file below the older copy's (a commit switches it: many files between two checkpoints) */
      for (uint32_t g = s->jrn_gone; g < lo; g++) {
        char name[32];
        st_name_ix(name, sizeof(name), k[i].base, g);
        if (unlinkat(s->dirfd, name, 0) == 0) s->dir_dirty = true;
      }
      if (lo > s->jrn_gone) s->jrn_gone = lo;
      continue;
    }
    for (uint32_t g = lo; g > 1 && lo - g < 8; ) {
      g--;
      char name[32];
      st_name_ix(name, sizeof(name), k[i].base, g);
      if (unlinkat(s->dirfd, name, 0) == 0) s->dir_dirty = true;
    }
  }
}

/* The begin of a checkpoint (writer mutex, ck_busy and the baton held): its position P is the last LSN; the journal goes on in the next file (records > P); the superblock as of P is made
 * in s->sbbuf (counters, views, cursors, the index generations of P); what the commit of P has to sync is taken (the dirty segments, the old journal's fd), and the index generations that
 * the flush syncs.  io_hold keeps all of it from being freed until ck_run() / ck_full_locked() is done with it.  No wait for the disk here. */
static int ck_take_locked(store_t *s);
static void ck_merge_locked(store_t *s);
static void ck_drop_taken(store_t *s);
static void ck_alloc_plan_locked(store_t *s);
static uint64_t st_seg_bytes(const store_t *s);
/* fuzzy: the writers go on while it writes (not ck_full_locked()); one begun during a bulk fill is a bulk checkpoint: ix / sx are not taken (their pages stay marked for the checkpoint that
 * ends the fill, a generation made during the fill is written whole by it) and its superblock says SBF_BULK_CK */
static int ck_begin_locked(store_t *s, bool clean, bool fuzzy) {
  const uint64_t P = s->lsn;
  s->ck.bulk = fuzzy && atomic_load_explicit(&s->bulk, memory_order_relaxed);
  s->ck.bulk_seg = s->ck.bulk ? st_seg_bytes(s) : 0;
  s->ck.ix = s->ck.bulk ? NULL : atomic_load_explicit(&s->ix, memory_order_relaxed);
  s->ck.sx = s->ck.bulk ? NULL : atomic_load_explicit(&s->sx, memory_order_relaxed);
  int r = ck_take_locked(s);                         /* (the pages the writers changed up to P) */
  if (r < 0) return r;
  int oldfd = -1;
  r = journal_switch_locked(s, P + 1, &oldfd, true);
  if (r < 0) { ck_merge_locked(s); return r; }
  CRASH_POINT();
  s->ck.epos = s->jr_head;                          /* (rule F: the records <= P and the new file's header are below it; ck_io_commit() waits for it) */
  ck_alloc_plan_locked(s);
  atomic_store_explicit(&s->ck_want, false, memory_order_relaxed);
  sb_fill(s, s->sbbuf, clean, s->sb_seq + 1, s->jrn_gen, s->ck.bulk);
  s->ck.nseg = commit_capture_locked(s, s->ck.seg, &s->ck.dir);           /* (io_hold + 1) */
  s->ck.lsn = P;
  s->ck.t0 = st_now_us();
  s->ck.clean = clean;
  s->ck.oldfd = oldfd;
  s->ck.newfd = s->jfd;
  s->ck.gen = s->jrn_gen;
  return 0;
}

/* the records up to P are durable: the segments, the journal before the switch (the baton held).  First the ring is written up to the position after the switch (rule F; with
 * the writers kept out, full, this is the drain after ck_begin_locked()); a fuzzy checkpoint leaves that wait at a stop (ck_cancel).  If either fails the old journal stays open
 * (jold, with its end: its bytes may still be written by the flusher's jw_retry()) and the next commit syncs it. */
static int ck_io_commit(store_t *s, bool full) {
  int r = jw_wait(s, s->ck.epos, full ? NULL : &s->ck_cancel);
  if (r < 0) commit_unmark(s, s->ck.seg, s->ck.nseg, s->ck.dir);
  else r = commit_sync(s, s->ck.lsn, s->ck.seg, s->ck.nseg, s->ck.dir, s->ck.oldfd);
  if (s->ck.oldfd >= 0) {
    if (r == 0) close(s->ck.oldfd);
    else { s->jold = s->ck.oldfd; s->jold_end = s->ck.epos; }   /* (jold was free: a checkpoint does not begin while one is kept) */
    s->ck.oldfd = -1;
  }
  /* with the writers kept out (full): the file the superblock names (its header) and its directory entry are durable now; a fuzzy checkpoint leaves that to ck_io_super() */
  if (r == 0 && full) {
    if (fsync(s->ck.newfd) != 0) r = -errno;
    else if (fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) r = -errno;
    else if (s->ck.gen > s->jrn_synced) s->jrn_synced = s->ck.gen;
  }
  return r;
}

/* ---- the write of the tables (0.7: the tables in private memory) ----
 * Table i of a checkpoint: 0 zt, 1 zc, 2 nx, 3 / 4 the ix / sx generation of P (s->ck.ix / ck.sx). */

#define ST_CK_RUN (1u << 20)                /* the longest run of pages copied and written at once (ck_buf holds two: zt and zc, ck_write_cells()) */

static dmap_t *ck_dmap(store_t *s, int i) {
  switch (i) {
  case 0: return &s->zt.d;
  case 1: return &s->zc.d;
  case 2: return &s->nx.d;
  case 3: return s->ck.ix ? &s->ck.ix->d : NULL;
  default: return s->ck.sx ? &s->ck.sx->d : NULL;
  }
}
/* The begin of a checkpoint takes the pages the writers changed (writer mutex, ck_busy): each table's dirty bitmap is the checkpoint's now, and the writers mark into a new empty one; a
 * generation made in this session gives its "write all of it".  The sizes as of P: what sb_fill() names.  -ENOMEM: nothing taken. */
static int ck_take_locked(store_t *s) {
  uint64_t *fresh[5] = { NULL, NULL, NULL, NULL, NULL };
  for (int i = 0; i < 5; i++) {
    const dmap_t *d = ck_dmap(s, i);
    if (!d) continue;
    const size_t nw = (size_t)((d->npages + 63) / 64);
    if (!(fresh[i] = calloc(nw ? nw : 1, sizeof(uint64_t)))) {
      for (int k = 0; k < i; k++) free(fresh[k]);
      return -ENOMEM;
    }
  }
  const mtab_t *tabs[3] = { &s->zt, &s->zc, &s->nx };
  for (int i = 0; i < 5; i++) {
    dmap_t *d = ck_dmap(s, i);
    s->ck.t[i].dirty = NULL;
    s->ck.t[i].npages = s->ck.t[i].bytes = 0;
    s->ck.t[i].all = false;
    if (!d) continue;
    s->ck.t[i].dirty = d->dirty;
    s->ck.t[i].npages = d->npages;
    s->ck.t[i].all = d->all;
    s->ck.t[i].bytes = i < 3 ? atomic_load_explicit(&tabs[i]->mapped, memory_order_relaxed) : (i == 3 ? s->ck.ix : s->ck.sx)->maplen;
    d->dirty = fresh[i];
    d->all = false;
  }
  return 0;
}
/* A checkpoint that did not reach its superblock gives the pages back (writer mutex): the next one writes them.  A generation that is no longer the current one is left: the checkpoint
 * that names the one after it writes that one whole. */
static void ck_merge_locked(store_t *s) {
  for (int i = 0; i < 5; i++) {
    uint64_t *t = s->ck.t[i].dirty;
    if (!t) continue;
    dmap_t *d = ck_dmap(s, i);
    const ixgen_t *cur = i == 3 ? atomic_load_explicit(&s->ix, memory_order_relaxed) : i == 4 ? atomic_load_explicit(&s->sx, memory_order_relaxed) : NULL;
    if (i < 3 || (i == 3 ? s->ck.ix : s->ck.sx) == cur) {
      const uint64_t n = s->ck.t[i].npages < d->npages ? s->ck.t[i].npages : d->npages;
      for (uint64_t w = 0; w < (n + 63) / 64; w++) d->dirty[w] |= t[w];
      if (s->ck.t[i].all) d->all = true;
    }
    free(t);
    s->ck.t[i].dirty = NULL;
  }
}
/* What the checkpoint's writes may allocate (writer mutex, after ck_take_locked()): on a copy-on-write file system (ZFS), and for a file whose growth was a sparse ftruncate() (no
 * posix_fallocate(): mtab_t.no_alloc), every byte written takes new blocks; otherwise an overwrite of the file's blocks takes nothing and only the growth past what the file holds
 * allocates.  The sum is ck_left (jr_floor()); ck_write_tab() charges it as it writes (space_used()). */
static void ck_alloc_plan_locked(store_t *s) {
  const mtab_t *tabs[3] = { &s->zt, &s->zc, &s->nx };
  const bool cow = atomic_load_explicit(&s->cow, memory_order_relaxed);
  uint64_t left = 0;
  for (int i = 0; i < 5; i++) {
    s->ck.t[i].cow = false;
    s->ck.t[i].grow = 0;
    if (!s->ck.t[i].dirty) continue;
    const uint64_t bytes = s->ck.t[i].bytes;
    uint64_t taken = 0;
    if (s->ck.t[i].all) taken = bytes;
    else {
      for (uint64_t w = 0; w < (s->ck.t[i].npages + 63) / 64; w++) taken += (uint64_t)__builtin_popcountll(s->ck.t[i].dirty[w]);
      taken <<= s->pgshift;
      if (taken > bytes) taken = bytes;
    }
    const bool sparse = i < 3 ? atomic_load_explicit(&tabs[i]->no_alloc, memory_order_relaxed) : atomic_load_explicit(&s->zt.no_alloc, memory_order_relaxed);
    const uint64_t held = i < 3 ? atomic_load_explicit(&tabs[i]->extended, memory_order_relaxed) : bytes;    /* (a generation's file is extended whole when it is made) */
    s->ck.t[i].cow = cow || sparse;
    s->ck.t[i].grow = bytes > held ? bytes - held : 0;
    left += s->ck.t[i].cow ? taken : s->ck.t[i].grow;
  }
  atomic_store_explicit(&s->ck_left, left, memory_order_relaxed);
}
static void ck_charge(store_t *s, uint64_t n) {        /* (the checkpoint allocated n bytes: the estimate and ck_left follow) */
  if (!n) return;
  space_used(s, n);
  uint64_t c = atomic_load_explicit(&s->ck_left, memory_order_relaxed);
  atomic_store_explicit(&s->ck_left, c > n ? c - n : 0, memory_order_relaxed);     /* (ck_busy: one writer) */
}
static void ck_drop_taken(store_t *s) {
  for (int i = 0; i < 5; i++) {
    free(s->ck.t[i].dirty);
    s->ck.t[i].dirty = NULL;
  }
}
/* A fuzzy checkpoint writes at most ST_CK_RATE bytes a second (0.7): written at full speed, a burst of table pages (a first fill changes every page, a growth's generation is written
 * whole) filled the file system's write queue that the writers' journal appends inside the mutex then waited for (ZFS: the transaction group, txg_wait_synced(), 1.0 to 5.0 s in a 10M
 * first fill; UFS: runningbufspace).  A checkpoint with the writers kept out does not wait (cancel NULL).  (Also tried, not kept: a sleep as long as a slow write, which made the
 * checkpoints of a 10M first start on UFS 60 to 98 s long and left the longest hold where it was; a sync every 64 MiB, which made the 10M first fill on ZFS slower, 371 to 411 s against
 * 316 to 336 s, with no shorter hold.) */
#define ST_CK_RATE (256ull << 20)
static void ck_pace(store_t *s, uint64_t done, const _Atomic bool *cancel) {
  const uint64_t el = st_now_us() - s->ck.tw0, due = done / (ST_CK_RATE / 1000000);
  if (due <= el) return;
  uint64_t nap = due - el > 200000 ? 200000 : due - el;
  atomic_fetch_add_explicit(&s->n_ck_paced_us, nap, memory_order_relaxed);
  while (nap && !atomic_load_explicit(cancel, memory_order_relaxed)) {
    const uint64_t p = nap > 20000 ? 20000 : nap;
    usleep((useconds_t)p);
    nap -= p;
  }
}
/* Write the pages of table i that the checkpoint took (no lock: the writers go on).  A run of pages is copied into ck_buf with word loads (the writers store words into those pages
 * meanwhile: a copy may hold the effect of records after P, which the replay from P makes right again, see "The tables in private memory") and written with pwrite(); the page that
 * a writer stores into is never the page the kernel writes out.  Then the file is extended to the size of P and synced.  *done: the bytes written. */
/* the end of a table's write: the file is extended to the size of P and synced (when anything was written to it) */
static int ck_tab_end(int fd, uint64_t bytes, bool wrote) {
  struct stat st;
  if (fstat(fd, &st) != 0) return -errno;
  if ((uint64_t)st.st_size < ST_HDR_PAGE + bytes) {
    int r = st_extend(fd, st.st_size, (off_t)(ST_HDR_PAGE + bytes));
    if (r < 0) return r;
    wrote = true;
  }
  if (wrote && fsync(fd) != 0) return -errno;
  return 0;
}
static int ck_write_tab(store_t *s, int i, int fd, const uint8_t *base, const _Atomic bool *cancel, uint64_t *done) {
  const uint64_t *dirty = s->ck.t[i].dirty, bytes = s->ck.t[i].bytes;
  const bool all = s->ck.t[i].all;
  uint64_t np = bytes >> s->pgshift;
  if (!all && np > s->ck.t[i].npages) np = s->ck.t[i].npages;
  const uint64_t run_max = ST_CK_RUN >> s->pgshift;
  bool wrote = false;
  if (!s->ck.t[i].cow) ck_charge(s, s->ck.t[i].grow);    /* (an overwrite takes no blocks here: only the growth past the file's end does) */
  for (uint64_t p = 0; p < np; ) {
    if (!all && dirty[p >> 6] == 0) { p = (p | 63) + 1; continue; }
    if (!all && !((dirty[p >> 6] >> (p & 63)) & 1)) { p++; continue; }
    const uint64_t start = p;
    while (p < np && p - start < run_max && (all || ((dirty[p >> 6] >> (p & 63)) & 1))) p++;
    const size_t len = (size_t)((p - start) << s->pgshift);
    const _Atomic uint64_t *src = (const _Atomic uint64_t *)(base + (start << s->pgshift));
    uint64_t *dst = (uint64_t *)s->ck_buf;
    for (size_t k = 0; k < len / 8; k++) dst[k] = atomic_load_explicit(&src[k], memory_order_relaxed);
    /* rule T (N1): this copy reaches the file only after the kernel holds the journal up to the jr_pub read after it (the acquire fence pairs with the release fence of every
     * record's reservation, journal_reserve_locked(): if the copy saw a store of a record, that jr_pub covers it).  A checkpoint that the stop leaves ends here (cancel). */
    atomic_thread_fence(memory_order_acquire);
    const uint64_t X = atomic_load_explicit(&s->jr_pub, memory_order_relaxed);
    if (atomic_load_explicit(&s->jr_tail, memory_order_acquire) < X && !RULE_T_OFF()) {
      atomic_fetch_add_explicit(&s->n_ck_twaits, 1, memory_order_relaxed);
      const int w = jw_wait(s, X, cancel);
      if (w < 0) return w;
    }
    if (s->ck.t[i].cow) ck_charge(s, len);
    int r = FAIL_CKWRITE() ? -EIO : st_pwrite_all(fd, s->ck_buf, len, (off_t)(ST_HDR_PAGE + (start << s->pgshift)));
    if (r < 0) return r;
    *done += len;
    wrote = true;
    CRASH_POINT();
    st_hook(&store_test_ckpt_hook, 5);
    if (cancel) ck_pace(s, *done, cancel);
    if (cancel && atomic_load_explicit(cancel, memory_order_relaxed)) return -ECANCELED;
  }
  return ck_tab_end(fd, bytes, wrote);
}

/* zt and zc in lockstep (0.7, every checkpoint): page n of zt and page n of zc hold the cells of the same zone ids (64 bytes a cell in both, from ST_HDR_PAGE in both files), and a zone's pair is
 * one record (its CRC covers both cells).  Copied one table after the other, a pair that a writer changed between the two copies reached the disk torn: zt of one version, zc of another, a CRC that
 * fails, a zone the rebuild drops (a bulk fill cut off after a bulk checkpoint, 678 of 200000 zones; the records past the durable journal after a power loss).  So a run of pages is the run of both
 * tables over the same cells (the union of the two maps: a page of zt and the same page of zc are marked separately), and in a fuzzy checkpoint every pair is copied as a lock-free reader reads it
 * (zrec_read_seq()): the sequence counter in word 7 of the zc cell, odd while a writer is in the pair, read before and after the copy of both cells; a pair that was being written or changed under the
 * copy is copied again (seq_wait(): a spin, a yield, short sleeps; a counter that stays odd for ST_SEQ_GIVEUP_US, which only a crash leaves behind, is copied as it is and the rebuild judges it).
 * With the writers kept out (cancel NULL) no pair changes and the copy is a plain one.  The writes, the pacing and the cancel points are those of ck_write_tab(), with a half of ck_buf (2 x ST_CK_RUN) for each table. */
static int ck_write_cells(store_t *s, const _Atomic bool *cancel, uint64_t *done) {
  const mtab_t *tabs[2] = { &s->zt, &s->zc };
  uint64_t np[2];
  for (int i = 0; i < 2; i++) {
    np[i] = s->ck.t[i].bytes >> s->pgshift;
    if (!s->ck.t[i].all && np[i] > s->ck.t[i].npages) np[i] = s->ck.t[i].npages;
    if (!s->ck.t[i].cow) ck_charge(s, s->ck.t[i].grow);
  }
  const uint64_t npmax = np[0] > np[1] ? np[0] : np[1], run_max = ST_CK_RUN >> s->pgshift, cpp = (uint64_t)s->pagesz / ST_REC;
  uint8_t *const buf[2] = { s->ck_buf, s->ck_buf + ST_CK_RUN };
  bool wrote[2] = { false, false };
#define CK_MARKED(i, p) ((p) < np[(i)] && (s->ck.t[(i)].all || ((s->ck.t[(i)].dirty[(p) >> 6] >> ((p) & 63)) & 1)))
  const bool any_all = s->ck.t[0].all || s->ck.t[1].all;
  for (uint64_t p = 0; p < npmax; ) {
    if (!any_all && (p >= np[0] || !s->ck.t[0].dirty[p >> 6]) && (p >= np[1] || !s->ck.t[1].dirty[p >> 6])) { p = (p | 63) + 1; continue; }     /* (no page of either in this word) */
    if (!CK_MARKED(0, p) && !CK_MARKED(1, p)) { p++; continue; }
    const uint64_t start = p;
    while (p < npmax && p - start < run_max && (CK_MARKED(0, p) || CK_MARKED(1, p))) p++;
    size_t len[2];
    for (int i = 0; i < 2; i++) len[i] = start < np[i] ? (size_t)(((p < np[i] ? p : np[i]) - start) << s->pgshift) : 0;
    const uint64_t z0 = start * cpp, z1 = z0 + (uint64_t)((len[0] < len[1] ? len[0] : len[1]) / ST_REC);    /* (the pairs: the cells both tables hold in the run) */
    for (uint64_t z = z0; z < z1; z++) {
      const _Atomic uint64_t *tc = (const _Atomic uint64_t *)(tabs[0]->base + z * ST_REC), *cc = (const _Atomic uint64_t *)(tabs[1]->base + z * ST_REC);
      uint64_t *dt = (uint64_t *)(buf[0] + (z - z0) * ST_REC), *dc = (uint64_t *)(buf[1] + (z - z0) * ST_REC);
      seqwait_t sw = { 0, 0 };
      for (;;) {
        const uint32_t s1 = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_acquire) >> 32);
        for (int k = 0; k < 8; k++) dt[k] = atomic_load_explicit(&tc[k], memory_order_relaxed);
        for (int k = 0; k < 8; k++) dc[k] = atomic_load_explicit(&cc[k], memory_order_relaxed);
        if (!cancel) break;
        atomic_thread_fence(memory_order_acquire);
        const uint32_t s2 = (uint32_t)(atomic_load_explicit(&cc[7], memory_order_relaxed) >> 32);
        if (!(s1 & 1u) && s1 == s2) break;
        if (!seq_wait(&sw)) break;
      }
    }
    for (int i = 0; i < 2; i++) {                    /* (the cells of a table past the other's end: a plain copy) */
      const size_t from = (size_t)((z1 - z0) * ST_REC);
      const _Atomic uint64_t *src = (const _Atomic uint64_t *)(tabs[i]->base + (start << s->pgshift) + from);
      uint64_t *dst = (uint64_t *)(buf[i] + from);
      for (size_t k = 0; from + k * 8 < len[i]; k++) dst[k] = atomic_load_explicit(&src[k], memory_order_relaxed);
    }
    /* rule T (N1), as in ck_write_tab(): both copies reach their files only after the kernel holds the journal up to the jr_pub read after them */
    atomic_thread_fence(memory_order_acquire);
    const uint64_t X = atomic_load_explicit(&s->jr_pub, memory_order_relaxed);
    if (atomic_load_explicit(&s->jr_tail, memory_order_acquire) < X && !RULE_T_OFF()) {
      atomic_fetch_add_explicit(&s->n_ck_twaits, 1, memory_order_relaxed);
      const int w = jw_wait(s, X, cancel);
      if (w < 0) return w;
    }
    for (int i = 0; i < 2; i++) {
      if (!len[i]) continue;
      if (s->ck.t[i].cow) ck_charge(s, len[i]);
      const int r = FAIL_CKWRITE() ? -EIO : st_pwrite_all(tabs[i]->fd, buf[i], len[i], (off_t)(ST_HDR_PAGE + (start << s->pgshift)));
      if (r < 0) return r;
      *done += len[i];
      wrote[i] = true;
      CRASH_POINT();
      st_hook(&store_test_ckpt_hook, 5);
    }
    if (cancel) ck_pace(s, *done, cancel);
    if (cancel && atomic_load_explicit(cancel, memory_order_relaxed)) return -ECANCELED;
  }
#undef CK_MARKED
  for (int i = 0; i < 2; i++) {
    const int r = ck_tab_end(tabs[i]->fd, s->ck.t[i].bytes, wrote[i]);
    if (r < 0) return r;
  }
  return 0;
}
/* The nx rule (0.7, the bulk fill; every fuzzy checkpoint): a zt cell that a writer changed after P on a page that was marked at P is copied with its new value, and its long name may be on a page of
 * nx that was first marked after P (the writers' new map): without this the cell would reach the disk and its name would not, and a rebuild with no journal to replay (a bulk fill, the records past the
 * durable journal after a power loss) would have a cell without its name.  So nx is written after zt and zc, up to its size now and from the pages of P and the ones marked since (taken under the writer
 * mutex: or'ed into the checkpoint's map, the writers' map keeps its bits for the next checkpoint).  A name is appended before its cell (the apply order, zrec_write_nx()), so every name a copied cell
 * needs was there before this; nx is only appended to (the nx pass, which moves names down, does not run during a bulk fill), so a page written twice is the same bytes.  -ENOMEM: the checkpoint fails. */
static int ck_nx_widen(store_t *s) {
  wr_lock_raw(s);
  const dmap_t *d = &s->nx.d;
  const uint64_t onp = s->ck.t[2].npages, np = d->npages, ow = (onp + 63) / 64, nw = (np + 63) / 64;
  uint64_t *m = s->ck.t[2].dirty;
  if (nw > ow) {
    if (!(m = calloc(nw, sizeof(uint64_t)))) { wr_unlock_raw(s); return -ENOMEM; }
    if (ow) memcpy(m, s->ck.t[2].dirty, (size_t)ow * sizeof(uint64_t));
    free(s->ck.t[2].dirty);
    s->ck.t[2].dirty = m;
  }
  if (np > onp) s->ck.t[2].npages = np;
  for (uint64_t w = 0; w < nw; w++) m[w] |= d->dirty[w];
  const uint64_t bytes = atomic_load_explicit(&s->nx.mapped, memory_order_relaxed), held = atomic_load_explicit(&s->nx.extended, memory_order_relaxed);
  if (bytes > s->ck.t[2].bytes) s->ck.t[2].bytes = bytes;
  s->ck.t[2].grow = s->ck.t[2].bytes > held ? s->ck.t[2].bytes - held : 0;
  wr_unlock_raw(s);
  return 0;
}

/* the write of the tables and the index generations of P (no lock).  cancel: the fuzzy checkpoint's (a close leaves it, see bg_stop_join()); NULL for one with the writers kept out */
static int ck_io_tables(store_t *s, const _Atomic bool *cancel) {
  mtab_t *tabs[3] = { &s->zt, &s->zc, &s->nx };
  uint64_t done = 0;
  s->ck.tw0 = st_now_us();
  int r = 0;
  for (int i = 0; i < 5 && r == 0; i++) {
    if (i == 2 && cancel) r = ck_nx_widen(s);       /* (fuzzy: the nx rule, above; with the writers kept out nothing was marked since P) */
    if (r < 0) break;
    if (i == 1) continue;                             /* (zc: with zt, in lockstep) */
    if (i == 0) {
      r = ck_write_cells(s, cancel, &done);
      if (r == 0) { mtab_note_extended(tabs[0], s->ck.t[0].bytes); mtab_note_extended(tabs[1], s->ck.t[1].bytes); }
    } else if (i == 2) {
      r = ck_write_tab(s, i, tabs[i]->fd, tabs[i]->base, cancel, &done);
      if (r == 0) mtab_note_extended(tabs[i], s->ck.t[i].bytes);
    } else {
      const ixgen_t *g = i == 3 ? s->ck.ix : s->ck.sx;
      if (g) r = ck_write_tab(s, i, g->fd, (const uint8_t *)g->slots, cancel, &done);
    }
  }
  atomic_fetch_add_explicit(&s->n_ck_bytes, done, memory_order_relaxed);
  if (r == 0) atomic_store_explicit(&s->ck_last_bytes, done, memory_order_relaxed);
  return r;
}

/* The journal file the superblock names and its directory entry are durable before it; then the superblock (ck_busy).  Fuzzy (not full): the writers append to that file, or did:
 * a commit that switched the journal on synced it, or the commit made here switches away from it and syncs it (st_commit_ex()).  The sync of the file the writers append to, at the
 * end of a flush that filled the disk queue, held its vnode lock for up to 1.4 s, and every append inside the writer mutex waited for it (UFS, 10M zones under load). */
static int ck_io_super(store_t *s, bool full) {
  int r = 0;
  if (!full && (r = st_commit_ex(s, 0, s->ck.gen)) == 0) {
    baton_take(s);
    if (s->jrn_synced < s->ck.gen) r = -EIO;          /* (no commit could sync it: it failed, or it is kept in jold; the superblock waits for the next checkpoint) */
    bg_release(s, true, false);
  }
  if (r == 0 && !full && fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) r = -errno;
  if (r < 0) return r;
  CRASH_POINT();
  return sb_store(s);
}

/* the superblock is on disk: the checkpoint is P (ck_busy) */
static void ck_finish(store_t *s) {
  const uint64_t us = st_now_us() - s->ck.t0;
  atomic_store_explicit(&s->ckpt_us, us, memory_order_relaxed);
  if (us > atomic_load_explicit(&s->ckpt_max_us, memory_order_relaxed)) atomic_store_explicit(&s->ckpt_max_us, us, memory_order_relaxed);   /* (ck_busy: one writer) */
  atomic_store_explicit(&s->ckpt_time, (uint64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&s->last_ckpt_ms, st_now_ms(), memory_order_relaxed);
  atomic_store_explicit(&s->clean_on_disk, s->ck.clean, memory_order_relaxed);
  atomic_store_explicit(&s->ckpt_lsn, s->ck.lsn, memory_order_release);
  atomic_fetch_add_explicit(&s->n_checkpoints, 1, memory_order_relaxed);
  if (s->ck.bulk) {                                   /* (the next one is due by the bytes appended since its begin, or by the time) */
    atomic_store_explicit(&s->bulk_base, s->ck.bulk_seg, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_last_ms, st_now_ms(), memory_order_relaxed);
    atomic_fetch_add_explicit(&s->n_bulk_ckpts, 1, memory_order_relaxed);
    st_log(s, 6, "store: bulk checkpoint %" PRIu64 " of the fill: %" PRIu64 " MiB of segments, %" PRIu64 " zones stored, %" PRIu64 " known (the fill goes back to here after a crash)",
           atomic_load_explicit(&s->n_bulk_ckpts, memory_order_relaxed), s->ck.bulk_seg >> 20, s->sbbuf->f.v[V_STORED], s->sbbuf->f.v[V_KNOWN]);
  }
  if (!(s->sbbuf->f.flags & SBF_BULK) && atomic_exchange_explicit(&s->bulk_end_pending, false, memory_order_relaxed)) {     /* (THE BULK FILL, E: the end of the fill is on disk) */
    atomic_store_explicit(&s->bulk_end_backoff_ms, 0, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_end_next_ms, 0, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_end_state, 0, memory_order_relaxed);
    st_log(s, 6, "store: the end of the bulk fill is on disk (position %" PRIu64 "): a crash replays the journal from here", s->ck.lsn);
  }
  unlink_old_gens(s);
}

/* the next journal file is made now (the baton held: every switch holds it), so that the next switch is a pwrite inside the mutex */
static void ck_precreate(store_t *s) {
  if (s->jnext_fd >= 0) return;
  const uint32_t g = s->jrn_gen + 1;
  const int fd = journal_create(s, g);
  if (fd >= 0) { s->jnext_fd = fd; s->jnext_gen = g; }
}

/* The rest of a checkpoint that ck_begin_locked() began (ck_busy and the baton held, no lock): the commit of P, the baton back (commits go on), the flush, the superblock.  A failure
 * leaves the superblocks as they were: the journal chain from the older checkpoint goes on through the file that was switched to, and the next checkpoint tries again. */
static int ck_run(store_t *s) {
  st_hook(&store_test_ckpt_hook, 1);
  int r = ck_io_commit(s, false);
  bg_release(s, true, false);
  if (r == 0) {
    CRASH_POINT();
    st_hook(&store_test_ckpt_hook, 2);
    r = ck_io_tables(s, &s->ck_cancel);
  }
  if (r == 0) {
    CRASH_POINT();
    st_hook(&store_test_ckpt_hook, 3);
    r = ck_io_super(s, false);
  }
  if (r == 0) ck_drop_taken(s);
  else {                                              /* (the pages it took are given back before io_hold lets their generations go) */
    wr_lock_raw(s);
    ck_merge_locked(s);
    wr_unlock_raw(s);
  }
  atomic_store_explicit(&s->ck_left, 0, memory_order_relaxed);
  atomic_fetch_sub_explicit(&s->io_hold, 1, memory_order_acq_rel);
  if (r == 0) {
    CRASH_POINT();
    ck_finish(s);
    baton_take(s);
    ck_precreate(s);
    bg_release(s, true, false);
    st_hook(&store_test_ckpt_hook, 4);
  } else if (r == -ECANCELED) {
    /* a clean checkpoint (a stop, a close) comes: this one is left (the superblocks stay as they were, the journal chain goes on through the file it switched to), that one flushes all */
    atomic_fetch_add_explicit(&s->n_ckpt_cancel, 1, memory_order_relaxed);
    st_log(s, 6, "store: the checkpoint in progress (position %" PRIu64 ") was left for the clean checkpoint that follows", s->ck.lsn);
  } else {
    note_error(s, r);
  }
  bg_release(s, false, true);
  return r;
}

/* The superblock on disk says "clean" and nothing was written since (the clean checkpoint is the state): a superblock without the flag, before the first record (writer mutex and
 * ck_busy + the baton held).  No flush: the tables are as the clean checkpoint left them. */
static int unclean_now_locked(store_t *s) {
  if (!s->clean_on_disk) return 0;
  int r = sb_write(s, false, s->jrn_gen);
  if (r == 0) atomic_store_explicit(&s->clean_on_disk, false, memory_order_relaxed);
  return r;
}

/* A checkpoint with the writers kept out for all of it (writer mutex, ck_busy and the baton held): the clean one (the flag must name a state that no record follows), the first one of an
 * open, the one of a repair, and the rare one a writer needs at once (the emergency cleaning, the nx pass).  The steps of the fuzzy one, in the same order. */
static int ck_full_locked(store_t *s, bool clean) {
  int r = jw_drain_locked(s);                         /* (the ring first: in the states that write nothing this fails, and no table page is written: N1) */
  if (r == 0) r = jold_sync(s);
  if (r == 0) r = ck_begin_locked(s, clean, false);
  if (r < 0) { atomic_store_explicit(&s->ck_left, 0, memory_order_relaxed); return r; }
  r = ck_io_commit(s, true);
  if (r == 0) { CRASH_POINT(); r = ck_io_tables(s, NULL); }
  if (r == 0) { CRASH_POINT(); r = ck_io_super(s, true); }
  if (r == 0) ck_drop_taken(s); else ck_merge_locked(s);
  atomic_store_explicit(&s->ck_left, 0, memory_order_relaxed);
  atomic_fetch_sub_explicit(&s->io_hold, 1, memory_order_acq_rel);
  if (r < 0) return r;
  CRASH_POINT();
  ck_finish(s);
  retire_run(s, false);
  space_checkpoint(s);
  return 0;
}
/* the writer mutex with the checkpoint's flags (for a ck_full_locked()); the clean flag on disk is cleared first when the caller writes records */
static void wr_lock_ck_at(store_t *s, const char *site) {
  ck_acquire(s);
  wr_lock_raw_at(s, site);
}
#define wr_lock_ck(s) wr_lock_ck_at((s), __func__)
static int wr_unlock_ck(store_t *s) {
  const uint64_t t = s->jr_head;
  wr_unlock_raw(s);
  bg_release(s, true, true);
  return jw_wait(s, t, NULL);                         /* (a repair, a compaction, a close: their records are written before they return; a failed state returns at once) */
}
/* A writer that holds the mutex and needs a checkpoint now: the flags are tried, and when another thread has them the mutex is given up while they are waited for.  1: the checkpoint was
 * made with the mutex given up for a moment (the caller's view of the store may have changed), 0: made, < 0: failed. */
static int ck_now_locked(store_t *s) {
  int given = 0;
  if (!ck_try_locked(s)) {
    wr_unlock_raw(s);
    ck_acquire(s);
    wr_lock_raw(s);
    given = 1;
  }
  int r = ck_full_locked(s, false);
  bg_release(s, true, true);
  if (r < 0) note_error(s, r);
  return r < 0 ? r : given;
}

/* the flags for the checkpoint thread of the flusher: false (none taken) when a writer has handed it a checkpoint meanwhile (post_write()): that one holds the flags until this thread
 * runs it, so waiting for them here would never end */
static bool ck_acquire_fl(store_t *s) {
  pthread_mutex_lock(&s->bg_mu);
  while ((s->io_busy || s->ck_busy) && !s->ck_handoff) pthread_cond_wait(&s->bg_cv, &s->bg_mu);
  const bool ok = !s->ck_handoff;
  if (ok) s->io_busy = s->ck_busy = true;
  pthread_mutex_unlock(&s->bg_mu);
  return ok;
}

static bool ckpt_due(const store_t *s, uint64_t now);
/* A checkpoint from a thread that holds no lock (the flusher, store_checkpoint()): the flags, the begin under the writer mutex, the rest without it.  force: also when nothing was
 * written since the last one.  fl: the flusher's checkpoint thread (it gives way to a checkpoint handed to it, and returns 1).  0, or -errno. */
/* The checkpoint that ends a bulk fill failed, or was not tried (no room): the next try comes after a back-off, 1 s doubling up to 5 min (ckpt_due()), so that a disk that is full or failing is not
 * rewritten with gigabytes of tables every second while the cleaner waits for the end.  One line at each change of the state, not one a try (ck_finish() says when it is on disk). */
#define ST_BULK_END_MAX_MS 300000u
#ifdef KARIDNS_UNIT_TEST
_Atomic uint32_t store_test_bulk_end_ms = 0;
#define BULK_END_BASE_MS() (atomic_load_explicit(&store_test_bulk_end_ms, memory_order_relaxed) ? atomic_load_explicit(&store_test_bulk_end_ms, memory_order_relaxed) : 1000u)
#else
#define BULK_END_BASE_MS() 1000u
#endif
static uint64_t st_avail(const store_t *s);
static int st_ckpt(store_t *s, bool force, bool fl) {
  if (!fl) ck_acquire(s);
  else if (!ck_acquire_fl(s)) return 1;
  int r = 0;
  const bool end = atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed);
  bool room = false;
  uint64_t need_b = 0;
  if (end) fs_probe(s);                               /* (the end of a bulk fill: is there room for what it writes?  A fresh estimate, outside the mutex) */
  r = jold_sync(s);                                   /* (a journal whose sync failed: synced first, with no lock held) */
  if (r == 0) {
    wr_lock_raw(s);
    /* (not forced: the caller found it due (the flusher, bg_due()) before it waited for the flags, and another checkpoint may have been made meanwhile and taken the reason away (the
     * growth's ck_want, a full journal): due is asked again here, under the mutex.  "Something was written since" alone is not a reason: a checkpoint the flusher had found due after a
     * growth, made after store_checkpoint() had already made one and the writes had begun again, cut the journal of a bulk fill (store_journal_boost()) at a fraction of its raised size,
     * test_store jboost on loaded CI VMs.  A bulk fill moves no LSN; its end is due until it is on disk) */
    const bool need = force || ckpt_due(s, st_now_ms()) || end;
    r = need ? unclean_now_locked(s) : 1;           /* (writers go on while this checkpoint flushes: a clean flag on disk goes first) */
    if (r == 0) r = ck_begin_locked(s, false, true);
    if (r == 0 && end && !s->ck.bulk) {
      /* what the checkpoint will allocate (ck_left: its pages on a copy-on-write file system, the growth past the files otherwise) and a slack, against the estimate: with less, nothing is
       * written now.  The begin is undone as a failed checkpoint is (its pages back to the maps, its segments and directory dirty again, the old journal kept for the next commit) */
      const int64_t est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
      need_b = atomic_load_explicit(&s->ck_left, memory_order_relaxed) + JR_SLACK;
      if (est >= 0 && (uint64_t)est < need_b) {
        commit_unmark(s, s->ck.seg, s->ck.nseg, s->ck.dir);
        if (s->ck.oldfd >= 0) { s->jold = s->ck.oldfd; s->jold_end = s->ck.epos; s->ck.oldfd = -1; }
        ck_merge_locked(s);
        atomic_store_explicit(&s->ck_left, 0, memory_order_relaxed);
        atomic_fetch_sub_explicit(&s->io_hold, 1, memory_order_acq_rel);
        room = true;
        r = -ENOSPC;
      }
    }
    wr_unlock_raw(s);
  }
  if (r == 0) r = ck_run(s);
  else {
    bg_release(s, true, true);
    if (r > 0) return 0;
    note_error(s, r);
  }
  if (r < 0 && end && atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed)) {
    /* the end of a bulk fill failed, or was not tried (no room): its back-off (inline, so that no function of its own runs only on a failure) */
    uint64_t b = atomic_load_explicit(&s->bulk_end_backoff_ms, memory_order_relaxed);
    b = b == 0 ? BULK_END_BASE_MS() : b >= ST_BULK_END_MAX_MS / 2 ? ST_BULK_END_MAX_MS : 2 * b;
    atomic_store_explicit(&s->bulk_end_backoff_ms, b, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_end_next_ms, st_now_ms() + b, memory_order_relaxed);
    const int bst = room ? 2 : 1;
    if (atomic_exchange_explicit(&s->bulk_end_state, bst, memory_order_relaxed) != bst) {
      if (room)
        st_log(s, 4, "store: the checkpoint that ends the bulk fill needs about %" PRIu64 " bytes and %" PRIu64 " are free: it is not tried until there is room (looked at again with a back-off up "
                     "to 5 min); until it is on disk a crash goes back to the last bulk checkpoint", need_b, st_avail(s));
      else
        st_log(s, 3, "store: the checkpoint that ends the bulk fill failed (%d): it is tried again with a back-off up to 5 min; until it is on disk a crash goes back to the last bulk checkpoint", r);
    }
  }
  return r;
}
/* what a checkpoint leaves to the writer mutex: the retired generations and segments, the free space and the warnings */
static void ck_after(store_t *s) {
  wr_lock_raw(s);
  retire_run(s, false);
  space_checkpoint(s);
  wr_unlock_raw(s);
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
  s->tabgen++;
  if (old) retire_add(s, old);
  return 0;
}
static void ixgen_drop(store_t *s, ixgen_t *g, uint32_t kind) {         /* a generation that was made and not put in: its file goes */
  if (!g) return;
  char name[32];
  st_name_ix(name, sizeof(name), kind == FK_IX ? "ix" : "sx", g->gen);
  ixgen_free(g);
  if (unlinkat(s->dirfd, name, 0) == 0) s->dir_dirty = true;
}

/* Insert every live zone of zt[0, hwm) into the new generations nix / nsx (either may be NULL).  lockfree: the writers go on meanwhile (a cell is read under its sequence counter, a long
 * name checked against it as store_zone_get() does; what the writers change is in the build's log); otherwise the writer mutex is held.  A damaged cell stays invisible.  *live_ix /
 * *live_sx: the entries made (into empty slots: as many used).  -ENOSPC: a generation is too small; -ECANCELED: the build was dropped meanwhile. */
static int rg_fill(store_t *s, ixgen_t *nix, ixgen_t *nsx, uint64_t hwm, bool lockfree, uint64_t *live_ix, uint64_t *live_sx) {
  uint64_t li = 0, ls = 0;
  for (uint64_t z = 0; z < hwm; z++) {
    if (lockfree && (z & 0x3fffu) == 0 &&
        (atomic_load_explicit(&s->rg_cancel, memory_order_relaxed) || atomic_load_explicit(&s->rg_stop, memory_order_relaxed))) return -ECANCELED;
    if (zt_state_fast(s, (uint32_t)z) == STORE_STATE_FREE) continue;
    r64_t rt, rc;
    zt_t t;
    zc_t c;
    uint8_t fn[256];
    bool ok = false;
    for (int tries = 0; tries < 64 && !ok; tries++) {
      uint32_t seq = 0;
      if ((lockfree ? zrec_read_seq(s, (uint32_t)z, &rt, &rc, &seq) : zrec_read_locked(s, (uint32_t)z, &rt, &rc)) < 0) break;
      zt_unpack(&rt, &t);
      zc_unpack(&rc, &c);
      if (t.state == STORE_STATE_FREE || !zt_fullname(s, &t, fn)) break;
      ok = true;
      if (lockfree && t.klen > ST_NAME_INL) {          /* (the nx pass may have moved the name while it was copied) */
        atomic_thread_fence(memory_order_acquire);
        ok = store_zone_unchanged(s, (uint32_t)z, seq);
      }
    }
    if (!ok) continue;
    if (nix) {
      if (ix_raw_insert(nix, st_hash_name(s, t.view, fn, t.klen), (uint32_t)z) < 0) return -ENOSPC;
      li++;
    }
    if (nsx && c.source_id != 0) {
      if (ix_raw_insert(nsx, st_hash_src(s, c.source, t.view, c.source_id), (uint32_t)z) < 0) return -ENOSPC;
      ls++;
    }
  }
  *live_ix = li;
  *live_sx = ls;
  return 0;
}

/* The new generations are put in (writer mutex): the bridge in the journal chain (GEN ops and the counters of the new tables), then the pointers.  The record is in the journal before the
 * memory follows it; it needs no sync of its own (a replay that meets it rebuilds the derived tables, the new file holding only what a checkpoint wrote, and so the old generation, which the
 * superblocks still name, is kept until two checkpoints name the new one).  On failure nothing changes. */
static int rg_publish_locked(store_t *s, ixgen_t *nix, ixgen_t *nsx, uint64_t ix_used, uint64_t ix_live, uint64_t sx_used, uint64_t sx_live) {
  jb_reset(&s->jb);
  int r = 0;
  if (nix) {
    uint8_t *p = jb_op(&s->jb, OP_GEN, 16);
    uint32_t w = 0, g = nix->gen;
    if (!p) r = -ENOMEM; else { memcpy(p, &w, 4); memcpy(p + 4, &g, 4); memcpy(p + 8, &nix->nslots, 8); }
    if (r == 0 && ((r = jb_vset(&s->jb, V_IX_USED, ix_used)) < 0 || (r = jb_vset(&s->jb, V_IX_LIVE, ix_live)) < 0)) {}
  }
  if (r == 0 && nsx) {
    uint8_t *p = jb_op(&s->jb, OP_GEN, 16);
    uint32_t w = 1, g = nsx->gen;
    if (!p) r = -ENOMEM; else { memcpy(p, &w, 4); memcpy(p + 4, &g, 4); memcpy(p + 8, &nsx->nslots, 8); }
    if (r == 0 && ((r = jb_vset(&s->jb, V_SX_USED, sx_used)) < 0 || (r = jb_vset(&s->jb, V_SX_LIVE, sx_live)) < 0)) {}
  }
  if (r == 0) r = journal_append(s);
  if (r < 0) return r;
  CRASH_POINT();
  if (nix) {
    index_publish(s, 0, nix);
    VS(s, V_IX_USED, ix_used);
    VS(s, V_IX_LIVE, ix_live);
  }
  if (nsx) {
    index_publish(s, 1, nsx);
    VS(s, V_SX_USED, sx_used);
    VS(s, V_SX_LIVE, sx_live);
  }
  s->n_growths++;
  atomic_store_explicit(&s->ck_want, true, memory_order_relaxed);
  CRASH_POINT();
  return 0;
}

/* Replace ix and / or sx (a non-zero slot count) by new generations built from a pass over zt, inside the writer mutex: the index filled up to one half before a build outside the mutex
 * ended (or none could be started).  A build in progress is dropped (its generation numbers are not used again).  Readers continue on the old generation. */
static int regrow_locked(store_t *s, uint64_t ix_slots, uint64_t sx_slots) {
  if (s->rg_active) atomic_store_explicit(&s->rg_cancel, true, memory_order_relaxed);
  uint64_t hwm = VG(s, V_HWM), live_ix = 0, live_sx = 0;
  if (hwm > st_zt_cap(s)) hwm = st_zt_cap(s);
  ixgen_t *nix = NULL, *nsx = NULL;
  int r = 0;
  if (ix_slots && (r = ixgen_create(s, FK_IX, s->ix_gen_next++, ix_slots, true, &nix)) < 0) return r;
  if (sx_slots && (r = ixgen_create(s, FK_SX, s->sx_gen_next++, sx_slots, true, &nsx)) < 0) { ixgen_drop(s, nix, FK_IX); return r; }
  r = rg_fill(s, nix, nsx, hwm, false, &live_ix, &live_sx);
  CRASH_POINT();
  if (r == 0) r = rg_publish_locked(s, nix, nsx, live_ix, live_ix, live_sx, live_sx);
  if (r < 0) { ixgen_drop(s, nix, FK_IX); ixgen_drop(s, nsx, FK_SX); }
  return r;
}

/* ---- growth outside the writer mutex (0.7 fix A; the pattern of the attach table's growth, M4) ----
 * At 3/8 of a generation in use (tombstones count) a build is started on a thread of its own: new generations of the next size are made from one pass over zt while the writers go on
 * (and keep using the old ones); every index change of a record written meanwhile is kept in rg_log (jb_t.pl, moved there by journal_commit_apply()).  At the end the build takes the
 * writer mutex, makes the logged changes on the new generations, in their order ("this hash leads to this zone" / "... no longer": each one sets the presence of one entry, so whatever
 * state of a zone the pass read, the last change of the entry decides), and puts them in with their OP_GEN record.  A build is dropped when a generation was changed meanwhile (a growth
 * inside the mutex, a repair: tabgen), when its log could not grow, or when the store closes; its files go.  If the index reaches one half before the build ends, the growth is made inside
 * the mutex as before.
 * The catch-up (0.7): at 10M zones the log of one build held up to 2.1 M changes, and making them inside the mutex took 0.18 to 0.34 s.  Now the build makes them in rounds with no lock
 * (the log is in chunks that never move: the entries before rg_n, read with acquire, are not written again until the build ends; the writers append after them) until the part that is
 * left is at most RG_TAIL changes (or after RG_ROUNDS rounds), and only that part is made inside the mutex, with the OP_GEN record.  The order is the order of the log either way. */
#define RG_TAIL 4096u                         /* changes the build makes inside the mutex at most, unless the writers outrun RG_ROUNDS rounds */
#define RG_ROUNDS 16
#define RG_PRESS 7u                           /* store_index_wait() waits while a build runs and the index is past RG_PRESS / 16 of its slots (the build began at 3/8 = 6/16, the growth inside the mutex is at 8/16) */
#ifdef KARIDNS_UNIT_TEST
_Atomic long store_test_rg_tail = -1;
#define RG_TAIL_NOW() (atomic_load_explicit(&store_test_rg_tail, memory_order_relaxed) >= 0 ? (size_t)atomic_load_explicit(&store_test_rg_tail, memory_order_relaxed) : (size_t)RG_TAIL)
#else
#define RG_TAIL_NOW() ((size_t)RG_TAIL)
#endif

static void rg_note_locked(store_t *s, const jb_t *j) {
  if (!s->rg_active || s->rg_bad || j->npl == 0) return;
  size_t n = atomic_load_explicit(&s->rg_n, memory_order_relaxed);
  if (n + j->npl > RG_LOG_MAX) { s->rg_bad = true; return; }
  for (unsigned k = 0; k < j->npl;) {
    rgent_t **c = &s->rg_ch[n >> RG_CH_SHIFT];
    const size_t at = n & (RG_CH - 1), m = RG_CH - at < j->npl - k ? RG_CH - at : j->npl - k;
    if (!*c && !(*c = malloc((size_t)RG_CH * sizeof(rgent_t)))) { s->rg_bad = true; return; }
    memcpy(*c + at, j->pl + k, m * sizeof(rgent_t));
    k += (unsigned)m;
    n += m;
    atomic_store_explicit(&s->rg_n, n, memory_order_release);
  }
}
static inline const rgent_t *rg_ent(const store_t *s, size_t k) { return &s->rg_ch[k >> RG_CH_SHIFT][k & (RG_CH - 1)]; }

/* one logged change on a new generation: the entry (hash, zone) is there (ins) or not; *used / *live follow */
static int rg_apply(ixgen_t *g, const rgent_t *e, uint64_t *used, uint64_t *live) {
  const uint64_t pos = slot_find_zid(g, e->h, e->z);
  if (e->ins) {
    if (pos != UINT64_MAX) return 0;
    bool was_empty;
    const uint64_t at = slot_find_insert(g, e->h, &was_empty, NULL, 0);
    if (at == UINT64_MAX) return -ENOSPC;
    atomic_store_explicit(&g->slots[at], st_slotval(st_tag(e->h), e->z), memory_order_relaxed);
    (*live)++;
    if (was_empty) (*used)++;
  } else if (pos != UINT64_MAX) {
    atomic_store_explicit(&g->slots[pos], st_slotval(st_tag(e->h), STORE_NONE), memory_order_relaxed);
    if (*live) (*live)--;
  }
  return 0;
}

/* the logged changes [from, to) on the new generations (the counters follow) */
typedef struct { uint64_t iu, il, su, sl; } rg_cnt_t;
static int rg_catch_up(const store_t *s, ixgen_t *nix, ixgen_t *nsx, size_t from, size_t to, rg_cnt_t *c) {
  int r = 0;
  for (size_t k = from; k < to && r == 0; k++) {
    const rgent_t *e = rg_ent(s, k);
    if (e->which == 0 && nix) r = rg_apply(nix, e, &c->iu, &c->il);
    else if (e->which == 1 && nsx) r = rg_apply(nsx, e, &c->su, &c->sl);
  }
  return r;
}

/* The build (the thread of rg_start_locked(), or the caller of store_reserve()): 0 put in, -ECANCELED dropped, or -errno. */
static int rg_build(store_t *s) {
  ixgen_t *nix = NULL, *nsx = NULL;
  uint64_t li = 0, ls = 0;
  int r = 0;
  if (s->rg_nix) r = ixgen_create(s, FK_IX, s->rg_ixgen, s->rg_nix, !s->rg_noalloc, &nix);
  if (r == 0 && s->rg_nsx) r = ixgen_create(s, FK_SX, s->rg_sxgen, s->rg_nsx, !s->rg_noalloc, &nsx);
  if (r == 0) r = rg_fill(s, nix, nsx, s->rg_hwm, true, &li, &ls);
  /* (no flush here: the build has to end before the writers fill the old index to one half, and the checkpoint that follows the growth flushes the new files) */
  CRASH_POINT();
  st_hook(&store_test_regrow_hook, 1);
  rg_cnt_t c = { li, li, ls, ls };
  size_t done = 0;
  for (int round = 0; r == 0 && round < RG_ROUNDS; round++) {         /* the catch-up with no lock (rg_active keeps the log: no other build starts until this one ends) */
    if (atomic_load_explicit(&s->rg_cancel, memory_order_relaxed) || atomic_load_explicit(&s->rg_stop, memory_order_relaxed)) { r = -ECANCELED; break; }
    const size_t n = atomic_load_explicit(&s->rg_n, memory_order_acquire);
    if (n - done <= RG_TAIL_NOW()) break;
    r = rg_catch_up(s, nix, nsx, done, n, &c);
    done = n;
    CRASH_POINT();
    st_hook(&store_test_regrow_hook, 3);
  }
  const int lr = wr_lock(s);                          /* (a clean flag on disk is cleared first, with the mutex given up while the flags are waited for, as for every writer: the OP_GEN record is a
                                                       * change after it; journal_append()'s guard would only try the flags, and fail the growth when a commit or a checkpoint has them) */
  if (lr < 0) {
    wr_lock_raw(s);
    if (r == 0) r = lr;
  }
  if (r == 0 && (atomic_load_explicit(&s->rg_cancel, memory_order_relaxed) || atomic_load_explicit(&s->rg_stop, memory_order_relaxed) || s->tabgen != s->rg_tabgen || s->rg_bad))
    r = -ECANCELED;
  if (r == 0) r = rg_catch_up(s, nix, nsx, done, atomic_load_explicit(&s->rg_n, memory_order_relaxed), &c);
  if (r == 0) r = rg_publish_locked(s, nix, nsx, c.iu, c.il, c.su, c.sl);
  if (r == 0) {
    atomic_fetch_add_explicit(&s->n_growths_bg, 1, memory_order_relaxed);
    nix = nsx = NULL;
  }
  s->rg_active = false;
  atomic_store_explicit(&s->rg_press, false, memory_order_release);     /* (the producers that wait for the build, store_index_wait(), go on) */
  atomic_store_explicit(&s->rg_n, 0, memory_order_relaxed);
  rgent_t *spare[RG_NCH];                             /* (the chunks past the first are freed after the mutex) */
  memcpy(spare, s->rg_ch, sizeof(spare));
  memset(s->rg_ch + 1, 0, sizeof(s->rg_ch) - sizeof(s->rg_ch[0]));
  const int w = wr_unlock_w(s);                     /* (its OP_GEN record is written before the build counts as done) */
  if (r == 0 && w < 0) r = w;
  for (unsigned k = 1; k < RG_NCH; k++) free(spare[k]);
  if (r == 0) st_hook(&store_test_regrow_hook, 2);
  ixgen_drop(s, nix, FK_IX);
  ixgen_drop(s, nsx, FK_SX);
  if (r == 0) bg_signal(s);                           /* (a checkpoint names the new generation soon: the old one's file can go) */
  else if (r != -ECANCELED) note_error(s, r);
  return r;
}
static void *rg_main(void *arg) {
  store_t *s = arg;
  (void)rg_build(s);
  atomic_fetch_sub_explicit(&s->rg_live, 1, memory_order_release);      /* (the last touch of the store: store_close() waits for it) */
  return NULL;
}
/* a build of generations with nix / nsx slots (0: that one does not grow) begins (writer mutex held); spawn: on its own thread (otherwise the caller runs rg_build() after the mutex).
 * false: none was started (one runs, the store closes, no thread). */
static bool rg_start_locked(store_t *s, uint64_t nix, uint64_t nsx, bool spawn) {
  if (s->rg_active || atomic_load_explicit(&s->rg_stop, memory_order_relaxed) || (!nix && !nsx)) return false;
  uint64_t hwm = VG(s, V_HWM);
  if (hwm > st_zt_cap(s)) hwm = st_zt_cap(s);
  s->rg_nix = nix;
  s->rg_nsx = nsx;
  s->rg_ixgen = nix ? s->ix_gen_next++ : 0;
  s->rg_sxgen = nsx ? s->sx_gen_next++ : 0;
  s->rg_hwm = hwm;
  s->rg_noalloc = !spawn;
  s->rg_tabgen = s->tabgen;
  atomic_store_explicit(&s->rg_n, 0, memory_order_relaxed);
  s->rg_bad = false;
  atomic_store_explicit(&s->rg_cancel, false, memory_order_relaxed);
  atomic_store_explicit(&s->rg_nowait, false, memory_order_relaxed);
  atomic_store_explicit(&s->rg_press, false, memory_order_relaxed);
  s->rg_active = true;
  if (!spawn) return true;
  pthread_attr_t at;
  pthread_t th;
  bool ok = pthread_attr_init(&at) == 0;
  if (ok) {
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    atomic_fetch_add_explicit(&s->rg_live, 1, memory_order_release);
    ok = pthread_create(&th, &at, rg_main, s) == 0;
    if (!ok) atomic_fetch_sub_explicit(&s->rg_live, 1, memory_order_release);
    pthread_attr_destroy(&at);
  }
  if (!ok) s->rg_active = false;                      /* (no thread: the growth is made inside the mutex at one half) */
  return ok;
}

/* would ix_make_room() grow a table inside the mutex if pix (psx) more index slots were in use? (the entries of a group commit have claimed slots that the counters do not show yet) */
static bool ix_room_short(const store_t *s, bool need_sx, uint64_t pix, uint64_t psx) {
  const ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  return (VG(s, V_IX_USED) + pix + 1) * 2 > ix->nslots || (need_sx && (VG(s, V_SX_USED) + psx + 1) * 2 > sx->nslots);
}

/* room for one more entry (writer mutex held): at 3/8 in use a build outside the mutex begins (the new size is four times the live entries: 1/4 in use, so that the writers have 1/8 of the old size to fill before the build has to be done, and the next build comes after 1.5 times the entries); at 1/2 the growth is made here */
static int ix_make_room(store_t *s, bool need_sx) {
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  const uint64_t iu = VG(s, V_IX_USED), su = VG(s, V_SX_USED), il = VG(s, V_IX_LIVE), sl = VG(s, V_SX_LIVE);
  uint64_t nix = 0, nsx = 0;
  if ((iu + 1) * 2 > ix->nslots) nix = ix_slots_for(il + il / 3 + 1);
  if (need_sx && (su + 1) * 2 > sx->nslots) nsx = ix_slots_for(sl + sl / 3 + 1);
  if (nix || nsx) return regrow_locked(s, nix, nsx);
  if (!s->rg_active && ((iu + 1) * 8 > ix->nslots * 3 || (su + 1) * 8 > sx->nslots * 3))
    (void)rg_start_locked(s, (iu + 1) * 8 > ix->nslots * 3 ? ix_slots_for(il + il / 3 + 1) : 0, (su + 1) * 8 > sx->nslots * 3 ? ix_slots_for(sl + sl / 3 + 1) : 0, true);
  /* a build runs and one of the indexes is past RG_PRESS: the bulk producers (store_index_wait()) wait for its end rather than fill the old index to one half */
  atomic_store_explicit(&s->rg_press, s->rg_active && !atomic_load_explicit(&s->rg_nowait, memory_order_relaxed) &&
                        ((iu + 1) * 16 > ix->nslots * RG_PRESS || (su + 1) * 16 > sx->nslots * RG_PRESS), memory_order_release);
  return 0;
}

/* The wait for a build (0.7, round 10).  The first fill of a database adds 0.4 to 0.9 M zones a second; the build of the next generation takes 0.63 us a zone, so it can lose the race
 * against the producer: at one half of the old index the writer grew it inside the mutex, dropped the build and made the pass over every zone again, with the file system of the new
 * files behind it (UFS, waiting for the checkpoint): holds of 1 to 7 seconds at 7M zones.  The bulk producer (the reconcile thread of a pass) that holds no lock calls this between its
 * groups: while a build runs and the index is past RG_PRESS (7/16, the build began at 3/8) it waits, with no lock held, for the build to end (it is not dropped, the mutex stays free:
 * lookups, bodies, checkpoints go on), so that the growth is the build's and not the mutex's.  The wait is bounded (RG_WAIT_MS): a build that does not end (the disk) is given up on once
 * (rg_nowait, a WARNING, store.index.wait_giveups) and the producer goes on as before, the growth inside the mutex being the last resort.  Callers that are not bulk producers (a
 * transfer, a dynamic update, the thread that also answers lookups) do not call it.  Returns the microseconds waited (0: no wait). */
#define RG_WAIT_MS 30000u
#ifdef KARIDNS_UNIT_TEST
_Atomic long store_test_rg_wait_ms = -1;
#define RG_WAIT_NOW() (atomic_load_explicit(&store_test_rg_wait_ms, memory_order_relaxed) >= 0 ? (uint64_t)atomic_load_explicit(&store_test_rg_wait_ms, memory_order_relaxed) : (uint64_t)RG_WAIT_MS)
#else
#define RG_WAIT_NOW() ((uint64_t)RG_WAIT_MS)
#endif
uint64_t store_index_wait(store_t *s) {
  if (!s || !atomic_load_explicit(&s->rg_press, memory_order_acquire) || atomic_load_explicit(&s->rg_nowait, memory_order_relaxed)) return 0;
  const uint64_t t0 = st_now_us(), lim = RG_WAIT_NOW() * 1000u;
  bool gave_up = false;
  while (atomic_load_explicit(&s->rg_press, memory_order_acquire) && !atomic_load_explicit(&s->rg_stop, memory_order_relaxed)) {
    if (st_now_us() - t0 >= lim) { gave_up = true; break; }
    usleep(1000);
  }
  const uint64_t us = st_now_us() - t0;
  atomic_fetch_add_explicit(&s->iw_n, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->iw_us, us, memory_order_relaxed);
  uint64_t m = atomic_load_explicit(&s->iw_max_us, memory_order_relaxed);
  while (us > m && !atomic_compare_exchange_weak_explicit(&s->iw_max_us, &m, us, memory_order_relaxed, memory_order_relaxed)) {}
  if (gave_up) {
    atomic_store_explicit(&s->rg_nowait, true, memory_order_relaxed);
    atomic_store_explicit(&s->rg_press, false, memory_order_release);
    atomic_fetch_add_explicit(&s->iw_giveups, 1, memory_order_relaxed);
    st_log(s, 4, "store: the build of the next index did not end in %" PRIu64 " ms; the pass goes on and the index may be grown inside the writer mutex (store.index.wait_giveups)", lim / 1000u);
  }
  return us ? us : 1;
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

static void degraded_end(store_t *s);
static inline bool is_nospc(int r) { return r == -ENOSPC || r == -EFBIG || r == -EDQUOT; }
static bool rl_ok(uint64_t *last, uint64_t every_ms) {                       /* a log line that may be said once in every_ms */
  uint64_t now = st_now_ms();
  if (*last && now - *last < every_ms) return false;
  *last = now;
  return true;
}
static void note_error(store_t *s, int r) {
  if (is_nospc(r)) {
    atomic_fetch_or(&s->state, STORE_ST_DEGRADED_NOSPC);
    atomic_fetch_add(&s->n_enospc, 1);
  }
  if (r < 0) s->n_write_errors++;
}
/* a write worked: the "last write failed" flag goes, unless the store is degraded (images are being kept as KNOWN because there is no room): that ends when an image is stored */
static void note_ok(store_t *s) {
  if (!s->degraded) atomic_fetch_and(&s->state, ~(uint32_t)STORE_ST_DEGRADED_NOSPC);
}

/* ---- free space (design 3.5) ---- */

static void fs_probe(store_t *s) {
  uint64_t total = 0, avail = 0;
  bool have = false;
#ifdef KARIDNS_UNIT_TEST
  if (store_test_fs_free) {
    int64_t v = store_test_fs_free();
    if (v >= 0) { avail = (uint64_t)v; total = avail > (1ull << 30) ? avail : (1ull << 30); have = true; }
    int64_t (*ft)(void) = atomic_load(&store_test_fs_total);
    if (v >= 0 && ft) total = (uint64_t)ft();
  }
#endif
#if defined(__FreeBSD__)
  if (!have) {
    struct statfs sfs;
    if (fstatfs(s->dirfd, &sfs) == 0) {
      total = (uint64_t)sfs.f_blocks * (uint64_t)sfs.f_bsize;
      avail = sfs.f_bavail > 0 ? (uint64_t)sfs.f_bavail * (uint64_t)sfs.f_bsize : 0;
      have = true;
    }
  }
#endif
  atomic_store_explicit(&s->last_probe_ms, st_now_ms(), memory_order_relaxed);
  atomic_store_explicit(&s->probe_bytes, 0, memory_order_relaxed);
  if (!have) { atomic_store_explicit(&s->avail_est, -1, memory_order_relaxed); return; }
  /* (the ring's bytes that wait for their write were subtracted at their reservation and are not in statfs yet; a space_used() between the statfs and this store is lost once:
   * bounded by one probe interval, inside JR_SLACK) */
  const uint64_t unw = atomic_load_explicit(&s->jr_pub, memory_order_acquire) - atomic_load_explicit(&s->jr_tail, memory_order_acquire);
  const uint64_t est = avail > unw ? avail - unw : 0;
  atomic_store_explicit(&s->avail_est, est > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)est, memory_order_relaxed);
  atomic_store_explicit(&s->fs_total, total, memory_order_relaxed);
  atomic_store_explicit(&s->fs_avail, avail, memory_order_relaxed);
  atomic_store_explicit(&s->fs_checked_unix, (uint64_t)time(NULL), memory_order_relaxed);
}
/* the estimate for a log line */
static uint64_t st_avail(const store_t *s) {
  const int64_t e = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  return e < 0 ? 0 : (uint64_t)e;
}
/* The probe is made before the writer mutex (0.7: a statfs inside it waited behind the file system's own locks): by the writer that finds it stale (a second, or a megabyte
 * reserved since, or none yet), one at a time (the CAS on last_probe_ms).  The mutex reads the estimate; it probes again only to confirm a refusal (jr_space_locked(),
 * space_allow(): the file system is nearly full then) and in the emergency cleaning. */
static void st_probe_stale(store_t *s) {
  const uint64_t now = st_now_ms();
  uint64_t last = atomic_load_explicit(&s->last_probe_ms, memory_order_relaxed);
  if (atomic_load_explicit(&s->avail_est, memory_order_relaxed) >= 0 && now - last < 1000 && atomic_load_explicit(&s->probe_bytes, memory_order_relaxed) < (1u << 20)) return;
  if (!atomic_compare_exchange_strong_explicit(&s->last_probe_ms, &last, now, memory_order_relaxed, memory_order_relaxed)) return;    /* (another thread probes now) */
  fs_probe(s);
}
/* An ordinary append of rlen bytes: is there room that is not the cleaner's nor the journal's (jr_floor())?  The cleaner is not checked (as before 0.7: it makes the room, a
 * segment is freed only after its live records were copied). */
static int space_allow(store_t *s, uint64_t rlen) {
  if (s->in_cleaner) return 0;
  const uint64_t keep = s->reserve_bytes + jr_floor(s);
  int64_t est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  if (est < 0) { fs_probe(s); est = atomic_load_explicit(&s->avail_est, memory_order_relaxed); }
  if (est >= 0 && (uint64_t)est < keep + rlen) {
    st_reprobe_locked(s);
    est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
    if (est >= 0 && (uint64_t)est < keep + rlen) return -ENOSPC;
  }
  return 0;
}
static void space_used(store_t *s, uint64_t n) {
  atomic_fetch_add_explicit(&s->probe_bytes, n, memory_order_relaxed);
  int64_t c = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  while (c >= 0 && !atomic_compare_exchange_weak_explicit(&s->avail_est, &c, (uint64_t)c > n ? c - (int64_t)n : 0, memory_order_relaxed, memory_order_relaxed)) {}
}

/* The size at which a checkpoint is forced (journal_max_bytes), and the base of the bound of the journal (jbound()).  While a bulk fill runs (store_journal_boost(): the manifest pass
 * of a first fill) it is JBOOST times as much: with the index reserved at its full size (round 10) every checkpoint writes all of it (10M zones: 430 to 600 MB, the hash scatters the
 * writes over every page), and one every 100 MiB of journal kept the disk busy with checkpoints for the whole pass (round 11: 14 to 17 of them, the journal bound waits of the pass
 * and a manifest pass of 42 to 45 s in 3 runs of 10).  A fourth of the checkpoints, the replay of a crash during the fill (which starts again anyway) four times as long: 400 MiB, about
 * 4 s.  Not when the file system could not take it: the journal at the hard bound of the thread that also answers lookups (4 x the raised size, 1.6 GiB at the default) must be no more
 * than an eighth of what is free (the share at which jr_floor() cuts what the checkpoint may still allocate, and the ENOSPC states of the journal keep their meaning: they look at
 * every record, not at this bound); the estimate is the checkpoint's probe, so a disk that fills during the fill takes the raise back by itself (a checkpoint cuts the journal at the
 * normal size then), and an unknown estimate (no statfs) never raises it.  On ZFS statfs counts everything the file system holds, on UFS only what is allocated: the same
 * estimate as the other space checks. */
#define JBOOST 4u
#define JBOOST_SPACE 8u
static uint64_t jmax(const store_t *s) {
  const uint64_t m = s->o.journal_max_bytes;
  if (!atomic_load_explicit(&s->jboost, memory_order_relaxed) || m > UINT64_MAX / (JBOOST_SPACE * 4u * JBOOST)) return m;
  const int64_t est = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  return est >= 0 && (uint64_t)est >= (uint64_t)JBOOST_SPACE * 4u * JBOOST * m ? (uint64_t)JBOOST * m : m;
}

/* is a commit due? (no lock: atomics) */
static bool commit_due(const store_t *s, uint64_t now) {
  const uint64_t lsn = atomic_load_explicit(&s->lsn, memory_order_relaxed), done = atomic_load_explicit(&s->committed_lsn, memory_order_relaxed);
  if (lsn <= done) return false;
  if (s->o.sync_policy == STORE_SYNC_EVERY) return true;               /* (what the writers' calls left: the cleaner, the scrub, a call that failed) */
  return s->o.sync_policy == STORE_SYNC_BATCH && now - atomic_load_explicit(&s->last_sync_ms, memory_order_relaxed) >= s->o.sync_interval_ms;
}
/* the bytes of every segment (the sum of their used counters; no lock: relaxed loads of the counters, a figure for the cadence of the bulk checkpoints) */
static uint64_t st_seg_bytes(const store_t *s) {
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS);
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  uint64_t b = 0;
  for (uint32_t n = 1; n <= nsegs; n++) b += VG(s, V_SEG(n, 0));
  return b;
}
#ifdef KARIDNS_UNIT_TEST
uint64_t store_test_seg_bytes(store_t *s) { return st_seg_bytes(s); }
#endif
/* the segment bytes at which the next bulk checkpoint is due: twice the bytes of the last one, and at least opts.bulk_ckpt_bytes more */
static uint64_t bulk_next_bytes(const store_t *s) {
  const uint64_t base = atomic_load_explicit(&s->bulk_base, memory_order_relaxed), minb = s->o.bulk_ckpt_bytes ? s->o.bulk_ckpt_bytes : ST_BULK_BYTES;
  const uint64_t a = base > UINT64_MAX / 2 ? UINT64_MAX : 2 * base, b = base > UINT64_MAX - minb ? UINT64_MAX : base + minb;
  return a > b ? a : b;
}
/* Is a bulk checkpoint due?  (THE BULK FILL: none while a pass runs; in the body fill when the segments reached bulk_next_bytes(), or when opts.bulk_ckpt_interval_ms passed since the last one and the
 * segments grew; no lock) */
static bool bulk_due(const store_t *s, uint64_t now) {
  if (!atomic_load_explicit(&s->bulk, memory_order_relaxed) || !atomic_load_explicit(&s->bulk_body, memory_order_relaxed)) return false;
  const uint64_t seg = st_seg_bytes(s), ivl = s->o.bulk_ckpt_interval_ms ? s->o.bulk_ckpt_interval_ms : ST_BULK_IVL_MS;
  if (seg <= atomic_load_explicit(&s->bulk_base, memory_order_relaxed)) return false;
  return seg >= bulk_next_bytes(s) || now - atomic_load_explicit(&s->bulk_last_ms, memory_order_relaxed) >= ivl;
}
/* is a checkpoint due? */
static bool ckpt_due(const store_t *s, uint64_t now) {
  if (atomic_load_explicit(&s->bulk, memory_order_relaxed)) return bulk_due(s, now);     /* (a bulk fill: not by the journal, which holds nothing, nor by checkpoint_interval_ms) */
  if (atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed)) return now >= atomic_load_explicit(&s->bulk_end_next_ms, memory_order_relaxed);      /* (its end, until a superblock without SBF_BULK is on disk; after a failure, or with no room, once its back-off is over, st_ckpt()) */
  const uint64_t lsn = atomic_load_explicit(&s->lsn, memory_order_relaxed);
  if (atomic_load_explicit(&s->jbytes, memory_order_relaxed) >= jmax(s)) return true;
  if (lsn <= atomic_load_explicit(&s->ckpt_lsn, memory_order_relaxed)) return false;
  if (atomic_load_explicit(&s->ck_want, memory_order_relaxed)) return true;
  return s->o.checkpoint_interval_ms != UINT32_MAX && now - atomic_load_explicit(&s->last_ckpt_ms, memory_order_relaxed) >= s->o.checkpoint_interval_ms;
}

/* After a writer call (writer mutex held): no I/O wait here.  The due commit and checkpoint are the flusher's (it is woken); a journal that is full is switched at once when no other
 * checkpoint runs (the flush of that checkpoint is handed to the flusher), so that the journal stays near its bound. */
static int post_write(store_t *s) {
  const uint64_t now = st_now_ms();
  bool kick = commit_due(s, now);
  if (s->fl_on && s->jbytes >= jmax(s) && ck_try_locked(s)) {
    int r = s->jold < 0 ? ck_begin_locked(s, false, true) : 1;          /* (the writers cleared the clean flag in wr_lock(); a journal whose sync failed is the flusher's first) */
    if (r == 0) {
      pthread_mutex_lock(&s->bg_mu);
      s->ck_handoff = true;
      pthread_cond_broadcast(&s->bg_cv);
      pthread_mutex_unlock(&s->bg_mu);
    } else {
      bg_release(s, true, true);
      if (r < 0) note_error(s, r);
      kick = true;
    }
  } else if (ckpt_due(s, now)) {
    kick = true;
  }
  retire_run(s, false);
  if (kick && s->fl_on) bg_signal(s);
  return 0;
}

/* The writer mutex for a call that writes records: a clean flag on disk is cleared first (the mutex is given up while the checkpoint's flags are waited for).  0, or the error of that
 * superblock write (the mutex is not held then). */
/* Before the mutex (0.7, the journal ring): the probe of the free space when it is stale, the states that take no record (-ENOSPC, -EIO at once: nobody waits for a full or
 * failed disk), and room in the ring: while less than JR_ADMIT is free (a stall longer than the ring) the caller writes or waits here, with no store lock held, so that the
 * in-mutex drain of jr_room_locked() stays rare. */
static int wr_admit(store_t *s) {
  st_probe_stale(s);
  const int st = atomic_load_explicit(&s->jw_state, memory_order_acquire);
  if (st == JW_FAILED) return -EIO;
  if (st == JW_NOSPACE) return -ENOSPC;
  const uint64_t pub = atomic_load_explicit(&s->jr_pub, memory_order_acquire), tail = atomic_load_explicit(&s->jr_tail, memory_order_acquire);
  const uint64_t admit = JR_ADMIT < s->jr_cap / 8 ? JR_ADMIT : s->jr_cap / 8;         /* (a small ring, in the tests: an eighth of it) */
  if (pub - tail + admit <= s->jr_cap && atomic_load_explicit(&s->jx_pub, memory_order_acquire) - atomic_load_explicit(&s->jx_done, memory_order_acquire) + 2 < s->jx_cap) return 0;
  const uint64_t t0 = st_now_us();
  atomic_fetch_add_explicit(&s->n_jr_waits, 1, memory_order_relaxed);
  const int r = jw_wait(s, pub, &s->bg_stop_a);       /* (a stop ends the wait: R2) */
  const uint64_t us = st_now_us() - t0;
  uint64_t m = atomic_load_explicit(&s->jr_wait_max_us, memory_order_relaxed);
  while (us > m && !atomic_compare_exchange_weak_explicit(&s->jr_wait_max_us, &m, us, memory_order_relaxed, memory_order_relaxed)) {}
  return r;
}
static int wr_lock_at(store_t *s, const char *site) {
  const int ar = wr_admit(s);
  if (ar < 0) { note_error(s, ar); return ar; }
  wr_lock_raw_at(s, site);
  while (atomic_load_explicit(&s->clean_on_disk, memory_order_relaxed)) {
    wr_unlock_raw(s);
    ck_acquire(s);
    wr_lock_raw_at(s, site);
    const int r = unclean_now_locked(s);
    bg_release(s, true, true);
    if (r < 0) {
      wr_unlock_raw(s);
      note_error(s, r);
      return r;
    }
  }
  return 0;
}

/* the due work without a flusher thread (no lock held) */
static void bg_due(store_t *s) {
  const uint64_t now = st_now_ms();
  if (atomic_load_explicit(&s->jw_state, memory_order_acquire) == JW_NOSPACE) jw_retry(s);    /* (no flusher: the writers' calls and the tick try the write again, once each) */
  if (commit_due(s, now)) (void)st_commit(s, atomic_load_explicit(&s->lsn, memory_order_relaxed));
  if (ckpt_due(s, now) && st_ckpt(s, false, false) == 0) ck_after(s);
}

/* The bound of the journal (0.7, store_journal_wait()).  A checkpoint begins when the journal reaches journal_max_bytes and the records go on in the next file while it flushes;
 * a journal that reaches a multiple of the limit before a checkpoint could cut it (the disk is slower than the writes, or no checkpoint could begin: the baton was busy, one had
 * failed) makes the writers that call this wait: the flusher is woken, and the call returns when the journal was switched or when a checkpoint ended (ck_ends; one that failed
 * too: a disk that fails is not waited for forever, each call waits for one try).  Not in the store's own calls: their callers hold locks of their own (the Backend's record
 * mutex), and a thread that waits for one of those would wait for the disk with them; the caller waits between its writes with no lock held.  So the journal, the replay after a
 * crash and the work of a clean stop stay bounded by factor x journal_max_bytes plus what one call of each such writer adds after its check.  The trade-off: those writers are
 * slowed down to the disk, which happens only when a checkpoint takes longer than the writing of journal_max_bytes of records (a 10M first fill on ZFS: during the manifest pass,
 * whose journal grows by 7 MB a second against checkpoints of 6 to 17 s), against a journal of gigabytes and minutes of replay.  Counted; a WARNING at most once a minute. */
static uint64_t jbound(const store_t *s, unsigned factor) {
  const uint64_t m = jmax(s);
  return factor && m > UINT64_MAX / factor ? UINT64_MAX : (uint64_t)factor * m;
}
uint64_t store_journal_wait(store_t *s, unsigned factor) {
  if (!s || factor == 0 || !s->fl_on) return 0;                  /* (without the flusher the writers make the checkpoints themselves: the journal does not run ahead) */
  const uint64_t lim = jbound(s, factor);
  if (atomic_load_explicit(&s->jbytes, memory_order_relaxed) < lim) return 0;
  const uint64_t t0 = st_now_us();
  bool waited = false, warn = false;
  pthread_mutex_lock(&s->bg_mu);
  const uint64_t ends = s->ck_ends;
  while (!s->bg_stop && s->ck_ends == ends && atomic_load_explicit(&s->jbytes, memory_order_relaxed) >= lim) {
    if (!waited) {
      const uint64_t now = st_now_ms();
      warn = s->jw_warn_ms == 0 || now - s->jw_warn_ms >= 60000u;
      if (warn) s->jw_warn_ms = now ? now : 1;
      s->bg_kick = true;                                 /* (the checkpoint thread begins one when none runs: the journal is over journal_max_bytes) */
      pthread_cond_broadcast(&s->bg_cv);
      waited = true;
    }
    pthread_cond_wait(&s->bg_cv, &s->bg_mu);             /* (bg_release() broadcasts: the baton after a switch, the end of a checkpoint) */
  }
  pthread_mutex_unlock(&s->bg_mu);
  if (!waited) return 0;
  const uint64_t us = st_now_us() - t0;
  const uint64_t n = atomic_fetch_add_explicit(&s->jw_n, 1, memory_order_relaxed) + 1;
  atomic_fetch_add_explicit(&s->jw_us, us, memory_order_relaxed);
  uint64_t m = atomic_load_explicit(&s->jw_max_us, memory_order_relaxed);
  while (us > m && !atomic_compare_exchange_weak_explicit(&s->jw_max_us, &m, us, memory_order_relaxed, memory_order_relaxed)) {}
  if (warn)
    st_log(s, 4, "store: the journal reached %u x journal_max_bytes (%" PRIu64 " bytes) before a checkpoint could cut it: a writer waited %" PRIu64 " ms (%" PRIu64 " waits since the open); "
                 "the disk does not keep up with the writes (store.journal.limit_waits, store.checkpoint.max_us)", factor, lim, us / 1000u, n);
  return us ? us : 1;
}

/* A bulk fill begins (on) or ends (off): see jmax().  Idempotent, no lock: the flag is read by the writers' checks.  The end of the fill: the journal may be past the normal size
 * (up to JBOOST x it, 2 x that at the bound of the pass), so the checkpoint that cuts it is due now, not at the next write or the next tick: the flusher is woken (ckpt_due() is
 * true at the normal size again; without a flusher the next writer call or tick makes it).  A crash before that checkpoint ended replays the larger journal (about 1 s per 100 MiB). */
void store_journal_boost(store_t *s, bool on) {
  if (!s) return;
  if (on) {
    if (atomic_exchange_explicit(&s->jboost, true, memory_order_acq_rel)) return;
    atomic_fetch_add_explicit(&s->n_jboost, 1, memory_order_relaxed);
    const uint64_t m = jmax(s);
    st_log(s, 6, "store: a bulk fill begins: a checkpoint is forced at %" PRIu64 " KiB of journal%s", m >> 10,
           m > s->o.journal_max_bytes ? "" : " (the free space is too small for a larger bound: it stays at the normal size)");
    return;
  }
  if (!atomic_exchange_explicit(&s->jboost, false, memory_order_acq_rel)) return;
  const uint64_t j = atomic_load_explicit(&s->jbytes, memory_order_relaxed);
  st_log(s, 6, "store: the bulk fill is over: a checkpoint is forced at %" PRIu64 " KiB of journal again (the journal holds %" PRIu64 " KiB)", s->o.journal_max_bytes >> 10, j >> 10);
  if (j >= s->o.journal_max_bytes && s->fl_on) bg_signal(s);
}

/* ---- 0.7: the unlogged bulk fill (THE BULK FILL at the top) ---- */

/* The fill of an empty store begins: the superblock that says BULK is made durable by a checkpoint with the writers kept out (cheap: the store is empty; the reserve of the tables and the index
 * comes after it, so that this checkpoint does not write the reserved index), and only then the writers stop logging. */
int store_bulk_begin(store_t *s) {
  if (!s) return -EINVAL;
  wr_lock_ck(s);
  int r = 0;
  if (atomic_load_explicit(&s->bulk, memory_order_relaxed)) {
    atomic_store_explicit(&s->bulk_body, false, memory_order_relaxed);     /* (going on: a pass begins) */
  } else if (VG(s, V_KNOWN) + VG(s, V_STORED) != 0 || st_seg_bytes(s) != 0 || atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed)) {
    r = -EEXIST;                                      /* (zone records, or segments of zones that are gone: dead bytes the cleaner would not free during the fill, which the doubling rule counts) */
  } else {
    atomic_store_explicit(&s->bulk, true, memory_order_relaxed);          /* (the superblock of the checkpoint below says BULK; no writer runs before it is on disk) */
    atomic_store_explicit(&s->bulk_body, false, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_passed, false, memory_order_relaxed);
    r = ck_full_locked(s, false);
    if (r < 0) {
      atomic_store_explicit(&s->bulk, false, memory_order_relaxed);
      note_error(s, r);
    } else {
      atomic_store_explicit(&s->bulk_base, st_seg_bytes(s), memory_order_relaxed);
      atomic_store_explicit(&s->bulk_last_ms, st_now_ms(), memory_order_relaxed);
      atomic_store_explicit(&s->bulk_since, (uint64_t)time(NULL), memory_order_relaxed);
      atomic_fetch_add_explicit(&s->n_bulk_fills, 1, memory_order_relaxed);
      st_log(s, 6, "store: an unlogged bulk fill of the empty store begins: the writers keep no journal until it is over (a crash goes back to the last bulk checkpoint, and the zones after it are read again)");
    }
  }
  (void)wr_unlock_ck(s);
  return r;
}

void store_bulk_phase(store_t *s, int phase) {
  if (!s || (phase != STORE_BULK_PASS && phase != STORE_BULK_BODY && phase != STORE_BULK_PASSED)) return;
  wr_lock_raw(s);
  if (atomic_load_explicit(&s->bulk, memory_order_relaxed)) {
    atomic_store_explicit(&s->bulk_body, phase != STORE_BULK_PASS, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_passed, phase == STORE_BULK_PASSED, memory_order_relaxed);     /* (a pass that begins, or that was cut off or failed: the fill needs one more that ends complete) */
  }
  wr_unlock_raw(s);
  if (phase != STORE_BULK_PASS && s->fl_on) bg_signal(s);              /* (a bulk checkpoint may be due now: the pass took long) */
}

int store_bulk(const store_t *s) {
  if (!s || !atomic_load_explicit(&s->bulk, memory_order_relaxed)) return 0;
  return atomic_load_explicit(&s->bulk_passed, memory_order_relaxed) ? 2 : 1;
}

bool store_bulk_pending(const store_t *s) { return s && st_bulk_busy(s); }
bool store_bulk_cut(const store_t *s) { return s && atomic_load_explicit(&s->bulk_cut, memory_order_relaxed); }
/* (the cursors were dropped: the next superblock has no SBF_BULK_CUT; it holds the dropped cursors too, which were changed before this under the writer mutex) */
void store_bulk_cut_done(store_t *s) {
  if (!s) return;
  wr_lock_raw(s);
  atomic_store_explicit(&s->bulk_cut, false, memory_order_relaxed);
  wr_unlock_raw(s);
  if (s->fl_on) bg_signal(s);
}

/* The fill is over (THE BULK FILL, E): the records the writers make from now on are logged (their LSNs follow the last checkpoint's), and the end is pending until a fuzzy checkpoint at a position
 * after this writes the tables (every page marked since the last full write, ix / sx included: a generation made during the fill whole) and a superblock without BULK (ck_finish() clears it).  That
 * checkpoint is the checkpoint thread's (ckpt_due(): due until it is on disk, after a failure again when the flusher's back-off is over), unless the caller waits (STORE_BULK_END_WAIT: made here; no
 * flusher: here too).  Until it is on disk a crash goes back to the last bulk checkpoint: the commits acknowledged meanwhile are lost with the fill (decision 1 of the plan). */
int store_bulk_end(store_t *s, unsigned how) {
  if (!s) return -EINVAL;
  wr_lock_raw(s);
  const bool was = atomic_load_explicit(&s->bulk, memory_order_relaxed) && (!(how & STORE_BULK_END_IF_PASSED) || atomic_load_explicit(&s->bulk_passed, memory_order_relaxed));
  if (was) {
    atomic_store_explicit(&s->bulk_end_pending, true, memory_order_relaxed);      /* (before the flag goes: st_bulk_busy() never sees neither) */
    atomic_store_explicit(&s->bulk, false, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_body, false, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_passed, false, memory_order_relaxed);
    atomic_store_explicit(&s->bulk_ended, (uint64_t)time(NULL), memory_order_relaxed);
  }
  const bool pending = atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed);
  wr_unlock_raw(s);
  if (was)
    st_log(s, 6, "store: the unlogged bulk fill is over (%" PRIu64 " unlogged records, %" PRIu64 " bulk checkpoints): the writers keep the journal again; the checkpoint that ends it writes every table",
           atomic_load_explicit(&s->n_bulk_unlogged, memory_order_relaxed), atomic_load_explicit(&s->n_bulk_ckpts, memory_order_relaxed));
  if (!pending) return 0;
  if (!(how & STORE_BULK_END_WAIT) && s->fl_on) {
    bg_signal(s);                                     /* (the checkpoint thread: ckpt_due() is true while the end is pending) */
    return 0;
  }
  int r = st_ckpt(s, true, false);
  ck_after(s);
  if (r == 0 && atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed)) r = -EAGAIN;     /* (a checkpoint begun while the fill ran ended first: the caller asks again) */
  return r;
}

/* The end of a writer call: the mutex is given up; STORE_SYNC_EVERY makes the call durable now (with the mutex released: other writers go on), and without a flusher the due work is done
 * here (no wait for the bound of the journal: store_journal_wait() is the caller's).  Returns r, or the error of that commit. */
/* (after wr_ack(): the commit of STORE_SYNC_EVERY and, without a flusher, the due work) */
static int wr_finish(store_t *s, int r, uint64_t my) {
  if (r >= 0 && s->o.sync_policy == STORE_SYNC_EVERY) {
    const int c = st_commit(s, my);
    if (c < 0) r = c;
  }
  if (!s->fl_on) bg_due(s);
  return r;
}
/* the end of a writer call: the target of its acknowledgement (rule A) is the ring's head as the call leaves the mutex: its own records and every record it planned on */
static int wr_done(store_t *s, int r) {
  const uint64_t my = s->lsn, t = s->jr_head;
  wr_unlock_raw(s);
  return wr_finish(s, wr_ack(s, r, t), my);
}
/* the mutex is given up by an internal writer (the cleaner, the scrub, a compaction, a growth's publish): it waits for its bytes too, with no lock held */
static int wr_unlock_w(store_t *s) {
  const uint64_t t = s->jr_head;
  wr_unlock_raw(s);
  return jw_wait(s, t, NULL);
}

/* The open segment for a record of rlen bytes: the current one when it has room, else a new one (the lowest free segment number: a segment that was cleaned and removed
 * has "used = 0" and its number is used again).  The counters of a new segment go into the builder.  *cur / *used: where the record goes. */
/* The segment made ahead, when it can serve this call (the writer mutex held): its number, with its descriptor in *g.  `want` is the number the next segment has: the lowest free one, or the one after the
 * last (the numbers of cleaned segments are used again, lowest first, as before).  *rsv: the number the thread holds (being made, or made and not usable now), which the scan for a free number must skip.
 * Usable: it is made, it is the number wanted, and the record fits its size (cap).  A file made for another number (the cleaner freed a lower one since) is given up: the thread removes it and makes the
 * right one; this call makes its file itself.  The number of a file made ahead is free: nothing but seg_place() gives a free number a record. */
static uint32_t seg_pre_peek(store_t *s, uint64_t cap, uint32_t want, seg_t **g, uint32_t *rsv) {
  uint32_t n = 0;
  bool stale = false;
  *g = NULL;
  *rsv = 0;
  pthread_mutex_lock(&s->pre_mu);
  if (s->pre_state != PRE_NONE) {
    *rsv = s->pre_n;
    if (s->pre_state == PRE_READY && s->pre_n == want && cap <= s->seg_size) {
      n = want;
      *g = s->pre_g;
    } else if (s->pre_state == PRE_READY && s->pre_n != want) {
      s->pre_state = PRE_STALE;
      stale = true;
    }
  }
  pthread_mutex_unlock(&s->pre_mu);
  if (stale) ahead_kick(&s->ah_seg, NULL);
  return n;
}
/* The segment made ahead is used (writer mutex held).  Its descriptor takes the place of the one of an older segment of the same number, as seg_create() does (the file is the new one: it was made empty). */
static void seg_pre_take(store_t *s, uint32_t n, seg_t *g) {
  pthread_mutex_lock(&s->pre_mu);
  s->pre_state = PRE_NONE;
  s->pre_g = NULL;
  pthread_mutex_unlock(&s->pre_mu);
  s->seg_draining[n] = 0;                              /* (as seg_create(): a removal that waited for the journal (3) does not unlink the new file: N8) */
  pthread_mutex_lock(&s->seg_mu);
  seg_t *old = atomic_exchange_explicit(&s->segs[n], g, memory_order_acq_rel);
  pthread_mutex_unlock(&s->seg_mu);
  if (old) retire_add_seg(s, old);                     /* (a reader or a commit may still hold it) */
  atomic_fetch_add_explicit(&s->n_seg_pre, 1, memory_order_relaxed);
}
/* 0.7 attach-align: on ZFS a read of an image reads (and decompresses) every record of the file that the image touches, and the ARC keeps whole records.  An image of 11 KB in
 * records of 16 KB lay across a boundary in 68 % of the cases (1.5-1.6 records read per attach, 2026-11-24 profile): a record that would cross a boundary that it need not cross
 * starts at that boundary instead, when the bytes skipped are at most a record / ST_ALIGN_GAP_DIV (bounded padding: a store of small zones, where a record crosses a boundary in
 * a few percent of the cases and skips less than its own size, grows by a few percent of its logical size; the skipped bytes are never written, a hole the file system keeps
 * for nothing or a run of zeros its compression removes).  The skipped bytes count as dead bytes of the segment (they are not a record).  Readers do not change: a record is
 * where its cell says; the cleaner steps over the gap as over any bytes that are not a record. */
#define ST_ALIGN_GAP_DIV 2
static uint64_t seg_align_pos(const store_t *s, uint64_t used, uint64_t rlen) {
  const uint64_t rs = s->align_rs;
  if (rs == 0) return used;
  const uint64_t o = used % rs, next = used - o + rs;
  if (o == 0 || next - used > rs / ST_ALIGN_GAP_DIV) return used;
  return (o + rlen + rs - 1) / rs > (rlen + rs - 1) / rs ? next : used;      /* (records read from here, from the boundary) */
}

/* A new segment is needed.  A segment made ahead by seg_pre_make() is taken when there is one: no file is made inside the mutex.  Else the file is made here, as before (store.segment.inline_creates).
 * *used_out: where the record goes (the end of the open segment, or the next record boundary: seg_align_pos()). */
static int seg_place(store_t *s, uint64_t rlen, uint32_t *cur_out, uint64_t *used_out) {
  jb_t *j = &s->jb;
  uint32_t cur = (uint32_t)jb_vget(s, j, V_CUR_SEG);
  uint64_t used = cur ? seg_align_pos(s, jb_vget(s, j, V_SEG(cur, 0)), rlen) : 0;
  if (cur == 0 || used + rlen > s->seg_size) {
    uint32_t nsegs = (uint32_t)jb_vget(s, j, V_NSEGS), n = 0, rsv, want = 0;
    seg_t *pg;
    int r;
    uint64_t cap = s->seg_size;
    if (ST_SEGHDR + rlen > cap) cap = ST_SEGHDR + rlen;
    for (uint32_t i = 1; i <= nsegs && i <= ST_MAXSEG; i++)
      if (jb_vget(s, j, V_SEG(i, 0)) == 0) { want = i; break; }
    if (!want) want = nsegs + 1;
    n = seg_pre_peek(s, cap, want, &pg, &rsv);
    if (n) {
      if (n == nsegs + 1 && (r = jb_vset(j, V_NSEGS, n)) < 0) return r;
      seg_pre_take(s, n, pg);
    } else {
      for (uint32_t i = 1; i <= nsegs && i <= ST_MAXSEG; i++)
        if (i != rsv && jb_vget(s, j, V_SEG(i, 0)) == 0) { n = i; break; }
      if (!n) {
        n = nsegs + 1;
        if (n == rsv) n++;                             /* (the number the thread is making: this one leaves a free number behind, which the next call finds) */
        if (n > ST_MAXSEG) return -ENOSPC;
        if ((r = jb_vset(j, V_NSEGS, n)) < 0) return r;
      }
      r = seg_create(s, n, cap);
      if (r < 0) return r;
    }
    if ((r = jb_vset(j, V_CUR_SEG, n)) < 0 || (r = jb_vset(j, V_SEG(n, 0), ST_SEGHDR)) < 0 || (r = jb_vset(j, V_SEG(n, 1), 0)) < 0) return r;
    cur = n;
    used = seg_align_pos(s, ST_SEGHDR, rlen);
    s->pre_asked = 0;
  }
  *cur_out = cur;
  *used_out = used;
  return 0;
}

static int st_pwritev_all(int fd, const struct iovec *iov, int niov, uint64_t rlen, off_t off);
/* a record of rlen bytes is at `used` in the open segment cur (written there by this call or before the mutex, st_prewrite()): the segment is dirty, *loc is where it is, the counters
 * (used, live) go into the builder */
static int seg_note_append(store_t *s, uint32_t cur, uint64_t used, uint64_t rlen, uint64_t *loc) {
  jb_t *j = &s->jb;
  const uint64_t end = jb_vget(s, j, V_SEG(cur, 0));
  if (used > end) {                                   /* (seg_align_pos() moved it to a record boundary) */
    atomic_fetch_add_explicit(&s->n_align_pads, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->n_align_pad_bytes, used - end, memory_order_relaxed);
  }
  s->seg_dirty[cur] = 1;
  *loc = ((uint64_t)cur << ST_LOC_SHIFT) | (used / 64);
  space_used(s, rlen);
  if (used + rlen >= s->seg_size / 2 && s->pre_asked != cur) {      /* (half full: the next segment's file is made ahead, off the mutex.  Here, not in seg_place(): an image written before the mutex does not pass it) */
    s->pre_asked = cur;
    ahead_kick(&s->ah_seg, NULL);
  }
  int r = jb_vset(j, V_SEG(cur, 0), used + rlen);
  if (r == 0) r = jb_vset(j, V_SEG(cur, 1), jb_vget(s, j, V_SEG(cur, 1)) + rlen);
  return r;
}
/* Append the record (iov: its bytes, rlen in all, a multiple of 64) to the open segment; *loc = where it is.  The counters (used, live of the segment) go into the builder: the
 * caller's journal record makes them real.  Checked before anything is written: the free space (the cleaner may use the reserve). */
static int seg_put_bytes(store_t *s, const struct iovec *iov, int niov, uint64_t rlen, uint64_t *loc) {
  int r = space_allow(s, rlen);
  if (r < 0) return r;
  uint32_t cur;
  uint64_t used;
  if ((r = seg_place(s, rlen, &cur, &used)) < 0) return r;
  seg_t *g = seg_get(s, cur);
  if (!g) return -EIO;
#if defined(KARIDNS_UNIT_TEST) || defined(KARIDNS_TEST_EVICT)
  if (store_test_append_fault) {
    int fe = store_test_append_fault(rlen);
    if (fe) return fe;
  }
#endif
  CRASH_POINT();
  if ((r = st_pwritev_all(g->fd, iov, niov, rlen, (off_t)used)) < 0) return r;
  CRASH_POINT();
  return seg_note_append(s, cur, used, rlen, loc);
}

/* The bytes of an image record (header, name, image, padding), built for an append inside the writer mutex (seg_append()) or before it (st_prewrite()): the same bytes either way. */
typedef struct {
  rhdr_t h;
  uint8_t namepad[256 + 16];
  uint8_t tail[64];
  struct iovec iov[4];
  uint64_t rlen;
} recbuf_t;
static void rec_build(recbuf_t *b, uint32_t zid, uint16_t view, const uint8_t *fn, size_t klen, const store_meta_t *m, const void *image, size_t ilen, uint64_t prev_loc) {
  const uint64_t rlen = st_reclen(klen, ilen);
  rhdr_t *h = &b->h;
  memset(h, 0, sizeof(*h));
  h->magic = ST_MAGIC_REC;
  h->reclen = (uint32_t)rlen;
  h->zid = zid;
  h->view = view;
  h->kind = 0;
  h->flags = m->flags;
  h->serial = m->serial;
  h->settings = m->settings;
  h->img_len = (uint32_t)ilen;
  h->stamp_gen = m->stamp_gen;
  h->prev_loc = prev_loc;
  h->klen = (uint16_t)klen;
  const size_t np = st_pad16(klen);
  memset(b->namepad, 0, np);
  memcpy(b->namepad, fn, klen);
  memset(b->tail, 0, sizeof(b->tail));
  const size_t tl = (size_t)(rlen - ST_RHDR - np - ilen);
  uint64_t sum = st_sum64(h, sizeof(*h), 0);
  sum = st_sum64(b->namepad, np, sum);
  sum = st_sum64(image, ilen, sum);
  h->checksum = sum;
  b->iov[0].iov_base = h;
  b->iov[0].iov_len = sizeof(*h);
  b->iov[1].iov_base = b->namepad;
  b->iov[1].iov_len = np;
  b->iov[2].iov_base = (void *)(uintptr_t)image;
  b->iov[2].iov_len = ilen;
  b->iov[3].iov_base = b->tail;
  b->iov[3].iov_len = tl;
  b->rlen = rlen;
}

/* append an image record to the open segment; plans the counters.  *loc receives the location. */
static int seg_append(store_t *s, uint32_t zid, uint16_t view, const uint8_t *fn, size_t klen, const store_meta_t *m,
                      const void *image, size_t ilen, uint64_t prev_loc, uint64_t *loc, uint64_t *rlen_out) {
  recbuf_t b;
  rec_build(&b, zid, view, fn, klen, m, image, ilen, prev_loc);
  int r = seg_put_bytes(s, b.iov, 4, b.rlen, loc);
  if (r == 0) *rlen_out = b.rlen;
  return r;
}

/* ---- 0.7: the image of a store_put() is written before the writer mutex ----
 * Inside the mutex the pwritev() of the image waited for the vnode lock that a commit's fsync() of the open segment holds (UFS; 0.2 to 0.5 s at 10M zones under load), and every writer
 * waited behind it.  Now store_put() serialises the writers of images (ap_mu: store_put() and the cleaner, the only ones that append to a segment), takes the writer mutex for a moment to
 * read where the record goes (the zone's id and its record before, the open segment and its end), writes the record there with the mutex released, marks the segment dirty, and then
 * makes the change inside the mutex as before, with the record already in place.  The order is kept: the image is in the kernel before the journal record that points at it (kill -9),
 * and the segment is dirty before that record, so the commit that covers the record syncs the segment first (power loss).  Nothing is recorded for the bytes until that record: after
 * a crash in between they lie past the segment's end and are written over.  When anything changed in between (the zone, its record, the open segment or its end: a rotation, a
 * growth of the store, an emergency cleaning) the change appends the record again inside the mutex (counted, store.writes.prewrite_misses), at the same end, over the bytes.  A new
 * zone (its id is given inside the mutex) and a full segment take the old way. */
typedef struct prew {
  seg_t *g;
  uint32_t cur, zid;
  uint64_t used, rlen, prev_loc, end;            /* used: where the record is written; end: the end of the open segment it was placed after (seg_align_pos()) */
} prew_t;
static _Thread_local bool t_ap_held;                  /* this thread holds ap_mu (store_put(): the emergency cleaning inside it appends) */

/* the record's bytes at the place it was given (prewrite or seg_put_bytes()) */
static int st_pwritev_all(int fd, const struct iovec *iov, int niov, uint64_t rlen, off_t off) {
  size_t done = 0;
  const size_t total = (size_t)rlen;
  while (done < total) {
    struct iovec v[4];
    int nv = 0;
    size_t skip = done;
    for (int i = 0; i < niov && i < 4; i++) {
      if (skip >= iov[i].iov_len) { skip -= iov[i].iov_len; continue; }
      v[nv].iov_base = (uint8_t *)iov[i].iov_base + skip;
      v[nv].iov_len = iov[i].iov_len - skip;
      skip = 0;
      nv++;
    }
    ssize_t w = pwritev(fd, v, nv, off + (off_t)done);
    if (w < 0) {
      if (errno == EINTR) continue;
      return -errno;
    }
    if (w == 0) return -EIO;
    done += (size_t)w;
  }
  return 0;
}

/* true: the record is written at p (io_hold is taken: the caller gives it back after the change); false: the change appends inside the mutex */
static bool st_prewrite(store_t *s, uint16_t view, const char *name, size_t nlen, const store_meta_t *m, const void *image, size_t ilen, prew_t *p) {
#if defined(KARIDNS_UNIT_TEST) || defined(KARIDNS_TEST_EVICT)
  if (store_test_append_fault) return false;          /* (the faults of an append are made by the append inside the mutex) */
#endif
  uint8_t fn[256];
  for (size_t i = 0; i < nlen; i++) fn[i] = st_lc((uint8_t)name[i]);
  const uint64_t rlen = st_reclen(nlen, ilen);
  bool ok = false;
  wr_lock_raw(s);
  const uint64_t h = st_hash_name(s, view, fn, nlen);
  const uint32_t z = ix_lookup(s, atomic_load_explicit(&s->ix, memory_order_relaxed), view, fn, nlen, h);
  r64_t rt, rc;
  if (z != STORE_NONE && zrec_read_locked(s, z, &rt, &rc) == 0) {
    zt_t t;
    zt_unpack(&rt, &t);
    const uint32_t cur = (uint32_t)VG(s, V_CUR_SEG);
    const uint64_t end = cur ? VG(s, V_SEG(cur, 0)) : 0, used = end >= ST_SEGHDR ? seg_align_pos(s, end, rlen) : end;
    seg_t *g = cur && used >= ST_SEGHDR && used + rlen <= s->seg_size && space_allow(s, rlen) == 0 ? seg_get(s, cur) : NULL;
    if (g) {
      p->g = g;
      p->cur = cur;
      p->zid = z;
      p->used = used;
      p->end = end;
      p->rlen = rlen;
      p->prev_loc = t.state == STORE_STATE_STORED ? t.loc : 0;
      atomic_fetch_add_explicit(&s->io_hold, 1, memory_order_acq_rel);      /* (the segment's descriptor is not freed under the write, nor its seg_t reused: put_locked() compares it) */
      ok = true;
    }
  }
  wr_unlock_raw(s);
  if (!ok) return false;
  recbuf_t b;
  rec_build(&b, p->zid, view, fn, nlen, m, image, ilen, p->prev_loc);
  CRASH_POINT();
  if (st_pwritev_all(p->g->fd, b.iov, 4, rlen, (off_t)p->used) < 0) {
    atomic_fetch_sub_explicit(&s->io_hold, 1, memory_order_acq_rel);
    return false;                                     /* (the change appends inside the mutex: its error is the one reported, as before) */
  }
  CRASH_POINT();
  atomic_store_explicit(&s->seg_dirty[p->cur], 1, memory_order_relaxed);   /* (before the record: the commit that covers it syncs the segment) */
  {
    void (*hk)(store_t *) = atomic_load_explicit(&store_test_prewrite_hook, memory_order_acquire);
    if (hk) hk(s);                                    /* (tests: a change of the zone between the write and the mutex) */
  }
  return true;
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
  if ((flags & STORE_F_NONSTORE) && (r = jb_vadd(s, j, V_NONSTORE, d)) < 0) return r;
  return 0;
}
static int release_old_record(store_t *s, const zt_t *old) {
  if (old->state != STORE_STATE_STORED || old->loc == 0) return 0;
  uint32_t sn = (uint32_t)(old->loc >> ST_LOC_SHIFT);
  if (sn == 0 || sn > ST_MAXSEG) return 0;
  return jb_vadd(s, &s->jb, V_SEG(sn, 1), -(int64_t)st_reclen(old->klen, old->img_len));
}

/* Group commit (store_set_known_n(), 0.7 M2): the entries of one call are planned one after the other into the one journal builder and written as one record.  A pending entry has not written a
 * cell: what a later entry reads (the name index, the source index, the cells) is the state before the group, so the group holds no two entries that touch the same name or source id (put_locked()
 * returns KN_FLUSH_FIRST and the call writes the group, then plans the entry again) and a later entry probes past the index slots the earlier ones have claimed. */
#define KN_MAX STORE_GROUP_MAX
#define KN_FLUSH_FIRST (-0x7000)
typedef struct {
  unsigned n, nix, nsx, nsrc, nnew;     /* entries pending; index slots claimed (name, source); source ids held; of the pending entries, the ones that make a new record */
  uint64_t h[KN_MAX];                   /* the name hashes of the pending entries */
  int64_t src[2 * KN_MAX];              /* the source ids they take and give back */
  uint64_t ixpos[KN_MAX], sxpos[KN_MAX];
} kn_chunk_t;
static bool kn_has_hash(const kn_chunk_t *ck, uint64_t h) {
  for (unsigned i = 0; i < ck->n; i++)
    if (ck->h[i] == h) return true;
  return false;
}
static bool kn_has_src(const kn_chunk_t *ck, int64_t id) {
  for (unsigned i = 0; i < ck->nsrc; i++)
    if (ck->src[i] == id) return true;
  return false;
}

static int put_locked(store_t *s, uint16_t view, const char *name, size_t nlen, const store_meta_t *m, const void *image,
                      size_t ilen, uint8_t state, uint32_t *zid_out, kn_chunk_t *ck) {
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
  bool sx_new = m->source_id != 0 && (!exists || oc.source_id != m->source_id || oc.source != m->source);
  bool sx_old = exists && oc.source_id != 0 && (m->source_id != oc.source_id || m->source != oc.source);
  if (ck && ck->n > 0) {                                       /* a group: this entry must not touch what a pending entry touches (every read below is of the state before the group), and the tables must not have to grow under it */
    if (kn_has_hash(ck, h) || (m->source_id != 0 && kn_has_src(ck, m->source_id)) || (sx_old && kn_has_src(ck, oc.source_id))) return KN_FLUSH_FIRST;
    if ((!exists || sx_new) && ix_room_short(s, sx_new, ck->nix, ck->nsx)) return KN_FLUSH_FIRST;
  }
  /* conflict of the source key: another zone owns (source, domain id, view) */
  uint64_t sxh = 0;
  if (m->source_id != 0) {
    sxh = st_hash_src(s, m->source, view, m->source_id);
    uint32_t o = sx_lookup(s, atomic_load_explicit(&s->sx, memory_order_relaxed), m->source, view, m->source_id, sxh);
    if (o != STORE_NONE && o != z) return -EEXIST;
  }
  /* room: zid, nx, index slots */
  if (!exists) {
    int r = ix_make_room(s, sx_new);
    if (r < 0) return r;
    ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
  } else if (sx_new) {
    int r = ix_make_room(s, true);
    if (r < 0) return r;
  }
  if (!ck || ck->n == 0) jb_reset(j);
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
    const prew_t *p = s->prew;                       /* (store_put(): the record may be in place already, written before the mutex) */
    s->prew = NULL;
    const uint64_t prev = exists && ot.state == STORE_STATE_STORED ? ot.loc : 0;
    if (p && exists && p->zid == nz && p->prev_loc == prev && p->rlen == st_reclen(nlen, ilen) && jb_vget(s, j, V_CUR_SEG) == p->cur && jb_vget(s, j, V_SEG(p->cur, 0)) == p->end &&
        atomic_load_explicit(&s->segs[p->cur], memory_order_acquire) == p->g) {
      rlen = p->rlen;
      r = seg_note_append(s, p->cur, p->used, rlen, &loc);
      atomic_fetch_add_explicit(&s->n_prew, 1, memory_order_relaxed);
    } else {
      if (p) atomic_fetch_add_explicit(&s->n_prew_miss, 1, memory_order_relaxed);
      r = seg_append(s, nz, view, fn, nlen, m, image, ilen, prev, &loc, &rlen);
    }
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
      if ((r = jb_pl(j, 1, false, oh, z)) < 0) return r;
    }
    if (sx_new) {
      bool was_empty;
      uint64_t pos = slot_find_insert(sx, sxh, &was_empty, ck ? ck->sxpos : NULL, ck ? ck->nsx : 0);
      if (pos == UINT64_MAX) return -ENOSPC;
      if (ck) ck->sxpos[ck->nsx] = pos;                   /* (claimed when the entry is kept: below) */
      if ((r = jb_pl(j, 1, true, sxh, nz)) < 0) return r;
      if ((r = jb_slot(j, OP_SX, pos, st_slotval(st_tag(sxh), nz))) < 0) return r;
      if ((r = jb_vadd(s, j, V_SX_LIVE, 1)) < 0) return r;
      if (was_empty && (r = jb_vadd(s, j, V_SX_USED, 1)) < 0) return r;
    }
  }
  /* name index last: it publishes a new zone */
  if (!exists) {
    bool was_empty;
    uint64_t pos = slot_find_insert(ix, h, &was_empty, ck ? ck->ixpos : NULL, ck ? ck->nix : 0);
    if (pos == UINT64_MAX) return -ENOSPC;
    if (ck) ck->ixpos[ck->nix] = pos;
    if ((r = jb_pl(j, 0, true, h, nz)) < 0) return r;
    if ((r = jb_slot(j, OP_IX, pos, st_slotval(st_tag(h), nz))) < 0) return r;
    if ((r = jb_vadd(s, j, V_IX_LIVE, 1)) < 0) return r;
    if (was_empty && (r = jb_vadd(s, j, V_IX_USED, 1)) < 0) return r;
  }
  if (ck) {                                                     /* a group: the entry is planned; its record is written with the others (kn_flush()) */
    ck->h[ck->n++] = h;
    if (!exists) ck->nnew++;
    if (!exists) ck->nix++;
    if (sx_new) ck->nsx++;
    if (m->source_id != 0) ck->src[ck->nsrc++] = m->source_id;
    if (sx_old) ck->src[ck->nsrc++] = oc.source_id;
    if (zid_out) *zid_out = nz;
    return 0;
  }
  r = journal_commit_apply(s);
  if (r < 0) return r;
  if (exists) s->n_replaces++; else s->n_puts++;
  if (zid_out) *zid_out = nz;
  if (state == STORE_STATE_STORED && s->degraded) degraded_end(s);
  return 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* 0.7 WP9: degraded mode, the cleaner, the nx pass                                                                     */
/* ------------------------------------------------------------------------------------------------------------------ */

static void space_dead_totals(const store_t *s, uint64_t *dead_total);

static void degraded_begin(store_t *s) {
  if (!s->degraded) {
    s->degraded = true;
    atomic_store_explicit(&s->degraded_since, (uint64_t)time(NULL), memory_order_relaxed);
    atomic_store_explicit(&s->space_level, 2, memory_order_relaxed);
  }
  atomic_fetch_or(&s->state, STORE_ST_DEGRADED_NOSPC);
  if (rl_ok(&s->last_err_ms, 60000)) {
    uint64_t dead = 0;
    space_dead_totals(s, &dead);
    st_log(s, 3, "store: no room for zone images: %" PRIu64 " bytes are free on the file system, %" PRIu64 " of them are kept for the cleaner; the store holds %" PRIu64 " bytes, %" PRIu64
                 " of them dead.  Images of new and changed zones are not stored (the zone is kept without an image and read from the database when it is asked for); images that are stored are still served.  "
                 "%" PRIu64 " zones were kept without an image since the space ran out",
           st_avail(s), s->reserve_bytes, atomic_load_explicit(&s->store_bytes, memory_order_relaxed), dead,
           atomic_load_explicit(&s->n_degraded, memory_order_relaxed));
  }
}
static void degraded_end(store_t *s) {
  if (!s->degraded) return;
  s->degraded = false;
  atomic_store_explicit(&s->degraded_since, 0, memory_order_relaxed);
  atomic_store_explicit(&s->space_level, 0, memory_order_relaxed);
  atomic_fetch_and(&s->state, ~(uint32_t)STORE_ST_DEGRADED_NOSPC);
  st_log(s, 6, "store: there is room again (%" PRIu64 " bytes free): zone images are stored again; zones that were kept without an image get theirs when the database is read again",
         st_avail(s));
}

static inline uint64_t loc_of(uint32_t seg, uint64_t off) { return ((uint64_t)seg << ST_LOC_SHIFT) | (off / 64); }
static inline int seg_refs(const store_t *s, uint32_t n) {
  seg_t *g = atomic_load_explicit(&((store_t *)s)->segs[n], memory_order_acquire);
  return g ? atomic_load_explicit(&g->refs, memory_order_acquire) : 0;
}

/* The zone keeps its record (name, stamp, digest, source) and loses its image: it is KNOWN, and the loader fetches it again.  expect_loc != 0: only when the zone still has the
 * image at that place (it may have been replaced).  Returns 0 (done), 1 (the zone is not stored there any more), or an error. */
static int zone_make_known_locked(store_t *s, uint32_t z, uint64_t expect_loc) {
  r64_t rt, rc;
  if (zrec_read_locked(s, z, &rt, &rc) < 0) return 1;
  zt_t t;
  zc_t c;
  zt_unpack(&rt, &t);
  zc_unpack(&rc, &c);
  if (t.state != STORE_STATE_STORED || (expect_loc && t.loc != expect_loc)) return 1;
  uint8_t fn[256];
  if (!zt_fullname(s, &t, fn)) return 1;
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.source_id = c.source_id;
  m.source = c.source;
  m.flags = t.flags;
  m.serial = t.serial;
  m.settings = t.settings;
  m.stamp_gen = c.stamp_gen;
  m.stamp_time = c.stamp_time;
  memcpy(m.digest, c.digest, STORE_DIGEST_LEN);
  return put_locked(s, t.view, (const char *)fn, t.klen, &m, NULL, 0, STORE_STATE_KNOWN, NULL, NULL);
}

/* ---- damaged images: the owner's notice ----
 * The zone of a damaged image was made KNOWN above (the writer mutex is held); the owner (opts.bad_image) may keep that image mapped in an attached zone, and takes the zone out of memory.  The notice is
 * only queued here: the owner takes its own locks (the registry's, which comes before the writer mutex in the lock order), so the tick hands the zone ids over when no lock of the store is held. */
#define ST_BAD_TRIES 100                 /* the owner said "not now" this many times: the zone is left to the next load from the database */
static void bad_note(store_t *s, uint32_t zid) {
  if (!s->o.bad_image) return;
  struct bad_n *n = malloc(sizeof(*n));
  pthread_mutex_lock(&s->bad_mu);
  if (!n) {
    s->bad_lost++;
  } else {
    n->next = NULL;
    n->zid = zid;
    n->tries = 0;
    if (s->bad_tail) s->bad_tail->next = n; else s->bad_head = n;
    s->bad_tail = n;
  }
  pthread_mutex_unlock(&s->bad_mu);
}
/* hand the queued zone ids to the owner (no lock of the store held); the ones that it cannot take now are queued again */
static void bad_drain(store_t *s) {
  if (!s->o.bad_image) return;
  pthread_mutex_lock(&s->bad_mu);
  struct bad_n *n = s->bad_head;
  s->bad_head = s->bad_tail = NULL;
  pthread_mutex_unlock(&s->bad_mu);
  while (n) {
    struct bad_n *next = n->next;
    const int r = s->o.bad_image(n->zid, s->o.bad_image_ctx);
    if (r == 1 && n->tries + 1 < ST_BAD_TRIES) {
      n->tries++;
      n->next = NULL;
      pthread_mutex_lock(&s->bad_mu);
      if (s->bad_tail) s->bad_tail->next = n; else s->bad_head = n;
      s->bad_tail = n;
      pthread_mutex_unlock(&s->bad_mu);
    } else {
      free(n);
    }
    n = next;
  }
}
static void bad_free_all(store_t *s) {
  struct bad_n *n = s->bad_head;
  while (n) {
    struct bad_n *next = n->next;
    free(n);
    n = next;
  }
  s->bad_head = s->bad_tail = NULL;
}

/* ---- the cleaner ---- */

/* The segment to clean: the one with the least live share among those that are dead enough, are not open, are not pinned and were not given up on.  *ncand / *dead_total (optional): the
 * number of segments that are dead enough and the dead bytes of all but the open one; *pinned: of the candidates, those an image points into; *draining: segments with nothing live. */
/* The background cleaner does not copy a segment that is still dying (0.7).  A segment whose dead bytes changed in the last CL_SETTLE_MS is being emptied by the writers right now
 * (a pass of the loader rewrites zone after zone, in the order the segment holds them): its live records are most likely replaced within seconds, and copying them is work that
 * is thrown away (run_db_store_test: when the store's lock no longer waited for the journal the cleaner took such segments at 50 % dead and moved 2.7 times the bytes).  It waits
 * until the dead bytes stand still, unless the segment is mostly dead already (live <= a quarter: cheap to copy), the space is low or the cleaner was asked for (store_compact(),
 * the operator's full speed, the emergency cleaning: they do not use the rule).  A store with steady random churn reaches the quarter on its own. */
#define CL_SETTLE_MS 1000u
static void cl_settle_scan_locked(store_t *s, uint64_t now) {
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS);
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  for (uint32_t n = 1; n <= nsegs; n++) {
    const uint64_t used = VG(s, V_SEG(n, 0)), live = VG(s, V_SEG(n, 1));
    const uint64_t body = used > ST_SEGHDR ? used - ST_SEGHDR : 0, dead = live < body ? body - live : 0;
    if (dead != s->seg_dead_seen[n] || s->seg_dead_ms[n] == 0) { s->seg_dead_seen[n] = dead; s->seg_dead_ms[n] = now; }
  }
}
static uint32_t cl_pick_ex(const store_t *s, uint32_t *ncand, uint64_t *dead_total, uint32_t *pinned, uint32_t *draining, bool respect_skip, bool settle);
static uint32_t cl_pick(const store_t *s, uint32_t *ncand, uint64_t *dead_total, uint32_t *pinned, uint32_t *draining, bool respect_skip) {
  return cl_pick_ex(s, ncand, dead_total, pinned, draining, respect_skip, false);
}
static uint32_t cl_pick_ex(const store_t *s, uint32_t *ncand, uint64_t *dead_total, uint32_t *pinned, uint32_t *draining, bool respect_skip, bool settle) {
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS), cur = (uint32_t)VG(s, V_CUR_SEG), best = 0;
  uint64_t now = st_now_ms(), mind = s->seg_size / 4 < (1ull << 20) ? s->seg_size / 4 : (1ull << 20);
  uint64_t best_pct = 101;
  uint32_t nc = 0, np = 0, nd = 0;
  uint64_t dt = 0;
  unsigned pct_min = s->o.compact_min_dead_pct ? s->o.compact_min_dead_pct : 50;
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  for (uint32_t n = 1; n <= nsegs; n++) {
    uint64_t used = VG(s, V_SEG(n, 0)), live = VG(s, V_SEG(n, 1));
    if (used <= ST_SEGHDR || n == cur) continue;
    uint64_t body = used - ST_SEGHDR, dead = live < body ? body - live : 0;
    dt += dead;
    if (live == 0) { nd++; continue; }
    if (dead * 100 < body * pct_min || dead < mind) continue;
    nc++;
    if (seg_refs(s, n) > 0) { np++; continue; }
    if (respect_skip && s->seg_skip_until[n] > now) continue;
    if (settle && live * 4 > body && now - s->seg_dead_ms[n] < CL_SETTLE_MS && atomic_load_explicit(&s->space_level, memory_order_relaxed) == 0) continue;     /* (still dying: see above) */
    uint64_t pct = live * 100 / body;
    if (pct < best_pct) { best_pct = pct; best = n; }
  }
  if (ncand) *ncand = nc;
  if (dead_total) *dead_total = dt;
  if (pinned) *pinned = np;
  if (draining) *draining = nd;
  return best;
}
static void space_dead_totals(const store_t *s, uint64_t *dead_total) { (void)cl_pick(s, NULL, dead_total, NULL, NULL, false); }

/* The open segment is never cleaned: it is still being written.  But a store whose zones are all replaced again and again fills a big segment with dead records and has nothing else
 * to clean: when the open segment is dead enough (as a segment must be to be a victim) it is closed (the next append begins a new one), and it is a victim like the others.
 * Writer mutex held.  true: it was closed. */
static bool cl_rotate_open_locked(store_t *s) {
  uint32_t cur = (uint32_t)VG(s, V_CUR_SEG);
  if (!cur || cur > ST_MAXSEG) return false;
  uint64_t used = VG(s, V_SEG(cur, 0)), live = VG(s, V_SEG(cur, 1)), mind = s->seg_size / 4 < (1ull << 20) ? s->seg_size / 4 : (1ull << 20);
  unsigned pct_min = s->o.compact_min_dead_pct ? s->o.compact_min_dead_pct : 50;
  if (used <= ST_SEGHDR) return false;
  uint64_t body = used - ST_SEGHDR, dead = live < body ? body - live : 0;
  if (dead * 100 < body * pct_min || dead < mind) return false;
  jb_reset(&s->jb);
  if (jb_vset(&s->jb, V_CUR_SEG, 0) < 0) return false;
  return journal_commit_apply(s) == 0;
}

/* the bytes [off, off + need) of the victim: MAP mode points into the mapping, COPY mode reads a piece of the file; NULL when they are not there */
static const uint8_t *cl_window(store_t *s, seg_t *g, uint64_t off, uint64_t need, uint64_t used) {
  if (need > (256ull << 20) || off + need > used) return NULL;
  if (s->mode == STORE_MODE_MAP) return g->map && off + need <= g->maplen ? g->map + off : NULL;
  if (s->cl_buf && off >= s->cl_buf_off && off + need <= s->cl_buf_off + s->cl_buf_len) return s->cl_buf + (off - s->cl_buf_off);
  uint64_t want = need > ST_CL_CHUNK ? need : ST_CL_CHUNK;
  if (off + want > used) want = used - off;
  if (want < need) return NULL;
  if (want > s->cl_buf_cap) {
    uint8_t *nb = realloc(s->cl_buf, (size_t)want);
    if (!nb) return NULL;
    s->cl_buf = nb;
    s->cl_buf_cap = (size_t)want;
  }
  s->cl_buf_len = 0;
  if (st_pread_all(g->fd, s->cl_buf, (size_t)want, (off_t)off) < 0) return NULL;
  s->cl_buf_off = off;
  s->cl_buf_len = (size_t)want;
  return s->cl_buf;
}

static void cl_reset_victim(store_t *s) {
  s->cl_seg = 0;
  s->cl_off = 0;
  s->cl_buf_len = 0;
}

/* Move the live record at (victim, off): copy its bytes to the open segment and give the zone the new location, in one journal record (writer mutex held). */
static int cl_move_locked(store_t *s, uint32_t zid, const zt_t *t, const r64_t *rc, const uint8_t *rec, uint64_t rlen) {
  jb_t *j = &s->jb;
  jb_reset(j);
  uint64_t newloc = 0;
  struct iovec iov = { (void *)rec, (size_t)rlen };
  int r = seg_put_bytes(s, &iov, 1, rlen, &newloc);
  if (r < 0) return r;
  zt_t nt = *t;
  nt.loc = newloc;
  r64_t nrt, nrc = *rc;
  zt_pack(&nt, &nrt);
  zrec_seal(&nrt, &nrc);
  if ((r = jb_zrec(j, zid, &nrt, &nrc)) < 0) return r;
  if ((r = release_old_record(s, t)) < 0) return r;
  return journal_commit_apply(s);
}

/* One slice of the cleaner on the victim s->cl_seg (writer mutex held): look at up to nrec_max records from cl_off; a live one is moved, as long as *quota lasts (bytes).
 * 1 = the victim is done (scanned to its end, or nothing live is left), 0 = more to do, < 0 = a move failed (no room, I/O). */
static int cl_step_locked(store_t *s, uint64_t *quota, unsigned nrec_max, store_compact_report_t *rep) {
  const uint32_t S = s->cl_seg;
  seg_t *g = seg_get(s, S);
  if (!g) return 1;
#ifdef KARIDNS_UNIT_TEST
  if (store_test_cleaner_step) store_test_cleaner_step(s, S);
#endif
  const bool was = s->in_cleaner;
  s->in_cleaner = true;
  int ret = 0;
  unsigned looked = 0;
  uint64_t used = VG(s, V_SEG(S, 0)), hwm = VG(s, V_HWM);
  if (hwm > st_zt_cap(s)) hwm = st_zt_cap(s);
  while (looked < nrec_max) {
    if (VG(s, V_SEG(S, 1)) == 0) { ret = 1; break; }
    uint64_t off = s->cl_off;
    if (off + ST_RHDR > used) { ret = 1; break; }
    if (*quota == 0) break;
    looked++;
    const uint8_t *hp = cl_window(s, g, off, ST_RHDR, used);
    if (!hp) { s->cl_off = off + 64; continue; }
    rhdr_t h;
    memcpy(&h, hp, sizeof(h));
    if (h.magic == 0 && s->align_rs) {                    /* (the gap before a record boundary, seg_align_pos(): not a record, and not one of the records this slice may look at) */
      looked--;
      s->cl_off = off + 64;
      continue;
    }
    if (h.magic != ST_MAGIC_REC || h.reclen < ST_RHDR || (h.reclen & 63u) || off + h.reclen > used) { s->cl_off = off + 64; continue; }       /* (not a record: look at the next 64 bytes) */
    const uint64_t rlen = h.reclen, loc = loc_of(S, off);
    r64_t rt, rc;
    zt_t t;
    memset(&t, 0, sizeof(t));
    memset(&rt, 0, sizeof(rt));
    memset(&rc, 0, sizeof(rc));
    bool live = false;
    if ((uint64_t)h.zid < hwm && zrec_read_locked(s, h.zid, &rt, &rc) == 0) {
      zt_unpack(&rt, &t);
      live = t.state == STORE_STATE_STORED && t.loc == loc;
    }
    if (!live) { s->cl_off = off + rlen; continue; }
    const uint8_t *rec = rlen == st_reclen(t.klen, t.img_len) ? cl_window(s, g, off, rlen, used) : NULL;
    bool good = rec != NULL;
    if (good) {                                           /* the record is checked before it is copied: damage is not carried to a new place */
      rhdr_t hh;
      memcpy(&hh, rec, sizeof(hh));
      uint64_t want = hh.checksum;
      hh.checksum = 0;
      size_t np = st_pad16(t.klen);
      uint64_t sum = st_sum64(&hh, sizeof(hh), 0);
      sum = st_sum64(rec + ST_RHDR, np, sum);
      sum = st_sum64(rec + ST_RHDR + np, t.img_len, sum);
      good = hh.zid == h.zid && hh.view == t.view && hh.klen == t.klen && hh.img_len == t.img_len && hh.kind == 0 && sum == want;
    }
    if (!good) {
      int mk = zone_make_known_locked(s, h.zid, loc);
      if (mk == 0) bad_note(s, h.zid);
      atomic_fetch_add_explicit(&s->c_bad, 1, memory_order_relaxed);
      if (rep) rep->bad_records++;
      if (mk < 0) { ret = mk; break; }
      s->cl_off = off + rlen;
      continue;
    }
    int r = cl_move_locked(s, h.zid, &t, &rc, rec, rlen);
    if (r < 0) { ret = r; break; }
    atomic_fetch_add_explicit(&s->c_moved_recs, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->c_moved_bytes, rlen, memory_order_relaxed);
    if (rep) { rep->moved_records++; rep->moved_bytes += rlen; }
    *quota = *quota > rlen ? *quota - rlen : 0;
    s->cl_off = off + rlen;
  }
  s->in_cleaner = was;
  return ret;
}

/* the victim is over: it is empty (it goes with the next retire pass), or it could not be emptied (a record that cannot be read: not again for ten minutes) */
static void cl_finish_victim(store_t *s, bool failed, store_compact_report_t *rep) {
  const uint32_t S = s->cl_seg;
  if (S) {
    if (VG(s, V_SEG(S, 1)) == 0) { if (rep) rep->segs_emptied++; }
    else {
      atomic_fetch_add_explicit(&s->c_incomplete, 1, memory_order_relaxed);
      s->seg_skip_until[S] = st_now_ms() + (failed ? 60000u : 600000u);
    }
  }
  cl_reset_victim(s);
}

/* Remove the segments that have no live record: the file goes when (a) a checkpoint after the last journal record that touched the segment is on disk, (b) the readers that
 * could still hold an old location are gone, (c) no image of it is held.  wait: give the grace period a moment (the emergency path and store_compact(finish)). */
/* the file of a removed segment goes (its record is in the kernel: N8) */
static void seg_unlink_locked(store_t *s, uint32_t n) {
  seg_t *g = atomic_exchange_explicit(&s->segs[n], NULL, memory_order_acq_rel);
  if (g) retire_add_seg(s, g);
  char name[32];
  snprintf(name, sizeof(name), "seg.%u", n);
  (void)unlinkat(s->dirfd, name, 0);
  s->dir_dirty = true;
  CRASH_POINT();
  s->seg_draining[n] = 0;
  s->seg_skip_until[n] = 0;
  s->seg_free_lsn[n] = s->lsn;                          /* (the record that zeroed the counters is at or below it: the number is made ahead only once that is durable, seg_pre_make()) */
  atomic_fetch_add_explicit(&s->c_segs_freed, 1, memory_order_relaxed);
}
static void seg_retire_locked(store_t *s, bool wait) {
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS), cur = (uint32_t)VG(s, V_CUR_SEG), draining = 0, pinned = 0;
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  for (uint32_t n = 1; n <= nsegs; n++) {
    uint64_t used = VG(s, V_SEG(n, 0)), live = VG(s, V_SEG(n, 1));
    if (used == 0 && s->seg_draining[n] == 3) {           /* (its record is applied, its file waits for the journal: N8) */
      if (jw_drain_locked(s) == 0) { seg_unlink_locked(s, n); draining--; }
      draining++;
      continue;
    }
    if (used == 0 || n == cur || live != 0 || n == s->cl_seg) { s->seg_draining[n] = 0; continue; }
    if (!s->seg_draining[n]) {
      s->seg_draining[n] = 1;
      s->seg_drain_lsn[n] = s->lsn;
      s->seg_drain_epoch[n] = rcu_writer_advance_epoch();
    }
    draining++;
    if (s->ckpt_lsn < s->seg_drain_lsn[n]) continue;
    if (!rcu_writer_is_safe(s->seg_drain_epoch[n]) && !(wait && rcu_writer_try_wait(s->seg_drain_epoch[n], 100))) continue;
    if (seg_refs(s, n) > 0) {
      pinned++;
      if (s->seg_draining[n] == 1) { s->seg_draining[n] = 2; atomic_fetch_add_explicit(&s->c_pinned, 1, memory_order_relaxed); }       /* (counted once for a segment) */
      continue;
    }
    jb_reset(&s->jb);
    if (jb_vset(&s->jb, V_SEG(n, 0), 0) < 0 || jb_vset(&s->jb, V_SEG(n, 1), 0) < 0) continue;
    CRASH_POINT();
    const bool was_cl = s->in_cleaner;
    s->in_cleaner = true;                               /* (the record frees a whole segment file: not refused by the journal's floor on a full disk, as the cleaner's records are not) */
    const int jr = journal_commit_apply(s);
    s->in_cleaner = was_cl;
    if (jr < 0) continue;
    CRASH_POINT();
    /* N8: the record that frees the number is in the kernel before the file goes (the number is free in memory at once: a new seg.N could be made before a later unlink).
     * Inside the mutex, once per removed segment; when the journal cannot be written the file stays, marked (3): a later pass unlinks it once the record is written, and a
     * segment made again with that number (seg_create()) clears the mark first. */
    if (jw_drain_locked(s) < 0) { s->seg_draining[n] = 3; continue; }
    seg_unlink_locked(s, n);
    draining--;
  }
  atomic_store_explicit(&s->c_draining, draining, memory_order_relaxed);
  atomic_store_explicit(&s->c_pinned_now, pinned, memory_order_relaxed);
}

/* ---- the nx pass ---- */

typedef struct { uint64_t off; uint32_t z, klen; } nxent_t;
static int nxent_cmp(const void *a, const void *b) {
  const nxent_t *x = a, *y = b;
  return x->off < y->off ? -1 : x->off > y->off ? 1 : 0;
}

/* Give back the space of the long names of deleted zones: the names that are in use are moved down, in the order of their offsets, and nx ends after the last one.  Under the
 * writer mutex for the whole pass (a put during the pass would append behind the part that is being moved).  Only when the dead part is more than half of nx and at least
 * opts.nx_reclaim_min bytes (force: whenever there is any).  *reclaimed: bytes given back. */
static int nx_reclaim_locked(store_t *s, bool force, uint64_t *reclaimed) {
  if (reclaimed) *reclaimed = 0;
  uint64_t used = VG(s, V_NX_USED), dead = VG(s, V_NX_DEAD);
  uint64_t minb = s->o.nx_reclaim_min ? s->o.nx_reclaim_min : (4ull << 20);
  if (dead == 0 || (!force && (dead < minb || dead * 2 < used))) return 0;
  uint64_t hwm = VG(s, V_HWM);
  if (hwm > st_zt_cap(s)) hwm = st_zt_cap(s);
  nxent_t *e = NULL;
  size_t n = 0, cap = 0;
  int r = 0;
  for (uint64_t z = 0; z < hwm && r == 0; z++) {
    r64_t rt, rc;
    if (zt_state_fast(s, (uint32_t)z) == STORE_STATE_FREE) continue;
    if (zrec_read_locked(s, (uint32_t)z, &rt, &rc) < 0) continue;            /* (a damaged cell is invisible; its bytes are dead for this purpose, the repair drops it) */
    zt_t t;
    zt_unpack(&rt, &t);
    if (t.state == STORE_STATE_FREE || t.klen <= ST_NAME_INL) continue;
    uint64_t off;
    memcpy(&off, t.name, 8);
    if (off > used || (uint64_t)t.klen > used - off) { r = -EBADMSG; break; }
    if (n == cap) {
      size_t nc = cap ? cap * 2 : 1024;
      nxent_t *ne = realloc(e, nc * sizeof(*e));
      if (!ne) { r = -ENOMEM; break; }
      e = ne;
      cap = nc;
    }
    e[n].off = off;
    e[n].z = (uint32_t)z;
    e[n].klen = t.klen;
    n++;
  }
  if (r == 0 && n > 1) qsort(e, n, sizeof(*e), nxent_cmp);
  for (size_t i = 1; r == 0 && i < n; i++)
    if (e[i].off < e[i - 1].off + e[i - 1].klen) r = -EBADMSG;               /* two zones claim the same bytes: a damaged table; the repair is the way, not this pass */
  uint64_t wp = 0;
  size_t batch = 0;
  for (size_t i = 0; r == 0 && i < n; i++) {
    if (e[i].off != wp) {
      r64_t rt, rc;
      if (zrec_read_locked(s, e[i].z, &rt, &rc) < 0) { r = -EBADMSG; break; }
      zt_t t;
      zt_unpack(&rt, &t);
      if (batch == 0) jb_reset(&s->jb);
      uint8_t *p = jb_op(&s->jb, OP_NXMOVE, 16 + 128 + e[i].klen);
      if (!p) { r = -ENOMEM; break; }
      zt_t nt = t;
      memcpy(nt.name, &wp, 8);
      r64_t nrt;
      zt_pack(&nt, &nrt);
      zrec_seal(&nrt, &rc);
      uint32_t z = e[i].z, kl = e[i].klen;
      memcpy(p, &z, 4);
      memcpy(p + 4, &kl, 4);
      memcpy(p + 8, &wp, 8);
      memcpy(p + 16, &nrt, 64);
      memcpy(p + 80, &rc, 64);
      nx_read(s, e[i].off, p + 144, kl);
      batch++;
    }
    wp += e[i].klen;
    if (batch >= 256 || (batch && i + 1 == n)) {
      r = journal_commit_apply(s);
      batch = 0;
      if (r == 0 && s->jbytes >= jmax(s) && ck_try_locked(s)) {    /* (the pass keeps the mutex: a checkpoint that runs elsewhere is not waited for, the journal grows meanwhile) */
        r = ck_full_locked(s, false);
        bg_release(s, true, true);
      }
    }
  }
  free(e);
  if (r < 0) return r;
  jb_reset(&s->jb);
  if ((r = jb_vset(&s->jb, V_NX_USED, wp)) < 0 || (r = jb_vset(&s->jb, V_NX_DEAD, 0)) < 0) return r;
  if ((r = journal_commit_apply(s)) < 0) return r;
  atomic_fetch_add_explicit(&s->c_nx_runs, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->c_nx_bytes, used - wp, memory_order_relaxed);
  if (reclaimed) *reclaimed = used - wp;
  return 0;
}

/* ---- no room: the cleaner now, then the KNOWN fallback ---- */

/* Free space now (writer mutex held): clean segments until some are empty, make that durable and remove them.  Bounded in time and bytes. */
static uint64_t emergency_free_locked(store_t *s) {
  uint64_t t0 = st_now_ms(), budget = 256ull << 20;
  const uint64_t freed0 = atomic_load_explicit(&s->c_segs_freed, memory_order_relaxed);
  store_compact_report_t rep;
  memset(&rep, 0, sizeof(rep));
  unsigned victims = 0;
  const bool was = s->in_cleaner;
  s->in_cleaner = true;
  while (budget > 0 && st_now_ms() - t0 < 3000 && victims < 16) {
    if (!s->cl_seg) {
      uint32_t v = cl_pick(s, NULL, NULL, NULL, NULL, true);
      if (!v && cl_rotate_open_locked(s)) v = cl_pick(s, NULL, NULL, NULL, NULL, true);
      if (!v) break;
      s->cl_seg = v;
      s->cl_off = ST_SEGHDR;
      s->cl_buf_len = 0;
      victims++;
      atomic_fetch_add_explicit(&s->c_runs, 1, memory_order_relaxed);
    }
    int r = cl_step_locked(s, &budget, 4096, &rep);
    if (r == 1) cl_finish_victim(s, false, &rep);
    else if (r < 0) { cl_finish_victim(s, true, &rep); break; }
  }
  (void)nx_reclaim_locked(s, false, NULL);
  s->in_cleaner = was;
  (void)ck_now_locked(s);                             /* (the mutex may be given up while another checkpoint ends: in_cleaner is the caller's again before that) */
  seg_retire_locked(s, true);
  retire_run(s, false);
  fs_probe(s);
  return atomic_load_explicit(&s->c_segs_freed, memory_order_relaxed) - freed0;
}

/* store_put with a full disk: try, clean and try again (at most once a second), then keep the zone without an image. */
static int put_stored_locked(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, const void *image, size_t ilen, unsigned pflags, uint32_t *zid) {
  int r = put_locked(s, view, name, len, meta, image, ilen, STORE_STATE_STORED, zid, NULL);
  s->prew = NULL;                                     /* (a record written ahead is for the first try only) */
  if (!is_nospc(r)) return r;
  note_error(s, r);
  uint64_t now = st_now_ms();
  if (now >= s->emerg_block_until && !st_bulk_busy(s)) {   /* (when the last cleaning found nothing to free, it is not repeated for every zone: once a second; none during a bulk fill: no cleaner) */
    if (emergency_free_locked(s) == 0) s->emerg_block_until = now + 1000;
    r = put_locked(s, view, name, len, meta, image, ilen, STORE_STATE_STORED, zid, NULL);
    if (!is_nospc(r)) return r;
  }
  /* 0.7 (STORE_PUT_NO_DEGRADE, a secondary's copy): no KNOWN fallback.  A STORED put_locked() that failed wrote no journal record (its ops are only in the builder, which the next
   * call resets; release_old_record() is an op of the record that was not written), so the zone's old record and its image are as they were; the store is not marked degraded */
  if (s->o.no_degrade || (pflags & STORE_PUT_NO_DEGRADE)) return r;
  int r2 = put_locked(s, view, name, len, meta, NULL, 0, STORE_STATE_KNOWN, zid, NULL);
  if (r2 < 0) return r2;
  atomic_fetch_add_explicit(&s->n_degraded, 1, memory_order_relaxed);
  degraded_begin(s);
  return 0;
}

/* (a name with a zero byte is refused: the rebuild takes such a name for a page of nx that did not reach the disk, st_name_text_ok(); counted, store.writes.names_refused) */
static int check_name_args(store_t *s, uint16_t view, const char *name, size_t nlen, const store_meta_t *m) {
  if (nlen > STORE_NAME_MAX || view >= atomic_load_explicit(&s->nviews, memory_order_relaxed)) return -EINVAL;
  if (m->source >= ST_MAXSRC) return -EINVAL;
  if (memchr(name, 0, nlen)) {
    atomic_fetch_add_explicit(&s->n_names_refused, 1, memory_order_relaxed);
    return -EINVAL;
  }
  return 0;
}

int store_put(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, const void *image,
              size_t image_len, uint32_t *zid) {
  return store_put_ex(s, view, name, len, meta, image, image_len, 0, zid);
}
int store_put_ex(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, const void *image,
                 size_t image_len, unsigned flags, uint32_t *zid) {
  if (!s || !name || !meta || !image || image_len == 0 || image_len > 0x7fffffffu) return -EINVAL;
  ST_FAULT("put", STORE_NONE);
  int r = check_name_args(s, view, name, len, meta);
  if (r < 0) return r;
  pthread_mutex_lock(&s->ap_mu);                     /* (the writers of images, one at a time: the place st_prewrite() takes is the end of the open segment) */
  t_ap_held = true;
  prew_t pw;
  const bool pre = st_prewrite(s, view, name, len, meta, image, image_len, &pw);
  uint64_t my = 0, t = 0;
  bool locked = false;
  if ((r = wr_lock(s)) < 0) goto out;
  s->prew = pre ? &pw : NULL;
  r = put_stored_locked(s, view, name, len, meta, image, image_len, flags, zid);
  s->prew = NULL;
  if (r < 0) { if (!is_nospc(r)) note_error(s, r); } else { note_ok(s); r = post_write(s); }       /* (a full disk was counted where it was found) */
  my = s->lsn;
  t = s->jr_head;
  locked = true;
  wr_unlock_raw(s);
out:
  if (pre) atomic_fetch_sub_explicit(&s->io_hold, 1, memory_order_acq_rel);
  t_ap_held = false;
  pthread_mutex_unlock(&s->ap_mu);
  if (locked) r = wr_finish(s, wr_ack(s, r, t), my);   /* (rule A, after ap_mu: the other writers of images do not wait for this call's journal write) */
  return r;
}
int store_set_known(store_t *s, uint16_t view, const char *name, size_t len, const store_meta_t *meta, uint32_t *zid) {
  if (!s || !name || !meta) return -EINVAL;
  ST_FAULT("set_known", STORE_NONE);
  int r = check_name_args(s, view, name, len, meta);
  if (r < 0) return r;
  if ((r = wr_lock(s)) < 0) return r;
  r = put_locked(s, view, name, len, meta, NULL, 0, STORE_STATE_KNOWN, zid, NULL);
  if (r < 0) note_error(s, r); else { note_ok(s); r = post_write(s); }
  return wr_done(s, r);
}

/* ---- group commit: store_set_known_n() ---- */

typedef struct {
  size_t len;
  uint32_t nops;
  unsigned nv, npl;
  struct { uint32_t fid; uint64_t val; } vs[JB_MAXV];
} jb_mark_t;
static void jb_mark(const jb_t *j, jb_mark_t *k) {
  k->len = j->len;
  k->nops = j->nops;
  k->nv = j->nv;
  k->npl = j->npl;
  memcpy(k->vs, j->vs, (size_t)j->nv * sizeof(k->vs[0]));
}
static void jb_rollback(jb_t *j, const jb_mark_t *k) {          /* (the entry that failed leaves nothing in the record) */
  j->len = k->len;
  j->nops = k->nops;
  j->nv = k->nv;
  j->npl = k->npl;
  memcpy(j->vs, k->vs, (size_t)k->nv * sizeof(k->vs[0]));
}

/* Write the pending entries of the group as ONE journal record and apply it: the record of a group is the record of a single entry with more ops (the format is the same: every op is a
 * full cell value, so a replay applies it as it applies any other), and one CRC covers all of it, so a torn record drops the whole group.  The commit policy is asked once for the record. */
static void kn_flush(store_t *s, kn_chunk_t *ck, const size_t *pidx, const uint32_t *pz, int *res, uint32_t *zid) {
  if (ck->n == 0) return;
  int r = journal_commit_apply(s);
  if (r == 0) {
    s->n_puts += ck->nnew;
    s->n_replaces += ck->n - ck->nnew;
    s->n_group_records++;
    s->n_group_entries += ck->n;
    note_ok(s);
    r = post_write(s);
  } else {
    note_error(s, r);
  }
  for (unsigned i = 0; i < ck->n; i++) {
    res[pidx[i]] = r;
    if (zid) zid[pidx[i]] = r < 0 ? STORE_NONE : pz[i];
  }
  memset(ck, 0, sizeof(*ck));
}

int store_set_known_n(store_t *s, uint16_t view, const store_known_t *in, size_t n, int *res, uint32_t *zid) {
  if (!s || !in || !res || n == 0) return -EINVAL;
  kn_chunk_t ck;
  size_t pidx[KN_MAX];
  uint32_t pz[KN_MAX];
  memset(&ck, 0, sizeof(ck));
  const int lr = wr_lock(s);
  if (lr < 0) {
    for (size_t i = 0; i < n; i++) { res[i] = lr; if (zid) zid[i] = STORE_NONE; }
    return 0;
  }
  for (size_t i = 0; i < n; i++) {
    res[i] = 0;
    if (zid) zid[i] = STORE_NONE;
    ST_FAULT_RES("set_known", STORE_NONE, res[i]);
    if (res[i] != 0) continue;
    if (!in[i].name || !in[i].meta) {
      res[i] = -EINVAL;
      continue;
    }
    int r = check_name_args(s, view, in[i].name, in[i].len, in[i].meta);
    if (r < 0) {
      res[i] = r;
      continue;
    }
    for (;;) {
      jb_mark_t mk;
      const bool held = ck.n > 0;
      if (held) jb_mark(&s->jb, &mk);
      uint32_t z = STORE_NONE;
      r = put_locked(s, view, in[i].name, in[i].len, in[i].meta, NULL, 0, STORE_STATE_KNOWN, &z, &ck);
      if (r == KN_FLUSH_FIRST || (r == -ENOMEM && held)) {        /* the entry cannot join the group (or the record is full: the builder's counters): write it, plan the entry again */
        if (held) jb_rollback(&s->jb, &mk);
        kn_flush(s, &ck, pidx, pz, res, zid);
        continue;
      }
      if (r < 0) {                                                  /* this entry fails; the group before it is not touched */
        if (held) jb_rollback(&s->jb, &mk);
        note_error(s, r);
        res[i] = r;
        break;
      }
      pidx[ck.n - 1] = i;
      pz[ck.n - 1] = z;
      if (ck.n == KN_MAX) kn_flush(s, &ck, pidx, pz, res, zid);
      break;
    }
  }
  kn_flush(s, &ck, pidx, pz, res, zid);
  const int c = wr_done(s, 0);
  if (c < 0)                                                        /* (STORE_SYNC_EVERY: the commit of the entries failed) */
    for (size_t i = 0; i < n; i++) if (res[i] == 0) res[i] = c;
  return 0;
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
    if ((r = jb_pl(j, 0, false, h, z)) < 0) return r;
  }
  if (c.source_id != 0) {
    ixgen_t *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
    uint64_t oh = st_hash_src(s, c.source, t.view, c.source_id);
    uint64_t pos = slot_find_zid(sx, oh, z);
    if (pos != UINT64_MAX) {
      if ((r = jb_slot(j, OP_SX, pos, st_slotval(st_tag(oh), STORE_NONE))) < 0) return r;
      if ((r = jb_vadd(s, j, V_SX_LIVE, -1)) < 0) return r;
    }
    if ((r = jb_pl(j, 1, false, oh, z)) < 0) return r;
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
    (void)store_err_clear(s, z);                      /* (the id is reused: its text must not show under the next zone that gets it; err_mu is innermost) */
  }
  return r;
}

int store_delete(store_t *s, uint32_t zid) {
  if (!s) return -EINVAL;
  ST_FAULT("delete", zid);
  int r = wr_lock(s);
  if (r < 0) return r;
  r = delete_locked(s, zid);
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  return wr_done(s, r);
}
int store_delete_name(store_t *s, uint16_t view, const char *name, size_t len) {
  if (!s || !name || len > STORE_NAME_MAX) return -EINVAL;
  uint8_t fn[256];
  for (size_t i = 0; i < len; i++) fn[i] = st_lc((uint8_t)name[i]);
  int r = wr_lock(s);
  if (r < 0) return r;
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
  uint32_t z = ix_lookup(s, ix, view, fn, len, st_hash_name(s, view, fn, len));
  r = z == STORE_NONE ? -ENOENT : delete_locked(s, z);
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  return wr_done(s, r);
}

int store_set_flags(store_t *s, uint32_t zid, uint16_t set, uint16_t clear) {
  if (!s) return -EINVAL;
  ST_FAULT("set_flags", zid);
  int r = wr_lock(s);
  if (r < 0) return r;
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
      int64_t dn = ((nf & STORE_F_NONSTORE) ? 1 : 0) - ((t.flags & STORE_F_NONSTORE) ? 1 : 0);
      t.flags = nf;
      zt_pack(&t, &rt);
      zrec_seal(&rt, &rc);
      if ((r = jb_zrec(j, zid, &rt, &rc)) == 0 && dr != 0) {
        r = jb_vadd(s, j, V_REJECTED, dr);
        if (r == 0) r = jb_vadd(s, j, V_VIEW(t.view, 2), dr);
      }
      if (r == 0 && dn != 0) r = jb_vadd(s, j, V_NONSTORE, dn);
      if (r == 0) r = journal_commit_apply(s);
    }
  }
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  return wr_done(s, r);
}

/* 0.7 WP7b: the version stamp (zc) and the flags (zt) of a zone, in one journal record: the database has another version than the one the record holds, or the same one again */
int store_set_stamp(store_t *s, uint32_t zid, uint64_t gen, uint64_t time, uint16_t set, uint16_t clear) {
  if (!s) return -EINVAL;
  ST_FAULT("set_stamp", zid);
  int r = wr_lock(s);
  if (r < 0) return r;
  r64_t rt, rc;
  if ((uint64_t)zid >= st_zt_cap(s) || zt_state_fast(s, zid) == STORE_STATE_FREE) r = -ENOENT;
  else if ((r = zrec_read_locked(s, zid, &rt, &rc)) == 0) {
    zt_t t;
    zc_t c;
    zt_unpack(&rt, &t);
    zc_unpack(&rc, &c);
    uint16_t nf = (uint16_t)((t.flags | set) & ~clear);
    if (nf != t.flags || c.stamp_gen != gen || c.stamp_time != time) {
      jb_t *j = &s->jb;
      jb_reset(j);
      int64_t dr = ((nf & STORE_F_REJECTED_NEW) ? 1 : 0) - ((t.flags & STORE_F_REJECTED_NEW) ? 1 : 0);
      int64_t dn = ((nf & STORE_F_NONSTORE) ? 1 : 0) - ((t.flags & STORE_F_NONSTORE) ? 1 : 0);
      t.flags = nf;
      c.stamp_gen = gen;
      c.stamp_time = time;
      zt_pack(&t, &rt);
      zc_pack(&c, &rc);
      zrec_seal(&rt, &rc);
      if ((r = jb_zrec(j, zid, &rt, &rc)) == 0 && dr != 0) {
        r = jb_vadd(s, j, V_REJECTED, dr);
        if (r == 0) r = jb_vadd(s, j, V_VIEW(t.view, 2), dr);
      }
      if (r == 0 && dn != 0) r = jb_vadd(s, j, V_NONSTORE, dn);
      if (r == 0) r = journal_commit_apply(s);
    }
  }
  if (r < 0 && r != -ENOENT) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  return wr_done(s, r);
}

/* 0.7 (a secondary's copy, planing_0.7.x_secondary_store.md 2.4): the digest, the settings id and the flags of the zone (view, name), only when its serial is expect_serial.  The zone is looked up
 * by name under the writer mutex, so a zone id that a delete freed and a put gave to another zone meanwhile is never written; the image, the stamp and the state stay.  One journal record. */
int store_set_digest(store_t *s, uint16_t view, const char *name, size_t len, uint32_t expect_serial, uint32_t settings, const uint8_t digest[STORE_DIGEST_LEN], uint16_t set,
                     uint16_t clear) {
  if (!s || !name || !digest || len > STORE_NAME_MAX || view >= atomic_load_explicit(&s->nviews, memory_order_relaxed)) return -EINVAL;
  ST_FAULT("set_digest", STORE_NONE);
  uint8_t fn[256];
  for (size_t i = 0; i < len; i++) fn[i] = st_lc((uint8_t)name[i]);
  int r = wr_lock(s);
  if (r < 0) return r;
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed);
  const uint32_t zid = ix_lookup(s, ix, view, fn, len, st_hash_name(s, view, fn, len));
  r64_t rt, rc;
  if (zid == STORE_NONE || (uint64_t)zid >= st_zt_cap(s) || zt_state_fast(s, zid) == STORE_STATE_FREE) r = -ENOENT;
  else if ((r = zrec_read_locked(s, zid, &rt, &rc)) == 0) {
    zt_t t;
    zc_t c;
    zt_unpack(&rt, &t);
    zc_unpack(&rc, &c);
    const uint16_t nf = (uint16_t)((t.flags | set) & ~clear);
    if (t.state == STORE_STATE_FREE) r = -ENOENT;
    else if (t.serial != expect_serial) r = -ESTALE;
    else if (nf != t.flags || t.settings != settings || memcmp(c.digest, digest, STORE_DIGEST_LEN) != 0) {
      jb_t *j = &s->jb;
      jb_reset(j);
      int64_t dr = ((nf & STORE_F_REJECTED_NEW) ? 1 : 0) - ((t.flags & STORE_F_REJECTED_NEW) ? 1 : 0);
      int64_t dn = ((nf & STORE_F_NONSTORE) ? 1 : 0) - ((t.flags & STORE_F_NONSTORE) ? 1 : 0);
      t.flags = nf;
      t.settings = settings;
      memcpy(c.digest, digest, STORE_DIGEST_LEN);
      zt_pack(&t, &rt);
      zc_pack(&c, &rc);
      zrec_seal(&rt, &rc);
      if ((r = jb_zrec(j, zid, &rt, &rc)) == 0 && dr != 0) {
        r = jb_vadd(s, j, V_REJECTED, dr);
        if (r == 0) r = jb_vadd(s, j, V_VIEW(t.view, 2), dr);
      }
      if (r == 0 && dn != 0) r = jb_vadd(s, j, V_NONSTORE, dn);
      if (r == 0) r = journal_commit_apply(s);
    }
  }
  if (r < 0 && r != -ENOENT && r != -ESTALE) note_error(s, r); else if (r == 0) { note_ok(s); r = post_write(s); }
  return wr_done(s, r);
}

int store_view_add(store_t *s, const char *name) {
  if (!s || !name || !*name || strlen(name) > STORE_VIEW_NAME_MAX) return -EINVAL;
  int r = wr_lock(s);
  if (r < 0) return r;
  uint32_t n = atomic_load_explicit(&s->nviews, memory_order_relaxed);
  for (uint32_t i = 0; i < n; i++)
    if (strcmp(s->views[i], name) == 0) return wr_done(s, (int)i);           /* (rule A: the view it found may be another call's, applied and not written yet) */
  if (n >= ST_MAXV) { wr_unlock_raw(s); return -ENOSPC; }
  jb_reset(&s->jb);
  uint8_t *p = jb_op(&s->jb, OP_VIEW, 8 + STORE_VIEW_NAME_MAX + 1);
  if (!p) { wr_unlock_raw(s); return -ENOMEM; }
  memcpy(p, &n, 4);
  memcpy(p + 8, name, strlen(name));
  r = journal_commit_apply(s);
  if (r < 0) note_error(s, r); else { note_ok(s); r = post_write(s); if (r == 0) r = (int)n; }
  return wr_done(s, r);
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
  ST_FAULT("set_cursor", STORE_NONE);
  int r = wr_lock(s);
  if (r < 0) return r;
  jb_reset(&s->jb);
  uint8_t *p = jb_op(&s->jb, OP_SRC, 24 + STORE_IDENT_MAX);
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
  return wr_done(s, r);
}
int store_get_cursor(store_t *s, uint16_t source, bool *valid, uint64_t *cursor, void *ident, size_t *ident_len) {
  if (!s || source >= ST_MAXSRC) return -EINVAL;
  wr_lock_raw(s);
  const srcent_t *e = &s->src[source];
  if (valid) *valid = e->valid != 0;
  if (cursor) *cursor = e->cursor;
  if (ident) memcpy(ident, e->ident, e->identlen);
  if (ident_len) *ident_len = e->identlen;
  wr_unlock_raw(s);
  return 0;
}

/* The first fill announces its size: the indexes and the tables are made big enough once.  The bigger indexes are built outside the writer mutex, on this thread (a build that runs is
 * waited for first), and before the blocks of zt and zc are allocated: the allocation of gigabytes on UFS stalls every file that another writer makes meanwhile (an index growth inside
 * the mutex of the first zones of a fill that the queries bring, 740 ms at 10M zones), so the index is there before it starts.  A build that is dropped meanwhile (another writer's growth
 * inside the mutex, regrow_locked(): the index of a store that is still small filled up to one half; a repair) is made again with the sizes the store has by then, up to RESERVE_TRIES
 * times (the zones are few then, the build short); the last try makes the growth inside the mutex, which nothing can drop.  A close ends the reserve without a growth.  It is never a
 * dropped build that counts as a reserve made (round 9: it returned 0 and the first fill of 10M zones went through 17 growths). */
#define RESERVE_TRIES 8
static void tables_ahead(store_t *s, uint64_t zones);
int store_reserve(store_t *s, uint64_t zones) {
  if (!s) return -EINVAL;
  int r = 0;
  for (int attempt = 0; attempt < RESERVE_TRIES; attempt++) {
    for (int wait = 0; wait < 100000 && atomic_load_explicit(&s->rg_live, memory_order_acquire); wait++) usleep(1000);
    r = wr_lock(s);
    if (r < 0) return r;
    bool built = false, again = false;
    ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
    uint64_t want = zones * 8 / 3 + 16;                 /* (the announced zones stay below the 3/8 at which a growth begins) */
    uint64_t nix = want > ix->nslots ? want : 0, nsx = want > sx->nslots ? want : 0;
    if (nix || nsx) {
      if (attempt < RESERVE_TRIES - 1 && rg_start_locked(s, nix, nsx, false)) {
        built = true;
        atomic_fetch_add_explicit(&s->rg_live, 1, memory_order_release);              /* (a build on this thread counts like one on its own: a second reserve and a close wait for it) */
      }
      else if (attempt < RESERVE_TRIES - 1 && s->rg_active) again = true;            /* (a writer's build began meanwhile: it is waited for, and the sizes it made looked at) */
      else r = regrow_locked(s, nix, nsx);                                            /* (the last try, or the store closes) */
    }
    if (r < 0) note_error(s, r);
    const int w = wr_unlock_w(s);
    if (r == 0) r = w;
    if (built) {
      const int br = rg_build(s);
      atomic_fetch_sub_explicit(&s->rg_live, 1, memory_order_release);
      if (br == -ECANCELED) again = r == 0 && !atomic_load_explicit(&s->rg_stop, memory_order_relaxed);
      else r = br;
    }
    if (r != 0 || !again) break;
  }
  if (r < 0) return r;
  tables_ahead(s, zones + 1);                          /* (the blocks of zt and zc outside the mutex: inside it the growth is a mapping) */
  r = wr_lock(s);
  if (r < 0) return r;
  r = ensure_zt_cap(s, zones + 1);
  if (r < 0) note_error(s, r);
  const int w = wr_unlock_w(s);
  return r == 0 ? w : r;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* 0.7 WP9: space at the checkpoint, the scrub, what the tick does                                                      */
/* ------------------------------------------------------------------------------------------------------------------ */

/* At every checkpoint (writer mutex held): the free space is read, the size of the store and its growth of the last hour are noted, and a WARNING says when the file system
 * is getting full (design 3.5: "P-F warns before it happens"); when a full disk made the store degraded and room is back, it ends. */
static void space_checkpoint(store_t *s) {
  fs_probe(s);
  uint32_t nsegs = (uint32_t)VG(s, V_NSEGS);
  uint64_t seg = 0;
  if (nsegs > ST_MAXSEG) nsegs = ST_MAXSEG;
  for (uint32_t n = 1; n <= nsegs; n++) {
    uint64_t used = VG(s, V_SEG(n, 0));
    if (used > ST_SEGHDR) seg += used;
  }
  ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_relaxed), *sx = atomic_load_explicit(&s->sx, memory_order_relaxed);
  uint64_t bytes = seg + atomic_load_explicit(&s->zt.mapped, memory_order_relaxed) + atomic_load_explicit(&s->zc.mapped, memory_order_relaxed) +
                   atomic_load_explicit(&s->nx.mapped, memory_order_relaxed) + (ix ? ix->maplen : 0) + (sx ? sx->maplen : 0) + s->jbytes + 2 * (uint64_t)ST_SB_SIZE;
  atomic_store_explicit(&s->store_bytes, bytes, memory_order_relaxed);
  uint64_t now = st_now_ms();
  if (s->gcount == 0 || now - s->last_gsample_ms >= 60000) {
    unsigned at;
    if (s->gcount < ST_GRING) { at = (s->ghead + s->gcount) % ST_GRING; s->gcount++; }
    else { at = s->ghead; s->ghead = (s->ghead + 1) % ST_GRING; }
    s->gring[at].ms = now;
    s->gring[at].bytes = bytes;
    s->last_gsample_ms = now;
  }
  /* the growth over the last hour (at least five minutes of samples) */
  uint64_t rate = 0;
  for (unsigned i = 0; i < s->gcount; i++) {
    const unsigned k = (s->ghead + i) % ST_GRING;
    if (now - s->gring[k].ms <= 3600000u) {
      if (now - s->gring[k].ms >= 300000u && bytes > s->gring[k].bytes) rate = (bytes - s->gring[k].bytes) * 3600000u / (now - s->gring[k].ms);
      break;
    }
  }
  if ((VG(s, V_HWM) > s->zt.reserve / ST_REC / 5 * 4 || VG(s, V_NX_USED) > s->nx.reserve / 5 * 4) && rl_ok(&s->last_resv_warn_ms, 600000))
    st_log(s, 4, "store: the tables are over 80 %% of the address space reserved for them: %" PRIu64 " of %" PRIu64 " zones, %" PRIu64 " of %" PRIu64 " bytes of long names; at the limit new zones are not "
                 "stored (served from the database): raise `store-max-zones` in the database block and restart", (uint64_t)VG(s, V_HWM), (uint64_t)(s->zt.reserve / ST_REC), (uint64_t)VG(s, V_NX_USED), (uint64_t)s->nx.reserve);
  const int64_t avail = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  /* A first fill is not a growth to extrapolate: the store grows as fast as the database delivers (96 GB an hour at 54 GB free, then it stops: the zones are all there).  While zones are
   * known without an image the size to come is known: the zones still to be stored at the size of those stored so far, and the warning is about that (and the hour figure is not made). */
  uint64_t known = 0, stored = 0, imgb = 0;
  const uint32_t nviews = atomic_load_explicit(&s->nviews, memory_order_acquire);
  for (uint32_t i = 0; i < nviews && i < STORE_MAX_VIEWS; i++) {
    known += VG(s, V_VIEW(i, 0));
    stored += VG(s, V_VIEW(i, 1));
    imgb += VG(s, V_VIEW(i, 3));
  }
  const bool filling = known > 0;
  const uint64_t pending = filling && stored ? known * (imgb / stored) : 0;
  uint64_t full_h = 0;
  if (rate && avail >= 0 && !filling) full_h = (uint64_t)avail / rate + 1;
  atomic_store_explicit(&s->growth_bph, rate, memory_order_relaxed);
  atomic_store_explicit(&s->full_in_h, full_h, memory_order_relaxed);
  if (s->degraded && avail >= 0 && (uint64_t)avail >= s->reserve_bytes + s->reserve_bytes / 2) degraded_end(s);   /* (a put needs the reserve and its own bytes; a quota of 100 MB with segments of 64 MB never has two reserves and a segment) */
  uint32_t lvl = s->degraded ? 2u : 0u;
  if (!s->degraded && avail >= 0) {
    uint64_t low = 2 * s->reserve_bytes > bytes / 10 ? 2 * s->reserve_bytes : bytes / 10;
    if ((uint64_t)avail < low || (full_h && full_h < 24) || pending > (uint64_t)avail) lvl = 1;
  }
  atomic_store_explicit(&s->space_level, lvl, memory_order_relaxed);
  if (lvl == 1 && rl_ok(&s->last_warn_ms, 600000)) {
    uint64_t dead = 0;
    space_dead_totals(s, &dead);
    char tf[240] = "";
    if (full_h) snprintf(tf, sizeof(tf), "; at the growth of the last hour (%" PRIu64 " bytes an hour) it is full in about %" PRIu64 " hour(s)", rate, full_h);
    else if (pending) snprintf(tf, sizeof(tf), "; %" PRIu64 " zone(s) are still to be stored: at the size of the zones stored so far they take about %" PRIu64 " bytes more", known, pending);
    st_log(s, 4, "store: the file system is getting full: %" PRIu64 " bytes are free (%" PRIu64 " of them kept for the cleaner), the store holds %" PRIu64 " bytes (%" PRIu64
                 " bytes of the segments are dead and can be won by the cleaner)%s; when it is full new zone images are not stored (zones are kept without an image and read from the database)",
           (uint64_t)avail, s->reserve_bytes, bytes, dead, tf);
  }
}

/* ---- the scrub ---- */

static void scrub_note_bad_image(store_t *s, uint32_t z, const store_zone_t *zz, const char *why) {
  int r = wr_lock(s);
  if (r < 0) return;
  r = zone_make_known_locked(s, z, zz->loc);
  if (r == 0) post_write(s);
  const int w = wr_unlock_w(s);
  if (r == 0) r = w;
  if (r == 0) {
    bad_note(s, z);
    s->sc_p_bad_img++;
    if (zz->flags & STORE_F_XFR)            /* (0.7, 2.2 W6: a secondary's copy is not read from a database: its next refresh stores it again) */
      st_log(s, 4, "store: scrub: the image of the secondary's stored copy %s (view %u) is damaged (%s); it is stored again by the next refresh", zz->name, (unsigned)zz->view, why);
    else
      st_log(s, 4, "store: scrub: the image of zone '%s' (view %u) is damaged (%s); the zone is read from the database again", zz->name, (unsigned)zz->view, why);
  }
}

/* one zone of the scrub (the thread that runs the pass) */
static void scrub_zone(store_t *s, uint32_t z) {
  store_zone_t zz;
  store_read_lock();
  int r = store_zone_get(s, z, &zz);
  if (r == -ENOENT) { store_read_unlock(); return; }
  s->sc_p_zones++;
  if (r < 0) {
    s->sc_p_bad_cell++;
    s->sc_need_repair = true;
    store_read_unlock();
    return;
  }
  if (store_find(s, zz.view, zz.name, zz.klen) != z || (zz.source_id != 0 && store_find_source(s, zz.source, zz.source_id, zz.view) != z)) {
    s->sc_p_bad_idx++;
    s->sc_need_repair = true;
  }
  bool bad = false;
  char why[200] = "";
  if (zz.state == STORE_STATE_STORED) {
    store_img_t im;
    r = store_image_read(s, z, &im);
    if (r == 0) {
      s->sc_p_images++;
      s->sc_p_bytes += st_reclen(zz.klen, zz.img_len);
      if (s->o.validate && s->o.validate(im.data, im.len, why, sizeof(why)) != 0) {
        bad = true;
        if (!why[0]) snprintf(why, sizeof(why), "the structure is not valid");
      }
      store_img_release(s, &im);
    } else if (r == -EBADMSG) {
      bad = true;
      snprintf(why, sizeof(why), "checksum or record header");
    } else if (r != -ENOENT) {
      s->sc_p_io++;
    }
  }
  store_read_unlock();
  if (bad) scrub_note_bad_image(s, z, &zz, why);
}

/* The end of a pass (sc_mu held): the repair when the pass found damage in the tables, the totals, the time (in the superblock at the next checkpoint). */
static void scrub_end_pass(store_t *s) {
  bool repaired = false;
  if (s->sc_need_repair) {
    int r = store_repair(s);
    repaired = r == 0;
    if (r < 0) st_log(s, 3, "store: scrub: the repair of the tables failed: %s", strerror(-r));
  }
  atomic_fetch_add_explicit(&s->sc_zones, s->sc_p_zones, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->sc_bytes, s->sc_p_bytes, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->sc_bad_img, s->sc_p_bad_img, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->sc_bad_cell, s->sc_p_bad_cell, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->sc_bad_idx, s->sc_p_bad_idx, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->sc_io, s->sc_p_io, memory_order_relaxed);
  atomic_fetch_add_explicit(&s->sc_passes, 1, memory_order_relaxed);
  atomic_store_explicit(&s->sc_last_end, (uint64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&s->sc_running_a, 0, memory_order_relaxed);
  atomic_store_explicit(&s->sc_pct, 100, memory_order_relaxed);
  atomic_store_explicit(&s->sc_last_done, (uint64_t)time(NULL), memory_order_relaxed);
  if (s->sc_p_bad_img || s->sc_p_bad_cell || s->sc_p_bad_idx || s->sc_p_io)
    st_log(s, 4, "store: scrub: %" PRIu64 " zones read: %" PRIu64 " damaged image(s) (the zones are read from the database again), %" PRIu64 " damaged table record(s), %" PRIu64
                 " index entr(ies) that do not lead to their zone%s, %" PRIu64 " read error(s)",
           s->sc_p_zones, s->sc_p_bad_img, s->sc_p_bad_cell, s->sc_p_bad_idx, repaired ? " (tables repaired)" : "", s->sc_p_io);
  else
    st_log(s, 6, "store: scrub: %" PRIu64 " zones, %" PRIu64 " images (%" PRIu64 " bytes) read, nothing wrong", s->sc_p_zones, s->sc_p_images, s->sc_p_bytes);
  s->sc_running = false;
}

static void scrub_begin_pass(store_t *s) {
  s->sc_running = true;
  s->sc_need_repair = false;
  s->sc_cursor = 0;
  s->sc_p_zones = s->sc_p_images = s->sc_p_bytes = s->sc_p_bad_img = s->sc_p_bad_cell = s->sc_p_bad_idx = s->sc_p_io = 0;
  atomic_store_explicit(&s->sc_last_start, (uint64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&s->sc_running_a, 1, memory_order_relaxed);
  atomic_store_explicit(&s->sc_pct, 0, memory_order_relaxed);
}

/* work on the running pass (sc_mu held) until `budget` bytes were read or slice_ms passed; true when the pass is over */
static bool scrub_work(store_t *s, uint64_t budget, uint64_t slice_ms) {
  uint64_t t0 = st_now_ms();
  const uint64_t b0 = s->sc_p_bytes;
  for (;;) {
    uint64_t hwm = VG(s, V_HWM);
    if (s->sc_cursor >= hwm) { scrub_end_pass(s); return true; }
    if (s->sc_p_bytes - b0 >= budget || st_now_ms() - t0 >= slice_ms) {
      atomic_store_explicit(&s->sc_pct, hwm ? (uint32_t)((uint64_t)s->sc_cursor * 100 / hwm) : 0, memory_order_relaxed);
      return false;
    }
    scrub_zone(s, s->sc_cursor++);
  }
}

void store_compact_request(store_t *s) {
  if (s) atomic_store_explicit(&s->c_forced, true, memory_order_relaxed);
}
void store_scrub_start(store_t *s) {
  if (!s) return;
  pthread_mutex_lock(&s->sc_mu);
  if (!s->sc_running) scrub_begin_pass(s);
  pthread_mutex_unlock(&s->sc_mu);
}
void store_scrub_stop(store_t *s) {
  if (!s) return;
  pthread_mutex_lock(&s->sc_mu);
  if (s->sc_running) {
    s->sc_running = false;
    atomic_store_explicit(&s->sc_running_a, 0, memory_order_relaxed);
  }
  pthread_mutex_unlock(&s->sc_mu);
}
int store_scrub_run(store_t *s, store_scrub_report_t *rep) {
  if (!s) return -EINVAL;
  if (rep) memset(rep, 0, sizeof(*rep));
  if (st_bulk_busy(s)) return -EBUSY;      /* (no scrub during a bulk fill: its repair would be a full checkpoint for every damaged cell it finds in a fill) */
  pthread_mutex_lock(&s->sc_mu);
  if (!s->sc_running) scrub_begin_pass(s);
  while (s->sc_running && !scrub_work(s, UINT64_MAX, 1000000)) {}
  if (rep) {
    rep->zones = s->sc_p_zones;
    rep->images = s->sc_p_images;
    rep->bytes = s->sc_p_bytes;
    rep->bad_images = s->sc_p_bad_img;
    rep->bad_cells = s->sc_p_bad_cell;
    rep->bad_index = s->sc_p_bad_idx;
    rep->io_errors = s->sc_p_io;
    rep->repaired = s->sc_p_bad_cell || s->sc_p_bad_idx;
  }
  pthread_mutex_unlock(&s->sc_mu);
  bad_drain(s);
  return 0;
}

/* ---- the cleaner by itself ---- */

/* Work of the cleaner for one tick or one store_compact(): victims, a bounded number of bytes moved.  Takes the writer mutex per slice of records. */
/* settle: the background cleaner of the tick (CL_SETTLE_MS); store_compact() and the operator's full speed take every segment that is dead enough */
static int cleaner_work(store_t *s, uint64_t budget, uint64_t until_ms, store_compact_report_t *rep, bool settle) {
  int ret = 0;
  while (budget > 0 && st_now_ms() < until_ms) {
    const bool ap = !t_ap_held;                       /* (the cleaner appends to the open segment: not while a store_put() has a record written ahead there) */
    if (ap) pthread_mutex_lock(&s->ap_mu);
    if ((ret = wr_lock(s)) < 0) { if (ap) pthread_mutex_unlock(&s->ap_mu); break; }
    if (!s->cl_seg) {
      if (settle) cl_settle_scan_locked(s, st_now_ms());
      uint32_t v = cl_pick_ex(s, NULL, NULL, NULL, NULL, true, settle);
      if (!v && cl_rotate_open_locked(s)) v = cl_pick_ex(s, NULL, NULL, NULL, NULL, true, settle);
      if (!v) { wr_unlock_raw(s); if (ap) pthread_mutex_unlock(&s->ap_mu); break; }
      s->cl_seg = v;
      s->cl_off = ST_SEGHDR;
      s->cl_buf_len = 0;
      atomic_fetch_add_explicit(&s->c_runs, 1, memory_order_relaxed);
    }
    int r = cl_step_locked(s, &budget, 256, rep);
    if (r == 1) cl_finish_victim(s, false, rep);
    else if (r < 0) { cl_finish_victim(s, true, rep); ret = r; }
    atomic_store_explicit(&s->c_last_unix, (uint64_t)time(NULL), memory_order_relaxed);
    int pr = post_write(s);
    const uint64_t t = s->jr_head;
    wr_unlock_raw(s);
    if (ap) pthread_mutex_unlock(&s->ap_mu);
    const int w = jw_wait(s, t, NULL);
    if (pr == 0) pr = w;
    if (r < 0 || pr < 0) { if (ret == 0) ret = pr; break; }
  }
  return ret;
}

/* the writer mutex with the checkpoint's flags, for a caller that writes records and then a checkpoint with the writers kept out (store_compact(finish), the operator's clean-now,
 * store_repair()): the clean flag on disk goes first.  wr_unlock_ck() gives all of it up. */
static int wr_lock_ck_w_at(store_t *s, const char *site) {
  wr_lock_ck_at(s, site);
  const int r = unclean_now_locked(s);
  if (r < 0) { wr_unlock_ck(s); note_error(s, r); }
  return r;
}
#define wr_lock_ck_w(s) wr_lock_ck_w_at((s), __func__)

int store_compact(store_t *s, uint64_t max_bytes, bool finish, store_compact_report_t *rep) {
  if (!s) return -EINVAL;
  if (rep) memset(rep, 0, sizeof(*rep));
  if (st_bulk_busy(s)) return -EBUSY;      /* (no cleaner during a bulk fill: THE BULK FILL) */
  const uint64_t freed0 = atomic_load_explicit(&s->c_segs_freed, memory_order_relaxed);
  int r = cleaner_work(s, max_bytes ? max_bytes : UINT64_MAX, st_now_ms() + 3600000u, rep, false);
  int lr = finish ? wr_lock_ck_w(s) : wr_lock(s);
  if (lr < 0) return r < 0 ? r : lr;
  uint64_t got = 0;
  int nr = nx_reclaim_locked(s, false, &got);
  if (rep) rep->nx_reclaimed = got;
  if (r == 0 && nr < 0) r = nr;
  if (finish) {
    int cr = ck_full_locked(s, false);
    if (cr < 0) note_error(s, cr);
    if (r == 0 && cr < 0) r = cr;
    seg_retire_locked(s, true);
    retire_run(s, false);
    const int w = wr_unlock_ck(s);
    if (r == 0) r = w;                                  /* (the records of the removals are written before the call returns 0) */
  } else {
    const int w = wr_unlock_w(s);
    if (r == 0) r = w;
  }
  if (rep) rep->segs_freed = (uint32_t)(atomic_load_explicit(&s->c_segs_freed, memory_order_relaxed) - freed0);
  bad_drain(s);
  return r;
}

/* What the tick does besides the commit and the checkpoint: the cleaner, the removal of empty segments, the nx pass, the free space, the scrub.  Never inside a read section. */
static void maintenance(store_t *s) {
  if (st_bulk_busy(s)) {         /* (a bulk fill: the cleaner, the removals, the nx pass and the scrub wait for its end, THE BULK FILL) */
    bad_drain(s);
    return;
  }
  uint64_t now = st_now_ms();
  const bool forced = atomic_load_explicit(&s->c_forced, memory_order_relaxed);
  const uint64_t rate = s->o.compact_rate ? s->o.compact_rate : (16ull << 20);
  uint64_t budget;
  if (rate == UINT64_MAX || forced) budget = UINT64_MAX;
  else {
    if (s->cl_tokens_ms) s->cl_tokens += (double)rate * (double)(now - s->cl_tokens_ms) / 1000.0;
    else s->cl_tokens = (double)rate;
    if (s->cl_tokens > 2.0 * (double)rate) s->cl_tokens = 2.0 * (double)rate;
    s->cl_tokens_ms = now;
    budget = (uint64_t)s->cl_tokens;
  }
  if (budget) {
    uint64_t before = atomic_load_explicit(&s->c_moved_bytes, memory_order_relaxed);
    (void)cleaner_work(s, budget, now + (forced ? 1000u : ST_CL_SLICE_MS), NULL, !forced);
    uint64_t moved = atomic_load_explicit(&s->c_moved_bytes, memory_order_relaxed) - before;
    if (rate != UINT64_MAX && !forced) s->cl_tokens = s->cl_tokens > (double)moved ? s->cl_tokens - (double)moved : 0.0;
  }
  if (forced && wr_lock_ck_w(s) == 0) {        /* nothing left to clean: the operator's request is over (a checkpoint, and the empty segments go) */
    if (!s->cl_seg && cl_pick(s, NULL, NULL, NULL, NULL, true) == 0 && !cl_rotate_open_locked(s)) {
      atomic_store_explicit(&s->c_forced, false, memory_order_relaxed);
      const int cr = ck_full_locked(s, false);
      if (cr < 0) note_error(s, cr);
      seg_retire_locked(s, true);
    }
    wr_unlock_ck(s);
  }
  if (wr_lock(s) == 0) {
    seg_retire_locked(s, false);
    (void)nx_reclaim_locked(s, false, NULL);
    if (atomic_load_explicit(&s->avail_est, memory_order_relaxed) < 0 || st_now_ms() - atomic_load_explicit(&s->last_probe_ms, memory_order_relaxed) >= 10000) fs_probe(s);
    (void)wr_unlock_w(s);                               /* (the records of the segment removals and the nx pass are written before the tick goes on) */
  }
  /* the scrub: a pass is due when the interval since the last one has passed; it runs in slices at scrub_rate */
  if (pthread_mutex_trylock(&s->sc_mu) == 0) {
    const uint32_t iv = s->o.scrub_interval_s ? s->o.scrub_interval_s : 604800u;
    uint64_t unow = (uint64_t)time(NULL);
    const uint64_t ld = atomic_load_explicit(&s->sc_last_done, memory_order_relaxed);
    if (!s->sc_running && iv != UINT32_MAX && ld && unow >= ld + iv) scrub_begin_pass(s);
    if (s->sc_running) {
      const uint64_t srate = s->o.scrub_rate ? s->o.scrub_rate : (16ull << 20);
      if (s->sc_tokens_ms) s->sc_tokens += (double)srate * (double)(now - s->sc_tokens_ms) / 1000.0;
      else s->sc_tokens = (double)srate;
      if (s->sc_tokens > 2.0 * (double)srate) s->sc_tokens = 2.0 * (double)srate;
      s->sc_tokens_ms = now;
      uint64_t b0 = s->sc_p_bytes;
      (void)scrub_work(s, (uint64_t)s->sc_tokens + 1, ST_SCRUB_SLICE_MS);
      double used = (double)(s->sc_p_bytes - b0);
      s->sc_tokens = s->sc_tokens > used ? s->sc_tokens - used : 0.0;
    } else {
      s->sc_tokens_ms = 0;
    }
    pthread_mutex_unlock(&s->sc_mu);
  }
  bad_drain(s);
}

int store_commit(store_t *s) {
  if (!s) return -EINVAL;
  return st_commit(s, atomic_load_explicit(&s->lsn, memory_order_acquire));
}
/* the tick: the commit that is due is made here (a short sync, no lock held while it waits), the checkpoint is the flusher's (without one the tick makes it), then the background work */
int store_tick(store_t *s) {
  if (!s) return -EINVAL;
  int r = 0;
  wr_lock_raw(s);
  (void)post_write(s);
  wr_unlock_raw(s);
  if (commit_due(s, st_now_ms())) r = st_commit(s, atomic_load_explicit(&s->lsn, memory_order_acquire));
  if (!s->fl_on) bg_due(s);
  maintenance(s);
  return r;
}
int store_checkpoint(store_t *s) {
  if (!s) return -EINVAL;
  int r = st_ckpt(s, true, false);
  ck_after(s);
  return r;
}
int store_checkpoint_clean(store_t *s) {
  if (!s) return -EINVAL;
  atomic_store_explicit(&s->ck_cancel, true, memory_order_relaxed);       /* (a fuzzy checkpoint in progress is left between two pieces of its flush: this one flushes everything, and a stop does not wait for the rest of the other) */
  wr_lock_ck(s);
  atomic_store_explicit(&s->ck_cancel, false, memory_order_relaxed);      /* (ck_busy is this call's: no fuzzy one runs; the later ones run to their end) */
  int r = ck_full_locked(s, true);
  if (r < 0) note_error(s, r);
  wr_unlock_ck(s);
  return r;
}

#ifdef KARIDNS_UNIT_TEST
/* the bytes of a table file from its data area equal len bytes of memory at base (the first difference is printed) */
static bool file_matches(int fd, const uint8_t *base, uint64_t len, int which) {
  uint8_t buf[65536];
  for (uint64_t o = 0; o < len; o += sizeof(buf)) {
    const size_t n = (size_t)(len - o < sizeof(buf) ? len - o : sizeof(buf));
    if (st_pread_all(fd, buf, n, (off_t)(ST_HDR_PAGE + o)) < 0) { printf("  table %d: the file is shorter than %" PRIu64 " bytes\n", which, len); return false; }
    for (size_t k = 0; k < n; k += 8) {
      uint64_t f, m = atomic_load_explicit((const _Atomic uint64_t *)(base + o + k), memory_order_relaxed);
      memcpy(&f, buf + k, 8);
      if (f != m) { printf("  table %d: offset %" PRIu64 " of %" PRIu64 ": file %016" PRIx64 ", memory %016" PRIx64 "\n", which, o + k, len, f, m); return false; }
    }
  }
  return true;
}
/* the word at byte offset off (a multiple of 8) of the memory of table which (0 zt, 1 zc, 2 nx, 3 the current ix, 4 the current sx); 0 beyond it */
static _Atomic uint64_t *test_word(store_t *s, int which, uint64_t off, dmap_t **d) {
  const mtab_t *tabs[3] = { &s->zt, &s->zc, &s->nx };
  if (which < 3) {
    *d = (dmap_t *)&tabs[which]->d;
    return off + 8 <= atomic_load_explicit(&tabs[which]->mapped, memory_order_relaxed) ? (_Atomic uint64_t *)(tabs[which]->base + off) : NULL;
  }
  ixgen_t *g = atomic_load_explicit(which == 3 ? &s->ix : &s->sx, memory_order_relaxed);
  *d = &g->d;
  return off + 8 <= g->nslots * 8 ? &g->slots[off / 8] : NULL;
}
uint64_t store_test_peek(store_t *s, int which, uint64_t off) {
  dmap_t *d;
  const _Atomic uint64_t *w = test_word(s, which, off, &d);
  return w ? atomic_load_explicit(w, memory_order_relaxed) : 0;
}
/* a word of a table changes in memory (damage, a writer in the middle of a cell), marked for the next checkpoint as a writer's change is */
void store_test_poke(store_t *s, int which, uint64_t off, uint64_t v) {
  wr_lock_raw(s);
  dmap_t *d;
  _Atomic uint64_t *w = test_word(s, which, off, &d);
  if (w) {
    dm_mark(d, off, 8);
    atomic_store_explicit(w, v, memory_order_relaxed);
  }
  wr_unlock_raw(s);
}
void store_test_hold(store_t *s, const char *site, uint64_t us) {
  wr_lock_raw_at(s, site);
  s->wl_t0 -= us;
  wr_unlock_raw(s);
}
bool store_test_writer_free(store_t *s) { return atomic_load_explicit(&s->wl_owner, memory_order_relaxed) != (uintptr_t)pthread_self(); }
bool store_test_files_match(store_t *s) {
  wr_lock_raw(s);
  const mtab_t *tabs[3] = { &s->zt, &s->zc, &s->nx };
  bool ok = true;
  for (int i = 0; i < 3 && ok; i++) ok = file_matches(tabs[i]->fd, tabs[i]->base, atomic_load_explicit(&tabs[i]->mapped, memory_order_relaxed), i);
  const ixgen_t *gens[2] = { atomic_load_explicit(&s->ix, memory_order_relaxed), atomic_load_explicit(&s->sx, memory_order_relaxed) };
  for (int i = 0; i < 2 && ok; i++) ok = file_matches(gens[i]->fd, (const uint8_t *)gens[i]->slots, gens[i]->maplen, 3 + i);
  wr_unlock_raw(s);
  return ok;
}
#endif

/* ------------------------------------------------------------------------------------------------------------------ */
/* readers                                                                                                            */
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
unsigned store_find_cand(const store_t *s, uint16_t view, const char *fname, size_t len, uint32_t *zids, unsigned max) {
  if (len > STORE_NAME_MAX || !max) return 0;
  const ixgen_t *g = atomic_load_explicit(&s->ix, memory_order_acquire);
  uint64_t h = st_hash_name(s, view, (const uint8_t *)fname, len);
  uint32_t tag = st_tag(h);
  uint64_t n = g->nslots, pos = st_pos(h, n);
  unsigned got = 0;
  for (uint64_t i = 0; i < n && got < max; i++) {
    uint64_t v = atomic_load_explicit(&g->slots[pos], memory_order_acquire);
    if (v == 0) break;
    uint32_t z = (uint32_t)v;
    if (z != STORE_NONE && (uint32_t)(v >> 32) == tag) zids[got++] = z;
    if (++pos == n) pos = 0;
  }
  return got;
}
bool store_zid_is(const store_t *s, uint32_t zid, uint16_t view, const char *name, size_t len) {
  if (len > STORE_NAME_MAX) return false;
  uint8_t fn[256];
  for (size_t i = 0; i < len; i++) fn[i] = st_lc((uint8_t)name[i]);
  return st_name_eq(s, zid, view, fn, len);
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
  if ((uint64_t)zid >= st_zt_cap(s) || zt_state_fast(s, zid) == STORE_STATE_FREE) return -ENOENT;
  for (int tries = 0;; tries++) {
    r64_t rt, rc;
    uint32_t seq = 0;
    int r = zrec_read_seq(s, zid, &rt, &rc, &seq);
    if (r < 0) return r;
    zt_t t;
    zc_t c;
    zt_unpack(&rt, &t);
    zc_unpack(&rc, &c);
    if (t.state == STORE_STATE_FREE) return -ENOENT;
    if (t.state > STORE_STATE_STORED) return -EBADMSG;
    bool ok;
    zone_fill(s, zid, &t, &c, out, &ok);
    out->seq = seq;
    if (t.klen > ST_NAME_INL) {                        /* the long name was copied from nx after the cell was read: the nx pass may have moved it meanwhile; the counter says */
      atomic_thread_fence(memory_order_acquire);
      if ((uint32_t)(atomic_load_explicit(&zc_cell(s, zid)[7], memory_order_relaxed) >> 32) != seq && tries < 64) continue;
    }
    return ok ? 0 : -EBADMSG;
  }
}

bool store_zone_unchanged(const store_t *s, uint32_t zid, uint32_t seq) {
  if ((uint64_t)zid >= st_zc_cap(s) || (seq & 1u)) return false;
  return (uint32_t)(atomic_load_explicit(&zc_cell(s, zid)[7], memory_order_acquire) >> 32) == seq;
}

/* ---- err.ring: 4096-byte header page {magic, version, entries, entry size, head}, then STORE_ERR_ENTRIES entries of 224 bytes = 28 words: seq, zid | textlen << 32 | tag << 40, stamp, time, text.
 * The words are read and written as relaxed atomics under the entry's sequence word (written last, cleared first), all of it under err_mu (innermost: nothing is taken while it is held).
 * Finding the newest entry of a zone id is a lookup, not a scan: err_ix is a table of ERR_IX_N buckets (twice the entries), a bucket is a chain through err_nx of ring slots, and a chain has
 * one entry per zone id (the newest: a put unlinks the entry that it supersedes, and the slot that the ring wraps over is unlinked before it is written).  It is made from the ring at the open. ---- */
#define ERR_HDR     4096u
#define ERR_ESZ     224u
#define ERR_WORDS   (ERR_ESZ / 8)
#define ERR_MAGIC   0x315252454952414bull       /* "KARIERR1" */
#define ERR_IX_N    (2u * STORE_ERR_ENTRIES)    /* a power of two (2^17) */

static inline uint32_t err_bucket(uint32_t zid) { return (zid * 2654435761u) >> (32 - 17); }
static inline _Atomic uint64_t *err_hdr(const store_t *s) { return (_Atomic uint64_t *)s->err_map; }
static inline _Atomic uint64_t *err_slot(const store_t *s, uint32_t slot) { return (_Atomic uint64_t *)(s->err_map + ERR_HDR + (size_t)slot * ERR_ESZ); }
static inline uint32_t err_slot_of(uint64_t seq) { return (uint32_t)((seq - 1) % STORE_ERR_ENTRIES); }
/* the entry of zid: its slot + 1, or 0; *pp (when given): where the link to it is kept (err_mu held) */
static uint32_t err_ix_find(const store_t *s, uint32_t zid, uint32_t **pp) {
  uint32_t *link = &s->err_ix[err_bucket(zid)];
  while (*link) {
    const uint32_t k = *link - 1;
    if ((uint32_t)atomic_load_explicit(&err_slot(s, k)[1], memory_order_relaxed) == zid) {
      if (pp) *pp = link;
      return k + 1;
    }
    link = &s->err_nx[k];
  }
  return 0;
}
/* take the slot out of the chain of zid (it may not be in it: a superseded entry) */
static void err_ix_unlink(store_t *s, uint32_t slot, uint32_t zid) {
  uint32_t *link = &s->err_ix[err_bucket(zid)];
  while (*link) {
    const uint32_t k = *link - 1;
    if (k == slot) { *link = s->err_nx[k]; s->err_nx[k] = 0; return; }
    link = &s->err_nx[k];
  }
}
/* the entry of the slot is the newest of its zone id from now on */
static void err_ix_link(store_t *s, uint32_t slot, uint32_t zid) {
  uint32_t *old = NULL;
  const uint32_t k = err_ix_find(s, zid, &old);
  if (k) { *old = s->err_nx[k - 1]; s->err_nx[k - 1] = 0; }
  uint32_t *head = &s->err_ix[err_bucket(zid)];
  s->err_nx[slot] = *head;
  *head = slot + 1;
}

/* open (make) the ring beneath the store directory; best effort: the store works without it */
static void err_ring_open(store_t *s) {
  s->err_len = (size_t)ERR_HDR + (size_t)STORE_ERR_ENTRIES * ERR_ESZ;
  int fd = st_openat(s, "err.ring", O_RDWR | O_CREAT);
  if (fd < 0) return;
  struct stat st;
  if (fstat(fd, &st) != 0 || (size_t)st.st_size > s->err_len * 2) { close(fd); return; }
  if (st.st_size > 0) {                    /* a file that is not ours (or damaged in its header) is emptied by cutting it to nothing: the entries are zero words again, without writing 14 MB */
    uint64_t magic = 0;
    if (pread(fd, &magic, 8, 0) != 8 || magic != ERR_MAGIC) {
      if (ftruncate(fd, 0) != 0) { close(fd); return; }
      st.st_size = 0;
    }
  }
  if ((size_t)st.st_size < s->err_len && ftruncate(fd, (off_t)s->err_len) != 0) { close(fd); return; }
  s->err_ix = calloc(ERR_IX_N, sizeof(*s->err_ix));
  s->err_nx = calloc(STORE_ERR_ENTRIES, sizeof(*s->err_nx));
  void *p = s->err_ix && s->err_nx ? mmap(NULL, s->err_len, PROT_READ | PROT_WRITE, MAP_SHARED | ST_NOCORE, fd, 0) : MAP_FAILED;
  if (p == MAP_FAILED) {
    close(fd);
    free(s->err_ix);
    free(s->err_nx);
    s->err_ix = NULL;
    s->err_nx = NULL;
    return;
  }
  s->err_fd = fd;
  s->err_map = p;
  _Atomic uint64_t *h = err_hdr(s);
  if (atomic_load_explicit(&h[0], memory_order_relaxed) != ERR_MAGIC || atomic_load_explicit(&h[1], memory_order_relaxed) != STORE_ERR_ENTRIES ||
      atomic_load_explicit(&h[2], memory_order_relaxed) != ERR_ESZ) {          /* a new file (zeros all through), or another ring size: an empty ring */
    if (atomic_load_explicit(&h[0], memory_order_relaxed) == ERR_MAGIC)
      for (uint32_t i = 0; i < STORE_ERR_ENTRIES; i++) atomic_store_explicit(err_slot(s, i), 0, memory_order_relaxed);
    atomic_store_explicit(&h[1], STORE_ERR_ENTRIES, memory_order_relaxed);
    atomic_store_explicit(&h[2], ERR_ESZ, memory_order_relaxed);
    atomic_store_explicit(&h[3], 0, memory_order_relaxed);
    atomic_store_explicit(&h[0], ERR_MAGIC, memory_order_release);
  } else if (atomic_load_explicit(&h[3], memory_order_relaxed) > (1ull << 60)) {
    atomic_store_explicit(&h[3], 0, memory_order_relaxed);
  }
  {                                         /* the table of the zone ids that have an entry: oldest first, so that the newest of a zone id is the one that stays */
    uint64_t head = atomic_load_explicit(&h[3], memory_order_relaxed), low = head > STORE_ERR_ENTRIES ? head - STORE_ERR_ENTRIES + 1 : 1;
    for (uint64_t seq = low; seq <= head; seq++) {
      _Atomic uint64_t *w = err_slot(s, err_slot_of(seq));
      if (atomic_load_explicit(&w[0], memory_order_relaxed) == seq) err_ix_link(s, err_slot_of(seq), (uint32_t)atomic_load_explicit(&w[1], memory_order_relaxed));
    }
  }
}
static void err_ring_close(store_t *s) {
  if (s->err_map) munmap(s->err_map, s->err_len);
  if (s->err_fd >= 0) close(s->err_fd);
  s->err_map = NULL;
  s->err_fd = -1;
  free(s->err_ix);
  free(s->err_nx);
  s->err_ix = NULL;
  s->err_nx = NULL;
}

/* err_mu is held */
static void err_put_locked(store_t *s, uint32_t zid, uint32_t tag, uint64_t stamp_gen, const char *text) {
  char buf[STORE_ERR_TEXT];
  size_t tl = strnlen(text, STORE_ERR_TEXT - 1);
  memset(buf, 0, sizeof(buf));
  memcpy(buf, text, tl);
  _Atomic uint64_t *h = err_hdr(s);
  uint64_t seq = atomic_load_explicit(&h[3], memory_order_relaxed) + 1;
  const uint32_t slot = err_slot_of(seq);
  _Atomic uint64_t *w = err_slot(s, slot);
  if (atomic_load_explicit(&w[0], memory_order_relaxed) != 0) err_ix_unlink(s, slot, (uint32_t)atomic_load_explicit(&w[1], memory_order_relaxed));      /* (the ring wraps over it) */
  atomic_store_explicit(&w[0], 0, memory_order_release);              /* (the slot is being overwritten) */
  atomic_thread_fence(memory_order_release);
  atomic_store_explicit(&w[1], (uint64_t)zid | ((uint64_t)tl << 32) | ((uint64_t)(tag & 0xFFFFFFu) << 40), memory_order_relaxed);
  atomic_store_explicit(&w[2], stamp_gen, memory_order_relaxed);
  atomic_store_explicit(&w[3], (uint64_t)time(NULL), memory_order_relaxed);
  for (unsigned i = 0; i < STORE_ERR_TEXT / 8; i++) {
    uint64_t v;
    memcpy(&v, buf + 8 * i, 8);
    atomic_store_explicit(&w[4 + i], v, memory_order_relaxed);
  }
  atomic_store_explicit(&w[0], seq, memory_order_release);
  atomic_store_explicit(&h[3], seq, memory_order_release);
  err_ix_link(s, slot, zid);
}

int store_err_put(store_t *s, uint32_t zid, uint32_t tag, uint64_t stamp_gen, const char *text) {
  if (!s || !text) return -EINVAL;
  if (!s->err_map) return -ENOTSUP;
  pthread_mutex_lock(&s->err_mu);
  err_put_locked(s, zid, tag, stamp_gen, text);
  pthread_mutex_unlock(&s->err_mu);
  return 0;
}

/* the newest entry of the zone id (err_mu held): false when there is none or it is a cleared one */
static bool err_get_locked(const store_t *s, uint32_t zid, store_err_t *out) {
  const uint32_t k = err_ix_find(s, zid, NULL);
  if (!k) return false;
  _Atomic uint64_t *w = err_slot(s, k - 1);
  const uint64_t seq = atomic_load_explicit(&w[0], memory_order_acquire), w1 = atomic_load_explicit(&w[1], memory_order_relaxed);
  if (seq == 0) return false;
  store_err_t e;
  memset(&e, 0, sizeof(e));
  e.seq = seq;
  e.zid = zid;
  e.tag = (uint32_t)(w1 >> 40);
  e.stamp_gen = atomic_load_explicit(&w[2], memory_order_relaxed);
  e.time = atomic_load_explicit(&w[3], memory_order_relaxed);
  for (unsigned i = 0; i < STORE_ERR_TEXT / 8; i++) {
    uint64_t v = atomic_load_explicit(&w[4 + i], memory_order_relaxed);
    memcpy(e.text + 8 * i, &v, 8);
  }
  e.text[STORE_ERR_TEXT - 1] = '\0';
  if (!e.text[0]) return false;                                                    /* (cleared: a record with no text) */
  *out = e;
  return true;
}

int store_err_clear(store_t *s, uint32_t zid) {
  if (!s) return -EINVAL;
  if (!s->err_map) return -ENOTSUP;
  /* only when the zone has a text: the ring is not filled with records of zones that never failed.  The record with no text is what a restart finds (the table is made from the ring). */
  pthread_mutex_lock(&s->err_mu);
  store_err_t e;
  if (err_get_locked(s, zid, &e)) err_put_locked(s, zid, 0, 0, "");
  pthread_mutex_unlock(&s->err_mu);
  return 0;
}

uint64_t store_err_total(const store_t *s) { return s && s->err_map ? atomic_load_explicit(&err_hdr(s)[3], memory_order_acquire) : 0; }

int store_err_get(const store_t *s, uint32_t zid, store_err_t *out) {
  if (!s || !out) return -EINVAL;
  if (!s->err_map) return -ENOENT;
  pthread_mutex_t *mu = (pthread_mutex_t *)&s->err_mu;
  pthread_mutex_lock(mu);
  const bool ok = err_get_locked(s, zid, out);
  pthread_mutex_unlock(mu);
  return ok ? 0 : -ENOENT;
}

int store_flag_next(const store_t *s, uint32_t *cursor, uint16_t flag, store_zone_t *out) {
  for (;;) {
    int r = store_iter(s, cursor, out);
    if (r <= 0) return r;
    if (out->flags & flag) return 1;
  }
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

/* 0.7 (Round 6): COPY mode reads a record into a buffer of the reading thread, touched once and reused (grown when a record is larger, up to ST_RBUF_MAX), and copies it into the image's own
 * buffer.  A pread() into a buffer that nobody touched before faults its pages in inside the read (vn_io_fault() holds the pages of the destination under the process's pmap lock); the copy
 * faults the image's pages in user mode instead, outside the file system's read.  Measured at 10 million zones on ZFS, a restart with no query load: the first half of an attach 19-23 us -> 16-16.5 us,
 * hot.list 233,000-284,000 -> 297,000-316,000 zones a second; under query load no difference beyond the noise.  The buffer is freed when the thread ends. */
#define ST_RBUF_MIN (64u << 10)
#define ST_RBUF_MAX (1u << 20)
static pthread_key_t st_rbuf_key;
static pthread_once_t st_rbuf_once = PTHREAD_ONCE_INIT;
static bool st_rbuf_ok;
_Atomic int store_test_rbuf_off;
typedef struct {
  size_t cap;
  uint8_t b[];
} st_rbuf_t;
static void st_rbuf_init(void) { st_rbuf_ok = pthread_key_create(&st_rbuf_key, free) == 0; }
static uint8_t *st_rbuf(size_t need) {
  if (atomic_load_explicit(&store_test_rbuf_off, memory_order_relaxed) || need > ST_RBUF_MAX) return NULL;
  (void)pthread_once(&st_rbuf_once, st_rbuf_init);
  if (!st_rbuf_ok) return NULL;
  st_rbuf_t *r = pthread_getspecific(st_rbuf_key);
  if (r && r->cap >= need) return r->b;
  size_t cap = ST_RBUF_MIN;
  while (cap < need) cap *= 2;
  st_rbuf_t *n = malloc(sizeof(*n) + cap);
  if (!n) return NULL;
  memset(n->b, 0, cap);                          /* (the pages are touched here, once) */
  n->cap = cap;
  if (pthread_setspecific(st_rbuf_key, n) != 0) {
    free(n);
    return NULL;
  }
  free(r);
  return n->b;
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
    uint8_t *tb = st_rbuf((size_t)rlen);
    r = st_pread_all(g->fd, tb ? tb : copy, (size_t)rlen, (off_t)off);
    if (r < 0) { free(copy); return r == -EIO ? -EBADMSG : r; }
    if (tb) memcpy(copy, tb, (size_t)rlen);
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

/* The index generations are read here, and a writer that grows an index retires the old generation after the grace period of the readers: the thread that reads them is a reader (the
 * section nests: a caller that has one already is not affected). */
void store_stats(const store_t *s, store_stats_t *o) {
  rcu_aux_read_lock();
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
  o->zones_nonstore = VG(s, V_NONSTORE);
  o->zones_free = VG(s, V_FREE_COUNT);
  o->zt_records = VG(s, V_HWM);
  o->zt_capacity = st_zt_cap(s);
  o->nx_used = VG(s, V_NX_USED);
  o->nx_dead = VG(s, V_NX_DEAD);
  const ixgen_t *ix = atomic_load_explicit(&s->ix, memory_order_acquire), *sx = atomic_load_explicit(&s->sx, memory_order_acquire);
  if (ix) { o->ix_gen = ix->gen; o->ix_slots = ix->nslots; }
#ifdef KARIDNS_UNIT_TEST
  if (store_test_in_stats) store_test_in_stats();
#endif
  if (sx) { o->sx_gen = sx->gen; o->sx_slots = sx->nslots; }
  o->ix_used = VG(s, V_IX_USED);
  o->ix_live = VG(s, V_IX_LIVE);
  o->sx_used = VG(s, V_SX_USED);
  o->sx_live = VG(s, V_SX_LIVE);
  o->seg_count = (uint32_t)VG(s, V_NSEGS);
  for (uint32_t n = 1; n <= o->seg_count && n <= ST_MAXSEG; n++) {
    uint64_t used = VG(s, V_SEG(n, 0));
    if (used < ST_SEGHDR) { o->seg_free_numbers++; continue; }
    o->seg_used_bytes += used - ST_SEGHDR;
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
  o->group_records = s->n_group_records;
  o->group_entries = s->n_group_entries;
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
  /* 0.7 WP9 */
  o->journal_max_bytes = jmax(s);
  o->journal_boost = atomic_load_explicit(&s->jboost, memory_order_relaxed);
  o->journal_boosts = atomic_load_explicit(&s->n_jboost, memory_order_relaxed);
  uint32_t draining = 0, pinned = 0;
  (void)cl_pick(s, &o->compact_candidates, &o->compact_dead_bytes, &pinned, &draining, false);
  o->seg_draining = draining;
  o->seg_pinned = atomic_load_explicit(&s->c_pinned_now, memory_order_relaxed);
  if (pinned > o->seg_pinned) o->seg_pinned = pinned;
  o->compact_runs = atomic_load_explicit(&s->c_runs, memory_order_relaxed);
  o->compact_moved_records = atomic_load_explicit(&s->c_moved_recs, memory_order_relaxed);
  o->compact_moved_bytes = atomic_load_explicit(&s->c_moved_bytes, memory_order_relaxed);
  o->compact_segs_freed = atomic_load_explicit(&s->c_segs_freed, memory_order_relaxed);
  o->compact_bad_records = atomic_load_explicit(&s->c_bad, memory_order_relaxed);
  o->compact_pinned_skips = atomic_load_explicit(&s->c_pinned, memory_order_relaxed);
  o->compact_incomplete = atomic_load_explicit(&s->c_incomplete, memory_order_relaxed);
  o->compact_last_unix = atomic_load_explicit(&s->c_last_unix, memory_order_relaxed);
  o->compact_rate = s->o.compact_rate ? s->o.compact_rate : (16ull << 20);
  o->nx_reclaims = atomic_load_explicit(&s->c_nx_runs, memory_order_relaxed);
  o->nx_reclaimed_bytes = atomic_load_explicit(&s->c_nx_bytes, memory_order_relaxed);
  o->fs_total_bytes = atomic_load_explicit(&s->fs_total, memory_order_relaxed);
  o->fs_free_bytes = atomic_load_explicit(&s->fs_avail, memory_order_relaxed);
  o->fs_checked_unix = atomic_load_explicit(&s->fs_checked_unix, memory_order_relaxed);
  o->reserve_bytes = s->reserve_bytes;
  o->fs_blksize = atomic_load_explicit(&s->fs_blksize, memory_order_relaxed);
  o->fs_recordsize_warn = atomic_load_explicit(&s->fs_rec_warn, memory_order_relaxed) != 0;
  o->align_rs = s->align_rs;
  o->align_pads = atomic_load_explicit(&s->n_align_pads, memory_order_relaxed);
  o->align_pad_bytes = atomic_load_explicit(&s->n_align_pad_bytes, memory_order_relaxed);
  o->space_level = atomic_load_explicit(&s->space_level, memory_order_relaxed);
  o->store_bytes = atomic_load_explicit(&s->store_bytes, memory_order_relaxed);
  o->growth_bytes_per_hour = atomic_load_explicit(&s->growth_bph, memory_order_relaxed);
  o->full_in_hours = atomic_load_explicit(&s->full_in_h, memory_order_relaxed);
  o->degraded_puts = atomic_load_explicit(&s->n_degraded, memory_order_relaxed);
  o->enospc_events = atomic_load_explicit(&s->n_enospc, memory_order_relaxed);
  o->degraded_since_unix = atomic_load_explicit(&s->degraded_since, memory_order_relaxed);
  o->scrub_interval_s = s->o.scrub_interval_s ? s->o.scrub_interval_s : 604800u;
  o->scrub_running = atomic_load_explicit(&s->sc_running_a, memory_order_relaxed) != 0;
  o->scrub_progress_pct = atomic_load_explicit(&s->sc_pct, memory_order_relaxed);
  o->scrub_passes = atomic_load_explicit(&s->sc_passes, memory_order_relaxed);
  o->scrub_last_start_unix = atomic_load_explicit(&s->sc_last_start, memory_order_relaxed);
  o->scrub_last_end_unix = atomic_load_explicit(&s->sc_last_end, memory_order_relaxed);
  o->scrub_zones_checked = atomic_load_explicit(&s->sc_zones, memory_order_relaxed);
  o->scrub_bytes_checked = atomic_load_explicit(&s->sc_bytes, memory_order_relaxed);
  o->scrub_bad_images = atomic_load_explicit(&s->sc_bad_img, memory_order_relaxed);
  o->scrub_bad_cells = atomic_load_explicit(&s->sc_bad_cell, memory_order_relaxed);
  o->scrub_bad_index = atomic_load_explicit(&s->sc_bad_idx, memory_order_relaxed);
  o->scrub_io_errors = atomic_load_explicit(&s->sc_io, memory_order_relaxed);
  o->ix_read_us = atomic_load_explicit(&s->ra_ix_us, memory_order_relaxed);
  o->zt_readahead_us = atomic_load_explicit(&s->ra_zt_us, memory_order_relaxed);
  o->zt_readahead_done = atomic_load_explicit(&s->ra_done, memory_order_acquire);
  o->err_total = store_err_total(s);
  o->lock_holds = atomic_load_explicit(&s->wl_n, memory_order_relaxed);
  o->lock_holds_slow = atomic_load_explicit(&s->wl_slow, memory_order_relaxed);
  o->lock_hold_max_us = atomic_load_explicit(&s->wl_max_us, memory_order_relaxed);
  o->lock_hold_max_site = atomic_load_explicit(&s->wl_max_site, memory_order_relaxed);
  o->lock_nsites = 0;
  for (unsigned i = 0; i < STORE_LOCK_SITES; i++) {
    const st_wl_site_t *w = &s->wl_sites[i];
    const char *at = atomic_load_explicit(&w->site, memory_order_acquire);
    if (!at) break;
    store_lock_site_t *o2 = &o->lock_sites[o->lock_nsites++];
    o2->site = at;
    o2->slow = atomic_load_explicit(&w->slow, memory_order_relaxed);
    o2->over_10ms = atomic_load_explicit(&w->over10, memory_order_relaxed);
    o2->over_100ms = atomic_load_explicit(&w->over100, memory_order_relaxed);
    o2->slow_us = atomic_load_explicit(&w->slow_us, memory_order_relaxed);
    o2->max_us = atomic_load_explicit(&w->max_us, memory_order_relaxed);
  }
  o->growths_background = atomic_load_explicit(&s->n_growths_bg, memory_order_relaxed);
  o->journal_state = atomic_load_explicit(&s->jw_state, memory_order_acquire);
  o->journal_error = atomic_load_explicit(&s->jw_last_err, memory_order_relaxed);
  o->journal_failed_unix = atomic_load_explicit(&s->jw_fail_unix, memory_order_relaxed);
  {
    const uint64_t pub = atomic_load_explicit(&s->jr_pub, memory_order_acquire), tail = atomic_load_explicit(&s->jr_tail, memory_order_acquire);
    o->ring_bytes = pub < s->jr_cap ? ((pub + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1)) : s->jr_cap;
    o->ring_unwritten_bytes = pub > tail ? pub - tail : 0;
  }
  o->ring_peak_bytes = atomic_load_explicit(&s->jr_peak, memory_order_relaxed);
  o->ring_waits = atomic_load_explicit(&s->n_jr_waits, memory_order_relaxed);
  o->ring_wait_max_us = atomic_load_explicit(&s->jr_wait_max_us, memory_order_relaxed);
  o->ring_full_in_lock = atomic_load_explicit(&s->n_jr_inlock, memory_order_relaxed);
  o->leader_writes = atomic_load_explicit(&s->n_jw_writes, memory_order_relaxed);
  o->leader_bytes = atomic_load_explicit(&s->n_jw_bytes, memory_order_relaxed);
  o->leader_write_max_us = atomic_load_explicit(&s->jw_write_max_us, memory_order_relaxed);
  o->leader_retries = atomic_load_explicit(&s->n_jw_retries, memory_order_relaxed);
  o->checkpoint_journal_waits = atomic_load_explicit(&s->n_ck_twaits, memory_order_relaxed);
  o->space_estimate_bytes = atomic_load_explicit(&s->avail_est, memory_order_relaxed);
  o->space_reprobe_in_lock = atomic_load_explicit(&s->n_reprobe_lock, memory_order_relaxed);
  o->defer_busy = atomic_load_explicit(&s->n_df_busy, memory_order_relaxed);
  for (unsigned k = 0; k < STORE_FINE_BUCKETS; k++) o->lock_hold_fine[k] = atomic_load_explicit(&s->wl_fine[k], memory_order_relaxed);
  o->journal_bytes_written = o->leader_bytes;
  o->bulk_active = (uint32_t)store_bulk(s);
  o->bulk_fills = atomic_load_explicit(&s->n_bulk_fills, memory_order_relaxed);
  o->bulk_resumed = s->rec.bulk_resumed ? 1 : 0;
  o->bulk_recoveries = s->rec.bulk_recovered ? 1 : 0;
  o->bulk_checkpoints = atomic_load_explicit(&s->n_bulk_ckpts, memory_order_relaxed);
  o->bulk_unlogged_records = atomic_load_explicit(&s->n_bulk_unlogged, memory_order_relaxed);
  o->bulk_since_unix = o->bulk_active ? atomic_load_explicit(&s->bulk_since, memory_order_relaxed) : 0;
  o->bulk_ended_unix = atomic_load_explicit(&s->bulk_ended, memory_order_relaxed);
  o->bulk_next_bytes = o->bulk_active && atomic_load_explicit(&s->bulk_body, memory_order_relaxed) ? bulk_next_bytes(s) : 0;
  o->bulk_end_pending = atomic_load_explicit(&s->bulk_end_pending, memory_order_relaxed) ? 1 : 0;
  o->bulk_cut = atomic_load_explicit(&s->bulk_cut, memory_order_relaxed) ? 1 : 0;
  o->names_refused = atomic_load_explicit(&s->n_names_refused, memory_order_relaxed);
  o->reserve_zones = s->zt.reserve / ST_REC;
  o->reserve_nx_bytes = s->nx.reserve;
  o->reserve_zones_used = VG(s, V_HWM);
  o->reserve_nx_used = VG(s, V_NX_USED);
  o->reserve_refused = atomic_load_explicit(&s->n_resv_refused, memory_order_relaxed);
  o->flusher = s->fl_on;
  o->checkpoint_max_us = atomic_load_explicit(&s->ckpt_max_us, memory_order_relaxed);
  o->checkpoints_cancelled = atomic_load_explicit(&s->n_ckpt_cancel, memory_order_relaxed);
  o->journal_peak_bytes = atomic_load_explicit(&s->jpeak, memory_order_relaxed);
  o->journal_bound_bytes = jbound(s, 2);
  o->journal_limit_waits = atomic_load_explicit(&s->jw_n, memory_order_relaxed);
  o->journal_limit_wait_us = atomic_load_explicit(&s->jw_us, memory_order_relaxed);
  o->journal_limit_wait_max_us = atomic_load_explicit(&s->jw_max_us, memory_order_relaxed);
  o->index_waits = atomic_load_explicit(&s->iw_n, memory_order_relaxed);
  o->index_wait_us = atomic_load_explicit(&s->iw_us, memory_order_relaxed);
  o->index_wait_max_us = atomic_load_explicit(&s->iw_max_us, memory_order_relaxed);
  o->index_wait_giveups = atomic_load_explicit(&s->iw_giveups, memory_order_relaxed);
  o->journal_commit_switches = atomic_load_explicit(&s->n_jswitch, memory_order_relaxed);
  o->image_prewrites = atomic_load_explicit(&s->n_prew, memory_order_relaxed);
  o->image_prewrite_misses = atomic_load_explicit(&s->n_prew_miss, memory_order_relaxed);
  o->ahead_allocs = atomic_load_explicit(&s->n_ah_allocs, memory_order_relaxed);
  o->ahead_alloc_us = atomic_load_explicit(&s->n_ah_us, memory_order_relaxed);
  o->ahead_alloc_max_us = atomic_load_explicit(&s->n_ah_max_us, memory_order_relaxed);
  o->ahead_thread_max_us = atomic_load_explicit(&s->n_ah_thread_max_us, memory_order_relaxed);
  o->ahead_errors = atomic_load_explicit(&s->n_ah_errors, memory_order_relaxed);
  o->ahead_busy_kicks = atomic_load_explicit(&s->n_ah_busy_kicks, memory_order_relaxed);
  o->ahead_unallocated_growths = atomic_load_explicit(&s->n_ah_unahead, memory_order_relaxed);
  o->segment_precreated = atomic_load_explicit(&s->n_seg_pre, memory_order_relaxed);
  o->segment_inline_creates = atomic_load_explicit(&s->n_seg_inline, memory_order_relaxed);
  o->segment_precreate_errors = atomic_load_explicit(&s->n_seg_pre_err, memory_order_relaxed);
  o->segment_precreate_us = atomic_load_explicit(&s->n_seg_pre_us, memory_order_relaxed);
  o->segment_precreate_max_us = atomic_load_explicit(&s->n_seg_pre_max_us, memory_order_relaxed);
  o->segment_inline_create_max_us = atomic_load_explicit(&s->n_seg_inline_max_us, memory_order_relaxed);
  o->segment_ready = atomic_load_explicit(&s->pre_state, memory_order_relaxed) == PRE_READY ? 1u : 0u;
  o->table_private_bytes = atomic_load_explicit(&s->priv_bytes, memory_order_relaxed);
  o->checkpoint_table_bytes = atomic_load_explicit(&s->n_ck_bytes, memory_order_relaxed);
  o->checkpoint_table_last_bytes = atomic_load_explicit(&s->ck_last_bytes, memory_order_relaxed);
  o->checkpoint_paced_us = atomic_load_explicit(&s->n_ck_paced_us, memory_order_relaxed);
  rcu_aux_read_unlock();
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

/* 0.7 (fix 7): the segments are opened (and mapped, in MAP mode) at the start, so that the first query of a zone finds its segment open (store_image_resident() asks no open of a worker).  Only the mapping is
 * made; no page is read. */
void store_open_segments(const store_t *cs) {
  store_t *s = (store_t *)cs;
  uint32_t nseg = (uint32_t)VG(s, V_NSEGS);
  if (nseg > ST_MAXSEG) nseg = ST_MAXSEG;
  for (uint32_t n = 1; n <= nseg; n++) (void)seg_get(s, n);
}

/* 0.7 (fix 7): are the pages of the zone's stored image in the page cache?  MAP mode only (COPY reads with pread, which can block); the segment must be open already (no open on this thread: a worker
 * calls it), the record must lie within the mapping and span few pages.  A page can leave between this call and the touch of it: the touch is then a fault that reads the page from the disk (the
 * worker waits for it once), the same risk every MAP lookup of the tables has; dns_db_store.c's worker attach documents it. */
#define ST_RES_PAGES 32
bool store_image_resident(const store_t *cs, const store_zone_t *z) {
  store_t *s = (store_t *)cs;
  if (s->mode != STORE_MODE_MAP || z->state != STORE_STATE_STORED || z->loc == 0) return false;
  const uint32_t sn = (uint32_t)(z->loc >> ST_LOC_SHIFT);
  if (sn == 0 || sn > ST_MAXSEG) return false;
  const seg_t *g = atomic_load_explicit(&s->segs[sn], memory_order_acquire);
  if (!g || !g->map) return false;
  const uint64_t off = (z->loc & ST_LOC_MASK) * 64, rlen = st_reclen(z->klen, z->img_len);
  if (off < ST_SEGHDR || off + rlen > g->maplen) return false;
  const uint64_t first = off & ~(uint64_t)(s->pagesz - 1), span = off + rlen - first;
  const size_t np = (size_t)((span + s->pagesz - 1) / s->pagesz);
  char vec[ST_RES_PAGES];
  if (np == 0 || np > ST_RES_PAGES) return false;
  if (mincore(g->map + first, np * s->pagesz, vec) != 0) return false;
  for (size_t i = 0; i < np; i++)
    if (!(vec[i] & 1)) return false;
  return true;
}

/* ---- 0.7 (fix 8): hot.list, the zone ids that were in memory at a clean stop, the most used first ----
 * One file in the store's directory: a 48-byte header (magic, version, the store's uuid, the count, the checksum64 of the ids and of the header) and the ids (u32 each).  The header is written
 * last (the file is first made invalid), so a torn write is a file that is not trusted; a list of another store (another uuid) is not trusted either.  Nothing in it is believed: the reader
 * of the list attaches only zones whose record is stored. */
#define ST_HOT_MAGIC 0x544F484Bu       /* "KHOT" */
#define ST_HOT_HDR 48u
typedef struct { uint32_t magic, version; uint8_t uuid[16]; uint64_t n, sum, hsum; } hothdr_t;
_Static_assert(sizeof(hothdr_t) == ST_HOT_HDR, "hothdr_t");

static uint64_t hot_hsum(const hothdr_t *h) { return st_sum64(h, ST_HOT_HDR - 8, 0x686F746C697374ull); }

int store_hot_write(store_t *s, const uint32_t *zids, size_t n) {
  if (!s || (n && !zids) || n > STORE_HOT_MAX) return -EINVAL;
  int fd = st_openat(s, "hot.list", O_RDWR | O_CREAT);
  if (fd < 0) return fd;
  hothdr_t h;
  memset(&h, 0, sizeof(h));
  int r = st_pwrite_all(fd, &h, sizeof(h), 0);                       /* (invalid until the ids are written) */
  if (r == 0 && n) r = st_pwrite_all(fd, zids, n * sizeof(uint32_t), ST_HOT_HDR);
  if (r == 0 && ftruncate(fd, (off_t)(ST_HOT_HDR + n * sizeof(uint32_t))) != 0) r = -errno;
  if (r == 0 && fsync(fd) != 0) r = -errno;
  if (r == 0) {
    h.magic = ST_HOT_MAGIC;
    h.version = 1;
    memcpy(h.uuid, s->uuid, 16);
    h.n = n;
    h.sum = st_sum64(zids, n * sizeof(uint32_t), 0);
    h.hsum = hot_hsum(&h);
    r = st_pwrite_all(fd, &h, sizeof(h), 0);
    if (r == 0 && fsync(fd) != 0) r = -errno;
  }
  close(fd);
  return r;
}

int store_hot_read(const store_t *cs, uint32_t **zids, size_t *n) {
  store_t *s = (store_t *)cs;
  *zids = NULL;
  *n = 0;
  int fd = st_openat(s, "hot.list", O_RDONLY);
  if (fd < 0) return fd;
  hothdr_t h;
  memset(&h, 0, sizeof(h));
  struct stat st;
  int r = fstat(fd, &st) != 0 ? -errno : (st.st_size < (off_t)ST_HOT_HDR ? -EBADMSG : st_pread_all(fd, &h, sizeof(h), 0));
  if (r == 0 && (h.magic != ST_HOT_MAGIC || h.version != 1 || memcmp(h.uuid, s->uuid, 16) != 0 || h.hsum != hot_hsum(&h) || h.n > STORE_HOT_MAX || (uint64_t)st.st_size != ST_HOT_HDR + h.n * 4)) r = -EBADMSG;
  uint32_t *ids = NULL;
  if (r == 0 && h.n) {
    ids = malloc((size_t)h.n * sizeof(uint32_t));
    if (!ids) r = -ENOMEM;
    else r = st_pread_all(fd, ids, (size_t)h.n * sizeof(uint32_t), ST_HOT_HDR);
    if (r == 0 && st_sum64(ids, (size_t)h.n * sizeof(uint32_t), 0) != h.sum) r = -EBADMSG;
  }
  close(fd);
  if (r != 0) {
    free(ids);
    return r;
  }
  *zids = ids;
  *n = (size_t)h.n;
  return 0;
}

#define CHK_FAIL(...) do { rep->errors++; if (!rep->first_error[0]) snprintf(rep->first_error, sizeof(rep->first_error), __VA_ARGS__); } while (0)

int store_check(store_t *s, store_check_report_t *rep) {
  memset(rep, 0, sizeof(*rep));
  wr_lock_raw(s);
  uint64_t hwm = VG(s, V_HWM), known = 0, stored = 0, rej = 0, nons = 0, bytes = 0, nfree = 0, live_ix = 0, live_sx = 0, nxlive = 0;
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
    if (t.flags & STORE_F_NONSTORE) nons++;
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
  if (nons != VG(s, V_NONSTORE)) CHK_FAIL("totals: nonstore %" PRIu64 "/%" PRIu64, nons, VG(s, V_NONSTORE));
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
  wr_unlock_raw(s);
  return rep->errors ? -EBADMSG : 0;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* repair: rebuild the derived tables from zt                                                                           */
/* ------------------------------------------------------------------------------------------------------------------ */

/* the counters are recomputed into a private array and stored at the end, so that readers (and a concurrent store_stats) never see a half-done recount */
#define NG(i)    (nv[(i)])
#define NS(i, x) (nv[(i)] = (x))
/* how: RB_OPEN (at the open: a long name may lie past the counter of nx, in bytes a checkpoint wrote by the nx rule, ck_nx_widen(); it is taken when it is the name the cell holds the start of),
 * RB_BULK (after a bulk fill was cut off: a STORED cell whose image is past the durable end of its segment, the counters of the superblock, becomes KNOWN with its name, source id and stamp, instead
 * of being dropped: the loader's cursor may already be past it) */
#define RB_OPEN 1u
#define RB_BULK 2u
/* Is a long name read from nx one that a writer could have stored?  The writers may store any bytes but a zero one (check_name_args() refuses a name with one; every name of the server is a C
 * string: the zone names of the loader and of the configuration, the keys of the secondaries' copies), so a name with a zero byte is a page of nx that did not reach the disk, not the name of
 * the cell.  Any other bytes are taken (escapes, 8-bit bytes, labels of any length): the rebuild never drops a name that the way in accepted.  The hash of the name cannot be checked against
 * its index slot here: the index the rebuild replaces is a copy of its own (fuzzy, or not written by a bulk checkpoint), so a slot that is missing proves nothing. */
static bool st_name_text_ok(const uint8_t *n, size_t len) { return memchr(n, 0, len) == NULL; }
static int rebuild_locked(store_t *s, unsigned how) {
  uint64_t *nv = malloc(ST_NV * sizeof(*nv));
  if (!nv) return -ENOMEM;
  for (uint32_t i = 0; i < ST_NV; i++) nv[i] = VG(s, i);
  if (how & RB_OPEN) {                                /* (no reader yet: the names that the files hold up to the size of nx are readable for the pass) */
    const uint64_t m = atomic_load_explicit(&s->nx.mapped, memory_order_relaxed);
    if (m > atomic_load_explicit(&s->nx_avail, memory_order_relaxed)) atomic_store_explicit(&s->nx_avail, m, memory_order_release);
  }
  uint64_t hwm = NG(V_HWM), cap = st_zt_cap(s);
  if (hwm > cap) hwm = cap;
  uint32_t nviews = atomic_load_explicit(&s->nviews, memory_order_relaxed);
  ixgen_t *nix = NULL, *nsx = NULL;
  uint64_t slots = ix_slots_for(hwm);
  if (s->rg_active) atomic_store_explicit(&s->rg_cancel, true, memory_order_relaxed);       /* (a build in progress is dropped: the generations change here) */
  int r = ixgen_create(s, FK_IX, s->ix_gen_next++, slots, true, &nix);
  if (r == 0) r = ixgen_create(s, FK_SX, s->sx_gen_next++, slots, true, &nsx);
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
  uint64_t nxlive = 0, live_ix = 0, live_sx = 0, nx_end = nx_used;
  for (uint64_t z = 0; z < hwm; z++) {
    r64_t rt, rc;
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
      if (ok && t.klen > ST_NAME_INL) ok = memcmp(fn, t.name + 8, ST_NAME_INL - 8) == 0 && st_name_text_ok(fn, t.klen);    /* (a long name is the one whose start the cell holds, and holds no zero byte: st_name_text_ok()) */
      if (ok && t.state == STORE_STATE_STORED) {
        uint32_t sn = (uint32_t)(t.loc >> ST_LOC_SHIFT);
        uint64_t off = (t.loc & ST_LOC_MASK) * 64, rl = st_reclen(t.klen, t.img_len);
        const bool placed = sn >= 1 && sn <= ST_MAXSEG && off >= ST_SEGHDR;
        ok = placed && sn <= nsegs && off + rl <= NG(V_SEG(sn, 0));
        if (!ok && placed && (how & RB_BULK)) {      /* (past the durable end of its segment: the zone is KNOWN, fetched again; THE BULK FILL, rule K) */
          t.state = STORE_STATE_KNOWN;
          t.loc = 0;
          t.img_len = 0;
          zt_pack(&t, &rt);
          zrec_seal(&rt, &rc);
          zrec_write(s, (uint32_t)z, &rt, &rc);
          s->rec.bulk_known++;
          ok = true;
        }
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
        s->rec.rebuilt_zones++;                      /* (live zones only: not the free cells, not the dropped ones) */
        if (c.source_id != 0) {
          ix_raw_insert(nsx, st_hash_src(s, c.source, t.view, c.source_id), (uint32_t)z);
          live_sx++;
        }
        if (t.klen > ST_NAME_INL) {
          uint64_t no;
          memcpy(&no, t.name, 8);
          nxlive += t.klen;
          if (no + t.klen > nx_end) nx_end = no + t.klen;      /* (a name past the counter, RB_OPEN: nx ends after it, the next name goes behind it) */
        }
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
        if (t.flags & STORE_F_NONSTORE) NS(V_NONSTORE, NG(V_NONSTORE) + 1);
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
  NS(V_NX_USED, nx_end);
  NS(V_NX_DEAD, nx_end >= nxlive ? nx_end - nxlive : 0);
  /* the segment counters of segments no record uses stay 0 live; V_SEG(n, 0) were restored above */
  /* (the new generations are anonymous memory: the checkpoint that follows the rebuild writes them whole, ck_write_tab()) */
  for (uint32_t i = 0; i < ST_NV; i++) VS(s, i, nv[i]);
  free(nv);
  if ((how & RB_OPEN) || nx_end > atomic_load_explicit(&s->nx_avail, memory_order_relaxed)) atomic_store_explicit(&s->nx_avail, nx_end, memory_order_release);
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
  int r = wr_lock_ck_w(s);                            /* (the writers are kept out until the checkpoint of the rebuild is on disk) */
  if (r < 0) return r;
  /* the rebuild changes cells, tables and counters that no journal record describes, and is only complete with its checkpoint: a marker in the journal first, so
   * that a crash (or a failed checkpoint and a later crash) in between makes the open rebuild again instead of trusting half of it */
  jb_reset(&s->jb);
  r = jb_op(&s->jb, OP_REBUILD, 8) ? journal_append(s) : -ENOMEM;
  if (r == 0) r = rebuild_locked(s, 0);
  if (r == 0) r = ck_full_locked(s, false);
  if (r < 0) note_error(s, r);
  wr_unlock_ck(s);
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
  if (s->jold >= 0) { close(s->jold); s->jold = -1; }
  if (s->jnext_fd >= 0) { close(s->jnext_fd); s->jnext_fd = -1; }
}

/* The zones the address space of zt and zc is reserved for (a table never moves, so it is the most the tables can hold until the next start).  `opt` (store-max-zones) when set; else the RAM
 * decides, 256 bytes of it for a zone (a zone of a small server takes about that much in zt, zc, the index and the name; the tables are the part that is mapped, the rest of the memory is
 * the zones themselves): physmem / 256 rounded up to a power of two, at least 1M zones and at most 2^25 (the largest the reservation was before: 4 GiB of address space for zt and zc).
 * A host whose RAM is not known (physmem 0) keeps the old 2^25. */
uint32_t store_reserve_zones(uint64_t physmem, uint32_t opt) {
  if (opt) return opt;
  if (physmem == 0) return 1u << 25;
  const uint64_t z = physmem / 256;
  uint32_t r = 1u << 20;
  while (r < z && r < (1u << 25)) r <<= 1;
  return r;
}
static uint64_t st_physmem(void) {
#if defined(__FreeBSD__)
  unsigned long pm = 0;
  size_t l = sizeof(pm);
  if (sysctlbyname("hw.physmem", &pm, &l, NULL, 0) == 0 && l == sizeof(pm)) return pm;
#endif
  return 0;
}
/* Open (or create) zt, zc and nx with the address space they may grow to: zones x 64 bytes for zt and zc each, zones x 32 bytes for nx (the long names; `nx_max` of the options says another
 * size), and at least twice what the files hold now plus a growth step (a store that grew to its reservation opens with room again; a file is never larger than its table plus the growth step). */
static int open_tables(store_t *s, uint64_t zt_cap, uint64_t nx_cap, bool create) {
  const uint64_t pm = s->o.physmem ? s->o.physmem : st_physmem();
  const uint32_t zones = store_reserve_zones(pm, s->o.max_zones);
  s->resv_zones = zones;
  s->resv_from_opt = s->o.max_zones != 0;
  uint64_t zres = (uint64_t)zones * ST_REC, nres = s->o.nx_max ? s->o.nx_max : (uint64_t)zones * 32;
  if (zt_cap && zt_cap * 2 * ST_REC + ST_CHUNK > zres) zres = zt_cap * 2 * ST_REC + ST_CHUNK;
  if (nx_cap && nx_cap * 2 + ST_CHUNK > nres) nres = nx_cap * 2 + ST_CHUNK;
  int r = mtab_open(s, &s->zt, "zt.1", FK_ZT, 64, (size_t)zres, create);
  if (r == 0) r = mtab_open(s, &s->zc, "zc.1", FK_ZC, 64, (size_t)zres, create);
  if (r == 0) r = mtab_open(s, &s->nx, "nx.1", FK_NX, 1, (size_t)nres, create);
  if (r == 0) st_log(s, 6, "store: address space reserved for the tables: %u zones (%s), %" PRIu64 " bytes for zt and zc each, %" PRIu64 " for nx", zones,
                     s->resv_from_opt ? "store-max-zones" : "from the RAM", zres, nres);
  return r;
}

/* Adopt the state of superblock copy b: open and check the table files.  On failure the files are closed again. */
/* a failure that says nothing about the files: the open fails with it and nothing is moved aside (only -EBADMSG, damage or another format, is) */
static bool st_resource_err(int r) { return r == -ENOMEM || r == -EAGAIN || r == -EMFILE || r == -ENFILE || r == -ENOBUFS; }
static int adopt_sb(store_t *s, const sb_t *b) {
  memcpy(s->uuid, b->f.uuid, 16);
  s->hk0 = b->f.hk0;
  s->hk1 = b->f.hk1;
  s->seg_size = b->f.seg_size;
  int r = open_tables(s, b->f.zt_cap, b->f.nx_cap, false);
  if (r < 0) goto fail;
  if (atomic_load(&s->zt.mapped) < b->f.zt_cap * ST_REC || atomic_load(&s->zc.mapped) < b->f.zt_cap * ST_REC ||
      atomic_load(&s->nx.mapped) < b->f.nx_cap || b->f.v[V_HWM] > b->f.zt_cap || b->f.v[V_NX_USED] > b->f.nx_cap) { r = -EBADMSG; goto fail; }
  /* every counter is bounded before it is taken in (the segment counters are array indexes and file offsets, the free list head a zone id) */
  for (uint32_t i = 0; i < ST_NV; i++)
    if (!v_value_ok(s, i, b->f.v[i])) { r = -EBADMSG; goto fail; }
  if (b->f.v[V_CUR_SEG] > b->f.v[V_NSEGS]) { r = -EBADMSG; goto fail; }
  for (uint32_t n = 1; n <= b->f.v[V_NSEGS]; n++)
    if (b->f.v[V_SEG(n, 0)] != 0 && b->f.v[V_SEG(n, 0)] < ST_SEGHDR) { r = -EBADMSG; goto fail; }       /* (0 = a segment that was cleaned and removed: its number is free) */
  ixgen_t *ix = NULL, *sx = NULL;
  if (b->f.flags & SBF_BULK_CK) {
    /* a bulk checkpoint wrote no ix / sx (their files may hold nothing, or be gone after a power loss): the open rebuilds them from zt (store_open()); the generation numbers are kept for the
     * numbering of the new ones */
  } else {
    if ((r = ixgen_open(s, FK_IX, b->f.ix_gen, b->f.ix_slots, &ix)) < 0) goto fail;
    if ((r = ixgen_open(s, FK_SX, b->f.sx_gen, b->f.sx_slots, &sx)) < 0) { ixgen_free(ix); goto fail; }
  }
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
  atomic_store_explicit(&s->sc_last_done, b->f.rsv[0] > (uint64_t)time(NULL) ? 0 : b->f.rsv[0], memory_order_relaxed);
  return 0;
fail:
  files_close(s);
  return r < 0 ? r : -EBADMSG;
}

/* the lowest journal file below generation lo that is still there (lo when none): the files of a chain that a checkpoint ended before it deleted them (a commit switches the file,
 * so there may be hundreds); the first checkpoint of the open deletes them.  The scan stops after 64 generations without a file. */
static uint32_t jrn_low_scan(store_t *s, uint32_t lo) {
  uint32_t low = lo;
  for (uint32_t g = lo, miss = 0; g > 1 && miss < 64; ) {
    g--;
    char name[32];
    struct stat st;
    st_name_ix(name, sizeof(name), "jrn", g);
    if (fstatat(s->dirfd, name, &st, 0) == 0) { low = g; miss = 0; }
    else miss++;
  }
  return low;
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

/* A bulk fill that was cut off (THE BULK FILL, K): nothing of the journal is applied (it holds no record of the fill; the records of its end, after its last checkpoint began, are
 * lost with the fill, whose cursors the caller drops), but the files of the chain are skipped, so that the next journal file is a new one */
static void journal_skip(store_t *s, uint32_t first_gen) {
  uint32_t last_gen = first_gen;
  for (uint32_t gen = first_gen;; gen++) {
    char name[32];
    st_name_ix(name, sizeof(name), "jrn", gen);
    const int fd = st_openat(s, name, O_RDONLY);
    if (fd < 0) break;
    fhdr_t h;
    const bool ok = st_pread_all(fd, &h, sizeof(h), 0) == 0 && fhdr_ok(s, &h, FK_JRN, gen);
    close(fd);
    if (!ok) break;
    last_gen = gen;
    s->rec.journals_read++;
  }
  s->rec.replay_from_lsn = s->ckpt_lsn + 1;
  s->rec.replay_to_lsn = s->ckpt_lsn;
  s->jrn_gen = last_gen;
}

static int create_store(store_t *s) {
  st_random(s->uuid, 16);
  if (s->o.hash_seed[0] || s->o.hash_seed[1]) { s->hk0 = s->o.hash_seed[0]; s->hk1 = s->o.hash_seed[1]; }
  else st_random(&s->hk0, 16);
  s->seg_size = s->seg_size ? s->seg_size : (256ull << 20);
  int r = open_tables(s, 0, 0, true);
  uint64_t zones = s->o.expected_zones;
  if (r == 0) r = ensure_zt_cap(s, zones + 1);
  if (r == 0) r = ensure_nx_cap(s, 1);
  ixgen_t *ix = NULL, *sx = NULL;
  uint64_t slots = zones ? zones * 8 / 3 + 16 : ST_IX_MIN;
  if (slots < ST_IX_MIN) slots = ST_IX_MIN;
  if (r == 0) r = ixgen_create(s, FK_IX, 1, slots, true, &ix);
  if (r == 0) r = ixgen_create(s, FK_SX, 1, slots, true, &sx);
  if (r < 0) { ixgen_free(ix); return r; }
  atomic_store(&s->ix, ix);
  atomic_store(&s->sx, sx);
  s->ix_gen = s->sx_gen = 1;
  VS(s, V_FREE_HEAD, STORE_NONE);
  atomic_store(&s->nx_avail, 0);
  s->lsn = 0;
  s->ckpt_lsn = 0;
  s->jrn_gen = 0;
  s->jrn_gone = 1;
  atomic_store_explicit(&s->sc_last_done, (uint64_t)time(NULL), memory_order_relaxed);
  s->ix_gen_next = s->sx_gen_next = 2;
  /* two superblock copies so that either one can be the "older" one from the start */
  s->sb_next = 0;
  int oldfd = -1;
  r = journal_switch_locked(s, 1, &oldfd, true);      /* (jrn_gen 0: the journal file 1, records from LSN 1) */
  if (r == 0) r = jw_wait(s, s->jr_head, NULL);          /* (its header is in the ring: written before the sync) */
  if (r == 0 && fsync(s->jfd) != 0) r = -errno;
  /* the table files (header page, size) and the directory entries of every file made so far are durable before a superblock names them: a checkpoint that finds nothing dirty syncs no table (0.7, UFS) */
  if (r == 0 && fsync(s->zt.fd) != 0) r = -errno;
  if (r == 0 && fsync(s->zc.fd) != 0) r = -errno;
  if (r == 0 && fsync(s->nx.fd) != 0) r = -errno;
  if (r == 0 && fsync(ix->fd) != 0) r = -errno;
  if (r == 0 && fsync(sx->fd) != 0) r = -errno;
  if (r == 0 && fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) r = -errno;
  if (r == 0) r = sb_write(s, false, 1);
  if (r == 0) r = sb_write(s, false, 1);
  if (r == 0 && fsync(s->dirfd) != 0 && errno != EINVAL && errno != ENOTSUP) r = -errno;      /* (the superblock files were made, empty, by store_open()) */
  return r;
}

/* Design 7: ix is read once, from the beginning, before the first answer (a lookup never waits for the disk in the index); zt is read in the background. */
#ifdef KARIDNS_UNIT_TEST
void (*store_test_ra_page)(void);
#endif
static void touch_pages(const void *base, size_t len, size_t pagesz, const _Atomic bool *stop) {
  volatile uint64_t sink = 0;
  for (size_t off = 0; off + 8 <= len; off += pagesz) {
    if (stop && atomic_load_explicit(stop, memory_order_relaxed)) break;                 /* (every page: a page that is not in memory waits for the disk, and the close waits for this thread) */
#ifdef KARIDNS_UNIT_TEST
    if (stop && store_test_ra_page) store_test_ra_page();
#endif
    sink += atomic_load_explicit((const _Atomic uint64_t *)((const uint8_t *)base + off), memory_order_relaxed);
  }
  (void)sink;
}
static void ix_prefetch(store_t *s) {
  uint64_t t0 = st_now_us();
  ixgen_t *g = atomic_load_explicit(&s->ix, memory_order_relaxed);
  if (g && g->slots) {
    (void)madvise((void *)g->slots, g->maplen, MADV_WILLNEED);
    touch_pages(g->slots, g->maplen, s->pagesz, NULL);
  }
  atomic_store_explicit(&s->ra_ix_us, st_now_us() - t0, memory_order_relaxed);
}
static void *ra_main(void *arg) {
  store_t *s = arg;
  uint64_t t0 = st_now_us();
  const uint64_t want = (VG(s, V_HWM) * ST_REC + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1);
  /* zt and zc: a lookup reads the record of a zone in both (zc by every lookup and attach: the cell with the counters), and a page that is not in memory is a wait for the disk on the thread
   * that asks (a worker's lookup, a store thread's attach) */
  const struct { const uint8_t *base; uint64_t mapped; } tab[2] = { { s->zt.base, atomic_load_explicit(&s->zt.mapped, memory_order_acquire) },
                                                                    { s->zc.base, atomic_load_explicit(&s->zc.mapped, memory_order_acquire) } };
  for (int i = 0; i < 2; i++) {
    uint64_t bytes = want < tab[i].mapped ? want : tab[i].mapped;
    if (!bytes || !tab[i].base) continue;
    (void)madvise((void *)(uintptr_t)tab[i].base, (size_t)bytes, MADV_WILLNEED);
    touch_pages(tab[i].base, (size_t)bytes, s->pagesz, &s->ra_stop);
  }
  atomic_store_explicit(&s->ra_zt_us, st_now_us() - t0, memory_order_relaxed);
  atomic_store_explicit(&s->ra_done, true, memory_order_release);
  return NULL;
}
/* the read-ahead thread is detached (a store that is never closed, a test child that dies, leaves no thread to join); the close waits for its end flag, after which the thread touches nothing of the store.
 * It does not give up: the thread reads the mapping that store_close() unmaps and the store that it frees, and it looks at the stop flag at every page, so the wait is one page read long. */
static void ra_stop_join(store_t *s) {
  if (!s->ra_started) return;
  atomic_store_explicit(&s->ra_stop, true, memory_order_relaxed);
  while (!atomic_load_explicit(&s->ra_done, memory_order_acquire)) usleep(100);
  s->ra_started = false;
}

/* ZFS: a segment is read in records of the dataset's record size; with the default of 128 KiB every attach would read and decompress 128 KiB for a zone of about a kilobyte (S0 Z1:
 * 50 us from the ARC against 6-10 us at 8 / 16 KiB).  st_blksize of a table file is the record size there. */
static void fs_open_checks(store_t *s) {
  /* 0.7 attach-align: the record size of the dataset (statfs f_iosize on ZFS; st_blksize of a file smaller than a record is the file's size), for seg_align_pos(): COPY mode on ZFS only (MAP and UFS read pages) */
  {
    uint32_t rs = 0;
    const uint32_t forced = atomic_load_explicit(&store_test_align_rs, memory_order_relaxed);
    struct statfs sfs;
    if (forced) rs = forced == UINT32_MAX ? 0 : forced;
    else if (strcmp(s->fstype, "zfs") == 0 && s->mode == STORE_MODE_COPY && fstatfs(s->dirfd, &sfs) == 0 && sfs.f_iosize >= 4096 && sfs.f_iosize <= (1 << 20) &&
             (sfs.f_iosize & (sfs.f_iosize - 1)) == 0)
      rs = (uint32_t)sfs.f_iosize;
    if ((uint64_t)rs * 16 > s->seg_size) rs = 0;                  /* (a record that is a large part of a segment: aligning would only end segments early) */
    s->align_rs = rs;
  }
  struct stat st;
  if (s->zt.fd < 0 || fstat(s->zt.fd, &st) != 0) return;
  atomic_store_explicit(&s->fs_blksize, (uint32_t)st.st_blksize, memory_order_relaxed);
  if (strcmp(s->fstype, "zfs") == 0 && st.st_blksize > 32768) {
    atomic_store_explicit(&s->fs_rec_warn, 1, memory_order_relaxed);
    st_log(s, 4, "store: the store is on ZFS with a record size of %" PRIu64 " bytes (st_blksize): a zone image is about a kilobyte, and every read of one reads and decompresses a whole record "
                 "(about 50 us from the ARC at 128 KiB against 6 to 10 us at 16 KiB, and the ARC keeps more of the neighbours' bytes than of the zone); set recordsize=16K (and compression=lz4, atime=off) "
                 "on the dataset of the store (`zfs set recordsize=16K <dataset>`); it applies to files written afterwards, so the segments that exist keep the old size until the store is copied "
                 "(stop the server and `cp -R` it, or `zfs send | zfs recv`)", (uint64_t)st.st_blksize);
  }
}

/* ---- the flusher (0.7 fix A): two threads, so that a long flush of the tables does not stop the commits ----
 * fl_commit_main(): the periodic commit (STORE_SYNC_BATCH: when a record waited sync_interval_ms; STORE_SYNC_EVERY: what the cleaner and the scrub left).  fl_ckpt_main(): the
 * checkpoints (journal size, checkpoint_interval_ms, after a growth) and the ones a writer began when it found the journal full (ck_handoff), then the housekeeping of the writer
 * mutex (ck_after()).  Neither holds a lock while it waits for the disk. */
static void bg_wait_ms(store_t *s, uint64_t ms) {           /* (bg_mu held) */
  if (s->bg_kick || s->bg_stop || s->ck_handoff) return;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ts.tv_sec += (time_t)(ms / 1000u);
  ts.tv_nsec += (long)(ms % 1000u) * 1000000L;
  if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
  (void)pthread_cond_timedwait(&s->bg_cv, &s->bg_mu, &ts);
}
static void bg_backoff(store_t *s, uint64_t ms) {           /* (bg_mu held) after a failed sync: the next try after `ms`, whatever wakes the thread meanwhile */
  const uint64_t until = st_now_ms() + ms;
  for (uint64_t now = st_now_ms(); now < until && !s->bg_stop && !s->ck_handoff; now = st_now_ms()) {
    s->bg_kick = false;
    bg_wait_ms(s, until - now);
  }
}
/* the blocks of the next growth of zt, zc and nx, allocated outside the writer mutex (zones: also room for that many records, store_reserve()) */
static void tables_ahead(store_t *s, uint64_t zones) {
  const uint64_t hwm = VG(s, V_HWM), need = zones * ST_REC;
  mtab_ahead(s, &s->zt, hwm * ST_REC, need);
  mtab_ahead(s, &s->zc, hwm * ST_REC, need);
  mtab_ahead(s, &s->nx, VG(s, V_NX_USED), 0);
}
/* The commit thread.  It is also the background leader of the journal ring (0.7): the records of threads that do not wait for them (store_defer()) are written by it within
 * about a millisecond while it is not in a commit's sync (fl_ckpt_main() writes them too, at the rule-T waits of a checkpoint), and in JW_NOSPACE it alone tries the write
 * again (jw_retry(), 100 ms to 1 s apart, outside any commit and without the baton: every other wait fails at once meanwhile).  The state's log line is said from here once a minute. */
static void *fl_commit_main(void *arg) {
  store_t *s = arg;
  uint64_t retry_ms = 100, next_retry = 0;
  pthread_mutex_lock(&s->bg_mu);
  while (!s->bg_stop) {
#ifdef KARIDNS_UNIT_TEST
    atomic_fetch_add_explicit(&store_test_fl_loops, 1, memory_order_relaxed);
#endif
    /* (the wait of each state: no commit is made in JW_NOSPACE and JW_FAILED, so the "a record waits for its commit" rule of JW_OK must not make the loop spin there) */
    const int jst = atomic_load_explicit(&s->jw_state, memory_order_acquire);
    const uint64_t now = st_now_ms();
    uint64_t wait;
    if (jst == JW_NOSPACE) {
      wait = next_retry > now ? next_retry - now : 0;
      if (wait > 20) wait = 20;
    } else if (jst == JW_FAILED) {
      wait = 1000;                                       /* (only the log line once a minute is left to do) */
    } else {
      wait = s->o.sync_policy == STORE_SYNC_BATCH ? s->o.sync_interval_ms : 1000u;
      const uint64_t last = atomic_load_explicit(&s->last_sync_ms, memory_order_relaxed);
      if (s->o.sync_policy == STORE_SYNC_BATCH && atomic_load_explicit(&s->lsn, memory_order_relaxed) > atomic_load_explicit(&s->committed_lsn, memory_order_relaxed))
        wait = now - last >= s->o.sync_interval_ms ? 0 : s->o.sync_interval_ms - (now - last);     /* (a record waits: commit when it is due, not a whole interval later) */
      if (wait > 1 && atomic_load_explicit(&s->jr_pub, memory_order_acquire) > atomic_load_explicit(&s->jr_tail, memory_order_acquire)) wait = 1;   /* (the background leader) */
    }
    if (wait) bg_wait_ms(s, wait);
    s->bg_kick = false;
    if (s->bg_stop) break;
    pthread_mutex_unlock(&s->bg_mu);
    int r = 0;
    const int st = atomic_load_explicit(&s->jw_state, memory_order_acquire);
    if (st == JW_NOSPACE) {
      const uint64_t now = st_now_ms();
      if (now >= next_retry) {
        jw_retry(s);
        retry_ms = atomic_load_explicit(&s->jw_state, memory_order_acquire) == JW_NOSPACE ? (retry_ms * 2 > 1000 ? 1000 : retry_ms * 2) : 100;
        next_retry = st_now_ms() + retry_ms;
      }
    } else if (st == JW_FAILED) {
      jw_log_state(s, st, atomic_load_explicit(&s->jw_last_err, memory_order_relaxed));
    } else {
      retry_ms = 100;
      atomic_store_explicit(&s->jw_kick, false, memory_order_release);
      if (atomic_load_explicit(&s->jr_pub, memory_order_acquire) > atomic_load_explicit(&s->jr_tail, memory_order_acquire))
        (void)jw_wait(s, atomic_load_explicit(&s->jr_pub, memory_order_acquire), &s->bg_stop_a);
      if (commit_due(s, st_now_ms())) r = st_commit(s, atomic_load_explicit(&s->lsn, memory_order_acquire));
    }
    ahead_kick(&s->ah_tab, &s->n_ah_busy_kicks);          /* (the blocks of the tables: another thread's work, since round 15; this thread never waits for an allocation) */
    pthread_mutex_lock(&s->bg_mu);
    if (r < 0) bg_backoff(s, s->o.sync_interval_ms > 1000u ? s->o.sync_interval_ms : 1000u);
  }
  pthread_mutex_unlock(&s->bg_mu);
  return NULL;
}
/* The thread of the blocks ahead (0.7 round 15).  A posix_fallocate() of the table files waited 0.5 to 11.3 s on UFS (the vnode lock that a checkpoint's fsync() of the table holds, a slow
 * disk) and stood in the commit thread, which makes the periodic commits and leads the journal ring for the deferred records.  It is here now, on its own: when it lags nothing waits for it.  The
 * growth of a table (mtab_grow(), inside the writer mutex) is a mapping and a check of the free space, the blocks are not needed for it; what is not allocated yet the checkpoint allocates when it
 * extends the file to the size of its position (ck_write_tab(): a delay of the checkpoint, which has its own thread, and the same ENOSPC / EIO handling as for any growth), so a lagging thread costs the
 * early warning of a full disk and a longer checkpoint, never a wrong answer (store.ahead.unallocated_growths counts the growths that found the blocks missing). */
static void *fl_tab_main(void *arg) {
  store_t *s = arg;
  while (ahead_wait(&s->ah_tab, 1000, NULL)) {
    const uint64_t t0 = st_now_us();
    tables_ahead(s, 0);
    const uint64_t us = st_now_us() - t0;
    if (us > atomic_load_explicit(&s->n_ah_thread_max_us, memory_order_relaxed)) atomic_store_explicit(&s->n_ah_thread_max_us, us, memory_order_relaxed);        /* (this thread only) */
  }
  return NULL;
}
/* The thread of the segment ahead (0.7 round 15): when the open segment is half full, the file of the next one is made here, outside the writer mutex (it was made inside it: openat(O_CREAT | O_TRUNC), a
 * pwrite and an ftruncate to 256 MiB cost 0.36 and 0.87 s there, with the records lock and the lock of the image writers held).  seg_place() takes it: no file is made inside the mutex.  When none is ready
 * (the first segment, a fill faster than the disk, a failure) seg_place() makes the file itself as before: store.segment.inline_creates.
 *
 * Durability (rules F, N4, the same argument as for the journal files made ahead, ck_precreate()): a directory entry is durable before any durable record names it.  The file is made, the header is
 * written and (MAP mode) the file is given its size here; then dir_dirty is set, and only then the file is published (PRE_READY).  The first record that names the segment (an image appended to it, the
 * journal record with its counters) is written after seg_place() took it, so after dir_dirty was set.  A commit that makes that journal record durable took dir_dirty under the writer mutex after the
 * record's LSN: it finds the flag set, or an earlier commit took it, and the commits go one at a time (the baton): that one's fsync() of the directory is over before this one's fsync() of the journal
 * (commit_sync(): segments, directory, journal), and a failed one sets the flag again.  So the directory entry is synced before the journal record that names the file can be durable, as it was when the
 * file was made inside the mutex; the entry may be durable much earlier, which does no harm.  The segment's bytes are synced by the same commit (seg_dirty, set at the first append) before the directory.
 *
 * The number: the lowest free one that seg_place() would take, and only when it is safe to truncate the old file of that number: no removal waits for the journal (seg_draining, N8), and the record that freed it
 * is durable (seg_free_lsn <= committed_lsn: a power loss must not leave counters that still name a segment whose file was made empty).  Chosen under the writer mutex (no I/O), so that a removal cannot
 * unlink the new file, which a removal in state (3) would do with the name; the file is made with the mutex released.  Crash: the file is never named by a counter until seg_place() took it, so a replay
 * never opens it (seg_get() is only called for the numbers the counters name); it stays as an empty file that the next making of that number truncates (seg_file_new()), or that a close removes. */
static void seg_pre_drop(store_t *s);
static void seg_pre_make(store_t *s, bool asked) {
  if (atomic_load_explicit(&s->pre_state, memory_order_relaxed) == PRE_STALE) seg_pre_drop(s);
  if (atomic_load_explicit(&s->pre_state, memory_order_relaxed) != PRE_NONE) return;
  uint32_t cur = (uint32_t)VG(s, V_CUR_SEG);
  if (cur == 0 || (!asked && VG(s, V_SEG(cur, 0)) < s->seg_size / 2)) return;       /* (asked: the writer that crossed the half has not made its counters real yet; a timed round looks at them) */
  uint32_t n = 0;
  wr_lock_raw(s);
  cur = (uint32_t)VG(s, V_CUR_SEG);
  if (cur != 0 && (asked || VG(s, V_SEG(cur, 0)) >= s->seg_size / 2) && atomic_load_explicit(&s->pre_state, memory_order_relaxed) == PRE_NONE) {
    const uint32_t nsegs = (uint32_t)VG(s, V_NSEGS);
    bool found = false;
    for (uint32_t i = 1; i <= nsegs && i <= ST_MAXSEG; i++) {
      if (VG(s, V_SEG(i, 0)) != 0) continue;
      found = true;
      if (s->seg_draining[i] == 0 && atomic_load_explicit(&s->committed_lsn, memory_order_acquire) >= s->seg_free_lsn[i]) n = i;
      break;
    }
    if (!found && nsegs < ST_MAXSEG) n = nsegs + 1;
    if (n) {
      pthread_mutex_lock(&s->pre_mu);
      atomic_store_explicit(&s->pre_state, PRE_BUSY, memory_order_relaxed);
      s->pre_n = n;
      pthread_mutex_unlock(&s->pre_mu);
    }
  }
  wr_unlock_raw(s);
  if (!n) return;
  const uint64_t t0 = st_now_us();
  AHEAD_HOOK(s, 2);
  seg_t *g = NULL;
  const int fd = seg_file_new(s, n, s->seg_size);
  if (fd >= 0) {
    CRASH_POINT();
    g = seg_wrap(s, fd, n, (size_t)((s->seg_size + s->pagesz - 1) & ~((uint64_t)s->pagesz - 1)));
    if (!g) close(fd);
  }
  if (!g) {                                            /* (a full disk, an I/O error, no memory: the writer makes the file itself and meets the error with its own state handling) */
    atomic_fetch_add_explicit(&s->n_seg_pre_err, 1, memory_order_relaxed);
    pthread_mutex_lock(&s->pre_mu);
    atomic_store_explicit(&s->pre_state, PRE_NONE, memory_order_relaxed);
    pthread_mutex_unlock(&s->pre_mu);
    return;
  }
  atomic_store_explicit(&s->dir_dirty, true, memory_order_seq_cst);        /* (before the file is published: see above) */
  CRASH_POINT();
  const uint64_t us = st_now_us() - t0;
  atomic_fetch_add_explicit(&s->n_seg_pre_us, us, memory_order_relaxed);
  if (us > atomic_load_explicit(&s->n_seg_pre_max_us, memory_order_relaxed)) atomic_store_explicit(&s->n_seg_pre_max_us, us, memory_order_relaxed);       /* (this thread only) */
  pthread_mutex_lock(&s->pre_mu);
  s->pre_g = g;
  atomic_store_explicit(&s->pre_state, PRE_READY, memory_order_release);
  pthread_mutex_unlock(&s->pre_mu);
}
static void *fl_seg_main(void *arg) {
  store_t *s = arg;
  bool kicked = false;
  while (ahead_wait(&s->ah_seg, 1000, &kicked)) seg_pre_make(s, kicked);
  return NULL;
}
/* A segment made ahead and not used is removed (the store closes and the thread is gone, or the thread gives up a file made for a number that is not the next one): its number is free, nothing names the
 * file.  The number stays the thread's (STALE, not NONE) until the file is gone, so that no writer makes a file of that name meanwhile. */
static void seg_pre_drop(store_t *s) {
  pthread_mutex_lock(&s->pre_mu);
  const int st = atomic_load_explicit(&s->pre_state, memory_order_relaxed);
  seg_t *const g = s->pre_g;
  const uint32_t n = s->pre_n;
  s->pre_g = NULL;
  pthread_mutex_unlock(&s->pre_mu);
  if ((st != PRE_READY && st != PRE_STALE) || !g) return;
  seg_free(g);
  if (VG(s, V_SEG(n, 0)) == 0) {                       /* (a number that a counter names now is not ours: nothing does, but the file is not removed on a guess) */
    char name[32];
    snprintf(name, sizeof(name), "seg.%u", n);
    (void)unlinkat(s->dirfd, name, 0);
  }
  pthread_mutex_lock(&s->pre_mu);
  atomic_store_explicit(&s->pre_state, PRE_NONE, memory_order_relaxed);
  pthread_mutex_unlock(&s->pre_mu);
}
static void *fl_ckpt_main(void *arg) {
  store_t *s = arg;
  pthread_mutex_lock(&s->bg_mu);
  for (;;) {
    if (s->ck_handoff) {                               /* (a writer began it and holds its flags for it: finished even when the store stops) */
      s->ck_handoff = false;
      pthread_mutex_unlock(&s->bg_mu);
      if (ck_run(s) == 0) ck_after(s);
      pthread_mutex_lock(&s->bg_mu);
      continue;
    }
    if (s->bg_stop) break;
    bg_wait_ms(s, 1000);
    s->bg_kick = false;
    if (s->bg_stop || s->ck_handoff) continue;
    pthread_mutex_unlock(&s->bg_mu);
    int r = 0;
    if (ckpt_due(s, st_now_ms())) {
#ifdef KARIDNS_UNIT_TEST
      st_hook(&store_test_fl_ckpt_hook, 1);
#endif
      if ((r = st_ckpt(s, false, true)) == 0) ck_after(s);
#ifdef KARIDNS_UNIT_TEST
      st_hook(&store_test_fl_ckpt_hook, 2);
#endif
    }
    pthread_mutex_lock(&s->bg_mu);
    if (r < 0) bg_backoff(s, 1000);
  }
  pthread_mutex_unlock(&s->bg_mu);
  return NULL;
}
#define FL_THREADS 4
/* stop the first n flusher threads (the checkpoint thread, the commit thread, the thread of the blocks ahead, the thread of the segment ahead) and wait for them */
static void bg_stop_n(store_t *s, int n) {
  pthread_t *const thr[FL_THREADS] = { &s->fl_thr, &s->fl_thr2, &s->fl_thr3, &s->fl_thr4 };
  pthread_mutex_lock(&s->bg_mu);
  s->bg_stop = true;
  pthread_cond_broadcast(&s->bg_cv);
  pthread_mutex_unlock(&s->bg_mu);
  ahead_stop(&s->ah_tab);
  ahead_stop(&s->ah_seg);
  for (int i = 0; i < n; i++) pthread_join(*thr[i], NULL);
}
static void bg_start(store_t *s) {
  if (atomic_load_explicit(&store_test_no_flusher, memory_order_relaxed)) return;
  static void *(*const mains[FL_THREADS])(void *) = { fl_ckpt_main, fl_commit_main, fl_tab_main, fl_seg_main };
  pthread_t *const thr[FL_THREADS] = { &s->fl_thr, &s->fl_thr2, &s->fl_thr3, &s->fl_thr4 };
  int n = 0;
  while (n < FL_THREADS && pthread_create(thr[n], NULL, mains[n], s) == 0) n++;
  if (n < FL_THREADS) {                                /* (a thread could not be made: none runs, the writers make the due work) */
    bg_stop_n(s, n);
    s->bg_stop = false;
    s->ah_tab.stop = s->ah_seg.stop = false;
    return;
  }
  s->fl_on = true;
}
/* the store closes: the flusher ends (a fuzzy checkpoint it runs is left between two pieces of its flush: the clean checkpoint of the close that follows flushes everything, so a
 * close does not wait for the rest of one; the store_close() of a 10M-zone fill on ZFS ran over the Manager's stop timeout), a build of the index is dropped and waited for */
static void bg_stop_join(store_t *s) {
  atomic_store_explicit(&s->ck_cancel, true, memory_order_relaxed);
  atomic_store_explicit(&s->bg_stop_a, true, memory_order_relaxed);
  atomic_store_explicit(&s->df_off, true, memory_order_relaxed);      /* (no background leader after this: every call waits for its bytes) */
  atomic_store_explicit(&s->rg_stop, true, memory_order_relaxed);
  while (atomic_load_explicit(&s->rg_live, memory_order_acquire)) usleep(1000);
  if (!s->fl_on) return;
  bg_stop_n(s, FL_THREADS);
  s->fl_on = false;
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
  if (s->o.journal_max_bytes == 0) s->o.journal_max_bytes = 100ull << 20;
  s->seg_size = s->o.seg_size ? s->o.seg_size : (256ull << 20);
  if (s->seg_size < 65536) s->seg_size = 65536;
  s->pagesz = (size_t)sysconf(_SC_PAGESIZE);
  if (s->pagesz == 0 || s->pagesz > ST_HDR_PAGE || (s->pagesz & (s->pagesz - 1))) { free(s); return -EINVAL; }
  while ((1ull << s->pgshift) < s->pagesz) s->pgshift++;
  pthread_mutex_init(&s->wlock, NULL);
  pthread_mutex_init(&s->seg_mu, NULL);
  pthread_mutex_init(&s->sc_mu, NULL);
  pthread_mutex_init(&s->bad_mu, NULL);
  pthread_mutex_init(&s->bg_mu, NULL);
  pthread_mutex_init(&s->ap_mu, NULL);
  pthread_mutex_init(&s->jw_mu, NULL);
  pthread_mutex_init(&s->pre_mu, NULL);
  ahead_init(&s->ah_tab);
  ahead_init(&s->ah_seg);
  {
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);         /* (bg_wait_ms(), jw_wait()) */
    pthread_cond_init(&s->bg_cv, &ca);
    pthread_cond_init(&s->jw_cv, &ca);
    pthread_condattr_destroy(&ca);
  }
  s->jold = s->jnext_fd = -1;
  atomic_store_explicit(&s->avail_est, -1, memory_order_relaxed);
  s->reserve_bytes = s->o.reserve_bytes ? s->o.reserve_bytes : s->seg_size / 2;
  if (!s->o.reserve_bytes) {
    if (s->reserve_bytes < (256u << 10)) s->reserve_bytes = 256u << 10;
    if (s->reserve_bytes > (128ull << 20)) s->reserve_bytes = 128ull << 20;
  }
  s->jfd = -1;
  s->err_fd = -1;
  pthread_mutex_init(&s->err_mu, NULL);
  s->sb_fd[0] = s->sb_fd[1] = -1;
  s->zt.fd = s->zc.fd = s->nx.fd = -1;
  s->sbbuf = calloc(1, sizeof(sb_t));
  s->ck_buf = malloc(2 * ST_CK_RUN);                     /* (zt and zc are copied in lockstep: ck_write_cells()) */
  s->jb.p = malloc(4096);
  s->jb.cap = s->jb.p ? 4096 : 0;
  s->jx_cap = JX_CAP;
  s->jr_cap = JR_CAP_DEF;
#ifdef KARIDNS_UNIT_TEST
  if (atomic_load(&store_test_jr_cap)) s->jr_cap = atomic_load(&store_test_jr_cap);
  if (atomic_load(&store_test_jx_cap) >= 3 && atomic_load(&store_test_jx_cap) <= JX_CAP) s->jx_cap = atomic_load(&store_test_jx_cap);
#endif
  s->jr_buf = mmap(NULL, (size_t)s->jr_cap, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | ST_NOCORE, -1, 0);    /* (pages are touched as the ring is used) */
  if (s->jr_buf == MAP_FAILED) s->jr_buf = NULL;
  sb_t *cand[2] = { NULL, NULL };
  int r = 0;
  if (!s->sbbuf || !s->jb.p || !s->ck_buf || !s->jr_buf) { r = -ENOMEM; goto fail; }
  strcpy(s->fstype, "unknown");
#if defined(__FreeBSD__)
  struct statfs sfs;
  if (fstatfs(dirfd, &sfs) == 0) snprintf(s->fstype, sizeof(s->fstype), "%s", sfs.f_fstypename);
#endif
  atomic_store_explicit(&s->cow, strcmp(s->fstype, "zfs") == 0, memory_order_relaxed);    /* (a checkpoint's overwrites allocate: jr_floor()) */
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
      else if (st_resource_err(r)) break;      /* (no address space, memory or descriptors: the other copy would fail the same way, and the store is not damaged) */
    }
    if (used < 0) {
      if (st_resource_err(r)) {                /* (0.7: with ulimit -v the reservations of the tables failed and the open moved a valid store aside) */
        st_log(s, 3, "store: cannot open the store, the directory is left as it is: %s", strerror(-r));
        goto fail;
      }
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
    s->jrn_gone = jrn_low_scan(s, s->slot_jrn[0] < s->slot_jrn[1] ? s->slot_jrn[0] : s->slot_jrn[1]);
    uint64_t was_boot = cand[used]->f.boot_id;
    bool unclean = !s->rec.was_clean;
    bool anomaly = false;
    const uint32_t sbfl = cand[used]->f.flags;
    const bool sb_bulk = (sbfl & SBF_BULK) != 0, sb_bulk_ck = (sbfl & SBF_BULK_CK) != 0, cut = sb_bulk && unclean;
    if (cut) journal_skip(s, cand[used]->f.jrn_gen);    /* (THE BULK FILL, K: a fill that was cut off is not replayed) */
    else r = journal_replay(s, cand[used]->f.jrn_gen, &anomaly);
    if (r < 0) goto fail;
    /* the numbers of new generation files start above every one that a superblock or the journal named */
    s->ix_gen_next = s->ix_gen > s->slot_ix[0] ? s->ix_gen : s->slot_ix[0];
    if (s->slot_ix[1] > s->ix_gen_next) s->ix_gen_next = s->slot_ix[1];
    s->ix_gen_next++;
    s->sx_gen_next = s->sx_gen > s->slot_sx[0] ? s->sx_gen : s->slot_sx[0];
    if (s->slot_sx[1] > s->sx_gen_next) s->sx_gen_next = s->slot_sx[1];
    s->sx_gen_next++;
    /* same boot after an unclean stop: the page cache kept every cell and the replay is exact; another or an unknown boot (power
     * loss, OS crash): cells may be ahead of the journal, so the derived tables are rebuilt */
    bool rebuild = s->o.force_rebuild || anomaly || sb_bulk_ck || cut || (unclean && (s->boot_id == 0 || was_boot == 0 || was_boot != s->boot_id));
    if (rebuild) {
      wr_lock_raw(s);
      r = rebuild_locked(s, RB_OPEN | (cut ? RB_BULK : 0u));
      wr_unlock_raw(s);
      if (r < 0) goto fail;
    }
    if (sb_bulk) {                                    /* (the fill goes on: the open's checkpoint below says BULK, and the writers log nothing from the start) */
      atomic_store_explicit(&s->bulk, true, memory_order_relaxed);
      atomic_store_explicit(&s->bulk_body, true, memory_order_relaxed);
      atomic_store_explicit(&s->bulk_passed, !cut && (sbfl & SBF_BULK_PASSED) != 0, memory_order_relaxed);
      atomic_store_explicit(&s->bulk_since, (uint64_t)time(NULL), memory_order_relaxed);
      s->rec.bulk_resumed = true;
      s->rec.bulk_recovered = cut;
    }
    if (cut || (sbfl & SBF_BULK_CUT)) atomic_store_explicit(&s->bulk_cut, true, memory_order_relaxed);   /* (the cursors are to be dropped: kept on disk until the caller did it, store_bulk_cut_done()) */
    if (cut) {
      char when[40] = "?";
      const time_t ct = (time_t)cand[used]->f.ckpt_time;
      struct tm tmv;
      if (gmtime_r(&ct, &tmv)) strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S UTC", &tmv);
      st_log(s, 4, "store: a bulk fill was cut off: the store is back at %s (%s), %" PRIu64 " zones stored, %" PRIu64 " known (%" PRIu64 " of them had an image past the durable end of their segment), "
                   "%" PRIu64 " dropped; nothing was replayed, the zones after it are read from the database again; the fill goes on", when,
             sb_bulk_ck ? "its last bulk checkpoint" : "the start of the fill", VG(s, V_STORED), VG(s, V_KNOWN), s->rec.bulk_known, s->rec.dropped_zones);
    }
  }
  free(cand[0]);
  free(cand[1]);
  cand[0] = cand[1] = NULL;
  /* start the session: a new journal and a superblock with the clean flag cleared and this boot id, durable before the first
   * modification */
  wr_lock_ck(s);
  r = ck_full_locked(s, false);
  wr_unlock_ck(s);
  if (r < 0) goto fail;
  s->clean_on_disk = false;
  s->last_sync_ms = st_now_ms();
  s->last_ckpt_ms = st_now_ms();
  atomic_store_explicit(&s->bulk_base, st_seg_bytes(s), memory_order_relaxed);          /* (a fill that goes on: its next bulk checkpoint counts from here) */
  atomic_store_explicit(&s->bulk_last_ms, st_now_ms(), memory_order_relaxed);
  if (!atomic_load_explicit(&s->sc_last_done, memory_order_relaxed)) atomic_store_explicit(&s->sc_last_done, (uint64_t)time(NULL), memory_order_relaxed);      /* (a store from before the scrub: its first pass is one interval from now) */
  fs_open_checks(s);
  err_ring_open(s);
  fs_probe(s);
  ix_prefetch(s);
  if (!s->o.no_readahead && pthread_create(&s->ra_thr, NULL, ra_main, s) == 0) {
    pthread_detach(s->ra_thr);
    s->ra_started = true;
  } else {
    atomic_store_explicit(&s->ra_done, true, memory_order_release);
  }
  bg_start(s);                                        /* the flusher (0.7 fix A); without it the writers make the due commits and checkpoints after the mutex */
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
  pthread_mutex_destroy(&s->sc_mu);
  bad_free_all(s);
  pthread_mutex_destroy(&s->bad_mu);
  pthread_mutex_destroy(&s->err_mu);
  pthread_mutex_destroy(&s->bg_mu);
  pthread_mutex_destroy(&s->ap_mu);
  pthread_cond_destroy(&s->bg_cv);
  pthread_mutex_destroy(&s->jw_mu);
  pthread_cond_destroy(&s->jw_cv);
  pthread_mutex_destroy(&s->pre_mu);
  ahead_destroy(&s->ah_tab);
  ahead_destroy(&s->ah_seg);
  if (s->jr_buf) munmap(s->jr_buf, (size_t)s->jr_cap);
  free(s->sbbuf);
  free(s->jb.p);
  free(s->cl_buf);
  free(s->ck_buf);
  free(s);
  return r < 0 ? r : -EIO;
}

int store_close(store_t *s) {
  if (!s) return -EINVAL;
  ra_stop_join(s);
  bg_stop_join(s);
  seg_pre_drop(s);
  wr_lock_ck(s);
  int r = ck_full_locked(s, true);
  if (r < 0) st_log(s, 3, "store: clean checkpoint at close failed: %d", r);
  /* wait (bounded) for readers of retired generations; the caller has stopped them */
  uint64_t e = rcu_writer_advance_epoch();
  rcu_writer_wait_until_safe(e, 2000);
  retire_run(s, true);
  files_close(s);
  for (int i = 0; i < 2; i++) if (s->sb_fd[i] >= 0) close(s->sb_fd[i]);
  wr_unlock_ck(s);
  pthread_mutex_destroy(&s->wlock);
  pthread_mutex_destroy(&s->seg_mu);
  pthread_mutex_destroy(&s->sc_mu);
  bad_free_all(s);
  pthread_mutex_destroy(&s->bad_mu);
  pthread_mutex_destroy(&s->err_mu);
  pthread_mutex_destroy(&s->bg_mu);
  pthread_mutex_destroy(&s->ap_mu);
  pthread_cond_destroy(&s->bg_cv);
  pthread_mutex_destroy(&s->jw_mu);
  pthread_cond_destroy(&s->jw_cv);
  pthread_mutex_destroy(&s->pre_mu);
  ahead_destroy(&s->ah_tab);
  ahead_destroy(&s->ah_seg);
  if (s->jr_buf) munmap(s->jr_buf, (size_t)s->jr_cap);
  err_ring_close(s);
  for (unsigned k = 0; k < RG_NCH; k++) free(s->rg_ch[k]);
  free(s->sbbuf);
  free(s->jb.p);
  free(s->cl_buf);
  free(s->ck_buf);
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
    static const char *const pre[] = { "super.", "zt.", "zc.", "nx.", "ix.", "sx.", "seg.", "jrn.", "err." };
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

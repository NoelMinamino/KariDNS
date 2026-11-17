#ifndef DNS_DB_RECON_H
#define DNS_DB_RECON_H

/*
 * dns_db_recon.h - the reconcile thread of the Backend (0.7 M2).
 *
 * The loader lists the zones of a view (a pass: MANIFEST_BEGIN, pages of up to 16,384 entries, MANIFEST_END).  Decoding a page and recording its entries in the store was done by the thread that also
 * answers the fetches and the lookups of the queries, one entry at a time (about 16 us each: 160 s for ten million zones, and the thread was busy all the time).  Now the stream thread (the ingest
 * thread, dns_db_ingest.c) only checks that a page is legal in the state of the stream (kdb_sm_legal_frame(), dns_db_stream.h) and copies it into a ring of 8 slots; this thread decodes it, checks
 * it against the pass (kdb_man_t: the batch, the view, the page number, the sum at the end: the checks kdb_sm_accept() does for a page) and records the entries in groups of up to 32 (STORE_GROUP_MAX; db_recon_entry_n(),
 * dns_db_store.h: one journal record, one hold of the mutex of the writers of the records and one decision of the commit policy for a group).
 *
 * Order.  The ring is in the order of the stream and there is one consumer, so the pass is applied in the order the loader sent it: MANIFEST_BEGIN (db_recon_begin()), the pages, MANIFEST_END (the check of the
 * sum, db_recon_end(): the cursor, the sweep of the zones the pass did not list).  Every other frame of the stream (BATCH_END and its answer, the next BATCH_BEGIN, CHANGES, a delete, a profile ...) first
 * waits until this thread has applied everything before it (db_recon_idle()): the thread that reads the stream does not handle it before, and does not read the stream meanwhile (the loader waits on its socket;
 * the fetch stream is served all the time).  So whatever reads what the pass did (the counts of BATCH_RESULT, the log lines, the cursor, the sweep) sees the pass whole, and whatever changes the same records
 * (a CHANGES entry, a delete, the answer of a lookup, the commit of a fetched body) finds them as the entries before it left them.
 *
 * Back-pressure.  When the ring is full the stream thread does not read the stream (the loader's socket fills, the loader blocks in its write): nothing is dropped and nothing grows.  The memory is the ring:
 * 8 slots of KDB_MAX_BODY bytes, allocated at the start (the pages that are never used cost no memory).
 *
 * A loader that is hostile.  Every check the decode did on the stream thread is still made, here: a page that does not decode, one that is not the next page of the pass, a MANIFEST_END whose sum is not the sum
 * of the pages end the stream exactly as before (db_recon_error_take(): the stream thread logs the reason as any protocol error and closes the stream); nothing after the bad item is applied.  A stream that ends
 * (drop_stream()) discards what is in the ring that it sent (db_recon_abort_stream(): an epoch counter, no wait), and the pass that was cut off sweeps nothing (db_recon_abort()).
 *
 * Threads.  One producer (the ingest thread: the db_recon_post_*() functions, db_recon_room(), db_recon_idle(), db_recon_take(), db_recon_error_take()), one consumer (this thread).  No mutex: the ring is two
 * counters of C11 atomics (release / acquire), the wake-ups are kevent() EVFILT_USER events (the thread's own kqueue; the ingest thread's, ident given to db_recon_thread_start()).  Both kqueues exist before
 * cap_enter() (Capsicum rule 2: no new open, no socket).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_db_stream.h"

#define DBRT_SLOTS 8
#define DBRT_CHUNK 64                /* entries decoded and recorded at once: the group of db_recon_entry_n() */

/* what the entries of the pages (and of the ingest thread's own CHANGES) became: BATCH_RESULT's numbers and the totals of `karictl dbstatus` */
typedef struct {
  uint32_t applied, unchanged, rejected, deleted;
  uint64_t tot_applied, tot_rejected, tot_deleted;
  uint64_t zones;                    /* entries of the pages (kdb_sm_t.n_zones counts them for the BATCH_END check) */
  bool wanted;                       /* a body is wanted: the background fetch has work */
  bool failed;                       /* an entry could not be recorded: its cursor is not kept */
} dbrt_counts_t;

/* what an entry's result adds to c (the entry_note() of the ingest thread); true: a body is wanted.  *unstorable_logged: the "cannot be served" line was said (once per page or frame) */
bool db_recon_note(dbrt_counts_t *c, int result, const char *zone, bool *unstorable_logged);

/* start the thread.  notify_kq / notify_ident: the EVFILT_USER event it triggers on the ingest thread's kqueue when a slot is free, the ring is empty, a counter is there or the stream is to be closed.  false: the thread could not start. */
bool db_recon_thread_start(int notify_kq, uintptr_t notify_ident);

/* ---- the ingest thread ---- */
bool db_recon_room(void);            /* a slot is free (the one producer: it stays free until the producer posts) */
bool db_recon_idle(void);            /* everything posted is applied, and the abort of a stream that ended is done */
/* The posts need a free slot (db_recon_room()).  view_count: the number of views the stream's CONFIG has (the decode checks the view of a page against it).  vname: the name of the view of the pass, "" when
 * the configuration has none (the pass is read and checked, not applied) */
void db_recon_post_begin(uint64_t batch_id, uint16_t view, uint32_t view_count, const char *vname, uint64_t count, bool force);
void db_recon_post_page(const uint8_t *body, uint32_t len, uint32_t view_count);
void db_recon_post_end(const kdb_manifest_end_t *e);
/* the stream ended: what the ring holds and what this thread has not done of it is dropped, a pass that was open is forgotten (nothing is swept).  Does not wait: db_recon_idle() says when it is done. */
void db_recon_abort_stream(void);
/* the thread found a protocol error in what the loader sent (the reason, without bytes of the stream, in why): true once; the caller closes the stream (and the rest of the ring is dropped) */
bool db_recon_error_take(char *why, size_t cap);
/* the counts of the batch the thread has collected since the last call (the ingest thread adds them to the batch's; the totals of tot_* are in db_recon_totals()).  Only when db_recon_idle() is true: a stream that ended
 * leaves nothing in them then, and nothing is added while they are read. */
void db_recon_take(dbrt_counts_t *out);
/* some entries want a body (the background fetch has work): true once */
bool db_recon_wanted_take(void);
/* the totals since the start of the entries recorded, refused and the zones the sweeps deleted (any time) */
void db_recon_totals(uint64_t *applied, uint64_t *rejected, uint64_t *deleted);
void db_recon_note_full(void);       /* the stream thread stopped reading because the ring was full (a counter) */
/* the longest pass of the ingest thread's loop (the time from the wake to the end of the pass: events, the streams, the fetches), in the window of ten seconds that is open and the one before */
void db_recon_note_loop(int64_t ns);
/* ... and of one read of the stream (the frames of the first stream: a page is a copy, the frame that waited for the thread, BATCH_END with the commit of the store) */
void db_recon_note_stream(int64_t ns);

#endif /* DNS_DB_RECON_H */

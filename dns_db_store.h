#ifndef DNS_DB_STORE_H
#define DNS_DB_STORE_H

#include "dns_mem_advice.h"

/*
 * dns_db_store - the zone store in the server (0.7 store S2 and S3; design: planning/planing_0.7.x_store_10m_design.md sections 2.1, 2.2, 3.4, 4.1, 4.2).
 *
 * dns_store.c is the store itself (files, index, journal).  This module is what the server does with it:
 *
 *   - The directory.  The process that starts the server (the "Frontend" side of the privilege separation: it runs as root and has not forked the
 *     Backend yet) opens or makes the store directory, checks who owns it and who can write to it, takes an exclusive lock on it (one server per
 *     store) and hands the descriptor to the Backend by fork().  The Backend limits the rights of the descriptor (cap_rights_limit()) and the
 *     store opens its files beneath it (openat(), also in capability mode).  `database { store "<dir>" | none; }` names the directory; without it
 *     the default /var/db/karidns/store is used when /var/db/karidns exists (and the server runs without a store, as before, when it does not or
 *     cannot use it); an explicit directory that cannot be used refuses the start.
 *
 *   - S3: the store is the directory of the database zones.  db_store_start() installs the operations of g_dbdir (dns_server_internal.h): the lookup of
 *     the query path asks the store's name index at every suffix after the heap directory, a zone that is in memory (attached) has a registry element that
 *     the attach table of this module reaches by the zone id, a zone that is not in memory costs no heap at all.  What the registry asks of the store (a
 *     zone's record, its put and delete, the settings by id) is here too.  Without a store (`store none;`, the directory unusable, the store cannot be
 *     opened) g_dbdir stays NULL and every database zone is a zone of the heap directory, as before 0.7.
 *
 *   - Write-through.  The install of a zone (the ingest thread: dbreg_commit()) copies the version into the store before the zone is registered
 *     (dbdir_ops_t.put): the record's zid is the zone's id in the attach table.  A zone that the database deletes is deleted from the store with its element.
 *
 *   - Attach.  A query for a zone whose record is stored and that is not in memory is not fetched from the loader: the worker parks it with the attach deadline
 *     (200 ms) and asks the store threads; a store thread reads the image (MAP: a pointer into the mapped segment; COPY: a buffer), checks it (the store's
 *     checksum, the whole structure: zone_image_validate(), at every attach - the checksum is not keyed and detects damage, not a forgery; the apex name),
 *     makes the entry like an install does (zone_install_version(), dbreg_attach_store(): the element and the commit in one section of the registry's lock) and wakes the
 *     parked queries.  A record that is missing, stale or damaged falls back to the fetch (the queries that wait are given the park-timeout again).  The version
 *     of an attached zone counts for memory-limit with its image: the mapped bytes (MAP) or the buffer (COPY), the same number when the version is counted and when it
 *     is given back.  Detaching is the eviction of the cache manager (the record stays in the store); a MAP version keeps its segment mapped until the version is
 *     freed, after its grace period (zone_version_free() -> image_free()).
 *
 *   - Settings.  The interned settings text of a zone (its allow-query, allow-transfer, ... ) gets an id that the record names; the texts are in settings.dat
 *     in the store's directory, so that a zone that is not in memory can be answered and attached with the loader stopped.
 *
 * Threads: one ticker (the store's group commit and checkpoint), `store-threads` attach threads, and whoever calls the functions below (the ingest threads write,
 * the workers look).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "dns_config_parser.h"
#include "dns_store.h"
#include "dns_store_status.h"


/* ---- the directory (the process that forks the Backend) ---- */

/* Open (make) the store directory the configuration names, before the Backend is forked.  privileged: the process is root; uid / gid: the user the server will
 * run as (the directory is handed to it; -1 = no change).  true: the start goes on, with the store (db_store_dir_fd() >= 0) or without (off by configuration, the
 * default directory is not usable: msg then says why, for the log); false: the directory the configuration names cannot be used (msg says why): refuse the start.
 * A configuration without a database block does nothing. */
bool db_store_frontend_open(const database_config_t *db, bool privileged, uid_t uid, gid_t gid, char *msg, size_t msglen);
/* the descriptor of the store directory (-1: no store); closed by db_store_frontend_close() in the process that does not use it (the manager after the fork) */
int db_store_dir_fd(void);
void db_store_frontend_close(void);
/* the directory of the configuration with the default applied; NULL: `store none;` */
const char *db_store_dir_of(const database_config_t *db, bool *is_default);
/* 0.7 (secondary store D1, 10): the same for the whole configuration: the database block's store, else options { zone-store }, else the default for a server with a database block or
 * at least one secondary zone.  *soft: a directory that cannot be used is an ERROR and a start without the store (no database block), not a refused start */
const char *db_store_dir_cfg(const server_config_t *cfg, bool *is_default, bool *soft);
/* will the start open a store (the default directory only when its parent exists and KARIDNS_NO_DEFAULT_STORE is not 1)?  The supervisor asks before the initial load */
bool db_store_wanted(const server_config_t *cfg);
/* db_store_frontend_open() for the whole configuration (db_store_dir_cfg()); *level: the syslog level of msg (LOG_ERR for a soft failure, the start goes on) */
bool db_store_frontend_open_cfg(const server_config_t *cfg, bool privileged, uid_t uid, gid_t gid, char *msg, size_t msglen, int *level);

/* ---- the Backend ---- */

/* Open the store on the descriptor the process inherited, make the views, check that the store belongs to the configured databases, start the threads.  Before
 * enter_capsicum_sandbox().  true: running with the store, or without one (no directory handed over; a store that cannot be opened is logged and not used: the zones are
 * read from the database as before).  false: out of memory or a thread that does not start. */
bool db_store_start(const server_config_t *cfg);    /* (0.7: also without a database block: the core of the store for the secondaries' copies, dns_xfr_store.h) */
/* Stop the threads after they have done what is queued, checkpoint the store.  The Backend calls it at its end; the store stays open (workers may still look). */
void db_store_stop(void);
bool db_store_enabled(void);
/* 0.7 fix 8: start the background attach of the zones of hot.list (read by db_store_start(): the zones that were in memory at the last clean stop, the most used first).  The server calls it when it serves;
 * the thread waits for the attach requests of queries, takes at most 20,000 zones a second and stops at the high mark of memory-limit.  db_store_stop() ends it and writes the list of the zones in memory. */
void db_store_hot_start(void);
store_t *db_store_handle(void);
/* 0.7: the bound of the store's journal (store_journal_wait()), for a thread that holds none of this module's locks: the reconcile thread between the groups of a pass
 * (factor 2), the ingest thread once per pass of its loop (factor 4: it also answers the lookups, so it waits only where the bulk writer did not keep the journal down).
 * The microseconds waited (0: none, no store). */
uint64_t db_store_journal_wait(unsigned factor);

/* ---- the ingest threads ---- */

/* a batch ended: what it wrote to the store is made durable (group commit) */
int  db_store_batch_end(void);         /* (the commit's result: 0, or -errno; 0.7: it is also the acknowledgement of the deferred calls of the ingest and the reconcile threads) */
/* 0.7: this thread's store calls do not wait for their journal record (the ingest and the reconcile thread; off before the thread ends) */
void db_store_defer_thread(bool on);

/* ---- 0.7 WP7b: the loader's manifest and change entries against the store (the ingest thread; store design 5.3, 5.4) ----
 *
 * The loader keeps no table of the zones; it lists them (a pass: MANIFEST_BEGIN, pages, MANIFEST_END) or says which changed (CHANGES).  What the Backend does with an entry:
 *   - a zone it does not know: a record in the state KNOWN (the name index is complete after the pass; the body is fetched in the background, or when a query asks for it);
 *   - a zone whose version stamp (generation, changed_at of karidns_zone_state; the serial for a source without stamps; a zone without a state row is always asked for) is not the
 *     record's: the stamp is recorded and the record is marked STORE_F_STALE (its image keeps serving until the new body is installed); a zone the record has no image for stays KNOWN;
 *   - the same stamp: nothing.  A version that was refused (STORE_F_REJECTED_NEW) with this stamp is not asked for again;
 *   - a zone whose id has another name (a rename) loses the old name; a name that another id holds is taken over;
 *   - a zone whose name the store cannot hold (the root zone) has no record: the Backend remembers it in a small list of its own (db_recon_apply()), fetches it like a
 *     secondary zone and serves it from the heap directory; it is logged once (NOTICE), counted (nonstore), and while a view has one its cursor is not kept (the next start lists the zones again);
 *   - a secondary or catalog zone is a KNOWN record with STORE_F_NONSTORE: it is a zone of the heap directory (never stored, never found by a query), and the record only makes the next
 *     start load it again.
 * A pass marks one bit per zone id; at its end (complete) the zones of the view that the pass did not list are deleted (the sweep), unless that would delete more than 20 percent of the
 * view's zones and more than 1,000 (decision D7, the mass-delete guard): then nothing is deleted, ERROR is logged and `karictl reload -force` (a pass that the operator asked for) deletes them.
 * The cursor and the identity of the database are kept in the superblock per view: the first 8 bytes of the identity are the hash of the view's configuration (the store was not filled from
 * another database), the rest is the loader's own identity. */
typedef struct {
  int64_t source_id;
  const char *name;              /* canonical, with the trailing dot */
  uint8_t kind;                  /* KDB_ZK_* (0 primary) */
  bool stamped;                  /* the stamp is real (the zone has a karidns_zone_state row) */
  uint64_t gen, time;
  bool has_serial;               /* a source without stamps: the SOA serial */
  uint32_t serial;
  bool force;                    /* the body is wanted whatever the stamp says (a reload of the zone) */
} db_recon_entry_t;
/* the result of an entry */
enum { DBR_UNSTORABLE = -2 /* a name the store cannot hold and the heap directory cannot key either (over 255 bytes of text, which only escapes make): the zone is not loaded */, DBR_ERROR = -1, DBR_SAME = 0, DBR_NEW, DBR_CHANGED, DBR_RENAMED, DBR_PENDING /* already asked for, not here yet */, DBR_KEPT /* refused with this stamp: not asked for again */ };
/* apply one entry (a pass entry also sets the zone's bit); *zid receives the record's zone id (STORE_NONE: none); the view's name as the registry knows it */
int db_recon_apply(const char *view, const db_recon_entry_t *e, uint32_t *zid);
/* a CHANGES upsert: db_recon_apply() and the count */
int db_recon_change(const char *view, const db_recon_entry_t *e, uint32_t *zid);
/* the answer of a by-name lookup (the ingest thread): as db_recon_change(), and the record is marked for the pass that is going on: it is newer than the page the loader read before, so an entry of the pass does not change it and the sweep does not delete it (dns_db_store.c, lk_mark()) */
int db_recon_lookup(const char *view, const db_recon_entry_t *e, uint32_t *zid);
/* 0.7 M2: n entries (any n) as n calls of db_recon_apply() / db_recon_change() / db_recon_entry(), in order: res[i] and zid[i] are what the call for entry i returns (res: DBR_*) and gives back.  The records that
 * are new are written in groups of up to 32 (STORE_GROUP_MAX), one journal record, one hold of the mutex of the writers of the records and one decision of the commit policy for a group (store_set_known_n()); an entry
 * of a record that exists, a rename or an entry that has the name or the source id of one that waits in the group writes the group first, so the effect is that of the calls one after the other.  The
 * counters of a pass are counted once per call. */
void db_recon_apply_n(const char *view, const db_recon_entry_t *e, size_t n, int *res, uint32_t *zid);
void db_recon_change_n(const char *view, const db_recon_entry_t *e, size_t n, int *res, uint32_t *zid);
void db_recon_entry_n(const db_recon_entry_t *e, size_t n, int *res, uint32_t *zid);
/* a pass over one view's source: false (why says why) when the store has no room for the view; force: the operator asked for this pass (the guard does not hold it back) */
bool db_recon_begin(const char *view, uint64_t estimate, bool force, char *why, size_t whylen);
/* one entry of the pass */
int db_recon_entry(const db_recon_entry_t *e, uint32_t *zid);
typedef struct { bool swept, held, failed; uint64_t total, unlisted, deleted; uint64_t duration_ms; } db_recon_end_t;
/* MANIFEST_END.  complete: every page was sent (else nothing is swept and no cursor is kept).  The cursor and the identity are made durable, not when the guard holds the sweep back (the view's cursor is made invalid then, so
 * that a restart makes a pass again and holds again), and not when an entry of the pass could not be recorded or a delete of the sweep failed (out->failed: nothing, or not everything, was swept) */
void db_recon_end(bool complete, uint64_t n_skipped, bool cursor_valid, uint64_t cursor, const uint8_t *ident, size_t ident_len, db_recon_end_t *out);
/* the stream ended in the middle of a pass: forget it (no sweep) */
void db_recon_abort(void);
/* a CHANGES delete: the zone of the source id (or of the name, when the loader has it) is deleted; 1 when something was deleted, 0 when there was nothing to delete, -1 when the store could not delete it (the zone stays: the caller does not keep its cursor, so that the delete is made again) */
int db_recon_delete(const char *view, int64_t source_id, const char *name);
/* the cursor of a view: false when the store has none for the loader (a first fill).  ident: STORE_IDENT_MAX bytes */
bool db_recon_cursor_get(const char *view, uint64_t *cursor, uint8_t *ident, size_t *ident_len);
/* make the cursor durable (the entries it covers are recorded); a view whose guard holds a sweep back keeps no cursor (db_recon_end() made it invalid), so that a restart makes a pass again */
void db_recon_cursor_put(const char *view, uint64_t cursor, const uint8_t *ident, size_t ident_len);
/* a zone whose body is wanted (the background fetch): the records KNOWN or STALE that were not refused, the secondary and catalog records once per run.  *cursor: the zone id to continue at;
 * budget: how many zones to look at.  1: an item; 0: the end of the store (cursor at the end); 2: the budget is used up without an item */
typedef struct { char view[STORE_VIEW_NAME_MAX + 1]; char zone[STORE_NAME_MAX + 2]; int64_t source_id; uint32_t zid; bool nonstore; uint64_t stamp_gen, stamp_time; } db_scan_item_t;
int db_recon_scan(uint32_t *cursor, unsigned budget, db_scan_item_t *out);
/* the fetch of a secondary or catalog zone failed: it is wanted again at the next pass of the scan */
void db_recon_scan_retry(uint32_t zid);
/* the figures of the reconcile (karictl store / dbstatus) */
typedef store_recon_t db_recon_status_t;        /* (dns_store_status.h: the report asks for it through a function) */
void db_recon_status(db_recon_status_t *out);
void db_recon_note_fetch(int what, uint64_t n);   /* DBR_FETCHED, DBR_FETCH_FAILED, DBR_IN_FLIGHT (a gauge) */
/* the reconcile thread (dns_db_recon.c) adds its own figures (store.recon.busy_pct ...) to what db_recon_status() gives; NULL: none */
void db_recon_set_status_fn(void (*fn)(db_recon_status_t *out));
enum { DBR_FETCHED = 0, DBR_FETCH_FAILED, DBR_IN_FLIGHT };

/* ---- a fetched body is installed only for the stamp it was asked for ----
 *
 * The ingest thread (a CHANGES entry, a manifest entry, a delete, the sweep of a pass) and the builder threads (the install of a body) both write the record of a zone.  The body of a fetch is for the
 * stamp the record had when the request was made; a record that has another stamp now (the database changed the zone again: the zone is wanted again) or none (the zone was deleted) must take nothing
 * from it, and the check and the install may not have a writer of the stamp between them (the version that is put gets the record's stamp: an old body would be installed under the newer stamp, and a
 * deleted zone would come back).  Every writer of a record's stamp or existence holds one mutex for its step; the commit of a fetched body holds it from the check to the end of the install. */
typedef struct { uint64_t gen, time; } db_stamp_t;
/* the stamp of the Backend's entry for the zone (the store's record, or the entry of a zone the store cannot name); *sid (may be NULL): its domain id.  false: there is no such entry (an unknown or deleted zone) */
bool db_store_zone_stamp(const char *view, const char *zone, db_stamp_t *out, int64_t *sid);
enum { DBC_OK = 0, DBC_STALE /* the entry has another stamp than the body was asked for */, DBC_GONE /* the entry is gone */ };
/* Start the commit of a body (after the install into the zone's entry, before dbreg_commit()); expect: the stamp it was asked for, NULL for a body that has no condition.  Always followed by db_store_commit_end()
 * on the same thread.  After DBC_STALE or DBC_GONE the store takes no version from this thread (dbreg_commit() of a zone that is in memory, whose entry was updated, still registers it; the caller does not
 * commit a new entry, and does not commit anything for DBC_GONE). */
int db_store_commit_begin(const char *view, const char *zone, const db_stamp_t *expect);
void db_store_commit_end(void);
/* after a body was dropped (installed = NULL), or installed for the stamp `installed`: the zone is wanted (its record is KNOWN or STALE and not refused; for an installed body only when the record has another stamp
 * than the body was asked for), and the scan of the wanted bodies has to ask for it again */
bool db_store_wanted_again(const char *view, const char *zone, const db_stamp_t *installed);
#ifdef KARIDNS_UNIT_TEST
/* called by db_store_commit_begin(): where 0 before the step (no mutex held: another writer may come in), 1 inside it (every other writer of a record waits) */
extern void (*db_store_test_commit_hook)(int where, const char *zone);
#endif

/* ---- attach (the store threads) ---- */

/* the attach of one request, on the calling thread (what a store thread does with every request; a test calls it too; the zone with its trailing dot) */
void db_store_attach_zone(const char *view, const char *zone);
/* 0.7 D6: what the store tells the memory advice (dns_mem_advice.h): its mode and the size of the images it holds (the size of a zone is measured, not assumed); nothing is changed when there is no store */
void db_store_ma_inputs(ma_in_t *in);
/* a first fill is going on: the reconcile has zones without an image and a pass or the background fetch of their bodies is running.  The server's own notices about the traffic ("memory-limit is too small") wait for it. */
bool db_store_filling(void);
/* 0.7 fix 8: a first fill whose first pass (the list of the zones) has not ended: the store does not know every zone yet (warm-before-serve holds the queries until it does) */
bool db_store_directory_wait(void);
/* ... of one view (its id in the store, zref_view_sid(); a view that has none: false) */
bool db_store_view_pending(int sid);
/* in every build (dns_db_store.c: the coverage of the test programs and of karidns merges) */
extern int db_store_test_stg_fail;
extern _Atomic bool db_store_test_not_resident;
extern _Atomic bool db_store_test_resident;
extern void (*_Atomic db_store_test_adopt_hook)(void);
extern _Atomic bool db_store_test_adopt_noview;
extern void (*_Atomic db_recon_test_entry_hook)(void);   /* called at every entry of a manifest pass (tests: an entry that takes time) */
extern _Atomic int db_store_test_bits_fail;               /* the bit of the n-th entry of a pass cannot be set (0: off) */
extern _Atomic int db_store_test_plog_fail;                       /* the log of a growth of the attach table that is being prepared cannot grow (the number of times) */
extern void (*_Atomic db_store_test_prep_hook)(int where);       /* the thread that prepares the growth of the attach table calls this (where 0) after it has copied the table and before it takes the lock */
struct dbdir_rec;
extern void (*_Atomic db_store_test_batch_hook)(struct dbdir_rec *rec);   /* called for the record of every job of a batch of attaches just before the batch is registered */
extern _Atomic bool db_store_test_hot_pending;                    /* the threads of hot.list see attach requests of queries that wait (tests: they are never starved by them) */
extern void (*_Atomic db_store_test_hot_hook)(uint32_t zid);   /* called by the threads of hot.list before each zone (tests: the order, and time) */
extern _Atomic bool db_store_test_hot_stuck;                   /* the threads of hot.list see attach requests that wait and are not served (tests: the list gives way once, not for the whole time) */
extern _Atomic uint64_t db_store_test_hot_naps;                /* the naps the threads of hot.list took for the queries (tests) */
#ifdef KARIDNS_UNIT_TEST
extern int db_store_test_set_fail;                      /* the n-th set_put_slot() of the settings table fails (0: off) */
extern int db_store_test_attach_reserve_fail;           /* the n-th reserve of room in the attach table fails (0: off) */
extern _Atomic(const char *) db_store_test_rec_fault_zone;   /* the store cannot read the record of this zone (name with its trailing dot; NULL: off): a damaged cell */
#endif

/* ---- 0.7 store S5 (design 6.7): the texts of rejected zones ----
 * The server keeps the text of the last rejection of a zone in a ring of 512 texts in memory (dbreg_err_note() / dbreg_err_get(), dns_server_internal.h): a rejected zone of the store has no registry
 * element for it.  When the store keeps the texts in a file (err.ring, by zone id) it installs three functions once, after db_store_start(), with
 *     static const dbreg_err_sink_t sink = { put, get, clear };  dbreg_err_set_sink(&sink);
 * put(zid, text): record the text of the zone's last rejection (the ring in memory has it too); get(zid, out, cap): the text, false when there is none; clear(zid): forget it (a version of the
 * zone was registered).  The server calls them without a lock held, from the thread that rejects or registers, and asks the sink only for a zone the memory ring does not have (a zone whose text
 * was pushed out, or a rejection from before a restart).  A zone with no record (zid 0xFFFFFFFF) is never given to the sink. */

/* ---- counters (tests; `karictl store` has the counters of dns_store_status.h) ---- */
typedef struct {
  uint64_t wt_queued, wt_inline, wt_put, wt_skipped, wt_deleted, wt_invalidated, wt_errors, wt_dropped;     /* wt_put: versions written; wt_skipped: the store had the version; wt_deleted; wt_invalidated: records set back to "known" */
  uint64_t attach_ok, attach_stale, attach_missing, attach_damaged, attach_fallback, attach_resident, attach_busy;
  uint64_t attached_bytes;       /* image bytes counted for the versions that were attached and are not freed yet */
  uint64_t versions_live;        /* attached versions not freed yet (their images are not given back) */
  uint64_t validated, validate_ns;   /* images checked by zone_image_validate() at an attach, and the nanoseconds that took */
  uint64_t pin_waits;            /* (unused since S3) */
  uint64_t pinned_peak;          /* (unused since S3) */
  /* 0.7 fix 7, the worker's attach: ok = attached and answered on the worker; the others are why not (cold: the pages are not in the page cache or the mode is COPY; over: above the hard line of memory-limit; claim: another
   * worker or a store thread has the zone; fail: the image or the entry could not be made (the store threads try and fall back); decline: a name server zone of the zone has to be attached too, or a view shared by in-view; full: the staging table or
   * the ring was full); adopted / lost: the staged zones that a store thread registered / found already in memory, changed or gone */
  uint64_t wa_ok, wa_cold, wa_over, wa_claim, wa_fail, wa_decline, wa_full, wa_adopted, wa_lost, wa_ns;
  /* 0.7 fix 8, hot.list: state 0 none, 1 attaching, 2 done, 3 stopped at the high mark of memory-limit, 4 off; listed: the ids that were read at the start; attached / skipped: the zones it attached / that were in memory or not stored; written: the ids written at the last stop */
  uint64_t hot_state, hot_listed, hot_attached, hot_skipped, hot_written;
  uint64_t hot_threads, hot_per_s;   /* 0.7 M4: the threads of the list, and the zones a second they attached (from the start of the list to now, or to its end) */
} db_store_counters_t;
void db_store_counters(db_store_counters_t *out);

#endif /* DNS_DB_STORE_H */

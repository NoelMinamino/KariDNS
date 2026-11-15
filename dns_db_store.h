#ifndef DNS_DB_STORE_H
#define DNS_DB_STORE_H

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
 *     makes the entry like an install does (zone_install_version(), dbreg_commit_attach(): conditional on the version the record offered) and wakes the
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

/* ---- the Backend ---- */

/* Open the store on the descriptor the process inherited, make the views, check that the store belongs to the configured databases, start the threads.  Before
 * enter_capsicum_sandbox().  true: running with the store, or without one (no directory handed over; a store that cannot be opened is logged and not used: the zones are
 * read from the database as before).  false: out of memory or a thread that does not start. */
bool db_store_start(const server_config_t *cfg);
/* Stop the threads after they have done what is queued, checkpoint the store.  The Backend calls it at its end; the store stays open (workers may still look). */
void db_store_stop(void);
bool db_store_enabled(void);
store_t *db_store_handle(void);

/* ---- the ingest threads ---- */

/* a batch ended: what it wrote to the store is made durable (group commit) */
void db_store_batch_end(void);
/* compatibility of the tests of S2 (the writes are made by the thread that installs the zone now: nothing is queued) */
bool db_store_sync(int timeout_ms);

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
enum { DBR_FETCHED = 0, DBR_FETCH_FAILED, DBR_IN_FLIGHT };

/* ---- attach (the store threads) ---- */

/* the attach of one request, on the calling thread (what a store thread does with every request; a test calls it too; the zone with its trailing dot) */
void db_store_attach_zone(const char *view, const char *zone);
#ifdef KARIDNS_UNIT_TEST
extern int db_store_test_set_fail;                      /* the n-th set_put_slot() of the settings table fails (0: off) */
extern int db_store_test_attach_reserve_fail;           /* the n-th reserve of room in the attach table fails (0: off) */
extern int db_store_test_bits_fail;                     /* the bit of the n-th entry of a pass cannot be set (0: off) */
#endif

/* ---- counters (tests; `karictl store` has the counters of dns_store_status.h) ---- */
typedef struct {
  uint64_t wt_queued, wt_inline, wt_put, wt_skipped, wt_deleted, wt_invalidated, wt_errors, wt_dropped;     /* wt_put: versions written; wt_skipped: the store had the version; wt_deleted; wt_invalidated: records set back to "known" */
  uint64_t attach_ok, attach_stale, attach_missing, attach_damaged, attach_fallback, attach_resident, attach_busy;
  uint64_t attached_bytes;       /* image bytes counted for the versions that were attached and are not freed yet */
  uint64_t versions_live;        /* attached versions not freed yet (their images are not given back) */
  uint64_t validated, validate_ns;   /* images checked by zone_image_validate() at an attach, and the nanoseconds that took */
  uint64_t pin_waits;            /* (unused since S3) */
  uint64_t pinned_peak;          /* (unused since S3) */
} db_store_counters_t;
void db_store_counters(db_store_counters_t *out);

#endif /* DNS_DB_STORE_H */

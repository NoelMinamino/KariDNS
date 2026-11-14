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

/* ---- attach (the store threads) ---- */

/* the attach of one request, on the calling thread (what a store thread does with every request; a test calls it too; the zone with its trailing dot) */
void db_store_attach_zone(const char *view, const char *zone);

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

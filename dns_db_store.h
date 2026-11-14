#ifndef DNS_DB_STORE_H
#define DNS_DB_STORE_H

/*
 * dns_db_store - the zone store in the server (0.7 store S2; design: planning/planing_0.7.x_store_10m_design.md sections 2.1, 3.4, 4.1, 4.2).
 *
 * dns_store.c is the store itself (files, index, journal).  This module is what the server does with it while the zone directory is still in the
 * heap (S3 moves the directory into the store):
 *
 *   - The directory.  The process that starts the server (the "Frontend" side of the privilege separation: it runs as root and has not forked the
 *     Backend yet) opens or makes the store directory, checks who owns it and who can write to it, takes an exclusive lock on it (one server per
 *     store) and hands the descriptor to the Backend by fork().  The Backend limits the rights of the descriptor (cap_rights_limit()) and the
 *     store opens its files beneath it (openat()), also in capability mode.  `database { store "<dir>" | none; }` names the directory; without it
 *     the default /var/db/karidns/store is used when /var/db/karidns exists (and the server runs without a store, as before, when it does not or
 *     cannot use it); an explicit directory that cannot be used refuses the start.
 *
 *   - Write-through.  A database zone that was installed (validated, frozen, published and entered in the registry) is copied into the store by the
 *     writer thread with the version the loader sent (source id, serial, digest), unless the store has that very version already.  A zone that the
 *     database deletes is deleted from the store; a zone that the loader announces as changed (a summary in a batch that is not the first) is set
 *     back to "known" (no image), so it is read from the database once more.  The ingest thread only queues the work: it pins the version
 *     (xfr_refs) and the entry (xfr_entry_hold(), which also keeps the cache manager from taking the zone out) until the writer is done.
 *
 *   - Attach.  A query for a zone that is out of memory (directory element ABSENT: not read yet after a start, or taken out by memory-limit) whose
 *     store record is stored and current (the record's serial is the directory's; the source id and, when the directory knows one, the digest
 *     agree) is not fetched from the loader: the worker parks it with the attach deadline (200 ms) and asks the store threads; a store thread reads
 *     the image (MAP: a pointer into the mapped segment; COPY: a buffer), checks it (the store's checksum, the apex name, with `store-paranoid` and in
 *     sanitizer builds the whole structure: zone_image_validate()), makes the entry like an install does (zone_install_version(), dbreg_commit()) and wakes
 *     the parked queries.  A record that is missing, stale or damaged falls back to the fetch (the queries that wait are given the park-timeout
 *     again).  The version of an attached zone counts for memory-limit with its image: the mapped bytes (MAP) or the buffer (COPY), the same number
 *     when the version is counted and when it is given back.  Detaching is the eviction of today (the record stays in the store); a MAP version keeps its
 *     segment mapped until the version is freed, after its grace period (zone_version_free() -> image_free()).
 *
 * Threads: one writer thread (the store's writer mutex serialises writers anyway; one thread keeps the order of the jobs), `store-threads` attach
 * threads, and whoever calls the functions below.  Nothing here runs on the query path except db_store_attach_possible(), which is a lookup in
 * the store's index and one table cell, inside the worker's read section.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "dns_config_parser.h"
#include "dns_store.h"

#define DB_STORE_WQ_MAX 4096        /* queued write-through jobs; a producer that finds the queue full does the job itself */

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

/* ---- write-through (the ingest threads) ---- */

/* view, zone: as the registry knows them (the zone with its trailing dot).  The version the zone has in memory (serial `serial`) goes to the store; digest: the loader's.
 * Queues the work and returns; no-op without a store, for a zone that has no data in memory, a dynamic UPDATE changed, or another serial by now. */
void db_store_write_through(const char *view, const char *zone, int64_t source_id, uint32_t serial, const uint8_t digest[32]);
/* the zone left the database: its record goes */
void db_store_delete(const char *view, const char *zone);
/* the loader says the zone changed (a summary in a later batch): the record keeps the zone's name and version but not its image */
void db_store_invalidate(const char *view, const char *zone, int64_t source_id, uint32_t serial);
/* a batch ended: everything queued before is made durable (group commit) */
void db_store_batch_end(void);
/* wait until every job queued so far is done (tests, karictl store checkpoint); false: time out (ms) */
bool db_store_sync(int timeout_ms);

/* ---- attach (the workers, the store threads) ---- */

/* The worker's decision before it parks a query for a zone that is out of memory: does the store hold the version the directory has (the record is stored, its serial is
 * `dir_serial`)?  Inside a read section.  The store threads check the rest (source id, digest, checksum) when they attach. */
bool db_store_attach_possible(const char *view, const char *zone, uint32_t dir_serial);
/* the attach of one request, on the calling thread (what a store thread does with every request; a test calls it too; the zone with its trailing dot) */
void db_store_attach_zone(const char *view, const char *zone);

/* ---- counters (tests; `karictl store` has the counters of dns_store_status.h) ---- */
typedef struct {
  uint64_t wt_queued, wt_inline, wt_put, wt_skipped, wt_deleted, wt_invalidated, wt_errors, wt_dropped;
  uint64_t attach_ok, attach_stale, attach_missing, attach_damaged, attach_fallback, attach_resident, attach_busy;
  uint64_t attached_bytes;       /* image bytes counted for the versions that were attached and are not freed yet */
  uint64_t versions_live;        /* attached versions not freed yet (their images are not given back) */
} db_store_counters_t;
void db_store_counters(db_store_counters_t *out);

#endif /* DNS_DB_STORE_H */

#ifndef DNS_DB_INGEST_H
#define DNS_DB_INGEST_H

/*
 * dns_db_ingest.h - the Backend side of the database loader link: the db ingest thread (beta design 1.3, 1.5, 4;
 * milestones B4a, B4b).
 *
 * One thread owns the KDB1 stream.  Its I/O is read() / write() on the stream descriptor, recvmsg() on the control
 * descriptor (the supervisor hands over a new stream after every loader restart, SCM_RIGHTS) and kevent() on its own
 * kqueue; all descriptors exist before cap_enter() and are limited to those rights (CLAUDE.md Rule 2: no open, no
 * connect, no sendto).  Everything the loader sends is untrusted input (dns_db_stream.h).
 *
 * The thread runs the whole protocol: HELLO -> CONFIG -> INVENTORY_REQ -> INVENTORY (the registry of DB zones,
 * chunked) -> batches.  Each zone of a batch is built by dns_db_install.c, published into its zone entry, entered in
 * the registry (snapshot_apply_db_delta() makes new zones visible once per batch and at least once per second) and
 * answered with ZONE_RESULT; BATCH_END is answered with BATCH_RESULT.  With `ingest-threads` N > 1, N builder threads
 * parse and publish complete zones while the stream thread keeps reading (at most N zones in flight).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_server_internal.h"

/* Limit the rights of the two descriptors and start the thread (and the builder threads).  Call before
 * enter_capsicum_sandbox().  stream_fd may be -1 (the loader is not connected yet); ctrl_fd is the Backend end of
 * pair C.  false: could not start. */
bool db_ingest_start(int stream_fd, int ctrl_fd, int fetch_fd);
/* D1a: fetch_fd is the Backend end of the second stream (design 6.1), -1 without one.  The thread also reads the fetch requests the workers push
 * (dns_park.h) and sends them to the loader on it; what comes back wakes the parked queries. */

/* A new configuration was published: tell the loader (CONFIG with the new generation).  No-op while the thread is
 * not running.  Called by the control thread; never blocks. */
void db_ingest_config_changed(void);

/* D1a step 7 (database { warm-before-serve }): should the workers still wait before they read their sockets?  True from the start until the loader's hot
 * list has been read, or the configured time is up, whichever comes first (always false without the option).  The query sockets stay unread meanwhile, so the
 * kernel queues the UDP datagrams and the TCP connections wait in the listen queue (a client retries as it does for any slow server; no SERVFAIL is sent, a
 * resolver would hold that against the server); the control channel is not held.  Any thread; no lock. */
bool db_ingest_hold_queries(void);

/* `karictl dbstatus [zone [view]]`: text for the control channel (design 5.2).  Returns the length written to out
 * (always NUL terminated), or 0 when the configuration has no database block.  Control thread. */
size_t db_ingest_status(const char *zone, const char *view, char *out, size_t cap);

/* ---- karictl reload (B6a, design 5.2, D5) ------------------------------------------------------------------------
 * The control thread never waits for the loader.  It hands a request to the ingest thread through a lock-free ring
 * (db_ingest_reload), parks the client, and gets the answer back through a second ring plus an EVFILT_USER event on
 * g_control_kq (ident DB_INGEST_CTL_EVENT); it times the parked client out itself (db-reload-timeout).  Both rings are
 * single producer, single consumer; there is no mutex. */
#define DB_INGEST_CTL_EVENT 3

typedef struct { uint64_t id; bool ok; char text[200]; } db_reload_result_t;

/* Is the ingest thread running (a database block is configured)? */
bool db_ingest_enabled(void);
/* all: RELOAD_REQ scope all (the caller has reloaded the configuration already).  Otherwise one zone of the view
 * `view` (a view name).  Returns the request id (> 0), or 0 when the thread is not running or the ring is full.
 * Control thread only. */
uint64_t db_ingest_reload(bool all, const char *view, const char *zone, bool force);
/* The client of that request is gone or timed out: forget the request.  Control thread only. */
void db_ingest_reload_cancel(uint64_t id);
/* One answer, if there is one (call until false after a DB_INGEST_CTL_EVENT).  Control thread only. */
bool db_ingest_reload_result(db_reload_result_t *out);
/* D1a step 7 (design 7, 12-6): a zone transfer thread (not a worker, not the ingest thread) waits for the zone of the directory element `el` (view `view`) to be
 * in memory: it asks the ingest thread for it (park_fetch_request_any(); the request obeys memory-limit and fetch-rate like a query's, and is made again every
 * 100 ms while the zone is out of memory and nothing is on its way) and polls the element.  The wait ends after `database { transfer-fetch-timeout }`.  Returns the
 * entry of the zone with the transfer counted in its active_axfr (the caller gives it back; the zone is not taken out of memory meanwhile), or NULL: the time
 * is up, the fetch failed or the zone has no usable version (the caller answers SERVFAIL).  A zone this wait brought into memory is marked evict-next.  `el`
 * must stay valid meanwhile (the caller holds a retained snapshot). */
zone_db_entry_t *db_ingest_xfr_await(zdir_elem_t *el, const char *view);

/* Which view a command about the zone means: view_arg if given, else the only view that takes zones from the database.
 * Several views and none named: true with an empty out (B6b: `reload <zone>` then asks every view that takes database
 * zones, and the answer names each).  false with a reason in err otherwise. */
bool db_ingest_pick_view(const char *view_arg, char *out, size_t cap, char *err, size_t errlen);

#endif /* DNS_DB_INGEST_H */

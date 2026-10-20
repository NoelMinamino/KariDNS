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

/* Limit the rights of the two descriptors and start the thread (and the builder threads).  Call before
 * enter_capsicum_sandbox().  stream_fd may be -1 (the loader is not connected yet); ctrl_fd is the Backend end of
 * pair C.  false: could not start. */
bool db_ingest_start(int stream_fd, int ctrl_fd);

/* A new configuration was published: tell the loader (CONFIG with the new generation).  No-op while the thread is
 * not running.  Called by the control thread; never blocks. */
void db_ingest_config_changed(void);

/* `karictl dbstatus [zone [view]]`: text for the control channel (design 5.2).  Returns the length written to out
 * (always NUL terminated), or 0 when the configuration has no database block.  Control thread. */
size_t db_ingest_status(const char *zone, const char *view, char *out, size_t cap);

#endif /* DNS_DB_INGEST_H */

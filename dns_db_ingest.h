#ifndef DNS_DB_INGEST_H
#define DNS_DB_INGEST_H

/*
 * dns_db_ingest.h - the Backend side of the database loader link: the db ingest thread (beta design 1.3, 1.5;
 * milestone B4a).
 *
 * One thread owns the KDB1 stream.  Its I/O is read() / write() on the stream descriptor, recvmsg() on the control
 * descriptor (the supervisor hands over a new stream after every loader restart, SCM_RIGHTS) and kevent() on its own
 * kqueue; all three descriptors exist before cap_enter() and are limited to those rights (CLAUDE.md Rule 2: no
 * open, no connect, no sendto).  Everything the loader sends is untrusted input (dns_db_stream.h).
 *
 * B4a: the thread runs the whole protocol up to the zones.  HELLO -> CONFIG -> INVENTORY_REQ -> (empty) INVENTORY +
 * INVENTORY_END -> batches.  The zones of a batch are validated by the state machine but not installed: every
 * completed zone is answered with ZONE_RESULT "rejected" (install comes with B4b).
 */

#include <stdbool.h>

/* Limit the rights of the two descriptors and start the thread.  Call before enter_capsicum_sandbox().  stream_fd
 * may be -1 (the loader is not connected yet); ctrl_fd is the Backend end of pair C.  false: could not start. */
bool db_ingest_start(int stream_fd, int ctrl_fd);

/* A new configuration was published: tell the loader (CONFIG with the new generation).  No-op while the thread is
 * not running.  Called by the control thread; never blocks. */
void db_ingest_config_changed(void);

#endif /* DNS_DB_INGEST_H */

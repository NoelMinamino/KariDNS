#ifndef DNS_XFR_STORE_H
#define DNS_XFR_STORE_H

/*
 * dns_xfr_store - the secondaries keep what they transferred in the zone store (0.7; design planing_0.7.x_secondary_store.md, revision 3.2).
 *
 * What is stored: the frozen image of a secondary's active version and the 32-byte secondary state (dns_xfr_state.h) in the record's digest, in the reserved store view
 * `_karidns-xfr` (KARIDNS_XFR_STORE_VIEW) under the key "<tag><k>.<zone>".  Who: configuration secondaries (`zone { type slave; }`, with or without `file`), catalog zones
 * that are secondaries, and their members (RFC 9432).  Database secondaries (B7b) are P3 and are not stored here yet.
 *
 * Writes (3.1): the end of every refresh (the transfer thread, holding the entry's is_transferring, no lock): a transfer puts image + state in one store_put_ex(NO_DEGRADE)
 * (the old copy survives a full disk); an up-to-date answer writes the state alone when the record already holds the copy of this serial, else the whole image (M2); a failure
 * writes the attempt time and the failure bit only.  After every write the entry is checked again: a record of an entry that left meanwhile is deleted (M6).
 *
 * Start (4): every secondary entry is made with restore_pending (the tick does not refresh it); the restore thread (`xfr-restore`, started by the store core before the sandbox)
 * installs the stored copy under the entry's writer lock when the entry has no version, or when the copy wins against the version of its `file` (D7), sets the serial and the
 * timers (the expire clock is not reset by a restart: RFC 1034 §4.3.5, RFC 7314), and clears the bit.  Every snapshot rebuild only asks the thread for a pass (M4 d); the pass
 * restores the new entries and deletes the copies of the zones that left (the diff GC over the zone ids of the reserved view, M6/R3).
 *
 * Lock order: the store is never called with an entry's writer lock held, nor inside an RCU read section that a store writer could wait for (the version to put is pinned with
 * xfr_refs).  Capsicum: everything is beneath the store's directory descriptor (no new open, Rule 2).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "dns_config_parser.h"
#include "dns_store.h"
#include "dns_store_status.h"
#include "dns_xfr_state.h"

struct zone_db_entry_s;

/* ---- the store core (dns_db_store.c) ---- */
/* the supervisor, before the initial load of the configuration: a store is configured, so the secondaries are made restore-pending (cleared by the core start when it does not run) */
void xfr_store_want(bool on);
/* the core start: the reserved view (allocated before the views of the database), the restore thread.  quarantined: the store was moved aside or created new (W3: the ERROR
 * line names the secondaries that start without their copy).  false: no copies (every pending bit is cleared; the server runs as before) */
bool xfr_store_core_start(store_t *st, bool quarantined, bool created);
/* the store did not open, or there is none: the pending bits are cleared, the secondaries run in memory only */
void xfr_store_core_off(void);
/* the main thread waits for the first restore pass up to budget_ms before it lets the workers serve (D4); the rest goes on in the background */
void xfr_store_wait_start(unsigned budget_ms);
/* stop the restore thread (db_store_stop(), before the store's checkpoint) */
void xfr_store_stop(void);
/* the store view of the copies (-1: none) */
int  xfr_store_vid(void);
bool xfr_store_active(void);

/* ---- the control channel ---- */
/* zonestatus of a secondary: the `Store:` and `Last-refresh` lines (and `Expired:` when it is) appended to out (a NUL-terminated text); the length written */
size_t xfr_store_zonestatus(struct zone_db_entry_s *e, const server_config_t *cfg, char *out, size_t cap);

/* ---- the expired secondaries (D9; the control thread's tick) ---- */
/* the tick's walk: begin, one call per secondary that has a primary, end (the summary, the hourly lines, the gauge) */
void xfr_expiry_begin(time_t now);
void xfr_expiry_entry(struct zone_db_entry_s *e, const server_config_t *cfg, time_t now);
void xfr_expiry_end(time_t now);
/* the tick's 30 s safety net (R2'): true when entries wait for a restore and the restore thread made no progress for 30 s (the tick then clears every bit it meets) */
bool xfr_restore_stuck(void);
void xfr_restore_note_timeouts(uint64_t n);

/* ---- counters (karictl store: xfr.*, secondary.*) ---- */
typedef store_xfr_t xfr_store_counters_t;           /* (dns_store_status.h) */
void xfr_store_counters(xfr_store_counters_t *out);

#ifdef KARIDNS_UNIT_TEST
/* tests: the restore thread calls this before every entry it restores (a test holds it there, or stops it); the queue's walk is asked for again */
extern void (*_Atomic xfr_store_test_restore_hook)(struct zone_db_entry_s *e);
/* tests: the restore of one entry on the calling thread (what the thread does for it) */
int  xfr_store_test_restore_one(struct zone_db_entry_s *e);
/* tests: a pass of the restore thread now, on the calling thread (restores + GC); returns the copies the GC deleted */
uint64_t xfr_store_test_pass(void);
void xfr_store_test_reset_counters(void);
#endif

#endif /* DNS_XFR_STORE_H */

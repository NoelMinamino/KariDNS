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
/* 2.2: two configured views whose names have one store tag: the later view's secondaries are not persisted (a WARNING once).  Called by every pass of the restore thread; returns the number of views left out */
int  xfr_store_config_check(const server_config_t *cfg);

/* ---- P3: the database secondaries (SLAVE kind 4, CONSUMER kind 5; 3.3, 4.4, 5) ----
 * Their copies are records `<tag>d.<zone>` of the reserved view, written by the end of every refresh like the others, with the id of the zone's settings (settings.dat) in the record and the
 * domains.id in the identity.  The restore thread's start gives every stored `d` copy to the ingest thread as a restore job (db_ingest_xfr_restore_post()); the job makes the entry from the
 * copy when the reconcile's record of the zone agrees (xfr_store_db_restore()), and job_execute_secondary() restores the copy into an entry it makes.  The DB delete paths ask for a pass
 * (g_xfr_ops->db_gone); its GC deletes a `d` copy whose zone the registry no longer has, once every restore job of the start has run (R3). */
/* the ingest thread: one restore job is done (the last one opens the GC of the `d` copies) */
void xfr_store_db_job_done(void);
/* the stored `d` copy of (view, zone): its kind, the id of its settings and its identity; false: none (or not STORED, or not of a database kind) */
bool xfr_store_db_copy(const char *view, const char *zone, int *kind, uint32_t *settings, uint64_t *identity);
/* delete the `d` copy of (view, zone) when it is still the copy of this identity (the row went while the server was stopped) */
void xfr_store_db_copy_drop(const char *view, const char *zone, uint64_t identity);
/* restore the copy into a new entry of a database secondary before it is registered (the ingest thread; the entry's xfr_db_sid is set); true: installed */
bool xfr_store_db_restore(struct zone_db_entry_s *e);

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
/* the gauges of the tick's last walk (karictl status): the expired secondaries, those answered from stale data, those answered SERVFAIL */
void xfr_store_expired(uint64_t *expired, uint64_t *stale, uint64_t *servfail);

#ifdef KARIDNS_UNIT_TEST
/* tests: the restore thread calls this before every entry it restores (a test holds it there, or stops it); the queue's walk is asked for again */
extern void (*_Atomic xfr_store_test_restore_hook)(struct zone_db_entry_s *e);
/* tests: the time the item in work may take beyond the safety net's 30 s (what the restore thread sets from the size of the image it reads) */
void xfr_store_test_item_allow(int64_t ms);
#endif

#endif /* DNS_XFR_STORE_H */

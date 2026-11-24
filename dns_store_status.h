#ifndef DNS_STORE_STATUS_H
#define DNS_STORE_STATUS_H

/*
 * dns_store_status - operator visibility of the zone store (0.7 store design section 9; `karictl store`).
 *
 * Three parts:
 *   1. The attach / cold-query counters (store_attach_stats_t): lock-free (relaxed atomics, sharded over 8 cache-line aligned shards
 *      so that the workers and the store threads do not share a line), O(1) per note, never reset by reading.  The server calls
 *      store_status_note_attach(), _note_detach() and _note_cold() where it attaches a zone, takes one out and answers a query for a
 *      zone that was not attached.  Latencies go into fixed log2 histograms (bucket i: <= 2^i us, i = 0..23, the last one is "more").
 *   2. store_status_format(): the whole picture in text, JSON or key=value form.  Everything is a counter, a gauge or a bounded sample
 *      (store_stats() is O(views), the page-cache residency is mincore() on at most STORE_STATUS_SAMPLE_PAGES pages, cached for 10 s):
 *      a request never walks the zones.  `zone` set: one index lookup and store_zone_get() of that zone, no attach.
 *   3. store_status_control(): the control channel's `store` command (arguments as typed after `karictl store`).
 *
 * The key names of the machine-readable forms are an interface (design decision D15, docs/karictl.md "karictl store"): flat dotted
 * names, JSON values as numbers where numeric.  Adding keys is compatible, renaming or removing one is not (bump "schema").
 *
 * Threads: store_status_format() may be called from any thread that is not inside the store's writer; it brackets its store reads with
 * store_read_lock().  The binding (store_status_bind) is set once by the thread that opens the store, before the control channel runs.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "dns_mem_advice.h"
#include "dns_store.h"

#define STORE_STATUS_SCHEMA        1
#define STORE_STATUS_SAMPLE_PAGES  4096     /* the most pages mincore() looks at per sample */
#define STORE_STATUS_SAMPLE_TTL_MS 10000    /* a sample is reused this long */
#define STORE_STATUS_HIST_BUCKETS  25       /* <= 1 us, <= 2 us, ... <= 2^23 us (8.4 s), more */
#define STORE_STATUS_FINE_BUCKETS  STORE_FINE_BUCKETS    /* 0.7: the percentiles' histogram: 0 .. 7 us one each, then eight per power of two (an eighth of an octave) up to 2^24 - 1 us, more */
#define STORE_STATUS_OUT_MAX       32768    /* the reply is always shorter than this (the callers' buffers are this big or larger) */

enum { STORE_FMT_TEXT = 0, STORE_FMT_JSON = 1, STORE_FMT_KV = 2 };

/* why an attach failed (store_status_note_attach): 0 = it worked */
enum {
  STORE_ATT_OK = 0,
  STORE_ATT_ERR_CHECKSUM,   /* the image's checksum64 is wrong (-EBADMSG of store_image_read) */
  STORE_ATT_ERR_RECORD,     /* the zone's table cell is damaged or does not match the record header */
  STORE_ATT_ERR_INVALID,    /* the image does not pass zone_image_validate() */
  STORE_ATT_ERR_IO,         /* a read failed */
  STORE_ATT_ERR_MEMORY,     /* no memory */
  STORE_ATT_ERR_OTHER,
  STORE_ATT_CAUSES
};
/* why a zone was taken out of memory (store_status_note_detach_why) */
enum { STORE_DET_OTHER = 0, STORE_DET_LIMIT, STORE_DET_ROOM, STORE_DET_OPERATOR, STORE_DET_REASONS };
/* how a query for a zone that was not attached ended (store_status_note_cold) */
enum {
  STORE_COLD_ATTACH = 0,    /* answered after the zone was attached from the store */
  STORE_COLD_FETCH,         /* fell back to a database fetch (a KNOWN zone, or a torn record) */
  STORE_COLD_TIMEOUT,       /* the park time-out ran out (no latency recorded) */
  STORE_COLD_PATHS
};

/* A merged copy of the counters (store_status_snapshot). */
typedef struct store_attach_stats {
  uint64_t attaches;                          /* successful attaches */
  uint64_t attach_failed[STORE_ATT_CAUSES];   /* by cause, [0] unused */
  uint64_t detaches;
  uint64_t detach_by[STORE_DET_REASONS];
  uint64_t cold[STORE_COLD_PATHS];
  uint64_t attach_hist[STORE_STATUS_HIST_BUCKETS];   /* successful attaches by latency */
  uint64_t cold_hist[STORE_STATUS_HIST_BUCKETS];     /* cold queries answered by an attach, park -> answer */
  uint64_t attach_fine[STORE_STATUS_FINE_BUCKETS];   /* the same two, finer (the percentiles) */
  uint64_t cold_fine[STORE_STATUS_FINE_BUCKETS];
  uint64_t attach_max_ns, cold_max_ns;
} store_attach_stats_t;

/* ---- the notes (any thread, any time, O(1), no lock) ---- */
void store_status_note_attach(uint64_t ns, int cause);        /* cause STORE_ATT_OK: ns is the time of the attach; else it is ignored */
void store_status_note_detach(void);                          /* a zone was taken out of memory (reason unknown) */
void store_status_note_detach_why(int reason);                /* STORE_DET_* */
void store_status_note_cold(uint64_t ns, int path);           /* STORE_COLD_*; ns = park -> answer (ignored for STORE_COLD_FETCH / TIMEOUT) */
void store_status_snapshot(store_attach_stats_t *out);
void store_status_reset(void);                                /* tests only */
/* p-th percentile (0..100) of a histogram, in us: the upper bound of the bucket that holds it; the maximum for the last bucket */
uint64_t store_status_hist_pct(const uint64_t *hist, unsigned p, uint64_t max_ns);
/* 0.7: the same for a fine histogram (STORE_STATUS_FINE_BUCKETS) and a quantile in tenths of a percent (0..1000: 990 = p99, 999 = p99.9): the upper bound of the bucket, at most an eighth above the value;
 * the maximum for the last bucket, and the maximum when it is below that bound */
uint64_t store_status_fine_pct(const uint64_t *fine, unsigned permille, uint64_t max_ns);
unsigned store_status_fine_bucket(uint64_t ns);               /* the bucket of a time in ns (rounded up to whole us, as the coarse histogram) */
uint64_t store_status_fine_upper_us(unsigned i);              /* the largest whole us of bucket i (UINT64_MAX for the last) */

/* 0.7 WP7b: the reconcile with the loader (the passes, the background fetch, the mass-delete guard); filled by dns_db_store.c */
typedef struct store_recon {
  bool active;                   /* a pass is running */
  char view[STORE_VIEW_NAME_MAX + 1];       /* of the running pass, or of the last one */
  uint64_t started_unix, duration_ms;
  uint64_t estimate, entries, created, same, changed, renamed, pending, kept, skipped;     /* of the last (or running) pass */
  uint64_t swept, unlisted, total;          /* the last sweep: zones deleted, zones the pass did not list, zones of the view */
  uint64_t passes, wanted, change_upserts, change_deletes, cursors;       /* since the start */
  uint64_t known_now;            /* the records in the state KNOWN now (the store's counter) */
  uint64_t nonstore;             /* zones of the database the store cannot name (the root zone): zones of the heap directory, no record */
  uint64_t fetched, fetch_failed, in_flight;        /* bodies the background fetch brought / could not bring / has in flight */
  unsigned guard_views;          /* views whose sweep the guard holds back */
  char guard_view[STORE_VIEW_NAME_MAX + 1];
  uint64_t guard_unlisted, guard_total, guard_unix;
  /* 0.7 M2, the reconcile thread (dns_db_recon.c: the pages of a pass are decoded and applied there, off the thread that answers the fetches and lookups): the share of the last window it was busy, the entries it applied
   * a second in that window, the pages that wait for it now, the time one entry took (wall time of the apply call over its entries, since the start), the entries and pages since the start, how often the stream
   * thread had to stop reading the loader because the ring was full, the group records the store wrote and their entries, and the longest pass of the ingest thread's loop in the last window (microseconds) */
  bool recon_thread;             /* the figures below are there (the thread runs) */
  uint64_t rt_busy_pct, rt_entries_per_s, rt_queued, rt_apply_ns_per_entry, rt_entries, rt_pages, rt_full_stops, rt_group_records, rt_group_entries, rt_loop_max_us, rt_stream_max_us;
  /* 0.7 fix A: the mutex of the writers of the records (dns_db_store.c g_rec_mu): holds since the start, those of 1 ms or more, the longest hold, the longest wait for it (microseconds) */
  uint64_t rec_holds, rec_holds_slow, rec_hold_max_us, rec_wait_max_us;
  uint64_t rec_hold_fine[STORE_FINE_BUCKETS];   /* 0.7: every hold of the records lock (store.lock.records_hold_p999_us) */
  uint64_t settle_errors;        /* 0.7: settles after the records lock that found the journal full or failed (the calls had returned 0) */
  uint64_t batch_store_errors;   /* batch ends whose commit failed (the cursor stays where it was durable) */
  int      batch_store_last;     /* the result of the last batch end's commit (0, -errno) */
  /* 0.7 signer-wait, since the start: versions that waited for karidns-signer while a signed one kept serving (held), of those the ones only the version in memory kept (the store had no image of the
   * zone), and versions served although the signer has not signed them (no signed version was here to keep: STORE_F_SIGNER_UNSIGNED) */
  uint64_t signer_held, signer_held_mem, signer_unsigned;
  /* 0.7 signer-wait (d): holds made before the loader (or the server) started again that its first batch said still wait (their signed version kept serving across the start).  Without the store
   * the holds of the versions in memory (the heap directory, ZONE_HOLD) count in held_mem and carried too. */
  uint64_t signer_carried;
} store_recon_t;
/* fills *out and returns true, or returns false when the server has none (no loader) */
void store_status_set_recon_fn(bool (*fn)(store_recon_t *out));

/* 0.7 S5 / S6: figures of the server's own tables that this module cannot see (the attach table, the pool of zone entries, the folded counters, the texts in memory); filled by the server */
typedef struct store_extra {
  uint64_t attach_slots, attach_grows, attach_shrinks;
  uint64_t pool_used, pool_slabs, pool_slab_bytes, pool_slot_bytes, pool_free_slots;
  uint64_t folded, fold_rows, fold_replaced;
  uint64_t err_texts, err_noted, err_dropped;
  uint64_t sampled_detaches;
  /* 0.7 fix 7 / 8: the worker's attach (ok: attached and answered on the worker; cold: the pages were not in the page cache, or COPY mode; over: above the hard line of memory-limit; claim: another thread has the zone; fail: the
   * image or the entry could not be made; declined: a name server zone has to be attached first; full: the staging table or the ring was full; adopted / lost: staged zones that were registered / found in memory, changed or gone)
   * and hot.list (state 0 none, 1 attaching, 2 done, 3 stopped at the high mark, 4 off) */
  uint64_t wa_ok, wa_cold, wa_over, wa_claim, wa_fail, wa_decline, wa_full, wa_adopted, wa_lost, wa_ns;
  uint64_t build_n, build_ns;     /* 0.7: the first half of the store threads' attaches (read, check, entry), timed for one in 8: count and nanoseconds */
  uint64_t hot_state, hot_listed, hot_attached, hot_skipped, hot_written;
  uint64_t hot_threads, hot_per_s;
  uint64_t att_shed, att_newest, att_queued;   /* 0.7: attach requests the store threads dropped unread because nobody waited for them, requests taken newest first (the store threads were behind), the slots of the workers' attach rings in use now (dns_park.h) */
} store_extra_t;
void store_status_set_extra_fn(bool (*fn)(store_extra_t *out));

/* 0.7: the by-name lookups of the first start (dns_db_ingest.c: a query for a name that no stored zone covers, while the first pass has not listed every zone): `store.lookup.*`.  asked: requests of the workers taken by the ingest
 * thread; found / none / failed: how the lookups ended (found: a zone was recorded); pending: lookups that wait for a place now (a gauge); take_fail: requests that a worker could not make because its ring was full (the query stays
 * parked as pending and the worker asks again: never a refusal); body_inline: zones whose body came with the answer (one round trip) and was taken; in_flight: lookups out now (and the bodies that came with them); refused: not made (no
 * loader that looks up, a view without database zones); same_name: the same name was on its way; covered: the zone of the name had become known; shed / expired: dropped because the queue was full / its time was up; bad_body: a body
 * that the answer did not announce, thrown away; hist: the time from the request to the answer, as the attach histograms. */
typedef struct store_lookup {
  bool ready;                    /* the loader answers lookups (HELLO features) and the store protocol is on */
  uint64_t asked, found, none, failed, refused, same_name, covered, shed, expired, body_inline, bad_body, take_fail;
  uint64_t pending, in_flight, peak;
  /* the queries that were dropped (overload: not answered, counted, like a query that RRL drops) and the ones answered "not ready": per lookup by why (no room in the park table, its time was up, the ingest thread's queue was full or it waited
   * there until its time was up), the lookups that failed (SERVFAIL + EDE 14), and the same drops for a query that waits for a zone that is out of memory */
  uint64_t drop_lk_room, drop_lk_timeout, drop_lk_queue, servfail, drop_zone_room, drop_zone_timeout, drop_zone_queue;
  /* remembered: names whose lookup was shed that were put in the table of the shed names (park_shed_remember()); reask_suppressed: queries for such a name that their worker dropped without a request (also a drop,
   * PARK_CNT_LK_REMEMBERED); remember_releases: times the names were forgotten at once because the ingest thread had caught up.  drain_*: the passes of the ingest thread over the workers' rings and queues
   * (fetch_issue()) that handled a request: how many, how many ended at the time slice with work left, the most requests one handled, the longest one ran (ns); since the start */
  uint64_t remembered, reask_suppressed, remember_releases, drain_passes, drain_cut, drain_pass_max, drain_pass_max_ns;
  uint64_t hist[STORE_STATUS_HIST_BUCKETS];
  uint64_t max_ns;
} store_lookup_t;
void store_status_set_lookup_fn(bool (*fn)(store_lookup_t *out));

/* 0.7 M3: the zone images the loader sent (dns_db_ingest.c): images / image_bytes: checked by zone_image_validate_ex(), validate_ns: the time of that check, invalid: refused;
 * store_only: put in the store alone (a body that nobody waited for, of a zone with no version here: no entry, attached when a query asks); resident: installed as an entry (a query's fetch,
 * a changed zone, a zone that is in memory, heap mode) */
typedef struct store_fill {
  uint64_t images, image_bytes, validate_ns, invalid, store_only, resident;
} store_fill_t;
void store_status_set_fill_fn(bool (*fn)(store_fill_t *out));

/* 0.7 (planing_0.7.x_secondary_store.md 11): the copies of the secondary zones in the reserved view `_karidns-xfr` (dns_xfr_store.c): `xfr.*` and `secondary.*` */
typedef struct store_xfr {
  uint64_t records, image_bytes, puts, puts_uptodate, put_nospc, put_errors, state_writes, state_stale, state_skipped, orphans_deleted, unstorable;
  uint64_t restored, restored_expired, file_won, restore_bad, restore_identity, restore_pending, restore_ms, restore_timeouts, gc_deleted, stale_capped;
  uint64_t expired_zones, stale_answers, expire_events;
  uint64_t expired_stale, expired_servfail;     /* the expired zones of the tick's last walk that answer from stale data (serve-stale) / SERVFAIL */
  /* P4 (R1, D5): the settings received from primaries in settings.dat (texts, octets), the texts not kept because of the cap, the restores that put them in force again, the restores
   * that asked for the whole zone because they were not kept */
  uint64_t rx_texts, rx_bytes, rx_capped, rx_restored, rx_lost;
  int64_t vid;                   /* the store view of the copies (-1: none) */
} store_xfr_t;
void store_status_set_xfr_fn(bool (*fn)(store_xfr_t *out));

/* ---- what the server tells this module ---- */
/* the open store (NULL: "store not configured", state=none) */
void store_status_bind(store_t *s);
/* the memory figures of the database (P-F): fills *out and returns true, or returns false when there are none.  Called per request. */
void store_status_set_memory_fn(bool (*fn)(ma_est_t *out));
/* optional: is the zone with this zid attached right now?  Adds store.zone.attached to `zone <name>` and is not needed for the counts */
void store_status_set_attached_fn(bool (*fn)(uint32_t zid));
/* optional, a diagnostic for a zone that does not answer (`karictl store zone`): where the zone is on the way to memory.  The server fills what it can tell; nothing is changed by it. */
typedef struct {
  bool elem;                    /* the attach table has an element for the zone id */
  bool resident;                /* ... and the element has its data (the entry) */
  bool staged;                  /* a worker's attach is in the staging table, not registered yet */
  int elem_state;               /* ZDIR_ST_* of the element, -1 without one */
  bool att_claim;               /* a claim for the attach of the zone is held (the workers wait for a store thread) */
  bool att_req;                 /* ... and its request is in a ring */
  uint32_t att_set;             /* ... the workers (bit set) that wait */
  bool fetch_claim;             /* the claim for the fetch of the zone from the database is held */
} store_zdetail_t;
void store_status_set_zdetail_fn(void (*fn)(uint16_t sview, uint32_t zid, const char *view, const char *name, store_zdetail_t *out));
/* the number of zones in memory (the attach table): `store.zones.attached`; without it the figure is attaches minus detaches */
void store_status_set_attached_count_fn(uint64_t (*fn)(void));

/* ---- the report ---- */
/* Writes the report into out (NUL-terminated, never more than cap - 1 bytes) and returns its length; 0 when cap is too small to
 * hold even a short reply.  zone: NULL, or "name" / "name view" (one index lookup, no attach).  JSON is one object; when the
 * report does not fit, it is {"schema":1,"error":"output too large"}.  An unknown zone gives "ERROR zone not found\n". */
size_t store_status_format(char *out, size_t cap, int fmt, const char *zone);
/* The control command `store`: arg and rest are the first word after the command and everything after it, as the control channel
 * splits a line (`store -j zone example.com view`: arg "-j", rest "zone example.com view"); either may be NULL.  A bad argument gives
 * an "ERROR ..." line. */
size_t store_status_control(const char *arg, const char *rest, char *out, size_t cap);
/* The control command `storeop` (karictl store compact | checkpoint | scrub start | scrub stop): what changes the store, so it is not a read command (a full control key only).  arg and
 * rest as above.  "OK ..." or "ERROR ...". */
size_t store_status_op(const char *arg, const char *rest, char *out, size_t cap);

#endif /* DNS_STORE_STATUS_H */

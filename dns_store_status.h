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
} store_extra_t;
void store_status_set_extra_fn(bool (*fn)(store_extra_t *out));

/* ---- what the server tells this module ---- */
/* the open store (NULL: "store not configured", state=none) */
void store_status_bind(store_t *s);
/* the memory figures of the database (P-F): fills *out and returns true, or returns false when there are none.  Called per request. */
void store_status_set_memory_fn(bool (*fn)(ma_est_t *out));
/* optional: is the zone with this zid attached right now?  Adds store.zone.attached to `zone <name>` and is not needed for the counts */
void store_status_set_attached_fn(bool (*fn)(uint32_t zid));
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

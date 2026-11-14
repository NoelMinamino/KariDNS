#ifndef DNS_PARK_H
#define DNS_PARK_H

/*
 * dns_park.h - parked queries and the fetch requests of the workers (D1a, design 4 and 6; milestone 2).
 *
 * A query for a database zone that is in the zone directory but not in memory (zdir_entry() == NULL) is not answered on the spot and
 * not dropped: the worker parks it, asks the db ingest thread to fetch the zone from the loader, and answers when the zone is
 * published (or with SERVFAIL + EDE 14 when the time is up).  Nothing in this milestone makes a zone non-resident, so with every
 * zone in memory none of this runs; the pieces are here, tested, and the worker has the hooks.
 *
 * Three structures, none of them with a lock or an allocation on the query path (CLAUDE.md rule 1):
 *   park_table_t       one per worker, owned by the worker thread alone: a table of park_max entries allocated at start
 *                      (calloc: pages nobody touched cost no memory), a free list, and for every parked query the key it waits for
 *                      (view name and zone name), a deadline and either the whole UDP request (udp_ipc_t and payload, the shape
 *                      of the receive buffers so the answer goes out the usual way) or, for TCP, the connection (descriptor, the
 *                      slot of the connection context and its generation).
 *   park_wake_ring_t   one per worker, single producer (the ingest thread) and single consumer (the worker): "the zone X of the
 *                      view V changed state".  A full ring sets an overflow flag, which the worker answers by waking every
 *                      parked query (they are all looked at again; one that still has no zone parks again).
 *   park_fetch_ring_t  one per worker, single producer (the worker) and single consumer (the ingest thread): "please fetch the zone
 *                      X of the view V" with a priority.  A full ring drops the request: the parked query times out and the next
 *                      query asks again.
 * The key is the view's name, not an index: the index of a view moves with every configuration, the name is what the ingest thread
 * (CONFIG order) and the workers (snapshot order) share.
 * The worker is woken by an EVFILT_USER event on its kqueue (park_wake_broadcast()); the ingest thread by one on its own kqueue
 * (park_fetch_set_notify()).
 *
 * A parked entry is a handle (index, generation): the generation changes every time the entry is given out, so a handle that is
 * kept (a TCP connection context's) and the entry it names cannot be confused after the entry was reused.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "dns_server_internal.h"

#define PARK_ZONE_MAX 255            /* longest zone name kept (the directory's klen is a byte) */
#define PARK_VIEW_MAX 63             /* longest view name (KARIDNS_VIEW_NAME_MAX - 1) */
#define PARK_UDP_MAX 4096            /* the biggest request that is parked; a bigger one gets the "not ready" answer at once (design 4.1) */
#define PARK_DEFAULT_MAX 1024        /* entries per worker (database { park-max }) */
#define PARK_DEFAULT_TIMEOUT_MS 1500 /* database { park-timeout }: shorter than a resolver's retry */
#define PARK_MAX_WORKERS 128         /* as MAX_WORKERS of dns_server_core.c */
#define PARK_WAKE_RING 256
#define PARK_FETCH_RING 128

typedef enum { PARK_FREE = 0, PARK_WAIT, PARK_READY, PARK_TIMEOUT } park_state_t;
typedef enum { PARK_UDP = 1, PARK_TCP = 2 } park_kind_t;

typedef struct {
  uint8_t state;                     /* park_state_t */
  uint8_t kind;                      /* park_kind_t */
  uint8_t zlen;
  uint8_t vlen;
  uint16_t udp_len;                  /* UDP: the request length */
  uint16_t reserved;
  uint32_t gen;                      /* changes every time the entry is given out */
  int64_t deadline_ms;               /* CLOCK_MONOTONIC */
  char view[PARK_VIEW_MAX + 1];      /* the view the query came in on */
  char zone[PARK_ZONE_MAX + 1];      /* the zone the query waits for, as the directory names it (canonical, lower case) */
  union {
    struct {
      int fd;                        /* the descriptor the request came in on (the answer goes out on it) */
      udp_ipc_t ipc;
      uint8_t payload[PARK_UDP_MAX];
    } udp;
    struct {
      int fd;
      uint32_t ctx_idx, ctx_gen;     /* the slot of tcp_stream_ctx_t and its generation: a context is reused for another connection */
    } tcp;
  } u;
} park_entry_t;

typedef struct park_table {
  park_entry_t *e;
  uint32_t cap;
  uint32_t *free_idx;                /* the free entries (a stack); entries never given out are not touched */
  uint32_t nfree;
  uint32_t nwait, nready;
  int64_t min_deadline_ms;           /* <= every WAIT deadline; INT64_MAX when nothing waits */
  uint32_t next_gen;
  /* counters (read by karictl status in a later milestone; the worker alone writes them) */
  uint64_t n_parked, n_full, n_toobig, n_timeout, n_woken, n_failed, n_cancelled;
} park_table_t;

/* cap entries; false: out of memory or cap == 0 */
bool park_init(park_table_t *t, uint32_t cap);
void park_free(park_table_t *t);

/* Park a UDP request.  Returns the index of the entry, or -1: the table is full, the request is longer than PARK_UDP_MAX, or a name
 * is empty or does not fit.  The entry's generation is t->e[idx].gen. */
int32_t park_udp(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, int fd, const udp_ipc_t *ipc,
                 const uint8_t *payload, size_t len);
/* Park a TCP connection (one request per connection: the request stays in the connection's receive buffer). */
int32_t park_tcp(park_table_t *t, int64_t now_ms, uint32_t timeout_ms, const char *view, const char *zone, int fd, uint32_t ctx_idx,
                 uint32_t ctx_gen);
/* Is there a waiting entry for this zone already (a fetch is on its way)? */
bool park_has_wait(const park_table_t *t, const char *view, const char *zone);
/* The entry for a handle: NULL when the entry is free or has been given out again since (generation mismatch). */
park_entry_t *park_get(park_table_t *t, int32_t idx, uint32_t gen);

/* WAIT -> READY for every query that waits for (view, zone).  Returns how many. */
uint32_t park_wake(park_table_t *t, const char *view, const char *zone);
/* WAIT -> TIMEOUT for them: the fetch failed, so the worker answers at once as it does when the time is up. */
uint32_t park_fail(park_table_t *t, const char *view, const char *zone);
uint32_t park_wake_all(park_table_t *t);
/* WAIT -> TIMEOUT for every entry whose deadline is now or past.  Returns how many. */
uint32_t park_expire(park_table_t *t, int64_t now_ms);
/* The next READY or TIMEOUT entry at or after *cursor (the cursor moves past it), NULL when there is none.  The caller serves it
 * and calls park_release(). */
park_entry_t *park_next_done(park_table_t *t, uint32_t *cursor);
void park_release(park_table_t *t, park_entry_t *e);
/* The connection was closed (or handed to another thread): drop its entry.  true when there was one. */
bool park_cancel_tcp(park_table_t *t, uint32_t ctx_idx, uint32_t ctx_gen);
/* Milliseconds until the first deadline, 0 when it is past, -1 when nothing waits. */
int64_t park_next_deadline_ms(const park_table_t *t, int64_t now_ms);

/* ---- the key the ingest thread sends to the workers ---- */
typedef struct {
  uint8_t vlen, zlen;
  bool failed;                       /* the fetch failed: the queries waiting for the zone are answered at once, not woken */
  char view[PARK_VIEW_MAX + 1];
  char zone[PARK_ZONE_MAX + 1];
} park_key_t;

typedef struct {
  park_key_t k[PARK_WAKE_RING];
  _Atomic uint32_t head, tail;       /* producer writes head, consumer tail; indexes grow without wrapping, slot = index % ring */
  _Atomic bool overflow;             /* a wake was dropped: the consumer wakes everything */
  _Atomic uint64_t dropped;
} park_wake_ring_t;

bool park_wake_push(park_wake_ring_t *r, const char *view, const char *zone, bool failed);
bool park_wake_pop(park_wake_ring_t *r, park_key_t *out);
bool park_wake_take_overflow(park_wake_ring_t *r);
/* Is there anything for the consumer: a key in the ring, or a dropped wake?  Two loads, no clock; the worker asks before it does the rest. */
bool park_wake_pending(const park_wake_ring_t *r);

/* ---- the worker's decision before it parks a query and asks for its zone (implemented in dns_server_core.c, used by the UDP and the TCP path; tests call it) ----
 * A query for a zone that is out of memory is never refused here (0.7 P-B): whatever fetch-concurrency, fetch-rate or the memory limit say, the query parks and the request
 * is made; the ingest thread keeps it in its queue until a place, a token and room are there (dns_db_ingest.c, "the wait queue"), or until park-timeout.  The gate only
 * keeps a zone from being asked for twice (see "the claims" in dns_park.c).
 * FETCH_GATE_ASK: no claim, ask as before (no memory-limit; or the zone is not ABSENT: LOADING means a fetch is on its way, ERROR and RESIDENT are answered by the ingest
 * thread; or a worker has claimed the zone already: park, and ask without a claim, the ingest thread drops that request while the claim is marked and the one fetch wakes
 * every worker).  FETCH_GATE_TAKEN: the zone is marked as claimed; ask with PARK_PRIO_CLAIMED, and clear the mark with park_claim_release() if the request is not made.
 * view: the name of the view that holds the zone (zdir_holder_view(), what the request carries). */
enum { FETCH_GATE_ASK = 0, FETCH_GATE_TAKEN };
int fetch_gate(const char *view, const zdir_elem_t *pel);

/* ---- worker -> ingest: please fetch ---- */
/* Set in the prio a worker passes to park_fetch_request(): the worker has marked the zone as claimed for this request (park_claim_mark()).  The ingest thread clears the mark
 * on every path that does not leave it to a queued request (see "the claims" in dns_park.c).  park_fetch_next() strips the bit and reports it as park_fetch_req_t.claimed. */
#define PARK_PRIO_CLAIMED 0x80

typedef struct {
  uint8_t prio;                      /* KDB_FETCH_PRIO_* (park_fetch_push() stores what it is given; park_fetch_next() hands out the plain value) */
  uint8_t mode;                      /* KDB_FETCH_FULL / KDB_FETCH_SUMMARY */
  uint8_t vlen, zlen;
  bool claimed;                      /* park_fetch_next() only: the request holds the claim mark of its zone */
  int16_t worker;                    /* park_fetch_next() only: the ring (worker) it came from, -1 for a thread that is not a worker */
  char view[PARK_VIEW_MAX + 1];
  char zone[PARK_ZONE_MAX + 1];
} park_fetch_req_t;

typedef struct {
  park_fetch_req_t q[PARK_FETCH_RING];
  _Atomic uint32_t head, tail;
  _Atomic uint64_t dropped;
} park_fetch_ring_t;

bool park_fetch_push(park_fetch_ring_t *r, const char *view, const char *zone, uint8_t prio, uint8_t mode);
bool park_fetch_pop(park_fetch_ring_t *r, park_fetch_req_t *out);

/* ---- totals for `karictl dbstatus` (fetchq:), all workers, since the start; relaxed atomics, no lock on the query path ---- */
typedef struct {
  uint64_t full;                     /* queries not parked because the worker's table was full */
  uint64_t timeout;                  /* parked queries that reached their deadline */
  uint64_t ring_dropped;             /* fetch requests the workers could not queue (their ring to the ingest thread was full) */
} park_stats_t;
void park_stats_get(park_stats_t *out);

/* ---- places and tokens (B2 W5, changed by 0.7 P-B) ----
 * Only the ingest thread takes them now: a worker's request waits in the ingest thread's queue until it can have both (a request is never refused for the lack of one).
 *   place   one of fetch-concurrency places for the whole-zone fetches that are on their way (in flight to the loader).  A counter bounded by the limit:
 *           park_place_take() / park_place_give(); the place is held from the take to the end of the fetch (completed, failed, dropped, the loader gone).
 *   token   one of the tokens of the fetch-rate bucket (milli-tokens and a time stamp in one word, compare-and-swap): park_rate_take() / park_rate_give().  With no rate
 *           (fetch-rate unlimited, the default) there is no bucket: the functions return at once, no atomic write.  The warm-up, the background requests and the summaries
 *           take their tokens from the same bucket, so the one rate is what fetch-rate says. */
void park_places_set_limit(uint32_t limit);       /* fetch-concurrency in effect; a lower limit takes effect as the places in use are given back */
uint32_t park_places_used(void);
bool park_place_take(void);                       /* false: every place is taken */
bool park_place_avail(void);                      /* is a place free now (no take)? */
void park_place_give(void);                       /* (never below 0: a place given back twice does not make room) */
void park_rate_set(uint32_t per_s);               /* fetch-rate; 0: no limit (nothing is set yet) */
/* Take a token.  half: only from a bucket that is at least half full (what the queries leave for the warm-up, the summaries and the background requests).
 * now_ms is CLOCK_MONOTONIC in milliseconds; threads may pass values that differ by a few milliseconds. */
bool park_rate_take(int64_t now_ms, bool half);
bool park_rate_check(int64_t now_ms, bool half);  /* the same without taking it */
uint32_t park_rate_level(int64_t now_ms);         /* the tokens in the bucket, in thousandths (0 without a rate) */
void park_rate_give(void);                        /* a token taken for a read that was not made */
void park_rate_reset(void);                       /* a full bucket (tests) */
/* The claims (B2 M1, "the claims" in dns_park.c): the first worker that asks for a zone that is out of memory marks the zone, the others
 * park and ask without a claim.  The key is the hash of (view, zone) (never 0).  park_claim_held(): is a claim marked.  park_claim_mark(): mark it; false: it was marked
 * already (ask without a claim); true: this caller holds the claim (also when there was no room for the mark).  park_claim_clear(): the claim is over (the ingest thread
 * calls it when the request became a fetch, was dropped or refused; a request that waits in its queue keeps the mark). */
uint64_t park_claim_key(const char *view, const char *zone);
bool park_claim_held(uint64_t key);
bool park_claim_mark(uint64_t key);
void park_claim_clear(uint64_t key);
/* The worker's side of a claim that was not used (the park table was full, the ring was full): the mark is cleared. */
void park_claim_release(const char *view, const char *zone);

/* ---- the workers' rings, and the notifications ---- */
/* Worker w (0 .. PARK_MAX_WORKERS-1) has its rings in these arrays.  kq: the kqueue the ingest thread triggers (-1: no notification,
 * unit tests). */
void park_register_worker(int w, int kq);
void park_unregister_worker(int w);
park_wake_ring_t *park_wake_ring(int w);
park_fetch_ring_t *park_fetch_ring(int w);
/* A fetch for (view, zone) is done: tell every registered worker (EVFILT_USER ident PARK_WAKE_IDENT on its kqueue).  The ingest thread
 * calls it.  Never blocks. */
#define PARK_WAKE_IDENT 0x7061726bu    /* "park" */
void park_wake_broadcast(const char *view, const char *zone, bool failed);
/* B2 W5: the ingest thread does it in two steps.  The key goes into the ring at once (to every registered worker, or only to worker w: a request that was shed
 * or refused concerns the worker that asked, w < 0 is a thread that is not a worker: nobody waits), the kqueue of a worker is triggered by park_wake_flush(), once
 * per worker however many keys were queued, which the thread calls when it has done its batch of work (a trigger is a system call: seven microseconds a worker). */
void park_wake_queue_all(const char *view, const char *zone, bool failed);
void park_wake_queue_one(int w, const char *view, const char *zone, bool failed);
void park_wake_flush(void);
/* The ingest thread's kqueue and the ident a worker triggers after pushing a fetch request (-1: none). */
#define PARK_FETCH_IDENT 0x66657463u   /* "fetc" */
void park_fetch_set_notify(int kq);
/* The worker side of the above: push the request and trigger the ingest thread (only when it may be asleep: see "the sleep protocol" in dns_park.c).  false:
 * the ring is full. */
bool park_fetch_request(int w, const char *view, const char *zone, uint8_t prio, uint8_t mode);
/* The ingest thread's side of the sleep protocol.  park_fetch_sleep_prepare() before it waits for events: it says "asleep" and looks once more for requests;
 * true: there is one, do not wait.  park_fetch_sleep_done() when it is awake.  park_fetch_pending(): is any request waiting (a ring, a slot of a transfer thread)? */
bool park_fetch_sleep_prepare(void);
void park_fetch_sleep_done(void);
bool park_fetch_pending(void);
/* The same for a thread that is not a worker (a transfer thread; any number of them, 16 requests wait at most).  false: no free slot or the names do not fit. */
bool park_fetch_request_any(const char *view, const char *zone, uint8_t prio, uint8_t mode);
/* D1a step 8: the query path asks for a zone in the background (g_query_bg_fetch of dns_query_engine.h): one request for a zone in 5 s, priority background. */
void park_bg_fetch(const char *view, const char *zone);
/* ingest side: the next request from any worker or from park_fetch_request_any() (round robin), false when there is none */
bool park_fetch_next(park_fetch_req_t *out);

#endif /* DNS_PARK_H */

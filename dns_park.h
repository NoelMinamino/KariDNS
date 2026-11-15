#ifndef DNS_PARK_H
#define DNS_PARK_H

/*
 * dns_park.h - parked queries and the fetch requests of the workers (D1a, design 4 and 6; milestone 2).
 *
 * A query for a database zone that is in the zone directory but not in memory (zdir_entry() == NULL) is not answered on the spot and
 * not dropped: the worker parks it, asks the db ingest thread to fetch the zone from the loader (or a store thread to attach it from the store),
 * and answers when the zone is published (or with SERVFAIL + EDE 14 when the time is up).  Nothing in this milestone makes a zone non-resident, so with every
 * zone in memory none of this runs; the pieces are here, tested, and the worker has the hooks.
 *
 * Three structures, none of them with a lock or an allocation on the query path (CLAUDE.md rule 1):
 *   park_table_t       one per worker, owned by the worker thread alone.  Everything is allocated at start (calloc: pages nobody touched cost no memory):
 *                      the entries (a header of about 100 bytes each: state, deadline, the links below), the payloads (two sizes of block: a request that
 *                      is parked is kept at about its own length, 256 bytes for the usual one, a block of the longest possible one for the few that need it),
 *                      and four indexes, so that every operation is O(1) or O(the entries of that zone), never a scan of the table:
 *                        - a hash of the key (view name and zone name) -> the waiting entries of a zone (park_has_wait / park_wake / park_fail / park_retry),
 *                        - a timing wheel of the deadlines (park_expire / park_next_deadline_ms),
 *                        - the list of the entries that are done, in the order they were done (park_next_done),
 *                        - the list of the entries whose request has not been handed to the ingest or store threads yet (a full ring never fails a query:
 *                          park_pending_*, the worker tries again).
 *   park_wake_ring_t   one per worker, producers (the ingest thread, the store threads) take turns, single consumer (the worker): "the zone with this key changed state"
 *                      (16 bytes: the 64-bit key of park_name_key(), not the names).  A full ring sets an overflow flag, which the worker answers by waking every
 *                      parked query (they are all looked at again; one that still has no zone parks again).
 *   park_fetch_ring_t  one per worker, single producer (the worker) and single consumer (the ingest thread): "please fetch the zone
 *                      X of the view V" with a priority.  A full ring does not drop the request: the entry stays parked, marked pending, and the worker asks again.
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
#define PARK_DEFAULT_MAX 16384       /* entries per worker (database { park-max }); 0.7: 1024 before the O(1) table, whose entries cost about 0.4 KB (park_bytes()) */
#define PARK_DEFAULT_TIMEOUT_MS 1500 /* database { park-timeout }: shorter than a resolver's retry */
#define PARK_MAX_WORKERS 128         /* as MAX_WORKERS of dns_server_core.c */
#define PARK_WAKE_RING 4096
#define PARK_FETCH_RING 128
#define PARK_ATTACH_RING 4096        /* 0.7 store: attach requests of one worker (8 bytes each: a zone id) */
#define PARK_BLK_SMALL 256           /* the payload block of an entry that fits (the two names, the ipc header and a request of about 100 bytes) */

typedef enum { PARK_FREE = 0, PARK_WAIT, PARK_READY, PARK_TIMEOUT } park_state_t;
typedef enum { PARK_UDP = 1, PARK_TCP = 2 } park_kind_t;
/* what a parked entry still has to ask for (park_pending_set()): its request was refused by a full ring and the worker tries again */
typedef enum { PARK_PEND_NONE = 0, PARK_PEND_ATTACH_ZID, PARK_PEND_ATTACH_NAME, PARK_PEND_FETCH } park_pend_t;

typedef struct park_entry {
  uint8_t state;                     /* park_state_t */
  uint8_t kind;                      /* park_kind_t */
  uint8_t zlen;
  uint8_t vlen;
  uint16_t udp_len;                  /* UDP: the request length */
  uint16_t wslot;                    /* the slot of the timing wheel the entry is in */
  uint8_t ulinked;                   /* the entry is in the list of the pending requests */
  uint8_t attach;                    /* 0.7 store S2: parked for an ATTACH from the store (park_mark_attach()): the deadline is the attach deadline, the time to answer is noted */
  uint8_t pend;                      /* park_pend_t: the request for the zone has not been made yet */
  uint8_t azid;                      /* 0.7 store: the entry waits for the attach of the stored zone `preq` (set by park_entry_attach_zid(); cleared when the wait changes to a fetch): a store thread that cannot name the zone says "zone id X failed" */
  uint32_t gen;                      /* changes every time the entry is given out */
  uint32_t blk;                      /* the payload block: class << 31 | index */
  uint32_t hnext, wprev, wnext, dprev, dnext, uprev, unext;   /* links (index + 1, 0 = none) of the hash chain, the wheel slot, the done list, the pending list */
  int fd;                            /* UDP: the descriptor the request came in on (the answer goes out on it); TCP: the client's */
  uint32_t ctx_idx, ctx_gen;         /* TCP: the slot of tcp_stream_ctx_t and its generation: a context is reused for another connection */
  int64_t deadline_ms;               /* CLOCK_MONOTONIC */
  int64_t t_park_ns;                 /* attach parks only: CLOCK_MONOTONIC in ns when the query was parked */
  int64_t full_ms;                   /* attach parks only: the deadline of the whole park-timeout (CLOCK_MONOTONIC ms); an attach that is still queued at its own deadline is given this one */
  uint64_t key;                      /* park_name_key(view, zone) */
  uint64_t preq;                     /* PARK_PEND_ATTACH_ZID: the zone (store view << 32 | zone id) */
  uint8_t prio;                      /* PARK_PEND_FETCH: the priority to ask with (with PARK_PRIO_CLAIMED when the worker holds the claim) */
  uint8_t *pl;                       /* the payload block: zone NUL, view NUL, (UDP) padding to 8, udp_ipc_t, the request */
} park_entry_t;

#define PARK_WHEEL 65536             /* slots of the timing wheel, 1 ms each: park-timeout is at most 60 s, so a deadline never wraps round the wheel */

typedef struct park_table {
  park_entry_t *e;
  uint32_t cap;
  uint32_t *free_idx;                /* the free entries (a stack); entries never given out are not touched */
  uint32_t nfree;
  uint32_t nwait, nready;
  uint32_t next_gen;
  uint32_t *bucket;                  /* hash of the keys: the head (index + 1) of the chain of the waiting entries */
  uint32_t bmask;
  uint32_t *wheel;                   /* slot -> the head (index + 1) of the entries whose deadline falls in it */
  uint64_t *wbits;                   /* the slots that are not empty */
  int64_t wcur_ms;                   /* every tick before this one has been looked at */
  uint32_t dhead, dtail;             /* entries that are READY or TIMEOUT, oldest first */
  uint32_t uhead, utail, nunsent;    /* entries whose request is pending */
  uint8_t *blk[2];                   /* payload blocks: 0 = PARK_BLK_SMALL bytes, 1 = the longest an entry can need */
  uint32_t *bfree[2];
  uint32_t bnfree[2], bsize[2];
  /* counters (read by karictl status in a later milestone; the worker alone writes them) */
  uint64_t n_parked, n_full, n_toobig, n_timeout, n_woken, n_failed, n_cancelled;
} park_table_t;

/* cap entries; false: out of memory or cap == 0 */
bool park_init(park_table_t *t, uint32_t cap);
void park_free(park_table_t *t);
size_t park_bytes(const park_table_t *t);          /* the bytes park_init() reserved (about 1 KB an entry, half of it touched by usual requests) */

/* The 64-bit key of (view, zone) that the table, the wake keys and the claims use.  The zone is compared without regard to case (the directory's names are lower case already). */
uint64_t park_name_key(const char *view, const char *zone);

/* the strings and the request of an entry (the payload block) */
static inline const char *park_entry_zone(const park_entry_t *e) { return (const char *)e->pl; }
static inline const char *park_entry_view(const park_entry_t *e) { return (const char *)e->pl + e->zlen + 1; }
static inline const udp_ipc_t *park_entry_ipc(const park_entry_t *e) { return (const udp_ipc_t *)(const void *)(e->pl + (((size_t)e->zlen + e->vlen + 2 + 7) & ~(size_t)7)); }
static inline const uint8_t *park_entry_req(const park_entry_t *e) { return (const uint8_t *)park_entry_ipc(e) + sizeof(udp_ipc_t); }

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

/* WAIT -> READY for every query that waits for the zone.  Returns how many.  The `_key` forms take what park_name_key() makes (a wake key carries nothing else). */
uint32_t park_wake(park_table_t *t, const char *view, const char *zone);
uint32_t park_wake_key(park_table_t *t, uint64_t key);
/* WAIT -> TIMEOUT for them: the fetch failed, so the worker answers at once as it does when the time is up. */
uint32_t park_fail(park_table_t *t, const char *view, const char *zone);
uint32_t park_fail_key(park_table_t *t, uint64_t key);
/* 0.7 store S2: the queries that wait for the zone stay parked, with a new deadline (the attach did not work and the zone is fetched now: the park-timeout runs from here).  Returns how many. */
uint32_t park_retry(park_table_t *t, const char *view, const char *zone, int64_t new_deadline_ms);
uint32_t park_retry_key(park_table_t *t, uint64_t key, int64_t new_deadline_ms);
/* 0.7 store: the entry waits for the attach of the stored zone (sview, zid) (park_ask_fetch_zid() finds it by the id) */
void park_entry_attach_zid(park_entry_t *e, uint16_t sview, uint32_t zid);
/* 0.7 store: the queries that wait for the zone (key), or for the attach of the zone id (store view << 32 | zone id), stay parked with a new deadline and this worker asks for the fetch from its own ring (a ring
 * that is full leaves it pending: park_ask_again()).  Returns how many queries. */
uint32_t park_ask_fetch_key(park_table_t *t, int widx, uint64_t key, int64_t new_deadline_ms);
uint32_t park_ask_fetch_zid(park_table_t *t, int widx, uint64_t zidkey, int64_t new_deadline_ms);
/* the entry idx (just parked) waits for an ATTACH from the store (the worker notes the time it took, dns_store_status.h), with the time in ns now; full_deadline_ms: until when the query may wait at the most (park_expire() extends the attach deadline to it instead of timing the query out: an attach that is queued behind slow reads is not a failure) */
void park_mark_attach(park_table_t *t, int32_t idx, int64_t now_ns, int64_t full_deadline_ms);
uint32_t park_wake_all(park_table_t *t);
/* WAIT -> TIMEOUT for every entry whose deadline is now or past.  Returns how many. */
uint32_t park_expire(park_table_t *t, int64_t now_ms);
/* The oldest entry that is READY or TIMEOUT, NULL when there is none.  The caller serves it and calls park_release() (which takes it off the list). */
park_entry_t *park_next_done(park_table_t *t);
void park_release(park_table_t *t, park_entry_t *e);
/* The connection was closed (or handed to another thread): drop its entry, if the handle (park_tcp()'s index and the entry's generation) still names it.  true when there was one. */
bool park_cancel_tcp(park_table_t *t, int32_t idx, uint32_t gen);
/* Milliseconds until the first deadline (not before it: a slot of the wheel that holds a later one is reported too), 0 when it is past, -1 when nothing waits. */
int64_t park_next_deadline_ms(const park_table_t *t, int64_t now_ms);

/* A request that a full ring refused: the entry stays parked and is asked for again (park_pending_head() / park_pending_done()).  kind: PARK_PEND_*; preq / prio as the fields of the entry. */
void park_pending_set(park_table_t *t, park_entry_t *e, park_pend_t kind, uint64_t preq, uint8_t prio);
park_entry_t *park_pending_head(park_table_t *t);              /* the entry that has waited longest to be asked for, NULL when none */
void park_pending_done(park_table_t *t, park_entry_t *e);      /* its request was made */

/* ---- the key the ingest thread and the store threads send to the workers ---- */
typedef struct {
  uint64_t key;                      /* park_name_key(view, zone) */
  bool failed;                       /* the fetch failed: the queries waiting for the zone are answered at once, not woken */
  bool retry;                        /* 0.7 store S2: the attach did not work (a stale or damaged record, or the zone is on its way by another route): the queries that wait for it get a new deadline (park_retry()) and stay parked */
  bool fetch;                        /* ... with `retry`: and the zone is read from the database (counted as store.cold.fetch), not waited for from another attach or fetch */
  uint8_t ask;                       /* 0.7 store: 1: the queries that wait for the zone (key) ask for its fetch themselves, from this worker's own ring, and stay parked (the shared slots for a store thread's request were all taken); 2: the attach of the zone id in `key` (store view << 32 | zone id) failed without a name for the zone (a deleted zone, a cell that cannot be read): the queries that wait for that zone id ask for their zone's fetch */
} park_key_t;

typedef struct {
  park_key_t k[PARK_WAKE_RING];
  _Atomic uint32_t head, tail;       /* producer writes head, consumer tail; indexes grow without wrapping, slot = index % ring */
  _Atomic bool overflow;             /* a wake was dropped: the consumer wakes everything */
  _Atomic bool plock;                /* 0.7 store S2: the producers (the ingest thread, the store threads) take turns: a short spin lock; the consumer is lock free */
  _Atomic uint64_t dropped;
} park_wake_ring_t;

static inline bool park_key_is(const park_key_t *k, const char *view, const char *zone) { return k->key == park_name_key(view, zone); }   /* is it the key of (view, zone)? */

bool park_wake_push(park_wake_ring_t *r, const char *view, const char *zone, bool failed);
bool park_wake_push_ex(park_wake_ring_t *r, const char *view, const char *zone, bool failed, bool retry);
bool park_wake_push_key(park_wake_ring_t *r, uint64_t key, bool failed, bool retry, bool fetch);
bool park_wake_push_ask(park_wake_ring_t *r, uint64_t key, bool failed, bool retry, bool fetch, uint8_t ask);
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
  uint64_t ring_dropped;             /* fetch requests the workers could not queue (their ring to the ingest thread was full: the entry stays parked and the request is made again, so this counts refusals, not lost queries) */
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
/* the attach of (view, zone) did not work and a fetch is on its way, or another attach or fetch has the zone: the parked queries for it get a new deadline and stay parked (`fetch`: it is a read from the database: counted).
 * `workers`: the workers that asked (park_att_take()); PARK_ATT_ALL: every worker. */
void park_wake_queue_retry(const char *view, const char *zone, uint32_t workers, bool fetch);
void park_wake_queue_mask(const char *view, const char *zone, uint32_t workers, bool failed);   /* park_wake_queue_one() for each worker of the set */
/* 0.7 store: the queries that wait for the zone ask for its fetch themselves (the shared slots for a store thread to ask the ingest thread were all taken: they wait, they are not answered "not ready") */
void park_wake_queue_ask(const char *view, const char *zone, uint32_t workers);
/* 0.7 store: the attach of the zone id (store view, zone id) cannot be done and the zone has no name to wake by (it was deleted, its cell cannot be read, the id is another view's now): the workers of the set ask for the fetch of the zones their queries wait for by that id */
void park_wake_queue_zid(uint16_t sview, uint32_t zid, uint32_t workers);
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

/* ---- 0.7 store: ATTACH requests, from the workers to the store threads (dns_db_store.c) ----
 * A query for a database zone that is out of memory and whose current version the store holds is parked with the attach deadline (200 ms); the worker asks the store threads,
 * not the ingest thread (whose 90-100 us per zone would queue the attach behind a fill).  The request is the zone's id in the store (8 bytes: view id, zone id), one per
 * zone however many workers park a query for it (the attach claims, below), in a ring of PARK_ATTACH_RING per worker, so a burst of first touches fills no ring that matters; a full ring
 * leaves the query parked and the request is made again (park_pending_set()), it is never a reason to read a stored zone from the database.  The store threads take requests
 * without a lock (a compare-and-swap on the ring's tail).  The sleep protocol is the fetch thread's: a worker triggers the store threads' kqueue only when one of them may be asleep. */
#define PARK_ATTACH_IDENT 0x61747463u  /* "attc" */
#define PARK_ATTACH_DEADLINE_MS 200
typedef struct {
  bool adopt;                        /* 0.7 fix 7: not a request to attach: the worker attached the zone itself and staged it (db_store_worker_attach()); a store thread registers it (sview and zid name it) */
  bool by_name;                      /* a request that has no zone id (a background attach of a CNAME or glue target, a cell of the store that was being written): the names */
  uint8_t prio;                      /* 2: background (nobody waits: the zone goes first when memory-limit needs room) */
  int16_t worker;                    /* the ring (worker) it came from, -1 for the slots of the other threads */
  uint16_t sview;                    /* by zone id: the view's id in the store */
  uint32_t zid;                      /* ... and the zone's */
  char view[PARK_VIEW_MAX + 1];      /* by name only */
  char zone[PARK_ZONE_MAX + 1];
} park_attach_req_t;
bool park_attach_zid(int w, uint16_t sview, uint32_t zid);       /* false: worker w's ring is full */
/* 0.7 fix 7: the worker attaches a resident image itself and hands the registration to the store threads: room in the ring first (only the worker pushes to it, so a push after a true answer works),
 * then park_attach_adopt() (the same ring, sview with PARK_ATT_ADOPT set: park_attach_next() reports adopt) */
#define PARK_ATT_ADOPT 0x8000u
bool park_attach_room(int w);
bool park_attach_adopt(int w, uint16_t sview, uint32_t zid);
bool park_attach_request_any(const char *view, const char *zone);   /* from any thread (slots taken by compare-and-swap, as the transfer threads' fetch requests); false: no free slot */
/* 0.7 WP7b: the same for a zone that nobody waits for (the background attach of a CNAME or glue target): the request carries the priority "background" (2), so that the store thread
 * marks the zone that it attaches to be the first to go when memory-limit needs room, as for a zone a background fetch brought (dbreg_bg_loaded()) */
bool park_attach_request_bg(const char *view, const char *zone);
void park_bg_attach(const char *view, const char *zone);         /* one request for a zone in a few seconds */
/* The store threads' side: the next request from any worker or slot (round robin).  false: none. */
bool park_attach_next(park_attach_req_t *out);
void park_attach_set_notify(int kq);
bool park_attach_sleep_prepare(void);   /* before waiting: says "asleep" and looks once more; true: there is a request, do not wait */
void park_attach_sleep_done(void);
bool park_attach_pending(void);
/* The attach claims: one request per zone across the workers.  The first worker that parks a query for a stored zone claims it and makes the request; a worker that finds the claim
 * marked parks and joins it (its bit is added to the set of workers to wake).  The store thread that has done the zone takes the claim (park_att_take()) and wakes the workers in the
 * set, and only those: the set is a set of workers as park_wake_queue_mask() takes it (bit w of the 32 for the workers 0..14, bits 15..31 for every worker from 15 up).
 * park_att_claim(): 1 this worker made the claim: it asks (park_attach_zid(), then park_att_requested()); 2 the claim was there, its request is not in a ring yet: this worker asks too; 0 the claim
 * was there with its request in a ring: nothing to ask; -1 no room for a mark: ask without one (the store thread then wakes every worker).
 * park_att_take(): the claim is taken (the zone is attached, or cannot be); returns the set to wake, PARK_ATT_ALL when there was no claim.  park_att_leave(): a worker that no longer waits.  The claim is
 * the exact zone (view id and zone id), never a hash of it, and one word: a worker that joins and the thread that takes the claim cannot miss each other. */
#define PARK_ATT_ALL 0xFFFFFFFFu
int park_att_claim(uint16_t sview, uint32_t zid, int w);
void park_att_requested(uint16_t sview, uint32_t zid);          /* the request of the claim is in a ring */
uint32_t park_att_take(uint16_t sview, uint32_t zid);
bool park_att_leave(uint16_t sview, uint32_t zid, int w);       /* worker w no longer waits for the zone (its entry was dropped without the zone) */

#endif /* DNS_PARK_H */

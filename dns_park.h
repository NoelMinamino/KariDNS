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

/* ---- worker -> ingest: please fetch ---- */
typedef struct {
  uint8_t prio;                      /* KDB_FETCH_PRIO_* */
  uint8_t mode;                      /* KDB_FETCH_FULL / KDB_FETCH_SUMMARY */
  uint8_t vlen, zlen;
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
/* The ingest thread's kqueue and the ident a worker triggers after pushing a fetch request (-1: none). */
#define PARK_FETCH_IDENT 0x66657463u   /* "fetc" */
void park_fetch_set_notify(int kq);
/* The worker side of the above: push the request and trigger the ingest thread.  false: the ring is full. */
bool park_fetch_request(int w, const char *view, const char *zone, uint8_t prio, uint8_t mode);
/* ingest side: the next request from any worker (round robin), false when there is none */
bool park_fetch_next(park_fetch_req_t *out);

#endif /* DNS_PARK_H */

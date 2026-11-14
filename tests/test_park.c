/*
 * test_park.c - the park table, the wake rings and the fetch rings (dns_park.c, D1a milestone 2).
 *
 * Single threaded cases for every rule of the table (full, too big, timeout, wake by key, generation mismatch, TCP cancel), then a
 * concurrency case: three workers (one table each) park queries while one "ingest" thread wakes them through the rings and takes
 * their fetch requests.  Under ThreadSanitizer (make test_park-tsan) it shows that the rings hand data over correctly, under
 * AddressSanitizer (make test_park-asan) that nothing is touched out of bounds.  Every parked query ends exactly once: answered after
 * a wake, answered after its timeout, or cancelled.
 *
 * B2 W5 (the admission gate of the workers): the pool of places (take / give, a lower limit, a place given back twice, eight threads against a limit of five), the
 * fetch-rate bucket (fill, burst, the half rule, a token given back, the wrap of the clock, eight threads for exactly the burst), the claim bit on a request, the wake of
 * one worker and one trigger per worker (park_wake_queue_one / _all / _flush), and the sleep protocol of the ingest thread (a trigger only while it may be asleep; producers
 * against a consumer that sleeps: no request is left in a ring with the thread asleep).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#include "../dns_park.h"
#include "../dns_db_stream.h"      /* KDB_FETCH_* (the values the rings carry) */

static _Atomic int g_checks, g_failed;      /* (the concurrency case checks from several threads) */
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static udp_ipc_t mk_ipc(int tag) {
  udp_ipc_t i;
  memset(&i, 0, sizeof(i));
  i.sock_fd_idx = tag;
  i.addr_len = 16;
  i.payload_len = 20;
  return i;
}

static void test_table(void) {
  printf("[park table]\n");
  park_table_t t;
  CHECK(!park_init(&t, 0));
  CHECK(park_init(&t, 4));
  uint8_t pay[PARK_UDP_MAX + 8];
  memset(pay, 0xA5, sizeof(pay));
  udp_ipc_t ipc = mk_ipc(7);
  CHECK(park_next_deadline_ms(&t, 1000) == -1);

  int32_t a = park_udp(&t, 1000, 1500, "v2", "a.test.", 3, &ipc, pay, 40);
  CHECK(a == 0 && t.nwait == 1 && t.nfree == 3);
  park_entry_t *ea = park_get(&t, a, t.e[a].gen);
  CHECK(ea && ea->state == PARK_WAIT && ea->kind == PARK_UDP && strcmp(ea->view, "v2") == 0 && strcmp(ea->zone, "a.test.") == 0 && ea->zlen == 7);
  CHECK(ea->deadline_ms == 2500 && ea->udp_len == 40 && ea->u.udp.ipc.sock_fd_idx == 7 && ea->u.udp.payload[39] == 0xA5);
  CHECK(park_next_deadline_ms(&t, 1000) == 1500 && park_next_deadline_ms(&t, 3000) == 0);

  /* refused: a request that is too big, an empty zone name, a zone name that does not fit (and nothing was taken) */
  CHECK(park_udp(&t, 1000, 1500, "v0", "b.test.", 3, &ipc, pay, PARK_UDP_MAX + 1) == -1 && t.n_toobig == 1);
  CHECK(park_udp(&t, 1000, 1500, "v0", "", 3, &ipc, pay, 40) == -1);
  char longz[PARK_ZONE_MAX + 4];
  memset(longz, 'x', sizeof(longz));
  longz[sizeof(longz) - 1] = '\0';
  CHECK(park_udp(&t, 1000, 1500, "v0", longz, 3, &ipc, pay, 40) == -1);
  CHECK(park_udp(&t, 1000, 1500, "v0", NULL, 3, &ipc, pay, 40) == -1);
  char longv[PARK_VIEW_MAX + 4];
  memset(longv, 'v', sizeof(longv));
  longv[sizeof(longv) - 1] = '\0';
  CHECK(park_udp(&t, 1000, 1500, longv, "a.test.", 3, &ipc, pay, 40) == -1);            /* a view name that does not fit */
  CHECK(park_udp(&t, 1000, 1500, "", "a.test.", 3, &ipc, pay, 40) == -1 && park_udp(&t, 1000, 1500, NULL, "a.test.", 3, &ipc, pay, 40) == -1);
  CHECK(t.nwait == 1 && t.nfree == 3);
  CHECK(park_udp(&t, 1000, 1500, "v0", "e.test.", 3, &ipc, pay, PARK_UDP_MAX) >= 0);   /* the biggest one fits */
  park_release(&t, &t.e[1]);

  /* full: four entries, the fifth is refused; releasing one makes room */
  CHECK(park_udp(&t, 1000, 1500, "v0", "b.test.", 3, &ipc, pay, 20) == 1);
  CHECK(park_udp(&t, 1000, 100, "v0", "c.test.", 3, &ipc, pay, 20) == 2);
  CHECK(park_udp(&t, 1000, 1500, "v1", "b.test.", 3, &ipc, pay, 20) == 3);
  CHECK(park_udp(&t, 1000, 1500, "v0", "d.test.", 3, &ipc, pay, 20) == -1 && t.n_full == 1 && t.nwait == 4 && t.nfree == 0);
  CHECK(park_has_wait(&t, "v0", "b.test.") && park_has_wait(&t, "v1", "b.test.") && !park_has_wait(&t, "v2", "b.test.") && !park_has_wait(&t, "v0", "d.test."));

  /* a wake by key: the same zone in another view stays asleep; one that does not exist wakes nobody */
  CHECK(park_wake(&t, "v0", "nope.test.") == 0);
  CHECK(park_wake(&t, "v0", "b.test.") == 1 && t.nwait == 3 && t.nready == 1);
  CHECK(park_wake(&t, "v0", "b.test.") == 0);                                      /* (already awake) */
  uint32_t cur = 0;
  park_entry_t *d = park_next_done(&t, &cur);
  CHECK(d && d->state == PARK_READY && strcmp(d->zone, "b.test.") == 0 && strcmp(d->view, "v0") == 0);
  CHECK(park_next_done(&t, &cur) == NULL);
  uint32_t gen_b = d->gen;
  int32_t idx_b = (int32_t)(d - t.e);
  park_release(&t, d);
  CHECK(t.nready == 0 && t.nfree == 1 && d->state == PARK_FREE);
  CHECK(park_get(&t, idx_b, gen_b) == NULL);                                     /* a handle to a free entry */
  park_release(&t, d);                                                           /* a second release changes nothing */
  CHECK(t.nfree == 1);

  /* the entry is given out again: the old handle names nothing, the new one does */
  int32_t again = park_udp(&t, 1000, 1500, "v0", "f.test.", 3, &ipc, pay, 20);
  CHECK(again == idx_b);
  CHECK(park_get(&t, again, gen_b) == NULL);                                     /* generation mismatch */
  CHECK(park_get(&t, again, t.e[again].gen) != NULL && t.e[again].gen != gen_b);
  CHECK(park_get(&t, -1, 1) == NULL && park_get(&t, 99, 1) == NULL);

  /* timeouts: c.test. had 100 ms; a deadline in the past is "timed out", the others keep waiting */
  CHECK(park_expire(&t, 1050) == 0);
  CHECK(park_expire(&t, 1100) == 1 && t.nwait == 3 && t.nready == 1 && t.n_timeout == 1);
  CHECK(park_expire(&t, 1100) == 0);
  cur = 0;
  d = park_next_done(&t, &cur);
  CHECK(d && d->state == PARK_TIMEOUT && strcmp(d->zone, "c.test.") == 0);
  CHECK(park_wake(&t, "v0", "c.test.") == 0);                                       /* a timed out entry is not woken */
  park_release(&t, d);
  CHECK(park_next_deadline_ms(&t, 1200) == 1300);                                /* a.test. 2500, the rest 2500 */
  CHECK(park_expire(&t, 2500) == 3 && t.nwait == 0 && t.nready == 3);
  CHECK(park_next_deadline_ms(&t, 3000) == -1);
  cur = 0;
  uint32_t served = 0;
  while ((d = park_next_done(&t, &cur))) {
    park_release(&t, d);
    served++;
  }
  CHECK(served == 3 && t.nready == 0 && t.nwait == 0 && t.nfree == 4);

  /* wake everything */
  CHECK(park_udp(&t, 0, 1500, "v0", "a.test.", 3, &ipc, pay, 20) >= 0 && park_udp(&t, 0, 1500, "v1", "b.test.", 3, &ipc, pay, 20) >= 0);
  CHECK(park_wake_all(&t) == 2 && t.nwait == 0 && t.nready == 2);
  cur = 0;
  while ((d = park_next_done(&t, &cur))) park_release(&t, d);
  CHECK(t.nfree == 4);

  /* a failed fetch: the entries for the zone are done at once, as a timeout (park_fail), the others stay */
  CHECK(park_udp(&t, 0, 1500, "v0", "bad.test.", 3, &ipc, pay, 20) >= 0 && park_udp(&t, 0, 1500, "v0", "bad.test.", 3, &ipc, pay, 20) >= 0 && park_udp(&t, 0, 1500, "v1", "bad.test.", 3, &ipc, pay, 20) >= 0);
  CHECK(park_fail(&t, "v0", "nope.test.") == 0 && park_fail(&t, "v0", "bad.test.") == 2 && t.nwait == 1 && t.nready == 2 && t.n_failed == 2);
  cur = 0;
  while ((d = park_next_done(&t, &cur))) {
    CHECK(d->state == PARK_TIMEOUT && strcmp(d->view, "v0") == 0);
    park_release(&t, d);
  }
  CHECK(park_wake_all(&t) == 1);
  cur = 0;
  while ((d = park_next_done(&t, &cur))) park_release(&t, d);
  CHECK(t.nfree == 4);

  /* the generation is never 0, also after the counter wraps */
  t.next_gen = UINT32_MAX;
  int32_t w1 = park_udp(&t, 0, 10, "v0", "w.test.", 3, &ipc, pay, 20), w2 = park_udp(&t, 0, 10, "v0", "w.test.", 3, &ipc, pay, 20);
  CHECK(w1 >= 0 && w2 >= 0 && t.e[w1].gen == UINT32_MAX && t.e[w2].gen == 1);
  park_free(&t);
  CHECK(t.e == NULL && t.cap == 0);
}

static void test_tcp(void) {
  printf("[parked TCP connections]\n");
  park_table_t t;
  CHECK(park_init(&t, 8));
  int32_t a = park_tcp(&t, 0, 1500, "v1", "t.test.", 17, 5, 100);
  int32_t b = park_tcp(&t, 0, 1500, "v1", "t.test.", 18, 6, 200);
  CHECK(a >= 0 && b >= 0 && t.nwait == 2);
  park_entry_t *ea = park_get(&t, a, t.e[a].gen);
  CHECK(ea && ea->kind == PARK_TCP && ea->u.tcp.fd == 17 && ea->u.tcp.ctx_idx == 5 && ea->u.tcp.ctx_gen == 100);
  /* the connection context 5 was reused for another connection (generation 101): the entry of generation 100 is not the new one's */
  CHECK(!park_cancel_tcp(&t, 5, 101));
  CHECK(!park_cancel_tcp(&t, 7, 100));
  CHECK(t.nwait == 2);
  CHECK(park_cancel_tcp(&t, 5, 100) && t.nwait == 1 && t.n_cancelled == 1);
  CHECK(park_get(&t, a, ea->gen) == NULL);
  CHECK(!park_cancel_tcp(&t, 5, 100));
  /* an awake entry is cancelled too (the connection closed before the worker served it) */
  CHECK(park_wake(&t, "v1", "t.test.") == 1);
  CHECK(park_cancel_tcp(&t, 6, 200) && t.nwait == 0 && t.nready == 0 && t.nfree == 8);
  /* a UDP entry is never cancelled by a TCP context */
  udp_ipc_t ipc = mk_ipc(1);
  uint8_t pay[20] = { 0 };
  int32_t u = park_udp(&t, 0, 1500, "v1", "u.test.", 3, &ipc, pay, 20);
  CHECK(u >= 0 && !park_cancel_tcp(&t, 0, 0) && t.nwait == 1);
  park_free(&t);
}

static void test_rings(void) {
  printf("[wake ring and fetch ring]\n");
  park_wake_ring_t *wr = park_wake_ring(PARK_MAX_WORKERS - 1);
  park_key_t k;
  CHECK(wr && !park_wake_pop(wr, &k));
  CHECK(!park_wake_pending(wr));                                                             /* nothing: the worker's loop does not go on */
  CHECK(park_wake_push(wr, "v3", "one.test.", false) && park_wake_pending(wr));
  CHECK(park_wake_pop(wr, &k) && !park_wake_pending(wr));
  atomic_store(&wr->overflow, true);
  CHECK(park_wake_pending(wr) && park_wake_take_overflow(wr) && !park_wake_pending(wr));    /* a dropped wake is something too */
  CHECK(park_wake_push(wr, "v3", "one.test.", false) && park_wake_push(wr, "v4", "two.test.", false));
  CHECK(park_wake_pop(wr, &k) && strcmp(k.view, "v3") == 0 && strcmp(k.zone, "one.test.") == 0 && k.zlen == 9);
  CHECK(park_wake_pop(wr, &k) && strcmp(k.view, "v4") == 0 && strcmp(k.zone, "two.test.") == 0);
  CHECK(!park_wake_pop(wr, &k) && !park_wake_take_overflow(wr));
  /* full: the key is dropped and the overflow flag says the consumer must look at everything */
  for (int i = 0; i < PARK_WAKE_RING; i++) CHECK(park_wake_push(wr, "v0", "z.test.", false));
  CHECK(!park_wake_push(wr, "v0", "late.test.", false) && park_wake_take_overflow(wr) && !park_wake_take_overflow(wr));
  CHECK(atomic_load(&wr->dropped) == 1);
  for (int i = 0; i < PARK_WAKE_RING; i++) CHECK(park_wake_pop(wr, &k));
  CHECK(!park_wake_pop(wr, &k));
  CHECK(!park_wake_push(wr, "v0", "", false));                                              /* no empty key */
  CHECK(park_wake_take_overflow(wr));
  /* the ring keeps working when the indexes pass the size many times over */
  for (int i = 0; i < 3 * PARK_WAKE_RING; i++) {
    char nm[32];
    snprintf(nm, sizeof(nm), "n%d.test.", i);
    char vn[16];
    snprintf(vn, sizeof(vn), "view%d", i);
    CHECK(park_wake_push(wr, vn, nm, false) && park_wake_pop(wr, &k) && strcmp(k.view, vn) == 0 && strcmp(k.zone, nm) == 0);
  }

  park_fetch_ring_t *fr = park_fetch_ring(PARK_MAX_WORKERS - 2);
  park_fetch_req_t q;
  CHECK(fr && !park_fetch_pop(fr, &q));
  CHECK(park_fetch_push(fr, "v1", "f1.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) && park_fetch_push(fr, "v2", "f2.test.", KDB_FETCH_PRIO_WARM, KDB_FETCH_SUMMARY));
  CHECK(park_fetch_pop(fr, &q) && strcmp(q.view, "v1") == 0 && q.prio == KDB_FETCH_PRIO_QUERY && q.mode == KDB_FETCH_FULL && strcmp(q.zone, "f1.test.") == 0);
  CHECK(park_fetch_pop(fr, &q) && strcmp(q.view, "v2") == 0 && q.prio == KDB_FETCH_PRIO_WARM && q.mode == KDB_FETCH_SUMMARY);
  CHECK(!park_fetch_pop(fr, &q));
  for (int i = 0; i < PARK_FETCH_RING; i++) CHECK(park_fetch_push(fr, "v0", "x.test.", 0, 0));
  CHECK(!park_fetch_push(fr, "v0", "over.test.", 0, 0) && atomic_load(&fr->dropped) == 1);
  CHECK(!park_fetch_push(fr, "v0", "", 0, 0));
  for (int i = 0; i < PARK_FETCH_RING; i++) CHECK(park_fetch_pop(fr, &q));

  /* the workers' side: a request from worker 5 and one from worker 9 reach the ingest side; a wake reaches every registered worker */
  park_register_worker(5, -1);
  park_register_worker(9, -1);
  CHECK(park_fetch_request(5, "v1", "a.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) && park_fetch_request(9, "v2", "b.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(!park_fetch_request(-1, "v1", "a.test.", 0, 0) && !park_fetch_request(PARK_MAX_WORKERS, "v1", "a.test.", 0, 0));
  int got = 0;
  while (park_fetch_next(&q)) got += q.view[1] - '0';
  CHECK(got == 3);
  park_wake_broadcast("v7", "wake.test.", false);
  CHECK(park_wake_pop(park_wake_ring(5), &k) && strcmp(k.view, "v7") == 0 && park_wake_pop(park_wake_ring(9), &k) && strcmp(k.view, "v7") == 0);
  park_unregister_worker(9);
  park_wake_broadcast("v8", "wake2.test.", false);
  CHECK(park_wake_pop(park_wake_ring(5), &k) && strcmp(k.view, "v8") == 0 && !park_wake_pop(park_wake_ring(9), &k));
  park_unregister_worker(5);
  CHECK(park_wake_ring(-1) == NULL && park_wake_ring(PARK_MAX_WORKERS) == NULL && park_fetch_ring(-1) == NULL);
}

/* ------------------------------------------------------------------ concurrency */
#define CW 3                     /* workers */
#define CZONES 5                 /* zones the queries wait for */
#define CROUNDS 4000

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static _Atomic bool g_stop;
static _Atomic uint64_t g_fetched, g_requested;
static uint64_t g_served_wake[CW], g_served_timeout[CW], g_parked[CW];
static pthread_barrier_t g_bar;

static void zname(int z, char *buf, size_t n) { snprintf(buf, n, "c%d.test.", z); }

/* a worker: parks a query for one of the zones, asks for the zone (once per zone while one waits), and serves what the rings and the
 * deadlines hand back; it ends when it has parked CROUNDS queries and served them all */
static void *worker(void *arg) {
  int w = (int)(intptr_t)arg;
  park_table_t t;
  CHECK(park_init(&t, 64));
  park_register_worker(w, -1);
  park_wake_ring_t *wr = park_wake_ring(w);
  unsigned seed = (unsigned)w * 7919u + 1;
  udp_ipc_t ipc = mk_ipc(w);
  uint8_t pay[32];
  memset(pay, w, sizeof(pay));
  pthread_barrier_wait(&g_bar);
  uint32_t parked = 0;
  while (parked < CROUNDS || t.nwait + t.nready > 0) {
    /* park */
    if (parked < CROUNDS) {
      seed = seed * 1103515245u + 12345u;
      int z = (int)((seed >> 8) % CZONES);
      char nm[32];
      zname(z, nm, sizeof(nm));
      bool never = (seed >> 12) % 7 == 0;                                             /* a zone nobody asks for and nobody wakes: it runs out */
      if (never) snprintf(nm, sizeof(nm), "never.test.");
      uint32_t to = never ? 2 : 50;
      bool had = park_has_wait(&t, "v1", nm);
      int32_t i = park_udp(&t, mono_ms(), to, "v1", nm, 3, &ipc, pay, sizeof(pay));
      if (i >= 0) {
        parked++;
        g_parked[w]++;
        if (!never && !had && park_fetch_request(w, "v1", nm, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL)) atomic_fetch_add(&g_requested, 1);
      }
    }
    /* what the ingest thread said */
    park_key_t k;
    while (park_wake_pop(wr, &k)) (void)park_wake(&t, k.view, k.zone);
    if (park_wake_take_overflow(wr)) (void)park_wake_all(&t);
    (void)park_expire(&t, mono_ms());
    uint32_t cur = 0;
    park_entry_t *e;
    while ((e = park_next_done(&t, &cur))) {
      if (e->state == PARK_READY) g_served_wake[w]++;
      else g_served_timeout[w]++;
      if (e->kind != PARK_UDP || e->u.udp.ipc.sock_fd_idx != w || e->u.udp.payload[31] != (uint8_t)w) {
        CHECK(false);                                                               /* the request came back as it went in */
      }
      park_release(&t, e);
    }
    if (parked >= CROUNDS && t.nwait > 0) usleep(200);
  }
  CHECK(t.nfree == t.cap && t.nwait == 0 && t.nready == 0);
  park_unregister_worker(w);
  park_free(&t);
  return NULL;
}

/* the ingest thread: takes the fetch requests and, a moment later, says the zone is there */
static void *ingest(void *arg) {
  (void)arg;
  pthread_barrier_wait(&g_bar);
  park_fetch_req_t q;
  while (!atomic_load(&g_stop)) {
    if (park_fetch_next(&q)) {
      atomic_fetch_add(&g_fetched, 1);
      if (atomic_load(&g_fetched) % 3 != 0) park_wake_broadcast(q.view, q.zone, false);     /* every third fetch is "lost": the queries time out */
    } else {
      usleep(100);
    }
  }
  return NULL;
}

static void test_concurrent(void) {
  printf("[workers parking while the ingest thread wakes them]\n");
  pthread_t th[CW], ig;
  pthread_barrier_init(&g_bar, NULL, CW + 1);
  pthread_create(&ig, NULL, ingest, NULL);
  for (long i = 0; i < CW; i++) pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
  for (int i = 0; i < CW; i++) pthread_join(th[i], NULL);
  atomic_store(&g_stop, true);
  pthread_join(ig, NULL);
  uint64_t parked = 0, w = 0, to = 0;
  for (int i = 0; i < CW; i++) {
    parked += g_parked[i];
    w += g_served_wake[i];
    to += g_served_timeout[i];
  }
  printf("  %llu parked, %llu answered after a wake, %llu after the timeout, %llu fetch requests (%llu taken)\n", (unsigned long long)parked,
         (unsigned long long)w, (unsigned long long)to, (unsigned long long)atomic_load(&g_requested), (unsigned long long)atomic_load(&g_fetched));
  CHECK(parked == (uint64_t)CW * CROUNDS);
  CHECK(w + to == parked);                      /* every parked query was served exactly once */
  CHECK(w > 0 && to > 0);
}

/* D1a step 7: the requests of threads that are not workers (the transfer threads): 16 slots, any number of producers, one consumer */
#define AW 4
#define AN 3000
static _Atomic uint64_t g_any_taken;
static void *any_producer(void *arg) {
  long id = (long)(intptr_t)arg;
  char zn[64];
  for (int i = 0; i < AN; i++) {
    snprintf(zn, sizeof(zn), "z%ld-%d.test.", id, i);
    while (!park_fetch_request_any("v1", zn, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL)) usleep(20);      /* (a full table: the caller asks again later) */
  }
  return NULL;
}
static void *any_consumer(void *arg) {
  (void)arg;
  park_fetch_req_t q;
  uint64_t seen = 0;
  while (seen < (uint64_t)AW * AN) {
    if (park_fetch_next(&q)) {
      long id = -1;
      int i = -1;
      if (strcmp(q.view, "v1") == 0 && sscanf(q.zone, "z%ld-%d.test.", &id, &i) == 2 && id >= 0 && id < AW && i >= 0 && i < AN && q.zlen == strlen(q.zone))
        seen++;
      else
        CHECK(false);                                  /* (a request that is not whole) */
    } else {
      usleep(50);
    }
  }
  atomic_store(&g_any_taken, seen);
  return NULL;
}

static void test_any(void) {
  printf("[requests of threads that are not workers]\n");
  park_fetch_req_t q;
  CHECK(!park_fetch_next(&q));
  /* the names must fit */
  char longz[PARK_ZONE_MAX + 10];
  memset(longz, 'a', sizeof(longz));
  longz[sizeof(longz) - 1] = '\0';
  CHECK(!park_fetch_request_any("v1", longz, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(!park_fetch_request_any("", "a.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  /* 16 slots: the 17th request finds none; taking one frees one */
  char zn[40];
  int ok = 0;
  for (int i = 0; i < 17; i++) {
    snprintf(zn, sizeof(zn), "s%d.test.", i);
    ok += park_fetch_request_any("v1", zn, i % 2 ? KDB_FETCH_PRIO_WARM : KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL);
  }
  CHECK(ok == 16);
  CHECK(park_fetch_next(&q) && strcmp(q.view, "v1") == 0 && strncmp(q.zone, "s", 1) == 0 && q.mode == KDB_FETCH_FULL);
  CHECK(park_fetch_request_any("v1", "again.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_SUMMARY));
  int got = 1, summary = 0;
  while (park_fetch_next(&q)) {
    got++;
    summary += q.mode == KDB_FETCH_SUMMARY && strcmp(q.zone, "again.test.") == 0 && q.prio == KDB_FETCH_PRIO_BACKGROUND;
  }
  CHECK(got == 17 && summary == 1);
  CHECK(!park_fetch_next(&q));
  /* park_bg_fetch(): a request that finds no free slot is neither made nor remembered as made (the next call makes it); one that was queued is made once in PARK_BG_MS */
  for (int i = 0; i < 16; i++) {
    snprintf(zn, sizeof(zn), "f%d.test.", i);
    CHECK(park_fetch_request_any("v1", zn, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  }
  park_bg_fetch("v1", "bg.test.");                        /* (no slot) */
  CHECK(park_fetch_next(&q));                             /* (one is free now) */
  park_bg_fetch("v1", "bg.test.");                        /* (the first call was not remembered: this one is queued) */
  park_bg_fetch("v1", "bg.test.");                        /* (and now it was: not again) */
  int bg_n = 0, bg_got = 0;
  while (park_fetch_next(&q)) {
    bg_n++;
    bg_got += strcmp(q.zone, "bg.test.") == 0 && q.prio == KDB_FETCH_PRIO_BACKGROUND && q.mode == KDB_FETCH_FULL;
  }
  CHECK(bg_n == 15 + 1 && bg_got == 1);
  CHECK(!park_fetch_next(&q));
  /* four producers, one consumer: every request arrives once, whole */
  pthread_t th[AW], cons;
  pthread_create(&cons, NULL, any_consumer, NULL);
  for (long i = 0; i < AW; i++) pthread_create(&th[i], NULL, any_producer, (void *)(intptr_t)i);
  for (int i = 0; i < AW; i++) pthread_join(th[i], NULL);
  pthread_join(cons, NULL);
  CHECK(atomic_load(&g_any_taken) == (uint64_t)AW * AN);
}

/* D1a review 7c: the slots of the transfer threads take turns with the workers' rings: a ring that is never empty does not starve them */
static void test_slots_not_starved(void) {
  printf("[the slots of the transfer threads are not starved by a busy worker ring]\n");
  park_register_worker(0, -1);
  park_fetch_ring_t *r0 = park_fetch_ring(0);
  for (int i = 0; i < PARK_FETCH_RING - 1; i++) CHECK(park_fetch_push(r0, "v1", "busy.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(park_fetch_request_any("v1", "xfer.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  park_fetch_req_t q;
  int calls = 0;
  bool seen = false;
  while (calls < 130 && !seen) {                       /* one turn of the round robin is 129 sources; the ring is refilled after every request */
    CHECK(park_fetch_next(&q));
    seen = strcmp(q.zone, "xfer.test.") == 0;
    if (!seen) CHECK(park_fetch_push(r0, "v1", "busy.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
    calls++;
  }
  CHECK(seen);
  while (park_fetch_next(&q)) {}
  park_unregister_worker(0);
}

/* B2 W3: the totals of dbstatus "fetchq:" (park_stats_get) follow the per-table counters and the ring drops, across tables */
static void test_stats(void) {
  park_stats_t s0, s1;
  park_table_t t1, t2;
  udp_ipc_t ipc;
  uint8_t pay[64];
  memset(&ipc, 0, sizeof(ipc));
  memset(pay, 0, sizeof(pay));
  CHECK(park_init(&t1, 1) && park_init(&t2, 1));
  park_stats_get(&s0);
  CHECK(park_udp(&t1, 0, 100, "v0", "a.test.", 3, &ipc, pay, 20) == 0);
  CHECK(park_udp(&t1, 0, 100, "v0", "b.test.", 3, &ipc, pay, 20) == -1);            /* table 1 is full */
  CHECK(park_tcp(&t1, 0, 100, "v0", "c.test.", 5, 1, 1) == -1);                      /* ... for TCP too */
  CHECK(park_udp(&t2, 0, 100, "v0", "a.test.", 3, &ipc, pay, 20) == 0);
  CHECK(park_udp(&t2, 0, 100, "v0", "b.test.", 3, &ipc, pay, 20) == -1);            /* table 2 (another worker) is full */
  CHECK(park_expire(&t1, 50) == 0 && park_expire(&t1, 100) == 1 && park_expire(&t2, 100) == 1);
  park_register_worker(5, -1);
  park_fetch_ring_t *r5 = park_fetch_ring(5);
  park_fetch_req_t q;
  while (park_fetch_pop(r5, &q)) {}                                                  /* (what the earlier tests left) */
  for (int i = 0; i < PARK_FETCH_RING; i++) CHECK(park_fetch_request(5, "v1", "ring.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(!park_fetch_request(5, "v1", "ring.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));   /* the ring is full: dropped */
  CHECK(!park_fetch_request(5, "v1", "ring.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  park_stats_get(&s1);
  CHECK(s1.full - s0.full == 3 && s1.timeout - s0.timeout == 2 && s1.ring_dropped - s0.ring_dropped == 2);
  while (park_fetch_pop(r5, &q)) {}
  park_unregister_worker(5);
  park_stats_get(&s0);
  CHECK(s0.full == s1.full && s0.timeout == s1.timeout && s0.ring_dropped == s1.ring_dropped);   /* nothing moves by itself */
  park_free(&t1);
  park_free(&t2);
}


/* ------------------------------------------------------------------ B2 W5: the admission gate */
/* places: a lock-free pool bounded by the limit; a lower limit takes effect as places come back; a place given back twice makes no room */
static void test_places(void) {
  printf("[admission gate: places]\n");
  park_places_set_limit(3);
  CHECK(park_places_used() == 0);
  CHECK(park_place_take() && park_place_take() && park_place_take());
  CHECK(!park_place_take() && park_places_used() == 3);
  park_place_give();
  CHECK(park_places_used() == 2 && park_place_take() && !park_place_take());
  park_places_set_limit(1);                                  /* lowered below what is in use: nothing is taken away, nothing new is given */
  CHECK(!park_place_take() && park_places_used() == 3);
  park_place_give();
  park_place_give();
  CHECK(!park_place_take() && park_places_used() == 1);      /* (as many as the limit) */
  park_place_give();
  CHECK(park_place_take() && !park_place_take());
  park_places_set_limit(4);                                  /* raised: room at once */
  CHECK(park_place_take() && park_place_take() && park_place_take() && !park_place_take() && park_places_used() == 4);
  for (int i = 0; i < 4; i++) park_place_give();
  park_place_give();                                         /* given back twice: no credit */
  park_place_give();
  CHECK(park_places_used() == 0);
  park_places_set_limit(2);
  CHECK(park_place_take() && park_place_take() && !park_place_take());
  park_place_give();
  park_place_give();
  park_places_set_limit(0);                                  /* (fetch-concurrency is at least 2 in the server; 0 here means no place at all) */
  CHECK(!park_place_take());
  park_places_set_limit(1u << 31);                           /* (a limit that does not fit is capped, not negative) */
  CHECK(park_place_take());
  park_place_give();
  park_places_set_limit(INT32_MAX);
  CHECK(park_places_used() == 0);
  /* park_place_avail(): is a place free (nothing is taken) */
  park_places_set_limit(2);
  CHECK(park_place_avail() && park_place_take() && park_place_avail() && park_place_take() && !park_place_avail() && park_places_used() == 2);
  park_place_give();
  CHECK(park_place_avail() && park_places_used() == 1);
  park_place_give();
  park_places_set_limit(1);
  CHECK(park_place_take() && !park_place_avail());
  park_place_give();
  park_places_set_limit(INT32_MAX);
}

/* the bucket: the fill by time, the burst, the half-full rule for the background work, a token given back, the wrap of the 32-bit clock, a clock that is a little behind */
static void test_rate(void) {
  printf("[admission gate: the fetch-rate bucket]\n");
  park_rate_set(0);
  CHECK(park_rate_take(5000, false) && park_rate_take(5000, true) && park_rate_check(5000, true) && park_rate_level(5000) == 0);   /* (no rate: no limit) */
  /* 0.7 P-A: with no rate (the default) a take is one load and returns: the word of the bucket is never written (no compare-and-swap on the query path), however many take */
  park_rate_reset();
  bool all_ok = true;
  for (int i = 0; i < 100000; i++) all_ok = park_rate_take(7000 + i, i % 2 == 0) && all_ok;
  CHECK(all_ok);
  park_rate_give();
  park_rate_set(10);                                                     /* no reset: a bucket that was never used is full */
  CHECK(park_rate_level(9000) == 10000);
  park_rate_reset();
  const int64_t t = 1000000;

  CHECK(park_rate_level(t) == 10000);                                    /* a new bucket is full: one second of the rate */
  for (int i = 0; i < 10; i++) CHECK(park_rate_take(t, false));
  CHECK(!park_rate_take(t, false) && park_rate_level(t) == 0);
  CHECK(!park_rate_take(t + 99, false) && park_rate_level(t + 99) == 990);   /* (a refusal writes nothing: the time still counts from t) */
  CHECK(park_rate_take(t + 100, false) && !park_rate_take(t + 100, false));  /* 10 per second: one token per 100 ms */
  CHECK(park_rate_level(t + 100 + 5000) == 10000);                       /* the burst is one second of the rate, however long it was idle */
  /* a token that was not used goes back (a read that was not made), up to the burst */
  park_rate_reset();
  CHECK(park_rate_take(t, false) && park_rate_level(t) == 9000);
  park_rate_give();
  CHECK(park_rate_level(t) == 10000);
  park_rate_give();
  park_rate_give();
  CHECK(park_rate_level(t) == 10000);
  /* half: the queries come first.  At least half full (and a whole token) for the warm-up, the summaries, the background requests */
  park_rate_set(100);
  park_rate_reset();
  for (int i = 0; i < 51; i++) CHECK(park_rate_take(t, false));          /* 49 tokens left of 100 */
  CHECK(!park_rate_check(t, true) && !park_rate_take(t, true));
  CHECK(park_rate_check(t, false) && park_rate_take(t, false));
  park_rate_give();
  park_rate_give();                                                      /* 50: half */
  CHECK(park_rate_check(t, true) && park_rate_take(t, true));
  park_rate_set(1);                                                      /* a rate of 1: half a token is not enough, one is: the rule is "a whole token" */
  park_rate_reset();
  CHECK(park_rate_take(t, true) && !park_rate_take(t, true) && !park_rate_take(t, false));
  /* the rate drops: the bucket cannot hold more than the new burst */
  park_rate_set(100);
  park_rate_reset();
  CHECK(park_rate_take(t, false));
  park_rate_set(10);
  CHECK(park_rate_level(t) == 10000);
  /* the low 32 bits of the clock wrap (after 49 days of uptime); a clock read a few ms before another thread's time is not a huge jump */
  park_rate_set(1000);
  park_rate_reset();
  const int64_t w0 = 0xFFFFFF00LL;
  for (int i = 0; i < 1000; i++) CHECK(park_rate_take(w0, false));
  CHECK(!park_rate_take(w0, false));
  CHECK(!park_rate_take(w0 - 5, false) && park_rate_level(w0 - 5) == 0);   /* (5 ms behind the stamp: nothing has passed) */
  const int64_t w1 = 0x100000000LL + 0x40;                               /* 0x140 = 320 ms later, across the wrap */
  CHECK(park_rate_level(w1) == 320000);
  for (int i = 0; i < 320; i++) CHECK(park_rate_take(w1, false));
  CHECK(!park_rate_take(w1, false));
  /* (B2 L1) a caller whose clock is seconds behind the stamp (it read the clock, lost the CPU, and another thread wrote a later time): nothing has passed for it.  The bucket
   * does not refill (it did when the lag was over 256 ms: the difference wrapped to about 2^32 ms) and the stamp does not move back */
  park_rate_set(10);
  park_rate_reset();
  for (int i = 0; i < 5; i++) CHECK(park_rate_take(t, false));           /* 5 left of 10, stamp t */
  CHECK(park_rate_level(t - 1500) == 5000 && park_rate_level(t - 2000) == 5000 && park_rate_level(t - 600000) == 5000);
  CHECK(park_rate_check(t - 1500, false) && park_rate_take(t - 1500, false) && park_rate_level(t) == 4000);      /* (a take from the past: 4, not 9) */
  CHECK(park_rate_level(t + 100) == 5000);                               /* (the stamp is still t: 100 ms at 10 a second is one token) */
  for (int i = 0; i < 4; i++) CHECK(park_rate_take(t, false));
  CHECK(!park_rate_take(t - 2000, false) && !park_rate_take(t, false));  /* (empty: the past does not fill it) */
  /* a stamp that is old, not ahead: idle for 25 days (the 32 bits of the clock have gone round past the half), the bucket is full again */
  CHECK(park_rate_level(t + 0x80000005LL) == 10000 && park_rate_take(t + 0x80000005LL, false));
  park_rate_set(0);
  park_rate_reset();
}

#define GTH 8
static _Atomic uint64_t g_gt_ok;
static void *rate_taker(void *arg) {
  (void)arg;
  for (int i = 0; i < 400; i++)
    if (park_rate_take(2000000, false)) atomic_fetch_add(&g_gt_ok, 1);
  return NULL;
}

static _Atomic int g_held, g_held_max, g_held_bad;
static _Atomic uint64_t g_pl_ok, g_pl_no;
#define PL_LIMIT 5
static void *place_user(void *arg) {
  (void)arg;
  for (int i = 0; i < 40000; i++) {
    if (park_place_take()) {
      int c = atomic_fetch_add(&g_held, 1) + 1;                          /* (the holders that this thread knows of: it must never be more than the limit) */
      if (c > PL_LIMIT) atomic_fetch_add(&g_held_bad, 1);
      int m = atomic_load(&g_held_max);
      while (c > m && !atomic_compare_exchange_weak(&g_held_max, &m, c)) {}
      atomic_fetch_add(&g_pl_ok, 1);
      if (i % 64 == 0) usleep(1);
      atomic_fetch_sub(&g_held, 1);
      park_place_give();
    } else {
      atomic_fetch_add(&g_pl_no, 1);
    }
  }
  return NULL;
}

/* the stress case: eight threads take and give places (never more holders than the limit, none lost) and take tokens from one bucket (exactly the burst) */
static void test_gate_stress(void) {
  printf("[admission gate: concurrent claims]\n");
  pthread_t th[GTH];
  park_places_set_limit(PL_LIMIT);
  for (int i = 0; i < GTH; i++) pthread_create(&th[i], NULL, place_user, NULL);
  for (int i = 0; i < GTH; i++) pthread_join(th[i], NULL);
  printf("  %llu places taken, %llu refused, at most %d held at once\n", (unsigned long long)atomic_load(&g_pl_ok), (unsigned long long)atomic_load(&g_pl_no), atomic_load(&g_held_max));
  CHECK(atomic_load(&g_held_bad) == 0 && atomic_load(&g_held_max) <= PL_LIMIT && atomic_load(&g_held_max) >= 2);
  CHECK(atomic_load(&g_pl_ok) > 0);        /* (refusals depend on the scheduling: a slow, instrumented build may see none; g_held_max shows the contention) */
  CHECK(park_places_used() == 0 && atomic_load(&g_held) == 0);
  park_places_set_limit(INT32_MAX);
  /* 1000 tokens in the bucket, no time passes: eight threads that try 400 times each get exactly 1000 */
  park_rate_set(1000);
  park_rate_reset();
  atomic_store(&g_gt_ok, 0);
  for (int i = 0; i < GTH; i++) pthread_create(&th[i], NULL, rate_taker, NULL);
  for (int i = 0; i < GTH; i++) pthread_join(th[i], NULL);
  CHECK(atomic_load(&g_gt_ok) == 1000);
  park_rate_set(0);
  park_rate_reset();
}

/* the claim bit travels with the request: a request of a worker comes out with claimed set, the plain priority and its ring; a request of a thread that is not a worker has none */
static void test_claim_ring(void) {
  printf("[admission gate: the claim on the request]\n");
  park_fetch_req_t q;
  park_register_worker(2, -1);
  while (park_fetch_next(&q)) {}
  CHECK(park_fetch_request(2, "v1", "c.test.", KDB_FETCH_PRIO_QUERY | PARK_PRIO_CLAIMED, KDB_FETCH_FULL));
  CHECK(park_fetch_request(2, "v1", "u.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(park_fetch_request_any("v1", "x.test.", KDB_FETCH_PRIO_BACKGROUND, KDB_FETCH_FULL));
  int seen = 0;
  while (park_fetch_next(&q)) {
    if (strcmp(q.zone, "c.test.") == 0) seen += (q.claimed && q.prio == KDB_FETCH_PRIO_QUERY && q.worker == 2 && q.mode == KDB_FETCH_FULL) ? 1 : 100;
    else if (strcmp(q.zone, "u.test.") == 0) seen += (!q.claimed && q.prio == KDB_FETCH_PRIO_QUERY && q.worker == 2) ? 2 : 100;
    else if (strcmp(q.zone, "x.test.") == 0) seen += (!q.claimed && q.prio == KDB_FETCH_PRIO_BACKGROUND && q.worker == -1) ? 4 : 100;
    else seen += 1000;
  }
  CHECK(seen == 7);
  /* the raw ring keeps the bit, park_fetch_next() takes it off */
  CHECK(park_fetch_request(2, "v1", "c.test.", KDB_FETCH_PRIO_WARM | PARK_PRIO_CLAIMED, KDB_FETCH_FULL));
  CHECK(park_fetch_pop(park_fetch_ring(2), &q) && q.prio == (KDB_FETCH_PRIO_WARM | PARK_PRIO_CLAIMED));
  /* a claim that was not used: the mark goes, and nothing else is touched (a worker holds neither a place nor a token any more: 0.7 P-B) */
  park_places_set_limit(2);
  park_rate_set(10);
  park_rate_reset();
  uint64_t ck = park_claim_key("v1", "c.test.");
  CHECK(park_claim_mark(ck) && park_claim_held(ck));
  park_claim_release("v1", "c.test.");
  CHECK(!park_claim_held(ck) && park_places_used() == 0 && park_rate_level(1000) == 10000);
  park_places_set_limit(INT32_MAX);
  park_rate_set(0);
  park_rate_reset();
  park_unregister_worker(2);
}

#ifdef __FreeBSD__
static int kq_events(int kq) {
  struct kevent ev[4];
  struct timespec z = { 0, 0 };
  return kevent(kq, NULL, 0, ev, 4, &z);
}
static int kq_make(unsigned ident) {
  int kq = kqueue();
  struct kevent ev;
  EV_SET(&ev, ident, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kq >= 0 && kevent(kq, &ev, 1, NULL, 0, NULL) != 0) {
    close(kq);
    return -1;
  }
  return kq;
}

/* the keys go into the ring at once; the trigger comes with park_wake_flush(), once per worker; one worker's key reaches that worker alone */
static void test_wake_queue(void) {
  printf("[wake: one worker, and one trigger per worker]\n");
  int kq6 = kq_make(PARK_WAKE_IDENT), kq7 = kq_make(PARK_WAKE_IDENT);
  CHECK(kq6 >= 0 && kq7 >= 0);
  park_register_worker(6, kq6);
  park_register_worker(7, kq7);
  park_key_t k;
  while (park_wake_pop(park_wake_ring(6), &k)) {}
  while (park_wake_pop(park_wake_ring(7), &k)) {}
  park_wake_flush();
  (void)kq_events(kq6);
  (void)kq_events(kq7);
  park_wake_queue_one(6, "v1", "a.test.", false);
  park_wake_queue_one(6, "v1", "b.test.", true);
  park_wake_queue_one(-1, "v1", "none.test.", true);                   /* a thread that is not a worker: nobody waits */
  park_wake_queue_one(PARK_MAX_WORKERS + 1, "v1", "none.test.", true);
  park_wake_queue_one(40, "v1", "none.test.", true);                   /* (not registered) */
  CHECK(kq_events(kq6) == 0 && kq_events(kq7) == 0);                   /* the keys are in the ring, nobody was triggered yet */
  CHECK(park_wake_pending(park_wake_ring(6)) && !park_wake_pending(park_wake_ring(7)));
  park_wake_flush();
  CHECK(kq_events(kq6) == 1 && kq_events(kq7) == 0);                   /* worker 6 once (for two keys), worker 7 not at all */
  CHECK(park_wake_pop(park_wake_ring(6), &k) && strcmp(k.zone, "a.test.") == 0 && !k.failed);
  CHECK(park_wake_pop(park_wake_ring(6), &k) && strcmp(k.zone, "b.test.") == 0 && k.failed);
  CHECK(!park_wake_pop(park_wake_ring(6), &k) && !park_wake_pop(park_wake_ring(7), &k));
  park_wake_flush();                                                   /* nothing queued since: no trigger */
  CHECK(kq_events(kq6) == 0 && kq_events(kq7) == 0);
  park_wake_queue_all("v1", "c.test.", false);
  CHECK(kq_events(kq6) == 0 && kq_events(kq7) == 0);
  park_wake_flush();
  CHECK(kq_events(kq6) == 1 && kq_events(kq7) == 1);
  CHECK(park_wake_pop(park_wake_ring(6), &k) && strcmp(k.zone, "c.test.") == 0 && park_wake_pop(park_wake_ring(7), &k) && strcmp(k.zone, "c.test.") == 0);
  park_wake_broadcast("v1", "d.test.", false);                         /* the old call: key and trigger at once */
  CHECK(kq_events(kq6) == 1 && kq_events(kq7) == 1);
  CHECK(park_wake_pop(park_wake_ring(6), &k) && park_wake_pop(park_wake_ring(7), &k));
  park_unregister_worker(7);
  park_wake_queue_one(7, "v1", "e.test.", false);                      /* gone: no key, no trigger */
  park_wake_flush();
  CHECK(!park_wake_pop(park_wake_ring(7), &k) && kq_events(kq7) == 0);
  park_unregister_worker(6);
  close(kq6);
  close(kq7);
}

/* the sleep protocol: a worker triggers only while the ingest thread may be asleep */
static void test_sleep_protocol(void) {
  printf("[sleep protocol: a trigger only when the ingest thread may be asleep]\n");
  int ikq = kq_make(PARK_FETCH_IDENT);
  CHECK(ikq >= 0);
  park_fetch_set_notify(ikq);
  park_register_worker(6, -1);
  park_fetch_req_t q;
  while (park_fetch_next(&q)) {}
  CHECK(!park_fetch_pending());
  CHECK(park_fetch_request(6, "v1", "s1.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(kq_events(ikq) == 0);                                          /* the thread is awake: no system call for it */
  CHECK(park_fetch_pending() && park_fetch_sleep_prepare());           /* a request is there: it must not sleep, and it is not marked asleep */
  CHECK(park_fetch_request(6, "v1", "s2.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) && kq_events(ikq) == 0);
  while (park_fetch_next(&q)) {}
  CHECK(!park_fetch_pending() && !park_fetch_sleep_prepare());         /* nothing: it sleeps, and says so */
  CHECK(park_fetch_request(6, "v1", "s3.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL));
  CHECK(kq_events(ikq) == 1);                                          /* ... so a request wakes it */
  park_fetch_sleep_done();
  CHECK(park_fetch_request(6, "v1", "s4.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) && kq_events(ikq) == 0);
  while (park_fetch_next(&q)) {}
  /* a slot of a transfer thread (and park_bg_fetch(), which uses one) follows the same rule */
  CHECK(!park_fetch_sleep_prepare());
  CHECK(park_fetch_request_any("v1", "x1.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) && kq_events(ikq) == 1);
  park_fetch_sleep_done();
  CHECK(park_fetch_request_any("v1", "x2.test.", KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) && kq_events(ikq) == 0);
  CHECK(park_fetch_pending() && park_fetch_sleep_prepare());           /* (a slot that is ready is a request too) */
  while (park_fetch_next(&q)) {}
  CHECK(!park_fetch_pending());
  park_fetch_sleep_done();
  park_unregister_worker(6);
  park_fetch_set_notify(-1);
  close(ikq);
}

/* the race: producers push requests while the ingest side goes to sleep.  The consumer waits for a trigger with a timeout, and finds a request pending after a timeout
 * without the trigger having come: that is a lost wake-up.  (Without the fences of the protocol this shows up in the first seconds.) */
#define SP_PROD 3
#define SP_N 6000
static int g_sp_kq;
static _Atomic uint64_t g_sp_lost, g_sp_consumed, g_sp_sleeps;
static void *sp_producer(void *arg) {
  int w = 10 + (int)(intptr_t)arg;
  unsigned seed = (unsigned)w * 2654435761u;
  char zn[32];
  for (int i = 0; i < SP_N; i++) {
    snprintf(zn, sizeof(zn), "p%d-%d.test.", w, i);
    while (!park_fetch_request(w, "v1", zn, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL)) usleep(50);
    seed = seed * 1103515245u + 12345u;
    if ((seed >> 16) % 5 == 0) usleep((seed >> 8) % 300);             /* (gaps: the consumer runs dry and goes to sleep) */
  }
  return NULL;
}
static void test_sleep_race(void) {
  printf("[sleep protocol: producers against a consumer that goes to sleep]\n");
  g_sp_kq = kq_make(PARK_FETCH_IDENT);
  CHECK(g_sp_kq >= 0);
  park_fetch_set_notify(g_sp_kq);
  pthread_t th[SP_PROD];
  for (int i = 0; i < SP_PROD; i++) park_register_worker(10 + i, -1);
  atomic_store(&g_sp_lost, 0);
  atomic_store(&g_sp_consumed, 0);
  atomic_store(&g_sp_sleeps, 0);
  for (long i = 0; i < SP_PROD; i++) pthread_create(&th[i], NULL, sp_producer, (void *)(intptr_t)i);
  park_fetch_req_t q;
  const uint64_t total = (uint64_t)SP_PROD * SP_N;
  while (atomic_load(&g_sp_consumed) < total) {
    while (park_fetch_next(&q)) atomic_fetch_add(&g_sp_consumed, 1);
    if (atomic_load(&g_sp_consumed) >= total) break;
    if (park_fetch_sleep_prepare()) continue;
    struct kevent ev;
    struct timespec ts = { 0, 300 * 1000000L };
    atomic_fetch_add(&g_sp_sleeps, 1);
    int n = kevent(g_sp_kq, NULL, 0, &ev, 1, &ts);
    park_fetch_sleep_done();
    if (n == 0 && park_fetch_pending()) {                              /* the time ran out with a request waiting: was a trigger on its way? */
      usleep(20000);
      if (kq_events(g_sp_kq) == 0) atomic_fetch_add(&g_sp_lost, 1);
    }
  }
  for (int i = 0; i < SP_PROD; i++) pthread_join(th[i], NULL);
  printf("  %llu requests, the consumer slept %llu times, %llu lost wake-ups\n", (unsigned long long)atomic_load(&g_sp_consumed), (unsigned long long)atomic_load(&g_sp_sleeps),
         (unsigned long long)atomic_load(&g_sp_lost));
  CHECK(atomic_load(&g_sp_consumed) == total && atomic_load(&g_sp_lost) == 0 && atomic_load(&g_sp_sleeps) > 10);
  for (int i = 0; i < SP_PROD; i++) park_unregister_worker(10 + i);
  park_fetch_set_notify(-1);
  close(g_sp_kq);
}
#endif
/* (B2 M1) the claim marks: one worker holds the claim for a zone, the others find it; a view is part of the key; a mark is cleared by the key; a window with no room, two
 * marks for one zone, and the threads that race for one zone: exactly one wins */
static _Atomic int g_cl_won;
static _Atomic bool g_cl_go;
static void *claim_racer(void *arg) {
  (void)arg;
  while (!atomic_load(&g_cl_go)) {}
  if (park_claim_mark(park_claim_key("v1", "race.test."))) atomic_fetch_add(&g_cl_won, 1);
  return NULL;
}

static void test_claims(void) {
  printf("[admission gate: the claim marks of a zone]\n");
  uint64_t a = park_claim_key("v1", "a.test."), b = park_claim_key("v2", "a.test."), c = park_claim_key("v1", "b.test.");
  CHECK(a != 0 && b != 0 && c != 0 && a != b && a != c);
  CHECK(a == park_claim_key("v1", "A.TEST."));                           /* (the zone's case does not matter: the directory's name and the request's are one) */
  CHECK(!park_claim_held(a) && !park_claim_held(b));
  CHECK(park_claim_mark(a) && park_claim_held(a) && !park_claim_held(b) && !park_claim_held(c));
  CHECK(!park_claim_mark(a));                                            /* (marked already: the second worker does not hold the claim) */
  CHECK(park_claim_mark(b) && park_claim_mark(c) && park_claim_held(b) && park_claim_held(c));
  park_claim_clear(a);
  CHECK(!park_claim_held(a) && park_claim_held(b) && park_claim_held(c));
  park_claim_clear(a);                                                   /* (clearing what is not marked does nothing) */
  CHECK(park_claim_mark(a) && !park_claim_mark(a));
  park_claim_clear(a);
  park_claim_clear(b);
  park_claim_clear(c);
  CHECK(!park_claim_held(a) && !park_claim_held(b) && !park_claim_held(c));
  /* the release of a claim that was not used: the mark goes, a place and a token that others hold are not touched (a worker holds neither: 0.7 P-B) */
  park_places_set_limit(2);
  park_rate_set(10);
  park_rate_reset();
  CHECK(park_place_take() && park_rate_take(1000, false) && park_claim_mark(a) && park_places_used() == 1 && park_rate_level(1000) == 9000);
  park_claim_release("v1", "a.test.");
  CHECK(park_places_used() == 1 && park_rate_level(1000) == 9000 && !park_claim_held(a));
  park_place_give();
  park_rate_give();
  park_places_set_limit(INT32_MAX);
  park_rate_set(0);
  park_rate_reset();
  /* no room: the slots a key may use (a window of 8) are all taken by other zones: the claim stands without a mark (true), the zone cannot be found held, and the clear finds nothing */
  {
    enum { N = 4096 };
    static uint64_t keys[N];
    int used = 0, nk = 0;
    for (; nk < N && used < 600; nk++) {
      char z[32];
      snprintf(z, sizeof(z), "fill%d.test.", nk);
      keys[nk] = park_claim_key("v1", z);
      if (park_claim_mark(keys[nk])) used++;
    }
    /* 600 marks in 1024 slots: some window is full; find a zone whose mark was not made although it was not held */
    int nomark = 0;
    for (int i = 0; i < nk; i++) {
      if (!park_claim_held(keys[i])) {
        CHECK(park_claim_mark(keys[i]));                                 /* (true: the claim is taken, no matter that there was no room for the mark) */
        if (!park_claim_held(keys[i])) nomark++;
        park_claim_clear(keys[i]);                                       /* (harmless) */
      }
    }
    for (int i = 0; i < nk; i++) park_claim_clear(keys[i]);
    for (int i = 0; i < nk; i++) CHECK(!park_claim_held(keys[i]));
    printf("  %d marks set, %d claims without room for a mark\n", used, nomark);
  }
  /* sixteen threads against one zone: one holds the claim, and when it is cleared one more can */
  pthread_t th[16];
  atomic_store(&g_cl_won, 0);
  atomic_store(&g_cl_go, false);
  for (int i = 0; i < 16; i++) pthread_create(&th[i], NULL, claim_racer, NULL);
  atomic_store(&g_cl_go, true);
  for (int i = 0; i < 16; i++) pthread_join(th[i], NULL);
  CHECK(atomic_load(&g_cl_won) == 1 && park_claim_held(park_claim_key("v1", "race.test.")));
  park_claim_clear(park_claim_key("v1", "race.test."));
  CHECK(!park_claim_held(park_claim_key("v1", "race.test.")) && park_claim_mark(park_claim_key("v1", "race.test.")));
  park_claim_clear(park_claim_key("v1", "race.test."));
}

int main(void) {
  test_table();
  test_tcp();
  test_rings();
  test_concurrent();
  test_any();
  test_slots_not_starved();
  test_stats();
  test_places();
  test_rate();
  test_gate_stress();
  test_claim_ring();
  test_claims();
#ifdef __FreeBSD__
  test_wake_queue();
  test_sleep_protocol();
  test_sleep_race();
#endif
  printf("\n%d checks, %d failed\n", g_checks, g_failed);
  if (g_failed) return 1;
  printf("=== test_park: all checks passed ===\n");
  return 0;
}

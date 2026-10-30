/*
 * test_park.c - the park table, the wake rings and the fetch rings (dns_park.c, D1a milestone 2).
 *
 * Single threaded cases for every rule of the table (full, too big, timeout, wake by key, generation mismatch, TCP cancel), then a
 * concurrency case: three workers (one table each) park queries while one "ingest" thread wakes them through the rings and takes
 * their fetch requests.  Under ThreadSanitizer (make test_park-tsan) it shows that the rings hand data over correctly, under
 * AddressSanitizer (make test_park-asan) that nothing is touched out of bounds.  Every parked query ends exactly once: answered after
 * a wake, answered after its timeout, or cancelled.
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
  /* four producers, one consumer: every request arrives once, whole */
  pthread_t th[AW], cons;
  pthread_create(&cons, NULL, any_consumer, NULL);
  for (long i = 0; i < AW; i++) pthread_create(&th[i], NULL, any_producer, (void *)(intptr_t)i);
  for (int i = 0; i < AW; i++) pthread_join(th[i], NULL);
  pthread_join(cons, NULL);
  CHECK(atomic_load(&g_any_taken) == (uint64_t)AW * AN);
}

int main(void) {
  test_table();
  test_tcp();
  test_rings();
  test_concurrent();
  test_any();
  printf("\n%d checks, %d failed\n", g_checks, g_failed);
  if (g_failed) return 1;
  printf("=== test_park: all checks passed ===\n");
  return 0;
}

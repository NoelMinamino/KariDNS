/*
 * Epoch RCU (dns_epoch_rcu.c) unit tests — R-25.
 *
 *  1. rcu_writer_publish(): the new pointer is visible before the epoch moves,
 *     and the returned retire epoch is the pre-publish epoch.
 *  2. A reader that entered before the publish blocks rcu_writer_wait_until_safe(retire);
 *     a reader that enters after it does not, and sees the new pointer.
 *  3. Auxiliary reader slots: nesting, pinning and slot release.
 *  4. Concurrent double-buffer stress (the arena / config pattern): the writer
 *     reuses the retired buffer only after the grace period and poisons it first,
 *     so a reader that is not protected sees the poison. Run under
 *     test_epoch_rcu-tsan as well.
 */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#include "dns_epoch_rcu.h"

_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);

#define STRESS_READERS 3
#define STRESS_ROUNDS 3000

/* worker_ctx_t は大きい (ログ用リングを含む) ので静的領域に置く */
static worker_ctx_t g_test_workers[STRESS_READERS];

static int count_aux_slots_in_use(void) {
  int n = 0;
  for (int i = 0; i < MAX_AUX_RCU_READERS; i++) {
    if (atomic_load_explicit(&g_aux_rcu_slots[i].in_use, memory_order_acquire)) n++;
  }
  return n;
}

static void register_workers(int n) {
  for (int i = 0; i < n; i++) {
    atomic_init(&g_test_workers[i].rcu_observed_epoch, RCU_EPOCH_IDLE);
  }
  atomic_store_explicit(&g_worker_ctxs, g_test_workers, memory_order_release);
  atomic_store_explicit(&g_worker_count, n, memory_order_release);
}

static void unregister_workers(void) {
  atomic_store_explicit(&g_worker_count, 0, memory_order_release);
  atomic_store_explicit(&g_worker_ctxs, NULL, memory_order_release);
}

static void test_publish_order(void) {
  printf("[TEST] rcu_writer_publish: publish before advancing the epoch...\n");
  static int obj_a = 1, obj_b = 2;
  static _Atomic(int *) slot;
  atomic_init(&slot, &obj_a);
  register_workers(1);
  worker_ctx_t *r = &g_test_workers[0];

  // A reader enters and loads the current object before the publish.
  rcu_reader_enter(r);
  int *seen_old = atomic_load_explicit(&slot, memory_order_acquire);
  assert(seen_old == &obj_a);

  uint64_t before = atomic_load_explicit(&g_global_epoch, memory_order_acquire);
  uint64_t retire = rcu_writer_publish(&slot, &obj_b);
  assert(retire == before);
  assert(atomic_load_explicit(&g_global_epoch, memory_order_acquire) == retire + 1);
  assert(atomic_load_explicit(&slot, memory_order_acquire) == &obj_b);

  // The early reader may still hold obj_a: the grace period must not end.
  assert(rcu_writer_wait_until_safe(retire, 20) == false);
  rcu_reader_exit(r);
  assert(rcu_writer_wait_until_safe(retire, 50) == true);

  // A reader that enters after the publish observes retire + 1 and the new object,
  // and does not delay the writer.
  rcu_reader_enter(r);
  assert(atomic_load_explicit(&r->rcu_observed_epoch, memory_order_acquire) == retire + 1);
  assert(atomic_load_explicit(&slot, memory_order_acquire) == &obj_b);
  assert(rcu_writer_wait_until_safe(retire, 50) == true);
  rcu_reader_exit(r);

  unregister_workers();
  printf("  [PASS] new pointer visible before the epoch moves; early reader blocks, late reader does not\n");
}

static void test_aux_slots(void) {
  printf("[TEST] auxiliary reader slots: nesting, pinning, release...\n");
  int base = count_aux_slots_in_use();

  // Unpinned: a slot is held only while a section is open.
  rcu_aux_read_lock();
  assert(count_aux_slots_in_use() == base + 1);
  uint64_t e = atomic_load_explicit(&g_global_epoch, memory_order_acquire);
  rcu_aux_read_lock();                 // nested section keeps the outer epoch
  rcu_writer_advance_epoch();
  rcu_aux_read_unlock();
  assert(count_aux_slots_in_use() == base + 1);
  assert(rcu_writer_wait_until_safe(e, 20) == false);
  rcu_aux_read_unlock();
  assert(count_aux_slots_in_use() == base);
  assert(rcu_writer_wait_until_safe(e, 50) == true);

  // Pinned: the slot survives sections and is released by unpin.
  rcu_aux_thread_pin();
  assert(count_aux_slots_in_use() == base + 1);
  rcu_aux_read_lock();
  e = atomic_load_explicit(&g_global_epoch, memory_order_acquire);
  assert(rcu_writer_wait_until_safe(e, 20) == false);
  rcu_aux_read_unlock();
  assert(count_aux_slots_in_use() == base + 1);
  assert(rcu_writer_wait_until_safe(e, 50) == true);
  rcu_aux_thread_unpin();
  assert(count_aux_slots_in_use() == base);

  // Unbalanced unlock is ignored.
  rcu_aux_read_unlock();
  assert(count_aux_slots_in_use() == base);
  printf("  [PASS] nesting keeps the outer epoch; slots are released on exit / unpin\n");
}

/* --- concurrent stress: double buffer reused after the grace period --------- */

#define BUF_WORDS 64
#define POISON 0xDEADDEADu

typedef struct {
  unsigned words[BUF_WORDS];
} test_buf_t;

static test_buf_t g_bufs[2];
static _Atomic(test_buf_t *) g_active_buf;
static _Atomic bool g_stop;
static _Atomic unsigned long g_bad_reads;
static _Atomic unsigned long g_reads;

static void fill_buf(test_buf_t *b, unsigned gen) {
  for (int i = 0; i < BUF_WORDS; i++) b->words[i] = gen;
}

static bool check_buf(const test_buf_t *b) {
  unsigned first = b->words[0];
  if (first == POISON) return false;
  for (int i = 1; i < BUF_WORDS; i++) {
    if (b->words[i] != first) return false;
  }
  return true;
}

typedef struct {
  worker_ctx_t *ctx;   // NULL: use an auxiliary slot
} reader_arg_t;

static void *stress_reader(void *arg) {
  reader_arg_t *ra = (reader_arg_t *)arg;
  while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
    if (ra->ctx) rcu_reader_enter(ra->ctx); else rcu_aux_read_lock();
    test_buf_t *b = atomic_load_explicit(&g_active_buf, memory_order_acquire);
    if (!check_buf(b)) atomic_fetch_add_explicit(&g_bad_reads, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_reads, 1, memory_order_relaxed);
    if (ra->ctx) rcu_reader_exit(ra->ctx); else rcu_aux_read_unlock();
  }
  return NULL;
}

static void test_concurrent_reuse(void) {
  printf("[TEST] concurrent publish / grace period / reuse of the retired buffer...\n");
  register_workers(STRESS_READERS - 1);
  fill_buf(&g_bufs[0], 0);
  atomic_init(&g_active_buf, &g_bufs[0]);
  atomic_store(&g_stop, false);
  atomic_store(&g_bad_reads, 0);
  atomic_store(&g_reads, 0);

  pthread_t th[STRESS_READERS];
  reader_arg_t args[STRESS_READERS];
  for (int i = 0; i < STRESS_READERS; i++) {
    // the last reader uses an auxiliary slot (control / transfer thread path)
    args[i].ctx = (i < STRESS_READERS - 1) ? &g_test_workers[i] : NULL;
    assert(pthread_create(&th[i], NULL, stress_reader, &args[i]) == 0);
  }

  // Start publishing only after every reader has read at least once, so that a
  // loaded machine cannot finish all rounds before the readers are scheduled.
  while (atomic_load(&g_reads) < STRESS_READERS) sched_yield();

  uint64_t retire = 0;
  bool have_retire = false;
  for (unsigned gen = 1; gen <= STRESS_ROUNDS; gen++) {
    test_buf_t *cur = atomic_load_explicit(&g_active_buf, memory_order_acquire);
    test_buf_t *standby = (cur == &g_bufs[0]) ? &g_bufs[1] : &g_bufs[0];
    // Same order as the arena writers: wait for the previous retire epoch,
    // then overwrite the standby buffer.
    if (have_retire) assert(rcu_writer_wait_until_safe(retire, 10000));
    for (int i = 0; i < BUF_WORDS; i++) standby->words[i] = POISON;
    fill_buf(standby, gen);
    retire = rcu_writer_publish(&g_active_buf, standby);
    have_retire = true;
  }

  atomic_store_explicit(&g_stop, true, memory_order_release);
  for (int i = 0; i < STRESS_READERS; i++) pthread_join(th[i], NULL);
  unregister_workers();

  unsigned long bad = atomic_load(&g_bad_reads);
  unsigned long reads = atomic_load(&g_reads);
  printf("  reads=%lu inconsistent=%lu\n", reads, bad);
  assert(reads > 0);
  assert(bad == 0);
  assert(count_aux_slots_in_use() == 0);
  printf("  [PASS] no reader observed a buffer that was being reused\n");
}

int main(void) {
  printf("=== Epoch RCU tests (R-25) ===\n");
  test_publish_order();
  test_aux_slots();
  test_concurrent_reuse();
  printf("=== All Epoch RCU tests passed ===\n");
  return 0;
}

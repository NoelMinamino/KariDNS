#include "dns_epoch_rcu.h"
#include "dns_server_internal.h"
#include <sched.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

_Atomic uint64_t g_global_epoch = ATOMIC_VAR_INIT(0);
rcu_reader_slot_t g_resp_logger_rcu_ctx = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) };
rcu_reader_slot_t g_query_logger_rcu_ctx = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) };

rcu_reader_slot_t g_async_io_rcu_ctxs[MAX_ASYNC_IO_RCU_WORKERS] = {
    [0 ... MAX_ASYNC_IO_RCU_WORKERS - 1] = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) }
};
int g_async_io_rcu_worker_count = MAX_ASYNC_IO_RCU_WORKERS;

rcu_aux_slot_t g_aux_rcu_slots[MAX_AUX_RCU_READERS] = {
    [0 ... MAX_AUX_RCU_READERS - 1] = { .observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE),
                                        .in_use = ATOMIC_VAR_INIT(false) }
};

_Thread_local _Atomic uint64_t *t_rcu_own_observed = NULL;

static _Thread_local rcu_aux_slot_t *t_aux_slot = NULL;
static _Thread_local int t_aux_depth = 0;
static _Thread_local bool t_aux_pinned = false;

void rcu_exponential_backoff(int *retries, useconds_t *sleep_time) {
  if (*retries < 100) {
    sched_yield();
  } else {
    usleep(*sleep_time);
    if (*sleep_time < 100000) *sleep_time *= 2;
  }
  (*retries)++;
}

uint64_t rcu_writer_advance_epoch(void) {
  uint64_t retire = atomic_fetch_add_explicit(&g_global_epoch, 1, memory_order_seq_cst);
  // rcu_epoch_enter() のフェンスと対になる。直前の公開 (store) を、この後の
  // rcu_observed_epoch の走査より前に全スレッドへ見せる。
  atomic_thread_fence(memory_order_seq_cst);
  return retire;
}

static bool epoch_blocks(_Atomic uint64_t *observed, uint64_t retire_epoch, _Atomic uint64_t *skip) {
  if (observed == skip) return false;
  uint64_t obs = atomic_load_explicit(observed, memory_order_acquire);
  return obs != RCU_EPOCH_IDLE && obs <= retire_epoch;
}

static bool wait_until_safe_impl(uint64_t retire_epoch, int timeout_ms, _Atomic uint64_t *skip);

bool rcu_writer_wait_until_safe(uint64_t retire_epoch, int timeout_ms) {
  return wait_until_safe_impl(retire_epoch, timeout_ms, NULL);
}

bool rcu_writer_wait_until_safe_in_reader(uint64_t retire_epoch, int timeout_ms) {
  return wait_until_safe_impl(retire_epoch, timeout_ms, t_rcu_own_observed);
}

static bool wait_until_safe_impl(uint64_t retire_epoch, int timeout_ms, _Atomic uint64_t *skip) {
  int retries = 0;
  useconds_t sleep_time = 1;
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);

  for (;;) {
    // 公開したスレッドと待つスレッドが異なる場合 (GC スレッド) にも、
    // 公開と走査の間に seq_cst フェンスを置く。
    atomic_thread_fence(memory_order_seq_cst);
    bool all_safe = true;
    int num_workers = atomic_load_explicit(&g_worker_count, memory_order_acquire);
    worker_ctx_t *workers = atomic_load_explicit(&g_worker_ctxs, memory_order_acquire);

    if (workers && num_workers > 0) {
      for (int i = 0; i < num_workers; i++) {
        if (epoch_blocks(&workers[i].rcu_observed_epoch, retire_epoch, skip)) {
          all_safe = false;
          break;
        }
      }
    }

    if (all_safe && epoch_blocks(&g_resp_logger_rcu_ctx.rcu_observed_epoch, retire_epoch, skip)) {
      all_safe = false;
    }
    if (all_safe && epoch_blocks(&g_query_logger_rcu_ctx.rcu_observed_epoch, retire_epoch, skip)) {
      all_safe = false;
    }
    if (all_safe && g_async_io_rcu_worker_count > 0) {
      for (int i = 0; i < g_async_io_rcu_worker_count; i++) {
        if (epoch_blocks(&g_async_io_rcu_ctxs[i].rcu_observed_epoch, retire_epoch, skip)) {
          all_safe = false;
          break;
        }
      }
    }
    if (all_safe) {
      for (int i = 0; i < MAX_AUX_RCU_READERS; i++) {
        if (epoch_blocks(&g_aux_rcu_slots[i].observed_epoch, retire_epoch, skip)) {
          all_safe = false;
          break;
        }
      }
    }

    if (all_safe) {
      return true;
    }

    rcu_exponential_backoff(&retries, &sleep_time);

    if (sleep_time >= 100000 && (retries % 10) == 0) {
      syslog(LOG_WARNING, "[EpochRCU] wait_until_safe stalled (retire_epoch=%" PRIu64 ")",
             retire_epoch);
    }

    if (timeout_ms > 0) {
      clock_gettime(CLOCK_MONOTONIC, &now);
      int64_t elapsed_ms = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
                           (int64_t)(now.tv_nsec - start.tv_nsec) / 1000000;
      if (elapsed_ms >= timeout_ms) {
        syslog(LOG_WARNING, "[EpochRCU] wait_until_safe timed out after %d ms (retire_epoch=%" PRIu64 ")",
               timeout_ms, retire_epoch);
        return false;
      }
    }
  }
}

static rcu_aux_slot_t *aux_slot_claim(void) {
  int retries = 0;
  useconds_t sleep_time = 1;
  bool warned = false;
  for (;;) {
    for (int i = 0; i < MAX_AUX_RCU_READERS; i++) {
      bool expected = false;
      if (!atomic_load_explicit(&g_aux_rcu_slots[i].in_use, memory_order_relaxed) &&
          atomic_compare_exchange_strong_explicit(&g_aux_rcu_slots[i].in_use, &expected, true,
                                                  memory_order_acquire, memory_order_relaxed)) {
        return &g_aux_rcu_slots[i];
      }
    }
    if (!warned) {
      syslog(LOG_WARNING, "[EpochRCU] all %d auxiliary reader slots are in use; waiting", MAX_AUX_RCU_READERS);
      warned = true;
    }
    rcu_exponential_backoff(&retries, &sleep_time);
  }
}

static void aux_slot_release(rcu_aux_slot_t *slot) {
  atomic_store_explicit(&slot->in_use, false, memory_order_release);
}

void rcu_aux_thread_pin(void) {
  if (t_aux_pinned) return;
  if (!t_aux_slot) t_aux_slot = aux_slot_claim();
  t_aux_pinned = true;
}

void rcu_aux_thread_unpin(void) {
  if (!t_aux_pinned) return;
  t_aux_pinned = false;
  if (t_aux_depth == 0 && t_aux_slot) {
    aux_slot_release(t_aux_slot);
    t_aux_slot = NULL;
  }
}

void rcu_aux_read_lock(void) {
  if (t_aux_depth++ > 0) return;
  if (!t_aux_slot) t_aux_slot = aux_slot_claim();
  rcu_epoch_enter(&t_aux_slot->observed_epoch);
}

void rcu_aux_read_unlock(void) {
  if (t_aux_depth <= 0) return;
  if (--t_aux_depth > 0) return;
  rcu_epoch_exit(&t_aux_slot->observed_epoch);
  if (!t_aux_pinned) {
    aux_slot_release(t_aux_slot);
    t_aux_slot = NULL;
  }
}

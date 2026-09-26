#include "dns_epoch_rcu.h"
#include "dns_server_internal.h"
#include <sched.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

_Atomic uint64_t g_global_epoch = ATOMIC_VAR_INIT(0);
worker_ctx_t g_resp_logger_rcu_ctx = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) };
worker_ctx_t g_query_logger_rcu_ctx = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) };

worker_ctx_t g_async_io_rcu_ctxs[MAX_ASYNC_IO_RCU_WORKERS] = {
    [0 ... MAX_ASYNC_IO_RCU_WORKERS - 1] = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) }
};
int g_async_io_rcu_worker_count = MAX_ASYNC_IO_RCU_WORKERS;

worker_ctx_t g_axfr_rcu_ctxs[MAX_AXFR_RCU_WORKERS] = {
    [0 ... MAX_AXFR_RCU_WORKERS - 1] = { .rcu_observed_epoch = ATOMIC_VAR_INIT(RCU_EPOCH_IDLE) }
};
int g_axfr_rcu_worker_count = MAX_AXFR_RCU_WORKERS;

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
  return atomic_fetch_add_explicit(&g_global_epoch, 1, memory_order_acq_rel);
}

bool rcu_writer_wait_until_safe(uint64_t retire_epoch, int timeout_ms) {
  int retries = 0;
  useconds_t sleep_time = 1;
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);

  for (;;) {
    bool all_safe = true;
    int num_workers = atomic_load_explicit(&g_worker_count, memory_order_acquire);
    worker_ctx_t *workers = atomic_load_explicit(&g_worker_ctxs, memory_order_acquire);

    if (workers && num_workers > 0) {
      for (int i = 0; i < num_workers; i++) {
        uint64_t obs = atomic_load_explicit(&workers[i].rcu_observed_epoch, memory_order_acquire);
        if (obs != RCU_EPOCH_IDLE && obs <= retire_epoch) {
          all_safe = false;
          break;
        }
      }
    }

    if (all_safe) {
      uint64_t obs_resp = atomic_load_explicit(&g_resp_logger_rcu_ctx.rcu_observed_epoch, memory_order_acquire);
      if (obs_resp != RCU_EPOCH_IDLE && obs_resp <= retire_epoch) {
        all_safe = false;
      }
    }
    if (all_safe) {
      uint64_t obs_query = atomic_load_explicit(&g_query_logger_rcu_ctx.rcu_observed_epoch, memory_order_acquire);
      if (obs_query != RCU_EPOCH_IDLE && obs_query <= retire_epoch) {
        all_safe = false;
      }
    }
    if (all_safe && g_async_io_rcu_worker_count > 0) {
      for (int i = 0; i < g_async_io_rcu_worker_count; i++) {
        uint64_t obs = atomic_load_explicit(&g_async_io_rcu_ctxs[i].rcu_observed_epoch, memory_order_acquire);
        if (obs != RCU_EPOCH_IDLE && obs <= retire_epoch) {
          all_safe = false;
          break;
        }
      }
    }
    if (all_safe && g_axfr_rcu_worker_count > 0) {
      for (int i = 0; i < g_axfr_rcu_worker_count; i++) {
        uint64_t obs = atomic_load_explicit(&g_axfr_rcu_ctxs[i].rcu_observed_epoch, memory_order_acquire);
        if (obs != RCU_EPOCH_IDLE && obs <= retire_epoch) {
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

#include "dns_epoch_rcu.h"
#include "dns_server_internal.h"
#include <sched.h>
#include "dns_log.h"
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>

/* (the [0 ... N - 1] range designators below are a GNU extension that both compilers of the project, clang and gcc, accept; C has no plain way to
 * initialise an array of RCU_EPOCH_IDLE = UINT64_MAX slots statically) */
_Atomic uint64_t g_global_epoch = 0;
rcu_reader_slot_t g_resp_logger_rcu_ctx = { .rcu_observed_epoch = RCU_EPOCH_IDLE };
rcu_reader_slot_t g_query_logger_rcu_ctx = { .rcu_observed_epoch = RCU_EPOCH_IDLE };

rcu_reader_slot_t g_async_io_rcu_ctxs[MAX_ASYNC_IO_RCU_WORKERS] = {
    [0 ... MAX_ASYNC_IO_RCU_WORKERS - 1] = { .rcu_observed_epoch = RCU_EPOCH_IDLE }
};
int g_async_io_rcu_worker_count = MAX_ASYNC_IO_RCU_WORKERS;

rcu_aux_slot_t g_aux_rcu_slots[MAX_AUX_RCU_READERS] = {
    [0 ... MAX_AUX_RCU_READERS - 1] = { .observed_epoch = RCU_EPOCH_IDLE,
                                        .in_use = false }
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

/* Precondition: the calling thread is in a worker / slot read section (rcu_reader_enter(), rcu_slot_reader_enter(); t_rcu_own_observed is its slot) and holds
 * no rcu_aux_read_lock() section: only the slot of t_rcu_own_observed is skipped, an auxiliary section of this same thread would be waited for.
 * The one caller, the UPDATE handler of a worker, takes none. */
bool rcu_writer_wait_until_safe_in_reader(uint64_t retire_epoch, int timeout_ms) {
  return wait_until_safe_impl(retire_epoch, timeout_ms, t_rcu_own_observed);
}

static bool readers_safe(uint64_t retire_epoch, _Atomic uint64_t *skip) {
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
  return all_safe;
}

/* 待たずに 1 回だけ調べる (S2: 制御スレッドの周期処理が解放待ちを処理するときに使う) */
bool rcu_writer_is_safe(uint64_t retire_epoch) {
  return readers_safe(retire_epoch, NULL);
}

static void blockers_add(char *buf, size_t len, size_t *off, int n, int first, const char *kind) {
  if (n == 0 || *off >= len) return;
  int w = first >= 0 ? snprintf(buf + *off, len - *off, "%s%d %s slot(s) (the first: %d)", *off ? ", " : "", n, kind, first)
                     : snprintf(buf + *off, len - *off, "%s%d %s slot(s)", *off ? ", " : "", n, kind);
  if (w > 0) *off += (size_t)w < len - *off ? (size_t)w : len - *off - 1;
}

/* R1 (0.7): which reader slots hold back the grace period of retire_epoch, by kind, as text for a warning ("1 worker slot(s) (the first: 3),
 * 1 auxiliary slot(s)").  -> the number of such slots (0: the grace period is over; buf is then "").  skip: a slot that is not counted (the waiting
 * worker's own, rcu_writer_wait_until_safe_in_reader(): it is never waited for), as readers_safe() skips it. */
static int describe_blockers(uint64_t retire_epoch, _Atomic uint64_t *skip, char *buf, size_t len) {
  int nw = 0, fw = -1, nlog = 0, nio = 0, fio = -1, naux = 0, faux = -1;
  atomic_thread_fence(memory_order_seq_cst);
  int num_workers = atomic_load_explicit(&g_worker_count, memory_order_acquire);
  worker_ctx_t *workers = atomic_load_explicit(&g_worker_ctxs, memory_order_acquire);
  if (workers)
    for (int i = 0; i < num_workers; i++)
      if (epoch_blocks(&workers[i].rcu_observed_epoch, retire_epoch, skip) && nw++ == 0) fw = i;
  if (epoch_blocks(&g_query_logger_rcu_ctx.rcu_observed_epoch, retire_epoch, skip)) nlog++;
  if (epoch_blocks(&g_resp_logger_rcu_ctx.rcu_observed_epoch, retire_epoch, skip)) nlog++;
  for (int i = 0; i < g_async_io_rcu_worker_count; i++)
    if (epoch_blocks(&g_async_io_rcu_ctxs[i].rcu_observed_epoch, retire_epoch, skip) && nio++ == 0) fio = i;
  for (int i = 0; i < MAX_AUX_RCU_READERS; i++)
    if (epoch_blocks(&g_aux_rcu_slots[i].observed_epoch, retire_epoch, skip) && naux++ == 0) faux = i;
  size_t off = 0;
  if (len) buf[0] = '\0';
  blockers_add(buf, len, &off, nw, fw, "worker");
  blockers_add(buf, len, &off, nlog, -1, "logger");
  blockers_add(buf, len, &off, nio, fio, "async I/O");
  blockers_add(buf, len, &off, naux, faux, "auxiliary (control, transfer or other thread)");
  return nw + nlog + nio + naux;
}

int rcu_describe_blockers(uint64_t retire_epoch, char *buf, size_t len) {
  return describe_blockers(retire_epoch, NULL, buf, len);
}

/* 猶予期間の待ちの 1 回の眠りの上限。読み手の区間は短い (問い合わせ 1 件、制御スレッドの tick 1 回) ので、
 * 眠りを倍々に伸ばし続けると (rcu_exponential_backoff は 131 ms まで) 数十 ms の読み手に 131 / 262 / 524 ms
 * 待つことになる: DB のゾーン 1 件の reload の BATCH_END (zone_retire_process(true)) がそれだった。1 ms 刻みなら
 * 読み手が抜けてから 1 ms 以内に戻る。待ちは稀なので CPU は問題にならない。 */
#define RCU_WAIT_SLEEP_MAX_US 1000u

static bool wait_until_safe_impl(uint64_t retire_epoch, int timeout_ms, _Atomic uint64_t *skip) {
  int retries = 0;
  useconds_t sleep_time = 1;
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int64_t next_stall_log_ms = 1000;

  for (;;) {
    bool all_safe = readers_safe(retire_epoch, skip);

    if (all_safe) {
      return true;
    }

    rcu_exponential_backoff(&retries, &sleep_time);
    if (sleep_time > RCU_WAIT_SLEEP_MAX_US) sleep_time = RCU_WAIT_SLEEP_MAX_US;

    if (sleep_time == RCU_WAIT_SLEEP_MAX_US || timeout_ms > 0) {
      clock_gettime(CLOCK_MONOTONIC, &now);
      int64_t elapsed_ms = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
                           (int64_t)(now.tv_nsec - start.tv_nsec) / 1000000;
      /* R1 (0.7): the first line after 1 s, then at most one a minute (it was one a second), naming the kinds of slot that hold the wait */
      if (elapsed_ms >= next_stall_log_ms) {
        next_stall_log_ms = elapsed_ms + 60000;
        char who[192];
        if (describe_blockers(retire_epoch, skip, who, sizeof(who)) == 0) snprintf(who, sizeof(who), "no reader now");
        syslog(LOG_WARNING, "[EpochRCU] wait_until_safe stalled for %" PRId64 " ms (retire_epoch=%" PRIu64 "; held by %s)",
               elapsed_ms, retire_epoch, who);
      }
      if (timeout_ms > 0 && elapsed_ms >= timeout_ms) {
        syslog(LOG_WARNING, "[EpochRCU] wait_until_safe timed out after %d ms (retire_epoch=%" PRIu64 ")",
               timeout_ms, retire_epoch);
        return false;
      }
    }
  }
}

/* A thread that ends while it still holds an auxiliary slot (pinned and never unpinned, or ended inside a section) gives the slot back here:
 * otherwise the slot would stay in use for good and, with an epoch in it, hold up every writer.  The key holds the slot of the thread. */
static pthread_key_t g_aux_slot_key;
static pthread_once_t g_aux_slot_key_once = PTHREAD_ONCE_INIT;

static void aux_slot_thread_exit(void *p) {
  rcu_aux_slot_t *slot = (rcu_aux_slot_t *)p;
  if (!slot) return;
  atomic_store_explicit(&slot->observed_epoch, RCU_EPOCH_IDLE, memory_order_release);
  atomic_store_explicit(&slot->in_use, false, memory_order_release);
}

static void aux_slot_key_create(void) {
  (void)pthread_key_create(&g_aux_slot_key, aux_slot_thread_exit);
}

static rcu_aux_slot_t *aux_slot_claim(void) {
  int retries = 0;
  useconds_t sleep_time = 1;
  struct timespec t0, tn;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  int64_t next_warn_s = 0;   /* seconds after t0 of the next warning: at once, then every 10 s while the wait goes on */
  for (;;) {
    for (int i = 0; i < MAX_AUX_RCU_READERS; i++) {
      bool expected = false;
      if (!atomic_load_explicit(&g_aux_rcu_slots[i].in_use, memory_order_relaxed) &&
          atomic_compare_exchange_strong_explicit(&g_aux_rcu_slots[i].in_use, &expected, true,
                                                  memory_order_acquire, memory_order_relaxed)) {
        pthread_once(&g_aux_slot_key_once, aux_slot_key_create);
        (void)pthread_setspecific(g_aux_slot_key, &g_aux_rcu_slots[i]);
        return &g_aux_rcu_slots[i];
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &tn);
    int64_t waited_s = (int64_t)(tn.tv_sec - t0.tv_sec);
    if (waited_s >= next_warn_s) {
      syslog(LOG_WARNING, "[EpochRCU] all %d auxiliary reader slots are in use; waiting (%" PRId64 " s so far)", MAX_AUX_RCU_READERS, waited_s);
      next_warn_s = waited_s + 10;
    }
    rcu_exponential_backoff(&retries, &sleep_time);
  }
}

static void aux_slot_release(rcu_aux_slot_t *slot) {
  (void)pthread_setspecific(g_aux_slot_key, NULL);   /* released on purpose: the exit handler has nothing left to do */
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
  if (t_aux_depth <= 0) return;   /* an unlock without a lock is ignored (the unit test checks it); a debug build is not made to abort on it */
  if (--t_aux_depth > 0) return;
  rcu_epoch_exit(&t_aux_slot->observed_epoch);
  if (!t_aux_pinned) {
    aux_slot_release(t_aux_slot);
    t_aux_slot = NULL;
  }
}

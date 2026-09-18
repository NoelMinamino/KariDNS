#ifndef DNS_EPOCH_RCU_H
#define DNS_EPOCH_RCU_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>

#define RCU_EPOCH_IDLE UINT64_MAX

#include "dns_server_internal.h"

#define MAX_ASYNC_IO_RCU_WORKERS 16
#define MAX_AXFR_RCU_WORKERS 32

extern _Atomic uint64_t g_global_epoch;
extern worker_ctx_t g_resp_logger_rcu_ctx;
extern worker_ctx_t g_query_logger_rcu_ctx;
extern worker_ctx_t g_async_io_rcu_ctxs[MAX_ASYNC_IO_RCU_WORKERS];
extern int g_async_io_rcu_worker_count;
extern worker_ctx_t g_axfr_rcu_ctxs[MAX_AXFR_RCU_WORKERS];
extern int g_axfr_rcu_worker_count;

// グローバル世代カウンタを1進めて新しい世代番号を返す(writer専用、低頻度呼び出し)
uint64_t rcu_writer_advance_epoch(void);

// 指定epoch以前を参照しているワーカーがいなくなるまで待つ(writer専用、低頻度呼び出し)
// timeout_ms <= 0 の場合は無制限に待つ。全リーダーの退出を確認できたら true、タイムアウト時は false を返す。
bool rcu_writer_wait_until_safe(uint64_t retire_epoch, int timeout_ms);

// 指数バックオフ関数 (共通利用可能)
void rcu_exponential_backoff(int *retries, useconds_t *sleep_time);

// リーダー側: クエリ処理開始時に呼ぶ。ctx はそのワーカー自身の worker_ctx_t。
static inline void rcu_reader_enter(worker_ctx_t *ctx) {
  if (!ctx) return;
  uint64_t e = atomic_load_explicit(&g_global_epoch, memory_order_relaxed);
  atomic_store_explicit(&ctx->rcu_observed_epoch, e, memory_order_release);
}

// リーダー側: クエリ処理終了時(応答送出後、または早期return/continueの直前)に呼ぶ。
static inline void rcu_reader_exit(worker_ctx_t *ctx) {
  if (!ctx) return;
  atomic_store_explicit(&ctx->rcu_observed_epoch, RCU_EPOCH_IDLE, memory_order_release);
}

#endif /* DNS_EPOCH_RCU_H */

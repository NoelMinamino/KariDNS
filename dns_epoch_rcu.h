#ifndef DNS_EPOCH_RCU_H
#define DNS_EPOCH_RCU_H

#include <stdalign.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>

#define RCU_EPOCH_IDLE UINT64_MAX

#include "dns_server_internal.h"

#define MAX_ASYNC_IO_RCU_WORKERS 16
#define MAX_AUX_RCU_READERS 128

/*
 * Epoch RCU の約束事
 *
 * writer: 新しいポインタを公開してから世代を進める (rcu_writer_publish)。
 *   戻り値の retire epoch 以下を観測中のリーダーがいなくなるまで
 *   (rcu_writer_wait_until_safe) 古いオブジェクトを解放・再利用しない。
 * reader: rcu_observed_epoch へ store した後に seq_cst フェンスを置き、
 *   その後で保護対象のポインタを load する (rcu_reader_enter)。
 *   writer 側のフェンスと対になり、「writer がこのリーダーを見落とす」か
 *   「リーダーが古いポインタを読む」のどちらか一方しか起きない。
 *
 * 読み取り区間の中で rcu_writer_wait_until_safe() を呼ばないこと
 * (自分自身を待って止まる)。長く保持する参照は retain_zone_snapshot() 等の
 * 参照カウントで持ち、区間は load から参照獲得までに限る。
 */

/* ワーカー以外のスレッド (制御スレッド、ゾーン転送スレッド) 用のリーダースロット。
 * worker_ctx_t 全体は不要なので世代だけを持つ。 */
typedef struct {
  alignas(64) _Atomic uint64_t observed_epoch;
  _Atomic bool in_use;
} rcu_aux_slot_t;

extern _Atomic uint64_t g_global_epoch;
extern worker_ctx_t g_resp_logger_rcu_ctx;
extern worker_ctx_t g_query_logger_rcu_ctx;
extern worker_ctx_t g_async_io_rcu_ctxs[MAX_ASYNC_IO_RCU_WORKERS];
extern int g_async_io_rcu_worker_count;
extern rcu_aux_slot_t g_aux_rcu_slots[MAX_AUX_RCU_READERS];

// グローバル世代カウンタを1進め、進める前の世代番号 (retire epoch) を返す(writer専用、低頻度呼び出し)
uint64_t rcu_writer_advance_epoch(void);

// 新しいオブジェクトを公開してから世代を進める。評価結果は retire epoch。
// slot の型 (_Atomic(T *)) を保つためマクロにしている。
#define rcu_writer_publish(slot, new_ptr)                                   \
  (atomic_store_explicit((slot), (new_ptr), memory_order_release),          \
   rcu_writer_advance_epoch())

// 指定epoch以前を参照しているワーカーがいなくなるまで待つ(writer専用、低頻度呼び出し)
// timeout_ms <= 0 の場合は無制限に待つ。全リーダーの退出を確認できたら true、タイムアウト時は false を返す。
bool rcu_writer_wait_until_safe(uint64_t retire_epoch, int timeout_ms);

// ワーカーが自分の読み取り区間の中で writer になるとき (UPDATE) に使う。自分の区間は待たない
// (待つと自分自身を待ってタイムアウトまで止まる)。呼び出し側は、待つ前に読んだ arena の
// ポインタを待機の後で使わないこと (その arena はこの writer 自身が standby として上書きする)。
bool rcu_writer_wait_until_safe_in_reader(uint64_t retire_epoch, int timeout_ms);

// rcu_reader_enter() が記録する、このスレッドのワーカー用スロット
extern _Thread_local _Atomic uint64_t *t_rcu_own_observed;

// 指数バックオフ関数 (共通利用可能)
void rcu_exponential_backoff(int *retries, useconds_t *sleep_time);

static inline void rcu_epoch_enter(_Atomic uint64_t *observed) {
  uint64_t e = atomic_load_explicit(&g_global_epoch, memory_order_relaxed);
  atomic_store_explicit(observed, e, memory_order_release);
  // store→load の並べ替えを禁止する。このフェンスは直前の世代の load に
  // acquire の効果も与えるので、進んだ世代を読んだリーダーは新しいポインタを読む。
  atomic_thread_fence(memory_order_seq_cst);
}

static inline void rcu_epoch_exit(_Atomic uint64_t *observed) {
  atomic_store_explicit(observed, RCU_EPOCH_IDLE, memory_order_release);
}

// リーダー側: クエリ処理開始時に呼ぶ。ctx はそのワーカー自身の worker_ctx_t。
static inline void rcu_reader_enter(worker_ctx_t *ctx) {
  if (!ctx) return;
  t_rcu_own_observed = &ctx->rcu_observed_epoch;
  rcu_epoch_enter(&ctx->rcu_observed_epoch);
}

// リーダー側: クエリ処理終了時(応答送出後、または早期return/continueの直前)に呼ぶ。
static inline void rcu_reader_exit(worker_ctx_t *ctx) {
  if (!ctx) return;
  rcu_epoch_exit(&ctx->rcu_observed_epoch);
}

// worker_ctx_t を持たないスレッドの読み取り区間。入れ子にできる (最外側だけが世代を記録する)。
// pin していないスレッドは最外側の区間ごとにスロットを確保し、空きが無ければ待つ。
void rcu_aux_read_lock(void);
void rcu_aux_read_unlock(void);
// 呼び出したスレッドにスロットを unpin まで割り当てる。ロックを持ったまま区間に入る
// スレッド (制御スレッド、ゾーン転送スレッド) は、ロックを取る前に pin しておくこと。
void rcu_aux_thread_pin(void);
void rcu_aux_thread_unpin(void);

#endif /* DNS_EPOCH_RCU_H */

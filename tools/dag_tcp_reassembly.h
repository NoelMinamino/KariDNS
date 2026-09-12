#ifndef DAG_TCP_REASSEMBLY_H
#define DAG_TCP_REASSEMBLY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dag_pcap_l4.h"

// 完全なDNSメッセージ(2byte長プレフィックスを除いた本体)を1件受け取るコールバック。
// direction: 0 = 該当ストリームのdir[0](正規化キーの第1エンドポイント側からの送信),
//            1 = dir[1](第2エンドポイント側からの送信)。
// addr_key / port_key はストリームの正規化4-tupleキー。
typedef void (*tcp_reasm_message_cb)(void *user_ctx, uint32_t stream_id, int direction,
                                     const uint8_t *addr_key, const uint16_t *port_key,
                                     const uint8_t *dns_msg, size_t dns_msg_len);

typedef struct tcp_reasm_table tcp_reasm_table_t;

// max_streams: 同時に保持するTCPストリーム数の上限(超過時は最も古いストリームをLRU的に破棄)。
// max_buffer_per_direction: 1方向あたりの再構成バッファの上限バイト数
tcp_reasm_table_t *tcp_reasm_create(uint32_t max_streams, size_t max_buffer_per_direction);
void tcp_reasm_destroy(tcp_reasm_table_t *t);

// 1個のTCPセグメント(pcap_extract_l4()の出力)を投入する。
// 完全なDNSメッセージが組み上がるたびに cb が呼ばれる。
void tcp_reasm_feed(tcp_reasm_table_t *t, const pcap_l4_info_t *l4, tcp_reasm_message_cb cb, void *user_ctx);

#endif /* DAG_TCP_REASSEMBLY_H */

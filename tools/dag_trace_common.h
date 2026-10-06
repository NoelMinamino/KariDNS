#ifndef DAG_TRACE_COMMON_H
#define DAG_TRACE_COMMON_H

#include "dag_internal.h"

/* +trace / +nssearch / +trace2 で共有するヘルパ群 */

/* 応答を ldns.jp trace URL 用の結果行として記録する */
void trace_record_result(const char *server, ssize_t n, const uint8_t *resp, long elapsed_ms, const char *proto);

/* pkt内のsection_count分のRRをパースし、want_typeに一致するレコードのrdata[0]を
 * out配列(out_cap個まで)に集める。roffは呼び出し元で更新される。 */
void trace_collect_rrs_by_type(const uint8_t *pkt, size_t pkt_len, size_t *roff,
                               int section_count, uint16_t want_type,
                               char out[][256], char owners[][256], int *out_count, int out_cap);

/* name が owner と等しいか owner の配下なら true (大文字小文字・末尾ドット無視) */
bool trace_name_is_subdomain(const char *name, const char *owner);

/* 2つの名前が等しいか (大文字小文字・末尾ドット無視) */
bool trace_name_equal(const char *a, const char *b);

/* ADDITIONAL セクションから NS 名に一致する A/AAAA (glue) を集める。
 * out_names が NULL でなければ、out[i] のアドレスを持つ NS 名を out_names[i] に入れる。 */
int trace_collect_glue(const uint8_t *pkt, size_t pkt_len, size_t *roff, int arcount,
                       char ns_names[][256], char ns_owners[][256], int ns_count,
                       const query_opts_t *qo, char out[][64], char out_names[][256], int count, int out_cap, bool report);

/* dig +trace と同じ形式で ";; Received N bytes from ADDR#PORT(name) in T ms" を出す。
 * name は @server に指定した文字列か NS 名 (末尾のドットは表示しない)。 */
void trace_print_received(ssize_t n, const char *addr, int port, const char *name, int ms);

#endif /* DAG_TRACE_COMMON_H */

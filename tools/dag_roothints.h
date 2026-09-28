#ifndef DAG_ROOTHINTS_H
#define DAG_ROOTHINTS_H

#include <stddef.h>

/* +trace2 のプライミングに使うルートヒント。
 * 内蔵のヒント (IANA named.root 相当) か、+roothints=FILE で与えた named.root 形式の
 * ファイルから読み込む。システムリゾルバには一切依存しない。 */

#define ROOTHINT_MAX 64

typedef struct {
    char name[256];  /* 例: "a.root-servers.net." */
    char addr[64];   /* IPv4 / IPv6 リテラル */
} roothint_t;

typedef struct {
    roothint_t h[ROOTHINT_MAX];
    int count;
} roothints_t;

/* 内蔵のルートヒント (13 サーバ x IPv4/IPv6) を読み込む */
void roothints_load_builtin(roothints_t *rh);

/* named.root 形式のテキストを解析する。
 *   ".  3600000  NS  A.ROOT-SERVERS.NET."
 *   "A.ROOT-SERVERS.NET.  3600000  A  198.41.0.4"
 * TTL・クラスは省略可。"name address" の2カラム形式も受け付ける。
 * "." の NS が書かれていればその NS 名の A/AAAA だけを採用する。
 * 成功時は採用したアドレス数 (>0)、失敗時は -1 を返し err にメッセージを書く。 */
int roothints_parse_text(const char *text, roothints_t *rh, char *err, size_t err_len);

/* named.root 形式のファイルを読み込む。戻り値は roothints_parse_text と同じ。 */
int roothints_load_file(const char *path, roothints_t *rh, char *err, size_t err_len);

#endif /* DAG_ROOTHINTS_H */

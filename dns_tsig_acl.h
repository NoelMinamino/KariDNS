#ifndef DNS_TSIG_ACL_H
#define DNS_TSIG_ACL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dns_config_parser.h"

bool check_acl(const char *client_ip, char **acl_list, int acl_count);
acl_entry_t *acl_list_parse(char **acl_list, int count);
bool check_acl_bin(const char *client_ip, const acl_entry_t *parsed, int count);
tsig_key_t *find_tsig_key_by_name(const server_config_t *cfg, const char *key_name);
/* 鍵名 (DNS 名) が同じか。大文字小文字と末尾のドットは区別しない (RFC 4343 §2、D-03) */
bool tsig_key_names_equal(const char *a, const char *b);

/* 要求の TSIG を調べた結果 (RFC 8945 §5.2)。サーバーは全ての応答をこの結果で仕上げる。 */
typedef enum {
    TSIG_REQ_NONE = 0,  /* TSIG なし */
    TSIG_REQ_VALID,     /* 検証できた。応答は同じ鍵で署名する (§5.3) */
    TSIG_REQ_ERROR,     /* 鍵・MAC・時刻・切り詰めのエラー。NOTAUTH + error (§5.2.1-§5.2.4) */
    TSIG_REQ_FORMERR    /* TSIG が解釈できない。TSIG なしの FORMERR (§5.2、§5.2.2.1) */
} tsig_req_status_t;

typedef struct {
    tsig_req_status_t status;
    uint16_t error;                    /* TSIG_REQ_ERROR: 16 BADSIG, 17 BADKEY, 18 BADTIME, 22 BADTRUNC */
    tsig_key_t *key;                   /* VALID、BADTIME、BADTRUNC: 要求を署名した鍵 (設定スナップショット内) */
    size_t stripped_len;               /* TSIG RR を除いた要求の長さ (VALID、ERROR) */
    uint8_t mac[64];                   /* 検証できた要求の MAC (VALID、BADTIME、BADTRUNC) */
    size_t mac_len;
    uint64_t time_signed;              /* 要求の Time Signed と Fudge (BADTIME の応答に使う) */
    uint16_t fudge;
    size_t res_limit;                  /* 応答の上限 (UDP ではクライアントの EDNS サイズ)。エンジンが決める */
    char key_name[DNS_NAME_TEXT_SIZE]; /* 要求の鍵名とアルゴリズム名 (無署名のエラー応答に写す。§5.3.2) */
    char alg_name[DNS_NAME_TEXT_SIZE];
} tsig_request_t;

/* 要求の TSIG を、要求が名乗る鍵名とアルゴリズムで設定の鍵から探して検証する。
 * 切り詰めた MAC は、切り詰めを設定する手段がないので BADTRUNC とする (BIND の既定と同じ。§5.2.4)。
 * client_ip はログ用 (NULL 可)。 */
void tsig_check_request(const server_config_t *cfg, const uint8_t *req, size_t req_len, const char *client_ip,
                        tsig_request_t *t);
/* 応答に付ける TSIG RR の最大バイト数 (VALID と BADTIME/BADTRUNC のときに応答の上限から差し引く)。 */
size_t tsig_response_reserve(const tsig_request_t *t);
/* 応答 res[0..res_len) に t に従って TSIG を付ける。NONE と FORMERR はそのまま。
 * 入りきらないときは質問だけにして TC=1、NOERROR で署名する (RFC 8945 §5.3)。
 * 戻り値は新しい長さ。署名できなければ -1。 */
int tsig_finish_response(uint8_t *res, size_t res_len, size_t max_len, const tsig_request_t *t);

#endif /* DNS_TSIG_ACL_H */

#ifndef DNS_RRL_H
#define DNS_RRL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dns_config_parser.h"

typedef enum {
  RRL_RESP_NOERROR,
  RRL_RESP_NODATA,
  RRL_RESP_NXDOMAIN,
  RRL_RESP_ERROR,
  RRL_RESP_REFERRAL, /* D-05: 委任 (referrals-per-second) */
  RRL_RESP_ALL       /* D-05: all-per-second のバケット (クライアントだけで数える) */
} rrl_response_class_t;

/* D-05: BIND (lib/dns/rrl.c make_key()) と同じ単位で数えるためのキー。
 * クライアントは ipv4-prefix-length / ipv6-prefix-length でまとめる。 */
typedef struct {
  rrl_response_class_t cls;
  const char *name;  /* NOERROR / NODATA: QNAME、NXDOMAIN: ゾーン名、referral: 委任点、エラー: NULL */
  bool wildcard;     /* name はゾーン名で、"*.<ゾーン>" のバケットに数える */
  uint16_t qtype;    /* NOERROR だけがキーに含める */
  uint16_t qclass;   /* NOERROR / NODATA / referral がキーに含める */
} rrl_key_t;

extern _Atomic uint64_t g_rrl_dropped_total;
extern _Atomic uint64_t g_rrl_slip_total;

void rrl_init(void);
void rrl_shutdown(void);
uint64_t siphash24(const uint8_t *in, size_t inlen, const uint64_t k[2]);
rrl_response_class_t get_rrl_class(const uint8_t *res_buf, size_t res_len);
/* 応答からキーを作る。zone は応答を作ったゾーンの名前 (無ければ NULL)、wildcard は答えが
 * ワイルドカードから作られたか。namebuf (DNS_NAME_TEXT_SIZE) は委任点の名前の置き場。 */
void rrl_make_key(rrl_key_t *key, const uint8_t *res, size_t res_len, const char *qname,
                  uint16_t qtype, uint16_t qclass, const char *zone, bool wildcard,
                  char *namebuf, size_t namebuf_cap);
bool rrl_check_key(const void *client_addr, const rrl_key_t *key, const rate_limit_config_t *cfg, bool *out_slip);
/* キーのバケット (または all-per-second のバケット) のトークンが尽きているか (使わない)。 */
bool rrl_key_exhausted(const void *client_addr, const rrl_key_t *key, const rate_limit_config_t *cfg);
/* 名前を含まないキー (クライアント + 応答の種類) で数える版 */
bool rrl_check(const void *client_addr, rrl_response_class_t cls, const rate_limit_config_t *cfg, bool *out_slip);
bool rrl_is_client_exhausted(const void *client_addr, const rate_limit_config_t *cfg);

#endif /* DNS_RRL_H */

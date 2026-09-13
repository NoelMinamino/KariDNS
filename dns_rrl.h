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
  RRL_RESP_ERROR
} rrl_response_class_t;

extern _Atomic uint64_t g_rrl_dropped_total;
extern _Atomic uint64_t g_rrl_slip_total;

void rrl_init(void);
void rrl_shutdown(void);
uint64_t siphash24(const uint8_t *in, size_t inlen, const uint64_t k[2]);
rrl_response_class_t get_rrl_class(const uint8_t *res_buf, size_t res_len);
bool rrl_check(const struct sockaddr_storage *client_addr, rrl_response_class_t cls, const rate_limit_config_t *cfg, bool *out_slip);
bool rrl_is_client_exhausted(const struct sockaddr_storage *client_addr, const rate_limit_config_t *cfg);

#endif /* DNS_RRL_H */

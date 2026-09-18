#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_rrl.h"
#include "dns_server_internal.h"
#include "dns_utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

#define RRL_TABLE_SIZE 65536

typedef struct {
  atomic_flag lock;
  _Atomic uint64_t client_hash;
  _Atomic int64_t last_refill_ms[4];
  _Atomic int32_t tokens[4];
  _Atomic uint32_t slip_counter;
} rrl_bucket_t;

static rrl_bucket_t g_rrl_table[RRL_TABLE_SIZE];

_Atomic uint64_t g_rrl_dropped_total = 0;
_Atomic uint64_t g_rrl_slip_total = 0;

static uint64_t g_rrl_hash_key[2];

void rrl_init(void) {
  arc4random_buf(g_rrl_hash_key, sizeof(g_rrl_hash_key));
}

void rrl_shutdown(void) {
}

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do { \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
} while (0)

uint64_t siphash24(const uint8_t *in, size_t inlen, const uint64_t k[2]) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k[0];
    uint64_t v1 = 0x646f72616e646f6dULL ^ k[1];
    uint64_t v2 = 0x6c7967656e657261ULL ^ k[0];
    uint64_t v3 = 0x7465646279746573ULL ^ k[1];
    uint64_t b = ((uint64_t)inlen) << 56;
    const uint8_t *end = in + (inlen & ~7);
    for (; in != end; in += 8) {
        uint64_t m; memcpy(&m, in, 8);
        v3 ^= m; SIPROUND; SIPROUND; v0 ^= m;
    }
    uint64_t t = 0;
    switch (inlen & 7) {
        case 7: t |= ((uint64_t)in[6]) << 48; // fallthrough
        case 6: t |= ((uint64_t)in[5]) << 40; // fallthrough
        case 5: t |= ((uint64_t)in[4]) << 32; // fallthrough
        case 4: t |= ((uint64_t)in[3]) << 24; // fallthrough
        case 3: t |= ((uint64_t)in[2]) << 16; // fallthrough
        case 2: t |= ((uint64_t)in[1]) << 8;  // fallthrough
        case 1: t |= ((uint64_t)in[0]);
    }
    b |= t;
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;
    v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static inline uint64_t rrl_hash_client_addr(const void *client_addr_ptr) {
  const struct sockaddr *client_addr = (const struct sockaddr *)client_addr_ptr;
  if (!client_addr) return 0;
  if (client_addr->sa_family == AF_INET) {
    uint32_t ip = ((const struct sockaddr_in *)client_addr)->sin_addr.s_addr & htonl(0xFFFFFF00); // /24 mask
    return siphash24((const uint8_t *)&ip, 4, g_rrl_hash_key);
  } else if (client_addr->sa_family == AF_INET6) {
    // /56 mask (7 bytes prefix). Directly read sin6_addr without stack memcpy/memset
    const uint8_t *s6 = (const uint8_t *)&((const struct sockaddr_in6 *)client_addr)->sin6_addr;
    return siphash24(s6, 7, g_rrl_hash_key);
  }
  return 0;
}

rrl_response_class_t get_rrl_class(const uint8_t *res_buf, size_t res_len) {
  if (res_len < DNS_HEADER_SIZE) return RRL_RESP_ERROR;
  uint8_t rcode = res_buf[3] & 0x0F;
  uint16_t ancount = (res_buf[6] << 8) | res_buf[7];
  if (rcode == 3) return RRL_RESP_NXDOMAIN;
  if (rcode == 0) {
    if (ancount > 0) return RRL_RESP_NOERROR;
    return RRL_RESP_NODATA;
  }
  return RRL_RESP_ERROR;
}

bool rrl_check(const void *client_addr_ptr, rrl_response_class_t cls, const rate_limit_config_t *cfg, bool *out_slip) {
  *out_slip = false;
  if (!cfg || !cfg->configured) return true;
  const struct sockaddr *client_addr = (const struct sockaddr *)client_addr_ptr;
  if (!client_addr) return true;

  uint32_t rate = 0;
  switch (cls) {
    case RRL_RESP_NOERROR: rate = cfg->responses_per_second; break;
    case RRL_RESP_NODATA:  rate = cfg->responses_per_second; break;
    case RRL_RESP_NXDOMAIN: rate = cfg->nxdomains_per_second; break;
    case RRL_RESP_ERROR:   rate = cfg->errors_per_second; break;
  }
  if (rate == 0) return true; // 0 means no limit

  if (cfg->exempt_clients_count > 0 && cfg->exempt_clients_parsed) {
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (cidr_entry_match_sockaddr(&cfg->exempt_clients_parsed[i], client_addr)) return true;
    }
  } else if (cfg->exempt_clients_count > 0 && cfg->exempt_clients) {
    char ip_str_exempt[INET6_ADDRSTRLEN] = {0};
    if (client_addr->sa_family == AF_INET) {
      inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, ip_str_exempt, INET_ADDRSTRLEN);
    } else if (client_addr->sa_family == AF_INET6) {
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, ip_str_exempt, INET6_ADDRSTRLEN);
    }
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (match_cidr(ip_str_exempt, cfg->exempt_clients[i].ip)) return true;
    }
  }

  char ip_str[INET6_ADDRSTRLEN] = {0};
  if (cfg->log_only) {
    if (client_addr->sa_family == AF_INET) {
      inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else if (client_addr->sa_family == AF_INET6) {
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    }
  }

  uint64_t full_hash = rrl_hash_client_addr(client_addr);
  uint64_t hash = full_hash;

#define RRL_PROBE_WAYS 4

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

  uint32_t window_sec = (cfg->window_seconds > 0) ? (uint32_t)cfg->window_seconds : 15;
  if (window_sec > 3600) window_sec = 3600;

  rrl_bucket_t *selected_bucket = NULL;
  size_t base_idx = hash & (RRL_TABLE_SIZE - 1);

  // 1st Pass: Look for exact hash match
  for (int probe = 0; probe < RRL_PROBE_WAYS; probe++) {
    size_t idx = (base_idx + (size_t)probe) & (RRL_TABLE_SIZE - 1);
    rrl_bucket_t *b = &g_rrl_table[idx];
    while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {
#if defined(__x86_64__) || defined(__i386__)
      __asm__ volatile("pause" ::: "memory");
#else
      sched_yield();
#endif
    }
    if (b->client_hash == full_hash) {
      selected_bucket = b;
      break;
    }
    atomic_flag_clear_explicit(&b->lock, memory_order_release);
  }

  // 2nd Pass: If no exact match, look for an empty or expired bucket
  if (!selected_bucket) {
    for (int probe = 0; probe < RRL_PROBE_WAYS; probe++) {
      size_t idx = (base_idx + (size_t)probe) & (RRL_TABLE_SIZE - 1);
      rrl_bucket_t *b = &g_rrl_table[idx];
      while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {
#if defined(__x86_64__) || defined(__i386__)
      __asm__ volatile("pause" ::: "memory");
#else
      sched_yield();
#endif
      }
      if (b->client_hash == 0 || (now_ms - b->last_refill_ms[cls] > (int64_t)window_sec * 1000)) {
        selected_bucket = b;
        break;
      }
      atomic_flag_clear_explicit(&b->lock, memory_order_release);
    }
  }

  // All candidate slots are busy active collisions.
  // Bypass RRL to prevent token-stealing / collateral DoS on legitimate users.
  if (!selected_bucket) {
    return true;
  }

  rrl_bucket_t *b = selected_bucket;
  if (b->client_hash != full_hash) {
    b->client_hash = full_hash;
    for (int i = 0; i < 4; i++) {
      b->last_refill_ms[i] = now_ms;
    }
    uint64_t cap0 = (uint64_t)cfg->responses_per_second * window_sec;
    uint64_t cap1 = (uint64_t)cfg->nodata_per_second * window_sec;
    uint64_t cap2 = (uint64_t)cfg->nxdomains_per_second * window_sec;
    uint64_t cap3 = (uint64_t)cfg->errors_per_second * window_sec;
    if (cap0 > 0x7FFFFFFF) cap0 = 0x7FFFFFFF;
    if (cap1 > 0x7FFFFFFF) cap1 = 0x7FFFFFFF;
    if (cap2 > 0x7FFFFFFF) cap2 = 0x7FFFFFFF;
    if (cap3 > 0x7FFFFFFF) cap3 = 0x7FFFFFFF;
    b->tokens[0] = (int32_t)cap0;
    b->tokens[1] = (int32_t)cap1;
    b->tokens[2] = (int32_t)cap2;
    b->tokens[3] = (int32_t)cap3;
    b->slip_counter = 0;
  } else {
    // nodata_per_second が未設定の場合は設定ロード時に responses_per_second へフォールバックされているため、既存設定ファイルの挙動は変わらない
    uint32_t rates[4] = {
      cfg->responses_per_second, // index0: NOERROR
      cfg->nodata_per_second,    // index1: NODATA（専用レート。未設定時は responses_per_second と同値）
      cfg->nxdomains_per_second, // index2: NXDOMAIN
      cfg->errors_per_second     // index3: ERROR
    };
    for (int i = 0; i < 4; i++) {
      if (rates[i] == 0) continue;
      int64_t elapsed_ms = now_ms - b->last_refill_ms[i];
      if (elapsed_ms > 0) {
        uint64_t max_cap = (uint64_t)rates[i] * window_sec;
        if (max_cap > 0x7FFFFFFF) max_cap = 0x7FFFFFFF;
        uint64_t add_t = ((uint64_t)elapsed_ms * rates[i]) / 1000;
        if (add_t > 0) {
          if (add_t > max_cap) add_t = max_cap;
          b->tokens[i] += (int32_t)add_t;
          if (b->tokens[i] > (int32_t)max_cap) b->tokens[i] = (int32_t)max_cap;
          if (b->tokens[i] < 0) b->tokens[i] = 0;
          b->last_refill_ms[i] = now_ms;
        }
      }
    }
  }

  bool allow = false;
  if (b->tokens[cls] > 0) {
    b->tokens[cls]--;
    allow = true;
  } else {
    b->slip_counter++;
    if (cfg->slip > 0 && (b->slip_counter % cfg->slip) == 0) {
      *out_slip = true;
    }
  }
  atomic_flag_clear_explicit(&b->lock, memory_order_release);

  if (!allow && !*out_slip) {
    atomic_fetch_add_explicit(&g_rrl_dropped_total, 1, memory_order_relaxed);
  } else if (!allow && *out_slip) {
    atomic_fetch_add_explicit(&g_rrl_slip_total, 1, memory_order_relaxed);
  }

  if (cfg->log_only && !allow) {
    syslog(LOG_INFO, "[RRL] would rate-limit %s (log-only)", ip_str);
    return true; // allow anyway
  }

  return allow;
}

bool rrl_is_client_exhausted(const void *client_addr_ptr, const rate_limit_config_t *cfg) {
  if (!cfg || !cfg->configured) return false;
  if (cfg->responses_per_second == 0) return false;
  const struct sockaddr *client_addr = (const struct sockaddr *)client_addr_ptr;
  if (!client_addr) return false;

  if (cfg->exempt_clients_count > 0 && cfg->exempt_clients_parsed) {
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (cidr_entry_match_sockaddr(&cfg->exempt_clients_parsed[i], client_addr)) return false;
    }
  } else if (cfg->exempt_clients_count > 0 && cfg->exempt_clients) {
    char ip_str[INET6_ADDRSTRLEN] = {0};
    if (client_addr->sa_family == AF_INET) {
      inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else if (client_addr->sa_family == AF_INET6) {
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    }
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (match_cidr(ip_str, cfg->exempt_clients[i].ip)) return false;
    }
  }

  uint64_t full_hash = rrl_hash_client_addr(client_addr);
  uint64_t hash = full_hash;

  size_t base_idx = hash & (RRL_TABLE_SIZE - 1);
  bool exhausted = false;

  for (int probe = 0; probe < 4; probe++) {
    size_t idx = (base_idx + (size_t)probe) & (RRL_TABLE_SIZE - 1);
    rrl_bucket_t *b = &g_rrl_table[idx];
    if (b->client_hash == full_hash) {
      while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ volatile("pause" ::: "memory");
#else
        sched_yield();
#endif
      }
      if (b->client_hash == full_hash) {
        // トークン残量が 0 以下（枯渇状態）なら true
        if (b->tokens[0] <= 0) {
          exhausted = true;
        }
      }
      atomic_flag_clear_explicit(&b->lock, memory_order_release);
      if (exhausted) break;
    }
  }
  return exhausted;
}

#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_rrl.h"
#include "dns_server_internal.h"
#include "dns_utils.h"
#include "dns_siphash.h"

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

#define RRL_TABLE_SIZE 131072 /* 固定長 (BIND の max-table-size の既定 100000 相当)。D-05 */

/* 1 バケット = 1 つのキー (クライアントのプレフィックス + 応答の種類 + 名前 ...) のトークン。
 * key_hash は空きの判定でロックの外から読むので atomic、残りはロックの中だけで触る。 */
typedef struct {
  atomic_flag lock;
  _Atomic uint64_t key_hash;
  int64_t last_refill_ms;
  int32_t tokens;
  uint32_t slip_counter;
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

uint64_t siphash24(const uint8_t *in, size_t inlen, const uint64_t k[2]) {
    return dns_siphash24(in, inlen, k);   /* shared header-only implementation */
}

rrl_response_class_t get_rrl_class(const uint8_t *res_buf, size_t res_len) {
  if (res_len < DNS_HEADER_SIZE) return RRL_RESP_ERROR;
  uint8_t rcode = res_buf[3] & 0x0F;
  uint16_t ancount = (res_buf[6] << 8) | res_buf[7];
  uint16_t nscount = (res_buf[8] << 8) | res_buf[9];
  if (rcode == 3) return RRL_RESP_NXDOMAIN;
  if (rcode == 0) {
    if (ancount > 0) return RRL_RESP_NOERROR;
    /* AA=0 で権威部がある応答は委任 (referral)。BIND の DNS_R_DELEGATION と同じ扱い */
    if (!(res_buf[2] & 0x04) && nscount > 0) return RRL_RESP_REFERRAL;
    return RRL_RESP_NODATA;
  }
  return RRL_RESP_ERROR;
}

/* 応答の権威部の最初の RR の所有者名 (委任点) を取り出す。 */
static bool rrl_referral_name(const uint8_t *res, size_t res_len, char *out, size_t cap) {
  uint16_t qdcount = (res[4] << 8) | res[5];
  uint16_t ancount = (res[6] << 8) | res[7];
  size_t off = DNS_HEADER_SIZE;
  for (uint16_t i = 0; i < qdcount; i++) {
    size_t next;
    if (skip_wire_name(res, res_len, off, &next) != 0 || next + 4 > res_len) return false;
    off = next + 4;
  }
  for (uint16_t i = 0; i < ancount; i++) {
    size_t next;
    if (skip_wire_name(res, res_len, off, &next) != 0 || next + 10 > res_len) return false;
    uint16_t rdlen = (res[next + 8] << 8) | res[next + 9];
    off = next + 10 + rdlen;
    if (off > res_len) return false;
  }
  size_t next;
  int len = expand_wire_name_to_buffer(res, res_len, off, &next, out, cap); /* NUL を含む長さ */
  if (len <= 0) return false;
  if (len > 2 && out[len - 2] == '.') out[len - 2] = '\0'; /* 末尾の '.' は QNAME やゾーン名と同じく付けない */
  return true;
}

void rrl_make_key(rrl_key_t *key, const uint8_t *res, size_t res_len, const char *qname,
                  uint16_t qtype, uint16_t qclass, const char *zone, bool wildcard,
                  char *namebuf, size_t namebuf_cap) {
  memset(key, 0, sizeof(*key));
  key->cls = get_rrl_class(res, res_len);
  key->qtype = qtype;
  key->qclass = qclass;
  switch (key->cls) {
  case RRL_RESP_NOERROR:
  case RRL_RESP_NODATA:
    /* ワイルドカードから作った応答は "*.<ゾーン>" の1つのバケットにまとめる (BIND make_key()) */
    if (wildcard && zone) {
      key->name = zone;
      key->wildcard = true;
    } else {
      key->name = qname;
    }
    break;
  case RRL_RESP_NXDOMAIN:
    /* NXDOMAIN はゾーン名 (BIND は db の origin) で数える: ランダムなサブドメインも1つに入る */
    key->name = zone ? zone : qname;
    break;
  case RRL_RESP_REFERRAL:
    key->name = (namebuf && rrl_referral_name(res, res_len, namebuf, namebuf_cap)) ? namebuf : qname;
    break;
  default:
    key->name = NULL; /* エラーはクライアントのプレフィックスだけで数える */
    break;
  }
}

static uint32_t rrl_rate(const rate_limit_config_t *cfg, rrl_response_class_t cls) {
  switch (cls) {
  case RRL_RESP_NOERROR:  return cfg->responses_per_second;
  case RRL_RESP_NODATA:   return cfg->nodata_per_second;
  case RRL_RESP_NXDOMAIN: return cfg->nxdomains_per_second;
  case RRL_RESP_REFERRAL: return cfg->referrals_per_second;
  case RRL_RESP_ALL:      return cfg->all_per_second;
  default:                return cfg->errors_per_second;
  }
}

static bool rrl_is_exempt(const struct sockaddr *client_addr, const rate_limit_config_t *cfg) {
  if (cfg->exempt_clients_count > 0 && cfg->exempt_clients_parsed) {
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (cidr_entry_match_sockaddr(&cfg->exempt_clients_parsed[i], client_addr)) return true;
    }
  } else if (cfg->exempt_clients_count > 0 && cfg->exempt_clients) {
    char ip_str[INET6_ADDRSTRLEN] = {0};
    if (client_addr->sa_family == AF_INET) {
      inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else if (client_addr->sa_family == AF_INET6) {
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    }
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (match_cidr(ip_str, cfg->exempt_clients[i].ip)) return true;
    }
  }
  return false;
}

/* キーのハッシュ。対象は BIND の make_key() と同じ:
 *   クライアント: ipv4-prefix-length / ipv6-prefix-length でまとめたアドレス
 *   NOERROR: 名前 + QTYPE + QCLASS、NODATA / referral: 名前 + QCLASS、NXDOMAIN: ゾーン名、
 *   エラーと all-per-second: クライアントだけ
 * 名前は大文字小文字を区別しない。0 は空きバケットの印なので使わない。 */
static uint64_t rrl_key_hash(const struct sockaddr *client_addr, const rrl_key_t *key,
                             const rate_limit_config_t *cfg) {
  uint8_t buf[2 + 16 + 4 + 2 + DNS_NAME_TEXT_SIZE];
  size_t n = 0;
  buf[n++] = (uint8_t)key->cls;
  buf[n++] = (uint8_t)client_addr->sa_family;
  const uint8_t *addr;
  size_t addr_len;
  unsigned plen;
  if (client_addr->sa_family == AF_INET6) {
    addr = (const uint8_t *)&((const struct sockaddr_in6 *)client_addr)->sin6_addr;
    addr_len = 16;
    plen = cfg->ipv6_prefix_length_set ? cfg->ipv6_prefix_length : 56;
  } else {
    addr = (const uint8_t *)&((const struct sockaddr_in *)client_addr)->sin_addr;
    addr_len = 4;
    plen = cfg->ipv4_prefix_length_set ? cfg->ipv4_prefix_length : 24;
  }
  for (size_t i = 0; i < addr_len; i++) {
    unsigned bits = plen > i * 8 ? plen - (unsigned)i * 8 : 0;
    uint8_t mask = bits >= 8 ? 0xFF : (uint8_t)(0xFF << (8 - bits));
    buf[n++] = addr[i] & mask;
  }
  if (key->cls == RRL_RESP_NOERROR) {
    buf[n++] = (uint8_t)(key->qtype >> 8);
    buf[n++] = (uint8_t)key->qtype;
  }
  if (key->cls == RRL_RESP_NOERROR || key->cls == RRL_RESP_NODATA || key->cls == RRL_RESP_REFERRAL) {
    buf[n++] = (uint8_t)(key->qclass >> 8);
    buf[n++] = (uint8_t)key->qclass;
  }
  if (key->name && key->cls != RRL_RESP_ERROR && key->cls != RRL_RESP_ALL) {
    if (key->wildcard) {
      buf[n++] = '*';
      buf[n++] = '.';
    }
    size_t name_len = strlen(key->name);
    if (name_len > 1 && key->name[name_len - 1] == '.' &&
        !dns_char_is_escaped(key->name, name_len - 1))
      name_len--; /* "a.example." と "a.example" は同じ名前 */
    for (size_t i = 0; i < name_len && n < sizeof(buf); i++) {
      char c = key->name[i];
      buf[n++] = (uint8_t)((c >= 'A' && c <= 'Z') ? (c | 0x20) : c);
    }
  }
  uint64_t h = siphash24(buf, n, g_rrl_hash_key);
  return h ? h : 1;
}

#define RRL_PROBE_WAYS 4

static void rrl_lock(rrl_bucket_t *b) {
  while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause" ::: "memory");
#else
    sched_yield();
#endif
  }
}

static void rrl_unlock(rrl_bucket_t *b) {
  atomic_flag_clear_explicit(&b->lock, memory_order_release);
}

/* キーのバケットからトークンを1つ使う。戻り値: 1 = 許可、0 = 制限 (*out_slip は slip の番か)、
 * -1 = 候補のバケットがすべて使用中 (制限しない: 他のクライアントのトークンを奪わない)。 */
static int rrl_debit(uint64_t hash, uint32_t rate, uint32_t window_sec, uint32_t slip,
                     int64_t now_ms, bool *out_slip) {
  *out_slip = false;
  rrl_bucket_t *selected = NULL;
  size_t base_idx = hash & (RRL_TABLE_SIZE - 1);

  // 1st Pass: Look for exact hash match
  for (int probe = 0; probe < RRL_PROBE_WAYS; probe++) {
    rrl_bucket_t *b = &g_rrl_table[(base_idx + (size_t)probe) & (RRL_TABLE_SIZE - 1)];
    rrl_lock(b);
    if (atomic_load_explicit(&b->key_hash, memory_order_relaxed) == hash) {
      selected = b;
      break;
    }
    rrl_unlock(b);
  }
  // 2nd Pass: If no exact match, look for an empty or expired bucket
  if (!selected) {
    for (int probe = 0; probe < RRL_PROBE_WAYS; probe++) {
      rrl_bucket_t *b = &g_rrl_table[(base_idx + (size_t)probe) & (RRL_TABLE_SIZE - 1)];
      rrl_lock(b);
      if (atomic_load_explicit(&b->key_hash, memory_order_relaxed) == 0 ||
          now_ms - b->last_refill_ms > (int64_t)window_sec * 1000) {
        selected = b;
        break;
      }
      rrl_unlock(b);
    }
  }
  // All candidate slots are busy active collisions.
  // Bypass RRL to prevent token-stealing / collateral DoS on legitimate users.
  if (!selected) return -1;

  rrl_bucket_t *b = selected;
  uint64_t max_cap = (uint64_t)rate * window_sec;
  if (max_cap > 0x7FFFFFFF) max_cap = 0x7FFFFFFF;
  if (atomic_load_explicit(&b->key_hash, memory_order_relaxed) != hash) {
    atomic_store_explicit(&b->key_hash, hash, memory_order_relaxed);
    b->last_refill_ms = now_ms;
    b->tokens = (int32_t)max_cap;
    b->slip_counter = 0;
  } else {
    int64_t elapsed_ms = now_ms - b->last_refill_ms;
    if (elapsed_ms > 0) {
      uint64_t add_t = ((uint64_t)elapsed_ms * rate) / 1000;
      if (add_t > 0) {
        if (add_t > max_cap) add_t = max_cap;
        int64_t t = (int64_t)b->tokens + (int64_t)add_t;
        if (t > (int64_t)max_cap) t = (int64_t)max_cap;
        if (t < 0) t = 0;
        b->tokens = (int32_t)t;
        b->last_refill_ms = now_ms;
      }
    }
  }

  int allow = 0;
  if (b->tokens > 0) {
    b->tokens--;
    allow = 1;
  } else {
    b->slip_counter++;
    if (slip > 0 && (b->slip_counter % slip) == 0) *out_slip = true;
  }
  rrl_unlock(b);
  return allow;
}

static uint32_t rrl_window(const rate_limit_config_t *cfg) {
  uint32_t window_sec = (cfg->window_seconds > 0) ? (uint32_t)cfg->window_seconds : 15;
  return window_sec > 3600 ? 3600 : window_sec;
}

static int64_t rrl_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool rrl_check_key(const void *client_addr_ptr, const rrl_key_t *key, const rate_limit_config_t *cfg,
                   bool *out_slip) {
  *out_slip = false;
  if (!cfg || !cfg->configured || !key) return true;
  const struct sockaddr *client_addr = (const struct sockaddr *)client_addr_ptr;
  if (!client_addr || (client_addr->sa_family != AF_INET && client_addr->sa_family != AF_INET6)) return true;

  uint32_t rate = rrl_rate(cfg, key->cls);
  if (rate == 0 && cfg->all_per_second == 0) return true; // 0 means no limit
  if (rrl_is_exempt(client_addr, cfg)) return true;

  int64_t now_ms = rrl_now_ms();
  uint32_t window_sec = rrl_window(cfg);
  bool allow = true;
  if (rate > 0) {
    bool slip = false;
    if (rrl_debit(rrl_key_hash(client_addr, key, cfg), rate, window_sec, cfg->slip, now_ms, &slip) == 0) {
      allow = false;
      *out_slip = slip;
    }
  }
  if (cfg->all_per_second > 0) {
    /* all-per-second: 名前を問わずクライアント (プレフィックス) ごとの全応答。両方の制限に
     * かかったら all-per-second の結果を使う (BIND dns_rrl())。 */
    rrl_key_t all = { .cls = RRL_RESP_ALL };
    bool slip = false;
    if (rrl_debit(rrl_key_hash(client_addr, &all, cfg), cfg->all_per_second, window_sec, cfg->slip,
                  now_ms, &slip) == 0) {
      allow = false;
      *out_slip = slip;
    }
  }

  if (!allow && !*out_slip) {
    atomic_fetch_add_explicit(&g_rrl_dropped_total, 1, memory_order_relaxed);
  } else if (!allow && *out_slip) {
    atomic_fetch_add_explicit(&g_rrl_slip_total, 1, memory_order_relaxed);
  }

  if (cfg->log_only && !allow) {
    char ip_str[INET6_ADDRSTRLEN] = {0};
    if (client_addr->sa_family == AF_INET) {
      inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
    } else {
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    }
    syslog(LOG_INFO, "[RRL] would rate-limit %s (log-only)", ip_str);
    *out_slip = false;
    return true; // allow anyway
  }

  return allow;
}

bool rrl_check(const void *client_addr_ptr, rrl_response_class_t cls, const rate_limit_config_t *cfg, bool *out_slip) {
  rrl_key_t key = { .cls = cls };
  return rrl_check_key(client_addr_ptr, &key, cfg, out_slip);
}

/* バケットの残りトークンを見る (使わない)。 */
static bool rrl_bucket_empty(uint64_t hash) {
  size_t base_idx = hash & (RRL_TABLE_SIZE - 1);
  for (int probe = 0; probe < RRL_PROBE_WAYS; probe++) {
    rrl_bucket_t *b = &g_rrl_table[(base_idx + (size_t)probe) & (RRL_TABLE_SIZE - 1)];
    if (atomic_load_explicit(&b->key_hash, memory_order_relaxed) != hash) continue;
    rrl_lock(b);
    bool empty = atomic_load_explicit(&b->key_hash, memory_order_relaxed) == hash && b->tokens <= 0;
    rrl_unlock(b);
    if (empty) return true;
  }
  return false;
}

bool rrl_key_exhausted(const void *client_addr_ptr, const rrl_key_t *key, const rate_limit_config_t *cfg) {
  if (!cfg || !cfg->configured || !key) return false;
  const struct sockaddr *client_addr = (const struct sockaddr *)client_addr_ptr;
  if (!client_addr || (client_addr->sa_family != AF_INET && client_addr->sa_family != AF_INET6)) return false;
  bool has_rate = rrl_rate(cfg, key->cls) > 0;
  if (!has_rate && cfg->all_per_second == 0) return false;
  if (rrl_is_exempt(client_addr, cfg)) return false;
  if (has_rate && rrl_bucket_empty(rrl_key_hash(client_addr, key, cfg))) return true;
  if (cfg->all_per_second > 0) {
    rrl_key_t all = { .cls = RRL_RESP_ALL };
    if (rrl_bucket_empty(rrl_key_hash(client_addr, &all, cfg))) return true;
  }
  return false;
}

bool rrl_is_client_exhausted(const void *client_addr_ptr, const rate_limit_config_t *cfg) {
  rrl_key_t key = { .cls = RRL_RESP_NOERROR };
  return rrl_key_exhausted(client_addr_ptr, &key, cfg);
}

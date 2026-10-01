#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_dynamic_update.h"
#include "dns_server_internal.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_axfr_ixfr.h"
#include "dns_snapshot_rcu.h"
#include "dns_tsig_acl.h"
#include "dns_config_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

uint32_t bump_soa_serial_in_arena(zone_arena_t *arena, const char *zone_name) {
  if (!arena || !zone_name) return 0;
  uint32_t new_serial = 0;
  for (size_t i = 0; i < arena->count; i++) {
    if (arena->records[i].type_code == 6 && domain_names_match_ci(arena->records[i].name, zone_name) && arena->records[i].rdata_count >= 3) {
      if (arena->records[i].rdata[2]) {
        uint32_t serial = strtoul(arena->records[i].rdata[2], NULL, 10);
        serial++;
        if (serial == 0) serial = 1;
        new_serial = serial;
        char buf[32];
        snprintf(buf, sizeof(buf), "%u", serial);
        /* [C-2] arena_strdup 失敗時は NULL が代入されることを防ぐ */
        char *new_rdata = arena_strdup(arena, buf);
        if (!new_rdata) {
          syslog(LOG_ERR, "[Update] arena_strdup failed bumping SOA serial; aborting update");
          return 0;
        }
        arena->records[i].rdata[2] = new_rdata;
        arena->records[i].is_cached = false;
        dns_record_preparse_cache(arena, &arena->records[i]);
      }
      break;
    }
  }
  return new_serial;
}

static uint32_t soa_serial_in_arena(const zone_arena_t *arena, const char *zone_name) {
  for (size_t i = 0; i < arena->count; i++) {
    const dns_record_t *rec = &arena->records[i];
    if (rec->type_code == 6 && rec->name && domain_names_match_ci(rec->name, zone_name) &&
        rec->rdata_count >= 3 && rec->rdata[2]) {
      return (uint32_t)strtoul(rec->rdata[2], NULL, 10);
    }
  }
  return 0;
}

int handle_dynamic_update(const uint8_t *req, size_t req_len,
                          zone_db_entry_t *entry,
                          const char *client_ip,
                          const char *matched_key_name) {
  pthread_mutex_lock(&entry->writer_lock);
  if (!wait_for_active_axfr(entry, 5000)) {
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_WARNING, "[Update] Dynamic update on zone '%s' rejected: active AXFR in progress.", entry->domain);
    return 2; // SERVFAIL
  }

  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  /* ワーカーの読み取り区間の中から呼ばれる。区間に入った後で別の writer がこのゾーンを
   * 公開していると、通常の待機は自分自身を待ってタイムアウトする (60 秒間 writer_lock を
   * 持ったまま他の writer も止める)。自分の区間だけを除いて待つ。UPDATE の応答は
   * 設定だけから作り、待機前に読んだ arena を使わない (process_dns_query_impl)。*/
  if (!rcu_writer_wait_until_safe_in_reader(entry->rcu.retire_epoch, 60000)) {
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Update] Dynamic update on zone '%s' aborted: RCU grace period wait timed out", entry->domain);
    return 2; // SERVFAIL
  }

  clone_zone_arena(z_active, z_standby);

  update_result_t result;
  int rcode = process_update_sections(req, req_len, entry->domain, z_standby, &result);
  if (rcode != 0 || !result.changed) {
    /* エラーなら何も適用しない (RFC 2136 §3.4.2.1)。何も変わらなかった UPDATE (前提条件だけ、
     * 無視された RR や既存と同じ RR だけ) はシリアルを上げず、公開も NOTIFY もしない (§3.6)。*/
    zone_arena_clear_data_pools(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    if (rcode == 0) {
      syslog(LOG_INFO, "[Update] client=%s key=%s zone='%s' prcount=%d upcount=%d: no change",
             client_ip, matched_key_name, entry->domain, result.prcount, result.upcount);
    }
    return rcode;
  }

  /* RFC 2136 §3.6: UPDATE が SOA を新しいシリアルで置き換えたときはそのシリアルを使い、
   * それ以外はサーバーがシリアルを増やす。*/
  uint32_t new_serial = result.soa_replaced ? soa_serial_in_arena(z_standby, entry->domain)
                                            : bump_soa_serial_in_arena(z_standby, entry->domain);
  if (result.soa_replaced || new_serial != 0) {
    atomic_store_explicit(&entry->serial, new_serial, memory_order_release);
  }

  if (build_zone_index(z_standby, true) != 0) {
    zone_arena_clear_data_pools(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after Update for '%s'", entry->domain);
    return 2; // SERVFAIL
  }

  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  if (cur_snap) retain_zone_snapshot(cur_snap);
  server_config_t *active_cfg_prelink = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  zone_config_t *zcfg = find_zone_config_in_view(active_cfg_prelink, entry->view_name, entry->domain);
  additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                      ? zcfg->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  prelink_zone_additional_glue(z_standby, entry->domain, snapshot_find_view(cur_snap, entry->view_name), policy);
  build_zone_response_cache(z_standby, active_cfg_prelink, entry->view_name, entry->domain);
  if (cur_snap) release_zone_snapshot(cur_snap);

  compute_ixfr_diff(entry, z_active, z_standby);

  entry->rcu.retire_epoch = rcu_writer_publish(&entry->rcu.active, z_standby);
  pthread_mutex_unlock(&entry->writer_lock);

  notify_request_send(entry);

  syslog(LOG_NOTICE,
         "[Update] client=%s key=%s zone='%s' prcount=%d upcount=%d "
         "(in-memory only, will revert on reload)",
         client_ip, matched_key_name, entry->domain, result.prcount, result.upcount);

  return 0; // NOERROR
}

void notify_request_send(zone_db_entry_t *entry) {
  atomic_store_explicit(&entry->notify_now, true, memory_order_release);
  if (g_control_kq != -1) {
    struct kevent ev;
    EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
  }
}

/* 送信して応答を待っている NOTIFY (RFC 1996 §3.6)。制御スレッドだけが読み書きするので
 * 排他は要らない。鍵は設定の入れ替えに影響されないよう値で持つ。 */
#define NOTIFY_PENDING_MAX 256
#define NOTIFY_PKT_MAX 1024
typedef struct {
  bool used;
  uint16_t id;
  struct sockaddr_storage dest;
  socklen_t dest_len;
  char domain[DNS_NAME_TEXT_SIZE];
  char view[64];
  char notify_source[INET6_ADDRSTRLEN];
  uint8_t pkt[NOTIFY_PKT_MAX];
  size_t pkt_len;
  size_t unsigned_len; /* TSIG を付ける前の長さ (再送のたびに署名し直す) */
  bool is_signed;
  char key_name[256];
  char key_alg[64];
  uint8_t key_secret[256];
  size_t key_secret_len;
  uint8_t req_mac[64];   /* 最後に送ったメッセージの MAC */
  size_t req_mac_len;
  uint8_t prev_mac[64];  /* その前の送信の MAC (遅れて届いた前回への応答も検証できるように) */
  size_t prev_mac_len;
  int sends;          /* 送信した回数 (最初の1回を含む) */
  int max_sends;      /* 1 + notify-retries */
  int interval;       /* 次の再送までの秒数 */
  bool exponential;
  time_t next_time;   /* 次の再送、最後の送信の後は諦める時刻 */
} notify_pending_t;

static notify_pending_t g_notify_pending[NOTIFY_PENDING_MAX];

static void send_single_notify(const uint8_t *req, size_t req_len,
                               const struct sockaddr *dest_addr, socklen_t addr_len,
                               const char *notify_source) {
  udp_ipc_t msg;
  memset(&msg, 0, sizeof(msg));
  msg.sock_fd_idx = -1; // -1 = NOTIFY / Dynamic UDP
  size_t copy_len = addr_len <= sizeof(msg.client_addr) ? addr_len : sizeof(msg.client_addr);
  memcpy(&msg.client_addr, dest_addr, copy_len);
  msg.addr_len = (uint16_t)addr_len;
  msg.payload_len = (uint16_t)req_len;

  int family = dest_addr->sa_family;
  if (notify_source && *notify_source) {
    if (family == AF_INET &&
        inet_pton(AF_INET, notify_source,
                  &msg.source_addr.sin.sin_addr) == 1) {
      msg.source_addr.ss_family = AF_INET;
      msg.has_source_addr = true;
    } else if (family == AF_INET6 &&
               inet_pton(AF_INET6, notify_source,
                         &msg.source_addr.sin6.sin6_addr) == 1) {
      msg.source_addr.ss_family = AF_INET6;
      msg.has_source_addr = true;
    }
  }

  uint8_t buf[2048];
  /* Defense in depth: all current callers build a small, internally-generated
   * NOTIFY packet (well under this limit), but nothing here enforced that.
   * Without this check, any future caller (or refactor) passing a larger
   * req_len would silently overflow this stack buffer. */
  if (sizeof(msg) + req_len > sizeof(buf)) {
    syslog(LOG_ERR, "[Notify] NOTIFY payload too large (%zu bytes), dropping", req_len);
    return;
  }
  memcpy(buf, &msg, sizeof(msg));
  memcpy(buf + sizeof(msg), req, req_len);
  /* [H-1] send 戻り値を検査してエラーをログに記録する */
  if (send(g_notify_ipc[1], buf, sizeof(msg) + req_len, 0) < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      syslog(LOG_WARNING, "[Notify] send to notify IPC failed: %m");
    }
  }
}

static bool sockaddr_equal(const struct sockaddr_storage *a, const struct sockaddr *b) {
  if (a->ss_family != b->sa_family) return false;
  if (b->sa_family == AF_INET) {
    const struct sockaddr_in *x = (const struct sockaddr_in *)a, *y = (const struct sockaddr_in *)b;
    return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
  }
  if (b->sa_family == AF_INET6) {
    const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a, *y = (const struct sockaddr_in6 *)b;
    return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(struct in6_addr)) == 0;
  }
  return false;
}

static void sockaddr_to_text(const struct sockaddr_storage *ss, char *buf, size_t len) {
  char ip[INET6_ADDRSTRLEN] = "?";
  unsigned port = 0;
  if (ss->ss_family == AF_INET) {
    inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, ip, sizeof(ip));
    port = ntohs(((const struct sockaddr_in *)ss)->sin_port);
  } else if (ss->ss_family == AF_INET6) {
    inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, ip, sizeof(ip));
    port = ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
  }
  snprintf(buf, len, "%s port %u", ip, port);
}

static void notify_pending_tsig_key(const notify_pending_t *p, tsig_key_t *k) {
  memset(k, 0, sizeof(*k));
  k->name = (char *)p->key_name;
  k->algorithm = (char *)p->key_alg;
  memcpy(k->secret_decoded, p->key_secret, p->key_secret_len);
  k->secret_decoded_len = p->key_secret_len;
}

/* p->pkt の先頭 unsigned_len バイト (ARCOUNT 0 の NOTIFY) に今の時刻で TSIG を付ける (RFC 8945 §5.1)。
 * 再送でも署名し直すので、間隔が Fudge (300 秒) を超えても BADTIME にならない。 */
static bool notify_sign(notify_pending_t *p) {
  tsig_key_t key;
  notify_pending_tsig_key(p, &key);
  size_t len = p->unsigned_len;
  p->pkt[10] = 0;
  p->pkt[11] = 0;
  memcpy(p->prev_mac, p->req_mac, p->req_mac_len);
  p->prev_mac_len = p->req_mac_len;
  size_t mac_len = 0;
  if (tsig_sign_packet(p->pkt, &len, NOTIFY_PKT_MAX, &key, 0, p->req_mac, &mac_len, NULL, 0, false) != 0) {
    syslog(LOG_ERR, "[Notify] zone '%s': failed to TSIG-sign NOTIFY with key '%s'", p->domain, p->key_name);
    return false;
  }
  p->req_mac_len = mac_len;
  p->pkt_len = len;
  return true;
}

/* 1つの宛先へ NOTIFY を組み立てて送り、応答待ちに登録する。宛先ごとに ID を変え (RFC 1996 §3.6 の
 * 照合は ID、QNAME、送信元アドレスとポート)、鍵があれば署名する (RFC 8945 §5.1)。
 * 同じゾーンの同じ宛先への古い NOTIFY が待っていれば置き換える (新しい版の通知で足りる)。 */
static void notify_send_to(const char *domain, const char *view_name, const struct sockaddr_storage *dest,
                           const char *notify_source, const tsig_key_t *key, const notify_retry_config_t *nr) {
  socklen_t dlen = dest->ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  notify_pending_t *slot = NULL;
  for (int i = 0; i < NOTIFY_PENDING_MAX; i++) {
    notify_pending_t *p = &g_notify_pending[i];
    if (p->used && sockaddr_equal(&p->dest, (const struct sockaddr *)dest) && domain_names_match_ci(p->domain, domain) &&
        strcmp(p->view, view_name ? view_name : "") == 0) {
      slot = p;
      break;
    }
    if (!p->used && !slot) slot = p;
  }
  notify_pending_t tmp;
  bool tracked = slot != NULL;
  if (!slot) slot = &tmp; /* 表が一杯: 1回だけ送る */
  memset(slot, 0, sizeof(*slot));
  slot->id = (uint16_t)(arc4random() & 0xFFFF);
  uint8_t *req = slot->pkt;
  memset(req, 0, DNS_HEADER_SIZE);
  req[0] = slot->id >> 8;
  req[1] = slot->id & 0xFF;
  req[2] = 0x24; // Opcode = NOTIFY (0x20) | AA = 1 (0x04) (RFC 1996 §3.4)
  req[5] = 1;
  size_t offset = DNS_HEADER_SIZE;
  long w = write_uncompressed_name(req, offset, NOTIFY_PKT_MAX, domain);
  if (w <= 0) return;
  offset += (size_t)w;
  req[offset++] = 0;
  req[offset++] = 6;
  req[offset++] = 0;
  req[offset++] = 1;
  slot->pkt_len = slot->unsigned_len = offset;
  strlcpy(slot->domain, domain, sizeof(slot->domain));
  if (key) {
    if (key->secret_decoded_len > sizeof(slot->key_secret) || !key->name || !key->algorithm) return;
    slot->is_signed = true;
    strlcpy(slot->key_name, key->name, sizeof(slot->key_name));
    strlcpy(slot->key_alg, key->algorithm, sizeof(slot->key_alg));
    memcpy(slot->key_secret, key->secret_decoded, key->secret_decoded_len);
    slot->key_secret_len = key->secret_decoded_len;
    if (!notify_sign(slot)) return;
  }
  slot->dest = *dest;
  slot->dest_len = dlen;
  strlcpy(slot->view, view_name ? view_name : "", sizeof(slot->view));
  if (notify_source) strlcpy(slot->notify_source, notify_source, sizeof(slot->notify_source));
  slot->sends = 1;
  slot->max_sends = 1 + nr->retries;
  slot->interval = nr->interval;
  slot->exponential = nr->backoff == NOTIFY_BACKOFF_EXPONENTIAL;
  slot->next_time = time(NULL) + slot->interval;
  send_single_notify(slot->pkt, slot->pkt_len, (const struct sockaddr *)&slot->dest, slot->dest_len,
                     slot->notify_source);
  if (tracked) {
    slot->used = true;
  } else {
    char a[INET6_ADDRSTRLEN + 16];
    sockaddr_to_text(dest, a, sizeof(a));
    syslog(LOG_WARNING, "[Notify] zone '%s': too many NOTIFYs awaiting an answer; NOTIFY to %s is not retransmitted",
           domain, a);
  }
}

void notify_retransmit_due(time_t now) {
  for (int i = 0; i < NOTIFY_PENDING_MAX; i++) {
    notify_pending_t *p = &g_notify_pending[i];
    if (!p->used || now < p->next_time) continue;
    if (p->sends >= p->max_sends) {
      char a[INET6_ADDRSTRLEN + 16];
      sockaddr_to_text(&p->dest, a, sizeof(a));
      syslog(LOG_WARNING, "[Notify] zone '%s': no answer from %s after %d NOTIFY message(s), giving up",
             p->domain, a, p->sends);
      p->used = false;
      continue;
    }
    /* 同じ ID で送り直す (RFC 1996 §3.6 の照合は ID で行う)。署名は今の時刻で付け直す */
    if (p->is_signed && !notify_sign(p)) {
      p->used = false;
      continue;
    }
    send_single_notify(p->pkt, p->pkt_len, (const struct sockaddr *)&p->dest, p->dest_len, p->notify_source);
    p->sends++;
    if (p->exponential && p->interval < NOTIFY_RETRY_INTERVAL_MAX) {
      p->interval = p->interval * 2 > NOTIFY_RETRY_INTERVAL_MAX ? NOTIFY_RETRY_INTERVAL_MAX : p->interval * 2;
    }
    p->next_time = now + p->interval;
  }
}

void notify_handle_response(const uint8_t *msg, size_t len, const struct sockaddr *from) {
  if (len < DNS_HEADER_SIZE || (msg[2] & 0x80) == 0 || ((msg[2] >> 3) & 0x0F) != 4) return;
  uint16_t id = (uint16_t)((msg[0] << 8) | msg[1]);
  uint16_t qdcount = (uint16_t)((msg[4] << 8) | msg[5]);
  char qname[DNS_NAME_TEXT_SIZE];
  size_t q_end;
  /* RFC 1996 §3.6: ID、QNAME、送信元アドレスとポートの一致した応答だけを NOTIFY の応答とする */
  if (qdcount < 1 || expand_wire_name_to_buffer(msg, len, DNS_HEADER_SIZE, &q_end, qname, sizeof(qname)) < 0)
    return;
  for (int i = 0; i < NOTIFY_PENDING_MAX; i++) {
    notify_pending_t *p = &g_notify_pending[i];
    if (!p->used || p->id != id || !sockaddr_equal(&p->dest, from) || !domain_names_match_ci(p->domain, qname))
      continue;
    char a[INET6_ADDRSTRLEN + 16];
    sockaddr_to_text(&p->dest, a, sizeof(a));
    unsigned rcode = msg[3] & 0x0F;
    if (p->is_signed) {
      /* RFC 8945 §5.4: 署名した要求への応答は検証できたものだけを受け付ける。無署名、検証できない、
       * MAC の無いエラー (BADKEY/BADSIG) はログに出して捨て、再送を続ける。 */
      tsig_key_t key;
      notify_pending_tsig_key(p, &key);
      uint8_t mac[64];
      size_t mac_len = 0;
      int tv = tsig_verify_packet(msg, len, &key, p->req_mac, p->req_mac_len, NULL, 0, false, mac, &mac_len);
      if (tv != 0 && p->prev_mac_len > 0) {
        int tv_prev = tsig_verify_packet(msg, len, &key, p->prev_mac, p->prev_mac_len, NULL, 0, false, mac, &mac_len);
        if (tv_prev == 0) tv = 0;
      }
      if (tv != 0) {
        const char *why = tv == -1 ? "unsigned" : tv == 16 ? "BADSIG" : tv == 17 ? "BADKEY" : tv == 18 ? "BADTIME"
                                                                                                  : "malformed TSIG";
        syslog(LOG_WARNING, "[Notify] zone '%s': ignoring NOTIFY answer from %s that fails TSIG verification "
               "with key '%s' (%s, rcode %u)", p->domain, a, p->key_name, why, rcode);
        return;
      }
    }
    if (rcode != 0) {
      syslog(LOG_WARNING, "[Notify] zone '%s': %s answered NOTIFY with rcode %u", p->domain, a, rcode);
    } else {
      syslog(LOG_DEBUG, "[Notify] zone '%s': NOTIFY acknowledged by %s", p->domain, a);
    }
    p->used = false;
    return;
  }
}

/* 宛先の一覧に重複なく加える */
static void notify_add_target(struct sockaddr_storage *targets, int *count, int max, int family,
                              const char *ip, uint16_t port) {
  struct sockaddr_storage d;
  memset(&d, 0, sizeof(d));
  if (family != AF_INET6 && inet_pton(AF_INET, ip, &((struct sockaddr_in *)&d)->sin_addr) == 1) {
    d.ss_family = AF_INET;
    ((struct sockaddr_in *)&d)->sin_port = htons(port);
  } else if (family != AF_INET && inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *)&d)->sin6_addr) == 1) {
    d.ss_family = AF_INET6;
    ((struct sockaddr_in6 *)&d)->sin6_port = htons(port);
  } else {
    return;
  }
  for (int i = 0; i < *count; i++) {
    if (sockaddr_equal(&targets[i], (const struct sockaddr *)&d)) return;
  }
  if (*count < max) targets[(*count)++] = d;
}

/* arena の中の name のアドレス (A/AAAA) を宛先に加える。見つかれば true */
static bool notify_add_glue(zone_arena_t *arena, const char *name, struct sockaddr_storage *targets, int *count,
                            int max) {
  bool found = false;
  size_t idx = calc_fnv1a_str(name) & (arena->hash_size - 1);
  for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
    dns_record_t *g = &arena->records[j];
    if ((g->type_code != 1 && g->type_code != 28) || g->rdata_count < 1 || !g->rdata[0] ||
        !domain_names_match_ci(g->name, name))
      continue;
    notify_add_target(targets, count, max, g->type_code == 1 ? AF_INET : AF_INET6, g->rdata[0], 53);
    found = true;
  }
  return found;
}

void send_notify_to_all(const char *domain, const char *view_name) {
  /* 制御スレッドだけが呼ぶ (応答待ちの表を持つため。他のスレッドは notify_request_send())。
   * 設定・スナップショット・arena を読むので、全体を読み取り区間に入れる (UDP の送信だけで、待ちは無い)。*/
  rcu_aux_read_lock();
  server_config_t *active = acquire_config_snapshot();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  if (snap) retain_zone_snapshot(snap);
  if (!active && !snap) {
    rcu_aux_read_unlock();
    return;
  }

  zone_config_t *zone = active ? find_zone_config_in_view(active, view_name, domain) : NULL;
  const char *notify_source = zone ? zone->notify_source : NULL;
  notify_retry_config_t nr = notify_retry_effective(active, zone);
  /* D-09: ゾーンに tsig-key があれば NOTIFY に署名する */
  const tsig_key_t *key = NULL;
  if (zone && zone->tsig_key && zone->tsig_key[0]) {
    key = find_tsig_key_by_name(active, zone->tsig_key);
    if (!key) syslog(LOG_ERR, "[Notify] zone '%s': tsig-key '%s' is not defined; NOTIFY sent unsigned", domain,
                     zone->tsig_key);
  }

  struct sockaddr_storage targets[64];
  int ntargets = 0;

  // 1. also-notify servers
  if (zone) {
    for (int i = 0; i < zone->also_notify_count; i++)
      notify_add_target(targets, &ntargets, 64, AF_UNSPEC, zone->also_notify[i].ip, zone->also_notify[i].port);
  }

  // 2. Addresses of the apex NS hosts except the SOA MNAME host (RFC 1996 §3.2)
  zone_db_entry_t *entry = NULL;
  view_snapshot_t *view = snap ? snapshot_find_view(snap, view_name) : NULL;
  // 同じゾーン名が別の view にもあり得るので、呼び出し元のエントリの view で引く (R-26)
  if (view) entry = find_zone_exact_in_view(view, domain);
  zone_arena_t *arena = entry ? atomic_load_explicit(&entry->rcu.active, memory_order_acquire) : NULL;
  if (arena && arena->hash_size > 0 && arena->hash_table) {
    const char *mname = NULL;
    size_t apex_idx = calc_fnv1a_str(entry->domain) & (arena->hash_size - 1);
    for (int i = arena->hash_table[apex_idx]; i != -1; i = arena->records[i].next_record) {
      if (arena->records[i].type_code == 6 && domain_names_match_ci(arena->records[i].name, entry->domain)) {
        if (arena->records[i].rdata_count >= 1 && arena->records[i].rdata[0]) mname = arena->records[i].rdata[0];
        break;
      }
    }
    for (int i = arena->hash_table[apex_idx]; i != -1; i = arena->records[i].next_record) {
      dns_record_t *rec = &arena->records[i];
      if (rec->type_code != 2 || !domain_names_match_ci(rec->name, entry->domain)) continue;
      if (rec->rdata_count < 1 || !rec->rdata[0]) continue;
      const char *ns_target = rec->rdata[0];
      if (mname && domain_names_match_ci(ns_target, mname)) continue;
      // A. in-zone glue, B. otherwise the address in a sibling zone of the same view
      if (notify_add_glue(arena, ns_target, targets, &ntargets, 64)) continue;
      zone_db_entry_t *sib_entry = find_zone_in_view(view, ns_target);
      if (!sib_entry || sib_entry == entry) continue;
      zone_arena_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
      if (sib_arena && sib_arena->hash_size > 0 && sib_arena->hash_table)
        notify_add_glue(sib_arena, ns_target, targets, &ntargets, 64);
    }
  }

  for (int i = 0; i < ntargets; i++) notify_send_to(domain, view_name, &targets[i], notify_source, key, &nr);

  if (entry && ntargets > 0) {
    atomic_fetch_add_explicit(&entry->observatory.notify_sent, ntargets, memory_order_relaxed);
    atomic_store_explicit(&entry->observatory.last_notify_time, (uint64_t)time(NULL), memory_order_relaxed);
  }

  if (snap) release_zone_snapshot(snap);
  if (active) release_config_snapshot(active);
  rcu_aux_read_unlock();
}

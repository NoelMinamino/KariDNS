#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_dynamic_update.h"
#include "dns_server_internal.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_zone_image.h"
#include "dns_axfr_ixfr.h"
#include "dns_snapshot_rcu.h"
#include "dns_tsig_acl.h"
#include "dns_config_parser.h"
#include "dns_priv_sandbox.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

/* 頂点の SOA のシリアルを 1 増やし、新しいシリアルを返す。0 は失敗 (SOA が無い、arena の確保失敗)。
 * 増やした結果の 0 は 1 にするので、成功時に 0 は返らない。 */
uint32_t bump_soa_serial_in_arena(zone_arena_t *arena, const char *zone_name) {
  if (!arena || !zone_name) return 0;
  uint32_t new_serial = 0;
  /* B8t-1: a zone can hold several apex SOA RRs (tinydns locations, tags), all with the one zone serial (RFC 2181 §6.1):
   * every one gets the new serial, computed once from the first. */
  for (size_t i = 0; i < arena->count; i++) {
    if (arena->records[i].type_code == 6 && domain_names_match_ci(arena->records[i].name, zone_name) && arena->records[i].rdata_count >= 3) {
      if (arena->records[i].rdata[2]) {
        if (new_serial == 0) {
          uint32_t serial = strtoul(arena->records[i].rdata[2], NULL, 10);
          serial++;
          if (serial == 0) serial = 1;
          new_serial = serial;
        }
        char buf[32];
        snprintf(buf, sizeof(buf), "%u", new_serial);
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

  zone_version_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  /* S5 B-2: the update is applied to a builder thawed from the published image (S5 B-3: a stack builder freed on every
   * way out; the result is published as a new version, the old one goes on the retire stack) */
  zone_arena_t z_builder;
  zone_arena_t *z_standby = &z_builder;
  zone_arena_init(z_standby);
  if (thaw_zone_arena(z_active, z_standby) != 0) {
    zone_arena_destroy(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Update] Dynamic update on zone '%s' aborted: cannot rebuild the zone from its image", entry->domain);
    return 2; // SERVFAIL
  }

  update_result_t result;
  int rcode = process_update_sections(req, req_len, entry->domain, z_standby, &result);
  if (rcode != 0 || !result.changed) {
    /* エラーなら何も適用しない (RFC 2136 §3.4.2.1)。何も変わらなかった UPDATE (前提条件だけ、
     * 無視された RR や既存と同じ RR だけ) はシリアルを上げず、公開も NOTIFY もしない (§3.6)。*/
    zone_arena_destroy(z_standby);
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
  if (!result.soa_replaced && new_serial == 0) {
    /* X-17: シリアルを上げられなかった (arena の確保失敗、または頂点の SOA が無い)。変更したゾーンを
     * 同じシリアルで公開するとセカンダリが転送しない (RFC 2136 §3.6) ので、UPDATE 全体を捨てて
     * SERVFAIL にする (§3.4.2.1 と同じく何も適用しない)。 */
    zone_arena_destroy(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Update] client=%s zone='%s': SOA serial could not be incremented; update aborted",
           client_ip, entry->domain);
    return 2; // SERVFAIL
  }

  /* S5 B-2: an RR that cannot be written in wire format is dropped with a warning, the rest of the UPDATE is applied
   * (as for a zone file); the published image holds only RRs that can be served */
  zone_drop_unencodable_logged(z_standby, entry->domain, "the dynamic update");

  zone_arena_shrink_records(z_standby);
  if (build_zone_index(z_standby, true) != 0) {
    zone_arena_destroy(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after Update for '%s'", entry->domain);
    return 2; // SERVFAIL
  }

  /* S5 B-1: 応答を作る側が読むイメージ。公開の直前に 1 回だけ作る。作れなければ索引を作れなかったときと同じく UPDATE を捨てる */
  z_standby->image = zone_image_freeze(z_standby, entry->domain);
  if (!z_standby->image) {
    zone_arena_destroy(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Failed to build the zone image after Update for '%s'", entry->domain);
    return 2; // SERVFAIL
  }
  zone_arena_free_builder(z_standby);
  zone_version_t *z_next = zone_version_new(z_standby);
  zone_arena_destroy(z_standby);
  if (!z_next) {
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Update] Dynamic update on zone '%s' aborted: out of memory", entry->domain);
    return 2; // SERVFAIL
  }

  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  if (cur_snap) retain_zone_snapshot(cur_snap);
  server_config_t *active_cfg_prelink = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  const zone_config_t *zcfg = zone_entry_config(active_cfg_prelink, entry);
  additional_from_auth_t policy = (zcfg && zext(zcfg)->additional_from_auth_specified)
                                      ? zext(zcfg)->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  zone_glue_track_build(z_next, entry->domain, snapshot_find_view(cur_snap, entry->view_name), policy);
  build_zone_response_cache(z_next, active_cfg_prelink, entry);
  if (cur_snap) release_zone_snapshot(cur_snap);

  compute_ixfr_diff(entry, z_active, z_next);
  /* 公開する直前に記録する (索引の構築に失敗して公開しなかった UPDATE のシリアルを残さない) */
  atomic_store_explicit(&entry->serial, new_serial, memory_order_release);

  zone_publish(entry, z_next);
  pthread_mutex_unlock(&entry->writer_lock);

  notify_request_send(entry);

  syslog(LOG_NOTICE,
         "[Update] client=%s key=%s zone='%s' prcount=%d upcount=%d "
         "(in-memory only, will revert on reload)",
         client_ip, matched_key_name, entry->domain, result.prcount, result.upcount);

  return 0; // NOERROR
}

void notify_request_send(zone_db_entry_t *entry) {
  zone_notify_request(entry);
  int kq = atomic_load_explicit(&g_control_kq, memory_order_acquire);
  if (kq != -1) {
    struct kevent ev;
    EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);
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
  bool has_src;          /* notify-source(-v6) / the `source` of the also-notify list: the local address the NOTIFY leaves from (the family of dest) */
  uint8_t src[16];
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
  bool tcp_stage;     /* NOTIFY over TCP: the message goes out over a TCP connection (tcp-only, or the UDP attempts are used up), see notify_tcp_start() */
  int tcp_tries;      /* TCP attempts the stage makes: 2 for tcp-only, 1 after UDP (BIND notify_done(), see the comment above notify_tcp_start()) */
  int tcp_timeout_ms; /* notify-tcp-timeout: the time one TCP attempt (connection and answer together) may take */
  int sends;          /* 送信した回数 (最初の1回を含む) */
  int max_sends;      /* 1 + notify-retries */
  int interval;       /* 次の再送までの秒数 */
  bool exponential;
  time_t next_time;   /* 次の再送、最後の送信の後は諦める時刻 */
} notify_pending_t;

static notify_pending_t g_notify_pending[NOTIFY_PENDING_MAX];
/* notify-rate (the control thread only): the budget of first NOTIFY messages in this second, and the rate of the configuration last used */
static xfr_rl_t g_notify_rl;
static uint32_t g_notify_rate = XFR_RATE_DEFAULT;

static void send_single_notify(const uint8_t *req, size_t req_len,
                               const struct sockaddr *dest_addr, socklen_t addr_len,
                               bool has_src, const uint8_t src[16]) {
  udp_ipc_t msg;
  memset(&msg, 0, sizeof(msg));
  msg.sock_fd_idx = -1; // -1 = NOTIFY / Dynamic UDP
  size_t copy_len = addr_len <= sizeof(msg.client_addr) ? addr_len : sizeof(msg.client_addr);
  memcpy(&msg.client_addr, dest_addr, copy_len);
  msg.addr_len = (uint16_t)addr_len;
  msg.payload_len = (uint16_t)req_len;

  /* the Router sends from a socket bound to this address (pre-bound at start-up from the same configuration) */
  int family = dest_addr->sa_family;
  if (has_src) {
    if (family == AF_INET) {
      memcpy(&msg.source_addr.sin.sin_addr, src, sizeof(msg.source_addr.sin.sin_addr));
      msg.source_addr.ss_family = AF_INET;
      msg.has_source_addr = true;
    } else if (family == AF_INET6) {
      memcpy(&msg.source_addr.sin6.sin6_addr, src, sizeof(msg.source_addr.sin6.sin6_addr));
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

/* The header and the question of an answer to a NOTIFY (RFC 1996 §3.6): QR set, opcode NOTIFY, a question.  The caller compares the ID
 * and the QNAME with the NOTIFY it sent (and, over UDP, the address and port it came from).  false = not an answer to a NOTIFY. */
static bool notify_parse_answer(const uint8_t *msg, size_t len, uint16_t *id, char *qname, size_t qsz, unsigned *rcode) {
  if (len < DNS_HEADER_SIZE || (msg[2] & 0x80) == 0 || ((msg[2] >> 3) & 0x0F) != 4) return false;
  uint16_t qdcount = (uint16_t)((msg[4] << 8) | msg[5]);
  size_t q_end;
  if (qdcount < 1 || expand_wire_name_to_buffer(msg, len, DNS_HEADER_SIZE, &q_end, qname, qsz) < 0) return false;
  *id = (uint16_t)((msg[0] << 8) | msg[1]);
  *rcode = msg[3] & 0x0F;
  return true;
}

/* RFC 8945 §5.4: the answer to a signed NOTIFY counts only when its TSIG verifies, against the MAC of the message last sent or (a late
 * answer to the one before) the previous one.  0 = verified; else the tsig_verify_packet() result (-1 unsigned, 16 BADSIG, 17 BADKEY,
 * 18 BADTIME, other: malformed). */
static int notify_answer_tsig(const notify_pending_t *p, const uint8_t *msg, size_t len) {
  tsig_key_t key;
  notify_pending_tsig_key(p, &key);
  uint8_t mac[64];
  size_t mac_len = 0;
  int tv = tsig_verify_packet(msg, len, &key, p->req_mac, p->req_mac_len, NULL, 0, false, mac, &mac_len);
  if (tv != 0 && p->prev_mac_len > 0) {
    int tv_prev = tsig_verify_packet(msg, len, &key, p->prev_mac, p->prev_mac_len, NULL, 0, false, mac, &mac_len);
    if (tv_prev == 0) tv = 0;
  }
  return tv;
}

static const char *notify_tsig_why(int tv) {
  return tv == -1 ? "unsigned" : tv == 16 ? "BADSIG" : tv == 17 ? "BADKEY" : tv == 18 ? "BADTIME" : "malformed TSIG";
}

/* An answer that was accepted: log it (the same words over UDP and TCP) */
static void notify_log_answer(const notify_pending_t *p, const char *a, unsigned rcode, const char *via) {
  if (rcode != 0) syslog(LOG_WARNING, "[Notify] zone '%s': %s answered NOTIFY%s with rcode %u", p->domain, a, via, rcode);
  else syslog(LOG_DEBUG, "[Notify] zone '%s': NOTIFY acknowledged by %s%s", p->domain, a, via);
}

/* ---- NOTIFY over TCP ----
 * BIND 9.20 (lib/dns/zone.c notify_send_toaddr() and notify_done(), lib/dns/request.c):
 *  - the `tcp-only yes` option of the `server` statement that covers the target (bin/named/server.c configure_peer() dns_peer_setforcetcp(),
 *    read by dns_peer_getforcetcp(); the option bit is DNS_REQUESTOPT_TCP) sends the NOTIFY over TCP from the start;
 *  - otherwise the NOTIFY goes out over UDP (udptimeout 5 s, udpretries 2: dns_request_create() sends three datagrams, at 0, 5 and 10 s, and
 *    req_response() gives up at 15 s), and a request that fails (no answer, an answer that cannot be parsed or whose TSIG does not verify) is
 *    made once more over TCP (DNS_NOTIFY_TCP, "notify to %s failed: %s: retrying over TCP"); the UDP attempts here are notify-retries /
 *    notify-retry-interval / notify-retry-backoff (the defaults 2 and 5 s, fixed, are BIND's schedule: dns_config_parser.h), and the TCP attempt
 *    follows the last;
 *  - a TCP request has a timeout of 15 s for the connection and the answer together (notify-tcp-timeout, default 15), one message each way
 *    (RFC 1035 §4.2.2: two octets of length first), signed like the UDP one (RFC 8945 §5.1) with the answer verified against the request MAC (§5.3);
 *  - with tcp-only the DNS_NOTIFY_TCP flag is not set, so notify_done() finds a failed TCP request "not yet retried over TCP" and makes it a
 *    second time: two TCP attempts in all (a BIND quirk, kept so that the two servers retry alike);
 *  - the retry goes through the notify rate limiter again (notify-rate); here the first TCP attempt takes a token like a first UDP message
 *    and the second TCP attempt of tcp-only follows at once.
 * The local address is the same as the UDP message's (notify-source(-v6), the `source` of the list, the server statement's: the connect broker
 * binds it before connect(), config_xfr_source_allowed()).  The Backend may not connect() itself (Capsicum): the connection comes from the
 * broker (broker_connect_opts()) like the SOA check and the transfers of a secondary, and the exchange runs in a detached thread of its own
 * (as the refresh of a secondary does, axfr_bg_thread_func()) because it waits up to notify-tcp-timeout (15 s) for a peer that is not under our control: the
 * thread works on a copy of the pending entry and logs the outcome, nothing else is shared with the control thread except the counter of
 * the threads in flight (g_notify_tcp_active), so no lock is needed. */
#define NOTIFY_TCP_MAX 64         /* threads in flight; one more waits in the pending table for a free place */
#define NOTIFY_TCP_RESP_MAX 4096  /* an answer to a NOTIFY is a header, the question and perhaps a TSIG: a longer one is not an answer */
static _Atomic int g_notify_tcp_active;

typedef struct {
  notify_pending_t p; /* a copy: the table slot may be reused while the thread runs */
  int tries;
} notify_tcp_job_t;

int notify_tcp_in_flight(void) { return atomic_load_explicit(&g_notify_tcp_active, memory_order_acquire); }

static int64_t notify_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait until fd is ready for ev or deadline_ms (CLOCK_MONOTONIC) has passed */
static int notify_tcp_wait(int fd, short ev, int64_t deadline_ms) {
  for (;;) {
    int64_t left = deadline_ms - notify_now_ms();
    if (left <= 0) return NOTIFY_TCP_TIMEOUT;
    struct pollfd pfd = {.fd = fd, .events = ev};
    int r = poll(&pfd, 1, left > 60000 ? 60000 : (int)left);
    if (r > 0) return NOTIFY_TCP_OK; /* ready, or HUP / ERR: the next send() / recv() says which */
    if (r < 0 && errno != EINTR) return NOTIFY_TCP_IO;
  }
}

/* send (wr) or receive exactly n octets; the whole transfer is held to deadline_ms (a peer that sends one octet a second does not hold the thread) */
static int notify_tcp_io(int fd, uint8_t *buf, size_t n, bool wr, int64_t deadline_ms) {
  size_t done = 0;
  while (done < n) {
    int w = notify_tcp_wait(fd, wr ? POLLOUT : POLLIN, deadline_ms);
    if (w != NOTIFY_TCP_OK) return w;
    ssize_t k = wr ? send(fd, buf + done, n - done, MSG_NOSIGNAL | MSG_DONTWAIT) : recv(fd, buf + done, n - done, MSG_DONTWAIT);
    if (k < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
      return NOTIFY_TCP_IO;
    }
    if (k == 0) return wr ? NOTIFY_TCP_IO : NOTIFY_TCP_CLOSED;
    done += (size_t)k;
  }
  return NOTIFY_TCP_OK;
}

/* Send one DNS message over the connected TCP socket fd (RFC 1035 §4.2.2: a two-octet length first) and read the one message that answers it.
 * The answer is the peer's: its length is checked against the header size and cap before anything is read into resp.  timeout_ms covers the
 * whole exchange. */
int notify_tcp_roundtrip(int fd, const uint8_t *msg, size_t len, uint8_t *resp, size_t cap, size_t *resp_len, int timeout_ms) {
  uint8_t frame[2 + NOTIFY_PKT_MAX];
  if (len > NOTIFY_PKT_MAX) return NOTIFY_TCP_IO;
  frame[0] = (uint8_t)(len >> 8);
  frame[1] = (uint8_t)(len & 0xFF);
  memcpy(frame + 2, msg, len);
  int64_t deadline = notify_now_ms() + (timeout_ms > 0 ? timeout_ms : 1);
  int rc = notify_tcp_io(fd, frame, 2 + len, true, deadline);
  if (rc != NOTIFY_TCP_OK) return rc;
  uint8_t lp[2];
  if ((rc = notify_tcp_io(fd, lp, 2, false, deadline)) != NOTIFY_TCP_OK) return rc;
  size_t rl = ((size_t)lp[0] << 8) | lp[1];
  if (rl < DNS_HEADER_SIZE || rl > cap) return NOTIFY_TCP_BAD_LENGTH;
  if ((rc = notify_tcp_io(fd, resp, rl, false, deadline)) != NOTIFY_TCP_OK) return rc;
  *resp_len = rl;
  return NOTIFY_TCP_OK;
}

/* One TCP attempt for the NOTIFY of p (a private copy): a new ID and signature, a connection from the source address of p, the exchange, the
 * checks of the answer.  true = answered (rcode set); false = failed, why says how. */
static bool notify_tcp_attempt(notify_pending_t *p, unsigned *rcode, char *why, size_t whysz) {
  p->id = (uint16_t)(arc4random() & 0xFFFF);
  p->pkt[0] = (uint8_t)(p->id >> 8);
  p->pkt[1] = (uint8_t)(p->id & 0xFF);
  p->pkt_len = p->unsigned_len;
  if (p->is_signed && !notify_sign(p)) {
    snprintf(why, whysz, "cannot sign the message");
    return false;
  }
  tcp_sockopts_t o;
  memset(&o, 0, sizeof(o));
  o.connect_timeout_ms = p->tcp_timeout_ms;
  if (p->has_src) {
    o.has_src = 1;
    memcpy(o.src, p->src, sizeof(o.src));
  }
  int64_t deadline = notify_now_ms() + p->tcp_timeout_ms;
  int fd = broker_connect_opts(p->dest.ss_family, SOCK_STREAM, (struct sockaddr *)&p->dest, p->dest_len, &o);
  if (fd < 0) {
    snprintf(why, whysz, "cannot connect%s", p->has_src ? " (from the configured notify source address)" : "");
    return false;
  }
  limit_client_socket_rights(fd);
  uint8_t resp[NOTIFY_TCP_RESP_MAX];
  size_t rlen = 0;
  int64_t left = deadline - notify_now_ms();
  int rc = notify_tcp_roundtrip(fd, p->pkt, p->pkt_len, resp, sizeof(resp), &rlen, left > 0 ? (int)left : 1);
  close(fd);
  if (rc != NOTIFY_TCP_OK) {
    snprintf(why, whysz, "%s", rc == NOTIFY_TCP_TIMEOUT ? "timed out" : rc == NOTIFY_TCP_CLOSED ? "the connection was closed before the answer"
                              : rc == NOTIFY_TCP_BAD_LENGTH ? "the answer has an impossible length" : "connection error");
    return false;
  }
  uint16_t rid = 0;
  char qname[DNS_NAME_TEXT_SIZE];
  /* RFC 1996 §3.6: the ID and the QNAME of the NOTIFY (the connection itself fixes the address and port) */
  if (!notify_parse_answer(resp, rlen, &rid, qname, sizeof(qname), rcode) || rid != p->id || !domain_names_match_ci(p->domain, qname)) {
    snprintf(why, whysz, "the reply is not an answer to this NOTIFY");
    return false;
  }
  if (p->is_signed) {
    int tv = notify_answer_tsig(p, resp, rlen);
    if (tv != 0) {
      snprintf(why, whysz, "the answer fails TSIG verification with key '%s' (%s, rcode %u)", p->key_name, notify_tsig_why(tv), *rcode);
      return false;
    }
  }
  return true;
}

static void *notify_tcp_thread(void *arg) {
  notify_tcp_job_t *job = arg;
  notify_pending_t *p = &job->p;
  char a[INET6_ADDRSTRLEN + 16];
  sockaddr_to_text(&p->dest, a, sizeof(a));
  for (int attempt = 1; attempt <= job->tries; attempt++) {
    char why[192];
    unsigned rcode = 0;
    if (notify_tcp_attempt(p, &rcode, why, sizeof(why))) {
      notify_log_answer(p, a, rcode, " over TCP");
      break;
    }
    if (attempt < job->tries) syslog(LOG_NOTICE, "[Notify] zone '%s': NOTIFY to %s over TCP failed: %s: retrying over TCP", p->domain, a, why);
    else syslog(LOG_WARNING, "[Notify] zone '%s': NOTIFY to %s over TCP failed: %s", p->domain, a, why);
  }
  free(job);
  atomic_fetch_sub_explicit(&g_notify_tcp_active, 1, memory_order_acq_rel);
  return NULL;
}

/* Room for one more TCP exchange (only the control thread adds to the count, so a true answer holds until it calls notify_tcp_start()) */
static bool notify_tcp_room(void) { return atomic_load_explicit(&g_notify_tcp_active, memory_order_acquire) < NOTIFY_TCP_MAX; }

/* Start the TCP exchange for the NOTIFY in p.  1 = started (the thread logs the outcome); 0 = no room, try again later; -1 = could not start (logged). */
static int notify_tcp_start(const notify_pending_t *p) {
  if (!xfr_counter_acquire(&g_notify_tcp_active, NOTIFY_TCP_MAX)) return 0;
  notify_tcp_job_t *job = malloc(sizeof(*job));
  if (!job) {
    atomic_fetch_sub_explicit(&g_notify_tcp_active, 1, memory_order_acq_rel);
    syslog(LOG_ERR, "[Notify] zone '%s': out of memory; NOTIFY over TCP not sent", p->domain);
    return -1;
  }
  job->p = *p;
  job->tries = p->tcp_tries > 0 ? p->tcp_tries : 1;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, 256 * 1024);
  pthread_t tid;
  int rc = pthread_create(&tid, &attr, notify_tcp_thread, job);
  pthread_attr_destroy(&attr);
  if (rc != 0) {
    free(job);
    atomic_fetch_sub_explicit(&g_notify_tcp_active, 1, memory_order_acq_rel);
    syslog(LOG_ERR, "[Notify] zone '%s': cannot start a thread; NOTIFY over TCP not sent", p->domain);
    return -1;
  }
  return 1;
}

/* The NOTIFY of p goes out now: a UDP datagram, or the TCP exchange (p leaves the table: the thread has a copy).  The caller has taken the
 * notify-rate token and, for TCP, checked notify_tcp_room(). */
static void notify_xmit(notify_pending_t *p, time_t now) {
  if (!p->tcp_stage) {
    send_single_notify(p->pkt, p->pkt_len, (const struct sockaddr *)&p->dest, p->dest_len, p->has_src, p->src);
    return;
  }
  if (notify_tcp_start(p) == 0) { /* cannot happen after notify_tcp_room(); held for the next tick */
    p->sends = 0;
    p->next_time = now + 1;
    return;
  }
  p->used = false;
}

/* The UDP attempts did not get the NOTIFY answered (or the answer was no good): the message is made over TCP once (BIND notify_done()) */
static void notify_to_tcp(notify_pending_t *p, time_t now, bool bad_answer) {
  char a[INET6_ADDRSTRLEN + 16];
  sockaddr_to_text(&p->dest, a, sizeof(a));
  if (bad_answer) syslog(LOG_NOTICE, "[Notify] zone '%s': the answer from %s was no good; retrying over TCP", p->domain, a);
  else syslog(LOG_NOTICE, "[Notify] zone '%s': no answer from %s after %d NOTIFY message(s); retrying over TCP", p->domain, a, p->sends);
  p->tcp_stage = true;
  p->tcp_tries = 1;
  p->sends = 0; /* "not sent yet": notify_retransmit_due() sends it with the notify-rate budget */
  p->next_time = now;
}

/* 1つの宛先へ NOTIFY を組み立てて送り、応答待ちに登録する。宛先ごとに ID を変え (RFC 1996 §3.6 の
 * 照合は ID、QNAME、送信元アドレスとポート)、鍵があれば署名する (RFC 8945 §5.1)。
 * 同じゾーンの同じ宛先への古い NOTIFY が待っていれば置き換える (新しい版の通知で足りる)。 */
static void notify_send_to(const char *domain, const char *view_name, const struct sockaddr_storage *dest,
                           bool has_src, const uint8_t *src, const tsig_key_t *key, const notify_retry_config_t *nr, uint32_t rate,
                           bool tcp_only) {
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
  slot->has_src = has_src;
  if (has_src && src) memcpy(slot->src, src, sizeof(slot->src));
  slot->max_sends = 1 + nr->retries;
  slot->interval = nr->interval;
  slot->exponential = nr->backoff == NOTIFY_BACKOFF_EXPONENTIAL;
  time_t now = time(NULL);
  /* tcp-only (the `server` statement): the NOTIFY goes over TCP from the start, two attempts (see the comment above notify_tcp_start()) */
  slot->tcp_stage = tcp_only;
  slot->tcp_tries = tcp_only ? 2 : 1;
  slot->tcp_timeout_ms = (nr->tcp_timeout > 0 ? nr->tcp_timeout : NOTIFY_TCP_TIMEOUT_DEFAULT) * 1000;
  /* notify-rate: at most that many NOTIFY messages a second.  One over the budget is sent by notify_retransmit_due() at a later tick, with
   * sends == 0 ("not sent yet"); when the table of pending NOTIFYs is full (not tracked) it cannot wait and goes now.  A TCP exchange also
   * waits for a free place among the threads in flight. */
  bool room = !slot->tcp_stage || notify_tcp_room();
  if (!tracked && !room) {
    char a[INET6_ADDRSTRLEN + 16];
    sockaddr_to_text(dest, a, sizeof(a));
    syslog(LOG_WARNING, "[Notify] zone '%s': too many NOTIFYs awaiting an answer; NOTIFY to %s over TCP is not sent", domain, a);
    return;
  }
  slot->used = tracked;
  if (!tracked || (room && xfr_rl_take(&g_notify_rl, rate, now))) {
    slot->sends = 1;
    slot->next_time = now + slot->interval;
    notify_xmit(slot, now);
  } else {
    slot->sends = 0;
    slot->next_time = now + 1;
  }
  if (!tracked) {
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
    if (p->sends > 0 && p->sends >= p->max_sends) {
      /* BIND notify_done(): a NOTIFY that got no answer over UDP is made once more over TCP; one that was over TCP already is gone with its
       * thread (notify_xmit()), so this is the end of the UDP attempts */
      notify_to_tcp(p, now, false);
    }
    if (p->sends == 0) {
      /* held back by notify-rate (or, over TCP, by the number of exchanges in flight): this is its first message */
      if ((p->tcp_stage && !notify_tcp_room()) || !xfr_rl_take(&g_notify_rl, g_notify_rate, now)) {
        p->next_time = now + 1;
        continue;
      }
      if (!p->tcp_stage && p->is_signed && !notify_sign(p)) {
        p->used = false;
        continue;
      }
      p->sends = 1;
      p->next_time = now + p->interval;
      notify_xmit(p, now);
      continue;
    }
    /* 同じ ID で送り直す (RFC 1996 §3.6 の照合は ID で行う)。署名は今の時刻で付け直す */
    if (p->is_signed && !notify_sign(p)) {
      p->used = false;
      continue;
    }
    send_single_notify(p->pkt, p->pkt_len, (const struct sockaddr *)&p->dest, p->dest_len, p->has_src, p->src);
    p->sends++;
    if (p->exponential && p->interval < NOTIFY_RETRY_INTERVAL_MAX) {
      p->interval = p->interval * 2 > NOTIFY_RETRY_INTERVAL_MAX ? NOTIFY_RETRY_INTERVAL_MAX : p->interval * 2;
    }
    p->next_time = now + p->interval;
  }
}

void notify_handle_response(const uint8_t *msg, size_t len, const struct sockaddr *from) {
  uint16_t id;
  unsigned rcode;
  char qname[DNS_NAME_TEXT_SIZE];
  /* RFC 1996 §3.6: ID、QNAME、送信元アドレスとポートの一致した応答だけを NOTIFY の応答とする */
  if (!notify_parse_answer(msg, len, &id, qname, sizeof(qname), &rcode)) return;
  for (int i = 0; i < NOTIFY_PENDING_MAX; i++) {
    notify_pending_t *p = &g_notify_pending[i];
    if (!p->used || p->id != id || !sockaddr_equal(&p->dest, from) || !domain_names_match_ci(p->domain, qname))
      continue;
    char a[INET6_ADDRSTRLEN + 16];
    sockaddr_to_text(&p->dest, a, sizeof(a));
    if (p->is_signed) {
      /* RFC 8945 §5.4: 署名した要求への応答は検証できたものだけを受け付ける。無署名、検証できない、
       * MAC の無いエラー (BADKEY/BADSIG) はログに出して捨てる。BIND (notify_done()) は応答が使えなかった要求を TCP でもう一度送る
       * ので、UDP の段階ならここから TCP に移る (再送の残りは待たない)。 */
      int tv = notify_answer_tsig(p, msg, len);
      if (tv != 0) {
        syslog(LOG_WARNING, "[Notify] zone '%s': ignoring NOTIFY answer from %s that fails TSIG verification "
               "with key '%s' (%s, rcode %u)", p->domain, a, p->key_name, notify_tsig_why(tv), rcode);
        if (!p->tcp_stage) notify_to_tcp(p, time(NULL), true);
        return;
      }
    }
    notify_log_answer(p, a, rcode, "");
    p->used = false;
    return;
  }
}

/* One NOTIFY destination: the address, the key that signs the message (NULL = unsigned) and the also-notify element it came from (NULL for
 * an NS host of the zone), which carries the `source` of its list */
typedef struct {
  struct sockaddr_storage addr;
  const tsig_key_t *key;
  const notify_target_t *tpl;
} notify_dest_t;

/* 宛先の一覧に重複なく加える */
static void notify_add_target(notify_dest_t *targets, int *count, int max, int family, const char *ip, uint16_t port,
                              const tsig_key_t *tkey, const notify_target_t *tpl) {
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
    if (sockaddr_equal(&targets[i].addr, (const struct sockaddr *)&d)) return;
  }
  if (*count < max) {
    targets[*count].key = tkey;
    targets[*count].tpl = tpl;
    targets[(*count)++].addr = d;
  }
}

/* arena の中の name のアドレス (A/AAAA) を宛先に加える。見つかれば true */
static bool notify_add_glue(const zone_image_t *img, const char *name, notify_dest_t *targets, int *count, int max, const tsig_key_t *tkey) {
  bool found = false;
  uint32_t id = zone_image_find_name(img, name);
  if (id == ZONE_IMAGE_NONE) return false;
  uint32_t end = zone_image_name_first_rr(img, id) + zone_image_name_rr_count(img, id);
  for (uint32_t k = zone_image_name_first_rr(img, id); k < end; k++) {
    uint16_t t = zone_image_rr_type(img, k);
    uint16_t len = zone_image_rr_rdlen(img, k);
    char ip[INET6_ADDRSTRLEN];
    if ((t != 1 || len != 4) && (t != 28 || len != 16)) continue;
    if (!inet_ntop(t == 1 ? AF_INET : AF_INET6, zone_image_rr_rdata(img, k), ip, sizeof(ip))) continue;
    notify_add_target(targets, count, max, t == 1 ? AF_INET : AF_INET6, ip, 53, tkey, NULL);
    found = true;
  }
  return found;
}

void send_notify_to_all(zone_db_entry_t *entry) {
  const char *domain = entry->domain;
  const char *view_name = entry->view_name;
  /* 制御スレッドだけが呼ぶ (応答待ちの表を持つため。他のスレッドは notify_request_send())。
   * 設定・スナップショット・arena を読むので、全体を読み取り区間に入れる (UDP の送信と TCP の交換を始めるだけで、待ちは無い)。*/
  rcu_aux_read_lock();
  server_config_t *active = acquire_config_snapshot();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  if (snap) retain_zone_snapshot(snap);
  if (!active && !snap) {
    rcu_aux_read_unlock();
    return;
  }

  /* DB のゾーンは dbcfg (DB のゾーンは active が無くても設定を持つ) */
  const zone_config_t *zone = zone_entry_config(active, entry);
  /* notify (BIND 9.20 ARM): no = nothing is sent (also for `karictl notify`); primary-only = only for primary zones, so a secondary or
   * catalog member does not pass a transfer on; explicit = only the also-notify list, not the NS hosts of the zone */
  notify_mode_t mode = notify_mode_effective(active, zone, view_name);
  if (mode == NOTIFY_MODE_NO || (mode == NOTIFY_MODE_PRIMARY_ONLY && zone_entry_ticks(entry))) {
    if (snap) release_zone_snapshot(snap);
    if (active) release_config_snapshot(active);
    rcu_aux_read_unlock();
    return;
  }
  /* notify-source / notify-source-v6, notify-to-soa, notify-rate (BIND 9.20): zone, else view, else options */
  xfr_eff_t eff;
  xfr_opts_effective(active, zone, view_name, &eff);
  g_notify_rate = xfr_cfg_limit(active, XL_NOTIFY_RATE);
  notify_retry_config_t nr = notify_retry_effective(active, zone);
  /* D-09: ゾーンに tsig-key があれば NOTIFY に署名する */
  const tsig_key_t *key = NULL;
  if (zone && zext(zone)->tsig_key && zext(zone)->tsig_key[0]) {
    key = find_tsig_key_in_view(active, view_name, zext(zone)->tsig_key);
    if (!key) syslog(LOG_ERR, "[Notify] zone '%s': tsig-key '%s' is not defined; NOTIFY sent unsigned", domain,
                     zext(zone)->tsig_key);
  }

  notify_dest_t targets[64];
  int ntargets = 0;

  // 1. also-notify servers: the zone's list, else its view's, else options' (BIND 9.20 ARM).  An address with its own `key` is signed
  // with that key; the others with the zone's tsig-key (as the NS-derived targets below).
  const notify_target_t *an = NULL;
  int an_count = also_notify_effective(active, zone, view_name, &an);
  for (int i = 0; i < an_count; i++) {
    const tsig_key_t *tk = key;
    if (an[i].key) {
      tk = find_tsig_key_in_view(active, view_name, an[i].key);
      if (!tk) syslog(LOG_ERR, "[Notify] zone '%s': also-notify key '%s' is not defined; NOTIFY sent unsigned", domain, an[i].key);
    }
    notify_add_target(targets, &ntargets, 64, AF_UNSPEC, an[i].ip, (uint16_t)an[i].port, tk, &an[i]);
  }

  // 2. Addresses of the apex NS hosts except the SOA MNAME host (RFC 1996 §3.2) -- unless notify-to-soa yes (BIND 9.20 ARM: "do not check the
  // name servers in the NS RRset against the SOA MNAME")
  // 同じゾーン名が別の view にもあり得るので、呼び出し元のエントリの view で引く (R-26)
  view_snapshot_t *view = snap ? snapshot_find_view(snap, view_name) : NULL;
  zone_version_t *arena = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  const zone_image_t *img = arena && mode != NOTIFY_MODE_EXPLICIT ? arena->image : NULL;
  uint32_t apex_id = img ? zone_image_find_name(img, entry->domain) : ZONE_IMAGE_NONE;
  if (apex_id != ZONE_IMAGE_NONE) {
    char mname_buf[DNS_NAME_TEXT_SIZE];
    const char *mname = NULL;
    uint32_t apex_end = zone_image_name_first_rr(img, apex_id) + zone_image_name_rr_count(img, apex_id);
    uint32_t soa = zone_image_apex_soa(img); /* B8t-1: the reference SOA (the SOA RRs of a zone can differ in MNAME) */
    if (soa != ZONE_IMAGE_NONE && zone_image_soa(img, soa, mname_buf, sizeof(mname_buf), NULL, 0, NULL) == 0)
      mname = mname_buf;
    for (uint32_t i = zone_image_name_first_rr(img, apex_id); i < apex_end; i++) {
      if (zone_image_rr_type(img, i) != 2) continue;
      char ns_target[DNS_NAME_TEXT_SIZE];
      if (zone_image_rr_target(img, i, ns_target, sizeof(ns_target)) != 0) continue;
      if (mname && !eff.notify_to_soa && domain_names_match_ci(ns_target, mname)) continue;
      // A. in-zone glue, B. otherwise the address in a sibling zone of the same view
      if (notify_add_glue(img, ns_target, targets, &ntargets, 64, key)) continue;
      zone_db_entry_t *sib_entry = find_zone_in_view(view, ns_target);
      if (!sib_entry || sib_entry == entry) continue;
      zone_version_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
      if (sib_arena && sib_arena->image)
        notify_add_glue(sib_arena->image, ns_target, targets, &ntargets, 64, key);
    }
  }

  for (int i = 0; i < ntargets; i++) {
    /* the local address of this NOTIFY: the `source` of the also-notify list the address is written in, else notify-source(-v6).  Only an
     * address that was in the configuration at start-up has a pre-bound socket (config_xfr_source_allowed()); another one is ignored with a
     * warning (a restart-only change) and the system chooses the source. */
    int fam = targets[i].addr.ss_family;
    uint8_t src[16];
    /* the server statement that covers the address (batch 5; the view's, else the top-level ones): its notify-source(-v6) is above the
     * list's `source` (BIND notify_send_toaddr()), and its `keys` signs the NOTIFY unless the also-notify element has a key of its own
     * (BIND: notify->key, else dns_view_getpeertsig()); the zone's tsig-key comes after both (KariDNS) */
    const uint8_t *dst_bytes = fam == AF_INET ? (const uint8_t *)&((const struct sockaddr_in *)&targets[i].addr)->sin_addr
                                              : (const uint8_t *)&((const struct sockaddr_in6 *)&targets[i].addr)->sin6_addr;
    const server_stmt_t *srv = config_server_find(active, view_name, fam, dst_bytes);
    const tsig_key_t *tkey = targets[i].key;
    if (srv && (srv->set & SV_KEYS) && !(targets[i].tpl && targets[i].tpl->key)) {
      const tsig_key_t *sk = find_tsig_key_in_view(active, view_name, srv->key);
      if (sk) tkey = sk;
      else syslog(LOG_ERR, "[Notify] zone '%s': the key '%s' of the server statement for %s is not defined; NOTIFY sent with the zone's key or unsigned",
                  domain, srv->key, targets[i].tpl ? targets[i].tpl->ip : "an NS host");
    }
    xfr_eff_t peff;
    xfr_opts_effective_peer(active, zone, view_name, srv, &peff);
    bool has_src = xfr_source_for(&peff, targets[i].tpl, fam, false, src);
    if (has_src && !config_xfr_source_allowed(fam, src, false)) {
      char txt[INET6_ADDRSTRLEN];
      inet_ntop(fam, src, txt, sizeof(txt));
      syslog(LOG_WARNING, "[Notify] zone '%s': the NOTIFY source address %s was not in the configuration at start-up; it is used after a restart "
                          "(until then the system chooses the source address)", domain, txt);
      has_src = false;
    }
    /* tcp-only yes in that server statement: the NOTIFY goes over TCP (BIND notify_send_toaddr(): dns_peer_getforcetcp()) */
    bool tcp_only = srv && (srv->set & SV_B_TCP_ONLY) && (srv->bools & SV_B_TCP_ONLY);
    notify_send_to(domain, view_name, &targets[i].addr, has_src, src, tkey, &nr, g_notify_rate, tcp_only);
  }

  if (ntargets > 0) {
    atomic_fetch_add_explicit(&entry->observatory.notify_sent, ntargets, memory_order_relaxed);
    atomic_store_explicit(&entry->observatory.last_notify_time, (uint64_t)time(NULL), memory_order_relaxed);
  }

  if (snap) release_zone_snapshot(snap);
  if (active) release_config_snapshot(active);
  rcu_aux_read_unlock();
}

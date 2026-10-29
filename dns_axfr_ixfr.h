#ifndef DNS_AXFR_IXFR_H
#define DNS_AXFR_IXFR_H

#include "dns_server_internal.h"
#include "dns_tsig_acl.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* axfr_bg_thread_func は detached スレッドとして動作するため、
 * 引数 ctx 以外のヒープ・スタック構造体へのアクセスを避け、
 * tsig_key_t など呼び出し元のメモリを直接参照しないように
 * ポインタ参照を一切排除する。*/
/* One primary a secondary zone is refreshed from (batch 4: the refresh asks the primaries in order, BIND 9.20 zone.c refresh_callback()).
 * The key is copied by value (no pointer into the configuration). */
#define XFR_PRIMARIES_MAX 32
typedef struct {
  char ip[64];
  int port;
  bool has_tsig;
  char tsig_name[256];
  char tsig_algorithm[64];
  uint8_t tsig_secret_decoded[256];
  size_t tsig_secret_decoded_len;
  bool has_src;      /* the local address of the connection (the server statement's transfer-source, else the primaries source, else transfer-source), allowed at start-up only */
  uint8_t src[16];
  /* batch 5: what the `server` statement that covers this primary says about the requests to it.  Only what the statement wrote is set; a
   * zeroed primary (a unit test, a primary with no statement) asks as the zone says: IXFR, EXPIRE and EDNS. */
  uint8_t srv_request_ixfr, srv_request_expire;   /* request-ixfr / request-expire of the server statement: 0 = not written (the zone's eff applies), 1 = yes, 2 = no */
  bool per_ns_set;           /* `transfers` of the server statement (BIND dns_peer_gettransfers()) replaces transfers-per-ns for this primary */
  uint32_t per_ns;
  bool no_edns;              /* `edns no`: the requests carry no OPT (so neither EXPIRE nor the Extended AXFR option) */
  bool request_nsid;         /* `request-nsid yes`: an empty NSID option (RFC 5001) in the OPT */
  uint8_t edns_version;      /* `edns-version` */
  uint16_t edns_udp_size;    /* `edns-udp-size` (0 = the default 4096) */
} xfr_primary_t;

typedef struct {
  char domain[256];
  zone_db_entry_t *entry;
  zone_db_snapshot_t *snap;
  int nprim;
  xfr_primary_t prim[XFR_PRIMARIES_MAX];
  /* マスターへの TCP 接続に使う zone-tcp-* / tcp-* (xfr_tcp_sockopts()) */
  tcp_sockopts_t tcp_opts;
  /* I2: the most RRs and message octets one transfer of this zone may bring (max-zone-records / max-zone-bytes of the
   * zone, else of options; xfr_zone_limits()).  0 = no limit. */
  uint64_t max_records;
  uint64_t max_bytes;
  bool has_eff;               /* eff is filled in (the scheduler does); a zeroed context (a unit test) asks for IXFR with EXPIRE and has no time limits */
  xfr_eff_t eff;              /* the transfer / timer options of the zone (xfr_opts_effective()); multi-master is applied only with several primaries */
  uint32_t per_ns_limit;      /* transfers-per-ns */
} axfr_bg_ctx_t;

static inline bool ctx_request_ixfr(const axfr_bg_ctx_t *c, const xfr_primary_t *p) {
  return !c->has_eff || (p->srv_request_ixfr ? p->srv_request_ixfr == 1 : c->eff.request_ixfr);
}
static inline bool ctx_request_expire(const axfr_bg_ctx_t *c, const xfr_primary_t *p) {
  return !p->no_edns && (!c->has_eff || (p->srv_request_expire ? p->srv_request_expire == 1 : c->eff.request_expire));
}
/* BIND (zoneconf.c) looks at multi-master only when the zone has more than one primary */
static inline bool ctx_multi_master(const axfr_bg_ctx_t *c) { return c->has_eff && c->eff.multi_master && c->nprim > 1; }
/* The primaries a secondary zone is refreshed from (dns_server_core.c; declared here so that a unit test can look at what it builds: the order, the
 * port, the key by the precedence of peer_key_name()).  entry: the zone's entry, zcfg: its configuration (NULL for a catalog member), snap: the
 * snapshot that holds the catalog zone of a member (may be NULL: the primary copied into the member is used). */
void xfr_build_primaries(server_config_t *active, zone_db_snapshot_t *snap, const zone_db_entry_t *entry, const zone_config_t *zcfg,
                         axfr_bg_ctx_t *ctx);

/* ---- batch 4: the policy of the secondary side, kept free of sockets so that it can be tested ---- */

/* The result of one try at a primary (xfr_run_primaries()) */
enum { XFR_R_FAILED = -1, XFR_R_TRANSFERRED = 1, XFR_R_UPTODATE = 2, XFR_R_BEHIND = 3, XFR_R_DEFERRED = 4 };
typedef int (*xfr_try_fn)(void *arg, int idx);
typedef struct {
  int tried;            /* primaries asked */
  int transferred_idx;  /* index of the primary the zone came from, -1 = none */
  int uptodate, behind, failed, deferred;
} xfr_run_t;
/* BIND's order: the primaries are asked one after the other from the first; a failure, an up-to-date answer, a primary that is behind and
 * a primary that cannot be asked now (the per-server quota) all go on to the next; a transfer ends the refresh. */
void xfr_run_primaries(int n, xfr_try_fn fn, void *arg, xfr_run_t *out);
/* transfers-per-ns: at most `limit` inbound transfers from one remote address at a time.  false = the quota is full (counts nothing). */
bool xfr_ns_acquire(const struct sockaddr_storage *a, uint32_t limit);
void xfr_ns_release(const struct sockaddr_storage *a);
/* transfers-in / transfers-out: a counter taken up to limit */
bool xfr_counter_acquire(_Atomic int *c, uint32_t limit);
void xfr_counter_release(_Atomic int *c);
extern _Atomic int g_xfr_in_active;    /* inbound transfers in progress (the threads of the secondary side) */
extern _Atomic int g_xfr_out_active;   /* outbound AXFR / IXFR in progress */
/* serial-query-rate / notify-rate: at most `rate` operations in a wall-clock second (BIND setrl() spaces them evenly; the control thread
 * wakes once a second, so the budget is per second).  true = the operation may run now (and has used one); false = the budget of this
 * second is spent, ask again at the next tick.  The control thread only, one limiter per kind. */
typedef struct { time_t sec; uint32_t used; } xfr_rl_t;
bool xfr_rl_take(xfr_rl_t *rl, uint32_t rate, time_t now);
/* max-transfer-time-in / max-transfer-idle-in: the longest the next read may wait, given the start-up deadline: min(idle, deadline - now), 0 when
 * the deadline has passed (idle 0 = no idle limit, deadline 0 = no total limit; the result 0 with no limit at all would mean "forever", so
 * *expired tells the two apart) */
uint32_t xfr_read_budget(time_t now, time_t deadline, uint32_t idle_secs, bool *expired);
/* The serial-behind test of a refresh (RFC 1982): the primary is behind when its serial is older than ours */
bool xfr_serial_behind(uint32_t ours, uint32_t theirs);

typedef struct {
  int client_fd;
  char client_ip[INET6_ADDRSTRLEN];
  int client_port;
  struct sockaddr_storage client_addr;
  socklen_t client_len;
  struct sockaddr_storage server_addr;
  socklen_t server_len;
  bool has_server_addr;
  char qname[DNS_NAME_TEXT_SIZE];
  uint16_t qclass;
  uint16_t qtype;
  bool has_edns;
  bool dnssec_ok;
  uint8_t req[BUFFER_SIZE];
  uint16_t req_len;
  bool has_tsig;
  char tsig_name[256];
  char tsig_algorithm[64];
  uint8_t tsig_secret_decoded[256];
  size_t tsig_secret_decoded_len;
  uint8_t tsig_mac[64]; /* >= EVP_MAX_MD_SIZE */
  size_t tsig_mac_len;
  zone_db_entry_t *entry;
  zone_db_snapshot_t *snap;
  uint32_t idle_out_secs;   /* max-transfer-idle-out: the longest a send may wait for the client (0 = no limit) */
  uint32_t time_out_secs;   /* max-transfer-time-out: the longest the whole transfer may take (0 = no limit) */
} axfr_worker_args_t;

int parse_xfr_packet(const uint8_t *packet, size_t packet_len,
                     zone_arena_t *standby, const zone_version_t *active,
                     axfr_session_t *session, const char *domain);
/* R-19: 転送応答の1通のヘッダーと質問を session->query_id / query_type / domain と照合する
 * (RFC 5936 §2.2.1、§2.2.2)。0 = 問題なし、-1 = 応答として受け付けない (ログ済み)、
 * 1 = エラーの RCODE (session->rcode に設定、ログ済み)。 */
int xfr_check_response_header(const uint8_t *msg, size_t msg_len, axfr_session_t *session, const char *domain);

int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry,
                      tcp_stream_ctx_t *stream_ctx, axfr_session_t *session,
                      tsig_key_t *tsig_key,
                      const uint8_t *req_mac, size_t req_mac_len);

/* RFC 7314 §4: 転送 / 最新確認の結果からセカンダリの expire タイマー期限を決める (0 = SOA EXPIRE で数える) */
time_t xfr_expire_deadline(bool transferred, bool has_expire, uint32_t expire_opt,
                           uint32_t soa_expire, time_t cur_deadline, time_t now);

/* B8t-2: which Extended AXFR version a primary speaks, as a secondary learns it (kept per zone, in memory).  The secondary asks for
 * version 3; a standard transfer in answer may come from a primary that speaks version 2 only (it ignores a version it does not know), so
 * the transfer is asked again with version 2 (no SOA_SET, no settings, as before) and the result is remembered: XFR_EXT_V2 = version 2,
 * XFR_EXT_STANDARD = no extension at all (asked with version 3, accepted as it comes, no second request).  Both are forgotten after
 * XFR_EXT_REPROBE_SECS, so an upgraded primary is found; XFR_EXT_V3 and XFR_EXT_UNKNOWN ask for version 3 and fall back when the answer
 * is a standard transfer. */
enum { XFR_EXT_UNKNOWN = 0, XFR_EXT_STANDARD = 1, XFR_EXT_V2 = 2, XFR_EXT_V3 = 3 };
#define XFR_EXT_REPROBE_SECS (6 * 3600)
uint8_t xfr_ext_effective(uint8_t state, time_t set_at, time_t now);   /* the state to act on: STANDARD and V2 expire to UNKNOWN */
uint8_t xfr_ext_request_version(uint8_t state);                        /* 2 for V2, else 3 */
bool xfr_ext_probe(uint8_t state);                                      /* may a standard answer to version 3 mean "ask with version 2"? */
uint8_t xfr_ext_learn(bool answered_extended, uint8_t answered_version); /* the state after a transfer that finished */

void *axfr_bg_thread_func(void *arg);

void send_axfr_response(int client_fd, const char *qname __attribute__((unused)), uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry,
                        uint8_t *req_mac, size_t req_mac_len,
                        const struct sockaddr_storage *client_addr, socklen_t client_len,
                        const struct sockaddr_storage *server_addr, bool has_server_addr);

void *axfr_worker_thread(void *arg);

bool wait_for_active_axfr(zone_db_entry_t *entry, int timeout_ms);

#endif /* DNS_AXFR_IXFR_H */

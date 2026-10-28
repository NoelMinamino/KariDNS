#ifndef DNS_CONFIG_PARSER_H
#define DNS_CONFIG_PARSER_H

#define KARIDNS_MAX_CONFIG_FILE_SIZE (256 * 1024 * 1024)

/* view 名の上限 (NUL 込みのバイト数)。zone_db_entry_t などが view 名をこの長さの配列で持つ */
#define KARIDNS_VIEW_NAME_MAX 64

/* tcp-mss / tcp-window / udp-bufsize と zone-tcp-* / zone-udp-bufsize の許容範囲 */
#define KARIDNS_TCP_MSS_MIN      536                 /* RFC 1122 §3.3.3 の既定 MSS */
#define KARIDNS_TCP_MSS_MAX      65495               /* 65535 - IPv4/TCP ヘッダ 40 */
#define KARIDNS_TCP_BUF_MIN      4096
#define KARIDNS_TCP_BUF_MAX      (64 * 1024 * 1024)
#define KARIDNS_UDP_BUFSIZE_MIN  512                 /* RFC 6891 §6.2.3 */
#define KARIDNS_UDP_BUFSIZE_MAX  4096
#define KARIDNS_UDP_BUFSIZE_DEFAULT 1232             /* DNS Flag Day 2020 */

/* karidns.conf.sample / karictl.conf.sample の secret プレースホルダ (Base64 として正しい値)。
 * デコードすると "REPLACE-ME:openssl-rand-base64-32"。このまま使われていたら警告する。 */
#define KARIDNS_SAMPLE_SECRET_PLACEHOLDER "UkVQTEFDRS1NRTpvcGVuc3NsLXJhbmQtYmFzZTY0LTMy"


#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/types.h>
#include "dns_wire.h"
#include "dns_cidr.h"
#include "dns_logcat.h"

typedef struct {
  char *ip;
  int port;
} ip_port_t;

/* One element of an also-notify { } list (BIND 9.20 ARM, "also-notify"): an address with its port and an optional TSIG key, or --
 * while the configuration is being read -- the name of a remote-servers / primaries / masters list.  After the parse has finished
 * every element is an address (list == NULL, port set, where == NULL): the names are expanded into the addresses of the list. */
typedef struct {
  char *ip;    /* address literal; NULL while the element is a list name */
  int port;    /* 1..65535; 0 only while the element is a list name */
  char *key;   /* TSIG key name that signs the NOTIFY to this address (RFC 8945), or NULL */
  char *list;  /* name of the list, until the parse has expanded it */
  char *where; /* "file:line" of the element, until the parse has checked it (only elements with a list name or a key) */
  /* The `source` / `source-v6` of the list statement this address is written in (BIND 9.20 ARM "primaries", "also-notify"): src_set[0] =
   * IPv4 (src[0], 4 octets), src_set[1] = IPv6 (src[1]).  `*` is the same as not written (the transfer-source / notify-source of the zone,
   * view or options applies).  An address of a named list keeps the source of that list (BIND lib/isccfg getipandkeylist()).  src_loc is
   * the "file:line" of the statement, for the start-up check of the address; NULL when no source is written. */
  uint8_t src_set[2];
  uint8_t src[2][16];
  char *src_loc;
} notify_target_t;

/* Top-level remote-servers <name> [port <n>] { ... }; (also written primaries / masters).  Items may name other lists. */
typedef struct remote_list {
  char *name;
  notify_target_t *items;
  int count;
  char *where;
  struct remote_list *next;
} remote_list_t;

/* notify <yes|no|explicit|primary-only|master-only>; (BIND 9.20 ARM "notify").  0 = not written: inherit (zone, else view, else
 * options; default yes).  master-only is the older spelling of primary-only. */
typedef enum { NOTIFY_MODE_INHERIT = 0, NOTIFY_MODE_YES = 1, NOTIFY_MODE_NO = 2, NOTIFY_MODE_EXPLICIT = 3, NOTIFY_MODE_PRIMARY_ONLY = 4 } notify_mode_t;

/* The most elements of one also-notify statement after the lists are expanded, and how deep lists may include lists */
#define KARIDNS_ALSO_NOTIFY_MAX 256
#define KARIDNS_REMOTE_LIST_DEPTH 8

/* B9a: the most alias-resolver addresses of a zone, of options, or of the database block */
#define KARIDNS_ALIAS_RESOLVERS_MAX 8

typedef struct {
  bool configured;
  bool early_drop;
  bool log_only;
  uint32_t responses_per_second;
  uint32_t nodata_per_second;
  bool nodata_per_second_set;
  uint32_t nxdomains_per_second;
  uint32_t errors_per_second;
  uint32_t referrals_per_second;  /* D-05: BIND と同じ。未指定なら responses-per-second */
  bool referrals_per_second_set;
  uint32_t all_per_second;        /* D-05: クライアント (プレフィックス) ごとの全応答。0 = 制限なし */
  uint8_t ipv4_prefix_length;     /* D-05: クライアントをまとめる長さ (_set でなければ既定 24) */
  uint8_t ipv6_prefix_length;     /* D-05: 同 (_set でなければ既定 56) */
  bool ipv4_prefix_length_set;
  bool ipv6_prefix_length_set;
  uint32_t window_seconds;
  uint32_t slip;
  ip_port_t *exempt_clients;
  int exempt_clients_count;
  cidr_entry_t *exempt_clients_parsed;
} rate_limit_config_t;

typedef enum {
  ADDITIONAL_AUTH_YES = 0,       /* 原則 (デフォルト): Primary/Slaveゾーン全体からsibling domainも含めて返す */
  ADDITIONAL_AUTH_IN_DOMAIN = 1, /* in-domain: 自ゾーン(管理するドメイン名)配下のレコードのみ返す */
  ADDITIONAL_AUTH_NO = 2         /* no: Additionalセクションへのアドレス付加を行わない */
} additional_from_auth_t;

/* 送信する NOTIFY の再送 (RFC 1996 §3.6: 間隔と回数は運用者が決める値)。
 * options の値は常に有効。zone の値は *_set のものだけが options を上書きする。 */
#define NOTIFY_RETRIES_DEFAULT 5
#define NOTIFY_RETRIES_MAX 10
#define NOTIFY_RETRY_INTERVAL_DEFAULT 60
#define NOTIFY_RETRY_INTERVAL_MAX 3600
typedef enum { NOTIFY_BACKOFF_FIXED = 0, NOTIFY_BACKOFF_EXPONENTIAL = 1 } notify_backoff_t;
typedef struct {
  int retries;        /* notify-retries: 最初の送信の後に再送する回数 */
  int interval;       /* notify-retry-interval: 最初の再送までの秒数 */
  notify_backoff_t backoff; /* notify-retry-backoff: fixed は同じ間隔、exponential は再送ごとに倍 */
  bool retries_set;
  bool interval_set;
  bool backoff_set;
} notify_retry_config_t;

/* ixfr-history <n>: how many past versions of a zone are kept as IXFR diffs (RFC 1995 §4). options and zone; a zone overrides options. */
#define IXFR_HISTORY_DEFAULT 4
#define IXFR_HISTORY_MAX 32

/* ---- Batch 4: the transfer / NOTIFY options of BIND 9.20 (ARM "Zone Transfers", "Boolean Options", "Zone Transfers" and the zone
 * statement), written in options, view and zone and resolved per option, zone > view > options (the lower level replaces, never merges). ---- */

/* notify-source / notify-source-v6 / transfer-source / transfer-source-v6: `( <address> | * )`, no port (9.20 grammar; a port is refused) */
enum { XSRC_NOTIFY4 = 0, XSRC_NOTIFY6, XSRC_XFER4, XSRC_XFER6, XSRC_N };
typedef struct {
  uint8_t state;      /* 0 = not written at this level, 1 = an address, 2 = `*` (the system chooses) */
  uint8_t addr[16];   /* network order; 4 octets for XSRC_*4 */
  char *loc;          /* "file:line" of the statement (owned) */
} xfr_src_t;

/* The numeric / boolean options; the bit says "written at this level" */
#define XO_MIN_REFRESH   (1u << 0)
#define XO_MAX_REFRESH   (1u << 1)
#define XO_MIN_RETRY     (1u << 2)
#define XO_MAX_RETRY     (1u << 3)
#define XO_XFER_TIME_IN  (1u << 4)
#define XO_XFER_IDLE_IN  (1u << 5)
#define XO_XFER_TIME_OUT (1u << 6)
#define XO_XFER_IDLE_OUT (1u << 7)
#define XO_NOTIFY_DELAY  (1u << 8)
#define XO_B_NOTIFY_TO_SOA   (1u << 9)
#define XO_B_TRY_TCP_REFRESH (1u << 10)
#define XO_B_REQUEST_IXFR    (1u << 11)
#define XO_B_PROVIDE_IXFR    (1u << 12)
#define XO_B_REQUEST_EXPIRE  (1u << 13)
#define XO_B_MULTI_MASTER    (1u << 14)
#define XO_LEGACY_NOTIFY6    (1u << 15)   /* the IPv6 notify source came from the KariDNS zone statement `notify-source <ipv6>`; notify-source-v6 replaces it */

/* bin/named/server.c MIN_/MAX_INITIAL_TIMEOUT, MIN_/MAX_IDLE_TIMEOUT, MAX_ADVERTISED_TIMEOUT, in units of 100 ms */
#define TCP_INITIAL_MIN_UNITS    25u
#define TCP_IDLE_MIN_UNITS       1u
#define TCP_IDLE_MAX_UNITS       1200u
#define TCP_ADVERTISED_MAX_UNITS 65535u

/* BIND 9.20 defaults (bin/named/config.c) and ranges (lib/isccfg/check.c) */
#define XFR_MIN_REFRESH_DEFAULT   300u
#define XFR_MAX_REFRESH_DEFAULT   2419200u   /* 4 weeks */
#define XFR_MIN_RETRY_DEFAULT     500u
#define XFR_MAX_RETRY_DEFAULT     1209600u   /* 2 weeks */
#define XFR_TIME_IN_DEFAULT       120u       /* minutes */
#define XFR_IDLE_IN_DEFAULT       60u
#define XFR_TIME_OUT_DEFAULT      120u
#define XFR_IDLE_OUT_DEFAULT      60u
#define XFR_MINUTES_MAX           40320u     /* 28 days */
#define XFR_NOTIFY_DELAY_DEFAULT  5u
#define XFR_MAX_EXPIRE            14515200u  /* 24 weeks: BIND's DNS_MAX_EXPIRE, the upper bound of the SOA EXPIRE a zone uses */
#define XFR_TRANSFERS_IN_DEFAULT  10u
#define XFR_TRANSFERS_OUT_DEFAULT 10u
#define XFR_TRANSFERS_PER_NS_DEFAULT 2u
#define XFR_RATE_DEFAULT          20u

typedef struct xfr_opts {
  uint32_t set;                                 /* XO_* bits of the options written at this level */
  uint32_t min_refresh, max_refresh, min_retry, max_retry;        /* seconds */
  uint32_t xfer_time_in, xfer_idle_in, xfer_time_out, xfer_idle_out; /* minutes */
  uint32_t notify_delay;                        /* seconds */
  uint32_t bools;                               /* the XO_B_* values (meaningful where the bit is in `set`) */
  xfr_src_t src[XSRC_N];
} xfr_opts_t;

/* The value that applies to a zone (xfr_opts_effective()) */
typedef struct {
  uint32_t min_refresh, max_refresh, min_retry, max_retry;
  uint32_t xfer_time_in, xfer_idle_in, xfer_time_out, xfer_idle_out;   /* seconds (minutes * 60) */
  uint32_t notify_delay;
  bool notify_to_soa, try_tcp_refresh, request_ixfr, provide_ixfr, request_expire, multi_master;
  struct { bool set; uint8_t addr[16]; } src[XSRC_N];  /* set == false: `*` or not written, the system chooses the source address */
  /* batch 5: the source addresses of the `server` statement of the peer (xfr_opts_effective_peer()), above the primaries / also-notify
   * list's `source` and above src[]: 0 = not written, 1 = an address, 2 = `*` (the system chooses) */
  struct { uint8_t state; uint8_t addr[16]; } psrc[XSRC_N];
} xfr_eff_t;

/* ---- Batch 5: server <prefix> { ... }; (BIND 9.20 ARM "server Statement Definition and Usage"; lib/isccfg/namedconf.c server_clauses,
 * bin/named/server.c configure_peer()).  A statement describes the remote server(s) an address prefix covers.  Where BIND uses an option
 * (lib/dns/zone.c, xfrin.c, lib/ns/xfrout.c, client.c): keys, transfers, transfer-source(-v6), notify-source(-v6), request-ixfr,
 * request-expire, edns, edns-udp-size, edns-version, request-nsid for our requests to the server; tcp-only for our NOTIFY (over TCP,
 * dns_dynamic_update.c notify_tcp_start()); provide-ixfr, transfer-format and
 * max-udp-size for what we send to it.  The others are accepted and have no effect on an authoritative server (resolver.c, checkds). ---- */
#define SV_B_BOGUS          (1u << 0)
#define SV_B_EDNS           (1u << 1)
#define SV_B_REQUEST_NSID   (1u << 2)
#define SV_B_SEND_COOKIE    (1u << 3)
#define SV_B_REQUIRE_COOKIE (1u << 4)
#define SV_B_TCP_KEEPALIVE  (1u << 5)
#define SV_B_TCP_ONLY       (1u << 6)
#define SV_B_ONE_ANSWER     (1u << 7)    /* transfer-format one-answer (clear: many-answers) */
#define SV_TRANSFER_FORMAT  (1u << 8)    /* the options below carry a number / a name: the bit says "written" */
#define SV_TRANSFERS        (1u << 9)
#define SV_EDNS_UDP_SIZE    (1u << 10)
#define SV_EDNS_VERSION     (1u << 11)
#define SV_MAX_UDP_SIZE     (1u << 12)
#define SV_PADDING          (1u << 13)
#define SV_KEYS             (1u << 14)
typedef struct server_stmt {
  uint8_t family;       /* AF_INET / AF_INET6 */
  uint8_t plen;         /* prefix length in bits (the address alone: 32 / 128) */
  uint8_t addr[16];     /* the prefix, network order (4 octets for AF_INET); the bits beyond plen are zero */
  uint32_t set;         /* SV_* of the options written */
  uint32_t bools;       /* SV_B_* values (meaningful where the bit is in `set`) */
  uint32_t transfers, edns_udp_size, edns_version, max_udp_size, padding;
  char *key;            /* keys: the TSIG key used for requests to this server (SV_KEYS) */
  xfr_opts_t xo;        /* request-ixfr, provide-ixfr, request-expire, notify-source(-v6), transfer-source(-v6) (the same parser as the zone's) */
  char loc[240];        /* "file:line" of the statement */
  struct server_stmt *next;   /* most specific prefix first (BIND dns_peerlist_addpeer()) */
} server_stmt_t;

/* One distinct source address of the configuration (start-up check, the Router's NOTIFY sockets, the connect broker's allow list) */
typedef struct {
  uint8_t family;       /* AF_INET / AF_INET6 */
  uint8_t addr[16];
  bool notify, xfer;    /* used as a NOTIFY source / a transfer source */
  char text[48];
  char loc[240];        /* "file:line" of the first statement that names it */
  char what[48];        /* the statement ("notify-source", "primaries source-v6", ...) */
} xfr_source_t;
#define KARIDNS_XFR_SOURCES_MAX 128

/* BIND address match list (BIND 9.20 ARM "Address Match Lists"), compiled: elements are evaluated in order and the first one that
 * matches decides (dns_tsig_acl.h: aml_t, aml_match()).  The statements below are shared with the zone, view and options level. */
typedef struct aml aml_t;

/* allow-query, allow-query-on, allow-transfer, allow-update and allow-notify of one level (zone, view or options).  NULL = the
 * statement is not written at this level (the next level up applies); an empty list `{ };` is written and matches nobody. */
typedef struct {
  aml_t *query;
  aml_t *query_on;
  aml_t *transfer;
  aml_t *update;
  aml_t *notify;
  aml_t *match;   /* view { match-clients } as written: kept so that its names are checked with file:line; the view is chosen with the flat list */
} acl_set_t;

/* ---- Batch 7: options that take a value and are written in options { }, view { } and zone { } (BIND 9.20 lib/isccfg/namedconf.c zone clauses,
 * bin/named/zoneconf.c).  Each level lists only what it wrote (`set`); zone_vopts_effective() gives the value of a zone: the zone's, else its
 * view's, else options', else the default.  ZC_* are the check-* options (lib/isccfg/check.c, bin/named/zoneconf.c): the severity is fail, warn
 * or ignore (a boolean check-* is fail = yes, ignore = no).  CHK_DEFAULT = not written anywhere: the check keeps the severity it always had in
 * KariDNS (zone_lint). ---- */
enum { CHK_FAIL = 0, CHK_WARN = 1, CHK_IGNORE = 2, CHK_DEFAULT = 3 };
enum { SUM_INCREMENT = 0, SUM_UNIXTIME = 1, SUM_DATE = 2 };   /* serial-update-method (BIND dns_updatemethod_*) */
enum {
  ZC_NAMES_PRIMARY = 0, ZC_NAMES_SECONDARY, ZC_NAMES_RESPONSE, ZC_DUP_RECORDS, ZC_INTEGRITY, ZC_MX, ZC_MX_CNAME, ZC_SIBLING, ZC_SPF,
  ZC_SRV_CNAME, ZC_SVCB, ZC_WILDCARD, ZC_N
};
#define ZV_MAX_RECORDS        (1u << 0)
#define ZV_MAX_PER_TYPE       (1u << 1)
#define ZV_MAX_TYPES_PER_NAME (1u << 2)
#define ZV_MAX_ZONE_TTL       (1u << 3)
#define ZV_SERIAL_METHOD      (1u << 4)
#define ZV_CHK(c)             (1u << (8 + (c)))      /* the check-* option ZC_c is written at this level */
typedef struct zone_vopts {
  uint32_t set;                    /* ZV_* of what is written at this level */
  uint32_t max_records;            /* RRs in the zone; 0 = no limit */
  uint32_t max_per_type;           /* RRs in one RRset; 0 = no limit */
  uint32_t max_types_per_name;     /* RR types at one name; 0 = no limit */
  uint32_t max_zone_ttl;           /* seconds; 0 = no limit (`unlimited`) */
  uint8_t serial_method;           /* SUM_* */
  uint8_t chk[ZC_N];               /* CHK_FAIL / CHK_WARN / CHK_IGNORE */
  uint8_t zone_check_names;        /* zone { check-names <mode>; }: applies to the zone's own type */
} zone_vopts_t;
#define ZV_ZONE_CHECK_NAMES   (1u << 30)
/* The value that applies to a zone */
typedef struct {
  uint32_t max_records, max_per_type, max_types_per_name, max_zone_ttl;
  uint8_t serial_method;
  uint8_t chk[ZC_N];               /* ZC_NAMES_PRIMARY .. : the effective severity, CHK_DEFAULT when not written; check_names: for the zone's type */
  uint8_t check_names;             /* the zone's check-names severity (primary or secondary one, or the zone's own) */
} zone_veff_t;

/* S6a: ゾーンごとの「まれに指定する」オプション。ほとんどのゾーン (domain/file/type だけの
 * 主ゾーン) では 1 つも指定しないので、zone_config_t は核だけを持ち、ここに挙げた値は
 * 1 つでも指定したゾーンに限って別のブロックに確保する (zone_config_t.ext)。
 * ext == NULL は「全部既定 (ゼロ)」。読み手は必ず zext(z) 経由で読むこと。
 * 書き手 (パーサ、テスト) は zone_ext_mut(z) で確保してから書く。 */
typedef struct zone_ext {
  notify_target_t *masters; /* primaries / masters: addresses with port and optional TSIG key (list names are expanded when the parse ends) */
  int masters_count;
  cidr_entry_t *masters_parsed;
  char *tsig_key;
  char **tsig_keys;
  int tsig_keys_count;
  notify_target_t *also_notify;
  int also_notify_count;
  uint8_t notify_mode;   /* notify_mode_t of the zone's own `notify` statement, 0 = inherit */
  bool also_notify_set;  /* the zone has an also-notify statement (even an empty one): it replaces the view's and options' list */
  char *notify_source;
  xfr_opts_t *xo;   /* batch 4 transfer / NOTIFY options written in this zone (NULL = none); `notify-source <address>` above is also entered here */
  zone_vopts_t zv;  /* batch 7: max-records, max-zone-ttl, serial-update-method, check-*, written in this zone */
  update_policy_t *upd_policy;   /* update-policy { grant | deny ... }: the rules, NULL = the zone has none (allow-update decides) */
  char **allow_transfer;
  int allow_transfer_count;
  acl_entry_t *allow_transfer_parsed;
  char **allow_update;
  int allow_update_count;
  acl_entry_t *allow_update_parsed;
  rate_limit_config_t rrl;
  /* BIND address match lists of this zone.  transfer / update, when written in a configuration file, are also kept as the flat lists above
   * (what the settings text sent to secondaries, and zone { } blocks built by hand, use); the zone's tsig-key is not in them. */
  acl_set_t acl;

  /* --- ここから追加: type "program" 用 --- */
  char *program_path;          /* 実行ファイルへの絶対パス(argv[0]相当) */
  char **program_args;         /* argv[1]以降。シェル展開はしない */
  int program_args_count;
  char *program_user;          /* 追加の権限降格先ユーザ(省略可) */
  uint32_t program_timeout_ms; /* 1クエリの応答待ちタイムアウト(既定 2000) */
  uint32_t program_max_failures; /* 連続失敗許容回数(既定 5) */
  uint32_t program_restart_backoff_ms; /* 未使用: v1では自動再起動なし。将来用に予約 */
  /* --- ここまで追加 --- */

  /* --- type "forward" 用 --- */
  ip_port_t *forwarders;
  int forwarders_count;
  uint32_t forward_timeout_ms; /* 既定 2000ms。フォワーダー1台あたりの待ち時間 */

  /* --- ゾーンファイルのフォーマット指定 --- */
  char *file_format; /* NULL(既定) は "bind" 扱い。他に "tinydns" を受け付ける */

  /* --- ECS サブネットタグ対応表 (ゾーン単位の上書き) --- */
  struct ecs_tag_def_s *ecs_tags;
  int ecs_tag_count;

  /* --- Location タグ対応表 (ゾーン単位の上書き) --- */
  struct ecs_tag_def_s *location_tags;
  int location_tag_count;

  /* --- ECS 信頼リゾルバ (ゾーン単位の上書き) --- */
  char **ecs_trusted_resolvers;
  int ecs_trusted_resolvers_count;
  acl_entry_t *ecs_trusted_resolvers_parsed;

  /* --- additional-from-auth (ゾーン単位の上書き) --- */
  additional_from_auth_t additional_from_auth;
  bool additional_from_auth_specified;

  /* --- disable-auto-tc-flag (ゾーン単位の上書き: 既定 no) --- */
  bool disable_auto_tc_flag;

  /* --- TCP/UDP 転送パラメータ (ゾーン単位の上書き: 0 = 未指定) ---
   * ゾーンはクエリを受信するまで確定しないため、TCP 系は accept 済みソケットへ
   * クエリ受信後に setsockopt する。ハンドシェイクで決まる値 (相手へ通知済みの MSS、
   * ウィンドウスケール) には影響しない。詳細は docs/karidns.md を参照。 */
  int zone_tcp_mss;         /* TCP_MAXSEG。確立済み接続なので現在値より小さくする方向のみ有効 */
  int zone_tcp_window;      /* SO_RCVBUF (受信ウィンドウ) */
  int zone_tcp_sndbuf;      /* SO_SNDBUF (送信バッファ) */
  uint16_t zone_udp_bufsize; /* EDNS UDP ペイロードサイズ上限 (512..4096) */

  notify_retry_config_t notify_retry; /* ゾーン単位の上書き (*_set のもの) */

  bool ixfr_history_set;     /* ixfr-history をこのゾーンで指定した */
  uint8_t ixfr_history;      /* その値 (0..IXFR_HISTORY_MAX) */
  /* I2: max-zone-records / max-zone-bytes of this zone (the most RRs and message octets one inbound AXFR/IXFR may
   * bring); 0 = the options value (xfr_zone_limits()) */
  uint64_t max_zone_records;
  uint64_t max_zone_bytes;

  /* --- transfer-acl-match / update-acl-match (B7a, beta design D14): which kinds of entry of an ACL must match.
   * ACL_MATCH_DEFAULT = the meaning karidns.conf always had: allow-transfer with addresses and keys = address AND key,
   * allow-update = address OR key.  The DB loader writes ACL_MATCH_ANY for transfers and ACL_MATCH_ALL for updates, which
   * is what PowerDNS does. --- */
  uint8_t transfer_acl_match;
  uint8_t update_acl_match;
  /* --- set by the code that installs the settings of a DB zone, never by text: the ACLs of this zone also have to pass
   * options { database { acl-ceiling } } (dns_tsig_acl.c) --- */
  bool db_acl_ceiling;
  /* --- B8t-2: primary-settings no; ignores the settings the primary sends with the zone (Extended AXFR v3).  Default: they are used. --- */
  bool primary_settings_off;
  /* --- B9a: alias-resolver { <ip> [port <n>]; ... };  the resolvers that expand the ALIAS records of this zone (dns_alias.h).  A zone value
   * replaces the options value and the options { database { alias-resolver } } value.  Never sent with Extended AXFR (it names a resolver
   * of this server's own network). --- */
  ip_port_t *alias_resolvers;
  int alias_resolvers_count;
} zone_ext_t;

/* transfer-acl-match / update-acl-match values (zone_ext_t) */
enum { ACL_MATCH_DEFAULT = 0, ACL_MATCH_ANY = 1, ACL_MATCH_ALL = 2 };

typedef struct zone_config {
  char *domain;
  char *file;
  char *type;
  bool is_catalog;
  bool ext_shared; /* ext points to the zone_ext_t at the start of a zone_ext_shared_t (reference counted, DB zones) */
  zone_ext_t *ext; /* NULL = 全オプション既定。直接読まず zext() を使う */
  struct zone_config *next;
} zone_config_t;

/* B7a: the settings of DB zones are interned: zones whose settings text is the same share one parsed zone_ext_t.  The
 * object is reference counted; the intern table (dns_snapshot_rcu.c) holds one reference, every zone_config_t with
 * ext_shared one more.  free_zone_config() drops that reference. */
typedef struct zone_ext_shared {
  zone_ext_t ext;               /* must stay first */
  _Atomic uint32_t refs;
  struct zone_ext_shared *next; /* intern table chain */
  uint64_t hash;
  char *key;                    /* profile name, NUL, profile text, NUL, zone text: what makes two settings the same */
  size_t key_len;
  char profile[256];            /* "" = none */
} zone_ext_shared_t;

zone_ext_shared_t *zone_ext_shared_ref(zone_ext_shared_t *s);
void zone_ext_shared_unref(zone_ext_shared_t *s);

/* Restricted parse of the settings text of a DB zone (beta design 1.3, 3.5).  The text is hostile: only the statements the
 * loader can write are accepted (allow-transfer, allow-update, also-notify, tsig-key, notify-retries, notify-retry-interval,
 * notify-retry-backoff, ixfr-history, additional-from-auth, disable-auto-tc-flag, zone-udp-bufsize, zone-tcp-mss,
 * zone-tcp-window, zone-tcp-sndbuf, transfer-acl-match, update-acl-match, and (B7b) masters / primaries: IP addresses with an optional
 * port, at most 32, for a database secondary zone); everything else (file, type, program*,
 * include, unknown) is an error.  A statement that is written twice replaces the first (so the text of a profile followed by
 * the text of a zone is "the zone overrides the profile, statement by statement").  The ACL entries must be addresses,
 * prefixes, any or none ("!" allowed); in allow-update a name that is not an address is a TSIG key name.  Named ACLs of
 * karidns.conf are not available.  On success returns a new zone_ext_shared_t (refs 1, profile/key empty) whose ext has
 * db_acl_ceiling set; NULL with a one-line reason in err.  key_text/profile/key are the caller's to fill. */
zone_ext_shared_t *db_settings_parse(const char *text, size_t len, char *err, size_t errlen);

/* 全オプション既定 (全ゼロ) の共有ブロック。読み取り専用 */
extern const zone_ext_t zone_ext_default;

/* ゾーンのオプションブロック。ext == NULL (または zone_config_t をゼロ初期化しただけ) でも
 * 既定値を返すので NULL チェックは要らない。共有の既定ブロックを返す設計にしなかったのは、
 * calloc しただけのゾーン (テスト、ファザー) でも正しく読め、書き込みが共有ブロックに
 * 届く事故が型 (const) で防げるため。 */
static inline const zone_ext_t *zext(const zone_config_t *z) {
  return z && z->ext ? z->ext : &zone_ext_default;
}

/* 書き込み用。無ければ確保する (メモリ不足は NULL)。パースとテストだけが呼ぶ */
zone_ext_t *zone_ext_mut(zone_config_t *z);


/* `logging { channel <name> { ... }; }` (BIND 9.20 ARM "logging Block Grammar", lib/isccfg/namedconf.c channel_clauses).  The parse fills in
 * everything but fd / current_size / current_date; the server copies the channels into its own runtime (dns_log.c) and opens the files
 * there, so the parsed channels never hold a descriptor. */
typedef enum { LOGDEST_FILE = 0, LOGDEST_SYSLOG, LOGDEST_STDERR, LOGDEST_NULL } log_dest_t;
typedef enum { LOGTIME_NONE = 0, LOGTIME_LOCAL, LOGTIME_ISO8601, LOGTIME_ISO8601_UTC } log_time_t;

/* `versions` of a file: not written (BIND ISC_LOG_ROLLNEVER), `versions unlimited` (ISC_LOG_ROLLINFINITE), else the number (0 = the file
 * is not kept when it is rolled).  A zeroed channel therefore means "versions 0". */
#define LOG_VERSIONS_UNSET (-1)
#define LOG_VERSIONS_UNLIMITED (-2)

typedef struct log_channel {
  char *name;
  log_dest_t dest;
  int syslog_facility;        /* LOG_DAEMON etc.: the facility of `syslog <facility>` (0 = LOG_KERN, which is a facility like any other) */
  int level;                  /* the `severity`: LOG_LVL_CRITICAL .. LOG_LVL_INFO, LOG_LVL_DYNAMIC, or N > 0 for `debug N` */
  char *file_path;
  int versions;
  size_t size_limit;          /* 0 = unlimited */
  bool suffix_timestamp;
  log_time_t time_fmt;        /* print-time */
  bool print_category;
  bool print_severity;
  bool buffered;              /* accepted; no effect (every line is written at once) */
  uint32_t max_qps;
  bool max_qps_specified;
  int line;                   /* where the channel was defined (messages of the runtime) */
  int fd;
  size_t current_size;
  int current_date;
  bool size_reached;          /* a file with a size limit and no versions is full: nothing is written until it is shorter (BIND FILE_MAXREACHED) */
  time_t size_recheck;        /* when the file was last looked at while it was full */
  pthread_mutex_t lock;
  struct log_channel *next;
} log_channel_t;

/* the channels one category writes to (names, so that the runtime can bind them to its own copies); n == 0: no statement */
#define LOG_ROUTE_MAX 8
typedef struct {
  int n;
  char *name[LOG_ROUTE_MAX];
} log_cat_cfg_t;

typedef struct {
  log_channel_t *channels;
  log_cat_cfg_t cat[LOGC_COUNT];   /* every `category` statement of the name, in the order written (BIND appends) */
  bool seen;                       /* a logging statement was read */
  /* the first channel of `category queries` / `category responses` when it is a channel of the file (NULL: a built-in channel, or none) */
  char *queries_channel_name;
  log_channel_t *queries_channel;
  char *responses_channel_name;
  log_channel_t *responses_channel;
  /* the query log is on: `querylog yes`, or (querylog not written) a `category queries` that lists a channel; the response log is on
   * when `category responses` lists one.  The query path reads only these two. */
  bool queries_enabled;
  bool responses_enabled;
} logging_config_t;

/* One `controls { inet ...; }` entry as written (BIND 9.20 lib/isccfg/namedconf.c inetcontrol_fields).  karictl uses control-channel; these
 * are only checked and then ignored. */
typedef struct {
  char loc[240];       /* "file:line" of the entry */
  char addr[48];       /* the address as written ("*" kept) */
  int port;            /* 0 = not written (rndc: 953) */
  aml_t *allow;        /* the allow list; names are resolved when the parse ends */
  char **keys;         /* keys { } */
  int nkeys;
  char **key_loc;      /* "file:line" of each key name */
} controls_inet_t;

typedef struct {
  bool enabled;
  char *socket_path;
  char *algorithm;
  char *secret;
  uint8_t secret_decoded[256];
  size_t secret_decoded_len;
} control_channel_config_t;

typedef struct {
  bool enabled;          // dnstap{} ブロックが存在すれば true
  char *socket_path;
  char *identity;
  char *version;
  bool log_auth_query;   // log-queries / auth-query yes; (両方省略時は true、片方だけ指定時は未指定側 false)
  bool log_auth_response;// log-responses / auth-response yes; (同上)
  bool require_connect;  // require-connect yes; (デフォルト false)
  uint32_t queue_size;   // queue-size 4096; (既定 4096)
  /* batch 7 (BIND grammar): where a value came from -- 'b' options { dnstap-output / dnstap-identity / dnstap-version }, 'k' the dnstap { } block of KariDNS,
   * 0 not written.  Two statements that set the same thing with different values are a mistake; bind_form: the block was written as `dnstap { auth; }`. */
  char origin_socket, origin_identity, origin_version;
  bool bind_form;
} dnstap_config_t;

/* view 内のゾーン設定のハッシュ索引 (オープンアドレス法)。キーは domain_names_match_ci()
 * と同じ規則 (dns_name_hash_ci)。パース中にゾーンを足すたびに作り、重複の検出にも使う。
 * 設定は公開後に書き換わらないので、読み手はロックなしで引ける。 */
typedef struct {
  zone_config_t **slots; /* NULL = 空き */
  uint32_t mask;         /* 容量 - 1 (容量は 2 のべき) */
  uint32_t count;
} zone_cfg_index_t;

typedef struct view_config {
  char *name;
  char **match_clients;
  int match_clients_count;
  acl_entry_t *match_clients_parsed;
  zone_config_t *zones;
  zone_cfg_index_t zone_index; /* zones の索引。手で組んだ設定 (テスト) では空で、線形探索になる */
  notify_target_t *also_notify; /* view { also-notify { } }: replaces the options list for the zones of this view that have none of their own */
  int also_notify_count;
  bool also_notify_set;
  acl_set_t acl;                /* view { allow-query ... }: overrides options' for the zones of this view that have none of their own */
  uint8_t notify_mode;          /* view { notify }: notify_mode_t, 0 = inherit options' */
  xfr_opts_t xo;                /* view { notify-source, transfer-source, min-refresh-time, ... }: replaces options' for the zones of this view that have none of their own */
  zone_vopts_t zv;              /* view { max-records, max-zone-ttl, check-*, ... }: replaces options' for the zones of this view that have none of their own */
  uint16_t max_udp_size;        /* view { max-udp-size }: the UDP response size limit of this view's clients (512..4096), 0 = not written (zone, else options) */
  bool require_cookie_set, require_cookie;   /* view { require-server-cookie }: replaces options' for this view */
  char **catz_names; int catz_count;   /* view { catalog-zones { zone "name"; } }: the zones of this view that are catalog zones */
  tsig_key_t *keys;             /* view { key }: keys visible to this view only (BIND bin/named/tsigconf.c: the view's ring is the global keys plus these) */
  server_stmt_t *servers;       /* view { server }: when there is any, it replaces the whole list of the top-level server statements (named_config_get() finds the view's first) */
  /* beta design 7.1: DB zone source of this view. NULL/false = the global source of options { database { } } */
  char *database_file;         /* "database-file": sqlite3, this view's own file */
  char *database_schema;       /* "database-schema": postgresql, this view's own schema */
  bool database_none;          /* "database none;": this view takes no DB zones */
  struct view_config *next;
} view_config_t;

/* options { database { ... }; }  (beta design 7.1). enabled == false: the block is absent and the rest is zero.
 * Paths and schema names are UTF-8 strings kept byte for byte (dns_path_is_valid_utf8()). */
#define KARIDNS_DB_PATH_MAX 1023            /* same limit as the CONFIG path TLV (dns_db_stream.h) */
#define KARIDNS_DB_DEFAULT_LOADER_PATH "/usr/local/libexec/karidns-dbloader"
typedef struct {
  bool enabled;
  char *driver;                /* "sqlite3" | "postgresql" */
  char *database_file;         /* sqlite3: source of the views without their own file */
  char *conninfo_file;         /* postgresql */
  char *schema;                /* postgresql: schema of the views without their own */
  char *loader_user;           /* restart-only */
  char *loader_group;          /* restart-only */
  char *loader_path;           /* restart-only; NULL = KARIDNS_DB_DEFAULT_LOADER_PATH */
  char **acl_ceiling;          /* stored only (enforced from B7): addresses, "!" negation like allow-transfer */
  int acl_ceiling_count;
  acl_entry_t *acl_ceiling_parsed;
  char **acl_ceiling_keys;
  int acl_ceiling_keys_count;
  uint8_t acl_ceiling_match;   /* acl-ceiling-match: ACL_MATCH_DEFAULT/ANY = address OR key (B7a), ACL_MATCH_ALL = address AND key */
  bool auto_reload;
  uint32_t poll_interval;      /* seconds, 1..60 */
  uint32_t coalesce_ms;        /* 0..10000 */
  uint32_t default_ttl;        /* 1..2147483647 */
  uint32_t bulk_threshold;     /* percent, 0..100 */
  uint64_t max_zone_records;   /* 2..4294967295 */
  uint64_t max_zone_bytes;     /* 65535..64G */
  uint32_t db_reload_timeout;  /* seconds, 1..3600 */
  uint32_t ingest_threads;     /* 1..16 */
  uint32_t loader_threads;     /* 1..16 */
  char *server_id;             /* postgresql only (B11) */
  char **alias_resolver;       /* stored only (B9a): IP address literals */
  int alias_resolver_count;
} database_config_t;

#define KARIDNS_DB_POLL_MIN 1
#define KARIDNS_DB_POLL_MAX 60
#define KARIDNS_DB_COALESCE_MAX 10000
#define KARIDNS_DB_TTL_MAX 2147483647u
#define KARIDNS_DB_RELOAD_TIMEOUT_MAX 3600
#define KARIDNS_DB_THREADS_MAX 16
#define KARIDNS_DB_MAX_VIEWS 1024   /* views that take DB zones: the CONFIG message of the loader link lists at most this many (KDB_MAX_CONFIG_VIEWS) */
#define KARIDNS_DB_MAX_ZONE_RECORDS_DEFAULT 10000000ull   /* the database block and options { max-zone-records } (I2) */
#define KARIDNS_DB_MAX_ZONE_BYTES_DEFAULT (1ull << 30)     /* the database block and options { max-zone-bytes } (I2) */
#define KARIDNS_DB_MAX_ZONE_RECORDS_MAX 4294967295ull
#define KARIDNS_DB_MAX_ZONE_BYTES_MIN 65535ull
#define KARIDNS_DB_MAX_ZONE_BYTES_MAX (64ull << 30)

/* D-22: トップレベルの acl "name" { ... }; 。要素は parse 時の文字列のまま持ち、
 * 設定全体を読んだ後に各 ACL の参照を展開する。key 要素は ACL_KEY_MARK を先頭に付けて区別する */
#define ACL_KEY_MARK '\001'
typedef struct acl_def {
  char *name;
  char **entries;
  int count;
  aml_t *aml;          /* the list as written (nested lists, ! and key kept); names are resolved when the parse ends */
  uint8_t state;       /* 0 = not resolved, 1 = being resolved (a loop), 2 = resolved */
  struct acl_def *next;
} acl_def_t;

/* One address the server listens on (UDP and TCP), the result of listen-on / listen-on-v6 / bind-address / the defaults (see
 * config_build_listen()).  Computed once when the configuration is read; the sockets are opened from this list only. */
#define KARIDNS_LISTEN_MAX 64   /* == MAX_BIND_ADDRS (dns_server_internal.h): the UDP sockets of the Frontend, notify-source pre-binds included */
typedef struct {
  uint8_t family;      /* AF_INET / AF_INET6 */
  bool wildcard;       /* 0.0.0.0 / :: */
  uint16_t port;
  uint8_t addr[16];    /* network byte order */
  char text[48];       /* the address as text (messages, bind()) */
} listen_addr_t;

/* One listen-on / listen-on-v6 statement as written (kept until the configuration is freed): the list is matched against the interface
 * addresses of the start-up snapshot when the parse ends. */
typedef struct {
  bool v6;
  int port;            /* 0 = not written: options { port } */
  aml_t *list;
  char loc[240];       /* "file:line" of the statement */
} listen_stmt_t;

/* options { version; hostname; server-id; } (BIND 9.20 lib/isccfg/namedconf.c: qstringornone, serverid): the CHAOS TXT answers of version.bind,
 * hostname.bind and id.server (bin/named/builtin.c).  The *_set flags say that the file wrote the statement, *_none that it wrote the
 * unquoted word `none`.  The texts are resolved when the parse ends (chaos_finish()): the Backend, in capability mode, never asks for the
 * host name. */
#define CHAOS_TXT_MAX 255   /* one character-string of the TXT RDATA (BIND puttxt() cuts longer texts) */
typedef struct {
  bool version_set, version_none, hostname_set, hostname_none, server_id_set, server_id_none, server_id_hostname;
  char version[CHAOS_TXT_MAX + 1], hostname[CHAOS_TXT_MAX + 1], server_id[CHAOS_TXT_MAX + 1];   /* as written */
  bool has_version, has_hostname, has_id;   /* resolved: is there a TXT RDATA to serve */
  char r_version[CHAOS_TXT_MAX + 1], r_hostname[CHAOS_TXT_MAX + 1], r_id[CHAOS_TXT_MAX + 1];
} chaos_cfg_t;

/* options { minimal-responses } (bin/named/server.c dns_minimal_*; lib/ns/query.c ns_query_start()): MINIMAL_NO_AUTH_RECURSIVE is the
 * written value, the query path turns it into MINIMAL_NO_AUTH (RD set) or MINIMAL_NO */
enum { MINIMAL_NO = 0, MINIMAL_YES = 1, MINIMAL_NO_AUTH = 2, MINIMAL_NO_AUTH_RECURSIVE = 3 };

typedef struct server_config_s {
  int port;
  char **bind_addresses;
  int bind_address_count;
  char bind_address_loc[240];   /* "file:line" of the last bind-address statement ("" = none) */
  listen_stmt_t *listen_stmts;  /* listen-on / listen-on-v6, in the order written */
  int listen_stmt_count;
  listen_addr_t *listen;        /* the addresses to listen on, computed by the parse (config_build_listen); NULL / 0 = none */
  int listen_count;
  aml_t *blackhole;             /* options { blackhole }: requests from a matching address are dropped; NULL = not written (BIND default none) */
  char *user;
  char *group;
  char *pid_file;
  char *directory;      /* options { directory }: the base of relative paths (see config_pin_directory()); NULL = not set (paths are relative to the startup directory) */
  bool directory_changed; /* a reload: the file now says another directory than the one the running server was started with (ignored until a restart) */
  view_config_t *views;
  zone_config_t *zones; /* パース中のトップレベル zone のリスト。パースが終わると既定の view に移るので、パース済みの設定では NULL。
                         * 手で組んだ設定 (テスト) では views を持たずにここへ並べる。全ビューのゾーンを引くには config_find_zone_any_view()、
                         * 順に見るには views の zones を辿る (S6a: ゾーン構造体を複製したフラットリストは廃止) */
  zone_cfg_index_t top_zone_index; /* パース中のトップレベル zone の索引。既定の view に移す */
  tsig_key_t *keys;
  server_stmt_t *servers;       /* top-level server statements, most specific prefix first (a view's own list replaces it) */
  acl_def_t *acls;
  acl_set_t acl;                /* options { allow-query ... }: the default of every view and zone */
  bool acl_query_active;        /* set when the parse ends: allow-query or allow-query-on is written somewhere (options, a view or a zone); false = the query path does not look at ACLs */
  remote_list_t *remote_lists;  /* top-level remote-servers / primaries / masters lists (also-notify names are expanded after the parse; the lists are kept until the configuration is freed) */
  notify_target_t *also_notify; /* options { also-notify { } }: the default of every zone, view and catalog member */
  int also_notify_count;
  uint8_t notify_mode;          /* options { notify }: notify_mode_t, 0 = yes */
  xfr_opts_t xo;                /* options { notify-source, transfer-source, min-refresh-time, ... }: the default of every view and zone */
  zone_vopts_t zv;              /* options { max-records, max-zone-ttl, check-*, ... }: the default of every view and zone */
  /* options-only limits of the transfer machinery (BIND 9.20 ARM "transfers-in" ...); the *_set flags say that the file wrote them */
  uint32_t transfers_in, transfers_out, transfers_per_ns;   /* concurrent inbound / outbound transfers, inbound per primary */
  uint32_t serial_query_rate, notify_rate, startup_notify_rate;   /* per second; 0 written = 1 */
  bool transfers_in_set, transfers_out_set, transfers_per_ns_set, serial_query_rate_set, notify_rate_set, startup_notify_rate_set;
  xfr_source_t *xfr_sources;    /* every distinct source address the configuration names, computed when the parse ends (config_collect_xfr_sources()) */
  int xfr_source_count;
  logging_config_t logging;
  bool querylog_set;            /* options { querylog }: written */
  bool querylog;                /* its value (BIND: when not written, the query log is off until rndc querylog; KariDNS: on when category queries lists a channel) */
  controls_inet_t *controls;    /* controls { inet ...; } entries (checked, then ignored: karictl has its own control channel) */
  int controls_count;
  control_channel_config_t control;
  dnstap_config_t dnstap;
  database_config_t database;  /* options { database { } }; .enabled == false when absent */
  rate_limit_config_t rrl;
  bool serve_stale;
  bool send_extended_errors;
  uint8_t minimal_responses;     /* MINIMAL_* */
  bool minimal_any;
  uint32_t minimal_any_ttl;
  uint32_t wire_cache_max_records;
  size_t response_cache_size;  /* 共有の応答キャッシュの大きさ (オクテット)。0 = 使わない */
  uint64_t generation;         /* 公開した設定ごとに増える (応答キャッシュの鍵) */
  additional_from_auth_t additional_from_auth;
  uint32_t query_log_max_qps;
  uint32_t query_log_buffer_size;
  int max_mqtypes;
  bool rfc10029_mqtype_enable;
  bool tcp_connection_reuse;
  uint32_t tcp_idle_timeout;    /* ms (the file says units of 100 ms, or Nms; see parse_tcp_timeout()); 0 = 10000 */
  uint32_t tcp_initial_timeout; /* ms。最初のメッセージを受け取るまでの待ち時間 (D-06) */
  bool tcp_advertised_set;      /* tcp-advertised-timeout written: the edns-tcp-keepalive value is tcp_advertised_units, not the idle timeout */
  uint16_t tcp_advertised_units; /* units of 100 ms (RFC 7828 §3.3.2) */
  char *nsid_string;
  chaos_cfg_t chaos;             /* version, hostname, server-id */
  /* RFC 9018 DNS Server Cookies. `cookie-secret "<32 hex>";` may be repeated: the first
   * secret generates new Server Cookies, all secrets are accepted for verification
   * (secret rollover). count == 0 -> a random per-process secret is used
   * (NOT interoperable across anycast/multi-server deployments). */
  uint8_t cookie_secrets[4][16];
  int cookie_secret_count;
  int udp_recvbuf_size;
  int udp_sndbuf_size;
  /* TCP の転送パラメータ (0 = OS 既定) */
  notify_retry_config_t notify_retry;
  int ixfr_history;         /* options の ixfr-history (既定 IXFR_HISTORY_DEFAULT) */
  /* I2: options { max-zone-records; max-zone-bytes; }: the limits of one inbound AXFR/IXFR of a secondary zone (the same
   * names and defaults as the database block, KARIDNS_DB_MAX_ZONE_*); a zone value replaces them */
  uint64_t max_zone_records;
  uint64_t max_zone_bytes;
  /* batch 7: options { tcp-receive-buffer; tcp-send-buffer; } (BIND 9.20 uint32, 0 = the system's): a direction written here replaces tcp-window for it
   * (cfg_tcp_rcvbuf() / cfg_tcp_sndbuf()).  Aliases of other options are checked against each other while they are read (alias_note). */
  int tcp_rcvbuf, tcp_sndbuf;
  bool tcp_rcvbuf_set, tcp_sndbuf_set;
  struct { char name[24]; long v; char loc[64]; } alias_note[3];   /* udp-bufsize / max-udp-size, udp-recvbuf-size / udp-receive-buffer, udp-sndbuf-size / udp-send-buffer */
  bool require_server_cookie;   /* options { require-server-cookie }: a UDP query with a client cookie but no valid server cookie gets BADCOOKIE (RFC 7873 §5.2.3) */
  char **catz_names; int catz_count;   /* options { catalog-zones { zone "name"; } }: names of zones (of every view) that are catalog zones */
  bool any_view_max_udp, any_view_cookie;   /* some view writes max-udp-size / require-server-cookie (set when the parse ends): the query path then looks the view up */
  int tcp_mss;              /* TCP_MAXSEG。accept 直後に各接続へ設定 (送信 MSS を下げる方向のみ) */
  int tcp_window;           /* SO_RCVBUF と SO_SNDBUF。listen() 前に設定し accept 済みソケットへ
                             * 継承させる。listen ソケットは reload で作り直さないため再起動が必要 */
  uint16_t udp_bufsize;     /* EDNS UDP ペイロードサイズ上限 (0 = 既定 1232) */
  bool any_zone_tcp_opts;   /* zone-tcp-* を持つゾーンが1つでもあるか (TCP 経路の追加検索を省く) */
  bool any_server_max_udp;  /* some server statement writes max-udp-size: the UDP query path then looks the client up in the server statements (set when the parse ends) */
  bool allow_program_zones; /* 既定 false。trueでない限り type program は起動時エラーで拒否 */
  bool ecs_enable;
  char **ecs_trusted_resolvers;
  int ecs_trusted_resolvers_count;
  acl_entry_t *ecs_trusted_resolvers_parsed;
  ecs_tag_def_t *ecs_tags;
  int ecs_tag_count;
  ecs_tag_def_t *location_tags;
  int location_tag_count;
  ip_port_t *alias_resolvers;   /* B9a: options { alias-resolver { ip [port n]; ... }; }: the default of every zone (dns_alias.h) */
  int alias_resolvers_count;
  _Atomic int reader_count;
} server_config_t;

/* The receive / send buffer of the TCP sockets: tcp-receive-buffer / tcp-send-buffer when written, else tcp-window (0 = the system's) */
static inline int cfg_tcp_rcvbuf(const server_config_t *c) { return c->tcp_rcvbuf_set ? c->tcp_rcvbuf : c->tcp_window; }
static inline int cfg_tcp_sndbuf(const server_config_t *c) { return c->tcp_sndbuf_set ? c->tcp_sndbuf : c->tcp_window; }
/* The view of that name (NULL = none, or name NULL / empty) */
const view_config_t *config_find_view(const server_config_t *cfg, const char *name);
/* require-server-cookie for the clients of a view: the view's statement, else options' */
bool config_require_server_cookie(const server_config_t *cfg, const char *view_name);

/* B7a: the first TSIG key name that the settings x of a DB zone name (allow-transfer key, allow-update name, tsig-key) and
 * cfg does not define in a key {} block, or NULL when all exist */
const char *db_settings_missing_key(const zone_ext_t *x, const server_config_t *cfg);

/* B8t-2: the settings of a zone as its primary sends them to the secondaries (Extended AXFR v3, TYPE 65408), in the syntax of
 * db_settings_parse(): allow-transfer (addresses and keys; the zone's tsig-key of a master zone), transfer-acl-match,
 * ecs-trusted-resolvers (the zone's list, else options'; not when omit_trusted: the zone data carries its own), additional-from-auth
 * and zone-udp-bufsize, each with the value the primary applies (the zone's, else options').  The ACLs of a database zone are cut at
 * acl-ceiling (only what lies inside it is written; no ceiling configured = none).  Never acl-ceiling itself, TSIG secrets or any other
 * server-level policy.  Returns the length (0 = nothing to send), (size_t)-1 when it does not fit cap. */
size_t zone_settings_render(const server_config_t *cfg, const zone_config_t *zcfg, bool omit_trusted, char *out, size_t cap);
/* B8t-2: the zone configuration a secondary uses for a zone that received settings rx (a db_settings_parse() result) from its primary:
 * a copy of base (the zone {} of karidns.conf, or the settings block of a database zone; NULL for a catalog member) in which a
 * statement the secondary did not write itself is taken from rx; the rest falls back to options as always.  A TSIG key the received
 * allow-transfer names and this server does not define makes the received allow-transfer "none" (note says why).  NULL when out of
 * memory.  The result owns everything it points to. */
zone_config_t *zone_config_with_received(const char *domain, const zone_config_t *base, const zone_ext_t *rx,
                                         const server_config_t *cfg, char *note, size_t notelen);
/* the same for a zone of view view_name: a TSIG key the received allow-transfer names is also found among the keys of that view (batch 5) */
zone_config_t *zone_config_with_received_in_view(const char *domain, const char *view_name, const zone_config_t *base, const zone_ext_t *rx,
                                                 const server_config_t *cfg, char *note, size_t notelen);
/* B7a: is options { database { acl-ceiling } } configured (any address or key entry)?  No ceiling = DB ACLs refuse everyone */
bool db_acl_ceiling_configured(const server_config_t *cfg);

/* loader-path with its default */
static inline const char *db_loader_path(const server_config_t *c) {
  return c->database.loader_path ? c->database.loader_path : KARIDNS_DB_DEFAULT_LOADER_PATH;
}

#define MAX_INCLUDE_DEPTH 16

typedef enum {
  TOKEN_EOF,
  TOKEN_STRING,
  TOKEN_LBRACE,
  TOKEN_RBRACE,
  TOKEN_SEMICOLON
} token_type_t;

typedef struct {
  token_type_t type;
  char *value;
  bool is_quoted;
} conf_token_t;

typedef struct {
  char *file_path;      // 解決済みファイルパス (or NULL)
  char *src;            // バッファ
  bool owns_src;        // read_entire_file等で動的確保されたか
  size_t pos;
  size_t len;
  dev_t dev;            // 循環検出用
  ino_t ino;            // 循環検出用
  bool via_rel;         // this file was reached by an include with a relative name (options { directory } check)
} config_file_frame_t;

typedef struct {
  config_file_frame_t stack[MAX_INCLUDE_DEPTH];
  int depth;            // 現在のスタック深さ (0 = トップレベル)
  bool error_occurred;  // 循環/不存在等のエラーフラグ
  bool no_include;      // B7a: 'include' is an error (settings text of a DB zone is hostile and must not open files)
  bool restricted;      // B7a: zone statements are limited to what a DB zone may set (db_settings_parse)
  char restricted_err[160]; // restricted: why a statement was refused (printable, no input bytes beyond the statement name)
  const char *directory; // options { directory } as far as it is known when an `include` is read: a relative include is resolved against it (NULL: against the including file)
  int rel_includes;     // relative include statements resolved so far (a `directory` found later must not change their meaning)
  int dir_rel_before;   // relative includes resolved before the last directory statement, not counting the ones that opened the files being read
  bool dir_pinned;      // directory is the one the running server was started with (config_pin_directory): the file cannot change it
  char *dir_written;    // the directory statement as the configuration writes it (owned by parse_named_conf_ext), NULL = none
  const tsig_key_t *scope_keys; // the keys of the view whose statements are being checked after the parse (a name is defined when it is global or in this list)
} token_ctx_t;

/* options { directory } (BIND 9.20 ARM: "the working directory of the server"; every relative path is relative to it) is read once, when
 * the server starts: the directory (and the sub-directories of the files below it) is opened then, before the Backend enters capability
 * mode.  The server calls this with the directory of its first configuration (NULL = none was written); a later parse (reload) then
 * resolves relative paths and `include` against that directory whatever the file now says, and reports a different one as
 * server_config_t.directory_changed (it takes effect after a restart).  Without a pin (karicheck, tests) each parse uses what it reads. */
/* The directory the server was started in (an absolute path).  Given to the parser before the first parse, it makes the relative paths that
 * the server hands to something that does not share its working directory -- pid-file, and the database files and loader-path of
 * options { database } (the loader is started from "/") -- absolute against it (or against options { directory }).  A path that becomes
 * longer than 1023 bytes is a configuration error.  Not set (karicheck, tests): those paths stay as written.  UNIX socket paths are never
 * changed: the server chdir()s to options { directory } at start-up and daemonize() keeps the working directory. */
void config_set_base_cwd(const char *cwd);
/* The port of the command line (-p): when set (> 0) it replaces options { port } and the port of every listen-on / listen-on-v6 statement,
 * as -p replaced the only port the configuration had before listen-on existed.  Given before the first parse; 0 = none (karicheck, tests). */
void config_set_port_override(int port);
void config_pin_directory(const char *dir);
void config_unpin_directory(void);
int parse_named_conf(const char *config_str, server_config_t *config);
int parse_named_conf_ext(const char *config_str, const char *initial_file_path, server_config_t *config);
void config_lexer_cleanup(token_ctx_t *ctx);
void free_server_config_fields(server_config_t *cfg);
void free_zone_config(zone_config_t *z);
/* 0: 追加した、1: 同じ名前のゾーンが既にある (*dup に返す)、-1: メモリ不足 */
int zone_cfg_index_insert(zone_cfg_index_t *ix, zone_config_t *z, zone_config_t **dup);
void zone_cfg_index_free(zone_cfg_index_t *ix);
/* view 内で domain (末尾ドットの有無、大文字小文字は問わない) のゾーン設定。索引が無ければ線形探索 */
zone_config_t *view_find_zone_config(const view_config_t *v, const char *domain);
/* 全ビューのゾーンを、ビューの並び順・ビュー内の並び順で辿る。内側のループだけを抜ける break は使えない */
#define CONFIG_FOR_EACH_ZONE(cfg, v, z) \
  for ((v) = (cfg)->views; (v); (v) = (v)->next) \
    for ((z) = (v)->zones; (z); (z) = (z)->next)
/* 全ビューを順に見て、最初に domain と一致したゾーン設定 (ビューが無い手組みの設定では cfg->zones から) */
zone_config_t *config_find_zone_any_view(const server_config_t *cfg, const char *domain);
/* zone (NULL 可) の NOTIFY 再送の設定を、options の値で補って返す */
notify_retry_config_t notify_retry_effective(const server_config_t *cfg, const zone_config_t *zone);
/* The also-notify list that applies to a zone: the zone's own statement, else that of its view (view_name; NULL or "" = none),
 * else options' (BIND 9.20 ARM: a zone / view statement overrides the global one).  zone may be NULL (catalog member, zone without
 * zone {}).  *out points into cfg / zone; returns the number of elements (all addresses, see notify_target_t). */
int also_notify_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name,
                          const notify_target_t **out);
/* The notify mode that applies to a zone (never NOTIFY_MODE_INHERIT): the zone's `notify`, else its view's, else options', else yes. */
notify_mode_t notify_mode_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name);
/* The transfer / NOTIFY options that apply to a zone: every option from the zone, else its view (view_name; NULL or "" = none), else
 * options, else the BIND 9.20 default (see XFR_*_DEFAULT).  zone may be NULL (catalog member, zone without zone {}) and cfg may be NULL
 * (defaults only).  multi_master is the option as written (BIND only looks at it when a zone has more than one primary). */
void xfr_opts_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, xfr_eff_t *out);
/* Batch 7: the value of the options of zone_vopts_t that apply to a zone: the zone's, else its view's (view_name; NULL or "" = none), else options',
 * else the default (no limits, serial-update-method increment, every check CHK_DEFAULT).  zone and cfg may be NULL. */
void zone_vopts_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, zone_veff_t *out);
/* The size limits of a zone (max-records, max-records-per-type, max-types-per-name; max-zone-ttl for primary zones only) */
void zone_limits_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, zone_limits_t *out);
/* The source address of a request to a primary / NOTIFY target `family` (AF_INET / AF_INET6): the address of the list the primary is
 * written in (t may be NULL), else the effective transfer-source(-v6) (xfer = true) or notify-source(-v6).  false = the system chooses. */
bool xfr_source_for(const xfr_eff_t *e, const notify_target_t *t, int family, bool xfer, uint8_t out[16]);
/* Batch 5.  The first server statement of list that covers the address (family AF_INET / AF_INET6, addr 4 / 16 octets in network order):
 * the list is ordered most specific prefix first, so this is BIND's dns_peerlist_peerbyaddr().  NULL = none. */
const server_stmt_t *server_list_find(const server_stmt_t *list, int family, const uint8_t *addr);
/* The server statement for a peer of a zone of view view_name (NULL or "" = no view): the view's own statements when it has any (they
 * replace the top-level ones as a whole, BIND named_config_get(cfgmaps, "server")), else the top-level ones. */
const server_stmt_t *config_server_find(const server_config_t *cfg, const char *view_name, int family, const uint8_t *addr);
/* the same for an address given as text (inet_ntop() form); NULL when ip is not an address */
const server_stmt_t *config_server_find_ip(const server_config_t *cfg, const char *view_name, const char *ip);
/* the same for the peer address of a socket (struct sockaddr_in / sockaddr_in6; an IPv4-mapped IPv6 address is looked up as the IPv4 address); NULL sa or another family: NULL */
struct sockaddr;
const server_stmt_t *config_server_find_sa(const server_config_t *cfg, const char *view_name, const struct sockaddr *sa);
/* xfr_opts_effective() for a request to / an answer for the peer srv (NULL = no server statement): the statement's request-ixfr,
 * provide-ixfr and request-expire replace the zone's (BIND zone.c: the peer's value is used when it is set), and its sources fill
 * psrc[] (xfr_source_for() puts them above the list's `source`) */
void xfr_opts_effective_peer(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const server_stmt_t *srv, xfr_eff_t *out);
/* The TSIG key name that signs a request to a peer: the key written on the primaries / also-notify element, else the `keys` of the server
 * statement of the peer, else the zone's tsig-key (KariDNS) -- BIND lib/dns/zone.c soa_query(), notify_send_toaddr(): the element's key,
 * then dns_view_getpeertsig().  NULL = unsigned. */
const char *peer_key_name(const char *element_key, const server_stmt_t *srv, const char *zone_key);
/* minutes of max-transfer-*-in/out in seconds.  KARIDNS_XFER_MINUTE_SECS in the environment (a test hook, like BIND's named -T transferinsecs)
 * sets the length of a "minute" to that many seconds (1..60), so that a test does not wait for real minutes. */
uint32_t xfr_minutes_to_secs(uint32_t minutes);
/* RANGE() of BIND lib/dns/zone.c: a < lo -> lo, else a < hi -> a, else hi (lo > hi gives hi for a >= lo) */
uint32_t xfr_range(uint32_t a, uint32_t lo, uint32_t hi);
/* The timers a zone uses after a transfer or an up-to-date answer (BIND zone_xfrdone()): refresh and retry are clamped to
 * [min-*-time, max-*-time], expire to [refresh + retry, XFR_MAX_EXPIRE].  Any pointer may be NULL. */
void xfr_clamp_timers(const xfr_eff_t *e, uint32_t soa_refresh, uint32_t soa_retry, uint32_t soa_expire, uint32_t *refresh,
                      uint32_t *retry, uint32_t *expire);
/* BIND setrl(): serial-query-rate / notify-rate / startup-notify-rate: 0 is silently raised to 1 */
uint32_t xfr_rate_clamp(uint32_t v);
/* The options-only limits (cfg may be NULL: the defaults); the rates come back clamped (>= 1) */
enum { XL_TRANSFERS_IN = 0, XL_TRANSFERS_OUT, XL_TRANSFERS_PER_NS, XL_SERIAL_QUERY_RATE, XL_NOTIFY_RATE, XL_STARTUP_NOTIFY_RATE };
uint32_t xfr_cfg_limit(const server_config_t *cfg, int which);
/* The source addresses that were in the configuration when the server started are the only ones it can use: the Router pre-binds the NOTIFY
 * sockets and the connect broker (a separate process) is told the transfer sources (and the NOTIFY sources, for NOTIFY over TCP) at its start, neither follows a reload.  The server
 * records the start-up set once (before it forks the children); config_xfr_source_allowed() says whether an address is in it for the
 * use (xfer = transfers, else NOTIFY).  A reload that names another address is a restart-only change. */
void config_set_startup_xfr_sources(const server_config_t *cfg);
bool config_xfr_source_allowed(int family, const uint8_t addr[16], bool xfer);
/* Fills cfg->xfr_sources from every level of the configuration; called when the parse ends.  -1 = out of memory or more than
 * KARIDNS_XFR_SOURCES_MAX distinct addresses (an error with the place has been printed) */
int config_collect_xfr_sources(token_ctx_t *ctx, server_config_t *cfg);
/* The TSIG key that signs the requests to primary i of a zone (and verifies its answers; also the key a NOTIFY from it must carry):
 * the primary's own `key`, else the zone's tsig-key, else NULL.  Precedence as for also-notify. */
static inline const char *zone_primary_key(const zone_ext_t *x, int i) {
  if (i >= 0 && i < x->masters_count && x->masters[i].key && x->masters[i].key[0]) return x->masters[i].key;
  return x->tsig_key && x->tsig_key[0] ? x->tsig_key : NULL;
}
/* The IXFR history depth of a zone: its own ixfr-history, else the options value, else IXFR_HISTORY_DEFAULT (zone/cfg may be NULL). */
int ixfr_history_effective(const server_config_t *cfg, const zone_config_t *zone);
/* I2: the inbound transfer limits of a secondary zone: the zone's max-zone-records / max-zone-bytes, else the options
 * values (a catalog member has no zone { } and takes the options values; cfg NULL = the database defaults) */
void xfr_zone_limits(const server_config_t *cfg, const zone_config_t *zone, uint64_t *max_records, uint64_t *max_bytes);
void free_rate_limit_config(rate_limit_config_t *rrl);
#include <sys/types.h>
char *read_entire_file(const char *path, dev_t *out_dev, ino_t *out_ino);
struct stat;
char *read_entire_file_stat(const char *path, struct stat *out_st);
bool match_cidr(const char *client_ip_str, const char *cidr_str);
bool parse_config_bool(const char *s, bool *out);
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable);
void *safe_realloc_or_die_test_wrapper(void *ptr, size_t size);
void *safe_calloc_or_die_test_wrapper(size_t nmemb, size_t size);

#endif

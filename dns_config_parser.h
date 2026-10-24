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

typedef struct {
  char *ip;
  int port;
} ip_port_t;

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

/* S6a: ゾーンごとの「まれに指定する」オプション。ほとんどのゾーン (domain/file/type だけの
 * 主ゾーン) では 1 つも指定しないので、zone_config_t は核だけを持ち、ここに挙げた値は
 * 1 つでも指定したゾーンに限って別のブロックに確保する (zone_config_t.ext)。
 * ext == NULL は「全部既定 (ゼロ)」。読み手は必ず zext(z) 経由で読むこと。
 * 書き手 (パーサ、テスト) は zone_ext_mut(z) で確保してから書く。 */
typedef struct zone_ext {
  ip_port_t *masters;
  int masters_count;
  cidr_entry_t *masters_parsed;
  char *tsig_key;
  char **tsig_keys;
  int tsig_keys_count;
  ip_port_t *also_notify;
  int also_notify_count;
  char *notify_source;
  char **allow_transfer;
  int allow_transfer_count;
  acl_entry_t *allow_transfer_parsed;
  char **allow_update;
  int allow_update_count;
  acl_entry_t *allow_update_parsed;
  rate_limit_config_t rrl;

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


typedef struct log_channel {
  char *name;
  char *file_path;
  int versions;
  size_t size_limit;
  bool suffix_timestamp;
  bool print_time;
  bool print_category;
  bool print_severity;
  uint32_t max_qps;
  bool max_qps_specified;
  int fd;
  size_t current_size;
  int current_date;
  pthread_mutex_t lock;
  struct log_channel *next;
} log_channel_t;

typedef struct {
  log_channel_t *channels;
  char *queries_channel_name;
  log_channel_t *queries_channel;
  char *responses_channel_name;
  log_channel_t *responses_channel;
} logging_config_t;

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
  struct acl_def *next;
} acl_def_t;

typedef struct server_config_s {
  int port;
  char **bind_addresses;
  int bind_address_count;
  char *user;
  char *group;
  char *pid_file;
  view_config_t *views;
  zone_config_t *zones; /* パース中のトップレベル zone のリスト。パースが終わると既定の view に移るので、パース済みの設定では NULL。
                         * 手で組んだ設定 (テスト) では views を持たずにここへ並べる。全ビューのゾーンを引くには config_find_zone_any_view()、
                         * 順に見るには views の zones を辿る (S6a: ゾーン構造体を複製したフラットリストは廃止) */
  zone_cfg_index_t top_zone_index; /* パース中のトップレベル zone の索引。既定の view に移す */
  tsig_key_t *keys;
  acl_def_t *acls;
  logging_config_t logging;
  control_channel_config_t control;
  dnstap_config_t dnstap;
  database_config_t database;  /* options { database { } }; .enabled == false when absent */
  rate_limit_config_t rrl;
  bool serve_stale;
  bool send_extended_errors;
  bool minimal_responses;
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
  uint32_t tcp_idle_timeout;
  uint32_t tcp_initial_timeout; /* ms。最初のメッセージを受け取るまでの待ち時間 (D-06) */
  char *nsid_string;
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
  int tcp_mss;              /* TCP_MAXSEG。accept 直後に各接続へ設定 (送信 MSS を下げる方向のみ) */
  int tcp_window;           /* SO_RCVBUF と SO_SNDBUF。listen() 前に設定し accept 済みソケットへ
                             * 継承させる。listen ソケットは reload で作り直さないため再起動が必要 */
  uint16_t udp_bufsize;     /* EDNS UDP ペイロードサイズ上限 (0 = 既定 1232) */
  bool any_zone_tcp_opts;   /* zone-tcp-* を持つゾーンが1つでもあるか (TCP 経路の追加検索を省く) */
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
} config_file_frame_t;

typedef struct {
  config_file_frame_t stack[MAX_INCLUDE_DEPTH];
  int depth;            // 現在のスタック深さ (0 = トップレベル)
  bool error_occurred;  // 循環/不存在等のエラーフラグ
  bool no_include;      // B7a: 'include' is an error (settings text of a DB zone is hostile and must not open files)
  bool restricted;      // B7a: zone statements are limited to what a DB zone may set (db_settings_parse)
  char restricted_err[160]; // restricted: why a statement was refused (printable, no input bytes beyond the statement name)
} token_ctx_t;

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
/* The IXFR history depth of a zone: its own ixfr-history, else the options value, else IXFR_HISTORY_DEFAULT (zone/cfg may be NULL). */
int ixfr_history_effective(const server_config_t *cfg, const zone_config_t *zone);
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

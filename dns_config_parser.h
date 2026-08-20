#ifndef DNS_CONFIG_PARSER_H
#define DNS_CONFIG_PARSER_H

#define KARIDNS_MAX_CONFIG_FILE_SIZE (256 * 1024 * 1024)


#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/types.h>
#include "dns_wire.h"

typedef struct {
  char *ip;
  int port;
} ip_port_t;

typedef struct {
  bool configured;
  bool log_only;
  uint32_t responses_per_second;
  uint32_t nxdomains_per_second;
  uint32_t errors_per_second;
  uint32_t window_seconds;
  uint32_t slip;
  ip_port_t *exempt_clients;
  int exempt_clients_count;
} rate_limit_config_t;

typedef struct zone_config {
  char *domain;
  char *file;
  char *type;
  bool is_catalog;
  ip_port_t *masters;
  int masters_count;
  char *tsig_key;
  ip_port_t *also_notify;
  int also_notify_count;
  char *notify_source;
  char **allow_transfer;
  int allow_transfer_count;
  char **allow_update;
  int allow_update_count;
  rate_limit_config_t rrl;
  struct zone_config *next;
} zone_config_t;

typedef struct log_channel {
  char *name;
  char *file_path;
  int versions;
  size_t size_limit;
  bool suffix_timestamp;
  bool print_time;
  bool print_category;
  bool print_severity;
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
  char *algorithm;
  char *secret;
  uint8_t secret_decoded[256];
  size_t secret_decoded_len;
} control_channel_config_t;

typedef struct view_config {
  char *name;
  char **match_clients;
  int match_clients_count;
  zone_config_t *zones;
  struct view_config *next;
} view_config_t;

typedef struct server_config_s {
  int port;
  char **bind_addresses;
  int bind_address_count;
  char *user;
  char *group;
  view_config_t *views;
  zone_config_t *zones; /* 所有権を持たない参照専用フラットリスト。ビュー内ゾーンへのポインタを共有しており、フィールド書き込みや free_zone_config() は絶対に行わないこと */
  tsig_key_t *keys;
  logging_config_t logging;
  control_channel_config_t control;
  rate_limit_config_t rrl;
  bool serve_stale;
  bool send_extended_errors;
  bool minimal_responses;
  bool minimal_any;
  uint32_t minimal_any_ttl;
  int max_mqtypes;
  bool rfc10029_mqtype_enable;
  bool tcp_connection_reuse;
  uint32_t tcp_idle_timeout;
  char *nsid_string;
  int udp_recvbuf_size;
  int udp_sndbuf_size;
} server_config_t;

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
} token_ctx_t;

int parse_named_conf(const char *config_str, server_config_t *config);
int parse_named_conf_ext(const char *config_str, const char *initial_file_path, server_config_t *config);
void config_lexer_cleanup(token_ctx_t *ctx);
void free_server_config_fields(server_config_t *cfg);
void free_zone_config(zone_config_t *z);
void free_rate_limit_config(rate_limit_config_t *rrl);
#include <sys/types.h>
char *read_entire_file(const char *path, dev_t *out_dev, ino_t *out_ino);
bool match_cidr(const char *client_ip_str, const char *cidr_str);
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable);

#endif

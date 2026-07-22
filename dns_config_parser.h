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

typedef struct {
  int port;
  char **bind_addresses;
  int bind_address_count;
  char *user;
  char *group;
  zone_config_t *zones;
  tsig_key_t *keys;
  logging_config_t logging;
  control_channel_config_t control;
  rate_limit_config_t rrl;
  bool send_extended_errors;
} server_config_t;

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
} conf_token_t;
typedef struct {
  const char *src;
  size_t pos;
  size_t len;
} token_ctx_t;

int parse_named_conf(const char *config_str, server_config_t *config);
void free_zone_config(zone_config_t *z);
void free_rate_limit_config(rate_limit_config_t *rrl);
char *read_entire_file(const char *path);
bool match_cidr(const char *client_ip_str, const char *cidr_str);
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable);

#endif
